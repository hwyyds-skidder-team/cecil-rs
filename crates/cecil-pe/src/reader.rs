//! PE / CLI image parsing.
//!
//! Port of `Mono.Cecil.PE/ImageReader.cs`, reading from an in-memory buffer
//! via [`cecil_core::io::ByteReader`] instead of a `Stream`. Metadata heaps
//! and the table heap are *located* here but parsed by the `cecil-metadata`
//! crate from the root slice obtained through [`Image::metadata_rva`].

use crate::image::{
    module_kind, CliHeader, Image, ImageDebugDirectory, ImageDebugEntry, TargetArchitecture,
};
use crate::section::{DataDirectory, Section};
use crate::{DataDirectoryIndex, DATA_DIRECTORIES};
use cecil_core::io::ByteReader;
use cecil_core::{Error, Result};

/// Parses a full image from `raw` (which the resulting [`Image`] owns).
pub fn read_image(raw: Vec<u8>) -> Result<Image> {
    // All parsing happens on a borrow of `raw`; every collected value is kept
    // in a local so the borrow can end before the image takes ownership.
    let pe_offset = read_pe_offset(&raw)?;
    let mut r = ByteReader::new(&raw);

    // - DOSHeader: 'MZ', 58 skipped bytes, then e_lfanew.
    if r.u16()? != 0x5A4D {
        return Err(Error::bad_image("missing MZ signature"));
    }
    r.seek(r.position() + 58)?;
    let stored_pe_offset = r.u32()? as usize;
    r.seek(stored_pe_offset)?;
    if r.u32()? != 0x0000_4550 {
        return Err(Error::bad_image("missing PE signature"));
    }

    // - PEFileHeader
    let architecture = TargetArchitecture(r.u16()?);
    let section_count = r.u16()? as usize;
    let timestamp = r.u32()?;
    // PointerToSymbolTable (4), NumberOfSymbols (4).
    r.seek(r.position() + 8)?;
    let optional_size = r.u16()? as usize;
    let characteristics = r.u16()?;

    // - PEOptionalHeader
    let optional_start = r.position();
    let optional_end = optional_start
        .checked_add(optional_size)
        .ok_or_else(|| Error::bad_image("optional-header range overflows"))?;
    let optional = raw
        .get(optional_start..optional_end)
        .ok_or_else(|| Error::bad_image("optional header extends past file"))?;
    let mut opt = ByteReader::new(optional);
    let magic = opt.u16()?;
    let pe64 = match magic {
        0x10B => false,
        0x20B => true,
        other => return Err(Error::bad_image(format!("unknown optional header magic {other:#x}"))),
    };
    let linker_version = opt.u16()?;
    // SizeOfCode (4), InitializedDataSize (4), UninitializedDataSize (4),
    // EntryPointRVA (4), BaseOfCode (4), BaseOfData (4 only for PE32),
    // ImageBase (4 or 8), SectionAlignment (4), FileAlignment (4),
    // OSMajor (2), OSMinor (2), UserMajor (2), UserMinor (2).
    opt.seek(48)?;
    let subsystem_major = opt.u16()?;
    let subsystem_minor = opt.u16()?;
    // Win32VersionValue (4), SizeOfImage (4), SizeOfHeaders (4), CheckSum (4).
    opt.seek(68)?;
    let subsystem = opt.u16()?;
    let dll_characteristics = opt.u16()?;
    // StackReserve/Commit and HeapReserve/Commit (4 or 8 each),
    // LoaderFlags (4), NumberOfRvaAndSizes (4): 24 bytes for PE32,
    // 40 bytes for PE32+. The cursor now sits on the data directories.
    opt.seek(if pe64 { 108 } else { 92 })?;
    let directory_count = opt.u32()? as usize;
    if directory_count.min(DATA_DIRECTORIES) > opt.remaining() / 8 {
        return Err(Error::bad_image("data directories exceed optional header"));
    }

    let mut data_directories = [DataDirectory::ZERO; DATA_DIRECTORIES];
    for dir in data_directories.iter_mut().take(directory_count.min(DATA_DIRECTORIES)) {
        dir.virtual_address = opt.u32()?;
        dir.size = opt.u32()?;
    }

    r.seek(optional_end)?;
    let sections = read_sections(&mut r, section_count)?;

    let cli_directory = data_directories[DataDirectoryIndex::ComDescription as usize];
    if cli_directory.is_zero() {
        return Err(Error::bad_image("missing CLI header data directory"));
    }
    let cli_header = read_cli_header(&mut r, cli_directory, &sections)?;

    let (metadata_section, runtime_version, streams) =
        read_metadata(&r, cli_header.metadata_rva, cli_header.metadata_size as usize, &sections)?;

    let debug_entries = read_debug_header(
        &mut r,
        data_directories[DataDirectoryIndex::Debug as usize],
        &sections,
        raw.len(),
    )
    .unwrap_or_default(); // Debug data is optional; malformed symbols do not invalidate CLI metadata.

    Ok(Image::from_parts(
        raw,
        pe_offset,
        module_kind(characteristics, subsystem),
        architecture,
        characteristics,
        dll_characteristics,
        linker_version,
        subsystem_major,
        subsystem_minor,
        timestamp,
        runtime_version,
        sections,
        metadata_section,
        cli_header,
        cli_directory,
        data_directories,
        streams,
        debug_entries,
    ))
}

/// File offset of the "PE\0\0" signature, validated loosely.
fn read_pe_offset(raw: &[u8]) -> Result<usize> {
    if raw.len() < 128 {
        return Err(Error::bad_image(format!(
            "file too small for a PE image: {} bytes",
            raw.len()
        )));
    }
    let mut r = ByteReader::new(raw);
    r.seek(0x3C)?;
    let lfanew = r.u32()? as usize;
    if raw.get(lfanew..lfanew.saturating_add(4)) != Some(b"PE\0\0".as_slice()) {
        return Err(Error::bad_image("missing PE signature"));
    }
    Ok(lfanew)
}

/// Translates an RVA to a file offset using the already-parsed section table.
fn resolve_rva_offset(rva: u64, sections: &[Section]) -> Result<usize> {
    let section = sections
        .iter()
        .find(|s| {
            let mapped_end =
                s.virtual_address as u64 + s.virtual_size.max(s.size_of_raw_data) as u64;
            rva >= s.virtual_address as u64 && rva < mapped_end && rva <= u32::MAX as u64
        })
        .ok_or_else(|| Error::bad_image(format!("rva {rva:#x} is not inside any section")))?;
    usize::try_from(rva - section.virtual_address as u64 + section.pointer_to_raw_data as u64)
        .map_err(|_| Error::bad_image("RVA file offset exceeds address space"))
}

fn resolve_file_range(rva: u64, size: usize, sections: &[Section], raw: &[u8]) -> Result<usize> {
    let at = resolve_rva_offset(rva, sections)?;
    let section = sections
        .iter()
        .find(|s| {
            rva >= s.virtual_address as u64
                && rva < s.virtual_address as u64 + s.virtual_size.max(s.size_of_raw_data) as u64
        })
        .ok_or_else(|| Error::bad_image("unmapped directory"))?;
    if rva - section.virtual_address as u64 + size as u64 > section.size_of_raw_data as u64 {
        return Err(Error::bad_image("directory exceeds file-backed section"));
    }
    let end = at.checked_add(size).ok_or_else(|| Error::bad_image("directory range overflows"))?;
    if end > raw.len() {
        return Err(Error::bad_image("directory extends past file"));
    }
    Ok(at)
}

fn read_sections(r: &mut ByteReader<'_>, count: usize) -> Result<Vec<Section>> {
    // The cursor sits directly after the optional header, where the section
    // table begins.
    if count > r.remaining() / 40 {
        return Err(Error::bad_image("section count exceeds section table"));
    }
    let mut sections = Vec::with_capacity(count);
    for _ in 0..count {
        let name = read_zero_terminated_string(r, 8)?;
        let virtual_size = r.u32()?;
        let virtual_address = r.u32()?;
        let size_of_raw_data = r.u32()?;
        let pointer_to_raw_data = r.u32()?;
        // PointerToRelocations (4), PointerToLineNumbers (4),
        // NumberOfRelocations (2), NumberOfLineNumbers (2), Characteristics (4).
        r.seek(r.position() + 16)?;
        sections.push(Section {
            name,
            virtual_address,
            virtual_size,
            size_of_raw_data,
            pointer_to_raw_data,
        });
    }
    Ok(sections)
}

fn read_cli_header(
    r: &mut ByteReader<'_>,
    directory: DataDirectory,
    sections: &[Section],
) -> Result<CliHeader> {
    if directory.size < 72 {
        return Err(Error::bad_image("CLI directory is smaller than its header"));
    }
    let at = resolve_file_range(directory.virtual_address as u64, 72, sections, r.bytes())?;
    let mut r = ByteReader::new(&r.bytes()[at..at + 72]);
    let cb = r.u32()?;
    if cb < 72 {
        return Err(Error::bad_image("CLI header size is smaller than 72 bytes"));
    }
    let runtime_major = r.u16()?;
    let runtime_minor = r.u16()?;
    let metadata_rva = r.u32()? as u64;
    let metadata_size = r.u32()? as u64;
    let flags = r.u32()?;
    let entry = r.u32()?;
    let native_entry_point_rva = (flags & 0x10 != 0).then_some(entry);
    Ok(CliHeader {
        cb,
        runtime_major,
        runtime_minor,
        metadata_rva,
        metadata_size,
        flags,
        entry_point_token: if native_entry_point_rva.is_some() {
            cecil_core::Token::NIL
        } else {
            cecil_core::Token(entry)
        },
        native_entry_point_rva,
        resources_rva: r.u32()? as u64,
        resources_size: r.u32()? as u64,
        strong_name_rva: r.u32()? as u64,
        strong_name_size: r.u32()? as u64,
        code_manager_table_rva: r.u32()? as u64,
        code_manager_table_size: r.u32()? as u64,
        vtable_fixups_rva: r.u32()? as u64,
        vtable_fixups_size: r.u32()? as u64,
        export_address_table_jumps_rva: r.u32()? as u64,
        export_address_table_jumps_size: r.u32()? as u64,
        managed_native_header_rva: r.u32()? as u64,
        managed_native_header_size: r.u32()? as u64,
    })
}

type MetadataInfo = (usize, String, Vec<crate::image::MetadataStream>);

/// Locates the metadata root and its stream directory.
///
/// Returns `(metadata section index, runtime version string, streams)`.
fn read_metadata(
    source: &ByteReader<'_>,
    metadata_rva: u64,
    metadata_size: usize,
    sections: &[Section],
) -> Result<MetadataInfo> {
    let start = resolve_file_range(metadata_rva, metadata_size, sections, source.bytes())?;
    let end = start
        .checked_add(metadata_size)
        .ok_or_else(|| Error::bad_image("metadata directory range overflows"))?;
    if end > source.bytes().len() {
        return Err(Error::bad_image("metadata directory extends past the file"));
    }
    // Keep the cursor inside the declared metadata directory. Without this
    // bound, a truncated stream name could scan into unrelated PE sections
    // and accept bytes beyond the metadata directory as stream metadata.
    let metadata = &source.bytes()[start..end];
    let mut r = ByteReader::new(metadata);

    if r.u32()? != 0x424A_5342 {
        return Err(Error::bad_image("missing BSJB metadata signature"));
    }
    // MajorVersion (2), MinorVersion (2), Reserved (4).
    r.seek(r.position() + 8)?;

    let version_length = r.i32()?;
    if version_length < 0 || version_length as usize > r.remaining() {
        return Err(Error::bad_image(format!("invalid metadata version length {version_length}")));
    }
    let runtime_version = read_zero_terminated_string(&mut r, version_length as usize)?;

    // Flags (2).
    r.seek(r.position() + 2)?;
    let stream_count = r.u16()? as usize;

    let metadata_section = sections
        .iter()
        .position(|s| {
            metadata_rva >= s.virtual_address as u64
                && metadata_rva < s.virtual_address as u64 + s.size_of_raw_data as u64
        })
        .ok_or_else(|| Error::bad_image("metadata root is not inside any section"))?;

    let mut streams = Vec::with_capacity(stream_count.min(64));
    for _ in 0..stream_count {
        let offset = r.u32()? as u64; // relative to the metadata root
        let size = r.u32()? as u64;
        let name = read_aligned_string(&mut r)?;
        // Discovery retains hostile extents without slicing or allocating.
        // The metadata consumer selects strict validation or bounded recovery.
        streams.push(crate::image::MetadataStream { name, offset, size });
    }

    Ok((metadata_section, runtime_version, streams))
}

/// Reads up to `max` bytes until NUL; the cursor ends 4-aligned relative to
/// the string's start (port of `ImageReader.ReadAlignedString`).
fn read_aligned_string(r: &mut ByteReader<'_>) -> Result<String> {
    let start = r.position();
    let len = r.bytes()[start..]
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| Error::bad_image("unterminated stream name"))?;
    let name = String::from_utf8_lossy(&r.bytes()[start..start + len]).into_owned();
    let consumed = len + 1;
    r.seek(start + ((consumed + 3) & !3))?;
    Ok(name)
}

/// Reads exactly `length` bytes and trims at the first NUL.
fn read_zero_terminated_string(r: &mut ByteReader<'_>, length: usize) -> Result<String> {
    let bytes = r.read_bytes(length)?;
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(length);
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

fn read_debug_header(
    r: &mut ByteReader<'_>,
    directory: DataDirectory,
    sections: &[Section],
    file_len: usize,
) -> Result<Vec<ImageDebugEntry>> {
    if directory.is_zero() {
        return Ok(Vec::new());
    }

    let at = resolve_file_range(
        directory.virtual_address as u64,
        directory.size as usize,
        sections,
        r.bytes(),
    )?;
    r.seek(at)?;

    // The directory size is hostile: clamp the entry count both by the
    // directory's own arithmetic and by the bytes actually left in the file
    // (28 bytes per entry), so the capacity reservation cannot balloon.
    let count = (directory.size as usize) / ImageDebugDirectory::SIZE;
    let remaining = r.bytes().len().saturating_sub(r.position());
    let count = count.min(remaining / ImageDebugDirectory::SIZE);
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let d = ImageDebugDirectory {
            characteristics: r.i32()?,
            time_date_stamp: r.i32()?,
            major_version: r.i16()?,
            minor_version: r.i16()?,
            kind: r.i32()?,
            size_of_data: r.i32()?,
            address_of_raw_data: r.i32()?,
            pointer_to_raw_data: r.i32()?,
        };

        // Entries without a backing payload keep empty data (Cecil behaves
        // the same way). The payload extent is computed in u64 and range-
        // checked so a hostile size/pointer pair can neither overflow the
        // addition nor allocate past the file.
        let mut data = Vec::new();
        if d.pointer_to_raw_data > 0 && d.size_of_data > 0 {
            let start = d.pointer_to_raw_data as usize;
            let end = start as u64 + d.size_of_data as u64;
            if end <= file_len as u64 {
                data = raw_slice(r, start, end as usize).to_vec();
            }
        }
        entries.push(ImageDebugEntry { directory: d, data });
    }
    Ok(entries)
}

/// Borrows a range of the underlying bytes at absolute file offsets.
fn raw_slice<'a>(r: &ByteReader<'a>, start: usize, end: usize) -> &'a [u8] {
    &r.bytes()[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::ModuleKind;
    use crate::testutil::{self, CLI_RVA, ENTRY_TOKEN, META_RVA, SEC1_VA, SEC2_VA, TIMESTAMP};
    use cecil_core::{TableIndex, Token};

    #[test]
    fn hostile_pe_header_ranges_and_aliasing_rvas_are_bounded() {
        let source = testutil::tiny_image();
        // Tiny image: PE at 0x40; optional header at 0x58; section table 0x138.
        for (offset, value) in [(0x54, 0u16), (0x54, 95), (0x46, u16::MAX)] {
            let mut bytes = source.clone();
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            assert!(Image::parse(&bytes).is_err());
        }
        for (offset, value) in [
            (0x58 + 92, 0u32),
            (0x58 + 92, 14),
            (0x200, 71),
            (0x20c, u32::MAX),
            (0x138 + 20, u32::MAX),
        ] {
            let mut bytes = source.clone();
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(Image::parse(&bytes).is_err(), "offset {offset:#x}");
        }
        let image = Image::parse(&source).unwrap();
        assert!(image.rva_offset(0x1_0000_1000).is_err());
        assert!(image.rva_bytes(SEC1_VA as u64 + 0x3ff, 2).is_err());
        assert!(image.rva_bytes(SEC1_VA as u64 + 1, usize::MAX).is_err());
        // Every truncation returns a checked parse failure or a valid bounded image.
        for end in 0..source.len() {
            assert!(std::panic::catch_unwind(|| Image::parse(&source[..end])).is_ok());
        }
    }

    #[test]
    fn optional_header_padding_and_fifteen_directories_are_honored() {
        let mut bytes = testutil::tiny_image();
        bytes[0x58 + 92..0x58 + 96].copy_from_slice(&15u32.to_le_bytes());
        assert!(Image::parse(&bytes).is_ok());
        // Extra optional-header padding moves the section table. Do not
        // accidentally interpret padding as a section header.
        let table = bytes[0x138..0x188].to_vec();
        bytes[0x138..0x190].fill(0);
        bytes[0x140..0x190].copy_from_slice(&table);
        bytes[0x54..0x56].copy_from_slice(&0xe8u16.to_le_bytes());
        assert_eq!(Image::parse(&bytes).unwrap().sections.len(), 2);
    }

    #[test]
    fn metadata_file_bounds_are_strict_but_stream_discovery_retains_extents() {
        let mut bytes = testutil::tiny_image();
        // First section's file backing ends before metadata, while virtual
        // size still covers it: metadata must not read unrelated file data.
        bytes[0x138 + 16..0x138 + 20].copy_from_slice(&0x100u32.to_le_bytes());
        assert!(Image::parse(&bytes).is_err());
        let mut bytes = testutil::tiny_image();
        bytes[0x20c..0x210].copy_from_slice(&40u32.to_le_bytes());
        bytes[0x316..0x318].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x318..0x31c].copy_from_slice(&40u32.to_le_bytes());
        bytes[0x31c..0x320].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x320..0x324].copy_from_slice(b"#x\0\0");
        let image = Image::parse(&bytes).unwrap();
        assert_eq!(image.streams[0].offset, 40);
        assert_eq!(image.streams[0].size, 1);
    }

    /// Independently walks the section table straight from the raw bytes so
    /// assertions do not just re-test the parser against itself.
    fn raw_sections(data: &[u8]) -> Vec<(String, u32, u32)> {
        let mut r = ByteReader::new(data);
        r.seek(0x3C).unwrap();
        let pe = r.u32().unwrap() as usize;
        r.seek(pe + 6).unwrap();
        let count = r.u16().unwrap() as usize;
        let opt_size = {
            r.seek(pe + 20).unwrap();
            r.u16().unwrap() as usize
        };
        let mut out = Vec::new();
        for i in 0..count {
            r.seek(pe + 24 + opt_size + 40 * i).unwrap();
            let name = String::from_utf8_lossy(r.read_bytes(8).unwrap())
                .trim_end_matches('\0')
                .to_string();
            r.seek(r.position() + 4).unwrap(); // VirtualSize
            let va = r.u32().unwrap();
            r.seek(r.position() + 4).unwrap(); // SizeOfRawData
            out.push((name, va, va));
        }
        out
    }

    #[test]
    fn parses_fixture_hello_exe() {
        let data = std::fs::read(cecil_core::fixtures_dir().join("hello.exe")).unwrap();
        let image = Image::parse(&data).unwrap();

        // Values cross-checked against the raw bytes.
        assert_eq!(image.architecture, TargetArchitecture(0x014C));
        let expected = raw_sections(&data);
        assert_eq!(expected.len(), image.sections.len());
        for ((name, _, _), section) in expected.iter().zip(image.sections.iter()) {
            assert_eq!(&section.name, name);
        }
        assert_eq!(image.section(".text").unwrap().virtual_address, expected[0].1);

        assert_eq!(image.kind, ModuleKind::Console);
        assert_eq!(image.timestamp, 0x4838_13DC);
        assert_eq!(image.subsystem_major, 4);

        // CLI header: runtime > 2.0 and a MethodDef entry point.
        let cli = image.cli_header();
        assert!(
            cli.runtime_major > 2 || (cli.runtime_major == 2 && cli.runtime_minor > 0),
            "runtime version {}.{} not > 2.0",
            cli.runtime_major,
            cli.runtime_minor
        );
        let token = image.entry_point_token();
        assert!(!token.is_nil());
        assert_eq!(token.table(), TableIndex::MethodDef);
    }

    #[test]
    fn parses_fixture_foo_dll() {
        let data = std::fs::read(cecil_core::fixtures_dir().join("foo.dll")).unwrap();
        let image = Image::parse(&data).unwrap();

        assert_eq!(image.architecture, TargetArchitecture(0x014C));
        let expected = raw_sections(&data);
        assert_eq!(expected.len(), image.sections.len());
        assert_eq!(
            image.sections.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            expected.iter().map(|(n, _, _)| n.as_str()).collect::<Vec<_>>()
        );

        assert_eq!(image.kind, ModuleKind::Dll);
        assert_ne!(image.characteristics & 0x2000, 0);

        let cli = image.cli_header();
        assert!(cli.runtime_major >= 2);
        // This DLL was built without an entry point, so the stored token is
        // legitimately nil; when present the table must be MethodDef.
        let token = image.entry_point_token();
        if !token.is_nil() {
            assert_eq!(token.table_byte(), 0x06, "entry point must be MethodDef");
        }
    }

    #[test]
    fn parses_synthetic_image_and_translates_rvas() {
        let data = testutil::tiny_image();
        let image = Image::parse(&data).unwrap();

        assert_eq!(image.kind, ModuleKind::Console);
        assert_eq!(image.timestamp, TIMESTAMP);
        assert_eq!(image.cli_header().runtime_major, 2);
        assert_eq!(image.cli_header().runtime_minor, 5);
        assert_eq!(image.entry_point_token(), Token(ENTRY_TOKEN));

        // RVA -> offset translation on the synthetic layout.
        assert_eq!(image.rva_offset(SEC1_VA as u64).unwrap(), 0x200);
        assert_eq!(image.rva_offset((SEC1_VA + 0x100) as u64).unwrap(), 0x300);
        assert_eq!(image.rva_offset((SEC2_VA + 0x10) as u64).unwrap(), 0x610);
        assert!(image.rva_offset(0x40).is_err()); // headers are not mapped
        assert!(image.rva_offset((SEC2_VA + 0x200) as u64).is_err()); // end of section

        // RVA slices.
        let meta = image.rva(META_RVA as u64).unwrap();
        assert_eq!(&meta[..4], b"BSJB");
        assert_eq!(image.rva(CLI_RVA as u64).unwrap()[0], 0x48);

        let (rva, size) = image.metadata_rva().unwrap();
        assert_eq!(rva, META_RVA as u64);
        assert_eq!(size, testutil::tiny_metadata_root().len());

        // Streams: the synthetic root has none; fixtures have five.
        let hello = std::fs::read(cecil_core::fixtures_dir().join("hello.exe")).unwrap();
        let hi = Image::parse(&hello).unwrap();
        let names: Vec<_> = hi.streams.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"#~") && names.contains(&"#Strings"));
        assert!(hi.rva(hi.cli_header().metadata_rva).is_ok());
    }
}
