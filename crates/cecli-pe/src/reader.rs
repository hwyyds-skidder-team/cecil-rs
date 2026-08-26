//! PE / CLI image parsing.
//!
//! Port of `Mono.Cecil.PE/ImageReader.cs`, reading from an in-memory buffer
//! via [`cecli_core::io::ByteReader`] instead of a `Stream`. Metadata heaps
//! and the table heap are *located* here but parsed by the `cecli-metadata`
//! crate from the root slice obtained through [`Image::metadata_rva`].

use crate::image::{
    module_kind, CliHeader, Image, ImageDebugDirectory, ImageDebugEntry, TargetArchitecture,
};
use crate::section::{DataDirectory, Section};
use crate::{DataDirectoryIndex, DATA_DIRECTORIES};
use cecli_core::io::ByteReader;
use cecli_core::{Error, Result};

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
    // PointerToSymbolTable (4), NumberOfSymbols (4), SizeOfOptionalHeader (2)
    r.seek(r.position() + 10)?;
    let characteristics = r.u16()?;

    // - PEOptionalHeader
    let magic = r.u16()?;
    let pe64 = match magic {
        0x10B => false,
        0x20B => true,
        other => return Err(Error::bad_image(format!("unknown optional header magic {other:#x}"))),
    };
    let linker_version = r.u16()?;
    // SizeOfCode (4), InitializedDataSize (4), UninitializedDataSize (4),
    // EntryPointRVA (4), BaseOfCode (4), BaseOfData (4 only for PE32),
    // ImageBase (4 or 8), SectionAlignment (4), FileAlignment (4),
    // OSMajor (2), OSMinor (2), UserMajor (2), UserMinor (2).
    r.seek(r.position() + 44)?;
    let subsystem_major = r.u16()?;
    let subsystem_minor = r.u16()?;
    // Win32VersionValue (4), SizeOfImage (4), SizeOfHeaders (4), CheckSum (4).
    r.seek(r.position() + 16)?;
    let subsystem = r.u16()?;
    let dll_characteristics = r.u16()?;
    // StackReserve/Commit and HeapReserve/Commit (4 or 8 each),
    // LoaderFlags (4), NumberOfRvaAndSizes (4): 24 bytes for PE32,
    // 40 bytes for PE32+. The cursor now sits on the data directories.
    r.seek(r.position() + if pe64 { 40 } else { 24 })?;

    let mut data_directories = [DataDirectory::ZERO; DATA_DIRECTORIES];
    for dir in &mut data_directories {
        dir.virtual_address = r.u32()?;
        dir.size = r.u32()?;
    }

    let sections = read_sections(&mut r, section_count)?;

    let cli_directory = data_directories[DataDirectoryIndex::ComDescription as usize];
    if cli_directory.is_zero() {
        return Err(Error::bad_image("missing CLI header data directory"));
    }
    let cli_header = read_cli_header(&mut r, cli_directory, &sections)?;

    let (metadata_section, runtime_version, streams) =
        read_metadata(&mut r, cli_header.metadata_rva, &sections)?;

    let debug_entries = read_debug_header(
        &mut r,
        data_directories[DataDirectoryIndex::Debug as usize],
        &sections,
        raw.len(),
    )?;
    drop(r);

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
    if lfanew + 4 > raw.len() || &raw[lfanew..lfanew + 4] != b"PE\0\0" {
        return Err(Error::bad_image("missing PE signature"));
    }
    Ok(lfanew)
}

/// Translates an RVA to a file offset using the already-parsed section table.
fn resolve_rva_offset(rva: u64, sections: &[Section]) -> Result<usize> {
    let section = sections
        .iter()
        .find(|s| {
            let rva = rva.min(u32::MAX as u64) as u32;
            let mapped_end =
                s.virtual_address.saturating_add(s.virtual_size.max(s.size_of_raw_data));
            rva >= s.virtual_address && rva < mapped_end
        })
        .ok_or_else(|| Error::bad_image(format!("rva {rva:#x} is not inside any section")))?;
    Ok((rva - section.virtual_address as u64 + section.pointer_to_raw_data as u64) as usize)
}

fn read_sections(r: &mut ByteReader<'_>, count: usize) -> Result<Vec<Section>> {
    // The cursor sits directly after the optional header, where the section
    // table begins.
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
    r.seek(resolve_rva_offset(directory.virtual_address as u64, sections)?)?;

    let mut h = CliHeader::default();
    h.cb = r.u32()?;
    h.runtime_major = r.u16()?;
    h.runtime_minor = r.u16()?;
    h.metadata_rva = r.u32()? as u64;
    h.metadata_size = r.u32()? as u64;
    h.flags = r.u32()?;
    h.entry_point_token = cecli_core::Token(r.u32()?);
    h.resources_rva = r.u32()? as u64;
    h.resources_size = r.u32()? as u64;
    h.strong_name_rva = r.u32()? as u64;
    h.strong_name_size = r.u32()? as u64;
    h.code_manager_table_rva = r.u32()? as u64;
    h.code_manager_table_size = r.u32()? as u64;
    h.vtable_fixups_rva = r.u32()? as u64;
    h.vtable_fixups_size = r.u32()? as u64;
    h.export_address_table_jumps_rva = r.u32()? as u64;
    h.export_address_table_jumps_size = r.u32()? as u64;
    h.managed_native_header_rva = r.u32()? as u64;
    h.managed_native_header_size = r.u32()? as u64;
    Ok(h)
}

type MetadataInfo = (usize, String, Vec<crate::image::MetadataStream>);

/// Locates the metadata root and its stream directory.
///
/// Returns `(metadata section index, runtime version string, streams)`.
fn read_metadata(
    r: &mut ByteReader<'_>,
    metadata_rva: u64,
    sections: &[Section],
) -> Result<MetadataInfo> {
    r.seek(resolve_rva_offset(metadata_rva, sections)?)?;

    if r.u32()? != 0x424A_5342 {
        return Err(Error::bad_image("missing BSJB metadata signature"));
    }
    // MajorVersion (2), MinorVersion (2), Reserved (4).
    r.seek(r.position() + 8)?;

    let version_length = r.i32()?;
    if version_length < 0 || version_length as usize > r.remaining() {
        return Err(Error::bad_image(format!("invalid metadata version length {version_length}")));
    }
    let runtime_version = read_zero_terminated_string(r, version_length as usize)?;

    // Flags (2).
    r.seek(r.position() + 2)?;
    let stream_count = r.u16()? as usize;

    let metadata_section = sections
        .iter()
        .position(|s| {
            let rva = metadata_rva.min(u32::MAX as u64) as u32;
            rva >= s.virtual_address && rva < s.virtual_address.saturating_add(s.size_of_raw_data)
        })
        .ok_or_else(|| Error::bad_image("metadata root is not inside any section"))?;

    let mut streams = Vec::with_capacity(stream_count.min(64));
    for _ in 0..stream_count {
        let offset = r.u32()? as u64; // relative to the metadata root
        let size = r.u32()? as u64;
        let name = read_aligned_string(r)?;
        streams.push(crate::image::MetadataStream { name, offset, size });
    }

    Ok((metadata_section, runtime_version, streams))
}

/// Reads up to `max` bytes until NUL; the cursor ends 4-aligned relative to
/// the string's start (port of `ImageReader.ReadAlignedString`).
fn read_aligned_string(r: &mut ByteReader<'_>) -> Result<String> {
    let start = r.position();
    let mut buf = Vec::new();
    for _ in 0..16 {
        let b = r.u8()?;
        if b == 0 {
            break;
        }
        buf.push(b);
    }
    let consumed = r.position() - start;
    r.seek(start + ((consumed + 3) & !3))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
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

    r.seek(resolve_rva_offset(directory.virtual_address as u64, sections)?)?;

    let count = (directory.size as usize) / ImageDebugDirectory::SIZE;
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
        // the same way).
        let mut data = Vec::new();
        if d.pointer_to_raw_data > 0 && d.size_of_data > 0 {
            let start = d.pointer_to_raw_data as usize;
            let end = start + d.size_of_data as usize;
            if end <= file_len {
                data = raw_slice(r, start, end).to_vec();
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
    use cecli_core::{TableIndex, Token};

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
        let data = std::fs::read(cecli_core::fixtures_dir().join("hello.exe")).unwrap();
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
        let data = std::fs::read(cecli_core::fixtures_dir().join("foo.dll")).unwrap();
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
        let hello = std::fs::read(cecli_core::fixtures_dir().join("hello.exe")).unwrap();
        let hi = Image::parse(&hello).unwrap();
        let names: Vec<_> = hi.streams.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"#~") && names.contains(&"#Strings"));
        assert!(hi.rva(hi.cli_header().metadata_rva).is_ok());
    }
}
