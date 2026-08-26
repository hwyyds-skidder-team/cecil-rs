//! Emission of complete PE32 / PE32+ images.
//!
//! Port of `Mono.Cecil.PE/ImageWriter.cs` and `TextMap.cs`, adapted to work
//! from a parsed [`Image`] instead of a `ModuleDefinition`:
//!
//! * [`ImageWriter::new`] creates a byte-faithful *pass-through* writer: an
//!   untouched image is re-emitted bit-for-bit, and individual fields
//!   (entry-point token, timestamp, same-size metadata replacement) can be
//!   patched without disturbing anything else.
//! * [`ImageWriter::rebuild`] performs a full canonical build (Cecil-style
//!   `.text` layout via [`TextMap`], import directory, startup stub,
//!   [`EmitParts`] bundle.
//!
//! Port deviations from the local Mono.Cecil fork (deliberate):
//! * The COM+/CLI-header data-directory segments are actually laid out in the
//!   text map (the C# fork leaves those slots unmapped, producing invalid
//!   directories).
//! * The PE checksum can be recomputed (`set_compute_checksum`); the C#
//!   writer always stores 0. Pass-through mode keeps the original value so
//!   untouched images round-trip exactly.

use crate::buffer::ByteBuffer;
use crate::image::{Image, ImageDebugEntry, ModuleKind, TargetArchitecture};
use crate::section::{DataDirectory, Range, Section};
use crate::{DataDirectoryIndex, DATA_DIRECTORIES};
use cecli_core::io::ByteWriter;
use cecli_core::{Error, Result, Token};

/// RVA where the `.text` section always begins in Cecil-emitted images.
pub const TEXT_RVA: u32 = 0x2000;

const PE_HEADER_SIZE: u32 = 0x98; // DOS header + PE signature + file header
const SECTION_HEADER_SIZE: u32 = 0x28;
const FILE_ALIGNMENT: u32 = 0x200;
const SECTION_ALIGNMENT: u32 = 0x2000;
const IMAGE_BASE: u64 = 0x0040_0000;
const CLI_HEADER_CB: u32 = 0x48;

fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment <= 1 {
        return value;
    }
    (value + (alignment - 1)) & !(alignment - 1)
}

/// Segments of the `.text` section, in Cecil's order (`TextSegment`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum TextSegment {
    ImportAddressTable,
    CliHeader,
    Code,
    Resources,
    Data,
    StrongNameSignature,

    // Metadata. This port places the whole BSJB root in `MetadataHeader`;
    // the per-heap slots exist for compatibility with the C# layout math.
    MetadataHeader,
    TableHeap,
    StringHeap,
    UserStringHeap,
    GuidHeap,
    BlobHeap,
    PdbHeap,

    DebugDirectory,
    ImportDirectory,
    ImportHintNameTable,
    StartupStub,
}

const TEXT_SEGMENT_COUNT: usize = 17;

/// RVA layout of the text section (port of Cecil's `TextMap`).
#[derive(Debug, Clone, Copy)]
pub struct TextMap {
    map: [Range; TEXT_SEGMENT_COUNT],
}

impl Default for TextMap {
    fn default() -> Self {
        TextMap { map: [Range::default(); TEXT_SEGMENT_COUNT] }
    }
}

impl TextMap {
    /// Adds a segment starting right after the previous one, unaligned.
    pub fn add(&mut self, segment: TextSegment, length: usize) {
        self.map[segment as usize] = Range::new(self.start_of(segment), length as u32);
    }

    /// Adds a segment whose start is aligned up; the previous segment's
    /// length is stretched so the two stay contiguous.
    pub fn add_aligned(&mut self, segment: TextSegment, length: usize, align: u32) {
        let index = segment as usize;
        let start = if index == 0 {
            TEXT_RVA
        } else {
            let previous = self.map[index - 1];
            let start = align_up(previous.end(), align);
            self.map[index - 1].length = start - previous.start;
            start
        };
        self.map[index] = Range::new(start, length as u32);
    }

    /// Adds a segment with an explicit range (used for empty tail segments).
    pub fn add_range(&mut self, segment: TextSegment, range: Range) {
        self.map[segment as usize] = range;
    }

    fn start_of(&self, segment: TextSegment) -> u32 {
        let index = segment as usize;
        if index == 0 {
            TEXT_RVA
        } else {
            self.map[index - 1].end()
        }
    }

    pub fn get_range(&self, segment: TextSegment) -> Range {
        self.map[segment as usize]
    }

    /// `(rva, size)` pair for the optional-header data directory of a segment.
    pub fn get_data_directory(&self, segment: TextSegment) -> DataDirectory {
        let range = self.get_range(segment);
        DataDirectory::new(if range.length == 0 { 0 } else { range.start }, range.length)
    }

    pub fn get_rva(&self, segment: TextSegment) -> u32 {
        self.map[segment as usize].start
    }

    pub fn get_next_rva(&self, segment: TextSegment) -> u32 {
        self.get_range(segment).end()
    }

    pub fn get_length(&self, segment: TextSegment) -> u32 {
        self.map[segment as usize].length
    }

    /// Total length of the text section, from `TEXT_RVA` through the last
    /// mapped segment.
    pub fn total_length(&self) -> u32 {
        let last = self.get_range(TextSegment::StartupStub);
        if last.start < TEXT_RVA {
            // Unmapped map (nothing added yet).
            return 0;
        }
        last.start - TEXT_RVA + last.length
    }
}

/// Everything a full rebuild needs besides what the parsed image provides.
#[derive(Debug, Clone)]
pub struct EmitParts {
    /// Method bodies (IL code), placed first in `.text`.
    pub code: Vec<u8>,
    /// Managed resources blob (CLI header Resources directory target).
    pub resources: Vec<u8>,
    /// Field RVA data placed between resources and the strong-name slot.
    pub data: Vec<u8>,
    /// Alignment of the data segment; defaults to 8.
    pub data_alignment: Option<u32>,
    /// Complete BSJB metadata root (header + all streams), as produced by the
    /// metadata layer.
    pub metadata: Vec<u8>,
    /// Size of the blank strong-name signature placeholder. For assemblies
    /// with a public key this is `public_key.len() - 32`, otherwise 128 for
    /// ECMA-key assemblies, or 0 when unsigned.
    pub strongname_size: u32,
    /// Raw Win32 resource data; gets its own `.rsrc` section with patched RVAs.
    pub win32_resources: Option<Vec<u8>>,
    /// Debug directory entries; their raw-data addresses are recomputed.
    pub debug_entries: Vec<ImageDebugEntry>,
    /// Entry point token written into the CLI header.
    pub entry_point_token: Token,
}

impl Default for EmitParts {
    fn default() -> Self {
        EmitParts {
            code: Vec::new(),
            resources: Vec::new(),
            data: Vec::new(),
            data_alignment: None,
            metadata: Vec::new(),
            strongname_size: 0,
            win32_resources: None,
            debug_entries: Vec::new(),
            entry_point_token: Token::NIL,
        }
    }
}

/// Re-emits a parsed image, either byte-faithfully or as a full rebuild.
pub struct ImageWriter<'a> {
    image: &'a Image,
    parts: Option<EmitParts>,
    entry_point_token: Option<Token>,
    timestamp: Option<u32>,
    metadata_override: Option<Vec<u8>>,
    compute_checksum: bool,
}

impl<'a> ImageWriter<'a> {
    /// Pass-through writer: emits the parsed bytes unchanged unless overrides
    /// are applied. The stored PE checksum is preserved by default.
    pub fn new(image: &'a Image) -> Self {
        ImageWriter {
            image,
            parts: None,
            entry_point_token: None,
            timestamp: None,
            metadata_override: None,
            compute_checksum: false,
        }
    }

    /// Full-rebuild writer: constructs a canonical PE32/PE32+ image from
    /// `parts` while preserving identity fields (machine, characteristics,
    /// timestamps, subsystem versions) from the parsed image.
    ///
    /// The checksum is recomputed by default.
    pub fn rebuild(image: &'a Image, parts: EmitParts) -> Self {
        ImageWriter {
            image,
            parts: Some(parts),
            entry_point_token: None,
            timestamp: None,
            metadata_override: None,
            compute_checksum: true,
        }
    }

    /// Overrides the entry-point token written into the CLI header.
    pub fn set_entry_point_token(&mut self, token: Token) -> &mut Self {
        self.entry_point_token = Some(token);
        self
    }

    /// Overrides the TimeDateStamp written into the PE file header.
    pub fn set_timestamp(&mut self, timestamp: u32) -> &mut Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Pass-through only: replaces the metadata root with a buffer of exactly
    /// the same size. Errors during [`Self::emit`] otherwise.
    pub fn set_metadata_same_size(&mut self, metadata: Vec<u8>) -> &mut Self {
        self.metadata_override = Some(metadata);
        self
    }

    /// Controls PE-checksum recomputation (see type docs for defaults).
    pub fn set_compute_checksum(&mut self, value: bool) -> &mut Self {
        self.compute_checksum = value;
        self
    }

    /// Produces the image bytes.
    pub fn emit(&self) -> Result<Vec<u8>> {
        match &self.parts {
            Some(parts) => self.emit_rebuild(parts),
            None => self.emit_passthrough(),
        }
    }

    // ------------------------------------------------------------------
    // pass-through mode
    // ------------------------------------------------------------------

    fn emit_passthrough(&self) -> Result<Vec<u8>> {
        let mut out = self.image.raw().to_vec();

        if let Some(metadata) = &self.metadata_override {
            let (_, size) = self.image.metadata_rva()?;
            if metadata.len() != size {
                return Err(Error::invalid_op(format!(
                    "metadata replacement is {} bytes but the image root is {size} bytes; \
                     use ImageWriter::rebuild instead",
                    metadata.len()
                )));
            }
            let at = self.image.rva_offset(self.image.cli_header().metadata_rva)?;
            out[at..at + size].copy_from_slice(metadata);
        }

        if let Some(token) = self.effective_entry_point(None) {
            let cli_va = self.image.cli_directory.virtual_address as u64;
            let at = self.image.rva_offset(cli_va)? + 20; // EntryPointToken field
            out[at..at + 4].copy_from_slice(&token.0.to_le_bytes());
        }

        if let Some(timestamp) = self.timestamp {
            let pe = self.image.pe_offset();
            out[pe + 8..pe + 12].copy_from_slice(&timestamp.to_le_bytes());
        }

        if self.compute_checksum {
            patch_checksum(&mut out, self.image.pe_offset())?;
        }

        Ok(out)
    }

    fn effective_entry_point(&self, parts: Option<&EmitParts>) -> Option<Token> {
        if let Some(t) = self.entry_point_token {
            return Some(t);
        }
        if let Some(p) = parts {
            if !p.entry_point_token.is_nil() {
                return Some(p.entry_point_token);
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // full rebuild mode
    // ------------------------------------------------------------------

    fn emit_rebuild(&self, parts: &EmitParts) -> Result<Vec<u8>> {
        if parts.metadata.is_empty() {
            return Err(Error::bad_image("rebuild requires a metadata root"));
        }

        let image = self.image;
        let architecture = image.architecture;
        let pe64 = architecture.is_pe64();
        let has_reloc = architecture == TargetArchitecture::I386;
        let kind = image.kind;

        // --- text map -------------------------------------------------
        let mut map = TextMap::default();
        map.add(TextSegment::ImportAddressTable, if has_reloc { 8 } else { 0 });
        map.add(TextSegment::CliHeader, CLI_HEADER_CB as usize);
        map.add_aligned(TextSegment::Code, parts.code.len(), if pe64 { 16 } else { 4 });
        map.add_aligned(TextSegment::Resources, parts.resources.len(), 8);
        map.add_aligned(TextSegment::Data, parts.data.len(), parts.data_alignment.unwrap_or(8));
        map.add_aligned(TextSegment::StrongNameSignature, parts.strongname_size as usize, 4);
        // The whole BSJB root travels as one aligned segment.
        map.add_aligned(TextSegment::MetadataHeader, parts.metadata.len(), 8);
        // The per-heap slots are unused in this port; keep the segment chain
        // contiguous by marking them as zero-length continuations.
        let metadata_tail = Range::new(map.get_next_rva(TextSegment::MetadataHeader), 0);
        for segment in [
            TextSegment::TableHeap,
            TextSegment::StringHeap,
            TextSegment::UserStringHeap,
            TextSegment::GuidHeap,
            TextSegment::BlobHeap,
            TextSegment::PdbHeap,
        ] {
            map.add_range(segment, metadata_tail);
        }

        // Debug directory: recompute AddressOfRawData for every entry.
        let mut debug_dirs: Vec<(crate::image::ImageDebugDirectory, Vec<u8>)> =
            parts.debug_entries.iter().map(|e| (e.directory, e.data.clone())).collect();
        let mut debug_len = 0usize;
        if !debug_dirs.is_empty() {
            let directories_len = debug_dirs.len() * crate::image::ImageDebugDirectory::SIZE;
            let mut data_address =
                map.get_next_rva(TextSegment::MetadataHeader) as usize + directories_len;
            for (dir, data) in &mut debug_dirs {
                dir.address_of_raw_data = if data.is_empty() { 0 } else { data_address as i32 };
                data_address += data.len();
                debug_len += data.len();
            }
            debug_len += directories_len;
        }
        map.add_aligned(TextSegment::DebugDirectory, debug_len, 4);

        if has_reloc {
            let import_dir_rva = map.get_next_rva(TextSegment::DebugDirectory);
            let mut import_hnt_rva = import_dir_rva + 48;
            import_hnt_rva = (import_hnt_rva + 15) & !15;
            let import_dir_len = (import_hnt_rva - import_dir_rva) + 27;
            let startup_stub_rva = 2 + ((import_dir_rva + import_dir_len + 3) & !3);

            map.add_range(TextSegment::ImportDirectory, Range::new(import_dir_rva, import_dir_len));
            map.add_range(TextSegment::ImportHintNameTable, Range::new(import_hnt_rva, 0));
            map.add_range(TextSegment::StartupStub, Range::new(startup_stub_rva, 6));
        } else {
            let start = map.get_next_rva(TextSegment::DebugDirectory);
            map.add_range(TextSegment::ImportDirectory, Range::new(start, 0));
            map.add_range(TextSegment::ImportHintNameTable, Range::new(start, 0));
            map.add_range(TextSegment::StartupStub, Range::new(start, 0));
        }

        // --- sections -------------------------------------------------
        let win32_resources = parts.win32_resources.clone();
        let sections_count: u16 = 1 + win32_resources.is_some() as u16 + has_reloc as u16;
        let optsz: u32 = if pe64 { 0xF0 } else { 0xE0 };
        let header_size = align_up(
            PE_HEADER_SIZE + optsz + sections_count as u32 * SECTION_HEADER_SIZE,
            FILE_ALIGNMENT,
        );

        let text = Section {
            name: ".text".into(),
            virtual_address: TEXT_RVA,
            virtual_size: map.total_length(),
            size_of_raw_data: align_up(map.total_length(), FILE_ALIGNMENT),
            pointer_to_raw_data: header_size,
        };

        let mut previous = &text;
        let mut rsrc: Option<Section> = None;
        if let Some(res) = &win32_resources {
            let s = create_section(".rsrc", res.len() as u32, previous);
            rsrc = Some(s);
            previous = rsrc.as_ref().unwrap();
        }

        let mut reloc: Option<Section> = None;
        if has_reloc {
            reloc = Some(create_section(".reloc", 12, previous));
        }

        // --- output buffer --------------------------------------------
        let last = reloc.as_ref().or(rsrc.as_ref()).unwrap_or(&text);
        let total = last.pointer_to_raw_data + last.size_of_raw_data;
        let mut out = vec![0u8; total as usize];

        // --- headers ---------------------------------------------------
        let mut hw = ByteWriter::new();
        hw.bytes(dos_header_blob());
        hw.u32(0x0000_4550); // PE signature
        hw.u16(image.architecture.0); // Machine
        hw.u16(sections_count);
        let timestamp = self.timestamp.unwrap_or(image.timestamp);
        hw.u32(timestamp);
        hw.u32(0); // PointerToSymbolTable
        hw.u32(0); // NumberOfSymbols
        hw.u16(optsz as u16);
        // Characteristics are preserved verbatim so identity survives a
        // rebuild (the C# fork recomputes a subset of the bits).
        hw.u16(image.characteristics);

        hw.u16(if pe64 { 0x20B } else { 0x10B }); // Magic
        hw.u16(image.linker_version);
        hw.u32(text.size_of_raw_data); // SizeOfCode
        hw.u32(
            reloc.as_ref().map(|s| s.size_of_raw_data).unwrap_or(0)
                + rsrc.as_ref().map(|s| s.size_of_raw_data).unwrap_or(0),
        ); // SizeOfInitializedData
        hw.u32(0); // SizeOfUninitializedData

        let startup_stub = map.get_range(TextSegment::StartupStub);
        hw.u32(if startup_stub.length > 0 { startup_stub.start } else { 0 }); // AddressOfEntryPoint
        hw.u32(TEXT_RVA); // BaseOfCode

        if !pe64 {
            hw.u32(0); // BaseOfData
            hw.u32(IMAGE_BASE as u32);
        } else {
            hw.u64(IMAGE_BASE);
        }

        hw.u32(SECTION_ALIGNMENT);
        hw.u32(FILE_ALIGNMENT);
        hw.u16(4); // MajorOSVersion
        hw.u16(0); // MinorOSVersion
        hw.u16(0); // MajorImageVersion
        hw.u16(0); // MinorImageVersion
        hw.u16(image.subsystem_major);
        hw.u16(image.subsystem_minor);
        hw.u32(0); // Win32VersionValue

        hw.u32(last.virtual_address + align_up(last.virtual_size, SECTION_ALIGNMENT)); // SizeOfImage
        hw.u32(text.pointer_to_raw_data); // SizeOfHeaders
        hw.u32(0); // Checksum placeholder
        hw.u16(subsystem_for(kind));
        hw.u16(image.dll_characteristics);

        if !pe64 {
            hw.u32(0x0010_0000); // SizeOfStackReserve
            hw.u32(0x1000); // SizeOfStackCommit
            hw.u32(0x0010_0000); // SizeOfHeapReserve
            hw.u32(0x1000); // SizeOfHeapCommit
        } else {
            hw.u64(0x0040_0000);
            hw.u64(0x4000);
            hw.u64(0x0010_0000);
            hw.u64(0x2000);
        }

        hw.u32(0); // LoaderFlags
        hw.u32(DATA_DIRECTORIES as u32);

        write_dir(&mut hw, DataDirectory::ZERO); // Export
        write_dir(&mut hw, map.get_data_directory(TextSegment::ImportDirectory));
        if let Some(s) = &rsrc {
            hw.u32(s.virtual_address);
            hw.u32(s.virtual_size);
        } else {
            write_dir(&mut hw, DataDirectory::ZERO); // Resource
        }
        write_dir(&mut hw, DataDirectory::ZERO); // Exception
        write_dir(&mut hw, DataDirectory::ZERO); // Certificate
        if let Some(s) = &reloc {
            hw.u32(s.virtual_address);
            hw.u32(s.virtual_size);
        } else {
            write_dir(&mut hw, DataDirectory::ZERO); // BaseRelocation
        }
        if debug_len > 0 {
            hw.u32(map.get_rva(TextSegment::DebugDirectory));
            hw.u32(debug_dirs.len() as u32 * crate::image::ImageDebugDirectory::SIZE as u32);
        } else {
            write_dir(&mut hw, DataDirectory::ZERO); // Debug
        }
        write_dir(&mut hw, DataDirectory::ZERO); // Copyright
        write_dir(&mut hw, DataDirectory::ZERO); // GlobalPtr
        write_dir(&mut hw, DataDirectory::ZERO); // TLS
        write_dir(&mut hw, DataDirectory::ZERO); // LoadConfig
        write_dir(&mut hw, DataDirectory::ZERO); // BoundImport
        write_dir(&mut hw, map.get_data_directory(TextSegment::ImportAddressTable)); // IAT
        write_dir(&mut hw, DataDirectory::ZERO); // DelayImport
        write_dir(&mut hw, map.get_data_directory(TextSegment::CliHeader)); // COM+
        write_dir(&mut hw, DataDirectory::ZERO); // Reserved

        write_section_header(&mut hw, &text, 0x6000_0020);
        if let Some(s) = &rsrc {
            write_section_header(&mut hw, s, 0x4000_0040);
        }
        if let Some(s) = &reloc {
            write_section_header(&mut hw, s, 0x4200_0040);
        }

        if hw.len() as u32 > header_size {
            return Err(Error::invalid_op("headers exceed computed header size"));
        }
        out[..hw.len()].copy_from_slice(hw.as_slice());

        // --- text section ----------------------------------------------
        let text_file_offset =
            |rva: u32| -> usize { (rva - TEXT_RVA + text.pointer_to_raw_data) as usize };

        if has_reloc {
            let at = text_file_offset(map.get_rva(TextSegment::ImportAddressTable));
            let hint = map.get_rva(TextSegment::ImportHintNameTable);
            out[at..at + 4].copy_from_slice(&hint.to_le_bytes());
            // second dword stays 0
        }

        // CLI header
        let cli = map.get_rva(TextSegment::CliHeader);
        let mut cw = ByteWriter::new();
        cw.u32(CLI_HEADER_CB);
        cw.u16(2); // MajorRuntimeVersion
        cw.u16(5); // MinorRuntimeVersion
        cw.u32(map.get_rva(TextSegment::MetadataHeader));
        cw.u32(parts.metadata.len() as u32);
        cw.u32(image.cli_header.flags); // preserved module attributes
        cw.u32(
            self.effective_entry_point(Some(parts)).unwrap_or(image.cli_header.entry_point_token).0,
        );
        write_dir(&mut cw, map.get_data_directory(TextSegment::Resources));
        write_dir(&mut cw, map.get_data_directory(TextSegment::StrongNameSignature));
        write_dir(&mut cw, DataDirectory::ZERO); // CodeManagerTable
        write_dir(&mut cw, DataDirectory::ZERO); // VTableFixups
        write_dir(&mut cw, DataDirectory::ZERO); // ExportAddressTableJumps
        write_dir(&mut cw, DataDirectory::ZERO); // ManagedNativeHeader
        let at = text_file_offset(cli);
        out[at..at + cw.len()].copy_from_slice(cw.as_slice());

        place(&mut out, text_file_offset(map.get_rva(TextSegment::Code)), &parts.code)?;
        place(&mut out, text_file_offset(map.get_rva(TextSegment::Resources)), &parts.resources)?;
        place(&mut out, text_file_offset(map.get_rva(TextSegment::Data)), &parts.data)?;
        place(
            &mut out,
            text_file_offset(map.get_rva(TextSegment::MetadataHeader)),
            &parts.metadata,
        )?;

        if !debug_dirs.is_empty() {
            let at = text_file_offset(map.get_rva(TextSegment::DebugDirectory));
            let mut dw = ByteWriter::new();
            let mut data_start = at + debug_dirs.len() * crate::image::ImageDebugDirectory::SIZE;
            for (dir, data) in &debug_dirs {
                dw.i32(dir.characteristics);
                dw.i32(dir.time_date_stamp);
                dw.i16(dir.major_version);
                dw.i16(dir.minor_version);
                dw.i32(dir.kind);
                dw.i32(dir.size_of_data);
                dw.i32(dir.address_of_raw_data);
                dw.i32(if data.is_empty() { dir.pointer_to_raw_data } else { data_start as i32 });
                data_start += data.len();
            }
            for (_, data) in &debug_dirs {
                dw.bytes(data);
            }
            place(&mut out, at, dw.as_slice())?;
        }

        if has_reloc {
            // Import directory
            let import_dir = map.get_rva(TextSegment::ImportDirectory);
            let hint = map.get_rva(TextSegment::ImportHintNameTable);
            let iat = map.get_rva(TextSegment::ImportAddressTable);
            let mut iw = ByteWriter::new();
            iw.u32(import_dir + 40); // ImportLookupTable
            iw.u32(0); // TimeDateStamp
            iw.u32(0); // ForwarderChain
            iw.u32(hint + 14); // Name
            iw.u32(iat); // FirstThunk
            iw.zeros(20);
            iw.u32(hint); // ImportLookupTable entry
            place(&mut out, text_file_offset(import_dir), iw.as_slice())?;

            // Import hint/name table
            let mut nw = ByteWriter::new();
            nw.u16(0); // Hint
            nw.bytes(match kind {
                ModuleKind::Dll | ModuleKind::NetModule => b"_CorDllMain".as_slice(),
                _ => b"_CorExeMain".as_slice(),
            });
            nw.u8(0);
            nw.bytes(b"mscoree.dll");
            nw.u16(0);
            place(&mut out, text_file_offset(hint), nw.as_slice())?;

            // Startup stub (I386): jmp dword ptr [abs]
            let stub = map.get_rva(TextSegment::StartupStub);
            let mut sw = ByteWriter::new();
            sw.u16(0x25FF);
            sw.u32((IMAGE_BASE + iat as u64) as u32);
            place(&mut out, text_file_offset(stub), sw.as_slice())?;
        }

        // --- rsrc section ----------------------------------------------
        if let (Some(section), Some(res)) = (&rsrc, &win32_resources) {
            let old = image.data_directories[DataDirectoryIndex::Resource as usize];
            place(
                &mut out,
                section.pointer_to_raw_data as usize,
                &patch_win32_resources(res, old.virtual_address, section.virtual_address)?,
            )?;
        }

        // --- reloc section ---------------------------------------------
        if let Some(section) = &reloc {
            let stub = map.get_rva(TextSegment::StartupStub);
            let reloc_rva = stub + 2;
            let page_rva = reloc_rva & !0xFFF;
            let mut rw = ByteWriter::new();
            rw.u32(page_rva);
            rw.u32(0x000C); // BlockSize
            rw.u32(0x3000 | (reloc_rva - page_rva)); // Type HIGHLOW | offset
            place(&mut out, section.pointer_to_raw_data as usize, rw.as_slice())?;
        }

        if self.compute_checksum {
            // The rebuilt DOS header is always the canonical 128-byte blob,
            // so the PE signature starts right after it.
            patch_checksum(&mut out, dos_header_blob().len())?;
        }

        Ok(out)
    }
}

/// Copies `data` into `out` at `at`, guarding against overflow.
fn place(out: &mut [u8], at: usize, data: &[u8]) -> Result<()> {
    let end = at + data.len();
    if end > out.len() {
        return Err(Error::invalid_op(format!(
            "section placement at {at} (+{}) exceeds output of {} bytes",
            data.len(),
            out.len()
        )));
    }
    out[at..end].copy_from_slice(data);
    Ok(())
}

fn create_section(name: &str, size: u32, previous: &Section) -> Section {
    Section {
        name: name.into(),
        virtual_address: previous.virtual_address
            + align_up(previous.virtual_size, SECTION_ALIGNMENT),
        virtual_size: size,
        pointer_to_raw_data: previous.pointer_to_raw_data + previous.size_of_raw_data,
        size_of_raw_data: align_up(size, FILE_ALIGNMENT),
    }
}

fn subsystem_for(kind: ModuleKind) -> u16 {
    match kind {
        ModuleKind::Windows => 0x2,
        ModuleKind::Console | ModuleKind::Dll | ModuleKind::NetModule => 0x3,
    }
}

fn write_dir(w: &mut ByteWriter, dir: DataDirectory) {
    w.u32(dir.virtual_address);
    w.u32(dir.size);
}

fn write_section_header(w: &mut ByteWriter, section: &Section, characteristics: u32) {
    let mut name = [0u8; 8];
    for (i, b) in section.name.bytes().take(8).enumerate() {
        name[i] = b;
    }
    w.bytes(&name);
    w.u32(section.virtual_size);
    w.u32(section.virtual_address);
    w.u32(section.size_of_raw_data);
    w.u32(section.pointer_to_raw_data);
    w.u32(0); // PointerToRelocations
    w.u32(0); // PointerToLineNumbers
    w.u16(0); // NumberOfRelocations
    w.u16(0); // NumberOfLineNumbers
    w.u32(characteristics);
}

/// The canonical DOS header + stub emitted by Cecil (128 bytes, e_lfanew 0x80).
fn dos_header_blob() -> &'static [u8; 128] {
    const BLOB: [u8; 128] = [
        // dos header start
        0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
        0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // lfanew
        0x80, 0x00, 0x00, 0x00, // dos stub ("This program cannot be run in DOS mode.")
        0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54,
        0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e,
        0x6e, 0x6f, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44,
        0x4f, 0x53, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 0x24, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    &BLOB
}

/// Rebases Win32 resource RVAs onto the new `.rsrc` section address
/// (port of `PatchWin32Resources`).
fn patch_win32_resources(resources: &[u8], old_rva: u32, new_rva: u32) -> Result<Vec<u8>> {
    let mut buf = ByteBuffer::from_slice(resources);
    patch_resource_directory_table(&mut buf, old_rva, new_rva)?;
    Ok(buf.as_slice().to_vec())
}

fn patch_resource_directory_table(buf: &mut ByteBuffer, old_rva: u32, new_rva: u32) -> Result<()> {
    buf.advance(12)?;
    // Number of entries = NamedEntries + IDEntries.
    let named = buf.u16()?;
    let ids = buf.u16()?;
    for _ in 0..(named + ids) {
        patch_resource_directory_entry(buf, old_rva, new_rva)?;
    }
    Ok(())
}

fn patch_resource_directory_entry(buf: &mut ByteBuffer, old_rva: u32, new_rva: u32) -> Result<()> {
    buf.advance(4)?;
    let child = buf.u32()?;
    let position = buf.position();
    buf.set_position((child & 0x7FFF_FFFF) as usize)?;
    if child & 0x8000_0000 != 0 {
        patch_resource_directory_table(buf, old_rva, new_rva)?;
    } else {
        patch_resource_data_entry(buf, old_rva, new_rva)?;
    }
    buf.set_position(position)?;
    Ok(())
}

fn patch_resource_data_entry(buf: &mut ByteBuffer, old_rva: u32, new_rva: u32) -> Result<()> {
    let at = buf.position();
    let rva = buf.u32()?;
    let rebased = rva.wrapping_sub(old_rva).wrapping_add(new_rva);
    buf.data_mut()[at..at + 4].copy_from_slice(&rebased.to_le_bytes());
    Ok(())
}

/// Computes the standard PE checksum over `data` (checksum field assumed 0).
///
/// The classic algorithm sums 16-bit words with carry folding, adds the file
/// length, and negates. Words are read little-endian; an odd trailing byte is
/// treated as a high-byte-padded final word.
pub fn compute_pe_checksum(data: &[u8]) -> u32 {
    let mut sum: u64 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_le_bytes([chunk[0], chunk[1]]) as u64;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if let [lo] = chunks.remainder() {
        sum += ((*lo as u16) << 8) as u64;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum += data.len() as u64;
    sum = (sum & 0xFFFF) + (sum >> 16);
    (!(sum as u16)) as u32
}

/// Zeroes the checksum field of `out` (whose PE signature starts at `pe`)
/// and patches in the recomputed value.
fn patch_checksum(out: &mut [u8], pe: usize) -> Result<()> {
    let checksum_at = pe + 24 + 64; // optional header + CheckSum offset
    if checksum_at + 4 > out.len() {
        return Err(Error::bad_image("optional header too small for checksum"));
    }
    out[checksum_at..checksum_at + 4].copy_from_slice(&0u32.to_le_bytes());
    let checksum = compute_pe_checksum(out);
    out[checksum_at..checksum_at + 4].copy_from_slice(&checksum.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Image;
    use crate::testutil::{self, ENTRY_TOKEN, TIMESTAMP};

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(cecli_core::fixtures_dir().join(name)).unwrap()
    }

    /// Acceptance: an untouched parsed image re-emits byte-identically.
    #[test]
    fn passthrough_roundtrips_hello_exe() {
        let data = fixture("hello.exe");
        let image = Image::parse(&data).unwrap();
        let out = ImageWriter::new(&image).emit().unwrap();
        assert_eq!(out.len(), data.len());
        assert_eq!(out, data);
    }

    #[test]
    fn passthrough_roundtrips_foo_dll() {
        let data = fixture("foo.dll");
        let image = Image::parse(&data).unwrap();
        assert_eq!(ImageWriter::new(&image).emit().unwrap(), data);
    }

    #[test]
    fn passthrough_overrides_are_patched_in_place() {
        let data = fixture("hello.exe");
        let image = Image::parse(&data).unwrap();

        // Same entry-point token => still identical bytes.
        let token = image.entry_point_token();
        let mut writer = ImageWriter::new(&image);
        writer.set_entry_point_token(token);
        assert_eq!(writer.emit().unwrap(), data);

        // Different timestamp shows up in exactly the PE-file-header field.
        let mut writer = ImageWriter::new(&image);
        writer.set_timestamp(0x0102_0304);
        let out = writer.emit().unwrap();
        assert_ne!(out, data);
        let pe = 0x80; // hello.exe e_lfanew
        let ts = u32::from_le_bytes(out[pe + 8..pe + 12].try_into().unwrap());
        assert_eq!(ts, 0x0102_0304);
        // Everything else untouched.
        let mut expected = data.clone();
        expected[pe + 8..pe + 12].copy_from_slice(&ts.to_le_bytes());
        assert_eq!(out, expected);

        // Metadata replacement must match the root size.
        let (_, size) = image.metadata_rva().unwrap();
        let mut writer = ImageWriter::new(&image);
        writer.set_metadata_same_size(vec![0u8; size - 1]);
        assert!(writer.emit().is_err());

        let mut flipped = vec![0u8; size];
        flipped[size - 1] = 0xAB;
        let mut writer = ImageWriter::new(&image);
        writer.set_metadata_same_size(flipped.clone());
        let out = writer.emit().unwrap();
        let at = image.rva_offset(image.cli_header().metadata_rva).unwrap();
        assert_eq!(&out[at..at + size], &flipped[..]);
    }

    /// Full rebuild of a synthetic image produces a parseable canonical
    /// PE32 image with a recomputed checksum.
    #[test]
    fn rebuild_emits_parseable_pe32() {
        let source = Image::parse(&testutil::tiny_image()).unwrap();
        let parts = EmitParts {
            code: vec![0x90; 16], // nops
            resources: Vec::new(),
            data: Vec::new(),
            data_alignment: None,
            metadata: testutil::tiny_metadata_root(),
            strongname_size: 0,
            win32_resources: None,
            debug_entries: Vec::new(),
            entry_point_token: Token(ENTRY_TOKEN),
        };

        let out = ImageWriter::rebuild(&source, parts).emit().unwrap();
        let image = Image::parse(&out).unwrap();

        assert_eq!(image.architecture.0, 0x014C);
        let names: Vec<_> = image.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec![".text", ".reloc"]);

        let cli = image.cli_header();
        assert_eq!((cli.runtime_major, cli.runtime_minor), (2, 5));
        assert_eq!(cli.entry_point_token, Token(ENTRY_TOKEN));
        assert!(cli.resources_rva == 0 && cli.resources_size == 0);

        // Metadata landed where the CLI header says it did.
        let at = image.rva_offset(cli.metadata_rva).unwrap();
        assert_eq!(&out[at..at + 4], b"BSJB");

        // Code is present in .text.
        assert!(out.contains(&0x90), "code segment should appear in the emitted image");

        // Checksum was recomputed.
        let pe = image.pe_offset();
        let stored = u32::from_le_bytes(out[pe + 24 + 64..pe + 24 + 68].try_into().unwrap());
        assert_ne!(stored, 0);
        let mut zeroed = out.clone();
        zeroed[pe + 24 + 64..pe + 24 + 68].fill(0);
        assert_eq!(stored, compute_pe_checksum(&zeroed));

        // Timestamp preserved from the source image.
        let ts = u32::from_le_bytes(out[pe + 8..pe + 12].try_into().unwrap());
        assert_eq!(ts, TIMESTAMP);
    }

    #[test]
    fn textmap_aligns_and_stretches_previous_segment() {
        let mut map = TextMap::default();
        map.add(TextSegment::ImportAddressTable, 8);
        map.add(TextSegment::CliHeader, CLI_HEADER_CB as usize);
        assert_eq!(map.get_rva(TextSegment::ImportAddressTable), TEXT_RVA);
        assert_eq!(map.get_rva(TextSegment::CliHeader), TEXT_RVA + 8);

        // Code starts aligned to 4; the CLI header length stretches so the
        // segments stay contiguous.
        map.add_aligned(TextSegment::Code, 3, 4);
        assert_eq!(map.get_rva(TextSegment::Code), TEXT_RVA + 8 + 72);
        assert_eq!(map.get_length(TextSegment::CliHeader), 72);

        // A misaligned previous segment gets stretched to the boundary.
        let mut map2 = TextMap::default();
        map2.add(TextSegment::ImportAddressTable, 5);
        map2.add_aligned(TextSegment::CliHeader, 10, 8);
        assert_eq!(map2.get_length(TextSegment::ImportAddressTable), 8);
        assert_eq!(map2.get_rva(TextSegment::CliHeader), TEXT_RVA + 8);

        assert_eq!(TextMap::default().total_length(), 0);
    }

    #[test]
    fn pe_checksum_known_properties() {
        // Empty and odd-length inputs are stable.
        assert_eq!(compute_pe_checksum(&[]), 0xFFFF); // ~(0+0) truncated
        let mut data = vec![1u8; 101];
        data[64..68].fill(0);
        let c1 = compute_pe_checksum(&data);
        // Changing a payload byte changes the checksum.
        data[100] ^= 0xFF;
        assert_ne!(compute_pe_checksum(&data), c1);
    }
}
