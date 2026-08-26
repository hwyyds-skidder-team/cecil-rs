//! The parsed PE/CLI image model.
//!
//! Port of `Mono.Cecil.PE/Image.cs` plus the header-parsing parts of
//! `ImageReader.cs` that feed it. An [`Image`] owns a copy of the source bytes
//! so RVA translation can return slices.

use crate::section::{DataDirectory, Section};
use cecli_core::{Error, Result, Token};

/// Target machine architecture stored in the PE file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetArchitecture(pub u16);

impl TargetArchitecture {
    pub const I386: TargetArchitecture = TargetArchitecture(0x014C);
    pub const ARM: TargetArchitecture = TargetArchitecture(0x01C4);
    pub const IA64: TargetArchitecture = TargetArchitecture(0x0200);
    pub const AMD64: TargetArchitecture = TargetArchitecture(0x8664);
    pub const ARM64: TargetArchitecture = TargetArchitecture(0xAA64);

    /// Raw machine value stored in the PE file header.
    pub fn machine(self) -> u16 {
        self.0
    }
    /// True for 64-bit image formats (PE32+ optional header).
    pub fn is_pe64(&self) -> bool {
        *self == Self::AMD64 || *self == Self::IA64 || *self == Self::ARM64
    }
}

/// What kind of module the image represents (Cecil's `ModuleKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Console,
    Windows,
    Dll,
    NetModule,
}

/// The CLI header (ECMA-335 II §25.3.3), a.k.a. the COM+ runtime header.
#[derive(Debug, Clone)]
pub struct CliHeader {
    /// Size of the header in bytes (0x48).
    pub cb: u32,
    pub runtime_major: u16,
    pub runtime_minor: u16,
    /// RVA and size of the metadata root ("BSJB").
    pub metadata_rva: u64,
    pub metadata_size: u64,
    /// CLI module flags (ILONLY, 32BITREQUIRED, STRONGNAMESIGNED, ...).
    pub flags: u32,
    /// Entry point as a MethodDef token (0 for pure DLLs without vtable fixups).
    pub entry_point_token: Token,
    /// Managed resources directory.
    pub resources_rva: u64,
    pub resources_size: u64,
    /// Strong-name signature directory.
    pub strong_name_rva: u64,
    pub strong_name_size: u64,
    pub code_manager_table_rva: u64,
    pub code_manager_table_size: u64,
    pub vtable_fixups_rva: u64,
    pub vtable_fixups_size: u64,
    pub export_address_table_jumps_rva: u64,
    pub export_address_table_jumps_size: u64,
    pub managed_native_header_rva: u64,
    pub managed_native_header_size: u64,
}

impl Default for CliHeader {
    fn default() -> Self {
        CliHeader {
            entry_point_token: Token::NIL,
            cb: 0,
            runtime_major: 0,
            runtime_minor: 0,
            metadata_rva: 0,
            metadata_size: 0,
            flags: 0,
            resources_rva: 0,
            resources_size: 0,
            strong_name_rva: 0,
            strong_name_size: 0,
            code_manager_table_rva: 0,
            code_manager_table_size: 0,
            vtable_fixups_rva: 0,
            vtable_fixups_size: 0,
            export_address_table_jumps_rva: 0,
            export_address_table_jumps_size: 0,
            managed_native_header_rva: 0,
            managed_native_header_size: 0,
        }
    }
}

/// One stream entry of the metadata root's stream directory.
///
/// `offset` is relative to the start of the metadata root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataStream {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

/// One IMAGE_DEBUG_DIRECTORY record (ECMA-335 II §C.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImageDebugDirectory {
    pub characteristics: i32,
    pub time_date_stamp: i32,
    pub major_version: i16,
    pub minor_version: i16,
    /// `IMAGE_DEBUG_TYPE` discriminator (CodeView = 2, PdbChecksum = 19, ...).
    pub kind: i32,
    pub size_of_data: i32,
    pub address_of_raw_data: i32,
    pub pointer_to_raw_data: i32,
}

impl ImageDebugDirectory {
    /// Size of one on-disk debug-directory record.
    pub const SIZE: usize = 28;
}

/// A debug directory record together with its payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDebugEntry {
    pub directory: ImageDebugDirectory,
    pub data: Vec<u8>,
}

/// A parsed PE / CLI image.
#[derive(Debug, Clone)]
pub struct Image {
    /// Full original file contents; RVA translation slices into this.
    raw: Vec<u8>,
    /// File offset of the "PE\0\0" signature.
    pe_offset: usize,

    pub kind: ModuleKind,
    pub architecture: TargetArchitecture,
    pub characteristics: u16,
    pub dll_characteristics: u16,
    pub linker_version: u16,
    pub subsystem_major: u16,
    pub subsystem_minor: u16,

    pub timestamp: u32,
    /// Runtime version string from the metadata root (e.g. "v4.0.30319").
    pub runtime_version: String,

    pub sections: Vec<Section>,
    /// Index into [`Self::sections`] of the section holding the metadata root.
    pub metadata_section: usize,

    pub cli_header: CliHeader,
    /// The COM+ data directory (index 14) as found in the optional header.
    pub cli_directory: DataDirectory,
    /// All 16 data directories from the optional header.
    pub data_directories: [DataDirectory; crate::DATA_DIRECTORIES],

    /// Stream directory of the metadata root; heaps/tables are parsed by the
    /// `cecli-metadata` crate.
    pub streams: Vec<MetadataStream>,
    /// Debug directory entries (empty when the Debug data directory is zero).
    pub debug_entries: Vec<ImageDebugEntry>,
}

impl Image {
    /// Parses a complete PE / CLI image from its raw bytes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        raw: Vec<u8>,
        pe_offset: usize,
        kind: ModuleKind,
        architecture: TargetArchitecture,
        characteristics: u16,
        dll_characteristics: u16,
        linker_version: u16,
        subsystem_major: u16,
        subsystem_minor: u16,
        timestamp: u32,
        runtime_version: String,
        sections: Vec<Section>,
        metadata_section: usize,
        cli_header: CliHeader,
        cli_directory: DataDirectory,
        data_directories: [DataDirectory; crate::DATA_DIRECTORIES],
        streams: Vec<MetadataStream>,
        debug_entries: Vec<ImageDebugEntry>,
    ) -> Image {
        Image {
            raw,
            pe_offset,
            kind,
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
        }
    }

    /// Parses a complete PE / CLI image from its raw bytes.
    pub fn parse(data: &[u8]) -> Result<Image> {
        crate::reader::read_image(data.to_vec())
    }

    /// The full original file bytes this image was parsed from.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// File offset of the PE signature.
    pub(crate) fn pe_offset(&self) -> usize {
        self.pe_offset
    }

    /// The parsed CLI header.
    pub fn cli_header(&self) -> &CliHeader {
        &self.cli_header
    }

    /// The entry-point token (MethodDef table), or NIL when absent.
    pub fn entry_point_token(&self) -> Token {
        self.cli_header.entry_point_token
    }

    /// `(rva, size)` of the CLI metadata root.
    pub fn metadata_rva(&self) -> Result<(u64, usize)> {
        if self.cli_header.metadata_rva == 0 {
            return Err(Error::bad_image("image has no metadata root"));
        }
        Ok((
            self.cli_header.metadata_rva,
            self.cli_header.metadata_size as usize,
        ))
    }

    /// The section containing `rva`, if any.
    pub fn section_at_virtual_address(&self, rva: u64) -> Option<&Section> {
        let rva = rva as u32;
        self.sections.iter().find(|s| {
            rva >= s.virtual_address && rva < s.virtual_address.saturating_add(s.size_of_raw_data)
        })
    }

    /// Looks a section up by (trimmed) name.
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Translates an RVA into a file offset (`PointerToRawData` based).
    pub fn rva_offset(&self, rva: u64) -> Result<usize> {
        let section = self
            .section_at_virtual_address(rva)
            .ok_or_else(|| Error::argument(format!("rva {rva:#x} is not inside any section")))?;
        Ok((rva - section.virtual_address as u64 + section.pointer_to_raw_data as u64) as usize)
    }

    /// Translates an RVA to the slice of raw bytes backing it. The slice ends
    /// at the end of the section's raw data.
    pub fn rva(&self, rva: u64) -> Result<&[u8]> {
        let section = self
            .section_at_virtual_address(rva)
            .ok_or_else(|| Error::argument(format!("rva {rva:#x} is not inside any section")))?;
        let start =
            (rva - section.virtual_address as u64 + section.pointer_to_raw_data as u64) as usize;
        let end = ((section.pointer_to_raw_data as u64 + section.size_of_raw_data as u64) as usize)
            .min(self.raw.len());
        if start >= end {
            return Err(Error::bad_image(format!(
                "rva {rva:#x} maps past the end of the file"
            )));
        }
        Ok(&self.raw[start..end])
    }
}

/// Derives the module kind from image characteristics and the subsystem field.
///
/// Port of `ImageReader.GetModuleKind`.
pub fn module_kind(characteristics: u16, subsystem: u16) -> ModuleKind {
    if characteristics & 0x2000 != 0 {
        // ImageCharacteristics::Dll
        return ModuleKind::Dll;
    }
    if subsystem == 0x2 || subsystem == 0x9 {
        // WindowsGui || WindowsCeGui
        return ModuleKind::Windows;
    }
    ModuleKind::Console
}
