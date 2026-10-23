//! PE section table primitives: sections, data directories, and RVA ranges.

/// A position in the `.text` section: an RVA start plus a byte length.
///
/// Port of Cecil's `Range` struct (`Mono.Cecil/MetadataSystem.cs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Range {
    pub start: u32,
    pub length: u32,
}

impl Range {
    pub fn new(start: u32, length: u32) -> Self {
        Range { start, length }
    }

    /// End offset (start when empty).
    pub fn end(&self) -> u32 {
        self.start + self.length
    }
}

/// One of the 16 optional-header data directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    pub const ZERO: DataDirectory = DataDirectory { virtual_address: 0, size: 0 };

    pub fn new(virtual_address: u32, size: u32) -> Self {
        DataDirectory { virtual_address, size }
    }

    /// True when both the address and the size are zero.
    pub fn is_zero(&self) -> bool {
        self.virtual_address == 0 && self.size == 0
    }
}

/// One entry of the PE section table.
///
/// Port of `Mono.Cecil.PE/Section.cs`.
#[derive(Debug, Clone, Default)]
pub struct Section {
    /// Section name, NUL-trimmed (at most 8 characters).
    pub name: String,
    /// Virtual address of the section in memory.
    pub virtual_address: u32,
    /// Size of the initialized data in memory (VirtualSize).
    pub virtual_size: u32,
    /// Size of the section's data in the file, aligned to `FileAlignment`.
    pub size_of_raw_data: u32,
    /// File offset of the section's raw data.
    pub pointer_to_raw_data: u32,
}
