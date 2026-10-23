//! Parsing and emitting of Windows PE / ECMA-335 CLI images.
//!
//! This crate is the Rust port of `Mono.Cecil.PE`. It reads the DOS/PE/CLI
//! headers, the section table, and the data directories of an image
//! ([`Image::parse`]), translates RVAs to file offsets, and re-emits complete
//! PE32 / PE32+ images ([`ImageWriter`]).
//!
//! Metadata heaps and tables are *not* parsed here; downstream crates consume
//! the metadata-root slice located through [`Image::metadata_rva`].

mod buffer;
mod image;
mod reader;
mod section;
mod writer;

#[cfg(test)]
pub(crate) mod testutil;

pub use buffer::ByteBuffer;
pub use image::{
    CliHeader, Image, ImageDebugDirectory, ImageDebugEntry, MetadataStream, ModuleKind,
    TargetArchitecture,
};
pub use section::{DataDirectory, Range, Section};
pub use writer::{compute_pe_checksum, EmitParts, ImageWriter, TextMap, TextSegment};

/// Index of a standard PE data directory inside the optional header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub enum DataDirectoryIndex {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Certificate = 4,
    BaseRelocation = 5,
    Debug = 6,
    Copyright = 7,
    GlobalPtr = 8,
    Tls = 9,
    LoadConfig = 10,
    BoundImport = 11,
    Iat = 12,
    DelayImport = 13,
    ComDescription = 14, // CLI header
    Reserved = 15,
}

/// Number of data-directory entries mandated by the PE spec.
pub const DATA_DIRECTORIES: usize = 16;
