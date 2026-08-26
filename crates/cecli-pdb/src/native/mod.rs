//! Native Windows PDB support (read-only).
//!
//! Scope of this module: parsing the MSF ("Compound File") container that wraps
//! every native PDB ([`msf`]), and decoding the CodeView symbol / line streams
//! inside it to map function tokens and RVAs to source files and lines
//! ([`symbols`] with [`NativePdbReader`]).
//!
//! Reading is the only supported direction: native PDB *emission* is out of
//! scope by design; debug information is written through the portable PDB
//! format instead (see `crate::portable_writer`). Ported from
//! `Microsoft.Cci.Pdb` (PdbFileHeader, MsfDirectory, PdbReader, DataStream,
//! BitAccess, BitSet) and the CodeView readers alongside them.

pub mod msf;
pub mod symbols;

pub use symbols::NativePdbReader;
