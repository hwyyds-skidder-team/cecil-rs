//! Native Windows PDB reading and writing.
//!
//! Scope of this module: parsing the MSF ("Compound File") container that wraps
//! every native PDB ([`msf`]), and decoding the CodeView symbol / line streams
//! inside it to map function tokens and RVAs to source files and lines
//! ([`symbols`] with [`NativePdbReader`]). Both native procedures and managed
//! IL procedures are decoded without WinAPI/DIA or an external PDB library.
//! Source checksums, full line/column ranges, locals, constants and lexical
//! scopes are available through [`FunctionDebugInfo`]. Native section offsets
//! are rebased through section-header and OMAP streams when those exist.
//! This covers MSF 7 containers and little-endian DBI/CodeView records. The
//! container reader additionally supports big-endian directory integers.
//! Legacy C11 lines, TPI/IPI type graphs, native variable location/lifetime
//! evaluation and OEM/inlining payload interpretation are not decoded.
//!
//! [`NativePdbBuilder`] emits MSF7, DBI, CodeView procedures and C13 source
//! information. Reconstruction retains original TPI/IPI streams; new native
//! type graphs and native variable location expressions are not synthesized.
//! The reader was ported from
//! `Microsoft.Cci.Pdb` (PdbFileHeader, MsfDirectory, PdbReader, DataStream,
//! BitAccess, BitSet) and the CodeView readers alongside them.

mod codeview_writer;
pub mod msf;
pub mod msf_writer;
pub mod symbols;
pub mod writer;

pub use writer::NativePdbBuilder;

pub use symbols::{
    ConstantValue, FunctionDebugInfo, FunctionKey, NativeConstant, NativeLocal, NativePdbReader,
    NativeScope, SourceDocument, SourceLine,
};
