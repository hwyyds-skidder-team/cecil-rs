//! cecli: Rust rewrite of Mono.Cecil - read, inspect, and write .NET assemblies.
//!
//! Crate layering: [`model`] holds the frozen data model; `read`/`write` convert
//! between the model and PE/metadata bytes; `assembly`/`module_def` expose the
//! public facade; `resolver`, `importer`, and `type_parser` are support services.

pub mod assembly;
pub mod importer;
pub mod model;
pub mod module_def;
pub mod read;
pub mod resolver;
pub mod type_parser;
pub mod write;
