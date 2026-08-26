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
pub mod resolution;
pub mod resolver;
pub mod strongname;
pub mod type_parser;
pub mod winrt;
pub mod edit;
pub mod write;

pub use model::types::{EventId, FieldId, GenericParamId, MethodId, PropertyId, TypeId};
pub use module_def::{ExportedImpl, ExportedTypeRow, FileRow, Module, Resource};
