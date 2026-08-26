//! # cecli
//!
//! Rust rewrite of [Mono.Cecil](https://github.com/jbevain/cecil): read,
//! inspect, modify and write .NET assemblies (ECMA-335).
//!
//! The facade is an eager, value-semantic object model: a [`Module`](crate::module_def::Module)
//! owns flat arenas of definitions addressed by copyable handles
//! ([`TypeId`], [`MethodId`], …), and references are enum values
//! ([`TypeDesc::Def`] / [`TypeDesc::External`] / generic-instance forms)
//! instead of shared base classes with virtual `Resolve()`.
//!
//! ## Reading and writing
//!
//! ```no_run
//! use cecli::AssemblyDefinition;
//!
//! let mut asm = AssemblyDefinition::read_file("demo.dll")?;
//! let module = asm.main_module_mut();
//!
//! for (id, method) in module.iter_methods() {
//!     if let Some(body) = &method.body {
//!         println!("{}: {} instructions", method.name, body.instructions.len());
//!     }
//! }
//!
//! asm.write_file("resaved.dll")?;
//! # Ok::<(), cecli_core::Error>(())
//! ```
//!
//! ## Locating types and members
//!
//! ```no_run
//! # use cecli::AssemblyDefinition;
//! # let asm = AssemblyDefinition::read_file("demo.dll")?;
//! # let module = asm.main_module();
//! // Cecil-style lookups:
//! let greeter = module.get_type("Demo", "Greeter");
//!
//! // Full-name spellings, including nested `Outer/Inner` and `Outer+Inner`:
//! let nested = module.find_type_full("Demo.Cache/Entry");
//!
//! // Entry point resolves to a real definition:
//! if let Some(main) = asm.entry_point_method() {
//!     println!("entry: {}", main.name);
//! }
//! # Ok::<(), cecli_core::Error>(())
//! ```
//!
//! ```no_run
//! use cecli::edit::{renumber, BodyEditor};
//! use cecli_cil::opcodes;
//!
//! # let mut asm = cecli::AssemblyDefinition::read_file("demo.dll")?;
//! # let id = asm.main_module().iter_methods().next().unwrap().0;
//! # let module = asm.main_module_mut();
//! # let method = module.method_mut(id).unwrap();
//! if let Some(body) = method.body.as_mut() {
//!     let mut editor = BodyEditor::new(body);
//!     let nop = BodyEditor::create(opcodes::NOP);
//!     editor.insert_before(0, &nop);
//!     editor.ldc_i4(42);
//!     renumber(body);                     // mandatory after structural edits
//!     cecli::edit::optimize_macros(body); // optional macro folding
//! }
//! # Ok::<(), cecli_core::Error>(())
//! ```
//!
//! ## Symbols
//!
//! ```no_run
//! # use cecli::{AssemblyDefinition, resolver::ReaderParameters};
//! # let mut asm = AssemblyDefinition::read_file_with(
//! #     "demo.exe", &ReaderParameters { read_symbols: true, ..Default::default() })?;
//! if let Some(debug) = &asm.main_module().debug {
//!     println!("{} documents", debug.documents.len());
//! }
//! # Ok::<(), cecli_core::Error>(())
//! ```
//!
//! [`model`] holds the frozen data model; `read`/`write` convert between the
//! model and PE/metadata bytes; [`assembly`] / `module_def` expose the public
//! facade; `resolver`, `importer`, `type_parser`, `resolution`, `winrt`,
//! `edit` and `strongname` are support services.

pub mod assembly;
pub mod edit;
pub mod importer;
pub mod model;
pub mod module_def;
pub mod read;
pub mod resolution;
pub mod resolver;
pub mod strongname;
pub mod type_parser;
pub mod winrt;
pub mod write;

pub use assembly::AssemblyDefinition;
pub use model::types::{EventId, FieldId, GenericParamId, MethodId, PropertyId, TypeId};
pub use module_def::{ExportedImpl, ExportedTypeRow, FileRow, Module, Resource};
