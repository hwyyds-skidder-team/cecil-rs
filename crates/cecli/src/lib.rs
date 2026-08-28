//! # cecli
//!
//! Rust rewrite of [Mono.Cecil](https://github.com/jbevain/cecil): read,
//! inspect, modify and write .NET assemblies (ECMA-335).
//!
//! ## The object model
//!
//! The facade is an eager, value-semantic object model: a [`Module`] owns
//! flat arenas of definitions addressed by copyable handles ([`TypeId`],
//! [`MethodId`], …), and references are enum values
//! ([`TypeDesc::Def`](crate::model::types::TypeDesc::Def) / [`TypeDesc::External`](crate::model::types::TypeDesc::External) / generic-instance forms)
//! instead of shared base classes with virtual `Resolve()`.
//!
//! Two consequences worth internalizing up front:
//!
//! * **A handle needs its module.** `TypeId` alone is just an index; every
//!   lookup goes through `&Module` (`module.types[id.index()]` or the
//!   accessor helpers). There is no dangling-reference hazard: handles are
//!   plain integers.
//! * **Trees share by `Arc`.** [`TypeDesc`](crate::model::types::TypeDesc)
//!   subtrees are `Arc`-shared, so generic-heavy metadata stays image-linear
//!   in memory on both read and write; clones are cheap.
//!
//! ## Reading
//!
//! [`AssemblyDefinition::read`] accepts raw bytes; `read_file` accepts a
//! path; both parse eagerly (method bodies included). `read_file_with`
//! honors [`resolver::ReaderParameters`]:
//!
//! ```no_run
//! use cecli::AssemblyDefinition;
//! use cecli::resolver::ReaderParameters;
//!
//! let mut params = ReaderParameters::new();
//! params.read_symbols = true; // attach debug symbols (see "Symbols" below)
//!
//! let asm = AssemblyDefinition::read_file_with("demo.exe", &params)?;
//! # Ok::<(), cecli_core::Error>(())
//! ```
//!
//! Byte-origin reads attach no symbols and probe no sibling netmodules
//! (there is no location to probe), mirroring Cecil's
//! `ReadAssembly(byte[])`.
//!
//! ## Inspecting
//!
//! ```no_run
//! # use cecli::AssemblyDefinition;
//! # let asm = AssemblyDefinition::read_file("demo.dll")?;
//! let module = asm.main_module();
//!
//! // Cecil-style lookups: namespace + simple name.
//! let greeter = module.get_type("Demo", "Greeter");
//!
//! // Full-name spellings, including nested `Outer/Inner` and `Outer+Inner`:
//! let nested = module.find_type_full("Demo.Cache/Entry");
//!
//! // Entry point resolves to a real definition:
//! if let Some(main) = asm.entry_point_method() {
//!     println!("entry: {}", main.name);
//! }
//!
//! // Method bodies arrive fully decoded:
//! for (id, method) in module.iter_methods() {
//!     if let Some(body) = &method.body {
//!         println!("{}: {} instructions", method.name, body.instructions.len());
//!     }
//! }
//! # Ok::<(), cecli_core::Error>(())
//! ```
//!
//! Richer reflection-shaped queries (`GetAllTypes`, `GetEnumUnderlyingType`,
//! constructor filters, IL validation, doc-comment IDs) live in the
//! `cecli-rocks` crate as extension traits.
//!
//! ## Modifying
//!
//! Structural edits go through [`edit::BodyEditor`], which keeps branch
//! targets and offsets consistent; call [`edit::renumber`] afterwards and
//! optionally fold macros:
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
//! New types and members attach through [`Module::add_type`] /
//! [`Module::add_method`]. Cross-module references built against another
//! module must be rebuilt through [`importer`] before use.
//!
//! ## Writing
//!
//! `write` serializes back to a full PE32/PE32+ image. Win32 resources and
//! the PE debug directory captured at read time are re-emitted automatically.
//! [`assembly::WriteParameters`] controls the extras:
//!
//! ```no_run
//! # use cecli::AssemblyDefinition;
//! # let asm = AssemblyDefinition::read_file("demo.dll")?;
//! use cecli::assembly::WriteParameters;
//!
//! // Write with a portable-PDB sidecar (when symbols were read):
//! asm.write_file_with("out.dll", &WriteParameters {
//!     write_symbols: true,
//!     ..Default::default()
//! })?;
//! # Ok::<(), cecli_core::Error>(())
//! ```
//!
//! With the `strongname` feature, `WriteParameters::strong_name_key` signs
//! the image in the same pass (public key replaced, signature slot
//! reserved, image signed).
//!
//! ## Symbols
//!
//! With `read_symbols`, the format is sniffed by magic — portable PDB
//! (BSJB), native PDB (MSF), or Mono MDB — so one flag covers all three
//! sidecar kinds. The default lookup probes `<file>.pdb`, `<stem>.pdb`,
//! `<file>.mdb`, `<stem>.mdb`; a custom
//! [`resolver::SymbolReaderProvider`] overrides the source entirely:
//!
//! ```no_run
//! # use cecli::{AssemblyDefinition, resolver::ReaderParameters};
//! # let mut asm = AssemblyDefinition::read_file_with(
//! #     "demo.exe", &ReaderParameters { read_symbols: true, ..Default::default() })?;
//! if let Some(debug) = &asm.main_module().debug {
//!     println!("{} documents", debug.documents.len());
//!     for (rid, entries) in &debug.points {
//!         println!("method rid {rid}: {} sequence-point groups", entries.len());
//!     }
//! }
//! # Ok::<(), cecli_core::Error>(())
//! ```
//!
//! Symbol writing is portable-PDB only (the common cross-platform case);
//! see [`assembly::build_portable_pdb`].
//!
//! ## Type names and resolution
//!
//! [`type_parser::parse_type_name`] turns reflection-style spellings into
//! [`TypeDesc`](crate::model::types::TypeDesc) trees;
//! [`resolution::ResolutionEngine`] resolves type references against a
//! primary module plus optional dependency modules;
//! [`resolver::DefaultAssemblyResolver`] locates assembly files on disk by
//! name/version.
//!
//! ## WinRT projection
//!
//! [`winrt::apply_projections`] / [`winrt::remove_projections`] translate a
//! Windows Metadata module between WinRT and CLR views (the same
//! transformations Cecil applies while reading `.winmd` files), with exact
//! reversal.
//!
//! ## Crate layout
//!
//! | Module | Role |
//! |---|---|
//! | [`model`] | Frozen data model: types, signatures, attributes, marshal specs |
//! | [`index`] | Reverse reference index (kind-less projection over [`xref`]) |
//! | [`xref`] | Bidirectional cross-references with usage kinds |
//! | [`flow`] | CFG (blocks/dominators/loops) + max-stack recomputation |
//! | [`diff`] | Semantic assembly diff |
//! | [`module_def`] | [`Module`] arenas, debug info, resources |
//! | [`assembly`] | The [`AssemblyDefinition`] facade: read/write entry points |
//! | [`read`] / [`write` module][crate::write] | PE + metadata conversion layers |
//! | [`edit`] | [`edit::BodyEditor`], macro simplify/optimize, renumber |
//! | [`importer`] | Cross-module reference remapping |
//! | [`resolver`] | Disk search, reader parameters, symbol providers |
//! | [`resolution`] | In-memory type reference resolution |
//! | [`type_parser`] | Reflection-style type-name parsing |
//! | [`winrt`] | WinRT ↔ CLR projection |
//! | `strongname` | `.snk` parsing and PE signing (`strongname` feature) |
//!
//! Layered crates: `cecli-core` (cursors, tokens, flags), `cecli-pe`,
//! `cecli-metadata`, `cecli-cil`, `cecli-pdb`, `cecli-mdb`, and
//! `cecli-rocks` (reflection extension traits).

pub mod assembly;
pub mod diff;
pub mod edit;
pub mod flow;
pub mod importer;
pub mod index;
pub mod model;
pub mod module_def;
pub mod read;
pub mod resolution;
pub mod resolver;
pub mod strongname;
pub mod type_parser;
pub mod type_system;
pub mod winrt;
pub mod write;
pub mod xref;

pub use assembly::{write_module, write_module_with, AssemblyDefinition};
pub use model::types::{EventId, FieldId, GenericParamId, MethodId, PropertyId, TypeId};
pub use module_def::{ExportedImpl, ExportedTypeRow, FileRow, Module, Resource};
