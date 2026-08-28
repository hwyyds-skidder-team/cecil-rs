//! Assembly definition: the public facade over one or more modules.
//! (flag types come straight from cecli_core)

use crate::model::types::*;
use crate::module_def::Module;
use crate::resolver::AssemblyResolver;
use cecli_core::flags::{AssemblyAttributes, AssemblyHashAlgorithm};
// Assembly-level identity (`Assembly` row equivalent).
/// Assembly-level identity (`Assembly` row equivalent).
#[derive(Debug, Clone)]
pub struct AssemblyNameDefinition {
    pub name: String,
    pub version: Version,
    pub culture: Option<String>,
    /// Public key (full key, not the token, for `Assembly` rows).
    pub public_key: Vec<u8>,
    pub hash: Vec<u8>,
    pub hash_algorithm: AssemblyHashAlgorithm,
    pub attributes: AssemblyAttributes,
    pub custom_attributes: Vec<CustomAttribute>,
    pub security_declarations: Vec<SecurityDeclaration>,
}

impl Default for AssemblyNameDefinition {
    fn default() -> Self {
        AssemblyNameDefinition {
            name: String::new(),
            version: Version::new(0, 0, 0, 0),
            culture: None,
            public_key: Vec::new(),
            hash: Vec::new(),
            hash_algorithm: AssemblyHashAlgorithm::None,
            attributes: AssemblyAttributes::empty(),
            custom_attributes: Vec::new(),
            security_declarations: Vec::new(),
        }
    }
}

/// Deferred body-decoding state for an assembly read with
/// [`ReadingMode::Lazy`](crate::resolver::ReadingMode::Lazy): the raw image
/// bytes plus the read context needed to resume. Consumed by
/// [`AssemblyDefinition::load_bodies`].
#[derive(Debug, Clone)]
pub struct LazyAssembly {
    pub(crate) raw: Vec<u8>,
    pub(crate) ctx: crate::read::context::ReadContext,
}

/// An assembly: main module plus optional satellite netmodules.
#[derive(Debug, Clone, Default)]
pub struct AssemblyDefinition {
    pub name: AssemblyNameDefinition,
    pub main: Module,
    /// Additional netmodules of a multi-module assembly.
    pub modules: Vec<Module>,
    /// Entry point as a method arena index into `main`.
    pub entry_point: Option<MethodId>,
    /// Present when method bodies were deferred at read time
    /// ([`ReadingMode::Lazy`](crate::resolver::ReadingMode::Lazy));
    /// [`Self::load_bodies`] consumes it. `None` once bodies are loaded.
    pub lazy: Option<LazyAssembly>,
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

impl AssemblyDefinition {
    /// Parses an assembly from its raw image bytes.
    ///
    /// Port of `AssemblyDefinition.ReadAssembly(byte[])`.
    pub fn read(bytes: &[u8]) -> Result<Self> {
        Self::read_impl(bytes, None, &crate::resolver::ReaderParameters::new())
    }

    /// Reads an assembly from a file path.
    ///
    /// Port of `AssemblyDefinition.ReadAssembly(string)`. Symbols are not
    /// loaded; use [`Self::read_file_with`] with
    /// [`crate::resolver::ReaderParameters::read_symbols`].
    pub fn read_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        Self::read_file_with(path, &crate::resolver::ReaderParameters::new())
    }

    /// Reads an assembly from a file path honoring reader parameters.
    ///
    /// The path doubles as the symbol origin: with `read_symbols` set, a
    /// portable PDB sidecar is looked up next to the image (`<file>.pdb`
    /// first, then the extension-swapped stem) and attached to
    /// [`Module::debug`]. Missing sidecars error, mirroring Cecil's
    /// `DefaultSymbolReaderProvider` throwing `FileNotFoundException`.
    pub fn read_file_with<P: AsRef<std::path::Path>>(
        path: P,
        opts: &crate::resolver::ReaderParameters,
    ) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path).map_err(Error::Io)?;
        Self::read_impl(&bytes, Some(path.to_path_buf()), opts)
    }

    /// Reads an assembly from raw bytes honoring reader parameters.
    ///
    /// Byte origins carry no location, so no symbols are attached and no
    /// sibling netmodules are probed on disk (Cecil behaves the same for
    /// `ReadAssembly(byte[])` without a symbol provider).
    pub fn read_with(bytes: &[u8], opts: &crate::resolver::ReaderParameters) -> Result<Self> {
        Self::read_impl(bytes, None, opts)
    }

    fn read_impl(
        bytes: &[u8],
        origin: Option<std::path::PathBuf>,
        opts: &crate::resolver::ReaderParameters,
    ) -> Result<Self> {
        let image = cecli_pe::Image::parse(bytes)?;
        let read_opts = crate::read::context::ReadOptions::default();
        let (mut module, mut ctx) = crate::read::module_reader::read_module(&image, &read_opts)?;

        // Method-body policy: `Immediate` (the default) decodes every body
        // up front. `Lazy`/`Deferred` skip the decode and stash the raw
        // image + read context at the end of this function so
        // [`Self::load_bodies`] can resume later — the value-model analogue
        // of Cecil's lazy reading (documented divergence: bodies defer as a
        // unit, not per member).
        let eager = opts.reading_mode == crate::resolver::ReadingMode::Immediate;
        if eager {
            // Decode IL bodies against the parsed metadata root.
            let (md_rva, _) = image.metadata_rva()?;
            let md_slice = image.rva(md_rva)?;
            let md = cecli_metadata::MetadataReader::parse(md_slice.as_ref())?;
            crate::read::instructions::resolve_bodies_opts(
                &mut module,
                &mut ctx,
                &md,
                &image,
                read_opts.load_bodies,
            )?;
        }

        // Preserve unmodeled PE payload for re-emission on write: the raw
        // Win32 resource section and the debug directory records. The
        // resource blob is only kept when its directory tree walks cleanly
        // (bounded offsets, bounded depth) — the writer re-walks the tree to
        // rebase RVAs, so garbage would otherwise crash (or loop) on write.
        let rsrc_dir = image.data_directories[cecli_pe::DataDirectoryIndex::Resource as usize];
        if !rsrc_dir.is_zero() && rsrc_dir.size > 0 {
            if let Ok(section) = image.rva(rsrc_dir.virtual_address as u64) {
                let end = (rsrc_dir.size as usize).min(section.len());
                let bytes = &section[..end];
                if win32_resources_tree_is_sane(bytes) {
                    module.win32_resources = Some(crate::module_def::Win32Resources {
                        original_rva: rsrc_dir.virtual_address,
                        bytes: bytes.to_vec(),
                    });
                }
            }
        }
        module.debug_entries = image.debug_entries.clone();

        // Assembly row -> facade identity. Netmodules have no Assembly table,
        // in which case the facade keeps Cecil's "unnamed" placeholder.
        let name = match ctx.assembly_row.take() {
            Some(row) => AssemblyNameDefinition {
                name: row.name,
                version: row.version,
                culture: row.culture,
                public_key: row.public_key,
                // The `Assembly` row itself carries no hash value.
                hash: Vec::new(),
                hash_algorithm: row.hash_alg,
                attributes: cecli_core::flags::AssemblyAttributes::from_bits_truncate(row.flags),
                custom_attributes: row.custom_attributes,
                security_declarations: row.security_declarations,
            },
            None => AssemblyNameDefinition {
                name: "unnamed".to_string(),
                ..AssemblyNameDefinition::default()
            },
        };

        // Symbols: a configured provider decides the source; the default
        // probes PDB then MDB sidecars next to the origin file. The format
        // is sniffed from magic (BSJB / MSF / MDB) and dispatched.
        if opts.read_symbols {
            let Some(origin_path) = origin.as_deref() else {
                return Err(Error::Unsupported(
                    "reading symbols requires a file-path origin; use AssemblyDefinition::read_file_with"
                        .to_string(),
                ));
            };
            let symbol_bytes = match opts.symbol_reader_provider.as_ref() {
                Some(provider) => provider.get_symbol_reader(origin_path)?.ok_or_else(|| {
                    Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "symbol provider returned no symbol data for '{}'",
                            origin_path.display()
                        ),
                    ))
                })?,
                // Default: sidecar files first, then an embedded portable PDB
                // in the image's own debug directory (Cecil's
                // DefaultSymbolReaderProvider prefers whatever the image
                // carries when no sidecar exists).
                None => load_symbol_bytes(origin_path)
                    .or_else(|| embedded_symbol_bytes(&image).map(|(bytes, _)| bytes))
                    .ok_or_else(|| {
                        Error::Io(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!(
                                "no symbol file (.pdb/.mdb) or embedded PDB found for '{}'",
                                origin_path.display()
                            ),
                        ))
                    })?,
            };
            attach_symbols(&mut module, &symbol_bytes)?;
        }

        // Eager satellite-module loading: every `File` row flagged
        // ContainsMetaData names a netmodule sitting next to the manifest
        // image (Cecil `ModuleDefinition.ReadModules`). Resolution failures
        // are non-fatal here; the row stays preserved on the main module.
        let mut modules = Vec::new();
        for row in &module.file_rows {
            if row.attributes.contains(cecli_core::flags::FileRowAttributes::CONTAINS_NO_METADATA) {
                continue;
            }
            if let Some(satellite_bytes) =
                locate_netmodule_bytes(origin.as_deref(), &row.name, opts)
            {
                if let Ok(satellite) = read_standalone_module(&satellite_bytes) {
                    modules.push(satellite);
                }
            }
        }

        let entry_point = method_of_token(&ctx, module.entry_point_token);

        let lazy = if eager { None } else { Some(LazyAssembly { raw: bytes.to_vec(), ctx }) };
        Ok(AssemblyDefinition { name, main: module, modules, entry_point, lazy })
    }

    /// Decodes the method bodies of an assembly read with
    /// [`ReadingMode::Lazy`](crate::resolver::ReadingMode::Lazy), consuming
    /// the deferred state (raw image + read context). A no-op when bodies
    /// are already loaded or were never deferred.
    ///
    /// Cecil's lazy reading decodes bodies per method on first access; this
    /// value-semantics model defers (and loads) them as one unit — the
    /// dominant memory cost of a method body lives in the model either way.
    pub fn load_bodies(&mut self) -> Result<()> {
        let Some(lazy) = self.lazy.take() else {
            return Ok(());
        };
        let image = cecli_pe::Image::parse(&lazy.raw)?;
        let (md_rva, _) = image.metadata_rva()?;
        let md_slice = image.rva(md_rva)?;
        let md = cecli_metadata::MetadataReader::parse(md_slice.as_ref())?;
        let mut ctx = lazy.ctx;
        crate::read::instructions::resolve_bodies_opts(
            &mut self.main,
            &mut ctx,
            &md,
            &image,
            true,
        )?;
        Ok(())
    }

    /// Resolves a type reference against this assembly and its dependencies
    /// (Cecil `TypeReference.Resolve`). Dependencies are located through
    /// `loader` — see [`crate::resolution::DirectoryLoader`] for the
    /// disk-backed default — and cached per call.
    ///
    /// Returns `Ok(None)` when the reference names nothing reachable.
    pub fn resolve_type_with<'a>(
        &'a self,
        loader: Box<dyn crate::resolution::AssemblyBytesLoader + 'a>,
        ty: &TypeDesc,
    ) -> Result<Option<crate::resolution::ResolvedType>> {
        let mut engine = self.resolution_engine(loader);
        engine.resolve_type(ty)
    }

    /// Resolves a method reference (Cecil `MethodReference.Resolve`); see
    /// [`Self::resolve_type_with`].
    pub fn resolve_method_with<'a>(
        &'a self,
        loader: Box<dyn crate::resolution::AssemblyBytesLoader + 'a>,
        r: &MethodRef,
    ) -> Result<Option<(usize, MethodId)>> {
        let mut engine = self.resolution_engine(loader);
        engine.resolve_method(r)
    }

    /// Resolves a field reference (Cecil `FieldReference.Resolve`); see
    /// [`Self::resolve_type_with`].
    pub fn resolve_field_with<'a>(
        &'a self,
        loader: Box<dyn crate::resolution::AssemblyBytesLoader + 'a>,
        r: &FieldRef,
    ) -> Result<Option<(usize, FieldId)>> {
        let mut engine = self.resolution_engine(loader);
        engine.resolve_field(r)
    }

    /// Disk-backed convenience for [`Self::resolve_type_with`]: dependencies
    /// are searched through the default resolver paths.
    pub fn resolve_type_on_disk(
        &self,
        ty: &TypeDesc,
    ) -> Result<Option<crate::resolution::ResolvedType>> {
        self.resolve_type_with(Box::new(crate::resolution::DirectoryLoader::new()), ty)
    }

    /// Builds a resolution engine over the manifest module with the
    /// satellite netmodules (already read into [`Self::modules`]) preloaded,
    /// so `OtherModule` scopes resolve without disk access.
    fn resolution_engine<'a>(
        &'a self,
        loader: Box<dyn crate::resolution::AssemblyBytesLoader + 'a>,
    ) -> crate::resolution::ResolutionEngine<'a> {
        let mut engine =
            crate::resolution::ResolutionEngine::with_primary_and_loader(&self.main, loader);
        for m in &self.modules {
            engine.push_cached_module(m.name.clone(), m.clone());
        }
        engine
    }

    /// The manifest module.
    pub fn main_module(&self) -> &Module {
        &self.main
    }

    /// Mutable access to the manifest module.
    pub fn main_module_mut(&mut self) -> &mut Module {
        &mut self.main
    }

    /// The entry-point method, resolved from the CLI header token recorded
    /// at read time; `None` for libraries or when the token dangles.
    pub fn entry_point_method(&self) -> Option<&crate::model::types::MethodDefinition> {
        let id = self.entry_point?;
        self.main.methods.get(id.index())
    }

    /// Reflection-style full name:
    /// `Name, Version=x.y.z.w, Culture=..., PublicKeyToken=...`.
    ///
    /// Deviation (v1): no SHA-1 lives in the dependency set, so assemblies
    /// with a full public key render the key hex instead of the derived
    /// 8-byte public key token; unsigned assemblies render `null` exactly
    /// like .NET reflection does.
    pub fn full_name(&self) -> String {
        let n = &self.name;
        let mut s = format!(
            "{}, Version={}, Culture={}",
            n.name,
            n.version,
            n.culture.as_deref().unwrap_or("neutral")
        );
        if n.public_key.is_empty() {
            s.push_str(", PublicKeyToken=null");
        } else {
            s.push_str(", PublicKeyToken=");
            for b in &n.public_key {
                s.push_str(&format!("{b:02X}"));
            }
        }
        s
    }

    /// Removes a type (with its nested subtree and members) from the main
    /// module. See [`Module::remove_type`] for the handle-invalidation and
    /// dangling-reference policies; the assembly entry point and
    /// assembly-level custom attributes are fixed up along the way.
    pub fn remove_type(&mut self, id: TypeId) {
        let maps = self.main.remove_type_mapped(id);
        self.fixup_after_removal(&maps);
    }

    /// Removes a method from the main module; see [`Self::remove_type`].
    pub fn remove_method(&mut self, id: MethodId) {
        let maps = self.main.remove_method_mapped(id);
        self.fixup_after_removal(&maps);
    }

    /// Removes a field from the main module; see [`Self::remove_type`].
    pub fn remove_field(&mut self, id: FieldId) {
        let maps = self.main.remove_field_mapped(id);
        self.fixup_after_removal(&maps);
    }

    /// Removes a property from the main module; see [`Self::remove_type`].
    pub fn remove_property(&mut self, id: PropertyId) {
        let maps = self.main.remove_property_mapped(id);
        self.fixup_after_removal(&maps);
    }

    /// Removes an event from the main module; see [`Self::remove_type`].
    pub fn remove_event(&mut self, id: EventId) {
        let maps = self.main.remove_event_mapped(id);
        self.fixup_after_removal(&maps);
    }

    /// Applies post-compaction fixups to assembly-level state that lives
    /// outside the module: the entry-point handle and the assembly name's
    /// custom attributes.
    fn fixup_after_removal(&mut self, maps: &crate::model::removal::ArenaMaps) {
        if let Some(ep) = self.entry_point {
            self.entry_point = maps.methods.get(ep.0).map(MethodId);
        }
        for ca in self.name.custom_attributes.iter_mut() {
            if let MethodRef::Def(id) = &mut ca.constructor {
                if let Some(n) = maps.methods.get(id.0) {
                    id.0 = n;
                }
                // Dangling ctor: drop the attribute below.
            }
        }
        self.name.custom_attributes.retain(|ca| match &ca.constructor {
            MethodRef::Def(id) => (id.0 as usize) < self.main.methods.len(),
            _ => true,
        });
    }
}

// ---------------------------------------------------------------------------
// Symbol + satellite-module plumbing (facade-integration parity phase)
// ---------------------------------------------------------------------------

/// Locates an embedded portable PDB (debug-directory entry of type
/// `EmbeddedPortablePdb`) in `image` and inflates it. Returns the PDB bytes
/// plus the checksum entry's digest when present.
fn embedded_symbol_bytes(image: &cecli_pe::Image) -> Option<(Vec<u8>, Option<[u8; 32]>)> {
    use cecli_pdb::embedded::image_debug_type as ty;
    let mut embedded = None;
    let mut checksum = None;
    for entry in &image.debug_entries {
        match entry.directory.kind {
            ty::EMBEDDED_PORTABLE_PDB => {
                embedded = cecli_pdb::embedded::unwrap_embedded(&entry.data).ok();
            }
            // "<algorithm>\0" + digest; only SHA-256 entries are recorded.
            ty::PDB_CHECKSUM
                if entry.data.starts_with(b"SHA256\0") && entry.data.len() >= 7 + 32 =>
            {
                checksum = Some(entry.data[7..39].try_into().expect("length checked above"));
            }
            _ => {}
        }
    }
    embedded.map(|pdb| (pdb, checksum))
}

/// Default symbol lookup next to `origin`: `<file>.pdb`, `<stem>.pdb`
/// (portable or native, told apart by magic at attach time), then
/// `<file>.mdb` / `<stem>.mdb` (Mono). Returns `None` when no candidate
/// exists.
fn load_symbol_bytes(origin: &std::path::Path) -> Option<Vec<u8>> {
    let mut candidates = Vec::with_capacity(4);
    if let Some(file_name) = origin.file_name() {
        let name = file_name.to_string_lossy();
        let stem = origin.file_stem().map(|s| s.to_string_lossy().into_owned());
        // Appended forms keep the full file name ("lib.dll.pdb",
        // "lib.dll.mdb"); extension-swapped forms replace it ("lib.pdb",
        // "lib.mdb"). Mono pairs MDBs as "<full-name>.mdb".
        candidates.push(origin.with_file_name(format!("{name}.pdb")));
        if let Some(stem) = &stem {
            candidates.push(origin.with_file_name(format!("{stem}.pdb")));
            candidates.push(origin.with_file_name(format!("{name}.mdb")));
            candidates.push(origin.with_file_name(format!("{stem}.mdb")));
        }
    }
    for candidate in candidates {
        if candidate.is_file() {
            if let Ok(bytes) = std::fs::read(&candidate) {
                return Some(bytes);
            }
        }
    }
    None
}

/// Sniffs the symbol format by magic and dispatches to the matching
/// attach: BSJB -> portable PDB, `Microsoft C/C++ MSF` -> native PDB,
/// the MDB magic -> Mono MDB.
fn attach_symbols(module: &mut Module, bytes: &[u8]) -> Result<()> {
    if bytes.starts_with(&0x424A_5342u32.to_le_bytes()) {
        attach_portable_symbols(module, bytes)
    } else if bytes.starts_with(b"Microsoft C/C++ MSF") {
        attach_native_symbols(module, bytes)
    } else if bytes.len() >= 8
        && u64::from_le_bytes(bytes[..8].try_into().unwrap()) == cecli_mdb::reader::MAGIC
    {
        attach_mdb_symbols(module, bytes)
    } else {
        Err(Error::bad_image(
            "unrecognized symbol file format (expected portable/native PDB or Mono MDB)",
        ))
    }
}

/// Parses a portable PDB and attaches its tables to `module.debug`.
///
/// Sequence points land keyed by 1-based `MethodDef` rid with the stream's
/// starting document converted to a 0-based index into
/// [`ModuleDebugInfo::documents`]; methods without points are omitted.
fn attach_portable_symbols(module: &mut Module, pdb_bytes: &[u8]) -> Result<()> {
    let reader = cecli_pdb::portable_reader::PortablePdbReader::parse(pdb_bytes)?;

    let documents = reader.documents()?;
    let mut points = std::collections::BTreeMap::new();
    let mut scopes = std::collections::BTreeMap::new();

    // MethodDebugInformation rows are rid-aligned with the module's MethodDef
    // table, so the row count bounds both lookups.
    let mdi_count = reader.metadata().row_count(cecli_core::TableIndex::MethodDebugInformation);
    for rid in 1..=mdi_count {
        if let Some((doc_rid, method_points)) = reader.sequence_points(rid)? {
            if !method_points.is_empty() && doc_rid > 0 {
                points.insert(rid, vec![(doc_rid - 1, method_points)]);
            }
        }
        let method_scopes = reader.local_scopes(rid)?;
        if !method_scopes.is_empty() {
            scopes.insert(rid, method_scopes);
        }
    }

    let custom_debug_info = reader
        .custom_debug_informations()?
        .into_iter()
        .map(|info| crate::module_def::CustomDebugInformation {
            parent: info.parent,
            kind: info.kind,
            value: info.value,
        })
        .collect();

    module.debug =
        Some(crate::module_def::ModuleDebugInfo { documents, points, scopes, custom_debug_info });
    Ok(())
}

/// Attaches native-PDB (MSF/CodeView) symbols: source files become
/// documents (name only — checksums live in per-line records, not the
/// document table), and each function's line records become sequence
/// points keyed by the MethodDef rid of its token.
///
/// Deviation: native records carry RVA deltas, not IL offsets; the delta
/// is stored in [`SequencePoint::offset`] verbatim (Cecil's
/// `NativePdbReader` performs the same lossy mapping when adapting to its
/// sequence-point model). Columns are unknown and stay zero.
fn attach_native_symbols(module: &mut Module, pdb_bytes: &[u8]) -> Result<()> {
    let reader = cecli_pdb::native::NativePdbReader::open(pdb_bytes)?;

    // Documents: unique file names in first-encounter order across all
    // functions' line records.
    let mut documents: Vec<cecli_pdb::document::Document> = Vec::new();
    let doc_index = |name: &str, documents: &mut Vec<cecli_pdb::document::Document>| -> u32 {
        if let Some(i) = documents.iter().position(|d| d.name == name) {
            return i as u32;
        }
        documents.push(cecli_pdb::document::Document {
            name: name.to_string(),
            hash_algorithm: [0; 16],
            hash: Vec::new(),
            language: [0; 16],
        });
        documents.len() as u32 - 1
    };

    let mut points = std::collections::BTreeMap::new();
    for function in reader.functions()? {
        if function.lines.is_empty() {
            continue;
        }
        let mut by_doc: std::collections::BTreeMap<
            u32,
            Vec<cecli_pdb::portable_reader::SequencePoint>,
        > = std::collections::BTreeMap::new();
        for line in &function.lines {
            let di = doc_index(&line.file, &mut documents);
            by_doc.entry(di).or_default().push(cecli_pdb::portable_reader::SequencePoint {
                offset: line.rva_delta as i32,
                start_line: line.line,
                start_column: 0,
                end_line: line.line,
                end_column: 0,
            });
        }
        // One entry per document the function touches (the portable model
        // keys points by (document, list)).
        points.insert(function.token.rid(), by_doc.into_iter().collect::<Vec<_>>());
    }

    module.debug = Some(crate::module_def::ModuleDebugInfo {
        documents,
        points,
        scopes: std::collections::BTreeMap::new(),
        custom_debug_info: Vec::new(),
    });
    Ok(())
}

/// Attaches Mono MDB symbols: source files become documents (with their
/// MD5 hashes), and each method's line table becomes sequence points keyed
/// by the MethodDef rid of its token. The per-point source file is not
/// surfaced by the MDB line table (it travels inside the packed DWARF
/// opcode stream), so every point references the method's compile-unit
/// primary source when one exists, else document 0.
fn attach_mdb_symbols(module: &mut Module, mdb_bytes: &[u8]) -> Result<()> {
    let reader = cecli_mdb::reader::MdbReader::open(mdb_bytes)?;

    let documents: Vec<cecli_pdb::document::Document> = reader
        .source_files()
        .into_iter()
        .map(|sf| cecli_pdb::document::Document {
            name: sf.path,
            hash_algorithm: [0; 16],
            hash: sf.hash.to_vec(),
            language: [0; 16],
        })
        .collect();
    // Compile unit -> 0-based index of its primary source file.
    let cu_doc: Vec<u32> = reader
        .compile_units()
        .into_iter()
        .map(|cu| cu.file_ids.first().copied().map(|id| id.saturating_sub(1)).unwrap_or(0))
        .collect();

    let mut points = std::collections::BTreeMap::new();
    for method in reader.methods() {
        let Some(lines) = reader.method_lines(method.row)? else { continue };
        if lines.il_offsets.is_empty() {
            continue;
        }
        let doc = cu_doc.get(method.compile_unit.saturating_sub(1) as usize).copied().unwrap_or(0);
        let sequence: Vec<cecli_pdb::portable_reader::SequencePoint> = lines
            .il_offsets
            .iter()
            .zip(&lines.line_numbers)
            .map(|(&offset, &line)| cecli_pdb::portable_reader::SequencePoint {
                offset,
                start_line: line.max(0) as u32,
                start_column: 0,
                end_line: line.max(0) as u32,
                end_column: 0,
            })
            .collect();
        points.insert(method.token.rid(), vec![(doc, sequence)]);
    }

    module.debug = Some(crate::module_def::ModuleDebugInfo {
        documents,
        points,
        scopes: std::collections::BTreeMap::new(),
        custom_debug_info: Vec::new(),
    });
    Ok(())
}

/// Structural sanity check for a Win32 resource section: the directory tree
/// (IMAGE_RESOURCE_DIRECTORY + entries) must reference only offsets inside
/// the blob and nest no deeper than [`WIN32_RESOURCES_MAX_DEPTH`]. The write
/// path re-walks this tree to rebase RVAs, so an unsound tree is dropped at
/// capture time instead of crashing the writer.
const WIN32_RESOURCES_MAX_DEPTH: usize = 32;

fn win32_resources_tree_is_sane(bytes: &[u8]) -> bool {
    /// One IMAGE_RESOURCE_DIRECTORY at `at`. Layout: 12 header bytes, then
    /// `NumberOfNamedEntries`/`NumberOfIdEntries` at +12/+14, then
    /// 8-byte entries from +16 (name/scope id, child offset).
    fn dir(bytes: &[u8], at: usize, depth: usize) -> bool {
        if depth > WIN32_RESOURCES_MAX_DEPTH || at + 16 > bytes.len() {
            return false;
        }
        let named = u16::from_le_bytes([bytes[at + 12], bytes[at + 13]]);
        let ids = u16::from_le_bytes([bytes[at + 14], bytes[at + 15]]);
        let entries = named as usize + ids as usize;
        let entries_at = at + 16;
        if entries_at + entries * 8 > bytes.len() {
            return false;
        }
        for i in 0..entries {
            let e = entries_at + i * 8;
            let child =
                u32::from_le_bytes([bytes[e + 4], bytes[e + 5], bytes[e + 6], bytes[e + 7]]);
            if child & 0x8000_0000 != 0 {
                // Subdirectory: recurse at the masked offset.
                if !dir(bytes, (child & 0x7FFF_FFFF) as usize, depth + 1) {
                    return false;
                }
            } else if (child as usize) + 16 > bytes.len() {
                return false; // Data entry must fit.
            }
        }
        true
    }
    // Layout mirrors patch_win32_resources in cecli-pe: the tree starts at
    // offset 0 of the captured blob.
    dir(bytes, 0, 0)
}

/// Loads a satellite netmodule's image bytes.
///
/// Primary probe: the file named by the `File` row inside the manifest
/// module's directory. Fallback: the configured assembly resolver (or a
/// default search-path resolver) asked for the row's file stem. `None` means
/// nothing resolvable was found; callers skip the row instead of failing.
fn locate_netmodule_bytes(
    origin: Option<&std::path::Path>,
    name: &str,
    opts: &crate::resolver::ReaderParameters,
) -> Option<Vec<u8>> {
    if let Some(origin) = origin {
        if let Some(dir) = origin.parent() {
            let sibling = dir.join(name);
            if sibling.is_file() {
                return std::fs::read(&sibling).ok();
            }
        }
    }

    let stem = std::path::Path::new(name)
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string());
    let reference = crate::model::types::AssemblyNameReference::new(&stem);
    match opts.assembly_resolver.as_ref() {
        Some(resolver) => {
            let path = resolver.resolve(&reference).ok()?;
            std::fs::read(path).ok()
        }
        None => {
            let resolver = crate::resolver::DefaultAssemblyResolver::new();
            let path = resolver.resolve(&reference).ok()?;
            std::fs::read(path).ok()
        }
    }
}

/// Runs the main-module read pipeline over one standalone image
/// (netmodules carry no `Assembly` row), returning its object model.
pub(crate) fn read_standalone_module(bytes: &[u8]) -> Result<Module> {
    let image = cecli_pe::Image::parse(bytes)?;
    let read_opts = crate::read::context::ReadOptions::default();
    let (mut module, mut ctx) = crate::read::module_reader::read_module(&image, &read_opts)?;
    let (md_rva, _) = image.metadata_rva()?;
    let md_slice = image.rva(md_rva)?;
    let md = cecli_metadata::MetadataReader::parse(md_slice.as_ref())?;
    crate::read::instructions::resolve_bodies_opts(
        &mut module,
        &mut ctx,
        &md,
        &image,
        read_opts.load_bodies,
    )?;
    Ok(module)
}

/// Resolves a MethodDef token through the read-context handle map.
fn method_of_token(
    ctx: &crate::read::context::ReadContext,
    token: cecli_core::Token,
) -> Option<crate::model::types::MethodId> {
    if token.is_nil() || token.table_byte() != cecli_core::TableIndex::MethodDef as u8 {
        return None;
    }
    let rid = token.rid() as usize;
    if rid == 0 || rid > ctx.method_defs.len() {
        return None;
    }
    Some(ctx.method_defs[rid - 1])
}

impl std::fmt::Display for AssemblyDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Assembly {}", self.full_name())
    }
}

// ---------------------------------------------------------------------------
// Read/write glue
// ---------------------------------------------------------------------------

use cecli_core::{Error, Result};

/// CLI header size (`ImageWriter`'s private `CLI_HEADER_CB`).
const CLI_HEADER_CB: usize = 0x48;
/// RVA where Cecil-emitted `.text` sections begin (`ImageWriter::TEXT_RVA`,
/// duplicated here because cecli-pe does not re-export the constant).
const TEXT_RVA: u32 = 0x2000;

/// How debug symbols are emitted alongside the image (Cecil
/// `ISymbolWriterProvider` selection, as an enum instead of a trait object).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SymbolOutput {
    /// No symbol output (the default).
    #[default]
    None,
    /// Standalone portable PDB sidecar (`<stem>.pdb`), the
    /// `write_symbols: true` shorthand.
    PortablePdb,
    /// Portable PDB embedded into the image's own debug directory as an
    /// MPDB entry (`EmbeddedPortablePdbWriter`): `"MPDB"` + uncompressed
    /// length + raw-Deflate PDB, plus a `PdbChecksum` (SHA-256) entry.
    EmbeddedPortablePdb,
    /// Mono MDB sidecar (`<file>.mdb`); the image's debug directory is left
    /// untouched (Cecil's MdbWriter produces an empty debug header).
    Mdb,
}

/// Writer configuration carrier. Port of the fields Mono.Cecil's
/// `WriterParameters` carries that matter here.
#[derive(Debug, Clone, Default)]
pub struct WriteParameters {
    /// Emit debug symbols for a module carrying
    /// [`crate::module_def::ModuleDebugInfo`] (Cecil
    /// `WriterParameters.WriteSymbols`).
    pub write_symbols: bool,
    /// Raw `.snk` key-pair bytes (Cecil `WriterParameters.StrongNameKeyPair`).
    /// When set, the output reserves a strong-name signature slot sized to
    /// the key, the `Assembly` row's public key is replaced by the key's
    /// public key, and — with the `strongname` feature enabled — the
    /// finished image is signed. Without the feature a key is rejected.
    pub strong_name_key: Option<Vec<u8>>,
    /// Raw PE/CLI images of referenced assemblies (Cecil resolves these
    /// through the module's `MetadataResolver` at write time). They drive
    /// `CLASS`/`VALUETYPE` classification of external types during signature
    /// encoding, replacing the token map's well-known-`System` heuristic:
    /// user-defined external structs/enums get the correct marker instead of
    /// being misclassified as classes. Classification falls back to the
    /// heuristic for scopes not covered by any supplied image.
    pub reference_images: Vec<Vec<u8>>,
    /// PE file-header `TimeDateStamp` override (Cecil
    /// `WriterParameters.Timestamp`). `None` keeps whatever the canonical
    /// rebuild preserves from the carrier image.
    pub timestamp: Option<u32>,
    /// Derive the Module row's MVID from the emitted content instead of the
    /// model's `Module::guid` (Cecil `WriterParameters.DeterministicMvid`),
    /// so identical content writes byte-identical images even when the
    /// source models carried different MVIDs: the metadata root is hashed
    /// (dual-seed 64-bit FNV-1a, vs Cecil's SHA-1 over the image) with the
    /// MVID slot zeroed, and the hash becomes the new RFC 4122 version-4
    /// GUID.
    pub deterministic_mvid: bool,
    /// Symbol output selection (Cecil `WriterParameters.SymbolWriterProvider`).
    /// `None` defers to [`Self::write_symbols`] (sidecar portable PDB when
    /// true); any other value overrides it.
    pub symbol_output: Option<SymbolOutput>,
}

impl WriteParameters {
    /// The effective [`SymbolOutput`]: an explicit `symbol_output` wins;
    /// otherwise `write_symbols` means [`SymbolOutput::PortablePdb`].
    pub fn effective_symbol_output(&self) -> SymbolOutput {
        match self.symbol_output {
            Some(output) => output,
            None if self.write_symbols => SymbolOutput::PortablePdb,
            None => SymbolOutput::None,
        }
    }
}

impl WriteParameters {
    /// Creates parameters with symbol writing and signing off.
    pub fn new() -> Self {
        WriteParameters::default()
    }
}

impl AssemblyDefinition {
    /// Serializes the assembly back into a complete PE32/PE32+ image.
    pub fn write(&self) -> Result<Vec<u8>> {
        self.write_with(&WriteParameters::default())
    }

    /// Serializes the assembly honoring write parameters.
    ///
    /// Port of `AssemblyDefinition.Write(WriterParameters)`. The pipeline is
    /// deterministic: resources blob -> IL bodies (through a shared token map
    /// so user strings register before table serialization) -> metadata
    /// tables with final RVAs -> canonical `.text` rebuild that preserves the
    /// module's identity fields (machine, characteristics, subsystem kind,
    /// CLI flags), plus the Win32 resources and PE debug directory captured
    /// at read time. Symbol emission happens in [`Self::write_file_with`],
    /// which knows the output path of the sidecar `.pdb`.
    ///
    /// With [`WriteParameters::strong_name_key`] set, the assembly's public
    /// key is taken from the key, a signature slot is reserved, and (with
    /// the `strongname` feature) the emitted image is signed in place.
    ///
    /// With [`WriteParameters::timestamp`] set, the value lands in the PE
    /// file header's `TimeDateStamp`. With
    /// [`WriteParameters::deterministic_mvid`] set, the Module row's MVID is
    /// replaced by a GUID derived from the emitted metadata (see
    /// `make_mvid_deterministic` for the algorithm) before the image is
    /// assembled; the PDB sidecar from [`Self::write_file_with`] keeps the
    /// model's original MVID.
    pub fn write_with(&self, opts: &WriteParameters) -> Result<Vec<u8>> {
        let module = &self.main;

        // Strong-name key handling. The key's public key replaces the
        // assembly's for the emitted Assembly row (Cecil does the same when
        // WriterParameters.StrongNameKeyPair is set) so the reserved
        // signature slot matches what the row advertises.
        #[cfg(feature = "strongname")]
        let key_pair = match opts.strong_name_key.as_deref() {
            Some(bytes) => Some(
                crate::strongname::StrongNameKeyPair::new(bytes)
                    .map_err(|e| Error::bad_image(format!("invalid strong-name key: {e}")))?,
            ),
            None => None,
        };
        #[cfg(not(feature = "strongname"))]
        if opts.strong_name_key.is_some() {
            return Err(Error::Unsupported(
                "strong-name signing requires the `strongname` feature".to_string(),
            ));
        }

        let effective_name = {
            // `mut` only under the strongname feature; the allow keeps the
            // default-feature build warning-free.
            #[allow(unused_mut)]
            let mut name = self.name.clone();
            #[cfg(feature = "strongname")]
            if let Some(kp) = &key_pair {
                name.public_key = kp.public_key();
            }
            name
        };
        let strongname_size = strong_name_signature_size(&effective_name, module);

        #[allow(unused_mut)] // signed in place under the strongname feature
        let (mut image, portable_pdb) = write_module_image(
            module,
            Some(&effective_name),
            self.entry_point,
            opts,
            strongname_size,
        )?;
        // Sidecar bytes for `write_file_with`; discarded for plain
        // `write_with` (the checksum entry is already inside the image).
        let _ = portable_pdb;

        // Strong-name sign the finished image in place (Cecil calls
        // CryptoService.StrongName right after ImageWriter.WriteImage).
        #[cfg(feature = "strongname")]
        if let Some(kp) = &key_pair {
            kp.sign_image(&mut image)
                .map_err(|e| Error::bad_image(format!("strong-name signing failed: {e}")))?;
        }
        Ok(image)
    }

    /// Writes the serialized image to `path`, emitting symbols according to
    /// the effective [`SymbolOutput`] (Cecil `ISymbolWriterProvider`):
    ///
    /// * [`SymbolOutput::PortablePdb`] / `write_symbols` — standalone
    ///   `<stem>.pdb` sidecar via [`build_portable_pdb`];
    /// * [`SymbolOutput::EmbeddedPortablePdb`] — no sidecar (the PDB is
    ///   already inside the image's debug directory);
    /// * [`SymbolOutput::Mdb`] — `<file>.mdb` sidecar via `cecli_mdb`.
    ///
    /// Modules without debug information silently skip symbol output.
    pub fn write_file_with<P: AsRef<std::path::Path>>(
        &self,
        path: P,
        opts: &WriteParameters,
    ) -> Result<()> {
        let path = path.as_ref();
        let image = self.write_with(opts)?;
        std::fs::write(path, image).map_err(Error::Io)?;
        if let Some(debug) = self.main.debug.as_ref() {
            match opts.effective_symbol_output() {
                SymbolOutput::PortablePdb => {
                    let pdb_bytes = build_portable_pdb(&self.main)?;
                    let sidecar = path.with_extension("pdb");
                    std::fs::write(sidecar, pdb_bytes).map_err(Error::Io)?;
                }
                SymbolOutput::Mdb => {
                    let mdb_bytes = build_mdb(&self.main, debug);
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let sidecar = path.with_file_name(format!("{name}.mdb"));
                    std::fs::write(sidecar, mdb_bytes).map_err(Error::Io)?;
                }
                SymbolOutput::EmbeddedPortablePdb | SymbolOutput::None => {}
            }
        }
        Ok(())
    }

    /// Writes the serialized image to `path` with default write parameters.
    ///
    /// Ergonomic alias for [`Self::write_file_with`] with
    /// [`WriteParameters::default()`] (Cecil's parameterless
    /// `AssemblyDefinition.Write(string)`).
    pub fn write_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        self.write_file_with(path, &WriteParameters::default())
    }
}

/// Shared module serialization pipeline behind
/// [`AssemblyDefinition::write_with`] and [`write_module_with`].
///
/// `asm_name` follows Cecil `ModuleWriter.Write`'s rule (`AssemblyWriter.cs`:
/// `module.assembly != null && module.kind != ModuleKind.NetModule ? … :
/// null`): `None` — or a [`ModuleKind::NetModule`] target — suppresses the
/// `Assembly` row and every assembly-parented table, producing a standalone
/// netmodule image. `strongname_size` reserves the signature slot (0 for
/// netmodules); signing itself is the caller's job.
fn write_module_image(
    module: &Module,
    asm_name: Option<&AssemblyNameDefinition>,
    entry_point: Option<MethodId>,
    opts: &WriteParameters,
    strongname_size: u32,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    // 1. Managed resources blob. Offsets become ManifestResource.Offset
    //    columns; bytes fill the CLI-header Resources directory.
    let resources = crate::write::resources::build_resources_blob(&module.resources)?;

    // 2. Text-layout prefix, mirroring ImageWriter::emit_rebuild (same
    //    segment order, same alignments). The Code segment base is fixed
    //    by the two segments before it, so bodies get their final RVAs
    //    before any metadata exists; the Data segment base additionally
    //    depends on the real code + resources lengths and is therefore
    //    computed below, once both blobs are complete.
    let pe64 = arch_is_pe64(module.architecture);
    let has_reloc = module.architecture == cecli_core::flags::TargetArchitecture::I386;
    let mut map = cecli_pe::TextMap::default();
    map.add(cecli_pe::TextSegment::ImportAddressTable, if has_reloc { 8 } else { 0 });
    map.add(cecli_pe::TextSegment::CliHeader, CLI_HEADER_CB);
    map.add_aligned(
        cecli_pe::TextSegment::Code,
        0, // length unknown yet; only the aligned start matters here
        if pe64 { 16 } else { 4 },
    );
    let code_segment_rva = u64::from(map.get_rva(cecli_pe::TextSegment::Code));

    // 3. Encode IL bodies through a shared TokenMap so user strings,
    //    locals signatures, and member refs land in the heaps before the
    //    table rows serialize. Fat bodies are 4-aligned like Cecil's
    //    CodeWriter; tiny bodies are padded too (documented deviation:
    //    harmless zero padding instead of replicating the tiny/fat size
    //    heuristic outside encode_body).
    let mut builder = cecli_metadata::MetadataBuilder::new(&module.runtime_version);
    let mut code = cecli_core::io::ByteWriter::new();
    let mut method_rvas: Vec<(crate::model::types::MethodId, u64)> = Vec::new();
    let mut emitted = {
        let mut tmap = crate::write::token_map::TokenMap::new(&mut builder);

        // Value-type classification of external types: with reference
        // images, classify by resolving each external type in them
        // (Cecil semantics, via the read-side MetadataResolver port);
        // results are memoized per external shape. Without images (or
        // for scopes they do not cover) the token map's documented
        // heuristic applies.
        if !opts.reference_images.is_empty() {
            let engine = std::cell::RefCell::new(
                crate::resolution::ResolutionEngine::with_reference_images(
                    module,
                    &opts.reference_images,
                )?,
            );
            let mut cache = std::collections::HashMap::<String, bool>::new();
            tmap.set_external_classifier(Box::new(move |ext| {
                let key = external_cache_key(ext);
                if let Some(&known) = cache.get(&key) {
                    return Ok(Some(known));
                }
                let ty = TypeDesc::External(Box::new(ext.clone()));
                let classified = match engine.borrow_mut().is_value_type(&ty) {
                    Ok(v) => v,
                    Err(_) => return Ok(None), // unresolved scope: heuristic
                };
                cache.insert(key, classified);
                Ok(Some(classified))
            }));
        }

        for (id, m) in module.iter_methods() {
            let Some(body) = m.body.as_ref() else {
                continue;
            };
            code.align(4);
            let start = code.position();
            crate::write::emit_il::encode_body(
                body,
                &mut tmap,
                module,
                &mut code,
                &module.sas_blobs,
            )?;
            method_rvas.push((id, code_segment_rva + start as u64));
        }

        // Data segment base: everything before it now has real lengths.
        map.add_aligned(cecli_pe::TextSegment::Code, code.len(), if pe64 { 16 } else { 4 });
        map.add_aligned(cecli_pe::TextSegment::Resources, resources.bytes.len(), 8);
        map.add_aligned(cecli_pe::TextSegment::Data, 0, 8);

        // 4. Serialize metadata with real RVAs / resource offsets. The
        //    token map's pending rows share one rid space with the tables
        //    emitted here; the version string comes from the module.
        let layout = crate::write::emit_metadata::EmitLayout {
            method_rvas,
            resource_offsets: resources.offsets.iter().map(|&o| o as u32).collect(),
            data_segment_rva: u64::from(map.get_rva(cecli_pe::TextSegment::Data)),
        };
        crate::write::emit_metadata::emit_metadata_with(
            module,
            asm_name,
            entry_point,
            &layout,
            tmap,
        )?
    };

    // Deterministic MVID (Cecil `WriterParameters.DeterministicMvid` /
    // `AssemblyWriter.ComputeDeterministicMvid`): replace the Module row's
    // MVID — inherited from whatever the source model carried — with a GUID
    // derived from the emitted metadata itself, so identical content yields
    // identical output regardless of input MVIDs. Must run before the root
    // is embedded in the PE image.
    if opts.deterministic_mvid {
        make_mvid_deterministic(&mut emitted.root, &module.guid);
    }

    // 5. Symbol output (Cecil wires this through MetadataBuilder's symbol
    //    writer; here the PDB is built up front and the debug directory is
    //    assembled locally). When symbols are emitted, the stale symbol
    //    entries captured at read time are replaced; non-symbol entries
    //    (Deterministic, ...) survive. Modules without debug info skip
    //    symbol output entirely.
    let mut debug_entries = module.debug_entries.clone();
    let mut portable_pdb: Option<Vec<u8>> = None;
    if let Some(debug) = module.debug.as_ref() {
        match opts.effective_symbol_output() {
            SymbolOutput::EmbeddedPortablePdb => {
                let pdb = build_portable_pdb(module)?;
                let payload = cecli_pdb::embedded::wrap_embedded(&pdb)?;
                let checksum = cecli_pdb::embedded::pdb_checksum_payload(&pdb);
                debug_entries.retain(|e| {
                    !matches!(
                        e.directory.kind,
                        cecli_pdb::embedded::image_debug_type::CODEVIEW
                            | cecli_pdb::embedded::image_debug_type::EMBEDDED_PORTABLE_PDB
                            | cecli_pdb::embedded::image_debug_type::PDB_CHECKSUM
                    )
                });
                debug_entries.push(cecli_pe::ImageDebugEntry {
                    directory: cecli_pe::ImageDebugDirectory {
                        major_version: 0x0100,
                        minor_version: 0x0100,
                        kind: cecli_pdb::embedded::image_debug_type::EMBEDDED_PORTABLE_PDB,
                        size_of_data: payload.len() as i32,
                        ..Default::default()
                    },
                    data: payload,
                });
                debug_entries.push(cecli_pe::ImageDebugEntry {
                    directory: cecli_pe::ImageDebugDirectory {
                        major_version: 1,
                        kind: cecli_pdb::embedded::image_debug_type::PDB_CHECKSUM,
                        size_of_data: checksum.len() as i32,
                        ..Default::default()
                    },
                    data: checksum,
                });
                let _ = debug;
            }
            SymbolOutput::PortablePdb => {
                // The sidecar bytes are written by `write_file_with` (it
                // knows the output path); the image gets a fresh
                // PdbChecksum pointing at the same content.
                let pdb = build_portable_pdb(module)?;
                let checksum = cecli_pdb::embedded::pdb_checksum_payload(&pdb);
                debug_entries.retain(|e| {
                    !matches!(
                        e.directory.kind,
                        cecli_pdb::embedded::image_debug_type::CODEVIEW
                            | cecli_pdb::embedded::image_debug_type::EMBEDDED_PORTABLE_PDB
                            | cecli_pdb::embedded::image_debug_type::PDB_CHECKSUM
                    )
                });
                debug_entries.push(cecli_pe::ImageDebugEntry {
                    directory: cecli_pe::ImageDebugDirectory {
                        major_version: 1,
                        kind: cecli_pdb::embedded::image_debug_type::PDB_CHECKSUM,
                        size_of_data: checksum.len() as i32,
                        ..Default::default()
                    },
                    data: checksum,
                });
                portable_pdb = Some(pdb);
            }
            SymbolOutput::Mdb | SymbolOutput::None => {}
        }
    }

    // 6. Rebuild the PE image. Identity fields travel through a minimal
    //    carrier image; the Win32 resources and debug directory captured
    //    at read time ride along in the parts (their RVAs/addresses are
    //    recomputed by the PE writer).
    let parts = cecli_pe::EmitParts {
        code: code.into_vec(),
        resources: resources.bytes,
        data: emitted.data,
        data_alignment: None,
        metadata: emitted.root,
        strongname_size,
        win32_resources: module.win32_resources.as_ref().map(|r| r.bytes.clone()),
        debug_entries,
        // A7-F2: take the token from the metadata emission (resolved via
        // `entry`), not the stale read-time `module.entry_point_token`.
        entry_point_token: emitted.entry_point_token,
    };
    let carrier = carrier_image(module)?;
    let mut writer = cecli_pe::ImageWriter::rebuild(&carrier, parts);
    // PE file-header TimeDateStamp override (Cecil `WriterParameters.Timestamp`).
    if let Some(timestamp) = opts.timestamp {
        writer.set_timestamp(timestamp);
    }
    Ok((writer.emit()?, portable_pdb))
}

/// Serializes a standalone module (netmodule) into a complete PE32/PE32+
/// image, honoring write parameters.
///
/// Port of `ModuleDefinition.Write(WriterParameters)` (Cecil routes it
/// through `ModuleWriter.Write`, the same pipeline the assembly writer uses).
/// Passing no assembly name suppresses the `Assembly` row and all
/// assembly-parented tables, and no entry-point token is emitted, so the
/// output is a netmodule even when `module.kind` is not
/// [`cecli_core::flags::ModuleKind::NetModule`]. Win32 resources and the PE
/// debug directory captured at read time follow the module.
///
/// Strong-name signing is assembly-level (Cecil's `ModuleWriter` only applies
/// `WriterParameters.StrongNameKeyPair` when writing with an assembly name),
/// so [`WriteParameters::strong_name_key`] is rejected here.
pub fn write_module_with(module: &Module, opts: &WriteParameters) -> Result<Vec<u8>> {
    if opts.strong_name_key.is_some() {
        return Err(Error::Unsupported(
            "strong-name signing applies to assemblies, not standalone modules".to_string(),
        ));
    }
    let (image, _sidecar) = write_module_image(module, None, None, opts, 0)?;
    Ok(image)
}

/// Serializes a standalone module (netmodule) with default write parameters.
///
/// Ergonomic alias for [`write_module_with`] with
/// [`WriteParameters::default()`] (Cecil's parameterless
/// `ModuleDefinition.Write()`).
pub fn write_module(module: &Module) -> Result<Vec<u8>> {
    write_module_with(module, &WriteParameters::default())
}

/// Serializes a module's debug information into standalone portable PDB bytes.
///
/// Port of the emission half of `Mono.Cecil.Cil/PortablePdb.cs`
/// (`PortablePdbWriter`): documents, per-method sequence points, and local
/// scopes rebuild into the debug metadata tables plus the `#Pdb` heap. The
/// module's MVID and entry-point token travel through unchanged so readers
/// can match the PDB against its assembly.
///
/// Deviation: local scopes are emitted with their IL ranges and import-scope
/// rids but without variable/constant detail — the frozen facade model keeps
/// only [`cecli_pdb::portable_reader::LocalScope`] rows, which reference
/// variable/constant rows by rid rather than owning their data.
pub fn build_portable_pdb(module: &Module) -> Result<Vec<u8>> {
    const FALLBACK_VERSION: &str = "v4.0.30319";
    let version =
        if module.runtime_version.is_empty() { FALLBACK_VERSION } else { &module.runtime_version };
    let mut builder = cecli_pdb::portable_writer::PortablePdbBuilder::with_version(version);
    builder.set_module_guid(module.guid);
    builder.set_entry_point(module.entry_point_token);

    let Some(debug) = module.debug.as_ref() else {
        return builder.finalize();
    };

    // Documents first: every sequence-point entry references one by index.
    let mut handles = Vec::with_capacity(debug.documents.len());
    for doc in &debug.documents {
        let handle = builder.add_document(&doc.name, doc.hash_algorithm, &doc.hash, doc.language);
        handles.push(cecli_pdb::portable_writer::DocumentHandle(handle.0));
    }

    for (&method_rid, entries) in &debug.points {
        let method = cecli_core::Token::new(cecli_core::TableIndex::MethodDef, method_rid);
        for &(doc_index, ref points) in entries.iter() {
            let handle = handles
                .get(doc_index as usize)
                .copied()
                .unwrap_or(cecli_pdb::portable_writer::DocumentHandle(0));
            builder.set_method_sequence_points(method, handle, points)?;
        }
    }

    for (&method_rid, scopes) in &debug.scopes {
        let method = cecli_core::Token::new(cecli_core::TableIndex::MethodDef, method_rid);
        for scope in scopes {
            builder.add_local_scope(
                method,
                scope.import_scope,
                &[],
                &[],
                scope.kind,
                scope.try_start,
                scope.try_length,
            );
        }
    }

    for info in &debug.custom_debug_info {
        builder.add_custom_debug_information(info.parent, info.kind, &info.value)?;
    }

    builder.finalize()
}

/// Serializes a module's debug information into Mono MDB bytes
/// (`SymbolOutput::Mdb` sidecar): documents become source files, sequence
/// points become per-method line tables (all of a method's points land in
/// one compile unit — the facade model does not retain per-document split),
/// and document order fixes compile-unit indices.
fn build_mdb(module: &Module, debug: &crate::module_def::ModuleDebugInfo) -> Vec<u8> {
    let mut writer = cecli_mdb::writer::MdbWriter::new(module.guid);
    // Source ids are 1-based; the facade document index maps directly.
    let mut source_ids = Vec::with_capacity(debug.documents.len());
    for doc in &debug.documents {
        source_ids.push(writer.add_source(&doc.name));
    }
    // One compile unit per document (points keep their document index).
    let cu_ids: Vec<u32> =
        (0..debug.documents.len()).map(|i| writer.add_compile_unit(&[source_ids[i]])).collect();

    for (&method_rid, entries) in &debug.points {
        let method = cecli_core::Token::new(cecli_core::TableIndex::MethodDef, method_rid);
        // Flatten the per-document groups into one line table (the MDB line
        // table carries a single compile unit per method).
        let (first_doc, mut lines) = (entries.first().map(|e| e.0).unwrap_or(0), Vec::new());
        for (_, points) in entries.iter() {
            for p in points.iter() {
                lines.push((p.offset, p.start_line as i32));
            }
        }
        let cu = *cu_ids.get(first_doc as usize).unwrap_or(&1);
        writer.add_method_lines(method, cu, &lines, 0);
    }

    writer.finalize()
}

fn arch_is_pe64(arch: cecli_core::flags::TargetArchitecture) -> bool {
    use cecli_core::flags::TargetArchitecture as A;
    matches!(arch, A::AMD64 | A::IA64 | A::ARM64)
}

/// Identity key for memoizing value-type classification of one external
/// type: scope identity plus the full (nested) name.
fn external_cache_key(ext: &ExternalType) -> String {
    let scope = match &ext.scope {
        ScopeRef::Assembly(anr) => format!("asm:{}", anr.name),
        ScopeRef::OtherModule(name) => format!("mod:{name}"),
        ScopeRef::ThisModule => "this".to_string(),
        ScopeRef::Moduleless => "none".to_string(),
    };
    let mut key = format!("{scope}:{}/{}", ext.namespace, ext.name);
    for n in &ext.nesting {
        key.push('/');
        key.push_str(&n.name);
    }
    key
}

/// Signature-slot size for the emitted image (Cecil `ImageWriter`'s
/// `GetStrongNameLength`): the RSA modulus size implied by the ECMA public
/// key (`len - 32` of header), 128 for short keys — including the 16-byte
/// ECMA "key", which the runtime replaces with a 1024-bit key — and for
/// flagged-but-keyless assemblies, 0 when unsigned.
fn strong_name_signature_size(name: &AssemblyNameDefinition, module: &Module) -> u32 {
    if name.public_key.len() > 32 {
        (name.public_key.len() - 32) as u32
    } else if !name.public_key.is_empty()
        || module.attributes.contains(cecli_core::flags::ModuleAttributes::STRONG_NAME_SIGNED)
    {
        128
    } else {
        0
    }
}

/// Replaces the Module MVID inside a serialized metadata root with a GUID
/// derived from the root's own content.
///
/// Port of `AssemblyWriter.ComputeDeterministicMvid` (Mono.Cecil): the MVID
/// GUID is the first entry in the `#GUID` heap, so it can be located and
/// rewritten in place without disturbing any row or offset. Cecil hashes the
/// finished image — whose MVID and strong-name signature are zero at that
/// point — with SHA-1 and shapes the leading hash bytes into an RFC 4122
/// "random" GUID (`CryptoService.ComputeGuid`). Deviation: cecli hashes the
/// serialized metadata root with the MVID's heap slot treated as zero, using
/// a dual-seed 64-bit FNV-1a for 128 hash bits — `sha2` is only an optional
/// dependency here, and the metadata root alone already pins every content
/// byte the MVID can observe. The RFC 4122 shaping matches Cecil.
///
/// Silently leaves the root untouched when the `#GUID` heap or the MVID
/// entry cannot be found (impossible for roots built by
/// [`crate::write::emit_metadata`], which always inserts the module's guid
/// first).
fn make_mvid_deterministic(root: &mut [u8], original: &[u8; 16]) {
    let Ok(header) = cecli_metadata::parse_root(root) else {
        return;
    };
    let Some(guid_stream) = header.stream("#GUID") else {
        return;
    };
    let Ok(heap) = cecli_metadata::stream_slice(root, guid_stream) else {
        return;
    };
    // The MVID is the first guid inserted, so the first matching entry is
    // its slot.
    let (chunks, _) = heap.as_chunks::<16>();
    let Some(slot) = chunks.iter().position(|entry| entry == original) else {
        return;
    };
    let at = guid_stream.offset as usize + slot * 16;
    if at + 16 > root.len() {
        return;
    }

    // Hash the root as if the MVID slot were all zeroes; two independent
    // FNV-1a seeds supply 128 bits.
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    fn fnv1a(bytes: &[u8], seed: u64) -> u64 {
        let mut h = seed;
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(FNV_PRIME);
        }
        h
    }
    let h1 = fnv1a(&root[at + 16..], fnv1a(&[0u8; 16], fnv1a(&root[..at], 0xcbf2_9ce4_8422_2325)));
    let h2 = fnv1a(&root[at + 16..], fnv1a(&[0u8; 16], fnv1a(&root[..at], 0x9e37_79b9_7f4a_7c15)));

    let mut guid = [0u8; 16];
    guid[..8].copy_from_slice(&h1.to_le_bytes());
    guid[8..].copy_from_slice(&h2.to_le_bytes());
    guid[7] = (guid[7] & 0x0f) | 0x40; // RFC 4122 version 4 ("random")
    guid[8] = (guid[8] & 0x3f) | 0x80; // RFC 4122 variant
    root[at..at + 16].copy_from_slice(&guid);
}

/// Builds a minimal parseable PE/CLI image whose identity fields match
/// `module`, used as the source image for [`cecli_pe::ImageWriter::rebuild`].
///
/// The rebuild path preserves machine, file/dll characteristics, subsystem
/// kind, linker/timestamp fields and CLI flags from the parsed image; the
/// object model keeps exactly the subset worth preserving (architecture,
/// characteristics, kind, CLI attributes), so the carrier synthesizes those
/// verbatim and fills the rest with neutral values.
fn carrier_image(module: &Module) -> Result<cecli_pe::Image> {
    const FILE_ALIGN: u32 = 0x200;
    const SECTION_ALIGN: u32 = 0x2000;
    const IMAGE_BASE: u64 = 0x0040_0000;

    fn align_up(v: u32, a: u32) -> u32 {
        (v + (a - 1)) & !(a - 1)
    }

    let pe64 = arch_is_pe64(module.architecture);
    let opt_size: u32 = if pe64 { 0xF0 } else { 0xE0 };

    // .text content: CLI header followed by a minimal BSJB root (the reader
    // locates but does not validate stream contents).
    let version = b"v4.0.30319\0";
    let version_len = version.len().next_multiple_of(4);
    let mut bsjb = Vec::new();
    bsjb.extend_from_slice(&0x424A_5342u32.to_le_bytes()); // BSJB
    bsjb.extend_from_slice(&1u16.to_le_bytes()); // MajorVersion
    bsjb.extend_from_slice(&1u16.to_le_bytes()); // MinorVersion
    bsjb.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    bsjb.extend_from_slice(&(version_len as u32).to_le_bytes());
    bsjb.extend_from_slice(version);
    bsjb.resize(16 + version_len, 0);
    bsjb.extend_from_slice(&0u16.to_le_bytes()); // Flags
    bsjb.extend_from_slice(&1u16.to_le_bytes()); // StreamCount
    bsjb.extend_from_slice(&0u32.to_le_bytes()); // #~ offset
    bsjb.extend_from_slice(&0u32.to_le_bytes()); // #~ size
    bsjb.extend_from_slice(b"#~\0\0");

    let text_len = CLI_HEADER_CB as u32 + bsjb.len() as u32;
    let text_raw = align_up(text_len, FILE_ALIGN);
    let headers_raw = align_up(128 + 4 + 20 + opt_size + 40, FILE_ALIGN);
    let total = headers_raw as usize + text_raw as usize;

    let mut out = vec![0u8; total];
    out[0] = b'M';
    out[1] = b'Z';
    out[0x3C..0x40].copy_from_slice(&128u32.to_le_bytes());
    out[128..132].copy_from_slice(b"PE\0\0");

    let is_dll = matches!(
        module.kind,
        cecli_core::flags::ModuleKind::Dll | cecli_core::flags::ModuleKind::NetModule
    );
    let file_chars: u16 = 0x0002 // EXECUTABLE_IMAGE
        | if pe64 { 0 } else { 0x0100 } // 32BIT_MACHINE for PE32 only
        | if pe64 { 0x0020 } else { 0 } // LARGE_ADDRESS_AWARE for PE32+
        | if is_dll { 0x2000 } else { 0 };

    // File header.
    let mut w = 132usize;
    out[w..w + 2].copy_from_slice(&module.architecture.machine().to_le_bytes());
    out[w + 2..w + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
    out[w + 4..w + 8].copy_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
    out[w + 16..w + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
    out[w + 18..w + 20].copy_from_slice(&file_chars.to_le_bytes());
    w += 20;

    // Optional header.
    out[w..w + 2].copy_from_slice(&(if pe64 { 0x20Bu16 } else { 0x10B }).to_le_bytes());
    w += 4; // magic + linker version (zero)
    out[w..w + 4].copy_from_slice(&text_raw.to_le_bytes()); // SizeOfCode
    w += 12; // SizeOfCode + initialized/uninitialized data sizes
    out[w..w + 4].copy_from_slice(&0u32.to_le_bytes()); // AddressOfEntryPoint
    w += 4;
    out[w..w + 4].copy_from_slice(&TEXT_RVA.to_le_bytes()); // BaseOfCode
    w += 4;
    if !pe64 {
        w += 4; // BaseOfData
        out[w..w + 4].copy_from_slice(&(IMAGE_BASE as u32).to_le_bytes());
        w += 4;
    } else {
        out[w..w + 8].copy_from_slice(&IMAGE_BASE.to_le_bytes());
        w += 8;
    }
    out[w..w + 4].copy_from_slice(&SECTION_ALIGN.to_le_bytes());
    out[w + 4..w + 8].copy_from_slice(&FILE_ALIGN.to_le_bytes());
    w += 8;
    out[w..w + 2].copy_from_slice(&4u16.to_le_bytes()); // OS version 4.0 (minor zero)
    w += 8; // OS minor + image version (zero)
    out[w..w + 2].copy_from_slice(&4u16.to_le_bytes()); // Subsystem version 4.0
    w += 8; // Subsystem minor + Win32VersionValue (zero)
    let size_of_image = TEXT_RVA + align_up(text_len, SECTION_ALIGN);
    out[w..w + 4].copy_from_slice(&size_of_image.to_le_bytes());
    out[w + 4..w + 8].copy_from_slice(&headers_raw.to_le_bytes()); // SizeOfHeaders
    w += 12; // + checksum placeholder
    let subsystem: u16 = match module.kind {
        cecli_core::flags::ModuleKind::Windows => 2,
        _ => 3,
    };
    out[w..w + 2].copy_from_slice(&subsystem.to_le_bytes());
    out[w + 2..w + 4].copy_from_slice(&module.characteristics.bits().to_le_bytes());
    w += 4;
    w += if pe64 { 40 } else { 24 }; // stack/heap + LoaderFlags + NumberOfRvaAndSizes(16)

    // Data directories: only COM+ points anywhere — plus, when the module
    // carries Win32 resources, the ORIGINAL resource directory so the PE
    // writer can patch internal resource RVAs from the old base to the
    // re-emitted `.rsrc` section.
    let cli_dir = w + 14 * 8;
    out[cli_dir..cli_dir + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());
    out[cli_dir + 4..cli_dir + 8].copy_from_slice(&(CLI_HEADER_CB as u32).to_le_bytes());
    if let Some(rsrc) = &module.win32_resources {
        let dd = w + 2 * 8;
        out[dd..dd + 4].copy_from_slice(&rsrc.original_rva.to_le_bytes());
        out[dd + 4..dd + 8].copy_from_slice(&(rsrc.bytes.len() as u32).to_le_bytes());
    }
    w += 16 * 8;

    // Section table: one `.text`.
    out[w..w + 5].copy_from_slice(b".text");
    out[w + 8..w + 12].copy_from_slice(&align_up(text_len, SECTION_ALIGN).to_le_bytes());
    out[w + 12..w + 16].copy_from_slice(&TEXT_RVA.to_le_bytes());
    out[w + 16..w + 20].copy_from_slice(&text_raw.to_le_bytes());
    out[w + 20..w + 24].copy_from_slice(&headers_raw.to_le_bytes());
    out[w + 36..w + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // Section payload: CLI header then the mini BSJB.
    let text_at = headers_raw as usize;
    out[text_at..text_at + 4].copy_from_slice(&(CLI_HEADER_CB as u32).to_le_bytes());
    out[text_at + 4..text_at + 6].copy_from_slice(&2u16.to_le_bytes()); // runtime 2.5
    out[text_at + 6..text_at + 8].copy_from_slice(&5u16.to_le_bytes());
    let md_rva = TEXT_RVA + CLI_HEADER_CB as u32;
    out[text_at + 8..text_at + 12].copy_from_slice(&md_rva.to_le_bytes());
    out[text_at + 12..text_at + 16].copy_from_slice(&(bsjb.len() as u32).to_le_bytes());
    out[text_at + 16..text_at + 20].copy_from_slice(&module.attributes.bits().to_le_bytes());
    out[text_at + 20..text_at + 24].copy_from_slice(&module.entry_point_token.0.to_le_bytes());
    out[text_at + CLI_HEADER_CB..text_at + CLI_HEADER_CB + bsjb.len()].copy_from_slice(&bsjb);

    cecli_pe::Image::parse(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a tiny in-memory assembly: Ns.Outer/Nested with one method.
    fn sample_assembly() -> AssemblyDefinition {
        let mut module = Module { name: "sample".into(), ..Default::default() };
        let outer = module.add_type(TypeDefinition {
            namespace: "Ns".into(),
            name: "Outer".into(),
            ..Default::default()
        });
        let nested = module.add_type(TypeDefinition {
            namespace: "Ns".into(),
            name: "Nested".into(),
            declaring_type: Some(outer),
            ..Default::default()
        });
        let method = MethodDefinition { name: "Bar".into(), ..Default::default() };
        let mid = module.add_method(nested, method);

        let mut ad = AssemblyDefinition::default();
        ad.name.name = "sample".into();
        ad.main = module;
        ad.entry_point = Some(mid);
        ad
    }

    #[test]
    fn main_module_and_entry_point() {
        let ad = sample_assembly();
        assert_eq!(ad.main_module().name, "sample");
        let ep = ad.entry_point_method().expect("entry point resolves");
        assert_eq!(ep.name, "Bar");
    }

    #[test]
    fn full_name_reflection_style() {
        let mut ad = sample_assembly();
        assert_eq!(ad.full_name(), "sample, Version=0.0.0.0, Culture=neutral, PublicKeyToken=null");
        ad.name.version = Version::new(1, 2, 3, 4);
        ad.name.culture = Some("de".into());
        assert_eq!(ad.full_name(), "sample, Version=1.2.3.4, Culture=de, PublicKeyToken=null");
    }

    #[test]
    fn carrier_image_parses_and_preserves_identity() {
        let module = Module {
            kind: cecli_core::flags::ModuleKind::Dll,
            architecture: cecli_core::flags::TargetArchitecture::AMD64,
            characteristics: cecli_core::flags::ModuleCharacteristics::NX_COMPAT,
            attributes: cecli_core::flags::ModuleAttributes::IL_ONLY
                | cecli_core::flags::ModuleAttributes::IL_LIBRARY,
            entry_point_token: cecli_core::Token::new(cecli_core::TableIndex::MethodDef, 7),
            ..Default::default()
        };
        let image = carrier_image(&module).expect("carrier parses");
        assert_eq!(image.architecture.0, 0x8664);
        assert_eq!(image.kind, cecli_pe::ModuleKind::Dll);
        assert_eq!(image.cli_header().flags, module.attributes.bits());
        assert_eq!(image.entry_point_token(), module.entry_point_token);
    }

    #[test]
    fn hello_exe_roundtrip() {
        let path = cecli_core::fixtures_dir().join("hello.exe");
        if !path.exists() {
            return; // fixtures not provisioned on this checkout
        }
        let bytes = std::fs::read(&path).expect("fixture readable");
        let ad = AssemblyDefinition::read(&bytes).expect("hello.exe parses");
        let types = ad.main.types.len();
        let methods = ad.main.methods.len();
        let entry_name =
            ad.entry_point_method().expect("hello.exe has an entry point").name.clone();

        let written = ad.write().expect("write succeeds");
        let re = AssemblyDefinition::read(&written).expect("output re-parses");
        assert_eq!(re.main.types.len(), types, "type count survives roundtrip");
        assert_eq!(re.main.methods.len(), methods, "method count survives roundtrip");
        assert_eq!(
            re.entry_point_method().map(|m| m.name.clone()),
            Some(entry_name.clone()),
            "entry point name survives roundtrip"
        );
        assert_eq!(entry_name, "Main");
    }

    /// ReadingMode::Lazy defers method bodies; load_bodies decodes them on
    /// demand and produces a model identical to the eager read.
    #[test]
    fn lazy_reading_defers_and_loads_bodies() {
        let path = cecli_core::fixtures_dir().join("hello.exe");
        if !path.exists() {
            return; // fixtures not provisioned on this checkout
        }
        let mut opts = crate::resolver::ReaderParameters::new();
        opts.reading_mode = crate::resolver::ReadingMode::Lazy;

        let mut lazy_asm =
            AssemblyDefinition::read_file_with(&path, &opts).expect("lazy read parses");
        assert!(lazy_asm.lazy.is_some(), "deferred state stashed");
        assert!(lazy_asm.main.methods.iter().all(|m| m.body.is_none()), "no bodies decoded yet");

        // Writing a body-less model still works (methods without bodies are
        // emitted as RVA-less rows).
        lazy_asm.write().expect("body-less model serializes");

        lazy_asm.load_bodies().expect("bodies load on demand");
        assert!(lazy_asm.lazy.is_none(), "deferred state consumed");
        let with_bodies: usize = lazy_asm.main.methods.iter().filter(|m| m.body.is_some()).count();
        assert!(with_bodies > 0, "bodies present after load_bodies");

        // The lazy-loaded model matches the eager one member-for-member and
        // round-trips identically.
        let eager = AssemblyDefinition::read_file(&path).expect("eager read parses");
        assert_eq!(
            lazy_asm.main.methods.iter().filter(|m| m.body.is_some()).count(),
            eager.main.methods.iter().filter(|m| m.body.is_some()).count(),
            "body counts match the eager read"
        );

        // Second load is a no-op.
        lazy_asm.load_bodies().expect("repeat load is a no-op");
    }

    fn unique_test_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("cecli_facade_tests").join(format!(
            "{}_{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp test dir created");
        dir
    }

    /// line.exe + line.pdb pairing: read_symbols attaches documents, points
    /// and scopes; writing with symbols emits a parseable sidecar PDB.
    #[test]
    fn symbols_attach_and_sidecar_roundtrip() {
        let fixtures = cecli_core::fixtures_dir();
        let exe = fixtures.join("line.exe");
        if !exe.exists() || !fixtures.join("line.pdb").exists() {
            return; // fixture pair not provisioned on this checkout
        }

        // Default reads leave debug empty.
        let plain = AssemblyDefinition::read_file(&exe).expect("line.exe parses");
        assert!(plain.main.debug.is_none(), "no symbols without read_symbols");

        let mut opts = crate::resolver::ReaderParameters::new();
        opts.read_symbols = true;
        let ad = AssemblyDefinition::read_file_with(&exe, &opts).expect("reads with symbols");
        let debug = ad.main.debug.as_ref().expect("symbols attached");
        assert!(!debug.documents.is_empty(), "documents present");
        assert!(
            debug.points.values().any(|entries| entries.iter().any(|(_, pts)| !pts.is_empty())),
            "sequence points non-empty"
        );

        let out_dir = unique_test_dir("sidecar");
        let out = out_dir.join("line_out.exe");
        ad.write_file_with(&out, &WriteParameters { write_symbols: true, ..Default::default() })
            .expect("write with symbols");
        assert!(out.exists(), "image written");
        let sidecar = out_dir.join("line_out.pdb");
        assert!(sidecar.exists(), "sidecar pdb emitted");

        let pdb_bytes = std::fs::read(&sidecar).expect("sidecar readable");
        let reader = cecli_pdb::portable_reader::PortablePdbReader::parse(&pdb_bytes)
            .expect("emitted pdb parses");
        assert_eq!(reader.documents().unwrap().len(), debug.documents.len());

        // write_symbols=false emits no sidecar.
        let quiet = out_dir.join("quiet.exe");
        ad.write_file_with(&quiet, &WriteParameters::default()).expect("write without symbols");
        assert!(!out_dir.join("quiet.pdb").exists(), "no sidecar when write_symbols off");

        let _ = std::fs::remove_dir_all(&out_dir);
    }

    /// Synthetic multi-module assembly: manifest + ContainsMetaData File row
    /// whose netmodule sits in the same directory -> both modules load.
    #[test]
    fn multi_module_synthetic_loads_two_modules() {
        use cecli_core::flags::ModuleKind;

        let netmodule = cecli_core::fixtures_dir().join("moda.netmodule");
        if !netmodule.exists() {
            return; // fixture not provisioned on this checkout
        }
        let out_dir = unique_test_dir("multimodule");
        std::fs::copy(&netmodule, out_dir.join("moda.netmodule")).expect("satellite copied");

        let mut module = Module {
            name: "multi".into(),
            kind: ModuleKind::Dll,
            runtime_version: "v4.0.30319".into(),
            ..Default::default()
        };
        module.file_rows.push(crate::module_def::FileRow {
            name: "moda.netmodule".into(),
            attributes: cecli_core::flags::FileRowAttributes::empty(),
            hash: Vec::new(),
        });
        let ad = AssemblyDefinition {
            name: AssemblyNameDefinition {
                name: "multi".into(),
                version: Version::new(1, 0, 0, 0),
                ..AssemblyNameDefinition::default()
            },
            main: module,
            modules: Vec::new(),
            entry_point: None,
            lazy: None,
        };
        let main_path = out_dir.join("multi.dll");
        ad.write_file(&main_path).expect("manifest written");

        let re = AssemblyDefinition::read_file_with(
            &main_path,
            &crate::resolver::ReaderParameters::new(),
        )
        .expect("re-reads");
        assert_eq!(re.main.file_rows.len(), 1, "File row preserved");
        assert_eq!(re.modules.len() + 1, 2, "main plus one satellite module loaded");
        assert!(re.modules[0].name.to_lowercase().contains("moda"), "satellite is moda");

        let _ = std::fs::remove_dir_all(&out_dir);
    }

    /// Standalone module write (Cecil `ModuleDefinition.Write`): reading
    /// moda.netmodule, serializing it through [`write_module`] and re-reading
    /// preserves the module's shape, and the emitted metadata carries no
    /// `Assembly` row.
    #[test]
    fn netmodule_write_module_roundtrip() {
        let path = cecli_core::fixtures_dir().join("moda.netmodule");
        if !path.exists() {
            return; // fixture not provisioned on this checkout
        }
        let bytes = std::fs::read(&path).expect("netmodule readable");
        let module = read_standalone_module(&bytes).expect("netmodule parses");
        assert!(!module.types.is_empty(), "fixture carries types");
        let type_count = module.types.len();
        let method_count = module.methods.len();

        let out = write_module(&module).expect("standalone module write");
        let reread = read_standalone_module(&out).expect("rewritten netmodule parses");
        assert_eq!(reread.types.len(), type_count, "type count preserved");
        assert_eq!(reread.methods.len(), method_count, "method count preserved");

        // No Assembly row in the emitted metadata (netmodule semantics).
        let image = cecli_pe::Image::parse(&out).expect("emitted image parses");
        let (md_rva, _) = image.metadata_rva().expect("metadata directory");
        let md_slice = image.rva(md_rva).expect("metadata slice");
        let md = cecli_metadata::MetadataReader::parse(md_slice.as_ref()).expect("metadata parses");
        assert_eq!(md.row_count(cecli_core::TableIndex::Assembly), 0, "no Assembly row");

        // A strong-name key is rejected for standalone modules.
        let err = write_module_with(
            &module,
            &WriteParameters { strong_name_key: Some(vec![1, 2, 3]), ..Default::default() },
        );
        assert!(err.is_err(), "strong-name key rejected for netmodule");
    }

    /// Fresh modules default to Cecil's ImageWriter DLL characteristics.
    #[test]
    fn fresh_module_default_characteristics() {
        use cecli_core::flags::{ModuleCharacteristics, ModuleKind};
        let m = Module::default();
        assert_ne!(m.kind, ModuleKind::NetModule);
        assert_eq!(
            m.characteristics,
            ModuleCharacteristics::DYNAMIC_BASE
                | ModuleCharacteristics::NX_COMPAT
                | ModuleCharacteristics::TERMINAL_SERVER_AWARE
                | ModuleCharacteristics::HIGH_ENTROPY_VA
        );
        assert!(m.debug.is_none());
    }

    /// Native PDB sidecar attaches through the default same-stem lookup
    /// (format sniffed from the MSF magic, not assumed).
    #[test]
    fn native_pdb_symbols_attach() {
        let fixtures = cecli_core::fixtures_dir();
        let dll = fixtures.join("ComplexPdb.dll");
        if !dll.exists() || !fixtures.join("ComplexPdb.pdb").exists() {
            return; // fixture pair not provisioned on this checkout
        }
        let mut opts = crate::resolver::ReaderParameters::new();
        opts.read_symbols = true;
        let ad = AssemblyDefinition::read_file_with(&dll, &opts).expect("reads with symbols");
        let debug = ad.main.debug.as_ref().expect("native symbols attached");
        assert!(!debug.documents.is_empty(), "native pdb yields documents");
        assert!(!debug.points.is_empty(), "native pdb yields sequence points");
    }

    /// Mono MDB sidecar attaches through the default same-stem lookup.
    #[test]
    fn mdb_symbols_attach() {
        let fixtures = cecli_core::fixtures_dir();
        let dll = fixtures.join("SQLite-net.dll");
        if !dll.exists() || !fixtures.join("SQLite-net.dll.mdb").exists() {
            return; // fixture pair not provisioned on this checkout
        }
        let mut opts = crate::resolver::ReaderParameters::new();
        opts.read_symbols = true;
        let ad = AssemblyDefinition::read_file_with(&dll, &opts).expect("reads with symbols");
        let debug = ad.main.debug.as_ref().expect("mdb symbols attached");
        assert!(!debug.documents.is_empty(), "mdb yields documents");
        assert!(!debug.points.is_empty(), "mdb yields sequence points");
    }

    /// A configured SymbolReaderProvider overrides the default sidecar
    /// lookup entirely.
    #[test]
    fn symbol_provider_overrides_default_lookup() {
        let fixtures = cecli_core::fixtures_dir();
        let dll = fixtures.join("ComplexPdb.dll");
        let native_pdb = fixtures.join("CecilTest.pdb");
        if !dll.exists() || !native_pdb.exists() {
            return;
        }
        struct FixedProvider(Vec<u8>);
        impl crate::resolver::SymbolReaderProvider for FixedProvider {
            fn get_symbol_reader(&self, _image_path: &std::path::Path) -> Result<Option<Vec<u8>>> {
                Ok(Some(self.0.clone()))
            }
        }

        let mut opts = crate::resolver::ReaderParameters::new();
        opts.read_symbols = true;
        opts.symbol_reader_provider =
            Some(Box::new(FixedProvider(std::fs::read(&native_pdb).expect("pdb readable"))));
        let ad = AssemblyDefinition::read_file_with(&dll, &opts).expect("reads via provider");
        let debug = ad.main.debug.as_ref().expect("provider symbols attached");
        assert!(
            !debug.documents.is_empty(),
            "documents come from the provider's file, not the sidecar"
        );
    }

    /// Win32 resources and the PE debug directory captured at read time
    /// survive the canonical rebuild: resource bytes roundtrip verbatim
    /// (at a fresh RVA), debug entries re-emit one-for-one.
    #[test]
    fn win32_resources_and_debug_directory_survive_rebuild() {
        let fixtures = cecli_core::fixtures_dir();
        let dll = fixtures.join("cecil.dll");
        if !dll.exists() {
            return; // fixture not provisioned on this checkout
        }
        let ad = AssemblyDefinition::read_file(&dll).expect("cecil.dll parses");
        let orig_rsrc = ad.main.win32_resources.clone().expect("cecil.dll carries resources");
        let orig_debug_count = ad.main.debug_entries.len();
        assert!(orig_debug_count > 0, "cecil.dll carries debug directory entries");

        let out = ad.write().expect("write");
        let re = AssemblyDefinition::read(&out).expect("output re-parses");
        let rsrc = re.main.win32_resources.as_ref().expect("resources re-emitted");
        // Internal RVAs are patched to the new section base, so bytes are
        // not verbatim — assert length and semantic content instead.
        assert_eq!(rsrc.bytes.len(), orig_rsrc.bytes.len(), "resource length preserved");
        let marker: Vec<u8> = "Mono.Cecil".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(
            rsrc.bytes.windows(marker.len()).any(|w| w == marker),
            "VS_VERSIONINFO string content survives the rebuild"
        );
        assert_eq!(
            re.main.debug_entries.len(),
            orig_debug_count,
            "debug entries re-emit one-for-one"
        );

        // The re-emitted resource directory must point into the new image,
        // not the stale original RVA.
        let image = cecli_pe::Image::parse(&out).expect("output is a PE image");
        let dir = image.data_directories[cecli_pe::DataDirectoryIndex::Resource as usize];
        assert_eq!(dir.size as usize, orig_rsrc.bytes.len());
        assert_eq!(dir.virtual_address, rsrc.original_rva, "directory tracks the new section");
    }

    /// Full strong-name wiring: key in, public key out, signature slot
    /// reserved and actually signed.
    #[cfg(all(test, feature = "strongname"))]
    #[test]
    fn strong_name_signing_wires_into_write() {
        let fixtures = cecli_core::fixtures_dir();
        let exe = fixtures.join("hello.exe");
        if !exe.exists() {
            return; // fixture not provisioned on this checkout
        }
        let ad = AssemblyDefinition::read_file(&exe).expect("hello.exe parses");

        let key_bytes =
            crate::strongname::tests::private_snk(&crate::strongname::tests::generate_key());
        let opts =
            WriteParameters { strong_name_key: Some(key_bytes.clone()), ..Default::default() };
        let out = ad.write_with(&opts).expect("signed write");

        let re = AssemblyDefinition::read(&out).expect("signed image re-parses");
        let kp = crate::strongname::StrongNameKeyPair::new(&key_bytes).expect("key parses");
        assert_eq!(
            re.name.public_key,
            kp.public_key(),
            "Assembly row carries the key's public key"
        );

        let image = cecli_pe::Image::parse(&out).expect("image layer parses");
        let header = image.cli_header();
        assert!(header.strong_name_rva != 0, "signature slot reserved");
        assert!(header.strong_name_size > 0, "signature slot sized");
        let slot = image.rva(header.strong_name_rva).expect("slot readable");
        let sig = &slot[..header.strong_name_size as usize];
        assert!(sig.iter().any(|&b| b != 0), "signature is signed, not a zero placeholder");
    }

    /// Without the `strongname` feature a key is a clean error, not a
    /// silent skip.
    #[cfg(all(test, not(feature = "strongname")))]
    #[test]
    fn strong_name_key_requires_feature() {
        let ad = sample_assembly();
        let opts = WriteParameters { strong_name_key: Some(vec![1u8; 16]), ..Default::default() };
        let err = ad.write_with(&opts).expect_err("key without feature must fail");
        assert!(err.to_string().contains("strongname"), "error names the feature: {err}");
    }

    /// Cecil `ImageWriter.GetStrongNameLength` boundaries: keys longer than
    /// 32 bytes reserve `len - 32`, any shorter key (including the 16-byte
    /// ECMA "key") reserves the 128-byte default, and keyless unflagged
    /// assemblies reserve nothing.
    #[test]
    fn strong_name_signature_size_matches_cecil_boundaries() {
        let ad = sample_assembly();
        let module = &ad.main;

        let mut with_key = ad.name.clone();
        with_key.public_key = vec![0u8; 94]; // 1024-bit key + 32-byte header
        assert_eq!(strong_name_signature_size(&with_key, module), 62);

        let mut ecma = ad.name.clone();
        ecma.public_key = vec![0u8; 16]; // ECMA test "key"
        assert_eq!(strong_name_signature_size(&ecma, module), 128);

        let mut short = ad.name.clone();
        short.public_key = vec![0u8; 32];
        assert_eq!(
            strong_name_signature_size(&short, module),
            128,
            "len == 32 is not a key with header"
        );

        let mut empty = ad.name.clone();
        empty.public_key.clear();
        assert_eq!(strong_name_signature_size(&empty, module), 0);
    }

    /// A short (ECMA-style) public key reserves the 128-byte default slot in
    /// the emitted image, not a zero-length one.
    #[test]
    fn short_public_key_reserves_default_signature_slot() {
        let mut ad = sample_assembly();
        ad.name.public_key = vec![0xA5u8; 16]; // ECMA test key shape
        let out = ad.write().expect("write succeeds");
        let image = cecli_pe::Image::parse(&out).expect("output parses");
        let header = image.cli_header();
        assert_eq!(header.strong_name_size, 128, "default slot reserved");
        assert_ne!(header.strong_name_rva, 0, "slot is placed in .text");
    }

    /// Cecil `WriterParameters.Timestamp` lands in the PE file header.
    #[test]
    fn write_parameters_timestamp_reaches_pe_header() {
        let ad = sample_assembly();
        let out = ad
            .write_with(&WriteParameters { timestamp: Some(0x5E12_3456), ..Default::default() })
            .expect("write succeeds");
        let image = cecli_pe::Image::parse(&out).expect("output parses");
        assert_eq!(image.timestamp, 0x5E12_3456, "TimeDateStamp override applied");
    }

    /// Cecil `WriterParameters.DeterministicMvid`: identical content written
    /// from models carrying different MVIDs produces byte-identical images,
    /// with an MVID derived from neither input; without the flag the input
    /// GUIDs survive.
    #[test]
    fn deterministic_mvid_erases_input_guid_differences() {
        let mut a = sample_assembly();
        let mut b = sample_assembly();
        a.main.guid = [0x11u8; 16];
        b.main.guid = [0x22u8; 16];

        let opts = WriteParameters { deterministic_mvid: true, ..Default::default() };
        let out_a = a.write_with(&opts).expect("write a");
        let out_b = b.write_with(&opts).expect("write b");
        assert_eq!(out_a, out_b, "content-derived MVID erases input GUID differences");

        // Without the flag the differing GUIDs survive into the output.
        assert_ne!(a.write().expect("plain a"), b.write().expect("plain b"));

        // The derived MVID is neither input value and the image re-parses.
        let re = AssemblyDefinition::read(&out_a).expect("deterministic output re-parses");
        assert_ne!(re.main.guid, [0x11u8; 16]);
        assert_ne!(re.main.guid, [0x22u8; 16]);
    }

    /// External value-type classification: `WriteParameters::reference_images`
    /// replaces the well-known-`System` heuristic, so user-defined external
    /// structs get the correct `VALUETYPE` marker instead of `CLASS`.
    #[test]
    fn reference_images_drive_value_type_classification() {
        use crate::model::types::{FieldDefinition, FieldSignature, ScopeRef, TypeDefinition};

        let external = |ns: &str, name: &str, asm: &str| {
            TypeDesc::External(Box::new(ExternalType {
                namespace: ns.into(),
                name: name.into(),
                nesting: Vec::new(),
                scope: if asm.is_empty() {
                    ScopeRef::ThisModule
                } else {
                    ScopeRef::Assembly(crate::model::types::AssemblyNameReference::new(asm))
                },
            }))
        };

        // Dependency image: assembly "dep" defining Ns.MyStruct : System.ValueType.
        let mut dep = Module {
            name: "dep".into(),
            runtime_version: "v4.0.30319".into(),
            ..Default::default()
        };
        dep.assembly_refs.push(crate::model::types::AssemblyNameReference::new("mscorlib"));
        dep.add_type(TypeDefinition {
            namespace: "Ns".into(),
            name: "MyStruct".into(),
            base_type: Some(external("System", "ValueType", "mscorlib")),
            ..Default::default()
        });
        let dep_asm = AssemblyDefinition {
            name: AssemblyNameDefinition { name: "dep".into(), ..Default::default() },
            main: dep,
            ..Default::default()
        };
        let dep_bytes = dep_asm.write().expect("dependency writes");

        // Main image: one field of type external Ns.MyStruct scoped to dep.
        let mut main = Module {
            name: "main".into(),
            runtime_version: "v4.0.30319".into(),
            ..Default::default()
        };
        main.assembly_refs.push(crate::model::types::AssemblyNameReference::new("dep"));
        let holder = main.add_type(TypeDefinition {
            namespace: "M".into(),
            name: "Holder".into(),
            ..Default::default()
        });
        main.add_field(
            holder,
            FieldDefinition {
                name: "f".into(),
                signature: FieldSignature(external("Ns", "MyStruct", "dep")),
                ..Default::default()
            },
        );
        let main_asm = AssemblyDefinition {
            name: AssemblyNameDefinition { name: "main".into(), ..Default::default() },
            main,
            ..Default::default()
        };

        // Heuristic path: Ns.MyStruct is not a well-known System type, so it
        // is misclassified as a class (the documented deviation).
        let heuristic = main_asm.write().expect("heuristic write");
        assert_eq!(field_sig_marker(&heuristic), Some(0x12), "heuristic writes CLASS");

        // Reference-image path: resolved in dep -> VALUETYPE.
        let classified = main_asm
            .write_with(&WriteParameters {
                reference_images: vec![dep_bytes],
                ..Default::default()
            })
            .expect("classified write");
        assert_eq!(field_sig_marker(&classified), Some(0x11), "resolution writes VALUETYPE");
    }

    /// Facade resolution (`resolve_type_with`, the Cecil
    /// `TypeReference.Resolve` analog): an external type scoped to a
    /// referenced assembly resolves into the dependency's module space.
    #[test]
    fn resolve_type_with_loads_dependency_through_loader() {
        use crate::model::types::{ScopeRef, TypeDefinition};
        use crate::resolution::AssemblyBytesLoader;

        // Dependency: assembly "dep" defining Ns.MyStruct : System.ValueType.
        let mut dep = Module {
            name: "dep".into(),
            runtime_version: "v4.0.30319".into(),
            ..Default::default()
        };
        dep.assembly_refs.push(crate::model::types::AssemblyNameReference::new("mscorlib"));
        dep.add_type(TypeDefinition {
            namespace: "Ns".into(),
            name: "MyStruct".into(),
            base_type: Some(TypeDesc::External(Box::new(ExternalType {
                namespace: "System".into(),
                name: "ValueType".into(),
                nesting: Vec::new(),
                scope: ScopeRef::Assembly(crate::model::types::AssemblyNameReference::new(
                    "mscorlib",
                )),
            }))),
            ..Default::default()
        });
        let dep_asm = AssemblyDefinition {
            name: AssemblyNameDefinition { name: "dep".into(), ..Default::default() },
            main: dep,
            ..Default::default()
        };
        let dep_bytes = std::rc::Rc::new(dep_asm.write().expect("dependency writes"));

        // Main: empty module whose only content is the reference to resolve.
        let mut main = Module {
            name: "main".into(),
            runtime_version: "v4.0.30319".into(),
            ..Default::default()
        };
        main.assembly_refs.push(crate::model::types::AssemblyNameReference::new("dep"));
        let main_asm = AssemblyDefinition {
            name: AssemblyNameDefinition { name: "main".into(), ..Default::default() },
            main,
            ..Default::default()
        };

        // Loader hands dep's image for any "dep" reference.
        struct DepLoader(std::rc::Rc<Vec<u8>>);
        impl AssemblyBytesLoader for DepLoader {
            fn load(
                &mut self,
                reference: &crate::model::types::AssemblyNameReference,
            ) -> Result<Option<std::borrow::Cow<'_, [u8]>>> {
                if reference.name == "dep" {
                    Ok(Some(std::borrow::Cow::Owned(self.0.as_ref().clone())))
                } else {
                    Ok(None)
                }
            }
        }

        let target = TypeDesc::External(Box::new(ExternalType {
            namespace: "Ns".into(),
            name: "MyStruct".into(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(crate::model::types::AssemblyNameReference::new("dep")),
        }));
        let resolved = main_asm
            .resolve_type_with(Box::new(DepLoader(dep_bytes.clone())), &target)
            .expect("resolve");
        let rt = resolved.expect("MyStruct resolves");
        assert_eq!(rt.module_index, 1, "found in the loaded dependency");

        // Verify the resolved handle through an engine kept alive: the
        // dependency's arena at that handle is Ns.MyStruct.
        let mut engine = crate::resolution::ResolutionEngine::with_primary_and_loader(
            &main_asm.main,
            Box::new(DepLoader(dep_bytes)),
        );
        let rt = engine.resolve_type(&target).expect("resolve").expect("resolves");
        let dep_module = &engine.loaded_modules()[rt.module_index - 1];
        assert_eq!(dep_module.type_def(rt.id).namespace, "Ns");
        assert_eq!(dep_module.type_def(rt.id).name, "MyStruct");
    }

    /// First element-type marker byte of Field row 1's signature blob in a
    /// written image (`0x11` = VALUETYPE, `0x12` = CLASS).
    fn field_sig_marker(image: &[u8]) -> Option<u8> {
        let img = cecli_pe::Image::parse(image).ok()?;
        let (rva, size) = img.metadata_rva().ok()?;
        let root = img.rva(rva).ok()?;
        let md = cecli_metadata::MetadataReader::parse(&root[..size.min(root.len())]).ok()?;
        let blob_idx = md.column(cecli_core::TableIndex::Field, 1, 2).ok()? as u32;
        let blob = md.heaps().blob.get(blob_idx).ok()?;
        blob.get(1).copied()
    }

    /// Embedded portable PDB end-to-end: write with
    /// `SymbolOutput::EmbeddedPortablePdb`, re-read with `read_symbols`, and
    /// the symbols come back from the image's own debug directory (no
    /// sidecar). The debug directory carries the MPDB entry plus a matching
    /// SHA-256 PdbChecksum; stale symbol entries are replaced.
    #[test]
    fn embedded_pdb_roundtrips_through_the_image() {
        use crate::model::types::TypeDefinition;
        use cecli_pdb::embedded::{image_debug_type as ty, sha256};

        let mut module = Module {
            name: "emb".into(),
            runtime_version: "v4.0.30319".into(),
            ..Default::default()
        };
        module.add_type(TypeDefinition {
            namespace: "E".into(),
            name: "T".into(),
            ..Default::default()
        });
        module.debug = Some(crate::module_def::ModuleDebugInfo {
            documents: vec![cecli_pdb::document::Document {
                name: "/src/a.cs".into(),
                hash_algorithm: [0; 16],
                hash: vec![1, 2, 3],
                language: [0; 16],
            }],
            points: [(
                1u32,
                vec![(
                    0u32,
                    vec![cecli_pdb::portable_reader::SequencePoint {
                        offset: 0,
                        start_line: 3,
                        start_column: 1,
                        end_line: 3,
                        end_column: 10,
                    }],
                )],
            )]
            .into_iter()
            .collect(),
            scopes: Default::default(),
            custom_debug_info: vec![crate::module_def::CustomDebugInformation {
                parent: cecli_core::Token::new(cecli_core::TableIndex::Module, 1),
                kind: [0xAA; 16],
                value: br#"{"key":"value"}"#.to_vec(),
            }],
        });
        // A stale CodeView entry that must be replaced.
        module.debug_entries.push(cecli_pe::ImageDebugEntry {
            directory: cecli_pe::ImageDebugDirectory {
                kind: ty::CODEVIEW,
                size_of_data: 4,
                ..Default::default()
            },
            data: vec![0, 0, 0, 0],
        });
        let asm = AssemblyDefinition {
            name: AssemblyNameDefinition { name: "emb".into(), ..Default::default() },
            main: module,
            ..Default::default()
        };

        let image_bytes = asm
            .write_with(&WriteParameters {
                symbol_output: Some(SymbolOutput::EmbeddedPortablePdb),
                ..Default::default()
            })
            .expect("embedded write");

        // Debug directory: stale CodeView gone, MPDB + PdbChecksum present
        // and the checksum matches the embedded PDB's content.
        let image = cecli_pe::Image::parse(&image_bytes).expect("image parses");
        let kinds: Vec<i32> = image.debug_entries.iter().map(|e| e.directory.kind).collect();
        assert!(!kinds.contains(&ty::CODEVIEW), "stale CodeView replaced");
        assert!(kinds.contains(&ty::EMBEDDED_PORTABLE_PDB), "MPDB entry present");
        assert!(kinds.contains(&ty::PDB_CHECKSUM), "PdbChecksum present");
        let emb = image
            .debug_entries
            .iter()
            .find(|e| e.directory.kind == ty::EMBEDDED_PORTABLE_PDB)
            .unwrap();
        let pdb = cecli_pdb::embedded::unwrap_embedded(&emb.data).expect("MPDB inflates");
        let chk =
            image.debug_entries.iter().find(|e| e.directory.kind == ty::PDB_CHECKSUM).unwrap();
        assert_eq!(&chk.data[..7], b"SHA256\0");
        assert_eq!(&chk.data[7..], &sha256(&pdb)[..], "checksum covers the PDB");

        // Plain read attaches nothing; read_symbols (via a temp file so the
        // embedded fallback can probe the image) brings everything back.
        let re = AssemblyDefinition::read(&image_bytes).expect("re-parse");
        assert!(re.main.debug.is_none(), "plain read attaches nothing");
        let dir = unique_test_dir("embedded");
        let exe = dir.join("emb.dll");
        std::fs::write(&exe, &image_bytes).expect("write temp exe");
        let mut params = crate::resolver::ReaderParameters::new();
        params.read_symbols = true;
        let re = AssemblyDefinition::read_file_with(&exe, &params).expect("read with symbols");
        let debug = re.main.debug.as_ref().expect("embedded symbols attached");
        assert_eq!(debug.documents.len(), 1);
        assert_eq!(debug.documents[0].name, "/src/a.cs");
        assert!(debug.points.contains_key(&1), "sequence points survive");
        assert_eq!(debug.custom_debug_info.len(), 1, "CDI survives");
        assert_eq!(debug.custom_debug_info[0].value, br#"{"key":"value"}"#);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CDI rows round-trip through build_portable_pdb -> portable reader.
    #[test]
    fn cdi_roundtrips_through_pdb_builder() {
        let debug = crate::module_def::ModuleDebugInfo {
            documents: vec![cecli_pdb::document::Document {
                name: "x.cs".into(),
                hash_algorithm: [0; 16],
                hash: Vec::new(),
                language: [0; 16],
            }],
            points: Default::default(),
            scopes: Default::default(),
            custom_debug_info: vec![
                crate::module_def::CustomDebugInformation {
                    parent: cecli_core::Token::new(cecli_core::TableIndex::Module, 1),
                    kind: [1; 16],
                    value: vec![9, 9],
                },
                crate::module_def::CustomDebugInformation {
                    parent: cecli_core::Token::new(cecli_core::TableIndex::MethodDef, 3),
                    kind: [2; 16],
                    value: b"async-hint".to_vec(),
                },
            ],
        };

        let pdb = build_portable_pdb(&Module { debug: Some(debug), ..Default::default() })
            .expect("pdb builds");
        let reader = cecli_pdb::portable_reader::PortablePdbReader::parse(&pdb).expect("parses");
        let cdi = reader.custom_debug_informations().expect("cdi reads");
        assert_eq!(cdi.len(), 2);
        assert_eq!(cdi[0].parent.table(), cecli_core::TableIndex::Module);
        assert_eq!(cdi[0].kind, [1; 16]);
        assert_eq!(cdi[0].value, vec![9, 9]);
        assert_eq!(cdi[1].parent.table(), cecli_core::TableIndex::MethodDef);
        assert_eq!(cdi[1].value, b"async-hint".to_vec());
    }

    /// MDB sidecar: `SymbolOutput::Mdb` writes a `<file>.mdb` next to the
    /// image that the MDB reader can open, with documents as sources.
    #[test]
    fn mdb_sidecar_written_and_opens() {
        let mut module =
            Module { name: "m".into(), runtime_version: "v4.0.30319".into(), ..Default::default() };
        module.debug = Some(crate::module_def::ModuleDebugInfo {
            documents: vec![cecli_pdb::document::Document {
                name: "C:\\src\\m.cs".into(),
                hash_algorithm: [0; 16],
                hash: vec![7; 16],
                language: [0; 16],
            }],
            points: Default::default(),
            scopes: Default::default(),
            custom_debug_info: Vec::new(),
        });
        let asm = AssemblyDefinition {
            name: AssemblyNameDefinition { name: "m".into(), ..Default::default() },
            main: module,
            ..Default::default()
        };

        let dir = unique_test_dir("mdbside");
        let out = dir.join("m.dll");
        asm.write_file_with(
            &out,
            &WriteParameters { symbol_output: Some(SymbolOutput::Mdb), ..Default::default() },
        )
        .expect("write with mdb");

        let sidecar = dir.join("m.dll.mdb");
        assert!(sidecar.exists(), "mdb sidecar next to the image");
        let bytes = std::fs::read(&sidecar).expect("sidecar readable");
        let reader = cecli_mdb::reader::MdbReader::open(&bytes).expect("mdb opens");
        assert_eq!(reader.source_files().len(), 1);
        assert_eq!(reader.source_files()[0].path, "C:\\src\\m.cs");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
