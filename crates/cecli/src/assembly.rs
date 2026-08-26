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

/// An assembly: main module plus optional satellite netmodules.
#[derive(Debug, Clone, Default)]
pub struct AssemblyDefinition {
    pub name: AssemblyNameDefinition,
    pub main: Module,
    /// Additional netmodules of a multi-module assembly.
    pub modules: Vec<Module>,
    /// Entry point as a method arena index into `main`.
    pub entry_point: Option<MethodId>,
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

        // Symbols (portable PDB sidecar next to the origin file).
        if opts.read_symbols {
            let Some(origin_path) = origin.as_deref() else {
                return Err(Error::Unsupported(
                    "reading symbols requires a file-path origin; use AssemblyDefinition::read_file_with"
                        .to_string(),
                ));
            };
            match load_portable_pdb_bytes(origin_path) {
                Some(pdb_bytes) => attach_portable_symbols(&mut module, &pdb_bytes)?,
                None => {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("no portable PDB found next to '{}'", origin_path.display()),
                    )));
                }
            }
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

        Ok(AssemblyDefinition { name, main: module, modules, entry_point })
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
}

// ---------------------------------------------------------------------------
// Symbol + satellite-module plumbing (facade-integration parity phase)
// ---------------------------------------------------------------------------

/// Locates and reads a portable PDB sidecar for `origin`.
///
/// Mirrors `DefaultSymbolReaderProvider.GetSymbolReaderFile`: `<file>.pdb`
/// (`line.exe.pdb`) is preferred, then the extension-swapped stem
/// (`line.pdb`). Returns `None` when neither candidate exists.
fn load_portable_pdb_bytes(origin: &std::path::Path) -> Option<Vec<u8>> {
    let mut candidates = Vec::with_capacity(2);
    if let Some(file_name) = origin.file_name() {
        let appended = origin.with_file_name(format!("{}.pdb", file_name.to_string_lossy()));
        candidates.push(appended);
    }
    candidates.push(origin.with_extension("pdb"));
    for candidate in candidates {
        if candidate.is_file() {
            return std::fs::read(&candidate).ok();
        }
    }
    None
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

    module.debug = Some(crate::module_def::ModuleDebugInfo { documents, points, scopes });
    Ok(())
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

/// Writer configuration carrier. Port of the fields Mono.Cecil's
/// `WriterParameters` carries that matter here.
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteParameters {
    /// Emit debug symbols for a module carrying
    /// [`crate::module_def::ModuleDebugInfo`] (Cecil
    /// `WriterParameters.WriteSymbols`).
    pub write_symbols: bool,
}

impl WriteParameters {
    /// Creates parameters with symbol writing off.
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
    /// CLI flags). Symbol emission happens in [`Self::write_file_with`],
    /// which knows the output path of the sidecar `.pdb`.
    pub fn write_with(&self, _opts: &WriteParameters) -> Result<Vec<u8>> {
        let module = &self.main;

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
        let emitted = {
            let mut tmap = crate::write::token_map::TokenMap::new(&mut builder);
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
                Some(&self.name),
                self.entry_point,
                &layout,
                tmap,
            )?
        };

        // 5. Rebuild the PE image. Identity fields travel through a minimal
        //    carrier image because the object model does not retain the
        //    original file bytes. Win32-resource passthrough and debug
        //    directory entries are not retained by the v1 model either.
        let parts = cecli_pe::EmitParts {
            code: code.into_vec(),
            resources: resources.bytes,
            data: emitted.data,
            data_alignment: None,
            metadata: emitted.root,
            strongname_size: 0, // strong-name signing is skipped per contract
            win32_resources: None,
            debug_entries: Vec::new(),
            // A7-F2: take the token from the metadata emission (resolved via
            // `entry`), not the stale read-time `module.entry_point_token`.
            entry_point_token: emitted.entry_point_token,
        };
        let carrier = carrier_image(module)?;
        cecli_pe::ImageWriter::rebuild(&carrier, parts).emit()
    }

    /// Writes the serialized image to `path`, optionally emitting a portable
    /// PDB sidecar next to it.
    ///
    /// With `opts.write_symbols` set and the manifest module carrying debug
    /// information ([`Module::debug`]), a `<output-stem>.pdb` file is written
    /// alongside the image via [`build_portable_pdb`]. Modules without debug
    /// information silently skip the sidecar.
    pub fn write_file_with<P: AsRef<std::path::Path>>(
        &self,
        path: P,
        opts: &WriteParameters,
    ) -> Result<()> {
        let path = path.as_ref();
        std::fs::write(path, self.write_with(opts)?).map_err(Error::Io)?;
        if opts.write_symbols && self.main.debug.is_some() {
            let pdb_bytes = build_portable_pdb(&self.main)?;
            let sidecar = path.with_extension("pdb");
            std::fs::write(sidecar, pdb_bytes).map_err(Error::Io)?;
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

    builder.finalize()
}

fn arch_is_pe64(arch: cecli_core::flags::TargetArchitecture) -> bool {
    use cecli_core::flags::TargetArchitecture as A;
    matches!(arch, A::AMD64 | A::IA64 | A::ARM64)
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

    // Data directories: only COM+ points anywhere.
    let cli_dir = w + 14 * 8;
    out[cli_dir..cli_dir + 4].copy_from_slice(&TEXT_RVA.to_le_bytes());
    out[cli_dir + 4..cli_dir + 8].copy_from_slice(&(CLI_HEADER_CB as u32).to_le_bytes());
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
        let mut module = Module::default();
        module.name = "sample".into();
        let outer = {
            let mut t = TypeDefinition::default();
            t.namespace = "Ns".into();
            t.name = "Outer".into();
            module.add_type(t)
        };
        let nested = {
            let mut t = TypeDefinition::default();
            t.namespace = "Ns".into();
            t.name = "Nested".into();
            t.declaring_type = Some(outer);
            module.add_type(t)
        };
        let method = {
            let mut m = MethodDefinition::default();
            m.name = "Bar".into();
            m
        };
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
        let mut module = Module::default();
        module.kind = cecli_core::flags::ModuleKind::Dll;
        module.architecture = cecli_core::flags::TargetArchitecture::AMD64;
        module.characteristics = cecli_core::flags::ModuleCharacteristics::NX_COMPAT;
        module.attributes = cecli_core::flags::ModuleAttributes::IL_ONLY
            | cecli_core::flags::ModuleAttributes::IL_LIBRARY;
        module.entry_point_token = cecli_core::Token::new(cecli_core::TableIndex::MethodDef, 7);
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
        ad.write_file_with(&out, &WriteParameters { write_symbols: true })
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

        let mut module = Module::default();
        module.name = "multi".into();
        module.kind = ModuleKind::Dll;
        module.runtime_version = "v4.0.30319".into();
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
}
