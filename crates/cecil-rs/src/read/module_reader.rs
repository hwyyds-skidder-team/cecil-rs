//! Port of Mono.Cecil's `AssemblyReader.cs` (`ReadModule`) path.
//!
//! [`read_module`] walks the metadata tables of an already-parsed PE/CLI
//! image and builds the arena-based object model ([`Module`])
//! together with its token maps ([`ReadContext`]). Deterministic ordering:
//! every arena is populated in metadata-table row order, so handle values are
//! always `rid - 1`.
//!
//! Method bodies are deliberately NOT resolved here; unit R3
//! (`read::instructions`) fills them afterwards using the returned context,
//! the image, and a fresh [`MetadataReader`].

use crate::model::marshal::parse_marshal_spec;
use crate::model::signature::{
    parse_constant_blob, parse_field_signature, parse_method_signature, parse_property_signature,
};
use crate::model::types::*;
use crate::module_def::{ExportedImpl, ExportedTypeRow, FileRow, Module, Resource};
use crate::read::context::{MemberRefRow, ReadContext, ReadOptions};

use cecil_core::flags::{
    AssemblyHashAlgorithm, EventAttributes, FieldAttributes, FileRowAttributes,
    GenericParameterAttributes, ManifestResourceAttributes, MethodAttributes, MethodImplAttributes,
    MethodSemanticsAttributes, ModuleAttributes, ModuleCharacteristics, ModuleKind,
    PInvokeAttributes, ParameterAttributes, PropertyAttributes, SecurityAction, TargetArchitecture,
    TargetRuntime, TypeAttributes,
};
use cecil_core::token::coded;
use cecil_core::{ElementType, Error, Result, TableIndex as T, Token};
use cecil_metadata::{decode_coded, MetadataReader};

/// Data of one `Assembly` table row, surfaced through
/// [`ReadContext::assembly_row`](crate::read::context::ReadContext) so the
/// facade can build its `AssemblyNameDefinition`. `None` for netmodules
/// (images without an `Assembly` row).
///
/// Assembly-scoped `CustomAttribute` (parent tag `Assembly` in
/// `HasCustomAttribute`) and `DeclSecurity` rows are collected here — the
/// frozen `Module` model has no assembly-level slots, so the facade consumes
/// these when building its `AssemblyDefinition`.
#[derive(Debug, Clone)]
pub struct AssemblyRowData {
    pub name: String,
    pub version: Version,
    pub culture: Option<String>,
    /// `Assembly.PublicKey` blob (the full key; the CLI `PUBLICKEY` flag
    /// decides whether callers treat it as key-or-token).
    pub public_key: Vec<u8>,
    pub hash_alg: AssemblyHashAlgorithm,
    /// Raw `Assembly.Flags` value (kept untruncated for round-tripping).
    pub flags: u32,
    pub entry_point_token: Token,
    /// `HasCustomAttribute` rows whose parent is the `Assembly` table
    /// (Mono.Cecil `AssemblyDefinition.CustomAttributes`).
    pub custom_attributes: Vec<CustomAttribute>,
    /// `DeclSecurity` rows whose parent is the `Assembly` table
    /// (Mono.Cecil `AssemblyDefinition.SecurityDeclarations`).
    pub security_declarations: Vec<SecurityDeclaration>,
}

// ---------------------------------------------------------------------------
// Table cell access helpers
// ---------------------------------------------------------------------------

fn cell_u16(md: &MetadataReader, table: T, rid: u32, c: usize) -> Result<u16> {
    Ok(md.column(table, rid, c)? as u16)
}

fn cell_u32(md: &MetadataReader, table: T, rid: u32, c: usize) -> Result<u32> {
    Ok(md.column(table, rid, c)? as u32)
}

fn cell_str(md: &MetadataReader, table: T, rid: u32, c: usize) -> Result<String> {
    let idx = md.column(table, rid, c)? as u32;
    heap_name(md, idx)
}

fn heap_name(md: &MetadataReader, idx: u32) -> Result<String> {
    if md.is_tolerant() {
        Ok(md.heaps().strings.get_lossy(idx).into_owned())
    } else {
        Ok(md.heaps().strings.get(idx)?.to_owned())
    }
}

fn heap_blob<'m>(md: &'m MetadataReader, idx: u32) -> Result<&'m [u8]> {
    if md.is_tolerant() {
        Ok(md.heaps().blob.get_tolerant(idx))
    } else {
        md.heaps().blob.get(idx)
    }
}

fn cell_blob<'m>(md: &'m MetadataReader, table: T, rid: u32, c: usize) -> Result<&'m [u8]> {
    let idx = md.column(table, rid, c)? as u32;
    heap_blob(md, idx)
}

fn cell_guid(md: &MetadataReader, table: T, rid: u32, c: usize) -> Result<[u8; 16]> {
    let idx = md.column(table, rid, c)? as u32;
    md.heaps().guid.get(idx)
}

/// Decodes a coded-index cell with a descriptive error when out of range.
fn decode_group(group: &'static cecil_core::CodedIndexGroup, value: u64) -> Result<(T, u32)> {
    decode_coded(group, value)
        .ok_or_else(|| Error::bad_image(format!("coded index {value:#x} out of range")))
}

fn bad(msg: String) -> Error {
    Error::bad_image(msg)
}

/// Validates a 1-based row id against an arena/table length and returns the
/// 0-based slot. Centralizes the `rid < 1 || rid > len` guard so coded-index
/// consumers cannot forget it — a rid of 0 would otherwise underflow `rid - 1`
/// or index out of bounds.
fn checked_slot(rid: usize, len: usize, what: &str) -> Result<usize> {
    if rid < 1 || rid > len {
        return Err(bad(format!("{what} out of range")));
    }
    Ok(rid - 1)
}

/// End (exclusive) of a `*List` run: the next row's start, or `count + 1`.
fn list_end(starts: &[u32], i: usize, count: u32) -> u32 {
    if i + 1 < starts.len() {
        starts[i + 1]
    } else {
        count + 1
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Reads a complete module (every metadata table, no method bodies) from a
/// parsed image. Returns the owned object model plus the token maps required
/// by later phases (body resolution, writing, facade glue).
pub fn read_module(image: &cecil_pe::Image, opts: &ReadOptions) -> Result<(Module, ReadContext)> {
    let (md_rva, md_size) = image.metadata_rva()?;
    let mapped = image.rva(md_rva)?;
    let root = &mapped[..md_size.min(mapped.len())];
    let md = MetadataReader::parse(root)?;

    read_module_with_metadata(image, &md, opts)
}

/// Reads a module using a metadata reader that was already parsed from this
/// image. Callers that also need the metadata for a later phase can avoid a
/// second full root parse by using this entry point.
pub fn read_module_with_metadata(
    image: &cecil_pe::Image,
    md: &MetadataReader<'_>,
    opts: &ReadOptions,
) -> Result<(Module, ReadContext)> {
    // Bodies belong to unit R3 (`resolve_bodies`); never loaded here.
    let _ = opts;

    // Portable PDB roots carry counts for tables in a different image. Those
    // counts select index widths; they cannot justify allocating module arenas.
    for slot in 0..=T::GenericParamConstraint as u8 {
        if let Some(table) = T::from_u8(slot) {
            if md.row_count(table) != 0 && !md.tables().is_present(table) {
                return Err(Error::bad_image(
                    "assembly metadata contains external #Pdb table counts",
                ));
            }
        }
    }

    md.validate_materialization_budget()?;
    let mut ctx = ReadContext::new(md);

    let mut module = Module {
        entry_point_token: image.entry_point_token(),
        native_entry_point_rva: image.native_entry_point_rva(),
        ..Default::default()
    };
    reserve_table_capacity(&mut module, &mut ctx, md);
    ctx.entry_point_token = module.entry_point_token;

    populate_shell(&mut module, image, md.version_string());
    read_module_row(&mut module, md)?;

    // ---- Arenas in table row order ------------------------------------
    let typedef_rows = read_type_defs(&mut module, &mut ctx, md)?;
    let nested_parents = read_nested_classes(&module, md)?;
    apply_nesting(&mut module, &nested_parents);
    read_fields(&mut module, &mut ctx, md)?;
    read_methods(&mut module, &mut ctx, md)?;
    attach_member_ranges(&mut module, &typedef_rows, md)?;
    let param_owners = read_params(&mut module, md)?;
    ctx.recover(read_properties_events_semantics(&mut module, &ctx, md), T::MethodSemantics, 0)?;
    let constraint_owners = read_generic_params(&mut module, &mut ctx, md)?;

    // TypeSpec / MemberRef rows eagerly decoded into the context in
    // deterministic table order so every cross-reference below resolves
    // through one uniform path.
    ctx.resolve_lazy_tables(md)?;

    // ---- Cross-table attachments ---------------------------------------
    let interface_impl_owners = read_base_types_and_interfaces(&mut module, &ctx, md)?;
    read_class_layouts(&mut module, md)?;
    read_field_layouts(&mut module, md)?;
    read_field_rvas(&mut module, image, md)?;
    ctx.recover(read_constants(&mut module, md, &param_owners), T::Constant, 0)?;
    ctx.recover(read_marshal_specs(&mut module, &ctx, md, &param_owners), T::FieldMarshal, 0)?;
    ctx.recover(read_impl_maps(&mut module, md), T::ImplMap, 0)?;
    ctx.recover(read_method_impls(&mut module, &ctx, md), T::MethodImpl, 0)?;
    // Assembly-scope data is read before the DeclSecurity / CustomAttribute
    // passes so rows parented to the `Assembly` table can be attached to
    // [`ReadContext::assembly_row`].
    let has_assembly_row = md.row_count(T::Assembly) > 0;
    if has_assembly_row {
        ctx.assembly_row = Some(read_assembly_row(image, md)?);
    } else {
        // No Assembly row => netmodule (Mono.Cecil ReadModuleManifest).
        module.kind = ModuleKind::NetModule;
    }
    let security_result = read_decl_security(&mut module, &mut ctx, md);
    ctx.recover(security_result, T::DeclSecurity, 0)?;
    let attribute_result = read_custom_attributes(
        &mut module,
        &mut ctx,
        md,
        &param_owners,
        &interface_impl_owners,
        &constraint_owners,
    );
    ctx.recover(attribute_result, T::CustomAttribute, 0)?;
    module.assembly_refs = ctx.asm_refs.clone();
    module.module_refs = ctx.mod_refs.clone();
    ctx.recover(
        read_files_exported_types_resources(&mut module, &ctx, image, md),
        T::ManifestResource,
        0,
    )?;
    module.external_value_types = ctx.external_value_types.borrow().clone();
    module.read_diagnostics.extend(ctx.diagnostics.borrow_mut().drain(..));

    Ok((module, ctx))
}

/// Most model arenas have a one-to-one metadata table. Reserve their final
/// size up front so normal images do not repeatedly grow and copy thousands
/// of already-populated definitions while reading.
fn reserve_table_capacity(module: &mut Module, ctx: &mut ReadContext, md: &MetadataReader) {
    let type_count = md.row_count(T::TypeDef) as usize;
    let method_count = md.row_count(T::MethodDef) as usize;
    let field_count = md.row_count(T::Field) as usize;
    let property_count = md.row_count(T::Property) as usize;
    let event_count = md.row_count(T::Event) as usize;
    let generic_count = md.row_count(T::GenericParam) as usize;

    module.types.reserve_exact(type_count);
    module.methods.reserve_exact(method_count);
    module.fields.reserve_exact(field_count);
    module.properties.reserve_exact(property_count);
    module.events.reserve_exact(event_count);
    module.generic_parameters.reserve_exact(generic_count);
    module.resources.reserve_exact(md.row_count(T::ManifestResource) as usize);
    module.file_rows.reserve_exact(md.row_count(T::File) as usize);
    module.exported_types.reserve_exact(md.row_count(T::ExportedType) as usize);

    ctx.type_defs.reserve_exact(type_count);
    ctx.method_defs.reserve_exact(method_count);
    ctx.field_defs.reserve_exact(field_count);
    ctx.prop_defs.reserve_exact(property_count);
    ctx.event_defs.reserve_exact(event_count);
    ctx.gen_params.reserve_exact(generic_count);
}

// ---------------------------------------------------------------------------
// Module shell
// ---------------------------------------------------------------------------

/// Mono.Cecil `ParseRuntime`: the second character of the version string
/// (`v1.0...`, `v1.1...`, `v2.0...`, `v4.0...`) picks the runtime.
fn parse_runtime(version: &str) -> TargetRuntime {
    let b = version.as_bytes();
    if b.len() < 4 {
        return TargetRuntime::Net40;
    }
    match b[1] {
        b'1' => {
            if b[3] == b'0' {
                TargetRuntime::Net10
            } else {
                TargetRuntime::Net11
            }
        }
        b'2' => TargetRuntime::Net20,
        _ => TargetRuntime::Net40,
    }
}

/// Port of `GetMetadataKind`: winmd roots carry `WindowsRuntime` markers in
/// the runtime version; managed winmd roots additionally say `CLR`.
fn metadata_kind(runtime_version: &str) -> cecil_core::flags::MetadataKind {
    if !runtime_version.contains("WindowsRuntime") {
        cecil_core::flags::MetadataKind::Ecma335
    } else if runtime_version.contains("CLR") {
        cecil_core::flags::MetadataKind::ManagedWindowsMetadata
    } else {
        cecil_core::flags::MetadataKind::WindowsMetadata
    }
}

fn populate_shell(module: &mut Module, image: &cecil_pe::Image, version: &str) {
    module.runtime_version = version.to_owned();
    module.runtime = parse_runtime(version);
    module.metadata_kind = metadata_kind(version);
    module.attributes = ModuleAttributes::from_bits_truncate(image.cli_header().flags);
    module.characteristics = ModuleCharacteristics::from_bits_truncate(image.dll_characteristics);
    module.architecture =
        TargetArchitecture::from_machine(image.architecture.0).unwrap_or(TargetArchitecture::I386);
    module.kind = match image.kind {
        cecil_pe::ModuleKind::Console => ModuleKind::Console,
        cecil_pe::ModuleKind::Windows => ModuleKind::Windows,
        cecil_pe::ModuleKind::Dll => ModuleKind::Dll,
        cecil_pe::ModuleKind::NetModule => ModuleKind::NetModule,
    };
}

/// The single `Module` table row: name + MVID.
fn read_module_row(module: &mut Module, md: &MetadataReader) -> Result<()> {
    if md.row_count(T::Module) == 0 {
        if md.is_tolerant() {
            module.read_diagnostics.push(crate::read::context::ReadDiagnostic {
                table: Some(T::Module),
                rid: 0,
                message: "metadata has no Module row".into(),
            });
            return Ok(());
        }
        return Err(bad("metadata has no Module row".into()));
    }
    module.name = cell_str(md, T::Module, 1, 1)?;
    module.guid = cell_guid(md, T::Module, 1, 2)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Type definitions
// ---------------------------------------------------------------------------

/// Per-TypeDef bookkeeping used to wire member lists.
struct TypedefRow {
    field_start: u32,
    method_start: u32,
}

fn read_type_defs(
    module: &mut Module,
    ctx: &mut ReadContext,
    md: &MetadataReader,
) -> Result<Vec<TypedefRow>> {
    let count = md.row_count(T::TypeDef);
    let mut rows = Vec::with_capacity(count as usize);
    for rid in 1..=count {
        let row = md.row_array::<6>(T::TypeDef, rid)?;
        let attributes = TypeAttributes::from_bits_truncate(row[0] as u32);
        // ECMA-335 II §22.37: TypeDef rows are [Flags(0), Name(1),
        // Namespace(2), Extends, FieldList, MethodList].
        let name = heap_name(md, row[1] as u32)?;
        let namespace = heap_name(md, row[2] as u32)?;
        module.types.push(TypeDefinition { namespace, name, attributes, ..Default::default() });
        ctx.type_defs.push(TypeId(rid - 1));
        rows.push(TypedefRow { field_start: row[4] as u32, method_start: row[5] as u32 });
    }
    Ok(rows)
}

/// Reverse map of the `NestedClass` table: nested rid -> enclosing rid.
fn read_nested_classes(module: &Module, md: &MetadataReader) -> Result<Vec<Option<u32>>> {
    let mut parents = vec![None; module.types.len()];
    for rid in 1..=md.row_count(T::NestedClass) {
        let nested = cell_u32(md, T::NestedClass, rid, 0)? as usize;
        let enclosing = cell_u32(md, T::NestedClass, rid, 1)? as usize;
        if nested == 0 || nested > parents.len() || enclosing == 0 || enclosing > parents.len() {
            return Err(bad(format!(
                "NestedClass row {rid} references a type outside the TypeDef table"
            )));
        }
        parents[nested - 1] = Some(enclosing as u32);
    }
    // A cyclic ownership graph would make type-name and writer traversal loop
    // forever. Cut the edge that closes each cycle, retaining the other rows.
    // Also bound nesting before handing the graph to recursive public helpers.
    let mut finished = vec![false; parents.len()];
    let mut heights = vec![0usize; parents.len()];
    for start in 0..parents.len() {
        let mut path = Vec::new();
        let mut current = start;
        while !finished[current] {
            path.push(current);
            let Some(parent) = parents[current] else { break };
            let next = parent as usize - 1;
            if path.contains(&next) || path.len() >= 64 {
                parents[current] = None;
                break;
            }
            current = next;
        }
        for slot in path.into_iter().rev() {
            if let Some(parent) = parents[slot] {
                let height = heights[parent as usize - 1] + 1;
                if height >= 64 {
                    parents[slot] = None;
                } else {
                    heights[slot] = height;
                }
            }
            finished[slot] = true;
        }
    }
    Ok(parents)
}

fn apply_nesting(module: &mut Module, nested_parents: &[Option<u32>]) {
    for (i, parent) in nested_parents.iter().enumerate() {
        let Some(parent) = parent else { continue };
        let parent_idx = *parent as usize - 1;
        module.types[i].declaring_type = Some(TypeId(parent_idx as u32));
        module.types[parent_idx].nested_types.push(TypeId(i as u32));
    }
}

/// Fills each type's `fields` / `methods` handle lists from the FieldList /
/// MethodList runs and stamps each method's `declaring_type`.
fn attach_member_ranges(
    module: &mut Module,
    rows: &[TypedefRow],
    md: &MetadataReader,
) -> Result<()> {
    let field_count = md.row_count(T::Field);
    let method_count = md.row_count(T::MethodDef);

    let valid_starts = |count: u32, method: bool| {
        let mut previous = 1;
        if count > 0 && rows.is_empty() {
            return false;
        }
        for (index, row) in rows.iter().enumerate() {
            let start = if method { row.method_start } else { row.field_start };
            if start == 0 || start > count + 1 || start < previous || (index == 0 && start != 1) {
                return false;
            }
            previous = start;
        }
        true
    };
    if !valid_starts(field_count, false) || !valid_starts(method_count, true) {
        let message = "TypeDef FieldList/MethodList ranges do not own each member exactly once";
        if !md.is_tolerant() {
            return Err(bad(message.into()));
        }
        module.read_diagnostics.push(crate::read::context::ReadDiagnostic {
            table: Some(T::TypeDef),
            rid: 0,
            message: message.into(),
        });
    }

    // ECMA member ranges are implicit runs [start_i, start_{i+1}); hostile
    // images can declare overlapping or unordered starts, which would attach
    // one member to several types — and the writer (which walks per-type
    // member lists) would then emit duplicate rows. Claim each member once,
    // first type wins.
    let mut field_next: Vec<usize> = (0..=field_count as usize).collect();
    let mut method_next: Vec<usize> = (0..=method_count as usize).collect();

    for i in 0..rows.len() {
        let f_end = rows.get(i + 1).map_or(field_count + 1, |row| row.field_start);
        let f_start = rows[i].field_start.max(1).saturating_sub(1) as usize;
        let f_limit = f_end.saturating_sub(1).min(field_count) as usize;
        let mut f = next_unclaimed(&mut field_next, f_start.min(field_count as usize));
        while f < f_limit {
            module.types[i].fields.push(FieldId(f as u32));
            let next = next_unclaimed(&mut field_next, f + 1);
            field_next[f] = next;
            f = next;
        }

        let m_end = rows.get(i + 1).map_or(method_count + 1, |row| row.method_start);
        let m_start = rows[i].method_start.max(1).saturating_sub(1) as usize;
        let m_limit = m_end.saturating_sub(1).min(method_count) as usize;
        let mut m = next_unclaimed(&mut method_next, m_start.min(method_count as usize));
        while m < m_limit {
            module.methods[m].declaring_type = TypeId(i as u32);
            module.types[i].methods.push(MethodId(m as u32));
            let next = next_unclaimed(&mut method_next, m + 1);
            method_next[m] = next;
            m = next;
        }
    }
    Ok(())
}

/// Successor set with path compression: repeated overlapping hostile ranges
/// skip members already attached instead of rescanning them quadratically.
fn next_unclaimed(next: &mut [usize], start: usize) -> usize {
    let mut end = start;
    while next[end] != end {
        end = next[end];
    }
    let mut cursor = start;
    while next[cursor] != end {
        let following = next[cursor];
        next[cursor] = end;
        cursor = following;
    }
    end
}

// ---------------------------------------------------------------------------
// Fields / Methods / Params
// ---------------------------------------------------------------------------

fn read_fields(module: &mut Module, ctx: &mut ReadContext, md: &MetadataReader) -> Result<()> {
    let count = md.row_count(T::Field);
    for rid in 1..=count {
        let row = md.row_array::<3>(T::Field, rid)?;
        let attributes = FieldAttributes::from_bits_truncate(row[0] as u16);
        let name = heap_name(md, row[1] as u32)?;
        let sig_blob = heap_blob(md, row[2] as u32)?;
        let signature = {
            let sig_ctx = ctx.sig_context(md);
            ctx.recover(parse_field_signature(sig_blob, &sig_ctx), T::Field, rid)?
                .unwrap_or(FieldDefinition::default().signature)
        };
        module.fields.push(FieldDefinition { name, attributes, signature, ..Default::default() });
        ctx.field_defs.push(FieldId(rid - 1));
    }
    Ok(())
}

fn read_methods(module: &mut Module, ctx: &mut ReadContext, md: &MetadataReader) -> Result<()> {
    let count = md.row_count(T::MethodDef);
    for rid in 1..=count {
        let row = md.row_array::<6>(T::MethodDef, rid)?;
        let impl_attributes = MethodImplAttributes::from_bits_truncate(row[1] as u16);
        if row[0] != 0 && row[1] & 3 != 0 {
            module.native_method_rvas.insert(MethodId(rid - 1), row[0]);
        }
        let attributes = MethodAttributes::from_bits_truncate(row[2] as u16);
        let name = heap_name(md, row[3] as u32)?;
        let sig_blob = heap_blob(md, row[4] as u32)?;
        let signature = {
            let sig_ctx = ctx.sig_context(md);
            ctx.decoded(parse_method_signature(sig_blob, &sig_ctx), T::MethodDef, rid)?
        };
        // Column 0 (RVA) is intentionally not stored: unit R3 re-reads the
        // MethodDef table itself when resolving bodies.
        module.methods.push(MethodDefinition {
            name,
            attributes,
            impl_attributes,
            signature,
            parameters: Vec::new(),
            return_parameter: Parameter::default(),
            generic_parameters: Vec::new(),
            declaring_type: TypeId(0),
            body: None,
            pinvoke: None,
            overrides: Vec::new(),
            constant: None,
            marshal_info: None,
            custom_attributes: Vec::new(),
            security_declarations: Vec::new(),
        });
        ctx.method_defs.push(MethodId(rid - 1));
    }
    Ok(())
}

/// Reads `Param` rows and attaches them to their owning methods
/// (`sequence == 0` is the return parameter). Returns a lookup
/// `param rid -> (method, sequence)` reused by Constant / FieldMarshal /
/// CustomAttribute passes.
fn read_params(module: &mut Module, md: &MetadataReader) -> Result<Vec<Option<(MethodId, u16)>>> {
    let count = md.row_count(T::Param);
    let mut owners: Vec<Option<(MethodId, u16)>> = vec![None; count as usize];
    let mut param_next: Vec<usize> = (0..=count as usize).collect();

    let method_count = md.row_count(T::MethodDef);
    let mut starts = Vec::with_capacity(method_count as usize);
    for rid in 1..=method_count {
        starts.push(cell_u32(md, T::MethodDef, rid, 5)?);
    }
    for (i, start) in starts.iter().enumerate() {
        let end = list_end(&starts, i, count);
        // Size the parameter arena from the signature's declared arity
        // (itself bounded by the signature blob): a hostile Param row with
        // sequence up to 65535 would otherwise resize one method's list to
        // 65K entries, and a few hundred such rows exhaust memory.
        let arity = module.methods[i].signature.parameters.len();
        module.methods[i].parameters.reserve_exact(arity);
        module.methods[i].parameters.resize(arity, Default::default());
        let mut p =
            next_unclaimed(&mut param_next, (*start).max(1).saturating_sub(1).min(count) as usize);
        let limit = end.saturating_sub(1).min(count) as usize;
        while p < limit {
            let p_rid = p as u32 + 1;
            let row = md.row_array::<3>(T::Param, p_rid)?;
            let attributes = ParameterAttributes::from_bits_truncate(row[0] as u16);
            let sequence = row[1] as u16;
            let name = heap_name(md, row[2] as u32)?;
            let parameter = Parameter { name, attributes, sequence, ..Default::default() };
            owners[p] = Some((MethodId(i as u32), sequence));
            let method = &mut module.methods[i];
            if sequence == 0 {
                method.return_parameter = parameter;
            } else {
                let slot = (sequence - 1) as usize;
                // Sequence beyond the declared arity is malformed; skip the
                // row (deferred-resolution policy for unresolvable links).
                if slot < method.parameters.len() {
                    method.parameters[slot] = parameter;
                }
            }
            let next = next_unclaimed(&mut param_next, p + 1);
            param_next[p] = next;
            p = next;
        }
    }
    Ok(owners)
}

// ---------------------------------------------------------------------------
// Properties / Events / MethodSemantics
// ---------------------------------------------------------------------------

/// Read PropertyMap/EventMap runs only when every member row has exactly one
/// valid owner. The arenas below must stay in metadata row order: gaps or
/// overlapping runs would make `rid - 1` handles point at the wrong definition.
fn read_member_map(
    md: &MetadataReader,
    map: T,
    member: T,
    type_count: usize,
) -> Result<Vec<(usize, std::ops::Range<u32>)>> {
    let map_count = md.row_count(map);
    let member_count = md.row_count(member);
    if map_count == 0 {
        if member_count != 0 {
            return Err(bad(format!("{map:?} missing for nonempty {member:?} table")));
        }
        return Ok(Vec::new());
    }

    let limit =
        member_count.checked_add(1).ok_or_else(|| bad(format!("{map:?} member count overflow")))?;
    let mut parents_seen = vec![false; type_count];
    let mut ranges: Vec<(usize, std::ops::Range<u32>)> = Vec::with_capacity(map_count as usize);
    for rid in 1..=map_count {
        let parent = cell_u32(md, map, rid, 0)?;
        let parent_slot = checked_slot(parent as usize, type_count, &format!("{map:?} parent"))?;
        if parents_seen[parent_slot] {
            return Err(bad(format!("{map:?} row {rid}: duplicate parent {parent}")));
        }
        parents_seen[parent_slot] = true;

        let start = cell_u32(md, map, rid, 1)?;
        if start == 0 || start > limit || (rid == 1 && start != 1) {
            return Err(bad(format!("{map:?} row {rid}: invalid list start {start}")));
        }
        if let Some((_, previous)) = ranges.last_mut() {
            if start < previous.start {
                return Err(bad(format!("{map:?} row {rid}: decreasing list start {start}")));
            }
            previous.end = start;
        }
        ranges.push((parent_slot, start..limit));
    }
    Ok(ranges)
}

/// Creates the property and event arenas from their maps, attaches them to
/// owning types, and wires accessor links from `MethodSemantics` rows.
fn read_properties_events_semantics(
    module: &mut Module,
    ctx: &ReadContext,
    md: &MetadataReader,
) -> Result<()> {
    // -- Events ----------------------------------------------------------
    let event_ranges = read_member_map(md, T::EventMap, T::Event, module.types.len())?;
    for (parent, range) in event_ranges {
        module.types[parent].events.reserve_exact(range.len());
        for e in range {
            let row = md.row_array::<3>(T::Event, e)?;
            let attributes = EventAttributes::from_bits_truncate(row[0] as u16);
            let name = heap_name(md, row[1] as u32)?;
            let event_type = if row[2] == 0 {
                None
            } else {
                ctx.recover(ctx.tdor_to_typedesc(md, row[2] as u32), T::Event, e)?
            };
            module.events.push(EventDefinition {
                name,
                attributes,
                event_type,
                ..Default::default()
            });
            module.types[parent].events.push(EventId(e - 1));
        }
    }

    // -- Properties -------------------------------------------------------
    let prop_ranges = read_member_map(md, T::PropertyMap, T::Property, module.types.len())?;
    for (parent, range) in prop_ranges {
        module.types[parent].properties.reserve_exact(range.len());
        for p in range {
            let row = md.row_array::<3>(T::Property, p)?;
            let attributes = PropertyAttributes::from_bits_truncate(row[0] as u16);
            let name = heap_name(md, row[1] as u32)?;
            let sig_blob = heap_blob(md, row[2] as u32)?;
            let signature = {
                let sig_ctx = ctx.sig_context(md);
                ctx.recover(parse_property_signature(sig_blob, &sig_ctx), T::Property, p)?
                    .unwrap_or(PropertyDefinition::default().signature)
            };
            module.properties.push(PropertyDefinition {
                name,
                attributes,
                signature,
                ..Default::default()
            });
            module.types[parent].properties.push(PropertyId(p - 1));
        }
    }

    // -- MethodSemantics ---------------------------------------------------
    for rid in 1..=md.row_count(T::MethodSemantics) {
        let row = md.row_array::<3>(T::MethodSemantics, rid)?;
        let semantics = MethodSemanticsAttributes::from_bits_truncate(row[0] as u16);
        let method_cell = row[1] as usize;
        let assoc_cell = row[2];
        let (table, target) = decode_group(&coded::HAS_SEMANTICS, assoc_cell)?;
        let method =
            MethodId(
                checked_slot(method_cell, module.methods.len(), "MethodSemantics method")? as u32
            );
        match table {
            T::Event => {
                let slot =
                    checked_slot(target as usize, module.events.len(), "MethodSemantics event")?;
                let event = &mut module.events[slot];
                if semantics.contains(MethodSemanticsAttributes::ADD_ON) {
                    event.add_on = Some(method);
                }
                if semantics.contains(MethodSemanticsAttributes::REMOVE_ON) {
                    event.remove_on = Some(method);
                }
                if semantics.contains(MethodSemanticsAttributes::FIRE) {
                    event.fire = Some(method);
                }
                if semantics.contains(MethodSemanticsAttributes::OTHER) {
                    event.other_methods.push(method);
                }
            }
            T::Property => {
                let slot = checked_slot(
                    target as usize,
                    module.properties.len(),
                    "MethodSemantics property",
                )?;
                let property = &mut module.properties[slot];
                if semantics.contains(MethodSemanticsAttributes::GETTER) {
                    property.get_method = Some(method);
                }
                if semantics.contains(MethodSemanticsAttributes::SETTER) {
                    property.set_method = Some(method);
                }
                if semantics.contains(MethodSemanticsAttributes::OTHER) {
                    property.other_methods.push(method);
                }
            }
            _ => return Err(bad("HasSemantics cell with unexpected tag".into())),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Generic parameters
// ---------------------------------------------------------------------------

fn read_generic_params(
    module: &mut Module,
    ctx: &mut ReadContext,
    md: &MetadataReader,
) -> Result<Vec<Option<(usize, usize)>>> {
    let count = md.row_count(T::GenericParam);
    for rid in 1..=count {
        let row = md.row_array::<4>(T::GenericParam, rid)?;
        let number = row[0] as u16;
        let attributes = GenericParameterAttributes::from_bits_truncate(row[1] as u16);
        let owner_cell = row[2];
        let (owner_table, owner_rid) = decode_group(&coded::TYPE_OR_METHOD_DEF, owner_cell)?;
        let name = heap_name(md, row[3] as u32)?;

        let owner = match owner_table {
            T::TypeDef => {
                let slot = checked_slot(
                    owner_rid as usize,
                    module.types.len(),
                    "GenericParam owner type",
                )?;
                module.types[slot].generic_parameters.push(GenericParamId(rid - 1));
                GenericOwner::Type(TypeId(slot as u32))
            }
            T::MethodDef => {
                let slot = checked_slot(
                    owner_rid as usize,
                    module.methods.len(),
                    "GenericParam owner method",
                )?;
                module.methods[slot].generic_parameters.push(GenericParamId(rid - 1));
                GenericOwner::Method(MethodId(slot as u32))
            }
            _ => return Err(bad("TypeOrMethodDef cell with unexpected tag".into())),
        };

        module.generic_parameters.push(GenericParameter {
            name,
            attributes,
            position: number,
            owner,
            ..Default::default()
        });
        ctx.gen_params.push(GenericParamId(rid - 1));
    }

    // Constraints grouped by owner parameter. The row -> (generic parameter,
    // constraint slot) map feeds the CustomAttribute pass, whose
    // GenericParamConstraint-parented rows target the constraint row itself.
    let mut constraints: Vec<Vec<u32>> = vec![Vec::new(); count as usize];
    let mut constraint_owners: Vec<Option<(usize, usize)>> =
        vec![None; md.row_count(T::GenericParamConstraint) as usize];
    for rid in 1..=md.row_count(T::GenericParamConstraint) {
        let owner = cell_u32(md, T::GenericParamConstraint, rid, 0)? as usize;
        let constraint_cell = md.column(T::GenericParamConstraint, rid, 1)?;
        let slot = checked_slot(owner, constraints.len(), "GenericParamConstraint owner")?;
        constraint_owners[rid as usize - 1] = Some((slot, constraints[slot].len()));
        constraints[slot].push(constraint_cell as u32);
    }
    for (i, cells) in constraints.iter().enumerate() {
        for cell_value in cells {
            let desc = ctx.tdor_to_typedesc(md, *cell_value)?;
            module.generic_parameters[i].constraints.push(GenericParamConstraint::from(desc));
        }
    }
    Ok(constraint_owners)
}

// ---------------------------------------------------------------------------
// Base types / Interfaces / Layouts / RVAs
// ---------------------------------------------------------------------------

fn read_base_types_and_interfaces(
    module: &mut Module,
    ctx: &ReadContext,
    md: &MetadataReader,
) -> Result<Vec<Option<(usize, usize)>>> {
    let count = md.row_count(T::TypeDef);
    for rid in 1..=count {
        let extends = md.column(T::TypeDef, rid, 3)?;
        if extends != 0 {
            module.types[rid as usize - 1].base_type =
                ctx.recover(ctx.tdor_to_typedesc(md, extends as u32), T::TypeDef, rid)?;
        }
    }

    // InterfaceImpl rows are sorted by Class; group them in row order. The
    // row -> (type, interface slot) map feeds the CustomAttribute pass, whose
    // InterfaceImpl-parented rows target the implementation row itself.
    let mut interface_owners: Vec<Option<(usize, usize)>> =
        vec![None; md.row_count(T::InterfaceImpl) as usize];
    for rid in 1..=md.row_count(T::InterfaceImpl) {
        let class = cell_u32(md, T::InterfaceImpl, rid, 0)? as usize;
        let iface_cell = cell_u32(md, T::InterfaceImpl, rid, 1)?;
        let iface = ctx.tdor_to_typedesc(md, iface_cell)?;
        let slot = checked_slot(class, module.types.len(), "InterfaceImpl class")?;
        interface_owners[rid as usize - 1] = Some((slot, module.types[slot].interfaces.len()));
        module.types[slot].interfaces.push(InterfaceImpl::from(iface));
    }
    Ok(interface_owners)
}

fn read_class_layouts(module: &mut Module, md: &MetadataReader) -> Result<()> {
    for rid in 1..=md.row_count(T::ClassLayout) {
        let packing_size = cell_u16(md, T::ClassLayout, rid, 0)? as i16 as i32;
        let class_size = cell_u32(md, T::ClassLayout, rid, 1)? as i32;
        let parent = cell_u32(md, T::ClassLayout, rid, 2)? as usize;
        let slot = checked_slot(parent, module.types.len(), "ClassLayout parent")?;
        module.types[slot].class_layout = Some(ClassLayout { packing_size, class_size });
    }
    Ok(())
}

fn read_field_layouts(module: &mut Module, md: &MetadataReader) -> Result<()> {
    for rid in 1..=md.row_count(T::FieldLayout) {
        let offset = cell_u32(md, T::FieldLayout, rid, 0)? as i32;
        let field = cell_u32(md, T::FieldLayout, rid, 1)? as usize;
        let slot = checked_slot(field, module.fields.len(), "FieldLayout field")?;
        module.fields[slot].offset = Some(offset);
    }
    Ok(())
}

/// Port of `GetFieldTypeSize`: initial-data length of a field with an RVA.
fn field_type_size(module: &Module, ty: &TypeDesc, pointer_size: usize) -> i32 {
    match ty {
        TypeDesc::Internal(name) => match name.as_ref() {
            "bool" | "int8" | "uint8" => 1,
            "char" | "int16" | "uint16" => 2,
            "int32" | "uint32" | "float32" => 4,
            "int64" | "uint64" | "float64" => 8,
            "intptr" | "uintptr" => pointer_size as i32,
            _ => 0,
        },
        TypeDesc::Ptr(_) | TypeDesc::FnPtr(_) => pointer_size as i32,
        TypeDesc::CMod { unmodified, .. } => field_type_size(module, unmodified, pointer_size),
        TypeDesc::Def(id) => {
            module.types[id.index()].class_layout.map(|l| l.class_size).unwrap_or(0)
        }
        _ => 0,
    }
}

/// Attaches `FieldRVA` rows: stores the RVA and slices the initial data out
/// of the image when the field carries `HAS_FIELD_RVA`. Data length follows
/// Mono.Cecil `GetFieldTypeSize` (primitive sizes; resolved class layout
/// size otherwise). Divergence note: Cecil resolves lazily and degrades to
/// an empty array on truncation; here malformed data is an error.
fn read_field_rvas(
    module: &mut Module,
    image: &cecil_pe::Image,
    md: &MetadataReader,
) -> Result<()> {
    let pointer_size = if image.architecture.is_pe64() { 8 } else { 4 };
    for rid in 1..=md.row_count(T::FieldRva) {
        let rva = cell_u32(md, T::FieldRva, rid, 0)? as u64;
        let field = cell_u32(md, T::FieldRva, rid, 1)? as usize;
        let slot = checked_slot(field, module.fields.len(), "FieldRVA field")?;
        let size = field_type_size(module, &module.fields[slot].signature.0, pointer_size);
        let field_def = &mut module.fields[slot];
        field_def.rva = rva;
        if field_def.attributes.contains(FieldAttributes::HAS_FIELD_RVA) && rva != 0 && size > 0 {
            let raw = image.rva(rva)?;
            let len = (size as usize).min(raw.len());
            field_def.initial_value = raw[..len].to_vec();
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Constants / Marshal specs
// ---------------------------------------------------------------------------

fn read_constants(
    module: &mut Module,
    md: &MetadataReader,
    param_owners: &[Option<(MethodId, u16)>],
) -> Result<()> {
    for rid in 1..=md.row_count(T::Constant) {
        let et_byte = md.column(T::Constant, rid, 0)? as u8;
        let parent_cell = md.column(T::Constant, rid, 2)?;
        let blob = cell_blob(md, T::Constant, rid, 3)?;
        let et = ElementType::from_u8(et_byte).ok_or_else(|| {
            bad(format!("Constant row {rid}: unknown element type 0x{et_byte:02X}"))
        })?;
        // Mono.Cecil `ReadConstantString`: a STRING constant's blob is the
        // raw UTF-16 payload (odd trailing byte dropped), not a #US index,
        // so it bypasses the primitive constant codec.
        let value = Some(if et == ElementType::String {
            let mut count = blob.len();
            if count & 1 == 1 {
                count -= 1;
            }
            let units: Vec<u16> = blob[..count]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .collect();
            ConstantValue::String(String::from_utf16_lossy(&units))
        } else {
            parse_constant_blob(et, blob)?
        });

        let (table, target) = decode_group(&coded::HAS_CONSTANT, parent_cell)?;
        match table {
            T::Field => {
                let slot = checked_slot(target as usize, module.fields.len(), "Constant field")?;
                module.fields[slot].constant = value;
            }
            T::Param => {
                let slot = checked_slot(target as usize, param_owners.len(), "Constant param")?;
                if let Some((method, sequence)) = param_owners[slot] {
                    let method_def = &mut module.methods[method.index()];
                    if sequence == 0 {
                        method_def.return_parameter.constant = value;
                    } else if let Some(parameter) =
                        method_def.parameters.get_mut(sequence as usize - 1)
                    {
                        parameter.constant = value;
                    }
                }
            }
            T::Property => {
                let slot =
                    checked_slot(target as usize, module.properties.len(), "Constant property")?;
                module.properties[slot].constant = value;
            }
            _ => return Err(bad("HasConstant cell with unexpected tag".into())),
        }
    }
    Ok(())
}

fn read_marshal_specs(
    module: &mut Module,
    ctx: &ReadContext,
    md: &MetadataReader,
    param_owners: &[Option<(MethodId, u16)>],
) -> Result<()> {
    for rid in 1..=md.row_count(T::FieldMarshal) {
        let parent_cell = md.column(T::FieldMarshal, rid, 0)?;
        let blob = cell_blob(md, T::FieldMarshal, rid, 1)?;
        let info =
            parse_marshal_spec(blob, &mut |cell_value: u32| ctx.tdor_to_typedesc(md, cell_value))?;

        let (table, target) = decode_group(&coded::HAS_FIELD_MARSHAL, parent_cell)?;
        match table {
            T::Field => {
                let slot =
                    checked_slot(target as usize, module.fields.len(), "FieldMarshal field")?;
                module.fields[slot].marshal_info = Some(info);
            }
            T::Param => {
                let slot = checked_slot(target as usize, param_owners.len(), "FieldMarshal param")?;
                if let Some((method, sequence)) = param_owners[slot] {
                    let method_def = &mut module.methods[method.index()];
                    if sequence == 0 {
                        method_def.return_parameter.marshal_info = Some(info);
                    } else if let Some(parameter) =
                        method_def.parameters.get_mut(sequence as usize - 1)
                    {
                        parameter.marshal_info = Some(info);
                    }
                }
            }
            _ => return Err(bad("HasFieldMarshal cell with unexpected tag".into())),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// P/Invoke / overrides / security
// ---------------------------------------------------------------------------

fn read_impl_maps(module: &mut Module, md: &MetadataReader) -> Result<()> {
    for rid in 1..=md.row_count(T::ImplMap) {
        let attributes = PInvokeAttributes::from_bits_truncate(cell_u16(md, T::ImplMap, rid, 0)?);
        let forwarded_cell = md.column(T::ImplMap, rid, 1)?;
        let entry_point = cell_str(md, T::ImplMap, rid, 2)?;
        let scope = cell_u32(md, T::ImplMap, rid, 3)? as usize;
        let scope = checked_slot(scope, md.row_count(T::ModuleRef) as usize, "ImplMap scope")?;
        let module_name = cell_str(md, T::ModuleRef, scope as u32 + 1, 0)?;

        let (table, target) = decode_group(&coded::MEMBER_FORWARDED, forwarded_cell)?;
        if table != T::MethodDef {
            // Field forwarding through P/Invoke has no slot in the frozen
            // field model.
            continue;
        }
        let slot = checked_slot(target as usize, module.methods.len(), "ImplMap method")?;
        module.methods[slot].pinvoke =
            Some(PInvokeInfo { attributes, entry_point, module: module_name });
    }
    Ok(())
}

fn read_method_impls(module: &mut Module, ctx: &ReadContext, md: &MetadataReader) -> Result<()> {
    for rid in 1..=md.row_count(T::MethodImpl) {
        let body_cell = md.column(T::MethodImpl, rid, 1)?;
        let decl_cell = md.column(T::MethodImpl, rid, 2)?;
        let body_ref = ctx.method_def_or_ref(md, body_cell as u32)?;
        let declaration = ctx.method_def_or_ref(md, decl_cell as u32)?;
        // Overrides hang off the implementing method; a MemberRef-implementing
        // body (only legal in edited metadata) has no owner to attach to.
        if let MethodRef::Def(method) = body_ref {
            if method.index() >= module.methods.len() {
                return Err(bad(format!("MethodImpl row {rid}: body method out of range")));
            }
            module.methods[method.index()]
                .overrides
                .push(MethodOverride { body: body_ref, declaration });
        }
    }
    Ok(())
}

fn security_action(value: u16) -> Result<SecurityAction> {
    Ok(match value {
        1 => SecurityAction::Request,
        2 => SecurityAction::Demand,
        3 => SecurityAction::Assert,
        4 => SecurityAction::Deny,
        5 => SecurityAction::PermitOnly,
        6 => SecurityAction::LinkDemand,
        7 => SecurityAction::InheritanceDemand,
        8 => SecurityAction::RequestMinimum,
        9 => SecurityAction::RequestOptional,
        10 => SecurityAction::RequestRefuse,
        _ => return Err(bad(format!("unknown DeclSecurity action {value}"))),
    })
}

fn read_decl_security(
    module: &mut Module,
    ctx: &mut ReadContext,
    md: &MetadataReader,
) -> Result<()> {
    for rid in 1..=md.row_count(T::DeclSecurity) {
        let action = security_action(cell_u16(md, T::DeclSecurity, rid, 0)?)?;
        let parent_cell = md.column(T::DeclSecurity, rid, 1)?;
        let blob = cell_blob(md, T::DeclSecurity, rid, 2)?.to_vec();
        let declaration = SecurityDeclaration { action, blob };

        let (table, target) = decode_group(&coded::HAS_DECL_SECURITY, parent_cell)?;
        match table {
            T::TypeDef => {
                let slot = checked_slot(target as usize, module.types.len(), "DeclSecurity type")?;
                module.types[slot].security_declarations.push(declaration);
            }
            T::MethodDef => {
                let slot =
                    checked_slot(target as usize, module.methods.len(), "DeclSecurity method")?;
                module.methods[slot].security_declarations.push(declaration);
            }
            T::Assembly => match ctx.assembly_row.as_mut() {
                Some(row) => row.security_declarations.push(declaration),
                None => {
                    return Err(bad(format!(
                        "DeclSecurity row {rid}: Assembly parent without an Assembly row"
                    )))
                }
            },
            _ => return Err(bad("HasDeclSecurity cell with unexpected tag".into())),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Custom attributes
// ---------------------------------------------------------------------------

/// Resolves a `CustomAttributeType` coded cell (3 tag bits; per ECMA-335
/// II §24.2.6 the used tags are 2 = MethodDef and 3 = MemberRef) into a
/// [`MethodRef`].
fn attribute_ctor(ctx: &ReadContext, _md: &MetadataReader, ctor_cell: u64) -> Result<MethodRef> {
    let (table, rid) = decode_group(&coded::CUSTOM_ATTRIBUTE_TYPE, ctor_cell)?;
    match table {
        T::MethodDef => {
            let slot = checked_slot(
                rid as usize,
                ctx.method_defs.len(),
                "custom attribute constructor method",
            )?;
            Ok(MethodRef::Def(ctx.method_defs[slot]))
        }
        T::MemberRef => match ctx.member_ref_row(rid) {
            Some(MemberRefRow::Method(external)) => Ok(MethodRef::External(external.clone())),
            _ => Err(bad(format!(
                "custom attribute constructor MemberRef row {rid} is not a method"
            ))),
        },
        _ => Err(bad("CustomAttributeType cell with unexpected tag".into())),
    }
}

/// Groups `CustomAttribute` rows by their `HasCustomAttribute` parent and
/// pushes each instance into the owning entity. Assembly-parented rows are
/// collected on [`AssemblyRowData::custom_attributes`], module-parented rows
/// on [`Module::custom_attributes`]. Parents without a slot in the frozen
/// model (TypeRef, MemberRef, DeclSecurity, StandAloneSig, ModuleRef,
/// TypeSpec, File, ExportedType, ManifestResource, MethodSpec) are skipped.
fn read_custom_attributes(
    module: &mut Module,
    ctx: &mut ReadContext,
    md: &MetadataReader,
    param_owners: &[Option<(MethodId, u16)>],
    interface_impl_owners: &[Option<(usize, usize)>],
    constraint_owners: &[Option<(usize, usize)>],
) -> Result<()> {
    // Writers normally sort HasCustomAttribute parents into consecutive runs.
    // Reserve each run once: Vec's first push otherwise allocates four large
    // constructor/blob records even for entities carrying just one attribute.
    // Runs may reappear in an unsorted table; later runs use geometric growth
    // so interleaving parents cannot force quadratic reallocation.
    let count = md.row_count(T::CustomAttribute);
    let mut run_end = 0;
    for rid in 1..=md.row_count(T::CustomAttribute) {
        let row = md.row_array::<3>(T::CustomAttribute, rid)?;
        let parent_cell = row[0];
        let reserve = if rid >= run_end {
            run_end = rid + 1;
            while run_end <= count && md.column(T::CustomAttribute, run_end, 0)? == parent_cell {
                run_end += 1;
            }
            (run_end - rid) as usize
        } else {
            0
        };
        let ctor_cell = row[1];
        let blob = heap_blob(md, row[2] as u32)?.to_vec();
        let constructor = attribute_ctor(ctx, md, ctor_cell)?;
        let attribute = CustomAttribute { constructor, blob };

        let (table, target) = decode_group(&coded::HAS_CUSTOM_ATTRIBUTE, parent_cell)?;
        // Checked parent index; keeps every arm a one-liner.
        let idx = |len: usize| -> Result<usize> {
            checked_slot(target as usize, len, "CustomAttribute parent")
        };
        match table {
            T::MethodDef => {
                let i = idx(module.methods.len())?;
                push_attribute(&mut module.methods[i].custom_attributes, attribute, reserve);
            }
            T::Field => {
                let i = idx(module.fields.len())?;
                push_attribute(&mut module.fields[i].custom_attributes, attribute, reserve);
            }
            T::TypeDef => {
                let i = idx(module.types.len())?;
                push_attribute(&mut module.types[i].custom_attributes, attribute, reserve);
            }
            T::Param => {
                let slot =
                    checked_slot(target as usize, param_owners.len(), "CustomAttribute param")?;
                let Some((method, sequence)) = param_owners[slot] else {
                    continue;
                };
                let method_def = &mut module.methods[method.index()];
                let slot = if sequence == 0 {
                    &mut method_def.return_parameter
                } else {
                    match method_def.parameters.get_mut(sequence as usize - 1) {
                        Some(parameter) => parameter,
                        None => continue,
                    }
                };
                push_attribute(&mut slot.custom_attributes, attribute, reserve);
            }
            T::Property => {
                let i = idx(module.properties.len())?;
                push_attribute(&mut module.properties[i].custom_attributes, attribute, reserve);
            }
            T::Event => {
                let i = idx(module.events.len())?;
                push_attribute(&mut module.events[i].custom_attributes, attribute, reserve);
            }
            T::GenericParam => {
                let i = idx(module.generic_parameters.len())?;
                push_attribute(
                    &mut module.generic_parameters[i].custom_attributes,
                    attribute,
                    reserve,
                );
            }
            T::Module => {
                // The Module table holds exactly one row; anything else is a
                // malformed parent cell.
                if target != 1 {
                    return Err(bad(format!("CustomAttribute row {rid}: invalid Module parent")));
                }
                push_attribute(&mut module.custom_attributes, attribute, reserve);
            }
            T::InterfaceImpl => {
                let slot = checked_slot(
                    target as usize,
                    interface_impl_owners.len(),
                    "CustomAttribute interface impl",
                )?;
                let Some((type_slot, iface_index)) = interface_impl_owners[slot] else {
                    continue;
                };
                let Some(type_def) = module.types.get_mut(type_slot) else {
                    continue;
                };
                match type_def.interfaces.get_mut(iface_index) {
                    Some(implementation) => {
                        push_attribute(&mut implementation.custom_attributes, attribute, reserve)
                    }
                    None => continue,
                }
            }
            T::GenericParamConstraint => {
                let slot = checked_slot(
                    target as usize,
                    constraint_owners.len(),
                    "CustomAttribute generic param constraint",
                )?;
                let Some((gp_slot, constraint_index)) = constraint_owners[slot] else {
                    continue;
                };
                let Some(gp) = module.generic_parameters.get_mut(gp_slot) else {
                    continue;
                };
                match gp.constraints.get_mut(constraint_index) {
                    Some(constraint) => {
                        push_attribute(&mut constraint.custom_attributes, attribute, reserve)
                    }
                    None => continue,
                }
            }
            T::AssemblyRef => {
                let i = idx(ctx.asm_refs.len())?;
                push_attribute(&mut ctx.asm_refs[i].custom_attributes, attribute, reserve);
            }
            T::Assembly => {
                // The Assembly table holds at most one row; anything else is
                // a malformed parent cell.
                if target != 1 {
                    return Err(bad(format!("CustomAttribute row {rid}: invalid Assembly parent")));
                }
                match ctx.assembly_row.as_mut() {
                    Some(row) => push_attribute(&mut row.custom_attributes, attribute, reserve),
                    None => {
                        return Err(bad(format!(
                            "CustomAttribute row {rid}: Assembly parent without an Assembly row"
                        )))
                    }
                }
            }
            // Parents without a slot in the object model are dropped, mirroring
            // the documented read-path behavior for unmodeled rows.
            _ => {}
        }
    }
    Ok(())
}

fn push_attribute(
    attributes: &mut Vec<CustomAttribute>,
    attribute: CustomAttribute,
    reserve: usize,
) {
    if reserve != 0 {
        if attributes.is_empty() {
            attributes.reserve_exact(reserve);
        } else {
            attributes.reserve(reserve);
        }
    }
    attributes.push(attribute);
}

// ---------------------------------------------------------------------------
// Assembly row
// ---------------------------------------------------------------------------

/// Reads the single `Assembly` row into [`AssemblyRowData`].
fn read_assembly_row(image: &cecil_pe::Image, md: &MetadataReader) -> Result<AssemblyRowData> {
    let hash_alg = AssemblyHashAlgorithm::from_u32(cell_u32(md, T::Assembly, 1, 0)?)
        .unwrap_or(AssemblyHashAlgorithm::None);
    let major = cell_u16(md, T::Assembly, 1, 1)?;
    let minor = cell_u16(md, T::Assembly, 1, 2)?;
    let build = cell_u16(md, T::Assembly, 1, 3)?;
    let revision = cell_u16(md, T::Assembly, 1, 4)?;
    let flags = cell_u32(md, T::Assembly, 1, 5)?;
    let public_key = cell_blob(md, T::Assembly, 1, 6)?.to_vec();
    let name = cell_str(md, T::Assembly, 1, 7)?;
    let culture = {
        let value = cell_str(md, T::Assembly, 1, 8)?;
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    };
    Ok(AssemblyRowData {
        name,
        version: Version::new(major, minor, build, revision),
        culture,
        public_key,
        hash_alg,
        flags,
        entry_point_token: image.entry_point_token(),
        // Populated later by read_custom_attributes / read_decl_security.
        custom_attributes: Vec::new(),
        security_declarations: Vec::new(),
    })
}

// ---------------------------------------------------------------------------
// File / ExportedType / ManifestResource
// ---------------------------------------------------------------------------

fn read_files_exported_types_resources(
    module: &mut Module,
    ctx: &ReadContext,
    image: &cecil_pe::Image,
    md: &MetadataReader,
) -> Result<()> {
    for rid in 1..=md.row_count(T::File) {
        let attributes = FileRowAttributes::from_bits_truncate(cell_u32(md, T::File, rid, 0)?);
        let name = cell_str(md, T::File, rid, 1)?;
        let hash = cell_blob(md, T::File, rid, 2)?.to_vec();
        module.file_rows.push(FileRow { name, attributes, hash });
    }

    for rid in 1..=md.row_count(T::ExportedType) {
        let attributes = TypeAttributes::from_bits_truncate(cell_u32(md, T::ExportedType, rid, 0)?);
        let type_def_id = cell_u32(md, T::ExportedType, rid, 1)?;
        let name = cell_str(md, T::ExportedType, rid, 2)?;
        let namespace = cell_str(md, T::ExportedType, rid, 3)?;
        let impl_cell = md.column(T::ExportedType, rid, 4)?;
        let (impl_table, impl_rid) = decode_group(&coded::IMPLEMENTATION, impl_cell)?;
        let implementation = match impl_table {
            T::File => {
                let slot =
                    checked_slot(impl_rid as usize, module.file_rows.len(), "ExportedType file")?;
                ExportedImpl::File(slot)
            }
            T::AssemblyRef => {
                let slot = checked_slot(
                    impl_rid as usize,
                    ctx.asm_refs.len(),
                    "ExportedType assembly ref",
                )?;
                ExportedImpl::AssemblyRef(slot)
            }
            T::ExportedType => {
                // Nested exported types may reference later rows, so validate
                // against the full table rather than the rows read so far.
                checked_slot(
                    impl_rid as usize,
                    md.row_count(T::ExportedType) as usize,
                    "ExportedType exported type",
                )?;
                ExportedImpl::ExportedType(impl_rid)
            }
            _ => return Err(bad("Implementation cell with unexpected tag".into())),
        };
        module.exported_types.push(ExportedTypeRow {
            namespace,
            name,
            attributes,
            implementation,
            type_def_id,
        });
    }

    for rid in 1..=md.row_count(T::ManifestResource) {
        let offset = cell_u32(md, T::ManifestResource, rid, 0)?;
        let flags = ManifestResourceAttributes::from_bits_truncate(cell_u32(
            md,
            T::ManifestResource,
            rid,
            1,
        )?);
        let name = cell_str(md, T::ManifestResource, rid, 2)?;
        let impl_cell = md.column(T::ManifestResource, rid, 3)?;

        let resource = if impl_cell == 0 {
            Resource::Embedded {
                name,
                attributes: flags,
                data: embedded_resource_data(image, offset)?,
            }
        } else {
            let (impl_table, impl_rid) = decode_group(&coded::IMPLEMENTATION, impl_cell)?;
            match impl_table {
                T::AssemblyRef => {
                    let slot = checked_slot(
                        impl_rid as usize,
                        ctx.asm_refs.len(),
                        "ManifestResource assembly ref",
                    )?;
                    Resource::AssemblyLinked {
                        name,
                        attributes: flags,
                        assembly: ctx.asm_refs[slot].clone(),
                    }
                }
                T::File => {
                    let slot = checked_slot(
                        impl_rid as usize,
                        module.file_rows.len(),
                        "ManifestResource file",
                    )?;
                    Resource::Linked {
                        name,
                        attributes: flags,
                        file: module.file_rows[slot].name.clone(),
                    }
                }
                _ => return Err(bad("Implementation cell with unexpected tag".into())),
            }
        };
        module.resources.push(resource);
    }
    Ok(())
}

/// Port of `MetadataReader.GetManagedResource`: at `offset` inside the CLI
/// resources directory sits a 4-byte little-endian length followed by that
/// many payload bytes.
fn embedded_resource_data(image: &cecil_pe::Image, offset: u32) -> Result<Vec<u8>> {
    let header = image.cli_header();
    if header.resources_size == 0 {
        return Err(bad("embedded resource but the image has no resources directory".into()));
    }
    let directory = image.rva(header.resources_rva)?;
    let end = (header.resources_size as usize).min(directory.len());
    let directory = &directory[..end];

    let start = offset as usize;
    let Some(payload_start) = start.checked_add(4) else {
        return Err(bad("embedded resource offset overflows the resources directory".into()));
    };
    if payload_start > directory.len() {
        return Err(bad(format!(
            "embedded resource offset {start} outside the resources directory"
        )));
    }
    let length = i32::from_le_bytes([
        directory[start],
        directory[start + 1],
        directory[start + 2],
        directory[start + 3],
    ]);
    if length < 0 {
        return Err(bad(format!("negative embedded resource length {length}")));
    }
    let Some(data_end) = payload_start.checked_add(length as usize) else {
        return Err(bad("embedded resource length overflows the resources directory".into()));
    };
    if data_end > directory.len() {
        return Err(bad(format!(
            "embedded resource of {length} bytes at offset {start} overruns the resources directory"
        )));
    }
    Ok(directory[payload_start..data_end].to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_parsing_follows_cecil_rules() {
        assert_eq!(parse_runtime("v1.0.3705"), TargetRuntime::Net10);
        assert_eq!(parse_runtime("v1.1.4322"), TargetRuntime::Net11);
        assert_eq!(parse_runtime("v2.0.50727"), TargetRuntime::Net20);
        assert_eq!(parse_runtime("v4.0.30319"), TargetRuntime::Net40);
        assert_eq!(parse_runtime(""), TargetRuntime::Net40);
        assert_eq!(parse_runtime("weird"), TargetRuntime::Net40);
    }

    #[test]
    fn metadata_kind_detection() {
        assert_eq!(metadata_kind("v4.0.30319"), cecil_core::flags::MetadataKind::Ecma335);
        assert_eq!(
            metadata_kind("WindowsRuntime 1.3"),
            cecil_core::flags::MetadataKind::WindowsMetadata
        );
        assert_eq!(
            metadata_kind("WindowsRuntime CLR 4.0"),
            cecil_core::flags::MetadataKind::ManagedWindowsMetadata
        );
    }

    /// Integration test over the shared `hello.exe` fixture: full metadata
    /// read with bodies disabled. Skips gracefully wherever the fixtures
    /// directory is absent so the suite stays green anywhere.
    #[test]
    fn hello_fixture_reads_fully() {
        let path = cecil_core::fixtures_dir().join("hello.exe");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(&path).expect("reading fixtures/hello.exe");
        let image = cecil_pe::Image::parse(&bytes).expect("parsing PE image");

        let opts = ReadOptions { load_bodies: false };
        let (module, ctx) = read_module(&image, &opts).expect("read_module");

        // Module shell. Ground truth (raw table dump of fixtures/hello.exe):
        // the Module row stores "hello.exe" while the Assembly row stores
        // "hello" - exactly what Mono.Cecil reports, so we assert both.
        assert_eq!(module.name, "hello.exe");
        assert_eq!(ctx.assembly_row.as_ref().expect("Assembly row present").name, "hello");
        assert!(!module.guid.iter().all(|b| *b == 0), "MVID must be present");
        assert!(matches!(module.metadata_kind, cecil_core::flags::MetadataKind::Ecma335));
        assert!(module.attributes.contains(ModuleAttributes::IL_ONLY));

        // Arenas populated in row order; context mirrors them.
        assert!(!module.types.is_empty(), "at least one type");
        assert_eq!(ctx.type_defs.len(), module.types.len());
        assert_eq!(ctx.method_defs.len(), module.methods.len());
        assert_eq!(ctx.field_defs.len(), module.fields.len());
        assert!(!module.methods.is_empty());

        // Main method: parameterless static void Main somewhere in the module.
        let main = module.methods.iter().find(|m| m.name == "Main").expect("Main method exists");
        assert!(main.parameters.is_empty(), "Main must have no parameters");
        assert!(
            matches!(main.signature.return_type, TypeDesc::Internal(ref name) if name.as_ref() == "void"),
            "Main must return void"
        );

        // One AssemblyRef present, mirrored between module and context.
        assert!(!module.assembly_refs.is_empty(), "an AssemblyRef exists");
        assert_eq!(module.assembly_refs.len(), ctx.asm_refs.len());
        assert!(module.assembly_refs.iter().any(|r| !r.name.is_empty()));

        // Entry point recorded in both places and consistent.
        assert!(!module.entry_point_token.is_nil());
        assert_eq!(ctx.entry_point_token, module.entry_point_token);

        // Every method belongs to some defined type.
        for (i, method) in module.methods.iter().enumerate() {
            let ty = &module.types[method.declaring_type.index()];
            assert!(
                ty.methods.contains(&MethodId(i as u32)),
                "method {} wired to its declaring type",
                method.name
            );
        }

        // Assembly row surfaced for the facade (hello.exe is an assembly).
        let asm = ctx.assembly_row.as_ref().expect("Assembly row present");
        assert_eq!(asm.entry_point_token, module.entry_point_token);
        assert!(!asm.name.is_empty());
    }

    /// BLOCKER A6/P1 regression guard: ECMA-335 II §22.37 orders TypeDef
    /// rows as [Flags(0), Name(1), Namespace(2), ...]; an earlier revision
    /// read column 1 as the namespace and column 2 as the name, turning
    /// `Program` into namespace `Program` with name `exe`.
    #[test]
    fn hello_fixture_type_def_columns() {
        let path = cecil_core::fixtures_dir().join("hello.exe");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(&path).expect("reading fixtures/hello.exe");
        let image = cecil_pe::Image::parse(&bytes).expect("parsing PE image");
        let opts = ReadOptions { load_bodies: false };
        let (module, _ctx) = read_module(&image, &opts).expect("read_module");

        // Ground truth (raw table dump of fixtures/hello.exe): two TypeDef
        // rows - `<Module>` and top-level `Program` with an empty namespace.
        let program = module.find_type_full("Program").expect("Program resolves");
        assert_eq!(module.get_type_id("", "Program"), Some(program));
        let ty = module.type_def(program);
        assert_eq!(ty.name, "Program");
        assert_eq!(ty.namespace, "");
        assert!(module.find_type_full("<Module>").is_some());

        // hello.exe declares no nested types: no nested spelling may resolve.
        assert!(
            module.types.iter().all(|t| t.declaring_type.is_none()),
            "hello.exe declares only top-level types"
        );
        assert!(module.find_type_full("Program+Nested").is_none());
    }

    /// Nested types resolve through both the `+` and the `/` spelling of
    /// [`crate::module_def::Module::find_type_full`]. iterator.exe nests a
    /// single compiler-generated state-machine type under `Program`.
    #[test]
    fn nested_types_resolve_via_find_type_full_spellings() {
        let path = cecil_core::fixtures_dir().join("iterator.exe");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(&path).expect("reading fixtures/iterator.exe");
        let image = cecil_pe::Image::parse(&bytes).expect("parsing PE image");
        let opts = ReadOptions { load_bodies: false };
        let (module, _ctx) = read_module(&image, &opts).expect("read_module");

        let program = module.find_type_full("Program").expect("Program resolves");
        let nested_plus =
            module.find_type_full("Program+<GetLittleArgs>d__0").expect("+ spelling resolves");
        let nested_slash =
            module.find_type_full("Program/<GetLittleArgs>d__0").expect("/ spelling resolves");
        assert_eq!(nested_plus, nested_slash);
        assert_eq!(
            module.type_def(nested_plus).declaring_type,
            Some(program),
            "nested type is wired to Program"
        );
        assert_ne!(nested_plus, program);
    }

    /// Assembly-parented `CustomAttribute` rows land on
    /// [`AssemblyRowData::custom_attributes`] instead of being dropped.
    /// Ground truth (raw CustomAttribute table dumps): xattr.dll carries
    /// exactly three assembly-level attributes (Debuggable,
    /// CompilationRelaxations, RuntimeCompatibility); hello.exe exactly two.
    #[test]
    fn assembly_level_custom_attributes_are_kept() {
        for (file, expected) in [("xattr.dll", 3usize), ("hello.exe", 2)] {
            let path = cecil_core::fixtures_dir().join(file);
            if !path.exists() {
                continue;
            }
            let bytes = std::fs::read(&path).expect("reading fixture");
            let image = cecil_pe::Image::parse(&bytes).expect("parsing PE image");
            let opts = ReadOptions { load_bodies: false };
            let (_module, ctx) = read_module(&image, &opts).expect("read_module");
            let asm = ctx.assembly_row.as_ref().expect("Assembly row present");
            assert_eq!(asm.custom_attributes.len(), expected, "{file}");
            assert!(
                asm.security_declarations.is_empty(),
                "{file} has no assembly-level security declarations"
            );
        }
    }

    /// Regression guard: coded-index consumers must reject rid 0 instead of
    /// computing `rid - 1` (usize underflow / out-of-bounds indexing).
    #[test]
    fn zero_rid_coded_parent_is_an_error_not_a_panic() {
        use cecil_metadata::{encode_coded, MetadataBuilder};

        let mut b = MetadataBuilder::new("v4.0.30319");
        let mname = b.insert_string("<Module>");
        let mvid = b.insert_guid(&[7u8; 16]);
        b.add_row(T::Module, &[0, mname as u64, mvid as u64, 0, 0]).unwrap();

        // One Field row; the arena stays empty to prove the rid<1 check
        // fires before any bounds arithmetic.
        let fname = b.insert_string("F");
        let fsig = b.insert_blob(&[0x06, 0x08]); // FIELD + I4
        b.add_row(T::Field, &[0u64, fname as u64, fsig as u64]).unwrap();

        // Constant row whose HasConstant parent encodes Field rid 0.
        let cell = encode_coded(&coded::HAS_CONSTANT, T::Field, 0).unwrap();
        let cblob = b.insert_blob(&[0u8; 4]);
        b.add_row(T::Constant, &[ElementType::I4 as u64, 0, cell, cblob as u64]).unwrap();

        let bytes = b.finalize();
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let mut module = Module::default();

        let err = read_constants(&mut module, &md, &[]).expect_err("rid-0 parent must be rejected");
        assert!(err.to_string().contains("out of range"), "unexpected error: {err}");
    }

    /// Regression: the three formerly-unmodeled `HasCustomAttribute` parents
    /// (Module tag 0x00, InterfaceImpl tag 0x05, GenericParamConstraint tag
    /// 0x0d) must survive a full write -> read cycle. The synthetic module
    /// carries one module-parented attribute, two attributes on an interface
    /// implementation and one on a generic parameter constraint; the counts
    /// must be identical after every re-read.
    #[test]
    fn unmodeled_ca_parents_survive_write_read_cycle() {
        use crate::assembly::{AssemblyDefinition, AssemblyNameDefinition};

        fn ext(ns: &str, name: &str) -> TypeDesc {
            TypeDesc::External(std::sync::Arc::new(ExternalType {
                namespace: ns.to_owned(),
                name: name.to_owned(),
                nesting: Vec::new(),
                scope: ScopeRef::Moduleless,
            }))
        }

        fn ctor_attr(ns: &str, name: &str) -> CustomAttribute {
            CustomAttribute {
                constructor: MethodRef::External(std::sync::Arc::new(ExternalMethod {
                    parent: ext(ns, name),
                    name: ".ctor".to_owned(),
                    signature: MethodSignature::default(),
                })),
                blob: vec![0x01, 0x00],
            }
        }

        let mut m = Module {
            name: "caparents".to_owned(),
            custom_attributes: vec![ctor_attr(
                "System.Runtime.CompilerServices",
                "ReferenceAssemblyAttribute",
            )],
            ..Default::default()
        };

        let mut widget = TypeDefinition { name: "Widget".to_owned(), ..Default::default() };
        widget.interfaces.push(InterfaceImpl {
            interface: ext("System", "IDisposable"),
            custom_attributes: vec![
                ctor_attr("System.Runtime.InteropServices", "TypeIdentifierAttribute"),
                ctor_attr("System", "ComVisibleAttribute"),
            ],
        });
        let wid = m.add_type(widget);

        m.add_generic_parameter(GenericParameter {
            name: "T".to_owned(),
            owner: GenericOwner::Type(wid),
            constraints: vec![GenericParamConstraint {
                constraint: ext("System", "ValueType"),
                custom_attributes: vec![ctor_attr("System", "ObsoleteAttribute")],
            }],
            ..Default::default()
        });

        let mut ad = AssemblyDefinition {
            name: AssemblyNameDefinition { name: "caparents".to_owned(), ..Default::default() },
            main: m,
            ..AssemblyDefinition::default()
        };

        // Two write -> read rounds: the first exercises the writer arms plus
        // the reader arms against freshly emitted rows, the second proves the
        // reparsed model re-emits byte-equivalent structures.
        for round in 0..2 {
            let written = ad.write().unwrap_or_else(|e| panic!("round {round}: write: {e:?}"));
            let re = AssemblyDefinition::read(&written)
                .unwrap_or_else(|e| panic!("round {round}: re-read: {e:?}"));

            assert_eq!(re.main.custom_attributes.len(), 1, "round {round}: module CA count");
            let ty = re.main.get_type("", "Widget").expect("round {round}: Widget survives");
            assert_eq!(ty.interfaces.len(), 1, "round {round}: interface count");
            assert_eq!(
                ty.interfaces[0].custom_attributes.len(),
                2,
                "round {round}: interface impl CA count"
            );
            assert_eq!(re.main.generic_parameters.len(), 1, "round {round}: generic param count");
            assert_eq!(
                re.main.generic_parameters[0].constraints.len(),
                1,
                "round {round}: constraint count"
            );
            assert_eq!(
                re.main.generic_parameters[0].constraints[0].custom_attributes.len(),
                1,
                "round {round}: constraint CA count"
            );

            ad = re;
        }
    }

    /// Real-fixture ground truth for the three formerly-unmodeled CA parents:
    /// `TypeDefinitionDebugInformation.dll` carries one Module-parented
    /// attribute, `GenericParameterConstraintAttributes.dll` one attribute on
    /// an interface implementation and one on a generic parameter constraint,
    /// and the winmd fixtures carry several interface-implementation
    /// attributes. Raw-table ground truth gathered with a scanner over the
    /// fixture corpus; the sweep test proves they survive write -> re-parse.
    #[test]
    fn fixture_unmodeled_ca_parent_counts() {
        let cases: [(&str, usize, usize, usize); 4] = [
            // (file, module CAs, interface-impl CAs, constraint CAs)
            ("TypeDefinitionDebugInformation.dll", 1, 0, 0),
            ("GenericParameterConstraintAttributes.dll", 0, 1, 1),
            ("ManagedWinmd.winmd", 0, 8, 0),
            ("winrtcomp.winmd", 0, 2, 0),
        ];
        for (file, module_cas, iface_cas, constraint_cas) in cases {
            let path = cecil_core::fixtures_dir().join(file);
            if !path.exists() {
                continue;
            }
            let bytes = std::fs::read(&path).expect("reading fixture");
            let image = cecil_pe::Image::parse(&bytes).expect("parsing PE image");
            let opts = ReadOptions { load_bodies: false };
            let (module, _ctx) = read_module(&image, &opts).expect("read_module");

            assert_eq!(module.custom_attributes.len(), module_cas, "{file}: module CAs");
            let interfaces: usize = module
                .types
                .iter()
                .flat_map(|t| t.interfaces.iter())
                .map(|i| i.custom_attributes.len())
                .sum();
            assert_eq!(interfaces, iface_cas, "{file}: interface-impl CAs");
            let constraints: usize = module
                .generic_parameters
                .iter()
                .flat_map(|g| g.constraints.iter())
                .map(|c| c.custom_attributes.len())
                .sum();
            assert_eq!(constraints, constraint_cas, "{file}: constraint CAs");
        }
    }
}
