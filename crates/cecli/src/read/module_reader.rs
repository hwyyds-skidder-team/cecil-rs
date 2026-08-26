//! Port of Mono.Cecil's `AssemblyReader.cs` (`ReadModule`) path.
//!
//! [`read_module`] walks the metadata tables of an already-parsed PE/CLI
//! image and builds the arena-based object model ([`Module`](crate::module_def::Module))
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

use cecli_core::flags::{
    AssemblyHashAlgorithm, EventAttributes, FieldAttributes, FileRowAttributes,
    GenericParameterAttributes, ManifestResourceAttributes, MethodAttributes, MethodImplAttributes,
    MethodSemanticsAttributes, ModuleAttributes, ModuleCharacteristics, ModuleKind,
    PInvokeAttributes, ParameterAttributes, PropertyAttributes, SecurityAction, TargetArchitecture,
    TargetRuntime, TypeAttributes,
};
use cecli_core::token::coded;
use cecli_core::{ElementType, Error, Result, TableIndex as T, Token};
use cecli_metadata::{decode_coded, MetadataReader};

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
    Ok(md.heaps().strings.get(idx)?.to_owned())
}

fn cell_blob<'m>(md: &'m MetadataReader, table: T, rid: u32, c: usize) -> Result<&'m [u8]> {
    let idx = md.column(table, rid, c)? as u32;
    md.heaps().blob.get(idx)
}

fn cell_guid(md: &MetadataReader, table: T, rid: u32, c: usize) -> Result<[u8; 16]> {
    let idx = md.column(table, rid, c)? as u32;
    md.heaps().guid.get(idx)
}

/// Decodes a coded-index cell with a descriptive error when out of range.
fn decode_group(group: &'static cecli_core::CodedIndexGroup, value: u64) -> Result<(T, u32)> {
    decode_coded(group, value)
        .ok_or_else(|| Error::bad_image(format!("coded index {value:#x} out of range")))
}

fn bad(msg: String) -> Error {
    Error::bad_image(msg)
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
pub fn read_module(image: &cecli_pe::Image, opts: &ReadOptions) -> Result<(Module, ReadContext)> {
    // Bodies belong to unit R3 (`resolve_bodies`); never loaded here.
    let _ = opts;

    let (md_rva, md_size) = image.metadata_rva()?;
    let mapped = image.rva(md_rva)?;
    let root = &mapped[..md_size.min(mapped.len())];
    let md = MetadataReader::parse(root)?;

    let mut ctx = ReadContext::new(&md);

    let mut module = Module { entry_point_token: image.entry_point_token(), ..Default::default() };
    ctx.entry_point_token = module.entry_point_token;

    populate_shell(&mut module, image, md.version_string());
    read_module_row(&mut module, &md)?;

    // ---- Arenas in table row order ------------------------------------
    let typedef_rows = read_type_defs(&mut module, &mut ctx, &md)?;
    let nested_parents = read_nested_classes(&module, &md)?;
    apply_nesting(&mut module, &nested_parents);
    read_fields(&mut module, &mut ctx, &md)?;
    read_methods(&mut module, &mut ctx, &md)?;
    attach_member_ranges(&mut module, &typedef_rows, &md);
    let param_owners = read_params(&mut module, &md)?;
    read_properties_events_semantics(&mut module, &ctx, &md)?;
    read_generic_params(&mut module, &mut ctx, &md)?;

    // TypeSpec / MemberRef rows eagerly decoded into the context in
    // deterministic table order so every cross-reference below resolves
    // through one uniform path.
    ctx.resolve_lazy_tables(&md)?;

    // ---- Cross-table attachments ---------------------------------------
    read_base_types_and_interfaces(&mut module, &ctx, &md)?;
    read_class_layouts(&mut module, &md)?;
    read_field_layouts(&mut module, &md)?;
    read_field_rvas(&mut module, image, &md)?;
    read_constants(&mut module, &md, &param_owners)?;
    read_marshal_specs(&mut module, &ctx, &md, &param_owners)?;
    read_impl_maps(&mut module, &md)?;
    read_method_impls(&mut module, &ctx, &md)?;
    // Assembly-scope data is read before the DeclSecurity / CustomAttribute
    // passes so rows parented to the `Assembly` table can be attached to
    // [`ReadContext::assembly_row`].
    let has_assembly_row = md.row_count(T::Assembly) > 0;
    if has_assembly_row {
        ctx.assembly_row = Some(read_assembly_row(image, &md)?);
    } else {
        // No Assembly row => netmodule (Mono.Cecil ReadModuleManifest).
        module.kind = ModuleKind::NetModule;
    }
    read_decl_security(&mut module, &mut ctx, &md)?;
    read_custom_attributes(&mut module, &mut ctx, &md, &param_owners)?;
    module.assembly_refs = ctx.asm_refs.clone();
    module.module_refs = ctx.mod_refs.clone();
    read_files_exported_types_resources(&mut module, &ctx, image, &md)?;

    Ok((module, ctx))
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
fn metadata_kind(runtime_version: &str) -> cecli_core::flags::MetadataKind {
    if !runtime_version.contains("WindowsRuntime") {
        cecli_core::flags::MetadataKind::Ecma335
    } else if runtime_version.contains("CLR") {
        cecli_core::flags::MetadataKind::ManagedWindowsMetadata
    } else {
        cecli_core::flags::MetadataKind::WindowsMetadata
    }
}

fn populate_shell(module: &mut Module, image: &cecli_pe::Image, version: &str) {
    module.runtime_version = version.to_owned();
    module.runtime = parse_runtime(version);
    module.metadata_kind = metadata_kind(version);
    module.attributes = ModuleAttributes::from_bits_truncate(image.cli_header().flags);
    module.characteristics = ModuleCharacteristics::from_bits_truncate(image.dll_characteristics);
    module.architecture =
        TargetArchitecture::from_machine(image.architecture.0).unwrap_or(TargetArchitecture::I386);
    module.kind = match image.kind {
        cecli_pe::ModuleKind::Console => ModuleKind::Console,
        cecli_pe::ModuleKind::Windows => ModuleKind::Windows,
        cecli_pe::ModuleKind::Dll => ModuleKind::Dll,
        cecli_pe::ModuleKind::NetModule => ModuleKind::NetModule,
    };
}

/// The single `Module` table row: name + MVID.
fn read_module_row(module: &mut Module, md: &MetadataReader) -> Result<()> {
    if md.row_count(T::Module) == 0 {
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
        let attributes = TypeAttributes::from_bits_truncate(cell_u32(md, T::TypeDef, rid, 0)?);
        // ECMA-335 II §22.37: TypeDef rows are [Flags(0), Name(1),
        // Namespace(2), Extends, FieldList, MethodList].
        let name = cell_str(md, T::TypeDef, rid, 1)?;
        let namespace = cell_str(md, T::TypeDef, rid, 2)?;
        module.types.push(TypeDefinition { namespace, name, attributes, ..Default::default() });
        ctx.type_defs.push(TypeId(rid - 1));
        rows.push(TypedefRow {
            field_start: cell_u32(md, T::TypeDef, rid, 4)?,
            method_start: cell_u32(md, T::TypeDef, rid, 5)?,
        });
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
fn attach_member_ranges(module: &mut Module, rows: &[TypedefRow], md: &MetadataReader) {
    let field_count = md.row_count(T::Field);
    let method_count = md.row_count(T::MethodDef);
    let field_starts: Vec<u32> = rows.iter().map(|t| t.field_start).collect();
    let method_starts: Vec<u32> = rows.iter().map(|t| t.method_start).collect();

    for i in 0..rows.len() {
        let f_end = list_end(&field_starts, i, field_count);
        let mut f = field_starts[i].max(1);
        while f < f_end && f <= field_count {
            module.types[i].fields.push(FieldId(f - 1));
            f += 1;
        }

        let m_end = list_end(&method_starts, i, method_count);
        let mut m = method_starts[i].max(1);
        while m < m_end && m <= method_count {
            module.methods[m as usize - 1].declaring_type = TypeId(i as u32);
            module.types[i].methods.push(MethodId(m - 1));
            m += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Fields / Methods / Params
// ---------------------------------------------------------------------------

fn read_fields(module: &mut Module, ctx: &mut ReadContext, md: &MetadataReader) -> Result<()> {
    let count = md.row_count(T::Field);
    for rid in 1..=count {
        let attributes = FieldAttributes::from_bits_truncate(cell_u16(md, T::Field, rid, 0)?);
        let name = cell_str(md, T::Field, rid, 1)?;
        let sig_blob = cell_blob(md, T::Field, rid, 2)?;
        let signature = {
            let sig_ctx = ctx.sig_context(md);
            parse_field_signature(sig_blob, &sig_ctx)?
        };
        module.fields.push(FieldDefinition { name, attributes, signature, ..Default::default() });
        ctx.field_defs.push(FieldId(rid - 1));
    }
    Ok(())
}

fn read_methods(module: &mut Module, ctx: &mut ReadContext, md: &MetadataReader) -> Result<()> {
    let count = md.row_count(T::MethodDef);
    for rid in 1..=count {
        let impl_attributes =
            MethodImplAttributes::from_bits_truncate(cell_u16(md, T::MethodDef, rid, 1)?);
        let attributes = MethodAttributes::from_bits_truncate(cell_u16(md, T::MethodDef, rid, 2)?);
        let name = cell_str(md, T::MethodDef, rid, 3)?;
        let sig_blob = cell_blob(md, T::MethodDef, rid, 4)?;
        let signature = {
            let sig_ctx = ctx.sig_context(md);
            parse_method_signature(sig_blob, &sig_ctx)?
        };
        // Column 0 (RVA) is intentionally not stored: unit R3 re-reads the
        // MethodDef table itself when resolving bodies.
        module.methods.push(MethodDefinition {
            name,
            attributes,
            impl_attributes,
            signature,
            ..Default::default()
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

    let method_count = md.row_count(T::MethodDef);
    let mut starts = Vec::with_capacity(method_count as usize);
    for rid in 1..=method_count {
        starts.push(cell_u32(md, T::MethodDef, rid, 5)?);
    }
    for (i, start) in starts.iter().enumerate() {
        let end = list_end(&starts, i, count);
        let mut p = (*start).max(1);
        while p < end && p <= count {
            let attributes = ParameterAttributes::from_bits_truncate(cell_u16(md, T::Param, p, 0)?);
            let sequence = cell_u16(md, T::Param, p, 1)?;
            let name = cell_str(md, T::Param, p, 2)?;
            let parameter = Parameter { name, attributes, sequence, ..Default::default() };
            owners[p as usize - 1] = Some((MethodId(i as u32), sequence));
            let method = &mut module.methods[i];
            if sequence == 0 {
                method.return_parameter = parameter;
            } else {
                let slot = (sequence - 1) as usize;
                if slot >= method.parameters.len() {
                    method.parameters.resize(slot + 1, Default::default());
                }
                method.parameters[slot] = parameter;
            }
            p += 1;
        }
    }
    Ok(owners)
}

// ---------------------------------------------------------------------------
// Properties / Events / MethodSemantics
// ---------------------------------------------------------------------------

/// Creates the property and event arenas from their maps, attaches them to
/// owning types, and wires accessor links from `MethodSemantics` rows.
fn read_properties_events_semantics(
    module: &mut Module,
    ctx: &ReadContext,
    md: &MetadataReader,
) -> Result<()> {
    // -- Events ----------------------------------------------------------
    let event_count = md.row_count(T::Event);
    let event_map_count = md.row_count(T::EventMap);
    let mut event_starts = Vec::with_capacity(event_map_count as usize);
    let mut event_parents = Vec::with_capacity(event_map_count as usize);
    for rid in 1..=event_map_count {
        event_parents.push(cell_u32(md, T::EventMap, rid, 0)?);
        event_starts.push(cell_u32(md, T::EventMap, rid, 1)?);
    }
    for (i, start) in event_starts.iter().enumerate() {
        let end = list_end(&event_starts, i, event_count);
        let mut e = (*start).max(1);
        while e < end && e <= event_count {
            let attributes = EventAttributes::from_bits_truncate(cell_u16(md, T::Event, e, 0)?);
            let name = cell_str(md, T::Event, e, 1)?;
            let event_type = md
                .column(T::Event, e, 2)
                .ok()
                .filter(|&cell| cell != 0)
                .map(|cell| ctx.tdor_to_typedesc(md, cell as u32))
                .transpose()?;
            module.events.push(EventDefinition {
                name,
                attributes,
                event_type,
                ..Default::default()
            });
            let parent = event_parents[i];
            if parent >= 1 && parent as usize <= module.types.len() {
                module.types[parent as usize - 1].events.push(EventId(e - 1));
            }
            e += 1;
        }
    }

    // -- Properties -------------------------------------------------------
    let prop_count = md.row_count(T::Property);
    let prop_map_count = md.row_count(T::PropertyMap);
    let mut prop_starts = Vec::with_capacity(prop_map_count as usize);
    let mut prop_parents = Vec::with_capacity(prop_map_count as usize);
    for rid in 1..=prop_map_count {
        prop_parents.push(cell_u32(md, T::PropertyMap, rid, 0)?);
        prop_starts.push(cell_u32(md, T::PropertyMap, rid, 1)?);
    }
    for (i, start) in prop_starts.iter().enumerate() {
        let end = list_end(&prop_starts, i, prop_count);
        let mut p = (*start).max(1);
        while p < end && p <= prop_count {
            let attributes =
                PropertyAttributes::from_bits_truncate(cell_u16(md, T::Property, p, 0)?);
            let name = cell_str(md, T::Property, p, 1)?;
            let sig_blob = cell_blob(md, T::Property, p, 2)?;
            let signature = {
                let sig_ctx = ctx.sig_context(md);
                parse_property_signature(sig_blob, &sig_ctx)?
            };
            module.properties.push(PropertyDefinition {
                name,
                attributes,
                signature,
                ..Default::default()
            });
            let parent = prop_parents[i];
            if parent >= 1 && parent as usize <= module.types.len() {
                module.types[parent as usize - 1]
                    .properties
                    .push(crate::model::types::PropertyId(p - 1));
            }
            p += 1;
        }
    }

    // -- MethodSemantics ---------------------------------------------------
    for rid in 1..=md.row_count(T::MethodSemantics) {
        let semantics = MethodSemanticsAttributes::from_bits_truncate(cell_u16(
            md,
            T::MethodSemantics,
            rid,
            0,
        )?);
        let method = cell_u32(md, T::MethodSemantics, rid, 1)? as usize;
        let assoc_cell = md.column(T::MethodSemantics, rid, 2)?;
        let (table, target) = decode_group(&coded::HAS_SEMANTICS, assoc_cell)?;
        if method == 0 || method > module.methods.len() {
            return Err(bad(format!("MethodSemantics row {rid} references method outside table")));
        }
        let method = MethodId(method as u32 - 1);
        match table {
            T::Event => {
                if target < 1 || target as usize > module.events.len() {
                    return Err(bad(format!(
                        "MethodSemantics row {rid} references event outside table"
                    )));
                }
                let event = &mut module.events[target as usize - 1];
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
                if target < 1 || target as usize > module.properties.len() {
                    return Err(bad(format!(
                        "MethodSemantics row {rid} references property outside table"
                    )));
                }
                let property = &mut module.properties[target as usize - 1];
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
) -> Result<()> {
    let count = md.row_count(T::GenericParam);
    for rid in 1..=count {
        let number = cell_u16(md, T::GenericParam, rid, 0)?;
        let attributes =
            GenericParameterAttributes::from_bits_truncate(cell_u16(md, T::GenericParam, rid, 1)?);
        let owner_cell = md.column(T::GenericParam, rid, 2)?;
        let (owner_table, owner_rid) = decode_group(&coded::TYPE_OR_METHOD_DEF, owner_cell)?;
        let name = cell_str(md, T::GenericParam, rid, 3)?;

        let owner = match owner_table {
            T::TypeDef => {
                if owner_rid as usize > module.types.len() {
                    return Err(bad(format!("GenericParam row {rid}: owner type out of range")));
                }
                module.types[owner_rid as usize - 1]
                    .generic_parameters
                    .push(GenericParamId(rid - 1));
                GenericOwner::Type(TypeId(owner_rid - 1))
            }
            T::MethodDef => {
                if owner_rid as usize > module.methods.len() {
                    return Err(bad(format!("GenericParam row {rid}: owner method out of range")));
                }
                module.methods[owner_rid as usize - 1]
                    .generic_parameters
                    .push(GenericParamId(rid - 1));
                GenericOwner::Method(MethodId(owner_rid - 1))
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

    // Constraints grouped by owner parameter.
    let mut constraints: Vec<Vec<u32>> = vec![Vec::new(); count as usize];
    for rid in 1..=md.row_count(T::GenericParamConstraint) {
        let owner = cell_u32(md, T::GenericParamConstraint, rid, 0)? as usize;
        let constraint_cell = md.column(T::GenericParamConstraint, rid, 1)?;
        if owner < 1 || owner > constraints.len() {
            return Err(bad(format!("GenericParamConstraint row {rid}: owner out of range")));
        }
        constraints[owner - 1].push(constraint_cell as u32);
    }
    for (i, cells) in constraints.iter().enumerate() {
        for cell_value in cells {
            let desc = ctx.tdor_to_typedesc(md, *cell_value)?;
            module.generic_parameters[i].constraints.push(desc);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Base types / Interfaces / Layouts / RVAs
// ---------------------------------------------------------------------------

fn read_base_types_and_interfaces(
    module: &mut Module,
    ctx: &ReadContext,
    md: &MetadataReader,
) -> Result<()> {
    let count = md.row_count(T::TypeDef);
    for rid in 1..=count {
        let extends = md.column(T::TypeDef, rid, 3)?;
        if extends != 0 {
            let base = ctx.tdor_to_typedesc(md, extends as u32)?;
            module.types[rid as usize - 1].base_type = Some(base);
        }
    }

    // InterfaceImpl rows are sorted by Class; group them in row order.
    for rid in 1..=md.row_count(T::InterfaceImpl) {
        let class = cell_u32(md, T::InterfaceImpl, rid, 0)? as usize;
        let iface_cell = cell_u32(md, T::InterfaceImpl, rid, 1)?;
        if class < 1 || class > module.types.len() {
            return Err(bad(format!("InterfaceImpl row {rid}: class out of range")));
        }
        let iface = ctx.tdor_to_typedesc(md, iface_cell)?;
        module.types[class - 1].interfaces.push(iface);
    }
    Ok(())
}

fn read_class_layouts(module: &mut Module, md: &MetadataReader) -> Result<()> {
    for rid in 1..=md.row_count(T::ClassLayout) {
        let packing_size = cell_u16(md, T::ClassLayout, rid, 0)? as i16 as i32;
        let class_size = cell_u32(md, T::ClassLayout, rid, 1)? as i32;
        let parent = cell_u32(md, T::ClassLayout, rid, 2)? as usize;
        if parent < 1 || parent > module.types.len() {
            return Err(bad(format!("ClassLayout row {rid}: parent out of range")));
        }
        module.types[parent - 1].class_layout = Some(ClassLayout { packing_size, class_size });
    }
    Ok(())
}

fn read_field_layouts(module: &mut Module, md: &MetadataReader) -> Result<()> {
    for rid in 1..=md.row_count(T::FieldLayout) {
        let offset = cell_u32(md, T::FieldLayout, rid, 0)? as i32;
        let field = cell_u32(md, T::FieldLayout, rid, 1)? as usize;
        if field < 1 || field > module.fields.len() {
            return Err(bad(format!("FieldLayout row {rid}: field out of range")));
        }
        module.fields[field - 1].offset = Some(offset);
    }
    Ok(())
}

/// Port of `GetFieldTypeSize`: initial-data length of a field with an RVA.
fn field_type_size(module: &Module, ty: &TypeDesc, pointer_size: usize) -> i32 {
    match ty {
        TypeDesc::Internal(name) => match name.as_str() {
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
    image: &cecli_pe::Image,
    md: &MetadataReader,
) -> Result<()> {
    let pointer_size = if image.architecture.is_pe64() { 8 } else { 4 };
    for rid in 1..=md.row_count(T::FieldRva) {
        let rva = cell_u32(md, T::FieldRva, rid, 0)? as u64;
        let field = cell_u32(md, T::FieldRva, rid, 1)? as usize;
        if field < 1 || field > module.fields.len() {
            return Err(bad(format!("FieldRVA row {rid}: field out of range")));
        }
        let size = field_type_size(module, &module.fields[field - 1].signature.0, pointer_size);
        let field_def = &mut module.fields[field - 1];
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
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect();
            ConstantValue::String(String::from_utf16_lossy(&units))
        } else {
            parse_constant_blob(et, blob)?
        });

        let (table, target) = decode_group(&coded::HAS_CONSTANT, parent_cell)?;
        match table {
            T::Field => {
                if target as usize > module.fields.len() {
                    return Err(bad(format!("Constant row {rid}: field out of range")));
                }
                module.fields[target as usize - 1].constant = value;
            }
            T::Param => {
                if target as usize > param_owners.len() {
                    return Err(bad(format!("Constant row {rid}: param out of range")));
                }
                if let Some((method, sequence)) = param_owners[target as usize - 1] {
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
                if target as usize > module.properties.len() {
                    return Err(bad(format!("Constant row {rid}: property out of range")));
                }
                module.properties[target as usize - 1].constant = value;
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
                if target as usize > module.fields.len() {
                    return Err(bad(format!("FieldMarshal row {rid}: field out of range")));
                }
                module.fields[target as usize - 1].marshal_info = Some(info);
            }
            T::Param => {
                if target as usize > param_owners.len() {
                    return Err(bad(format!("FieldMarshal row {rid}: param out of range")));
                }
                if let Some((method, sequence)) = param_owners[target as usize - 1] {
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
        if scope < 1 || scope as usize > md.row_count(T::ModuleRef) as usize {
            return Err(bad(format!("ImplMap row {rid}: ModuleRef scope out of range")));
        }
        let module_name = cell_str(md, T::ModuleRef, scope as u32, 0)?;

        let (table, target) = decode_group(&coded::MEMBER_FORWARDED, forwarded_cell)?;
        if table != T::MethodDef {
            // Field forwarding through P/Invoke has no slot in the frozen
            // field model.
            continue;
        }
        if target as usize > module.methods.len() {
            return Err(bad(format!("ImplMap row {rid}: method out of range")));
        }
        module.methods[target as usize - 1].pinvoke =
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
                if target as usize > module.types.len() {
                    return Err(bad(format!("DeclSecurity row {rid}: type out of range")));
                }
                module.types[target as usize - 1].security_declarations.push(declaration);
            }
            T::MethodDef => {
                if target as usize > module.methods.len() {
                    return Err(bad(format!("DeclSecurity row {rid}: method out of range")));
                }
                module.methods[target as usize - 1].security_declarations.push(declaration);
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
            if rid as usize > ctx.method_defs.len() {
                return Err(bad("custom attribute constructor method out of range".into()));
            }
            Ok(MethodRef::Def(ctx.method_defs[rid as usize - 1]))
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
/// collected on [`AssemblyRowData::custom_attributes`]. Parents without a
/// slot in the frozen model (TypeRef, InterfaceImpl, MemberRef, Module,
/// DeclSecurity, StandAloneSig, ModuleRef, TypeSpec, File, ExportedType,
/// ManifestResource, GenericParamConstraint, MethodSpec) are skipped.
fn read_custom_attributes(
    module: &mut Module,
    ctx: &mut ReadContext,
    md: &MetadataReader,
    param_owners: &[Option<(MethodId, u16)>],
) -> Result<()> {
    for rid in 1..=md.row_count(T::CustomAttribute) {
        let parent_cell = md.column(T::CustomAttribute, rid, 0)?;
        let ctor_cell = md.column(T::CustomAttribute, rid, 1)?;
        let blob = cell_blob(md, T::CustomAttribute, rid, 2)?.to_vec();
        let constructor = attribute_ctor(ctx, md, ctor_cell)?;
        let attribute = CustomAttribute { constructor, blob };

        let (table, target) = decode_group(&coded::HAS_CUSTOM_ATTRIBUTE, parent_cell)?;
        // Checked parent index; keeps every arm a one-liner.
        let idx = |len: usize| -> Result<usize> {
            if target < 1 || target as usize > len {
                Err(bad(format!("CustomAttribute row {rid}: parent out of range")))
            } else {
                Ok(target as usize - 1)
            }
        };
        match table {
            T::MethodDef => {
                let i = idx(module.methods.len())?;
                module.methods[i].custom_attributes.push(attribute);
            }
            T::Field => {
                let i = idx(module.fields.len())?;
                module.fields[i].custom_attributes.push(attribute);
            }
            T::TypeDef => {
                let i = idx(module.types.len())?;
                module.types[i].custom_attributes.push(attribute);
            }
            T::Param => {
                if target as usize > param_owners.len() {
                    return Err(bad(format!("CustomAttribute row {rid}: param out of range")));
                }
                let Some((method, sequence)) = param_owners[target as usize - 1] else {
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
                slot.custom_attributes.push(attribute);
            }
            T::Property => {
                let i = idx(module.properties.len())?;
                module.properties[i].custom_attributes.push(attribute);
            }
            T::Event => {
                let i = idx(module.events.len())?;
                module.events[i].custom_attributes.push(attribute);
            }
            T::GenericParam => {
                let i = idx(module.generic_parameters.len())?;
                module.generic_parameters[i].custom_attributes.push(attribute);
            }
            T::AssemblyRef => {
                let i = idx(ctx.asm_refs.len())?;
                ctx.asm_refs[i].custom_attributes.push(attribute);
            }
            T::Assembly => {
                // The Assembly table holds at most one row; anything else is
                // a malformed parent cell.
                if target != 1 {
                    return Err(bad(format!("CustomAttribute row {rid}: invalid Assembly parent")));
                }
                match ctx.assembly_row.as_mut() {
                    Some(row) => row.custom_attributes.push(attribute),
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

// ---------------------------------------------------------------------------
// Assembly row
// ---------------------------------------------------------------------------

/// Reads the single `Assembly` row into [`AssemblyRowData`].
fn read_assembly_row(image: &cecli_pe::Image, md: &MetadataReader) -> Result<AssemblyRowData> {
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
    image: &cecli_pe::Image,
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
                if impl_rid as usize > module.file_rows.len() {
                    return Err(bad(format!("ExportedType row {rid}: file out of range")));
                }
                ExportedImpl::File(impl_rid as usize - 1)
            }
            T::AssemblyRef => {
                if impl_rid as usize > ctx.asm_refs.len() {
                    return Err(bad(format!("ExportedType row {rid}: assembly ref out of range")));
                }
                ExportedImpl::AssemblyRef(impl_rid as usize - 1)
            }
            T::ExportedType => ExportedImpl::ExportedType(impl_rid),
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
                    if impl_rid as usize > ctx.asm_refs.len() {
                        return Err(bad(format!(
                            "ManifestResource row {rid}: assembly ref out of range"
                        )));
                    }
                    Resource::AssemblyLinked {
                        name,
                        attributes: flags,
                        assembly: ctx.asm_refs[impl_rid as usize - 1].clone(),
                    }
                }
                T::File => {
                    if impl_rid as usize > module.file_rows.len() {
                        return Err(bad(format!("ManifestResource row {rid}: file out of range")));
                    }
                    Resource::Linked {
                        name,
                        attributes: flags,
                        file: module.file_rows[impl_rid as usize - 1].name.clone(),
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
fn embedded_resource_data(image: &cecli_pe::Image, offset: u32) -> Result<Vec<u8>> {
    let header = image.cli_header();
    if header.resources_size == 0 {
        return Err(bad("embedded resource but the image has no resources directory".into()));
    }
    let directory = image.rva(header.resources_rva)?;
    let end = (header.resources_size as usize).min(directory.len());
    let directory = &directory[..end];

    let start = offset as usize;
    if start + 4 > directory.len() {
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
    let data_end = start + 4 + length as usize;
    if data_end > directory.len() {
        return Err(bad(format!(
            "embedded resource of {length} bytes at offset {start} overruns the resources directory"
        )));
    }
    Ok(directory[start + 4..data_end].to_vec())
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
        assert_eq!(metadata_kind("v4.0.30319"), cecli_core::flags::MetadataKind::Ecma335);
        assert_eq!(
            metadata_kind("WindowsRuntime 1.3"),
            cecli_core::flags::MetadataKind::WindowsMetadata
        );
        assert_eq!(
            metadata_kind("WindowsRuntime CLR 4.0"),
            cecli_core::flags::MetadataKind::ManagedWindowsMetadata
        );
    }

    /// Integration test over the shared `hello.exe` fixture: full metadata
    /// read with bodies disabled. Skips gracefully wherever the fixtures
    /// directory is absent so the suite stays green anywhere.
    #[test]
    fn hello_fixture_reads_fully() {
        let path = cecli_core::fixtures_dir().join("hello.exe");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(&path).expect("reading fixtures/hello.exe");
        let image = cecli_pe::Image::parse(&bytes).expect("parsing PE image");

        let opts = ReadOptions { load_bodies: false };
        let (module, ctx) = read_module(&image, &opts).expect("read_module");

        // Module shell. Ground truth (raw table dump of fixtures/hello.exe):
        // the Module row stores "hello.exe" while the Assembly row stores
        // "hello" - exactly what Mono.Cecil reports, so we assert both.
        assert_eq!(module.name, "hello.exe");
        assert_eq!(ctx.assembly_row.as_ref().expect("Assembly row present").name, "hello");
        assert!(!module.guid.iter().all(|b| *b == 0), "MVID must be present");
        assert!(matches!(module.metadata_kind, cecli_core::flags::MetadataKind::Ecma335));
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
            matches!(main.signature.return_type, TypeDesc::Internal(ref name) if name == "void"),
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
        let path = cecli_core::fixtures_dir().join("hello.exe");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(&path).expect("reading fixtures/hello.exe");
        let image = cecli_pe::Image::parse(&bytes).expect("parsing PE image");
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
        let path = cecli_core::fixtures_dir().join("iterator.exe");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(&path).expect("reading fixtures/iterator.exe");
        let image = cecli_pe::Image::parse(&bytes).expect("parsing PE image");
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
            let path = cecli_core::fixtures_dir().join(file);
            if !path.exists() {
                continue;
            }
            let bytes = std::fs::read(&path).expect("reading fixture");
            let image = cecli_pe::Image::parse(&bytes).expect("parsing PE image");
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
}
