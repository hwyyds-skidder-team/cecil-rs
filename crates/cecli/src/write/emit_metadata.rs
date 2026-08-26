//! Deterministic metadata-table emission: the Rust port of the table-building
//! half of `Mono.Cecil/AssemblyWriter.cs` (`MetadataBuilder.BuildModule`,
//! `BuildTypes`, `AddType`, and friends).
//!
//! The emitter walks the [`Module`] arenas in index order and appends raw rows
//! to a [`MetadataBuilder`], which serializes them into a BSJB metadata root.
//! Row plans are fully deterministic: every table's row order is derived from
//! arena/index order, never from hashing or run-time state.
//!
//! Two entry points:
//!
//! * [`emit_metadata`] - self-contained; creates its own `MetadataBuilder` +
//!   [`TokenMap`], emits placeholder zeros for every location that depends on
//!   the final PE layout (method RVAs, `FieldRva` RVAs, embedded-resource
//!   offsets) and reports those locations back as patch lists.
//! * [`emit_metadata_with`] - integration path; consumes a caller-owned
//!   [`TokenMap`] (so IL bodies encoded earlier through the same map share one
//!   heap/token space) and takes an [`EmitLayout`] with the real final values,
//!   producing a finished image without post-patching.

use std::mem;

use cecli_core::flags::{
    FileRowAttributes, MethodSemanticsAttributes, ModuleKind,
};
use cecli_core::token::{coded, CodedIndexGroup, TableIndex, Token};
use cecli_core::{ElementType, Error, Result};
use cecli_metadata::tables::{encode_coded, TableSet, TABLE_COUNT};
use cecli_metadata::{parse_root, MetadataBuilder};

use crate::assembly::AssemblyNameDefinition;
use crate::model::marshal::write_marshal_spec;
use crate::model::signature::{
    write_constant_blob, write_field_signature, write_method_signature,
    write_property_signature,
};
use crate::model::types::*;
use crate::module_def::{ExportedImpl, Module, Resource};
use super::token_map::TokenMap;

/// Runtime version emitted when [`Module::runtime_version`] is empty.
pub const DEFAULT_RUNTIME_VERSION: &str = "v4.0.30319";

/// Alignment applied between consecutive `FieldRva` initial-value chunks in the
/// data blob. Mono.Cecil aligns to the declaring type's packing size; we always
/// use 8 so the facade can place one contiguous blob without per-type knowledge.
const FIELD_DATA_ALIGN: usize = 8;

/// Rows of the tables Mono.Cecil sorts before serialization
/// (`MetadataBuilder.SortTables`): buffered during emission, then added to
/// the builder stably-sorted by their first-column parent/key cell ascending
/// (coded-cell numeric compare) right before the metadata root finalizes.
/// These tables are leaves - no emitted cell references their rids - so
/// deferring their `add_row` calls is rid-safe. (`CustomDebugInformation`
/// belongs to the same sorted set in Cecil, but its rows are only ever
/// produced by the portable-PDB writer, never here.)
#[derive(Default)]
struct SortedTables {
    constant: Vec<Vec<u64>>,
    custom_attribute: Vec<Vec<u64>>,
    field_marshal: Vec<Vec<u64>>,
    decl_security: Vec<Vec<u64>>,
    class_layout: Vec<Vec<u64>>,
    field_layout: Vec<Vec<u64>>,
    method_semantics: Vec<Vec<u64>>,
    impl_map: Vec<Vec<u64>>,
    /// FieldRva rows carry their FieldId so RVA patch bookkeeping survives
    /// the sort.
    field_rva: Vec<(FieldId, Vec<u64>)>,
    nested_class: Vec<Vec<u64>>,
}

impl SortedTables {
    /// Stably sorts every buffer by its first cell and drains it into
    /// `builder`; FieldRva placeholder rows extend `rva_patches` with their
    /// FINAL (sorted) row indexes.
    fn flush(
        self,
        builder: &mut MetadataBuilder,
        rva_patches: &mut Vec<(FieldId, usize)>,
    ) -> Result<()> {
        let Self {
            constant,
            custom_attribute,
            field_marshal,
            decl_security,
            class_layout,
            field_layout,
            method_semantics,
            impl_map,
            mut field_rva,
            nested_class,
        } = self;
        for (table, mut rows) in [
            (TableIndex::Constant, constant),
            (TableIndex::CustomAttribute, custom_attribute),
            (TableIndex::FieldMarshal, field_marshal),
            (TableIndex::DeclSecurity, decl_security),
            (TableIndex::ClassLayout, class_layout),
            (TableIndex::FieldLayout, field_layout),
            (TableIndex::MethodSemantics, method_semantics),
            (TableIndex::ImplMap, impl_map),
            (TableIndex::NestedClass, nested_class),
        ] {
            // `sort_by_key` is stable: equal keys keep first-encounter order,
            // matching Cecil's sort stability guarantees.
            rows.sort_by_key(|row| row[0]);
            for row in rows {
                builder.add_row(table, &row)?;
            }
        }
        field_rva.sort_by_key(|(_, row)| row[0]);
        for (fid, row) in &field_rva {
            let rid = builder.add_row(TableIndex::FieldRva, row)?;
            if row[0] == 0 {
                rva_patches.push((*fid, rid as usize - 1));
            }
        }
        Ok(())
    }
}

/// Result of metadata emission.
#[derive(Debug)]
pub struct EmittedMetadata {
    /// Serialized BSJB metadata root (`#~`, `#Strings`, `#US`, `#GUID`, `#Blob`).
    pub root: Vec<u8>,
    /// Entry point token (`MethodDef` rid built from the passed [`MethodId`]),
    /// or [`Token::NIL`] when `entry` was `None`.
    pub entry_point_token: Token,
    /// Concatenated `FieldRva` initial-value chunks (each padded to
    /// [`FIELD_DATA_ALIGN`]), in `FieldRva` row order. Place this blob at
    /// `EmitLayout::data_segment_rva` (or at any RVA you write into the patch
    /// cells below).
    pub data: Vec<u8>,
    /// `(field handle, FieldRva row index)` for rows whose RVA cell holds the
    /// placeholder `0`. Empty when an [`EmitLayout`] supplied real values.
    pub rva_patches: Vec<(FieldId, usize)>,
    /// Byte offset within [`EmittedMetadata::root`] of each placeholder RVA
    /// `u32`, parallel to [`EmittedMetadata::rva_patches`].
    pub rva_patch_offsets: Vec<usize>,
    /// `ManifestResource` row indices whose Offset cell holds the placeholder
    /// `0` (embedded resources without a supplied layout offset).
    pub resource_patches: Vec<usize>,
    /// Byte offset within [`EmittedMetadata::root`] of each placeholder Offset
    /// `u32`, parallel to [`EmittedMetadata::resource_patches`].
    pub resource_patch_offsets: Vec<usize>,
    /// `(method handle, StandAloneSig token)` for every method body carrying
    /// locals, in method arena order. Feed these tokens to the IL encoder so
    /// fat headers reference the freshly allocated signatures.
    pub local_var_sig_tokens: Vec<(MethodId, Token)>,
}

/// Final PE-layout values needed to emit finished metadata in one pass.
#[derive(Debug, Clone, Default)]
pub struct EmitLayout {
    /// Real text-section RVA per method body (`MethodDef.Rva` column).
    /// Methods absent from the list keep `0`.
    pub method_rvas: Vec<(MethodId, u64)>,
    /// `ManifestResource.Offset` value per `module.resources[i]` (from the
    /// managed-resource blob builder). Missing entries keep `0`.
    pub resource_offsets: Vec<u32>,
    /// RVA where the [`EmittedMetadata::data`] blob will be placed.
    /// `0` means "unknown yet" and produces placeholder RVAs.
    pub data_segment_rva: u64,
}

/// Emits complete metadata using a throwaway builder and token map.
///
/// Layout-dependent cells are left as placeholder zeros; see
/// [`EmittedMetadata`] for the patch lists describing exactly where they live.
pub fn emit_metadata(
    m: &Module,
    asm: Option<&AssemblyNameDefinition>,
    entry: Option<MethodId>,
) -> Result<EmittedMetadata> {
    let mut builder = MetadataBuilder::new(&runtime_version_string(m));
    let mut tmap = TokenMap::new(&mut builder);
    let layout = EmitLayout::default();
    emit_metadata_with(m, asm, entry, &layout, tmap)
}

/// Emits complete metadata into the caller's token map / underlying builder.
///
/// Use this when method bodies were already encoded through `tmap`: every
/// `TypeRef`/`MemberRef`/`TypeSpec`/`MethodSpec`/`StandAloneSig` row buffered
/// there plus everything emitted here shares one rid space, and the returned
/// root is final (given a populated [`EmitLayout`]).
pub fn emit_metadata_with(
    m: &Module,
    asm: Option<&AssemblyNameDefinition>,
    entry: Option<MethodId>,
    layout: &EmitLayout,
    mut tmap: TokenMap<'_>,
) -> Result<EmittedMetadata> {
    let mut next_field_rid: u32 = 1;
    let mut next_method_rid: u32 = 1;
    let mut next_param_rid: u32 = 1;
    // Running first-rid counters for PropertyMap/EventMap start columns and
    // Property/Event row allocation.
    let mut property_rid: u32 = 1;
    let mut event_rid: u32 = 1;

    let mut rva_patches: Vec<(FieldId, usize)> = Vec::new();
    let mut field_data: Vec<u8> = Vec::new();
    let mut local_var_sig_tokens: Vec<(MethodId, Token)> = Vec::new();
    // Whether the Assembly row exists (drives Assembly-parented side tables).
    let mut assembly_emitted = false;
    let mut sorted = SortedTables::default();

    // -- Module (ECMA-335 II §22.30): generation, name, MVID, EncId, EncBaseId.
    let name_idx = tmap.builder().insert_string(&m.name);
    let mvid_idx = tmap.builder().insert_guid(&m.guid);
    tmap
        .builder()
        .add_row(TableIndex::Module, &[0, name_idx as u64, mvid_idx as u64, 0, 0])?;

    // -- Assembly row (§22.5): skipped for netmodules even when a name is
    // supplied, matching `MetadataBuilder.BuildModule` in Mono.Cecil.
    if let Some(name) = asm {
        if m.kind != ModuleKind::NetModule {
            let key_idx = tmap.builder().insert_blob(&name.public_key);
            let asm_name = tmap.builder().insert_string(&name.name);
            let culture =
                tmap.builder()
                    .insert_string(name.culture.as_deref().unwrap_or(""));
            let v = &name.version;
            tmap.builder().add_row(
                TableIndex::Assembly,
                &[
                    name.hash_algorithm as u32 as u64,
                    v.major as u64,
                    v.minor as u64,
                    v.build as u64,
                    v.revision as u64,
                    name.attributes.bits() as u64,
                    key_idx as u64,
                    asm_name as u64,
                    culture as u64,
                ],
            )?;
            assembly_emitted = true;
        }
    }

    // -- AssemblyRef rows (§22.6), in module order.
    for r in &m.assembly_refs {
        let key_idx = tmap.builder().insert_blob(&r.public_key_or_token);
        let ref_name = tmap.builder().insert_string(&r.name);
        let culture = tmap.builder().insert_string(r.culture.as_deref().unwrap_or(""));
        let hash_idx = tmap.builder().insert_blob(&r.hash);
        tmap.builder().add_row(
            TableIndex::AssemblyRef,
            &[
                r.version.major as u64,
                r.version.minor as u64,
                r.version.build as u64,
                r.version.revision as u64,
                r.attributes.bits() as u64,
                key_idx as u64,
                ref_name as u64,
                culture as u64,
                hash_idx as u64,
            ],
        )?;
    }
    // -- ModuleRef rows (§22.28), in module order (P/Invoke target modules).
    for n in &m.module_refs {
        let idx = tmap.builder().insert_string(n);
        tmap.builder().add_row(TableIndex::ModuleRef, &[idx as u64])?;
    }

    // -- File rows (§22.17) preserved from read, then File rows synthesized for
    // linked resources as they are encountered below (indices into `file_rows`
    // stay valid because preserved rows come first).
    for f in &m.file_rows {
        let fname = tmap.builder().insert_string(&f.name);
        let hash_idx = tmap.builder().insert_blob(&f.hash);
        tmap.builder().add_row(
            TableIndex::File,
            &[f.attributes.bits() as u64, fname as u64, hash_idx as u64],
        )?;
    }

    // -- ManifestResource rows (§22.24).
    let mut resource_patches: Vec<usize> = Vec::new();
    for (i, res) in m.resources.iter().enumerate() {
        let mut impl_cell = 0u64;
        match res {
            Resource::Embedded { .. } => {} // offset handled below
            Resource::Linked { file, .. } => {
                let fname = tmap.builder().insert_string(file);
                let rid = tmap.builder().add_row(
                    TableIndex::File,
                    &[
                        FileRowAttributes::CONTAINS_NO_METADATA.bits() as u64,
                        fname as u64,
                        0, // hash unknown in the object model
                    ],
                )?;
                impl_cell = encode_coded(&coded::IMPLEMENTATION, TableIndex::File, rid)?;
            }
            Resource::AssemblyLinked { assembly, .. } => {
                let pos = m
                    .assembly_refs
                    .iter()
                    .position(|r| r.name == assembly.name && r.version == assembly.version)
                    .ok_or_else(|| {
                        Error::argument(format!(
                            "assembly-linked resource references unlisted assembly {}",
                            assembly.name
                        ))
                    })?;
                impl_cell = encode_coded(
                    &coded::IMPLEMENTATION,
                    TableIndex::AssemblyRef,
                    pos as u32 + 1,
                )?;
            }
        }
        // Embedded rows take the real offset from the layout, else a
        // placeholder reported back for the facade PE pass.
        let offset = layout.resource_offsets.get(i).copied().unwrap_or(0) as u64;
        let rname = tmap.builder().insert_string(res.name());
        let rid = tmap.builder().add_row(
            TableIndex::ManifestResource,
            &[
                offset,
                res.attributes().bits() as u64,
                rname as u64,
                impl_cell,
            ],
        )?;
        if matches!(res, Resource::Embedded { .. })
            && layout.resource_offsets.get(i).is_none()
        {
            resource_patches.push(rid as usize - 1);
        }
    }

    // -- ExportedType rows (§22.15).
    for et in &m.exported_types {
        let impl_cell = match &et.implementation {
            ExportedImpl::File(i) => {
                encode_coded(&coded::IMPLEMENTATION, TableIndex::File, *i as u32 + 1)?
            }
            ExportedImpl::AssemblyRef(i) => encode_coded(
                &coded::IMPLEMENTATION,
                TableIndex::AssemblyRef,
                *i as u32 + 1,
            )?,
            ExportedImpl::ExportedType(rid) => {
                encode_coded(&coded::IMPLEMENTATION, TableIndex::ExportedType, *rid)?
            }
        };
        let ename = tmap.builder().insert_string(&et.name);
        let ens = tmap.builder().insert_string(&et.namespace);
        tmap.builder().add_row(
            TableIndex::ExportedType,
            &[
                et.attributes.bits() as u64,
                et.type_def_id as u64,
                ename as u64,
                ens as u64,
                impl_cell,
            ],
        )?;
    }

    // -- Types, in arena index order (TypeDef rid == arena index + 1, which is
    // what signature encoding through `TokenMap` assumes for `Def` cells).
    for (ti, td) in m.types.iter().enumerate() {
        let type_rid = ti as u32 + 1;

        let base_cell = match &td.base_type {
            Some(base) => tmap.tdor_cell(base, m)? as u64,
            None => 0,
        };
        // FieldList/MethodList point at this type's first member rid; types
        // without members point at the next rid that will be handed out so the
        // implicit range stays empty.
        let field_list = match td.fields.first() {
            Some(f) => f.0 + 1,
            None => next_field_rid,
        };
        let method_list = match td.methods.first() {
            Some(mi) => mi.0 + 1,
            None => next_method_rid,
        };
        let tname = tmap.builder().insert_string(&td.name);
        let tns = tmap.builder().insert_string(&td.namespace);
        tmap.builder().add_row(
            TableIndex::TypeDef,
            &[
                td.attributes.bits() as u64,
                tname as u64,
                tns as u64,
                base_cell,
                field_list as u64,
                method_list as u64,
            ],
        )?;
        if let Some(last) = td.fields.last() {
            next_field_rid = next_field_rid.max(last.0 + 2);
        }
        if let Some(last) = td.methods.last() {
            next_method_rid = next_method_rid.max(last.0 + 2);
        }

        // InterfaceImpl rows (§22.20).
        for iface in &td.interfaces {
            let cell = tmap.tdor_cell(iface, m)?;
            tmap
                .builder()
                .add_row(TableIndex::InterfaceImpl, &[type_rid as u64, cell as u64])?;
        }

        // ClassLayout row (§22.9).
        if let Some(cl) = td.class_layout {
            sorted.class_layout.push(vec![
                cl.packing_size as i16 as u16 as u64,
                cl.class_size as i32 as u32 as u64,
                type_rid as u64,
            ]);
        }

        // Fields (§22.16) plus their satellite rows, in Cecil's per-field order:
        // FieldRva, FieldLayout, custom attributes, constant, marshal info.
        for fid in &td.fields {
            let fd = &m.fields[fid.index()];
            let frid = fid.0 + 1;
            let sig_blob = {
                let ctx = tmap.encoder(m);
                write_field_signature(&fd.signature, &ctx)?
            };
            let fsig = tmap.builder().insert_blob(&sig_blob);
            let fname = tmap.builder().insert_string(&fd.name);
            tmap.builder().add_row(
                TableIndex::Field,
                &[fd.attributes.bits() as u64, fname as u64, fsig as u64],
            )?;

            if !fd.initial_value.is_empty() {
                while field_data.len() % FIELD_DATA_ALIGN != 0 {
                    field_data.push(0);
                }
                let chunk_offset = field_data.len() as u64;
                field_data.extend_from_slice(&fd.initial_value);
                let rva = if layout.data_segment_rva != 0 {
                    layout.data_segment_rva + chunk_offset
                } else {
                    0
                };
                sorted.field_rva.push((*fid, vec![rva, frid as u64]));
            }

            if let Some(off) = fd.offset {
                sorted.field_layout.push(vec![off as i32 as u32 as u64, frid as u64]);
            }

            for ca in &fd.custom_attributes {
                add_custom_attribute(&mut tmap, m, TableIndex::Field, frid, ca, &mut sorted)?;
            }
            if let Some(c) = &fd.constant {
                add_constant(&mut tmap, &coded::HAS_CONSTANT, TableIndex::Field, frid, c, &mut sorted)?;
            }
            if let Some(mi) = &fd.marshal_info {
                add_marshal_info(&mut tmap, m, &coded::HAS_FIELD_MARSHAL, TableIndex::Field, frid, mi, &mut sorted)?;
            }
        }

        // Methods (§22.26) plus parameters, P/Invoke, attributes, security and
        // overrides, in Cecil's per-method order.
        for mid in &td.methods {
            let md = &m.methods[mid.index()];
            let mrid = mid.0 + 1;
            let sig_blob = {
                let ctx = tmap.encoder(m);
                write_method_signature(&md.signature, &ctx)?
            };
            let msig = tmap.builder().insert_blob(&sig_blob);
            let mname = tmap.builder().insert_string(&md.name);
            // Bodies are emitted by the PE pass; without a layout entry the RVA
            // column stays 0 (the facade fixes it up afterwards).
            let rva = layout
                .method_rvas
                .iter()
                .find(|(id, _)| id == mid)
                .map(|(_, rva)| *rva)
                .unwrap_or(0);
            tmap.builder().add_row(
                TableIndex::MethodDef,
                &[
                    rva,
                    md.impl_attributes.bits() as u64,
                    md.attributes.bits() as u64,
                    mname as u64,
                    msig as u64,
                    next_param_rid as u64,
                ],
            )?;

            // Param rows (§22.33): the return parameter (sequence 0) is emitted
            // first when it carries information, like Cecil's `AddParameters`.
            if requires_parameter_row(&md.return_parameter) {
                let prid = next_param_rid;
                next_param_rid += 1;
                add_parameter(&mut tmap, m, prid, 0, &md.return_parameter, &mut sorted)?;
            }
            for (i, p) in md.parameters.iter().enumerate() {
                if requires_parameter_row(p) {
                    let prid = next_param_rid;
                    next_param_rid += 1;
                    add_parameter(&mut tmap, m, prid, i as u16 + 1, p, &mut sorted)?;
                }
            }

            if let Some(pk) = &md.pinvoke {
                let pos = m.module_refs.iter().position(|n| n == &pk.module).ok_or_else(
                    || {
                        Error::argument(format!(
                            "pinvoke targets module `{}` which is not listed in module_refs",
                            pk.module
                        ))
                    },
                )?;
                let entry_idx = tmap.builder().insert_string(&pk.entry_point);
                let forwarded =
                    encode_coded(&coded::MEMBER_FORWARDED, TableIndex::MethodDef, mrid)?;
                sorted.impl_map.push(vec![
                    pk.attributes.bits() as u64,
                    forwarded,
                    entry_idx as u64,
                    pos as u64 + 1,
                ]);
            }

            for ca in &md.custom_attributes {
                add_custom_attribute(&mut tmap, m, TableIndex::MethodDef, mrid, ca, &mut sorted)?;
            }
            for d in &md.security_declarations {
                add_decl_security(&mut tmap, &coded::HAS_DECL_SECURITY, TableIndex::MethodDef, mrid, d, &mut sorted)?;
            }
            for ov in &md.overrides {
                let body_tok = tmap.method_ref(&ov.body, m)?;
                let decl_tok = tmap.method_ref(&ov.declaration, m)?;
                let body_cell =
                    encode_coded(&coded::METHOD_DEF_OR_REF, body_tok.table(), body_tok.rid())?;
                let decl_cell = encode_coded(
                    &coded::METHOD_DEF_OR_REF,
                    decl_tok.table(),
                    decl_tok.rid(),
                )?;
                tmap.builder().add_row(
                    TableIndex::MethodImpl,
                    &[type_rid as u64, body_cell, decl_cell],
                )?;
            }

            // Register the stand-alone signature for bodies with locals now so
            // the facade can hand the fresh token to the IL encoder.
            if let Some(body) = &md.body {
                if !body.locals.is_empty() {
                    let tok = tmap.local_var_sig_token(&body.locals, m)?;
                    local_var_sig_tokens.push((*mid, tok));
                }
            }
        }

        // Properties (§22.34) + PropertyMap (§22.35).
        if !td.properties.is_empty() {
            tmap
                .builder()
                .add_row(TableIndex::PropertyMap, &[type_rid as u64, property_rid as u64])?;
            for pid in &td.properties {
                let pd = &m.properties[pid.index()];
                let prid = property_rid;
                property_rid += 1;
                let sig_blob = {
                    let ctx = tmap.encoder(m);
                    write_property_signature(&pd.signature, &ctx)?
                };
                let psig = tmap.builder().insert_blob(&sig_blob);
                let pname = tmap.builder().insert_string(&pd.name);
                tmap.builder().add_row(
                    TableIndex::Property,
                    &[pd.attributes.bits() as u64, pname as u64, psig as u64],
                )?;
                if let Some(getter) = pd.get_method {
                    add_semantic(&mut tmap, MethodSemanticsAttributes::GETTER, getter, &coded::HAS_SEMANTICS, TableIndex::Property, prid, &mut sorted)?;
                }
                if let Some(setter) = pd.set_method {
                    add_semantic(&mut tmap, MethodSemanticsAttributes::SETTER, setter, &coded::HAS_SEMANTICS, TableIndex::Property, prid, &mut sorted)?;
                }
                for other in &pd.other_methods {
                    add_semantic(&mut tmap, MethodSemanticsAttributes::OTHER, *other, &coded::HAS_SEMANTICS, TableIndex::Property, prid, &mut sorted)?;
                }
                for ca in &pd.custom_attributes {
                    add_custom_attribute(&mut tmap, m, TableIndex::Property, prid, ca, &mut sorted)?;
                }
                if let Some(c) = &pd.constant {
                    add_constant(&mut tmap, &coded::HAS_CONSTANT, TableIndex::Property, prid, c, &mut sorted)?;
                }
            }
        }

        // Events (§22.18) + EventMap (§22.19).
        if !td.events.is_empty() {
            tmap
                .builder()
                .add_row(TableIndex::EventMap, &[type_rid as u64, event_rid as u64])?;
            for eid in &td.events {
                let ed = &m.events[eid.index()];
                let erid = event_rid;
                event_rid += 1;
                let ename = tmap.builder().insert_string(&ed.name);
                let event_type_cell = match &ed.event_type {
                    Some(ty) => tmap.tdor_cell(ty, m)?,
                    None => 0,
                };
                tmap.builder().add_row(
                    TableIndex::Event,
                    &[ed.attributes.bits() as u64, ename as u64, event_type_cell as u64],
                )?;
                if let Some(add_on) = ed.add_on {
                    add_semantic(&mut tmap, MethodSemanticsAttributes::ADD_ON, add_on, &coded::HAS_SEMANTICS, TableIndex::Event, erid, &mut sorted)?;
                }
                if let Some(remove_on) = ed.remove_on {
                    add_semantic(&mut tmap, MethodSemanticsAttributes::REMOVE_ON, remove_on, &coded::HAS_SEMANTICS, TableIndex::Event, erid, &mut sorted)?;
                }
                if let Some(fire) = ed.fire {
                    add_semantic(&mut tmap, MethodSemanticsAttributes::FIRE, fire, &coded::HAS_SEMANTICS, TableIndex::Event, erid, &mut sorted)?;
                }
                for other in &ed.other_methods {
                    add_semantic(&mut tmap, MethodSemanticsAttributes::OTHER, *other, &coded::HAS_SEMANTICS, TableIndex::Event, erid, &mut sorted)?;
                }
                for ca in &ed.custom_attributes {
                    add_custom_attribute(&mut tmap, m, TableIndex::Event, erid, ca, &mut sorted)?;
                }
            }
        }

        // Type-level custom attributes and security declarations.
        for ca in &td.custom_attributes {
            add_custom_attribute(&mut tmap, m, TableIndex::TypeDef, type_rid, ca, &mut sorted)?;
        }
        for d in &td.security_declarations {
            add_decl_security(&mut tmap, &coded::HAS_DECL_SECURITY, TableIndex::TypeDef, type_rid, d, &mut sorted)?;
        }
    }

    // -- NestedClass rows (§22.27), after the whole TypeDef pass, in arena
    // order: nested rid, enclosing rid.
    for (ti, td) in m.types.iter().enumerate() {
        if let Some(parent) = td.declaring_type {
            sorted
                .nested_class
                .push(vec![ti as u64 + 1, parent.0 as u64 + 1]);
        }
    }

    // -- GenericParam (§22.21) + GenericParamConstraint (§22.20), in generic
    // parameter arena order (which mirrors the sorted table order produced by
    // readers; Mono.Cecil sorts explicitly because it collects during traversal).
    for (gi, gp) in m.generic_parameters.iter().enumerate() {
        let grid = gi as u32 + 1;
        let owner_cell = match gp.owner {
            GenericOwner::Type(t) => {
                encode_coded(&coded::TYPE_OR_METHOD_DEF, TableIndex::TypeDef, t.0 + 1)?
            }
            GenericOwner::Method(mi) => {
                encode_coded(&coded::TYPE_OR_METHOD_DEF, TableIndex::MethodDef, mi.0 + 1)?
            }
        };
        let gname = tmap.builder().insert_string(&gp.name);
        tmap.builder().add_row(
            TableIndex::GenericParam,
            &[
                gp.position as u64,
                gp.attributes.bits() as u64,
                owner_cell,
                gname as u64,
            ],
        )?;
        for c in &gp.constraints {
            let cell = tmap.tdor_cell(c, m)?;
            tmap
                .builder()
                .add_row(TableIndex::GenericParamConstraint, &[grid as u64, cell as u64])?;
        }
        for ca in &gp.custom_attributes {
            add_custom_attribute(&mut tmap, m, TableIndex::GenericParam, grid, ca, &mut sorted)?;
        }
    }

    // -- Assembly-level custom attributes and security declarations (emitted
    // after types, mirroring Cecil's `BuildModule` ordering).
    if let Some(name) = asm {
        if assembly_emitted {
            for ca in &name.custom_attributes {
                add_custom_attribute(&mut tmap, m, TableIndex::Assembly, 1, ca, &mut sorted)?;
            }
            for d in &name.security_declarations {
                add_decl_security(&mut tmap, &coded::HAS_DECL_SECURITY, TableIndex::Assembly, 1, d, &mut sorted)?;
            }
        }
    }
    // Custom attributes attached to assembly references.
    for (i, r) in m.assembly_refs.iter().enumerate() {
        for ca in &r.custom_attributes {
                add_custom_attribute(&mut tmap, m, TableIndex::AssemblyRef, i as u32 + 1, ca, &mut sorted)?;
        }
    }

    // -- Flush the token map's lazily-buffered rows. Rid numbering is
    // position+1 within each vector, exactly what earlier-encoded cells assume.
    let (builder, pending) = tmap.into_parts();
    for r in &pending.type_refs {
        builder.add_row(
            TableIndex::TypeRef,
            &[r.scope_cell as u64, r.name as u64, r.namespace as u64],
        )?;
    }
    for ts in &pending.type_specs {
        builder.add_row(TableIndex::TypeSpec, &[ts.blob as u64])?;
    }
    for mr in &pending.member_refs {
        builder.add_row(
            TableIndex::MemberRef,
            &[mr.parent_cell as u64, mr.name as u64, mr.signature as u64],
        )?;
    }
    for ms in &pending.method_specs {
        builder.add_row(
            TableIndex::MethodSpec,
            &[ms.method_cell as u64, ms.instantiation as u64],
        )?;
    }
    for s in &pending.standalone_sigs {
        builder.add_row(TableIndex::StandAloneSig, &[*s as u64])?;
    }
    // -- Emit the Cecil-sorted tables stably ordered by their first column.
    sorted.flush(builder, &mut rva_patches)?;

    let entry_point_token = entry
        .map(|id| Token::new(TableIndex::MethodDef, id.0 + 1))
        .unwrap_or(Token::NIL);

    // -- Finalize and locate the placeholder cells that still need patching.
    let owned = mem::replace(builder, MetadataBuilder::new(DEFAULT_RUNTIME_VERSION));
    let root = owned.finalize();

    let (table_data_base, set) = table_stream_layout(&root)?;
    let rva_patch_offsets = rva_patches
        .iter()
        .map(|(_, row)| -> Result<usize> {
            let (rel, width) = set.cell_location(TableIndex::FieldRva, *row as u32 + 1, 0)?;
            debug_assert_eq!(width, 4, "FieldRva.Rva is a U32 column");
            Ok(table_data_base + rel as usize)
        })
        .collect::<Result<Vec<_>>>()?;
    let resource_patch_offsets = resource_patches
        .iter()
        .map(|row| -> Result<usize> {
            let (rel, width) =
                set.cell_location(TableIndex::ManifestResource, *row as u32 + 1, 0)?;
            debug_assert_eq!(width, 4, "ManifestResource.Offset is a U32 column");
            Ok(table_data_base + rel as usize)
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(EmittedMetadata {
        root,
        entry_point_token,
        data: field_data,
        rva_patches,
        rva_patch_offsets,
        resource_patches,
        resource_patch_offsets,
        local_var_sig_tokens,
    })
}

/// The metadata-root version string for `m`, with the standard fallback.
pub fn runtime_version_string(m: &Module) -> String {
    if m.runtime_version.is_empty() {
        DEFAULT_RUNTIME_VERSION.to_string()
    } else {
        m.runtime_version.clone()
    }
}

/// Mono.Cecil's `RequiresParameterRow`: a Param row exists only when the
/// parameter carries a name, non-default attributes, marshal info, a constant
/// or custom attributes.
fn requires_parameter_row(p: &Parameter) -> bool {
    !p.name.is_empty()
        || p.attributes != cecli_core::flags::ParameterAttributes::empty()
        || p.marshal_info.is_some()
        || p.constant.is_some()
        || !p.custom_attributes.is_empty()
}

/// Emits one Param row plus its satellite rows (custom attributes, constant,
/// marshal info) exactly like Cecil's `AddParameter`.
fn add_parameter(
    tmap: &mut TokenMap<'_>,
    m: &Module,
    rid: u32,
    sequence: u16,
    p: &Parameter,
    sorted: &mut SortedTables,
) -> Result<()> {
    let name = tmap.builder().insert_string(&p.name);
    tmap.builder().add_row(
        TableIndex::Param,
        &[p.attributes.bits() as u64, sequence as u64, name as u64],
    )?;
    for ca in &p.custom_attributes {
        add_custom_attribute(tmap, m, TableIndex::Param, rid, ca, sorted)?;
    }
    if let Some(c) = &p.constant {
        add_constant(tmap, &coded::HAS_CONSTANT, TableIndex::Param, rid, c, sorted)?;
    }
    if let Some(mi) = &p.marshal_info {
        add_marshal_info(tmap, m, &coded::HAS_FIELD_MARSHAL, TableIndex::Param, rid, mi, sorted)?;
    }
    Ok(())
}

/// One CustomAttribute row for `owner` (`table`, `rid`).
fn add_custom_attribute(
    tmap: &mut TokenMap<'_>,
    m: &Module,
    table: TableIndex,
    rid: u32,
    ca: &CustomAttribute,
    sorted: &mut SortedTables,
) -> Result<()> {
    let ctor = tmap.method_ref(&ca.constructor, m)?;
    let parent = encode_coded(&coded::HAS_CUSTOM_ATTRIBUTE, table, rid)?;
    let ty_cell = encode_coded(&coded::CUSTOM_ATTRIBUTE_TYPE, ctor.table(), ctor.rid())?;
    let blob = tmap.builder().insert_blob(&ca.blob);
    sorted.custom_attribute.push(vec![parent, ty_cell, blob as u64]);
    Ok(())
}

/// One Constant row; string constants store their UTF-16 payload directly
/// (Mono.Cecil `SignatureWriter.WriteConstantString`), everything else goes
/// through the shared constant codec.
fn add_constant(
    tmap: &mut TokenMap<'_>,
    group: &'static CodedIndexGroup,
    table: TableIndex,
    rid: u32,
    value: &ConstantValue,
    sorted: &mut SortedTables,
) -> Result<()> {
    let (tag, payload): (u8, Vec<u8>) = match value {
        ConstantValue::String(s) => (
            ElementType::String as u8,
            s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect(),
        ),
        other => write_constant_blob(other)?,
    };
    let parent = encode_coded(group, table, rid)?;
    let blob_idx = tmap.builder().insert_blob(&payload);
    sorted.constant.push(vec![tag as u64, 0, parent, blob_idx as u64]);
    Ok(())
}

/// One FieldMarshal row for `owner`.
fn add_marshal_info(
    tmap: &mut TokenMap<'_>,
    m: &Module,
    group: &'static CodedIndexGroup,
    table: TableIndex,
    rid: u32,
    info: &MarshalInfo,
    sorted: &mut SortedTables,
) -> Result<()> {
    let blob = {
        let tm_ref = &*tmap;
        let mut enc = |ty: &TypeDesc| tm_ref.tdor_cell(ty, m);
        write_marshal_spec(info, &mut enc)?
    };
    let blob_idx = tmap.builder().insert_blob(&blob);
    let parent = encode_coded(group, table, rid)?;
    sorted.field_marshal.push(vec![parent, blob_idx as u64]);
    Ok(())
}

/// One DeclSecurity row for `owner`.
fn add_decl_security(
    tmap: &mut TokenMap<'_>,
    group: &'static CodedIndexGroup,
    table: TableIndex,
    rid: u32,
    d: &SecurityDeclaration,
    sorted: &mut SortedTables,
) -> Result<()> {
    let blob = tmap.builder().insert_blob(&d.blob);
    let parent = encode_coded(group, table, rid)?;
    sorted
        .decl_security
        .push(vec![d.action as u16 as u64, parent, blob as u64]);
    Ok(())
}

/// One MethodSemantics row wiring `method` to its owning property/event.
fn add_semantic(
    tmap: &mut TokenMap<'_>,
    semantics: MethodSemanticsAttributes,
    method: MethodId,
    group: &'static CodedIndexGroup,
    table: TableIndex,
    rid: u32,
    sorted: &mut SortedTables,
) -> Result<()> {
    let owner = encode_coded(group, table, rid)?;
    sorted.method_semantics.push(vec![
        semantics.bits() as u64,
        method.0 as u64 + 1,
        owner,
    ]);
    Ok(())
}

/// Locates the `#~` stream inside a finalized root and rebuilds its table
/// layout, returning the absolute byte offset of the row data plus the parsed
/// layout (for cell-address arithmetic).
fn table_stream_layout(root: &[u8]) -> Result<(usize, TableSet)> {
    let header = parse_root(root)?;
    let sh = header
        .streams
        .iter()
        .find(|s| s.name == "#~")
        .ok_or_else(|| Error::bad_image("metadata root has no #~ stream"))?;
    let start = sh.offset as usize;
    let end = (start + sh.size as usize).min(root.len());
    let til = root
        .get(start..end)
        .ok_or_else(|| Error::bad_image("#~ stream out of bounds"))?;
    if til.len() < 24 {
        return Err(Error::bad_image("#~ stream header truncated"));
    }
    // #~ header: Reserved u32, Major u8, Minor u8, HeapSizes (byte 6), Reserved.
    let heap_flags = til[6];
    let valid = u64::from_le_bytes(til[8..16].try_into().expect("fixed-size slice"));
    let mut counts = [0u32; TABLE_COUNT];
    let mut written = 0usize;
    for (i, slot) in counts.iter_mut().enumerate() {
        if valid >> i & 1 == 1 {
            let at = 24 + written * 4;
            if at + 4 > til.len() {
                return Err(Error::bad_image("#~ row-count array truncated"));
            }
            *slot = u32::from_le_bytes(til[at..at + 4].try_into().expect("fixed-size slice"));
            written += 1;
        }
    }
    let set = TableSet::compute(valid, &counts, heap_flags);
    Ok((start + 24 + written * 4, set))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{
        ExternalType, LocalVariable, MethodSignature, PropertySignature, ScopeRef,
    };
    use cecli_core::flags::{
        FieldAttributes, ManifestResourceAttributes, MethodAttributes, TypeAttributes,
    };
    use cecli_metadata::MetadataReader;
    use std::fmt::Debug;

    fn ext_object(scope: ScopeRef) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: "System".into(),
            name: "Object".into(),
            nesting: Vec::new(),
            scope,
        }))
    }

    fn void() -> TypeDesc {
        TypeDesc::Internal("void".into())
    }

    fn i32_ty() -> TypeDesc {
        TypeDesc::Internal("int32".into())
    }

    /// Synthetic module: 2 types (one nested), external base, 3 methods (one
    /// with a locals signature), wired property + event, an initialized field
    /// and one embedded resource.
    fn sample_module() -> (Module, AssemblyNameDefinition) {
        let system_ref = AssemblyNameReference {
            name: "System.Runtime".into(),
            version: Version::new(8, 0, 0, 0),
            culture: None,
            public_key_or_token: Vec::new(),
            hash: Vec::new(),
            hash_algorithm: cecli_core::flags::AssemblyHashAlgorithm::None,
            attributes: cecli_core::flags::AssemblyAttributes::empty(),
            custom_attributes: Vec::new(),
        };

        let mut m = Module {
            name: "sample.dll".into(),
            guid: [7u8; 16],
            runtime_version: "v4.0.30319".into(),
            ..Module::default()
        };
        m.types.push(TypeDefinition {
            namespace: "NS".into(),
            name: "A".into(),
            attributes: TypeAttributes::PUBLIC,
            base_type: Some(ext_object(ScopeRef::Assembly(system_ref.clone()))),
            nested_types: vec![TypeId(1)],
            fields: vec![FieldId(0)],
            methods: vec![MethodId(0), MethodId(1), MethodId(2)],
            properties: vec![PropertyId(0)],
            events: vec![EventId(0)],
            ..TypeDefinition::default()
        });
        m.types.push(TypeDefinition {
            name: "B".into(),
            attributes: TypeAttributes::NESTED_PRIVATE,
            declaring_type: Some(TypeId(0)),
            methods: vec![],
            ..TypeDefinition::default()
        });

        m.fields.push(FieldDefinition {
            name: "seed".into(),
            attributes: FieldAttributes::PRIVATE
                | FieldAttributes::STATIC
                | FieldAttributes::HAS_FIELD_RVA,
            signature: FieldSignature(i32_ty()),
            initial_value: vec![1, 2, 3, 4],
            ..FieldDefinition::default()
        });

        let mut get_x = MethodDefinition {
            name: "GetX".into(),
            attributes: MethodAttributes::PUBLIC
                | MethodAttributes::STATIC
                | MethodAttributes::HIDE_BY_SIG,
            signature: MethodSignature {
                has_this: false,
                return_type: i32_ty(),
                ..MethodSignature::default()
            },
            declaring_type: TypeId(0),
            ..MethodDefinition::default()
        };
        get_x.body = Some(ResolvedBody {
            max_stack: 1,
            locals: vec![LocalVariable {
                index: 0,
                ty: i32_ty(),
                pinned: false,
            }],
            ..ResolvedBody::default()
        });
        m.methods.push(get_x);
        m.methods.push(MethodDefinition {
            name: "get_P".into(),
            attributes: MethodAttributes::PUBLIC
                | MethodAttributes::SPECIAL_NAME
                | MethodAttributes::HIDE_BY_SIG,
            signature: MethodSignature {
                return_type: i32_ty(),
                ..MethodSignature::default()
            },
            declaring_type: TypeId(0),
            ..MethodDefinition::default()
        });
        m.methods.push(MethodDefinition {
            name: "add_E".into(),
            attributes: MethodAttributes::PUBLIC
                | MethodAttributes::SPECIAL_NAME
                | MethodAttributes::HIDE_BY_SIG,
            signature: MethodSignature {
                parameters: vec![void()],
                return_type: void(),
                vararg_start: 1,
                ..MethodSignature::default()
            },
            declaring_type: TypeId(0),
            ..MethodDefinition::default()
        });

        m.properties.push(PropertyDefinition {
            name: "P".into(),
            signature: PropertySignature {
                has_this: true,
                parameters: Vec::new(),
                property_type: i32_ty(),
            },
            get_method: Some(MethodId(1)),
            ..PropertyDefinition::default()
        });
        m.events.push(EventDefinition {
            name: "E".into(),
            add_on: Some(MethodId(2)),
            ..EventDefinition::default()
        });

        m.resources.push(Resource::Embedded {
            name: "Res.data".into(),
            attributes: ManifestResourceAttributes::PRIVATE,
            data: vec![0xAA, 0xBB],
        });
        m.assembly_refs.push(system_ref);

        let asm = AssemblyNameDefinition {
            name: "Sample".into(),
            version: Version::new(1, 2, 3, 4),
            ..AssemblyNameDefinition::default()
        };
        (m, asm)
    }

    #[track_caller]
    fn cell<T: TryFrom<u64> + Debug>(r: &MetadataReader, t: TableIndex, rid: u32, col: usize) -> T
    where
        <T as TryFrom<u64>>::Error: Debug,
    {
        T::try_from(r.column(t, rid, col).expect("cell")).expect("cell cast")
    }

    #[test]
    fn synthetic_module_roundtrips_through_reader() {
        let (m, asm) = sample_module();
        let out = emit_metadata(&m, Some(&asm), Some(MethodId(0))).expect("emit");

        let reader = MetadataReader::parse(&out.root).expect("parse own output");
        let strings = &reader.heaps().strings;
        let ti = TableIndex::TypeDef;

        // Row counts per touched table.
        let expect: &[(TableIndex, u32)] = &[
            (TableIndex::Module, 1),
            (TableIndex::Assembly, 1),
            (TableIndex::AssemblyRef, 1),
            (ti, 2),
            (TableIndex::NestedClass, 1),
            (TableIndex::Field, 1),
            (TableIndex::MethodDef, 3),
            (TableIndex::PropertyMap, 1),
            (TableIndex::Property, 1),
            (TableIndex::EventMap, 1),
            (TableIndex::Event, 1),
            (TableIndex::MethodSemantics, 2),
            (TableIndex::StandAloneSig, 1),
            (TableIndex::FieldRva, 1),
            (TableIndex::ManifestResource, 1),
            (TableIndex::Param, 0),
            (TableIndex::CustomAttribute, 0),
        ];
        for (t, n) in expect {
            assert_eq!(reader.row_count(*t), *n, "table {}", t.name());
        }

        // Spot cells: module + type names.
        assert_eq!(
            strings.get(cell::<u32>(&reader, TableIndex::Module, 1, 1)).unwrap(),
            "sample.dll"
        );
        assert_eq!(strings.get(cell::<u32>(&reader, ti, 1, 1)).unwrap(), "A");
        assert_eq!(strings.get(cell::<u32>(&reader, ti, 1, 2)).unwrap(), "NS");
        assert_eq!(strings.get(cell::<u32>(&reader, ti, 2, 1)).unwrap(), "B");

        // Base type: TypeRef tag 1 pointing at the single System.Object row.
        let base = reader.column(ti, 1, 3).unwrap();
        assert_eq!(
            cecli_metadata::decode_coded(&coded::TYPE_DEF_OR_REF, base),
            Some((TableIndex::TypeRef, 1)),
        );
        let tr = reader.row(TableIndex::TypeRef, 1).unwrap();
        assert_eq!(strings.get(tr[1] as u32).unwrap(), "Object");

        // Method flags + name of GetX (cols: RVA, ImplFlags, Flags, Name...).
        let want_flags =
            (MethodAttributes::PUBLIC | MethodAttributes::STATIC | MethodAttributes::HIDE_BY_SIG)
                .bits();
        assert_eq!(cell::<u16>(&reader, TableIndex::MethodDef, 1, 2), want_flags);
        assert_eq!(
            strings.get(cell::<u32>(&reader, TableIndex::MethodDef, 1, 3)).unwrap(),
            "GetX"
        );
        // Semantics rows are STABLY SORTED by their FIRST column - the
        // SemanticsAttributes flag (A7-F1) - not the parent cell: the
        // Property getter (flag 2) precedes the Event add-on (flag 8)
        // although add_E was emitted first.
        let sem = reader.row(TableIndex::MethodSemantics, 1).unwrap();
        assert_eq!(
            cecli_metadata::decode_coded(&coded::HAS_SEMANTICS, sem[2]),
            Some((TableIndex::Property, 1))
        );
        assert_eq!(sem[1], 2, "getter is MethodDef rid 2");
        let sem2 = reader.row(TableIndex::MethodSemantics, 2).unwrap();
        assert_eq!(
            cecli_metadata::decode_coded(&coded::HAS_SEMANTICS, sem2[2]),
            Some((TableIndex::Event, 1))
        );
        assert_eq!(sem2[1], 3, "add_E is MethodDef rid 3");

        // Resource name spot cell.
        assert_eq!(
            strings
                .get(cell::<u32>(&reader, TableIndex::ManifestResource, 1, 2))
                .unwrap(),
            "Res.data"
        );

        // Assembly identity.
        assert_eq!(strings.get(cell::<u32>(&reader, TableIndex::Assembly, 1, 7)).unwrap(), "Sample");
        assert_eq!(cell::<u16>(&reader, TableIndex::Assembly, 1, 1), 1);
        assert_eq!(cell::<u16>(&reader, TableIndex::Assembly, 1, 4), 4);
        assert_eq!(reader.version_string(), "v4.0.30319");

        // Entry point + locals signature token.
        assert_eq!(out.entry_point_token, Token::new(TableIndex::MethodDef, 1));
        assert_eq!(out.local_var_sig_tokens.len(), 1);
        let (mid, tok) = out.local_var_sig_tokens[0];
        assert_eq!(mid, MethodId(0));
        assert_eq!(tok.table(), TableIndex::StandAloneSig);
        let sig_blob = reader
            .heaps()
            .blob
            .get(cell::<u32>(&reader, TableIndex::StandAloneSig, tok.rid(), 0))
            .unwrap();
        assert_eq!(&sig_blob[..2], &[0x07, 0x01], "LOCAL_SIG with 1 slot");

        // Patch placeholders: write values, re-parse, observe.
        assert_eq!(out.rva_patches.len(), 1);
        assert_eq!(out.rva_patches[0], (FieldId(0), 0));
        assert_eq!(out.rva_patch_offsets.len(), 1);
        assert_eq!(out.resource_patches, vec![0]);
        assert_eq!(out.resource_patch_offsets.len(), 1);
        let mut patched = out.root.clone();
        let off = out.rva_patch_offsets[0];
        patched[off..off + 4].copy_from_slice(&0x0000_2000u32.to_le_bytes());
        let roff = out.resource_patch_offsets[0];
        patched[roff..roff + 4].copy_from_slice(&64u32.to_le_bytes());
        let reread = MetadataReader::parse(&patched).unwrap();
        assert_eq!(reread.column(TableIndex::FieldRva, 1, 0).unwrap(), 0x2000);
        assert_eq!(reread.column(TableIndex::ManifestResource, 1, 0).unwrap(), 64);
        // Data blob holds the aligned field initial value.
        assert_eq!(out.data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn netmodule_suppresses_assembly_row_and_none_entry_is_nil() {
        let (mut m, asm) = sample_module();
        m.kind = ModuleKind::NetModule;
        let out = emit_metadata(&m, Some(&asm), None).expect("emit");
        let reader = MetadataReader::parse(&out.root).unwrap();
        assert_eq!(reader.row_count(TableIndex::Assembly), 0);
        assert!(out.entry_point_token.is_nil());
    }

    #[test]
    fn layout_path_writes_real_values_without_patches() {
        let (m, asm) = sample_module();
        let mut builder = MetadataBuilder::new("v4.0.30319");
        let tmap = TokenMap::new(&mut builder);
        let layout = EmitLayout {
            method_rvas: vec![(MethodId(0), 0x250)],
            resource_offsets: vec![8],
            data_segment_rva: 0x4000,
        };
        let out =
            emit_metadata_with(&m, Some(&asm), Some(MethodId(0)), &layout, tmap).unwrap();
        assert!(out.rva_patches.is_empty() && out.resource_patches.is_empty());

        let reader = MetadataReader::parse(&out.root).unwrap();
        assert_eq!(reader.column(TableIndex::MethodDef, 1, 0).unwrap(), 0x250);
        assert_eq!(reader.column(TableIndex::MethodDef, 2, 0).unwrap(), 0);
        assert_eq!(reader.column(TableIndex::FieldRva, 1, 0).unwrap(), 0x4000);
        assert_eq!(reader.column(TableIndex::ManifestResource, 1, 0).unwrap(), 8);
        // Entry point identical across both paths.
        assert_eq!(out.entry_point_token, Token::new(TableIndex::MethodDef, 1));
    }

    #[test]
    fn deterministic_output_across_runs() {
        let (m, asm) = sample_module();
        let a = emit_metadata(&m, Some(&asm), Some(MethodId(0))).unwrap();
        let b = emit_metadata(&m, Some(&asm), Some(MethodId(0))).unwrap();
        assert_eq!(a.root.len(), b.root.len());
        let same = a
            .root
            .iter()
            .zip(b.root.iter())
            .all(|(x, y)| x == y);
        // GUID heap input is fixed ([7u8;16]), so the whole root must repeat.
        assert!(same, "metadata root must be byte-deterministic");
    }

    #[test]
    fn sorted_tables_flush_stably_by_first_cell() {
        // A7-F1: Cecil sorts Constant/CustomAttribute/FieldMarshal/DeclSecurity/
        // ClassLayout/FieldLayout/MethodSemantics/ImplMap/FieldRva/NestedClass by
        // their first-column key cell before serialization. Keys are pushed in
        // deliberately descending order here.
        let mut builder = MetadataBuilder::new("v4.0.30319");
        let mut patches = Vec::new();
        let mut s = SortedTables::default();
        s.custom_attribute.push(vec![7, 1, 2]);
        s.custom_attribute.push(vec![3, 3, 4]);
        s.method_semantics.push(vec![9, 1, 30]);
        s.method_semantics.push(vec![5, 99, 31]);
        s.method_semantics.push(vec![5, 98, 32]); // equal key: stability keeps 99 first
        s.field_rva.push((FieldId(1), vec![0, 2])); // placeholder patch
        s.field_rva.push((FieldId(0), vec![0x2000, 1]));
        s.flush(&mut builder, &mut patches).expect("flush");

        let root = builder.finalize();
        let reader = MetadataReader::parse(&root).expect("parse");
        assert_eq!(reader.row_count(TableIndex::CustomAttribute), 2);
        assert_eq!(reader.column(TableIndex::CustomAttribute, 1, 0).unwrap(), 3);
        assert_eq!(reader.column(TableIndex::CustomAttribute, 2, 0).unwrap(), 7);
        assert_eq!(reader.row_count(TableIndex::MethodSemantics), 3);
        assert_eq!(reader.column(TableIndex::MethodSemantics, 1, 0).unwrap(), 5);
        assert_eq!(reader.column(TableIndex::MethodSemantics, 1, 1).unwrap(), 99);
        assert_eq!(reader.column(TableIndex::MethodSemantics, 2, 0).unwrap(), 5);
        assert_eq!(reader.column(TableIndex::MethodSemantics, 2, 1).unwrap(), 98);
        // FieldRva rows sort ascending by Rva cell; the zero placeholder lands
        // first. Patches record the ZERO-BASED sorted position (the consumer
        // adds one to reach the final rid).
        assert_eq!(reader.row_count(TableIndex::FieldRva), 2);
        assert_eq!(reader.column(TableIndex::FieldRva, 1, 0).unwrap(), 0);
        assert_eq!(reader.column(TableIndex::FieldRva, 2, 0).unwrap(), 0x2000);
        assert_eq!(patches, vec![(FieldId(1), 0)]);
    }
}
