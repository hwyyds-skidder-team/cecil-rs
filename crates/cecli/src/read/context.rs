//! Read-side token resolution layer (`ReadContext`).
//!
//! One [`ReadContext`] instance accompanies every module being read. It holds
//! token→handle vectors for the definition tables (`TypeDef`, `MethodDef`,
//! `Field`, `Property`, `Event`, `GenericParam`) plus eagerly pre-scanned
//! reference material (`AssemblyRef`, `ModuleRef`, `#US`, `StandAloneSig`),
//! and resolves the lazily-interpreted rows (`TypeSpec`, `MemberRef`) into the
//! object model on demand.
//!
//! Lifecycle (driven by `read_module`):
//! 1. [`ReadContext::new`] pre-scans heaps and simple reference tables.
//! 2. The module reader pushes definition handles into the public vectors in
//!    table-row order while building the arenas.
//! 3. [`ReadContext::resolve_lazy_tables`] decodes every `TypeSpec` blob and
//!    every `MemberRef` row once, deterministically, filling `type_specs` /
//!    `member_refs`. Before (or without) this step the query methods fall back
//!    to pure on-the-fly decoding, so they always work.

use std::fmt;

use cecli_core::flags::{AssemblyAttributes, AssemblyHashAlgorithm};
use cecli_core::io::ByteReader;
use cecli_core::token::{coded, TableIndex, Token};
use cecli_core::{Error, Result};
use cecli_metadata::{decode_coded, MetadataReader};

use super::module_reader::AssemblyRowData;
use crate::model::signature::{
    parse_field_signature, parse_method_signature, parse_type_element, SigContext,
};
use crate::model::types::{
    AssemblyNameReference, EventId, ExternalField, ExternalMethod, ExternalType, FieldId,
    FieldSignature, GenericParamId, MethodId, MethodRef, PropertyId, ScopeRef, TypeDesc, TypeId,
    Version,
};

/// Maximum recursion depth when walking nested TypeRef parents or chained
/// TypeSpec blobs; guards against malformed/cyclic metadata overflowing the
/// stack.
const MAX_TDOR_DEPTH: u32 = 64;

/// Options controlling what the reader loads.
#[derive(Debug, Clone)]
pub struct ReadOptions {
    /// Decode method bodies (`true` mirrors Mono.Cecil's default).
    pub load_bodies: bool,
}

impl Default for ReadOptions {
    fn default() -> Self {
        ReadOptions { load_bodies: true }
    }
}

/// Resolution result of one `MemberRef` row (indexed by rid-1).
///
/// `Spec` is never produced by [`ReadContext::resolve_member_ref`] — generic
/// instantiations live in the separate `MethodSpec` table and are resolved via
/// [`ReadContext::method_spec_ref`]; the variant exists so instruction
/// resolution can treat every member-reference shape uniformly.
#[derive(Debug, Clone, PartialEq)]
pub enum MemberRefRow {
    /// `MemberRef` carrying a method signature.
    Method(ExternalMethod),
    /// `MemberRef` carrying a field signature.
    Field(ExternalField),
    /// Instantiated method reference (filled from a `MethodSpec` row).
    Spec(MethodRef),
    /// Placeholder for a row that has not been resolved yet.
    Pending,
}

/// Read-side token resolution state for one module.
#[derive(Default)]
pub struct ReadContext {
    /// `TypeDef` rid → arena handle (rid-1 indexed).
    pub type_defs: Vec<TypeId>,
    /// `MethodDef` rid → arena handle (rid-1 indexed).
    pub method_defs: Vec<MethodId>,
    /// `Field` rid → arena handle (rid-1 indexed).
    pub field_defs: Vec<FieldId>,
    /// `Property` rid → arena handle (rid-1 indexed).
    pub prop_defs: Vec<PropertyId>,
    /// `Event` rid → arena handle (rid-1 indexed).
    pub event_defs: Vec<EventId>,
    /// `GenericParam` rid → arena handle (rid-1 indexed).
    pub gen_params: Vec<GenericParamId>,
    /// Decoded `TypeSpec` blobs (rid-1 indexed); filled by
    /// [`ReadContext::resolve_lazy_tables`].
    pub type_specs: Vec<TypeDesc>,
    /// Resolved `MemberRef` rows (rid-1 indexed); filled by
    /// [`ReadContext::resolve_lazy_tables`].
    pub member_refs: Vec<MemberRefRow>,
    /// `AssemblyRef` rows, in row order.
    pub asm_refs: Vec<AssemblyNameReference>,
    /// `ModuleRef` names, in row order.
    pub mod_refs: Vec<String>,
    /// Raw `StandAloneSig` blobs (rid-1 indexed).
    pub stand_alone_sigs: Vec<Vec<u8>>,
    /// Raw `calli` signature blobs captured during body decode:
    /// original `StandAloneSig` rid -> blob bytes. Mirrored into
    /// [`crate::module_def::Module::sas_blobs`] once body resolution finishes
    /// so the writer can re-emit the signatures through its own deduplicated
    /// `StandAloneSig` rows instead of passing stale read-side rids through.
    pub sas_blobs: std::collections::BTreeMap<u32, Vec<u8>>,
    /// Decoded `#US` heap contents in heap order (for `ldstr` operands).
    pub us_strings: Vec<String>,
    /// Entrypoint token from the CLI header (`Token::NIL` until set).
    pub entry_point_token: Token,
    /// Assembly-table row data (facade input for `AssemblyNameDefinition`);
    /// populated by the module reader when the table is non-empty.
    pub assembly_row: Option<AssemblyRowData>,

    /// `#US` heap byte offset of each entry in `us_strings`.
    pub(crate) us_offsets: Vec<u32>,
    /// On-demand decode memoization for `TypeSpec` blobs (rid-1 slots).
    /// Without it, DAG-shaped references (row K referencing row K-1 twice)
    /// would re-decode shared subtrees exponentially. Correctness never
    /// depends on it being filled.
    pub(crate) spec_memo: std::cell::RefCell<Vec<Option<TypeDesc>>>,
    /// TypeSpec rids currently being decoded (cycle detection).
    pub(crate) spec_stack: std::cell::RefCell<Vec<u32>>,
}

impl fmt::Debug for ReadContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadContext")
            .field("type_defs", &self.type_defs.len())
            .field("method_defs", &self.method_defs.len())
            .field("field_defs", &self.field_defs.len())
            .field("prop_defs", &self.prop_defs.len())
            .field("event_defs", &self.event_defs.len())
            .field("sas_blobs", &self.sas_blobs.len())
            .field("gen_params", &self.gen_params.len())
            .field("type_specs", &self.type_specs.len())
            .field("member_refs", &self.member_refs.len())
            .field("asm_refs", &self.asm_refs.len())
            .field("mod_refs", &self.mod_refs.len())
            .field("stand_alone_sigs", &self.stand_alone_sigs.len())
            .field("us_strings", &self.us_strings.len())
            .field("entry_point_token", &self.entry_point_token)
            .finish()
    }
}

impl ReadContext {
    /// Pre-scans the metadata root: reads `AssemblyRef`, `ModuleRef`,
    /// `StandAloneSig`, and the `#US` heap. Definition-handle vectors start
    /// empty and are filled by the module reader; call
    /// [`ReadContext::resolve_lazy_tables`] once they are complete.
    pub fn new(md: &MetadataReader) -> Self {
        let mut ctx = ReadContext::default();

        // AssemblyRef (ECMA-335 II §22.2): MajorVersion, MinorVersion,
        // BuildNumber, RevisionNumber, Flags, PublicKeyOrToken (blob),
        // Name (string), Culture (string), HashValue (blob).
        for rid in 1..=md.row_count(TableIndex::AssemblyRef) {
            let Ok(cells) = md.row(TableIndex::AssemblyRef, rid) else {
                break;
            };
            let culture_idx = cells[7] as u32;
            let culture = if culture_idx == 0 {
                None
            } else {
                md.heaps().strings.get(culture_idx).ok().map(str::to_owned)
            };
            ctx.asm_refs.push(AssemblyNameReference {
                name: md.heaps().strings.get(cells[6] as u32).unwrap_or("").to_owned(),
                version: Version::new(
                    cells[0] as u16,
                    cells[1] as u16,
                    cells[2] as u16,
                    cells[3] as u16,
                ),
                culture,
                public_key_or_token: md.heaps().blob.get(cells[5] as u32).unwrap_or(&[]).to_vec(),
                hash: md.heaps().blob.get(cells[8] as u32).unwrap_or(&[]).to_vec(),
                hash_algorithm: AssemblyHashAlgorithm::None,
                attributes: AssemblyAttributes::from_bits_truncate(cells[4] as u32),
                // AssemblyRef custom attributes are attached later by the
                // module reader (they require resolved constructors).
                custom_attributes: Vec::new(),
            });
        }

        // ModuleRef: Name.
        for rid in 1..=md.row_count(TableIndex::ModuleRef) {
            match md.column(TableIndex::ModuleRef, rid, 0) {
                Ok(idx) => {
                    ctx.mod_refs.push(md.heaps().strings.get(idx as u32).unwrap_or("").to_owned())
                }
                Err(_) => ctx.mod_refs.push(String::new()),
            }
        }

        // StandAloneSig: Signature blob (raw; parsed by body readers).
        for rid in 1..=md.row_count(TableIndex::StandAloneSig) {
            let blob = md
                .column(TableIndex::StandAloneSig, rid, 0)
                .and_then(|idx| md.heaps().blob.get(idx as u32))
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            ctx.stand_alone_sigs.push(blob);
        }

        // Walk the #US heap sequentially, recording each string and its byte
        // offset so ldstr tokens (which store offsets) can be mapped back.
        let data = md.heaps().user_strings.data();
        if !data.is_empty() {
            // Cecil/Roslyn writers emit a leading 0x00 filler byte, so real
            // images start their first string at offset 1; the metadata
            // builder's synthetic heaps start at offset 0. A compressed
            // length is never 0x00, so data[0] disambiguates.
            let mut pos = if data[0] == 0 { 1usize } else { 0usize };
            while pos < data.len() {
                let mut r = ByteReader::at(data, pos);
                let raw = match r.compressed_u32() {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let payload = r.position();
                let len = (raw & !1) as usize;
                if !len.is_multiple_of(2) || payload + len > data.len() {
                    break;
                }
                let s = md.heaps().user_strings.get(pos as u32).unwrap_or_default();
                ctx.us_offsets.push(pos as u32);
                ctx.us_strings.push(s);
                pos = payload + len;
            }
        }

        ctx
    }

    /// Eagerly decodes every `TypeSpec` blob and every `MemberRef` row in
    /// deterministic table order. MUST be called after the definition-handle
    /// vectors have been filled (TypeDef/MethodDef handles are referenced by
    /// the decoded trees). Idempotent: re-running simply recomputes them.
    pub fn resolve_lazy_tables(&mut self, md: &MetadataReader) -> Result<()> {
        let mut specs = Vec::with_capacity(md.row_count(TableIndex::TypeSpec) as usize);
        for rid in 1..=md.row_count(TableIndex::TypeSpec) {
            specs.push(self.type_spec_at(md, rid, 0)?);
        }
        let mut refs = Vec::with_capacity(md.row_count(TableIndex::MemberRef) as usize);
        for rid in 1..=md.row_count(TableIndex::MemberRef) {
            refs.push(self.resolve_member_ref_row(md, rid, 0)?);
        }
        self.type_specs = specs;
        self.member_refs = refs;
        Ok(())
    }

    /// Resolves an encoded TypeDefOrRef cell ((rid << 2) | tag) into its
    /// object-model descriptor.
    ///
    /// - `TypeDef` → [`TypeDesc::Def`] using the `type_defs` handle vector.
    /// - `TypeSpec` → decoded on demand from its signature blob (memoized;
    ///   forward references to later TypeSpec rows are supported).
    pub fn tdor_to_typedesc(&self, md: &MetadataReader, cell: u32) -> Result<TypeDesc> {
        self.tdor_to_typedesc_at(md, cell, 0)
    }

    /// Depth-aware [`ReadContext::tdor_to_typedesc`]: `depth` is the signature
    /// reader's current nesting level, threaded through [`SigContext::tdor_type`]
    /// so TypeSpec hops consume the same global depth budget as composite
    /// prefixes instead of restarting it per blob.
    fn tdor_to_typedesc_at(&self, md: &MetadataReader, cell: u32, depth: u32) -> Result<TypeDesc> {
        let Some((table, rid)) = decode_coded(&coded::TYPE_DEF_OR_REF, cell as u64) else {
            return Err(Error::bad_image(format!("nil TypeDefOrRef cell {cell:#x}")));
        };
        match table {
            TableIndex::TypeDef => Ok(TypeDesc::Def(self.type_def_handle(rid)?)),
            TableIndex::TypeRef => Ok(TypeDesc::External(Box::new(self.type_ref_external(
                md,
                rid,
                depth,
                &mut Default::default(),
            )?))),
            TableIndex::TypeSpec => self.type_spec_at(md, rid, depth),
            other => Err(Error::bad_image(format!(
                "unexpected table {} in TypeDefOrRef cell",
                other.name()
            ))),
        }
    }

    /// Resolves a `MemberRef` row (1-based rid) into an external method/field
    /// reference, walking the MemberRefParent coded group.
    ///
    /// A `MethodDef` parent (vararg support) yields the referenced method
    /// itself wrapped as an [`ExternalMethod`] whose parent is the declaring
    /// [`TypeDesc::Def`].
    pub fn resolve_member_ref(&self, md: &MetadataReader, cell: u32) -> Result<MemberRefRow> {
        // Serve from the cache filled by resolve_lazy_tables when available.
        let idx =
            cell.checked_sub(1).ok_or_else(|| Error::argument("MemberRef rid must be 1-based"))?
                as usize;
        if let Some(row) = self.member_refs.get(idx) {
            if !matches!(row, MemberRefRow::Pending) {
                return Ok(row.clone());
            }
        }
        self.resolve_member_ref_row(md, cell, 0)
    }

    /// Borrowed view into the cached `MemberRef` row (rid-based), if resolved.
    pub fn member_ref_row(&self, cell_rid: u32) -> Option<&MemberRefRow> {
        self.member_refs.get(cell_rid.checked_sub(1)? as usize)
    }

    /// Builds a [`SigContext`] bridging signature-blob decoding to this
    /// context's tables. Pass the same `MetadataReader` that backs the blobs.
    pub fn sig_context<'a>(&'a self, md: &'a MetadataReader) -> impl SigContext + 'a {
        CtxSigContext { ctx: self, md }
    }

    /// Resolves a METHOD_DEF_OR_REF coded cell into a [`MethodRef`]:
    /// `MethodDef` tags map through [`ReadContext::method_of`]; `MemberRef`
    /// tags through [`ReadContext::resolve_member_ref`].
    pub fn method_def_or_ref(&self, md: &MetadataReader, cell: u32) -> Result<MethodRef> {
        let Some((table, rid)) = decode_coded(&coded::METHOD_DEF_OR_REF, cell as u64) else {
            return Err(Error::bad_image(format!("nil MethodDefOrRef cell {cell:#x}")));
        };
        match table {
            TableIndex::MethodDef => {
                let id =
                    self.method_of(Token::new(TableIndex::MethodDef, rid)).ok_or_else(|| {
                        Error::bad_image(format!(
                            "MethodDef rid {rid} outside populated method arena"
                        ))
                    })?;
                Ok(MethodRef::Def(id))
            }
            TableIndex::MemberRef => match self.resolve_member_ref(md, rid)? {
                MemberRefRow::Method(em) => Ok(MethodRef::External(em)),
                MemberRefRow::Spec(mr) => Ok(mr),
                other => Err(Error::bad_image(format!(
                    "expected a method-shaped MemberRef row, got {other:?}"
                ))),
            },
            other => Err(Error::bad_image(format!(
                "unexpected table {} in MethodDefOrRef cell",
                other.name()
            ))),
        }
    }

    /// Resolves a `MethodSpec` row (1-based rid): resolves the METHOD_DEF_OR_REF
    /// base and decodes the instantiation blob (`0x0A` + arity + type elements)
    /// into a [`MethodRef::Spec`].
    pub fn method_spec_ref(&self, md: &MetadataReader, rid: u32) -> Result<MethodRef> {
        if rid == 0 || rid > md.row_count(TableIndex::MethodSpec) {
            return Err(Error::argument(format!("MethodSpec rid {rid} out of range")));
        }
        let base_cell = md.column(TableIndex::MethodSpec, rid, 0)? as u32;
        let blob_idx = md.column(TableIndex::MethodSpec, rid, 1)? as u32;
        let blob = md.heaps().blob.get(blob_idx)?;

        let base = self.method_def_or_ref(md, base_cell)?;

        let mut r = ByteReader::at(blob, 0);
        if r.u8()? != 0x0A {
            return Err(Error::bad_image(format!(
                "MethodSpec rid {rid} signature does not start with GENERICINST (0x0A)"
            )));
        }
        let arity = r.compressed_u32()?;
        let sctx = CtxSigContext { ctx: self, md };
        let mut arguments = Vec::with_capacity(arity as usize);
        for _ in 0..arity {
            let (ty, consumed) = parse_type_element(blob, r.position(), &sctx, 0, false)?;
            r.seek(r.position() + consumed)?;
            arguments.push(ty);
        }
        Ok(MethodRef::Spec { method: Box::new(base), arguments })
    }

    /// Maps a `MethodDef` token to its arena handle.
    pub fn method_of(&self, tok: Token) -> Option<MethodId> {
        if tok.table_byte() != TableIndex::MethodDef as u8 || tok.rid() == 0 {
            return None;
        }
        self.method_defs.get(tok.rid() as usize - 1).copied()
    }

    /// Maps a `#US` heap offset (as stored in `ldstr` tokens) to its decoded
    /// string, preferring the pre-scanned enumeration over a fresh heap read.
    pub fn user_string_at(&self, md: &MetadataReader, offset: u32) -> Result<String> {
        if let Ok(i) = self.us_offsets.binary_search(&offset) {
            return Ok(self.us_strings[i].clone());
        }
        // Bounds-check first: the raw heap reader assumes in-range offsets.
        if offset as usize >= md.heaps().user_strings.data().len() {
            return Err(Error::bad_image(format!(
                "#US offset {offset} outside heap ({} bytes)",
                md.heaps().user_strings.data().len()
            )));
        }
        md.heaps().user_strings.get(offset)
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    fn type_def_handle(&self, rid: u32) -> Result<TypeId> {
        self.type_defs
            .get(rid.checked_sub(1).ok_or_else(|| Error::bad_image("TypeDef rid 0 is invalid"))?
                as usize)
            .copied()
            .ok_or_else(|| {
                Error::bad_image(format!(
                    "TypeDef rid {rid} outside populated type arena ({} entries)",
                    self.type_defs.len()
                ))
            })
    }

    /// Resolves a TypeRef row to its external-type tree, walking the
    /// ResolutionScope and (for nested types) chaining same-table parents.
    /// `nesting` ends up innermost-last.
    ///
    /// Malformed images may contain circular TypeRef parent chains; mirroring
    /// Mono.Cecil, the walk then returns an incomplete reference (the row's
    /// own identity with a [`ScopeRef::Moduleless`] scope) instead of failing
    /// the whole module read. `visited` carries the rids of the current chain.
    fn type_ref_external(
        &self,
        md: &MetadataReader,
        rid: u32,
        depth: u32,
        visited: &mut std::collections::BTreeSet<u32>,
    ) -> Result<ExternalType> {
        let degraded = depth > MAX_TDOR_DEPTH || !visited.insert(rid);
        let scope_cell = md.column(TableIndex::TypeRef, rid, 0)? as u32;
        let name =
            md.heaps().strings.get(md.column(TableIndex::TypeRef, rid, 1)? as u32)?.to_owned();
        let namespace =
            md.heaps().strings.get(md.column(TableIndex::TypeRef, rid, 2)? as u32)?.to_owned();

        // Circular or pathologically deep chain: return the row's own identity
        // without further scope resolution so callers still get a usable tree.
        if degraded {
            return Ok(ExternalType {
                namespace,
                name,
                nesting: Vec::new(),
                scope: ScopeRef::Moduleless,
            });
        }

        let scope = match decode_coded(&coded::RESOLUTION_SCOPE, scope_cell as u64) {
            // Nil scope behaves like the current module (Mono.Cecil semantics).
            None | Some((TableIndex::Module, 0)) => ScopeRef::ThisModule,
            Some((TableIndex::Module, mrid)) => {
                if mrid == 1 {
                    // Row 1 of the Module table is the module being read.
                    ScopeRef::ThisModule
                } else {
                    // A different Module-table row: resolve that row's name.
                    let name_idx = md.column(TableIndex::Module, mrid, 1)? as u32;
                    ScopeRef::OtherModule(md.heaps().strings.get(name_idx)?.to_owned())
                }
            }
            Some((TableIndex::ModuleRef, mr)) => {
                let name = self
                    .mod_refs
                    .get(
                        mr.checked_sub(1)
                            .ok_or_else(|| Error::bad_image("ModuleRef rid 0 is invalid"))?
                            as usize,
                    )
                    .ok_or_else(|| Error::bad_image(format!("ModuleRef rid {mr} out of range")))?
                    .clone();
                ScopeRef::OtherModule(name)
            }
            Some((TableIndex::AssemblyRef, ar)) => {
                let asm = self
                    .asm_refs
                    .get(
                        ar.checked_sub(1)
                            .ok_or_else(|| Error::bad_image("AssemblyRef rid 0 is invalid"))?
                            as usize,
                    )
                    .ok_or_else(|| Error::bad_image(format!("AssemblyRef rid {ar} out of range")))?
                    .clone();
                ScopeRef::Assembly(asm)
            }
            // Nested type: adopt the parent's resolution scope and splice the
            // parent onto our ancestor chain (the direct declaring type lands
            // last in `nesting`).
            Some((TableIndex::TypeRef, prid)) => {
                let parent = self.type_ref_external(md, prid, depth + 1, visited)?;
                let scope = parent.scope.clone();
                let mut nesting = parent.nesting;
                nesting.push(Box::new(ExternalType {
                    namespace: parent.namespace,
                    name: parent.name,
                    nesting: Vec::new(),
                    scope: scope.clone(),
                }));
                return Ok(ExternalType { namespace, name, nesting, scope });
            }
            Some((other, _)) => {
                return Err(Error::bad_image(format!(
                    "unexpected table {} in ResolutionScope cell",
                    other.name()
                )))
            }
        };

        Ok(ExternalType { namespace, name, nesting: Vec::new(), scope })
    }

    /// Decodes a TypeSpec row's signature blob on demand, directly from the
    /// metadata bytes. Blobs may reference OTHER TypeSpec rows (including
    /// forward references to later rows), so decoding is fully recursive and
    /// never depends on [`ReadContext::resolve_lazy_tables`] having run;
    /// successful decodes are memoized so DAG-shaped reference graphs (row K
    /// referencing row K-1 twice) stay linear instead of exponential. The
    /// memo clone is shallow because [`TypeDesc`] children are `Arc`-shared:
    /// repeated references alias one allocation instead of re-expanding.
    ///
    /// `depth` is the caller's nesting level; the blob is re-parsed seeded at
    /// that depth, so the [`crate::model::signature`] depth budget is shared
    /// across blob hops instead of resetting per hop. A cycle guard rejects
    /// rows that (transitively) reference themselves.
    ///
    /// The writer mirrors this linearity: `TokenMap`'s per-allocation
    /// encoding cache (`SigContext::cached_element` / `remember_element`)
    /// encodes each shared `Arc` subtree once, so DAG-shaped graphs stay
    /// linear in both directions.
    fn type_spec_at(&self, md: &MetadataReader, rid: u32, depth: u32) -> Result<TypeDesc> {
        if rid == 0 || rid > md.row_count(TableIndex::TypeSpec) {
            return Err(Error::argument(format!("TypeSpec rid {rid} out of range")));
        }
        let idx = rid as usize - 1;
        if let Some(Some(cached)) = self.spec_memo.borrow().get(idx) {
            return Ok(cached.clone());
        }
        {
            let stack = self.spec_stack.borrow();
            // The caller-supplied depth only tracks one bridge path; the
            // active chain length below also bounds blob-cell chains that
            // re-enter this function with a stale depth (TypeSpec[1] ->
            // cell -> TypeSpec[2] -> ...).
            if depth > MAX_TDOR_DEPTH || stack.len() >= MAX_TDOR_DEPTH as usize {
                return Err(Error::bad_image("TypeSpec chain deeper than 64 levels"));
            }
            if stack.contains(&rid) {
                return Err(Error::bad_image(format!(
                    "cyclic TypeSpec reference through rid {rid}"
                )));
            }
        }
        let blob_idx = md.column(TableIndex::TypeSpec, rid, 0)? as u32;
        let blob = md.heaps().blob.get(blob_idx)?;

        self.spec_stack.borrow_mut().push(rid);
        let decoded = {
            let sctx = CtxSigContext { ctx: self, md };
            parse_type_element(blob, 0, &sctx, depth, false).map(|(ty, _)| ty)
        };
        self.spec_stack.borrow_mut().pop();
        let ty = decoded?;

        let mut memo = self.spec_memo.borrow_mut();
        if memo.len() <= idx {
            memo.resize(md.row_count(TableIndex::TypeSpec) as usize, None);
        }
        memo[idx] = Some(ty.clone());
        drop(memo);
        Ok(ty)
    }

    /// Full MemberRef row resolution (see [`ReadContext::resolve_member_ref`]).
    fn resolve_member_ref_row(
        &self,
        md: &MetadataReader,
        rid: u32,
        depth: u32,
    ) -> Result<MemberRefRow> {
        if depth > MAX_TDOR_DEPTH {
            return Err(Error::bad_image("nested MemberRef resolution too deep"));
        }
        if rid == 0 || rid > md.row_count(TableIndex::MemberRef) {
            return Err(Error::argument(format!("MemberRef rid {rid} out of range")));
        }
        let parent_cell = md.column(TableIndex::MemberRef, rid, 0)? as u32;
        let name =
            md.heaps().strings.get(md.column(TableIndex::MemberRef, rid, 1)? as u32)?.to_owned();
        let sig_blob = md.heaps().blob.get(md.column(TableIndex::MemberRef, rid, 2)? as u32)?;
        let sctx = CtxSigContext { ctx: self, md };

        let Some((parent_table, prid)) =
            decode_coded(&coded::MEMBER_REF_PARENT, parent_cell as u64)
        else {
            return Err(Error::bad_image(format!(
                "nil MemberRefParent cell {parent_cell:#x} in MemberRef rid {rid}"
            )));
        };

        // Function-pointer/vararg members point straight at a MethodDef row;
        // the referenced member is that method itself.
        if parent_table == TableIndex::MethodDef {
            let declaring = self.declaring_type_of_method(md, prid)?;
            return Ok(MemberRefRow::Method(ExternalMethod {
                parent: TypeDesc::Def(declaring),
                name,
                signature: parse_method_signature(sig_blob, &sctx)?,
            }));
        }

        let parent = match parent_table {
            TableIndex::TypeDef => TypeDesc::Def(self.type_def_handle(prid)?),
            TableIndex::TypeRef => TypeDesc::External(Box::new(self.type_ref_external(
                md,
                prid,
                depth + 1,
                &mut Default::default(),
            )?)),
            TableIndex::ModuleRef => {
                // Members declared in the `<Module>` pseudo-type of another
                // netmodule: the type carries the module's name.
                let mod_name = self
                    .mod_refs
                    .get(
                        prid.checked_sub(1)
                            .ok_or_else(|| Error::bad_image("ModuleRef rid 0 is invalid"))?
                            as usize,
                    )
                    .cloned()
                    .ok_or_else(|| {
                        Error::bad_image(format!("ModuleRef rid {prid} out of range"))
                    })?;
                TypeDesc::External(Box::new(ExternalType {
                    namespace: String::new(),
                    name: mod_name.clone(),
                    nesting: Vec::new(),
                    scope: ScopeRef::OtherModule(mod_name),
                }))
            }
            TableIndex::TypeSpec => self.type_spec_at(md, prid, depth + 1)?,
            other => {
                return Err(Error::bad_image(format!(
                    "unexpected table {} in MemberRefParent cell",
                    other.name()
                )))
            }
        };

        // First signature byte disambiguates: 0x06 is ELEMENT_TYPE_FIELD.
        if sig_blob.first() == Some(&0x06) {
            Ok(MemberRefRow::Field(ExternalField {
                parent,
                name,
                signature: FieldSignature(parse_field_signature(sig_blob, &sctx)?.0),
            }))
        } else {
            Ok(MemberRefRow::Method(ExternalMethod {
                parent,
                name,
                signature: parse_method_signature(sig_blob, &sctx)?,
            }))
        }
    }

    /// Finds the declaring TypeDef of a MethodDef rid by walking TypeDef
    /// method-list ranges (`start .. next_start`, last type ends at
    /// MethodDef-count + 1).
    fn declaring_type_of_method(&self, md: &MetadataReader, method_rid: u32) -> Result<TypeId> {
        let type_count = md.row_count(TableIndex::TypeDef);
        let end_bound = md.row_count(TableIndex::MethodDef) + 1;
        for t in 1..=type_count {
            let start = md.column(TableIndex::TypeDef, t, 5)? as u32;
            let end = if t < type_count {
                md.column(TableIndex::TypeDef, t + 1, 5)? as u32
            } else {
                end_bound
            };
            if method_rid >= start && method_rid < end {
                return self.type_def_handle(t);
            }
        }
        Err(Error::bad_image(format!("no TypeDef declares MethodDef rid {method_rid}")))
    }
}

/// Private bridge exposing this context to the signature codec: the read side
/// never encodes blobs, so the write-direction methods fail.
struct CtxSigContext<'c, 'd> {
    ctx: &'c ReadContext,
    md: &'d MetadataReader<'d>,
}

impl<'c, 'd> SigContext for CtxSigContext<'c, 'd> {
    fn tdor_cell(&self, _ty: &TypeDesc) -> Result<u32> {
        Err(Error::unsupported("read-side SigContext never encodes TypeDefOrRef cells"))
    }

    fn is_value_type(&self, _ty: &TypeDesc) -> Result<bool> {
        Err(Error::unsupported("read-side SigContext cannot classify value types"))
    }

    fn tdor_type(&self, _value_type: bool, cell: u32, depth: u32) -> Result<TypeDesc> {
        // The CLASS/VALUETYPE marker is irrelevant here: TypeDesc trees do not
        // record it, and the blob position already told the codec which branch
        // to take. The reader's nesting level rides along so TypeSpec hops
        // share one global depth budget.
        self.ctx.tdor_to_typedesc_at(self.md, cell, depth)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::signature::parse_local_var_sig;
    use cecli_metadata::{encode_coded, MetadataBuilder};

    /// Synthetic root: Module, AssemblyRef(mscorlib), TypeRef(System.Object),
    /// nested TypeRef, TypeDef, MemberRef(object.ToString()),
    /// TypeSpec(SzArray of TypeDef), MethodSpec, StandAloneSig, #US entry.
    fn build_test_md() -> (Vec<u8>, u32 /* us offset */) {
        let mut b = MetadataBuilder::new("v4.0.30319");

        let mname = b.insert_string("<Module>");
        let mvid = b.insert_guid(&[9u8; 16]);
        b.add_row(TableIndex::Module, &[0, mname as u64, mvid as u64, 0, 0]).unwrap();

        let ar_name = b.insert_string("mscorlib");
        b.add_row(
            TableIndex::AssemblyRef,
            // Name index in slot 6: ReadContext applies ECMA II §22.2 order
            // (PK, Name, Culture, Hash), matching real images.
            &[2, 0, 0, 0, 0, 0, ar_name as u64, 0, 0],
        )
        .unwrap();
        let obj_ns = b.insert_string("System");
        let obj_name = b.insert_string("Object");
        let scope_asm = encode_coded(&coded::RESOLUTION_SCOPE, TableIndex::AssemblyRef, 1).unwrap();
        b.add_row(TableIndex::TypeRef, &[scope_asm, obj_name as u64, obj_ns as u64]).unwrap(); // rid 1

        // Nested TypeRef whose parent is TypeRef rid 1.
        let coll_ns = b.insert_string("System.Collections");
        let coll_name = b.insert_string("Enumerator");
        let scope_nested = encode_coded(&coded::RESOLUTION_SCOPE, TableIndex::TypeRef, 1).unwrap();
        b.add_row(TableIndex::TypeRef, &[scope_nested, coll_name as u64, coll_ns as u64]).unwrap(); // rid 2

        let def_ns = b.insert_string("TestNs");
        let def_name = b.insert_string("Mine");
        b.add_row(TableIndex::TypeDef, &[0x0010_0001, def_name as u64, def_ns as u64, 0, 1, 1])
            .unwrap(); // rid 1
        let tostring = b.insert_string("ToString");
        let m_sig = b.insert_blob(&[0x20, 0x00, 0x01]); // instance, 0 params, void ret
        let mr_parent = encode_coded(&coded::MEMBER_REF_PARENT, TableIndex::TypeRef, 1).unwrap();
        b.add_row(TableIndex::MemberRef, &[mr_parent, tostring as u64, m_sig as u64]).unwrap(); // rid 1

        // TypeSpec rid 1: SZARRAY over CLASS(TypeDef rid 1), cell = (1<<2)|0 = 4.
        let ts_blob = b.insert_blob(&[0x1D, 0x12, 0x04]);
        b.add_row(TableIndex::TypeSpec, &[ts_blob as u64]).unwrap(); // rid 1

        // MethodSpec rid 1: instantiates MemberRef rid 1 with one argument
        // (CLASS over TypeDef rid 1).
        let msor = encode_coded(&coded::METHOD_DEF_OR_REF, TableIndex::MemberRef, 1).unwrap();
        let spec_blob = b.insert_blob(&[0x0A, 0x01, 0x12, 0x04]);
        b.add_row(TableIndex::MethodSpec, &[msor, spec_blob as u64]).unwrap(); // rid 1

        // StandAloneSig rid 1: one local of type SzArray(Class TypeDef 1).
        let local_sig = b.insert_blob(&[0x07, 0x01, 0x1D, 0x12, 0x04]);
        b.add_row(TableIndex::StandAloneSig, &[local_sig as u64]).unwrap(); // rid 1

        let us_off = b.insert_user_string("hello");
        (b.finalize(), us_off)
    }

    /// Parses fresh bytes and returns a fully-resolved context. The caller
    /// keeps `bytes` alive; the reader borrows it.
    fn setup(bytes: &[u8]) -> ReadContext {
        let md = MetadataReader::parse(bytes).expect("synthetic root parses");
        let mut ctx = ReadContext::new(&md);
        ctx.type_defs.push(TypeId(0));
        ctx.resolve_lazy_tables(&md).expect("lazy tables resolve");
        ctx
    }

    #[test]
    fn prescan_fills_reference_rows() {
        let (bytes, _us) = build_test_md();
        let _md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let ctx = setup(&bytes);
        assert_eq!(ctx.asm_refs.len(), 1);
        let asm = &ctx.asm_refs[0];
        assert_eq!(asm.name, "mscorlib");
        assert_eq!(asm.version, Version::new(2, 0, 0, 0));
        assert!(asm.culture.is_none());
        assert!(asm.public_key_or_token.is_empty());
        assert_eq!(ctx.mod_refs.len(), 0);
        // The synthetic builder appends a redundant trailing flag byte per
        // record, which the sequential walker may surface as a trailing "";
        // real ECMA heaps do not. Either way "hello" maps at its offset.
        assert_eq!(ctx.us_strings[0], "hello");
        assert_eq!(ctx.stand_alone_sigs.len(), 1);
        assert_eq!(ctx.entry_point_token, Token::NIL);
        assert!(ctx.assembly_row.is_none());
    }

    #[test]
    fn tdor_typeref_walks_resolution_scope() {
        let (bytes, _us) = build_test_md();
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let ctx = setup(&bytes);
        let cell = (1u32 << 2) | 1; // TypeRef rid 1
        match ctx.tdor_to_typedesc(&md, cell).unwrap() {
            TypeDesc::External(e) => {
                assert_eq!((e.namespace.as_str(), e.name.as_str()), ("System", "Object"));
                assert_eq!(e.nesting.len(), 0);
                match e.scope {
                    ScopeRef::Assembly(ref a) => {
                        assert_eq!(a.name, "mscorlib");
                        assert_eq!(a.version, Version::new(2, 0, 0, 0));
                    }
                    other => panic!("expected Assembly scope, got {other:?}"),
                }
            }
            other => panic!("expected External, got {other:?}"),
        }

        // Nested TypeRef inherits the scope and chains the parent.
        let nested_cell = (2u32 << 2) | 1;
        match ctx.tdor_to_typedesc(&md, nested_cell).unwrap() {
            TypeDesc::External(e) => {
                assert_eq!(
                    (e.namespace.as_str(), e.name.as_str()),
                    ("System.Collections", "Enumerator")
                );
                assert_eq!(e.nesting.len(), 1);
                assert_eq!(e.nesting[0].name, "Object");
                assert!(matches!(e.scope, ScopeRef::Assembly(_)));
            }
            other => panic!("expected External, got {other:?}"),
        }
    }

    #[test]
    fn tdor_typedef_maps_to_handle() {
        let (bytes, _us) = build_test_md();
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let ctx = setup(&bytes);
        let cell = 1u32 << 2;
        assert_eq!(ctx.tdor_to_typedesc(&md, cell).unwrap(), TypeDesc::Def(TypeId(0)));
    }

    #[test]
    fn tdor_typespec_decodes_szarray_of_typedef() {
        let (bytes, _us) = build_test_md();
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let ctx = setup(&bytes);
        let cell = (1u32 << 2) | 2;
        assert_eq!(
            ctx.tdor_to_typedesc(&md, cell).unwrap(),
            TypeDesc::SzArray(std::sync::Arc::new(TypeDesc::Def(TypeId(0))))
        );
        // Cached path (post-resolve_lazy_tables) agrees.
        assert_eq!(ctx.type_specs.len(), 1);
        assert_eq!(
            ctx.type_specs[0],
            TypeDesc::SzArray(std::sync::Arc::new(TypeDesc::Def(TypeId(0))))
        );
    }

    #[test]
    fn member_ref_resolves_to_object_to_string() {
        let (bytes, _us) = build_test_md();
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let ctx = setup(&bytes);
        match ctx.resolve_member_ref(&md, 1).unwrap() {
            MemberRefRow::Method(em) => {
                match em.parent {
                    TypeDesc::External(e) => {
                        assert_eq!((e.namespace.as_str(), e.name.as_str()), ("System", "Object"));
                    }
                    other => panic!("expected External parent, got {other:?}"),
                }
                assert_eq!(em.name, "ToString");
                assert!(em.signature.has_this);
                assert_eq!(em.signature.parameters.len(), 0);
                assert_eq!(em.signature.return_type, TypeDesc::Internal("void".into()));
                assert_eq!(
                    em.signature.convention,
                    cecli_core::flags::SignatureCallingConvention::Default
                );
            }
            other => panic!("expected Method row, got {other:?}"),
        }
        // Cached accessor serves the identical row.
        let again = ctx.resolve_member_ref(&md, 1).unwrap();
        assert_eq!(ctx.member_ref_row(1), Some(&again));
    }

    #[test]
    fn method_spec_resolves_instantiation() {
        let (bytes, _us) = build_test_md();
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let ctx = setup(&bytes);
        match ctx.method_spec_ref(&md, 1).unwrap() {
            MethodRef::Spec { method, arguments } => {
                assert!(matches!(*method, MethodRef::External(_)));
                assert_eq!(arguments, vec![TypeDesc::Def(TypeId(0))]);
            }
            other => panic!("expected Spec, got {other:?}"),
        }
    }

    #[test]
    fn method_def_or_ref_and_method_of() {
        let (bytes, _us) = build_test_md();
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let ctx = setup(&bytes);
        // MethodDef tag with no methods populated -> error surfaces cleanly.
        let cell =
            encode_coded(&coded::METHOD_DEF_OR_REF, TableIndex::MethodDef, 1).unwrap() as u32;
        assert!(ctx.method_def_or_ref(&md, cell).is_err());
        // MemberRef tag resolves to External (METHOD_DEF_OR_REF uses 1 tag bit).
        let cell =
            encode_coded(&coded::METHOD_DEF_OR_REF, TableIndex::MemberRef, 1).unwrap() as u32;
        assert!(matches!(ctx.method_def_or_ref(&md, cell).unwrap(), MethodRef::External(_)));
        // method_of on non-MethodDef tokens is None.
        assert_eq!(ctx.method_of(Token::new(TableIndex::TypeDef, 1)), None);
    }

    #[test]
    fn sig_context_parses_local_var_sig() {
        let (bytes, _us) = build_test_md();
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let ctx = setup(&bytes);
        let sc = ctx.sig_context(&md);
        let vars = parse_local_var_sig(&ctx.stand_alone_sigs[0], &sc).unwrap();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars[0].index, 0);
        assert!(!vars[0].pinned);
        assert_eq!(vars[0].ty, TypeDesc::SzArray(std::sync::Arc::new(TypeDesc::Def(TypeId(0)))));
    }

    #[test]
    fn user_string_lookup_roundtrips() {
        let (bytes, us_off) = build_test_md();
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let ctx = setup(&bytes);
        assert_eq!(ctx.user_string_at(&md, us_off).unwrap(), "hello");
        // Unknown offsets fall back to the heap reader.
        assert!(ctx.user_string_at(&md, 0xFFFF_FFFF).is_err());
    }

    #[test]
    fn pure_fallback_works_without_lazy_tables() {
        let (bytes, _us) = build_test_md();
        let md = MetadataReader::parse(&bytes).unwrap();
        // TypeSpec decode falls back to pure parsing; Def handles are missing
        // though (arena empty), so expect the bad-image error rather than a panic.
        let cell = (1u32 << 2) | 2;
        let ctx = ReadContext::new(&md); // no handles pushed, no resolve_lazy_tables
        assert!(ctx.tdor_to_typedesc(&md, cell).is_err());
        // TypeRef resolution is fully independent of arenas and still works.
        let tr_cell = (1u32 << 2) | 1;
        assert!(matches!(ctx.tdor_to_typedesc(&md, tr_cell).unwrap(), TypeDesc::External(_)));
    }

    /// Builds a synthetic root whose TypeSpec rows form a sharing DAG: row K
    /// is `SZARRAY(GENERICINST Class TypeDef1 < cell(K-1), cell(K-1) >)`, so
    /// every row references its predecessor twice. Fully expanded this is
    /// ~2^rows nodes; `Arc`-shared subgraphs keep it linear.
    fn build_dag_md(rows: u32) -> Vec<u8> {
        let mut b = MetadataBuilder::new("v4.0.30319");
        let mname = b.insert_string("<Module>");
        let mvid = b.insert_guid(&[7u8; 16]);
        b.add_row(TableIndex::Module, &[0, mname as u64, mvid as u64, 0, 0]).unwrap();
        let def_name = b.insert_string("Mine");
        let def_ns = b.insert_string("TestNs");
        b.add_row(TableIndex::TypeDef, &[0x0010_0001, def_name as u64, def_ns as u64, 0, 1, 1])
            .unwrap(); // rid 1

        // TypeDef rid 1 cell: TypeDef tag 0.
        let td_cell: u8 = 4;
        for k in 1..=rows {
            let blob = if k == 1 {
                // Base case: SZARRAY of I4.
                vec![0x1D, 0x08]
            } else {
                let prev = ((k - 1) << 2) | 2; // TypeSpec tag 2, rid k-1
                                               // SZARRAY + GENERICINST Class TypeDef1 < Class prev, Class prev >
                vec![0x1D, 0x15, 0x12, td_cell, 0x02, 0x12, prev as u8, 0x12, prev as u8]
            };
            let idx = b.insert_blob(&blob);
            b.add_row(TableIndex::TypeSpec, &[idx as u64]).unwrap();
        }
        b.finalize()
    }

    /// ~2^30 nodes when fully expanded: `Arc`-shared subgraphs must keep the
    /// whole DAG resolving in linear time and memory (the pre-Arc node-budget
    /// era rejected this image; sharing makes the budget unnecessary).
    #[test]
    fn dag_typespec_resolves_linearly_via_memo() {
        let bytes = build_dag_md(30);
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let mut ctx = ReadContext::new(&md);
        ctx.type_defs.push(TypeId(0));
        ctx.resolve_lazy_tables(&md).expect("30-row DAG resolves");
        assert_eq!(ctx.type_specs.len(), 30);
    }

    /// The sharing must be structural, not just value equality: row 30's two
    /// generic arguments both point at the SAME `Arc` allocation holding row
    /// 29's tree.
    #[test]
    fn dag_typespec_arguments_share_allocations() {
        let bytes = build_dag_md(30);
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let mut ctx = ReadContext::new(&md);
        ctx.type_defs.push(TypeId(0));
        ctx.resolve_lazy_tables(&md).expect("30-row DAG resolves");

        // Row 30 = SZARRAY(GI{args: [row29, row29]}).
        let row30 = &ctx.type_specs[29];
        let TypeDesc::SzArray(outer) = row30 else {
            panic!("expected SzArray at row 30, got {row30:?}")
        };
        let TypeDesc::GenericInstance { arguments, .. } = outer.as_ref() else {
            panic!("expected GenericInstance under SzArray, got {outer:?}")
        };
        assert_eq!(arguments.len(), 2);
        let TypeDesc::SzArray(a) = arguments[0].as_ref() else {
            panic!("expected SzArray argument, got {:?}", arguments[0])
        };
        let TypeDesc::SzArray(b) = arguments[1].as_ref() else {
            panic!("expected SzArray argument, got {:?}", arguments[1])
        };
        // Both references to row 29 resolve to the same allocation.
        assert!(std::sync::Arc::ptr_eq(a, b), "arguments must share one Arc");
        // ...and that allocation is the memoized row 29 tree itself.
        let TypeDesc::SzArray(row29_inner) = &ctx.type_specs[28] else {
            panic!("expected SzArray at row 29")
        };
        assert!(
            std::sync::Arc::ptr_eq(a, row29_inner),
            "argument must alias the memoized row-29 subtree"
        );
    }

    /// Regression guard: the signature depth budget must be global across
    /// TypeSpec hops, not reset per blob. A chain of TypeSpec rows whose
    /// blobs each nest several composite levels and reference the NEXT row
    /// (forward references bypass memoization, forcing real recursion) must
    /// fail once the combined depth crosses the cap.
    #[test]
    fn typespec_hop_depth_is_global_not_per_blob() {
        let per_blob_prefix: u32 = 8; // SZARRAY layers inside each blob
        let rows = (MAX_TDOR_DEPTH / per_blob_prefix) + 2;

        let mut b = MetadataBuilder::new("v4.0.30319");
        let mname = b.insert_string("<Module>");
        let mvid = b.insert_guid(&[7u8; 16]);
        b.add_row(TableIndex::Module, &[0, mname as u64, mvid as u64, 0, 0]).unwrap();
        let def_name = b.insert_string("Mine");
        let def_ns = b.insert_string("TestNs");
        b.add_row(TableIndex::TypeDef, &[0x0010_0001, def_name as u64, def_ns as u64, 0, 1, 1])
            .unwrap();

        for k in 1..=rows {
            let mut blob = vec![0x1Du8; per_blob_prefix as usize];
            blob.push(0x12); // CLASS
            if k == rows {
                blob.push(0x04); // terminal: TypeDef rid 1
            } else {
                blob.push(((k + 1) << 2 | 2) as u8); // forward ref to row k+1
            }
            let idx = b.insert_blob(&blob);
            b.add_row(TableIndex::TypeSpec, &[idx as u64]).unwrap();
        }
        let bytes = b.finalize();
        let md = MetadataReader::parse(&bytes).expect("synthetic root parses");
        let mut ctx = ReadContext::new(&md);
        ctx.type_defs.push(TypeId(0));
        // Combined depth ~ rows * per_blob_prefix exceeds the cap; a per-hop
        // reset would let it through, the global budget must not.
        let err = ctx.resolve_lazy_tables(&md).expect_err("depth budget must be global");
        assert!(err.to_string().contains("deeper than"), "unexpected error: {err}");
    }
}
