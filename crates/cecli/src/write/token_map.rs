//! Write-side deduplication and token allocation (`Mono.Cecil` writer's
//! `TypeReferenceCounter` / `MemberReferenceCollector` analog).
//!
//! [`TokenMap`] sits between the object model and the
//! [`cecli_metadata::MetadataBuilder`] during assembly emission. Every encoded
//! signature blob needs `TypeDefOrRef` coded cells; every IL instruction needs
//! tokens. This module guarantees that:
//!
//! * identical external types collapse into a single `TypeRef` row,
//! * identical instantiated shapes collapse into a single `TypeSpec` row,
//! * identical member references collapse into a single `MemberRef` row,
//! * generic method instantiations get one `MethodSpec` row each,
//! * `Def` handles always map to the table rid their arena position yields
//!   (arena order == table row order), whether or not the owning emitter has
//!   reached that row yet,
//! * all buffered rows drain deterministically (first-encounter order) via
//!   [`TokenMap::into_parts`].
//!
//! # Borrowing shape
//!
//! The dedup bookkeeping lives behind a `RefCell` so that a shared
//! [`TokenMap::encoder`] view can implement [`SigContext`] (`&self`
//! receiver, as the frozen codec trait demands) while interleaving with the
//! other shared-borrow queries. Heap inserts (`#Strings`, `#Blob`, `#US`) are
//! deferred to [`TokenMap::into_parts`] wherever an `&self` path creates the
//! data; rid/cell values never depend on heap indexes, so callers see stable
//! tokens immediately.
//!
//! # Value-type classification deviation
//!
//! `Mono.Cecil` classifies external value types by resolving the referenced
//! assembly. That requires an `AssemblyResolver` at write time, which this
//! phase does not have. Instead [`TokenMap`] uses a documented heuristic:
//!
//! * `Def`: interfaces are classes; otherwise the base-type chain is walked
//!   until it reaches an external `System.ValueType`/`System.Enum`
//!   (value type) or anything else (class).
//! * `External`: well-known `System` value types (`Int32`, `Decimal`,
//!   `Guid`, ...) are marked `VALUETYPE`; everything else - including
//!   `System.ValueType` and `System.Enum` themselves - is marked `CLASS`.
//!   User-defined external structs are therefore misclassified as classes;
//!   resolving them properly is future work once the resolver is wired into
//!   the writer.

use std::collections::BTreeMap;
use std::sync::Arc;

use cecli_core::flags::TypeAttributes;
use cecli_core::io::ByteWriter;
use cecli_core::token::coded;
use cecli_core::{ElementType, Error, Result, TableIndex, Token};

use crate::model::signature::{write_method_signature, write_type_element, SigContext};
use crate::model::types::{
    ExternalType, FieldRef, LocalVariable, MethodRef, ScopeRef, TypeDesc, TypeId,
};
use crate::module_def::Module;
use cecli_metadata::MetadataBuilder;

// ---------------------------------------------------------------------------
// Buffered row records
// ---------------------------------------------------------------------------

/// One pending `TypeRef` row; cells in schema order
/// (`ResolutionScope`, name, namespace).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeRefRow {
    /// Encoded `ResolutionScope` cell (nil for moduleless scopes).
    pub scope_cell: u32,
    /// `#Strings` index of the namespace (0 when empty).
    pub namespace: u32,
    /// `#Strings` index of the name.
    pub name: u32,
}

/// One pending `TypeSpec` row together with the descriptor that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingTypeSpec {
    /// The full instantiated/composite type the blob encodes.
    pub ty: TypeDesc,
    /// Whether the shape's underlying definition is a value type
    /// (`GENERICINST` marker byte information).
    pub is_value: bool,
    /// `#Blob` index of the encoded signature element.
    pub blob: u32,
}

/// One pending `MemberRef` row; cells in schema order
/// (`MemberRefParent`, name, signature).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingMemberRef {
    /// Encoded `MemberRefParent` cell.
    pub parent_cell: u32,
    /// `#Strings` index of the member name.
    pub name: u32,
    /// `#Blob` index of the member signature.
    pub signature: u32,
}

/// One pending `MethodSpec` row; cells in schema order
/// (`MethodDefOrRef`, instantiation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodSpecRow {
    /// Encoded `MethodDefOrRef` cell pointing at the generic template.
    pub method_cell: u32,
    /// `#Blob` index of the `GENERICINST` instantiation blob.
    pub instantiation: u32,
}

/// Everything [`TokenMap`] buffered while encoding, ready to be turned into
/// table rows by the metadata emitter in deterministic first-encounter order.
///
/// Rid numbering (assumed by every cell handed out earlier):
/// `type_refs[i]` has rid `i+1`, likewise `member_refs`, `method_specs`,
/// `type_specs` and `standalone_sigs`.
///
/// User strings were pushed straight into the `#US` heap during emission
/// (their offsets are return values), so nothing pends for them.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingRows {
    pub type_refs: Vec<TypeRefRow>,
    pub type_specs: Vec<PendingTypeSpec>,
    pub member_refs: Vec<PendingMemberRef>,
    pub method_specs: Vec<MethodSpecRow>,
    /// `#Blob` indexes for `StandAloneSig` rows; rid = position + 1.
    pub standalone_sigs: Vec<u32>,
}

// ---------------------------------------------------------------------------
// Dedup keys (sortable)
// ---------------------------------------------------------------------------

/// Dedup key for one `TypeRef` row: resolved scope cell plus the names.
/// Nested externals allocate one row per chain link, so the parent link is
/// fully captured by its scope cell.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TypeRefKey {
    scope_cell: u32,
    namespace: String,
    name: String,
}

/// Dedup key for a `MemberRef`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MemberRefKey {
    parent_cell: u32,
    name: String,
    signature: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

/// Mutable bookkeeping; behind a `RefCell` in [`TokenMap`] so the shared
/// [`SigContext`] view can drive it.
#[derive(Debug, Default)]
struct State {
    type_rows: Vec<u32>,
    field_rows: Vec<u32>,
    method_rows: Vec<u32>,
    property_rows: Vec<u32>,
    event_rows: Vec<u32>,
    generic_param_rows: Vec<u32>,

    type_ref_ids: BTreeMap<TypeRefKey, u32>,
    trefs: Vec<(u32, String, String)>, // (scope_cell, namespace, name)

    type_spec_ids: BTreeMap<Vec<u8>, u32>,
    tspecs: Vec<(TypeDesc, bool, Vec<u8>)>, // (ty, is_value, blob bytes)

    member_ref_ids: BTreeMap<MemberRefKey, u32>,
    mrefs: Vec<(u32, String, Vec<u8>)>, // (parent_cell, name, sig bytes)

    method_spec_ids: BTreeMap<(u32, Vec<u8>), u32>,
    mspecs: Vec<(u32, Vec<u8>)>, // (method_cell, instantiation bytes)

    standalone_ids: BTreeMap<Vec<u8>, u32>,
    ssigs: Vec<Vec<u8>>,

    /// Fast path for subtree hoisting: `Arc` allocation -> interned rid.
    /// Without it the second reference to a shared subtree would re-encode
    /// the entire subtree just to hit the blob-bytes dedup inside
    /// `intern_type_spec` — and that re-encode recursively re-hoists, which
    /// is exponential on doubling DAGs. The value pins the `Arc` so the
    /// pointer key stays valid. Pure accelerator: blob dedup remains the
    /// correctness-level identity for structurally equal distinct
    /// allocations.
    hoist_ids: std::collections::HashMap<usize, (std::sync::Arc<TypeDesc>, u32)>,
}

/// Whether a child element is worth hoisting to its own `TypeSpec` row.
/// Composite shapes benefit (their subtree may be shared or large); leaves
/// would add a row per reference for nothing. `FnPtr` stays inline too —
/// its payload is a method signature, not a type subtree, and hoisting
/// would change calli/local-sig blob shapes that the SAS pass-through
/// compares by bytes.
fn is_hoistable(e: &TypeDesc) -> bool {
    matches!(
        e,
        TypeDesc::SzArray(_)
            | TypeDesc::Array { .. }
            | TypeDesc::Ptr(_)
            | TypeDesc::ByRef(_)
            | TypeDesc::Pinned(_)
            | TypeDesc::GenericInstance { .. }
            | TypeDesc::CMod { .. }
    )
}

// ---------------------------------------------------------------------------
// TokenMap
// ---------------------------------------------------------------------------

/// Write-side allocator for `TypeRef` / `TypeSpec` / `MemberRef` /
/// `MethodSpec` / `StandAloneSig` rows plus the `#US` heap, with
/// deterministic deduplication. See the [module docs](self).
pub struct TokenMap<'b> {
    builder: &'b mut MetadataBuilder,
    state: std::cell::RefCell<State>,
}

impl<'b> TokenMap<'b> {
    /// Wraps `builder`; buffered rows drain back through
    /// [`TokenMap::into_parts`].
    pub fn new(builder: &'b mut MetadataBuilder) -> Self {
        TokenMap { builder, state: std::cell::RefCell::new(State::default()) }
    }

    /// Direct access for the metadata emitter to add its own rows
    /// (`TypeDef`, `Field`, `MethodDef`, ...) between token queries.
    pub fn builder(&mut self) -> &mut MetadataBuilder {
        self.builder
    }

    /// Creates a shared [`SigContext`] view bound to `m` for signature
    /// encoding (`model::signature::write_*` calls). The view may be held
    /// across other shared-borrow queries such as
    /// [`TokenMap::method_ref`]; only [`TokenMap::user_string`],
    /// the `register_*` family, [`TokenMap::builder`] and
    /// [`TokenMap::into_parts`] need exclusive access.
    pub fn encoder<'s, 'm>(&'s self, m: &'m Module) -> SigEncoder<'m, 's, 'b> {
        SigEncoder { tm: self, m }
    }

    // -- registration ------------------------------------------------------

    /// Records that arena type `idx` was emitted as the next `TypeDef` row;
    /// returns its 1-based rid. Keeps the `Def` <-> rid mapping stable.
    pub fn register_type_row(&mut self, idx: usize) -> u32 {
        self.register_row(idx, |s| &mut s.type_rows)
    }

    /// See [`TokenMap::register_type_row`] (Field table).
    pub fn register_field_row(&mut self, idx: usize) -> u32 {
        self.register_row(idx, |s| &mut s.field_rows)
    }

    /// See [`TokenMap::register_type_row`] (MethodDef table).
    pub fn register_method_row(&mut self, idx: usize) -> u32 {
        self.register_row(idx, |s| &mut s.method_rows)
    }

    /// See [`TokenMap::register_type_row`] (Property table).
    pub fn register_property_row(&mut self, idx: usize) -> u32 {
        self.register_row(idx, |s| &mut s.property_rows)
    }

    /// See [`TokenMap::register_type_row`] (Event table).
    pub fn register_event_row(&mut self, idx: usize) -> u32 {
        self.register_row(idx, |s| &mut s.event_rows)
    }

    /// See [`TokenMap::register_type_row`] (GenericParam table).
    pub fn register_generic_param_row(&mut self, idx: usize) -> u32 {
        self.register_row(idx, |s| &mut s.generic_param_rows)
    }

    fn register_row(&mut self, idx: usize, pick: impl FnOnce(&mut State) -> &mut Vec<u32>) -> u32 {
        let rid = idx + 1;
        let mut guard = self.state.borrow_mut();
        let rows = pick(&mut guard);
        if rows.len() <= idx {
            rows.resize(idx + 1, 0);
        }
        rows[idx] = rid as u32;
        rid as u32
    }

    fn rid_of(rows: &[u32], idx: u32) -> u32 {
        rows.get(idx as usize).copied().filter(|r| *r != 0).unwrap_or(idx + 1) // arena order == table row order fallback
    }

    // -- type cells --------------------------------------------------------

    /// Returns the encoded `TypeDefOrRef` cell for any type shape that maps
    /// onto one of the three participating tables:
    ///
    /// * `Def` -> `TypeDef` (rid from [`TokenMap::register_type_row`],
    ///   falling back to arena position + 1),
    /// * `External` (with nesting chain) -> `TypeRef`,
    /// * everything else -> `TypeSpec`.
    ///
    /// Every non-table shape is emitted as a `TypeSpec` row whose signature is
    /// the type's own encoding — this mirrors Mono.Cecil's
    /// `MetadataBuilder.GetToken`, which routes any `TypeSpecification`
    /// (generic instances, generic variables, `SzArray`/`Array`, `Ptr`,
    /// `ByRef`, `FnPtr`, `CMod`, ...) through a fresh `TypeSpec` row whenever
    /// a bare coded token is needed (IL operands such as `constrained. !!T`,
    /// `box !0`, `sizeof int[]`, catch-clause types, ...).
    pub fn tdor_cell(&self, ty: &TypeDesc, m: &Module) -> Result<u32> {
        match ty {
            TypeDesc::Def(id) => Ok(Self::rid_of(&self.state.borrow().type_rows, id.0) << 2),
            TypeDesc::External(_) => Ok((self.intern_external(ty, m)? << 2) | 1),
            ty => Ok((self.intern_type_spec(ty, m)? << 2) | 2),
        }
    }

    /// Convenience wrapper: [`TokenMap::tdor_cell`] as a full token.
    pub fn type_token(&self, ty: &TypeDesc, m: &Module) -> Result<Token> {
        let cell = self.tdor_cell(ty, m)?;
        let table = match cell & 3 {
            0 => TableIndex::TypeDef,
            1 => TableIndex::TypeRef,
            _ => TableIndex::TypeSpec,
        };
        Ok(Token::new(table, cell >> 2))
    }

    /// Interns the whole nesting chain of an external type and returns the
    /// rid of its innermost `TypeRef` row.
    fn intern_external(&self, ty: &TypeDesc, m: &Module) -> Result<u32> {
        let ExternalType { namespace, name, nesting, scope } = match ty {
            TypeDesc::External(e) => e.as_ref(),
            _ => return Err(Error::argument("internal error: not an external type")),
        };
        let mut scope_cell = scope_cell(scope, m)?;
        let mut levels: Vec<(String, String)> =
            nesting.iter().map(|p| (p.namespace.clone(), p.name.clone())).collect();
        levels.push((namespace.clone(), name.clone()));
        let mut rid = 0;
        // Chain runs outermost-first; each level's ResolutionScope is the
        // previous level's TypeRef (ECMA-335 II 22.32).
        for (ns, nm) in levels {
            let key = TypeRefKey { scope_cell, namespace: ns, name: nm };
            let hit = {
                let st = self.state.borrow();
                st.type_ref_ids.get(&key).copied()
            };
            rid = if let Some(r) = hit {
                r
            } else {
                let mut st = self.state.borrow_mut();
                let r = st.trefs.len() as u32 + 1;
                st.trefs.push((scope_cell, key.namespace.clone(), key.name.clone()));
                st.type_ref_ids.insert(key, r);
                r
            };
            scope_cell = (rid << 2) | 3; // ResolutionScope tag: TypeRef
        }
        Ok(rid)
    }

    /// Interns a composite type as a `TypeSpec` row and returns its rid.
    ///
    /// Children of composite shapes are hoisted recursively (via
    /// [`SigContext::hoist_element`]), so this re-enters itself down the
    /// tree: recursion depth equals tree depth (read trees are depth-bounded
    /// by the signature decoder; user-built deep trees recurse the same way
    /// inline encoding always has), and the row count is bounded by the
    /// number of distinct composite subtrees.
    fn intern_type_spec(&self, ty: &TypeDesc, m: &Module) -> Result<u32> {
        let is_value = match ty {
            TypeDesc::GenericInstance { definition, .. } => self.is_value_type(definition, m)?,
            _ => false,
        };
        let mut w = ByteWriter::new();
        write_type_element(ty, &mut w, &SigBridge { tm: self, m })?;
        let blob = w.into_vec();
        let st = self.state.borrow();
        if let Some(&rid) = st.type_spec_ids.get(&blob) {
            return Ok(rid);
        }
        drop(st);
        let mut st = self.state.borrow_mut();
        let rid = st.tspecs.len() as u32 + 1;
        st.tspecs.push((ty.clone(), is_value, blob.clone()));
        st.type_spec_ids.insert(blob, rid);
        Ok(rid)
    }

    /// Hoists a composite child element to its own `TypeSpec` row so shared
    /// subtrees encode once and the parent references them by cell (the
    /// write-side counterpart of Arc sharing; see
    /// [`SigContext::hoist_element`]). Leaf shapes stay inline — interning
    /// those would add rows without saving any expansion.
    ///
    /// The pointer cache is load-bearing, not just an accelerator: blob
    /// dedup checks happen after a full encode, so without it the second
    /// reference to a shared subtree re-encodes it (recursively re-hoisting
    /// its children), which is exponential on DAG-shaped trees.
    fn hoist_element(&self, e: &Arc<TypeDesc>, m: &Module) -> Result<Option<u32>> {
        if !is_hoistable(e) {
            return Ok(None);
        }
        let key = Arc::as_ptr(e) as usize;
        if let Some(&(_, rid)) = self.state.borrow().hoist_ids.get(&key) {
            return Ok(Some((rid << 2) | 2)); // TypeSpec tag in TypeDefOrRef
        }
        let rid = self.intern_type_spec(e, m)?;
        self.state.borrow_mut().hoist_ids.insert(key, (e.clone(), rid));
        Ok(Some((rid << 2) | 2))
    }

    // -- members -----------------------------------------------------------

    /// Resolves a method reference to its token:
    ///
    /// * `Def` -> `MethodDef` token (registration-aware),
    /// * `External` -> deduped `MemberRef` token,
    /// * `Spec` -> deduped `MethodSpec` token over the resolved template.
    pub fn method_ref(&self, r: &MethodRef, m: &Module) -> Result<Token> {
        match r {
            MethodRef::Def(id) => Ok(Token::new(
                TableIndex::MethodDef,
                Self::rid_of(&self.state.borrow().method_rows, id.0),
            )),
            MethodRef::External(ext) => {
                let parent_cell = self.member_parent_cell_tm(&ext.parent, m)?;
                let sig = write_method_signature(&ext.signature, &SigBridge { tm: self, m })?;
                let key =
                    MemberRefKey { parent_cell, name: ext.name.clone(), signature: sig.clone() };
                let st = self.state.borrow();
                if let Some(&rid) = st.member_ref_ids.get(&key) {
                    return Ok(Token::new(TableIndex::MemberRef, rid));
                }
                drop(st);
                let mut st = self.state.borrow_mut();
                let rid = st.mrefs.len() as u32 + 1;
                st.mrefs.push((parent_cell, ext.name.clone(), sig));
                st.member_ref_ids.insert(key, rid);
                Ok(Token::new(TableIndex::MemberRef, rid))
            }
            MethodRef::Spec { method, arguments } => {
                let template = self.method_ref(method, m)?;
                let tag = match template.table() {
                    TableIndex::MethodDef => 0u32,
                    TableIndex::MemberRef => 1,
                    t => return Err(Error::argument(format!("bad MethodSpec template {t:?}"))),
                };
                let method_cell = (template.rid() << 1) | tag;
                // Instantiation blob: GENERICINST + arg count + arguments.
                let mut w = ByteWriter::new();
                w.u8(0x0A); // ELEMENT_TYPE_GENERICINST (calling-convention slot)
                w.compressed_u32(arguments.len() as u32);
                let bridge = SigBridge { tm: self, m };
                for arg in arguments {
                    write_type_element(arg, &mut w, &bridge)?;
                }
                let inst = w.into_vec();
                let st = self.state.borrow();
                if let Some(&rid) = st.method_spec_ids.get(&(method_cell, inst.clone())) {
                    return Ok(Token::new(TableIndex::MethodSpec, rid));
                }
                drop(st);
                let mut st = self.state.borrow_mut();
                let rid = st.mspecs.len() as u32 + 1;
                st.mspecs.push((method_cell, inst.clone()));
                st.method_spec_ids.insert((method_cell, inst), rid);
                Ok(Token::new(TableIndex::MethodSpec, rid))
            }
        }
    }

    /// Resolves a field reference to its token: `Def` -> `Field` token,
    /// `External` -> deduped `MemberRef` token.
    pub fn field_ref(&self, r: &FieldRef, m: &Module) -> Result<Token> {
        match r {
            FieldRef::Def(id) => Ok(Token::new(
                TableIndex::Field,
                Self::rid_of(&self.state.borrow().field_rows, id.0),
            )),
            FieldRef::External(ext) => {
                let parent_cell = self.member_parent_cell_tm(&ext.parent, m)?;
                let mut w = ByteWriter::new();
                w.u8(0x06); // FIELD calling convention
                write_type_element(&ext.signature.0, &mut w, &SigBridge { tm: self, m })?;
                let sig = w.into_vec();
                let key =
                    MemberRefKey { parent_cell, name: ext.name.clone(), signature: sig.clone() };
                let st = self.state.borrow();
                if let Some(&rid) = st.member_ref_ids.get(&key) {
                    return Ok(Token::new(TableIndex::MemberRef, rid));
                }
                drop(st);
                let mut st = self.state.borrow_mut();
                let rid = st.mrefs.len() as u32 + 1;
                st.mrefs.push((parent_cell, ext.name.clone(), sig));
                st.member_ref_ids.insert(key, rid);
                Ok(Token::new(TableIndex::MemberRef, rid))
            }
        }
    }

    // -- user strings & stand-alone sigs ------------------------------------

    /// Inserts `s` into the `#US` heap and returns its byte offset.
    /// Duplicates fold to the same offset.
    pub fn user_string(&mut self, s: &str) -> u32 {
        self.builder.insert_user_string(s)
    }

    /// Returns the `StandAloneSig` token for a body's local slots, encoding
    /// and deduping the local variable signature blob. An empty slice yields
    /// [`Token::NIL`] (tiny bodies carry no local signature).
    pub fn local_var_sig_token(&self, locals: &[LocalVariable], m: &Module) -> Result<Token> {
        if locals.is_empty() {
            return Ok(Token::NIL);
        }
        let mut w = ByteWriter::new();
        w.u8(0x07); // LOCAL_SIG
        w.compressed_u32(locals.len() as u32);
        let bridge = SigBridge { tm: self, m };
        for var in locals {
            if var.pinned {
                w.u8(ElementType::Pinned as u8);
            }
            write_type_element(&var.ty, &mut w, &bridge)?;
        }
        let blob = w.into_vec();
        let st = self.state.borrow();
        if let Some(&rid) = st.standalone_ids.get(&blob) {
            return Ok(Token::new(TableIndex::StandAloneSig, rid));
        }
        drop(st);
        let mut st = self.state.borrow_mut();
        let rid = st.ssigs.len() as u32 + 1;
        st.ssigs.push(blob.clone());
        st.standalone_ids.insert(blob, rid);
        Ok(Token::new(TableIndex::StandAloneSig, rid))
    }

    /// Returns the `StandAloneSig` token for a raw signature blob (e.g. a
    /// `calli` signature captured at read time), deduplicating byte-identical
    /// blobs into a single pending row. The row drains through
    /// [`PendingRows::standalone_sigs`] like the local-variable signatures.
    pub fn stand_alone_sig_blob(&mut self, blob: &[u8]) -> Token {
        let mut st = self.state.borrow_mut();
        if let Some(&rid) = st.standalone_ids.get(blob) {
            return Token::new(TableIndex::StandAloneSig, rid);
        }
        let rid = st.ssigs.len() as u32 + 1;
        st.ssigs.push(blob.to_vec());
        st.standalone_ids.insert(blob.to_vec(), rid);
        Token::new(TableIndex::StandAloneSig, rid)
    }

    // -- classification ------------------------------------------------------

    /// Returns whether `ty` must be written with the `VALUETYPE` marker.
    /// See the module-level deviation notes for the heuristic used.
    pub fn is_value_type(&self, ty: &TypeDesc, m: &Module) -> Result<bool> {
        match ty {
            TypeDesc::Def(id) => Ok(def_is_value_type(m, *id)),
            TypeDesc::External(e) => Ok(external_is_value_type(e)),
            TypeDesc::GenericInstance { definition, .. } => self.is_value_type(definition, m),
            _ => {
                Err(Error::argument(format!("type shape {ty:?} carries no CLASS/VALUETYPE marker")))
            }
        }
    }

    // -- drain ---------------------------------------------------------------

    /// Materializes every buffered row (inserting the deferred heap entries
    /// in first-encounter order) and hands the builder back to the emitter
    /// together with the rows to `add_row` in deterministic order.
    pub fn into_parts(self) -> (&'b mut MetadataBuilder, PendingRows) {
        let st = self.state.into_inner();

        let type_refs = st
            .trefs
            .iter()
            .map(|(scope_cell, ns, name)| TypeRefRow {
                scope_cell: *scope_cell,
                namespace: self.builder.insert_string(ns),
                name: self.builder.insert_string(name),
            })
            .collect();

        let type_specs = st
            .tspecs
            .iter()
            .map(|(ty, is_value, blob)| PendingTypeSpec {
                ty: ty.clone(),
                is_value: *is_value,
                blob: self.builder.insert_blob(blob),
            })
            .collect();

        let member_refs = st
            .mrefs
            .iter()
            .map(|(parent_cell, name, sig)| PendingMemberRef {
                parent_cell: *parent_cell,
                name: self.builder.insert_string(name),
                signature: self.builder.insert_blob(sig),
            })
            .collect();

        let method_specs = st
            .mspecs
            .iter()
            .map(|(method_cell, inst)| MethodSpecRow {
                method_cell: *method_cell,
                instantiation: self.builder.insert_blob(inst),
            })
            .collect();

        let standalone_sigs = st.ssigs.iter().map(|blob| self.builder.insert_blob(blob)).collect();

        (
            self.builder,
            PendingRows { type_refs, type_specs, member_refs, method_specs, standalone_sigs },
        )
    }
}

impl std::fmt::Debug for TokenMap<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.state.borrow();
        f.debug_struct("TokenMap")
            .field("type_refs", &st.trefs.len())
            .field("type_specs", &st.tspecs.len())
            .field("member_refs", &st.mrefs.len())
            .field("method_specs", &st.mspecs.len())
            .field("standalone_sigs", &st.ssigs.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// SigContext bridge
// ---------------------------------------------------------------------------

/// Shared-borrow [`SigContext`] view over a [`TokenMap`] plus the module
/// being emitted. Produced by [`TokenMap::encoder`].
pub struct SigEncoder<'m, 'x, 'b> {
    tm: &'x TokenMap<'b>,
    m: &'m Module,
}

impl<'m, 'x, 'b> SigContext for SigEncoder<'m, 'x, 'b> {
    fn tdor_cell(&self, ty: &TypeDesc) -> Result<u32> {
        self.tm.tdor_cell(ty, self.m)
    }

    fn is_value_type(&self, ty: &TypeDesc) -> Result<bool> {
        self.tm.is_value_type(ty, self.m)
    }

    fn hoist_element(&self, e: &Arc<TypeDesc>) -> Result<Option<u32>> {
        self.tm.hoist_element(e, self.m)
    }
}

/// Private bridge used inside allocation paths where a fresh shared view is
/// needed while `&mut self`-free encoding runs.
struct SigBridge<'m, 'x, 't> {
    tm: &'x TokenMap<'t>,
    m: &'m Module,
}

impl<'m, 'x, 't> SigContext for SigBridge<'m, 'x, 't> {
    fn tdor_cell(&self, ty: &TypeDesc) -> Result<u32> {
        self.tm.tdor_cell(ty, self.m)
    }

    fn is_value_type(&self, ty: &TypeDesc) -> Result<bool> {
        self.tm.is_value_type(ty, self.m)
    }

    fn hoist_element(&self, e: &Arc<TypeDesc>) -> Result<Option<u32>> {
        self.tm.hoist_element(e, self.m)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encodes a `ResolutionScope` cell for a top-level external type.
fn scope_cell(scope: &ScopeRef, m: &Module) -> Result<u32> {
    match scope {
        ScopeRef::ThisModule => Ok(1 << 2), // Module row 1
        ScopeRef::OtherModule(name) => {
            let pos = m.module_refs.iter().position(|s| s == name).ok_or_else(|| {
                Error::argument(format!("module ref `{name}` missing from module.module_refs"))
            })?;
            Ok((((pos + 1) as u32) << 2) | 1)
        }
        ScopeRef::Assembly(anr) => {
            let pos = m.assembly_refs.iter().position(|a| a == anr).ok_or_else(|| {
                Error::argument(format!(
                    "assembly ref `{}` missing from module.assembly_refs",
                    anr.name
                ))
            })?;
            Ok((((pos + 1) as u32) << 2) | 2)
        }
        ScopeRef::Moduleless => Ok(0), // nil scope
    }
}

impl TokenMap<'_> {
    /// Encodes a `MemberRefParent` cell for any supported parent shape:
    /// `Def` -> `TypeDef` tag, `External` -> `TypeRef` tag,
    /// `GenericInstance` -> `TypeSpec` tag.
    fn member_parent_cell_tm(&self, ty: &TypeDesc, m: &Module) -> Result<u32> {
        // MEMBER_REF_PARENT spans five tables => three tag bits.
        let shift = coded::MEMBER_REF_PARENT.shift_bits();
        match ty {
            TypeDesc::Def(id) => Ok(Self::rid_of(&self.state.borrow().type_rows, id.0) << shift),
            TypeDesc::External(_) => Ok((self.intern_external(ty, m)? << shift) | 1),
            TypeDesc::GenericInstance { .. } => {
                Ok((self.intern_type_spec(ty, m)? << shift) | 4) // TypeSpec tag
            }
            _ => Err(Error::argument(format!("unsupported MemberRefParent shape {ty:?}"))),
        }
    }
}

/// Walks a definition's base-type chain to decide the `VALUETYPE` marker.
/// Interfaces are classes; the chain terminates positively only at external
/// `System.ValueType` / `System.Enum`.
fn def_is_value_type(m: &Module, id: TypeId) -> bool {
    let mut cur = id;
    let mut hops = 0usize;
    loop {
        hops += 1;
        if hops > m.types.len() + 1 {
            return false; // cyclic base chain: refuse to hang
        }
        let t = &m.types[cur.0 as usize];
        if t.attributes.contains(TypeAttributes::INTERFACE) {
            return false;
        }
        match &t.base_type {
            None => return false,
            Some(TypeDesc::External(base)) => {
                return base.namespace == "System"
                    && matches!(base.name.as_str(), "ValueType" | "Enum");
            }
            Some(TypeDesc::Def(next)) => cur = *next,
            Some(_) => return false,
        }
    }
}

/// Well-known `System` value types classified without assembly resolution.
const WELL_KNOWN_VALUE_TYPES: &[&str] = &[
    "Boolean",
    "Char",
    "SByte",
    "Byte",
    "Int16",
    "UInt16",
    "Int32",
    "UInt32",
    "Int64",
    "UInt64",
    "Single",
    "Double",
    "IntPtr",
    "UIntPtr",
    "TypedReference",
    "Decimal",
    "DateTime",
    "TimeSpan",
    "Guid",
    "ArgIterator",
    "RuntimeArgumentHandle",
    "RuntimeFieldHandle",
    "RuntimeMethodHandle",
    "RuntimeTypeHandle",
];

/// Heuristic classifier for external types (documented deviation; see module
/// docs). `System.ValueType` and `System.Enum` are themselves classes.
fn external_is_value_type(et: &ExternalType) -> bool {
    et.namespace == "System"
        && et.name != "ValueType"
        && et.name != "Enum"
        && WELL_KNOWN_VALUE_TYPES.contains(&et.name.as_str())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::signature::parse_field_signature;
    use crate::model::types::{
        AssemblyNameReference, ExternalMethod, FieldSignature, MethodSignature, Version,
    };
    use std::cell::RefCell;
    use std::collections::HashMap;

    fn ver(major: u16, minor: u16, build: u16, revision: u16) -> Version {
        Version { major, minor, build, revision }
    }

    fn module_with_refs() -> Module {
        let mut m = Module::default();
        m.assembly_refs.push(AssemblyNameReference {
            version: ver(4, 0, 0, 0),
            ..AssemblyNameReference::new("mscorlib")
        });
        m.module_refs.push("native.dll".to_string());
        m
    }

    fn ext(ns: &str, name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: ns.to_string(),
            name: name.to_string(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(assembly_ref()),
        }))
    }

    fn assembly_ref() -> AssemblyNameReference {
        AssemblyNameReference { version: ver(4, 0, 0, 0), ..AssemblyNameReference::new("mscorlib") }
    }

    #[test]
    fn identical_externals_dedup_to_one_typeref_row() {
        let m = module_with_refs();
        let mut b = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::new(&mut b);

        let c1 = tm.tdor_cell(&ext("System.Collections", "List"), &m).unwrap();
        let c2 = tm.tdor_cell(&ext("System.Collections", "List"), &m).unwrap();
        assert_eq!(c1, c2);
        let (_, pending) = tm.into_parts();
        assert_eq!(pending.type_refs.len(), 1, "identical externals share one row");
        // ResolutionScope tag = AssemblyRef (2), rid 1.
        assert_eq!(pending.type_refs[0].scope_cell, (1 << 2) | 2);
        assert_eq!(pending.type_specs.len(), 0);
    }

    #[test]
    fn different_scopes_produce_distinct_rows() {
        let mut m = module_with_refs();
        m.assembly_refs.push(AssemblyNameReference {
            version: ver(8, 0, 0, 0),
            ..AssemblyNameReference::new("System.Runtime")
        });
        let mut b = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::new(&mut b);

        let a = TypeDesc::External(Box::new(ExternalType {
            namespace: "System".into(),
            name: "String".into(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(m.assembly_refs[1].clone()),
        }));
        let c2 = tm.tdor_cell(&ext("System", "String"), &m).unwrap();
        let c1 = tm.tdor_cell(&a, &m).unwrap();
        assert_ne!(c1, c2);
        let (_, pending) = tm.into_parts();
        assert_eq!(pending.type_refs.len(), 2);
    }

    #[test]
    fn nested_external_chain_allocates_one_row_per_link_and_dedups() {
        let m = module_with_refs();
        let mut b = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::new(&mut b);

        let make = || {
            TypeDesc::External(Box::new(ExternalType {
                namespace: String::new(),
                name: "Inner".into(),
                nesting: vec![Box::new(ExternalType {
                    namespace: "NS".into(),
                    name: "Outer".into(),
                    nesting: Vec::new(),
                    scope: ScopeRef::Assembly(assembly_ref()),
                })],
                scope: ScopeRef::Assembly(assembly_ref()),
            }))
        };
        let c1 = tm.tdor_cell(&make(), &m).unwrap();
        let c2 = tm.tdor_cell(&make(), &m).unwrap();
        assert_eq!(c1, c2, "repeated nested reference dedups");

        let (_, pending) = tm.into_parts();
        assert_eq!(pending.type_refs.len(), 2, "outer + inner links");
        // Inner row's scope is the outer TypeRef: tag 3, rid 1.
        assert_eq!(pending.type_refs[1].scope_cell, (1 << 2) | 3);
        assert_eq!(c1, ((2 << 2) | 1)); // innermost is TypeRef rid 2
    }

    /// Recording context: forwards to `TokenMap` while capturing
    /// cell -> TypeDesc, then replays for parsing (acceptance roundtrip).
    struct RoundtripCtx<'m, 'x, 't> {
        tm: &'x TokenMap<'t>,
        m: &'m Module,
        seen: RefCell<HashMap<u32, (bool, TypeDesc)>>,
    }

    impl<'m, 'x, 't> RoundtripCtx<'m, 'x, 't> {
        fn record(&self, value_type: bool, cell: u32, ty: &TypeDesc) -> u32 {
            let c = self.tm.tdor_cell(ty, self.m).unwrap();
            self.seen.borrow_mut().insert(c >> 2, (value_type, ty.clone()));
            let _ = cell;
            c
        }
    }

    impl<'m, 'x, 't> SigContext for RoundtripCtx<'m, 'x, 't> {
        fn tdor_cell(&self, ty: &TypeDesc) -> Result<u32> {
            Ok(self.record(false, 0, ty))
        }
        fn is_value_type(&self, ty: &TypeDesc) -> Result<bool> {
            self.tm.is_value_type(ty, self.m)
        }
        fn tdor_type(&self, value_type: bool, cell: u32, _depth: u32) -> Result<TypeDesc> {
            let rid = cell >> 2;
            let (_, ty) = self
                .seen
                .borrow()
                .get(&rid)
                .cloned()
                .ok_or_else(|| Error::bad_image(format!("unrecorded cell rid {rid}")))?;
            let _ = value_type;
            Ok(ty)
        }
    }

    #[test]
    fn tdor_cells_roundtrip_through_signature_parser_external_only() {
        let m = module_with_refs();
        let mut b = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::new(&mut b);

        let list = ext("System.Collections.Generic", "List`1");
        let int32 = ext("System", "Int32");
        let foo = ext("Demo", "Foo");
        let generic = TypeDesc::GenericInstance {
            definition: std::sync::Arc::new(list.clone()),
            arguments: vec![std::sync::Arc::new(int32.clone())],
        };

        // Encode a field signature: 0x06 + List`1<Int32> + Foo.
        let ctx = RoundtripCtx { tm: &tm, m: &m, seen: RefCell::new(HashMap::new()) };
        // Pre-record every named ref so parse-time lookups cover each cell
        // appearing in the blobs (this order fixes the rid assignment).
        let _ = ctx.record(false, 0, &list);
        let _ = ctx.record(false, 0, &int32);
        let _ = ctx.record(false, 0, &generic);
        let _ = ctx.record(false, 0, &foo);

        // Field signatures are just the 0x06 prolog plus the type element
        // (no parameter-count byte, unlike method/property signatures).
        let mut w = ByteWriter::new();
        w.u8(0x06);
        write_type_element(&generic, &mut w, &ctx).unwrap();
        let blob = w.into_vec();

        let parsed = parse_field_signature(&blob, &ctx).unwrap();
        assert_eq!(parsed.0, generic, "generic instance roundtrips exactly");

        // Plain external element roundtrips through the element parser too.
        let mut fw = ByteWriter::new();
        write_type_element(&foo, &mut fw, &ctx).unwrap();
        let fblob = fw.into_vec();
        let (foo_back, consumed) =
            crate::model::signature::parse_type_element(&fblob, 0, &ctx, 0, false).unwrap();
        assert_eq!(foo_back, foo);
        assert_eq!(consumed, fblob.len());
    }

    #[test]
    fn def_registration_keeps_rids_stable() {
        let m = Module::default();
        let mut b = MetadataBuilder::new("v4.0.30319");
        let mut tm = TokenMap::new(&mut b);

        let id = TypeId(7);
        let ty = TypeDesc::Def(id);
        // Fallback (unregistered): arena order == table row order.
        assert_eq!(tm.tdor_cell(&ty, &m).unwrap(), (8 << 2));
        assert_eq!(tm.register_type_row(7), 8);
        assert_eq!(tm.tdor_cell(&ty, &m).unwrap(), (8 << 2));
    }

    #[test]
    fn method_def_member_ref_and_methodspec_tokens() {
        let m = module_with_refs();
        let mut b = MetadataBuilder::new("v4.0.30319");
        let mut tm = TokenMap::new(&mut b);

        // Def path honors registered rids.
        assert_eq!(tm.register_method_row(3), 4);
        let tok = tm.method_ref(&MethodRef::Def(crate::model::types::MethodId(3)), &m).unwrap();
        assert_eq!(tok, Token::new(TableIndex::MethodDef, 4));

        // External path: MemberRef with dedup.
        let em = ExternalMethod {
            parent: ext("System.Collections", "List"),
            name: "Add".into(),
            signature: MethodSignature::default(),
        };
        let t1 = tm.method_ref(&MethodRef::External(em.clone()), &m).unwrap();
        let t2 = tm.method_ref(&MethodRef::External(em), &m).unwrap();
        assert_eq!(t1, t2);
        assert_eq!(t1.table(), TableIndex::MemberRef);

        // Spec path: MethodSpec over the MemberRef template.
        let spec = MethodRef::Spec {
            method: Box::new(MethodRef::External(ExternalMethod {
                parent: ext("System.Linq", "Enumerable"),
                name: "Where".into(),
                signature: MethodSignature::default(),
            })),
            arguments: vec![ext("System", "Int32")],
        };
        let s1 = tm.method_ref(&spec, &m).unwrap();
        let s2 = tm.method_ref(&spec, &m).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.table(), TableIndex::MethodSpec);

        let (_, pending) = tm.into_parts();
        assert_eq!(pending.member_refs.len(), 2);
        // MemberRefParent spans five tables => three tag bits; TypeRef tag 1.
        assert_eq!(pending.member_refs[0].parent_cell, (1 << 3) | 1);
        assert_eq!(pending.method_specs.len(), 1);
        // Template cell = (memberref rid << 1) | 1; Enumerable.Where is the
        // second member ref (rid 2).
        assert_eq!(pending.method_specs[0].method_cell, (2 << 1) | 1);
    }

    #[test]
    fn field_refs_dedup_and_defs_map_to_field_table() {
        let m = module_with_refs();
        let mut b = MetadataBuilder::new("v4.0.30319");
        let mut tm = TokenMap::new(&mut b);

        let fe = FieldRef::External(crate::model::types::ExternalField {
            parent: ext("System", "Console"),
            name: "Out".into(),
            signature: FieldSignature(ext("System.IO", "TextWriter")),
        });
        let t1 = tm.field_ref(&fe, &m).unwrap();
        let t2 = tm.field_ref(&fe, &m).unwrap();
        assert_eq!(t1, t2);
        assert_eq!(t1.table(), TableIndex::MemberRef);

        assert_eq!(tm.register_field_row(0), 1);
        let d = tm.field_ref(&FieldRef::Def(crate::model::types::FieldId(0)), &m).unwrap();
        assert_eq!(d.table(), TableIndex::Field);

        let (_, pending) = tm.into_parts();
        assert_eq!(pending.member_refs.len(), 1);
    }

    #[test]
    fn user_strings_fold_to_same_offset() {
        let mut b = MetadataBuilder::new("v4.0.30319");
        let mut tm = TokenMap::new(&mut b);
        let o1 = tm.user_string("hello");
        let o2 = tm.user_string("hello");
        let o3 = tm.user_string("world");
        assert_eq!(o1, o2);
        assert_ne!(o1, o3);
    }

    #[test]
    fn local_var_sig_empty_is_nil_and_nonempty_dedups() {
        let m = module_with_refs();
        let mut b = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::new(&mut b);

        assert_eq!(tm.local_var_sig_token(&[], &m).unwrap(), Token::NIL);

        let vars = vec![LocalVariable { index: 0, ty: ext("System", "Int32"), pinned: false }];
        let t1 = tm.local_var_sig_token(&vars, &m).unwrap();
        let t2 = tm.local_var_sig_token(&vars, &m).unwrap();
        assert_eq!(t1, t2);
        assert_eq!(t1.table(), TableIndex::StandAloneSig);
        let (_, pending) = tm.into_parts();
        assert_eq!(pending.standalone_sigs.len(), 1);
    }

    #[test]
    fn value_type_classification_rules() {
        let mut m = Module::default();
        // struct Derived : System.ValueType -> value type
        m.types.push(crate::model::types::TypeDefinition {
            base_type: Some(ext("System", "ValueType")),
            ..Default::default()
        });
        // enum Color : System.Enum -> value type
        m.types.push(crate::model::types::TypeDefinition {
            base_type: Some(ext("System", "Enum")),
            ..Default::default()
        });
        // class Node : object -> class
        m.types.push(crate::model::types::TypeDefinition {
            base_type: Some(ext("System", "Object")),
            ..Default::default()
        });
        // interface IFoo -> class
        m.types.push(crate::model::types::TypeDefinition {
            attributes: TypeAttributes::INTERFACE,
            ..Default::default()
        });
        // struct Wrapper : Derived (transitive)
        m.types.push(crate::model::types::TypeDefinition {
            base_type: Some(TypeDesc::Def(TypeId(0))),
            ..Default::default()
        });

        let mut b = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::new(&mut b);

        assert!(tm.is_value_type(&TypeDesc::Def(TypeId(0)), &m).unwrap());
        assert!(tm.is_value_type(&TypeDesc::Def(TypeId(1)), &m).unwrap());
        assert!(!tm.is_value_type(&TypeDesc::Def(TypeId(2)), &m).unwrap());
        assert!(!tm.is_value_type(&TypeDesc::Def(TypeId(3)), &m).unwrap());
        assert!(tm.is_value_type(&TypeDesc::Def(TypeId(4)), &m).unwrap());

        assert!(tm.is_value_type(&ext("System", "Int32"), &m).unwrap());
        assert!(!tm.is_value_type(&ext("System", "String"), &m).unwrap());
        assert!(!tm.is_value_type(&ext("System", "ValueType"), &m).unwrap());
        assert!(!tm.is_value_type(&ext("Example", "MyStruct"), &m).unwrap());
    }

    /// Builds a doubling shared DAG: level K wraps level K-1 twice as
    /// generic arguments, with the two argument Arcs sharing the previous
    /// level's children (the shape the reader produces for TypeSpec rows
    /// that reference one another). Fully expanded this is 2^levels nodes;
    /// the per-allocation encoding cache keeps write time linear.
    fn build_dag_tree(levels: u32) -> TypeDesc {
        let mut t = ext("System", "Int32");
        for _ in 0..levels {
            let shared = Arc::new(t);
            t = TypeDesc::GenericInstance {
                definition: Arc::new(ext("System.Collections", "Tuple")),
                arguments: vec![shared.clone(), shared],
            };
        }
        t
    }

    #[test]
    fn write_dag_encodes_linearly_via_elem_cache() {
        let m = module_with_refs();
        let mut b = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::new(&mut b);

        // ~2^30 expanded nodes without hoisting (would effectively hang);
        // with subtree hoisting every level becomes one TypeSpec row and the
        // shared argument hits the pointer cache without re-encoding.
        let tree = build_dag_tree(30);
        let cell = tm.tdor_cell(&tree, &m).expect("30-level DAG encodes");
        let (_, pending) = tm.into_parts();
        // One row per level: each doubling level is one distinct composite
        // subtree, referenced by cell from its parent.
        assert_eq!(pending.type_specs.len(), 30);
        assert_eq!(cell >> 2, 30, "outermost level interns last (rid 30)");
    }

    /// The cache must be invisible on the wire: encoding the same shared DAG
    /// through two fresh token maps (each starting with an empty hoist
    /// cache) yields identical row sets and blobs — hoisting is
    /// deterministic.
    #[test]
    fn elem_cache_preserves_bytes() {
        let m = module_with_refs();
        let tree = build_dag_tree(3);

        let mut b = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::new(&mut b);
        let cell = tm.tdor_cell(&tree, &m).unwrap();
        let (_, pending) = tm.into_parts();

        let mut b2 = MetadataBuilder::new("v4.0.30319");
        let tm2 = TokenMap::new(&mut b2);
        let cell2 = tm2.tdor_cell(&tree, &m).unwrap();
        let (_, pending2) = tm2.into_parts();

        // Blob indexes are assigned in first-encounter order during drain,
        // so row-for-row equality implies identical wire bytes.
        assert_eq!(
            pending.type_specs, pending2.type_specs,
            "two fresh maps produce identical rows"
        );
        assert_eq!(cell, cell2);
    }

    /// Repeated interning of the same shared tree must hit the pointer
    /// cache rather than re-walking the expanded view, and must still
    /// deduplicate to one row per distinct composite subtree.
    #[test]
    fn repeated_intern_of_shared_tree_dedups() {
        let m = module_with_refs();
        let mut b = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::new(&mut b);

        let tree = build_dag_tree(10);
        let c1 = tm.tdor_cell(&tree, &m).unwrap();
        let c2 = tm.tdor_cell(&tree, &m).unwrap();
        assert_eq!(c1, c2, "same tree dedups to one TypeSpec row");
        let (_, pending) = tm.into_parts();
        // 10 rows: one per doubling level; re-interning the root adds none.
        assert_eq!(pending.type_specs.len(), 10);
    }
}
