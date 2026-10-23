//! Write-side deduplication and token allocation (`Mono.Cecil` writer's
//! `TypeReferenceCounter` / `MemberReferenceCollector` analog).
//!
//! [`TokenMap`] sits between the object model and the
//! [`cecil_metadata::MetadataBuilder`] during assembly emission. Every encoded
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
//! receiver, as the codec trait requires) while interleaving with the
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
//! * `External`: preserve value-type identities observed in input signatures;
//!   otherwise consult the optional resolution-backed classifier. Without
//!   either, well-known `System` value types (`Int32`, `Decimal`, `Guid`, ...)
//!   are marked `VALUETYPE`; everything else - including
//!   `System.ValueType` and `System.Enum` themselves - is marked `CLASS`.
//!   Fresh external structs should supply a classifier or add their identity
//!   to `Module::external_value_types` when authoring a module.

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};
use std::sync::Arc;

use cecil_core::flags::TypeAttributes;
use cecil_core::io::ByteWriter;
use cecil_core::token::coded;
use cecil_core::{ElementType, Error, Result, TableIndex, Token};

use crate::model::signature::{put_method_signature, write_type_element, SigContext};

/// Resolution-backed classifier hook: decides the `CLASS`/`VALUETYPE` marker
/// of one external type; `Ok(None)` defers to the built-in heuristic.
pub type ExternalClassifier<'b> = Box<dyn FnMut(&ExternalType) -> Result<Option<bool>> + 'b>;
use crate::model::types::{
    AssemblyNameReference, ExternalType, FieldRef, LocalVariable, MethodRef, MethodSignature,
    ScopeRef, TypeDesc, TypeId,
};
use crate::module_def::Module;
use cecil_metadata::MetadataBuilder;

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
// Dedup indexes
// ---------------------------------------------------------------------------

/// Index borrowed keys against their single owned copy in the pending rows.
/// Hash collisions form chains of row ids and always compare the complete
/// key. Randomized hashing affects lookup only; row order stays deterministic.
#[derive(Debug, Default)]
struct DedupIndex {
    heads: HashMap<u64, u32>,
    next: Vec<u32>,
}

impl DedupIndex {
    fn hash(&self, key: impl Hash) -> u64 {
        self.heads.hasher().hash_one(key)
    }

    fn find(&self, hash: u64, mut matches: impl FnMut(usize) -> bool) -> Option<u32> {
        let mut rid = self.heads.get(&hash).copied().unwrap_or(0);
        while rid != 0 {
            let index = rid as usize - 1;
            if matches(index) {
                return Some(rid);
            }
            rid = self.next[index];
        }
        None
    }

    fn insert(&mut self, hash: u64) -> u32 {
        let rid = self.next.len() as u32 + 1;
        self.next.push(self.heads.insert(hash, rid).unwrap_or(0));
        rid
    }
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct EncodedElement {
    // Keep the node alive so its address cannot be reused by another allocation.
    _owner: Arc<TypeDesc>,
    bytes: Arc<[u8]>,
}

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

    type_ref_ids: DedupIndex,
    trefs: Vec<(u32, String, String)>, // (scope_cell, namespace, name)
    /// Shared external identities can reuse a row directly. Pin each Arc so
    /// pointer reuse and copy-on-write edits cannot alias an earlier identity.
    external_rows: HashMap<usize, (Arc<ExternalType>, u32)>,

    type_spec_ids: DedupIndex,
    tspecs: Vec<(TypeDesc, bool, Vec<u8>)>, // (ty, is_value, blob bytes)

    member_ref_ids: DedupIndex,
    mrefs: Vec<(u32, String, Vec<u8>)>, // (parent_cell, name, sig bytes)

    method_spec_ids: DedupIndex,
    mspecs: Vec<(u32, Vec<u8>)>, // (method_cell, instantiation bytes)

    standalone_ids: DedupIndex,
    ssigs: Vec<Vec<u8>>,

    /// Cached legal inline encodings. Pin the Arc so pointer keys cannot
    /// alias a later allocation. Output-size bounds live in the codec.
    element_blobs: HashMap<(u64, usize), EncodedElement>,
    /// Buffers are removed before invoking the codec or a classifier so nested
    /// signature encoding can borrow the token map normally.
    signature_buffers: Vec<ByteWriter>,
}

impl State {
    fn recycle_signature(&mut self, mut writer: ByteWriter) {
        writer.clear();
        self.signature_buffers.push(writer);
    }
}

/// Cache composite children; leaves are cheap to encode directly.
fn is_cacheable(e: &TypeDesc) -> bool {
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

/// The facade holds the source module immutable for the entire emission.
/// Index its repeated identity lookups without cloning the model or changing
/// the public TokenMap constructor's ability to work with different modules.
struct ModuleIndex<'m> {
    module: &'m Module,
    assembly_scopes: HashMap<&'m str, Vec<usize>>,
    module_scopes: HashMap<&'m str, u32>,
    external_values: HashMap<&'m str, Vec<&'m ExternalType>>,
}

impl<'m> ModuleIndex<'m> {
    fn new(module: &'m Module) -> Self {
        let mut assembly_scopes: HashMap<&str, Vec<usize>> = HashMap::new();
        for (i, reference) in module.assembly_refs.iter().enumerate() {
            assembly_scopes.entry(&reference.name).or_default().push(i);
        }
        let mut module_scopes = HashMap::new();
        for (i, name) in module.module_refs.iter().enumerate() {
            module_scopes.entry(name.as_str()).or_insert((((i + 1) as u32) << 2) | 1);
        }
        let mut external_values: HashMap<&str, Vec<&ExternalType>> = HashMap::new();
        for value in &module.external_value_types {
            external_values.entry(&value.name).or_default().push(value);
        }
        Self { module, assembly_scopes, module_scopes, external_values }
    }
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
    bound_module: Option<&'b Module>,
    module_index: Option<ModuleIndex<'b>>,
    /// Zero identifies the immutably bound module. Other views receive a
    /// fresh namespace so cached cells cannot survive changes to their scopes.
    next_cache_epoch: std::cell::Cell<u64>,
    /// Optional resolution-based classifier for EXTERNAL types (see
    /// [`TokenMap::set_external_classifier`]). `None` keeps the documented
    /// well-known-System heuristic.
    external_classifier: std::cell::RefCell<Option<ExternalClassifier<'b>>>,
}

impl<'b> TokenMap<'b> {
    /// Wraps `builder`; buffered rows drain back through
    /// [`TokenMap::into_parts`].
    pub fn new(builder: &'b mut MetadataBuilder) -> Self {
        TokenMap {
            builder,
            state: std::cell::RefCell::new(State::default()),
            bound_module: None,
            module_index: None,
            next_cache_epoch: std::cell::Cell::new(1),
            external_classifier: std::cell::RefCell::new(None),
        }
    }

    pub(crate) fn for_module(builder: &'b mut MetadataBuilder, m: &'b Module) -> Self {
        let mut map = Self::new(builder);
        map.bound_module = Some(m);
        // A bounded linear search is cheaper than constructing three indexes
        // for modules with only a handful of scope/value identities.
        if m.assembly_refs.len() > 8 || m.module_refs.len() > 8 || m.external_value_types.len() > 8
        {
            map.module_index = Some(ModuleIndex::new(m));
        }
        map
    }

    /// Installs a classifier consulted before the built-in heuristic when an
    /// EXTERNAL type needs a `CLASS`/`VALUETYPE` marker. Returning
    /// `Ok(Some(bool))` decides the marker; `Ok(None)` falls back to the
    /// heuristic and errors propagate. This is the write-side hook for
    /// [`crate::resolution::ResolutionEngine`]-backed classification
    /// (Cecil resolves external value types through the module's
    /// `MetadataResolver` while writing).
    pub fn set_external_classifier(&self, classifier: ExternalClassifier<'b>) {
        *self.external_classifier.borrow_mut() = Some(classifier);
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
        SigEncoder { tm: self, m, cache_epoch: self.cache_epoch(m) }
    }

    fn cache_epoch(&self, m: &Module) -> u64 {
        if self.bound_module.is_some_and(|bound| std::ptr::eq(bound, m)) {
            return 0;
        }
        let epoch = self.next_cache_epoch.get();
        self.next_cache_epoch.set(epoch.checked_add(1).expect("signature cache epoch overflow"));
        epoch
    }

    fn signature_bridge<'s, 'm>(&'s self, m: &'m Module) -> SigBridge<'m, 's, 'b> {
        SigBridge { tm: self, m, cache_epoch: self.cache_epoch(m) }
    }

    fn encode_signature(
        &self,
        encode: impl FnOnce(&mut ByteWriter) -> Result<()>,
    ) -> Result<ByteWriter> {
        let mut writer = self.state.borrow_mut().signature_buffers.pop().unwrap_or_default();
        if let Err(err) = encode(&mut writer) {
            self.state.borrow_mut().recycle_signature(writer);
            return Err(err);
        }
        Ok(writer)
    }

    pub(crate) fn method_signature_blob(
        &mut self,
        signature: &MethodSignature,
        m: &Module,
    ) -> Result<u32> {
        let writer = self
            .encode_signature(|w| put_method_signature(w, signature, &self.signature_bridge(m)))?;
        let index = self.builder.insert_blob(writer.as_slice());
        self.state.borrow_mut().recycle_signature(writer);
        Ok(index)
    }

    pub(crate) fn call_site_sig_token(
        &self,
        signature: &MethodSignature,
        m: &Module,
    ) -> Result<Token> {
        let writer = self
            .encode_signature(|w| put_method_signature(w, signature, &self.signature_bridge(m)))?;
        Ok(self.intern_standalone_writer(writer))
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
        let external = match ty {
            TypeDesc::External(e) => e,
            _ => return Err(Error::argument("internal error: not an external type")),
        };
        // The module borrow held by for_module keeps scope rows immutable.
        // Public TokenMap::new and calls with another module use full lookup.
        let shared_identity = self.bound_module.is_some_and(|bound| std::ptr::eq(bound, m));
        let key = Arc::as_ptr(external) as usize;
        if shared_identity {
            if let Some((_, rid)) = self.state.borrow().external_rows.get(&key) {
                return Ok(*rid);
            }
        }
        let ExternalType { namespace, name, nesting, scope } = external.as_ref();
        let mut scope_cell = self.scope_cell(scope, m)?;
        let mut rid = 0;
        // Chain runs outermost-first; each level's ResolutionScope is the
        // previous level's TypeRef (ECMA-335 II 22.32).
        let mut st = self.state.borrow_mut();
        for (ns, nm) in nesting
            .iter()
            .map(|p| (&p.namespace, &p.name))
            .chain(std::iter::once((namespace, name)))
        {
            let hash = st.type_ref_ids.hash((scope_cell, ns, nm));
            let hit = st.type_ref_ids.find(hash, |i| {
                let row = &st.trefs[i];
                row.0 == scope_cell && row.1 == *ns && row.2 == *nm
            });
            rid = if let Some(r) = hit {
                r
            } else {
                let r = st.type_ref_ids.insert(hash);
                st.trefs.push((scope_cell, ns.clone(), nm.clone()));
                r
            };
            scope_cell = (rid << 2) | 3; // ResolutionScope tag: TypeRef
        }
        if shared_identity {
            st.external_rows.insert(key, (external.clone(), rid));
        }
        Ok(rid)
    }

    /// Interns a composite type as a `TypeSpec` row and returns its rid.
    ///
    /// Children remain inline in the signature. Only token-bearing positions
    /// (such as IL operands) create TypeSpec rows.
    fn intern_type_spec(&self, ty: &TypeDesc, m: &Module) -> Result<u32> {
        let is_value = match ty {
            TypeDesc::GenericInstance { definition, .. } => self.is_value_type(definition, m)?,
            _ => false,
        };
        let writer =
            self.encode_signature(|w| write_type_element(ty, w, &self.signature_bridge(m)))?;
        let blob = writer.as_slice();
        let mut st = self.state.borrow_mut();
        let hash = st.type_spec_ids.hash(blob);
        if let Some(rid) = st.type_spec_ids.find(hash, |i| st.tspecs[i].2 == blob) {
            st.recycle_signature(writer);
            return Ok(rid);
        }
        let rid = st.type_spec_ids.insert(hash);
        st.tspecs.push((ty.clone(), is_value, writer.into_vec()));
        Ok(rid)
    }

    /// Reuses inline bytes of shared children without changing the wire grammar.
    fn encoded_element(
        &self,
        e: &Arc<TypeDesc>,
        m: &Module,
        cache_epoch: u64,
    ) -> Result<Option<Arc<[u8]>>> {
        // Classifiers may change their answer or fail on every invocation.
        // Reusing bytes would suppress those observable calls, even for a
        // child cached before a classifier was installed.
        if !is_cacheable(e)
            || self.external_classifier.try_borrow().map_or(true, |callback| callback.is_some())
        {
            return Ok(None);
        }
        let key = (cache_epoch, Arc::as_ptr(e) as usize);
        if let Some(cached) = self.state.borrow().element_blobs.get(&key) {
            return Ok(Some(cached.bytes.clone()));
        }
        let mut w = ByteWriter::new();
        write_type_element(e, &mut w, &SigBridge { tm: self, m, cache_epoch })?;
        let bytes: Arc<[u8]> = w.into_vec().into();
        self.state
            .borrow_mut()
            .element_blobs
            .insert(key, EncodedElement { _owner: e.clone(), bytes: bytes.clone() });
        Ok(Some(bytes))
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
                let sig = self.encode_signature(|w| {
                    put_method_signature(w, &ext.signature, &self.signature_bridge(m))
                })?;
                Ok(self.intern_member_ref(parent_cell, &ext.name, sig))
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
                let writer = self.encode_signature(|w| {
                    w.u8(0x0A); // ELEMENT_TYPE_GENERICINST (calling-convention slot)
                    w.compressed_u32(arguments.len() as u32);
                    let bridge = self.signature_bridge(m);
                    for arg in arguments.iter() {
                        write_type_element(arg, w, &bridge)?;
                    }
                    Ok(())
                })?;
                let inst = writer.as_slice();
                let mut st = self.state.borrow_mut();
                let hash = st.method_spec_ids.hash((method_cell, inst));
                if let Some(rid) = st
                    .method_spec_ids
                    .find(hash, |i| st.mspecs[i].0 == method_cell && st.mspecs[i].1 == inst)
                {
                    st.recycle_signature(writer);
                    return Ok(Token::new(TableIndex::MethodSpec, rid));
                }
                let rid = st.method_spec_ids.insert(hash);
                st.mspecs.push((method_cell, writer.into_vec()));
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
                let sig = self.encode_signature(|w| {
                    w.u8(0x06); // FIELD calling convention
                    write_type_element(&ext.signature.0, w, &self.signature_bridge(m))
                })?;
                Ok(self.intern_member_ref(parent_cell, &ext.name, sig))
            }
        }
    }

    fn intern_member_ref(&self, parent_cell: u32, name: &str, writer: ByteWriter) -> Token {
        let mut st = self.state.borrow_mut();
        let sig = writer.as_slice();
        let hash = st.member_ref_ids.hash((parent_cell, name, sig));
        if let Some(rid) = st.member_ref_ids.find(hash, |i| {
            let row = &st.mrefs[i];
            row.0 == parent_cell && row.1 == name && row.2 == sig
        }) {
            st.recycle_signature(writer);
            return Token::new(TableIndex::MemberRef, rid);
        }
        let rid = st.member_ref_ids.insert(hash);
        st.mrefs.push((parent_cell, name.to_string(), writer.into_vec()));
        Token::new(TableIndex::MemberRef, rid)
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
        let writer = self.encode_signature(|w| {
            w.u8(0x07); // LOCAL_SIG
            w.compressed_u32(locals.len() as u32);
            let bridge = self.signature_bridge(m);
            for var in locals {
                if var.pinned {
                    w.u8(ElementType::Pinned as u8);
                }
                write_type_element(&var.ty, w, &bridge)?;
            }
            Ok(())
        })?;
        Ok(self.intern_standalone_writer(writer))
    }

    fn intern_standalone_writer(&self, writer: ByteWriter) -> Token {
        let blob = writer.as_slice();
        let mut st = self.state.borrow_mut();
        let hash = st.standalone_ids.hash(blob);
        if let Some(rid) = st.standalone_ids.find(hash, |i| st.ssigs[i] == blob) {
            st.recycle_signature(writer);
            return Token::new(TableIndex::StandAloneSig, rid);
        }
        let rid = st.standalone_ids.insert(hash);
        st.ssigs.push(writer.into_vec());
        Token::new(TableIndex::StandAloneSig, rid)
    }

    /// Returns the `StandAloneSig` token for a raw signature blob (e.g. a
    /// `calli` signature captured at read time), deduplicating byte-identical
    /// blobs into a single pending row. The row drains through
    /// [`PendingRows::standalone_sigs`] like the local-variable signatures.
    pub fn stand_alone_sig_blob(&mut self, blob: &[u8]) -> Token {
        let mut st = self.state.borrow_mut();
        let hash = st.standalone_ids.hash(blob);
        if let Some(rid) = st.standalone_ids.find(hash, |i| st.ssigs[i] == blob) {
            return Token::new(TableIndex::StandAloneSig, rid);
        }
        let rid = st.standalone_ids.insert(hash);
        st.ssigs.push(blob.to_vec());
        Token::new(TableIndex::StandAloneSig, rid)
    }

    // -- classification ------------------------------------------------------

    /// Returns whether `ty` must be written with the `VALUETYPE` marker.
    /// External types preserve input VALUETYPE markers, then consult the
    /// installed classifier (see [`TokenMap::set_external_classifier`]);
    /// otherwise the documented heuristic applies.
    pub fn is_value_type(&self, ty: &TypeDesc, m: &Module) -> Result<bool> {
        match ty {
            TypeDesc::Def(id) => Ok(def_is_value_type(m, *id)),
            TypeDesc::External(e) => {
                if self.has_external_value(e, m) {
                    return Ok(true);
                }
                if let Some(classifier) = self.external_classifier.borrow_mut().as_mut() {
                    if let Some(classified) = classifier(e)? {
                        return Ok(classified);
                    }
                }
                Ok(external_is_value_type(e))
            }
            TypeDesc::GenericInstance { definition, .. } => self.is_value_type(definition, m),
            _ => {
                Err(Error::argument(format!("type shape {ty:?} carries no CLASS/VALUETYPE marker")))
            }
        }
    }

    fn has_external_value(&self, e: &ExternalType, m: &Module) -> bool {
        if let Some(index) = self.module_index.as_ref().filter(|i| std::ptr::eq(i.module, m)) {
            return index
                .external_values
                .get(e.name.as_str())
                .is_some_and(|values| values.iter().any(|value| **value == *e));
        }
        m.external_value_types.contains(e)
    }

    fn scope_cell(&self, scope: &ScopeRef, m: &Module) -> Result<u32> {
        if let Some(index) = self.module_index.as_ref().filter(|i| std::ptr::eq(i.module, m)) {
            match scope {
                ScopeRef::Assembly(reference) => {
                    if let Some(pos) =
                        index.assembly_scopes.get(reference.name.as_str()).and_then(|positions| {
                            positions
                                .iter()
                                .find(|&&i| same_assembly_reference(&m.assembly_refs[i], reference))
                        })
                    {
                        return Ok((((pos + 1) as u32) << 2) | 2);
                    }
                }
                ScopeRef::OtherModule(name) => {
                    if let Some(&cell) = index.module_scopes.get(name.as_str()) {
                        return Ok(cell);
                    }
                }
                ScopeRef::ThisModule => return Ok(1 << 2),
                ScopeRef::Moduleless => return Ok(0),
            }
        }
        scope_cell(scope, m)
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
            .into_iter()
            .map(|(ty, is_value, blob)| PendingTypeSpec {
                ty,
                is_value,
                blob: self.builder.insert_blob(&blob),
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
    cache_epoch: u64,
}

impl<'m, 'x, 'b> SigContext for SigEncoder<'m, 'x, 'b> {
    fn tdor_cell(&self, ty: &TypeDesc) -> Result<u32> {
        self.tm.tdor_cell(ty, self.m)
    }

    fn is_value_type(&self, ty: &TypeDesc) -> Result<bool> {
        self.tm.is_value_type(ty, self.m)
    }

    fn encoded_element(&self, e: &Arc<TypeDesc>) -> Result<Option<Arc<[u8]>>> {
        self.tm.encoded_element(e, self.m, self.cache_epoch)
    }
}

/// Private bridge used inside allocation paths where a fresh shared view is
/// needed while `&mut self`-free encoding runs.
struct SigBridge<'m, 'x, 't> {
    tm: &'x TokenMap<'t>,
    m: &'m Module,
    cache_epoch: u64,
}

impl<'m, 'x, 't> SigContext for SigBridge<'m, 'x, 't> {
    fn tdor_cell(&self, ty: &TypeDesc) -> Result<u32> {
        self.tm.tdor_cell(ty, self.m)
    }

    fn is_value_type(&self, ty: &TypeDesc) -> Result<bool> {
        self.tm.is_value_type(ty, self.m)
    }

    fn encoded_element(&self, e: &Arc<TypeDesc>) -> Result<Option<Arc<[u8]>>> {
        self.tm.encoded_element(e, self.m, self.cache_epoch)
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
            // Scopes are cloned before the reader attaches AssemblyRef custom
            // attributes. Match the row data, not those later annotations (which
            // can themselves contain references back to this assembly).
            let pos =
                m.assembly_refs.iter().position(|a| same_assembly_reference(a, anr)).ok_or_else(
                    || {
                        Error::argument(format!(
                            "assembly ref `{}` missing from module.assembly_refs",
                            anr.name
                        ))
                    },
                )?;
            Ok((((pos + 1) as u32) << 2) | 2)
        }
        ScopeRef::Moduleless => Ok(0), // nil scope
    }
}

fn same_assembly_reference(a: &AssemblyNameReference, b: &AssemblyNameReference) -> bool {
    a.name == b.name
        && a.version == b.version
        && a.culture == b.culture
        && a.public_key_or_token == b.public_key_or_token
        && a.hash == b.hash
        && a.hash_algorithm == b.hash_algorithm
        && a.attributes == b.attributes
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
            // Any other shape (generic instances, arrays/pointers, or
            // primitive INTERNAL forms a hostile TypeSpec blob decoded to)
            // is interned as a TypeSpec row — MemberRefParent's tag 4 slot
            // accepts exactly that, and write_type_element can encode every
            // TypeDesc shape.
            _ => Ok((self.intern_type_spec(ty, m)? << shift) | 4),
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
        TypeDesc::External(std::sync::Arc::new(ExternalType {
            namespace: ns.to_string(),
            name: name.to_string(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(assembly_ref().into()),
        }))
    }

    fn assembly_ref() -> AssemblyNameReference {
        AssemblyNameReference { version: ver(4, 0, 0, 0), ..AssemblyNameReference::new("mscorlib") }
    }

    #[test]
    fn assembly_scope_matches_row_data_without_custom_attributes() {
        use crate::model::types::{CustomAttribute, MethodId};

        let mut reference = assembly_ref();
        reference.public_key_or_token = vec![1; 8];
        let mut other_key = reference.clone();
        other_key.public_key_or_token = vec![2; 8];
        let mut other_version = reference.clone();
        other_version.version = ver(8, 0, 0, 0);
        let mut other_culture = reference.clone();
        other_culture.culture = Some("fr-FR".into());
        let mut annotated = reference.clone();
        annotated.custom_attributes.push(CustomAttribute {
            constructor: MethodRef::Def(MethodId(0)),
            blob: vec![1, 0, 0, 0],
        });
        let mut m = Module {
            assembly_refs: vec![other_key, other_version, other_culture, annotated],
            ..Default::default()
        };
        assert_eq!(
            scope_cell(&ScopeRef::Assembly(reference.clone().into()), &m).unwrap(),
            (4 << 2) | 2
        );
        let mut small_builder = MetadataBuilder::new("v4.0.30319");
        let small = TokenMap::for_module(&mut small_builder, &m);
        assert!(small.module_index.is_none());
        assert_eq!(
            small.scope_cell(&ScopeRef::Assembly(reference.clone().into()), &m).unwrap(),
            (4 << 2) | 2
        );
        drop(small);
        m.assembly_refs.extend(std::iter::repeat_n(m.assembly_refs[0].clone(), 5));
        let mut builder = MetadataBuilder::new("v4.0.30319");
        let indexed = TokenMap::for_module(&mut builder, &m);
        assert!(indexed.module_index.is_some());
        assert_eq!(
            indexed.scope_cell(&ScopeRef::Assembly(reference.clone().into()), &m).unwrap(),
            (4 << 2) | 2
        );
        reference.version = ver(9, 0, 0, 0);
        assert!(indexed.scope_cell(&ScopeRef::Assembly(reference.clone().into()), &m).is_err());
        assert!(scope_cell(&ScopeRef::Assembly(reference.into()), &m).is_err());
    }

    #[test]
    fn dedup_hash_collisions_keep_distinct_row_keys() {
        let mut index = DedupIndex::default();
        let keys = ["first", "second", "third"];
        // Force one collision chain instead of depending on random hash seeds.
        for (i, _) in keys.iter().enumerate() {
            assert_eq!(index.insert(7), i as u32 + 1);
        }
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(index.find(7, |row| keys[row] == *key), Some(i as u32 + 1));
        }
        assert_eq!(index.find(7, |row| keys[row] == "missing"), None);
        assert_eq!(index.find(8, |_| true), None);
    }

    #[test]
    fn indexed_value_types_preserve_scope_identity_and_other_module_fallback() {
        let mut reference = assembly_ref();
        reference.public_key_or_token = vec![1; 8];
        let mut other_reference = reference.clone();
        other_reference.public_key_or_token = vec![2; 8];
        let make = |scope: AssemblyNameReference| ExternalType {
            namespace: "Example".into(),
            name: "Value".into(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(scope.into()),
        };
        let value = make(reference);
        let other_value = make(other_reference);
        let m = Module { external_value_types: vec![value.clone(); 9], ..Default::default() };
        let other =
            Module { external_value_types: vec![other_value.clone()], ..Default::default() };
        let mut builder = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::for_module(&mut builder, &m);
        assert!(tm.module_index.is_some());
        let value = TypeDesc::External(std::sync::Arc::new(value));
        let other_value = TypeDesc::External(std::sync::Arc::new(other_value));
        assert!(tm.is_value_type(&value, &m).unwrap());
        assert!(!tm.is_value_type(&other_value, &m).unwrap());
        assert!(!tm.is_value_type(&value, &other).unwrap());
        assert!(tm.is_value_type(&other_value, &other).unwrap());
        tm.set_external_classifier(Box::new(|_| Ok(Some(true))));
        assert!(tm.is_value_type(&other_value, &m).unwrap(), "unknown types still use classifier");
    }

    #[test]
    fn signature_buffer_reuse_preserves_callbacks_and_recovers_from_errors() {
        use std::cell::Cell;
        use std::rc::Rc;

        let m = module_with_refs();
        let mut builder = MetadataBuilder::new("v4.0.30319");
        let tm = Rc::new(TokenMap::for_module(&mut builder, &m));
        let weak = Rc::downgrade(&tm);
        let calls = Rc::new(Cell::new(0));
        let callback_calls = calls.clone();
        let module = &m;
        tm.set_external_classifier(Box::new(move |_| {
            let count = callback_calls.get() + 1;
            callback_calls.set(count);
            // A callback may itself encode a signature through this map.
            // Its writer must be separate from the suspended outer writer.
            let nested = MethodSignature {
                return_type: TypeDesc::Ptr(Arc::new(TypeDesc::SzArray(Arc::new(
                    TypeDesc::Internal("int32".into()),
                )))),
                ..Default::default()
            };
            weak.upgrade().unwrap().call_site_sig_token(&nested, module)?;
            if count == 1 {
                return Err(Error::argument("classifier failed"));
            }
            Ok(Some(count % 2 == 0))
        }));
        let method = MethodRef::External(
            ExternalMethod {
                parent: ext("System", "Object"),
                name: "Get".into(),
                signature: MethodSignature {
                    return_type: ext("Example", "Value"),
                    ..Default::default()
                },
            }
            .into(),
        );
        assert!(tm.method_ref(&method, &m).unwrap_err().to_string().contains("classifier failed"));
        let value = tm.method_ref(&method, &m).unwrap();
        let class = tm.method_ref(&method, &m).unwrap();
        assert_ne!(value, class, "classification callbacks are never memoized");
        assert_eq!(tm.method_ref(&method, &m).unwrap(), value);
        assert_eq!(calls.get(), 4);

        let (builder, pending) = Rc::try_unwrap(tm).unwrap().into_parts();
        assert_eq!(pending.member_refs.len(), 2);
        assert_eq!(pending.standalone_sigs.len(), 1);
        let root = std::mem::replace(builder, MetadataBuilder::new("v4.0.30319")).finalize();
        let reader = cecil_metadata::MetadataReader::parse(&root).unwrap();
        for (row, marker) in pending.member_refs.iter().zip([0x11, 0x12]) {
            let blob = reader.heaps().blob.get(row.signature).unwrap();
            assert_eq!(&blob[..3], &[0x20, 0, marker], "no partial failed encoding remains");
        }
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
    fn shared_external_rows_respect_copy_on_write_and_other_module_scopes() {
        let m = module_with_refs();
        let mut other = module_with_refs();
        other.assembly_refs.insert(0, AssemblyNameReference::new("Other"));
        let mut builder = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::for_module(&mut builder, &m);
        let TypeDesc::External(mut external) = ext("Example", "Original") else { unreachable!() };
        let original = tm.tdor_cell(&TypeDesc::External(external.clone()), &m).unwrap();
        assert_eq!(tm.tdor_cell(&TypeDesc::External(external.clone()), &m).unwrap(), original);
        let other_scope = tm.tdor_cell(&TypeDesc::External(external.clone()), &other).unwrap();
        assert_ne!(original, other_scope);
        assert!(tm.tdor_cell(&TypeDesc::External(external.clone()), &Module::default()).is_err());

        Arc::make_mut(&mut external).name = "Changed".into();
        let changed = tm.tdor_cell(&TypeDesc::External(external), &m).unwrap();
        assert_ne!(original, changed);
        let (_, pending) = tm.into_parts();
        assert_eq!(pending.type_refs.len(), 3);
        assert_eq!(pending.type_refs[0].scope_cell, (1 << 2) | 2);
        assert_eq!(pending.type_refs[1].scope_cell, (2 << 2) | 2);
        assert_eq!(pending.type_refs[2].scope_cell, (1 << 2) | 2);
    }

    #[test]
    fn shared_signature_children_recheck_unbound_and_other_module_scopes() {
        let m = module_with_refs();
        let mut other = module_with_refs();
        other.assembly_refs.insert(0, AssemblyNameReference::new("Other"));
        let child = Arc::new(TypeDesc::SzArray(Arc::new(ext("Example", "Value"))));
        let signature = crate::model::types::FieldSignature(TypeDesc::Ptr(child));

        let mut builder = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::new(&mut builder);
        let first =
            crate::model::signature::write_field_signature(&signature, &tm.encoder(&m)).unwrap();
        let second =
            crate::model::signature::write_field_signature(&signature, &tm.encoder(&other))
                .unwrap();
        assert_ne!(first, second, "the same child resolves against each module's scope rows");
        assert!(crate::model::signature::write_field_signature(
            &signature,
            &tm.encoder(&Module::default()),
        )
        .is_err());
        drop(tm);

        let bound = TokenMap::for_module(&mut builder, &m);
        crate::model::signature::write_field_signature(&signature, &bound.encoder(&m)).unwrap();
        assert!(
            crate::model::signature::write_field_signature(
                &signature,
                &bound.encoder(&Module::default()),
            )
            .is_err(),
            "a bound map's cache cannot satisfy another module"
        );

        let mut mutable = module_with_refs();
        let mut other_builder = MetadataBuilder::new("v4.0.30319");
        let unbound = TokenMap::new(&mut other_builder);
        crate::model::signature::write_field_signature(&signature, &unbound.encoder(&mutable))
            .unwrap();
        mutable.assembly_refs.clear();
        assert!(
            crate::model::signature::write_field_signature(&signature, &unbound.encoder(&mutable),)
                .is_err(),
            "public maps do not hold their module immutable between calls"
        );
    }

    #[test]
    fn shared_signature_children_preserve_dynamic_classifier_calls() {
        use std::cell::Cell;
        use std::rc::Rc;

        let m = module_with_refs();
        let mut builder = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::for_module(&mut builder, &m);
        let signature = crate::model::types::FieldSignature(TypeDesc::Ptr(Arc::new(
            TypeDesc::SzArray(Arc::new(ext("Example", "Value"))),
        )));
        let encode = || crate::model::signature::write_field_signature(&signature, &tm.encoder(&m));
        // Fill the cache before installing a classifier as well.
        encode().unwrap();
        let calls = Rc::new(Cell::new(0));
        let callback_calls = calls.clone();
        tm.set_external_classifier(Box::new(move |_| {
            let count = callback_calls.get() + 1;
            callback_calls.set(count);
            if count == 3 {
                return Err(Error::argument("classifier failed"));
            }
            Ok(Some(count % 2 == 1))
        }));
        let value = encode().unwrap();
        let class = encode().unwrap();
        assert_ne!(value, class, "callbacks may change the CLASS/VALUETYPE marker");
        assert!(encode().unwrap_err().to_string().contains("classifier failed"));
        assert_eq!(encode().unwrap(), class);
        assert_eq!(calls.get(), 4, "each encoding still invokes the classifier");
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

        let a = TypeDesc::External(std::sync::Arc::new(ExternalType {
            namespace: "System".into(),
            name: "String".into(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(m.assembly_refs[1].clone().into()),
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
            TypeDesc::External(std::sync::Arc::new(ExternalType {
                namespace: String::new(),
                name: "Inner".into(),
                nesting: vec![std::sync::Arc::new(ExternalType {
                    namespace: "NS".into(),
                    name: "Outer".into(),
                    nesting: Vec::new(),
                    scope: ScopeRef::Assembly(assembly_ref().into()),
                })],
                scope: ScopeRef::Assembly(assembly_ref().into()),
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
            arguments: vec![std::sync::Arc::new(int32.clone())].into(),
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
        let t1 = tm.method_ref(&MethodRef::External(em.clone().into()), &m).unwrap();
        let t2 = tm.method_ref(&MethodRef::External(em.into()), &m).unwrap();
        assert_eq!(t1, t2);
        assert_eq!(t1.table(), TableIndex::MemberRef);

        // Spec path: MethodSpec over the MemberRef template.
        let spec = MethodRef::Spec {
            method: std::sync::Arc::new(MethodRef::External(
                ExternalMethod {
                    parent: ext("System.Linq", "Enumerable"),
                    name: "Where".into(),
                    signature: MethodSignature::default(),
                }
                .into(),
            )),
            arguments: vec![ext("System", "Int32")].into(),
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

        let fe = FieldRef::External(
            crate::model::types::ExternalField {
                parent: ext("System", "Console"),
                name: "Out".into(),
                signature: FieldSignature(ext("System.IO", "TextWriter")),
            }
            .into(),
        );
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
    /// the per-allocation encoding cache avoids repeated tree traversal.
    fn build_dag_tree(levels: u32) -> TypeDesc {
        let mut t = ext("System", "Int32");
        for _ in 0..levels {
            let shared = Arc::new(t);
            t = TypeDesc::GenericInstance {
                definition: Arc::new(ext("System.Collections", "Tuple")),
                arguments: vec![shared.clone(), shared].into(),
            };
        }
        t
    }

    #[test]
    fn write_dag_rejects_excessive_inline_expansion() {
        let m = module_with_refs();
        let mut b = MetadataBuilder::new("v4.0.30319");
        let tm = TokenMap::new(&mut b);

        // Legal inline encoding would need billions of bytes. Fail within
        // the resource bound instead of emitting invalid CLASS + TypeSpec.
        let tree = build_dag_tree(30);
        let err = tm.tdor_cell(&tree, &m).unwrap_err();
        assert!(err.to_string().contains("expanded signature exceeds"), "{err}");
    }

    /// The cache must be invisible on the wire: encoding the same shared DAG
    /// through two fresh token maps yields identical row sets and blobs.
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
    /// deduplicate to one row for the root type.
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
        assert_eq!(pending.type_specs.len(), 1);
    }
}
