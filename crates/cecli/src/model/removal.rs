//! Runtime removal of types and members (Cecil `Collection<T>.Remove`).
//!
//! Cecil removes members by detaching them from their owner's collection;
//! sibling references keep pointing at the detached object. The arena model
//! here has no detached objects — handles are indices — so removal is
//! implemented as an eager **compaction**: the removed slots are physically
//! dropped from their arenas and every surviving handle in the model is
//! remapped to the slot's new position.
//!
//! # Handle invalidation
//!
//! Like `Vec::remove`, any remove invalidates arena handles held by caller
//! code: a `MethodId` captured before `remove_method` may refer to a
//! different (or out-of-range) method afterwards. Re-enumerate with
//! [`Module::iter_methods`](crate::module_def::Module::iter_methods) et al.
//! after mutating.
//!
//! # Dangling references
//!
//! References *from surviving elements* to a removed target cannot dangle
//! silently; they are replaced with wire-legal sentinels instead (fix the
//! references before removal if that is not wanted):
//!
//! * a `TypeDesc::Def` whose target type was removed becomes
//!   `TypeDesc::Internal("<removed>")`;
//! * a `MethodRef::Def` / `FieldRef::Def` in an instruction operand becomes
//!   the raw nil token operand;
//! * accessor links (`get_method`, `add_on`, ...), overrides and custom
//!   attributes whose constructor or owner method was removed are dropped.

use std::collections::BTreeSet;

use super::types::{
    CustomAttribute, EventDefinition, FieldDefinition, FieldId, FieldRef, GenericOwner,
    GenericParamId, MethodDefinition, MethodId, MethodRef, PropertyDefinition, PropertyId,
    RInstruction, ROperand, ResolvedBody, TypeDesc, TypeId,
};
use super::types::{EventId, GenericParameter, TypeDefinition};
use crate::module_def::Module;
use crate::module_def::ModuleDebugInfo;
use cecli_core::Token;

/// Old-slot → new-slot map for one arena during compaction.
pub(crate) struct ArenaMap {
    slots: Vec<Option<u32>>,
}

impl ArenaMap {
    fn build(len: usize, removed: &BTreeSet<u32>) -> (ArenaMap, Vec<u32>) {
        // `keep[i]` lists the old indices that survive, in order; their new
        // index is their position in that list.
        let keep: Vec<u32> = (0..len as u32).filter(|i| !removed.contains(i)).collect();
        let mut slots = vec![None; len];
        for (new, &old) in keep.iter().enumerate() {
            slots[old as usize] = Some(new as u32);
        }
        (ArenaMap { slots }, keep)
    }

    pub(crate) fn get(&self, old: u32) -> Option<u32> {
        self.slots.get(old as usize).copied().flatten()
    }
}

/// The sentinel substituted for type references to removed types.
fn removed_type_sentinel() -> TypeDesc {
    TypeDesc::Internal("<removed>".into())
}

/// Rebuilds a `TypeDesc` with its `Def` handles remapped (the tree is
/// `Arc`-shared, so remapping is functional, not in-place).
fn remap_type_desc(ty: &TypeDesc, types: &ArenaMap) -> TypeDesc {
    use std::sync::Arc;
    match ty {
        TypeDesc::Def(id) => match types.get(id.0) {
            Some(new) => TypeDesc::Def(TypeId(new)),
            None => removed_type_sentinel(),
        },
        TypeDesc::SzArray(t) => TypeDesc::SzArray(Arc::new(remap_type_desc(t, types))),
        TypeDesc::Ptr(t) => TypeDesc::Ptr(Arc::new(remap_type_desc(t, types))),
        TypeDesc::ByRef(t) => TypeDesc::ByRef(Arc::new(remap_type_desc(t, types))),
        TypeDesc::Pinned(t) => TypeDesc::Pinned(Arc::new(remap_type_desc(t, types))),
        TypeDesc::Array { element, sizes, lobounds } => TypeDesc::Array {
            element: Arc::new(remap_type_desc(element, types)),
            sizes: sizes.clone(),
            lobounds: lobounds.clone(),
        },
        TypeDesc::GenericInstance { definition, arguments } => TypeDesc::GenericInstance {
            definition: Arc::new(remap_type_desc(definition, types)),
            arguments: arguments.iter().map(|a| Arc::new(remap_type_desc(a, types))).collect(),
        },
        TypeDesc::FnPtr(sig) => {
            let mut sig = (**sig).clone();
            for p in sig.parameters.iter_mut() {
                *p = remap_type_desc(p, types);
            }
            sig.return_type = remap_type_desc(&sig.return_type, types);
            TypeDesc::FnPtr(Box::new(sig))
        }
        TypeDesc::CMod { required, modifier, unmodified } => TypeDesc::CMod {
            required: *required,
            modifier: Arc::new(remap_type_desc(modifier, types)),
            unmodified: Arc::new(remap_type_desc(unmodified, types)),
        },
        other => other.clone(),
    }
}

/// In-place slot variant for `&mut TypeDesc` call sites.
fn remap_type_slot(slot: &mut TypeDesc, types: &ArenaMap) {
    *slot = remap_type_desc(slot, types);
}

/// In-place optional slot variant.
fn remap_type_opt(slot: &mut Option<TypeDesc>, types: &ArenaMap) {
    if let Some(t) = slot.as_mut() {
        remap_type_slot(t, types);
    }
}

fn remap_method_ref(r: &mut MethodRef, types: &ArenaMap, methods: &ArenaMap) -> bool {
    // Returns false when the reference dangles (target method removed).
    match r {
        MethodRef::Def(id) => match methods.get(id.0) {
            Some(new) => {
                id.0 = new;
                true
            }
            None => false,
        },
        MethodRef::External(ext) => {
            remap_type_slot(&mut ext.parent, types);
            for arg in ext.signature.parameters.iter_mut() {
                remap_type_slot(arg, types);
            }
            remap_type_slot(&mut ext.signature.return_type, types);
            true
        }
        MethodRef::Spec { method, arguments } => {
            let alive = remap_method_ref(method, types, methods);
            for arg in arguments.iter_mut() {
                remap_type_slot(arg, types);
            }
            alive
        }
    }
}

fn remap_field_ref(r: &mut FieldRef, types: &ArenaMap, fields: &ArenaMap) -> bool {
    match r {
        FieldRef::Def(id) => match fields.get(id.0) {
            Some(new) => {
                id.0 = new;
                true
            }
            None => false,
        },
        FieldRef::External(ext) => {
            remap_type_slot(&mut ext.parent, types);
            remap_type_slot(&mut ext.signature.0, types);
            true
        }
    }
}

fn remap_custom_attributes(cas: &mut Vec<CustomAttribute>, types: &ArenaMap, methods: &ArenaMap) {
    cas.retain_mut(|ca| remap_method_ref(&mut ca.constructor, types, methods));
}

fn remap_body(body: &mut ResolvedBody, types: &ArenaMap, methods: &ArenaMap, fields: &ArenaMap) {
    for instr in body.instructions.iter_mut() {
        remap_instruction(instr, types, methods, fields);
    }
    for handler in body.exception_handlers.iter_mut() {
        if let Some(ct) = handler.catch_type.as_mut() {
            remap_type_slot(ct, types);
        }
    }
}

fn remap_instruction(
    instr: &mut RInstruction,
    types: &ArenaMap,
    methods: &ArenaMap,
    fields: &ArenaMap,
) {
    let operand = std::mem::replace(&mut instr.operand, ROperand::None);
    instr.operand = match operand {
        ROperand::Type(mut ty) => {
            remap_type_slot(&mut ty, types);
            ROperand::Type(ty)
        }
        ROperand::Method(mut m) => {
            if remap_method_ref(&mut m, types, methods) {
                ROperand::Method(m)
            } else {
                ROperand::Token(Token::NIL)
            }
        }
        ROperand::Field(mut f) => {
            if remap_field_ref(&mut f, types, fields) {
                ROperand::Field(f)
            } else {
                ROperand::Token(Token::NIL)
            }
        }
        ROperand::CallSite(mut sig) => {
            for p in sig.parameters.iter_mut() {
                remap_type_slot(p, types);
            }
            remap_type_slot(&mut sig.return_type, types);
            ROperand::CallSite(sig)
        }
        ROperand::Token(t) => ROperand::Token(t),
        other => other,
    };
}

fn remap_debug_info(debug: &mut ModuleDebugInfo, methods: &ArenaMap) {
    let remap_key = |key: &u32| methods.get(key.saturating_sub(1)).map(|n| n + 1);
    debug.points = std::mem::take(&mut debug.points)
        .into_iter()
        .filter_map(|(rid, v)| remap_key(&rid).map(|n| (n, v)))
        .collect();
    debug.scopes = std::mem::take(&mut debug.scopes)
        .into_iter()
        .filter_map(|(rid, v)| remap_key(&rid).map(|n| (n, v)))
        .collect();
}

impl Module {
    /// Removes one type (and its whole nested subtree, with all their
    /// members) from the module.
    ///
    /// Handles are invalidated model-wide; see the [module
    /// docs](self) for the sentinel policy for surviving references.
    pub fn remove_type(&mut self, id: TypeId) {
        let _ = self.remove_type_mapped(id);
    }

    /// `remove_type` returning the arena remappings for facade-level
    /// fixups (entry point, assembly custom attributes).
    pub(crate) fn remove_type_mapped(&mut self, id: TypeId) -> ArenaMaps {
        let mut types = BTreeSet::new();
        let mut methods = BTreeSet::new();
        let mut fields = BTreeSet::new();
        let mut properties = BTreeSet::new();
        let mut events = BTreeSet::new();
        self.collect_type_removal(
            id,
            &mut types,
            &mut methods,
            &mut fields,
            &mut properties,
            &mut events,
        );

        // Detach from the declaring parent's nested list (top-level types
        // need no detach: the arena is filtered directly).
        if let Some(parent) = self.types.get(id.0 as usize).and_then(|t| t.declaring_type) {
            if let Some(p) = self.types.get_mut(parent.0 as usize) {
                p.nested_types.retain(|&n| n != id);
            }
        }

        self.compact(&types, &methods, &fields, &properties, &events)
    }

    /// Removes one method from its declaring type.
    pub fn remove_method(&mut self, id: MethodId) {
        let _ = self.remove_method_mapped(id);
    }

    /// `remove_method` returning the arena remappings.
    pub(crate) fn remove_method_mapped(&mut self, id: MethodId) -> ArenaMaps {
        let methods = BTreeSet::from([id.0]);

        // Detach from the owner's method list.
        if let Some(index) = self.methods.get(id.0 as usize).map(|m| m.declaring_type) {
            if let Some(t) = self.types.get_mut(index.0 as usize) {
                t.methods.retain(|&m| m != id);
            }
        }

        // compact() drops the method's generic parameters implicitly (owner
        // removed) and remaps every surviving handle.
        self.compact(
            &BTreeSet::new(),
            &methods,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
    }

    /// Removes one field from its declaring type.
    pub fn remove_field(&mut self, id: FieldId) {
        let _ = self.remove_field_mapped(id);
    }

    /// `remove_field` returning the arena remappings.
    pub(crate) fn remove_field_mapped(&mut self, id: FieldId) -> ArenaMaps {
        let fields = BTreeSet::from([id.0]);
        if let Some(index) = self.member_owner(|t| t.fields.contains(&id)) {
            if let Some(t) = self.types.get_mut(index.0 as usize) {
                t.fields.retain(|&f| f != id);
            }
        }
        self.compact(
            &BTreeSet::new(),
            &BTreeSet::new(),
            &fields,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )
    }

    /// Removes one property from its declaring type.
    pub fn remove_property(&mut self, id: PropertyId) {
        let _ = self.remove_property_mapped(id);
    }

    /// `remove_property` returning the arena remappings.
    pub(crate) fn remove_property_mapped(&mut self, id: PropertyId) -> ArenaMaps {
        let properties = BTreeSet::from([id.0]);
        if let Some(index) = self.member_owner(|t| t.properties.contains(&id)) {
            if let Some(t) = self.types.get_mut(index.0 as usize) {
                t.properties.retain(|&p| p != id);
            }
        }
        self.compact(
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            &properties,
            &BTreeSet::new(),
        )
    }

    /// Removes one event from its declaring type.
    pub fn remove_event(&mut self, id: EventId) {
        let _ = self.remove_event_mapped(id);
    }

    /// `remove_event` returning the arena remappings.
    pub(crate) fn remove_event_mapped(&mut self, id: EventId) -> ArenaMaps {
        let events = BTreeSet::from([id.0]);
        if let Some(index) = self.member_owner(|t| t.events.contains(&id)) {
            if let Some(t) = self.types.get_mut(index.0 as usize) {
                t.events.retain(|&e| e != id);
            }
        }
        self.compact(
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            &events,
        )
    }

    /// Index of the (unique) type whose member list satisfies `has`.
    fn member_owner(&self, has: impl Fn(&TypeDefinition) -> bool) -> Option<TypeId> {
        let i = self.types.iter().position(has)?;
        Some(TypeId(i as u32))
    }

    /// Recursively collects a type subtree and every member handle owned by
    /// it into the removal sets.
    fn collect_type_removal(
        &self,
        id: TypeId,
        types: &mut BTreeSet<u32>,
        methods: &mut BTreeSet<u32>,
        fields: &mut BTreeSet<u32>,
        properties: &mut BTreeSet<u32>,
        events: &mut BTreeSet<u32>,
    ) {
        let Some(td) = self.types.get(id.0 as usize) else { return };
        if !types.insert(id.0) {
            return; // already collected (cycle guard)
        }
        methods.extend(td.methods.iter().map(|m| m.0));
        fields.extend(td.fields.iter().map(|f| f.0));
        properties.extend(td.properties.iter().map(|p| p.0));
        events.extend(td.events.iter().map(|e| e.0));
        let nested: Vec<TypeId> = td.nested_types.clone();
        for n in nested {
            self.collect_type_removal(n, types, methods, fields, properties, events);
        }
    }

    /// Physically removes the given slots and remaps every surviving handle.
    ///
    /// Generic parameters whose owner (type or method) is removed are removed
    /// implicitly, whether or not they appear in the passed sets.
    fn compact(
        &mut self,
        removed_types: &BTreeSet<u32>,
        removed_methods: &BTreeSet<u32>,
        removed_fields: &BTreeSet<u32>,
        removed_properties: &BTreeSet<u32>,
        removed_events: &BTreeSet<u32>,
    ) -> ArenaMaps {
        if removed_types.is_empty()
            && removed_methods.is_empty()
            && removed_fields.is_empty()
            && removed_properties.is_empty()
            && removed_events.is_empty()
        {
            return ArenaMaps::identity(
                self.types.len(),
                self.methods.len(),
                self.fields.len(),
                self.properties.len(),
                self.events.len(),
            );
        }

        // Generic parameters die with their owner.
        let removed_generic_params: BTreeSet<u32> = self
            .generic_parameters
            .iter()
            .enumerate()
            .filter(|(_i, gp)| match gp.owner {
                GenericOwner::Type(t) => removed_types.contains(&t.0),
                GenericOwner::Method(m) => removed_methods.contains(&m.0),
            })
            .map(|(i, _)| i as u32)
            .collect();

        let (tmap, keep_types) = ArenaMap::build(self.types.len(), removed_types);
        let (mmap, keep_methods) = ArenaMap::build(self.methods.len(), removed_methods);
        let (fmap, keep_fields) = ArenaMap::build(self.fields.len(), removed_fields);
        let (pmap, keep_props) = ArenaMap::build(self.properties.len(), removed_properties);
        let (emap, keep_events) = ArenaMap::build(self.events.len(), removed_events);
        let (gmap, keep_gps) =
            ArenaMap::build(self.generic_parameters.len(), &removed_generic_params);

        // --- rebuild arenas ------------------------------------------------
        let mut new_types: Vec<super::types::TypeDefinition> = Vec::with_capacity(keep_types.len());
        for &old in &keep_types {
            let mut td = std::mem::take(&mut self.types[old as usize]);
            if let Some(p) = td.declaring_type.as_mut() {
                match tmap.get(p.0) {
                    Some(n) => p.0 = n,
                    None => td.declaring_type = None, // declaring type was removed
                }
            }
            remap_id_list(&mut td.nested_types, &tmap);
            remap_id_list(&mut td.methods, &mmap);
            remap_id_list(&mut td.fields, &fmap);
            remap_id_list(&mut td.properties, &pmap);
            remap_id_list(&mut td.events, &emap);
            remap_id_list(&mut td.generic_parameters, &gmap);
            remap_type_opt(&mut td.base_type, &tmap);
            for iface in td.interfaces.iter_mut() {
                remap_type_slot(&mut iface.interface, &tmap);
                remap_custom_attributes(&mut iface.custom_attributes, &tmap, &mmap);
            }
            remap_custom_attributes(&mut td.custom_attributes, &tmap, &mmap);
            new_types.push(td);
        }
        self.types = new_types;

        let mut new_methods: Vec<MethodDefinition> = Vec::with_capacity(keep_methods.len());
        for &old in &keep_methods {
            let mut md = std::mem::take(&mut self.methods[old as usize]);
            if let Some(n) = tmap.get(md.declaring_type.0) {
                md.declaring_type.0 = n;
            }
            remap_id_list(&mut md.generic_parameters, &gmap);
            for p in md.signature.parameters.iter_mut() {
                remap_type_slot(p, &tmap);
            }
            remap_type_slot(&mut md.signature.return_type, &tmap);
            for p in md.parameters.iter_mut() {
                remap_custom_attributes(&mut p.custom_attributes, &tmap, &mmap);
            }
            remap_custom_attributes(&mut md.return_parameter.custom_attributes, &tmap, &mmap);
            if let Some(body) = md.body.as_mut() {
                remap_body(body, &tmap, &mmap, &fmap);
            }
            md.overrides.retain_mut(|ov| {
                remap_method_ref(&mut ov.body, &tmap, &mmap)
                    && remap_method_ref(&mut ov.declaration, &tmap, &mmap)
            });
            remap_custom_attributes(&mut md.custom_attributes, &tmap, &mmap);
            new_methods.push(md);
        }
        self.methods = new_methods;

        let mut new_fields: Vec<FieldDefinition> = Vec::with_capacity(keep_fields.len());
        for &old in &keep_fields {
            let mut fd = std::mem::take(&mut self.fields[old as usize]);
            remap_type_slot(&mut fd.signature.0, &tmap);
            remap_custom_attributes(&mut fd.custom_attributes, &tmap, &mmap);
            new_fields.push(fd);
        }
        self.fields = new_fields;

        let mut new_props: Vec<PropertyDefinition> = Vec::with_capacity(keep_props.len());
        for &old in &keep_props {
            let mut pd = std::mem::take(&mut self.properties[old as usize]);
            remap_type_slot(&mut pd.signature.property_type, &tmap);
            for p in pd.signature.parameters.iter_mut() {
                remap_type_slot(p, &tmap);
            }
            pd.get_method = pd.get_method.filter(|m| mmap.get(m.0).is_some()).map(|mut m| {
                m.0 = mmap.get(m.0).unwrap();
                m
            });
            pd.set_method = pd.set_method.filter(|m| mmap.get(m.0).is_some()).map(|mut m| {
                m.0 = mmap.get(m.0).unwrap();
                m
            });
            pd.other_methods.retain_mut(|m| {
                if let Some(n) = mmap.get(m.0) {
                    m.0 = n;
                    true
                } else {
                    false
                }
            });
            remap_custom_attributes(&mut pd.custom_attributes, &tmap, &mmap);
            new_props.push(pd);
        }
        self.properties = new_props;

        let mut new_events: Vec<EventDefinition> = Vec::with_capacity(keep_events.len());
        for &old in &keep_events {
            let mut ed = std::mem::take(&mut self.events[old as usize]);
            remap_type_opt(&mut ed.event_type, &tmap);
            ed.add_on = ed.add_on.filter(|m| mmap.get(m.0).is_some()).map(|mut m| {
                m.0 = mmap.get(m.0).unwrap();
                m
            });
            ed.remove_on = ed.remove_on.filter(|m| mmap.get(m.0).is_some()).map(|mut m| {
                m.0 = mmap.get(m.0).unwrap();
                m
            });
            ed.fire = ed.fire.filter(|m| mmap.get(m.0).is_some()).map(|mut m| {
                m.0 = mmap.get(m.0).unwrap();
                m
            });
            ed.other_methods.retain_mut(|m| {
                if let Some(n) = mmap.get(m.0) {
                    m.0 = n;
                    true
                } else {
                    false
                }
            });
            remap_custom_attributes(&mut ed.custom_attributes, &tmap, &mmap);
            new_events.push(ed);
        }
        self.events = new_events;

        let mut new_gps: Vec<GenericParameter> = Vec::with_capacity(keep_gps.len());
        for &old in &keep_gps {
            let mut gp = std::mem::take(&mut self.generic_parameters[old as usize]);
            match gp.owner {
                GenericOwner::Type(t) => {
                    if let Some(n) = tmap.get(t.0) {
                        gp.owner = GenericOwner::Type(TypeId(n));
                    }
                }
                GenericOwner::Method(m) => {
                    if let Some(n) = mmap.get(m.0) {
                        gp.owner = GenericOwner::Method(MethodId(n));
                    }
                }
            }
            for c in gp.constraints.iter_mut() {
                remap_type_slot(&mut c.constraint, &tmap);
                remap_custom_attributes(&mut c.custom_attributes, &tmap, &mmap);
            }
            remap_custom_attributes(&mut gp.custom_attributes, &tmap, &mmap);
            new_gps.push(gp);
        }
        self.generic_parameters = new_gps;

        // --- module-level state ---------------------------------------------
        if let Some(debug) = self.debug.as_mut() {
            remap_debug_info(debug, &mmap);
        }

        ArenaMaps { types: tmap, methods: mmap }
    }
}

/// The arena remappings produced by one compaction, for callers that hold
/// assembly-level state outside the module (entry point, assembly custom
/// attributes).
pub(crate) struct ArenaMaps {
    /// Reserved for facade fixups over type handles (currently unused: the
    /// entry point is a method and assembly CAs reference methods only).
    #[allow(dead_code)]
    pub(crate) types: ArenaMap,
    pub(crate) methods: ArenaMap,
}

impl ArenaMaps {
    /// Placeholder returned when nothing was removed.
    fn identity(
        _types: usize,
        _methods: usize,
        _fields: usize,
        _props: usize,
        _events: usize,
    ) -> Self {
        ArenaMaps { types: ArenaMap { slots: Vec::new() }, methods: ArenaMap { slots: Vec::new() } }
    }
}

fn remap_id_list<T: Handle>(ids: &mut Vec<T>, map: &ArenaMap) {
    ids.retain_mut(|id| {
        if let Some(n) = map.get(id.raw()) {
            id.set_raw(n);
            true
        } else {
            false
        }
    });
}

/// Index-carrying handle abstraction for the generic list remapper.
trait Handle {
    fn raw(&self) -> u32;
    fn set_raw(&mut self, v: u32);
}

macro_rules! impl_handle {
    ($($t:ty),*) => {$(
        impl Handle for $t {
            fn raw(&self) -> u32 { self.0 }
            fn set_raw(&mut self, v: u32) { self.0 = v; }
        }
    )*};
}
impl_handle!(TypeId, MethodId, FieldId, PropertyId, EventId, GenericParamId);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {

    use super::*;
    use crate::model::types::{FieldDefinition, FieldSignature, MethodDefinition, TypeDefinition};

    /// Module with three types — A (fields f0/f1, methods m0/m1), B (field fb,
    /// method mb), C nested in A — plus cross-references: B's method body calls
    /// A.m0, C's base is A.
    fn module_with_members() -> Module {
        let mut m =
            Module { name: "t".into(), runtime_version: "v4.0.30319".into(), ..Default::default() };
        m.assembly_refs.push(crate::model::types::AssemblyNameReference::new("mscorlib"));

        let a = m.add_type(TypeDefinition {
            namespace: "N".into(),
            name: "A".into(),
            ..Default::default()
        });
        let c = m.add_type(TypeDefinition {
            namespace: "N".into(),
            name: "C".into(),
            declaring_type: Some(a),
            base_type: Some(TypeDesc::Def(a)),
            ..Default::default()
        });
        let b = m.add_type(TypeDefinition {
            namespace: "N".into(),
            name: "B".into(),
            ..Default::default()
        });

        for name in ["f0", "f1"] {
            m.add_field(
                a,
                FieldDefinition {
                    name: name.into(),
                    signature: FieldSignature(TypeDesc::Internal("int32".into())),
                    ..Default::default()
                },
            );
        }
        m.add_field(
            b,
            FieldDefinition {
                name: "fb".into(),
                signature: FieldSignature(TypeDesc::Internal("int32".into())),
                ..Default::default()
            },
        );

        let a_m0 = m.add_method(a, MethodDefinition { name: "m0".into(), ..Default::default() });
        let _a_m1 = m.add_method(a, MethodDefinition { name: "m1".into(), ..Default::default() });
        let b_mb = m.add_method(b, MethodDefinition { name: "mb".into(), ..Default::default() });

        // B.mb body: call A.m0; ldsfld B.fb's sibling field f1 of A.
        let call = crate::model::types::RInstruction {
            offset: 0,
            opcode: cecli_cil::opcodes::CALL,
            operand: crate::model::types::ROperand::Method(MethodRef::Def(a_m0)),
        };
        let ldsfld = crate::model::types::RInstruction {
            offset: 5,
            opcode: cecli_cil::opcodes::LDSFLD,
            operand: crate::model::types::ROperand::Field(FieldRef::Def(FieldId(1))),
        };
        let ret = crate::model::types::RInstruction {
            offset: 10,
            opcode: cecli_cil::opcodes::RET,
            operand: crate::model::types::ROperand::None,
        };
        if let Some(mb) = m.method_mut(b_mb) {
            mb.body = Some(crate::model::types::ResolvedBody {
                instructions: vec![call, ldsfld, ret],
                ..Default::default()
            });
        }
        let _ = c;
        m
    }

    #[test]
    fn remove_method_renumbers_and_rewires() {
        let mut m = module_with_members();
        let b_id = m.types.iter().position(|t| t.name == "B").map(|i| TypeId(i as u32)).unwrap();
        let _b_mb = m.types[b_id.0 as usize].methods[0];
        assert_eq!(m.methods.len(), 3);

        // Remove A.m0 (arena index 0): B.mb's call operand must become the nil
        // token (dangling), and surviving method handles shift down by one.
        m.remove_method(MethodId(0));

        assert_eq!(m.methods.len(), 2);
        assert_eq!(m.methods[0].name, "m1");
        assert_eq!(m.methods[1].name, "mb");
        // B's list still contains its (remapped) method.
        let b = &m.types[b_id.0 as usize];
        assert_eq!(b.methods.len(), 1);
        assert_eq!(m.methods[b.methods[0].0 as usize].name, "mb");
        // The dangling call became a raw token; the field operand survived.
        let mb = m.methods.iter().find(|x| x.name == "mb").unwrap();
        let body = mb.body.as_ref().unwrap();
        assert!(matches!(body.instructions[0].operand, ROperand::Token(_)));
        assert!(
            matches!(body.instructions[1].operand, ROperand::Field(FieldRef::Def(id)) if id.0 == 1)
        );
    }

    #[test]
    fn remove_field_renumbers_and_rewires() {
        let mut m = module_with_members();
        m.remove_field(FieldId(0)); // A.f0

        assert_eq!(m.fields.len(), 2);
        assert_eq!(m.fields[0].name, "f1");
        // B.mb's ldsfld pointed at f1 (old index 1) -> now index 0.
        let mb = m.methods.iter().find(|x| x.name == "mb").unwrap();
        let body = mb.body.as_ref().unwrap();
        assert!(
            matches!(body.instructions[1].operand, ROperand::Field(FieldRef::Def(id)) if id.0 == 0)
        );
    }

    #[test]
    fn remove_type_drops_subtree_and_sentinels_references() {
        let mut m = module_with_members();
        let a_id = m.types.iter().position(|t| t.name == "A").map(|i| TypeId(i as u32)).unwrap();
        let b_id = m.types.iter().position(|t| t.name == "B").map(|i| TypeId(i as u32)).unwrap();

        m.remove_type(a_id); // removes A, nested C, their fields and methods

        assert_eq!(m.types.len(), 1);
        assert_eq!(m.types[0].name, "B");
        assert_eq!(m.fields.len(), 1); // fb only
        assert_eq!(m.methods.len(), 1); // mb only
                                        // C's base was A; C is gone too, so just check B survived intact.
                                        // (b_id is a stale pre-removal handle — B compacted to index 0.)
        let b = &m.types[0];
        let _ = b_id;
        assert_eq!(b.fields.len(), 1);
        assert_eq!(b.methods.len(), 1);
        // mb's call operand dangles (A.m0 removed with A) -> nil token.
        let mb = &m.methods[0];
        assert!(matches!(mb.body.as_ref().unwrap().instructions[0].operand, ROperand::Token(_)));
    }

    #[test]
    fn removal_then_write_roundtrips() {
        let mut m = module_with_members();
        let b_id = m.types.iter().position(|t| t.name == "B").map(|i| TypeId(i as u32)).unwrap();
        let _ = b_id;
        m.remove_field(FieldId(0));
        m.remove_method(MethodId(0));

        let asm = crate::assembly::AssemblyDefinition {
            name: crate::assembly::AssemblyNameDefinition {
                name: "t".into(),
                ..Default::default()
            },
            main: m,
            ..Default::default()
        };
        let bytes = asm.write().expect("post-removal write");
        let re = crate::assembly::AssemblyDefinition::read(&bytes).expect("re-read");
        let module = re.main_module();
        assert_eq!(module.types.len(), 3); // B and A remain (C nested in A)
        assert_eq!(module.fields.len(), 2);
        assert_eq!(module.methods.len(), 2);
        assert!(module.fields.iter().all(|f| f.name != "f0"));
        assert!(module.methods.iter().all(|x| x.name != "m0"));
    }
}
