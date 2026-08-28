//! Bidirectional cross-reference (xref) analysis.
//!
//! The reverse direction answers "who uses this?" like
//! [`crate::index::ReferenceIndex`] (which delegates here), but every use
//! carries a [`UsageKind`] — callers vs. constructors, field reads vs.
//! writes vs. address-of — and external members are queryable by their
//! `Ns.Type::Member` key, not just external types.
//!
//! The forward direction answers the mirror question "what does this
//! use?": a method's callees and referenced types, a type's base,
//! interfaces, constraints and field-signature dependencies.
//!
//! Build once with [`Xref::build`], query both directions in constant
//! time.

use std::collections::BTreeMap;

use crate::model::types::{
    FieldId, FieldRef, MethodId, MethodRef, RInstruction, ROperand, TypeDesc, TypeId,
};
use crate::Module;

/// How an entity is used at a site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageKind {
    /// `call` / `callvirt`.
    Call,
    /// `newobj`.
    NewObject,
    /// Field value read (`ldfld*`, `ldsfld*`).
    FieldLoad,
    /// Field write (`stfld*`, `stsfld*`).
    FieldStore,
    /// Field address (`ldflda`, `ldsflda`).
    FieldAddress,
    /// Type operand (`box`, `castclass`, `newarr`, `ldtoken`, `initobj`, ...).
    TypeOperand,
    /// Base type of a type definition.
    BaseType,
    /// Implemented interface.
    Interface,
    /// Generic-parameter constraint.
    Constraint,
    /// Inside a member signature (parameter, return, local or field type).
    Signature,
}

/// Where a use happens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsageSite {
    /// Instruction operand inside `method`'s body at IL offset `offset`.
    Instruction { method: MethodId, offset: i32 },
    /// Base type / interface / constraint of `ty`.
    TypeHead { ty: TypeId },
    /// Member signature: a method's or a field's.
    Signature { method: Option<MethodId>, field: Option<FieldId> },
}

/// One recorded use of an entity (reverse direction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub kind: UsageKind,
    pub site: UsageSite,
}

/// What is being used (forward direction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UsedEntity {
    Type(TypeId),
    /// External type by reflection-style full name.
    ExternalType(String),
    Method(MethodId),
    /// External method by `Ns.Type::Method` key.
    ExternalMethod(String),
    Field(FieldId),
    /// External field by `Ns.Type::Field` key.
    ExternalField(String),
}

/// One dependency of a method or type (forward direction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Use {
    pub kind: UsageKind,
    pub entity: UsedEntity,
}

/// Where forward-direction uses accumulate.
#[derive(Debug, Clone, Copy)]
enum ForwardOwner {
    Type(TypeId),
    Method(MethodId),
    /// Orphan field with no owning type: reverse-only.
    Field,
}

/// Bidirectional cross-reference index of one module.
#[derive(Debug, Default, Clone)]
pub struct Xref {
    type_users: BTreeMap<TypeId, Vec<Usage>>,
    method_users: BTreeMap<MethodId, Vec<Usage>>,
    field_users: BTreeMap<FieldId, Vec<Usage>>,
    external_type_users: BTreeMap<String, Vec<Usage>>,
    external_method_users: BTreeMap<String, Vec<Usage>>,
    external_field_users: BTreeMap<String, Vec<Usage>>,
    method_uses: BTreeMap<MethodId, Vec<Use>>,
    type_uses: BTreeMap<TypeId, Vec<Use>>,
}

impl Xref {
    /// Walks every type head, field signature, method signature, local and
    /// instruction operand of `module` once, recording both directions.
    pub fn build(module: &Module) -> Xref {
        let mut x = Xref::default();

        // Field ownership (fields carry no declaring-type backref).
        let mut field_owner: BTreeMap<FieldId, TypeId> = BTreeMap::new();
        for (tid, ty) in module.types.iter().enumerate() {
            let tid = TypeId(tid as u32);
            for &fid in &ty.fields {
                field_owner.insert(fid, tid);
            }
        }

        // Type heads: base, interfaces, generic constraints.
        for (tid, ty) in module.types.iter().enumerate() {
            let tid = TypeId(tid as u32);
            let owner = ForwardOwner::Type(tid);
            if let Some(base) = &ty.base_type {
                x.walk_type_desc(base, UsageKind::BaseType, UsageSite::TypeHead { ty: tid }, owner);
            }
            for iface in &ty.interfaces {
                x.walk_type_desc(
                    &iface.interface,
                    UsageKind::Interface,
                    UsageSite::TypeHead { ty: tid },
                    owner,
                );
            }
            for &gp in &ty.generic_parameters {
                let Some(gp) = module.generic_parameters.get(gp.index()) else { continue };
                for constraint in &gp.constraints {
                    x.walk_type_desc(
                        &constraint.constraint,
                        UsageKind::Constraint,
                        UsageSite::TypeHead { ty: tid },
                        owner,
                    );
                }
            }
        }

        // Field signatures (reverse always; forward attributed to the owner).
        for (fid, field) in module.fields.iter().enumerate() {
            let fid = FieldId(fid as u32);
            let site = UsageSite::Signature { method: None, field: Some(fid) };
            let owner = field_owner
                .get(&fid)
                .map(|&t| ForwardOwner::Type(t))
                .unwrap_or(ForwardOwner::Field);
            x.walk_type_desc(&field.signature.0, UsageKind::Signature, site, owner);
        }

        // Method signatures, locals and bodies.
        for (mid, method) in module.methods.iter().enumerate() {
            let mid = MethodId(mid as u32);
            let owner = ForwardOwner::Method(mid);
            let sig_site = UsageSite::Signature { method: Some(mid), field: None };
            x.walk_type_desc(
                &method.signature.return_type,
                UsageKind::Signature,
                sig_site.clone(),
                owner,
            );
            for p in &method.signature.parameters {
                x.walk_type_desc(p, UsageKind::Signature, sig_site.clone(), owner);
            }
            for &gp in &method.generic_parameters {
                let Some(gp) = module.generic_parameters.get(gp.index()) else { continue };
                for constraint in &gp.constraints {
                    x.walk_type_desc(
                        &constraint.constraint,
                        UsageKind::Constraint,
                        sig_site.clone(),
                        owner,
                    );
                }
            }
            let Some(body) = &method.body else { continue };
            for local in &body.locals {
                x.walk_type_desc(&local.ty, UsageKind::Signature, sig_site.clone(), owner);
            }
            for ins in &body.instructions {
                x.record_instruction(ins, mid);
            }
        }

        x
    }

    // -- reverse queries -----------------------------------------------------

    /// Everything that references a locally-defined type.
    pub fn users_of_type(&self, id: TypeId) -> &[Usage] {
        self.type_users.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Everything that invokes a locally-defined method (calls and
    /// constructions).
    pub fn callers_of(&self, id: MethodId) -> &[Usage] {
        self.method_users.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Every access of a locally-defined field; filter by
    /// [`UsageKind::FieldLoad`] / [`UsageKind::FieldStore`] /
    /// [`UsageKind::FieldAddress`] for direction.
    pub fn field_accesses(&self, id: FieldId) -> &[Usage] {
        self.field_users.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Everything that references an external type by full name.
    pub fn users_of_external_type(&self, full_name: &str) -> &[Usage] {
        self.external_type_users.get(full_name).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Everything that calls an external method by `Ns.Type::Method` key.
    pub fn users_of_external_method(&self, key: &str) -> &[Usage] {
        self.external_method_users.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Everything that accesses an external field by `Ns.Type::Field` key.
    pub fn users_of_external_field(&self, key: &str) -> &[Usage] {
        self.external_field_users.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    // -- forward queries -----------------------------------------------------

    /// Everything a method uses: callees, field accesses, type operands,
    /// signature types, local types.
    pub fn uses_of_method(&self, id: MethodId) -> &[Use] {
        self.method_uses.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// What a method calls (local and external methods, constructors).
    pub fn callees_of(&self, id: MethodId) -> Vec<&Use> {
        self.uses_of_method(id)
            .iter()
            .filter(|u| {
                matches!(u.entity, UsedEntity::Method(_) | UsedEntity::ExternalMethod(_))
                    && matches!(u.kind, UsageKind::Call | UsageKind::NewObject)
            })
            .collect()
    }

    /// A type's dependencies: base type, interfaces, constraints and the
    /// types appearing in its field signatures.
    pub fn dependencies_of_type(&self, id: TypeId) -> &[Use] {
        self.type_uses.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    // -- iteration (projections, used by crate::index) -----------------------

    pub fn type_users_iter(&self) -> impl Iterator<Item = (TypeId, &[Usage])> {
        self.type_users.iter().map(|(k, v)| (*k, v.as_slice()))
    }

    pub fn method_users_iter(&self) -> impl Iterator<Item = (MethodId, &[Usage])> {
        self.method_users.iter().map(|(k, v)| (*k, v.as_slice()))
    }

    pub fn field_users_iter(&self) -> impl Iterator<Item = (FieldId, &[Usage])> {
        self.field_users.iter().map(|(k, v)| (*k, v.as_slice()))
    }

    pub fn external_type_users_iter(&self) -> impl Iterator<Item = (&str, &[Usage])> {
        self.external_type_users.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }

    // -- recording -----------------------------------------------------------

    fn record(
        &mut self,
        entity: UsedEntity,
        kind: UsageKind,
        site: UsageSite,
        owner: ForwardOwner,
    ) {
        let map = match &entity {
            UsedEntity::Type(id) => &mut self.type_users.entry(*id).or_default(),
            UsedEntity::Method(id) => &mut self.method_users.entry(*id).or_default(),
            UsedEntity::Field(id) => &mut self.field_users.entry(*id).or_default(),
            UsedEntity::ExternalType(name) => {
                &mut self.external_type_users.entry(name.clone()).or_default()
            }
            UsedEntity::ExternalMethod(key) => {
                &mut self.external_method_users.entry(key.clone()).or_default()
            }
            UsedEntity::ExternalField(key) => {
                &mut self.external_field_users.entry(key.clone()).or_default()
            }
        };
        map.push(Usage { kind, site: site.clone() });

        let forward = match owner {
            ForwardOwner::Type(tid) => &mut self.type_uses.entry(tid).or_default(),
            ForwardOwner::Method(mid) => &mut self.method_uses.entry(mid).or_default(),
            // Orphan field with no owning type: reverse-only.
            ForwardOwner::Field => return,
        };
        forward.push(Use { kind, entity });
    }

    /// Visits every Def/External leaf of a type descriptor tree (including
    /// external nesting chains and signature types inside function
    /// pointers), recording each as used with `kind` at `site`.
    fn walk_type_desc(
        &mut self,
        ty: &TypeDesc,
        kind: UsageKind,
        site: UsageSite,
        owner: ForwardOwner,
    ) {
        match ty {
            TypeDesc::Def(id) => {
                self.record(UsedEntity::Type(*id), kind, site, owner);
            }
            TypeDesc::External(ext) => {
                for nested in &ext.nesting {
                    // A nested-type spelling names every ancestor too.
                    self.record(
                        UsedEntity::ExternalType(external_full_name(nested)),
                        kind,
                        site.clone(),
                        owner,
                    );
                }
                self.record(UsedEntity::ExternalType(external_full_name(ext)), kind, site, owner);
            }
            TypeDesc::GenericInstance { definition, arguments } => {
                self.walk_type_desc(definition, kind, site.clone(), owner);
                for arg in arguments {
                    self.walk_type_desc(arg, kind, site.clone(), owner);
                }
            }
            TypeDesc::SzArray(e) | TypeDesc::Ptr(e) | TypeDesc::ByRef(e) | TypeDesc::Pinned(e) => {
                self.walk_type_desc(e, kind, site, owner);
            }
            TypeDesc::Array { element, .. } => self.walk_type_desc(element, kind, site, owner),
            TypeDesc::CMod { modifier, unmodified, .. } => {
                self.walk_type_desc(modifier, kind, site.clone(), owner);
                self.walk_type_desc(unmodified, kind, site, owner);
            }
            TypeDesc::FnPtr(sig) => {
                self.walk_type_desc(&sig.return_type, kind, site.clone(), owner);
                for p in &sig.parameters {
                    self.walk_type_desc(p, kind, site.clone(), owner);
                }
            }
            _ => {}
        }
    }

    fn record_instruction(&mut self, ins: &RInstruction, mid: MethodId) {
        let site = UsageSite::Instruction { method: mid, offset: ins.offset };
        let owner = ForwardOwner::Method(mid);
        match &ins.operand {
            ROperand::Method(mr) => {
                let kind = if ins.opcode.name == "newobj" {
                    UsageKind::NewObject
                } else {
                    UsageKind::Call
                };
                self.record_method_ref(mr, kind, site, owner);
            }
            ROperand::Field(fr) => {
                let name = ins.opcode.name;
                let kind = if name.starts_with("st") {
                    UsageKind::FieldStore
                } else if name.ends_with('a') {
                    UsageKind::FieldAddress
                } else {
                    UsageKind::FieldLoad
                };
                self.record_field_ref(fr, kind, site, owner);
            }
            ROperand::Type(ty) => {
                self.walk_type_desc(ty, UsageKind::TypeOperand, site, owner);
            }
            // calli: no named target; its signature's types are used.
            ROperand::CallSite(sig) => {
                self.walk_type_desc(&sig.return_type, UsageKind::TypeOperand, site.clone(), owner);
                for p in &sig.parameters {
                    self.walk_type_desc(p, UsageKind::TypeOperand, site.clone(), owner);
                }
            }
            _ => {}
        }
    }

    fn record_method_ref(
        &mut self,
        mr: &MethodRef,
        kind: UsageKind,
        site: UsageSite,
        owner: ForwardOwner,
    ) {
        match mr {
            MethodRef::Def(id) => {
                self.record(UsedEntity::Method(*id), kind, site, owner);
            }
            MethodRef::External(ext) => {
                let key = format!("{}::{}", external_full_name_of(&ext.parent), ext.name);
                self.record(UsedEntity::ExternalMethod(key), kind, site.clone(), owner);
                // The call also uses the declaring type and the signature's
                // types.
                self.walk_type_desc(&ext.parent, kind, site.clone(), owner);
                self.walk_type_desc(
                    &ext.signature.return_type,
                    UsageKind::Signature,
                    site.clone(),
                    owner,
                );
                for p in &ext.signature.parameters {
                    self.walk_type_desc(p, UsageKind::Signature, site.clone(), owner);
                }
            }
            MethodRef::Spec { method, arguments } => {
                for arg in arguments {
                    self.walk_type_desc(arg, UsageKind::TypeOperand, site.clone(), owner);
                }
                self.record_method_ref(method, kind, site, owner);
            }
        }
    }

    fn record_field_ref(
        &mut self,
        fr: &FieldRef,
        kind: UsageKind,
        site: UsageSite,
        owner: ForwardOwner,
    ) {
        match fr {
            FieldRef::Def(id) => {
                self.record(UsedEntity::Field(*id), kind, site, owner);
            }
            FieldRef::External(ext) => {
                let key = format!("{}::{}", external_full_name_of(&ext.parent), ext.name);
                self.record(UsedEntity::ExternalField(key), kind, site.clone(), owner);
                self.walk_type_desc(&ext.parent, kind, site.clone(), owner);
                self.walk_type_desc(&ext.signature.0, UsageKind::Signature, site, owner);
            }
        }
    }
}

/// Reflection-style full name of an external type: `Ns.Outer/Inner`.
pub(crate) fn external_full_name(ext: &crate::model::types::ExternalType) -> String {
    let mut name = String::new();
    if !ext.namespace.is_empty() {
        name.push_str(&ext.namespace);
        name.push('.');
    }
    for nested in &ext.nesting {
        name.push_str(&nested.name);
        name.push('/');
    }
    name.push_str(&ext.name);
    name
}

/// Full name of the type inside a TypeDesc (external form; Def callers use
/// `Module::type_full_name` instead).
fn external_full_name_of(ty: &TypeDesc) -> String {
    match ty {
        TypeDesc::External(ext) => external_full_name(ext),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{
        AssemblyNameReference, ExternalMethod, ExternalType, FieldDefinition, FieldRef,
        FieldSignature, MethodDefinition, MethodSignature, ScopeRef, TypeDefinition,
    };

    fn ext(ns: &str, name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: ns.into(),
            name: name.into(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(AssemblyNameReference::new("mscorlib")),
        }))
    }

    fn ext_method(ns: &str, ty: &str, name: &str, params: Vec<TypeDesc>) -> MethodRef {
        MethodRef::External(ExternalMethod {
            parent: ext(ns, ty),
            name: name.into(),
            signature: MethodSignature { parameters: params, ..Default::default() },
        })
    }

    /// Point : ValueType; Greeter : Object with field origin: Point;
    /// Point::Callee; Greeter::Caller body: call Callee, ldsfld origin,
    /// stsfld counter, call Console::WriteLine(string).
    fn sample() -> Module {
        use crate::model::types::{RInstruction as RI, ROperand};

        let mut module = Module { name: "sample".into(), ..Default::default() };

        let point = module.add_type(TypeDefinition {
            namespace: "Demo".into(),
            name: "Point".into(),
            base_type: Some(ext("System", "ValueType")),
            ..Default::default()
        });
        let greeter = module.add_type(TypeDefinition {
            namespace: "Demo".into(),
            name: "Greeter".into(),
            base_type: Some(ext("System", "Object")),
            ..Default::default()
        });
        let origin = module.add_field(
            point,
            FieldDefinition {
                name: "origin".into(),
                signature: FieldSignature(TypeDesc::Def(greeter)),
                ..Default::default()
            },
        );
        let counter = module.add_field(
            greeter,
            FieldDefinition {
                name: "counter".into(),
                signature: FieldSignature(TypeDesc::Internal("int32".into())),
                ..Default::default()
            },
        );

        let callee = module
            .add_method(point, MethodDefinition { name: "Callee".into(), ..Default::default() });
        let caller = module
            .add_method(greeter, MethodDefinition { name: "Caller".into(), ..Default::default() });

        let body = crate::model::types::ResolvedBody {
            max_stack: 8,
            instructions: vec![
                RI {
                    offset: 0,
                    opcode: cecli_cil::opcodes::CALL,
                    operand: ROperand::Method(MethodRef::Def(callee)),
                },
                RI {
                    offset: 5,
                    opcode: cecli_cil::opcodes::LDSFLD,
                    operand: ROperand::Field(FieldRef::Def(origin)),
                },
                RI {
                    offset: 10,
                    opcode: cecli_cil::opcodes::STSFLD,
                    operand: ROperand::Field(FieldRef::Def(counter)),
                },
                RI {
                    offset: 15,
                    opcode: cecli_cil::opcodes::CALL,
                    operand: ROperand::Method(ext_method(
                        "System",
                        "Console",
                        "WriteLine",
                        vec![TypeDesc::Internal("string".into())],
                    )),
                },
                RI { offset: 20, opcode: cecli_cil::opcodes::RET, operand: ROperand::None },
            ],
            ..Default::default()
        };
        module.methods[caller.index()].body = Some(body);
        module
    }

    #[test]
    fn reverse_with_kinds() {
        let m = sample();
        let x = Xref::build(&m);

        // Callee: one call site.
        let callers = x.callers_of(MethodId(0));
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0].kind, UsageKind::Call);
        assert_eq!(callers[0].site, UsageSite::Instruction { method: MethodId(1), offset: 0 });

        // counter: one store.
        let accesses = x.field_accesses(FieldId(1));
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].kind, UsageKind::FieldStore);
        assert_eq!(accesses[0].site, UsageSite::Instruction { method: MethodId(1), offset: 10 });

        // origin: one load.
        let accesses = x.field_accesses(FieldId(0));
        assert_eq!(accesses.len(), 1);
        assert_eq!(accesses[0].kind, UsageKind::FieldLoad);

        // External method keyed by Parent::Name.
        let wl = x.users_of_external_method("System.Console::WriteLine");
        assert_eq!(wl.len(), 1);
        assert_eq!(wl[0].kind, UsageKind::Call);

        // External type users keep working.
        assert!(!x.users_of_external_type("System.Object").is_empty());
        assert!(!x.users_of_external_type("System.ValueType").is_empty());
    }

    #[test]
    fn forward_with_kinds() {
        let m = sample();
        let x = Xref::build(&m);

        // Caller calls Callee and Console::WriteLine.
        let callees = x.callees_of(MethodId(1));
        let names: Vec<&UsedEntity> = callees.iter().map(|u| &u.entity).collect();
        assert!(names.contains(&&UsedEntity::Method(MethodId(0))), "{names:?}");
        assert!(
            names.contains(&&UsedEntity::ExternalMethod("System.Console::WriteLine".into())),
            "{names:?}"
        );

        // Caller's full use list includes the field accesses.
        let uses = x.uses_of_method(MethodId(1));
        assert!(uses
            .iter()
            .any(|u| u.kind == UsageKind::FieldLoad && u.entity == UsedEntity::Field(FieldId(0))));
        assert!(uses
            .iter()
            .any(|u| u.kind == UsageKind::FieldStore && u.entity == UsedEntity::Field(FieldId(1))));

        // Point depends on System.ValueType (base) and Greeter (field type).
        let deps = x.dependencies_of_type(TypeId(0));
        assert!(deps.iter().any(|u| u.kind == UsageKind::BaseType
            && u.entity == UsedEntity::ExternalType("System.ValueType".into())));
        assert!(deps
            .iter()
            .any(|u| u.kind == UsageKind::Signature && u.entity == UsedEntity::Type(TypeId(1))));
    }

    /// ReferenceIndex (delegating projection) keeps its documented behavior.
    #[test]
    fn index_projection_unchanged() {
        let m = sample();
        let index = crate::index::ReferenceIndex::build(&m);
        let greeter_users = index.type_users(TypeId(1));
        assert_eq!(greeter_users.len(), 1, "field signature site only");
        let callers = index.method_users(MethodId(0));
        assert_eq!(callers.len(), 1);
        assert!(!index.external_users("System.Object").is_empty());
    }
}
