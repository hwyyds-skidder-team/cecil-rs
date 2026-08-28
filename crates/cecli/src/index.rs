//! Reverse reference index: "who uses this type / method / field?".
//!
//! Cecil offers no built-in answer — analysis tools walk every method body
//! by hand. This module builds the inverted mapping once
//! ([`ReferenceIndex::build`]) and answers member-level queries in constant
//! time. Coverage:
//!
//! * instruction operands (method calls, field loads/stores, type operands
//!   such as `box`/`castclass`/`newarr`),
//! * member signatures (method parameter/return types, field types, property
//!   types, local-variable types),
//! * type heads (base type, implemented interfaces, generic constraints).
//!
//! External references are keyed by reflection-style full name
//! (`Ns.Outer/Inner`), the same spelling [`Module::type_full_name`] uses.

use std::collections::BTreeMap;

use crate::model::types::{
    ExternalType, FieldId, FieldRef, MethodId, MethodRef, ROperand, TypeDesc, TypeId,
};
use crate::Module;

/// One recorded use of an entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceSite {
    /// Instruction operand inside `method`'s body at IL offset `offset`.
    Instruction { method: MethodId, offset: i32 },
    /// The base type / an interface / a generic constraint of `ty`.
    TypeHead { ty: TypeId },
    /// The signature (parameters/return/field/local type) of the member.
    Signature { method: Option<MethodId>, field: Option<FieldId> },
}

/// Inverted index from definitions and external names to their use sites.
#[derive(Debug, Default, Clone)]
pub struct ReferenceIndex {
    type_users: BTreeMap<TypeId, Vec<ReferenceSite>>,
    method_users: BTreeMap<MethodId, Vec<ReferenceSite>>,
    field_users: BTreeMap<FieldId, Vec<ReferenceSite>>,
    external_users: BTreeMap<String, Vec<ReferenceSite>>,
}

impl ReferenceIndex {
    /// Walks every body, signature and type head of `module`, recording use
    /// sites. O(module size); build once, query many times.
    pub fn build(module: &Module) -> ReferenceIndex {
        let mut index = ReferenceIndex::default();

        for (tid, ty) in module.types.iter().enumerate() {
            let tid = TypeId(tid as u32);
            if let Some(base) = &ty.base_type {
                index.record_type_desc(base, ReferenceSite::TypeHead { ty: tid });
            }
            for iface in &ty.interfaces {
                index.record_type_desc(&iface.interface, ReferenceSite::TypeHead { ty: tid });
            }
            for &gp in &ty.generic_parameters {
                let Some(gp) = module.generic_parameters.get(gp.index()) else { continue };
                for constraint in &gp.constraints {
                    index.record_type_desc(
                        &constraint.constraint,
                        ReferenceSite::TypeHead { ty: tid },
                    );
                }
            }
        }

        for (fid, field) in module.fields.iter().enumerate() {
            let fid = FieldId(fid as u32);
            index.record_type_desc(
                &field.signature.0,
                ReferenceSite::Signature { method: None, field: Some(fid) },
            );
        }

        for (mid, method) in module.methods.iter().enumerate() {
            let mid = MethodId(mid as u32);
            let sig_site = ReferenceSite::Signature { method: Some(mid), field: None };
            index.record_type_desc(&method.signature.return_type, sig_site.clone());
            for p in &method.signature.parameters {
                index.record_type_desc(p, sig_site.clone());
            }
            for &gp in &method.generic_parameters {
                let Some(gp) = module.generic_parameters.get(gp.index()) else { continue };
                for constraint in &gp.constraints {
                    index.record_type_desc(&constraint.constraint, sig_site.clone());
                }
            }

            let Some(body) = &method.body else { continue };
            for local in &body.locals {
                index.record_type_desc(&local.ty, sig_site.clone());
            }
            for ins in &body.instructions {
                let site = ReferenceSite::Instruction { method: mid, offset: ins.offset };
                match &ins.operand {
                    ROperand::Type(ty) => index.record_type_desc(ty, site),
                    ROperand::Method(mr) => index.record_method_ref(mr, site),
                    ROperand::Field(fr) => index.record_field_ref(fr, site),
                    _ => {}
                }
            }
        }

        index
    }

    /// Use sites of a locally-defined type.
    pub fn type_users(&self, id: TypeId) -> &[ReferenceSite] {
        self.type_users.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Use sites of a locally-defined method (calls, overrides).
    pub fn method_users(&self, id: MethodId) -> &[ReferenceSite] {
        self.method_users.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Use sites of a locally-defined field (loads/stores).
    pub fn field_users(&self, id: FieldId) -> &[ReferenceSite] {
        self.field_users.get(&id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Use sites of an external type by full name (`Ns.Outer/Inner`).
    pub fn external_users(&self, full_name: &str) -> &[ReferenceSite] {
        self.external_users.get(full_name).map(Vec::as_slice).unwrap_or(&[])
    }

    // -- recording -----------------------------------------------------------

    fn push_type(&mut self, id: TypeId, site: ReferenceSite) {
        self.type_users.entry(id).or_default().push(site);
    }

    fn push_method(&mut self, id: MethodId, site: ReferenceSite) {
        self.method_users.entry(id).or_default().push(site);
    }

    fn push_field(&mut self, id: FieldId, site: ReferenceSite) {
        self.field_users.entry(id).or_default().push(site);
    }

    fn push_external(&mut self, name: String, site: ReferenceSite) {
        self.external_users.entry(name).or_default().push(site);
    }

    fn record_type_desc(&mut self, ty: &TypeDesc, site: ReferenceSite) {
        match ty {
            TypeDesc::Def(id) => self.push_type(*id, site),
            TypeDesc::External(ext) => {
                for nested in &ext.nesting {
                    // The enclosing chain is referenced too (a nested-type
                    // spelling names every ancestor).
                    self.push_external(external_full_name(nested), site.clone());
                }
                self.push_external(external_full_name(ext), site);
            }
            TypeDesc::GenericInstance { definition, arguments } => {
                self.record_type_desc(definition, site.clone());
                for arg in arguments {
                    self.record_type_desc(arg, site.clone());
                }
            }
            TypeDesc::SzArray(e) | TypeDesc::Ptr(e) | TypeDesc::ByRef(e) | TypeDesc::Pinned(e) => {
                self.record_type_desc(e, site)
            }
            TypeDesc::Array { element, .. } => self.record_type_desc(element, site),
            TypeDesc::CMod { modifier, unmodified, .. } => {
                self.record_type_desc(modifier, site.clone());
                self.record_type_desc(unmodified, site);
            }
            TypeDesc::FnPtr(sig) => {
                self.record_type_desc(&sig.return_type, site.clone());
                for p in &sig.parameters {
                    self.record_type_desc(p, site.clone());
                }
            }
            _ => {}
        }
    }

    fn record_method_ref(&mut self, r: &MethodRef, site: ReferenceSite) {
        match r {
            MethodRef::Def(id) => self.push_method(*id, site),
            MethodRef::External(ext) => {
                // Method use implies the declaring type is used as well.
                self.record_type_desc(&ext.parent, site.clone());
                for p in &ext.signature.parameters {
                    self.record_type_desc(p, site.clone());
                }
                self.record_type_desc(&ext.signature.return_type, site);
            }
            MethodRef::Spec { method, arguments } => {
                self.record_method_ref(method, site.clone());
                for arg in arguments {
                    self.record_type_desc(arg, site.clone());
                }
            }
        }
    }

    fn record_field_ref(&mut self, r: &FieldRef, site: ReferenceSite) {
        match r {
            FieldRef::Def(id) => self.push_field(*id, site),
            FieldRef::External(ext) => {
                self.record_type_desc(&ext.parent, site.clone());
                self.record_type_desc(&ext.signature.0, site);
            }
        }
    }
}

/// Reflection-style full name of an external type: `Ns.Outer/Inner`.
fn external_full_name(ext: &ExternalType) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{AssemblyNameReference, MethodDefinition, ScopeRef, TypeDefinition};

    fn ext(ns: &str, name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: ns.into(),
            name: name.into(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(AssemblyNameReference::new("mscorlib")),
        }))
    }

    /// Two types: Greeter (base = external Object) with a field of local type
    /// Point and a method calling the other method; Point : ValueType.
    fn sample() -> Module {
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
        let field = module.add_field(
            point,
            crate::model::types::FieldDefinition {
                name: "origin".into(),
                signature: crate::model::types::FieldSignature(TypeDesc::Def(greeter)),
                ..Default::default()
            },
        );

        let callee = module
            .add_method(point, MethodDefinition { name: "Callee".into(), ..Default::default() });
        let caller = module.add_method(
            greeter,
            MethodDefinition {
                name: "Caller".into(),
                signature: crate::model::types::MethodSignature {
                    parameters: vec![TypeDesc::Def(point)],
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        // Build a minimal body: ldarg.0-ish var load, call Callee, ret.
        let mid = caller;
        let body = crate::model::types::ResolvedBody {
            max_stack: 1,
            instructions: vec![
                crate::model::types::RInstruction {
                    offset: 0,
                    opcode: cecli_cil::opcodes::LDC_I4_0,
                    operand: ROperand::None,
                },
                crate::model::types::RInstruction {
                    offset: 1,
                    opcode: cecli_cil::opcodes::CALL,
                    operand: ROperand::Method(MethodRef::Def(callee)),
                },
                crate::model::types::RInstruction {
                    offset: 6,
                    opcode: cecli_cil::opcodes::LDSFLD,
                    operand: ROperand::Field(FieldRef::Def(field)),
                },
                crate::model::types::RInstruction {
                    offset: 11,
                    opcode: cecli_cil::opcodes::RET,
                    operand: ROperand::None,
                },
            ],
            ..Default::default()
        };
        module.methods[mid.index()].body = Some(body);
        module
    }

    #[test]
    fn index_answers_reverse_queries() {
        let m = sample();
        let index = ReferenceIndex::build(&m);

        // Greeter type: used by Point.origin's field signature.
        let greeter_users = index.type_users(TypeId(1));
        assert_eq!(greeter_users.len(), 1, "field signature site");
        assert!(matches!(
            greeter_users[0],
            ReferenceSite::Signature { field: Some(FieldId(0)), .. }
        ));

        // Callee method: one call site.
        let callee_users = index.method_users(MethodId(0));
        assert_eq!(callee_users.len(), 1);
        assert_eq!(callee_users[0], ReferenceSite::Instruction { method: MethodId(1), offset: 1 });

        // origin field: one ldsfld site.
        let field_users = index.field_users(FieldId(0));
        assert_eq!(field_users.len(), 1);
        assert_eq!(field_users[0], ReferenceSite::Instruction { method: MethodId(1), offset: 6 });

        // Externals by full name.
        assert!(!index.external_users("System.Object").is_empty());
        assert!(!index.external_users("System.ValueType").is_empty());
        assert!(index.external_users("System.Missing").is_empty());

        // The caller method references Point through its parameter type.
        let point_users = index.type_users(TypeId(0));
        assert!(
            point_users
                .iter()
                .any(|s| matches!(s, ReferenceSite::Signature { method: Some(MethodId(1)), .. })),
            "parameter signature site recorded"
        );
    }
}
