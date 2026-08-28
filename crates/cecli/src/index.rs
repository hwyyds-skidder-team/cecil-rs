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
//!
//! This type is a kind-less projection over [`crate::xref::Xref`], the
//! canonical walker; for usage kinds (call vs. construct, field read vs.
//! write) and the forward direction ("what does this use?"), use
//! [`crate::xref::Xref`] directly.

use std::collections::BTreeMap;

use crate::model::types::{FieldId, MethodId, TypeId};
use crate::xref::Xref;
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

impl From<crate::xref::UsageSite> for ReferenceSite {
    fn from(site: crate::xref::UsageSite) -> Self {
        match site {
            crate::xref::UsageSite::Instruction { method, offset } => {
                ReferenceSite::Instruction { method, offset }
            }
            crate::xref::UsageSite::TypeHead { ty } => ReferenceSite::TypeHead { ty },
            crate::xref::UsageSite::Signature { method, field } => {
                ReferenceSite::Signature { method, field }
            }
        }
    }
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
    /// Builds the index over every body, signature and type head of
    /// `module`. O(module size); build once, query many times.
    ///
    /// Delegates to [`crate::xref::Xref`] (the canonical walker) and
    /// projects the kind-less surface this type documents.
    pub fn build(module: &Module) -> ReferenceIndex {
        let xref = Xref::build(module);
        let mut index = ReferenceIndex::default();
        for (id, usages) in xref.type_users_iter() {
            let v = index.type_users.entry(id).or_default();
            v.extend(usages.iter().map(|u| u.site.clone().into()));
        }
        for (id, usages) in xref.method_users_iter() {
            let v = index.method_users.entry(id).or_default();
            v.extend(usages.iter().map(|u| u.site.clone().into()));
        }
        for (id, usages) in xref.field_users_iter() {
            let v = index.field_users.entry(id).or_default();
            v.extend(usages.iter().map(|u| u.site.clone().into()));
        }
        for (name, usages) in xref.external_type_users_iter() {
            let v = index.external_users.entry(name.to_string()).or_default();
            v.extend(usages.iter().map(|u| u.site.clone().into()));
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{
        AssemblyNameReference, ExternalType, FieldRef, MethodDefinition, MethodRef, ROperand,
        ScopeRef, TypeDefinition, TypeDesc,
    };

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
