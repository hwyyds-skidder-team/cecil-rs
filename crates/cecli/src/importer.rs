//! Cross-module reference remapping (port of Mono.Cecil `Import.cs` /
//! `DefaultMetadataImporter`).
//!
//! A [`TypeDesc`] built against one [`Module`] cannot be stored into another
//! module verbatim: `Def` handles index the *source* arena, and external
//! scopes reference the *source* module's assembly references. The importer
//! rebuilds such references so they are valid in a *target* module:
//!
//! * A local definition (`Def`) maps to the matching `Def` in the target when
//!   one exists (same namespace, name, and declaring-type chain), otherwise to
//!   an [`TypeDesc::External`] whose scope is the best [`ScopeRef::Assembly`]
//!   match for the source module's own assembly name in
//!   `target.assembly_refs`, falling back to [`ScopeRef::Moduleless`] (v1 does
//!   not append a new `AssemblyRef` row; Mono.Cecil would add one).
//! * Composite shapes (`SzArray`, `Array`, `Ptr`, `ByRef`, `Pinned`,
//!   `GenericInstance`, `FnPtr`, `CMod`) recurse into their element types /
//!   signatures. `Var` / `MVar` are context-bound numbers and pass through
//!   untouched.
//! * Already-external references are re-scoped against the target's assembly
//!   references by name (`ThisModule` scope is treated as source-local).
//!
//! Matching rule (documented contract): a `Def` maps to `Def(target)` only via
//! the structural scan in [`find_matching`] - there is no deep semantic merge
//! (no member-by-member unification) in v1.

use crate::model::types::{
    ExternalField, ExternalMethod, ExternalType, FieldRef, FieldSignature, MethodRef,
    MethodSignature, ScopeRef, TypeDefinition, TypeDesc, TypeId,
};
use crate::module_def::Module;

/// Remaps references from [`Self::source`] so they are usable in
/// [`Self::target`].
///
/// Mirrors Mono.Cecil's `DefaultMetadataImporter`; see the [module docs](self)
/// for the matching rules.
#[derive(Debug)]
pub struct Importer<'a> {
    /// Module the incoming references were built against.
    pub source: &'a Module,
    /// Module the remapped references must be valid in.
    pub target: &'a Module,
}

impl<'a> Importer<'a> {
    /// Creates an importer remapping `source` references into `target`.
    pub fn new(source: &'a Module, target: &'a Module) -> Self {
        Importer { source, target }
    }

    /// Imports a type reference (free-function form: [`import_type`]).
    pub fn import_type(&self, ty: &TypeDesc) -> TypeDesc {
        match ty {
            TypeDesc::Def(id) => self.import_def(*id),
            TypeDesc::External(ext) => {
                TypeDesc::External(Box::new(self.rebuild_external(ext)))
            }
            TypeDesc::SzArray(element) => {
                TypeDesc::SzArray(Box::new(self.import_type(element)))
            }
            TypeDesc::Array {
                element,
                sizes,
                lobounds,
            } => TypeDesc::Array {
                element: Box::new(self.import_type(element)),
                sizes: sizes.clone(),
                lobounds: lobounds.clone(),
            },
            TypeDesc::Ptr(pointee) => TypeDesc::Ptr(Box::new(self.import_type(pointee))),
            TypeDesc::ByRef(pointee) => TypeDesc::ByRef(Box::new(self.import_type(pointee))),
            TypeDesc::Pinned(pointee) => TypeDesc::Pinned(Box::new(self.import_type(pointee))),
            TypeDesc::GenericInstance {
                definition,
                arguments,
            } => TypeDesc::GenericInstance {
                definition: Box::new(self.import_type(definition)),
                arguments: arguments.iter().map(|a| self.import_type(a)).collect(),
            },
            TypeDesc::FnPtr(signature) => {
                TypeDesc::FnPtr(Box::new(self.import_signature(signature)))
            }
            TypeDesc::CMod {
                required,
                modifier,
                unmodified,
            } => TypeDesc::CMod {
                required: *required,
                modifier: Box::new(self.import_type(modifier)),
                unmodified: Box::new(self.import_type(unmodified)),
            },
            // Context-bound or leaf values carry no cross-module state.
            TypeDesc::Var(_) | TypeDesc::MVar(_) | TypeDesc::Sentinel => ty.clone(),
            TypeDesc::TypedByRef | TypeDesc::Internal(_) => ty.clone(),
        }
    }

    /// Imports a method reference (free-function form: [`import_method`]).
    ///
    /// A `Def` is always rebuilt as an [`ExternalMethod`] cloned from the
    /// source definition (name + remapped signature + remapped parent); v1
    /// performs no member-level merge even when the declaring type resolves to
    /// a `Def` in the target.
    pub fn import_method(&self, r: &MethodRef) -> MethodRef {
        match r {
            MethodRef::Def(id) => {
                let method = &self.source.methods[id.index()];
                let parent = self.import_type(&TypeDesc::Def(method.declaring_type));
                MethodRef::External(ExternalMethod {
                    parent,
                    name: method.name.clone(),
                    signature: self.import_signature(&method.signature),
                })
            }
            MethodRef::External(external) => MethodRef::External(ExternalMethod {
                parent: self.import_type(&external.parent),
                name: external.name.clone(),
                signature: self.import_signature(&external.signature),
            }),
            MethodRef::Spec { method, arguments } => MethodRef::Spec {
                method: Box::new(self.import_method(method)),
                arguments: arguments.iter().map(|a| self.import_type(a)).collect(),
            },
        }
    }

    /// Imports a field reference (free-function form: [`import_field`]).
    ///
    /// A `Def` is always rebuilt as an [`ExternalField`] cloned from the source
    /// definition, mirroring [`Importer::import_method`].
    pub fn import_field(&self, r: &FieldRef) -> FieldRef {
        match r {
            FieldRef::Def(id) => {
                let field = &self.source.fields[id.index()];
                // Recover the declaring type by scanning the source arenas:
                // fields do not back-reference their owner, so take the first
                // type listing this field. Valid modules always contain one.
                let parent = self
                    .source
                    .types
                    .iter()
                    .position(|t| t.fields.iter().any(|f| *f == *id))
                    .map(|i| self.import_type(&TypeDesc::Def(TypeId(i as u32))))
                    .unwrap_or_else(|| self.source_local_external());
                FieldRef::External(ExternalField {
                    parent,
                    name: field.name.clone(),
                    signature: FieldSignature(self.import_type(&field.signature.0)),
                })
            }
            FieldRef::External(external) => FieldRef::External(ExternalField {
                parent: self.import_type(&external.parent),
                name: external.name.clone(),
                signature: FieldSignature(self.import_type(&external.signature.0)),
            }),
        }
    }


    /// Imports every [`TypeDesc`] inside a method signature.
    pub fn import_signature(&self, sig: &MethodSignature) -> MethodSignature {
        MethodSignature {
            has_this: sig.has_this,
            explicit_this: sig.explicit_this,
            convention: sig.convention,
            generic_count: sig.generic_count,
            vararg_start: sig.vararg_start,
            parameters: sig.parameters.iter().map(|p| self.import_type(p)).collect(),
            return_type: self.import_type(&sig.return_type),
        }
    }

    /// Maps a source-local definition handle to the target module.
    fn import_def(&self, id: TypeId) -> TypeDesc {
        let def = &self.source.types[id.index()];
        match find_matching(self.source, self.target, def) {
            Some(matched) => TypeDesc::Def(matched),
            None => {
                let external = self.external_from_chain(def);
                TypeDesc::External(Box::new(external))
            }
        }
    }

    /// Builds an [`ExternalType`] carrying the full declaring-type chain of
    /// `def`, scoped to the best assembly-reference match for the source
    /// module (or [`ScopeRef::Moduleless`]).
    fn external_from_chain(&self, def: &TypeDefinition) -> ExternalType {
        let scope = self.source_local_scope();
        let mut chain = Vec::new();
        let mut current = Some(def);
        while let Some(ty) = current {
            chain.push((ty.namespace.clone(), ty.name.clone()));
            current = ty.declaring_type.map(|pid| &self.source.types[pid.index()]);
        }
        // chain is innermost-first; nesting is outermost-first with the leaf
        chain.reverse(); // root .. leaf
        let (namespace, name) = chain.pop().expect("type chain has at least the leaf");
        let nesting = chain
            .into_iter()
            .map(|(ns, n)| {
                Box::new(ExternalType {
                    namespace: ns,
                    name: n,
                    nesting: Vec::new(),
                    scope: scope.clone(),
                })
            })
            .collect();
        ExternalType {
            namespace,
            name,
            nesting,
            scope,
        }
    }

    /// Re-scopes an already-external reference against the target's assembly
    /// references. Unmatched assembly scopes keep their original reference
    /// (the writer emits the missing `AssemblyRef`); a `ThisModule` scope
    /// refers to the source module itself and is treated like a source-local
    /// definition.
    fn rebuild_external(&self, ext: &ExternalType) -> ExternalType {
        let mut rebuilt = ExternalType {
            namespace: ext.namespace.clone(),
            name: ext.name.clone(),
            nesting: ext
                .nesting
                .iter()
                .map(|n| Box::new(self.rebuild_external(n)))
                .collect(),
            scope: match &ext.scope {
                ScopeRef::ThisModule => self.source_local_scope(),
                ScopeRef::Assembly(anr) => {
                    ScopeRef::Assembly(self.match_assembly_ref(anr).clone())
                }
                ScopeRef::OtherModule(_) | ScopeRef::Moduleless => ext.scope.clone(),
            },
        };
        if !rebuilt.nesting.is_empty() {
            // Ancestors share the leaf's scope so full-name rendering and
            // emission see a consistent picture.
            let scope = rebuilt.scope.clone();
            for ancestor in &mut rebuilt.nesting {
                ancestor.scope = scope.clone();
            }
        }
        rebuilt
    }

    /// Best [`ScopeRef::Assembly`] match for `anr`'s name in the target;
    /// returns `anr` unchanged when no reference matches.
    fn match_assembly_ref(
        &self,
        anr: &crate::model::types::AssemblyNameReference,
    ) -> crate::model::types::AssemblyNameReference {
        self.target
            .assembly_refs
            .iter()
            .find(|candidate| candidate.name == anr.name)
            .cloned()
            .unwrap_or_else(|| anr.clone())
    }

    /// Scope standing in for the source module's own assembly identity.
    fn source_local_scope(&self) -> ScopeRef {
        match self
            .target
            .assembly_refs
            .iter()
            .find(|a| a.name == self.source.name)
        {
            Some(anr) => ScopeRef::Assembly(anr.clone()),
            None => ScopeRef::Moduleless,
        }
    }

    /// Fallback external descriptor for the source module itself (used only
    /// when a field reference cannot be attributed to any declaring type).
    fn source_local_external(&self) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: String::new(),
            name: String::new(),
            nesting: Vec::new(),
            scope: self.source_local_scope(),
        }))
    }
}

/// Imports a type reference from `source` into `target`.
///
/// See [`Importer::import_type`] and the [module docs](self).
pub fn import_type(ty: &TypeDesc, source: &Module, target: &Module) -> TypeDesc {
    Importer::new(source, target).import_type(ty)
}

/// Imports a method reference from `source` into `target`.
///
/// See [`Importer::import_method`].
pub fn import_method(r: &MethodRef, source: &Module, target: &Module) -> MethodRef {
    Importer::new(source, target).import_method(r)
}

/// Imports a field reference from `source` into `target`.
///
/// See [`Importer::import_field`].
pub fn import_field(r: &FieldRef, source: &Module, target: &Module) -> FieldRef {
    Importer::new(source, target).import_field(r)
}

/// Linear-scan matcher: finds the target type equivalent to `def`.
///
/// Two types match when their namespace-and-name declaring chains are
/// identical (root namespace compared at the outermost link, names everywhere
/// else). Returns the first match in target arena (= table row) order, keeping
/// output deterministic.
///
/// v1 deliberately compares structure only - attributes, members, and layouts
/// are ignored (no deep semantic merge).
fn find_matching(
    source: &Module,
    target: &Module,
    def: &crate::model::types::TypeDefinition,
) -> Option<TypeId> {
    let wanted = declaring_chain(source, def);
    target.types.iter().enumerate().find_map(|(i, candidate)| {
        let candidate_chain = declaring_chain(target, candidate);
        if candidate_chain == wanted {
            Some(TypeId(i as u32))
        } else {
            None
        }
    })
}

/// Collects `(namespace, name)` pairs from the outermost declaring type down to
/// the given one. Cycles in malformed metadata are cut off at the arena length.
fn declaring_chain<'a>(
    module: &'a Module,
    mut def: &'a crate::model::types::TypeDefinition,
) -> Vec<(String, String)> {
    let mut chain = Vec::with_capacity(4);
    let mut hops = 0usize;
    loop {
        chain.push((def.namespace.clone(), def.name.clone()));
        match def.declaring_type {
            Some(parent) if hops <= module.types.len() => {
                def = &module.types[parent.index()];
                hops += 1;
            }
            _ => break,
        }
    }
    chain.reverse();
    chain
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{
        AssemblyNameReference, ExternalMethod, ExternalType, FieldDefinition, FieldSignature,
        MethodDefinition, MethodSignature, TypeDefinition,
    };
    use crate::model::types::{FieldId, MethodId};
    fn system(name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: "System".into(),
            name: name.into(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(AssemblyNameReference::new("mscorlib")),
        }))
    }

    fn int32_sig(param: TypeDesc) -> MethodSignature {
        MethodSignature {
            has_this: true,
            explicit_this: false,
            convention: cecli_core::flags::SignatureCallingConvention::Default,
            generic_count: 0,
            parameters: vec![param],
            return_type: system("Int32"),
            vararg_start: 1,
        }
    }

    /// Builds `src`: type `Point` (field `x:i32`, method `Get(Point)->i32`)
    /// plus optional extra types. Returns (module, point id, x id, get id).
    fn make_source(with_nested: bool) -> (Module, TypeId, FieldId, MethodId) {
        let mut src = Module::default();
        src.name = "srcasm".into();

        let mut point = TypeDefinition {
            name: "Point".into(),
            ..Default::default()
        };
        src.types.push(point.clone());
        let pid = TypeId(0);

        src.fields.push(FieldDefinition {
            name: "x".into(),
            signature: FieldSignature(system("Int32")),
            ..Default::default()
        });
        let fid = FieldId(0);
        point.fields.push(fid);

        src.methods.push(MethodDefinition {
            name: "Get".into(),
            signature: int32_sig(TypeDesc::Def(pid)),
            declaring_type: pid,
            ..Default::default()
        });
        let gid = MethodId(0);
        point.methods.push(gid);
        src.types[0] = point;

        if with_nested {
            // Outer / Inner nested under Point-like chain for chain matching.
            let mut outer = TypeDefinition {
                name: "Outer".into(),
                ..Default::default()
            };
            src.types.push(outer.clone());
            let oid = TypeId(1);
            let inner = TypeDefinition {
                name: "Inner".into(),
                declaring_type: Some(oid),
                ..Default::default()
            };
            src.types.push(inner);
            let iid = TypeId(2);
            outer.nested_types.push(iid);
            src.types[1] = outer;
        }

        (src, pid, fid, gid)
    }

    fn make_target() -> Module {
        let mut target = Module::default();
        target.name = "target".into();
        target
            .assembly_refs
            .push(AssemblyNameReference::new("mscorlib"));
        target
    }

    #[test]
    fn def_maps_to_moduleless_external_when_unmatched() {
        let (src, pid, _, _) = make_source(false);
        let target = make_target();

        let imported = import_type(&TypeDesc::Def(pid), &src, &target);
        match imported {
            TypeDesc::External(ext) => {
                assert_eq!(ext.namespace, "");
                assert_eq!(ext.name, "Point");
                assert!(ext.nesting.is_empty());
                // "srcasm" is not among target's assembly refs -> Moduleless.
                assert_eq!(ext.scope, ScopeRef::Moduleless);
            }
            other => panic!("expected External, got {:?}", other),
        }
    }

    #[test]
    fn def_maps_to_matched_assembly_ref_when_named() {
        let (src, pid, _, _) = make_source(false);
        let mut target = make_target();
        // Target references the source assembly by name.
        target
            .assembly_refs
            .push(AssemblyNameReference::new("srcasm"));

        let imported = import_type(&TypeDesc::Def(pid), &src, &target);
        match imported {
            TypeDesc::External(ext) => match ext.scope {
                ScopeRef::Assembly(anr) => assert_eq!(anr.name, "srcasm"),
                other => panic!("expected Assembly scope, got {:?}", other),
            },
            other => panic!("expected External, got {:?}", other),
        }
    }

    #[test]
    fn second_import_after_adding_type_yields_target_def() {
        let (src, pid, fid, gid) = make_source(false);
        // Wire Get's parameter through a mutable copy so later assertions hold.
        let mut target = make_target();

        // First import: External.
        let first = import_type(&TypeDesc::Def(pid), &src, &target);
        assert!(matches!(first, TypeDesc::External(_)));

        // Add the same-named type to the target.
        target.types.push(TypeDefinition {
            name: "Point".into(),
            fields: vec![fid],
            methods: vec![gid],
            ..Default::default()
        });

        // Second import: Def(target id 0).
        let second = import_type(&TypeDesc::Def(pid), &src, &target);
        assert_eq!(second, TypeDesc::Def(TypeId(0)));
    }

    #[test]
    fn nested_declaring_chain_is_required_and_rebuilt() {
        let (src, _, _, _) = make_source(true);
        let target = make_target();

        // Inner (TypeId 2) alone must NOT match a target "Inner" without the
        // Outer chain.
        let mut partial = make_target();
        partial.types.push(TypeDefinition {
            name: "Inner".into(),
            ..Default::default()
        });
        let imported = import_type(&TypeDesc::Def(TypeId(2)), &src, &partial);
        assert!(
            matches!(imported, TypeDesc::External(_)),
            "chain mismatch must fall back to External"
        );

        // With the full chain present, the nested def resolves to the target.
        let mut full = make_target();
        full.types.push(TypeDefinition {
            name: "Outer".into(),
            ..Default::default()
        });
        full.types.push(TypeDefinition {
            name: "Inner".into(),
            declaring_type: Some(TypeId(0)),
            ..Default::default()
        });
        let imported = import_type(&TypeDesc::Def(TypeId(2)), &src, &full);
        assert_eq!(imported, TypeDesc::Def(TypeId(1)));

        // Without the chain, the External carries nesting outermost-first.
        let external = import_type(&TypeDesc::Def(TypeId(2)), &src, &target);
        match external {
            TypeDesc::External(ext) => {
                assert_eq!(ext.name, "Inner");
                assert_eq!(ext.nesting.len(), 1);
                assert_eq!(ext.nesting[0].name, "Outer");
            }
            other => panic!("expected External, got {:?}", other),
        }
    }

    #[test]
    fn signature_import_remaps_parameter_types() {
        let (src, pid, _, _) = make_source(false);
        let mut target = make_target();
        target.types.push(TypeDefinition {
            name: "Point".into(),
            ..Default::default()
        });

        let importer = Importer::new(&src, &target);
        let sig = int32_sig(TypeDesc::Def(pid));
        let imported = importer.import_signature(&sig);

        assert_eq!(imported.parameters[0], TypeDesc::Def(TypeId(0)));
        // Primitive return stays external, re-scoped to the target's mscorlib.
        match &imported.return_type {
            TypeDesc::External(ext) => {
                assert_eq!(ext.name, "Int32");
                let expected = ScopeRef::Assembly(AssemblyNameReference::new("mscorlib"));
                assert_eq!(ext.scope, expected);
            }
            other => panic!("expected External return, got {:?}", other),
        }
    }
    #[test]
    fn method_import_rebuilds_external_with_remapped_parent_and_signature() {
        let (src, pid, _, gid) = make_source(false);
        let mut target = make_target();
        target.types.push(TypeDefinition {
            name: "Point".into(),
            ..Default::default()
        });

        let imported = import_method(&MethodRef::Def(gid), &src, &target);
        match imported {
            MethodRef::External(ExternalMethod {
                parent,
                name,
                signature,
            }) => {
                assert_eq!(name, "Get");
                assert_eq!(parent, TypeDesc::Def(pid));
                assert_eq!(signature.parameters[0], TypeDesc::Def(TypeId(0)));
                assert_eq!(signature.return_type, system("Int32"));
            }
            other => panic!("expected External method, got {:?}", other),
        }
    }

    #[test]
    fn method_spec_recurses_into_inner_reference_and_arguments() {
        let (src, pid, _, _) = make_source(false);
        let target = make_target();

        let spec = MethodRef::Spec {
            method: Box::new(MethodRef::Def(MethodId(0))),
            arguments: vec![TypeDesc::Def(pid)],
        };
        let imported = import_method(&spec, &src, &target);
        match imported {
            MethodRef::Spec { method, arguments } => {
                assert!(matches!(*method, MethodRef::External(_)));
                assert!(matches!(arguments[0], TypeDesc::External(_)));
            }
            other => panic!("expected Spec, got {:?}", other),
        }
    }

    #[test]
    fn field_import_rebuilds_external_with_remapped_parent() {
        let (src, _pid, fid, _gid) = make_source(false);
        let target = make_target();

        let imported = import_field(&FieldRef::Def(fid), &src, &target);
        match imported {
            FieldRef::External(ExternalField {
                parent,
                name,
                signature,
            }) => {
                assert_eq!(name, "x");
                assert!(matches!(parent, TypeDesc::External(_)));
                assert!(matches!(signature.0, TypeDesc::External(_)));
            }
            other => panic!("expected External field, got {:?}", other),
        }
    }

    #[test]
    fn composite_shapes_recurse_var_mvar_untouched() {
        let (src, pid, _, _) = make_source(false);
        let mut target = make_target();
        target.types.push(TypeDefinition {
            name: "Point".into(),
            ..Default::default()
        });

        let ty = TypeDesc::GenericInstance {
            definition: Box::new(TypeDesc::Def(pid)),
            arguments: vec![
                TypeDesc::SzArray(Box::new(TypeDesc::Var(0))),
                TypeDesc::MVar(1),
                TypeDesc::FnPtr(Box::new(int32_sig(TypeDesc::Def(pid)))),
                TypeDesc::CMod {
                    required: true,
                    modifier: Box::new(system("IsConst")),
                    unmodified: Box::new(TypeDesc::Def(pid)),
                },
            ],
        };

        let imported = import_type(&ty, &src, &target);
        match imported {
            TypeDesc::GenericInstance {
                definition,
                arguments,
            } => {
                assert_eq!(*definition, TypeDesc::Def(TypeId(0)));
                match &arguments[0] {
                    TypeDesc::SzArray(inner) => assert_eq!(**inner, TypeDesc::Var(0)),
                    other => panic!("expected SzArray, got {:?}", other),
                }
                assert_eq!(arguments[1], TypeDesc::MVar(1));
                match &arguments[2] {
                    TypeDesc::FnPtr(sig) => {
                        assert_eq!(sig.parameters[0], TypeDesc::Def(TypeId(0)))
                    }
                    other => panic!("expected FnPtr, got {:?}", other),
                }
                match &arguments[3] {
                    TypeDesc::CMod { unmodified, .. } => {
                        assert_eq!(**unmodified, TypeDesc::Def(TypeId(0)))
                    }
                    other => panic!("expected CMod, got {:?}", other),
                }
            }
            other => panic!("expected GenericInstance, got {:?}", other),
        }
    }

    #[test]
    fn existing_external_rescopes_to_matching_target_ref() {
        let (src, _, _, _) = make_source(false);
        let mut target = make_target();
        // Same-name-but-different-instance mscorlib ref in the target.
        let mut anr = AssemblyNameReference::new("mscorlib");
        anr.version = crate::model::types::Version::new(4, 0, 0, 0);
        target.assembly_refs.clear();
        target.assembly_refs.push(anr);

        let importer = Importer::new(&src, &target);
        let imported = importer.import_type(&system("Int32"));
        match imported {
            TypeDesc::External(ext) => match ext.scope {
                ScopeRef::Assembly(resolved) => {
                    assert_eq!(resolved.version, crate::model::types::Version::new(4, 0, 0, 0));
                }
                other => panic!("expected Assembly scope, got {:?}", other),
            },
            other => panic!("expected External, got {:?}", other),
        }
    }

    #[test]
    fn importer_struct_mirrors_free_functions() {
        let (src, pid, fid, gid) = make_source(false);
        let target = make_target();
        let importer = Importer::new(&src, &target);

        assert_eq!(
            importer.import_type(&TypeDesc::Def(pid)),
            import_type(&TypeDesc::Def(pid), &src, &target)
        );
        assert_eq!(
            importer.import_method(&MethodRef::Def(gid)),
            import_method(&MethodRef::Def(gid), &src, &target)
        );
        assert_eq!(
            importer.import_field(&FieldRef::Def(fid)),
            import_field(&FieldRef::Def(fid), &src, &target)
        );
    }
}
