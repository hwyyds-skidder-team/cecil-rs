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
//!   an [`TypeDesc::External`] whose scope is resolved against the source
//!   assembly's identity (see below).
//! * Composite shapes (`SzArray`, `Array`, `Ptr`, `ByRef`, `Pinned`,
//!   `GenericInstance`, `FnPtr`, `CMod`) recurse into their element types /
//!   signatures. `Var` / `MVar` are context-bound numbers and pass through
//!   untouched.
//! * Already-external references are re-scoped against the target's assembly
//!   references by identity (name + version + culture + public key or token).
//!   When no reference matches, a deduped clone of the incoming
//!   [`AssemblyNameReference`] is appended to `target.assembly_refs` and the
//!   scope points at it - mirroring Mono.Cecil's `ImportReference`. A
//!   `ThisModule` scope is treated as source-local.
//!
//! * The source module's own assembly identity is taken from the optional
//!   `source_identity` parameter on [`Importer::new`] and the free functions
//!   (the facade passes its own assembly-name reference). When absent, the
//!   importer falls back to matching `source.name` against the target's
//!   assembly references by name only, and to [`ScopeRef::Moduleless`] when
//!   nothing matches.

use crate::model::types::{
    AssemblyNameReference, ExternalField, ExternalMethod, ExternalType, FieldRef, FieldSignature,
    MethodRef, MethodSignature, ScopeRef, TypeDesc, TypeId,
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
    /// Module the remapped references must be valid in. The importer may
    /// append missing [`AssemblyNameReference`] rows to it while importing.
    pub target: &'a mut Module,
    /// Identity of the source assembly used to scope source-local
    /// definitions. When `None`, the importer approximates with
    /// `source.name`.
    pub source_identity: Option<&'a AssemblyNameReference>,
}

impl<'a> Importer<'a> {
    /// Creates an importer remapping `source` references into `target`.
    ///
    /// `source_identity` is the source assembly's own name reference; pass it
    /// whenever the caller knows the assembly identity (the facade passes its
    /// own). With `None`, source-local definitions fall back to a name-only
    /// match against `source.name` in `target.assembly_refs`.
    pub fn new(
        source: &'a Module,
        target: &'a mut Module,
        source_identity: Option<&'a AssemblyNameReference>,
    ) -> Self {
        Importer { source, target, source_identity }
    }

    /// Imports a type reference (free-function form: [`import_type`]).
    pub fn import_type(&mut self, ty: &TypeDesc) -> TypeDesc {
        match ty {
            TypeDesc::Def(id) => self.import_def(*id),
            TypeDesc::External(ext) => TypeDesc::External(Box::new(self.rebuild_external(ext))),
            TypeDesc::SzArray(element) => {
                TypeDesc::SzArray(std::sync::Arc::new(self.import_type(element)))
            }
            TypeDesc::Array { element, sizes, lobounds } => TypeDesc::Array {
                element: std::sync::Arc::new(self.import_type(element)),
                sizes: sizes.clone(),
                lobounds: lobounds.clone(),
            },
            TypeDesc::Ptr(pointee) => TypeDesc::Ptr(std::sync::Arc::new(self.import_type(pointee))),
            TypeDesc::ByRef(pointee) => {
                TypeDesc::ByRef(std::sync::Arc::new(self.import_type(pointee)))
            }
            TypeDesc::Pinned(pointee) => {
                TypeDesc::Pinned(std::sync::Arc::new(self.import_type(pointee)))
            }
            TypeDesc::GenericInstance { definition, arguments } => TypeDesc::GenericInstance {
                definition: std::sync::Arc::new(self.import_type(definition)),
                arguments: arguments
                    .iter()
                    .map(|a| std::sync::Arc::new(self.import_type(a)))
                    .collect(),
            },
            TypeDesc::FnPtr(signature) => {
                TypeDesc::FnPtr(Box::new(self.import_signature(signature)))
            }
            TypeDesc::CMod { required, modifier, unmodified } => TypeDesc::CMod {
                required: *required,
                modifier: std::sync::Arc::new(self.import_type(modifier)),
                unmodified: std::sync::Arc::new(self.import_type(unmodified)),
            },
            // Context-bound or leaf values carry no cross-module state.
            TypeDesc::Var(_) | TypeDesc::MVar(_) | TypeDesc::Sentinel => ty.clone(),
            TypeDesc::TypedByRef | TypeDesc::Internal(_) => ty.clone(),
        }
    }

    /// Imports a method reference (free-function form: [`import_method`]).
    ///
    /// A `Def` is always rebuilt as an [`ExternalMethod`] cloned from the
    /// source definition (name + remapped signature + remapped parent); no
    /// member-level merge is performed even when the declaring type resolves
    /// to a `Def` in the target.
    pub fn import_method(&mut self, r: &MethodRef) -> MethodRef {
        match r {
            MethodRef::Def(id) => {
                let parent = self
                    .import_type(&TypeDesc::Def(self.source.methods[id.index()].declaring_type));
                let name = self.source.methods[id.index()].name.clone();
                let signature = self.source.methods[id.index()].signature.clone();
                MethodRef::External(ExternalMethod {
                    parent,
                    name,
                    signature: self.import_signature(&signature),
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
    pub fn import_field(&mut self, r: &FieldRef) -> FieldRef {
        match r {
            FieldRef::Def(id) => {
                // Recover the declaring type by scanning the source arenas:
                // fields do not back-reference their owner, so take the first
                // type listing this field. Valid modules always contain one.
                // Name and signature are cloned up front so no shared source
                // borrow stays alive across the mutable target access.
                let name = self.source.fields[id.index()].name.clone();
                let signature = self.source.fields[id.index()].signature.clone();
                let parent = self
                    .source
                    .types
                    .iter()
                    .position(|t| t.fields.contains(id))
                    .map(|i| self.import_type(&TypeDesc::Def(TypeId(i as u32))))
                    .unwrap_or_else(|| self.source_local_external());
                FieldRef::External(ExternalField {
                    parent,
                    name,
                    signature: FieldSignature(self.import_type(&signature.0)),
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
    pub fn import_signature(&mut self, sig: &MethodSignature) -> MethodSignature {
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
    fn import_def(&mut self, id: TypeId) -> TypeDesc {
        let def = &self.source.types[id.index()];
        let matched = find_matching(self.source, self.target, def);
        match matched {
            Some(matched) => TypeDesc::Def(matched),
            None => {
                // Outermost-first namespace/name chain of `def`; computed
                // before any mutable target access so the shared source
                // borrow ends here.
                let chain = declaring_chain(self.source, def);
                TypeDesc::External(Box::new(self.external_from_chain(chain)))
            }
        }
    }

    /// Builds an [`ExternalType`] carrying the full declaring-type chain of
    /// `def`, scoped to the target's assembly reference matching the source
    /// assembly's identity (appended when missing), or
    /// [`ScopeRef::Moduleless`] under the name-only fallback without an
    /// identity.
    fn external_from_chain(&mut self, mut chain: Vec<(String, String)>) -> ExternalType {
        let scope = self.source_local_scope();
        // chain is outermost-first; nesting is outermost-first with the leaf
        // popped off last.
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
        ExternalType { namespace, name, nesting, scope }
    }

    /// Re-scopes an already-external reference against the target's assembly
    /// references. Unmatched assembly scopes get a deduped clone appended to
    /// the target (mirroring Mono.Cecil's `ImportReference`); a `ThisModule`
    /// scope refers to the source module itself and is treated like a
    /// source-local definition.
    fn rebuild_external(&mut self, ext: &ExternalType) -> ExternalType {
        let mut rebuilt = ExternalType {
            namespace: ext.namespace.clone(),
            name: ext.name.clone(),
            nesting: ext.nesting.iter().map(|n| Box::new(self.rebuild_external(n))).collect(),
            scope: match &ext.scope {
                ScopeRef::ThisModule => self.source_local_scope(),
                ScopeRef::Assembly(anr) => ScopeRef::Assembly(self.match_or_append(anr)),
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

    /// Target [`AssemblyNameReference`] matching `anr`'s identity (name +
    /// version + culture + public key or token); appends a deduped clone of
    /// `anr` to the target and returns it when no reference matches.
    fn match_or_append(&mut self, anr: &AssemblyNameReference) -> AssemblyNameReference {
        if let Some(existing) = self.target.assembly_refs.iter().find(|candidate| {
            candidate.name == anr.name
                && candidate.version == anr.version
                && candidate.culture == anr.culture
                && candidate.public_key_or_token == anr.public_key_or_token
        }) {
            return existing.clone();
        }
        self.target.assembly_refs.push(anr.clone());
        anr.clone()
    }

    /// Scope standing in for the source module's own assembly identity.
    ///
    /// With a known identity the target's assembly references are matched on
    /// the full identity key, appending a deduped row when missing. Without
    /// one, the importer falls back to matching `source.name` by name only,
    /// and to [`ScopeRef::Moduleless`] when nothing matches.
    fn source_local_scope(&mut self) -> ScopeRef {
        match self.source_identity {
            Some(identity) => ScopeRef::Assembly(self.match_or_append(identity)),
            None => {
                let name = &self.source.name;
                match self.target.assembly_refs.iter().find(|a| a.name == *name) {
                    Some(anr) => ScopeRef::Assembly(anr.clone()),
                    None => ScopeRef::Moduleless,
                }
            }
        }
    }

    /// Fallback external descriptor for the source module itself (used only
    /// when a field reference cannot be attributed to any declaring type).
    fn source_local_external(&mut self) -> TypeDesc {
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
pub fn import_type(
    ty: &TypeDesc,
    source: &Module,
    target: &mut Module,
    source_identity: Option<&AssemblyNameReference>,
) -> TypeDesc {
    Importer::new(source, target, source_identity).import_type(ty)
}

/// Imports a method reference from `source` into `target`.
///
/// See [`Importer::import_method`].
pub fn import_method(
    r: &MethodRef,
    source: &Module,
    target: &mut Module,
    source_identity: Option<&AssemblyNameReference>,
) -> MethodRef {
    Importer::new(source, target, source_identity).import_method(r)
}

/// Imports a field reference from `source` into `target`.
///
/// See [`Importer::import_field`].
pub fn import_field(
    r: &FieldRef,
    source: &Module,
    target: &mut Module,
    source_identity: Option<&AssemblyNameReference>,
) -> FieldRef {
    Importer::new(source, target, source_identity).import_field(r)
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
        MethodDefinition, MethodSignature, TypeDefinition, Version,
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
        let mut src = Module { name: "srcasm".into(), ..Default::default() };

        let mut point = TypeDefinition { name: "Point".into(), ..Default::default() };
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
            let mut outer = TypeDefinition { name: "Outer".into(), ..Default::default() };
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
        let mut target = Module { name: "target".into(), ..Default::default() };
        target.assembly_refs.push(AssemblyNameReference::new("mscorlib"));
        target
    }

    #[test]
    fn def_maps_to_moduleless_external_when_unmatched() {
        let (src, pid, _, _) = make_source(false);
        let mut target = make_target();

        let imported = import_type(&TypeDesc::Def(pid), &src, &mut target, None);
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
        target.assembly_refs.push(AssemblyNameReference::new("srcasm"));

        let imported = import_type(&TypeDesc::Def(pid), &src, &mut target, None);
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
        let first = import_type(&TypeDesc::Def(pid), &src, &mut target, None);
        assert!(matches!(first, TypeDesc::External(_)));

        // Add the same-named type to the target.
        target.types.push(TypeDefinition {
            name: "Point".into(),
            fields: vec![fid],
            methods: vec![gid],
            ..Default::default()
        });

        // Second import: Def(target id 0).
        let second = import_type(&TypeDesc::Def(pid), &src, &mut target, None);
        assert_eq!(second, TypeDesc::Def(TypeId(0)));
    }

    #[test]
    fn nested_declaring_chain_is_required_and_rebuilt() {
        let (src, _, _, _) = make_source(true);
        let mut target = make_target();

        // Inner (TypeId 2) alone must NOT match a target "Inner" without the
        // Outer chain.
        let mut partial = make_target();
        partial.types.push(TypeDefinition { name: "Inner".into(), ..Default::default() });
        let imported = import_type(&TypeDesc::Def(TypeId(2)), &src, &mut partial, None);
        assert!(
            matches!(imported, TypeDesc::External(_)),
            "chain mismatch must fall back to External"
        );

        // With the full chain present, the nested def resolves to the target.
        let mut full = make_target();
        full.types.push(TypeDefinition { name: "Outer".into(), ..Default::default() });
        full.types.push(TypeDefinition {
            name: "Inner".into(),
            declaring_type: Some(TypeId(0)),
            ..Default::default()
        });
        let imported = import_type(&TypeDesc::Def(TypeId(2)), &src, &mut full, None);
        assert_eq!(imported, TypeDesc::Def(TypeId(1)));

        // Without the chain, the External carries nesting outermost-first.
        let external = import_type(&TypeDesc::Def(TypeId(2)), &src, &mut target, None);
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
        target.types.push(TypeDefinition { name: "Point".into(), ..Default::default() });

        let mut importer = Importer::new(&src, &mut target, None);
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
        target.types.push(TypeDefinition { name: "Point".into(), ..Default::default() });

        let imported = import_method(&MethodRef::Def(gid), &src, &mut target, None);
        match imported {
            MethodRef::External(ExternalMethod { parent, name, signature }) => {
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
        let mut target = make_target();

        let spec = MethodRef::Spec {
            method: Box::new(MethodRef::Def(MethodId(0))),
            arguments: vec![TypeDesc::Def(pid)],
        };
        let imported = import_method(&spec, &src, &mut target, None);
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
        let mut target = make_target();

        let imported = import_field(&FieldRef::Def(fid), &src, &mut target, None);
        match imported {
            FieldRef::External(ExternalField { parent, name, signature }) => {
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
        target.types.push(TypeDefinition { name: "Point".into(), ..Default::default() });

        let ty = TypeDesc::GenericInstance {
            definition: std::sync::Arc::new(TypeDesc::Def(pid)),
            arguments: vec![
                std::sync::Arc::new(TypeDesc::SzArray(std::sync::Arc::new(TypeDesc::Var(0)))),
                std::sync::Arc::new(TypeDesc::MVar(1)),
                std::sync::Arc::new(TypeDesc::FnPtr(Box::new(int32_sig(TypeDesc::Def(pid))))),
                std::sync::Arc::new(TypeDesc::CMod {
                    required: true,
                    modifier: std::sync::Arc::new(system("IsConst")),
                    unmodified: std::sync::Arc::new(TypeDesc::Def(pid)),
                }),
            ],
        };

        let imported = import_type(&ty, &src, &mut target, None);
        match imported {
            TypeDesc::GenericInstance { definition, arguments } => {
                assert_eq!(*definition, TypeDesc::Def(TypeId(0)));
                match arguments[0].as_ref() {
                    TypeDesc::SzArray(inner) => assert_eq!(**inner, TypeDesc::Var(0)),
                    other => panic!("expected SzArray, got {:?}", other),
                }
                assert_eq!(*arguments[1], TypeDesc::MVar(1));
                match arguments[2].as_ref() {
                    TypeDesc::FnPtr(sig) => {
                        assert_eq!(sig.parameters[0], TypeDesc::Def(TypeId(0)))
                    }
                    other => panic!("expected FnPtr, got {:?}", other),
                }
                match arguments[3].as_ref() {
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
    fn external_rescopes_to_identity_matched_target_ref() {
        let (src, _, _, _) = make_source(false);
        let mut target = make_target();
        // Target's mscorlib carries a real version; the incoming external
        // uses the same identity, so it must re-scope without appending.
        let mut anr = AssemblyNameReference::new("mscorlib");
        anr.version = Version::new(4, 0, 0, 0);
        target.assembly_refs.clear();
        target.assembly_refs.push(anr.clone());

        let ty = TypeDesc::External(Box::new(ExternalType {
            namespace: "System".into(),
            name: "Int32".into(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(anr),
        }));

        let mut importer = Importer::new(&src, &mut target, None);
        let imported = importer.import_type(&ty);
        assert_eq!(target.assembly_refs.len(), 1);
        match imported {
            TypeDesc::External(ext) => match ext.scope {
                ScopeRef::Assembly(resolved) => {
                    assert_eq!(resolved.name, "mscorlib");
                    assert_eq!(resolved.version, Version::new(4, 0, 0, 0));
                }
                other => panic!("expected Assembly scope, got {:?}", other),
            },
            other => panic!("expected External, got {:?}", other),
        }
    }

    #[test]
    fn missing_assembly_scope_is_appended_once_and_deduped() {
        let (src, _, _, _) = make_source(false);
        let mut target = make_target();
        let mut anr = AssemblyNameReference::new("System.Runtime");
        anr.version = Version::new(8, 0, 0, 0);
        anr.public_key_or_token = vec![0xB0, 0x3F, 0x5F, 0x7F];
        let ty = TypeDesc::External(Box::new(ExternalType {
            namespace: "System".into(),
            name: "String".into(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(anr),
        }));

        // The Importer holds `&mut target` for its whole lifetime, so reads
        // of `target.assembly_refs` happen before the binding is created or
        // after it is dropped at the end of each scoped block.
        assert_eq!(target.assembly_refs.len(), 1);

        // First import appends exactly one new AssemblyRef row.
        let first = {
            let mut importer = Importer::new(&src, &mut target, None);
            importer.import_type(&ty)
        };
        assert_eq!(target.assembly_refs.len(), 2);
        let appended = match &first {
            TypeDesc::External(ext) => match &ext.scope {
                ScopeRef::Assembly(resolved) => resolved.clone(),
                other => panic!("expected Assembly scope, got {:?}", other),
            },
            other => panic!("expected External, got {:?}", other),
        };
        assert_eq!(appended.name, "System.Runtime");
        assert_eq!(appended.version, Version::new(8, 0, 0, 0));
        // Dedup check by index scan: exactly one new row landed after the
        // pre-existing mscorlib ref, and it matches the resolved scope.
        assert_eq!(target.assembly_refs[1], appended);

        // Second import of the same identity dedups instead of appending.
        let second = {
            let mut importer = Importer::new(&src, &mut target, None);
            importer.import_type(&ty)
        };
        assert_eq!(target.assembly_refs.len(), 2);
        match second {
            TypeDesc::External(ext) => {
                assert_eq!(ext.scope, ScopeRef::Assembly(appended));
            }
            other => panic!("expected External, got {:?}", other),
        }
    }

    #[test]
    fn version_mismatch_counts_as_missing_and_appends() {
        let (src, _, _, _) = make_source(false);
        let mut target = make_target();
        // Target has mscorlib 4.0.0.0; the incoming external is mscorlib
        // 2.0.0.0 - identity differs, so a new ref must be appended.
        let mut anr = AssemblyNameReference::new("mscorlib");
        anr.version = Version::new(4, 0, 0, 0);
        target.assembly_refs.clear();
        target.assembly_refs.push(anr);

        let mut incoming = AssemblyNameReference::new("mscorlib");
        incoming.version = Version::new(2, 0, 0, 0);
        let ty = TypeDesc::External(Box::new(ExternalType {
            namespace: "System".into(),
            name: "Object".into(),
            nesting: Vec::new(),
            scope: ScopeRef::Assembly(incoming),
        }));

        let mut importer = Importer::new(&src, &mut target, None);
        importer.import_type(&ty);
        assert_eq!(target.assembly_refs.len(), 2);
        assert_eq!(target.assembly_refs[1].version, Version::new(2, 0, 0, 0));
    }

    #[test]
    fn identity_override_used_when_provided() {
        let (src, pid, _, _) = make_source(false);
        let mut target = make_target();
        // The name-only approximation would find this `srcasm` ref; the
        // explicit identity must win instead.
        target.assembly_refs.push(AssemblyNameReference::new("srcasm"));

        let mut identity = AssemblyNameReference::new("real.src");
        identity.version = Version::new(2, 5, 0, 0);
        identity.culture = Some("en".into());
        identity.public_key_or_token = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let imported = import_type(&TypeDesc::Def(pid), &src, &mut target, Some(&identity));
        match imported {
            TypeDesc::External(ext) => match ext.scope {
                ScopeRef::Assembly(anr) => {
                    assert_eq!(anr.name, "real.src");
                    assert_eq!(anr.version, Version::new(2, 5, 0, 0));
                    assert_eq!(anr.culture.as_deref(), Some("en"));
                    assert_eq!(anr.public_key_or_token, vec![0xDE, 0xAD, 0xBE, 0xEF]);
                }
                other => panic!("expected Assembly scope, got {:?}", other),
            },
            other => panic!("expected External, got {:?}", other),
        }
        // Exactly one new row (the appended identity) beyond mscorlib + srcasm.
        assert_eq!(target.assembly_refs.len(), 3);
        assert_eq!(target.assembly_refs[2], identity);
    }

    #[test]
    fn importer_struct_mirrors_free_functions() {
        let (src, pid, fid, gid) = make_source(false);
        let mut struct_target = make_target();
        let mut importer = Importer::new(&src, &mut struct_target, None);
        let struct_ty = importer.import_type(&TypeDesc::Def(pid));
        let struct_md = importer.import_method(&MethodRef::Def(gid));
        let struct_fd = importer.import_field(&FieldRef::Def(fid));

        let mut fn_target = make_target();
        assert_eq!(struct_ty, import_type(&TypeDesc::Def(pid), &src, &mut fn_target, None));
        assert_eq!(struct_md, import_method(&MethodRef::Def(gid), &src, &mut fn_target, None));
        assert_eq!(struct_fd, import_field(&FieldRef::Def(fid), &src, &mut fn_target, None));
    }
}
