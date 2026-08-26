//! Generic type-substitution over [`TypeDesc`] trees.
//!
//! Rust port of `Mono.Cecil/TypeResolver.cs`: replaces `Var` (type generic
//! parameter) and `MVar` (method generic parameter) leaves through caller
//! provided lookup maps, recursing through every composite type node
//! (generic instances, function pointer signatures, custom modifiers,
//! arrays / pointers / by-ref / pinned elements).
//!
//! Unlike Cecil's resolver - which rebuilds reference objects and drops
//! required modifiers while resolving (`RequiredModifierType` branch) - this
//! port is a pure structural rewrite: the `CMod` wrapper is preserved and its
//! `modifier` and `unmodified` parts are substituted independently, so no
//! information is lost.

use super::types::{GenericParameter, MethodSignature, TypeDesc};

/// Deeply substitutes generic-parameter leaves in `ty`.
///
/// * `map_v` - lookup for `Var(n)` (type-level generic parameters).
/// * `map_m` - lookup for `MVar(n)` (method-level generic parameters).
///
/// When a lookup returns `None` the original leaf is kept unchanged, mirroring
/// Cecil's behaviour where an unresolved generic parameter passes through.
pub fn substitute(
    ty: &TypeDesc,
    map_v: &dyn Fn(u16) -> Option<TypeDesc>,
    map_m: &mut dyn Fn(u16) -> Option<TypeDesc>,
) -> TypeDesc {
    match ty {
        // Leaves that may be rewritten.
        TypeDesc::Var(pos) => map_v(*pos).unwrap_or_else(|| ty.clone()),
        TypeDesc::MVar(pos) => map_m(*pos).unwrap_or_else(|| ty.clone()),

        // Composite nodes: recurse structurally.
        TypeDesc::SzArray(element) => {
            TypeDesc::SzArray(Box::new(substitute(element, map_v, map_m)))
        }
        TypeDesc::Array { element, sizes, lobounds } => TypeDesc::Array {
            element: Box::new(substitute(element, map_v, map_m)),
            sizes: sizes.clone(),
            lobounds: lobounds.clone(),
        },
        TypeDesc::Ptr(element) => TypeDesc::Ptr(Box::new(substitute(element, map_v, map_m))),
        TypeDesc::ByRef(element) => TypeDesc::ByRef(Box::new(substitute(element, map_v, map_m))),
        TypeDesc::Pinned(element) => TypeDesc::Pinned(Box::new(substitute(element, map_v, map_m))),
        TypeDesc::GenericInstance { definition, arguments } => {
            let arguments = arguments.iter().map(|arg| substitute(arg, map_v, map_m)).collect();
            TypeDesc::GenericInstance {
                definition: Box::new(substitute(definition, map_v, map_m)),
                arguments,
            }
        }
        TypeDesc::FnPtr(signature) => {
            TypeDesc::FnPtr(Box::new(substitute_signature(signature, map_v, map_m)))
        }
        TypeDesc::CMod { required, modifier, unmodified } => TypeDesc::CMod {
            required: *required,
            modifier: Box::new(substitute(modifier, map_v, map_m)),
            unmodified: Box::new(substitute(unmodified, map_v, map_m)),
        },

        // Ground nodes: nothing to substitute.
        TypeDesc::Def(_)
        | TypeDesc::External(_)
        | TypeDesc::Sentinel
        | TypeDesc::TypedByRef
        | TypeDesc::Internal(_) => ty.clone(),
    }
}

/// Substitutes through every type in a [`MethodSignature`] (parameters and
/// return type); all non-type fields are copied verbatim.
pub fn substitute_signature(
    sig: &MethodSignature,
    map_v: &dyn Fn(u16) -> Option<TypeDesc>,
    map_m: &mut dyn Fn(u16) -> Option<TypeDesc>,
) -> MethodSignature {
    MethodSignature {
        parameters: sig.parameters.iter().map(|p| substitute(p, map_v, map_m)).collect(),
        return_type: substitute(&sig.return_type, map_v, map_m),
        ..sig.clone()
    }
}

/// Builds the type-level (`Var`) lookup map for a generic instantiation.
///
/// Given the generic parameter list of a definition and the concrete argument
/// list of an instantiation, the returned closure resolves a parameter
/// position to the corresponding argument (position-indexed, matching
/// Cecil's `TypeResolver.ResolveGenericParameter`, which indexes the context's
/// `GenericArguments` by `GenericParameter.Position`). Returns `None` when the
/// position does not name one of `defs` or exceeds `args`, leaving the leaf
/// untouched downstream.
pub fn build_generic_context<'a>(
    defs: &[GenericParameter],
    args: &'a [TypeDesc],
) -> impl Fn(u16) -> Option<TypeDesc> + 'a {
    let positions: Vec<u16> = defs.iter().map(|d| d.position).collect();
    move |pos: u16| {
        if positions.contains(&pos) {
            args.get(pos as usize).cloned()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{ExternalType, ScopeRef};
    use cecli_core::flags::SignatureCallingConvention;

    /// Convenience: named external type `Ns.Name`.
    fn ext(ns: &str, name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: ns.to_string(),
            name: name.to_string(),
            nesting: Vec::new(),
            scope: ScopeRef::ThisModule,
        }))
    }

    #[test]
    fn nested_generic_instance_remap() {
        // Dictionary<string, List<T>> -> Dictionary<string, List<int>>
        let dict = ext("System.Collections.Generic", "Dictionary`2");
        let list = ext("System.Collections.Generic", "List`1");
        let ty = TypeDesc::GenericInstance {
            definition: Box::new(dict),
            arguments: vec![
                ext("System", "String"),
                TypeDesc::GenericInstance {
                    definition: Box::new(list),
                    arguments: vec![TypeDesc::Var(0)],
                },
            ],
        };

        let map_v = |pos: u16| {
            if pos == 0 {
                Some(ext("System", "Int32"))
            } else {
                None
            }
        };
        let mut map_m = |_pos: u16| -> Option<TypeDesc> { None };

        let out = substitute(&ty, &map_v, &mut map_m);
        assert_eq!(
            out,
            TypeDesc::GenericInstance {
                definition: Box::new(ext("System.Collections.Generic", "Dictionary`2")),
                arguments: vec![
                    ext("System", "String"),
                    TypeDesc::GenericInstance {
                        definition: Box::new(ext("System.Collections.Generic", "List`1")),
                        arguments: vec![ext("System", "Int32")],
                    },
                ],
            }
        );
    }

    #[test]
    fn fnptr_signature_substitution() {
        // void* M(T[] arg, U ret-param) expressed as FnPtr inside a Ptr chain.
        let sig = MethodSignature {
            has_this: false,
            explicit_this: false,
            convention: SignatureCallingConvention::Default,
            generic_count: 0,
            parameters: vec![TypeDesc::SzArray(Box::new(TypeDesc::Var(1))), TypeDesc::MVar(0)],
            return_type: TypeDesc::Var(0),
            vararg_start: 2,
        };
        let ty = TypeDesc::FnPtr(Box::new(sig));

        let map_v = |pos: u16| match pos {
            0 => Some(ext("System", "Void")),
            1 => Some(ext("System", "Byte")),
            _ => None,
        };
        let mut map_m = |pos: u16| {
            if pos == 0 {
                Some(ext("System", "Int64"))
            } else {
                None
            }
        };

        let out = substitute(&ty, &map_v, &mut map_m);
        match out {
            TypeDesc::FnPtr(sig) => {
                assert_eq!(sig.parameters.len(), 2);
                assert_eq!(sig.parameters[0], TypeDesc::SzArray(Box::new(ext("System", "Byte"))));
                assert_eq!(sig.parameters[1], ext("System", "Int64"));
                assert_eq!(sig.return_type, ext("System", "Void"));
                assert_eq!(sig.vararg_start, 2);
            }
            other => panic!("expected FnPtr, got {other:?}"),
        }

        // Unmapped leaves pass through unchanged.
        let passthrough = TypeDesc::FnPtr(Box::new(MethodSignature {
            parameters: vec![TypeDesc::MVar(7), TypeDesc::Var(7)],
            return_type: TypeDesc::Var(9),
            ..MethodSignature::default()
        }));
        let none_v = |_p: u16| -> Option<TypeDesc> { None };
        let mut none_m = |_p: u16| -> Option<TypeDesc> { None };
        assert_eq!(substitute(&passthrough, &none_v, &mut none_m), passthrough);
    }

    #[test]
    fn cmod_and_container_substitution() {
        // modreq(int) T[][] plus Ptr/ByRef wrappers.
        let ty = TypeDesc::CMod {
            required: true,
            modifier: Box::new(ext("System.Runtime.CompilerServices", "IsVolatile")),
            unmodified: Box::new(TypeDesc::ByRef(Box::new(TypeDesc::MVar(2)))),
        };
        let map_v = |_p: u16| -> Option<TypeDesc> { None };
        let mut map_m = |pos: u16| {
            if pos == 2 {
                Some(ext("System", "Single"))
            } else {
                None
            }
        };
        assert_eq!(
            substitute(&ty, &map_v, &mut map_m),
            TypeDesc::CMod {
                required: true,
                modifier: Box::new(ext("System.Runtime.CompilerServices", "IsVolatile")),
                unmodified: Box::new(TypeDesc::ByRef(Box::new(ext("System", "Single")))),
            }
        );

        // Multi-dim array keeps bounds while substituting the element.
        let arr = TypeDesc::Array {
            element: Box::new(TypeDesc::Var(3)),
            sizes: vec![4],
            lobounds: vec![1],
        };
        let map_v = |pos: u16| {
            if pos == 3 {
                Some(TypeDesc::Ptr(Box::new(ext("System", "Char"))))
            } else {
                None
            }
        };
        let mut none = |_p: u16| -> Option<TypeDesc> { None };
        assert_eq!(
            substitute(&arr, &map_v, &mut none),
            TypeDesc::Array {
                element: Box::new(TypeDesc::Ptr(Box::new(ext("System", "Char")))),
                sizes: vec![4],
                lobounds: vec![1],
            }
        );
    }

    #[test]
    fn generic_context_positional() {
        // class Foo<A, B, C> : Dictionary<B, List<C>> instantiated as <int, string, bool>
        let defs: Vec<GenericParameter> = ["A", "B", "C"]
            .iter()
            .enumerate()
            .map(|(i, n)| GenericParameter {
                name: n.to_string(),
                position: i as u16,
                ..GenericParameter::default()
            })
            .collect();
        let args = vec![ext("System", "Int32"), ext("System", "String"), ext("System", "Boolean")];

        let ctx = build_generic_context(&defs, &args);
        assert_eq!(ctx(0), Some(ext("System", "Int32")));
        assert_eq!(ctx(1), Some(ext("System", "String")));
        assert_eq!(ctx(2), Some(ext("System", "Boolean")));

        // Out-of-range positions leave the leaf alone.
        assert_eq!(ctx(3), None);

        // End-to-end: Dictionary<B, List<C>> with the built context.
        let body = TypeDesc::GenericInstance {
            definition: Box::new(ext("System.Collections.Generic", "Dictionary`2")),
            arguments: vec![
                TypeDesc::Var(1),
                TypeDesc::GenericInstance {
                    definition: Box::new(ext("System.Collections.Generic", "List`1")),
                    arguments: vec![TypeDesc::Var(2)],
                },
            ],
        };
        let mut no_mvars = |_p: u16| -> Option<TypeDesc> { None };
        assert_eq!(
            substitute(&body, &ctx, &mut no_mvars),
            TypeDesc::GenericInstance {
                definition: Box::new(ext("System.Collections.Generic", "Dictionary`2")),
                arguments: vec![
                    ext("System", "String"),
                    TypeDesc::GenericInstance {
                        definition: Box::new(ext("System.Collections.Generic", "List`1")),
                        arguments: vec![ext("System", "Boolean")],
                    },
                ],
            }
        );
    }

    #[test]
    fn signature_substitution_params_and_return() {
        // R Method<T>(T a, List<T> b) with T -> string
        let defs = vec![GenericParameter {
            name: "T".into(),
            position: 0,
            owner: crate::model::types::GenericOwner::Method(crate::model::types::MethodId(0)),
            ..GenericParameter::default()
        }];
        let sig = MethodSignature {
            has_this: false,
            explicit_this: false,
            convention: SignatureCallingConvention::Default,
            generic_count: 1,
            parameters: vec![
                TypeDesc::Var(0),
                TypeDesc::GenericInstance {
                    definition: Box::new(ext("System.Collections.Generic", "List`1")),
                    arguments: vec![TypeDesc::Var(0)],
                },
            ],
            return_type: TypeDesc::Var(0),
            vararg_start: 2,
        };
        let args = vec![ext("System", "String")];
        let ctx = build_generic_context(&defs, &args);
        let mut no_mvars = |_p: u16| -> Option<TypeDesc> { None };
        let out = substitute_signature(&sig, &ctx, &mut no_mvars);
        assert_eq!(out.return_type, ext("System", "String"));
        assert_eq!(out.parameters[0], ext("System", "String"));
        assert_eq!(out.generic_count, 1);
        assert_eq!(
            out.parameters[1],
            TypeDesc::GenericInstance {
                definition: Box::new(ext("System.Collections.Generic", "List`1")),
                arguments: vec![ext("System", "String")],
            }
        );
    }
}
