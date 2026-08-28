//! Core type system helpers (port of `Mono.Cecil/TypeSystem.cs`, the
//! `CommonTypeSystem` flavor).
//!
//! Cecil's `module.TypeSystem.Object`/`.String`/`.Int32`/… provide the 18
//! well-known `System.*` types with a correctly scoped core-library
//! reference. The Rust rendition is functional instead of object-shaped:
//!
//! * [`typedesc_for_primitive`] maps a CLI type name (`"Int32"`) to the
//!   [`TypeDesc`] that signature encoding writes with the right
//!   `ELEMENT_TYPE_*` shortcut (`TypeDesc::Internal("int32")`, encoded as
//!   `I4` instead of a `CLASS` + TypeRef cell).
//! * [`system_type`] resolves any `System.<name>` — primitive or not —
//!   against a module, reusing a core-library assembly reference
//!   (`mscorlib` / `System.Runtime` / `System.Private.CoreLib` /
//!   `netstandard`, Cecil `Mixin.IsCoreLibrary`) already present in the
//!   module's [`Module::assembly_refs`].
//!
//! Deviation from Cecil (documented simplification): Cecil's
//! `CommonTypeSystem.GetCoreLibraryReference` appends a fresh `mscorlib`
//! reference to the module when none exists; the frozen facade model keeps
//! `Module` shared behind `&` here, so the fallback returns a
//! [`ScopeRef::Moduleless`] external type instead of mutating the module.

use crate::model::types::{ExternalType, ScopeRef, TypeDesc};
use crate::module_def::Module;

/// Cecil `Mixin` core-library names (`TypeSystem.cs`): an assembly reference
/// matching any of these can scope `System.*` types.
const CORE_LIBRARY_NAMES: [&str; 4] =
    ["mscorlib", "System.Runtime", "System.Private.CoreLib", "netstandard"];

/// CLI name of a core type -> the canonical [`TypeDesc::Internal`] name
/// (or [`TypeDesc::TypedByRef`], which has a dedicated variant).
///
/// Every one of Cecil's 18 `TypeSystem` types (`TypeSystem.cs` Object …
/// TypedReference) carries an `ElementType` code, so none of them needs an
/// external TypeRef to encode correctly.
fn core_primitive(name: &str) -> Option<TypeDesc> {
    let internal = match name {
        "Object" => "object",
        "Void" => "void",
        "Boolean" => "bool",
        "Char" => "char",
        "SByte" => "int8",
        "Byte" => "uint8",
        "Int16" => "int16",
        "UInt16" => "uint16",
        "Int32" => "int32",
        "UInt32" => "uint32",
        "Int64" => "int64",
        "UInt64" => "uint64",
        "Single" => "float32",
        "Double" => "float64",
        "IntPtr" => "intptr",
        "UIntPtr" => "uintptr",
        "String" => "string",
        "TypedReference" => return Some(TypeDesc::TypedByRef),
        _ => return None,
    };
    debug_assert!(
        crate::model::signature::primitive_code(internal).is_some(),
        "core type {name} must map to a primitive element code"
    );
    Some(TypeDesc::Internal(internal.to_string()))
}

/// Returns the [`TypeDesc`] for one of Cecil's 18 core types, given its CLI
/// name (`"Object"`, `"Int32"`, `"TypedReference"`, …).
///
/// The result encodes as the matching `ELEMENT_TYPE_*` shortcut, so a field
/// or parameter typed `Int32` serializes as `I4` rather than a `CLASS`
/// element referencing a `System.Int32` TypeRef — exactly what Cecil's
/// `TypeSystem.Int32` guarantees through the `etype` it stamps on the
/// reference.
pub fn typedesc_for_primitive(name: &str) -> Option<TypeDesc> {
    core_primitive(name)
}

/// Finds a core-library scope for `module`: the first assembly reference
/// whose name is one of Cecil's core libraries (search order: declaration
/// order in `assembly_refs`, like `Mixin.TryGetCoreLibraryReference`).
fn core_library_scope(module: &Module) -> ScopeRef {
    for name in CORE_LIBRARY_NAMES {
        if let Some(reference) = module.assembly_refs.iter().find(|r| r.name == name) {
            return ScopeRef::Assembly(reference.clone());
        }
    }
    ScopeRef::Moduleless
}

/// Resolves `System.<name>` against `module` (Cecil
/// `TypeSystem.LookupType("System", name)`).
///
/// * Core primitives (`"Int32"`, `"String"`, `"Object"`, …) come back as
///   [`TypeDesc::Internal`] / [`TypeDesc::TypedByRef`] so they encode with
///   their element-type shortcut.
/// * Anything else (`"ValueType"`, `"Enum"`, `"Attribute"`, …) becomes an
///   external `System` type scoped to the module's existing core-library
///   reference, or [`ScopeRef::Moduleless`] when the module references no
///   core library (see the module docs for the deviation from Cecil's
///   reference-appending behavior).
///
/// If the module itself defines `System.<name>`, that definition wins
/// (Cecil's `CoreTypeSystem` semantics for the core library itself).
pub fn system_type(module: &Module, name: &str) -> TypeDesc {
    if let Some(primitive) = core_primitive(name) {
        return primitive;
    }
    if let Some((id, _)) =
        module.iter_types().find(|(_, def)| def.namespace == "System" && def.name == name)
    {
        return TypeDesc::Def(id);
    }
    TypeDesc::External(Box::new(ExternalType {
        namespace: "System".to_string(),
        name: name.to_string(),
        nesting: Vec::new(),
        scope: core_library_scope(module),
    }))
}

macro_rules! core_type_accessors {
    ($($fn_name:ident => $cli_name:expr),+ $(,)?) => {
        $(
            /// Named accessor for the `System.<cli>` core type (Cecil
            /// `ModuleDefinition.TypeSystem` property of the same name).
            pub fn $fn_name(module: &Module) -> TypeDesc {
                system_type(module, $cli_name)
            }
        )+
    };
}

core_type_accessors! {
    object => "Object",
    void => "Void",
    boolean => "Boolean",
    char_ => "Char",
    sbyte => "SByte",
    byte => "Byte",
    int16 => "Int16",
    uint16 => "UInt16",
    int32 => "Int32",
    uint32 => "UInt32",
    int64 => "Int64",
    uint64 => "UInt64",
    single => "Single",
    double => "Double",
    intptr => "IntPtr",
    uintptr => "UIntPtr",
    string => "String",
    typed_reference => "TypedReference",
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::AssemblyNameReference;

    /// Primitives map to Internal names the encoder knows; every Cecil
    /// core type is covered.
    #[test]
    fn core_types_cover_cecils_eighteen() {
        let cecil_names = [
            "Object",
            "Void",
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
            "String",
            "TypedReference",
        ];
        for name in cecil_names {
            assert!(typedesc_for_primitive(name).is_some(), "{name} missing");
        }
        assert!(typedesc_for_primitive("Guid").is_none(), "non-core rejected");
        assert!(typedesc_for_primitive("int32").is_none(), "ILAsm name rejected");
    }

    #[test]
    fn primitive_shapes() {
        assert_eq!(typedesc_for_primitive("Int32"), Some(TypeDesc::Internal("int32".into())));
        assert_eq!(typedesc_for_primitive("Object"), Some(TypeDesc::Internal("object".into())));
        assert_eq!(typedesc_for_primitive("String"), Some(TypeDesc::Internal("string".into())));
        assert_eq!(typedesc_for_primitive("IntPtr"), Some(TypeDesc::Internal("intptr".into())));
        assert_eq!(typedesc_for_primitive("UIntPtr"), Some(TypeDesc::Internal("uintptr".into())));
        assert_eq!(typedesc_for_primitive("TypedReference"), Some(TypeDesc::TypedByRef));
    }

    /// Non-primitive System types scope to an existing core-library
    /// reference; without one, the scope degrades to Moduleless.
    #[test]
    fn non_primitive_scopes_to_core_library() {
        let with_runtime = Module {
            assembly_refs: vec![
                AssemblyNameReference::new("System.Linq"),
                AssemblyNameReference::new("System.Runtime"),
            ],
            ..Module::default()
        };
        let ty = system_type(&with_runtime, "ValueType");
        match ty {
            TypeDesc::External(ext) => {
                assert_eq!(ext.namespace, "System");
                assert_eq!(ext.name, "ValueType");
                assert!(matches!(
                    &ext.scope,
                    ScopeRef::Assembly(r) if r.name == "System.Runtime"
                ));
            }
            other => panic!("expected external, got {other:?}"),
        }

        let bare = Module::default();
        let ty = system_type(&bare, "Enum");
        match ty {
            TypeDesc::External(ext) => assert_eq!(ext.scope, ScopeRef::Moduleless),
            other => panic!("expected external, got {other:?}"),
        }
    }

    /// A module-local System definition wins over an external reference
    /// (CoreTypeSystem semantics for the core library itself).
    #[test]
    fn module_local_system_type_wins() {
        let mut module = Module::default();
        let tid = crate::model::types::TypeId(module.types.len() as u32);
        module.types.push(crate::model::types::TypeDefinition {
            namespace: "System".into(),
            name: "ValueType".into(),
            ..Default::default()
        });
        assert_eq!(system_type(&module, "ValueType"), TypeDesc::Def(tid));
    }

    /// Every named accessor is primitive-shaped and encodes with an element
    /// shortcut (`int32` -> I4), never a CLASS cell.
    #[test]
    fn named_accessors_are_primitives() {
        let module = Module::default();
        assert_eq!(int32(&module), TypeDesc::Internal("int32".into()));
        assert_eq!(object(&module), TypeDesc::Internal("object".into()));
        assert_eq!(string(&module), TypeDesc::Internal("string".into()));
        assert_eq!(typed_reference(&module), TypeDesc::TypedByRef);
    }

    /// int32 round-trips through the signature encoder as ELEMENT_TYPE_I4.
    #[test]
    fn int32_encodes_as_element_i4() {
        let module = Module::default();
        let ty = int32(&module);
        let mut w = cecli_core::io::ByteWriter::new();
        crate::model::signature::write_type_element(&ty, &mut w, &()).expect("int32 encodes");
        assert_eq!(w.into_vec(), vec![0x08], "ELEMENT_TYPE_I4");
    }
}
