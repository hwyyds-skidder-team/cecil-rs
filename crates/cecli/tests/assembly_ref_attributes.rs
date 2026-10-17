//! AssemblyRef attributes must not change how TypeRef scopes find their rows.

use cecli::model::types::{MethodRef, ScopeRef, TypeDesc};
use cecli::AssemblyDefinition;
use cecli_core::{token::coded, TableIndex as T};
use cecli_metadata::{encode_coded, MetadataBuilder};
use cecli_pe::{EmitParts, Image, ImageWriter};

#[test]
fn assembly_ref_attributes_preserve_type_scopes_across_roundtrip() {
    let mut builder = MetadataBuilder::new("v4.0.30319");
    let name = builder.insert_string("assembly_ref_attributes.netmodule");
    builder.add_row(T::Module, &[0, name as u64, 0, 0, 0]).unwrap();
    let assembly = builder.insert_string("System.Drawing");
    builder.add_row(T::AssemblyRef, &[2, 0, 0, 0, 0, 0, assembly as u64, 0, 0]).unwrap();
    let scope = encode_coded(&coded::RESOLUTION_SCOPE, T::AssemblyRef, 1).unwrap();
    for name in ["BaseType", "MarkerAttribute"] {
        let name = builder.insert_string(name);
        builder.add_row(T::TypeRef, &[scope, name as u64, 0]).unwrap();
    }
    let base = encode_coded(&coded::TYPE_DEF_OR_REF, T::TypeRef, 1).unwrap();
    for (name, base) in [("<Module>", 0), ("Derived", base)] {
        let name = builder.insert_string(name);
        builder.add_row(T::TypeDef, &[0, name as u64, 0, base, 1, 1]).unwrap();
    }
    let ctor = builder.insert_string(".ctor");
    let sig = builder.insert_blob(&[0x20, 0x00, 0x01]); // instance void ()
    let parent = encode_coded(&coded::MEMBER_REF_PARENT, T::TypeRef, 2).unwrap();
    builder.add_row(T::MemberRef, &[parent, ctor as u64, sig as u64]).unwrap();
    let owner = encode_coded(&coded::HAS_CUSTOM_ATTRIBUTE, T::AssemblyRef, 1).unwrap();
    let ctor = encode_coded(&coded::CUSTOM_ATTRIBUTE_TYPE, T::MemberRef, 1).unwrap();
    let blob = builder.insert_blob(&[1, 0, 0, 0]);
    builder.add_row(T::CustomAttribute, &[owner, ctor, blob as u64]).unwrap();

    let carrier = AssemblyDefinition::default().write().unwrap();
    let image = Image::parse(&carrier).unwrap();
    let bytes = ImageWriter::rebuild(
        &image,
        EmitParts { metadata: builder.finalize(), ..Default::default() },
    )
    .emit()
    .unwrap();
    let mut asm = AssemblyDefinition::read(&bytes).unwrap();
    let expected_refs = asm.main.assembly_refs.clone();
    let expected_base = asm.main.types[1].base_type.clone();

    // The attribute constructor itself references its owning assembly. Its
    // scope, like the base type's scope, was decoded before attaching attributes.
    for _ in 0..2 {
        assert_eq!(asm.main.types.len(), 2);
        assert_eq!(asm.main.assembly_refs, expected_refs);
        assert_eq!(asm.main.types[1].base_type, expected_base);
        let attrs = &asm.main.assembly_refs[0].custom_attributes;
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].blob, [1, 0, 0, 0]);
        let MethodRef::External(ctor) = &attrs[0].constructor else {
            panic!("expected external attribute constructor");
        };
        let TypeDesc::External(ty) = &ctor.parent else {
            panic!("expected external attribute type");
        };
        let ScopeRef::Assembly(scope) = &ty.scope else {
            panic!("expected AssemblyRef scope");
        };
        assert_eq!(scope.name, "System.Drawing");
        assert!(scope.custom_attributes.is_empty());
        asm = AssemblyDefinition::read(&asm.write().unwrap()).unwrap();
    }
    assert_eq!(asm.main.assembly_refs, expected_refs);
    assert_eq!(asm.main.types[1].base_type, expected_base);
}
