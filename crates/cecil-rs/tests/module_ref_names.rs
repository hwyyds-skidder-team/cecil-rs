//! ModuleRef identities must agree with P/Invoke and TypeRef scopes after
//! recovery decoding, including truncated and invalid UTF-8 heap names.

use cecil::model::types::{ScopeRef, TypeDesc};
use cecil::resolver::{MalformedInputPolicy, ReaderParameters};
use cecil::AssemblyDefinition;
use cecil_core::flags::{MethodAttributes, PInvokeAttributes};
use cecil_core::{token::coded, TableIndex as T};
use cecil_metadata::{encode_coded, parse_root, stream_slice, write_root, MetadataBuilder};
use cecil_pe::{EmitParts, Image, ImageWriter};

fn module_ref_image(name: &[u8]) -> Vec<u8> {
    let mut builder = MetadataBuilder::new("v4.0.30319");
    let module_name = builder.insert_string("module_ref_names.netmodule");
    builder.add_row(T::Module, &[0, module_name as u64, 0, 0, 0]).unwrap();
    let type_name = builder.insert_string("Imports");
    builder.add_row(T::TypeDef, &[0, type_name as u64, 0, 0, 1, 1]).unwrap();
    let imported_type_name = builder.insert_string("NativeType");
    let scope = encode_coded(&coded::RESOLUTION_SCOPE, T::ModuleRef, 1).unwrap();
    builder.add_row(T::TypeRef, &[scope, imported_type_name as u64, 0]).unwrap();
    let field_name = builder.insert_string("Value");
    let field_sig = builder.insert_blob(&[0x06, 0x12, 0x05]); // FIELD CLASS TypeRef(1)
    builder.add_row(T::Field, &[0, field_name as u64, field_sig as u64]).unwrap();
    let method_sig = builder.insert_blob(&[0, 0, 1]); // static void()
    for method in ["Import", "OtherImport"] {
        let method_name = builder.insert_string(method);
        let rid = builder
            .add_row(
                T::MethodDef,
                &[
                    0,
                    0,
                    (MethodAttributes::STATIC | MethodAttributes::PINVOKE_IMPL).bits() as u64,
                    method_name as u64,
                    method_sig as u64,
                    1,
                ],
            )
            .unwrap();
        let forwarded = encode_coded(&coded::MEMBER_FORWARDED, T::MethodDef, rid).unwrap();
        builder
            .add_row(
                T::ImplMap,
                &[
                    PInvokeAttributes::CALL_CONV_WINAPI.bits() as u64,
                    forwarded,
                    method_name as u64,
                    1,
                ],
            )
            .unwrap();
    }
    // Keep this name last so replacing the heap tail can remove its NUL.
    let name_index = builder.insert_string("native.dll");
    builder.add_row(T::ModuleRef, &[name_index as u64]).unwrap();
    let metadata = builder.finalize();
    let header = parse_root(&metadata).unwrap();
    let strings = header.streams.iter().find(|stream| stream.name == "#Strings").unwrap();
    let mut heap = stream_slice(&metadata, strings).unwrap()[..name_index as usize].to_vec();
    heap.extend_from_slice(name);
    let streams: Vec<_> = header
        .streams
        .iter()
        .map(|stream| {
            let payload = if stream.name == "#Strings" {
                heap.as_slice()
            } else {
                stream_slice(&metadata, stream).unwrap()
            };
            (stream.name.as_str(), payload)
        })
        .collect();
    let metadata = write_root(&header.version, &streams);
    let carrier = AssemblyDefinition::default().write().unwrap();
    ImageWriter::rebuild(
        &Image::parse(&carrier).unwrap(),
        EmitParts { metadata, ..Default::default() },
    )
    .emit()
    .unwrap()
}

fn assert_names(assembly: &AssemblyDefinition, expected: &str) {
    let module = assembly.main_module();
    assert_eq!(module.types.len(), 1);
    assert_eq!(module.fields.len(), 1);
    assert_eq!(module.methods.len(), 2);
    assert_eq!(module.module_refs, [expected]);
    for (method, entry_point) in module.methods.iter().zip(["Import", "OtherImport"]) {
        let pinvoke = method.pinvoke.as_ref().unwrap();
        assert_eq!(pinvoke.module, expected);
        assert_eq!(pinvoke.entry_point, entry_point);
        assert_eq!(pinvoke.attributes, PInvokeAttributes::CALL_CONV_WINAPI);
    }
    let TypeDesc::External(external) = &module.fields[0].signature.0 else {
        panic!("expected an external field type")
    };
    assert_eq!(external.name, "NativeType");
    assert_eq!(external.scope, ScopeRef::OtherModule(expected.to_owned()));
}

#[test]
fn recovered_module_ref_names_roundtrip_consistently() {
    let strict =
        ReaderParameters { malformed_input: MalformedInputPolicy::Strict, ..Default::default() };
    for (name, expected) in [
        (&b"shelAsyncStat"[..], "shelAsyncStat"), // Missing NUL in the clipped heap.
        (&b"\xff\x0f\x08\0"[..], "\u{fffd}\x0f\x08"),
        (&b"native-\xf0\x9f"[..], "native-\u{fffd}"), // Truncated UTF-8 and no NUL.
    ] {
        let bytes = module_ref_image(name);
        assert!(AssemblyDefinition::read_with(&bytes, &strict).is_err());
        let mut assembly = AssemblyDefinition::read(&bytes).unwrap();
        assert_names(&assembly, expected);
        assert!(assembly
            .main
            .read_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.table == Some(T::ModuleRef) && diagnostic.rid == 1));
        assert_eq!(assembly.write().unwrap(), bytes);
        // Exercise canonical emission of the recovered names as well as any
        // retained original-image path, with no dependency on fuzz archives.
        assembly.main.native_image = None;
        let output = assembly.write().unwrap();
        let reread = AssemblyDefinition::read_with(&output, &strict).unwrap();
        assert_names(&reread, expected);
        assert_names(&AssemblyDefinition::read(&reread.write().unwrap()).unwrap(), expected);
    }
}

#[test]
fn valid_module_ref_names_keep_strict_and_recovery_behavior() {
    let strict =
        ReaderParameters { malformed_input: MalformedInputPolicy::Strict, ..Default::default() };
    for name in ["native.dll", "本地模块.dll"] {
        let mut heap_name = name.as_bytes().to_vec();
        heap_name.push(0);
        let bytes = module_ref_image(&heap_name);
        for assembly in [
            AssemblyDefinition::read(&bytes).unwrap(),
            AssemblyDefinition::read_with(&bytes, &strict).unwrap(),
        ] {
            assert_names(&assembly, name);
            assert_names(&AssemblyDefinition::read(&assembly.write().unwrap()).unwrap(), name);
        }
    }
}

#[test]
fn module_ref_decoding_does_not_hide_missing_writer_references() {
    let mut assembly = AssemblyDefinition::read(&module_ref_image(b"native.dll\0")).unwrap();
    assembly.main.module_refs.clear();
    assert!(assembly.write().is_err());
}
