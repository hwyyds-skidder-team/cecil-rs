//! Small hostile ownership graphs must remain safe for model traversal/writing.
use cecil::AssemblyDefinition;
use cecil_core::TableIndex as T;
use cecil_metadata::MetadataBuilder;
use cecil_pe::{EmitParts, Image, ImageWriter};

fn image(builder: MetadataBuilder) -> Vec<u8> {
    let mut carrier_asm = AssemblyDefinition::default();
    carrier_asm.main.attributes = cecil_core::flags::ModuleAttributes::IL_ONLY;
    let carrier = carrier_asm.write().unwrap();
    let parsed = Image::parse(&carrier).unwrap();
    ImageWriter::rebuild(&parsed, EmitParts { metadata: builder.finalize(), ..Default::default() })
        .emit()
        .unwrap()
}

fn builder() -> MetadataBuilder {
    let mut md = MetadataBuilder::new("v4.0.30319");
    let name = md.insert_string("graph.netmodule");
    md.add_row(T::Module, &[0, name as u64, 0, 0, 0]).unwrap();
    md
}

#[test]
fn nesting_cycles_are_cut_before_model_traversal() {
    for pairs in [vec![(1, 1)], vec![(1, 2), (2, 1)], vec![(1, 2), (2, 3), (3, 1)]] {
        let mut md = builder();
        for name in ["A", "B", "C"] {
            let name = md.insert_string(name);
            md.add_row(T::TypeDef, &[0, name as u64, 0, 0, 1, 1]).unwrap();
        }
        for (child, parent) in pairs {
            md.add_row(T::NestedClass, &[child, parent]).unwrap();
        }
        let asm = AssemblyDefinition::read(&image(md)).unwrap();
        for (id, _) in asm.main.iter_types() {
            assert!(!asm.main.type_full_name(id).is_empty());
        }
        let written = asm.write().unwrap();
        assert_eq!(AssemblyDefinition::read(&written).unwrap().main.types.len(), 3);
    }
}

#[test]
fn overlapping_member_ranges_attach_each_row_once() {
    let mut md = builder();
    for index in 0..256 {
        let name = md.insert_string(&format!("T{index}"));
        let start = if index % 2 == 0 { 1 } else { 257 };
        md.add_row(T::TypeDef, &[0, name as u64, 0, 0, start, start]).unwrap();
    }
    let field_sig = md.insert_blob(&[6, 8]);
    let method_sig = md.insert_blob(&[0, 0, 1]);
    for index in 0..256 {
        let name = md.insert_string(&format!("M{index}"));
        md.add_row(T::Field, &[0, name as u64, field_sig as u64]).unwrap();
        md.add_row(T::MethodDef, &[0, 0, 0, name as u64, method_sig as u64, 1]).unwrap();
    }
    let asm = AssemblyDefinition::read(&image(md)).unwrap();
    assert_eq!(asm.main.types.iter().map(|t| t.fields.len()).sum::<usize>(), 256);
    assert_eq!(asm.main.types.iter().map(|t| t.methods.len()).sum::<usize>(), 256);
    let reread = AssemblyDefinition::read(&asm.write().unwrap()).unwrap();
    assert_eq!(reread.main.fields.len(), 256);
    assert_eq!(reread.main.methods.len(), 256);
}

#[test]
fn unowned_member_rows_preserve_recovery_image_and_fail_strict_reads() {
    let mut md = builder();
    let name = md.insert_string("Unowned");
    md.add_row(T::TypeDef, &[0, name as u64, 0, 0, 2, 2]).unwrap();
    let field_sig = md.insert_blob(&[6, 8]);
    let method_sig = md.insert_blob(&[0, 0, 1]);
    md.add_row(T::Field, &[0, name as u64, field_sig as u64]).unwrap();
    md.add_row(T::MethodDef, &[0, 0, 0, name as u64, method_sig as u64, 1]).unwrap();
    let bytes = image(md);
    let recovered = AssemblyDefinition::read(&bytes).unwrap();
    assert_eq!(
        AssemblyDefinition::read(&recovered.write().unwrap()).unwrap().main.methods.len(),
        1
    );
    let opts = cecil::resolver::ReaderParameters {
        malformed_input: cecil::resolver::MalformedInputPolicy::Strict,
        ..Default::default()
    };
    assert!(AssemblyDefinition::read_with(&bytes, &opts).is_err());
    assert!(!recovered.main.read_diagnostics.is_empty());
}
