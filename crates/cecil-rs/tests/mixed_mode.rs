use cecil::assembly::{SymbolOutput, WriteParameters};
use cecil::model::types::{MethodId, RInstruction, ROperand};
use cecil::AssemblyDefinition;
use cecil_core::{Error, TableIndex};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(cecil_core::fixtures_dir().join(name)).unwrap()
}

#[test]
fn real_cppcli_images_roundtrip_with_native_payload_byte_for_byte() {
    for name in ["MixedNativeCLI.exe", "cppcli.dll"] {
        let bytes = fixture(name);
        let assembly = AssemblyDefinition::read(&bytes).unwrap();
        assert!(assembly.main.is_mixed_mode(), "{name}");
        assert!(!assembly.main.native_method_rvas.is_empty(), "{name}");
        for (&id, &rva) in &assembly.main.native_method_rvas {
            assert_ne!(rva, 0);
            assert!(
                assembly.main.methods[id.index()].body.is_none(),
                "native method must not decode as IL"
            );
        }
        assert_eq!(assembly.write().unwrap(), bytes, "{name}");
    }
}

#[test]
fn managed_body_can_grow_and_new_user_string_keeps_original_native_rvas() {
    let bytes = fixture("MixedNativeCLI.exe");
    let before = cecil_pe::Image::parse(&bytes).unwrap();
    let mut assembly = AssemblyDefinition::read(&bytes).unwrap();
    let (index, _) = assembly
        .main
        .methods
        .iter()
        .enumerate()
        .find(|(_, method)| {
            method.body.as_ref().is_some_and(|b| {
                b.exception_handlers.is_empty()
                    && b.instructions
                        .iter()
                        .all(|i| !matches!(i.operand, ROperand::Branch(_) | ROperand::Switch(_)))
            })
        })
        .unwrap();
    let original_native_rvas = assembly.main.native_method_rvas.clone();
    let body = assembly.main.methods[index].body.as_mut().unwrap();
    body.instructions.insert(
        0,
        RInstruction {
            offset: 0,
            opcode: cecil_cil::opcodes::LDSTR,
            operand: ROperand::String("mixed-mode appended user string 中文".into()),
        },
    );
    body.instructions.insert(
        1,
        RInstruction { offset: 5, opcode: cecil_cil::opcodes::POP, operand: ROperand::None },
    );
    cecil::edit::renumber(body);
    let out = assembly.write().unwrap();
    let after = cecil_pe::Image::parse(&out).unwrap();
    assert_eq!(after.sections.len(), before.sections.len() + 1);
    for section in &before.sections {
        let start = section.pointer_to_raw_data as usize;
        let end = start + section.size_of_raw_data as usize;
        let cli = before.rva_offset(before.cli_directory.virtual_address as u64).unwrap();
        let mut expected = bytes[start..end].to_vec();
        // Only the two CLI metadata directory fields change in old sections.
        if (start..end).contains(&cli) {
            expected[cli - start + 8..cli - start + 16].copy_from_slice(&out[cli + 8..cli + 16]);
        }
        assert_eq!(&out[start..end], expected, "native section {} stays fixed", section.name);
    }
    let reread = AssemblyDefinition::read(&out).unwrap();
    assert_eq!(reread.main.native_method_rvas, original_native_rvas);
    assert_eq!(
        reread.main.methods[index].body.as_ref().unwrap().instructions[0].operand,
        ROperand::String("mixed-mode appended user string 中文".into())
    );
    assert_eq!(reread.write().unwrap(), out);
}

#[test]
fn longer_definition_names_are_token_preserving_and_unsafe_edits_error() {
    let bytes = fixture("MixedNativeCLI.exe");
    let mut assembly = AssemblyDefinition::read(&bytes).unwrap();
    let name = "MuchLongerManagedTypeNameForNativePreservingWriter";
    assembly.main.types[1].name = name.into();
    assembly.name.name = "RenamedMixedNativeCLI".into();
    let out = assembly.write().unwrap();
    let reread = AssemblyDefinition::read(&out).unwrap();
    assert_eq!(reread.main.types[1].name, name);
    assert_eq!(reread.name.name, "RenamedMixedNativeCLI");
    let image = cecil_pe::Image::parse(&out).unwrap();
    let (rva, size) = image.metadata_rva().unwrap();
    let md = cecil_metadata::MetadataReader::parse(image.rva_bytes(rva, size).unwrap()).unwrap();
    assert_eq!(md.row_count(TableIndex::MethodDef) as usize, assembly.main.methods.len());
    assembly.main.methods[0].signature.has_this = !assembly.main.methods[0].signature.has_this;
    assert!(matches!(assembly.write(), Err(Error::Unsupported(_))));
    let mut assembly = AssemblyDefinition::read(&bytes).unwrap();
    let native = *assembly.main.native_method_rvas.keys().next().unwrap();
    assembly.main.methods[native.index()].body = Some(Default::default());
    assert!(matches!(assembly.write(), Err(Error::Unsupported(_))));
    let opts =
        WriteParameters { symbol_output: Some(SymbolOutput::PortablePdb), ..Default::default() };
    assert!(matches!(assembly.write_with(&opts), Err(Error::Unsupported(_))));
    let assembly = AssemblyDefinition::read(&bytes).unwrap();
    assert_eq!(assembly.write_with(&opts).unwrap(), bytes);
}

#[test]
fn native_cli_entrypoint_is_an_rva_and_never_a_method_token() {
    let mut bytes = fixture("MixedNativeCLI.exe");
    let image = cecil_pe::Image::parse(&bytes).unwrap();
    let cli = image.rva_offset(image.cli_directory.virtual_address as u64).unwrap();
    let flags = image.cli_header.flags | 0x10;
    // Deliberately look like a valid MethodDef token: the flag defines its meaning.
    let native_rva = 0x0600_0001u32;
    bytes[cli + 16..cli + 20].copy_from_slice(&flags.to_le_bytes());
    bytes[cli + 20..cli + 24].copy_from_slice(&native_rva.to_le_bytes());
    let assembly = AssemblyDefinition::read(&bytes).unwrap();
    assert_eq!(assembly.native_entry_point_rva(), Some(native_rva));
    assert!(assembly.entry_point.is_none());
    assert!(assembly.main.entry_point_token.is_nil());
    assert_eq!(assembly.write().unwrap(), bytes);
    let mut assembly = assembly;
    assembly.entry_point = Some(MethodId(0));
    assert!(matches!(assembly.write(), Err(Error::Unsupported(_))));
}

#[test]
fn native_pdb_exposes_native_addresses_and_managed_lines_separately() {
    let path = cecil_core::fixtures_dir().join("MixedNativeCLI.exe");
    let opts = cecil::resolver::ReaderParameters { read_symbols: true, ..Default::default() };
    let assembly = AssemblyDefinition::read_file_with(path, &opts).unwrap();
    let native = assembly.main.native_debug.as_ref().unwrap();
    assert!(native.functions.iter().any(|f| f.token.is_none() && f.rva.is_some()));
    assert!(native.functions.iter().any(|f| f.token.is_some() && !f.scopes.is_empty()));
    assert!(native.documents.iter().any(|d| !d.checksum.is_empty()));
    let managed = assembly.main.debug.as_ref().unwrap();
    assert!(!managed.points.is_empty());
    assert!(!managed.scopes.is_empty());
    for function in native.functions.iter().filter(|f| f.token.is_some()) {
        assert!(function.lines.iter().all(|line| line.rva.is_none()));
    }
}

#[test]
fn lazy_loading_keeps_edits_reviewable_and_does_not_bless_unsupported_changes() {
    let bytes = fixture("MixedNativeCLI.exe");
    let opts = cecil::resolver::ReaderParameters {
        reading_mode: cecil::resolver::ReadingMode::Lazy,
        ..Default::default()
    };
    let mut assembly = AssemblyDefinition::read_with(&bytes, &opts).unwrap();
    assert_eq!(assembly.write().unwrap(), bytes);
    assembly.main.types[1].name = "LongNameSetBeforeLoadingBodies".into();
    assembly.load_bodies().unwrap();
    let reread = AssemblyDefinition::read(&assembly.write().unwrap()).unwrap();
    assert_eq!(reread.main.types[1].name, "LongNameSetBeforeLoadingBodies");
    let mut assembly = AssemblyDefinition::read_with(&bytes, &opts).unwrap();
    assembly.main.methods[0].signature.has_this = !assembly.main.methods[0].signature.has_this;
    assembly.load_bodies().unwrap();
    assert!(matches!(assembly.write(), Err(Error::Unsupported(_))));

    let mut assembly = AssemblyDefinition::read_with(&bytes, &opts).unwrap();
    let native = *assembly.main.native_method_rvas.keys().next().unwrap();
    assembly.main.methods[native.index()].body = Some(Default::default());
    assembly.load_bodies().unwrap();
    assert!(matches!(assembly.write(), Err(Error::Unsupported(_))));
}

#[test]
fn edited_typed_operands_must_match_opcode_token_kind() {
    use cecil::model::types::{MethodRef, TypeDesc, TypeId};
    for (opcode, operand) in [
        (cecil_cil::opcodes::CALL, ROperand::Type(TypeDesc::Def(TypeId(0)))),
        (cecil_cil::opcodes::BOX, ROperand::Method(MethodRef::Def(MethodId(0)))),
    ] {
        let mut assembly = AssemblyDefinition::read(&fixture("MixedNativeCLI.exe")).unwrap();
        let body = assembly.main.methods.iter_mut().find_map(|m| m.body.as_mut()).unwrap();
        body.instructions.insert(0, RInstruction { offset: 0, opcode, operand });
        cecil::edit::renumber(body);
        assert!(matches!(assembly.write(), Err(Error::Argument(_))));
    }
}

#[test]
fn native_cli_directories_survive_even_with_il_only_flag_set() {
    let mut source = AssemblyDefinition::default();
    source.name.name = "AuxiliaryNativeDirectories".into();
    let mut bytes = source.write().unwrap();
    let image = cecil_pe::Image::parse(&bytes).unwrap();
    let cli = image.rva_offset(image.cli_directory.virtual_address as u64).unwrap();
    let fixups_rva = image.cli_directory.virtual_address;
    bytes[cli + 48..cli + 52].copy_from_slice(&fixups_rva.to_le_bytes());
    bytes[cli + 52..cli + 56].copy_from_slice(&4u32.to_le_bytes());
    let before = cecil_pe::Image::parse(&bytes).unwrap();
    assert!(before.has_native_payload());
    assert!(cecil_pe::ImageWriter::rebuild(&before, Default::default()).emit().is_err());
    let mut assembly = AssemblyDefinition::read(&bytes).unwrap();
    assert!(assembly.main.is_mixed_mode());
    assert_eq!(assembly.write().unwrap(), bytes);
    assembly.main.name = "RenamedWithNativeFixups.exe".into();
    let out = assembly.write().unwrap();
    let after = cecil_pe::Image::parse(&out).unwrap();
    assert_eq!(after.cli_header.vtable_fixups_rva, fixups_rva as u64);
    assert_eq!(after.cli_header.vtable_fixups_size, 4);
    assert_eq!(after.cli_header.flags, before.cli_header.flags);
}

#[test]
fn precompiled_native_maps_allow_passthrough_but_reject_metadata_relocation() {
    let mut bytes = fixture("hello.exe");
    let image = cecil_pe::Image::parse(&bytes).unwrap();
    let cli = image.rva_offset(image.cli_directory.virtual_address as u64).unwrap();
    bytes[cli + 64..cli + 68].copy_from_slice(&image.cli_directory.virtual_address.to_le_bytes());
    bytes[cli + 68..cli + 72].copy_from_slice(&4u32.to_le_bytes());
    let mut assembly = AssemblyDefinition::read(&bytes).unwrap();
    assert_eq!(assembly.write().unwrap(), bytes);
    assembly.main.name = "UnsafeRelocatedPrecompiledMetadata.exe".into();
    assert!(matches!(assembly.write(), Err(Error::Unsupported(_))));
}

#[test]
fn skipped_param_sequences_preserve_noop_and_other_supported_edits() {
    let mut bytes = fixture("MixedNativeCLI.exe");
    let image = cecil_pe::Image::parse(&bytes).unwrap();
    let (rva, size) = image.metadata_rva().unwrap();
    let root = image.rva_bytes(rva, size).unwrap();
    let md = cecil_metadata::MetadataReader::parse(root).unwrap();
    let header = cecil_metadata::parse_root(root).unwrap();
    let table = header.streams.iter().rev().find(|s| s.name == "#~" || s.name == "#-").unwrap();
    let stream = cecil_metadata::stream_slice(root, table).unwrap();
    let valid = u64::from_le_bytes(stream[8..16].try_into().unwrap());
    let start = 24 + valid.count_ones() as usize * 4 + if stream[6] & 0x40 != 0 { 4 } else { 0 };
    let (offset, width) = md.tables().cell_location(TableIndex::Param, 1, 1).unwrap();
    assert_eq!(width, 2);
    let at = image.rva_offset(rva).unwrap() + table.offset as usize + start + offset as usize;
    bytes[at..at + 2].copy_from_slice(&u16::MAX.to_le_bytes());
    let mut assembly = AssemblyDefinition::read(&bytes).unwrap();
    assert_eq!(assembly.write().unwrap(), bytes);
    assembly.main.types[1].name = "RenameDespiteSkippedParamSequence".into();
    assert!(AssemblyDefinition::read(&assembly.write().unwrap()).is_ok());
}

#[test]
fn nan_body_preserves_bits_without_rejecting_noop() {
    let bytes = fixture("MixedNativeCLI.exe");
    let mut assembly = AssemblyDefinition::read(&bytes).unwrap();
    let index = assembly
        .main
        .methods
        .iter()
        .position(|m| {
            m.body.as_ref().is_some_and(|b| {
                b.exception_handlers.is_empty()
                    && b.instructions
                        .iter()
                        .all(|i| !matches!(i.operand, ROperand::Branch(_) | ROperand::Switch(_)))
            })
        })
        .unwrap();
    let body = assembly.main.methods[index].body.as_mut().unwrap();
    body.instructions.insert(
        0,
        RInstruction {
            offset: 0,
            opcode: cecil_cil::opcodes::LDC_R8,
            operand: ROperand::Float64(f64::from_bits(0x7ff8_0000_0000_0055)),
        },
    );
    body.instructions.insert(
        1,
        RInstruction { offset: 9, opcode: cecil_cil::opcodes::POP, operand: ROperand::None },
    );
    cecil::edit::renumber(body);
    let out = assembly.write().unwrap();
    let reread = AssemblyDefinition::read(&out).unwrap();
    assert_eq!(reread.write().unwrap(), out);
}

#[test]
fn nan_metadata_constants_do_not_invalidate_native_snapshot_identity() {
    use cecil::model::types::{
        ConstantValue, FieldDefinition, FieldSignature, TypeDefinition, TypeDesc,
    };
    let mut assembly = AssemblyDefinition::default();
    assembly.name.name = "NanConstant".into();
    let owner =
        assembly.main.add_type(TypeDefinition { name: "Holder".into(), ..Default::default() });
    assembly.main.add_field(
        owner,
        FieldDefinition {
            name: "Value".into(),
            attributes: cecil_core::flags::FieldAttributes::PUBLIC
                | cecil_core::flags::FieldAttributes::STATIC
                | cecil_core::flags::FieldAttributes::LITERAL
                | cecil_core::flags::FieldAttributes::HAS_DEFAULT,
            signature: FieldSignature(TypeDesc::Internal("float64".into())),
            constant: Some(ConstantValue::F64(f64::from_bits(0x7ff8_0000_0000_0055))),
            ..Default::default()
        },
    );
    let mut bytes = assembly.write().unwrap();
    let image = cecil_pe::Image::parse(&bytes).unwrap();
    let cli = image.rva_offset(image.cli_directory.virtual_address as u64).unwrap();
    bytes[cli + 16..cli + 20].copy_from_slice(&(image.cli_header.flags & !1).to_le_bytes());
    let assembly = AssemblyDefinition::read(&bytes).unwrap();
    assert_eq!(assembly.write().unwrap(), bytes);
    let mut changed = assembly;
    changed.main.fields[0].constant =
        Some(ConstantValue::F64(f64::from_bits(0x7ff8_0000_0000_0056)));
    assert!(matches!(changed.write(), Err(Error::Unsupported(_))));
}

#[test]
fn structurally_equal_shared_type_graphs_are_bounded_and_changes_are_detected() {
    use cecil::model::types::{ExternalType, ScopeRef, TypeDesc};
    use std::sync::Arc;
    fn dag(depth: usize) -> TypeDesc {
        let mut node = TypeDesc::Internal("int32".into());
        for _ in 0..depth {
            let shared = Arc::new(node);
            node = TypeDesc::GenericInstance {
                definition: shared.clone(),
                arguments: vec![shared.clone(), shared].into(),
            };
        }
        node
    }
    let left = dag(48);
    let right = dag(48);
    assert_eq!(left, right);
    assert_ne!(left, dag(47));
    let mut left = Arc::new(ExternalType {
        namespace: "N".into(),
        name: "Root".into(),
        nesting: Vec::new(),
        scope: ScopeRef::ThisModule,
    });
    let mut right = left.clone();
    for i in 0..48 {
        left = Arc::new(ExternalType {
            namespace: "N".into(),
            name: i.to_string(),
            nesting: vec![left.clone(), left],
            scope: ScopeRef::ThisModule,
        });
        right = Arc::new(ExternalType {
            namespace: "N".into(),
            name: i.to_string(),
            nesting: vec![right.clone(), right],
            scope: ScopeRef::ThisModule,
        });
    }
    assert_eq!(left, right);
    // Iterative equality handles deeply constructed trees without stack recursion.
    let mut deep = TypeDesc::Sentinel;
    let mut other = TypeDesc::Sentinel;
    for _ in 0..20_000 {
        deep = TypeDesc::Ptr(Arc::new(deep));
        other = TypeDesc::Ptr(Arc::new(other));
    }
    assert_eq!(deep, other);
    // Recursive Arc destruction is unrelated to comparison and avoided here.
    std::mem::forget(deep);
    std::mem::forget(other);
}
