//! Editing existing types must not confuse stable arena handles with emitted RIDs.

use cecil::model::types::{
    FieldDefinition, FieldRef, FieldSignature, MethodDefinition, MethodRef, MethodSignature,
    RInstruction, ROperand, ResolvedBody, TypeDefinition, TypeDesc,
};
use cecil::{AssemblyDefinition, Module};
use cecil_cil::opcode_table as op;
use cecil_core::flags::{FieldAttributes, MethodAttributes, ModuleAttributes};

fn instruction(offset: i32, opcode: cecil_cil::OpCode, operand: ROperand) -> RInstruction {
    RInstruction { offset, opcode, operand }
}

fn method(name: &str, result: &str, instructions: Vec<RInstruction>) -> MethodDefinition {
    MethodDefinition {
        name: name.into(),
        attributes: MethodAttributes::PUBLIC | MethodAttributes::STATIC,
        signature: MethodSignature {
            has_this: false,
            return_type: TypeDesc::Internal(result.into()),
            ..Default::default()
        },
        body: Some(ResolvedBody { max_stack: 2, instructions, ..Default::default() }),
        ..Default::default()
    }
}

fn members(module: &Module) -> Vec<(String, Vec<String>, Vec<String>)> {
    module
        .types
        .iter()
        .map(|ty| {
            (
                ty.name.clone(),
                ty.methods.iter().map(|&id| module.method_def(id).name.clone()).collect(),
                ty.fields.iter().map(|&id| module.fields[id.index()].name.clone()).collect(),
            )
        })
        .collect()
}

fn appended_fixture(reverse: bool) -> AssemblyDefinition {
    let mut asm = AssemblyDefinition::default();
    asm.name.name = "MemberEmission".into();
    let module = asm.main_module_mut();
    module.name = "MemberEmission.exe".into();
    module.attributes = ModuleAttributes::IL_ONLY;
    module.add_type(TypeDefinition { name: "<Module>".into(), ..Default::default() });
    let first = module.add_type(TypeDefinition { name: "First".into(), ..Default::default() });
    module.add_type(TypeDefinition { name: "Empty".into(), ..Default::default() });
    let second = module.add_type(TypeDefinition { name: "Second".into(), ..Default::default() });
    module.add_method(
        first,
        method("Original", "void", vec![instruction(0, op::RET, ROperand::None)]),
    );
    let main = module.add_method(second, method("Main", "void", vec![]));
    for (owner, name) in [(first, "FirstField"), (second, "SecondField")] {
        module.add_field(
            owner,
            FieldDefinition {
                name: name.into(),
                attributes: FieldAttributes::PUBLIC | FieldAttributes::STATIC,
                signature: FieldSignature(TypeDesc::Internal("int32".into())),
                ..Default::default()
            },
        );
    }
    let field = module.add_field(
        first,
        FieldDefinition {
            name: "LateField".into(),
            attributes: FieldAttributes::PUBLIC | FieldAttributes::STATIC,
            signature: FieldSignature(TypeDesc::Internal("int32".into())),
            ..Default::default()
        },
    );
    let helper = module.add_method(
        first,
        method(
            "LateHelper",
            "int32",
            vec![
                instruction(0, op::LDC_I4, ROperand::Int32(42)),
                instruction(5, op::RET, ROperand::None),
            ],
        ),
    );
    module.method_mut(main).unwrap().body.as_mut().unwrap().instructions = vec![
        instruction(0, op::CALL, ROperand::Method(MethodRef::Def(helper))),
        instruction(5, op::STSFLD, ROperand::Field(FieldRef::Def(field))),
        instruction(10, op::RET, ROperand::None),
    ];
    if reverse {
        module.type_mut(first).unwrap().methods.reverse();
        module.type_mut(first).unwrap().fields.reverse();
    }
    asm.entry_point = Some(main);
    asm
}

#[test]
fn appended_and_reordered_members_preserve_owners_entry_and_il_references() {
    for reverse in [false, true] {
        let asm = appended_fixture(reverse);
        let expected = members(asm.main_module());
        let before = asm.main_module().clone();
        let bytes = asm.write().unwrap();
        assert_eq!(asm.main_module(), &before, "writing must not invalidate caller handles");
        assert_eq!(asm.write().unwrap(), bytes, "writing must be deterministic");
        let re = AssemblyDefinition::read_with(
            &bytes,
            &cecil::resolver::ReaderParameters {
                malformed_input: cecil::resolver::MalformedInputPolicy::Strict,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(members(re.main_module()), expected);
        let main = re.entry_point_method().unwrap();
        assert_eq!(main.name, "Main");
        let instructions = &main.body.as_ref().unwrap().instructions;
        let ROperand::Method(MethodRef::Def(helper)) = instructions[0].operand else {
            panic!("call was not resolved to a method definition");
        };
        assert_eq!(re.main_module().method_def(helper).name, "LateHelper");
        let ROperand::Field(FieldRef::Def(field)) = instructions[1].operand else {
            panic!("field store was not resolved to a field definition");
        };
        assert_eq!(re.main_module().fields[field.index()].name, "LateField");
    }
}

#[test]
fn portable_and_native_symbols_follow_emitted_method_rids() {
    use cecil::module_def::{CustomDebugInformation, ModuleDebugInfo};
    use cecil_core::{TableIndex as T, Token};
    use cecil_pdb::document::Document;
    use cecil_pdb::portable_reader::{LocalScope, PortablePdbReader, SequencePoint};
    use std::collections::BTreeMap;

    let mut asm = appended_fixture(false);
    let main = asm.entry_point.unwrap();
    let helper = asm.main_module().iter_methods().find(|(_, m)| m.name == "LateHelper").unwrap().0;
    let point = |line| SequencePoint {
        offset: 0,
        start_line: line,
        end_line: line,
        start_column: 1,
        end_column: 2,
    };
    asm.main.entry_point_token = Token::new(T::MethodDef, main.0 + 1);
    asm.main.debug = Some(ModuleDebugInfo {
        documents: vec![Document {
            name: "MemberEmission.cs".into(),
            hash_algorithm: [0; 16],
            hash: vec![],
            language: [0; 16],
        }],
        points: BTreeMap::from([
            (main.0 + 1, vec![(0, vec![point(20)])]),
            (helper.0 + 1, vec![(0, vec![point(10)])]),
        ]),
        scopes: BTreeMap::from([(
            main.0 + 1,
            vec![LocalScope {
                method: Token::new(T::MethodDef, main.0 + 1),
                import_scope: 0,
                variables: vec![],
                constants: vec![],
                kind: 0,
                try_start: 0,
                try_length: 1,
                handler_start: -1,
                handler_length: -1,
            }],
        )]),
        custom_debug_info: vec![CustomDebugInformation {
            parent: Token::new(T::MethodDef, main.0 + 1),
            kind: [1; 16],
            value: b"main-info".to_vec(),
        }],
    });
    let re = AssemblyDefinition::read(&asm.write().unwrap()).unwrap();
    let emitted_main = re.entry_point.unwrap().0 + 1;
    let emitted_helper =
        re.main_module().iter_methods().find(|(_, m)| m.name == "LateHelper").unwrap().0 .0 + 1;

    let pdb = cecil::assembly::build_portable_pdb(&asm.main).unwrap();
    let reader = PortablePdbReader::parse(&pdb).unwrap();
    assert_eq!(reader.entry_point(), Token::new(T::MethodDef, emitted_main));
    assert_eq!(reader.sequence_points(emitted_main).unwrap().unwrap().1[0].start_line, 20);
    assert_eq!(reader.sequence_points(emitted_helper).unwrap().unwrap().1[0].start_line, 10);
    assert_eq!(reader.local_scopes(emitted_main).unwrap().len(), 1);
    assert_eq!(reader.custom_debug_informations().unwrap()[0].parent, reader.entry_point());

    let pdb = cecil::assembly::build_native_pdb(&asm.main).unwrap();
    let reader = cecil_pdb::native::NativePdbReader::open(&pdb).unwrap();
    for (rid, name, line) in [(emitted_main, "Main", 20), (emitted_helper, "LateHelper", 10)] {
        let function = reader
            .function_debug_info()
            .iter()
            .find(|f| f.token == Some(Token::new(T::MethodDef, rid)))
            .unwrap();
        assert_eq!(function.name, name);
        assert_eq!(function.lines[0].start_line, line);
    }
}

#[test]
fn member_annotations_semantics_generics_and_raw_tokens_follow_owner_order() {
    use cecil::assembly::{SymbolOutput, WriteParameters};
    use cecil::model::types::{
        ConstantValue, CustomAttribute, EventDefinition, GenericOwner, GenericParameter,
        MarshalInfo, MethodOverride, NativeTypeSpec, Parameter, PropertyDefinition,
        PropertySignature, TypeId,
    };
    use cecil::module_def::{CustomDebugInformation, ModuleDebugInfo};
    use cecil_core::{TableIndex as T, Token};

    for reverse in [false, true] {
        let mut asm = appended_fixture(reverse);
        let first = TypeId(1);
        let second = TypeId(3);
        let helper = asm.main.iter_methods().find(|(_, m)| m.name == "LateHelper").unwrap().0;
        let field = asm.main.iter_fields().find(|(_, f)| f.name == "LateField").unwrap().0;
        let mut constructor =
            method(".ctor", "void", vec![instruction(0, op::RET, ROperand::None)]);
        constructor.attributes = MethodAttributes::PUBLIC
            | MethodAttributes::SPECIAL_NAME
            | MethodAttributes::RTSPECIAL_NAME;
        constructor.signature.has_this = true;
        constructor.signature.parameters = vec![TypeDesc::Internal("int32".into())];
        constructor.signature.vararg_start = 1;
        let ctor = asm.main.add_method(first, constructor);
        let annotation = |tag: u8| CustomAttribute {
            constructor: MethodRef::Def(ctor),
            blob: vec![1, 0, tag, 0, 0, 0, 0, 0],
        };
        let marshal = MarshalInfo { spec: NativeTypeSpec::I4 };
        let late = &mut asm.main.fields[field.index()];
        late.constant = Some(ConstantValue::I32(7));
        late.initial_value = vec![1, 2, 3, 4];
        late.offset = Some(16);
        late.marshal_info = Some(marshal.clone());
        late.custom_attributes.push(annotation(10));
        late.attributes |= FieldAttributes::HAS_DEFAULT | FieldAttributes::HAS_FIELD_RVA;

        let mut generic_methods = Vec::new();
        for (owner, name, tag) in [(second, "GenericSecond", 20), (first, "GenericFirst", 30)] {
            let mut generic = method(
                name,
                "int32",
                vec![
                    instruction(0, op::LDARG_0, ROperand::None),
                    instruction(1, op::RET, ROperand::None),
                ],
            );
            generic.signature.generic_count = 1;
            generic.signature.parameters = vec![TypeDesc::Internal("int32".into())];
            generic.signature.vararg_start = 1;
            generic.parameters = vec![Parameter {
                name: format!("{name}Arg"),
                sequence: 1,
                constant: Some(ConstantValue::I32(tag as i32)),
                marshal_info: Some(marshal.clone()),
                custom_attributes: vec![annotation(tag + 1)],
                ..Default::default()
            }];
            generic.return_parameter = Parameter {
                name: format!("{name}Result"),
                custom_attributes: vec![annotation(tag + 2)],
                ..Default::default()
            };
            generic.custom_attributes.push(annotation(tag));
            generic_methods.push(asm.main.add_method(owner, generic));
        }
        let generic_first = generic_methods[1];
        asm.main.methods[generic_first.index()].overrides.push(MethodOverride {
            body: MethodRef::Def(generic_first),
            declaration: MethodRef::Def(generic_methods[0]),
        });
        for (id, name, tag) in [(generic_methods[0], "TSecond", 40), (generic_first, "TFirst", 50)]
        {
            let mut constraint: cecil::model::types::GenericParamConstraint =
                TypeDesc::Def(second).into();
            constraint.custom_attributes.push(annotation(tag + 1));
            asm.main.add_generic_parameter(GenericParameter {
                name: name.into(),
                owner: GenericOwner::Method(id),
                constraints: vec![constraint],
                custom_attributes: vec![annotation(tag)],
                ..Default::default()
            });
        }
        for (owner, name, tag) in [(second, "SecondProperty", 60), (first, "FirstProperty", 70)] {
            asm.main.add_property(
                owner,
                PropertyDefinition {
                    name: name.into(),
                    signature: PropertySignature {
                        has_this: false,
                        parameters: vec![],
                        property_type: TypeDesc::Internal("int32".into()),
                    },
                    get_method: Some(helper),
                    constant: Some(ConstantValue::I32(tag as i32)),
                    custom_attributes: vec![annotation(tag)],
                    ..Default::default()
                },
            );
        }
        for (owner, name, tag) in [(second, "SecondEvent", 80), (first, "FirstEvent", 90)] {
            asm.main.add_event(
                owner,
                EventDefinition {
                    name: name.into(),
                    event_type: Some(TypeDesc::Def(second)),
                    add_on: Some(generic_first),
                    remove_on: Some(generic_methods[0]),
                    custom_attributes: vec![annotation(tag)],
                    ..Default::default()
                },
            );
        }
        asm.main.methods[asm.entry_point.unwrap().index()].body.as_mut().unwrap().instructions = vec![
            instruction(0, op::LDTOKEN, ROperand::Token(Token::new(T::Field, field.0 + 1))),
            instruction(5, op::POP, ROperand::None),
            instruction(6, op::LDTOKEN, ROperand::Token(Token::new(T::MethodDef, helper.0 + 1))),
            instruction(11, op::POP, ROperand::None),
            instruction(12, op::LDC_I4_7, ROperand::None),
            instruction(
                13,
                op::CALL,
                ROperand::Method(MethodRef::Spec {
                    method: std::sync::Arc::new(MethodRef::Def(generic_first)),
                    arguments: vec![TypeDesc::Internal("int32".into())].into(),
                }),
            ),
            instruction(18, op::POP, ROperand::None),
            instruction(19, op::CALL, ROperand::Method(MethodRef::Def(helper))),
            instruction(24, op::STSFLD, ROperand::Field(FieldRef::Def(field))),
            instruction(29, op::RET, ROperand::None),
        ];
        asm.main.debug = Some(ModuleDebugInfo {
            custom_debug_info: [
                (T::Property, 2, "FirstProperty"),
                (T::Event, 2, "FirstEvent"),
                (T::Param, 4, "GenericFirstArg"),
                (T::GenericParam, 2, "TFirst"),
                (T::GenericParamConstraint, 2, "TFirstConstraint"),
            ]
            .into_iter()
            .map(|(table, rid, value)| CustomDebugInformation {
                parent: Token::new(table, rid),
                kind: [1; 16],
                value: value.as_bytes().to_vec(),
            })
            .collect(),
            ..Default::default()
        });
        let before = asm.main.clone();
        let bytes = asm
            .write_with(&WriteParameters {
                symbol_output: Some(SymbolOutput::EmbeddedPortablePdb),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(asm.main, before);
        let re = AssemblyDefinition::read(&bytes).unwrap();
        let check_annotation = |attributes: &[CustomAttribute], tag| {
            assert_eq!(attributes.len(), 1);
            assert_eq!(attributes[0].blob[2], tag);
            let MethodRef::Def(id) = attributes[0].constructor else {
                panic!("lost local constructor")
            };
            let constructor = re.main.method_def(id);
            assert_eq!(constructor.name, ".ctor");
            assert_eq!(re.main.types[constructor.declaring_type.index()].name, "First");
        };
        let late = re.main.fields.iter().find(|f| f.name == "LateField").unwrap();
        assert_eq!(late.constant, Some(ConstantValue::I32(7)));
        assert_eq!(late.initial_value, [1, 2, 3, 4]);
        assert_eq!(late.offset, Some(16));
        assert_eq!(late.marshal_info, Some(marshal.clone()));
        check_annotation(&late.custom_attributes, 10);
        for (name, tag) in [("GenericSecond", 20), ("GenericFirst", 30)] {
            let method = re.main.methods.iter().find(|m| m.name == name).unwrap();
            check_annotation(&method.custom_attributes, tag);
            check_annotation(&method.parameters[0].custom_attributes, tag + 1);
            check_annotation(&method.return_parameter.custom_attributes, tag + 2);
            assert_eq!(method.parameters[0].name, format!("{name}Arg"));
            assert_eq!(method.parameters[0].constant, Some(ConstantValue::I32(tag as i32)));
            assert_eq!(method.parameters[0].marshal_info, Some(marshal.clone()));
        }
        let generic = re.main.methods.iter().find(|m| m.name == "GenericFirst").unwrap();
        let MethodRef::Def(declaration) = generic.overrides[0].declaration else {
            panic!("lost override")
        };
        assert_eq!(re.main.method_def(declaration).name, "GenericSecond");
        for (name, tag) in [("TSecond", 40), ("TFirst", 50)] {
            let parameter = re.main.generic_parameters.iter().find(|p| p.name == name).unwrap();
            check_annotation(&parameter.custom_attributes, tag);
            check_annotation(&parameter.constraints[0].custom_attributes, tag + 1);
            let GenericOwner::Method(id) = parameter.owner else { panic!("lost generic owner") };
            assert_eq!(
                re.main.method_def(id).name,
                if name == "TFirst" { "GenericFirst" } else { "GenericSecond" }
            );
        }
        for property in &re.main.properties {
            let tag = if property.name == "FirstProperty" { 70 } else { 60 };
            check_annotation(&property.custom_attributes, tag);
            assert_eq!(property.constant, Some(ConstantValue::I32(tag as i32)));
            assert_eq!(re.main.method_def(property.get_method.unwrap()).name, "LateHelper");
        }
        for event in &re.main.events {
            check_annotation(
                &event.custom_attributes,
                if event.name == "FirstEvent" { 90 } else { 80 },
            );
            assert_eq!(re.main.method_def(event.add_on.unwrap()).name, "GenericFirst");
            assert_eq!(re.main.method_def(event.remove_on.unwrap()).name, "GenericSecond");
        }
        let instructions = &re.entry_point_method().unwrap().body.as_ref().unwrap().instructions;
        let ROperand::Field(FieldRef::Def(id)) = instructions[0].operand else {
            panic!("lost raw field")
        };
        assert_eq!(re.main.fields[id.index()].name, "LateField");
        let ROperand::Method(MethodRef::Def(id)) = instructions[2].operand else {
            panic!("lost raw method")
        };
        assert_eq!(re.main.method_def(id).name, "LateHelper");
        let ROperand::Method(MethodRef::Spec { method, .. }) = &instructions[5].operand else {
            panic!("lost MethodSpec")
        };
        let MethodRef::Def(id) = **method else { panic!("lost generic method") };
        assert_eq!(re.main.method_def(id).name, "GenericFirst");

        let image = cecil_pe::Image::parse(&bytes).unwrap();
        let (rva, size) = image.metadata_rva().unwrap();
        let metadata =
            cecil_metadata::MetadataReader::parse(image.rva_bytes(rva, size).unwrap()).unwrap();
        let entry = image.debug_entries.iter().find(|e| e.directory.kind == 17).unwrap();
        let pdb = cecil_pdb::embedded::unwrap_embedded(&entry.data).unwrap();
        let reader = cecil_pdb::portable_reader::PortablePdbReader::parse(&pdb).unwrap();
        for info in reader.custom_debug_informations().unwrap() {
            let table = info.parent.table();
            let rid = info.parent.rid();
            let name = match table {
                T::Property => re.main.properties[rid as usize - 1].name.clone(),
                T::Event => re.main.events[rid as usize - 1].name.clone(),
                T::GenericParam => re.main.generic_parameters[rid as usize - 1].name.clone(),
                T::Param => metadata
                    .heaps()
                    .strings
                    .get(metadata.column(T::Param, rid, 2).unwrap() as u32)
                    .unwrap()
                    .into(),
                T::GenericParamConstraint => {
                    let owner =
                        metadata.column(T::GenericParamConstraint, rid, 0).unwrap() as usize;
                    format!("{}Constraint", re.main.generic_parameters[owner - 1].name)
                }
                _ => panic!("unexpected debug parent"),
            };
            assert_eq!(name.as_bytes(), info.value);
        }
    }
}

#[test]
fn portable_outputs_use_emitted_counts_entry_point_and_local_signatures() {
    use cecil::assembly::{SymbolOutput, WriteParameters};
    use cecil::model::types::LocalVariable;
    use cecil::module_def::ModuleDebugInfo;
    use cecil::resolver::{ReaderParameters, ReadingMode};
    use cecil_core::{io::ByteReader, TableIndex as T, Token};
    use cecil_pdb::portable_reader::{PortablePdbReader, SequencePoint};

    let input = std::fs::read(cecil_core::fixtures_dir().join("hello.exe")).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "cecil_member_emission_{}_{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for mode in [ReadingMode::Immediate, ReadingMode::Lazy, ReadingMode::Deferred] {
        let mut asm = AssemblyDefinition::read_with(
            &input,
            &ReaderParameters { reading_mode: mode, ..Default::default() },
        )
        .unwrap();
        let original_main = asm.entry_point.unwrap();
        let owner = asm.main.method_def(original_main).declaring_type;
        let mut helper =
            method("LocalSigHelper", "void", vec![instruction(0, op::RET, ROperand::None)]);
        helper.body.as_mut().unwrap().locals.push(LocalVariable {
            index: 0,
            ty: TypeDesc::Internal("int32".into()),
            pinned: false,
        });
        helper.body.as_mut().unwrap().local_var_sig_tok = Token::new(T::StandAloneSig, 99);
        let helper = asm.main.add_method(owner, helper);
        asm.main.add_method(
            owner,
            method("WithoutPoints", "void", vec![instruction(0, op::RET, ROperand::None)]),
        );
        asm.entry_point = Some(helper);
        asm.main.debug = Some(ModuleDebugInfo {
            documents: vec![cecil_pdb::document::Document {
                name: "hello.cs".into(),
                hash_algorithm: [0; 16],
                hash: vec![],
                language: [0; 16],
            }],
            points: [(
                helper.0 + 1,
                vec![(
                    0,
                    vec![SequencePoint {
                        offset: 0,
                        start_line: 10,
                        end_line: 10,
                        start_column: 1,
                        end_column: 2,
                    }],
                )],
            )]
            .into_iter()
            .collect(),
            ..Default::default()
        });
        let before = asm.main.clone();
        for output in [SymbolOutput::PortablePdb, SymbolOutput::EmbeddedPortablePdb] {
            let path = dir.join(format!("{mode:?}-{output:?}.exe"));
            asm.write_file_with(
                &path,
                &WriteParameters {
                    symbol_output: Some(output),
                    deterministic_mvid: true,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(asm.main, before);
            let bytes = std::fs::read(&path).unwrap();
            let image = cecil_pe::Image::parse(&bytes).unwrap();
            let (rva, size) = image.metadata_rva().unwrap();
            let metadata =
                cecil_metadata::MetadataReader::parse(image.rva_bytes(rva, size).unwrap()).unwrap();
            let pdb = if output == SymbolOutput::PortablePdb {
                std::fs::read(path.with_extension("pdb")).unwrap()
            } else {
                let entry = image.debug_entries.iter().find(|e| e.directory.kind == 17).unwrap();
                cecil_pdb::embedded::unwrap_embedded(&entry.data).unwrap()
            };
            let reader = PortablePdbReader::parse(&pdb).unwrap();
            let pdb_counts = reader.metadata().heaps().pdb.as_ref().unwrap();
            for table in (0..T::PORTABLE_PDB_FIRST).filter_map(T::from_u8) {
                assert_eq!(pdb_counts.row_count(table), metadata.row_count(table), "{table:?}");
                assert!(!reader.metadata().tables().is_present(table));
            }
            assert_eq!(reader.entry_point(), image.entry_point_token());
            assert_eq!(
                reader.metadata().row_count(T::MethodDebugInformation),
                metadata.row_count(T::MethodDef)
            );
            assert!(reader.sequence_points(metadata.row_count(T::MethodDef)).unwrap().is_none());
            let re = AssemblyDefinition::read_file_with(
                &path,
                &ReaderParameters { read_symbols: true, ..Default::default() },
            )
            .unwrap();
            assert_eq!(re.entry_point_method().unwrap().name, "LocalSigHelper");
            assert!(re.main.methods.iter().all(|m| m.body.is_some()));
            let emitted_helper = re.entry_point.unwrap().0 + 1;
            let blob =
                reader.metadata().column(T::MethodDebugInformation, emitted_helper, 1).unwrap()
                    as u32;
            let mut sequence = ByteReader::new(reader.metadata().heaps().blob.get(blob).unwrap());
            assert_eq!(
                sequence.compressed_u32().unwrap(),
                re.entry_point_method().unwrap().body.as_ref().unwrap().local_var_sig_tok.rid()
            );
            assert_eq!(
                re.main.debug.as_ref().unwrap().points[&emitted_helper][0].1[0].start_line,
                10
            );
            let checksum = image.debug_entries.iter().find(|e| e.directory.kind == 19).unwrap();
            assert_eq!(&checksum.data[7..], &cecil_pdb::embedded::sha256(&pdb));
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}
