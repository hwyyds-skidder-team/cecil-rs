use std::sync::Arc;

use cecil::model::types::*;
use cecil::AssemblyDefinition;
use cecil_core::flags::{FieldAttributes, MethodAttributes, TypeAttributes};
use cecil_core::{TableIndex as T, Token};
use cecil_metadata::MetadataReader;

fn save_verification_fixture(name: &str, bytes: &[u8]) {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/harden");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join(name), bytes).unwrap();
}

fn fixture() -> Vec<u8> {
    std::fs::read(cecil_core::fixtures_dir().join("MixedNativeCLI.exe")).unwrap()
}

fn metadata(image: &cecil_pe::Image) -> MetadataReader<'_> {
    let (rva, size) = image.metadata_rva().unwrap();
    MetadataReader::parse(image.rva_bytes(rva, size).unwrap()).unwrap()
}

fn assert_preserved(before: &[u8], after: &[u8]) {
    let old = cecil_pe::Image::parse(before).unwrap();
    let new = cecil_pe::Image::parse(after).unwrap();
    let cli = old.rva_offset(old.cli_directory.virtual_address as u64).unwrap();
    for (index, section) in old.sections.iter().enumerate() {
        let start = section.pointer_to_raw_data as usize;
        let end = start + section.size_of_raw_data as usize;
        let mut expected = before[start..end].to_vec();
        if (start..end).contains(&cli) {
            expected[cli - start + 8..cli - start + 16].copy_from_slice(&after[cli + 8..cli + 16]);
        }
        assert_eq!(&after[start..end], expected, "native section {}", section.name);
        let retained = &new.sections[index];
        assert_eq!(retained.virtual_address, section.virtual_address);
        assert_eq!(retained.pointer_to_raw_data, section.pointer_to_raw_data);
        assert_eq!(retained.size_of_raw_data, section.size_of_raw_data);
    }
    let old_md = metadata(&old);
    let new_md = metadata(&new);
    for table in [
        T::Module,
        T::TypeDef,
        T::Field,
        T::MethodDef,
        T::Param,
        T::TypeRef,
        T::AssemblyRef,
        T::ModuleRef,
        T::MemberRef,
        T::TypeSpec,
        T::MethodSpec,
        T::StandAloneSig,
    ] {
        assert!(new_md.row_count(table) >= old_md.row_count(table));
        for rid in 1..=old_md.row_count(table) {
            let mut expected = old_md.row(table, rid).unwrap();
            let actual = new_md.row(table, rid).unwrap();
            // Managed methods can move to their new bodies; tokens stay fixed.
            if table == T::MethodDef {
                expected[0] = actual[0];
            }
            assert_eq!(actual, expected, "{table:?} token {rid}");
        }
    }
    assert!(new_md.heaps().strings.data().starts_with(old_md.heaps().strings.data()));
    assert!(new_md.heaps().blob.data().starts_with(old_md.heaps().blob.data()));
    let old_assembly = AssemblyDefinition::read(before).unwrap();
    let new_assembly = AssemblyDefinition::read(after).unwrap();
    assert_eq!(new_assembly.main.native_method_rvas, old_assembly.main.native_method_rvas);
    assert_eq!(new_assembly.write().unwrap(), after);
}

fn simple_method(assembly: &AssemblyDefinition) -> usize {
    assembly
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
        .unwrap()
}

fn prepend(body: &mut ResolvedBody, instructions: Vec<(cecil_cil::OpCode, ROperand)>) {
    let added: Vec<_> = instructions
        .into_iter()
        .map(|(opcode, operand)| RInstruction { offset: 0, opcode, operand })
        .collect();
    body.instructions.splice(..0, added);
    cecil::edit::renumber(body);
}

#[test]
fn new_imported_call_and_module_scope_append_without_retargeting_native_tokens() {
    let original = fixture();
    let mut assembly = AssemblyDefinition::read(&original).unwrap();
    let index = simple_method(&assembly);
    let system = Arc::new(AssemblyNameReference::new("System"));
    assembly.main.assembly_refs.push((*system).clone());
    assembly.main.module_refs.push("Auxiliary.netmodule".into());
    let parent = TypeDesc::External(Arc::new(ExternalType {
        namespace: "System.Diagnostics".into(),
        name: "Debug".into(),
        nesting: Vec::new(),
        scope: ScopeRef::Assembly(system),
    }));
    let call = MethodRef::External(Arc::new(ExternalMethod {
        parent,
        name: "WriteLine".into(),
        signature: MethodSignature {
            has_this: false,
            parameters: vec![TypeDesc::Internal("string".into())],
            vararg_start: 1,
            ..Default::default()
        },
    }));
    prepend(
        assembly.main.methods[index].body.as_mut().unwrap(),
        vec![
            (cecil_cil::opcodes::LDSTR, ROperand::String("instrumented IL".into())),
            (cecil_cil::opcodes::CALL, ROperand::Method(call.clone())),
        ],
    );
    let output = assembly.write().unwrap();
    assert_preserved(&original, &output);
    let reread = AssemblyDefinition::read(&output).unwrap();
    assert_eq!(
        reread.main.methods[index].body.as_ref().unwrap().instructions[1].operand,
        ROperand::Method(call)
    );
    assert!(reread.main.module_refs.iter().any(|name| name == "Auxiliary.netmodule"));
    save_verification_fixture("mixed-new-import.exe", &output);
}

#[test]
fn new_locals_type_spec_and_calli_signatures_are_retained_with_native_payload() {
    let original = fixture();
    let mut assembly = AssemblyDefinition::read(&original).unwrap();
    let index = simple_method(&assembly);
    let signature = MethodSignature { has_this: false, ..Default::default() };
    let body = assembly.main.methods[index].body.as_mut().unwrap();
    let slot = body.locals.len() as u16;
    body.locals.push(LocalVariable {
        index: slot,
        ty: TypeDesc::SzArray(Arc::new(TypeDesc::Internal("int32".into()))),
        pinned: false,
    });
    body.init_locals = true;
    let array = TypeDesc::SzArray(Arc::new(TypeDesc::Internal("int32".into())));
    prepend(
        body,
        vec![
            (cecil_cil::opcodes::LDNULL, ROperand::None),
            (cecil_cil::opcodes::STLOC, ROperand::Var(slot)),
            (cecil_cil::opcodes::LDTOKEN, ROperand::Type(array.clone())),
            (cecil_cil::opcodes::POP, ROperand::None),
            (cecil_cil::opcodes::LDC_I4_0, ROperand::None),
            (cecil_cil::opcodes::CONV_I, ROperand::None),
            (cecil_cil::opcodes::CALLI, ROperand::CallSite(Box::new(signature.clone()))),
        ],
    );
    let output = assembly.write().unwrap();
    assert_preserved(&original, &output);
    let reread = AssemblyDefinition::read(&output).unwrap();
    let written = reread.main.methods[index].body.as_ref().unwrap();
    assert_eq!(written.locals.last().unwrap().ty, array);
    assert_eq!(written.instructions[6].operand, ROperand::CallSite(Box::new(signature)));
    save_verification_fixture("mixed-new-signatures.exe", &output);
}

#[test]
fn appended_helpers_keep_old_definition_tokens_and_own_contiguous_new_members() {
    let original = fixture();
    let mut assembly = AssemblyDefinition::read(&original).unwrap();
    let helper = assembly.main.add_type(TypeDefinition {
        namespace: "Instrumentation".into(),
        name: "Helper".into(),
        attributes: TypeAttributes::PUBLIC,
        ..Default::default()
    });
    let field = assembly.main.add_field(
        helper,
        FieldDefinition {
            name: "Calls".into(),
            attributes: FieldAttributes::PUBLIC | FieldAttributes::STATIC,
            signature: FieldSignature(TypeDesc::Internal("int32".into())),
            ..Default::default()
        },
    );
    let helper_method = assembly.main.add_method(
        helper,
        MethodDefinition {
            name: "Observe".into(),
            attributes: MethodAttributes::PUBLIC | MethodAttributes::STATIC,
            signature: MethodSignature {
                has_this: false,
                parameters: vec![TypeDesc::Internal("int32".into())],
                return_type: TypeDesc::Internal("int32".into()),
                vararg_start: 1,
                ..Default::default()
            },
            parameters: vec![Parameter { name: "value".into(), sequence: 1, ..Default::default() }],
            body: Some(ResolvedBody {
                instructions: vec![
                    RInstruction {
                        offset: 0,
                        opcode: cecil_cil::opcodes::LDARG_0,
                        operand: ROperand::None,
                    },
                    RInstruction {
                        offset: 1,
                        opcode: cecil_cil::opcodes::RET,
                        operand: ROperand::None,
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let index = simple_method(&assembly);
    prepend(
        assembly.main.methods[index].body.as_mut().unwrap(),
        vec![
            (cecil_cil::opcodes::LDC_I4_0, ROperand::None),
            (cecil_cil::opcodes::CALL, ROperand::Method(MethodRef::Def(helper_method))),
            (cecil_cil::opcodes::STSFLD, ROperand::Field(FieldRef::Def(field))),
        ],
    );
    let output = assembly.write().unwrap();
    assert_preserved(&original, &output);
    let reread = AssemblyDefinition::read(&output).unwrap();
    assert_eq!(reread.main.types[helper.index()].methods, vec![helper_method]);
    assert_eq!(reread.main.types[helper.index()].fields, vec![field]);
    assert_eq!(reread.main.methods[helper_method.index()].parameters[0].name, "value");
    assert_eq!(
        Token::new(T::MethodDef, helper_method.0 + 1).rid() as usize,
        reread.main.methods.len()
    );
    save_verification_fixture("mixed-new-helper.exe", &output);
}

#[test]
fn appending_helpers_and_renaming_an_old_parameter_uses_only_original_param_lists() {
    let mut assembly = AssemblyDefinition::read(&fixture()).unwrap();
    let method = assembly
        .main
        .methods
        .iter_mut()
        .find(|method| method.parameters.iter().any(|parameter| !parameter.name.is_empty()))
        .unwrap();
    let parameter = method.parameters.iter_mut().find(|p| !p.name.is_empty()).unwrap();
    parameter.name = "renamed_original_parameter".into();
    let helper =
        assembly.main.add_type(TypeDefinition { name: "Helper".into(), ..Default::default() });
    assembly.main.add_method(
        helper,
        MethodDefinition {
            name: "Run".into(),
            attributes: MethodAttributes::STATIC,
            signature: MethodSignature { has_this: false, ..Default::default() },
            body: Some(ResolvedBody {
                instructions: vec![RInstruction {
                    offset: 0,
                    opcode: cecil_cil::opcodes::RET,
                    operand: ROperand::None,
                }],
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let output = assembly.write().unwrap();
    let reread = AssemblyDefinition::read(&output).unwrap();
    assert!(reread
        .main
        .methods
        .iter()
        .flat_map(|m| &m.parameters)
        .any(|p| p.name == "renamed_original_parameter"));
}

#[test]
fn generic_member_instantiation_and_new_catch_type_append_reference_rows() {
    let original = fixture();
    let mut assembly = AssemblyDefinition::read(&original).unwrap();
    let index = simple_method(&assembly);
    let reference = Arc::new(AssemblyNameReference::new("Instrumentation.Runtime"));
    let parent = TypeDesc::External(Arc::new(ExternalType {
        namespace: "Instrumentation".into(),
        name: "Probe".into(),
        nesting: Vec::new(),
        scope: ScopeRef::Assembly(reference.clone()),
    }));
    let method = MethodRef::Spec {
        method: Arc::new(MethodRef::External(Arc::new(ExternalMethod {
            parent,
            name: "Observe".into(),
            signature: MethodSignature {
                has_this: false,
                generic_count: 1,
                parameters: vec![TypeDesc::MVar(0)],
                vararg_start: 1,
                ..Default::default()
            },
        }))),
        arguments: vec![TypeDesc::Internal("int32".into())].into(),
    };
    let exception = TypeDesc::External(Arc::new(ExternalType {
        namespace: "Instrumentation".into(),
        name: "ProbeException".into(),
        nesting: Vec::new(),
        scope: ScopeRef::Assembly(reference),
    }));
    let body = assembly.main.methods[index].body.as_mut().unwrap();
    body.instructions = vec![
        RInstruction { offset: 0, opcode: cecil_cil::opcodes::LDC_I4_0, operand: ROperand::None },
        RInstruction {
            offset: 1,
            opcode: cecil_cil::opcodes::CALL,
            operand: ROperand::Method(method.clone()),
        },
        RInstruction {
            offset: 6,
            opcode: cecil_cil::opcodes::LEAVE_S,
            operand: ROperand::Branch(11),
        },
        RInstruction { offset: 8, opcode: cecil_cil::opcodes::POP, operand: ROperand::None },
        RInstruction {
            offset: 9,
            opcode: cecil_cil::opcodes::LEAVE_S,
            operand: ROperand::Branch(11),
        },
        RInstruction { offset: 11, opcode: cecil_cil::opcodes::RET, operand: ROperand::None },
    ];
    body.exception_handlers = vec![ExceptionHandlerIL {
        kind: ExceptionKind::Catch,
        try_offset: 0,
        try_length: 8,
        handler_offset: 8,
        handler_length: 3,
        filter_offset: 0,
        catch_type: Some(exception.clone()),
    }];
    body.max_stack = 1;
    let output = assembly.write().unwrap();
    assert_preserved(&original, &output);
    let reread = AssemblyDefinition::read(&output).unwrap();
    let body = reread.main.methods[index].body.as_ref().unwrap();
    assert_eq!(body.instructions[1].operand, ROperand::Method(method));
    assert_eq!(body.exception_handlers[0].catch_type, Some(exception));
    save_verification_fixture("mixed-new-generics-catch.exe", &output);
}

#[test]
fn helpers_reject_dangling_ownership_and_individually_abstract_or_pinvoke_methods() {
    let mut assembly = AssemblyDefinition::read(&fixture()).unwrap();
    let helper =
        assembly.main.add_type(TypeDefinition { name: "Helper".into(), ..Default::default() });
    let method = assembly.main.add_method(
        helper,
        MethodDefinition {
            name: "Run".into(),
            attributes: MethodAttributes::STATIC,
            signature: MethodSignature { has_this: false, ..Default::default() },
            body: Some(ResolvedBody {
                instructions: vec![RInstruction {
                    offset: 0,
                    opcode: cecil_cil::opcodes::RET,
                    operand: ROperand::None,
                }],
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    for flags in [MethodAttributes::ABSTRACT, MethodAttributes::PINVOKE_IMPL] {
        let mut invalid = assembly.clone();
        invalid.main.methods[method.index()].attributes |= flags;
        assert!(invalid.write().is_err());
    }
    assembly.main.methods[method.index()].declaring_type = TypeId(u32::MAX);
    assert!(matches!(assembly.write(), Err(cecil_core::Error::Argument(_))));
}

#[test]
fn edited_raw_tokens_must_match_opcode_table_and_member_signature_kind() {
    let original = fixture();
    let image = cecil_pe::Image::parse(&original).unwrap();
    let md = metadata(&image);
    let method_member = (1..=md.row_count(T::MemberRef))
        .find(|&rid| {
            let blob = md.column(T::MemberRef, rid, 2).unwrap() as u32;
            md.heaps().blob.get(blob).unwrap().first() != Some(&6)
        })
        .unwrap();
    let field_member = (1..=md.row_count(T::MemberRef))
        .find(|&rid| {
            let blob = md.column(T::MemberRef, rid, 2).unwrap() as u32;
            md.heaps().blob.get(blob).unwrap().first() == Some(&6)
        })
        .unwrap();
    for (opcode, token) in [
        (cecil_cil::opcodes::CALL, Token::new(T::TypeDef, 1)),
        (cecil_cil::opcodes::BOX, Token::new(T::MethodDef, 1)),
        (cecil_cil::opcodes::CALL, Token::new(T::MemberRef, field_member)),
        (cecil_cil::opcodes::LDSFLD, Token::new(T::MemberRef, method_member)),
        (cecil_cil::opcodes::LDTOKEN, Token::new(T::StandAloneSig, 1)),
        (cecil_cil::opcodes::CALLI, Token::new(T::StandAloneSig, 1)),
    ] {
        let mut assembly = AssemblyDefinition::read(&original).unwrap();
        let index = simple_method(&assembly);
        prepend(
            assembly.main.methods[index].body.as_mut().unwrap(),
            vec![(opcode, ROperand::Token(token))],
        );
        assert!(
            matches!(assembly.write(), Err(cecil_core::Error::Argument(_))),
            "reject {opcode:?} {token:?}"
        );
    }
    for token in [
        Token::new(T::TypeDef, 1),
        Token::new(T::MethodDef, 1),
        Token::new(T::Field, 1),
        Token::new(T::MemberRef, method_member),
        Token::new(T::MemberRef, field_member),
    ] {
        let mut assembly = AssemblyDefinition::read(&original).unwrap();
        let index = simple_method(&assembly);
        prepend(
            assembly.main.methods[index].body.as_mut().unwrap(),
            vec![
                (cecil_cil::opcodes::LDTOKEN, ROperand::Token(token)),
                (cecil_cil::opcodes::POP, ROperand::None),
            ],
        );
        assert!(assembly.write().is_ok(), "accept InlineTok {token:?}");
    }
}

#[test]
fn unchanged_abstract_and_pinvoke_body_absence_survives_other_il_edits() {
    let mut source = AssemblyDefinition::default();
    source.name.name = "NativeBodyAbsence".into();
    source.main.module_refs.push("NativeLibrary.dll".into());
    let owner = source.main.add_type(TypeDefinition {
        name: "Holder".into(),
        attributes: TypeAttributes::ABSTRACT,
        ..Default::default()
    });
    source.main.add_method(
        owner,
        MethodDefinition {
            name: "Abstract".into(),
            attributes: MethodAttributes::ABSTRACT | MethodAttributes::VIRTUAL,
            ..Default::default()
        },
    );
    source.main.add_method(
        owner,
        MethodDefinition {
            name: "External".into(),
            attributes: MethodAttributes::PINVOKE_IMPL | MethodAttributes::STATIC,
            signature: MethodSignature { has_this: false, ..Default::default() },
            pinvoke: Some(PInvokeInfo {
                attributes: cecil_core::flags::PInvokeAttributes::empty(),
                entry_point: "External".into(),
                module: "NativeLibrary.dll".into(),
            }),
            ..Default::default()
        },
    );
    let run = source.main.add_method(
        owner,
        MethodDefinition {
            name: "Run".into(),
            attributes: MethodAttributes::STATIC,
            signature: MethodSignature { has_this: false, ..Default::default() },
            body: Some(ResolvedBody {
                instructions: vec![RInstruction {
                    offset: 0,
                    opcode: cecil_cil::opcodes::RET,
                    operand: ROperand::None,
                }],
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    let mut original = source.write().unwrap();
    let image = cecil_pe::Image::parse(&original).unwrap();
    let cli = image.rva_offset(image.cli_directory.virtual_address as u64).unwrap();
    original[cli + 16..cli + 20].copy_from_slice(&(image.cli_header.flags & !1).to_le_bytes());
    let mut assembly = AssemblyDefinition::read(&original).unwrap();
    assert_eq!(assembly.write().unwrap(), original);
    prepend(
        assembly.main.methods[run.index()].body.as_mut().unwrap(),
        vec![(cecil_cil::opcodes::NOP, ROperand::None)],
    );
    let output = assembly.write().unwrap();
    let reread = AssemblyDefinition::read(&output).unwrap();
    for name in ["Abstract", "External"] {
        assert!(reread.main.methods.iter().find(|m| m.name == name).unwrap().body.is_none());
    }
}
