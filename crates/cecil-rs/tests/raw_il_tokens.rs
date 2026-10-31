//! Unresolved IL tokens stay opaque, while references to existing definitions
//! follow their emitted RIDs and typed handles retain their validation.

use cecil::model::types::{
    FieldDefinition, FieldId, FieldRef, FieldSignature, MethodDefinition, MethodId, MethodRef,
    MethodSignature, RInstruction, ROperand, ResolvedBody, TypeDefinition, TypeDesc,
};
use cecil::resolver::{MalformedInputPolicy, ReaderParameters, ReadingMode};
use cecil::write::token_map::TokenMap;
use cecil::AssemblyDefinition;
use cecil_cil::{opcode_table as op, OpCode};
use cecil_core::flags::{FieldAttributes, MethodAttributes, ModuleAttributes};
use cecil_core::{TableIndex as T, Token};
use cecil_metadata::{MetadataBuilder, MetadataReader};
use cecil_pe::Image;

fn assembly(opcode: OpCode) -> AssemblyDefinition {
    let mut asm = AssemblyDefinition::default();
    asm.main.attributes = ModuleAttributes::IL_ONLY;
    let owner = asm.main.add_type(TypeDefinition { name: "Tokens".into(), ..Default::default() });
    for name in ["FirstField", "SecondField"] {
        asm.main.add_field(
            owner,
            FieldDefinition {
                name: name.into(),
                attributes: FieldAttributes::PUBLIC | FieldAttributes::STATIC,
                signature: FieldSignature(TypeDesc::Internal("int32".into())),
                ..Default::default()
            },
        );
    }
    for name in ["Main", "Helper"] {
        let mut instructions = Vec::new();
        if name == "Main" {
            instructions.push(RInstruction {
                offset: 0,
                opcode,
                operand: ROperand::Token(Token::NIL),
            });
        }
        instructions.push(RInstruction { offset: 5, opcode: op::RET, operand: ROperand::None });
        let id = asm.main.add_method(
            owner,
            MethodDefinition {
                name: name.into(),
                attributes: MethodAttributes::PUBLIC | MethodAttributes::STATIC,
                signature: MethodSignature {
                    has_this: false,
                    return_type: TypeDesc::Internal("void".into()),
                    ..Default::default()
                },
                body: Some(ResolvedBody { instructions, ..Default::default() }),
                ..Default::default()
            },
        );
        if name == "Main" {
            asm.entry_point = Some(id);
        }
    }
    asm
}

fn token_image(opcode: OpCode, token: Token) -> Vec<u8> {
    // Patch a nil operand in a well-formed carrier, so the test can reach the
    // reader even when the writer cannot yet emit the hostile token.
    let mut bytes = assembly(opcode).write().unwrap();
    let image = Image::parse(&bytes).unwrap();
    let (rva, size) = image.metadata_rva().unwrap();
    let md = MetadataReader::parse(image.rva_bytes(rva, size).unwrap()).unwrap();
    let method_rva = md.column(T::MethodDef, 1, 0).unwrap();
    let body = image.rva_offset(method_rva).unwrap();
    let header = cecil_cil::method_body_header_len(&bytes[body..]).unwrap();
    let slot = body + header + opcode.size as usize;
    bytes[slot..slot + 4].copy_from_slice(&token.0.to_le_bytes());
    bytes
}

fn main_operand(asm: &AssemblyDefinition) -> &ROperand {
    &asm.entry_point_method().unwrap().body.as_ref().unwrap().instructions[0].operand
}

#[test]
fn unresolved_raw_tokens_roundtrip_in_all_reading_modes() {
    let mut tokens = vec![Token::NIL, Token(0xff12_3456)];
    for table in [
        T::Field,
        T::MethodDef,
        T::Param,
        T::Property,
        T::Event,
        T::GenericParam,
        T::GenericParamConstraint,
    ] {
        for rid in [0, 3, 0x00ff_ffff] {
            tokens.push(Token::new(table, rid));
        }
    }
    for table in [T::TypeDef, T::TypeRef, T::TypeSpec, T::MemberRef, T::MethodSpec] {
        tokens.push(Token::new(table, 0x00ff_ffff));
    }
    for token in tokens {
        for opcode in [op::LDFLD, op::CALL, op::BOX, op::LDTOKEN] {
            let input = token_image(opcode, token);
            for policy in [MalformedInputPolicy::Recover, MalformedInputPolicy::Strict] {
                for mode in [ReadingMode::Immediate, ReadingMode::Lazy, ReadingMode::Deferred] {
                    let asm = AssemblyDefinition::read_with(
                        &input,
                        &ReaderParameters {
                            malformed_input: policy,
                            reading_mode: mode,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                    assert!(asm.main.read_diagnostics.is_empty());
                    assert!(asm.main.native_image.is_none());
                    if mode == ReadingMode::Immediate {
                        assert_eq!(main_operand(&asm), &ROperand::Token(token));
                    }
                    let before = asm.main.clone();
                    let written = asm.write().unwrap_or_else(|error| {
                        panic!("{opcode:?} {token} ({policy:?}, {mode:?}): {error}")
                    });
                    assert_eq!(asm.main, before, "writing must not load or mutate caller bodies");
                    let re = AssemblyDefinition::read_with(
                        &written,
                        &ReaderParameters {
                            malformed_input: MalformedInputPolicy::Strict,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                    assert_eq!(main_operand(&re), &ROperand::Token(token));
                    assert_eq!(re.main.types.len(), asm.main.types.len());
                    assert_eq!(re.main.methods.len(), asm.main.methods.len());
                    assert_eq!(re.main.fields.len(), asm.main.fields.len());
                    assert_eq!(re.main.properties.len(), asm.main.properties.len());
                    assert_eq!(re.main.events.len(), asm.main.events.len());
                }
            }
        }
    }
}

#[test]
fn raw_tokens_for_existing_definitions_follow_reordered_members() {
    // A token of the wrong operand shape stays raw after reading. Its valid
    // definition RID still needs remapping when its owner's members move.
    for (opcode, token, expected) in [
        (op::CALL, Token::new(T::Field, 1), Token::new(T::Field, 2)),
        (op::LDFLD, Token::new(T::MethodDef, 2), Token::new(T::MethodDef, 1)),
    ] {
        let mut asm = AssemblyDefinition::read(&token_image(opcode, token)).unwrap();
        assert_eq!(main_operand(&asm), &ROperand::Token(token));
        asm.main.types[0].fields.reverse();
        asm.main.types[0].methods.reverse();
        let re = AssemblyDefinition::read(&asm.write().unwrap()).unwrap();
        assert_eq!(main_operand(&re), &ROperand::Token(expected));
        assert_eq!(re.main.fields[1].name, "FirstField");
        assert_eq!(re.main.methods[0].name, "Helper");
    }
}

#[test]
fn typed_handles_and_explicit_definition_tokens_still_reject_invalid_rids() {
    for (opcode, operand, table) in [
        (op::LDFLD, ROperand::Field(FieldRef::Def(FieldId(2))), T::Field),
        (op::CALL, ROperand::Method(MethodRef::Def(MethodId(2))), T::MethodDef),
    ] {
        let mut asm = assembly(opcode);
        asm.main.methods[0].body.as_mut().unwrap().instructions[0].operand = operand;
        assert!(asm.write().is_err(), "invalid typed {table:?} handle must not become a raw token");
        let mut metadata = MetadataBuilder::new("v4.0.30319");
        let mut map = TokenMap::new(&mut metadata);
        map.bind_definitions(&asm.main).unwrap();
        assert!(map.definition_token(Token::new(table, 3)).is_err());
    }
}
