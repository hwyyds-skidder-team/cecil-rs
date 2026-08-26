//! IL method-body emission (`Mono.Cecil.Cil/CodeWriter.cs`
//! `WriteResolvedMethodBody` + header selection rules).
//!
//! [`encode_body`] serializes one [`ResolvedBody`] into an IL code stream:
//! tiny or fat header (ECMA-335 II §25.4.2), the instruction stream with
//! branch fixups, and the trailing exception-handling sections (§25.4.6).
//! Metadata operands (types, methods, fields, strings, local signatures)
//! are registered through the caller's [`TokenMap`]; raw tokens pass through.
//!
//! Like Cecil, instruction offsets are recomputed sequentially before
//! encoding (two passes: layout, then emission), so stale input offsets are
//! normalized rather than trusted.

use cecli_core::io::ByteWriter;
use cecli_core::{Error, Result, Token};
use cecli_cil::{ExceptionHandlerType, OpCode, OperandType};

use crate::model::types::{
    ExceptionHandlerIL, ExceptionKind, ResolvedBody, RInstruction, ROperand,
};
use crate::module_def::Module;
use crate::write::token_map::TokenMap;

const TINY_FORMAT: u8 = 0x02;
const FAT_FORMAT: u8 = 0x03;
const MORE_SECTS_FLAG: u8 = 0x08;
const INIT_LOCALS_FLAG: u8 = 0x10;
/// Fat-header size field: 12 bytes = 3 dwords, shifted into bits 4..8
/// (`CodeWriter.WriteFatHeader` writes the literal `0x30`).
const FAT_HEADER_SIZE_BYTE: u8 = 0x30;
/// High byte of an `ldstr` metadata token (`TokenType.String`).
const STRING_TOKEN_TYPE: u32 = 0x70 << 24;

/// Encodes one resolved method body into `out`.
///
/// Writes the header, the instruction stream and (when present) the exception
/// handling sections at the writer's current position and returns the total
/// number of bytes written. Bodies without instructions and without locals
/// yield `Ok(0)` and leave `out` untouched (Cecil's `IsEmptyMethodBody` rule);
/// the caller then omits the method from the `MethodDef.RVA` column.
///
/// Fat bodies are padded so their header starts 4-aligned relative to the
/// start of this body, mirroring `CodeWriter.WriteResolvedMethodBody`; place
/// the body at a 4-aligned RVA for a spec-conformant image.
pub fn encode_body(
    body: &ResolvedBody,
    tmap: &mut TokenMap<'_>,
    m: &Module,
    out: &mut ByteWriter,
) -> Result<u64> {
    if body.instructions.is_empty() && body.locals.is_empty() {
        return Ok(0);
    }

    let start = out.position();

    // Pass 1: sequential offsets and total code size (`ComputeHeader`,
    // minus stack analysis: `max_stack` is carried by the model).
    let offsets = compute_offsets(&body.instructions)?;
    let code_size = code_stream_size(&body.instructions, &offsets);

    let has_eh = !body.exception_handlers.is_empty();
    if requires_fat_header(code_size, body, has_eh) {
        align_from(out, start);
        write_fat_header(out, body, tmap, m, code_size as u32, has_eh)?;
    } else {
        // Tiny form: six-bit code size, enforced by the fat-selection rule.
        out.u8(TINY_FORMAT | ((code_size as u8) << 2));
    }

    // Pass 2: emit instructions; all branch displacements derive from the
    // layout fixed above, so no back-patching is required.
    for (instr, &offset) in body.instructions.iter().zip(&offsets) {
        write_opcode(out, instr.opcode);
        write_operand(out, instr, offset, tmap, m)?;
    }

    if has_eh {
        align_from(out, start);
        write_exception_handlers(out, body, tmap, m)?;
    }

    Ok((out.position() - start) as u64)
}

/// Cecil's `RequiresFatHeader`: the fat form is used whenever the code does
/// not fit the tiny envelope or any explicit state exists.
fn requires_fat_header(code_size: usize, body: &ResolvedBody, has_eh: bool) -> bool {
    code_size >= 64
        || body.init_locals
        || !body.locals.is_empty()
        || has_eh
        || body.max_stack > 8
}

/// Recomputes sequential instruction offsets (`CodeWriter.ComputeHeader`).
fn compute_offsets(instructions: &[RInstruction]) -> Result<Vec<i32>> {
    let mut offsets = Vec::with_capacity(instructions.len());
    let mut offset = 0usize;
    for instr in instructions {
        offsets.push(
            i32::try_from(offset).map_err(|_| Error::invalid_op("method body exceeds 2 GiB"))?,
        );
        offset += rinstr_size(instr)?;
    }
    Ok(offsets)
}

fn code_stream_size(instructions: &[RInstruction], offsets: &[i32]) -> usize {
    match instructions.split_last() {
        None => 0,
        Some((last, rest)) => offsets[rest.len()] as usize + rinstr_size(last).unwrap_or(0),
    }
}

/// Encoded length of one resolved instruction, including the variable-length
/// switch-target table.
fn rinstr_size(instr: &RInstruction) -> Result<usize> {
    let fixed = match instr.opcode.operand_type.size() {
        Some(n) => n,
        // Switch: count dword plus one displacement per target.
        None => 4 * (switch_targets(&instr.operand)?.len() + 1),
    };
    Ok(instr.opcode.size as usize + fixed)
}

fn switch_targets(operand: &ROperand) -> Result<&Vec<i32>> {
    match operand {
        ROperand::Switch(targets) => Ok(targets),
        other => Err(Error::invalid_op(format!(
            "switch operand expected, found {other:?}"
        ))),
    }
}

/// Writes the opcode bytes (`byte2` alone for single-byte encodings).
fn write_opcode(out: &mut ByteWriter, opcode: OpCode) {
    if opcode.is_single_byte() {
        out.u8(opcode.byte2);
    } else {
        out.u8(opcode.byte1);
        out.u8(opcode.byte2);
    }
}

/// Writes the fat method header (`CodeWriter.WriteFatHeader`).
fn write_fat_header(
    out: &mut ByteWriter,
    body: &ResolvedBody,
    tmap: &mut TokenMap<'_>,
    m: &Module,
    code_size: u32,
    has_eh: bool,
) -> Result<()> {
    let mut flags = FAT_FORMAT;
    if body.init_locals {
        flags |= INIT_LOCALS_FLAG;
    }
    if has_eh {
        flags |= MORE_SECTS_FLAG;
    }
    out.u8(flags);
    out.u8(FAT_HEADER_SIZE_BYTE);
    out.u16(body.max_stack);
    out.u32(code_size);
    let locals_token = if body.locals.is_empty() {
        Token::NIL
    } else {
        tmap.local_var_sig_token(&body.locals, m)?
    };
    out.u32(locals_token.0);
    Ok(())
}

/// Encodes a single operand (`CodeWriter.WriteOperand`).
fn write_operand(
    out: &mut ByteWriter,
    instr: &RInstruction,
    offset: i32,
    tmap: &mut TokenMap<'_>,
    m: &Module,
) -> Result<()> {
    let opcode_size = instr.opcode.size as i32;
    // Fast path: no operand to encode.
    if instr.opcode.operand_type == OperandType::InlineNone {
        debug_assert!(matches!(instr.operand, ROperand::None));
        return Ok(());
    }
    match (&instr.operand, instr.opcode.operand_type) {
        // Raw pointer loads carry an RVA truncated to the 32-bit token slot.
        (ROperand::Rva(v), _) => {
            let v = u32::try_from(*v)
                .map_err(|_| Error::invalid_op("rva operand does not fit 32 bits"))?;
            out.u32(v);
        }
        (ROperand::Switch(targets), OperandType::InlineSwitch) => {
            out.u32(targets.len() as u32);
            // Displacements are relative to the address just past the whole
            // switch instruction (count dword included).
            let diff = offset + opcode_size + 4 * (targets.len() as i32 + 1);
            for &target in targets {
                out.i32(target - diff);
            }
        }
        (ROperand::Branch(target), OperandType::ShortInlineBrTarget) => {
            let rel = *target - (offset + opcode_size + 1);
            let rel =
                i8::try_from(rel).map_err(|_| Error::invalid_op("short branch out of range"))?;
            out.i8(rel);
        }
        (ROperand::Branch(target), OperandType::InlineBrTarget) => {
            out.i32(*target - (offset + opcode_size + 4));
        }
        (ROperand::Var(index), OperandType::ShortInlineVar | OperandType::ShortInlineArg) => {
            let index = u8::try_from(*index)
                .map_err(|_| Error::invalid_op("local index does not fit a short inline var"))?;
            out.u8(index);
        }
        (ROperand::Var(index), OperandType::InlineVar | OperandType::InlineArg) => {
            out.u16(*index);
        }
        (ROperand::Int8(v), OperandType::ShortInlineI) => out.i8(*v),
        (ROperand::Int32(v), OperandType::InlineI) => out.i32(*v),
        (ROperand::Int64(v), OperandType::InlineI8) => out.i64(*v),
        (ROperand::Float32(v), OperandType::ShortInlineR) => out.f32(*v),
        (ROperand::Float64(v), OperandType::InlineR) => out.f64(*v),
        (ROperand::String(s), OperandType::InlineString) => {
            let index = tmap.user_string(s);
            out.u32(STRING_TOKEN_TYPE | index);
        }
        (ROperand::UserString(index), OperandType::InlineString) => {
            out.u32(STRING_TOKEN_TYPE | index);
        }
        // Metadata-bearing opcodes resolve through the token map; raw tokens
        // (kept when resolution was impossible) pass through unchanged.
        (ROperand::Type(ty), OperandType::InlineType | OperandType::InlineTok) => {
            out.u32(tmap.type_token(ty, m)?.0);
        }
        (
            ROperand::Method(method),
            OperandType::InlineMethod | OperandType::InlineSig | OperandType::InlineTok,
        ) => {
            out.u32(tmap.method_ref(method, m)?.0);
        }
        (ROperand::Field(field), OperandType::InlineField | OperandType::InlineTok) => {
            out.u32(tmap.field_ref(field, m)?.0);
        }
        (
            ROperand::Token(token),
            OperandType::InlineTok
            | OperandType::InlineType
            | OperandType::InlineMethod
            | OperandType::InlineField
            | OperandType::InlineSig,
        ) => {
            out.u32(token.0);
        }
        (operand, operand_type) => {
            return Err(Error::invalid_op(format!(
                "operand {operand:?} does not match operand kind {operand_type:?}"
            )));
        }
    }
    Ok(())
}

/// Sorts the clauses deterministically (by try offset, then handler offset)
/// and emits them as a single small/fat section (`WriteExceptionHandlers`).
fn write_exception_handlers(
    out: &mut ByteWriter,
    body: &ResolvedBody,
    tmap: &mut TokenMap<'_>,
    m: &Module,
) -> Result<()> {
    let mut order: Vec<usize> = (0..body.exception_handlers.len()).collect();
    order.sort_by_key(|&i| {
        let h = &body.exception_handlers[i];
        (h.try_offset, h.handler_offset)
    });

    let mut clauses = Vec::with_capacity(order.len());
    for &i in &order {
        clauses.push(to_cil_clause(&body.exception_handlers[i], tmap, m)?);
    }

    let section = cecli_cil::write_section(&clauses, false)?;
    out.bytes(&section);
    Ok(())
}

/// Converts a model clause into the table-driven `cecli-cil` form, resolving
/// catch types through the token map.
fn to_cil_clause(
    handler: &ExceptionHandlerIL,
    tmap: &mut TokenMap<'_>,
    m: &Module,
) -> Result<cecli_cil::ExceptionHandler> {
    let handler_type = match handler.kind {
        ExceptionKind::Catch => ExceptionHandlerType::Catch,
        ExceptionKind::Filter => ExceptionHandlerType::Filter,
        ExceptionKind::Finally => ExceptionHandlerType::Finally,
        ExceptionKind::Fault => ExceptionHandlerType::Fault,
    };
    let mut clause = cecli_cil::ExceptionHandler::new(handler_type);
    clause.try_start = handler.try_offset;
    clause.try_length = handler.try_length;
    clause.handler_start = handler.handler_offset;
    clause.handler_length = handler.handler_length;
    if handler.kind == ExceptionKind::Filter {
        clause.filter_start = Some(handler.filter_offset);
    }
    if handler.kind == ExceptionKind::Catch {
        let ty = handler
            .catch_type
            .as_ref()
            .ok_or_else(|| Error::invalid_op("catch clause without a catch type"))?;
        clause.catch_type = tmap.type_token(ty, m)?;
    }
    Ok(clause)
}

/// Pads zeros until `position - start` is 4-aligned.
fn align_from(out: &mut ByteWriter, start: usize) {
    while (out.position() - start) % 4 != 0 {
        out.u8(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{
        ExternalMethod, ExternalType, LocalVariable, MethodRef, MethodSignature, ScopeRef, TypeDesc,
    };
    use cecli_cil::{parse_body_header, Instruction, Operand, ParsedHeader};

    use cecli_cil::opcodes::*;
    use cecli_metadata::MetadataBuilder;

    fn ext_type(ns: &str, name: &str) -> TypeDesc {
        TypeDesc::External(Box::new(ExternalType {
            namespace: ns.to_string(),
            name: name.to_string(),
            nesting: Vec::new(),
            scope: ScopeRef::Moduleless,
        }))
    }

    fn external_call(name: &str) -> MethodRef {
        MethodRef::External(ExternalMethod {
            parent: ext_type("System", "Object"),
            name: name.to_string(),
            signature: MethodSignature::default(),
        })
    }

    fn instr(offset: i32, opcode: OpCode, operand: ROperand) -> RInstruction {
        RInstruction {
            offset,
            opcode,
            operand,
        }
    }

    fn int32_local() -> LocalVariable {
        LocalVariable {
            index: 0,
            ty: TypeDesc::Internal("int32".into()),
            pinned: false,
        }
    }

    /// Decodes header + code via the `cecli-cil` helpers.
    fn decode(bytes: &[u8]) -> (ParsedHeader, Vec<Instruction>) {
        let header = parse_body_header(bytes).expect("header parses");
        let code_start = if header.fat { 12 } else { 1 };
        let code = cecli_cil::read_code(
            &bytes[code_start..code_start + header.code_size as usize],
            header.code_size as usize,
        )
        .expect("code decodes");
        (header, code)
    }

    /// Parses the exception section starting after alignment padding.
    fn decode_sections(data: &[u8]) -> (usize, Vec<cecli_cil::ExceptionHandler>) {
        let mut pos = 0;
        while data.get(pos) == Some(&0) {
            pos += 1;
        }
        let clauses = cecli_cil::parse_sections(&data[pos..])
            .expect("sections parse")
            .0;
        (pos, clauses)
    }

    #[test]
    fn tiny_body_roundtrip() {
        let body = ResolvedBody {
            instructions: vec![
                instr(0, NOP, ROperand::None),
                instr(1, BR_S, ROperand::Branch(3)),
                instr(3, RET, ROperand::None),
            ],
            ..Default::default()
        };

        let mut builder = MetadataBuilder::new("v4.0.30319");
        let mut tmap = TokenMap::new(&mut builder);
        let m = Module::default();

        let mut out = ByteWriter::new();
        let written = encode_body(&body, &mut tmap, &m, &mut out).expect("encode");
        let bytes = out.into_vec();

        assert_eq!(written as usize, bytes.len());
        assert_eq!(bytes.len(), 5); // 1 header byte + 4 code bytes
        assert_eq!(bytes[0], 0x2 | (4 << 2)); // tiny header
        assert_eq!(&bytes[1..], &[0x00, 0x2B, 0x00, 0x2A]);

        let (header, code) = decode(&bytes);
        assert!(!header.fat);
        assert_eq!(header.code_size, 4);
        assert_eq!(code.len(), 3);
        assert_eq!(code[0].opcode, NOP);
        assert_eq!(code[1].operand, Operand::Branch(3));
        assert_eq!(code[2].opcode, RET);
    }

    #[test]
    fn tiny_backward_branch_fixup() {
        let body = ResolvedBody {
            instructions: vec![
                instr(0, NOP, ROperand::None),
                instr(1, BR_S, ROperand::Branch(0)),
                instr(3, RET, ROperand::None),
            ],
            ..Default::default()
        };

        let mut builder = MetadataBuilder::new("v4.0.30319");
        let mut tmap = TokenMap::new(&mut builder);
        let m = Module::default();

        let mut out = ByteWriter::new();
        encode_body(&body, &mut tmap, &m, &mut out).expect("encode");
        let bytes = out.into_vec();

        assert_eq!(&bytes[1..], &[0x00, 0x2B, 0xFD, 0x2A]); // -3 displacement
        let (_, code) = decode(&bytes);
        assert_eq!(code[1].operand, Operand::Branch(0));
    }

    #[test]
    fn empty_body_writes_nothing() {
        let body = ResolvedBody::default();

        let mut builder = MetadataBuilder::new("v4.0.30319");
        let mut tmap = TokenMap::new(&mut builder);
        let m = Module::default();

        let mut out = ByteWriter::new();
        let written = encode_body(&body, &mut tmap, &m, &mut out).expect("encode");
        assert_eq!(written, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn fat_body_full_roundtrip() {
        // maxstack 16 + int32 local + finally handler + ldc.i4.s +
        // switch with 3 targets + call token => fat header forced.
        let call = external_call("ToString");
        let body = ResolvedBody {
            max_stack: 16,
            init_locals: true,
            locals: vec![int32_local()],
            instructions: vec![
                instr(0, LDC_I4_S, ROperand::Int8(42)),         // 2 bytes
                instr(2, STLOC_S, ROperand::Var(0)),            // 2
                instr(4, LDLOC_S, ROperand::Var(0)),            // 2
                instr(6, CALL, ROperand::Method(call.clone())), // 5
                instr(11, SWITCH, ROperand::Switch(vec![28, 29, 30])), // 17
                instr(28, NOP, ROperand::None),                 // 1
                instr(29, NOP, ROperand::None),                 // 1
                instr(30, NOP, ROperand::None),                 // 1
                instr(31, RET, ROperand::None),                 // 1
            ],
            exception_handlers: vec![ExceptionHandlerIL {
                kind: ExceptionKind::Finally,
                try_offset: 0,
                try_length: 11,
                filter_offset: 0,
                handler_offset: 28,
                handler_length: 3,
                catch_type: None,
            }],
            ..Default::default()
        };

        let mut builder = MetadataBuilder::new("v4.0.30319");
        let mut tmap = TokenMap::new(&mut builder);
        let m = Module::default();

        let mut out = ByteWriter::new();
        let written = encode_body(&body, &mut tmap, &m, &mut out).expect("encode");
        let bytes = out.into_vec();
        assert_eq!(written as usize, bytes.len());

        // Header checks: fat, init locals, more sects, maxstack 16, code 32.
        let header = parse_body_header(&bytes).expect("parses");
        assert!(header.fat);
        assert!(header.init_locals);
        assert!(header.more_sects);
        assert_eq!(header.max_stack, 16);
        assert_eq!(header.code_size, 32);
        assert_eq!(bytes[0], FAT_FORMAT | INIT_LOCALS_FLAG | MORE_SECTS_FLAG);
        assert_eq!(bytes[1], FAT_HEADER_SIZE_BYTE);

        // Locals StandAloneSig token flows through the map.
        let expected_locals = tmap
            .local_var_sig_token(std::slice::from_ref(&int32_local()), &m)
            .expect("local sig");
        assert_eq!(header.locals_token, expected_locals);
        assert!(!header.locals_token.is_nil());

        // Manual remap of decoded operands back onto expected ROperands.
        let call_token = tmap.method_ref(&call, &m).expect("call token");
        let expected_operands: Vec<ROperand> = vec![
            ROperand::Int8(42),
            ROperand::Var(0),
            ROperand::Var(0),
            ROperand::Token(call_token),
            ROperand::Switch(vec![28, 29, 30]),
            ROperand::None,
            ROperand::None,
            ROperand::None,
            ROperand::None,
        ];
        let (_, code) = decode(&bytes);
        assert_eq!(code.len(), body.instructions.len());
        for (decoded, source) in code.iter().zip(expected_operands.iter()) {
            match (&decoded.operand, source) {
                (Operand::Token(got), ROperand::Token(want)) => assert_eq!(got, want),
                (got, want) => assert_eq!(got, &remap_to_operand(want)),
            }
        }

        // Finally clause survives verbatim.
        let (_, clauses) = decode_sections(&bytes[12 + 32..]);
        assert_eq!(clauses.len(), 1);
        let f = &clauses[0];
        assert_eq!(f.handler_type, cecli_cil::ExceptionHandlerType::Finally);
        assert_eq!(f.try_start, 0);
        assert_eq!(f.try_length, 11);
        assert_eq!(f.handler_start, 28);
        assert_eq!(f.handler_length, 3);
    }

    #[test]
    fn ldstr_uses_user_string_token() {
        let body = ResolvedBody {
            instructions: vec![
                instr(0, LDSTR, ROperand::String("hello".into())),
                instr(5, POP, ROperand::None),
                instr(6, RET, ROperand::None),
            ],
            ..Default::default()
        };

        let mut builder = MetadataBuilder::new("v4.0.30319");
        let mut tmap = TokenMap::new(&mut builder);
        let m = Module::default();

        let mut out = ByteWriter::new();
        encode_body(&body, &mut tmap, &m, &mut out).expect("encode");
        let bytes = out.into_vec();

        let index = tmap.user_string("hello");
        let expected = (0x70u32 << 24) | index;
        assert_eq!(&bytes[2..6], &expected.to_le_bytes());

        let (_, code) = decode(&bytes);
        assert_eq!(code[0].operand, Operand::UserString(index));
    }

    #[test]
    fn exception_clauses_sorted_and_fat_section_forced() {
        let ty = ext_type("System", "Exception");
        // Deliberately unsorted input; large try length forces the fat form.
        let body = ResolvedBody {
            max_stack: 1,
            instructions: vec![instr(0, RET, ROperand::None)],
            exception_handlers: vec![
                ExceptionHandlerIL {
                    kind: ExceptionKind::Fault,
                    try_offset: 100,
                    try_length: 1,
                    filter_offset: 0,
                    handler_offset: 101,
                    handler_length: 1,
                    catch_type: None,
                },
                ExceptionHandlerIL {
                    kind: ExceptionKind::Catch,
                    try_offset: 0,
                    try_length: 400, // > u8::MAX => fat section
                    filter_offset: 0,
                    handler_offset: 100,
                    handler_length: 1,
                    catch_type: Some(ty.clone()),
                },
            ],
            ..Default::default()
        };

        let mut builder = MetadataBuilder::new("v4.0.30319");
        let mut tmap = TokenMap::new(&mut builder);
        let m = Module::default();

        let mut out = ByteWriter::new();
        encode_body(&body, &mut tmap, &m, &mut out).expect("encode");
        let bytes = out.into_vec();

        // Code is a single `ret`; section follows after 4-alignment padding.
        let (pad, clauses) = decode_sections(&bytes[13..]);
        assert_eq!(13 + pad, 16); // padded to a multiple of four
        assert_eq!(bytes[16] & 0x41, 0x41); // EH table | fat format

        assert_eq!(clauses.len(), 2);
        // Sorted by try offset despite unsorted input.
        assert_eq!(clauses[0].try_start, 0);
        assert_eq!(clauses[0].handler_type, ExceptionHandlerType::Catch);
        assert_eq!(
            clauses[0].catch_type,
            tmap.type_token(&ty, &m).expect("catch token")
        );
        assert_eq!(clauses[1].try_start, 100);
        assert_eq!(clauses[1].handler_type, ExceptionHandlerType::Fault);
    }

    #[test]
    fn rva_operand_range_checked() {
        let fits = ResolvedBody {
            instructions: vec![instr(0, LDC_I4, ROperand::Rva(0x1234_5678))],
            ..Default::default()
        };
        let too_big = ResolvedBody {
            instructions: vec![instr(0, LDC_I4, ROperand::Rva(u64::MAX))],
            ..Default::default()
        };

        let mut builder = MetadataBuilder::new("v4.0.30319");
        let mut tmap = TokenMap::new(&mut builder);
        let m = Module::default();

        let mut out = ByteWriter::new();
        encode_body(&fits, &mut tmap, &m, &mut out).expect("fits");
        assert_eq!(&out.as_slice()[2..6], &0x1234_5678u32.to_le_bytes());

        let err = encode_body(&too_big, &mut tmap, &m, &mut out).unwrap_err();
        assert!(err.to_string().contains("32 bits"));
    }

    #[test]
    fn fat_selection_rule_matches_cecil() {
        let base = ResolvedBody::default();
        // 63 bytes stay tiny when nothing else forces fat.
        assert!(!requires_fat_header(63, &base, false));
        // Every forcing condition flips the decision at 63 bytes.
        assert!(requires_fat_header(64, &base, false));
        let init = ResolvedBody {
            init_locals: true,
            ..base.clone()
        };
        assert!(requires_fat_header(63, &init, false));
        let local = ResolvedBody {
            locals: vec![int32_local()],
            ..base.clone()
        };
        assert!(requires_fat_header(63, &local, false));
        assert!(requires_fat_header(63, &base, true));
        let deep_stack = ResolvedBody {
            max_stack: 9,
            ..base
        };
        assert!(requires_fat_header(63, &deep_stack, false));
    }

    #[test]
    fn operand_opcode_mismatch_is_error() {
        let bad = ResolvedBody {
            instructions: vec![instr(0, BR_S, ROperand::Int8(0))],
            ..Default::default()
        };
        let mut builder = MetadataBuilder::new("v4.0.30319");
        let mut tmap = TokenMap::new(&mut builder);
        let m = Module::default();

        let mut out = ByteWriter::new();
        assert!(encode_body(&bad, &mut tmap, &m, &mut out).is_err());
    }

    /// Maps a resolved operand onto its decoded `cecli-cil` counterpart for
    /// non-token operands.
    fn remap_to_operand(op: &ROperand) -> Operand {
        match op {
            ROperand::None => Operand::None,
            ROperand::Int8(v) => Operand::Int8(*v),
            ROperand::Int32(v) => Operand::Int32(*v),
            ROperand::Int64(v) => Operand::Int64(*v),
            ROperand::Float32(v) => Operand::Float32(*v),
            ROperand::Float64(v) => Operand::Float64(*v),
            ROperand::Branch(v) => Operand::Branch(*v),
            ROperand::Switch(v) => Operand::Switch(v.clone()),
            ROperand::Var(v) => Operand::Var(*v),
            ROperand::UserString(v) => Operand::UserString(*v),
            _ => unreachable!("token operands compared separately"),
        }
    }
}
