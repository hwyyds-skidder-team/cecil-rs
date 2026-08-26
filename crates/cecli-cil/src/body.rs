//! Method body model and header/code encode+decode
//! (`Mono.Cecil.Cil/MethodBody.cs` plus `CodeReader.ReadMethodBody` /
//! `CodeWriter.WriteResolvedMethodBody`; ECMA-335 II §25.4.2).

use cecli_core::io::{ByteReader, ByteWriter};
use cecli_core::{Error, Result, Token};

use crate::exceptions::{parse_sections, requires_fat_section, write_section};
use crate::instruction::{Instruction, Operand};
use crate::opcode::{OpCode, OperandType};
use crate::opcodes;
use crate::variable::VariableDefinition;

/// The IL body of a method: header fields, instructions, locals and
/// exception handlers.
#[derive(Debug, Clone, PartialEq)]
pub struct MethodBody {
    /// Maximum evaluation-stack depth (`maxstack`).
    pub max_stack: u16,
    /// `StandAloneSig` token of the local variable signature; `Token::NIL`
    /// when the body has no locals.
    pub local_var_sig_tok: Token,
    /// Whether the locals must be zero-initialized before the body runs.
    pub init_locals: bool,
    /// Decoded instruction stream; branch operands hold absolute offsets.
    pub instructions: Vec<Instruction>,
    /// Exception-handling clauses.
    pub exception_handlers: Vec<crate::ExceptionHandler>,
    /// Local variable slots (populated by the metadata layer from the
    /// local signature).
    pub variables: Vec<VariableDefinition>,
}

impl Default for MethodBody {
    fn default() -> Self {
        MethodBody {
            max_stack: 8,
            local_var_sig_tok: Token::NIL,
            init_locals: false,
            instructions: Vec::new(),
            exception_handlers: Vec::new(),
            variables: Vec::new(),
        }
    }
}

impl MethodBody {
    /// Total size in bytes of the encoded instruction stream.
    pub fn code_size(&self) -> u32 {
        self.instructions.iter().map(Instruction::size).sum::<usize>() as u32
    }
}

/// Result of parsing a method body header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedHeader {
    /// `true` for a fat header, `false` for a tiny one.
    pub fat: bool,
    /// Size in bytes of the IL code that follows the header.
    pub code_size: u32,
    /// Declared maximum stack depth (always 8 for tiny headers).
    pub max_stack: u16,
    /// `StandAloneSig` token of the locals (`Token::NIL` when absent).
    pub locals_token: Token,
    /// Whether locals are zero-initialized (always `false` for tiny).
    pub init_locals: bool,
    /// Whether extra data sections (exception clauses) follow the code.
    pub more_sects: bool,
}

const TINY_FORMAT: u8 = 0x2;
const FAT_FORMAT: u8 = 0x3;
const MORE_SECTS_FLAG: u16 = 0x8;
const INIT_LOCALS_FLAG: u16 = 0x10;

/// Parses a method body header at the start of `data`.
///
/// Tiny form: one byte `(code_size << 2) | 0x2`. Fat form: twelve bytes
/// (flags u16, maxstack u16, code size u32, locals token u32).
pub fn parse_body_header(data: &[u8]) -> Result<ParsedHeader> {
    if data.is_empty() {
        return Err(Error::bad_image("empty method body"));
    }
    let flags_byte = data[0];
    match flags_byte & 0x3 {
        TINY_FORMAT => Ok(ParsedHeader {
            fat: false,
            code_size: (flags_byte >> 2) as u32,
            max_stack: 8,
            locals_token: Token::NIL,
            init_locals: false,
            more_sects: false,
        }),
        FAT_FORMAT => {
            if data.len() < 12 {
                return Err(Error::bad_image("truncated fat method body header"));
            }
            let mut r = ByteReader::new(data);
            let flags = r.u16()?;
            let max_stack = r.u16()?;
            let code_size = r.u32()?;
            let locals_token = r.u32()?;
            Ok(ParsedHeader {
                fat: true,
                code_size,
                max_stack,
                locals_token: Token(locals_token),
                init_locals: flags & INIT_LOCALS_FLAG != 0,
                more_sects: flags & MORE_SECTS_FLAG != 0,
            })
        }
        other => Err(Error::bad_image(format!("invalid method header format bits {other:#x}"))),
    }
}

/// Encodes a method body header.
///
/// With `tiny == true` the body must fit the tiny constraints (code < 64
/// bytes, no explicit locals/init/maxstack), otherwise an error is returned.
/// Fat headers are always 12 bytes long.
pub fn encode_body_header(
    tiny: bool,
    code_size: u32,
    max_stack: u16,
    locals: Token,
    init_locals: bool,
) -> Result<Vec<u8>> {
    if tiny {
        if code_size >= 64 {
            return Err(Error::invalid_op("tiny header cannot encode code >= 64 bytes"));
        }
        if !locals.is_nil() || init_locals || max_stack > 8 {
            return Err(Error::invalid_op(
                "tiny header cannot encode locals, init_locals or max_stack > 8",
            ));
        }
        return Ok(vec![TINY_FORMAT | ((code_size as u8) << 2)]);
    }

    if code_size > u32::MAX >> 1 {
        return Err(Error::invalid_op("code size too large"));
    }
    // Low nibble: format + flags; high nibble of the second byte: header
    // size in dwords (3), exactly like Cecil's `WriteFatHeader` (0x30).
    let mut flags: u16 = (FAT_FORMAT as u16) | 0x3000;
    if init_locals {
        flags |= INIT_LOCALS_FLAG;
    }
    let mut w = ByteWriter::new();
    w.u16(flags);
    w.u16(max_stack);
    w.u32(code_size);
    w.u32(locals.0);
    Ok(w.into_vec())
}

/// Decodes an IL code stream into instructions.
///
/// Branch operands are resolved to absolute IL offsets relative to the start
/// of `data`. Unknown encodings or truncated operands yield errors; no panic
/// occurs on malformed input.
pub fn read_code(data: &[u8], code_size: usize) -> Result<Vec<Instruction>> {
    if code_size > data.len() {
        return Err(Error::bad_image(format!(
            "code size {code_size} exceeds available {} bytes",
            data.len()
        )));
    }
    let mut reader = ByteReader::new(&data[..code_size]);
    let mut instructions = Vec::new();

    while !reader.is_empty() {
        let offset = reader.position() as i32;
        let opcode = read_opcode(&mut reader)?;

        let operand = if opcode.operand_type == OperandType::InlineNone {
            Operand::None
        } else {
            read_operand(&mut reader, opcode, offset)?
        };
        instructions.push(Instruction::new(offset, opcode, operand));
    }
    Ok(instructions)
}

fn read_opcode(reader: &mut ByteReader<'_>) -> Result<OpCode> {
    let first = reader.u8()?;
    if first != 0xFE {
        return opcodes::one_byte(first)
            .copied()
            .ok_or_else(|| Error::bad_image(format!("unknown single-byte opcode {first:#04x}")));
    }
    let second = reader.u8()?;
    opcodes::two_byte(second)
        .copied()
        .ok_or_else(|| Error::bad_image(format!("unknown two-byte opcode fe {second:#04x}")))
}

fn read_operand(reader: &mut ByteReader<'_>, opcode: OpCode, offset: i32) -> Result<Operand> {
    // Offset just past the fixed-size operand; branch targets are relative
    // to it (Cecil's `Offset` inside `ReadOperand`).
    let next_offset = offset + instruction_fixed_size(opcode) as i32;
    match opcode.operand_type {
        OperandType::InlineSwitch => {
            let count = reader.i32()?;
            if count < 0 || count > (reader.remaining() / 4) as i32 {
                return Err(Error::bad_image(format!("invalid switch target count {count}")));
            }
            let base = next_offset + 4 * count;
            let mut targets = Vec::with_capacity(count as usize);
            for _ in 0..count {
                targets.push(base + reader.i32()?);
            }
            Ok(Operand::Switch(targets))
        }
        OperandType::ShortInlineBrTarget => Ok(Operand::Branch(next_offset + reader.i8()? as i32)),
        OperandType::InlineBrTarget => Ok(Operand::Branch(next_offset + reader.i32()?)),
        OperandType::ShortInlineI => Ok(Operand::Int8(reader.i8()?)),
        OperandType::InlineI => Ok(Operand::Int32(reader.i32()?)),
        OperandType::InlineI8 => Ok(Operand::Int64(reader.i64()?)),
        OperandType::ShortInlineR => Ok(Operand::Float32(reader.f32()?)),
        OperandType::InlineR => Ok(Operand::Float64(reader.f64()?)),
        OperandType::ShortInlineVar | OperandType::ShortInlineArg => {
            Ok(Operand::Var(reader.u8()? as u16))
        }
        OperandType::InlineVar | OperandType::InlineArg => Ok(Operand::Var(reader.u16()?)),
        OperandType::InlineString => Ok(Operand::UserString(reader.u32()? & 0x00FF_FFFF)),
        OperandType::InlineSig
        | OperandType::InlineTok
        | OperandType::InlineType
        | OperandType::InlineMethod
        | OperandType::InlineField => Ok(Operand::Token(Token(reader.u32()?))),
        OperandType::InlineNone => Ok(Operand::None),
    }
}

const fn instruction_fixed_size(opcode: OpCode) -> usize {
    match opcode.operand_type.size() {
        Some(n) => opcode.size as usize + n,
        None => opcode.size as usize + 4,
    }
}

/// Encodes instructions back into an IL byte stream.
///
/// Offsets are recomputed sequentially; absolute branch targets are turned
/// back into their relative encodings. User-string operands are written as
/// `ldstr` tokens (`0x70 << 24 | index`).
pub fn write_code(instructions: &[Instruction]) -> Result<Vec<u8>> {
    let mut offsets = Vec::with_capacity(instructions.len());
    let mut offset = 0usize;
    for instruction in instructions {
        offsets.push(offset as i32);
        offset += instruction.size();
    }

    let mut writer = ByteWriter::new();
    for (index, instruction) in instructions.iter().enumerate() {
        let offset = offsets[index];
        let opcode = instruction.opcode;

        if opcode.is_single_byte() {
            writer.u8(opcode.byte2);
        } else {
            writer.u8(opcode.byte1);
            writer.u8(opcode.byte2);
        }

        let rel_base = offset + instruction_fixed_size(opcode) as i32;
        match (&instruction.operand, opcode.operand_type) {
            (Operand::Switch(targets), OperandType::InlineSwitch) => {
                writer.i32(targets.len() as i32);
                let base = rel_base + 4 * targets.len() as i32;
                for &target in targets {
                    writer.i32(target - base);
                }
            }
            (Operand::Branch(target), OperandType::ShortInlineBrTarget) => {
                let delta = *target - rel_base;
                if !(i8::MIN as i32..=i8::MAX as i32).contains(&delta) {
                    return Err(Error::invalid_op("branch target out of sbyte range"));
                }
                writer.i8(delta as i8);
            }
            (Operand::Branch(target), OperandType::InlineBrTarget) => {
                writer.i32(*target - rel_base);
            }
            (operand, ot) => write_simple_operand(&mut writer, operand, ot)?,
        }
    }
    Ok(writer.into_vec())
}

fn write_simple_operand(writer: &mut ByteWriter, operand: &Operand, ot: OperandType) -> Result<()> {
    macro_rules! expect {
        ($pat:pat => $val:expr, $what:expr) => {
            match operand {
                $pat => $val,
                other => {
                    return Err(Error::argument(format!(
                        concat!("expected ", $what, ", got {:?}"),
                        other
                    )))
                }
            }
        };
    }

    match ot {
        OperandType::InlineNone => Ok(()),
        OperandType::ShortInlineI => {
            writer.i8(expect!(Operand::Int8(v) => *v, "an Int8"));
            Ok(())
        }
        OperandType::InlineI => {
            writer.i32(expect!(Operand::Int32(v) => *v, "an Int32"));
            Ok(())
        }
        OperandType::InlineI8 => {
            writer.i64(expect!(Operand::Int64(v) => *v, "an Int64"));
            Ok(())
        }
        OperandType::ShortInlineR => {
            writer.f32(expect!(Operand::Float32(v) => *v, "a Float32"));
            Ok(())
        }
        OperandType::InlineR => {
            writer.f64(expect!(Operand::Float64(v) => *v, "a Float64"));
            Ok(())
        }
        OperandType::ShortInlineVar | OperandType::ShortInlineArg => {
            let v = expect!(Operand::Var(v) => *v, "a Var");
            if v > u8::MAX as u16 {
                return Err(Error::invalid_op("variable index does not fit one byte"));
            }
            writer.u8(v as u8);
            Ok(())
        }
        OperandType::InlineVar | OperandType::InlineArg => {
            writer.u16(expect!(Operand::Var(v) => *v, "a Var"));
            Ok(())
        }
        OperandType::InlineString => {
            let idx = expect!(Operand::UserString(v) => *v, "a UserString");
            writer.u32(0x7000_0000 | idx);
            Ok(())
        }
        OperandType::InlineSig
        | OperandType::InlineTok
        | OperandType::InlineType
        | OperandType::InlineMethod
        | OperandType::InlineField => {
            writer.u32(expect!(Operand::Token(t) => t.0, "a Token"));
            Ok(())
        }
        OperandType::InlineSwitch
        | OperandType::ShortInlineBrTarget
        | OperandType::InlineBrTarget => {
            Err(Error::argument("branch operand handled by write_code"))
        }
    }
}

/// Convenience: parses the header, code stream and trailing sections of a
/// complete method body image. Returns the decoded body along with the total
/// number of bytes consumed (header + code + aligned sections).
pub fn decode_method_body(data: &[u8]) -> Result<(MethodBody, usize)> {
    let header = parse_body_header(data)?;
    let header_len = if header.fat { 12 } else { 1 };
    let code_start = header_len;
    let code_end = code_start + header.code_size as usize;
    if code_end > data.len() {
        return Err(Error::bad_image("method body code exceeds input length"));
    }

    let mut body = MethodBody {
        max_stack: header.max_stack,
        local_var_sig_tok: header.locals_token,
        init_locals: header.init_locals,
        ..MethodBody::default()
    };
    body.instructions = read_code(&data[code_start..code_end], header.code_size as usize)?;
    let mut consumed = code_end;

    if header.more_sects {
        let sections_start = (consumed + 3) & !3usize;
        if sections_start > data.len() {
            return Err(Error::bad_image("missing exception sections"));
        }
        let (handlers, _more) = parse_sections(&data[sections_start..])?;
        body.exception_handlers = handlers;
        consumed = sections_start + section_stream_len(&data[sections_start..]);
    }

    Ok((body, consumed))
}

/// Walks chained exception sections and returns their total byte length.
fn section_stream_len(data: &[u8]) -> usize {
    let mut pos = 0usize;
    loop {
        if data.len() < pos + 4 {
            return data.len();
        }
        let flags = data[pos];
        let size = if flags & 0x40 != 0 {
            (data[pos + 1] as usize)
                | (data[pos + 2] as usize) << 8
                | (data[pos + 3] as usize) << 16
        } else {
            data[pos + 1] as usize
        };
        pos += size.max(4);
        if flags & 0x80 == 0 || pos >= data.len() {
            return pos.min(data.len());
        }
        // Chained sections start at the next 4-byte boundary.
        while !pos.is_multiple_of(4) && pos < data.len() {
            pos += 1;
        }
    }
}

/// Encodes a complete method body image (header + code + optional exception
/// sections), choosing the tiny or the fat form like Cecil's
/// `CodeWriter.RequiresFatHeader`.
pub fn encode_method_body(body: &MethodBody) -> Result<Vec<u8>> {
    let code_bytes = write_code(&body.instructions)?;
    let code_size = code_bytes.len() as u32;
    let has_handlers = !body.exception_handlers.is_empty();

    let fat = body.init_locals
        || !body.local_var_sig_tok.is_nil()
        || has_handlers
        || body.max_stack > 8
        || code_size >= 64;

    let mut out = encode_body_header(
        !fat,
        code_size,
        body.max_stack,
        body.local_var_sig_tok,
        body.init_locals,
    )?;

    if fat && has_handlers {
        // Reserve the more_sects bit in the header before writing the code.
        let flags_pos = 0;
        out[flags_pos] |= 0x08;
    }

    out.extend_from_slice(&code_bytes);

    if has_handlers {
        while out.len() % 4 != 0 {
            out.push(0); // align section to 4 bytes
        }
        let force_fat = requires_fat_section(&body.exception_handlers, false)
            || body.exception_handlers.len() >= 0x15;
        out.extend_from_slice(&write_section(&body.exception_handlers, force_fat)?);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exceptions::{ExceptionHandler, ExceptionHandlerType};
    use crate::opcodes;
    use cecli_core::{TableIndex, Token};

    /// Acceptance #2: tiny header encode -> parse roundtrip.
    #[test]
    fn tiny_header_roundtrip() {
        let bytes = encode_body_header(true, 42, 8, Token::NIL, false).unwrap();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], (42 << 2) | 0x2);
        let parsed = parse_body_header(&bytes).unwrap();
        assert!(!parsed.fat);
        assert_eq!(parsed.code_size, 42);
        assert_eq!(parsed.max_stack, 8);
        assert!(parsed.locals_token.is_nil());
        assert!(!parsed.init_locals);
        assert!(!parsed.more_sects);
    }

    /// Acceptance #2: fat header encode -> parse roundtrip incl.
    /// init_locals and locals token.
    #[test]
    fn fat_header_roundtrip() {
        let locals = Token::new(TableIndex::StandAloneSig, 7); // StandAloneSig rid 7
        let bytes = encode_body_header(false, 300, 16, locals, true).unwrap();
        assert_eq!(bytes.len(), 12);
        // flags: 0x3 | init_locals(0x10)
        assert_eq!((bytes[0], bytes[1]), (0x13, 0x30));
        let parsed = parse_body_header(&bytes).unwrap();
        assert!(parsed.fat);
        assert_eq!(parsed.code_size, 300);
        assert_eq!(parsed.max_stack, 16);
        assert_eq!(parsed.locals_token, locals);
        assert!(parsed.init_locals);
        assert!(!parsed.more_sects);
    }

    #[test]
    fn tiny_header_rejects_fat_only_fields() {
        assert!(encode_body_header(true, 64, 8, Token::NIL, false).is_err());
        assert!(encode_body_header(true, 10, 9, Token::NIL, false).is_err());
        assert!(encode_body_header(true, 10, 8, Token::new(TableIndex::StandAloneSig, 1), false)
            .is_err());
        assert!(encode_body_header(true, 10, 8, Token::NIL, true).is_err());
    }

    #[test]
    fn malformed_headers_error() {
        assert!(parse_body_header(&[]).is_err());
        assert!(parse_body_header(&[0x00]).is_err()); // format bits 0
        assert!(parse_body_header(&[0x03, 0x30]).is_err()); // truncated fat
    }

    /// Decode -> encode roundtrip over a program with branches and a switch.
    #[test]
    fn code_roundtrip_with_branches_and_switch() {
        // IL_0000: nop                       (1 byte)
        // IL_0001: ldc.i4.s 5                (2 bytes)
        // IL_0003: br.s IL_0010              (2 bytes)   target abs 16
        // IL_0005: ldarg.1                   (1 byte)
        // IL_0006: switch (IL_0005, IL_0010) (1+4+4+4=13 bytes)
        // IL_0013: ldc.i4 1000               (5 bytes)
        // IL_0018: leave IL_0018             (5 bytes) self-branch
        // IL_001D: ret                       (1 byte)
        let instructions = vec![
            Instruction::none(0, opcodes::NOP),
            Instruction::new(1, opcodes::LDC_I4_S, Operand::Int8(5)),
            Instruction::new(3, opcodes::BR_S, Operand::Branch(16)),
            Instruction::none(5, opcodes::LDARG_1),
            Instruction::new(6, opcodes::SWITCH, Operand::Switch(vec![5, 16])),
            Instruction::new(19, opcodes::LDC_I4, Operand::Int32(1000)),
            Instruction::new(24, opcodes::LEAVE, Operand::Branch(24)),
            Instruction::none(29, opcodes::RET),
        ];
        // Verify offsets line up with sizes before encoding.
        let mut off = 0usize;
        for instr in &instructions {
            assert_eq!(instr.offset, off as i32);
            off += instr.size();
        }
        assert_eq!(off, 30);

        let encoded = write_code(&instructions).unwrap();
        assert_eq!(encoded.len(), 30);
        // Spot-check raw encodings.
        assert_eq!(&encoded[..3], &[0x00, 0x1F, 0x05]);
        assert_eq!(encoded[3], 0x2B); // br.s
        assert_eq!(encoded[4], 11); // rel = target 16 - next offset 5
        assert_eq!(encoded[6], 0x45); // switch

        let decoded = read_code(&encoded, encoded.len()).unwrap();
        assert_eq!(decoded, instructions);
    }

    #[test]
    fn code_decode_handles_tokens_and_strings() {
        // callvirt on MethodDef 4; ldstr us-index 0x1234; ldloc 300; ret.
        let instructions = vec![
            Instruction::new(
                0,
                opcodes::CALLVIRT,
                Operand::Token(Token::new(TableIndex::MethodDef, 4)),
            ),
            Instruction::new(5, opcodes::LDSTR, Operand::UserString(0x1234)),
            Instruction::new(10, opcodes::LDLOC, Operand::Var(300)),
            Instruction::new(14, opcodes::STIND_I, Operand::None),
            Instruction::new(15, opcodes::CONV_U8, Operand::None),
            Instruction::none(16, opcodes::RET),
        ];
        let encoded = write_code(&instructions).unwrap();
        assert_eq!(encoded.len(), 17);
        let decoded = read_code(&encoded, encoded.len()).unwrap();
        assert_eq!(decoded, instructions);
    }

    #[test]
    fn unknown_opcode_is_an_error_not_a_panic() {
        let data = [0x24]; // undefined slot
        assert!(read_code(&data, 1).is_err());
        let data2 = [0xFE, 0x08];
        assert!(read_code(&data2, 2).is_err());
        // Truncated operand.
        let data3 = [0x20, 0x01]; // ldc.i4 missing 3 bytes
        assert!(read_code(&data3, 2).is_err());
    }

    /// Full-body roundtrip: tiny form.
    #[test]
    fn tiny_body_roundtrip() {
        let body = MethodBody {
            instructions: vec![
                Instruction::none(0, opcodes::LDC_I4_2),
                Instruction::none(1, opcodes::RET),
            ],
            ..MethodBody::default()
        };
        let bytes = encode_method_body(&body).unwrap();
        assert_eq!(bytes.len(), 3); // 1 header + 2 code
        assert_eq!(bytes[0], (2 << 2) | 0x2);
        let (decoded, consumed) = decode_method_body(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, body);
    }

    /// Full-body roundtrip: fat form with locals, init_locals and exception
    /// handlers in both clause forms.
    #[test]
    fn fat_body_with_sections_roundtrip() {
        let locals = Token::new(TableIndex::StandAloneSig, 42);
        let mut handler = ExceptionHandler::new(ExceptionHandlerType::Catch);
        handler.try_start = 0;
        handler.try_length = 6;
        handler.handler_start = 6;
        handler.handler_length = 4;
        handler.catch_type = Token(0x0100_000A);

        // Offsets: nop(0) leave.s(1..3) pop(3)? keep simple:
        // 0: nop, 1: leave.s -> 6, 3: pop, 4: endfinally, 5: rethrow? use:
        // 0: nop; 1: leave.s 7 (2 bytes); 3: pop; 4: pop; 5: endfinally;
        // 6: rethrow (fe 1a); 8: ret
        let body = MethodBody {
            max_stack: 8,
            local_var_sig_tok: locals,
            init_locals: true,
            instructions: vec![
                Instruction::none(0, opcodes::NOP),
                Instruction::new(1, opcodes::LEAVE_S, Operand::Branch(7)),
                Instruction::none(3, opcodes::POP),
                Instruction::none(4, opcodes::ENDFINALLY),
                Instruction::none(5, opcodes::RETHROW),
                Instruction::none(8 - 1, opcodes::RET), // offset 7
            ],
            exception_handlers: vec![handler],
            variables: vec![
                VariableDefinition::new(0, Token(0x0100_0001)),
                VariableDefinition::new(1, Token(0x0100_0002)),
            ],
        };

        let bytes = encode_method_body(&body).unwrap();
        let (decoded, _consumed) = decode_method_body(&bytes).unwrap();
        // Header fields survive.
        assert!(decoded.init_locals);
        assert_eq!(decoded.local_var_sig_tok, locals);
        assert!(!decoded.instructions.is_empty());
        // Instructions compare equal including recomputed offsets.
        assert_eq!(decoded.instructions, body.instructions);
        // Clause survives with identical semantics (small form).
        assert_eq!(decoded.exception_handlers.len(), 1);
        assert_eq!(decoded.exception_handlers[0].handler_type, ExceptionHandlerType::Catch);
        assert_eq!(decoded.exception_handlers[0].try_start, 0);
        assert_eq!(decoded.exception_handlers[0].try_length, 6);
        assert_eq!(decoded.exception_handlers[0].handler_start, 6);
        assert_eq!(decoded.exception_handlers[0].handler_length, 4);
        assert_eq!(decoded.exception_handlers[0].catch_type, Token(0x0100_000A));

        // Re-encode is stable (byte-for-byte).
        let again = encode_method_body(&decoded).unwrap();
        assert_eq!(again, bytes);
    }

    /// A try block longer than 255 bytes must switch the section to fat form.
    #[test]
    fn long_ranges_force_fat_section() {
        let mut handler = ExceptionHandler::new(ExceptionHandlerType::Finally);
        handler.try_start = 0;
        handler.try_length = 600;
        handler.handler_start = 600;
        handler.handler_length = 200;

        // Build matching instruction stream: 600 nops + endfinally + ret.
        let mut instructions: Vec<Instruction> =
            Vec::with_capacity(handler.try_length as usize + 2);
        let mut off = 0i32;
        for _ in 0..handler.try_length {
            instructions.push(Instruction::none(off, opcodes::NOP));
            off += 1;
        }
        instructions.push(Instruction::none(off, opcodes::ENDFINALLY));
        off += 1;
        handler.handler_start = off;
        instructions.push(Instruction::none(off, opcodes::RET));

        let body = MethodBody {
            max_stack: 8,
            local_var_sig_tok: Token::NIL,
            init_locals: false,
            instructions,
            exception_handlers: vec![handler],
            variables: Vec::new(),
        };
        let bytes = encode_method_body(&body).unwrap();
        let (decoded, _) = decode_method_body(&bytes).unwrap();
        assert_eq!(decoded.instructions, body.instructions);
        assert_eq!(decoded.exception_handlers, body.exception_handlers);
        // The section really used the fat flag: code size is 602 bytes, so
        // the body is fat (12-byte header) and sections start 4-aligned.
        assert_eq!(decoded.code_size(), 602);
        let sections_start = ((12 + 602usize) + 3) & !3usize;
        let flags = bytes[sections_start];
        assert_eq!(flags & 0x40, 0x40);
        // Fat section data length = 1 clause * 24 + 4.
        let size = (bytes[sections_start + 1] as usize)
            | (bytes[sections_start + 2] as usize) << 8
            | (bytes[sections_start + 3] as usize) << 16;
        assert_eq!(size, 28);
    }
}
