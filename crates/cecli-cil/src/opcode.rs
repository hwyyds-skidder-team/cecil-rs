//! Opcode descriptor type and operand-kind enumeration (`Mono.Cecil.Cil.OpCode`).
//!
//! An [`OpCode`] couples an instruction identifier ([`Code`]) with its wire
//! encoding (one- or two-byte, ECMA-335 partition III) and the shape of its
//! inline operand ([`OperandType`]).

use crate::code::Code;

/// The shape and width of an opcode's inline operand.
///
/// Mirrors `Mono.Cecil.Cil.OperandType`; the variants are exactly those of
/// the C# enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OperandType {
    InlineBrTarget,
    InlineField,
    InlineI,
    InlineI8,
    InlineMethod,
    InlineNone,
    InlineR,
    InlineSig,
    InlineString,
    InlineSwitch,
    InlineTok,
    InlineType,
    InlineVar,
    InlineArg,
    ShortInlineBrTarget,
    ShortInlineI,
    ShortInlineR,
    ShortInlineVar,
    ShortInlineArg,
}

impl OperandType {
    /// Fixed operand width in bytes; [`OperandType::InlineSwitch`] has no
    /// fixed width (`None`) because it carries a variable number of targets.
    pub const fn size(self) -> Option<usize> {
        match self {
            OperandType::InlineNone => Some(0),
            OperandType::ShortInlineBrTarget
            | OperandType::ShortInlineI
            | OperandType::ShortInlineVar
            | OperandType::ShortInlineArg => Some(1),
            OperandType::InlineVar | OperandType::InlineArg => Some(2),
            OperandType::InlineBrTarget
            | OperandType::InlineField
            | OperandType::InlineI
            | OperandType::InlineMethod
            | OperandType::InlineSig
            | OperandType::InlineString
            | OperandType::InlineTok
            | OperandType::InlineType
            | OperandType::ShortInlineR => Some(4),
            OperandType::InlineI8 | OperandType::InlineR => Some(8),
            OperandType::InlineSwitch => None,
        }
    }
}

/// A CIL opcode: identifier, canonical mnemonic, wire encoding and operand kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpCode {
    /// Instruction identifier.
    pub code: Code,
    /// Canonical IL mnemonic, e.g. `"ldarg.0"`, `"br.s"`, `"conv.ovf.i1.un"`.
    pub name: &'static str,
    /// Shape of the inline operand.
    pub operand_type: OperandType,
    /// Length in bytes of the opcode itself: 1 (`0xFF` prefix byte omitted)
    /// or 2 (`0xFE` prefix + second byte).
    pub size: u8,
    /// First encoding byte: `0xFF` for single-byte opcodes, `0xFE` for
    /// two-byte opcodes.
    pub byte1: u8,
    /// Second encoding byte (the low byte of the instruction encoding).
    pub byte2: u8,
}

impl OpCode {
    /// Builds an opcode descriptor from its encoding halves.
    pub const fn new(
        code: Code,
        name: &'static str,
        byte1: u8,
        byte2: u8,
        operand_type: OperandType,
    ) -> Self {
        OpCode {
            code,
            name,
            operand_type,
            size: if byte1 == 0xFF { 1 } else { 2 },
            byte1,
            byte2,
        }
    }

    /// Full two-byte encoding as `(byte1 << 8) | byte2`.
    pub const fn encoding(self) -> u16 {
        ((self.byte1 as u16) << 8) | self.byte2 as u16
    }

    /// True when the opcode is a single-byte instruction.
    pub const fn is_single_byte(self) -> bool {
        self.byte1 == 0xFF
    }
}

/// Encoded size in bytes of the fixed part of an instruction: the opcode
/// bytes plus its fixed-width operand.
///
/// For [`OperandType::InlineSwitch`] only the leading target-count `u32` is
/// counted; each additional switch target adds 4 bytes (see
/// [`crate::instruction::Instruction::size`] for the full encoded length).
pub const fn instruction_size(op: OpCode) -> usize {
    let operand = match op.operand_type.size() {
        Some(n) => n,
        // Switch: count field only.
        None => 4,
    };
    op.size as usize + operand
}
