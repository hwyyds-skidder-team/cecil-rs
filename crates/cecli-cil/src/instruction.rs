//! The CIL instruction model (`Mono.Cecil.Cil/Instruction.cs`), decoupled
//! from the object model: metadata references stay encoded as tokens.

use std::fmt;

use crate::opcode::{instruction_size, OpCode, OperandType};
use cecli_core::Token;

/// tokens / heap indices; resolution happens in the object-model layer.
#[derive(Debug, Clone, PartialEq)]
pub enum Operand {
    /// No operand (`InlineNone`).
    None,
    /// Signed 8-bit immediate (`ShortInlineI`, e.g. `ldc.i4.s`, `unaligned.`).
    Int8(i8),
    /// Signed 32-bit immediate (`InlineI`) or a branch-relative base.
    Int32(i32),
    /// Signed 64-bit immediate (`InlineI8`).
    Int64(i64),
    /// 32-bit float immediate (`ShortInlineR`).
    Float32(f32),
    /// 64-bit float immediate (`InlineR`).
    Float64(f64),
    /// Absolute target IL offset of a branch (`ShortInlineBrTarget` /
    /// `InlineBrTarget`).
    Branch(i32),
    /// Absolute target IL offsets of a `switch` (`InlineSwitch`).
    Switch(Vec<i32>),
    /// Raw metadata token (`InlineType`, `InlineMethod`, `InlineField`,
    /// `InlineTok`, `InlineSig`).
    Token(Token),
    /// User-string heap index (`InlineString` / `ldstr`).
    UserString(u32),
    /// Local variable or parameter index (`ShortInlineVar`, `InlineVar`,
    /// `ShortInlineArg`, `InlineArg`).
    Var(u16),
    /// Raw RVA operand (reserved; produced by `cecli`-level resolution).
    Rva(u64),
}

impl Operand {
    /// True when this operand carries no data.
    pub fn is_none(&self) -> bool {
        matches!(self, Operand::None)
    }
}

/// A single CIL instruction: its offset within the method body, the opcode,
/// and the decoded operand.
///
/// Branch targets ([`Operand::Branch`], [`Operand::Switch`]) store absolute
/// IL offsets, matching Cecil's `Instruction.Offset` comparisons.
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    /// Offset of this instruction from the start of the method's IL code.
    pub offset: i32,
    /// The opcode.
    pub opcode: OpCode,
    /// The decoded operand (`Operand::None` for `InlineNone` opcodes).
    pub operand: Operand,
}

impl Instruction {
    /// Creates an instruction at `offset`.
    pub fn new(offset: i32, opcode: OpCode, operand: Operand) -> Self {
        Instruction {
            offset,
            opcode,
            operand,
        }
    }

    /// Creates a zero-operand instruction at `offset`; panics in debug builds
    /// if the opcode expects an operand.
    pub fn none(offset: i32, opcode: OpCode) -> Self {
        debug_assert_eq!(opcode.operand_type, OperandType::InlineNone);
        Instruction {
            offset,
            opcode,
            operand: Operand::None,
        }
    }

    /// Full encoded length of this instruction in bytes, including the
    /// variable switch-target table.
    pub fn size(&self) -> usize {
        match &self.operand {
            Operand::Switch(targets) => self.opcode.size as usize + 4 * (1 + targets.len()),
            _ => instruction_size(self.opcode),
        }
    }
}

impl fmt::Display for Instruction {
    /// Formats like Cecil: `IL_0004: ldarg.0`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IL_{:04x}: {}", self.offset, self.opcode.name)?;
        match &self.operand {
            Operand::None => Ok(()),
            Operand::Branch(target) => write!(f, " IL_{:04x}", target),
            Operand::Switch(targets) => {
                for (i, t) in targets.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, " IL_{:04x}", t)?;
                }
                Ok(())
            }
            Operand::UserString(idx) => write!(f, " \"<us:{:#x}>\"", idx),
            Operand::Token(tok) => write!(f, " {}", tok),
            other => write!(f, " {:?}", other),
        }
    }
}
