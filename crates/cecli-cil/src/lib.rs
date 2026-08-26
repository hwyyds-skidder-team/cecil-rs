//! `cecli-cil`: the CIL layer of the Cecil rewrite.
//!
//! Provides the complete ECMA-335 partition III opcode table, the
//! [`Instruction`] / [`MethodBody`] model, and encode+decode helpers for
//! method-body headers (ECMA II §25.4.2) and exception-handler sections
//! (§25.4.6), ported from `Mono.Cecil.Cil`.
//!
//! This crate is deliberately decoupled from the object model: operands that
//! reference metadata stay encoded as [`Operand::Token`],
//! [`Operand::UserString`], or local-variable indices; resolution happens in
//! the `cecli` facade crate.

pub mod body;
pub mod code;
pub mod exceptions;
pub mod instruction;
pub mod opcode;
pub mod opcodes;
pub mod variable;

pub use body::{
    decode_method_body, encode_body_header, encode_method_body, parse_body_header, read_code,
    write_code, MethodBody, ParsedHeader,
};
pub use code::Code;
pub use exceptions::{
    parse_sections, read_clause, requires_fat_section, write_clause, write_section,
    ExceptionHandler, ExceptionHandlerType, FAT_CLAUSE_SIZE, SMALL_CLAUSE_SIZE,
};
pub use instruction::{Instruction, Operand};
pub use opcode::{instruction_size, OpCode, OperandType};
pub use opcodes as opcode_table;
pub use variable::VariableDefinition;
