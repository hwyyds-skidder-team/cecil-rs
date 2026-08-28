//! IL body validation and walk utilities over resolved method bodies.
//!
//! Port of `Mono.Cecil.Rocks/ILParser.cs`, reworked for the resolved object
//! model: the C# parser decodes raw bytes and drives an `IILVisitor`-style
//! callback per operand kind. Here bodies arrive already decoded
//! ([`ResolvedBody`]), so the same logic becomes
//!
//! * [`validate_body`] / [`validate_body_for`] - re-plays the parser's
//!   per-`OperandType` dispatch as a consistency check: every instruction
//!   operand must have the shape its opcode demands, branch/switch targets
//!   must land inside the code, local-variable indices must exist, argument
//!   indices are checked against the caller-supplied parameter count, and
//!   exception-clause ranges must be sane;
//! * [`visit`] - the visitor walk (index + instruction pairs);
//! * [`collect_branch_targets`] / [`find_by_offset`] - small query helpers.
//!
//! Validation failures are reported as [`cecli_core::Error::InvalidOperation`]
//! with the offending instruction index in the message; no panic ever occurs
//! on malformed input.

use cecli::model::types::{
    ExceptionHandlerIL, ExceptionKind, RInstruction, ROperand, ResolvedBody,
};
use cecli_cil::opcode::{OpCode, OperandType};
use cecli_core::{Error, Result};

/// Encoded size in bytes of one decoded instruction (opcode bytes plus
/// operand bytes). Mirrors `cecli_cil`'s size rules: switch instructions
/// carry 4 bytes of target count plus 4 bytes per target.
pub fn encoded_size(ins: &RInstruction) -> i32 {
    let targets = match &ins.operand {
        ROperand::Switch(v) => v.len(),
        _ => 0,
    };
    let operand = match ins.opcode.operand_type {
        OperandType::InlineSwitch => 4 + 4 * targets as i32,
        other => other.size().map(|n| n as i32).unwrap_or(0),
    };
    ins.opcode.size as i32 + operand
}

/// Total code size in bytes implied by the instruction list: end offset of
/// the last instruction (`0` for an empty body).
pub fn code_size(body: &ResolvedBody) -> i32 {
    body.instructions.last().map(|ins| ins.offset + encoded_size(ins)).unwrap_or(0)
}

/// True when `operand` has exactly the shape demanded by `opcode.operand_type`.
///
/// This is the Rust counterpart of the big `switch (opcode.OperandType)` in
/// `ILParser.ParseCode`: each arm corresponds to one visitor callback the C#
/// parser would have invoked.
fn operand_matches(opcode: OpCode, operand: &ROperand) -> bool {
    use OperandType::*;
    matches!(
        (opcode.operand_type, operand),
        (InlineNone, ROperand::None)
            | (ShortInlineBrTarget | InlineBrTarget, ROperand::Branch(_))
            | (ShortInlineI, ROperand::Int8(_))
            | (InlineI, ROperand::Int32(_))
            | (InlineI8, ROperand::Int64(_))
            | (ShortInlineR, ROperand::Float32(_))
            | (InlineR, ROperand::Float64(_))
            | (InlineSwitch, ROperand::Switch(_))
            // GetString over the #US heap; unresolved strings keep raw offsets.
            | (InlineString, ROperand::String(_) | ROperand::UserString(_))
            // ShortInlineVar/InlineVar cover locals; the Arg variants cover
            // ldarg/starg, both stored as bare indices (`ROperand::Var`).
            | (
                ShortInlineVar | InlineVar | ShortInlineArg | InlineArg,
                ROperand::Var(_)
            )
            // calli: typed CallSite signature, or the raw StandAloneSig token
            // fallback (GetCallSite in C#).
            | (InlineSig, ROperand::CallSite(_) | ROperand::Token(_))
            | (InlineType, ROperand::Type(_) | ROperand::Token(_))
            | (InlineMethod, ROperand::Method(_) | ROperand::Token(_))
            // `ldsflda`/field RVA forms may keep the raw address.
            | (InlineField, ROperand::Field(_) | ROperand::Token(_) | ROperand::Rva(_))
            | (
                InlineTok,
                ROperand::Type(_) | ROperand::Method(_) | ROperand::Field(_) | ROperand::Token(_)
            )
    )
}

fn invalid(idx: usize, msg: String) -> Error {
    Error::invalid_op(format!("instruction #{idx}: {msg}"))
}

/// Validates a resolved body without argument-index checking.
///
/// * every operand kind agrees with `opcode.operand_type`
///   (`operand_matches`);
/// * instruction offsets are non-decreasing and never overlap;
/// * branch and switch targets lie within `[0, code_size]`;
/// * local variable indices (`ldloc*`/`stloc*`) are `< locals.len()`;
/// * exception-handler try/handler ranges stay inside the code with
///   non-negative lengths, and filter offsets point into the code.
///
/// Argument-carrying opcodes (`ldarg`, `ldarg.s`, `starg.s`, `ldarga.s`)
/// cannot be range-checked here: a resolved body does not know its method's
/// parameter count. This wrapper therefore delegates to
/// [`validate_body_for`] with a `usize::MAX` parameter count, which lets any
/// well-shaped argument index pass while still rejecting malformed operands.
/// Callers that know the declaring method should prefer
/// [`validate_body_for`].
pub fn validate_body(body: &ResolvedBody) -> Result<()> {
    validate_body_for(body, usize::MAX)
}

/// Validates a resolved body with full argument checking.
///
/// Same rules as [`validate_body`], plus:
///
/// * argument indices (`ShortInlineArg`/`InlineArg` opcodes) are
///   `< param_count`.
///
/// `param_count` is the caller-supplied slot count for argument operands;
/// for an instance method the implicit `this` occupies slot 0, so callers
/// should pass `1 + parameters.len()` there, matching ECMA-335 II §15.4.1.
/// The `Ldarg_0..Ldarg_3` macro opcodes carry no operand
/// (`OperandType::InlineNone`) and are covered by the shape check only.
pub fn validate_body_for(body: &ResolvedBody, param_count: usize) -> Result<()> {
    let end = code_size(body);

    let mut expected_min = 0i32;
    for (idx, ins) in body.instructions.iter().enumerate() {
        if ins.offset < expected_min {
            return Err(invalid(
                idx,
                format!(
                    "offset {} overlaps or precedes previous instruction (expected >= {expected_min})",
                    ins.offset
                ),
            ));
        }
        expected_min = ins.offset + encoded_size(ins);

        if !operand_matches(ins.opcode, &ins.operand) {
            return Err(invalid(
                idx,
                format!(
                    "opcode `{}` ({:?}) carries incompatible operand {:?}",
                    ins.opcode.name, ins.opcode.operand_type, ins.operand
                ),
            ));
        }

        match &ins.operand {
            ROperand::Branch(target) => {
                if !(0..=end).contains(target) {
                    return Err(invalid(idx, format!("branch target {target} outside [0, {end}]")));
                }
            }
            ROperand::Switch(targets) => {
                for target in targets {
                    if !(0..=end).contains(target) {
                        return Err(invalid(
                            idx,
                            format!("switch target {target} outside [0, {end}]"),
                        ));
                    }
                }
            }
            ROperand::Var(index) => {
                // `ROperand::Var` stores both argument and local slots; the
                // opcode's operand kind decides which table the index names.
                match ins.opcode.operand_type {
                    OperandType::ShortInlineArg | OperandType::InlineArg => {
                        if (*index as usize) >= param_count {
                            return Err(invalid(
                                idx,
                                format!(
                                    "argument index {index} out of range ({param_count} parameter slots)"
                                ),
                            ));
                        }
                    }
                    _ => {
                        if (*index as usize) >= body.locals.len() {
                            return Err(invalid(
                                idx,
                                format!(
                                    "variable index {index} out of range ({} locals)",
                                    body.locals.len()
                                ),
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    for clause in &body.exception_handlers {
        validate_clause(clause, end)?;
    }

    Ok(())
}

fn validate_clause(clause: &ExceptionHandlerIL, end: i32) -> Result<()> {
    let check_range = |what: &str, offset: i32, length: i32| -> Result<()> {
        if offset < 0 || length < 0 || offset + length > end {
            return Err(Error::invalid_op(format!(
                "exception handler {what} range [{offset}, {}) escapes code [0, {end}]",
                offset + length
            )));
        }
        Ok(())
    };
    check_range("try", clause.try_offset, clause.try_length)?;
    if clause.kind == ExceptionKind::Filter
        && (clause.filter_offset < 0 || clause.filter_offset > end)
    {
        return Err(Error::invalid_op(format!(
            "filter offset {} outside [0, {end}]",
            clause.filter_offset
        )));
    }
    check_range("handler", clause.handler_offset, clause.handler_length)?;
    Ok(())
}

/// Walks every instruction in order, invoking `v` with its index and a
/// shared reference (the Rust rendering of the C# `IILVisitor` dispatch).
pub fn visit(body: &ResolvedBody, v: &mut dyn FnMut(usize, &RInstruction)) {
    for (idx, ins) in body.instructions.iter().enumerate() {
        v(idx, ins);
    }
}

/// Collects every branch destination referenced by the body: absolute
/// `br`/`br.s`/leave-style targets plus all switch arms, sorted ascending
/// with duplicates removed.
pub fn collect_branch_targets(body: &ResolvedBody) -> Vec<i32> {
    let mut targets = Vec::new();
    visit(body, &mut |_idx, ins| match &ins.operand {
        ROperand::Branch(t) => targets.push(*t),
        ROperand::Switch(ts) => targets.extend_from_slice(ts),
        _ => {}
    });
    targets.sort_unstable();
    targets.dedup();
    targets
}

/// Returns the index of the instruction starting exactly at `offset`
/// (binary search; bodies keep instructions ordered by offset).
pub fn find_by_offset(body: &ResolvedBody, offset: i32) -> Option<usize> {
    body.instructions.binary_search_by(|ins| ins.offset.cmp(&offset)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cecli::model::types::{ExceptionKind, LocalVariable};
    use cecli_cil::opcodes;

    fn ins(offset: i32, opcode: OpCode, operand: ROperand) -> RInstruction {
        RInstruction { offset, opcode, operand }
    }

    /// Layout:
    /// `nop@0 | ldc.i4.s 42@1 | stloc.0@3 | br.s ->10@4 | ret@6 |
    ///  switch(20,12)@7..19 | ldloc.0@20 | ret@21`, code size 22.
    fn ok_body() -> ResolvedBody {
        ResolvedBody {
            max_stack: 1,
            init_locals: true,
            local_var_sig_tok: cecli_core::Token(0x11000001),
            locals: vec![LocalVariable {
                index: 0,
                ty: cecli::model::types::TypeDesc::TypedByRef,
                pinned: false,
            }],
            instructions: vec![
                ins(0, opcodes::NOP, ROperand::None),
                ins(1, opcodes::LDC_I4_S, ROperand::Int8(42)),
                ins(3, opcodes::STLOC_0, ROperand::None),
                ins(4, opcodes::BR_S, ROperand::Branch(10)),
                ins(6, opcodes::RET, ROperand::None),
                // switch with two arms, encoded at offset 7:
                // 1 byte opcode + 4 byte count + 2*4 targets = 13 bytes.
                ins(7, opcodes::SWITCH, ROperand::Switch(vec![20, 12])),
                ins(20, opcodes::LDLOC_0, ROperand::None),
                ins(21, opcodes::RET, ROperand::None),
            ],
            exception_handlers: Vec::new(),
        }
    }

    #[test]
    fn valid_body_passes() {
        let body = ok_body();
        assert_eq!(code_size(&body), 22);
        validate_body(&body).expect("body is well formed");
    }

    #[test]
    fn wrong_operand_kind_is_rejected() {
        // ldc.i4.s demands Int8 (ShortInlineI); carrying None is malformed.
        let mut body = ok_body();
        body.instructions[1].operand = ROperand::None;
        let err = validate_body(&body).unwrap_err().to_string();
        assert!(err.contains("ldc.i4.s"), "message names opcode: {err}");
    }

    #[test]
    fn branch_outside_code_is_rejected() {
        let mut body = ok_body();
        body.instructions[3].operand = ROperand::Branch(-1);
        assert!(validate_body(&body).is_err());

        let mut body = ok_body();
        body.instructions[3].operand = ROperand::Branch(999);
        assert!(validate_body(&body).is_err());
    }

    /// Zero-local body exercising the argument opcodes:
    /// `ldarg.s 0@0` (2 bytes) | `ret@2`.
    fn arg_body() -> ResolvedBody {
        ResolvedBody {
            locals: Vec::new(),
            instructions: vec![
                ins(0, opcodes::LDARG_S, ROperand::Var(0)),
                ins(2, opcodes::RET, ROperand::None),
            ],
            ..Default::default()
        }
    }

    #[test]
    fn ldarg_on_zero_local_method_passes_with_parameter_count() {
        let body = arg_body();
        // The macro `ldarg.0` carries no operand and always passes.
        validate_body_for(&body, 1).expect("one parameter slot covers ldarg.0/ldarg.s 0");
    }

    #[test]
    fn arg_indices_validate_against_supplied_parameter_count() {
        let mut body = arg_body();
        assert!(
            validate_body_for(&body, 0).is_err(),
            "ldarg.s 0 needs at least one parameter slot"
        );
        body.instructions[0].operand = ROperand::Var(3);
        assert!(validate_body_for(&body, 4).is_ok());
        assert!(validate_body_for(&body, 3).is_err());
    }

    #[test]
    fn validate_body_without_provider_skips_arg_range_check() {
        let body = arg_body();
        // No parameter count is known here; well-shaped args must pass.
        validate_body(&body).expect("argument indices are unchecked without a provider");
    }

    #[test]
    fn local_indices_still_validate_without_parameter_count() {
        // stloc.s into a nonexistent local stays an error even though the
        // wrapper passes usize::MAX as the parameter count.
        let mut body = ok_body();
        body.instructions[6].opcode = opcodes::STLOC_S;
        body.instructions[6].operand = ROperand::Var(9); // only 1 local
        assert!(validate_body(&body).is_err());
        assert!(validate_body_for(&body, usize::MAX).is_err());
    }

    #[test]
    fn switch_arm_outside_code_is_rejected() {
        let mut body = ok_body();
        body.instructions[5].operand = ROperand::Switch(vec![20, 23]);
        assert!(validate_body(&body).is_err());
    }

    #[test]
    fn variable_index_must_exist() {
        let mut body = ok_body();
        body.instructions[6].opcode = opcodes::LDLOC_S;
        body.instructions[6].operand = ROperand::Var(1); // only 1 local
        assert!(validate_body(&body).is_err());
        assert_eq!(find_by_offset(&body, 20), Some(6));
    }

    #[test]
    fn exception_ranges_must_stay_inside_code() {
        let mut body = ok_body();
        body.exception_handlers.push(ExceptionHandlerIL {
            kind: ExceptionKind::Catch,
            try_offset: 0,
            try_length: 22,
            filter_offset: 0,
            handler_offset: 0,
            handler_length: 22,
            catch_type: None,
        });
        validate_body(&body).expect("ranges exactly cover the code");

        body.exception_handlers[0].handler_length = 23;
        assert!(validate_body(&body).is_err());
    }

    #[test]
    fn branch_collection_includes_switch_arms_sorted_unique() {
        let body = ok_body();
        assert_eq!(collect_branch_targets(&body), vec![10, 12, 20]);
    }

    #[test]
    fn visit_walks_all_instructions_with_indices() {
        let body = ok_body();
        let mut seen = Vec::new();
        visit(&body, &mut |idx, i| seen.push((idx, i.offset)));
        assert_eq!(seen, vec![(0, 0), (1, 1), (2, 3), (3, 4), (4, 6), (5, 7), (6, 20), (7, 21)]);
    }

    #[test]
    fn find_by_offset_hits_and_misses() {
        let body = ok_body();
        assert_eq!(find_by_offset(&body, 0), Some(0));
        assert_eq!(find_by_offset(&body, 7), Some(5));
        assert_eq!(find_by_offset(&body, 8), None);
        assert_eq!(find_by_offset(&body, 21), Some(7));
    }

    #[test]
    fn empty_and_overlapping_bodies() {
        assert_eq!(code_size(&ResolvedBody::default()), 0);
        assert!(validate_body(&ResolvedBody::default()).is_ok());

        let mut body = ok_body();
        body.instructions[2].offset = 0; // overlaps nop
        assert!(validate_body(&body).is_err());
    }
}
