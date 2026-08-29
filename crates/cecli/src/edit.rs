//! IL body editing, macro simplification and macro optimization.
//!
//! Ports the editing surface of `Mono.Cecil.Cil/ILProcessor.cs` together with
//! the `SimplifyMacros` / `OptimizeMacros` passes of
//! `Mono.Cecil.Rocks/MethodBodyRocks.cs` onto the owned [`ResolvedBody`] model.
//!
//! # Design notes / documented deviations
//!
//! * The frozen model stores branch and switch targets as *absolute* `i32`
//!   IL offsets instead of `Instruction` references. Every resizing operation
//!   (insertion, removal, replacement, opcode rewrite) therefore remaps
//!   affected targets by the same byte delta applied to the layout, and
//!   [`renumber`] recomputes all offsets from the current instruction sizes
//!   while translating targets recorded against the previous layout.
//! * Argument/local operands are raw slot indices ([`ROperand::Var`]) that
//!   already include the `this` slot adjustment. `OptimizeMacros` therefore
//!   consumes the encoded index directly instead of re-deriving it from
//!   `ParameterDefinition.Index` plus the `HasThis` offset like the original.
//! * Removing instructions whose span a branch target points into leaves that
//!   target dangling - exactly like Mono.Cecil, where the referenced
//!   `Instruction` object is simply gone.
//! * `renumber` can only translate targets when the instruction sequence
//!   itself is unchanged (macro passes, operand rewrites); structural edits go
//!   through [`BodyEditor`], which maintains targets incrementally.
//! * `ILProcessor.Clear` only clears the instruction list; exception handler
//!   clauses (which reference IL offsets) are preserved, matching Cecil.

use std::collections::HashMap;
use std::ops::Range;

use cecli_cil::opcode_table as op;
use cecli_cil::{Code, OpCode, OperandType};
use cecli_core::Token;

use crate::model::types::{
    FieldId, FieldRef, MethodId, MethodRef, RInstruction, ROperand, ResolvedBody,
};
use crate::Module;
use cecli_core::{Error, Result};

// ---------------------------------------------------------------------------
// Offset / target maintenance
// ---------------------------------------------------------------------------

/// Encoded byte length of one resolved instruction (switch tables included).
fn encoded_size(instr: &RInstruction) -> usize {
    match &instr.operand {
        ROperand::Switch(targets) => instr.opcode.size as usize + 4 * (targets.len() + 1),
        _ => cecli_cil::instruction_size(instr.opcode),
    }
}

/// Reassigns every instruction offset sequentially from the encoded sizes.
fn recompute_offsets(body: &mut ResolvedBody) {
    let mut offset = 0i32;
    for instr in &mut body.instructions {
        instr.offset = offset;
        offset += encoded_size(instr) as i32;
    }
}

/// Shifts every branch/switch target at or after `from` by `delta` bytes.
///
/// `from` is a byte position between instructions; a target exactly on a
/// boundary at or past `from` belongs to the shifted tail of the body. When
/// `skip` is `Some(index)`, the instruction at that position keeps its
/// operand untouched (used when the moved instruction carries a freshly
/// authored operand of its own).
fn shift_targets(body: &mut ResolvedBody, from: i32, delta: i32, skip: Option<usize>) {
    if delta == 0 {
        return;
    }
    for (index, instr) in body.instructions.iter_mut().enumerate() {
        if skip == Some(index) {
            continue;
        }
        match &mut instr.operand {
            ROperand::Branch(target) => {
                if *target >= from {
                    *target += delta;
                }
            }
            ROperand::Switch(targets) => {
                for target in targets.iter_mut() {
                    if *target >= from {
                        *target += delta;
                    }
                }
            }
            _ => {}
        }
    }
}

/// Recomputes instruction offsets from the current instruction order and
/// sizes, fixing absolute branch/switch targets along the way.
///
/// Before rewriting the offsets, the previous layout is snapshotted. When the
/// instruction sequence is unchanged (the common case after operand/macro
/// rewrites), every old boundary is positionally paired with its instruction
/// and each branch/switch target recorded against the previous layout is
/// remapped to the new offset of the instruction it landed on; a target at
/// the previous end-of-body position follows the end of the body. When the
/// sequence changed (structural edits), only the end-of-body anchor is
/// translated - use [`BodyEditor`] for structural edits, which keeps targets
/// consistent incrementally. The pass is idempotent on an already-consistent
/// body.
pub fn renumber(body: &mut ResolvedBody) {
    let old_offsets: Vec<i32> = body.instructions.iter().map(|i| i.offset).collect();
    let old_end =
        body.instructions.last().map_or(0, |last| last.offset + encoded_size(last) as i32);

    let mut offset = 0i32;
    for instr in &mut body.instructions {
        instr.offset = offset;
        offset += encoded_size(instr) as i32;
    }
    let new_end = offset;

    let mut map: HashMap<i32, i32> = HashMap::with_capacity(old_offsets.len() + 1);
    if old_offsets.len() == body.instructions.len() {
        for (old, instr) in old_offsets.iter().zip(body.instructions.iter()) {
            map.entry(*old).or_insert(instr.offset);
        }
    }
    map.insert(old_end, new_end);

    for instr in &mut body.instructions {
        match &mut instr.operand {
            ROperand::Branch(target) => {
                if let Some(new) = map.get(target) {
                    *target = *new;
                }
            }
            ROperand::Switch(targets) => {
                for target in targets.iter_mut() {
                    if let Some(new) = map.get(target) {
                        *target = *new;
                    }
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// BodyEditor
// ---------------------------------------------------------------------------

/// Editing surface over one borrowed [`ResolvedBody`].
///
/// Mirrors `Mono.Cecil.Cil/ILProcessor.cs`: indexed insertion/removal/
/// replacement plus emit helpers. All mutations keep instruction offsets and
/// absolute branch/switch targets consistent, so a body remains encodable at
/// any point. A freshly inserted or replaced instruction keeps its own branch
/// operand verbatim (it was authored against the caller's intended layout);
/// every other target at or past the edited byte position follows the layout.
pub struct BodyEditor<'a> {
    body: &'a mut ResolvedBody,
}

impl<'a> BodyEditor<'a> {
    /// Opens an editor over `body`.
    pub fn new(body: &'a mut ResolvedBody) -> Self {
        BodyEditor { body }
    }

    /// Borrows the underlying body back.
    pub fn body(&mut self) -> &mut ResolvedBody {
        self.body
    }

    // -- factories ----------------------------------------------------------

    /// Creates a no-operand instruction (`offset` is assigned on insertion).
    pub fn create(opcode: OpCode) -> RInstruction {
        RInstruction { offset: 0, opcode, operand: ROperand::None }
    }

    /// Creates `ldc.i4 <value>` (long form; see [`BodyEditor::ldc_i4`] for the
    /// smart opcode pick).
    pub fn create_i32(value: i32) -> RInstruction {
        RInstruction { offset: 0, opcode: op::LDC_I4, operand: ROperand::Int32(value) }
    }

    /// Creates `ldc.i8 <value>`.
    pub fn create_i64(value: i64) -> RInstruction {
        RInstruction { offset: 0, opcode: op::LDC_I8, operand: ROperand::Int64(value) }
    }

    /// Creates `ldc.r4 <value>`.
    pub fn create_r32(value: f32) -> RInstruction {
        RInstruction { offset: 0, opcode: op::LDC_R4, operand: ROperand::Float32(value) }
    }

    /// Creates `ldc.r8 <value>`.
    pub fn create_r64(value: f64) -> RInstruction {
        RInstruction { offset: 0, opcode: op::LDC_R8, operand: ROperand::Float64(value) }
    }

    /// Creates an unconditional branch (long form) to the absolute IL offset
    /// `target`; [`optimize_macros`] shortens it when possible.
    pub fn create_branch(target: i32) -> RInstruction {
        RInstruction { offset: 0, opcode: op::BR, operand: ROperand::Branch(target) }
    }

    /// Creates a jump-table `switch` over absolute target IL offsets.
    pub fn create_switch(targets: Vec<i32>) -> RInstruction {
        RInstruction { offset: 0, opcode: op::SWITCH, operand: ROperand::Switch(targets) }
    }

    /// Creates an instruction carrying a raw metadata token operand.
    pub fn create_token(opcode: OpCode, token: Token) -> RInstruction {
        RInstruction { offset: 0, opcode, operand: ROperand::Token(token) }
    }

    // -- mutation -----------------------------------------------------------

    /// Recomputes instruction offsets only (targets are maintained by the
    /// individual mutations).
    fn relayout(&mut self) {
        recompute_offsets(self.body);
    }

    /// Appends `instr` at the end of the body.
    fn append(&mut self, instr: RInstruction) -> &mut Self {
        let index = self.body.instructions.len();
        self.insert_at(index, &instr);
        self
    }

    /// Inserts `instr` at `index` (the current occupant of `index` moves
    /// behind it). `index == len` appends.
    ///
    /// Existing branch/switch targets at or after the insertion byte position
    /// are shifted by the inserted instruction's encoded size.
    pub fn insert_at(&mut self, index: usize, instr: &RInstruction) {
        let len = self.body.instructions.len();
        let size = encoded_size(instr) as i32;
        let pos = if index < len {
            self.body.instructions[index].offset
        } else {
            self.body.instructions.last().map_or(0, |last| last.offset + encoded_size(last) as i32)
        };
        let at = index.min(len);
        self.body.instructions.insert(at, instr.clone());
        shift_targets(self.body, pos, size, Some(at));
        self.relayout();
    }

    /// Inserts `instr` immediately before the instruction at `index`.
    pub fn insert_before(&mut self, index: usize, instr: &RInstruction) {
        self.insert_at(index, instr);
    }

    /// Inserts `instr` immediately after the instruction at `index`.
    pub fn insert_after(&mut self, index: usize, instr: &RInstruction) {
        self.insert_at(index + 1, instr);
    }

    /// Replaces the instruction at `index`, shifting every other branch/switch
    /// target by the encoded-size difference.
    pub fn replace(&mut self, index: usize, instr: RInstruction) {
        let old_size = encoded_size(&self.body.instructions[index]) as i32;
        let new_size = encoded_size(&instr) as i32;
        let pos_after = self.body.instructions[index].offset + old_size;
        self.body.instructions[index] = instr;
        if new_size != old_size {
            shift_targets(self.body, pos_after, new_size - old_size, Some(index));
            self.relayout();
        }
    }

    /// Removes the instruction at `index`.
    pub fn remove(&mut self, index: usize) {
        self.remove_range(index..index + 1);
    }

    /// Removes the instructions in `range`.
    ///
    /// Surviving targets at or after the end of the removed byte span slide
    /// down by the removed size; targets pointing strictly inside the removed
    /// span dangle (the instruction they referenced no longer exists).
    pub fn remove_range(&mut self, range: Range<usize>) {
        let len = self.body.instructions.len();
        if range.start >= range.end || range.start >= len {
            return;
        }
        let end = range.end.min(len);
        let start_pos = self.body.instructions[range.start].offset;
        let removed: i32 =
            self.body.instructions[range.start..end].iter().map(|i| encoded_size(i) as i32).sum();
        self.body.instructions.drain(range.start..end);
        shift_targets(self.body, start_pos + removed, -removed, None);
        self.relayout();
    }

    /// Removes every instruction (exception clauses are preserved).
    pub fn clear(&mut self) {
        self.body.instructions.clear();
    }

    // -- emit helpers -------------------------------------------------------

    /// Emits a constant load picking the smallest deterministic opcode:
    /// `ldc.i4.m1` / `ldc.i4.0`..`ldc.i4.8` for the magic values, `ldc.i4.s`
    /// for `-128..=127`, otherwise the long `ldc.i4` form.
    pub fn ldc_i4(&mut self, value: i32) -> &mut Self {
        let instr = match value {
            -1 => Self::create(op::LDC_I4_M1),
            0..=8 => Self::create(
                [
                    op::LDC_I4_0,
                    op::LDC_I4_1,
                    op::LDC_I4_2,
                    op::LDC_I4_3,
                    op::LDC_I4_4,
                    op::LDC_I4_5,
                    op::LDC_I4_6,
                    op::LDC_I4_7,
                    op::LDC_I4_8,
                ][value as usize],
            ),
            -128..=127 => RInstruction {
                offset: 0,
                opcode: op::LDC_I4_S,
                operand: ROperand::Int8(value as i8),
            },
            _ => Self::create_i32(value),
        };
        self.append(instr)
    }

    /// Emits `call <method>`; the reference is stored unresolved and mapped to
    /// a metadata token by the writer.
    pub fn call(&mut self, method: MethodRef) -> &mut Self {
        self.append(RInstruction { offset: 0, opcode: op::CALL, operand: ROperand::Method(method) })
    }

    /// Emits an unconditional branch (long form) to the absolute IL offset
    /// `target`.
    pub fn br(&mut self, target: i32) -> &mut Self {
        self.append(Self::create_branch(target))
    }

    /// Emits `ret`.
    pub fn ret(&mut self) -> &mut Self {
        self.append(Self::create(op::RET))
    }
}

// ---------------------------------------------------------------------------
// SimplifyMacros (Mono.Cecil.Rocks/MethodBodyRocks.cs)
// ---------------------------------------------------------------------------

/// Replaces opcode and operand of a macro expansion.
fn expand_macro(instr: &mut RInstruction, opcode: OpCode, operand: ROperand) {
    instr.opcode = opcode;
    instr.operand = operand;
}

/// Collapses an instruction into a no-operand macro.
fn make_macro(instr: &mut RInstruction, opcode: OpCode) {
    instr.opcode = opcode;
    instr.operand = ROperand::None;
}

/// Expands all macro instructions into long form; see [`simplify_macros`].
fn simplify_instructions(body: &mut ResolvedBody) {
    for instr in &mut body.instructions {
        match instr.opcode.code {
            Code::Ldarg_0 => expand_macro(instr, op::LDARG, ROperand::Var(0)),
            Code::Ldarg_1 => expand_macro(instr, op::LDARG, ROperand::Var(1)),
            Code::Ldarg_2 => expand_macro(instr, op::LDARG, ROperand::Var(2)),
            Code::Ldarg_3 => expand_macro(instr, op::LDARG, ROperand::Var(3)),
            Code::Ldloc_0 => expand_macro(instr, op::LDLOC, ROperand::Var(0)),
            Code::Ldloc_1 => expand_macro(instr, op::LDLOC, ROperand::Var(1)),
            Code::Ldloc_2 => expand_macro(instr, op::LDLOC, ROperand::Var(2)),
            Code::Ldloc_3 => expand_macro(instr, op::LDLOC, ROperand::Var(3)),
            Code::Stloc_0 => expand_macro(instr, op::STLOC, ROperand::Var(0)),
            Code::Stloc_1 => expand_macro(instr, op::STLOC, ROperand::Var(1)),
            Code::Stloc_2 => expand_macro(instr, op::STLOC, ROperand::Var(2)),
            Code::Stloc_3 => expand_macro(instr, op::STLOC, ROperand::Var(3)),
            Code::Ldarg_S => instr.opcode = op::LDARG,
            Code::Ldarga_S => instr.opcode = op::LDARGA,
            Code::Starg_S => instr.opcode = op::STARG,
            Code::Ldloc_S => instr.opcode = op::LDLOC,
            Code::Ldloca_S => instr.opcode = op::LDLOCA,
            Code::Stloc_S => instr.opcode = op::STLOC,
            Code::Ldc_I4_M1 => expand_macro(instr, op::LDC_I4, ROperand::Int32(-1)),
            Code::Ldc_I4_0 => expand_macro(instr, op::LDC_I4, ROperand::Int32(0)),
            Code::Ldc_I4_1 => expand_macro(instr, op::LDC_I4, ROperand::Int32(1)),
            Code::Ldc_I4_2 => expand_macro(instr, op::LDC_I4, ROperand::Int32(2)),
            Code::Ldc_I4_3 => expand_macro(instr, op::LDC_I4, ROperand::Int32(3)),
            Code::Ldc_I4_4 => expand_macro(instr, op::LDC_I4, ROperand::Int32(4)),
            Code::Ldc_I4_5 => expand_macro(instr, op::LDC_I4, ROperand::Int32(5)),
            Code::Ldc_I4_6 => expand_macro(instr, op::LDC_I4, ROperand::Int32(6)),
            Code::Ldc_I4_7 => expand_macro(instr, op::LDC_I4, ROperand::Int32(7)),
            Code::Ldc_I4_8 => expand_macro(instr, op::LDC_I4, ROperand::Int32(8)),
            Code::Ldc_I4_S => {
                if let ROperand::Int8(value) = instr.operand {
                    expand_macro(instr, op::LDC_I4, ROperand::Int32(value as i32));
                }
            }
            Code::Br_S => instr.opcode = op::BR,
            Code::Brfalse_S => instr.opcode = op::BRFALSE,
            Code::Brtrue_S => instr.opcode = op::BRTRUE,
            Code::Beq_S => instr.opcode = op::BEQ,
            Code::Bge_S => instr.opcode = op::BGE,
            Code::Bgt_S => instr.opcode = op::BGT,
            Code::Ble_S => instr.opcode = op::BLE,
            Code::Blt_S => instr.opcode = op::BLT,
            Code::Bne_Un_S => instr.opcode = op::BNE_UN,
            Code::Bge_Un_S => instr.opcode = op::BGE_UN,
            Code::Bgt_Un_S => instr.opcode = op::BGT_UN,
            Code::Ble_Un_S => instr.opcode = op::BLE_UN,
            Code::Blt_Un_S => instr.opcode = op::BLT_UN,
            Code::Leave_S => instr.opcode = op::LEAVE,
            _ => {}
        }
    }
}

/// Expands every macro instruction into its long-form equivalent and
/// recomputes offsets / branch targets.
///
/// Port of `MethodBodyRocks.SimplifyMacros`: `ldarg.0`..`ldarg.3`,
/// `ldloc.0`..`ldloc.3`, `stloc.0`..`stloc.3`, `ldc.i4.m1`..`ldc.i4.8` and
/// `ldc.i4.s` grow into `ldarg`/`ldloc`/`stloc`/`ldc.i4`; the short `_S`
/// forms (`ldarg.s`, `ldarga.s`, `starg.s`, `ldloc.s`, `ldloca.s`,
/// `stloc.s`) and the short branch/`leave` forms grow into their long
/// counterparts.
pub fn simplify_macros(body: &mut ResolvedBody) {
    simplify_instructions(body);
    renumber(body);
}

// ---------------------------------------------------------------------------
// OptimizeMacros (Mono.Cecil.Rocks/MethodBodyRocks.cs)
// ---------------------------------------------------------------------------

/// Raw slot index of a variable-style operand, if any.
fn var_index(operand: &ROperand) -> Option<u16> {
    match operand {
        ROperand::Var(index) => Some(*index),
        _ => None,
    }
}

/// Collapses long forms into the smallest macro instructions; see
/// [`optimize_macros`].
fn optimize_instructions(body: &mut ResolvedBody) {
    for instr in &mut body.instructions {
        match instr.opcode.code {
            Code::Ldarg => match var_index(&instr.operand) {
                Some(0) => make_macro(instr, op::LDARG_0),
                Some(1) => make_macro(instr, op::LDARG_1),
                Some(2) => make_macro(instr, op::LDARG_2),
                Some(3) => make_macro(instr, op::LDARG_3),
                Some(index) if index < 256 => instr.opcode = op::LDARG_S,
                _ => {}
            },
            Code::Ldloc => match var_index(&instr.operand) {
                Some(0) => make_macro(instr, op::LDLOC_0),
                Some(1) => make_macro(instr, op::LDLOC_1),
                Some(2) => make_macro(instr, op::LDLOC_2),
                Some(3) => make_macro(instr, op::LDLOC_3),
                Some(index) if index < 256 => instr.opcode = op::LDLOC_S,
                _ => {}
            },
            Code::Stloc => match var_index(&instr.operand) {
                Some(0) => make_macro(instr, op::STLOC_0),
                Some(1) => make_macro(instr, op::STLOC_1),
                Some(2) => make_macro(instr, op::STLOC_2),
                Some(3) => make_macro(instr, op::STLOC_3),
                Some(index) if index < 256 => instr.opcode = op::STLOC_S,
                _ => {}
            },
            Code::Ldarga => {
                if matches!(var_index(&instr.operand), Some(index) if index < 256) {
                    instr.opcode = op::LDARGA_S;
                }
            }
            Code::Ldloca => {
                if matches!(var_index(&instr.operand), Some(index) if index < 256) {
                    instr.opcode = op::LDLOCA_S;
                }
            }
            Code::Ldc_I4 => {
                if let ROperand::Int32(value) = instr.operand {
                    match value {
                        -1 => make_macro(instr, op::LDC_I4_M1),
                        0 => make_macro(instr, op::LDC_I4_0),
                        1 => make_macro(instr, op::LDC_I4_1),
                        2 => make_macro(instr, op::LDC_I4_2),
                        3 => make_macro(instr, op::LDC_I4_3),
                        4 => make_macro(instr, op::LDC_I4_4),
                        5 => make_macro(instr, op::LDC_I4_5),
                        6 => make_macro(instr, op::LDC_I4_6),
                        7 => make_macro(instr, op::LDC_I4_7),
                        8 => make_macro(instr, op::LDC_I4_8),
                        -128..=127 => {
                            instr.opcode = op::LDC_I4_S;
                            instr.operand = ROperand::Int8(value as i8);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}

/// Short `_S` counterpart of a long branch opcode, if one exists.
fn short_branch(code: Code) -> Option<OpCode> {
    Some(match code {
        Code::Br => op::BR_S,
        Code::Brfalse => op::BRFALSE_S,
        Code::Brtrue => op::BRTRUE_S,
        Code::Beq => op::BEQ_S,
        Code::Bge => op::BGE_S,
        Code::Bgt => op::BGT_S,
        Code::Ble => op::BLE_S,
        Code::Blt => op::BLT_S,
        Code::Bne_Un => op::BNE_UN_S,
        Code::Bge_Un => op::BGE_UN_S,
        Code::Bgt_Un => op::BGT_UN_S,
        Code::Ble_Un => op::BLE_UN_S,
        Code::Blt_Un => op::BLT_UN_S,
        Code::Leave => op::LEAVE_S,
        _ => return None,
    })
}

/// Port of `MethodBodyRocks.OptimizeBranches`: walks inline branch targets in
/// order, switching each to its short form while the displacement fits a
/// signed byte, recomputing offsets (and remapping absolute targets) after
/// every successful shrink.
fn optimize_branches(body: &mut ResolvedBody) {
    renumber(body);

    let mut index = 0;
    while index < body.instructions.len() {
        let (opcode, target, offset) = {
            let instr = &body.instructions[index];
            let target = match instr.operand {
                ROperand::Branch(target) => target,
                _ => {
                    index += 1;
                    continue;
                }
            };
            (instr.opcode, target, instr.offset)
        };
        if opcode.operand_type != OperandType::InlineBrTarget {
            index += 1;
            continue;
        }
        // Displacement of the long (5-byte) form.
        let displacement = target - (offset + opcode.size as i32 + 4);
        if !(-128..=127).contains(&displacement) {
            index += 1;
            continue;
        }
        let short = match short_branch(opcode.code) {
            Some(short) => short,
            None => {
                index += 1;
                continue;
            }
        };

        // Shrinking saves exactly 3 bytes; every boundary at or after this
        // instruction's end slides up - including this branch's own target
        // when it points forward.
        let pos_after = offset + opcode.size as i32 + 4;
        body.instructions[index].opcode = short;
        shift_targets(body, pos_after, -3, None);
        recompute_offsets(body);
        index += 1;
    }
}

/// Collapses long-form instructions into the smallest equivalent macros and
/// shortens branches whose displacement fits a signed byte.
///
/// Port of `MethodBodyRocks.OptimizeMacros`: `ldarg`/`ldloc`/`stloc` with slot
/// `0..3` become the no-operand macros, slot `< 256` becomes the `_S` form;
/// `ldarga`/`ldloca` shrink to `_S` below 256; `ldc.i4` collapses to
/// `ldc.i4.m1`/`ldc.i4.0`..`ldc.i4.8`, then `ldc.i4.s` for `-128..=127`;
/// finally the branch-shortening pass runs.
pub fn optimize_macros(body: &mut ResolvedBody) {
    optimize_instructions(body);
    optimize_branches(body);
}

/// Port of `MethodBodyRocks.Optimize`: narrows representable `ldc.i8`
/// constants (`optimize_longs`) and then runs the full
/// [`optimize_macros`] pipeline.
pub fn optimize(body: &mut ResolvedBody) {
    optimize_longs(body);
    optimize_macros(body);
}

/// Port of `MethodBodyRocks.OptimizeLongs`: an `ldc.i8` whose value fits
/// strictly inside the `i32` range (the boundaries themselves are kept as
/// `ldc.i8`) becomes a 32-bit load followed by an inserted `conv.i8`.
fn optimize_longs(body: &mut ResolvedBody) {
    let mut index = 0;
    while index < body.instructions.len() {
        let value = match body.instructions[index].operand {
            ROperand::Int64(value) if body.instructions[index].opcode.code == Code::Ldc_I8 => value,
            _ => {
                index += 1;
                continue;
            }
        };
        // C# keeps l >= int.MaxValue || l <= int.MinValue wide.
        if value >= i32::MAX as i64 || value <= i32::MIN as i64 {
            index += 1;
            continue;
        }

        let old_end =
            body.instructions[index].offset + encoded_size(&body.instructions[index]) as i32;
        let instr = &mut body.instructions[index];
        instr.opcode = op::LDC_I4;
        instr.operand = ROperand::Int32(value as i32);
        // The narrowed load is 4 bytes shorter; everything after it slides.
        shift_targets(body, old_end, -4, Some(index));
        // Insert conv.i8 right behind the load (one byte back).
        let pos = old_end - 4;
        body.instructions.insert(
            index + 1,
            RInstruction { offset: 0, opcode: op::CONV_I8, operand: ROperand::None },
        );
        shift_targets(body, pos, 1, Some(index + 1));
        recompute_offsets(body);
        index += 2;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{LocalVariable, TypeDesc};

    fn make_body(instructions: Vec<RInstruction>) -> ResolvedBody {
        ResolvedBody { instructions, ..Default::default() }
    }

    fn instr(offset: i32, opcode: OpCode, operand: ROperand) -> RInstruction {
        RInstruction { offset, opcode, operand }
    }

    fn local(index: u16) -> LocalVariable {
        LocalVariable { index, ty: TypeDesc::Internal("int32".into()), pinned: false }
    }

    fn nop() -> RInstruction {
        BodyEditor::create(op::NOP)
    }

    #[test]
    fn renumber_recomputes_offsets_and_fixes_stale_targets() {
        // Long-form body laid out as:
        // ldc.i4 5 (5); stloc 0 (4); ldloc 0 (4); br -> ret (5); ret (1)
        let mut b = make_body(vec![
            instr(0, op::LDC_I4, ROperand::Int32(5)),
            instr(5, op::STLOC, ROperand::Var(0)),
            instr(9, op::LDLOC, ROperand::Var(0)),
            instr(13, op::BR, ROperand::Branch(18)),
            instr(18, op::RET, ROperand::None),
        ]);
        // Simulate an external operand rewrite: swap the load for a 1-byte
        // macro without touching offsets or targets.
        b.instructions[0].opcode = op::LDC_I4_5;
        renumber(&mut b);

        let offsets: Vec<i32> = b.instructions.iter().map(|i| i.offset).collect();
        assert_eq!(offsets, [0, 1, 5, 9, 14]);
        assert_eq!(b.instructions[3].operand, ROperand::Branch(14));
        assert_eq!(b.instructions[4].offset, 14);
    }

    #[test]
    fn renumber_translates_switch_targets() {
        // switch with two targets (13 bytes); nop; nop; ret.
        let mut b = make_body(vec![
            instr(0, op::SWITCH, ROperand::Switch(vec![13, 15])),
            instr(13, op::NOP, ROperand::None),
            instr(14, op::NOP, ROperand::None),
            instr(15, op::RET, ROperand::None),
        ]);
        // External rewrite: drop one switch target (raw operand assignment,
        // offsets and targets left stale).
        b.instructions[0].operand = ROperand::Switch(vec![13]);
        renumber(&mut b);

        // switch shrinks 13 -> 9 bytes, sliding the tail up by 4; the target
        // 13 (first nop) follows its instruction to offset 9.
        assert_eq!(b.instructions[0].operand, ROperand::Switch(vec![9]));
        let offsets: Vec<i32> = b.instructions.iter().map(|i| i.offset).collect();
        assert_eq!(offsets, [0, 9, 10, 11]);
    }

    #[test]
    fn edit_then_renumber_keeps_branch_targets_valid() {
        // 0: nop; 1: br -> 7 (ret); 6: nop; 7: ret
        let mut b = make_body(vec![
            instr(0, op::NOP, ROperand::None),
            instr(1, op::BR, ROperand::Branch(7)),
            instr(6, op::NOP, ROperand::None),
            instr(7, op::RET, ROperand::None),
        ]);

        // Long-constant insertion before the branch target: target slides 5.
        {
            let mut editor = BodyEditor::new(&mut b);
            editor.insert_before(2, &BodyEditor::create_i32(42));
        }
        assert_eq!(b.instructions[1].operand, ROperand::Branch(12));
        assert_eq!(b.instructions.last().unwrap().opcode, op::RET);
        assert_eq!(b.instructions.last().unwrap().offset, 12);

        // 150 single-byte insertions between the branch and its target.
        {
            let mut editor = BodyEditor::new(&mut b);
            for _ in 0..150 {
                editor.insert_before(3, &nop());
            }
        }
        assert_eq!(b.instructions[1].operand, ROperand::Branch(162));
        assert_eq!(b.instructions.last().unwrap().offset, 162);

        // Removing them again restores the layout and the target.
        {
            let mut editor = BodyEditor::new(&mut b);
            editor.remove_range(3..153);
        }
        assert_eq!(b.instructions[1].operand, ROperand::Branch(12));
        assert_eq!(b.instructions.last().unwrap().offset, 12);
    }

    #[test]
    fn replace_and_remove_keep_targets_consistent() {
        // 0: ldc.i4 1000 (5 bytes); 5: br -> 10; 10: ret
        let mut b = make_body(vec![
            instr(0, op::LDC_I4, ROperand::Int32(1000)),
            instr(5, op::BR, ROperand::Branch(10)),
            instr(10, op::RET, ROperand::None),
        ]);
        {
            let mut editor = BodyEditor::new(&mut b);
            // Replace the 5-byte load with a 1-byte nop: target slides down 4.
            editor.replace(0, nop());
        }
        assert_eq!(b.instructions[1].operand, ROperand::Branch(6));
        assert_eq!(b.instructions.last().unwrap().offset, 6);

        {
            // Remove the branch; the remaining body stays consistent.
            let mut editor = BodyEditor::new(&mut b);
            editor.remove(1);
        }
        assert_eq!(b.instructions.len(), 2);
        assert_eq!(b.instructions[1].offset, 1);
    }

    #[test]
    fn ldc_i4_picks_the_smallest_opcode() {
        let mut b = make_body(Vec::new());
        let mut editor = BodyEditor::new(&mut b);
        editor.ldc_i4(-1);
        editor.ldc_i4(0);
        editor.ldc_i4(5);
        editor.ldc_i4(8);
        editor.ldc_i4(42);
        editor.ldc_i4(127);
        editor.ldc_i4(-128);
        editor.ldc_i4(128);
        editor.ret();

        let codes: Vec<Code> = b.instructions.iter().map(|i| i.opcode.code).collect();
        assert_eq!(
            codes,
            [
                Code::Ldc_I4_M1,
                Code::Ldc_I4_0,
                Code::Ldc_I4_5,
                Code::Ldc_I4_8,
                Code::Ldc_I4_S,
                Code::Ldc_I4_S,
                Code::Ldc_I4_S,
                Code::Ldc_I4,
                Code::Ret,
            ]
        );
        assert_eq!(b.instructions[4].operand, ROperand::Int8(42));
        assert_eq!(b.instructions[7].operand, ROperand::Int32(128));
    }

    #[test]
    fn optimize_collapses_ldc_i4_5_to_ldc_i4_5_macro() {
        let mut b = make_body(vec![
            instr(0, op::LDC_I4, ROperand::Int32(5)),
            instr(5, op::RET, ROperand::None),
        ]);
        optimize_macros(&mut b);

        assert_eq!(b.instructions[0].opcode, op::LDC_I4_5);
        assert_eq!(b.instructions[0].operand, ROperand::None);
        assert_eq!(b.instructions[0].offset, 0);
        assert_eq!(b.instructions[1].offset, 1);
    }

    #[test]
    fn optimize_shortens_branches_and_collapses_vars() {
        // ldc.i4 7 (5); stloc 0 (4); ldloc 0 (4); br -> ret (5); ret
        let mut b = make_body(vec![
            instr(0, op::LDC_I4, ROperand::Int32(7)),
            instr(5, op::STLOC, ROperand::Var(0)),
            instr(9, op::LDLOC, ROperand::Var(0)),
            instr(13, op::BR, ROperand::Branch(18)),
            instr(18, op::RET, ROperand::None),
        ]);
        b.locals.push(local(0));
        optimize_macros(&mut b);

        let codes: Vec<Code> = b.instructions.iter().map(|i| i.opcode.code).collect();
        assert_eq!(codes, [Code::Ldc_I4_7, Code::Stloc_0, Code::Ldloc_0, Code::Br_S, Code::Ret,]);
        // After collapsing: br.s sits at 3, ret lands at 5: 5 - (3 + 2) = 0.
        assert_eq!(b.instructions[3].operand, ROperand::Branch(5));
        assert_eq!(b.instructions[4].offset, 5);
    }

    #[test]
    fn optimize_keeps_long_branch_when_displacement_overflows() {
        // A branch whose displacement cannot fit a signed byte stays long.
        let mut instructions = vec![instr(0, op::BR, ROperand::Branch(144))];
        for i in 0..139 {
            instructions.push(instr(5 + i, op::NOP, ROperand::None));
        }
        instructions.push(instr(144, op::RET, ROperand::None));
        let mut b = make_body(instructions);
        optimize_macros(&mut b);

        assert_eq!(b.instructions[0].opcode, op::BR);
        assert_eq!(b.instructions[0].operand, ROperand::Branch(144));
        assert_eq!(b.instructions.last().unwrap().offset, 144);
    }

    #[test]
    fn simplify_of_optimize_is_byte_comparable_with_the_original() {
        // Fully expanded long-form original.
        let original = make_body(vec![
            instr(0, op::LDC_I4, ROperand::Int32(5)),
            instr(5, op::STLOC, ROperand::Var(0)),
            instr(9, op::LDLOC, ROperand::Var(0)),
            instr(13, op::BR, ROperand::Branch(18)),
            instr(18, op::RET, ROperand::None),
        ]);
        let mut optimized = original.clone();
        optimize_macros(&mut optimized);

        // Collapsed to the shortest deterministic forms...
        let codes: Vec<Code> = optimized.instructions.iter().map(|i| i.opcode.code).collect();
        assert_eq!(codes, [Code::Ldc_I4_5, Code::Stloc_0, Code::Ldloc_0, Code::Br_S, Code::Ret,]);

        // ...and simplify(optimize(x)) restores the original stream exactly
        // (opcodes, operands and offsets - i.e. byte-identical IL).
        simplify_macros(&mut optimized);
        assert_eq!(optimized.instructions, original.instructions);
    }

    #[test]
    fn simplify_expands_all_macro_families() {
        let mut b = make_body(vec![
            instr(0, op::LDARG_0, ROperand::None),
            instr(1, op::LDARG_2, ROperand::None),
            instr(2, op::LDLOC_1, ROperand::None),
            instr(3, op::STLOC_3, ROperand::None),
            instr(4, op::LDARG_S, ROperand::Var(4)),
            instr(6, op::STLOC_S, ROperand::Var(5)),
            instr(8, op::LDC_I4_S, ROperand::Int8(-3)),
            instr(10, op::BRTRUE_S, ROperand::Branch(0)),
            instr(12, op::RET, ROperand::None),
        ]);
        simplify_macros(&mut b);

        let codes: Vec<Code> = b.instructions.iter().map(|i| i.opcode.code).collect();
        assert_eq!(
            codes,
            [
                Code::Ldarg,
                Code::Ldarg,
                Code::Ldloc,
                Code::Stloc,
                Code::Ldarg,
                Code::Stloc,
                Code::Ldc_I4,
                Code::Brtrue,
                Code::Ret,
            ]
        );
        assert_eq!(b.instructions[0].operand, ROperand::Var(0));
        assert_eq!(b.instructions[3].operand, ROperand::Var(3));
        assert_eq!(b.instructions[4].operand, ROperand::Var(4));
        assert_eq!(b.instructions[6].operand, ROperand::Int32(-3));
        // Offsets recomputed for the grown encodings (ldarg/ldloc/stloc are
        // 2+2 bytes, ldc.i4 and brtrue 1+4); the back-branch follows slot 0.
        let offsets: Vec<i32> = b.instructions.iter().map(|i| i.offset).collect();
        assert_eq!(offsets, [0, 4, 8, 12, 16, 20, 24, 29, 34]);
        assert_eq!(b.instructions[7].operand, ROperand::Branch(0));
    }

    #[test]
    fn editor_emit_helpers_append_and_chain() {
        let mut b = make_body(Vec::new());
        {
            let mut editor = BodyEditor::new(&mut b);
            // Emit helpers chain and append; a branch operand authored at
            // emission time is kept verbatim (the appended ret lands at or
            // past the branch, so it cannot move the target backwards).
            editor.ldc_i4(5).ret();
        }
        let codes: Vec<Code> = b.instructions.iter().map(|i| i.opcode.code).collect();
        assert_eq!(codes, [Code::Ldc_I4_5, Code::Ret]);
        assert_eq!(b.instructions[0].offset, 0);
        assert_eq!(b.instructions[1].offset, 1);

        // br()/ret() chain too; a backward (self-loop) target is untouched by
        // later appends.
        let mut d = make_body(Vec::new());
        {
            let mut editor = BodyEditor::new(&mut d);
            editor.br(0).ret();
        }
        let codes: Vec<Code> = d.instructions.iter().map(|i| i.opcode.code).collect();
        assert_eq!(codes, [Code::Br, Code::Ret]);
        assert_eq!(d.instructions[0].operand, ROperand::Branch(0));

        // Inserting a branch into an existing body keeps the target verbatim.
        let mut c =
            make_body(vec![instr(0, op::NOP, ROperand::None), instr(1, op::RET, ROperand::None)]);
        let mut editor = BodyEditor::new(&mut c);
        editor.insert_at(1, &BodyEditor::create_branch(6));
        assert_eq!(c.instructions[1].operand, ROperand::Branch(6));
        assert_eq!(c.instructions[2].offset, 6);
    }

    #[test]
    fn factories_cover_operand_kinds() {
        let token = Token(0x06000001);
        assert_eq!(BodyEditor::create(op::NOP).operand, ROperand::None);
        assert_eq!(BodyEditor::create_i64(-2).operand, ROperand::Int64(-2));
        assert_eq!(BodyEditor::create_r32(1.5).operand, ROperand::Float32(1.5));
        assert_eq!(BodyEditor::create_r64(2.5).operand, ROperand::Float64(2.5));
        assert_eq!(BodyEditor::create_branch(9).operand, ROperand::Branch(9));
        assert_eq!(BodyEditor::create_switch(vec![3, 4]).operand, ROperand::Switch(vec![3, 4]));
        let tok_instr = BodyEditor::create_token(op::CALL, token);
        assert_eq!(tok_instr.opcode, op::CALL);
        assert_eq!(tok_instr.operand, ROperand::Token(token));
    }

    #[test]
    fn optimize_narrows_representable_i8_constants_with_conv_i8() {
        // ldc.i8 42 (9); br -> ret (5); ret
        let mut b = make_body(vec![
            instr(0, op::LDC_I8, ROperand::Int64(42)),
            instr(9, op::BR, ROperand::Branch(14)),
            instr(14, op::RET, ROperand::None),
        ]);
        optimize(&mut b);

        // The long narrows to an sbyte load plus conv.i8; the macro pass then
        // collapses the load and shortens the branch, whose absolute target
        // keeps tracking ret through every relayout.
        let codes: Vec<Code> = b.instructions.iter().map(|i| i.opcode.code).collect();
        assert_eq!(codes, [Code::Ldc_I4_S, Code::Conv_I8, Code::Br_S, Code::Ret]);
        assert_eq!(b.instructions[0].operand, ROperand::Int8(42));
        assert_eq!(b.instructions[2].opcode.code, Code::Br_S);
        assert_eq!(b.instructions[2].operand, ROperand::Branch(5));
        assert_eq!(b.instructions[2].offset, 3);
        assert_eq!(b.instructions.last().unwrap().offset, 5);
    }

    #[test]
    fn optimize_keeps_boundary_i8_values_wide() {
        let mut b = make_body(vec![
            instr(0, op::LDC_I8, ROperand::Int64(i32::MIN as i64)),
            instr(9, op::LDC_I8, ROperand::Int64(i32::MAX as i64)),
            instr(18, op::RET, ROperand::None),
        ]);
        optimize(&mut b);

        let codes: Vec<Code> = b.instructions.iter().map(|i| i.opcode.code).collect();
        assert_eq!(codes, [Code::Ldc_I8, Code::Ldc_I8, Code::Ret]);
        assert_eq!(b.instructions[2].offset, 18);
    }
}

// ---------------------------------------------------------------------------
// Call / field redirection (xref-powered patching)
// ---------------------------------------------------------------------------

/// Rewrites every direct call site of `from` to invoke `to` instead:
/// instruction operands (`call`/`callvirt`/`newobj`, including targets
/// nested inside generic `MethodRef::Spec` instantiations) and
/// `MethodImpl` body references. Returns the number of rewritten sites.
///
/// The hook/patching primitive (Cecil users hand-roll this with full-module
/// walks). Signatures must be call-compatible: the parameter count
/// (including the implicit `this`) must match, and a void `to` cannot
/// replace a value-returning `from` — the caller would pop a value nobody
/// pushed.
pub fn redirect_calls(module: &mut Module, from: MethodId, to: MethodId) -> Result<usize> {
    use crate::model::types::TypeDesc;

    let check = || -> Result<()> {
        let f = &module.methods[from.index()];
        let t = &module.methods[to.index()];
        let f_arity = f.signature.parameters.len() + usize::from(f.signature.has_this);
        let t_arity = t.signature.parameters.len() + usize::from(t.signature.has_this);
        if f_arity != t_arity {
            return Err(Error::invalid_op(format!(
                "redirect: arity mismatch ({} takes {f_arity}, {} takes {t_arity})",
                f.name, t.name
            )));
        }
        let f_void = matches!(&f.signature.return_type, TypeDesc::Internal(s) if s == "void");
        let t_void = matches!(&t.signature.return_type, TypeDesc::Internal(s) if s == "void");
        if f_void != t_void && t_void {
            return Err(Error::invalid_op(format!(
                "redirect: {} returns void but {} expects a value",
                t.name, f.name
            )));
        }
        Ok(())
    };
    check()?;

    let mut rewritten = 0usize;
    for method in module.methods.iter_mut() {
        let Some(body) = &mut method.body else { continue };
        for ins in &mut body.instructions {
            if let ROperand::Method(mr) = &mut ins.operand {
                if rewrite_method_ref(mr, from, to) {
                    rewritten += 1;
                }
            }
        }
        // MethodImpl bodies pointing at `from` retarget too.
        for ov in &mut method.overrides {
            if rewrite_method_ref(&mut ov.body, from, to) {
                rewritten += 1;
            }
        }
    }
    Ok(rewritten)
}

/// Same redirect for field accesses — instruction operands only
/// (`ldfld`/`stfld`/`ldsfld`/`stsfld`/address-of). Returns the rewritten
/// site count.
pub fn redirect_field_accesses(module: &mut Module, from: FieldId, to: FieldId) -> usize {
    let mut rewritten = 0usize;
    for method in module.methods.iter_mut() {
        let Some(body) = &mut method.body else { continue };
        for ins in &mut body.instructions {
            if let ROperand::Field(FieldRef::Def(id)) = &mut ins.operand {
                if *id == from {
                    *id = to;
                    rewritten += 1;
                }
            }
        }
    }
    rewritten
}

/// Rewrites `from` inside a method reference tree (Spec nesting included).
fn rewrite_method_ref(mr: &mut MethodRef, from: MethodId, to: MethodId) -> bool {
    match mr {
        MethodRef::Def(id) => {
            if *id == from {
                *id = to;
                true
            } else {
                false
            }
        }
        MethodRef::Spec { method, .. } => rewrite_method_ref(method, from, to),
        MethodRef::External(_) => false,
    }
}

#[cfg(test)]
mod redirect_tests {
    use super::*;
    use crate::model::types::{
        FieldDefinition, FieldSignature, MethodDefinition, RInstruction, TypeDefinition,
    };

    fn int_desc() -> crate::model::types::TypeDesc {
        crate::model::types::TypeDesc::Internal("int32".into())
    }

    /// T with Orig/Hook/Caller methods; Caller calls Orig and loads field a.
    fn sample() -> Module {
        let mut module = Module { name: "s".into(), ..Default::default() };
        let t = module.add_type(TypeDefinition {
            namespace: "Ns".into(),
            name: "T".into(),
            ..Default::default()
        });
        let orig =
            module.add_method(t, MethodDefinition { name: "Orig".into(), ..Default::default() });
        let _hook =
            module.add_method(t, MethodDefinition { name: "Hook".into(), ..Default::default() });
        let caller =
            module.add_method(t, MethodDefinition { name: "Caller".into(), ..Default::default() });
        let f1 = module.add_field(
            t,
            FieldDefinition {
                name: "a".into(),
                signature: FieldSignature(int_desc()),
                ..Default::default()
            },
        );
        module.methods[caller.index()].body = Some(crate::model::types::ResolvedBody {
            max_stack: 1,
            instructions: vec![
                RInstruction {
                    offset: 0,
                    opcode: cecli_cil::opcodes::CALL,
                    operand: ROperand::Method(MethodRef::Def(orig)),
                },
                RInstruction {
                    offset: 5,
                    opcode: cecli_cil::opcodes::LDSFLD,
                    operand: ROperand::Field(FieldRef::Def(f1)),
                },
                RInstruction {
                    offset: 10,
                    opcode: cecli_cil::opcodes::RET,
                    operand: ROperand::None,
                },
            ],
            ..Default::default()
        });
        module
    }

    #[test]
    fn redirects_calls_and_fields() {
        let mut m = sample();
        // Call: Orig(0) -> Hook(1); one site.
        assert_eq!(redirect_calls(&mut m, MethodId(0), MethodId(1)).unwrap(), 1);
        let body = m.methods[2].body.as_ref().unwrap();
        assert_eq!(body.instructions[0].operand, ROperand::Method(MethodRef::Def(MethodId(1))));
        // Second redirect: no sites left.
        assert_eq!(redirect_calls(&mut m, MethodId(0), MethodId(1)).unwrap(), 0);

        // Field: a(0) -> b(1); one site.
        assert_eq!(redirect_field_accesses(&mut m, FieldId(0), FieldId(1)), 1);
        let body = m.methods[2].body.as_ref().unwrap();
        assert_eq!(body.instructions[1].operand, ROperand::Field(FieldRef::Def(FieldId(1))));
    }

    #[test]
    fn arity_mismatch_rejected() {
        let mut m = sample();
        // Give Hook an extra parameter.
        m.methods[1].signature.parameters.push(int_desc());
        let err = redirect_calls(&mut m, MethodId(0), MethodId(1)).unwrap_err();
        assert!(err.to_string().contains("arity"), "{err}");
    }
}
