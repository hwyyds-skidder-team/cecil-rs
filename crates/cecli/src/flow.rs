//! Control-flow analysis over resolved method bodies: basic blocks,
//! dominance and natural loops — plus ECMA-accurate evaluation-stack
//! simulation ([`recompute_max_stack`]).
//!
//! Cecil never shipped this (the `Mono.Cecil.FlowAnalysis` side project was
//! abandoned in 2009); IL tooling that needs a CFG — deobfuscators,
//! decompilers, coverage tools — hand-rolls one on top of Cecil's
//! instruction-reference graph. This module works over the offset-based
//! [`ResolvedBody`] model directly.
//!
//! `Cfg::build` requires a well-formed body: every branch target must land
//! exactly on an instruction boundary inside the code. Malformed bodies are
//! an error (this is an analysis tool, not a lenient reader).

use std::collections::BTreeSet;

use cecli_core::{Error, Result};

use crate::model::types::{ExceptionKind, MethodRef, RInstruction, ROperand, ResolvedBody};
use crate::Module;

/// A maximal straight-line instruction sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BasicBlock {
    /// IL offset of the first instruction.
    pub start: i32,
    /// Index range into `body.instructions` (`lo` inclusive, `hi` exclusive).
    pub instrs: std::ops::Range<usize>,
}

/// Control-flow graph of one method body.
///
/// The graph models NORMAL control flow only: branch/switch/fall-through
/// edges. Exception dispatch (try region -> handler) is deliberately NOT an
/// edge — the CLR clears the evaluation stack before entering a handler, so
/// a throwing instruction's normal-flow depth must not propagate into the
/// handler ([`Cfg::build`] explains the max-stack consequence). Handler
/// reachability is carried by [`Self::handler_entries`] instead, which the
/// stack simulation seeds independently.
#[derive(Debug, Clone)]
pub struct Cfg {
    /// Blocks in ascending offset order; block 0 is the entry block.
    pub blocks: Vec<BasicBlock>,
    /// Successor block indices per block (sorted, deduplicated).
    pub succs: Vec<Vec<usize>>,
    /// Predecessor block indices per block (sorted, deduplicated).
    pub preds: Vec<Vec<usize>>,
    /// Exception-handler entry blocks with their entry stack depth:
    /// catch and filter handlers enter with the exception object on the
    /// stack (depth 1), finally/fault handlers enter empty (depth 0). A
    /// filter has TWO runtime entries — FilterStart and HandlerStart — both
    /// at depth 1, so it can appear twice.
    pub handler_entries: Vec<(usize, u16)>,
}

/// One natural loop: a back edge `tail -> header` plus every block that can
/// reach `tail` without passing through `header`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loop {
    /// Block index of the loop header (dominates `tail`).
    pub header: usize,
    /// Block index of the back-edge source.
    pub tail: usize,
    /// Header, tail and all blocks in between (natural-loop body).
    pub body: BTreeSet<usize>,
}

impl Cfg {
    /// Builds the CFG of `body`.
    ///
    /// Leaders: offset 0, every branch/switch target, every exception-handler
    /// entry, and the instruction after any block terminator (branch, `ret`,
    /// `jmp`, `throw`, `rethrow`, `endfinally`, `endfilter`, tail call).
    pub fn build(body: &ResolvedBody) -> Result<Cfg> {
        let instrs = &body.instructions;
        if instrs.is_empty() {
            return Ok(Cfg {
                blocks: Vec::new(),
                succs: Vec::new(),
                preds: Vec::new(),
                handler_entries: Vec::new(),
            });
        }

        // offset -> instruction index map (offsets are dense per construction,
        // but a map keeps this robust against un-renumbered bodies).
        let mut at: std::collections::BTreeMap<i32, usize> = std::collections::BTreeMap::new();
        for (i, ins) in instrs.iter().enumerate() {
            at.insert(ins.offset, i);
        }

        let mut leaders: BTreeSet<i32> = BTreeSet::new();
        leaders.insert(instrs[0].offset);

        let targets = |ins: &RInstruction, leaders: &mut BTreeSet<i32>| -> Result<()> {
            match &ins.operand {
                ROperand::Branch(t) => {
                    if !leaders.contains(t) && at.contains_key(t) {
                        leaders.insert(*t);
                    } else if !at.contains_key(t) {
                        return Err(Error::bad_image(format!(
                            "cfg: branch target {t} is not an instruction boundary"
                        )));
                    }
                }
                ROperand::Switch(list) => {
                    for t in list {
                        if at.contains_key(t) {
                            leaders.insert(*t);
                        } else {
                            return Err(Error::bad_image(format!(
                                "cfg: switch target {t} is not an instruction boundary"
                            )));
                        }
                    }
                }
                _ => {}
            }
            Ok(())
        };

        for ins in instrs {
            targets(ins, &mut leaders)?;
            if is_terminator(ins) {
                // The next instruction (if any) starts a new block.
                if let Some(next) = at.range(ins.offset + 1..).next() {
                    leaders.insert(*next.0);
                }
            }
        }
        for h in &body.exception_handlers {
            // try block entry, handler entry, filter entry are leaders.
            if at.contains_key(&h.try_offset) {
                leaders.insert(h.try_offset);
            } else if h.try_length > 0 {
                return Err(Error::bad_image(format!(
                    "cfg: try start {} is not an instruction boundary",
                    h.try_offset
                )));
            }
            if at.contains_key(&h.handler_offset) {
                leaders.insert(h.handler_offset);
            } else {
                return Err(Error::bad_image(format!(
                    "cfg: handler start {} is not an instruction boundary",
                    h.handler_offset
                )));
            }
            if h.filter_offset != 0 {
                if at.contains_key(&h.filter_offset) {
                    leaders.insert(h.filter_offset);
                } else {
                    return Err(Error::bad_image(format!(
                        "cfg: filter start {} is not an instruction boundary",
                        h.filter_offset
                    )));
                }
            }
        }

        // Slice blocks between leaders.
        let leader_list: Vec<i32> = leaders.into_iter().collect();
        let mut blocks = Vec::with_capacity(leader_list.len());
        for (i, &start) in leader_list.iter().enumerate() {
            let lo = at[&start];
            let hi = if i + 1 < leader_list.len() { at[&leader_list[i + 1]] } else { instrs.len() };
            blocks.push(BasicBlock { start, instrs: lo..hi });
        }

        let block_of_offset = |offset: i32| -> Result<usize> {
            blocks.binary_search_by(|b| b.start.cmp(&offset)).map_err(|_| {
                Error::bad_image(format!("cfg: offset {offset} matches no basic block"))
            })
        };

        // Edges.
        let mut succs: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
        for (bi, block) in blocks.iter().enumerate() {
            let last = &instrs[block.instrs.end - 1];
            match &last.operand {
                ROperand::Branch(t) => {
                    let t = *t;
                    if is_unconditional_branch(last) {
                        succs[bi].push(block_of_offset(t)?);
                    } else {
                        // Conditional: taken + fall-through.
                        succs[bi].push(block_of_offset(t)?);
                        if bi + 1 < blocks.len() {
                            succs[bi].push(bi + 1);
                        }
                    }
                }
                ROperand::Switch(list) => {
                    for t in list {
                        succs[bi].push(block_of_offset(*t)?);
                    }
                    if bi + 1 < blocks.len() {
                        succs[bi].push(bi + 1);
                    }
                }
                _ if is_terminator(last) => {
                    if last.opcode.code == cecli_cil::Code::Jmp {
                        // jmp transfers out of the method: no successors.
                    }
                    // br.s/jmp/ret/throw/... : no fall-through.
                }
                _ => {
                    if bi + 1 < blocks.len() {
                        succs[bi].push(bi + 1);
                    }
                }
            }
        }
        // Do not add exception edges to the normal-flow graph. The CLR clears
        // the evaluation stack before entering a handler; propagating a
        // throwing instruction's normal depth here creates false join
        // mismatches. Handler reachability is represented by independent
        // `handler_entries` seeds below.
        for s in succs.iter_mut() {
            s.sort_unstable();
            s.dedup();
        }

        let mut preds: Vec<Vec<usize>> = vec![Vec::new(); blocks.len()];
        for (bi, ss) in succs.iter().enumerate() {
            for &s in ss {
                if !preds[s].contains(&bi) {
                    preds[s].push(bi);
                }
            }
        }
        preds.iter_mut().for_each(|p| p.sort_unstable());

        // Handler entry depths (catch/filter enter with the exception object
        // on the stack; finally/fault enter empty). A filter has TWO runtime
        // entries: FilterStart and HandlerStart, both with one exception
        // object on the stack.
        let mut handler_entries = Vec::new();
        for h in &body.exception_handlers {
            let depth = match h.kind {
                ExceptionKind::Catch | ExceptionKind::Filter => 1,
                ExceptionKind::Finally | ExceptionKind::Fault => 0,
            };
            if matches!(h.kind, ExceptionKind::Filter) && h.filter_offset != 0 {
                if let Ok(b) = block_of_offset(h.filter_offset) {
                    handler_entries.push((b, 1));
                }
            }
            if let Ok(b) = block_of_offset(h.handler_offset) {
                handler_entries.push((b, depth));
            }
        }

        Ok(Cfg { blocks, succs, preds, handler_entries })
    }

    /// Immediate dominator per block over the NORMAL-FLOW graph, computed
    /// with the Cooper-Harvey-Kennedy iterative algorithm over reverse
    /// postorder. Block 0 dominates everything; the entry's own idom is
    /// the `usize::MAX` sentinel.
    ///
    /// Because exception edges are deliberately absent (see [`Cfg::build`]),
    /// blocks reachable only through exception dispatch — handler entries
    /// and their bodies, unless some ordinary branch also targets them —
    /// have no immediate dominator (`usize::MAX`): they are unreachable in
    /// normal flow. This is the intended model for dominance/loop queries;
    /// stack simulation handles handlers through
    /// [`handler_entries`](Cfg::handler_entries) seeds instead.
    pub fn immediate_dominators(&self) -> Vec<usize> {
        let n = self.blocks.len();
        let mut idom = vec![usize::MAX; n];
        let rpo = self.reverse_postorder();
        let rpo_index = {
            let mut idx = vec![usize::MAX; n];
            for (i, &b) in rpo.iter().enumerate() {
                idx[b] = i;
            }
            idx
        };
        if rpo.is_empty() {
            return idom;
        }
        let entry = rpo[0];
        idom[entry] = entry;
        let intersect = |idom: &Vec<usize>, a: usize, b: usize| -> usize {
            let (mut a, mut b) = (a, b);
            while a != b {
                while rpo_index[a] > rpo_index[b] {
                    a = idom[a];
                }
                while rpo_index[b] > rpo_index[a] {
                    b = idom[b];
                }
            }
            a
        };
        let mut changed = true;
        while changed {
            changed = false;
            for &b in rpo.iter().skip(1) {
                let mut new_idom = usize::MAX;
                for &p in &self.preds[b] {
                    if idom[p] == usize::MAX {
                        continue; // not yet processed
                    }
                    new_idom =
                        if new_idom == usize::MAX { p } else { intersect(&idom, new_idom, p) };
                }
                if new_idom != usize::MAX && idom[b] != new_idom {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }
        idom
    }

    /// Natural loops: one per back edge `tail -> header` (header dominates
    /// tail), each with its full loop body.
    pub fn natural_loops(&self) -> Vec<Loop> {
        let idom = self.immediate_dominators();
        let mut loops = Vec::new();
        for (tail, succs) in self.succs.iter().enumerate() {
            for &header in succs {
                // Back edge iff header dominates tail. Walk the idom chain.
                let mut dominated = false;
                let mut cur = tail;
                loop {
                    if cur == header {
                        dominated = true;
                        break;
                    }
                    if idom[cur] == cur || idom[cur] == usize::MAX {
                        break;
                    }
                    cur = idom[cur];
                }
                if !dominated {
                    continue;
                }

                // Collect the natural-loop body backwards from tail to header.
                let mut body = BTreeSet::from([header, tail]);
                let mut stack = vec![tail];
                while let Some(b) = stack.pop() {
                    for &p in &self.preds[b] {
                        if body.insert(p) {
                            stack.push(p);
                        }
                    }
                }
                loops.push(Loop { header, tail, body });
            }
        }
        loops
    }

    /// Reverse postorder of the blocks REACHABLE FROM THE ENTRY (block 0)
    /// over normal-flow edges. Exception-only blocks (handler entries and
    /// their bodies, unless some ordinary branch also targets them) are
    /// absent — with them, a multi-seed walk put an exception-only block
    /// at the front of the "reverse postorder", breaking the entry
    /// assumption of [`Self::immediate_dominators`].
    ///
    /// Callers that need to visit every block regardless of reachability
    /// should iterate `self.blocks` directly.
    pub fn reverse_postorder(&self) -> Vec<usize> {
        let mut visited = vec![false; self.blocks.len()];
        let mut post = Vec::new();
        if self.blocks.is_empty() {
            return post;
        }
        // Iterative DFS to avoid deep recursion on huge bodies.
        visited[0] = true;
        let mut stack = vec![(0usize, 0usize)];
        while let Some(&mut (b, ref mut next)) = stack.last_mut() {
            if *next < self.succs[b].len() {
                let s = self.succs[b][*next];
                *next += 1;
                if !visited[s] {
                    visited[s] = true;
                    stack.push((s, 0));
                }
            } else {
                post.push(b);
                stack.pop();
            }
        }
        post.reverse();
        post
    }
}

fn is_unconditional_branch(ins: &RInstruction) -> bool {
    use cecli_cil::Code;
    // `leave`/`leave.s` carry a Branch operand but transfer control
    // unconditionally, exactly like `br` — treating them as conditional
    // would fabricate fall-through edges into unrelated code.
    matches!(ins.opcode.code, Code::Br | Code::Br_S | Code::Leave | Code::Leave_S)
}

/// Instructions that end a basic block unconditionally (no fall-through).
fn is_terminator(ins: &RInstruction) -> bool {
    use cecli_cil::Code;
    if matches!(ins.operand, ROperand::Branch(_) | ROperand::Switch(_)) {
        return true;
    }
    matches!(
        ins.opcode.code,
        Code::Ret | Code::Jmp | Code::Throw | Code::Rethrow | Code::Endfinally | Code::Endfilter
    )
}

/// Recomputes the evaluation-stack depth requirement of `body` (ECMA-335
/// III.1.7.5 / Cecil's `ComputeMaxStack`).
///
/// `module` supplies signatures for calls that target locally-defined
/// methods (their `MethodRef::Def` operand carries only the handle).
///
/// The body must be well-formed: branch targets on instruction boundaries
/// and stack depths equal at every control-flow join; violations are errors,
/// so this doubles as a body verifier. Exception-handler entries are seeded
/// per ECMA (catch/filter enter at depth 1, finally/fault at depth 0).
pub fn recompute_max_stack(module: &Module, body: &ResolvedBody) -> Result<u16> {
    let cfg = Cfg::build(body)?;
    if cfg.blocks.is_empty() {
        return Ok(0);
    }

    // Depth at block entry; unknown blocks stay at the sentinel.
    const UNKNOWN: u32 = u32::MAX;
    let mut entry_depth: Vec<u32> = vec![UNKNOWN; cfg.blocks.len()];
    entry_depth[0] = 0;
    for &(b, d) in &cfg.handler_entries {
        entry_depth[b] = d as u32;
    }

    let mut max: u32 = 0;
    let mut work: Vec<usize> = vec![0];
    work.extend(cfg.handler_entries.iter().map(|&(b, _)| b));
    let mut in_work = vec![false; cfg.blocks.len()];
    for &b in &work {
        in_work[b] = true;
    }

    while let Some(b) = work.pop() {
        in_work[b] = false;
        let depth = entry_depth[b];
        if depth == UNKNOWN {
            continue;
        }
        let mut d = depth;
        for i in cfg.blocks[b].instrs.clone() {
            let ins = &body.instructions[i];
            if is_prefix(ins) {
                continue; // prefixes modify the next instruction, stack-neutral
            }
            let (pops, pushes) = stack_effect(module, ins)?;
            d = d
                .checked_sub(pops as u32)
                .ok_or_else(|| Error::bad_image("cfg: evaluation stack underflow"))?;
            max = max.max(d + pushes as u32);
            d += pushes as u32;
        }
        // Branch comparand pops are already applied by stack_effect; the
        // exit depth is simply the post-instruction depth.
        max = max.max(d);
        let last = &body.instructions[cfg.blocks[b].instrs.end - 1];
        // `leave` clears the evaluation stack before transferring to its
        // runtime continuation/finally chain; normal branches preserve `d`.
        let outgoing_depth =
            if matches!(last.opcode.code, cecli_cil::Code::Leave | cecli_cil::Code::Leave_S) {
                0
            } else {
                d
            };
        for &s in &cfg.succs[b] {
            if entry_depth[s] == UNKNOWN {
                entry_depth[s] = outgoing_depth;
                if !in_work[s] {
                    in_work[s] = true;
                    work.push(s);
                }
            } else if entry_depth[s] != outgoing_depth {
                return Err(Error::bad_image(format!(
                    "cfg: stack depth mismatch at join ({} != {outgoing_depth})",
                    entry_depth[s]
                )));
            }
        }
    }

    u16::try_from(max).map_err(|_| Error::bad_image("cfg: max stack exceeds u16"))
}

/// Value pops of a branch/switch at block exit (0 for non-branches).
fn branch_pops(ins: &RInstruction) -> u8 {
    match &ins.operand {
        ROperand::Branch(_) if is_unconditional_branch(ins) => 0,
        // brtrue/brfalse compare one value; every other conditional branch
        // compares two.
        ROperand::Branch(_) => {
            if ins.opcode.name.starts_with("brtrue") || ins.opcode.name.starts_with("brfalse") {
                1
            } else {
                2
            }
        }
        ROperand::Switch(_) => 1,
        _ => 0,
    }
}

/// (pops, pushes) of one instruction; `call`-family effects come from the
/// resolved signature operand, Def targets through `module`.
fn stack_effect(module: &Module, ins: &RInstruction) -> Result<(u8, u8)> {
    let name = ins.opcode.name;

    // Call family: variadic by signature.
    if matches!(name, "call" | "callvirt" | "calli" | "newobj") {
        return match (&ins.operand, name) {
            (ROperand::Method(mr), "call" | "callvirt" | "newobj") => {
                let sig = signature_of(module, mr)?;
                let this = if sig.has_this && name != "newobj" { 1 } else { 0 };
                let pops = sig.parameters.len() as u8 + this;
                let pushes = if name == "newobj" {
                    1
                } else if is_void(&sig.return_type) {
                    0
                } else {
                    1
                };
                Ok((pops, pushes))
            }
            (ROperand::CallSite(sig), "calli") => {
                let this = if sig.has_this { 1 } else { 0 };
                // arguments + implicit this + the function pointer itself
                Ok((
                    sig.parameters.len() as u8 + this + 1,
                    if is_void(&sig.return_type) { 0 } else { 1 },
                ))
            }
            _ => Err(Error::bad_image(format!("cfg: {name} without a resolved signature operand"))),
        };
    }

    // Branch/switch operands: pop their comparands here (the block-exit
    // propagation must not subtract them again).
    match &ins.operand {
        ROperand::Branch(_) => return Ok((branch_pops(ins), 0)),
        ROperand::Switch(_) => return Ok((1, 0)),
        _ => {}
    }

    // Terminators that end a block: their residual pops cannot raise the
    // maximum, and modeling them exactly would need return-type knowledge.
    if matches!(
        name,
        "ret" | "jmp" | "throw" | "rethrow" | "endfinally" | "endfilter" | "leave" | "leave.s"
    ) {
        return Ok((0, 0));
    }

    if name == "nop" || name == "break" {
        return Ok((0, 0));
    }

    let effect: (u8, u8) = if name.starts_with("ldarg")
        || name.starts_with("ldloc")
        || name.starts_with("ldc")
        || name.starts_with("ldsfld")
        || name.starts_with("ldarga")
        || name.starts_with("ldloca")
        || name.starts_with("ldsflda")
        || name == "ldftn"
        || name == "ldstr"
        || name == "ldnull"
        || name == "ldtoken"
        || name == "arglist"
        || name == "sizeof"
    {
        (0, 1)
    } else if name == "ldfld" || name == "ldflda" {
        // Both instance field loads consume the object reference and push
        // one value (the address form is not a zero-pop load).
        (1, 1)
    } else if name == "ldvirtftn" || name == "refanytype" {
        (1, 1)
    } else if name == "dup" {
        (1, 2)
    } else if name.starts_with("starg") || name.starts_with("stloc") || name == "pop" {
        (1, 0)
    } else if name == "stfld" {
        (2, 0)
    } else if name == "stsfld" {
        (1, 0)
    } else if name.starts_with("ldelem") {
        (2, 1)
    } else if name.starts_with("stelem") {
        (3, 0)
    } else if name.starts_with("ldind") {
        (1, 1)
    } else if name.starts_with("stind") {
        (2, 0)
    } else if name == "newarr" || name == "ldlen" || name == "localloc" {
        (1, 1)
    } else if name == "initobj" {
        // consume the address, produce nothing
        (1, 0)
    } else if name == "ldobj" {
        (1, 1)
    } else if name == "cpobj" || name == "stobj" {
        // src address + destination address
        (2, 0)
    } else if name.starts_with("conv")
        || name == "not"
        || name == "neg"
        || name == "ckfinite"
        || name == "box"
        || name == "unbox.any"
        || name == "castclass"
        || name == "isinst"
        || name == "unbox"
        || name == "refanyval"
        || name == "mkrefany"
        || name == "ckany"
    {
        (1, 1)
    } else if name == "cpblk" || name == "initblk" {
        (3, 0)
    } else {
        // Binary arithmetic / comparison / shift / logic and everything else
        // that is not a load, store, call, branch or prefix: 2 -> 1.
        (2, 1)
    };
    Ok(effect)
}

/// True for prefix instructions (stack-neutral modifiers of the next one).
fn is_prefix(ins: &RInstruction) -> bool {
    ins.opcode.name.starts_with("tail.")
        || ins.opcode.name.starts_with("volatile.")
        || ins.opcode.name.starts_with("unaligned.")
        || ins.opcode.name.starts_with("constrained.")
        || ins.opcode.name.starts_with("readonly.")
        || ins.opcode.name.starts_with("no.")
}

/// Signature of a method reference; Def handles index `module.methods`.
fn signature_of<'a>(
    module: &'a Module,
    mr: &'a MethodRef,
) -> Result<&'a crate::model::types::MethodSignature> {
    match mr {
        MethodRef::External(ext) => Ok(&ext.signature),
        MethodRef::Def(id) => module
            .methods
            .get(id.index())
            .map(|m| &m.signature)
            .ok_or_else(|| Error::bad_image("cfg: call target outside the method arena")),
        MethodRef::Spec { method, .. } => signature_of(module, method),
    }
}

fn is_void(ty: &crate::model::types::TypeDesc) -> bool {
    use crate::model::types::TypeDesc;
    match ty {
        // C++/CLI metadata commonly wraps the return type in one or more
        // custom modifiers.  The modifier does not change the evaluation
        // stack shape; inspect the underlying type instead.
        TypeDesc::CMod { unmodified, .. } => is_void(unmodified),
        TypeDesc::Internal(s) => {
            s.eq_ignore_ascii_case("void") || s.eq_ignore_ascii_case("system.void")
        }
        TypeDesc::External(ext) => {
            ext.namespace.eq_ignore_ascii_case("system") && ext.name.eq_ignore_ascii_case("void")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{
        ExternalMethod, ExternalType, MethodSignature, RInstruction, ROperand, ScopeRef, TypeDesc,
    };
    use crate::Module;
    use cecli_cil::opcodes;

    fn ins(offset: i32, opcode: cecli_cil::OpCode, operand: ROperand) -> RInstruction {
        RInstruction { offset, opcode, operand }
    }

    fn body(instrs: Vec<RInstruction>) -> ResolvedBody {
        let max = instrs.len() as u16; // irrelevant for CFG tests
        ResolvedBody { max_stack: max, instructions: instrs, ..Default::default() }
    }

    /// Straight-line body: one block.
    #[test]
    fn linear_body_is_one_block() {
        let b = body(vec![
            ins(0, opcodes::LDC_I4_0, ROperand::None),
            ins(1, opcodes::RET, ROperand::None),
        ]);
        let cfg = Cfg::build(&b).unwrap();
        assert_eq!(cfg.blocks.len(), 1);
        assert!(cfg.succs[0].is_empty());
    }

    /// if/else diamond: 4 blocks, 1 -> {2,3}, 2 -> 0-join, 3 -> join.
    #[test]
    fn diamond_shape() {
        // 0: ldc.i4.0; 1: brtrue.s -> 5; 3: ldc.i4.1; 4: br.s -> 6;
        // 5: ldc.i4.2; 6: ret
        let b = body(vec![
            ins(0, opcodes::LDC_I4_0, ROperand::None),
            ins(1, opcodes::BRTRUE_S, ROperand::Branch(5)),
            ins(3, opcodes::LDC_I4_1, ROperand::None),
            ins(4, opcodes::BR_S, ROperand::Branch(6)),
            ins(5, opcodes::LDC_I4_2, ROperand::None),
            ins(6, opcodes::RET, ROperand::None),
        ]);
        let cfg = Cfg::build(&b).unwrap();
        // Blocks start at 0, 3, 5, 6.
        assert_eq!(cfg.blocks.len(), 4);
        assert_eq!(cfg.blocks[0].start, 0);
        assert_eq!(cfg.blocks[1].start, 3);
        assert_eq!(cfg.blocks[2].start, 5);
        assert_eq!(cfg.blocks[3].start, 6);
        // Block 0 branches to 5 (taken) and falls through to 3.
        assert!(cfg.succs[0].contains(&2) && cfg.succs[0].contains(&1));
        // Both arms reach the ret block.
        assert!(cfg.succs[1].contains(&3));
        assert!(cfg.succs[2].contains(&3));
    }

    /// while-loop: back edge, one natural loop containing the body.
    #[test]
    fn loop_detection() {
        // 0: br.s -> 5 (loop condition); 2: ldc.i4.0; 3: br.s -> 0?
        // Simpler canonical while: 0: ldc.i4.1 (cond); 1: brtrue.s -> 5;
        // 3: nop; 4: br.s -> 0; 5: ret
        let b = body(vec![
            ins(0, opcodes::LDC_I4_1, ROperand::None),
            ins(1, opcodes::BRTRUE_S, ROperand::Branch(5)),
            ins(3, opcodes::NOP, ROperand::None),
            ins(4, opcodes::BR_S, ROperand::Branch(0)),
            ins(5, opcodes::RET, ROperand::None),
        ]);
        let cfg = Cfg::build(&b).unwrap();
        let loops = cfg.natural_loops();
        assert_eq!(loops.len(), 1, "one back edge");
        assert_eq!(loops[0].header, 0);
        assert!(loops[0].body.contains(&0) && loops[0].body.contains(&1));
    }

    /// recompute_max_stack over hand-built bodies with known depths.
    #[test]
    fn max_stack_simple_bodies() {
        // ldc.i4.0; ldc.i4.1; add; ret -> peak 2.
        let b = body(vec![
            ins(0, opcodes::LDC_I4_0, ROperand::None),
            ins(1, opcodes::LDC_I4_1, ROperand::None),
            ins(2, opcodes::ADD, ROperand::None),
            ins(3, opcodes::RET, ROperand::None),
        ]);
        assert_eq!(recompute_max_stack(&Module::default(), &b).unwrap(), 2);

        // Empty body.
        assert_eq!(recompute_max_stack(&Module::default(), &body(vec![])).unwrap(), 0);

        // dup: 1 -> 2.
        let b = body(vec![
            ins(0, opcodes::LDC_I4_0, ROperand::None),
            ins(1, opcodes::DUP, ROperand::None),
            ins(2, opcodes::POP, ROperand::None),
            ins(3, opcodes::POP, ROperand::None),
            ins(4, opcodes::RET, ROperand::None),
        ]);
        assert_eq!(recompute_max_stack(&Module::default(), &b).unwrap(), 2);
    }

    /// Stack depth must agree at joins; disagreement is an error.
    #[test]
    fn join_depth_mismatch_rejected() {
        // 0: ldc.i4.0; 1: brtrue.s -> 5; 3: ldc.i4.0; 4: br.s -> 6;
        // 5: ldc.i4.0; 6: pop; 7: ret  — one arm enters the join with 1,
        // the other with 2 (fall-through from block at 3 carries 1... both
        // 1). Craft a real mismatch:
        // arm A: 3: ldc; 4: ldc; 5: br.s -> 8   (joins at depth 2)
        // arm B: 6: ldc; 7: br.s -> 8           (joins at depth 1)
        let b = body(vec![
            ins(0, opcodes::LDC_I4_0, ROperand::None),
            ins(1, opcodes::BRTRUE_S, ROperand::Branch(6)),
            ins(3, opcodes::LDC_I4_0, ROperand::None),
            ins(4, opcodes::LDC_I4_0, ROperand::None),
            ins(5, opcodes::BR_S, ROperand::Branch(8)),
            ins(6, opcodes::LDC_I4_0, ROperand::None),
            ins(7, opcodes::BR_S, ROperand::Branch(8)),
            ins(8, opcodes::POP, ROperand::None),
            ins(9, opcodes::RET, ROperand::None),
        ]);
        assert!(recompute_max_stack(&Module::default(), &b).is_err(), "depth 2 vs 1 at the join");
    }

    #[test]
    fn branch_target_off_boundary_is_error() {
        let b = body(vec![
            ins(0, opcodes::LDC_I4_0, ROperand::None),
            ins(1, opcodes::BRTRUE_S, ROperand::Branch(2)), // mid-instruction
            ins(3, opcodes::RET, ROperand::None),
        ]);
        assert!(Cfg::build(&b).is_err());
    }

    #[test]
    fn custom_modifier_void_call_has_no_result() {
        let void = TypeDesc::CMod {
            required: false,
            modifier: std::sync::Arc::new(TypeDesc::Internal("native".into())),
            unmodified: std::sync::Arc::new(TypeDesc::Internal("void".into())),
        };
        let method = MethodRef::External(ExternalMethod {
            parent: TypeDesc::External(Box::new(ExternalType {
                namespace: "Native".into(),
                name: "Runtime".into(),
                nesting: Vec::new(),
                scope: ScopeRef::Moduleless,
            })),
            name: "Release".into(),
            signature: MethodSignature {
                has_this: false,
                return_type: void,
                ..MethodSignature::default()
            },
        });
        let call = ins(0, opcodes::CALL, ROperand::Method(method));
        assert_eq!(stack_effect(&Module::default(), &call).unwrap(), (0, 0));
    }
}

#[cfg(test)]
mod fixture_tests {
    use super::*;

    /// The ultimate validation: for every method body of every fixture, the
    /// recomputed evaluation-stack requirement must equal the value stored
    /// in the image. This exercises the stack-effect table and the CFG over
    /// tens of thousands of real instructions.
    #[test]
    fn recomputed_max_stack_matches_every_fixture() {
        let dir = cecli_core::fixtures_dir();
        if !dir.is_dir() {
            return; // fixtures not provisioned on this checkout
        }
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension()
                    .is_some_and(|x| x == "exe" || x == "dll" || x == "netmodule" || x == "winmd")
            })
            .collect();
        files.sort();

        let mut bodies = 0usize;
        let mut mismatches = Vec::new();
        for path in &files {
            let Ok(bytes) = std::fs::read(path) else { continue };
            let Ok(asm) = crate::AssemblyDefinition::read(&bytes) else { continue };
            let m = asm.main_module();
            for (mid, method) in m.iter_methods() {
                let Some(body) = &method.body else { continue };
                bodies += 1;
                // `max_stack` in the method header is an upper bound, not a
                // promise of the minimal requirement. Compilers are allowed
                // to over-allocate it (including values below Roslyn's usual
                // padding threshold), so the only portable invariant is that
                // the recomputed requirement does not exceed the declaration.
                match recompute_max_stack(m, body) {
                    Ok(computed) => {
                        if computed > body.max_stack {
                            mismatches.push(format!(
                                "{}::{}: stored {}, computed {}",
                                path.file_name().unwrap().to_string_lossy(),
                                method.name,
                                body.max_stack,
                                computed
                            ));
                        }
                    }
                    Err(e) => mismatches.push(format!(
                        "{}::{}: {e}",
                        path.file_name().unwrap().to_string_lossy(),
                        method.name
                    )),
                }
                // CFG must also build cleanly for every body.
                if let Err(e) = Cfg::build(body) {
                    mismatches.push(format!(
                        "{}::{} cfg: {e}",
                        path.file_name().unwrap().to_string_lossy(),
                        method.name
                    ));
                }
                let _ = mid;
            }
        }
        assert!(bodies > 100, "expected a real corpus, saw {bodies} bodies");
        assert!(
            mismatches.is_empty(),
            "{} mismatch(es) across {bodies} bodies:\n{}",
            mismatches.len(),
            mismatches.join("\n")
        );
    }
}

#[cfg(test)]
mod dominance_tests {
    use super::*;
    use crate::model::types::{ExceptionHandlerIL, ExceptionKind, RInstruction, ROperand};
    use cecli_cil::opcodes;

    fn ins(offset: i32, opcode: cecli_cil::OpCode, operand: ROperand) -> RInstruction {
        RInstruction { offset, opcode, operand }
    }

    /// A try/catch whose handler is reachable ONLY through exception
    /// dispatch: with exception edges deliberately absent, the handler
    /// block has no immediate dominator (normal-flow unreachable), while
    /// still appearing in the reverse postorder and in handler_entries.
    #[test]
    fn exception_only_handler_is_not_dominated() {
        let body = ResolvedBody {
            max_stack: 1,
            instructions: vec![
                ins(0, opcodes::NOP, ROperand::None),
                ins(1, opcodes::LDC_I4_1, ROperand::None),
                ins(2, opcodes::POP, ROperand::None),
                ins(3, opcodes::NOP, ROperand::None),
                ins(4, opcodes::LEAVE_S, ROperand::Branch(8)), // try end
                ins(6, opcodes::LEAVE_S, ROperand::Branch(8)), // handler
                ins(8, opcodes::RET, ROperand::None),
            ],
            exception_handlers: vec![ExceptionHandlerIL {
                kind: ExceptionKind::Catch,
                try_offset: 0,
                try_length: 6,
                filter_offset: 0,
                handler_offset: 6,
                handler_length: 2,
                catch_type: Some(crate::model::types::TypeDesc::Internal("object".into())),
            }],
            ..Default::default()
        };

        let cfg = Cfg::build(&body).unwrap();
        // Blocks: [0..4], [6], [8]. Handler block index = 1.
        let handler = 1usize;
        // The handler is seeded with catch depth 1.
        assert!(
            cfg.handler_entries.iter().any(|&(b, d)| b == handler && d == 1),
            "catch entry seeded at depth 1: {:?}",
            cfg.handler_entries
        );
        // No normal-flow predecessors.
        assert!(cfg.preds[handler].is_empty(), "no exception edges in preds");

        let idom = cfg.immediate_dominators();
        assert_eq!(idom[handler], usize::MAX, "exception-only block is not dominated");
        // The join block after both leaves IS dominated by the entry block.
        assert_eq!(idom[0], 0, "entry dominates itself");
        assert_eq!(idom[2], 0, "join block dominated by the entry");
        // Entry-only RPO does NOT contain the exception-only handler block
        // (it is reachable solely through exception dispatch).
        assert!(!cfg.reverse_postorder().contains(&handler));
    }

    /// Diamond: both arms are dominated by the entry; the join is dominated
    /// by the entry too (either arm can reach it), not by an arm.
    #[test]
    fn dominators_of_a_diamond() {
        let body = ResolvedBody {
            max_stack: 1,
            instructions: vec![
                ins(0, opcodes::LDC_I4_0, ROperand::None),
                ins(1, opcodes::BRTRUE_S, ROperand::Branch(5)),
                ins(3, opcodes::NOP, ROperand::None),
                ins(4, opcodes::BR_S, ROperand::Branch(6)),
                ins(5, opcodes::NOP, ROperand::None),
                ins(6, opcodes::RET, ROperand::None),
            ],
            ..Default::default()
        };
        let cfg = Cfg::build(&body).unwrap();
        // Blocks by start offset: 0, 3, 5, 6 -> indices 0,1,2,3.
        let idom = cfg.immediate_dominators();
        assert_eq!(idom[0], 0);
        assert_eq!(idom[1], 0, "arm A dominated by entry");
        assert_eq!(idom[2], 0, "arm B dominated by entry");
        assert_eq!(idom[3], 0, "join dominated by entry");
    }
}
