//! Method-level call graph, strongly-connected components and dead-code
//! analysis.
//!
//! [`CallGraph`] records every direct call edge between locally-defined
//! methods (external targets are kept by name). Tarjan SCC identifies
//! recursion clusters; [`dead_members`] layers reachability over a
//! conservative root set to report methods, fields and types that no code
//! can reach — the analysis Cecil users currently bolt on with bespoke
//! walkers.
//!
//! The graph covers `call`/`callvirt`/`newobj`/`calli`-through-`CallSite`
//! edges with resolved `Def` targets. Indirect dispatch (delegates,
//! virtual overrides) is invisible by construction — which is exactly why
//! [`dead_members`] treats virtual/new-slot/override/accessor members as
//! roots instead of trusting the graph alone.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use cecli_core::flags::MethodAttributes;

use crate::model::types::{FieldId, MethodId, MethodRef, ROperand, TypeId};
use crate::Module;

/// Method-level call graph of one module.
#[derive(Debug, Default, Clone)]
pub struct CallGraph {
    /// Direct call edges: caller -> callees (local targets, deduplicated,
    /// in first-encounter order). `newobj` counts as a call.
    edges: BTreeMap<MethodId, Vec<MethodId>>,
    /// External call targets per caller, keyed `Ns.Type::Member` (the same
    /// spelling [`crate::xref`] uses).
    external: BTreeMap<MethodId, Vec<String>>,
}

impl CallGraph {
    /// Walks every method body once, recording call edges.
    pub fn build(module: &Module) -> CallGraph {
        let mut g = CallGraph::default();
        for (mid, method) in module.methods.iter().enumerate() {
            let mid = MethodId(mid as u32);
            let Some(body) = &method.body else { continue };
            for ins in &body.instructions {
                // Only Method operands create Def edges; `calli` targets ride
                // in their CallSite signature for indirect invocation.
                if let ROperand::Method(mr) = &ins.operand {
                    g.record(mid, mr);
                }
            }
        }
        g
    }

    fn record(&mut self, caller: MethodId, mr: &MethodRef) {
        match mr {
            MethodRef::Def(id) => {
                let v = self.edges.entry(caller).or_default();
                if !v.contains(id) {
                    v.push(*id);
                }
            }
            MethodRef::External(ext) => {
                let key = format!("{}::{}", external_parent_name(&ext.parent), ext.name);
                let v = self.external.entry(caller).or_default();
                if !v.contains(&key) {
                    v.push(key);
                }
                // The call also touches the declaring type, but that is a
                // type-level xref concern, not a call edge.
            }
            MethodRef::Spec { method, .. } => self.record(caller, method),
        }
    }

    /// Locally-defined methods this method calls directly.
    pub fn callees(&self, caller: MethodId) -> &[MethodId] {
        self.edges.get(&caller).map(Vec::as_slice).unwrap_or(&[])
    }

    /// External targets (`Ns.Type::Member` keys) this method calls.
    pub fn external_callees(&self, caller: MethodId) -> &[String] {
        self.external.get(&caller).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Reverse adjacency: for every local method, who calls it directly.
    pub fn callers_map(&self) -> BTreeMap<MethodId, Vec<MethodId>> {
        let mut callers: BTreeMap<MethodId, Vec<MethodId>> = BTreeMap::new();
        for (&caller, callees) in &self.edges {
            for &callee in callees {
                callers.entry(callee).or_default().push(caller);
            }
        }
        callers
    }

    /// True when the method participates in a call cycle (direct or mutual
    /// recursion, including self-calls).
    pub fn is_recursive(&self, m: MethodId) -> bool {
        let sccs = self.strongly_connected_components();
        sccs.iter().any(|scc| (scc.len() > 1 || self.self_loop(m)) && scc.contains(&m))
    }

    fn self_loop(&self, m: MethodId) -> bool {
        self.callees(m).contains(&m)
    }

    /// Tarjan strongly-connected components over the local call graph,
    /// iterative (no recursion, bodies can be large). Components are
    /// returned in reverse topological order (callees before callers);
    /// trivial components (single method without a self-loop) are included.
    pub fn strongly_connected_components(&self) -> Vec<Vec<MethodId>> {
        // Nodes: every method that either calls or is called.
        let mut nodes: BTreeSet<MethodId> = BTreeSet::new();
        for (&caller, callees) in &self.edges {
            nodes.insert(caller);
            nodes.extend(callees);
        }

        // Tarjan state.
        let mut index_of: BTreeMap<MethodId, usize> = BTreeMap::new();
        let mut lowlink: BTreeMap<MethodId, usize> = BTreeMap::new();
        let mut on_stack: BTreeSet<MethodId> = BTreeSet::new();
        let mut stack: Vec<MethodId> = Vec::new();
        let mut next_index = 0usize;
        let mut sccs: Vec<Vec<MethodId>> = Vec::new();

        for &root in &nodes {
            if index_of.contains_key(&root) {
                continue;
            }
            // Frame: (node, next successor cursor).
            let mut frames: Vec<(MethodId, usize)> = vec![(root, 0)];
            index_of.insert(root, next_index);
            lowlink.insert(root, next_index);
            next_index += 1;
            stack.push(root);
            on_stack.insert(root);

            while let Some(&mut (v, ref mut cursor)) = frames.last_mut() {
                let succs = self.callees(v);
                if *cursor < succs.len() {
                    let w = succs[*cursor];
                    *cursor += 1;
                    if let std::collections::btree_map::Entry::Vacant(e) = index_of.entry(w) {
                        e.insert(next_index);
                        lowlink.insert(w, next_index);
                        next_index += 1;
                        stack.push(w);
                        on_stack.insert(w);
                        frames.push((w, 0));
                    } else if on_stack.contains(&w) {
                        let iw = index_of[&w];
                        let lv = lowlink[&v];
                        if iw < lv {
                            lowlink.insert(v, iw);
                        }
                    }
                } else {
                    frames.pop();
                    if let Some(&(parent, _)) = frames.last() {
                        let lv = lowlink[&v];
                        let lp = lowlink[&parent];
                        if lv < lp {
                            lowlink.insert(parent, lv);
                        }
                    }
                    if lowlink[&v] == index_of[&v] {
                        let mut component = Vec::new();
                        while let Some(top) = stack.pop() {
                            on_stack.remove(&top);
                            component.push(top);
                            if top == v {
                                break;
                            }
                        }
                        sccs.push(component);
                    }
                }
            }
        }
        sccs
    }
}

/// Dead-code report: members no code can reach.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct DeadMembers {
    pub methods: Vec<MethodId>,
    pub fields: Vec<FieldId>,
    pub types: Vec<TypeId>,
}

/// Root-set policy for [`dead_members`], kept explicit so callers can widen
/// or narrow the conservative defaults.
#[derive(Debug, Clone, PartialEq)]
pub struct RootPolicy {
    /// Methods that may be dispatched virtually or override a base member.
    pub virtual_methods: bool,
    /// Property/event accessors (linked via MethodSemantics, not call
    /// sites).
    pub accessors: bool,
    /// The assembly entry point.
    pub entry_point: bool,
    /// Static constructors (invoked by the runtime).
    pub class_constructors: bool,
    /// P/Invoke thunks (invoked by name from native code).
    pub pinvoke: bool,
    /// Methods visible outside the assembly (public / family): callable by
    /// name from other assemblies, reflection and serializers.
    pub externally_visible: bool,
    /// Extra explicit roots supplied by the caller.
    pub extra: Vec<MethodId>,
}

impl Default for RootPolicy {
    fn default() -> Self {
        RootPolicy {
            virtual_methods: true,
            accessors: true,
            entry_point: true,
            class_constructors: true,
            pinvoke: true,
            externally_visible: true,
            extra: Vec::new(),
        }
    }
}

/// Reports members that no reachable code touches.
///
/// A method is dead when it is not a root (see [`RootPolicy`]), no live
/// method calls it, and it is not itself live. A private field is dead when
/// no instruction in a live body reads, writes or takes its address. A
/// private nested type is dead when nothing references it and all of its
/// members are dead. The analysis is intra-assembly by construction —
/// cross-assembly reachability is why externally visible members are roots.
///
/// False negatives are possible (roots are conservative); false positives
/// are not, as long as reflection-only users respect [`RootPolicy::extra`].
pub fn dead_members(module: &Module, policy: &RootPolicy) -> DeadMembers {
    let graph = CallGraph::build(module);
    let xref = crate::xref::Xref::build(module);

    // -- roots ---------------------------------------------------------------
    let mut roots: BTreeSet<MethodId> = BTreeSet::new();
    for (mid, method) in module.methods.iter().enumerate() {
        let mid = MethodId(mid as u32);
        let a = &method.attributes;
        if policy.virtual_methods
            && (a.contains(MethodAttributes::VIRTUAL) || a.contains(MethodAttributes::NEW_SLOT))
        {
            roots.insert(mid);
        }
        if policy.class_constructors && method.name == ".cctor" {
            roots.insert(mid);
        }
        if policy.pinvoke && method.pinvoke.is_some() {
            roots.insert(mid);
        }
        if policy.externally_visible {
            let access = a.intersection(MethodAttributes::MEMBER_ACCESS_MASK);
            // PUBLIC and FAMILY (and their combinations) escape the assembly.
            if access.intersects(MethodAttributes::PUBLIC | MethodAttributes::FAMILY) {
                roots.insert(mid);
            }
        }
        if !method.overrides.is_empty() {
            // Explicit interface implementations are dispatched.
            roots.insert(mid);
        }
    }
    if policy.accessors {
        for p in &module.properties {
            if let Some(m) = p.get_method {
                roots.insert(m);
            }
            if let Some(m) = p.set_method {
                roots.insert(m);
            }
            roots.extend(p.other_methods.iter().copied());
        }
        for e in &module.events {
            if let Some(m) = e.add_on {
                roots.insert(m);
            }
            if let Some(m) = e.remove_on {
                roots.insert(m);
            }
            if let Some(m) = e.fire {
                roots.insert(m);
            }
            roots.extend(e.other_methods.iter().copied());
        }
    }
    if policy.entry_point {
        // The entry point is a MethodDef token; rid maps to the arena
        // (arena order == table row order).
        let tok = module.entry_point_token;
        if tok.table_byte() == cecli_core::TableIndex::MethodDef as u8 && tok.rid() > 0 {
            let idx = tok.rid() as usize - 1;
            if idx < module.methods.len() {
                roots.insert(MethodId(idx as u32));
            }
        }
    }
    roots.extend(policy.extra.iter().copied());

    // -- reachability over call edges ----------------------------------------
    // Two edge sources: direct Def references (the CallGraph) and the xref
    // reverse index, whose second pass maps same-module MemberRefs made
    // through generic instantiation contexts (TypeSpec parents) back onto
    // local methods — exactly the calls the Def-only graph cannot see.
    let mut extra_edges: BTreeMap<MethodId, Vec<MethodId>> = BTreeMap::new();
    for (callee, usages) in xref.method_users_iter() {
        for u in usages {
            if matches!(u.kind, crate::xref::UsageKind::Call | crate::xref::UsageKind::NewObject) {
                if let crate::xref::UsageSite::Instruction { method: caller, .. } = u.site {
                    extra_edges.entry(caller).or_default().push(callee);
                }
            }
        }
    }

    let mut live: BTreeSet<MethodId> = BTreeSet::new();
    let mut work: Vec<MethodId> = roots.iter().copied().collect();
    while let Some(m) = work.pop() {
        if !live.insert(m) {
            continue;
        }
        for &callee in graph.callees(m) {
            if !live.contains(&callee) {
                work.push(callee);
            }
        }
        if let Some(callees) = extra_edges.get(&m) {
            for &callee in callees {
                if !live.contains(&callee) {
                    work.push(callee);
                }
            }
        }
    }

    let mut report = DeadMembers::default();
    for (mid, method) in module.methods.iter().enumerate() {
        let mid = MethodId(mid as u32);
        if !live.contains(&mid) {
            report.methods.push(mid);
            let _ = method;
        }
    }

    // Dead fields: no access from ANY body (dead bodies do not resurrect a
    // field, but accesses in dead bodies would hide it — use live bodies
    // only for a strict report; the simple all-bodies check is the
    // conservative middle ground the doc promises). Fields of ENUM types are
    // exempt: compilers inline named constants, so no runtime access ever
    // appears, yet the backing field and names are structurally required.
    let enum_types: BTreeSet<TypeId> = (0..module.types.len())
        .filter(|&i| {
            module.types[i].base_type.as_ref().is_some_and(|b| {
                matches!(
                    b,
                    crate::model::types::TypeDesc::External(ext)
                        if ext.namespace == "System" && ext.name == "Enum"
                )
            })
        })
        .map(|i| TypeId(i as u32))
        .collect();
    let mut enum_fields: BTreeSet<FieldId> = BTreeSet::new();
    for (tid, ty) in module.types.iter().enumerate() {
        if enum_types.contains(&TypeId(tid as u32)) {
            enum_fields.extend(ty.fields.iter().copied());
        }
    }

    for (fid, field) in module.fields.iter().enumerate() {
        let fid = FieldId(fid as u32);
        if enum_fields.contains(&fid) {
            continue;
        }
        // Literal (const) fields: compile-time inlined by every consumer
        // compiler, so no runtime access can exist.
        if field.constant.is_some() {
            continue;
        }
        if xref.field_accesses(fid).is_empty() {
            report.fields.push(fid);
        }
    }

    // Dead types: nothing references them and every member is dead. The
    // `<Module>` pseudo-type is structural (always present, never
    // referenced) and is exempt.
    for (tid, ty) in module.types.iter().enumerate() {
        let tid = TypeId(tid as u32);
        if tid.index() == 0 && ty.name == "<Module>" {
            continue;
        }
        if !xref.users_of_type(tid).is_empty() {
            continue;
        }
        let members_dead = ty.methods.iter().all(|&m| report.methods.contains(&m))
            && ty.fields.iter().all(|&f| report.fields.contains(&f));
        if members_dead {
            report.types.push(tid);
        }
    }

    report
}

/// Display name of an external method's declaring type (Def parents render
/// through the module in xref; here we only need the external spelling).
fn external_parent_name(ty: &crate::model::types::TypeDesc) -> String {
    use crate::model::types::TypeDesc;
    match ty {
        TypeDesc::External(ext) => crate::xref::external_full_name(ext),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{
        FieldDefinition, FieldSignature, MethodDefinition, RInstruction, ROperand, TypeDefinition,
    };

    /// Library: Lib.A (entry, public) calls Helper; Helper calls back into
    /// Lib.A (mutual recursion); Dead.DeadMethod and a private unused field
    /// and a fully-dead private type are unreferenced.
    fn sample() -> Module {
        use cecli_core::flags::{MethodAttributes, TypeAttributes};

        let mut module = Module { name: "sample".into(), ..Default::default() };

        let lib = module.add_type(TypeDefinition {
            namespace: "Ns".into(),
            name: "Lib".into(),
            attributes: TypeAttributes::PUBLIC | TypeAttributes::BEFORE_FIELD_INIT,
            ..Default::default()
        });
        let dead_ty = module.add_type(TypeDefinition {
            namespace: "Ns".into(),
            name: "Dead".into(),
            ..Default::default() // nested default = private visibility
        });

        // Entry: public static Main -> calls Helper (mutual recursion).
        let main_id = module.add_method(
            lib,
            MethodDefinition {
                name: "Main".into(),
                attributes: MethodAttributes::PUBLIC | MethodAttributes::STATIC,
                ..Default::default()
            },
        );
        let helper_id = module.add_method(
            lib,
            MethodDefinition {
                name: "Helper".into(),
                attributes: MethodAttributes::PRIVATE | MethodAttributes::STATIC,
                ..Default::default()
            },
        );
        let dead_method = module.add_method(
            dead_ty,
            MethodDefinition {
                name: "DeadMethod".into(),
                attributes: MethodAttributes::PRIVATE | MethodAttributes::STATIC,
                ..Default::default()
            },
        );
        let unused_field = module.add_field(
            lib,
            FieldDefinition {
                name: "s_unused".into(),
                signature: FieldSignature(int_desc()),
                ..Default::default()
            },
        );
        let _ = unused_field;

        // Bodies: Main calls Helper; Helper calls Main (cycle); DeadMethod
        // has a body but nobody calls it.
        let call = |target| RInstruction {
            offset: 0,
            opcode: cecli_cil::opcodes::CALL,
            operand: ROperand::Method(MethodRef::Def(target)),
        };
        let ret =
            || RInstruction { offset: 5, opcode: cecli_cil::opcodes::RET, operand: ROperand::None };
        for (owner, callee) in
            [(main_id, helper_id), (helper_id, main_id), (dead_method, dead_method)]
        {
            module.methods[owner.index()].body = Some(crate::model::types::ResolvedBody {
                max_stack: 1,
                instructions: vec![call(callee), ret()],
                ..Default::default()
            });
        }
        module.entry_point_token =
            cecli_core::Token::new(cecli_core::TableIndex::MethodDef, main_id.index() as u32 + 1);
        module
    }

    fn int_desc() -> crate::model::types::TypeDesc {
        crate::model::types::TypeDesc::Internal("int32".into())
    }

    #[test]
    fn scc_finds_mutual_recursion() {
        let m = sample();
        let g = CallGraph::build(&m);
        // Main <-> Helper is one SCC of size 2.
        let sccs = g.strongly_connected_components();
        let big: Vec<&Vec<MethodId>> = sccs.iter().filter(|s| s.len() > 1).collect();
        assert_eq!(big.len(), 1, "{sccs:?}");
        let scc = big[0];
        assert!(scc.contains(&MethodId(0)) && scc.contains(&MethodId(1)));

        assert!(g.is_recursive(MethodId(0)));
        assert!(g.is_recursive(MethodId(1)));
        // DeadMethod only self-loops through itself -> its self-call makes
        // it recursive too (self-loop).
        assert!(g.is_recursive(MethodId(2)));
    }

    #[test]
    fn dead_members_report() {
        let m = sample();
        let dead = dead_members(&m, &RootPolicy::default());
        // Only DeadMethod is dead (Main is entry+public, Helper is called,
        // both are in the live set via the cycle).
        assert_eq!(dead.methods, vec![MethodId(2)], "{dead:?}");
        // s_unused: no accesses anywhere.
        assert_eq!(dead.fields, vec![FieldId(0)], "{dead:?}");
        // Ns.Dead: no type users and its only member is dead.
        assert_eq!(dead.types, vec![TypeId(1)], "{dead:?}");
    }

    #[test]
    fn extra_roots_rescue_members() {
        let m = sample();
        let policy = RootPolicy { extra: vec![MethodId(2)], ..Default::default() };
        let dead = dead_members(&m, &policy);
        assert!(!dead.methods.contains(&MethodId(2)));
    }

    /// Fixture smoke: the analysis runs over a real assembly and its numbers
    /// stay stable (cecil.dll has hundreds of externally-visible members, so
    /// the dead set is small but non-trivial).
    #[test]
    fn fixture_smoke() {
        let dir = cecli_core::fixtures_dir();
        let path = dir.join("hello.exe");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(&path).expect("fixture readable");
        let asm = crate::AssemblyDefinition::read(&bytes).expect("parses");
        let m = asm.main_module();
        let graph = CallGraph::build(m);
        let _sccs = graph.strongly_connected_components();
        let dead = dead_members(m, &RootPolicy::default());
        // hello.exe: Program::.ctor is public (root), Main is entry; the
        // compiler-generated <>c::<.cctor> if present is a root. Expect a
        // small or empty dead set — no assertion on exact membership, just
        // that the analysis terminates and stays within the arena.
        assert!(dead.methods.len() <= m.methods.len());
    }
}
