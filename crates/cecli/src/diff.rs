//! Semantic assembly diff: compare two assemblies layer by layer —
//! identity, type roster, per-type member rosters, and method-body IL —
//! and report every difference.
//!
//! No .NET library ships this (Cecil users diff by re-serializing bytes and
//! comparing, which flags every timestamp and heap-ordering change). This
//! diff is semantic: it aligns types by full name, members by name (methods
//! also by parameter count), and bodies by instruction sequence, so
//! "nothing changed" is reported as nothing changed regardless of layout.

use std::collections::BTreeMap;

use crate::model::types::MethodDefinition;
use crate::{AssemblyDefinition, Module};

/// One difference between two assemblies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffEntry {
    /// Assembly-level identity changed (name, version, public key).
    Identity { field: &'static str, from: String, to: String },
    /// Type present only in one side.
    TypeOnly { full_name: String, side: Side },
    /// A member-level difference inside an otherwise matched type.
    Member { type_full_name: String, change: MemberChange },
    /// Both sides have the type, but its attributes differ.
    TypeAttributes { full_name: String, from: u32, to: u32 },
    /// The reference roster (assembly references) differs.
    AssemblyRef { name: String, change: RefChange },
    /// The manifest-resource roster differs.
    Resource { name: String, change: RefChange },
}

/// Which side an item appears on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberChange {
    Added {
        kind: MemberKind,
        name: String,
    },
    Removed {
        kind: MemberKind,
        name: String,
    },
    /// Same name, different signature (parameter count / types).
    SignatureChanged {
        name: String,
        from: String,
        to: String,
    },
    /// Same signature, different IL (instruction count / sequence).
    BodyChanged {
        name: String,
        from_instrs: usize,
        to_instrs: usize,
    },
    /// Same signature, one side has a body and the other does not.
    BodyPresence {
        name: String,
        from: bool,
        to: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    Method,
    Field,
    Property,
    Event,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefChange {
    Added,
    Removed,
    Modified,
}

/// The full difference report between two assemblies.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiffReport {
    pub entries: Vec<DiffEntry>,
}

impl DiffReport {
    /// True when the assemblies are semantically identical.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of recorded differences.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl std::fmt::Display for DiffReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.entries.is_empty() {
            return write!(f, "no differences");
        }
        for e in &self.entries {
            match e {
                DiffEntry::Identity { field, from, to } => {
                    writeln!(f, "identity: {field}: {from} -> {to}")?;
                }
                DiffEntry::TypeOnly { full_name, side } => {
                    let side = match side {
                        Side::Left => "-",
                        Side::Right => "+",
                    };
                    writeln!(f, "{side} type {full_name}")?;
                }
                DiffEntry::TypeAttributes { full_name, from, to } => {
                    writeln!(f, "~ type {full_name}: attributes {from:#x} -> {to:#x}")?;
                }
                DiffEntry::Member { type_full_name, change } => match change {
                    MemberChange::Added { kind, name } => {
                        writeln!(
                            f,
                            "+ {full_name}::{name} ({kind:?})",
                            full_name = type_full_name
                        )?;
                    }
                    MemberChange::Removed { kind, name } => {
                        writeln!(
                            f,
                            "- {full_name}::{name} ({kind:?})",
                            full_name = type_full_name
                        )?;
                    }
                    MemberChange::SignatureChanged { name, from, to } => {
                        writeln!(
                            f,
                            "~ {full_name}::{name}: signature {from} -> {to}",
                            full_name = type_full_name
                        )?;
                    }
                    MemberChange::BodyChanged { name, from_instrs, to_instrs } => {
                        writeln!(
                            f,
                            "~ {full_name}::{name}: body {from_instrs} -> {to_instrs} instructions",
                            full_name = type_full_name
                        )?;
                    }
                    MemberChange::BodyPresence { name, from, to } => {
                        writeln!(
                            f,
                            "~ {full_name}::{name}: body {from} -> {to}",
                            full_name = type_full_name
                        )?;
                    }
                },
                DiffEntry::AssemblyRef { name, change } => match change {
                    RefChange::Added => writeln!(f, "+ assemblyref {name}")?,
                    RefChange::Removed => writeln!(f, "- assemblyref {name}")?,
                    RefChange::Modified => writeln!(f, "~ assemblyref {name}")?,
                },
                DiffEntry::Resource { name, change } => match change {
                    RefChange::Added => writeln!(f, "+ resource {name}")?,
                    RefChange::Removed => writeln!(f, "- resource {name}")?,
                    RefChange::Modified => writeln!(f, "~ resource {name}")?,
                },
            }
        }
        write!(f, "{} difference(s)", self.entries.len())
    }
}

/// Diffs `left` against `right` (both fully read, bodies loaded).
pub fn diff(left: &AssemblyDefinition, right: &AssemblyDefinition) -> DiffReport {
    let mut report = DiffReport::default();

    // Assembly identity.
    let (l, r) = (&left.name, &right.name);
    if l.name != r.name {
        report.entries.push(DiffEntry::Identity {
            field: "name",
            from: l.name.clone(),
            to: r.name.clone(),
        });
    }
    if l.version != r.version {
        report.entries.push(DiffEntry::Identity {
            field: "version",
            from: l.version.to_string(),
            to: r.version.to_string(),
        });
    }
    if l.public_key != r.public_key {
        report.entries.push(DiffEntry::Identity {
            field: "public key",
            from: format!("{} bytes", l.public_key.len()),
            to: format!("{} bytes", r.public_key.len()),
        });
    }

    diff_assembly_refs(left.main_module(), right.main_module(), &mut report);
    diff_resources(left.main_module(), right.main_module(), &mut report);
    diff_type_rosters(left.main_module(), right.main_module(), &mut report);

    report
}

fn diff_assembly_refs(left: &Module, right: &Module, report: &mut DiffReport) {
    let l: BTreeMap<&str, &crate::model::types::AssemblyNameReference> =
        left.assembly_refs.iter().map(|r| (r.name.as_str(), r)).collect();
    let r: BTreeMap<&str, &crate::model::types::AssemblyNameReference> =
        right.assembly_refs.iter().map(|r| (r.name.as_str(), r)).collect();
    for (name, ref_) in &l {
        match r.get(name) {
            None => report.entries.push(DiffEntry::AssemblyRef {
                name: name.to_string(),
                change: RefChange::Removed,
            }),
            Some(other) => {
                if ref_.version != other.version {
                    report.entries.push(DiffEntry::AssemblyRef {
                        name: name.to_string(),
                        change: RefChange::Modified,
                    });
                }
            }
        }
    }
    for name in r.keys() {
        if !l.contains_key(name) {
            report
                .entries
                .push(DiffEntry::AssemblyRef { name: name.to_string(), change: RefChange::Added });
        }
    }
}

fn diff_resources(left: &Module, right: &Module, report: &mut DiffReport) {
    let l: BTreeMap<String, ()> =
        left.resources.iter().map(|r| (resource_name(r).to_string(), ())).collect();
    let r: BTreeMap<String, ()> =
        right.resources.iter().map(|r| (resource_name(r).to_string(), ())).collect();
    for name in l.keys() {
        if !r.contains_key(name) {
            report
                .entries
                .push(DiffEntry::Resource { name: name.clone(), change: RefChange::Removed });
        }
    }
    for name in r.keys() {
        if !l.contains_key(name) {
            report
                .entries
                .push(DiffEntry::Resource { name: name.clone(), change: RefChange::Added });
        }
    }
}

fn resource_name(r: &crate::module_def::Resource) -> &str {
    use crate::module_def::Resource;
    match r {
        Resource::Embedded { name, .. }
        | Resource::Linked { name, .. }
        | Resource::AssemblyLinked { name, .. } => name,
    }
}

fn diff_type_rosters(left: &Module, right: &Module, report: &mut DiffReport) {
    let index = |m: &Module| -> BTreeMap<String, crate::model::types::TypeId> {
        m.types
            .iter()
            .enumerate()
            .map(|(i, _)| {
                (
                    m.type_full_name(crate::model::types::TypeId(i as u32)),
                    crate::model::types::TypeId(i as u32),
                )
            })
            .collect()
    };
    let (l, r) = (index(left), index(right));

    for (name, &lid) in &l {
        match r.get(name) {
            None => report
                .entries
                .push(DiffEntry::TypeOnly { full_name: name.clone(), side: Side::Left }),
            Some(&rid) => diff_type(left, lid, right, rid, name, report),
        }
    }
    for name in r.keys() {
        if !l.contains_key(name) {
            report.entries.push(DiffEntry::TypeOnly { full_name: name.clone(), side: Side::Right });
        }
    }
}

fn diff_type(
    left: &Module,
    lid: crate::model::types::TypeId,
    right: &Module,
    rid: crate::model::types::TypeId,
    name: &str,
    report: &mut DiffReport,
) {
    let lt = left.type_def(lid);
    let rt = right.type_def(rid);
    if lt.attributes.bits() != rt.attributes.bits() {
        report.entries.push(DiffEntry::TypeAttributes {
            full_name: name.to_string(),
            from: lt.attributes.bits(),
            to: rt.attributes.bits(),
        });
    }

    // Members aligned by (kind, name); methods additionally key on parameter
    // count so overloads pair correctly.
    let method_key = |m: &Module,
                      id: crate::model::types::TypeId|
     -> BTreeMap<(String, usize), crate::model::types::MethodId> {
        m.type_def(id)
            .methods
            .iter()
            .map(|&mid| {
                let md = &m.methods[mid.index()];
                ((md.name.clone(), md.signature.parameters.len()), mid)
            })
            .collect()
    };
    let field_key = |m: &Module,
                     id: crate::model::types::TypeId|
     -> BTreeMap<String, crate::model::types::FieldId> {
        m.type_def(id).fields.iter().map(|&fid| (m.fields[fid.index()].name.clone(), fid)).collect()
    };

    let (lm, rm) = (method_key(left, lid), method_key(right, rid));
    for (key, &lmid) in &lm {
        match rm.get(key) {
            None => report.entries.push(DiffEntry::Member {
                type_full_name: name.to_string(),
                change: MemberChange::Removed { kind: MemberKind::Method, name: key.0.clone() },
            }),
            Some(&rmid) => diff_method(left, lmid, right, rmid, &key.0, name, report),
        }
    }
    for key in rm.keys() {
        if !lm.contains_key(key) {
            report.entries.push(DiffEntry::Member {
                type_full_name: name.to_string(),
                change: MemberChange::Added { kind: MemberKind::Method, name: key.0.clone() },
            });
        }
    }

    let (lf, rf) = (field_key(left, lid), field_key(right, rid));
    for fname in lf.keys() {
        if !rf.contains_key(fname) {
            report.entries.push(DiffEntry::Member {
                type_full_name: name.to_string(),
                change: MemberChange::Removed { kind: MemberKind::Field, name: fname.clone() },
            });
        }
    }
    for fname in rf.keys() {
        if !lf.contains_key(fname) {
            report.entries.push(DiffEntry::Member {
                type_full_name: name.to_string(),
                change: MemberChange::Added { kind: MemberKind::Field, name: fname.clone() },
            });
        }
    }
}

fn diff_method(
    left: &Module,
    lmid: crate::model::types::MethodId,
    right: &Module,
    rmid: crate::model::types::MethodId,
    mname: &str,
    tname: &str,
    report: &mut DiffReport,
) {
    let lm = &left.methods[lmid.index()];
    let rm = &right.methods[rmid.index()];

    if signature_string(lm) != signature_string(rm) {
        report.entries.push(DiffEntry::Member {
            type_full_name: tname.to_string(),
            change: MemberChange::SignatureChanged {
                name: mname.to_string(),
                from: signature_string(lm),
                to: signature_string(rm),
            },
        });
        return;
    }
    match (&lm.body, &rm.body) {
        (None, None) => {}
        (Some(lb), Some(rb)) => {
            if lb.instructions != rb.instructions {
                report.entries.push(DiffEntry::Member {
                    type_full_name: tname.to_string(),
                    change: MemberChange::BodyChanged {
                        name: mname.to_string(),
                        from_instrs: lb.instructions.len(),
                        to_instrs: rb.instructions.len(),
                    },
                });
            }
        }
        (Some(_), None) | (None, Some(_)) => report.entries.push(DiffEntry::Member {
            type_full_name: tname.to_string(),
            change: MemberChange::BodyPresence {
                name: mname.to_string(),
                from: lm.body.is_some(),
                to: rm.body.is_some(),
            },
        }),
    }
}

fn signature_string(m: &MethodDefinition) -> String {
    format!(
        "({}) -> {:?}",
        m.signature.parameters.iter().map(|p| format!("{p:?}")).collect::<Vec<_>>().join(", "),
        m.signature.return_type
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{
        MethodDefinition, RInstruction, ROperand, ResolvedBody, TypeDefinition, TypeId,
    };

    fn assembly(name: &str) -> AssemblyDefinition {
        let mut a = AssemblyDefinition::default();
        a.name.name = name.into();
        a
    }

    fn with_type(mut a: AssemblyDefinition, ns: &str, name: &str) -> AssemblyDefinition {
        let id = a.main.add_type(TypeDefinition {
            namespace: ns.into(),
            name: name.into(),
            ..Default::default()
        });
        let _ = id;
        a
    }

    fn method(name: &str, body_instrs: usize) -> MethodDefinition {
        let mut md = MethodDefinition { name: name.into(), ..Default::default() };
        if body_instrs > 0 {
            md.body = Some(ResolvedBody {
                max_stack: 1,
                instructions: (0..body_instrs)
                    .map(|i| RInstruction {
                        offset: i as i32,
                        opcode: cecli_cil::opcodes::RET,
                        operand: ROperand::None,
                    })
                    .collect(),
                ..Default::default()
            });
        }
        md
    }

    #[test]
    fn identical_assemblies_are_empty() {
        let a = with_type(assembly("A"), "Ns", "T");
        let b = with_type(assembly("A"), "Ns", "T");
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn type_and_member_changes_reported() {
        let mut a = with_type(assembly("A"), "Ns", "T");
        let mut b = with_type(assembly("A"), "Ns", "T");
        // Same method, different body sizes; plus one extra method on the right.
        a.main.add_method(TypeId(0), method("Run", 3));
        b.main.add_method(TypeId(0), method("Run", 1));
        b.main.add_method(TypeId(0), method("Extra", 0));

        let report = diff(&a, &b);
        let text = report.to_string();
        assert!(text.contains("~ Ns.T::Run: body 3 -> 1"), "{text}");
        assert!(text.contains("+ Ns.T::Extra"), "{text}");
        assert_eq!(report.len(), 2);
    }

    #[test]
    fn added_removed_types() {
        let a = with_type(assembly("A"), "Ns", "Only");
        let b = with_type(assembly("A"), "Ns", "Other");
        let report = diff(&a, &b);
        let text = report.to_string();
        assert!(text.contains("- type Ns.Only"), "{text}");
        assert!(text.contains("+ type Ns.Other"), "{text}");
    }
}

#[cfg(test)]
mod fixture_tests {
    use super::*;

    /// Semantic diff of a fixture against its own round-trip write must be
    /// empty: layout changes (heap order, timestamp, section layout) are not
    /// semantic changes.
    #[test]
    fn roundtrip_image_is_semantically_identical() {
        let dir = cecli_core::fixtures_dir();
        let path = dir.join("cecil.dll");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(&path).expect("fixture readable");
        let a = AssemblyDefinition::read(&bytes).expect("parses");
        let rewritten = a.write().expect("writes");
        let b = AssemblyDefinition::read(&rewritten).expect("re-parses");
        let report = diff(&a, &b);
        assert!(report.is_empty(), "unexpected differences:\n{report}");
    }
}
