//! `cecli` — command-line inspection, verification and diffing of .NET
//! assemblies, built on the cecli library.
//!
//! Subcommands:
//! * `inspect <file>`   — assembly identity, counts, entry point, references
//! * `dump <file>`      — full type/member roster (use `--il` for bodies)
//! * `verify <file>`    — parse, CFG + max-stack-check every body, roundtrip
//! * `roundtrip <file>` — read → write → re-read with count comparison
//! * `diff <a> <b>`     — semantic difference report
//! * `xref <file> <n>`  — bidirectional cross-references (callers/callees,
//!   readers/writers, dependencies)
//! * `unused <file>`    — dead-code report over the conservative root set

use std::process::ExitCode;

use cecli::AssemblyDefinition;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("inspect") => cmd_inspect(&args[2..]),
        Some("dump") => cmd_dump(&args[2..]),
        Some("verify") => cmd_verify(&args[2..]),
        Some("roundtrip") => cmd_roundtrip(&args[2..]),
        Some("diff") => cmd_diff(&args[2..]),
        Some("xref") => cmd_xref(&args[2..]),
        Some("unused") => cmd_unused(&args[2..]),
        None | Some("--help" | "-h") => {
            print_help();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown command: {other}");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!(
        "cecli — .NET assembly toolchain

USAGE:
    cecli inspect   <file>           assembly identity, counts, references
    cecli dump      <file> [--il]    type/member roster (optionally with IL)
    cecli verify    <file>           CFG + max-stack validation of every body
    cecli roundtrip <file> [-o out]  read -> write -> re-read, count checks
    cecli diff      <a> <b>          semantic difference report
    cecli xref      <file> <name>    cross-references of a type/method/field
    cecli unused    <file>           unreachable private members (dead code)"
    );
}

fn read(path: &str) -> Result<AssemblyDefinition, String> {
    AssemblyDefinition::read_file(path).map_err(|e| format!("{path}: {e}"))
}

// -- inspect ---------------------------------------------------------------

fn cmd_inspect(args: &[String]) -> ExitCode {
    let Some(path) = args.first() else {
        eprintln!("usage: cecli inspect <file>");
        return ExitCode::from(2);
    };
    match inspect(path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn inspect(path: &str) -> Result<(), String> {
    let asm = read(path)?;
    let m = asm.main_module();
    println!("assembly:  {}", asm.name.name);
    println!("version:   {}", asm.name.version);
    println!("kind:      {:?}", m.kind);
    println!("arch:      {:?}", m.architecture);
    println!("runtime:   {}", m.runtime_version);
    if let Some(ep) = asm.entry_point_method() {
        println!("entry:     {} ({} params)", ep.name, ep.signature.parameters.len());
    }
    println!(
        "types: {}  methods: {}  fields: {}  properties: {}  events: {}",
        m.types.len(),
        m.methods.len(),
        m.fields.len(),
        m.properties.len(),
        m.events.len()
    );
    if !m.assembly_refs.is_empty() {
        println!("references:");
        for r in &m.assembly_refs {
            println!("  {} ({})", r.name, r.version);
        }
    }
    if !m.resources.is_empty() {
        println!("resources: {}", m.resources.len());
    }
    Ok(())
}

// -- dump ------------------------------------------------------------------

fn cmd_dump(args: &[String]) -> ExitCode {
    let with_il = args.iter().any(|a| a == "--il");
    let Some(path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: cecli dump <file> [--il]");
        return ExitCode::from(2);
    };
    match dump(path, with_il) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn dump(path: &str, with_il: bool) -> Result<(), String> {
    let asm = read(path)?;
    let m = asm.main_module();
    for (tid, ty) in m.types.iter().enumerate() {
        let full = m.type_full_name(cecli::model::types::TypeId(tid as u32));
        println!("type {full}");
        for &fid in &ty.fields {
            let f = &m.fields[fid.index()];
            println!("  field {}", f.name);
        }
        for &mid in &ty.methods {
            let md = &m.methods[mid.index()];
            println!("  method {}({})", md.name, md.signature.parameters.len());
            if with_il {
                if let Some(body) = &md.body {
                    for ins in &body.instructions {
                        let op = operand_display(m, &ins.operand);
                        if op.is_empty() {
                            println!("    IL_{:04}: {}", ins.offset, ins.opcode.name);
                        } else {
                            println!("    IL_{:04}: {} {}", ins.offset, ins.opcode.name, op);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// -- verify ----------------------------------------------------------------

fn cmd_verify(args: &[String]) -> ExitCode {
    let Some(path) = args.first() else {
        eprintln!("usage: cecli verify <file>");
        return ExitCode::from(2);
    };
    match verify(path) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn verify(path: &str) -> Result<String, String> {
    let asm = read(path)?;
    let m = asm.main_module();
    let mut bodies = 0usize;
    let mut failures = Vec::new();
    for (_mid, method) in m.iter_methods() {
        let Some(body) = &method.body else { continue };
        bodies += 1;
        if let Err(e) = cecli::flow::Cfg::build(body) {
            failures.push(format!("{}::{}: {e}", path, method.name));
            continue;
        }
        if let Err(e) = cecli::flow::recompute_max_stack(m, body) {
            failures.push(format!("{}::{}: {e}", path, method.name));
        }
    }
    if failures.is_empty() {
        Ok(format!("{path}: OK ({bodies} bodies verified)"))
    } else {
        Err(format!(
            "{path}: {} of {bodies} bodies failed:\n  {}",
            failures.len(),
            failures.join("\n  ")
        ))
    }
}

// -- roundtrip -------------------------------------------------------------

fn cmd_roundtrip(args: &[String]) -> ExitCode {
    let out = args.iter().position(|a| a == "-o").and_then(|i| args.get(i + 1)).cloned();
    let Some(path) = args.iter().find(|a| !a.starts_with("-")) else {
        eprintln!("usage: cecli roundtrip <file> [-o out]");
        return ExitCode::from(2);
    };
    match roundtrip(path, out.as_deref()) {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn roundtrip(path: &str, out: Option<&str>) -> Result<String, String> {
    let asm = read(path)?;
    let before = counts(&asm);
    let bytes = asm.write().map_err(|e| format!("write: {e}"))?;
    if let Some(out) = out {
        std::fs::write(out, &bytes).map_err(|e| format!("save {out}: {e}"))?;
    }
    let re = AssemblyDefinition::read(&bytes).map_err(|e| format!("re-read: {e}"))?;
    let after = counts(&re);
    if before != after {
        return Err(format!("counts changed: {before:?} -> {after:?}"));
    }
    Ok(format!("{path}: OK ({} bytes written, member counts stable)", bytes.len()))
}

fn counts(asm: &AssemblyDefinition) -> (usize, usize, usize, usize, usize) {
    let m = asm.main_module();
    (m.types.len(), m.methods.len(), m.fields.len(), m.properties.len(), m.events.len())
}

// -- diff ------------------------------------------------------------------

fn cmd_diff(args: &[String]) -> ExitCode {
    if args.len() < 2 {
        eprintln!("usage: cecli diff <a> <b>");
        return ExitCode::from(2);
    }
    let (a, b) = match (read(&args[0]), read(&args[1])) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let report = cecli::diff::diff(&a, &b);
    println!("{report}");
    // Differences are information, not tool failure: exit 0 either way.
    ExitCode::SUCCESS
}

// -- xref ------------------------------------------------------------------

fn cmd_xref(args: &[String]) -> ExitCode {
    if args.len() < 2 {
        eprintln!("usage: cecli xref <file> <type-or-member>");
        return ExitCode::from(2);
    }
    match xref(&args[0], &args[1]) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn method_display(m: &cecli::Module, mid: cecli::model::types::MethodId) -> String {
    let md = &m.methods[mid.index()];
    format!("{}::{}", m.type_full_name(md.declaring_type), md.name)
}

fn site_display(m: &cecli::Module, site: &cecli::xref::UsageSite) -> String {
    use cecli::xref::UsageSite;
    match site {
        UsageSite::Instruction { method, offset } => {
            format!("{} @ IL_{:04X}", method_display(m, *method), offset)
        }
        UsageSite::TypeHead { ty } => format!("{} (head)", m.type_full_name(*ty)),
        UsageSite::Signature { method: Some(mid), .. } => {
            format!("{} (signature)", method_display(m, *mid))
        }
        UsageSite::Signature { field: Some(fid), .. } => {
            format!("{} (field type)", m.fields[fid.index()].name)
        }
        UsageSite::Signature { .. } => "signature".to_string(),
    }
}

fn entity_display(m: &cecli::Module, entity: &cecli::xref::UsedEntity) -> String {
    use cecli::xref::UsedEntity;
    match entity {
        UsedEntity::Type(id) => m.type_full_name(*id),
        UsedEntity::ExternalType(name) => name.clone(),
        UsedEntity::Method(id) => method_display(m, *id),
        UsedEntity::ExternalMethod(key) => key.clone(),
        UsedEntity::Field(id) => m.fields[id.index()].name.clone(),
        UsedEntity::ExternalField(key) => key.clone(),
    }
}

fn kind_name(kind: cecli::xref::UsageKind) -> &'static str {
    use cecli::xref::UsageKind as K;
    match kind {
        K::Call => "call",
        K::NewObject => "newobj",
        K::FieldLoad => "read",
        K::FieldStore => "write",
        K::FieldAddress => "address",
        K::TypeOperand => "type",
        K::BaseType => "base",
        K::Interface => "interface",
        K::Constraint => "constraint",
        K::Signature => "signature",
    }
}

fn xref(path: &str, query: &str) -> Result<(), String> {
    use cecli::xref::UsedEntity;

    let asm = read(path)?;
    let m = asm.main_module();
    let x = cecli::xref::Xref::build(m);

    // 1. A local type by full name.
    if let Some(tid) = m.find_type_full(query) {
        println!("type {}", m.type_full_name(tid));
        let deps = x.dependencies_of_type(tid);
        if !deps.is_empty() {
            println!("  depends on:");
            for u in deps {
                println!("    {:10} {}", kind_name(u.kind), entity_display(m, &u.entity));
            }
        }
        let users = x.users_of_type(tid);
        println!("  used by ({}):", users.len());
        for u in users {
            println!("    {:10} {}", kind_name(u.kind), site_display(m, &u.site));
        }
        return Ok(());
    }

    // 2. Type::Member for local members.
    if let Some((type_part, member_part)) = query.split_once("::") {
        if let Some(tid) = m.find_type_full(type_part) {
            let ty = m.type_def(tid).clone();
            let mut found = false;
            for &mid in &ty.methods {
                if m.methods[mid.index()].name != member_part {
                    continue;
                }
                found = true;
                println!(
                    "method {} ({} params)",
                    method_display(m, mid),
                    m.methods[mid.index()].signature.parameters.len()
                );
                let callers = x.callers_of(mid);
                println!("  callers ({}):", callers.len());
                for u in callers {
                    println!("    {:10} {}", kind_name(u.kind), site_display(m, &u.site));
                }
                let callees = x.callees_of(mid);
                if !callees.is_empty() {
                    println!("  calls:");
                    for u in callees {
                        println!("    {:10} {}", kind_name(u.kind), entity_display(m, &u.entity));
                    }
                }
                let uses = x.uses_of_method(mid);
                let other: Vec<_> = uses
                    .iter()
                    .filter(|u| {
                        !matches!(u.entity, UsedEntity::Method(_) | UsedEntity::ExternalMethod(_))
                    })
                    .collect();
                if !other.is_empty() {
                    println!("  uses:");
                    for u in other {
                        println!("    {:10} {}", kind_name(u.kind), entity_display(m, &u.entity));
                    }
                }
            }
            for &fid in &ty.fields {
                if m.fields[fid.index()].name != member_part {
                    continue;
                }
                found = true;
                println!("field {}::{}", m.type_full_name(tid), member_part);
                let accesses = x.field_accesses(fid);
                println!("  accesses ({}):", accesses.len());
                for u in accesses {
                    println!("    {:10} {}", kind_name(u.kind), site_display(m, &u.site));
                }
            }
            if found {
                return Ok(());
            }
            return Err(format!("{query}: no such member in type {type_part}"));
        }

        // 3. External member by exact key.
        let method_users = x.users_of_external_method(query);
        if !method_users.is_empty() {
            println!("external method {query}");
            println!("  callers ({}):", method_users.len());
            for u in method_users {
                println!("    {:10} {}", kind_name(u.kind), site_display(m, &u.site));
            }
            return Ok(());
        }
        let field_users = x.users_of_external_field(query);
        if !field_users.is_empty() {
            println!("external field {query}");
            println!("  accesses ({}):", field_users.len());
            for u in field_users {
                println!("    {:10} {}", kind_name(u.kind), site_display(m, &u.site));
            }
            return Ok(());
        }
    }

    // 4. Bare member name across all types.
    let matches: Vec<cecli::model::types::MethodId> =
        m.iter_methods().filter(|(_, md)| md.name == query).map(|(mid, _)| mid).collect();
    if matches.len() == 1 {
        let mid = matches[0];
        println!("method {}", method_display(m, mid));
        let callers = x.callers_of(mid);
        println!("  callers ({}):", callers.len());
        for u in callers {
            println!("    {:10} {}", kind_name(u.kind), site_display(m, &u.site));
        }
        return Ok(());
    }
    if matches.len() > 1 {
        println!("{} overloads:", matches.len());
        for mid in matches {
            println!("  {}", method_display(m, mid));
        }
        return Ok(());
    }

    // 5. External type by name.
    let users = x.users_of_external_type(query);
    if !users.is_empty() {
        println!("external type {query}");
        println!("  used by ({}):", users.len());
        for u in users {
            println!("    {:10} {}", kind_name(u.kind), site_display(m, &u.site));
        }
        return Ok(());
    }

    Err(format!("{query}: not found (type, Type::Member, member name, or external Ns.T::M)"))
}

// -- IL operand rendering (dump --il) ---------------------------------------

fn type_desc_display(m: &cecli::Module, ty: &cecli::model::types::TypeDesc) -> String {
    use cecli::model::types::TypeDesc;
    match ty {
        TypeDesc::Def(id) => m.type_full_name(*id),
        TypeDesc::External(ext) => cecli::xref::external_full_name(ext),
        TypeDesc::GenericInstance { definition, arguments } => {
            let args: Vec<String> = arguments.iter().map(|a| type_desc_display(m, a)).collect();
            format!("{}<{}>", type_desc_display(m, definition), args.join(", "))
        }
        TypeDesc::SzArray(e) => format!("{}[]", type_desc_display(m, e)),
        TypeDesc::Ptr(e) => format!("{}*", type_desc_display(m, e)),
        TypeDesc::ByRef(e) => format!("{}&", type_desc_display(m, e)),
        TypeDesc::Pinned(e) => type_desc_display(m, e),
        TypeDesc::Array { element, sizes, .. } => {
            // Rank is the larger of the two bound-vector lengths.
            let rank = sizes.len().max(1);
            format!("{}[{}]", type_desc_display(m, element), ",".repeat(rank.saturating_sub(1)))
        }
        TypeDesc::Var(n) => format!("!{n}"),
        TypeDesc::MVar(n) => format!("!!{n}"),
        other => format!("{other:?}"),
    }
}

fn method_ref_display(m: &cecli::Module, mr: &cecli::model::types::MethodRef) -> String {
    use cecli::model::types::MethodRef;
    match mr {
        MethodRef::Def(id) => method_display(m, *id),
        MethodRef::External(ext) => format!("{}::{}", type_desc_display(m, &ext.parent), ext.name),
        MethodRef::Spec { method, arguments } => {
            let args: Vec<String> = arguments.iter().map(|a| type_desc_display(m, a)).collect();
            format!("{}<{}>", method_ref_display(m, method), args.join(", "))
        }
    }
}

fn operand_display(m: &cecli::Module, op: &cecli::model::types::ROperand) -> String {
    use cecli::model::types::ROperand;
    match op {
        ROperand::None => String::new(),
        ROperand::Int8(v) => format!("{v}"),
        ROperand::Int32(v) => format!("{v}"),
        ROperand::Int64(v) => format!("{v}"),
        ROperand::Float32(v) => format!("{v}"),
        ROperand::Float64(v) => format!("{v}"),
        ROperand::Branch(t) => format!("IL_{t:04X}"),
        ROperand::Switch(list) => {
            let targets: Vec<String> = list.iter().map(|t| format!("IL_{t:04X}")).collect();
            format!("({})", targets.join(", "))
        }
        ROperand::Type(ty) => type_desc_display(m, ty),
        ROperand::Method(mr) => method_ref_display(m, mr),
        ROperand::Field(fr) => match fr {
            cecli::model::types::FieldRef::Def(id) => {
                // Find the declaring type for context.
                let f = &m.fields[id.index()];
                for ty in &m.types {
                    if ty.fields.contains(id) {
                        let tid = m
                            .types
                            .iter()
                            .position(|t| std::ptr::eq(t, ty))
                            .map(|i| cecli::model::types::TypeId(i as u32));
                        if let Some(tid) = tid {
                            return format!("{}::{}", m.type_full_name(tid), f.name);
                        }
                    }
                }
                f.name.clone()
            }
            cecli::model::types::FieldRef::External(ext) => {
                format!("{}::{}", type_desc_display(m, &ext.parent), ext.name)
            }
        },
        ROperand::String(s) => format!("{s:?}"),
        ROperand::UserString(off) => format!("us@{off:#x}"),
        ROperand::Token(tok) => format!("token {tok}"),
        ROperand::Rva(rva) => format!("{rva:#x}"),
        ROperand::Var(slot) => format!("slot {slot}"),
        ROperand::CallSite(sig) => {
            let ret = type_desc_display(m, &sig.return_type);
            let params: Vec<String> =
                sig.parameters.iter().map(|p| type_desc_display(m, p)).collect();
            format!("fn({}) -> {ret}", params.join(", "))
        }
    }
}

// -- unused (dead-code detection) -------------------------------------------

fn cmd_unused(args: &[String]) -> ExitCode {
    let Some(path) = args.first() else {
        eprintln!("usage: cecli unused <file>");
        return ExitCode::from(2);
    };
    match unused(path) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn unused(path: &str) -> Result<(), String> {
    let asm = read(path)?;
    let m = asm.main_module();
    let dead = cecli::callgraph::dead_members(m, &cecli::callgraph::RootPolicy::default());

    if dead.methods.is_empty() && dead.fields.is_empty() && dead.types.is_empty() {
        println!("{path}: no unreachable private members");
        return Ok(());
    }

    for &tid in &dead.types {
        println!("type   {}", m.type_full_name(tid));
    }
    for &mid in &dead.methods {
        println!("method {}", method_display(m, mid));
    }
    for &fid in &dead.fields {
        // Find the declaring type for context.
        let mut owner = String::new();
        for (i, ty) in m.types.iter().enumerate() {
            if ty.fields.contains(&fid) {
                owner = m.type_full_name(cecli::model::types::TypeId(i as u32));
                break;
            }
        }
        println!("field  {}::{}", owner, m.fields[fid.index()].name);
    }
    println!(
        "{} type(s), {} method(s), {} field(s) unreachable \
         (roots: entry point, virtual/override, accessors, .cctor, P/Invoke, \
         externally visible)",
        dead.types.len(),
        dead.methods.len(),
        dead.fields.len()
    );
    Ok(())
}
