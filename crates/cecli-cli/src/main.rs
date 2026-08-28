//! `cecli` — command-line inspection, verification and diffing of .NET
//! assemblies, built on the cecli library.
//!
//! Subcommands:
//! * `inspect <file>`   — assembly identity, counts, entry point, references
//! * `dump <file>`      — full type/member roster (use `--il` for bodies)
//! * `verify <file>`    — parse, CFG + max-stack-check every body, roundtrip
//! * `roundtrip <file>` — read → write → re-read with count comparison
//! * `diff <a> <b>`     — semantic difference report

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
    cecli diff      <a> <b>          semantic difference report"
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
                        println!("    IL_{:04}: {}", ins.offset, ins.opcode.name);
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
