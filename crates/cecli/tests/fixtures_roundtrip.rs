//! Integration acceptance suite (contract section "Integration acceptance
//! after O2 gates"):
//!
//! * every `fixtures/*.exe|dll|netmodule` parses, writes, re-parses with
//!   identical type/method/field/property/event/custom-attribute/resource
//!   counts, stable entry-point token, and equal kind + architecture;
//! * `hello.exe` entry point decodes a non-empty IL body;
//! * `xattr.dll` attribute constructor names surface with the expected
//!   distinct set;
//! * `varargs.exe` / `fptr.exe` parse;
//! * `winrtcomp.winmd` reports metadata kind `ManagedWindowsMetadata`;
//! * `line.exe` attaches symbols from the same-stem `.pdb` (skipped when
//!   either file is absent);
//! * `simplemdb.exe.mdb` opens through the MDB reader (skipped when absent).
//!
//! Every test degrades to a skip (with an explanatory message on stderr)
//! when the workspace fixtures directory is missing.

mod helpers;

use cecli::assembly::AssemblyDefinition;
use cecli_core::flags::{MetadataKind, ModuleKind};
use helpers::{
    collect_attribute_type_names, require_fixtures, roundtrip_fixtures, temp_output_dir, Counts,
};
use std::collections::BTreeSet;

/// The full sweep: read -> snapshot counts -> write -> re-read -> compare.
#[test]
fn every_fixture_roundtrips_with_stable_counts() {
    let Some(dir) = require_fixtures() else {
        return;
    };
    let files = roundtrip_fixtures(&dir);
    assert!(
        !files.is_empty(),
        "no *.exe|dll|netmodule fixtures found in {}",
        dir.display()
    );

    let out_dir = temp_output_dir("roundtrip");
    let mut attribute_names: BTreeSet<String> = BTreeSet::new();

    for path in &files {
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());

        let asm = AssemblyDefinition::read_file(path)
            .unwrap_or_else(|e| panic!("{label}: initial parse failed: {e:?}"));
        let before = Counts::snapshot(asm.main_module());
        attribute_names.extend(collect_attribute_type_names(asm.main_module()));

        let out_path = out_dir.join(&label);
        asm.write_file(&out_path)
            .unwrap_or_else(|e| panic!("{label}: write failed: {e:?}"));

        let reparsed = AssemblyDefinition::read_file(&out_path)
            .unwrap_or_else(|e| panic!("{label}: re-parse of written image failed: {e:?}"));
        let after = Counts::snapshot(reparsed.main_module());
        assert_eq!(
            before, after,
            "{label}: member counts changed across write -> re-parse"
        );
        assert_eq!(
            asm.main.kind,
            reparsed.main.kind,
            "{label}: module kind changed"
        );
        assert_eq!(
            asm.main.architecture,
            reparsed.main.architecture,
            "{label}: PE architecture changed"
        );
        assert_eq!(
            asm.main.entry_point_token,
            reparsed.main.entry_point_token,
            "{label}: entry point token changed"
        );
        assert_eq!(
            asm.entry_point,
            reparsed.entry_point,
            "{label}: resolved entry point changed"
        );
    }

    let _ = std::fs::remove_dir_all(&out_dir);

    // Attribute-name parity over the reachable surface of the whole sweep:
    // the union of constructor declaring-type names must contain at least
    // three distinct attributes somewhere in the fixture corpus.
    let distinct = attribute_names.len();
    assert!(
        distinct >= 3,
        "expected >= 3 distinct attribute constructor type names across all \
         fixtures, found {distinct}: {attribute_names:?}"
    );
}

/// `hello.exe`: the CLI-header entry token resolves to a method whose body
/// decodes to a non-empty instruction stream.
#[test]
fn hello_entry_point_body_decodes() {
    let Some(dir) = require_fixtures() else {
        return;
    };
    let path = dir.join("hello.exe");
    if !path.exists() {
        eprintln!("skipping: {} not found", path.display());
        return;
    }

    let asm = AssemblyDefinition::read_file(&path)
        .unwrap_or_else(|e| panic!("hello.exe: parse failed: {e:?}"));
    let entry = asm
        .entry_point_method()
        .expect("hello.exe: CLI entry token resolves to a MethodDef");
    let body = entry
        .body
        .as_ref()
        .expect("hello.exe: entry point has an IL body");
    assert!(
        !body.instructions.is_empty(),
        "hello.exe: entry point decoded zero instructions"
    );
}

/// `xattr.dll` assembly-level custom attributes surface through
/// `AssemblyNameDefinition.custom_attributes` with at least three distinct
/// constructor declaring-type names (`DebuggableAttribute`,
/// `CompilationRelaxationsAttribute`, `RuntimeCompatibilityAttribute`).
///
/// INTENTIONALLY STRICT per orchestrator decision: this is expected to be
/// red until the queued fix-up wave wires Assembly-parented CustomAttribute
/// rows into `AssemblyNameDefinition` during read (the reader currently
/// drops them; see `read/module_reader.rs::read_custom_attributes`). Kept as
/// its own test so it can be tracked independently of the sweep above.
#[test]
fn xattr_assembly_attributes_surface() {
    let Some(dir) = require_fixtures() else {
        return;
    };
    let path = dir.join("xattr.dll");
    if !path.exists() {
        eprintln!("skipping: {} not found", path.display());
        return;
    }

    let asm = AssemblyDefinition::read_file(&path)
        .unwrap_or_else(|e| panic!("xattr.dll: parse failed: {e:?}"));
    let mut names: Vec<String> = asm
        .name
        .custom_attributes
        .iter()
        .filter_map(|attr| helpers::attribute_type_name(attr, asm.main_module()))
        .collect();
    names.sort();
    names.dedup();
    assert!(
        names.len() >= 3,
        "xattr.dll: expected >= 3 distinct assembly-level attribute \
         constructor type names, found {}: {names:?}",
        names.len()
    );
}

/// `varargs.exe` and `fptr.exe` exercise exotic signatures (vararg call
/// sites, function pointers); both must parse cleanly.
#[test]
fn varargs_and_fptr_parse() {
    let Some(dir) = require_fixtures() else {
        return;
    };
    for name in ["varargs.exe", "fptr.exe"] {
        let path = dir.join(name);
        if !path.exists() {
            eprintln!("skipping: {name} not found");
            continue;
        }
        let asm = AssemblyDefinition::read_file(&path)
            .unwrap_or_else(|e| panic!("{name}: parse failed: {e:?}"));
        assert!(
            !asm.main.types.is_empty(),
            "{name}: parsed but no types decoded"
        );
    }
}

/// `winrtcomp.winmd` is a *managed* Windows Runtime image: its metadata root
/// version string is "WindowsRuntime 1.3;CLR v4.0.30319", which
/// `AssemblyReader.GetMetadataKind` maps to the ManagedWindowsMetadata
/// bucket (WindowsRuntime marker + CLR marker). The reader must classify it
/// accordingly rather than as plain ECMA-335 or native winmd.
#[test]
fn winrtcomp_metadata_kind_is_managed_windows_metadata() {
    let Some(dir) = require_fixtures() else {
        return;
    };
    let path = dir.join("winrtcomp.winmd");
    if !path.exists() {
        eprintln!("skipping: {} not found", path.display());
        return;
    }
    let asm = AssemblyDefinition::read_file(&path)
        .unwrap_or_else(|e| panic!("winrtcomp.winmd: parse failed: {e:?}"));
    assert_eq!(
        asm.main.metadata_kind,
        MetadataKind::ManagedWindowsMetadata,
        "winrtcomp.winmd: unexpected metadata kind"
    );
    // A .winmd is a DLL-flavored image, never a console/NetModule kind.
    assert_ne!(asm.main.kind, ModuleKind::NetModule);
}

/// `line.exe` + same-stem `line.pdb`: reading with `read_symbols` must
/// attach portable-PDB documents and sequence points to the module.
///
/// Skipped when either file is absent or when symbols were not attached
/// because no same-stem `.pdb` exists next to the origin path.
#[test]
fn line_symbols_attach() {
    let Some(dir) = require_fixtures() else {
        return;
    };
    let exe = dir.join("line.exe");
    let pdb = dir.join("line.pdb");
    if !exe.exists() || !pdb.exists() {
        eprintln!(
            "skipping: line symbol fixtures missing (need {} and {})",
            exe.display(),
            pdb.display()
        );
        return;
    }

    let params = cecli::resolver::ReaderParameters {
        read_symbols: true,
        ..Default::default()
    };
    let asm = AssemblyDefinition::read_file_with(&exe, &params)
        .unwrap_or_else(|e| panic!("line.exe: parse with symbols failed: {e:?}"));
    let debug = asm
        .main
        .debug
        .as_ref()
        .expect("line.exe: symbols not attached despite same-stem .pdb");
    assert!(
        !debug.documents.is_empty(),
        "line.exe: no documents attached from portable pdb"
    );
    assert!(
        !debug.points.is_empty(),
        "line.exe: no sequence points attached from portable pdb"
    );
}

/// `simplemdb.exe.mdb` opens through the Mono MDB reader and yields at least
/// one method entry. Skipped when the fixture is absent.
#[test]
fn simplemdb_mdb_opens() {
    let Some(dir) = require_fixtures() else {
        return;
    };
    let mdb_path = dir.join("simplemdb.exe.mdb");
    if !mdb_path.exists() {
        eprintln!("skipping: {} not found", mdb_path.display());
        return;
    }
    let bytes = std::fs::read(&mdb_path)
        .unwrap_or_else(|e| panic!("simplemdb.exe.mdb: read failed: {e:?}"));
    let mdb =
        cecli_mdb::reader::MdbReader::open(&bytes).expect("simplemdb.exe.mdb: open failed");
    assert!(
        !mdb.methods().is_empty(),
        "simplemdb.exe.mdb: opened but contains no method entries"
    );
}
