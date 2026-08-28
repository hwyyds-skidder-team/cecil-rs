//! Shared helpers for the fixture acceptance suite (`fixtures_roundtrip.rs`).
//!
//! Everything here is deterministic and side-effect free unless documented
//! (the temp-directory helper owns the directory it creates).

use cecli::model::types::{CustomAttribute, MethodRef, TypeDesc};
use cecli::module_def::Module;
use std::collections::BTreeSet;
use std::path::PathBuf;

/// Extensions that make up the roundtrip sweep set
/// (`fixtures/*.exe|dll|netmodule`, case-insensitive).
pub const SWEEP_EXTENSIONS: [&str; 3] = ["exe", "dll", "netmodule"];

/// Workspace-level `fixtures/` directory (via `cecli_core`, per contract).
pub fn fixtures_dir() -> PathBuf {
    cecli_core::fixtures_dir()
}

/// Returns the fixtures directory, or `None` after printing a clear skip
/// message when it is missing. Every test starts with this guard so the
/// suite degrades to a skip instead of failing on a checkout without
/// fixtures.
pub fn require_fixtures() -> Option<PathBuf> {
    let dir = fixtures_dir();
    if dir.is_dir() {
        Some(dir)
    } else {
        eprintln!("skipping: fixtures directory {} not found", dir.display());
        None
    }
}

/// Sorted list of every `*.exe|dll|netmodule` under [`fixtures_dir`].
///
/// Sorted for determinism: panic messages and the accumulated attribute-name
/// set must not depend on `read_dir` order.
pub fn roundtrip_fixtures(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("fixtures directory {}: {e:?}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            let ext = path.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase());
            ext.is_some() && SWEEP_EXTENSIONS.contains(&ext.unwrap().as_str())
        })
        .collect();
    files.sort();
    files
}

/// Creates (recreating if present) a process-private output directory under
/// the system temp dir; tests write roundtrip outputs there.
pub fn temp_output_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cecli-fixtures-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|e| panic!("create temp dir {}: {e:?}", dir.display()));
    dir
}

/// Member-count snapshot of one module, compared across write -> re-parse.
///
/// Scope note: custom attributes counted over every slot the frozen model
/// keeps them on (types, methods incl. parameter slots, fields, properties,
/// events, generic parameters, interface implementations, generic parameter
/// constraints, module row, assembly references). Assembly-level attribute
/// rows live on `AssemblyNameDefinition`, outside the module, and are not
/// counted here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counts {
    pub types: usize,
    pub methods: usize,
    pub fields: usize,
    pub properties: usize,
    pub events: usize,
    pub custom_attributes: usize,
    pub resources: usize,
}

impl Counts {
    pub fn snapshot(module: &Module) -> Self {
        let mut custom_attributes = 0usize;
        for ty in &module.types {
            custom_attributes += ty.custom_attributes.len();
            for iface in &ty.interfaces {
                custom_attributes += iface.custom_attributes.len();
            }
        }
        for m in &module.methods {
            custom_attributes += m.custom_attributes.len();
            custom_attributes += m.return_parameter.custom_attributes.len();
            for p in &m.parameters {
                custom_attributes += p.custom_attributes.len();
            }
        }
        for f in &module.fields {
            custom_attributes += f.custom_attributes.len();
        }
        for p in &module.properties {
            custom_attributes += p.custom_attributes.len();
        }
        for e in &module.events {
            custom_attributes += e.custom_attributes.len();
        }
        for g in &module.generic_parameters {
            custom_attributes += g.custom_attributes.len();
            for c in &g.constraints {
                custom_attributes += c.custom_attributes.len();
            }
        }
        custom_attributes += module.custom_attributes.len();
        for r in &module.assembly_refs {
            custom_attributes += r.custom_attributes.len();
        }
        Counts {
            types: module.types.len(),
            methods: module.methods.len(),
            fields: module.fields.len(),
            properties: module.properties.len(),
            events: module.events.len(),
            custom_attributes,
            resources: module.resources.len(),
        }
    }
}

/// Declaring-type name of an attribute's constructor, resolved through the
/// module arena when the ctor is a `MethodDef` and through the referenced
/// type otherwise (`.ctor` itself is identical everywhere, so the *type*
/// name is the discriminating part).
pub fn attribute_type_name(attr: &CustomAttribute, module: &Module) -> Option<String> {
    method_ref_type_name(&attr.constructor, module)
}

fn method_ref_type_name(method_ref: &MethodRef, module: &Module) -> Option<String> {
    match method_ref {
        MethodRef::Def(id) => {
            let m = &module.methods[id.index()];
            definition_full_name(module, m.declaring_type)
        }
        MethodRef::External(external) => type_desc_name(module, &external.parent),
        MethodRef::Spec { method, .. } => method_ref_type_name(method, module),
    }
}

fn type_desc_name(module: &Module, ty: &TypeDesc) -> Option<String> {
    match ty {
        TypeDesc::Def(id) => definition_full_name(module, *id),
        TypeDesc::External(external) => Some(external.name.clone()),
        TypeDesc::GenericInstance { definition, .. } => type_desc_name(module, definition),
        _ => None,
    }
}

fn definition_full_name(module: &Module, id: cecli::TypeId) -> Option<String> {
    let ty = module.types.get(id.index())?;
    if ty.namespace.is_empty() {
        Some(ty.name.clone())
    } else {
        Some(format!("{}.{}", ty.namespace, ty.name))
    }
}

/// Distinct attribute constructor declaring-type names over every reachable
/// slot of `module`.
pub fn collect_attribute_type_names(module: &Module) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut push = |attr: &CustomAttribute| {
        if let Some(name) = attribute_type_name(attr, module) {
            names.insert(name);
        }
    };
    for ty in &module.types {
        ty.custom_attributes.iter().for_each(&mut push);
        for iface in &ty.interfaces {
            iface.custom_attributes.iter().for_each(&mut push);
        }
    }
    for m in &module.methods {
        m.custom_attributes.iter().for_each(&mut push);
        m.return_parameter.custom_attributes.iter().for_each(&mut push);
        for p in &m.parameters {
            p.custom_attributes.iter().for_each(&mut push);
        }
    }
    for f in &module.fields {
        f.custom_attributes.iter().for_each(&mut push);
    }
    for p in &module.properties {
        p.custom_attributes.iter().for_each(&mut push);
    }
    for e in &module.events {
        e.custom_attributes.iter().for_each(&mut push);
    }
    for g in &module.generic_parameters {
        g.custom_attributes.iter().for_each(&mut push);
        for c in &g.constraints {
            c.custom_attributes.iter().for_each(&mut push);
        }
    }
    module.custom_attributes.iter().for_each(&mut push);
    for r in &module.assembly_refs {
        r.custom_attributes.iter().for_each(&mut push);
    }
    names
}
