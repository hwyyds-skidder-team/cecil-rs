//! Memory-only comparison driver; see scripts/compare-cecil/README.md.
use std::hint::black_box;
use std::time::Instant;

use cecil::model::types::*;
use cecil::{AssemblyDefinition, Module, Resource};

// Match the release CLI's allocator. The library itself never installs one.
#[cfg(feature = "fast-allocator")]
#[global_allocator]
static ALLOCATOR: cecil::MiMalloc = cecil::MiMalloc;

#[derive(Debug, PartialEq, Eq)]
struct Counts {
    types: usize,
    methods: usize,
    fields: usize,
    properties: usize,
    events: usize,
    attributes: usize,
    bodies: usize,
    instructions: usize,
    locals: usize,
    handlers: usize,
}

impl Counts {
    fn read(asm: &AssemblyDefinition) -> Self {
        let m = asm.main_module();
        let mut c = Self {
            types: m.types.len(),
            methods: m.methods.len(),
            fields: m.fields.len(),
            properties: m.properties.len(),
            events: m.events.len(),
            attributes: asm.name.custom_attributes.len() + m.custom_attributes.len(),
            bodies: 0,
            instructions: 0,
            locals: 0,
            handlers: 0,
        };
        for t in &m.types {
            c.attributes += t.custom_attributes.len();
            for interface in &t.interfaces {
                c.attributes += interface.custom_attributes.len();
            }
        }
        for method in &m.methods {
            c.attributes +=
                method.custom_attributes.len() + method.return_parameter.custom_attributes.len();
            for p in &method.parameters {
                c.attributes += p.custom_attributes.len();
            }
            if let Some(b) = &method.body {
                c.bodies += 1;
                c.instructions += b.instructions.len();
                c.locals += b.locals.len();
                c.handlers += b.exception_handlers.len();
            }
        }
        c.attributes += m.fields.iter().map(|f| f.custom_attributes.len()).sum::<usize>();
        c.attributes += m.properties.iter().map(|p| p.custom_attributes.len()).sum::<usize>();
        c.attributes += m.events.iter().map(|e| e.custom_attributes.len()).sum::<usize>();
        c.attributes += m.assembly_refs.iter().map(|r| r.custom_attributes.len()).sum::<usize>();
        for g in &m.generic_parameters {
            c.attributes += g.custom_attributes.len();
            for constraint in &g.constraints {
                c.attributes += constraint.custom_attributes.len();
            }
        }
        c
    }

    fn json(&self) -> String {
        format!(
            "{{\"types\":{},\"methods\":{},\"fields\":{},\"properties\":{},\"events\":{},\"attributes\":{},\"bodies\":{},\"instructions\":{},\"locals\":{},\"handlers\":{}}}",
            self.types, self.methods, self.fields, self.properties, self.events,
            self.attributes, self.bodies, self.instructions, self.locals, self.handlers
        )
    }
}

// Validation only. Each reader has its own canonical representation: comparisons
// are made within a reader, across the original and BOTH writers' images. This
// catches writer drift without assuming Cecil and Rust expose identical models.
// No token, RID, RVA, heap index, MVID or original instruction offset is hashed.
#[derive(Debug, PartialEq, Eq)]
struct Semantics {
    metadata: Vec<String>,
    bodies: Vec<String>,
}

fn row(tag: &str, values: impl IntoIterator<Item = String>) -> String {
    let mut text = tag.to_owned();
    for value in values {
        use std::fmt::Write;
        write!(text, "|{}:{value}", value.len()).unwrap();
    }
    text
}

fn assembly_ref(a: &AssemblyNameReference) -> String {
    format!("{:?}", (&a.name, a.version, &a.culture, &a.public_key_or_token, a.attributes.bits()))
}

fn external_type(t: &ExternalType) -> String {
    let scope = match &t.scope {
        ScopeRef::ThisModule => "module".into(),
        ScopeRef::OtherModule(n) => format!("module:{n:?}"),
        ScopeRef::Assembly(a) => assembly_ref(a),
        ScopeRef::Moduleless => "none".into(),
    };
    row(
        "type",
        [
            t.namespace.clone(),
            t.name.clone(),
            row("nesting", t.nesting.iter().map(|p| external_type(p))),
            scope,
        ],
    )
}

fn ty(m: &Module, t: &TypeDesc) -> String {
    match t {
        TypeDesc::Def(id) => format!("def:{:?}", m.type_full_name(*id)),
        TypeDesc::External(t) => external_type(t),
        TypeDesc::SzArray(t) => format!("szarray({})", ty(m, t)),
        TypeDesc::Array { element, sizes, lobounds } => {
            format!("array({},{sizes:?},{lobounds:?})", ty(m, element))
        }
        TypeDesc::Ptr(t) => format!("ptr({})", ty(m, t)),
        TypeDesc::ByRef(t) => format!("byref({})", ty(m, t)),
        TypeDesc::Pinned(t) => format!("pinned({})", ty(m, t)),
        TypeDesc::GenericInstance { definition, arguments } => row(
            "generic",
            [ty(m, definition), row("arguments", arguments.iter().map(|a| ty(m, a)))],
        ),
        TypeDesc::Var(i) => format!("!{i}"),
        TypeDesc::MVar(i) => format!("!!{i}"),
        TypeDesc::FnPtr(s) => format!("fnptr({})", sig(m, s)),
        TypeDesc::CMod { required, modifier, unmodified } => {
            format!("modifier({required},{},{})", ty(m, modifier), ty(m, unmodified))
        }
        TypeDesc::Sentinel => "sentinel".into(),
        TypeDesc::TypedByRef => "typedbyref".into(),
        TypeDesc::Internal(n) => format!("internal:{n:?}"),
    }
}

fn sig(m: &Module, s: &MethodSignature) -> String {
    row(
        "signature",
        [
            s.has_this.to_string(),
            s.explicit_this.to_string(),
            format!("{:?}", s.convention),
            s.generic_count.to_string(),
            ty(m, &s.return_type),
            row("parameters", s.parameters.iter().map(|p| ty(m, p))),
            s.vararg_start.to_string(),
        ],
    )
}

fn method_ref(m: &Module, r: &MethodRef) -> String {
    match r {
        MethodRef::Def(id) => {
            let d = m.method_def(*id);
            row(
                "method",
                [m.type_full_name(d.declaring_type), d.name.clone(), sig(m, &d.signature)],
            )
        }
        MethodRef::External(d) => {
            row("external-method", [ty(m, &d.parent), d.name.clone(), sig(m, &d.signature)])
        }
        MethodRef::Spec { method, arguments } => row(
            "method-spec",
            [method_ref(m, method), row("arguments", arguments.iter().map(|a| ty(m, a)))],
        ),
    }
}

fn field_ref(m: &Module, owners: &[String], r: &FieldRef) -> String {
    match r {
        FieldRef::Def(id) => {
            let f = m.field_def(*id);
            format!("field:{:?}", (&owners[id.index()], &f.name, ty(m, &f.signature.0)))
        }
        FieldRef::External(f) => {
            format!("external-field:{:?}", (ty(m, &f.parent), &f.name, ty(m, &f.signature.0)))
        }
    }
}

fn constant(c: &Option<ConstantValue>) -> String {
    match c {
        Some(ConstantValue::F32(v)) => format!("f32:{:08x}", v.to_bits()),
        Some(ConstantValue::F64(v)) => format!("f64:{:016x}", v.to_bits()),
        _ => format!("{c:?}"),
    }
}

fn attributes(m: &Module, records: &mut Vec<String>, owner: &str, attrs: &[CustomAttribute]) {
    for a in attrs {
        records.push(format!("attribute:{:?}", (owner, method_ref(m, &a.constructor), &a.blob)));
    }
}

fn security(records: &mut Vec<String>, owner: &str, declarations: &[SecurityDeclaration]) {
    for d in declarations {
        records.push(format!("security:{:?}", (owner, d.action, &d.blob)));
    }
}

fn parameter(m: &Module, records: &mut Vec<String>, owner: &str, p: &Parameter) {
    records.push(format!(
        "parameter:{:?}",
        (owner, &p.name, p.attributes.bits(), constant(&p.constant))
    ));
    attributes(m, records, owner, &p.custom_attributes);
}

impl Semantics {
    fn read(asm: &AssemblyDefinition) -> Self {
        let m = asm.main_module();
        let mut metadata = vec![
            format!(
                "assembly:{:?}",
                (
                    &asm.name.name,
                    asm.name.version,
                    &asm.name.culture,
                    &asm.name.public_key,
                    asm.name.attributes.bits()
                )
            ),
            format!("module:{:?}", (&m.name, m.kind, m.architecture, &m.runtime_version)),
        ];
        let mut bodies = Vec::new();
        attributes(m, &mut metadata, "assembly", &asm.name.custom_attributes);
        attributes(m, &mut metadata, "module", &m.custom_attributes);
        security(&mut metadata, "assembly", &asm.name.security_declarations);
        if let Some(entry) = asm.entry_point {
            metadata.push(format!("entry:{}", method_ref(m, &MethodRef::Def(entry))));
        }
        for a in &m.assembly_refs {
            let owner = format!("assembly-ref:{}", assembly_ref(a));
            metadata.push(owner.clone());
            attributes(m, &mut metadata, &owner, &a.custom_attributes);
        }
        for name in &m.module_refs {
            metadata.push(format!("module-ref:{name:?}"));
        }
        for r in &m.resources {
            metadata.push(match r {
                Resource::Embedded { name, attributes, data } => {
                    format!("embedded:{:?}", (name, attributes.bits(), data))
                }
                Resource::Linked { name, attributes, file } => {
                    format!("linked:{:?}", (name, attributes.bits(), file))
                }
                Resource::AssemblyLinked { name, attributes, assembly } => {
                    format!(
                        "assembly-linked:{:?}",
                        (name, attributes.bits(), assembly_ref(assembly))
                    )
                }
            });
        }
        let mut field_owners = vec![String::new(); m.fields.len()];
        for (id, t) in m.iter_types() {
            let name = m.type_full_name(id);
            for f in &t.fields {
                field_owners[f.index()] = name.clone();
            }
            metadata.push(format!(
                "type:{:?}",
                (
                    &name,
                    t.attributes.bits(),
                    t.base_type.as_ref().map(|b| ty(m, b)),
                    t.class_layout
                )
            ));
            attributes(m, &mut metadata, &name, &t.custom_attributes);
            security(&mut metadata, &name, &t.security_declarations);
            for i in &t.interfaces {
                let owner = format!("interface:{:?}", (&name, ty(m, &i.interface)));
                metadata.push(owner.clone());
                attributes(m, &mut metadata, &owner, &i.custom_attributes);
            }
            for f in &t.fields {
                let f = m.field_def(*f);
                let owner = format!("field:{:?}", (&name, &f.name, ty(m, &f.signature.0)));
                metadata.push(format!(
                    "{owner}:{:?}",
                    (f.attributes.bits(), &f.initial_value, constant(&f.constant), f.offset)
                ));
                attributes(m, &mut metadata, &owner, &f.custom_attributes);
            }
            for p in &t.properties {
                let p = m.property_def(*p);
                let owner = format!(
                    "property:{:?}",
                    (
                        &name,
                        &p.name,
                        p.signature.has_this,
                        ty(m, &p.signature.property_type),
                        p.signature.parameters.iter().map(|p| ty(m, p)).collect::<Vec<_>>()
                    )
                );
                metadata.push(format!(
                    "{owner}:{:?}",
                    (
                        p.attributes.bits(),
                        constant(&p.constant),
                        p.get_method.map(|id| method_ref(m, &MethodRef::Def(id))),
                        p.set_method.map(|id| method_ref(m, &MethodRef::Def(id))),
                        p.other_methods
                            .iter()
                            .map(|id| method_ref(m, &MethodRef::Def(*id)))
                            .collect::<Vec<_>>()
                    )
                ));
                attributes(m, &mut metadata, &owner, &p.custom_attributes);
            }
            for e in &t.events {
                let e = m.event_def(*e);
                let owner = format!(
                    "event:{:?}",
                    (&name, &e.name, e.event_type.as_ref().map(|t| ty(m, t)))
                );
                metadata.push(format!(
                    "{owner}:{:?}",
                    (
                        e.attributes.bits(),
                        e.add_on.map(|id| method_ref(m, &MethodRef::Def(id))),
                        e.remove_on.map(|id| method_ref(m, &MethodRef::Def(id))),
                        e.fire.map(|id| method_ref(m, &MethodRef::Def(id))),
                        e.other_methods
                            .iter()
                            .map(|id| method_ref(m, &MethodRef::Def(*id)))
                            .collect::<Vec<_>>()
                    )
                ));
                attributes(m, &mut metadata, &owner, &e.custom_attributes);
            }
        }
        for (id, d) in m.iter_methods() {
            let owner = method_ref(m, &MethodRef::Def(id));
            metadata.push(format!(
                "{owner}:{:?}",
                (d.attributes.bits(), d.impl_attributes.bits(), &d.pinvoke)
            ));
            attributes(m, &mut metadata, &owner, &d.custom_attributes);
            security(&mut metadata, &owner, &d.security_declarations);
            parameter(m, &mut metadata, &format!("{owner}:return"), &d.return_parameter);
            for (i, p) in d.parameters.iter().enumerate() {
                parameter(m, &mut metadata, &format!("{owner}:param:{i}"), p);
            }
            for o in &d.overrides {
                metadata.push(format!("override:{:?}", (&owner, method_ref(m, &o.declaration))));
            }
            if let Some(b) = &d.body {
                let mut offsets = std::collections::BTreeMap::new();
                for (i, instruction) in b.instructions.iter().enumerate() {
                    offsets.insert(instruction.offset, i);
                }
                if let Some(last) = b.instructions.last() {
                    let size = match &last.operand {
                        ROperand::Switch(t) => last.opcode.size as usize + 4 * (1 + t.len()),
                        _ => cecil_cil::instruction_size(last.opcode),
                    };
                    offsets.insert(last.offset + size as i32, b.instructions.len());
                }
                let target = |offset: i32| {
                    *offsets.get(&offset).unwrap_or_else(|| {
                        panic!("non-instruction control-flow target {offset} in {owner}")
                    })
                };
                let instructions = b
                    .instructions
                    .iter()
                    .map(|i| {
                        let operand = match &i.operand {
                            ROperand::None => "none".into(),
                            ROperand::Branch(t) => format!("branch:{}", target(*t)),
                            ROperand::Switch(t) => format!(
                                "switch:{:?}",
                                t.iter().map(|t| target(*t)).collect::<Vec<_>>()
                            ),
                            ROperand::Type(t) => ty(m, t),
                            ROperand::Method(r) => method_ref(m, r),
                            ROperand::Field(r) => field_ref(m, &field_owners, r),
                            ROperand::Float32(f) => format!("f32:{:08x}", f.to_bits()),
                            ROperand::Float64(f) => format!("f64:{:016x}", f.to_bits()),
                            ROperand::CallSite(s) => format!("callsite:{}", sig(m, s)),
                            ROperand::Token(_) | ROperand::UserString(_) | ROperand::Rva(_) => {
                                panic!(
                                    "unresolved IL operand in semantic validation: {owner}: {i:?}"
                                )
                            }
                            other => format!("{other:?}"),
                        };
                        format!("{} {operand}", i.opcode.name)
                    })
                    .collect::<Vec<_>>();
                let mut handlers = b
                    .exception_handlers
                    .iter()
                    .map(|h| {
                        (
                            h.kind,
                            target(h.try_offset),
                            target(h.try_offset + h.try_length),
                            target(h.handler_offset),
                            target(h.handler_offset + h.handler_length),
                            if h.kind == ExceptionKind::Filter {
                                Some(target(h.filter_offset))
                            } else {
                                None
                            },
                            h.catch_type.as_ref().map(|t| ty(m, t)),
                        )
                    })
                    .collect::<Vec<_>>();
                // EH rows for different try regions may be reordered. The CLR
                // tests catches/filters sharing ONE try region in table order,
                // so stable sorting preserves that significant precedence.
                handlers.sort_by_key(|h| (h.1, h.2));
                bodies.push(format!(
                    "body:{:?}",
                    (
                        &owner,
                        b.init_locals,
                        b.locals.iter().map(|l| (ty(m, &l.ty), l.pinned)).collect::<Vec<_>>(),
                        instructions,
                        handlers
                    )
                ));
            } else {
                bodies.push(format!("no-body:{owner}"));
            }
        }
        for g in &m.generic_parameters {
            let owner = match g.owner {
                GenericOwner::Type(t) => m.type_full_name(t),
                GenericOwner::Method(d) => method_ref(m, &MethodRef::Def(d)),
            };
            let owner = format!("generic:{:?}", (owner, g.position));
            metadata.push(format!("{owner}:{:?}", (&g.name, g.attributes.bits())));
            attributes(m, &mut metadata, &owner, &g.custom_attributes);
            for c in &g.constraints {
                let owner = format!("constraint:{:?}", (&owner, ty(m, &c.constraint)));
                metadata.push(owner.clone());
                attributes(m, &mut metadata, &owner, &c.custom_attributes);
            }
        }
        metadata.sort_unstable();
        bodies.sort_unstable();
        Self { metadata, bodies }
    }

    fn hash(records: &[String]) -> String {
        // Stable FNV-1a-128, an accidental-corruption guard, not a security hash.
        let mut h = 0x6c62272e07bb014262b821756295c58du128;
        for record in records {
            for byte in record.bytes().chain(std::iter::once(b'\n')) {
                h = (h ^ byte as u128).wrapping_mul(0x0000000001000000000000000000013bu128);
            }
        }
        format!("{h:032x}")
    }

    fn json(&self) -> String {
        format!("{{\"scheme\":\"rust-model-v1-fnv1a128\",\"metadata\":\"{}\",\"bodies\":\"{}\",\"metadata_records\":{},\"body_records\":{}}}",
            Self::hash(&self.metadata), Self::hash(&self.bodies), self.metadata.len(), self.bodies.len())
    }

    fn assert_same(&self, after: &Self) {
        for (label, before, after) in
            [("metadata", &self.metadata, &after.metadata), ("bodies", &self.bodies, &after.bodies)]
        {
            if before != after {
                let first = before
                    .iter()
                    .zip(after)
                    .position(|(a, b)| a != b)
                    .unwrap_or(before.len().min(after.len()));
                let old = before.get(first).map_or("<end>", String::as_str);
                let new = after.get(first).map_or("<end>", String::as_str);
                let at = old
                    .bytes()
                    .zip(new.bytes())
                    .position(|(a, b)| a != b)
                    .unwrap_or(old.len().min(new.len()));
                let context = |s: &str| {
                    String::from_utf8_lossy(
                        &s.as_bytes()[at.saturating_sub(120).min(s.len())..(at + 200).min(s.len())],
                    )
                    .into_owned()
                };
                panic!("semantic {label} changed at record {first}, byte {at}: before {:?}; after {:?}", context(old), context(new));
            }
        }
    }
}

fn operation(mode: &str, bytes: &[u8], loaded: &AssemblyDefinition) {
    match mode {
        "read" => {
            let asm = AssemblyDefinition::read(black_box(bytes)).expect("read failed");
            black_box(Counts::read(&asm));
            black_box(asm);
        }
        "write" => {
            black_box(loaded.write().expect("write failed"));
        }
        "roundtrip" => {
            let asm = AssemblyDefinition::read(black_box(bytes)).expect("read failed");
            black_box(Counts::read(&asm));
            black_box(asm.write().expect("write failed"));
        }
        _ => panic!("unknown mode: {mode}"),
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(args.len() >= 3, "usage: compare_cecil MODE PATH [SAMPLES SAMPLE_MS WARMUP_MS OUTPUT]");
    let mode = &args[1];
    let bytes = std::fs::read(&args[2]).expect("input read failed");
    let loaded = AssemblyDefinition::read(&bytes).expect("initial parse failed");
    let counts = Counts::read(&loaded);
    if mode == "validate" || mode == "inspect" {
        let semantics = Semantics::read(&loaded);
        if let Some(path) = args.get(7) {
            let text = semantics
                .metadata
                .iter()
                .chain(&semantics.bodies)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(path, text).expect("semantic dump failed");
        }
        if mode == "inspect" {
            println!("{{\"implementation\":\"cecil-rs\",\"mode\":\"inspect\",\"input_bytes\":{},\"counts\":{},\"semantics\":{}}}", bytes.len(), counts.json(), semantics.json());
            return;
        }
        let out = loaded.write().expect("write failed");
        if let Some(path) = args.get(6) {
            std::fs::write(path, &out).unwrap();
        }
        let after = AssemblyDefinition::read(&out).expect("output read failed");
        assert_eq!(counts, Counts::read(&after), "counts changed on roundtrip");
        semantics.assert_same(&Semantics::read(&after));
        println!("{{\"implementation\":\"cecil-rs\",\"mode\":\"validate\",\"input_bytes\":{},\"output_bytes\":{},\"counts\":{},\"semantics\":{}}}", bytes.len(), out.len(), counts.json(), semantics.json());
        return;
    }
    let samples: usize = args.get(3).map_or(11, |v| v.parse().unwrap());
    let sample_ms: f64 = args.get(4).map_or(120.0, |v| v.parse().unwrap());
    let warmup_ms: f64 = args.get(5).map_or(800.0, |v| v.parse().unwrap());
    assert!(samples > 0 && sample_ms > 0.0 && warmup_ms > 0.0);
    let start = Instant::now();
    let mut warmup_ops = 0;
    while start.elapsed().as_secs_f64() * 1000.0 < warmup_ms {
        operation(mode, &bytes, &loaded);
        warmup_ops += 1;
    }
    let estimate = start.elapsed().as_secs_f64() * 1000.0 / warmup_ops as f64;
    let iterations = ((sample_ms / estimate).ceil() as usize).clamp(1, 1_000_000);
    let mut values = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..iterations {
            operation(mode, &bytes, &loaded);
        }
        values.push(start.elapsed().as_secs_f64() * 1e6 / iterations as f64);
    }
    let raw = values.iter().map(|v| format!("{v:.6}")).collect::<Vec<_>>().join(",");
    println!("{{\"implementation\":\"cecil-rs\",\"mode\":\"{mode}\",\"input_bytes\":{},\"iterations_per_sample\":{iterations},\"warmup_ops\":{warmup_ops},\"counts\":{},\"samples_us\":[{raw}]}}", bytes.len(), counts.json());
}
