//! Diagnostic write-stage timings and allocation counts, separate from baseline benchmarks.
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use cecil::model::types::{MethodRef, ROperand};
use cecil::write::{emit_il, emit_metadata, resources, token_map::TokenMap};
use cecil::{AssemblyDefinition, MethodId};
use cecil_core::io::ByteWriter;
use cecil_core::TableIndex;
use cecil_metadata::{MetadataBuilder, MetadataReader};

struct CountingAllocator;
static ENABLED: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

fn record(size: usize) {
    if ENABLED.load(Ordering::Relaxed) {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(size as u64, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn stage<T>(label: &str, counted: bool, run: impl FnOnce() -> T) -> T {
    ALLOCS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    ENABLED.store(counted, Ordering::Relaxed);
    let start = Instant::now();
    let value = run();
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    ENABLED.store(false, Ordering::Relaxed);
    println!("{{\"stage\":\"{label}\",\"counted\":{counted},\"ms\":{elapsed:.6},\"allocations\":{},\"allocated_bytes\":{}}}", ALLOCS.load(Ordering::Relaxed), BYTES.load(Ordering::Relaxed));
    value
}

fn profile(asm: &AssemblyDefinition, counted: bool) {
    let m = asm.main_module();
    let resources =
        stage("resources", counted, || resources::build_resources_blob(&m.resources).unwrap());
    let mut builder = MetadataBuilder::new(&m.runtime_version);
    let mut tmap = TokenMap::new(&mut builder);
    let mut code = ByteWriter::new();
    let mut method_rvas = Vec::new();
    // The test inputs are PE32; this reproduces the production segment positions.
    let code_base = 0x2050u64;
    stage("il", counted, || {
        for (id, method) in m.iter_methods() {
            if let Some(body) = &method.body {
                code.align(4);
                method_rvas.push((id, code_base + code.position() as u64));
                emit_il::encode_body(body, &mut tmap, m, &mut code, &m.sas_blobs).unwrap();
            }
        }
    });
    let layout = emit_metadata::EmitLayout {
        method_rvas,
        resource_offsets: resources.offsets.iter().map(|&o| o as u32).collect(),
        data_segment_rva: (code_base + code.len() as u64).next_multiple_of(8)
            + resources.bytes.len() as u64,
    };
    let emitted = stage("metadata", counted, || {
        emit_metadata::emit_metadata_with(m, Some(&asm.name), asm.entry_point, &layout, tmap)
            .unwrap()
    });
    stage("buffer_drop", counted, || {
        black_box(emitted);
        black_box(code);
        black_box(resources);
    });
    stage("full_write", counted, || {
        black_box(asm.write().unwrap());
    });
}

fn external_method(method: &MethodRef) -> usize {
    match method {
        MethodRef::Def(_) => 0,
        MethodRef::External(_) => 1,
        MethodRef::Spec { method, .. } => external_method(method),
    }
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: write_profile PATH");
    let bytes = std::fs::read(&path).unwrap();
    let asm = AssemblyDefinition::read(&bytes).unwrap();
    let m = asm.main_module();
    let bodies: Vec<_> = m
        .methods
        .iter()
        .enumerate()
        .filter(|(_, m)| m.body.is_some())
        .map(|(i, _)| MethodId(i as u32))
        .collect();
    let mut comparisons = 0u64;
    for i in 0..m.methods.len() {
        comparisons +=
            bodies.iter().position(|id| id.index() == i).map_or(bodies.len(), |p| p + 1) as u64;
    }
    let instructions: usize =
        m.methods.iter().filter_map(|m| m.body.as_ref()).map(|b| b.instructions.len()).sum();
    let external_methods: usize = m
        .methods
        .iter()
        .filter_map(|m| m.body.as_ref())
        .flat_map(|b| &b.instructions)
        .map(|i| match &i.operand {
            ROperand::Method(method) => external_method(method),
            _ => 0,
        })
        .sum();
    let image = cecil_pe::Image::parse(&bytes).unwrap();
    let (rva, size) = image.metadata_rva().unwrap();
    let md = image.rva(rva).unwrap();
    let md = MetadataReader::parse(&md[..size]).unwrap();
    println!("{{\"input\":\"{}\",\"methods\":{},\"bodies\":{},\"instructions\":{instructions},\"rva_comparisons\":{comparisons},\"external_method_operands\":{external_methods},\"original_member_refs\":{},\"external_value_types\":{},\"instruction_size\":{}}}", path.replace('\\', "/"), m.methods.len(), bodies.len(), md.row_count(TableIndex::MemberRef), m.external_value_types.len(), std::mem::size_of::<cecil::model::types::RInstruction>());
    for _ in 0..3 {
        black_box(asm.write().unwrap());
    }
    for _ in 0..5 {
        profile(&asm, false);
    }
    profile(&asm, true);
}
