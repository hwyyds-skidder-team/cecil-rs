use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use cecli::read::context::ReadOptions;
use cecli::read::{instructions, module_reader};
use cecli_core::TableIndex;
use cecli_pe::Image;

struct CountingAllocator;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static BUCKETS: [AtomicU64; 16] = [const { AtomicU64::new(0) }; 16];

fn bucket(size: usize) -> usize {
    if size == 0 {
        0
    } else {
        (usize::BITS - size.leading_zeros()).min(15) as usize
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        BUCKETS[bucket(layout.size())].fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        BUCKETS[bucket(new_size)].fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn reset() {
    ALLOCS.store(0, Ordering::Relaxed);
    BYTES.store(0, Ordering::Relaxed);
    for b in &BUCKETS {
        b.store(0, Ordering::Relaxed);
    }
}

fn report(label: &str, started: Instant) {
    println!(
        "{label:18} {:8.3} ms  {:8} allocs  {:10} bytes",
        started.elapsed().as_secs_f64() * 1_000.0,
        ALLOCS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
    );
    println!(
        "  buckets 2^n: {:?}",
        BUCKETS.iter().map(|b| b.load(Ordering::Relaxed)).collect::<Vec<_>>()
    );
}

fn main() {
    println!(
        "RInstruction size {} ROperand {}",
        std::mem::size_of::<cecli::model::types::RInstruction>(),
        std::mem::size_of::<cecli::model::types::ROperand>()
    );
    let path = std::env::args().nth(1).unwrap_or_else(|| "fixtures/cecil.dll".into());
    let bytes = std::fs::read(path).unwrap();

    reset();
    let started = Instant::now();
    let image = Image::parse(&bytes).unwrap();
    report("pe", started);

    reset();
    let started = Instant::now();
    let (mut module, mut ctx) =
        module_reader::read_module(&image, &ReadOptions::default()).unwrap();
    report("model", started);

    let (md_rva, _) = image.metadata_rva().unwrap();
    let md_slice = image.rva(md_rva).unwrap();
    let md = cecli_metadata::MetadataReader::parse(md_slice.as_ref()).unwrap();
    for table in [
        TableIndex::TypeDef,
        TableIndex::Field,
        TableIndex::MethodDef,
        TableIndex::Param,
        TableIndex::InterfaceImpl,
        TableIndex::MemberRef,
        TableIndex::CustomAttribute,
        TableIndex::Property,
        TableIndex::Event,
        TableIndex::GenericParam,
        TableIndex::MethodSpec,
    ] {
        println!("{:24} {}", table.name(), md.row_count(table));
    }
    reset();
    let started = Instant::now();
    instructions::resolve_bodies_opts(&mut module, &mut ctx, &md, &image, true).unwrap();
    report("bodies", started);
    let mut methods = 0usize;
    let mut instructions = 0usize;
    let mut code = 0usize;
    for m in &module.methods {
        if let Some(body) = &m.body {
            methods += 1;
            instructions += body.instructions.len();
            code += body
                .instructions
                .iter()
                .map(|i| {
                    i.opcode.size as usize
                        + match &i.operand {
                            cecli::model::types::ROperand::Switch(v) => 4 * (1 + v.len()),
                            cecli::model::types::ROperand::Branch(_) => match i.opcode.operand_type
                            {
                                cecli_cil::OperandType::ShortInlineBrTarget => 1,
                                _ => 4,
                            },
                            _ => i.opcode.operand_type.size().unwrap_or(4),
                        }
                })
                .sum::<usize>();
        }
    }
    println!(
        "bodies {} instructions {} code {} avg {:.2}",
        methods,
        instructions,
        code,
        code as f64 / instructions as f64
    );
}
