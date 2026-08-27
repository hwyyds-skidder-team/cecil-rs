//! Criterion benchmarks: real-fixture read/write/roundtrip throughput plus
//! a synthetic doubling-DAG regression bench guarding the image-linear
//! TypeSpec handling (previously exponential: 30 rows once OOM'd the
//! process).
//!
//! Run with `cargo bench -p cecli`. Fixtures resolve through the same
//! `CARGO_MANIFEST_DIR/../../fixtures` layout as the test suite; a missing
//! fixture is skipped with a note, so the bench still runs from a checkout
//! without the corpus.

use std::path::PathBuf;

use cecli::AssemblyDefinition;
use cecli_core::TableIndex;
use cecli_metadata::{MetadataBuilder, MetadataReader};
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

/// Representative size ladder; entries missing from fixtures/ are skipped.
const FIXTURES: &[&str] = &[
    "hello.exe",          // tiny
    "cecil.dll",          // medium
    "SQLite-net.dll",     // medium-large
    "System.Runtime.dll", // large
];

// ---------------------------------------------------------------------------
// Fixture benchmarks
// ---------------------------------------------------------------------------

fn bench_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("read");
    for name in FIXTURES {
        let path = fixtures_dir().join(name);
        let Ok(bytes) = std::fs::read(&path) else {
            println!("skipping {name}: fixture not found");
            continue;
        };
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &bytes, |b, bytes| {
            b.iter(|| AssemblyDefinition::read(bytes).expect("fixture must parse"))
        });
    }
    group.finish();
}

fn bench_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("write");
    for name in FIXTURES {
        let path = fixtures_dir().join(name);
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let asm = AssemblyDefinition::read(&bytes).expect("fixture must parse");
        let out_len = asm.write().expect("write must succeed").len();
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_function(*name, |b| b.iter(|| asm.write().expect("write must succeed")));
    }
    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");
    for name in FIXTURES {
        let path = fixtures_dir().join(name);
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &bytes, |b, bytes| {
            b.iter(|| {
                let asm = AssemblyDefinition::read(bytes).expect("fixture must parse");
                asm.write().expect("write must succeed")
            })
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Doubling-DAG regression bench
// ---------------------------------------------------------------------------

/// Synthetic metadata root whose TypeSpec rows form a sharing DAG (row K
/// references row K-1 twice); ~2^rows nodes fully expanded. Mirrors the
/// `read::context` regression tests.
fn build_dag_md(rows: u32) -> Vec<u8> {
    let mut b = MetadataBuilder::new("v4.0.30319");
    let mname = b.insert_string("<Module>");
    let mvid = b.insert_guid(&[7u8; 16]);
    b.add_row(TableIndex::Module, &[0, mname as u64, mvid as u64, 0, 0]).unwrap();
    let def_name = b.insert_string("Mine");
    let def_ns = b.insert_string("TestNs");
    b.add_row(TableIndex::TypeDef, &[0x0010_0001, def_name as u64, def_ns as u64, 0, 1, 1])
        .unwrap();

    let td_cell: u8 = 4; // TypeDef rid 1, tag 0
    for k in 1..=rows {
        let blob = if k == 1 {
            vec![0x1D, 0x08] // SZARRAY of I4
        } else {
            let prev = ((k - 1) << 2) | 2; // TypeSpec tag 2, rid k-1
            vec![0x1D, 0x15, 0x12, td_cell, 0x02, 0x12, prev as u8, 0x12, prev as u8]
        };
        let idx = b.insert_blob(&blob);
        b.add_row(TableIndex::TypeSpec, &[idx as u64]).unwrap();
    }
    b.finalize()
}

/// Parse + eager TypeSpec resolution over doubling DAGs of growing depth.
/// Time must scale linearly with `rows`; pre-Arc this was exponential
/// (24 rows = ~16M expanded nodes, 30 rows OOM'd).
fn bench_dag(c: &mut Criterion) {
    let mut group = c.benchmark_group("dag_read");
    for rows in [16u32, 20, 24, 28] {
        let image = build_dag_md(rows);
        group.throughput(Throughput::Bytes(image.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(rows), &image, |b, image| {
            b.iter_batched(
                || image.clone(),
                |image| {
                    let md = MetadataReader::parse(&image).expect("synthetic root parses");
                    let mut ctx = cecli::read::context::ReadContext::new(&md);
                    ctx.type_defs.push(cecli::TypeId(0));
                    ctx.resolve_lazy_tables(&md).expect("DAG resolves");
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(benches, bench_read, bench_write, bench_roundtrip, bench_dag);
criterion_main!(benches);
