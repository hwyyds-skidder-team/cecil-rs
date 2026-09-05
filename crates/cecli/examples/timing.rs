use std::hint::black_box;
use std::time::{Duration, Instant};

use cecli::resolver::{ReaderParameters, ReadingMode};
use cecli::AssemblyDefinition;
use cecli_core::TableIndex;

fn stats(mut values: Vec<Duration>) -> (f64, f64, f64) {
    values.sort_unstable();
    let n = values.len();
    let sum: f64 = values.iter().map(Duration::as_secs_f64).sum();
    (
        values[0].as_secs_f64() * 1000.0,
        values[n / 2].as_secs_f64() * 1000.0,
        sum / n as f64 * 1000.0,
    )
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "fixtures/cecil.dll".into());
    let bytes = std::fs::read(path).unwrap();
    for _ in 0..3 {
        black_box(AssemblyDefinition::read(&bytes).unwrap());
    }
    let mut full = Vec::with_capacity(20);
    for _ in 0..20 {
        let start = Instant::now();
        black_box(AssemblyDefinition::read(&bytes).unwrap());
        full.push(start.elapsed());
    }
    let (min, med, avg) = stats(full);
    println!("full min={min:.3} median={med:.3} avg={avg:.3} ms");

    let mut opts = ReaderParameters::new();
    opts.reading_mode = ReadingMode::Lazy;
    let mut model = Vec::with_capacity(20);
    let mut body = Vec::with_capacity(20);
    for _ in 0..20 {
        let start = Instant::now();
        let mut asm = AssemblyDefinition::read_with(&bytes, &opts).unwrap();
        model.push(start.elapsed());
        let start = Instant::now();
        black_box(asm.load_bodies().unwrap());
        body.push(start.elapsed());
    }
    let (min, med, avg) = stats(model);
    println!("model min={min:.3} median={med:.3} avg={avg:.3} ms");
    let (min, med, avg) = stats(body);
    println!("body min={min:.3} median={med:.3} avg={avg:.3} ms");

    let image = cecli_pe::Image::parse(&bytes).unwrap();
    let (rva, _) = image.metadata_rva().unwrap();
    let md_bytes = image.rva(rva).unwrap();
    let md = cecli_metadata::MetadataReader::parse(md_bytes.as_ref()).unwrap();
    let mut raw = Vec::with_capacity(20);
    for _ in 0..20 {
        let start = Instant::now();
        let mut count = 0usize;
        for rid in 1..=md.row_count(TableIndex::MethodDef) {
            let rva = md.column(TableIndex::MethodDef, rid, 0).unwrap();
            if rva == 0 { continue; }
            let body = image.rva(rva).unwrap();
            let header = cecli_cil::parse_body_header(&body).unwrap();
            let header_len = if header.fat { 12 } else { 1 };
            let code = cecli_cil::read_code(&body[header_len..], header.code_size as usize).unwrap();
            count += code.len();
            black_box(code);
        }
        black_box(count);
        raw.push(start.elapsed());
    }
    let (min, med, avg) = stats(raw);
    println!("raw_il min={min:.3} median={med:.3} avg={avg:.3} ms");
}
