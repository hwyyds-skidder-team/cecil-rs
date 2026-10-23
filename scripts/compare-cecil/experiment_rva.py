"""Build an isolated RVA-index experiment, restoring production source even on failure."""
import json
import subprocess
from pathlib import Path

repo = Path(__file__).resolve().parents[2]
source = repo / "crates/cecil-rs/src/write/emit_metadata.rs"
original = source.read_bytes()
text = original.decode("utf-8")
needle = "    let mut next_field_rid: u32 = 1;"
replacement = """    let mut method_rva_index = vec![0u64; m.methods.len()];
    for &(id, rva) in &layout.method_rvas {
        method_rva_index[id.index()] = rva;
    }
    let mut next_field_rid: u32 = 1;"""
old = """            let rva = layout
                .method_rvas
                .iter()
                .find(|(id, _)| id == mid)
                .map(|(_, rva)| *rva)
                .unwrap_or(0);"""
new = "            let rva = method_rva_index[mid.index()];"
assert text.count(needle) == text.count(old) == 1, "source changed; review experiment first"
patched = text.replace(needle, replacement).replace(old, new)
target = repo / "target/compare-cecil/rva-index-build"
try:
    source.write_bytes(patched.encode("utf-8"))
    subprocess.run(["cargo", "build", "--release", "-p", "cecil-rs", "--example", "compare_cecil",
                    "--target-dir", str(target)], cwd=repo, check=True)
finally:
    source.write_bytes(original)
assert source.read_bytes() == original, "source restoration failed"
baseline = repo / "target/release/examples/compare_cecil.exe"
indexed = target / "release/examples/compare_cecil.exe"
raw = repo / "target/compare-cecil/rva-index-experiment.jsonl"
inputs = [repo / "fixtures/cecil.dll", repo / "target/compare-cecil/roslyn/tasks/netcore/bincore/Microsoft.CodeAnalysis.dll",
          repo / "target/compare-cecil/roslyn/tasks/netcore/bincore/Microsoft.CodeAnalysis.CSharp.dll"]
with raw.open("w", encoding="utf-8") as output:
    for path in inputs:
        # Cross-check that the experimental output preserves all metadata/IL counts.
        a = json.loads(subprocess.check_output([str(baseline), "validate", str(path)], cwd=repo))
        b = json.loads(subprocess.check_output([str(indexed), "validate", str(path)], cwd=repo))
        assert a == b, "experimental validation differs"
        for round_no in range(1, 4):
            order = [("baseline", baseline), ("rva-index", indexed)]
            if round_no % 2 == 0:
                order.reverse()
            for variant, executable in order:
                print(f"RVA experiment {path.name} round {round_no} {variant}", flush=True)
                row = json.loads(subprocess.check_output(
                    [str(executable), "write", str(path), "15", "160", "2000"], cwd=repo))
                row.update(input=path.name, round=round_no, variant=variant)
                output.write(json.dumps(row) + "\n")
                output.flush()
print(raw, flush=True)
