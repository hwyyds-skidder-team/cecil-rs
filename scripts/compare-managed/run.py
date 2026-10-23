"""Run four full-load managed-assembly implementations and validate all outputs."""
import argparse
import datetime as dt
import json
import os
import platform
import re
import subprocess
import zipfile
from pathlib import Path

from prepare import ROOT, HERE, WORK, execute, prepare, sha256

IMPLEMENTATIONS = ("cecil-rs", "Mono.Cecil", "dnlib", "AsmResolver")
MODES = ("read", "write", "roundtrip")


def run_json(command):
    try:
        result = execute(command, capture_output=True)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"driver exited {error.returncode}: {command}\n{error.stdout}\n{error.stderr}") from error
    return json.loads(result.stdout)


def manifest():
    files = execute(["git", "ls-files", "--cached", "--others", "--exclude-standard", "--",
                     "Cargo.toml", "Cargo.lock", "crates", ".cargo", "scripts/compare-cecil", "scripts/compare-managed"], capture_output=True).stdout.splitlines()
    return [{"path": p, "bytes": (ROOT / p).stat().st_size, "sha256": sha256(ROOT / p)}
            for p in sorted(set(files)) if (ROOT / p).is_file() and "__pycache__" not in p and not p.endswith(".pyc")]


def same_source(before):
    if manifest() != before:
        raise RuntimeError("Build inputs changed during this run. Artifacts are retained; acceptance is refused.")


def machine():
    command = "@{cpu=(Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors);ram_bytes=(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory;os=(Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version)} | ConvertTo-Json -Depth 5 -Compress"
    return json.loads(execute(["powershell", "-NoProfile", "-Command", command], capture_output=True).stdout)


def config_hashes():
    paths = [ROOT / ".cargo/config", ROOT / ".cargo/config.toml"]
    cargo_dir = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")))
    paths += [cargo_dir / "config", cargo_dir / "config.toml"]
    return [{"path": str(p), "sha256": sha256(p)} for p in sorted(set(paths)) if p.is_file()]


def all_inputs():
    cecil_cache = WORK
    return [
        ("hello.exe", ROOT / "fixtures/hello.exe"),
        ("System.Runtime.dll (fixture)", ROOT / "fixtures/System.Runtime.dll"),
        ("SQLite-net.dll", ROOT / "fixtures/SQLite-net.dll"),
        ("cecil.dll (fixture)", ROOT / "fixtures/cecil.dll"),
        ("Mono.Cecil.dll (0.11.6)", cecil_cache / "cecil/lib/netstandard2.0/Mono.Cecil.dll"),
        ("Microsoft.CodeAnalysis.dll", cecil_cache / "roslyn/tasks/netcore/bincore/Microsoft.CodeAnalysis.dll"),
        ("Microsoft.CodeAnalysis.CSharp.dll", cecil_cache / "roslyn/tasks/netcore/bincore/Microsoft.CodeAnalysis.CSharp.dll"),
    ]


def compare_reader(original, reread, context):
    for field in ("counts", "semantics"):
        if original[field] != reread[field]:
            raise ValueError(f"{context}: {field} mismatch; canonical dumps are retained in the run artifact directory. Original {original[field]}; output {reread[field]}")


def validate(inputs, drivers, artifact_dir):
    validation = []
    validation_errors = []
    for inp in inputs:
        name, source = inp["name"], inp["path"]
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        print("Validate " + name, flush=True)
        originals, writer_results = {}, {}
        for reader in ("cecil-rs", "Mono.Cecil"):
            dump = artifact_dir / f"{safe}.original.{reader}.txt"
            originals[reader] = run_json(drivers[reader] + ["inspect", source, "1", "1", "1", "-", str(dump)])
        if originals["cecil-rs"]["counts"] != originals["Mono.Cecil"]["counts"]:
            raise ValueError(f"original reader counts disagree: {name}")
        errors, outputs = [], {}
        for writer in IMPLEMENTATIONS:
            output = artifact_dir / f"{safe}.{writer}.dll"
            try:
                result = run_json(drivers[writer] + ["validate", source, "1", "1", "1", str(output)])
                outputs[writer] = {"bytes": output.stat().st_size, "sha256": sha256(output), "path": str(output), "readers": {}}
                writer_results[writer] = result
                if result["counts"] != originals["cecil-rs"]["counts"]:
                    raise ValueError(f"materialized counts disagree: {writer} {name}")
            except Exception as exc:
                errors.append(f"{writer} validation: {exc}")
                if not output.exists():
                    continue
                if writer not in outputs:
                    outputs[writer] = {"bytes": output.stat().st_size, "sha256": sha256(output), "path": str(output), "readers": {}}
            for reader in ("cecil-rs", "Mono.Cecil"):
                try:
                    reread = run_json(drivers[reader] + ["inspect", str(output), "1", "1", "1", "-", str(artifact_dir / f"{safe}.{writer}-output.{reader}.txt")])
                    compare_reader(originals[reader], reread, f"{reader} reads {writer} output for {name}")
                    outputs[writer]["readers"][reader] = reread["semantics"]
                except Exception as exc:
                    errors.append(f"{reader} reads {writer}: {exc}")
        item = {"name": name, "counts": originals["cecil-rs"]["counts"],
                "readers": {key: value["semantics"] for key, value in originals.items()},
                "writers": writer_results, "outputs": outputs, "semantic_validation": "failed" if errors else "passed", "errors": errors}
        validation.append(item)
        validation_errors.extend(f"{name}: {e}" for e in errors)
        (artifact_dir / "validation.json").write_text(json.dumps(validation, indent=2, ensure_ascii=False), encoding="utf-8")
    return validation, validation_errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--samples", type=int, default=11)
    parser.add_argument("--sample-ms", type=int, default=120)
    parser.add_argument("--warmup-ms", type=int, default=800)
    parser.add_argument("--input-filter", default=".")
    parser.add_argument("--mode-filter", default=".")
    parser.add_argument("--cargo-target-dir", default="target/perf-managed")
    parser.add_argument("--cargo-profile", default="release")
    parser.add_argument("--cargo-features", default="fast-allocator")
    parser.add_argument("--allocator", default=None, help="allocator identity if a nonstandard feature/build selects it")
    parser.add_argument("--rust-binary", type=Path, help="reuse a preserved binary; never satisfies fresh-build provenance acceptance")
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--require-all-cells", action="store_true")
    args = parser.parse_args()
    if min(args.rounds, args.samples, args.sample_ms, args.warmup_ms) <= 0:
        parser.error("durations and counts must be positive")
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    results = ROOT / "benchmarks"; results.mkdir(exist_ok=True)
    prefix = results / f"{stamp}-managed-comparison"
    artifact_dir = WORK / "runs" / stamp
    sources = manifest()
    Path(str(prefix) + ".source.json").write_text(json.dumps(sources, indent=2), encoding="utf-8")
    with zipfile.ZipFile(str(prefix) + ".source.zip", "x", zipfile.ZIP_DEFLATED) as z:
        for source in sources:
            z.write(ROOT / source["path"], source["path"])
    managed = prepare(artifact_dir)
    cargo_command = ["cargo", "build", "--locked", "--profile", args.cargo_profile, "--target-dir", args.cargo_target_dir, "-p", "cecil-rs", "--example", "compare_cecil"]
    if args.cargo_features:
        cargo_command += ["--features", args.cargo_features]
    if args.rust_binary:
        rust = args.rust_binary.resolve()
    else:
        execute(cargo_command)
        rust = ROOT / args.cargo_target_dir / ("debug" if args.cargo_profile == "dev" else args.cargo_profile) / "examples/compare_cecil.exe"
    drivers = {"cecil-rs": [str(rust)], **managed["drivers"]}
    same_source(sources)
    inputs = [{"name": name, "path": str(path), "bytes": path.stat().st_size, "sha256": sha256(path)}
              for name, path in all_inputs() if re.search(args.input_filter, name)]
    modes = [mode for mode in MODES if re.search(args.mode_filter, mode)]
    if not inputs or not modes:
        raise ValueError("filters selected no inputs or modes")
    validation, errors = validate(inputs, drivers, artifact_dir)
    same_source(sources)
    relevant_environment = {k: v for k, v in os.environ.items() if re.fullmatch(r"RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTUP_TOOLCHAIN|CARGO_BUILD_(TARGET|RUSTFLAGS)|CARGO_PROFILE_.+|CARGO_TARGET_.+_RUSTFLAGS", k)}
    features = set(args.cargo_features.replace(",", " ").split())
    allocator = args.allocator or ("mimalloc" if "fast-allocator" in features else "system")
    env = {
        "suite": "managed-7x3x3-v1", "required_comparisons": 63,
        "recorded_at": dt.datetime.now().astimezone().isoformat(),
        "commit": execute(["git", "rev-parse", "HEAD"], capture_output=True).stdout.strip(),
        "git_status": execute(["git", "status", "--porcelain=v1", "--untracked-files=all"], capture_output=True).stdout,
        "rust": execute(["rustc", "-Vv"], capture_output=True).stdout,
        "rounds": args.rounds, "samples_per_round": args.samples, "sample_ms": args.sample_ms, "warmup_ms": args.warmup_ms,
        "modes": modes, "implementations": list(IMPLEMENTATIONS), "inputs": inputs, "validation": validation,
        "validation_errors": errors, "managed": managed, **machine(),
        "build": {"profile": args.cargo_profile, "features": args.cargo_features, "allocator": allocator,
                  "fresh_rust_build": args.rust_binary is None, "cargo_command": cargo_command,
                  "cargo_version": execute(["cargo", "-Vv"], capture_output=True).stdout,
                  "environment": relevant_environment, "cargo_configs": config_hashes(),
                  "rust_binary": str(rust), "rust_binary_sha256": sha256(rust), "artifact_dir": str(artifact_dir)},
        "source_snapshot": {"manifest": str(prefix) + ".source.json", "manifest_sha256": sha256(str(prefix) + ".source.json"),
                            "archive": str(prefix) + ".source.zip", "archive_sha256": sha256(str(prefix) + ".source.zip")},
    }
    env_path = Path(str(prefix) + ".environment.json")
    env_path.write_text(json.dumps(env, indent=2, ensure_ascii=False), encoding="utf-8")
    if errors:
        raise RuntimeError("Semantic validation failed; performance run refused. Preserved evidence: " + str(env_path) + "\n" + "\n".join(errors))
    if args.validate_only:
        print("Validation passed: " + str(env_path), flush=True)
        return 0
    raw_path = Path(str(prefix) + ".raw.jsonl")
    with raw_path.open("x", encoding="utf-8") as raw:
        for round_number in range(1, args.rounds + 1):
            cell = 0
            for inp in inputs:
                for mode in modes:
                    # Rotate and reverse across rounds/cells to avoid one
                    # implementation always receiving the same process order.
                    offset = (round_number - 1 + cell) % len(IMPLEMENTATIONS)
                    order = list(IMPLEMENTATIONS[offset:] + IMPLEMENTATIONS[:offset])
                    if (round_number + cell) % 2 == 0:
                        order.reverse()
                    for implementation in order:
                        print(f"Round {round_number}/{args.rounds} {inp['name']} {mode} {implementation}", flush=True)
                        data = run_json(drivers[implementation] + [mode, inp["path"], str(args.samples), str(args.sample_ms), str(args.warmup_ms)])
                        data.update(input=inp["name"], round=round_number, process_order=order.index(implementation))
                        raw.write(json.dumps(data, separators=(",", ":")) + "\n"); raw.flush()
                    cell += 1
    same_source(sources)
    env["source_consistent"] = True
    env_path.write_text(json.dumps(env, indent=2, ensure_ascii=False), encoding="utf-8")
    command = ["python", "-X", "utf8", HERE / "report.py", env_path, raw_path]
    if args.require_all_cells:
        command.append("--require-all-cells")
    return subprocess.run(list(map(str, command)), cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
