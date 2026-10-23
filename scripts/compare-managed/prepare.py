"""Download hash-pinned dependencies and compile the three managed drivers."""
import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
WORK = ROOT / "target/compare-managed"
RUNTIME_REFERENCES = (
    "System.Private.CoreLib.dll", "System.Runtime.dll", "netstandard.dll",
    "System.Console.dll", "System.Collections.dll", "System.Diagnostics.Process.dll",
    "System.Runtime.Extensions.dll", "System.Security.Cryptography.dll", "System.Memory.dll",
    "System.Collections.Concurrent.dll", "System.Collections.Immutable.dll", "System.Linq.dll",
    "System.IO.dll", "System.Threading.dll", "System.Runtime.InteropServices.dll",
)


def execute(command, **kwargs):
    return subprocess.run([str(p) for p in command], cwd=ROOT, check=True, text=True,
                          encoding="utf-8", errors="replace", **kwargs)


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def packages():
    lock = json.loads((HERE / "packages.lock.json").read_text(encoding="utf-8"))
    destinations = {}
    (WORK / "packages").mkdir(parents=True, exist_ok=True)
    for p in lock["packages"]:
        name = f"{p['id']}.{p['version']}"
        archive = WORK / "packages" / f"{name}.nupkg"
        if not archive.exists():
            cached = ROOT / p.get("cache_archive", "nonexistent-cache")
            if cached.is_file() and sha256(cached) == p["sha256"]:
                shutil.copy2(cached, archive)
            else:
                urllib.request.urlretrieve(f"https://api.nuget.org/v3-flatcontainer/{p['id']}/{p['version']}/{name}.nupkg", archive)
        if sha256(archive) != p["sha256"]:
            raise ValueError(f"NuGet archive SHA-256 mismatch: {archive}")
        destination = WORK / p["directory"] if "directory" in p else WORK / "packages" / name
        if not destination.exists():
            with zipfile.ZipFile(archive) as z:
                z.extractall(destination)
        destinations[p["id"]] = destination
    return lock, destinations


def prepare(output):
    lock, libs = packages()
    # Old package caches can be copied after hash verification. Everything this
    # harness writes lives under compare-managed; old caches stay untouched.
    cecil = libs["mono.cecil"] / "lib/netstandard2.0/Mono.Cecil.dll"
    compiler = libs["microsoft.net.compilers.toolset"] / "tasks/netcore/bincore/csc.dll"
    runtimes = execute(["dotnet", "--list-runtimes"], capture_output=True).stdout.splitlines()
    found = [re.fullmatch(r"Microsoft.NETCore.App (\S+) \[(.+)\]", line) for line in runtimes]
    matches = [m for m in found if m and "-" not in m[1]]
    runtime = max(matches, key=lambda m: tuple(map(int, m[1].split("."))))
    version, runtime_dir = runtime[1], Path(runtime[2]) / runtime[1]
    if int(version.split(".")[0]) < 10:
        raise ValueError("AsmResolver's pinned net10.0 target requires .NET 10 or newer.")
    output.mkdir(parents=True, exist_ok=False)
    config = {"runtimeOptions": {"tfm": "net10.0", "framework": {"name": "Microsoft.NETCore.App", "version": version},
              "configProperties": {"System.Runtime.TieredCompilation": False, "System.GC.Server": False}}}
    references = ["-r:" + str(runtime_dir / name) for name in RUNTIME_REFERENCES]
    dnlib = [libs["dnlib"] / "lib/net6.0/dnlib.dll"]
    asm = [libs[p] / "lib/net10.0" / (name + ".dll") for p, name in (
        ("asmresolver", "AsmResolver"), ("asmresolver.pe.file", "AsmResolver.PE.File"),
        ("asmresolver.pe", "AsmResolver.PE"), ("asmresolver.dotnet", "AsmResolver.DotNet"))]
    drivers, builds = {}, []
    for name, implementation, dependencies, destination in (
        ("DnlibBench", "dnlib", dnlib, output), ("AsmResolverBench", "AsmResolver", asm, output),
        ("CecilBench", "Mono.Cecil", [cecil], output)):
        sources = [HERE / "BenchProtocol.cs", HERE / f"{name}.cs"] if name != "CecilBench" else [ROOT / "scripts/compare-cecil/CecilBench.cs"]
        binary = destination / f"{name}.dll"
        command = ["dotnet", "--roll-forward", "Major", compiler, "-nologo", "-noconfig", "-nostdlib+", "-target:exe", "-optimize+", "-out:" + str(binary)]
        command += references + ["-r:" + str(d) for d in dependencies] + sources
        execute(command)
        for dependency in dependencies:
            shutil.copy2(dependency, destination / dependency.name)
        (destination / f"{name}.runtimeconfig.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
        drivers[implementation] = ["dotnet", str(binary)]
        builds.append({"implementation": implementation, "binary": str(binary), "binary_sha256": sha256(binary),
                       "dependencies": [{"path": str(destination / d.name), "bytes": d.stat().st_size,
                                         "sha256": sha256(destination / d.name)} for d in dependencies],
                       "sources": [{"path": str(s.relative_to(ROOT)), "sha256": sha256(s)} for s in sources],
                       "command": list(map(str, command))})
    info = {"drivers": drivers, "managed_builds": builds, "dotnet": version, "runtime_config": config,
            "packages": lock, "compiler_sha256": sha256(compiler), "cecil_binary_sha256": sha256(cecil),
            "mono_cecil_package_sha256": sha256(WORK / "packages/mono.cecil.0.11.6.nupkg"),
            "roslyn_package_sha256": sha256(WORK / "packages/microsoft.net.compilers.toolset.4.14.0.nupkg")}
    (output / "drivers.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return info


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or WORK / "runs" / dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    if not output.is_absolute():
        output = ROOT / output
    prepare(output)
    print(output / "drivers.json")


if __name__ == "__main__":
    main()
