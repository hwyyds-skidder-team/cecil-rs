"""Summarize measurements and evaluate the fixed 7 x 3 acceptance matrix."""
import argparse
import csv
import datetime as dt
import json
import math
import statistics
from collections import defaultdict
from pathlib import Path

SUITE_INPUTS = {
    "hello.exe", "System.Runtime.dll (fixture)", "SQLite-net.dll",
    "cecil.dll (fixture)", "Mono.Cecil.dll (0.11.6)",
    "Microsoft.CodeAnalysis.dll", "Microsoft.CodeAnalysis.CSharp.dll",
}
MODES = ("read", "write", "roundtrip")
LABELS = {"read": "完整读取", "write": "重新写出", "roundtrip": "读取→写出"}


def summarize(env, raw):
    """Reject incomplete/duplicate data before calculating any speedups."""
    # Keep archived implementation labels without modifying raw evidence.
    rust_impl = "cecil-rs" if any(row["implementation"] == "cecil-rs" for row in raw) else "cecli-rs"
    groups = defaultdict(list)
    rounds = {}
    inputs = {i["name"]: i for i in env["inputs"]}
    validation = {v["name"]: v for v in env["validation"]}
    modes = env.get("modes", MODES)
    expected = {(name, mode, impl) for name in inputs for mode in modes
                for impl in (rust_impl, "Mono.Cecil")}
    identities = {(name, mode, impl, r) for name, mode, impl in expected
                  for r in range(1, env["rounds"] + 1)}
    for row in raw:
        key = row["input"], row["mode"], row["implementation"]
        identity = (*key, row["round"])
        assert identity in identities, f"unexpected measurement: {identity}"
        assert identity not in rounds, f"duplicate measurement: {identity}"
        values = row["samples_us"]
        assert len(values) == env["samples_per_round"], f"incomplete samples: {identity}"
        assert all(math.isfinite(v) and v > 0 for v in values), f"invalid timing: {identity}"
        assert row["counts"] == validation[row["input"]]["counts"], f"count mismatch: {identity}"
        assert row["input_bytes"] == inputs[row["input"]]["bytes"], f"input size mismatch: {identity}"
        groups[key].extend(values)
        rounds[identity] = statistics.median(values)
    assert set(rounds) == identities, "missing benchmark rounds or cells"
    assert set(groups) == expected, "missing or unexpected benchmark cells"

    rows = []
    for inp in env["inputs"]:
        for mode in modes:
            rk, ck = (inp["name"], mode, rust_impl), (inp["name"], mode, "Mono.Cecil")
            rust = [rounds[(*rk, r)] for r in range(1, env["rounds"] + 1)]
            cecil = [rounds[(*ck, r)] for r in range(1, env["rounds"] + 1)]
            paired = [c / r for c, r in zip(cecil, rust)]
            r, c = statistics.median(groups[rk]), statistics.median(groups[ck])
            rows.append({
                "input": inp["name"], "input_bytes": inp["bytes"], "mode": mode,
                "rust_implementation": rust_impl,
                "rust_median_us": r, "cecil_median_us": c, "cecil_over_rust": c / r,
                "rust_round_min_us": min(rust), "rust_round_max_us": max(rust),
                "cecil_round_min_us": min(cecil), "cecil_round_max_us": max(cecil),
                "samples_each": len(groups[rk]), "median_win": c > r,
                "rounds_won": sum(ratio > 1 for ratio in paired),
                "rounds_total": len(paired), "worst_round_cecil_over_rust": min(paired),
                "all_rounds_win": all(ratio > 1 for ratio in paired),
                "round_ranges_separated": max(rust) < min(cecil),
            })
    return rows


def acceptance(env, rows):
    full = ({i["name"] for i in env["inputs"]} == SUITE_INPUTS
            and set(env.get("modes", MODES)) == set(MODES) and len(rows) == 21)
    repeated = env["rounds"] >= 3
    semantics = all(v.get("semantic_validation") == "passed"
                    and v.get("rust_semantics") and v.get("cecil_semantics")
                    for v in env["validation"])
    provenance = bool(env.get("source_snapshot") and env.get("build"))
    failures = [{"input": r["input"], "mode": r["mode"],
                 "median_ratio": r["cecil_over_rust"], "rounds_won": r["rounds_won"],
                 "rounds_total": r["rounds_total"], "worst_round_ratio": r["worst_round_cecil_over_rust"]}
                for r in rows if not r["median_win"] or not r["all_rounds_win"]]
    return {
        "suite": "cecil-7x3-v1", "required_cells": 21, "measured_cells": len(rows),
        "full_matrix": full, "at_least_three_rounds": repeated,
        "median_wins": sum(r["median_win"] for r in rows),
        "all_round_wins": sum(r["all_rounds_win"] for r in rows),
        "semantic_validation": semantics, "source_provenance": provenance,
        "passed": full and repeated and semantics and provenance and not failures,
        "failed_cells": failures,
        "rule": "All fixed 21 cells must have Cecil/Rust > 1 for the pooled median and every paired round median, with >= 3 rounds, semantic cross-reading and archived source provenance.",
    }


def generate_report(env, rows, result, env_path, raw_path, csv_path):
    labels = {k: v for k, v in LABELS.items() if k in env.get("modes", MODES)}
    build = env.get("build", {})
    profile = build.get("profile", "release（旧记录未保存完整配置）")
    allocator = build.get("allocator", "系统默认（旧记录）")
    report = [f"# {rows[0]['rust_implementation']} 与 Mono.Cecil 性能实测", "",
              f"测试时间：{env['recorded_at']}；基准提交：`{env['commit']}`。",
              f"验收：**{'通过' if result['passed'] else '未通过'}**；中位数胜出 {result['median_wins']}/{len(rows)}，每轮均胜出 {result['all_round_wins']}/{len(rows)}；固定目标为全部 21 格。", "",
              "验收要求完整七输入 × 三场景、至少三轮、每格汇总中位数及每一对应轮次中位数均比 Cecil 快，并通过语义交叉重读和源码溯源。几何平均不能替代逐格验收；本次结论只覆盖这组输入和配置。", "",
              f"Windows {env['os']['Version']}，{env['cpu']['Name']}，{env['cpu']['NumberOfCores']} 核 / {env['cpu']['NumberOfLogicalProcessors']} 线程，内存 {env['ram_bytes'] / 2**30:.1f} GiB。",
              f"{env['rust'].splitlines()[0]}，Cargo profile `{profile}`，分配器 `{allocator}`，features `{build.get('features', '')}`；Mono.Cecil {env['mono_cecil']}，Roslyn {env['roslyn']} 优化编译，.NET {env['dotnet']} x64，关闭分层 JIT，工作站 GC。", "",
              f"每种输入、场景、实现分别运行 {env['rounds']} 个独立进程；每进程预热 {env['warmup_ms']} ms，采集 {env['samples_per_round']} 个批次，每批目标 {env['sample_ms']} ms。两实现交替顺序、串行执行。表中耗时为全部批次每次操作均值的中位数。", "",
              "所有输入在计时前读取为内存字节；编译、进程启动、文件 I/O、预热及语义指纹均不计入。未读取 PDB、未签名。Cecil 显式访问元数据、特性原始 blob 和全部 IL；Rust 默认完整读取。读取和往返包含模型创建及释放；C# 计时中允许正常 GC。", "",
              "比值 = Cecil 耗时 / Rust 耗时；大于 1 表示 Rust 较快。逐轮胜数比较同一轮的两个独立进程中位数。", "",
              "| 输入 | 大小 KiB | 操作 | Rust ms | Cecil ms | Cecil / Rust | 逐轮胜数 |",
              "| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |"]
    for row in rows:
        report.append(f"| {row['input']} | {row['input_bytes']/1024:.1f} | {labels[row['mode']]} | {row['rust_median_us']/1000:.4f} | {row['cecil_median_us']/1000:.4f} | {row['cecil_over_rust']:.3f}× | {row['rounds_won']}/{row['rounds_total']} |")
    report.extend(["", "## 验收检查", ""])
    for label, key in [("完整 21 格", "full_matrix"), ("至少三轮", "at_least_three_rounds"),
                       ("语义交叉重读", "semantic_validation"), ("源码与构建溯源", "source_provenance")]:
        report.append(f"- {label}：{'通过' if result[key] else '未满足'}。")
    if result["failed_cells"]:
        report.extend(["", "尚未稳定胜出的格：", ""])
        for cell in result["failed_cells"]:
            report.append(f"- {cell['input']} / {labels[cell['mode']]}：汇总 {cell['median_ratio']:.3f}×，逐轮 {cell['rounds_won']}/{cell['rounds_total']}，最弱轮 {cell['worst_round_ratio']:.3f}×。")
    report.extend(["", "## 按场景汇总", "", "几何平均仅描述本次样本集合，每个输入权重相同。", ""])
    for mode in labels:
        selected = [r for r in rows if r["mode"] == mode]
        ratio = math.exp(statistics.mean(math.log(r["cecil_over_rust"]) for r in selected))
        report.append(f"- {labels[mode]}：Cecil / Rust 几何平均 **{ratio:.3f}×**，中位数胜出 {sum(r['median_win'] for r in selected)}/{len(selected)}。")
    report.extend(["", "## 正确性与比较范围", ""])
    if result["semantic_validation"]:
        report.extend([
            "原始输入和双方输出均由两个读者读取。每个读者分别要求原始输入、自身写出后重读、对方输出交叉重读的规范化元数据与 IL 指纹一致；不同读者的指纹格式互不比较。类型、方法、字段、属性、事件、特性、方法体、指令、局部变量和异常处理器数量也全部一致。", "",
            "指纹覆盖名称、定义标志、类型/成员/泛型签名、泛型约束、接口、常量、字段初始数据、特性构造函数和原始 blob、安全声明、P/Invoke、覆盖和访问器、托管资源，以及全部 IL 操作码、已解析操作数、浮点位模式、局部类型、init-locals、分支目标和异常区域。分支和异常边界转为指令序号，引用转为带作用域的名称与签名；不比较 token/RID、堆偏移、RVA、MVID、PE 布局或 Cecil 会重算的 max-stack。", "",
            "这是一项较强的回归检查，仍不等价于执行验证或全部 CLR 语义证明；当前未对符号、签名有效性、封送描述、导出类型和 Win32 资源作完整语义指纹。Rust 使用稳定 FNV-1a-128 作意外损坏检查，Cecil 使用 SHA-256。规范化明细和输出镜像保存在环境记录的 `build.artifact_dir`。", "",
        ])
    else:
        report.extend(["本记录仅保存了数量和交叉重读检查，未提供增强语义指纹证据，不能据此认定签名或 IL 操作数不变。", ""])
    report.extend(["| 输入 | 类型 | 方法 | IL 方法体 | 指令 | Rust 输出字节 | Cecil 输出字节 |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"])
    for v in env["validation"]:
        c = v["counts"]
        report.append(f"| {v['name']} | {c['types']} | {c['methods']} | {c['bodies']} | {c['instructions']} | {v['rust_output_bytes']} | {v['cecil_output_bytes']} |")
    snapshot = env.get("source_snapshot")
    report.extend(["", "## 源码与构建溯源", ""])
    if snapshot:
        report.extend([
            f"工作树状态：{'存在未提交或未跟踪文件' if snapshot['dirty'] else '干净'}。提交号仅标识基线；本次实际源码以 `{Path(snapshot['manifest']).name}` 的逐文件 SHA-256 和 `{Path(snapshot['archive']).name}` 的源码归档为准。脚本在编译后、验证后和测量后复查构建输入，变化时拒绝验收。",
            "Cargo profile、构建参数、影响编译的环境变量、Cargo 配置文件哈希和 .NET 运行配置均保存在环境记录的 `build` 字段。配置文件哈希用于标识外部 Cargo 配置；其内容不包含在源码归档时，复现仍需相同配置。", "",
        ])
    else:
        report.extend(["旧记录没有源码归档或完整 profile/配置快照，提交号不足以确定存在未提交文件时的实际构建。", ""])
    report.extend(["## 局限与重复测量", "",
                   "- Rust arena 值模型与 Cecil 引用对象模型不同；分配器、GC、缓存和遍历开销均属于当前实现表现，不能单独归因于语言。",
                   "- `write` 重用同一个完整读取模型；Cecil 写入会改变或缓存内部状态。一次性处理参考 `roundtrip`。",
                   "- Cecil 写出枚举常量时可能自动解析依赖，共用 resolver 的首次加载在预热期完成；Rust 使用镜像中已记录的值类型标记。未主动调用外部引用解析 API。",
                   "- 本机 .NET ReadyToRun DLL 被原版 Cecil 拒绝写出，未纳入计时；大型输入使用 Roslyn 4.14.0 的纯托管程序集。七个验收输入始终固定。",
                   "- 未绑核或禁用后台应用；小文件易受调度、频率和内存管理影响。逐轮一致胜出是有限重复证据，不是统计置信区间。原始数据保留所有批次。", "",
                   "| 输入 | 操作 | Rust 轮次中位数范围 ms | Cecil 轮次中位数范围 ms | 最弱轮比值 | 轮次范围分离 |",
                   "| --- | --- | ---: | ---: | ---: | --- |"])
    for r in rows:
        report.append(f"| {r['input']} | {labels[r['mode']]} | {r['rust_round_min_us']/1000:.4f}–{r['rust_round_max_us']/1000:.4f} | {r['cecil_round_min_us']/1000:.4f}–{r['cecil_round_max_us']/1000:.4f} | {r['worst_round_cecil_over_rust']:.3f}× | {'是' if r['round_ranges_separated'] else '否'} |")
    report.extend(["", "## 复现", "", "```powershell",
                   "powershell -ExecutionPolicy Bypass -File scripts/compare-cecil/run.ps1 -RequireAllCells", "```", "",
                   f"环境和输入 SHA-256：`{env_path.name}`；原始样本：`{raw_path.name}`；汇总：`{csv_path.name}`。验收结果另存为 `.acceptance.json`；历史结果不会被覆写。", ""])
    return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment", type=Path)
    parser.add_argument("raw", type=Path)
    parser.add_argument("--require-all-cells", action="store_true", help="exit 2 unless the fixed full matrix passes")
    args = parser.parse_args()
    env = json.loads(args.environment.read_text(encoding="utf-8-sig"))
    raw = [json.loads(line) for line in args.raw.read_text(encoding="utf-8-sig").splitlines() if line]
    rows = summarize(env, raw)
    result = acceptance(env, rows)
    base = args.raw.with_suffix("")
    if any(Path(str(base) + suffix).exists() for suffix in (".md", ".csv", ".acceptance.json")):
        base = Path(str(base) + ".analysis-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S-%f"))
    csv_path, report_path, acceptance_path = (Path(str(base) + suffix) for suffix in (".csv", ".md", ".acceptance.json"))
    with csv_path.open("x", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    acceptance_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    report_path.write_text(generate_report(env, rows, result, args.environment, args.raw, csv_path), encoding="utf-8")
    print(report_path)
    print(f"Acceptance: {'PASS' if result['passed'] else 'FAIL'}; median wins {result['median_wins']}/{len(rows)}; all-round wins {result['all_round_wins']}/{len(rows)}; fixed target 21/21")
    for mode in env.get("modes", MODES):
        ratio = math.exp(statistics.mean(math.log(r["cecil_over_rust"]) for r in rows if r["mode"] == mode))
        print(f"{mode}: Cecil/Rust geometric mean = {ratio:.3f}x")
    return 2 if args.require_all_cells and not result["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
