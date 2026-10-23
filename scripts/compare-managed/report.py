"""Evaluate all 63 Rust-versus-managed-library comparisons without averaging losses away."""
import argparse
import csv
import datetime as dt
import json
import math
import statistics
from pathlib import Path

INPUTS = {"hello.exe", "System.Runtime.dll (fixture)", "SQLite-net.dll", "cecil.dll (fixture)",
          "Mono.Cecil.dll (0.11.6)", "Microsoft.CodeAnalysis.dll", "Microsoft.CodeAnalysis.CSharp.dll"}
MODES = ("read", "write", "roundtrip")
COMPETITORS = ("Mono.Cecil", "dnlib", "AsmResolver")
LABELS = {"read": "完整读取", "write": "重新写出", "roundtrip": "读取→写出"}


def rust_implementation(env):
    # Archived measurements retain their original label and source hashes.
    return "cecil-rs" if "cecil-rs" in env["implementations"] else "cecli-rs"


def summarize(env, raw):
    rust_impl = rust_implementation(env)
    names = {i["name"]: i for i in env["inputs"]}
    validation = {v["name"]: v for v in env["validation"]}
    modes = env["modes"]
    expected = {(name, mode, impl, n) for name in names for mode in modes
                for impl in (rust_impl, *COMPETITORS) for n in range(1, env["rounds"] + 1)}
    cells = {}
    for row in raw:
        key = row["input"], row["mode"], row["implementation"], row["round"]
        assert key in expected, f"unexpected measurement: {key}"
        assert key not in cells, f"duplicate measurement: {key}"
        assert len(row["samples_us"]) == env["samples_per_round"], f"incomplete sample count: {key}"
        assert all(math.isfinite(v) and v > 0 for v in row["samples_us"]), f"invalid measurement: {key}"
        assert row["input_bytes"] == names[row["input"]]["bytes"], f"input size changed: {key}"
        assert row["counts"] == validation[row["input"]]["counts"], f"materialized counts changed: {key}"
        cells[key] = row
    assert set(cells) == expected, "missing benchmark cell or round"

    rows = []
    for inp in env["inputs"]:
        for mode in modes:
            rust = [cells[inp["name"], mode, rust_impl, n]["samples_us"] for n in range(1, env["rounds"] + 1)]
            r = statistics.median(v for sample in rust for v in sample)
            r_round = list(map(statistics.median, rust))
            for competitor in COMPETITORS:
                other = [cells[inp["name"], mode, competitor, n]["samples_us"] for n in range(1, env["rounds"] + 1)]
                c = statistics.median(v for sample in other for v in sample)
                c_round = list(map(statistics.median, other))
                paired = [c / r for c, r in zip(c_round, r_round)]
                rows.append({"input": inp["name"], "input_bytes": inp["bytes"], "mode": mode,
                             "competitor": competitor, "rust_median_us": r, "competitor_median_us": c,
                             "competitor_over_rust": c / r, "median_win": c > r,
                             "rounds_won": sum(p > 1 for p in paired), "rounds_total": len(paired),
                             "all_rounds_win": all(p > 1 for p in paired), "worst_round_ratio": min(paired),
                             "rust_round_min_us": min(r_round), "rust_round_max_us": max(r_round),
                             "competitor_round_min_us": min(c_round), "competitor_round_max_us": max(c_round),
                             "round_ranges_separated": max(r_round) < min(c_round),
                             "samples_each": env["rounds"] * env["samples_per_round"]})
    return rows


def acceptance(env, rows):
    rust_impl = rust_implementation(env)
    full = ({i["name"] for i in env["inputs"]} == INPUTS and set(env["modes"]) == set(MODES)
            and set(env["implementations"]) == {rust_impl, *COMPETITORS} and len(rows) == 63)
    semantic = len(env["validation"]) == len(env["inputs"]) and all(
        v["semantic_validation"] == "passed"
        and set(v["outputs"]) == {rust_impl, *COMPETITORS}
        and all(set(o["readers"]) == {rust_impl, "Mono.Cecil"} for o in v["outputs"].values())
        for v in env["validation"])
    provenance = bool(env.get("source_snapshot") and env.get("build")
                      and env["build"].get("fresh_rust_build")
                      and env.get("source_consistent", False))
    failures = [{"input": r["input"], "mode": r["mode"], "competitor": r["competitor"],
                 "median_ratio": r["competitor_over_rust"], "rounds_won": r["rounds_won"],
                 "rounds_total": r["rounds_total"], "worst_round_ratio": r["worst_round_ratio"]}
                for r in rows if not (r["median_win"] and r["all_rounds_win"])]
    repeated = env["rounds"] >= 3
    return {"suite": "managed-7x3x3-v1", "required_comparisons": 63, "measured_comparisons": len(rows),
            "passed": full and semantic and provenance and repeated and not failures,
            "full_matrix": full, "semantic_validation": semantic, "source_provenance": provenance,
            "at_least_three_rounds": repeated, "median_wins": sum(r["median_win"] for r in rows),
            "all_round_wins": sum(r["all_rounds_win"] for r in rows), "failed_comparisons": failures,
            "rule": "All fixed 63 comparisons require competitor/Rust > 1 in the pooled median and EVERY paired round median, >= 3 rounds, both independent semantic readers for all four outputs, and stable archived source/fresh build provenance."}


def report(env, rows, gate, env_path, raw_path):
    build = env["build"]
    text = [f"# {rust_implementation(env)} 与 Mono.Cecil、dnlib、AsmResolver 性能比较", "",
            f"验收：**{'通过' if gate['passed'] else '未通过'}**；汇总中位数胜出 {gate['median_wins']}/{len(rows)}，每轮均胜出 {gate['all_round_wins']}/{len(rows)}，固定目标 **63/63**。", "",
            f"记录时间 {env['recorded_at']}；基线提交 `{env['commit']}`；Cargo profile `{build['profile']}`、features `{build['features']}`、分配器 `{build['allocator']}`。",
            f"{env['rust'].splitlines()[0]}；Mono.Cecil 0.11.6、dnlib 4.5.0、AsmResolver 6.0.1；.NET {env['managed']['dotnet']}，关闭分层 JIT、工作站 GC。包 SHA-256 和对应源码提交写入环境记录，NuGet 版本锁定于 2026-10-21 查询的稳定版本。", "",
            f"{env['cpu']['Name']}；{env['cpu']['NumberOfCores']} 核 / {env['cpu']['NumberOfLogicalProcessors']} 线程；内存 {env['ram_bytes']/2**30:.1f} GiB；Windows {env['os']['Version']}。", "",
            f"每个输入/场景/实现运行 {env['rounds']} 个独立进程，每进程预热 {env['warmup_ms']} ms，采集 {env['samples_per_round']} 批，每批目标 {env['sample_ms']} ms。四实现串行交替顺序，报告值为全部批次每次操作均值的中位数。", "",
            "输入先读入内存；计时排除文件读取、编译、进程启动、预热和语义验证。read 完整物化元数据及全部 IL；write 从完整模型序列化到新内存输出；roundtrip 读取后序列化。未读取 PDB、未签名、未主动解析属性参数或外部程序集。模型建立、遍历和释放/正常 GC 均计入。", "",
            "比值 = 对方耗时 / Rust 耗时，大于 1 表示 Rust 快。验收逐格逐轮判断；几何平均不能抵消任何落后格。", "",
            "| 输入 | 操作 | 对手 | Rust ms | 对方 ms | 对方 / Rust | 逐轮胜数 |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: |"]
    for r in rows:
        text.append(f"| {r['input']} | {LABELS[r['mode']]} | {r['competitor']} | {r['rust_median_us']/1000:.4f} | {r['competitor_median_us']/1000:.4f} | {r['competitor_over_rust']:.3f}× | {r['rounds_won']}/{r['rounds_total']} |")
    text.extend(["", "## 验收", ""])
    for label, key in (("全部 63 比较", "full_matrix"), ("至少三轮", "at_least_three_rounds"),
                       ("双读者语义检查", "semantic_validation"), ("实际构建源码溯源", "source_provenance")):
        text.append(f"- {label}：{'通过' if gate[key] else '未满足'}。")
    if gate["failed_comparisons"]:
        text.extend(["", "尚未稳定胜出的比较：", ""])
        for r in gate["failed_comparisons"]:
            text.append(f"- {r['input']} / {LABELS[r['mode']]} / {r['competitor']}：中位数 {r['median_ratio']:.3f}×，逐轮 {r['rounds_won']}/{r['rounds_total']}，最弱轮 {r['worst_round_ratio']:.3f}×。")
    text.extend(["", "## 分场景描述", "", "下列几何平均仅描述固定输入，各输入权重相同。", ""])
    for competitor in COMPETITORS:
        for mode in env["modes"]:
            selected = [r for r in rows if r["competitor"] == competitor and r["mode"] == mode]
            ratio = math.exp(statistics.mean(math.log(r["competitor_over_rust"]) for r in selected))
            text.append(f"- {competitor} / {LABELS[mode]}：几何平均 {ratio:.3f}×，中位数胜 {sum(r['median_win'] for r in selected)}/{len(selected)}。")
    text.extend(["", "## 物化范围与正确性", "",
                 "两个新增驱动显式访问定义和 UTF8 名称解码、类型/成员签名、泛型及约束、接口、常量、封送描述、布局、P/Invoke、覆盖、访问器、资源、所有方法体指令/引用/局部/异常处理器。递归仅强制懒属性，按对象身份去重共享签名/引用，避免重复展开 DAG。每次操作实际覆盖保存在 JSON 的 `access_coverage`。", "",
                 "dnlib 枚举 CustomAttributes 会主动解码参数并可能解析外部枚举，故读取场景使用其公开元数据接口读取全部 CustomAttribute 行、复制原始 blob 并物化构造函数引用；不枚举参数值。AsmResolver 构造惰性 signature 包装并复制同样的原始 blob，不触发参数解码；它的默认 writer 可直接保留未初始化 blob。各 writer 本身额外执行的原生逻辑均计时，未抑制其验证或 max-stack 计算。", "",
                 "四种输出全部由 Rust 和 Cecil 两个独立读者 canonical inspect，分别与该读者对原始输入的结果比较；验证数量、名称/标志、带作用域的签名、泛型约束、接口、常量/字段数据、属性构造函数/blob、安全声明、P/Invoke、覆盖/访问器、资源，以及 IL 操作码/操作数/浮点位模式/局部/init-locals/分支/异常边界。引用比较名称和签名，控制流转成指令序号，避免 token/RID/堆/RVA/MVID/布局差异。读者之间的指纹格式不互比。", "",
                 "语义指纹仍不是执行证明；符号、封送描述、导出类型和 Win32 资源未获完整指纹覆盖。默认 writer 可能改变布局、时间戳和 max-stack，这些物理差异不进入语义指纹。所有失败和规范化明细保留，不允许仅凭 counts 相同通过验收。", ""])
    if env.get("validation_errors"):
        text.extend(["本记录存在语义验证错误，不能通过验收：", ""])
        text.extend("- " + error.replace("\n", " ") for error in env["validation_errors"])
        text.append("")
    text.extend(["## 溯源与限制", "",
                 "提交号仅标识基线；实际构建输入以保存的逐文件 SHA-256 和源码 ZIP 为准，包含未提交/未跟踪源码。构建/验证/测量后复查相同输入；参数、profile、features、allocator、编译环境、Cargo 配置哈希、驱动/依赖二进制和 NuGet 包哈希均写入环境记录。复用旧 Rust 二进制的探索运行标记 fresh_rust_build=false，不能通过最终验收。", "",
                 "write 复用同一模型，允许各实现自己的内部缓存；不会缓存输出来替代真正写出。一次性处理参考 roundtrip。对象模型、分配器与 GC 开销均属于实际实现，不能单独归因于语言。未绑核或停止后台程序；逐轮一致胜出只是有限重复证据，不是统计置信区间。结论只覆盖这七个纯托管输入。", "",
                 f"环境：`{env_path.name}`；原始数据：`{raw_path.name}`；规范化输出和镜像：`{build['artifact_dir']}`。历史结果不覆盖。", "",
                 "```powershell", "powershell -ExecutionPolicy Bypass -File scripts/compare-managed/run.ps1 -RequireAllCells", "```", ""])
    return "\n".join(text)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("environment", type=Path); p.add_argument("raw", type=Path)
    p.add_argument("--require-all-cells", action="store_true")
    args = p.parse_args()
    env = json.loads(args.environment.read_text(encoding="utf-8-sig"))
    raw = [json.loads(line) for line in args.raw.read_text(encoding="utf-8-sig").splitlines() if line]
    rows = summarize(env, raw); gate = acceptance(env, rows)
    base = args.raw.with_suffix("")
    if any(Path(str(base) + suffix).exists() for suffix in (".md", ".csv", ".acceptance.json")):
        base = Path(str(base) + ".analysis-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f"))
    with Path(str(base) + ".csv").open("x", encoding="utf-8", newline="") as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    Path(str(base) + ".acceptance.json").write_text(json.dumps(gate, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    path = Path(str(base) + ".md")
    path.write_text(report(env, rows, gate, args.environment, args.raw), encoding="utf-8")
    print(path)
    print(f"Acceptance {'PASS' if gate['passed'] else 'FAIL'}: median {gate['median_wins']}/{len(rows)}; all-round {gate['all_round_wins']}/{len(rows)}; fixed target 63/63")
    return 2 if args.require_all_cells and not gate["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
