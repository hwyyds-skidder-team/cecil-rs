# 四库性能验收

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/compare-managed/run.ps1 -CargoTargetDir target/perf-managed -RequireAllCells
```

比较 cecil-rs、Mono.Cecil 0.11.6、dnlib 4.5.0 和 AsmResolver 6.0.1。NuGet
版本及包 SHA-256 固定在 `packages.lock.json`；脚本复用已校验的下载缓存，使用
Roslyn 4.14.0 编译驱动。本机需要 Python、Rust 和 .NET 10 运行时，无需 .NET SDK。

固定输入为四个仓库夹具、Mono.Cecil 0.11.6 和 Roslyn 的两个 CodeAnalysis
程序集。三个场景为完整读取、已加载模型写出和读取后写出；文件读取、进程启动、
编译、预热和语义指纹不计时，模型创建、遍历及释放或正常 GC 计时。详细物化范围
记录在驱动的 `access_coverage` 和结果报告中。

dnlib 的读取通过公开原始元数据接口加载自定义特性的构造函数与 blob，避免其
`CustomAttributes` 集合主动解析特性参数和外部枚举。AsmResolver 加载惰性特性
签名包装及原始 blob。各库的默认写出行为均实际执行，包括各自的附加验证和缓存。
`write` 重用同一完整模型；一次性处理成本参考 `roundtrip`。

默认 Rust 配置是 release、ThinLTO、一个 codegen unit 及显式安装 mimalloc 的
`fast-allocator` feature，与 CLI 默认发布配置一致。系统分配器复测可直接运行：

```powershell
python -X utf8 scripts/compare-managed/run.py --cargo-features= --cargo-target-dir target/perf-managed-system --require-all-cells
```

每次先写出四种输出，分别交给 Rust 和 Cecil 重读，要求每个读者的数量与规范化
元数据/IL 指纹均与原始输入相同。此检查不等价于运行验证，尚未完整覆盖符号、
封送描述、导出类型和 Win32 资源。输出及规范化明细保存在独立运行目录。

完整验收要求七输入 × 三场景 × 三对手共 **63/63** 比较全部满足：至少三轮、
汇总中位数和每个对应轮次中位数都更快、语义检查通过、实际构建源码一致。
过滤输入、只跑一轮或使用 `--rust-binary` 复用旧二进制只能用于定位，不能通过
完整验收。逐轮胜出提供有限重复证据，不代表统计置信区间或其他输入上的表现。

可用 `-ValidateOnly` 只做正确性验证，或用 `-InputFilter`、`-ModeFilter` 定位。
每轮交替四实现的进程顺序，计时串行运行；请避免同时编译或修改构建输入。
默认三轮，每进程预热 800 ms，11 批样本，每批目标 120 ms。

无需计时即可检查验收规则的回归守卫：
`python -X utf8 -m unittest discover -s scripts/compare-managed -p test_report.py`。
检查涵盖单项或单轮落后、平局、筛选矩阵、缺失样本、语义失败和构建溯源缺失。

`benchmarks/` 保存 JSONL、CSV、中文报告、逐项验收 JSON、环境信息、逐文件源码
SHA-256 和源码 ZIP。环境包含编译命令、features、分配器、Cargo 配置哈希及驱动/
依赖二进制哈希。源码归档包含未提交和未跟踪的构建输入，提交号只代表基线。
每次运行和重新分析都生成新文件，保留历史数据。
