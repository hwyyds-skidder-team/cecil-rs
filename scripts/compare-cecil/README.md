# cecil-rs 与 Mono.Cecil 性能对比

运行 `powershell -ExecutionPolicy Bypass -File scripts/compare-cecil/run.ps1`。
脚本在 `target/compare-cecil` 下载固定版本 Mono.Cecil 0.11.6 和 Roslyn 4.14.0，
使用本机 .NET 运行时编译 C# 对照程序，并以 release profile 编译 Rust 程序。
不需要安装 .NET SDK。原始结果和中文报告保存到 `benchmarks/`。

默认启用 `-CargoFeatures fast-allocator`，与正式 CLI 的默认 mimalloc 配置一致；
release profile 使用 ThinLTO 和一个 codegen unit。分配器属于测试配置，结果不代表
系统默认分配器下的耗时。传入 `-CargoFeatures ''` 可复测系统分配器。
库的 `fast-allocator` feature 只导出 `cecil::MiMalloc`，由宿主程序显式安装，
不会替换使用者已有的全局分配器。计时操作和七个输入始终相同。

输入包括四个仓库夹具、Mono.Cecil 0.11.6 本身，以及 Roslyn 4.14.0 的
Microsoft.CodeAnalysis / Microsoft.CodeAnalysis.CSharp 两个大型纯托管程序集。

测试只计内存中的程序集操作，文件读取、进程启动、编译和预热不计入结果。
Mono.Cecil 使用 Deferred 模式并显式加载元数据和全部 IL，避免把懒加载入口
与 Rust 默认的完整读取直接比较。自定义特性读取原始 blob，两边不主动解析外部
程序集、不读取 PDB、不签名。Cecil 写入枚举常量时会自动解析依赖，使用共用
resolver 缓存，相关首次解析在预热期完成。完整读取包含模型释放；C# 的 GC 正常运行，
仅在每个场景的预热之前清理一次。

- `read`: 元数据和全部 IL 的读取、遍历计数及释放。
- `write`: 已完整读取模型的重新序列化，输出新内存缓冲区；不包含预先读取。
- `roundtrip`: 完整读取后序列化，输出新内存缓冲区。
- `validate`: 写出并重读，检查数量和规范化元数据/IL 指纹。仅验证阶段生成指纹，
  计时循环不受影响。
- `inspect`: 只读取输入并生成数量和指纹，供交叉重读双方输出使用。

验证要求每个读者独立满足：原始输入 = 自己的输出 = 对方的输出。
两个读者的指纹格式不同，互不比较。除了数量，指纹还覆盖类型和成员名称与标志、
带作用域的签名、泛型约束、接口、常量、字段数据、特性构造函数及 blob、安全声明、
P/Invoke、覆盖和访问器、托管资源、IL 操作码与解析后操作数、浮点位模式、
局部类型、init-locals、分支目标和异常区域。

引用使用名称/作用域/签名；分支和异常边界使用指令序号，避免把 token/RID、
堆偏移、RVA、MVID 和 PE 布局变化误报为语义改变。不同 try 区域的 EH 组按边界
规范排序；**同一 try 区域内 catch/filter 的顺序保留**。Cecil 会重算的 max-stack
不进入指纹。Rust 使用稳定 FNV-1a-128 作意外损坏检查；Cecil 使用 SHA-256。
本检查不等价于执行验证，未完整覆盖符号、封送描述、导出类型和 Win32 资源。
若失败，脚本保留规范化明细和已写出的 DLL，避免仅凭相同数量认定结果正确。

注意：两个对象模型和内存管理方式不同，这是一组相同输入和主要工作量下的
实测，不能单独归因于编程语言。重复写出使用同一个已加载模型，Cecil 写入器
可能保留缓存。报告记录这项限制，并提供读写往返作为一次性使用的对照。

默认每格运行三轮，两个实现交替先后顺序。使用 `-RequireAllCells` 让脚本在未达到
性能目标时返回非零状态：固定七输入 × 三场景必须全部存在，至少三轮，**每格的
汇总中位数和每一对应轮次的中位数均须快于 Cecil**，并通过语义验证和源码溯源。
几何平均仅供描述，不能抵消任何落后的格。筛选输入或场景仅用于定位，不能通过
完整验收。逐轮比较是有限重复证据，不是统计置信区间。

每次运行使用毫秒时间戳创建新结果和 `target/compare-cecil/runs/<timestamp>`。
报告保存 JSONL 原始样本、CSV 汇总、逐格 `.acceptance.json`、环境记录、
构建输入逐文件 SHA-256，以及包含实际源码的 ZIP（含未提交/未跟踪构建输入）。
提交号标识基线，源码归档标识实际构建；编译、验证和计时后均复查源码是否变化。
环境记录包含 Cargo profile/参数、编译相关环境变量、Cargo 配置文件哈希、
双方驱动源码/二进制哈希和 .NET 配置。旧版记录缺少这些信息时会明确报告。
重新分析已有原始数据会生成新文件，保留历史报告。

可用 `-CargoTargetDir target/perf-cecil` 选择独立构建目录，或使用 `-CargoProfile`
选择已定义的 Cargo profile；配置会进入环境记录。`-ValidateOnly` 只执行验证、
源码归档和环境记录，不采集性能样本。

可用 `-InputFilter` 和 `-ModeFilter` 正则表达式复测部分项目，例如：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/compare-cecil/run.ps1 -InputFilter 'SQLite|cecil|Microsoft.CodeAnalysis' -WarmupMs 2000 -Samples 15 -SampleMs 160
```

完整验收：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/compare-cecil/run.ps1 -CargoTargetDir target/perf-cecil -RequireAllCells
```
