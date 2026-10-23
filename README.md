# cecil-rs

[![CI](https://github.com/hwyyds-skidder-team/cecil-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/hwyyds-skidder-team/cecil-rs/actions/workflows/ci.yml)
[![Fuzz](https://github.com/hwyyds-skidder-team/cecil-rs/actions/workflows/fuzz.yml/badge.svg)](https://github.com/hwyyds-skidder-team/cecil-rs/actions/workflows/fuzz.yml)

Mono.Cecil 的 Rust 完整重写:读取、检查、修改并写回 .NET 程序集(ECMA-335)。

`0.1.0` 开发完成：包含程序集读写、IL 编辑、符号读写、混合模式支持、
损坏输入防护和性能优化；各项支持范围与限制见下文。

主 crate 名为 `cecil-rs`，Rust 库导入名为 `cecil`；配套 crate 使用 `cecil-*`
前缀，CLI 命令为 `cecil`。在本仓库中使用库的依赖配置：

```toml
[dependencies]
cecil = { package = "cecil-rs", path = "crates/cecil-rs" }
```

```rust
use cecil::AssemblyDefinition;

let mut asm = AssemblyDefinition::read_file("demo.dll")?;
let module = asm.main_module_mut();

if let Some(ty) = module.get_type("Demo", "Greeter") {
    println!("found {}", module.type_full_name(ty));
}

asm.write_file("patched.dll")?;
```

## 发布构建

发布构建启用 ThinLTO 和单个 codegen unit。CLI 默认使用 mimalloc，
可通过 `cargo build -p cecil-cli --no-default-features --release` 使用系统分配器。
库使用者可启用 `cecil-rs` 的 `fast-allocator` feature，并在程序入口选择安装：

```rust,ignore
#[global_allocator]
static ALLOCATOR: cecil::MiMalloc = cecil::MiMalloc;
```

该 feature 仅导出分配器类型，库本身不安装全局分配器。性能结果应注明宿主的分配器配置。

## Crate 布局

依赖单向分层,上层不感知下层细节之外的内容:

| Crate | 职责 |
|---|---|
| `cecil-core` | 二进制游标(含 Cecil 逐位等价的压缩整数)、Token/表/编码索引、ElementType、全部特性位标志 |
| `cecil-pe` | PE32/PE32+ 镜像解析与生成(未修改镜像字节级直通;修改后规范化重建,含校验和) |
| `cecil-metadata` | BSJB 根、五堆、全部 45+8 张表的 schema、行读写与 `MetadataBuilder` |
| `cecil-cil` | 219 条操作码表、方法体模型、fat/tiny 头与异常子句编解码 |
| `cecil-rs` | 门面(库导入名 `cecil`):arena 对象模型、Assembly 读/写、签名/特性/封送/安全编解码、解析器、导入器、类型名解析器、IL 编辑器、WinRT 投影、强名签名(`strongname` feature) |
| `cecil-pdb` | Portable PDB + 原生 PDB 读写(MSF7、DBI、CodeView、C13 行号/作用域) |
| `cecil-mdb` | Mono MDB 符号格式读写 |
| `cecil-rocks` | 原 Mono.Cecil.Rocks 全部扩展的 trait 形式(GetAllTypes、GetEnumUnderlyingType、IL 校验、DocCommentId 等) |
| `cecil-cli` | `cecil` 命令行工具(inspect / dump / verify / roundtrip / diff) |

## 能力概览

- 读 → 检查 → 改 → 写完整闭环;未触碰的镜像可字节级直通;Win32 资源与 PE
  debug 目录在读时保留、写时原样重发(RVA 重定位)
- 运行时增删:`add_type/add_method/...` 与 `remove_type/remove_method/...`
  (eager compaction,全模型句柄重映射)
- 引用解析:`AssemblyDefinition::resolve_type_with`(Cecil
  `TypeReference.Resolve` 对应物,经 `AssemblyBytesLoader` 按需加载依赖,
  `DirectoryLoader` 为磁盘实现);`WriteParameters::reference_images` 驱动
  写侧外部值类型的精确 CLASS/VALUETYPE 分类
- `calli` 的 CallSite 类型化签名(`ROperand::CallSite`,Cecil `CallSite`
  对应物);独立 netmodule 写出(`write_module`);核心类型辅助
  (`type_system` 模块,Cecil `TypeSystem` 对应物);Module/InterfaceImpl/
  GenericParamConstraint 三处 custom attribute 读写;写侧 PE 时间戳与
  确定性 MVID
- 泛型实例 / vararg / 函数指针 / 自定义修饰符等全部签名字形
- 自定义特性:构造函数签名驱动的真实镜像解码 + 类型化参数视图
- 方法体编辑:`BodyEditor`(插入/替换/删除/发射辅助)、`simplify_macros` / `optimize_macros` / `renumber`
- 符号:三格式接入主读流程(`read_symbols` 自动嗅探 Portable PDB / 原生
  PDB / Mono MDB,`SymbolReaderProvider` 可注入自定义来源;无 sidecar 时
  回退到镜像内嵌 PDB)、Portable PDB 读写(文档、序列点、局部作用域、
  CustomDebugInformation 原始透传)、原生 PDB 读写、MDB 读写
- 符号输出注入(`WriteParameters::symbol_output`,Cecil
  `ISymbolWriterProvider` 对应物):standalone Portable PDB sidecar /
  **MPDB 内嵌 PDB**("MPDB"+长度+raw Deflate,附 SHA-256 PdbChecksum 条目,
  读侧自动回退)/ Windows native PDB sidecar / Mono MDB sidecar
- P/Invoke、封送规范全量 NativeTypeSpec、安全声明(XML/二进制两种线格式)
- WinRT 投影(`apply_projections` / `remove_projections`,移植自 WindowsRuntimeProjections.cs)
- 强名签名:`.snk` 密钥解析与 PE 签名;`WriteParameters::strong_name_key`
  直接在 `write` 流程内完成签名目录预留 + 公钥替换 + 签名(启用
  `strongname` feature)

### 损坏输入、混合模式与原生 PDB

默认读取使用 `MalformedInputPolicy::Recover`，在可恢复的成员解码错误处保留
`Module::read_diagnostics`；需要首个错误即失败时，在 `ReaderParameters` 中设置
`MalformedInputPolicy::Strict`。两种模式都检查物理边界、递归深度和输入相关的
解码预算。恢复模型可能缺少损坏成员；写出会保留原始镜像，无法安全支持的编辑返回错误。
元数据模型预算为元数据根大小的 128 倍、上限 256 MiB；内嵌 PDB 解压上限为 256 MiB。

混合模式读取区分托管 IL、原生方法 RVA 和原生入口；`Module::is_mixed_mode()`、
`native_method_rva()` 和 `native_entry_point_rva` 可查询。未编辑时逐字节保留原始 PE。
支持修改已有定义名称和 IL 方法体、用户字符串、局部变量类型、calli、catch 类型，
以及追加 TypeRef/TypeSpec/MemberRef/MethodSpec/StandAloneSig/AssemblyRef/ModuleRef。
允许追加顶层非泛型 helper 类型及连续拥有的字段/普通 IL 方法；原始 metadata 含
FieldPtr/MethodPtr/ParamPtr 时暂不追加 helper。原有 token 和 heap
偏移保持不变，表或 heap 超过索引宽度阈值时重新编码数值引用。编辑后的内容追加到新节，
原生代码、原有节/RVA、imports、TLS、relocations 和 vtable fixups 保持位置。
仍拒绝删除/重排原有定义、修改原有成员签名、向原有类型插入成员、native 方法改为 IL、
helper 的泛型/属性/事件/布局/辅助注解，以及签名镜像的修改。
需要可用的节头空间；预编译 managed-native 镜像拒绝元数据搬迁。
可通过 `SymbolOutput::NativePdb` 写出 Windows PDB，也支持 Portable/Embedded/MDB 输出。
IL 编辑时需同步修改 `Module::debug` 中的序列点和作用域偏移；默认写出保留原有符号目录。
示例见 [mixed_mode_edit.rs](crates/cecil-rs/examples/mixed_mode_edit.rs)。

原生 PDB 由手写 MSF7/DBI/CodeView 读写器处理，跨平台且不依赖 WinAPI、DIA
或第三方 PDB 库。提供托管/原生过程、public symbols、C13 文件校验和与行列、
词法作用域、局部名称/类型索引/托管槽、常量与 imports。托管 IL 信息附加到
`Module::debug`，完整原生信息保留在 `Module::native_debug`；有 section/OMAP
映射时计算原生 RVA。暂不解码 C11 行表、TPI/IPI 类型图、原生变量位置/生存期、
OEM/inlining 内容。`NativePdbBuilder::from_pdb` 保留原始 TPI/IPI 和过程类型；重写模块时
仅重建已建模的符号，不恢复 native 寄存器/frame/defrange 位置。facade 写出生成与内容
相关的新 PDB identity，并让 RSDS 与 sidecar 一致，避免匹配旧符号缓存。新建 native 过程缺少
类型图时使用 T_NOTYPE。Native→Portable 转换将同地址多行保留为最后一项，并为省略
列号的可见行使用最小列宽。Portable PDB 序列点支持同一方法的多文档切换。

```rust
use cecil::assembly::{SymbolOutput, WriteParameters};
// asm 已通过 read_file_with(..., read_symbols: true) 读取，可编辑托管 IL。
asm.write_file_with("edited.exe", &WriteParameters {
    symbol_output: Some(SymbolOutput::NativePdb),
    ..Default::default()
})?;
```

独立验证：11 个原生 PDB fixture 重建后函数/文档/publics 模型一致，LLVM 可读取其
结构、行号、publics 和类型流；ComplexPdb 的完整常量 dump 触发 LLVM APSInt 限制，
该错误也发生于原文件。示例见 [native_pdb_rebuild.rs](crates/cecil-pdb/examples/native_pdb_rebuild.rs)。

### 超越 Cecil 的能力(上游没有)

- **双向交叉引用**(`xref::Xref`):一次构建,常数时间回答"谁用它"与
  "它用什么"两个方向,每处使用带类别(call/newobj、字段读/写/取地址、
  类型操作数、基类/接口/约束/签名),外部方法/字段也可按
  `Ns.Type::Member` 键查询;`index::ReferenceIndex` 为其无类别投影
- **控制流图**(`flow::Cfg`):基本块、支配树、自然循环检测——Cecil.FX
  的 FlowAnalysis 2009 年弃坑,混淆器/反编译器至今各自手搓
- **求值栈模拟**(`flow::recompute_max_stack`):ECMA III.1.7.5 精确
  max_stack 重算(兼做方法体校验器),经全部 86 个夹具、3715 个方法体
  与镜像存储值逐一比对验证
- **语义 diff**(`diff::diff`):类型/成员/IL 三层对齐的差异报告,布局
  变化(堆顺序、时间戳)不产生噪音
- **CLI 工具**(`cargo run -p cecil-cli`):`inspect` / `dump --il` /
  `verify` / `roundtrip` / `diff` / `xref` 六个子命令

## 与 Mono.Cecil 的 API 差异

能力面对齐(经逐文件审计核对),使用模型重新设计为 Rust 惯用风格:

- **值语义 arena 模型**:成员以 `TypeId`/`MethodId` 等 Copy 句柄交叉引用;
  引用与定义由 `TypeDesc::Def | External(...)` 枚举表达
- **共享引用**:外部类型、方法、字段、程序集 scope、函数指针和泛型参数切片使用
  `Arc`，基本类型名称使用 `Arc<str>`。克隆这些引用不再复制整个引用树。
  从旧 API 迁移时，将 `Box::new(...)` 改为 `Arc::new(...)`，将 owned 外部方法/
  字段/scope 和 `Vec` 参数切片通过 `.into()` 转换；字符串字面量的 `.into()` 仍可用。
  修改共享对象时使用 `Arc::make_mut`，保持其他引用和已克隆模块的独立内容
- **`Result` 替代异常**:所有格式错误返回 `cecil_core::Error`,不 panic
- **扩展方法 → trait**:`ModuleDefinitionRocks` 等显式引入
- `ReadingMode::Lazy` 延迟方法体解码(`load_bodies()` 按需恢复);偏离点:体作为整体
  延迟而非逐成员代理。其余有意偏离(BCL 强依赖项)记录于各模块文档:GAC 自动探测
  (改为显式搜索目录 + 版本比较选择)、CSP 具名密钥容器(仅支持 .snk 文件)

## 测试

```sh
cargo test --workspace --all-features   # 含真实夹具的读→写→重读、符号和强名测试
cargo test -p cecil-rs --features strongname   # 强名签名套件(含 write 集成签名)
```

`fixtures/` 内置 127 个真实 .NET 程序集/PDB/MDB 作为回归基线。

CI(GitHub Actions)覆盖 fmt / clippy(-D warnings)/ 双平台测试矩阵 / MSRV(1.88)/ fuzz 目标编译;
fuzz(libFuzzer)每晚对 6 个解析入口做变异测试,种子来自 fixtures 语料;benchmark
(criterion)定期跑并在 Artifacts 留报告。

## Fuzzing

```sh
cargo install cargo-fuzz
cd fuzz
cargo fuzz run read_assembly -- -max_total_time=60        # 全链读取
cargo fuzz run roundtrip -- -max_total_time=60            # 读→写→重读性质测试
cargo fuzz run parse_metadata -- -max_total_time=60       # BSJB 根
cargo fuzz run parse_portable_pdb -- -max_total_time=60   # Portable PDB
cargo fuzz run parse_native_pdb -- -max_total_time=60     # 原生 PDB(MSF)
cargo fuzz run parse_mdb -- -max_total_time=60            # Mono MDB
```

语料不提交(gitignore);运行前从 fixtures 复制种子(定时任务自动做,见
`.github/workflows/fuzz.yml`)。主要在 Linux 上跑——Windows 工具链对
libFuzzer/ASan 支持不完整。

## Benchmark

```sh
cargo bench -p cecil-rs           # read / write / roundtrip / dag_read 四组
```

固定七个输入的四库对比及严格 63 项验收见
[四库基准说明](scripts/compare-managed/README.md)。运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/compare-managed/run.ps1 -RequireAllCells
```

报告保存逐项和逐轮结果、独立读者的元数据/IL 语义验证、分配器/编译配置及源码归档。
性能结论只适用于所记录的输入与配置。
2026-10-23 的冻结源码三轮验收通过：汇总和每轮均为 63/63，详见
[完整结果](benchmarks/20261023-185319-143072-managed-comparison.raw.md)。该归档早于
随后新增的 native PDB 与 mixed 元数据编辑实现。

历史基准报告、原始数据和源码归档保留测量时的旧实现标签 `cecli-rs`；
报告脚本兼容旧标签，当前构建和新测量统一使用 `cecil-rs`。

`dag_read` 是线性回归基准:对合成的 doubling-DAG 镜像(每行 TypeSpec 引用前行两次,
展开后 ~2^N 节点)计时读取。Arc 共享 + 子树提升之前 30 行即可 OOM;现在 28 行
约 10µs,时间随行数线性增长——该基准防止性能回退。

## License

MIT(与上游 Mono.Cecil 一致)
