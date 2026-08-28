# cecli-rs

[![CI](https://github.com/hwyyds-skidder-team/cecil-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/hwyyds-skidder-team/cecil-rs/actions/workflows/ci.yml)
[![Fuzz](https://github.com/hwyyds-skidder-team/cecil-rs/actions/workflows/fuzz.yml/badge.svg)](https://github.com/hwyyds-skidder-team/cecil-rs/actions/workflows/fuzz.yml)

Mono.Cecil 的 Rust 完整重写:读取、检查、修改并写回 .NET 程序集(ECMA-335)。

```rust
use cecli::AssemblyDefinition;

let mut asm = AssemblyDefinition::read_file("demo.dll")?;
let module = asm.main_module_mut();

if let Some(ty) = module.get_type("Demo", "Greeter") {
    println!("found {}", module.type_full_name(ty));
}

asm.write_file("patched.dll")?;
```

## Crate 布局

依赖单向分层,上层不感知下层细节之外的内容:

| Crate | 职责 |
|---|---|
| `cecli-core` | 二进制游标(含 Cecil 逐位等价的压缩整数)、Token/表/编码索引、ElementType、全部特性位标志 |
| `cecli-pe` | PE32/PE32+ 镜像解析与生成(未修改镜像字节级直通;修改后规范化重建,含校验和) |
| `cecli-metadata` | BSJB 根、五堆、全部 45+8 张表的 schema、行读写与 `MetadataBuilder` |
| `cecli-cil` | 219 条操作码表、方法体模型、fat/tiny 头与异常子句编解码 |
| `cecli` | 门面:arena 对象模型、Assembly 读/写、签名/特性/封送/安全编解码、解析器、导入器、类型名解析器、IL 编辑器、WinRT 投影、强名签名(`strongname` feature) |
| `cecli-pdb` | Portable PDB(文档/序列点/作用域)+ 原生 PDB(MSF 容器 + CodeView 符号/行号,只读) |
| `cecli-mdb` | Mono MDB 符号格式读写 |
| `cecli-rocks` | 原 Mono.Cecil.Rocks 全部扩展的 trait 形式(GetAllTypes、GetEnumUnderlyingType、IL 校验、DocCommentId 等) |
| `cecli-cli` | `cecli` 命令行工具(inspect / dump / verify / roundtrip / diff) |

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
  CustomDebugInformation 原始透传)、原生 PDB 行号读取、MDB 读写
- 符号输出注入(`WriteParameters::symbol_output`,Cecil
  `ISymbolWriterProvider` 对应物):standalone Portable PDB sidecar /
  **MPDB 内嵌 PDB**("MPDB"+长度+raw Deflate,附 SHA-256 PdbChecksum 条目,
  读侧自动回退)/ Mono MDB sidecar
- P/Invoke、封送规范全量 NativeTypeSpec、安全声明(XML/二进制两种线格式)
- WinRT 投影(`apply_projections` / `remove_projections`,移植自 WindowsRuntimeProjections.cs)
- 强名签名:`.snk` 密钥解析与 PE 签名;`WriteParameters::strong_name_key`
  直接在 `write` 流程内完成签名目录预留 + 公钥替换 + 签名(启用
  `strongname` feature)

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
- **CLI 工具**(`cargo run -p cecli-cli`):`inspect` / `dump --il` /
  `verify` / `roundtrip` / `diff` / `xref` 六个子命令

## 与 Mono.Cecil 的 API 差异

能力面对齐(经逐文件审计核对),使用模型重新设计为 Rust 惯用风格:

- **值语义 arena 模型**:成员以 `TypeId`/`MethodId` 等 Copy 句柄交叉引用;
  引用与定义由 `TypeDesc::Def | External(...)` 枚举表达
- **`Result` 替代异常**:所有格式错误返回 `cecli_core::Error`,不 panic
- **扩展方法 → trait**:`ModuleDefinitionRocks` 等显式引入
- `ReadingMode::Lazy` 延迟方法体解码(`load_bodies()` 按需恢复);偏离点:体作为整体
  延迟而非逐成员代理。其余有意偏离(BCL 强依赖项)记录于各模块文档:GAC 自动探测
  (改为显式搜索目录 + 版本比较选择)、CSP 具名密钥容器(仅支持 .snk 文件)

## 测试

```sh
cargo test --workspace          # 405 个测试,含真实程序集夹具的读→写→重读等价套件
cargo test -p cecli --features strongname   # 强名签名套件(含 write 集成签名)
```

`fixtures/` 内置 127 个真实 .NET 程序集/PDB/MDB 作为回归基线。

CI(GitHub Actions)覆盖 fmt / clippy(-D warnings)/ 双平台测试矩阵 / MSRV(1.87)/ fuzz 目标编译;
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
cargo bench -p cecli           # read / write / roundtrip / dag_read 四组
```

`dag_read` 是线性回归基准:对合成的 doubling-DAG 镜像(每行 TypeSpec 引用前行两次,
展开后 ~2^N 节点)计时读取。Arc 共享 + 子树提升之前 30 行即可 OOM;现在 28 行
约 10µs,时间随行数线性增长——该基准防止性能回退。

## License

MIT(与上游 Mono.Cecil 一致)
