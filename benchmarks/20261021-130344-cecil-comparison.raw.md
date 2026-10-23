# cecli-rs 与 Mono.Cecil 性能实测

测试时间：2026-10-21T13:03:44.1885269+08:00；Rust 提交：`d508c8cca9f3be36a9eefb165e9638ca9b1bee61`。

Windows 10.0.26200，Genuine Intel(R) 0000，14 核 / 20 线程，内存 15.8 GiB。
rustc 1.97.1 (8bab26f4f 2026-07-14)，release 默认优化；Mono.Cecil 0.11.6，Roslyn 4.14.0 优化编译，.NET 10.0.13 x64，关闭分层 JIT，工作站 GC。

每种输入、场景、实现分别运行 1 个独立进程；每进程预热 400 ms，采集 7 个批次，每批目标 60 ms。两实现交替顺序、串行执行。表中耗时是全部批次每次操作均值的中位数。

所有输入在计时前读取为内存字节；编译、进程启动、文件 I/O、预热均不计入。未读取 PDB、未签名。Cecil 显式访问元数据、特性原始 blob 和全部 IL；Rust 默认完整读取。读取和往返包含模型创建及释放；C# 计时中允许正常 GC。

比值 = Cecil 耗时 / Rust 耗时；大于 1 表示 Rust 较快，小于 1 表示 Cecil 较快。

| 输入 | 大小 KiB | 操作 | Rust ms | Cecil ms | Cecil / Rust |
| --- | ---: | --- | ---: | ---: | ---: |
| hello.exe | 3.5 | 完整读取 | 0.0090 | 0.0054 | 0.60× |
| hello.exe | 3.5 | 重新写出 | 0.0139 | 0.0083 | 0.60× |
| hello.exe | 3.5 | 读取→写出 | 0.0255 | 0.0138 | 0.54× |
| System.Runtime.dll (fixture) | 21.6 | 完整读取 | 0.0506 | 0.0218 | 0.43× |
| System.Runtime.dll (fixture) | 21.6 | 重新写出 | 0.0589 | 0.0273 | 0.46× |
| System.Runtime.dll (fixture) | 21.6 | 读取→写出 | 0.1290 | 0.0532 | 0.41× |
| SQLite-net.dll | 69.5 | 完整读取 | 2.1665 | 1.2295 | 0.57× |
| SQLite-net.dll | 69.5 | 重新写出 | 2.3723 | 1.4443 | 0.61× |
| SQLite-net.dll | 69.5 | 读取→写出 | 4.4475 | 3.2253 | 0.73× |
| cecil.dll (fixture) | 336.0 | 完整读取 | 16.9886 | 12.1781 | 0.72× |
| cecil.dll (fixture) | 336.0 | 重新写出 | 9.9304 | 9.3391 | 0.94× |
| cecil.dll (fixture) | 336.0 | 读取→写出 | 27.6702 | 39.3342 | 1.42× |
| Mono.Cecil.dll (0.11.6) | 353.0 | 完整读取 | 18.1502 | 12.4133 | 0.68× |
| Mono.Cecil.dll (0.11.6) | 353.0 | 重新写出 | 11.7902 | 11.2108 | 0.95× |
| Mono.Cecil.dll (0.11.6) | 353.0 | 读取→写出 | 29.3089 | 38.1776 | 1.30× |
| Microsoft.CodeAnalysis.dll | 2958.8 | 完整读取 | 154.9285 | 266.7250 | 1.72× |
| Microsoft.CodeAnalysis.dll | 2958.8 | 重新写出 | 220.8062 | 89.9485 | 0.41× |
| Microsoft.CodeAnalysis.dll | 2958.8 | 读取→写出 | 385.8179 | 365.2275 | 0.95× |
| Microsoft.CodeAnalysis.CSharp.dll | 6540.8 | 完整读取 | 366.5857 | 584.2668 | 1.59× |
| Microsoft.CodeAnalysis.CSharp.dll | 6540.8 | 重新写出 | 759.8961 | 211.3011 | 0.28× |
| Microsoft.CodeAnalysis.CSharp.dll | 6540.8 | 读取→写出 | 1137.5565 | 744.1666 | 0.65× |

## 按场景汇总

几何平均仅描述本次样本集合，每个输入权重相同；不代表真实生产工作负载。

- 完整读取：Cecil / Rust 几何平均 **0.79×**，Rust 较快的输入 2/7。
- 重新写出：Cecil / Rust 几何平均 **0.56×**，Rust 较快的输入 0/7。
- 读取→写出：Cecil / Rust 几何平均 **0.79×**，Rust 较快的输入 2/7。

## 正确性与比较范围

原始输入的类型、方法、字段、属性、事件、自定义特性、IL 方法体、指令、局部变量和异常处理器数量全部与对方一致；双方写出后自身重读，以及对方交叉重读均通过。数量一致不能证明 IL 操作数或全部程序集语义完全等价。

| 输入 | 类型 | 方法 | IL 方法体 | 指令 | Rust 输出字节 | Cecil 输出字节 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| hello.exe | 2 | 2 | 2 | 8 | 3584 | 3584 |
| System.Runtime.dll (fixture) | 9 | 10 | 9 | 33 | 6144 | 5632 |
| SQLite-net.dll | 81 | 492 | 492 | 7753 | 73216 | 71168 |
| cecil.dll (fixture) | 298 | 2783 | 2686 | 62880 | 354304 | 343552 |
| Mono.Cecil.dll (0.11.6) | 351 | 3152 | 3046 | 55872 | 374272 | 359936 |
| Microsoft.CodeAnalysis.dll | 2338 | 19417 | 17192 | 301569 | 3105792 | 2999808 |
| Microsoft.CodeAnalysis.CSharp.dll | 2713 | 42395 | 41435 | 865740 | 6888448 | 6633472 |

## 局限与重复测量

- Rust arena 值模型与 Cecil 引用对象模型不同；分配器、GC、缓存和遍历开销均属于当前实现表现，不能把差异单独归因于 Rust 或 C#。
- `write` 重用同一个完整读取模型，并在预热后计时；Cecil 写入会改变或缓存内部状态。一次性处理应参考 `roundtrip`。
- Cecil 写出枚举常量时可能自动解析依赖，共用 resolver 的首次加载在预热期完成；Rust 使用镜像中已记录的值类型标记。未主动调用外部引用解析 API。
- 本机 .NET 运行时的 ReadyToRun DLL 被原版 Cecil 拒绝写出，未纳入计时；大型输入改用 Roslyn 4.14.0 的纯托管程序集。
- 本次测试未做 CPU 绑核或禁用后台应用；小文件更容易受调度、频率和内存管理影响。各独立轮次的中位数范围见下表，原始数据保留所有批次。

| 输入 | 操作 | Rust 轮次中位数范围 ms | Cecil 轮次中位数范围 ms |
| --- | --- | ---: | ---: |
| hello.exe | 完整读取 | 0.0090–0.0090 | 0.0054–0.0054 |
| hello.exe | 重新写出 | 0.0139–0.0139 | 0.0083–0.0083 |
| hello.exe | 读取→写出 | 0.0255–0.0255 | 0.0138–0.0138 |
| System.Runtime.dll (fixture) | 完整读取 | 0.0506–0.0506 | 0.0218–0.0218 |
| System.Runtime.dll (fixture) | 重新写出 | 0.0589–0.0589 | 0.0273–0.0273 |
| System.Runtime.dll (fixture) | 读取→写出 | 0.1290–0.1290 | 0.0532–0.0532 |
| SQLite-net.dll | 完整读取 | 2.1665–2.1665 | 1.2295–1.2295 |
| SQLite-net.dll | 重新写出 | 2.3723–2.3723 | 1.4443–1.4443 |
| SQLite-net.dll | 读取→写出 | 4.4475–4.4475 | 3.2253–3.2253 |
| cecil.dll (fixture) | 完整读取 | 16.9886–16.9886 | 12.1781–12.1781 |
| cecil.dll (fixture) | 重新写出 | 9.9304–9.9304 | 9.3391–9.3391 |
| cecil.dll (fixture) | 读取→写出 | 27.6702–27.6702 | 39.3342–39.3342 |
| Mono.Cecil.dll (0.11.6) | 完整读取 | 18.1502–18.1502 | 12.4133–12.4133 |
| Mono.Cecil.dll (0.11.6) | 重新写出 | 11.7902–11.7902 | 11.2108–11.2108 |
| Mono.Cecil.dll (0.11.6) | 读取→写出 | 29.3089–29.3089 | 38.1776–38.1776 |
| Microsoft.CodeAnalysis.dll | 完整读取 | 154.9285–154.9285 | 266.7250–266.7250 |
| Microsoft.CodeAnalysis.dll | 重新写出 | 220.8062–220.8062 | 89.9485–89.9485 |
| Microsoft.CodeAnalysis.dll | 读取→写出 | 385.8179–385.8179 | 365.2275–365.2275 |
| Microsoft.CodeAnalysis.CSharp.dll | 完整读取 | 366.5857–366.5857 | 584.2668–584.2668 |
| Microsoft.CodeAnalysis.CSharp.dll | 重新写出 | 759.8961–759.8961 | 211.3011–211.3011 |
| Microsoft.CodeAnalysis.CSharp.dll | 读取→写出 | 1137.5565–1137.5565 | 744.1666–744.1666 |

## 复现

```powershell
powershell -ExecutionPolicy Bypass -File scripts/compare-cecil/run.ps1
```

环境和输入 SHA-256：`20261021-130344-cecil-comparison.environment.json`；原始样本：`20261021-130344-cecil-comparison.raw.jsonl`；汇总：`20261021-130344-cecil-comparison.raw.csv`。
