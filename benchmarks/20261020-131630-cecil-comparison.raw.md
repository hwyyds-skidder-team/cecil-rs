# cecli-rs 与 Mono.Cecil 性能实测

测试时间：2026-10-20T13:16:30.9588024+08:00；Rust 提交：`d508c8cca9f3be36a9eefb165e9638ca9b1bee61`。

Windows 10.0.26200，Genuine Intel(R) 0000，14 核 / 20 线程，内存 15.8 GiB。
rustc 1.97.1 (8bab26f4f 2026-07-14)，release 默认优化；Mono.Cecil 0.11.6，Roslyn 4.14.0 优化编译，.NET 10.0.13 x64，关闭分层 JIT，工作站 GC。

每种输入、场景、实现分别运行 3 个独立进程；每进程预热 800 ms，采集 11 个批次，每批目标 120 ms。两实现交替顺序、串行执行。表中耗时是全部批次每次操作均值的中位数。

所有输入在计时前读取为内存字节；编译、进程启动、文件 I/O、预热均不计入。未读取 PDB、未签名。Cecil 显式访问元数据、特性原始 blob 和全部 IL；Rust 默认完整读取。读取和往返包含模型创建及释放；C# 计时中允许正常 GC。

比值 = Cecil 耗时 / Rust 耗时；大于 1 表示 Rust 较快，小于 1 表示 Cecil 较快。

| 输入 | 大小 KiB | 操作 | Rust ms | Cecil ms | Cecil / Rust |
| --- | ---: | --- | ---: | ---: | ---: |
| hello.exe | 3.5 | 完整读取 | 0.0086 | 0.0045 | 0.53× |
| hello.exe | 3.5 | 重新写出 | 0.0133 | 0.0068 | 0.51× |
| hello.exe | 3.5 | 读取→写出 | 0.0230 | 0.0119 | 0.51× |
| System.Runtime.dll (fixture) | 21.6 | 完整读取 | 0.0454 | 0.0184 | 0.41× |
| System.Runtime.dll (fixture) | 21.6 | 重新写出 | 0.0538 | 0.0235 | 0.44× |
| System.Runtime.dll (fixture) | 21.6 | 读取→写出 | 0.1100 | 0.0429 | 0.39× |
| SQLite-net.dll | 69.5 | 完整读取 | 1.9223 | 1.1100 | 0.58× |
| SQLite-net.dll | 69.5 | 重新写出 | 2.0932 | 1.3207 | 0.63× |
| SQLite-net.dll | 69.5 | 读取→写出 | 4.0512 | 2.8168 | 0.70× |
| cecil.dll (fixture) | 336.0 | 完整读取 | 12.4896 | 11.3017 | 0.90× |
| cecil.dll (fixture) | 336.0 | 重新写出 | 8.8394 | 7.8181 | 0.88× |
| cecil.dll (fixture) | 336.0 | 读取→写出 | 20.6120 | 39.0357 | 1.89× |
| Mono.Cecil.dll (0.11.6) | 353.0 | 完整读取 | 13.1158 | 11.5251 | 0.88× |
| Mono.Cecil.dll (0.11.6) | 353.0 | 重新写出 | 10.3312 | 9.9855 | 0.97× |
| Mono.Cecil.dll (0.11.6) | 353.0 | 读取→写出 | 21.8189 | 41.7407 | 1.91× |
| Microsoft.CodeAnalysis.dll | 2958.8 | 完整读取 | 143.4266 | 263.9606 | 1.84× |
| Microsoft.CodeAnalysis.dll | 2958.8 | 重新写出 | 200.5750 | 88.0507 | 0.44× |
| Microsoft.CodeAnalysis.dll | 2958.8 | 读取→写出 | 350.6717 | 343.6435 | 0.98× |
| Microsoft.CodeAnalysis.CSharp.dll | 6540.8 | 完整读取 | 309.4841 | 541.5393 | 1.75× |
| Microsoft.CodeAnalysis.CSharp.dll | 6540.8 | 重新写出 | 679.2323 | 187.6997 | 0.28× |
| Microsoft.CodeAnalysis.CSharp.dll | 6540.8 | 读取→写出 | 1011.9327 | 724.1501 | 0.72× |

## 按场景汇总

几何平均仅描述本次样本集合，每个输入权重相同；不代表真实生产工作负载。

- 完整读取：Cecil / Rust 几何平均 **0.85×**，Rust 较快的输入 2/7。
- 重新写出：Cecil / Rust 几何平均 **0.55×**，Rust 较快的输入 0/7。
- 读取→写出：Cecil / Rust 几何平均 **0.86×**，Rust 较快的输入 2/7。

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
| hello.exe | 完整读取 | 0.0084–0.0087 | 0.0044–0.0046 |
| hello.exe | 重新写出 | 0.0132–0.0134 | 0.0067–0.0077 |
| hello.exe | 读取→写出 | 0.0229–0.0231 | 0.0117–0.0129 |
| System.Runtime.dll (fixture) | 完整读取 | 0.0445–0.0460 | 0.0182–0.0189 |
| System.Runtime.dll (fixture) | 重新写出 | 0.0534–0.0542 | 0.0231–0.0239 |
| System.Runtime.dll (fixture) | 读取→写出 | 0.1092–0.1104 | 0.0427–0.0434 |
| SQLite-net.dll | 完整读取 | 1.8422–3.6269 | 1.0848–1.1893 |
| SQLite-net.dll | 重新写出 | 2.0587–2.5651 | 1.3063–1.3940 |
| SQLite-net.dll | 读取→写出 | 3.8997–4.2158 | 2.7465–2.9692 |
| cecil.dll (fixture) | 完整读取 | 10.0405–12.8688 | 10.7001–12.0029 |
| cecil.dll (fixture) | 重新写出 | 8.6323–9.3493 | 7.5220–8.7608 |
| cecil.dll (fixture) | 读取→写出 | 19.1350–21.4058 | 37.5869–39.3107 |
| Mono.Cecil.dll (0.11.6) | 完整读取 | 12.5473–14.0306 | 11.1724–12.2325 |
| Mono.Cecil.dll (0.11.6) | 重新写出 | 10.0729–10.8433 | 9.3471–10.5133 |
| Mono.Cecil.dll (0.11.6) | 读取→写出 | 20.7614–22.3943 | 40.2094–44.1747 |
| Microsoft.CodeAnalysis.dll | 完整读取 | 135.2044–158.7033 | 247.4440–427.2935 |
| Microsoft.CodeAnalysis.dll | 重新写出 | 198.4347–207.2361 | 86.2002–89.6661 |
| Microsoft.CodeAnalysis.dll | 读取→写出 | 345.1741–357.6414 | 332.3944–360.7615 |
| Microsoft.CodeAnalysis.CSharp.dll | 完整读取 | 304.1036–314.3665 | 529.0160–569.5621 |
| Microsoft.CodeAnalysis.CSharp.dll | 重新写出 | 671.8036–1202.1675 | 164.2629–192.7510 |
| Microsoft.CodeAnalysis.CSharp.dll | 读取→写出 | 996.6984–1805.8362 | 668.7236–1129.8017 |

## 复现

```powershell
powershell -ExecutionPolicy Bypass -File scripts/compare-cecil/run.ps1
```

环境和输入 SHA-256：`20261020-131630-cecil-comparison.environment.json`；原始样本：`20261020-131630-cecil-comparison.raw.jsonl`；汇总：`20261020-131630-cecil-comparison.raw.csv`。
