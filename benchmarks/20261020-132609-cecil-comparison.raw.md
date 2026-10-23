# cecli-rs 与 Mono.Cecil 性能实测

测试时间：2026-10-20T13:26:09.9211429+08:00；Rust 提交：`d508c8cca9f3be36a9eefb165e9638ca9b1bee61`。

Windows 10.0.26200，Genuine Intel(R) 0000，14 核 / 20 线程，内存 15.8 GiB。
rustc 1.97.1 (8bab26f4f 2026-07-14)，release 默认优化；Mono.Cecil 0.11.6，Roslyn 4.14.0 优化编译，.NET 10.0.13 x64，关闭分层 JIT，工作站 GC。

每种输入、场景、实现分别运行 3 个独立进程；每进程预热 2000 ms，采集 15 个批次，每批目标 160 ms。两实现交替顺序、串行执行。表中耗时是全部批次每次操作均值的中位数。

所有输入在计时前读取为内存字节；编译、进程启动、文件 I/O、预热均不计入。未读取 PDB、未签名。Cecil 显式访问元数据、特性原始 blob 和全部 IL；Rust 默认完整读取。读取和往返包含模型创建及释放；C# 计时中允许正常 GC。

比值 = Cecil 耗时 / Rust 耗时；大于 1 表示 Rust 较快，小于 1 表示 Cecil 较快。

| 输入 | 大小 KiB | 操作 | Rust ms | Cecil ms | Cecil / Rust |
| --- | ---: | --- | ---: | ---: | ---: |
| SQLite-net.dll | 69.5 | 完整读取 | 2.0299 | 1.2939 | 0.64× |
| SQLite-net.dll | 69.5 | 重新写出 | 2.2209 | 1.4333 | 0.65× |
| SQLite-net.dll | 69.5 | 读取→写出 | 4.2864 | 2.9347 | 0.68× |
| cecil.dll (fixture) | 336.0 | 完整读取 | 12.1471 | 20.0413 | 1.65× |
| cecil.dll (fixture) | 336.0 | 重新写出 | 17.3600 | 15.0772 | 0.87× |
| cecil.dll (fixture) | 336.0 | 读取→写出 | 35.3373 | 52.9352 | 1.50× |
| Mono.Cecil.dll (0.11.6) | 353.0 | 完整读取 | 11.8962 | 19.0103 | 1.60× |
| Mono.Cecil.dll (0.11.6) | 353.0 | 重新写出 | 10.3043 | 16.4955 | 1.60× |
| Mono.Cecil.dll (0.11.6) | 353.0 | 读取→写出 | 22.5239 | 50.7296 | 2.25× |
| Microsoft.CodeAnalysis.dll | 2958.8 | 完整读取 | 207.7613 | 379.6284 | 1.83× |
| Microsoft.CodeAnalysis.dll | 2958.8 | 重新写出 | 243.7953 | 160.8555 | 0.66× |
| Microsoft.CodeAnalysis.dll | 2958.8 | 读取→写出 | 661.8793 | 392.8369 | 0.59× |
| Microsoft.CodeAnalysis.CSharp.dll | 6540.8 | 完整读取 | 497.8356 | 898.1628 | 1.80× |
| Microsoft.CodeAnalysis.CSharp.dll | 6540.8 | 重新写出 | 809.4264 | 365.2816 | 0.45× |
| Microsoft.CodeAnalysis.CSharp.dll | 6540.8 | 读取→写出 | 1865.0095 | 1260.4668 | 0.68× |

## 按场景汇总

几何平均仅描述本次样本集合，每个输入权重相同；不代表真实生产工作负载。

- 完整读取：Cecil / Rust 几何平均 **1.41×**，Rust 较快的输入 4/5。
- 重新写出：Cecil / Rust 几何平均 **0.77×**，Rust 较快的输入 1/5。
- 读取→写出：Cecil / Rust 几何平均 **0.98×**，Rust 较快的输入 2/5。

## 正确性与比较范围

原始输入的类型、方法、字段、属性、事件、自定义特性、IL 方法体、指令、局部变量和异常处理器数量全部与对方一致；双方写出后自身重读，以及对方交叉重读均通过。数量一致不能证明 IL 操作数或全部程序集语义完全等价。

| 输入 | 类型 | 方法 | IL 方法体 | 指令 | Rust 输出字节 | Cecil 输出字节 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
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
| SQLite-net.dll | 完整读取 | 1.9375–3.3855 | 1.2291–2.0672 |
| SQLite-net.dll | 重新写出 | 2.2034–3.6886 | 1.3763–2.7636 |
| SQLite-net.dll | 读取→写出 | 4.1669–7.6714 | 2.8791–5.5394 |
| cecil.dll (fixture) | 完整读取 | 12.0446–18.8395 | 19.3627–23.4584 |
| cecil.dll (fixture) | 重新写出 | 17.2495–17.8621 | 14.4548–17.3621 |
| cecil.dll (fixture) | 读取→写出 | 33.8221–37.8062 | 44.4709–54.9576 |
| Mono.Cecil.dll (0.11.6) | 完整读取 | 11.2676–16.4870 | 15.8117–22.3842 |
| Mono.Cecil.dll (0.11.6) | 重新写出 | 10.0474–22.5863 | 10.4658–20.1849 |
| Mono.Cecil.dll (0.11.6) | 读取→写出 | 20.2491–37.6066 | 47.2465–75.2788 |
| Microsoft.CodeAnalysis.dll | 完整读取 | 150.5070–221.9872 | 303.3437–511.1977 |
| Microsoft.CodeAnalysis.dll | 重新写出 | 212.3573–487.4941 | 95.4916–253.1079 |
| Microsoft.CodeAnalysis.dll | 读取→写出 | 347.3631–730.9687 | 347.8212–647.5753 |
| Microsoft.CodeAnalysis.CSharp.dll | 完整读取 | 288.9559–543.0839 | 571.2178–1091.4608 |
| Microsoft.CodeAnalysis.CSharp.dll | 重新写出 | 700.3807–1428.2176 | 262.1141–385.9765 |
| Microsoft.CodeAnalysis.CSharp.dll | 读取→写出 | 1009.7637–1912.3544 | 909.9822–1534.3167 |

## 复现

```powershell
powershell -ExecutionPolicy Bypass -File scripts/compare-cecil/run.ps1
```

环境和输入 SHA-256：`20261020-132609-cecil-comparison.environment.json`；原始样本：`20261020-132609-cecil-comparison.raw.jsonl`；汇总：`20261020-132609-cecil-comparison.raw.csv`。
