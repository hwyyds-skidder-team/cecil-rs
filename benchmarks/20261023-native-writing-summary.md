# Native PDB 写出与 mixed IL 编辑验收

已实现 Windows native PDB 写出，并将 mixed 写回扩展为保留原有 token、追加新元数据。

## 可用接口与行为

```rust
use cecli::assembly::{SymbolOutput, WriteParameters};
use cecli::resolver::ReaderParameters;
use cecli::AssemblyDefinition;

let mut asm = AssemblyDefinition::read_file_with("input.exe", &ReaderParameters {
    read_symbols: true, ..Default::default()
})?;
// 修改 asm.main 的 IL；同步修改 debug 中序列点与作用域偏移。
asm.write_file_with("edited.exe", &WriteParameters {
    symbol_output: Some(SymbolOutput::NativePdb), ..Default::default()
})?;
```

- mixed 输出保留原有节内容/RVA、native 方法、imports、TLS、relocations、vtable fixups；CLI 元数据目录指向追加节。
- 允许新 AssemblyRef/ModuleRef/TypeRef/TypeSpec/MemberRef/MethodSpec/StandAloneSig、用户字符串、locals、calli、catch 类型与顶层 helper 定义。
- 原有 metadata 行 RID 和 heap 偏移保留；simple/coded/heap 索引宽度跨阈值后按数值重新编码。
- `NativePdbBuilder` 手写 MSF7、双 FPM、info/DBI/GSI/PSI、CodeView 和 C13；`from_pdb` 保留原始类型流及可用 native 过程类型。
- facade NativePdb 输出复用本次生成的 PDB sidecar，更新 RSDS、SHA256 校验和及内容相关 identity；局部变量引用本次实际分配的签名 token。
- mixed 也支持 Portable、EmbeddedPortable 和 MDB 输出。

## 验证结果

| 验证 | 结果 | 证据 |
| --- | --- | --- |
| 全工作区 all-features、strongname、doctests | 577 通过，零失败/忽略 | `target/harden/native-final-workspace-20261023.log` |
| Workspace Clippy all-targets/all-features `-D warnings` | 通过 | `target/harden/native-final-clippy-20261023.log` |
| rustdoc `-D warnings`、fmt、git whitespace | 通过 | `target/harden/native-final-docs-20261023.log` |
| 六个 fuzz binaries 编译、CLI no-default-features | 通过 | `native-final-fuzz-20261023.log` / `native-final-cli-20261023.log` |
| 11 个真实 MSF PDB 重建 | 函数、文档和 publics 模型完全一致；TPI/IPI 保留 | `native/writer.rs` corpus tests |
| LLVM 22.1.8 | 11 个结构/模块/文件/行号/public/type/id 验证通过；10 个完整 symbols dump 通过 | `target/harden/llvm-native-final-*-20261023.txt` |
| 最终 mixed/managed facade PDB | LLVM 完整 dump 通过 | `llvm-native-facade-20261023.txt` / `llvm-managed-native-facade-20261023.txt` |
| dnlib 4.5 | 4 个新元数据样本和 6 个 facade PE 输出均接受 | `mixed-metadata-dnlib-20261023.log` / `native-facade-dnlib-20261023.log` |
| 三个 fuzz archives 回放 | 3113 输入；2450 roundtrips、663 read rejections、零失败 | `target/harden/native-final-roundtrip-20261023.log` |

ComplexPdb 的 LLVM 完整 symbols dump 在 string constant 上触发 APSInt 限制；原文件也出现同一错误。该文件结构与其他内容验证通过，手写读者常量模型重建一致。

## 支持边界

保留旧 token 是保护 native 引用的前提。仍不能删除/重排已有定义、修改已有成员签名、向已有类型插入成员，或把 native 方法改为 IL。新 helper 目前为顶层非泛型类型及连续字段/普通 managed IL 方法，不含属性、事件、布局、泛型和辅助注解；原 metadata 有 FieldPtr/MethodPtr/ParamPtr 时不追加 helper。

native TPI/IPI 图不从新模型合成。重写模块仅恢复已建模的符号；native register/frame/defrange、C11、OEM/inlining 内容未重建。新 native 过程没有类型图时使用 T_NOTYPE。native 签名镜像修改需要重新签名，目前拒绝；PE 追加节需要足够节头空间，预编译 managed-native 映射仍限制搬迁。

编辑 IL 时序列点和作用域偏移需由调用者同步更新。Native→Portable 将同地址多行映射为最后一项，为缺列号的可见行使用最小列宽。native 原始模型保留完整信息。

此前性能基线完成三轮固定 63 项验收，汇总与每轮均为 63/63：[基线结果](20261023-185319-143072-managed-comparison.raw.md)。它针对归档的冻结源码，早于本报告的新功能；本次未重新计时或扩大性能结论。未 commit 或 push。
