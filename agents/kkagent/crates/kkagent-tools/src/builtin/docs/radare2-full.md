# radare2 命令分类参考（r2 6.x）

> 覆盖解题常用的命令族。SKILL.md 是工作流精编；本文件按类别列全，用于不确定命令/参数时 grep。命令里 `@ addr` 表示临时 seek，`~pat` 表示 grep 过滤，`;` 连接多条命令。

## 0. 启动与批处理

| 命令 | 说明 |
| --- | --- |
| `r2 bin` | 只读打开 |
| `r2 -A bin` | 打开并自动分析（等价 `aaa`） |
| `r2 -d bin` | 调试模式 |
| `r2 -w bin` | 写模式（patch） |
| `r2 -q -c 'cmd' bin` | 执行 cmd 后退出 |
| `r2 -q -c 'cmd' bin > out` | 批处理输出到文件 |
| `r2 -i file.r2 bin` | 执行 r2 脚本 |
| `r2 -e asm.bits=64 -e scr.color=0 bin` | 带配置打开 |
| `r2 -2 bin` | 关闭 stderr（屏蔽警告输出） |
| `r2 -z bin` | 不加载符号/字符串 |
| `r2 --` | 之后的参数传给被调试程序 |

## 1. 信息 info（i*）

| 命令 | 说明 |
| --- | --- |
| `iI` | 二进制整体信息：arch/bits/endian/type/baddr/os/class |
| `iIj` | 同上，JSON |
| `ii` / `iij` | 导入表（imports） |
| `iE` | 导出表（exports） |
| `is` / `isj` | 符号表（symbols） |
| `iS` / `iSj` | 节表（sections，含 VA/大小/权限） |
| `ie` | 入口点（entrypoints） |
| `iH` | 文件头（PE/ELF headers） |
| `iz` | 数据段字符串 |
| `izz` | 全文件字符串（含未映射区域） |
| `izz~flag` | 字符串 grep |
| `iM` | main 地址 |
| `iV` | 版本信息 |
| `om` | 内存映射（调试时） |
| `id` | 动态链接信息 |

## 2. 定位 seek（s）

| 命令 | 说明 |
| --- | --- |
| `s` | 显示当前 seek |
| `s addr` | 跳到地址 |
| `s main` | 跳到符号 |
| `s section..text` | 跳到节名 |
| `s +16` / `s -8` | 相对移动 |
| `s+` / `s-` | 前进/后退一个单位 |
| `s..` | 撤销 seek（回到上一个） |
| `s++` / `s--` | 前进/后退 N 字节（默认 1，可 `s++100`） |

## 3. 分析 analyze（a*）

| 命令 | 说明 |
| --- | --- |
| `aaa` | 完整分析（命名、xref、变量、类型，最常用） |
| `aa` | 基础分析 |
| `aac` | 分析函数调用 |
| `aae` | 分析 ESIL（模拟执行，用于更准确的控制流） |
| `aar` | 分析交叉引用 |
| `aap` | 分析函数序言（prelude） |
| `aav` | 分析值（找潜在指针） |
| `af addr` | 在 addr 定义并分析一个函数 |
| `afl` / `aflj` | 列出函数（name/size/addr） |
| `afl~main` | 过滤函数名 |
| `afr` | 重命名当前函数 |
| `afn newname addr` | 给函数命名 |
| `af+` / `af-` | 手动定义/取消函数 |
| `afvd` | 显示函数变量（反汇编视图） |
| `afv` | 列出函数变量 |
| `afvn new old` | 重命名变量 |
| `afvt` | 设置变量类型 |

## 4. 反汇编 print（p*）

| 命令 | 说明 |
| --- | --- |
| `pdf` | 反汇编当前函数（带控制流 ASCII 图） |
| `pdf @ main` | 反汇编 main |
| `pd N` | 反汇编 N 条指令 |
| `pd 20 @ 0x401000` | 从地址反汇编 20 条 |
| `pD N` | 反汇编 N 字节 |
| `pdr` | 递归反汇编（沿控制流） |
| `pdc` | r2 自带伪代码（近似反编译） |
| `pdd` | 另一种伪代码输出 |
| `pdg` | Ghidra 反编译（需 r2ghidra 插件） |
| `pi N` | 反汇编 N 条指令（纯指令，无地址） |
| `pI N` | 反汇编 N 字节（纯指令） |
| `pid` | 反汇编当前指令 |

## 5. 交叉引用（axt/axf/ax）

| 命令 | 说明 |
| --- | --- |
| `axt addr` | 谁引用该地址（xrefs TO） |
| `axt sym.main` | 谁调用 main |
| `axf addr` | 该地址引用谁（xrefs FROM） |
| `ax` | 列出所有交叉引用 |
| `axg` | xref 图 |
| `/r sym.printf` | 搜对符号的引用 |

## 6. 搜索 search（/）

| 命令 | 说明 |
| --- | --- |
| `/ flag` | 搜 ASCII 字符串 |
| `/w flag` | 搜宽字符串 |
| `/x 9090` | 搜字节序列 |
| `/x 483b4c2430` | 搜机器码 |
| `/a cmp eax, 0x7b` | 搜汇编模式（/a 才是汇编搜索） |
| `/R` | 搜 ROP gadget |
| `/R pop rdi` | 搜指定 gadget |
| `/c` | 搜 crypto 材料（/ca 密钥、/ck 常量表、/cd 证书） |
| `s hit0` | 跳到第 0 个命中点 |
| `/` 回车 | 下一个命中 |

## 7. 写/patch write（w*，需 -w 或 oo+）

| 命令 | 说明 |
| --- | --- |
| `wx 9090` | 写十六进制字节（当前 seek） |
| `wx ff @ addr` | 写到指定地址 |
| `wv 0x1234` | 写立即数（按当前 asm.bits 宽度） |
| `wv1 0x41 @ addr` | 写 1 字节值 |
| `wa nop` | 写汇编指令 |
| `wa "xor eax,eax" @ addr` | 写到地址 |
| `oo+` | 只读打开时重开为读写 |
| `woo [val]` | 对当前块按位或写入（wo* 是位运算写家族，不是切写模式） |
| `wo2/wo4/wo8` | 2/4/8 字节字节序交换 |
| `wB` | 写入缓冲区 |
| `wz string` | 写以 0 结尾的字符串 |
| `ws string` | 写字符串 |
| `we N` | 用 N 覆盖（expand） |
| `q` | 退出（写模式会询问保存；`q!` 强制） |

## 8. 调试 debug（d*，需 -d）

| 命令 | 说明 |
| --- | --- |
| `db addr` | 下断点 |
| `db sym.main` | 符号断点 |
| `db -addr` | 删断点 |
| `dbi` | 列出断点 |
| `dc` | 继续 |
| `dcu addr` | 运行到地址 |
| `ds` | 单步（步入） |
| `dso` | 单步（步过） |
| `dss` | 单步（跳过函数调用） |
| `dr` | 显示所有寄存器 |
| `dr rax` | 显示单寄存器 |
| `dr rax=0x41` | 设寄存器 |
| `dr?` | 寄存器操作帮助 |
| `drt` | 显示寄存器类型 |
| `dm` / `dmj` | 内存映射 |
| `dmp` | 修改内存权限 |
| `dbt` | 调用栈回溯 |
| `doo` | 重开调试 |
| `ood` | 重启被调试进程 |
| `dp` | 列出进程/线程 |
| `dk` | 发信号 |

## 9. 打印内存（px 系列）

| 命令 | 说明 |
| --- | --- |
| `px N` | 十六进制 dump N 字节 |
| `px 32 @ rsp` | dump 栈 |
| `pxq N` | 按 8 字节 dump |
| `pxw N` | 按 4 字节 dump |
| `pxw 16 @ rbp+0x30` | 看栈上 4 字节变量 |
| `pc` | C 数组形式 |
| `ps` | 以字符串打印 |
| `psz` | 打印 0 结尾字符串 |
| `pv` | 打印值（按类型解析） |
| `p8 N` | 8 位字节 dump |
| `p64` / `p32` | 按 8/4 字节立即数 |

## 10. 可视化 visual（V）

| 命令 | 说明 |
| --- | --- |
| `V` | 进入可视化模式 |
| `VV` | 图模式（控制流图） |
| `V!` | 面板模式 |
| `q` | 退出当前层 |
| `p`/`P` | 图模式里切换布局 |
| `s`/`S` | 图模式里步入/步过 |
| `t`/`T` | 图模式里切换注释 |
| `x` | 图模式里查看 xref |
| `g` | 图模式里 seek |

## 11. 配置 eval（e）

| 命令 | 说明 |
| --- | --- |
| `e` | 列出所有配置 |
| `e asm.arch=x86` | 架构 |
| `e asm.bits=64` | 位宽 |
| `e asm.syntax=intel` | Intel 语法 |
| `e scr.color=0` | 关颜色 |
| `e bin.demangle=true` | C++ 符号还原 |
| `e anal.autoname=true` | 自动命名 |
| `e io.cache=true` | 写操作先缓存（不直接改文件） |
| `e search.in=raw` | 搜索原始字节 |

## 12. 输出过滤与批处理语法

| 语法 | 说明 |
| --- | --- |
| `cmd~pat` | grep 过滤 |
| `cmd~pat1~pat2` | 多级过滤 |
| `cmd | shell` | 管道给 shell |
| `cmd @ addr` | 临时 seek 后执行（不改变当前 seek） |
| `cmd @@ addr1 addr2` | 对多个地址分别执行 |
| `cmd @@= addr` | 遍历 |
| `cmd;cmd2` | 顺序执行 |
| `#!python ...` | 内联 python |
| `#!pipe cat file` | 内联 shell 管道 |

## 13. 项目 project（P）

| 命令 | 说明 |
| --- | --- |
| `Ps name` | 保存项目（分析结果可复用） |
| `Po name` | 打开项目 |
| `r2 -p name bin` | 打开时加载项目 |

## 14. 常见题型对应命令

- **字符串比较题**：`izz~flag` → 定位引用 `axt 0x...` → `pdf @ 校验函数`。
- **纯算法/数学变换**：`pdf` 找到变换 → 用 Python 复现（前缀和/异或/查表），r2 只负责还原算法。
- **VM 题**：`afl` 找 handler，`pdf @ handler` 逐个还原，`e asm.bits` 按需切。
- **花指令/反调试**：`-d` 调试 + `dcu` 绕过，或 `-w` patch 掉 `IsDebuggerPresent` 分支。
- **ROP**：`/R` 找 gadget，`checksec` 确认保护（NX/PIE/canary）。
