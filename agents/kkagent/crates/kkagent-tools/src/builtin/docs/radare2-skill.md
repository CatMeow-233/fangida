---
name: radare2
description: radare2（r2）逆向核心技能，CLI 优先：r2 -q -c 批处理一次取数、-w patch、-d 调试、r2pipe 自动化；识别→定位函数→反编译→交叉引用→patch 的完整解题工作流。做任何二进制反汇编/反编译、交叉引用、搜索、patch、调试前先加载本技能；完整命令分类见本目录 radare2-full.md，命令/参数不确定时 grep 它，禁止凭记忆写参数。
---

# radare2（r2）逆向工作流

入口是 CLI（经 Bash 执行）；若环境配置了 r2 的 MCP server，工具桥接的
`mcp__<server>__*` 等价可用且优先（有会话状态复用）。**`radare2-full.md`
是完整命令分类参考**，命令/参数不确定时 grep 它，不要凭记忆写参数。

## CLI 主线（推荐顺序）

```bash
r2 -q -e scr.color=0 -c 'iI; ii; iz~flag' ./bin     # 识别：信息+导入+字符串
r2 -q -A -c 'afl~main' ./bin                         # 分析一次，列函数（-A = aaa）
r2 -q -A -c 's main; pdf' ./bin                      # 定位并看汇编
r2 -q -A -c 's sym.main; pdc' ./bin                  # 伪代码（有 r2ghidra 用 pdg）
```

要点：

- **`-q -c 'cmd'` 一次性批处理取数据**是默认形态：每条命令独立开文件，不维护交互状态；
  需要多步连续分析时用 `;` 连接或 r2pipe。
- `-e scr.color=0` 关颜色（输出进管道必加）；`-e asm.syntax=intel` 切 Intel 语法。
- 大文件分析慢：`-A` 换 `aa`（只分析函数），或加 `-e bin.cache=true`。
- `~pat` 是内置 grep（`iz~flag`）、`@ addr` 临时 seek、`@@` 多地址迭代。

## 识别（第一步，对应 CTF 工作流）

| 命令 | 看什么 |
| --- | --- |
| `iI` | 架构/位宽/端序/类型/基址（PIE 判断 baddr） |
| `ii` | 调了哪些 API——`gets/scanf/read` 溢出候选，`printf/puts` 泄漏候选，`malloc/free` 堆题，`prctl/seccomp` 沙箱题 |
| `iz` / `izz` | 数据节/全文件字符串：输入提示、菜单串、`GNU C Library` 版本串（libc 定版本） |
| `iS` | `.text/.data/.bss` 的 VA 与大小（bss 全局缓冲区是溢出常见目标） |
| `iE` / `is` | 导出/符号（去符号题常空；有符号直接 `is~main` 定位） |

## 静态分析锚点

- 反编译（`pdc`/`pdg`）结果里找校验/比较分支（`if (v == ...)`、`memcmp/strcmp`）与表驱动循环。
- `lea/mov` 引用常量地址 → `px 32 @ addr` 看内容。
- 谁引用了成功/失败串 → `axt @ str_addr`（交叉引用）倒推校验函数；**axt 传地址不是符号名**，
  先 `is~name` 把名字换地址。
- C++/ObjC/Swift/Java：`ic`（类列表）、`icq`、`im`（方法）。
- 逆清楚的函数随手沉淀：`afn newname @ addr` 改名、`CC 注释 @ addr` 加注释——防反复重看。

## patch（写模式）

```bash
r2 -w -q -c 's 0x14000109c; wx 9090; q!' ./bin   # NOP 两字节；wa "xor eax,eax" 按汇编写
```

patch 前先 `px` 确认原字节；改完用 `pd` 复核再跑。

## 调试

```bash
r2 -d ./bin        # db addr 断点 / dc 继续 / dcu addr 运行到 / dr 寄存器 / px 32 @ rsp
```

macOS 宿主跑不了 Linux ELF：跨平台题用 qemu-user 包一层（`qemu-x86_64 -g 1234 ./bin` +
`r2 -d gdb://:1234`），或交给 `symexec` 技能静态求解。

## r2pipe（Python 自动化）

```python
import r2pipe
r2 = r2pipe.open('./bin')      # ['-d'] 调试 / ['-w'] 写
r2.cmd('aaa')
print(r2.cmd('s main; pdf'))
print(r2.cmdj('aflj'))         # JSON
```

## 解题优先顺序

1. 识别三连：`iI; ii; iz` 定题型（静态/动态、溢出/算法、架构与 libc 版本）。
2. `afl` 定位 main/校验函数 → `pdf`/`pdc` 读逻辑；`axt` 追数据流，别从头线性读。
3. 算法题：抽出核心函数交给 `symexec` 技能（angr/Unicorn）求解；动态验证交给 `frida` 技能。
4. 偏移/地址计算一律用代码（python/`?v 表达式`），禁止心算。
5. 结论写工作区文件，对话只引用地址+结论；不确定的命令 grep `radare2-full.md`。
