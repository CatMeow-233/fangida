# ARM64 BR/BLR 求解插件

`arm64_br_solver` 是独立、按需加载的插件，只消费已经完成的指令和 CFG
快照。原生分析、打开文件和默认插件路由不会加载或运行它。插件不调用
Loader、解码器或 xref 分析，也不修改分析结果、名称、注释或数据库。

当前范围是**小端 ARM64 的 `BR Xn` 和 `BLR Xn`**。反向数据流切片回溯目标
寄存器的定义，包含寄存器别名、部分写入、条件选择和有证据的内存读写。
提供原始字节后，可在插件内部用 Unicorn 验证候选路径；到 BR/BLR 前停止，
不跳入目标，不执行外部调用或系统副作用。

## 从源码运行

使用 Python 3.11 或更新版本。Unicorn 是可选依赖，只有字节仿真阶段才导入：

```sh
cd /Users/meow233/Desktop/ai/fangida-0.4.0
python3 -m pip install -e '.[br-solver]'
```

先用原有分析入口生成 ARM64 分析快照。下面的路径需替换成自己的 ARM64 文件：

```sh
python3 -m fangida.ui /path/to/arm64.elf --full --database arm64.fdb
```

显式调用插件列出已有 BR/BLR，然后把示例地址 `0x1234` 换成列表中的指令地址：

```sh
python3 -m fangida.plugins.br_solver arm64.fdb --database --list
python3 -m fangida.plugins.br_solver arm64.fdb --database --address 0x1234 \
  --source /path/to/arm64.elf --timeout-ms 1000 --details --output br-result.json
```

FDB 默认读取最新快照，可用 `--snapshot-id 1` 指定已有编号。JSON 分析快照
同样可用，省略 `--database`：

```sh
python3 -m fangida.plugins.br_solver analysis.json --list
python3 -m fangida.plugins.br_solver analysis.json --address 0x1234 \
  --source /path/to/arm64.elf --timeout-ms 1000
```

这些命令不重新分析，也不写 FDB。省略 `--source` 时仍能回溯已有 IR 的常量，
但不会声称经过 Unicorn 验证。FDB 不保存原始二进制，所以字节验证需要原文件。
快照存在来源 SHA-256 时严格比对；旧快照无指纹时 `source_verified=false`。

## 提供运行时上下文

函数入参、外部调用返回值、系统寄存器、可写内存和动态重定位槽不会被
替换成零或文件初值。结果会列出所缺依赖。可以显式提供**切片入口**的寄存器：

```sh
python3 -m fangida.plugins.br_solver arm64.fdb --database --address 0x1234 \
  --source /path/to/arm64.elf --register X0=0x8000 --register SP=0x70000000
```

寄存器是函数入口或快照边界处的值，不能用入口 X0 替代后续外部调用的返回值。
`Wn` 输入按 32 位写入并清零高位。运行时内存用 JSON 数组传入，地址是整数，
`data` 是按内存顺序排列的十六进制字节，例如地址 `0x3000` 存放指针 `0x8000`：

```json
[{"address": 12288, "data": "0080000000000000"}]
```

用 `--memory-json runtime-memory.json` 传入。上下文使求解成功时，仍保留
`context_dependent=true` 和原始运行时来源，不能当作静态常量证明。

## 结果含义

| 字段 | 含义 |
| --- | --- |
| `status` | `resolved`、`runtime_required`、`unknown`、`budget_exceeded`、`cancelled` 或 `unsupported` |
| `targets` | 完整相关路径证据支持的唯一目标；否则为空 |
| `possible_targets` | 已有证据产生的候选值；不能当成已确认目标 |
| `runtime_generated` | `true`：目标依赖已识别的运行时来源；`false`：目标有静态来源证明；`null`：证据不足 |
| `requires_runtime_context` | 目标求解仍包含已识别的运行时依赖 |
| `context_dependent` | 本次计算使用了调用方提供的寄存器或内存 |
| `verified_by_unicorn` | 所确认路径经过真实字节仿真与最终 BR/BLR 编码核对 |
| `parameter_sources` / `dependencies` | 原始来源及本次尚未解决的依赖，区分目标值和控制条件 |
| `paths` | 每条相关路径的切片地址、条件、候选值及仿真状态 |

无关的栈序言因 SP 未知而阻止仿真时，仍可能静态求得 BR 的参数值，但
`verified_by_unicorn=false`；这不能证明整条路径可执行。源字节冲突、未知
别名、缺失上游 CFG、循环、未支持的语义和预算耗尽会保留诊断，避免误确认。
运行时条件在不同常量目标间选择也算运行时依赖，提供选择器上下文后仍保留该来源。

默认预算为 512 条指令、32 条路径、200 ms。可选参数上限分别为 4096、64、
10000 ms；源文件最多 128 MiB，运行时内存最多 8 MiB。预算覆盖快照收集、
切片、来源读取和仿真，插件不新建分析线程。尚未覆盖全部 ARM64 指令或混淆模式；
无法确定的情况返回未知，外部调用不会被假造返回值。

## Python 与脚本入口

插件协议独立于原 `Plugin.analyze()`，已有 API 保留。直接使用已完成的字典快照：

```python
from fangida.plugins.manager import PluginManager

manager = PluginManager()
try:
    solver = manager.load_branch_solver("arm64_br_solver")
    result = solver.solve(snapshot, 0x1234, source_path="/path/to/arm64.elf",
                          timeout_ms=1000)
finally:
    manager.teardown()
```

`solve()` 还接受可选 `registers`、`memory`、`function_address`、`cancel`、
`on_progress` 和 `include_details`。取消可用 `threading.Event` 或布尔回调。
第三方提供者可通过 `register_branch_solver(name, factory)` 按同一协议注册，
注册不会加载模块或修改原生分析路由。

项目中的 [脚本示例](../../../examples/br_solver_plugin.py) 展示了显式调用插件；
可交给既有可信脚本运行器执行。当前插件结果独立返回，不自动写回 CFG/xref，
也未加入 GUI 或 MCP 的默认功能。
