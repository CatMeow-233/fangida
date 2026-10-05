# Fangida

Fangida is a modular, static binary inspection tool. Version 0.4 analyzes a
bounded part of native binaries and Android/JVM inputs, and labels incomplete
results as `partial`. It has a JSON CLI, terminal and optional Tk browsers,
Python APIs, persistent SQLite projects, and MCP servers. It is not an
IDA-equivalent decompiler or debugger.

## Install and try it

Python 3.11 or newer is required. The base install has no mandatory third-party
runtime dependencies. Capstone is recommended for native instruction decoding.

```sh
python -m pip install -e '.[disasm,config]'
cc -g -O0 examples/native_sample.c -o native_sample
fangida ./native_sample --output native-sample.json
fangida ./native_sample --threads 2 --output native-sample-parallel.json
fangida ./native_sample --fast --interactive
fangida /path/to/app.apk --output app.json
```

The compiler example uses a Unix-style `cc`; on Windows, use your C compiler
or supply an existing executable. The APK command needs an APK you are allowed
to inspect. JSON output includes
`kind`, `status`, `functions`, `xrefs`, `metadata`, and `warnings`; a successful
inspection can still be `partial`. `--fast` skips deeper native function
analysis. `--threads N` (1–16) selects native semantic workers and raises the
CLI analysis thread budget to at least N; `fangida-gui` accepts the same flag
where Tk is available.
See [worked examples](examples/README.md).

## 原生分析 agent

独立 Rust agent 副本位于 `agents/kkagent`，通过 Fangida MCP 工具读取分析结果和
数据库，保持 Loader、处理器、分析插件与 agent 的模块边界。从源码目录运行：

```sh
cd /path/to/fangida-0.4.0
python3 -m fangida.agent_cli --build
python3 -m fangida.agent_cli
python3 -m fangida.agent_cli -- --help
```

安装本项目后，也可用 `fangida-agent`。首次构建需要已有 Rust 工具链；仅显式
`--build` 执行 `cargo build --manifest-path agents/kkagent/Cargo.toml -p kkagent`。
Cargo 从 PATH 或 `~/.cargo/bin` 查找。Windows 可用 `python -m fangida.agent_cli`，
启动器自动选择 `ctfer.exe`。Python wheel 不包含 Rust 副本；请从保留
`agents/kkagent` 的源码目录安装，或显式配置已有 agent 文件与 `FANGIDA_ROOT`。
启动器优先使用 `--agent-binary` 或 `FANGIDA_AGENT_BINARY` 指定的文件，再查项目
副本的 release/debug 产物，不查 PATH 中的同名 agent；`--build` 后使用新生成的
debug 产物。`--` 后的参数原样交给 agent，`--help` 单独显示启动器帮助。

| 原生工具 | 用途 |
| --- | --- |
| FangidaAnalyze | 分析源文件，获得分析会话和结果身份 |
| FangidaRead | 分页读取摘要、函数、汇编、CFG、xref 等现有证据 |
| FangidaDatabase | 打开数据库、查看历史与分页读取已保存结果 |
| FangidaSave | 把已完成的分析保存到数据库 |
| FangidaAnnotate | 在数据库中保存名称和注释 |

函数摘要和 CFG 分页省略完整指令列表；汇编通过独立分页工具读取。工具不会在
查询 CFG 时重新解码，没有 CFG 时会明确报不可用。模型与 API 配置继续由 agent
原有配置机制处理。启动器默认设置 `FANGIDA_PYTHON` 为当前 Python、
`FANGIDA_ROOT` 为当前源码根目录；已显式设置的环境变量保持不变。

## 模块开发契约

加载器、处理器、插件接口已分别放在 `fangida.loaders`、`fangida.processors`
和 `fangida.plugins.interfaces`。加载器负责文件格式和代码区域，处理器负责
给定字节窗口的指令解码，插件负责分析编排。加载器与处理器各自注册，按能力
选择实现；旧 `binary`、`translator` 和插件导入路径继续可用。

独立插件通过 `PluginManager.register(name, factory, kinds=..., pool=...)` 注册，
`route(kind)` 选择分析器；首次使用才构造插件。注册默认拒绝覆盖已有路由。

公共 API 只增不删：保留已有名称、位置参数顺序、返回字段和 MCP 工具，追加
参数必须有默认值。`tests/test_api_compatibility.py` 验证旧调用和协议基线。
详细边界见[架构记录](docs/architecture.md)。

## 内置伪 C

原生快速、深度和完整分析会从已经完成的函数指令/CFG 快照生成伪 C，无需安装
Ghidra。新分析默认保存源码重建视图：变量命名、整数位宽与有符号性恢复、
指针和数组访问、ABI 参数、调用实参、栈局部变量，以及常见 `if/else` 和
`while`。机器视图和分类微码同时保留用于核对副作用及位宽语义。
结果中的 `pseudoc_producer` 继续为 `fangida_native_pseudoc`；已有 Ghidra
伪 C 继续优先保留。无调试信息时使用中性名称，不宣称恢复了原始变量名。
未恢复的操作、条件、控制流或调用参数显式标注；浮点/向量源码恢复、
复杂间接跳转和不可约控制流仍有覆盖限制。详见[源码重建说明](docs/reconstruction.md)。

原生伪 C 由分类微码生成：数据传送、转换、整数运算、位运算、访存、栈、
比较、条件选择、浮点、控制流和系统副作用分别处理。比较保留操作位宽、
有符号/无符号条件、浮点无序情况和标志位来源；条件移动、进位/借位、
移位计数、部分寄存器写入及未知副作用也有独立语义记录。未覆盖的指令
明确保存为不透明屏障，不会参与可证明的常量分支结论；常量特化遇到已提升但未建模求值的操作（`bt` 系列、
`ccmp`、`rcl` 等）时同样丢弃已知标志，遇到它们写内存时丢弃已知的栈槽内容。
AArch64 `mrs`/`msr nzcv` 与条件标志按第 31..28 位精确互转，TLS、浮点控制/状态、
计数器等系统寄存器读为带名字的显式读取；指针认证（`paciasp`/`autiasp` 等）只改写
目的寄存器，结果标为依赖密钥的未知值，带认证的间接转移只表示目标操作数、不求解目标；
按通道的 NEON/SSE 整数运算（含饱和加减 `uqadd`/`sqadd`/`padds`/`paddus`、字节重排 `pshufb`、饱和打包
`packss`/`packus`）按通道宽度精确建模并可求值；AArch64 获取/释放访存 `ldar`/`stlr` 系列（内存序作为属性，
可读 C 写成前导的原子访问 `arm_load_acquire_W`/`arm_store_release_W`）、`ldpsw`、`extr`、`fcsel`（精确的条件拷贝）、
x86 位测试 `bt`/`bts`/`btr`/`btc`（寄存器与立即数索引内存形式，依赖 CF 的分支还原为 `(x >> i) & 1`）也精确提升；
标量与向量浮点算术、整数↔浮点转换提升后在可读 C 中写成依赖 FPCR 的占位辅助（标量 `fadd_64`、
`signed_to_float_32`…，向量 `vec_fadd32_128`…；写标量或 64 位排列时 V 寄存器高位清零），函数头注明“浮点运算
依赖舍入/异常环境”而不自称完整；`fcmp` 等依赖 FP 标志的比较仍为 `unresolved_operation`；x86 `rep stos`/`rep movs`
给出显式的指针/计数结果和内存效果，方向标志按写入属性的 ABI 假设 DF=0 处理，函数中
出现 `std`/`popf` 时保持不透明。可读伪 C 中按通道运算写成 `vec_add32_128(a, b)` 这类
辅助调用，系统寄存器读取写成 `__arm_rsr64("tpidr_el0")`，串操作写成
`x86_rep_stos64(目的, 值, 个数)`，这些辅助函数的参数都是整数，被推断为指针的实参会显式转换；
`mrs xN, nzcv` 在可读 C 中由比较来源还原 N/Z/C/V，来源未知时对应位写成 `unresolved_condition`
并把函数标为不完整。返回地址（LR）的签名/认证（`paciasp`/`autiasp`）通常不生成 C 语句，因为可读 C
不建模返回地址；只有签名或认证后的 x30 被当作数据使用时（包括序言未被识别为栈帧脚手架、x30
一直是普通 C 变量的情形），才以 `pacia_64(…)`/`autia_64(…)` 赋值出现。数据指针的认证可能陷入，
结果无人使用时也会保留。
这些辅助函数与占位集中在“伪 C 前导”中：`fangida.plugins.pseudoc.pseudoc_prelude()` 返回固定前导（辅助函数有与微码一致的精确定义，`unknown_value()`、`unresolved_operation("…")` 等占位只声明、不赋予语义），`pseudoc_prelude(结果)` 另附该函数引用的外部函数声明（重建报告新增 `external_functions`）。前导 + 可读文本可以用 `cc -fsyntax-only -std=c11 -Werror=implicit-function-declaration` 编译；移位计数可能越界时写成 `shl_32(x, n & 0xff)` 等辅助调用，不再出现 C 未定义的移位；除数可能为 0（或带符号除数可能为 -1）的除法写成 `udiv_32(a, b)` 等，除以 0、带符号溢出时陷入而不是 C 未定义行为。可读 C 力求与微码 `evaluate` 的语义逐位一致（在 `tests/test_pseudoc_exactness.py` 覆盖的范围内与参考模型、真实 CPU 逐一对照）：8/16 位的加/减/乘/取反/取非截回原宽度（`(uint8_t)((uint32_t)a + (uint32_t)b)`，不外泄高位），带符号类型的值零扩展前先转为无符号；x86 `DIV`/`IDIV` 精确写成宽除法辅助 `x86_(u|i)div_quo/rem_W`（#DE 时陷入，32 位结果写回时清零高位），单操作数 `MUL`/`IMUL` 精确给出 rdx 高半与 rax 低半——都不再是 `unresolved_operation`；MUL/IMUL 之后读 CF/OF 的 `jo`/`jc` 等写成 `umul_overflow_W`/`smul_overflow_W`（其它指令之后的 `jo` 等溢出条件不在本轮范围，仍为 `unresolved_condition`）。通用除法的架构语义由提升器在操作属性 `division_semantics`（`"arm_zero"`/`"x86_fault"`）中声明，evaluate 与渲染按声明执行。`pseudoc_prelude(可读文本)` 也会声明文本中只以名字出现的函数地址，但返回类型只能从结果或报告得到，优先传结果。指针与整数混用处（部分寄存器写入并入指针变量、复制传播后的比较/下标/switch、指针与整数互相赋值、存储目的上的转换）在输出前按渲染出的 C 类型只在 C 不接受隐式转换处写显式转换（值逐位不变、不改声明类型；整数结果的加减按字节计算，指针结果的加减按节点类型的元素计；函数名赋给对象指针、丢掉 `const` 限定的指针赋值与传参同样显式转换）；循环头标签只输出一次；自递归调用按本函数签名给出实参与返回类型；左移的常量左操作数写成 `1U`/`1ULL`。challenge、zsh、bash、libtersafe 全部函数加前导后都能编译（以前 97.8%/86.4%/89.9%/93.8%）。详见[源码重建说明](docs/reconstruction.md)“可编译的伪 C”。

函数快照新增可选 `microcode`、`microcode_version`、`microcode_complete` 和
`microcode_analysis`。已有 Ghidra 伪 C 保留原文本与来源，同时可生成独立
微码。Python 的 `AnalysisView.microcode` / `microcode_facts` 和 MCP 的
`get_microcode` / `get_microcode_facts` 分页读取保存结果；
`simplify_micro_expression` 可直接化简固定宽度表达式，不需要文件句柄。
微码层支持混合布尔算术恒等式、已知位和基本块内常量分支分析；调用、
控制流汇合及未知效果会清除缺乏证明的状态。详见[微码 API](docs/microcode.md)。

伪 C 使用独立的 `PseudocodePlugin` 协议，由
`PluginManager.register_pseudocode` / `load_pseudocode` 注册和延迟加载；
`fangida.plugins.pseudoc.generate_pseudoc(function_snapshot, architecture)`
也可直接处理快照；原调用默认保持机器视图，新增可选 `style="readable"`
返回源码重建视图及 `machine_pseudoc`、`reconstruction`。插件不读取源文件，
不调用 Loader、解码器或 xref 分析。
DEX/JVM 提纲使用独立的 `bytecode_pseudoc` 插件，旧
`fangida.core.apk_analyzer.pseudocode.outline` 参数和返回值保持兼容；新字节码
指令快照由处理器提供分支偏移，旧快照的操作数兼容转换仍保留在原入口。

自动原生生成最多处理 128 个函数，每个函数最多 512 条指令、32768 个字符，
总文本最多 524288 个字符。`pseudoc_truncated` 标注输出或控制流不完整；
`pseudoc_functions`、`pseudoc_characters`、`pseudoc_budget_exhausted` 记录生成量
和预算状态。生成支持取消和进度回调，不额外创建线程。
微码每函数同样限制为 512 条指令，文本截断不会缩减独立微码的指令预算；
`microcode_functions`、`microcode_instructions` 和 `microcode_budget_exhausted`
记录附加语义阶段的工作量。旧保存结果没有微码时，查询明确报告不可用。
其它函数可以在分析完成后按需生成伪 C：GUI 按 Ctrl+F5（或点“生成伪代码”），MCP 调用
`get_pseudoc` 时传 `generate=true`，Python 使用
`fangida.plugins.pseudoc.on_demand.generate_function_pseudoc(结果, 地址)`。单函数指令上限由
设置项 `pseudoc_max_instructions` 决定，默认 512，最大 8192。按需生成复用流水线的同一套名字、
签名与参数上下文；对流水线已经渲染过的函数，结果逐字相同。生成结果只缓存在当前会话，
不写入数据库。

可读视图的名字只来自容器与链接证据：ELF/PE 符号、Mach-O `LC_SYMTAB`（伪 C 用去掉
前导下划线的源码名，原始符号保留在 `name` 中）、PLT、Mach-O `__stubs`、PE 导入 thunk，
以及经 IAT/GOT 槽位的已核实调用点。已知库函数（libc 常用函数与常见 Windows API）按原型
给出实参，printf 系列按格式串确定可变参数个数；只读节中的字符串地址写成字面量
（PE 的 UTF-16 字符串写成 `L"..."`），地址和位运算常量用十六进制。每个函数第一行是
`// 地址 名字 | 名字来源 | 完整/不完整原因` 的说明，`pseudoc_reconstruction["header"]`
保存同一内容。

GUI 中按 `F5` 或 `Tab` 查看伪 C：左侧是函数列表（含状态列），右侧是带语法高亮的
代码区和函数头（签名、调用、引用的字符串、不完整原因）；双击函数名或地址跳转，
Shift+双击跳到反汇编，双击 goto 标签在函数内定位，可在可读/机器视图间切换。
终端浏览器的 `pseudoc` 保持原 JSON 输出，`pseudocode [名称|0x地址] [machine]`
（别名 `code`、`decompile`）按函数打印函数头与代码。MCP 使用
`get_pseudoc`。MCP 的可选 `address` 支持函数入口及已解码指令内部地址；
可选 `source`、`address_space` 用于选择归档成员和地址空间，`style="machine"`
读取保存的机器视图，`style="readable"` 读取重建视图。结果可随已有
JSON、项目和 SQLite 快照保存及读取。

## 原生完整代码区域分析

原生字符串保留文件偏移，并附上实际映射的虚拟地址；字符串列表按数据段内容
优先展示。选中字符串后按 `X` 可查看引用它的指令，引用字符串内部字节也会
关联到该字符串。旧数据库已有引用可通过保存的 section 映射恢复导航；数据库
缺少的引用需要用原文件重新分析。常规扫描最多返回 1000 条字符串，完整模式
保留扫描范围内的全部 ASCII 候选；`metadata.string_scan` 明确数量及截断情况。

`--full` 分析 ELF、PE、Mach-O 在文件中实际存储的所有可执行区域，恢复函数、CFG
及引用，不要求安装反编译器。默认读取整个输入，显式 `--max-bytes` 仍会限制
读取范围；`--full` 和 `--fast` 互斥。默认模式保留原有扫描预算。GUI/CLI 继续
尊重已有 Ghidra 配置；下述测速命令明确关闭该补充，计量原生分析本身。

```sh
python -m fangida.ui ./native_sample --full --threads 4 --output full-result.json
python -m fangida.gui ./native_sample --full
python -m fangida.benchmark ./native_sample --full --runs 3 --semantic-threads 1 --output bench-full-1.json
python -m fangida.benchmark ./native_sample --full --runs 3 --compare-threads 4 --output bench-full-4.json
```

保存完整结果时 JSON 流式写入文件，控制台输出路径和统计摘要；不指定
`--output` 时仍在标准输出返回完整 JSON。结果的 `metadata.full_analysis`
记录每个区域的覆盖、解码字节和空缺，`metadata.full_disassembly` 保留全区域
指令。函数带来源信息；无法保证代码/数据划分及全部间接目标，结果仍可为
`partial`，`function_recovery_complete` 明确保留为 false。

完整分析会识别不返回的函数，包括 `exit`、`abort`、`__stack_chk_fail`、`__cxa_throw` 等名单函数，
经 PLT/IAT/Mach-O 桩调用的同名导入，以及“所有路径都终止于不返回调用”的本地包装函数。
对它们的调用不再落空到下一段代码。截断记录在 `cfg.noreturn_calls`，函数带 `noreturn` 和
`noreturn_evidence`。伪 C 中这类调用就是路径终点，不再输出 `unresolved_fallthrough`；已证明不返回的
函数签名写成 `void`。在 libtersafe.so（arm64）上，完整 CFG 从 11390 个增加到 12947 个；含不返回调用的
1745 个函数里，伪 C 的 `unresolved_fallthrough` 从 1881 处降到 41 处，剩下的都来自指令上限截断。
默认 deep 模式只使用名单和 Mach-O 声明桩。详见[架构说明](docs/architecture.md#非返回函数)。

`stats.full_function_sources` 区分符号、ELF unwind/FDE 与 init/fini 声明、入口、直接
调用目标和可执行区域起点。FDE 范围和区域起点可以作为 CFG 的分析根；根的
数量不能直接当成已确认的真实函数数量。

完整分析还会发现“只经数据指针到达”的函数，提升代码覆盖，证据由容器结构给出：
Mach-O 的 `LC_FUNCTION_STARTS`（来源 `function_starts`）、`__mod_init_func`/
`__mod_term_func` 构造/析构指针与当前工具链默认产出的 `__TEXT,__init_offsets`（来源
`init_offsets`），PE 的 `.pdata`（按 Machine 解析：x64 为 12 字节项，ARM64/ARM32 为
8 字节项、长度取自打包展开数据或 `.xdata`，其它 Machine 只告警；来源 `pdata`）与导出表
（来源 `export`）都作为声明起点消费。只纳入已是解码边界的起点；被跳过的起点经复测是
真函数，只是前面内联跳转表数据的末尾字节与函数首字节被线性扫描拼成了一条跨越起点的
指令，对齐它们属于处理器层的重同步锚点职责。

ELF 的 `R_*_RELATIVE`（REL/RELA、RELR、Android RELR 与 APS2 打包重定位，无法解析时告警）/
`ABS`/`GLOB_DAT`（APS2 打包表中的这两类经该节链接的 `.dynsym` 读取，只认本地已定义符号）
与 PE 基址重定位写入、且值落在可执行区域内的指针（来源 `data_pointer`）
证据弱得多：它们可能来自虚表、回调表、函数指针数组，也可能是 switch 跳转表、混淆分支表
或指令操作数，而分支标签的前一条指令通常就是 `jmp [table]` 或 `ret`，单看前驱挡不住。
因此第二轮按相邻槽位组成的“指针表”整体裁决，宁缺毋滥：任一项槽位在代码区内、目标不是
解码边界、是陷阱或零填充、在已声明区间内、已被首轮 CFG 认领、前一条指令会落空进入它，
或所在“已知函数起点到下一个已知起点”区间的起点函数有未解析的间接跳转，就整表拒绝；新目标
重复、两个新目标落在同一区间、或表中没有任何已知函数起点（`.init_array` 等声明结构除外），
也不接受。不求解任何间接跳转。`metadata.full_analysis.pointer_roots` 记录候选、表、接受、
实际建图（`built`）与按原因拒绝的计数，以及未确认目标（最多 256 项）；
`stats.full_pointer_candidates`/`full_pointer_functions`（建图数）/`full_pointer_accepted`
为对应计数（缺省 0）。第二轮只在同一 CFG 线程池中有界分批建图，使用本地不动点之后的
不返回集合；建图后在第二轮函数上补算本地不动点，所有出口都不返回的指针函数与首轮同形
函数一样标为 `noreturn`（证据带 `pass: "pointer_roots"`，轮数见
`noreturn.pointer_fixed_point_rounds`，缺省 0）。中途取消时未建图的种子以 `not_decoded`
出现，`cfg_pass_complete` 为 false。ELF `.init_array`/`.fini_array` 声明根与指针候选读取
同样的重定位编码：APS2 打包的 RELA 中数组槽位内容通常为 0，根取自重定位加数。

实测（`tests/test_full_discovery.py` 含同形用例）：审查用 PE32 switch 样本（跳转表在 `.rdata`
或内联在 `.text`）原先接受的 9/10 个 `data_pointer` 中 8/9 个是 switch 分支，现在各只接受
真实回调 1 个、误报 0；libtersafe.so 原先唯一接受的 0x2f4e88 是混淆 `br` 分支表指向 FDE
末尾零填充的项，现在整表拒绝，`data_pointer` 接受 0 个。去掉 eh_frame 声明区间模拟无
unwind 信息时，libtersafe 原规则接受 14222 个、其中 11641 个不是 FDE 起点，现规则接受 18 个、
全部是 FDE 起点；代价是召回很低，例如 challenge 的 149 个真实函数指针因同区间规则全部放弃。
eh_frame 完整的 ELF（challenge、libtersafe）上 `data_pointer` 不新增函数；收益主要来自
Mach-O 的 `LC_FUNCTION_STARTS`（bash x86-64 切片完整 CFG 从 844 增至 1072、未归属指令
34642 降到 18014）。修复前后 full 分析耗时差在 ±1% 内（独立进程 A/B 交替取最小值）。
用 Android NDK 的 ld.lld 真实链接产物核对：aarch64（RELA）、armv7a（REL）、x86-64、i686
在 `--pack-dyn-relocs=none/android/relr/android+relr` 与 `--use-android-relr-tags` 下，APS2、
RELR 与 Android RELR 解码与 `llvm-readelf -r` 逐项一致，指针候选与 init/fini 数组根按符号
在各打包方式下完全相同（修复前 APS2 产物缺少 `ABS` 指向的函数指针，APS2 RELA 产物缺少
数组根）；lld-link 链接的 ARM64、ARMNT（Thumb-2）与 x64 PE 的 `.pdata` 起点与长度（打包展开
数据与 `.xdata` 两种编码）与 `llvm-readobj --unwind` 一致。找到 NDK 时这些用例自动运行。
默认 deep 模式与非 full 路径不涉及此流程，行为完全不变。

GUI 摘要保留完整指令计数，反汇编表每页显示最多 1000 条，可翻页或跳转页码
查看全部已完成的指令。隐藏标签页不提前填充控件，CFG 在选中标签页时显示。
full 模式的表格和 CFG 读取同一个完成后的快照，只有函数显示字段另建表头，
不再为显示重复复制整份分析图；公共 API 返回的副本仍保持修改隔离。
在桌面界面点击“打开文件…”并选中文件后，会出现分析选项，可选择常规、快速
或完整分析，再点击“开始分析”。完整选项适用于 ELF、PE 和 Mach-O，并取消
字节扫描上限；取消选择会保留当前结果。顶部区分当前结果与下次打开模式，后续打开文件可以
重新选择；原有命令行 `--fast`、`--full` 参数继续可用。
同一对话框里的“启用多线程分析”默认按配置开启，可选 2–16 个解码线程（等同命令行
`--threads N`）：完整分析时指令解码按线程数分到多个子进程并行，交叉引用始终在独立线程中
进行。取消勾选后总线程预算为 1，解码与交叉引用在同一线程中依次执行，结果相同只是更慢；
不改动该选项时沿用原有设置。
完整分析会渐进式显示结果：指令解码完成后（大文件通常 1～3 秒）先显示反汇编和函数列表，
CFG、交叉引用和伪代码在后台补齐，完成后自动替换，当前浏览位置会保留。预览期间不能保存或编辑。
程序化调用可以通过 `AnalysisService.analyze(..., on_preview=回调)` 获得同样的预览。
批量构建结果时 Fangida 会暂停 Python 的自动循环 GC，以减少约 20% 的耗时；设置
`FANGIDA_GC_PAUSE=0` 可以关闭这一行为。

测速关闭 Ghidra，记录相同输入 SHA-256 与覆盖范围。旧 `seconds`、
`median_seconds` 继续表示暖服务的分析墙钟时间；新增 `cold_total_seconds`
表示服务构造加首次分析，排除 Python 启动、预先文件哈希和服务关闭，操作系统
缓存未被清空。`cpu_seconds` 统计当前进程的全部线程，Unix 的
`child_cpu_seconds` 只统计测量期间已经回收的子进程。`peak_rss_bytes` 为整个
测速进程生命周期的累计 RSS 高水位，包含结果哈希开销；Windows 没有该能力时
返回 null。`postprocess_seconds` 单列结果哈希和覆盖摘要时间。

`single_thread` 表示一个解码 worker；分析预算大于 1 时 xref 仍使用独立线程。
`--semantic-threads N` 和 `--compare-threads N` 需要在配置的 `analyze_threads`
预算内为 xref 留出一个位置。只有证据哈希和覆盖范围一致时才给出本机时间比例。
这些测量不构成与 IDA 的速度比较。

## 桌面导航与快捷键

从源码启动时先进入项目目录，避免在主目录运行时出现 `ModuleNotFoundError`：

```sh
cd /Users/meow233/Desktop/ai/fangida-0.4.0
python3 -m fangida.gui
```

左侧函数列表与汇编、流程图使用同一当前位置；跳转支持符号和地址，并自动定位
对应数据页。打开新的文件会清除导航历史，保存名称或注释后保留当前位置。
流程图默认以可读大小显示当前块，可滚动、缩放或点击“适应视图”查看整图。
图形布局保留全部基本块和边，画布只绘制当前视口内有界数量的记录；基本块
列表仍保留原显示上限，并明确提示被限制的数量。

| 快捷键 | 功能 |
| --- | --- |
| G / Ctrl+L / Ctrl+E | 地址或符号跳转 / 名称跳转 / 入口跳转 |
| Enter / Esc / Ctrl+Enter | 跟随目标 / 后退 / 前进 |
| Space | 汇编与所属函数流程图切换 |
| X / Ctrl+X / Ctrl+J | 操作数引用 / 当前位置的传入引用 / 传出引用 |
| N / ; | 重命名函数 / 编辑地址注释 |
| Ctrl+P / Ctrl+S / Shift+F12 | 函数 / 区段 / 字符串 |
| Tab / F5 | 浏览已有伪代码或返回汇编 |
| Ctrl+F5 / Shift+F5 | 为当前函数按需生成伪代码 |
| Alt+T / Ctrl+T | 查找文本 / 查找下一条 |
| Ctrl+W / F1 | 保存数据库 / 快捷键帮助 |

Ctrl+O 打开文件、Ctrl+F 查找和 F3 查找下一条是 Fangida 的附加入口。
macOS 还保留 Command+O / Command+S / Command+F。键位对照
[IDA 官方快捷键表](https://hex-rays.com/hubfs/freefile/IDA_Pro_Shortcuts.pdf)及
[引用导航说明](https://hex-rays.com/blog/igor-tip-of-the-week-16-cross-references?hs_amp=true)。
输入框保留正常输入；模态窗口打开期间不执行后台导航命令。

重命名和注释保存在可写的分析数据库（`.fdb`）中。当前结果还没有数据库时，按钮和
N / ; 快捷键仍可用：第一次标注会询问是否把结果保存为数据库（默认文件名为原文件名加
`.fdb`），保存后自动写入这条标注。之后的标注只写入数据库并在内存中更新当前结果，
不会重新读出整个快照（大文件每次约 1～2 秒）。改名会同步显示在所有伪代码的调用处与
函数头中（字符串字面量和注释保持原样）。只读数据库不可写。当前存储标注以整数地址定位，
APK/JAR 可能有多个成员共享偏移，因此界面暂不提供此类输入的地址标注，避免串改成员。
Tab / F5 只浏览已有伪代码；没有伪代码时会提示，不会隐式重跑分析。Ctrl+F5 / Shift+F5
为当前函数在后台按需生成伪代码，生成期间界面可以继续操作。

GUI 功能分别放在 `gui_modules/commands.py`（命令）、`shortcuts.py`（键位与焦点）、
`navigation.py`（位置与索引）、`graph.py`（布局与视口）、`workspace.py`（侧栏与工作区）、
`records.py`（已完成记录的显示）和 `controller.py`（界面协调）。这些模块不导入
Loader、处理器或分析插件；`gui.py` 保留原入口并负责后台分析和数据库服务调用。

## Current analysis scope

| Input | Evidence Fangida can report | Current limit |
| --- | --- | --- |
| ELF, PE, thin and fat Mach-O | Headers, sections, strings, bounded entry disassembly and CFGs; optional `--full` scans all file-backed executable regions and recovers functions/CFGs/xrefs with coverage records | A fat Mach-O selects one file-backed slice within the scan budget. Function recovery, indirect targets and whole-program data flow remain incomplete. Capstone gives register access and a local liveness estimate; GNU/LLVM `objdump` is an x86 fallback. |
| APK, DEX, JAR, JVM class | 独立 APK Analyzer 项目通过插件提供方法反汇编、CFG、字符串/调用/字段/类型 xref、Kotlin Metadata、Manifest/AXML 和 ARSC 资源；支持 `--full` 和覆盖记录 | Java/Kotlin 仍为提纲；动态调用保留证据，未确定运行时目标；native `.so` 目前报告容器成员信息。预算耗尽明确标为 partial。 |
| Other files | Tentative bounded native scan with identification evidence | The container may remain unidentified. |

APK Analyzer 源码位于相邻独立项目 [`../apk-analyzer`](../apk-analyzer/README.md)，
可单独安装、测试和运行，不导入 Fangida。宿主的 `plugins/apk_bridge` 使用
JSON-RPC stdio 连接，`core/apk_analyzer` 只保留旧入口兼容门面。相邻源码目录
可自动定位，其他位置使用 `FANGIDA_APK_ANALYZER_PROJECT`；独立环境可通过
`FANGIDA_APK_ANALYZER_COMMAND` 指定 worker。含空格的跨平台命令建议使用 JSON
参数数组，例如 `["/path with spaces/python", "-m", "apk_analyzer.worker"]`。

```sh
python3 -m pip install -e ../apk-analyzer
python3 -m fangida.ui /路径/app.apk --full
python3 -m fangida.benchmark /路径/app.apk --full --runs 3 --output apk-bench.json
```

打开文件对话框可选择完整字节码分析。多 DEX/JAR 成员的地址通过 `source` 和
`address_space` 区分；`AnalysisView.xrefs`、脚本 `xrefs` 和 MCP `xref_query`
支持这两个可选筛选参数，原调用保持兼容。

Concurrent requests for **separate files** can use up to
`min(parse_threads, 4)` workers, subject to the scheduler's parse pool. Each
APK/JAR still processes its members in sequence. Workers support progress
notifications, cooperative cancellation at parser checkpoints, result paging,
timeout recovery, and bounded archive inspection.

Native semantic threads may analyze nonoverlapping, size-bounded symbol
functions or separated functions discovered through direct calls when enough
budget remains. Each batch is checked for conflicts before its results commit;
conflicting work is replayed with serial decoding. Progress or cancellation
callbacks also use serial decoding. Result statistics retain
`semantic_workers_requested`, `semantic_workers_used`, and
`semantic_parallel_functions`.

汇编解码和 xref 分析分配不同线程，单分析线程预算时才合并执行；快速分析、
进度/取消、冲突重放均遵守同一边界。服务在 `analyze_threads` 中预留一个引用
线程：预算为 2 时一个解码线程加一个引用线程，预算为 1 时内联。DEX/JVM
同样把调用快照交给独立引用阶段，并在每个 worker 请求内复用它。线程分离
不保证绕过 Python GIL 或提高实际吞吐。

## Saved projects and scripts

Save a versioned result in a SQLite project, then inspect it separately:

```sh
fangida ./native_sample --project demo.sqlite3 --output native-sample.json
fangida-project demo.sqlite3 history --file ./native_sample
fangida-project demo.sqlite3 page 1 functions --limit 20
```

Use the snapshot ID returned by `history` in place of `1` when reusing a
project. `fangida-project` also supports `show`, `rename`, `comment`, and
`annotations`. Renames and comments are stored for the current source content
hash; they never change the binary or the immutable result. A later `fangida`
run analyzes again and saves another snapshot. There is no automatic analysis
cache lookup in the CLI.

`fangida.scripts.ScriptContext` reads an isolated snapshot and grants `rename`,
`comment`, and `export` independently. `run_script` executes a trusted Python
file in a child process with wall-time and output limits. Neither Python API
is a security sandbox. See [script usage](fangida/scripts/README.md).

## Headless access

`fangida-mcp` serves MCP tools over newline-delimited JSON-RPC stdio. Configure
an MCP client to launch that command, or use the complete stdio example in
[examples](examples/README.md). Snapshot tools include `open_file`,
`close_file`, `list_functions`, `get_disasm`, `get_pseudoc`, `get_microcode`,
`get_microcode_facts`, `simplify_micro_expression`, `xref_query`,
`list_api_calls`, and paged `export_result`. The default project tools open an
existing compatible project and read its history, pages, annotations, or a
saved result. A missing analysis capability returns a tool error.
`--allow-writes` also exposes project creation, analysis saving, and persistent
rename/comment annotations. Its separate `rename_symbol` tool affects only an
open MCP session snapshot. A server process holds at most eight open file
snapshots and four project handles.

原生 agent 可使用增量只读工具 `analysis_summary(handle)` 获取身份、状态、
集合计数和完整分析覆盖；它省略 IR、CFG、pcode 和原始字节。警告最多返回
100 项、每项 2048 字符，另给出 `warning_count`、`warnings_truncated`；
统计过大或包含分析大表时通过 `stats_truncated` 明确标记省略。
`counts.instructions` 优先取完整指令表的数量，缺少列表时使用已开启 full
分析的覆盖计数；`instruction_count_source` 明确说明来源。没有这些证据时
仍按顶层 `instructions` 计数，缺失则标为 `unavailable`；计数不改变完整性状态。

`get_cfg(handle, address)` 只读取指定函数起点的已完成快照；`collection` 可为
`blocks`（默认）、`edges` 或 `frontier`，支持 `offset` 和 `limit`（最多 200）。
响应带函数身份、覆盖完整性、总数与 `next_offset`；块摘要只给出指令数量，
具体指令另用 `get_disasm` 读取。APK 成员或地址空间共享起点时，须提供
`source`、`address_space` 消歧；没有 CFG 时返回工具错误，不隐式分析。

`list_functions` 与 `database_page(collection="functions")` 可选
`include_details=false`，分页返回函数身份、边界、CFG 完整性与指令/引用数量，
省略完整指令图；默认 `true` 保留旧详细输出。数据库函数摘要只处理请求页，
不会恢复整个快照。

私有 stdio 子进程可显式使用 `--own-completed-results`，接管已完成的原生
full 结果，避免复制整份 IR。嵌入式 `McpServer` 同名可选参数默认 `false`，
即 `McpServer(own_completed_results=False)`，保持外部结果隔离；只有能放弃
原结果所有权的私有服务才应开启。

`fangida-mcp-http` exposes the same tools at `http://127.0.0.1:8765/mcp` by
default, using session IDs. Its request/response transport does not offer a
server-initiated SSE stream. Nonlocal binding requires explicit TLS files,
allowed hosts, and a bearer token. Keep the default loopback binding for local
use.

## 插件分析数据库（.fdb）

分析数据库通过独立的 `sqlite_storage` 存储插件读写，保存分析快照、名称和
注释。它不内嵌原始二进制，也不兼容 IDA 的 `.idb` 或 `.i64` 文件。
原文件移动或删除后，仍可浏览已保存的函数、汇编、CFG、xref 和标注；
读取原始字节或 Hex 视图仍需要原文件。

从源码运行时，先进入项目目录，再分析并保存：

```sh
cd /Users/meow233/Desktop/ai/fangida-0.4.0
python3 -m fangida.ui /Users/meow233/Downloads/project/dist/challenge --full --database demo.fdb
python3 -m fangida.gui --open-database demo.fdb
python3 -m fangida.database_cli demo.fdb history
python3 -m fangida.database_cli demo.fdb page 1 functions --limit 20
python3 -m fangida.database_cli demo.fdb rename 1 0x20f0 main
python3 -m fangida.database_cli demo.fdb comment 1 0x20f0 '已检查入口'
```

`1` 是示例快照编号，实际使用 `history` 返回的编号。`show` 省略编号时读取
最新快照，`annotations` 读取对应来源哈希的标注。安装项目后可以使用
`fangida-db` 代替 `python3 -m fangida.database_cli`。`history`、`show`、`page`、
`annotations` 严格只读，路径不存在时返回错误，不创建数据库；`rename`、
`comment` 是显式写操作，原文件删除后也可执行。重新打开快照会应用最新名称
和注释，已经载入的独立会话副本保持原来的内容。

Python 读取同样不重新分析、不要求原文件存在：

```python
from fangida.api import open_database
view = open_database("demo.fdb")
print(view.functions())
print(view.disassembly(0x20f0, limit=20))
```

`AnalysisService(database_path="demo.fdb")` 会在分析完成后通过存储插件保存结果；
直接插件接口是 `PluginManager.load_storage("sqlite_storage")`，随后调用
`open_database` 和 `save_analysis`。新增存储协议与 Loader、处理器、分析插件
各自独立，旧的 `ProjectStore`、`--project`、脚本和项目 MCP 工具继续可用。

MCP 增加 `open_database`、`close_database`、`database_history`、`database_page`、
`database_annotations` 和 `open_database_snapshot`。`open_database` 默认
`read_only=true`，即使服务器开启写权限也不会自动改成可写。
`open_database_snapshot` 返回的普通 `handle` 可直接用于已有 `list_functions`、
`get_disasm`、`xref_query` 等工具。只有 `--allow-writes` 才暴露
`create_database`、`save_to_database`、`database_rename_symbol`、
`database_set_comment`；修改已有数据库还须以 `read_only=false` 打开。
`save_to_database` 保存已经打开的结果，不再次调用分析器，并拒绝原文件在
分析后发生变化的结果。一个 MCP 会话最多打开四个分析数据库。

数据库中的全量结果保留原有覆盖范围、警告和 `partial` 状态。保存数据库不会
补齐未知函数、未解析间接跳转或其他分析缺口；只读打开不会迁移旧版本，
格式和版本不兼容时会报错。写入、名称及注释采用事务，异常时回滚；数据库
句柄和存储插件由打开它们的服务、会话或 CLI 统一关闭。

## 可选 ARM64 BR/BLR 求解插件

`arm64_br_solver` 通过独立插件协议按需加载，使用反向数据流切片和可选
Unicorn 仿真求解已有快照中的 ARM64 `BR/BLR`，识别运行时参数来源。
只有显式调用才运行，不接入默认原生分析、GUI 或 MCP；不修改已有 CFG/xref。
用 `python3 -m fangida.plugins.br_solver arm64.fdb --database --list` 列出分支。
安装、求解和运行时上下文用法见[插件文档](fangida/plugins/br_solver/README.md)。

## Optional integrations

Install Ghidra separately and set `GHIDRA_HOME` or
`FANGIDA_GHIDRA_HEADLESS`, then pass `--ghidra` to request bounded functions,
xrefs, p-code, and available pseudo-C from its headless analyzer. Ghidra is not
bundled. Its actual output depends on the installed Ghidra and input; local
tests exercise a fake launcher, not a full Ghidra installation.

The `native/` directory provides matching Rust and C++ implementations of a
versioned C ABI for a byte histogram and ASCII strings. After building one,
set `FANGIDA_NATIVE_LIB` to the shared library path. This does not offload CFG
or semantic analysis. See [native build instructions](native/README.md).

Settings load from built-in defaults, `~/.config/fangida/config.yaml`,
`.fangida.yaml` beside the input, then session overrides. YAML requires the
`config` extra. See [the settings schema](settings/settings.schema.json) and
[architecture](docs/architecture.md).

## Verify

```sh
python -m unittest discover -s . -p 'test_*.py' -v
python -m compileall -q fangida
fangida-bench /bin/ls --runs 3
fangida-bench ./native_sample --runs 5 --compare-threads 2
```

`--compare-threads N` times one versus N native workers with warmups and
alternating order, and checks whether evidence and analysis scope match. N
must fit the configured `analyze_threads` budget with one slot for xref; a small sample may use only
one worker. The timing ratio is local and workload-dependent, not an IDA
performance comparison. Full semantic recovery, a source-level decompiler,
dynamic debugging, and executable unpacking remain open engineering work.
