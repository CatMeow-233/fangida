# 可读伪 C 与源码重建

分类微码表达机器语义；源码重建模块消费微码，生成面向阅读的伪 C。
Loader、处理器、xref 和插件的职责不变。此阶段不读取源文件、不解码字节、
不创建线程，仅处理完成的指令快照。

## 分模块实现

| 模块 | 职责 |
| --- | --- |
| `model.py` | 源码表达式、语句、变量与证据模型 |
| `cfg.py` | 从保存的终结操作构建 CFG、支配关系、后支配关系和自然循环 |
| `abi.py` | ABI 选择、读前定义分析、声明参数映射 |
| `flagflow.py` | 跨基本块的唯一标志位定义传播，汇合歧义与副作用形成屏障 |
| `specialize.py` | 基于微码常量与私有栈槽的有界 CFG 特化，保留未知边与逐条原始来源 |
| `types.py` | 整数宽度、有符号性、指针访问类型和复制约束 |
| `stack.py` | SP/FP 仿射偏移、栈槽、重叠访问、栈地址逃逸和成对保存恢复 |
| `expressions.py` | 命名值、数组索引、字节偏移、栈变量和全局存储表达式 |
| `calls.py` | 基于声明或被调函数摘要恢复调用实参与返回位宽 |
| `lower.py` | 将机器效果转换为源码语句；捕获比较值和有副作用的条件移动源 |
| `dataflow.py` | 跨块必定复制传播、活跃变量分析、无用纯赋值消除与数组地址恢复 |
| `regions.py` | 将无源码状态协议的终端片段明确保留为机器区域，附全部原始微码证据 |
| `structure.py` | 常见分支、早返回、自然循环以及残余标签 |
| `typecheck.py` | 输出前的指针/整数一致性：只在 C 不接受隐式转换处写显式转换，不改声明类型 |
| `__init__.py` | 有界编排、声明生成、文本及恢复证据报告 |

例如 `mov eax,edi; add eax,esi; ret` 在 ELF/SysV64 下生成：

```c
uint32_t add_values(uint32_t arg_1, uint32_t arg_2) {
    return (arg_1 + arg_2);
}
```

条件来自有符号比较时恢复 `int32_t`，无符号比较使用 `uint32_t`；
访存步长匹配元素宽度时恢复 `array[index]`。稳定的栈偏移变成
`local_N`，重叠访问共享字节数组，避免将别名误拆为多个变量。
栈槽的读前初始化使用跨块必定定义分析；未知初值通过 `unknown_value()`
或 `initialize_unknown_bytes()` 显式标注。被普通访存观察的帧指针保存
不当作可消除的函数序言。
栈地址逃逸且可确定分配范围时形成局部缓冲区，传给调用点。
无法确定范围时保留 `unresolved_stack_address()`。

复制传播保留写入转换和比较捕获；加载及调用结果不作为纯复制，
明确写入使依赖它的复制事实失效，未知效果清除复制事实。
CMOV 的内存源在条件表达式之前读取，避免用 C 三元表达式错误地跳过读取。
窄返回值的高位清零仅在被调函数有对应机器证据时传播；外部声明仅说明
返回类型时，完整机器返回寄存器的高位使用 `unknown_return_upperN` 标注。
窄整数乘法及移位显式使用无符号提升，避免 C 整数提升引入有符号溢出。
传入参数与被复用的寄存器变量分开；入口读取宽度不被后续 ABI 寄存器写入
污染，返回位宽依据到达返回指令的定义恢复。相邻零写入可合并为 `memset`。
入口指针类型按值的复制来源传播，后续调用返回指针不改变保存的入口参数类型。
调用后的易失寄存器及异常处理器输出不作为入口参数证据。复制事实只跨一致
的 CFG 汇合传播，重叠栈数组的读取不作为纯复制，避免后续写入改变先前捕获值。

## ABI、参数与类型证据

显式 `abi` / `calling_convention` 优先；平台缺省支持 ELF/Mach-O x86_64
SysV64、PE x86_64 Win64、ARM AAPCS32/64 和 ELF/Mach-O x86 cdecl。
未知或不匹配的 ABI 不推断寄存器参数，输入保持明确的未知值。
平台缺省是推断依据，不能证明手写汇编采用了该 ABI。

ABI 寄存器在使用前未定义，是参数候选；栈参数依据稳定偏移和 ABI 边界。
`prototype` 字典可声明 `return_type`、`parameters`，参数项可含
`name`、`type`、`register`。声明的未使用参数仍保留。完整声明与推断摘要
分开记录；没有符号或调试信息时使用 `arg_N`、`value_N` 等中性名称。
不会凭指令序列捏造业务语义名称。

调用参数优先采用完整声明，其次采用被调函数读前定义摘要。
仅有调用前寄存器写入时，显示能恢复的前缀和 `unknown_arguments()`。
摘要不能证明全部参数数量；推断摘要的 `argument_count_known` 为 false。
不完整摘要保留 ABI 槽位缺口及未知尾；完整显式用途证据仅能提供可读投影，
不把 `argument_uses_complete` 当作原始函数原型完整。窗口外直跳及间接跳使用
保留真实目标和已知实参的 `tail_transfer`，截断顺序边使用
`unresolved_fallthrough`，两者均不伪造 C 返回。已验证动态符号可命名尾转移目标。
浮点参数 ABI、变参、复杂聚合参数、cdecl 调用点栈实参目前未完整恢复。

ABI 规则参考 [Microsoft x64 调用约定](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170)、
[ARM AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
和 [x86-64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI)。

## 接口及保存结果

```python
from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.reconstruct import reconstruct_function, recover_signature

# 原调用保留机器视图，已有第三方插件参数不变。
machine = generate_pseudoc(function_snapshot, "x86_64")
readable = generate_pseudoc(function_snapshot, "x86_64", style="readable")

# 直接消费已保存的微码；不重新提升或解码。
recovered = reconstruct_function(function_snapshot, "x86_64",
                                 microcode=saved_microcode,
                                 context={"kind": "elf"})
```

`PseudocodeResult` 追加兼容默认字段 `machine_pseudoc` 和 `reconstruction`。
新原生分析将可读文本保存于既有 `pseudoc` 字段，并追加
`machine_pseudoc`、`pseudoc_style`、`pseudoc_reconstruction`。
已有 Ghidra 文本及来源继续保留。JSON、项目与 SQLite 沿用现有快照保存机制。
GUI 的 F5/Tab 和终端 `pseudoc` 显示保存文本。

MCP `get_pseudoc` 新增可选 `style="readable"` / `"machine"`。
不传参数仍返回保存文本；旧原生快照有微码时，可显式请求可读视图，
仅在内存重建，不修改快照。旧结果缺少机器文本或微码时不触发补分析。

恢复报告包含 ABI 及其依据、参数、类型与存储来源、栈帧、调用证据、
未恢复项、结构化分支/循环数和残余 goto 数。
`complete` 只表示该有界快照的源码语句恢复没有已知缺项，
不代表原始源码或函数签名已经完整恢复；签名完整性另由
`signature_complete` 描述。恢复异常保留机器文本、微码和失败报告。
`machine_regions` 保存终端状态片段的原始逐条微码、范围、原因和所需机器状态。
含未知异常处理协议或越过自身帧的栈操作时，无法建立普通 C 状态边界的片段
明确显示 `__machine_state_region__`，附部分重建说明和警告；此标记不是可执行 C
函数，也不是已恢复逻辑，`source_semantics_complete` 为 false。仅有内部后继的
片段不会被这样替换后强行恢复为普通 C。

ELF Loader 新增有界动态重定位元数据，负责 REL/RELA、符号表和字符串校验；
`pseudoc/linkage.py` 仅消费这些元数据及已完成处理器快照，核对 ARM64 四指令
PLT 模式后命名目标，不调用解码器或 xref，不按固定步长猜测。动态符号抢占
仍可能改变实际被调实现，因此 PLT 命名不附带推测的完整原型。

## 可编译的伪 C（前导）

可读伪 C 只写函数本身；它用到的辅助运算与占位集中在“伪 C 前导”（prelude）里，通过新增的公开 API 取得
（只增不删，原有调用与返回值不变）：

```python
from fangida.plugins.pseudoc import generate_pseudoc, pseudoc_prelude

readable = generate_pseudoc(function_snapshot, "arm64", style="readable")
header = pseudoc_prelude()                                     # 固定前导，可保存为头文件（带包含保护）
source = pseudoc_prelude(readable) + "\n" + readable.pseudoc  # 另附本函数引用的外部函数声明
```

`pseudoc_prelude(source)` 的 `source` 可以是 `generate_pseudoc` 的结果、其 `reconstruction` 报告、流水线函数
记录或按需生成的输出（含 `pseudoc_reconstruction`），也可以是可读文本本身；同名函数也可从
`fangida.plugins.pseudoc.reconstruct` 导入。只传文本时，以调用形式出现的名字与只以名字出现的函数地址
（例如作为实参传递、作为尾转移目标）都会声明，但返回类型无法从文本得知，非库函数一律写 `uint64_t`；
传结果或报告时按调用处的类型声明，更准确，应优先使用。前导 + 函数文本可以用 GNU C（GCC/Clang）以 C11
或更新标准编译，例如 `cc -fsyntax-only -std=c11 -Werror=implicit-function-declaration`。前导内容固定
（版本 1，990 行、58190 个字符，UTF-8 编码 60491 字节），与 `PYTHONHASHSEED` 无关；
`tests/test_pseudoc_compilable.py` 钉住其 SHA-256，修改前导须同步更新。

前导中的名字分三类：

* 辅助函数（`static inline`，有精确定义，语义与微码 `evaluate_expression` 一致）：
  `shl_W`/`lshr_W`/`ashr_W`/`rol_W`/`ror_W`（W = 8/16/32/64/128；计数为无符号数，>= W 时 shl/lshr 得 0、
  ashr 填符号位，循环移位按 W 取模）、`bswap_128`、`arm_udiv_W`/`arm_sdiv_W`/`arm_urem_W`/`arm_srem_W`
  （W = 8～128；AArch64/AArch32 UDIV/SDIV 不陷入：除数为 0 时商为 0，最小负数除以 -1 的商为最小负数；ARM 没有
  取余指令，取余按编译器生成的 udiv/sdiv + msub 即 `a - (a / b) * b`：除数为 0 时余数为被除数，最小负数对 -1
  取余为 0；32/64 位在 AArch64 真实 CPU 上与 `udiv`/`sdiv`/`msub` 逐一对照）、
  `udiv_W`/`urem_W`/`sdiv_W`/`srem_W`（W = 8～128；除数为 0 或带符号溢出时机器陷入、微码不定义结果，
  这里以 `__builtin_trap()` 陷入）、`x86_udiv_quo/rem_W`/`x86_idiv_quo/rem_W`（W = 8/16/32/64；x86 DIV/IDIV 的
  2W÷W 宽除法，被除数为 hi:lo，商与余数各 W 位，除数为 0 或商溢出时触发 #DE，以 `__builtin_trap()` 陷入；
  辅助函数本身与真实 CPU 逐一对照一致）、`umul_overflow_W`/`smul_overflow_W`（W = 8/16/32/64；x86 MUL/IMUL 的
  CF = OF：W 位操作数的乘积超出 W 位，无符号 / 带符号）、[微码说明](microcode.md)辅助名表中的全部 `vec_*` 组合（含
  饱和加减 `vec_uqadd/uqsub/sqadd/sqsub`、字节重排 `vec_pshufb8_128`、饱和打包 `vec_packss/packus{16,32}_128`；结果宽度
  8～128 中满足通道约束的每一种，与真实 CPU 逐一对照）、`x86_rep_stos/movs{8,16,32,64}`（按元素升序、小端字节序）以及
  `arm_load_acquire_W`/`arm_load_acquire_pc_W`/`arm_store_release_W`（W = 8/16/32/64；AArch64 `ldar`/`ldapr`/`stlr` 系列，
  用 GCC/Clang 的 `__atomic` 内建按名字中的宽度原子访问：`ldar`/`stlr` 是 RCsc，写成 `__ATOMIC_SEQ_CST`——C11 → AArch64
  的标准映射中 seq_cst 加载/存储正是 LDAR/STLR；`ldapr` 是 RCpc，写成 `__ATOMIC_ACQUIRE`；指针形参为
  `(const) volatile void *`；与真实 CPU 执行同一编码对照，见 `tests/test_lifter_exact_forms.py`）。
  归约 `vec_addv{L}_{L}(a)` 等是宏：通道数按实参类型的 `sizeof` 计算，可读 C 把实参写成确切宽度的类型。
* 与机器相关：`pacia_64`/`autia_64`/`xpaci_64`/`pacga_64` 等只在编译目标是实现 PAuth 的 AArch64
  （编译器定义 `__ARM_FEATURE_PAUTH`）时以同一条指令定义（使用当前进程的密钥），其它平台只声明；
  `__arm_rsr64`/`__arm_wsr64` 在 AArch64 上来自 `<arm_acle.h>`，其它平台只声明。
* 占位（只声明、没有定义，不赋予任何语义，链接时缺少符号）：`unknown_value`、`unknown_arguments`、
  `unresolved_operation`、`unresolved_condition`、`unresolved_fallthrough`、`unresolved_stack_address`、
  `unresolved_control_flow`、`unresolved_result`、`initialize_unknown_bytes`、`handler_dependent_value`、
  `unknown_return_upper{8,16,32}`、`tail_transfer`、`indirect_call`、`trap`、`arm64_supervisor_call`，以及
  浮点微码运算 `fadd_32`/`float_to_signed_64` 等（结果取决于舍入模式与浮点异常状态），以及按通道浮点
  `vec_fadd32_128`/`vec_fmul64_128` 等（AArch64 向量 `fadd`/`fsub`/`fmul`/`fdiv`，同样依赖 FPCR，名字为
  `vec_f{运算}{通道位宽}_{结果总宽度}`）。标量/向量浮点算术与整数↔浮点转换在可读 C 中渲染为这些占位辅助、
  不再是 `unresolved_operation`，但重建会记一条 `fp_environment_operation` 未解析项，不自称完整恢复（函数头写明
  “N 处浮点运算依赖舍入/异常环境”；AArch64 写标量或 64 位排列时 V 寄存器高位按硬件清零）；依赖 FP
  标志的比较（`fcmp`/`ucomiss`）仍为 `unresolved_operation`。参数个数可变的
  占位用宏 `FANGIDA_ANY_ARGUMENTS` 声明为未指定形参（C11/C17 写作 `T f()`，C23 起写作 `T f(...)`）。
  `__machine_state_region__(片段名)` 是宏，把片段名转成字符串交给只声明的 `fangida_machine_state_region`。
  `isunordered` 在未包含 `<math.h>` 时定义为 `__builtin_isunordered`（前导不包含 `<math.h>`/`<string.h>`，
  避免与被重建的同名库函数冲突）。

可读 C 的渲染（只改变这些辅助与占位的写法，变量名、结构与类型不变）：

* 移位计数能证明小于宽度时（x86 计数已 `& 31`/`& 63`、AArch64 寄存器移位 `& 31`/`& 63`、常数计数）
  仍写 C 的 `<<`、`>>`；不能证明时（AArch32 寄存器移位取 Rs 低 8 位、`lsr`/`asr #32`）写成
  `shl_32(x, n & 0xff)`、`lshr_32(x, 32)`，不再出现 C 未定义的 `x << (n & 0xff)`、`x >> 32`。窄于 32 位的
  左移按 32 位计算后截回原宽度：`(uint8_t)((uint32_t)x << n)`。左操作数是常量时写成该宽度的无符号常量
  （`1U << (n & 0x1f)`、`1ULL << (n & 0x3f)`，128 位写 `(__uint128_t)5 << …`）：`a << n` 的结果类型是 `a` 提升后的
  类型，以前的 `1 << n` 按 int 计算，`1 << 31` 是带符号溢出，64 位的 `1 << 40` 结果也不对（types 轮修正）。
* 窄位宽（8/16）的加、减、乘、取反、取非在 C 中按整数提升以 `int`/`uint32_t` 计算，可读 C 统一截回原宽度：
  `(uint8_t)((uint32_t)a + (uint32_t)b)`、`(uint8_t)(~(uint8_t)x)` 等（以前溢出/借位或 `~y` 的高位会外泄到
  对高位敏感的上下文——比较、除法/取余、右移、扩展到更宽类型、存入更宽变量或内存、作实参/返回值、
  指针运算、移位计数等，`~y` 甚至可能为负）。链式窄算术只在最外层截一次（模 2^W 下这些运算可结合），
  不给每个窄运算都加转换。计数上界按渲染后的 C 值证明：截回后窄运算落在 `[0, 2^W)`，可用其类型范围作上界
  （如 `(~y & 0xff) >> 3 <= 31` 直接写成 C 的移位）；逻辑右移按 `uint32_t` 计算、不额外截回，但据被移数上界收紧；
  占位与外部调用返回声明的类型，仍不能用 `uint8_t`/`uint16_t` 的范围作上界。
* 带符号类型的值零扩展到更宽类型时先转为同宽度无符号类型（C 的转换会做符号扩展，机器是零扩展）：微码 `zext`
  的操作数是带符号类型（如 `sext` 的结果）时写成 `(uint64_t)(uint16_t)(int16_t)x`；x86-64 写 32 位寄存器（清零
  高 32 位）的值是带符号类型（`movsx ecx, dx`、`x86_idiv_quo_32` 的返回值）时写成 `(uint32_t)(int16_t)x` 再扩展；
  条件选择 `c ? a : b` 中带符号类型的臂先转为结果宽度的无符号类型（否则 C 的通常算术转换可能得到负的 `int`，
  再扩展时被符号扩展）。
* 算术右移：计数在范围内写成 `(uint32_t)((int32_t)x >> n)`（GCC/Clang 对负数为算术右移），否则写
  `ashr_32(x, n)`。循环移位：常数计数且操作数是变量时写成 `(x >> 5) | (x << 27)`，其余写 `ror_32(x, n)`。
* 字节交换写成 `__builtin_bswap16/32/64(x)`，128 位为 `bswap_128(x)`。
* 除法按各架构的真实机器语义精确渲染（不再用一刀切近似）：
  * x86 `div`/`idiv` 是 2W÷W 的宽除法，提升为 `divide_wide`（操作属性 `wide_outputs` 给出两个写回切片，见
    [微码说明](microcode.md)）：可读 C 先把余数算进临时变量，再写商、最后写余数——
    `remainder_N = x86_udiv_rem_W(rdx, rax, d); rax = x86_udiv_quo_W(rdx, rax, d); rdx = remainder_N;`
    （8 位用 ah:al；两次调用都在任何写回之前读输入，实参文本相同；内存源操作数先快照一次，只读一次内存）。
    除数为 0 或商溢出时触发 #DE，由辅助函数 `__builtin_trap()` 表示（不是 C 未定义行为）。商的调用携带 #DE
    （结果无人使用时也保留为语句）；余数与商在同一条件下陷入，余数的调用是纯的，无人使用时整句删除——因此只用
    余数时会看到一条保留的 `x86_idiv_quo_32(…);`。`x86_idiv_*` 返回带符号类型，写 eax/edx 时先转为 `uint32_t`
    再零扩展（机器清零高 32 位）。单操作数 `mul`/`imul` 的 `multiply_wide` 同样精确：低半 `(uintW)(a*b)`，
    高半为 2W 位乘积（无符号零扩展/带符号符号扩展）的高 W 位，例如 64 位
    `(uint64_t)(((__uint128_t)a * (__uint128_t)b) >> 64)`；其后的 `jo`/`jc`/`seto`/`setnc` 等读取 CF = OF
    （乘积超出 W 位），还原为 `umul_overflow_W(a, b)`/`smul_overflow_W(a, b)`（双/三操作数 `imul` 同样如此）；
    SF/ZF/AF/PF 在机器上未定义，读取它们的条件（`je`、`js`、`jp` 等）仍显示 `unresolved_condition`。
  * AArch64/AArch32 除法是 `arm_udiv`/`arm_sdiv`：除数为 0 得 0，最小负数除以 -1 得最小负数，写成 `arm_sdiv_32(a, b)` 等。
  * 微码通用 `udiv`/`urem`/`sdiv`/`srem` 的除数是非零常数（带符号时也不是 -1）时写成 C 的 `/`、`%`（带符号为
    `(uint32_t)((int32_t)a / (int32_t)b)`），否则写成 `udiv_32(a, b)` 等：除数为 0 或带符号溢出时陷入。
    产生它的提升器在操作属性 `division_semantics` 中声明架构语义（新增可选属性）：`"arm_zero"`（ARM：除数为 0
    商为 0、余数为被除数，最小负数 / -1 不溢出）时可读 C 写 `arm_udiv_W`/`arm_urem_W`/`arm_sdiv_W`/`arm_srem_W`
    （W = 8～128，这些除法不会陷入，是纯运算），`"x86_fault"`（除数为 0、带符号溢出时 #DE）与不声明相同，写会陷入的
    `udiv_W` 等；表达式 `name` 字段可逐节点声明，优先于操作级声明；不认识的值按不声明处理。除数是可证明安全的
    非零常数时各语义相同，仍写 C 运算符。`evaluate_expression(…, division_semantics=…)`（新增可选关键字参数）与
    微码分析按同一声明求值，lower 在处理每条操作前把声明交给表达式渲染，因此 evaluate 与渲染在每个宽度上一致。
    目前没有 lifter 产生带声明的通用除法（ARM 走 `arm_udiv`/`arm_sdiv`，x86 走 `divide_wide`），没有声明时行为与
    以前相同；该声明机制为前瞻性接口。位段插入展开为 `(a & ~掩码) | ((uintW_t)b << s)`。
* 这些辅助函数的参数是整数：被推断为指针的实参显式转为整数（地址不变）。占位为可编译补显式转换：
  指针变量的初值与赋值写 `(uint8_t *)unknown_value()`，以未知值为基址的下标写
  `((uint32_t *)unknown_value())[1]`，写入指针变量的 `handler_dependent_value(…)` 前加转换。

外部函数：重建报告新增 `external_functions`（缺省视为空列表），每项为
`{name, return_type, parameters, variadic, source}`。`source` 为 `known_prototype`（名字来自符号/链接证据的
已知库函数，按原型声明）、`call_site`（形参未知，按调用处的返回类型声明为未指定形参）或 `address_only`
（只以函数地址出现）。被重建函数自己的名字与前导中的名字不再声明。外部声明针对单个函数：把多个函数放进
同一个编译单元时，被调函数的定义可能与这里的声明不一致。旧结果没有该字段时按文本中引用的名字生成声明：
调用名按已知原型或 `uint64_t f(FANGIDA_ANY_ARGUMENTS)`，只以名字出现、又不是文本中声明的变量/参数/全局/标号
的名字按 `address_only` 声明为 `void f(FANGIDA_ANY_ARGUMENTS)`。只传文本时的编译率（同一批文本，三个样本都与
传报告相同）：zsh 1081/1251（以前只认调用名时为 888），challenge 675/690（以前 673），libtersafe 全部函数
15505/16529（以前 13926）。

编译率（`cc -fsyntax-only -std=c11 -Werror=implicit-function-declaration`，Apple clang 21；真实上下文与
流水线相同，修改前只包含 `<stdint.h>`/`<stdbool.h>`/`<stddef.h>`）：

| 样本 | 函数 | 修改前 | 修改后 |
| --- | --- | --- | --- |
| challenge（ELF x86-64） | 全部 690 | 72.0% | 97.8% |
| zsh（Mach-O x86-64） | 全部 1251 | 8.9% | 86.4% |
| libtersafe.so（ELF arm64） | 均匀抽样 2000 | 19.2% | 94.1% |

剩余失败都不是辅助/占位造成的：类型恢复把同一寄存器既当指针又当整数（部分寄存器写入并入指针变量、
比较快照/switch/下标用指针、指针与整数直接赋值，共 270 个）、结构化输出重复标签（15）、存储目标带
转换（9）、自递归调用的实参个数与本函数签名不一致（9）；这些属于类型与结构恢复，由下面的 types 轮修正。

types 轮（指针与整数混用处的类型一致性，`typecheck.py` 与 lower/calls/structure 的相应改动）之后，同一口径
（按需生成全部函数，`pseudoc_prelude(结果)` + 文本，`cc -fsyntax-only -std=c11 -Werror=implicit-function-declaration`）：

| 样本 | 函数 | types 轮前 | types 轮后 |
| --- | --- | --- | --- |
| challenge（ELF x86-64） | 全部 690 | 675（97.8%） | 690（100%） |
| zsh（Mach-O x86-64） | 全部 1251 | 1081（86.4%） | 1251（100%） |
| bash（Mach-O x86-64） | 全部 1717 | 1544（89.9%） | 1717（100%） |
| libtersafe.so（ELF arm64） | 全部 16529 | 15505（93.8%） | 16529（100%） |

更严格的口径（另加 `-Werror=int-conversion -Werror=incompatible-pointer-types -Werror=conditional-type-mismatch`，
不计缺少返回值的 `-Wreturn-type`）：types 轮后仍有 zsh 9、bash 44、libtersafe 16 个函数不通过（challenge 全部通过），
都是函数名赋给 `const char *` 变量（`str = handler;`，GCC 14 默认报错）与丢掉 `const` 限定的指针赋值/传参；修复轮把
这两类也写成显式转换后，四个样本全部函数在严格口径下也都通过（challenge 690、zsh 1251、bash 1717、libtersafe 16529）。

做法——类型仍只来自证据，不为编译通过而声明类型：

* 部分寄存器写入（`sete cl`、`mov al, [p]`）并入被推断为指针的变量时，位段合并在地址整数上进行，合并结果是
  整数（再按变量类型转换）：`value = ((uint64_t)ptr & 0xffffffffffffff00ULL) | ptr[0];`。以前写成对指针的
  `&`/`|`（C 约束违例），合并值还被标成指针类型，使按定义-使用网拆分时把整数 web 定成指针、返回类型细化为指针。
* 输出前（结构化之后、所有声明类型与最终返回类型都已确定）按渲染出的 C 类型逐个检查（`TypeCoercion`），
  只在 C 不接受隐式转换处插入显式转换，值逐位不变：赋值、存储、返回、已知原型的实参处指针 ⇄ 整数（空指针常量
  0 除外）、互不兼容的指针类型、丢掉被指类型限定符的指针（`const char *` 赋给 `void *` 变量或作 `free` 的实参写成
  `(void *)"abc"`；多级指针的内层限定符必须相同，C11 6.5.16.1）与函数名赋给对象指针（`str = (const char *)handler;`，
  GCC 14 默认报错；赋给 `void *` 是 GCC/Clang 扩展，保持原样）；比较与条件运算允许限定符不同，不加转换；按位运算、移位、乘除、取反、比较大小、下标、switch 的控制表达式、条件选择两臂
  中的指针转为指针宽度的无符号整数（运算更窄时再截到该宽度）。指针与指针宽度整数之间的中转转换先去掉：
  复制传播代入的 `(uint64_t *)x` 在整数位置写回 `x`，例如 `switch ((uint8_t *)value)` 写成 `switch (value)`、
  `p[(uint32_t *)i]` 写成 `p[i]`。已经类型正确的表达式原样返回，不产生文本差异。
* 加减：整数结果的加减（微码的加减，按字节计算）里出现指针时先转为地址整数，例如以前的
  `(cond ? a : (uint64_t *)b) - (uint64_t)j` 在 C 中按 8 字节缩放，现在写成 `(uint64_t)(…) - (uint64_t)j`。
  指针结果的加减按 C 的指针运算解释，单位是节点类型（`Value.ctype`）的元素，与 `readability._index`、
  `ordering._pointer` 的约定一致：字节地址运算（局部数组地址 + 偏移）的节点为 `uint8_t *`，基址不是字节指针时改写为
  `(uint8_t *)((uintptr_t)p + k)`；按元素计的 `p + k`（如 `arm_load_acquire_32(p + 2)`，即 p 之后第 2 个
  `uint32_t`）原样保留，基址渲染成另一种元素大小（变量重定为字节指针）时先把基址转为节点类型（`(uint32_t *)b + 2`）。
  修复轮前这里把所有加法都当作按字节，会把后者改写成 +2 字节；该路径在真实样本中不可达（`ldar` 系列没有偏移寻址），
  输出未变。
* 存储目的上的右值转换（简化下标读取时加在元素外的同宽度转换，如 `(uint8_t)str[0] = 0`、
  `(uint32_t)error_slot[0] = v`）改为直接对同宽度的左值赋值（C 的赋值转换逐位相同）；经推测为
  `const char *` 的指针写入时基址转为非 const（`((char *)str)[k] = 0`）。
* 结构化：循环头同时是汇合块或循环后的出口时，标签只放一次（以前在同一位置输出两个同名标签）。
* 自递归调用：直接调用自身时按本函数恢复出的签名给出实参（形参顺序与定义一致，栈形参取调用点对应的栈实参槽，
  有自递归时签名保留全部栈形参）与返回类型（摘要证明零扩展时同其它调用），调用证据 `argument_evidence` 为
  `"own_signature"`、参数个数已知；不再写 `unknown_arguments()`，也不再按 ABI 顺序把实参传给按寄存器名排列的
  定义。函数名取定义名（`lower.definition_name`）。

验证：`tests/test_pseudoc_types.py`（修复前全部失败）用 `-Werror=int-conversion -Werror=incompatible-pointer-types`
编译合成函数，能执行的（指针形参指向按同一规则填充、按 4096 字节对齐的缓冲区）加前导开 UBSan 编译运行，与微码
逐条执行比对返回值与缓冲区内容；自递归函数与 Python 参考实现比对。真实样本只访问栈的函数（libtersafe 1467 个、
zsh 11 个、bash 10 个、challenge 1 个，共 55434 组输入）编译运行与微码逐条执行 0 处不一致（修改前 zsh 与 libtersafe
各有 1 个函数因 `1 << 31` 触发 UBSan）。注意比对口径：这些函数几乎都不在 types 轮有文本变化的函数之列（libtersafe 1467
个中 1 个、zsh 11 个中 1 个、bash 与 challenge 0 个），这一项主要说明未改动的函数没有回退；有变化的函数大多调用其它
函数或读写全局数据，不能离线逐条执行（审查时逐个尝试：zsh 275 个中只有 2 个可执行且一致，bash 306 个与 libtersafe
抽样 223 个中没有可执行的）。改动部分的语义证据来自合成用例（上述测试；修复轮补上栈形参取调用点栈实参槽、有自递归时
保留死读取的栈形参、零扩展的自递归返回值、条件选择两臂、窄比较、自递归结果类型等用例，并用变异测试确认每项都有用例
守护）与真实硬件对照：35 个 C 函数（指针标记/对齐/差值/比较/选择、部分寄存器写入、自递归含 x86-64 第 7 个栈实参与
AArch64 10 个形参、`1 << n`、链表与树递归、循环 goto）用 clang -O1/-O2/-O3/-Os 编译，原函数在 arm64 本机、x86-64
经 Rosetta 执行，与流水线生成的可读伪 C（开 UBSan）在相同缓冲区输入下比对返回值与内存——可读 C 完整的 arm64
30/30/30/31 个函数（293/292/292/300 组输入）、x86-64 24/24/24/22 个函数（236/237/237/229 组），0 处不一致
（`skip_ws` 因下述“入口块是循环头”的既有问题跳过）。另把比对扩展到指针形参指向缓冲区的叶子函数（libtersafe 398 个、zsh 22 个、
bash 7 个，关闭 alignment 检查），返回值与缓冲区内容除下述两个既有问题外全部一致（修改前另有 1 个 `int` 移位
溢出与 2 个编译失败）。文本差异逐行归因：zsh/bash/challenge 中有变化的 275/306/16 个函数、libtersafe 中的 1894 个（1851 个只差显式转换，
50 个去掉重复标签，26 个自递归调用，3 个下标上的指针转换）全部归入显式转换的增删、部分写入改为整数合并（随之变化的
变量类型与编号）、截取低位时去掉低位为 0 的常量项、重复标签、自递归调用（实参按定义顺序、去掉无用的候选实参）与函数头说明。
修复轮的文本差异（修复前后，同一实时树口径）：challenge 0 个、zsh 10 个、bash 47 个、libtersafe 全部 16529 个中 16 个函数
有变化，全部是新增的指针转换——函数名前的 `(const char *)`（函数地址赋给按字符串使用的变量）与 `const` 指针、
字符串字面量前的 `(void *)`（作 `free` 等的 `void *` 实参或赋给 `void *` 变量时丢掉限定符），没有其它变化。

生成耗时：类型一致性检查只遍历含指针参与的表达式（`Value.pointer_typed` 与声明为指针的变量名预筛；修复轮另加“叶子操作数、
自身操作数不需转换的节点原样返回”等快速路径），单进程约占可读生成耗时的 1.5%（zsh/bash 全部函数，此前 1.8～1.9%）。
修复轮同时把 `Value` 的派生属性（`pure`、`variable_names`、`has_constants`；单个子节点时共用其不可变名字集合）与
readability 改写时的节点重建改为显式循环，并在没有“返回值高位未知”未解决项时跳过逐句查找，输出逐字相同。单进程交错
计时三轮（`PYTHONHASHSEED=0`，全部函数，均值）：zsh types 轮前 6.45s、types 轮 6.57s（+1.9%）、修复轮后 6.39s（−1.0%）；
bash 6.94s、7.08s（+2.0%）、6.82s（−1.7%）。输出与 `PYTHONHASHSEED` 无关（0 与 12345 下 zsh、bash 全部函数文本相同）。

已知的既有限制（types 轮发现，未改动）：

* 签名中寄存器形参按寄存器名排序而不是 ABI 顺序：x86-64 用到 rcx/r8/r9 的函数写成
  `f(uint64_t arg_4, uint64_t arg_1, uint64_t arg_3, uint64_t arg_2)`，其它函数按 ABI 顺序调用它时位置不对应
  （自递归调用已按定义顺序给出实参）。是否改为 ABI 顺序由所有者决定。
* 函数入口块本身是循环头（入口即被跳回，例如 AArch64 `ldrb w8, [x0]` … `add x0, x0, #1; b 入口`）且入参与寄存器
  变量分开时，入参复制语句 `result = arg_1` 放在入口块里，每次迭代都重新执行，循环不前进（libtersafe 7 个、zsh/bash
  各 1 个函数入口是跳转目标）。需要单独的前置块。
* 带符号下标按无符号整数参与指针运算（`p[(uint64_t)(int32_t)i]`、`arg_2[arg_3 - 1]`），下标为负时是 C 的指针
  溢出（机器上按模 2^64 回绕，结果相同）；按类型化指针读写不检查对齐，未对齐地址在 C 中是未定义行为
  （x86-64/AArch64 硬件允许）。

语义精确性（exactness 轮）：窄于 32 位的加、减、乘、取反、取非现已统一截回原宽度，不再把进位/借位或 `~y`
的高位外泄（例如 x86 `add al, sil` 写成 `(arg_1 & 0xffffffffffffff00ULL) | (uint8_t)((uint32_t)(uint8_t)arg_1 + (uint32_t)(uint8_t)arg_2)`）；
x86 `div`/`idiv`、单操作数 `mul`/`imul` 不再写成 `unresolved_operation`，而是精确渲染为宽除法辅助与宽乘高半
（见上文“除法按各架构的真实机器语义精确渲染”）。真实样本 challenge/zsh/bash 中 `unresolved_operation("div"/"idiv"/"mul"/"imul")`
分别由 32/58/28 条降到 0 条，编译通过率不变。修复轮：`IDIV r/m32` 的商/余数写回 rax/rdx 时不再被符号扩展
（以前写成 `(uint64_t)x86_idiv_quo_32(…)`，商或余数为负时读完整 rax/rdx 与机器不同）；带符号窄值的零扩展同样修正
（见上文）；MUL/IMUL（单操作数与双/三操作数）之后读 CF/OF 的条件精确还原为 `umul_overflow_W`/`smul_overflow_W`
（见下文“条件标志”）；通用除法的 `division_semantics` 改为操作属性并支持 `"x86_fault"`，`arm_*` 辅助覆盖 8～128 位，
ARM 语义取余除以 0 得被除数（与 `udiv`/`sdiv` + `msub` 一致）。

语义：前导里每个辅助函数的 C 定义与微码求值对边界与随机输入逐一比对（移位计数 0、W-1、W、W+1、2W、
0xff、0x100、2^32、2^63…；全部 `vec_*` 组合）；111 个合成叶子函数（x86-64/AArch64/AArch32 的移位、循环
移位、字节交换、除法）共 6078 组输入，以及 libtersafe 中 1449 个、zsh 中 10 个只访问栈的叶子函数共 47690
组输入，编译运行结果与微码逐条执行完全一致（0 处不一致）。真实样本的叶子函数里含移位的只有 5 个、ARM 除法
6 个、字节交换 1 个（challenge 的叶子函数都读写全局数据，不在比对范围内），辅助函数本身主要由前两项覆盖。
测试编译运行时开启 UBSan（`-fsanitize=undefined -fno-sanitize-recover=undefined`，编译器支持时），出现任何
C 未定义行为即失败；另有表达式级比对（微码表达式逐个经 `Expressions.lift` + `format_value` 渲染、编译运行，
覆盖计数上界的各条推理、常数与寄存器除数、窄类型变量的循环移位、归约实参、指针操作数），陷入情形
（除以 0、带符号溢出）在子进程中运行并检查确实陷入。exactness 轮另见 `tests/test_pseudoc_exactness.py`：
8/16 位 add/sub/mul/not/neg 及其组合在边界值（0、1、最大值、符号位、溢出）上开 UBSan（-O0 与 -O2）与微码
逐一比对；x86 DIV/IDIV 的 `x86_(u|i)div_quo/rem_W` 与 MUL/IMUL 的高/低半及 CF/OF（含前导的 `umul/smul_overflow_W`）
与真实 CPU 的 `div`/`idiv`/`mul`/`imul` 逐一对照（含商溢出与除 0 的 #DE 陷入）。流水线级：宽乘/宽除（8/16/32/64 位，
寄存器与内存源；内存源只读一次）写回后读完整 64 位 rax/rdx、商与余数都无人使用时仍陷入、MUL/IMUL 之后的
seto/setc/setno/setnc、双/三操作数 `imul` 的 seto/setnc、`movsx` 后清零高位与两臂带符号的 `cmov`，共 112 个函数，在
1681 组输入（含除数 0、-1、商溢出）上与按 Intel SDM 独立写成的 Python 参考模型逐一相同（本机编译，UBSan，-O0 与
-O2；MUL/IMUL 之后的 jo/jno/jb/jae/jc/jnc 条件分支另有 56 个函数）；能运行 x86-64 时（x86-64 本机，或 Apple Silicon 经 Rosetta 2）再与真实 CPU 执行同一指令序列逐一对照
（同样开 UBSan），陷入必须一致。通用除法的 `division_semantics` 声明在 8～128 位按声明一致求值与渲染（经 lower 的
流水线同样）。验证范围之外（例如本节未列出的指令组合）不作“逐位一致”的保证。已知的既有限制（不属于 exactness 轮）：
入口寄存器先以 8/16 位部分读取（如先 `shl dx, 7`）、之后又读完整 64 位时，签名恢复把该入参推断为窄类型，
完整读取得到的高位不是调用方传入的值。

## 当前边界与验证

默认最多 128 个函数，每函数 512 条指令、32768 字符，总文本 524288 字符。
源码重建及签名预分析固定限制为每函数 512 条指令，支持取消检查；
显式请求更大机器快照时保留全部已提升微码，并标记源码重建截断。
CFG 特化最多 128 个抽象状态、512 条源码指令，预算耗尽时完整回退到
原 CFG，不输出半个特化图。调用清除易变寄存器和内存事实，未知访存
不作为常量；只有唯一确定的标志来源才跨基本块传播。原始微码保持不变，
特化报告记录已证明分支及每条源码指令的原始地址。深层控制流递归限制为
48 层，超出时保留标签；文本超限返回明确的截断占位文本。

常见 `if/else` 和自然循环可结构化，不可约控制流保留 `goto block_N`。
当前未提供通用 switch/for 恢复。浮点、向量及部分复杂指令的源码转换
显式保留 `unresolved_operation`；精确位宽、NaN、舍入、异常和副作用
仍在机器文本及分类微码中查询。辅助运算由 `pseudoc_prelude()` 定义；未知值等占位只声明，不是可直接链接的 C 库（见上节“可编译的伪 C”）。

按通道的整数 SIMD 运算以 `vec_<运算><通道宽度>_<结果宽度>(…)` 辅助调用出现（语义见
[微码说明](microcode.md)中的辅助名表）。AArch64 系统寄存器读取写成 ACLE 的
`__arm_rsr64("名字")` 调用并标为有副作用：计数器、FPSR 每次读取可能不同，因此不做复制传播或
死代码删除，两次 `cntvct_el0` 读取保持两次；`msr tpidr_el0`/`fpcr`/`fpsr` 写成
`__arm_wsr64("名字", 值)`。`msr nzcv` 只改写条件标志，可读 C 中没有对应语句，
其后无法还原的条件显示 `unresolved_condition`。`mrs xN, nzcv` 把标志作为数值读出：N/Z/C/V
由当前（或汇合点共享的）标志来源逐个还原成 C 条件，再放到第 31..28 位。例如 `cmp a, b` 之后
N 为 `(int64_t)(a - b) < 0`，Z 为 `a == b`，C 为 `a >= b`（无符号），V 为
`(int64_t)((a ^ b) & (a ^ (a - b))) < 0`；`tst`/`ands` 之后 C、V 为 0；`ccmp` 在条件不成立时取
指令中的常量位。来源未知时（函数入口、`msr nzcv` 或其它无法建模的标志写入之后），对应位写成
`unresolved_condition("mi")`/`("eq")`/`("hs")`/`("vs")`（标志置位恰好等价于这些条件），并计入函数头的
“处条件未恢复”，不用匿名的 `unknown_value()` 冒充完整结果。x86 MUL/IMUL（单操作数与双/三操作数）之后的
`jo`/`jc`/`jb`/`jae`/`seto`/`setc`… 读的是 CF = OF = 乘积超出 W 位，还原为 `umul_overflow_W(a, b)`/`smul_overflow_W(a, b)`；
MUL/IMUL 之后机器未定义的 ZF/SF/PF 不还原，读取它们的条件仍显示 `unresolved_condition`。其它指令（add/sub/cmp 等）
之后只看溢出标志的条件（x86 `jo`/`seto`、AArch64 `b.vs`）不在 exactness 轮范围内，仍显示 `unresolved_condition`。x86 `rep stos`/`rep movs` 写成
`x86_rep_stos<位宽>(目的, 值, 个数)` / `x86_rep_movs<位宽>(目的, 源, 个数)`，随后的指针与计数
更新按普通赋值还原。这些辅助函数以及 `pac*`/`aut*`/`xpac*`、`vec_*` 的原型参数都是整数（见
[微码说明](microcode.md)）：实参在可读 C 中被推断为指针时显式转换为指针宽度的整数，例如
`x86_rep_stos64((uint64_t)(uint64_t *)local_1, 0, 4)`、`pacda_64(arg_1, (uint64_t)arg_2)`，
按文档原型可直接编译。指针认证只在被认证的寄存器是 C 层变量时出现（例如 `pacda_64(p, m)` 作为
函数结果）；数据指针的认证（`autda`、`autia x1, x2` 等）在实现 FEAT_FPAC 时失败会陷入，结果无人
使用时也保留为 `(void)(autia_64(p, m));`。LR 上的 `paciasp`/`autiasp` 只保护返回地址，可读 C 不建模
返回地址（与保存/恢复 x30 的栈帧脚手架相同），所以签名与认证本身不单独成句；x30 经 `stp`/`ldp`
保存恢复而成为 C 层变量时同样如此。只有签名或认证后的 x30 被当作数据使用（例如 `mov x0, x30`，或
序言未被识别为栈帧脚手架、x30 一直是普通变量）时，才以 `value = pacia_64(value, sp)` 这类赋值出现。
机器文本始终保留 `x30 = pacia_64(x30, sp);`。
重叠栈槽使用字节数组表示机器布局，跨架构可移植 C 还需处理字节序、
对齐和别名规则；本模块不宣称输出可作为原源码重新编译。

`tests/test_reconstruction.py` 验证五类重建功能，使用 C 编译执行检查
整数边界、类型转换、比较捕获、分支汇合、循环、数组、栈槽和调用结果；
同时检查未知 ABI、残余控制流、快照不可变性、预算和 MCP 双视图。
既有机器语义、API 兼容与解码/xref 线程身份测试保留。

真实 ARM64 回归使用 `tests/fixtures/tersafe_tss_unity_is_enable.json`：
255 条指令、66 个基本块的常量状态混淆，覆盖 MOVK、LDUR/STUR、ORN/BIC、
MOVI 向量清零与 Q 寄存器成对访存。对原始微码与生成 C 使用独立路径求值和
可控外部调用桩核对 24 组边界输入；不会将调用桩验证当作原型恢复完成。

`tersafe_tp2_dec_tss_info.json` 保存另一真实函数的36条指令。回归分别核对
正常零分支的三个参数、callee-saved 寄存器及 SP 恢复、SDK 尾转移，以及
非零分支19条机器区域指令、literal 内存读取、SVC、间接调用与最终 BR 的
完整保留。零分支用7组边界输入独立遍历原始微码并编译生成源码，外部调用
和转移使用可控桩；未执行用户 SO，也未证明非零机器状态路径的业务含义。
