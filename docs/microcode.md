# 分类微码与语义 API

微码提升消费处理器已经完成的指令和 CFG 快照。Loader 仍只负责文件与容器，
处理器仍负责解码，伪 C/微码仍通过独立插件加载。提升、化简与查询不重新
读取源文件、不调用解码器或 xref、不创建工作线程。

## 分类和边界

原生支持 `x86`、`x86_64`、`arm`、`arm64` 的以下常见指令子集。类别是
语义分类，并不表示该架构整个指令集已实现；不支持的形式会退回不透明屏障。

| 类别 | 独立模块 | 保留的主要语义 |
| --- | --- | --- |
| 传送、转换 | `data_transfer.py` | 寄存器别名、符号/零扩展、宽立即数、LEA/ADR/ADRP 地址形成、交换与原子访存 |
| 整数运算 | `arithmetic.py` | 固定宽度回绕、进位/借位、乘法高低结果、除零/商溢出、架构除法差异 |
| 位运算 | `bitwise.py` | 逻辑运算、移位计数掩码、旋转、含进位旋转、位测试、字节交换 |
| 访存 | `memory.py`、`x86_strings.py` | 访问宽度、符号扩展、成对访问、访问地址捕获、前后索引回写；x86 `stos`/`movs`（含 `rep`）的串填充/复制 |
| 栈 | `stack.py` | 栈指针变化、操作顺序、内存读写、`pop rsp` 与栈帧退出 |
| 比较、条件选择 | `comparison.py` | 比较来源、条件码、`SETcc`、`CMOVcc`、ARM 条件选择与条件比较 |
| 浮点及转换 | `floating_point.py` | 标量运算、转换方向、舍入环境、异常规则、向量高位保留/清零 |
| 控制流 | `control_flow.py` | 直接目标、间接目标表达式、条件分支、调用屏障与未解析目标 |
| 系统效果 | `system.py`、`aarch64_system.py` | 填充指令、进位标志、方向标志；AArch64 `mrs`/`msr`（NZCV 与标志精确互转、具名系统寄存器读取）与指针认证；特权/未知操作保留未知效果 |
| 按通道 SIMD | `vector_lanes.py`（语义 `lane_ops.py`） | 通道宽度与个数、64 位排列清零高半、窄化/扩展/归约/重排；x86 SSE 两操作数与 VEX 三操作数、内存源对齐 |

补充覆盖（与 Ghidra 对比后补齐的缺口）：

- 乘法：arm64 `umulh`/`smulh` 按 128 位乘积取高 64 位（带符号版本先符号扩展再乘），以及
  `umaddl`/`smaddl`/`umsubl`/`smsubl`/`umnegl`/`smnegl`、`mneg`、`negs`；ARM32 `mla`/`mls`/`umull`/`smull`。
  `umull`/`smull` 的目的寄存器与源寄存器重叠时，先写不覆盖输入的那一半；两个目的都重叠时保持不透明。
- AArch32 条件执行（`conditional.py`，只在没有其它提升器认领时尝试）：`addeq`、`movne`、`lslne #imm`
  等，把每个寄存器赋值改写为条件选择，条件不成立时保留旧值。剥离条件码要求去掉末两个字母后正好是
  白名单里的基础助记符，所以 `teq`、`mls`、`umulls`、`lsls`、`movs`、`bics` 不会被误拆。以下几类仍保持
  不透明：条件访存（`ldrne`/`strne`，因为选择的源会被无条件求值）、会设置标志的条件指令（`addseq`）、
  带进位的条件指令（`adceq`）、寄存器控制移位和计数达到宽度的条件移位。另外补了 `bx<cond>` 和 arm64
  `bc.<cond>` 的条件码解析，以及 arm64 `cinc`/`cinv`/`cneg` 和 ARM32 `movw`/`movt`。
- 向量与浮点搬移（`vector.py`）：x86 的 `movaps`/`movups`/`movdqa`/`movdqu`/`vmov*`、`movq`/`movd`、
  `movss`/`movsd`（寄存器间只替换低位，从内存读入时清零高位）、`pxor`/`xorps` 清零惯用法、
  `punpcklqdq`/`movlhps` 等；arm64 的向量 `mov`/`orr`/`and`/`eor`/`bic`/`not`、`fmov` 各种形式、通道插入与
  提取（`ins`/`umov`/`smov`）、`dup`、`movi`。这些都是 128 位精确赋值；按通道的整数运算见下一条。
  可读 C 中超过 64 位的常量写成 `(((__uint128_t)hi << 64) | lo)`。
- 按通道 SIMD 整数运算（`vector_lanes.py`，语义集中在 `lane_ops.py`）：opcode 名字自带通道宽度 L，表达式宽度
  W 是结果总位数，例如 `vec_add32`（宽度 128 即 4 个 32 位通道）。AArch64 覆盖向量与标量 `dN` 形式的
  `add`/`sub`/`mul`/`neg`/`abs`、`cmeq`/`cmhi`/`cmhs`/`cmgt`/`cmge`/`cmtst`（含与 `#0` 比较及 `cmle`/`cmlt #0`）、
  `ushl`/`sshl`、`umax`/`umin`/`smax`/`smin`、立即数移位 `shl`/`ushr`/`sshr`/`usra`/`ssra`、窄化
  `xtn`/`xtn2`/`shrn`/`shrn2`、扩展 `ushll`/`sshll`/`uxtl`/`sxtl`/`shll`（含 “2” 形式）、
  `uaddl`/`saddl`/`usubl`/`ssubl`/`umull`/`smull`/`umlal`/`smlal`/`umlsl`/`smlsl`、`uaddw`/`saddw`/`usubw`/`ssubw`、
  `mla`/`mls`、`uzp1`/`uzp2`、`ext`、`rev16`/`rev32`/`rev64`、`bsl`/`bit`/`bif`、`addv`/`umaxv`/`uminv`/`smaxv`/`sminv`、
  `addp dN`、`mvni` 与向量立即数 `orr`/`bic`、单通道 `ld1`/`st1`（不回写基址）以及饱和加减
  `uqadd`/`uqsub`/`sqadd`/`sqsub`（向量与 `dN` 形式；AArch64 饱和时置位的 FPSR.QC 不是寄存器结果，记在操作属性
  `saturating="fpsr_qc"`）。64 位排列与标量形式写低 64 位并
  清零高 64 位；`xtn2`/`shrn2` 保留低 64 位。x86 覆盖 `padd`/`psub`/`pcmpeq`/`pcmpgt`（b/w/d/q）、`pmullw`/`pmulld`、
  `pmin`/`pmax` 各宽度、饱和加减 `padds`/`psubs`/`paddus`/`psubus`（b/w）、`psll`/`psrl`/`psra`（立即数与 xmm 计数）、
  `pinsr`/`pextr`、`pmovmskb`/`movmskps`/`movmskpd`、
  `pblendw`/`blendps`/`blendpd`、`pshufd`、字节重排 `pshufb`（由控制字节选 a 的字节、最高位为 1 时清零）、
  饱和打包 `packsswb`/`packssdw`/`packuswb`/`packusdw`（源按带符号解释饱和到半宽，低半为第一个源）、
  `pmovsx`/`pmovzx`、`movlps`/`movhps`/`movlpd`/`movhpd` 及对应 VEX.128
  形式；`pcmpeq x, x` 记为全 1 常量。融合乘加（`fmadd`/`fmla`…）、舍入运算、`tbl`、多结构访存、ymm/zmm 形式仍保持不透明。
- 标量与向量浮点（`floating_point.py`）：标量 `fadd`/`fsub`/`fmul`/`fdiv`、整数↔浮点转换（`scvtf`/`ucvtf`/`fcvtzs`/
  `fcvtzu`，含源/目的都是 SIMD 标量 `sN`/`dN` 的形式）、`fcsel`（按条件精确拷贝，不依赖 FPCR，可读 C 中是普通的
  条件选择）与向量浮点算术 `fadd`/`fsub`/`fmul`/`fdiv`（`2s`/`4s`/`2d` 及 `fmul` 的按元素形式）都已提升。AArch64 写
  标量 `sN`/`dN` 或 64 位排列（`2s`）时硬件把 V 寄存器的 `[127:W]` 清零，这些操作都带 `destination_width`=W、
  `storage_width`=128、`zero_upper`=true（x86 传统 SSE 标量运算保留高位，不受影响）。按元素 `fmul vD.T, vN.T, vM.T[i]`
  的第二个实参是“把 vM 的第 i 个元素精确广播到各通道”的整数表达式（与 `dup vD.T, vM.T[i]` 相同），因此
  `vec_fmul{通道}_{总宽}` 仍是逐通道运算，元素下标不会丢失。浮点算术/转换的结果依赖 FPCR 舍入与异常，微码求值
  返回 `UnknownValue`，可读 C 渲染为前导声明的 `fp_environment` 占位辅助（标量 `fadd_W`、`signed_to_float_W`…；
  向量 `vec_f{运算}{通道}_{总宽}`），不是精确可求值的整数运算，重建记 `fp_environment_operation` 未解析项，函数头
  写明“N 处浮点运算依赖舍入/异常环境”。依赖 FP 标志的比较 `fcmp`/`ucomiss` 仍保持不透明（可读 C 为
  `unresolved_operation`）。
- AArch64 带内存序的单寄存器访存（`memory.py`）：获取加载 `ldar`/`ldarb`/`ldarh`/`ldapr`… 与释放存储
  `stlr`/`stlrb`/`stlrh` 的值语义等同普通 `ldr`/`str`，内存序作为操作属性 `memory_order="acquire"/"release"` 保留，
  另有能精确表达它的 C11 内存序 `c11_memory_order`：`ldar`/`stlr` 系列是 RCsc（`stlr` 之后的 `ldar` 不能提前），只有
  `seq_cst` 能表达（C11 → AArch64 的标准映射中 seq_cst 加载/存储正是 LDAR/STLR）；`ldapr` 系列（RCpc）是 `acquire`。
  可读 C 据此写成前导的原子访问 `arm_load_acquire_W(p)`/`arm_load_acquire_pc_W(p)`/`arm_store_release_W(p, v)`
  （GCC/Clang `__atomic` 内建），而不是会被编译器提出循环的普通读写；私有栈槽（地址未外泄）只有本线程能访问，
  仍写普通读写；地址已外泄的栈槽也写普通读写，但记 `memory_order` 未解析项、不自称完整。地址须是裸基址 `[Xn]`。
  `ldpsw`（加载一对 32 位并各自符号扩展到 64 位，含前后变址回写）也已提升。成对加载 `ldp`/`ldpsw` 无回写且第一个
  目的就是基址时（`ldp x0, x1, [x0]`，架构上合法），先发出第二个元素的加载，两个元素都从原基址读取。独占/原子
  访存 `ldaxr`/`stlxr`/`ldaddal` 仍保持不透明。
- 位域提取与位测试：AArch64 `extr Wd, Wn, Wm, #lsb`（`Wn:Wm` 右移 `lsb` 取低 W 位，精确）。x86 `bt`/`bts`/`btr`/`btc`
  提升为 `bit_test`（CF = 取模后的位）与 `bit_modify`（`bts/btr/btc` 的写回）：寄存器形式与立即数索引的内存形式都已
  表达（寄存器索引的内存形式会寻址到别的字，保持不透明）；可读 C 把 `bt` 之后依赖 CF 的分支/`setcc` 还原为
  `(x >> i) & 1` 条件（操作数被推断为指针时先转为整数），`bts/btr/btc` 还原为 `| / & ~ / ^` 的位修改。可读 C 的
  常量特化不求值 `bit_test`/`bit_modify`：遇到它们（以及其它改写标志或写内存的未建模操作，如 `ccmp`、`rcl`、
  `cmpxchg`）时丢弃已知标志与已知栈槽内容，不会按 `xor eax, eax` 留下的过期 CF 或写入前的栈槽值“证明”分支。
- AArch64 系统寄存器（`aarch64_system.py`）：`mrs xN, nzcv` 是由 `flags.N/Z/C/V` 放在第 31..28 位拼出的普通
  位向量表达式（其余位为 0）；`msr nzcv, xN` 是 `flags_nzcv` 操作，按属性 `bit_positions` 整体写四个标志，
  其余位忽略。块内分析据此精确保存/恢复标志，混淆代码常见的“保存标志—改写—恢复”往返不会丢失条件。
  白名单中读取无副作用的寄存器（`tpidr_el0`/`tpidrro_el0`/`tpidr2_el0`、`fpcr`/`fpsr`、`cntvct_el0` 等计数器、
  `ctr_el0`/`dczid_el0`、`midr_el1` 与 `id_aa64*_el1`）读为带寄存器名的 `system_register` 表达式：它不是纯表达式
  （计数器与 FPSR 会变化，ID/计数器在 EL0 可能陷入后由系统模拟，属性 `volatile`/`may_trap` 记录），
  只有调用方给出该寄存器值时才能求值。`tpidr_el0`/`tpidr2_el0`/`fpcr`/`fpsr` 的写入是显式
  `system_register_write`（后两者改写浮点环境）。特权寄存器、PSTATE 立即数形式（`msr daifset, #2`）、
  实现定义寄存器、会改写标志的 `rndr` 等保持不透明屏障。
- 指针认证（`aarch64_system.py`）：`paciasp`/`autiasp`/`pacibsp`/`autibsp`/`paciaz`/`autiaz`/`pacia1716`/
  `autib1716`/`xpaclri` 以及寄存器形式 `pacia`/`pacib`/`pacda`/`pacdb`/`autia`…/`paciza`…/`xpaci`/`xpacd`/`pacga`
  只写目的寄存器（并读取修饰寄存器），不再是清空全部状态的屏障。结果取决于密钥与 PAuth 实现/配置，
  求值为未知；`aut*` 在实现 FEAT_FPAC 时认证失败会陷入，记为非纯表达式。HINT 空间形式在未实现 PAuth 的
  处理器上按 NOP 执行（属性 `without_pauth: "nop"`），`paciasp`/`pacibsp` 同时是隐式 BTI c 落点。
  `retaa`/`retab` 仍是返回，`braa`/`brab`/`blraa`/`blrab`（含 z 形式）是间接跳转/调用，只把目标操作数表示为
  `autia(Xn, Xm 或 0)`，从不求解目标。
- x86 串操作（`x86_strings.py`）：单次 `stos`/`movs` 用已有的 store/load/assign 表达；`rep stos`/`rep movs`
  为 `memory_fill`/`memory_copy`（目的、值或源、元素个数），随后 `rdi`/`rsi += rcx*元素字节数`、`rcx = 0`。
  复制按元素升序进行（重叠时与 memmove 不同，属性 `overlap` 记录）。方向标志只按 DF=0 建模：这是写入属性的
  ABI 假设（System V/Win64 要求入口和调用前后 DF=0），函数快照中出现 `std`/`popf` 等可能置位 DF 的指令时
  保持不透明。32 位形式另记平坦模型 ES 段基址为 0 的假设；`67h` 地址宽度前缀、段超越、`repe cmps`/
  `repne scas` 保持不透明。
- 不透明回退保留快照里的读写集。寄存器名先规范化为微码根，例如 `eax`→`rax`、`w0`→`x0`、
  `nzcv`→`flags`。只有“必定整体写入”的寄存器计入 `writes`；条件执行、先读后写（`lock xadd`、
  `bsf rdi, rdi`、`cpuid`）、x86 的 8/16 位部分写以及可能不发生的写，都改记到 `reads`，避免 ABI 推断
  把可能写当成必定定义而丢掉参数。屏障语义不变，完整快照保存在操作属性
  `snapshot_reads`/`snapshot_writes` 中。

实测（与改动前对比）：challenge（x86-64，25 万条指令）的不透明指令从 1075 条降到 3 条；
libtersafe.so（arm64，65 万条指令）从 8022 条降到 6683 条，512 条上限下伪 C 的 `unresolved_operation`
从 8737 处降到 7459 处。剩余的主要是 `mrs`/`msr`、指针认证 `autiasp`/`paciasp` 和 lane 级 SIMD。

第二轮补齐系统寄存器、指针认证、按通道 SIMD 与 x86 串操作后（同一份函数快照、隔离副本前后对比，
512 条上限）：libtersafe.so 的不透明指令从 6683 条降到 153 条，可读伪 C 的 `unresolved_operation`
从 7459 处降到 366 处（指针认证不再是屏障后，栈帧序言/尾声的 `stp`/`ldp` 也能正常还原）；challenge 从
3 条降到 0 条（`unresolved_operation` 38→34）；zsh（Mach-O x86-64）从 40 条降到 7 条（529→403）。
三者伪 C 生成失败均为 0，PYTHONHASHSEED 取 0/1/12345 时伪 C 与微码输出逐字节相同。剩余不透明指令
主要是 `ldar`/`ldarb`（获取语义加载）、浮点通道运算与转换、`bt` 内存形式和 `pshufb`。

第三轮补齐这些剩余的不可表示操作后（同一份函数快照、基线副本与“基线 + 只覆盖本轮改动”两棵隔离树前后
对比，512 条上限）：libtersafe.so 的不透明指令从 153 条降到 46 条，可读伪 C 的 `unresolved_operation` 从 366 处
降到 104 处；zsh（Mach-O x86-64）不透明 11→0、`unresolved_operation` 400→155（`bt`/标量浮点消失，剩 `push`/`pop`/
`adc`/`sbb`/`setcc` 等既有类别）；bash（Mach-O x86-64）不透明 2→0、308→142；challenge 不透明保持 0、2→2。
本轮新增：x86 `bt`/`bts`/`btr`/`btc`（寄存器与立即数索引内存形式）与依赖 CF 的分支还原、`pshufb`、饱和打包
`packss`/`packus`、饱和加减 `padds`/`psubs`/`paddus`/`psubus`；AArch64 `ldar`/`stlr` 系列（内存序属性）、`ldpsw`、
`extr`、`fcsel`（精确条件拷贝）、饱和加减 `uqadd`/`uqsub`/`sqadd`/`sqsub`；标量与向量浮点算术、整数↔浮点转换
（渲染为 `fp_environment` 占位辅助，FPSR.QC/舍入作为属性如实标注）。三样本伪 C 生成失败仍为 0，编译通过率
不下降，PYTHONHASHSEED 取 0/1/12345 输出逐字节相同。注意 `unresolved_operation` 的下降中有一部分只是换了
归类：浮点算术与转换（libtersafe 约 204 处，zsh 约 67 处）改写成不可求值的占位辅助，另记
`fp_environment_operation`，并非精确恢复。

第三轮审查后的修正：常量特化不再按 `bt` 系列/`ccmp` 之前的过期标志、或 `bts`/`btr`/`btc` 写入前的栈槽内容
证明分支；AArch64 标量/64 位排列浮点写入清零 V 寄存器高位；按元素 `fmul` 保留元素下标；`ldp`/`ldpsw` 的第一个
目的与基址相同时从原基址读取两个元素；位测试的指针操作数先转为整数；`ldar`/`stlr` 系列写成原子访问；浮点
运算的输出参与变量宽度推断（AArch64 整体写回的结果；不再把只读低/高 64 位的 128 位向量结果定成 64 位变量而丢掉高半）。饱和、`pshufb`、打包已有硬件
对照（`tests/test_lifter_system_simd.py`）；`bt`/`bts`/`btr`/`btc`、`extr`、`ldpsw`/`ldp`、获取/释放访存、`fcsel`、
`ccmp` 后的特化、标量 SIMD 转换与按元素 `fmul`（浮点占位按默认 FPCR 给出参考定义）由
`tests/test_lifter_exact_forms.py` 以 Capstone 解码的真实编码，在 arm64 原生与 Rosetta 下 x86 硬件上对照，渲染出的
可读 C 开 UBSan 编译运行，并与微码逐条执行比对。修正前后（同一份快照、隔离副本，512 条上限）不透明指令不变（libtersafe 46、zsh/bash/challenge 0），`unresolved_operation` 为 libtersafe 104→104、zsh 155→153、bash 142→141、challenge 2→2（特化不再沿过期标志克隆路径）；按占位渲染的 `fp_environment_operation` 另计：libtersafe 204、zsh 67、bash 1、challenge 0。
剩余不透明主要是融合乘加 `fmadd`/`fmla`、向量浮点转换/比较 `fcvtzs`/`fcvtn`/`fcmle`、多结构访存 `ld4`/`st3`、
独占/原子访存 `ldaxr`/`stlxr`/`ldaddal`、屏障 `dsb`/`isb`/`dc`/`ic` 与内存标签 `stg`；可读 C 中最大的剩余
`unresolved_operation` 是 `fcmp`（FP 标志未重建为源比较）与 x86 `push`/`pop`/`adc`/`sbb`/`setcc`。

`conditions.py` 区分有符号与无符号关系、严格与包含边界的比较。浮点比较
保留 NaN 的无序情况，不能直接套整数分支条件。比较操作数先捕获为临时值；
后续寄存器赋值不能改变已发生的比较。标志位变化、控制流汇合和未知效果
会使来源失效，此时机器视图保留标志位公式；源码重建视图无法恢复条件时
显示 `unresolved_condition`，不会生成猜测的比较。

浮点异常及舍入依赖 `fp_environment`；转换记录其规则，但在没有控制状态
的情况下，纯表达式求值器返回 `UnknownValue`。浮点数不会参与整数恒等式
化简。访存也不视为纯表达式，同一加载不能凭借 `x ^ x` 被消除。
可能陷阱的整数除法及依赖浮点环境的转换也不会被恒等式消除。ARM32 立即数
没有提供旋转编码时，其移位器进位保留为未知，不能沿用旧进位推断大小关系。

当前事实分析限定于基本块内，不推测路径合并、未知内存、间接调用 ABI、
自修改代码或 VM 的内部语义。虚拟化混淆仍需注册针对该语义的提升器；没有
证据的操作标记 `supported=False` 并使分析状态失效。

语义核对参考 [Intel 指令集手册](https://cdrdv2-public.intel.com/868140/253666-089-sdm-vol-2a.pdf)
以及 [Arm 浮点条件码说明](https://developer.arm.com/community/arm-community-blogs/b/architectures-and-processors-blog/posts/condition-codes-4-floating-point-comparisons-using-vfp)。

### 新增表达式与辅助名

可读 C 对未专门渲染的微码 opcode 统一写成 `{opcode}_{宽度}(参数…)`，宽度为表达式结果位数（移位、循环移位、字节交换与除法另有不含未定义行为的专门写法，见[源码重建](reconstruction.md)“可编译的伪 C”）。下表名字都由 `pseudoc_prelude()` 定义或声明。本轮新增：

| 名字（渲染形式） | 参数 | 精确语义 |
| --- | --- | --- |
| `vec_{add,sub,mul}{L}_{W}(a, b)` | a、b 均为 W 位 | 每个 L 位通道模 2^L 加/减/乘 |
| `vec_{cmeq,cmhi,cmhs,cmgt,cmge,cmtst}{L}_{W}(a, b)` | 同上 | 关系成立的通道为全 1，否则为 0；hi/hs 无符号 >、>=，gt/ge 带符号 >、>=，tst 为 `(a&b)!=0` |
| `vec_{umax,umin,smax,smin}{L}_{W}(a, b)` | 同上 | 无符号/带符号逐通道最大、最小 |
| `vec_{ushl,sshl}{L}_{W}(a, b)` | 同上 | 按 b 通道最低字节的带符号值移位：正数左移，负数逻辑（ushl）/算术（sshl）右移，移出全部位为 0 或符号填充 |
| `vec_{neg,abs}{L}_{W}(a)` | a 为 W 位 | 逐通道取负（模 2^L）/ 带符号绝对值（最小负数不变） |
| `vec_{shl,lshr,ashr}{L}_{W}(a, n)` | a 为 W 位，n 为无符号计数 | 每个通道移 n 位；n >= L 时 shl/lshr 为 0、ashr 为符号填充 |
| `vec_narrow{L}_{W}(a)` | a 为 2W 位 | 每个 L 位通道截断为低 L/2 位后依次排列 |
| `vec_{zext,sext}{L}_{W}(a)` | a 为 W/2 位 | 每个 L 位通道零/符号扩展为 2L 位 |
| `vec_{addv,umaxv,uminv,smaxv,sminv}{L}_{L}(a)` | a 为 L 的整数倍 | 全部通道的和（模 2^L）/无符号或带符号最大、最小值 |
| `vec_signmask{L}_{W}(a)` | a 为 L 的整数倍 | 第 i 位为第 i 个通道的最高位，其余位为 0 |
| `vec_{uqadd,uqsub,sqadd,sqsub}{L}_{W}(a, b)` | a、b 均为 W 位 | 每个 L 位通道的饱和加/减：`uq` 无符号截到 `[0, 2^L-1]`，`sq` 带符号截到 `[-2^(L-1), 2^(L-1)-1]`（AArch64 UQADD/SQADD…、x86 PADDS/PADDUS…） |
| `vec_pshufb8_128(a, b)` | a、b 均为 128 位 | x86 PSHUFB：结果第 i 字节在控制字节 `b[i]` 最高位为 1 时为 0，否则取 a 的第 `b[i] & 15` 字节 |
| `vec_{packss,packus}{L}_128(a, b)` | a、b 均为 128 位（L ∈ 16/32） | 把每个 L 位通道按带符号解释饱和到 L/2 位（`ss` 带符号范围、`us` 无符号 `[0, 2^(L/2)-1]`），结果低半为 a 的通道、高半为 b 的通道（x86 PACKSSWB/PACKSSDW/PACKUSWB/PACKUSDW） |
| `vec_f{add,sub,mul,div}{L}_{W}(a, b)` | a、b 为 W 位（占位，只声明） | AArch64 向量浮点逐通道算术（L 为单/双精度 32/64，W 为结果总宽 64/128）；结果依赖 FPCR 舍入与异常，不精确求值 |
| `pacia_64`/`pacib_64`/`pacda_64`/`pacdb_64(p, m)` | `uint64_t p`（指针的整数值）、`uint64_t m`（修饰值），返回 `uint64_t` | 用对应密钥给指针加 PAC；结果取决于密钥与配置 |
| `autia_64`/`autib_64`/`autda_64`/`autdb_64(p, m)` | 同上 | 认证并去除 PAC；失败时陷入（FEAT_FPAC）或得到不可用指针；有副作用，结果无人使用时保留为 `(void)(autda_64(p, m));` |
| `xpaci_64`/`xpacd_64(p)` | `uint64_t p`，返回 `uint64_t` | 按配置的地址宽度清除 PAC 字段 |
| `pacga_64(n, m)` | 两个 `uint64_t`，返回 `uint64_t` | 通用 PAC：高 32 位为 PAC，低 32 位为 0 |
| `__arm_rsr64("名字")` | 系统寄存器名 | ACLE 系统寄存器读取（可读 C 中带副作用，不参与复制传播） |
| `__arm_wsr64("名字", 值)` | 系统寄存器名、64 位值 | ACLE 系统寄存器写入（`tpidr_el0`/`tpidr2_el0`/`fpcr`/`fpsr`） |
| `arm_load_acquire_{8,16,32,64}(p)`、`arm_load_acquire_pc_{8,16,32,64}(p)` | `const volatile void *p`，返回 `uintW_t` | AArch64 `ldar`/`ldarb`/`ldarh`（RCsc，`__atomic_load_n(…, __ATOMIC_SEQ_CST)`）与 `ldapr`/`ldaprb`/`ldaprh`（RCpc，`__ATOMIC_ACQUIRE`）：按名字中的宽度原子读取 p |
| `arm_store_release_{8,16,32,64}(p, v)` | `volatile void *p`、`uintW_t v`，返回 `void` | AArch64 `stlr`/`stlrb`/`stlrh`：`__atomic_store_n(…, v, __ATOMIC_SEQ_CST)`（与 `ldar` 之间不可重排，C11 中只有 seq_cst 能表达） |
| `x86_rep_stos{8,16,32,64}(d, v, n)` | `uint64_t d`（目的地址）、`uint64_t v`（值）、`uint64_t n`（元素个数），返回 `void` | 从 d 起按元素升序写 n 个 v 的低位（DF=0） |
| `x86_rep_movs{8,16,32,64}(d, s, n)` | `uint64_t d`、`uint64_t s`、`uint64_t n`，返回 `void` | 按元素升序把 s 起 n 个元素逐个复制到 d（重叠时不是 memmove） |
| `x86_udiv_quo/rem_{8,16,32,64}(hi, lo, d)` | 三个 `uintW_t`（被除数高/低半与除数），返回 `uintW_t` | x86 `DIV`：`hi:lo` 为 2W 位被除数，商（quo）/余数（rem）各 W 位；除数为 0 或商 >= 2^W 时触发 #DE（`__builtin_trap()`） |
| `x86_idiv_quo/rem_{8,16,32,64}(hi, lo, d)` | 三个 `uintW_t`，返回 `intW_t` | x86 `IDIV`：同上但带符号（商向零截断），商超出 `[-2^(W-1), 2^(W-1)-1]` 或除数为 0 时 #DE |
| `arm_udiv/arm_sdiv/arm_urem/arm_srem_{8,16,32,64,128}(a, b)` | 两个 `uintW_t`，返回 `uintW_t` | ARM 语义（AArch64/AArch32 `UDIV`/`SDIV` 不陷入；供专用 `arm_udiv`/`arm_sdiv` 与 `division_semantics="arm_zero"` 的通用除法使用）：除数为 0 时商为 0；最小负数除以 -1 得最小负数；取余按编译器的 `udiv`/`sdiv` + `msub` 即 `a - (a / b) * b`，除数为 0 时得被除数，最小负数对 -1 取余为 0（128 位需要 `__int128`） |
| `umul_overflow_{8,16,32,64}`/`smul_overflow_{8,16,32,64}(a, b)` | 两个 `uintW_t`，返回 `bool` | x86 `MUL`/`IMUL` 的 CF = OF：W 位操作数的完整乘积超出 W 位（无符号：高半不为 0；带符号：不能表示为 W 位带符号数）。可读 C 中 MUL/IMUL 之后的 `jo`/`jc`/`seto`/`setnc` 等写成这两个调用 |

`__arm_rsr64`/`__arm_wsr64` 是 `<arm_acle.h>` 中的标准内建；其余名字由 `pseudoc_prelude()` 按上表定义（`pac*`/`aut*`/`xpac*`/`pacga` 只在实现 PAuth 的 AArch64 上以同一条指令定义，其它平台只声明）。上表辅助函数的
参数都是整数（`vec_*` 为对应宽度的无符号整数，128 位为 `__uint128_t`）：可读 C 中被推断为指针的实参会显式
转换为指针宽度的整数（例如 `x86_rep_stos64((uint64_t)(uint64_t *)local_1, 0, 4)`、`pacia_64(x, (uint64_t)ptr)`），
因此按上表原型定义后可直接编译，不会触发 `-Wint-conversion`。输出前的类型一致性检查（`reconstruct/typecheck.py`）
对复制传播等之后才出现在这些位置的指针同样补上转换；`call` 节点渲染的 `x86_rep_*`、`x86_(u|i)div_*`、
`umul/smul_overflow_*`、`unknown_return_upperN` 的形参按整数检查，`unresolved_operation`、`handler_dependent_value`
的字符串形参与 `__arm_rsr64`/`__arm_wsr64` 的寄存器名保持指针。`arm_load_acquire_W(p + k)` 等原子访问辅助的实参若是
指针结果的加减，按 C 的指针运算解释（单位是该加法节点类型的元素，`p + 2` 对 `uint32_t *p` 即 +8 字节，与 `ordering.py`
的构造一致），类型一致性检查不会把它改写成字节偏移。机器伪 C 另用 `flags.N = (x >> 31) & 1;` 等表示
NZCV 恢复。可读 C 中 `mrs xN, nzcv` 由标志来源还原成 `((uint64_t)(N 条件) << 31) | …`，来源未知的位写成
`unresolved_condition("mi"/"eq"/"hs"/"vs")`（见[源码重建](reconstruction.md)），不新增辅助名。
`mrs`/`msr tpidr2_el0` 的属性 `may_trap` 为真：该寄存器只在实现 FEAT_SME 时存在，SME 访问未启用时会陷入；
`msr` 写入现在同样带 `may_trap` 属性（新增字段，`tpidr_el0`/`fpcr`/`fpsr` 为假）。

## 保存格式

函数新增可选字段，旧结果和旧插件无需迁移：

| 字段 | 含义 |
| --- | --- |
| `microcode` | 按地址排序的指令语义记录 |
| `microcode_version` | 当前为 `1.0` |
| `microcode_complete` | 指令/控制流未截断且记录均受支持；不代表已恢复源代码 |
| `microcode_analysis` | 常量赋值、分支事实、类别统计与未支持地址 |

每条记录包含 `addr`、`size`、`mnemonic`、`architecture`、`category`、
`operations`、`reads`、`writes`、`flag_effect`、`memory_effect`、`supported`。
操作保留类型化 `inputs`、可选 `output`/`expression` 及 `attributes`；
表达式包含 `opcode`、`width`、`domain` 和可选操作数、常量或寄存器名。
部分寄存器写入另有目标宽度、存储宽度、位偏移和高位清零规则。

伪 C 的字段契约及 Ghidra 来源保留。新原生分析默认将源码重建文本保存于
`pseudoc`，机器文本保存于 `machine_pseudoc`，证据保存于
`pseudoc_reconstruction`。详见[源码重建说明](reconstruction.md)。微码随现有 JSON、项目与 SQLite 快照
保存，查询使用独立副本，修改查询返回值不会修改保存证据。旧结果缺少微码
时报告不可用，查询入口不会触发补分析。

## Python API

```python
from fangida.plugins.pseudoc.microcode import (
    Expression, constant, lift_function, analyze_microcode, simplify_expression,
)

# function_snapshot 中的 blocks/disassembly 必须来自已完成解码。
ir = lift_function(function_snapshot, "x86_64", max_instructions=512)
facts = analyze_microcode(ir["instructions"], max_steps=8192)

x = Expression("register", 32, name="x")
zero = simplify_expression(Expression("xor", 32, (x, x)))
assert zero == constant(0, 32)

# view 是已有 AnalysisView；查询只读取已保存的语义。
page = view.microcode(address, offset=0, limit=100, category="comparison")
branches = view.microcode_facts(address, kind="branch")
```

`lift_instruction(snapshot, architecture)` 提升单条记录。
`evaluate_expression` 在给定寄存器值下计算纯位向量表达式；无法确定、可能
触发未处理异常或依赖外部状态时抛出 `UnknownValue`。新增可选关键字参数 `division_semantics`（所在操作声明的
除法语义，见下文），不传时行为不变。

新增的可选操作属性（旧数据没有这些字段时按缺省处理，兼容不变）：

* `wide_outputs`（x86 单操作数 `mul`/`imul` 的 `multiply_wide`、`div`/`idiv` 的 `divide_wide`）：两个写回切片的列表，
  每项为 `{output, destination_width, storage_width, bit_offset, zero_upper, role}`——寄存器根、写入宽度、寄存器
  总宽度、位偏移（`ah` 为 8）、是否清零高位（64 位模式写 32 位寄存器）与角色（乘法 `low`/`high`，除法
  `quotient`/`remainder`）。可读 C 据此精确写回 rax/rdx（或 al/ah…）；缺少时可读层保持 `unresolved_operation`。
  `multiply_wide` 同时是 CF/OF 的标志来源（双/三操作数 `imul` 的 `flags_multiply` 同样），其余标志未定义。
* `division_semantics`（产生通用 `udiv`/`sdiv`/`urem`/`srem` 的操作）：`"arm_zero"` 表示 ARM 语义（除数为 0 商为 0、
  余数为被除数，最小负数 / -1 商为最小负数、余数为 0，不陷入），`"x86_fault"` 表示除数为 0 或带符号溢出时陷入
  （#DE，与不声明相同）；不认识的值按不声明处理。表达式 `name` 字段可逐节点声明同一取值，优先于操作级声明。
  `evaluate_expression`（关键字参数）、微码分析（同一操作的全部输入与条件表达式）与可读 C 渲染都按声明执行。
  目前内置 lifter 不产生带声明的通用除法（ARM 用专用 `arm_udiv`/`arm_sdiv`，x86 用 `divide_wide`），这是给自定义
  lifter（`register_lifter`）的接口。

`evaluate_condition` 返回 `True`、`False` 或 `None`，缺少标志位不是假条件。
`simplify_expression` 只在固定宽度下做可证明的纯整数化简，包括常量折叠、
异或抵消、`(x & y) + (x | y) = x + y` 等模整数恒等式。

`register_lifter(name, handler, first=False)` 提供针对性扩展。
处理器先输出指令快照，回调 `handler(context, row, operands, operand_access)`
再返回 `LiftedInstruction`；不匹配时返回 `None`。`context` 提供架构、位宽
及当前比较状态，`operand_access` 提供已有操作数的寄存器、地址及读写表示。
回调须明确寄存器/标志/内存效果，并在语义未知时返回不透明屏障；不得从此
入口调用解码器。`first=True` 可将针对混淆模式的实现放在通用处理之前；
同名重复注册会报错。`list_lifters()` 可查看已注册的大类处理器。

独立伪 C 提供者继续使用 `PseudocodePlugin` 和
`PluginManager.register_pseudocode` / `load_pseudocode`。其返回值
`PseudocodeResult` 的新 `microcode` 字段默认是空元组。

## MCP 与预算

| 工具 | 参数与作用 |
| --- | --- |
| `get_microcode` | `handle`、`address`，可选 `offset`/`limit`、`source`、`address_space`、`category` |
| `get_microcode_facts` | 同样的地址与分页参数，可选事实 `kind`，如 `branch` |
| `simplify_micro_expression` | 类型化 `expression` 对象，无需文件句柄，返回化简表达式 |

地址支持函数入口及已保存微码指令的内部地址；归档成员或地址空间冲突时
必须用过滤参数消除歧义。分页每次限制为 1–1000 条。

自动原生阶段最多处理 128 个函数、每函数 512 条微码。伪 C 每函数最多
32768 字符，总计 524288 字符；文本截断不会缩减独立微码的指令预算。
直接提升允许显式选择 1–8192 条指令，事实分析默认最多 8192 步，允许
显式选择 1–65536 步。预算或取消使生成停止，不增加解码/xref 的线程数。

`microcode_functions`、`microcode_instructions`、`microcode_budget_exhausted`
记录语义阶段工作量。分支事实的 `taken=None` 与 `proof="unknown"` 表示
尚未证明，不能据此删除分支；`microcode_complete=False` 表示保存证据不全
或存在未支持操作。

ARM64 补充：MOVZ/MOVN/MOVK 保留 16 位插入位置、W 写入清零高位及标志位
不变规则；LDUR/STUR 及字节、半字、符号扩展变体使用独立无回写访存语义；
ORN/BIC/EON 保留固定宽度取反；MOVI 的已覆盖全向量清零及 Q 寄存器
成对访存按 128 位位模式记录。这不表示已覆盖全部 SIMD 指令或浮点 ABI。

ARM64 literal 访存独立校验 PC/目标对齐及 signed imm19×4 范围，保留真实
内存读取，代码区地址不自动折叠为常量。S/D/Q 加载及成对访问按原始位模式
写入 128 位 V 寄存器；S/D 加载清零高位，存储仅提取低32/64位，不经过浮点
数值转换。寄存器索引地址以类型化 add/extend/shift 表达式区分 W/X、
UXTW/SXTW/SXTX 和合法缩放，防止读取 W 索引的未指定高32位。

`arm64_operands.py` 为整数大类提供可编码的移位和扩展操作数。ADD/SUB、
CMP/CMN 支持 shifted/extended register 与 imm12 LSL #0/#12；逻辑运算保留
LSL/LSR/ASR/ROR 及固定宽度反转，SMULL/UMULL、MADD/MSUB 保留乘数扩展
和模整数结果。零位移单独处理，避免生成按存储位宽移位的未定义 C 表达式。

SVC 使用独立 `system_transition`，保留 imm16、指令地址及异常 syndrome。
handler、平台 ABI、返回行为及寄存器/内存/标志效果均依赖执行环境，未知时
形成全状态分析屏障；不会默认套用 Linux syscall 或普通 AAPCS 调用规则。
