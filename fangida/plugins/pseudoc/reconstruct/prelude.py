"""可读伪 C 的前导（prelude）：辅助函数的定义与占位函数的声明。

可读伪 C（generate_pseudoc(..., style="readable")）只写函数本身；它用到的辅助运算（移位计数可能越界的
shl_32、循环移位 ror_64、ARM 除法 arm_sdiv_32、除数可能为 0 的 udiv_32、按通道运算 vec_add8_128、x86 串操作
x86_rep_stos64…）
与占位（unknown_value()、unresolved_operation("…")…）都集中在这里。``pseudoc_prelude()`` 返回固定的
前导文本；传入一次生成结果（或其 reconstruction 报告、流水线函数记录、按需生成的输出）时，另附该函数
引用的外部函数声明。前导 + 函数文本可以用 GNU C（GCC/Clang）以 C11 或更新标准编译。

三类名字：

* 辅助函数（有精确定义）：语义与微码 evaluate 完全一致，见 docs/reconstruction.md“可编译的伪 C”。
* 与机器相关的运算：PAC（pacia_64 等）只在实现 PAuth 的 AArch64 上以同一条指令定义（结果取决于当前
  进程的密钥与配置），其它平台只声明；__arm_rsr64/__arm_wsr64 在 AArch64 上来自 <arm_acle.h>。
* 占位函数：只声明、没有定义，表示重建未恢复的内容（未知值、未识别指令、未解析跳转…）；文本因此可以
  编译，但链接时缺少这些符号，不会被当作有语义的 C 运行。

本模块只生成文本，不访问输入文件；输出与 PYTHONHASHSEED 无关（名字一律排序后输出）。
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from functools import lru_cache

from ..microcode.lane_ops import LANE_OPCODES, PERMUTE_OPCODES

PRELUDE_VERSION = "1"

# 标量辅助函数覆盖的宽度（128 位需要 __uint128_t）。
_WIDTHS = (8, 16, 32, 64, 128)
# 可读 C 在移位计数可能越界、或循环移位的操作数不是简单值时调用的辅助函数（{运算}_{宽度}）。
SHIFT_HELPERS = ("shl", "lshr", "ashr", "rol", "ror")
# ARM 整数除法与取余（AArch64/AArch32 SDIV/UDIV 不陷入）：除数为 0 时商为 0，最小负数除以 -1 的商为最小负数；
# 取余按编译器的 udiv/sdiv + msub 序列 a - (a / b) * b：除数为 0 时余数为被除数，最小负数对 -1 取余为 0。
# arm_udiv/arm_sdiv 是 AArch64/AArch32 除法提升出的专用 opcode（32/64 位）；各宽度的 arm_* 也供声明了
# division_semantics="arm_zero" 的通用 udiv/sdiv/urem/srem 使用（8/16/32/64，128 位需要 __int128）。
DIVISION_HELPERS = ("arm_udiv", "arm_sdiv", "arm_urem", "arm_srem")
# x86 MUL/IMUL 的 CF/OF：W 位乘积是否超出 W 位（无符号 / 带符号），返回 bool（8/16/32/64）。
MULTIPLY_OVERFLOW_HELPERS = ("umul_overflow", "smul_overflow")
# 微码 udiv/urem/sdiv/srem（除数为 0 或带符号溢出时机器陷入，微码不定义结果）：除数不是可证明安全的常数时
# 可读 C 调用这些辅助函数（{运算}_{宽度}），陷入情形以 __builtin_trap() 陷入，不是 C 未定义行为。
TRAPPING_DIVISION_HELPERS = ("udiv", "urem", "sdiv", "srem")
# x86 DIV/IDIV 的宽除法辅助：2W 位被除数 hi:lo 除以 W 位除数，商与余数各 W 位（#DE 时 __builtin_trap()）。
X86_WIDE_DIVISION_HELPERS = ("x86_udiv_quo", "x86_udiv_rem", "x86_idiv_quo", "x86_idiv_rem")
# 浮点微码运算：结果取决于舍入模式与浮点异常状态（微码 evaluate 也不求值），只声明。
FLOAT_PLACEHOLDERS = ("fadd", "fsub", "fmul", "fdiv", "signed_to_float", "unsigned_to_float",
                      "float_to_signed", "float_to_unsigned", "float_resize")
# 按通道浮点占位（AArch64 向量 fadd/fsub/fmul/fdiv）：结果依赖 FPCR，只声明。名字为 vec_f{op}{lane}_{total}，
# lane 为通道位宽（32/64），total 为结果总宽度（64/128，由排列决定）。返回 total 位的位模式。
_FLOAT_VECTOR_LANES = {32: (64, 128), 64: (128,)}
FLOAT_VECTOR_PLACEHOLDERS = tuple(f"vec_f{op}{lane}_{total}"
                                  for op in ("add", "sub", "mul", "div")
                                  for lane, totals in _FLOAT_VECTOR_LANES.items() for total in totals)
# AArch64 带内存序的单寄存器访存（名字 → (C11 内存序, 是否为存储)，宽度 8/16/32/64）：ldar*/stlr* 是 RCsc 的
# 获取/释放（stlr 之后的 ldar 不能提前到它之前），C11 中只有 seq_cst 能表达这一点——C11 → AArch64 的标准
# 映射里 seq_cst 加载/存储正是 LDAR/STLR；ldapr*（RCpc，FEAT_LRCPC）是 C11 的 acquire 加载。
# 指针形参为 (const) volatile void *，按名字中的宽度访问。
ORDERED_ACCESS_HELPERS = {"arm_load_acquire": ("__ATOMIC_SEQ_CST", False),
                          "arm_load_acquire_pc": ("__ATOMIC_ACQUIRE", False),
                          "arm_store_release": ("__ATOMIC_SEQ_CST", True)}
_POINTER_AUTH = (("pacia", 2), ("pacib", 2), ("pacda", 2), ("pacdb", 2), ("autia", 2), ("autib", 2),
                 ("autda", 2), ("autdb", 2), ("xpaci", 1), ("xpacd", 1), ("pacga", 2))

# 占位函数：只声明（没有定义），名字 → 声明。参数个数可变的写作未指定形参。
PLACEHOLDERS = {
    "unknown_value": "uint64_t unknown_value(void);",
    "unknown_arguments": "uint64_t unknown_arguments(void);",
    "unresolved_operation": "void unresolved_operation(const char *mnemonic);",
    "unresolved_condition": "bool unresolved_condition(FANGIDA_ANY_ARGUMENTS);",
    "unresolved_fallthrough": "void unresolved_fallthrough(uint64_t address);",
    "unresolved_stack_address": "uint8_t *unresolved_stack_address(void);",
    "unresolved_control_flow": "void unresolved_control_flow(void);",
    "unresolved_result": "uint64_t unresolved_result(void);",
    "initialize_unknown_bytes": "void initialize_unknown_bytes(void *object, size_t size);",
    "handler_dependent_value": "uint64_t handler_dependent_value(uint64_t address, const char *register_name);",
    "unknown_return_upper8": "uint64_t unknown_return_upper8(uint8_t low);",
    "unknown_return_upper16": "uint64_t unknown_return_upper16(uint16_t low);",
    "unknown_return_upper32": "uint64_t unknown_return_upper32(uint32_t low);",
    "tail_transfer": "void tail_transfer(FANGIDA_ANY_ARGUMENTS);",
    "indirect_call": "uint64_t indirect_call(FANGIDA_ANY_ARGUMENTS);",
    "trap": "void trap(void);",
    "arm64_supervisor_call": "void arm64_supervisor_call(FANGIDA_ANY_ARGUMENTS);",
    "fangida_machine_state_region": "void fangida_machine_state_region(const char *region);",
}
# 前导中以宏给出的名字（不是函数声明）。
MACROS = frozenset({"__machine_state_region__", "isunordered", "FANGIDA_ANY_ARGUMENTS", "FANGIDA_HELPER"})


def _ctype(width):
    return "__uint128_t" if width == 128 else f"uint{width}_t"


def _stype(width):
    return "__int128_t" if width == 128 else f"int{width}_t"


def _ordered_access_helpers(width):
    """AArch64 获取/释放访存（见 ORDERED_ACCESS_HELPERS）：GCC/Clang 的 __atomic 内建按给定内存序原子访问。"""
    t, lines = _ctype(width), []
    for name, (order, store) in ORDERED_ACCESS_HELPERS.items():
        if store:
            lines.append(f"FANGIDA_HELPER void {name}_{width}(volatile void *p, {t} v) "
                         f"{{ __atomic_store_n((volatile {t} *)p, v, {order}); }}")
        else:
            lines.append(f"FANGIDA_HELPER {t} {name}_{width}(const volatile void *p) "
                         f"{{ return __atomic_load_n((const volatile {t} *)p, {order}); }}")
    return lines


def _scalar_helpers(width):
    """移位/循环移位辅助函数：计数为无符号数，>= 宽度时 shl/lshr 得 0、ashr 填符号位，循环移位按宽度取模。"""
    t, s, top = _ctype(width), _stype(width), width - 1
    return [
        f"FANGIDA_HELPER {t} shl_{width}({t} x, uint64_t n) {{ return n < {width} ? ({t})(x << n) : 0; }}",
        f"FANGIDA_HELPER {t} lshr_{width}({t} x, uint64_t n) {{ return n < {width} ? ({t})(x >> n) : 0; }}",
        f"FANGIDA_HELPER {t} ashr_{width}({t} x, uint64_t n) {{ return ({t})(({s})x >> (n < {width} ? n : {top})); }}",
        f"FANGIDA_HELPER {t} rol_{width}({t} x, uint64_t n) {{ n %= {width}; return n ? ({t})(x << n | x >> ({width} - n)) : x; }}",
        f"FANGIDA_HELPER {t} ror_{width}({t} x, uint64_t n) {{ n %= {width}; return n ? ({t})(x >> n | x << ({width} - n)) : x; }}",
    ]


def _trapping_division_helpers(width):
    """微码 udiv/urem/sdiv/srem：除数为 0、带符号最小负数除以 -1 时 __builtin_trap()（与机器陷入一致），其余按 C 计算。"""
    t, s = _ctype(width), _stype(width)
    overflow = f"(b == 0 || (a == ({t})1 << {width - 1} && b == ({t})-1))"
    return [
        f"FANGIDA_HELPER {t} udiv_{width}({t} a, {t} b) {{ if (b == 0) __builtin_trap(); return a / b; }}",
        f"FANGIDA_HELPER {t} urem_{width}({t} a, {t} b) {{ if (b == 0) __builtin_trap(); return a % b; }}",
        f"FANGIDA_HELPER {t} sdiv_{width}({t} a, {t} b) {{ if {overflow} __builtin_trap(); return ({t})(({s})a / ({s})b); }}",
        f"FANGIDA_HELPER {t} srem_{width}({t} a, {t} b) {{ if {overflow} __builtin_trap(); return ({t})(({s})a % ({s})b); }}",
    ]


def _x86_wide_division_helpers(width):
    """x86 DIV/IDIV：被除数为 hi:lo（2W 位），除以 W 位除数，得 W 位商与余数（商写 rax 系列、余数写 rdx 系列）。
    除数为 0 或商超出 W 位范围时机器触发 #DE，这里用 __builtin_trap() 精确表示（不是 C 未定义行为），与硬件逐位一致。"""
    t, s = _ctype(width), _stype(width)
    dt, ds = _ctype(2 * width), _stype(2 * width)
    umax = f"({dt})({t})-1"                              # 2W 位里 W 位无符号最大值
    smin, smax = f"(-(({ds})1 << {width - 1}))", f"((({ds})1 << {width - 1}) - 1)"
    dmin = f"(({dt})1 << {2 * width - 1})"               # 2W 位带符号最小负数的无符号位型（避免有符号溢出字面量）
    return [
        f"FANGIDA_HELPER {t} x86_udiv_quo_{width}({t} hi, {t} lo, {t} d) {{\n"
        f"    if (d == 0) __builtin_trap();\n"
        f"    {dt} n = ({dt})hi << {width} | lo;\n"
        f"    if (n / d > {umax}) __builtin_trap();\n"
        f"    return ({t})(n / d);\n}}",
        f"FANGIDA_HELPER {t} x86_udiv_rem_{width}({t} hi, {t} lo, {t} d) {{\n"
        f"    if (d == 0) __builtin_trap();\n"
        f"    {dt} n = ({dt})hi << {width} | lo;\n"
        f"    if (n / d > {umax}) __builtin_trap();\n"
        f"    return ({t})(n % d);\n}}",
        f"FANGIDA_HELPER {s} x86_idiv_quo_{width}({t} hi, {t} lo, {t} d) {{\n"
        f"    if (d == 0) __builtin_trap();\n"
        f"    {dt} nu = ({dt})hi << {width} | lo;\n"
        f"    {ds} dd = ({s})d;\n"
        f"    if (dd == -1 && nu == {dmin}) __builtin_trap();\n"
        f"    {ds} q = ({ds})nu / dd;\n"
        f"    if (q < {smin} || q > {smax}) __builtin_trap();\n"
        f"    return ({s})q;\n}}",
        f"FANGIDA_HELPER {s} x86_idiv_rem_{width}({t} hi, {t} lo, {t} d) {{\n"
        f"    if (d == 0) __builtin_trap();\n"
        f"    {dt} nu = ({dt})hi << {width} | lo;\n"
        f"    {ds} dd = ({s})d, n = ({ds})nu;\n"
        f"    if (dd == -1 && nu == {dmin}) __builtin_trap();\n"
        f"    {ds} q = n / dd;\n"
        f"    if (q < {smin} || q > {smax}) __builtin_trap();\n"
        f"    return ({s})(n % dd);\n}}",
    ]


def _arm_division_helpers(width):
    """ARM 语义的除法与取余（AArch64/AArch32 UDIV/SDIV 不陷入；供 arm_udiv/arm_sdiv 与声明了
    division_semantics="arm_zero" 的通用 udiv/sdiv/urem/srem 使用）：除数为 0 时商为 0；最小负数除以 -1 得最小负数。
    ARM 没有取余指令，取余是编译器生成的 udiv/sdiv + msub，即 a - (a / b) * b：除数为 0 时余数为被除数，
    最小负数对 -1 取余为 0。与微码 evaluate 的 ARM 除法边界一致。"""
    t, s = _ctype(width), _stype(width)
    smin = f"({t})(({t})1 << {width - 1})"
    return [
        f"FANGIDA_HELPER {t} arm_udiv_{width}({t} a, {t} b) {{ return b ? ({t})(a / b) : 0; }}",
        f"FANGIDA_HELPER {t} arm_sdiv_{width}({t} a, {t} b) {{\n"
        f"    if (b == 0) return 0;\n"
        f"    if (a == {smin} && b == ({t})-1) return a;\n"
        f"    return ({t})(({s})a / ({s})b);\n}}",
        f"FANGIDA_HELPER {t} arm_urem_{width}({t} a, {t} b) {{ return b ? ({t})(a % b) : a; }}",
        f"FANGIDA_HELPER {t} arm_srem_{width}({t} a, {t} b) {{\n"
        f"    if (b == 0) return a;\n"
        f"    if (a == {smin} && b == ({t})-1) return 0;\n"
        f"    return ({t})(({s})a % ({s})b);\n}}",
    ]


def _multiply_overflow_helpers(width):
    """x86 MUL/IMUL 的 CF/OF：W 位操作数的完整乘积超出 W 位（无符号：高半不为 0；带符号：不能表示为 W 位带符号数，
    即高半不等于低半的符号扩展）。其余标志（SF/ZF/AF/PF）机器未定义，可读 C 不还原。"""
    t, s = _ctype(width), _stype(width)
    return [
        f"FANGIDA_HELPER bool umul_overflow_{width}({t} a, {t} b) {{ {t} r; return __builtin_mul_overflow(a, b, &r); }}",
        f"FANGIDA_HELPER bool smul_overflow_{width}({t} a, {t} b) {{ {s} r; return __builtin_mul_overflow(({s})a, ({s})b, &r); }}",
    ]


# 按通道运算族的编号（与 C 中 fangida_lane_* 的 switch 分支一致）。
_LANE_BINARY = ("add", "sub", "mul", "cmeq", "cmhi", "cmhs", "cmgt", "cmge", "cmtst",
                "umax", "umin", "smax", "smin", "ushl", "sshl", "uqadd", "uqsub", "sqadd", "sqsub")
_LANE_UNARY = ("neg", "abs")
_LANE_SHIFTS = ("shl", "lshr", "ashr")
_LANE_REDUCTIONS = ("addv", "umaxv", "uminv", "smaxv", "sminv")

_LANE_CORE = r"""/* 按通道运算的公共实现：第 i 个 L 位通道占第 [i*L, (i+1)*L) 位（小端通道序），各通道互相独立。 */
FANGIDA_HELPER uint64_t fangida_lane_mask(unsigned lane) { return lane >= 64 ? UINT64_MAX : (UINT64_C(1) << lane) - 1; }
FANGIDA_HELPER uint64_t fangida_lane_get(__uint128_t v, unsigned lane, unsigned i) { return (uint64_t)(v >> (i * lane)) & fangida_lane_mask(lane); }
FANGIDA_HELPER __uint128_t fangida_lane_put(__uint128_t r, unsigned lane, unsigned i, uint64_t x) { return r | (__uint128_t)(x & fangida_lane_mask(lane)) << (i * lane); }
FANGIDA_HELPER int64_t fangida_lane_signed(uint64_t x, unsigned lane) {
    return lane < 64 && (x >> (lane - 1) & 1) ? (int64_t)(x | ~fangida_lane_mask(lane)) : (int64_t)x;
}
FANGIDA_HELPER uint64_t fangida_lane_binary(int op, unsigned lane, uint64_t x, uint64_t y) {
    uint64_t mask = fangida_lane_mask(lane);
    int64_t sx = fangida_lane_signed(x, lane), sy = fangida_lane_signed(y, lane);
    int amount;
    switch (op) {
    case 0: return x + y;                    /* add：模 2^L */
    case 1: return x - y;                    /* sub */
    case 2: return x * y;                    /* mul */
    case 3: return x == y ? mask : 0;        /* cmeq */
    case 4: return x > y ? mask : 0;         /* cmhi：无符号 > */
    case 5: return x >= y ? mask : 0;        /* cmhs：无符号 >= */
    case 6: return sx > sy ? mask : 0;       /* cmgt：带符号 > */
    case 7: return sx >= sy ? mask : 0;      /* cmge：带符号 >= */
    case 8: return (x & y) ? mask : 0;       /* cmtst */
    case 9: return x >= y ? x : y;           /* umax */
    case 10: return x <= y ? x : y;          /* umin */
    case 11: return sx >= sy ? x : y;        /* smax */
    case 12: return sx <= sy ? x : y;        /* smin */
    case 15: {                               /* uqadd：无符号饱和加，截到 [0, 2^L-1] */
        uint64_t s;
        if (__builtin_add_overflow(x, y, &s) || (lane < 64 && s > mask)) return mask;
        return s;
    }
    case 16: return x > y ? x - y : 0;       /* uqsub：无符号饱和减 */
    case 17: case 18: {                      /* sqadd(17)/sqsub(18)：带符号饱和加/减，截到 [-2^(L-1), 2^(L-1)-1] */
        __int128 e = op == 17 ? (__int128)sx + sy : (__int128)sx - sy;
        __int128 hi = ((__int128)1 << (lane - 1)) - 1, lo = -((__int128)1 << (lane - 1));
        if (e > hi) e = hi; else if (e < lo) e = lo;
        return (uint64_t)e & mask;
    }
    default:                                 /* ushl(13)/sshl(14)：移位量为 y 最低字节的带符号值 */
        amount = (int)(y & 0xff);
        if (amount >= 128) amount -= 256;
        if (amount >= 0) return amount < (int)lane ? x << amount : 0;
        amount = -amount;
        if (op == 13) return amount < (int)lane ? x >> amount : 0;
        return (uint64_t)(sx >> (amount < 64 ? amount : 63));
    }
}
/* 跨通道重排与饱和打包（参数与结果都是 128 位）。 */
FANGIDA_HELPER __uint128_t vec_pshufb8_128(__uint128_t a, __uint128_t b) {
    /* x86 PSHUFB：结果第 i 字节在控制字节 b[i] 最高位为 1 时为 0，否则取 a 的第 (b[i] & 15) 字节。 */
    __uint128_t r = 0;
    for (unsigned i = 0; i < 16; i++) {
        uint64_t c = fangida_lane_get(b, 8, i);
        r = fangida_lane_put(r, 8, i, (c & 0x80) ? 0 : fangida_lane_get(a, 8, (unsigned)(c & 15)));
    }
    return r;
}
FANGIDA_HELPER __uint128_t fangida_vec_pack(int unsigned_result, unsigned lane, __uint128_t a, __uint128_t b) {
    /* 把 a、b 的每个 lane 位通道（按带符号解释）饱和到 lane/2 位，结果低半为 a 的通道、高半为 b 的通道。 */
    unsigned half = lane / 2, per = 128 / lane;
    __int128 lo = unsigned_result ? 0 : -((__int128)1 << (half - 1));
    __int128 hi = unsigned_result ? ((__int128)1 << half) - 1 : ((__int128)1 << (half - 1)) - 1;
    __uint128_t r = 0;
    for (unsigned i = 0; i < per; i++) {
        __int128 va = fangida_lane_signed(fangida_lane_get(a, lane, i), lane);
        __int128 vb = fangida_lane_signed(fangida_lane_get(b, lane, i), lane);
        if (va < lo) va = lo; else if (va > hi) va = hi;
        if (vb < lo) vb = lo; else if (vb > hi) vb = hi;
        r = fangida_lane_put(r, half, i, (uint64_t)va);
        r = fangida_lane_put(r, half, per + i, (uint64_t)vb);
    }
    return r;
}
#define FANGIDA_PACK(name, unsigned_result, lane) FANGIDA_HELPER __uint128_t name(__uint128_t a, __uint128_t b) { return fangida_vec_pack(unsigned_result, lane, a, b); }
FANGIDA_HELPER __uint128_t fangida_vec_binary(int op, unsigned lane, unsigned width, __uint128_t a, __uint128_t b) {
    __uint128_t r = 0;
    for (unsigned i = 0; i < width / lane; i++)
        r = fangida_lane_put(r, lane, i, fangida_lane_binary(op, lane, fangida_lane_get(a, lane, i), fangida_lane_get(b, lane, i)));
    return r;
}
FANGIDA_HELPER __uint128_t fangida_vec_unary(int op, unsigned lane, unsigned width, __uint128_t a) {
    __uint128_t r = 0;
    for (unsigned i = 0; i < width / lane; i++) {
        uint64_t x = fangida_lane_get(a, lane, i);
        r = fangida_lane_put(r, lane, i, op == 0 || fangida_lane_signed(x, lane) < 0 ? 0 - x : x);  /* neg(0)/abs(1) */
    }
    return r;
}
/* 按标量计数移位：计数为无符号数；>= L 时 shl/lshr 得 0，ashr 填符号位。 */
FANGIDA_HELPER __uint128_t fangida_vec_shift(int op, unsigned lane, unsigned width, __uint128_t a, __uint128_t n) {
    __uint128_t r = 0;
    for (unsigned i = 0; i < width / lane; i++) {
        uint64_t x = fangida_lane_get(a, lane, i), z;
        if (op == 2)
            z = (uint64_t)(fangida_lane_signed(x, lane) >> (n < lane ? (unsigned)n : lane - 1));
        else
            z = n >= lane ? 0 : op == 0 ? x << (unsigned)n : x >> (unsigned)n;
        r = fangida_lane_put(r, lane, i, z);
    }
    return r;
}
/* 窄化：参数为 2W 位，每个 L 位通道截断为低 L/2 位，结果通道数不变。 */
FANGIDA_HELPER __uint128_t fangida_vec_narrow(unsigned lane, unsigned width, __uint128_t a) {
    __uint128_t r = 0;
    for (unsigned i = 0; i < 2 * width / lane; i++)
        r = fangida_lane_put(r, lane / 2, i, fangida_lane_get(a, lane, i));
    return r;
}
/* 扩展：参数为 W/2 位，每个 L 位通道零/符号扩展为 2L 位。 */
FANGIDA_HELPER __uint128_t fangida_vec_widen(int is_signed, unsigned lane, unsigned width, __uint128_t a) {
    __uint128_t r = 0;
    for (unsigned i = 0; i < width / 2 / lane; i++) {
        uint64_t x = fangida_lane_get(a, lane, i);
        r = fangida_lane_put(r, 2 * lane, i, is_signed ? (uint64_t)fangida_lane_signed(x, lane) : x);
    }
    return r;
}
/* 归约：参数宽度 bits 为 L 的整数倍（由实参类型的 sizeof 给出），结果为 L 位。 */
FANGIDA_HELPER uint64_t fangida_vec_reduce(int op, unsigned lane, unsigned bits, __uint128_t a) {
    uint64_t best = fangida_lane_get(a, lane, 0), sum = 0;
    for (unsigned i = 0; i < bits / lane; i++) {
        uint64_t x = fangida_lane_get(a, lane, i);
        int64_t sx = fangida_lane_signed(x, lane), sb = fangida_lane_signed(best, lane);
        sum += x;
        if ((op == 1 && x > best) || (op == 2 && x < best) || (op == 3 && sx > sb) || (op == 4 && sx < sb))
            best = x;
    }
    return (op == 0 ? sum : best) & fangida_lane_mask(lane);  /* addv(0)/umaxv/uminv/smaxv/sminv */
}
/* 符号位掩码：结果第 i 位为第 i 个通道的最高位（参数零扩展到 128 位不改变结果）。 */
FANGIDA_HELPER uint64_t fangida_vec_signmask(unsigned lane, __uint128_t a) {
    uint64_t r = 0;
    for (unsigned i = 0; i < 128 / lane; i++)
        r |= (fangida_lane_get(a, lane, i) >> (lane - 1) & 1) << i;
    return r;
}
/* 每个 vec_* 辅助函数的定义（名字、结果类型 T、运算编号、通道宽度 L、结果宽度 W）。 */
#define FANGIDA_LANE_BINARY(name, T, op, lane, width) FANGIDA_HELPER T name(T a, T b) { return (T)fangida_vec_binary(op, lane, width, a, b); }
#define FANGIDA_LANE_UNARY(name, T, op, lane, width) FANGIDA_HELPER T name(T a) { return (T)fangida_vec_unary(op, lane, width, a); }
#define FANGIDA_LANE_SHIFT(name, T, op, lane, width) FANGIDA_HELPER T name(T a, __uint128_t n) { return (T)fangida_vec_shift(op, lane, width, a, n); }
#define FANGIDA_LANE_NARROW(name, T, S, lane, width) FANGIDA_HELPER T name(S a) { return (T)fangida_vec_narrow(lane, width, a); }
#define FANGIDA_LANE_WIDEN(name, T, S, is_signed, lane, width) FANGIDA_HELPER T name(S a) { return (T)fangida_vec_widen(is_signed, lane, width, a); }
#define FANGIDA_LANE_SIGNMASK(name, T, lane) FANGIDA_HELPER T name(__uint128_t a) { return (T)fangida_vec_signmask(lane, a); }"""


def lane_helper_names():
    """前导中定义的全部按通道/重排辅助名（{opcode}_{W}），按名字排序。"""
    return tuple(sorted([name for name, _ in _lane_definitions()] + [name for name, _ in _permute_definitions()]))


def _permute_definitions():
    """(名字, C 定义) 列表：跨通道重排与饱和打包（结果均为 128 位）。vec_pshufb8_128 在 _LANE_CORE 中直接定义。"""
    items = [("vec_pshufb8_128", None)]
    for opcode, (family, operation, lane) in sorted(PERMUTE_OPCODES.items()):
        if family == "pack":
            name = f"{opcode}_128"
            items.append((name, f"FANGIDA_PACK({name}, {int(operation == 'us')}, {lane})"))
    return items


def _lane_definitions():
    """(名字, C 定义) 列表：opcode 族 × 合法的结果宽度 W（与 lane_ops.evaluate_lanes 的宽度约束一致）。"""
    items = []
    for opcode, (family, operation, lane) in sorted(LANE_OPCODES.items(), key=lambda item: (item[1][2], item[0])):
        if family in {"binary", "unary", "shift"}:
            for width in _WIDTHS:
                if width < lane or width % lane:
                    continue
                t = _ctype(width)
                name = f"{opcode}_{width}"
                if family == "binary":
                    code = _LANE_BINARY.index(operation)
                    body = f"FANGIDA_LANE_BINARY({name}, {t}, {code}, {lane}, {width})"
                elif family == "unary":
                    code = _LANE_UNARY.index(operation)
                    body = f"FANGIDA_LANE_UNARY({name}, {t}, {code}, {lane}, {width})"
                else:
                    code = _LANE_SHIFTS.index(operation)
                    body = f"FANGIDA_LANE_SHIFT({name}, {t}, {code}, {lane}, {width})"
                items.append((name, body))
        elif family == "narrow":
            for width in _WIDTHS:
                if width > 64 or (2 * width) % lane or width % (lane // 2):
                    continue
                t, source = _ctype(width), _ctype(2 * width)
                name = f"{opcode}_{width}"
                items.append((name, f"FANGIDA_LANE_NARROW({name}, {t}, {source}, {lane}, {width})"))
        elif family == "widen":
            for width in _WIDTHS:
                if width < 2 * lane or width % (2 * lane):
                    continue
                t, source = _ctype(width), _ctype(width // 2)
                name = f"{opcode}_{width}"
                signed = int(operation == "sext")
                items.append((name, f"FANGIDA_LANE_WIDEN({name}, {t}, {source}, {signed}, {lane}, {width})"))
        elif family == "reduce":
            # 参数可以是 64 或 128 位（AArch64 8B/16B…）：按实参类型的 sizeof 确定通道数，实参只求值一次。
            code = _LANE_REDUCTIONS.index(operation)
            name = f"{opcode}_{lane}"
            items.append((name, f"#define {name}(a) (({_ctype(lane)})fangida_vec_reduce({code}, {lane}, 8u * (unsigned)sizeof(a), (__uint128_t)(a)))"))
        else:  # signmask：结果宽度 W 不小于通道数
            for width in _WIDTHS:
                if width > 64:
                    continue
                t = _ctype(width)
                name = f"{opcode}_{width}"
                items.append((name, f"FANGIDA_LANE_SIGNMASK({name}, {t}, {lane})"))
    return items


def _pointer_auth():
    defined, declared = [], []
    for name, arity in _POINTER_AUTH:
        helper = f"{name}_64"
        if name == "pacga":
            defined.append(f"FANGIDA_HELPER uint64_t {helper}(uint64_t n, uint64_t m) {{ uint64_t r; __asm__(\"pacga %0, %1, %2\" : \"=r\"(r) : \"r\"(n), \"r\"(m)); return r; }}")
            declared.append(f"uint64_t {helper}(uint64_t n, uint64_t m);")
        elif arity == 1:
            defined.append(f"FANGIDA_HELPER uint64_t {helper}(uint64_t p) {{ __asm__(\"{name} %0\" : \"+r\"(p)); return p; }}")
            declared.append(f"uint64_t {helper}(uint64_t p);")
        else:
            # aut* 认证失败时可能陷入（FEAT_FPAC）：volatile，结果无人使用也不能删除。
            volatile = " volatile" if name.startswith("aut") else ""
            defined.append(f"FANGIDA_HELPER uint64_t {helper}(uint64_t p, uint64_t m) {{ __asm__{volatile}(\"{name} %0, %1\" : \"+r\"(p) : \"r\"(m)); return p; }}")
            declared.append(f"uint64_t {helper}(uint64_t p, uint64_t m);")
    return defined, declared


def _x86_strings():
    lines = []
    for width in (8, 16, 32, 64):
        size = width // 8
        lines.append(f"FANGIDA_HELPER void x86_rep_stos{width}(uint64_t d, uint64_t v, uint64_t n) {{\n"
                     f"    for (uint64_t i = 0; i < n; i++)\n"
                     f"        for (unsigned k = 0; k < {size}; k++) ((unsigned char *)(uintptr_t)(d + i * {size}))[k] = (unsigned char)(v >> (8 * k));\n"
                     "}")
        lines.append(f"FANGIDA_HELPER void x86_rep_movs{width}(uint64_t d, uint64_t s, uint64_t n) {{\n"
                     f"    for (uint64_t i = 0; i < n; i++) {{\n"
                     f"        unsigned char t[{size}];\n"
                     f"        for (unsigned k = 0; k < {size}; k++) t[k] = ((const unsigned char *)(uintptr_t)(s + i * {size}))[k];\n"
                     f"        for (unsigned k = 0; k < {size}; k++) ((unsigned char *)(uintptr_t)(d + i * {size}))[k] = t[k];\n"
                     "    }\n}")
    return lines


@lru_cache(maxsize=1)
def prelude_text():
    """完整的前导文本（固定内容，带包含保护，可以保存为头文件）。"""
    lines = [
        f"/* fangida 可读伪 C 前导（版本 {PRELUDE_VERSION}）：可读伪 C 用到的辅助函数（有精确定义，语义与微码一致）",
        " * 与占位函数（只声明、没有定义，表示重建未恢复的内容）。需要 GNU C（GCC/Clang）、C11 或更新标准；",
        " * 带符号转换与带符号右移按 GCC/Clang 的定义（模 2^N、算术右移）。 */",
        "#ifndef FANGIDA_PSEUDOC_PRELUDE",
        "#define FANGIDA_PSEUDOC_PRELUDE 1",
        "#include <stdbool.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "/* 辅助函数都是 static inline；未被使用时不告警。 */",
        "#if defined(__GNUC__) || defined(__clang__)",
        "#define FANGIDA_HELPER static inline __attribute__((unused))",
        "#else",
        "#define FANGIDA_HELPER static inline",
        "#endif",
        "/* 未指定形参：C11/C17 写作 T f()（调用时不检查实参），C23 起写作 T f(...)。 */",
        "#if defined(__STDC_VERSION__) && __STDC_VERSION__ > 201710L",
        "#define FANGIDA_ANY_ARGUMENTS ...",
        "#else",
        "#define FANGIDA_ANY_ARGUMENTS",
        "#endif",
        "",
        "/* ---- 移位与循环移位：计数为无符号数；>= 宽度时 shl/lshr 得 0、ashr 填符号位；循环移位按宽度取模。",
        " * 计数已证明小于宽度时，可读 C 直接写成 C 的 <<、>>（算术右移写成带符号类型的 >>），不调用这些函数。 */",
    ]
    for width in _WIDTHS:
        if width == 128:
            lines.append("#ifdef __SIZEOF_INT128__")
        lines.extend(_scalar_helpers(width))
        if width == 128:
            lines.append("FANGIDA_HELPER __uint128_t bswap_128(__uint128_t x) { return (__uint128_t)__builtin_bswap64((uint64_t)x) << 64 | __builtin_bswap64((uint64_t)(x >> 64)); }")
            lines.append("#endif")
    lines += [
        "",
        "/* ---- ARM 整数除法（SDIV/UDIV）：除数为 0 时结果为 0；最小负数除以 -1 得最小负数（不陷入）。",
        " * 取余（ARM 没有取余指令，编译器用 udiv/sdiv + msub）为 a - (a / b) * b：除数为 0 时得被除数、最小负数对 -1 得 0。",
        " * 微码 udiv/urem/sdiv/srem：除数是非零常数（带符号时也不是 -1）时可读 C 写成 C 的 / 与 %，否则调用",
        " * udiv_W/urem_W/sdiv_W/srem_W：除数为 0 或带符号溢出时机器陷入、微码不定义结果，这里以 __builtin_trap()",
        " * 陷入（不是 C 未定义行为）；提升器声明 division_semantics=\"arm_zero\" 时改用 arm_*_W（\"x86_fault\" 与不声明相同）。",
        " * x86 DIV/IDIV 是 2W÷W 的宽除法：提升为 divide_wide，可读 C 用下面的 x86_(u|i)div_quo/rem_W 精确还原。 */",
    ]
    for width in _WIDTHS:
        if width == 128:
            lines.append("#ifdef __SIZEOF_INT128__")
        lines.extend(_arm_division_helpers(width))
        if width == 128:
            lines.append("#endif")
    for width in _WIDTHS:
        if width == 128:
            lines.append("#ifdef __SIZEOF_INT128__")
        lines.extend(_trapping_division_helpers(width))
        if width == 128:
            lines.append("#endif")
    lines += [
        "",
        "/* ---- x86 DIV/IDIV（宽除法）：被除数 hi:lo 为 2W 位，商与余数各 W 位；除数为 0 或商溢出时触发 #DE，",
        " * 以 __builtin_trap() 精确表示。128 位被除数需要 __uint128_t，仅在支持时定义。 */",
    ]
    for width in (8, 16, 32):
        lines.extend(_x86_wide_division_helpers(width))
    lines.append("#ifdef __SIZEOF_INT128__")
    lines.extend(_x86_wide_division_helpers(64))
    lines.append("#endif")
    lines += [
        "",
        "/* ---- x86 MUL/IMUL 的 CF/OF（= 乘积超出 W 位：无符号 / 带符号）；SF/ZF/AF/PF 机器未定义，不提供。 */",
    ]
    for width in (8, 16, 32, 64):
        lines.extend(_multiply_overflow_helpers(width))
    lines += [
        "",
        "/* ---- AArch64 获取/释放访存：ldar、ldarb、ldarh 与 stlr、stlrb、stlrh（RCsc）写成 C11 seq_cst 原子加载/存储",
        " * （C11 → AArch64 的标准映射中 seq_cst 加载/存储正是 LDAR/STLR），ldapr、ldaprb、ldaprh（RCpc）写成 acquire",
        " * 加载；指针按名字中的宽度访问。 */",
    ]
    for width in (8, 16, 32, 64):
        lines.extend(_ordered_access_helpers(width))
    lines += [
        "",
        "/* ---- 浮点比较：isunordered 与 <math.h> 相同（不包含 <math.h>，避免与被重建的同名函数冲突）。 */",
        "#ifndef isunordered",
        "#define isunordered(a, b) __builtin_isunordered(a, b)",
        "#endif",
        "",
        "/* ---- 按通道 SIMD 整数运算 vec_{运算}{L}_{W}（L 为通道位宽，W 为结果宽度），语义见 docs/microcode.md。 */",
        "#ifdef __SIZEOF_INT128__",
        _LANE_CORE,
    ]
    lines.extend(body for _, body in _lane_definitions())
    lines.extend(body for _, body in _permute_definitions() if body is not None)
    lines += [
        "#endif",
        "",
        "/* ---- x86 rep stos/movs：从 d 起按元素升序写 n 个元素（小端字节序）；movs 逐个元素复制（不是 memmove）。 */",
        *_x86_strings(),
        "",
        "/* ---- AArch64 系统寄存器（ACLE）：AArch64 上来自 <arm_acle.h>，其它平台只声明。 */",
        "#if defined(__aarch64__) && defined(__has_include)",
        "#if __has_include(<arm_acle.h>)",
        "#include <arm_acle.h>",
        "#define FANGIDA_HAVE_ACLE 1",
        "#endif",
        "#endif",
        "#ifndef FANGIDA_HAVE_ACLE",
        "uint64_t __arm_rsr64(const char *name);",
        "void __arm_wsr64(const char *name, uint64_t value);",
        "#endif",
        "",
        "/* ---- 指针认证（PAC）：结果取决于密钥与 PAuth 配置，不能离线求值。实现 PAuth 的 AArch64 上执行同一条",
        " * 指令（使用当前进程的密钥），其它平台只声明。aut* 认证失败时陷入（FEAT_FPAC）或得到不可用的指针。 */",
        "#if defined(__aarch64__) && defined(__ARM_FEATURE_PAUTH) && (defined(__GNUC__) || defined(__clang__))",
    ]
    defined, declared = _pointer_auth()
    lines += defined + ["#else"] + declared + ["#endif", ""]
    lines += [
        "/* ---- 占位：只声明、没有定义（链接时缺少符号），表示重建未恢复的内容，不代表任何具体语义。 */",
        *(PLACEHOLDERS[name] for name in sorted(PLACEHOLDERS)),
        "#define __machine_state_region__(region) fangida_machine_state_region(#region)",
        "/* 浮点微码运算：结果取决于舍入模式与浮点异常状态，只声明。 */",
        *(f"uint64_t {name}_{width}(FANGIDA_ANY_ARGUMENTS);" for name in FLOAT_PLACEHOLDERS for width in (32, 64)),
        "/* 按通道浮点占位（向量 fadd/fsub/fmul/fdiv，fp_environment）：返回结果总宽度的位模式，只声明。 */",
        "#ifdef __SIZEOF_INT128__",
        *(f"__uint128_t {name}(FANGIDA_ANY_ARGUMENTS);" for name in FLOAT_VECTOR_PLACEHOLDERS if name.endswith("_128")),
        "#endif",
        *(f"uint64_t {name}(FANGIDA_ANY_ARGUMENTS);" for name in FLOAT_VECTOR_PLACEHOLDERS if name.endswith("_64")),
        "#endif /* FANGIDA_PSEUDOC_PRELUDE */",
        "",
    ]
    return "\n".join(lines)


@lru_cache(maxsize=1)
def prelude_names():
    """前导声明或定义的全部名字（函数与宏），供生成外部声明时排除。"""
    names = set(PLACEHOLDERS) | set(MACROS) | set(lane_helper_names())
    for width in _WIDTHS:
        names.update(f"{name}_{width}" for name in SHIFT_HELPERS)
    names.add("bswap_128")
    names.update(f"{name}_{width}" for name in DIVISION_HELPERS for width in _WIDTHS)
    names.update(f"{name}_{width}" for name in MULTIPLY_OVERFLOW_HELPERS for width in (8, 16, 32, 64))
    names.update(f"{name}_{width}" for name in ORDERED_ACCESS_HELPERS for width in (8, 16, 32, 64))
    names.update(f"{name}_{width}" for name in TRAPPING_DIVISION_HELPERS for width in _WIDTHS)
    names.update(f"{name}_{width}" for name in X86_WIDE_DIVISION_HELPERS for width in (8, 16, 32, 64))
    names.update(f"{name}_64" for name, _ in _POINTER_AUTH)
    names.update(f"x86_rep_{kind}{width}" for kind in ("stos", "movs") for width in (8, 16, 32, 64))
    names.update(f"{name}_{width}" for name in FLOAT_PLACEHOLDERS for width in (32, 64))
    names.update(FLOAT_VECTOR_PLACEHOLDERS)
    names.update({"__arm_rsr64", "__arm_wsr64"})
    return frozenset(names)


# ---------------------------------------------------------------------------
# 外部函数声明
# ---------------------------------------------------------------------------

def external_functions(values, own_name, calls, word_type):
    """可读文本引用、但前导与文本本身都没有声明的函数：[{name, return_type, parameters?, variadic?}]。

    values：最终输出的表达式（调用与以名字出现的函数地址）；own_name：被重建函数自己的名字（其定义就是
    声明）；calls：重建报告的调用证据（argument_evidence 为 known_prototype 的调用按库函数原型声明）。
    其余函数的形参未知，按调用处的返回类型声明为“未指定形参”。结果按名字排序，与哈希种子无关。
    """
    from .prototypes import lookup
    returns, referenced = {}, set()
    pending = list(values)
    while pending:
        value = pending.pop()
        if value.op == "call" and value.name:
            returns.setdefault(value.name, set()).add(value.ctype or word_type)
        elif value.op == "function" and value.name:
            referenced.add(value.name)
        pending.extend(value.args)
    evidence = {}
    for call in calls or ():
        if isinstance(call, Mapping) and isinstance(call.get("name"), str):
            evidence.setdefault(call["name"], set()).add(call.get("argument_evidence"))
    excluded = prelude_names() | {own_name}
    result = []
    for name in sorted((set(returns) | referenced) - excluded):
        prototype = lookup(name)
        kinds = evidence.get(name, set())
        if prototype is not None and kinds <= {"known_prototype"}:
            result.append({"name": name, "return_type": prototype.return_type,
                           "parameters": [{"name": parameter, "type": ctype} for parameter, ctype in prototype.parameters],
                           "variadic": prototype.variadic, "source": "known_prototype"})
            continue
        types = returns.get(name)
        # 同名调用的返回类型应当一致；不一致时取排序后的第一个（确定性）。仅以地址出现时没有返回值证据。
        return_type = sorted(types)[0] if types else "void"
        result.append({"name": name, "return_type": return_type, "parameters": None, "variadic": False,
                       "source": "call_site" if types else "address_only"})
    return result


def external_declaration(item):
    """一个外部函数的 C 声明文本。"""
    return_type = item.get("return_type") or "uint64_t"
    separator = "" if return_type.endswith("*") else " "
    parameters = item.get("parameters")
    if parameters is None:
        arguments = "FANGIDA_ANY_ARGUMENTS"
    else:
        arguments = ", ".join(f"{parameter['type']}{'' if parameter['type'].endswith('*') else ' '}{parameter['name']}"
                              for parameter in parameters) or ("" if item.get("variadic") else "void")
        if item.get("variadic"):
            arguments = arguments + ", ..." if arguments else "FANGIDA_ANY_ARGUMENTS"
    return f"{return_type}{separator}{item['name']}({arguments});"


_KEYWORDS = frozenset({"if", "while", "for", "switch", "return", "sizeof", "do", "else", "case", "goto", "break",
                       "continue", "default", "_Generic", "_Alignof", "_Static_assert"})
_COMMENTS = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
_LITERALS = re.compile(r"L?\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'")
_CALLED = re.compile(r"\b([A-Za-z_][A-Za-z_0-9]*)\s*\(")
_DEFINITION = re.compile(r"^[A-Za-z_][\w \t*]*?\b([A-Za-z_][A-Za-z_0-9]*)\s*\([^;{]*\)\s*\{", re.M)
# 可读伪 C 中出现的类型名（变量、参数、extern 全局与转换）；声明 = 类型名 + 可选的 * + 名字，后接 [ = ; , )。
_TYPE_NAME = (r"(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:void|char|wchar_t|short|int|long(?:\s+long)?|float|double|bool|"
              r"_Bool|u?int(?:8|16|32|64)_t|size_t|uintptr_t|__u?int128_t)")
_DECLARED = re.compile(r"\b" + _TYPE_NAME + r"(?:\s*\*)*\s*\b([A-Za-z_]\w*)\s*(?=[\[=;,)])")
_REFERENCED = re.compile(r"\b([A-Za-z_]\w*)\b(?!\s*\()")
_LABEL = re.compile(r"^\s*([A-Za-z_]\w*):(?!:)", re.M)
_GOTO = re.compile(r"\bgoto\s+([A-Za-z_]\w*)")
# __machine_state_region__(片段名) 的实参是片段名（宏转成字符串），不是 C 名字。
_MACHINE_REGION = re.compile(r"__machine_state_region__\s*\([^)]*\)")
_TYPE_WORDS = frozenset({"const", "unsigned", "signed", "void", "char", "wchar_t", "short", "int", "long", "float", "double",
                         "bool", "_Bool", "size_t", "uintptr_t", "__uint128_t", "__int128_t", "true", "false", "NULL",
                         "extern", "static", "volatile", "struct", "union", "enum", "register", "inline", "restrict"}
                        | {f"{sign}int{width}_t" for sign in ("u", "") for width in (8, 16, 32, 64)})


def _text_externals(text):
    """只有文本时（旧结果、没有报告）：从文本里找引用了但未定义的函数名，按库函数原型或未指定形参声明。

    以调用形式出现的名字按调用声明（不知道返回类型时写 uint64_t）；只以名字出现、又不是文本中声明的
    变量/参数/全局/标号的名字（作为实参传递的函数地址等）与报告的 address_only 相同，声明为 void 返回的
    未指定形参函数。返回类型只能从报告得到，因此传报告比只传文本更准确。
    """
    from .prototypes import lookup
    body = _MACHINE_REGION.sub("__machine_state_region__()", _LITERALS.sub('""', _COMMENTS.sub(" ", text)))
    defined = set(_DEFINITION.findall(body))
    # 编译器内建（__builtin_bswap32 等）不能重新声明。
    excluded = defined | _KEYWORDS | prelude_names()
    called = {name for name in set(_CALLED.findall(body)) - excluded if not name.startswith("__builtin_")}
    declared = set(_DECLARED.findall(body)) | set(_LABEL.findall(body)) | set(_GOTO.findall(body))
    addressed = {name for name in set(_REFERENCED.findall(body)) - excluded - declared - _TYPE_WORDS - called
                 if not name.startswith("__builtin_")}
    result = []
    for name in sorted(called | addressed):
        prototype = lookup(name)
        if prototype is not None:
            result.append({"name": name, "return_type": prototype.return_type,
                           "parameters": [{"name": parameter, "type": ctype} for parameter, ctype in prototype.parameters],
                           "variadic": prototype.variadic, "source": "known_prototype"})
        elif name in called:
            result.append({"name": name, "return_type": "uint64_t", "parameters": None, "variadic": False,
                           "source": "text"})
        else:
            result.append({"name": name, "return_type": "void", "parameters": None, "variadic": False,
                           "source": "address_only"})
    return result


def _externals_of(source):
    """从生成结果、报告、函数记录或文本中取外部函数列表；取不到时返回 None。"""
    if source is None:
        return None
    if isinstance(source, str):
        return _text_externals(source)
    report = getattr(source, "reconstruction", None)
    text = getattr(source, "pseudoc", None)
    if isinstance(source, Mapping):
        report = source.get("pseudoc_reconstruction", source.get("reconstruction"))
        if report is None and "external_functions" in source:
            report = source
        text = source.get("pseudoc")
    if isinstance(report, Mapping) and isinstance(report.get("external_functions"), list):
        return [item for item in report["external_functions"] if isinstance(item, Mapping) and isinstance(item.get("name"), str)]
    if isinstance(text, str):
        return _text_externals(text)
    raise TypeError("pseudoc_prelude source must be a pseudo-C result, reconstruction report, function record or text")


def pseudoc_prelude(source=None):
    """可读伪 C 的前导文本。

    source 为空时返回固定的前导（辅助函数定义与占位声明，可以保存为头文件）。source 可以是
    generate_pseudoc(..., style="readable") 的结果、其 reconstruction 报告、流水线函数记录或按需生成的
    输出（含 pseudoc_reconstruction），也可以是可读伪 C 文本本身：此时在前导之后附上该函数引用的外部
    函数声明（库函数按已知原型；其它按调用处的返回类型声明为未指定形参）。只传文本时调用处的返回类型
    无从得知，非库函数一律声明为返回 uint64_t（只以名字出现的函数地址声明为 void），因此优先传结果或报告。
    外部声明针对单个函数：把多个函数放进同一个编译单元时，其中被调函数的定义与这里的声明可能不一致。
    """
    text = prelude_text()
    externals = _externals_of(source)
    if not externals:
        return text
    lines = [text, "/* 本函数引用的外部函数 */"]
    lines.extend(external_declaration(item) for item in externals)
    return "\n".join(lines) + "\n"


__all__ = ["PRELUDE_VERSION", "pseudoc_prelude", "prelude_text", "prelude_names", "external_functions",
           "external_declaration", "lane_helper_names"]
