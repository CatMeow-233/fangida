"""第三轮提升（lifters3）新增形式的语义对照：真实编码、真实 CPU、微码逐条执行与可读 C（UBSan）三方一致。

覆盖的形式（每个用例都是 clang 汇编出的真实编码，由项目的 NativeDecoder（Capstone）解码后进入流水线）：

* x86 ``bt``/``bts``/``btr``/``btc``：寄存器形式（含 16/32/64 位、位索引取模）、立即数索引的内存形式（读改写只
  访问所给地址）；``bt`` 之后依赖 CF 的 ``jcc``/``setcc``/``cmovcc``；``xor eax, eax; bt; jcc`` 惯用法与栈槽上的
  ``bts``/``btc`` 经过常量特化后仍然正确（特化器不能按过期的标志或写入前的栈槽内容“证明”分支）；寄存器索引
  的内存形式保持不透明；位测试的操作数被推断为指针时可读 C 仍可编译。
* AArch64 ``extr``、``ldpsw``/``ldp``（含第一个目的与基址相同、后变址回写）、获取/释放访存
  ``ldar``/``ldarb``/``ldarh``/``ldapr``/``ldaprb``/``stlr``/``stlrb``/``stlrh``/``stlr wzr``（可读 C 写成前导的原子访问
  辅助）、``fcsel``（条件、两臂与高位清零）、``ccmp`` 之后的常量特化。
* AArch64 标量 SIMD 整数↔浮点转换、标量与向量浮点运算：可读 C 中写成 fp_environment 占位辅助；这里在测试
  程序里按默认 FPCR（就近舍入、不陷入）给出占位的参考定义，与真实 CPU 对照转换的有/无符号、按元素 ``fmul``
  的元素下标，以及写标量/64 位排列时 V 寄存器高位清零。

三方对照：可读 C（前导 + 生成的函数，开 UBSan，任何 C 未定义行为都会使测试失败）在本机编译运行；能编译运行
该架构的程序时（arm64 本机；x86-64 本机或 Apple Silicon 经 Rosetta 2）再与执行同一编码的真实 CPU 逐一对照
（返回值与内存缓冲区）；整数形式另与微码逐条执行（evaluate）对照。没有 C 编译器或 Capstone 时跳过对应部分。
"""
from __future__ import annotations

import functools
import importlib.util
import random
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from fangida.plugins.pseudoc import generate_pseudoc, pseudoc_prelude
from fangida.plugins.pseudoc.microcode import evaluate_expression, lift_function, lift_instruction
from fangida.plugins.pseudoc.microcode.conditions import evaluate_condition
from fangida.plugins.pseudoc.microcode.evaluate import integer_flags, logic_flags
from tests.test_lifter_system_simd import _toolchain
from tests.test_pseudoc_compilable import _Machine, _REGISTERS, _RETURN, _Unsupported, _syntax_check

_HAS_CAPSTONE = importlib.util.find_spec("capstone") is not None
_BASE = 0x1000
# 微码逐条执行时缓冲区的地址（与硬件上的实际地址无关：用例只按基址相对访问）。
_BUFFER = 0x10000000
# 缓冲区 256 字节，基址指向第 64 字节；比较 [-16, +48) 这 64 个字节（各用例只访问这一段）。
_BUFFER_SIZE, _BUFFER_BASE, _WINDOW = 256, 64, (48, 112)

# (名字, 编码, Capstone 解码文本, 选项)。选项："mem" 表示第一个实参是缓冲区指针；"fp" 表示含浮点占位
# （微码不能求值，只与真实 CPU 对照）；"compile" 表示只检查可读 C 能编译（执行会解引用任意地址）；
# "opaque" 表示应保持不透明；"no_microcode" 表示用到本测试的微码执行器未实现的操作（ccmp）。
_X86_CASES = [
    ("bt64_jae", "31c0480fa3f77304488d4701c3",
     ["xor eax, eax", "bt rdi, rsi", "jae 0x100c", "lea rax, [rdi + 1]", "ret"], ""),
    ("bt32_jb", "31c00fa3f77205b807000000c3",
     ["xor eax, eax", "bt edi, esi", "jb 0x100c", "mov eax, 7", "ret"], ""),
    ("bt_imm_setb", "480fbae7250f92c00fb6c0c3",
     ["bt rdi, 0x25", "setb al", "movzx eax, al", "ret"], ""),
    ("bts64", "4889f8480fabf00f92c20fb6d24831d0c3",
     ["mov rax, rdi", "bts rax, rsi", "setb dl", "movzx edx, dl", "xor rax, rdx", "ret"], ""),
    ("btr32", "89f80fb3f00f92c20fb6d248c1e2284809d0c3",
     ["mov eax, edi", "btr eax, esi", "setb dl", "movzx edx, dl", "shl rdx, 0x28", "or rax, rdx", "ret"], ""),
    ("btc16", "89f8660fbbf00f93c20fb6d248c1e2284809d0c3",
     ["mov eax, edi", "btc ax, si", "setae dl", "movzx edx, dl", "shl rdx, 0x28", "or rax, rdx", "ret"], ""),
    ("bts_imm_cmov", "4889f8480fbae83f480f42c6c3",
     ["mov rax, rdi", "bts rax, 0x3f", "cmovb rax, rsi", "ret"], ""),
    ("mem_bts", "0fba6f04030f92c00fb6c0c3",
     ["bts dword ptr [rdi + 4], 3", "setb al", "movzx eax, al", "ret"], "mem"),
    ("mem_btr", "480fba77083f0f93c00fb6c0c3",
     ["btr qword ptr [rdi + 8], 0x3f", "setae al", "movzx eax, al", "ret"], "mem"),
    ("mem_btc", "b801000000660fba7f02090f42c6c3",
     ["mov eax, 1", "btc word ptr [rdi + 2], 9", "cmovb eax, esi", "ret"], "mem"),
    ("mem_bt", "b8030000000fba27250f43c6c3",
     ["mov eax, 3", "bt dword ptr [rdi], 0x25", "cmovae eax, esi", "ret"], "mem"),
    ("stack_bts", "c74424f0000000000fba6c24f0038b4424f085c07405b809000000c3",
     ["mov dword ptr [rsp - 0x10], 0", "bts dword ptr [rsp - 0x10], 3", "mov eax, dword ptr [rsp - 0x10]",
      "test eax, eax", "je 0x101b", "mov eax, 9", "ret"], ""),
    ("stack_btc", "c74424f0080000000fba7c24f003837c24f0007506b805000000c3b806000000c3",
     ["mov dword ptr [rsp - 0x10], 8", "btc dword ptr [rsp - 0x10], 3", "cmp dword ptr [rsp - 0x10], 0",
      "jne 0x101b", "mov eax, 5", "ret", "mov eax, 6", "ret"], ""),
    ("mem_bt_reg_index", "0fa337c3", ["bt dword ptr [rdi], esi", "ret"], "opaque"),
    ("bt_ptr", "488b07480fa3f07303488b00c3",
     ["mov rax, qword ptr [rdi]", "bt rax, rsi", "jae 0x100c", "mov rax, qword ptr [rax]", "ret"], "compile"),
    ("bt_ptr_imm", "488b07488b08480fbae00372034889c8c3",
     ["mov rax, qword ptr [rdi]", "mov rcx, qword ptr [rax]", "bt rax, 3", "jb 0x1010", "mov rax, rcx", "ret"], "compile"),
]
_A64_CASES = [
    ("extr64", "0014c193c0035fd6", ["extr x0, x0, x1, #5", "ret"], ""),
    ("extr32", "007c8113c0035fd6", ["extr w0, w0, w1, #0x1f", "ret"], ""),
    ("extr64_63", "20fcc093c0035fd6", ["extr x0, x1, x0, #0x3f", "ret"], ""),
    ("extr32_0", "20008213c0035fd6", ["extr w0, w1, w2, #0", "ret"], ""),
    ("ldpsw", "020c41694004038bc0035fd6", ["ldpsw x2, x3, [x0, #8]", "add x0, x2, x3, lsl #1", "ret"], "mem"),
    ("ldpsw_alias", "00047f69000801cac0035fd6", ["ldpsw x0, x1, [x0, #-8]", "eor x0, x0, x1, lsl #2", "ret"], "mem"),
    ("ldpsw_post", "e50300aaa20cfd68a00000cb0000028b0010038bc0035fd6",
     ["mov x5, x0", "ldpsw x2, x3, [x5], #-0x18", "sub x0, x5, x0", "add x0, x0, x2", "add x0, x0, x3, lsl #4", "ret"], "mem"),
    ("ldp_alias", "008440a9000801cac0035fd6", ["ldp x0, x1, [x0, #8]", "eor x0, x0, x1, lsl #2", "ret"], "mem"),
    ("ldp_w_alias", "008440290008014ac0035fd6", ["ldp w0, w1, [x0, #4]", "eor w0, w0, w1, lsl #2", "ret"], "mem"),
    ("ldar", "01fcdf0802fcdf4803fcdf8804fcdfc82120028b2140038b200004cac0035fd6",
     ["ldarb w1, [x0]", "ldarh w2, [x0]", "ldar w3, [x0]", "ldar x4, [x0]", "add x1, x1, x2, lsl #8",
      "add x1, x1, x3, lsl #16", "eor x0, x1, x4", "ret"], "mem"),
    ("ldapr", "01c0bf3802c0bff82000028bc0035fd6", ["ldaprb w1, [x0]", "ldapr x2, [x0]", "add x0, x1, x2", "ret"], "mem"),
    ("stlr", "0320009162fc9f480440009181fc9f8805600091a2fc9fc801fc9f0806800091dffc9f88e00302aac0035fd6",
     ["add x3, x0, #8", "stlrh w2, [x3]", "add x4, x0, #0x10", "stlr w1, [x4]", "add x5, x0, #0x18", "stlr x2, [x5]",
      "stlrb w1, [x0]", "add x6, x0, #0x20", "stlr wzr, [x6]", "mov x0, x2", "ret"], "mem"),
    ("fcsel_d", "0000679e2100679e621c184e5f0003eb02bc611e4000669e413c184e000001cac0035fd6",
     ["fmov d0, x0", "fmov d1, x1", "mov v2.d[1], x3", "cmp x2, x3", "fcsel d2, d0, d1, lt", "fmov x0, d2",
      "mov x1, v2.d[1]", "eor x0, x0, x1", "ret"], ""),
    ("fcsel_s", "0000271e2100271e621c084e621c184e5f0003eb028c211e403c084e413c184e0034c1cac0035fd6",
     ["fmov s0, w0", "fmov s1, w1", "mov v2.d[0], x3", "mov v2.d[1], x3", "cmp x2, x3", "fcsel s2, s0, s1, hi",
      "mov x0, v2.d[0]", "mov x1, v2.d[1]", "eor x0, x0, x1, ror #13", "ret"], ""),
    ("ccmp_flags", "220080d25f0400f1200842fa61000054e00080d2c0035fd6200180d2c0035fd6",
     ["mov x2, #1", "cmp x2, #1", "ccmp x1, #2, #0, eq", "b.ne #0x1018", "mov x0, #7", "ret", "mov x0, #9", "ret"],
     "no_microcode"),
    ("scvtf_d", "0000679e601c184e00d8615e0000669e013c184e000001cac0035fd6",
     ["fmov d0, x0", "mov v0.d[1], x3", "scvtf d0, d0", "fmov x0, d0", "mov x1, v0.d[1]", "eor x0, x0, x1", "ret"], "fp"),
    ("ucvtf_d", "0000679e601c184e00d8617e0000669e013c184e000001cac0035fd6",
     ["fmov d0, x0", "mov v0.d[1], x3", "ucvtf d0, d0", "fmov x0, d0", "mov x1, v0.d[1]", "eor x0, x0, x1", "ret"], "fp"),
    ("scvtf_s", "0000271e00d8215e0000261ec0035fd6", ["fmov s0, w0", "scvtf s0, s0", "fmov w0, s0", "ret"], "fp"),
    ("ucvtf_gpr", "601c184e2000639e0000669e013c184e000001cac0035fd6",
     ["mov v0.d[1], x3", "ucvtf d0, x1", "fmov x0, d0", "mov x1, v0.d[1]", "eor x0, x0, x1", "ret"], "fp"),
    ("fcvtzs_d", "0000679e00b8e15e0000669ec0035fd6", ["fmov d0, x0", "fcvtzs d0, d0", "fmov x0, d0", "ret"], "fp"),
    ("fmul_elem_s", "0100679e211c184e4200679e621c184e2098a24f003c084e013c184e001cc1cac0035fd6",
     ["fmov d1, x0", "mov v1.d[1], x1", "fmov d2, x2", "mov v2.d[1], x3", "fmul v0.4s, v1.4s, v2.s[3]",
      "mov x0, v0.d[0]", "mov x1, v0.d[1]", "eor x0, x0, x1, ror #7", "ret"], "fp"),
    ("fmul_elem_s1", "0100679e211c184e4200679e621c184e2090a24f003c084e013c184e001cc1cac0035fd6",
     ["fmov d1, x0", "mov v1.d[1], x1", "fmov d2, x2", "mov v2.d[1], x3", "fmul v0.4s, v1.4s, v2.s[1]",
      "mov x0, v0.d[0]", "mov x1, v0.d[1]", "eor x0, x0, x1, ror #7", "ret"], "fp"),
    ("fmul_elem_d", "0100679e211c184e4200679e621c184e2098c24f003c084e013c184e001cc1cac0035fd6",
     ["fmov d1, x0", "mov v1.d[1], x1", "fmov d2, x2", "mov v2.d[1], x3", "fmul v0.2d, v1.2d, v2.d[1]",
      "mov x0, v0.d[0]", "mov x1, v0.d[1]", "eor x0, x0, x1, ror #7", "ret"], "fp"),
    ("fmul_elem_2s", "0100679e4200679e621c184e201c184e2098820f003c084e013c184e001cc1cac0035fd6",
     ["fmov d1, x0", "fmov d2, x2", "mov v2.d[1], x3", "mov v0.d[1], x1", "fmul v0.2s, v1.2s, v2.s[2]",
      "mov x0, v0.d[0]", "mov x1, v0.d[1]", "eor x0, x0, x1, ror #7", "ret"], "fp"),
    ("fadd_2s_upper", "0100679e2200679e601c184e20d4220e003c184ec0035fd6",
     ["fmov d1, x0", "fmov d2, x1", "mov v0.d[1], x3", "fadd v0.2s, v1.2s, v2.2s", "mov x0, v0.d[1]", "ret"], "fp"),
    ("fadd_d_upper", "0000679e2100679e621c184e0228611e403c184ec0035fd6",
     ["fmov d0, x0", "fmov d1, x1", "mov v2.d[1], x3", "fadd d2, d0, d1", "mov x0, v2.d[1]", "ret"], "fp"),
    ("fcvt_upper", "0100271e601c184e20c0221e003c184ec0035fd6",
     ["fmov s1, w0", "mov v0.d[1], x3", "fcvt d0, s1", "mov x0, v0.d[1]", "ret"], "fp"),
]
_CASES = {"x86_64": _X86_CASES, "arm64": _A64_CASES}

# 浮点占位在测试程序中的参考定义：按默认 FPCR（就近舍入、不陷入、非 flush-to-zero）计算，与 AArch64 指令语义
# 一致（fcvtzs：向零截断、NaN 得 0、越界饱和）。只用于对照，不属于前导（前导中它们只声明）。
_FP_REFERENCE = r"""
static uint64_t fangida_bits64(double d) { uint64_t b; __builtin_memcpy(&b, &d, 8); return b; }
static uint32_t fangida_bits32(float f) { uint32_t b; __builtin_memcpy(&b, &f, 4); return b; }
static double fangida_double(uint64_t b) { double d; __builtin_memcpy(&d, &b, 8); return d; }
static float fangida_float(uint32_t b) { float f; __builtin_memcpy(&f, &b, 4); return f; }
uint64_t signed_to_float_64(uint64_t x) { return fangida_bits64((double)(int64_t)x); }
uint64_t unsigned_to_float_64(uint64_t x) { return fangida_bits64((double)x); }
uint64_t signed_to_float_32(uint32_t x) { return fangida_bits32((float)(int32_t)x); }
uint64_t float_to_signed_64(uint64_t x) {
    double d = fangida_double(x);
    if (d != d) return 0;
    if (d >= 9223372036854775808.0) return (uint64_t)INT64_MAX;
    if (d < -9223372036854775808.0) return (uint64_t)INT64_MIN;
    return (uint64_t)(int64_t)d;
}
__uint128_t vec_fmul32_128(__uint128_t a, __uint128_t b) {
    __uint128_t r = 0;
    for (int i = 0; i < 4; i++)
        r |= (__uint128_t)fangida_bits32(fangida_float((uint32_t)(a >> (32 * i))) * fangida_float((uint32_t)(b >> (32 * i)))) << (32 * i);
    return r;
}
uint64_t vec_fmul32_64(__uint128_t a, __uint128_t b) { return (uint64_t)vec_fmul32_128(a, b); }
__uint128_t vec_fmul64_128(__uint128_t a, __uint128_t b) {
    __uint128_t r = 0;
    for (int i = 0; i < 2; i++)
        r |= (__uint128_t)fangida_bits64(fangida_double((uint64_t)(a >> (64 * i))) * fangida_double((uint64_t)(b >> (64 * i)))) << (64 * i);
    return r;
}
/* setcc 等部分写寄存器时高位取自未知的入口值（随后被 movzx 丢弃）：占位给一个固定值即可。 */
uint64_t unknown_value(void) { return 0x5a5a5a5a5a5a5a5aULL; }
/* 只检查高位清零的用例：结果低位不参与比较。 */
uint64_t vec_fadd32_64(__uint128_t a, __uint128_t b) { return (uint64_t)(a ^ b) | 1; }
uint64_t fadd_64(__uint128_t a, __uint128_t b) { return (uint64_t)(a + b) | 1; }
uint64_t float_resize_64(__uint128_t a) { return (uint64_t)a | 1; }
"""


def _rows(architecture, encoding):
    from fangida.processors.decoder import NativeDecoder
    rows, warnings = NativeDecoder(architecture).decode_bytes(bytes.fromhex(encoding), _BASE)
    if warnings:
        raise AssertionError(f"decode failed: {warnings}")
    for row in rows:
        if row["mnemonic"] == "ret":
            row["branch_info"] = {"kind": "return", "target": None, "conditional": False}
    return rows


def _text(row):
    return (row["mnemonic"] + " " + ", ".join(row["operands"])).strip()


def _function(architecture, name, encoding):
    rows = _rows(architecture, encoding)
    return {"name": name, "start": rows[0]["addr"], "blocks": [{"start": row["addr"], "instructions": [row]} for row in rows],
            "cfg": {"complete": True, "frontier": []}, "pseudoc_context": {"kind": "elf"}}


@functools.lru_cache(maxsize=None)
def _generated(architecture, name, encoding):
    function = _function(architecture, f"lx_{name}", encoding)
    return function, generate_pseudoc(function, architecture, style="readable")


def _float_bits(value, width):
    return struct.unpack("<I", struct.pack("<f", value))[0] if width == 32 else struct.unpack("<Q", struct.pack("<d", value))[0]


def _inputs(architecture, name, options):
    """每个用例的实参表 (a0, a1, a2, a3)；mem 用例的 a0 由缓冲区指针代替。"""
    rng = random.Random(f"{architecture}:{name}")
    edge = [0, 1, 0x7f, 0x80, 0xffff, 0x8000, 0x7fffffff, 0x80000000, 0xffffffff, 1 << 63, (1 << 64) - 1,
            0xdeadbeefcafebabe, 0x0123456789abcdef, 0x8000000000000001]
    if name.startswith(("bt", "bts", "btr", "btc")) and architecture == "x86_64":
        # 位索引：取模前后的边界（含超出宽度、32 位全 1、带符号最小值）。
        indices = [0, 1, 5, 15, 16, 31, 32, 33, 63, 64, 65, 127, 0xffffffff, 1 << 63, (1 << 64) - 1]
        return [(value, index, rng.getrandbits(64), rng.getrandbits(64)) for value in edge[::2] for index in indices]
    if name.startswith("fcsel") or name == "ccmp_flags":
        small = [0, 1, 2, 3, 5, 1 << 63, (1 << 64) - 1]
        return [(rng.getrandbits(64), rng.choice(small), left, right) for left in small for right in small]
    if name in {"scvtf_d", "ucvtf_d", "scvtf_s", "ucvtf_gpr"}:
        values = edge + [(1 << 53) + 1, (1 << 63) + 1025, (1 << 31) + 1, 0xfffffffffffff800] + [rng.getrandbits(64) for _ in range(24)]
        return [(value, value ^ 0x5555, rng.getrandbits(64), rng.getrandbits(64)) for value in values]
    if name == "fcvtzs_d":
        doubles = [0.0, -0.0, 0.5, -1.5, 2.0 ** 62, -(2.0 ** 63), 2.0 ** 63, 1e19, -1e19, 1e300, float("inf"), float("-inf"),
                   float("nan"), 123456789.75, -987654321.25, 5e-324]
        doubles += [rng.uniform(-1e18, 1e18) for _ in range(16)]
        return [(_float_bits(value, 64), 0, 0, 0) for value in doubles]
    if name.startswith("fmul_elem"):
        width = 64 if name.endswith("_d") else 32
        specials = [0.0, -0.0, 1.0, -2.5, 3.0e38 if width == 32 else 1.0e300, 1.0e-40 if width == 32 else 5e-324]

        def lanes():
            if width == 64:
                return _float_bits(rng.choice(specials + [rng.uniform(-1e6, 1e6)] * 3), 64)
            return _float_bits(rng.choice(specials + [rng.uniform(-1e6, 1e6)] * 3), 32) | (
                _float_bits(rng.choice(specials + [rng.uniform(-1e6, 1e6)] * 3), 32) << 32)
        return [(lanes(), lanes(), lanes(), lanes()) for _ in range(40)]
    if name.endswith("_upper"):
        return [(rng.getrandbits(64), rng.getrandbits(64), rng.getrandbits(64), rng.getrandbits(64) | 1) for _ in range(12)]
    values = edge + [rng.getrandbits(64) for _ in range(10)]
    return [(value, values[(index * 5 + 3) % len(values)], values[(index * 7 + 1) % len(values)], rng.getrandbits(64))
            for index, value in enumerate(values)]


def _buffer(seed):
    """缓冲区初值（与 C 程序中的初始化一致）：含 >= 0x80 的字节，使符号/零扩展的差别可见。"""
    return bytes((k * 37 + 11 + seed * 101) & 0xff for k in range(_BUFFER_SIZE))


def _signature(text, name):
    """可读 C 函数的返回类型与形参 [(类型, 实参序号)]。"""
    match = re.search(rf"^([A-Za-z_][\w \*]*?)\s*\b{name}\(([^)]*)\)\s*\{{", text, re.M)
    if match is None:
        raise AssertionError(text)
    parameters = []
    for item in match.group(2).split(","):
        item = item.strip()
        if item and item != "void":
            parameters.append((item[:item.rfind("arg_")].strip(), int(re.search(r"arg_(\d+)$", item).group(1)) - 1))
    return match.group(1).strip(), parameters


_RETURN_WIDTH = {"uint8_t": 8, "int8_t": 8, "uint16_t": 16, "int16_t": 16, "uint32_t": 32, "int32_t": 32}


def _return_mask(return_type):
    return (1 << _RETURN_WIDTH.get(return_type, 64)) - 1


# ---------------------------------------------------------------------------
# 微码逐条执行（参考）：在 tests.test_pseudoc_compilable 的执行器上加缓冲区、bit_test 与 bit_modify
# ---------------------------------------------------------------------------

class _BufferMachine(_Machine):
    def __init__(self, architecture, registers, buffer):
        super().__init__(architecture, registers)
        for index, byte in enumerate(buffer):
            self.memory[_BUFFER + index] = byte

    def _check(self, address, size):
        if _BUFFER <= address and address + size <= _BUFFER + _BUFFER_SIZE:
            return
        super()._check(address, size)


def _execute(records, entry, architecture, registers, buffer, max_steps=2000):
    """逐条执行微码到 return：返回 (返回寄存器的值, 缓冲区比较窗口的字节)。"""
    machine = _BufferMachine(architecture, registers, buffer)
    rows = {row["addr"]: (index, row) for index, row in enumerate(records)}
    pc = entry
    for _ in range(max_steps):
        index, row = rows[pc]
        if not row.get("supported"):
            raise _Unsupported("opaque")
        snapshot = dict(machine.registers)
        next_pc = records[index + 1]["addr"] if index + 1 < len(records) else pc + row["size"]
        handled = False
        for operation in row["operations"]:
            opcode, attributes, inputs = operation["opcode"], operation.get("attributes", {}), operation.get("inputs", ())
            if opcode == "assign":
                machine.write(operation, machine.evaluate(operation["expression"]))
            elif opcode == "store":
                machine.store(machine.evaluate(inputs[0]), machine.evaluate(inputs[1]), operation["width"])
            elif opcode == "bit_test":
                # x86 bt*：CF = 取模后的位；ZF 不变，OF/SF/AF/PF 未定义。
                handled = True
                value, bit = (machine.evaluate(item) for item in inputs)
                machine.flags = {"CF": bool(value >> bit & 1), "ZF": machine.flags.get("ZF")}
            elif opcode == "bit_modify":
                if operation.get("output"):
                    machine.write(operation, machine.evaluate(operation["expression"]))
                else:
                    machine.store(machine.evaluate(inputs[0]), machine.evaluate(inputs[1]), operation["width"])
            elif opcode == "address_writeback":
                address = machine.address(attributes["address"], snapshot)
                if attributes.get("mode") == "post_index":
                    address += int(str(attributes["offset"]).lstrip("#"), 0)
                machine.registers[operation["output"]] = address & machine.mask
            elif opcode == "compare":
                handled = True
                left, right = (machine.evaluate(item) for item in inputs)
                machine.flags = integer_flags(attributes["flag_family"], "sub", left, right, operation["width"])
            elif opcode in {"flags_add", "flags_sub", "flags_logic", "test"} and not attributes.get("carry"):
                handled = True
                values = [machine.evaluate(item) for item in inputs]
                family = attributes.get("family", attributes.get("flag_family", "x86"))
                if opcode in {"flags_logic", "test"}:
                    result = values[0] if opcode == "flags_logic" else values[0] & values[1]
                    machine.flags = logic_flags(family, result, operation["width"], previous=machine.flags)
                else:
                    machine.flags = integer_flags(family, "sub" if opcode == "flags_sub" else "add", values[0], values[1],
                                                  operation["width"])
            elif opcode.startswith("flags_"):
                handled = True
                machine.flags = {}
            elif opcode in {"select", "set_condition"}:
                taken = machine.condition(attributes["condition"])
                if opcode == "set_condition":
                    value = attributes.get("true_value", 1) if taken else 0
                else:
                    if attributes.get("false_operation") not in {None, "csel", "identity"}:
                        raise _Unsupported("conditional increment")
                    value = machine.evaluate(inputs[0 if taken else 1])
                machine.write(operation, value & ((1 << operation["width"]) - 1))
            elif opcode == "branch":
                if machine.condition(attributes["condition"]):
                    next_pc = attributes["target"]
                elif attributes.get("fallthrough") is not None:
                    next_pc = attributes["fallthrough"]
            elif opcode == "jump" and type(attributes.get("target")) is int:
                next_pc = attributes["target"]
            elif opcode == "return":
                window = bytes(machine.memory.get(_BUFFER + offset, 0) for offset in range(*_WINDOW))
                return machine.registers[_RETURN[architecture]], window
            elif opcode != "nop":
                raise _Unsupported(opcode)
        if row.get("flag_effect", "unknown") not in {"preserve", "partial_non_condition"} and not handled:
            machine.flags = {}
        pc = next_pc
    raise _Unsupported("step budget")


# ---------------------------------------------------------------------------
# C 程序：可读 C（+ 浮点占位的参考定义）与执行同一编码的汇编函数
# ---------------------------------------------------------------------------

def _hardware_function(architecture, name, encoding):
    blob = bytes.fromhex(encoding)
    if architecture == "arm64":
        body = "\\n".join(f".inst {int.from_bytes(blob[i:i + 4], 'little'):#010x}" for i in range(0, len(blob), 4))
        align = ".p2align 2"
    else:
        body = "\\n.byte " + ", ".join(f"{byte:#04x}" for byte in blob)
        align = ".p2align 4"
    return (f'__asm__(".text\\n{align}\\n.globl fangida_hw_{name}\\nfangida_hw_{name}:\\n{body}\\n");\n'
            f'extern uint64_t fangida_hw_{name}(uint64_t, uint64_t, uint64_t, uint64_t) __asm__("fangida_hw_{name}");')


def _program(architecture, cases, hardware):
    """cases: [(名字, 编码, 选项, 输出, 实参表)]。每次调用打印：名字 序号 硬件返回值 伪C返回值 硬件窗口 伪C窗口。"""
    parts = ["#include <stdio.h>", pseudoc_prelude(), _FP_REFERENCE]
    parts.extend(output.pseudoc for _, _, _, output, _ in cases)
    calls = []
    for name, encoding, options, output, inputs in cases:
        if hardware:
            parts.append(_hardware_function(architecture, name, encoding))
        return_type, parameters = _signature(output.pseudoc, f"lx_{name}")
        for index, values in enumerate(inputs):
            literals = [f"{value:#x}ULL" for value in values]
            pseudo_values, hardware_values = list(literals), list(literals)
            if "mem" in options:
                hardware_values[0] = "(uint64_t)(uintptr_t)(b1 + 64)"
                pseudo_values[0] = "(uint64_t)(uintptr_t)(b2 + 64)"
            arguments = ", ".join(f"({ctype})({pseudo_values[slot]})" for ctype, slot in parameters)
            pseudo_call = f"lx_{name}({arguments})"
            if return_type == "void":
                pseudo = f"{pseudo_call}; ps = 0;"
            else:
                pseudo = f"ps = (uint64_t)({pseudo_call});"
            run_hardware = f"hw = fangida_hw_{name}({', '.join(hardware_values)});" if hardware else "hw = 0;"
            calls.append(
                f"    {{ fill({index}); uint64_t hw, ps; {run_hardware} {pseudo}\n"
                f"      printf(\"{name} {index} %llx %llx \", (unsigned long long)hw, (unsigned long long)ps);"
                f" dump(b1); printf(\" \"); dump(b2); printf(\"\\n\"); }}")
    parts.append(f"static uint8_t b1[{_BUFFER_SIZE}] __attribute__((aligned(16))), b2[{_BUFFER_SIZE}] __attribute__((aligned(16)));\n"
                 f"static void fill(int seed) {{ for (int k = 0; k < {_BUFFER_SIZE}; k++)"
                 f" b1[k] = b2[k] = (uint8_t)(k * 37 + 11 + seed * 101); }}\n"
                 f"static void dump(const uint8_t *b) {{ for (int k = {_WINDOW[0]}; k < {_WINDOW[1]}; k++) printf(\"%02x\", b[k]); }}")
    parts.append("int main(void) {\n" + "\n".join(calls) + "\n    return 0;\n}\n")
    return "\n".join(parts)


@functools.lru_cache(maxsize=None)
def _sanitizer(architecture):
    """该架构的程序能否开 UBSan（-fsanitize=undefined，出现 C 未定义行为即失败）。"""
    toolchain = _toolchain(architecture)
    if toolchain is None:
        return ()
    compiler, flags, runner = toolchain
    sanitize = ("-fsanitize=undefined", "-fno-sanitize-recover=undefined")
    with tempfile.TemporaryDirectory() as tmp:
        source, binary = Path(tmp) / "p.c", Path(tmp) / "p"
        source.write_text("int main(int c, char **v) { (void)v; return c << 1 == 2 ? 0 : 1; }\n")
        built = subprocess.run([compiler, *flags, *sanitize, str(source), "-o", str(binary)], capture_output=True, text=True)
        if built.returncode or subprocess.run([*runner, str(binary)], capture_output=True).returncode:
            return ()
    return sanitize


def _compile_and_run(architecture, source):
    """architecture 为 None 时在本机编译运行（只含可读 C）；否则按该架构编译并执行（含汇编函数）。"""
    if architecture is None:
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("需要 C 编译器")
        flags, runner, sanitize = (), (), _sanitizer_native()
    else:
        toolchain = _toolchain(architecture)
        if toolchain is None:
            raise unittest.SkipTest(f"本机不能编译运行 {architecture} 程序")
        compiler, flags, runner = toolchain
        sanitize = _sanitizer(architecture)
    with tempfile.TemporaryDirectory() as tmp:
        path, binary = Path(tmp) / "check.c", Path(tmp) / "check"
        path.write_text(source)
        built = subprocess.run([compiler, *flags, "-std=gnu11", "-O1", "-w", *sanitize, str(path), "-o", str(binary)],
                               capture_output=True, text=True)
        if built.returncode:
            raise AssertionError(built.stderr[-4000:])
        ran = subprocess.run([*runner, str(binary)], capture_output=True, text=True, timeout=300)
        if ran.returncode:
            raise AssertionError(f"exit {ran.returncode}: {ran.stderr[-3000:]}")
        return ran.stdout.splitlines()


@functools.lru_cache(maxsize=None)
def _sanitizer_native():
    compiler = shutil.which("cc")
    if compiler is None:
        return ()
    sanitize = ("-fsanitize=undefined", "-fno-sanitize-recover=undefined")
    with tempfile.TemporaryDirectory() as tmp:
        source, binary = Path(tmp) / "p.c", Path(tmp) / "p"
        source.write_text("int main(void) { return 0; }\n")
        built = subprocess.run([compiler, *sanitize, str(source), "-o", str(binary)], capture_output=True, text=True)
        if built.returncode or subprocess.run([str(binary)], capture_output=True).returncode:
            return ()
    return sanitize


def _runnable(architecture, *, fp):
    """参与运行对照的用例（fp 为真时含浮点占位用例）：[(名字, 编码, 选项, 输出, 实参表)]。"""
    result = []
    for name, encoding, _, options in _CASES[architecture]:
        if options in {"compile", "opaque"} or ("fp" in options and not fp):
            continue
        _, output = _generated(architecture, name, encoding)
        result.append((name, encoding, options, output, _inputs(architecture, name, options)))
    return result


def _parse(lines):
    results = {}
    for line in lines:
        name, index, hw, ps, hw_window, ps_window = line.split()
        results[(name, int(index))] = (int(hw, 16), int(ps, 16), bytes.fromhex(hw_window), bytes.fromhex(ps_window))
    return results


@unittest.skipUnless(_HAS_CAPSTONE, "需要 Capstone")
class ExactFormDecodingTests(unittest.TestCase):
    def test_encodings_decode_to_the_recorded_text_and_lift(self):
        for architecture, cases in _CASES.items():
            for name, encoding, texts, options in cases:
                with self.subTest(architecture=architecture, name=name):
                    rows = _rows(architecture, encoding)
                    self.assertEqual([_text(row) for row in rows], texts)
                    supported = [lift_instruction(row, architecture)["supported"] for row in rows]
                    if options == "opaque":
                        # 寄存器索引的内存 bt 会按 idx/宽度 寻址到别的字：保持不透明。
                        self.assertFalse(supported[0])
                    else:
                        self.assertTrue(all(supported), list(zip(texts, supported)))

    def test_readable_c_has_no_unresolved_operation(self):
        for architecture, cases in _CASES.items():
            for name, encoding, _, options in cases:
                if options == "opaque":
                    continue
                with self.subTest(architecture=architecture, name=name):
                    _, output = _generated(architecture, name, encoding)
                    self.assertNotIn("unresolved_operation", output.pseudoc)
                    self.assertNotIn("unresolved_condition", output.pseudoc)
                    kinds = {item.get("kind") for item in output.reconstruction["unresolved"]}
                    if "fp" not in options:
                        # 整数形式都已精确还原（setcc 部分写入时被丢弃的入口高位记为 incoming_value，不影响结果）。
                        self.assertLessEqual(kinds, {"incoming_value"}, output.pseudoc)
                    else:
                        # 只因浮点占位而不完整的函数在头部写明原因，而不是“见 pseudoc_reconstruction”。
                        self.assertEqual(kinds, {"fp_environment_operation"}, output.pseudoc)
                        self.assertIn("处浮点运算依赖舍入/异常环境", output.pseudoc.splitlines()[0])


@unittest.skipUnless(_HAS_CAPSTONE, "需要 Capstone")
class ExactFormMicrocodeTests(unittest.TestCase):
    def test_fmul_by_element_broadcasts_the_selected_element(self):
        # 按元素 fmul：第二个实参是把 v2 的第 i 个元素精确广播到各通道的整数表达式，元素下标不能丢。
        v2 = int.from_bytes(bytes(range(0x10, 0x20)), "little")
        seen = set()
        for word, lane, index, total in ((0x4fa29820, 32, 3, 128), (0x4fa29020, 32, 1, 128), (0x4f829020, 32, 0, 128),
                                         (0x4fc29820, 64, 1, 128), (0x0f829820, 32, 2, 64)):
            row = _rows("arm64", struct.pack("<I", word).hex() + "c0035fd6")[0]
            operation = lift_instruction(row, "arm64")["operations"][0]
            with self.subTest(text=_text(row)):
                self.assertEqual(operation["opcode"], f"vec_fmul{lane}")
                left, right = operation["expression"]["args"]
                self.assertEqual(left, {"opcode": "register", "width": 128, "domain": "bitvector", "name": "v1"})
                element = (v2 >> (lane * index)) & ((1 << lane) - 1)
                expected = sum(element << (lane * k) for k in range(total // lane))
                self.assertEqual(evaluate_expression(right, {"v2": v2}), expected)
                seen.add(evaluate_expression(right, {"v2": v2}))
                self.assertEqual(operation["attributes"]["zero_upper"], total < 128)
        self.assertEqual(len(seen), 5)

    def test_ordered_accesses_keep_memory_order_and_render_atomically(self):
        expectations = {"ldarb": ("acquire", "seq_cst"), "ldarh": ("acquire", "seq_cst"), "ldar": ("acquire", "seq_cst"),
                        "ldaprb": ("acquire", "acquire"), "ldapr": ("acquire", "acquire"), "stlrh": ("release", "seq_cst"),
                        "stlr": ("release", "seq_cst"), "stlrb": ("release", "seq_cst")}
        for name in ("ldar", "ldapr", "stlr"):
            encoding = next(item[1] for item in _A64_CASES if item[0] == name)
            for row in _rows("arm64", encoding):
                if row["mnemonic"] not in expectations:
                    continue
                operation = next(item for item in lift_instruction(row, "arm64")["operations"]
                                 if item["opcode"] in {"assign", "store"})
                with self.subTest(text=_text(row)):
                    if operation["opcode"] == "store":
                        # 存储的值与访问同宽（stlrb/stlrh 只写低 8/16 位）。
                        self.assertEqual(operation["inputs"][1]["width"], operation["width"])
                    order, c11 = expectations[row["mnemonic"]]
                    self.assertEqual(operation["attributes"]["memory_order"], order)
                    self.assertEqual(operation["attributes"]["c11_memory_order"], c11)
        texts = {name: _generated("arm64", name, next(item[1] for item in _A64_CASES if item[0] == name))[1].pseudoc
                 for name in ("ldar", "ldapr", "stlr")}
        for helper in ("arm_load_acquire_8(", "arm_load_acquire_16(", "arm_load_acquire_32(", "arm_load_acquire_64("):
            self.assertIn(helper, texts["ldar"])
        for helper in ("arm_load_acquire_pc_8(", "arm_load_acquire_pc_64("):
            self.assertIn(helper, texts["ldapr"])
        for helper in ("arm_store_release_8(", "arm_store_release_16(", "arm_store_release_32(", "arm_store_release_64("):
            self.assertIn(helper, texts["stlr"])
        # 不再是普通的非原子读写（编译器可以把它提出循环）。
        self.assertNotRegex(texts["ldar"], r"=\s*(?:\*\(uint\d+_t \*\)|arg_1\[)")
        self.assertNotRegex(texts["stlr"], r"\barg_1\[\d+\]\s*=|\*\(uint\d+_t \*\)\([^;]*\)\s*=")
        prelude = pseudoc_prelude()
        self.assertIn("__atomic_load_n((const volatile uint8_t *)p, __ATOMIC_SEQ_CST)", prelude)
        self.assertIn("__atomic_load_n((const volatile uint64_t *)p, __ATOMIC_ACQUIRE)", prelude)
        self.assertIn("__atomic_store_n((volatile uint32_t *)p, v, __ATOMIC_SEQ_CST)", prelude)

    def test_spin_wait_on_load_acquire_is_not_a_plain_load(self):
        # 1: ldarb w8, [x0]; cbz w8, 1b; mov w0, w8; ret —— 普通读写会被编译器提出循环（死循环）。
        output = generate_pseudoc(_function("arm64", "spin", "08fcdf08e8ffff34e003082ac0035fd6"), "arm64", style="readable")
        self.assertIn("arm_load_acquire_8(", output.pseudoc)
        self.assertTrue(output.reconstruction["complete"], output.pseudoc)

    def test_specializer_drops_flags_written_by_unmodelled_operations(self):
        # xor eax, eax（CF=0）; rcl rcx, 1（CF = rdi 的最高位，特化器不求值 rotate_carry）; jb：不能按过期的 CF=0
        # “证明”分支不跳转（修复前可读 C 为恒定的 return 7）。条件无法还原时保持 unresolved_condition。
        rows = _rows("x86_64", "31c04889f948d1d17205b807000000c3")
        self.assertEqual([_text(row) for row in rows][2:4], ["rcl rcx, 1", "jb 0x100f"])
        output = generate_pseudoc(_function("x86_64", "rcl_flags", "31c04889f948d1d17205b807000000c3"), "x86_64",
                                  style="readable")
        self.assertIn('unresolved_condition("b")', output.pseudoc)
        self.assertNotRegex(output.pseudoc, r"\{\s*unresolved_operation\(\"rcl\"\);\s*return 7;\s*\}")
        self.assertFalse(output.reconstruction.get("specialization", {}).get("applied", False))

    def test_ordered_access_to_escaped_stack_slot_is_not_claimed_complete(self):
        # 栈槽地址传给了外部函数（可能被别的线程访问）：可读 C 仍写普通读写，但记 memory_order 未解析项，
        # 函数头写明原因；地址未外泄的私有栈槽写普通读写就是精确的（见 test_x86/a64_forms_* 的栈槽用例）。
        encoding = "ff8300d1fd7b01a9e003009100080094e0ffdf88e123009120fc9f88e00b40b9fd7b41a9ff830091c0035fd6"
        rows = _rows("arm64", encoding)
        self.assertEqual([_text(row) for row in rows][3:7], ["bl #0x300c", "ldar w0, [sp]", "add x1, sp, #8", "stlr w0, [x1]"])
        output = generate_pseudoc(_function("arm64", "escaped", encoding), "arm64", style="readable")
        orders = [item for item in output.reconstruction["unresolved"] if item.get("kind") == "memory_order"]
        self.assertEqual([(item["address"], item["mnemonic"]) for item in orders], [(0x1010, "ldar"), (0x1018, "stlr")])
        self.assertFalse(output.reconstruction["complete"])
        self.assertIn("2 处带内存序的栈槽访问写成普通读写", output.pseudoc.splitlines()[0])

    def test_scalar_and_64_bit_simd_writes_zero_the_upper_bits(self):
        # AArch64 写 sN/dN 或 64 位排列时硬件把 V 寄存器 [127:W] 清零：微码属性必须是 zero_upper。
        for text, encoding, width in (("fcsel d2, d0, d1, lt", "02bc611e", 64), ("fcsel s2, s0, s1, hi", "028c211e", 32),
                                      ("fadd d2, d0, d1", "0228611e", 64), ("scvtf d0, d0", "00d8615e", 64),
                                      ("ucvtf d0, x1", "2000639e", 64), ("fcvt d0, s1", "20c0221e", 64),
                                      ("fcvtzs d0, d0", "00b8e15e", 64), ("fadd v0.2s, v1.2s, v2.2s", "20d4220e", 64)):
            row = _rows("arm64", encoding + "c0035fd6")[0]
            operation = lift_instruction(row, "arm64")["operations"][0]
            with self.subTest(text=text):
                self.assertEqual(_text(row), text)
                attributes = operation["attributes"]
                self.assertTrue(attributes["zero_upper"], attributes)
                self.assertEqual((attributes["destination_width"], attributes["storage_width"], attributes["bit_offset"]),
                                 (width, 128, 0))

    def test_bit_test_on_inferred_pointer_compiles(self):
        # 位测试的操作数被推断为指针时，移位前先转为整数（否则是 (T *)p >> n 这样不合法的 C）。
        for name, encoding, _, options in _X86_CASES:
            if options != "compile":
                continue
            with self.subTest(name=name):
                _, output = _generated("x86_64", name, encoding)
                self.assertRegex(output.pseudoc, r"\(uint64_t\)\w+ >> ")
                _syntax_check(pseudoc_prelude(output) + "\n" + output.pseudoc + "\n", "-Werror=int-conversion")


@unittest.skipUnless(_HAS_CAPSTONE, "需要 Capstone")
class ExactFormExecutionTests(unittest.TestCase):
    def _microcode(self, architecture, name, encoding, options, inputs):
        function, _ = _generated(architecture, name, encoding)
        records = lift_function(function, architecture)["instructions"]
        results = []
        for index, values in enumerate(inputs):
            # 其余通用寄存器的入口值不影响结果（各用例在读取前先写，或只用到被写的低位）：取 0。
            registers = {root: 0 for root in _REGISTERS[architecture]}
            names = ("rdi", "rsi", "rdx", "rcx") if architecture == "x86_64" else ("x0", "x1", "x2", "x3")
            for register, value in zip(names, values):
                registers[register] = value
            if "mem" in options:
                registers[names[0]] = _BUFFER + _BUFFER_BASE
            registers.update({f"v{k}": 0 for k in range(32)} if architecture == "arm64" else {})
            buffer = bytes((k * 37 + 11 + index * 101) & 0xff for k in range(_BUFFER_SIZE))
            results.append(_execute(records, function["start"], architecture, registers, buffer))
        return results

    def _check(self, architecture, hardware):
        cases = _runnable(architecture, fp=hardware)
        if not hardware:
            source = _program(architecture, cases, False)
            results = _parse(_compile_and_run(None, source))
        else:
            source = _program(architecture, cases, True)
            results = _parse(_compile_and_run(architecture, source))
        mismatches = []
        for name, encoding, options, output, inputs in cases:
            mask = _return_mask(_signature(output.pseudoc, f"lx_{name}")[0])
            reference = None
            if "fp" not in options and "no_microcode" not in options:
                reference = self._microcode(architecture, name, encoding, options, inputs)
            for index, values in enumerate(inputs):
                hw, ps, hw_window, ps_window = results[(name, index)]
                observed = (ps & mask, ps_window)
                if hardware and observed != (hw & mask, hw_window):
                    mismatches.append((name, [hex(v) for v in values], "hardware", hex(hw & mask), hex(ps & mask),
                                       hw_window == ps_window))
                if reference is not None:
                    value, window = reference[index]
                    if observed != (value & mask, window):
                        mismatches.append((name, [hex(v) for v in values], "microcode", hex(value & mask), hex(ps & mask),
                                           window == ps_window))
        self.assertEqual(mismatches[:10], [], f"共 {len(mismatches)} 处不一致")

    def test_x86_forms_match_microcode(self):
        # 可读 C（本机编译，UBSan）与微码逐条执行逐一相同；不需要 x86 硬件。
        self._check("x86_64", hardware=False)

    def test_a64_forms_match_microcode(self):
        self._check("arm64", hardware=False)

    def test_x86_forms_match_hardware(self):
        # 真实 CPU（x86-64 本机或 Rosetta 2）执行同一编码；同时与微码对照。
        self._check("x86_64", hardware=True)

    def test_a64_forms_match_hardware(self):
        # 真实 CPU（AArch64）执行同一编码；浮点占位按默认 FPCR 的参考定义参与对照。
        self._check("arm64", hardware=True)


if __name__ == "__main__":
    unittest.main()
