"""微码层新增精确语义：AArch64 系统寄存器与指针认证、按通道 SIMD 整数运算、x86 串操作。

* 每条指令都用 Capstone 解码真实编码（编码由 clang 汇编得到并固定在表中），先核对解码文本，
  再检查读写集与操作形态；
* 按通道运算在边界值（0、全 1、符号位、各通道溢出、移位量正负边界）与随机值上，用
  evaluate_expression 与独立按 ARM/Intel 伪代码写成的 Python 参考实现逐一比对；
* 本机能执行对应架构时（arm64 原生；x86_64 原生或经 Rosetta），把同一编码嵌入 C 程序在硬件上
  执行，结果必须与求值逐位相同（未写的寄存器保持不变）；
* mrs/msr nzcv 往返保持标志；PAC 指令不再清空无关寄存器状态；不支持的形式仍为 opaque。
"""
from __future__ import annotations

import functools
import importlib.util
import os
import platform
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.microcode import (UnknownValue, analyze_microcode, evaluate_expression, lift_function,
                                              lift_instruction)
from fangida.plugins.pseudoc.microcode.ir import Expression
from tests.test_pseudoc import function as fn, instruction as ins
from tests.test_reconstruction import compile_run

_HAS_CAPSTONE = importlib.util.find_spec("capstone") is not None
_HOST = platform.machine().lower()
_MASK128 = (1 << 128) - 1
_ROOT = Path(__file__).resolve().parents[1]

# 编码由 clang -arch arm64 / -arch x86_64 汇编得到；测试先核对 Capstone 解码文本与表中文本一致。
_A64_LANES = [
    ("add v0.16b, v1.16b, v2.16b", 0x4e228420), ("add v0.8h, v1.8h, v2.8h", 0x4e628420),
    ("add v0.4s, v1.4s, v2.4s", 0x4ea28420), ("add v0.2d, v1.2d, v2.2d", 0x4ee28420),
    ("add v0.8b, v1.8b, v2.8b", 0x0e228420), ("add v0.4h, v1.4h, v2.4h", 0x0e628420),
    ("add v0.2s, v1.2s, v2.2s", 0x0ea28420), ("add d0, d1, d2", 0x5ee28420),
    ("sub v0.16b, v1.16b, v2.16b", 0x6e228420), ("sub v0.4s, v1.4s, v2.4s", 0x6ea28420),
    ("sub v0.2d, v1.2d, v2.2d", 0x6ee28420), ("sub v0.4h, v1.4h, v2.4h", 0x2e628420), ("sub d0, d1, d2", 0x7ee28420),
    ("mul v0.16b, v1.16b, v2.16b", 0x4e229c20), ("mul v0.8h, v1.8h, v2.8h", 0x4e629c20),
    ("mul v0.4s, v1.4s, v2.4s", 0x4ea29c20), ("mul v0.2s, v1.2s, v2.2s", 0x0ea29c20),
    ("cmeq v0.16b, v1.16b, v2.16b", 0x6e228c20), ("cmeq v0.2d, v1.2d, v2.2d", 0x6ee28c20),
    ("cmhi v0.2d, v1.2d, v2.2d", 0x6ee23420), ("cmhi v0.4s, v1.4s, v2.4s", 0x6ea23420),
    ("cmhi v0.8h, v1.8h, v2.8h", 0x6e623420), ("cmhi v0.16b, v1.16b, v2.16b", 0x6e223420),
    ("cmhi v0.2s, v1.2s, v2.2s", 0x2ea23420), ("cmhs v0.2d, v1.2d, v2.2d", 0x6ee23c20),
    ("cmhs v0.8b, v1.8b, v2.8b", 0x2e223c20), ("cmgt v0.4s, v1.4s, v2.4s", 0x4ea23420),
    ("cmgt v0.2d, v1.2d, v2.2d", 0x4ee23420), ("cmge v0.8h, v1.8h, v2.8h", 0x4e623c20),
    ("cmtst v0.4s, v1.4s, v2.4s", 0x4ea28c20), ("cmtst v0.16b, v1.16b, v2.16b", 0x4e228c20),
    ("cmeq d0, d1, d2", 0x7ee28c20), ("cmhi d0, d1, d2", 0x7ee23420), ("cmgt d0, d1, d2", 0x5ee23420),
    ("cmeq v0.4s, v1.4s, #0", 0x4ea09820), ("cmge v0.2d, v1.2d, #0", 0x6ee08820),
    ("cmgt v0.8b, v1.8b, #0", 0x0e208820), ("cmle v0.8h, v1.8h, #0", 0x6e609820),
    ("cmlt v0.16b, v1.16b, #0", 0x4e20a820), ("cmlt d0, d1, #0", 0x5ee0a820), ("cmeq d0, d1, #0", 0x5ee09820),
    ("umax v0.16b, v1.16b, v2.16b", 0x6e226420), ("umin v0.8h, v1.8h, v2.8h", 0x6e626c20),
    ("smax v0.4s, v1.4s, v2.4s", 0x4ea26420), ("smin v0.2s, v1.2s, v2.2s", 0x0ea26c20),
    ("ushl v0.8h, v1.8h, v2.8h", 0x6e624420), ("ushl v0.16b, v1.16b, v2.16b", 0x6e224420),
    ("ushl v0.4s, v1.4s, v2.4s", 0x6ea24420), ("ushl v0.2d, v1.2d, v2.2d", 0x6ee24420),
    ("ushl v0.2s, v1.2s, v2.2s", 0x2ea24420), ("sshl v0.2d, v1.2d, v2.2d", 0x4ee24420),
    ("sshl v0.4s, v1.4s, v2.4s", 0x4ea24420), ("sshl v0.8b, v1.8b, v2.8b", 0x0e224420),
    ("ushl d0, d1, d2", 0x7ee24420), ("sshl d0, d1, d2", 0x5ee24420), ("neg v0.8h, v1.8h", 0x6e60b820),
    ("neg v0.2d, v1.2d", 0x6ee0b820), ("neg v0.8b, v1.8b", 0x2e20b820), ("neg d0, d1", 0x7ee0b820),
    ("abs v0.4s, v1.4s", 0x4ea0b820), ("abs v0.16b, v1.16b", 0x4e20b820), ("abs d0, d1", 0x5ee0b820),
    ("shl v0.4s, v1.4s, #0x18", 0x4f385420), ("shl v0.16b, v1.16b, #7", 0x4f0f5420),
    ("shl v0.2d, v1.2d, #0x3f", 0x4f7f5420), ("shl d0, d1, #3", 0x5f435420),
    ("ushr v0.4s, v1.4s, #0x18", 0x6f280420), ("ushr v0.2d, v1.2d, #0x40", 0x6f400420),
    ("ushr v0.8b, v1.8b, #8", 0x2f080420), ("ushr v0.4h, v1.4h, #8", 0x2f180420),
    ("sshr v0.8h, v1.8h, #0x10", 0x4f100420), ("sshr v0.2s, v1.2s, #1", 0x0f3f0420),
    ("sshr d0, d1, #0x40", 0x5f400420), ("ushr d0, d1, #1", 0x7f7f0420), ("usra v0.2d, v1.2d, #0x3f", 0x6f411420),
    ("ssra v0.4s, v1.4s, #0x1f", 0x4f211420), ("usra d0, d1, #0x40", 0x7f401420), ("xtn v0.8b, v1.8h", 0x0e212820),
    ("xtn v0.4h, v1.4s", 0x0e612820), ("xtn v0.2s, v1.2d", 0x0ea12820), ("xtn2 v0.16b, v1.8h", 0x4e212820),
    ("xtn2 v0.8h, v1.4s", 0x4e612820), ("xtn2 v0.4s, v1.2d", 0x4ea12820), ("shrn v0.2s, v1.2d, #8", 0x0f388420),
    ("shrn v0.8b, v1.8h, #8", 0x0f088420), ("shrn v0.4h, v1.4s, #1", 0x0f1f8420),
    ("shrn2 v0.4s, v1.2d, #0x20", 0x4f208420), ("shrn2 v0.16b, v1.8h, #1", 0x4f0f8420),
    ("ushll v0.8h, v1.8b, #0", 0x2f08a420), ("ushll v0.4s, v1.4h, #3", 0x2f13a420),
    ("ushll v0.2d, v1.2s, #0x1f", 0x2f3fa420), ("ushll2 v0.4s, v1.8h, #8", 0x6f18a420),
    ("ushll2 v0.8h, v1.16b, #0", 0x6f08a420), ("sshll v0.2d, v1.2s, #0", 0x0f20a420),
    ("sshll v0.8h, v1.8b, #7", 0x0f0fa420), ("sshll2 v0.4s, v1.8h, #0xf", 0x4f1fa420),
    ("shll v0.4s, v1.4h, #16", 0x2e613820), ("shll2 v0.2d, v1.4s, #32", 0x6ea13820),
    ("shll v0.8h, v1.8b, #8", 0x2e213820), ("uaddl v0.4s, v1.4h, v2.4h", 0x2e620020),
    ("uaddl2 v0.4s, v1.8h, v2.8h", 0x6e620020), ("saddl v0.2d, v1.2s, v2.2s", 0x0ea20020),
    ("usubl v0.8h, v1.8b, v2.8b", 0x2e222020), ("ssubl2 v0.2d, v1.4s, v2.4s", 0x4ea22020),
    ("uaddw v0.4s, v1.4s, v2.4h", 0x2e621020), ("uaddw2 v0.4s, v1.4s, v2.8h", 0x6e621020),
    ("saddw v0.2d, v1.2d, v2.2s", 0x0ea21020), ("saddw2 v0.2d, v1.2d, v2.4s", 0x4ea21020),
    ("ssubw v0.2d, v1.2d, v2.2s", 0x0ea23020), ("ssubw2 v0.2d, v1.2d, v2.4s", 0x4ea23020),
    ("usubw v0.8h, v1.8h, v2.8b", 0x2e223020), ("umull v0.2d, v1.2s, v2.2s", 0x2ea2c020),
    ("smull v0.2d, v1.2s, v2.2s", 0x0ea2c020), ("smull2 v0.2d, v1.4s, v2.4s", 0x4ea2c020),
    ("umull2 v0.8h, v1.16b, v2.16b", 0x6e22c020), ("smull v0.4s, v1.4h, v2.4h", 0x0e62c020),
    ("umlal v0.2d, v1.2s, v2.2s", 0x2ea28020), ("smlal v0.2d, v1.2s, v2.2s", 0x0ea28020),
    ("smlal2 v0.2d, v1.4s, v2.4s", 0x4ea28020), ("umlsl v0.4s, v1.4h, v2.4h", 0x2e62a020),
    ("smlsl2 v0.8h, v1.16b, v2.16b", 0x4e22a020), ("mla v0.4s, v1.4s, v2.4s", 0x4ea29420),
    ("mls v0.8h, v1.8h, v2.8h", 0x6e629420), ("mla v0.8b, v1.8b, v2.8b", 0x0e229420),
    ("uzp1 v0.8h, v1.8h, v2.8h", 0x4e421820), ("uzp1 v0.4s, v1.4s, v2.4s", 0x4e821820),
    ("uzp1 v0.16b, v1.16b, v2.16b", 0x4e021820), ("uzp1 v0.2d, v1.2d, v2.2d", 0x4ec21820),
    ("uzp1 v0.4h, v1.4h, v2.4h", 0x0e421820), ("uzp1 v0.8b, v1.8b, v2.8b", 0x0e021820),
    ("uzp1 v0.2s, v1.2s, v2.2s", 0x0e821820), ("uzp2 v0.8h, v1.8h, v2.8h", 0x4e425820),
    ("uzp2 v0.4s, v1.4s, v2.4s", 0x4e825820), ("uzp2 v0.16b, v1.16b, v2.16b", 0x4e025820),
    ("uzp2 v0.2d, v1.2d, v2.2d", 0x4ec25820), ("uzp2 v0.4h, v1.4h, v2.4h", 0x0e425820),
    ("uzp2 v0.2s, v1.2s, v2.2s", 0x0e825820), ("ext v0.16b, v1.16b, v2.16b, #8", 0x6e024020),
    ("ext v0.16b, v1.16b, v2.16b, #0", 0x6e020020), ("ext v0.16b, v1.16b, v2.16b, #0xf", 0x6e027820),
    ("ext v0.8b, v1.8b, v2.8b, #3", 0x2e021820), ("ext v0.8b, v1.8b, v2.8b, #7", 0x2e023820),
    ("addv b0, v1.16b", 0x4e31b820), ("addv h0, v1.8h", 0x4e71b820), ("addv s0, v1.4s", 0x4eb1b820),
    ("addv b0, v1.8b", 0x0e31b820), ("addv h0, v1.4h", 0x0e71b820), ("umaxv b0, v1.16b", 0x6e30a820),
    ("umaxv h0, v1.4h", 0x2e70a820), ("uminv s0, v1.4s", 0x6eb1a820), ("smaxv b0, v1.8b", 0x0e30a820),
    ("sminv h0, v1.8h", 0x4e71a820), ("addp d0, v1.2d", 0x5ef1b820), ("bsl v0.16b, v1.16b, v2.16b", 0x6e621c20),
    ("bit v0.16b, v1.16b, v2.16b", 0x6ea21c20), ("bif v0.16b, v1.16b, v2.16b", 0x6ee21c20),
    ("bsl v0.8b, v1.8b, v2.8b", 0x2e621c20), ("bit v0.8b, v1.8b, v2.8b", 0x2ea21c20),
    ("bif v0.8b, v1.8b, v2.8b", 0x2ee21c20), ("mvni v0.4s, #0x39", 0x6f010720),
    ("mvni v0.8h, #0x12, lsl #8", 0x6f00a640), ("mvni v0.2s, #0xff, lsl #24", 0x2f0767e0),
    ("mvni v0.4h, #1", 0x2f008420), ("orr v0.4s, #0x10, lsl #8", 0x4f003600), ("orr v0.8h, #0xff", 0x4f0797e0),
    ("bic v0.8h, #1", 0x6f009420), ("bic v0.2s, #0x80, lsl #24", 0x2f047400), ("rev16 v0.16b, v1.16b", 0x4e201820),
    ("rev16 v0.8b, v1.8b", 0x0e201820), ("rev32 v0.16b, v1.16b", 0x6e200820), ("rev32 v0.8h, v1.8h", 0x6e600820),
    ("rev32 v0.4h, v1.4h", 0x2e600820), ("rev64 v0.16b, v1.16b", 0x4e200820), ("rev64 v0.4s, v1.4s", 0x4ea00820),
    ("rev64 v0.8h, v1.8h", 0x4e600820), ("rev64 v0.2s, v1.2s", 0x0ea00820), ("rev64 v0.8b, v1.8b", 0x0e200820),
    ("add v3.4s, v3.4s, v3.4s", 0x4ea38463), ("uzp1 v2.8h, v2.8h, v2.8h", 0x4e421842),
    ("xtn2 v1.8h, v1.4s", 0x4e612821),
    # 饱和加减（置位 FPSR.QC，这里只核对向量结果）。
    ("uqadd v0.16b, v1.16b, v2.16b", 0x6e220c20), ("uqadd v0.8h, v1.8h, v2.8h", 0x6e620c20),
    ("uqsub v0.4s, v1.4s, v2.4s", 0x6ea22c20), ("sqadd v0.2d, v1.2d, v2.2d", 0x4ee20c20),
    ("sqsub v0.8b, v1.8b, v2.8b", 0x0e222c20), ("uqadd d0, d1, d2", 0x7ee20c20),
    ("sqsub d0, d1, d2", 0x5ee22c20),

]

_X86_LANES = [
    ("paddb xmm0, xmm1", "660ffcc1"), ("paddw xmm0, xmm1", "660ffdc1"), ("paddd xmm0, xmm1", "660ffec1"),
    ("paddq xmm0, xmm1", "660fd4c1"), ("psubb xmm0, xmm1", "660ff8c1"), ("psubq xmm0, xmm1", "660ffbc1"),
    ("pcmpeqb xmm0, xmm1", "660f74c1"), ("pcmpeqd xmm0, xmm1", "660f76c1"), ("pcmpeqd xmm1, xmm1", "660f76c9"),
    ("pcmpeqq xmm0, xmm1", "660f3829c1"), ("pcmpgtb xmm0, xmm1", "660f64c1"), ("pcmpgtd xmm0, xmm1", "660f66c1"),
    ("pcmpgtq xmm0, xmm1", "660f3837c1"), ("pcmpgtw xmm2, xmm2", "660f65d2"), ("pmullw xmm0, xmm1", "660fd5c1"),
    ("pmulld xmm0, xmm1", "660f3840c1"), ("pminub xmm0, xmm1", "660fdac1"), ("pmaxsw xmm0, xmm1", "660feec1"),
    ("pminsd xmm0, xmm1", "660f3839c1"), ("pmaxud xmm0, xmm1", "660f383fc1"), ("psllw xmm0, 7", "660f71f007"),
    ("pslld xmm0, 8", "660f72f008"), ("psllq xmm0, 0x3f", "660f73f03f"), ("psrlw xmm0, 0x10", "660f71d010"),
    ("psrld xmm0, 0x1f", "660f72d01f"), ("psraw xmm0, 0xf", "660f71e00f"), ("psrad xmm0, 0xc8", "660f72e0c8"),
    ("psllq xmm0, xmm1", "660ff3c1"), ("psrlw xmm0, xmm1", "660fd1c1"), ("psrad xmm0, xmm1", "660fe2c1"),
    ("pinsrb xmm0, eax, 3", "660f3a20c003"), ("pinsrw xmm0, ecx, 7", "660fc4c107"),
    ("pinsrd xmm0, edx, 1", "660f3a22c201"), ("pinsrq xmm0, rax, 1", "66480f3a22c001"),
    ("pextrb eax, xmm0, 5", "660f3a14c005"), ("pextrw ecx, xmm1, 3", "660fc5c903"),
    ("pextrd edx, xmm0, 3", "660f3a16c203"), ("pextrq rax, xmm1, 1", "66480f3a16c801"),
    ("pmovmskb ecx, xmm1", "660fd7c9"), ("movmskps eax, xmm0", "0f50c0"), ("movmskpd edx, xmm1", "660f50d1"),
    ("pblendw xmm1, xmm0, 0x3f", "660f3a0ec83f"), ("blendps xmm0, xmm1, 5", "660f3a0cc105"),
    ("blendpd xmm0, xmm1, 2", "660f3a0dc102"), ("pshufd xmm0, xmm0, 0xe1", "660f70c0e1"),
    ("pshufd xmm2, xmm1, 0x1b", "660f70d11b"), ("pmovsxbd xmm0, xmm0", "660f3821c0"),
    ("pmovzxbw xmm0, xmm1", "660f3830c1"), ("pmovsxbq xmm2, xmm1", "660f3822d1"),
    ("pmovzxwd xmm0, xmm1", "660f3833c1"), ("pmovsxwq xmm0, xmm1", "660f3824c1"),
    ("pmovzxdq xmm0, xmm1", "660f3835c1"), ("vpaddd xmm0, xmm1, xmm2", "c5f1fec2"),
    ("vpcmpeqb xmm3, xmm1, xmm2", "c5f174da"), ("vpsllq xmm0, xmm1, 3", "c5f973f103"),
    ("vpinsrd xmm0, xmm1, eax, 2", "c4e37122c002"), ("vpblendw xmm0, xmm1, xmm2, 0xa5", "c4e3710ec2a5"),
    ("vpmovmskb eax, xmm2", "c5f9d7c2"),
    # imm8 超出通道数：硬件只取低 log2(通道数) 位（pinsrb 0x13 写第 3 个字节，pextrw 0xb 取第 3 个字）。
    ("pinsrb xmm0, eax, 0x13", "660f3a20c013"), ("pinsrw xmm0, ecx, 9", "660fc4c109"),
    ("pinsrd xmm0, edx, 5", "660f3a22c205"), ("pinsrq xmm0, rax, 3", "66480f3a22c003"),
    ("pextrb eax, xmm0, 0x13", "660f3a14c013"), ("pextrw ecx, xmm1, 0xb", "660fc5c90b"),
    ("pextrd edx, xmm0, 6", "660f3a16c206"), ("pextrq rax, xmm1, 2", "66480f3a16c802"),
    ("vpinsrd xmm0, xmm1, eax, 6", "c4e37122c006"), ("vpextrw eax, xmm2, 0xff", "c5f9c5c2ff"),
    # 饱和加减、字节重排与饱和打包。
    ("paddsb xmm0, xmm1", "660fecc1"), ("paddsw xmm0, xmm1", "660fedc1"), ("psubsb xmm0, xmm1", "660fe8c1"),
    ("psubsw xmm0, xmm1", "660fe9c1"), ("paddusb xmm0, xmm1", "660fdcc1"), ("paddusw xmm0, xmm1", "660fddc1"),
    ("psubusb xmm0, xmm1", "660fd8c1"), ("psubusw xmm0, xmm1", "660fd9c1"), ("pshufb xmm0, xmm1", "660f3800c1"),
    ("packsswb xmm0, xmm1", "660f63c1"), ("packssdw xmm0, xmm1", "660f6bc1"), ("packuswb xmm0, xmm1", "660f67c1"),
    ("packusdw xmm0, xmm1", "660f382bc1"), ("vpshufb xmm0, xmm1, xmm2", "c4e27100c2"),
    ("vpacksswb xmm0, xmm1, xmm2", "c5f163c2"),

]



# ---------------------------------------------------------------------------
# 解码、硬件执行与输入生成
# ---------------------------------------------------------------------------

def _decode(architecture, blob):
    from fangida.processors.decoder import NativeDecoder
    rows, warnings = NativeDecoder(architecture).decode_bytes(blob, 0x1000)
    if warnings or not rows:
        raise AssertionError(f"decode failed: {warnings}")
    return rows[0]


def _a64(word):
    return _decode("arm64", struct.pack("<I", word))


def _text(row):
    return (row["mnemonic"] + " " + ", ".join(row["operands"])).strip()


@functools.lru_cache(maxsize=None)
def _toolchain(architecture):
    """(编译参数, 运行前缀)；本机不能编译并执行该架构的程序时为 None。"""
    compiler = shutil.which("cc")
    if compiler is None:
        return None
    if architecture == "arm64":
        candidates = [([], [])] if _HOST in {"arm64", "aarch64"} else []
    elif _HOST in {"x86_64", "amd64"}:
        candidates = [([], [])]
    elif sys.platform == "darwin" and _HOST == "arm64" and Path("/usr/bin/arch").exists():
        candidates = [(["-arch", "x86_64"], ["/usr/bin/arch", "-x86_64"])]  # 经 Rosetta 执行
    else:
        candidates = []
    for flags, runner in candidates:
        with tempfile.TemporaryDirectory() as tmp:
            source, binary = Path(tmp) / "probe.c", Path(tmp) / "probe"
            source.write_text("int main(void) { return 0; }\n")
            if subprocess.run([compiler, *flags, str(source), "-o", str(binary)], capture_output=True).returncode:
                continue
            if subprocess.run([*runner, str(binary)], capture_output=True).returncode == 0:
                return compiler, tuple(flags), tuple(runner)
    return None


def _run_c(architecture, source_text):
    """编译并运行 C 程序，返回标准输出；本机不能执行该架构时跳过。"""
    toolchain = _toolchain(architecture)
    if toolchain is None:
        raise unittest.SkipTest(f"本机不能编译运行 {architecture} 程序")
    compiler, flags, runner = toolchain
    with tempfile.TemporaryDirectory() as tmp:
        source, binary = Path(tmp) / "check.c", Path(tmp) / "check"
        source.write_text(source_text)
        compiled = subprocess.run([compiler, *flags, "-O1", str(source), "-o", str(binary)], capture_output=True, text=True)
        if compiled.returncode:
            raise AssertionError(compiled.stderr)
        result = subprocess.run([*runner, str(binary)], capture_output=True, text=True, timeout=300)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result.stdout


def _lane_pattern(rng, lane):
    """按 lane 位通道构造的 128 位值：每个通道取边界值、移位量边界（低字节）或随机值。"""
    boundaries = [0, 1, 2, (1 << lane) - 1, (1 << lane) - 2, 1 << (lane - 1), (1 << (lane - 1)) - 1, (1 << (lane - 1)) + 1]
    shifts = [0, 1, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 0xff, 0xfe, 0xf8, 0xf0, 0xe1, 0xe0,
              0xc1, 0xc0, 0x80, 0x81, 0xf7]
    result = 0
    for index in range(128 // lane):
        choice = rng.random()
        if choice < 0.45:
            item = rng.choice(boundaries)
        elif choice < 0.7:
            item = rng.choice(shifts) if lane == 8 else (rng.getrandbits(lane) & ~0xff) | rng.choice(shifts)
        else:
            item = rng.getrandbits(lane)
        result |= (item & ((1 << lane) - 1)) << (index * lane)
    return result


def _vector_cases(seed, count, registers=4):
    rng = random.Random(seed)
    cases = [[0] * registers, [_MASK128] * registers,
             [int("80" * 16, 16)] * registers, [int("7f" * 16, 16)] * registers]
    while len(cases) < count:
        cases.append([_lane_pattern(rng, rng.choice((8, 16, 32, 64))) if rng.random() < 0.85 else
                      rng.choice((0, _MASK128, rng.getrandbits(128))) for _ in range(registers)])
    return cases


def _apply(lifted, values, registers):
    """按微码 assign 操作更新寄存器（未写的寄存器保持不变）。

    这些指令的各个 assign 只读取指令执行前的值（rep 串操作先更新指针、最后清零计数），
    因此都用执行前的 values 求值。
    """
    result = dict(values)
    for operation in lifted["operations"]:
        output = operation.get("output")
        if operation["opcode"] != "assign" or output not in registers:
            continue
        attributes = operation["attributes"]
        computed = evaluate_expression(operation["expression"], values)
        width, storage, shift = attributes["destination_width"], attributes["storage_width"], attributes["bit_offset"]
        if width == storage or attributes.get("zero_upper"):
            result[output] = computed & ((1 << width) - 1)
        else:
            mask = ((1 << width) - 1) << shift
            result[output] = (values[output] & ~mask) | ((computed << shift) & mask)
    return result


# ---------------------------------------------------------------------------
# 独立参考实现：AArch64（按 ARM 伪代码逐元素计算）
# ---------------------------------------------------------------------------

_ARRANGEMENTS = {"8b": (8, 8), "16b": (8, 16), "4h": (16, 4), "8h": (16, 8), "2s": (32, 2), "4s": (32, 4), "2d": (64, 2)}
_SCALARS = {"b": 8, "h": 16, "s": 32, "d": 64}


def _sint(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


def _elements(value, size, count, offset=0):
    return [(value >> (offset + index * size)) & ((1 << size) - 1) for index in range(count)]


def _pack(items, size):
    return sum((item & ((1 << size) - 1)) << (index * size) for index, item in enumerate(items))


def _register(token):
    """(寄存器号, 元素位宽, 元素个数)：vN.T 或标量 b/h/s/dN。"""
    match = re.fullmatch(r"v(\d+)\.(\w+)", token)
    if match:
        return (int(match[1]), *_ARRANGEMENTS[match[2]])
    match = re.fullmatch(r"([bhsd])(\d+)", token)
    return int(match[2]), _SCALARS[match[1]], 1


def _immediate(token):
    return int(token.strip().lstrip("#"), 0)


def _relation(name, left, right, size):
    if name == "cmeq":
        return left == right
    if name == "cmhi":
        return left > right
    if name == "cmhs":
        return left >= right
    if name == "cmgt":
        return _sint(left, size) > _sint(right, size)
    if name == "cmge":
        return _sint(left, size) >= _sint(right, size)
    return (left & right) != 0  # cmtst


def _saturate(value, size, signed):
    """把精确整数 value 饱和到 size 位带符号/无符号范围。"""
    if signed:
        low, high = -(1 << (size - 1)), (1 << (size - 1)) - 1
    else:
        low, high = 0, (1 << size) - 1
    return min(max(value, low), high) & ((1 << size) - 1)


def _shift_by_register(element, amount, size, signed):
    shift = _sint(amount, 8)
    number = _sint(element, size) if signed else element
    number = number << shift if shift >= 0 else number >> -shift
    return number & ((1 << size) - 1)


def _a64_reference(text, registers):
    """返回 (目的寄存器号, 新的 128 位值)。"""
    mnemonic, _, rest = text.partition(" ")
    operands = [item.strip() for item in rest.split(",")]
    destination, size, count = _register(operands[0])
    old = registers[destination]
    width = size * count

    def value(token):
        index, element, number = _register(token)
        return _elements(registers[index], element, number)

    def half(token, upper, element):
        index = _register(token)[0]
        return _elements(registers[index], element, 64 // element, 64 if upper else 0)

    def extend(items, element, signed):
        return [_sint(item, element) if signed else item for item in items]

    upper = mnemonic.endswith("2") and mnemonic[:-1] in {
        "xtn", "shrn", "ushll", "sshll", "shll", "uaddl", "saddl", "usubl", "ssubl", "umull", "smull",
        "uaddw", "saddw", "usubw", "ssubw", "umlal", "smlal", "umlsl", "smlsl"}
    base = mnemonic[:-1] if upper else mnemonic
    if base in {"add", "sub", "mul", "umax", "umin", "smax", "smin", "ushl", "sshl", "cmeq", "cmhi", "cmhs",
                "cmgt", "cmge", "cmtst", "cmle", "cmlt", "uqadd", "uqsub", "sqadd", "sqsub"}:
        left = value(operands[1])
        right = [0] * count if operands[2].startswith("#") else value(operands[2])
        mask = (1 << size) - 1
        if base in {"cmle", "cmlt"}:
            out = [mask if (_sint(item, size) <= 0 if base == "cmle" else _sint(item, size) < 0) else 0 for item in left]
        elif base.startswith("cm"):
            out = [mask if _relation(base, a, b, size) else 0 for a, b in zip(left, right)]
        elif base in {"ushl", "sshl"}:
            out = [_shift_by_register(a, b, size, base == "sshl") for a, b in zip(left, right)]
        elif base in {"umax", "umin"}:
            out = [(max if base == "umax" else min)(a, b) for a, b in zip(left, right)]
        elif base in {"smax", "smin"}:
            out = [(max if base == "smax" else min)(_sint(a, size), _sint(b, size)) for a, b in zip(left, right)]
        elif base == "uqadd":
            out = [_saturate(a + b, size, False) for a, b in zip(left, right)]
        elif base == "uqsub":
            out = [_saturate(a - b, size, False) for a, b in zip(left, right)]
        elif base == "sqadd":
            out = [_saturate(_sint(a, size) + _sint(b, size), size, True) for a, b in zip(left, right)]
        elif base == "sqsub":
            out = [_saturate(_sint(a, size) - _sint(b, size), size, True) for a, b in zip(left, right)]
        else:
            out = [a + b if base == "add" else a - b if base == "sub" else a * b for a, b in zip(left, right)]
        return destination, _pack(out, size)
    if base in {"neg", "abs"}:
        out = [-_sint(item, size) if base == "neg" else abs(_sint(item, size)) for item in value(operands[1])]
        return destination, _pack(out, size)
    if base in {"shl", "ushr", "sshr", "usra", "ssra"}:
        amount = _immediate(operands[2])
        source = value(operands[1])
        if base == "shl":
            out = [item << amount for item in source]
        elif base in {"ushr", "usra"}:
            out = [item >> amount for item in source]
        else:
            out = [_sint(item, size) >> amount for item in source]
        if base in {"usra", "ssra"}:
            out = [a + b for a, b in zip(_elements(old, size, count), out)]
        return destination, _pack(out, size)
    if base in {"xtn", "shrn"}:
        source = value(operands[1])
        amount = _immediate(operands[2]) if base == "shrn" else 0
        narrowed = _pack([item >> amount for item in source], size)
        return destination, (old & ((1 << 64) - 1)) | (narrowed << 64) if upper else narrowed
    if base in {"ushll", "sshll", "shll"}:
        source = half(operands[1], upper, size // 2)
        out = [item << _immediate(operands[2]) for item in extend(source, size // 2, base == "sshll")]
        return destination, _pack(out, size)
    if base in {"uaddl", "saddl", "usubl", "ssubl", "umull", "smull", "umlal", "smlal", "umlsl", "smlsl"}:
        signed = base.startswith("s")
        left = extend(half(operands[1], upper, size // 2), size // 2, signed)
        right = extend(half(operands[2], upper, size // 2), size // 2, signed)
        if base.endswith("l") and base[1:4] in {"add", "sub"}:
            out = [a + b if "add" in base else a - b for a, b in zip(left, right)]
        else:
            products = [a * b for a, b in zip(left, right)]
            accumulator = _elements(old, size, count)
            out = products if base.endswith("mull") else [
                c + p if "mla" in base else c - p for c, p in zip(accumulator, products)]
        return destination, _pack(out, size)
    if base in {"uaddw", "saddw", "usubw", "ssubw"}:
        left = value(operands[1])
        right = extend(half(operands[2], upper, size // 2), size // 2, base.startswith("s"))
        return destination, _pack([a + b if "add" in base else a - b for a, b in zip(left, right)], size)
    if base in {"mla", "mls"}:
        products = [a * b for a, b in zip(value(operands[1]), value(operands[2]))]
        return destination, _pack([c + p if base == "mla" else c - p
                                   for c, p in zip(_elements(old, size, count), products)], size)
    if mnemonic in {"uzp1", "uzp2"}:
        combined = value(operands[1]) + value(operands[2])
        part = int(mnemonic == "uzp2")
        return destination, _pack([combined[2 * index + part] for index in range(count)], size)
    if base == "ext":
        data = value(operands[1]) + value(operands[2])
        start = _immediate(operands[3])
        return destination, _pack(data[start:start + count], 8)
    if base in {"addv", "umaxv", "uminv", "smaxv", "sminv"}:
        index, element, number = _register(operands[1])
        items = _elements(registers[index], element, number)
        if base == "addv":
            return destination, sum(items) & ((1 << element) - 1)
        if base in {"umaxv", "uminv"}:
            return destination, (max if base == "umaxv" else min)(items)
        return destination, (max if base == "smaxv" else min)(items, key=lambda item: _sint(item, element))
    if base == "addp":
        return destination, sum(value(operands[1])) & ((1 << 64) - 1)
    if base in {"bsl", "bit", "bif"}:
        mask = (1 << width) - 1
        current, left, right = old & mask, registers[_register(operands[1])[0]] & mask, registers[_register(operands[2])[0]] & mask
        if base == "bsl":
            return destination, (current & left) | (~current & right & mask)
        if base == "bit":
            return destination, (current & ~right & mask) | (left & right)
        return destination, (current & right) | (left & ~right & mask)
    if base in {"mvni", "orr", "bic"}:
        shift = _immediate(operands[2].split()[-1]) if len(operands) == 3 else 0
        element = (_immediate(operands[1]) << shift) & ((1 << size) - 1)
        if base == "mvni":
            return destination, _pack([~element] * count, size)
        current = _elements(old, size, count)
        return destination, _pack([item | element if base == "orr" else item & ~element for item in current], size)
    if base in {"rev16", "rev32", "rev64"}:
        container = int(base[3:]) // size
        items = value(operands[1])
        out = []
        for start in range(0, count, container):
            out.extend(reversed(items[start:start + container]))
        return destination, _pack(out, size)
    raise AssertionError("no reference for " + text)


def _a64_expected(text, registers):
    """完整寄存器组的预期结果：64 位结果清零高 64 位，xtn2/shrn2 保留低 64 位。"""
    destination, result = _a64_reference(text, registers)
    mnemonic, _, rest = text.partition(" ")
    first = rest.split(",")[0].strip()
    _, size, count = _register(first)
    width = size * count
    expected = dict(registers)
    expected[destination] = result & ((1 << width) - 1)
    return expected


# ---------------------------------------------------------------------------
# 独立参考实现：x86 SSE（按 Intel SDM 逐元素计算）
# ---------------------------------------------------------------------------

_X86_SIZE = {"b": 8, "w": 16, "d": 32, "q": 64}
_GPR = {"eax": "rax", "rax": "rax", "ecx": "rcx", "rcx": "rcx", "edx": "rdx", "rdx": "rdx"}


def _x86_expected(text, xmm, gpr):
    mnemonic, _, rest = text.partition(" ")
    operands = [item.strip() for item in rest.split(",")]
    vex = mnemonic.startswith("v")
    base = mnemonic[1:] if vex else mnemonic
    xmm, gpr = list(xmm), dict(gpr)

    def vector(token):
        return xmm[int(token[3:])]

    destination = operands[0]
    if vex:
        first, second, rest_operands = operands[1], (operands[2] if len(operands) > 2 else None), operands[3:]
    else:
        first, second, rest_operands = operands[0], (operands[1] if len(operands) > 1 else None), operands[2:]

    def write_vector(value):
        xmm[int(destination[3:])] = value & _MASK128

    def write_gpr(token, value):
        gpr[_GPR[token]] = value & ((1 << 64) - 1) if token.startswith("r") else value & 0xffffffff

    _SAT = {"paddsb": ("sqadd", 8), "paddsw": ("sqadd", 16), "psubsb": ("sqsub", 8), "psubsw": ("sqsub", 16),
            "paddusb": ("uqadd", 8), "paddusw": ("uqadd", 16), "psubusb": ("uqsub", 8), "psubusw": ("uqsub", 16)}
    if base in _SAT:
        op, size = _SAT[base]
        left, right = _elements(vector(first), size, 128 // size), _elements(vector(second), size, 128 // size)
        if op == "uqadd":
            out = [_saturate(a + b, size, False) for a, b in zip(left, right)]
        elif op == "uqsub":
            out = [_saturate(a - b, size, False) for a, b in zip(left, right)]
        elif op == "sqadd":
            out = [_saturate(_sint(a, size) + _sint(b, size), size, True) for a, b in zip(left, right)]
        else:
            out = [_saturate(_sint(a, size) - _sint(b, size), size, True) for a, b in zip(left, right)]
        write_vector(_pack(out, size))
        return xmm, gpr
    if base == "pshufb":
        table = _elements(vector(first), 8, 16)
        control = _elements(vector(second), 8, 16)
        write_vector(_pack([0 if c & 0x80 else table[c & 15] for c in control], 8))
        return xmm, gpr
    if base in {"packsswb", "packssdw", "packuswb", "packusdw"}:
        size = 16 if base.endswith("wb") else 32  # 源通道宽度（wb：16→8，dw：32→16）
        unsigned = base[4] == "u"
        half = size // 2
        a = [_saturate(_sint(item, size), half, not unsigned) for item in _elements(vector(first), size, 128 // size)]
        b = [_saturate(_sint(item, size), half, not unsigned) for item in _elements(vector(second), size, 128 // size)]
        write_vector(_pack(a + b, half))
        return xmm, gpr
    for prefix, operation in (("padd", "add"), ("psub", "sub"), ("pcmpeq", "eq"), ("pcmpgt", "gt")):
        if base.startswith(prefix) and len(base) == len(prefix) + 1:
            size = _X86_SIZE[base[-1]]
            left, right = _elements(vector(first), size, 128 // size), _elements(vector(second), size, 128 // size)
            mask = (1 << size) - 1
            if operation == "add":
                out = [a + b for a, b in zip(left, right)]
            elif operation == "sub":
                out = [a - b for a, b in zip(left, right)]
            elif operation == "eq":
                out = [mask if a == b else 0 for a, b in zip(left, right)]
            else:
                out = [mask if _sint(a, size) > _sint(b, size) else 0 for a, b in zip(left, right)]
            write_vector(_pack(out, size))
            return xmm, gpr
    if base in {"pmullw", "pmulld"}:
        size = 16 if base == "pmullw" else 32
        write_vector(_pack([a * b for a, b in zip(_elements(vector(first), size, 128 // size),
                                                  _elements(vector(second), size, 128 // size))], size))
        return xmm, gpr
    if base[:4] in {"pmin", "pmax"}:
        size, signed = _X86_SIZE[base[-1]], base[4] == "s"
        key = (lambda item: _sint(item, size)) if signed else (lambda item: item)
        chooser = min if base.startswith("pmin") else max
        write_vector(_pack([chooser(a, b, key=key) for a, b in zip(_elements(vector(first), size, 128 // size),
                                                                   _elements(vector(second), size, 128 // size))], size))
        return xmm, gpr
    if base[:4] in {"psll", "psrl", "psra"}:
        size = _X86_SIZE[base[-1]]
        count_token = operands[-1]
        count = vector(count_token) & ((1 << 64) - 1) if count_token.startswith("xmm") else int(count_token, 0) & 0xff
        source = _elements(vector(first), size, 128 // size)
        if base.startswith("psra"):
            out = [_sint(item, size) >> min(count, size) for item in source]
        elif count >= size:
            out = [0] * len(source)
        else:
            out = [item << count if base.startswith("psll") else item >> count for item in source]
        write_vector(_pack(out, size))
        return xmm, gpr
    if base.startswith("pinsr"):
        size = _X86_SIZE[base[-1]]
        index = int(operands[-1], 0) & (128 // size - 1)
        source = gpr[_GPR[operands[-2]]] & ((1 << size) - 1)
        current = vector(first)
        lane_mask = ((1 << size) - 1) << (index * size)
        write_vector((current & ~lane_mask) | (source << (index * size)))
        return xmm, gpr
    if base.startswith("pextr"):
        size = _X86_SIZE[base[-1]]
        index = int(operands[2], 0) & (128 // size - 1)
        write_gpr(operands[0], (vector(operands[1]) >> (index * size)) & ((1 << size) - 1))
        return xmm, gpr
    if base in {"pmovmskb", "movmskps", "movmskpd"}:
        size = {"pmovmskb": 8, "movmskps": 32, "movmskpd": 64}[base]
        items = _elements(vector(operands[1]), size, 128 // size)
        write_gpr(operands[0], sum(((item >> (size - 1)) & 1) << index for index, item in enumerate(items)))
        return xmm, gpr
    if base in {"pblendw", "blendps", "blendpd"}:
        size = {"pblendw": 16, "blendps": 32, "blendpd": 64}[base]
        selector = int(rest_operands[0], 0)
        left, right = _elements(vector(first), size, 128 // size), _elements(vector(second), size, 128 // size)
        write_vector(_pack([b if selector >> index & 1 else a for index, (a, b) in enumerate(zip(left, right))], size))
        return xmm, gpr
    if base == "pshufd":
        selector = int(operands[2], 0)
        items = _elements(vector(operands[1]), 32, 4)
        write_vector(_pack([items[(selector >> (2 * index)) & 3] for index in range(4)], 32))
        return xmm, gpr
    if base.startswith("pmov") and base[4] in "sz":
        source_size, target_size = _X86_SIZE[base[6]], _X86_SIZE[base[7]]
        items = _elements(vector(operands[1]), source_size, 128 // target_size)
        if base[4] == "s":
            items = [_sint(item, source_size) for item in items]
        write_vector(_pack(items, target_size))
        return xmm, gpr
    raise AssertionError("no reference for " + text)


# ---------------------------------------------------------------------------
# 测试
# ---------------------------------------------------------------------------

@unittest.skipUnless(_HAS_CAPSTONE, "需要 Capstone 解码真实编码")
class LaneOperationTests(unittest.TestCase):
    def test_a64_encodings_decode_to_the_assembled_text_and_lift(self):
        for text, word in _A64_LANES:
            with self.subTest(text=text):
                row = _a64(word)
                self.assertEqual(_text(row), text)
                result = lift_instruction(row, "arm64")
                self.assertTrue(result["supported"])
                self.assertEqual(result["flag_effect"], "preserve")
                destination = "v" + str(_register(text.split(" ", 1)[1].split(",")[0])[0])
                self.assertEqual(result["writes"], [destination])
                # 只有累加、插入高半与按位选择类指令读取目的寄存器的旧值。
                reads_destination = destination in result["reads"]
                mnemonic = text.split()[0]
                operands = text.split(" ", 1)[1]
                self.assertEqual(reads_destination, mnemonic in {
                    "usra", "ssra", "xtn2", "shrn2", "umlal", "smlal", "smlal2", "umlsl", "smlsl2", "mla", "mls",
                    "bsl", "bit", "bif", "orr", "bic"} or operands.count(destination + ".") > 1)

    def test_a64_lanes_match_the_reference_at_boundaries(self):
        for number, (text, word) in enumerate(_A64_LANES):
            lifted = lift_instruction(_a64(word), "arm64")
            for case in _vector_cases(number, 40):
                values = {f"v{index}": item for index, item in enumerate(case)}
                expected = _a64_expected(text, dict(enumerate(case)))
                with self.subTest(text=text, inputs=[hex(item) for item in case]):
                    actual = _apply(lifted, values, values)
                    self.assertEqual([actual[f"v{index}"] for index in range(4)], [expected[index] for index in range(4)])

    def test_a64_lanes_match_hardware(self):
        cases_per_instruction = 24
        functions, inputs, plans = [], bytearray(), []
        for number, (text, word) in enumerate(_A64_LANES):
            functions.append(
                f"static void f{number}(const uint8_t *in, uint8_t *out) {{ __asm__ volatile("
                f"\"ldp q0, q1, [%0]\\n ldp q2, q3, [%0, #32]\\n .inst {word:#010x}\\n"
                f" stp q0, q1, [%1]\\n stp q2, q3, [%1, #32]\\n\" :: \"r\"(in), \"r\"(out)"
                f" : \"v0\", \"v1\", \"v2\", \"v3\", \"memory\"); }}")
            cases = _vector_cases(1000 + number, cases_per_instruction)
            plans.append((text, lift_instruction(_a64(word), "arm64"), cases))
            for case in cases:
                for item in case:
                    inputs += item.to_bytes(16, "little")
        program = "\n".join([
            "#include <stdio.h>", "#include <stdint.h>", *functions,
            "typedef void (*step)(const uint8_t *, uint8_t *);",
            "static const step table[] = {" + ", ".join(f"f{index}" for index in range(len(functions))) + "};",
            f"static const uint8_t inputs[{len(inputs)}] = {{{','.join(map(str, inputs))}}};",
            f"int main(void) {{ uint8_t out[64]; for (int i = 0; i < {len(functions)}; i++)"
            f" for (int c = 0; c < {cases_per_instruction}; c++) {{"
            f" table[i](inputs + (i * {cases_per_instruction} + c) * 64, out);"
            " for (int k = 0; k < 64; k++) printf(\"%02x\", out[k]); printf(\"\\n\"); } return 0; }"])
        lines = iter(_run_c("arm64", program).split())
        for text, lifted, cases in plans:
            for case in cases:
                hardware = bytes.fromhex(next(lines))
                observed = [int.from_bytes(hardware[index * 16:(index + 1) * 16], "little") for index in range(4)]
                values = {f"v{index}": item for index, item in enumerate(case)}
                actual = _apply(lifted, values, values)
                with self.subTest(text=text, inputs=[hex(item) for item in case]):
                    self.assertEqual([actual[f"v{index}"] for index in range(4)], observed)

    def test_x86_encodings_decode_lift_and_match_the_reference(self):
        rng = random.Random(7)
        for text, encoding in _X86_LANES:
            row = _decode("x86_64", bytes.fromhex(encoding))
            with self.subTest(text=text):
                self.assertEqual(_text(row), text)
                lifted = lift_instruction(row, "x86_64")
                self.assertTrue(lifted["supported"])
                self.assertEqual(lifted["flag_effect"], "preserve")
            for case in _vector_cases(len(text), 32):
                if rng.random() < 0.6:  # 移位计数寄存器 xmm1 的低 64 位经常取小值
                    case[1] = (case[1] & ~((1 << 64) - 1)) | rng.choice((0, 1, 7, 15, 16, 31, 32, 63, 64, 65, 1 << 40))
                gpr = {"rax": rng.choice((0, 0xff, 0x80, 0x7fffffff, (1 << 64) - 1, rng.getrandbits(64))),
                       "rcx": rng.getrandbits(64), "rdx": rng.choice((0, 1, rng.getrandbits(64)))}
                values = {**{f"xmm{index}": item for index, item in enumerate(case)}, **gpr}
                expected_xmm, expected_gpr = _x86_expected(text, case, gpr)
                actual = _apply(lifted, values, values)
                with self.subTest(text=text, inputs=[hex(item) for item in case]):
                    self.assertEqual([actual[f"xmm{index}"] for index in range(4)], expected_xmm)
                    self.assertEqual({name: actual[name] for name in gpr}, expected_gpr)

    def test_x86_lanes_match_hardware(self):
        cases_per_instruction = 16
        functions, inputs, plans = [], bytearray(), []
        rng = random.Random(11)
        for number, (text, encoding) in enumerate(_X86_LANES):
            body = ",".join(f"{byte:#04x}" for byte in bytes.fromhex(encoding))
            functions.append(
                f"static void f{number}(const uint8_t *in, uint8_t *out) {{ __asm__ volatile("
                "\"movdqu (%0), %%xmm0\\n movdqu 16(%0), %%xmm1\\n movdqu 32(%0), %%xmm2\\n movdqu 48(%0), %%xmm3\\n"
                f" mov 64(%0), %%rax\\n mov 72(%0), %%rcx\\n mov 80(%0), %%rdx\\n .byte {body}\\n"
                " movdqu %%xmm0, (%1)\\n movdqu %%xmm1, 16(%1)\\n movdqu %%xmm2, 32(%1)\\n movdqu %%xmm3, 48(%1)\\n"
                " mov %%rax, 64(%1)\\n mov %%rcx, 72(%1)\\n mov %%rdx, 80(%1)\\n\" :: \"r\"(in), \"r\"(out)"
                " : \"xmm0\", \"xmm1\", \"xmm2\", \"xmm3\", \"rax\", \"rcx\", \"rdx\", \"memory\"); }")
            cases = []
            for case in _vector_cases(2000 + number, cases_per_instruction):
                case[1] = (case[1] & ~((1 << 64) - 1)) | rng.choice((0, 3, 15, 16, 31, 32, 63, 64, 1 << 40))
                gpr = [rng.choice((0, 0xff, 0x80, (1 << 64) - 1, rng.getrandbits(64))) for _ in range(3)]
                cases.append((case, gpr))
                for item in case:
                    inputs += item.to_bytes(16, "little")
                for item in gpr:
                    inputs += item.to_bytes(8, "little")
            plans.append((text, lift_instruction(_decode("x86_64", bytes.fromhex(encoding)), "x86_64"), cases))
        program = "\n".join([
            "#include <stdio.h>", "#include <stdint.h>", *functions,
            "typedef void (*step)(const uint8_t *, uint8_t *);",
            "static const step table[] = {" + ", ".join(f"f{index}" for index in range(len(functions))) + "};",
            f"static const uint8_t inputs[{len(inputs)}] = {{{','.join(map(str, inputs))}}};",
            f"int main(void) {{ uint8_t out[88]; for (int i = 0; i < {len(functions)}; i++)"
            f" for (int c = 0; c < {cases_per_instruction}; c++) {{"
            f" table[i](inputs + (i * {cases_per_instruction} + c) * 88, out);"
            " for (int k = 0; k < 88; k++) printf(\"%02x\", out[k]); printf(\"\\n\"); } return 0; }"])
        lines = iter(_run_c("x86_64", program).split())
        names = ("rax", "rcx", "rdx")
        for text, lifted, cases in plans:
            for case, gpr in cases:
                hardware = bytes.fromhex(next(lines))
                observed_xmm = [int.from_bytes(hardware[index * 16:(index + 1) * 16], "little") for index in range(4)]
                observed_gpr = [int.from_bytes(hardware[64 + index * 8:72 + index * 8], "little") for index in range(3)]
                values = {**{f"xmm{index}": item for index, item in enumerate(case)}, **dict(zip(names, gpr))}
                actual = _apply(lifted, values, values)
                with self.subTest(text=text, inputs=[hex(item) for item in case + gpr]):
                    self.assertEqual([actual[f"xmm{index}"] for index in range(4)], observed_xmm)
                    self.assertEqual([actual[name] for name in names], observed_gpr)

    def test_lane_opcodes_evaluate_exact_boundaries(self):
        def register(name):
            return Expression("register", 128, name=name)

        def evaluate(opcode, width, *args, **values):
            return evaluate_expression(Expression(opcode, width, args), values)

        ones = _MASK128
        # 模 2^L 回绕、各通道独立：0xff + 1 只影响本字节。
        self.assertEqual(evaluate("vec_add8", 128, register("a"), register("b"), a=0xff, b=1), 0)
        self.assertEqual(evaluate("vec_add64", 128, register("a"), register("b"), a=ones, b=1), ((1 << 64) - 1) << 64)
        self.assertEqual(evaluate("vec_sub16", 128, register("a"), register("b"), a=0, b=1), 0xffff)
        # 比较结果为全 1 / 全 0 通道；带符号与无符号的分界在符号位。
        self.assertEqual(evaluate("vec_cmhi32", 128, register("a"), register("b"), a=0x80000000, b=0x7fffffff), 0xffffffff)
        self.assertEqual(evaluate("vec_cmgt32", 128, register("a"), register("b"), a=0x80000000, b=0x7fffffff), 0)
        # USHL/SSHL：移位量是带符号低字节；左移出界为 0，右移出界为 0 或符号填充。
        for amount, unsigned, signed in ((8, 0, 0), (-8, 0, 0xff), (7, 0, 0), (-7, 1, 0xff), (0x80, 0, 0xff), (0x7f, 0, 0)):
            with self.subTest(amount=amount):
                self.assertEqual(evaluate("vec_ushl8", 128, register("a"), register("b"), a=0x80, b=amount & 0xff), unsigned)
                self.assertEqual(evaluate("vec_sshl8", 128, register("a"), register("b"), a=0x80, b=amount & 0xff), signed)
        # 立即数/标量计数：>= 通道宽度时逻辑移位为 0、算术移位为符号填充。
        count = Expression("constant", 64, value=64)
        self.assertEqual(evaluate("vec_lshr64", 128, register("a"), count, a=ones), 0)
        self.assertEqual(evaluate("vec_ashr64", 128, register("a"), count, a=1 << 127), ones ^ ((1 << 64) - 1))
        # 窄化、扩展、归约与符号掩码的宽度关系。
        self.assertEqual(evaluate("vec_narrow16", 64, register("a"), a=0x01ff_0280_0000_ffff | (0xab << 64)), 0xff80_00ff | (0xab << 32))
        low = Expression("register", 64, name="a")
        self.assertEqual(evaluate("vec_sext8", 128, low, a=0x80_7f), 0xff80_007f)
        self.assertEqual(evaluate("vec_zext8", 128, low, a=0x80_7f), 0x0080_007f)
        self.assertEqual(evaluate("vec_addv8", 8, register("a"), a=int("ff" * 16, 16)), 0xf0)
        self.assertEqual(evaluate("vec_sminv16", 16, register("a"), a=0x8000_7fff), 0x8000)
        self.assertEqual(evaluate("vec_signmask8", 32, register("a"), a=int("80" * 8, 16)), 0xff)
        with self.assertRaises(ValueError):  # 参数宽度与 opcode 不符视为格式错误
            evaluate("vec_add8", 128, low, low, a=1)

    def test_unsupported_vector_forms_stay_opaque(self):
        rows = [
            ("arm64", ins(0, "fmla", "v0.4s", "v1.4s", "v2.4s", size=4)),        # 融合乘加（FMA）依赖 FPCR
            ("arm64", ins(0, "sqdmulh", "v0.4s", "v1.4s", "v2.4s", size=4)),     # 饱和倍乘取高半
            ("arm64", ins(0, "sqadd", "b0", "b1", "b2", size=4)),                # 标量字节饱和（非 64 位标量）
            ("arm64", ins(0, "mvni", "v0.4s", "#0x12", "msl #8", size=4)),       # MSL 移入 1
            ("arm64", ins(0, "ld1", "{v1.s}[3]", "[x8]", "#4", size=4)),         # 回写基址
            ("arm64", ins(0, "mla", "v0.4s", "v1.4s", "v2.s[1]", size=4)),       # 按元素形式
            ("arm64", ins(0, "tbl", "v0.16b", "{v1.16b}", "v2.16b", size=4)),    # 表查找
            ("arm64", ins(0, "add", "v0.1d", "v1.1d", "v2.1d", size=4)),         # 不存在的排列
            ("x86_64", ins(0, "vpaddd", "ymm0", "ymm1", "ymm2")),                # 256 位
            ("x86_64", ins(0, "vpshufb", "ymm0", "ymm1", "ymm2")),               # 256 位字节表查找
            ("x86_64", ins(0, "paddb", "mm0", "mm1")),                           # MMX
            ("x86_64", ins(0, "paddsb", "mm0", "mm1")),                          # MMX 饱和运算
        ]
        for architecture, row in rows:
            with self.subTest(mnemonic=row["mnemonic"], operands=row["operands"]):
                result = lift_instruction(row, architecture)
                self.assertFalse(result["supported"])
                self.assertEqual(result["operations"][0]["opcode"], "opaque")

    def test_single_lane_memory_accesses_touch_one_lane(self):
        load = lift_instruction(_a64(0x0d400501), "arm64")  # ld1 {v1.b}[1], [x8]
        self.assertEqual((load["reads"], load["writes"], load["memory_effect"]), (["v1", "x8"], ["v1"], "read"))
        store = lift_instruction(_a64(0x4d008401), "arm64")  # st1 {v1.d}[1], [x0]
        self.assertEqual((store["reads"], store["writes"], store["memory_effect"]), (["v1", "x0"], [], "write"))
        self.assertEqual(store["operations"][0]["opcode"], "store")
        self.assertEqual((store["operations"][0]["inputs"][1]["opcode"], store["operations"][0]["inputs"][1]["value"]), ("extract", 64))
        # 只替换第 1 个字节通道：用常量代替内存读取后逐位核对。
        expression = load["operations"][0]["expression"]

        def replace_load(node):
            if node["opcode"] == "load":
                return {"opcode": "constant", "width": node["width"], "value": 0xab, "domain": "bitvector"}
            return {**node, "args": [replace_load(arg) for arg in node.get("args", [])]} if node.get("args") else node
        old = 0x00112233445566778899aabbccddeeff
        self.assertEqual(evaluate_expression(replace_load(expression), {"v1": old}), (old & ~(0xff << 8)) | (0xab << 8))


@unittest.skipUnless(_HAS_CAPSTONE, "需要 Capstone 解码真实编码")
class SystemRegisterTests(unittest.TestCase):
    def test_system_register_encodings_lift_with_exact_effects(self):
        # (编码, 解码文本, 支持, 读集合, 写集合, 第一个操作的 opcode, 表达式 opcode 或系统寄存器名)
        fixtures = [
            (0xd53bd048, "mrs x8, tpidr_el0", True, [], ["x8"], "assign", "tpidr_el0"),
            (0xd53bd069, "mrs x9, tpidrro_el0", True, [], ["x9"], "assign", "tpidrro_el0"),
            (0xd53b4400, "mrs x0, fpcr", True, ["fp_environment"], ["x0"], "assign", "fpcr"),
            (0xd53b4420, "mrs x0, fpsr", True, ["fp_environment"], ["x0"], "assign", "fpsr"),
            (0xd53be040, "mrs x0, cntvct_el0", True, [], ["x0"], "assign", "cntvct_el0"),
            (0xd53be003, "mrs x3, cntfrq_el0", True, [], ["x3"], "assign", "cntfrq_el0"),
            (0xd5380609, "mrs x9, id_aa64isar0_el1", True, [], ["x9"], "assign", "id_aa64isar0_el1"),
            (0xd53b0029, "mrs x9, ctr_el0", True, [], ["x9"], "assign", "ctr_el0"),
            (0xd53b00e9, "mrs x9, dczid_el0", True, [], ["x9"], "assign", "dczid_el0"),
            (0xd53b4201, "mrs x1, nzcv", True, ["flags", "flags.C", "flags.N", "flags.V", "flags.Z"], ["x1"], "assign", None),
            (0xd51b4201, "msr nzcv, x1", True, ["x1"], ["flags"], "flags_nzcv", None),
            (0xd51b421f, "msr nzcv, xzr", True, [], ["flags"], "flags_nzcv", None),
            (0xd51b4400, "msr fpcr, x0", True, ["x0"], ["fp_environment"], "system_register_write", None),
            (0xd51b4422, "msr fpsr, x2", True, ["x2"], ["fp_environment"], "system_register_write", None),
            (0xd51bd043, "msr tpidr_el0, x3", True, ["x3"], [], "system_register_write", None),
        ]
        for word, text, supported, reads, writes, opcode, register in fixtures:
            with self.subTest(text=text):
                row = _a64(word)
                self.assertEqual(_text(row), text)
                result = lift_instruction(row, "arm64")
                self.assertEqual(result["supported"], supported)
                self.assertEqual((result["reads"], result["writes"]), (reads, writes))
                operation = result["operations"][0]
                self.assertEqual(operation["opcode"], opcode)
                if register:
                    self.assertEqual(operation["expression"], {"opcode": "system_register", "width": 64,
                                                               "domain": "bitvector", "name": register})
                    self.assertEqual(operation["attributes"]["system_register"], register)
        volatile = lift_instruction(_a64(0xd53be040), "arm64")["operations"][0]["attributes"]
        stable = lift_instruction(_a64(0xd53bd048), "arm64")["operations"][0]["attributes"]
        self.assertEqual((volatile["volatile"], volatile["may_trap"], stable["volatile"], stable["may_trap"]),
                         (True, True, False, False))

    def test_system_register_reads_are_named_impure_and_never_invented(self):
        operation = lift_instruction(_a64(0xd53bd048), "arm64")["operations"][0]
        expression = Expression.from_dict(operation["expression"])
        self.assertFalse(expression.pure)  # 计数器/FPSR 每次读取可能不同，读取不能合并
        self.assertEqual(evaluate_expression(expression, {"tpidr_el0": 0x7000_1000}), 0x7000_1000)
        with self.assertRaises(UnknownValue):
            evaluate_expression(expression, {"x8": 1})
        report = analyze_microcode(lift_function(fn(ins(0, "mov", "x8", "#5", size=4), ins(4, "mrs", "x8", "tpidr_el0", size=4),
                                                    ins(8, "mov", "x9", "#1", size=4)), "arm64")["instructions"])
        self.assertNotIn("x8", report["remaining_register_bits"])
        self.assertEqual(report["remaining_register_bits"]["x9"]["value"], 1)

    def test_nzcv_round_trip_preserves_every_flag_combination(self):
        mrs = lift_instruction(_a64(0xd53b4201), "arm64")["operations"][0]   # mrs x1, nzcv
        msr = lift_instruction(_a64(0xd51b4201), "arm64")["operations"][0]   # msr nzcv, x1
        positions = msr["attributes"]["bit_positions"]
        self.assertEqual(positions, {"N": 31, "Z": 30, "C": 29, "V": 28})
        rng = random.Random(5)
        for bits in range(16):
            flags = {"N": bits >> 3 & 1, "Z": bits >> 2 & 1, "C": bits >> 1 & 1, "V": bits & 1}
            saved = evaluate_expression(mrs["expression"], {f"flags.{name}": value for name, value in flags.items()})
            with self.subTest(flags=flags):
                # 其余位读为 0（RES0）。
                self.assertEqual(saved, bits << 28)
                # 写回时其余位被忽略：任意填充其余位，恢复出的标志不变。
                noisy = saved | (rng.getrandbits(64) & ~(0xf << 28))
                restored = {name: noisy >> bit & 1 for name, bit in positions.items()}
                self.assertEqual(restored, flags)

    def test_nzcv_round_trip_in_block_analysis(self):
        # cmp 建立标志 -> mrs 保存 -> cmn 改写 -> msr 恢复 -> 条件分支看到的是 cmp 的标志。
        for left, right, code in ((5, 5, "eq"), (5, 7, "lo"), (7, 5, "hi"), (0, 1, "mi"), (0x7fffffff, 0, "gt"),
                                  (1, 2, "ge"), (3, 3, "ne")):
            rows = [ins(0, "mov", "x0", f"#{left}", size=4), ins(4, "mov", "x1", f"#{right}", size=4),
                    ins(8, "cmp", "x0", "x1", size=4), ins(12, "mrs", "x2", "nzcv", size=4),
                    ins(16, "cmn", "x0", "#1", size=4), ins(20, "msr", "nzcv", "x2", size=4),
                    ins(24, f"b.{code}", "0x40", size=4, kind="jump", target=0x40, conditional=True)]
            report = analyze_microcode(lift_function(fn(*rows), "arm64")["instructions"])
            branch = next(fact for fact in report["facts"] if fact["kind"] == "branch")
            difference = (left - right) & ((1 << 64) - 1)
            reference = {"eq": left == right, "ne": left != right, "lo": left < right, "hi": left > right,
                         "mi": bool(difference >> 63), "gt": left > right, "ge": left >= right}[code]
            with self.subTest(left=left, right=right, code=code):
                self.assertEqual(branch["taken"], reference)
                saved = next(fact for fact in report["facts"] if fact.get("output") == "x2")
                self.assertEqual(saved["value"] & ~(0xf << 28), 0)
        # 恢复的值未知时标志也未知，不会沿用 cmn 的结果。
        rows = [ins(0, "cmp", "x0", "x0", size=4), ins(4, "msr", "nzcv", "x5", size=4),
                ins(8, "b.eq", "0x40", size=4, kind="jump", target=0x40, conditional=True)]
        report = analyze_microcode(lift_function(fn(*rows), "arm64")["instructions"])
        self.assertIsNone(next(fact for fact in report["facts"] if fact["kind"] == "branch")["taken"])

    def test_nzcv_layout_matches_hardware(self):
        values = [0, 0xffffffffffffffff, 0x80000000, 0x40000000, 0x20000000, 0x10000000, 0xf0000000, 0x0fffffff,
                  0x123456789abcdef0, 0xa0000001]
        body = "\n".join(
            f"  {{ uint64_t out; __asm__ volatile(\"msr nzcv, %1\\n mrs %0, nzcv\" : \"=r\"(out) : \"r\"((uint64_t){value:#x}ULL));"
            " printf(\"%016llx\\n\", (unsigned long long)out); }" for value in values)
        observed = [int(line, 16) for line in _run_c("arm64", "#include <stdio.h>\n#include <stdint.h>\nint main(void) {\n"
                                                     + body + "\n  return 0;\n}\n").split()]
        msr = lift_instruction(_a64(0xd51b4201), "arm64")["operations"][0]
        mrs = lift_instruction(_a64(0xd53b4201), "arm64")["operations"][0]
        for value, hardware in zip(values, observed):
            flags = {f"flags.{name}": value >> bit & 1 for name, bit in msr["attributes"]["bit_positions"].items()}
            with self.subTest(value=hex(value)):
                self.assertEqual(evaluate_expression(mrs["expression"], flags), hardware)

    def test_privileged_or_unknown_system_registers_stay_opaque(self):
        for word, text in ((0xd50342df, "msr daifset, #2"), (0xd51bd060, "msr tpidrro_el0, x0"),
                           (0xd538f200, "mrs x0, s3_0_c15_c2_0"), (0xd53b2400, "mrs x0, rndr"),
                           (0xd50041bf, "msr spsel, #1"), (0xd53b4220, "mrs x0, daif"), (0xd5384240, "mrs x0, currentel"),
                           (0xf8200420, "ldraa x0, [x1]")):
            with self.subTest(text=text):
                row = _a64(word)
                self.assertEqual(_text(row), text)
                result = lift_instruction(row, "arm64")
                self.assertFalse(result["supported"])
                self.assertTrue(result["operations"][0]["attributes"]["barrier"])

    def test_readable_c_names_reads_and_keeps_each_counter_read(self):
        output = generate_pseudoc(fn(ins(0, "mrs", "x0", "cntvct_el0", size=4), ins(4, "mrs", "x1", "cntvct_el0", size=4),
                                     ins(8, "sub", "x0", "x1", "x0", size=4), ins(12, "ret", kind="return", size=4),
                                     name="elapsed", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        self.assertEqual(output.pseudoc.count('__arm_rsr64("cntvct_el0")'), 2)
        self.assertNotIn("unresolved_operation", output.pseudoc)
        self.assertIn('x0 = __arm_rsr64("cntvct_el0");', output.machine_pseudoc)
        if _toolchain("arm64") is None:
            self.skipTest("本机不能编译运行 arm64 程序")
        # ACLE 的 __arm_rsr64 读取真实计数器：两次读取单调不减。
        compile_run(output.pseudoc, "uint64_t delta = elapsed(); return delta < (1ull << 40) ? 0 : 1;",
                    prefix="#include <arm_acle.h>\n")

    def test_readable_c_writes_system_registers_explicitly(self):
        rows = [ins(0, "mrs", "x1", "fpcr", size=4), ins(4, "msr", "fpcr", "x1", size=4), ins(8, "msr", "tpidr_el0", "x0", size=4),
                ins(12, "ret", kind="return", size=4)]
        output = generate_pseudoc(fn(*rows, name="keep_mode", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        self.assertIn('__arm_wsr64("fpcr", ', output.pseudoc)
        self.assertIn('__arm_wsr64("tpidr_el0", ', output.pseudoc)
        self.assertNotIn("unresolved_operation", output.pseudoc)
        self.assertIn('__arm_wsr64("fpcr", x1);', output.machine_pseudoc)
        if _toolchain("arm64") is None:
            self.skipTest("本机不能编译运行 arm64 程序")
        # 只在运行时执行 fpcr 的读出再写回（不改变浮点环境）；tpidr_el0 的写入只编译不执行。
        fpcr_only = generate_pseudoc(fn(*rows[:2], ins(8, "mov", "x0", "x1", size=4), ins(12, "ret", kind="return", size=4),
                                        name="keep_fpcr", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        self.assertIn("uint64_t keep_fpcr(void)", fpcr_only.pseudoc)
        compile_run(fpcr_only.pseudoc + "\n" + output.pseudoc,
                    "return keep_fpcr() == __arm_rsr64(\"fpcr\") ? 0 : 1;", prefix="#include <arm_acle.h>\n")

    def test_sme_thread_pointer_access_may_trap(self):
        # TPIDR2_EL0 只在实现 FEAT_SME 时存在：未实现时是未定义指令，SME 访问未启用时陷入 EL1。
        for word, text, may_trap in ((0xd53bd0a0, "mrs x0, tpidr2_el0", True), (0xd51bd0a1, "msr tpidr2_el0, x1", True),
                                     (0xd53bd048, "mrs x8, tpidr_el0", False), (0xd51bd043, "msr tpidr_el0, x3", False),
                                     (0xd51b4400, "msr fpcr, x0", False)):
            with self.subTest(text=text):
                row = _a64(word)
                self.assertEqual(_text(row), text)
                attributes = lift_instruction(row, "arm64")["operations"][0]["attributes"]
                self.assertIs(attributes["may_trap"], may_trap)

    # (名字, 设置标志的指令行, 同一操作的内联汇编)：mrs 读到的 NZCV 必须与硬件逐位相同。
    _FLAG_SOURCES = (
        ("flags_cmp_x", [ins(0, "cmp", "x0", "x1", size=4)], "cmp %1, %2"),
        ("flags_cmp_w", [ins(0, "cmp", "w0", "w1", size=4)], "cmp %w1, %w2"),
        ("flags_cmp_imm", [ins(0, "cmp", "x0", "#5", size=4)], "cmp %1, #5"),
        ("flags_cmn_x", [ins(0, "cmn", "x0", "x1", size=4)], "cmn %1, %2"),
        ("flags_adds_w", [ins(0, "adds", "w3", "w0", "w1", size=4)], "adds w3, %w1, %w2"),
        ("flags_tst_x", [ins(0, "tst", "x0", "x1", size=4)], "tst %1, %2"),
        ("flags_ccmp", [ins(0, "cmp", "x0", "#0", size=4), ins(4, "ccmp", "x0", "x1", "#6", "ne", size=4)],
         "cmp %1, #0\\n ccmp %1, %2, #6, ne"),
    )

    def test_readable_c_reconstructs_saved_flags_from_their_source(self):
        # mrs xN, nzcv 在可读 C 中由标志来源还原 N/Z/C/V，不出现匿名的 unknown_value()；逐位与硬件比对。
        sources, references, checks = [], [], []
        for name, rows, assembly in self._FLAG_SOURCES:
            end = rows[-1]["addr"] + 4
            output = generate_pseudoc(fn(*rows, ins(end, "mrs", "x0", "nzcv", size=4), ins(end + 4, "ret", kind="return", size=4),
                                         name=name, pseudoc_context={"kind": "elf"}), "arm64", style="readable")
            with self.subTest(source=name):
                self.assertNotIn("unknown_value", output.pseudoc)
                self.assertNotIn("unresolved", output.pseudoc)
                self.assertNotIn("不完整", output.pseudoc.splitlines()[0])
            sources.append(output.pseudoc)
            references.append(f"static uint64_t hw_{name}(uint64_t a, uint64_t b) {{ uint64_t r; (void)b; __asm__ volatile("
                              f"\"{assembly}\\n mrs %0, nzcv\" : \"=r\"(r) : \"r\"(a), \"r\"(b) : \"cc\", \"x3\"); return r; }}")
            parameters = re.search(rf"\b{name}\(([^)]*)\)", output.pseudoc)[1]
            arguments = ", ".join({"arg_1": "a", "arg_2": "b"}[item.split()[-1]] for item in parameters.split(",")
                                  if item.strip() != "void")
            checks.append(f"if ({name}({arguments}) != hw_{name}(a, b)) return 1;")
        if _toolchain("arm64") is None:
            self.skipTest("本机不能编译运行 arm64 程序")
        values = (0, 1, 2, 5, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000, 0x7fffffffffffffff, 0x8000000000000000,
                  0x8000000000000001, 0xffffffffffffffff, 0xfffffffffffffffb, 0x123456789abcdef0)
        compile_run("\n".join(sources) + "\n" + "\n".join(references),
                    f"static const uint64_t values[] = {{{', '.join(f'{value:#x}ULL' for value in values)}}};\n"
                    f"    for (int i = 0; i < {len(values)}; i++) for (int j = 0; j < {len(values)}; j++) {{\n"
                    "        uint64_t a = values[i], b = values[j];\n        " + "\n        ".join(checks) + "\n    }\n    return 0;")

    def test_readable_c_marks_saved_flags_without_a_source_incomplete(self):
        # 入口处或标志被 msr 改写后，NZCV 来源未知：写成 unresolved_condition 并计入“不完整”，不伪装成完整。
        for rows in ([ins(0, "mrs", "x0", "nzcv", size=4)],
                     [ins(0, "cmp", "x0", "x1", size=4), ins(4, "msr", "nzcv", "x2", size=4), ins(8, "mrs", "x0", "nzcv", size=4)]):
            end = rows[-1]["addr"] + 4
            output = generate_pseudoc(fn(*rows, ins(end, "ret", kind="return", size=4), name="saved_flags",
                                         pseudoc_context={"kind": "elf"}), "arm64", style="readable")
            with self.subTest(rows=[row["mnemonic"] for row in rows]):
                self.assertIn("不完整", output.pseudoc.splitlines()[0])
                self.assertNotIn("unknown_value", output.pseudoc)
                for code in ("mi", "eq", "hs", "vs"):  # N/Z/C/V 分别等价于条件 mi/eq/hs/vs
                    self.assertIn(f'unresolved_condition("{code}")', output.pseudoc)


@unittest.skipUnless(_HAS_CAPSTONE, "需要 Capstone 解码真实编码")
class PointerAuthenticationTests(unittest.TestCase):
    def test_pac_instructions_write_only_their_destination(self):
        # (编码, 文本, 读集合, 写集合, 表达式 opcode, 修饰值, 是否 HINT 空间)
        fixtures = [
            (0xd503233f, "paciasp", ["sp", "x30"], ["x30"], "pacia", "sp", True),
            (0xd50323bf, "autiasp", ["sp", "x30"], ["x30"], "autia", "sp", True),
            (0xd503237f, "pacibsp", ["sp", "x30"], ["x30"], "pacib", "sp", True),
            (0xd50323ff, "autibsp", ["sp", "x30"], ["x30"], "autib", "sp", True),
            (0xd503231f, "paciaz", ["x30"], ["x30"], "pacia", "zero", True),
            (0xd503239f, "autiaz", ["x30"], ["x30"], "autia", "zero", True),
            (0xd503235f, "pacibz", ["x30"], ["x30"], "pacib", "zero", True),
            (0xd50323df, "autibz", ["x30"], ["x30"], "autib", "zero", True),
            (0xd503211f, "pacia1716", ["x16", "x17"], ["x17"], "pacia", "x16", True),
            (0xd50321df, "autib1716", ["x16", "x17"], ["x17"], "autib", "x16", True),
            (0xd50320ff, "xpaclri", ["x30"], ["x30"], "xpaci", None, True),
            (0xdac10020, "pacia x0, x1", ["x0", "x1"], ["x0"], "pacia", "x1", False),
            (0xdac103e2, "pacia x2, sp", ["sp", "x2"], ["x2"], "pacia", "sp", False),
            (0xdac123e3, "paciza x3", ["x3"], ["x3"], "pacia", "zero", False),
            (0xdac10ca4, "pacdb x4, x5", ["x4", "x5"], ["x4"], "pacdb", "x5", False),
            (0xdac118e6, "autda x6, x7", ["x6", "x7"], ["x6"], "autda", "x7", False),
            (0xdac137e8, "autizb x8", ["x8"], ["x8"], "autib", "zero", False),
            (0xdac143e9, "xpaci x9", ["x9"], ["x9"], "xpaci", None, False),
            (0xdac147ea, "xpacd x10", ["x10"], ["x10"], "xpacd", None, False),
            (0x9adf318b, "pacga x11, x12, sp", ["sp", "x12"], ["x11"], "pacga", "sp", False),
        ]
        for word, text, reads, writes, opcode, modifier, hint in fixtures:
            with self.subTest(text=text):
                row = _a64(word)
                self.assertEqual(_text(row), text)
                result = lift_instruction(row, "arm64")
                self.assertTrue(result["supported"])
                self.assertEqual((result["reads"], result["writes"], result["flag_effect"], result["memory_effect"]),
                                 (reads, writes, "preserve", "none"))
                operation = result["operations"][0]
                self.assertEqual((operation["opcode"], operation["expression"]["opcode"]), ("assign", opcode))
                attributes = operation["attributes"]
                self.assertEqual(attributes["modifier"], modifier)
                self.assertEqual(attributes["without_pauth"], "nop" if hint else "undefined_instruction")
                self.assertNotIn("barrier", attributes)
                with self.assertRaises(UnknownValue):  # 结果取决于密钥与配置，绝不臆造
                    evaluate_expression(operation["expression"], {name: 0x1234 for name in ("x30", "sp", "x0", "x1", "x2",
                                        "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x12", "x16", "x17")})
                self.assertEqual(Expression.from_dict(operation["expression"]).pure, not opcode.startswith("aut"))
        sign = lift_instruction(_a64(0xd503233f), "arm64")["operations"][0]["attributes"]
        self.assertEqual(sign["branch_target_landing_pad"], "bti_c")

    def test_pac_does_not_clear_unrelated_register_state(self):
        rows = [ins(0, "mov", "x0", "#5", size=4), ins(4, "mov", "x1", "#7", size=4), ins(8, "paciasp", size=4),
                ins(12, "add", "x2", "x0", "x1", size=4), ins(16, "autiasp", size=4), ins(20, "add", "x3", "x2", "#1", size=4),
                ins(24, "xpaclri", size=4), ins(28, "ret", kind="return", size=4)]
        report = analyze_microcode(lift_function(fn(*rows), "arm64")["instructions"])
        self.assertEqual(report["unsupported_addresses"], [])
        facts = {fact["output"]: fact["value"] for fact in report["facts"] if fact["kind"] == "constant_assignment"}
        self.assertEqual((facts["x2"], facts["x3"]), (12, 13))
        remaining = report["remaining_register_bits"]
        self.assertEqual({name: remaining[name]["value"] for name in ("x0", "x1", "x2", "x3")},
                         {"x0": 5, "x1": 7, "x2": 12, "x3": 13})
        self.assertNotIn("x30", remaining)  # 签名/认证后的 LR 未知，不臆造

    def test_authenticated_branches_represent_operands_without_solving_targets(self):
        for word, text, kind, opcode, modifier in ((0xd71f0a11, "braa x16, x17", "jump", "autia", "x17"),
                                                   (0xd61f0d1f, "brabz x8", "jump", "autib", "zero"),
                                                   (0xd73f0909, "blraa x8, x9", "call", "autia", "x9"),
                                                   (0xd63f0d5f, "blrabz x10", "call", "autib", "zero")):
            with self.subTest(text=text):
                row = _a64(word)
                self.assertEqual(_text(row), text)
                result = lift_instruction(row, "arm64")
                operation = result["operations"][0]
                self.assertEqual((result["supported"], operation["opcode"]), (True, kind))
                self.assertIsNone(operation["attributes"]["target"])
                self.assertEqual(operation["attributes"]["target_expression"]["opcode"], opcode)
                self.assertEqual(operation["attributes"]["modifier"], modifier)
                if kind == "jump":
                    self.assertEqual(operation["attributes"]["target_resolution"], "indirect_unknown")
        for word, key in ((0xd65f0bff, "ia"), (0xd65f0fff, "ib")):
            result = lift_instruction(_a64(word), "arm64")
            attributes = result["operations"][0]["attributes"]
            self.assertEqual((result["operations"][0]["opcode"], attributes["key"], attributes["authenticated_pointer"]),
                             ("return", key, "x30"))

    def test_readable_c_omits_return_address_signing_but_keeps_data_pointer_signing(self):
        frame = [ins(0, "paciasp", size=4), ins(4, "add", "x0", "x0", "#1", size=4), ins(8, "autiasp", size=4),
                 ins(12, "ret", kind="return", size=4)]
        output = generate_pseudoc(fn(*frame, name="increment", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        # LR 只是返回地址：可读 C 不建模返回地址（与保存/恢复 x30 的栈帧脚手架一致），签名/认证没有 C 层效果。
        self.assertNotIn("unresolved_operation", output.pseudoc)
        self.assertNotIn("pacia", output.pseudoc)
        self.assertIn("x30 = pacia_64(x30, sp);", output.machine_pseudoc)
        compile_run(output.pseudoc, "return increment(41) == 42 ? 0 : 1;")
        data = [ins(0, "pacda", "x0", "x1", size=4), ins(4, "ret", kind="return", size=4)]
        output = generate_pseudoc(fn(*data, name="sign", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        self.assertIn("pacda_64(", output.pseudoc)  # 数据指针签名是函数结果的一部分，必须显式出现
        self.assertNotIn("unresolved_operation", output.pseudoc)

    # 按文档原型（docs/microcode.md：uint64_t xxx_64(uint64_t p, uint64_t m)）定义的测试模型：
    # 签名置第 60 位、认证清除第 60 位并计数（认证可能陷入，调用不能被删除）。
    _PAC_MODEL = ("static int authentications;\n"
                  "__attribute__((unused)) static uint64_t pacda_64(uint64_t pointer, uint64_t modifier) {"
                  " (void)modifier; return pointer | (1ull << 60); }\n"
                  "__attribute__((unused)) static uint64_t autda_64(uint64_t pointer, uint64_t modifier) {"
                  " (void)modifier; authentications++; return pointer & ~(1ull << 60); }\n"
                  "__attribute__((unused)) static uint64_t autia_64(uint64_t pointer, uint64_t modifier) {"
                  " (void)modifier; authentications++; return pointer & ~(1ull << 60); }\n")

    @staticmethod
    def _call(name, text, arguments):
        parameters = re.search(rf"\b{name}\(([^)]*)\)", text)[1]
        return f"{name}(" + ", ".join(arguments[item.split()[-1]] for item in parameters.split(",") if item.strip() != "void") + ")"

    def test_readable_c_pac_helpers_take_integer_arguments(self):
        # 修饰值或被认证的值被推断为指针时，实参显式转为整数，按文档原型可直接编译。
        signed = generate_pseudoc(fn(ins(0, "ldr", "x2", "[x1]", size=4), ins(4, "pacda", "x0", "x1", size=4),
                                     ins(8, "add", "x0", "x0", "x2", size=4), ins(12, "ret", kind="return", size=4),
                                     name="sign_with_pointer", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        loaded = generate_pseudoc(fn(ins(0, "autda", "x0", "x1", size=4), ins(4, "ldr", "x0", "[x0]", size=4),
                                     ins(8, "ret", kind="return", size=4),
                                     name="load_authenticated", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        for output in (signed, loaded):
            # 没有直接以指针作实参（(uint64_t)(T *)p 这类显式转为整数的写法可以）。
            self.assertNotRegex(output.pseudoc, r"\b(?:pac|aut)da_64\((?:[^;]*?, )?\(\w+ \*\)")
        sign_call = self._call("sign_with_pointer", signed.pseudoc, {"arg_1": "0x1000", "arg_2": "&five"})
        load_call = self._call("load_authenticated", loaded.pseudoc,
                               {"arg_1": "((uint64_t)(uintptr_t)&forty_two | (1ull << 60))", "arg_2": "7"})
        compile_run(signed.pseudoc + "\n" + loaded.pseudoc,
                    "uint64_t five = 5, forty_two = 42;\n"
                    f"    if ({sign_call} != ((1ull << 60) | 0x1000) + 5) return 1;\n"
                    f"    return {load_call} == 42 && authentications == 1 ? 0 : 1;", prefix=self._PAC_MODEL)

    def test_readable_c_keeps_an_unused_data_authentication(self):
        # aut* 非纯（FEAT_FPAC 下认证失败会陷入）：结果无人使用时也不能被死代码删除。
        output = generate_pseudoc(fn(ins(0, "autia", "x1", "x2", size=4), ins(4, "mov", "x0", "#0", size=4),
                                     ins(8, "ret", kind="return", size=4), name="check_only",
                                     pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        self.assertIn("autia_64(", output.pseudoc)
        call = self._call("check_only", output.pseudoc, {"arg_1": "0", "arg_2": "0x1234", "arg_3": "9"})
        compile_run(output.pseudoc, f"return {call} == 0 && authentications == 1 ? 0 : 1;", prefix=self._PAC_MODEL)
        # 返回地址（LR）的认证仍按设计省略：即使 x30 经 stp/ldp 保存恢复而成为 C 层变量。
        frame = [ins(0, "paciasp", size=4), ins(4, "stp", "x29", "x30", "[sp, #-0x10]!", size=4),
                 ins(8, "mov", "x29", "sp", size=4), ins(12, "add", "x0", "x0", "#1", size=4),
                 ins(16, "ldp", "x29", "x30", "[sp], #0x10", size=4), ins(20, "autiasp", size=4), ins(24, "ret", kind="return", size=4)]
        output = generate_pseudoc(fn(*frame, name="framed", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        self.assertNotRegex(output.pseudoc, r"\b(?:pac|aut)ia_64\(")
        self.assertNotIn("不完整", output.pseudoc.splitlines()[0])
        compile_run(output.pseudoc, "return framed(41) == 42 ? 0 : 1;")


@unittest.skipUnless(_HAS_CAPSTONE, "需要 Capstone 解码真实编码")
class StringOperationTests(unittest.TestCase):
    _ENCODINGS = [("f348ab", "rep stosq", 64), ("f3ab", "rep stosd", 32), ("f366ab", "rep stosw", 16), ("f3aa", "rep stosb", 8),
                  ("f348a5", "rep movsq", 64), ("f3a5", "rep movsd", 32), ("f366a5", "rep movsw", 16), ("f3a4", "rep movsb", 8),
                  ("48ab", "stosq", 64), ("aa", "stosb", 8), ("a5", "movsd", 32), ("a4", "movsb", 8)]

    def test_string_operations_have_explicit_register_results(self):
        for encoding, mnemonic, width in self._ENCODINGS:
            row = _decode("x86_64", bytes.fromhex(encoding))
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(row["mnemonic"], mnemonic)
                result = lift_instruction(row, "x86_64")
                self.assertTrue(result["supported"])
                self.assertEqual(result["flag_effect"], "preserve")
                store, repeat = "stos" in mnemonic, mnemonic.startswith("rep")
                expected_writes = sorted({"rdi"} | ({"rcx"} if repeat else set()) | (set() if store else {"rsi"}))
                self.assertEqual(result["writes"], expected_writes)
                self.assertEqual(result["memory_effect"], "write" if store else "read_write")
                first = result["operations"][0]
                self.assertEqual(first["opcode"], ("memory_fill" if store else "memory_copy") if repeat else "store")
                self.assertEqual(first["attributes"]["direction_flag"], "assumed_clear")
                self.assertEqual(first["attributes"]["element_bytes"], width // 8)
                values = {"rdi": 0x1000, "rsi": 0x8000, "rcx": 5, "rax": 0}
                final = _apply(result, values, values)
                step = (5 if repeat else 1) * width // 8
                self.assertEqual(final["rdi"], 0x1000 + step)
                self.assertEqual(final["rsi"], 0x8000 + (0 if store else step))
                self.assertEqual(final["rcx"], 0 if repeat else 5)

    def test_string_operations_match_hardware(self):
        # 每个用例：(编码, 目的偏移, 源偏移, 元素个数, rax)；含源与目的重叠的升序复制（逐元素，不是 memmove）。
        cases = []
        for encoding, mnemonic, width in self._ENCODINGS:
            for destination, source, count in ((16, 96, 0), (16, 96, 1), (8, 64, 7), (1, 0, 9), (3, 0, 5), (40, 33, 4)):
                cases.append((encoding, mnemonic, width, destination, source, count, 0x8877665544332211))
        functions = []
        for index, (encoding, *_rest) in enumerate(cases):
            body = ",".join(f"{byte:#04x}" for byte in bytes.fromhex(encoding))
            functions.append(
                f"static void f{index}(uint64_t *r) {{ __asm__ volatile(\"cld\\n mov (%0), %%rdi\\n mov 8(%0), %%rsi\\n"
                f" mov 16(%0), %%rcx\\n mov 24(%0), %%rax\\n .byte {body}\\n mov %%rdi, (%0)\\n mov %%rsi, 8(%0)\\n"
                f" mov %%rcx, 16(%0)\\n\" :: \"r\"(r) : \"rdi\", \"rsi\", \"rcx\", \"rax\", \"memory\"); }}")
        calls = "\n".join(
            f"  {{ uint8_t buffer[160]; for (int i = 0; i < 160; i++) buffer[i] = (uint8_t)(i * 7 + 1);"
            f" uint64_t r[4] = {{(uint64_t)(buffer + {destination}), (uint64_t)(buffer + {source}), {count}, {pattern:#x}ULL}};"
            f" f{index}(r); printf(\"%lld %lld %llu \", (long long)(r[0] - (uint64_t)buffer), (long long)(r[1] - (uint64_t)buffer),"
            f" (unsigned long long)r[2]); for (int i = 0; i < 160; i++) printf(\"%02x\", buffer[i]); printf(\"\\n\"); }}"
            for index, (_, _, _, destination, source, count, pattern) in enumerate(cases))
        output = _run_c("x86_64", "#include <stdio.h>\n#include <stdint.h>\n" + "\n".join(functions)
                        + "\nint main(void) {\n" + calls + "\n  return 0;\n}\n").splitlines()
        for line, (encoding, mnemonic, width, destination, source, count, pattern) in zip(output, cases):
            destination_after, source_after, count_after, memory = line.split()
            result = lift_instruction(_decode("x86_64", bytes.fromhex(encoding)), "x86_64")
            base = 0x10000
            final = _apply(result, {"rdi": base + destination, "rsi": base + source, "rcx": count, "rax": pattern},
                           {"rdi", "rsi", "rcx", "rax"})
            # 参考：按元素从低到高依次存储/复制（rep 前缀重复 count 次，无前缀执行一次）。
            buffer = bytearray((index * 7 + 1) & 0xff for index in range(160))
            size = width // 8
            for element in range(count if mnemonic.startswith("rep") else 1):
                if "stos" in mnemonic:
                    buffer[destination + element * size:destination + (element + 1) * size] = (pattern & ((1 << width) - 1)).to_bytes(size, "little")
                else:
                    chunk = bytes(buffer[source + element * size:source + (element + 1) * size])
                    buffer[destination + element * size:destination + (element + 1) * size] = chunk
            with self.subTest(mnemonic=mnemonic, destination=destination, source=source, count=count):
                self.assertEqual((final["rdi"] - base, final["rsi"] - base, final["rcx"]),
                                 (int(destination_after), int(source_after), int(count_after)))
                self.assertEqual(memory, buffer.hex())

    def test_direction_flag_writers_and_other_forms_stay_opaque(self):
        rep = _decode("x86_64", bytes.fromhex("f3a4"))
        for writer in ("std", "popfq"):
            with self.subTest(writer=writer):
                rows = [ins(0, writer), {**rep, "addr": 1}, ins(3, "ret", kind="return")]
                lifted = lift_function(fn(*rows), "x86_64")["instructions"]
                self.assertFalse(lifted[1]["supported"])
        cleared = lift_function(fn(ins(0, "cld"), {**rep, "addr": 1}, ins(3, "ret", kind="return")), "x86_64")["instructions"]
        self.assertTrue(cleared[1]["supported"])
        for encoding, text in (("67f348ab", "rep stosq qword ptr [edi], rax"), ("f3a6", "repe cmpsb byte ptr [rsi], byte ptr [rdi]"),
                               ("f2ae", "repne scasb al, byte ptr [rdi]"), ("64f3a4", "rep movsb byte ptr [rdi], byte ptr fs:[rsi]")):
            row = _decode("x86_64", bytes.fromhex(encoding))
            with self.subTest(text=text):
                self.assertEqual(_text(row), text)
                self.assertFalse(lift_instruction(row, "x86_64")["supported"])
        legacy = _decode("x86", bytes.fromhex("f3a5"))  # 32 位：es:[edi]，平坦模型假设记入属性
        result = lift_instruction(legacy, "x86")
        self.assertTrue(result["supported"])
        self.assertEqual(result["operations"][0]["attributes"]["segment"], "es_base_zero_flat_model_assumed")

    def test_readable_c_calls_explicit_string_helpers(self):
        rows = [ins(0, "mov", "rcx", "rdx", size=3), {**_decode("x86_64", bytes.fromhex("f3a4")), "addr": 3},
                ins(5, "mov", "rax", "rdi", size=3), ins(8, "ret", kind="return")]
        output = generate_pseudoc(fn(*rows, name="copy_forward", pseudoc_context={"kind": "elf"}), "x86_64", style="readable")
        self.assertIn("x86_rep_movs8(", output.pseudoc)
        self.assertNotIn("unresolved_operation", output.pseudoc)
        helpers = ("static void x86_rep_movs8(uint64_t destination, uint64_t source, uint64_t count) {\n"
                   "    for (uint64_t i = 0; i < count; i++) ((uint8_t *)(uintptr_t)destination)[i] = ((const uint8_t *)(uintptr_t)source)[i];\n"
                   "}\n")
        signature = re.search(r"\bcopy_forward\(([^)]*)\)", output.pseudoc)[1]
        arguments = {"arg_1": "(uint64_t)(uintptr_t)(buffer + 1)", "arg_2": "(uint64_t)(uintptr_t)buffer", "arg_3": "6"}
        call = "copy_forward(" + ", ".join(arguments[item.split()[-1]] for item in signature.split(",")) + ")"
        compile_run(output.pseudoc,
                    "uint8_t buffer[16] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0};\n"
                    f"    uint64_t end = {call};\n"
                    "    for (int i = 1; i <= 6; i++) if (buffer[i] != 9) return 1;  /* 升序逐元素复制：重叠时重复首字节 */\n"
                    "    return end == (uint64_t)(uintptr_t)(buffer + 7) && buffer[7] == 2 ? 0 : 1;",
                    prefix=helpers)

    def test_readable_c_string_helpers_take_integer_arguments(self):
        # 目的寄存器被推断为指针（rep stosq/movsq 写栈上缓冲区）时，实参仍按文档原型
        # x86_rep_*64(uint64_t d, uint64_t v 或 s, uint64_t n) 传入，可直接编译。
        fill = [ins(0x1000, "push", "rbx", size=1), ins(0x1001, "mov", "rbx", "rdi", size=3),
                ins(0x1004, "sub", "rsp", "0x20", size=4), ins(0x1008, "mov", "qword ptr [rsp + 0x18]", "rsi", size=5),
                ins(0x100d, "mov", "rdi", "rsp", size=3), ins(0x1010, "xor", "eax", "eax", size=2),
                ins(0x1012, "mov", "ecx", "4", size=5), ins(0x1017, "rep stosq", "qword ptr [rdi]", "rax", size=3),
                ins(0x101a, "mov", "rax", "qword ptr [rsp + 0x18]", size=5), ins(0x101f, "add", "rsp", "0x20", size=4),
                ins(0x1023, "pop", "rbx", size=1), ins(0x1024, "ret", size=1, kind="return")]
        copy = [ins(0x1000, "sub", "rsp", "0x28", size=4), ins(0x1004, "mov", "qword ptr [rsp + 8]", "rdx", size=5),
                ins(0x1009, "mov", "rdi", "rsp", size=3), ins(0x100c, "mov", "ecx", "4", size=5),
                ins(0x1011, "rep movsq", "qword ptr [rdi]", "qword ptr [rsi]", size=3),
                ins(0x1014, "mov", "rax", "qword ptr [rsp + 8]", size=5), ins(0x1019, "add", "rsp", "0x28", size=4),
                ins(0x101d, "ret", size=1, kind="return")]
        outputs = {name: generate_pseudoc(fn(*rows, name=name, pseudoc_context={"kind": "elf"}), "x86_64", style="readable")
                   for name, rows in (("clear_spilled", fill), ("copy_spilled", copy))}
        for name, output in outputs.items():
            with self.subTest(name=name):
                self.assertRegex(output.pseudoc, r"x86_rep_(?:stos|movs)64\(")
                self.assertNotRegex(output.pseudoc, r"x86_rep_\w+\((?:[^;]*?, )?\(\w+ \*\)")
                self.assertNotIn("unresolved_operation", output.pseudoc)
        helpers = ("#include <string.h>\n"
                   "static void x86_rep_stos64(uint64_t destination, uint64_t value, uint64_t count) {\n"
                   "    for (uint64_t i = 0; i < count; i++) memcpy((void *)(uintptr_t)(destination + i * 8), &value, 8);\n"
                   "}\n"
                   "static void x86_rep_movs64(uint64_t destination, uint64_t source, uint64_t count) {\n"
                   "    for (uint64_t i = 0; i < count; i++)\n"
                   "        memmove((void *)(uintptr_t)(destination + i * 8), (const void *)(uintptr_t)(source + i * 8), 8);\n"
                   "}\n")
        text = outputs["clear_spilled"].pseudoc + "\n" + outputs["copy_spilled"].pseudoc
        clear = PointerAuthenticationTests._call("clear_spilled", text, {"arg_1": "1", "arg_2": "7"})
        copied = PointerAuthenticationTests._call("copy_spilled", text,
                                                 {"arg_2": "(uint64_t)(uintptr_t)source", "arg_3": "99"})
        # rep stosq 覆盖了溢出槽：读回 0；rep movsq 把 source[0..3] 复制到栈上，溢出槽读回 source[1]。
        compile_run(text, "uint64_t source[4] = {11, 22, 33, 44};\n"
                          f"    return {clear} == 0 && {copied} == 22 ? 0 : 1;", prefix=helpers)


class DeterminismTests(unittest.TestCase):
    def test_lifting_is_identical_across_hash_seeds(self):
        script = (
            "import json\n"
            "from fangida.plugins.pseudoc.microcode import lift_instruction\n"
            "from tests.test_pseudoc import instruction as ins\n"
            "rows = [('arm64', ins(0, 'paciasp', size=4)), ('arm64', ins(0, 'mrs', 'x1', 'nzcv', size=4)),\n"
            "        ('arm64', ins(0, 'msr', 'nzcv', 'x1', size=4)), ('arm64', ins(0, 'mrs', 'x8', 'tpidr_el0', size=4)),\n"
            "        ('arm64', ins(0, 'umlal2', 'v0.2d', 'v1.4s', 'v2.4s', size=4)), ('arm64', ins(0, 'rev64', 'v0.8h', 'v1.8h', size=4)),\n"
            "        ('x86_64', ins(0, 'rep movsq', 'qword ptr [rdi]', 'qword ptr [rsi]')), ('x86_64', ins(0, 'pblendw', 'xmm1', 'xmm0', '0x3f'))]\n"
            "print(json.dumps([lift_instruction(row, arch) for arch, row in rows], sort_keys=False))\n")
        outputs = set()
        for seed in ("0", "1", "12345"):
            result = subprocess.run([sys.executable, "-c", script], cwd=_ROOT, capture_output=True, text=True,
                                    env={**os.environ, "PYTHONHASHSEED": seed}, timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs.add(result.stdout)
        self.assertEqual(len(outputs), 1)


if __name__ == "__main__":
    unittest.main()
