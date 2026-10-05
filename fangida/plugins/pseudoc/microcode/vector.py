"""SIMD/FP 寄存器的整宽搬移、清零与按位运算（x86 SSE/AVX-128、AArch64 AdvSIMD）。

只覆盖能用定宽位向量精确表达的指令：寄存器/内存整体搬移、低位标量搬移（高位清零或
保留）、通道插入/提取、广播、立即数、按位与/或/异或/取反以及 64 位通道交织。按通道
的整数算术、比较、窄化/扩展、移位等运算由 vector_lanes.py（语义见 lane_ops.py）处理；
浮点通道运算等其余形式继续保持 opaque。

向量寄存器的根名沿用已有约定：x86 为 xmmN，AArch64 为 vN（与浮点处理器一致），
存储宽度均为 128 位。为了让还原出的 C 能直接编译，表达式只使用 8/16/32/64/128
这些标准宽度：插入通道时用移位清除旧位段，而不是非标准宽度的截断。
"""
from __future__ import annotations

import re
import struct

from .common import assignment, lifted, resize, value
from .ir import Expression, MicroOperation, constant

# ---------------------------------------------------------------------------
# 操作数识别（只读解析已解码的文本操作数，不读取指令字节）
# ---------------------------------------------------------------------------

_XMM = re.compile(r"xmm([0-9]|[12][0-9]|3[01])")
# x86 内存操作数：宽度前缀 + 方括号地址；段前缀等其它写法交给通用路径（保持 opaque）。
_X86_MEMORY = re.compile(r"(byte|word|dword|qword|xmmword|oword)\s+ptr\s+(\[[^\]]+\])", re.I)
_X86_MEMORY_WIDTHS = {"byte": 8, "word": 16, "dword": 32, "qword": 64, "xmmword": 128, "oword": 128}
# AArch64：整寄存器排列 vN.T、单个通道 vN.T[i]、标量 FP/SIMD 寄存器 b/h/s/d/qN。
_A64_ARRANGEMENT = re.compile(r"v([0-9]|[12][0-9]|3[01])\.(8b|16b|4h|8h|2s|4s|1d|2d)")
_A64_LANE = re.compile(r"v([0-9]|[12][0-9]|3[01])\.([bhsd])\[(0x[0-9a-f]+|[0-9]+)\]")
_A64_SCALAR = re.compile(r"([bhsdq])([0-9]|[12][0-9]|3[01])")
_ARRANGEMENT_LANES = {"8b": (8, 64), "16b": (8, 128), "4h": (16, 64), "8h": (16, 128),
                      "2s": (32, 64), "4s": (32, 128), "1d": (64, 64), "2d": (64, 128)}
_LANE_BITS = {"b": 8, "h": 16, "s": 32, "d": 64, "q": 128}
_LSL_MODIFIER = re.compile(r"lsl\s+#?(0x[0-9a-f]+|[0-9]+)")

# x86 整寄存器搬移；带 a 的形式要求内存操作数 16 字节对齐（否则 #GP）。
_X86_FULL_MOVES = {"movaps": 16, "movapd": 16, "movdqa": 16, "movups": 1, "movupd": 1, "movdqu": 1,
                   "lddqu": 1, "movntdq": 16, "movntps": 16, "movntpd": 16,
                   "vmovaps": 16, "vmovapd": 16, "vmovdqa": 16, "vmovups": 1, "vmovupd": 1, "vmovdqu": 1}
# lddqu 只能从内存读取，movnt* 只能写内存。
_X86_LOAD_ONLY = frozenset({"lddqu"})
_X86_STORE_ONLY = frozenset({"movntdq", "movntps", "movntpd"})
# x86 128 位按位运算：(运算, 是否先对目的操作数取反)。整型与单/双精度形式只是解码域不同，位运算结果相同。
_X86_BITWISE = {"pxor": ("xor", False), "xorps": ("xor", False), "xorpd": ("xor", False),
                "por": ("or", False), "orps": ("or", False), "orpd": ("or", False),
                "pand": ("and", False), "andps": ("and", False), "andpd": ("and", False),
                "pandn": ("and", True), "andnps": ("and", True), "andnpd": ("and", True)}
# AArch64 按位向量指令：(运算, 是否对第二个源取反)。
_A64_BITWISE = {"and": ("and", False), "orr": ("or", False), "eor": ("xor", False),
                "bic": ("and", True), "orn": ("or", True)}
# AArch64 FMOV 立即数只能是 ±n/16 * 2^r（n 为 16..31，r 为 -3..4）：解码文本必须精确等于其中之一。
_FMOV_IMMEDIATES = frozenset(sign * n / 16 * 2.0 ** r for sign in (1, -1) for n in range(16, 32) for r in range(-3, 5))


def _xmm(operand):
    match = _XMM.fullmatch(operand.lower().strip())
    return "xmm" + match[1] if match else None


def _x86_memory(op, operand):
    """(宽度, 地址文本, 地址表达式)；不是受支持的内存操作数时返回 None。"""
    match = _X86_MEMORY.fullmatch(operand.strip())
    if match is None:
        return None
    address = op.address(match[2])
    return _X86_MEMORY_WIDTHS[match[1].lower()], address, Expression("address", op.bits, name=address)


def _number(text):
    raw = text.strip().lstrip("#").strip().lower()
    negative = raw.startswith("-")
    raw = raw.lstrip("-")
    number = int(raw, 16) if raw.startswith("0x") else int(raw, 10)
    return -number if negative else number


def _vector(root):
    return Expression("register", 128, name=root)


def _low(expression, width):
    """表达式的低 width 位（width 为标准宽度）。"""
    return expression if expression.width == width else Expression("truncate", width, (expression,))


def _field(expression, shift, width):
    """第 shift 位起的 width 位通道。"""
    if not shift:
        return _low(expression, width)
    return Expression("extract", width, (expression,), value=shift)


def _shl(expression, count):
    return Expression("shl", expression.width, (expression, constant(count, expression.width))) if count else expression


def _lshr(expression, count):
    return Expression("lshr", expression.width, (expression, constant(count, expression.width))) if count else expression


def _or(*parts):
    result = parts[0]
    for part in parts[1:]:
        result = Expression("or", 128, (result, part))
    return result


def _merge(old, lane, shift, width):
    """把 width 位的 lane 写入 128 位旧值 old 的 [shift, shift+width) 位，其余位保持不变。

    只用移位清除旧位段（不需要超过 64 位的掩码常量，也不产生非标准宽度的截断）。
    """
    parts = []
    if shift:
        parts.append(_lshr(_shl(old, 128 - shift), 128 - shift))
    parts.append(_shl(resize(lane, 128), shift))
    top = shift + width
    if top < 128:
        parts.append(_shl(_lshr(old, top), top))
    return _or(*parts)


def _replicate(lane, width, total):
    """把 width 位的 lane 复制到 total 位（再零扩展到 128 位）。

    乘以每隔 width 位放一个 1 的常量：各副本互不重叠、没有进位，结果逐位精确。
    """
    if lane.opcode == "constant":
        number = 0
        for index in range(total // width):
            number |= (lane.value & ((1 << width) - 1)) << (index * width)
        return constant(number, 128)
    pattern = sum(1 << (index * width) for index in range(total // width))
    widened = resize(lane, 128)
    return widened if pattern == 1 else Expression("mul", 128, (widened, constant(pattern, 128)))


def _vector_write(context, root, expression, **extra):
    context.vector_registers.add(root)
    attributes = {"destination_width": 128, "storage_width": 128, "bit_offset": 0, "zero_upper": False, **extra}
    return MicroOperation("assign", 128, (expression,), root, expression, attributes)


def _vector_store(width, address, source, **extra):
    return MicroOperation("store", width, (address, source),
                          attributes={"effect": "write", "endianness": "architecture", **extra})


# ---------------------------------------------------------------------------
# x86 SSE / AVX-128
# ---------------------------------------------------------------------------

def _x86_full_move(context, row, args, op, mnemonic):
    if len(args) != 2:
        return None
    alignment = _X86_FULL_MOVES[mnemonic]
    vex = mnemonic.startswith("v")
    extra = {"alignment": alignment, "alignment_fault": alignment > 1}
    if vex:
        extra["upper_bits"] = "zeroed_above_128"
    destination, source = _xmm(args[0]), _xmm(args[1])
    if destination and source and mnemonic not in _X86_LOAD_ONLY | _X86_STORE_ONLY:
        return lifted(context, row, "data_transfer", [f"{destination} = {source};"],
                      [_vector_write(context, destination, _vector(source), **({"upper_bits": extra["upper_bits"]} if vex else {}))])
    if destination and mnemonic not in _X86_STORE_ONLY:
        memory = _x86_memory(op, args[1])
        if memory is None or memory[0] != 128:
            return None
        _, address, address_expression = memory
        loaded = Expression("load", 128, (address_expression,))
        return lifted(context, row, "memory", [f"{destination} = load128({address});"],
                      [_vector_write(context, destination, loaded, memory_width=128, **extra)])
    if source and mnemonic not in _X86_LOAD_ONLY:
        memory = _x86_memory(op, args[0])
        if memory is None or memory[0] != 128:
            return None
        _, address, address_expression = memory
        context.vector_registers.add(source)
        return lifted(context, row, "memory", [f"store128({address}, {source});"],
                      [_vector_store(128, address_expression, _vector(source), **extra)])
    return None


def _x86_scalar_move(context, row, args, op, mnemonic):
    """movd/movq/vmovd/vmovq 与 movss/movsd：低 32/64 位搬移。

    写 xmm 的 movd/movq 与“从内存读入”的 movss/movsd 清零其余高位；寄存器之间的
    movss/movsd 只替换低位、保留高位。MMX 寄存器（mmN）不在此建模。
    """
    if len(args) != 2:
        return None
    base = mnemonic.removeprefix("v")
    width = 32 if base in {"movd", "movss"} else 64
    merge_low = base in {"movss", "movsd"}
    destination, source = _xmm(args[0]), _xmm(args[1])
    if destination and source:
        context.vector_registers.add(source)
        if merge_low:
            if mnemonic.startswith("v"):
                return None  # VEX 形式是三操作数合并，留给通用路径
            expression = _merge(_vector(destination), _low(_vector(source), width), 0, width)
            text = f"{destination} = vector_insert{width}({destination}, 0, (uint{width}_t){source});"
        else:
            if base == "movd":
                return None  # movd 不存在 xmm 到 xmm 的编码
            expression = resize(_low(_vector(source), 64), 128)
            text = f"{destination} = (vector128_t)(uint64_t){source};"
        return lifted(context, row, "data_transfer", [text], [_vector_write(context, destination, expression)])
    if destination:
        register = op.register(args[1])
        if register is not None:
            if merge_low or register.bits != width:
                return None
            gpr = value(op, args[1])
            text = op.read(args[1])
            return lifted(context, row, "data_transfer", [f"{destination} = (vector128_t)(uint{width}_t)({text});"],
                          [_vector_write(context, destination, resize(gpr, 128))])
        memory = _x86_memory(op, args[1])
        if memory is None or memory[0] != width:
            return None
        _, address, address_expression = memory
        loaded = Expression("load", width, (address_expression,))
        return lifted(context, row, "memory", [f"{destination} = (vector128_t)load{width}({address});"],
                      [_vector_write(context, destination, resize(loaded, 128), memory_width=width, upper_lanes="zero")])
    if source:
        context.vector_registers.add(source)
        lane = _low(_vector(source), width)
        register = op.register(args[0])
        if register is not None:
            if merge_low or register.bits != width:
                return None
            return lifted(context, row, "data_transfer", [op.write(args[0], f"(uint{width}_t){source}")],
                          [assignment(op, args[0], lane)])
        memory = _x86_memory(op, args[0])
        if memory is None or memory[0] != width:
            return None
        _, address, address_expression = memory
        return lifted(context, row, "memory", [f"store{width}({address}, (uint{width}_t){source});"],
                      [_vector_store(width, address_expression, lane)])
    return None


def _x86_source(context, op, operand):
    """128 位源操作数（xmm 或 xmmword 内存）：(文本, 表达式)。"""
    register = _xmm(operand)
    if register:
        context.vector_registers.add(register)
        return register, _vector(register)
    memory = _x86_memory(op, operand)
    if memory is None or memory[0] != 128:
        raise ValueError("Unsupported 128-bit vector source")
    return f"load128({memory[1]})", Expression("load", 128, (memory[2],))


def _x86_bitwise(context, row, args, op, mnemonic):
    vex = mnemonic.startswith("v")
    base = mnemonic[1:] if vex else mnemonic
    if base not in _X86_BITWISE or len(args) != (3 if vex else 2):
        return None
    destination = _xmm(args[0])
    if destination is None:
        return None
    left_operand, right_operand = (args[1], args[2]) if vex else (args[0], args[1])
    opcode, invert = _X86_BITWISE[base]
    left_text, left = _x86_source(context, op, left_operand)
    right_text, right = _x86_source(context, op, right_operand)
    if opcode == "xor" and not invert and left == right and left.opcode == "register":
        # 清零惯用法 pxor x, x / xorps x, x：结果恒为 0，不依赖原值。
        return lifted(context, row, "bitwise", [f"{destination} = vector_zero128();"],
                      [_vector_write(context, destination, constant(0, 128), idiom="zero")])
    if invert:
        left = Expression("not", 128, (left,))
        left_text = f"~{left_text}"
    expression = Expression(opcode, 128, (left, right))
    symbol = {"and": "&", "or": "|", "xor": "^"}[opcode]
    extra = {"upper_bits": "zeroed_above_128"} if vex else {}
    if right.opcode == "load" and not vex:
        extra["alignment"], extra["alignment_fault"] = 16, True
    return lifted(context, row, "bitwise", [f"{destination} = {left_text} {symbol} {right_text};"],
                  [_vector_write(context, destination, expression, **extra)])


def _x86_interleave(context, row, args, op, mnemonic):
    """64 位通道交织：punpcklqdq/unpcklpd/movlhps 取两者低半，punpckhqdq/unpckhpd 取两者高半，
    movhlps 用源的高半替换目的的低半。"""
    if len(args) != 2:
        return None
    destination = _xmm(args[0])
    if destination is None:
        return None
    if mnemonic in {"movlhps", "movhlps"} and _xmm(args[1]) is None:
        return None  # 这两条只有寄存器形式
    source_text, source = _x86_source(context, op, args[1])
    context.vector_registers.add(destination)
    old = _vector(destination)
    if mnemonic in {"punpcklqdq", "unpcklpd", "movlhps"}:
        expression = _or(resize(_low(old, 64), 128), _shl(resize(_low(source, 64), 128), 64))
        text = f"{destination} = vector_pair64((uint64_t){destination}, (uint64_t){source_text});"
    elif mnemonic in {"punpckhqdq", "unpckhpd"}:
        expression = _or(_lshr(old, 64), _shl(_lshr(source, 64), 64))
        text = f"{destination} = vector_pair64(high64({destination}), high64({source_text}));"
    else:  # movhlps
        expression = _or(_lshr(source, 64), _shl(_lshr(old, 64), 64))
        text = f"{destination} = vector_pair64(high64({source_text}), high64({destination}));"
    extra = {"alignment": 16, "alignment_fault": True} if source.opcode == "load" else {}
    return lifted(context, row, "memory" if source.opcode == "load" else "data_transfer", [text],
                  [_vector_write(context, destination, expression, **extra)])


def _x86(context, row, args, op, mnemonic):
    if mnemonic in _X86_FULL_MOVES:
        return _x86_full_move(context, row, args, op, mnemonic)
    if mnemonic in {"movd", "movq", "vmovd", "vmovq", "movss", "movsd"}:
        return _x86_scalar_move(context, row, args, op, mnemonic)
    if mnemonic in {"punpcklqdq", "punpckhqdq", "unpcklpd", "unpckhpd", "movlhps", "movhlps"}:
        return _x86_interleave(context, row, args, op, mnemonic)
    return None


# ---------------------------------------------------------------------------
# AArch64 AdvSIMD / FP
# ---------------------------------------------------------------------------

def _arrangement(operand):
    match = _A64_ARRANGEMENT.fullmatch(operand.lower().strip())
    if match is None:
        return None
    lane, total = _ARRANGEMENT_LANES[match[2]]
    return "v" + match[1], lane, total


def _lane(operand):
    match = _A64_LANE.fullmatch(operand.lower().strip())
    if match is None:
        return None
    width = _LANE_BITS[match[2]]
    index = int(match[3], 16 if match[3].startswith("0x") else 10)
    if not 0 <= index < 128 // width:
        raise ValueError("Vector lane index out of range")
    return "v" + match[1], width, index


def _scalar(operand):
    match = _A64_SCALAR.fullmatch(operand.lower().strip())
    return ("v" + match[2], _LANE_BITS[match[1]]) if match else None


def _gpr(op, operand):
    register = op.register(operand)
    if register is None or register.root == "sp" or register.bits not in {32, 64}:
        return None
    return register


def _a64_write_scalar(context, row, root, expression, width, text, category="data_transfer"):
    # 写入 b/h/s/d 标量寄存器会清零 V 寄存器的其余高位。
    return lifted(context, row, category, [text],
                  [_vector_write(context, root, resize(expression, 128), lane_width=width, upper_lanes="zero")])


def _fmov_immediate(text, width):
    raw = text.strip().lstrip("#").strip()
    number = float(raw)
    if number not in _FMOV_IMMEDIATES:
        raise ValueError("Not an FMOV floating immediate")
    if width == 64:
        return struct.unpack("<Q", struct.pack("<d", number))[0]
    if width == 32:
        return struct.unpack("<I", struct.pack("<f", number))[0]
    return struct.unpack("<H", struct.pack("<e", number))[0]


def _a64_fmov(context, row, args, op):
    if len(args) != 2:
        return None
    destination, source = args[0].lower().strip(), args[1].lower().strip()
    target, origin = _scalar(destination), _scalar(source)
    arrangement = _arrangement(destination) if "." in destination else None
    if arrangement and source.startswith("#") and arrangement[1] in {16, 32, 64}:
        # FMOV（向量立即数）：把同一个浮点位模式复制到每个通道。
        root, width, total = arrangement
        bits = _fmov_immediate(source, width)
        expression = _replicate(constant(bits, width), width, total)
        return lifted(context, row, "data_transfer", [f"{root} = {hex(expression.value)}; /* {source.lstrip('#')} x{total // width} */"],
                      [_vector_write(context, root, expression, lane_width=width, upper_lanes="zero" if total < 128 else "full")])
    if target and target[1] in {16, 32, 64}:
        root, width = target
        if origin:
            if origin[1] != width:
                return None
            context.vector_registers.add(origin[0])
            lane = _low(_vector(origin[0]), width)
            return _a64_write_scalar(context, row, root, lane, width, f"{root} = (vector128_t)(uint{width}_t){origin[0]};")
        register = _gpr(op, source) or (op.register(source) if source in {"xzr", "wzr"} else None)
        if register is not None:
            if register.bits != (64 if width == 64 else 32):
                return None
            lane = _low(value(op, source), width)
            return _a64_write_scalar(context, row, root, lane, width,
                                     f"{root} = (vector128_t)(uint{width}_t)({op.read(source)});")
        if source.startswith("#"):
            bits = _fmov_immediate(source, width)
            return _a64_write_scalar(context, row, root, constant(bits, width), width,
                                     f"{root} = (vector128_t){hex(bits)}; /* {source.lstrip('#')} */")
        return None
    register = _gpr(op, destination)
    if register is not None:
        if origin and origin[1] in {16, 32, 64}:
            root, width = origin
            if register.bits != (64 if width == 64 else 32):
                return None
            context.vector_registers.add(root)
            return lifted(context, row, "data_transfer", [op.write(destination, f"(uint{width}_t){root}")],
                          [assignment(op, destination, resize(_low(_vector(root), width), register.bits))])
        lane = _lane(source)
        if lane and lane[1:] == (64, 1) and register.bits == 64:
            root = lane[0]
            context.vector_registers.add(root)
            return lifted(context, row, "data_transfer", [op.write(destination, f"high64({root})")],
                          [assignment(op, destination, _field(_vector(root), 64, 64))])
        return None
    lane = _lane(destination)
    if lane and lane[1:] == (64, 1):
        gpr = _gpr(op, source) or (op.register(source) if source == "xzr" else None)
        if gpr is None or gpr.bits != 64:
            return None
        root = lane[0]
        context.vector_registers.add(root)
        expression = _merge(_vector(root), value(op, source), 64, 64)
        return lifted(context, row, "data_transfer", [f"{root} = vector_insert64({root}, 1, {op.read(source)});"],
                      [_vector_write(context, root, expression)])
    return None


def _a64_lane_moves(context, row, args, op, mnemonic):
    """mov/umov/smov/ins/dup 的通道插入、提取与标量复制。"""
    destination, source = args[0].lower().strip(), args[1].lower().strip()
    target_lane, source_lane = _lane(destination), _lane(source)
    if target_lane and mnemonic in {"mov", "ins"}:
        root, width, index = target_lane
        context.vector_registers.add(root)
        if source_lane:
            if source_lane[1] != width:
                return None
            context.vector_registers.add(source_lane[0])
            lane = _field(_vector(source_lane[0]), source_lane[1] * source_lane[2], width)
            source_text = f"lane{width}({source_lane[0]}, {source_lane[2]})"
        else:
            register = _gpr(op, source) or (op.register(source) if source in {"xzr", "wzr"} else None)
            if register is None or register.bits != (64 if width == 64 else 32):
                return None
            lane = _low(value(op, source), width)
            source_text = op.read(source)
        expression = _merge(_vector(root), lane, width * index, width)
        return lifted(context, row, "data_transfer",
                      [f"{root} = vector_insert{width}({root}, {index}, {source_text});"],
                      [_vector_write(context, root, expression)])
    if source_lane and mnemonic in {"mov", "umov", "smov"}:
        root, width, index = source_lane
        register = _gpr(op, destination)
        lane = _field(_vector(root), width * index, width)
        if register is not None:
            signed = mnemonic == "smov"
            # UMOV/MOV 读取与目的同宽的通道（x 对应 d、w 对应 b/h/s）；SMOV 只做带符号扩展。
            if signed and not (width < register.bits and width <= 32):
                return None
            if not signed and (width == 64) != (register.bits == 64):
                return None
            context.vector_registers.add(root)
            cast = "int" if signed else "uint"
            return lifted(context, row, "data_transfer",
                          [op.write(destination, f"({cast}{width}_t)lane{width}({root}, {index})")],
                          [assignment(op, destination, resize(lane, register.bits, signed=signed))])
        scalar = _scalar(destination)
        if scalar and scalar[1] == width and mnemonic == "mov":
            # mov dN, vM.d[i]（DUP 标量形式）：取出通道并清零其余高位。
            context.vector_registers.add(root)
            return _a64_write_scalar(context, row, scalar[0], lane, width,
                                     f"{scalar[0]} = (vector128_t)lane{width}({root}, {index});")
    return None


def _a64_dup(context, row, args, op):
    if len(args) != 2:
        return None
    arrangement = _arrangement(args[0])
    if arrangement is None:
        lane = _lane(args[1])
        scalar = _scalar(args[0])
        if lane and scalar and scalar[1] == lane[1]:
            # dup dN, vM.d[i]：标量形式与 mov 别名相同。
            return _a64_lane_moves(context, row, args, op, "mov")
        return None
    root, width, total = arrangement
    source_lane = _lane(args[1])
    if source_lane:
        if source_lane[1] != width:
            return None
        context.vector_registers.add(source_lane[0])
        lane = _field(_vector(source_lane[0]), width * source_lane[2], width)
        source_text = f"lane{width}({source_lane[0]}, {source_lane[2]})"
    else:
        register = _gpr(op, args[1]) or (op.register(args[1]) if args[1].lower().strip() in {"xzr", "wzr"} else None)
        if register is None or register.bits != (64 if width == 64 else 32):
            return None
        lane = _low(value(op, args[1]), width)
        source_text = op.read(args[1])
    expression = _replicate(lane, width, total)
    return lifted(context, row, "data_transfer", [f"{root} = vector_broadcast{width}x{total // width}({source_text});"],
                  [_vector_write(context, root, expression, lane_width=width, upper_lanes="zero" if total < 128 else "full")])


def _a64_movi(context, row, args, op):
    if len(args) not in {2, 3}:
        return None
    immediate = _number(args[1])
    shift = 0
    if len(args) == 3:
        match = _LSL_MODIFIER.fullmatch(args[2].lower().strip())
        if match is None:
            return None  # MSL（移入 1）形式不在这里建模
        shift = int(match[1], 16 if match[1].startswith("0x") else 10)
    scalar = _scalar(args[0])
    if scalar:
        if scalar[1] != 64 or shift or not 0 <= immediate < 1 << 64:
            return None
        root, width, total = scalar[0], 64, 64
        lane_value = immediate
    else:
        arrangement = _arrangement(args[0])
        if arrangement is None:
            return None
        root, width, total = arrangement
        if width == 64:
            if shift or not 0 <= immediate < 1 << 64:
                return None
            lane_value = immediate
        else:
            if not 0 <= immediate <= 0xff or shift not in ({0} if width == 8 else {0, 8} if width == 16 else {0, 8, 16, 24}):
                return None
            lane_value = immediate << shift
    if width == 64 and any(((lane_value >> bit) & 0xff) not in {0, 0xff} for bit in range(0, 64, 8)):
        raise ValueError("A64 MOVI 64-bit immediate must be a byte mask")
    expression = _replicate(constant(lane_value, width), width, total)
    text = "vector_zero128()" if not expression.value else hex(expression.value)
    return lifted(context, row, "data_transfer", [f"{root} = {text};"],
                  [_vector_write(context, root, expression, lane_width=width, upper_lanes="zero" if total < 128 else "full")])


def _a64_bitwise(context, row, args, op, mnemonic):
    if mnemonic in {"not", "mvn"}:
        if len(args) != 2:
            return None
        target, source = _arrangement(args[0]), _arrangement(args[1])
        if not target or not source or target[1:] != source[1:] or target[1] != 8:
            return None
        total = target[2]
        context.vector_registers.add(source[0])
        expression = resize(Expression("not", total, (_low(_vector(source[0]), total),)), 128)
        return lifted(context, row, "bitwise", [f"{target[0]} = ~{source[0]};"],
                      [_vector_write(context, target[0], expression, upper_lanes="zero" if total < 128 else "full")])
    if len(args) != 3:
        return None
    operands = [_arrangement(arg) for arg in args]
    if not all(operands) or len({item[1:] for item in operands}) != 1 or operands[0][1] != 8:
        return None
    total = operands[0][2]
    opcode, invert = _A64_BITWISE[mnemonic]
    for item in operands[1:]:
        context.vector_registers.add(item[0])
    left, right = (_low(_vector(item[0]), total) for item in operands[1:])
    if invert:
        right = Expression("not", total, (right,))
    if opcode == "xor" and not invert and operands[1][0] == operands[2][0]:
        # eor v, x, x：清零惯用法，与源寄存器无关。
        expression = constant(0, 128)
        text = f"{operands[0][0]} = vector_zero128();"
    else:
        expression = resize(Expression(opcode, total, (left, right)), 128)
        if opcode in {"and", "or"} and not invert and operands[1][0] == operands[2][0]:
            # orr v, x, x 即寄存器搬移（mov 别名）。
            expression = resize(left, 128)
        symbol = {"and": "&", "or": "|", "xor": "^"}[opcode]
        text = f"{operands[0][0]} = {operands[1][0]} {symbol} {'~' if invert else ''}{operands[2][0]};"
    return lifted(context, row, "bitwise", [text],
                  [_vector_write(context, operands[0][0], expression, upper_lanes="zero" if total < 128 else "full")])


def _a64(context, row, args, op, mnemonic):
    if mnemonic == "fmov":
        return _a64_fmov(context, row, args, op)
    if mnemonic == "movi":
        return _a64_movi(context, row, args, op)
    if mnemonic == "dup":
        return _a64_dup(context, row, args, op)
    if mnemonic in {"mov", "umov", "smov", "ins"} and len(args) == 2:
        if "." not in args[0] and "." not in args[1]:
            return None  # 通用寄存器之间的 mov（最常见）：没有向量排列或通道写法，直接交给标量路径
        target, source = _arrangement(args[0]), _arrangement(args[1])
        if target or source:
            # mov vD.T, vN.T（ORR 别名）：整寄存器或低 64 位搬移。
            if not target or not source or target[1:] != source[1:] or mnemonic != "mov":
                return None
            total = target[2]
            context.vector_registers.add(source[0])
            expression = resize(_low(_vector(source[0]), total), 128)
            return lifted(context, row, "data_transfer", [f"{target[0]} = {source[0]};"],
                          [_vector_write(context, target[0], expression, upper_lanes="zero" if total < 128 else "full")])
        return _a64_lane_moves(context, row, args, op, mnemonic)
    return None


def _x86_bitwise_mnemonic(mnemonic):
    return mnemonic in _X86_BITWISE or (mnemonic.startswith("v") and mnemonic[1:] in _X86_BITWISE)


def lift_transfer(context, row, args, op):
    """向量/浮点寄存器搬移（含清零与立即数）；不认识的形式返回 None，交给其它处理器或 opaque。"""
    mnemonic = str(row["mnemonic"]).lower()
    if context.architecture.startswith("x86"):
        return _x86(context, row, args, op, mnemonic)
    if context.architecture == "arm64":
        return _a64(context, row, args, op, mnemonic)
    return None


def lift_bitwise(context, row, args, op):
    """128/64 位向量按位运算（含 pxor/eor 清零惯用法）；不认识的形式返回 None。"""
    mnemonic = str(row["mnemonic"]).lower()
    if context.architecture.startswith("x86"):
        return _x86_bitwise(context, row, args, op, mnemonic) if _x86_bitwise_mnemonic(mnemonic) else None
    if context.architecture == "arm64" and (mnemonic in _A64_BITWISE or mnemonic in {"not", "mvn"}):
        if not args or "." not in args[0]:
            return None  # 标量 and/orr/eor/bic/orn/mvn 交给通用位运算路径
        return _a64_bitwise(context, row, args, op, mnemonic)
    return None
