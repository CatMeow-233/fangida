"""Moves, address formation, alias writes and scalar type conversions."""
from __future__ import annotations

from .common import assignment, lifted, resize, value
from .ir import Expression, MicroOperation
from .ir import constant
from . import vector, vector_lanes
import re

# 模块级预编译正则（与原字符串模式及标志位一致）。
_VECTOR_ARRANGEMENT = re.compile(r"v([0-9]|[12][0-9]|3[01])\.(2d|4s|8h|16b)")
_WIDE_MOVE_SHIFT = re.compile(r"lsl\s+#?(\d+)")
_ARM32_IMMEDIATE16 = re.compile(r"#?(0x[0-9a-fA-F]+|[0-9]+)")


def _arm32_wide_move(context, row, args, op, mnemonic):
    """AArch32 movw（零扩展装入低 16 位）与 movt（只替换高 16 位，保留低 16 位）。"""
    register = op.register(args[0])
    match = _ARM32_IMMEDIATE16.fullmatch(args[1].strip())
    if register is None or register.bits != 32 or match is None:
        raise ValueError("Invalid AArch32 wide-move operands")
    immediate = int(match[1], 16 if match[1].lower().startswith("0x") else 10)
    if not 0 <= immediate <= 0xffff:
        raise ValueError("AArch32 wide-move immediate exceeds imm16")
    if mnemonic == "movw":
        expression = constant(immediate, 32)
        text = hex(immediate)
    else:
        expression = Expression("or", 32, (Expression("and", 32, (value(op, args[0]), constant(0xffff, 32))),
                                           constant(immediate << 16, 32)))
        text = f"(({op.read(args[0])} & 0xffffU) | {hex(immediate << 16)}U)"
    return lifted(context, row, "data_transfer", [op.write(args[0], text)], [assignment(op, args[0], expression)])


def lift(context, row, args, op):
    mnemonic = str(row["mnemonic"]).lower()
    x86 = context.architecture.startswith("x86")
    # SIMD/FP 寄存器的整宽搬移、清零、通道插入/提取与立即数（见 vector.py）。
    moved = vector.lift_transfer(context, row, args, op)
    if moved is not None:
        return moved
    if context.architecture == "arm" and mnemonic in {"movw", "movt"} and len(args) == 2:
        return _arm32_wide_move(context, row, args, op, mnemonic)
    if context.architecture == "arm64" and mnemonic == "movi" and len(args) == 2:
        match = _VECTOR_ARRANGEMENT.fullmatch(args[0].lower())
        raw = args[1].lstrip("#").strip()
        if match and int(raw, 16 if "0x" in raw else 10) == 0:
            root = "v" + match[1]
            context.vector_registers.add(root)
            expression = constant(0, 128)
            return lifted(context, row, "data_transfer", [f"{root} = vector_zero128();"],
                [MicroOperation("assign", 128, (expression,), root, expression,
                    {"destination_width": 128, "storage_width": 128, "bit_offset": 0, "zero_upper": False})])
    if context.architecture == "arm64" and mnemonic in {"movz", "movn", "movk"} and len(args) in {2, 3}:
        register = op.register(args[0])
        raw = args[1].lstrip("#$").strip()
        raw_immediate = int(raw, 16 if "0x" in raw.lower() else 10)
        immediate = value(op, args[1], 16)
        shift = 0
        if len(args) == 3:
            match = _WIDE_MOVE_SHIFT.fullmatch(args[2].lower())
            if match is None:
                raise ValueError("Invalid wide-move shift")
            shift = int(match[1])
        if register is None or register.root == "sp" or immediate.opcode != "constant" or not 0 <= raw_immediate <= 0xffff or shift not in range(0, register.bits, 16):
            raise ValueError("Invalid wide-move operands")
        width = register.bits
        inserted = constant(immediate.value << shift, width)
        expression = inserted
        if mnemonic == "movn":
            expression = constant((~inserted.value) & ((1 << width) - 1), width)
        elif mnemonic == "movk":
            mask = ((1 << width) - 1) ^ (0xffff << shift)
            expression = Expression("or", width, (Expression("and", width, (value(op, args[0]), constant(mask, width))), inserted))
        text = hex(expression.value) if expression.opcode == "constant" else f"(({op.read(args[0])} & {hex(mask)}ULL) | {hex(inserted.value)}ULL)"
        return lifted(context, row, "data_transfer", [op.write(args[0], text)], [assignment(op, args[0], expression)])
    if mnemonic in {"mov", "movabs"} and len(args) == 2:
        width = op.width(args[0], op.width(args[1]))
        source = value(op, args[1], width)
        category = "memory" if "[" in args[0] or "[" in args[1] else "data_transfer"
        return lifted(context, row, category,
            [op.write(args[0], op.read(args[1], width), op.width(args[1]))], [assignment(op, args[0], source)])
    if context.architecture == "arm64" and mnemonic in {"adr", "adrp"} and len(args) == 2:
        # The decoder supplies an absolute address, including ADRP's PC page
        # calculation. It must not be reinterpreted as a raw displacement.
        source = value(op, args[1], 64)
        if source.opcode != "constant" or (mnemonic == "adrp" and source.value & 0xfff):
            raise ValueError("Missing normalized PC-relative address")
        return lifted(context, row, "data_transfer", [op.write(args[0], hex(source.value))],
            [assignment(op, args[0], source)])
    if x86 and mnemonic in {"movzx", "movsx", "movsxd"} and len(args) == 2:
        source_bits = op.width(args[1], 32 if mnemonic == "movsxd" else 8)
        is_signed = mnemonic != "movzx"
        expression = resize(value(op, args[1], source_bits), op.width(args[0]), signed=is_signed)
        cast = "int" if is_signed else "uint"
        return lifted(context, row, "conversion",
            [op.write(args[0], f"({cast}{source_bits}_t)({op.read(args[1], source_bits)})")],
            [assignment(op, args[0], expression)])
    if x86 and mnemonic in {"cbw", "cwde", "cdqe"} and not args:
        # 累加器原地符号扩展：ax = (int8_t)al、eax = (int16_t)ax、rax = (int32_t)eax。
        if mnemonic == "cdqe" and context.architecture != "x86_64":
            return None
        bits, source, target = {"cbw": (8, "al", "ax"), "cwde": (16, "ax", "eax"), "cdqe": (32, "eax", "rax")}[mnemonic]
        expression = resize(value(op, source, bits), bits * 2, signed=True)
        return lifted(context, row, "conversion", [op.write(target, f"(int{bits}_t)({op.read(source, bits)})")],
                      [assignment(op, target, expression)])
    if x86 and mnemonic in {"cwd", "cdq", "cqo"} and not args:
        # dx/edx/rdx 填满累加器的符号位：负数为全 1，否则为 0（写成 0 - 符号位，避免带符号右移）。
        if mnemonic == "cqo" and context.architecture != "x86_64":
            return None
        bits, source, target = {"cwd": (16, "ax", "dx"), "cdq": (32, "eax", "edx"), "cqo": (64, "rax", "rdx")}[mnemonic]
        sign = Expression("lshr", bits, (value(op, source, bits), constant(bits - 1, bits)))
        expression = Expression("neg", bits, (sign,))
        return lifted(context, row, "conversion",
                      [op.write(target, f"(uint{bits}_t)0 - ({op.read(source, bits)} >> {bits - 1})")],
                      [assignment(op, target, expression)])
    if x86 and mnemonic == "lea" and len(args) == 2:
        address = op.address(args[1])
        return lifted(context, row, "data_transfer", [op.write(args[0], address)],
            [assignment(op, args[0], Expression("address", op.bits, name=address))])
    if mnemonic in {"sxtb", "sxth", "sxtw", "uxtb", "uxth", "uxtw"} and len(args) == 2:
        bits = {"b": 8, "h": 16, "w": 32}[mnemonic[-1]]
        source = resize(value(op, args[1]), bits)
        expression = resize(source, op.width(args[0]), signed=mnemonic.startswith("s"))
        cast = "int" if mnemonic.startswith("s") else "uint"
        return lifted(context, row, "conversion", [op.write(args[0], f"({cast}{bits}_t)({op.read(args[1])})")],
                      [assignment(op, args[0], expression)])
    if x86 and mnemonic == "xchg" and len(args) == 2:
        width = op.width(args[0])
        temporary = f"exchange_{row['addr']:x}"
        memory_args = [arg for arg in args if "[" in arg]
        if memory_args:
            if len(memory_args) != 1:
                raise ValueError("Exchange cannot have two memory operands")
            memory_arg = memory_args[0]
            register_arg = args[1] if args[0] == memory_arg else args[0]
            statements = [f"uint{width}_t {temporary} = atomic_exchange{width}({op.address(memory_arg)}, {op.read(register_arg)});",
                          op.write(register_arg, temporary)]
        else:
            statements = [f"uint{width}_t {temporary} = {op.read(args[0], width)};",
                op.write(args[0], op.read(args[1], width)), op.write(args[1], temporary)]
        operations = [MicroOperation("exchange", width, (value(op, args[0], width), value(op, args[1], width)),
            attributes={"destinations": args, "simultaneous": True, "atomic": bool(memory_args),
                        "outputs": list(dict.fromkeys(op.register(arg).root for arg in args if op.register(arg)))})]
        return lifted(context, row, "memory" if any("[" in arg for arg in args) else "data_transfer", statements, operations,
                      memory_effect="atomic_read_write" if any("[" in arg for arg in args) else "none")
    # 按通道的 SIMD 整数运算（add v.4s、xtn、ushll、cmhi、paddb、pinsrd…，见 vector_lanes.py）。
    # 本处理器的标量形式都不用这些助记符；放在末尾，常见的 mov/lea/movk 等不付过滤开销。
    # 必须先于整数算术等标量处理器：它们会把向量操作数当作非法标量操作数而直接失败。
    if (mnemonic in vector_lanes.X86_CANDIDATES if x86 else
            mnemonic in vector_lanes.A64_CANDIDATES and args and args[0][:1] in vector_lanes.A64_FIRST_CHARACTERS):
        return vector_lanes.lift(context, row, args, op, mnemonic)
    return None
