"""Logic, shifts/rotates and bit tests with explicit count and flag rules."""
from __future__ import annotations

from .common import assignment, binary, lifted, value
from .ir import Expression, MicroOperation, constant
from .optimize import simplify_expression
from .arm64_operands import register_operand, shifted_register
from . import vector


# 只读查找表提到模块级，避免每条指令重建字典（内容与原局部字典相同）。
_OPERATORS = {"and": "&", "or": "|", "xor": "^", "orr": "|", "eor": "^"}
_SHIFT_ALIASES = {"sal": "shl", "shr": "lshr", "sar": "ashr", "lsl": "shl", "lsr": "lshr", "asr": "ashr"}


_BITFIELD_ARM64 = frozenset({"ubfx", "sbfx", "ubfiz", "sbfiz", "bfxil", "bfi", "bfc"})
_BITFIELD_ARM32 = frozenset({"ubfx", "sbfx", "bfi", "bfc"})


def _immediate(text):
    raw = text.strip().lstrip("#").strip()
    return int(raw, 0)


def _bitfield(context, row, args, op, mnemonic):
    """ARM 位域指令（不写标志）：ubfx/sbfx 提取位段，ubfiz/sbfiz 把低位段放到 lsb 处，
    bfxil/bfi/bfc 只改写目标寄存器的一段并保留其余位。

    带符号扩展写成 ((x ^ m) - m)（m 为位段最高位），不依赖 C 中带符号右移的实现定义行为。
    """
    destination = op.register(args[0])
    if destination is None or destination.root == "sp":
        return None
    width = destination.bits
    sources = args[1:-2]
    if len(sources) != (0 if mnemonic == "bfc" else 1):
        return None
    lsb, size = _immediate(args[-2]), _immediate(args[-1])
    if not (0 <= lsb < width and 1 <= size <= width - lsb):
        return None
    full = (1 << width) - 1
    mask = (1 << size) - 1
    suffix = "ULL" if width == 64 else "U"

    def number(item):
        return constant(item & full, width)

    source = value(op, sources[0], width) if sources else None
    source_text = op.read(sources[0], width) if sources else ""
    old, old_text = value(op, args[0], width), op.read(args[0], width)
    if mnemonic in {"ubfx", "sbfx", "bfxil"}:
        field = Expression("and", width, (Expression("lshr", width, (source, number(lsb))), number(mask))) if lsb else \
            Expression("and", width, (source, number(mask)))
        field_text = f"(({source_text} >> {lsb}) & {hex(mask)}{suffix})"
    else:
        field = Expression("and", width, (source, number(mask))) if source is not None else None
        field_text = f"({source_text} & {hex(mask)}{suffix})"
    if mnemonic in {"sbfx", "sbfiz"} and size < width:
        top = 1 << (size - 1)
        field = Expression("sub", width, (Expression("xor", width, (field, number(top))), number(top)))
        field_text = f"(({field_text} ^ {hex(top)}{suffix}) - {hex(top)}{suffix})"
    if mnemonic in {"ubfiz", "sbfiz", "bfi"} and lsb:
        field = Expression("shl", width, (field, number(lsb)))
        field_text = f"({field_text} << {lsb})"
    if mnemonic in {"ubfx", "sbfx", "ubfiz", "sbfiz"}:
        expression, text = field, field_text
    else:
        keep = full ^ ((mask << (0 if mnemonic == "bfxil" else lsb)) & full)
        kept = Expression("and", width, (old, number(keep)))
        kept_text = f"({old_text} & {hex(keep)}{suffix})"
        expression = kept if mnemonic == "bfc" else Expression("or", width, (kept, field))
        text = kept_text if mnemonic == "bfc" else f"({kept_text} | {field_text})"
    return lifted(context, row, "bitwise", [op.write(args[0], text)],
                  [assignment(op, args[0], simplify_expression(expression))])


def lift(context, row, args, op):
    mnemonic = str(row["mnemonic"]).lower()
    x86 = context.architecture.startswith("x86")
    # 128/64 位向量按位运算（pxor/por/pand、AArch64 and/orr/eor v.16b 等）先于标量形式判断。
    vector_result = vector.lift_bitwise(context, row, args, op)
    if vector_result is not None:
        return vector_result
    stem = "and" if mnemonic == "ands" and not x86 else mnemonic
    if (mnemonic in _BITFIELD_ARM64 if context.architecture == "arm64" else
            context.architecture == "arm" and mnemonic in _BITFIELD_ARM32) and len(args) in {3, 4}:
        return _bitfield(context, row, args, op, mnemonic)
    if context.architecture == "arm64" and mnemonic in {"and", "ands", "orr", "eor", "bic", "bics", "orn", "eon"} and len(args) == 4:
        width = op.width(args[0])
        register_operand(op, args[0], width, read=False)
        left, left_value = register_operand(op, args[1], width)
        right, right_value, attributes = shifted_register(op, args[2], args[3], width, rotate=True)
        opcode = {"and": "and", "ands": "and", "bic": "and", "bics": "and",
                  "orr": "or", "orn": "or", "eor": "xor", "eon": "xor"}[mnemonic]
        inverted = mnemonic in {"bic", "bics", "orn", "eon"}
        expression = binary(opcode, width, left_value,
                            Expression("not", width, (right_value,)) if inverted else right_value)
        expression = simplify_expression(expression)
        symbol = {"and": "&", "or": "|", "xor": "^"}[opcode]
        text = f"({left} {symbol} {'~' if inverted else ''}({right}))"
        statements, operations = [], []
        changes_flags = mnemonic in {"ands", "bics"}
        if changes_flags:
            statements.append(f"flags = arm_logic_flags{width}({text});")
            operations.append(MicroOperation("flags_logic", width, (expression,),
                attributes={"family": "arm", "shifter_carry": "not_used", **attributes}))
        statements.append(op.write(args[0], text))
        operations.append(assignment(op, args[0], expression))
        return lifted(context, row, "bitwise", statements, operations,
                      flag_effect="write" if changes_flags else "preserve")
    if not x86 and mnemonic in {"bic", "bics", "orn", "eon"} and len(args) == 3:
        width = op.width(args[0])
        left, right = value(op, args[1], width), value(op, args[2], width)
        opcode, symbol = {"bic": ("and", "&"), "bics": ("and", "&"), "orn": ("or", "|"), "eon": ("xor", "^")}[mnemonic]
        expression = binary(opcode, width, left, Expression("not", width, (right,)))
        text = f"({op.read(args[1], width)} {symbol} ~({op.read(args[2], width)}))"
        operations, statements = [], []
        if mnemonic == "bics":
            if context.architecture != "arm64":
                return None  # ARM32 shifter carry needs encoding evidence.
            operations.append(MicroOperation("flags_logic", width, (expression,), attributes={"family": "arm"}))
            statements.append(f"flags = arm_logic_flags{width}({text});")
        operations.append(assignment(op, args[0], expression))
        statements.append(op.write(args[0], text))
        return lifted(context, row, "bitwise", statements, operations, flag_effect="write" if mnemonic == "bics" else "preserve")
    operators = _OPERATORS
    if stem in operators and len(args) == (2 if x86 else 3):
        width = op.width(args[0])
        left_operand = args[0] if x86 else args[1]
        opcode = {"orr": "or", "eor": "xor"}.get(stem, stem)
        expression = simplify_expression(binary(opcode, width, value(op, left_operand, width), value(op, args[-1], width)))
        left, right = op.read(left_operand, width), op.read(args[-1], width)
        text = str(expression.value) if expression.opcode == "constant" else f"({left} {operators[stem]} {right})"
        changes_flags = x86 or mnemonic == "ands"
        statements, operations = [], []
        if any("[" in operand for operand in (left_operand, args[-1])):
            capture = f"bit_result_{row['addr']:x}"
            statements.append(f"uint{width}_t {capture} = (uint{width}_t){text};")
            text = capture
        if changes_flags:
            family = "x86" if x86 else "arm32" if context.architecture == "arm" else "arm"
            previous = ", flags" if context.architecture == "arm" else ""
            shifter_unknown = context.architecture == "arm" and op.register(args[-1]) is None
            if shifter_unknown:
                family = "arm32_logic_shifted"
                previous += ", symbolic_shifter_carry()"
            helper = f"{family}_flags{width}" if shifter_unknown else f"{family}_logic_flags{width}"
            statements.append(f"flags = {helper}({text}{previous});")
            operations.append(MicroOperation("flags_logic", width, (expression,), attributes={"family": "x86" if x86 else "arm",
                "shifter_carry": "unknown" if shifter_unknown else "preserve" if context.architecture == "arm" else "not_used"}))
        statements.append(op.write(args[0], f"(uint{width}_t){text}", width))
        operations.append(assignment(op, args[0], expression))
        return lifted(context, row, "bitwise", statements, operations,
                      flag_effect="partial" if changes_flags and context.architecture == "arm" else "write" if changes_flags else "preserve")
    if mnemonic in {"not", "mvn"} and len(args) == (1 if x86 else 2):
        width = op.width(args[0])
        source = args[0] if x86 else args[1]
        return lifted(context, row, "bitwise", [op.write(args[0], f"(uint{width}_t)~({op.read(source)})")],
            [assignment(op, args[0], Expression("not", width, (value(op, source),)))])
    shift = _SHIFT_ALIASES.get(mnemonic, mnemonic)
    if shift in {"shl", "lshr", "ashr", "rol", "ror"} and len(args) == (2 if x86 else 3):
        width = op.width(args[0])
        source = args[0] if x86 else args[1]
        count_operand = args[-1]
        count = value(op, count_operand, width)
        count_text = op.read(count_operand, width)
        if x86:
            count = binary("and", width, count, constant(63 if width == 64 else 31, width))
            count_text = f"({count_text} & {63 if width == 64 else 31})"
        elif op.register(count_operand) is not None:
            # A64 variable shifts use log2(width) low bits; A32 register
            # shifts use the low byte and retain its out-of-range meaning.
            count_mask = width - 1 if context.architecture == "arm64" else 255
            count = binary("and", width, count, constant(count_mask, width))
            count_text = f"({count_text} & {count_mask})"
        expression = binary(shift, width, value(op, source, width), count)
        statements, operations = [], []
        source_text = op.read(source)
        if "[" in source:
            capture = f"shift_input_{row['addr']:x}"
            statements.append(f"uint{width}_t {capture} = {source_text};")
            source_text = capture
        if x86:
            statements.append(f"flags = x86_{shift}_flags{width}({source_text}, {count_text}, flags);")
            operations.append(MicroOperation("flags_shift", width, expression.args, attributes={
                "operation": shift, "count_zero": "preserve", "overflow_defined_when": "count_one", "out_of_range_flags": "undefined"}))
        statements.append(op.write(args[0], f"bitvector_{shift}{width}({source_text}, {count_text})"))
        operations.append(assignment(op, args[0], expression))
        return lifted(context, row, "bitwise", statements, operations, flag_effect="conditional_partial" if x86 else "preserve")
    if x86 and mnemonic in {"rcl", "rcr"} and len(args) == 2:
        width = op.width(args[0])
        result = f"rotate_carry_{row['addr']:x}"
        statements = [f"carry_result_t {result} = x86_{mnemonic}{width}({op.read(args[0])}, {op.read(args[1])}, flags);",
                      op.write(args[0], f"{result}.value"), f"flags = {result}.flags;"]
        return lifted(context, row, "bitwise", statements,
            [MicroOperation("rotate_carry", width, (value(op, args[0]), value(op, args[1], width)),
                attributes={"direction": mnemonic, "count_mask": 63 if width == 64 else 31,
                            "count_zero": "preserve", "carry_input": "CF", "ring_width": width + 1})],
            flag_effect="conditional_partial")
    if mnemonic in {"bswap", "rev", "rev32"} and len(args) == (1 if x86 else 2):
        width = op.width(args[0])
        source = args[0] if x86 else args[1]
        if mnemonic == "rev32" and width == 64:
            return None  # Lane-wise reversal must not be confused with a full bswap64.
        return lifted(context, row, "bitwise", [op.write(args[0], f"bswap{width}({op.read(source)})")],
            [assignment(op, args[0], Expression("bswap", width, (value(op, source),)))])
    if context.architecture == "arm64" and mnemonic == "extr" and len(args) == 4:
        # extr Wd, Wn, Wm, #lsb：把 Wn:Wm 拼成 2W 位后右移 lsb 位取低 W 位，即 (Wn << (W-lsb)) | (Wm >> lsb)。
        width = op.width(args[0])
        register = op.register(args[0])
        if register is None or width not in {32, 64}:
            return None
        raw = args[3].strip().lstrip("#")
        lsb = int(raw, 16 if raw.lower().startswith("0x") else 10)
        if not 0 <= lsb < width:
            raise ValueError("EXTR shift out of range")
        high, low = value(op, args[1]), value(op, args[2])
        high_text, low_text = op.read(args[1]), op.read(args[2])
        if lsb == 0:
            expression, text = low, low_text
        else:
            expression = Expression("or", width, (Expression("shl", width, (high, constant(width - lsb, width))),
                                                  Expression("lshr", width, (low, constant(lsb, width)))))
            text = f"(({high_text} << {width - lsb}) | ({low_text} >> {lsb}))"
        return lifted(context, row, "bitwise", [op.write(args[0], f"(uint{width}_t){text}")],
                      [assignment(op, args[0], expression)])
    if x86 and mnemonic in {"bt", "bts", "btr", "btc"} and len(args) == 2:
        width = op.width(args[0])
        memory = "[" in args[0]
        # 寄存器形式的位索引取模宽度，访问的是同一个操作数；内存形式只有“立即数索引”才一定访问所给地址
        # （寄存器索引会把地址按 idx/宽度 调整到别的字，保持不透明）。
        if memory and op.register(args[1]) is not None:
            return None
        index_value = value(op, args[1], width)
        if memory and index_value.opcode != "constant":
            return None
        if width not in {16, 32, 64}:
            return None
        masked_index = Expression("and", width, (index_value, constant(width - 1, width)))
        index = f"({op.read(args[1], width)} & {width - 1})"
        original = op.read(args[0])
        operand_value = value(op, args[0])
        statements, operations = [], []
        if memory and mnemonic != "bt":
            # 内存读改写：读一次、改位、写回同一地址。
            captured = f"bit_base_{row['addr']:x}"
            statements.append(f"uint{width}_t {captured} = {original};")
            original = captured
        statements.append(f"flags.CF = ({original} >> {index}) & 1;")
        operations.append(MicroOperation("bit_test", width, (operand_value, masked_index),
            attributes={"index_modulo": width, "flag_write": ["CF"], "other_flags": "undefined_except_ZF"}))
        if mnemonic != "bt":
            operator = {"bts": "|", "btr": "&", "btc": "^"}[mnemonic]
            mask = f"(1ULL << {index})"
            text = f"({original} {operator} {'~' if mnemonic == 'btr' else ''}{mask})"
            one = constant(1, width)
            bit_mask = Expression("shl", width, (one, masked_index))
            if mnemonic == "bts":
                modified = Expression("or", width, (operand_value, bit_mask))
            elif mnemonic == "btc":
                modified = Expression("xor", width, (operand_value, bit_mask))
            else:
                modified = Expression("and", width, (operand_value, Expression("not", width, (bit_mask,))))
            statements.append(op.write(args[0], text))
            if memory:
                address = Expression("address", op.bits, name=op.address(args[0]))
                operations.append(MicroOperation("bit_modify", width, (address, modified),
                    attributes={"operation": mnemonic, "destination": args[0], "effect": "write"}))
            else:
                store = assignment(op, args[0], modified)
                operations.append(MicroOperation("bit_modify", store.width, (operand_value, masked_index),
                    output=store.output, expression=store.expression,
                    attributes={**store.attributes, "operation": mnemonic, "destination": args[0]}))
        statements.append("flags = invalidate_undefined_bit_flags(flags);")
        memory_effect = ("read_write" if memory and mnemonic != "bt" else "read" if memory else None)
        return lifted(context, row, "bitwise", statements, operations,
                      flag_effect="partial_undefined", memory_effect=memory_effect)
    return None
