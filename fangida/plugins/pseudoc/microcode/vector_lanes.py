"""按通道的 SIMD 整数运算提升（AArch64 AdvSIMD、x86 SSE/AVX-128 整数形式）。

语义由 lane_ops.py 的 vec_* opcode 精确定义（通道宽度写在名字里，表达式宽度为结果总位数），
其余部分（取高/低半、拼接、插入通道、按位选择、常量掩码）只用已有的位向量运算表达。
寄存器根沿用 vector.py 的约定（AArch64 vN、x86 xmmN，存储宽度 128 位）：

* AArch64 64 位排列（8b/4h/2s）与标量 dN 形式的结果写入低 64 位并清零高 64 位；
  xtn2/shrn2/ins 类“写高半/写单个通道”的指令保留其余位。
* x86 传统 SSE 形式为两操作数（目的同时是第一个源），内存源要求 16 字节对齐（属性
  alignment_fault）；VEX.128 形式为三操作数，并把 ymm 的 255:128 位清零（属性 upper_bits）。
  只接受 xmm 寄存器，ymm/zmm 形式保持 opaque。
* 浮点通道运算（fadd v.4s…）、饱和/舍入运算（sqadd、rshrn…）、表查找（tbl、pshufb）、
  多结构访存（ld2/ld3/ld4…）等不在这里建模，保持 opaque。
"""
from __future__ import annotations

import re

from . import vector as _vector
from .common import assignment, lifted, resize, value
from .ir import Expression, constant
from .lane_ops import LANE_OPCODES, lane_opcode

# ---------------------------------------------------------------------------
# 表达式工具与机器伪 C 文本
# ---------------------------------------------------------------------------

_INFIX = {"or": "|", "and": "&", "xor": "^", "add": "+", "sub": "-", "shl": "<<", "lshr": ">>"}


def render(expression):
    """把表达式渲染成机器伪 C 文本：位向量运算用 C 运算符，通道运算写成 opcode_宽度(参数…)。"""
    opcode, args = expression.opcode, expression.args
    if opcode == "register":
        return expression.name
    if opcode == "constant":
        return hex(expression.value)
    if opcode == "truncate":
        return f"(uint{expression.width}_t){render(args[0])}"
    if opcode == "zext":
        return f"({'vector128_t' if expression.width == 128 else f'uint{expression.width}_t'}){render(args[0])}"
    if opcode == "extract":
        return f"(uint{expression.width}_t)({render(args[0])} >> {expression.value})"
    if opcode == "not":
        return f"~{render(args[0])}"
    if opcode == "load":
        return f"load{expression.width}({args[0].name})"
    if opcode in _INFIX and len(args) == 2:
        return f"({render(args[0])} {_INFIX[opcode]} {render(args[1])})"
    return f"{opcode}_{expression.width}({', '.join(render(arg) for arg in args)})"


def _lanes(operation, lane, width, *args):
    return Expression(lane_opcode(operation, lane), width, tuple(args))


def _count(amount):
    return constant(amount, 64)


def _low(expression, width):
    return _vector._low(expression, width)


def _high64(expression):
    return Expression("extract", 64, (expression,), value=64)


def _concat64(low, high):
    """两个 64 位值拼成 128 位：low 在低半，high 在高半。"""
    return Expression("or", 128, (resize(low, 128), Expression("shl", 128, (resize(high, 128), constant(64, 128)))))


def _replicate_constant(lane_value, lane, total):
    number = 0
    for index in range(total // lane):
        number |= (lane_value & ((1 << lane) - 1)) << (index * lane)
    return number


def _write(context, row, root, expression, total, lane, category, **extra):
    """写整个向量寄存器：64 位结果零扩展（AArch64 清零高 64 位）。"""
    full = resize(expression, 128) if expression.width < 128 else expression
    extra.setdefault("upper_lanes", "zero" if total < 128 else "full")
    return lifted(context, row, category, [f"{root} = {render(full)};"],
                  [_vector._vector_write(context, root, full, lane_width=lane, **extra)])


# ---------------------------------------------------------------------------
# AArch64 AdvSIMD
# ---------------------------------------------------------------------------

_A64_SAME = {"add": "add", "sub": "sub", "mul": "mul", "cmeq": "cmeq", "cmhi": "cmhi", "cmhs": "cmhs",
             "cmgt": "cmgt", "cmge": "cmge", "cmtst": "cmtst", "ushl": "ushl", "sshl": "sshl",
             "umax": "umax", "umin": "umin", "smax": "smax", "smin": "smin",
             "uqadd": "uqadd", "uqsub": "uqsub", "sqadd": "sqadd", "sqsub": "sqsub"}
# 置位 FPSR.QC（饱和累积位）的同宽二元运算；QC 不是寄存器结果，只记在操作属性里。
_A64_SATURATING = frozenset({"uqadd", "uqsub", "sqadd", "sqsub"})
# 接受标量形式的同宽二元运算：只认标量 dN（视为一个 64 位通道，见 _a64_operand）；饱和运算的标量
# bN/hN/sN 形式（sqadd b0, b1, b2 等）不在此表达，保持不透明。
_A64_SCALAR_SAME = frozenset({"add", "sub", "cmeq", "cmhi", "cmhs", "cmgt", "cmge", "cmtst", "ushl", "sshl",
                              "uqadd", "uqsub", "sqadd", "sqsub"})
_A64_NO_64BIT_LANES = frozenset({"mul", "umax", "umin", "smax", "smin", "mla", "mls"})
# 与零比较：(运算, 是否交换操作数)。cmle x, #0 即 0 >= x，cmlt x, #0 即 0 > x。
_A64_ZERO_COMPARE = {"cmeq": ("cmeq", False), "cmge": ("cmge", False), "cmgt": ("cmgt", False),
                     "cmle": ("cmge", True), "cmlt": ("cmgt", True)}
_A64_SHIFT_IMMEDIATE = {"shl": "shl", "ushr": "lshr", "sshr": "ashr", "usra": "lshr", "ssra": "ashr"}
_A64_LONG = {"uaddl": ("add", False), "saddl": ("add", True), "usubl": ("sub", False), "ssubl": ("sub", True),
             "umull": ("mul", False), "smull": ("mul", True)}
_A64_WIDE = {"uaddw": ("add", False), "saddw": ("add", True), "usubw": ("sub", False), "ssubw": ("sub", True)}
_A64_MULTIPLY_ACCUMULATE_LONG = {"umlal": ("add", False), "smlal": ("add", True),
                                 "umlsl": ("sub", False), "smlsl": ("sub", True)}
_A64_REDUCTIONS = {"addv": "addv", "umaxv": "umaxv", "uminv": "uminv", "smaxv": "smaxv", "sminv": "sminv"}
_A64_WIDEN = {"ushll": False, "sshll": True, "uxtl": False, "sxtl": True, "shll": False}
_ZERO_IMMEDIATE = frozenset({"#0", "#0x0", "#0.0"})
_SINGLE_LANE = re.compile(r"\{\s*v([0-9]|[12][0-9]|3[01])\.([bhsd])\s*\}\s*\[(0x[0-9a-f]+|[0-9]+)\]")
_SHIFT_MODIFIER = re.compile(r"lsl\s+#?(0x[0-9a-f]+|[0-9]+)")
_A64_MNEMONICS = frozenset(set(_A64_SAME) | set(_A64_ZERO_COMPARE) | set(_A64_SHIFT_IMMEDIATE) |
                           {name + suffix for name in (*_A64_LONG, *_A64_WIDE, *_A64_MULTIPLY_ACCUMULATE_LONG,
                                                       *_A64_WIDEN, "xtn", "shrn") for suffix in ("", "2")} |
                           set(_A64_REDUCTIONS) | {"neg", "abs", "mla", "mls", "uzp1", "uzp2", "ext", "bsl", "bit",
                                                   "bif", "mvni", "orr", "bic", "rev16", "rev32", "rev64", "addp",
                                                   "ld1", "st1"})


def _a64_operand(operand, *, scalar_ok=False):
    """(根, 通道宽度, 总宽度)：vN.T 排列，或 scalar_ok 时的标量 dN（视为一个 64 位通道）。"""
    arrangement = _vector._arrangement(operand)
    if arrangement:
        # 1D 排列只出现在搬移/乘法多项式等其它指令中；这里的按通道运算用标量 dN 表示单个 64 位通道。
        return arrangement if arrangement[2] // arrangement[1] > 1 else None
    if scalar_ok:
        scalar = _vector._scalar(operand)
        if scalar and scalar[1] == 64:
            return scalar[0], 64, 64
    return None


def _read(context, item):
    context.vector_registers.add(item[0])
    return _low(_vector._vector(item[0]), item[2])


def _half(context, item, upper):
    """64 位半宽源：非 “2” 形式取低 64 位（排列本身为 64 位），“2” 形式取 128 位排列的高 64 位。"""
    root, _, total = item
    context.vector_registers.add(root)
    if upper:
        if total != 128:
            raise ValueError("Upper-half form requires a 128-bit source")
        return _high64(_vector._vector(root))
    if total != 64:
        raise ValueError("Lower-half form requires a 64-bit source arrangement")
    return _low(_vector._vector(root), 64)


def _immediate(text):
    return _vector._number(text)


def _widen(source, lane, signed):
    return _lanes("sext" if signed else "zext", lane, 128, source)


def _a64_same(context, row, args, mnemonic):
    scalar_ok = mnemonic in _A64_SCALAR_SAME or mnemonic in _A64_ZERO_COMPARE
    destination, left = _a64_operand(args[0], scalar_ok=scalar_ok), _a64_operand(args[1], scalar_ok=scalar_ok)
    if destination is None or left is None or destination[1:] != left[1:]:
        return None
    root, lane, total = destination
    if args[2].lower().strip() in _ZERO_IMMEDIATE and mnemonic in _A64_ZERO_COMPARE:
        operation, swapped = _A64_ZERO_COMPARE[mnemonic]
        operands = (constant(0, total), _read(context, left))
        if not swapped:
            operands = operands[::-1]
        return _write(context, row, root, _lanes(operation, lane, total, *operands), total, lane, "comparison",
                      lane_operation=operation)
    if mnemonic not in _A64_SAME:
        return None
    right = _a64_operand(args[2], scalar_ok=scalar_ok)
    if right is None or right[1:] != destination[1:] or (lane == 64 and mnemonic in _A64_NO_64BIT_LANES):
        return None
    operation = _A64_SAME[mnemonic]
    expression = _lanes(operation, lane, total, _read(context, left), _read(context, right))
    category = "comparison" if operation.startswith("cm") else "bitwise" if operation.endswith("shl") else "integer_arithmetic"
    extra = {"saturating": "fpsr_qc"} if operation in _A64_SATURATING else {}
    return _write(context, row, root, expression, total, lane, category, lane_operation=operation, **extra)


def _a64_unary(context, row, args, mnemonic):
    destination, source = _a64_operand(args[0], scalar_ok=True), _a64_operand(args[1], scalar_ok=True)
    if destination is None or source is None or destination[1:] != source[1:]:
        return None
    root, lane, total = destination
    return _write(context, row, root, _lanes(mnemonic, lane, total, _read(context, source)), total, lane,
                  "integer_arithmetic", lane_operation=mnemonic)


def _a64_shift_immediate(context, row, args, mnemonic):
    destination, source = _a64_operand(args[0], scalar_ok=True), _a64_operand(args[1], scalar_ok=True)
    if destination is None or source is None or destination[1:] != source[1:]:
        return None
    root, lane, total = destination
    amount = _immediate(args[2])
    if not (0 <= amount < lane if mnemonic == "shl" else 1 <= amount <= lane):
        raise ValueError("A64 shift immediate out of range")
    operation = _A64_SHIFT_IMMEDIATE[mnemonic]
    expression = _lanes(operation, lane, total, _read(context, source), _count(amount))
    if mnemonic in {"usra", "ssra"}:
        expression = _lanes("add", lane, total, _read(context, destination), expression)
    return _write(context, row, root, expression, total, lane, "bitwise", lane_operation=mnemonic)


def _a64_widen(context, row, args, mnemonic):
    upper = mnemonic.endswith("2")
    base = mnemonic[:-1] if upper else mnemonic
    if len(args) != (2 if base in {"uxtl", "sxtl"} else 3):
        return None
    destination, source = _a64_operand(args[0]), _a64_operand(args[1])
    if destination is None or source is None or destination[2] != 128 or destination[1] != 2 * source[1]:
        return None
    lane = source[1]
    amount = _immediate(args[2]) if len(args) == 3 else 0
    if base == "shll":
        if amount != lane:
            raise ValueError("SHLL shifts by the source element size")
    elif not 0 <= amount < lane:
        raise ValueError("A64 widening shift out of range")
    expression = _widen(_half(context, source, upper), lane, _A64_WIDEN[base])
    if amount:
        expression = _lanes("shl", 2 * lane, 128, expression, _count(amount))
    return _write(context, row, destination[0], expression, 128, 2 * lane, "conversion", lane_operation=mnemonic)


def _a64_long(context, row, args, mnemonic):
    """uaddl/saddl/usubl/ssubl/umull/smull、uaddw/saddw/usubw/ssubw、umlal/smlal/umlsl/smlsl（含 “2” 形式）。"""
    upper = mnemonic.endswith("2")
    base = mnemonic[:-1] if upper else mnemonic
    destination = _a64_operand(args[0])
    left, right = _a64_operand(args[1]), _a64_operand(args[2])
    if destination is None or left is None or right is None or destination[2] != 128:
        return None
    lane = right[1]
    if destination[1] != 2 * lane:
        return None
    if base in _A64_WIDE:
        operation, signed = _A64_WIDE[base]
        if left[1:] != destination[1:]:
            return None
        expression = _lanes(operation, 2 * lane, 128, _read(context, left),
                            _widen(_half(context, right, upper), lane, signed))
    else:
        if left[1:] != right[1:]:
            return None
        accumulate = base in _A64_MULTIPLY_ACCUMULATE_LONG
        operation, signed = (_A64_MULTIPLY_ACCUMULATE_LONG if accumulate else _A64_LONG)[base]
        widened = (_widen(_half(context, left, upper), lane, signed), _widen(_half(context, right, upper), lane, signed))
        if accumulate:
            product = _lanes("mul", 2 * lane, 128, *widened)
            expression = _lanes(operation, 2 * lane, 128, _read(context, destination), product)
        else:
            expression = _lanes(operation, 2 * lane, 128, *widened)
    return _write(context, row, destination[0], expression, 128, 2 * lane, "integer_arithmetic", lane_operation=mnemonic)


def _a64_accumulate(context, row, args, mnemonic):
    operands = [_a64_operand(arg) for arg in args]
    if not all(operands) or len({item[1:] for item in operands}) != 1 or operands[0][1] == 64:
        return None
    root, lane, total = operands[0]
    product = _lanes("mul", lane, total, _read(context, operands[1]), _read(context, operands[2]))
    expression = _lanes("add" if mnemonic == "mla" else "sub", lane, total, _read(context, operands[0]), product)
    return _write(context, row, root, expression, total, lane, "integer_arithmetic", lane_operation=mnemonic)


def _a64_narrow(context, row, args, mnemonic):
    upper = mnemonic.endswith("2")
    base = mnemonic[:-1] if upper else mnemonic
    if len(args) != (3 if base == "shrn" else 2):
        return None
    destination, source = _a64_operand(args[0]), _a64_operand(args[1])
    if destination is None or source is None or source[2] != 128 or source[1] != 2 * destination[1]:
        return None
    if destination[2] != (128 if upper else 64):
        return None
    lane = source[1]
    wide = _read(context, source)
    if base == "shrn":
        amount = _immediate(args[2])
        if not 1 <= amount <= lane // 2:
            raise ValueError("SHRN shift out of range")
        wide = _lanes("lshr", lane, 128, wide, _count(amount))
    narrowed = _lanes("narrow", lane, 64, wide)
    if upper:
        context.vector_registers.add(destination[0])
        expression = _concat64(_low(_vector._vector(destination[0]), 64), narrowed)
        return _write(context, row, destination[0], expression, 128, lane // 2, "conversion",
                      lane_operation=mnemonic, preserved_lanes="low_64")
    return _write(context, row, destination[0], narrowed, 64, lane // 2, "conversion", lane_operation=mnemonic)


def _even_lanes(expression, lane, odd):
    """64/128 位值中偶数（odd=True 时奇数）编号的 lane 位通道（lane < 64），依次排成一半宽度的值。

    偶数通道正是把相邻两个通道看作一个 2*lane 位通道后的低半，即 vec_narrow{2*lane}；
    奇数通道先把每个 2*lane 位通道逻辑右移 lane 位再窄化。
    """
    if odd:
        expression = _lanes("lshr", 2 * lane, expression.width, expression, _count(lane))
    return _lanes("narrow", 2 * lane, expression.width // 2, expression)


def _a64_unzip(context, row, args, mnemonic):
    operands = [_a64_operand(arg) for arg in args]
    if not all(operands) or len({item[1:] for item in operands}) != 1:
        return None
    root, lane, total = operands[0]
    if lane == 64 and total != 128:
        return None
    odd = mnemonic == "uzp2"
    left, right = _read(context, operands[1]), _read(context, operands[2])
    if lane == 64:
        pick = _high64 if odd else (lambda value: _low(value, 64))
        expression = _concat64(pick(left), pick(right))
    else:
        halves = [_even_lanes(item, lane, odd) for item in (left, right)]
        if total == 128:
            expression = _concat64(*halves)
        else:
            expression = Expression("or", 64, (resize(halves[0], 64), Expression(
                "shl", 64, (resize(halves[1], 64), constant(32, 64)))))
    return _write(context, row, root, expression, total, lane, "data_transfer", lane_operation=mnemonic)


def _a64_ext(context, row, args):
    if len(args) != 4:
        return None
    operands = [_a64_operand(arg) for arg in args[:3]]
    if not all(operands) or len({item[1:] for item in operands}) != 1 or operands[0][1] != 8:
        return None
    root, _, total = operands[0]
    index = _immediate(args[3])
    if not 0 <= index < total // 8:
        raise ValueError("EXT index out of range")
    low, high = _read(context, operands[1]), _read(context, operands[2])
    if not index:
        expression = low
    else:
        expression = Expression("or", total, (Expression("lshr", total, (low, constant(8 * index, total))),
                                              Expression("shl", total, (high, constant(total - 8 * index, total)))))
    return _write(context, row, root, expression, total, 8, "data_transfer", lane_operation="ext")


def _a64_select(context, row, args, mnemonic):
    operands = [_a64_operand(arg) for arg in args]
    if len(args) != 3 or not all(operands) or len({item[1:] for item in operands}) != 1 or operands[0][1] != 8:
        return None
    root, _, total = operands[0]
    destination, left, right = (_read(context, item) for item in operands)

    def both(first, second):
        return Expression("and", total, (first, second))

    def inverse(item):
        return Expression("not", total, (item,))

    if mnemonic == "bsl":  # 目的寄存器是选择掩码：1 取第一个源，0 取第二个源
        expression = Expression("or", total, (both(destination, left), both(inverse(destination), right)))
    elif mnemonic == "bit":  # 第二个源为 1 的位插入第一个源
        expression = Expression("or", total, (both(destination, inverse(right)), both(left, right)))
    else:  # bif：第二个源为 0 的位插入第一个源
        expression = Expression("or", total, (both(destination, right), both(left, inverse(right))))
    return _write(context, row, root, expression, total, 8, "bitwise", lane_operation=mnemonic)


def _a64_immediate(context, row, args, mnemonic):
    """mvni / orr / bic（向量立即数，可选 lsl #s；msl 形式不建模）。"""
    if len(args) not in {2, 3}:
        return None
    destination = _a64_operand(args[0])
    if destination is None or destination[1] not in {16, 32}:
        return None
    root, lane, total = destination
    immediate, shift = _immediate(args[1]), 0
    if len(args) == 3:
        match = _SHIFT_MODIFIER.fullmatch(args[2].lower().strip())
        if match is None:
            return None
        shift = int(match[1], 16 if match[1].startswith("0x") else 10)
    if not 0 <= immediate <= 0xff or shift not in ({0, 8} if lane == 16 else {0, 8, 16, 24}):
        raise ValueError("Invalid A64 vector immediate")
    lane_value = immediate << shift
    if mnemonic == "mvni":
        expression = constant(_replicate_constant(~lane_value, lane, total), total)
    else:
        pattern = constant(_replicate_constant(lane_value if mnemonic == "orr" else ~lane_value, lane, total), total)
        expression = Expression("or" if mnemonic == "orr" else "and", total, (_read(context, destination), pattern))
    return _write(context, row, root, expression, total, lane, "data_transfer" if mnemonic == "mvni" else "bitwise",
                  lane_operation=mnemonic)


def _a64_reverse(context, row, args, mnemonic):
    destination, source = _a64_operand(args[0]), _a64_operand(args[1])
    if destination is None or source is None or destination[1:] != source[1:]:
        return None
    root, lane, total = destination
    container = int(mnemonic[3:])
    if lane >= container:
        return None
    value_expression = _read(context, source)
    count = container // lane
    parts = []
    for position in range(count):
        # 每个容器内第 position 个通道移到第 count-1-position 个位置。
        mask = 0
        for base in range(0, total, container):
            mask |= ((1 << lane) - 1) << (base + position * lane)
        selected = Expression("and", total, (value_expression, constant(mask, total)))
        distance = (count - 1 - 2 * position) * lane
        if distance > 0:
            selected = Expression("shl", total, (selected, constant(distance, total)))
        elif distance < 0:
            selected = Expression("lshr", total, (selected, constant(-distance, total)))
        parts.append(selected)
    expression = parts[0]
    for part in parts[1:]:
        expression = Expression("or", total, (expression, part))
    return _write(context, row, root, expression, total, lane, "data_transfer", lane_operation=mnemonic)


def _a64_reduce(context, row, args, mnemonic):
    scalar, source = _vector._scalar(args[0]), _a64_operand(args[1])
    if scalar is None or source is None or scalar[1] != source[1] or source[1] == 64:
        return None
    expression = _lanes(_A64_REDUCTIONS[mnemonic], source[1], source[1], _read(context, source))
    return _vector._a64_write_scalar(context, row, scalar[0], expression, source[1],
                                     f"{scalar[0]} = (vector128_t){render(expression)};", "integer_arithmetic")


def _a64_pairwise_scalar(context, row, args):
    scalar, source = _vector._scalar(args[0]), _a64_operand(args[1])
    if scalar is None or source is None or scalar[1] != 64 or source[1:] != (64, 128):
        return None
    full = _read(context, source)
    expression = Expression("add", 64, (_low(full, 64), _high64(full)))
    return _vector._a64_write_scalar(context, row, scalar[0], expression, 64,
                                     f"{scalar[0]} = (vector128_t){render(expression)};", "integer_arithmetic")


def _a64_single_lane(context, row, args, op, mnemonic):
    """ld1/st1 单通道形式（不回写基址）：只读写一个通道，其余通道保持不变。"""
    if len(args) != 2:
        return None
    match = _SINGLE_LANE.fullmatch(args[0].lower().strip())
    if match is None or not args[1].strip().startswith("["):
        return None
    root, lane = "v" + match[1], _vector._LANE_BITS[match[2]]
    index = int(match[3], 16 if match[3].startswith("0x") else 10)
    if not 0 <= index < 128 // lane:
        raise ValueError("Vector lane index out of range")
    address_text = op.address(args[1])
    address = Expression("address", op.bits, name=address_text)
    context.vector_registers.add(root)
    full = _vector._vector(root)
    if mnemonic == "ld1":
        loaded = Expression("load", lane, (address,))
        expression = _vector._merge(full, loaded, lane * index, lane)
        return lifted(context, row, "memory", [f"{root} = vector_insert{lane}({root}, {index}, load{lane}({address_text}));"],
                      [_vector._vector_write(context, root, expression, memory_width=lane, lane_width=lane)])
    lane_value = _vector._field(full, lane * index, lane)
    return lifted(context, row, "memory", [f"store{lane}({address_text}, lane{lane}({root}, {index}));"],
                  [_vector._vector_store(lane, address, lane_value)])


def _a64(context, row, args, op, mnemonic):
    if mnemonic not in _A64_MNEMONICS or not args:
        return None
    if mnemonic in {"ld1", "st1"}:
        return _a64_single_lane(context, row, args, op, mnemonic)
    first = args[0]
    if "." not in first:
        # 标量形式：dN（同宽二元/一元/立即数移位、addp）与归约的 b/h/s 目的寄存器；通用寄存器形式直接放过。
        if _vector._scalar(first) is None:
            return None
    if mnemonic in _A64_REDUCTIONS:
        return _a64_reduce(context, row, args, mnemonic) if len(args) == 2 else None
    if mnemonic == "addp":
        return _a64_pairwise_scalar(context, row, args) if len(args) == 2 and "." not in first else None
    if mnemonic in {"neg", "abs"}:
        return _a64_unary(context, row, args, mnemonic) if len(args) == 2 else None
    if mnemonic in _A64_SHIFT_IMMEDIATE:
        return _a64_shift_immediate(context, row, args, mnemonic) if len(args) == 3 else None
    if mnemonic in _A64_SAME or mnemonic in _A64_ZERO_COMPARE:
        return _a64_same(context, row, args, mnemonic) if len(args) == 3 else None
    if "." not in first:
        return None
    if mnemonic in {"mla", "mls"}:
        return _a64_accumulate(context, row, args, mnemonic) if len(args) == 3 else None
    base = mnemonic[:-1] if mnemonic.endswith("2") else mnemonic
    if base in _A64_WIDEN:
        return _a64_widen(context, row, args, mnemonic)
    if base in _A64_LONG or base in _A64_WIDE or base in _A64_MULTIPLY_ACCUMULATE_LONG:
        return _a64_long(context, row, args, mnemonic) if len(args) == 3 else None
    if base in {"xtn", "shrn"}:
        return _a64_narrow(context, row, args, mnemonic)
    if mnemonic in {"uzp1", "uzp2"}:
        return _a64_unzip(context, row, args, mnemonic) if len(args) == 3 else None
    if mnemonic == "ext":
        return _a64_ext(context, row, args)
    if mnemonic in {"bsl", "bit", "bif"}:
        return _a64_select(context, row, args, mnemonic)
    if mnemonic in {"mvni", "orr", "bic"}:
        # orr/bic 的三寄存器形式由 vector.py 处理；这里只认立即数形式。
        return _a64_immediate(context, row, args, mnemonic) if len(args) >= 2 and args[1].strip().startswith("#") else None
    if mnemonic in {"rev16", "rev32", "rev64"}:
        return _a64_reverse(context, row, args, mnemonic) if len(args) == 2 else None
    return None


# ---------------------------------------------------------------------------
# x86 SSE / AVX-128 整数通道运算
# ---------------------------------------------------------------------------

_X86_SIZES = {"b": 8, "w": 16, "d": 32, "q": 64}
_X86_BINARY = {}
for _suffix, _lane_width in _X86_SIZES.items():
    _X86_BINARY["padd" + _suffix] = ("add", _lane_width)
    _X86_BINARY["psub" + _suffix] = ("sub", _lane_width)
    _X86_BINARY["pcmpeq" + _suffix] = ("cmeq", _lane_width)
    _X86_BINARY["pcmpgt" + _suffix] = ("cmgt", _lane_width)
del _suffix, _lane_width
_X86_BINARY.update({"paddsb": ("sqadd", 8), "paddsw": ("sqadd", 16), "psubsb": ("sqsub", 8), "psubsw": ("sqsub", 16),
                    "paddusb": ("uqadd", 8), "paddusw": ("uqadd", 16), "psubusb": ("uqsub", 8), "psubusw": ("uqsub", 16),
                    "pmullw": ("mul", 16), "pmulld": ("mul", 32),
                    "pminub": ("umin", 8), "pmaxub": ("umax", 8), "pminsw": ("smin", 16), "pmaxsw": ("smax", 16),
                    "pminsb": ("smin", 8), "pmaxsb": ("smax", 8), "pminuw": ("umin", 16), "pmaxuw": ("umax", 16),
                    "pminsd": ("smin", 32), "pmaxsd": ("smax", 32), "pminud": ("umin", 32), "pmaxud": ("umax", 32)})
_X86_SHIFTS = {"psllw": ("shl", 16), "pslld": ("shl", 32), "psllq": ("shl", 64),
               "psrlw": ("lshr", 16), "psrld": ("lshr", 32), "psrlq": ("lshr", 64),
               "psraw": ("ashr", 16), "psrad": ("ashr", 32)}
_X86_INSERT = {"pinsrb": 8, "pinsrw": 16, "pinsrd": 32, "pinsrq": 64}
_X86_EXTRACT = {"pextrb": 8, "pextrw": 16, "pextrd": 32, "pextrq": 64}
_X86_SIGN_MASK = {"pmovmskb": 8, "movmskps": 32, "movmskpd": 64}
_X86_BLEND = {"pblendw": 16, "blendps": 32, "blendpd": 64}
_X86_EXTEND = {f"pmov{kind}x{source}{target}": (kind == "s", _X86_SIZES[source], _X86_SIZES[target])
               for kind in "sz" for source, target in (("b", "w"), ("b", "d"), ("b", "q"), ("w", "d"), ("w", "q"), ("d", "q"))}
_X86_HALF_MOVES = frozenset({"movlps", "movhps", "movlpd", "movhpd"})
# 跨通道重排/饱和打包：mnemonic -> (重排 opcode 名, 源通道宽度)。pshufb 的源通道宽度记 8。
_X86_PERMUTE = {"pshufb": ("pshufb", 8), "packsswb": ("packss", 16), "packssdw": ("packss", 32),
                "packuswb": ("packus", 16), "packusdw": ("packus", 32)}
_X86_MNEMONICS = frozenset({*_X86_BINARY, *_X86_SHIFTS, *_X86_INSERT, *_X86_EXTRACT, *_X86_SIGN_MASK, *_X86_BLEND,
                            *_X86_EXTEND, *_X86_PERMUTE, "pshufd"})


def _x86_extra(vex, source):
    if vex:
        return {"upper_bits": "zeroed_above_128"}
    return {"alignment": 16, "alignment_fault": True} if source.opcode == "load" else {}


def _x86_operands(context, op, args, vex, count):
    """(目的根, 第一个源, 第二个源文本, 第二个源, 剩余参数)；传统形式的第一个源就是目的。"""
    if len(args) != count + int(vex):
        raise ValueError("Unexpected x86 vector operand count")
    destination = _vector._xmm(args[0])
    if destination is None:
        raise ValueError("Unsupported x86 vector destination")
    context.vector_registers.add(destination)
    first_operand = args[1] if vex else args[0]
    first = _vector._xmm(first_operand)
    if first is None:
        raise ValueError("Unsupported x86 vector source")
    context.vector_registers.add(first)
    source_text, source = _vector._x86_source(context, op, args[2 if vex else 1])
    return destination, _vector._vector(first), source_text, source, args[(3 if vex else 2):]


def _x86_binary(context, row, args, op, mnemonic, vex):
    operation, lane = _X86_BINARY[mnemonic]
    destination, first, _, source, _ = _x86_operands(context, op, args, vex, 2)
    if operation in {"cmeq", "cmgt"} and source == first and source.opcode == "register":
        # 同一寄存器比较：pcmpeq x, x 恒为全 1、pcmpgt x, x 恒为 0，与原值无关。
        expression = constant((1 << 128) - 1 if operation == "cmeq" else 0, 128)
        return _write(context, row, destination, expression, 128, lane, "data_transfer", idiom="all_ones" if
                      operation == "cmeq" else "zero", **_x86_extra(vex, source))
    expression = _lanes(operation, lane, 128, first, source)
    category = "comparison" if operation.startswith("cm") else "integer_arithmetic"
    return _write(context, row, destination, expression, 128, lane, category, lane_operation=operation,
                  **_x86_extra(vex, source))


def _x86_shift(context, row, args, op, mnemonic, vex):
    operation, lane = _X86_SHIFTS[mnemonic]
    if len(args) != 2 + int(vex):
        return None
    destination = _vector._xmm(args[0])
    first = _vector._xmm(args[1] if vex else args[0])
    if destination is None or first is None:
        return None
    context.vector_registers.update((destination, first))
    count_operand = args[-1].strip()
    extra = {"upper_bits": "zeroed_above_128"} if vex else {}
    if _vector._xmm(count_operand) is None and "[" not in count_operand:
        count = _count(_immediate(count_operand) & 0xff)  # imm8 按无符号解释，>= 通道宽度时结果为 0/符号填充
    else:
        # 计数来自 xmm/m128 的低 64 位（无符号）。
        _, source = _vector._x86_source(context, op, count_operand)
        count = _low(source, 64)
        extra.update(_x86_extra(vex, source))
    expression = _lanes(operation, lane, 128, _vector._vector(first), count)
    return _write(context, row, destination, expression, 128, lane, "bitwise", lane_operation=operation, **extra)


def _x86_insert(context, row, args, op, mnemonic, vex):
    lane = _X86_INSERT[mnemonic]
    if len(args) != 3 + int(vex):
        return None
    destination, first = _vector._xmm(args[0]), _vector._xmm(args[1] if vex else args[0])
    if destination is None or first is None:
        return None
    source_operand = args[-2]
    index = _immediate(args[-1]) & (128 // lane - 1)
    register = op.register(source_operand)
    if register is not None:
        if register.bits != (64 if lane == 64 else 32):
            return None
        inserted = _low(value(op, source_operand), lane)
    else:
        memory = _vector._x86_memory(op, source_operand)
        if memory is None or memory[0] != lane:
            return None
        inserted = Expression("load", lane, (memory[2],))
    context.vector_registers.update((destination, first))
    expression = _vector._merge(_vector._vector(first), inserted, lane * index, lane)
    extra = {"upper_bits": "zeroed_above_128"} if vex else {}
    return _write(context, row, destination, expression, 128, lane, "memory" if inserted.opcode == "load" else "data_transfer",
                  lane_operation="insert", **extra)


def _x86_extract(context, row, args, op, mnemonic):
    lane = _X86_EXTRACT[mnemonic]
    if len(args) != 3:
        return None
    source = _vector._xmm(args[1])
    if source is None:
        return None
    index = _immediate(args[2]) & (128 // lane - 1)
    context.vector_registers.add(source)
    field = _vector._field(_vector._vector(source), lane * index, lane)
    register = op.register(args[0])
    if register is not None:
        if register.bits != (64 if lane == 64 else 32):
            return None
        return lifted(context, row, "data_transfer", [op.write(args[0], f"lane{lane}({source}, {index})")],
                      [assignment(op, args[0], resize(field, register.bits))])
    memory = _vector._x86_memory(op, args[0])
    if memory is None or memory[0] != lane:
        return None
    return lifted(context, row, "memory", [f"store{lane}({memory[1]}, lane{lane}({source}, {index}));"],
                  [_vector._vector_store(lane, memory[2], field)])


def _x86_sign_mask(context, row, args, op, mnemonic):
    lane = _X86_SIGN_MASK[mnemonic]
    if len(args) != 2:
        return None
    register, source = op.register(args[0]), _vector._xmm(args[1])
    if register is None or source is None or register.bits not in {32, 64} or register.root in {"rsp", "esp"}:
        return None
    context.vector_registers.add(source)
    expression = _lanes("signmask", lane, register.bits, _vector._vector(source))
    return lifted(context, row, "data_transfer", [op.write(args[0], render(expression))],
                  [assignment(op, args[0], expression)])


def _x86_blend(context, row, args, op, mnemonic, vex):
    lane = _X86_BLEND[mnemonic]
    destination, first, _, source, rest = _x86_operands(context, op, args, vex, 3)
    selector = _immediate(rest[0]) & 0xff
    mask = 0
    for index in range(128 // lane):
        if selector >> (index % 8) & 1:
            mask |= ((1 << lane) - 1) << (index * lane)
    expression = Expression("or", 128, (Expression("and", 128, (first, constant(((1 << 128) - 1) ^ mask, 128))),
                                        Expression("and", 128, (source, constant(mask, 128)))))
    return _write(context, row, destination, expression, 128, lane, "data_transfer", lane_operation="blend",
                  **_x86_extra(vex, source))


def _x86_shuffle_dwords(context, row, args, op, vex):
    if len(args) != 3:
        return None
    destination = _vector._xmm(args[0])
    if destination is None:
        return None
    _, source = _vector._x86_source(context, op, args[1])
    selector = _immediate(args[2]) & 0xff
    parts = [Expression("shl", 128, (resize(_vector._field(source, 32 * ((selector >> (2 * index)) & 3), 32), 128),
                                     constant(32 * index, 128))) if index else
             resize(_vector._field(source, 32 * (selector & 3), 32), 128) for index in range(4)]
    expression = parts[0]
    for part in parts[1:]:
        expression = Expression("or", 128, (expression, part))
    context.vector_registers.add(destination)
    return _write(context, row, destination, expression, 128, 32, "data_transfer", lane_operation="shuffle",
                  **_x86_extra(vex, source))


def _x86_extend(context, row, args, op, mnemonic):
    signed, source_lane, target_lane = _X86_EXTEND[mnemonic.removeprefix("v")]
    if len(args) != 2:
        return None
    destination = _vector._xmm(args[0])
    if destination is None:
        return None
    source_bits = 128 // target_lane * source_lane
    register = _vector._xmm(args[1])
    if register is not None:
        context.vector_registers.add(register)
        current = _low(_vector._vector(register), source_bits)
        extra = {}
    else:
        memory = _vector._x86_memory(op, args[1])
        if memory is None or memory[0] != source_bits:
            return None
        current = Expression("load", source_bits, (memory[2],))
        extra = {"memory_width": source_bits}
    lane = source_lane
    while lane < target_lane:
        current = _lanes("sext" if signed else "zext", lane, 2 * current.width, current)
        lane *= 2
    if mnemonic.startswith("v"):
        extra["upper_bits"] = "zeroed_above_128"
    return _write(context, row, destination, current, 128, target_lane,
                  "memory" if register is None else "conversion", lane_operation=mnemonic.removeprefix("v"), **extra)


def _x86_half_move(context, row, args, op, mnemonic):
    """movlps/movlpd/movhps/movhpd：内存与 xmm 低/高 64 位之间搬移，另一半保持不变。"""
    if len(args) != 2:
        return None
    high = mnemonic.startswith("movh")
    destination, source = _vector._xmm(args[0]), _vector._xmm(args[1])
    if destination and source is None:
        memory = _vector._x86_memory(op, args[1])
        if memory is None or memory[0] != 64:
            return None
        context.vector_registers.add(destination)
        old = _vector._vector(destination)
        loaded = Expression("load", 64, (memory[2],))
        expression = _vector._merge(old, loaded, 64 if high else 0, 64)
        return lifted(context, row, "memory", [f"{destination} = vector_insert64({destination}, {int(high)}, load64({memory[1]}));"],
                      [_vector._vector_write(context, destination, expression, memory_width=64)])
    if source and destination is None:
        memory = _vector._x86_memory(op, args[0])
        if memory is None or memory[0] != 64:
            return None
        context.vector_registers.add(source)
        lane_value = _high64(_vector._vector(source)) if high else _low(_vector._vector(source), 64)
        return lifted(context, row, "memory", [f"store64({memory[1]}, lane64({source}, {int(high)}));"],
                      [_vector._vector_store(64, memory[2], lane_value)])
    return None


def _x86_permute(context, row, args, op, mnemonic, vex):
    """pshufb（字节重排）与 packss/packus（带符号/无符号饱和打包）：两个 128 位源，结果 128 位。"""
    name, lane = _X86_PERMUTE[mnemonic]
    destination, first, _, source, _ = _x86_operands(context, op, args, vex, 2)
    expression = Expression(f"vec_{name}{lane}", 128, (first, source))
    return _write(context, row, destination, expression, 128, lane, "data_transfer", lane_operation=name,
                  **_x86_extra(vex, source))


def _x86(context, row, args, op, mnemonic):
    vex = mnemonic.startswith("v") and mnemonic[1:] in _X86_MNEMONICS
    base = mnemonic[1:] if vex else mnemonic
    if base in _X86_HALF_MOVES and not vex:
        return _x86_half_move(context, row, args, op, mnemonic)
    if base not in _X86_MNEMONICS:
        return None
    if any(item.lower().lstrip().startswith(("ymm", "zmm")) for item in args):
        return None
    if base in _X86_PERMUTE:
        return _x86_permute(context, row, args, op, base, vex)
    if base in _X86_BINARY:
        return _x86_binary(context, row, args, op, base, vex)
    if base in _X86_SHIFTS:
        return _x86_shift(context, row, args, op, base, vex)
    if base in _X86_INSERT:
        return _x86_insert(context, row, args, op, base, vex)
    if base in _X86_EXTRACT:
        return _x86_extract(context, row, args, op, base)
    if base in _X86_SIGN_MASK:
        return _x86_sign_mask(context, row, args, op, base)
    if base in _X86_BLEND:
        return _x86_blend(context, row, args, op, base, vex)
    if base in _X86_EXTEND:
        return _x86_extend(context, row, args, op, mnemonic)
    if base == "pshufd":
        return _x86_shuffle_dwords(context, row, args, op, vex)
    return None


# 本模块可能认领的助记符（x86 含 VEX 形式）；调用方可先按架构过滤，避免每条标量指令都进入本模块。
A64_CANDIDATES = _A64_MNEMONICS
X86_CANDIDATES = frozenset(_X86_MNEMONICS | _X86_HALF_MOVES | {"v" + name for name in _X86_MNEMONICS})
MNEMONICS = frozenset(A64_CANDIDATES | X86_CANDIDATES)
# AArch64 形式的第一个操作数总是向量排列、标量 SIMD 寄存器或 {vN.T}[i]；通用寄存器形式直接放过。
A64_FIRST_CHARACTERS = frozenset("vbhsdq{")


def lift(context, row, args, op, mnemonic=None):
    """按通道 SIMD 整数运算；不认识的形式返回 None，交给其它处理器或 opaque。

    mnemonic（可选）为调用方已算好的小写助记符。
    """
    if mnemonic is None:
        mnemonic = str(row["mnemonic"]).lower()
    if not args:
        return None
    architecture = context.architecture
    if architecture == "arm64":
        if mnemonic not in A64_CANDIDATES or args[0][:1] not in A64_FIRST_CHARACTERS:
            return None
        return _a64(context, row, args, op, mnemonic)
    if architecture.startswith("x86") and mnemonic in X86_CANDIDATES:
        return _x86(context, row, args, op, mnemonic)
    return None


__all__ = ["lift", "render", "LANE_OPCODES"]
