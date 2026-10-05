"""按通道（lane）的 SIMD 整数运算语义：opcode 表与精确求值，不涉及指令解析。

每个 opcode 名字自带通道宽度 L（vec_add32、vec_narrow16…），表达式宽度 W 是结果的总位数，
通道数由宽度推出；可读 C 的通用回退把它渲染成 ``{opcode}_{W}(参数…)``（例如
``vec_add32_128(a, b)``），因此名字与宽度一起就完整确定了语义。所有通道互相独立，
通道 i 占第 [i*L, (i+1)*L) 位（小端通道序，与 AArch64 Vn.T[i]、x86 xmm 的元素序一致）。

opcode 族（L 为通道位宽，W 为表达式宽度；参数宽度必须与下表一致，否则视为格式错误）：

* 同宽二元（参数 a、b 宽度均为 W）：
  vec_add/vec_sub/vec_mul：模 2^L 的加/减/乘；
  vec_cmeq/vec_cmhi/vec_cmhs/vec_cmgt/vec_cmge/vec_cmtst：关系成立时通道为全 1，否则为 0
  （hi/hs 为无符号 >、>=，gt/ge 为带符号 >、>=，tst 为 (a & b) != 0）；
  vec_umax/vec_umin/vec_smax/vec_smin：无符号/带符号的最大、最小值；
  vec_ushl/vec_sshl：按 b 通道最低字节的带符号值移位（正数左移、负数右移；ushl 逻辑右移，
  sshl 算术右移；移出全部位时为 0 或符号填充），与 AArch64 USHL/SSHL 相同；
  vec_uqadd/vec_uqsub：无符号饱和加/减（结果截到 [0, 2^L-1]），vec_sqadd/vec_sqsub：带符号饱和加/减
  （结果截到 [-2^(L-1), 2^(L-1)-1]），与 AArch64 UQADD/UQSUB/SQADD/SQSUB 及 x86 PADDUS/PSUBUS/PADDS/PSUBS 相同
  （AArch64 饱和时还会置位 FPSR.QC，这个累积状态位不是寄存器结果，由提升器记在操作属性里）。
* 同宽一元（参数宽度 W）：vec_neg（模 2^L 取负）、vec_abs（带符号绝对值，最小负数保持不变）。
* 按标量计数移位（a 宽度 W，计数为任意宽度的无符号数）：vec_shl/vec_lshr/vec_ashr；
  计数 >= L 时 shl/lshr 结果为 0、ashr 为符号填充（与 AArch64 立即数移位及 x86 PSLL/PSRL/PSRA 相同）。
* 窄化 vec_narrow{L}（L ∈ 16/32/64，参数宽度 2W）：每个 L 位通道截断为低 L/2 位，结果通道数不变。
* 扩展 vec_zext{L}/vec_sext{L}（L ∈ 8/16/32，参数宽度 W/2）：每个 L 位通道零/符号扩展为 2L 位。
* 归约（参数宽度为 L 的整数倍，结果宽度 W = L）：vec_addv（模 2^L 求和）、vec_umaxv/vec_uminv/
  vec_smaxv/vec_sminv。
* 符号位掩码 vec_signmask{L}（参数宽度为 L 的整数倍，结果宽度 W 不小于通道数）：结果第 i 位是
  第 i 个通道的最高位，其余位为 0（x86 PMOVMSKB/MOVMSKPS/MOVMSKPD）。

跨通道的重排与打包在单独的表 PERMUTE_OPCODES 中（参数 a、b 与结果都是 W 位）：

* vec_pshufb8（W = 128）：x86 PSHUFB（SSSE3，xmm 形式）。结果第 i 个字节：b 的第 i 个字节最高位为 1 时为 0，
  否则为 a 的第 (b[i] & 15) 个字节。
* vec_packss{L}/vec_packus{L}（L ∈ 16/32，W = 128）：x86 PACKSSWB/PACKSSDW/PACKUSWB/PACKUSDW。a、b 的每个 L 位
  通道按带符号数解释，饱和到 L/2 位（ss：带符号范围，us：无符号范围 [0, 2^(L/2)-1]）；结果低半依次是 a 的
  通道，高半依次是 b 的通道。
"""
from __future__ import annotations

_LANE_WIDTHS = (8, 16, 32, 64)
_BINARY = ("add", "sub", "mul", "cmeq", "cmhi", "cmhs", "cmgt", "cmge", "cmtst",
           "umax", "umin", "smax", "smin", "ushl", "sshl", "uqadd", "uqsub", "sqadd", "sqsub")
_UNARY = ("neg", "abs")
_SHIFTS = ("shl", "lshr", "ashr")
_REDUCTIONS = ("addv", "umaxv", "uminv", "smaxv", "sminv")

# opcode -> (族, 运算, 通道宽度)
LANE_OPCODES: dict[str, tuple[str, str, int]] = {}
for _lane in _LANE_WIDTHS:
    for _name in _BINARY:
        LANE_OPCODES[f"vec_{_name}{_lane}"] = ("binary", _name, _lane)
    for _name in _UNARY:
        LANE_OPCODES[f"vec_{_name}{_lane}"] = ("unary", _name, _lane)
    for _name in _SHIFTS:
        LANE_OPCODES[f"vec_{_name}{_lane}"] = ("shift", _name, _lane)
    for _name in _REDUCTIONS:
        LANE_OPCODES[f"vec_{_name}{_lane}"] = ("reduce", _name, _lane)
    LANE_OPCODES[f"vec_signmask{_lane}"] = ("signmask", "signmask", _lane)
    if _lane > 8:
        LANE_OPCODES[f"vec_narrow{_lane}"] = ("narrow", "narrow", _lane)
    if _lane < 64:
        LANE_OPCODES[f"vec_zext{_lane}"] = ("widen", "zext", _lane)
        LANE_OPCODES[f"vec_sext{_lane}"] = ("widen", "sext", _lane)
del _lane, _name


def lane_opcode(operation: str, lane: int) -> str:
    """运算名与通道宽度对应的 opcode；组合不存在时抛出 ValueError。"""
    opcode = f"vec_{operation}{lane}"
    if opcode not in LANE_OPCODES:
        raise ValueError(f"No lane operation {operation} for {lane}-bit lanes")
    return opcode


def _signed(value: int, width: int) -> int:
    value &= (1 << width) - 1
    return value - (1 << width) if value >> (width - 1) else value


def _split(value: int, lane: int, count: int) -> list[int]:
    mask = (1 << lane) - 1
    return [(value >> (index * lane)) & mask for index in range(count)]


def _join(lanes: list[int], lane: int) -> int:
    mask, result = (1 << lane) - 1, 0
    for index, item in enumerate(lanes):
        result |= (item & mask) << (index * lane)
    return result


def _variable_shift(value: int, amount: int, lane: int, signed: bool) -> int:
    """AArch64 USHL/SSHL 的单通道语义：amount 为带符号移位量（正左移、负右移）。"""
    if amount >= 0:
        return (value << amount) & ((1 << lane) - 1) if amount < lane else 0
    source = _signed(value, lane) if signed else value
    return (source >> -amount) & ((1 << lane) - 1)  # Python 的 >> 对负数是向下取整的算术右移


def _binary(name: str, left: int, right: int, lane: int) -> int:
    mask = (1 << lane) - 1
    if name == "add":
        return (left + right) & mask
    if name == "sub":
        return (left - right) & mask
    if name == "mul":
        return (left * right) & mask
    if name in {"ushl", "sshl"}:
        return _variable_shift(left, _signed(right, 8), lane, name == "sshl")
    if name in {"uqadd", "uqsub"}:
        # 无符号饱和：精确和/差截到 [0, 2^L - 1]。
        exact = left + right if name == "uqadd" else left - right
        return min(max(exact, 0), mask)
    if name in {"sqadd", "sqsub"}:
        # 带符号饱和：按带符号值求精确和/差，再截到 [-2^(L-1), 2^(L-1) - 1]。
        first, second = _signed(left, lane), _signed(right, lane)
        exact = first + second if name == "sqadd" else first - second
        return min(max(exact, -(1 << (lane - 1))), (1 << (lane - 1)) - 1) & mask
    if name in {"smax", "smin", "cmgt", "cmge"}:
        left_value, right_value = _signed(left, lane), _signed(right, lane)
    else:
        left_value, right_value = left, right
    if name in {"umax", "smax"}:
        return (left if left_value >= right_value else right) & mask
    if name in {"umin", "smin"}:
        return (left if left_value <= right_value else right) & mask
    truth = {"cmeq": left_value == right_value, "cmhi": left_value > right_value,
             "cmhs": left_value >= right_value, "cmgt": left_value > right_value,
             "cmge": left_value >= right_value, "cmtst": (left & right) != 0}[name]
    return mask if truth else 0


def _check(condition: bool) -> None:
    if not condition:
        raise ValueError("Malformed lane operation widths")


def evaluate_lanes(opcode: str, width: int, args: list[int], arg_widths: tuple[int, ...]) -> int:
    """按 LANE_OPCODES 的定义求值；args 为已求值的无符号整数，arg_widths 为各参数表达式宽度。"""
    family, name, lane = LANE_OPCODES[opcode]
    if family == "binary":
        _check(len(args) == 2 and width % lane == 0 and arg_widths == (width, width))
        count = width // lane
        return _join([_binary(name, left, right, lane) for left, right in
                      zip(_split(args[0], lane, count), _split(args[1], lane, count))], lane)
    if family == "unary":
        _check(len(args) == 1 and width % lane == 0 and arg_widths == (width,))
        lanes = _split(args[0], lane, width // lane)
        if name == "neg":
            return _join([-item for item in lanes], lane)
        return _join([abs(_signed(item, lane)) for item in lanes], lane)
    if family == "shift":
        _check(len(args) == 2 and width % lane == 0 and arg_widths[0] == width)
        count, lanes = args[1], _split(args[0], lane, width // lane)
        if name == "ashr":
            return _join([_signed(item, lane) >> min(count, lane) for item in lanes], lane)
        if count >= lane:
            return 0
        return _join([(item << count) if name == "shl" else (item >> count) for item in lanes], lane)
    if family == "narrow":
        _check(len(args) == 1 and arg_widths == (2 * width,) and (2 * width) % lane == 0)
        return _join(_split(args[0], lane, 2 * width // lane), lane // 2)
    if family == "widen":
        _check(len(args) == 1 and 2 * arg_widths[0] == width and arg_widths[0] % lane == 0)
        lanes = _split(args[0], lane, arg_widths[0] // lane)
        if name == "sext":
            lanes = [_signed(item, lane) for item in lanes]
        return _join(lanes, 2 * lane)
    if family == "reduce":
        _check(len(args) == 1 and width == lane and arg_widths[0] % lane == 0)
        lanes = _split(args[0], lane, arg_widths[0] // lane)
        if name == "addv":
            return sum(lanes) & ((1 << lane) - 1)
        if name.startswith("s"):
            chosen = (max if name == "smaxv" else min)(lanes, key=lambda item: _signed(item, lane))
        else:
            chosen = (max if name == "umaxv" else min)(lanes)
        return chosen
    # signmask
    _check(len(args) == 1 and arg_widths[0] % lane == 0 and width >= arg_widths[0] // lane)
    lanes = _split(args[0], lane, arg_widths[0] // lane)
    return sum(((item >> (lane - 1)) & 1) << index for index, item in enumerate(lanes))


# ---------------------------------------------------------------------------
# 跨通道重排与饱和打包（PERMUTE_OPCODES，见模块说明）
# ---------------------------------------------------------------------------

# opcode -> (族, 运算, 源通道宽度)
PERMUTE_OPCODES: dict[str, tuple[str, str, int]] = {"vec_pshufb8": ("shuffle", "pshufb", 8)}
for _lane in (16, 32):
    PERMUTE_OPCODES[f"vec_packss{_lane}"] = ("pack", "ss", _lane)
    PERMUTE_OPCODES[f"vec_packus{_lane}"] = ("pack", "us", _lane)
del _lane


def evaluate_permute(opcode: str, width: int, args: list[int], arg_widths: tuple[int, ...]) -> int:
    """按 PERMUTE_OPCODES 的定义求值（只接受 W = 128 的两参数形式，其余视为格式错误）。"""
    family, name, lane = PERMUTE_OPCODES[opcode]
    _check(len(args) == 2 and width == 128 and arg_widths == (128, 128))
    if family == "shuffle":
        table, control = _split(args[0], 8, 16), _split(args[1], 8, 16)
        return _join([0 if index & 0x80 else table[index & 15] for index in control], 8)
    half = lane // 2
    if name == "ss":
        low, high = -(1 << (half - 1)), (1 << (half - 1)) - 1
    else:
        low, high = 0, (1 << half) - 1
    lanes = [min(max(_signed(item, lane), low), high) for value in args for item in _split(value, lane, 128 // lane)]
    return _join(lanes, half)
