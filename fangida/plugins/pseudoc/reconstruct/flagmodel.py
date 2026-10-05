"""标志来源模型：把设置条件标志的 microcode 操作归一成可还原为 C 条件的形式。

flagflow（跨块到达分析）与 lower（块内还原）共用这里的分类，保证两边对“哪条指令
建立了可还原的标志、哪条指令把标志变成未知”的判断完全一致。

归一后的种类（kind）与输入：

* ``flags_sub``    (a, b)：标志等同整数减法 a - b（cmp/subs/sub/neg，以及加非零常数的
  cmn/adds/add，它们与“减去相反数”逐位等价）；可还原全部整数关系与符号位条件。
* ``flags_sub_nc`` (a, b)：同上但指令不写进位（x86 inc/dec），不能还原无符号条件。
* ``flags_sub_cinv`` (a, b)：x86 加非零常数：除进位外等同 a - b，但 x86 的 CF 对加法是进位、
  对减法是借位，极性相反，无符号关系须取反（ARM 的 C 对两者都是“进位/不借位”，无此问题）。
* ``flags_add``    (a, b)：标志等同 a + b（寄存器形式的 cmn/adds/add）。
* ``test``         (a, b)：结果为 a & b，进位与溢出清零（x86 test、AArch64 tst）。
* ``flags_logic``  (r,)  ：结果为 r，进位与溢出清零（and/or/xor/ands 等）。
* ``flags_result`` (r,)  ：只知道 Z/N 来自结果 r（x86 常数逻辑移位、AArch32 只写 N/Z 的逻辑运算）。
* ``flags_sar``    (a, n)：x86 常数算术右移 a >> n 的 Z/N（避免依赖带符号右移的实现定义行为）。
* ``ccmp:<inner>:<nzcv>`` (a, b)：AArch64 条件比较；条件成立时标志等同 inner(a, b)，
  否则为常量 nzcv。lower 会在输入前额外放一个快照条件本身的布尔临时变量。
* ``flags_umul`` / ``flags_smul`` (a, b)：x86 MUL / IMUL（单操作数 multiply_wide 与双/三操作数 imul 的
  flags_multiply）：只有 CF = OF = “W 位乘积超出 W 位”（无符号 / 带符号）有定义，SF/ZF/AF/PF 机器未定义；
  只还原 o/no/b/c/nae/ae/nb/nc。

返回 None 表示该操作写标志但无法建模（屏障）；``writes_flags`` 判断一条记录是否写标志。
"""
from __future__ import annotations

from ..microcode.evaluate import UnknownValue, evaluate_expression

# 这些整行效果表示指令不改写条件标志（与 microcode 分析中的判断一致）。
_PRESERVING_EFFECTS = frozenset({"preserve", "partial_non_condition"})
# 自身不以 flags_ 开头、但会改写或使标志未知的操作。
_FLAG_WRITERS = frozenset({"compare", "compare_float", "compare_add", "conditional_compare", "test",
                           "flag_write", "call", "opaque", "system_transition", "bit_test",
                           "rotate_carry", "multiply_wide", "divide_wide", "carry_input"})
# 可以作为标志来源的 opcode（其余写标志的操作都是屏障）。
SOURCE_OPCODES = frozenset({"compare", "compare_add", "conditional_compare", "test", "flags_logic",
                            "flags_sub", "flags_add", "flags_unary", "flags_shift", "multiply_wide",
                            "flags_multiply", "bit_test"})


def _constant(width, value):
    """构造与 microcode 序列化格式一致的常量表达式。"""
    return {"opcode": "constant", "width": width, "value": value % (1 << width), "domain": "bitvector"}


def _constant_value(expression):
    """表达式是整数常量时返回其值，否则返回 None。"""
    if isinstance(expression, dict) and expression.get("opcode") == "constant" and type(expression.get("value")) is int:
        return expression["value"]
    return None


def _addition(left, right, width, family):
    """把 a + b 的标志归一：加非零且非最小负数的常数 k 等价于与 -k 比较。

    a + k 与 a - (-k) 的结果逐位相同；k != 0 时 a + k 的进位等于 a >= -k（无符号），
    在 ARM 上正是减法的 C（不借位），在 x86 上则是减法 CF（借位）的反面；k 不是
    2^(w-1) 时 -k 可表示、溢出判断一致。加 0 时进位和溢出都为 0，相当于逻辑运算的结果标志。
    """
    constant = _constant_value(right)
    if constant is None:
        constant, left, right = _constant_value(left), right, left
    if constant is not None:
        constant %= 1 << width
        if constant == 0:
            return "flags_logic", (left,)
        if constant != 1 << (width - 1):
            return ("flags_sub" if family == "arm" else "flags_sub_cinv"), (left, _constant(width, -constant))
    return "flags_add", (left, right)


def writes_flags(row, operation=None):
    """该记录（或其中一条操作）是否改写或使条件标志未知。"""
    if operation is not None:
        opcode = operation["opcode"]
        return opcode.startswith("flags_") or opcode in _FLAG_WRITERS
    return row.get("flag_effect", "unknown") not in _PRESERVING_EFFECTS


def flag_source(row, operation):
    """把一条设置标志的操作归一成 (kind, 输入表达式元组, 宽度)；无法建模时返回 None。"""
    opcode = operation["opcode"]
    if opcode not in SOURCE_OPCODES:
        return None
    attributes = operation.get("attributes", {}) or {}
    inputs, width = tuple(operation.get("inputs", ())), operation.get("width", 0)
    if not width or attributes.get("carry"):
        return None  # adc/sbb/adcs/sbcs 依赖进位输入，不能还原为单纯的比较
    partial = row.get("flag_effect") == "partial"  # AArch32 逻辑运算只写 N/Z（C 来自移位器、V 不变）
    if opcode in {"compare", "flags_sub"} and len(inputs) == 2:
        return "flags_sub", inputs, width
    family = attributes.get("family", attributes.get("flag_family", "x86"))
    if opcode in {"compare_add", "flags_add"} and len(inputs) == 2:
        kind, values = _addition(inputs[0], inputs[1], width, family)
        return kind, values, width
    if opcode == "test" and len(inputs) == 2:
        if partial:
            return "flags_result", ({"opcode": "and", "width": width, "args": list(inputs), "domain": "bitvector"},), width
        return "test", inputs, width
    if opcode == "flags_logic" and len(inputs) == 1:
        return ("flags_result" if partial else "flags_logic"), inputs, width
    if opcode == "flags_unary" and len(inputs) == 1:
        action = attributes.get("operation")
        if action == "neg":
            return "flags_sub", (_constant(width, 0), inputs[0]), width  # neg a 的标志等同 0 - a
        if action in {"inc", "dec"}:
            # inc/dec 不写 CF：标志等同 a - (-1) / a - 1，但只能还原相等、带符号与符号位条件。
            return "flags_sub_nc", (inputs[0], _constant(width, -1 if action == "inc" else 1)), width
        return None
    if opcode == "flags_shift" and len(inputs) == 2:
        action = attributes.get("operation")
        if action not in {"lshr", "ashr", "shl"}:
            return None  # 循环移位不写 ZF/SF
        try:
            count = int(evaluate_expression(inputs[1]))
        except (UnknownValue, ValueError, TypeError, KeyError):
            return None  # 移位计数为 0 时标志保持不变，只接受已知的非零计数
        if not 0 < count < width:
            return None
        if action == "ashr":
            # 算术右移 0 < n < w：符号位等于原值符号位，结果为 0 当且仅当逻辑右移结果为 0。
            return "flags_sar", (inputs[0], _constant(width, count)), width
        result = {"opcode": action, "width": width, "args": [inputs[0], _constant(width, count)], "domain": "bitvector"}
        return "flags_result", (result,), width
    if opcode == "bit_test" and len(inputs) == 2:
        # x86 bt/bts/btr/btc：只有 CF = 第 index 位有定义（index 已取模宽度），ZF 保持、OF/SF/AF/PF 机器未定义；
        # 只还原依赖 CF 的条件（b/c/nae、ae/nb/nc）。inputs 为 (操作数, 已取模的位索引)。
        return "flags_bit_test", inputs, width
    if opcode in {"multiply_wide", "flags_multiply"} and len(inputs) == 2:
        # x86 MUL/IMUL：CF = OF = 乘积超出 W 位（MUL 无符号、IMUL 带符号）；其余标志未定义。
        if opcode == "flags_multiply" and not {"CF", "OF"} <= set(attributes.get("defined", ("CF", "OF"))):
            return None
        return ("flags_smul" if attributes.get("signed") else "flags_umul"), inputs, width
    if opcode == "conditional_compare" and len(inputs) == 2:
        nzcv = attributes.get("false_nzcv")
        condition = attributes.get("condition")
        if type(nzcv) is not int or not 0 <= nzcv <= 15 or not isinstance(condition, dict):
            return None
        if attributes.get("operation") == "add":
            inner, values = _addition(inputs[0], inputs[1], width, "arm")
        elif attributes.get("operation") == "sub":
            inner, values = "flags_sub", inputs
        else:
            return None
        return f"ccmp:{inner}:{nzcv}", values, width
    return None
