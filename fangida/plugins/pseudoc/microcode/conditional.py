"""AArch32 条件执行：剥离条件后缀，提升基础指令，再把寄存器赋值改写为条件选择。

只改写结果全部是寄存器赋值、不写标志、不访存的基础指令：条件成立时取新值，否则保持
原值（microcode 的 select，false_operation 为 identity，与 csel/cmov 的表示一致）。

以下情形保持 opaque（由调用方回退）：
- 条件访存（ldrne/strne）：条件不成立时不得访问内存，而 select 的源会被无条件求值；
- 条件设置标志（addseq、cmpeq）：标志只在条件成立时改写，现有标志模型无法精确表达；
- 基础指令本身无法提升，或产生赋值以外的操作（如 adc 的进位输入）；
- 移位/循环移位的计数不是小于宽度的常量（lslne Rd, Rn, Rm 等寄存器控制移位，lsrne/asrne #32）：
  microcode 语义精确（计数取低 8 位，≥ 宽度时 LSL/LSR 得 0），但可读伪 C 会渲染成 C 中未定义的
  x << n / x >> 32 或含义不明的辅助函数调用，条件形式因此保持显式的 opaque。

带 branch_info 的转移（b<cond>、bl<cond>、bx<cond>、写 pc 的条件指令）由控制流处理器
负责，这里不接管。助记符只有在“去掉末尾两个字母后恰好是白名单中的基础助记符、且末尾
两个字母是条件码”时才视为条件执行，因此 teq（t+eq）、mls（m+ls）、umulls/smulls
（umull/smull+s）、lsls（lsl+s）、movs（mov+s）、muls 等以条件码字母结尾的普通指令
不会被误拆。
"""
from __future__ import annotations

from .common import lifted
from .conditions import ARM_CONDITIONS, condition
from .ir import Expression, MicroOperation

# 允许条件执行改写的基础助记符：现有处理器对它们只产生寄存器赋值。
CONDITIONAL_BASES = frozenset({
    "mov", "mvn", "movw", "movt", "neg",
    "add", "sub", "and", "orr", "eor", "bic", "orn",
    "lsl", "lsr", "asr", "ror",
    "mul", "mla", "mls", "umull", "smull", "udiv", "sdiv",
    "sxtb", "sxth", "uxtb", "uxth", "ubfx", "sbfx", "bfi", "bfc", "rev",
})


# 以条件码字母结尾、但本身是无条件指令的 AArch32 助记符（teq 不是 t+eq，mls 不是 m+ls）。
_ARM_UNCONDITIONAL = frozenset({"teq", "mls", "vmls", "svc", "hvc"})
# 设置标志的“基础+s”形式：末尾的 cs/hs/ls/vs 与条件码同形（movs 是 mov+s 而不是 mo+vs，
# bics 是 bic+s，umulls 是 umull+s）。条件执行的同名形式多出两个字母（movvs、lslls、adccs）。
_ARM_FLAG_SETTING_BASES = frozenset({
    "mov", "mvn", "neg", "mul", "mla", "lsl", "lsr", "asr", "ror", "rrx",
    "add", "adc", "sub", "sbc", "rsb", "rsc", "and", "orr", "eor", "bic", "orn",
    "umull", "smull", "umlal", "smlal",
})
# 移位与循环移位：条件改写要求计数是小于宽度的常量（见模块说明）。
_SHIFT_OPCODES = frozenset({"shl", "lshr", "ashr", "ror", "rol"})


def split_condition(mnemonic: str) -> tuple[str, str] | None:
    """(基础助记符, 条件码)；不是可改写的条件执行形式时返回 None。"""
    if type(mnemonic) is not str:
        return None
    mnemonic = mnemonic.lower()
    base, code = mnemonic[:-2], mnemonic[-2:]
    if code in ARM_CONDITIONS and base in CONDITIONAL_BASES:
        return base, code
    return None


def may_be_conditional(mnemonic) -> bool:
    """AArch32 助记符是否可能是条件执行形式（条件不成立时指令什么都不写）。

    与 split_condition 不同，这里不限定基础助记符：ldrne、popne、ldmibne、ldrne.w、vmovne.f32
    都算。只排除已知的同形无条件指令。供 opaque 回退判断快照写集合是否“必定写入”：
    误判为条件执行只会让写入退回“可能写”，是保守方向。
    """
    if type(mnemonic) is not str:
        return False
    head = mnemonic.lower().split(".", 1)[0]
    if len(head) <= 2 or head[-2:] not in ARM_CONDITIONS or head in _ARM_UNCONDITIONAL:
        return False
    return not (head[-1] == "s" and head[:-1] in _ARM_FLAG_SETTING_BASES)


def _bounded_shifts(expression: Expression) -> bool:
    """表达式中每个移位/循环移位的计数都是 [0, 宽度) 内的常量。"""
    if expression.opcode in _SHIFT_OPCODES:
        count = expression.args[1] if len(expression.args) == 2 else None
        if (count is None or count.opcode != "constant" or type(count.value) is not int or
                not 0 <= count.value < expression.width):
            return False
    return all(_bounded_shifts(argument) for argument in expression.args)


def _pure_assignments(result) -> bool:
    if not result.supported or result.flag_effect != "preserve" or result.memory_effect != "none":
        return False
    if not result.operations:
        return False
    for operation in result.operations:
        if (operation.opcode != "assign" or not operation.output or operation.expression is None or
                not operation.expression.pure or not _bounded_shifts(operation.expression)):
            return False
    return True


def lift(handlers, context, row, args, op):
    """AArch32 条件执行指令的提升；不是条件执行形式时返回 None。

    handlers 为注册表的处理器链（用于提升剥离条件后的基础指令）。基础指令无法安全
    改写时抛出 ValueError，由注册表回退为 opaque。
    """
    if context.architecture != "arm" or (row.get("branch_info") or {}).get("kind"):
        return None
    split = split_condition(row.get("mnemonic"))
    if split is None:
        return None
    base, code = split
    # 条件在指令执行前按当前标志求值：先于基础指令的任何副作用取得谓词。
    predicate = condition("arm", code, context.comparison_origin)
    base_row = {**row, "mnemonic": base}
    result = None
    for handler in handlers:
        result = handler(context, base_row, args, op)
        if result is not None:
            break
    if result is None or not _pure_assignments(result):
        raise ValueError("Conditional base instruction is not a pure register assignment with bounded shifts")
    if predicate.origin is None or predicate.relation == "flags":
        context.flags = True  # 机器级伪 C 直接引用 flags，需要声明它
    attributes_condition = predicate.to_dict()
    operations = []
    for assignment in result.operations:
        attributes = assignment.attributes
        storage = attributes.get("storage_width", assignment.width)
        width = attributes.get("destination_width", assignment.width)
        shift = attributes.get("bit_offset", 0)
        old = Expression("register", storage, name=assignment.output)
        if width != storage:
            old = Expression("extract", width, (old,), value=shift)
        operations.append(MicroOperation("select", assignment.width, (assignment.expression, old), assignment.output,
            attributes={**attributes, "condition": attributes_condition, "false_operation": "identity",
                        "conditional_execution": True, "base_mnemonic": base, "source_read": "conditional"}))
    body = " ".join(result.statements)
    statements = [f"if ({predicate.render()}) {{ {body} }}"]
    return lifted(context, row, "conditional", statements, operations)
