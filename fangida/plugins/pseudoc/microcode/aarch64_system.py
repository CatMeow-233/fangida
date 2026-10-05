"""AArch64 系统寄存器访问（MRS/MSR）与指针认证（PAC）的显式语义。

MRS/MSR：
* NZCV 与条件标志精确互转：N/Z/C/V 依次对应第 31..28 位，其余位读为 0（RES0），写入时忽略。
  ``mrs xN, nzcv`` 是由 flags.N/Z/C/V 拼出的普通位向量表达式；``msr nzcv, xN`` 是一个
  flags_nzcv 操作（按上述位置整体写四个标志），因此保存/恢复标志的往返可以逐位求值。
* 白名单中读取没有副作用的寄存器（TLS 指针 tpidr_el0/tpidrro_el0、fpcr/fpsr、计数器、ID 寄存器等）
  读为带寄存器名的 system_register 表达式；它不是纯表达式（计数器、FPSR 会变化，ID/计数器
  在 EL0 访问可能陷入后由操作系统模拟），求值只接受调用方给出的寄存器值。
* EL0 可写且除寄存器本身外没有其它架构副作用的寄存器（tpidr_el0、tpidr2_el0、fpcr、fpsr）
  写为显式 system_register_write 操作；fpcr/fpsr 的写入同时改变浮点环境。
* 其余系统寄存器（特权寄存器、PSTATE 字段立即数形式、读取有副作用的寄存器、RNDR 等会改写
  标志的寄存器）不在这里建模，保持 opaque 屏障。

指针认证（FEAT_PAuth）：
* PACIA/PACIB/PACDA/PACDB（含 SP/Z/1716 变体）只改写目的寄存器：Xd = pacXX(Xd, 修饰值)；
  AUTxx 同理为 autXX；XPACI/XPACD/XPACLRI 为 xpaci/xpacd；PACGA 为 pacga(Xn, Xm)。
  结果取决于密钥与 PAuth 实现/配置，求值为未知；aut* 在实现 FEAT_FPAC 时认证失败会陷入
  （否则产生不可用的指针），记为非纯表达式。
* HINT 空间的形式（paciasp、autiasp、xpaclri、pacia1716…）在未实现 PAuth 的处理器上按 NOP
  执行，记在属性 without_pauth 中；寄存器形式在未实现时是未定义指令。paciasp/pacibsp 同时
  是隐式的 BTI c 落点，与 bti 处理一致，不产生额外效果。
"""
from __future__ import annotations

from .common import assignment, lifted, value
from .ir import Expression, MicroOperation, constant

# NZCV 各标志在系统寄存器中的位置。
NZCV_BITS = (("N", 31), ("Z", 30), ("C", 29), ("V", 28))

# 读取无副作用、在 EL0 可读（或由操作系统陷入后模拟）的系统寄存器：名字 -> 访问说明。
_READABLE = {
    "tpidr_el0": "thread_pointer", "tpidrro_el0": "thread_pointer_read_only", "tpidr2_el0": "sme_thread_pointer",
    "fpcr": "fp_control", "fpsr": "fp_status",
    "cntvct_el0": "virtual_counter", "cntpct_el0": "physical_counter",
    "cntvctss_el0": "virtual_counter", "cntpctss_el0": "physical_counter", "cntfrq_el0": "counter_frequency",
    "ctr_el0": "cache_type", "dczid_el0": "dc_zva_block_size",
    "midr_el1": "identification", "mpidr_el1": "identification", "revidr_el1": "identification",
}
for _name in ("pfr0", "pfr1", "pfr2", "dfr0", "dfr1", "isar0", "isar1", "isar2", "isar3",
              "mmfr0", "mmfr1", "mmfr2", "mmfr3", "mmfr4", "zfr0", "smfr0", "afr0", "afr1"):
    _READABLE[f"id_aa64{_name}_el1"] = "identification"
del _name
# 每次读取可能得到不同值的寄存器（计数器随时间递增，FPSR 随浮点运算累积异常标志）。
_VOLATILE = frozenset({"cntvct_el0", "cntpct_el0", "cntvctss_el0", "cntpctss_el0", "fpsr"})
# 在 EL0 访问可能陷入更高异常级别（由操作系统模拟或报告未定义指令）的寄存器。
# tpidr2_el0 只在实现 FEAT_SME 时存在：未实现时访问是未定义指令，SME 访问未启用
# （CPACR_EL1.SMEN）时读写都会陷入 EL1。
_MAY_TRAP = frozenset(name for name, kind in _READABLE.items() if kind == "identification") | {
    "ctr_el0", "cntvct_el0", "cntpct_el0", "cntvctss_el0", "cntpctss_el0", "cntfrq_el0", "tpidr2_el0"}
# EL0 可写、除寄存器本身外没有其它架构副作用（fpcr/fpsr 改变浮点环境）。
_WRITABLE = frozenset({"tpidr_el0", "tpidr2_el0", "fpcr", "fpsr"})
_FP_ENVIRONMENT = frozenset({"fpcr", "fpsr"})

# 指针认证：助记符 -> (动作, 密钥, 目的, 修饰值)；修饰值为寄存器名、"zero" 或 None（第二个操作数）。
_PAC_HINTS = {
    "paciasp": ("sign", "ia", "x30", "sp"), "pacibsp": ("sign", "ib", "x30", "sp"),
    "paciaz": ("sign", "ia", "x30", "zero"), "pacibz": ("sign", "ib", "x30", "zero"),
    "pacia1716": ("sign", "ia", "x17", "x16"), "pacib1716": ("sign", "ib", "x17", "x16"),
    "autiasp": ("authenticate", "ia", "x30", "sp"), "autibsp": ("authenticate", "ib", "x30", "sp"),
    "autiaz": ("authenticate", "ia", "x30", "zero"), "autibz": ("authenticate", "ib", "x30", "zero"),
    "autia1716": ("authenticate", "ia", "x17", "x16"), "autib1716": ("authenticate", "ib", "x17", "x16"),
    "xpaclri": ("strip", "i", "x30", None),
}
_PAC_REGISTER_FORMS = {}
for _key in ("ia", "ib", "da", "db"):
    _PAC_REGISTER_FORMS["pac" + _key] = ("sign", _key, None, None)
    _PAC_REGISTER_FORMS["aut" + _key] = ("authenticate", _key, None, None)
    _PAC_REGISTER_FORMS[f"pac{_key[0]}z{_key[1]}"] = ("sign", _key, None, "zero")
    _PAC_REGISTER_FORMS[f"aut{_key[0]}z{_key[1]}"] = ("authenticate", _key, None, "zero")
del _key
_PAC_REGISTER_FORMS.update({"xpaci": ("strip", "i", None, None), "xpacd": ("strip", "d", None, None),
                            "pacga": ("generic", "ga", None, None)})


def pac_opcode(action, key):
    """指针认证动作与密钥对应的表达式 opcode（pacia、autib、xpaci…）。"""
    return {"sign": "pac", "authenticate": "aut", "strip": "xpac", "generic": "pac"}[action] + key


def pac_attributes(action, key, modifier, *, hint_space):
    """PAC 操作的属性：只描述语义与实现依赖，不涉及任何目标求解。"""
    attributes = {"pointer_authentication": action, "key": key, "modifier": modifier,
                  "result": "key_and_configuration_dependent",
                  "without_pauth": "nop" if hint_space else "undefined_instruction"}
    if action == "authenticate":
        attributes["authentication_failure"] = "trap_with_fpac_else_unusable_pointer"
    if action == "strip":
        attributes["result"] = "pac_field_cleared_per_configured_address_size"
    return attributes


def _x_register(op, token, *, allow_sp=False, allow_zero=True):
    register = op.register(token)
    if (register is None or register.bits != 64 or (register.root == "sp" and not allow_sp)
            or (register.root == "zero" and not allow_zero)):
        raise ValueError("Invalid AArch64 64-bit register operand")
    return register


def _lift_pac(context, row, args, op, mnemonic):
    hint_space = mnemonic in _PAC_HINTS
    action, key, destination, modifier = _PAC_HINTS[mnemonic] if hint_space else _PAC_REGISTER_FORMS[mnemonic]
    if hint_space:
        if args:
            return None
    else:
        expected = 3 if action == "generic" else 1 if action == "strip" or modifier == "zero" else 2
        if len(args) != expected:
            return None
        destination = args[0]
        _x_register(op, destination, allow_zero=False)
        if action != "strip" and modifier is None:
            modifier = args[-1]
    if action == "generic":
        _x_register(op, args[1], allow_zero=False)
        _x_register(op, args[2], allow_sp=True, allow_zero=False)
        inputs = (value(op, args[1]), value(op, args[2]))
        texts = (op.read(args[1]), op.read(args[2]))
        modifier = args[2].lower()
    else:
        pointer = value(op, destination)
        if action == "strip":
            inputs, texts = (pointer,), (op.read(destination),)
        elif modifier == "zero":
            inputs, texts = (pointer, constant(0, 64)), (op.read(destination), "0")
        else:
            _x_register(op, modifier, allow_sp=True, allow_zero=False)
            inputs, texts = (pointer, value(op, modifier)), (op.read(destination), op.read(modifier))
            modifier = op.register(modifier).root
    opcode = pac_opcode(action, key)
    expression = Expression(opcode, 64, inputs)
    operation = assignment(op, destination, expression)
    attributes = dict(operation.attributes)
    attributes.update(pac_attributes(action, key, modifier, hint_space=hint_space))
    if mnemonic in {"paciasp", "pacibsp"}:
        attributes["branch_target_landing_pad"] = "bti_c"
    operation = MicroOperation(operation.opcode, operation.width, operation.inputs, operation.output,
                               operation.expression, attributes)
    statement = op.write(destination, f"{opcode}_64({', '.join(texts)})")
    return lifted(context, row, "system", [statement + f" /* pointer authentication: {action} */"], [operation])


def _nzcv_expression():
    """mrs xN, nzcv 的值：flags.N/Z/C/V 放在第 31..28 位，其余位为 0。"""
    result = None
    for name, bit in NZCV_BITS:
        flag = Expression("zext", 64, (Expression("register", 1, name="flags." + name),))
        part = Expression("shl", 64, (flag, constant(bit, 64)))
        result = part if result is None else Expression("or", 64, (result, part))
    return result


# 表达式不可变，模块加载时构造一次即可复用（与 common.py 缓存寄存器表达式的做法相同）。
_NZCV_EXPRESSION = _nzcv_expression()
_NZCV_TEXT = " | ".join(f"((uint64_t)flags.{flag} << {bit})" for flag, bit in NZCV_BITS)


def _lift_mrs(context, row, args, op):
    if len(args) != 2:
        return None
    name = args[1].lower().strip()
    destination = _x_register(op, args[0])
    if name == "nzcv":
        context.flags = True
        expression, text = _NZCV_EXPRESSION, _NZCV_TEXT
        operation = assignment(op, args[0], expression)
        if destination.root != "zero":
            attributes = dict(operation.attributes, system_register="nzcv", layout="N31_Z30_C29_V28_res0")
            operation = MicroOperation(operation.opcode, operation.width, operation.inputs, operation.output,
                                       operation.expression, attributes)
        return lifted(context, row, "system", [op.write(args[0], text)], [operation], extra_reads=("flags",))
    kind = _READABLE.get(name)
    if kind is None:
        return None
    expression = Expression("system_register", 64, name=name)
    operation = assignment(op, args[0], expression)
    if destination.root != "zero":
        attributes = dict(operation.attributes, system_register=name, register_kind=kind,
                          volatile=name in _VOLATILE, may_trap=name in _MAY_TRAP)
        operation = MicroOperation(operation.opcode, operation.width, operation.inputs, operation.output,
                                   operation.expression, attributes)
    extra = ("fp_environment",) if name in _FP_ENVIRONMENT else ()
    return lifted(context, row, "system", [op.write(args[0], f'__arm_rsr64("{name}")')], [operation],
                  extra_reads=extra)


def _lift_msr(context, row, args, op):
    if len(args) != 2:
        return None
    name = args[0].lower().strip()
    if name != "nzcv" and name not in _WRITABLE:
        return None
    if op.register(args[1]) is None:
        return None  # 立即数形式只用于 PSTATE 字段（daifset、spsel…），不在这里建模
    _x_register(op, args[1])
    source = value(op, args[1])
    text = op.read(args[1])
    if name == "nzcv":
        statements = [f"flags.{flag} = ({text} >> {bit}) & 1;" for flag, bit in NZCV_BITS]
        operation = MicroOperation("flags_nzcv", 64, (source,), attributes={
            "family": "arm", "system_register": "nzcv", "bit_positions": dict(NZCV_BITS),
            "other_bits": "ignored"})
        return lifted(context, row, "system", statements, [operation], flag_effect="write")
    attributes = {"system_register": name, "effect": "write", "barrier": False,
                  "register_kind": _READABLE[name], "may_trap": name in _MAY_TRAP}
    if name in _FP_ENVIRONMENT:
        attributes["outputs"] = ["fp_environment"]
        attributes["changes"] = "fp_environment"
    operation = MicroOperation("system_register_write", 64, (source,), attributes=attributes)
    return lifted(context, row, "system", [f'__arm_wsr64("{name}", {text});'], [operation])


def lift(context, row, args, op):
    """mrs/msr 与 PAC 指令；不认识的形式返回 None（交给 opaque）。"""
    mnemonic = str(row["mnemonic"]).lower()
    if mnemonic == "mrs":
        return _lift_mrs(context, row, args, op)
    if mnemonic == "msr":
        return _lift_msr(context, row, args, op)
    if mnemonic in _PAC_HINTS or mnemonic in _PAC_REGISTER_FORMS:
        return _lift_pac(context, row, args, op, mnemonic)
    return None
