"""Branches, calls and terminal effects consume semantic predicates."""
from __future__ import annotations

import json

from ..native_operands import identifier
from .common import lifted, value
from .conditions import ARM_CONDITIONS, condition
from .ir import Expression, MicroOperation, constant
from .aarch64_system import pac_attributes, pac_opcode


def branch_condition(context, mnemonic, args, op):
    x86 = context.architecture.startswith("x86")
    if x86 and mnemonic in {"jcxz", "jecxz", "jrcxz"}:
        register = mnemonic[1:-1]
        return f"{op.read(register)} == 0", {"kind": "zero_test", "relation": "eq", "value": value(op, register).to_dict()}, (value(op, register),)
    if not x86 and mnemonic in {"cbz", "cbnz"} and len(args) == 2:
        relation = "eq" if mnemonic == "cbz" else "ne"
        return f"{op.read(args[0])} {'==' if relation == 'eq' else '!='} 0", {
            "kind": "zero_test", "relation": relation, "value": value(op, args[0]).to_dict()}, (value(op, args[0]),)
    if not x86 and mnemonic in {"tbz", "tbnz"} and len(args) == 3:
        relation = "eq" if mnemonic == "tbz" else "ne"
        return f"({op.read(args[0])} & (1ULL << {op.read(args[1])})) {'==' if relation == 'eq' else '!='} 0", {
            "kind": "bit_test", "relation": relation, "value": value(op, args[0]).to_dict(), "bit": value(op, args[1]).to_dict()}, (value(op, args[0]), value(op, args[1]))
    code = mnemonic[1:] if x86 or not mnemonic.startswith("b.") else mnemonic[2:]
    if not x86 and code not in ARM_CONDITIONS:
        # AArch32 bx<cond>/bxj<cond>（条件间接跳转，如 bxeq lr）与 AArch64 bc.<cond>：
        # 去掉基础助记符后才是条件码；b<cond> 与 b.<cond> 的既有解析保持不变。
        for prefix in ("bxj", "bx", "bc."):
            if mnemonic.startswith(prefix) and mnemonic[len(prefix):] in ARM_CONDITIONS:
                code = mnemonic[len(prefix):]
                break
    predicate = condition("x86" if x86 else "arm", code, context.comparison_origin)
    return predicate.render(), predicate.to_dict(), ()


# 带指针认证的 A64 间接转移：助记符 -> (密钥, 修饰值是否为 0)。认证后的指针才是转移目标；
# 这里只表示目标操作数（autXX(Xn, 修饰值)），不求解目标。
_AUTHENTICATED_BRANCHES = {"braa": ("ia", False), "brab": ("ib", False), "braaz": ("ia", True), "brabz": ("ib", True),
                           "blraa": ("ia", False), "blrab": ("ib", False), "blraaz": ("ia", True), "blrabz": ("ib", True)}
_AUTHENTICATED_RETURNS = {"retaa": "ia", "retab": "ib"}


def _authenticated_target(context, mnemonic, args, op):
    """braa/blraa 等的目标表达式 autXX(Xn, Xm|SP 或 0)：(文本, 表达式, 属性)；不是这类指令时返回 None。"""
    if context.architecture != "arm64" or mnemonic not in _AUTHENTICATED_BRANCHES:
        return None
    key, zero_modifier = _AUTHENTICATED_BRANCHES[mnemonic]
    if len(args) != (1 if zero_modifier else 2):
        raise ValueError("Invalid authenticated branch operands")
    target = op.register(args[0])
    modifier = None if zero_modifier else op.register(args[1])
    if target is None or target.bits != 64 or target.root in {"sp", "zero"} or (
            not zero_modifier and (modifier is None or modifier.bits != 64 or modifier.root == "zero")):
        raise ValueError("Invalid authenticated branch register")
    opcode = pac_opcode("authenticate", key)
    modifier_value = constant(0, 64) if zero_modifier else value(op, args[1])
    modifier_text = "0" if zero_modifier else op.read(args[1])
    expression = Expression(opcode, 64, (value(op, args[0]), modifier_value))
    attributes = pac_attributes("authenticate", key, "zero" if zero_modifier else modifier.root, hint_space=False)
    return f"{opcode}_64({op.read(args[0])}, {modifier_text})", expression, attributes


def lift(context, row, args, op):
    mnemonic = str(row["mnemonic"]).lower()
    branch = row.get("branch_info") or {}
    kind = branch.get("kind")
    if kind == "return":
        context.registers.add(context.return_register)
        attributes = {"abi": "symbolic", "stack_cleanup": args}
        if context.architecture == "arm64" and mnemonic in _AUTHENTICATED_RETURNS:
            # retaa/retab：返回前用 SP 作修饰值认证 LR（x30），认证失败时陷入或跳到不可用地址。
            attributes.update(pac_attributes("authenticate", _AUTHENTICATED_RETURNS[mnemonic], "sp", hint_space=False),
                              authenticated_pointer="x30")
        return lifted(context, row, "control_flow", [f"return {context.return_register}; /* ABI return register */"],
            [MicroOperation("return", context.bits, (Expression("register", context.bits, name=context.return_register),),
                attributes=attributes)])
    if kind == "trap":
        return lifted(context, row, "system", [f"trap({json.dumps(mnemonic)});"],
            [MicroOperation("trap", attributes={"reason": mnemonic, "terminal": True})])
    if kind == "jump":
        target = branch.get("target")
        transfer = context.transfer(target)
        attributes = {"target": target, "target_resolution": "direct" if isinstance(target, int) else "indirect_unknown"}
        inputs = ()
        authenticated = None if isinstance(target, int) else _authenticated_target(context, mnemonic, args, op)
        if authenticated is not None:
            text, expression, authentication = authenticated
            inputs = (expression,)
            attributes["target_expression"] = expression.to_dict()
            attributes.update(authentication)
            transfer = f"return unresolved_jump({text}); /* indirect target */"
        elif not isinstance(target, int) and len(args) == 1:
            expression = value(op, args[0])
            inputs = (expression,)
            attributes["target_expression"] = expression.to_dict()
            transfer = f"return unresolved_jump({op.read(args[0])}); /* indirect target */"
        if branch.get("conditional"):
            clause, predicate, inputs = branch_condition(context, mnemonic, args, op)
            context.flags |= "kind" not in predicate
            attributes.update(condition=predicate, fallthrough=row["addr"] + row["size"], uses_flags="kind" not in predicate)
            return lifted(context, row, "control_flow", [f"if ({clause}) {{ {transfer} }}",
                context.transfer(row["addr"] + row["size"], "fallthrough")],
                [MicroOperation("branch", inputs=inputs, attributes=attributes)])
        return lifted(context, row, "control_flow", [transfer], [MicroOperation("jump", inputs=inputs, attributes=attributes)])
    if kind == "call":
        target = branch.get("target")
        names = context.function.get("pseudoc_symbols", {})
        name = identifier(names.get(target, f"sub_{target:x}")) if isinstance(target, int) else "indirect_call"
        call_args = "/* symbolic args */" if isinstance(target, int) else "symbolic_target(), /* symbolic args */"
        inputs = ()
        authenticated = None if isinstance(target, int) else _authenticated_target(context, mnemonic, args, op)
        if authenticated is not None:
            call_args = f"{authenticated[0]}, /* symbolic args */"
            inputs = (authenticated[1],)
        elif not isinstance(target, int) and len(args) == 1:
            call_args = f"{op.read(args[0])}, /* symbolic args */"
            inputs = (value(op, args[0]),)
        context.registers.add(context.return_register)
        attributes = {"target": target, "arguments": "symbolic", "clobbers": "unknown_abi", "barrier": True}
        if authenticated is not None:
            attributes.update(authenticated[2])
        if inputs:
            attributes["target_expression"] = inputs[0].to_dict()
        site = getattr(context, "noreturn_sites", {}).get(row["addr"])
        if site is not None and not branch.get("conditional"):
            # 核心 CFG 已证明此调用不返回并截断了落空边（cfg.noreturn_calls）：
            # 标记后重建把它当作路径终点，不再按地址相邻接到下一条指令。
            attributes["noreturn"] = True
            attributes["noreturn_evidence"] = str(site.get("evidence") or "noreturn")
        return lifted(context, row, "control_flow", [f"{context.return_register} = {name}({call_args}); /* ABI clobbers symbolic */",
            "flags = symbolic_flags();"], [MicroOperation("call", context.bits, inputs, context.return_register,
                attributes=attributes)],
            flag_effect="unknown", memory_effect="unknown")
    return None
