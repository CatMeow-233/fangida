"""Restore call arguments from declarations or bounded callee summaries."""
from __future__ import annotations

from .expressions import cast
from .model import Value
from .prototypes import lookup
from .types import valid_type

# 可变参数候选的上限：格式串解析出的个数超过候选时，尾部仍写 unknown_arguments()。
MAX_VARIADIC_CANDIDATES = 12


def _argument(index, expressions, abi, stack_argument):
    """调用点第 index 个整数/指针实参：先用 ABI 参数寄存器，用尽后取调用点的栈参数槽。"""
    if index < len(abi.arguments):
        root = abi.arguments[index]
        return expressions.variable(root) if root in expressions.variables else Value("unknown", abi.word * 8)
    if stack_argument is not None:
        value = stack_argument(index - len(abi.arguments))
        if value is not None:
            return value
    return Value("unknown", abi.word * 8)


def _site_import(site, target):
    """调用点的已核实导入名（经指针槽位的间接调用）：{name, slot} 或 None。"""
    if isinstance(target, int) or not isinstance(site, dict):
        return None
    name = site.get("name")
    return site if isinstance(name, str) and name else None


def restore_call(operation, expressions, abi, callees, symbols, initialized, at, *,
                 stack_argument=None, variadic_on_stack=False, explicit=None, site=None, own=None):
    """恢复一次调用。

    stack_argument(i)：调用点第 i 个栈实参槽（可选）；variadic_on_stack：可变参数一律经栈传递
    （Apple arm64 约定）；explicit：本块内、上一次调用之后被显式赋值的参数寄存器（可选）；
    site：本调用点经指针槽位调用的已核实导入 {"name", "slot"}（可选，来自链接证据的
    call_sites）；own：被重建函数自己的 {"target", "name", "parameters": [(寄存器, 类型)], "return_type"}
    （可选）——直接调用自身（自递归）时按本函数恢复出的签名给出实参与返回类型，与函数定义一致。
    这些都是可选参数，旧调用方式与结果不变。
    """
    attributes = operation.get("attributes", {})
    target = attributes.get("target")
    imported = _site_import(site, target)
    if (isinstance(own, dict) and imported is None and isinstance(target, int) and target == own.get("target")
            and isinstance(own.get("name"), str) and own["name"]):
        return _own_call(operation, expressions, abi, own, at, target, stack_argument, callees.get(target, {}))
    summary = callees.get(target, {}) if imported is None else {"name": imported["name"]}
    name = summary.get("name", symbols.get(target, "unknown_function"))
    if name == "unknown_function" and isinstance(target,int):
        if target not in expressions.call_names:
            ordinal=len(expressions.call_names)+1
            expressions.call_names[target]="unknown_function" if ordinal==1 else f"unknown_function_{ordinal}"
        name=expressions.call_names[target]
    from ..native_operands import identifier
    name = identifier(name)
    arguments, evidence = [], "unknown"
    # 名字来自符号/链接证据的已知库函数：按原型给出参数个数与类型（声明的原型优先）。
    prototype = lookup(name) if (isinstance(target, int) or imported is not None) and not summary.get("signature_complete") else None
    return_type = summary.get("return_type")
    if prototype is not None:
        evidence = "known_prototype"
        for index, (_, ctype) in enumerate(prototype.parameters):
            argument = _argument(index, expressions, abi, stack_argument)
            arguments.append(cast(argument, valid_type(ctype), argument.width))
        if prototype.variadic:
            fixed = len(prototype.parameters)
            if variadic_on_stack:
                candidates = [stack_argument(index) if stack_argument is not None else None for index in range(MAX_VARIADIC_CANDIDATES)]
                candidates = [item if item is not None else Value("unknown", abi.word * 8) for item in candidates]
            else:
                candidates = [_argument(fixed + index, expressions, abi, stack_argument) for index in range(MAX_VARIADIC_CANDIDATES)]
            # 占位：格式串在常量传播之后才可读，由 readability.resolve_variadic 定下实参个数。
            # 首个参数记录调用地址，便于回填调用证据（常量不会被传播改写）。
            arguments.append(Value("variadic", abi.word * 8, (Value("constant", abi.word * 8, number=at if isinstance(at, int) else -1), *candidates), name=prototype.format_kind,
                                   number=prototype.format_index if prototype.format_index is not None else -1))
        return_type = prototype.return_type
    elif "parameters" in summary:
        evidence = "declared_prototype" if summary.get("signature_complete") else "callee_read_before_definition"
        parameters = summary["parameters"]
        incomplete = not summary.get("signature_complete") and not summary.get("argument_uses_complete")
        if incomplete:
            by_slot = {abi.arguments.index(item.get("register")): item for item in parameters if item.get("register") in abi.arguments}
            parameters = [by_slot.get(index, {"register": None}) for index in range(max(by_slot, default=-1) + 1)]
        for parameter in parameters:
            root = parameter.get("register")
            argument = expressions.variable(root) if root in expressions.variables else Value("unknown", abi.word * 8)
            if parameter.get("type"):
                argument = cast(argument, valid_type(parameter["type"]), argument.width)
            arguments.append(argument)
        if incomplete:
            # 被调函数可能把更多参数寄存器转交给其它函数：调用前在本块内被显式赋值的后续
            # 参数寄存器依次列出（只是传入的入口值不算），并保留 unknown_arguments() 表示个数仍未知。
            for root in abi.arguments[len(parameters):] if explicit is not None else ():
                if root not in explicit or root not in expressions.variables:
                    break
                arguments.append(expressions.variable(root))
            arguments.append(Value("call", abi.word * 8, name="unknown_arguments"))
    else:
        # Caller writes alone cannot establish arity. Show available leading
        # values and an explicit unresolved tail instead of inventing a call.
        for root in abi.arguments:
            if root not in initialized:
                break
            arguments.append(expressions.variable(root))
        arguments.append(Value("call", abi.word * 8, name="unknown_arguments"))
    if not isinstance(target, int) and imported is None:
        name = "indirect_call"
        if attributes.get("target_expression"):
            arguments.insert(0, expressions.lift(attributes["target_expression"], at))
    recovered_count = len(arguments) - int(any(argument.op == "call" and argument.name == "unknown_arguments" or argument.op == "variadic" for argument in arguments)) - int(not isinstance(target, int) and imported is None and bool(attributes.get("target_expression")))
    value = Value("call", operation.get("width", abi.word * 8), tuple(arguments), name=name,
                 ctype=valid_type(return_type, "uint64_t" if abi.word == 8 else "uint32_t"), effect=True)
    if summary.get("return_zero_extended") and prototype is None:
        value = cast(value, "uint32_t", 32)
    return_extension = "declared_or_full_width"
    import re
    narrow = re.fullmatch(r"u?int(8|16|32)_t", value.ctype)
    if narrow and int(narrow.group(1)) < operation.get("width", abi.word * 8) and not (summary.get("return_zero_extended") and prototype is None):
        width = int(narrow.group(1))
        value = Value("call", abi.word * 8, (cast(value, f"uint{width}_t", width),),
                      name=f"unknown_return_upper{width}", ctype="uint64_t" if abi.word == 8 else "uint32_t", effect=True)
        return_extension = "unknown_upper_bits"
    result = {
        "address": at, "target": target, "name": name, "argument_evidence": evidence,
        "argument_count_known": ("parameters" in summary and (summary.get("signature_complete", False)
                                                              or summary.get("argument_uses_complete", False))) or (
            prototype is not None and not prototype.variadic),
        "return_extension": return_extension,
        "recovered_argument_count": recovered_count,
        # 参数个数只在“间接调用的目标只读取调用前显式写入的寄存器”约定下确定（新增字段）。
        "argument_count_assumed": bool(summary.get("argument_uses_assumed")) and prototype is None
                                  and not summary.get("signature_complete")}
    if prototype is not None:
        result["prototype"] = prototype.name
    if imported is not None:
        # 调用目标是导入函数（经已核实的指针槽位），不是本映像内的代码地址。
        result.update(import_slot=imported.get("slot"), target_kind="import_pointer_slot")
    return value, result


def _own_call(operation, expressions, abi, own, at, target, stack_argument=None, summary=None):
    """自递归调用：被调函数就是正在重建的函数，它的形参（入口处先读后写的参数寄存器与栈参数，或声明的
    原型）就是本函数签名列出的那些。实参按定义中的形参顺序取调用点这些寄存器的当前值（栈形参取调用点
    对应的栈实参槽）并按形参类型转换，返回类型取本函数的返回类型；文本中的调用因此与函数定义的原型
    一致（不再写 unknown_arguments()）。"""
    arguments = []
    for kind, key, ctype in own.get("parameters", ()):
        unknown = Value("unknown", abi.word * 8, ctype="uint64_t" if abi.word == 8 else "uint32_t")
        if kind == "stack":
            argument = stack_argument(key) if stack_argument is not None else None
            argument = argument if argument is not None else unknown
        else:
            argument = expressions.variable(key) if key in expressions.variables else unknown
        if ctype:
            argument = cast(argument, valid_type(ctype), argument.width)
        arguments.append(argument)
    word_type = "uint64_t" if abi.word == 8 else "uint32_t"
    return_type = valid_type(own.get("return_type"), word_type)
    value = Value("call", operation.get("width", abi.word * 8), tuple(arguments), name=own["name"],
                  ctype=return_type, effect=True)
    return_extension = "declared_or_full_width"
    # 调用摘要证明返回值零扩展（如 x86-64 写 eax）时与其它调用相同：结果按 uint32_t 使用，高位为 0。
    zero_extended = bool((summary or {}).get("return_zero_extended"))
    if zero_extended:
        value = cast(value, "uint32_t", 32)
    import re
    narrow = re.fullmatch(r"u?int(8|16|32)_t", value.ctype)
    if narrow and int(narrow.group(1)) < operation.get("width", abi.word * 8) and not zero_extended:
        # 与其它调用相同：本函数只恢复出低 W 位的返回值，调用者看到的高位未知。
        width = int(narrow.group(1))
        value = Value("call", abi.word * 8, (cast(value, f"uint{width}_t", width),),
                      name=f"unknown_return_upper{width}", ctype=word_type, effect=True)
        return_extension = "unknown_upper_bits"
    return value, {"address": at, "target": target, "name": own["name"], "argument_evidence": "own_signature",
                   "argument_count_known": True, "return_extension": return_extension,
                   "recovered_argument_count": len(arguments), "argument_count_assumed": False}


def restore_transfer(descriptor, expressions, abi, callees, symbols, initialized, at, *,
                     stack_argument=None, variadic_on_stack=False, site=None):
    """A control transfer has no proven C return contract or continuation."""
    attributes = {key: descriptor[key] for key in ("target", "target_expression") if key in descriptor}
    operation = {"opcode": "call", "width": abi.word * 8, "attributes": attributes}
    value, evidence = restore_call(operation, expressions, abi, callees, symbols, initialized, at,
                                   stack_argument=stack_argument, variadic_on_stack=variadic_on_stack, site=site)
    while value.op == "cast" or value.op == "call" and value.name.startswith("unknown_return_upper"):
        value = value.args[0]
    arguments = value.args
    target = attributes.get("target")
    if isinstance(target, int):
        known_name = callees.get(target, {}).get("name") or symbols.get(target)
        target_value = Value("function", abi.word * 8, name=evidence["name"]) if isinstance(known_name, str) and known_name else Value("constant", abi.word * 8, number=target)
        arguments = (target_value, *arguments)
    elif _site_import(site, target) is not None:
        # 经已核实指针槽位的尾跳转（导入桩/thunk 自身或尾调用）：目标就是该导入函数。
        arguments = (Value("function", abi.word * 8, name=evidence["name"]), *arguments)
    elif not attributes.get("target_expression"):
        arguments = (Value("unknown", abi.word * 8), *arguments)
    evidence.update(kind="tail_transfer", target_expression=attributes.get("target_expression"))
    return Value("call", abi.word * 8, tuple(arguments), name="tail_transfer", ctype="void", effect=True), evidence
