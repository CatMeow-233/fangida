"""Bounded source recovery: naming, types, ABI, frames, dataflow and regions."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar

from .abi import signature
from .cfg import build_cfg, reachable, coalesce
from .dataflow import optimize, uninitialized_stack_reads, remove_unused_private_stores, combine_zero_initialization
from .lower import Recovery
from .model import Value
from .structure import Structurer
from .types import integer_type, valid_type
from ..models import PseudocodeResult, validate_limits
from ..native_operands import identifier

RECONSTRUCTION_VERSION = "1.0"
MAX_SOURCE_INSTRUCTIONS = 512
#: 按需生成可放宽到的单函数源码恢复指令上限（与 validate_limits 的 max_instructions 上限一致）。
MAX_SOURCE_INSTRUCTIONS_LIMIT = 8192

# 当前上下文（线程/任务）内放宽的源码恢复上限；None 表示沿用 MAX_SOURCE_INSTRUCTIONS。
_SOURCE_LIMIT: ContextVar[int | None] = ContextVar("fangida_source_instruction_limit", default=None)


def _source_limit():
    """生效的单函数源码恢复指令上限（默认 MAX_SOURCE_INSTRUCTIONS，调用时读取以便补丁生效）。"""
    value = _SOURCE_LIMIT.get()
    return MAX_SOURCE_INSTRUCTIONS if value is None else value


@contextmanager
def source_instruction_limit(limit):
    """在当前上下文内把单函数源码恢复的指令上限设为 limit（1～MAX_SOURCE_INSTRUCTIONS_LIMIT）。

    只影响本线程/任务的调用，退出即恢复；未进入作用域的调用与原实现完全相同。
    """
    if type(limit) is not int or not 1 <= limit <= MAX_SOURCE_INSTRUCTIONS_LIMIT:
        raise ValueError(f"source instruction limit must be an integer in [1, {MAX_SOURCE_INSTRUCTIONS_LIMIT}]")
    token = _SOURCE_LIMIT.set(limit)
    try:
        yield limit
    finally:
        _SOURCE_LIMIT.reset(token)


def reconstruct_function(function, architecture, *, microcode=None, context=None,
                         max_instructions=512, max_chars=32768):
    from .cfg import view_scope
    with view_scope():
        return _reconstruct_function(function, architecture, microcode=microcode, context=context,
                                     max_instructions=max_instructions, max_chars=max_chars)


def _reconstruct_function(function, architecture, *, microcode=None, context=None,
                          max_instructions=512, max_chars=32768):
    validate_limits(max_instructions, max_chars)
    context = {**function.get("pseudoc_context", {}), **(context or {})}
    if microcode is None:
        from ..microcode import lift_function
        lifted = lift_function(function, architecture, max_instructions=max_instructions)
        records, truncated = lifted["instructions"], lifted["truncated"]
    else:
        records = list(microcode[:max_instructions])
        truncated = len(microcode) > max_instructions
    semantic_records = records
    source_limit = _source_limit()
    if len(records) > source_limit:
        records = records[:source_limit]
        truncated = True
    if not records:
        return PseudocodeResult(warnings=("No semantic snapshot to reconstruct",))
    entry = function.get("start", records[0]["addr"])
    from .abi import select_abi
    from .specialize import specialize
    abi = select_abi(architecture, {**context, **{key: function[key] for key in ("abi", "calling_convention") if key in function}})
    function = _known_definition(function, context, abi)
    original_records, original_entry = records, entry
    records, entry, specialization = specialize(records, entry, abi)
    function = {**function, "start": entry, "source_original_start": original_entry}
    blocks = coalesce(reachable(build_cfg(records), entry), entry)
    if not blocks:
        return PseudocodeResult(warnings=("Function entry is outside the semantic snapshot",), truncated=True)
    recovery = Recovery(function, records, blocks, architecture, context, signature_records=original_records).run()
    recovery.unresolved.extend(recovery.expressions.unresolved)
    from .regions import retain_machine_regions
    machine_regions = retain_machine_regions(blocks, entry, recovery.frame, architecture, original_records=semantic_records)
    region_addresses = {row["addr"]: region["name"] for region in machine_regions for row in region["instructions"]}
    if region_addresses:
        # 与逐项线性查找相同（同一地址取第一行）；没有机器状态片段时无需查找。
        originals = {}
        for row in records:
            originals.setdefault(row["addr"], row.get("original_address", row["addr"]))
        for item in recovery.calls + recovery.unresolved:
            address = item.get("address")
            original = originals.get(address, address) if isinstance(address, int) else next(
                (row.get("original_address", row["addr"]) for row in records if row["addr"] == address), address)
            if original in region_addresses:
                item["machine_region"] = region_addresses[original]
    recovery.unresolved.extend({"address": region["entry"], "kind": "machine_state_region",
                                "name": region["name"], "reasons": region["reasons"]} for region in machine_regions)
    source_incoming = optimize(blocks).get(entry,set())
    remove_unused_private_stores(blocks,recovery.frame.slots)
    # 可读性：常量折叠、只读字符串/函数地址还原、按格式串确定可变参数个数。
    # 改写可能让参数寄存器的定义变为死代码，因此再做一次传播与删除。
    from .readability import fold_and_resolve, resolve_variadic, simplify_statements
    fold_and_resolve(blocks, context.get("data_references"), recovery.bits)
    # 折叠与字面量还原不会减少变量使用；只有可变参数定数后去掉的候选实参会让定义变成死代码。
    if resolve_variadic(blocks, recovery.calls, recovery.unresolved, recovery.abi, recovery.variadic_on_stack):
        source_incoming = optimize(blocks).get(entry,set())
        remove_unused_private_stores(blocks,recovery.frame.slots)
    # 按定义-使用网拆分复用的寄存器并确定类型，再按用途命名（只改名字与类型，使用点语义不变）。
    from .variables import split_webs, name_variables, retype_parameters
    split_webs(blocks, entry, recovery)
    retype_parameters(blocks, recovery)
    renamed = name_variables(blocks, entry, recovery)
    source_incoming = {renamed.get(item, item) for item in source_incoming}
    used, assigned = set(), set()
    for block in blocks.values():
        if block.predicate:
            used.update(block.predicate.variables())
        for statement in block.statements:
            used.update(statement.uses())
            if statement.destination:
                assigned.add(statement.destination)
    required = used | assigned
    # 有按本函数签名恢复的自递归调用时，签名保留全部栈形参：调用处的实参列表与定义逐个对应。
    variables = [variable for variable in recovery.variables.values() if variable.name in required or
                 variable.parameter and (not variable.storage.startswith("stack:") or recovery.own_calls)]
    unknown_stack = uninitialized_stack_reads(blocks, entry, recovery.frame.slots)
    combine_zero_initialization(blocks,recovery.frame.slots)
    parameters = [variable for variable in variables if variable.parameter]
    result_variable = recovery.variables.get(recovery.abi.return_register)
    return_type = valid_type(recovery.profile.get("return_type"), result_variable.ctype if result_variable else integer_type(recovery.bits))
    if "[" in return_type:
        return_type = "void *"
    from .lower import definition_name
    name = definition_name(function, context, original_entry)  # Original addresses remain in provenance.
    def declaration(variable):
        if "[" in variable.ctype:
            base, extent = variable.ctype.split("[", 1)
            return f"{base} {variable.name}[{extent}"
        return f"{variable.ctype} {variable.name}"
    signature_text = ", ".join(declaration(variable) for variable in parameters) or "void"
    if isinstance(function.get("prototype"), dict) and function["prototype"].get("variadic") is True and parameters:
        signature_text += ", ..."
    variable_types = {variable.name: variable.ctype for variable in recovery.variables.values()}
    simplify_statements(blocks, variable_types, return_type, recovery.bits,
                        readable_addresses=context.get("import_slots"))
    refine = None
    if not recovery.profile.get("signature_complete"):
        # 没有声明原型时：最终的返回值全是同一种指针（如字符串字面量）就按该指针类型声明返回值。
        from .readability import refine_return_type
        refine = lambda statements: refine_return_type(statements, return_type, recovery.bits)  # noqa: E731
    # 占位 unknown_value() 在前导中声明为返回整数：赋给指针变量时显式转换（只为可编译，不赋予语义）。
    for block in blocks.values():
        for statement in block.statements:
            if (statement.kind == "assign" and statement.value is not None and statement.value.op == "unknown"
                    and "*" in variable_types.get(statement.destination, "") and "[" not in variable_types[statement.destination]):
                statement.value = Value("cast", statement.value.width, (statement.value,), ctype=variable_types[statement.destination])
    # 输出前的指针/整数一致性检查：只在 C 不接受隐式转换处写出显式转换（值逐位不变，不改声明类型）；
    # 自递归调用按本函数最终的形参与返回类型检查。
    from .typecheck import TypeCoercion
    coerce = TypeCoercion(variable_types, return_type, recovery.bits, function_name=name,
                          parameter_types=[variable.ctype for variable in parameters], check_all=bool(recovery.own_calls))
    structurer = Structurer(blocks, entry, variable_types, refine_returns=refine, coerce=coerce)
    body = structurer.render()
    if structurer.return_type:
        return_type = structurer.return_type
    # 结构化时可能把 `x = v; return x;` 合并或复制短尾块：按最终输出的语句重新确定需要声明的变量。
    # 返回值高位未知只在仍被使用时才算未解决：结果被丢弃或已被截成低位时去掉该项。
    upper_used = set()
    upper_pending = any(item.get("kind") == "call_return_upper_bits" for item in recovery.unresolved)
    for statement in structurer.printed_statements if upper_pending else ():  # 没有这类未解决项时不必逐句查找
        if statement.value is not None and _has_upper_wrapper(statement.value):
            upper_used.add(statement.address)
            if id(statement) in structurer.folded_from:
                upper_used.add(structurer.folded_from[id(statement)])
    recovery.unresolved[:] = [item for item in recovery.unresolved
                              if item.get("kind") != "call_return_upper_bits" or item.get("address") in upper_used]
    printed = structurer.used_names | structurer.assigned_names
    variables = [variable for variable in variables if variable.name in printed or
                 variable.parameter and not variable.storage.startswith("stack:")]
    used = set(structurer.used_names)
    declarations = []
    for variable in variables:
        if not variable.parameter:
            initial = " = unknown_value()" if variable.name in source_incoming and "[" not in variable.ctype or variable.name in unknown_stack and "[" not in variable.ctype else ""
            if initial and "*" in variable.ctype:
                # 占位 unknown_value() 在前导中声明为返回整数：指针变量的初值显式转换（只为可编译）。
                initial = f" = ({variable.ctype})unknown_value()"
            declarations.append("    " + declaration(variable) + initial + ";")
            if variable.name in unknown_stack and "[" in variable.ctype:
                declarations.append(f"    initialize_unknown_bytes({variable.name}, sizeof({variable.name}));")
    globals_text = [f"extern uint8_t *{name};" for name in recovery.expressions.globals.values() if name in used]
    partial_note = ["/* 部分源码重建：标出的机器状态片段尚未恢复，不能作为等价 C 执行。 */"] if machine_regions else []
    text = "\n".join(partial_note + globals_text + [f"{return_type} {name}({signature_text}) {{", *declarations,
        *( [""] if declarations else []), *body, "}"])
    # 仅指令快照本身被截断（不含 CFG 出口）；CFG 出口另行说明：到已核实导入函数的尾跳转不算缺失。
    snapshot_truncated = truncated
    frontier_sources = frozenset(item.get("from") for item in function.get("cfg", {}).get("frontier", ()) or ()
                                 if isinstance(item, dict))
    truncated |= bool(function.get("cfg", {}).get("frontier")) or function.get("cfg", {}).get("complete") is False
    for block in blocks.values():
        if None in block.successors:
            recovery.unresolved.append({"address": block.address, "kind": "control_flow_target"})
    for variable in variables:
        if variable.name in source_incoming and not variable.parameter and not variable.storage.startswith("stack:"):
            recovery.unresolved.append({"kind": "incoming_value", "storage": variable.storage})
        if variable.name in unknown_stack:
            recovery.unresolved.append({"kind": "incoming_stack_value", "storage": variable.storage})
    report = {"version": RECONSTRUCTION_VERSION, "style": "readable", "abi": recovery.abi.name,
        "specialization": specialization,
        "abi_evidence": recovery.abi.confidence, "signature_complete": recovery.profile["signature_complete"],
        "parameters": [variable.to_dict() for variable in parameters], "return_type": return_type,
        "variables": [variable.to_dict() for variable in variables], "stack_frame": recovery.frame.slots,
        "calls": recovery.calls, "unresolved": recovery.unresolved, "machine_regions": machine_regions,
        "source_semantics_complete": not machine_regions and not truncated and not recovery.unresolved and not structurer.labels,
        "globals": [{"name": name, "address": address, "kind": "memory_region"} for address, name in recovery.expressions.globals.items()],
        "structured_branches": structurer.structured_branches, "structured_loops": structurer.structured_loops,
        "residual_gotos": len(structurer.labels), "complete": not truncated and not recovery.unresolved and not structurer.labels}
    # 文本引用的外部函数（新增字段，缺省视为空列表）：pseudoc_prelude(结果) 据此附上声明，使文本可单独编译。
    from .prelude import external_functions
    # 输出的语句都在 printed_statements 里；if/while/switch 条件由各块谓词组合而成（叶子相同）。
    printed_values = [statement.value for statement in structurer.printed_statements if statement.value is not None]
    printed_values.extend(block.predicate for block in blocks.values() if block.predicate is not None)
    report["external_functions"] = external_functions(printed_values, name, recovery.calls, integer_type(recovery.bits))
    provenance = {row["addr"]: row.get("original_address", row["addr"]) for row in records}
    for evidence in report["calls"] + report["unresolved"]:
        if "address" in evidence:
            evidence["address"] = provenance.get(evidence["address"], evidence["address"])
    header = _header_line(function, context, name, original_entry, report, truncated, snapshot_truncated, frontier_sources)
    report["header"] = header
    text = header + "\n" + text
    if len(text) > max_chars:
        text = f"{integer_type(recovery.bits)} {name}(void) {{\n    /* Reconstruction text budget exhausted. */\n    return unresolved_result();\n}}"
        if len(header) + 1 + len(text) <= max_chars:
            text = header + "\n" + text
        truncated, report["complete"], report["source_semantics_complete"] = True, False, False
        report["external_functions"] = []
    warnings = ("部分源码重建：仍有依赖原始寄存器、栈或异常处理协议的机器状态片段；详见微码。",) if machine_regions else ()
    return PseudocodeResult(text, "fangida_native_pseudoc", truncated, warnings, tuple(semantic_records), reconstruction=report)


_GENERATED_NAMES = ("sub_", "function_", "entry_window_", "recovered_function", "region_", "entry_", "fde_")
_NAME_SOURCES = {"symtab": "符号表", "dynsym": "动态符号表", "symbol": "符号表", "symbols": "符号表",
                 "macho_symtab": "符号表", "macho-symbol": "符号表", "pe-export": "导出表", "export": "导出表",
                 "exports": "导出表", "pe-import": "导入表", "ghidra": "Ghidra", "eh_frame": "异常展开信息",
                 "linkage": "导入桩（链接信息）"}
_UNRESOLVED_TEXT = (("call_signature", "处调用参数个数未知"),
                    ("call_signature_assumed", "处调用参数个数为推断（被调路径含间接调用）"), ("condition", "处条件未恢复"),
                    ("operation", "条未识别指令"), ("control_flow_target", "个未解析跳转"),
                    ("system_transition", "处系统调用/异常"), ("incoming_value", "个寄存器入口值未知"),
                    ("incoming_stack_value", "个栈槽未初始化"), ("call_return_upper_bits", "处返回值高位未知"))
# 排在机器状态片段与 goto 标签之后的说明（头部最多列 4 条，不挤掉结构性的说明）：浮点运算与转换写成
# fp_environment 占位（结果依赖 FPCR/MXCSR 的舍入与异常，不可离线求值）；地址外泄的栈槽上的获取/释放访存
# 仍写成普通读写（见 ordering.py）。只因这些而不完整的函数据此写明原因，而不是“见 pseudoc_reconstruction”。
_TRAILING_UNRESOLVED_TEXT = (("fp_environment_operation", "处浮点运算依赖舍入/异常环境"),
                             ("memory_order", "处带内存序的栈槽访问写成普通读写"))


def _has_upper_wrapper(value):
    pending = [value]
    while pending:
        item = pending.pop()
        if item.op == "call" and item.name.startswith("unknown_return_upper"):
            return True
        pending.extend(item.args)
    return False


# 不返回证据的中文说明；未列出的证据种类原样显示。
_NORETURN_EVIDENCE = {"symbol_name": "已知不返回函数名", "declared_stub": "容器声明的导入桩",
                      "import_stub": "导入桩", "import_slot_call": "经导入槽调用",
                      "local_fixed_point": "所有路径终止于不返回调用"}


def _header_line(function, context, name, address, report, truncated, snapshot_truncated=None, frontier_sources=frozenset()):
    """伪 C 第一行的简短说明：地址、函数名及其来源、是否完整。"""
    raw = str(function.get("name", ""))
    source = context.get("name_source") or function.get("name_source")
    if isinstance(source, str) and source:
        origin = _NAME_SOURCES.get(source, source)
    elif not raw or raw.startswith(_GENERATED_NAMES) or name == "recovered_function":
        origin = "自动生成"
    elif str(function.get("source", "")) in _NAME_SOURCES:
        origin = _NAME_SOURCES[str(function["source"])]
    elif str(function.get("source", "")) in {"entry", "entry_window"}:
        origin = "入口点"
    else:
        origin = "分析结果"
    if raw and raw != name and origin in {"符号表", "动态符号表", "导出表"} and identifier(raw) != name:
        # 显示的是源码级名字（如 Mach-O 去掉前导下划线）：同时给出原始符号，便于对照其它工具。
        origin += f"（{raw[:64]}）"
    where = f"0x{address:x} " if isinstance(address, int) and address >= 0 else ""
    parts = [f"// {where}{name}", f"名字：{origin}"]
    if function.get("noreturn"):
        # 核心分析证明不返回（名单 / 导入桩 / 本地不动点），证据见 noreturn_evidence。
        evidence = function.get("noreturn_evidence")
        kind = evidence.get("evidence") if isinstance(evidence, dict) else None
        parts.append("不返回" + (f"（{_NORETURN_EVIDENCE.get(kind, kind)}）" if isinstance(kind, str) and kind else ""))
    unresolved = list(report.get("unresolved", ()))
    # 目标已知的尾跳转（已核实导入函数或已命名函数）：单独说明，不算“未解析跳转”。
    jumps = [item for item in unresolved if item.get("kind") == "control_flow_target"]
    named = [item for item in jumps if item.get("import_name") or item.get("target_name")]
    if named:
        unresolved = [item for item in unresolved if not (item.get("kind") == "control_flow_target" and
                                                          (item.get("import_name") or item.get("target_name")))]
        if (len(named) == len(jumps) and snapshot_truncated is not None and
                frontier_sources <= {item.get("address") for item in named}):
            # 所有 CFG 出口都是到已知目标的尾跳转：这不是快照缺失。
            truncated = snapshot_truncated
    imports = sorted({str(item["import_name"]) for item in named if item.get("import_name")})
    calls = sorted({str(item["target_name"]) for item in named if item.get("target_name") and not item.get("import_name")})
    tail_notes = []
    if imports:
        tail_notes.append("尾跳转到导入函数 " + "、".join(imports[:3]) + (" 等" if len(imports) > 3 else ""))
    if calls:
        tail_notes.append("尾调用 " + "、".join(calls[:3]) + (" 等" if len(calls) > 3 else ""))
    # 导入桩只是原样转交寄存器与栈：实参就是调用者给桩的实参，不算个数未知。
    unknown_tail_arguments = 0 if origin.startswith("导入桩") else sum(1 for item in named if not item.get("arguments_known"))
    if report.get("complete"):
        parts.append("完整")
    elif (named and not truncated and not unresolved and not report.get("machine_regions")
          and not report.get("residual_gotos") and not unknown_tail_arguments):
        slot = named[0].get("import_slot")
        where_slot = f"（槽位 0x{slot:x}）" if isinstance(slot, int) and len(named) == 1 else ""
        parts.append(("导入桩：" if origin.startswith("导入桩") else "") + "、".join(tail_notes) + where_slot)
    else:
        notes = []
        if truncated:
            notes.append("指令快照不完整")
        counts = {}
        for item in unresolved:
            counts[item.get("kind")] = counts.get(item.get("kind"), 0) + 1
        if unknown_tail_arguments:
            counts["call_signature"] = counts.get("call_signature", 0) + unknown_tail_arguments
        for kind, text in _UNRESOLVED_TEXT:
            if counts.get(kind):
                notes.append(f"{counts[kind]} {text}")
        if report.get("machine_regions"):
            notes.append(f"{len(report['machine_regions'])} 个机器状态片段")
        if report.get("residual_gotos"):
            notes.append(f"{report['residual_gotos']} 个 goto 标签")
        for kind, text in _TRAILING_UNRESOLVED_TEXT:
            if counts.get(kind):
                notes.append(f"{counts[kind]} {text}")
        parts.append("不完整：" + ("、".join(notes[:4]) if notes else "见 pseudoc_reconstruction"))
        parts.extend(tail_notes)
    return " | ".join(parts).replace("*/", "* /")


def _known_definition(function, context, abi):
    """当前函数名（来自符号）是已知定义（如 main）且没有声明原型时，补上该原型。"""
    if "prototype" in function or not abi.arguments:
        return function
    from .prototypes import definition, lookup
    summary = context.get("callees", {}).get(function.get("start"), {})
    known = definition(function.get("name")) or definition(summary.get("name"))
    variadic = False
    if known is None and context.get("name_source") == "linkage":
        # 已验证的导入桩：寄存器原样交给被导入的函数，签名就是该库函数的原型；
        # 可变参数原型只声明固定形参，签名末尾写 “...”（桩不读取也不改变可变参数）。
        known = lookup(function.get("name")) or lookup(summary.get("name"))
        variadic = known is not None and known.variadic
    if known is None or len(known.parameters) > len(abi.arguments):
        return function
    prototype = {"return_type": known.return_type, "source": "known_definition",
                 "parameters": [{"name": name, "type": ctype} for name, ctype in known.parameters]}
    if variadic:
        prototype["variadic"] = True
    return {**function, "prototype": prototype}


def recover_signature(function, architecture, *, context=None, max_instructions=512):
    from .cfg import view_scope
    with view_scope():
        return _recover_signature(function, architecture, context=context, max_instructions=max_instructions)


def _recover_signature(function, architecture, *, context=None, max_instructions=512):
    from ..microcode import lift_function
    from ..native import _memo_lift
    limit = min(max_instructions, _source_limit())
    # 流水线作用域内若已有输入完全相同的完整渲染，直接取其微码（与重新提升逐字段相同）；
    # 否则（包括作用域外的普通调用）仍走 lift_function，行为与错误不变。
    lifted = _memo_lift(function, architecture, limit)
    records = (lifted if lifted is not None else lift_function(function, architecture, max_instructions=limit))["instructions"]
    result = signature(function, records, architecture, context or function.get("pseudoc_context", {}))
    from .types import constraints, incoming_types
    bits = 64 if architecture in {"x86_64", "arm64"} else 32
    widths, types, _ = constraints(records, bits)
    from .abi import incoming_registers, initial_widths, never_returns, return_width
    abi = result.pop("abi")
    initial = initial_widths(records, function.get("start", 0), abi)
    input_types = incoming_types(records, function.get("start", 0), abi)
    for parameter in result["parameters"]:
        root = parameter.get("register")
        ctype = input_types.get(root, "")
        parameter.setdefault("type", ctype if "*" in ctype else integer_type(initial.get(root, widths.get(root, bits)), ctype == "signed"))
    logical_return = return_width(records, function.get("start", 0), abi)
    if not result["return_type"] and never_returns(function, records, function.get("start", 0)):
        result["return_type"] = "void"
    result["return_type"] = result["return_type"] or integer_type(logical_return, types.get(abi.return_register, "").startswith("int"))
    result["return_zero_extended"] = bits == 64 and logical_return == 32 and all(row.get("supported") for row in records)
    call_context = context or function.get("pseudoc_context", {})
    from .cfg import cfg_view
    graph = cfg_view(records)
    result["argument_uses_complete"] = bool(records) and not any(None in block.successors for block in graph.values()) and all(
        row.get("supported") and not any(op["opcode"] in {"opaque", "system_transition"} or
            op["opcode"] == "call" and not call_context.get("callees", {}).get(op.get("attributes", {}).get("target"), {}).get("signature_complete")
            for op in row["operations"]) for row in records)
    return {**result, "abi": abi.name, "abi_evidence": abi.confidence}


def pseudoc_prelude(source=None):
    """可读伪 C 的前导（辅助函数定义与占位声明）；source 为生成结果/报告/文本时另附其外部函数声明。

    详见 prelude.pseudoc_prelude；与 fangida.plugins.pseudoc.pseudoc_prelude 相同。
    """
    from .prelude import pseudoc_prelude as build
    return build(source)


__all__ = ["reconstruct_function", "recover_signature", "RECONSTRUCTION_VERSION", "pseudoc_prelude"]
