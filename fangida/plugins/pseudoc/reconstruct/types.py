"""Recover scalar widths, signed constraints and pointer access types."""
from __future__ import annotations

import ast
import re
from functools import lru_cache


@lru_cache(maxsize=8192)
def _parsed_base(text):
    """(是否解析成功, ast.walk 顺序中的第一个名字或 None)；纯函数，有界缓存，结果不可变。"""
    try:
        tree = ast.parse(text, mode="eval")
    except (SyntaxError, ValueError):
        return False, None
    return True, next((node.id for node in ast.walk(tree) if isinstance(node, ast.Name)), None)


def _address_base(text):
    # 非精确 str（含不可哈希值）走原始解析路径，保持原有的异常类型与语义。
    if type(text) is str:
        return _parsed_base(text)
    tree = ast.parse(text, mode="eval")
    return True, next((node.id for node in ast.walk(tree) if isinstance(node, ast.Name)), None)


def integer_type(width, signed=False):
    if width == 128:
        return "__int128_t" if signed else "__uint128_t"
    return ("int" if signed else "uint") + str(width if width in {8, 16, 32, 64} else 64) + "_t"


def valid_type(text, fallback="uint64_t"):
    # Only declarator-free scalar/pointer names are accepted from evidence.
    return text if isinstance(text, str) and re.fullmatch(r"(?:const\s+)?(?:void|char|wchar_t|short|int|long|float|double|bool|u?int(?:8|16|32|64)_t|size_t|uintptr_t)(?:\s*\*){0,3}", text) else fallback


# 写回目的寄存器的浮点微码运算（与 lower 的浮点渲染分支一致）。
_FLOATING_OUTPUTS = frozenset({"fadd", "fsub", "fmul", "fdiv", "integer_to_float", "float_to_integer", "float_resize"})


def constraints(records, bits):
    widths, signedness, pointers = {}, {}, {}
    def visit(expr, requested=None):
        opcode, width = expr.get("opcode"), requested or expr.get("width", bits)
        if opcode == "register" and not expr.get("name", "").startswith("flags."):
            root = expr["name"]
            widths[root] = max(widths.get(root, 0), width)
        if opcode == "load":
            address = expr.get("args", [{}])[0]
            mark_pointer(address, expr.get("width", bits))
        for arg in expr.get("args", ()):
            visit(arg, width if opcode in {"extract", "truncate"} else None)
    def mark_pointer(address, width):
        if address.get("opcode") in {"add", "sub"} and address.get("args"):
            mark_pointer(address["args"][0], width)
            return
        if address.get("opcode") == "register":
            base = address.get("name")
            pointers.setdefault(base, set()).add(width)
            widths[base] = bits
            return
        try:
            # The leftmost register in an address is the base; scaled index
            # registers must not all become pointers.
            parsed, base = _address_base(address.get("name", ""))
            if parsed and base is not None:
                pointers.setdefault(base, set()).add(width)
                widths[base] = bits
        except (SyntaxError, ValueError):
            pass
    comparisons = {}
    for row in records:
        for operation in row["operations"]:
            opcode = operation["opcode"]
            attributes = operation.get("attributes", {})
            if opcode == "return":
                continue  # ABI register size is not the recovered return type.
            if opcode == "compare":
                comparisons[row["addr"]] = operation
            for expr in operation.get("inputs", ()):
                visit(expr)
            if opcode == "store" and operation.get("inputs"):
                mark_pointer(operation["inputs"][0], operation["width"])
            # AArch64 浮点运算与转换（含向量 vec_f*、fcsel 的浮点 select）写目的寄存器的全部位（写入宽度之外清零，
            # zero_upper）：在可读 C 中同样整体写回（见 lower 的浮点分支），目的宽度按写入宽度计，否则只读低/高
            # 64 位的 128 位向量结果会被定成 64 位变量，丢掉高半。x86 传统 SSE 标量运算保留高位，不在此计入。
            floating_output = (opcode in _FLOATING_OUTPUTS or opcode.startswith("vec_f")
                               or opcode == "select" and attributes.get("domain") == "floating") and (
                attributes.get("zero_upper") or attributes.get("destination_width", operation["width"])
                >= attributes.get("storage_width", 0))
            if (opcode == "assign" or floating_output) and operation.get("output"):
                width = attributes.get("destination_width", operation["width"])
                if width < attributes.get("storage_width", width) and not attributes.get("zero_upper"):
                    width = attributes["storage_width"]
                widths[operation["output"]] = max(widths.get(operation["output"], 0), width)
            predicate = attributes.get("condition", {})
            domain = predicate.get("domain")
            comparison = comparisons.get(predicate.get("origin"))
            if comparison and domain in {"signed", "unsigned"}:
                from .abi import expression_registers
                for expr in comparison["inputs"]:
                    for root in expression_registers(expr):
                        signedness.setdefault(root, set()).add(domain)
    types = {root: integer_type(width, signedness.get(root) == {"signed"}) for root, width in widths.items()}
    by_output = None
    for root, accessed in pointers.items():
        if by_output is None:
            by_output = _operations_by_output(records)
        # 只检查 output 与 root 相等的操作（顺序不变）；其余操作在原表达式里同样短路为 False。
        candidates = by_output.get(root, ()) if by_output is not False and (root is None or type(root) is str) else (
            op for row in records for op in row["operations"])
        reused_as_scalar = any(op.get("output") == root and op.get("attributes", {}).get("destination_width", op.get("width", bits)) < bits
            for op in candidates)
        if not reused_as_scalar:
            types[root] = (integer_type(next(iter(accessed))) if len(accessed) == 1 else "uint8_t") + " *"
    pairs = None
    for _ in range(min(len(widths), 16)):
        changed = False
        # 第一轮边解析边处理（与原顺序、异常行为一致）并记录 (source, destination)；
        # 之后各轮直接复用：记录只依赖只读的表达式结构，不依赖 types/widths。
        if pairs is None:
            pairs = []
            sequence = _register_copies(records, pairs)
        else:
            sequence = pairs
        for source, destination in sequence:
            if source in types and destination in widths and source != destination:
                if "*" in types[source] and widths[destination] == bits or widths.get(source) == widths[destination] and signedness.get(source) == {"signed"} and destination not in signedness:
                    if types.get(destination) != types[source]:
                        types[destination], changed = types[source], True
        if not changed:
            break
    return widths, types, pointers


def _operations_by_output(records):
    """按 output 分组的操作（保持原顺序）；出现非 str/None 的 output 时返回 False（回退到逐个比较）。"""
    index = {}
    for row in records:
        for operation in row["operations"]:
            output = operation.get("output")
            if output is not None and type(output) is not str:
                return False
            index.setdefault(output, []).append(operation)
    return index


def _register_copies(records, pairs):
    """逐个产出源为寄存器的 assign 的 (source, destination)，同时追加到 pairs。"""
    for row in records:
        for operation in row["operations"]:
            if operation["opcode"] != "assign":
                continue
            expression = operation.get("expression", {})
            while expression.get("opcode") in {"extract", "truncate", "zext"} and not expression.get("value", 0):
                expression = expression["args"][0]
            source, destination = expression.get("name"), operation.get("output")
            if expression.get("opcode") == "register":
                pairs.append((source, destination))
                yield source, destination


def incoming_types(records, entry, abi):
    """Infer types for entry values, without merging later register versions.

    A call result reusing x0 must not turn the saved incoming x0 into a pointer.
    Copy origins survive only unanimous CFG joins and full-width copies.
    """
    from .cfg import cfg_view, reachable, predecessors
    blocks = reachable(cfg_view(records), entry)
    parents = predecessors(blocks)
    bits = abi.word * 8
    after, pointers, signedness, comparisons = {}, {}, {}, {}

    def source_origin(expression, origins):
        while expression.get("opcode") in {"extract", "truncate", "zext", "sext"} and not expression.get("value", 0):
            expression = expression.get("args", [{}])[0]
        return origins.get(expression.get("name")) if expression.get("opcode") == "register" else None

    def address_origin(expression, origins):
        if expression.get("opcode") in {"add", "sub"} and expression.get("args"):
            return address_origin(expression["args"][0], origins)
        if expression.get("opcode") == "register":
            return origins.get(expression.get("name"))
        if expression.get("opcode") != "address":
            return None
        try:
            parsed, root = _address_base(expression.get("name", ""))
            return origins.get(root) if parsed else None
        except (SyntaxError, ValueError):
            return None

    collect = False
    origins = {}

    def visit(expression):
        if collect and expression.get("opcode") == "load":
            origin = address_origin(expression.get("args", [{}])[0], origins)
            if origin:
                pointers.setdefault(origin, set()).add(expression["width"])
        for child in expression.get("args", ()):
            visit(child)

    # 非收集轮次里 visit 只做遍历（没有副作用，只可能抛异常）：第一轮完整遍历一次即可，
    # 之后的非收集轮次输入表达式不变，不会再抛异常，可以跳过。
    # 非收集轮次里块的出口只取决于入口 origins 的内容：入口相同则复用上一轮的出口。
    first = True
    transfers = {}
    for _ in range(len(blocks) + 2):
        changed = False
        for address, block in blocks.items():
            if address == entry:
                origins = {root: root for root in abi.arguments}
            else:
                if not parents[address] or any(parent not in after for parent in parents[address]):
                    origins = {}
                else:
                    states = [after[parent] for parent in parents[address]]
                    origins = {root: origin for root, origin in states[0].items()
                               if all(state.get(root) == origin for state in states[1:])}
            if not collect:
                previous = transfers.get(address)
                if previous is not None and previous[0] == origins:
                    origins = previous[1]
                    if after.get(address) != origins:
                        after[address], changed = origins, True
                    continue
                incoming = dict(origins)
            for row in block.records:
                for operation in row["operations"]:
                    opcode, attrs = operation["opcode"], operation.get("attributes", {})
                    if collect or first:
                        for expression in operation.get("inputs", ()):
                            visit(expression)
                    if collect and opcode == "store":
                        origin = address_origin(operation["inputs"][0], origins)
                        if origin:
                            pointers.setdefault(origin, set()).add(operation["width"])
                    if collect and opcode == "compare":
                        comparisons[row["addr"]] = tuple(source_origin(expr, origins) for expr in operation["inputs"])
                    predicate = attrs.get("condition", {})
                    if collect and predicate.get("domain") in {"signed", "unsigned"}:
                        for origin in comparisons.get(predicate.get("origin"), ()):
                            if origin:
                                signedness.setdefault(origin, set()).add(predicate["domain"])
                    output = operation.get("output")
                    if opcode == "assign" and output:
                        origin = source_origin(operation.get("expression", {}), origins)
                        width = attrs.get("destination_width", operation.get("width", bits))
                        if origin and (width == attrs.get("storage_width", width) or attrs.get("zero_upper")):
                            origins[output] = origin
                        else:
                            origins.pop(output, None)
                    elif opcode == "call":
                        for root in abi.volatile or tuple(origins):
                            origins.pop(root, None)
                        origins.pop(output, None)
                    elif opcode in {"opaque", "system_transition"}:
                        origins.clear()
                    elif output:
                        origins.pop(output, None)
            if not collect:
                transfers[address] = (incoming, origins)
            if after.get(address) != origins:
                after[address], changed = origins, True
        first = False
        if collect:
            break
        if not changed:
            collect = True
    result = {root: "signed" for root, domains in signedness.items() if domains == {"signed"}}
    for root, widths in pointers.items():
        result[root] = (integer_type(next(iter(widths))) if len(widths) == 1 else "uint8_t") + " *"
    return result
