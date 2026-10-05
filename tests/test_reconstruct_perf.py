"""重建层（reconstruct）性能优化的等价性回归。

这些用例只新增、不改动既有测试。对每一项优化，用优化前的原始实现（下方 ref_* 函数，
逐字取自优化前版本，仅改为绝对导入并加 ref 前缀）在真实微码夹具与合成函数上做逐项对照：
结果（含字典键顺序）必须完全相同；异常输入的异常类型也必须相同；输入快照不得被修改。
"""
from __future__ import annotations

import ast
import copy
import json
import random
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fangida.plugins.pseudoc import generate_pseudoc
import fangida.plugins.pseudoc.reconstruct as reconstruct_package
from fangida.plugins.pseudoc.reconstruct import abi as abi_module
from fangida.plugins.pseudoc.reconstruct import cfg as cfg_module
from fangida.plugins.pseudoc.reconstruct import dataflow
from fangida.plugins.pseudoc.reconstruct import specialize as specialize_module
from fangida.plugins.pseudoc.reconstruct import stack
from fangida.plugins.pseudoc.reconstruct import types as types_module
from fangida.plugins.pseudoc.reconstruct.abi import instruction_definitions, select_abi
from fangida.plugins.pseudoc.reconstruct.cfg import predecessors, reachable
from fangida.plugins.pseudoc.reconstruct.model import Block, Statement, Value
from fangida.plugins.pseudoc.reconstruct.types import integer_type
from tests.test_pseudoc import function as fn, instruction as ins

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# 优化前的参考实现（行为基准）。
# ---------------------------------------------------------------------------

def ref_build_cfg(records):
    rows = {row["addr"]: row for row in records}
    leaders = {records[0]["addr"]} if records else set()
    for index, row in enumerate(records):
        terminal = next((op for op in row["operations"] if op["opcode"] in {"branch", "jump", "return", "trap"}), None)
        if terminal:
            attributes = terminal.get("attributes", {})
            leaders.update(target for target in (attributes.get("target"), attributes.get("fallthrough")) if target in rows)
        if index + 1 < len(records) and (terminal or row["addr"] + row["size"] != records[index + 1]["addr"]):
            leaders.add(records[index + 1]["addr"])
    blocks, current = {}, None
    for row in records:
        if row["addr"] in leaders:
            current = Block(row["addr"])
            blocks[current.address] = current
        current.records.append(row)
    instruction_blocks = {row["addr"]: block.address for block in blocks.values() for row in block.records}
    for block in blocks.values():
        last = block.records[-1]
        terminal = next((op for op in last["operations"] if op["opcode"] in {"branch", "jump", "return", "trap"}), None)
        if terminal:
            block.terminal = terminal["opcode"]
            attributes = terminal.get("attributes", {})
            targets = ((attributes.get("target"), attributes.get("fallthrough")) if block.terminal == "branch" else
                       (attributes.get("target"),) if block.terminal == "jump" else ())
        else:
            targets = (last["addr"] + last["size"],)
        block.successors = tuple(instruction_blocks.get(target) for target in targets)
        frontiers = []
        for index, target in enumerate(targets):
            if target in instruction_blocks:
                frontiers.append(None)
                continue
            attributes = terminal.get("attributes", {}) if terminal else {}
            fallthrough = not terminal or block.terminal == "branch" and index == 1 or attributes.get("frontier_kind") == "fallthrough"
            target = attributes.get("external_fallthrough" if block.terminal == "branch" and index == 1 else "external_target", target)
            descriptor = {"address": last.get("original_address", last["addr"]), "target": target,
                          "kind": "fallthrough" if fallthrough else "direct_jump" if isinstance(target, int) else "indirect_jump"}
            if not fallthrough and attributes.get("target_expression"):
                descriptor["target_expression"] = attributes["target_expression"]
            frontiers.append(descriptor)
        block.frontiers = tuple(frontiers)
    return blocks


def ref_expression_registers(expression):
    result = {expression["name"]} if expression.get("opcode") in {"register", "float_register"} else set()
    if expression.get("opcode") == "address":
        try:
            tree = ast.parse(expression.get("name", ""), mode="eval")
            result.update(node.id for node in ast.walk(tree) if isinstance(node, ast.Name))
        except (SyntaxError, ValueError):
            pass
    for arg in expression.get("args", ()):
        result.update(ref_expression_registers(arg))
    return result


def ref_incoming_registers(records, entry, abi=None):
    blocks = reachable(ref_build_cfg(records), entry)
    parents = predecessors(blocks)
    machine_roots = {root for row in records for root in (*row.get("reads", ()), *row.get("writes", ()))}
    universe = set().union(*(instruction_definitions(row, abi, machine_roots) for row in records)) if records else set()
    before = {address: set() if address == entry else set(universe) for address in blocks}
    after = {address: set() if address == entry else set(universe) for address in blocks}
    for _ in range(len(blocks) + 1):
        changed = False
        for address, block in blocks.items():
            inputs = set.intersection(*(after[parent] for parent in parents[address])) if parents[address] and address != entry else set()
            outputs = inputs | set().union(*(instruction_definitions(row, abi, machine_roots) for row in block.records))
            if inputs != before[address] or outputs != after[address]:
                before[address], after[address], changed = inputs, outputs, True
        if not changed:
            break
    incoming = set()
    for address, block in blocks.items():
        defined = set(before[address])
        for row in block.records:
            reads = set()
            for operation in row["operations"]:
                for expression in operation.get("inputs", ()):
                    reads.update(ref_expression_registers(expression))
                attributes = operation.get("attributes", {})
                if operation["opcode"] == "assign" and attributes.get("destination_width", 0) < attributes.get("storage_width", 0) and not attributes.get("zero_upper"):
                    reads.add(operation["output"])
            incoming.update(reads - defined)
            defined.update(instruction_definitions(row, abi, machine_roots))
    return incoming


def ref_constraints(records, bits):
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
            tree = ast.parse(address.get("name", ""), mode="eval")
            # The leftmost register in an address is the base; scaled index
            # registers must not all become pointers.
            names = [node.id for node in ast.walk(tree) if isinstance(node, ast.Name)]
            base = names[0] if names else None
            if base is not None:
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
            if opcode == "assign" and operation.get("output"):
                width = attributes.get("destination_width", operation["width"])
                if width < attributes.get("storage_width", width) and not attributes.get("zero_upper"):
                    width = attributes["storage_width"]
                widths[operation["output"]] = max(widths.get(operation["output"], 0), width)
            predicate = attributes.get("condition", {})
            domain = predicate.get("domain")
            comparison = comparisons.get(predicate.get("origin"))
            if comparison and domain in {"signed", "unsigned"}:
                pass
                for expr in comparison["inputs"]:
                    for root in ref_expression_registers(expr):
                        signedness.setdefault(root, set()).add(domain)
    types = {root: integer_type(width, signedness.get(root) == {"signed"}) for root, width in widths.items()}
    for root, accessed in pointers.items():
        reused_as_scalar = any(op.get("output") == root and op.get("attributes", {}).get("destination_width", op.get("width", bits)) < bits
            for row in records for op in row["operations"])
        if not reused_as_scalar:
            types[root] = (integer_type(next(iter(accessed))) if len(accessed) == 1 else "uint8_t") + " *"
    for _ in range(min(len(widths), 16)):
        changed = False
        for row in records:
            for operation in row["operations"]:
                if operation["opcode"] != "assign":
                    continue
                expression = operation.get("expression", {})
                while expression.get("opcode") in {"extract", "truncate", "zext"} and not expression.get("value", 0):
                    expression = expression["args"][0]
                source, destination = expression.get("name"), operation.get("output")
                if expression.get("opcode") == "register" and source in types and destination in widths and source != destination:
                    if "*" in types[source] and widths[destination] == bits or widths.get(source) == widths[destination] and signedness.get(source) == {"signed"} and destination not in signedness:
                        if types.get(destination) != types[source]:
                            types[destination], changed = types[source], True
        if not changed:
            break
    return widths, types, pointers


def ref_incoming_types(records, entry, abi):
    """Infer types for entry values, without merging later register versions.

    A call result reusing x0 must not turn the saved incoming x0 into a pointer.
    Copy origins survive only unanimous CFG joins and full-width copies.
    """
    from fangida.plugins.pseudoc.reconstruct.cfg import reachable, predecessors
    blocks = reachable(ref_build_cfg(records), entry)
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
            tree = ast.parse(expression.get("name", ""), mode="eval")
            root = next((node.id for node in ast.walk(tree) if isinstance(node, ast.Name)), None)
            return origins.get(root)
        except (SyntaxError, ValueError):
            return None

    collect = False
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
            for row in block.records:
                for operation in row["operations"]:
                    opcode, attrs = operation["opcode"], operation.get("attributes", {})

                    def visit(expression):
                        if collect and expression.get("opcode") == "load":
                            origin = address_origin(expression.get("args", [{}])[0], origins)
                            if origin:
                                pointers.setdefault(origin, set()).add(expression["width"])
                        for child in expression.get("args", ()):
                            visit(child)

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
            if after.get(address) != origins:
                after[address], changed = origins, True
        if collect:
            break
        if not changed:
            collect = True
    result = {root: "signed" for root, domains in signedness.items() if domains == {"signed"}}
    for root, widths in pointers.items():
        result[root] = (integer_type(next(iter(widths))) if len(widths) == 1 else "uint8_t") + " *"
    return result


def ref_substitute(value, copies):
    if value is None:
        return None
    if value.op == "variable" and value.name in copies:
        return copies[value.name]
    args = tuple(ref_substitute(arg, copies) for arg in value.args)
    if len(args) == 2 and args[0] == args[1] and args[0].pure:
        if value.op in {"and", "or"}:
            return args[0]
        if value.op in {"sub", "xor"}:
            from fangida.plugins.pseudoc.reconstruct.model import Value
            return Value("constant", value.width, number=0, ctype=value.ctype)
    if value.op == "cast" and args and args[0].op == "constant" and type(args[0].number) is int and "*" not in value.ctype:
        from fangida.plugins.pseudoc.reconstruct.model import Value
        number = args[0].number & ((1 << value.width) - 1)
        if value.ctype.startswith("int") and number & (1 << (value.width - 1)):
            number -= 1 << value.width
        return Value("constant", value.width, number=number, ctype=value.ctype)
    if value.op == "cast" and args and args[0].ctype == value.ctype:
        return args[0]
    if value.op == "cast" and args and args[0].op == "cast" and args[0].width >= value.width and args[0].args[0].width == value.width and args[0].args[0].ctype == value.ctype:
        return args[0].args[0]
    if value.op == "load" and args and args[0].op == "add" and value.width in {8, 16, 32, 64}:
        from fangida.plugins.pseudoc.reconstruct.model import Value
        from fangida.plugins.pseudoc.reconstruct.types import integer_type
        base, offset = args[0].args
        if base.op == "cast" and base.width == base.args[0].width and "*" in base.args[0].ctype:
            base = base.args[0]
        size = value.width // 8
        index = offset if size == 1 else None
        if offset.op == "shl" and offset.args[1].op == "constant" and 1 << offset.args[1].number == size:
            index = offset.args[0]
        if index is not None and base.ctype == integer_type(value.width) + " *":
            # A64 SXTW was cast into the unsigned address domain before its
            # shift. Recover its signed index when expressing array elements.
            if index.op == "cast" and index.args[0].ctype.startswith("int") and index.width == index.args[0].width:
                index = index.args[0]
            return Value("index", value.width, (base, index), ctype=value.ctype, effect=value.effect)
    return replace(value, args=args)


def ref_copy_candidate(value):
    if value is None or not value.pure or value.op in {"slot_access", "index", "load", "global"}:
        return False
    return all(ref_copy_candidate(child) for child in value.args)


def ref_copy_states(blocks):
    """Must-copy facts at block entry; disagreement or cycles stay unknown."""
    from fangida.plugins.pseudoc.reconstruct.cfg import predecessors
    parents = predecessors(blocks)
    after, before = {}, {}
    for _ in range(len(blocks) + 1):
        changed = False
        for address, block in blocks.items():
            states = [after[parent] for parent in parents[address] if parent in after]
            copies = {name: value for name, value in states[0].items()
                      if all(state.get(name) == value for state in states[1:])} if states and len(states) == len(parents[address]) else {}
            before[address] = dict(copies)
            for statement in block.statements:
                value = ref_substitute(statement.value, copies)
                destination = statement.destination
                if destination:
                    copies = {name: expr for name, expr in copies.items() if name != destination and destination not in expr.variables()}
                    if ref_copy_candidate(value) and destination not in value.variables() and ref_size(value) <= 32:
                        copies[destination] = value
                if statement.kind == "opaque":
                    copies = {}
            if after.get(address) != copies:
                after[address], changed = copies, True
        if not changed:
            return before
    return {}  # A bounded pass cannot prove an unstable loop's copy facts.


def ref_optimize(blocks):
    incoming_copies = ref_copy_states(blocks)
    for block in blocks.values():
        copies = dict(incoming_copies.get(block.address, {}))
        for statement in block.statements:
            statement.value = ref_substitute(statement.value, copies)
            destination = statement.destination
            if destination:
                copies = {name: value for name, value in copies.items() if name != destination and destination not in value.variables()}
                value = statement.value
                if ref_copy_candidate(value) and destination not in value.variables() and ref_size(value) <= 32:
                    copies[destination] = value
            if statement.kind == "opaque":
                copies = {}  # Loads/calls are never copy candidates; explicit
                # writes invalidate dependencies while immutable values survive.
        block.predicate = ref_substitute(block.predicate, copies)
    before = {address: set() for address in blocks}
    after = {address: set() for address in blocks}
    for _ in range(len(blocks) + 1):
        changed = False
        for address, block in reversed(list(blocks.items())):
            live = set().union(*(before[target] for target in block.successors if target in blocks))
            after[address] = set(live)
            if block.predicate:
                live.update(block.predicate.variables())
            for statement in reversed(block.statements):
                if statement.kind == "assign" and statement.destination not in live and statement.value.pure:
                    continue
                if statement.destination:
                    live.discard(statement.destination)
                live.update(statement.uses())
            if live != before[address]:
                before[address], changed = live, True
        if not changed:
            break
    # Repeat because removing a dead copy can make its own inputs dead.
    for _ in range(4):
        removed = False
        for address, block in blocks.items():
            live = set(after[address])
            if block.predicate:
                live.update(block.predicate.variables())
            kept = []
            for statement in reversed(block.statements):
                if statement.kind == "assign" and statement.destination not in live:
                    if statement.value.pure:
                        removed = True
                        continue
                    statement = replace(statement, kind="expression", destination="")
                if statement.destination:
                    live.discard(statement.destination)
                live.update(statement.uses())
                kept.append(statement)
            block.statements = list(reversed(kept))
        if not removed:
            break
    return before


def ref_size(value):
    pending, count = [value], 0
    while pending:
        current = pending.pop()
        count += 1
        if count > 32:
            return count
        pending.extend(current.args)
    return count


# ---------------------------------------------------------------------------
# 语料：真实 arm64 夹具 + 覆盖比较/分支/循环/调用/栈访问/条件选择的合成函数。
# ---------------------------------------------------------------------------

def _x86(*rows, name="sample"):
    return fn(*rows, name=name, pseudoc_context={"kind": "elf"})


def _synthetic_functions():
    yield "x86_64", _x86(ins(0, "cmp", "edi", "esi"), ins(1, "jmp", "0x3", kind="jump", target=3),
        ins(3, "mov", "edi", "7"), ins(4, "jl", "0x8", kind="jump", target=8, conditional=True),
        ins(5, "mov", "eax", "1"), ins(6, "ret", kind="return"), ins(8, "mov", "eax", "2"), ins(9, "ret", kind="return"), name="cross")
    yield "x86_64", _x86(ins(0, "push", "rbp"), ins(1, "mov", "rbp", "rsp"), ins(2, "sub", "rsp", "0x20"),
        ins(3, "mov", "dword ptr [rbp - 0x4]", "edi"), ins(4, "mov", "dword ptr [rbp - 0x8]", "0"),
        ins(5, "mov", "eax", "dword ptr [rbp - 0x8]"), ins(6, "cmp", "eax", "dword ptr [rbp - 0x4]"),
        ins(7, "jge", "0xb", kind="jump", target=11, conditional=True), ins(8, "add", "dword ptr [rbp - 0x8]", "1"),
        ins(9, "lea", "rcx", "[rbp - 0x10]"), ins(10, "jmp", "0x5", kind="jump", target=5),
        ins(11, "mov", "eax", "dword ptr [rbp - 0x8]"), ins(12, "leave"), ins(13, "ret", kind="return"), name="loop")
    yield "x86_64", _x86(ins(0, "xor", "eax", "eax"), ins(1, "test", "eax", "eax"),
        ins(2, "jne", "0x4", kind="jump", target=4, conditional=True), ins(3, "ret", kind="return"),
        ins(4, "mov", "eax", "dword ptr [rdi + rsi*4 + 8]"), ins(5, "ret", kind="return"), name="opaque")
    yield "x86_64", _x86(ins(0, "mov", "eax", "dword ptr [rdi]"), ins(1, "cmp", "eax", "0"),
        ins(2, "je", "0x5", kind="jump", target=5, conditional=True), ins(3, "call", "0x20", kind="call", target=32),
        ins(4, "ret", kind="return"), ins(5, "cmovl", "eax", "esi"), ins(6, "ret", kind="return"), name="calls")
    yield "x86_64", _x86(ins(0, "mov", "eax", "1"), ins(1, "cmp", "eax", "1"),
        ins(2, "je", "0x5", kind="jump", target=5, conditional=True), ins(3, "mov", "eax", "3"),
        ins(4, "ret", kind="return"), ins(5, "mov", "qword ptr [rsp - 0x8]", "rdi"), ins(6, "mov", "rax", "qword ptr [rsp - 0x8]"),
        ins(7, "ret", kind="return"), name="proven")
    yield "arm64", fn(ins(0, "mov", "w0", "#0", size=4),
        ins(4, "cbz", "w0", "0x99", size=4, kind="jump", target=153, conditional=True),
        ins(8, "mov", "w0", "#7", size=4), ins(12, "ret", size=4, kind="return"), name="external", pseudoc_context={"kind": "elf"})
    yield "arm64", fn(ins(0, "stp", "x29", "x30", "[sp, #-16]!", size=4), ins(4, "mov", "x29", "sp", size=4),
        ins(8, "ldr", "w8", "[x0, #4]", size=4), ins(12, "cmp", "w8", "#3", size=4),
        ins(16, "b.lt", "0x1c", size=4, kind="jump", target=28, conditional=True), ins(20, "add", "w0", "w8", "w1", size=4),
        ins(24, "b", "0x20", size=4, kind="jump", target=32), ins(28, "mov", "w0", "#0", size=4),
        ins(32, "ldp", "x29", "x30", "[sp], #16", size=4), ins(36, "ret", size=4, kind="return"), name="frame", pseudoc_context={"kind": "elf"})


def _corpus():
    """[(名字, 体系结构, 函数快照, 微码)]，微码来自机器风格的伪 C 生成（只读快照）。"""
    items = []
    for path in sorted(FIXTURES.glob("tersafe_*.json")):
        function = json.loads(path.read_text())
        items.append((path.stem, "arm64", function))
    for architecture, function in _synthetic_functions():
        items.append((function["name"], architecture, function))
    result = []
    for name, architecture, function in items:
        output = generate_pseudoc(function, architecture)
        result.append((name, architecture, function, list(output.microcode)))
    return result


CORPUS = None


def corpus():
    global CORPUS
    if CORPUS is None:
        CORPUS = _corpus()
    return CORPUS


def _abi(architecture):
    return select_abi(architecture, {"kind": "elf"})


def _block_shape(blocks):
    return [(address, [row["addr"] for row in block.records], block.successors, block.terminal, block.frontiers)
            for address, block in blocks.items()]


def _random_value(rng, depth=0):
    names = ("a", "b", "c", "d")
    if depth > 3 or rng.random() < 0.3:
        kind = rng.random()
        if kind < 0.45:
            return Value("variable", rng.choice((32, 64)), name=rng.choice(names), ctype=rng.choice(("uint64_t", "uint32_t", "uint64_t *")))
        if kind < 0.8:
            return Value("constant", rng.choice((8, 32, 64)), number=rng.choice((0, 1, 7, 0xffffffff, -1)), ctype=rng.choice(("uint64_t", "int32_t", "uint32_t")))
        return Value(rng.choice(("slot_access", "global")), 64, name=rng.choice(names), number=0)
    op = rng.choice(("add", "sub", "and", "or", "xor", "cast", "load", "shl", "call", "mul"))
    width = rng.choice((32, 64))
    if op == "cast":
        return Value("cast", width, (_random_value(rng, depth + 1),), ctype=rng.choice(("uint64_t", "uint32_t", "int32_t", "uint32_t *")))
    if op == "load":
        base = Value("variable", 64, name=rng.choice(names), ctype=rng.choice(("uint32_t *", "uint64_t *", "uint8_t *")))
        offset = Value("shl", 64, (_random_value(rng, depth + 1), Value("constant", 64, number=rng.choice((0, 2, 3)))))
        return Value("load", rng.choice((8, 32, 64)), (Value("add", 64, (base, offset)),), ctype="uint32_t", effect=True)
    if op == "call":
        return Value("call", width, (_random_value(rng, depth + 1),), name="f", effect=rng.random() < 0.5)
    left = _random_value(rng, depth + 1)
    right = left if rng.random() < 0.2 else _random_value(rng, depth + 1)
    return Value(op, width, (left, right), ctype=rng.choice(("uint64_t", "uint32_t")))


class ValueCacheTests(unittest.TestCase):
    def test_variables_and_uses_still_return_fresh_mutable_sets(self):
        value = Value("add", 64, (Value("variable", name="a"), Value("global", name="g"), Value("slot_access", name="s")))
        first = value.variables()
        first.add("mutated")
        self.assertEqual(value.variables(), {"a", "g", "s"})
        self.assertIsInstance(value.variables(), set)
        self.assertEqual(value.variable_names, frozenset({"a", "g", "s"}))
        statement = Statement("assign", value, "x")
        uses = statement.uses()
        uses.clear()
        self.assertEqual(statement.uses(), {"a", "g", "s"})
        self.assertEqual(Statement("expression").uses(), set())

    def test_cached_attributes_do_not_change_dataclass_semantics(self):
        rng = random.Random(7)
        for _ in range(200):
            value = _random_value(rng)
            twin = replace(value)
            self.assertEqual(hash(value), hash(twin))
            _ = value.pure, value.variable_names, dataflow.substitute(value, {}), dataflow._size(value), dataflow._copy_candidate(value)
            self.assertEqual(value, twin)
            self.assertEqual(hash(value), hash(twin))
            self.assertEqual(repr(value), repr(twin))
            self.assertEqual(value.pure, not value.effect and all(arg.pure for arg in value.args))


class DataflowEquivalenceTests(unittest.TestCase):
    def test_substitute_matches_reference_with_and_without_copies(self):
        rng = random.Random(11)
        for _ in range(600):
            value = _random_value(rng)
            copies = {name: _random_value(rng, 3) for name in rng.sample(("a", "b", "c", "d"), rng.randint(0, 3))}
            expected = ref_substitute(value, copies)
            self.assertEqual(dataflow.substitute(value, copies), expected)
            self.assertEqual(dataflow.substitute(value, copies), expected)  # 第二次命中缓存
            self.assertEqual(dataflow.substitute(value, {}), ref_substitute(value, {}))
            self.assertEqual(dataflow._size(value), ref_size(value))
            self.assertEqual(dataflow._copy_candidate(value), ref_copy_candidate(value))

    def test_copy_fact_maintenance_matches_dictionary_rebuild(self):
        rng = random.Random(5)
        for _ in range(300):
            names = ("a", "b", "c", "d", "e")
            copies = {name: _random_value(rng, 3) for name in rng.sample(names, 3) if True}
            copies = {name: value for name, value in copies.items() if name not in value.variable_names}
            reference = dict(copies)
            current = dict(copies)
            dependents = dataflow._dependents(current)
            for _ in range(12):
                destination = rng.choice(names)
                reference = {name: expr for name, expr in reference.items() if name != destination and destination not in expr.variables()}
                dataflow._kill(current, dependents, destination)
                value = _random_value(rng, 3)
                if destination not in value.variable_names and rng.random() < 0.7:
                    reference[destination] = value
                    dataflow._insert(current, dependents, destination, value)
                self.assertEqual(list(current.items()), list(reference.items()))

    def test_optimize_matches_reference_on_reconstructed_blocks(self):
        captured = []
        real = reconstruct_package.optimize

        def capture(blocks):
            captured.append(copy.deepcopy(blocks))
            return real(blocks)

        with patch.object(reconstruct_package, "optimize", capture):
            for name, architecture, function, _ in corpus():
                generate_pseudoc(function, architecture, style="readable")
        self.assertGreaterEqual(len(captured), 5)
        for blocks in captured:
            expected_blocks, actual_blocks = copy.deepcopy(blocks), copy.deepcopy(blocks)
            expected = ref_optimize(expected_blocks)
            actual = dataflow.optimize(actual_blocks)
            self.assertEqual(list(actual.items()), list(expected.items()))
            for address in expected_blocks:
                self.assertEqual(actual_blocks[address].statements, expected_blocks[address].statements)
                self.assertEqual(actual_blocks[address].predicate, expected_blocks[address].predicate)


class SpecializeDryRunTests(unittest.TestCase):
    @staticmethod
    def original(records, entry, abi, **limits):
        """原始算法：逐行 deepcopy + _rewrite 的完整构建路径（未作任何改动）。"""
        blocks = reachable(cfg_module.build_cfg(records), entry)
        if not blocks:
            return records, entry, {"applied": False}
        return specialize_module._explore(records, entry, abi, blocks, limits.get("max_rows", 512),
                                          limits.get("max_states", 128), build=True)

    @staticmethod
    def outcome(call):
        try:
            return "ok", repr(call())
        except Exception as exc:  # 异常类型必须一致
            return "error", type(exc).__name__

    def test_dry_run_matches_original_algorithm_and_keeps_input(self):
        applied = 0
        for name, architecture, function, records in corpus():
            abi = _abi(architecture)
            entry = function["start"]
            for limits in ({}, {"max_states": 1}, {"max_states": 4}, {"max_rows": 40}):
                before = copy.deepcopy(records)
                expected = self.outcome(lambda: self.original(copy.deepcopy(records), entry, abi, **limits))
                actual = self.outcome(lambda: specialize_module.specialize(records, entry, abi, **limits))
                self.assertEqual(actual, expected, (name, limits))
                self.assertEqual(records, before)
                applied += "'applied': True" in actual[1]
        self.assertGreater(applied, 0)

    def test_unproven_specialization_does_not_clone_rows(self):
        name, architecture, function, records = next(item for item in corpus() if item[0] == "cross")
        with patch.object(specialize_module, "deepcopy", side_effect=AssertionError("dry run must not clone")):
            _, _, report = specialize_module.specialize(records, function["start"], _abi(architecture))
        self.assertFalse(report["applied"])

    def test_non_plain_or_malformed_rows_fall_back_to_original_algorithm(self):
        rng = random.Random(3)
        cases = 0
        for name, architecture, function, records in corpus():
            if len(records) > 80:
                continue
            abi = _abi(architecture)
            for _ in range(25):
                mutated = copy.deepcopy(records)
                row = rng.choice(mutated)
                operations = row["operations"]
                choice = rng.random()
                if choice < 0.3 and operations:
                    operations.append(operations[0])  # 操作字典别名：必须回退
                elif choice < 0.5:
                    row["attributes_note"] = frozenset({1, 2})  # 非朴素叶子：必须回退
                elif choice < 0.75 and operations:
                    operations[0]["inputs"] = [{"opcode": "load", "width": 64}]  # 缺少参数：异常类型必须一致
                elif operations:
                    operations[-1]["inputs"] = [{"opcode": "select", "width": 8, "args": [{"opcode": "constant", "width": 8, "value": 1}]}]
                expected = self.outcome(lambda: self.original(copy.deepcopy(mutated), function["start"], abi))
                actual = self.outcome(lambda: specialize_module.specialize(mutated, function["start"], abi))
                self.assertEqual(actual, expected, name)
                cases += 1
        self.assertGreater(cases, 50)

    def test_prefix_sums_match_original_formula(self):
        rng = random.Random(9)
        for _ in range(50):
            records = [{"addr": index * 3, "size": rng.randint(1, 15)} for index in range(rng.randint(0, 40))]
            cursor = rng.randint(0, 1 << 20)
            expected = {row["addr"]: cursor + sum(r["size"] for r in records[:index]) for index, row in enumerate(records)}
            self.assertEqual(specialize_module._cumulative_addresses(records, cursor), expected)


class AnalysisEquivalenceTests(unittest.TestCase):
    def test_cfg_registers_constraints_and_incoming_types_match_reference(self):
        for name, architecture, function, records in corpus():
            abi = _abi(architecture)
            entry = function["start"]
            bits = 64 if architecture in {"x86_64", "arm64"} else 32
            self.assertEqual(_block_shape(cfg_module.build_cfg(records)), _block_shape(ref_build_cfg(records)), name)
            self.assertEqual(abi_module.incoming_registers(records, entry, abi), ref_incoming_registers(records, entry, abi), name)
            for expression in (expr for row in records for op in row["operations"] for expr in op.get("inputs", ())):
                self.assertEqual(abi_module.expression_registers(expression), ref_expression_registers(expression))
            actual, expected = types_module.constraints(records, bits), ref_constraints(records, bits)
            self.assertEqual([list(part.items()) for part in actual], [list(part.items()) for part in expected], name)
            actual, expected = types_module.incoming_types(records, entry, abi), ref_incoming_types(records, entry, abi)
            self.assertEqual(list(actual.items()), list(expected.items()), name)

    def test_signature_reuse_matches_separate_computation(self):
        for name, architecture, function, records in corpus():
            profile, incoming = abi_module._signature_and_incoming(function, records, architecture, {"kind": "elf"})
            self.assertEqual(profile, abi_module.signature(function, records, architecture, {"kind": "elf"}))
            self.assertEqual(incoming, abi_module.incoming_registers(records, function["start"], profile["abi"]))

    def test_non_string_address_names_keep_original_behavior(self):
        address = {"opcode": "address", "width": 64, "name": b"rax + rbx * 4"}
        self.assertEqual(abi_module.expression_registers(address), ref_expression_registers(address))
        for bad in ({"opcode": "address", "width": 64, "name": 5},):
            for current, reference in ((abi_module.expression_registers, ref_expression_registers),):
                with self.assertRaises(TypeError):
                    reference(bad)
                with self.assertRaises(TypeError):
                    current(bad)
        rows = [{"addr": 0, "size": 1, "operations": [{"opcode": "store", "width": 32,
                 "inputs": [{"opcode": "address", "width": 64, "name": 5}, {"opcode": "constant", "width": 32, "value": 0}]}]}]
        for current, reference in ((lambda: types_module.constraints(rows, 64), lambda: ref_constraints(rows, 64)),):
            self.assertEqual(SpecializeDryRunTests.outcome(current), SpecializeDryRunTests.outcome(reference))

    def test_shared_address_trees_are_isolated_from_public_parser(self):
        fresh = stack.parse_address("rbp - 0x10")
        self.assertIsNot(fresh, stack.parse_address("rbp - 0x10"))
        fresh.left.id = "mutated"
        self.assertEqual(ast.dump(stack._address_tree("rbp - 0x10")), ast.dump(stack.parse_address("rbp - 0x10")))
        self.assertIsNone(stack._address_tree("rbp(1)"))
        for cache in (stack._parse_address_cached, abi_module._address_names, types_module._parsed_base):
            self.assertIsNotNone(cache.cache_info().maxsize)


if __name__ == "__main__":
    unittest.main()
