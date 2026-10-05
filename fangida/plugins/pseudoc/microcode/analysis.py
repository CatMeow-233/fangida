"""Bounded semantic facts within basic blocks, never assembly-level replay.

Joins, calls, unknown effects and memory reads invalidate facts. Missing
evidence remains unknown; this pass does not invent paths through flattening.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable

from .conditions import evaluate_condition
from .evaluate import (UnknownValue, declared_division_semantics, evaluate_expression, integer_flags, floating_flags,
                       logic_flags)
from .ir import Expression, constant
from .optimize import simplify_expression


@dataclass(frozen=True)
class KnownBits:
    width: int
    mask: int
    value: int


def _known(expression, state, division_semantics=None):
    """division_semantics：所在操作声明的通用除法语义（见 evaluate.DIVISION_SEMANTICS），不声明时为 None。"""
    expr = Expression.from_dict(expression) if isinstance(expression, dict) else expression
    if expr.domain != "bitvector":
        raise UnknownValue("Non-integer abstract value")
    if expr.opcode == "register":
        bits = state.get(expr.name)
        mask = (1 << expr.width) - 1
        if bits is None or bits.mask & mask != mask:
            raise UnknownValue(f"Unknown bits: {expr.name}")
        return bits.value & mask
    if expr.opcode == "extract" and expr.args[0].opcode == "register":
        bits = state.get(expr.args[0].name)
        shift, mask = int(expr.value or 0), (1 << expr.width) - 1
        if bits is None or (bits.mask >> shift) & mask != mask:
            raise UnknownValue("Unknown extracted bits")
        return (bits.value >> shift) & mask
    if not expr.args:
        return evaluate_expression(expr)
    # Replace only proven operands; optimize without treating memory as pure.
    args = []
    for arg in expr.args:
        try:
            args.append(constant(int(_known(arg, state, division_semantics)), arg.width))
        except UnknownValue:
            args.append(arg)
    reduced = simplify_expression(Expression(expr.opcode, expr.width, tuple(args), expr.value, expr.name, expr.domain))
    return evaluate_expression(reduced, division_semantics=division_semantics)


def _flag_view(state, flags):
    """把已证明的条件标志作为 flags.X 寄存器（值为 0/1）并入状态的只读副本。

    adc/sbc 的进位输入、mrs xN, nzcv 等表达式以 flags.C、flags.N… 寄存器读取标志；
    只有分析已证明的标志才会出现在视图里，未知标志仍是未知。
    """
    view = dict(state)
    for name, known in flags.items():
        if known is not None:
            view["flags." + name] = KnownBits(128, (1 << 128) - 1, int(bool(known)))
    return view


def _write(operation, value, state):
    output = operation.get("output")
    if not output:
        return
    attributes = operation.get("attributes", {})
    width = attributes.get("destination_width", operation.get("width", 0))
    storage = attributes.get("storage_width", width)
    shift = attributes.get("bit_offset", 0)
    if not width or not storage:
        state.pop(output, None)
        return
    mask = ((1 << width) - 1) << shift
    if attributes.get("zero_upper"):
        state[output] = KnownBits(storage, (1 << storage) - 1, value & ((1 << width) - 1))
    elif width == storage:
        state[output] = KnownBits(storage, mask, value & mask)
    else:
        old = state.get(output, KnownBits(storage, 0, 0))
        state[output] = KnownBits(storage, old.mask | mask, (old.value & ~mask) | ((value << shift) & mask))


def _forget_write(operation, state):
    output = operation.get("output")
    if not output:
        return
    attributes = operation.get("attributes", {})
    width = attributes.get("destination_width", operation.get("width", 0))
    storage = attributes.get("storage_width", width)
    shift = attributes.get("bit_offset", 0)
    if not width or not storage:
        state.pop(output, None)
        return
    mask = ((1 << width) - 1) << shift
    old = state.get(output, KnownBits(storage, 0, 0))
    known = old.mask & ~mask
    value = old.value & ~mask
    if attributes.get("zero_upper"):
        known |= ((1 << storage) - 1) ^ ((1 << width) - 1)
        value &= (1 << width) - 1
    if known:
        state[output] = KnownBits(storage, known, value)
    else:
        state.pop(output, None)


def analyze_microcode(records: Iterable[dict], *, max_steps: int = 8192) -> dict:
    if type(max_steps) is not int or not 1 <= max_steps <= 65536:
        raise ValueError("max_steps must be in [1, 65536]")
    rows = []
    truncated = False
    for row in records:
        if len(rows) >= max_steps:
            truncated = True
            break
        rows.append(row)
    targets = {operation.get("attributes", {}).get("target") for row in rows
               for operation in row.get("operations", []) if operation.get("opcode") in {"branch", "jump"}}
    state, flags, facts, unsupported, categories = {}, {}, [], [], {}
    previous_end = None
    previous_terminal = False
    for row in rows:
        address = row["addr"]
        if previous_terminal or address in targets or (previous_end is not None and address != previous_end):
            state, flags = {}, {}
        categories[row["category"]] = categories.get(row["category"], 0) + 1
        if not row.get("supported", False):
            unsupported.append(address)
        previous_terminal = False
        flags_handled = False
        handled_writes = set()
        for operation in row.get("operations", []):
            opcode, attributes = operation["opcode"], operation.get("attributes", {})
            # 本操作声明的通用除法语义（division_semantics）：作用于下面所有输入、条件表达式的求值。
            division = declared_division_semantics(attributes) or None
            if operation.get("output"):
                handled_writes.add(operation["output"])
            handled_writes.update(attributes.get("outputs", ()))
            if attributes.get("barrier") or opcode in {"call", "opaque"}:
                state, flags = {}, {}
                flags_handled = True
                continue
            if opcode == "assign" and "expression" in operation:
                try:
                    view = _flag_view(state, flags) if flags and "flags" in row.get("reads", ()) else state
                    resolved = _known(operation["expression"], view, division)
                    _write(operation, int(resolved), state)
                    facts.append({"addr": address, "kind": "constant_assignment", "output": operation["output"], "value": int(resolved), "width": operation["width"]})
                except UnknownValue:
                    _forget_write(operation, state)
                continue
            if opcode in {"set_condition", "select"} and operation.get("output"):
                predicate = evaluate_condition(attributes.get("condition", {}), flags=flags)
                try:
                    if predicate is None:
                        raise UnknownValue("Unproven conditional assignment")
                    if opcode == "set_condition":
                        resolved = attributes.get("true_value", 1) if predicate else 0
                    else:
                        resolved = int(_known(operation["inputs"][0 if predicate else 1], state, division))
                        if not predicate:
                            action = attributes.get("false_operation", "identity")
                            if action == "csinc":
                                resolved += 1
                            elif action == "csinv":
                                resolved = ~resolved
                            elif action == "csneg":
                                resolved = -resolved
                    resolved &= (1 << operation["width"]) - 1
                    _write(operation, resolved, state)
                    facts.append({"addr": address, "kind": "constant_assignment", "output": operation["output"],
                                  "value": resolved, "width": operation["width"], "conditional": True})
                except UnknownValue:
                    _forget_write(operation, state)
                continue
            if opcode == "compare":
                flags_handled = True
                try:
                    left, right = [_known(expr, state, division) for expr in operation["inputs"]]
                    flags = integer_flags(attributes["flag_family"], "sub", int(left), int(right), operation["width"])
                except UnknownValue:
                    flags = {}
                continue
            if opcode in {"flags_add", "flags_sub", "compare_add", "flags_logic", "test"}:
                flags_handled = True
                try:
                    inputs = [_known(expr, state, division) for expr in operation["inputs"]]
                    family = attributes.get("family", attributes.get("flag_family", "x86"))
                    if opcode in {"flags_logic", "test"}:
                        result = inputs[0] if opcode == "flags_logic" else int(inputs[0]) & int(inputs[1])
                        flags = logic_flags(family, int(result), operation["width"], previous=flags,
                                            arm32=row.get("architecture") == "arm")
                        if attributes.get("shifter_carry") == "unknown":
                            flags["C"] = None
                    elif attributes.get("carry"):
                        flags = {}
                    else:
                        flags = integer_flags(family, "sub" if opcode == "flags_sub" else "add",
                                              int(inputs[0]), int(inputs[1]), operation["width"])
                except UnknownValue:
                    flags = {}
                continue
            if opcode == "flags_nzcv":
                # msr nzcv, xN：按记录的位位置（N31 Z30 C29 V28）整体写四个标志；源值未知时标志未知。
                flags_handled = True
                positions = attributes.get("bit_positions")
                try:
                    if not isinstance(positions, dict) or not operation.get("inputs"):
                        raise UnknownValue("Malformed NZCV write")
                    source = int(_known(operation["inputs"][0], state, division))
                    flags = {name: bool((source >> int(bit)) & 1) for name, bit in positions.items()}
                except (UnknownValue, TypeError, ValueError):
                    flags = {}
                continue
            if opcode.startswith("flags_") or opcode == "compare_float":
                flags_handled = True
                # Specialized flag effects are conservatively unknown unless
                # this pass has a concrete evaluator for the exact operation.
                flags = {}
                continue
            if opcode == "branch":
                predicate = attributes.get("condition", {})
                taken = None
                if predicate.get("kind") in {"zero_test", "bit_test"}:
                    try:
                        source = int(_known(predicate["value"], state, division))
                        if predicate["kind"] == "bit_test":
                            source &= 1 << int(_known(predicate["bit"], state, division))
                        taken = source == 0 if predicate["relation"] == "eq" else source != 0
                    except UnknownValue:
                        pass
                else:
                    taken = evaluate_condition(predicate, flags=flags)
                facts.append({"addr": address, "kind": "branch", "taken": taken,
                              "target": attributes.get("target"), "fallthrough": attributes.get("fallthrough"),
                              "condition": predicate, "proof": "known_semantic_values" if taken is not None else "unknown"})
                previous_terminal = True
                continue
            if opcode in {"jump", "return", "trap"}:
                previous_terminal = True
            if operation.get("output") and opcode not in {"flag_write"}:
                state.pop(operation["output"], None)
            for output in attributes.get("outputs", []):
                state.pop(output, None)
            if opcode == "flag_write" and operation.get("output", "").startswith("flags."):
                flags_handled = True
                name = operation["output"].split(".", 1)[1]
                action = attributes.get("operation")
                if action in {"clc", "stc"}:
                    flags[name] = action == "stc"
                elif action == "cmc":
                    flags[name] = None if flags.get(name) is None else not flags[name]
        if row.get("flag_effect", "unknown") not in {"preserve", "partial_non_condition"} and not flags_handled:
            flags = {}
        # Some multi-result operations expose their writes at instruction
        # level. Never let their old register values survive a missing output.
        for output in row.get("writes", ()):
            if output not in handled_writes and output != "flags" and not output.startswith("flags."):
                state.pop(output, None)
        previous_end = address + row["size"]
    return {"facts": facts, "categories": categories, "unsupported_addresses": unsupported,
            "steps": len(rows), "truncated": truncated,
            "remaining_register_bits": {name: dict(width=bits.width, known_mask=bits.mask, value=bits.value)
                                        for name, bits in state.items()},
            "scope": "basic_block_facts", "memory_model": "unknown_effects", "microcode_version": "1.0"}
