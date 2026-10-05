"""ARM64 indirect-branch slicing over completed instruction snapshots.

This optional plugin consumes existing IR.  It never loads a container,
decodes bytes, creates xrefs, or substitutes a concrete zero for unknown input.
Paths retain their complete original rows for the separate Unicorn backend.
"""
from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import replace
from math import isfinite
from time import monotonic
from typing import Any

from ..pseudoc.microcode import (
    Expression, UnknownValue, constant, evaluate_condition, evaluate_expression,
    integer_flags, lift_instruction, simplify_expression,
)
from ..pseudoc.native_operands import split_operands

_REGISTERS = frozenset({*(f"x{i}" for i in range(31)), "sp"})
_RUNTIME = frozenset({"entry_register", "external_call", "system_register", "system_transition"})
_CONDITION_FLAGS = {"eq": "Z", "ne": "Z", "cs": "C", "hs": "C", "cc": "C", "lo": "C",
    "mi": "N", "pl": "N", "vs": "V", "vc": "V", "hi": "ZC", "ls": "ZC",
    "ge": "NV", "lt": "NV", "gt": "NZV", "le": "NZV"}
_EXPRESSION_NODES = 8192


class _SliceStopped(Exception):
    def __init__(self, reason, branch=None, rows=()):
        self.reason, self.branch, self.rows = reason, branch, rows


def _check_abort(deadline, cancel, *, branch=None, rows=()):
    if cancel is not None and bool(cancel() if callable(cancel) else cancel.is_set()):
        raise _SliceStopped("cancelled", branch, rows)
    if deadline is not None and monotonic() >= deadline:
        raise _SliceStopped("deadline", branch, rows)


def _expression_budget(expr):
    """Bound expanded output size without expanding a shared expression DAG."""
    memo, active = {}, set()

    def count(item, depth):
        if depth > 64:
            raise ValueError("Slice expression nesting exceeds limit")
        identity = id(item)
        if identity in memo:
            size, height = memo[identity]
            if depth + height > 64:
                raise ValueError("Slice expression nesting exceeds limit")
            return size, height
        if identity in active or len(memo) + len(active) >= _EXPRESSION_NODES:
            raise ValueError("Slice expression node budget exceeded")
        active.add(identity)
        size, height = 1, 0
        children = item.get("args", ()) if isinstance(item, dict) else item.args
        if not isinstance(children, (tuple, list)):
            raise ValueError("Invalid slice expression operands")
        for child in children:
            if not isinstance(child, (Expression, dict)):
                raise ValueError("Invalid slice expression operand")
            child_size, child_height = count(child, depth + 1)
            size += child_size
            height = max(height, child_height + 1)
            if size > _EXPRESSION_NODES:
                raise ValueError("Slice expression node budget exceeded")
        active.remove(identity)
        memo[identity] = size, height
        return size, height

    count(expr, 0)


def _predicate(code, at):
    if code in {"al", "nv"}:
        return constant(1, 1)
    selected = _CONDITION_FLAGS.get(code)
    if selected is None:
        return Expression("unknown", 1, name=f"unsupported_condition:{at}")
    flags = [flag for flag in ("N", "Z", "C", "V") if flag in selected]
    mask = sum(1 << ("N", "Z", "C", "V").index(flag) for flag in flags)
    return Expression("condition", 1, tuple(Expression("register", 1, name="flags." + flag) for flag in flags),
                      value=mask, name=code)


def _integer(token):
    try:
        return int(str(token).lstrip("#").strip(), 0)
    except (ValueError, TypeError):
        return None


def _root(token):
    token = str(token).lower().strip()
    token = {"fp": "x29", "lr": "x30", "wsp": "sp"}.get(token, token)
    if token.startswith("w") and token[1:].isdigit():
        token = "x" + token[1:]
    return token if token in _REGISTERS else None


def _branch(row):
    """Read saved control metadata, with a textual fallback for old snapshots."""
    info = dict(row.get("branch_info") or {})
    mnemonic = str(row.get("mnemonic", "")).lower()
    args = split_operands(row)
    if info.get("kind"):
        return info
    if mnemonic in {"br", "blr", "ret"}:
        return {"kind": {"br": "jump", "blr": "call", "ret": "return"}[mnemonic],
                "target": None, "conditional": False}
    if mnemonic in {"b", "bl"} or mnemonic.startswith("b.") or mnemonic in {"cbz", "cbnz", "tbz", "tbnz"}:
        return {"kind": "call" if mnemonic == "bl" else "jump",
                "target": _integer(args[-1]) if args else None,
                "conditional": mnemonic not in {"b", "bl"}}
    return info


def _address(text):
    """Convert the lifter's restricted arithmetic address text into typed IR."""
    node = ast.parse(str(text), mode="eval").body

    def visit(item):
        if isinstance(item, ast.Constant) and type(item.value) is int:
            return constant(item.value, 64)
        if isinstance(item, ast.Name) and _root(item.id):
            return Expression("register", 64, name=_root(item.id))
        if isinstance(item, ast.UnaryOp) and isinstance(item.op, (ast.USub, ast.UAdd)):
            value = visit(item.operand)
            return Expression("neg", 64, (value,)) if isinstance(item.op, ast.USub) else value
        if isinstance(item, ast.BinOp) and isinstance(item.op, (ast.Add, ast.Sub, ast.Mult)):
            opcode = {ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul"}[type(item.op)]
            return Expression(opcode, 64, (visit(item.left), visit(item.right)))
        raise ValueError("Unsupported address expression")

    return _reduce(visit(node))


def _reduce(expr, depth=0):
    _expression_budget(expr)
    return _reduce_node(expr, depth, {})


def _reduce_node(expr, depth, memo):
    identity = id(expr)
    if identity in memo:
        return memo[identity]
    result = _reduce_operation(expr, depth, memo)
    memo[identity] = result
    return result


def _reduce_operation(expr, depth, memo):
    if depth > 64:
        raise ValueError("Slice expression nesting exceeds limit")
    # A known select kills the unused arm rather than leaking its dependencies.
    if expr.opcode == "select" and len(expr.args) == 3:
        predicate = _reduce_node(expr.args[0], depth + 1, memo)
        if predicate.opcode == "constant":
            return _reduce_node(expr.args[1 if predicate.value else 2], depth + 1, memo)
        if expr.args[1] == expr.args[2] and expr.args[1].pure:
            return _reduce_node(expr.args[1], depth + 1, memo)
    args = tuple(_reduce_node(arg, depth + 1, memo) for arg in expr.args)
    if any(new is not old for new, old in zip(args, expr.args)):
        expr = replace(expr, args=args)
    if expr.opcode == "arm_flag" and all(arg.opcode == "constant" for arg in args):
        family, operation, width, flag = expr.name.split(":")
        result = integer_flags(family, operation, args[0].value, args[1].value, int(width))
        return constant(int(result[flag]), 1)
    if expr.opcode == "condition" and all(arg.opcode == "constant" for arg in args):
        keys = [flag for index, flag in enumerate(("N", "Z", "C", "V")) if int(expr.value or 15) & (1 << index)]
        flags = {key: bool(arg.value) for key, arg in zip(keys, args)}
        result = evaluate_condition({"family": "arm", "code": expr.name}, flags=flags)
        if result is not None:
            return constant(int(result), 1)
    if expr.opcode == "zero_test" and args[0].opcode == "constant":
        return constant(int((args[0].value == 0) == (expr.name == "eq")), 1)
    return simplify_expression(expr)


def simplify_slice_expression(expression):
    """Fold a slice after proven context or read-only memory substitution."""
    if isinstance(expression, dict):
        # A caller can also supply a shared dictionary DAG.  Check it before
        # Expression.from_dict would duplicate the children into an IR tree.
        _expression_budget(expression)
    expr = Expression.from_dict(expression) if isinstance(expression, dict) else expression
    if not isinstance(expr, Expression):
        raise TypeError("A slice Expression or serialized expression is required")
    return _reduce(expr)


def _normalize(expr, at):
    if expr.opcode == "address":
        try:
            return _address(expr.name)
        except (ValueError, SyntaxError, RecursionError):
            return Expression("unknown", expr.width, name=f"unsupported_address:{at}")
    args = tuple(_normalize(arg, at) for arg in expr.args)
    if expr.opcode == "load":
        address = args[0]
        # Byte-level loads preserve overlapping stores and partial writes.
        value = constant(0, expr.width)
        for index in range(expr.width // 8):
            location = _reduce(Expression("add", 64, (address, constant(index, 64))))
            byte = Expression("load", 8, (location,), name=f"memory:{at}")
            byte = Expression("zext", expr.width, (byte,)) if expr.width != 8 else byte
            if index:
                byte = Expression("shl", expr.width, (byte, constant(index * 8, expr.width)))
            value = Expression("or", expr.width, (value, byte))
        return value
    return replace(expr, args=args)


def _replace_register(expr, name, value, _memo=None):
    memo = {} if _memo is None else _memo
    identity = id(expr)
    if identity in memo:
        return memo[identity]
    if expr.opcode == "register" and expr.name == name:
        result = value if value.width == expr.width else Expression("truncate", expr.width, (value,))
    else:
        args = tuple(_replace_register(arg, name, value, memo) for arg in expr.args)
        result = expr if all(new is old for new, old in zip(args, expr.args)) else replace(expr, args=args)
    memo[identity] = result
    return result


def _leaves(expr, opcode):
    result, pending, visited = [], [expr], set()
    while pending:
        item = pending.pop()
        identity = id(item)
        if identity in visited:
            continue
        visited.add(identity)
        if len(visited) > _EXPRESSION_NODES:
            raise ValueError("Slice expression node budget exceeded")
        if item.opcode == opcode:
            result.append(item)
        pending.extend(item.args)
    return result


def _affine(expr):
    """A base plus constant is enough to prove stack/absolute byte aliasing."""
    if expr.opcode == "constant":
        return None, expr.value
    if expr.opcode in {"add", "sub"} and expr.args[1].opcode == "constant":
        base, offset = _affine(expr.args[0])
        return base, (offset + (expr.args[1].value if expr.opcode == "add" else -expr.args[1].value)) % (1 << 64)
    return expr, 0


def _store(expr, address, source, width, at):
    base, offset = _affine(address)
    memo = {}

    def visit(item):
        identity = id(item)
        if identity in memo:
            return memo[identity]
        result = update(item)
        memo[identity] = result
        return result

    def update(item):
        if item.opcode == "load":
            other_base, other_offset = _affine(item.args[0])
            if other_base == base:
                delta = (other_offset - offset) % (1 << 64)
                if delta < width // 8:
                    return Expression("extract", 8, (source,), value=delta * 8)
                return item
            # Distinct unresolved bases may alias; an older store cannot prove it.
            if base is not None or other_base is not None:
                return Expression("unknown", item.width, (item.args[0], address, source),
                                  name=f"memory_alias:{at}")
            return item
        return replace(item, args=tuple(visit(arg) for arg in item.args))

    return visit(expr)


def _write_value(operation, at):
    opcode, attributes = operation["opcode"], operation.get("attributes", {})
    width = operation.get("width", 64)
    if opcode == "assign":
        source = _normalize(Expression.from_dict(operation["expression"]), at)
    elif opcode in {"select", "set_condition"}:
        predicate = attributes.get("condition", {})
        code = predicate.get("code", "")
        source_condition = _predicate(code, at)
        if opcode == "set_condition":
            left, right = constant(attributes.get("true_value", 1), width), constant(0, width)
        else:
            left, right = [_normalize(Expression.from_dict(value), at) for value in operation["inputs"]]
            action = attributes.get("false_operation", "identity")
            if action == "csinc":
                right = Expression("add", width, (right, constant(1, width)))
            elif action in {"csinv", "csneg"}:
                right = Expression("not" if action == "csinv" else "neg", width, (right,))
        source = Expression("select", width, (source_condition, left, right))
    elif opcode == "address_writeback":
        source = _address(attributes["address"])
        if attributes.get("mode") == "post_index":
            offset = _integer(attributes.get("offset"))
            if offset is None:
                raise ValueError("Unknown memory writeback")
            source = Expression("add", 64, (source, constant(offset, 64)))
    else:
        raise ValueError("Unsupported target definition")
    storage = attributes.get("storage_width", 64)
    if source.width != storage:
        source = Expression("zext", storage, (source,)) if attributes.get("zero_upper") else Expression(
            "insert", storage, (Expression("register", storage, name=operation["output"]), source),
            value=attributes.get("bit_offset", 0))
    return _reduce(source)


def _condition_expression(terminal, at):
    predicate = terminal.get("attributes", {}).get("condition", {})
    if predicate.get("kind") in {"zero_test", "bit_test"}:
        value = Expression.from_dict(predicate["value"])
        if predicate["kind"] == "bit_test":
            bit = Expression.from_dict(predicate["bit"])
            mask = Expression("shl", value.width, (constant(1, value.width), bit))
            value = Expression("and", value.width, (value, mask))
        return Expression("zero_test", 1, (value,), name=predicate.get("relation", "eq"))
    return _predicate(predicate.get("code", ""), at)


def _analyze_path(rows, branch, boundary, edges, truncated, *, entry=None, cfg_frontiers=(), deadline=None, cancel=None):
    target = _root(split_operands(branch)[0])
    expressions = [Expression("register", 64, name=target)]
    controls, selected, records, dependency_details = [], set(), {}, {}
    expression_limited = False
    for row in rows:
        _check_abort(deadline, cancel, branch=branch, rows=rows)
        saved = dict(row)
        saved["branch_info"] = _branch(row)
        try:
            records[row["addr"]] = lift_instruction(saved, "arm64")
        except (ValueError, TypeError, KeyError, RecursionError):
            records[row["addr"]] = {"supported": False, "operations": [], "writes": []}
    for row in reversed(rows[:-1]):
        _check_abort(deadline, cancel, branch=branch, rows=rows)
        at, mnemonic, micro = row["addr"], str(row.get("mnemonic", "")).lower(), records[row["addr"]]
        operations = micro.get("operations", [])
        # Trace control is part of feasibility evidence, not branch solving.
        if at in edges:
            terminal = next((op for op in operations if op["opcode"] == "branch"), None)
            if terminal:
                controls.append({"at": at, **edges[at], "expression_index": len(expressions),
                                 "condition": terminal.get("attributes", {}).get("condition", {})})
                expressions.append(_condition_expression(terminal, at))
                selected.add(at)
        live = {leaf.name for expr in expressions for leaf in _leaves(expr, "register")}
        loads = any(_leaves(expr, "load") for expr in expressions)
        if not live and not loads:
            continue
        if mnemonic == "mrs":
            args = split_operands(row)
            destination = _root(args[0]) if len(args) == 2 else None
            if destination in live:
                token = f"system_register:{at}:{destination}"
                dependency_details[token] = {"kind": "system_register", "at": at, "register": destination,
                    "system_register": args[1], "reason": "value read from ARM64 system register"}
                value = Expression("unknown", 64, name=token)
                expressions = [_replace_register(expr, destination, value) for expr in expressions]
                selected.add(at)
            continue
        if not micro.get("supported", False) or any(op["opcode"] in {"opaque", "call", "system_transition"} for op in operations):
            opcode = next((op["opcode"] for op in operations if op["opcode"] in {"call", "system_transition"}), "opaque")
            kind = {"call": "external_call", "system_transition": "system_transition"}.get(opcode, "unsupported")
            for name in live:
                # BL sets LR to its return address independently of the callee.
                # The value after return is ABI dependent, so it remains unknown.
                token = f"{kind}:{at}:{name}"
                dependency_details[token] = {"kind": kind, "at": at, "register": name,
                                             "reason": "unknown effects of " + mnemonic}
                expressions = [_replace_register(expr, name, Expression("unknown", 64, name=token)) for expr in expressions]
            if loads:
                token = f"{kind}:{at}:memory"
                dependency_details[token] = {"kind": kind, "at": at, "reason": "unknown memory effects of " + mnemonic}
                def barrier(expr):
                    if expr.opcode == "load":
                        return Expression("unknown", expr.width, expr.args, name=token)
                    return replace(expr, args=tuple(barrier(arg) for arg in expr.args))
                expressions = [barrier(expr) for expr in expressions]
            selected.add(at)
            continue
        handled = set()
        for operation in reversed(operations):
            opcode, output = operation["opcode"], operation.get("output")
            # Outputs that are not live after this micro-operation still count
            # as handled: a later reverse substitution may introduce a read of
            # the old value (notably pair loads with SP writeback).
            if output:
                handled.add(output)
            if opcode in {"compare", "flags_add", "flags_sub", "compare_add"}:
                attributes = operation.get("attributes", {})
                if not attributes.get("carry") and len(operation.get("inputs", ())) == 2:
                    inputs = tuple(_normalize(Expression.from_dict(value), at) for value in operation["inputs"])
                    action = "sub" if opcode in {"compare", "flags_sub"} else "add"
                    for flag in ("N", "Z", "C", "V"):
                        name = "flags." + flag
                        if any(leaf.name == name for expr in expressions for leaf in _leaves(expr, "register")):
                            value = Expression("arm_flag", 1, inputs, name=f"arm:{action}:{operation['width']}:{flag}")
                            expressions = [_replace_register(expr, name, value) for expr in expressions]
                            selected.add(at)
                    handled.add("flags")
            if opcode == "store" and any(_leaves(expr, "load") for expr in expressions):
                address, source = [_normalize(Expression.from_dict(value), at) for value in operation["inputs"]]
                expressions = [_store(expr, address, source, operation["width"], at) for expr in expressions]
                selected.add(at)
            if output and any(leaf.name == output for expr in expressions for leaf in _leaves(expr, "register")):
                try:
                    value = _write_value(operation, at)
                except (ValueError, TypeError, KeyError, RecursionError):
                    token = f"unsupported:{at}:{output}"
                    dependency_details[token] = {"kind": "unsupported", "at": at, "register": output,
                                                 "reason": "unsupported semantic definition"}
                    value = Expression("unknown", 64, name=token)
                expressions = [_replace_register(expr, output, value) for expr in expressions]
                selected.add(at)
                handled.add(output)
        for name in micro.get("writes", ()):
            names = ("flags.N", "flags.Z", "flags.C", "flags.V") if name == "flags" else (name,)
            if name in handled:
                continue
            for register in names:
                if any(leaf.name == register for expr in expressions for leaf in _leaves(expr, "register")):
                    token = f"unsupported:{at}:{register}"
                    dependency_details[token] = {"kind": "unsupported", "at": at, "register": register,
                                                 "reason": "semantic write is not modeled by slicer"}
                    expressions = [_replace_register(expr, register, Expression("unknown", 64, name=token)) for expr in expressions]
                    selected.add(at)
        try:
            expressions = [_reduce(expr) for expr in expressions]
        except (ValueError, RecursionError):
            token = f"expression_budget:{at}"
            dependency_details[token] = {"kind": "expression_budget", "at": at, "reason": "expression depth or node count exceeds bounded representation"}
            expressions = [Expression("unknown", 64, name=token)]
            controls = []
            expression_limited = True
            break
    dependencies = []
    for index, expr in enumerate(expressions):
        _check_abort(deadline, cancel, branch=branch, rows=rows)
        role = "target" if index == 0 else "control"
        for leaf in _leaves(expr, "register"):
            kind = "entry_register" if boundary == "entry" else "missing_definition"
            dependencies.append({"kind": kind, "role": role, "at": rows[0]["addr"], "register": leaf.name,
                                 "reason": "function entry input" if kind == "entry_register" else "snapshot boundary without a defining instruction"})
        for leaf in _leaves(expr, "load"):
            address = _reduce(leaf.args[0])
            dependencies.append({"kind": "memory_read", "role": role, "at": int(leaf.name.split(":")[-1]),
                "width": leaf.width, "address": address.value if address.opcode == "constant" else None,
                "address_expression": address.to_dict(), "reason": "memory contents require mapping/provenance evidence"})
        for leaf in _leaves(expr, "unknown"):
            if leaf.name in dependency_details:
                dependencies.append({**dependency_details[leaf.name], "role": role})
            else:
                dependencies.append({"kind": "memory_alias" if leaf.name.startswith("memory_alias:") else "unsupported", "role": role,
                    "at": int(leaf.name.split(":")[-1]), "reason": "unproven memory alias" if leaf.name.startswith("memory_alias:") else "unsupported address form"})
    if boundary in {"loop", "instruction_budget"}:
        dependencies.append({"kind": boundary, "at": rows[0]["addr"], "reason": "backward CFG traversal was bounded"})
    missing_entry = boundary == "missing_definition" and entry is not None
    cfg_incomplete = missing_entry or bool(cfg_frontiers)
    if missing_entry:
        dependencies.append({"kind": "cfg_incomplete", "role": "control", "at": rows[0]["addr"],
                             "entry": entry, "reason": "predecessor path did not reach the declared function entry"})
    if cfg_frontiers:
        dependencies.append({"kind": "cfg_incomplete", "role": "control", "at": entry,
                             "frontiers": list(cfg_frontiers),
                             "reason": "entry-reachable control flow has missing or indirect upstream continuations"})
    if truncated:
        dependencies.append({"kind": "path_budget", "at": branch["addr"], "reason": "not all predecessor paths were enumerated"})
    dedup = {}
    for item in dependencies:
        key = (item["kind"], item.get("role"), item.get("at"), item.get("register"), item.get("address"), repr(item.get("address_expression")))
        dedup[key] = item
    conditions, feasible = [], True
    for item in reversed(controls):
        expr = expressions[item.pop("expression_index")]
        known = bool(expr.value) if expr.opcode == "constant" else None
        if known is not None and known != item["taken"]:
            feasible = False
        conditions.append({**item, "expression": expr.to_dict(), "proven": known})
    value = expressions[0]
    target_value = value.value if value.opcode == "constant" else None
    return {"instructions": list(rows), "slice_addresses": sorted(selected | {branch["addr"]}),
            "expression": value.to_dict(), "constant_target": target_value,
            "dependencies": list(dedup.values()), "conditions": conditions,
            "feasible": feasible, "complete": boundary not in {"loop", "instruction_budget"} and not truncated and not expression_limited and not cfg_incomplete,
            "boundary": boundary}


def _function_scope(functions, branch_address, *, deadline=None, cancel=None):
    for function in functions:
        _check_abort(deadline, cancel)
        if not isinstance(function, Mapping):
            continue
        addresses = set()
        direct = function.get("instructions", ())
        for row in direct if isinstance(direct, (list, tuple)) else ():
            _check_abort(deadline, cancel)
            if isinstance(row, Mapping):
                addresses.add(row.get("addr"))
        for block in function.get("blocks", ()):
            _check_abort(deadline, cancel)
            if isinstance(block, Mapping):
                for row in block.get("instructions", ()):
                    _check_abort(deadline, cancel)
                    if isinstance(row, Mapping):
                        addresses.add(row.get("addr"))
        if branch_address in addresses:
            return addresses, function.get("start")
        start, size = function.get("start"), function.get("size")
        if type(start) is int and type(size) is int and size > 0 and start <= branch_address < start + size:
            return (start, start + size), start
    return None, None


def slice_branch(instructions, branch_address, architecture, *, functions=(), max_instructions=512, max_paths=32,
                 deadline=None, cancel=None):
    """Return conservative definitions and all bounded CFG predecessor paths.

    Only ARM64 BR/BLR is supported.  Unknown values stay symbolic.  A runtime
    status needs an identified runtime source; unsupported or missing evidence
    produces unknown.  Constants on unproven paths remain possible per-path
    candidates rather than one arbitrarily selected concrete destination.
    """
    if architecture not in {"arm64", "aarch64"}:
        raise ValueError("BR solver currently supports only ARM64 BR/BLR")
    if type(branch_address) is not int or not 0 <= branch_address < 1 << 64 or branch_address % 4:
        raise ValueError("Invalid branch address")
    if type(max_instructions) is not int or not 1 <= max_instructions <= 32768:
        raise ValueError("max_instructions must be in [1, 32768]")
    if type(max_paths) is not int or not 1 <= max_paths <= 256:
        raise ValueError("max_paths must be in [1, 256]")
    if deadline is not None and (type(deadline) not in {int, float} or not isfinite(deadline)):
        raise ValueError("deadline must be a finite monotonic absolute time")
    if cancel is not None and not callable(cancel) and not callable(getattr(cancel, "is_set", None)):
        raise TypeError("cancel must be callable or expose is_set()")
    try:
        return _slice_branch(instructions, branch_address, functions=functions, max_instructions=max_instructions,
                             max_paths=max_paths, deadline=deadline, cancel=cancel)
    except _SliceStopped as stopped:
        branch = stopped.branch
        args = split_operands(branch) if branch else []
        dependency = {"kind": stopped.reason, "role": "target", "at": branch_address,
                      "reason": "slice cancelled" if stopped.reason == "cancelled" else "slice deadline expired"}
        return {"architecture": "arm64", "branch_address": branch_address,
                "branch_mnemonic": str(branch["mnemonic"]).lower() if branch else "",
                "target_register": _root(args[0]) if args else None,
                "status": "unknown", "truncated": True, "stop_reason": stopped.reason,
                "paths": [{"instructions": list(stopped.rows), "slice_addresses": [],
                           "expression": Expression("unknown", 64, name=f"{stopped.reason}:{branch_address}").to_dict(),
                           "constant_target": None, "dependencies": [dependency], "conditions": [],
                           "feasible": True, "complete": False, "boundary": stopped.reason}]}


def _slice_branch(instructions, branch_address, *, functions, max_instructions, max_paths, deadline, cancel):
    _check_abort(deadline, cancel)
    scope, entry = _function_scope(functions, branch_address, deadline=deadline, cancel=cancel)
    if type(entry) is not int or not 0 <= entry < 1 << 64 or entry % 4:
        entry = None
    rows = {}
    for row in instructions:
        _check_abort(deadline, cancel, branch=rows.get(branch_address))
        if not isinstance(row, Mapping) or type(row.get("addr")) is not int or type(row.get("size")) is not int or row["size"] != 4:
            continue
        address = row["addr"]
        if not 0 <= address < 1 << 64 or address % 4:
            continue
        if isinstance(scope, set) and address not in scope or isinstance(scope, tuple) and not scope[0] <= address < scope[1]:
            continue
        if address in rows:
            raise ValueError("Ambiguous duplicate instruction address")
        rows[address] = row
    branch = rows.get(branch_address)
    args = split_operands(branch) if branch else []
    if not branch or str(branch.get("mnemonic", "")).lower() not in {"br", "blr"} or len(args) != 1 or _root(args[0]) is None or not str(args[0]).lower().strip().startswith(("x", "lr", "fp")):
        raise ValueError("Requested address is not an ARM64 BR/BLR register instruction")
    predecessors = {}
    successors, row_frontiers = {}, {}
    for address in rows:
        _check_abort(deadline, cancel, branch=branch)
        predecessors[address] = []
    for address, row in rows.items():
        _check_abort(deadline, cancel, branch=branch)
        info = _branch(row)
        kind, target = info.get("kind"), info.get("target")
        following = address + 4
        edges = [(following, None)] if kind not in {"jump", "return", "trap"} else []
        if kind == "jump":
            edges = [(target, True if info.get("conditional") else None)]
            if info.get("conditional"):
                edges.append((following, False))
        for destination, taken in edges:
            if destination in predecessors:
                predecessors[destination].append((address, taken))
                successors.setdefault(address, []).append(destination)
            elif address != branch_address:
                row_frontiers.setdefault(address, []).append({"at": address, "target": destination,
                    "kind": "indirect_control" if destination is None else "missing_instruction",
                    "taken": taken})
    cfg_frontiers = []
    if entry in rows:
        reachable, forward = set(), [entry]
        while forward:
            _check_abort(deadline, cancel, branch=branch)
            address = forward.pop()
            if address in reachable:
                continue
            reachable.add(address)
            cfg_frontiers.extend(row_frontiers.get(address, ()))
            forward.extend(successors.get(address, ()))
        if branch_address in reachable:
            # A decoded but unreachable block may lexically fall into a live
            # block.  It is not another function-entry execution path.  Keep
            # frontier evidence separately so gaps/unknown transfers cannot be
            # silently removed by this reachability filter.
            for address in reachable:
                _check_abort(deadline, cancel, branch=branch)
                predecessors[address] = [parent for parent in predecessors[address] if parent[0] in reachable]
    pending = [(branch_address, (branch_address,), {}, frozenset({branch_address}))]
    collected, truncated = [], False
    while pending:
        _check_abort(deadline, cancel, branch=branch)
        address, reverse_path, conditions, visited = pending.pop()
        parents = predecessors[address]
        if address == entry:
            collected.append((reverse_path, conditions, "entry"))
            if not parents:
                continue
            if len(reverse_path) >= max_instructions:
                if len(collected) + len(pending) < max_paths:
                    collected.append((reverse_path, conditions, "instruction_budget"))
                else:
                    truncated = True
                continue
        elif not parents or len(reverse_path) >= max_instructions:
            boundary = "instruction_budget" if parents else "missing_definition"
            collected.append((reverse_path, conditions, boundary))
            continue
        for parent, taken in reversed(parents):
            _check_abort(deadline, cancel, branch=branch)
            next_conditions = dict(conditions)
            if taken is not None:
                info = _branch(rows[parent])
                next_conditions[parent] = {"taken": taken, "target": info.get("target"), "fallthrough": parent + 4}
            if parent in visited:
                if len(collected) + len(pending) < max_paths:
                    collected.append((reverse_path, next_conditions, "loop"))
                else:
                    truncated = True
            elif len(collected) + len(pending) < max_paths:
                pending.append((parent, reverse_path + (parent,), next_conditions, visited | {parent}))
            else:
                truncated = True
    paths = [_analyze_path([rows[address] for address in reversed(path)], branch, boundary, conditions, truncated,
                          entry=entry, cfg_frontiers=cfg_frontiers, deadline=deadline, cancel=cancel)
             for path, conditions, boundary in collected]
    _check_abort(deadline, cancel, branch=branch)
    feasible_paths = [path for path in paths if path["feasible"]]
    kinds = {item["kind"] for path in feasible_paths for item in path["dependencies"]}
    candidates = {path["constant_target"] for path in feasible_paths if path["constant_target"] is not None}
    if feasible_paths and not kinds and len(candidates) == 1 and all(path["complete"] for path in feasible_paths):
        status = "static"
    elif feasible_paths and kinds and kinds <= _RUNTIME and not truncated:
        status = "runtime"
    else:
        status = "unknown"
    return {"architecture": "arm64", "branch_address": branch_address,
            "branch_mnemonic": str(branch["mnemonic"]).lower(), "target_register": _root(args[0]),
            "status": status, "paths": paths, "truncated": truncated or any(not path["complete"] for path in paths)}


__all__ = ["slice_branch", "simplify_slice_expression"]
