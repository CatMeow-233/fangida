"""显式调用的 ARM64 BR/BLR 求解插件；不挂入任何默认分析流程。"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from time import monotonic

from .memory import MemoryEvidenceError, MemoryImage, PluginStopped, check_budget, unsigned

_RUNTIME = frozenset({"entry_register", "external_call", "system_register", "system_transition",
                      "writable_memory", "runtime_relocation", "runtime_memory", "uninitialized_register"})
_BOUNDS = frozenset({"loop", "instruction_budget", "path_budget", "expression_budget"})


def _registers(values):
    if values is None:
        return {}
    if not isinstance(values, Mapping):
        raise ValueError("registers 必须是寄存器到数值的映射")
    result = {}
    for name, value in values.items():
        if not isinstance(name, str) or not unsigned(value):
            raise ValueError("寄存器值必须是无符号 64 位整数")
        token = name.lower()
        width = 32 if token.startswith("w") else 64
        token = {"fp": "x29", "lr": "x30", "wsp": "sp", "flags": "nzcv"}.get(token, token)
        if token.startswith("w") and token[1:].isdigit():
            token = "x" + token[1:]
        if token not in {*('x' + str(index) for index in range(31)), "sp", "nzcv"}:
            raise ValueError("仅接受 ARM64 X/W、SP 和 NZCV 寄存器")
        value &= (1 << width) - 1
        if token in result and result[token] != value:
            raise ValueError("寄存器别名的值冲突")
        result[token] = value
    return result


def _rows(snapshot, branch_address, function_address=None, *, deadline=None, cancel=None):
    metadata = snapshot.get("metadata", {})
    indexed = {}
    functions = []
    for function in snapshot.get("functions", ()):
        check_budget(deadline, cancel)
        if not isinstance(function, Mapping):
            continue
        own = list(function.get("disassembly", ())) + list(function.get("instructions", ()))
        for block in function.get("blocks", ()):
            if isinstance(block, Mapping):
                own.extend(block.get("instructions", ()))
        addresses = set()
        for position, row in enumerate(own):
            if position % 256 == 0:
                check_budget(deadline, cancel)
            if isinstance(row, Mapping):
                addresses.add(row.get("addr"))
        start, size = function.get("start"), function.get("size")
        if branch_address in addresses or (unsigned(start) and type(size) is int and size > 0
                                           and start <= branch_address < start + size):
            if function_address is None or start == function_address:
                functions.append(function)
    if len({function.get("start") for function in functions}) > 1:
        raise ValueError("该 BR/BLR 属于多个函数，请指定 function_address")
    if function_address is not None and not functions:
        raise ValueError("指定函数不含该 BR/BLR")
    # 已有函数块就是独立作用域；一次求解不再整理整份程序的大表。
    selected_records = []
    for function in functions:
        selected_records.extend((function.get("disassembly", ()), function.get("instructions", ())))
        selected_records.extend(block.get("instructions", ()) for block in function.get("blocks", ()) if isinstance(block, Mapping))
    owns_instruction = any(any(isinstance(row, Mapping) and row.get("addr") == branch_address for row in records)
                           for records in selected_records)
    missing_entry = bool(functions and unsigned(functions[0].get("start")) and not any(
        any(isinstance(row, Mapping) and row.get("addr") == functions[0]["start"] for row in records)
        for records in selected_records))
    collections = (selected_records if owns_instruction and not missing_entry else
                   [metadata.get("disassembly", ()), metadata.get("full_disassembly", ()), *selected_records])
    for records in collections:
        for position, row in enumerate(records):
            if position % 256 == 0:
                check_budget(deadline, cancel)
            if not isinstance(row, Mapping) or not unsigned(row.get("addr")):
                continue
            if missing_entry:
                start, size = functions[0]["start"], functions[0].get("size")
                end = start + size if type(size) is int and size > 0 else max(start, branch_address) + 4
                if not start <= row["addr"] < end:
                    continue
            if row.get("source") or (row.get("arch_meta") or {}).get("container_member"):
                raise ValueError("BR solver 只接受主原生映像的指令快照")
            old = indexed.get(row["addr"])
            if old is not None and (old.get("mnemonic"), tuple(old.get("operands", ()))) != (row.get("mnemonic"), tuple(row.get("operands", ()))):
                raise ValueError("已完成快照在同一地址包含冲突指令")
            indexed[row["addr"]] = row
    check_budget(deadline, cancel)
    rows = [indexed[address] for address in sorted(indexed)]
    if missing_entry:
        functions = [{**functions[0], "instructions": rows}]
    return rows, functions[:1]


def _dedup(items):
    unique = {}
    for item in items:
        key = repr(sorted(item.items()))
        unique[key] = item
    return list(unique.values())


def _resolve(record, registers, memory, diagnostics, used_context, *, role="target"):
    check_budget(memory.deadline, memory.cancel)
    from ..pseudoc.microcode import Expression, constant
    from .slicing import simplify_slice_expression
    expression = Expression.from_dict(record) if isinstance(record, Mapping) else record
    if expression.opcode == "register":
        if expression.name in registers:
            used_context.add(expression.name)
            return constant(registers[expression.name], expression.width)
        if expression.name.startswith("flags.") and "nzcv" in registers:
            position = {"N": 31, "Z": 30, "C": 29, "V": 28}.get(expression.name[6:])
            if position is not None:
                used_context.add("nzcv")
                return constant((registers["nzcv"] >> position) & 1, 1)
        return expression
    if expression.opcode == "select" and len(expression.args) == 3:
        predicate = _resolve(expression.args[0], registers, memory, diagnostics, used_context, role=role)
        if predicate.opcode == "constant":
            return _resolve(expression.args[1 if predicate.value else 2], registers, memory,
                            diagnostics, used_context, role=role)
    children = tuple(_resolve(child, registers, memory, diagnostics, used_context, role=role)
                     for child in expression.args)
    expression = replace(expression, args=children)
    if expression.opcode == "load" and children and children[0].opcode == "constant":
        try:
            data, origin = memory.read_static(children[0].value, expression.width // 8)
        except MemoryEvidenceError as exc:
            diagnostics.append({**exc.dependency, "role": role})
        else:
            if origin == "provided":
                used_context.add("memory")
            return constant(int.from_bytes(data, "little"), expression.width)
    return simplify_slice_expression(expression)


def _leaves(expression):
    yield expression
    for child in expression.args:
        yield from _leaves(child)


class PluginImpl:
    """快照消费者：反向定义回溯与有界 Unicorn 验证独立于原生分析。"""

    name = "arm64_br_solver"
    version = "0.1.0"

    def capabilities(self):
        return ("arm64_br", "arm64_blr", "backward_slice", "runtime_provenance", "optional_unicorn")

    def solve(self, snapshot: Mapping, branch_address: int, *, source_path=None,
              registers=None, memory=(), function_address=None,
              max_instructions=512, max_paths=32, timeout_ms=200,
              cancel=None, on_progress=None, include_details=False):
        started = monotonic()
        if not isinstance(snapshot, Mapping) or not isinstance(snapshot.get("metadata", {}), Mapping):
            raise ValueError("插件需要已完成的分析快照")
        if not unsigned(branch_address) or (function_address is not None and not unsigned(function_address)):
            raise ValueError("分支/函数地址必须是无符号 64 位整数")
        for name, value, limit in (("max_instructions", max_instructions, 4096), ("max_paths", max_paths, 64),
                                   ("timeout_ms", timeout_ms, 10000)):
            if type(value) is not int or not 1 <= value <= limit:
                raise ValueError(f"{name} 必须在 [1, {limit}] 范围内")
        if type(include_details) is not bool:
            raise ValueError("include_details 必须是布尔值")
        metadata = snapshot.get("metadata", {})
        architecture = metadata.get("architecture", "")
        base = {"plugin": self.name, "plugin_version": self.version, "architecture": architecture,
                "branch_address": branch_address, "status": "unknown", "targets": [], "possible_targets": [],
                "target_register": None, "branch_mnemonic": "", "parameter_sources": [],
                "source_sha256": None, "source_verified": False, "slice_truncated": False,
                "engine": "backward_slice",
                "runtime_generated": None, "requires_runtime_context": False, "context_dependent": False,
                "verified_by_unicorn": False, "paths": [], "dependencies": [], "warnings": []}
        if architecture not in {"arm64", "aarch64"} or metadata.get("endian", "little") != "little":
            return {**base, "status": "unsupported", "warnings": ["当前插件仅支持小端 ARM64 BR/BLR"]}
        if cancel is not None and not callable(cancel) and not callable(getattr(cancel, "is_set", None)):
            raise TypeError("cancel 必须是可调用对象或提供 is_set()")
        context = _registers(registers)
        deadline = started + timeout_ms / 1000
        try:
            check_budget(deadline, cancel)
            rows, functions = _rows(snapshot, branch_address, function_address, deadline=deadline, cancel=cancel)
        except PluginStopped as exc:
            return {**base, "status": exc.reason}
        from .slicing import slice_branch
        sliced = slice_branch(rows, branch_address, "arm64", functions=functions,
                              max_instructions=max_instructions, max_paths=max_paths,
                              deadline=deadline, cancel=cancel)
        graph = functions[0].get("cfg") if functions else None
        if isinstance(graph, Mapping):
            frontiers = graph.get("frontier", ())
            unclosed = [record for record in frontiers if isinstance(record, Mapping) and not (
                record.get("from") == branch_address and record.get("reason") == "indirect_jump") and
                record.get("reason") not in {"other_function", "symbol_end", "outside_executable"}]
            if unclosed or (graph.get("complete") is False and not frontiers):
                sliced["truncated"] = True
                for path in sliced["paths"]:
                    path["complete"] = False
                    path["dependencies"].append({"kind": "cfg_incomplete", "role": "control",
                        "at": branch_address, "reason": "已有 CFG 包含未完成的上游路径证据"})
        base.update(target_register=sliced["target_register"], branch_mnemonic=sliced["branch_mnemonic"],
                    slice_truncated=sliced["truncated"])
        if sliced.get("stop_reason"):
            return {**base, "status": "cancelled" if sliced["stop_reason"] == "cancelled" else "budget_exceeded"}
        try:
            image = MemoryImage(snapshot, source_path, memory=memory, deadline=deadline, cancel=cancel)
        except PluginStopped as exc:
            return {**base, "status": exc.reason}
        base.update(source_sha256=image.source_sha256, source_verified=image.source_verified)
        possible, confirmed, dependencies, source_dependencies = set(), set(), [], []
        all_proven, verified, context_used, runtime, target_static = True, True, False, False, True
        evidence_invalid = False
        selection_candidates, selection_unknown, runtime_control = set(), False, False
        feasible = 0
        for index, path in enumerate(sliced["paths"]):
            if not path.get("feasible", True):
                continue
            diagnostic, used = [], set()
            try:
                expression = _resolve(path["expression"], context, image, diagnostic, used)
                provided_target_memory = "memory" in used
                conditions, eligible = [], True
                for condition in path.get("conditions", ()):
                    predicate = _resolve(condition["expression"], context, image, diagnostic, used, role="control")
                    condition_proven = bool(predicate.value) if predicate.opcode == "constant" else None
                    conditions.append({**condition, "proven": condition_proven})
                    if condition_proven is not None and condition_proven != condition["taken"]:
                        eligible = False
            except PluginStopped as exc:
                return {**base, "status": exc.reason}
            target = expression.value if expression.opcode == "constant" else None
            # 运行时上下文能选择路径，但不会改变选择器原本的参数来源。
            if unsigned(target):
                selection_candidates.add(target)
            else:
                selection_unknown = True
            runtime_control |= any(dep["kind"] in _RUNTIME and dep.get("role") == "control"
                                   for dep in path["dependencies"])
            if not eligible:
                continue
            remaining = []
            for dep in path["dependencies"]:
                if dep["kind"] == "memory_read":
                    if any(node.opcode == "load" for node in _leaves(expression)):
                        remaining.append(dep)
                elif dep.get("register") in context and dep["kind"] in {"entry_register", "missing_definition"}:
                    continue
                else:
                    remaining.append(dep)
            remaining.extend(diagnostic)
            conditions_proven = all(condition["proven"] is not None for condition in conditions)
            proven = path["complete"] and not remaining and conditions_proven and unsigned(target)
            contradictory = False
            verification = {"status": "not_run", "target": None, "engine": "unicorn", "steps": 0}
            if (image.data is not None or image.provided) and not any(dep["kind"] in _BOUNDS for dep in remaining):
                from .emulator import emulate_slice
                try:
                    segments = image.segments(path["instructions"], [*path["dependencies"], *diagnostic])
                    check_budget(deadline, cancel)
                except PluginStopped as exc:
                    return {**base, "status": exc.reason}
                verification = emulate_slice(path["instructions"], branch_address, sliced["target_register"],
                    segments=segments,
                    registers=context, max_steps=max_instructions,
                    timeout_ms=max(1, int((deadline - monotonic()) * 1000)), cancel=cancel,
                    slice_addresses=path["slice_addresses"])
                if verification["status"] == "infeasible":
                    continue
                if verification["status"] == "resolved":
                    actual = verification.get("target")
                    if target is not None and actual != target:
                        remaining.append({"kind": "evidence_conflict", "at": branch_address,
                                          "reason": "反向表达式与 Unicorn 结果不一致"})
                        proven = False
                        contradictory = True
                    elif not any(dep["kind"] not in {"memory_read"} for dep in remaining) and conditions_proven and path["complete"]:
                        target = actual
                        proven = True
                        remaining = []
                else:
                    remaining.extend(verification.get("dependencies", ()))
                    if verification["status"] in {"cancelled", "budget_exceeded"}:
                        base["status"] = verification["status"]
                    # 参数的静态证明和整条路径的仿真验证是两个结论。
                    # 未知栈序言/外部副作用可阻断验证；源字节冲突会推翻证据。
                    contradictory = any(dep.get("source") in {"byte_mismatch", "self_modifying_code",
                                        "readonly_write", "unreadable", "non_executable"}
                                        for dep in verification.get("dependencies", ()))
                    if contradictory or verification["status"] in {"cancelled", "budget_exceeded", "error"}:
                        proven = False
            feasible += 1
            source_dependencies.extend(path["dependencies"])
            if unsigned(target):
                possible.add(target)
            runtime |= any(dep["kind"] in _RUNTIME and dep.get("role", "target") == "target"
                           for dep in [*path["dependencies"], *diagnostic])
            runtime |= provided_target_memory
            unknown_origin = any(dep["kind"] == "missing_definition" and dep.get("role", "target") == "target"
                                 for dep in path["dependencies"])
            target_static &= unsigned(target) and path["complete"] and not unknown_origin and not contradictory
            evidence_invalid |= contradictory
            context_used |= bool(used) or verification.get("context_dependent", False)
            is_verified = verification["status"] == "resolved" and proven
            verified &= is_verified
            all_proven &= proven
            if proven:
                confirmed.add(target)
            dependencies.extend(remaining)
            report = {"slice_addresses": path["slice_addresses"], "constant_target": target,
                      "complete": path["complete"], "conditions": conditions,
                      "dependencies": _dedup(remaining), "resolved": proven, "verification": verification}
            if include_details:
                report["expression"] = expression.to_dict()
                report["instructions"] = path["instructions"]
            base["paths"].append(report)
            if on_progress is not None:
                try:
                    on_progress({"stage": "br_solver", "completed_paths": index + 1, "total_paths": len(sliced["paths"])})
                except Exception as exc:
                    base["warnings"].append(f"插件进度回调失败：{type(exc).__name__}: {exc}")
        dependencies = _dedup(dependencies)
        runtime |= len(selection_candidates) > 1 and runtime_control
        base.update(possible_targets=sorted(possible), dependencies=dependencies,
                    parameter_sources=_dedup(source_dependencies), context_dependent=context_used,
                    requires_runtime_context=any(dep["kind"] in _RUNTIME for dep in dependencies))
        if runtime and not evidence_invalid:
            base["runtime_generated"] = True
        elif target_static and feasible and len(possible) == 1 and not sliced["truncated"] and not (runtime_control and selection_unknown):
            base["runtime_generated"] = False
        if base["status"] not in {"cancelled", "budget_exceeded"}:
            if all_proven and feasible and len(confirmed) == 1 and not sliced["truncated"]:
                base.update(status="resolved", targets=sorted(confirmed), verified_by_unicorn=verified)
            elif base["requires_runtime_context"]:
                base["status"] = "runtime_required"
            elif any(dep["kind"] in _BOUNDS for dep in dependencies):
                base["status"] = "budget_exceeded"
        base["engine"] = "backward_slice+unicorn" if base["verified_by_unicorn"] else "backward_slice"
        return base

    def teardown(self):
        pass


__all__ = ["PluginImpl"]
