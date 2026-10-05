"""Bounded pseudo-C enrichment after decode/CFG/xref stages have completed."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ...models import AnalysisResult
from ..manager import PluginManager
from . import generate_pseudoc

MAX_FUNCTIONS = 128
MAX_TOTAL_CHARS = 524288
#: 流水线默认的单函数指令上限（与 generate_pseudoc / recover_signature 的默认值一致）。
DEFAULT_MAX_INSTRUCTIONS = 512
#: 原生伪 C 支持的架构。
NATIVE_ARCHITECTURES = frozenset({"x86", "x86_64", "arm", "arm64"})
_MISSING = object()


def _prepare_render(function: dict[str, Any], architecture: str, names: dict[Any, dict[int, str]],
                    prepared: dict[int, tuple[Any, ...]], native: Any) -> None:
    """为签名恢复阶段预渲染“生成阶段将看到的快照视图”。

    视图与第二轮的 snapshot 共享同一 pseudoc_symbols 字典及 start/name/cfg/行对象，
    因而 generate 的首次渲染、recover_signature 与截断后的微码重提升都可复用这一次渲染。
    任何失败都只放弃加速：各阶段按原路径自行渲染，并给出与原实现相同的错误。
    """
    try:
        space = function.get("address_space", "ram")
        own = function.get("pseudoc_symbols", _MISSING)
        # 与第二轮 snapshot 的 pseudoc_symbols 表达式逐字等价。
        symbols = {**names.get(space, {}), **(own if own is not _MISSING else {})}
        prepared[id(function)] = (function, space, own, symbols)
        native._prime_render({**function, "pseudoc_symbols": symbols}, architecture)
    except Exception:
        return


def _snapshot_symbols(function: dict[str, Any], space: Any, names: dict[Any, dict[int, str]],
                      prepared: dict[int, tuple[Any, ...]]) -> dict[Any, Any]:
    # 只有同一函数对象、同一地址空间且自带符号表仍是同一对象时才复用预先合并的字典；
    # 否则按原表达式重新合并（内容与异常都与原实现相同）。
    entry = prepared.get(id(function))
    if (entry is not None and entry[0] is function and
            (entry[1] is space or type(space) is str and type(entry[1]) is str and entry[1] == space) and
            function.get("pseudoc_symbols", _MISSING) is entry[2]):
        return entry[3]
    return {**names.get(space, {}), **function.get("pseudoc_symbols", {})}


def display_name(record: Any, default: str = "function") -> str:
    """伪 C 中使用的源码级名字。

    Loader 或链接证据给出 display_name 时使用它（例如 Mach-O 的 _main → main、
    _puts → puts）；否则沿用原始 name。原始符号名仍保留在函数记录与链接证据中。
    """
    if isinstance(record, dict):
        value = record.get("display_name")
        if isinstance(value, str) and value:
            return value
        return str(record.get("name", default))
    return default


def _site_names(linkage: dict[int, dict[str, Any]]) -> dict[int, dict[str, Any]]:
    """经指针槽位的已核实调用点 → {name, slot}（call [IAT]、call [rip+GOT]、adrp/ldr/blr）。"""
    sites: dict[int, dict[str, Any]] = {}
    for slot, evidence in linkage.items():
        if evidence.get("target_kind") != "import_pointer_slot":
            continue
        entry = {"name": display_name(evidence), "slot": slot}
        for site in evidence.get("call_sites", ()) or ():
            if type(site) is int:
                sites[site] = entry
    return sites


def _thunk_jumps(function: dict[str, Any], evidence: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """已验证导入桩自身的间接跳转（唯一一条）→ 导入名；形状未经快照核实时不命名。"""
    if not isinstance(evidence.get("slot_address"), int):
        return {}
    blocks = function.get("blocks") or function.get("cfg", {}).get("blocks", ())
    rows = (row for block in blocks for row in block.get("instructions", ())) if blocks else function.get("disassembly", ())
    found = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        branch = row.get("branch_info") or {}
        if branch.get("kind") == "jump" and branch.get("target") is None and type(row.get("addr")) is int:
            found.add(row["addr"])
            if len(found) > 1:
                return {}
    return {address: {"name": display_name(evidence), "slot": evidence["slot_address"]} for address in found}


def _name_table(result: Any) -> dict[Any, dict[int, str]]:
    """全部函数的源码级名字表；只有同一地址空间的名字才能解析直接调用。"""
    names: dict[Any, dict[int, str]] = {}
    for function in result.functions:
        if isinstance(function.get("start"), int):
            names.setdefault(function.get("address_space", "ram"), {})[function["start"]] = display_name(function)
    return names


def _add_linkage_names(names: dict[Any, dict[int, str]], linkage: dict[int, dict[str, Any]]) -> None:
    """把已核实的导入桩名字并入名字表（按需生成与流水线共用同一规则）。"""
    for target, evidence in linkage.items():
        if evidence.get("target_kind") == "import_pointer_slot":
            # 槽位地址不是代码地址：只按已核实的调用点命名，不进入函数名表
            # （否则常量还原会把槽位地址误写成函数名）。
            continue
        names.setdefault("ram", {})[target] = display_name(evidence)


def _base_context(result: Any) -> dict[str, Any]:
    """所有函数共用的渲染上下文（容器种类与 Loader 声明的 ABI）。"""
    return {"kind": result.kind, **{key: result.metadata[key] for key in ("abi", "calling_convention") if key in result.metadata}}


def _limit_scope(max_instructions: int | None):
    """按需生成用：max_instructions 为 None（默认 512）时不改变源码恢复上限；否则在作用域内放宽到该值。"""
    from contextlib import nullcontext
    if max_instructions is None:
        return nullcontext()
    from .reconstruct import source_instruction_limit
    return source_instruction_limit(max_instructions)


def populate_native_pseudoc(result: AnalysisResult, *,
                           manager: PluginManager | None = None,
                           is_cancelled: Callable[[], bool] | None = None,
                           on_progress: Callable[[dict[str, Any]], None] | None = None) -> None:
    """为前 MAX_FUNCTIONS 个函数生成伪 C。

    其余函数可在分析完成后用 ``fangida.plugins.pseudoc.on_demand`` 按需生成：两者共用本模块的
    上下文构建（_name_table、_signature_summaries、_argument_closure、_render_snapshot），结果一致。
    """
    architecture = result.metadata.get("architecture", "unknown")
    if architecture not in NATIVE_ARCHITECTURES:
        return
    # Only names from the same address space may resolve a direct call.
    names = _name_table(result)
    from .linkage import resolve_linkage
    linkage = resolve_linkage(result, is_cancelled=is_cancelled)
    _add_linkage_names(names, linkage)
    if linkage:
        result.metadata["pseudoc_linkage"] = list(linkage.values())
    if not result.functions:
        # 没有函数时两轮循环都不会渲染；不为此导入渲染模块（避免一次性导入开销）。
        _populate(result, architecture, names, linkage, None, manager=manager,
                  is_cancelled=is_cancelled, on_progress=on_progress)
        return
    from . import native
    from .datarefs import DataReferences
    # 只读字符串/函数地址解释器：只用 Loader 的节映射，按需有界读取，结束即关闭。
    with DataReferences.from_result(result, names.get("ram", {})) as references:
        # 渲染备忘录只在本次调用内有效（ContextVar），退出即恢复；不跨请求保留任何结果。
        with native._render_scope():
            _populate(result, architecture, names, linkage, native, manager=manager,
                      is_cancelled=is_cancelled, on_progress=on_progress, references=references)


def _register_arity(prototype: Any, registers: int) -> int | None:
    """原型占用的整数参数寄存器个数（浮点参数走向量寄存器，不计入）；变参返回 None。"""
    if prototype is None or prototype.variadic:
        return None
    integer = [ctype for _, ctype in prototype.parameters
               if "*" in ctype or not any(word in ctype for word in ("float", "double"))]
    return min(len(integer), registers)


def _call_targets(function: dict[str, Any]):
    """函数体内的直接调用目标与 CFG 记录的“进入其它函数”出口（只读完成快照）。"""
    for block in function["blocks"]:
        for row in block.get("instructions", ()):
            branch = row.get("branch_info") or {}
            if branch.get("kind") == "call" and isinstance(branch.get("target"), int):
                yield branch["target"]
    for item in function.get("cfg", {}).get("frontier", ()) or ():
        if isinstance(item, dict) and item.get("reason") == "other_function" and isinstance(item.get("to"), int):
            yield item["to"]


def _stub_like(function: dict[str, Any]) -> bool:
    return (sum(len(block.get("instructions", ())) for block in function["blocks"]) <= 4
            and any(isinstance(item, dict) and item.get("reason") == "indirect_jump"
                    for item in function.get("cfg", {}).get("frontier", ()) or ()))


def _ram_bodies(result: Any) -> tuple[dict[int, dict[str, Any]], dict[str, int]]:
    """ram 空间中有函数体的函数（起点 → 记录）及本映像内的名字 → 起点。"""
    by_start = {function["start"]: function for function in result.functions
                if function.get("address_space", "ram") == "ram" and function.get("blocks")
                and isinstance(function.get("start"), int)}
    # 本映像内有函数体的名字：共享库经 PLT 调用自己导出的函数时，桩实际执行的就是它。
    local_by_name: dict[str, int] = {}
    for start, function in by_start.items():
        name = display_name(function)
        if name and name not in local_by_name:
            local_by_name[name] = start
    return by_start, local_by_name


def _argument_closure(result: Any, architecture: str, context: dict[str, Any],
                      names: dict[Any, dict[int, str]], thunks: dict[int, dict[str, Any]],
                      roots: Any = None, *, bodies: tuple[dict[int, Any], dict[str, int]] | None = None
                      ) -> tuple[Any, set[int], dict[int, dict[str, Any]], dict[int, int]] | None:
    """计算 roots（默认前 MAX_FUNCTIONS 个函数）调用闭包内各函数的参数用法。

    返回 (abi, 闭包, 参数用法, 别名)；ABI 没有参数寄存器、没有函数体或分析失败时返回 None。
    被调函数的结论只依赖它自己的子调用，因此同一函数在任何包含它的闭包里结论都相同；
    按需生成据此只为被请求函数的闭包补算，结果与把它并入流水线根集合时一致。
    bodies 可传入预先计算的 _ram_bodies(result)（按需生成的上下文缓存它）。
    """
    from dataclasses import replace
    from .reconstruct.abi import select_abi
    from .reconstruct.arguments import argument_usage
    from .reconstruct.prototypes import lookup
    abi = select_abi(architecture, context)
    if not abi.arguments:
        return None
    by_start, local_by_name = bodies if bodies is not None else _ram_bodies(result)
    if not by_start:
        return None

    thunks = dict(thunks)
    aliases: dict[int, int] = {}
    closure: set[int] = set()
    checked: set[int] = set()
    if roots is None:
        pending = [function["start"] for function in result.functions[:MAX_FUNCTIONS]
                   if isinstance(function.get("start"), int) and function["start"] in by_start]
    else:
        pending = [start for start in roots if isinstance(start, int) and start in by_start]
    for _ in range(64):
        while pending:
            start = pending.pop()
            start = aliases.get(start, start)
            if start in closure or start not in by_start:
                continue
            closure.add(start)
            pending.extend(_call_targets(by_start[start]))
        # resolve_linkage 只覆盖前 128 个函数调用的桩；闭包里更深层的桩在这里补充识别。
        stubs = {start for start in closure - checked if start not in thunks and _stub_like(by_start[start])}
        checked |= closure
        if stubs:
            from .linkage import resolve_thunk_targets
            try:
                thunks.update(resolve_thunk_targets(result, stubs))
            except Exception:
                pass  # 只是补充证据
        for target in closure & thunks.keys():
            local = local_by_name.get(display_name(thunks[target]))
            if local is not None and local != target and target not in aliases:
                aliases[target] = local
                pending.append(local)
        if not pending:
            break
    known: dict[int, int | None] = {}
    variadic: dict[int, int] = {}

    def declare(target: int, prototype: Any) -> None:
        known[target] = _register_arity(prototype, len(abi.arguments))
        if prototype is not None and prototype.variadic:
            fixed = _register_arity(replace(prototype, variadic=False), len(abi.arguments))
            if fixed is not None:
                variadic[target] = fixed

    for target, evidence in thunks.items():
        if isinstance(target, int) and target not in aliases:
            declare(target, lookup(display_name(evidence)))
    for start in closure:
        prototype = lookup(names.get("ram", {}).get(start))
        if prototype is not None and start not in known and start not in aliases:
            declare(start, prototype)
    try:
        usage = argument_usage([by_start[start] for start in sorted(closure)], architecture, abi.arguments,
                               abi.volatile, known_arity=known, aliases=aliases, variadic_fixed=variadic)
    except Exception:
        return None  # 参数用法只是补充证据，失败时保持原摘要
    return abi, closure, usage, aliases


def _merge_usage(summary: dict[str, Any], info: dict[str, Any], order: dict[str, int]) -> None:
    """把一个函数的参数用法并入它的摘要（原地修改 summary；重复合并同一结论不改变结果）。"""
    parameters = [item for item in summary.get("parameters", []) if isinstance(item, dict)]
    present = {item.get("register") for item in parameters}
    for root in info["registers"]:
        if root not in present:
            parameters.append({"register": root, "name": f"arg_{order[root] + 1}",
                               "argument_index": order[root], "evidence": "argument_flow"})
    parameters.sort(key=lambda item: order.get(item.get("register"), len(order)))
    summary["parameters"] = parameters
    proven = bool(summary.get("argument_uses_complete")) or info["complete"]
    if not proven and info.get("complete_assuming_indirect_calls"):
        # 只差间接调用/变参无法严格证明：按通行约定确定参数个数，并在调用证据中标明是推断。
        summary["argument_uses_assumed"] = True
    summary["argument_uses_complete"] = proven or bool(summary.get("argument_uses_assumed"))


def _merge_argument_usage(summaries: dict[str, dict[int, dict]], abi: Any, usage: dict[int, dict[str, Any]],
                          aliases: dict[int, int], *, skip: Any = frozenset(), copy: bool = False) -> None:
    """把参数用法合并进 summaries（新增摘要不带名字，调用处仍按原规则命名）。

    skip：不再改动的函数起点（按需生成时为已合并过的闭包）；copy 为真时先复制已有摘要再修改，
    不改动可能正被其它线程读取的旧摘要对象。流水线使用默认参数，行为与原实现相同。
    """
    ram = summaries.setdefault("ram", {})
    order = {root: index for index, root in enumerate(abi.arguments)}
    for start, info in usage.items():
        if start in skip:
            continue
        summary = ram.get(start)
        if summary is not None and summary.get("signature_complete"):
            continue  # 声明的原型优先
        if summary is None:
            summary = ram[start] = {"parameters": []}
        elif copy:
            summary = ram[start] = dict(summary)
        _merge_usage(summary, info, order)
    # 调用 PLT 桩、而桩指向本库导出函数时：调用处使用该函数的参数结论。
    for target, local in aliases.items():
        if target in skip:
            continue
        if local in ram and target not in ram:
            ram[target] = {key: value for key, value in ram[local].items() if key != "name"}


def _propagate_arguments(result: AnalysisResult, architecture: str, context: dict[str, Any],
                         names: dict[Any, dict[int, str]], thunks: dict[int, dict[str, Any]],
                         summaries: dict[str, dict[int, dict]]) -> None:
    """过程间补全调用目标的参数用法，使调用处在能证实时不再写 unknown_arguments()。

    只分析待渲染函数（前 MAX_FUNCTIONS 个）的调用闭包：被调函数的结论只依赖它自己的子调用，
    闭包内的结果与全量计算相同。闭包遇到 PLT 桩时补充识别；桩指向本库导出函数时沿别名继续。
    只读已完成的指令快照；结果合并进 summaries（新增摘要不带名字，调用处仍按原规则命名）。
    """
    computed = _argument_closure(result, architecture, context, names, thunks)
    if computed is None:
        return
    abi, _closure, usage, aliases = computed
    _merge_argument_usage(summaries, abi, usage, aliases)


def _signature_summary(function: dict[str, Any], index: int, architecture: str, context: dict[str, Any],
                       max_instructions: int | None = None) -> dict[str, Any] | None:
    """第 index 个函数（result.functions 中的下标）的签名摘要；失败时返回 None（不编造证据）。"""
    from .reconstruct import recover_signature
    try:
        if max_instructions is None:
            summary = recover_signature(function, architecture, context=context)
        else:
            summary = recover_signature(function, architecture, context=context, max_instructions=max_instructions)
        if str(summary["name"]).startswith("sub_"):
            summary["name"] = f"function_{index + 1}"
        elif isinstance(function.get("display_name"), str) and function["display_name"]:
            # 符号的源码级名字（Mach-O 去掉前导下划线）用于调用处与函数签名。
            summary["name"] = function["display_name"]
    except Exception:
        return None  # Signature evidence is optional; never invent it on failure.
    return summary


def _signature_summaries(result: Any, architecture: str, names: dict[Any, dict[int, str]],
                         context: dict[str, Any], *, native: Any = None,
                         prepared: dict[int, tuple[Any, ...]] | None = None,
                         is_cancelled: Callable[[], bool] | None = None) -> dict[Any, dict[int, dict]]:
    """前 MAX_FUNCTIONS 个函数的签名摘要（调用处的名字与参数证据）。

    prepared 不为 None 时（流水线）同时预渲染“生成阶段将看到的快照视图”供后续复用；
    按需生成不预渲染，结果相同（预渲染只是加速）。
    """
    summaries: dict[Any, dict[int, dict]] = {}
    for index, function in enumerate(result.functions[:MAX_FUNCTIONS]):
        if is_cancelled is not None and is_cancelled():
            break
        if not isinstance(function.get("start"), int):
            continue
        if prepared is not None:
            _prepare_render(function, architecture, names, prepared, native)
        summary = _signature_summary(function, index, architecture, context)
        if summary is not None:
            summaries.setdefault(function.get("address_space", "ram"), {})[function["start"]] = summary
    return summaries


def _render_snapshot(function: dict[str, Any], space: Any, context: dict[str, Any], references: Any,
                     summaries: dict[Any, dict[int, dict]], names: dict[Any, dict[int, str]],
                     prepared: dict[int, tuple[Any, ...]], thunks: dict[int, dict[str, Any]],
                     site_names: dict[int, dict[str, Any]], import_slots: frozenset[int]) -> dict[str, Any]:
    """生成阶段看到的函数快照：名字表、调用目标摘要、链接证据与只读数据引用。

    流水线与按需生成共用这一构造，因此同一函数在相同上下文下得到相同的伪 C。
    """
    snapshot = {**function, "pseudoc_symbols": _snapshot_symbols(function, space, names, prepared),
                "pseudoc_context": {**context, **({"data_references": references} if references is not None and space == "ram" else {}),
                    **function.get("pseudoc_context", {}),
                    "callees": {**summaries.get(space, {}), **function.get("pseudoc_context", {}).get("callees", {})}}}
    if space == "ram" and isinstance(function.get("start"), int) and function["start"] in thunks and "name_source" not in snapshot["pseudoc_context"]:
        # 函数本身就是已验证的导入桩：伪 C 头注释据此说明名字来源。
        snapshot["pseudoc_context"]["name_source"] = "linkage"
    if space == "ram" and import_slots and "import_slots" not in snapshot["pseudoc_context"]:
        snapshot["pseudoc_context"]["import_slots"] = import_slots
    if space == "ram" and (site_names or isinstance(function.get("start"), int) and function["start"] in thunks):
        own = _thunk_jumps(function, thunks[function["start"]]) if function.get("start") in thunks else {}
        declared_sites = function.get("pseudoc_context", {}).get("call_site_names", {})
        if own or declared_sites:
            snapshot["pseudoc_context"]["call_site_names"] = {**site_names, **own, **declared_sites}
        else:
            snapshot["pseudoc_context"]["call_site_names"] = site_names
    # A verified dynamic symbol names the PLT entry. Its local body does
    # not establish the prototype of a possibly interposed runtime callee.
    for target, evidence in thunks.items():
        if space == "ram":
            declared = function.get("pseudoc_context", {}).get("callees", {}).get(target, {})
            snapshot["pseudoc_context"]["callees"][target] = declared if declared.get("signature_complete") else {"name": display_name(evidence)}
    return snapshot


def _populate(result: AnalysisResult, architecture: str, names: dict[Any, dict[int, str]],
              linkage: dict[int, dict[str, Any]], native: Any, *, manager: PluginManager | None,
              is_cancelled: Callable[[], bool] | None,
              on_progress: Callable[[dict[str, Any]], None] | None,
              references: Any = None) -> None:
    context = _base_context(result)
    prepared: dict[int, tuple[Any, ...]] = {}
    summaries = _signature_summaries(result, architecture, names, context, native=native, prepared=prepared,
                                     is_cancelled=is_cancelled)
    produced = attempted = characters = microcode_functions = microcode_instructions = 0
    limited = False
    # 经指针槽位的调用点名字（只读共享）；导入桩自身的跳转在下面按函数补充。
    site_names = _site_names(linkage)
    thunks = {target: evidence for target, evidence in linkage.items()
              if evidence.get("target_kind") != "import_pointer_slot"}
    if not (is_cancelled is not None and is_cancelled()):
        _propagate_arguments(result, architecture, context, names, thunks, summaries)
    # 已核实的导入指针槽位（GOT/IAT/la_symbol_ptr）：映像内必然可读，读取无副作用。
    import_slots = frozenset(evidence["slot_address"] for evidence in linkage.values()
                             if type(evidence.get("slot_address")) is int)
    for function in result.functions:
        if is_cancelled is not None and is_cancelled():
            limited = True
            break
        existing = bool(function.get("pseudoc") or function.get("pseudo_c"))
        if existing and function.get("microcode"):
            continue
        if not function.get("blocks") and not function.get("disassembly") and not function.get("cfg", {}).get("blocks"):
            continue
        if attempted >= MAX_FUNCTIONS or MAX_TOTAL_CHARS - characters < 256:
            limited = True
            break
        attempted += 1
        space = function.get("address_space", "ram")
        snapshot = _render_snapshot(function, space, context, references, summaries, names, prepared,
                                    thunks, site_names, import_slots)
        output = None
        if not existing:
            try:
                output = generate_pseudoc(snapshot, architecture, manager=manager,
                                         max_chars=min(32768, MAX_TOTAL_CHARS - characters), style="readable")
            except Exception as exc:
                # Optional enrichment failures must not discard completed analysis.
                result.warnings.append(f"Pseudo-C unavailable: {type(exc).__name__}: {exc}")
                break
        if output is not None and output.pseudoc:
            function.update(pseudoc=output.pseudoc, pseudoc_producer=output.producer,
                            pseudoc_truncated=output.truncated)
            if output.reconstruction:
                function.update(machine_pseudoc=output.machine_pseudoc, pseudoc_style=output.reconstruction.get("style", "readable"),
                                pseudoc_reconstruction=output.reconstruction)
            result.warnings.extend(output.warnings)
            characters += len(output.pseudoc)
            produced += 1
        try:
            from .microcode import MICROCODE_VERSION, analyze_microcode, lift_function
            if output is not None and output.microcode and not output.truncated:
                records, truncated = list(output.microcode), False
            else:
                # Microcode has its own instruction budget: existing C and C
                # character truncation must not remove semantic evidence.
                # 同一快照的完整渲染已在本次调用中完成时直接复用其微码（与重新
                # lift_function 逐字段相同）；否则照旧重新提升。
                semantic = native._memo_lift(snapshot, architecture)
                if semantic is None:
                    semantic = lift_function(snapshot, architecture)
                records, truncated = semantic["instructions"], semantic["truncated"]
            if records:
                analysis = analyze_microcode(records)
                function.update(microcode=records, microcode_version=MICROCODE_VERSION,
                    microcode_complete=not truncated and all(row["supported"] for row in records),
                    microcode_analysis=analysis)
                microcode_functions += 1
                microcode_instructions += len(records)
        except Exception as exc:
            result.warnings.append(f"Microcode unavailable: {type(exc).__name__}: {exc}")
        if on_progress is not None:
            on_progress({"stage": "native_pseudoc", "completed_functions": produced,
                         "attempted_functions": attempted})
    result.stats.update(pseudoc_functions=produced, pseudoc_characters=characters,
                        pseudoc_budget_exhausted=limited, microcode_functions=microcode_functions,
                        microcode_instructions=microcode_instructions, microcode_budget_exhausted=limited)
    if limited:
        result.warnings.append("Pseudo-C generation stopped at its function/output budget or cancellation")
