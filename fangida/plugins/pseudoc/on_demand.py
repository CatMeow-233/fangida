"""对已完成分析结果中的任意函数按需生成伪 C。

分析时的流水线（pipeline.populate_native_pseudoc）只为前 MAX_FUNCTIONS 个函数生成伪 C。
本模块在分析完成之后，为任意函数复用流水线的同一套上下文构建：

- 名字表：全部函数的源码级名字 + 已核实导入桩的名字（pipeline._name_table / _add_linkage_names）；
- linkage：resolve_linkage 给出的导入桩、指针槽位调用点与槽位集合；被请求函数不在 linkage
  扫描的前 128 个函数之内时，只为本次请求补充它自己的链接证据（不改动共享上下文）；
- 签名摘要：前 MAX_FUNCTIONS 个函数的 recover_signature（调用处的名字与参数证据）；流水线渲染
  范围之外的被请求函数按同一规则补上自己的摘要（sub_ 函数改名为 function_N），它在按需生成的
  文本里调用的同类函数也用同一 function_N 命名（函数头与调用处一致）；
- 过程间参数传播：前 MAX_FUNCTIONS 个函数的调用闭包，并按请求把被请求函数的调用闭包并入；
- 只读数据引用：每次请求独立的 DataReferences（只读字符串与函数地址，按需有界读取）。

职责边界：只消费已完成的指令快照与 Loader 的节映射，不调用解码器，不产生交叉引用；
不修改结果对象（不写 functions、metadata、warnings，也不写数据库）。微码提升属于本插件
对快照的处理。

一致性：被调函数的参数结论只依赖它自己的子调用（见 pipeline._argument_closure），把被请求函数的
闭包并入时只新增尚未出现的函数、不改动已有摘要，因此前 MAX_FUNCTIONS 个函数按需生成的文本与
流水线为同一函数生成的文本逐字相同（流水线的总字符预算未让该函数的 max_chars 低于 32768 时）。

缓存：上下文按结果对象缓存（模块级有界 LRU，线程安全；也可由调用方自行持有 PseudocContext），
同一函数、同一上限的生成结果在上下文内缓存（有界 LRU）。结果对象的函数列表或名字变化后自动重建。
"""
from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from . import pipeline
from .models import validate_limits

_log = logging.getLogger(__name__)

#: 默认单函数指令上限，与分析时的流水线相同。
DEFAULT_MAX_INSTRUCTIONS = pipeline.DEFAULT_MAX_INSTRUCTIONS
#: 按需生成允许的单函数指令上限（与 validate_limits 的上限一致）。
MAX_ON_DEMAND_INSTRUCTIONS = 8192
#: 默认单函数字符上限（与流水线单函数上限相同）；指令上限超过 512 时按每条指令 128 个字符放宽，
#: 最多 MAX_ON_DEMAND_CHARS。
DEFAULT_MAX_CHARS = 32768
MAX_ON_DEMAND_CHARS = 131072
#: 模块级上下文缓存最多保留的结果对象个数（每个上下文强引用其结果，故保持很小）。
MAX_CONTEXTS = 2
#: 每个上下文缓存的生成结果条数。
MAX_CACHED_OUTPUTS = 256
#: 每个上下文缓存的“被请求函数自身的链接证据”条数。
MAX_CACHED_OVERLAYS = 64

# 流水线写回函数记录的字段：生成时去掉，保证与流水线当时看到的输入相同（生成本身也不读取它们）。
_GENERATED_KEYS = frozenset({"pseudoc", "pseudo_c", "pseudoc_producer", "pseudoc_truncated", "machine_pseudoc",
                             "pseudoc_style", "pseudoc_reconstruction", "microcode", "microcode_version",
                             "microcode_complete", "microcode_analysis"})


class _ResultView:
    """把快照字典（MCP、GUI、数据库）适配成流水线读取的属性接口；只借用引用，不复制。"""

    __slots__ = ("path", "kind", "metadata", "functions")

    def __init__(self, path: Any, kind: str, metadata: Mapping[str, Any], functions: list[Any]) -> None:
        self.path, self.kind, self.metadata, self.functions = path, kind, metadata, functions


def _as_result(source: Any) -> Any:
    """AnalysisResult 原样使用；快照字典与 AnalysisView 适配为只读视图。"""
    snapshot = getattr(source, "_snapshot", None)
    if not isinstance(source, Mapping) and isinstance(snapshot, Mapping):
        source = snapshot  # api.AnalysisView：借用其内部快照，避免 snapshot() 的整图深拷贝
    if isinstance(source, Mapping):
        metadata = source.get("metadata")
        functions = source.get("functions")
        return _ResultView(source.get("path"), str(source.get("kind", "")),
                           metadata if isinstance(metadata, Mapping) else {},
                           functions if isinstance(functions, list) else [])
    if all(hasattr(source, name) for name in ("kind", "metadata", "functions")):
        return source
    raise TypeError("source must be an AnalysisResult, AnalysisView or analysis snapshot mapping")


def _has_instructions(function: Mapping[str, Any]) -> bool:
    # 与流水线、resolve_linkage 判断“带指令函数”的规则相同。
    return bool(function.get("blocks") or function.get("disassembly") or function.get("cfg", {}).get("blocks"))


def _referenced_targets(function: Mapping[str, Any]) -> set[int]:
    """函数快照中的直接控制转移目标（调用、跳转）与 CFG 记录的出口地址（只读完成快照）。

    微码的调用目标取自指令行的 branch_info.target（见 microcode.control_flow），因此这里覆盖
    伪 C 中所有可能按名字写出的直接调用与尾跳转目标。
    """
    blocks = function.get("blocks") or function.get("cfg", {}).get("blocks") or ()
    rows = [row for block in blocks if isinstance(block, Mapping) for row in block.get("instructions", ())]
    if not blocks:
        rows = list(function.get("disassembly", ()) or ())
    targets: set[int] = set()
    for row in rows:
        branch = row.get("branch_info") if isinstance(row, Mapping) else None
        if isinstance(branch, Mapping) and type(branch.get("target")) is int:
            targets.add(branch["target"])
    for item in function.get("cfg", {}).get("frontier", ()) or ():
        if isinstance(item, Mapping) and type(item.get("to")) is int:
            targets.add(item["to"])
    return targets


def _stub_candidate(function: Mapping[str, Any]) -> bool:
    """形似链接桩（与过程间参数分析补充识别桩的规则 pipeline._stub_like 相同）；快照异常时为假。"""
    try:
        return bool(function.get("blocks")) and pipeline._stub_like(function)
    except Exception:
        return False


def _fingerprint(functions: list[Any]) -> tuple[Any, ...]:
    """函数列表中影响上下文的字段：起点、地址空间与源码级名字（重命名后重建上下文）。"""
    return tuple((function.get("start"), function.get("address_space", "ram"), pipeline.display_name(function))
                 if isinstance(function, dict) else None for function in functions)


def _limits(max_instructions: Any, max_chars: Any) -> tuple[int, int]:
    if max_instructions is None:
        max_instructions = DEFAULT_MAX_INSTRUCTIONS
    if type(max_instructions) is not int or not 1 <= max_instructions <= MAX_ON_DEMAND_INSTRUCTIONS:
        raise ValueError(f"max_instructions must be an integer in [1, {MAX_ON_DEMAND_INSTRUCTIONS}]")
    if max_chars is None:
        # 默认上限保持流水线的 32768（结果与流水线一致）；放宽指令上限时机器视图文本也会变长
        # （每条指令约 100 个字符），按每条指令 128 个字符放宽。
        max_chars = (DEFAULT_MAX_CHARS if max_instructions <= DEFAULT_MAX_INSTRUCTIONS
                     else min(MAX_ON_DEMAND_CHARS, max_instructions * 128))
    validate_limits(max_instructions, max_chars)
    return max_instructions, max_chars


class _State:
    """一次构建得到的共享上下文；summaries/closure/usage 只以“整体替换”的方式更新（写时复制）。"""

    def __init__(self) -> None:
        self.result: Any = None
        self.functions: list[Any] = []
        self.fingerprint: tuple[Any, ...] = ()
        self.architecture = "unknown"
        self.context: dict[str, Any] = {}
        self.names: dict[Any, dict[int, str]] = {}
        self.linkage: dict[int, dict[str, Any]] = {}
        self.thunks: dict[int, dict[str, Any]] = {}
        self.site_names: dict[int, dict[str, Any]] = {}
        self.import_slots: frozenset[int] = frozenset()
        self.linkage_scanned: frozenset[int] = frozenset()  # resolve_linkage 扫描过的函数下标
        self.rendered: frozenset[int] = frozenset()  # 流水线渲染范围内的函数下标
        self.bodies: tuple[dict[int, Any], dict[str, int]] = ({}, {})
        self.abi: Any = None  # None：参数传播不可用（没有参数寄存器或流水线同样失败）
        self.summaries: dict[Any, dict[int, dict]] = {}
        self.closure: frozenset[int] = frozenset()
        self.usage: dict[int, dict[str, Any]] = {}
        self.positions: dict[tuple[Any, int], int] = {}
        self.identities: dict[int, int] = {}
        self.overlays: OrderedDict[int, dict[str, Any]] = OrderedDict()
        # 流水线渲染范围之外、按需生成时会补上自身摘要的函数中，被改名为 function_N 的那些：
        # {地址空间: {起点: function_N}}（见 _offpipeline_names）。
        self.offpipeline_names: dict[Any, dict[int, str]] = {}
        # linkage 扫描范围之外、形似链接桩且经核实的导入桩（首次需要时一次核对，见 _stub_thunks）。
        self.stub_thunks: dict[int, dict[str, Any]] | None = None


class _SanitizedResult:
    """把函数列表里的非字典条目换成空字典的只读代理，其余属性转发给原结果。

    流水线的上下文构建（_name_table、resolve_linkage、_ram_bodies 等）假定每个条目都是字典；
    快照（MCP、数据库）里混入的非字典条目在这里换成空字典：空字典没有起点和指令，会被各阶段
    跳过，下标保持不变（function_N 的编号不受影响）。只在确有非字典条目时使用。
    """

    def __init__(self, result: Any) -> None:
        self._result = result
        self.functions = [function if isinstance(function, dict) else {} for function in result.functions]

    def __getattr__(self, name: str) -> Any:
        return getattr(self._result, name)


def _offpipeline_name(record: Any, position: int) -> str | None:
    """流水线 _signature_summary 的改名规则：原始名字以 sub_ 开头时改为 function_{下标+1}。"""
    if not isinstance(record, dict) or not str(record.get("name", "function")).startswith("sub_"):
        return None
    return f"function_{position + 1}"


def _offpipeline_names(state: _State) -> dict[Any, dict[int, str]]:
    """按需生成时会被改名为 function_N 的函数（流水线渲染范围之外、下标不小于 MAX_FUNCTIONS）。

    流水线只为前 MAX_FUNCTIONS 个函数恢复签名摘要，摘要里的 function_N 同时用于函数头与调用处；
    按需生成为范围之外的函数补摘要时用同一规则命名。为了让同一函数在按需生成的文本里只有一个
    名字，这些函数作为调用目标时也用同一个 function_N（见 _request_view）。
    """
    names: dict[Any, dict[int, str]] = {}
    for (space, start), position in state.positions.items():
        if position < pipeline.MAX_FUNCTIONS or position in state.rendered:
            continue
        name = _offpipeline_name(state.functions[position], position)
        if name is not None:
            names.setdefault(space, {})[start] = name
    return names


def _build_state(result: Any, fingerprint: tuple[Any, ...]) -> _State:
    """与 populate_native_pseudoc 相同的上下文构建（名字、linkage、签名摘要、参数传播）。"""
    state = _State()
    state.result, state.functions, state.fingerprint = result, result.functions, fingerprint
    state.architecture = result.metadata.get("architecture", "unknown")
    for position, function in enumerate(result.functions):
        if not isinstance(function, dict):
            continue
        state.identities[id(function)] = position
        if isinstance(function.get("start"), int):
            state.positions.setdefault((function.get("address_space", "ram"), function["start"]), position)
    if state.architecture not in pipeline.NATIVE_ARCHITECTURES:
        return state
    if any(not isinstance(function, dict) for function in result.functions):
        # 有非字典条目：上下文构建改用代理（state.functions 仍是原列表，用于身份与下标检查）。
        result = state.result = _SanitizedResult(result)
    from .linkage import MAX_LINKAGE_FUNCTIONS, resolve_linkage
    names = pipeline._name_table(result)
    linkage = resolve_linkage(result)
    pipeline._add_linkage_names(names, linkage)
    context = pipeline._base_context(result)
    summaries = pipeline._signature_summaries(result, state.architecture, names, context)
    thunks = {target: evidence for target, evidence in linkage.items()
              if evidence.get("target_kind") != "import_pointer_slot"}
    bodies = pipeline._ram_bodies(result)
    computed = pipeline._argument_closure(result, state.architecture, context, names, thunks, bodies=bodies)
    if computed is not None:
        abi, closure, usage, aliases = computed
        pipeline._merge_argument_usage(summaries, abi, usage, aliases)
        state.abi, state.closure, state.usage = abi, frozenset(closure), dict(usage)
    # resolve_linkage 只扫描前 MAX_LINKAGE_FUNCTIONS 个带指令的函数；流水线按同一顺序渲染前
    # MAX_FUNCTIONS 个带指令的函数（两者通常是同一集合）。
    with_instructions = [position for position, function in enumerate(result.functions)
                         if isinstance(function, dict) and _has_instructions(function)]
    state.linkage_scanned = frozenset(with_instructions[:MAX_LINKAGE_FUNCTIONS])
    state.rendered = frozenset(with_instructions[:pipeline.MAX_FUNCTIONS])
    state.context, state.names, state.linkage, state.thunks = context, names, linkage, thunks
    state.site_names = pipeline._site_names(linkage)
    state.import_slots = frozenset(evidence["slot_address"] for evidence in linkage.values()
                                   if type(evidence.get("slot_address")) is int)
    state.bodies, state.summaries = bodies, summaries
    state.offpipeline_names = _offpipeline_names(state)
    return state


class PseudocContext:
    """一个已完成结果的按需伪 C 上下文：延迟构建、线程安全、有界缓存。

    构造本身不做任何分析（可以在界面线程创建）；第一次 generate 时在调用线程构建上下文。
    同一上下文可被多个线程同时使用：共享状态在锁内以写时复制方式更新，渲染在锁外进行。
    """

    def __init__(self, source: Any) -> None:
        _as_result(source)  # 尽早拒绝不支持的输入类型
        self.source = source
        self._lock = threading.RLock()
        self._state: _State | None = None
        self._outputs: OrderedDict[tuple[Any, ...], dict[str, Any]] = OrderedDict()
        self.builds = 0  # 上下文构建次数（诊断与测试用）

    # ------------------------------------------------------------------ 状态
    def current(self, source: Any = None) -> bool:
        """上下文仍对应 source（默认自身来源）的当前函数列表与名字。"""
        if source is not None and source is not self.source:
            return False
        with self._lock:
            state = self._state
            if state is None:
                return True
            result = _as_result(self.source)
            return state.functions is result.functions and state.fingerprint == _fingerprint(result.functions)

    def _ensure(self) -> _State:
        with self._lock:
            result = _as_result(self.source)
            fingerprint = _fingerprint(result.functions)
            state = self._state
            if state is None or state.functions is not result.functions or state.fingerprint != fingerprint:
                try:
                    built = _build_state(result, fingerprint)
                except ValueError:
                    raise
                except Exception as exc:
                    # 与渲染失败相同：快照内容异常时给出 ValueError（MCP 转成工具错误），不外抛内部异常。
                    raise ValueError(f"Pseudo-C context unavailable: {type(exc).__name__}: {exc}") from exc
                state = self._state = built
                self._outputs.clear()
                self.builds += 1
            return state

    def prepare(self) -> PseudocContext:
        """提前构建上下文（例如在后台线程预热）；返回自身。"""
        self._ensure()
        return self

    def _locate(self, state: _State, function: Any, address_space: str | None) -> int:
        if isinstance(function, Mapping):
            position = state.identities.get(id(function))
            if position is None or state.functions[position] is not function:
                raise ValueError("function record does not belong to this analysis result")
            return position
        if type(function) is not int or function < 0:
            raise ValueError("function must be a function record or a non-negative start address")
        position = state.positions.get((address_space or "ram", function))
        if position is None:
            raise ValueError(f"No function starts at {function:#x}")
        return position

    # ------------------------------------------------------------------ 每次请求的上下文
    def _linkage_overlay(self, state: _State, position: int, function: dict[str, Any]) -> dict[str, Any]:
        """被请求函数不在 linkage 扫描范围内时，只为它补充导入桩、槽位调用点与槽位（按函数缓存）。"""
        with self._lock:
            cached = state.overlays.get(position)
            if cached is not None:
                state.overlays.move_to_end(position)
                return cached
        overlay: dict[str, Any] = {"linkage": {}}
        if position not in state.linkage_scanned and function.get("address_space", "ram") == "ram":
            from .linkage import resolve_linkage
            result = state.result
            # 被请求函数排在第一位：扫描规则与流水线完全相同，只是扫描集合包含了它。
            # result.functions：有非字典条目时是代理里已替换为空字典的列表。
            proxy = _ResultView(getattr(result, "path", None), result.kind, result.metadata,
                                [function, *result.functions])
            try:
                overlay["linkage"] = resolve_linkage(proxy)
            except Exception:
                overlay["linkage"] = {}  # 链接证据只是补充；失败时沿用共享上下文
            start = function.get("start")
            if (type(start) is int and start not in overlay["linkage"] and start not in state.thunks
                    and _stub_candidate(function)):
                # 被请求函数本身可能是链接桩（PLT/导入桩）：resolve_linkage 只从调用点收集候选，
                # 桩自身不在其中，而调用它的函数按需生成时会经链接证据写出导入名。这里按与过程间
                # 参数分析相同的规则（形似桩 → resolve_thunk_targets 核对）补充，使函数头与调用处同名。
                evidence = self._stub_thunks(state).get(start)
                if evidence is not None:
                    overlay["linkage"] = {**overlay["linkage"], start: evidence}
        with self._lock:
            state.overlays[position] = overlay
            while len(state.overlays) > MAX_CACHED_OVERLAYS:
                state.overlays.popitem(last=False)
        return overlay

    def _stub_thunks(self, state: _State) -> dict[int, dict[str, Any]]:
        """linkage 扫描范围之外、形似链接桩的函数中经核实的导入桩（每个上下文只核对一次）。

        resolve_thunk_targets 的耗时主要是扫描指令行，与候选个数基本无关，因此一次核对全部候选
        并缓存；每个候选的结论与单独核对时相同（候选按 MAX_LINKAGE_TARGETS 分批，不触发上限），
        与请求顺序无关。
        """
        with self._lock:
            cached = state.stub_thunks
        if cached is not None:
            return cached
        from .linkage import MAX_LINKAGE_TARGETS, resolve_thunk_targets
        candidates = sorted(record["start"] for position, record in enumerate(state.functions)
                            if position not in state.linkage_scanned and isinstance(record, dict)
                            and record.get("address_space", "ram") == "ram" and type(record.get("start")) is int
                            and record["start"] not in state.thunks and _stub_candidate(record))
        found: dict[int, dict[str, Any]] = {}
        for offset in range(0, len(candidates), MAX_LINKAGE_TARGETS):
            try:
                found.update(resolve_thunk_targets(state.result, candidates[offset:offset + MAX_LINKAGE_TARGETS]))
            except Exception:
                # 只是补充证据（与流水线 _argument_closure 的处理相同）；记录调试日志以免掩盖链接解析缺陷
                _log.debug("resolve_thunk_targets 失败，忽略本批形似桩函数的导入桩证据", exc_info=True)
        with self._lock:
            if state.stub_thunks is None:
                state.stub_thunks = found
            return state.stub_thunks

    def _extend_closure(self, state: _State, start: int) -> None:
        """把被请求函数的调用闭包并入参数传播结果（只新增未出现过的函数，写时复制）。"""
        with self._lock:
            if state.abi is None or start in state.closure or start not in state.bodies[0]:
                return
            # 与流水线相同的名字表与导入桩：闭包内各函数的结论只取决于闭包成员，与请求顺序无关。
            computed = pipeline._argument_closure(state.result, state.architecture, state.context, state.names,
                                                  state.thunks, roots=[start], bodies=state.bodies)
            if computed is None:
                return
            abi, closure, usage, aliases = computed
            summaries = {space: dict(entries) for space, entries in state.summaries.items()}
            pipeline._merge_argument_usage(summaries, abi, usage, aliases, skip=state.closure, copy=True)
            state.usage = {**state.usage, **{key: value for key, value in usage.items() if key not in state.closure}}
            state.summaries = summaries
            state.closure = state.closure | closure

    def _request_view(self, state: _State, position: int, function: dict[str, Any], clean: dict[str, Any],
                      max_instructions: int) -> tuple[Any, ...]:
        """本次请求的名字表、调用目标摘要与链接证据视图（共享上下文保持不变）。"""
        space = function.get("address_space", "ram")
        start = function.get("start")
        if space == "ram" and isinstance(start, int):
            self._extend_closure(state, start)
        with self._lock:
            names, summaries, thunks = state.names, state.summaries, state.thunks
            site_names, import_slots, usage, abi = state.site_names, state.import_slots, state.usage, state.abi
        overlay = self._linkage_overlay(state, position, function)["linkage"]
        if overlay:
            names = {key: dict(value) for key, value in names.items()}
            pipeline._add_linkage_names(names, overlay)
            thunks = {**{target: evidence for target, evidence in overlay.items()
                         if evidence.get("target_kind") != "import_pointer_slot"}, **thunks}
            site_names = {**pipeline._site_names(overlay), **site_names}
            import_slots = import_slots | frozenset(evidence["slot_address"] for evidence in overlay.values()
                                                    if type(evidence.get("slot_address")) is int)
        if position >= pipeline.MAX_FUNCTIONS and position not in state.rendered and isinstance(start, int):
            # 流水线只为前 MAX_FUNCTIONS 个函数恢复签名；流水线渲染范围之外的被请求函数按同一规则
            # 补上自己的摘要（名字 function_N / 显示名、参数与返回类型），只用于本次请求。
            # 流水线渲染过的函数保持流水线当时的上下文，保证结果一致。
            own = pipeline._signature_summary(
                clean, position, state.architecture, state.context,
                None if max_instructions == DEFAULT_MAX_INSTRUCTIONS else max_instructions)
            entries = dict(summaries.get(space, {}))
            # 同样在范围之外、按同一规则改名为 function_N 的调用目标：调用处也用这个名字，使同一
            # 函数在按需生成的文本里只有一个名字（与流水线里 function_N 同时用于函数头和调用处
            # 一致）。只补名字，不改参数证据（缺摘要时调用处的参数规则不变）。
            renamed = state.offpipeline_names.get(space, {})
            if renamed:
                for target in _referenced_targets(clean):
                    name = renamed.get(target)
                    if name is not None and target != start:
                        entries[target] = {**entries.get(target, {}), "name": name}
            if own is not None:
                info = usage.get(start)
                if info is not None and abi is not None and not own.get("signature_complete"):
                    pipeline._merge_usage(own, info, {root: index for index, root in enumerate(abi.arguments)})
                entries[start] = own
            elif start in renamed:
                # 签名恢复失败（不编造参数证据）时仍用调用处的同一名字，函数头不退化为 recovered_function。
                entries[start] = {**entries.get(start, {}), "name": renamed[start]}
            summaries = {**summaries, space: entries}
        return names, summaries, thunks, site_names, import_slots

    # ------------------------------------------------------------------ 生成
    def generate(self, function: Any, *, address_space: str | None = None,
                 max_instructions: int | None = None, max_chars: int | None = None,
                 manager: Any = None) -> dict[str, Any]:
        """为一个函数生成伪 C，返回与流水线写入函数记录相同的字段（另带 address、warnings 等）。

        function：函数记录（必须是本结果中的对象）或函数起点地址（address_space 默认 ram）。
        max_instructions：单函数指令上限，默认 512，最大 8192；max_chars 默认随之放宽。
        """
        max_instructions, max_chars = _limits(max_instructions, max_chars)
        state = self._ensure()
        if state.architecture not in pipeline.NATIVE_ARCHITECTURES:
            raise ValueError(f"On-demand pseudo-C is unavailable for architecture {state.architecture!r}")
        position = self._locate(state, function, address_space)
        record = state.functions[position]
        key = (position, max_instructions, max_chars, id(manager) if manager is not None else None)
        with self._lock:
            cached = self._outputs.get(key)
            if cached is not None:
                self._outputs.move_to_end(key)
                return _copy_output(cached, cached=True)
        if not _has_instructions(record):
            raise ValueError("Function has no completed instruction snapshot")
        clean = {name: value for name, value in record.items() if name not in _GENERATED_KEYS}
        output = self._render(state, position, record, clean, max_instructions, max_chars, manager)
        with self._lock:
            if self._state is state:
                self._outputs[key] = output
                while len(self._outputs) > MAX_CACHED_OUTPUTS:
                    self._outputs.popitem(last=False)
        return _copy_output(output, cached=False)

    def _render(self, state: _State, position: int, record: dict[str, Any], clean: dict[str, Any],
                max_instructions: int, max_chars: int, manager: Any) -> dict[str, Any]:
        from .datarefs import DataReferences
        space = record.get("address_space", "ram")
        limit = None if max_instructions == DEFAULT_MAX_INSTRUCTIONS else max_instructions
        try:
            with pipeline._limit_scope(limit):
                names, summaries, thunks, site_names, import_slots = self._request_view(
                    state, position, record, clean, max_instructions)
                # 每次请求独立的只读数据引用：自己的文件句柄与查找预算，结束即关闭。
                with DataReferences.from_result(state.result, names.get("ram", {})) as references:
                    snapshot = pipeline._render_snapshot(clean, space, state.context, references, summaries, names,
                                                         {}, thunks, site_names, import_slots)
                    extra = {} if limit is None else {"max_instructions": max_instructions}
                    output = pipeline.generate_pseudoc(snapshot, state.architecture, manager=manager,
                                                       max_chars=max_chars, style="readable", **extra)
                    if limit is not None:
                        output = _widen_readable(snapshot, state.architecture, output, max_instructions, max_chars)
        except ValueError:
            raise
        except Exception as exc:
            raise ValueError(f"Pseudo-C generation failed: {type(exc).__name__}: {exc}") from exc
        if not output.pseudoc:
            reason = "; ".join(output.warnings) or "no pseudo-C produced"
            raise ValueError(f"Pseudo-C is unavailable for this function: {reason}")
        generated = {"address": record.get("start"), "address_space": space, "name": record.get("name"),
                     "position": position, "pseudoc": output.pseudoc, "pseudoc_producer": output.producer,
                     "pseudoc_truncated": output.truncated, "warnings": list(output.warnings),
                     "max_instructions": max_instructions, "max_chars": max_chars, "on_demand": True}
        if output.reconstruction:
            generated.update(machine_pseudoc=output.machine_pseudoc,
                             pseudoc_style=output.reconstruction.get("style", "readable"),
                             pseudoc_reconstruction=output.reconstruction)
        return generated


def _widen_readable(snapshot: dict[str, Any], architecture: str, output: Any, max_instructions: int,
                    max_chars: int) -> Any:
    """放宽指令上限时，可读视图不受机器视图文本预算限制。

    generate_pseudoc 的可读视图取自机器视图渲染的微码；机器视图文本超出 max_chars 时会减半
    指令，可读视图随之只覆盖前一半。这里在机器微码少于快照（上限内）指令数时，按同一上限
    重新提升完整微码再做源码恢复；机器视图保持原样。只用于非默认上限（默认 512 与流水线相同）。

    截断标记与 generate_pseudoc 的语义相同：任一视图被截断即为真。机器视图仍是原来那份
    （已被截断的）文本，因此它的截断标记必须保留——MCP 的 style=machine 直接返回这个标记。
    """
    if not output.reconstruction or not output.machine_pseudoc:
        return output
    from dataclasses import replace
    from .microcode import lift_function
    from .reconstruct import reconstruct_function
    try:
        lifted = lift_function(snapshot, architecture, max_instructions=max_instructions)
        records = lifted["instructions"]
        if len(records) <= len(output.microcode):
            return output
        recovered = reconstruct_function(snapshot, architecture, microcode=records,
                                         max_instructions=max_instructions, max_chars=max_chars)
    except Exception:
        return output  # 只是扩大覆盖范围；失败时保留原结果
    if not recovered.pseudoc:
        return output
    # output.truncated：机器视图自身的截断（文本减半）；lifted/recovered：可读视图的截断。
    return replace(recovered, machine_pseudoc=output.machine_pseudoc,
                   truncated=output.truncated or bool(lifted["truncated"]) or recovered.truncated,
                   warnings=output.warnings + recovered.warnings)


def _copy_output(output: dict[str, Any], *, cached: bool) -> dict[str, Any]:
    # 调用方拿到独立副本：修改返回值不会污染缓存。
    copied = {**output, "warnings": list(output["warnings"]), "cached": cached}
    if "pseudoc_reconstruction" in copied:
        copied["pseudoc_reconstruction"] = deepcopy(copied["pseudoc_reconstruction"])
    return copied


# ---------------------------------------------------------------------------
# 模块级上下文缓存
# ---------------------------------------------------------------------------

_CONTEXTS: OrderedDict[int, PseudocContext] = OrderedDict()
_CONTEXTS_LOCK = threading.Lock()


def pseudoc_context(source: Any) -> PseudocContext:
    """按结果对象（身份）取得缓存的上下文；最多保留 MAX_CONTEXTS 个，最久未用的先淘汰。"""
    with _CONTEXTS_LOCK:
        context = _CONTEXTS.get(id(source))
        if context is not None and context.source is source:
            _CONTEXTS.move_to_end(id(source))
            return context
        context = PseudocContext(source)
        _CONTEXTS[id(source)] = context
        while len(_CONTEXTS) > MAX_CONTEXTS:
            _CONTEXTS.popitem(last=False)
        return context


def discard_pseudoc_context(source: Any) -> None:
    """释放某个结果对象的缓存上下文（例如关闭文件后）。"""
    with _CONTEXTS_LOCK:
        context = _CONTEXTS.get(id(source))
        if context is not None and context.source is source:
            del _CONTEXTS[id(source)]


def clear_pseudoc_contexts() -> None:
    with _CONTEXTS_LOCK:
        _CONTEXTS.clear()


def generate_function_pseudoc(source: Any, function: Any, *, address_space: str | None = None,
                              max_instructions: int | None = None, max_chars: int | None = None,
                              manager: Any = None, context: PseudocContext | None = None) -> dict[str, Any]:
    """为已完成结果中的任意函数按需生成伪 C。

    source：AnalysisResult、AnalysisView 或分析快照字典；function：函数记录或起点地址。
    context：调用方自行持有的 PseudocContext（必须属于同一 source）；默认使用模块级缓存。
    返回 {"address", "address_space", "name", "pseudoc", "pseudoc_producer", "pseudoc_truncated",
    "machine_pseudoc", "pseudoc_style", "pseudoc_reconstruction", "warnings", "max_instructions",
    "max_chars", "on_demand": True, "cached"}；不修改 source。
    """
    if context is None:
        context = pseudoc_context(source)
    elif context.source is not source:
        raise ValueError("context belongs to a different analysis result")
    return context.generate(function, address_space=address_space, max_instructions=max_instructions,
                            max_chars=max_chars, manager=manager)


__all__ = ["DEFAULT_MAX_INSTRUCTIONS", "MAX_ON_DEMAND_INSTRUCTIONS", "PseudocContext", "clear_pseudoc_contexts",
           "discard_pseudoc_context", "generate_function_pseudoc", "pseudoc_context"]
