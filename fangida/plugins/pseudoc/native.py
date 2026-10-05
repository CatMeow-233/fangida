"""Bounded native pseudo-C lifting, driven exclusively by completed IR/CFG.

Registers and flags stay explicit across blocks. No ABI, argument list,
source-level type or indirect target is guessed. Memory/flag/opaque helpers
describe machine semantics; this is not a source-level decompiler.
"""
from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from itertools import islice
from typing import Any

from .models import PseudocodeResult, validate_limits
from .native_operands import Operands, identifier, split_operands


from .microcode.conditions import X86_CONDITIONS, ARM_CONDITIONS
from .microcode.control_flow import branch_condition
from .microcode.ir import MICROCODE_VERSION
from .microcode.registry import DEFAULT_LIFTERS


def _snapshot(function: Mapping[str, Any], limit: int) -> tuple[list[Mapping[str, Any]], bool]:
    blocks = function.get("blocks") or function.get("cfg", {}).get("blocks", ())
    stream = (row for block in blocks for row in block.get("instructions", ())) if blocks else iter(function.get("disassembly", ()))
    rows, seen = [], set()
    for scanned, row in enumerate(stream):
        if scanned >= limit * 8:
            return sorted(rows, key=lambda row: row["addr"]), True
        if (not isinstance(row, Mapping) or type(row.get("addr")) is not int or
                type(row.get("size")) is not int or row["size"] <= 0):
            continue
        if row["addr"] in seen:
            continue
        if len(rows) == limit:
            return sorted(rows, key=lambda row: row["addr"]), True
        seen.add(row["addr"])
        rows.append(row)
    return sorted(rows, key=lambda row: row["addr"]), False


def _noreturn_sites(function: Mapping[str, Any]) -> dict[int, Mapping[str, Any]]:
    """核心 CFG 记录的不返回调用点：{调用指令地址: 记录}。

    只收落空边确实被截断的记录；fallthrough_trap=True 的调用其后紧跟陷阱指令，
    核心保留了那条边（陷阱本身就是终点），这里也照常落空到陷阱。
    """
    cfg = function.get("cfg")
    calls = cfg.get("noreturn_calls") if isinstance(cfg, Mapping) else None
    sites: dict[int, Mapping[str, Any]] = {}
    for item in calls or ():
        if isinstance(item, Mapping) and type(item.get("from")) is int and not item.get("fallthrough_trap"):
            sites[item["from"]] = item
    return sites


class _Renderer:
    def __init__(self, function: Mapping[str, Any], architecture: str, rows: list[Mapping[str, Any]]):
        self.function, self.architecture, self.rows = function, architecture, rows
        self.noreturn_sites = _noreturn_sites(function)
        self.addresses = {row["addr"] for row in rows}
        self.registers: set[str] = set()
        self.bits = 64 if architecture in {"x86_64", "arm64"} else 32
        self.return_register = {"x86_64": "rax", "x86": "eax", "arm64": "x0", "arm": "r0"}[architecture]
        self.flags = False
        self.comparison_origin = None
        self.vector_registers: set[str] = set()
        self.fp_environment = False
        self.microcode: list[dict[str, Any]] = []
        self.incomplete = False
        self.opaque = 0

    def transfer(self, target: int | None, kind: str = "jump") -> str:
        if target in self.addresses:
            return f"goto L_{target:x};"
        self.incomplete = True
        value = hex(target) if isinstance(target, int) else "symbolic_target()"
        return f"return unresolved_{kind}({value}); /* outside instruction snapshot */"

    def condition(self, mnemonic: str, operands: list[str], op: Operands) -> str:
        return branch_condition(self, mnemonic, operands, op)[0]

    def statement(self, row: Mapping[str, Any]) -> list[str]:
        op = Operands(self.architecture, row, self.registers)
        self.current_operands = op
        result = DEFAULT_LIFTERS.lift(self, row, split_operands(row), op)
        self.microcode.append(result.to_dict())
        return list(result.statements)

    def render(self, truncated: bool) -> str:
        lines = []
        entry = self.function.get("start")
        labels = {self.rows[0]["addr"], entry}
        for index, row in enumerate(self.rows):
            branch = row.get("branch_info") or {}
            if branch.get("kind") == "jump":
                labels.add(branch.get("target"))
                if branch.get("conditional"):
                    labels.add(row["addr"] + row["size"])
            elif index + 1 < len(self.rows) and (self.rows[index + 1]["addr"] != row["addr"] + row["size"]
                                                  or row["addr"] in self.noreturn_sites):
                # 不返回调用之后的相邻指令只能经其它边到达：加标签，也切断词法上的标志来源。
                labels.add(row["addr"] + row["size"])
        if isinstance(entry, int) and entry not in self.addresses:
            self.incomplete = True
            lines.append(f"  return unresolved_entry({hex(entry)}); /* entry omitted */")
        if entry in self.addresses and entry != self.rows[0]["addr"]:
            lines.append(f"  goto L_{entry:x};")
        for index, row in enumerate(self.rows):
            lines.append((f"L_{row['addr']:x}:" if row["addr"] in labels else " ") + f" /* 0x{row['addr']:x} */")
            if row["addr"] in labels:
                self.comparison_origin = None  # A join/entry cannot inherit lexical predecessor flags.
            try:
                statements = self.statement(row)
            except (ValueError, TypeError, KeyError):
                self.opaque += 1
                raw = str(row.get("mnemonic", "unknown")) + " " + ", ".join(split_operands(row))
                statements = [f"asm_opaque({json.dumps(raw[:256], ensure_ascii=True)}); /* effects symbolic */"]
                if (row.get("branch_info") or {}).get("kind") in {"call", "jump"}:
                    self.incomplete = True
                    statements.append("return unresolved_control_flow();")
            lines.extend("  " + statement for statement in statements)
            kind = (row.get("branch_info") or {}).get("kind")
            site = self.noreturn_sites.get(row["addr"]) if kind == "call" else None
            if site is not None:
                # 调用不返回：明确写出终点，C 里也不会词法落空到下一条指令。
                name = json.dumps(str(site.get("name") or "callee")[:80]).replace("*/", "* /")
                evidence = json.dumps(str(site.get("evidence") or "noreturn")[:40]).replace("*/", "* /")
                lines.append(f"  __builtin_unreachable(); /* call does not return: {name}, evidence {evidence} */")
            elif kind not in {"jump", "return", "trap"} and (
                    index + 1 == len(self.rows) or self.rows[index + 1]["addr"] != row["addr"] + row["size"]):
                lines.append("  " + self.transfer(row["addr"] + row["size"], "fallthrough"))
        frontier = self.function.get("cfg", {}).get("frontier", ())
        for item in islice(frontier, 16):
            # JSON escaping keeps source-provided frontier reasons inside a comment.
            reason = json.dumps(str(item.get("reason", "unresolved"))[:80]).replace("*/", "* /")
            lines.append(f"  /* CFG frontier: {reason} */")
        if truncated or self.incomplete:
            lines.append("  /* Partial instruction snapshot; remaining control flow unresolved. */")
        name = identifier(self.function.get("name", f"sub_{entry:x}" if isinstance(entry, int) else "function"))
        declarations = [f'  uint{self.bits}_t {reg} = symbolic_input("{reg}");' for reg in sorted(self.registers)]
        declarations.extend(f'  vector128_t {reg} = symbolic_vector_input("{reg}");' for reg in sorted(self.vector_registers))
        if self.fp_environment:
            declarations.append("  fp_environment_t fp_environment = symbolic_fp_environment();")
        if self.flags:
            declarations.append("  flags_t flags = symbolic_flags();")
        return "\n".join(["// IR-derived pseudo-C; registers, memory helpers and ABI inputs are symbolic.",
            f"uint{self.bits}_t {name}(/* ABI arguments symbolic */) {{", *declarations, *lines, "}"])


_NATIVE_ARCHITECTURES = frozenset({"x86", "x86_64", "arm", "arm64"})
# 内置语义处理器的注册名（registry.py 中按此顺序注册）。注册名唯一且没有注销
# 接口，所以名单完全一致就说明没有第三方处理器参与，渲染只取决于下列输入。
_BUILTIN_LIFTERS = ("control_flow", "comparison", "data_transfer", "integer_arithmetic",
                    "bitwise", "memory", "stack", "floating_point", "system")
_MISSING = object()


@dataclass(frozen=True, eq=False)
class _Rendering:
    """一次“全部行”渲染（未减半）的结果及其全部决定性输入。

    _Renderer 的输出只取决于：架构、行对象序列、function 的 start、name、
    cfg.frontier、pseudoc_symbols（只影响调用语句文本）以及 truncated 实参
    （只影响末尾的“部分快照”注释行）。微码、incomplete 与 opaque 与
    pseudoc_symbols / truncated 无关：内置处理器只在 control_flow 的调用语句
    文本里读取 function["pseudoc_symbols"]，LiftedInstruction.to_dict 不含语句。
    """
    architecture: str
    rows: tuple[Mapping[str, Any], ...]  # 持有行对象引用，键中的 id 在备忘录存活期间不会被复用
    entry: Any
    name: Any
    frontier: Any
    symbols: Any
    truncated: bool
    microcode: tuple[dict[str, Any], ...]
    incomplete: bool
    opaque: int


def _render_inputs(function: Mapping[str, Any]) -> tuple[Any, Any, Any, Any]:
    # 与 _Renderer.render / 内置调用处理器读取的字段完全一致。
    return (function.get("start"), function.get("name", _MISSING),
            function.get("cfg", {}).get("frontier", ()), function.get("pseudoc_symbols", _MISSING))


def _same(left: Any, right: Any) -> bool:
    # 不可变标量按“类型 + 值”比较；容器只认同一对象（作用域内无人原地修改快照）。
    if left is right:
        return True
    return type(left) is type(right) and type(left) in (str, int, bool) and left == right


class _RenderMemo:
    """单次 populate_native_pseudoc 调用内有效的完整渲染备忘录。

    只经由 ContextVar 暴露给当前调用（当前线程/上下文），调用结束即丢弃，
    不是进程全局缓存，也不会把一次请求的结果带进另一次请求。
    """
    MAX_ENTRIES = 1024

    def __init__(self) -> None:
        self._entries: dict[tuple[str, tuple[int, ...]], _Rendering] = {}
        self._texts: dict[tuple[str, tuple[int, ...]], str] = {}

    @staticmethod
    def _key(architecture: str, rows: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...]) -> tuple[str, tuple[int, ...]]:
        return architecture, tuple(map(id, rows))

    def find(self, function: Mapping[str, Any], architecture: str, rows: list[Mapping[str, Any]], *,
             truncated: bool | None = None) -> tuple[_Rendering, str | None] | None:
        """truncated 为 None 时只要求微码等价；否则还要求文本输入完全一致并取走文本。"""
        if DEFAULT_LIFTERS.names() != _BUILTIN_LIFTERS:
            return None
        key = self._key(architecture, rows)
        entry = self._entries.get(key)
        if entry is None:
            return None
        start, name, frontier, symbols = _render_inputs(function)
        if not (_same(start, entry.entry) and _same(name, entry.name) and _same(frontier, entry.frontier)):
            return None
        if truncated is None:
            return entry, None
        if symbols is not entry.symbols or truncated is not entry.truncated or key not in self._texts:
            return None
        # 文本只会被 generate 的首次渲染消费一次；取走后释放，降低峰值内存。
        return entry, self._texts.pop(key)

    def store(self, rendering: _Rendering, text: str | None) -> None:
        """登记一次完整渲染；text 为 None 表示只保留微码（文本已被调用方直接使用）。"""
        if DEFAULT_LIFTERS.names() != _BUILTIN_LIFTERS:
            return
        key = self._key(rendering.architecture, rendering.rows)
        if key not in self._entries and len(self._entries) >= self.MAX_ENTRIES:
            return
        self._entries[key] = rendering
        # 文本与条目必须成对更新，不能让旧条目的文本配上新条目的校验输入。
        if text is None:
            self._texts.pop(key, None)
        else:
            self._texts[key] = text


_ACTIVE_MEMO: ContextVar[_RenderMemo | None] = ContextVar("fangida_native_render_memo", default=None)


@contextmanager
def _render_scope() -> Iterator[_RenderMemo]:
    """在一次流水线调用内启用渲染备忘录；退出时恢复上一层状态。"""
    memo = _RenderMemo()
    token = _ACTIVE_MEMO.set(memo)
    try:
        yield memo
    finally:
        _ACTIVE_MEMO.reset(token)


def _complete_render(function: Mapping[str, Any], architecture: str, rows: list[Mapping[str, Any]],
                     truncated: bool, *, keep_text: bool = False) -> tuple[_Rendering, str]:
    """渲染全部行；仅在流水线作用域内并且全部输入相同时复用已有渲染。

    keep_text 只由预渲染使用：文本留给随后 generate 的首次渲染消费一次。
    """
    memo = _ACTIVE_MEMO.get()
    if memo is not None:
        try:
            hit = memo.find(function, architecture, rows, truncated=truncated)
        except Exception:
            hit = None  # 输入异常时交给真实渲染抛出与原实现相同的错误。
        if hit is not None:
            return hit
    renderer = _Renderer(function, architecture, rows)
    text = renderer.render(truncated)
    start, name, frontier, symbols = _render_inputs(function)
    rendering = _Rendering(architecture, tuple(rows), start, name, frontier, symbols, truncated,
                           tuple(renderer.microcode), renderer.incomplete, renderer.opaque)
    if memo is not None:
        memo.store(rendering, text if keep_text else None)
    return rendering, text


def _first_render_inputs(function: Mapping[str, Any], max_instructions: int
                         ) -> tuple[list[Mapping[str, Any]], bool, bool]:
    # 与 PluginImpl.generate 首次渲染的输入计算逐字相同。
    rows, limited = _snapshot(function, max_instructions)
    cfg = function.get("cfg", {})
    truncated = limited or bool(cfg.get("frontier")) or cfg.get("complete") is False
    return rows, limited, truncated


def _prime_render(function: Mapping[str, Any], architecture: str, *, max_instructions: int = 512) -> bool:
    """流水线预渲染：产生与 generate 首次渲染完全相同的结果并登记到备忘录。"""
    if _ACTIVE_MEMO.get() is None or architecture not in _NATIVE_ARCHITECTURES:
        return False
    validate_limits(max_instructions, 32768)
    rows, _, truncated = _first_render_inputs(function, max_instructions)
    if not rows:
        return False
    _complete_render(function, architecture, rows, truncated, keep_text=True)
    return True


def _memo_lift(function: Mapping[str, Any], architecture: str,
               max_instructions: int = 512) -> dict[str, Any] | None:
    """与 microcode.lift_function 返回值逐字段相同；无可证明等价的渲染时返回 None。"""
    memo = _ACTIVE_MEMO.get()
    if (memo is None or architecture not in _NATIVE_ARCHITECTURES or
            type(max_instructions) is not int or not 1 <= max_instructions <= 8192):
        return None  # 参数非法或未命中时由 lift_function 给出原有行为与错误。
    try:
        rows, limited = _snapshot(function, max_instructions)
        if not rows:
            return None
        hit = memo.find(function, architecture, rows)
        if hit is None:
            return None
        rendering = hit[0]
        cfg = function.get("cfg", {})
        truncated = (limited or rendering.incomplete or bool(cfg.get("frontier")) or
                     cfg.get("complete") is False)
    except Exception:
        return None  # 仅放弃复用加速路径；调用方回退 lift_function，给出原实现的结果或错误。
    return {"instructions": list(rendering.microcode), "truncated": truncated,
            "microcode_version": MICROCODE_VERSION}


class PluginImpl:
    name = "native_pseudoc"
    version = "0.4.0"

    def capabilities(self) -> tuple[str, ...]:
        return ("x86", "x86_64", "arm", "arm64", "native_pseudoc", "snapshot_only")

    def generate(self, function: Mapping[str, Any], architecture: str, *,
                 max_instructions: int = 512, max_chars: int = 32768) -> PseudocodeResult:
        validate_limits(max_instructions, max_chars)
        if architecture not in {"x86", "x86_64", "arm", "arm64"}:
            return PseudocodeResult(warnings=(f"Native pseudo-C unavailable for {architecture}",))
        rows, limited = _snapshot(function, max_instructions)
        if not rows:
            return PseudocodeResult(warnings=("No native instruction snapshot",))
        cfg = function.get("cfg", {})
        truncated = limited or bool(cfg.get("frontier")) or cfg.get("complete") is False
        # 首次（全部行）渲染：流水线作用域内可复用预渲染结果，其余行为不变。
        first, text = _complete_render(function, architecture, rows, truncated)
        if len(text) <= max_chars:
            warnings = (f"{first.opaque} instruction semantics retained as opaque operations",) if first.opaque else ()
            return PseudocodeResult(text, "fangida_native_pseudoc", truncated or first.incomplete, warnings, first.microcode)
        rows = rows[:len(rows) // 2]
        truncated = True
        while rows:
            renderer = _Renderer(function, architecture, rows)
            text = renderer.render(truncated)
            if len(text) <= max_chars:
                warnings = (f"{renderer.opaque} instruction semantics retained as opaque operations",) if renderer.opaque else ()
                return PseudocodeResult(text, "fangida_native_pseudoc", truncated or renderer.incomplete, warnings, tuple(renderer.microcode))
            rows = rows[:len(rows) // 2]
            truncated = True
        # The minimum character budget still yields a complete, honest outline.
        name = identifier(function.get("name", "function"))
        text = f"uint{64 if architecture in {'x86_64', 'arm64'} else 32}_t {name}() {{\n  /* Pseudo-C size limit reached; instructions omitted. */\n}}"
        return PseudocodeResult(text, "fangida_native_pseudoc", True)

    def teardown(self) -> None:
        pass
