"""伪代码与微码工具：读取已保存的伪 C、类型化语义 IR 与事实，化简独立的微表达式。

只投影已有快照，不重新解码源文件；伪代码插件按需延迟导入。参数校验顺序、错误文本
与返回结构和拆分前逐字一致，异常由 McpServer.call_tool 统一转换为工具错误。

get_pseudoc 新增可选参数 generate（默认 false，行为不变）与 max_instructions：generate 为 true
时，对没有已保存伪 C 的函数用伪 C 插件按需生成（只消费已完成快照，不解码、不写数据库），
结果在本会话内按句柄缓存；同时给出 max_instructions 时，能按需生成的函数（原生架构、带指令）
总是按该上限生成，不能按需生成时（dex/jvm 等）回退到已保存的伪 C。
"""
from __future__ import annotations

from typing import Any

from . import _facade


def _has_instructions(function: dict[str, Any]) -> bool:
    """函数带已完成的指令快照（与按需生成、流水线判断“带指令函数”的规则相同）。"""
    cfg = function.get("cfg")
    return bool(function.get("blocks") or function.get("disassembly") or
                (cfg.get("blocks") if isinstance(cfg, dict) else None))


class PseudocToolsMixin:
    """伪代码/微码相关工具；依赖宿主 McpServer 的 _snapshot/_pagination 方法。"""

    def _tool_simplify_micro_expression(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        from ..plugins.pseudoc.microcode import Expression, simplify_expression
        expression = arguments.get("expression")
        if not isinstance(expression, dict):
            raise ValueError("expression must be a micro-expression object")
        result = simplify_expression(Expression.from_dict(expression))
        return _facade()._result({"expression": result.to_dict(), "microcode_version": "1.0",
                                  "scope": "fixed_width_bitvector", "assembly_execution": False})

    def _tool_get_pseudoc(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        snapshot = self._snapshot(arguments)
        address = m._address(arguments["address"]) if "address" in arguments else None
        style = arguments.get("style")
        if style not in {None, "readable", "machine"}:
            raise ValueError("style must be readable or machine")
        source, space = arguments.get("source"), arguments.get("address_space")
        if source is not None and not isinstance(source, str):
            raise ValueError("source must be a string")
        if space is not None and (not isinstance(space, str) or not space):
            raise ValueError("address_space must be a non-empty string")
        if space is not None:
            space = m._CFG_SPACE_ALIASES.get(space, space)
        # 新增的可选参数在原有校验之后检查：旧调用的错误顺序与文本不变。
        generate = arguments.get("generate", False)
        if type(generate) is not bool:
            raise ValueError("generate must be boolean")
        limit = arguments.get("max_instructions")
        if limit is not None and (type(limit) is not int or not 1 <= limit <= 8192):
            raise ValueError("max_instructions must be an integer between 1 and 8192")
        candidates = []
        for function in snapshot.get("functions", []):
            if not isinstance(function, dict):
                continue
            context = m._cfg_context(function, snapshot.get("kind", ""))
            if ((source is not None and context[0] != source) or
                    (space is not None and context[1] != space)):
                continue
            exact = address is None or address in [
                m._record_address(function, key) for key in ("address", "start", "code_offset", "addr")]
            if not exact:
                listing = function.get("disassembly", [])
                blocks = function.get("blocks") or function.get("cfg", {}).get("blocks", [])
                rows = (row for block in blocks for row in block.get("instructions", [])) if blocks else iter(listing)
                if not any(isinstance(row, dict) and isinstance(row.get("addr"), int) and
                    isinstance(row.get("size"), int) and row["addr"] <= address < row["addr"] + row["size"] for row in rows):
                    continue
            candidates.append((not exact, function))
        # Exact starts retain legacy priority; interior lookup only uses
        # instruction spans that were actually decoded in this context.
        ordered = [function for _, function in sorted(candidates, key=lambda item: item[0])]
        # generate 且显式给出 max_instructions：能按需生成时（原生架构、函数带指令）按请求的上限
        # 重新生成，不取已保存的伪 C；不能重新生成时（dex/jvm 等非原生结果、没有指令的函数）
        # 回退到已保存的伪 C，与不给 max_instructions 时相同。
        regenerate = generate and limit is not None and self._can_generate_pseudoc(snapshot)
        for function in ordered:
            if regenerate and _has_instructions(function):
                return self._generated_pseudoc(arguments["handle"], snapshot, function, style, limit)
            pseudoc = function.get("pseudoc") or function.get("pseudo_c")
            reconstruction = function.get("pseudoc_reconstruction", {})
            truncated = function.get("pseudoc_truncated", False)
            if style == "machine":
                pseudoc = function.get("machine_pseudoc") or (pseudoc if function.get("pseudoc_style") != "readable" and function.get("pseudoc_producer") == "fangida_native_pseudoc" else None)
            elif style == "readable" and function.get("microcode") and function.get("pseudoc_style") != "readable" and function.get("pseudoc_producer") == "fangida_native_pseudoc":
                from ..plugins.pseudoc.reconstruct import reconstruct_function
                recovered = reconstruct_function(function, snapshot.get("metadata", {}).get("architecture", "unknown"),
                    microcode=function["microcode"], context={"kind": snapshot.get("kind", "")})
                pseudoc, reconstruction = recovered.pseudoc, recovered.reconstruction
                truncated = truncated or recovered.truncated
            if isinstance(pseudoc, str) and pseudoc:
                return m._result({"available": True, "address": m._record_address(function, "start", "address", "code_offset", "addr"),
                                  "pseudoc": pseudoc,
                                  "producer": function.get("pseudoc_producer", "analyzer"),
                                  "style": style or function.get("pseudoc_style", "legacy"),
                                  "reconstruction": reconstruction,
                                  "truncated": truncated})
        if generate:
            for function in ordered:
                if _has_instructions(function):
                    return self._generated_pseudoc(arguments["handle"], snapshot, function, style, limit)
        return m._tool_error("Pseudo-C is unavailable for this analysis result")

    @staticmethod
    def _can_generate_pseudoc(snapshot: dict[str, Any]) -> bool:
        """快照的架构支持按需生成原生伪 C（与伪 C 插件的 NATIVE_ARCHITECTURES 相同）。"""
        from ..plugins.pseudoc.pipeline import NATIVE_ARCHITECTURES
        metadata = snapshot.get("metadata")
        return isinstance(metadata, dict) and metadata.get("architecture") in NATIVE_ARCHITECTURES

    def _pseudoc_contexts_for_session(self) -> dict[str, Any]:
        contexts = getattr(self, "_pseudoc_contexts", None)
        if contexts is None:
            contexts = self._pseudoc_contexts = {}
        # 顺带清掉已关闭句柄的上下文：缓存不会比打开的结果活得更久。
        for stale in tuple(contexts):
            if stale not in self._snapshots:
                contexts.pop(stale, None)
        return contexts

    def _generated_pseudoc(self, handle: str, snapshot: dict[str, Any], function: dict[str, Any],
                           style: str | None, limit: int | None) -> dict[str, Any]:
        """按需生成一个函数的伪 C；上下文与结果按句柄缓存在本会话内，不写回快照或数据库。"""
        m = _facade()
        from ..plugins.pseudoc.on_demand import PseudocContext
        contexts = self._pseudoc_contexts_for_session()
        context = contexts.get(handle)
        if context is None or context.source is not snapshot:
            context = contexts[handle] = PseudocContext(snapshot)
        if limit is None:
            limit = getattr(self.settings, "pseudoc_max_instructions", 512)
        generated = context.generate(function, max_instructions=limit)
        pseudoc = generated["pseudoc"]
        if style == "machine":
            pseudoc = generated.get("machine_pseudoc") or (pseudoc if generated.get("pseudoc_style") != "readable" else None)
        if not isinstance(pseudoc, str) or not pseudoc:
            return m._tool_error("Pseudo-C is unavailable for this analysis result")
        return m._result({"available": True, "address": m._record_address(function, "start", "address", "code_offset", "addr"),
                          "pseudoc": pseudoc, "producer": generated["pseudoc_producer"],
                          "style": style or generated.get("pseudoc_style", "legacy"),
                          "reconstruction": generated.get("pseudoc_reconstruction", {}),
                          "truncated": generated["pseudoc_truncated"],
                          # 新增字段：标明按需生成、是否命中会话缓存及使用的指令上限。
                          "generated": True, "cached": generated["cached"],
                          "max_instructions": generated["max_instructions"],
                          "warnings": generated["warnings"]})

    def _tool_get_microcode(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        snapshot = self._snapshot(arguments)
        from ..plugins.pseudoc.snapshot import microcode_page
        offset, limit = self._pagination(arguments)
        return m._result(microcode_page(snapshot, m._address(arguments.get("address")),
            offset=offset, limit=limit, source=arguments.get("source"),
            address_space=arguments.get("address_space"), category=arguments.get("category")))

    def _tool_get_microcode_facts(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        m = _facade()
        snapshot = self._snapshot(arguments)
        from ..plugins.pseudoc.snapshot import microcode_facts_page
        offset, limit = self._pagination(arguments)
        return m._result(microcode_facts_page(snapshot, m._address(arguments.get("address")),
            offset=offset, limit=limit, source=arguments.get("source"),
            address_space=arguments.get("address_space"), kind=arguments.get("kind")))
