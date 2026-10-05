"""Native executable metadata and bounded multi-function semantic analysis."""
from __future__ import annotations
import os
import re
from pathlib import Path
from threading import Event
from typing import Any, Callable
from ..._gc import bulk_allocation
from ...models import AnalysisResult, AnalysisTask, Xref
from ...xrefs import XrefStage, direct_references, index_entry_references
from .binary import BinaryFormatError, parse_binary
from .cfg import build_entry_cfg
from .noreturn import named_targets
from .symbols import parse_symbols
from .semantic import analyze_semantics
from .translator import disassemble_entry
from .strings import MAX_STRING_BYTES, scan_native_strings

MAX_SCAN_BYTES = 32 * 1024 * 1024

def _preview_result(result: AnalysisResult, instructions: list[dict[str, Any]],
                    coverage: list[dict[str, Any]],
                    functions: list[dict[str, Any]] | None = None) -> AnalysisResult:
    """完整分析解码完成时的只读预览：区段、符号、字符串与全部指令，函数尚无 CFG。

    指令列表与最终结果共享（解码完成后只读）；其余列表与字典是浅拷贝，
    之后的函数恢复、CFG、xref 与伪 C 只修改最终结果，不影响已交出的预览。
    """
    metadata = {**result.metadata, "full_disassembly": instructions,
                "full_analysis": {"enabled": True, "preview": True,
                                  "scope": "all_file_backed_executable_regions",
                                  "instruction_count": len(instructions), "regions": coverage,
                                  "function_recovery_complete": False, "cfg_pass_complete": False,
                                  "xref_pass_complete": False}}
    stats = {**result.stats, "full_analysis": True, "full_preview": True,
             "full_instructions": len(instructions)}
    return AnalysisResult(result.path, result.kind, result.analyzer, "partial",
                          metadata=metadata,
                          functions=([{**item, "analysis_scope": "preview_declared_root"} for item in functions]
                                     if functions is not None else [dict(item) for item in result.functions]),
                          strings=list(result.strings), imports=list(result.imports),
                          exports=list(result.exports), xrefs=list(result.xrefs), stats=stats,
                          warnings=[*result.warnings, "预览：反汇编已完成；函数恢复、CFG、交叉引用和伪代码仍在进行"])


class PluginImpl:
    name = "kkagent"
    version = "0.4.0"

    def capabilities(self) -> tuple[str, ...]:
        return ("metadata", "sections", "entry_disassembly", "entry_cfg", "elf_symbols",
                "pe_imports_exports", "elf_dynamic_symbols", "direct_xrefs", "strings",
                "bounded_semantics", "optional_ghidra", "full_code_regions", "pseudoc")

    def analyze(self, task: AnalysisTask) -> AnalysisResult:
        return self.analyze_with_control(task)

    def analyze_with_control(self, task: AnalysisTask,
                             on_progress: Callable[[dict[str, Any]], None] | None = None,
                             cancel: Event | None = None,
                             on_preview: Callable[[AnalysisResult], None] | None = None) -> AnalysisResult:
        """on_preview（可选）：完整分析解码完成后收到一次只读的部分结果，用于渐进式显示。"""
        separate = task.semantic_threads > 1 or bool(task.xref_threads)
        # 整个原生分析期间暂停自动循环 GC：结果对象全部长期存活，反复全代扫描只会拖慢分析。
        with bulk_allocation(), XrefStage(separate_thread=separate) as xref_stage:
            return self._analyze_with_stages(task, on_progress, cancel, xref_stage, on_preview)

    def _analyze_with_stages(self, task: AnalysisTask,
                             on_progress: Callable[[dict[str, Any]], None] | None,
                             cancel: Event | None, xref_stage: XrefStage,
                             on_preview: Callable[[AnalysisResult], None] | None = None) -> AnalysisResult:
        result = AnalysisResult(task.path, task.kind, self.name, "partial")
        def emit(stage: str, **details: Any) -> None:
            if on_progress is not None:
                try:
                    on_progress({"stage": stage, **details})
                except Exception as exc:
                    result.warnings.append(f"Progress callback failed: {type(exc).__name__}: {exc}")

        def cancelled() -> bool:
            return cancel is not None and cancel.is_set()

        if cancelled():
            result.stats["cancelled"] = True
            result.warnings.append("Native analysis cancelled before scan")
            return result
        try:
            if type(task.full_analysis) is not bool:
                raise ValueError("full_analysis must be boolean")
            if task.xref_threads is not None and (
                    type(task.xref_threads) is not int or task.xref_threads not in (0, 1)):
                raise ValueError("xref_threads must be 0, 1 or None")
            size = Path(task.path).stat().st_size
            scan_budget = (max(0, task.max_bytes) if task.full_analysis else
                           min(max(0, task.max_bytes), MAX_SCAN_BYTES))
            with open(task.path, "rb") as stream:
                data = stream.read(scan_budget)
            emit("native_scan", scanned_bytes=len(data), size_bytes=size)
            result.metadata.update(size_bytes=size, scanned_bytes=len(data), preview_hex=data[:64].hex())
            if not task.full_analysis and task.max_bytes > MAX_SCAN_BYTES:
                result.warnings.append(f"Native scan capped at {MAX_SCAN_BYTES} bytes")
            if size > len(data):
                result.warnings.append("Scan truncated at max_bytes")
            try:
                image = parse_binary(data, task.kind)
            except BinaryFormatError as exc:
                result.warnings.append(f"Native container metadata unavailable: {exc}")
                result.strings, result.metadata["string_scan"] = scan_native_strings(
                    data, full_analysis=task.full_analysis)
            else:
                result.metadata.update(image.metadata())
                result.strings, result.metadata["string_scan"] = scan_native_strings(
                    data, image, full_analysis=task.full_analysis)
                result.functions = ([dict(item) for item in image.functions]
                                    if task.full_analysis else image.functions)
                result.warnings.extend(image.warnings)
                result.imports, result.exports, symbol_warnings = parse_symbols(data, image)
                result.warnings.extend(symbol_warnings)
                result.stats["imports"] = len(result.imports)
                result.stats["exports"] = len(result.exports)
                instructions, warnings = disassemble_entry(data, image)
                result.metadata["disassembly"] = instructions
                result.warnings.extend(warnings)
                result.stats["entry_instructions"] = len(instructions)
                # 入口窗口只接入不需要引用的不返回证据：本地函数符号的已知名单。
                graph, reached = build_entry_cfg(instructions, image.entry_address,
                                                 named_targets(image.functions, image.format))
                entry_functions: list[dict] = []
                if graph is not None:
                    result.metadata["entry_cfg"] = graph
                    entry_functions = [item for item in result.functions if item.get("start") == image.entry_address]
                    if not entry_functions:
                        window = {"name": f"entry_window_{image.entry_address:x}",
                                  "start": image.entry_address, "size": None, "source": "entry_window",
                                  "boundary_known": False, "blocks": [], "cfg": {},
                                  "xrefs_in": [], "xrefs_out": []}
                        result.functions.append(window)
                        entry_functions = [window]
                    for function in entry_functions:
                        function["blocks"] = graph["blocks"]
                        function["cfg"] = {key: value for key, value in graph.items() if key != "blocks"}
                        function["analysis_scope"] = "bounded_entry_window"
                    result.stats["entry_cfg_blocks"] = len(graph["blocks"])
                    result.stats["entry_cfg_frontier"] = len(graph["frontier"])
                result.xrefs = xref_stage.run(direct_references, tuple(instructions),
                                              None if graph is None else reached.copy(),
                                              include_data=True,
                                              data_ranges=tuple((address, address + length)
                                                  for item in result.strings
                                                  for address, length in item.get("data_ranges", ())))
                result.stats["entry_direct_xrefs"] = len(result.xrefs)
                xref_stage.run(index_entry_references, result.functions, entry_functions,
                               tuple(result.xrefs))
                if instructions:
                    result.warnings.append("Entry CFG and entry disassembly cover only a bounded entry window")
                if task.full_analysis and not cancelled():
                    from .full_analysis import analyze_full
                    preview_options = {}
                    if on_preview is not None:
                        def decoded(instructions: list[dict], coverage: list[dict],
                                    functions: list[dict]) -> None:
                            on_preview(_preview_result(result, instructions, coverage, functions))
                            emit("native_preview", instruction_count=len(instructions))
                        preview_options["on_decoded"] = decoded
                    full_functions, full_xrefs, full_stats, full_metadata, full_warnings = analyze_full(
                        data, image, workers=task.semantic_threads, xref_stage=xref_stage,
                        is_cancelled=cancelled if cancel is not None else None,
                        imports=result.imports,
                        on_progress=(lambda event: emit("native_full", full_stage=event.get("stage"),
                                                       **{k: v for k, v in event.items() if k != "stage"}))
                        if on_progress is not None else None, **preview_options)
                    result.functions, result.xrefs = full_functions, full_xrefs
                    result.stats.update(full_stats)
                    result.metadata.update(full_metadata)
                    result.metadata["full_analysis"]["input_truncated"] = size > len(data)
                    if size > len(data):
                        result.stats["full_decode_complete"] = False
                        result.metadata["full_analysis"]["decode_complete"] = False
                    result.warnings.extend(full_warnings)
                elif task.deep_analysis and not cancelled():
                    semantic_functions, semantic_xrefs, semantic_stats, semantic_warnings = analyze_semantics(
                        data, image, max_functions=task.semantic_max_functions,
                        max_instructions=task.semantic_max_instructions,
                        max_workers=task.semantic_threads,
                        is_cancelled=cancelled if cancel is not None else None,
                        on_progress=(lambda event: emit("native_semantic", **event))
                        if on_progress is not None else None, xref_stage=xref_stage,
                        imports=result.imports)
                    analyzed = {item["start"] for item in semantic_functions}
                    result.functions = semantic_functions + [item for item in image.functions
                                                              if item["start"] not in analyzed]
                    result.xrefs = semantic_xrefs
                    result.stats.update(semantic_stats)
                    result.warnings.extend(semantic_warnings)
            if not cancelled() and (library_path := os.environ.get("FANGIDA_NATIVE_LIB")):
                try:
                    from ...native_bridge import NativeBridge
                    result.metadata["native_summary"] = NativeBridge(library_path).analyze(data)
                except Exception as exc:
                    result.warnings.append(f"Optional native scan unavailable: {type(exc).__name__}: {exc}")
            if task.use_ghidra and not cancelled():
                try:
                    from .ghidra_bridge import GhidraBridge
                    supplement = GhidraBridge.from_environment(
                        timeout_seconds=task.ghidra_timeout_seconds,
                        max_cpu=task.ghidra_max_cpu,
                        max_decompiled_functions=task.ghidra_decompiled_functions,
                        max_decompile_seconds=task.ghidra_decompile_seconds,
                    ).analyze(task.path)
                    xref_stage.run(_merge_ghidra, result, supplement)
                except Exception as exc:
                    result.warnings.append(f"Ghidra supplement unavailable: {type(exc).__name__}: {exc}")
            if not cancelled():
                from ...plugins.pseudoc.pipeline import populate_native_pseudoc
                populate_native_pseudoc(result, is_cancelled=cancelled,
                    on_progress=(lambda event: emit(event["stage"],
                        **{key: value for key, value in event.items() if key != "stage"}))
                    if on_progress is not None else None)
            if cancelled():
                result.stats["cancelled"] = True
                result.warnings.append("Native analysis cancelled; partial results retained")
            elif task.full_analysis:
                result.warnings.append("Full code-region mode does not guarantee exhaustive function recovery")
            elif task.deep_analysis:
                result.warnings.append("Semantic analysis is bounded; function recovery and data flow are incomplete")
            else:
                result.warnings.append("Deep semantic analysis disabled for this request")
        except Exception as exc:
            result.status = "error"
            result.warnings.append(f"Native scan failed: {type(exc).__name__}: {exc}")
        emit("done", status=result.status, cancelled=cancelled())
        return result

    def teardown(self) -> None:
        pass


def _merge_ghidra(result: AnalysisResult, supplement: object) -> None:
    """Adapt Ghidra's bounded memory references without discarding local evidence."""
    known = {(item.get("start"), item.get("address_space", "ram")): item
             for item in result.functions}
    for function in supplement.functions:
        key = (function["start"], function["address_space"])
        if key in known:
            known[key]["ghidra_name"] = function["name"]
        else:
            item = {**function, "source": "ghidra", "blocks": [], "cfg": {"edges": []}}
            result.functions.append(item)
            known[key] = item
    xref_keys = {(item["src"], item["dst"], item["kind"], item.get("src_space", "ram"),
                  item.get("dst_space", "ram")) for item in result.xrefs}
    for xref in supplement.xrefs:
        key = (xref["src"], xref["dst"], xref["kind"], xref["src_space"], xref["dst_space"])
        if key not in xref_keys:
            result.xrefs.append({**xref, "confidence": 1.0})
            xref_keys.add(key)
    decompiled = getattr(supplement, "decompiled_functions", [])
    for entry in decompiled:
        target = known.get((entry["start"], entry["address_space"]))
        if target is not None:
            target["pseudoc"] = entry["pseudoc"]
            target["pseudoc_producer"] = entry["producer"]
            target["pseudoc_truncated"] = entry["truncated"]
    result.metadata["ghidra"] = {"stats": supplement.stats, "pcode": supplement.pcode,
                                 "decompiled_count": len(decompiled)}
    result.warnings.extend(supplement.warnings)
    result.stats["ghidra_functions"] = len(supplement.functions)
    result.stats["ghidra_xrefs"] = len(supplement.xrefs)
    result.stats["ghidra_decompiled"] = len(decompiled)
