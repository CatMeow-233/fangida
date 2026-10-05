"""工具结果、分页、地址解析与快照摘要/CFG 投影辅助函数。

只读取已完成的分析快照，复制当前页而不重新解码；引用其它门面名字时经 _facade() 查找。
"""
from __future__ import annotations

import json
import re
from typing import Any

from . import _facade

_CFG_SPACE_ALIASES = {"ram": "native", "virtual": "native", "virtual_address": "native",
                      "fileoffset": "file_offset", "offset": "file_offset"}
_SUMMARY_WARNINGS = 100
_SUMMARY_TEXT = 2048


def _result(value: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}],
            "structuredContent": value}


def _tool_error(message: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _page(items: list[Any], offset: int, limit: int) -> dict[str, Any]:
    selected = items[offset:offset + limit]
    following = offset + len(selected)
    return {"items": selected, "total": len(items),
            "next_offset": following if following < len(items) else None}


def _address(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("address must be an integer or a hexadecimal string")
    if isinstance(value, int):
        address = value
    elif re.fullmatch(r"0[xX][0-9a-fA-F]+", value):
        address = int(value, 16)
    elif re.fullmatch(r"[0-9]+", value):
        address = int(value, 10)
    else:
        raise ValueError("address must be a non-negative integer or 0x-prefixed hex string")
    if address < 0:
        raise ValueError("address must be non-negative")
    return address


def _record_address(record: dict[str, Any], *keys: str) -> int | None:
    m = _facade()
    for key in keys:
        if record.get(key) is not None:
            try:
                return m._address(record[key])
            except ValueError:
                pass
    return None


def _cfg_context(function: dict[str, Any], kind: str) -> tuple[str, str]:
    """Compatibility facade for shared snapshot address contexts."""
    from ..snapshot_context import function_context
    return function_context(function, kind)


def _block_instruction_count(block: Any) -> int:
    if not isinstance(block, dict):
        return 0
    instructions = block.get("instructions")
    if isinstance(instructions, list):
        return len(instructions)
    count = block.get("instruction_count", 0)
    return count if type(count) is int and count >= 0 else 0


def _function_summary(function: Any, kind: str) -> Any:
    if not isinstance(function, dict):
        return None
    m = _facade()
    source, space = m._cfg_context(function, kind)
    summary = {key: function[key] for key in (
        "name", "start", "code_offset", "addr", "size", "kind", "class", "descriptor",
        "analysis_scope", "boundary_known", "boundary_scope", "noreturn", "noreturn_evidence") if key in function}
    summary.update(address=m._record_address(function, "start", "address", "code_offset", "addr"),
                   source=source, address_space=space)
    if function.get("source") and function["source"] != source:
        summary["symbol_source"] = function["source"]
    graph = function.get("cfg")
    graph = graph if isinstance(graph, dict) else {}
    blocks = function.get("blocks", graph.get("blocks", []))
    blocks = blocks if isinstance(blocks, list) else []
    summary["cfg"] = {key: graph[key] for key in ("scope", "entry", "complete", "boundary_known")
                      if key in graph}
    summary.update(block_count=len(blocks), instruction_count=sum(map(m._block_instruction_count, blocks)))
    for field in ("edges", "frontier"):
        records = graph.get(field)
        summary[{"edges": "edge_count", "frontier": "frontier_count"}[field]] = (
            len(records) if isinstance(records, list) else 0)
    if isinstance(graph.get("noreturn_calls"), list):
        # 只有分析记录了不返回调用（full 模式总有，其它路径有证据时才有）才给出计数，旧结果不变。
        summary["noreturn_call_count"] = len(graph["noreturn_calls"])
    for field, count_field in (("xrefs_in", "xref_in_count"), ("xrefs_out", "xref_out_count")):
        references = function.get(field)
        summary[count_field] = len(references) if isinstance(references, list) else 0
    return m.deepcopy(summary)


def _analysis_summary(snapshot: dict[str, Any]) -> dict[str, Any]:
    """小响应只含标量身份和覆盖；统计递归有界，不展开生产者附带的分析大表。"""
    m = _facade()
    budget = 200
    truncated = False
    omitted = object()
    large_fields = {"instructions", "disassembly", "full_disassembly", "cfg", "blocks", "edges",
                    "frontier", "pcode", "bytes", "raw_bytes", "bytecode"}

    def compact(value: Any, depth: int = 0) -> Any:
        nonlocal budget, truncated
        if budget <= 0:
            truncated = True
            return omitted
        budget -= 1
        if value is None or type(value) in (bool, int, float):
            return value
        if isinstance(value, str):
            truncated |= len(value) > m._SUMMARY_TEXT
            return value[:m._SUMMARY_TEXT]
        if isinstance(value, dict) and depth < 3:
            output = {}
            for key, item in value.items():
                if not isinstance(key, str) or key in large_fields:
                    truncated = True
                    continue
                small = compact(item, depth + 1)
                if small is not omitted:
                    output[key[:m._SUMMARY_TEXT]] = small
                if budget <= 0:
                    truncated |= len(output) < len(value)
                    break
            return output
        truncated = True
        return omitted

    stats = compact(snapshot.get("stats", {}))
    metadata = snapshot.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    full = metadata.get("full_analysis")
    coverage = {key: full[key] for key in (
        "enabled", "scope", "executable_bytes", "decoded_bytes", "decode_complete",
        "instruction_count", "unassigned_instructions", "function_recovery_complete",
        "xref_pass_complete", "cfg_pass_complete", "xref_scope", "input_truncated")
        if isinstance(full, dict) and key in full and type(full[key]) in (bool, int, float, str, type(None))}
    if isinstance(full, dict) and isinstance(full.get("regions"), list):
        coverage["region_count"] = len(full["regions"])
    database = metadata.get("analysis_database")
    database = database if isinstance(database, dict) else {}
    source = {"path": snapshot.get("path"),
              "sha256": metadata.get("source_sha256", database.get("source_sha256")),
              "size_bytes": metadata.get("source_size_bytes", metadata.get("size_bytes"))}
    source = {key: value for key, value in source.items()
              if type(value) in (bool, int, float, str, type(None))}
    for key in ("format", "architecture", "bits", "endian", "entry_address", "entry_offset",
                "image_base", "fat_slice_offset", "scanned_bytes"):
        if key in metadata and type(metadata[key]) in (bool, int, float, str, type(None)):
            source[key] = metadata[key]
    warnings = snapshot.get("warnings", [])
    warnings = warnings if isinstance(warnings, list) else []
    warning_page = [str(item)[:m._SUMMARY_TEXT] for item in warnings[:m._SUMMARY_WARNINGS]]
    counts = {key: len(snapshot[key]) if isinstance(snapshot.get(key), list) else 0
              for key in ("functions", "strings", "imports", "exports", "xrefs", "instructions")}
    instruction_source = "instructions" if isinstance(snapshot.get("instructions"), list) else "unavailable"
    full_listing = metadata.get("full_disassembly")
    declared_instructions = full.get("instruction_count") if isinstance(full, dict) else None
    if isinstance(full_listing, list):
        # 原生 full IR 存在 metadata 中；取长度即可，不遍历或复制任何指令。
        counts["instructions"] = len(full_listing)
        instruction_source = "metadata.full_disassembly"
    elif (isinstance(full, dict) and full.get("enabled") is True and
          type(declared_instructions) is int and declared_instructions >= 0):
        counts["instructions"] = declared_instructions
        instruction_source = "metadata.full_analysis.instruction_count"
    return {"kind": snapshot.get("kind"), "analyzer": snapshot.get("analyzer"),
            "status": snapshot.get("status"), "schema_version": snapshot.get("schema_version"),
            "source": m.deepcopy(source), "full_analysis": m.deepcopy(coverage),
            "stats": {} if stats is omitted else stats, "stats_truncated": truncated,
            "counts": counts, "instruction_count_source": instruction_source,
            "warnings": warning_page, "warning_count": len(warnings),
            "warnings_truncated": len(warnings) > m._SUMMARY_WARNINGS or any(
                len(str(item)) > m._SUMMARY_TEXT for item in warnings[:m._SUMMARY_WARNINGS])}


def _cfg_page(snapshot: dict[str, Any], arguments: dict[str, Any],
              offset: int, limit: int) -> dict[str, Any]:
    """仅对完成的快照投影，复制当前页，不复制或重新解码完整指令图。"""
    m = _facade()
    address = m._address(arguments.get("address"))
    source = arguments.get("source")
    if source is not None and not isinstance(source, str):
        raise ValueError("source must be a string")
    space = arguments.get("address_space")
    if space is not None:
        if not isinstance(space, str) or not space:
            raise ValueError("address_space must be a non-empty string")
        space = m._CFG_SPACE_ALIASES.get(space, space)
    collection = arguments.get("collection", "blocks")
    if collection not in ("blocks", "edges", "frontier", "noreturn_calls"):
        raise ValueError("collection must be blocks, edges, frontier, or noreturn_calls")
    matching = []
    for function in snapshot.get("functions", []):
        if not isinstance(function, dict) or m._record_address(
                function, "start", "address", "code_offset", "addr") != address:
            continue
        context = m._cfg_context(function, snapshot.get("kind", ""))
        if ((source is not None and source != context[0]) or
                (space is not None and space != context[1])):
            continue
        matching.append((function, context))
    if not matching:
        raise ValueError(f"No identified function starts at address {address:#x} in the selected context")
    if len(matching) != 1:
        raise ValueError(f"Ambiguous function address {address:#x}; specify source and address_space")
    function, (source, space) = matching[0]
    graph = function.get("cfg")
    if not isinstance(graph, dict) or not graph:
        raise ValueError("Control-flow graph is unavailable for this function")
    collections = {"blocks": function.get("blocks", graph.get("blocks", [])),
                   "edges": graph.get("edges", []), "frontier": graph.get("frontier", [])}
    if any(not isinstance(items, list) for items in collections.values()):
        raise ValueError("CFG blocks, edges and frontier must be lists")
    if collection == "noreturn_calls":
        # 被截断落空边的不返回调用（from/fallthrough/target/name/evidence）；旧结果没有时为空。
        # 只在请求时校验，其它集合的读取不受该字段影响。
        collections["noreturn_calls"] = graph.get("noreturn_calls", [])
        if not isinstance(collections["noreturn_calls"], list):
            raise ValueError("CFG noreturn_calls must be a list")
    page = m._page(collections[collection], offset, limit)
    if collection == "blocks":
        page["items"] = [{**m.deepcopy({key: value for key, value in block.items()
                                       if key != "instructions"}),
                          "instruction_count": m._block_instruction_count(block)}
                         if isinstance(block, dict) else m.deepcopy(block)
                         for block in page["items"]]
    else:
        page["items"] = m.deepcopy(page["items"])
    identity = {"address": address, "name": function.get("name"),
                "source": source, "address_space": space}
    if "size" in function:
        identity["size"] = function["size"]
    return {"available": True, "function": m.deepcopy(identity),
            "cfg": m.deepcopy({key: value for key, value in graph.items()
                               if key in {"scope", "entry", "complete", "boundary_known", "assumptions",
                                          "architecture", "address_space"}}),
            "counts": {**{key: len(items) for key, items in collections.items()},
                       "instructions": sum(map(m._block_instruction_count, collections["blocks"]))},
            "collection": collection, **page, "status": snapshot.get("status")}
