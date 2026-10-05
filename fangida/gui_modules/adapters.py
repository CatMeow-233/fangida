"""只读结果适配：地址解析、十六进制分页、CFG 图与基本块、表格行和概要文本。

只读取已完成的快照，或按需读取源文件的一页字节，不执行分析；由 fangida.gui 门面再导出。
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .constants import HEX_PAGE_ROWS
from .facade import _gui

# gui_modules 不直接导入 api、dispatcher、plugins 等分析实现（见 tests/test_gui_workbench.py 的依赖检查）：
# 注解里的 AnalysisView 由 fangida.gui 门面注入本模块（保持 typing.get_type_hints 可解析），
# 运行时需要的 AnalysisView 由调用方传入。HEX_PAGE_ROWS 仅用于定义时求值的参数默认值。
# 运行时引用的原 fangida.gui 模块级名字（函数、类、常量及 Path 等导入的名字）一律经门面 _gui() 查找，
# 对门面打的补丁因此仍作用于实现，与拆分前一致。


def parse_seek_offset(value: str) -> int:
    """Parse a decimal or 0x-prefixed file offset or virtual address."""
    stripped = value.strip()
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", stripped):
        offset = int(stripped, 16)
    elif re.fullmatch(r"[0-9]+", stripped):
        offset = int(stripped, 10)
    else:
        raise ValueError("Enter a non-negative decimal or 0x-prefixed hexadecimal address")
    if offset > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("Address exceeds 64 bits")
    return offset


def _file_identity(stat: Any) -> tuple[int, int, int, int, int]:
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns)


def hex_page(path: str | Path, offset: int, *, rows: int = HEX_PAGE_ROWS,
             expected_identity: tuple[int, int, int, int, int] | None = None) -> dict[str, Any]:
    """Seek into a file and format at most 4096 bytes as hex and ASCII.

    Only the requested page is read. File size and identity are checked on both
    sides of the read, so a replaced or changing input does not appear reliable.
    """
    if type(offset) is not int or offset < 0:
        raise ValueError("offset must be a non-negative integer")
    if type(rows) is not int or not 1 <= rows <= _gui().MAX_HEX_ROWS:
        raise ValueError(f"rows must be between 1 and {_gui().MAX_HEX_ROWS}")
    if expected_identity is not None and (not isinstance(expected_identity, tuple) or
            len(expected_identity) != 5 or any(type(item) is not int for item in expected_identity)):
        raise ValueError("expected_identity must contain five integer stat identity fields")
    source = _gui().Path(path).expanduser().resolve(strict=True)
    if not source.is_file():
        raise ValueError(f"Not a regular file: {source}")
    before = source.stat()
    identity = _gui()._file_identity(before)
    if expected_identity is not None and identity != expected_identity:
        raise OSError("Original source changed since verification; reopen the source or database")
    if offset > before.st_size:
        raise ValueError(f"Offset {offset:#x} exceeds file size {before.st_size:#x}")
    start = (offset // _gui().HEX_BYTES_PER_ROW) * _gui().HEX_BYTES_PER_ROW
    page_bytes = rows * _gui().HEX_BYTES_PER_ROW
    with source.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if _gui()._file_identity(opened) != identity:
            raise OSError("The file changed before reading the hex page; reload analysis")
        stream.seek(start)
        data = stream.read(page_bytes)
    after = source.stat()
    if identity != _gui()._file_identity(after):
        raise OSError("The file changed while reading the hex page; reload analysis")
    width = max(8, len(f"{before.st_size:x}"))
    lines = []
    for position in range(0, len(data), _gui().HEX_BYTES_PER_ROW):
        chunk = data[position:position + _gui().HEX_BYTES_PER_ROW]
        hex_column = " ".join(f"{byte:02x}" for byte in chunk).ljust(_gui().HEX_BYTES_PER_ROW * 3 - 1)
        ascii_column = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{start + position:0{width}x}  {hex_column}  |{ascii_column}|")
    if not lines:
        lines.append("End of file")
    following = start + len(data)
    return {"start": start, "end": following, "size": before.st_size,
            "text": "\n".join(lines) + "\n",
            "previous_offset": max(0, start - page_bytes) if start else None,
            "next_offset": following if following < before.st_size else None}


def cfg_graphs(view: AnalysisView) -> list[dict[str, Any]]:
    """Collect graphs with decoded blocks, including the bounded entry graph."""
    return _gui()._cfg_graphs_snapshot(view.snapshot())


def _cfg_graphs_snapshot(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    graphs: list[dict[str, Any]] = []
    starts: set[int] = set()
    for function in snapshot.get("functions", []):
        if not isinstance(function, dict):
            continue
        blocks = function.get("blocks")
        cfg = function.get("cfg")
        if not isinstance(blocks, list) or not blocks:
            continue
        if not isinstance(cfg, dict):
            cfg = {}
        start = function.get("start")
        if isinstance(start, int):
            starts.add(start)
        graphs.append({"name": str(function.get("name") or "unnamed"), "start": start,
                       "graph": {**cfg, "blocks": blocks},
                       "source": function.get("source", ""),
                       "address_space": function.get("address_space", "native")
                       if snapshot.get("kind") not in {"apk", "dex", "jar", "class"}
                       else function.get("address_space", "file_offset")})
    entry = snapshot.get("metadata", {}).get("entry_cfg")
    if isinstance(entry, dict) and isinstance(entry.get("blocks"), list) and entry["blocks"]:
        address = entry.get("entry")
        if address not in starts:
            graphs.append({"name": "Entry window", "start": address, "graph": entry})
    return graphs


def cfg_block_rows(graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Prepare block details and outgoing edges for the CFG inspector."""
    blocks = graph.get("blocks", [])
    if not isinstance(blocks, list):
        return []
    edges = graph.get("edges", [])
    frontiers = graph.get("frontier", [])
    edges = edges if isinstance(edges, list) else []
    frontiers = frontiers if isinstance(frontiers, list) else []
    # Index each recorded source once rather than rescan every edge for each
    # block. Ordinals retain the original graph's edge/frontier order.
    edge_sources: dict[Any, list[tuple[int, dict[str, Any]]]] = {}
    frontier_sources: dict[Any, list[tuple[int, dict[str, Any]]]] = {}
    for records, key, sources in ((edges, "src", edge_sources),
                                  (frontiers, "from", frontier_sources)):
        for ordinal, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            try:
                sources.setdefault(record.get(key), []).append((ordinal, record))
            except TypeError:
                continue  # malformed, unhashable source cannot name a block
    result = []
    for block in blocks[:_gui().MAX_CFG_BLOCKS]:
        if not isinstance(block, dict) or not isinstance(block.get("start"), int):
            continue
        instructions = block.get("instructions", [])
        if not isinstance(instructions, list):
            instructions = []
        addresses = {block["start"]} | {ins.get("addr") for ins in instructions if isinstance(ins, dict)}
        outgoing = [record for _, record in sorted(
            (item for address in addresses for item in edge_sources.get(address, [])),
            key=lambda item: item[0])]
        frontier = [record for _, record in sorted(
            (item for address in addresses for item in frontier_sources.get(address, [])),
            key=lambda item: item[0])]
        declared = block.get("successors")
        declared = declared if isinstance(declared, list) else []
        successors = sorted({edge["dst"] for edge in outgoing if isinstance(edge.get("dst"), int)} |
                            {target for target in declared if isinstance(target, int)})
        result.append({"start": block["start"], "instructions": instructions,
                       "instruction_count": len(instructions), "successors": successors,
                       "outgoing": outgoing, "frontier": frontier})
    return result


def _display(value: Any, column: str) -> str:
    """Format a table cell without losing its original value in the detail pane."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, int) and column in {"address", "offset", "location", "addr", "src", "dst", "start"}:
        return f"{value:#x}"
    if isinstance(value, (tuple, list)):
        if column == "address":
            return ", ".join(_gui()._display(item, column) for item in value)
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value).replace("\r", "\\r").replace("\n", "\\n")


def table_data(view: AnalysisView) -> dict[str, list[dict[str, Any]]]:
    """Build browsable tables from the public snapshot interface."""
    snapshot = view.snapshot()
    if snapshot.get("stats", {}).get("full_analysis"):
        return _gui()._full_tables(snapshot)
    functions = view.functions()
    for function in functions:
        function["location"] = function.get("start", function.get("code_offset"))
    return {
        "Sections": snapshot.get("metadata", {}).get("sections", []),
        "Functions": functions,
        "Disassembly": view.disassembly(0, 1000),
        "Strings": view.strings(),
        "Imports": snapshot.get("imports", []),
        "Exports": snapshot.get("exports", []),
        "Xrefs": view.xrefs(),
        **_gui()._extra_display_tables(snapshot),
    }


def _full_tables(snapshot: dict[str, Any], *, disassembly_limit: int | None = 1000
                 ) -> dict[str, list[dict[str, Any]]]:
    """Build display rows without mutating the completed analysis graph."""
    functions = [{**function, "location": function.get("start", function.get("code_offset"))}
                 for function in snapshot.get("functions", [])]
    metadata = snapshot.get("metadata", {})
    disassembly = metadata.get("full_disassembly", metadata.get("disassembly", []))
    if disassembly_limit is not None:
        disassembly = disassembly[:disassembly_limit]
    return {"Sections": metadata.get("sections", []), "Functions": functions,
            "Disassembly": disassembly,
            "Strings": snapshot.get("strings", []), "Imports": snapshot.get("imports", []),
            "Exports": snapshot.get("exports", []), "Xrefs": snapshot.get("xrefs", []),
            **_gui()._extra_display_tables(snapshot)}


def _extra_display_tables(snapshot: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    from .records import extra_tables
    return extra_tables(snapshot)


def summary_text(view: AnalysisView) -> str:
    """Describe the result and its limits, omitting tables shown in other tabs."""
    # A summary only reads fields and returns text; reading the completed
    # private full snapshot avoids copying every instruction just to omit it.
    snapshot = getattr(view, "_snapshot", {})
    if not isinstance(snapshot, dict) or not snapshot.get("stats", {}).get("full_analysis"):
        snapshot = view.snapshot()
    return _gui()._summary_snapshot(snapshot)


def _summary_snapshot(snapshot: dict[str, Any]) -> str:
    metadata = snapshot.get("metadata", {}).copy()
    metadata.pop("sections", None)
    metadata.pop("disassembly", None)
    full_disassembly = metadata.pop("full_disassembly", None)
    if isinstance(full_disassembly, list):
        metadata["full_disassembly_count"] = len(full_disassembly)
    ghidra = metadata.get("ghidra")
    if isinstance(ghidra, dict) and isinstance(ghidra.get("pcode"), list):
        metadata["ghidra"] = {"stats": ghidra.get("stats", {}),
                              "pcode_count": len(ghidra["pcode"])}
    summary = {
        "path": snapshot.get("path"),
        "kind": snapshot.get("kind"),
        "analyzer": snapshot.get("analyzer"),
        "status": snapshot.get("status"),
        "metadata": metadata,
        "stats": snapshot.get("stats", {}),
        "warnings": snapshot.get("warnings", []),
    }
    return json.dumps(summary, indent=2, ensure_ascii=False) + "\n"
