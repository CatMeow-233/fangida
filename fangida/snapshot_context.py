"""Address context normalization for saved evidence, independent of access layers."""
from __future__ import annotations
from typing import Any

SPACE_ALIASES = {"ram": "native", "virtual": "native", "virtual_address": "native",
                 "fileoffset": "file_offset", "offset": "file_offset"}


def function_context(function: dict[str, Any], kind: str) -> tuple[str, str]:
    """区分容器成员与地址空间；原生函数的 source 是符号来源标签。"""
    meta = function.get("arch_meta")
    meta = meta if isinstance(meta, dict) else {}
    graph = function.get("cfg")
    graph = graph if isinstance(graph, dict) else {}
    explicit = function.get("address_space", meta.get("address_space", graph.get("address_space")))
    space = SPACE_ALIASES.get(str(explicit), str(explicit)) if explicit else None
    bytecode = ("code_offset" in function or function.get("kind") in {"dex", "jvm", "class"}
                or meta.get("arch") in {"dex", "jvm"}
                or (space is None and kind in {"apk", "dex", "jar", "class"}))
    space = space or ("file_offset" if bytecode else "native")
    member = meta.get("container_member", function.get("container_member"))
    source = member if member is not None else (
        function.get("source", "") if bytecode or space != "native" else "")
    return str(source or ""), space
