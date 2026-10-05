"""Small terminal result browser that does not depend on an external UI framework."""
from __future__ import annotations
from typing import Any, TextIO
import json
import os
import sys
from .api import AnalysisView, _shared_snapshot

HELP = ("Commands: summary, sections, functions, imports, exports, strings [limit], disasm [limit], cfg, xrefs, "
        "pseudoc (JSON), pseudocode [name|0xaddr] [machine], help, quit")
#: 逐函数显示完整伪代码的命令名；pseudoc 保留原 JSON 输出供脚本使用。
PSEUDOCODE_COMMANDS = frozenset({"pseudocode", "code", "decompile"})

def browse(view: AnalysisView, output: TextIO = sys.stdout) -> None:
    # 下面只读取快照（只新建 data 容器、从不写回），因此不再整图深拷贝；
    # 覆写了 snapshot() 的视图仍调用其 snapshot()。
    snapshot = _shared_snapshot(view)
    print(HELP, file=output)
    while True:
        try:
            command = input("fangida> ").strip().split()
        except (EOFError, KeyboardInterrupt):
            print(file=output)
            return
        if not command:
            continue
        name = command[0].lower()
        if name in {"quit", "exit", "q"}:
            return
        if name == "help":
            print(HELP, file=output)
            continue
        if name in PSEUDOCODE_COMMANDS:
            print_pseudocode(snapshot, command[1:], output)
            continue
        try:
            if name == "summary":
                data = {key: snapshot[key] for key in ("path", "kind", "status", "analyzer", "warnings")}
                data["metadata"] = {key: value for key, value in snapshot["metadata"].items()
                                    if key != "disassembly"}
            elif name == "sections":
                data = snapshot["metadata"].get("sections", [])
            elif name == "functions":
                data = view.functions()
            elif name in {"imports", "exports"}:
                data = snapshot.get(name, [])
            elif name == "cfg":
                data = snapshot["metadata"].get("entry_cfg", {"available": False})
            elif name == "strings":
                limit = int(command[1]) if len(command) > 1 else 30
                data = view.strings()[:_limit(limit)]
            elif name == "disasm":
                limit = int(command[1]) if len(command) > 1 else 30
                data = view.disassembly(0, _limit(limit))
            elif name == "xrefs":
                data = view.xrefs()
            elif name == "imports":
                data = snapshot.get("imports", [])
            elif name == "exports":
                data = snapshot.get("exports", [])
            elif name == "api_calls":
                data = snapshot["metadata"].get("api_calls", [])
            elif name == "cfg":
                data = snapshot["metadata"].get("entry_cfg", {"available": False})
            elif name == "pseudoc":
                data = [{"name": item.get("name"), "start": item.get("start"),
                         "producer": item.get("pseudoc_producer"), "pseudoc": item["pseudoc"]}
                        for item in snapshot["functions"] if item.get("pseudoc")]
            else:
                print("Unknown command; type help", file=output)
                continue
            print(json.dumps(data, indent=2), file=output)
        except (ValueError, IndexError) as exc:
            print(f"Invalid argument: {exc}", file=output)

def _wants_color(output: TextIO) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return bool(output.isatty())
    except (AttributeError, ValueError):
        return False


def print_pseudocode(snapshot: dict[str, Any], arguments: list[str] | tuple[str, ...] = (),
                     output: TextIO = sys.stdout, *, color: bool | None = None) -> int:
    """逐函数输出带函数头（名字/地址/签名/调用/字符串/截断提示）的完整伪代码。

    arguments 可包含函数名、0x 地址（入口或指令内部）以及 ``machine``
    （显示机器视图）。只读快照，不重新生成伪代码；返回输出的函数个数。
    """
    from .gui_modules.pseudocode import (build_symbol_context, no_pseudocode_message,
                                         render_listing, select_functions, status_flags)
    style = "readable"
    terms = []
    for argument in arguments:
        if argument.lower() in {"machine", "--machine", "-m"}:
            style = "machine"
        elif argument.lower() in {"readable", "--readable"}:
            style = "readable"
        else:
            terms.append(argument)
    functions = [item for item in snapshot.get("functions", []) if isinstance(item, dict)]
    available = select_functions(functions)
    if not available:
        print(no_pseudocode_message(snapshot.get("stats", {}), str(snapshot.get("kind", ""))), file=output)
        return 0
    query = " ".join(terms)
    selected = select_functions(available, query) if query else available
    if not selected:
        print(f"没有名称或地址匹配“{query}”的伪代码函数。可用函数：", file=output)
        for item in available:
            start = item.get("start")
            location = f"{start:#x}" if type(start) is int else "?"
            print(f"  {location:>18}  {item.get('name', '?')}  [{status_flags(item)}]", file=output)
        return 0
    metadata = snapshot.get("metadata", {})
    context = build_symbol_context(functions=functions, imports=snapshot.get("imports", ()),
                                   exports=snapshot.get("exports", ()),
                                   strings=snapshot.get("strings", ()),
                                   sections=metadata.get("sections", ()) if isinstance(metadata, dict) else (),
                                   pseudocode=available)
    use_color = _wants_color(output) if color is None else color
    if not query:
        print(f"共 {len(selected)} 个函数有伪代码（pseudocode <名称|0x地址> [machine] 只看一个函数）", file=output)
    for item in selected:
        print(render_listing(item, style=style, context=context, color=use_color), file=output)
    return len(selected)


def _limit(value: int) -> int:
    if not 1 <= value <= 1000:
        raise ValueError("limit must be 1..1000")
    return value
