"""Inspect and annotate persistent Fangida projects."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from . import _json_stream
from .project import ProjectError, ProjectStore

def _address(value: str) -> int:
    address = int(value, 0)
    if address < 0:
        raise argparse.ArgumentTypeError("address must be nonnegative")
    return address

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fangida-project")
    parser.add_argument("database", type=Path)
    command = parser.add_subparsers(dest="command", required=True)
    history = command.add_parser("history", help="List saved analysis snapshots")
    history.add_argument("--file", type=Path)
    history.add_argument("--offset", type=int, default=0)
    history.add_argument("--limit", type=int, default=100)
    show = command.add_parser("show", help="Read a saved snapshot")
    show.add_argument("snapshot_id", type=int)
    page = command.add_parser("page", help="Read one snapshot collection page")
    page.add_argument("snapshot_id", type=int)
    page.add_argument("collection", choices=["functions", "strings", "imports", "exports", "xrefs", "warnings", "disassembly"])
    page.add_argument("--offset", type=int, default=0)
    page.add_argument("--limit", type=int, default=100)
    rename = command.add_parser("rename", help="Save a symbol rename annotation")
    rename.add_argument("file", type=Path)
    rename.add_argument("address", type=_address)
    rename.add_argument("name")
    comment = command.add_parser("comment", help="Save a comment annotation")
    comment.add_argument("file", type=Path)
    comment.add_argument("address", type=_address)
    comment.add_argument("text")
    annotations = command.add_parser("annotations", help="Read annotations for current file content")
    annotations.add_argument("file", type=Path)
    args = parser.parse_args(argv)
    try:
        store = ProjectStore(args.database)
        if args.command == "history":
            value = store.history(args.file, offset=args.offset, limit=args.limit)
        elif args.command == "show":
            value = store.get_snapshot(args.snapshot_id)
        elif args.command == "page":
            value = store.page(args.snapshot_id, args.collection, offset=args.offset, limit=args.limit)
        elif args.command == "rename":
            store.rename_symbol(args.file, args.address, args.name)
            value = {"saved": True, "kind": "rename", "address": args.address}
        elif args.command == "comment":
            store.set_comment(args.file, args.address, args.text)
            value = {"saved": True, "kind": "comment", "address": args.address}
        else:
            value = store.annotations(args.file)
        # 先生成完整文本再输出：输出编码失败时 stdout 不留半截 JSON（与原行为一致）；
        # 3.11/3.12 的 indent 编码改由分块编码器完成，文本逐字节相同。
        print(_json_stream.dumps(value, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, ProjectError, KeyError) as exc:
        print(json.dumps({"status": "error", "message": str(exc)}), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
