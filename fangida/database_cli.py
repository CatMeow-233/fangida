"""在不读取原始二进制的情况下检查、标注插件分析数据库。"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3
import sys

from . import _json_stream
from .plugins.manager import PluginManager
from .project import COLLECTIONS, ProjectError


def _address(value: str) -> int:
    try:
        address = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("地址须为整数或 0x 开头的十六进制数") from exc
    if address < 0:
        raise argparse.ArgumentTypeError("地址不能为负数")
    return address


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fangida-db", description=__doc__)
    parser.add_argument("database", type=Path, help="已有的 .fdb 分析数据库")
    commands = parser.add_subparsers(dest="command", required=True)
    history = commands.add_parser("history", help="列出保存的分析快照")
    history.add_argument("--file", type=Path, help="按历史来源路径筛选；该文件可以已经删除")
    history.add_argument("--offset", type=int, default=0)
    history.add_argument("--limit", type=int, default=100)
    show = commands.add_parser("show", help="读取带名称、注释的分析快照")
    show.add_argument("snapshot_id", type=int, nargs="?", help="省略时读取最新快照")
    page = commands.add_parser("page", help="分页读取保存的分析集合")
    page.add_argument("snapshot_id", type=int)
    page.add_argument("collection", choices=sorted(COLLECTIONS))
    page.add_argument("--offset", type=int, default=0)
    page.add_argument("--limit", type=int, default=100)
    rename = commands.add_parser("rename", help="按快照保存符号名称；无需原文件")
    rename.add_argument("snapshot_id", type=int)
    rename.add_argument("address", type=_address)
    rename.add_argument("name")
    comment = commands.add_parser("comment", help="按快照保存注释；空文本移除注释")
    comment.add_argument("snapshot_id", type=int)
    comment.add_argument("address", type=_address)
    comment.add_argument("text")
    annotations = commands.add_parser("annotations", help="读取快照来源哈希的名称和注释")
    annotations.add_argument("snapshot_id", type=int)
    args = parser.parse_args(argv)
    manager = PluginManager()
    store = None
    try:
        plugin = manager.load_storage("sqlite_storage")
        store = plugin.open_database(args.database,
                                     read_only=args.command not in ("rename", "comment"))
        if args.command == "history":
            value = store.history(args.file, offset=args.offset, limit=args.limit)
        elif args.command == "show":
            value = store.get_snapshot(args.snapshot_id)
        elif args.command == "page":
            value = store.page(args.snapshot_id, args.collection,
                               offset=args.offset, limit=args.limit)
        elif args.command == "rename":
            store.rename_symbol(args.snapshot_id, args.address, args.name)
            value = {"saved": True, "kind": "rename", "address": args.address}
        elif args.command == "comment":
            store.set_comment(args.snapshot_id, args.address, args.text)
            value = {"saved": True, "kind": "comment", "address": args.address}
        else:
            value = store.annotations(args.snapshot_id)
        # 先生成完整文本再输出：输出编码失败时 stdout 不留半截 JSON（与原行为一致）；
        # 3.11/3.12 的 indent 编码改由分块编码器完成，文本逐字节相同。
        print(_json_stream.dumps(value, indent=2, ensure_ascii=False))
        return 0
    except (OSError, ValueError, ProjectError, KeyError, TypeError, sqlite3.Error) as exc:
        print(json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    finally:
        try:
            if store is not None:
                store.close()
        finally:
            manager.teardown()


if __name__ == "__main__":
    raise SystemExit(main())
