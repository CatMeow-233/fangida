"""独立插件命令，只消费已有 JSON/FDB；不会启动原生分析。"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from . import _rows
from ..manager import PluginManager


def _number(token):
    try:
        value = int(token, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("地址和值应为十进制或 0x 十六进制") from exc
    if not 0 <= value < 1 << 64:
        raise argparse.ArgumentTypeError("地址和值应为无符号 64 位整数")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description="独立 ARM64 BR/BLR 插件：反向切片 + 可选 Unicorn")
    parser.add_argument("snapshot", help="已完成的分析 JSON；--database 时为 FDB/SQLite")
    parser.add_argument("--database", action="store_true", help="以只读方式加载数据库快照")
    parser.add_argument("--snapshot-id", type=int)
    parser.add_argument("--address", type=_number, help="需要求解的 BR/BLR 指令虚拟地址")
    parser.add_argument("--list", action="store_true", help="列出已有快照内的 ARM64 BR/BLR，不求解")
    parser.add_argument("--source", help="原始二进制，仅用于插件内的有界 Unicorn 仿真")
    parser.add_argument("--register", action="append", default=[], metavar="X0=0x1234", help="切片入口的运行时寄存器，可重复")
    parser.add_argument("--memory-json", help="运行时内存快照 JSON 数组：address、data(十六进制字节)")
    parser.add_argument("--function", type=_number, help="重叠函数时指定函数入口")
    parser.add_argument("--max-instructions", type=int, default=512)
    parser.add_argument("--max-paths", type=int, default=32)
    parser.add_argument("--timeout-ms", type=int, default=200)
    parser.add_argument("--details", action="store_true", help="在结果中包含切片指令和表达式")
    parser.add_argument("--output", help="另存插件结果 JSON；不改分析数据库或原文件")
    args = parser.parse_args(argv)
    if not args.list and args.address is None:
        parser.error("请指定 --address 或使用 --list")
    manager = PluginManager()
    try:
        path = Path(args.snapshot).expanduser().resolve(strict=True)
        if args.database:
            from ...storage import database_session
            with database_session(path, manager=manager, read_only=True) as database:
                snapshot = database.get_snapshot(args.snapshot_id)
        else:
            if path.stat().st_size > 128 * 1024 * 1024:
                raise ValueError("JSON 快照超过 128 MiB 预算；请使用 FDB")
            snapshot = json.loads(path.read_text(encoding="utf-8"))
        if args.list:
            rows, _ = _rows(snapshot, args.address or 0)
            output = {"plugin": "arm64_br_solver", "branches": [
                {"address": row["addr"], "mnemonic": row["mnemonic"], "operands": row.get("operands", ())}
                for row in rows if row.get("mnemonic", "").lower() in {"br", "blr"}]}
        else:
            registers = {}
            for pair in args.register:
                if "=" not in pair:
                    raise ValueError("--register 格式为 X0=0x1234")
                name, value = pair.split("=", 1)
                if name in registers:
                    raise ValueError("不能重复指定同一寄存器")
                registers[name] = _number(value)
            memory = ()
            if args.memory_json:
                context_path = Path(args.memory_json).expanduser()
                if context_path.stat().st_size > 16 * 1024 * 1024:
                    raise ValueError("运行时内存 JSON 超过读取预算")
                memory = json.loads(context_path.read_text(encoding="utf-8"))
                if not isinstance(memory, list):
                    raise ValueError("运行时内存 JSON 必须是数组")
            output = manager.load_branch_solver().solve(snapshot, args.address, source_path=args.source,
                registers=registers, memory=memory, function_address=args.function,
                max_instructions=args.max_instructions, max_paths=args.max_paths,
                timeout_ms=args.timeout_ms, include_details=args.details)
        serialized = json.dumps(output, ensure_ascii=False, indent=2)
        if args.output:
            destination = Path(args.output).expanduser().resolve()
            protected = {path}
            if args.source:
                protected.add(Path(args.source).expanduser().resolve())
            if destination in protected:
                raise ValueError("插件结果不能覆盖分析快照、数据库或原文件")
            if destination.exists() and any(item.exists() and destination.samefile(item) for item in protected):
                raise ValueError("插件结果不能覆盖输入文件的硬链接")
            destination.write_text(serialized + "\n", encoding="utf-8")
        print(serialized)
        return 0
    except (ValueError, TypeError, KeyError, OSError, argparse.ArgumentTypeError) as exc:
        print(f"BR 插件：{exc}", file=sys.stderr)
        return 2
    finally:
        manager.teardown()


if __name__ == "__main__":
    raise SystemExit(main())
