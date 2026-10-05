"""CLI access to the common analysis service."""
from __future__ import annotations
import argparse
import json
import sys
from dataclasses import fields, is_dataclass, replace
from pathlib import Path
from .dispatcher import AnalysisService
from .settings import load_settings
from .project import ProjectError
from .api import AnalysisView, _shared_snapshot, open_database
from .tui import browse
from . import _json_stream
from .models import AnalysisResult
from .project import _dataclass_json


def _result_json(result: AnalysisResult, *, ensure_ascii: bool) -> str:
    """与 json.dumps(result.to_dict(), indent=2) 相同的文本，但不先 asdict 复制整个结果。

    嵌套 dataclass 由 default 钩子按 asdict 展开；3.11/3.12 的 indent 编码走分块编码器。
    """
    payload = {item.name: getattr(result, item.name) for item in fields(result)}
    return _json_stream.dumps(payload, indent=2, ensure_ascii=ensure_ascii, default=_dataclass_json)


def _full_json(result, stream, *, ensure_ascii: bool) -> None:
    """Write JSON-compatible result fields without copying the complete graph."""
    payload = ({item.name: getattr(result, item.name) for item in fields(result)}
               if is_dataclass(result) else result)
    # 与 json.JSONEncoder(indent=2).iterencode 逐字节一致，但按约 1 MiB 的块编码与写出，
    # 写入次数从每个 token 一次降到每块一次。
    _json_stream.dump(payload, stream, indent=2, ensure_ascii=ensure_ascii)
    stream.write("\n")

def main() -> int:
    parser = argparse.ArgumentParser(prog="fangida")
    parser.add_argument("file", nargs="?", help="File to inspect")
    parser.add_argument("--max-bytes", type=int, default=None, help="Scan budget in bytes")
    parser.add_argument("--output", type=Path, help="Export the JSON result to this file")
    parser.add_argument("--project", type=Path, help="Save a versioned snapshot in this SQLite project")
    parser.add_argument("--database", type=Path, help="Save analysis through the independent storage plugin")
    parser.add_argument("--open-database", type=Path, help="Read an existing analysis database without reanalysis")
    parser.add_argument("--snapshot-id", type=int, help="Snapshot ID to open (default: newest)")
    parser.add_argument("--ghidra", action="store_true", help="Supplement native analysis with installed Ghidra")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fast", action="store_true", help="Run metadata/entry scan without deeper native function analysis")
    mode.add_argument("--full", action="store_true", help="Analyze all native code regions or Android/JVM bytecode methods, CFGs and xrefs")
    parser.add_argument("--threads", type=int, help="Native semantic workers (1–16; default is automatic)")
    view_group = parser.add_mutually_exclusive_group()
    view_group.add_argument("--interactive", action="store_true", help="Browse the result in a terminal")
    view_group.add_argument("--gui", action="store_true", help="Open the optional desktop browser")
    args = parser.parse_args()
    if args.file is None and args.open_database is None:
        parser.error("file is required unless --open-database is supplied")
    if args.open_database is not None and (args.file is not None or args.database is not None or
                                           args.project is not None):
        parser.error("--open-database cannot be combined with a source file, --database or --project")
    if args.open_database is not None and (args.max_bytes is not None or args.ghidra or args.fast or
                                           args.full or args.threads is not None):
        parser.error("Analysis options cannot be combined with --open-database")
    if args.snapshot_id is not None and (args.open_database is None or args.snapshot_id <= 0):
        parser.error("--snapshot-id requires --open-database and a positive snapshot ID")
    if args.threads is not None and not 1 <= args.threads <= 16:
        parser.error("--threads must be between 1 and 16")
    try:
        if args.gui:
            from .gui import launch
            return launch(args.file, max_bytes=args.max_bytes,
                          use_ghidra=True if args.ghidra else None,
                          deep_analysis=False if args.fast else None,
                          semantic_threads=args.threads,
                          **({"full_analysis": True} if args.full else {}),
                          **({"database_path": args.database} if args.database is not None else {}),
                          **({"open_database_path": args.open_database} if args.open_database is not None else {}),
                          **({"snapshot_id": args.snapshot_id} if args.snapshot_id is not None else {}))
        if args.open_database is not None:
            view = open_database(args.open_database, args.snapshot_id)
            # 以下只读导出/打印摘要：直接读视图内部快照，省去一次整图深拷贝（视图仍保持隔离）。
            snapshot = _shared_snapshot(view)
            full = bool(snapshot.get("stats", {}).get("full_analysis"))
            if args.output:
                with args.output.expanduser().open("w", encoding="utf-8") as stream:
                    _full_json(snapshot, stream, ensure_ascii=False)
            if args.interactive:
                browse(view)
            elif full and args.output:
                print(json.dumps({"path": snapshot["path"], "status": snapshot["status"],
                                  "analysis_database": snapshot.get("metadata", {}).get("analysis_database"),
                                  "output": str(args.output.expanduser().resolve()),
                                  "stats": snapshot.get("stats", {}), "warnings": snapshot.get("warnings", [])},
                                 indent=2))
            else:
                _full_json(snapshot, sys.stdout, ensure_ascii=True)
            return 1 if snapshot["status"] == "error" else 0
        settings = load_settings(project_dir=Path(args.file).expanduser().resolve().parent)
        if args.threads is not None:
            settings = replace(settings, semantic_threads=args.threads,
                               analyze_threads=max(settings.analyze_threads,
                                                   args.threads + int(args.threads > 1))).validated()
        with AnalysisService(settings, project_path=args.project,
                             **({"database_path": args.database} if args.database is not None else {})) as service:
            result = service.analyze(args.file, max_bytes=args.max_bytes,
                                     use_ghidra=True if args.ghidra else None,
                                     deep_analysis=False if args.fast else None,
                                     **({"full_analysis": True} if args.full else {}))
        full = args.full or bool(result.stats.get("full_analysis"))
        if args.output:
            if full:
                with args.output.expanduser().open("w", encoding="utf-8") as stream:
                    _full_json(result, stream, ensure_ascii=False)
            elif type(result) is AnalysisResult:
                # 只读导出：省去 AnalysisView 构造时的 asdict 与整图深拷贝，文本与 export_json 相同。
                args.output.expanduser().resolve().write_text(
                    _result_json(result, ensure_ascii=False) + "\n", encoding="utf-8")
            else:
                AnalysisView(result).export_json(args.output)
        if args.interactive:
            # 此后 CLI 只再读取 result.status：完整结果直接移交给视图，避免整图深拷贝；
            # 非完整结果仍走原来的复制构造。
            browse(AnalysisView._from_owned_result(result) if full else AnalysisView(result))
        elif full and args.output:
            print(json.dumps({"path": result.path, "kind": result.kind,
                              "analyzer": result.analyzer, "status": result.status,
                              "output": str(args.output.expanduser().resolve()),
                              "full_analysis": result.metadata.get("full_analysis"),
                              "stats": result.stats, "warnings": result.warnings}, indent=2))
        elif full:
            _full_json(result, sys.stdout, ensure_ascii=True)
        elif type(result) is AnalysisResult:
            print(_result_json(result, ensure_ascii=True))
        else:
            print(json.dumps(result.to_dict(), indent=2))
        return 1 if result.status == "error" else 0
    except (OSError, ValueError, RuntimeError, ProjectError) as exc:
        print(json.dumps({"status": "error", "message": str(exc)}), file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
