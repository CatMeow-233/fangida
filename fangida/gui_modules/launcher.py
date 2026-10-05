"""GUI 启动入口：launch 创建 Tk 窗口并可立即打开文件，main 解析 fangida-gui 命令行。

_Browser、launch 与 Path 在调用时经 fangida.gui 门面查找，对门面打的补丁仍然生效。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .facade import _gui


def launch(path: str | Path | None = None, *, max_bytes: int | None = None,
           use_ghidra: bool | None = None,
           deep_analysis: bool | None = None,
           semantic_threads: int | None = None,
           full_analysis: bool = False,
           database_path: str | Path | None = None,
           open_database_path: str | Path | None = None,
           snapshot_id: int | None = None,
           storage_plugin: str = "sqlite_storage") -> int:
    """Launch the optional Tk browser and optionally open a file immediately."""
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError as exc:
        raise RuntimeError("Tkinter is unavailable in this Python installation") from exc
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise RuntimeError("The desktop GUI needs a graphical display") from exc
    if path is not None and open_database_path is not None:
        root.destroy()
        raise ValueError("Choose either a source file or an analysis database")
    browser = _gui()._Browser(root, tk, ttk, filedialog, messagebox, max_bytes, use_ghidra,
                              deep_analysis, semantic_threads, full_analysis, database_path,
                              storage_plugin)
    if open_database_path is not None:
        root.after(0, browser.open_database, open_database_path, snapshot_id)
    elif path is not None:
        root.after(0, browser.open_file, path)
    root.mainloop()
    return 0


def main(argv: list[str] | None = None) -> int:
    """Console entry point for ``fangida-gui [file]``."""
    parser = argparse.ArgumentParser(prog="fangida-gui")
    parser.add_argument("file", nargs="?", help="File to inspect on startup")
    parser.add_argument("--database", type=_gui().Path, help="Save completed analysis through the storage plugin")
    parser.add_argument("--open-database", type=_gui().Path,
                        help="Browse an existing analysis database without reanalysis")
    parser.add_argument("--snapshot-id", type=int, help="Snapshot ID to open (default: newest)")
    parser.add_argument("--max-bytes", type=int, help="Maximum bytes scanned")
    parser.add_argument("--ghidra", action="store_true", help="Enable installed Ghidra supplement")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fast", action="store_true", help="Skip deeper native function analysis")
    mode.add_argument("--full", action="store_true", help="Scan all executable native regions; recover functions, CFGs and xrefs")
    parser.add_argument("--threads", type=int, help="Native semantic workers (1–16)")
    args = parser.parse_args(argv)
    if args.open_database is not None and (args.file is not None or args.database is not None):
        parser.error("--open-database cannot be combined with a source file or --database")
    if args.open_database is not None and (args.max_bytes is not None or args.ghidra or args.fast or
                                           args.full or args.threads is not None):
        parser.error("Analysis options cannot be combined with --open-database")
    if args.snapshot_id is not None and (args.open_database is None or args.snapshot_id <= 0):
        parser.error("--snapshot-id requires --open-database and a positive snapshot ID")
    if args.max_bytes is not None and args.max_bytes <= 0:
        parser.error("--max-bytes must be a positive integer")
    if args.threads is not None and not 1 <= args.threads <= 16:
        parser.error("--threads must be between 1 and 16")
    try:
        return _gui().launch(args.file, max_bytes=args.max_bytes,
                             use_ghidra=True if args.ghidra else None,
                             deep_analysis=False if args.fast else None,
                             semantic_threads=args.threads,
                             **({"full_analysis": True} if args.full else {}),
                             **({"database_path": args.database} if args.database is not None else {}),
                             **({"open_database_path": args.open_database} if args.open_database is not None else {}),
                             **({"snapshot_id": args.snapshot_id} if args.snapshot_id is not None else {}))
    except RuntimeError as exc:
        print(f"fangida-gui: {exc}", file=sys.stderr)
        return 2
