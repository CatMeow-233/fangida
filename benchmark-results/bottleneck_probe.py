#!/usr/bin/env python3
"""隔离测量数据库、GUI 准备与导出；不分析源文件、不创建 Tk 窗口。

从任意工作目录运行，例如：
    python3 /path/to/fangida/benchmark-results/bottleneck_probe.py SOURCE \
        --database EXISTING.fdb --runs 3 --output probe.json

已有数据库仅以 read_only=True 打开，所有数据库与导出写操作使用临时目录。
--profile 可额外生成恢复和导航索引的 cProfile 文本，只供归因。
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gc
import json
import os
from pathlib import Path
import platform
from statistics import median
import sys
import tempfile
import time
from typing import Any, Callable, TypeVar


# 直接运行本文件时，Python 默认只把 benchmark-results 放入导入路径。
REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY))
# 诊断执行不在产品目录生成新的字节码缓存。
sys.dont_write_bytecode = True

from fangida.api import AnalysisView
from fangida.gui import _prepare
from fangida.gui_modules.navigation import AddressIndex
from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase
from fangida.project import fingerprint


T = TypeVar("T")


def measure(operation: Callable[[], T]) -> tuple[T, dict[str, float]]:
    """计时中不插桩；GC 保持 Python 默认状态，显式收集在计时前。"""
    gc.collect()
    cpu_start = time.process_time()
    wall_start = time.perf_counter()
    result = operation()
    wall_seconds = time.perf_counter() - wall_start
    cpu_seconds = time.process_time() - cpu_start
    return result, {"wall_seconds": wall_seconds, "cpu_seconds": cpu_seconds}


def _annotation_address(view: AnalysisView) -> int:
    """选用已存在的指令/函数地址；不向解码器请求补充分析。"""
    snapshot = view._snapshot
    metadata = snapshot.get("metadata", {})
    for instructions in (metadata.get("full_disassembly", ()),
                         metadata.get("disassembly", ())):
        for instruction in instructions:
            if isinstance(instruction, dict) and type(instruction.get("addr")) is int:
                return instruction["addr"]
    for function in snapshot.get("functions", ()):
        if not isinstance(function, dict):
            continue
        for field in ("start", "address", "code_offset"):
            if type(function.get(field)) is int:
                return function[field]
    return 0


def _validate_source(snapshot: dict[str, Any], source_hash: str, source_size: int) -> None:
    metadata = snapshot.get("metadata", {})
    identity = metadata.get("analysis_database", {})
    if identity.get("source_sha256") != source_hash:
        raise ValueError("源文件 SHA-256 与数据库快照不匹配，已停止诊断")
    if identity.get("source_size") != source_size:
        raise ValueError("源文件大小与数据库快照不匹配，已停止诊断")


def _relocate_owned_view(view: AnalysisView, source: Path) -> bool:
    # 仅修改刚恢复的私有内存快照。源文件已验证，方便诊断原文件移动后的数据库。
    changed = Path(view._snapshot["path"]).expanduser().resolve() != source
    if changed:
        view._snapshot["path"] = str(source)
    return changed


def run_once(source: Path, database_path: Path, source_hash: str,
             source_size: int, run_number: int) -> dict[str, Any]:
    stages: dict[str, dict[str, float]] = {}
    original_database: SQLiteAnalysisDatabase | None = None
    temporary_database: SQLiteAnalysisDatabase | None = None
    annotation_database: SQLiteAnalysisDatabase | None = None
    # 每轮使用新临时目录；返回值只留标量，退出本函数释放全部大对象。
    with tempfile.TemporaryDirectory(prefix="fangida-bottleneck-probe-") as directory:
        temporary_path = Path(directory)
        try:
            original_database, stages["database_open_read_only"] = measure(
                lambda: SQLiteAnalysisDatabase(database_path, read_only=True, create=False))
            snapshot, stages["database_restore"] = measure(original_database.get_snapshot)
            original_database.close()
            original_database = None
            _validate_source(snapshot, source_hash, source_size)
            database_source = snapshot["path"]
            view, stages["owned_snapshot_to_view"] = measure(
                lambda: AnalysisView._from_owned_snapshot(snapshot))
            del snapshot
            source_relocated = _relocate_owned_view(view, source)

            loaded, stages["gui_prepare_including_navigation"] = measure(
                lambda: _prepare(view, share_completed=True))
            if loaded.hex_path is None:
                raise ValueError(f"GUI 准备没有通过源文件验证：{loaded.hex_unavailable}")
            table_counts = {name: len(rows) for name, rows in loaded.tables.items()}
            cfg_count = len(loaded.cfgs)
            # 独立索引计时为重复诊断，不应再加到 GUI prepare 总时间中。
            loaded.navigation_index = None
            navigation_index, stages["navigation_index_standalone"] = measure(
                lambda: AddressIndex(loaded.tables, loaded.cfgs, kind=loaded.kind))
            del navigation_index

            new_database_path = temporary_path / "new-analysis.fdb"
            temporary_database, stages["new_database_create"] = measure(
                lambda: SQLiteAnalysisDatabase(new_database_path, read_only=False, create=True))
            snapshot_id, stages["new_database_save_analysis"] = measure(
                lambda: temporary_database.save_analysis(source, view._snapshot,
                                                          expected_hash=source_hash))
            saved_database_bytes = new_database_path.stat().st_size
            temporary_database.close()
            temporary_database = None

            annotation_database, stages["annotation_database_open"] = measure(
                lambda: SQLiteAnalysisDatabase(new_database_path, read_only=False, create=False))
            annotation_address = _annotation_address(view)
            annotation_value = f"fangida bottleneck probe run {run_number}"
            _, stages["annotation_write_transaction"] = measure(
                lambda: annotation_database.set_comment(snapshot_id, annotation_address,
                                                         annotation_value))
            annotated_snapshot, stages["annotation_full_restore"] = measure(
                lambda: annotation_database.get_snapshot(snapshot_id))
            actual_comment = annotated_snapshot["metadata"]["user_annotations"]["comments"].get(
                str(annotation_address))
            if actual_comment != annotation_value:
                raise ValueError("临时数据库标注未通过恢复验证")
            annotated_view, stages["annotation_owned_snapshot_to_view"] = measure(
                lambda: AnalysisView._from_owned_snapshot(annotated_snapshot))
            del annotated_snapshot
            annotated_loaded, stages["annotation_gui_prepare_including_navigation"] = measure(
                lambda: _prepare(annotated_view, share_completed=True))
            # 把恢复后的导航重建也隔离测量；同样不能加到 prepare 中。
            annotated_loaded.navigation_index = None
            annotation_index, stages["annotation_navigation_index_standalone"] = measure(
                lambda: AddressIndex(annotated_loaded.tables, annotated_loaded.cfgs,
                                     kind=annotated_loaded.kind))
            del annotation_index

            export_path, stages["api_export_json"] = measure(
                lambda: annotated_view.export_json(temporary_path / "analysis.json"))
            export_bytes = export_path.stat().st_size
            if fingerprint(source) != (source_hash, source_size):
                raise ValueError("诊断期间源文件发生变化，结果无效")
            return {"run": run_number, "stages": stages, "table_counts": table_counts,
                    "cfg_count": cfg_count, "snapshot_kind": loaded.kind,
                    "full_analysis": bool(view._snapshot.get("stats", {}).get("full_analysis")),
                    "original_database_source": database_source,
                    "source_path_relocated_in_memory": source_relocated,
                    "saved_database_bytes": saved_database_bytes,
                    "export_json_bytes": export_bytes,
                    "annotation_address": annotation_address,
                    "annotation_restored_correctly": True}
        finally:
            for database in (annotation_database, temporary_database, original_database):
                if database is not None:
                    database.close()


def profile_attribution(database_path: Path, source: Path, source_hash: str,
                        source_size: int, output: Path) -> dict[str, str]:
    """在所有无插桩计时之后单独做归因，不把受插桩影响的时间填入样本。"""
    import cProfile
    import io
    import pstats

    def write_profile(profiler: cProfile.Profile, suffix: str) -> Path:
        report_path = output.with_name(f"{output.stem}-{suffix}-profile.txt")
        stream = io.StringIO()
        stream.write("此输出用于归因。cProfile 会扰动速度，不应与无插桩样本比较。\n\n")
        stats = pstats.Stats(profiler, stream=stream)
        stats.strip_dirs().sort_stats("cumulative").print_stats(50)
        stats.sort_stats("tottime").print_stats(50)
        report_path.write_text(stream.getvalue(), encoding="utf-8")
        return report_path

    database = SQLiteAnalysisDatabase(database_path, read_only=True, create=False)
    try:
        gc.collect()
        restore_profiler = cProfile.Profile()
        snapshot = restore_profiler.runcall(database.get_snapshot)
        restore_path = write_profile(restore_profiler, "database-restore")
    finally:
        database.close()
    _validate_source(snapshot, source_hash, source_size)
    view = AnalysisView._from_owned_snapshot(snapshot)
    del snapshot
    _relocate_owned_view(view, source)
    loaded = _prepare(view, share_completed=True)
    loaded.navigation_index = None
    gc.collect()
    index_profiler = cProfile.Profile()
    index = index_profiler.runcall(AddressIndex, loaded.tables, loaded.cfgs, kind=loaded.kind)
    del index
    index_path = write_profile(index_profiler, "navigation-index")
    return {"database_restore": str(restore_path), "navigation_index": str(index_path)}


STAGE_SCOPES = {
    "database_open_read_only": "原库 read_only=True 打开及格式/表结构校验，不含快照恢复",
    "database_restore": "原库最新快照恢复：读取、解压、JSON、共享指令引用展开及已有标注覆盖",
    "owned_snapshot_to_view": "GUI 私有快照接管与兼容字段校验，不做公共 API 深复制",
    "gui_prepare_including_navigation": "实际 _prepare(share_completed=True)，含源指纹验证、表投影、CFG列表与导航索引",
    "navigation_index_standalone": "对已准备的 rows/CFG 独立重建 AddressIndex；与上项重叠，不得相加",
    "new_database_create": "临时新库创建、迁移及校验，不含保存",
    "new_database_save_analysis": "已有结果首次保存，含源验证、收集去重、JSON、zlib(level=1)及事务提交，不重新分析",
    "annotation_database_open": "重新打开临时库，模拟标注工作线程的数据库校验，不含写入",
    "annotation_write_transaction": "set_comment 验证、连接、单条 SQL 写入及事务提交，不含快照恢复",
    "annotation_full_restore": "标注后调用 get_snapshot，全量恢复并覆盖标注",
    "annotation_owned_snapshot_to_view": "标注后 GUI 私有快照接管",
    "annotation_gui_prepare_including_navigation": "标注后实际 GUI _prepare，含源验证、表投影与导航重建",
    "annotation_navigation_index_standalone": "标注后独立导航重建诊断，与上一项重叠，不得相加",
    "api_export_json": "公开 AnalysisView.export_json：整份快照 JSON(indent=2)序列化及临时文件写入",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="只读原始二进制，用于指纹验证")
    parser.add_argument("--database", required=True, type=Path, help="只读已有 Fangida .fdb")
    parser.add_argument("--runs", type=int, default=3, help="顺序重复次数，默认 3")
    parser.add_argument("--output", required=True, type=Path, help="保存无插桩计时 JSON")
    parser.add_argument("--profile", action="store_true", help="计时完成后另生成恢复/导航 cProfile 文本")
    args = parser.parse_args(argv)
    if not 1 <= args.runs <= 100:
        parser.error("--runs 必须在 1 到 100 之间")
    source = args.source.expanduser().resolve(strict=True)
    database_path = args.database.expanduser().resolve(strict=True)
    output = args.output.expanduser().resolve()
    if not source.is_file() or not database_path.is_file():
        parser.error("源文件和数据库必须为普通文件")
    protected = {source, database_path, Path(f"{database_path}-wal"), Path(f"{database_path}-shm")}
    destinations = [output]
    if args.profile:
        destinations.extend(output.with_name(f"{output.stem}-{suffix}-profile.txt")
                            for suffix in ("database-restore", "navigation-index"))
    for destination in destinations:
        if destination in protected or any(destination.exists() and protected_path.exists()
                and destination.samefile(protected_path) for protected_path in protected):
            parser.error("报告路径不能覆盖源文件、原数据库或其 sidecar")
    output.parent.mkdir(parents=True, exist_ok=True)
    source_hash, source_size = fingerprint(source)
    measurements = []
    for run_number in range(1, args.runs + 1):
        print(f"诊断第 {run_number}/{args.runs} 轮：顺序运行，原库只读。", file=sys.stderr, flush=True)
        measurements.append(run_once(source, database_path, source_hash, source_size, run_number))
        gc.collect()
    summary = {stage: {metric: median(sample["stages"][stage][metric] for sample in measurements)
                       for metric in ("wall_seconds", "cpu_seconds")}
               for stage in STAGE_SCOPES}
    report: dict[str, Any] = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "repository": str(REPOSITORY), "source": str(source), "source_sha256": source_hash,
        "source_size_bytes": source_size, "database": str(database_path),
        "database_open_mode": "read_only=True", "runs": args.runs,
        "environment": {"python": platform.python_version(), "platform": platform.platform(),
                        "cpu_count": os.cpu_count()},
        "measurement_scope": {"includes": "数据库/已完成快照/导航索引/保存标注/JSON导出",
            "excludes": ["源文件分析", "Tk窗口创建与可见绘制", "GUI事件队列等待",
                         "解释器启动和模块导入", "临时目录清理", "报告序列化写入", "cProfile归因"],
            "gc": "每次计时前显式 gc.collect；计时期间保留 Python 默认自动GC，不插桩",
            "cache": "顺序重复；第一轮和后续轮均保留，OS缓存未强制清空",
            "writes": "数据库、标注与API导出仅写 TemporaryDirectory；报告写入 --output 指定位置",
            "sum_warning": "standalone 索引是独立重复诊断，与 GUI prepare 重叠，禁止重复相加",
            "cpu_seconds": "当前进程所有线程CPU，不含子进程"},
        "stage_scopes": STAGE_SCOPES, "samples": measurements, "median": summary,
    }
    if args.profile:
        report["profile_attribution"] = profile_attribution(database_path, source, source_hash,
                                                          source_size, output)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"无插桩诊断结果已保存：{output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
