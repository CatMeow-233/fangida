"""分析与存储操作：后台分析、分析数据库读写与标注、十六进制源校验，以及为界面准备结果。

这些函数在工作线程中调用，不触碰 Tk 控件。分析服务、插件管理器、源文件指纹、配置读取、
源校验以及结果适配函数和常量等原模块级名字在调用时经 fangida.gui 门面查找（见 facade._gui），
对门面打的补丁因此仍然生效；由 fangida.gui 门面再导出。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .facade import _gui

# gui_modules 不直接导入 api、dispatcher、plugins 等分析实现（见 tests/test_gui_workbench.py 的依赖检查）：
# 注解里的 AnalysisView 由 fangida.gui 门面注入本模块（保持 typing.get_type_hints 可解析）；
# 运行时引用的原 fangida.gui 模块级名字（AnalysisView、AnalysisService、PluginManager、Path 等导入的
# 名字，以及函数、类和常量）一律经门面 _gui() 查找，对门面打的补丁因此仍作用于实现，与拆分前一致。


def _analyze_file(path: str | Path, max_bytes: int | None,
                  use_ghidra: bool | None, deep_analysis: bool | None,
                  semantic_threads: int | None = None,
                  full_analysis: bool = False,
                  analyze_threads: int | None = None,
                  on_preview: Any = None) -> AnalysisView:
    file_path = _gui().Path(path).expanduser().resolve()
    before = file_path.stat()
    signature = (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns)
    source_hash, source_size = _gui().fingerprint(file_path)
    settings = _gui().load_settings(project_dir=file_path.parent)
    if semantic_threads is not None:
        settings = _gui().replace(settings, semantic_threads=semantic_threads,
                           analyze_threads=max(settings.analyze_threads,
                                               semantic_threads + int(semantic_threads > 1))).validated()
    if analyze_threads is not None:
        # 显式的总线程预算（GUI 关闭多线程时为 1：解码与 xref 依次在同一线程执行）。
        settings = _gui().replace(settings, analyze_threads=analyze_threads,
                           semantic_threads=min(settings.semantic_threads,
                                                max(1, analyze_threads - int(analyze_threads > 1)))).validated()
    with _gui().AnalysisService(settings) as service:
        result = service.analyze(file_path, max_bytes=max_bytes,
                                 use_ghidra=use_ghidra,
                                 deep_analysis=deep_analysis,
                                 full_analysis=full_analysis,
                                 **({"on_preview": on_preview} if on_preview is not None else {}))
    after = file_path.stat()
    if signature != (after.st_dev, after.st_ino, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns):
        raise _gui().SourceChangedError("Source changed during analysis; reopen the file before saving")
    result.metadata.setdefault("source_sha256", source_hash)
    result.metadata.setdefault("source_size", source_size)
    return _gui().AnalysisView._from_owned_result(result)


def _database_view(path: str | Path, snapshot_id: int | None = None, *,
                   storage_plugin: str = "sqlite_storage") -> AnalysisView:
    """Read through the storage protocol; original bytes are not required."""
    manager = _gui().PluginManager()
    try:
        source = _gui().Path(path).expanduser().resolve()
        writable = (bool(source.stat().st_mode & 0o222) and os.access(source, os.W_OK) and
                    bool(source.parent.stat().st_mode & 0o222) and os.access(source.parent, os.W_OK))
        database = manager.load_storage(storage_plugin).open_database(
            source, read_only=not writable, create=False)
        try:
            snapshot = database.get_snapshot(snapshot_id)
            return (_gui().AnalysisView._from_owned_snapshot(snapshot) if storage_plugin == "sqlite_storage"
                    else _gui().AnalysisView.from_snapshot(snapshot))
        finally:
            database.close()
    finally:
        manager.teardown()


def _save_database_view(view: AnalysisView, path: str | Path, *,
                        storage_plugin: str = "sqlite_storage") -> AnalysisView:
    """Persist a completed snapshot without launching another analysis."""
    # The default provider serializes completed input without mutation. Other
    # providers retain the previous isolated-copy contract.
    snapshot = view._snapshot if storage_plugin == "sqlite_storage" else view.snapshot()
    source = snapshot["path"]
    if not _gui().Path(source).expanduser().is_file():
        raise FileNotFoundError("Original source is required when first saving an analysis database")
    metadata = snapshot.get("metadata", {})
    saved_info = metadata.get("analysis_database", {})
    expected = saved_info.get("source_sha256") or metadata.get("source_sha256")
    manager = _gui().PluginManager()
    try:
        database = manager.load_storage(storage_plugin).open_database(
            path, read_only=False, create=True)
        try:
            snapshot_id = database.save_analysis(source, snapshot, expected_hash=expected)
            # A verified, unannotated result is already the exact evidence we
            # just saved. Reopening its compressed IR would add a full read
            # before the GUI could display the completed analysis. Existing
            # database annotations still require the provider's normal overlay.
            source_size = saved_info.get("source_size", metadata.get("source_size"))
            user_annotations = metadata.get("user_annotations", {})
            annotation_reader = getattr(database, "annotations", None)
            if (storage_plugin == "sqlite_storage" and callable(annotation_reader)
                    and isinstance(expected, str) and type(source_size) is int and source_size >= 0
                    and isinstance(user_annotations, dict)
                    and not user_annotations.get("renames") and not user_annotations.get("comments")):
                annotations = annotation_reader(snapshot_id)
                if (annotations["sha256"] == expected and not annotations["renames"]
                        and not annotations["comments"]):
                    restored = {**snapshot, "metadata": {**metadata,
                        "user_annotations": {"sha256": expected, "renames": {}, "comments": {}},
                        "analysis_database": {"path": str(database.path), "snapshot_id": snapshot_id,
                            "format": database.info()["format"], "source_sha256": expected,
                            "source_size": source_size, "read_only": database.read_only}}}
                    return _gui().AnalysisView._from_owned_snapshot(restored)
            restored = database.get_snapshot(snapshot_id)
            return (_gui().AnalysisView._from_owned_snapshot(restored) if storage_plugin == "sqlite_storage"
                    else _gui().AnalysisView.from_snapshot(restored))
        finally:
            database.close()
    finally:
        manager.teardown()


def _annotation_index(snapshot: dict[str, Any]) -> dict[int, list[dict[str, Any]]]:
    """快照里所有带整数 address/start/addr 的字典，按地址分组（与存储层叠加标注的规则相同）。

    共享的同一对象只记录一次。只读结构，不修改快照；一次构建后可供多次标注复用。
    """
    index: dict[int, list[dict[str, Any]]] = {}
    seen: set[int] = set()
    stack: list[Any] = [snapshot]
    pop, push = stack.pop, stack.append
    while stack:
        value = pop()
        identity = id(value)
        if identity in seen:
            continue
        seen.add(identity)
        if isinstance(value, dict):
            address = value.get("address", value.get("start", value.get("addr")))
            if type(address) is int:
                index.setdefault(address, []).append(value)
            for item in value.values():
                if isinstance(item, (dict, list)):
                    push(item)
        else:
            for item in value:
                if isinstance(item, (dict, list)):
                    push(item)
    return index


def _annotation_targets(snapshot: dict[str, Any]) -> dict[int, dict[str, Any] | list[dict[str, Any]]]:
    """与 _annotation_index 相同的分组与组内顺序，但更省内存，供 GUI 标注缓存使用。

    值为单个 dict；只有同一地址有多条记录时才是 list（顺序与 _annotation_index 逐对象相同）。
    遍历顺序与 _annotation_index 完全相同，只是不再为每个对象记录 id：
    - 带地址的字典按“是否已在该地址的分组里”（对象身份）去重，二者等价——它被首次访问时
      正好加入分组；
    - 无地址、但含 dict/list 子项的容器才记入 seen；
    - 不含容器子项的叶子容器重复访问既不建索引也不压栈，没有任何效果，因此不必记录。
    任何环都只经过前两类容器，所以遍历一定终止。
    """
    index: dict[int, Any] = {}
    large: dict[int, set[int]] = {}  # 记录多的地址改用 id 集合去重，避免逐个比较退化成平方
    seen: set[int] = set()
    stack: list[Any] = [snapshot]
    pop, push = stack.pop, stack.append
    while stack:
        value = pop()
        if isinstance(value, dict):
            address = value.get("address", value.get("start", value.get("addr")))
            if type(address) is int:
                slot = index.get(address)
                if slot is None:
                    index[address] = value
                elif type(slot) is list:
                    ids = large.get(address)
                    if ids is not None:
                        if id(value) in ids:
                            continue
                        ids.add(id(value))
                    else:
                        if any(item is value for item in slot):
                            continue
                        if len(slot) >= 8:
                            large[address] = {id(item) for item in slot}
                            large[address].add(id(value))
                    slot.append(value)
                elif slot is value:
                    continue
                else:
                    index[address] = [slot, value]
                for item in value.values():
                    if isinstance(item, (dict, list)):
                        push(item)
                continue
            identity = id(value)
            if identity in seen:
                continue
            depth = len(stack)
            for item in value.values():
                if isinstance(item, (dict, list)):
                    push(item)
        else:
            identity = id(value)
            if identity in seen:
                continue
            depth = len(stack)
            for item in value:
                if isinstance(item, (dict, list)):
                    push(item)
        if len(stack) != depth:
            seen.add(identity)
    return index


def _apply_annotation(snapshot: dict[str, Any], index: dict[int, Any],
                      operation: str, address: int, value: str) -> None:
    """在内存快照上施加一条标注，结果与从数据库重新读出（叠加全部标注）相同。

    index 可以是 _annotation_index（值总是 list）或 _annotation_targets（单条记录时值为 dict）的结果。
    """
    annotations = snapshot.setdefault("metadata", {}).setdefault("user_annotations", {})
    renames = annotations.setdefault("renames", {})
    comments = annotations.setdefault("comments", {})
    key = str(address)
    targets = index.get(address, ())
    if isinstance(targets, dict):
        targets = (targets,)  # _annotation_targets 中只有一条记录的地址直接存记录本身
    if operation == "rename_symbol":
        for record in targets:
            if "name" in record:
                record.setdefault("original_name", record["name"])
                record["name"] = value
        renames[key] = value
        return
    annotated = key in comments  # 已有用户注释：原始注释（若有）已保存在 original_comment
    for record in targets:
        if value == "":
            if "original_comment" in record:
                record["comment"] = record.pop("original_comment")
            else:
                record.pop("comment", None)
        else:
            if "comment" in record and not annotated:
                record.setdefault("original_comment", record["comment"])
            record["comment"] = value
    if value == "":
        comments.pop(key, None)
    else:
        comments[key] = value


def _annotate_owned_view(view: AnalysisView, operation: str, address: int, value: str, *,
                         storage_plugin: str = "sqlite_storage", cache: dict[str, Any] | None = None
                         ) -> AnalysisView:
    """写入数据库后直接更新 GUI 自己持有的快照，不再从数据库重新读出整个快照。

    大文件重新读库要十几秒（全部指令解压与解析），而写入一条标注只需毫秒。非默认存储
    插件仍走原来的“写入后重新读出”路径。cache 用于跨多次标注复用地址索引。
    """
    if storage_plugin != "sqlite_storage":
        return _gui()._annotate_database_view(view, operation, address, value,
                                              storage_plugin=storage_plugin)
    snapshot = view._snapshot
    info = dict(snapshot.get("metadata", {}).get("analysis_database", {}))
    if not info.get("path") or info.get("snapshot_id") is None:
        raise ValueError("Save this analysis to a database before editing names or comments")
    if info.get("read_only"):
        raise ValueError("The analysis database is read-only")
    if operation not in {"rename_symbol", "set_comment"}:
        raise ValueError("Unknown annotation operation")
    manager = _gui().PluginManager()
    try:
        database = manager.load_storage(storage_plugin).open_database(info["path"], read_only=False, create=False)
        try:
            getattr(database, operation)(info["snapshot_id"], address, value)
        finally:
            database.close()
    finally:
        manager.teardown()
    if cache is not None and cache.get("snapshot") is snapshot:
        index = cache["index"]
    else:
        if cache is not None:
            # 先丢弃旧快照的索引再建新索引，两份索引不同时存活（大文件上各有数 GB）。
            cache.clear()
        index = _gui()._annotation_targets(snapshot)
        if cache is not None:
            cache.update(snapshot=snapshot, index=index)
    _gui()._apply_annotation(snapshot, index, operation, address, value)
    return _gui().AnalysisView._from_owned_snapshot(snapshot)


def _annotate_database_view(view: AnalysisView, operation: str, address: int,
                            value: str, *, storage_plugin: str = "sqlite_storage") -> AnalysisView:
    # The completed view is isolated and immutable here. Read just its database
    # identity; copying all decoded instructions would not help an annotation.
    info = dict(view._snapshot.get("metadata", {}).get("analysis_database", {}))
    if not info.get("path") or info.get("snapshot_id") is None:
        raise ValueError("Save this analysis to a database before editing names or comments")
    if info.get("read_only"):
        raise ValueError("The analysis database is read-only")
    if operation not in {"rename_symbol", "set_comment"}:
        raise ValueError("Unknown annotation operation")
    manager = _gui().PluginManager()
    try:
        database = manager.load_storage(storage_plugin).open_database(
            info["path"], read_only=False, create=False)
        try:
            getattr(database, operation)(info["snapshot_id"], address, value)
            restored = database.get_snapshot(info["snapshot_id"])
            return (_gui().AnalysisView._from_owned_snapshot(restored) if storage_plugin == "sqlite_storage"
                    else _gui().AnalysisView.from_snapshot(restored))
        finally:
            database.close()
    finally:
        manager.teardown()


@dataclass
class _Loaded:
    view: AnalysisView
    summary: str
    tables: dict[str, list[dict[str, Any]]]
    cfgs: list[dict[str, Any]]
    path: str
    kind: str
    status: str
    warnings: list[str]
    hex_path: Path | None = None
    hex_unavailable: str = ""
    hex_identity: tuple[int, int, int, int, int] | None = None
    navigation_index: Any = None
    pseudocode_context: Any = None
    # 完整分析解码完成后的渐进式预览（函数尚无 CFG）；最终结果到达后被替换。
    preview: bool = False


def _hex_source(snapshot: dict[str, Any]) -> tuple[Path | None, str]:
    """Database snapshots contain results; hex must come from matching source bytes."""
    source, reason, _ = _gui()._verified_hex_source(snapshot)
    return source, reason


def _verified_hex_source(snapshot: dict[str, Any]) -> tuple[
        Path | None, str, tuple[int, int, int, int, int] | None]:
    source = _gui().Path(snapshot["path"]).expanduser()
    metadata = snapshot.get("metadata", {})
    info = metadata.get("analysis_database", {})
    if not source.is_file():
        return None, ("Original source is unavailable. The database stores analysis, names and "
                      "comments; original binary bytes are not embedded."), None
    expected = info.get("source_sha256") or metadata.get("source_sha256")
    try:
        identity = _gui()._file_identity(source.stat())
        if expected:
            digest, _ = _gui().fingerprint(source)
            if digest != expected:
                return None, ("Original source no longer matches this snapshot; hex view is disabled. "
                              "Reopen the source or database."), None
        if _gui()._file_identity(source.stat()) != identity:
            return None, ("Original source changed while verifying; hex view is disabled. "
                          "Reopen the source or database."), None
    except (OSError, ValueError, _gui().SourceChangedError) as exc:
        return None, (f"Original source cannot be verified: {exc}. "
                      "Reopen the source or database."), None
    return source, "", identity


def _prepare(view: AnalysisView, *, share_completed: bool = False) -> _Loaded:
    """Prepare detached adapters, or opt into the GUI's read-only full graph.

    Existing callers retain isolated records and the original entry preview.
    The controller only reads completed data, so its worker can explicitly
    share that graph while keeping every instruction available for paging.
    """
    # 表格行与导航索引同样是一次性批量创建的长期对象：期间暂停自动循环 GC。
    from .._gc import bulk_allocation
    with bulk_allocation():
        return _gui()._prepare_tables(view, share_completed=share_completed)


def _prepare_tables(view: AnalysisView, *, share_completed: bool = False) -> _Loaded:
    is_full = view._snapshot.get("stats", {}).get("full_analysis")
    shared_full = is_full and share_completed
    snapshot = view._snapshot if shared_full else view.snapshot()
    hex_path, hex_unavailable, hex_identity = _gui()._verified_hex_source(snapshot)
    if snapshot.get("stats", {}).get("full_analysis"):
        # Only function display headers need extra fields. Completed IR and
        # CFG records can be shared read-only; default adapters remain isolated.
        loaded = _gui()._Loaded(view, _gui()._summary_snapshot(snapshot),
                                _gui()._full_tables(snapshot, disassembly_limit=None if shared_full else 1000),
                                _gui()._cfg_graphs_snapshot(snapshot), snapshot["path"], snapshot["kind"],
                                snapshot["status"], snapshot["warnings"], hex_path, hex_unavailable, hex_identity)
    else:
        loaded = _gui()._Loaded(view, _gui().summary_text(view), _gui().table_data(view),
                                _gui().cfg_graphs(view), snapshot["path"],
                                snapshot["kind"], snapshot["status"], snapshot["warnings"], hex_path, hex_unavailable,
                                hex_identity)
    if share_completed:
        # Build navigation indexes on the worker, never in the Tk event loop.
        from .navigation import AddressIndex
        loaded.navigation_index = AddressIndex(loaded.tables, loaded.cfgs, kind=loaded.kind)
        if loaded.tables.get("Pseudocode"):
            # 伪代码视图的符号表（函数名、字符串、区段）同样在后台线程建立。
            loaded.pseudocode_context = _gui()._pseudocode_context(loaded.tables)
    return loaded


def _pseudocode_context(tables: dict[str, list[dict[str, Any]]]) -> Any:
    """只读已完成的结果表，建立伪代码跳转与函数头使用的符号上下文。"""
    from .pseudocode import build_symbol_context
    return build_symbol_context(functions=tables.get("Functions", ()),
                                imports=tables.get("Imports", ()),
                                exports=tables.get("Exports", ()),
                                strings=tables.get("Strings", ()),
                                sections=tables.get("Sections", ()),
                                pseudocode=tables.get("Pseudocode", ()))
