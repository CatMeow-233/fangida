"""File identification and shared UI/headless scheduling path."""
from __future__ import annotations
from functools import partial
from pathlib import Path
from threading import Event
from typing import Any, Callable
from .models import AnalysisResult, AnalysisTask
from .loaders import identify_file
from .plugins.manager import PluginManager
from .resource_scheduler import ResourceScheduler
from .settings import Settings, load_settings
from .project import ProjectStore, fingerprint

MAGIC = ((b"\x7fELF", "elf"), (b"MZ", "pe"), (b"dex\n", "dex"))
MACHO = {b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"}
EXTENSIONS = {".elf": "elf", ".exe": "pe", ".dll": "pe", ".dylib": "macho", ".apk": "apk", ".dex": "dex", ".jar": "jar", ".class": "class"}

def identify(path: Path) -> tuple[str, str]:
    """Compatibility entry point; identification belongs to the loader layer."""
    return identify_file(path)

class AnalysisService:
    """Long-lived service shares plugins and bounded resource pools across requests."""
    def __init__(self, settings: Settings | None = None, manager: PluginManager | None = None,
                 project_path: str | Path | None = None,
                 database_path: str | Path | None = None,
                 storage_plugin: str = "sqlite_storage") -> None:
        if (project_path is not None and database_path is not None and
                Path(project_path).expanduser().resolve() == Path(database_path).expanduser().resolve()):
            raise ValueError("Legacy project and analysis database must use different paths")
        self.settings = (settings or load_settings()).validated()
        self.manager = manager or PluginManager()
        self.scheduler = ResourceScheduler(self.settings)
        self.project = None
        self.storage_plugin = storage_plugin
        self.database = None
        try:
            if project_path is not None:
                self.project = ProjectStore(project_path)
            if database_path is not None:
                self.database = self.manager.load_storage(storage_plugin).open_database(
                    database_path, read_only=False, create=True)
        except BaseException:
            try:
                self.scheduler.shutdown()
            finally:
                if manager is None:
                    self.manager.teardown()
            raise

    def analyze(self, path: str | Path, max_bytes: int | None = None,
                use_ghidra: bool | None = None,
                deep_analysis: bool | None = None,
                on_progress: Callable[[dict[str, Any]], None] | None = None,
                cancel: Event | None = None,
                full_analysis: bool | None = None,
                on_preview: Callable[[AnalysisResult], None] | None = None) -> AnalysisResult:
        """Analyze a file, optionally observing or cancelling analysis work.

        Progress runs in a scheduler thread. Android cancellation is checked
        between bounded members; worker timeout reaps a blocked child.
        ``on_preview`` (optional) receives one read-only partial result as soon
        as a full analysis has decoded every region, on the analysis thread;
        it should hand the result off and return quickly.
        """
        file_path = Path(path).expanduser().resolve(strict=True)
        if not file_path.is_file():
            raise ValueError(f"Not a regular file: {file_path}")
        for store in (self.project, self.database):
            if (store is not None and Path(store.path).exists() and
                    file_path.samefile(store.path)):
                raise ValueError("The input binary cannot also be the analysis database")
        full = self.settings.full_analysis if full_analysis is None else full_analysis
        if type(full) is not bool:
            raise ValueError("full_analysis must be boolean")
        cap = max_bytes if max_bytes is not None else (max(1, file_path.stat().st_size)
                                                     if full else self.settings.max_bytes)
        if type(cap) is not int or cap <= 0:
            raise ValueError("max_bytes must be a positive integer")
        with self.scheduler.slot("io"):
            kind, evidence = identify(file_path)
            source_fingerprint = (fingerprint(file_path) if self.project is not None or
                                  self.database is not None else None)
            source_hash = source_fingerprint[0] if source_fingerprint is not None else None
        if full and kind not in {"elf", "pe", "macho", "apk", "dex", "jar", "class"}:
            raise ValueError("Full analysis supports ELF, PE, Mach-O, APK, DEX, JAR and JVM class files")
        if full and max_bytes is None and kind in {"apk", "jar"}:
            # ZIP size is not the uncompressed bytecode budget.
            cap = self.settings.max_archive_uncompressed_bytes
        route = getattr(self.manager, "route", None)
        if callable(route):
            plugin_name, pool = route(kind)
        else:
            # Keep existing duck-typed managers that only expose analyze().
            plugin_name = "apk_analyzer" if kind in {"apk", "dex", "jar", "class"} else "kkagent"
            pool = "parse" if plugin_name == "apk_analyzer" else "analyze"
        task = AnalysisTask(
            path=str(file_path), kind=kind, max_bytes=cap,
            worker_timeout_seconds=self.settings.worker_timeout_seconds,
            max_archive_entries=self.settings.max_archive_entries,
            max_archive_uncompressed_bytes=self.settings.max_archive_uncompressed_bytes,
            use_ghidra=self.settings.ghidra_enabled if use_ghidra is None else use_ghidra,
            ghidra_timeout_seconds=self.settings.ghidra_timeout_seconds,
            ghidra_max_cpu=self.settings.ghidra_max_cpu,
            ghidra_decompiled_functions=self.settings.ghidra_decompiled_functions,
            ghidra_decompile_seconds=self.settings.ghidra_decompile_seconds,
            deep_analysis=self.settings.deep_analysis if deep_analysis is None else deep_analysis,
            semantic_max_functions=self.settings.semantic_max_functions,
            semantic_max_instructions=self.settings.semantic_max_instructions,
            semantic_threads=self.scheduler.semantic_workers,
            parse_threads=min(self.settings.parse_threads, 4),
            xref_threads=self.scheduler.xref_workers,
            full_analysis=full,
        )
        analyze = (self.manager.analyze if on_preview is None else
                   partial(self.manager.analyze, on_preview=on_preview))
        result = self.scheduler.submit(pool, analyze, plugin_name,
                                       task, on_progress, cancel).result()
        result.metadata["identification"] = evidence
        if self.project is not None and not (cancel is not None and cancel.is_set()):
            snapshot_id = self.project.save_analysis(file_path, result, expected_hash=source_hash)
            result.metadata["project_snapshot_id"] = snapshot_id
        if self.database is not None and not (cancel is not None and cancel.is_set()):
            result.metadata.update(source_sha256=source_hash, source_size=source_fingerprint[1])
            snapshot_id = self.database.save_analysis(file_path, result, expected_hash=source_hash)
            result.metadata["analysis_database"] = {
                "path": str(self.database.path), "snapshot_id": snapshot_id,
                "format": self.database.info()["format"], "source_sha256": source_hash,
                "source_size": source_fingerprint[1], "read_only": self.database.read_only,
            }
        return result

    def load_database(self, path: str | Path, snapshot_id: int | None = None, *,
                      storage_plugin: str | None = None) -> dict[str, Any]:
        """Restore completed evidence without invoking loaders or analyzers."""
        from .storage import database_session
        with database_session(path, manager=self.manager,
                              storage_plugin=storage_plugin or self.storage_plugin) as database:
            return database.get_snapshot(snapshot_id)

    def close(self) -> None:
        try:
            self.scheduler.shutdown()
        finally:
            try:
                if self.database is not None:
                    self.database.close()
            finally:
                self.manager.teardown()

    def __enter__(self) -> AnalysisService:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

def analyze(path: str | Path, manager: PluginManager | None = None,
            max_bytes: int | None = None,
            on_progress: Callable[[dict[str, Any]], None] | None = None,
            cancel: Event | None = None,
            full_analysis: bool | None = None) -> AnalysisResult:
    """Convenience one-shot API. Use AnalysisService for repeated requests."""
    with AnalysisService(manager=manager) as service:
        options = {} if full_analysis is None else {"full_analysis": full_analysis}
        return service.analyze(path, max_bytes, on_progress=on_progress, cancel=cancel, **options)
