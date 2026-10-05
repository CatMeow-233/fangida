"""Lazy core loading with a small stable plugin contract."""
from __future__ import annotations
from importlib import import_module
import inspect
from threading import Event, RLock
from typing import Any, Callable, Iterable, Protocol
from ..models import AnalysisResult, AnalysisTask
from .interfaces import Plugin, PseudocodePlugin, StoragePlugin, BranchSolverPlugin


def _accepts_keyword(function: Callable[..., Any], name: str) -> bool:
    """可调用对象是否接受该关键字参数（含 **kwargs）；无法获取签名时按不接受处理。"""
    try:
        parameters = inspect.signature(function).parameters
    except (TypeError, ValueError):
        return False
    return name in parameters or any(item.kind is inspect.Parameter.VAR_KEYWORD
                                     for item in parameters.values())

MODULES = {"kkagent": "fangida.core.kkagent", "apk_analyzer": "fangida.core.apk_analyzer"}
STORAGE_MODULES = {"sqlite_storage": "fangida.plugins.sqlite_storage"}
PSEUDOC_MODULES = {"native_pseudoc": "fangida.plugins.pseudoc.native",
                   "bytecode_pseudoc": "fangida.plugins.pseudoc.bytecode"}
BRANCH_SOLVER_MODULES = {"arm64_br_solver": "fangida.plugins.br_solver"}
RESOURCE_POOLS = frozenset({"io", "parse", "analyze", "native"})
DEFAULT_ROUTES = {
    **{kind: ("kkagent", "analyze") for kind in ("elf", "pe", "macho", "unknown")},
    **{kind: ("apk_analyzer", "parse") for kind in ("apk", "dex", "jar", "class")},
}

class PluginManager:
    def __init__(self) -> None:
        self._loaded: dict[str, Plugin] = {}
        self._factories: dict[str, Callable[[], Plugin]] = {}
        self._storage_loaded: dict[str, StoragePlugin] = {}
        self._storage_factories: dict[str, Callable[[], StoragePlugin]] = {}
        self._pseudoc_loaded: dict[str, PseudocodePlugin] = {}
        self._pseudoc_factories: dict[str, Callable[[], PseudocodePlugin]] = {}
        self._branch_solver_loaded: dict[str, BranchSolverPlugin] = {}
        self._branch_solver_factories: dict[str, Callable[[], BranchSolverPlugin]] = {}
        self._routes = DEFAULT_ROUTES.copy()
        self._lock = RLock()

    def register(self, name: str, factory: Callable[[], Plugin], *,
                 kinds: Iterable[str] = (), pool: str = "analyze",
                 replace_routes: bool = False) -> None:
        """Register a lazy factory and explicit routes on this manager only.

        Names cannot replace built-in, registered, or loaded plugins. Replacing
        a route requires opt-in and its previous plugin must still be unloaded.
        Registration performs no discovery, import, installation, or startup.
        """
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Plugin name must be a non-empty string")
        if not callable(factory):
            raise TypeError("Plugin factory must be callable")
        if isinstance(kinds, (str, bytes)):
            raise TypeError("Plugin kinds must be an iterable of strings")
        registered_kinds = tuple(kinds)
        if any(not isinstance(kind, str) or not kind.strip() for kind in registered_kinds):
            raise ValueError("Plugin kinds must be non-empty strings")
        if not isinstance(pool, str) or pool not in RESOURCE_POOLS:
            raise ValueError(f"Unknown resource pool: {pool}")
        if type(replace_routes) is not bool:
            raise TypeError("replace_routes must be a boolean")
        with self._lock:
            if (name in MODULES or name in self._factories or name in self._loaded or
                    name in STORAGE_MODULES or name in self._storage_factories or
                    name in self._storage_loaded or name in PSEUDOC_MODULES or
                    name in self._pseudoc_factories or name in self._pseudoc_loaded or
                    name in BRANCH_SOLVER_MODULES or name in self._branch_solver_factories or
                    name in self._branch_solver_loaded):
                raise ValueError(f"Plugin already registered or loaded: {name}")
            for kind in registered_kinds:
                previous = self._routes.get(kind)
                if previous is None:
                    continue
                if not replace_routes:
                    raise ValueError(f"Plugin route already registered: {kind}")
                if previous[0] in self._loaded:
                    raise ValueError(f"Cannot replace loaded plugin route: {kind}")
            self._factories[name] = factory
            for kind in registered_kinds:
                self._routes[kind] = (name, pool)

    def route(self, kind: str) -> tuple[str, str]:
        """Return the selected plugin and resource pool without loading it."""
        if not isinstance(kind, str) or not kind.strip():
            raise ValueError("File kind must be a non-empty string")
        with self._lock:
            return self._routes.get(kind, ("kkagent", "analyze"))

    def load(self, name: str) -> Plugin:
        with self._lock:
            if name not in MODULES and name not in self._factories:
                raise ValueError(f"Unknown plugin: {name}")
            if name not in self._loaded:
                factory = self._factories.get(name)
                plugin: Plugin = (factory() if factory is not None
                                  else import_module(MODULES[name]).PluginImpl())
                self._loaded[name] = plugin
            return self._loaded[name]

    def register_storage(self, name: str, factory: Callable[[], StoragePlugin]) -> None:
        """Register a lazy storage provider without changing analyzer routes."""
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Plugin name must be a non-empty string")
        if not callable(factory):
            raise TypeError("Plugin factory must be callable")
        with self._lock:
            if (name in MODULES or name in STORAGE_MODULES or name in self._factories or
                    name in self._storage_factories or name in self._loaded or
                    name in self._storage_loaded or name in PSEUDOC_MODULES or
                    name in self._pseudoc_factories or name in self._pseudoc_loaded or
                    name in BRANCH_SOLVER_MODULES or name in self._branch_solver_factories or
                    name in self._branch_solver_loaded):
                raise ValueError(f"Plugin already registered or loaded: {name}")
            self._storage_factories[name] = factory

    def load_storage(self, name: str = "sqlite_storage") -> StoragePlugin:
        """Load only the chosen persistence provider, once per manager."""
        with self._lock:
            if name not in STORAGE_MODULES and name not in self._storage_factories:
                raise ValueError(f"Unknown storage plugin: {name}")
            if name not in self._storage_loaded:
                factory = self._storage_factories.get(name)
                provider = (factory() if factory is not None else
                            import_module(STORAGE_MODULES[name]).PluginImpl())
                if not isinstance(provider, StoragePlugin):
                    raise TypeError(f"Storage plugin does not implement the storage protocol: {name}")
                self._storage_loaded[name] = provider
            return self._storage_loaded[name]

    def register_pseudocode(self, name: str,
                            factory: Callable[[], PseudocodePlugin]) -> None:
        """Register a lazy pseudo-C provider without changing analyzer routes."""
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Plugin name must be a non-empty string")
        if not callable(factory):
            raise TypeError("Plugin factory must be callable")
        with self._lock:
            if (name in MODULES or name in STORAGE_MODULES or name in PSEUDOC_MODULES or
                    name in self._factories or name in self._storage_factories or
                    name in self._pseudoc_factories or name in self._loaded or
                    name in self._storage_loaded or name in self._pseudoc_loaded or
                    name in BRANCH_SOLVER_MODULES or name in self._branch_solver_factories or
                    name in self._branch_solver_loaded):
                raise ValueError(f"Plugin already registered or loaded: {name}")
            self._pseudoc_factories[name] = factory

    def load_pseudocode(self, name: str = "native_pseudoc") -> PseudocodePlugin:
        """Load a snapshot renderer independently of loaders and processors."""
        with self._lock:
            if name not in PSEUDOC_MODULES and name not in self._pseudoc_factories:
                raise ValueError(f"Unknown pseudocode plugin: {name}")
            if name not in self._pseudoc_loaded:
                factory = self._pseudoc_factories.get(name)
                provider = (factory() if factory is not None else
                            import_module(PSEUDOC_MODULES[name]).PluginImpl())
                if not isinstance(provider, PseudocodePlugin):
                    raise TypeError(f"Pseudocode plugin does not implement the protocol: {name}")
                self._pseudoc_loaded[name] = provider
            return self._pseudoc_loaded[name]

    def register_branch_solver(self, name: str, factory: Callable[[], BranchSolverPlugin]) -> None:
        """注册独立求解提供者；不会修改文件类型路由或启动分析。"""
        if not isinstance(name, str) or not name.strip() or not callable(factory):
            raise ValueError("Branch solver requires a name and callable factory")
        with self._lock:
            if any(name in collection for collection in (MODULES, STORAGE_MODULES, PSEUDOC_MODULES,
                    BRANCH_SOLVER_MODULES, self._factories, self._loaded, self._storage_factories,
                    self._storage_loaded, self._pseudoc_factories, self._pseudoc_loaded,
                    self._branch_solver_factories, self._branch_solver_loaded)):
                raise ValueError(f"Plugin already registered or loaded: {name}")
            self._branch_solver_factories[name] = factory

    def load_branch_solver(self, name: str = "arm64_br_solver") -> BranchSolverPlugin:
        """只有显式调用这个入口才导入插件，Unicorn 仍到仿真阶段才加载。"""
        with self._lock:
            if name not in BRANCH_SOLVER_MODULES and name not in self._branch_solver_factories:
                raise ValueError(f"Unknown branch solver: {name}")
            if name not in self._branch_solver_loaded:
                factory = self._branch_solver_factories.get(name)
                provider = (factory() if factory is not None else
                            import_module(BRANCH_SOLVER_MODULES[name]).PluginImpl())
                if not isinstance(provider, BranchSolverPlugin):
                    raise TypeError(f"Branch solver does not implement the protocol: {name}")
                self._branch_solver_loaded[name] = provider
            return self._branch_solver_loaded[name]

    def analyze(self, name: str, task: AnalysisTask,
                on_progress: Callable[[dict[str, Any]], None] | None = None,
                cancel: Event | None = None,
                on_preview: Callable[[AnalysisResult], None] | None = None) -> AnalysisResult:
        """Forward optional controls to plugins that implement them.

        A plugin with only the original analyze(task) contract continues to
        work. Such plugins can be stopped before dispatch but do not expose
        in-flight cancellation or progress until they opt in. ``on_preview``
        reaches only plugins whose ``analyze_with_control`` accepts it.
        """
        if cancel is not None and cancel.is_set():
            return AnalysisResult(task.path, task.kind, name, "error",
                                  warnings=["Analysis cancelled before dispatch"])
        plugin = self.load(name)
        controlled = getattr(plugin, "analyze_with_control", None)
        if callable(controlled):
            if on_preview is not None and _accepts_keyword(controlled, "on_preview"):
                return controlled(task, on_progress=on_progress, cancel=cancel, on_preview=on_preview)
            return controlled(task, on_progress=on_progress, cancel=cancel)
        return plugin.analyze(task)

    def teardown(self) -> None:
        with self._lock:
            first_error: BaseException | None = None
            try:
                for plugin in (*tuple(self._loaded.values()), *tuple(self._storage_loaded.values()),
                               *tuple(self._pseudoc_loaded.values()), *tuple(self._branch_solver_loaded.values())):
                    try:
                        plugin.teardown()
                    except BaseException as exc:
                        if first_error is None:
                            first_error = exc
            finally:
                self._loaded.clear()
                self._storage_loaded.clear()
                self._pseudoc_loaded.clear()
                self._branch_solver_loaded.clear()
            if first_error is not None:
                raise first_error
