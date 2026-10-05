"""Bounded, thread-safe resource pools for later asynchronous analyzers."""
from __future__ import annotations
from contextlib import contextmanager
from concurrent.futures import Future, ThreadPoolExecutor
from threading import BoundedSemaphore
from typing import Callable, Iterator, TypeVar
from .settings import Settings

T = TypeVar("T")

class ResourceScheduler:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings.validated()
        # Reference analysis owns a different thread whenever the analysis
        # budget permits it. Reserve that slot before allocating decoders.
        self.xref_workers = int(settings.analyze_threads > 1)
        self.semantic_workers = min(settings.semantic_threads,
                                    max(1, settings.analyze_threads - self.xref_workers))
        self._pool_threads = {name: getattr(settings, f"{name}_threads")
                              for name in ("io", "parse", "analyze", "native")}
        # Include the dedicated reference worker in each request's budget.
        self._pool_threads["analyze"] = max(
            1, settings.analyze_threads // (self.semantic_workers + self.xref_workers))
        self._limits = {name: BoundedSemaphore(count)
                        for name, count in self._pool_threads.items()}
        self._pending = {name: BoundedSemaphore(2 * count)
                         for name, count in self._pool_threads.items()}
        self._executors = {name: ThreadPoolExecutor(max_workers=count,
                                                   thread_name_prefix=f"fangida-{name}")
                           for name, count in self._pool_threads.items()}

    @contextmanager
    def slot(self, pool: str) -> Iterator[None]:
        if pool not in self._limits:
            raise ValueError(f"Unknown resource pool: {pool}")
        semaphore = self._limits[pool]
        semaphore.acquire()
        try:
            yield
        finally:
            semaphore.release()

    def submit(self, pool: str, function: Callable[..., T], *args: object) -> Future[T]:
        if pool not in self._executors:
            raise ValueError(f"Unknown resource pool: {pool}")
        if not self._pending[pool].acquire(blocking=False):
            raise RuntimeError(f"{pool} queue is full")
        def bounded() -> T:
            with self.slot(pool):
                return function(*args)
        try:
            future = self._executors[pool].submit(bounded)
        except BaseException:
            self._pending[pool].release()
            raise
        future.add_done_callback(lambda _: self._pending[pool].release())
        return future

    def shutdown(self) -> None:
        for executor in self._executors.values():
            executor.shutdown(cancel_futures=True)

    def __enter__(self) -> ResourceScheduler:
        return self

    def __exit__(self, *_: object) -> None:
        self.shutdown()
