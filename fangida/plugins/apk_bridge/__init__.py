"""Supervisor for a bounded pool of separate Android/JVM workers.

Each child handles one complete request. Separate input files may be analyzed
at the same time, without sharing ZIP handles or per-request budgets.
"""
from __future__ import annotations

from dataclasses import replace
from threading import Condition, Event
from time import monotonic
from typing import Any, Callable

from ...models import AnalysisResult, AnalysisTask
from .ipc import IPCClient


class PluginImpl:
    name = "apk_analyzer"
    version = "0.4.0"

    def __init__(self) -> None:
        # Keep the first client eagerly represented for the original plugin
        # API and diagnostics; each client starts its child only on demand.
        self._client = IPCClient()
        self._clients = [self._client]
        self._available = [self._client]
        self._active = 0
        self._closed = False
        self._condition = Condition()

    def capabilities(self) -> tuple[str, ...]:
        return ("metadata", "classes", "methods", "kotlin_metadata_hint", "pseudoc",
                "strings", "xrefs", "cfg", "manifest", "resources", "full_analysis", "external_backend")

    def analyze(self, task: AnalysisTask) -> AnalysisResult:
        return self.analyze_with_control(task)

    def analyze_with_control(self, task: AnalysisTask,
                             on_progress: Callable[[dict[str, Any]], None] | None = None,
                             cancel: Event | None = None) -> AnalysisResult:
        """Run independent file requests on at most four isolated children.

        The shared resource scheduler also caps concurrent requests by its
        parse pool. A request's worker timeout includes time spent waiting
        for an available child, and waiting can be cancelled.
        """
        configured = getattr(task, "parse_threads", 2)
        if type(configured) is not int or configured < 1:
            raise ValueError("parse_threads must be a positive integer")
        limit = min(configured, 4)
        timeout = min(max(float(task.worker_timeout_seconds), 0.001), 3600.0)
        deadline = monotonic() + timeout

        def failed(message: str) -> AnalysisResult:
            return AnalysisResult(task.path, task.kind, self.name, "error", warnings=[message])

        with self._condition:
            while True:
                if self._closed:
                    return failed("Android worker pool is closed")
                if cancel is not None and cancel.is_set():
                    return failed("Analysis cancelled waiting for an Android worker")
                remaining = deadline - monotonic()
                if remaining <= 0:
                    return failed("Android worker queue exceeded its timeout")
                if self._active < limit:
                    if self._available:
                        client = self._available.pop()
                    elif len(self._clients) < limit:
                        client = IPCClient()
                        self._clients.append(client)
                    else:
                        # A previous request used a larger limit. Wait for
                        # one of its children rather than creating another.
                        self._condition.wait(timeout=min(remaining, 0.05))
                        continue
                    self._active += 1
                    break
                self._condition.wait(timeout=min(remaining, 0.05))
        try:
            # The child client enforces the remaining request deadline.
            remaining = deadline - monotonic()
            if remaining <= 0:
                return failed("Android worker queue exceeded its timeout")
            return client.analyze(replace(task, worker_timeout_seconds=remaining),
                                  on_progress=on_progress, cancel=cancel)
        finally:
            with self._condition:
                self._active -= 1
                if self._closed:
                    close_client = True
                else:
                    self._available.append(client)
                    close_client = False
                self._condition.notify_all()
            if close_client:
                client.close()

    def teardown(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closed = True
            available = self._available[:]
            self._available.clear()
            self._condition.notify_all()
        for client in available:
            client.close()
