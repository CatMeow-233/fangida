"""Bounded, persistent JSON-RPC client for the isolated Android worker.

The transport is intentionally small: one analysis at a time per worker,
notifications for progress/cancellation, and base64 pages for large results.
The worker is restarted after a crash; teardown reaps the child process.
"""
from __future__ import annotations

import base64
import hashlib
import json
import queue
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from typing import Any, Callable

from ...models import AnalysisResult, AnalysisTask

MAX_RPC_LINE = 512 * 1024
MAX_RESULT_BYTES = 256 * 1024 * 1024
PAGE_BYTES = 256 * 1024
INLINE_RESULT_BYTES = 128 * 1024


class WorkerError(RuntimeError):
    """A worker returned an error or an invalid response."""


class WorkerCrashed(WorkerError):
    """The worker terminated or broke its transport unexpectedly."""


class WorkerTimedOut(WorkerError):
    """A request exceeded its allotted wall time."""


ProgressCallback = Callable[[dict[str, Any]], None]


class IPCClient:
    """Serializes requests to a lazily started long-lived worker process."""

    def __init__(self, command: list[str] | None = None) -> None:
        self.command = command
        self._worker_environment = None
        self._process: subprocess.Popen[bytes] | None = None
        self._messages: queue.Queue[dict[str, Any] | BaseException] | None = None
        self._lock = threading.RLock()
        self._next_id = 0

    @property
    def pid(self) -> int | None:
        """Expose the current child PID for diagnostics and lifecycle tests."""
        with self._lock:
            return self._process.pid if self._process and self._process.poll() is None else None

    def _start(self) -> None:
        if self._process is not None and self._process.poll() is None:
            return
        self._stop()
        self._messages = queue.Queue(maxsize=64)
        from .runtime import worker_launch
        launch_command, launch_environment = worker_launch() if self.command is None else (self.command, None)
        self._process = subprocess.Popen(
            launch_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=-1, env=launch_environment,
        )
        process = self._process
        inbox = self._messages

        def deliver(value: dict[str, Any] | BaseException) -> None:
            try:
                inbox.put_nowait(value)
            except queue.Full:
                # The consumer can drain concurrently between these steps.
                try:
                    inbox.get_nowait()
                except queue.Empty:
                    pass
                inbox.put_nowait(value)

        def reader() -> None:
            assert process.stdout is not None
            try:
                while True:
                    line = process.stdout.readline(MAX_RPC_LINE + 1)
                    if not line:
                        raise WorkerCrashed("worker closed its output")
                    if len(line) > MAX_RPC_LINE or not line.endswith(b"\n"):
                        raise WorkerCrashed("worker response exceeds line limit")
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise WorkerCrashed("worker response must be an object")
                    # A cancelled caller may stop draining notifications.
                    # Prefer a response over old progress when bounded.
                    deliver(value)
            except (OSError, UnicodeError, ValueError, WorkerCrashed) as exc:
                # The client is waiting on this queue. Reader threads are bound
                # to their own queue so a restarted child cannot contaminate it.
                deliver(WorkerCrashed(str(exc)))

        threading.Thread(target=reader, name="fangida-android-ipc", daemon=True).start()

    def _stop(self) -> None:
        process = self._process
        self._process = None
        self._messages = None
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
        except OSError:
            pass
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        if process.stdout:
            process.stdout.close()

    def close(self) -> None:
        with self._lock:
            self._stop()

    def _send(self, request: dict[str, Any]) -> None:
        encoded = json.dumps(request, separators=(",", ":"), ensure_ascii=True).encode("utf-8") + b"\n"
        if len(encoded) > MAX_RPC_LINE:
            raise WorkerError("request exceeds line limit")
        process = self._process
        if process is None or process.stdin is None or process.poll() is not None:
            raise WorkerCrashed("worker is unavailable")
        try:
            process.stdin.write(encoded)
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise WorkerCrashed("worker input closed") from exc

    def _request(self, method: str, params: dict[str, Any], deadline: float,
                 progress: ProgressCallback | None = None,
                 cancel: threading.Event | None = None) -> Any:
        self._next_id += 1
        request_id = self._next_id
        request: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id,
                                   "method": method, "params": params}
        if method == "analyze":
            request["progress"] = True
        self._send(request)
        cancelled = False
        assert self._messages is not None
        while True:
            if cancel is not None and cancel.is_set() and not cancelled:
                self._send({"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": request_id}})
                cancelled = True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WorkerTimedOut(f"worker {method} exceeded its timeout")
            try:
                message = self._messages.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue
            if isinstance(message, BaseException):
                raise message
            if message.get("jsonrpc") != "2.0":
                raise WorkerCrashed("invalid JSON-RPC version")
            if message.get("method") == "$/progress":
                event = message.get("params")
                if progress and isinstance(event, dict) and event.get("request_id") == request_id:
                    try:
                        progress(event)
                    except Exception:
                        # An observer must not orphan an analysis or prevent
                        # the transport from consuming its final response.
                        pass
                continue
            if message.get("id") != request_id:
                raise WorkerCrashed("unexpected JSON-RPC response ID")
            if "error" in message:
                error = message["error"]
                if not isinstance(error, dict) or type(error.get("code")) is not int:
                    raise WorkerCrashed("invalid worker error")
                raise WorkerError(str(error.get("message", "worker error"))[:500])
            if "result" not in message:
                raise WorkerCrashed("missing worker result")
            return message["result"]

    def _analyze_once(self, task: AnalysisTask, deadline: float,
                      progress: ProgressCallback | None,
                      cancel: threading.Event | None) -> AnalysisResult:
        self._start()
        payload = self._request("analyze", asdict(task), deadline, progress, cancel)
        if not isinstance(payload, dict):
            raise WorkerCrashed("invalid analysis response")
        if payload.get("paged") is True:
            handle = payload.get("handle")
            page_count = payload.get("pages")
            size = payload.get("size")
            digest = payload.get("sha256")
            if (not isinstance(handle, str) or len(handle) != 32 or
                    type(page_count) is not int or not 1 <= page_count <= 1024 or
                    type(size) is not int or not 0 < size <= MAX_RESULT_BYTES or
                    not isinstance(digest, str) or len(digest) != 64):
                raise WorkerCrashed("invalid paged result descriptor")
            chunks: list[bytes] = []
            received = 0
            try:
                for index in range(page_count):
                    if cancel is not None and cancel.is_set():
                        raise WorkerError("Analysis cancelled while downloading result")
                    page = self._request("result_page", {"handle": handle, "index": index}, deadline)
                    if not isinstance(page, dict) or page.get("index") != index:
                        raise WorkerCrashed("invalid result page")
                    try:
                        chunk = base64.b64decode(page["data"], validate=True)
                    except (KeyError, TypeError, ValueError) as exc:
                        raise WorkerCrashed("invalid base64 result page") from exc
                    if not chunk or len(chunk) > PAGE_BYTES:
                        raise WorkerCrashed("result page exceeds its limit")
                    received += len(chunk)
                    if received > size:
                        raise WorkerCrashed("result pages exceed declared size")
                    chunks.append(chunk)
                if cancel is not None and cancel.is_set():
                    raise WorkerError("Analysis cancelled while downloading result")
                raw = b"".join(chunks)
                if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
                    raise WorkerCrashed("paged result integrity check failed")
                payload = json.loads(raw)
            finally:
                # Release is best effort: a timed out/crashed worker will be
                # reaped by analyze(), which also frees the result buffer.
                if time.monotonic() < deadline:
                    try:
                        self._request("release_result", {"handle": handle}, deadline)
                    except WorkerError:
                        pass
        if not isinstance(payload, dict):
            raise WorkerCrashed("invalid analysis result")
        if cancel is not None and cancel.is_set():
            raise WorkerError("Analysis cancelled")
        try:
            return AnalysisResult(**payload)
        except TypeError as exc:
            raise WorkerCrashed("invalid analysis result schema") from exc

    def analyze(self, task: AnalysisTask, on_progress: ProgressCallback | None = None,
                cancel: threading.Event | None = None) -> AnalysisResult:
        with self._lock:
            result = AnalysisResult(task.path, task.kind, "apk_analyzer", "error")
            timeout = min(max(float(task.worker_timeout_seconds), 0.001), 3600.0)
            deadline = time.monotonic() + timeout
            try:
                for attempt in range(2):
                    try:
                        return self._analyze_once(task, deadline, on_progress, cancel)
                    except WorkerCrashed:
                        self._stop()
                        if attempt == 1 or time.monotonic() >= deadline:
                            raise
                raise WorkerCrashed("worker could not be restarted")
            except (OSError, ValueError, RuntimeError, WorkerError) as exc:
                if isinstance(exc, (WorkerCrashed, WorkerTimedOut)):
                    self._stop()
                result.warnings.append(f"Worker failed: {type(exc).__name__}: {exc}")
                return result
