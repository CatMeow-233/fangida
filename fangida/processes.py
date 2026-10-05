"""Lifecycle management for external tools and their ordinary descendants.

This is a fault boundary, not a security sandbox. POSIX children run in their
own session. Windows children enter a kill-on-close Job Object before their
initial thread is resumed, so even fast-launching tools cannot escape cleanup.
"""
from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import threading
from typing import Any

from .windows_batch import prepare_windows_batch


class _WindowsJob:
    def __init__(self) -> None:
        # Fixed-width Windows types also let non-Windows tests verify layout.
        DWORD, LONG = ctypes.c_uint32, ctypes.c_int32
        HANDLE, SIZE_T = ctypes.c_void_p, ctypes.c_size_t

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                ("flags", DWORD), ("min_working_set", SIZE_T),
                ("max_working_set", SIZE_T), ("active_processes", DWORD),
                ("affinity", SIZE_T), ("priority", DWORD), ("scheduling", DWORD),
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("basic", BasicLimits), ("io_counters", ctypes.c_uint64 * 6),
                ("process_memory", SIZE_T), ("job_memory", SIZE_T),
                ("peak_process_memory", SIZE_T), ("peak_job_memory", SIZE_T),
            ]

        class ThreadEntry(ctypes.Structure):
            _fields_ = [
                ("size", DWORD), ("usage", DWORD), ("thread_id", DWORD),
                ("process_id", DWORD), ("base_priority", LONG),
                ("delta_priority", LONG), ("flags", DWORD),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, ctypes.c_wchar_p], HANDLE),
            "SetInformationJobObject": ([HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD], LONG),
            "OpenProcess": ([DWORD, LONG, DWORD], HANDLE),
            "AssignProcessToJobObject": ([HANDLE, HANDLE], LONG),
            "TerminateJobObject": ([HANDLE, ctypes.c_uint], LONG),
            "CloseHandle": ([HANDLE], LONG),
            "CreateToolhelp32Snapshot": ([DWORD, DWORD], HANDLE),
            "Thread32First": ([HANDLE, ctypes.POINTER(ThreadEntry)], LONG),
            "Thread32Next": ([HANDLE, ctypes.POINTER(ThreadEntry)], LONG),
            "OpenThread": ([DWORD, LONG, DWORD], HANDLE),
            "ResumeThread": ([HANDLE], DWORD),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(kernel, name)
            function.argtypes, function.restype = arguments, result
        self._kernel, self._thread_entry = kernel, ThreadEntry
        self._handle = kernel.CreateJobObjectW(None, None)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits()
        limits.basic.flags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel.SetInformationJobObject(self._handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign_and_resume(self, pid: int) -> None:
        kernel = self._kernel
        # PROCESS_SET_QUOTA | PROCESS_TERMINATE, required by assignment.
        handle = kernel.OpenProcess(0x0101, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not kernel.AssignProcessToJobObject(self._handle, handle):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            kernel.CloseHandle(handle)

        snapshot = kernel.CreateToolhelp32Snapshot(0x00000004, 0)  # TH32CS_SNAPTHREAD
        if snapshot == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            entry = self._thread_entry()
            entry.size = ctypes.sizeof(entry)
            present = kernel.Thread32First(snapshot, ctypes.byref(entry))
            while present:
                if entry.process_id == pid:
                    handle = kernel.OpenThread(0x0002, False, entry.thread_id)  # THREAD_SUSPEND_RESUME
                    if not handle:
                        raise ctypes.WinError(ctypes.get_last_error())
                    try:
                        previous_count = kernel.ResumeThread(handle)
                        if previous_count == 0xFFFFFFFF:
                            raise ctypes.WinError(ctypes.get_last_error())
                        if previous_count != 1:
                            raise OSError("initial process thread did not resume")
                    finally:
                        kernel.CloseHandle(handle)
                    return
                entry.size = ctypes.sizeof(entry)
                present = kernel.Thread32Next(snapshot, ctypes.byref(entry))
            raise OSError("could not find the suspended process thread")
        finally:
            kernel.CloseHandle(snapshot)

    def terminate(self) -> None:
        if self._handle and not self._kernel.TerminateJobObject(self._handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self._handle:
            self._kernel.CloseHandle(self._handle)
            self._handle = None


class ProcessTree:
    """Own one Popen, terminate its descendants, and reap it on close."""

    def __init__(self, process: subprocess.Popen[Any], job: _WindowsJob | None = None) -> None:
        self.process, self._job = process, job
        self._lock = threading.RLock()
        self._closed = False

    def terminate(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._job is not None:
                self._job.terminate()
            elif os.name == "posix":
                # The launcher may already have exited while its children live.
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    # macOS 对只剩僵尸成员的进程组返回 EPERM；已退出的子进程无需再终止。
                    if self.process.poll() is None:
                        raise
            elif self.process.poll() is None:
                self.process.kill()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self.terminate()
            finally:
                if self._job is not None:
                    self._job.close()
                self._closed = True
                self.process.wait()

    def __enter__(self) -> ProcessTree:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def wait_readable(streams: list[Any], timeout: float) -> list[Any]:
    """Return the child pipes that have data or EOF, waiting at most ``timeout``.

    Polling happens on the calling thread, so supervising several children
    never adds helper threads. Windows anonymous pipes cannot be selected;
    PeekNamedPipe reports pending bytes, and a closed writer counts as ready
    so the following read observes EOF.
    """
    if not streams:
        return []
    if os.name == "nt":
        import msvcrt
        import time
        import _winapi  # type: ignore[import-not-found]

        handles = [(stream, msvcrt.get_osfhandle(stream.fileno())) for stream in streams]
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            ready = []
            for stream, handle in handles:
                try:
                    if _winapi.PeekNamedPipe(handle, 0)[0]:
                        ready.append(stream)
                except OSError:
                    ready.append(stream)
            remaining = deadline - time.monotonic()
            if ready or remaining <= 0:
                return ready
            time.sleep(min(remaining, 0.002))
    import selectors

    with selectors.DefaultSelector() as selector:
        for stream in streams:
            selector.register(stream, selectors.EVENT_READ)
        return [key.fileobj for key, _ in selector.select(max(0.0, timeout))]


def wait_streams(readable: list[Any], writable: list[Any], timeout: float
                 ) -> tuple[list[Any], list[Any]]:
    """Wait until child pipes can be read (data or EOF) or written without blocking.

    Like ``wait_readable`` this polls on the calling thread. POSIX waits on one
    selector for both directions. Windows anonymous pipes cannot report free
    space; writers there use a pipe buffer sized for a whole message (see
    ``input_pipe``), so writable streams are reported ready immediately.
    """
    if os.name == "nt":
        if writable:
            return wait_readable(readable, 0), list(writable)
        return wait_readable(readable, timeout), []
    if not readable and not writable:
        if timeout > 0:
            import time
            time.sleep(timeout)
        return [], []
    import selectors

    with selectors.DefaultSelector() as selector:
        for stream in readable:
            selector.register(stream, selectors.EVENT_READ)
        for stream in writable:
            selector.register(stream, selectors.EVENT_WRITE)
        ready_read, ready_write = [], []
        for key, events in selector.select(max(0.0, timeout)):
            (ready_read if events & selectors.EVENT_READ else ready_write).append(key.fileobj)
        return ready_read, ready_write


def set_nonblocking(stream: Any) -> None:
    """Make a parent-side child pipe non-blocking (POSIX; Windows keeps blocking handles)."""
    if os.name == "posix" and stream is not None:
        os.set_blocking(stream.fileno(), False)


def read_available(stream: Any, buffer: Any) -> int | None:
    """Read what a child pipe already holds into ``buffer`` without waiting.

    Returns the byte count, 0 at EOF, or None when nothing is available yet.
    POSIX streams must be non-blocking (``set_nonblocking``). On Windows the
    read is limited to the bytes PeekNamedPipe reports, so it cannot block.
    """
    if os.name == "nt":
        import msvcrt
        import _winapi  # type: ignore[import-not-found]

        try:
            available = _winapi.PeekNamedPipe(msvcrt.get_osfhandle(stream.fileno()), 0)[0]
        except OSError:
            return 0  # 写端已关闭（ERROR_BROKEN_PIPE）：按 EOF 处理
        if not available:
            return None
        buffer = memoryview(buffer)[:available]
    try:
        return stream.readinto(buffer)
    except BlockingIOError:
        return None


def write_available(stream: Any, data: Any) -> int:
    """Write as much of ``data`` as the pipe accepts now; returns the bytes written.

    A non-blocking POSIX pipe accepts what fits. Windows handles stay blocking;
    callers size their pipe so one message never has to wait for the reader.
    """
    try:
        return stream.write(data) or 0
    except BlockingIOError as exc:
        return getattr(exc, "characters_written", 0) or 0


def input_pipe(size: int) -> tuple[int, Any]:
    """Windows: a child stdin pipe whose buffer holds ``size`` bytes.

    Returns a read descriptor to pass as Popen ``stdin`` (the caller closes it
    once the child has started; Popen hands the child its own inheritable
    duplicate) and an unbuffered binary writer for the parent. A message of at
    most ``size`` bytes written to an empty pipe completes without waiting for
    the child to read it, so a child that stops reading cannot block the
    parent. This mirrors ``subprocess``'s own ``CreatePipe`` handling.
    """
    import msvcrt
    import _winapi  # type: ignore[import-not-found]

    read_handle, write_handle = _winapi.CreatePipe(None, size)
    try:
        read_fd = msvcrt.open_osfhandle(read_handle, os.O_RDONLY)
    except BaseException:
        _winapi.CloseHandle(read_handle)
        _winapi.CloseHandle(write_handle)
        raise
    try:
        write_fd = msvcrt.open_osfhandle(write_handle, 0)
    except BaseException:
        os.close(read_fd)
        _winapi.CloseHandle(write_handle)
        raise
    try:
        return read_fd, open(write_fd, "wb", buffering=0)
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise


def start_process(args: Any, **kwargs: Any) -> ProcessTree:
    """Launch a supervised process; normal Popen arguments remain supported.

    Session and suspension flags are owned here. If Windows cannot establish
    supervision, startup fails after cleaning up the suspended child.
    """
    if os.name == "nt":
        batch = prepare_windows_batch(
            args, env=kwargs.get("env"), executable=kwargs.get("executable"),
            shell=kwargs.get("shell", False),
        )
        if batch is not None:
            args = batch.command_line
            kwargs.update(executable=batch.executable, env=batch.environment, shell=False)
    job = _WindowsJob() if os.name == "nt" else None
    process = None
    try:
        if os.name == "posix":
            kwargs["start_new_session"] = True
        elif job is not None:
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | 0x00000004  # CREATE_SUSPENDED
        process = subprocess.Popen(args, **kwargs)
        if job is not None:
            try:
                job.assign_and_resume(process.pid)
            except OSError as exc:
                raise OSError(f"could not supervise Windows child process {process.pid}: {exc}") from exc
        return ProcessTree(process, job)
    except BaseException:
        if process is not None:
            process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        if job is not None:
            job.close()
        raise
