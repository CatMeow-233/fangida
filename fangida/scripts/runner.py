"""Bounded subprocess execution for *trusted* read-only helper scripts.

The subprocess is a fault and resource boundary, not a Python sandbox. The
invoked code retains its normal operating-system permissions.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import TYPE_CHECKING, BinaryIO

from fangida.processes import start_process

if TYPE_CHECKING:
    from . import ScriptContext


class ScriptExecutionError(RuntimeError):
    """A script exited with an error."""


class ScriptTimeout(ScriptExecutionError):
    """Execution exceeded the allotted wall time."""


class ScriptOutputLimitExceeded(ScriptExecutionError):
    """Combined stdout and stderr exceeded the configured byte limit."""


@dataclass(frozen=True)
class ScriptRun:
    stdout: str
    stderr: str
    returncode: int


def _write_all(stream: BinaryIO, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = stream.write(remaining)
        if written is None or written <= 0:
            raise BrokenPipeError("script input pipe stopped accepting bytes")
        remaining = remaining[written:]


def run_script(
    script_path: str | Path,
    context: ScriptContext,
    *,
    timeout_seconds: float = 5.0,
    max_output_bytes: int = 64 * 1024,
) -> ScriptRun:
    """Execute a trusted Python file with an independent analysis snapshot.

    The script receives ``analysis`` as a global dict. If it defines
    ``main(analysis)``, the runner invokes it and JSON-prints a non-None return
    value. Persistent writes through ScriptContext are unavailable here. This
    is not a security sandbox; only run Python files that you trust.
    """
    if not 0 < timeout_seconds <= 300:
        raise ValueError("timeout_seconds must be between 0 and 300")
    if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 16 * 1024 * 1024:
        raise ValueError("max_output_bytes must be between 1 and 16777216")
    script = Path(script_path).expanduser().resolve(strict=True)
    if not script.is_file():
        raise ValueError("script_path must name a file")
    payload = json.dumps(context.snapshot(), ensure_ascii=False).encode("utf-8")
    environment = os.environ.copy()
    environment.update(PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    tree = start_process(
        [sys.executable, "-u", str(Path(__file__).with_name("_child.py")), str(script)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        bufsize=0,
    )
    process = tree.process
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    lock = threading.Lock()

    def drain(stream: BinaryIO, sink: bytearray) -> None:
        try:
            while data := stream.read(8192):
                with lock:
                    space = max_output_bytes - len(stdout) - len(stderr)
                    sink.extend(data[:max(0, space)])
                    if len(data) > space:
                        overflow.set()
                        tree.terminate()
                        return
        finally:
            stream.close()

    def send_input() -> None:
        try:
            _write_all(process.stdin, payload)
        except (BrokenPipeError, OSError):
            pass
        finally:
            process.stdin.close()

    threads = [
        threading.Thread(target=drain, args=(process.stdout, stdout), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr), daemon=True),
        threading.Thread(target=send_input, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        tree.terminate()
        process.wait()
        raise ScriptTimeout(f"script exceeded {timeout_seconds} seconds") from exc
    finally:
        tree.close()
        for thread in threads:
            thread.join(timeout=0.5)
    if overflow.is_set():
        raise ScriptOutputLimitExceeded(f"script exceeded {max_output_bytes} output bytes")
    result = ScriptRun(stdout.decode("utf-8", errors="replace"),
                       stderr.decode("utf-8", errors="replace"), process.returncode)
    if process.returncode != 0:
        raise ScriptExecutionError(f"script exited with status {process.returncode}: {result.stderr[:1000]}")
    return result
