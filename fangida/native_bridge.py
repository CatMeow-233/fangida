"""Optional ctypes client for the shared Rust/C++ C ABI."""
from __future__ import annotations
import ctypes
import json
from pathlib import Path
from typing import Any

ABI_MAJOR = 1
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_RESULT_BYTES = 1024 * 1024

class NativeUnavailable(RuntimeError):
    pass

class _Buffer(ctypes.Structure):
    _fields_ = [("data", ctypes.POINTER(ctypes.c_uint8)), ("length", ctypes.c_uint64)]

class NativeBridge:
    def __init__(self, library: str | Path) -> None:
        try:
            self._library = ctypes.CDLL(str(Path(library).expanduser().resolve(strict=True)))
            self._library.fangida_abi_version.argtypes = []
            self._library.fangida_abi_version.restype = ctypes.c_uint32
            self._library.fangida_analyze.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint64,
                                                       ctypes.POINTER(_Buffer)]
            self._library.fangida_analyze.restype = ctypes.c_int
            self._library.fangida_release.argtypes = [ctypes.POINTER(_Buffer)]
            self._library.fangida_release.restype = None
        except (OSError, AttributeError) as exc:
            raise NativeUnavailable(f"Could not load native ABI: {exc}") from exc
        version = self._library.fangida_abi_version()
        if version >> 16 != ABI_MAJOR:
            raise NativeUnavailable(f"Native ABI major mismatch: {version >> 16} != {ABI_MAJOR}")

    def analyze(self, data: bytes) -> dict[str, Any]:
        if len(data) > MAX_INPUT_BYTES:
            raise ValueError(f"Native scan limit is {MAX_INPUT_BYTES} bytes")
        # ctypes creates a stable copy for the duration of the FFI call.
        source = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        result = _Buffer()
        status = self._library.fangida_analyze(source, len(data), ctypes.byref(result))
        try:
            if status != 0:
                raise NativeUnavailable(f"Native analyze returned error code {status}")
            if result.length > MAX_RESULT_BYTES or not result.data:
                raise NativeUnavailable("Native result size/pointer is invalid")
            payload = json.loads(ctypes.string_at(result.data, result.length).decode("utf-8"))
            if not isinstance(payload, dict) or payload.get("schema_version") != 1:
                raise NativeUnavailable("Native result schema mismatch")
            return payload
        finally:
            self._library.fangida_release(ctypes.byref(result))
