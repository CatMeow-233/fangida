"""Bounded static indicators for possible packed or embedded compressed data.

High entropy is not proof of packing or encryption. Signatures are byte-level
observations, not identification of the container as a specific packer.
"""
from __future__ import annotations

from collections import Counter
from math import log2
from typing import Any


MAX_SCAN_BYTES = 4 * 1024 * 1024
MAX_WINDOWS = 128
WINDOW_SIZE = 4096
HIGH_ENTROPY_THRESHOLD = 7.2
_SIGNATURES = ((b"UPX!", "UPX marker"), (b"UPX0", "UPX section marker"),
               (b"UPX1", "UPX section marker"), (b"\x1f\x8b\x08", "gzip header"),
               (b"PK\x03\x04", "ZIP local header"))


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    return round(-sum((count / length) * log2(count / length)
                      for count in Counter(data).values()), 4)


def inspect_packing_indicators(data: bytes, *, max_bytes: int = MAX_SCAN_BYTES,
                               window_size: int = WINDOW_SIZE) -> dict[str, Any]:
    """Inspect bytes without executing or decompressing them.

    Scans at most ``max_bytes`` and at most 128 consecutive fixed-size windows.
    The input should be a caller-supplied bounded file prefix. Byte signatures
    are searched in the entire scanned prefix, including skipped entropy
    windows. Output contains only JSON values and reports coverage explicitly.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 0 < max_bytes <= MAX_SCAN_BYTES:
        raise ValueError(f"max_bytes must be in 1..{MAX_SCAN_BYTES}")
    if isinstance(window_size, bool) or not isinstance(window_size, int) or not 512 <= window_size <= 65536:
        raise ValueError("window_size must be in 512..65536")
    prefix = data[:max_bytes]
    limit = min(len(prefix), window_size * MAX_WINDOWS)
    windows: list[dict[str, Any]] = []
    for offset in range(0, limit, window_size):
        chunk = prefix[offset:min(offset + window_size, limit)]
        if len(chunk) < 512:
            break
        entropy = _entropy(chunk)
        windows.append({"offset": offset, "length": len(chunk),
                        "entropy_bits_per_byte": entropy,
                        "high_entropy": entropy >= HIGH_ENTROPY_THRESHOLD})
    signatures: list[dict[str, Any]] = []
    for signature, label in _SIGNATURES:
        offset = prefix.find(signature)
        if offset >= 0:
            signatures.append({"offset": offset, "label": label, "hex": signature.hex()})
    return {
        "scanned_bytes": len(prefix), "input_bytes": len(data),
        "entropy_covered_bytes": sum(item["length"] for item in windows),
        "entropy_bits_per_byte": _entropy(prefix),
        "windows": windows,
        "signatures": signatures,
        "high_entropy_window_count": sum(item["high_entropy"] for item in windows),
        "truncated": len(prefix) < len(data),
        "interpretation": "Indicators only; high entropy and signatures do not establish packing",
    }
