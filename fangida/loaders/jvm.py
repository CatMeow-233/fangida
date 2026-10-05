"""JVM/Android container identification; analysis remains in its own plugin."""
from __future__ import annotations

from pathlib import Path

from .interfaces import LoaderMatch


class JvmContainerProbe:
    """Recognize worker formats without importing or launching the analyzer.

    This is intentionally a FormatProbe, not a native BinaryImage loader.
    ZIP/DEX/class parsing belongs to the standalone Android/JVM backend.
    """

    name = "jvm"
    extensions = {".apk": "apk", ".dex": "dex", ".jar": "jar", ".class": "class"}

    def probe(self, data: bytes, path: str | Path | None = None) -> LoaderMatch | None:
        if data.startswith(b"dex\n"):
            return LoaderMatch("dex")
        if data.startswith(b"PK\x03\x04"):
            suffix = Path(path).suffix.lower() if path is not None else ""
            return LoaderMatch("apk" if suffix == ".apk" else "jar", "magic+extension")
        if data.startswith(b"\xca\xfe\xba\xbe"):
            return LoaderMatch("class")
        return None
