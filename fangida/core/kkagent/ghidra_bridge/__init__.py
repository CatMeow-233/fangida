"""Optional, isolated Ghidra analysis through ``analyzeHeadless``.

No JVM is started at import time. Set ``FANGIDA_GHIDRA_HEADLESS`` to Ghidra's
``support/analyzeHeadless`` launcher, or ``GHIDRA_HOME`` to its installation
directory, then call :meth:`GhidraBridge.analyze` explicitly.
"""

from .bridge import (
    GhidraAnalysisError,
    GhidraBridge,
    GhidraSnapshot,
    GhidraUnavailable,
)

__all__ = [
    "GhidraAnalysisError",
    "GhidraBridge",
    "GhidraSnapshot",
    "GhidraUnavailable",
]
