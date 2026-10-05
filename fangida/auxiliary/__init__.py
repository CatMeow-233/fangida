"""Bounded static assistance for control flow and packed-data triage.

These helpers never execute input bytes. They produce JSON-compatible evidence
and do not modify the caller's graph or buffer.
"""

from .cfg import simplify_transparent_dispatchers
from .unpacking import inspect_packing_indicators

__all__ = ["simplify_transparent_dispatchers", "inspect_packing_indicators"]
