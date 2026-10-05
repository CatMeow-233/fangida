"""Compatibility module for the independent processor tool backend.

Keep the same module object so legacy patches of discovery helpers and
subprocess/shutil also affect the decoder's implementation.
"""
import sys

from ...processors import objdump_backend as _implementation

sys.modules[__name__] = _implementation
