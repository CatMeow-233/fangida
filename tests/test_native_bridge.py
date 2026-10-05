import tempfile
import unittest
from pathlib import Path
from fangida.native_bridge import NativeBridge, NativeUnavailable

class NativeBridgeTests(unittest.TestCase):
    def test_missing_library_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(NativeUnavailable):
                NativeBridge(Path(directory) / "missing.so")
