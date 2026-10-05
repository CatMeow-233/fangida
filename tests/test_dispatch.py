import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import time
from fangida.dispatcher import analyze, identify
from fangida.plugins.manager import PluginManager

class DispatchTests(unittest.TestCase):
    def test_concurrent_first_load_creates_one_plugin(self) -> None:
        calls: list[str] = []

        class Stub:
            def teardown(self) -> None:
                pass

        def load_module(name: str) -> SimpleNamespace:
            calls.append(name)
            time.sleep(0.02)
            return SimpleNamespace(PluginImpl=Stub)

        manager = PluginManager()
        with patch("fangida.plugins.manager.import_module", side_effect=load_module):
            with ThreadPoolExecutor(max_workers=8) as executor:
                plugins = list(executor.map(manager.load, ["apk_analyzer"] * 8))
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(plugin is plugins[0] for plugin in plugins))
        manager.teardown()

    def test_native_magic_over_extension(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fake.apk"
            path.write_bytes(b"\x7fELFhello world\x00")
            result = analyze(path)
            self.assertEqual((result.kind, result.analyzer), ("elf", "kkagent"))
            self.assertIn("hello world", result.strings[0]["value"])

    def test_android_separate_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.dex"
            path.write_bytes(b"dex\n035\x00")
            manager = PluginManager()
            result = analyze(path, manager)
            self.assertEqual((result.kind, result.analyzer), ("dex", "apk_analyzer"))
            self.assertEqual((result.status, result.metadata["identification"]), ("partial", "magic"))
            manager.teardown()

    def test_zip_routing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.apk"
            path.write_bytes(b"PK\x03\x04")
            self.assertEqual(identify(path), ("apk", "magic+extension"))

if __name__ == "__main__":
    unittest.main()
