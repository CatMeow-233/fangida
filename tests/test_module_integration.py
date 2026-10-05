"""Explicit loader/processor/plugin registration reaches the shared service."""
from __future__ import annotations

from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from fangida import loaders, processors
from fangida.core.kkagent import PluginImpl
from fangida.dispatcher import AnalysisService
from fangida.models import AnalysisResult
from fangida.plugins.manager import PluginManager
from fangida.settings import Settings


class ModuleIntegrationTests(unittest.TestCase):
    def test_three_registered_modules_compose_without_editing_builtin_routes(self) -> None:
        decoder_calls: list[int] = []
        plugin_starts: list[str] = []

        class FixtureLoader:
            name = "fixture-loader"
            extensions = {".fixture": "fixture-format"}

            def probe(self, data, path=None):
                return loaders.LoaderMatch("fixture-format") if data.startswith(b"FNG0") else None

            def load(self, data, kind):
                return loaders.BinaryImage("fixture-format", "fixture-cpu", 32, "little",
                                           entry_address=0x1000, entry_offset=4,
                                           sections=[{"offset": 4, "address": 0x1000,
                                                      "size": 1, "executable": True}])

        class FixtureProcessor:
            engine, warning = "fixture", None

            def decode_bytes(self, code, address, *, max_instructions=128):
                decoder_calls.append(threading.get_ident())
                return [{"addr": address, "size": 1, "mnemonic": "ret", "operands": (),
                         "reads": (), "writes": (), "branch_info": {"kind": "return", "target": None},
                         "arch_meta": {"engine": self.engine, "architecture": "fixture-cpu"}}], []

        class FixturePlugin(PluginImpl):
            name = "fixture-plugin"

            def __init__(self):
                plugin_starts.append(self.name)

        loader_registry = loaders.default_registry()
        loader_registry.register(FixtureLoader())
        processor_registry = processors.ProcessorRegistry()
        processor_registry.register("fixture-cpu", lambda arch, endian: FixtureProcessor())
        manager = PluginManager()
        manager.register("fixture-plugin", FixturePlugin, kinds=("fixture-format",))
        self.assertEqual(plugin_starts, [])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.fixture"
            path.write_bytes(b"FNG0\xff")
            with patch.object(loaders, "DEFAULT_LOADERS", loader_registry), \
                 patch.object(processors, "_registry", processor_registry):
                with AnalysisService(Settings(analyze_threads=2), manager) as service:
                    result = service.analyze(path)
        self.assertEqual((result.kind, result.analyzer), ("fixture-format", "fixture-plugin"))
        self.assertEqual(result.metadata["identification"], "magic")
        self.assertEqual(len(result.functions), 1)
        self.assertEqual(result.functions[0]["blocks"][0]["instructions"][0]["mnemonic"], "ret")
        self.assertEqual(plugin_starts, ["fixture-plugin"])
        self.assertTrue(decoder_calls)
        self.assertEqual(manager.route("elf"), ("kkagent", "analyze"))

    def test_explicit_unloaded_route_replacement_is_used_by_service(self) -> None:
        class Replacement:
            def analyze(self, task):
                return AnalysisResult(task.path, task.kind, "replacement", "partial",
                                      metadata={"xref_threads": task.xref_threads})

            def teardown(self):
                pass

        manager = PluginManager()
        manager.register("replacement", Replacement, kinds=("elf",), replace_routes=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.elf"
            path.write_bytes(b"\x7fELF")
            with AnalysisService(Settings(analyze_threads=2), manager) as service:
                result = service.analyze(path)
        self.assertEqual(result.analyzer, "replacement")
        self.assertEqual(result.metadata["xref_threads"], 1)


if __name__ == "__main__":
    unittest.main()
