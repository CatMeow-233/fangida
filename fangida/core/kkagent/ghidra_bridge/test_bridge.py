"""Adapter contract tests using a Python subprocess stand-in for analyzeHeadless."""

from __future__ import annotations

from contextlib import nullcontext
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from .bridge import GhidraAnalysisError, GhidraBridge, GhidraUnavailable


class BridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="fangida ghidra 中文 ")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.binary = self.base / "sample.elf"
        self.binary.write_bytes(b"\x7fELFtest")

    def launcher(self, body: str) -> Path:
        launcher = self.base / "analyzeHeadless.py"
        launcher.write_text(body, encoding="utf-8")
        launcher.chmod(0o755)
        # Windows cannot execute a POSIX shebang, and interpreter paths with
        # spaces cannot reliably appear in one. Keep the bridge's real child
        # process and generated arguments, but run the fixture via Python.
        real_popen = subprocess.Popen

        def launch(command: list[str], **kwargs: object) -> subprocess.Popen[bytes]:
            self.assertEqual(Path(command[0]), launcher.resolve())
            return real_popen([sys.executable, str(launcher), *command[1:]], **kwargs)

        launch_patch = patch(f"{GhidraBridge.__module__}.subprocess.Popen", side_effect=launch)
        launch_patch.start()
        self.addCleanup(launch_patch.stop)
        return launcher

    def test_unavailable_is_explicit(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            bridge = GhidraBridge.from_environment()
        self.assertFalse(bridge.available())
        with self.assertRaisesRegex(GhidraUnavailable, "not configured"):
            bridge.analyze(self.binary)

    def test_bounded_export_and_headless_command(self) -> None:
        fake = self.launcher("""
import json, pathlib, sys
args = sys.argv[1:]
assert '-readOnly' in args and '-deleteProject' in args
assert '-max-cpu' in args and args[args.index('-max-cpu') + 1] == '1'
assert args[args.index('-analysisTimeoutPerFile') + 1] == '72'
assert pathlib.Path(args[args.index('-scriptPath') + 1], 'FangidaExport.java').is_file()
assert pathlib.Path(args[args.index('-import') + 1]).is_file()
position = args.index('-postScript')
assert args[position + 1] == 'FangidaExport.java'
assert args[position + 3:position + 8] == ['4', '5', '6', '2', '9']
output = pathlib.Path(args[position + 2])
output.write_text(json.dumps({
    'schema_version': 2, 'status': 'ok',
    'functions': [{'start': 0x401000, 'name': 'main', 'address_space': 'ram'}],
    'xrefs': [{'src': 0x401001, 'dst': 0x401100, 'kind': 'call',
               'src_space': 'ram', 'dst_space': 'ram'}],
    'pcode': [{'addr': 0x401001, 'address_space': 'ram',
               'ops': [{'opcode': 'CALL', 'inputs': ['(ram, 0x401100, 8)'], 'output': None}]}],
    'decompiled_functions': [{'start': 0x401000, 'address_space': 'ram',
        'pseudoc': 'int main(void) { return 你好; }', 'producer': 'ghidra', 'truncated': False}],
    'stats': {'function_count': 1, 'xref_count': 1, 'pcode_instruction_count': 1,
              'decompile_succeeded': 1},
    'warnings': []
}, ensure_ascii=False), encoding='utf-8')
""")
        result = GhidraBridge(fake, max_cpu=1, max_functions=4, max_xrefs=5,
                              max_pcode_instructions=6, max_decompiled_functions=2,
                              max_decompile_seconds=9).analyze(self.binary)
        self.assertEqual(result.functions[0]["start"], 0x401000)
        self.assertEqual(result.xrefs[0]["kind"], "call")
        self.assertEqual(result.pcode[0]["ops"][0]["opcode"], "CALL")
        self.assertIn("你好", result.decompiled_functions[0]["pseudoc"])
        self.assertEqual(result.decompiled_functions[0]["producer"], "ghidra")
        self.assertEqual(json.loads(json.dumps(result.to_dict())), result.to_dict())

    def test_postscript_absent_is_failure_even_on_zero_exit(self) -> None:
        fake = self.launcher("import sys\nsys.exit(0)\n")
        with self.assertRaisesRegex(GhidraAnalysisError, "without a bridge result"):
            GhidraBridge(fake).analyze(self.binary)

    def test_invalid_result_is_rejected(self) -> None:
        fake = self.launcher("""
import json, pathlib, sys
output = pathlib.Path(sys.argv[sys.argv.index('-postScript') + 2])
output.write_text(json.dumps({'schema_version': 2, 'status': 'ok',
    'functions': [{'start': 'not-an-address', 'name': 'f', 'address_space': 'ram'}],
    'xrefs': [], 'pcode': [], 'decompiled_functions': [], 'stats': {}, 'warnings': []}))
""")
        with self.assertRaisesRegex(GhidraAnalysisError, "Malformed Ghidra function"):
            GhidraBridge(fake).analyze(self.binary)

    def test_result_over_limit_is_rejected(self) -> None:
        fake = self.launcher("""
import json, pathlib, sys
output = pathlib.Path(sys.argv[sys.argv.index('-postScript') + 2])
output.write_text(json.dumps({'schema_version': 2, 'status': 'ok',
    'functions': [{'start': n, 'name': 'f', 'address_space': 'ram'} for n in range(2)],
    'xrefs': [], 'pcode': [], 'decompiled_functions': [], 'stats': {}, 'warnings': []}))
""")
        with self.assertRaisesRegex(GhidraAnalysisError, "over-limit functions"):
            GhidraBridge(fake, max_functions=1).analyze(self.binary)

    def test_decompiled_text_requires_matching_function_and_provenance(self) -> None:
        fake = self.launcher("""
import json, pathlib, sys
output = pathlib.Path(sys.argv[sys.argv.index('-postScript') + 2])
output.write_text(json.dumps({'schema_version': 2, 'status': 'ok',
    'functions': [{'start': 7, 'name': 'known', 'address_space': 'ram'}],
    'xrefs': [], 'pcode': [],
    'decompiled_functions': [{'start': 8, 'address_space': 'ram',
       'pseudoc': 'invented()', 'producer': 'ghidra', 'truncated': False}],
    'stats': {}, 'warnings': []}))
""")
        with self.assertRaisesRegex(GhidraAnalysisError, "Malformed Ghidra decompiled function"):
            GhidraBridge(fake).analyze(self.binary)

    def test_decompilation_can_be_disabled_and_schema_remains_explicit(self) -> None:
        fake = self.launcher("""
import json, pathlib, sys
args = sys.argv
position = args.index('-postScript')
assert args[position + 6] == '0'
pathlib.Path(args[position + 2]).write_text(json.dumps({
    'schema_version': 2, 'status': 'ok', 'functions': [], 'xrefs': [], 'pcode': [],
    'decompiled_functions': [], 'stats': {'decompile_attempted': 0}, 'warnings': []
}))
""")
        result = GhidraBridge(fake, max_decompiled_functions=0).analyze(self.binary)
        self.assertEqual(result.decompiled_functions, [])

    def test_short_wall_budget_and_partial_decompile_result(self) -> None:
        fake = self.launcher("""
import json, pathlib, sys
args = sys.argv
position = args.index('-postScript')
assert args[position + 7] == '6'  # total decompile budget is capped at 30% of 20s
assert args[args.index('-analysisTimeoutPerFile') + 1] == '12'
pathlib.Path(args[position + 2]).write_text(json.dumps({
    'schema_version': 2, 'status': 'ok',
    'functions': [{'start': 7, 'name': 'known', 'address_space': 'ram'}],
    'xrefs': [], 'pcode': [], 'decompiled_functions': [],
    'stats': {'decompile_attempted': 1, 'decompile_succeeded': 0,
              'decompile_timed_out': 1, 'decompile_budget_seconds': 6},
    'warnings': ['Ghidra decompilation time budget reached']
}))
""")
        result = GhidraBridge(fake, timeout_seconds=20,
                              max_decompiled_functions=1,
                              max_decompile_seconds=100).analyze(self.binary)
        self.assertEqual(result.functions[0]["name"], "known")
        self.assertEqual(result.decompiled_functions, [])
        self.assertEqual(result.stats["decompile_timed_out"], 1)
        self.assertTrue(result.warnings)

    def test_timeout_kills_process(self) -> None:
        fake = self.launcher("import time\ntime.sleep(10)\n")
        started = time.monotonic()
        with self.assertRaisesRegex(GhidraAnalysisError, "exceeded"):
            GhidraBridge(fake, timeout_seconds=0.2).analyze(self.binary)
        self.assertLess(time.monotonic() - started, 5)

    def test_nonzero_exit_reports_bounded_diagnostic(self) -> None:
        fake = self.launcher(
            "import sys\nsys.stderr.write('script compilation failed')\nsys.exit(3)\n"
        )
        with self.assertRaisesRegex(GhidraAnalysisError, "script compilation failed"):
            GhidraBridge(fake).analyze(self.binary)

    def batch_fixture(self, folder: Path | None = None) -> Path:
        folder = folder or self.base
        folder.mkdir(parents=True, exist_ok=True)
        launcher = folder / "analyzeHeadless.bat"
        launcher.write_text("@echo off\n", encoding="ascii")
        launcher.chmod(0o755)
        return launcher

    def export_standin(self, command: list[str], **kwargs: object) -> MagicMock:
        output = Path(command[command.index("-postScript") + 2])
        output.write_text(json.dumps({
            "schema_version": 2, "status": "ok", "functions": [], "xrefs": [],
            "pcode": [], "decompiled_functions": [], "stats": {}, "warnings": [],
        }), encoding="utf-8")
        tree = MagicMock()
        tree.process.wait.return_value = 0
        return tree

    def test_sensitive_input_paths_are_staged_only_for_windows_batches(self) -> None:
        binary = self.base / "input %HOME% ! & ^.elf"
        binary.write_bytes(self.binary.read_bytes())
        launcher = self.batch_fixture()
        real_copy = shutil.copyfile
        for batch in (False, True):
            with self.subTest(batch=batch):
                imported = []

                def launch(command: list[str], **kwargs: object) -> MagicMock:
                    source = Path(command[command.index("-import") + 1])
                    self.assertEqual(source.read_bytes(), binary.read_bytes())
                    imported.append(source)
                    if batch:
                        self.assertEqual(source.name, "input.bin")
                        self.assertFalse(any(character in str(source) for character in "%!&^"))
                    else:
                        self.assertEqual(source, binary.resolve())
                    return self.export_standin(command, **kwargs)

                with patch(f"{GhidraBridge.__module__}._windows_batch_launcher", return_value=batch), \
                     patch(f"{GhidraBridge.__module__}.start_process", side_effect=launch), \
                     patch(f"{GhidraBridge.__module__}.shutil.copyfile", wraps=real_copy) as copied:
                    GhidraBridge(launcher).analyze(binary)
                self.assertEqual(copied.call_count, 1 if batch else 0)
                self.assertEqual(binary.read_bytes(), b"\x7fELFtest")
                if batch:
                    self.assertFalse(imported[0].exists(), "staged input was not removed")

    def test_normal_windows_batch_input_avoids_extra_copy(self) -> None:
        launcher = self.batch_fixture()
        with patch(f"{GhidraBridge.__module__}._windows_batch_launcher", return_value=True), \
             patch(f"{GhidraBridge.__module__}.start_process", side_effect=self.export_standin) as started, \
             patch(f"{GhidraBridge.__module__}.shutil.copyfile") as copied:
            GhidraBridge(launcher).analyze(self.binary)
        command = started.call_args.args[0]
        self.assertEqual(command[command.index("-import") + 1], str(self.binary.resolve()))
        copied.assert_not_called()

    def test_packaged_script_in_sensitive_directory_is_staged(self) -> None:
        launcher = self.batch_fixture()
        folder = self.base / "export %CACHE% ! & ^"
        folder.mkdir()
        original = folder / "FangidaExport.java"
        original.write_bytes(b"// packaged export script\n")
        staged = []

        def launch(command: list[str], **kwargs: object) -> MagicMock:
            script = Path(command[command.index("-scriptPath") + 1]) / "FangidaExport.java"
            self.assertEqual(script.read_bytes(), original.read_bytes())
            self.assertEqual(script.parent.name, "scripts")
            self.assertFalse(any(character in str(script) for character in "%!&^"))
            staged.append(script)
            return self.export_standin(command, **kwargs)

        with patch(f"{GhidraBridge.__module__}._windows_batch_launcher", return_value=True), \
             patch(f"{GhidraBridge.__module__}.as_file", return_value=nullcontext(original)), \
             patch(f"{GhidraBridge.__module__}.start_process", side_effect=launch):
            GhidraBridge(launcher).analyze(self.binary)
        self.assertTrue(original.exists())
        self.assertFalse(staged[0].exists(), "staged script was not removed")

    def test_windows_batch_rejects_expanding_installation_paths(self) -> None:
        for name in ("ghidra%HOME%", "ghidra!"):
            with self.subTest(name=name):
                launcher = self.batch_fixture(self.base / name)
                with patch(f"{GhidraBridge.__module__}._windows_batch_launcher", return_value=True), \
                     patch(f"{GhidraBridge.__module__}.start_process") as started:
                    bridge = GhidraBridge(launcher)
                    self.assertFalse(bridge.available())
                    with self.assertRaisesRegex(GhidraUnavailable, "installation path"):
                        bridge.analyze(self.binary)
                started.assert_not_called()
                with patch(f"{GhidraBridge.__module__}._windows_batch_launcher", return_value=False):
                    self.assertTrue(bridge.available())

    def test_windows_batch_rejects_expanding_temporary_paths_before_copy(self) -> None:
        launcher = self.batch_fixture()
        for name in ("tmp%CACHE%", "tmp!"):
            with self.subTest(name=name):
                temporary = self.base / name
                temporary.mkdir()
                with patch(f"{GhidraBridge.__module__}._windows_batch_launcher", return_value=True), \
                     patch(f"{GhidraBridge.__module__}.tempfile.TemporaryDirectory",
                           return_value=nullcontext(str(temporary))), \
                     patch(f"{GhidraBridge.__module__}.start_process") as started, \
                     patch(f"{GhidraBridge.__module__}.shutil.copyfile") as copied:
                    with self.assertRaisesRegex(GhidraUnavailable, "temporary path"):
                        GhidraBridge(launcher).analyze(self.binary)
                copied.assert_not_called()
                started.assert_not_called()


if __name__ == "__main__":
    unittest.main()
