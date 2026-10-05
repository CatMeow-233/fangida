import json
import hashlib
import io
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fangida.models import AnalysisResult
from fangida.project import ProjectStore
from fangida.processes import _WindowsJob, start_process
from fangida.scripts.runner import _write_all
from fangida.scripts import (
    ScriptCapabilities,
    ScriptContext,
    ScriptOutputLimitExceeded,
    ScriptTimeout,
    run_script,
)


class MemoryStore:
    def __init__(self, result):
        self.result = result
        self.renames = {}
        self.comments = {}

    def load_analysis(self, source_path):
        return self.result if source_path == "sample" else None

    def rename_symbol(self, source_path, address, name):
        self.renames[address] = name

    def set_comment(self, source_path, address, text):
        self.comments[address] = text

    def annotations(self, source_path):
        return {"renames": self.renames.copy(), "comments": self.comments.copy()}


class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.result = AnalysisResult(
            "sample", "elf", "kkagent", "partial",
            functions=[{"start": 4096, "disassembly": [{"addr": 4096, "mnemonic": "ret"}]}],
            strings=[{"value": "hello"}], xrefs=[{"src": 4096, "dst": 8192}],
        )
        self.store = MemoryStore(self.result.to_dict())

    def test_snapshot_and_returns_are_isolated(self):
        ctx = ScriptContext.from_project(self.store, "sample")
        self.result.strings[0]["value"] = "changed"
        self.store.result["strings"][0]["value"] = "also changed"
        ctx.snapshot()["strings"][0]["value"] = "mutated"
        ctx.functions()[0]["start"] = 0
        ctx.disassembly()[0]["mnemonic"] = "call"
        self.assertEqual(ctx.strings(), [{"value": "hello"}])
        self.assertEqual(ctx.functions()[0]["start"], 4096)
        self.assertEqual(ctx.disassembly()[0]["mnemonic"], "ret")
        self.assertEqual(ctx.xrefs(8192)[0]["src"], 4096)

    def test_default_denies_every_write_and_explicit_grants_persist(self):
        ctx = ScriptContext.from_project(self.store, "sample")
        with self.assertRaises(PermissionError):
            ctx.rename_symbol(4096, "entry")
        with self.assertRaises(PermissionError):
            ctx.set_comment(4096, "important")
        with self.assertRaises(PermissionError):
            ctx.export_json("out.json")
        ctx = ScriptContext.from_project(
            self.store, "sample", capabilities=ScriptCapabilities.from_names(["rename", "comment"])
        )
        ctx.rename_symbol(4096, "entry")
        ctx.set_comment(4096, "important")
        ctx.annotations()["renames"][4096] = "tampered"
        self.assertEqual(ctx.annotations()["renames"][4096], "entry")
        self.assertEqual(ctx.annotations()["comments"][4096], "important")
        self.assertEqual(ctx.snapshot()["functions"][0]["start"], 4096)
        with self.assertRaises(ValueError):
            ctx.rename_symbol(-1, "entry")
        with self.assertRaises(ValueError):
            ctx.rename_symbol(0, "not a valid name")

    def test_exports_remain_in_granted_root(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = ScriptContext(self.result, capabilities=ScriptCapabilities.from_names(["export"]),
                                export_root=directory)
            output = ctx.export_json("nested/result.json")
            self.assertEqual(json.loads(output.read_text())["path"], "sample")
            with self.assertRaises(PermissionError):
                ctx.export_json("../escape.json")
            with self.assertRaises(PermissionError):
                ctx.export_json(Path(directory).parent / "escape.json")

    def test_missing_project_and_unknown_grant(self):
        with self.assertRaises(FileNotFoundError):
            ScriptContext.from_project(self.store, "unknown")
        with self.assertRaises(ValueError):
            ScriptCapabilities.from_names(["delete_binary"])

    def test_actual_store_annotations_survive_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.bin"
            source.write_bytes(b"\x7fELF" + bytes(32))
            database = Path(directory) / "project.sqlite3"
            store = ProjectStore(database)
            store.save_analysis(source, self.result)
            ctx = ScriptContext.from_project(
                store, source, capabilities=ScriptCapabilities.from_names(["rename", "comment"])
            )
            ctx.rename_symbol(4096, "entry")
            ctx.set_comment(4096, "Reviewed")
            other = ScriptContext.from_project(ProjectStore(database), source)
            self.assertEqual(other.annotations()["renames"][4096], "entry")
            self.assertEqual(other.annotations()["comments"][4096], "Reviewed")
            self.assertNotIn("comments", other.snapshot())

    def test_trusted_runner_output_timeout_and_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "inspect.py"
            script.write_text("def main(analysis):\n    return {'kind': analysis['kind'], 'strings': len(analysis['strings'])}\n")
            ctx = ScriptContext(self.result)
            result = run_script(script, ctx)
            self.assertEqual(json.loads(result.stdout), {"kind": "elf", "strings": 1})
            script.write_text("print('x' * 10000)\n")
            with self.assertRaises(ScriptOutputLimitExceeded):
                run_script(script, ctx, max_output_bytes=64)
            script.write_text("import time\ntime.sleep(5)\n")
            with self.assertRaises(ScriptTimeout):
                run_script(script, ctx, timeout_seconds=0.1)

    def test_runner_unicode_paths_output_and_sibling_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "脚本 空格"
            folder.mkdir()
            (folder / "helper_utils.py").write_text("VALUE = '相邻模块 ✓'\n", encoding="utf-8")
            script = folder / "检查 脚本.py"
            script.write_text(
                "import helper_utils, sys\n"
                "print('中文 stderr ✓', file=sys.stderr)\n"
                "def main(analysis):\n"
                "    return {'helper': helper_utils.VALUE, 'input': analysis['strings'][0]['value']}\n",
                encoding="utf-8",
            )
            snapshot = self.result.to_dict()
            snapshot["strings"][0]["value"] = "中文分析结果 ✓"
            with patch.dict(os.environ, {"PYTHONIOENCODING": "ascii", "PYTHONUTF8": "0"}):
                result = run_script(script, ScriptContext(snapshot))
            self.assertEqual(json.loads(result.stdout), {
                "helper": "相邻模块 ✓", "input": "中文分析结果 ✓",
            })
            self.assertEqual(result.stderr.strip(), "中文 stderr ✓")

    def test_runner_transfers_large_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "digest.py"
            script.write_text(
                "import hashlib\n"
                "def main(analysis):\n"
                "    value = analysis['strings'][0]['value']\n"
                "    return {'size': len(value), 'digest': hashlib.sha256(value.encode('utf-8')).hexdigest()}\n",
                encoding="utf-8",
            )
            value = "完整传输 abc" * 100_000
            snapshot = self.result.to_dict()
            snapshot["strings"][0]["value"] = value
            result = run_script(script, ScriptContext(snapshot))
            self.assertEqual(json.loads(result.stdout), {
                "size": len(value), "digest": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            })

    def test_input_writer_retries_short_writes(self):
        class ShortWriter(io.BytesIO):
            def write(self, data):
                return super().write(data[:7])

        stream = ShortWriter()
        payload = "完整传输".encode("utf-8") * 100
        _write_all(stream, payload)
        self.assertEqual(stream.getvalue(), payload)

    def test_runner_cleans_descendants_when_launcher_exits_or_times_out(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "escaped.txt"
            ready = Path(directory) / "spawned.txt"
            script = Path(directory) / "spawn.py"
            child = (
                "import pathlib, sys, time; time.sleep(0.7); "
                "pathlib.Path(sys.argv[1]).write_text('survived', encoding='utf-8')"
            )
            source = (
                "import subprocess, sys, time\nfrom pathlib import Path\n"
                f"subprocess.Popen([sys.executable, '-c', {child!r}, {str(marker)!r}])\n"
                f"Path({str(ready)!r}).write_text('spawned', encoding='utf-8')\n"
                "print('spawned', flush=True)\n"
            )
            ctx = ScriptContext(self.result)
            for timeout in (False, True):
                with self.subTest(timeout=timeout):
                    script.write_text(source + ("time.sleep(10)\n" if timeout else ""), encoding="utf-8")
                    if timeout:
                        with self.assertRaises(ScriptTimeout):
                            run_script(script, ctx, timeout_seconds=0.5)
                    else:
                        self.assertEqual(run_script(script, ctx).stdout.strip(), "spawned")
                    self.assertTrue(ready.exists(), "script did not reach descendant startup")
                    ready.unlink()
                    time.sleep(0.8)
                    self.assertFalse(marker.exists(), "runner left its descendant running")

    def test_windows_job_assigns_before_resuming_and_releases_handles(self):
        calls = []

        def record(name, value=1):
            def invoke(*args):
                calls.append(name)
                return value
            return MagicMock(side_effect=invoke)

        kernel = SimpleNamespace(**{
            name: record(name) for name in (
                "SetInformationJobObject", "AssignProcessToJobObject", "TerminateJobObject",
                "CloseHandle", "Thread32Next", "ResumeThread",
            )
        })
        kernel.CreateJobObjectW = record("CreateJobObjectW", 41)
        kernel.OpenProcess = record("OpenProcess", 42)
        kernel.CreateToolhelp32Snapshot = record("CreateToolhelp32Snapshot", 43)
        kernel.OpenThread = record("OpenThread", 44)

        def first_thread(_handle, entry_pointer):
            entry_pointer._obj.process_id = 123
            entry_pointer._obj.thread_id = 456
            return 1

        kernel.Thread32First = MagicMock(side_effect=first_thread)
        with patch("fangida.processes.ctypes.WinDLL", create=True, return_value=kernel):
            job = _WindowsJob()
            job.assign_and_resume(123)
            job.terminate()
            job.close()
            job.close()
        self.assertLess(calls.index("AssignProcessToJobObject"), calls.index("ResumeThread"))
        limits = kernel.SetInformationJobObject.call_args.args[2]._obj
        self.assertEqual(limits.basic.flags, 0x2000)
        self.assertEqual(kernel.OpenProcess.call_args.args, (0x101, False, 123))
        self.assertEqual(kernel.OpenThread.call_args.args, (2, False, 456))
        self.assertEqual([call.args[0] for call in kernel.CloseHandle.call_args_list], [42, 44, 43, 41])

    def test_windows_start_is_suspended_and_failure_cleans_child(self):
        for failure in (False, True):
            with self.subTest(failure=failure):
                job = MagicMock()
                process = MagicMock(pid=123)
                process.stdin, process.stdout, process.stderr = io.BytesIO(), io.BytesIO(), io.BytesIO()
                if failure:
                    job.assign_and_resume.side_effect = OSError("job assignment failed")
                with patch("fangida.processes.os.name", "nt"), \
                     patch("fangida.processes._WindowsJob", return_value=job), \
                     patch("fangida.processes.subprocess.Popen", return_value=process) as popen:
                    if failure:
                        with self.assertRaisesRegex(OSError, "job assignment failed"):
                            start_process(["python", "script.py"], creationflags=0x200)
                    else:
                        tree = start_process(["python", "script.py"], creationflags=0x200)
                        self.assertIs(tree.process, process)
                        tree.close()
                self.assertEqual(popen.call_args.kwargs["creationflags"], 0x204)
                job.assign_and_resume.assert_called_once_with(123)
                job.close.assert_called_once()
                process.wait.assert_called_once()
                if failure:
                    process.kill.assert_called_once()
                    self.assertTrue(all(stream.closed for stream in (process.stdin, process.stdout, process.stderr)))


if __name__ == "__main__":
    unittest.main()
