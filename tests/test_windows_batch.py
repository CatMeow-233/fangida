"""Construction and Windows execution contracts for batch argument delivery."""
from __future__ import annotations

import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from fangida.processes import start_process
from fangida.windows_batch import prepare_windows_batch


class BatchPreparationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = {"SystemRoot": r"C:\Windows", "KEEP": "original"}

    def prepare(self, args, **kwargs):
        with patch.dict(os.environ, self.environment, clear=True):
            return prepare_windows_batch(args, **kwargs)

    def test_values_cross_only_through_quoted_environment_references(self) -> None:
        arguments = [r"C:\工具 & %KEEP% !\启动.CMD", r"C:\输入\a&b%KEEP%!^.elf", "中文 空格", ""]
        supplied = dict(self.environment)
        prepared = self.prepare(arguments, env=supplied)
        self.assertIsNotNone(prepared)
        self.assertEqual(supplied, self.environment)
        self.assertEqual(prepared.executable, r"C:\Windows\System32\cmd.exe")
        self.assertEqual(prepared.environment["KEEP"], "original")
        self.assertIn(" /d /v:off /s /c ", prepared.command_line)
        self.assertNotIn("call", prepared.command_line.lower())
        for argument in arguments[:-1]:
            self.assertNotIn(argument, prepared.command_line)
        names = re.findall(r'"%(FANGIDA_BATCH_[0-9a-f]{32}_\d+)%"', prepared.command_line)
        self.assertEqual([prepared.environment[name] for name in names], arguments[:-1])
        self.assertTrue(prepared.command_line.endswith(' """'))

    def test_generated_environment_names_do_not_alias_concurrent_runs(self) -> None:
        first = self.prepare(["run.bat", "%KEEP%"])
        second = self.prepare(["run.bat", "%KEEP%"])
        names = lambda result: {key for key in result.environment if key.startswith("FANGIDA_BATCH_")}
        self.assertTrue(names(first).isdisjoint(names(second)))

    def test_regular_programs_keep_their_original_popen_contract(self) -> None:
        for args in (["python.exe", "helper.py"], ["tool.exe", "a&b"], "echo something", []):
            with self.subTest(args=args):
                self.assertIsNone(self.prepare(args))
        self.assertIsNone(self.prepare(["fake.bat", "x"], executable="python.exe"))

    def test_case_insensitive_extension_and_text_paths(self) -> None:
        prepared = self.prepare([PureWindowsPath(r"C:\scripts\helper.BaT"), Path("input.bin")])
        self.assertIn(r"C:\scripts\helper.BaT", prepared.environment.values())
        self.assertIn("input.bin", prepared.environment.values())
        self.assertIsNotNone(self.prepare(PureWindowsPath(r"C:\scripts\helper.cmd")))

    def test_unsupported_characters_and_shell_options_fail_explicitly(self) -> None:
        for value in ('quote"inside', "line\nfeed", "carriage\rreturn", "nul\0byte", "tab\there"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "double quotes or control"):
                    self.prepare(["run.bat", value])
        with self.assertRaisesRegex(TypeError, "Unicode"):
            self.prepare(["run.bat", b"argument"])
        with self.assertRaisesRegex(ValueError, "shell=False"):
            self.prepare(["run.bat"], shell=True)
        with self.assertRaisesRegex(ValueError, "executable overrides"):
            self.prepare(["run.bat"], executable="run.bat")

    def test_command_limit_covers_expansion_and_unicode_utf16_units(self) -> None:
        for argument in ("x" * 8191, "😀" * 4096):
            with self.subTest(argument_length=len(argument)):
                with self.assertRaisesRegex(ValueError, "8191-character"):
                    self.prepare(["run.bat", argument])
        with self.assertRaisesRegex(ValueError, "8191-character"):
            self.prepare(["run.bat", *([""] * 3000)])

    def test_host_system_interpreter_does_not_use_comspec_or_path(self) -> None:
        prepared = self.prepare(["run.bat"], env={"COMSPEC": r"C:\fake\cmd.exe", "PATH": "fake"})
        self.assertEqual(prepared.executable, r"C:\Windows\System32\cmd.exe")
        self.assertEqual(prepared.environment["SystemRoot"], r"C:\Windows")
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(OSError, "SystemRoot"):
                prepare_windows_batch(["run.bat"], env={})

    def test_startup_keeps_job_assignment_before_resume_and_preserves_flags(self) -> None:
        job = MagicMock()
        process = MagicMock(pid=123)
        with patch("fangida.processes.os.name", "nt"), \
             patch.dict(os.environ, self.environment, clear=True), \
             patch("fangida.processes._WindowsJob", return_value=job), \
             patch("fangida.processes.subprocess.Popen", return_value=process) as popen:
            tree = start_process(["run.cmd", "a&b%KEEP%!"], creationflags=0x200)
            tree.close()
        command = popen.call_args.args[0]
        self.assertIsInstance(command, str)
        self.assertNotIn("a&b", command)
        self.assertEqual(popen.call_args.kwargs["executable"], r"C:\Windows\System32\cmd.exe")
        self.assertEqual(popen.call_args.kwargs["creationflags"], 0x204)
        self.assertFalse(popen.call_args.kwargs["shell"])
        job.assign_and_resume.assert_called_once_with(123)
        job.terminate.assert_called_once()
        job.close.assert_called_once()
        process.wait.assert_called_once()


@unittest.skipUnless(os.name == "nt", "Actual cmd.exe execution requires Windows")
class WindowsBatchExecutionTests(unittest.TestCase):
    def test_batch_and_cmd_preserve_literal_paths_and_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / "中文 空格 & %FANGIDA_TEST_EXPAND% ! ^ (目录)"
            folder.mkdir()
            capture = folder / "capture.py"
            capture.write_text(
                "import json, os, pathlib, sys\n"
                "pathlib.Path(os.environ['FANGIDA_TEST_RESULT']).write_text(\n"
                "    json.dumps(sys.argv[1:], ensure_ascii=False), encoding='utf-8')\n",
                encoding="utf-8",
            )
            arguments = ["中文 空格", "no&space", "%FANGIDA_TEST_EXPAND%", "bang!literal!",
                         "percent%1%2%PATH%end", "caret^and(paren)", "", "tail"]
            environment = dict(os.environ, FANGIDA_TEST_PYTHON=sys.executable,
                               FANGIDA_TEST_CAPTURE=str(capture), FANGIDA_TEST_EXPAND="MUST_NOT_EXPAND")
            for extension in ("bat", "cmd"):
                with self.subTest(extension=extension):
                    result = folder / f"result.{extension}.json"
                    environment["FANGIDA_TEST_RESULT"] = str(result)
                    launcher = folder / f"启动 & %FANGIDA_TEST_EXPAND% !.{extension}"
                    launcher.write_text(
                        '@echo off\nsetlocal DisableDelayedExpansion\n'
                        '"%FANGIDA_TEST_PYTHON%" "%FANGIDA_TEST_CAPTURE%" %*\n'
                        'exit /b %errorlevel%\n',
                        encoding="ascii",
                    )
                    with start_process([str(launcher), *arguments], env=environment,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE) as tree:
                        stdout, stderr = tree.process.communicate(timeout=15)
                        self.assertEqual(tree.process.returncode, 0, (stdout, stderr))
                    self.assertEqual(json.loads(result.read_text(encoding="utf-8")), arguments)


if __name__ == "__main__":
    unittest.main()
