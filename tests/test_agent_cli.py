"""原生 agent 启动器：只定位项目副本，参数与环境跨平台原样传递。"""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from fangida import agent_cli


class AgentCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="fangida-agent-")
        self.addCleanup(self.directory.cleanup)
        self.root = (Path(self.directory.name) / "项目 root").resolve()
        self.root.mkdir()
        self.manifest = self.root / "agents" / "kkagent" / "Cargo.toml"
        self.stderr, self.stdout = io.StringIO(), io.StringIO()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(agent_cli, "_project_root", return_value=self.root))
        self.stack.enter_context(patch.dict(os.environ, {}, clear=True))
        self.stack.enter_context(redirect_stderr(self.stderr))
        self.stack.enter_context(redirect_stdout(self.stdout))
        self.run = self.stack.enter_context(patch.object(agent_cli.subprocess, "run",
                                                        return_value=subprocess.CompletedProcess([], 0)))
        self.which = self.stack.enter_context(patch.object(agent_cli.shutil, "which", return_value=None))
        self.stack.enter_context(patch.object(agent_cli.Path, "home", return_value=self.root / "用户 home"))

    def executable(self, profile: str = "debug", name: str | None = None) -> Path:
        name = name or ("ctfer.exe" if agent_cli._windows() else "ctfer")
        target = self.root / "agents" / "kkagent" / "target" / profile / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"fixture")
        target.chmod(0o755)
        return target

    def build_manifest(self) -> None:
        self.manifest.parent.mkdir(parents=True, exist_ok=True)
        self.manifest.write_text("[workspace]\n", encoding="utf-8")

    def test_debug_launch_passes_arguments_without_shell_and_inherits_cwd(self) -> None:
        binary = self.executable()
        arguments = ["--model", "带 空格", "--", "%USER% ; $(ignored)"]
        self.assertEqual(agent_cli.main(["--", *arguments]), 0)
        self.run.assert_called_once()
        self.assertEqual(self.run.call_args.args, ([str(binary), *arguments],))
        self.assertFalse(self.run.call_args.kwargs["shell"])
        self.assertNotIn("cwd", self.run.call_args.kwargs)
        self.assertEqual(self.run.call_args.kwargs["env"]["FANGIDA_ROOT"], str(self.root))
        self.assertEqual(self.run.call_args.kwargs["env"]["FANGIDA_PYTHON"], sys.executable)
        self.which.assert_not_called()

    def test_release_is_preferred_without_explicit_build(self) -> None:
        self.executable()
        release = self.executable("release")
        self.assertEqual(agent_cli.main([]), 0)
        self.assertEqual(self.run.call_args.args[0], [str(release)])

    def test_explicit_binary_overrides_environment_and_project_candidates(self) -> None:
        self.executable()
        environment_binary = self.executable("other", "环境 agent")
        explicit_binary = self.executable("custom", "指定 agent")
        os.environ["FANGIDA_AGENT_BINARY"] = str(environment_binary)
        self.assertEqual(agent_cli.main(["--agent-binary", str(explicit_binary), "--", "--help"]), 0)
        self.assertEqual(self.run.call_args.args[0], [str(explicit_binary), "--help"])

    def test_environment_binary_and_explicit_environment_are_preserved(self) -> None:
        binary = self.executable("outside", "环境 agent")
        configured = {"FANGIDA_AGENT_BINARY": str(binary), "FANGIDA_ROOT": "自定义 root",
                      "FANGIDA_PYTHON": "自定义 python", "USER_SETTING": "保留"}
        os.environ.update(configured)
        self.assertEqual(agent_cli.main([]), 0)
        self.assertEqual(self.run.call_args.args[0], [str(binary)])
        self.assertEqual(self.run.call_args.kwargs["env"], configured)

    def test_windows_uses_exe_candidate(self) -> None:
        self.executable(name="ctfer")
        binary = self.executable(name="ctfer.exe")
        with patch.object(agent_cli.sys, "platform", "win32"):
            self.assertEqual(agent_cli.main(["--", "中文 参数"]), 0)
        self.assertEqual(self.run.call_args.args[0], [str(binary), "中文 参数"])

    def test_build_uses_manifest_absolute_path_and_new_debug_binary(self) -> None:
        self.build_manifest()
        debug = self.executable()
        self.executable("release")
        self.which.return_value = "/工具 root/cargo"
        self.assertEqual(agent_cli.main(["--build", "--", "--help"]), 0)
        calls = self.run.call_args_list
        self.assertEqual(calls[0].args[0], ["/工具 root/cargo", "build", "--manifest-path",
                                          str(self.manifest), "-p", "kkagent"])
        self.assertEqual(calls[1].args[0], [str(debug), "--help"])
        self.assertTrue(self.manifest.is_absolute())
        for call in calls:
            self.assertFalse(call.kwargs["shell"])
            self.assertNotIn("cwd", call.kwargs)
        self.which.assert_called_once_with("cargo")

    def test_windows_cargo_home_fallback_without_path_tool(self) -> None:
        self.build_manifest()
        binary = self.executable(name="ctfer.exe")
        cargo = self.root / "用户 home" / ".cargo" / "bin" / "cargo.exe"
        cargo.parent.mkdir(parents=True)
        cargo.write_bytes(b"fixture")
        with patch.object(agent_cli.sys, "platform", "win32"):
            self.assertEqual(agent_cli.main(["--build"]), 0)
        self.assertEqual(self.run.call_args_list[0].args[0][0], str(cargo))
        self.assertEqual(self.run.call_args_list[1].args[0], [str(binary)])

    def test_build_failure_does_not_launch_and_propagates_exit_code(self) -> None:
        self.build_manifest()
        self.executable()
        self.which.return_value = "/tools/cargo"
        self.run.return_value = subprocess.CompletedProcess([], 17)
        self.assertEqual(agent_cli.main(["--build"]), 17)
        self.assertEqual(self.run.call_count, 1)
        self.assertIn("构建失败", self.stderr.getvalue())

    def test_missing_binary_shows_build_command_without_path_fallback(self) -> None:
        self.assertEqual(agent_cli.main([]), 2)
        self.assertIn("python3 -m fangida.agent_cli --build", self.stderr.getvalue())
        self.assertIn("--manifest-path", self.stderr.getvalue())
        self.assertIn(str(self.manifest), self.stderr.getvalue())
        self.run.assert_not_called()
        self.which.assert_not_called()

    def test_missing_explicit_binary_does_not_fall_back_to_existing_debug(self) -> None:
        self.executable()
        missing = self.root / "不存在的 agent"
        self.assertEqual(agent_cli.main(["--agent-binary", str(missing)]), 2)
        self.assertIn(str(missing), self.stderr.getvalue())
        self.run.assert_not_called()

    def test_build_requires_source_and_preinstalled_cargo(self) -> None:
        self.assertEqual(agent_cli.main(["--build"]), 2)
        self.assertIn("源码清单", self.stderr.getvalue())
        self.which.assert_not_called()
        self.build_manifest()
        self.assertEqual(agent_cli.main(["--build"]), 2)
        self.assertIn("未找到 cargo", self.stderr.getvalue())
        self.run.assert_not_called()

    def test_launcher_help_does_not_launch_or_build(self) -> None:
        with self.assertRaises(SystemExit) as stopped:
            agent_cli.main(["--help"])
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("--agent-binary", self.stdout.getvalue())
        self.assertIn("-- 后", self.stdout.getvalue())
        self.run.assert_not_called()
        self.which.assert_not_called()

    def test_agent_options_require_separator_and_child_exit_code_is_preserved(self) -> None:
        self.executable()
        with self.assertRaises(SystemExit) as stopped:
            agent_cli.main(["--model", "configuration"])
        self.assertEqual(stopped.exception.code, 2)
        self.run.assert_not_called()
        self.run.return_value = subprocess.CompletedProcess([], 5)
        self.assertEqual(agent_cli.main(["--", "--model", "configuration"]), 5)

    def test_process_failure_is_reported_without_shell_fallback(self) -> None:
        self.executable()
        self.run.side_effect = OSError("fixture startup failure")
        self.assertEqual(agent_cli.main([]), 2)
        self.assertIn("fixture startup failure", self.stderr.getvalue())
        self.assertEqual(self.run.call_count, 1)

    def test_console_entry_is_added(self) -> None:
        manifest = Path(__file__).resolve().parents[1] / "pyproject.toml"
        settings = tomllib.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(settings["project"]["scripts"]["fangida-agent"], "fangida.agent_cli:main")


if __name__ == "__main__":
    unittest.main()
