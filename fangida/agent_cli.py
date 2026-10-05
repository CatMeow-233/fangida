"""启动项目内的原生 Fangida agent，构建只在显式请求时执行。"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _windows() -> bool:
    return sys.platform == "win32"


def _command_text(arguments: list[str]) -> str:
    return subprocess.list2cmdline(arguments) if _windows() else shlex.join(arguments)


def _executable(path: Path) -> bool:
    return path.is_file() and (_windows() or os.access(path, os.X_OK))


def _find_cargo() -> str:
    configured = shutil.which("cargo")
    if configured:
        return configured
    bundled = Path.home() / ".cargo" / "bin" / ("cargo.exe" if _windows() else "cargo")
    if _executable(bundled):
        return str(bundled)
    raise FileNotFoundError("未找到 cargo；构建需要已安装的 Rust 工具链。启动器不会自动安装或更新。")


def _agent_binary(root: Path, explicit: Path | None, *, built: bool = False) -> Path:
    configured = explicit if explicit is not None else os.environ.get("FANGIDA_AGENT_BINARY")
    if configured:
        binary = Path(configured).expanduser().resolve()
        if not _executable(binary):
            raise FileNotFoundError(f"指定的 agent 文件不存在或不可执行：{binary}")
        return binary
    filename = "ctfer.exe" if _windows() else "ctfer"
    # --build 执行普通 debug 构建，随后使用新产物，避免已有 release 遮住本次修改。
    profiles = ("debug",) if built else ("release", "debug")
    for profile in profiles:
        binary = root / "agents" / "kkagent" / "target" / profile / filename
        if _executable(binary):
            return binary
    manifest = root / "agents" / "kkagent" / "Cargo.toml"
    command = _command_text(["cargo", "build", "--manifest-path", str(manifest), "-p", "kkagent"])
    raise FileNotFoundError(
        "未找到项目内的原生 agent。请从 Fangida 源码目录运行 "
        "python3 -m fangida.agent_cli --build，或指定 --agent-binary。\n"
        f"构建命令：{command}")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    separator = arguments.index("--") if "--" in arguments else len(arguments)
    launcher_arguments = arguments[:separator]
    agent_arguments = arguments[separator + 1:] if separator < len(arguments) else []
    parser = argparse.ArgumentParser(
        prog="fangida-agent",
        description="启动原生支持 Fangida 分析器的项目内 agent。",
        epilog="将 agent 参数放在 -- 后；例如 fangida-agent -- --help 查看 agent 自身的帮助。")
    parser.add_argument("--agent-binary", type=Path,
                        help="指定 agent 可执行文件；优先于 FANGIDA_AGENT_BINARY")
    parser.add_argument("--build", action="store_true",
                        help="先运行 cargo build -p kkagent，再启动（不安装或更新工具链）")
    options = parser.parse_args(launcher_arguments)
    root = _project_root()
    environment = os.environ.copy()
    environment.setdefault("FANGIDA_PYTHON", sys.executable)
    environment.setdefault("FANGIDA_ROOT", str(root))
    try:
        if options.build:
            manifest = root / "agents" / "kkagent" / "Cargo.toml"
            if not manifest.is_file():
                raise FileNotFoundError(f"缺少 agent 源码清单：{manifest}；请使用包含 agents/kkagent 的源码目录。")
            command = [_find_cargo(), "build", "--manifest-path", str(manifest), "-p", "kkagent"]
            completed = subprocess.run(command, env=environment, shell=False)
            if completed.returncode:
                print(f"fangida-agent：构建失败，退出码 {completed.returncode}。", file=sys.stderr)
                return completed.returncode
        binary = _agent_binary(root, options.agent_binary, built=options.build)
        return subprocess.run([str(binary), *agent_arguments], env=environment, shell=False).returncode
    except OSError as error:
        print(f"fangida-agent：{error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
