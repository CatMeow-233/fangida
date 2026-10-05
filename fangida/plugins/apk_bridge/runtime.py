"""定位独立 APK Analyzer；宿主不包含其 Loader 或处理器实现。"""
from __future__ import annotations

from importlib import import_module, util
import json
import os
from pathlib import Path
import shlex
import sys


def project_directory():
    explicit = os.environ.get("FANGIDA_APK_ANALYZER_PROJECT")
    directory = (Path(explicit).expanduser() if explicit else
                 Path(__file__).resolve().parents[3].parent / "apk-analyzer")
    if explicit and not (directory / "apk_analyzer" / "worker.py").is_file():
        raise RuntimeError("FANGIDA_APK_ANALYZER_PROJECT 未指向独立 APK Analyzer 项目")
    return directory.resolve() if (directory / "apk_analyzer" / "worker.py").is_file() else None


def worker_launch():
    """首次分析才定位 worker，允许连接独立部署的兼容进程。"""
    command = os.environ.get("FANGIDA_APK_ANALYZER_COMMAND")
    if command:
        if command.lstrip().startswith("["):
            tokens = json.loads(command)
            if not isinstance(tokens, list) or not all(isinstance(token, str) and token for token in tokens):
                raise ValueError("FANGIDA_APK_ANALYZER_COMMAND 的 JSON 值必须是非空字符串参数数组")
        else:
            tokens = shlex.split(command, posix=os.name != "nt")
            if os.name == "nt":
                tokens = [token[1:-1] if len(token) >= 2 and token[0] == token[-1] == '"' else token for token in tokens]
        if not tokens:
            raise RuntimeError("FANGIDA_APK_ANALYZER_COMMAND 不能为空")
        return tokens, None
    environment = dict(os.environ)
    directory = project_directory()
    if directory is not None:
        environment["PYTHONPATH"] = str(directory) + (os.pathsep + environment["PYTHONPATH"]
                                                     if environment.get("PYTHONPATH") else "")
    elif util.find_spec("apk_analyzer") is None:
        raise RuntimeError("APK Analyzer 为独立项目，请单独安装或设置 FANGIDA_APK_ANALYZER_PROJECT")
    return [sys.executable, "-m", "apk_analyzer.worker"], environment


def import_backend_module(name):
    """仅旧直接 Python 调用需要导入后端；普通插件分析走进程协议。"""
    directory = project_directory()
    if directory is not None and str(directory) not in sys.path:
        sys.path.append(str(directory))
    try:
        return import_module("apk_analyzer." + name)
    except ModuleNotFoundError as exc:
        raise RuntimeError("旧 APK Python 入口需要安装独立 APK Analyzer 项目") from exc
