"""可信脚本入口示例：显式加载插件，求解第一条 ARM64 BR/BLR。"""
from pathlib import Path

from fangida.plugins.manager import PluginManager


def main(analysis):
    rows = analysis.get("metadata", {}).get("full_disassembly", analysis.get("metadata", {}).get("disassembly", ()))
    branch = next((row for row in rows if row.get("mnemonic", "").lower() in {"br", "blr"}), None)
    if branch is None:
        return {"plugin": "arm64_br_solver", "status": "unavailable", "reason": "快照中没有 BR/BLR"}
    manager = PluginManager()
    try:
        path = analysis.get("path")
        source = path if path and Path(path).is_file() else None
        return manager.load_branch_solver().solve(analysis, branch["addr"], source_path=source)
    finally:
        manager.teardown()
