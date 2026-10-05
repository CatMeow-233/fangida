"""Layered, validated settings. YAML is optional; JSON is a valid YAML subset."""
from __future__ import annotations
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import Any
import json
import os

@dataclass(frozen=True)
class Settings:
    max_bytes: int = 16 * 1024 * 1024
    worker_timeout_seconds: float = 30.0
    max_archive_entries: int = 10000
    max_archive_uncompressed_bytes: int = 256 * 1024 * 1024
    io_threads: int = 2
    parse_threads: int = 2
    # 总分析线程预算：默认留 1 个核给界面/系统，最多 13（12 个解码 + 1 个独立的 xref 线程）。
    analyze_threads: int = max(1, min(13, (os.cpu_count() or 2) - 1))
    native_threads: int = 1
    # A single native analysis may decode independent functions concurrently.
    # The outer analyze_threads setting remains the total analysis budget.
    # 默认解码 worker 数：实测（87 万条指令的 arm64 库）4 → 12 个解码进程使解码从 1.6s 降到 0.74s，
    # 超过 12 不再变快。比总预算少 1，保证 xref 始终有独立线程（约束 3、4）。
    semantic_threads: int = max(1, min(12, (os.cpu_count() or 2) - 2))
    mcp_allow_writes: bool = False
    ghidra_enabled: bool = False
    ghidra_timeout_seconds: float = 120.0
    ghidra_max_cpu: int = 2
    ghidra_decompiled_functions: int = 16
    ghidra_decompile_seconds: int = 30
    deep_analysis: bool = True
    semantic_max_functions: int = 128
    semantic_max_instructions: int = 8192
    full_analysis: bool = False
    # 按需生成伪 C 时的单函数指令上限（MCP get_pseudoc generate、GUI“生成伪代码”的默认值）。
    # 默认 512 与分析时的伪 C 流水线相同；最大 8192（与伪 C 插件的 max_instructions 上限一致）。
    pseudoc_max_instructions: int = 512

    def validated(self) -> Settings:
        for item in fields(self):
            value = getattr(self, item.name)
            if item.name in {"mcp_allow_writes", "ghidra_enabled", "deep_analysis", "full_analysis"}:
                if type(value) is not bool:
                    raise ValueError(f"{item.name} must be boolean")
            elif item.name == "ghidra_decompile_seconds":
                if type(value) is not int or not 0 < value <= 3600:
                    raise ValueError(f"Invalid {item.name}: {value!r}")
            elif item.name == "ghidra_decompiled_functions":
                if type(value) is not int or not 0 <= value <= 1000:
                    raise ValueError(f"Invalid {item.name}: {value!r}")
            elif item.name == "pseudoc_max_instructions":
                if type(value) is not int or not 1 <= value <= 8192:
                    raise ValueError(f"Invalid {item.name}: {value!r}")
            elif item.name == "semantic_threads":
                if type(value) is not int or not 1 <= value <= 16:
                    raise ValueError(f"Invalid {item.name}: {value!r}")
            elif item.name in {"io_threads", "parse_threads", "analyze_threads", "native_threads"}:
                if type(value) is not int or not 1 <= value <= 64:
                    raise ValueError(f"Invalid {item.name}: {value!r}")
            elif item.name in {"worker_timeout_seconds", "ghidra_timeout_seconds"}:
                if type(value) not in (int, float) or not 0 < value <= 3600:
                    raise ValueError(f"Invalid {item.name}: {value!r}")
            elif type(value) is not int or not 0 < value <= (1 << 31):
                raise ValueError(f"Invalid {item.name}: {value!r}")
        return self

DEFAULTS = Settings()

def _read_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    content = path.read_text(encoding="utf-8")
    if path.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as exc:
            raise RuntimeError("YAML configuration needs PyYAML; install fangida[config]") from exc
        parsed = yaml.safe_load(content)
    else:
        parsed = json.loads(content)
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ValueError(f"Settings root must be a mapping: {path}")
    return parsed

def load_settings(project_dir: Path | None = None, global_path: Path | None = None,
                  session: dict[str, Any] | None = None) -> Settings:
    """Apply global, project, and session overrides in that order."""
    global_path = global_path or Path.home() / ".config" / "fangida" / "config.yaml"
    project_dir = project_dir or Path.cwd()
    overrides: dict[str, Any] = {}
    for source in (_read_file(global_path), _read_file(project_dir / ".fangida.yaml"), session or {}):
        unknown = source.keys() - Settings.__dataclass_fields__.keys()
        if unknown:
            raise ValueError(f"Unknown setting(s): {', '.join(sorted(unknown))}")
        overrides.update(source)
    return replace(DEFAULTS, **overrides).validated()
