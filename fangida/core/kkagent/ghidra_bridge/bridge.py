"""Bounded, lazy subprocess adapter for Ghidra's official headless launcher."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.resources import as_file, files
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any

from ....processes import start_process


class GhidraUnavailable(RuntimeError):
    """The optional Ghidra launcher is unconfigured or cannot be executed."""


class GhidraAnalysisError(RuntimeError):
    """Ghidra failed, timed out, or returned an invalid export."""


def _windows_batch_launcher(path: Path) -> bool:
    """Keep the platform test separate from pathlib's platform selection."""
    return os.name == "nt" and path.suffix.lower() in {".bat", ".cmd"}


def _batch_sensitive_path(path: Path) -> bool:
    # Ghidra's batch scripts enable delayed expansion and use CALL. Escaping
    # cmd.exe's first parsing pass cannot preserve these argument characters.
    return any(character in str(path) for character in "%!&^")


def _validate_batch_root(path: Path, description: str) -> None:
    if any(character in str(path) for character in "%!"):
        raise GhidraUnavailable(
            f"Ghidra Windows batch launcher cannot preserve '%' or '!' in its {description}: {path}; "
            "use a path without those characters"
        )


@dataclass(frozen=True)
class GhidraSnapshot:
    """A bounded Ghidra supplement, independent of the main analysis result.

    Addresses are unsigned integer offsets. ``address_space`` and the two
    ``*_space`` xref fields distinguish offsets from separate address spaces.
    The bridge does not infer a CFG. Optional pseudo-C comes only from Ghidra's
    decompiler and is labeled with its producer.
    """

    functions: list[dict[str, Any]]
    xrefs: list[dict[str, Any]]
    pcode: list[dict[str, Any]]
    decompiled_functions: list[dict[str, Any]]
    stats: dict[str, Any]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON-compatible bridge boundary representation."""
        return {
            "functions": self.functions,
            "xrefs": self.xrefs,
            "pcode": self.pcode,
            "decompiled_functions": self.decompiled_functions,
            "stats": self.stats,
            "warnings": self.warnings,
        }


@dataclass(frozen=True)
class GhidraBridge:
    """Run one isolated temporary Ghidra project per explicit analysis call.

    This is a command adapter, not a persistent daemon. Subsequent calls can
    be cached by the caller using its binary digest and Ghidra version.
    """

    headless_path: str | Path | None = None
    timeout_seconds: float = 120.0
    max_cpu: int = 2
    max_functions: int = 10_000
    max_xrefs: int = 100_000
    max_pcode_instructions: int = 5_000
    max_decompiled_functions: int = 16
    # Total budget for all selected functions, capped further by process time.
    max_decompile_seconds: int = 30
    max_result_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        """Validate limits before handing them to the subprocess."""
        if (type(self.timeout_seconds) not in (int, float) or
            not math.isfinite(self.timeout_seconds) or
            not 0 < self.timeout_seconds <= 3600):
            raise ValueError("timeout_seconds must be finite and in (0, 3600]")
        for name in ("max_cpu", "max_functions", "max_xrefs", "max_pcode_instructions",
                     "max_decompile_seconds", "max_result_bytes"):
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= 1 << 30:
                raise ValueError(f"{name} must be a positive integer no greater than 2^30")
        if (type(self.max_decompiled_functions) is not int or
            not 0 <= self.max_decompiled_functions <= 1_000):
            raise ValueError("max_decompiled_functions must be an integer in [0, 1000]")
        if self.max_decompile_seconds > 3600:
            raise ValueError("max_decompile_seconds must not exceed 3600")

    @classmethod
    def from_environment(cls, **kwargs: Any) -> GhidraBridge:
        """Resolve an explicit launcher path without starting or probing Java."""
        launcher = os.environ.get("FANGIDA_GHIDRA_HEADLESS")
        if not launcher and os.environ.get("GHIDRA_HOME"):
            suffix = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
            launcher = str(Path(os.environ["GHIDRA_HOME"]) / "support" / suffix)
        return cls(headless_path=launcher, **kwargs)

    def available(self) -> bool:
        """Return whether the configured launcher exists and is executable."""
        try:
            self._launcher()
        except GhidraUnavailable:
            return False
        return True

    def _launcher(self) -> Path:
        """Validate the chosen launcher without consulting the ambient PATH."""
        if not self.headless_path:
            raise GhidraUnavailable(
                "Ghidra is not configured: set FANGIDA_GHIDRA_HEADLESS or GHIDRA_HOME"
            )
        path = Path(self.headless_path).expanduser().resolve()
        if not path.is_file() or (os.name != "nt" and not os.access(path, os.X_OK)):
            raise GhidraUnavailable(f"Ghidra headless launcher is not executable: {path}")
        if _windows_batch_launcher(path):
            _validate_batch_root(path, "installation path")
        return path

    def analyze(self, path: str | Path) -> GhidraSnapshot:
        """Analyze an existing file on demand and parse the script's result.

        Captured logs and the temporary Ghidra project are removed even when
        analysis fails. A timeout terminates the launcher and its descendants.
        Windows batch arguments with expansion characters use temporary copies.
        """
        launcher = self._launcher()
        windows_batch = _windows_batch_launcher(launcher)
        binary = Path(path).expanduser().resolve(strict=True)
        if not binary.is_file():
            raise ValueError(f"Expected a regular binary file: {binary}")

        with tempfile.TemporaryDirectory(prefix="fangida-ghidra-") as temp_name:
            temporary = Path(temp_name)
            imported_binary = binary
            if windows_batch:
                _validate_batch_root(temporary, "temporary path")
                if _batch_sensitive_path(binary):
                    imported_binary = temporary / "input.bin"
                    try:
                        shutil.copyfile(binary, imported_binary)
                    except OSError as exc:
                        raise GhidraAnalysisError(f"Cannot stage the Ghidra input: {exc}") from exc
            output = temporary / "result.json"
            run_log = temporary / "headless.log"
            script_log = temporary / "script.log"
            analysis_seconds = max(
                1, math.floor(self.timeout_seconds * (0.6 if self.max_decompiled_functions else 0.8))
            )
            decompile_seconds = min(
                self.max_decompile_seconds, max(1, math.floor(self.timeout_seconds * 0.3))
            )
            command = [
                str(launcher), str(temporary), "FangidaTemporary",
                "-import", str(imported_binary),
                "-scriptPath", "",  # replaced with the packaged script directory
                "-postScript", "FangidaExport.java", str(output),
                str(self.max_functions), str(self.max_xrefs), str(self.max_pcode_instructions),
                str(self.max_decompiled_functions), str(decompile_seconds),
                "-analysisTimeoutPerFile", str(analysis_seconds),
                "-max-cpu", str(self.max_cpu),
                "-readOnly", "-deleteProject",
                "-log", str(run_log), "-scriptlog", str(script_log),
            ]
            with as_file(files(__package__).joinpath("FangidaExport.java")) as script:
                if not script.is_file():
                    raise GhidraUnavailable("FangidaExport.java is missing from the package")
                if windows_batch and _batch_sensitive_path(script.parent):
                    staged_script = temporary / "scripts" / "FangidaExport.java"
                    staged_script.parent.mkdir()
                    try:
                        shutil.copyfile(script, staged_script)
                    except OSError as exc:
                        raise GhidraUnavailable(f"Cannot stage the Ghidra export script: {exc}") from exc
                    script = staged_script
                command[6] = str(script.parent)
                with run_log.open("wb") as log_stream:
                    try:
                        tree = start_process(
                            command, stdin=subprocess.DEVNULL, stdout=log_stream,
                            stderr=subprocess.STDOUT,
                        )
                    except OSError as exc:
                        raise GhidraUnavailable(f"Cannot launch Ghidra: {exc}") from exc
                    with tree:
                        try:
                            code = tree.process.wait(timeout=self.timeout_seconds)
                        except subprocess.TimeoutExpired as exc:
                            raise GhidraAnalysisError(
                                f"Ghidra exceeded {self.timeout_seconds:g} seconds"
                            ) from exc

            if code != 0:
                raise GhidraAnalysisError(
                    f"Ghidra exited with code {code}: {_diagnostic(script_log, run_log)}"
                )
            if not output.is_file():
                raise GhidraAnalysisError(
                    "Ghidra completed without a bridge result; the post-script may have failed: "
                    + _diagnostic(script_log, run_log)
                )
            if output.stat().st_size > self.max_result_bytes:
                raise GhidraAnalysisError("Ghidra bridge result exceeded max_result_bytes")
            try:
                result = json.loads(output.read_text(encoding="utf-8"))
            except (UnicodeError, ValueError) as exc:
                raise GhidraAnalysisError("Ghidra bridge emitted invalid JSON") from exc
            return _parse_snapshot(result, self)


def _tail(path: Path, max_bytes: int = 2_048) -> str:
    """Read only a bounded diagnostic suffix from a potentially large log."""
    try:
        with path.open("rb") as stream:
            stream.seek(0, os.SEEK_END)
            stream.seek(max(0, stream.tell() - max_bytes))
            return stream.read().decode("utf-8", errors="replace").strip()
    except OSError:
        return "no log available"


def _diagnostic(*paths: Path) -> str:
    """Include bounded tails from both script and launcher logs when present."""
    snippets = [_tail(path) for path in paths if path.is_file()]
    return " | ".join(part for part in snippets if part) or "no log available"


def _parse_snapshot(payload: Any, limits: GhidraBridge) -> GhidraSnapshot:
    """Reject missing, malformed, or over-limit results before merging them."""
    if (not isinstance(payload, dict) or type(payload.get("schema_version")) is not int or
        payload["schema_version"] != 2):
        raise GhidraAnalysisError("Unsupported Ghidra bridge result schema")
    if payload.get("status") != "ok":
        raise GhidraAnalysisError("Ghidra bridge export did not complete")
    keys = {"functions": limits.max_functions, "xrefs": limits.max_xrefs,
            "pcode": limits.max_pcode_instructions,
            "decompiled_functions": limits.max_decompiled_functions}
    for key, maximum in keys.items():
        value = payload.get(key)
        if not isinstance(value, list) or len(value) > maximum:
            raise GhidraAnalysisError(f"Invalid or over-limit {key} in Ghidra export")
        if not all(isinstance(item, dict) for item in value):
            raise GhidraAnalysisError(f"Invalid {key} entry in Ghidra export")
    for function in payload["functions"]:
        if (not _address(function.get("start")) or
            not isinstance(function.get("name"), str) or
            not isinstance(function.get("address_space"), str)):
            raise GhidraAnalysisError("Malformed Ghidra function")
    for xref in payload["xrefs"]:
        if (not _address(xref.get("src")) or not _address(xref.get("dst")) or
            xref.get("kind") not in ("call", "jmp", "data") or
            not isinstance(xref.get("src_space"), str) or
            not isinstance(xref.get("dst_space"), str)):
            raise GhidraAnalysisError("Malformed Ghidra xref")
    for entry in payload["pcode"]:
        if (not _address(entry.get("addr")) or
            not isinstance(entry.get("address_space"), str) or
            not isinstance(entry.get("ops"), list)):
            raise GhidraAnalysisError("Malformed Ghidra pcode entry")
        for op in entry["ops"]:
            if (not isinstance(op, dict) or not isinstance(op.get("opcode"), str) or
                not isinstance(op.get("inputs"), list) or
                not all(isinstance(item, str) for item in op["inputs"])):
                raise GhidraAnalysisError("Malformed Ghidra pcode operation")
    function_keys = {(item["start"], item["address_space"]) for item in payload["functions"]}
    seen_decompiled: set[tuple[int, str]] = set()
    total_pseudoc_chars = 0
    for entry in payload["decompiled_functions"]:
        key = (entry.get("start"), entry.get("address_space"))
        if (not _address(entry.get("start")) or
            not isinstance(entry.get("address_space"), str) or
            key not in function_keys or key in seen_decompiled or
            not isinstance(entry.get("pseudoc"), str) or
            not entry["pseudoc"] or len(entry["pseudoc"]) > 131_072 or
            entry.get("producer") != "ghidra" or
            type(entry.get("truncated")) is not bool):
            raise GhidraAnalysisError("Malformed Ghidra decompiled function")
        seen_decompiled.add(key)
        total_pseudoc_chars += len(entry["pseudoc"])
        if total_pseudoc_chars > 524_288:
            raise GhidraAnalysisError("Ghidra pseudo-C exceeded total text limit")
    stats = payload.get("stats")
    warnings = payload.get("warnings")
    if (not isinstance(stats, dict) or not isinstance(warnings, list) or
        not all(isinstance(item, str) for item in warnings)):
        raise GhidraAnalysisError("Malformed Ghidra export metadata")
    return GhidraSnapshot(payload["functions"], payload["xrefs"], payload["pcode"],
                          payload["decompiled_functions"], stats, warnings)


def _address(value: Any) -> bool:
    """Validate a JSON integer offset without accepting bool as an integer."""
    return type(value) is int and 0 <= value <= 0xffffffffffffffff
