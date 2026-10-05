"""Local, scope-checked timing of Fangida's bounded native analysis.

The comparison measures warm native analysis calls with different semantic
worker counts. It is not a cross-product benchmark or an accuracy claim.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
from statistics import median
import time
from typing import Any

from . import _json_stream
from .dispatcher import AnalysisService, identify
from .models import AnalysisResult
from .settings import Settings, load_settings


def _prepare(path: Path, runs: int, threads: int | None) -> tuple[Path, str, int, str]:
    if type(runs) is not int or not 1 <= runs <= 100:
        raise ValueError("runs must be between 1 and 100")
    if threads is not None and (type(threads) is not int or not 1 <= threads <= 16):
        raise ValueError("semantic threads must be between 1 and 16")
    path = path.expanduser().resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")
    digest = sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    kind, _ = identify(path)
    return path, digest.hexdigest(), path.stat().st_size, kind


def _settings(path: Path, threads: int | None, full_analysis: bool = False) -> Settings:
    # A benchmark of per-function native workers needs the semantic pass on.
    # Disable the optional external JVM whose startup masks native timing.
    if type(full_analysis) is not bool:
        raise ValueError("full_analysis must be boolean")
    overrides: dict[str, Any] = {"deep_analysis": True, "ghidra_enabled": False,
                                 "full_analysis": full_analysis}
    if threads is not None:
        overrides["semantic_threads"] = threads
    settings = load_settings(project_dir=path.parent, session=overrides)
    available = max(1, settings.analyze_threads - int(settings.analyze_threads > 1))
    if threads is not None and threads > available:
        raise ValueError(f"semantic threads ({threads}) exceed available decoder budget "
                         f"({available}) after reserving the xref thread; "
                         f"analyze_threads={settings.analyze_threads}")
    return settings


def _evidence_digest(result: AnalysisResult) -> str:
    """Hash analysis output, excluding timing/worker statistics.

    Top-level result collections are unordered evidence sets, while block and
    instruction order within each function remains meaningful and is retained.
    """
    canonical = json.JSONEncoder(sort_keys=True, separators=(",", ":"))
    encode = canonical.encode

    def sorted_records(items: list[dict[str, Any]]) -> list[str]:
        # 历史排序键是 json.dumps(item, sort_keys=True)（默认分隔符 ", "/": "）。两种规范文本
        # 只差结构性逗号/冒号后的一个空格，而是否插入空格只取决于相同前缀的词法状态，
        # 所以两段文本的第一处差异在两种格式里是同一对字符：按紧凑文本排序与按历史键排序
        # 结果完全一致（文本相同即记录相同，稳定排序的并列项也不影响摘要）。
        # 每条记录只经 C 编码器编码一次，同一份文本既作排序键又直接参与摘要。
        return sorted(map(encode, items))

    evidence: dict[str, Any] = {
        "kind": result.kind, "status": result.status,
        "functions": sorted_records(result.functions),
        "strings": sorted_records(result.strings),
        "imports": sorted_records(result.imports),
        "exports": sorted_records(result.exports),
        "xrefs": sorted_records(result.xrefs),
        "metadata": result.metadata,
        "warnings": sorted(result.warnings),
    }
    encoded = {"functions", "strings", "imports", "exports", "xrefs"}
    # Stream the canonical encoding: full disassembly can be much larger than
    # an entry preview, and a second complete JSON string would distort RSS.
    # 摘要输入与 JSONEncoder(sort_keys=True, separators=(",", ":")).iterencode(evidence)
    # 逐字节一致：顶层按键排序；预编码记录按约 1 MiB 一批以 "," 拼接后哈希（既摊薄 update
    # 调用开销，又不生成与整个集合等大的临时文本），其余字段由 _json_stream 分块流式编码。
    digest = sha256()
    update = digest.update
    limit = _json_stream.DEFAULT_CHUNK_SIZE
    opening = "{"
    for key in sorted(evidence):
        # 逐项取出：已哈希集合的预编码文本在处理下一个键时即可释放，不与后续流式编码同时驻留。
        value = evidence.pop(key)
        update(f"{opening}{encode(key)}:".encode())
        opening = ","
        if key not in encoded:
            for chunk in _json_stream.iterencode_with(canonical, value):
                update(chunk.encode())
            continue
        update(b"[")
        lead, batch, pending = "", [], 0
        for text in value:
            batch.append(text)
            pending += len(text)
            if pending >= limit:
                update((lead + ",".join(batch)).encode())
                lead, batch, pending = ",", [], 0
        if batch:
            update((lead + ",".join(batch)).encode())
        update(b"]")
    update(b"}")
    return digest.hexdigest()


def _coverage(result: AnalysisResult) -> dict[str, Any]:
    keys = ("semantic_functions", "semantic_pending_symbols", "semantic_instructions",
            "semantic_partial_functions", "semantic_budget_exhausted", "semantic_decoder",
            "semantic_cancelled")
    return {"status": result.status, "functions": len(result.functions),
            "xrefs": len(result.xrefs), "scanned_bytes": result.metadata.get("scanned_bytes"),
            "xref_kinds": dict(sorted(Counter(str(reference.get("kind", "unknown"))
                                              for reference in result.xrefs).items())),
            "function_sources": dict(sorted(Counter(str(function.get("source", "unknown"))
                                                      for function in result.functions).items())),
            "cfg_functions": sum(isinstance(function.get("cfg"), dict) for function in result.functions),
            "cfg_blocks": sum(len(function.get("blocks", [])) for function in result.functions),
            "cfg_frontiers": sum(len(function.get("cfg", {}).get("frontier", []))
                                  for function in result.functions),
            "complete_function_cfgs": sum(function.get("cfg", {}).get("complete") is True
                                          for function in result.functions),
            "full_analysis": result.stats.get("full_analysis", False),
            "full_coverage": result.metadata.get("full_analysis"),
            **{key: result.stats.get(key) for key in (
                "full_instructions", "full_decoded_bytes", "full_executable_bytes",
                "full_decode_complete", "full_cfg_functions", "full_unassigned_instructions",
                "full_function_sources")},
            **{key: result.stats.get(key) for key in keys},
            "semantic_workers_requested": result.stats.get("semantic_workers_requested"),
            "semantic_workers_used": result.stats.get("semantic_workers_used"),
            "semantic_parallel_functions": result.stats.get("semantic_parallel_functions")}


def _same_scope(left: dict[str, Any], right: dict[str, Any]) -> bool:
    scheduling = {"semantic_workers_requested", "semantic_workers_used",
                  "semantic_parallel_functions"}
    return ({key: value for key, value in left.items() if key not in scheduling} ==
            {key: value for key, value in right.items() if key not in scheduling})


def _environment(path: Path, digest: str, size: int, kind: str, runs: int,
                 full_analysis: bool = False) -> dict[str, Any]:
    return {"path": str(path), "sha256": digest, "size_bytes": size,
            "kind": kind, "runs": runs, "python": platform.python_version(),
            "platform": platform.platform(), "cpu_count": os.cpu_count(),
            "full_analysis": full_analysis,
            "scope": ("Independent APK Analyzer bytecode, CFG, xrefs and container metadata; "
                      "result coverage and output budgets are reported separately."
                      if kind in {"apk", "dex", "jar", "class"} else
                      "Full file-backed executable-region disassembly, function recovery, CFG and xrefs; "
                      "Ghidra disabled; recovery completeness is reported separately."
                      if full_analysis else
                      "Deep native semantic analysis enabled; Ghidra disabled; "
                      "analysis remains bounded by configured scan/function/instruction budgets."),
            "measurement_scope": {
                "seconds": "Warm service.analyze wall time; excludes evidence hashing and service startup/shutdown",
                "cold_total_seconds": "Service construction plus first analyze; excludes interpreter/import/hash setup and shutdown; OS caches are uncontrolled",
                "cpu_seconds": "Current-process CPU across all threads; excludes child processes",
                "child_cpu_seconds": "CPU of reaped children during this call; unavailable without resource.getrusage",
                "peak_rss_bytes": "Whole benchmark process lifetime high-water RSS; cumulative across calls and modes, includes evidence hashing; unavailable without resource.getrusage",
                "postprocess_seconds": "Evidence digest and coverage extraction after each call; excluded from seconds",
                "single_thread": "One decoder worker; xref still has a separate worker whenever analyze_threads budget exceeds one",
            }}


def _child_cpu() -> float | None:
    try:
        import resource
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        return usage.ru_utime + usage.ru_stime
    except (ImportError, AttributeError, OSError):
        return None


def _peak_rss() -> int | None:
    try:
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if platform.system() == "Darwin" else value * 1024)
    except (ImportError, AttributeError, OSError):
        return None


def _measure(service: AnalysisService, path: Path) -> tuple[AnalysisResult, dict[str, Any]]:
    cpu_start, child_start = time.process_time(), _child_cpu()
    start = time.perf_counter()
    result = service.analyze(path)
    elapsed = time.perf_counter() - start
    cpu_seconds, child_end = time.process_time() - cpu_start, _child_cpu()
    return result, {"analysis_wall_seconds": round(elapsed, 6),
                    "cpu_seconds": round(cpu_seconds, 6),
                    "child_cpu_seconds": (round(max(0, child_end - child_start), 6)
                                          if child_start is not None and child_end is not None else None),
                    "process_peak_rss_bytes": _peak_rss(),
                    "phase_seconds": dict(result.stats.get("phase_seconds", {}))}


def _summarize(result: AnalysisResult, measurement: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    start = time.perf_counter()
    digest, coverage = _evidence_digest(result), _coverage(result)
    measurement["postprocess_seconds"] = round(time.perf_counter() - start, 6)
    return digest, coverage


def _samples(measurements: list[dict[str, Any]]) -> dict[str, Any]:
    seconds = [item["analysis_wall_seconds"] for item in measurements]
    cpu = [item["cpu_seconds"] for item in measurements]
    return {"seconds": seconds, "median_seconds": median(seconds),
            "cpu_seconds": cpu, "median_cpu_seconds": median(cpu),
            "postprocess_seconds": [item["postprocess_seconds"] for item in measurements],
            "measurements": measurements}


def benchmark(path: Path, runs: int = 3, semantic_threads: int | None = None,
              full_analysis: bool = False) -> dict[str, Any]:
    """Time one native worker setting. Retains legacy `median_seconds` fields."""
    path, digest, size, kind = _prepare(path, runs, semantic_threads)
    if full_analysis and kind not in {"elf", "pe", "macho", "apk", "dex", "jar", "class"}:
        raise ValueError("full benchmark requires native or Android/JVM bytecode input")
    settings = _settings(path, semantic_threads, full_analysis)
    measurements: list[dict[str, Any]] = []
    hashes: list[str] = []
    coverage: dict[str, Any] = {}
    cold_start, cold_cpu = time.perf_counter(), time.process_time()
    with AnalysisService(settings) as service:
        result, cold = _measure(service, path)
        cold_total_seconds = round(time.perf_counter() - cold_start, 6)
        cold_cpu_seconds = round(time.process_time() - cold_cpu, 6)
        cold_digest, cold_coverage = _summarize(result, cold)
        del result
        for _ in range(runs):
            result, measurement = _measure(service, path)
            output_digest, coverage = _summarize(result, measurement)
            hashes.append(output_digest)
            measurements.append(measurement)
            del result
    return {**_environment(path, digest, size, kind, runs, full_analysis),
            "semantic_threads": settings.semantic_threads,
            "decoder_threads_effective": min(settings.semantic_threads,
                                              max(1, settings.analyze_threads - int(settings.analyze_threads > 1))),
            "xref_threads": int(settings.analyze_threads > 1),
            "analyze_threads_budget": settings.analyze_threads,
            "cold_total_seconds": cold_total_seconds, "cold_cpu_seconds": cold_cpu_seconds,
            "cold_measurement": cold, "cold_coverage": cold_coverage,
            "cold_output_digest": cold_digest, "peak_rss_bytes": _peak_rss(),
            **_samples(measurements), "status": coverage["status"], "coverage": coverage,
            "output_digest": hashes[-1], "stable_output": len(set(hashes)) == 1}


def compare_threads(path: Path, runs: int = 3, semantic_threads: int = 2,
                    full_analysis: bool = False) -> dict[str, Any]:
    """Time 1 versus N workers with alternating order and identical budgets."""
    path, digest, size, kind = _prepare(path, runs, semantic_threads)
    if semantic_threads <= 1:
        raise ValueError("comparison needs at least 2 semantic threads")
    if kind not in {"elf", "pe", "macho"}:
        raise ValueError("thread comparison requires an ELF, PE, or Mach-O input")
    settings = {count: _settings(path, count, full_analysis) for count in (1, semantic_threads)}
    samples: dict[int, list[dict[str, Any]]] = {count: [] for count in settings}
    digests: dict[int, list[str]] = {count: [] for count in settings}
    coverage: dict[int, dict[str, Any]] = {}
    cold: dict[int, dict[str, Any]] = {}
    with ExitStack() as stack:
        services: dict[int, AnalysisService] = {}
        for count in (1, semantic_threads):
            cold_start, cold_cpu = time.perf_counter(), time.process_time()
            services[count] = stack.enter_context(AnalysisService(settings[count]))
            result, measurement = _measure(services[count], path)
            cold_total_seconds = round(time.perf_counter() - cold_start, 6)
            cold_cpu_seconds = round(time.process_time() - cold_cpu, 6)
            cold_digest, cold_coverage = _summarize(result, measurement)
            cold[count] = {"cold_total_seconds": cold_total_seconds,
                           "cold_cpu_seconds": cold_cpu_seconds,
                           "cold_measurement": measurement, "cold_coverage": cold_coverage,
                           "cold_output_digest": cold_digest}
            del result
        for iteration in range(runs):
            order = (1, semantic_threads) if iteration % 2 == 0 else (semantic_threads, 1)
            for count in order:
                result, measurement = _measure(services[count], path)
                output_digest, coverage[count] = _summarize(result, measurement)
                digests[count].append(output_digest)
                samples[count].append(measurement)
                del result
    comparable = (all(len(set(values)) == 1 for values in digests.values())
                  and digests[1][-1] == digests[semantic_threads][-1]
                  and _same_scope(coverage[1], coverage[semantic_threads]))
    summaries = {count: _samples(samples[count]) for count in settings}
    medians = {count: summaries[count]["median_seconds"] for count in settings}
    return {**_environment(path, digest, size, kind, runs, full_analysis),
            "peak_rss_bytes": _peak_rss(),
            "settings": {"max_bytes": settings[1].max_bytes,
                         "analyze_threads_budget": settings[1].analyze_threads,
                         "semantic_max_functions": settings[1].semantic_max_functions,
                         "semantic_max_instructions": settings[1].semantic_max_instructions,
                         "full_analysis": full_analysis},
            "single_thread": {"semantic_threads": 1, **summaries[1], **cold[1],
                              "decoder_threads_effective": 1,
                              "xref_threads": int(settings[1].analyze_threads > 1), "coverage": coverage[1],
                              "output_digest": digests[1][-1],
                              "stable_output": len(set(digests[1])) == 1},
            "multi_thread": {"semantic_threads": semantic_threads,
                             **summaries[semantic_threads], **cold[semantic_threads],
                             "decoder_threads_effective": semantic_threads,
                             "xref_threads": int(settings[semantic_threads].analyze_threads > 1),
                             "coverage": coverage[semantic_threads],
                             "output_digest": digests[semantic_threads][-1],
                             "stable_output": len(set(digests[semantic_threads])) == 1},
            "same_evidence_and_scope": comparable,
            "local_median_ratio": (round(medians[1] / medians[semantic_threads], 3)
                                   if comparable and medians[semantic_threads] > 0 else None)}


def main() -> int:
    parser = argparse.ArgumentParser(prog="fangida-bench")
    parser.add_argument("file", type=Path)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--full", action="store_true", help="Time full native or Android/JVM bytecode analysis without Ghidra")
    parser.add_argument("--output", type=Path, help="Save benchmark JSON to this file")
    options = parser.add_mutually_exclusive_group()
    options.add_argument("--semantic-threads", type=int, help="native function workers")
    options.add_argument("--compare-threads", type=int, metavar="N",
                         help="compare 1 and N native function workers")
    args = parser.parse_args()
    try:
        outcome = (compare_threads(args.file, args.runs, args.compare_threads, args.full)
                   if args.compare_threads is not None else
                   benchmark(args.file, args.runs, args.semantic_threads, args.full))
        payload = json.dumps(outcome, indent=2)
        if args.output is not None:
            args.output.expanduser().write_text(payload + "\n", encoding="utf-8")
        print(payload)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
