"""Attribute current analysis calls through real workers without changing APIs.

This is an attribution run, not an uninstrumented speed benchmark. Decoder
workers stay at one while the normal dedicated xref worker remains enabled.
The full-analysis collector can also observe other worker activity on CPython
3.13; it must not be interpreted as a per-thread CPU profile.
"""
from __future__ import annotations

import argparse
import cProfile
import functools
import gc
import io
import json
from pathlib import Path
import platform
import pstats
import sys
import threading
import time
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fangida.benchmark import _coverage, _evidence_digest, _same_scope, _settings
from fangida.core.kkagent import PluginImpl
from fangida.dispatcher import AnalysisService
from fangida.project import fingerprint
from fangida.xrefs import XrefStage


def profile_text(profiles: list[cProfile.Profile]) -> str:
    output = io.StringIO()
    stats = pstats.Stats(profiles[0], stream=output)
    for profile in profiles[1:]:
        stats.add(profile)
    stats.strip_dirs().sort_stats("cumulative").print_stats(65)
    stats.sort_stats("tottime").print_stats(35)
    return output.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    args = parser.parse_args()
    source = args.source.expanduser().resolve(strict=True)
    before = fingerprint(source)
    settings = _settings(source, 1, full_analysis=True)
    if settings.analyze_threads <= 1:
        raise ValueError("This probe requires a separate xref worker budget")

    analysis_profiles: list[cProfile.Profile] = []
    xref_profiles: list[cProfile.Profile] = []
    analysis_ids: set[int] = set()
    xref_ids: set[int] = set()
    lock = threading.Lock()
    mode = "analysis"
    analyze = PluginImpl._analyze_with_stages
    run_xref = XrefStage.run

    @functools.wraps(analyze)
    def profiled_analysis(self, *positional, **keywords):
        profile = cProfile.Profile()
        with lock:
            analysis_ids.add(threading.get_ident())
        if mode != "analysis":
            return analyze(self, *positional, **keywords)
        try:
            return profile.runcall(analyze, self, *positional, **keywords)
        finally:
            with lock:
                analysis_profiles.append(profile)

    @functools.wraps(run_xref)
    def profiled_xref(self, function, *positional, **keywords):
        @functools.wraps(function)
        def execute(*items, **options):
            profile = cProfile.Profile()
            with lock:
                xref_ids.add(threading.get_ident())
            if mode != "xref":
                return function(*items, **options)
            try:
                return profile.runcall(function, *items, **options)
            finally:
                with lock:
                    xref_profiles.append(profile)
        return run_xref(self, execute, *positional, **keywords)

    baseline = None
    if args.baseline:
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        if baseline["sha256"] != before[0]:
            raise ValueError("Baseline belongs to a different source")
        if not baseline.get("full_analysis") or not baseline["single_thread"]["stable_output"]:
            raise ValueError("Baseline must contain stable full analysis")

    runs = []
    # CPython 3.13 allows only one active cProfile collector. Profile the two
    # roles in separate runs, keeping their real thread separation in both.
    for mode in ("analysis", "xref"):
        analysis_ids.clear()
        xref_ids.clear()
        gc.collect()
        with patch.object(PluginImpl, "_analyze_with_stages", profiled_analysis), \
                patch.object(XrefStage, "run", profiled_xref), \
                AnalysisService(settings) as service:
            started = time.perf_counter()
            result = service.analyze(source, full_analysis=True)
            instrumented_seconds = time.perf_counter() - started
        if result.status == "error":
            raise RuntimeError("Profiled analysis failed: " + "; ".join(result.warnings))
        if not analysis_ids or not xref_ids or analysis_ids & xref_ids:
            raise AssertionError("Decoder analysis and xref did not use distinct threads")
        if fingerprint(source) != before:
            raise AssertionError("Source changed during profiling")
        digest = _evidence_digest(result)
        coverage = _coverage(result)
        matches_baseline = None if baseline is None else digest == baseline["single_thread"]["output_digest"]
        same_scope = None if baseline is None else _same_scope(coverage, baseline["single_thread"]["coverage"])
        if matches_baseline is False or same_scope is False:
            raise AssertionError("Profiled output differs from baseline evidence")
        runs.append({
            "profiled_role": mode, "instrumented_wall_seconds": instrumented_seconds,
            "instrumented_phase_seconds": result.stats.get("phase_seconds"),
            "analysis_thread_ids": sorted(analysis_ids), "xref_thread_ids": sorted(xref_ids),
            "separate_threads_verified": True, "output_digest": digest,
            "matches_uninstrumented_baseline": matches_baseline,
            "matches_baseline_scope": same_scope, "coverage": coverage,
        })
        del result

    output = args.output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    analysis_path = output.with_suffix(".analysis.txt")
    xref_path = output.with_suffix(".xref.txt")
    analysis_path.write_text(profile_text(analysis_profiles), encoding="utf-8")
    xref_path.write_text(profile_text(xref_profiles), encoding="utf-8")
    report = {
        "source": str(source), "sha256": before[0], "size_bytes": before[1],
        "python": platform.python_version(), "platform": platform.platform(),
        "measurement_scope": "cProfile attribution only; wall and phase times are perturbed; excludes evidence hashing and visible Tk rendering",
        "profile_limitations": "Single decoder worker only. The full-analysis collector can observe xref work and waiting on CPython 3.13; this is not a per-thread CPU profile. Xref sampling uses a separate run; the two profiles cannot be added together.",
        "decoder_workers": 1, "analyze_threads_budget": settings.analyze_threads,
        "profiling_runs": runs,
        "analysis_profile": str(analysis_path), "xref_profile": str(xref_path),
    }
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "matches_baseline": all(run["matches_uninstrumented_baseline"] is True for run in runs),
                      "separate_threads_verified": True}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
