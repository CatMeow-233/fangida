"""Lazy pseudo-C providers; public calls accept completed snapshots only."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..manager import PluginManager
from .models import PseudocodeResult, validate_limits

DEFAULT_PSEUDOC = PluginManager()


def generate_pseudoc(function: Mapping[str, Any], architecture: str, *,
                     provider: str | None = None, manager: PluginManager | None = None,
                     max_instructions: int = 512, max_chars: int = 32768,
                     style: str = "machine"
                     ) -> PseudocodeResult:
    name = provider or ("bytecode_pseudoc" if architecture in {"dex", "jvm"}
                        else "native_pseudoc")
    validate_limits(max_instructions, max_chars)
    if style not in {"machine", "readable"}:
        raise ValueError("style must be machine or readable")
    output = (manager or DEFAULT_PSEUDOC).load_pseudocode(name).generate(
        function, architecture, max_instructions=max_instructions, max_chars=max_chars)
    if (not isinstance(output, PseudocodeResult) or not isinstance(output.pseudoc, str) or
            len(output.pseudoc) > max_chars or type(output.truncated) is not bool or
            not isinstance(output.producer, str) or not isinstance(output.microcode, (tuple, list)) or
            len(output.microcode) > max_instructions):
        raise ValueError("Invalid or oversized pseudocode plugin result")
    if style == "readable" and architecture in {"x86", "x86_64", "arm", "arm64"} and output.microcode:
        from dataclasses import replace
        from .reconstruct import reconstruct_function
        try:
            recovered = reconstruct_function(function, architecture, microcode=output.microcode,
                                             max_instructions=max_instructions, max_chars=max_chars)
        except Exception as exc:
            return replace(output, reconstruction={"style": "machine", "complete": False,
                "unresolved": [{"kind": "reconstruction_failure", "error": type(exc).__name__}]},
                warnings=output.warnings + (f"Source reconstruction unavailable: {type(exc).__name__}",))
        if recovered.pseudoc:
            return replace(recovered, machine_pseudoc=output.pseudoc,
                           truncated=output.truncated or recovered.truncated,
                           warnings=output.warnings + recovered.warnings)
    return output


def pseudoc_prelude(source: Any = None) -> str:
    """可读伪 C 的前导文本：辅助函数的定义（语义与微码一致）与占位函数的声明（只声明，没有定义）。

    source 为空时返回固定前导，可以保存为头文件；传入 generate_pseudoc(..., style="readable") 的结果、
    其 reconstruction 报告、流水线函数记录、按需生成的输出或可读伪 C 文本时，另附该函数引用的外部函数
    声明。前导 + 可读伪 C 可以用 GNU C（GCC/Clang）以 C11 或更新标准编译，见 docs/reconstruction.md。
    """
    from .reconstruct.prelude import pseudoc_prelude as build
    return build(source)


__all__ = ["PseudocodeResult", "generate_pseudoc", "DEFAULT_PSEUDOC", "pseudoc_prelude"]
