"""Entry-window disassembly into a JSON-compatible instruction IR.

Capstone is preferred. GNU/LLVM objdump is a bounded, isolated fallback for x86
when Capstone is not installed; neither path claims function boundaries.
"""
from __future__ import annotations

import re
from typing import Any

from ...models import Instruction
from ...processors import get_processor
from ...processors.decoder import (NativeDecoder, branch_info, decode_objdump,
                                  objdump_data_metadata, _LINE, _TARGET)
from .binary import BinaryImage
from .objdump_backend import ObjdumpUnavailable, available_backends, disassemble_bytes


MAX_CODE_BYTES = 512
MAX_INSTRUCTIONS = 128


# Compatibility entry point for processor-level branch classification.
# 直接引用处理器的默认分类：解码器据身份识别默认分类，才会做需要操作数的 ARM 细化
# （bx lr、pop {pc}）并缓存助记符分类；入口窗口、semantic 与 full 三条路径因此结果一致。
# 补丁点不变：测试仍可替换 translator._branch。
_branch = branch_info


def _entry_bytes(data: bytes, image: BinaryImage) -> tuple[bytes, int] | None:
    offset, address = image.entry_offset, image.entry_address
    if offset is None or address is None or not (0 <= offset < len(data)):
        return None
    for section in image.sections:
        start, size = section["offset"], section["size"]
        if section["executable"] and start <= offset < start + size:
            end = min(len(data), start + size, offset + MAX_CODE_BYTES)
            declared = [function["size"] for function in image.functions
                        if function["start"] == address and isinstance(function.get("size"), int)
                        and function["size"] > 0]
            if declared:
                end = min(end, offset + min(declared))
            return data[offset:end], address
    return None


def disassemble_entry(data: bytes, image: BinaryImage) -> tuple[list[dict[str, Any]], list[str]]:
    """Return a limited entry-point window and any capability warnings."""
    entry = _entry_bytes(data, image)
    if entry is None:
        return [], ["No executable entry bytes within scan budget"]
    code, address = entry
    try:
        processor = get_processor(image.architecture, image.endian)
    except Exception as exc:
        return [], [f"Capstone could not decode entry point: {type(exc).__name__}: {exc}"]
    if (processor.engine == "objdump" and type(processor) is NativeDecoder) or (processor.engine == "none" and
            image.architecture in {"arm", "arm64"}):
        output, warnings = _objdump(code, address, image.architecture)
        return objdump_data_metadata(output, image.architecture), warnings
    if processor.engine == "none":
        return [], [processor.warning or f"Disassembly unavailable for {image.architecture}"]
    try:
        if type(processor) is NativeDecoder:
            output, warnings = processor.decode_bytes(
                code, address, max_instructions=MAX_INSTRUCTIONS, classify=_branch, include_data=True)
        else:
            output, warnings = processor.decode_bytes(code, address, max_instructions=MAX_INSTRUCTIONS)
        failures = [warning for warning in warnings if warning.startswith("Capstone decode failed:")]
        if failures:
            return [], [failures[0].replace("Capstone decode failed:", "Capstone could not decode entry point:", 1)]
        return output, (warnings if output else ["Disassembler found no instructions at entry point"])
    except Exception as exc:
        return [], [f"Capstone could not decode entry point: {type(exc).__name__}: {exc}"]


def _objdump(code: bytes, address: int, arch: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Preserve existing fallback patch points while delegating CPU parsing."""
    return decode_objdump(code, address, arch, max_instructions=MAX_INSTRUCTIONS,
                          render=disassemble_bytes, classify=_branch)


def objdump_available() -> bool:
    """Whether a recognized GNU or LLVM fallback tool is installed."""
    return bool(available_backends())
