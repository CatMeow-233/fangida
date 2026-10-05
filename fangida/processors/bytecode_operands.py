"""Branch operands for bytecode processors and legacy instruction snapshots."""
from __future__ import annotations

from collections.abc import Mapping


def _branch_target(row: Mapping[str, object], kind: str, data: bytes | None) -> int | None:
    branch = row.get("branch_info")
    if isinstance(branch, Mapping) and isinstance(branch.get("target_offset"), int):
        return branch["target_offset"]
    meta = row.get("arch_meta")
    if not isinstance(meta, dict):
        return None
    pc_name = "bytecode_offset" if kind == "jvm" else "code_unit_offset"
    pc = meta.get(pc_name)
    opcode = meta.get("opcode")
    addr = row.get("addr")
    if not isinstance(pc, int) or not isinstance(opcode, int) or not isinstance(addr, int):
        return None
    if kind == "jvm":
        operands = row.get("operands")
        if not isinstance(operands, list) or not operands or not isinstance(operands[0], str):
            return None
        try:
            raw = bytes.fromhex(operands[0])
        except ValueError:
            return None
        if 0x99 <= opcode <= 0xa8 or opcode in {0xc6, 0xc7}:
            return pc + int.from_bytes(raw, "big", signed=True) if len(raw) == 2 else None
        if opcode in {0xc8, 0xc9}:
            return pc + int.from_bytes(raw, "big", signed=True) if len(raw) == 4 else None
    elif kind == "dex" and data is not None and 0 <= addr < len(data) - 1:
        opcode_word = int.from_bytes(data[addr:addr + 2], "little")
        if opcode == 0x28:
            raw = (opcode_word >> 8).to_bytes(1, "little")
        elif opcode in {0x29, *range(0x32, 0x3e)} and addr + 4 <= len(data):
            raw = data[addr + 2:addr + 4]
        elif opcode == 0x2a and addr + 6 <= len(data):
            raw = data[addr + 2:addr + 6]
        else:
            return None
        return pc + int.from_bytes(raw, "little", signed=True)
    return None

