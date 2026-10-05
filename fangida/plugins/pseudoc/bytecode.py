"""Conservative, bounded Java-like outlines from DEX/JVM bytecode listings.

These sketches preserve observed calls and branch targets. They do not perform
stack/register data flow, reconstruct source expressions, or infer Kotlin
syntax from a Kotlin metadata string table.
"""
from __future__ import annotations

from collections.abc import Mapping

from .models import PseudocodeResult, validate_limits
from .bytecode_types import (PRIMITIVES, MAX_OUTLINE_CHARS, _type_at,
                             method_signature, kotlin_hints, _call_name)


def outline(name: str, descriptor: str, kind: str,
            instructions: list[dict[str, object]], bytecode_length: int,
            *, access_flags: int = 0, bytecode: bytes | None = None
            ) -> tuple[str, bool]:
    """Produce a bounded outline from only the instructions actually listed."""
    signature = method_signature(name, descriptor, access_flags)
    lines = ["// Bytecode-derived outline; values and source syntax are not recovered.",
             f"{signature} {{"]
    targets: dict[int, int] = {}
    for row in instructions:
        branch = row.get("branch_info", {})
        target = branch.get("target_offset") if isinstance(branch, Mapping) else None
        if isinstance(target, int) and isinstance(row.get("addr"), int):
            targets[int(row["addr"])] = target
    label_targets = set(targets.values())
    pc_key = "bytecode_offset" if kind == "jvm" else "code_unit_offset"
    retained_offsets = {row.get("arch_meta", {}).get(pc_key) for row in instructions[:64]}
    unresolved_targets = False
    for row in instructions[:64]:
        meta = row.get("arch_meta", {})
        offset = meta.get("bytecode_offset" if kind == "jvm" else "code_unit_offset") if isinstance(meta, dict) else None
        if not isinstance(offset, int):
            continue
        if offset in label_targets:
            lines.append(f"L{offset:04x}:")
        mnemonic = str(row.get("mnemonic", "unknown"))
        addr = row.get("addr")
        target = targets.get(addr) if isinstance(addr, int) else None
        prefix = f"  /* +0x{offset:x} */ "
        if target is not None:
            opcode = meta.get("opcode") if isinstance(meta, dict) else None
            conditional = mnemonic.startswith("if") or (kind == "dex" and
                         isinstance(opcode, int) and 0x32 <= opcode <= 0x3d)
            clause = "if (/* bytecode condition */) " if conditional else ""
            if target in retained_offsets:
                lines.append(f"{prefix}{clause}goto L{target:04x};")
            else:
                unresolved_targets = True
                lines.append(f"{prefix}/* {mnemonic}: target L{target:04x} outside instruction snapshot */")
        elif mnemonic.startswith("invoke") and isinstance(row.get("operands"), list) and row["operands"]:
            call = _call_name(str(row["operands"][0]))
            lines.append(f"{prefix}/* {mnemonic}: arguments symbolic */ {call};")
        elif mnemonic == "return-void" or (kind == "jvm" and mnemonic == "return"):
            lines.append(f"{prefix}return;")
        elif mnemonic in {"areturn", "ireturn", "lreturn", "freturn", "dreturn",
                          "return", "return-wide", "return-object"}:
            lines.append(f"{prefix}return /* symbolic bytecode value */;")
        elif mnemonic.startswith("goto") or mnemonic.startswith("if") or "switch" in mnemonic:
            lines.append(f"{prefix}/* {mnemonic}: target/conditions unresolved */")
        else:
            lines.append(f"{prefix}/* {mnemonic} */")
    consumed = 0
    if instructions:
        last = instructions[-1]
        meta = last.get("arch_meta", {})
        pc = meta.get("bytecode_offset" if kind == "jvm" else "code_unit_offset") if isinstance(meta, dict) else None
        if isinstance(pc, int) and isinstance(last.get("size"), int):
            consumed = pc * (2 if kind == "dex" else 1) + int(last["size"])
    truncated = consumed < bytecode_length or len(instructions) > 64 or unresolved_targets
    if truncated:
        lines.append("  /* Remaining bytecode omitted by inspection limit. */")
    lines.append("}")
    return "\n".join(lines), truncated


class PluginImpl:
    name = "bytecode_pseudoc"
    version = "0.4.0"

    def capabilities(self) -> tuple[str, ...]:
        return ("jvm", "dex", "bytecode_outline", "snapshot_only")

    def generate(self, function: Mapping[str, object], architecture: str, *,
                 max_instructions: int = 512, max_chars: int = 32768) -> PseudocodeResult:
        validate_limits(max_instructions, max_chars)
        if architecture not in {"jvm", "dex"}:
            return PseudocodeResult(warnings=(f"Bytecode pseudo-C unavailable for {architecture}",))
        rows = function.get("disassembly", [])
        selected = rows[:min(max_instructions, 65)]
        char_limit = min(max_chars, MAX_OUTLINE_CHARS)
        while True:
            text, truncated = outline(str(function.get("name", "method")),
                str(function.get("descriptor", "")), architecture, selected,
                int(function.get("bytecode_length", 0)),
                access_flags=int(function.get("access_flags", 0)))
            truncated |= len(rows) > len(selected)
            if len(text) <= char_limit:
                return PseudocodeResult(text, "fangida_bytecode_outline", truncated)
            if not selected:
                text = "method /* Declaration exceeds outline budget */ {\n  /* Instructions omitted. */\n}"
                return PseudocodeResult(text, "fangida_bytecode_outline", True)
            # Regenerate after reducing the snapshot so every goto still has
            # its label, or an explicit unresolved-target annotation.
            selected = selected[:len(selected) // 2]

    def teardown(self) -> None:
        pass
