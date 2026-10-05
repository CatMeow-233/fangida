"""Portable GNU/LLVM adapters for bounded x86 instruction windows.

LLVM has no GNU-style raw binary input mode. Wrap only the supplied bytes in
a minimal ELF object, so neither backend parses the original input container.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


class ObjdumpUnavailable(RuntimeError):
    """No discovered backend could decode the requested instruction window."""


@dataclass(frozen=True)
class ObjdumpBackend:
    executable: str
    provider: str


@lru_cache(maxsize=16)
def _provider(executable: str) -> str | None:
    try:
        result = subprocess.run(
            [executable, "--version"], capture_output=True, timeout=3,
            check=False, text=True, encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    version = result.stdout.lower()
    if result.returncode == 0:
        if "gnu objdump" in version or "gnu binutils" in version:
            return "gnu"
        if "llvm" in version:
            return "llvm"
    return None


def available_backends() -> tuple[ObjdumpBackend, ...]:
    """Resolve PATH on each call; cache version probes for resolved tools."""
    found: list[ObjdumpBackend] = []
    seen: set[str] = set()
    for name in ("gobjdump", "objdump", "llvm-objdump"):
        executable = shutil.which(name)
        if executable is None or executable in seen:
            continue
        seen.add(executable)
        provider = _provider(executable)
        if provider is not None:
            found.append(ObjdumpBackend(executable, provider))
    return tuple(found)


def _elf_window(code: bytes, address: int, arch: str) -> bytes:
    bits = 64 if arch == "x86_64" else 32
    if not 0 <= address < (1 << bits) or address + len(code) > (1 << bits):
        raise ValueError(f"Instruction window exceeds the {bits}-bit address space")
    header_size, section_size = (64, 64) if bits == 64 else (52, 40)
    names = b"\0.text\0.shstrtab\0"
    names_offset = header_size + len(code)
    table_offset = (names_offset + len(names) + 7) // 8 * 8
    ident = b"\x7fELF" + bytes((2 if bits == 64 else 1, 1, 1)) + bytes(9)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH" if bits == 64 else "<16sHHIIIIIHHHHHH",
        ident, 1, 62 if bits == 64 else 3, 1, 0, 0, table_offset, 0,
        header_size, 0, 0, section_size, 3, 2,
    )
    section_format = "<IIQQQQIIQQ" if bits == 64 else "<IIIIIIIIII"
    sections = bytes(section_size) + struct.pack(
        section_format, 1, 1, 6, address, header_size, len(code), 0, 0, 1, 0,
    ) + struct.pack(
        section_format, 7, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0,
    )
    return (header + code + names).ljust(table_offset, b"\0") + sections


def disassemble_bytes(code: bytes, address: int, arch: str) -> tuple[str, str]:
    """Return backend output and provenance, retrying other discovered tools."""
    backends = available_backends()
    if not backends:
        raise ObjdumpUnavailable("No compatible GNU or LLVM objdump found on PATH")
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="fangida-disasm-") as directory:
        for backend in backends:
            source = Path(directory) / ("entry.o" if backend.provider == "llvm" else "entry.bin")
            if backend.provider == "llvm":
                source.write_bytes(_elf_window(code, address, arch))
                command = [backend.executable, "-d", "--section=.text",
                           "--disassemble-zeroes", "--x86-asm-syntax=intel", str(source)]
            else:
                source.write_bytes(code)
                machine = "i386:x86-64" if arch == "x86_64" else "i386"
                command = [backend.executable, "-D", "--disassemble-zeroes", "--insn-width=16",
                           "-b", "binary", "-m", machine, "-M", "intel",
                           f"--adjust-vma={address}", str(source)]
            try:
                completed = subprocess.run(
                    command, capture_output=True, timeout=3, check=False,
                    text=True, encoding="utf-8", errors="replace",
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append(f"{backend.provider}: {type(exc).__name__}: {exc}")
                continue
            if completed.returncode == 0 and completed.stdout.strip():
                return completed.stdout, backend.provider
            diagnostic = completed.stderr.strip()[:300] or f"exit status {completed.returncode}"
            errors.append(f"{backend.provider}: {diagnostic}")
    raise ObjdumpUnavailable("; ".join(errors))
