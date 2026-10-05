"""Prepare one Windows batch entry boundary without shell-interpreting data.

Argument values enter cmd through separate inherited environment variables;
the command contains only quoted references to controlled variable names.
Variable expansion is not recursive, and delayed expansion is disabled. Do
not introduce CALL here: it adds another parsing/expansion boundary.

This preserves arguments at entry to a batch program. A target that enables
delayed expansion, uses CALL, or strips its own quotes must handle its own
arguments correctly. For example, Ghidra's upstream Windows launch scripts
perform additional expansions; this adapter cannot repair their internals.

References:
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmd
https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import ntpath
import os
from typing import Any
from uuid import uuid4


CMD_MAX_CHARACTERS = 8191


@dataclass(frozen=True)
class BatchInvocation:
    command_line: str
    executable: str
    environment: dict[str, str]


def _text(value: Any) -> str:
    value = os.fspath(value)
    if not isinstance(value, str):
        raise TypeError("Windows batch arguments must be Unicode strings or text paths")
    return value


def _is_batch(value: str) -> bool:
    return ntpath.splitext(value)[1].lower() in (".bat", ".cmd")


def _environment_value(environment: Mapping[str, str], name: str) -> str | None:
    for key, value in environment.items():
        if key.casefold() == name.casefold():
            return value
    return None


def _utf16_length(value: str) -> int:
    return len(value.encode("utf-16-le", errors="surrogatepass")) // 2


def prepare_windows_batch(
    args: Any,
    *,
    env: Mapping[str, str] | None = None,
    executable: str | os.PathLike[str] | None = None,
    shell: bool = False,
) -> BatchInvocation | None:
    """Return a cmd invocation for a batch path, or None for other programs.

    Pass batch paths as an argument sequence or a single text/path value.
    Raw shell command strings are not parsed. Double quotes and control
    characters are rejected explicitly: they cannot name ordinary Windows
    files and cannot safely cross this quoted batch boundary. Empty arguments
    are represented directly as two quotes rather than undefined variables.
    """
    if isinstance(args, (str, os.PathLike)):
        arguments = [_text(args)]
    elif isinstance(args, Sequence) and args:
        arguments = list(args)
    else:
        return None
    program = _text(executable if executable is not None else arguments[0])
    if not _is_batch(program):
        return None
    if executable is not None:
        raise ValueError("Windows batch launch does not support executable overrides")
    if shell:
        raise ValueError("Windows batch launch requires shell=False and separate arguments")
    arguments = [_text(argument) for argument in arguments]
    if any('"' in argument or any(ord(char) < 32 for char in argument)
           for argument in arguments):
        raise ValueError("Windows batch arguments cannot contain double quotes or control characters")

    environment = dict(os.environ if env is None else env)
    # Resolve the system interpreter from the host, not an ambient COMSPEC or
    # PATH that may select a different program. The second source supports
    # explicit environments and construction tests on other platforms.
    system_root = (_environment_value(os.environ, "SystemRoot") or
                   _environment_value(environment, "SystemRoot"))
    if not isinstance(system_root, str) or not ntpath.isabs(system_root):
        raise OSError("SystemRoot must name an absolute Windows directory for batch launch")
    if '"' in system_root or any(ord(char) < 32 for char in system_root):
        raise ValueError("SystemRoot contains unsupported characters")
    interpreter = ntpath.join(system_root, "System32", "cmd.exe")
    if _environment_value(environment, "SystemRoot") is None:
        environment["SystemRoot"] = system_root

    prefix = f"FANGIDA_BATCH_{uuid4().hex}_"
    references = []
    for index, argument in enumerate(arguments):
        if not argument:
            references.append('""')
            continue
        name = f"{prefix}{index}"
        # A supplied environment may have case variants of a generated name.
        # Remove them before adding one canonical key for Windows' lookup.
        for existing in list(environment):
            if existing.casefold() == name.casefold():
                del environment[existing]
        environment[name] = argument
        references.append(f'"%{name}%"')

    # /s removes precisely the outer quote pair. Every individual reference
    # remains quoted, including the batch path. Pass this string directly to
    # CreateProcess through Popen(executable=...), never through list2cmdline.
    command_prefix = f'"{interpreter}" /d /v:off /s /c '
    command_line = command_prefix + '"' + " ".join(references) + '"'
    expanded_line = command_prefix + '"' + " ".join(f'"{arg}"' for arg in arguments) + '"'
    if max(_utf16_length(command_line), _utf16_length(expanded_line)) > CMD_MAX_CHARACTERS:
        raise ValueError("Windows batch command exceeds cmd.exe's 8191-character limit")
    return BatchInvocation(command_line, interpreter, environment)
