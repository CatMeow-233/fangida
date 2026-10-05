"""Explicit status/privileged effects and harmless padding instructions."""
from __future__ import annotations

import re

from . import aarch64_system
from .common import lifted
from .ir import MicroOperation, constant

# 模块级预编译正则（与原字符串模式及标志位一致）。
_UNSIGNED_IMMEDIATE = re.compile(r"#?(?:0[xX][0-9a-fA-F]+|[0-9]+)")


def lift(context, row, args, op):
    mnemonic = str(row["mnemonic"]).lower()
    if context.architecture == "arm64":
        # MRS/MSR（NZCV、TLS、浮点控制/状态、计数器等）与指针认证指令（见 aarch64_system.py）。
        explicit = aarch64_system.lift(context, row, args, op)
        if explicit is not None:
            return explicit
    if context.architecture == "arm64" and mnemonic == "svc":
        if len(args) != 1 or _UNSIGNED_IMMEDIATE.fullmatch(args[0]) is None:
            raise ValueError("A64 SVC requires one unsigned immediate")
        raw = args[0].lstrip("#")
        immediate = int(raw, 16 if raw.lower().startswith("0x") else 10)
        if not 0 <= immediate <= 0xffff:
            raise ValueError("A64 SVC immediate exceeds imm16")
        address = row["addr"]
        # The ISA identifies an exception transition, not a function-call ABI.
        # Register/memory effects after a handler returns require its platform
        # contract. In particular, imm16 does not identify a Linux service.
        attributes = {
            "transition": "exception", "exception": "supervisor_call",
            "immediate": immediate, "instruction_address": address,
            "resume_address": address + row["size"],
            "input_roles": ["imm16", "instruction_address"],
            "syndrome": {"exception_class": 0x15, "iss": immediate},
            "state_boundary": True, "barrier": True,
            "platform": "unknown", "handler": "unknown",
            "exception_routing": "execution_context_dependent",
            "register_effects": "handler_dependent",
            "memory_effects": "handler_dependent",
            "condition_flags_effects": "handler_dependent",
            "return_behavior": "handler_dependent",
            "source_recovery": "requires_exception_handler_contract",
        }
        return lifted(context, row, "system",
            [f"arm64_supervisor_call({hex(immediate)}, {hex(address)}); "
             "/* exception transition; handler and return effects unknown */"],
            [MicroOperation("system_transition", inputs=(constant(immediate, 16), constant(address, 64)),
                            attributes=attributes)],
            flag_effect="unknown", memory_effect="unknown")
    if mnemonic in {"nop", "endbr64", "endbr32"}:
        return lifted(context, row, "system", [f"/* {mnemonic} */"], [MicroOperation("nop")])
    if context.architecture == "arm64" and mnemonic == "bti" and (not args or (len(args) == 1 and args[0].lower() in {"c", "j", "jc"})):
        # BTI 只标记间接跳转的合法落点（与 endbr64 同类），不改变寄存器、内存或标志。
        return lifted(context, row, "system", ["/* bti */"], [MicroOperation("nop")])
    if context.architecture.startswith("x86") and mnemonic in {"clc", "stc", "cmc"} and not args:
        text = {"clc": "0", "stc": "1", "cmc": "!flags.CF"}[mnemonic]
        return lifted(context, row, "system", [f"flags.CF = {text};"],
            [MicroOperation("flag_write", 1, output="flags.CF", attributes={"operation": mnemonic, "preserve_other_flags": True})],
            flag_effect="partial")
    if context.architecture.startswith("x86") and mnemonic in {"cld", "std"} and not args:
        return lifted(context, row, "system", [f"flags.DF = {1 if mnemonic == 'std' else 0};"],
            [MicroOperation("flag_write", 1, output="flags.DF", attributes={"value": int(mnemonic == "std"), "preserve_condition_flags": True})],
            flag_effect="partial_non_condition")
    return None
