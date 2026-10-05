"""Bounded ARM64 emulation for the explicitly invoked BR solver plugin.

Only completed instruction records and caller-supplied byte mappings are used.
This module does not load files, decode instructions, follow a solved branch,
create xrefs, or change the default analysis pipeline.
"""
from __future__ import annotations

from bisect import bisect_right
from collections.abc import Mapping
from time import monotonic

PAGE_SIZE = 4096
MAX_MAPPING_BYTES = 16 * 1024 * 1024
MAX_MAPPING_PAGES = MAX_MAPPING_BYTES // PAGE_SIZE
MAX_SEGMENTS = 256
MAX_STEPS = 65536
MAX_TIMEOUT_MS = 30000
_U64 = (1 << 64) - 1
_CATEGORIES = frozenset({"data_transfer", "integer_arithmetic", "bitwise",
                         "comparison", "conditional", "memory", "control_flow"})
_SYSTEM = frozenset({"svc", "hvc", "smc", "msr", "mrs", "sys", "sysl",
                     "brk", "hlt", "eret", "drps", "wfi", "wfe", "sev", "sevl"})


def _register(name):
    if not isinstance(name, str):
        return None
    name = name.lower().strip()
    name = {"fp": "x29", "lr": "x30", "ip0": "x16", "ip1": "x17",
            "wsp": "sp", "flags": "nzcv"}.get(name, name)
    if name in {"xzr", "wzr"}:
        return "zero"
    if name in {"sp", "nzcv", "pc"}:
        return name
    if name.startswith(("x", "w")) and name[1:].isdigit() and 0 <= int(name[1:]) <= 30:
        return "x" + str(int(name[1:]))
    return None


def _integer(value):
    return type(value) is int and 0 <= value <= _U64


def _cancelled(cancel):
    if cancel is None:
        return False
    return bool(cancel() if callable(cancel) else cancel.is_set())


def _lift(row):
    # The existing semantic lifter consumes IR, not bytes or a decoder.
    from ..pseudoc.microcode import lift_instruction
    copy = dict(row)
    mnemonic = copy["mnemonic"]
    if not copy.get("branch_info"):
        conditional = mnemonic.startswith("b.") or mnemonic in {"cbz", "cbnz", "tbz", "tbnz"}
        if mnemonic in {"b", "br", "blr", "bl", "ret"} or conditional:
            target = None
            operands = copy.get("operands", ())
            try:
                target = int(str(operands[-1]).strip().lstrip("#"), 0)
            except (ValueError, TypeError, IndexError):
                pass
            copy["branch_info"] = {"kind": "call" if mnemonic in {"bl", "blr"} else
                                  "return" if mnemonic == "ret" else "jump",
                                  "conditional": conditional, "target": target}
    micro = lift_instruction(copy, "arm64")
    reads = set(micro.get("reads", ())) | set(row.get("reads", ()))
    writes = set(micro.get("writes", ())) | set(row.get("writes", ()))
    if mnemonic in {"cbz", "cbnz", "tbz", "tbnz"}:
        # Some saved Capstone versions list NZCV for these instructions,
        # although their architectural predicates test the explicit register.
        reads.difference_update({"nzcv", "flags"})
    operations = micro.get("operations", ())
    # A semantic constant-kill is a proof of independence, not a default input.
    constant_kill = bool(operations) and micro.get("memory_effect") == "none" and (
        micro.get("flag_effect") == "preserve") and all(
            operation.get("opcode") == "assign" and
            operation.get("expression", {}).get("opcode") == "constant"
            for operation in operations)
    if constant_kill:
        reads.clear()
    unsupported = [name for name in reads | writes if _register(name) is None]
    return micro, {_register(name) for name in reads}, {_register(name) for name in writes}, constant_kill, unsupported


class _Memory:
    """Last mapping wins; page padding has no declared byte provenance."""

    def __init__(self, segments):
        edges = sorted({point for segment in segments for point in
                        (segment["address"], segment["address"] + len(segment["data"]))})
        self.regions = []
        for start, end in zip(edges, edges[1:]):
            source = next((segment for segment in reversed(segments)
                           if segment["address"] <= start and
                           end <= segment["address"] + len(segment["data"])), None)
            if source is not None:
                if self.regions and self.regions[-1][1] == start and self.regions[-1][2] is source:
                    previous = self.regions.pop()
                    start = previous[0]
                self.regions.append((start, end, source))
        self.starts = [region[0] for region in self.regions]
        self.written = []

    def region(self, address):
        index = bisect_right(self.starts, address) - 1
        if index >= 0 and address < self.regions[index][1]:
            return self.regions[index]
        return None

    def mark_written(self, start, size):
        end = start + size
        merged = []
        for low, high in self.written:
            if high < start:
                merged.append((low, high))
            elif end < low:
                merged.append((start, end))
                start, end = low, high
            else:
                start, end = min(start, low), max(end, high)
        merged.append((start, end))
        self.written = merged

    def known_end(self, address):
        for start, end in self.written:
            if start <= address < end:
                return end
            if start > address:
                break
        return address


def emulate_slice(instructions, branch_address, target_register, *, segments=(),
                  registers=None, max_steps=512, timeout_ms=200, cancel=None,
                  slice_addresses=None):
    """Emulate one saved path, stopping *before* its final BR/BLR.

    ``provided`` segments/registers are concrete runtime context, not static
    proof. Writable file bytes and ``runtime`` segments remain unknown until a
    known instruction stores all bytes subsequently read. ``slice_addresses``
    optionally permits skipping unrelated pure register operations; skipped
    outputs are invalidated. Control instructions are always checked against
    the next path record, including conditional branch feasibility.
    """
    output = {"status": "unknown", "target": None, "engine": "unicorn", "steps": 0,
              "dependencies": [], "warnings": [], "context_dependent": False,
              "proofs": [], "path_verified": False, "branch_bytes_verified": False}
    started = monotonic()
    deadline = started + (timeout_ms / 1000 if type(timeout_ms) is int else 0)
    dependency_keys = set()
    stopped = None
    mu = None
    hook_ids = []
    current_address = branch_address

    def warn(message):
        if len(output["warnings"]) < 32:
            output["warnings"].append(message)

    def dependency(kind, **fields):
        record = {"kind": kind, "at": current_address, **fields}
        key = repr(sorted(record.items()))
        if key not in dependency_keys and len(output["dependencies"]) < 512:
            dependency_keys.add(key)
            output["dependencies"].append(record)

    def stop(status, message=None):
        nonlocal stopped
        if stopped is None:
            stopped = status
            output["status"] = status
            if message:
                warn(message)
            if mu is not None:
                mu.emu_stop()

    def budget_check():
        if _cancelled(cancel):
            stop("cancelled", "Unicorn 仿真已取消")
        elif monotonic() >= deadline:
            stop("budget_exceeded", "Unicorn 仿真达到时间预算")
        return stopped is not None

    try:
        if not _integer(branch_address) or branch_address % 4 or _register(target_register) is None:
            raise ValueError("BR/BLR 地址或目标寄存器无效")
        if type(max_steps) is not int or max_steps <= 0 or type(timeout_ms) is not int or timeout_ms <= 0:
            raise ValueError("max_steps 和 timeout_ms 必须为正整数")
        if max_steps > MAX_STEPS or timeout_ms > MAX_TIMEOUT_MS:
            stop("budget_exceeded", "请求超过 Unicorn 后端的硬预算")
            return output
        if budget_check():
            return output
        # Optional dependency is deliberately absent from module imports.
        try:
            import unicorn as uc
            from unicorn import arm64_const as arm
        except (ImportError, OSError) as exc:
            stop("unavailable", f"Unicorn 不可用：{type(exc).__name__}")
            return output
        rows = []
        for row in instructions:
            if budget_check():
                return output
            if len(rows) >= MAX_STEPS:
                stop("budget_exceeded", "指令快照数量超过硬预算")
                return output
            if (not isinstance(row, Mapping) or not _integer(row.get("addr")) or
                    row["addr"] % 4 or type(row.get("size")) is not int or row["size"] != 4):
                raise ValueError("ARM64 指令快照必须含对齐地址和 4 字节长度")
            if row["addr"] > _U64 - 4 or not isinstance(row.get("mnemonic"), str):
                raise ValueError("指令快照地址或 mnemonic 无效")
            for field in ("reads", "writes", "operands"):
                value = row.get(field, ())
                if not isinstance(value, (tuple, list)) or len(value) > 64 or any(not isinstance(item, str) or len(item) > 512 for item in value):
                    raise ValueError(f"指令快照的 {field} 无效")
            if (row.get("arch_meta") or {}).get("architecture", "arm64") != "arm64":
                raise ValueError("此后端只支持 ARM64 快照")
            rows.append(row)
        target = _register(target_register)
        if not rows or rows[-1]["addr"] != branch_address or rows[-1]["mnemonic"] not in {"br", "blr"}:
            raise ValueError("路径须以指定地址的 BR/BLR 快照结束")
        operands = rows[-1].get("operands", ())
        if len(operands) != 1 or _register(operands[0]) != target or not operands[0].lower().startswith("x"):
            raise ValueError("BR/BLR 快照与目标寄存器不一致")
        selected = None
        if slice_addresses is not None:
            selected = set()
            for scanned, address in enumerate(slice_addresses):
                if budget_check():
                    return output
                if not _integer(address):
                    raise ValueError("slice_addresses 必须是有效地址")
                if scanned >= MAX_STEPS:
                    stop("budget_exceeded", "切片地址数量超过硬预算")
                    return output
                selected.add(address)
        mappings, pages, total_bytes = [], set(), 0
        for scanned, segment in enumerate(segments):
            if budget_check():
                return output
            if scanned >= MAX_SEGMENTS:
                stop("budget_exceeded", "内存段数量超过硬预算")
                return output
            if not isinstance(segment, Mapping) or not _integer(segment.get("address")):
                raise ValueError("内存段须声明有效 address")
            data = segment.get("data")
            if not isinstance(data, (bytes, bytearray, memoryview)):
                raise ValueError("内存段 data 必须是字节缓冲区")
            length = data.nbytes if isinstance(data, memoryview) else len(data)
            if length > _U64 - segment["address"]:
                raise ValueError("内存段范围溢出")
            writable, executable = segment.get("writable"), segment.get("executable", False)
            readable = segment.get("readable", True)
            origin = segment.get("origin", "file")
            if ((writable is not None and type(writable) is not bool) or
                    (readable is not None and type(readable) is not bool) or
                    type(executable) is not bool or origin not in {"file", "provided", "runtime"}):
                raise ValueError("内存段权限或来源无效")
            total_bytes += length
            if total_bytes > MAX_MAPPING_BYTES:
                stop("budget_exceeded", "映射字节数量超过硬预算")
                return output
            if length:
                first = segment["address"] // PAGE_SIZE
                last = (segment["address"] + length - 1) // PAGE_SIZE
                if last - first + 1 > MAX_MAPPING_PAGES:
                    stop("budget_exceeded", "映射页数量超过硬预算")
                    return output
                pages.update(range(first, last + 1))
                if len(pages) > MAX_MAPPING_PAGES:
                    stop("budget_exceeded", "映射页数量超过硬预算")
                    return output
                mappings.append({"address": segment["address"], "data": bytes(data),
                                 "writable": writable, "readable": readable,
                                 "executable": executable, "origin": origin})
        memory = _Memory(mappings)
        mu = uc.Uc(uc.UC_ARCH_ARM64, uc.UC_MODE_ARM)
        for page in sorted(pages):
            if budget_check():
                return output
            # Byte-level hooks enforce declared permissions and provenance;
            # page permissions cannot represent partial/overlapping segments.
            mu.mem_map(page * PAGE_SIZE, PAGE_SIZE, uc.UC_PROT_ALL)
        for segment in mappings:
            mu.mem_write(segment["address"], segment["data"])
        register_ids = {f"x{index}": getattr(arm, f"UC_ARM64_REG_X{index}") for index in range(31)}
        register_ids.update(sp=arm.UC_ARM64_REG_SP, nzcv=arm.UC_ARM64_REG_NZCV, pc=arm.UC_ARM64_REG_PC)
        known = {"zero", "pc"}
        provided = set()
        initial = {}
        if registers is not None and not isinstance(registers, Mapping):
            raise ValueError("registers 必须为寄存器和值的映射")
        for scanned, (name, value) in enumerate((registers or {}).items()):
            if budget_check():
                return output
            if scanned >= 128:
                stop("budget_exceeded", "寄存器上下文数量超过硬预算")
                return output
            canonical = _register(name)
            if canonical is None or not _integer(value):
                raise ValueError("提供的寄存器或值无效")
            if canonical == "zero":
                if value:
                    raise ValueError("零寄存器不能赋予非零值")
                continue
            if canonical == "pc":
                continue
            if name.lower().startswith("w") or canonical == "nzcv":
                value &= 0xFFFFFFFF
            if canonical in initial and initial[canonical] != value:
                raise ValueError("提供的寄存器别名值冲突")
            initial[canonical] = value
            known.add(canonical)
            provided.add(canonical)
            mu.reg_write(register_ids[canonical], value)
        pending_writes = []

        def access(address, size, *, write=False, fetch=False):
            if budget_check():
                return False
            if not _integer(address) or type(size) is not int or size <= 0 or size > _U64 - address:
                stop("unknown", "无效的仿真内存访问")
                return False
            end, cursor = address + size, address
            while cursor < end:
                region = memory.region(cursor)
                if region is None:
                    dependency("memory", address=cursor, size=end - cursor, source="unmapped")
                    stop("unknown", "访问未声明字节；映射页的零填空洞不构成已知内存")
                    return False
                _, high, source = region
                high = min(high, end)
                if fetch and not source["executable"]:
                    dependency("memory", address=cursor, size=high - cursor, source="non_executable")
                    stop("unknown", "指令字节不属于可执行映射")
                    return False
                if not write and not fetch and source["readable"] is not True:
                    dependency("memory", address=cursor, size=high - cursor,
                               source="read_permission_unknown" if source["readable"] is None else "unreadable")
                    stop("unknown", "读取目标没有已声明的可读权限")
                    return False
                if write:
                    if source["writable"] is not True:
                        dependency("memory", address=cursor, size=high - cursor, source="write_permission_unknown" if source["writable"] is None else "readonly_write")
                        stop("unknown", "存储目标没有已声明的可写权限")
                        return False
                    if source["executable"]:
                        dependency("memory", address=cursor, size=high - cursor, source="self_modifying_code")
                        stop("unknown", "写入代码会使已完成指令快照失效")
                        return False
                else:
                    written_end = memory.known_end(cursor)
                    if written_end > cursor:
                        cursor = min(high, written_end)
                        continue
                    if source["origin"] == "provided":
                        output["context_dependent"] = True
                        dependency("memory", address=cursor, size=high - cursor, source="provided")
                    elif source["origin"] == "runtime" or source["writable"] is True:
                        dependency("memory", address=cursor, size=high - cursor, source="runtime" if source["origin"] == "runtime" else "writable_file")
                        stop("runtime_dependent", "引用依赖运行时内存；文件初始字节不能替代运行时值")
                        return False
                    elif source["writable"] is None:
                        dependency("memory", address=cursor, size=high - cursor, source="permission_unknown")
                        stop("unknown", "内存段可写权限未知")
                        return False
                cursor = high
            return True

        def memory_hook(_mu, kind, address, size, _value, _user):
            try:
                if access(address, size, write=kind == uc.UC_MEM_WRITE):
                    if kind == uc.UC_MEM_WRITE:
                        pending_writes.append((address, size))
            except Exception as exc:
                stop("error", f"内存来源检查失败：{type(exc).__name__}")

        def invalid_hook(_mu, kind, address, size, _value, _user):
            dependency("memory", address=address, size=size, source="unmapped_or_protected")
            stop("unknown", "Unicorn 遇到未映射或受保护的内存；未补造字节")
            return False

        def verify_branch_bytes():
            if not access(branch_address, 4, fetch=True):
                return False
            # Check this evidence before unrelated unknown path inputs can
            # block emulation. This is fixed-encoding validation, not decoding.
            register_number = 31 if target == "zero" else int(target[1:])
            expected_word = (0xD61F0000 if rows[-1]["mnemonic"] == "br" else 0xD63F0000) | (register_number << 5)
            if bytes(mu.mem_read(branch_address, 4)) != expected_word.to_bytes(4, "little"):
                dependency("instruction_bytes", source="byte_mismatch")
                stop("unknown", "源字节与指定 BR/BLR 的固定编码和目标寄存器不一致")
                return False
            output["branch_bytes_verified"] = True
            return True

        current_address = branch_address
        if not verify_branch_bytes():
            return output
        hook_ids.append(mu.hook_add(uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE, memory_hook))
        hook_ids.append(mu.hook_add(uc.UC_HOOK_MEM_INVALID, invalid_hook))
        for index, row in enumerate(rows):
            current_address = row["addr"]
            if budget_check():
                return output
            if index == len(rows) - 1:
                if not verify_branch_bytes():
                    return output
                if target not in known:
                    dependency("register", register=target, source="uninitialized")
                    stop("runtime_dependent", "BR/BLR 目标寄存器没有已知定义")
                    return output
                if target in provided:
                    output["context_dependent"] = True
                    dependency("register", register=target, source="provided")
                output["target"] = 0 if target == "zero" else int(mu.reg_read(register_ids[target]))
                output["status"] = "resolved"
                output["path_verified"] = True
                return output
            mnemonic = row["mnemonic"]
            if mnemonic in _SYSTEM or mnemonic in {"bl", "blr"}:
                dependency("external_call" if mnemonic in {"bl", "blr"} else "system", mnemonic=mnemonic)
                stop("runtime_dependent", "不执行外部调用或系统副作用")
                return output
            if mnemonic in {"br", "ret"}:
                stop("unknown", "指定目标之前存在未解析的控制转移")
                return output
            micro, reads, writes, proof, unsupported = _lift(row)
            control = micro.get("category") == "control_flow"
            if ((row.get("arch_meta") or {}).get("address_state_clobber") or
                    not micro.get("supported") or (micro.get("category") not in _CATEGORIES and mnemonic != "nop") or
                    micro.get("memory_effect") not in {"none", "read", "write"} or
                    micro.get("flag_effect") not in {"preserve", "write", "partial_non_condition"} or unsupported):
                dependency("unsupported_instruction", mnemonic=mnemonic)
                stop("unknown", "未知寄存器、内存或指令副作用不能用于确定目标")
                return output
            if selected is not None and current_address not in selected and not control and micro.get("memory_effect") == "none":
                known.difference_update(writes - {"zero", "pc"})
                provided.difference_update(writes)
                if rows[index + 1]["addr"] != current_address + 4:
                    stop("unknown", "省略的纯指令之后缺少连续路径快照")
                    return output
                continue
            missing = sorted(reads - known)
            if missing:
                for name in missing:
                    dependency("register", register=name, source="uninitialized")
                stop("runtime_dependent", "输入寄存器尚未初始化，未使用 Unicorn 的默认零值")
                return output
            for name in reads & provided:
                output["context_dependent"] = True
                dependency("register", register=name, source="provided")
            if output["steps"] >= max_steps:
                stop("budget_exceeded", "Unicorn 仿真达到指令步数预算")
                return output
            if not access(current_address, 4, fetch=True):
                return output
            pending_writes.clear()
            remaining_us = max(1, int((deadline - monotonic()) * 1000000))
            try:
                mu.emu_start(current_address, current_address + 4, timeout=remaining_us, count=1)
            except uc.UcError as exc:
                if stopped is None:
                    stop("unknown", f"Unicorn 无法完成指令：{exc}")
                return output
            if stopped is not None or budget_check():
                return output
            output["steps"] += 1
            if proof:
                for operation in micro["operations"]:
                    destination = _register(operation.get("output"))
                    expression = operation["expression"]
                    expected_value = int(expression["value"]) & ((1 << expression["width"]) - 1)
                    actual_value = 0 if destination == "zero" else int(mu.reg_read(register_ids[destination]))
                    if destination != "zero" and actual_value != expected_value:
                        dependency("instruction_bytes", source="byte_mismatch", register=destination)
                        stop("unknown", "源指令的实际输出与常量赋值快照不一致")
                        return output
            if proof and len(output["proofs"]) < 512:
                output["proofs"].append({"at": current_address, "kind": "constant_assignment"})
            known.update(writes)
            provided.difference_update(writes)
            for address, size in pending_writes:
                memory.mark_written(address, size)
            actual_next = int(mu.reg_read(arm.UC_ARM64_REG_PC))
            expected_next = rows[index + 1]["addr"]
            if actual_next != expected_next:
                dependency("path", actual=actual_next, expected=expected_next)
                stop("infeasible", "实际控制流与候选路径的下一条快照不一致")
                return output
    except Exception as exc:
        stop("error", f"Unicorn 后端请求失败：{type(exc).__name__}: {str(exc)[:256]}")
    finally:
        # Remove callbacks that close over this private UC instance, so its
        # normal binding finalizer can release the engine without a cycle.
        for hook_id in hook_ids:
            try:
                mu.hook_del(hook_id)
            except Exception:
                pass
    return output


__all__ = ["emulate_slice"]
