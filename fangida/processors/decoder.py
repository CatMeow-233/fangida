"""CPU instruction decoding only; no container parsing or xref analysis."""
from __future__ import annotations

import re
import sys
from typing import Any, Callable

from ..models import Instruction
from .objdump_backend import ObjdumpUnavailable, disassemble_bytes


# 控制流分类只依据助记符；需要操作数才能区分的 ARM 情形（bx lr、pop {pc}、mov pc, lr）
# 由 NativeDecoder 在默认分类结果上细化，branch_info 的两参数签名保持不变。
_CALLS = frozenset({"bl", "blr", "blx", "lcall", "blraa", "blrab", "blraaz", "blrabz"})
# 异常/中断返回同样不落空：x86 iret/sysret/sysexit，AArch64 eret/drps，AArch32 eret/rfe。
_RETURNS = frozenset({"iret", "iretd", "iretq", "sysret", "sysretq", "sysexit", "sysexitq", "uiret",
                      "eret", "eretaa", "eretab", "drps", "rfeia", "rfeib", "rfeda", "rfedb"})
# int/int1/syscall 属于 Capstone INT 组但执行后返回下一条，不是陷阱；int3 沿用原有约定
# （编译器把它放在不返回调用之后作填充）。ud0/ud1 是 clang 的 UBSan 陷阱指令。
_TRAPS = frozenset({"hlt", "ud0", "ud1", "ud2", "int3", "brk", "udf", "bkpt"})
# tbb/tbh 是 Thumb-2 跳转表分支（目标来自内存表，未知）。
_UNCONDITIONAL_JUMPS = frozenset({"jmp", "jmpq", "ljmp", "b", "br", "bx", "bxj", "bal", "b.al", "b.nv",
                                  "bc.al", "bc.nv", "braa", "brab", "braaz", "brabz", "tbb", "tbh"})
# xbegin 的目标是事务中止处理入口，顺序路径是事务体：与条件跳转同形。
_CONDITIONAL_JUMPS = frozenset({"cbz", "cbnz", "tbz", "tbnz", "xbegin", "bcs", "bcc"})
# 段:偏移远转移的立即数是选择子与偏移，不是线性地址。
_FAR_TRANSFERS = frozenset({"ljmp", "lcall"})
_TARGETLESS_KINDS = frozenset({"return", "trap"})
_ARM64_BIT_TESTS = frozenset({"tbz", "tbnz"})
# 只接受 Capstone 的条件码拼写（hs/lo，不含 cs/cc 别名）：x86 TBM 的 "blcs" 因此不会被拆成 bl+cs。
_ARM_CONDITIONS = frozenset({"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"})
# 先长后短逐个尝试；"bls" 拆成 bl+"s" 失败后才得到 b+ls，两种拆分不可能同时成立。
_ARM_CONDITIONAL_BASES = (("blx", "call"), ("bxj", "jump"), ("bx", "jump"), ("bl", "call"), ("b", "jump"))


def branch_info(mnemonic: str, target: int | None) -> dict[str, Any] | None:
    name = mnemonic.lower()
    if " " in name:
        # x86 前缀（repz/bnd/notrack…）与核心助记符写在一起，不改变控制流种类。
        name = name.rsplit(None, 1)[-1]
    if name.endswith((".w", ".n")):
        name = name[:-2]  # Thumb 宽度限定符：b.w 是无条件跳转，不是 AArch64 的 b.<cond>。
    if name.startswith("call") or name in _CALLS:
        return {"kind": "call", "target": None if name in _FAR_TRANSFERS else target, "conditional": False}
    if name.startswith("ret") or name in _RETURNS:
        return {"kind": "return", "target": None, "conditional": False}
    if name in _TRAPS:
        return {"kind": "trap", "target": None, "conditional": False}
    if (name.startswith(("j", "loop", "b.", "bc.")) or name in _UNCONDITIONAL_JUMPS
            or name in _CONDITIONAL_JUMPS):
        return {"kind": "jump", "target": None if name in _FAR_TRANSFERS else target,
                "conditional": name not in _UNCONDITIONAL_JUMPS}
    if name[:1] == "b":
        # AArch32 条件形式：b<cond>、bl<cond>、bx<cond>、blx<cond>、bxj<cond>。
        for base, kind in _ARM_CONDITIONAL_BASES:
            if name.startswith(base) and name[len(base):] in _ARM_CONDITIONS:
                return {"kind": kind, "target": target, "conditional": True}
    return None


# LDM 基址与寄存器名：同时接受 Capstone 默认的别名与 CS_OPT_SYNTAX_NOREGNAME 的 rN 写法。
_ARM_STACK_BASES = frozenset({"sp", "r13"})
_ARM_FRAME_BASES = frozenset({"fp", "r11"})
_ARM_PC_NAMES = frozenset({"pc", "r15"})
# APCS 帧返回 "ldmdb fp, {.., sp, pc}"（GNU 别名 ldmea）。
_ARM_FRAME_RETURNS = frozenset({"ldmdb", "ldmea"})


def _arm_ldm_returns(mnemonic: str, op_str: str) -> bool:
    """LDM 只有从栈（sp 基址，任意寻址方式与写回）或 APCS 帧（ldmdb fp）恢复 pc 时才是返回。

    longjmp 式的 "ldm r0!, {r1, pc}" 从任意缓冲区装入 pc，"ldmib pc!, {...}" 只经写回改写 pc
    （UNPREDICTABLE）：它们都不是返回，由调用方按目标未知的间接跳转处理。
    """
    base, separator, registers = op_str.partition(",")
    opening, closing = registers.find("{"), registers.find("}")
    if not separator or opening < 0 or closing < opening:
        return False
    # Capstone 逐个列出寄存器；仍按 "r4-r11" 区间写法拆分，区间端点为 pc 时同样视为含 pc。
    listed = {name.strip() for name in registers[opening + 1:closing].replace("-", ",").split(",")}
    if listed.isdisjoint(_ARM_PC_NAMES):
        return False
    base = base.strip().rstrip("!").rstrip()
    return base in _ARM_STACK_BASES or (mnemonic in _ARM_FRAME_RETURNS and base in _ARM_FRAME_BASES)


def _arm_pc_write(mnemonic: str, op_str: str, conditional: bool) -> dict[str, Any]:
    """AArch32 中助记符未识别、但 Capstone 报告写 PC 的指令（pop/ldm/ldr/mov/add… pc）。

    目标来自寄存器或内存，一律未知。无条件的出栈/链接寄存器形式是函数返回；
    其余写 PC 的 LDM（不以 sp/APCS fp 为基址，或寄存器列表不含 pc）是目标未知的间接跳转。
    条件形式暂按条件间接跳转表示：现有 CFG 只对 jump 读取 conditional，
    若标成 return 会丢掉条件不成立时的落空边。
    """
    if mnemonic.endswith((".w", ".n")):
        mnemonic = mnemonic[:-2]
    if not conditional and (
            mnemonic == "pop"
            or (mnemonic.startswith("ldm") and _arm_ldm_returns(mnemonic, op_str))
            or (mnemonic in {"mov", "movs"} and op_str == "pc, lr")
            or (mnemonic == "ldr" and op_str.startswith("pc, [sp], "))
            or (mnemonic == "subs" and op_str.startswith("pc, lr, "))):
        return {"kind": "return", "target": None, "conditional": False}
    return {"kind": "jump", "target": None, "conditional": conditional}


def _refine_arm(ins: Any, mnemonic: str, op_str: str, branch: dict[str, Any] | None,
                write_names: Any, capstone: Any) -> dict[str, Any] | None:
    """细化默认分类：只用文本操作数、已算好的写寄存器集合和条件码，不展开 operands。"""
    if not branch:
        if "pc" not in write_names:
            return branch
        return _arm_pc_write(mnemonic, op_str,
                             ins.cc not in (capstone.arm.ARM_CC_AL, capstone.arm.ARM_CC_INVALID))
    if op_str == "lr" and mnemonic in {"bx", "bxj"}:
        return {"kind": "return", "target": None, "conditional": False}
    return branch


_ARM64_LITERAL_LOADS = frozenset({"ldr", "ldrsw", "prfm"})
_ARM64_DIRECT_ADDRESSES = _ARM64_LITERAL_LOADS | {"adr"}
_ARM64_ADDRESS_INSTRUCTIONS = _ARM64_LITERAL_LOADS | {"adr", "adrp"}
_X86_POINTER_IMMEDIATES = frozenset({"mov", "movabs", "push"})
# Capstone 对 0–9 的立即数/绝对位移打印十进制（"[5]"、"eax, 5"、"push -1"），其余打印 0x…：
# include_data 的文本预过滤按 "[" 后紧跟数字/负号判断绝对位移，不枚举具体拼写。
_X86_NUMBER_STARTS = frozenset("-0123456789")
# 立即数地址候选只取十六进制打印者（|值| ≥ 10）：十进制打印的 0–9、-1… 几乎总是计数、标志或
# 填充值；把它们当候选会让基址为 0 的映像（.o/.ko）在 0–9 处产生大量伪数据引用。
# 预过滤与结构化提取使用同一文本规则，因此预过滤仍不会漏掉任何候选。
_X86_HEX_IMMEDIATE = ("0x", "-0x")


# 快路径指令记录的键与顺序（与 Instruction.to_dict() 的字段顺序相同）。
RECORD_KEYS = ("addr", "size", "mnemonic", "operands", "reads", "writes", "branch_info", "arch_meta")


class _CompactRecord:
    """只用来构造指令记录 dict：取 vars() 之后实例立即丢弃。

    CPython 3.11+ 的实例字典与类共享键表（拆分表），8 键记录约 160 字节，而同内容的
    字面量 dict 是 272 字节（几千万条指令时相差数 GB）。得到的仍是普通 dict
    （type is dict），键、键顺序与值都和字面量相同，json/marshal/pickle 输出逐字节相同；
    下游给记录新增键时 CPython 自动转换存储，语义不变。
    """

    def __init__(self, addr: int, size: int, mnemonic: str, operands: tuple[str, ...],
                 reads: tuple[str, ...], writes: tuple[str, ...], branch_info: dict[str, Any],
                 arch_meta: dict[str, Any]) -> None:
        self.addr = addr
        self.size = size
        self.mnemonic = mnemonic
        self.operands = operands
        self.reads = reads
        self.writes = writes
        self.branch_info = branch_info
        self.arch_meta = arch_meta


def _compact_supported() -> bool:
    """导入时自检：只有实例字典确实是键序相同且更小的普通 dict 时才启用紧凑记录。"""
    try:
        # CPython 3.13 在前若干个实例里逐步收紧内联值容量：先预热，再比较稳定后的大小。
        for _ in range(64):
            probe = vars(_CompactRecord(*RECORD_KEYS))
        return (type(probe) is dict and tuple(probe) == RECORD_KEYS
                and list(probe.values()) == list(RECORD_KEYS)
                and sys.getsizeof(probe) < sys.getsizeof(dict(zip(RECORD_KEYS, RECORD_KEYS))))
    except Exception:
        # PyPy 等实现的 getsizeof 可能不可用：退回普通 dict，只放弃内存收益。
        return False


COMPACT_RECORDS = _compact_supported()


def record_from_row(row: Any) -> dict[str, Any]:
    """按 RECORD_KEYS 顺序的 8 项 -> 值与键顺序都相同的普通 dict（支持时为紧凑存储）。"""
    return vars(_CompactRecord(*row)) if COMPACT_RECORDS else dict(zip(RECORD_KEYS, row))


def records_from_rows(rows: Any) -> list[dict[str, Any]]:
    """批量版 record_from_row（解码子进程按行传回的记录在父进程重建）。"""
    if COMPACT_RECORDS:
        return [vars(_CompactRecord(*row)) for row in rows]
    return [dict(zip(RECORD_KEYS, row)) for row in rows]


_LINE = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S+)(?:\s+(.*))?$", re.I)
_TARGET = re.compile(r"^(?:\*?\$?0x)?([0-9a-f]+)(?:\s*<.*>)?$", re.I)
# objdump 把 x86 前缀输出为独立的词（LLVM "rep\t\tret"、GNU "notrack jmp rax"），Capstone 则并入助记符。
_OBJDUMP_PREFIXES = frozenset({"rep", "repe", "repz", "repne", "repnz", "bnd", "notrack", "lock",
                               "xacquire", "xrelease", "data16", "data32", "addr16", "addr32",
                               "cs", "ds", "es", "ss", "fs", "gs"})


def decode_objdump(
    code: bytes, address: int, architecture: str, *, max_instructions: int = 128,
    render: Callable[[bytes, int, str], tuple[str, str]] | None = None,
    classify: Callable[[str, int | None], dict[str, Any] | None] = branch_info,
    include_data: bool = False,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Decode an x86 window, preserving the existing GNU/LLVM IR contract."""
    if architecture not in {"x86_64", "x86"}:
        return [], ["Capstone is required to disassemble this architecture"]
    if type(max_instructions) is not int or max_instructions < 1:
        raise ValueError("max_instructions must be a positive integer")
    try:
        rendered, provider = (render or disassemble_bytes)(code, address, architecture)
    except (OSError, ValueError, ObjdumpUnavailable) as exc:
        return [], [f"Capstone unavailable and objdump failed: {type(exc).__name__}: {exc}"]
    output: list[dict[str, Any]] = []
    for line in rendered.splitlines():
        match = _LINE.match(line)
        if not match or len(output) >= max_instructions:
            continue
        addr, encoded, mnemonic, op_str = match.groups()
        if re.fullmatch(r"[0-9a-f]{2}", mnemonic, re.I):
            continue
        if mnemonic.startswith(".") or mnemonic in {"(bad)", "bad", "<unknown>"}:
            continue
        words, rest = [mnemonic], op_str or ""
        while words[-1].lower() in _OBJDUMP_PREFIXES or words[-1].lower().startswith("rex"):
            parts = rest.split(None, 1)
            if not parts:
                break
            words.append(parts[0])
            rest = parts[1] if len(parts) > 1 else ""
        # 只在前缀后面是控制流指令时与 Capstone 一样并入助记符（"repz ret"、"bnd jmp"），
        # 其他带前缀指令（lock add、rep stos）的历史 IR 保持不变。
        if len(words) > 1 and branch_info(words[-1], None) is not None:
            mnemonic, op_str = " ".join(words), rest
        operands = (op_str or "").split("#", 1)[0].strip()
        target_match = _TARGET.match(operands) if classify(mnemonic, None) else None
        target = int(target_match.group(1), 16) if target_match else None
        output.append(Instruction(int(addr, 16), len(encoded.split()), mnemonic,
                                  tuple(part.strip() for part in operands.split(",") if part.strip()),
                                  branch_info=classify(mnemonic, target) or {},
                                  arch_meta={"engine": "objdump", "architecture": architecture,
                                             "provider": provider}).to_dict())
    if not output:
        return [], ["Capstone unavailable and objdump found no entry instructions"]
    if include_data:
        output = objdump_data_metadata(output, architecture)
    return output, ["Register read/write sets require Capstone; objdump fallback omits them"]


_OBJDUMP_MEMORY = re.compile(r"\[\s*(?:(rip|eip)\s*([+-])\s*)?(0x[0-9a-f]+|[0-9]+)\s*\]", re.I)
_OBJDUMP_SEGMENT = re.compile(r"\b(?:fs|gs)\s*:", re.I)
_OBJDUMP_ABSOLUTE = re.compile(r"\bds\s*:\s*(0x[0-9a-f]+|[0-9]+)\b", re.I)
_OBJDUMP_IMMEDIATE = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$", re.I)


def objdump_data_metadata(instructions: list[dict[str, Any]], architecture: str
                         ) -> list[dict[str, Any]]:
    """Describe addresses in completed Intel listings, without another decode.

    Legacy objdump entry points still receive the original metadata by default.
    Only exact absolute/PC-relative operands and pointer-immediate candidates
    are accepted; register-dependent expressions and FS/GS offsets stay unknown.
    """
    output = []
    for instruction in instructions:
        metadata = instruction.get("arch_meta") or {}
        if metadata.get("engine") != "objdump" or architecture not in {"x86", "x86_64"}:
            output.append(instruction)
            continue
        references, candidates = [], []
        bits = 64 if architecture == "x86_64" else 32
        mask = (1 << bits) - 1
        for operand in instruction.get("operands", ()):
            if _OBJDUMP_SEGMENT.search(operand):
                continue
            match = _OBJDUMP_MEMORY.search(operand)
            if match:
                register, sign, number = match.groups()
                value = int(number, 16 if number.lower().startswith("0x") else 10)
                if register:
                    if sign == "-":
                        value = -value
                    target_bits = 32 if register.lower() == "eip" else bits
                    value = (instruction["addr"] + instruction["size"] + value) & ((1 << target_bits) - 1)
                references.append(value & mask)
            else:
                absolute = _OBJDUMP_ABSOLUTE.search(operand)
                if absolute:
                    number = absolute.group(1)
                    references.append(int(number, 16 if number.lower().startswith("0x") else 10) & mask)
            if (instruction.get("mnemonic") in _X86_POINTER_IMMEDIATES
                    and _OBJDUMP_IMMEDIATE.fullmatch(operand)):
                candidates.append(int(operand, 16 if operand.lower().startswith("0x") else 10) & mask)
        if references or candidates:
            metadata = dict(metadata)
            if references:
                metadata["memory_references"] = tuple(dict.fromkeys(references))
            if candidates:
                metadata["address_candidates"] = tuple(dict.fromkeys(candidates))
            instruction = {**instruction, "arch_meta": metadata}
        output.append(instruction)
    return output


class NativeDecoder:
    """One private Capstone decoder or the existing x86 objdump fallback."""

    def __init__(self, architecture: str, endian: str = "little") -> None:
        self.architecture, self.endian = architecture, endian
        self.engine = "none"
        self.warning: str | None = None
        self.capstone: Any = None
        self.disassembler: Any = None
        if architecture not in {"x86_64", "x86", "arm64", "arm"}:
            self.warning = f"Disassembly unavailable for {architecture}"
            return
        try:
            import capstone  # type: ignore[import-not-found]
        except ImportError:
            if architecture in {"x86_64", "x86"}:
                self.engine = "objdump"
            else:
                self.warning = f"Capstone is required to analyze {architecture}"
            return
        family = (capstone.CS_ARCH_X86 if architecture.startswith("x86") else
                  capstone.CS_ARCH_ARM64 if architecture == "arm64" else capstone.CS_ARCH_ARM)
        mode = (capstone.CS_MODE_64 if architecture == "x86_64" else
                capstone.CS_MODE_32 if architecture == "x86" else capstone.CS_MODE_ARM)
        if endian == "big":
            mode |= capstone.CS_MODE_BIG_ENDIAN
        decoder = capstone.Cs(family, mode)
        decoder.detail = True
        self.capstone, self.disassembler = capstone, decoder
        self.engine = "capstone"

    def decode_bytes(
        self, code: bytes, address: int, *, max_instructions: int = 128,
        classify: Callable[[str, int | None], dict[str, Any] | None] = branch_info,
        include_data: bool = False,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        if type(max_instructions) is not int or max_instructions < 1:
            raise ValueError("max_instructions must be a positive integer")
        if type(include_data) is not bool:
            raise ValueError("include_data must be boolean")
        if include_data:
            return self.decode_bytes_fast(code, address, max_instructions=max_instructions,
                                          classify=classify, include_data=True)
        if self.engine == "none":
            return [], [self.warning or "Instruction decoder is unavailable"]
        if self.engine == "objdump":
            return decode_objdump(code, address, self.architecture,
                                  max_instructions=max_instructions, classify=classify)
        output: list[dict[str, Any]] = []
        capstone, decoder = self.capstone, self.disassembler
        try:
            # 只细化默认分类；第三方 classify 的结果除目标外按原样保留。
            refine_arm = classify is branch_info and decoder.arch == capstone.CS_ARCH_ARM
            for ins in decoder.disasm(code, address, count=max_instructions):
                branch = classify(ins.mnemonic, None)
                # 返回/陷阱没有转移目标（"ret 8" 的立即数是弹栈字节数，"brk #1" 是注释号）。
                if branch is not None and branch.get("kind") not in _TARGETLESS_KINDS:
                    immediate = (capstone.x86.X86_OP_IMM if decoder.arch == capstone.CS_ARCH_X86 else
                                 capstone.arm64.ARM64_OP_IMM if decoder.arch == capstone.CS_ARCH_ARM64 else
                                 capstone.arm.ARM_OP_IMM)
                    target = None
                    if ins.mnemonic not in _FAR_TRANSFERS:
                        branch_operands = (reversed(ins.operands) if self.architecture == "arm64" and
                                           ins.mnemonic in _ARM64_BIT_TESTS else ins.operands)
                        for operand in branch_operands:
                            if operand.type == immediate:
                                target = int(operand.imm)
                                break
                    branch["target"] = target
                try:
                    reads, writes = ins.regs_access()
                    read_names = [ins.reg_name(register) for register in reads]
                    write_names = [ins.reg_name(register) for register in writes]
                except (AttributeError, ValueError):
                    read_names, write_names = [], []
                if refine_arm:
                    branch = _refine_arm(ins, ins.mnemonic, ins.op_str, branch, write_names, capstone)
                output.append(Instruction(ins.address, ins.size, ins.mnemonic,
                                          tuple(part.strip() for part in ins.op_str.split(",") if part.strip()),
                                          tuple(read_names), tuple(write_names), branch or {},
                                          {"engine": "capstone", "architecture": self.architecture}).to_dict())
        except Exception as exc:
            return output, [f"Capstone decode failed: {type(exc).__name__}: {exc}"]
        return output, []

    def decode_bytes_fast(
        self, code: bytes, address: int, *, max_instructions: int = 128,
        classify: Callable[[str, int | None], dict[str, Any] | None] = branch_info,
        include_data: bool = False,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Build the same IR without the per-instruction dataclass deep copy.

        This optional bulk-decoding API is deliberately separate from the
        public processor protocol, so registered providers need not implement
        it. Each returned record owns its mutable branch and metadata dicts.
        By default the historical fast snapshot only adds PC-relative memory
        targets. Opt-in data metadata also describes absolute addresses and
        decoded address operations; their combinations are resolved by the
        independent xref consumer. Old default snapshots remain unchanged.
        """
        if type(max_instructions) is not int or max_instructions < 1:
            raise ValueError("max_instructions must be a positive integer")
        if type(include_data) is not bool:
            raise ValueError("include_data must be boolean")
        if self.engine != "capstone":
            instructions, warnings = self.decode_bytes(code, address, max_instructions=max_instructions,
                                                        classify=classify)
            return (objdump_data_metadata(instructions, self.architecture) if include_data else instructions), warnings
        output: list[dict[str, Any]] = []
        append = output.append
        capstone, decoder = self.capstone, self.disassembler
        architecture = self.architecture
        try:
            is_x86 = decoder.arch == capstone.CS_ARCH_X86
            is_arm64 = decoder.arch == capstone.CS_ARCH_ARM64
            is_arm = decoder.arch == capstone.CS_ARCH_ARM
            immediate = (capstone.x86.X86_OP_IMM if is_x86 else
                         capstone.arm64.ARM64_OP_IMM if is_arm64 else
                         capstone.arm.ARM_OP_IMM)
            memory = (capstone.x86.X86_OP_MEM if is_x86 else
                      capstone.arm64.ARM64_OP_MEM if is_arm64 else
                      capstone.arm.ARM_OP_MEM)
            pc_registers = ({capstone.x86.X86_REG_RIP, capstone.x86.X86_REG_EIP}
                            if is_x86 else
                            {capstone.arm.ARM_REG_PC} if is_arm else set())
            excluded_segments = ({capstone.x86.X86_REG_FS, capstone.x86.X86_REG_GS}
                                 if is_x86 else set())
            # 文本仅预过滤可能携带地址的指令；由结构化操作数确定语义。
            # 常量候选并非引用，只有 xref 阶段命中已映射数据区间后才接受。
            pc_text = "ip" if is_x86 else "pc" if is_arm else None
            address_mnemonics = ((_ARM64_ADDRESS_INSTRUCTIONS if include_data else _ARM64_LITERAL_LOADS)
                                 if is_arm64 else ())
            eip = capstone.x86.X86_REG_EIP if is_x86 else None
            wide = architecture == "x86_64"
            # 每批独立缓存：寄存器名（仍逐条调用 regs_access）、分类结果、操作数文本拆分。
            register_names: dict[int, str] = {}
            lookup = register_names.__getitem__
            def name(register: int) -> str:
                if register not in register_names:
                    register_names[register] = ins.reg_name(register)
                return register_names[register]
            branch_cache: dict[str, Any] | None = {} if classify is branch_info else None
            refine_arm = is_arm and branch_cache is not None
            operand_cache: dict[str, tuple[str, ...]] = {}
            # 寄存器名元组只有少量不同取值（challenge 上约两百种）：按值共享不可变元组以降低常驻内存。
            interned: dict[tuple[str, ...], tuple[str, ...]] = {}
            # 记录用紧凑的普通 dict 构造（见 _CompactRecord）；不支持时仍用字面量。
            # 每条记录仍拥有自己的 branch_info / arch_meta 字典。
            compact = _CompactRecord if COMPACT_RECORDS else None
            for ins in decoder.disasm(code, address, count=max_instructions):
                mnemonic, instruction_address, instruction_size = ins.mnemonic, ins.address, ins.size
                op_str = ins.op_str
                if branch_cache is None:
                    classified = classify(mnemonic, None)
                elif mnemonic in branch_cache:
                    classified = branch_cache[mnemonic]
                else:
                    classified = branch_cache[mnemonic] = classify(mnemonic, None)
                branch = dict(classified) if classified is not None else {}
                metadata = {"engine": "capstone", "architecture": architecture}
                # 返回/陷阱不取立即数目标，也没有内存操作数，无需为它们展开 operands。
                targeted = classified is not None and classified.get("kind") not in _TARGETLESS_KINDS
                if (targeted or mnemonic in address_mnemonics
                        or (pc_text is not None and pc_text in op_str)
                        # x86 至多一个 ModRM/moffs 内存操作数可写绝对位移；两个 "[" 只出现在
                        # movs/cmps 这类以寄存器为基址的串操作中，因此只看第一个 "[" 之后的字符
                        # （Capstone 的内存操作数总是成对的 "[...]"，"[" 之后必有字符）。
                        or (include_data and is_x86 and (
                                "[" in op_str and op_str[op_str.index("[") + 1] in _X86_NUMBER_STARTS
                                or mnemonic in _X86_POINTER_IMMEDIATES
                                and op_str.rpartition(", ")[2].startswith(_X86_HEX_IMMEDIATE)))
                        or (include_data and is_arm64 and (mnemonic == "add" and "#" in op_str
                                          or "[x" in op_str or "[fp" in op_str or "[lr" in op_str))):
                    operands = ins.operands
                    if targeted:
                        if mnemonic in _FAR_TRANSFERS:
                            branch["target"] = None
                        else:
                            branch_operands = reversed(operands) if is_arm64 and mnemonic in _ARM64_BIT_TESTS else operands
                            branch["target"] = next((int(operand.imm) for operand in branch_operands
                                                     if operand.type == immediate), None)
                    references = []
                    candidates = []
                    memory_operations = []
                    for operand in operands:
                        if (operand.type == memory and operand.mem.base in pc_registers and not operand.mem.index
                            and (not is_x86 or operand.mem.segment not in excluded_segments)):
                            pc = instruction_address + (instruction_size if is_x86 else 8)
                            bits = 64 if wide and operand.mem.base != eip else 32
                            references.append((pc + int(operand.mem.disp)) & ((1 << bits) - 1))
                        elif (include_data and is_x86 and operand.type == memory and not operand.mem.base
                              and not operand.mem.index and operand.mem.segment not in excluded_segments):
                            references.append(int(operand.mem.disp) & ((1 << (64 if wide else 32)) - 1))
                        elif (is_arm64 and operand.type == immediate
                              and mnemonic in (_ARM64_DIRECT_ADDRESSES if include_data else _ARM64_LITERAL_LOADS)):
                            references.append(int(operand.imm))
                        elif (include_data and is_x86 and operand.type == immediate
                              and mnemonic in _X86_POINTER_IMMEDIATES
                              and op_str.rpartition(", ")[2].startswith(_X86_HEX_IMMEDIATE)):
                            candidates.append(int(operand.imm) & ((1 << (64 if wide else 32)) - 1))
                        elif (include_data and is_arm64 and operand.type == memory and not operand.mem.index
                              and not ins.writeback):
                            memory_operations.append((name(operand.mem.base), int(operand.mem.disp)))
                    if references:
                        metadata["memory_references"] = tuple(dict.fromkeys(references))
                    if candidates:
                        metadata["address_candidates"] = tuple(dict.fromkeys(candidates))
                    if memory_operations:
                        metadata["memory_address_operations"] = tuple(memory_operations)
                    if (include_data and is_arm64 and mnemonic in {"adr", "adrp"} and len(operands) == 2
                            and operands[0].type == capstone.arm64.ARM64_OP_REG
                            and operands[1].type == immediate):
                        metadata["address_operation"] = {
                            "kind": "page" if mnemonic == "adrp" else "set",
                            "destination": name(operands[0].reg), "value": int(operands[1].imm)}
                    elif (include_data and is_arm64 and mnemonic == "add" and len(operands) == 3
                            and operands[0].type == capstone.arm64.ARM64_OP_REG
                            and operands[1].type == capstone.arm64.ARM64_OP_REG
                            and operands[2].type == immediate
                            and operands[2].shift.type in {0, capstone.arm64.ARM64_SFT_LSL}):
                        destination, source = name(operands[0].reg), name(operands[1].reg)
                        if (isinstance(destination, str) and isinstance(source, str)
                                and (destination.startswith("x") or destination in {"fp", "lr"})
                                and (source.startswith("x") or source in {"fp", "lr"})):
                            metadata["address_operation"] = {
                                "kind": "add", "destination": destination,
                                "source": source, "value": int(operands[2].imm) << operands[2].shift.value}
                try:
                    reads, writes = ins.regs_access()
                    try:
                        read_names = tuple(map(lookup, reads))
                        write_names = tuple(map(lookup, writes))
                    except KeyError:
                        # 首次出现的寄存器：按 reads 再 writes 的原顺序各查询一次。
                        for register in reads:
                            name(register)
                        for register in writes:
                            name(register)
                        read_names = tuple(map(lookup, reads))
                        write_names = tuple(map(lookup, writes))
                    read_names = interned.setdefault(read_names, read_names)
                    write_names = interned.setdefault(write_names, write_names)
                except (AttributeError, ValueError):
                    read_names = write_names = ()
                    if include_data and is_arm64:
                        metadata["address_state_clobber"] = True
                # 绝大多数指令只做一次成员/相等判断，不进入细化函数。
                if refine_arm and ((op_str == "lr") if branch else ("pc" in write_names)):
                    branch = _refine_arm(ins, mnemonic, op_str, branch, write_names, capstone) or {}
                operand_text = operand_cache.get(op_str)
                if operand_text is None:
                    operand_text = operand_cache[op_str] = tuple(
                        part.strip() for part in op_str.split(",") if part.strip())
                if compact is not None:
                    append(vars(compact(instruction_address, instruction_size, mnemonic, operand_text,
                                        read_names, write_names, branch, metadata)))
                else:
                    append({
                        "addr": instruction_address, "size": instruction_size, "mnemonic": mnemonic,
                        "operands": operand_text,
                        "reads": read_names, "writes": write_names, "branch_info": branch,
                        "arch_meta": metadata,
                    })
        except Exception as exc:
            return output, [f"Capstone decode failed: {type(exc).__name__}: {exc}"]
        return output, []


class UnavailableDecoder:
    """A capability result for an architecture with no registered provider."""

    engine = "none"
    capstone = None
    disassembler = None

    def __init__(self, architecture: str) -> None:
        self.warning = f"Disassembly unavailable for {architecture}"

    def decode_bytes(self, code: bytes, address: int, *, max_instructions: int = 128
                     ) -> tuple[list[dict[str, Any]], list[str]]:
        return [], [self.warning]
