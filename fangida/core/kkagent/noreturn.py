"""非返回（noreturn）调用目标的中立判定：已知名单、导入桩与本地不动点。

本模块不依赖任何分析插件，也从不调用指令解码器。它只读取三类已经完成的事实：

* Loader 元数据：ELF 动态重定位（JUMP_SLOT/GLOB_DAT 的符号名与槽位地址）、
  PE 导入地址表（IAT 槽位）与 Mach-O 导入（指针槽位、容器声明的桩地址）；
* 处理器已完成的只读指令快照（地址 → 指令记录）；
* xref 阶段已完成的引用（桩或调用点对导入槽位的数据引用、直接调用目标）。

判定分三步，全部保守：

1. 已知名单：名字规范化后（去掉版本后缀、PE ``__imp_`` 前缀、Mach-O/PE 的一个前导下划线）
   精确匹配 C 运行库、C++ ABI 与 Windows 的不返回函数；
2. 导入桩：调用目标处是不超过 MAX_STUB_INSTRUCTIONS（6）条的直线指令序列（x86 PLT 1～2 条，
   arm64 PLT 4 条，带 BTI/PAC 时 5～6 条），以无条件间接跳转结束，跳转所用的目标恰好由
   一个导入槽位装入（x86 ``jmp [rip+X]``；arm64 ``adrp/ldr/add/br``），且该槽位的导入名在
   名单中；经槽位的间接调用（``call [IAT]``、``mov reg, [slot]; call reg``、``adrp/ldr/blr``）
   按调用点判定；
3. 本地不动点：已分析函数从入口出发、把已知不返回调用视为路径终点后，若可达部分没有
   返回指令、没有可恢复的陷阱（int3/hlt/bkpt/其它 brk 立即数，见 deterministic_trap），
   也没有任何未知出口（间接跳转、未解码、越界、取消……），它本身也不返回。只有确定性
   陷阱（ud0/ud1/ud2、udf、arm64 ``brk #1``）与无出口的循环可以作为终点。

调用方把结果交给 CFG 构建（semantic._analyze_function 的可选参数）：对不返回目标的
无条件调用不再跟随顺序落空边（落空目标本身是陷阱指令时保留，陷阱即终点），并在
cfg["noreturn_calls"] 中留下可审计的记录。
"""
from __future__ import annotations

from bisect import bisect_left
from itertools import islice
from operator import itemgetter
import re
from typing import Any, Callable, Iterable, Mapping


# 导入桩最多几条指令：arm64 PLT 为 4 条，带 BTI/PAC 的 PLT 为 5～6 条
# （bti c / autia1716），x86 PLT 为 1～2 条（endbr64）。
MAX_STUB_INSTRUCTIONS = 6
# 经槽位间接调用：装入指令之后最多向前看几条指令找到使用该寄存器的调用。
MAX_SITE_LOOKAHEAD = 4
# 本地不动点的轮数上限（每轮只重算上一轮新增函数的调用者）。
MAX_FIXED_POINT_ROUNDS = 64
# 读取的重定位记录上限，与 Loader 自身的扫描预算同量级。
MAX_RELOCATIONS = 65536

# ELF 槽位重定位类型：GLOB_DAT 与 JUMP_SLOT。
_ELF_SLOT_TYPES = {"arm64": frozenset({1025, 1026}), "x86_64": frozenset({6, 7}),
                   "x86": frozenset({6, 7}), "arm": frozenset({21, 22})}

# 各平台通用的 C/POSIX/C++ 运行库不返回函数（规范化后的精确名字）。
_COMMON_NAMES = frozenset({
    # C 与 POSIX
    "exit", "_exit", "_Exit", "quick_exit", "abort", "thrd_exit", "pthread_exit",
    "longjmp", "_longjmp", "siglongjmp", "__longjmp_chk", "__libc_longjmp", "__libc_siglongjmp",
    # err/verr 这类过短的名字常见于用户代码中的普通函数，不收录；errx/verrx 沿用 Ghidra 名单。
    "errx", "verrx",
    # 栈保护、_FORTIFY_SOURCE 与断言（glibc / bionic / Apple libc）
    "__stack_chk_fail", "__stack_chk_fail_local", "__chk_fail", "__fortify_fail",
    "__fortify_fatal", "__libc_fatal", "__assert_fail", "__assert_perror_fail", "__assert",
    "__assert2", "__android_log_assert", "__assert_rtn", "abort_report_np",
    "abort_with_reason", "abort_with_payload",
    "__ubsan_handle_builtin_unreachable", "__ubsan_handle_missing_return",
    # C++ ABI 与展开
    "__cxa_throw", "__cxa_rethrow", "__cxa_bad_cast", "__cxa_bad_typeid",
    "__cxa_throw_bad_array_new_length", "__cxa_call_unexpected", "__cxa_pure_virtual",
    "__cxa_deleted_virtual", "__cxa_call_terminate", "__clang_call_terminate", "abort_message",
    "_Unwind_Resume", "_Unwind_SjLj_Resume",
    # std::terminate / unexpected / rethrow_exception（libstdc++ 与 libc++ 的修饰名）
    "_ZSt9terminatev", "_ZSt10unexpectedv", "_ZN10__cxxabiv111__terminateEPFvvE",
    "_ZSt11__terminatePFvvE", "_ZSt12__unexpectedPFvvE",
    "_ZSt17rethrow_exceptionNSt15__exception_ptr13exception_ptrE",
    "_ZSt17rethrow_exceptionSt13exception_ptr",
    "_ZNSt6__ndk117rethrow_exceptionENS_13exception_ptrE",
    "_ZNSt3__117rethrow_exceptionENS_13exception_ptrE",
    # Objective-C 运行时
    "objc_exception_throw", "objc_exception_rethrow", "objc_terminate",
})

# 只对 PE（或格式未知）生效的 Windows 名字：其中 terminate 之类在 ELF 程序里可能是普通函数。
_WINDOWS_NAMES = frozenset({
    "ExitProcess", "ExitThread", "FreeLibraryAndExitThread", "RtlExitUserProcess",
    "RtlExitUserThread", "RtlRaiseStatus", "_CxxThrowException", "__std_terminate", "terminate",
    "_invalid_parameter_noinfo_noreturn", "_invoke_watson", "_amsg_exit",
    "__report_gsfailure", "__report_rangecheckfailure", "__raise_securityfailure",
    "__report_securityfailure", "__report_securityfailureEx",
    "KeBugCheck", "KeBugCheckEx", "ExRaiseStatus", "ExRaiseAccessViolation",
    "ExRaiseDatatypeMisalignment", "RpcRaiseException",
    "?terminate@@YAXXZ", "?_Xbad_alloc@std@@YAXXZ", "?_Xbad_function_call@std@@YAXXZ",
    "?_Xlength_error@std@@YAXPBD@Z", "?_Xlength_error@std@@YAXPEBD@Z",
    "?_Xout_of_range@std@@YAXPBD@Z", "?_Xout_of_range@std@@YAXPEBD@Z",
    "?_Xinvalid_argument@std@@YAXPBD@Z", "?_Xinvalid_argument@std@@YAXPEBD@Z",
    "?_Xruntime_error@std@@YAXPBD@Z", "?_Xruntime_error@std@@YAXPEBD@Z",
    "?_Xoverflow_error@std@@YAXPBD@Z", "?_Xoverflow_error@std@@YAXPEBD@Z",
})

#: 全部已知名字（供其它模块查询或展示；判定请用 noreturn_name，它按容器格式选择名单）。
NORETURN_NAMES = _COMMON_NAMES | _WINDOWS_NAMES

_STD_PREFIXES = ("_ZSt", "_ZNSt", "_ZNKSt")
_DIGITS_BEFORE_THROW = re.compile(r"(\d+)__throw_")


def _std_throw_helper(text: str) -> bool:
    """libstdc++/libc++ 的 std::__throw_*（含 vector/string 的 __throw_length_error 等）。

    这些辅助函数按设计总是抛出异常。只接受 std 命名空间的修饰名，并要求
    ``<长度>__throw_<名字>`` 构成一个 Itanium 源名字：数字紧接在 ``__throw_`` 之前，
    且长度覆盖 ``__throw_`` 之后至少一个标识符字符，避免把更长标识符中的子串
    （如 ``do__throw_``）误判。
    """
    if not text.startswith(_STD_PREFIXES):
        return False
    for match in _DIGITS_BEFORE_THROW.finditer(text):
        digits, begin = match.group(1), match.start(1)
        for skip in range(len(digits)):
            length = int(digits[skip:])
            start = begin + len(digits)
            identifier = text[start:start + length]
            if (len(identifier) == length and identifier.startswith("__throw_")
                    and len(identifier) > len("__throw_")
                    and all(char.isalnum() or char == "_" for char in identifier)):
                return True
    return False


def normalize_symbol_name(name: object) -> str:
    """去掉 PE 导入前缀与版本后缀（``exit@GLIBC_2.2.5``、``exit@plt``、``_ExitProcess@4``）。

    MSVC 修饰名以 ``?`` 开头，其中的 ``@`` 是修饰语法的一部分，保持原样。
    前导下划线按容器格式在 noreturn_name 中处理。
    """
    if not isinstance(name, str):
        return ""
    text = name.strip()
    for prefix in ("__imp_", "_imp__"):
        if text.startswith(prefix) and len(text) > len(prefix):
            text = text[len(prefix):]
            break
    if not text.startswith("?"):
        text = text.split("@", 1)[0]
    return text


def noreturn_name(name: object, fmt: str = "") -> str | None:
    """名字在不返回名单中时返回规范化后的名字，否则返回 None。

    fmt 为容器格式（"elf"/"pe"/"macho"，未知时为空串）：Mach-O 的 C 符号带一个前导下划线，
    32 位 PE 的 cdecl 名字也带一个；ELF 名字按原样精确匹配（``_exit`` 与 ``exit`` 是两个函数，
    都在名单中）。Windows 专有名字只对 PE 与未知格式生效。
    """
    text = normalize_symbol_name(name)
    if not text:
        return None
    names = NORETURN_NAMES if fmt in {"pe", ""} else _COMMON_NAMES
    if fmt == "macho" and text.startswith("_") and len(text) > 1:
        # Mach-O 的 C 名字总是符号去掉一个前导下划线：_exit 是 exit，__exit 才是 _exit。
        candidates: tuple[str, ...] = (text[1:],)
    elif fmt != "elf" and text.startswith("_") and len(text) > 1:
        candidates = (text, text[1:])
    else:
        candidates = (text,)
    for candidate in candidates:
        if candidate in names or _std_throw_helper(candidate):
            return candidate
    return None


def is_noreturn_name(name: object, fmt: str = "") -> bool:
    return noreturn_name(name, fmt) is not None


# ---------------------------------------------------------------------------
# 名字 → 本地函数起点
# ---------------------------------------------------------------------------

def named_targets(functions: Iterable[dict[str, Any]], fmt: str = "",
                  accept: Callable[[int], bool] | None = None) -> dict[int, dict[str, Any]]:
    """本地定义的函数（符号表、导出、unwind 声明等）中名字在名单内的起点。

    同一起点的多个别名只要有一个名字在名单中即可（它们是同一段代码）。
    accept(起点) 可进一步限定（例如必须是已解码的指令起点）。按输入顺序确定性地取第一个证据。
    """
    targets: dict[int, dict[str, Any]] = {}
    for item in functions:
        if not isinstance(item, dict):
            continue
        start = item.get("start")
        if type(start) is not int or start in targets:
            continue
        name = noreturn_name(item.get("name"), fmt)
        if name is None or (accept is not None and not accept(start)):
            continue
        targets[start] = {"name": name, "evidence": "symbol_name", "symbol": item["name"]}
    return targets


# ---------------------------------------------------------------------------
# Loader 事实：导入槽位 → 名字
# ---------------------------------------------------------------------------

def _add_slot(table: dict[int, str | None], address: Any, name: Any) -> None:
    """同一槽位出现两个不同名字时记为 None（歧义，不使用）。"""
    if type(address) is not int or not isinstance(name, str) or not name:
        return
    if address in table and table[address] != name:
        table[address] = None
    elif address not in table:
        table[address] = name


def import_slots(image: Any, imports: Iterable[dict[str, Any]] | None = None
                 ) -> tuple[dict[int, str], str]:
    """返回 ({槽位地址: 导入名}, 证据来源)。歧义槽位被丢弃。

    ELF 使用 Loader 已读出的动态重定位（只接受虚拟地址形式的 GLOB_DAT/JUMP_SLOT）；
    PE 使用导入表的 IAT 槽位；Mach-O 使用导入的指针槽位（GOT/la_symbol_ptr）。
    """
    fmt = getattr(image, "format", "")
    table: dict[int, str | None] = {}
    source = ""
    if fmt == "elf":
        source = "elf_relocation"
        types = _ELF_SLOT_TYPES.get(getattr(image, "architecture", ""))
        if types:
            for item in islice(getattr(image, "dynamic_relocations", None) or (), MAX_RELOCATIONS):
                if (isinstance(item, dict) and item.get("type") in types
                        and item.get("address_kind", "virtual_address") == "virtual_address"):
                    _add_slot(table, item.get("address"), item.get("symbol_name"))
    elif fmt == "pe":
        source = "pe_import_address_table"
        for item in islice(imports or (), MAX_RELOCATIONS):
            if not isinstance(item, dict) or item.get("source") != "pe-import":
                continue
            name = item.get("name")
            # 按序号导入没有名字，无法与名单比对。
            if isinstance(name, str) and not name.startswith("#"):
                _add_slot(table, item.get("address"), name)
    elif fmt == "macho":
        source = "macho_indirect_symbol_table"
        for item in islice(imports or (), MAX_RELOCATIONS):
            if not isinstance(item, dict) or item.get("source") != "macho-import":
                continue
            for address in item.get("pointer_addresses") or ():
                _add_slot(table, address, item.get("name"))
    return {address: name for address, name in table.items() if name is not None}, source


def declared_stubs(image: Any, imports: Iterable[dict[str, Any]] | None = None) -> dict[int, str]:
    """Mach-O 间接符号表声明的“桩地址 → 导入名”（歧义桩被丢弃）。"""
    if getattr(image, "format", "") != "macho":
        return {}
    table: dict[int, str | None] = {}
    for item in islice(imports or (), MAX_RELOCATIONS):
        if not isinstance(item, dict) or item.get("source") != "macho-import":
            continue
        for address in item.get("stub_addresses") or ():
            _add_slot(table, address, item.get("name"))
    return {address: name for address, name in table.items() if name is not None}


def declared_noreturn_stubs(image: Any, imports: Iterable[dict[str, Any]] | None = None
                            ) -> dict[int, dict[str, Any]]:
    """容器声明的、指向不返回导入的 Mach-O 桩（不需要指令快照）。"""
    fmt = getattr(image, "format", "")
    found: dict[int, dict[str, Any]] = {}
    for address, name in sorted(declared_stubs(image, imports).items()):
        canonical = noreturn_name(name, fmt)
        if canonical is not None:
            found[address] = {"name": canonical, "evidence": "declared_stub", "symbol": name,
                              "slot": None, "source": "macho_indirect_symbol_table"}
    return found


# ---------------------------------------------------------------------------
# 已完成快照的只读访问：寄存器、装入与内存操作数
# ---------------------------------------------------------------------------

_X86_ALIASES = {**{f"e{name}": f"r{name}" for name in ("ax", "bx", "cx", "dx", "si", "di", "bp")},
                **{f"r{index}d": f"r{index}" for index in range(8, 16)}}
_X86_GPRS = frozenset({"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
                       *(f"r{index}" for index in range(8, 16))})
_A64_LOADS = frozenset({"ldr", "ldur", "ldar", "ldapr", "ldapur", "ldraa", "ldrab"})
# PAC-PLT 在 br x17 之前用 x16 作修饰符认证 x17：值仍是从槽位装入的指针，按“透传”处理。
_A64_PASS_THROUGH = frozenset({"autia1716", "autib1716"})


def _register(name: Any, architecture: str) -> str | None:
    """规范化通用寄存器名；栈指针、程序计数器、零寄存器与标志不参与寄存器流判断。"""
    if not isinstance(name, str):
        return None
    name = name.lower()
    if architecture == "arm64":
        if len(name) in {2, 3} and name[0] in {"x", "w"} and name[1:].isdigit() and int(name[1:]) <= 30:
            return "x" + str(int(name[1:]))
        return {"fp": "x29", "lr": "x30"}.get(name)
    if architecture in {"x86", "x86_64"}:
        name = _X86_ALIASES.get(name, name)
        return name if name in _X86_GPRS else None
    return None


def _architecture(instruction: dict[str, Any]) -> str:
    metadata = instruction.get("arch_meta")
    return metadata.get("architecture", "") if isinstance(metadata, dict) else ""


def _registers(instruction: dict[str, Any], key: str) -> set[str]:
    architecture = _architecture(instruction)
    found = set()
    for name in instruction.get(key) or ():
        register = _register(name, architecture)
        if register is not None:
            found.add(register)
    return found


def _memory_operand(instruction: dict[str, Any]) -> bool:
    return any(isinstance(operand, str) and "[" in operand
               for operand in instruction.get("operands") or ())


def _is_load(instruction: dict[str, Any]) -> bool:
    """只把真正“从内存取值写入寄存器”的指令当作槽位装入；地址计算（add/lea）不算。"""
    mnemonic = str(instruction.get("mnemonic", "")).lower()
    architecture = _architecture(instruction)
    if architecture == "arm64":
        return mnemonic in _A64_LOADS
    if architecture in {"x86", "x86_64"}:
        operands = instruction.get("operands") or ()
        return mnemonic == "mov" and len(operands) == 2 and "[" in str(operands[1])
    return False


def _branch(instruction: dict[str, Any]) -> dict[str, Any]:
    branch = instruction.get("branch_info")
    return branch if isinstance(branch, dict) else {}


def _single(values: set[int] | None) -> int | None:
    return next(iter(values)) if values is not None and len(values) == 1 else None


def _stub_chain(cache: Mapping[int, dict[str, Any]], start: int) -> list[dict[str, Any]] | None:
    """从 start 起不超过 MAX_STUB_INSTRUCTIONS 条、以无条件间接跳转结束的直线序列。"""
    chain: list[dict[str, Any]] = []
    address = start
    for _ in range(MAX_STUB_INSTRUCTIONS):
        instruction = cache.get(address)
        if instruction is None or type(instruction.get("size")) is not int or instruction["size"] <= 0:
            return None
        chain.append(instruction)
        branch = _branch(instruction)
        if branch.get("kind"):
            if (branch.get("kind") != "jump" or branch.get("target") is not None
                    or branch.get("conditional")):
                return None
            return chain
        address += instruction["size"]
    return None


def _chain_slot(chain: list[dict[str, Any]], slot_refs: Mapping[int, set[int]]) -> int | None:
    """桩末尾间接跳转实际使用的槽位：跳转自身的内存操作数，或其寄存器的最后一次装入。"""
    jump = chain[-1]
    own = slot_refs.get(jump["addr"])
    if own is not None:
        return _single(own) if _memory_operand(jump) else None
    used = _registers(jump, "reads")
    if len(used) != 1:
        return None
    (register,) = used
    for instruction in reversed(chain[:-1]):
        if register in _registers(instruction, "writes"):
            if (_architecture(instruction) == "arm64"
                    and str(instruction.get("mnemonic", "")).lower() in _A64_PASS_THROUGH):
                continue
            if not _is_load(instruction) or _registers(instruction, "writes") != {register}:
                return None
            return _single(slot_refs.get(instruction["addr"]))
    return None


# ---------------------------------------------------------------------------
# 导入桩与经槽位的间接调用点
# ---------------------------------------------------------------------------

def import_noreturn(cache: Mapping[int, dict[str, Any]], references: Iterable[dict[str, Any]],
                    image: Any, imports: Iterable[dict[str, Any]] | None = None, *,
                    is_cancelled: Callable[[], bool] | None = None
                    ) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, Any]]]:
    """返回 (调用目标 → 证据, 间接调用指令地址 → 证据)，只含不返回的导入。

    references 是 xref 阶段已完成的引用；这里只按 kind/dst 读取，不新建引用，也不解码。
    """
    fmt = getattr(image, "format", "")
    slots, source = import_slots(image, imports)
    declared = declared_noreturn_stubs(image, imports)
    noreturn_slots = {address for address, name in slots.items() if noreturn_name(name, fmt)}
    noreturn_stubs = set(declared)
    targets: dict[int, dict[str, Any]] = {}
    sites: dict[int, dict[str, Any]] = {}
    if not noreturn_slots and not noreturn_stubs:
        return targets, sites
    # 一次遍历：所有槽位的数据引用（含非名单槽位，用于识别桩实际读取的是哪个导入）与直接调用目标。
    slot_refs: dict[int, set[int]] = {}
    call_targets: set[int] = set()
    references = references if isinstance(references, (list, tuple)) else list(references)
    for reference in references:
        kind = reference.get("kind")
        if kind == "data":
            destination = reference.get("dst")
            if destination in slots and reference.get("evidence") is None:
                source_address = reference.get("src")
                if type(source_address) is int:
                    slot_refs.setdefault(source_address, set()).add(destination)
        elif kind == "call":
            destination = reference.get("dst")
            if type(destination) is int:
                call_targets.add(destination)
    if is_cancelled is not None and is_cancelled():
        return {}, {}
    # 1) 导入桩：直接调用目标处的短直线序列经某个槽位间接跳转。
    for start in sorted(call_targets | noreturn_stubs):
        if start not in cache:
            continue
        chain = _stub_chain(cache, start)
        slot = _chain_slot(chain, slot_refs) if chain is not None else None
        if start in noreturn_stubs:
            evidence = declared[start]
            # 桩实际读取的槽位若属于另一个导入，容器声明与快照矛盾：拒绝。
            if slot is not None and slots.get(slot) != evidence["symbol"]:
                continue
            targets[start] = {**evidence, "slot": slot}
        elif slot is not None and slot in noreturn_slots:
            targets[start] = {"name": noreturn_name(slots[slot], fmt), "evidence": "import_stub",
                              "symbol": slots[slot], "slot": slot, "source": source}
    # 2) 经槽位的间接调用：x86 ``call [slot]``；arm64 ``ldr xN, [slot]`` 之后不远处的 ``blr xN``。
    pending: list[tuple[int, int, list[int]]] = []   # (调用点, 槽位, 装入之后到调用点为止的地址)
    for address in sorted(slot_refs):
        slot = _single(slot_refs[address])
        if slot is None or slot not in noreturn_slots:
            continue
        instruction = cache.get(address)
        if instruction is None:
            continue
        branch = _branch(instruction)
        if branch.get("kind") == "call":
            if branch.get("target") is None and not branch.get("conditional") and _memory_operand(instruction):
                sites[address] = {"name": noreturn_name(slots[slot], fmt), "evidence": "import_slot_call",
                                  "symbol": slots[slot], "slot": slot, "source": source}
            continue
        if branch or not _is_load(instruction):
            continue
        written = _registers(instruction, "writes")
        if len(written) != 1:
            continue
        (register,) = written
        between: list[int] = []
        cursor = address + instruction["size"]
        for _ in range(MAX_SITE_LOOKAHEAD):
            following = cache.get(cursor)
            if following is None:
                break
            between.append(cursor)
            follow_branch = _branch(following)
            if follow_branch.get("kind"):
                operands = following.get("operands") or ()
                # 调用目标必须就是装入的寄存器本身（blr xN / call rax），
                # 而不是以它为基址的内存操作数（call [rax + 8]）。
                uses = (not _memory_operand(following)
                        and _register(operands[0], _architecture(following)) == register
                        if operands else register in _registers(following, "reads"))
                if (follow_branch.get("kind") == "call" and follow_branch.get("target") is None
                        and not follow_branch.get("conditional") and uses):
                    pending.append((cursor, slot, between))
                break
            if register in _registers(following, "writes"):
                break
            cursor += following["size"]
    if pending:
        # 装入与调用之间（含调用点）若是某条直接分支的目标，别的路径可能带来不同的寄存器值：放弃。
        interest = {address for _, _, between in pending for address in between}
        entered = {reference["dst"] for reference in references
                   if reference.get("kind") in {"call", "jmp"} and reference.get("dst") in interest}
        for call, slot, between in pending:
            if entered.isdisjoint(between) and call not in sites:
                sites[call] = {"name": noreturn_name(slots[slot], fmt), "evidence": "import_slot_call",
                               "symbol": slots[slot], "slot": slot, "source": source}
    return targets, sites


# ---------------------------------------------------------------------------
# 本地不动点：所有出口都只能结束于不返回调用/确定性陷阱/循环的函数
# ---------------------------------------------------------------------------

# 执行后一定不会继续到下一条指令的陷阱助记符：x86 ud0/ud1/ud2 产生 #UD（无效指令），
# ARM/AArch64 的 udf 是永久未定义指令。
_DETERMINISTIC_TRAP_MNEMONICS = frozenset({"ud0", "ud1", "ud2", "udf"})
# AArch64 brk 中只接受 clang/GCC __builtin_trap 使用的立即数 1。其它立即数含义因平台而异：
# __builtin_debugtrap 的 brk #0xf000、Linux 内核 WARN 使用的 brk #0x800 都会在处理后继续执行。
_DETERMINISTIC_BRK_IMMEDIATES = frozenset({1})


def _immediate(operand: Any) -> int | None:
    """解析 ``#1``、``#0x1``、``1`` 形式的立即数操作数；其它形式返回 None。"""
    if not isinstance(operand, str):
        return None
    text = operand.strip().lstrip("#").strip()
    try:
        return int(text, 0)
    except ValueError:
        return None


def deterministic_trap(instruction: Mapping[str, Any]) -> bool:
    """处理器归为 trap 的指令中，执行后确定不会落空到下一条指令的那些。

    int3、hlt、bkpt 与 brk 的其它立即数是可恢复的：调试器或 SIGTRAP 处理函数返回后、
    内核态 hlt 被中断唤醒后都会继续执行下一条指令（例如 ``int3; ret`` 形式的
    __builtin_debugtrap 包装函数会正常返回），推导“不返回”时只能按未知出口处理。
    """
    mnemonic = str(instruction.get("mnemonic", "")).lower()
    if " " in mnemonic:
        mnemonic = mnemonic.rsplit(None, 1)[-1]  # 与处理器分类一致：忽略 x86 前缀
    if mnemonic in _DETERMINISTIC_TRAP_MNEMONICS:
        return True
    if mnemonic == "brk":
        operands = instruction.get("operands") or ()
        return len(operands) == 1 and _immediate(operands[0]) in _DETERMINISTIC_BRK_IMMEDIATES
    return False


# 每个基本块的摘要：(块尾可能返回：返回指令或可恢复陷阱, 块尾无条件调用 (目标, 指令地址) 或 None,
#                    块尾出口 ((原因, 去向), ...), 后继块起点)
_Block = tuple[bool, "tuple[int | None, int] | None", tuple, tuple]
_BRANCH_INFO = itemgetter("branch_info")


def _summary(function: dict[str, Any]
             ) -> tuple[int, dict[int, _Block] | None, set[int], set[int]] | None:
    """把一个已完成 CFG 压缩成可反复做可达性判断的摘要（不修改原记录）。

    返回 (入口, {块起点: 块摘要} 或 None, 依赖的目标地址, 块尾无条件直接调用的目标)。
    CFG 构建保证只有块尾带分支信息、出口（frontier）只从块尾发出，因此只需看块尾；
    不符合这一形状的图（块内出现分支或出口）摘要为 None，表示“总是可能返回”（保守）。
    """
    start = function.get("start")
    cfg = function.get("cfg")
    blocks = function.get("blocks")
    if type(start) is not int or not isinstance(cfg, dict) or not blocks:
        return None
    exits: dict[Any, list[tuple[Any, Any]]] = {}
    for item in cfg.get("frontier") or ():
        if isinstance(item, dict):
            exits.setdefault(item.get("from"), []).append((item.get("reason"), item.get("to")))
    summary: dict[int, _Block] | None = {}
    dependencies: set[int] = set()
    called: set[int] = set()
    pop_exits = exits.pop if exits else None
    for block in blocks:
        try:
            instructions = block["instructions"]
            tail = instructions[-1]
            # CFG 构建保证块内（除块尾外）不带分支信息；否则形状不符，保守处理。
            if summary is not None and len(instructions) > 1 and any(map(_BRANCH_INFO, instructions[:-1])):
                summary = None
            branch = tail["branch_info"]
        except (KeyError, IndexError, TypeError):
            return None
        kind = branch.get("kind") if branch else None
        call = None
        if kind == "call" and not branch.get("conditional"):
            target = branch.get("target")
            address = tail.get("addr")
            if type(target) is int:
                call = (target, address)
                dependencies.add(target)
                called.add(target)
            else:
                call = (None, address)
        tail_exits: tuple = ()
        if pop_exits is not None:
            tail_exits = tuple(pop_exits(tail.get("addr"), ()))
            for reason, destination in tail_exits:
                if reason == "other_function" and type(destination) is int:
                    dependencies.add(destination)
        if summary is not None:
            # 可恢复陷阱之后会继续执行下一条指令（CFG 不跟随），与返回同样视为“可能返回”。
            exits_here = kind == "return" or (kind == "trap" and not deterministic_trap(tail))
            # 后继列表只读共享，不复制。
            summary[block.get("start")] = (exits_here, call, tail_exits,
                                           block.get("successors") or ())
    if exits:
        summary = None  # 有出口不是从块尾发出：形状不符，保守
    return start, summary, dependencies, called


# 本项目 CFG 构建器（semantic._analyze_function）产出的图：只有块尾带分支信息、出口只从块尾
# 发出、全部块都从入口经后继边可达。对这类图先做一次不建块摘要的精简扫描（见 _scan）。
_TRUSTED_SCOPES = frozenset({"bounded_function", "full_region_recovered_function"})


def _scan(function: dict[str, Any], targets: Mapping[int, Any], sites: Mapping[int, Any]
          ) -> tuple[int, set[int], set[int], bool | None] | None:
    """精简扫描（只用于 _TRUSTED_SCOPES 的图）：返回 (入口, 依赖, 直接调用目标, 首轮结论)。

    首轮结论只在函数中没有任何“已知不返回调用”时给出：此时 _may_return 不会跳过任何后继，
    会遍历全部块（全部块都从入口可达），结论就是“是否存在返回/可恢复陷阱块尾或未知出口”
    （True 表示可能返回）。其它情况结论为 None，由调用方精确判断（_may_return_blocks）。
    输入不合预期时返回 None，调用方改走 _summary，与原实现的保守处理完全一致。
    依赖 = 直接调用目标 ∪ 流入其它函数的出口去向（与 _summary 相同）。
    """
    start = function.get("start")
    blocks = function.get("blocks")
    if type(start) is not int or not blocks:
        return None
    called: set[int] = set()
    flowing: set[int] = set()
    may_exit = False
    simple = True
    try:
        for block in blocks:
            tail = block["instructions"][-1]
            branch = tail["branch_info"]
            if not branch:
                continue
            kind = branch.get("kind")
            if kind == "call":
                if branch.get("conditional"):
                    continue
                target = branch.get("target")
                if type(target) is int:
                    called.add(target)
                    if target in targets:
                        simple = False
                # 与 _may_return 相同：直接调用的指令地址在 sites 中也算不返回调用。
                if sites and simple and tail.get("addr") in sites:
                    simple = False
            elif kind == "return" or (kind == "trap" and not deterministic_trap(tail)):
                may_exit = True
        for item in function["cfg"].get("frontier") or ():
            if not isinstance(item, dict):
                continue
            reason, destination = item.get("reason"), item.get("to")
            if reason == "other_function" and type(destination) is int:
                flowing.add(destination)
            # 只有“流入已知不返回函数”的出口是终点，其余出口一律未知。
            if reason != "other_function" or destination not in targets:
                may_exit = True
    except Exception:
        return None
    return start, (called | flowing if flowing else called), called, (may_exit if simple else None)


_BLOCK_START = itemgetter("start")


def _may_return_blocks(function: dict[str, Any], current: Mapping[int, Any],
                       sites: Mapping[int, Any]) -> bool:
    """_summary + _may_return 的等价形式，直接在 _TRUSTED_SCOPES 的图上遍历，不预建块摘要。

    这类图的块按起点有序，后继块用二分查找定位；逐块读取的事实与 _summary 完全相同。
    遍历一遇到可能返回的块就停止，通常只访问少数块（大函数里的栈保护失败分支等）。
    输入不合预期时按“可能返回”处理（保守）。
    """
    try:
        blocks = function["blocks"]
        exits: dict[Any, list[tuple[Any, Any]]] = {}
        for item in function["cfg"].get("frontier") or ():
            if isinstance(item, dict):
                exits.setdefault(item.get("from"), []).append((item.get("reason"), item.get("to")))
        entry, count = function["start"], len(blocks)
        stack, seen = [entry], {entry}
        while stack:
            address = stack.pop()
            position = bisect_left(blocks, address, key=_BLOCK_START)
            if position == count or blocks[position]["start"] != address:
                return True
            block = blocks[position]
            tail = block["instructions"][-1]
            branch = tail["branch_info"]
            kind = branch.get("kind") if branch else None
            if kind == "return" or (kind == "trap" and not deterministic_trap(tail)):
                return True
            if kind == "call" and not branch.get("conditional"):
                target = branch.get("target")
                if (type(target) is int and target in current) or tail.get("addr") in sites:
                    continue  # 不返回的调用：本路径到此结束
            for reason, destination in exits.get(tail.get("addr"), ()):
                if reason != "other_function" or destination not in current:
                    return True
            for successor in block.get("successors") or ():
                if successor not in seen:
                    seen.add(successor)
                    stack.append(successor)
        return False
    except Exception:
        return True


def _may_return(entry: int, blocks: dict[int, _Block] | None, current: Mapping[int, Any],
                sites: Mapping[int, Any]) -> bool:
    """从入口出发，把已知不返回调用当作路径终点后，是否可能返回或经未知出口离开。

    路径终点只有三种：已知不返回调用、确定性陷阱、以及流入已知不返回函数的出口；
    返回指令、可恢复陷阱与其它出口一律算作“可能返回”。"""
    if blocks is None:
        return True
    stack, seen = [entry], {entry}
    while stack:
        block = blocks.get(stack.pop())
        if block is None:
            return True
        may_exit, call, tail_exits, successors = block
        if may_exit:
            return True
        if call is not None and ((call[0] is not None and call[0] in current) or call[1] in sites):
            continue  # 不返回的调用：本路径到此结束，落空边与其出口都不再计入
        for reason, destination in tail_exits:
            # 只有“流入另一个已知不返回函数”（尾跳转或落空进入）是已知终点，其余出口一律未知。
            if reason != "other_function" or destination not in current:
                return True
        for successor in successors:
            if successor not in seen:
                seen.add(successor)
                stack.append(successor)
    return False


def local_noreturn(functions: Iterable[dict[str, Any]], targets: Mapping[int, Any],
                   sites: Mapping[int, Any] | None = None, *,
                   max_rounds: int = MAX_FIXED_POINT_ROUNDS,
                   is_cancelled: Callable[[], bool] | None = None
                   ) -> tuple[dict[int, dict[str, Any]], list[int], int]:
    """在已完成的 CFG 上迭代到不动点，返回 (新增不返回函数 → 证据, 需要重建的调用者起点, 轮数)。

    只有确定性陷阱（deterministic_trap）可以作为路径终点；int3/hlt/bkpt 等可恢复陷阱按未知
    出口处理，因此 ``int3; ret`` 形式的调试陷阱包装函数及其调用者都不会被判为不返回。
    “不返回”是单调的：已知集合越大，可达部分越小，因此按轮（每轮先判定、再整体加入）
    迭代得到唯一的最小不动点，与函数顺序无关。达到 max_rounds 时停止，已得到的结论仍然成立。
    需要重建的调用者：CFG 中存在对新增函数的无条件直接调用的函数（落空边应被截断）。
    """
    sites = sites or {}
    # 本项目 CFG（_TRUSTED_SCOPES）先做精简扫描：多数函数在首轮就由扫描结论判定，其余情况
    # （含已知不返回调用的函数、后续轮次重算的调用者）直接在块上遍历，不预建摘要；
    # 其它来源的图仍按 _summary + _may_return 处理。两种方式对同一张图的结论相同。
    summaries: dict[int, tuple[int, dict[int, _Block] | None]] = {}
    sources: dict[int, dict[str, Any]] = {}
    first_round: dict[int, bool] = {}   # 精简扫描给出的首轮结论（True 表示可能返回）
    callers: dict[int, set[int]] = {}
    call_sites: dict[int, set[int]] = {}
    for function in functions:
        if not isinstance(function, dict):
            continue
        cfg = function.get("cfg")
        scanned = (_scan(function, targets, sites)
                   if isinstance(cfg, dict) and cfg.get("scope") in _TRUSTED_SCOPES else None)
        if scanned is None:
            summary = _summary(function)
            if summary is None or summary[0] in sources:
                continue
            start, blocks, dependencies, called = summary
            summaries[start] = (start, blocks)
        else:
            start, dependencies, called, verdict = scanned
            if start in sources:
                continue
            if verdict is not None:
                first_round[start] = verdict
        sources[start] = function
        # 已在 targets 中的依赖不会再“新增”，不需要反向索引。
        for dependency in dependencies:
            if dependency in targets:
                continue
            entry = callers.get(dependency)
            if entry is None:
                callers[dependency] = {start}
            else:
                entry.add(start)
        for target in called:
            if target in targets:
                continue
            entry = call_sites.get(target)
            if entry is None:
                call_sites[target] = {start}
            else:
                entry.add(start)

    def may_return(start: int) -> bool:
        # 首轮结论只对首轮的已知集合（targets）成立，用过即弃；之后一律精确判断。
        verdict = first_round.pop(start, None)
        if verdict is not None:
            return verdict
        summary = summaries.get(start)
        if summary is None:
            return _may_return_blocks(sources[start], current, sites)
        return _may_return(*summary, current, sites)

    current = dict(targets)
    found: dict[int, dict[str, Any]] = {}
    pending = sorted(start for start in sources if start not in current)
    rounds = 0
    while pending and rounds < max_rounds:
        if is_cancelled is not None and is_cancelled():
            break
        rounds += 1
        new = [start for start in pending if not may_return(start)]
        first_round.clear()
        if not new:
            break
        for start in new:
            name = sources[start].get("name")
            evidence = {"name": name if isinstance(name, str) else f"sub_{start:x}",
                        "evidence": "local_fixed_point", "round": rounds}
            current[start] = found[start] = evidence
        pending = sorted({caller for start in new for caller in callers.get(start, ())}
                         - current.keys())
    rebuild = sorted({caller for start in found for caller in call_sites.get(start, ())})
    return found, rebuild, rounds
