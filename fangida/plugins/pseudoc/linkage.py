"""Name verified linkage thunks from loader facts and completed snapshots.

No binary reader, decoder or xref analysis is called here. Every supported
pattern is intentionally exact; another layout remains unresolved.

支持的链接形式（全部只读取 Loader 事实与已完成的指令快照）：

* ELF arm64 PLT：adrp x16 / ldr x17 / add x16 / br x17 + R_AARCH64_JUMP_SLOT（原有实现）。
* ELF x86/x86-64 PLT：.plt / .plt.sec / .plt.got 中的 ``jmp [GOT]``（可带 endbr、bnd 前缀）
  + R_X86_64_JUMP_SLOT / GLOB_DAT（i386 为 R_386_JMP_SLOT / GLOB_DAT）。
* Mach-O __stubs / __auth_stubs：容器的间接符号表本身声明了“第 i 个桩 → 符号”，
  Loader 已据此给出导入的 stub_addresses / pointer_addresses；若快照中有桩指令，
  还会核对桩实际读取的指针槽位指向同一符号，矛盾时拒绝命名。
* PE 导入：``jmp [IAT]`` 形式的导入 thunk（x86/x86-64），以及 ARM64 的
  adrp x16 / ldr x16 / br x16 thunk。

返回 ``{目标地址: 证据}``。目标是代码地址（thunk/桩/PLT 项）时
``target_kind == "linkage_thunk"``；``call [IAT]``、``call [rip+GOT]``、
``adrp/ldr/blr`` 这类直接经指针槽位的调用没有可作为调用目标的代码地址，
以槽位地址为键给出 ``target_kind == "import_pointer_slot"`` 的证据，并在
``call_sites`` 中列出已核实的调用点地址，供下游按调用点或常量槽位命名。
"""
from __future__ import annotations

from itertools import islice, chain
import re

from .native_operands import split_operands


MAX_LINKAGE_ROWS = 2_000_000
MAX_LINKAGE_TARGETS = 4096
# 与伪 C 流水线一致：只为它会渲染的前 128 个带指令的函数收集调用目标与调用点。
MAX_LINKAGE_FUNCTIONS = 128
MAX_CALL_SITES_PER_SLOT = 1024
# A64 调用点向前追溯寄存器定义的最大指令数（只在同一基本块内）。
MAX_BACKTRACK = 16

_RUNTIME_BINDING = "dynamic_and_possibly_preemptible"
_X86_JUMPS = frozenset({"jmp", "bnd jmp", "notrack jmp", "notrack bnd jmp", "bnd notrack jmp"})
_X86_CALLS = frozenset({"call", "bnd call", "notrack call", "notrack bnd call", "bnd notrack call"})
_X86_MEMORY = re.compile(
    r"(byte|word|dword|qword|xword|tbyte) ptr (?:[cdefgs]s:)?"
    r"\[(?:(rip|eip)\s*([+-])\s*)?(0x[0-9a-f]+|[0-9]+)\]", re.I)
_A64_INDIRECT_CALLS = frozenset({"blr", "blraa", "blraaz", "blrab", "blrabz"})
_A64_INDIRECT_JUMPS = frozenset({"br", "braa", "braaz", "brab", "brabz"})
_A64_REGISTER = re.compile(r"[xw]([0-9]|[12][0-9]|30)")
_NUMBER = re.compile(r"#?(-?)(0x[0-9a-f]+|[0-9]+)", re.I)
# ELF 槽位重定位类型：(GLOB_DAT, JUMP_SLOT)
_ELF_SLOT_TYPES = {"x86_64": frozenset({6, 7}), "x86": frozenset({6, 7}), "arm64": frozenset({1025, 1026})}


class _Cancelled(Exception):
    """内部信号：取消时整体返回空结果，不给出部分猜测。"""


def resolve_thunk_targets(result, targets, *, is_cancelled=None):
    """只核对给定地址是否为链接桩（PLT / 导入桩），证据规则与 resolve_linkage 相同。

    resolve_linkage 只从前 128 个函数收集候选；过程间参数分析需要更深层调用链上的桩时
    用本函数补充。返回 {桩地址: 证据}，只含 target_kind="linkage_thunk" 的项。
    """
    candidates = sorted({target for target in targets if type(target) is int})
    if not candidates:
        return {}
    kind = result.kind
    if kind not in {"elf", "macho", "pe"}:
        kind = result.metadata.get("format", kind)
    architecture = result.metadata.get("architecture")
    try:
        if kind == "elf" and architecture == "arm64":
            found = _resolve_elf_a64_plt(result, is_cancelled, candidates) or {}
        elif kind == "elf" and architecture in {"x86", "x86_64"}:
            found = _resolve_slots_and_thunks(result, is_cancelled, _elf_slots(result, architecture),
                                              {}, architecture, "elf_relocation", candidates)
        elif kind == "macho" and architecture in {"x86", "x86_64", "arm64"}:
            slots, stubs = _macho_slots(result)
            found = _resolve_slots_and_thunks(result, is_cancelled, slots, stubs, architecture,
                                              "macho_indirect_symbol_table", candidates)
        elif kind == "pe" and architecture in {"x86", "x86_64", "arm64"}:
            found = _resolve_slots_and_thunks(result, is_cancelled, _pe_slots(result), {},
                                              architecture, "pe_import_address_table", candidates)
        else:
            return {}
    except _Cancelled:
        return {}
    return {target: item for target, item in found.items() if item.get("target_kind") == "linkage_thunk"}


def resolve_linkage(result, *, is_cancelled=None):
    kind = result.kind
    if kind not in {"elf", "macho", "pe"}:
        # 直接用 kind="unknown" 调用插件时，以 Loader 写入的容器格式为准。
        kind = result.metadata.get("format", kind)
    architecture = result.metadata.get("architecture")
    try:
        if kind == "elf" and architecture == "arm64":
            return _resolve_elf_a64(result, is_cancelled)
        if kind == "elf" and architecture in {"x86", "x86_64"}:
            return _resolve_slots_and_thunks(result, is_cancelled, _elf_slots(result, architecture),
                                             {}, architecture, "elf_relocation")
        if kind == "macho" and architecture in {"x86", "x86_64", "arm64"}:
            slots, stubs = _macho_slots(result)
            return _resolve_slots_and_thunks(result, is_cancelled, slots, stubs, architecture,
                                             "macho_indirect_symbol_table")
        if kind == "pe" and architecture in {"x86", "x86_64", "arm64"}:
            return _resolve_slots_and_thunks(result, is_cancelled, _pe_slots(result), {},
                                             architecture, "pe_import_address_table")
    except _Cancelled:
        return {}
    return {}


# ---------------------------------------------------------------------------
# Loader 事实：槽位地址 → 符号
# ---------------------------------------------------------------------------

def _add_unique(table, address, value, key):
    """同一地址出现两个不同事实时记为 None（歧义，不命名）。"""
    if address in table:
        if table[address] is not None and table[address][key] != value[key]:
            table[address] = None
        return
    table[address] = value


def _relocation_map(result, types):
    relocations = {}
    for item in islice(result.metadata.get("dynamic_relocations", ()), 10000):
        if item.get("type") in types and isinstance(item.get("address"), int) and item.get("symbol_name"):
            if item["address"] in relocations and relocations[item["address"]] != item:
                relocations[item["address"]] = None
            else:
                relocations[item["address"]] = item
    return relocations


def _elf_slots(result, architecture):
    slots = {}
    for address, item in _relocation_map(result, _ELF_SLOT_TYPES[architecture]).items():
        if item is None:
            slots[address] = None
            continue
        slots[address] = {"name": item["symbol_name"], "display_name": item["symbol_name"],
                          "symbol_value": item.get("symbol_value"), "got_address": address,
                          "relocation_type": item.get("type")}
    return slots


def _import_rows(result, source):
    for item in islice(getattr(result, "imports", None) or (), 65536):
        if isinstance(item, dict) and item.get("source") == source and isinstance(item.get("name"), str) and item["name"]:
            yield item


def _macho_slots(result):
    slots, stubs = {}, {}
    for item in _import_rows(result, "macho-import"):
        evidence = {"name": item["name"], "display_name": item.get("display_name") or item["name"],
                    "library": item.get("library")}
        for address in item.get("pointer_addresses") or ():
            if type(address) is int:
                _add_unique(slots, address, evidence, "name")
        for address in item.get("stub_addresses") or ():
            if type(address) is int:
                _add_unique(stubs, address, evidence, "name")
    return slots, stubs


def _pe_slots(result):
    slots = {}
    for item in _import_rows(result, "pe-import"):
        if type(item.get("address")) is not int:
            continue
        name = item["name"]
        library = item.get("library")
        if name.startswith("#") and type(item.get("ordinal")) is int:
            stem = str(library or "import").rsplit(".", 1)[0]
            name = f"{stem}_ordinal_{item['ordinal']}"
        _add_unique(slots, item["address"], {"name": name, "display_name": name,
                                             "symbol_name": item["name"], "library": library}, "name")
    return slots


# ---------------------------------------------------------------------------
# 已完成快照的只读访问
# ---------------------------------------------------------------------------

def _function_row_lists(function):
    blocks = function.get("blocks") or function.get("cfg", {}).get("blocks", ())
    if blocks:
        return [block.get("instructions", ()) for block in blocks]
    return [function.get("disassembly", ())]


def _scan_rendered(result, is_cancelled, observe):
    """按伪 C 流水线的顺序遍历前 MAX_LINKAGE_FUNCTIONS 个带指令函数的基本块。

    只对带 branch_info 的指令调用 observe(local, rows, index, row)；local 是本函数所有
    基本块起点的集合：函数内部跳转总是落在块起点上，据此可以把真正离开函数的跳转
    （尾调用 thunk）与普通分支区分开。
    """
    seen = scanned = next_check = 0
    for function in result.functions:
        if not (function.get("blocks") or function.get("disassembly") or function.get("cfg", {}).get("blocks")):
            continue
        seen += 1
        if seen > MAX_LINKAGE_FUNCTIONS:
            break
        row_lists = _function_row_lists(function)
        local = {rows[0].get("addr") for rows in row_lists if rows and isinstance(rows[0], dict)}
        for rows in row_lists:
            rows = rows if isinstance(rows, (list, tuple)) else list(rows)
            if is_cancelled is not None and scanned >= next_check:
                next_check = scanned + 4096
                if is_cancelled():
                    raise _Cancelled
            if scanned + len(rows) > MAX_LINKAGE_ROWS:
                rows = rows[:max(0, MAX_LINKAGE_ROWS - scanned)]
            scanned += len(rows)
            for index, row in enumerate(rows):
                if row.get("branch_info"):
                    observe(local, rows, index, row)
            if scanned >= MAX_LINKAGE_ROWS:
                return


def _index_rows(result, wanted, is_cancelled):
    """与原 A64 PLT 实现相同：在快照的全部来源中查找所需地址，记录冲突的解码。

    来源顺序与总行数预算（MAX_LINKAGE_ROWS）与原实现一致；按 4096 行分段检查取消，
    每段内只做一次字典查找与集合成员判断。
    """
    def row_lists():
        yield result.metadata.get("full_disassembly", ())
        yield result.metadata.get("disassembly", ())
        for function in result.functions:
            for block in (function.get("blocks") or function.get("cfg", {}).get("blocks", ())):
                yield block.get("instructions", ())

    rows = {}
    conflicts = set()
    remaining = MAX_LINKAGE_ROWS
    checked = next_check = 0
    for source in row_lists():
        if remaining <= 0:
            break
        source = source if isinstance(source, (list, tuple)) else list(islice(source, remaining))
        for start in range(0, min(len(source), remaining), 4096):
            if is_cancelled is not None and checked >= next_check:
                next_check = checked + 4096
                if is_cancelled():
                    raise _Cancelled
            chunk = source[start:min(start + 4096, remaining)]
            checked += len(chunk)
            for row in chunk:
                address = row.get("addr")
                if address in wanted:
                    if address in rows and rows[address] != row:
                        conflicts.add(address)
                    else:
                        rows[address] = row
        remaining -= min(len(source), remaining)
    return rows, conflicts


def _number(token):
    match = _NUMBER.fullmatch(token.strip())
    if not match:
        return None
    value = int(match[2], 16 if match[2].lower().startswith("0x") else 10)
    return -value if match[1] else value


def _mnemonic(row):
    return " ".join(str(row.get("mnemonic", "")).lower().split())


def _branch(row):
    branch = row.get("branch_info")
    return branch if isinstance(branch, dict) else {}


def _x86_slot(row, word):
    """``jmp/call <width> ptr [rip ± d]`` 或 ``[abs]`` 的槽位地址；与 memory_references 交叉核对。"""
    operands = split_operands(row)
    if len(operands) != 1 or type(row.get("addr")) is not int or type(row.get("size")) is not int:
        return None
    match = _X86_MEMORY.fullmatch(operands[0].strip())
    if not match or match[1].lower() != ("qword" if word == 8 else "dword"):
        return None
    displacement = int(match[4], 16 if match[4].lower().startswith("0x") else 10)
    if match[2]:
        slot = row["addr"] + row["size"] + (displacement if match[3] == "+" else -displacement)
    else:
        slot = displacement
    slot &= (1 << (word * 8)) - 1
    references = (row.get("arch_meta") or {}).get("memory_references") if isinstance(row.get("arch_meta"), dict) else None
    if references and list(references) != [slot]:
        return None  # 解码器给出的有效地址与操作数文本不一致：不猜测
    return slot


def _x86_thunk_slot(rows, conflicts, target, word):
    """PLT/桩/IAT thunk：目标处是 ``jmp [slot]``，或 ``endbr`` 后紧跟 ``jmp [slot]``。"""
    first = rows.get(target)
    if first is None or target in conflicts:
        return None
    jump = first
    if _mnemonic(first) in {"endbr64", "endbr32"}:
        if first.get("size") != 4 or (target + 4) in conflicts:
            return None
        jump = rows.get(target + 4)
        if jump is None:
            return None
    branch = _branch(jump)
    if _mnemonic(jump) not in _X86_JUMPS or branch.get("kind") != "jump" or branch.get("target") is not None:
        return None
    return _x86_slot(jump, word)


def _a64_page(row, register):
    if _mnemonic(row) != "adrp" or row.get("size") != 4:
        return None
    operands = split_operands(row)
    if len(operands) != 2 or operands[0].lower() != register:
        return None
    page = _number(operands[1])
    return page if page is not None and page >= 0 and page % 4096 == 0 else None


def _a64_load(row, destination):
    """``ldr <destination>, [xB{, #off}]`` → (xB, off)；不接受前/后变址形式。"""
    if _mnemonic(row) != "ldr" or row.get("size") != 4:
        return None
    operands = split_operands(row)
    if len(operands) != 2 or operands[0].lower() != destination:
        return None
    match = re.fullmatch(r"\[(x(?:[0-9]|[12][0-9]|30))(?:,\s*(#?(?:0x[0-9a-f]+|[0-9]+)))?\]", operands[1].strip(), re.I)
    if not match:
        return None
    offset = _number(match[2]) if match[2] else 0
    if offset is None or offset < 0 or offset % 8:
        return None
    return match[1].lower(), offset


def _a64_add(row, register):
    """``add xR, xR, #lo`` → lo。"""
    if _mnemonic(row) != "add" or row.get("size") != 4:
        return None
    operands = [item.lower() for item in split_operands(row)]
    if len(operands) != 3 or operands[0] != register or operands[1] != register:
        return None
    value = _number(operands[2])
    return value if value is not None and 0 <= value <= 4095 else None


def _a64_stub_slot(rows, conflicts, target):
    """Mach-O arm64 桩 / PE ARM64 导入 thunk / Mach-O arm64e 认证桩。

    adrp x16, page ; ldr x16, [x16, #off] ; br x16
    adrp x17, page ; add x17, x17, #off ; ldr x16, [x17] ; braa x16, x17
    """
    sequence = [rows.get(target + offset) for offset in (0, 4, 8, 12)]
    if sequence[0] is None:
        return None
    if None not in sequence[:3] and not any(target + offset in conflicts for offset in (0, 4, 8)):
        page = _a64_page(sequence[0], "x16")
        load = _a64_load(sequence[1], "x16")
        branch = sequence[2]
        if (page is not None and load is not None and load[0] == "x16" and _mnemonic(branch) == "br"
                and [item.lower() for item in split_operands(branch)] == ["x16"]
                and _branch(branch).get("kind") == "jump" and branch.get("size") == 4):
            return page + load[1]
    if None not in sequence and not any(target + offset in conflicts for offset in (0, 4, 8, 12)):
        page = _a64_page(sequence[0], "x17")
        low = _a64_add(sequence[1], "x17")
        load = _a64_load(sequence[2], "x16")
        branch = sequence[3]
        if (page is not None and low is not None and load == ("x17", 0)
                and _mnemonic(branch) in {"braa", "brab"} and branch.get("size") == 4
                and [item.lower() for item in split_operands(branch)] == ["x16", "x17"]
                and _branch(branch).get("kind") == "jump"):
            return page + low
    return None


def _a64_register(token):
    token = token.strip().lower()
    match = _A64_REGISTER.fullmatch(token)
    return f"x{match[1]}" if match else None


def _a64_writes(row, register):
    writes = row.get("writes")
    if writes is not None:
        return any(_a64_register(str(item)) == register for item in writes)
    # 没有读写集时只按目的操作数保守判断：存储/比较/分支不写第一个操作数。
    mnemonic = _mnemonic(row)
    if mnemonic.startswith(("st", "cmp", "cmn", "tst", "b", "cb", "tb", "ret", "prfm", "nop")):
        return False
    operands = split_operands(row)
    # ldp/ldxp 等成对加载写前两个操作数。
    written = operands[:2] if mnemonic.startswith("ld") and mnemonic.endswith("p") else operands[:1]
    return any(_a64_register(item) == register for item in written)


def _a64_call_slot(rows, index):
    """``blr xN`` 前同一基本块内的 adrp/ldr（或 adrp/add/ldr）定义链 → 槽位地址。"""
    operands = split_operands(rows[index])
    if not operands:
        return None
    register = _a64_register(operands[0])
    if register is None:
        return None

    def definition(position, wanted):
        for back in range(position - 1, max(-1, position - 1 - MAX_BACKTRACK), -1):
            row = rows[back]
            if _branch(row).get("kind") in {"call", "jump", "return"}:
                return None, None  # 调用会破坏调用者保存寄存器；不跨越
            if _a64_writes(row, wanted):
                return back, row
        return None, None

    position, row = definition(index, register)
    if row is None:
        return None
    load = _a64_load(row, register)
    if load is None:
        return None
    base, offset = load
    position, row = definition(position, base)
    if row is None:
        return None
    page = _a64_page(row, base)
    if page is not None:
        return page + offset
    low = _a64_add(row, base)
    if low is None or offset:
        return None
    position, row = definition(position, base)
    page = None if row is None else _a64_page(row, base)
    return None if page is None else page + low


# ---------------------------------------------------------------------------
# 解析器
# ---------------------------------------------------------------------------

def _collect(result, is_cancelled, architecture, slots, accept=None, exclusive=False, linkage_code=None):
    """一次遍历收集直接调用/尾跳转目标，以及经指针槽位的间接调用点。

    accept(target) 为真的目标总是候选；exclusive 时只接受这些目标（Mach-O 桩由容器声明）。
    linkage_code(address) 为真的指令属于桩/PLT 自身，不计为调用点。
    """
    targets = set()
    sites = {}
    word = 4 if architecture == "x86" else 8

    def observe(local, rows, index, row):
        branch = _branch(row)
        kind = branch.get("kind")
        if kind not in {"call", "jump"}:
            return
        target = branch.get("target")
        if type(target) is int:
            # 已知的链接区域（Mach-O 桩、ELF PLT 节）内的目标无论调用还是（条件）尾跳转都是候选；
            # 其它目标只接受调用与离开本函数的无条件跳转。函数内分支很多，计入它们会挤占
            # MAX_LINKAGE_TARGETS 并漏掉真正的 thunk。
            if len(targets) < MAX_LINKAGE_TARGETS and (
                    (accept is not None and accept(target)) or
                    (not exclusive and (kind == "call" or not branch.get("conditional") and target not in local))):
                targets.add(target)
            return
        if target is not None or not slots:
            return
        mnemonic = _mnemonic(row)
        slot = None
        if architecture in {"x86", "x86_64"}:
            if mnemonic in _X86_CALLS or mnemonic in _X86_JUMPS:
                slot = _x86_slot(row, word)
        elif mnemonic in _A64_INDIRECT_CALLS or mnemonic in _A64_INDIRECT_JUMPS:
            slot = _a64_call_slot(rows, index)
        if (slot is not None and slots.get(slot) is not None and type(row.get("addr")) is int
                and not (linkage_code is not None and linkage_code(row["addr"]))):
            bucket = sites.setdefault(slot, set())
            if len(bucket) < MAX_CALL_SITES_PER_SLOT:
                bucket.add(row["addr"])

    _scan_rendered(result, is_cancelled, observe)
    return targets, sites


_LINKAGE_SECTIONS = frozenset({".plt", ".plt.sec", ".plt.got", ".plt.bnd", ".iplt"})


def _linkage_section_test(result, *, stub_types=False):
    """链接代码节的地址范围：ELF PLT 类节，或（stub_types）Mach-O S_SYMBOL_STUBS 节。

    只用于挑选候选与排除桩自身指令，命名证据仍来自 Loader 事实与指令快照。
    """
    ranges = []
    for section in result.metadata.get("sections", ()) or ():
        if not isinstance(section, dict):
            continue
        wanted = (section.get("section_type") == 0x8 if stub_types
                  else section.get("name") in _LINKAGE_SECTIONS)
        if (wanted and
                type(section.get("address")) is int and type(section.get("size")) is int and section["size"] > 0):
            ranges.append((section["address"], section["address"] + section["size"]))
    if not ranges:
        return None
    return lambda target: any(start <= target < end for start, end in ranges)


def _resolve_slots_and_thunks(result, is_cancelled, slots, stubs, architecture, source, candidates=None):
    if is_cancelled is not None and is_cancelled():
        return {}
    if not slots and not stubs:
        return {}
    x86 = architecture in {"x86", "x86_64"}
    word = 4 if architecture == "x86" else 8
    offsets = (0, 4) if x86 else (0, 4, 8, 12)
    if stubs:
        accept, exclusive = stubs.__contains__, True
        # 桩自身的 jmp/br 指令（含 arm64e 认证桩的 4 条指令）不是调用点。
        stub_code = {target + offset for target in stubs for offset in offsets}
        stub_sections = _linkage_section_test(result, stub_types=True)
        linkage_code = (lambda address: address in stub_code or
                        (stub_sections is not None and stub_sections(address)))
    else:
        accept, exclusive = _linkage_section_test(result), False
        linkage_code = accept
    if candidates is None:
        targets, sites = _collect(result, is_cancelled, architecture, slots, accept, exclusive, linkage_code)
    else:
        # 调用方给定候选地址（例如过程间分析需要的深层桩）：只核对这些地址，不收集调用点。
        targets, sites = {target for target in candidates if not exclusive or accept(target)}, {}
    # Mach-O 桩由容器声明，只需核对被调用的桩；PE/ELF 的 thunk 必须由快照证明。
    candidates = sorted(targets)
    rows, conflicts = _index_rows(result, {target + offset for target in candidates for offset in offsets},
                                  is_cancelled) if candidates else ({}, set())
    matched = {}
    for target in candidates:
        if len(matched) >= MAX_LINKAGE_TARGETS:
            break
        if target in conflicts:
            continue  # 同一地址存在互相矛盾的解码：不命名
        slot = _x86_thunk_slot(rows, conflicts, target, word) if x86 else _a64_stub_slot(rows, conflicts, target)
        if stubs:
            declared = stubs.get(target)
            if declared is None:
                continue  # 歧义的桩声明
            if slot is not None:
                observed = slots.get(slot)
                if observed is None or observed["name"] != declared["name"]:
                    continue  # 桩实际读取的槽位与容器声明不符：拒绝
                evidence = f"{source}_and_completed_stub_snapshot"
            else:
                # 桩指令不在快照中或不是已知形状：间接符号表本身就是容器对“桩 → 符号”的声明。
                evidence = source
            matched[target] = {**declared, "target": target, "target_kind": "linkage_thunk",
                               "slot_address": slot, "evidence": evidence,
                               "runtime_binding": _RUNTIME_BINDING}
        elif slot is not None and slots.get(slot) is not None:
            matched[target] = {**slots[slot], "target": target, "target_kind": "linkage_thunk",
                               "slot_address": slot,
                               "evidence": f"{source}_and_completed_thunk_snapshot",
                               "runtime_binding": _RUNTIME_BINDING}
    _drop_thunk_sites(sites, matched, offsets)
    for slot in sorted(sites):
        if len(matched) >= MAX_LINKAGE_TARGETS:
            break
        if slot in matched or slots.get(slot) is None:
            continue
        matched[slot] = {**slots[slot], "target": slot, "target_kind": "import_pointer_slot",
                         "slot_address": slot, "call_sites": sorted(sites[slot]),
                         "evidence": f"{source}_and_completed_call_site_snapshot",
                         "runtime_binding": _RUNTIME_BINDING}
    return dict(sorted(matched.items()))


def _drop_thunk_sites(sites, matched, offsets):
    """thunk/桩自身的 ``jmp [slot]`` 已由 linkage_thunk 证据覆盖，不再重复记为调用点。"""
    covered = {target + offset for target, item in matched.items()
               if item.get("target_kind") == "linkage_thunk" for offset in offsets}
    for slot in list(sites):
        sites[slot] -= covered
        if not sites[slot]:
            del sites[slot]


def _resolve_elf_a64(result, is_cancelled):
    matched = _resolve_elf_a64_plt(result, is_cancelled)
    if matched is None:
        return {}
    slots = _elf_slots(result, "arm64")
    if slots and any(value is not None for value in slots.values()):
        plt = _linkage_section_test(result)
        _targets, sites = _collect(result, is_cancelled, "arm64", slots, linkage_code=plt)
        _drop_thunk_sites(sites, matched, (0, 4, 8, 12))
        for slot in sorted(sites):
            if len(matched) >= MAX_LINKAGE_TARGETS:
                break
            if slot in matched or slots.get(slot) is None:
                continue
            matched[slot] = {**slots[slot], "target": slot, "target_kind": "import_pointer_slot",
                             "slot_address": slot, "call_sites": sorted(sites[slot]),
                             "evidence": "loader_relocation_and_completed_call_site_snapshot",
                             "runtime_binding": _RUNTIME_BINDING}
    return matched


def _resolve_elf_a64_plt(result, is_cancelled, candidates=None):
    """原有 ELF arm64 PLT 识别，逻辑保持不变；取消时返回 None。

    candidates（可选）：直接给定要核对的地址，代替从前 128 个函数收集的调用目标。
    """
    relocations = {}
    for item in islice(result.metadata.get("dynamic_relocations", ()), 10000):
        if item.get("type") == 1026 and isinstance(item.get("address"), int) and item.get("symbol_name"):
            if item["address"] in relocations and relocations[item["address"]] != item:
                relocations[item["address"]] = None
            else:
                relocations[item["address"]] = item
    if not relocations:
        return {}
    if candidates is not None:
        candidates = {target for target in candidates if type(target) is int}
    else:
        candidates = _a64_call_targets(result)
    return _match_a64_plt(result, is_cancelled, relocations, candidates)


def _a64_call_targets(result):
    """前 128 个函数（每个至多 512 条指令）的直接调用/跳转目标（原有候选范围）。"""
    candidates = set()
    for function in result.functions[:128]:
        blocks = function.get("blocks") or function.get("cfg", {}).get("blocks", ())
        rows = (row for block in blocks for row in block.get("instructions", ())) if blocks else function.get("disassembly", ())
        for row in islice(rows, 512):
            branch = row.get("branch_info", {})
            target = branch.get("target")
            if branch.get("kind") in {"call", "jump"} and type(target) is int:
                candidates.add(target)
                if len(candidates) == MAX_LINKAGE_TARGETS:
                    break
        if len(candidates) == MAX_LINKAGE_TARGETS:
            break
    return candidates


def _match_a64_plt(result, is_cancelled, relocations, candidates):
    wanted = {target + offset for target in candidates for offset in (0, 4, 8, 12)}
    function_rows = (row for function in result.functions for block in
                     (function.get("blocks") or function.get("cfg", {}).get("blocks", ()))
                     for row in block.get("instructions", ()))
    source = chain(result.metadata.get("full_disassembly", ()), result.metadata.get("disassembly", ()), function_rows)
    rows = {}
    conflicts = set()
    for index, row in enumerate(islice(source, MAX_LINKAGE_ROWS)):
        if index % 4096 == 0 and is_cancelled is not None and is_cancelled():
            return None
        address = row.get("addr")
        if address in wanted:
            if address in rows and rows[address] != row:
                conflicts.add(address)
            else:
                rows[address] = row
    matched = {}
    for target in sorted(candidates):
        sequence = [rows.get(target + offset) for offset in (0, 4, 8, 12)]
        if any(row is None or row.get("size") != 4 or row["addr"] in conflicts for row in sequence):
            continue
        if [str(row.get("mnemonic", "")).lower() for row in sequence] != ["adrp", "ldr", "add", "br"]:
            continue
        page_args, load_args, add_args, branch_args = map(split_operands, sequence)
        if len(page_args) != 2 or page_args[0].lower() != "x16" or len(load_args) != 2 or load_args[0].lower() != "x17":
            continue
        page = re.fullmatch(r"#?(0x[0-9a-f]+|[0-9]+)", page_args[1], re.I)
        slot = re.fullmatch(r"\[x16(?:,\s*#?(0x[0-9a-f]+|[0-9]+))?\]", load_args[1], re.I)
        if not page or not slot or len(add_args) != 3 or [arg.lower() for arg in add_args[:2]] != ["x16", "x16"] or branch_args != ["x17"]:
            continue
        offset_token = slot[1] or "0"
        try:
            page_value = int(page[1], 16 if page[1].lower().startswith("0x") else 10)
            offset = int(offset_token, 16 if offset_token.lower().startswith("0x") else 10)
            add_token = add_args[2].removeprefix("#")
            addition = int(add_token, 16 if add_token.lower().startswith("0x") else 10)
        except ValueError:
            continue
        if page_value % 4096 or not 0 <= page_value < 1 << 64 or offset != addition or offset % 8 or not 0 <= offset <= 4095:
            continue
        relocation = relocations.get(page_value + offset)
        if relocation:
            matched[target] = {"name": relocation["symbol_name"], "target": target,
                "symbol_value": relocation.get("symbol_value"), "got_address": page_value + offset,
                "evidence": "loader_relocation_and_completed_a64_plt_snapshot",
                "runtime_binding": "dynamic_and_possibly_preemptible",
                # 新增字段（只增不删）：与其它格式统一的显示名、目标种类与槽位。
                "display_name": relocation["symbol_name"], "target_kind": "linkage_thunk",
                "slot_address": page_value + offset}
    return matched
