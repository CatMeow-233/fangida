"""Thin and universal Mach-O container headers, address mapping and symbol tables.

符号层只读取容器自身声明的事实：LC_SYMTAB（nlist/nlist_64 与字符串表）、
LC_DYSYMTAB 的间接符号表、LC_FUNCTION_STARTS 以及 LC_LOAD_DYLIB 系列命令。
这里不解码任何指令、不分析交叉引用；所有表、偏移与字符串都在输入切片内做边界
检查，畸形的可选元数据只产生警告，不会让主容器解析失败。
"""
from __future__ import annotations

import struct
from typing import Any

from .common import MAX_SECTIONS, MAX_SYMBOLS, _unpack
from .models import BinaryFormatError, BinaryImage
from .interfaces import LoaderMatch

THIN_MAGIC = frozenset({b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                        b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"})
FAT_MAGIC = frozenset({b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                       b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"})
MAX_FAT_ARCHITECTURES = 64
_INSTRUCTION_ATTRIBUTES = 0x80000000 | 0x00000400  # PURE / SOME_INSTRUCTIONS
_SYMBOL_STUBS = 0x8
_VM_PROT_EXECUTE = 0x4
_VM_PROT_READ = 0x1
_VM_PROT_WRITE = 0x2
# S_ZEROFILL, S_GB_ZEROFILL and S_THREAD_LOCAL_ZEROFILL describe memory extent
# without corresponding file bytes.
_ZEROFILL_TYPES = frozenset({0x1, 0xC, 0x12})
# 这些节类型按定义只保存字面量、指针、偏移或 TLV 描述，即使带指令属性也不是代码。
# 只排除已知的数据类型：未知的新类型仍按属性判断，避免新工具链的代码节被静默丢弃。
_DATA_ONLY_TYPES = _ZEROFILL_TYPES | frozenset({
    0x2, 0x3, 0x4, 0x5,             # CSTRING/4BYTE/8BYTE_LITERALS, LITERAL_POINTERS
    0x6, 0x7, 0x9, 0xA,             # (NON_)LAZY_SYMBOL_POINTERS, MOD_INIT/TERM_FUNC_POINTERS
    0xD, 0xE, 0xF, 0x10,            # INTERPOSING, 16BYTE_LITERALS, DTRACE_DOF, LAZY_DYLIB pointers
    0x11, 0x13, 0x14, 0x15, 0x16})  # THREAD_LOCAL_* data/pointers, INIT_FUNC_OFFSETS


# ---- 符号表相关常量（mach-o/loader.h 与 mach-o/nlist.h） ----
_LC_SYMTAB = 0x2
_LC_DYSYMTAB = 0xB
_LC_FUNCTION_STARTS = 0x26
# LC_LOAD_DYLIB、LC_LOAD_WEAK_DYLIB、LC_REEXPORT_DYLIB、LC_LAZY_LOAD_DYLIB、LC_LOAD_UPWARD_DYLIB：
# 两级命名空间的库序号按这些命令出现的顺序从 1 开始编号。
_DYLIB_COMMANDS = frozenset({0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023})
_MH_OBJECT = 0x1
_MH_TWOLEVEL = 0x80
_N_STAB, _N_PEXT, _N_TYPE, _N_EXT = 0xE0, 0x10, 0x0E, 0x01
_N_UNDF, _N_ABS, _N_SECT, _N_PBUD = 0x0, 0x2, 0xE, 0xC
_N_WEAK_REF, _N_WEAK_DEF, _N_ARM_THUMB_DEF = 0x40, 0x80, 0x8
_INDIRECT_SYMBOL_LOCAL, _INDIRECT_SYMBOL_ABS = 0x80000000, 0x40000000
# 由间接符号表逐项索引的节类型：桩（S_SYMBOL_STUBS）与各类符号指针节。
_POINTER_SECTION_TYPES = {0x6: "non_lazy_pointer", 0x7: "lazy_pointer",
                          0x10: "lazy_dylib_pointer", 0x14: "thread_local_pointer"}
_SPECIAL_LIBRARY_ORDINALS = {0x0: "<self>", 0xFE: "<executable>", 0xFF: "<dynamic lookup>"}
MAX_SYMBOL_RECORDS = 262144      # 单个 LC_SYMTAB 最多扫描的 nlist 记录数（含调试 STAB 记录）
MAX_INDIRECT_SYMBOLS = 65536     # 间接符号表最多展开的条目数
MAX_FUNCTION_STARTS = 262144     # LC_FUNCTION_STARTS 最多解码的起点数
MAX_DYLIBS = 4096
MAX_SYMBOL_NAME_BYTES = 1024


def _declares_instructions(name: str, flags: int) -> bool:
    """按节类型与属性判断节内容是否为指令；段权限由调用方另行检查。"""
    section_type = flags & 0xFF
    if section_type in _DATA_ONLY_TYPES:
        return False
    # S_SYMBOL_STUBS（__stubs/__auth_stubs/__jump_table）按定义就是桩代码，旧工具链可能
    # 不写属性；手写或极简样本的 __text 常把 flags 留为 0，保留把它当代码的历史行为。
    return (bool(flags & _INSTRUCTION_ATTRIBUTES) or section_type == _SYMBOL_STUBS
            or (name == "__text" and flags == 0))


def _text(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def _macho(data: bytes) -> BinaryImage:
    """解析 thin Mach-O 容器；符号表中的命名函数写入 image.functions。"""
    image, layout = _macho_parse(data)
    try:
        table = _symbol_layer(data, image, layout)
    except (BinaryFormatError, struct.error) as exc:  # 可选元数据畸形：只告警，不影响容器结构
        image.warnings.append(f"Mach-O symbol table unavailable: {exc}")
    else:
        image.functions = table["functions"]
        image.warnings.extend(table["warnings"])
    return image


def _macho_parse(data: bytes) -> tuple[BinaryImage, dict[str, Any]]:
    """解析一个 thin Mach-O：返回镜像与符号层所需的加载命令布局（不含指令分析）。"""
    magic = bytes(data[:4])
    endian = "little" if magic in {b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"} else "big"
    bits = 64 if magic in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"} else 32
    order = "<" if endian == "little" else ">"
    header_size = 32 if bits == 64 else 28
    (_magic, cputype, _subtype, filetype, ncmds, cmdsize, header_flags) = _unpack(data, 0, order + "IIIIIII")
    if bits == 64:
        _unpack(data, 28, order + "I")
    arch = {0x01000007: "x86_64", 0x0100000c: "arm64", 7: "x86", 12: "arm"}.get(cputype, f"macho-cpu-{cputype}")
    image = BinaryImage("macho", arch, bits, endian)
    # 符号层布局：只记录加载命令中的偏移/计数，真正的表在 _symbol_layer 中按需有界读取。
    layout: dict[str, Any] = {"order": order, "bits": bits, "filetype": filetype,
                              "flags": header_flags, "symtab": None, "dysymtab": None,
                              "function_starts": None, "dylibs": [], "ordinals": [],
                              "ordinals_complete": True, "text_vmaddr": None}
    if ncmds > MAX_SECTIONS or cmdsize > len(data) - header_size:
        image.warnings.append("Mach-O load commands exceed scan budget or safety limits")
        return image, layout
    cursor = header_size
    entryoff: int | None = None
    segments: list[tuple[int, int, int]] = []
    ordinals: list[tuple[dict[str, Any], int, int]] = layout["ordinals"]
    for i in range(ncmds):
        if cursor + 8 > len(data):
            image.warnings.append("Truncated Mach-O load command")
            break
        cmd, length = _unpack(data, cursor, order + "II")
        if length < 8 or length > len(data) - cursor or cursor + length > header_size + cmdsize:
            image.warnings.append("Malformed Mach-O load command length")
            break
        if cmd == 0x80000028 and length >= 24:
            entryoff, _stacksize = _unpack(data, cursor + 8, order + "QQ")
        elif cmd == _LC_SYMTAB and length >= 24:
            # symtab_command: symoff, nsyms, stroff, strsize（相对当前切片的文件偏移）
            layout["symtab"] = _unpack(data, cursor + 8, order + "IIII")
        elif cmd == _LC_DYSYMTAB and length >= 80:
            # dysymtab_command 的 18 个 uint32：局部/外部定义/未定义符号区间与间接符号表等
            layout["dysymtab"] = _unpack(data, cursor + 8, order + "I" * 18)
        elif cmd == _LC_FUNCTION_STARTS and length >= 16:
            layout["function_starts"] = _unpack(data, cursor + 8, order + "II")
        elif cmd in _DYLIB_COMMANDS and length >= 24 and len(layout["dylibs"]) < MAX_DYLIBS:
            # dylib_command.name 是相对命令起点的 lc_str 偏移，字符串必须位于命令内部
            name_offset, = _unpack(data, cursor + 8, order + "I")
            name = _text(data[cursor + name_offset:cursor + length]) if 24 <= name_offset < length else ""
            layout["dylibs"].append(name or None)
        if (bits == 64 and cmd == 0x19 and length >= 72) or (bits == 32 and cmd == 1 and length >= 56):
            if bits == 64:
                vmaddr, _vmsize, fileoff, filesize = _unpack(data, cursor + 24, order + "QQQQ")
                nsects, = _unpack(data, cursor + 64, order + "I")
                base, stride, fmt = 72, 80, order + "16s16sQQIIIIIIII"
            else:
                vmaddr, _vmsize, fileoff, filesize = _unpack(data, cursor + 24, order + "IIII")
                nsects, = _unpack(data, cursor + 48, order + "I")
                base, stride, fmt = 56, 68, order + "16s16sIIIIIIIII"
            initprot, = _unpack(data, cursor + (60 if bits == 64 else 44), order + "I")
            segment_executable = bool(initprot & _VM_PROT_EXECUTE)
            segments.append((fileoff, filesize, vmaddr))
            if layout["text_vmaddr"] is None and _text(bytes(data[cursor + 8:cursor + 24])) == "__TEXT":
                layout["text_vmaddr"] = vmaddr  # LC_FUNCTION_STARTS 的第一个增量相对 __TEXT 段起点
            if nsects > MAX_SECTIONS or base + nsects * stride > length:
                image.warnings.append(f"Segment {i} has a truncated section table")
                # nlist.n_sect 是全部节按加载命令顺序的 1 基序号；缺失一个节表后其后序号不再可信。
                layout["ordinals_complete"] = False
            else:
                # 代码区域只来自节表。无节段（nsects == 0）即使可执行也不产生区域：真实语料中
                # 只有 MH_FILESET 内核集合含这种段，其内容是内嵌的完整 Mach-O 镜像（头、
                # __cstring/__const/__os_log 等数据与代码混排），整段按代码解码既错误又会
                # 让 full 模式耗费数 GB 内存。子镜像节表（LC_FILESET_ENTRY）目前不展开。
                for j in range(nsects):
                    section = _unpack(data, cursor + base + j * stride, fmt)
                    name = _text(section[0])
                    address, size, offset = section[2:5]
                    section_flags = section[8]
                    section_type = section_flags & 0xFF
                    file_backed = (section_type not in _ZEROFILL_TYPES
                                   and fileoff <= offset < fileoff + filesize)
                    stored = min(size, fileoff + filesize - offset) if file_backed else 0
                    # initprot 只说明页可执行：__TEXT 内的 __const/__cstring/__unwind_info/
                    # __eh_frame 等数据节同样位于 r-x 段。只有段可执行、节声明含指令且有
                    # 文件字节时才是代码区域；semantic/translator 直接按 offset/size 读文件，
                    # 不能把没有文件内容的节交给它们。
                    executable = (segment_executable and file_backed
                                  and _declares_instructions(name, section_flags))
                    record = {"name": name or f"section_{j}", "address": address,
                              "offset": offset, "size": size, "type": "MACHO_SECTION",
                              "section_flags": section_flags,
                              "file_backed": file_backed, "file_size": stored,
                              "executable": executable,
                              "readable": bool(initprot & _VM_PROT_READ),
                              "writable": bool(initprot & _VM_PROT_WRITE),
                              "permissions_source": "segment",
                              # 新增字段：节所属段、段权限与 flags 的类型/属性拆分。
                              "segment": _text(section[1]),
                              "segment_executable": segment_executable,
                              "section_type": section_type,
                              "section_attributes": section_flags & 0xFFFFFF00}
                    reserved1, reserved2 = section[9], section[10]
                    if section_type == _SYMBOL_STUBS or section_type in _POINTER_SECTION_TYPES:
                        # 新增字段：桩/符号指针节在间接符号表中的起始下标与每项字节数。
                        record["indirect_symbol_index"] = reserved1
                        record["indirect_entry_size"] = (reserved2 if section_type == _SYMBOL_STUBS
                                                         else bits // 8)
                    image.sections.append(record)
                    if layout["ordinals_complete"] and len(ordinals) < 255:
                        ordinals.append((record, reserved1, reserved2))
        cursor += length
    if entryoff is not None:
        image.entry_offset = entryoff
        for fileoff, filesize, vmaddr in segments:
            if fileoff <= entryoff < fileoff + filesize:
                image.entry_address = vmaddr + entryoff - fileoff
                break
        if image.entry_address is None:
            image.warnings.append("Mach-O entry offset does not map to a segment")
    else:
        image.warnings.append("No LC_MAIN entry point (older LC_UNIXTHREAD is not decoded)")
    return image, layout


def display_symbol_name(name: str) -> str:
    """Mach-O C 符号带一个前导下划线；显示名去掉它（_main → main，__Z3foov → _Z3foov）。"""
    return name[1:] if len(name) > 1 and name[0] == "_" else name


def _symbol_layer(data: bytes, image: BinaryImage, layout: dict[str, Any]) -> dict[str, Any]:
    """读取 LC_SYMTAB/LC_DYSYMTAB/LC_FUNCTION_STARTS，返回命名函数、导入、导出与间接符号项。

    返回字典的键：
      functions — 定义在可执行节中的 N_SECT 符号（与 ELF 的 symtab 函数格式一致）；
      imports / exports — 供 kkagent.symbols.parse_symbols 使用的导入/导出记录；
      indirect — 桩与符号指针节的逐项映射（地址 → 符号名），只含有名字的项；
      warnings — 加载器级警告；symbol_warnings — 导入/导出列表自身的截断警告。
    """
    order, bits = layout["order"], layout["bits"]
    result: dict[str, Any] = {"functions": [], "imports": [], "exports": [], "indirect": [],
                              "warnings": [], "symbol_warnings": []}
    warnings: list[str] = result["warnings"]
    symtab = layout["symtab"]
    if symtab is None:
        return result
    symoff, nsyms, stroff, strsize = symtab
    if stroff > len(data):
        warnings.append("Mach-O string table exceeds scan budget")
        return result
    if strsize > len(data) - stroff:
        # 扫描前缀截断了字符串表：保留可读部分，越界或未终止的名字按空名跳过。
        warnings.append("Mach-O string table exceeds scan budget")
        strsize = len(data) - stroff
    strings = bytes(data[stroff:stroff + strsize])
    entry_size = 16 if bits == 64 else 12
    available = 0 if symoff > len(data) else min(nsyms, (len(data) - symoff) // entry_size)
    if available < nsyms:
        warnings.append("Mach-O symbol table exceeds scan budget")
    if available > MAX_SYMBOL_RECORDS:
        warnings.append(f"Mach-O symbol table capped at {MAX_SYMBOL_RECORDS} records")
        available = MAX_SYMBOL_RECORDS
    # nlist_64: n_strx, n_type, n_sect, n_desc, n_value；32 位版本的 n_value 为 uint32。
    record_format = order + ("IBBHQ" if bits == 64 else "IBBHI")
    records = list(struct.iter_unpack(record_format, data[symoff:symoff + available * entry_size]))
    names: dict[int, str] = {}

    def symbol_name(index: int) -> str:
        """按需解码并缓存名字；越界或未终止的名字视为空串。"""
        cached = names.get(index)
        if cached is not None:
            return cached
        offset = records[index][0]
        text = ""
        if 0 < offset < len(strings):
            end = strings.find(b"\0", offset, offset + MAX_SYMBOL_NAME_BYTES + 1)
            if end > offset:
                text = strings[offset:end].decode("utf-8", "replace")
        names[index] = text
        return text

    ordinals = layout["ordinals"]
    dylibs = layout["dylibs"]
    twolevel = bool(layout["flags"] & _MH_TWOLEVEL)

    def library(desc: int) -> tuple[str | None, int | None]:
        if not twolevel:
            return None, None
        ordinal = (desc >> 8) & 0xFF
        if ordinal in _SPECIAL_LIBRARY_ORDINALS:
            return _SPECIAL_LIBRARY_ORDINALS[ordinal], ordinal
        return (dylibs[ordinal - 1] if ordinal <= len(dylibs) else None), ordinal

    def defining_section(n_sect: int, value: int) -> dict[str, Any] | None:
        if not 1 <= n_sect <= len(ordinals):
            return None
        section = ordinals[n_sect - 1][0]
        start, size = section.get("address"), section.get("size")
        if type(start) is not int or type(size) is not int or not start <= value < start + size:
            return None
        return section

    # ---- 1. 定义在可执行节中的函数符号 ----
    function_symbols: list[tuple[int, str, int, dict[str, Any], int]] = []
    exports = result["exports"]
    export_capped = False
    for index, (_strx, n_type, n_sect, n_desc, value) in enumerate(records):
        if n_type & _N_STAB:
            continue  # 调试 STAB 记录不是符号定义
        kind = n_type & _N_TYPE
        external = bool(n_type & _N_EXT) and not n_type & _N_PEXT
        if kind == _N_SECT:
            section = defining_section(n_sect, value)
            is_code = section is not None and bool(section.get("executable"))
            if is_code:
                name = symbol_name(index)
                # l/L 前缀是汇编器/链接器私有标签（如 ltmp0），不是函数名。
                if name and not (name[0] in "lL" and not n_type & _N_EXT):
                    function_symbols.append((value, name, n_desc, section, n_type))
            if external:
                if len(exports) >= MAX_SYMBOLS:
                    export_capped = True
                    continue
                name = symbol_name(index)
                if name:
                    exports.append({"name": name, "display_name": display_symbol_name(name),
                                    "address": value, "source": "macho-export",
                                    "kind": "function" if is_code else "object",
                                    "weak": bool(n_desc & _N_WEAK_DEF)})
        elif kind == _N_ABS and external:
            name = symbol_name(index)
            if name and len(exports) < MAX_SYMBOLS:
                exports.append({"name": name, "display_name": display_symbol_name(name),
                                "address": value, "source": "macho-export",
                                "kind": "absolute", "weak": bool(n_desc & _N_WEAK_DEF)})
            elif name:
                export_capped = True
    if export_capped:
        result["symbol_warnings"].append(f"Mach-O exports capped at {MAX_SYMBOLS} entries")
    if len(function_symbols) > MAX_SYMBOLS:
        warnings.append(f"Mach-O function symbols capped at {MAX_SYMBOLS} entries")
        function_symbols.sort(key=lambda item: (item[0], item[1]))
        del function_symbols[MAX_SYMBOLS:]
    result["functions"] = _function_records(data, layout, image, function_symbols, warnings)

    # ---- 2. 间接符号表：桩与符号指针节的逐项映射 ----
    dysymtab = layout["dysymtab"]
    stubs: dict[int, list[int]] = {}
    pointers: dict[int, list[int]] = {}
    indirect = result["indirect"]
    if dysymtab is not None:
        indirect_offset, indirect_count = dysymtab[12], dysymtab[13]
        if indirect_offset > len(data) or indirect_count > (len(data) - indirect_offset) // 4:
            warnings.append("Mach-O indirect symbol table exceeds scan budget")
            indirect_count = max(0, (len(data) - indirect_offset) // 4) if indirect_offset <= len(data) else 0
        expanded = 0
        for section, reserved1, _reserved2 in ordinals:
            section_type = section.get("section_type")
            entry = section.get("indirect_entry_size")
            if type(entry) is not int or entry <= 0 or type(section.get("size")) is not int:
                continue
            count = section["size"] // entry
            if reserved1 >= indirect_count:
                if count:
                    warnings.append(f"Mach-O section {section['name']} indirect symbols exceed table")
                continue
            if count > indirect_count - reserved1:
                warnings.append(f"Mach-O section {section['name']} indirect symbols exceed table")
                count = indirect_count - reserved1
            if expanded + count > MAX_INDIRECT_SYMBOLS:
                warnings.append(f"Mach-O indirect symbols capped at {MAX_INDIRECT_SYMBOLS} entries")
                count = max(0, MAX_INDIRECT_SYMBOLS - expanded)
            expanded += count
            values = struct.unpack_from(f"{order}{count}I", data, indirect_offset + 4 * reserved1) if count else ()
            is_stub = section_type == _SYMBOL_STUBS
            for position, symbol_index in enumerate(values):
                if symbol_index & (_INDIRECT_SYMBOL_LOCAL | _INDIRECT_SYMBOL_ABS) or symbol_index >= len(records):
                    continue
                name = symbol_name(symbol_index)
                if not name:
                    continue
                address = section["address"] + position * entry
                (stubs if is_stub else pointers).setdefault(symbol_index, []).append(address)
                indirect.append({"address": address, "name": name, "symbol_index": symbol_index,
                                 "section": section["name"],
                                 "kind": "stub" if is_stub else _POINTER_SECTION_TYPES[section_type]})

    # ---- 3. 导入：未定义的外部符号（附带桩与指针槽位地址） ----
    imports = result["imports"]
    if dysymtab is not None and dysymtab[5]:
        first, count = dysymtab[4], dysymtab[5]
        candidates = range(min(first, len(records)), min(first + count, len(records)))
    else:
        candidates = range(len(records))
    for index in candidates:
        _strx, n_type, _n_sect, n_desc, value = records[index]
        if n_type & _N_STAB or not n_type & _N_EXT or n_type & _N_TYPE not in (_N_UNDF, _N_PBUD):
            continue
        if n_type & _N_TYPE == _N_UNDF and value:
            continue  # 公共符号（common）由链接器分配，不是外部导入
        name = symbol_name(index)
        if not name:
            continue
        if len(imports) >= MAX_SYMBOLS:
            result["symbol_warnings"].append(f"Mach-O imports capped at {MAX_SYMBOLS} entries")
            break
        library_name, ordinal = library(n_desc)
        stub_addresses = stubs.get(index, [])
        pointer_addresses = pointers.get(index, [])
        imports.append({"name": name, "display_name": display_symbol_name(name),
                        "library": library_name, "library_ordinal": ordinal,
                        "address": pointer_addresses[0] if pointer_addresses else None,
                        "stub_address": stub_addresses[0] if stub_addresses else None,
                        "stub_addresses": stub_addresses, "pointer_addresses": pointer_addresses,
                        "source": "macho-import",
                        "kind": "function" if stub_addresses else "notype",
                        "weak": bool(n_desc & _N_WEAK_REF)})
    return result


def _function_starts(data: bytes, layout: dict[str, Any], warnings: list[str]) -> list[int]:
    """解码 LC_FUNCTION_STARTS 的 ULEB128 增量序列（第一个增量相对 __TEXT 段起点）。"""
    descriptor, base = layout["function_starts"], layout["text_vmaddr"]
    if descriptor is None or base is None:
        return []
    offset, size = descriptor
    if offset > len(data) or size > len(data) - offset:
        warnings.append("Mach-O function starts exceed scan budget")
        return []
    raw = bytes(data[offset:offset + size])
    starts: list[int] = []
    address, value, shift = base, 0, 0
    for byte in raw:
        value |= (byte & 0x7F) << shift
        if byte & 0x80:
            shift += 7
            if shift > 63:
                warnings.append("Mach-O function starts contain an overlong ULEB128 value")
                return starts
            continue
        if value == 0:
            break  # 0 增量终止序列，其后是对齐填充
        address += value
        starts.append(address)
        value, shift = 0, 0
        if len(starts) >= MAX_FUNCTION_STARTS:
            warnings.append(f"Mach-O function starts capped at {MAX_FUNCTION_STARTS} entries")
            break
    return starts


def _function_records(data: bytes, layout: dict[str, Any], image: BinaryImage,
                      symbols: list[tuple[int, str, int, dict[str, Any], int]],
                      warnings: list[str]) -> list[dict[str, Any]]:
    """把函数符号转换为 image.functions 记录，并在有可靠依据时推断大小。

    大小规则（宁可未知也不猜错：过大的范围会让完整分析把其后未命名函数并入）：
      * 有 LC_FUNCTION_STARTS：到下一个函数起点（或节尾）为止——它覆盖所有函数，含无符号函数；
      * MH_OBJECT（目标文件不剥离局部符号）：到同节下一个符号（或节尾）为止；
      * 其它情况（可能剥离了局部符号）：None。
    """
    if not symbols:
        return []
    from bisect import bisect_right
    thumb_mask = ~1 if image.architecture == "arm" else ~0
    starts = sorted({address & thumb_mask for address in _function_starts(data, layout, warnings)})
    size_source = "function_starts" if starts else (
        "next_symbol" if layout["filetype"] == _MH_OBJECT else None)
    by_section: dict[int, list[int]] = {}
    if size_source == "next_symbol":
        for value, _name, _desc, section, _type in symbols:
            by_section.setdefault(id(section), []).append(value)
        for values in by_section.values():
            values.sort()
    functions: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for value, name, desc, section, n_type in symbols:
        if (value, name) in seen:
            continue
        seen.add((value, name))
        end = section["address"] + section["size"]
        size: int | None = None
        if size_source is not None:
            boundaries = starts if size_source == "function_starts" else by_section[id(section)]
            position = bisect_right(boundaries, value)
            following = boundaries[position] if position < len(boundaries) else end
            size = min(following, end) - value
            if size <= 0:
                size = None
        record: dict[str, Any] = {"name": name, "display_name": display_symbol_name(name),
                                  "start": value, "size": size, "source": "symtab",
                                  "size_source": size_source if size is not None else None,
                                  "blocks": [], "cfg": {"edges": []},
                                  "xrefs_in": [], "xrefs_out": []}
        if image.architecture == "arm" and desc & _N_ARM_THUMB_DEF:
            record["thumb"] = True
        if not n_type & _N_EXT:
            record["local"] = True
        functions.append(record)
    # 按地址排序（与 ELF 一致），但 LC_MAIN 声明的入口函数排在最前：有界语义分析按此顺序
    # 取种子，符号很多的程序也能先完整分析 main，而不是在预算耗尽后只剩入口窗口。
    entry = image.entry_address
    functions.sort(key=lambda function: (function["start"] != entry, function["start"], function["name"]))
    return functions


def _select_fat_slice(data: bytes) -> tuple[int, int, int, int]:
    """按既有优先级选择胖文件切片：返回 (下标, 架构数, 切片偏移, 切片大小)。"""
    magic = bytes(data[:4])
    order = ">" if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"} else "<"
    fat64 = magic in {b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"}
    count, = _unpack(data, 4, order + "I")
    if not 1 <= count <= MAX_FAT_ARCHITECTURES:
        raise BinaryFormatError("Invalid fat Mach-O architecture count")
    stride = 32 if fat64 else 20
    if 8 + count * stride > len(data):
        raise BinaryFormatError("Fat Mach-O architecture table exceeds scan budget")
    candidates: list[tuple[int, int, int, int]] = []
    for index in range(count):
        values = _unpack(data, 8 + index * stride, order + ("IIQQII" if fat64 else "IIIII"))
        cpu, _subtype, offset, size = values[:4]
        if offset > len(data) or size > len(data) - offset:
            continue
        priority = {0x0100000c: 0, 0x01000007: 1, 12: 2, 7: 3}.get(cpu, 4)
        candidates.append((priority, index, offset, size))
    if not candidates:
        raise BinaryFormatError("No fat Mach-O slice is within scan budget")
    _, index, offset, size = min(candidates)
    return index, count, offset, size


def _fat_macho(data: bytes) -> BinaryImage:
    """Select one file-backed architecture from a universal Mach-O container."""
    index, count, offset, size = _select_fat_slice(data)
    image = _macho(data[offset:offset + size])
    image.fat_slice_offset = offset
    if image.entry_offset is not None:
        image.entry_offset += offset
    for section in image.sections:
        section["offset"] += offset
    image.warnings.append(f"Selected fat Mach-O slice {index} of {count}")
    return image


def read_macho_symbols(data: bytes) -> dict[str, Any]:
    """读取 Mach-O（含胖文件中与加载器相同的切片）的符号层事实。

    返回 _symbol_layer 的字典（functions/imports/exports/indirect/warnings/
    symbol_warnings）以及 "fat_slice_offset"。所有地址都是虚拟地址，不依赖切片偏移；
    只解析容器表，不解码指令。非 Mach-O 输入或畸形头抛出 BinaryFormatError。
    """
    magic = bytes(data[:4])
    slice_offset = None
    if magic in FAT_MAGIC:
        _index, _count, slice_offset, size = _select_fat_slice(data)
        data = data[slice_offset:slice_offset + size]
    elif magic not in THIN_MAGIC:
        raise BinaryFormatError("Not a Mach-O image")
    image, layout = _macho_parse(data)
    try:
        table = _symbol_layer(data, image, layout)
    except struct.error as exc:
        raise BinaryFormatError(f"Malformed Mach-O symbol table: {exc}") from exc
    table["fat_slice_offset"] = slice_offset
    return table


def recover_function_ranges(data: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    """Recover declared function starts and initializer pointers from a Mach-O.

    附加的只读操作，与加载器选同一个胖文件切片；只读容器声明的事实：
      * LC_FUNCTION_STARTS — 编译器声明的全部函数起点（含无符号函数），边界取到
        同一可执行节内的下一个起点（或节尾）；是容器级证据，不是“已确认的真实函数数”。
      * ``__mod_init_func`` / ``__mod_term_func`` — C/C++ 构造/析构函数指针节。只接受
        “原始指针值落在某个可执行节内”的项（经链式修订编码的值不会命中，故被跳过）。
      * ``__TEXT,__init_offsets``（S_INIT_FUNC_OFFSETS=0x16）— 当前 Apple 工具链（链式
        修订）默认产出的构造函数表：每项是相对镜像基址（__TEXT 段 vmaddr）的 32 位
        偏移，不需要修订即可读出，来源记为 ``init_offsets``。
    地址都是虚拟地址，与切片偏移无关。不解码指令、不恢复 CFG、不修改任何镜像。
    """
    magic = bytes(data[:4])
    if magic in FAT_MAGIC:
        _index, _count, slice_offset, size = _select_fat_slice(data)
        data = data[slice_offset:slice_offset + size]
    elif magic not in THIN_MAGIC:
        return [], ["Mach-O function range recovery requires a Mach-O image"]
    warnings: list[str] = []
    try:
        image, layout = _macho_parse(data)
    except (BinaryFormatError, struct.error) as exc:
        return [], [f"Mach-O function range recovery failed: {exc}"]
    bits = layout["bits"]
    thumb_mask = ~1 if image.architecture == "arm" else ~0
    executable = sorted((section["address"], section["address"] + section["size"])
                        for section in image.sections
                        if section.get("executable") and type(section.get("address")) is int
                        and type(section.get("size")) is int and section["size"] > 0)
    exec_starts = [start for start, _ in executable]

    def executable_span(address: int) -> tuple[int, int] | None:
        from bisect import bisect_right
        position = bisect_right(exec_starts, address) - 1
        if position >= 0 and address < executable[position][1]:
            return executable[position]
        return None

    roots: dict[int, dict[str, Any]] = {}
    # --- LC_FUNCTION_STARTS：落在可执行节内的声明函数起点，边界取到同节下一个起点。---
    raw_starts = _function_starts(data, layout, warnings)
    thumb_starts = {address & thumb_mask for address in raw_starts if address & 1}
    starts = sorted({address & thumb_mask for address in raw_starts})
    for position, address in enumerate(starts):
        span = executable_span(address)
        if span is None:
            continue
        following = starts[position + 1] if position + 1 < len(starts) else span[1]
        end = min(following, span[1])
        size = end - address if end > address else None
        root: dict[str, Any] = {"name": f"func_{address:x}", "start": address, "size": size,
                                "source": "function_starts", "sources": ["function_starts"],
                                "boundary_known": size is not None,
                                "boundary_scope": "function_starts" if size is not None else None,
                                "blocks": [], "cfg": {"edges": []}, "xrefs_in": [], "xrefs_out": []}
        if image.architecture == "arm" and address in thumb_starts:
            root["isa_mode"] = "thumb"
        roots[address] = root
    # --- __mod_init_func / __mod_term_func：构造/析构函数指针。只接受原始指针落在可执行节内。---
    order = layout["order"]
    pointer_size = bits // 8
    for section in image.sections:
        section_type = section.get("section_type")
        source = {0x9: "mod_init_func", 0xA: "mod_term_func", 0x16: "init_offsets"}.get(section_type)
        if source is None:
            continue
        offset, size, address = section.get("offset"), section.get("size"), section.get("address")
        if any(type(value) is not int for value in (offset, size)) or not section.get("file_backed"):
            continue
        # __init_offsets 每项固定 4 字节（相对镜像基址的偏移）；指针节按镜像指针宽度。
        entry_size = 4 if section_type == 0x16 else pointer_size
        image_base = layout["text_vmaddr"]
        if section_type == 0x16 and type(image_base) is not int:
            warnings.append("Mach-O init_offsets cannot be resolved without a __TEXT segment")
            continue
        if size % entry_size or offset < 0 or offset + size > len(data):
            warnings.append(f"Mach-O {source} is truncated or misaligned")
            continue
        for index in range(size // entry_size):
            slot = offset + index * entry_size
            raw = int.from_bytes(data[slot:slot + entry_size], image.endian)
            pointer = image_base + raw if section_type == 0x16 else raw
            target = pointer & thumb_mask
            span = executable_span(target)
            if span is None:
                continue
            slot_address = address + index * entry_size if type(address) is int else None
            existing = roots.get(target)
            evidence = {"pointer_address": slot_address, "section": section.get("name")}
            if existing is None:
                roots[target] = {"name": f"{source}_{target:x}", "start": target, "size": None,
                                 "source": source, "sources": [source], "boundary_known": False,
                                 "evidence": evidence, "blocks": [], "cfg": {"edges": []},
                                 "xrefs_in": [], "xrefs_out": []}
            elif source not in existing["sources"]:
                existing["sources"].append(source)
    return [roots[start] for start in sorted(roots)], warnings


def _plausible_fat_table(data: bytes, count: int) -> bool:
    """Disambiguate fat counts 45–64 from legal JVM class major versions.

    The bounded probe need not include each slice, but it must include its
    architecture descriptor. Do not decode any instructions or recover xrefs.
    """
    table_end = 8 + count * 20
    if not 1 <= count <= MAX_FAT_ARCHITECTURES or table_end > len(data):
        return False
    for index in range(count):
        cpu, _subtype, offset, size, alignment = _unpack(data, 8 + index * 20, ">IIIII")
        if not cpu or offset < table_end or size < 28 or alignment > 31:
            return False
        if offset % (1 << alignment) or offset + size > 1 << 32:
            return False
        if offset + 4 <= len(data) and bytes(data[offset:offset + 4]) not in THIN_MAGIC:
            return False
    return True


class MachOLoader:
    name = "macho"
    extensions = {".dylib": "macho"}

    def probe(self, data: bytes, path: object = None) -> LoaderMatch | None:
        magic = bytes(data[:4])
        if magic in THIN_MAGIC or magic in FAT_MAGIC - {b"\xca\xfe\xba\xbe"}:
            return LoaderMatch("macho")
        if magic != b"\xca\xfe\xba\xbe":
            return None
        count = int.from_bytes(data[4:8], "big") if len(data) >= 8 else 0
        if (1 <= count < 45 or
                45 <= count <= MAX_FAT_ARCHITECTURES and _plausible_fat_table(data, count)):
            return LoaderMatch("macho")
        # Native-only loading retains the historical parser/error behavior
        # for malformed fat headers. Identification lets the JVM probe win.
        return LoaderMatch("macho", score=1)

    def load(self, data: bytes, kind: str = "macho") -> BinaryImage:
        return _fat_macho(data) if bytes(data[:4]) in FAT_MAGIC else _macho(data)


load_macho = _macho
load_fat_macho = _fat_macho
