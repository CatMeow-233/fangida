"""PE container headers, sections and entry-point mapping."""
from __future__ import annotations

from typing import Any

from .common import MAX_SECTIONS, _table, _unpack
from .models import BinaryFormatError, BinaryImage
from .interfaces import LoaderMatch

# 节是否为代码区域只看 IMAGE_SCN_MEM_EXECUTE（页可执行），与原始行为一致；
# IMAGE_SCN_CNT_CODE（0x20）只是内容声明，不单独授予可执行。
_SCN_MEM_EXECUTE = 0x20000000
_SCN_MEM_READ = 0x40000000
_SCN_MEM_WRITE = 0x80000000


def _pe(data: bytes) -> BinaryImage:
    peoff, = _unpack(data, 0x3c, "<I")
    if peoff > len(data) - 24 or data[peoff:peoff + 4] != b"PE\0\0":
        raise BinaryFormatError("Invalid or truncated PE signature")
    machine, nsections, _timestamp, _symtab, _nsyms, optsize, _flags = _unpack(data, peoff + 4, "<HHIIIHH")
    if nsections > MAX_SECTIONS:
        raise BinaryFormatError("PE section count exceeds safety limit")
    optoff = peoff + 24
    if optoff > len(data) or optsize > len(data) - optoff:
        raise BinaryFormatError("Truncated PE optional header")
    magic, = _unpack(data, optoff, "<H")
    if magic not in {0x10b, 0x20b}:
        raise BinaryFormatError(f"Unsupported PE optional header magic {magic:#x}")
    bits = 64 if magic == 0x20b else 32
    required = 32 if bits == 64 else 32
    if optsize < required:
        raise BinaryFormatError("Truncated PE entry and image base")
    entry_rva, = _unpack(data, optoff + 16, "<I")
    image_base, = _unpack(data, optoff + (24 if bits == 64 else 28), "<Q" if bits == 64 else "<I")
    arch = {0x8664: "x86_64", 0xaa64: "arm64", 0x14c: "x86", 0x1c0: "arm"}.get(machine, f"pe-machine-{machine}")
    image = BinaryImage("pe", arch, bits, "little", image_base + entry_rva,
                        image_base=image_base)
    sectoff = optoff + optsize
    if not _table(data, sectoff, 40, nsections, 40, MAX_SECTIONS):
        image.warnings.append("PE section table exceeds scan budget or safety limits")
        return image
    for i in range(nsections):
        (name, vsize, rva, rawsize, rawoff, _reloc, _line, _nreloc,
         _nline, flags) = _unpack(data, sectoff + i * 40, "<8sIIIIIIHHI")
        # SizeOfRawData 按 FileAlignment 向上取整，超出 VirtualSize 的尾部只是文件对齐填充，
        # 不属于节的映射内容；VirtualSize 为 0 时按惯例（目标文件、部分链接器）回退到原始大小。
        mapped = min(rawsize, vsize) if vsize else rawsize
        image.sections.append({"name": name.split(b"\0", 1)[0].decode("ascii", "replace") or f"section_{i}",
                               "address": image_base + rva, "offset": rawoff,
                               "size": mapped, "virtual_size": vsize, "type": "PE_SECTION",
                               "file_backed": mapped > 0, "file_size": mapped,
                               "executable": bool(flags & _SCN_MEM_EXECUTE),
                               "readable": bool(flags & _SCN_MEM_READ),
                               "writable": bool(flags & _SCN_MEM_WRITE),
                               "permissions_source": "section",
                               # 新增字段：节头原始 SizeOfRawData 与 Characteristics。
                               "size_of_raw_data": rawsize, "section_flags": flags})
        if image.entry_offset is None and rva <= entry_rva < rva + mapped:
            image.entry_offset = rawoff + entry_rva - rva
    if image.entry_offset is None and entry_rva < sectoff + nsections * 40:
        image.entry_offset = entry_rva  # PE headers are mapped at their RVA.
    if entry_rva and image.entry_offset is None:
        image.warnings.append("Entry point does not map to scanned sections")
    return image


class PELoader:
    name = "pe"
    extensions = {".exe": "pe", ".dll": "pe"}

    def probe(self, data: bytes, path: object = None) -> LoaderMatch | None:
        return LoaderMatch("pe") if data.startswith(b"MZ") else None

    def load(self, data: bytes, kind: str = "pe") -> BinaryImage:
        return _pe(data)


def recover_function_ranges(data: bytes, image: BinaryImage) -> tuple[list[dict[str, Any]], list[str]]:
    """Recover PE declared function starts (.pdata/exports) and code pointers.

    附加的只读操作，不修改 ``image``、不解码指令；候选是否接受为函数入口由分析核心
    按完整证据规则裁决。``.pdata`` 与导出表给出声明起点，基址重定位给出指针候选。
    """
    from .pe_pointers import recover_function_ranges as recover
    return recover(data, image)


def recover_code_pointers(data: bytes, image: BinaryImage) -> tuple[list[dict[str, Any]], list[str]]:
    """Recover base-relocation code pointers slot by slot.

    附加的只读操作，不修改 ``image``、不解码指令；与 ELF 的同名门面同形，每个槽位
    一条候选（同一目标可出现多次），供分析核心按相邻槽位组成的指针表做表级裁决。
    """
    from .pe_pointers import recover_code_pointers as recover
    return recover(data, image)


load_pe = _pe
