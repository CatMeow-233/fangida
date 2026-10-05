"""Opt-in recovery of ELF unwind ranges and initialization/termination roots.

The parser follows LSB's .eh_frame/.eh_frame_hdr formats. It reads declared PC
ranges, never interprets CFA instructions or infers sizes from adjacent starts.
Unsupported encodings and unresolved relocations are reported rather than guessed.
https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
"""
from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Any

from .common import MAX_SECTIONS, _table, _unpack
from .elf_pointers import (_SHT_ANDROID_REL, _SHT_ANDROID_RELA, _SHT_ANDROID_RELR, _SHT_RELR,
                           _android_packed, _relr_slots)
from .models import BinaryFormatError, BinaryImage

MAX_RECORDS = 1_000_000
MAX_WARNINGS = 64
_ARRAY_TYPES = {14: "init_array", 15: "fini_array", 16: "preinit_array"}
_ARRAY_NAMES = {"." + name: name for name in _ARRAY_TYPES.values()}
_RELATIVE_RELOCATIONS = {"x86_64": 8, "x86": 8, "arm64": 1027, "arm": 23}


class _Invalid(ValueError):
    pass


class _Warnings:
    def __init__(self) -> None:
        self.items: list[str] = []
        self.omitted = 0

    def add(self, message: str) -> None:
        if len(self.items) < MAX_WARNINGS:
            self.items.append(message)
        else:
            self.omitted += 1

    def result(self) -> list[str]:
        return self.items + ([f"{self.omitted} additional ELF recovery warnings omitted"]
                             if self.omitted else [])


@dataclass
class _Reader:
    data: bytes
    position: int
    end: int
    address_delta: int
    endian: str
    address_size: int

    def integer(self, size: int, signed: bool = False) -> int:
        if self.position < 0 or size > self.end - self.position:
            raise _Invalid("truncated field")
        value = int.from_bytes(self.data[self.position:self.position + size],
                               self.endian, signed=signed)
        self.position += size
        return value

    def leb(self, signed: bool = False) -> int:
        value = 0
        for index in range(10):
            byte = self.integer(1)
            value |= (byte & 0x7f) << (index * 7)
            if not byte & 0x80:
                if signed and byte & 0x40:
                    value -= 1 << ((index + 1) * 7)
                if not (-(1 << 63) <= value < (1 << 63) if signed
                        else 0 <= value < (1 << 64)):
                    raise _Invalid("LEB128 value exceeds 64 bits")
                return value
        raise _Invalid("unterminated LEB128 value")

    def scalar(self, encoding: int) -> int:
        form = encoding & 0x0f
        if form == 0:
            return self.integer(self.address_size)
        if form == 1:
            return self.leb()
        if form == 9:
            return self.leb(signed=True)
        sizes = {2: 2, 3: 4, 4: 8, 8: self.address_size, 10: 2, 11: 4, 12: 8}
        if form not in sizes:
            raise _Invalid(f"unsupported pointer encoding {encoding:#x}")
        return self.integer(sizes[form], signed=bool(form & 8))

    def encoded(self, encoding: int, *, data_base: int | None = None,
                value_only: bool = False) -> int:
        if encoding == 0xff:
            raise _Invalid("omitted required pointer")
        application = encoding & 0x70
        if application == 0x50:
            padding = -(self.address_delta + self.position) % self.address_size
            if padding > self.end - self.position:
                raise _Invalid("truncated aligned pointer")
            self.position += padding
        place = self.address_delta + self.position
        value = self.scalar(encoding)
        # Personality pointers need only be skipped, not dereferenced or based.
        if value_only:
            return value
        if encoding & 0x80:
            raise _Invalid(f"unsupported indirect pointer encoding {encoding:#x}")
        if application in (0, 0x50):
            return value
        if application == 0x10:
            return place + value
        if application == 0x30 and data_base is not None:
            return data_base + value
        raise _Invalid(f"unsupported pointer base {encoding:#x}")


@dataclass(frozen=True)
class _CIE:
    encoding: int
    augmented: bool
    address_size: int
    address: int


def _reader(data: bytes, section: dict[str, Any], image: BinaryImage,
            warnings: _Warnings) -> _Reader:
    offset, size, address = (section.get(key) for key in ("offset", "size", "address"))
    if any(type(value) is not int or value < 0 for value in (offset, size, address)):
        raise _Invalid("invalid section bounds")
    if offset > len(data):
        raise _Invalid("section lies outside supplied file bytes")
    if size > len(data) - offset:
        warnings.add(f"ELF {section.get('name')} exceeds supplied file bytes")
    return _Reader(data, offset, min(len(data), offset + size), address - offset,
                   image.endian, image.bits // 8)


def _read_cie(reader: _Reader, address: int) -> _CIE:
    version = reader.integer(1)
    if version not in (1, 3, 4):
        raise _Invalid(f"unsupported CIE version {version}")
    zero = reader.data.find(b"\0", reader.position, min(reader.end, reader.position + 256))
    if zero < 0:
        raise _Invalid("unterminated CIE augmentation string")
    try:
        augmentation = reader.data[reader.position:zero].decode("ascii")
    except UnicodeDecodeError as exc:
        raise _Invalid("non-ASCII CIE augmentation") from exc
    reader.position = zero + 1
    if version == 4:
        address_size, segment_size = reader.integer(1), reader.integer(1)
        if address_size not in (4, 8) or segment_size != 0:
            raise _Invalid("unsupported CIE address/segment size")
        reader.address_size = address_size
    if reader.leb() == 0:
        raise _Invalid("invalid CIE code alignment")
    reader.leb(signed=True)
    reader.integer(1) if version == 1 else reader.leb()
    encoding = 0
    if augmentation:
        if not augmentation.startswith("z"):
            raise _Invalid(f"unsupported CIE augmentation {augmentation!r}")
        length = reader.leb()
        if length > reader.end - reader.position:
            raise _Invalid("truncated CIE augmentation data")
        augmentation_end = reader.position + length
        augmented = _Reader(reader.data, reader.position, augmentation_end,
                            reader.address_delta, reader.endian, reader.address_size)
        for character in augmentation[1:]:
            if character == "R":
                encoding = augmented.integer(1)
            elif character == "L":
                augmented.integer(1)
            elif character == "P":
                personality_encoding = augmented.integer(1)
                augmented.encoded(personality_encoding, value_only=True)
            elif character != "S":
                raise _Invalid(f"unsupported CIE augmentation character {character!r}")
        reader.position = augmentation_end
    return _CIE(encoding, augmentation.startswith("z"), reader.address_size, address)


def _executable_range(image: BinaryImage, data: bytes, start: int, size: int) -> bool:
    if start < 0 or size < 1 or start + size > 1 << image.bits:
        return False
    for section in image.sections:
        if not section.get("executable") or section.get("type") == 8:
            continue
        address, offset, length = (section.get(key) for key in ("address", "offset", "size"))
        if any(type(value) is not int or value < 0 for value in (address, offset, length)):
            continue
        available = min(length, max(0, len(data) - offset))
        if address <= start and start + size <= address + available:
            return True
    return False


def _frame_records(data: bytes, section: dict[str, Any], image: BinaryImage,
                   warnings: _Warnings) -> dict[int, dict[str, Any]]:
    reader = _reader(data, section, image, warnings)
    cies: dict[int, _CIE] = {}
    fdes: dict[int, dict[str, Any]] = {}
    for _ in range(MAX_RECORDS):
        if reader.position == reader.end:
            break
        offset = reader.position
        record_address = reader.address_delta + offset
        try:
            length = reader.integer(4)
            if length == 0:
                break
            if length == 0xffffffff:
                length = reader.integer(8)
            if length < 4 or length > reader.end - reader.position:
                raise _Invalid("invalid or truncated frame record length")
        except _Invalid as exc:
            warnings.add(f"ELF .eh_frame record at {record_address:#x}: {exc}")
            break
        end = reader.position + length
        entry = _Reader(data, reader.position, end, reader.address_delta,
                        reader.endian, reader.address_size)
        reader.position = end
        try:
            id_position = entry.position
            identifier = entry.integer(4)
            if identifier == 0:
                cies[offset] = _read_cie(entry, record_address)
                continue
            cie = cies.get(id_position - identifier)
            if cie is None:
                raise _Invalid("FDE references an unavailable CIE")
            entry.address_size = cie.address_size
            start = entry.encoded(cie.encoding)
            # PC Range is absolute and uses only the encoding's scalar format.
            size = entry.scalar(cie.encoding)
            if cie.augmented:
                augmentation_length = entry.leb()
                if augmentation_length > entry.end - entry.position:
                    raise _Invalid("truncated FDE augmentation data")
            if size == 0:
                continue
            if not _executable_range(image, data, start, size):
                raise _Invalid("FDE PC range lies outside supplied executable bytes")
            fdes[record_address] = {
                "name": f"fde_{start:x}", "start": start, "size": size,
                "source": "eh_frame", "sources": ["eh_frame"],
                "boundary_known": True, "boundary_scope": "unwind_range",
                "fde_addresses": [record_address], "cie_address": cie.address,
                "blocks": [], "cfg": {"edges": []}, "xrefs_in": [], "xrefs_out": [],
            }
        except _Invalid as exc:
            warnings.add(f"ELF .eh_frame record at {record_address:#x}: {exc}")
    else:
        if reader.position < reader.end:
            warnings.add(f"ELF .eh_frame capped at {MAX_RECORDS} records")
    return fdes


def _check_header(data: bytes, section: dict[str, Any], frames: list[dict[str, Any]],
                  fdes: dict[int, dict[str, Any]], image: BinaryImage,
                  warnings: _Warnings) -> None:
    try:
        reader = _reader(data, section, image, warnings)
        version = reader.integer(1)
        pointer_encoding, count_encoding, table_encoding = (reader.integer(1) for _ in range(3))
        if version != 1:
            raise _Invalid(f"unsupported header version {version}")
        frame_address = (reader.encoded(pointer_encoding, data_base=section["address"])
                         if pointer_encoding != 0xff else None)
        if frame_address is not None and not any(frame["address"] == frame_address for frame in frames):
            warnings.add("ELF .eh_frame_hdr points outside available .eh_frame sections")
        if count_encoding == 0xff or table_encoding == 0xff:
            return
        if count_encoding & 0xf0:
            raise _Invalid("header FDE count must be an absolute scalar")
        count = reader.scalar(count_encoding)
        if not 0 <= count <= MAX_RECORDS:
            raise _Invalid("invalid or excessive header FDE count")
        previous = -1
        for _ in range(count):
            start = reader.encoded(table_encoding, data_base=section["address"])
            fde_address = reader.encoded(table_encoding, data_base=section["address"])
            if start < previous:
                raise _Invalid("header table is not sorted by initial location")
            previous = start
            fde = fdes.get(fde_address)
            if fde is None:
                warnings.add(f"ELF .eh_frame_hdr references unavailable FDE at {fde_address:#x}")
            elif fde["start"] != start:
                warnings.add(f"ELF .eh_frame_hdr start disagrees with FDE at {fde_address:#x}")
            elif "eh_frame_hdr" not in fde["sources"]:
                fde["sources"].append("eh_frame_hdr")
    except _Invalid as exc:
        warnings.add(f"ELF .eh_frame_hdr: {exc}")


# 打包重定位节类型：SHT_RELR、SHT_ANDROID_RELR 与 APS2 打包的 SHT_ANDROID_REL/RELA。
_PACKED_RELOCATION_TYPES = frozenset({_SHT_RELR, _SHT_ANDROID_RELR, _SHT_ANDROID_REL,
                                      _SHT_ANDROID_RELA})


def _packed_relocations(data: bytes, image: BinaryImage, section: tuple[Any, ...]):
    """逐项产出打包重定位节的 (r_offset, r_info, 显式加数或 None)。

    SHT_RELR（19）与 Android 旧标签 SHT_ANDROID_RELR 只编码相对重定位的槽位，隐式加数是
    槽位当前内容（返回 None）；APS2 打包的 SHT_ANDROID_REL/RELA 与普通 REL/RELA 同义。
    解码器与 elf_pointers 共用（同属 Loader，不解码指令）；畸形编码抛出 _Invalid。
    """
    kind, offset, size = section[1], section[4], section[5]
    if not _table(data, offset, 1, size, 1, len(data)):
        raise _Invalid("invalid or truncated ELF packed relocation table")
    raw = data[offset:offset + size]
    try:
        if kind in (_SHT_RELR, _SHT_ANDROID_RELR):
            width = image.bits // 8
            if size % width:
                raise ValueError("size is not pointer-aligned")
            relative = _RELATIVE_RELOCATIONS.get(image.architecture)
            words = (int.from_bytes(raw[position:position + width], image.endian)
                     for position in range(0, size, width))
            for count, place in enumerate(_relr_slots(words, image.bits)):
                if count >= MAX_RECORDS:
                    raise ValueError("relocation count exceeds scan budget")
                # 架构未建模时 r_info 记为 None，逐槽位按“无法解析”处理，不臆测槽位内容。
                yield place, relative, None
        else:
            explicit = kind == _SHT_ANDROID_RELA
            for count, (place, info, addend) in enumerate(_android_packed(raw, image.bits, explicit)):
                if count >= MAX_RECORDS:
                    raise ValueError("relocation count exceeds scan budget")
                yield place, info, addend if explicit else None
    except ValueError as exc:
        raise _Invalid(f"invalid ELF packed relocation table: {exc}") from exc



def _array_relocations(data: bytes, image: BinaryImage, slots: dict[int, int],
                       warnings: _Warnings) -> dict[int, int | None]:
    """Resolve only declared RELATIVE relocations to link-time ELF addresses.

    普通 REL/RELA 之外，也读取 RELR 与 Android 打包重定位（APS2 打包的 RELA 中数组槽位
    内容通常为 0，不读加数就拿不到根）；与 elf_pointers 的覆盖面一致。
    """
    resolved: dict[int, int | None] = {}
    if not slots:
        return resolved
    order = "<" if image.endian == "little" else ">"

    def apply(place: int, info: int | None, addend: int | None) -> None:
        # addend 为 None 表示隐式加数（REL/RELR：槽位当前内容）。
        if place not in slots:
            return
        if info is None:
            resolved[place] = None
            warnings.add(f"Unresolved ELF array RELR relocation at {place:#x}")
            return
        kind = info & (0xff if image.bits == 32 else 0xffffffff)
        symbol = info >> (8 if image.bits == 32 else 32)
        if kind == 0:
            return
        if kind == _RELATIVE_RELOCATIONS.get(image.architecture) and symbol == 0:
            value = addend if addend is not None else slots[place]
            if place in resolved and resolved[place] != value:
                warnings.add(f"Conflicting ELF array relocations at {place:#x}")
                resolved[place] = None
            else:
                resolved[place] = value
        else:
            resolved[place] = None
            warnings.add(f"Unresolved ELF array relocation {kind} at {place:#x}")

    try:
        header = _unpack(data, 16, order + ("HHIIIIIHHHHHH" if image.bits == 32 else "HHIQQQIHHHHHH"))
        shoff, stride, count = header[5], header[10], header[11]
        fmt = order + ("IIIIIIIIII" if image.bits == 32 else "IIQQQQIIQQ")
        if not _table(data, shoff, stride, count, struct.calcsize(fmt), MAX_SECTIONS):
            raise _Invalid("relocation section table is unavailable")
        mask = (1 << image.bits) - 1
        for index in range(count):
            section = _unpack(data, shoff + index * stride, fmt)
            if section[1] in _PACKED_RELOCATION_TYPES:
                for place, info, addend in _packed_relocations(data, image, section):
                    apply(place & mask, info, addend)
                continue
            if section[1] not in (4, 9):
                continue
            offset, size, entry_size = section[4], section[5], section[9]
            relocation_fmt = order + ("II" if image.bits == 32 else "QQ")
            if section[1] == 4:
                relocation_fmt += "i" if image.bits == 32 else "q"
            minimum = struct.calcsize(relocation_fmt)
            if (entry_size < minimum or size % entry_size or
                    not _table(data, offset, entry_size, size // entry_size, minimum, MAX_RECORDS)):
                raise _Invalid("invalid or truncated ELF relocation table")
            for position in range(offset, offset + size, entry_size):
                relocation = _unpack(data, position, relocation_fmt)
                apply(relocation[0], relocation[1], relocation[2] if section[1] == 4 else None)
    except (BinaryFormatError, _Invalid) as exc:
        warnings.add(f"ELF initialization relocations unavailable: {exc}")
        # A malformed relocation table could change any literal array pointer.
        return {place: None for place in slots}
    return resolved


def _array_roots(data: bytes, image: BinaryImage, warnings: _Warnings) -> list[dict[str, Any]]:
    slots: dict[int, int] = {}
    entries: list[tuple[str, int, int]] = []
    for section in image.sections:
        source = _ARRAY_TYPES.get(section.get("type"), _ARRAY_NAMES.get(section.get("name")))
        if source is None:
            continue
        try:
            reader = _reader(data, section, image, warnings)
            if section["size"] % reader.address_size:
                raise _Invalid("array size is not pointer-aligned")
            count = (reader.end - reader.position) // reader.address_size
            if count > MAX_RECORDS:
                warnings.add(f"ELF {source} capped at {MAX_RECORDS} entries")
            for _ in range(min(count, MAX_RECORDS)):
                place = reader.address_delta + reader.position
                pointer = reader.integer(reader.address_size)
                slots[place] = pointer
                entries.append((source, place, pointer))
        except _Invalid as exc:
            warnings.add(f"ELF {source}: {exc}")
    relocations = _array_relocations(data, image, slots, warnings)
    roots = []
    for source, place, pointer in entries:
        pointer = relocations.get(place, pointer)
        if pointer is None or pointer in (0, (1 << image.bits) - 1):
            continue
        # ARM function-pointer bit zero explicitly selects Thumb ISA.
        thumb = image.architecture == "arm" and bool(pointer & 1)
        start = pointer & ~1 if thumb else pointer
        if not _executable_range(image, data, start, 1):
            warnings.add(f"ELF {source} pointer at {place:#x} is outside executable bytes")
            continue
        root = {"name": f"{source}_{start:x}", "start": start, "size": None,
                "source": source, "sources": [source], "boundary_known": False,
                "array_slots": [place], "blocks": [], "cfg": {"edges": []},
                "xrefs_in": [], "xrefs_out": []}
        if thumb:
            root["isa_mode"] = "thumb"
        roots.append(root)
    return roots


def recover_function_ranges(data: bytes, image: BinaryImage) -> tuple[list[dict[str, Any]], list[str]]:
    """Return newly recovered declarations without modifying ``image``.

    Ranges are validated against executable bytes supplied by the caller. A
    positive FDE size is known only as an unwind range; it does not establish
    source-level function identity. Array-only roots have unknown boundaries.
    ELF relocatable objects, indirect FDE pointers, non-z legacy augmentations,
    and symbol-based initialization relocations remain explicitly unsupported.
    """
    warnings = _Warnings()
    if image.format != "elf" or image.bits not in (32, 64) or image.endian not in ("little", "big"):
        return [], ["ELF function range recovery requires a supported ELF image"]
    if len(data) < 18 or data[:4] != b"\x7fELF":
        return [], ["ELF function range recovery requires ELF file bytes"]
    file_type = int.from_bytes(data[16:18], image.endian)
    if file_type not in (2, 3):
        return [], ["ELF function range recovery requires a linked executable or shared object"]
    frames = [section for section in image.sections if section.get("name") == ".eh_frame"]
    fdes: dict[int, dict[str, Any]] = {}
    for section in frames:
        try:
            fdes.update(_frame_records(data, section, image, warnings))
        except _Invalid as exc:
            warnings.add(f"ELF .eh_frame: {exc}")
    for section in image.sections:
        if section.get("name") == ".eh_frame_hdr":
            _check_header(data, section, frames, fdes, image, warnings)
    recovered: dict[int, dict[str, Any]] = {}
    for function in list(fdes.values()) + _array_roots(data, image, warnings):
        start = function["start"]
        previous = recovered.get(start)
        if previous is None:
            recovered[start] = function
            continue
        for source in function["sources"]:
            if source not in previous["sources"]:
                previous["sources"].append(source)
        for key in ("fde_addresses", "array_slots"):
            if key in function:
                previous.setdefault(key, []).extend(function[key])
        if previous["size"] is not None and function["size"] is not None and previous["size"] != function["size"]:
            previous.setdefault("unwind_ranges", [previous["size"]]).append(function["size"])
            previous["size"] = None
            previous["boundary_known"] = False
            previous["boundary_scope"] = "conflicting_unwind_ranges"
            warnings.add(f"Conflicting ELF unwind ranges at {start:#x}; no unique boundary selected")
        elif "unwind_ranges" in previous and function["size"] is not None:
            previous["unwind_ranges"].append(function["size"])
    return sorted(recovered.values(), key=lambda function: function["start"]), warnings.result()
