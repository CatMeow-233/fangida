"""Declared ELF ranges with no sample execution or external tool dependency."""
from __future__ import annotations

from copy import deepcopy
import struct
import unittest
from unittest.mock import patch

from fangida.loaders.elf import _elf, recover_function_ranges
from fangida.loaders import elf_unwind


def leb(value: int, signed: bool = False) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        done = (value == 0 and not (signed and byte & 0x40)) or (signed and value == -1 and byte & 0x40)
        result.append(byte if done else byte | 0x80)
        if done:
            return bytes(result)


def encoded(value: int, encoding: int, bits: int, order: str) -> bytes:
    form = encoding & 0xf
    if form in (1, 9):
        return leb(value, signed=form == 9)
    formats = {0: "I" if bits == 32 else "Q", 2: "H", 3: "I", 4: "Q",
               8: "i" if bits == 32 else "q", 10: "h", 11: "i", 12: "q"}
    return struct.pack(order + formats[form], value)


def frame_data(ranges=((0x4010, 0x18),), *, bits=64, order="<", encoding=0x1b,
               version=1, augmentation=None, extended=False, frame_address=0x6000):
    if augmentation is None:
        augmentation = b"zR" if encoding else b""
    cie = b"\0" * 4 + bytes([version]) + augmentation + b"\0"
    if version == 4:
        cie += bytes([bits // 8, 0])
    cie += leb(1) + leb(-8, signed=True) + (b"\x10" if version == 1 else leb(16))
    if augmentation.startswith(b"z"):
        cie += leb(1) + bytes([encoding])
    cie += bytes((-len(cie) - 4) % 8)
    data = bytearray(struct.pack(order + "I", len(cie)) + cie)
    entries = []
    for start, size in ranges:
        offset = len(data)
        prefix_size = 12 if extended else 4
        field_address = frame_address + offset + prefix_size + 4
        initial = start - field_address if encoding & 0x70 == 0x10 else start
        body = struct.pack(order + "I", offset + prefix_size)
        body += encoded(initial, encoding, bits, order) + encoded(size, encoding, bits, order)
        if augmentation.startswith(b"z"):
            body += leb(0)
        body += bytes((-len(body) - prefix_size) % 8)
        data += (struct.pack(order + "IQ", 0xffffffff, len(body)) if extended
                 else struct.pack(order + "I", len(body))) + body
        entries.append((start, frame_address + offset))
    return bytes(data) + b"\0" * 4, entries


def elf_file(*, bits=64, order="<", frame=None, entries=(), arrays=(), relocations=(),
             with_header=False, file_type=3, frame_address=0x6000, rela=True):
    """Create a complete linked ELF with real section-header/relocation tables."""
    header_size = 52 if bits == 32 else 64
    section_size = 40 if bits == 32 else 64
    data = bytearray(header_size)
    sections = [("", 0, 0, 0, 0, 0, 0, 0, 0, 0)]

    def add(name, section_type, flags, address, content, entry_size=0):
        data.extend(bytes(-len(data) % 8))
        offset = len(data)
        data.extend(content)
        sections.append((name, section_type, flags, address, offset, len(content), 0, 0, 8, entry_size))

    add(".text", 1, 6, 0x4000, b"\x90" * 512)
    if frame is not None:
        add(".eh_frame", 1, 2, frame_address, frame)
    if with_header:
        header_address = 0x7000
        header = bytes([1, 0x1b, 3, 0x3b])
        header += struct.pack(order + "iI", frame_address - (header_address + 4), len(entries))
        for start, fde in sorted(entries):
            header += struct.pack(order + "ii", start - header_address, fde - header_address)
        add(".eh_frame_hdr", 1, 2, header_address, header)
    pointer_format = order + ("I" if bits == 32 else "Q")
    for index, (name, values) in enumerate(arrays):
        section_type = {".init_array": 14, ".fini_array": 15, ".preinit_array": 16}[name]
        add(name, section_type, 3, 0x8000 + index * 0x100,
            b"".join(struct.pack(pointer_format, value) for value in values), bits // 8)
    if relocations:
        payload = bytearray()
        for place, kind, symbol, addend in relocations:
            info = symbol << (8 if bits == 32 else 32) | kind
            payload += struct.pack(order + ("II" if bits == 32 else "QQ"), place, info)
            if rela:
                payload += struct.pack(order + ("i" if bits == 32 else "q"), addend)
        add(".rela.dyn" if rela else ".rel.dyn", 4 if rela else 9, 2, 0x9000,
            payload, (bits // 8) * (3 if rela else 2))
    names = bytearray(b"\0")
    name_offsets = {"": 0}
    for name in [section[0] for section in sections] + [".shstrtab"]:
        if name not in name_offsets:
            name_offsets[name] = len(names)
            names.extend(name.encode() + b"\0")
    add(".shstrtab", 3, 0, 0, names)
    data.extend(bytes(-len(data) % 8))
    shoff = len(data)
    fmt = order + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
    for section in sections:
        data.extend(struct.pack(fmt, name_offsets[section[0]], *section[1:]))
    data[:16] = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if order == "<" else 2, 1]) + bytes(9)
    struct.pack_into(order + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"), data, 16,
                     file_type, 3 if bits == 32 else 62, 1, 0x4000, 0, shoff, 0,
                     header_size, 0, 0, section_size, len(sections), len(sections) - 1)
    return bytes(data)


class ElfUnwindTests(unittest.TestCase):
    def test_default_parser_is_unchanged_and_recovery_is_explicit(self):
        frame, entries = frame_data(((0x4010, 0x18), (0x4080, 0x30)))
        data = elf_file(frame=frame, entries=entries, with_header=True)
        image = _elf(data)
        original = deepcopy(image)
        functions, warnings = recover_function_ranges(data, image)
        self.assertEqual(image, original)
        self.assertEqual(_elf(data).functions, [])
        self.assertEqual(warnings, [])
        self.assertEqual([(f["start"], f["size"]) for f in functions], [(0x4010, 0x18), (0x4080, 0x30)])
        self.assertTrue(all(f["boundary_known"] and f["boundary_scope"] == "unwind_range" for f in functions))
        self.assertTrue(all(f["source"] == "eh_frame" and f["sources"] == ["eh_frame", "eh_frame_hdr"] for f in functions))

    def test_eh_frame_does_not_require_search_header(self):
        frame, _ = frame_data()
        data = elf_file(frame=frame)
        functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual(warnings, [])
        self.assertEqual(functions[0]["sources"], ["eh_frame"])

    def test_absolute_ranges_32_64_bits_both_endiannesses(self):
        for bits in (32, 64):
            for order in ("<", ">"):
                with self.subTest(bits=bits, order=order):
                    frame, _ = frame_data(bits=bits, order=order, encoding=0)
                    data = elf_file(bits=bits, order=order, frame=frame)
                    functions, warnings = recover_function_ranges(data, _elf(data))
                    self.assertEqual(warnings, [])
                    self.assertEqual((functions[0]["start"], functions[0]["size"]), (0x4010, 0x18))

    def test_leb_encodings_cie_versions_and_extended_record_length(self):
        for encoding, frame_address, version, extended in ((0x11, 0x3000, 3, False),
                                                           (0x19, 0x6000, 3, False),
                                                           (0x1b, 0x6000, 4, False),
                                                           (0x1b, 0x6000, 1, True)):
            with self.subTest(encoding=encoding, version=version, extended=extended):
                frame, _ = frame_data(encoding=encoding, frame_address=frame_address,
                                      version=version, extended=extended)
                data = elf_file(frame=frame, frame_address=frame_address)
                functions, warnings = recover_function_ranges(data, _elf(data))
                self.assertEqual(warnings, [])
                self.assertEqual((functions[0]["start"], functions[0]["size"]), (0x4010, 0x18))

    def test_bad_cie_and_unsupported_pointer_encodings_are_not_guessed(self):
        for kwargs, message in (({"augmentation": b"zX"}, "augmentation character"),
                                ({"encoding": 0x9b}, "indirect pointer"),
                                ({"encoding": 0x2b}, "pointer base"),
                                ({"version": 2}, "CIE version")):
            with self.subTest(kwargs=kwargs):
                frame, _ = frame_data(**kwargs)
                data = elf_file(frame=frame)
                functions, warnings = recover_function_ranges(data, _elf(data))
                self.assertEqual(functions, [])
                self.assertTrue(any(message in warning for warning in warnings), warnings)

    def test_fde_pointer_and_record_bounds_preserve_valid_prefix(self):
        frame, _ = frame_data(((0x4010, 0x18), (0x4080, 0x20)))
        second = len(frame_data()[0]) - 4
        broken = bytearray(frame)
        struct.pack_into("<I", broken, second + 4, 0xffff)
        data = elf_file(frame=broken)
        functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual(len(functions), 1)
        self.assertTrue(any("unavailable CIE" in warning for warning in warnings))
        broken = bytearray(frame)
        struct.pack_into("<I", broken, second, 0xfffffff0)
        data = elf_file(frame=broken)
        functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual(len(functions), 1)
        self.assertTrue(any("record length" in warning for warning in warnings))

    def test_declared_ranges_must_fit_supplied_executable_bytes(self):
        for start, size in ((0x3000, 0x20), (0x41f0, 0x20)):
            frame, _ = frame_data(((start, size),))
            data = elf_file(frame=frame)
            functions, warnings = recover_function_ranges(data, _elf(data))
            self.assertEqual(functions, [])
            self.assertTrue(any("outside supplied executable" in warning for warning in warnings))

    def test_corrupt_header_does_not_invent_ranges_or_erase_fde_facts(self):
        frame, entries = frame_data()
        for changed in (((0x4020, entries[0][1]),), ((0x4010, 0x1234),)):
            data = elf_file(frame=frame, entries=changed, with_header=True)
            functions, warnings = recover_function_ranges(data, _elf(data))
            self.assertEqual((functions[0]["start"], functions[0]["size"]), (0x4010, 0x18))
            self.assertEqual(functions[0]["sources"], ["eh_frame"])
            self.assertTrue(warnings)

    def test_header_entries_never_supply_sizes_without_available_fdes(self):
        data = elf_file(entries=((0x4010, 0x6000),), with_header=True)
        functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual(functions, [])
        self.assertTrue(any("unavailable FDE" in warning for warning in warnings))

    def test_array_roots_have_unknown_boundaries_and_combine_sources(self):
        data = elf_file(arrays=((".init_array", (0, 0xffffffffffffffff, 0x4010)),
                                (".fini_array", (0x4010, 0x4080))))
        functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual(warnings, [])
        self.assertEqual([f["start"] for f in functions], [0x4010, 0x4080])
        self.assertTrue(all(f["size"] is None and not f["boundary_known"] for f in functions))
        self.assertEqual(functions[0]["sources"], ["init_array", "fini_array"])

    def test_array_evidence_preserves_a_corresponding_known_unwind_range(self):
        frame, _ = frame_data()
        data = elf_file(frame=frame, arrays=((".init_array", (0x4010,)),))
        functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual(warnings, [])
        self.assertEqual(len(functions), 1)
        self.assertEqual(functions[0]["sources"], ["eh_frame", "init_array"])
        self.assertEqual(functions[0]["size"], 0x18)
        self.assertTrue(functions[0]["boundary_known"])

    def test_rela_relative_array_pointer_is_recovered_from_explicit_addend(self):
        data = elf_file(arrays=((".init_array", (0,)),), relocations=((0x8000, 8, 0, 0x4010),))
        functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual(warnings, [])
        self.assertEqual(functions[0]["start"], 0x4010)
        self.assertFalse(functions[0]["boundary_known"])

    def test_relative_relocations_32_64_bits_both_byte_orders_and_rel_format(self):
        for bits in (32, 64):
            for order in ("<", ">"):
                for rela in (True, False):
                    with self.subTest(bits=bits, order=order, rela=rela):
                        data = elf_file(bits=bits, order=order, rela=rela,
                                        arrays=((".init_array", (0 if rela else 0x4010,)),),
                                        relocations=((0x8000, 8, 0, 0x4010),))
                        functions, warnings = recover_function_ranges(data, _elf(data))
                        self.assertEqual(warnings, [])
                        self.assertEqual(functions[0]["start"], 0x4010)

    def test_aarch64_relative_relocation_uses_its_own_abi_type(self):
        data = bytearray(elf_file(arrays=((".init_array", (0,)),),
                                  relocations=((0x8000, 1027, 0, 0x4010),)))
        struct.pack_into("<H", data, 18, 183)
        functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual(warnings, [])
        self.assertEqual(functions[0]["start"], 0x4010)

    def test_truncated_augmentation_and_malformed_relocation_table_are_visible(self):
        frame, _ = frame_data()
        frame = bytearray(frame)
        frame[15] = 0x7f
        data = elf_file(frame=frame)
        functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual(functions, [])
        self.assertTrue(any("truncated CIE augmentation" in warning for warning in warnings))
        data = bytearray(elf_file(arrays=((".init_array", (0x4010,)),),
                                  relocations=((0x8000, 8, 0, 0x4010),)))
        shoff = struct.unpack_from("<Q", data, 40)[0]
        image = _elf(data)
        index = next(index for index, section in enumerate(image.sections) if section["type"] == 4)
        struct.pack_into("<Q", data, shoff + 64 * index + 56, 0)
        functions, warnings = recover_function_ranges(data, image)
        self.assertEqual(functions, [])
        self.assertTrue(any("relocation table" in warning for warning in warnings))

    def test_symbol_relocation_cannot_be_mistaken_for_a_literal_array_pointer(self):
        data = elf_file(arrays=((".init_array", (0x4010, 0x4080)),),
                        relocations=((0x8000, 1, 1, 0),))
        functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual([f["start"] for f in functions], [0x4080])
        self.assertTrue(any("Unresolved ELF array relocation" in warning for warning in warnings))

    def test_conflicting_declared_ranges_keep_the_conflict_visible(self):
        frame, _ = frame_data(((0x4010, 0x18), (0x4010, 0x20)))
        data = elf_file(frame=frame)
        functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual(len(functions), 1)
        self.assertIsNone(functions[0]["size"])
        self.assertFalse(functions[0]["boundary_known"])
        self.assertEqual(functions[0]["unwind_ranges"], [0x18, 0x20])
        self.assertTrue(any("Conflicting ELF unwind ranges" in warning for warning in warnings))

    def test_truncated_sections_invalid_arrays_and_relocatable_objects_are_visible(self):
        frame, _ = frame_data()
        data = elf_file(frame=frame, arrays=((".init_array", (0x3000,)),))
        image = _elf(data)
        functions, warnings = recover_function_ranges(data, image)
        self.assertEqual(len(functions), 1)
        self.assertTrue(any("outside executable" in warning for warning in warnings))
        array = next(section for section in image.sections if section["name"] == ".init_array")
        array["size"] += 1
        _, warnings = recover_function_ranges(data, image)
        self.assertTrue(any("pointer-aligned" in warning for warning in warnings))
        frame_section = next(section for section in image.sections if section["name"] == ".eh_frame")
        frame_section["size"] = len(data) + 1
        _, warnings = recover_function_ranges(data, image)
        self.assertTrue(any("exceeds supplied file bytes" in warning for warning in warnings))
        obj = elf_file(frame=frame, file_type=1)
        functions, warnings = recover_function_ranges(obj, _elf(obj))
        self.assertEqual(functions, [])
        self.assertTrue(any("linked executable" in warning for warning in warnings))

    def test_record_cap_is_reported_without_hiding_already_recovered_ranges(self):
        frame, _ = frame_data(((0x4010, 0x18), (0x4080, 0x30)))
        data = elf_file(frame=frame)
        with patch.object(elf_unwind, "MAX_RECORDS", 2):
            functions, warnings = recover_function_ranges(data, _elf(data))
        self.assertEqual([f["start"] for f in functions], [0x4010])
        self.assertTrue(any("capped at 2 records" in warning for warning in warnings))


if __name__ == "__main__":
    unittest.main()
