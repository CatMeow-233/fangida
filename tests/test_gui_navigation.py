"""验证导航历史、空间隔离及只读索引，不启动图形界面或分析器。"""
from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch

from fangida.gui_modules.navigation import (
    AddressIndex, AmbiguousLocationError, Location, NavigationHistory,
    UnknownLocationError,
)


class NavigationHistoryTests(unittest.TestCase):
    def test_location_is_immutable_and_rejects_invalid_addresses(self) -> None:
        location = Location(0x1000, "", "ram")
        self.assertEqual(location.address_space, "native")
        with self.assertRaises(FrozenInstanceError):
            location.address = 2
        for address in (True, -1, 1 << 64, "12"):
            with self.assertRaises(ValueError):
                Location(address)
        with self.assertRaises(TypeError):
            Location(0, source=4)

    def test_history_bounds_duplicate_and_branch(self) -> None:
        history = NavigationHistory()
        first, second, third = Location(1), Location(2), Location(3)
        self.assertIsNone(history.current)
        self.assertEqual(history.cursor, -1)
        self.assertIsNone(history.back())
        self.assertIsNone(history.forward())
        history.visit(first)
        history.visit(first)
        history.visit(second)
        self.assertEqual(history.entries, (first, second))
        self.assertTrue(history.can_back)
        self.assertFalse(history.can_forward)
        self.assertEqual(history.back(), first)
        history.visit(first)
        self.assertTrue(history.can_forward)
        self.assertEqual(history.forward(), second)
        history.back()
        history.visit(third)
        self.assertEqual(history.entries, (first, third))
        self.assertFalse(history.can_forward)
        history.reset(second)
        self.assertEqual(history.current, second)
        self.assertEqual(history.cursor, 0)
        history.reset()
        self.assertEqual(history.entries, ())

    def test_history_distinguishes_equal_offsets_in_containers(self) -> None:
        history = NavigationHistory()
        history.visit(Location(0x40, "classes.dex", "file_offset"))
        history.visit(Location(0x40, "classes2.dex", "file_offset"))
        self.assertEqual(len(history.entries), 2)
        with self.assertRaises(TypeError):
            history.visit(0x40)


class AddressIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = {
            "Sections": [{"name": ".text", "address": 0x1000, "offset": 0x100, "size": 0x200}],
            "Functions": [{"name": "main", "start": 0x1000, "size": 0x20, "source": "symtab"},
                          {"name": "helper", "start": 0x1100, "size": 8, "source": "direct_call"}],
            "Disassembly": [{"addr": 0x1000, "size": 5, "mnemonic": "call"},
                            {"addr": 0x1005, "size": 1, "mnemonic": "ret"},
                            {"addr": 0x1100, "size": 1, "mnemonic": "ret"}],
            "Strings": [{"offset": 0x40, "value": "hello"}],
            "Imports": [{"address": 0x1300, "name": "puts", "source": "pe-import"}],
            "Exports": [{"address": 0x1000, "name": "main"}],
            "Xrefs": [{"src": 0x1000, "dst": 0x1100, "kind": "call", "src_space": "ram", "dst_space": "ram"}],
        }
        self.cfgs = [{"name": "main", "start": 0x1000,
                      "graph": {"blocks": [{"start": 0x1000, "instructions": self.rows["Disassembly"][:2]}]}}]
        self.index = AddressIndex(self.rows, self.cfgs, kind="elf")

    def test_native_addresses_and_symbols_ignore_provenance_labels(self) -> None:
        self.assertEqual(self.index.resolve("main"), Location(0x1000))
        self.assertEqual(self.index.resolve("0x1100"), Location(0x1100))
        self.assertEqual(self.index.resolve(0x1300), Location(0x1300))
        self.assertEqual(self.index.location_for_row("Functions", 0), Location(0x1000))
        self.assertIsNone(self.index.location_for_row("Functions", -1))
        self.assertIsNone(self.index.location_for_row("Functions", True))
        with self.assertRaises(UnknownLocationError):
            self.index.resolve("missing")
        with self.assertRaises(UnknownLocationError):
            self.index.resolve(0x9999)
        with self.assertRaises(TypeError):
            self.index.resolve(True)

    def test_native_and_file_offset_are_not_silently_mixed(self) -> None:
        self.assertEqual(self.index.resolve("0x40"), Location(0x40, "", "file_offset"))
        self.assertEqual(self.index.location_for_row("Sections", 0, "offset"),
                         Location(0x100, "", "file_offset"))
        overlapping = AddressIndex({"Disassembly": [{"addr": 16, "size": 2}],
                                    "Strings": [{"offset": 16}]})
        with self.assertRaises(AmbiguousLocationError) as raised:
            overlapping.resolve(16)
        self.assertEqual(len(raised.exception.candidates), 2)
        self.assertEqual(overlapping.resolve(16, address_space="native"), Location(16))
        self.assertEqual(overlapping.resolve(16, address_space="offset"), Location(16, "", "file_offset"))

    def test_mid_instruction_returns_actual_start_and_function_cfg(self) -> None:
        location = self.index.resolve("0x1002")
        target, = self.index.find_targets(location, table="Disassembly")
        self.assertEqual(target.location.address, 0x1000)
        self.assertEqual(target.row_index, 0)
        function = self.index.function_at(location)
        self.assertEqual(function.name, "main")
        self.assertEqual(function.cfg_index, 0)
        self.assertEqual(self.index.find_targets(location, table="CFG")[0].location.address, 0x1000)
        self.assertIsNone(self.index.function_at(Location(0x1180)))

    def test_incoming_outgoing_are_read_only_evidence_handles(self) -> None:
        outgoing, = self.index.outgoing(Location(0x1000))
        incoming, = self.index.incoming(Location(0x1100))
        self.assertIs(outgoing, incoming)
        self.assertEqual(outgoing.table, "Xrefs")
        self.assertEqual(outgoing.row_index, 0)
        self.assertEqual(outgoing.src, Location(0x1000))
        self.assertEqual(outgoing.dst, Location(0x1100))
        self.assertEqual(self.index.incoming(Location(0x1100, "classes.dex", "file_offset")), ())

    def test_index_borrows_ir_without_copy_or_record_mutation(self) -> None:
        row = self.rows["Disassembly"][0]
        instruction_ids = [id(record) for record in self.rows["Disassembly"]]
        with patch("copy.deepcopy", side_effect=AssertionError("不得复制 IR")):
            index = AddressIndex(self.rows, self.cfgs, kind="elf")
            index.resolve("main")
            index.function_at(Location(0x1002))
            index.find_targets(Location(0x1002))
        self.assertEqual(instruction_ids, [id(record) for record in self.rows["Disassembly"]])
        self.assertIs(index._rows["Disassembly"][0], row)
        self.assertNotIn("address_space", row)
        self.assertNotIn("location", self.rows["Functions"][0])

    def test_overlapping_functions_are_reported_not_selected_randomly(self) -> None:
        index = AddressIndex({"Functions": [{"name": "first", "start": 100, "size": 20},
                                            {"name": "second", "start": 105, "size": 20}]})
        with self.assertRaises(AmbiguousLocationError) as raised:
            index.function_at(Location(110))
        self.assertEqual([item.name for item in raised.exception.targets], ["first", "second"])
        self.assertEqual(len(index.find_functions(Location(110))), 2)

    def test_cfg_only_and_non_contiguous_functions_do_not_invent_coverage(self) -> None:
        graph = {"blocks": [{"start": 100, "instructions": [{"addr": 100, "size": 2}]},
                            {"start": 200, "instructions": [{"addr": 200, "size": 3}]}]}
        cfgs = [{"start": 100, "name": "main", "graph": graph}]
        index = AddressIndex({"Functions": [{"name": "main", "start": 100}]}, cfgs)
        self.assertEqual(index.resolve(201), Location(201))
        target, = index.find_targets(Location(201), table="CFG")
        self.assertEqual((target.cfg_index, target.row_index, target.location.address), (0, 1, 200))
        self.assertEqual(index.function_at(Location(201)).name, "main")
        self.assertIsNone(index.function_at(Location(150)))
        with self.assertRaises(UnknownLocationError):
            index.resolve(150)

    def test_malformed_rows_are_ignored_and_negative_addresses_rejected(self) -> None:
        index = AddressIndex({"Functions": [None, {"start": True}, {"start": -1}],
                              "Disassembly": [{"addr": 12, "size": "bad"}],
                              "Xrefs": [{"src": [], "dst": 3}]})
        self.assertEqual(index.resolve(12), Location(12))
        self.assertIsNone(index.location_for_row("Functions", 0))
        with self.assertRaises(ValueError):
            index.resolve(-1)

    def test_same_offset_and_symbol_in_dex_members_remain_ambiguous(self) -> None:
        rows = {"Functions": [
            {"name": "Lx;->main", "descriptor": "()V", "start": 128, "code_offset": 128,
             "source": "classes.dex", "kind": "dex", "bytecode_length": 8},
            {"name": "Lx;->main", "descriptor": "()V", "start": 128, "code_offset": 128,
             "source": "classes2.dex", "kind": "dex", "bytecode_length": 8}],
            "Disassembly": [
                {"addr": 144, "size": 4, "source": "classes.dex", "arch_meta": {
                    "arch": "dex", "address_space": "file_offset", "container_member": "classes.dex"}},
                {"addr": 144, "size": 4, "source": "classes2.dex", "arch_meta": {
                    "arch": "dex", "address_space": "file_offset", "container_member": "classes2.dex"}}]}
        index = AddressIndex(rows, kind="apk")
        for query in (128, 146, "Lx;->main", "Lx;->main()V"):
            with self.assertRaises(AmbiguousLocationError):
                index.resolve(query)
        location = index.resolve(146, source="classes2.dex", address_space="file_offset")
        self.assertEqual(index.function_at(location).row_index, 1)
        self.assertEqual(index.find_targets(location, table="Disassembly")[0].row_index, 1)
        self.assertEqual(index.resolve("Lx;->main()V", source="classes.dex"),
                         Location(128, "classes.dex", "file_offset"))

    def test_jvm_overloads_use_descriptor_and_api_calls_do_not_guess(self) -> None:
        rows = {"Functions": [
            {"name": "x->main", "descriptor": "()V", "start": 100, "source": "x.class", "kind": "jvm"},
            {"name": "x->main", "descriptor": "(I)V", "start": 200, "source": "x.class", "kind": "jvm"}],
            "API Calls": [
                {"source": "x.class", "addr": 300, "target": "x->main", "descriptor": "()V"},
                {"source": "x.class", "addr": 304, "target": "x->main"}]}
        index = AddressIndex(rows, kind="class")
        with self.assertRaises(AmbiguousLocationError):
            index.resolve("x->main")
        first = index.resolve("x->main()V")
        self.assertEqual(first, Location(100, "x.class", "file_offset"))
        incoming, = index.incoming(first)
        self.assertEqual(incoming.src.address, 300)
        unresolved, = index.outgoing(Location(304, "x.class", "file_offset"))
        self.assertIsNone(unresolved.dst)
        self.assertEqual(unresolved.target, "x->main")

    def test_xref_endpoint_spaces_and_members_are_kept_separate(self) -> None:
        index = AddressIndex({"Xrefs": [
            {"src": 16, "dst": 20, "src_space": "file_offset", "dst_space": "file_offset",
             "src_source": "a.dex", "dst_source": "b.dex", "kind": "call"}]}, kind="apk")
        src, dst = Location(16, "a.dex", "file_offset"), Location(20, "b.dex", "file_offset")
        self.assertEqual(index.resolve(src), src)
        self.assertEqual(index.resolve(dst), dst)
        self.assertEqual(index.outgoing(src)[0].dst, dst)
        self.assertEqual(index.incoming(dst)[0].src, src)

    def test_native_string_uses_virtual_address_and_keeps_file_offset_alias(self) -> None:
        string = {"offset": 0x2010, "address": 0x402010, "address_space": "native",
                  "value": "hello", "length": 5}
        rows = {"Strings": [string], "Xrefs": [
            {"src": 0x401000, "dst": 0x402010, "kind": "data"},
            {"src": 0x401008, "dst": 0x402012, "kind": "data"},
            {"src": 0x401010, "dst": 0x402015, "kind": "data"}]}
        index = AddressIndex(rows, kind="elf")
        self.assertEqual(index.location_for_row("Strings", 0), Location(0x402010))
        self.assertEqual(index.location_for_row("Strings", 0, "offset"),
                         Location(0x2010, address_space="file_offset"))
        references = index.incoming(Location(0x402010))
        self.assertEqual([item.dst.address for item in references], [0x402010, 0x402012])
        self.assertIs(references[1], index.outgoing(Location(0x401008))[0])
        self.assertEqual(index.incoming(Location(0x2010, address_space="file_offset")), ())
        target, = index.find_targets(Location(0x402012), table="Strings")
        self.assertEqual((target.row_index, target.location, target.field),
                         (0, Location(0x402010), "address"))
        self.assertEqual(index.resolve(0x402012), Location(0x402012))
        self.assertEqual(index.find_targets(Location(0x402015), table="Strings"), ())
        self.assertEqual(string, {"offset": 0x2010, "address": 0x402010,
            "address_space": "native", "value": "hello", "length": 5})

    def test_old_string_records_map_completed_sections_without_loading_source(self) -> None:
        string = {"offset": 0x2010, "length": 5, "value": "hello"}
        sections = [{"name": ".rodata", "offset": 0x2000, "address": 0x402000,
                     "size": 0x80, "file_size": 0x80, "allocated": True}]
        rows = {"Sections": sections, "Strings": [string], "Xrefs": [
            {"src": 0x401000, "dst": 0x402014, "kind": "data"}]}
        with patch("copy.deepcopy", side_effect=AssertionError("不得复制分析图")), \
             patch("builtins.open", side_effect=AssertionError("旧数据库导航不能读取原文件")):
            index = AddressIndex(rows, kind="elf")
            self.assertEqual(index.location_for_row("Strings", 0), Location(0x402010))
            self.assertEqual(index.incoming(Location(0x402010))[0].dst, Location(0x402014))
        self.assertNotIn("address", string)
        self.assertIs(index._rows["Strings"][0], string)

    def test_unmapped_strings_do_not_gain_false_native_locations(self) -> None:
        rows = {"Sections": [
            {"offset": 0x100, "address": 0x400100, "size": 0x20, "allocated": False},
            {"offset": 0x200, "address": 0x400200, "size": 0x20, "file_backed": False},
            {"offset": 0x300, "address": 0x400300, "size": 0x20, "type": 8}],
            "Strings": [{"offset": offset, "length": 4} for offset in (0x100, 0x200, 0x300)]}
        index = AddressIndex(rows, kind="elf")
        for position, offset in enumerate((0x100, 0x200, 0x300)):
            self.assertEqual(index.location_for_row("Strings", position),
                             Location(offset, address_space="file_offset"))
            self.assertEqual(index.locations_for_row("Strings", position, "address"), ())
            self.assertEqual(index.find_targets(Location(offset + 0x400000), table="Strings"), ())

    def test_string_members_keep_their_own_offsets_and_reference_ranges(self) -> None:
        rows = {"Sections": [{"offset": 0, "address": 0x400000, "size": 0x1000}],
            "Strings": [{"offset": 0x80, "length": 4, "value": "text", "source": member}
                        for member in ("classes.dex", "classes2.dex")],
            "Xrefs": [{"src": 0x100, "dst": 0x82, "kind": "string",
                       "src_space": "file_offset", "dst_space": "file_offset",
                       "src_source": "classes.dex", "dst_source": "classes.dex"}]}
        index = AddressIndex(rows, kind="apk")
        first = Location(0x80, "classes.dex", "file_offset")
        second = Location(0x80, "classes2.dex", "file_offset")
        self.assertEqual(index.location_for_row("Strings", 0), first)
        self.assertEqual(index.location_for_row("Strings", 1), second)
        self.assertEqual(index.incoming(first)[0].dst, Location(0x82, "classes.dex", "file_offset"))
        self.assertEqual(index.incoming(second), ())
        self.assertEqual(index.incoming(Location(0x400080)), ())
        with self.assertRaises(AmbiguousLocationError):
            index.resolve(0x82)
        target, = index.find_targets(Location(0x82, "classes.dex", "file_offset"), table="Strings")
        self.assertEqual(target.location, first)

    def test_multiple_string_mappings_report_ambiguity_and_keep_exact_alias(self) -> None:
        string = {"offset": 0x10, "addresses": [0x401010, 0x501010], "length": 4}
        index = AddressIndex({"Strings": [string], "Xrefs": [
            {"src": 0x1000, "dst": 0x401012, "kind": "data"},
            {"src": 0x1008, "dst": 0x501013, "kind": "data"}]}, kind="elf")
        with self.assertRaises(AmbiguousLocationError) as raised:
            index.location_for_row("Strings", 0)
        self.assertEqual(raised.exception.candidates, (Location(0x401010), Location(0x501010)))
        self.assertEqual(index.location_for_row("Strings", 0, "offset"),
                         Location(0x10, address_space="file_offset"))
        for start in (0x401010, 0x501010):
            target, = index.find_targets(Location(start + 2), table="Strings")
            self.assertEqual(target.location, Location(start))
            references = index.incoming(Location(start))
            self.assertEqual(len(references), 1)
            self.assertTrue(start <= references[0].dst.address < start + 4)

    def test_old_string_overlapping_mappings_do_not_pick_the_first_section(self) -> None:
        index = AddressIndex({"Strings": [{"offset": 0x10, "length": 4}], "Sections": [
            {"offset": 0, "address": 0x400000, "size": 0x100, "allocated": True},
            {"offset": 0, "address": 0x500000, "size": 0x100, "allocated": True}]}, kind="elf")
        with self.assertRaises(AmbiguousLocationError):
            index.location_for_row("Strings", 0)
        self.assertEqual(index.locations_for_row("Strings", 0, "address"),
                         (Location(0x400010), Location(0x500010)))

    def test_string_byte_length_controls_interior_reference_boundary(self) -> None:
        index = AddressIndex({"Strings": [{"offset": 0x10, "address": 0x400010,
                                             "length": 1, "byte_length": 3, "value": "中"}],
                              "Xrefs": [{"src": 0x1000, "dst": 0x400012, "kind": "data"},
                                        {"src": 0x1008, "dst": 0x400013, "kind": "data"}]})
        reference, = index.incoming(Location(0x400010))
        self.assertEqual(reference.dst.address, 0x400012)
        target, = index.find_targets(Location(0x400012), table="Strings")
        self.assertEqual(target.location, Location(0x400010))
        self.assertEqual(index.find_targets(Location(0x400013), table="Strings"), ())

    def test_named_strings_keep_symbol_navigation_and_multi_mapping_ambiguity(self) -> None:
        index = AddressIndex({"Strings": [
            {"name": "file_text", "offset": 0x10},
            {"name": "loaded_text", "offset": 0x20, "address": 0x400020},
            {"name": "ambiguous_text", "offset": 0x30, "addresses": [0x400030, 0x500030]}]})
        self.assertEqual(index.resolve("file_text"), Location(0x10, address_space="file_offset"))
        self.assertEqual(index.resolve("loaded_text"), Location(0x400020))
        with self.assertRaises(AmbiguousLocationError):
            index.resolve("ambiguous_text")

    def test_declared_string_mapping_range_stops_at_file_backed_boundary(self) -> None:
        index = AddressIndex({"Strings": [{"offset": 0x20E, "address": 0x40020E,
            "length": 10, "address_ranges": ((0x40020E, 2),)}], "Xrefs": [
            {"src": 0x1000, "dst": 0x40020F, "kind": "data"},
            {"src": 0x1008, "dst": 0x400210, "kind": "data"},
            {"src": 0x1010, "dst": 0x216, "kind": "data", "dst_space": "file_offset"}]}, kind="elf")
        reference, = index.incoming(Location(0x40020E))
        self.assertEqual(reference.dst.address, 0x40020F)
        self.assertEqual(index.find_targets(Location(0x400210), table="Strings"), ())
        file_reference, = index.incoming(Location(0x20E, address_space="file_offset"))
        self.assertEqual(file_reference.dst, Location(0x216, address_space="file_offset"))
        file_target, = index.find_targets(Location(0x216, address_space="file_offset"), table="Strings")
        self.assertEqual(file_target.location, Location(0x20E, address_space="file_offset"))

    def test_old_string_crossing_sections_or_bss_has_only_its_mapped_prefix(self) -> None:
        for following in ({"offset": 0x210, "address": 0x500000, "size": 0x20, "allocated": True},
                          {"offset": 0x210, "address": 0x400210, "size": 0x20, "type": 8}):
            with self.subTest(following=following):
                index = AddressIndex({"Strings": [{"offset": 0x20E, "length": 10}],
                    "Sections": [{"offset": 0x200, "address": 0x400200, "size": 0x10,
                                  "file_size": 0x10, "allocated": True}, following],
                    "Xrefs": [{"src": 0x1000, "dst": 0x40020F, "kind": "data"},
                              {"src": 0x1008, "dst": 0x400210, "kind": "data"}]}, kind="elf")
                self.assertEqual(index.location_for_row("Strings", 0), Location(0x40020E))
                reference, = index.incoming(Location(0x40020E))
                self.assertEqual(reference.dst, Location(0x40020F))
                self.assertEqual(index.find_targets(Location(0x400210), table="Strings"), ())
                self.assertEqual(index.find_targets(Location(0x500000), table="Strings"), ())
                self.assertEqual(len(index.find_targets(Location(0x217, address_space="file_offset"),
                                                       table="Strings")), 1)

    def test_old_pe_string_range_excludes_unmapped_raw_padding(self) -> None:
        index = AddressIndex({"Strings": [{"offset": 0x206, "length": 10}],
            "Sections": [{"offset": 0x200, "address": 0x400200, "size": 0x20,
                          "file_size": 0x20, "virtual_size": 8, "file_backed": True}],
            "Xrefs": [{"src": 0x1000, "dst": 0x400207, "kind": "data"},
                      {"src": 0x1008, "dst": 0x400208, "kind": "data"}]}, kind="pe")
        self.assertEqual(index.location_for_row("Strings", 0), Location(0x400206))
        reference, = index.incoming(Location(0x400206))
        self.assertEqual(reference.dst, Location(0x400207))
        self.assertEqual(index.find_targets(Location(0x400208), table="Strings"), ())
        self.assertEqual(len(index.find_targets(Location(0x20F, address_space="file_offset"),
                                               table="Strings")), 1)

    def test_explicit_legacy_string_address_keeps_declared_length_without_range_field(self) -> None:
        index = AddressIndex({"Strings": [{"offset": 0x206, "address": 0x400206, "length": 10}],
            "Sections": [{"offset": 0x200, "address": 0x400200, "size": 8, "file_size": 8}],
            "Xrefs": [{"src": 0x1000, "dst": 0x40020F, "kind": "data"}]}, kind="elf")
        reference, = index.incoming(Location(0x400206))
        self.assertEqual(reference.dst, Location(0x40020F))
        self.assertEqual(len(index.find_targets(Location(0x40020F), table="Strings")), 1)


if __name__ == "__main__":
    unittest.main()
