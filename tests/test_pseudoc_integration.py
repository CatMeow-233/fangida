"""伪 C 联调：名字（符号/链接证据）、调用实参与字面量、展示层之间的接口约定。

覆盖整合时补上的几处衔接：
- 伪 C 使用源码级名字（display_name，Mach-O 去掉前导下划线），原始符号仍留在记录中；
- 经指针槽位（IAT/GOT）的已核实调用点按导入名渲染，并按已知原型给出实参；
- 导入桩自身的间接跳转写成到导入函数的尾跳转，桩读取槽位的无效果读被删除；
- PE 的 UTF-16LE 宽字符串还原为 L"..."，不再被截成首字符；
- 返回值全是同一种指针（字符串字面量、字符串指针表）时返回类型写成该指针类型；
- 函数头与 GUI 状态把“到已知函数的尾跳转”与真正未解析的控制流分开。
"""
from __future__ import annotations

import os
import tempfile
import unittest

from fangida.gui_modules.pseudocode import build_header, format_header, status_flags
from fangida.models import AnalysisResult
from fangida.plugins.pseudoc.datarefs import DataReferences
from fangida.plugins.pseudoc.pipeline import display_name, populate_native_pseudoc
from fangida.plugins.pseudoc.reconstruct import _header_line
from fangida.plugins.pseudoc.reconstruct.expressions import format_value
from fangida.plugins.pseudoc.reconstruct.model import Statement, Value
from fangida.plugins.pseudoc.reconstruct.prototypes import lookup
from fangida.plugins.pseudoc.reconstruct.readability import refine_return_type, simplify_statements
from fangida.plugins.pseudoc.reconstruct.model import Block
from tests.test_symbol_names import TEXT, function, macho_result, pe_result, row


def _caller_with_iat_call():
    return [row(0x140001000, "sub", "rsp", "0x28", size=4),
            row(0x140001004, "mov", "ecx", "0x2a", size=5),
            row(0x140001009, "call", "qword ptr [rip + 0x1ff1]", size=6, kind="call"),
            row(0x14000100f, "add", "rsp", "0x28", size=4),
            row(0x140001013, "ret", size=1, kind="return")]


class DisplayNameTests(unittest.TestCase):
    def test_display_name_prefers_loader_source_name(self):
        self.assertEqual(display_name({"name": "_main", "display_name": "main"}), "main")
        self.assertEqual(display_name({"name": "puts"}), "puts")
        self.assertEqual(display_name({"name": "_x", "display_name": ""}), "_x")
        self.assertEqual(display_name(None), "function")

    def test_macho_stub_and_callers_use_source_names(self):
        stub = [row(TEXT + 0x420, "jmp", "qword ptr [rip + 0xbda]", size=6, kind="jump", refs=[TEXT + 0x1000])]
        result = macho_result(stub)
        populate_native_pseudoc(result)
        caller, thunk = result.functions
        self.assertRegex(caller["pseudoc"], r"\bputs\(")
        self.assertNotIn("_puts", caller["pseudoc"])
        # 原始符号仍留在链接证据中（只增不删）。
        self.assertEqual(result.metadata["pseudoc_linkage"][0]["name"], "_puts")
        # 桩自身：签名取库函数原型，函数体是到导入函数的尾跳转，槽位读被删除。
        self.assertIn("int32_t puts(const char * str)", thunk["pseudoc"])
        self.assertIn("tail_transfer(puts, str);", thunk["pseudoc"])
        self.assertNotIn("(void)*", thunk["pseudoc"])
        header = thunk["pseudoc"].splitlines()[0]
        self.assertIn("名字：导入桩（链接信息）", header)
        self.assertIn("导入桩：尾跳转到导入函数 puts", header)
        self.assertNotIn("不完整", header)
        unresolved = thunk["pseudoc_reconstruction"]["unresolved"]
        self.assertEqual([item.get("import_name") for item in unresolved], ["puts"])
        self.assertEqual(status_flags(thunk), "完整")


class ImportSlotCallTests(unittest.TestCase):
    def test_pe_call_through_iat_is_named_with_prototype_arguments(self):
        result = pe_result(_caller_with_iat_call())
        populate_native_pseudoc(result)
        caller = result.functions[0]
        self.assertIn("ExitProcess(42);", caller["pseudoc"])
        self.assertNotIn("indirect_call", caller["pseudoc"])
        call = caller["pseudoc_reconstruction"]["calls"][0]
        self.assertEqual((call["name"], call["target"], call["import_slot"], call["target_kind"]),
                         ("ExitProcess", None, 0x140003000, "import_pointer_slot"))
        self.assertTrue(call["argument_count_known"])
        # 槽位地址不是代码地址：不进入函数名表（常量不会被写成 ExitProcess）。
        self.assertFalse(any(item.get("target") == 0x140003000 and item.get("target_kind") == "linkage_thunk"
                             for item in result.metadata["pseudoc_linkage"]))
        text = format_header(build_header(caller)).text
        self.assertIn("ExitProcess（导入）", text)

    def test_unverified_indirect_call_stays_indirect(self):
        caller = [row(0x140001000, "mov", "rax", "qword ptr [rcx]", size=3),
                  row(0x140001003, "call", "rax", size=2, kind="call"),
                  row(0x140001005, "ret", size=1, kind="return")]
        result = pe_result(caller)
        populate_native_pseudoc(result)
        self.assertIn("indirect_call(", result.functions[0]["pseudoc"])

    def test_tail_jump_through_slot_is_described_in_header(self):
        tail = [row(0x140001100, "jmp", "qword ptr [rip + 0x1efa]", size=6, kind="jump")]
        result = pe_result(tail)
        populate_native_pseudoc(result)
        text = result.functions[0]["pseudoc"]
        self.assertIn("tail_transfer(ExitProcess, ", text)
        self.assertIn("尾跳转到导入函数 ExitProcess", text.splitlines()[0])
        self.assertNotIn("未解析跳转", text.splitlines()[0])


class WideStringTests(unittest.TestCase):
    def _references(self, payload, kind="pe", flags=0x40000040):
        handle = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(os.unlink, handle.name)
        handle.write(payload)
        handle.close()
        section = {"name": ".rdata", "address": 0x140002000, "offset": 0, "size": len(payload),
                   "section_flags": flags}
        references = DataReferences([section], kind=kind, path=handle.name, size=len(payload))
        self.addCleanup(references.close)
        return references

    def test_utf16_string_is_read_whole(self):
        payload = b"\0\0" + "mscoree.dll".encode("utf-16-le") + b"\0\0" + b"ok\0"
        references = self._references(payload)
        found = references.get(0x140002002)
        self.assertEqual((found["value"], found["encoding"]), ("mscoree.dll", "utf-16le"))
        self.assertIsNone(references.get(0x140002003))        # 奇地址：宽字符串中间，不是窄空串
        self.assertIsNone(references.get(0x140002004))        # 宽字符串中间（前两字节不是 NUL）
        narrow = references.get(0x140002002 + len("mscoree.dll") * 2 + 2)
        self.assertEqual((narrow["value"], narrow.get("encoding")), ("ok", None))

    def test_wide_detection_is_pe_only(self):
        payload = b"\0\0" + "ab".encode("utf-16-le") + b"\0\0"
        section = {"name": ".rodata", "address": 0x2000, "offset": 0, "size": len(payload), "type": 1}
        handle = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(os.unlink, handle.name)
        handle.write(payload)
        handle.close()
        references = DataReferences([section], kind="elf", path=handle.name, size=len(payload))
        self.addCleanup(references.close)
        self.assertIsNone(references.get(0x2002))            # ELF：按窄串只有 1 个字符，不还原

    def test_wide_literal_prints_with_l_prefix_and_types(self):
        literal = Value("string_literal", 64, name="a\"b", number=0x1000, ctype="const wchar_t *")
        self.assertEqual(format_value(literal), 'L"a\\"b"')
        prototype = lookup("GetModuleHandleW")
        self.assertEqual(prototype.parameters, (("module_name", "const wchar_t *"),))
        self.assertEqual(lookup("_GetProcAddress").name, "GetProcAddress")


class ReturnTypeTests(unittest.TestCase):
    def test_string_returns_and_string_table_load_become_char_pointer(self):
        literal = Value("cast", 64, (Value("string_literal", 64, name="unknown", number=0x1000, ctype="const char *"),),
                        ctype="uint64_t")
        table = Value("index", 64, (Value("cast", 64, (Value("constant", 64, number=0x4030),), ctype="uint64_t *"),
                                    Value("variable", 64, name="i", ctype="uint64_t")), ctype="uint64_t")
        returns = [Statement("return", literal), Statement("return", table)]
        self.assertEqual(refine_return_type(returns, "uint64_t"), "const char *")
        self.assertEqual(format_value(returns[0].value), '"unknown"')
        self.assertEqual(returns[1].value.ctype, "const char *")
        self.assertEqual(returns[1].value.args[0], table)     # 只加类型转换，读本身不变

    def test_integer_returns_keep_their_type(self):
        literal = Value("string_literal", 64, name="x", number=0x1000, ctype="const char *")
        mixed = [Statement("return", literal), Statement("return", Value("add", 64, (
            Value("variable", 64, name="a", ctype="uint64_t"), Value("constant", 64, number=1)), ctype="uint64_t"))]
        self.assertEqual(refine_return_type(mixed, "uint64_t"), "uint64_t")
        self.assertIs(mixed[0].value, literal)
        only_loads = [Statement("return", Value("load", 64, (Value("constant", 64, number=0x4000),), ctype="uint64_t"))]
        self.assertEqual(refine_return_type(only_loads, "uint64_t"), "uint64_t")   # 没有指针证据
        self.assertEqual(refine_return_type([Statement("return", literal)], "uint32_t"), "uint32_t")


class SlotReadTests(unittest.TestCase):
    def test_discarded_read_of_import_slot_is_removed_only_for_known_slots(self):
        def block():
            read = Value("index", 64, (Value("cast", 64, (Value("constant", 64, number=0x5000),), ctype="uint64_t *"),
                                       Value("constant", 64, number=1)), ctype="uint64_t", effect=True)
            return {0: Block(0, statements=[Statement("expression", read)])}
        kept = block()
        simplify_statements(kept, {}, "void", readable_addresses=frozenset({0x5000}))
        self.assertEqual(len(kept[0].statements), 1)           # 0x5008 不是已核实槽位
        removed = block()
        simplify_statements(removed, {}, "void", readable_addresses=frozenset({0x5008}))
        self.assertEqual(removed[0].statements, [])


class PrintfArgumentTests(unittest.TestCase):
    def test_printf_int_argument_positions(self):
        from fangida.plugins.pseudoc.reconstruct.prototypes import printf_int_arguments
        self.assertEqual(printf_int_arguments("total=%d %s\n"), (True, False))
        self.assertEqual(printf_int_arguments("%*.*x %hhu %c %ld %zu %p %%"), (True, True, True, True, True, False, False, False))
        self.assertIsNone(printf_int_arguments("%f"))       # 浮点：不处理
        self.assertIsNone(printf_int_arguments("%1$d"))     # 位置参数：不处理
        self.assertIsNone(printf_int_arguments("%"))

    def test_widening_casts_on_int_arguments_are_removed(self):
        from fangida.plugins.pseudoc.reconstruct.readability import simplify_value
        argc = Value("variable", 32, name="argc", ctype="int32_t")
        widened = Value("cast", 64, (Value("cast", 32, (argc,), ctype="uint32_t"),), ctype="uint64_t")
        narrow = Value("cast", 64, (Value("cast", 8, (argc,), ctype="uint8_t"),), ctype="uint64_t")
        fmt = Value("string_literal", 64, name="%d %c", number=0x1000, ctype="const char *")
        call = Value("call", 32, (fmt, widened, narrow), name="printf", ctype="int32_t", effect=True)
        self.assertEqual(format_value(simplify_value(call)), 'printf("%d %c", argc, (uint8_t)argc)')
        # 实参个数与格式串不一致（或尾部未知）时保持原样。
        short = Value("call", 32, (fmt, widened), name="printf", ctype="int32_t", effect=True)
        self.assertIn("(uint64_t)", format_value(simplify_value(short)))
        wide = Value("string_literal", 64, name="%ld", number=0x1000, ctype="const char *")
        long_call = Value("call", 32, (wide, widened), name="printf", ctype="int32_t", effect=True)
        self.assertIn("(uint64_t)", format_value(simplify_value(long_call)))


class AddressWritebackTests(unittest.TestCase):
    def test_post_and_pre_index_base_updates_are_lowered(self):
        from fangida.plugins.pseudoc import generate_pseudoc
        from tests.test_pseudoc import function as fn, instruction as ins
        from tests.test_reconstruction import compile_run
        rows = [ins(0, "mov", "w8", "#0", size=4), ins(4, "ldr", "w9", "[x0]", "#4", size=4),
                ins(8, "add", "w8", "w8", "w9", size=4), ins(12, "subs", "x1", "x1", "#1", size=4),
                ins(16, "b.ne", "#0x4", kind="jump", target=4, conditional=True, size=4),
                ins(20, "mov", "w0", "w8", size=4), ins(24, "ret", kind="return", size=4)]
        output = generate_pseudoc(fn(*rows, name="sum", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        self.assertNotIn("unresolved_operation", output.pseudoc)
        self.assertNotIn("unknown_value", output.pseudoc)
        compile_run(output.pseudoc, "uint32_t a[3] = {1, 2, 3};\nreturn sum((uint64_t)(uintptr_t)a, 3) == 6 ? 0 : 1;")
        rows = [ins(0, "ldr", "x8", "[x0, #8]!", size=4), ins(4, "ldr", "x9", "[x0, #8]!", size=4),
                ins(8, "add", "x0", "x8", "x9", size=4), ins(12, "ret", kind="return", size=4)]
        output = generate_pseudoc(fn(*rows, name="pre", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        self.assertNotIn("unresolved_operation", output.pseudoc)
        compile_run(output.pseudoc, "uint64_t b[3] = {5, 9, 30};\nreturn pre(b) == 39 ? 0 : 1;")

    def test_stack_pointer_and_register_offsets_stay_unresolved(self):
        from fangida.plugins.pseudoc import generate_pseudoc
        from tests.test_pseudoc import function as fn, instruction as ins
        rows = [ins(0, "ld1", "{v0.4s}", "[x0]", "x2", size=4), ins(4, "ret", kind="return", size=4)]
        output = generate_pseudoc(fn(*rows, name="vec", pseudoc_context={"kind": "elf"}), "arm64", style="readable")
        self.assertIn("unresolved_operation", output.pseudoc)


class HeaderTests(unittest.TestCase):
    def test_named_tail_call_with_unknown_arguments_is_still_incomplete(self):
        report = {"complete": False, "unresolved": [
            {"address": 0x10, "kind": "control_flow_target", "transfer_kind": "jump", "target": 0x40,
             "target_name": "zsh_main", "arguments_known": False}]}
        header = _header_line({"name": "_main", "source": "symtab"}, {}, "main", 0x0, report, True, False,
                              frozenset({0x10}))
        self.assertEqual(header, "// 0x0 main | 名字：符号表（_main） | 不完整：1 处调用参数个数未知 | 尾调用 zsh_main")

    def test_unexplained_frontier_keeps_snapshot_note(self):
        report = {"complete": False, "unresolved": [
            {"address": 0x10, "kind": "control_flow_target", "transfer_kind": "jump", "target": 0x40,
             "target_name": "helper", "arguments_known": True}]}
        header = _header_line({"name": "f", "source": "symtab"}, {}, "f", 0x0, report, True, False,
                              frozenset({0x10, 0x20}))
        self.assertIn("指令快照不完整", header)
        self.assertIn("尾调用 helper", header)


if __name__ == "__main__":
    unittest.main()
