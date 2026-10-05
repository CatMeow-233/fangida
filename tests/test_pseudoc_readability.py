"""伪 C 可读性：调用实参、字面量、去噪、命名、结构化与函数头注释。

每项可读性改写都必须保持机器语义：能编译的用例一律编译运行比对；
无法证明的部分（未知格式串、未知调用目标）保留原有保守写法。
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.datarefs import DataReferences, decode_literal
from fangida.plugins.pseudoc.reconstruct.expressions import c_string_literal, format_number, format_value
from fangida.plugins.pseudoc.reconstruct.model import Value
from fangida.plugins.pseudoc.reconstruct.prototypes import format_arguments, lookup, normalize_name
from fangida.plugins.pseudoc.reconstruct.readability import simplify_value
from tests.test_pseudoc import function as fn, instruction as ins
from tests.test_reconstruction import compile_run


def x86(*rows, name="example", context=None, **fields):
    return generate_pseudoc(fn(*rows, name=name, pseudoc_context={"kind": "elf", **(context or {})}, **fields),
                            "x86_64", style="readable")


def arm(*rows, name="example", context=None, kind="elf", **fields):
    return generate_pseudoc(fn(*rows, name=name, pseudoc_context={"kind": kind, **(context or {})}, **fields),
                            "arm64", style="readable")


def body(output):
    """去掉首行函数头注释后的伪 C。"""
    return output.pseudoc.split("\n", 1)[1]


STRINGS = {0x402010: {"kind": "string", "value": "access granted"},
           0x402020: {"kind": "string", "value": "total=%d %s\n"},
           0x402030: {"kind": "string", "value": "ok"},
           0x402040: {"kind": "string", "value": "%1$s"}}
LIBC = {0x500: {"name": "puts"}, 0x510: {"name": "printf"}, 0x520: {"name": "strlen"}, 0x530: {"name": "malloc"},
        0x540: {"name": "_atexit"}}


class CallArgumentTests(unittest.TestCase):
    def test_known_prototype_shows_string_argument_and_discards_result_without_cast(self):
        output = x86(ins(0, "mov", "edi", "0x402010"), ins(1, "call", "0x500", kind="call", target=0x500),
                     ins(2, "xor", "eax", "eax"), ins(3, "ret", kind="return"),
                     context={"data_references": STRINGS, "callees": LIBC})
        self.assertIn('    puts("access granted");', output.pseudoc)
        self.assertNotRegex(output.pseudoc, r"\(u?int\d+_t\)\s*\(?puts")
        call = output.reconstruction["calls"][0]
        self.assertEqual((call["argument_evidence"], call["argument_count_known"], call["prototype"]),
                         ("known_prototype", True, "puts"))
        self.assertTrue(output.reconstruction["complete"])

    def test_printf_argument_count_follows_format_string(self):
        output = x86(ins(0, "mov", "edi", "0x402020"), ins(1, "mov", "esi", "12"), ins(2, "mov", "edx", "0x402030"),
                     ins(3, "mov", "ecx", "99"), ins(4, "xor", "eax", "eax"), ins(5, "call", "0x510", kind="call", target=0x510),
                     ins(6, "ret", kind="return"), context={"data_references": STRINGS, "callees": LIBC})
        self.assertIn('printf("total=%d %s\\n", 12, "ok");', output.pseudoc)
        self.assertNotIn("unknown_arguments", output.pseudoc)
        self.assertNotIn("99", output.pseudoc)  # 格式串只用两个实参：rcx 不是实参
        call = output.reconstruction["calls"][0]
        self.assertEqual((call["variadic_argument_count"], call["recovered_argument_count"]), (2, 3))
        self.assertTrue(call["argument_count_known"])

    def test_unparsable_or_unknown_format_keeps_unknown_tail(self):
        for format_address in ("0x402040", "0x999999"):
            with self.subTest(format=format_address):
                output = x86(ins(0, "mov", "edi", format_address), ins(1, "mov", "esi", "7"),
                             ins(2, "call", "0x510", kind="call", target=0x510), ins(3, "ret", kind="return"),
                             context={"data_references": STRINGS, "callees": LIBC})
                self.assertRegex(output.pseudoc, r"printf\(.*unknown_arguments\(\)\)")
                self.assertFalse(output.reconstruction["calls"][0]["argument_count_known"])
                self.assertIn("call_signature", {item["kind"] for item in output.reconstruction["unresolved"]})

    def test_apple_arm64_variadic_arguments_are_read_from_outgoing_stack_slots(self):
        rows = (ins(0, "sub", "sp", "sp", "#0x20", size=4), ins(4, "mov", "w9", "#0xc", size=4),
                ins(8, "adrp", "x8", "#0x402000", size=4), ins(12, "add", "x8", "x8", "#0x30", size=4),
                ins(16, "stp", "x9", "x8", "[sp]", size=4), ins(20, "adrp", "x0", "#0x402000", size=4),
                ins(24, "add", "x0", "x0", "#0x20", size=4), ins(28, "bl", "0x510", size=4, kind="call", target=0x510),
                ins(32, "mov", "w0", "#0", size=4), ins(36, "add", "sp", "sp", "#0x20", size=4),
                ins(40, "ret", size=4, kind="return"))
        output = arm(*rows, kind="macho", context={"data_references": STRINGS, "callees": LIBC})
        self.assertIn('printf("total=%d %s\\n", 12, "ok");', output.pseudoc)
        # ELF/Linux 的 AAPCS64 可变参数走寄存器：同样的代码不能从栈槽取实参。
        linux = arm(*rows, kind="elf", context={"data_references": STRINGS, "callees": LIBC})
        self.assertNotIn('"ok"', linux.pseudoc)

    def test_unknown_target_keeps_unknown_arguments(self):
        output = x86(ins(0, "mov", "edi", "4"), ins(1, "call", "0x20", kind="call", target=32), ins(2, "ret", kind="return"))
        self.assertIn("unknown_function(4, unknown_arguments())", output.pseudoc)

    def test_incomplete_summary_lists_only_explicitly_defined_argument_registers(self):
        summary = {32: {"name": "helper", "parameters": [{"register": "x0"}], "signature_complete": False,
                        "argument_uses_complete": False, "return_type": "uint64_t"}}
        explicit = arm(ins(0, "mov", "x0", "#4", size=4), ins(4, "mov", "x1", "#5", size=4),
                       ins(8, "bl", "0x20", size=4, kind="call", target=32), ins(12, "ret", size=4, kind="return"),
                       context={"callees": summary})
        self.assertIn("helper(4, 5, unknown_arguments())", explicit.pseudoc)
        incoming = arm(ins(0, "mov", "x0", "#4", size=4), ins(4, "add", "x2", "x1", "#1", size=4),
                       ins(8, "bl", "0x20", size=4, kind="call", target=32), ins(12, "ret", size=4, kind="return"),
                       context={"callees": summary})
        self.assertIn("helper(4, unknown_arguments())", incoming.pseudoc)

    def test_format_string_argument_counting(self):
        self.assertEqual(format_arguments("total=%d %s\n"), (2, 0))
        self.assertEqual(format_arguments("%%d %5.2f %*d %-08lld|%zu"), (4, 1))
        self.assertIsNone(format_arguments("%1$s"))
        self.assertIsNone(format_arguments("bad %"))
        self.assertEqual(format_arguments("%d %*d %[^,] %s", "scanf"), (3, 0))

    def test_prototype_names_are_normalized(self):
        for name in ("puts", "_puts", "puts@GLIBC_2.2.5", "__imp_puts"):
            with self.subTest(name=name):
                self.assertEqual(normalize_name(name), "puts")
                self.assertEqual(lookup(name).parameters, (("str", "const char *"),))
        self.assertEqual(lookup("___stack_chk_fail").name, "__stack_chk_fail")
        self.assertIsNone(lookup("my_function"))

    def test_main_definition_names_parameters(self):
        output = arm(ins(0, "ldr", "x0", "[x1, #8]", size=4), ins(4, "ret", size=4, kind="return"), name="_main")
        self.assertIn("int32_t _main(int32_t argc, char ** argv)", output.pseudoc)
        self.assertIn("argv[1]", output.pseudoc)


class LiteralTests(unittest.TestCase):
    def test_c_string_literal_escaping(self):
        self.assertEqual(c_string_literal('a"b\\c\n\t\x01?? é'), '"a\\"b\\\\c\\n\\t\\001?\\? é"')
        self.assertEqual(c_string_literal("\x1b[0m"), '"\\033[0m"')
        compile_run('const char *s = "' + c_string_literal('a"b\\c\n\t\x01??')[1:] + ';',
                    'return s[1]==34 && s[3]==92 && s[5]==10 && s[7]==1 && s[8]==63 && s[9]==63 && !s[10] ? 0:1;')

    def test_number_formatting_prefers_hex_for_masks_and_addresses(self):
        self.assertEqual([format_number(value) for value in (0, 9, 12, 255, 1000, 0x1234, 0xffff, -5, -0x1234)],
                         ["0", "9", "12", "255", "1000", "0x1234", "0xffff", "-5", "-0x1234"])
        self.assertEqual(format_number(0xff, hint="bitwise"), "0xff")
        self.assertEqual(format_number(31, hint="count"), "31")
        self.assertEqual(format_number(0x100000000, 64), "0x100000000ULL")
        self.assertEqual(format_number(0xffffffff, 32), "0xffffffffU")
        self.assertEqual(format_number(-(1 << 31), 32), str(-(1 << 31)))
        output = x86(ins(0, "and", "edi", "0xffff"), ins(1, "cmp", "edi", "0x1234"),
                     ins(2, "sete", "al"), ins(3, "movzx", "eax", "al"), ins(4, "ret", kind="return"), name="check")
        self.assertIn("0xffff", output.pseudoc)
        self.assertIn("0x1234", output.pseudoc)
        self.assertNotIn("4660", output.pseudoc)
        compile_run(body(output), "return check(0x11234)==1 && check(0x1235)==0 ? 0:1;",
                    "static uint32_t unknown_value(void) { return 0xdeadbeefU; }\n")

    def test_negative_displacement_is_subtraction(self):
        output = arm(ins(0, "sub", "w0", "w0", "#5", size=4), ins(4, "ret", size=4, kind="return"), name="minus")
        self.assertIn("arg_1 - 5", output.pseudoc)
        compile_run(body(output), "return minus(3)==UINT32_MAX-1 ? 0:1;")

    def test_adrp_add_constant_becomes_string_literal(self):
        output = arm(ins(0, "adrp", "x0", "#0x402000", size=4), ins(4, "add", "x0", "x0", "#0x10", size=4),
                     ins(8, "bl", "0x500", size=4, kind="call", target=0x500), ins(12, "ret", size=4, kind="return"),
                     context={"data_references": STRINGS, "callees": LIBC})
        self.assertIn('puts("access granted")', output.pseudoc)
        self.assertNotIn("0x402010", output.pseudoc)

    def test_function_address_becomes_name(self):
        refs = {0x401600: {"kind": "function", "name": "cleanup"}}
        output = x86(ins(0, "mov", "edi", "0x401600"), ins(1, "call", "0x540", kind="call", target=0x540),
                     ins(2, "xor", "eax", "eax"), ins(3, "ret", kind="return"),
                     context={"data_references": refs, "callees": {0x540: {"name": "atexit"}}})
        self.assertIn("atexit(cleanup);", output.pseudoc)

    def test_integer_prototype_parameter_is_not_turned_into_literal(self):
        refs = {0x402010: {"kind": "string", "value": "looks like text"}, 0x410000: {"kind": "function", "name": "routine"},
                0x2000: {"kind": "function", "name": "low_routine"}}
        output = x86(ins(0, "mov", "edi", "0x402010"), ins(1, "call", "0x530", kind="call", target=0x530),
                     ins(2, "mov", "edi", "0x2000"), ins(3, "call", "0x540", kind="call", target=0x540),
                     ins(4, "mov", "edi", "0x410000"), ins(5, "call", "0x540", kind="call", target=0x540),
                     ins(6, "xor", "eax", "eax"), ins(7, "ret", kind="return"),
                     context={"data_references": refs, "callees": {0x530: {"name": "malloc"}, 0x540: {"name": "atexit"}}})
        self.assertIn("malloc(0x402010);", output.pseudoc)   # size_t 形参：仍是数值
        self.assertIn("atexit((void *)0x2000);", output.pseudoc)  # 低地址不还原成函数名
        self.assertIn("atexit(routine);", output.pseudoc)

    def test_loaded_address_stays_numeric(self):
        output = x86(ins(0, "mov", "eax", "dword ptr [0x402010]"), ins(1, "ret", kind="return"),
                     context={"data_references": STRINGS})
        self.assertNotIn("access granted", output.pseudoc)

    def test_data_references_read_only_nul_terminated_strings_through_loader_sections(self):
        payload = bytearray(0x200)
        payload[0x100:0x10e] = b"hello\tworld\n\0\0"
        payload[0x120:0x124] = b"abc"  # 无 NUL 结尾（到节末尾）
        payload[0x140:0x146] = b"\x01\x02\x03\0\0\0"
        payload[0x180:0x188] = b"rw-data\0"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "image.bin"
            path.write_bytes(bytes(payload))
            sections = [{"name": ".rodata", "address": 0x401100, "offset": 0x100, "size": 0x23, "file_size": 0x23, "executable": False},
                        {"name": ".rodata.str1.1", "address": 0x401140, "offset": 0x140, "size": 0x10, "file_size": 0x10, "executable": False},
                        {"name": ".data", "address": 0x401180, "offset": 0x180, "size": 0x10, "file_size": 0x10, "executable": False},
                        {"name": ".text", "address": 0x400000, "offset": 0, "size": 0x100, "file_size": 0x100, "executable": True}]
            with DataReferences(sections, kind="elf", path=path, size=len(payload), functions={0x400010: "start_routine", 0x400020: "sub_400020"}) as refs:
                self.assertEqual(refs.get(0x401100), {"kind": "string", "value": "hello\tworld\n", "address": 0x401100, "section": ".rodata"})
                self.assertIsNone(refs.get(0x401102))   # 普通 .rodata：不在字符串开头
                self.assertIsNone(refs.get(0x401120))   # 没有 NUL 结尾
                self.assertIsNone(refs.get(0x401140))   # 不可打印
                self.assertEqual(refs.get(0x401143)["value"], "")  # 字面量池里的空串
                self.assertIsNone(refs.get(0x401180))   # 可写数据不是字面量
                self.assertEqual(refs.get(0x400010), {"kind": "function", "name": "start_routine", "address": 0x400010})
                self.assertIsNone(refs.get(0x400020))   # 自动生成的名字不算
                self.assertIsNone(refs.get(-1))
            with DataReferences(sections, kind="elf", path=path, size=len(payload) + 1) as stale:
                self.assertIsNone(stale.get(0x401100))  # 文件已变：整体停用
            with DataReferences(sections, kind="elf", path=Path(tmp) / "missing") as missing:
                self.assertIsNone(missing.get(0x401100))
        self.assertIsNone(decode_literal(b"\xff\xfe"))
        self.assertEqual(decode_literal("中文".encode()), "中文")


class NoiseTests(unittest.TestCase):
    def test_zero_extended_byte_loads_use_index_and_one_conversion(self):
        output = arm(ins(0, "ldrb", "w8", "[x0, #1]", size=4), ins(4, "ldrb", "w9", "[x0]", size=4),
                     ins(8, "add", "w0", "w8", "w9", size=4), ins(12, "ret", size=4, kind="return"), name="pair_sum")
        text = body(output)
        self.assertIn("arg_1[1]", text)
        self.assertNotRegex(text, r"\(uint64_t\)\s*\(\(?uint32_t\)")
        self.assertNotIn("((", text)
        compile_run(text, "uint8_t b[]={200,100}; return pair_sum(b)==300 ? 0:1;")

    def test_register_reused_for_pointer_and_counter_gets_separate_variables(self):
        output = arm(ins(0, "adrp", "x8", "#0x402000", size=4), ins(4, "add", "x8", "x8", "#0x10", size=4),
                     ins(8, "mov", "x0", "x8", size=4), ins(12, "bl", "0x500", size=4, kind="call", target=0x500),
                     ins(16, "mov", "w8", "#0", size=4), ins(20, "add", "w8", "w8", "#3", size=4),
                     ins(24, "mov", "w0", "w8", size=4), ins(28, "ret", size=4, kind="return"),
                     context={"data_references": STRINGS, "callees": LIBC}, name="reuse")
        self.assertIn('puts("access granted");', output.pseudoc)
        self.assertNotRegex(body(output), r"\(u?int\d+_t\)\"")  # 字符串不经整数转换显示

    def test_web_split_keeps_semantics_when_retyped(self):
        # x8 先装 32 位累加值再装 64 位指针：拆成两个变量后编译运行结果不变。
        output = arm(ins(0, "ldrb", "w8", "[x0]", size=4), ins(4, "add", "w8", "w8", "w8", "lsl #5", size=4),
                     ins(8, "and", "w9", "w8", "#0xffff", size=4), ins(12, "add", "x8", "x0", "#2", size=4),
                     ins(16, "ldrb", "w10", "[x8]", size=4), ins(20, "add", "w0", "w9", "w10", size=4),
                     ins(24, "ret", size=4, kind="return"), name="mixed")
        text = body(output)
        compile_run(text, "uint8_t b[]={7,1,250}; return mixed(b)==((7+(7<<5))&0xffff)+250 ? 0:1;")

    def test_loop_counter_is_named_i_and_call_result_after_prototype(self):
        output = x86(ins(0, "xor", "eax", "eax"), ins(1, "xor", "ecx", "ecx"),
                     ins(2, "cmp", "ecx", "edi"), ins(3, "jge", "0x8", kind="jump", target=8, conditional=True),
                     ins(4, "add", "eax", "ecx"), ins(5, "inc", "ecx"), ins(6, "jmp", "0x2", kind="jump", target=2),
                     ins(8, "ret", kind="return"), name="sum_to")
        self.assertRegex(output.pseudoc, r"\bi = (\(uint32_t\))?i \+ 1;")
        compile_run(body(output), "return sum_to(5)==10 && sum_to(-1)==0 ? 0:1;")
        length = x86(ins(0, "push", "rbx"), ins(1, "mov", "rbx", "rdi"), ins(2, "call", "0x520", kind="call", target=0x520),
                     ins(3, "mov", "rbx", "rax"), ins(4, "mov", "edi", "0x402010"), ins(5, "call", "0x500", kind="call", target=0x500),
                     ins(6, "mov", "rax", "rbx"), ins(7, "pop", "rbx"), ins(8, "ret", kind="return"),
                     context={"data_references": STRINGS, "callees": LIBC}, name="measure")
        self.assertRegex(length.pseudoc, r"size_t length;|length = strlen\(")
        self.assertIn("strlen(str)", length.pseudoc)
        self.assertIn("const char * str", length.pseudoc)  # 参数按原型改名、改类型

    def test_simplifications_preserve_values(self):
        byte = Value("load", 8, (Value("variable", 64, name="p", ctype="uint8_t *"),), ctype="uint8_t", effect=True)
        chain = Value("cast", 64, (Value("cast", 32, (byte,), ctype="uint32_t"),), ctype="uint64_t")
        self.assertEqual(format_value(simplify_value(chain)), "(uint64_t)p[0]")
        signed = Value("variable", 32, name="x", ctype="uint32_t")
        sign_extended = Value("cast", 64, (Value("cast", 32, (signed,), ctype="int32_t"),), ctype="int64_t")
        self.assertEqual(format_value(simplify_value(sign_extended)), "(int64_t)(int32_t)x")  # 不能丢掉符号扩展
        masked = Value("cast", 8, (Value("or", 64, (Value("and", 64, (Value("variable", 64, name="y", ctype="uint64_t"),
            Value("constant", 64, number=0xffffffffffffff00, ctype="uint64_t")), ctype="uint64_t"),
            Value("constant", 64, number=2, ctype="uint64_t")), ctype="uint64_t"),), ctype="uint8_t")
        self.assertEqual(format_value(simplify_value(masked)), "2")

    def test_parentheses_follow_c_precedence(self):
        a, b, c = (Value("variable", 32, name=name, ctype="uint32_t") for name in "abc")
        product = Value("mul", 32, (a, b), ctype="uint32_t")
        self.assertEqual(format_value(Value("add", 32, (product, c), ctype="uint32_t")), "a * b + c")
        self.assertEqual(format_value(Value("sub", 32, (a, Value("sub", 32, (b, c), ctype="uint32_t")), ctype="uint32_t")), "a - (b - c)")
        self.assertEqual(format_value(Value("and", 32, (Value("add", 32, (a, b), ctype="uint32_t"), c), ctype="uint32_t")), "(a + b) & c")
        # 移位计数必须证明小于宽度才写成 C 的 <<（否则 c >= 32 时未定义，改用前导中的 shl_32）。
        count = Value("and", 32, (c, Value("constant", 32, number=31, ctype="uint32_t")), ctype="uint32_t")
        self.assertEqual(format_value(Value("shl", 32, (Value("add", 32, (a, b), ctype="uint32_t"), count), ctype="uint32_t")),
                         "(a + b) << (c & 0x1f)")
        self.assertEqual(format_value(Value("shl", 32, (Value("add", 32, (a, b), ctype="uint32_t"), c), ctype="uint32_t")),
                         "shl_32(a + b, c)")
        compare = Value("compare", 1, (Value("and", 32, (a, Value("constant", 32, number=0xff, ctype="uint32_t")), ctype="uint32_t"),
                                       Value("constant", 32, number=0x12, ctype="uint32_t")), name="==", ctype="bool")
        self.assertEqual(format_value(compare), "(a & 0xff) == 18")
        parts = [format_value(Value("sub", 32, (a, Value("sub", 32, (b, c), ctype="uint32_t")), ctype="uint32_t")),
                 format_value(Value("shl", 32, (Value("add", 32, (a, b), ctype="uint32_t"), count), ctype="uint32_t")),
                 format_value(compare), format_value(Value("add", 32, (product, c), ctype="uint32_t"))]
        compile_run("uint32_t f(uint32_t a, uint32_t b, uint32_t c) { return " + " + ".join(f"({part})" for part in parts) + "; }",
                    "return f(3,4,1)==(3-(4-1))+((3+4)<<1)+0+(12+1) ? 0:1;")


class StructureTests(unittest.TestCase):
    def test_shared_tail_label_stays_at_outer_level(self):
        rows = (ins(0, "test", "edi", "edi"), ins(1, "je", "0x10", kind="jump", target=16, conditional=True),
                ins(2, "test", "esi", "esi"), ins(3, "je", "0x20", kind="jump", target=32, conditional=True),
                ins(4, "mov", "eax", "2"), ins(5, "jmp", "0x30", kind="jump", target=48),
                ins(16, "mov", "eax", "1"), ins(17, "jmp", "0x30", kind="jump", target=48),
                ins(32, "mov", "eax", "3"), ins(33, "ret", kind="return"),
                ins(48, "add", "eax", "10"), ins(49, "imul", "eax", "esi"), ins(50, "add", "eax", "edi"), ins(51, "ret", kind="return"))
        output = x86(*rows, name="tail")
        text = body(output)
        for line in text.splitlines():
            if re.fullmatch(r"\s*block_\d+:", line):
                self.assertEqual(line, line.lstrip())  # 标签只在函数体最外层
        compile_run(text, "return tail(0,5)==55 && tail(1,0)==3 && tail(2,3)==38 ? 0:1;")

    def test_equality_chain_becomes_switch(self):
        rows = (ins(0, "cmp", "edi", "0"), ins(1, "je", "0x10", kind="jump", target=16, conditional=True),
                ins(2, "cmp", "edi", "1"), ins(3, "je", "0x20", kind="jump", target=32, conditional=True),
                ins(4, "cmp", "edi", "2"), ins(5, "je", "0x30", kind="jump", target=48, conditional=True),
                ins(6, "mov", "eax", "0x63"), ins(7, "ret", kind="return"),
                ins(16, "mov", "eax", "0x0a"), ins(17, "ret", kind="return"),
                ins(32, "mov", "eax", "0x14"), ins(33, "ret", kind="return"),
                ins(48, "mov", "eax", "0x1e"), ins(49, "ret", kind="return"))
        output = x86(*rows, name="classify")
        text = body(output)
        self.assertIn("switch (arg_1) {", text)
        self.assertEqual(len(re.findall(r"^\s*case \d+:", text, re.M)), 3)
        self.assertIn("default:", text)
        self.assertNotIn("goto", text)
        compile_run(text, "return classify(0)==10 && classify(1)==20 && classify(2)==30 && classify(7)==99 ? 0:1;")

    def test_two_way_chain_uses_else_if(self):
        rows = (ins(0, "cmp", "edi", "0"), ins(1, "je", "0x10", kind="jump", target=16, conditional=True),
                ins(2, "cmp", "esi", "1"), ins(3, "je", "0x20", kind="jump", target=32, conditional=True),
                ins(4, "mov", "eax", "3"), ins(5, "jmp", "0x30", kind="jump", target=48),
                ins(16, "mov", "eax", "1"), ins(17, "jmp", "0x30", kind="jump", target=48),
                ins(32, "mov", "eax", "2"), ins(33, "jmp", "0x30", kind="jump", target=48),
                ins(48, "add", "eax", "edi"), ins(49, "ret", kind="return"))
        output = x86(*rows, name="pick")
        text = body(output)
        self.assertIn("} else if (", text)
        self.assertNotIn("goto", text)
        compile_run(text, "return pick(0,1)==1 && pick(4,1)==6 && pick(4,0)==7 ? 0:1;")

    def test_small_return_tails_are_duplicated_instead_of_goto(self):
        # 汇合块 M（加法后返回）与 R（返回 0）都有两个前驱：只有一个能紧跟在 if 之后，
        # 另一个原本要 goto；R 很短且以 return 结束，直接复制到两处。
        rows = (ins(0, "test", "edi", "edi"), ins(1, "je", "0x10", kind="jump", target=16, conditional=True),
                ins(2, "test", "esi", "esi"), ins(3, "je", "0x28", kind="jump", target=40, conditional=True),
                ins(4, "mov", "eax", "2"), ins(5, "jmp", "0x18", kind="jump", target=24),
                ins(16, "test", "esi", "esi"), ins(17, "je", "0x28", kind="jump", target=40, conditional=True),
                ins(18, "mov", "eax", "3"), ins(19, "jmp", "0x18", kind="jump", target=24),
                ins(24, "add", "eax", "edi"), ins(25, "ret", kind="return"),
                ins(40, "mov", "eax", "0"), ins(41, "ret", kind="return"))
        output = x86(*rows, name="status")
        text = body(output)
        self.assertNotIn("goto", text)
        self.assertEqual(output.reconstruction["residual_gotos"], 0)
        self.assertGreaterEqual(text.count("return 0;"), 2)
        compile_run(text, "return status(0,0)==0 && status(0,1)==3 && status(5,0)==0 && status(5,1)==7 ? 0:1;")

    def test_bottom_tested_loop_becomes_do_while(self):
        rows = (ins(0, "mov", "w8", "#0", size=4), ins(4, "add", "w8", "w8", "w0", size=4),
                ins(8, "subs", "w0", "w0", "#1", size=4), ins(12, "b.ne", "0x4", size=4, kind="jump", target=4, conditional=True),
                ins(16, "mov", "w0", "w8", size=4), ins(20, "ret", size=4, kind="return"))
        output = arm(*rows, name="triangle")
        text = body(output)
        self.assertIn("do {", text)
        self.assertRegex(text, r"} while \(.+\);")
        compile_run(text, "return triangle(4)==10 && triangle(1)==1 ? 0:1;")


class HeaderTests(unittest.TestCase):
    def test_header_reports_address_name_source_and_completeness(self):
        output = x86(ins(0x40, "mov", "eax", "edi"), ins(0x41, "ret", kind="return"), name="identity", source="symtab")
        self.assertEqual(output.pseudoc.splitlines()[0], "// 0x40 identity | 名字：符号表 | 完整")
        self.assertEqual(output.reconstruction["header"], output.pseudoc.splitlines()[0])
        self.assertIn("uint32_t identity(uint32_t arg_1) {", output.pseudoc.splitlines()[1])
        partial = x86(ins(0, "mov", "edi", "4"), ins(1, "call", "0x20", kind="call", target=32), ins(2, "ret", kind="return"),
                      name="sub_0")
        first = partial.pseudoc.splitlines()[0]
        self.assertTrue(first.startswith("// 0x0 recovered_function | 名字：自动生成 | 不完整："), first)
        self.assertIn("调用参数个数未知", first)


DEMO = r'''
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static int checksum(const unsigned char *buf, int len) {
    int sum = 0;
    for (int i = 0; i < len; i++) sum = (sum * 31 + buf[i]) & 0xffff;
    return sum;
}
int check_password(const char *input) {
    if (strlen(input) != 8) { puts("bad length"); return 0; }
    if (checksum((const unsigned char *)input, 8) == 0x1234) { puts("access granted"); return 1; }
    puts("wrong password");
    return 0;
}
int main(int argc, char **argv) {
    if (argc > 1) return check_password(argv[1]) ? 0 : 2;
    return 0;
}
'''


class CompiledSampleTests(unittest.TestCase):
    def test_compiled_demo_shows_string_literals_and_hex_constants(self):
        compiler = shutil.which("cc")
        if not compiler or os.name == "nt":
            raise unittest.SkipTest("需要 C 编译器")
        from fangida import benchmark
        from fangida.dispatcher import AnalysisService
        with tempfile.TemporaryDirectory() as tmp:
            source, binary = Path(tmp) / "demo.c", Path(tmp) / "demo"
            source.write_text(DEMO)
            built = subprocess.run([compiler, "-O2", "-o", str(binary), str(source)], capture_output=True, text=True)
            if built.returncode:
                raise unittest.SkipTest("无法编译示例：" + built.stderr[-200:])
            with AnalysisService(benchmark._settings(binary, 1, full_analysis=True)) as service:
                result = service.analyze(binary, full_analysis=True)
        texts = [function.get("pseudoc", "") for function in result.functions if function.get("pseudoc_style") == "readable"]
        self.assertTrue(texts)
        joined = "\n".join(texts)
        self.assertIn('"bad length"', joined)
        self.assertIn('"access granted"', joined)
        self.assertIn("0x1234", joined)
        self.assertTrue(all(text.startswith("// ") for text in texts))


if __name__ == "__main__":
    unittest.main()
