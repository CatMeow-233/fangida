"""算术取得的栈地址（ARM64 add x0, sp, #N）与被调函数通过指针写入的局部变量。

修复前：sp 被当作“未知的寄存器入口值”（ptr = unknown_value(); ptr + 8），
调用后读回的局部变量被误报为“栈槽未初始化”（local = unknown_value()）。
"""
from __future__ import annotations

import unittest

from fangida.plugins.pseudoc import generate_pseudoc
from tests.test_pseudoc import function as fn, instruction as ins
from tests.test_reconstruction import compile_run


def arm(address, mnemonic, *operands, **options):
    return ins(address, mnemonic, *operands, size=4, **options)


FILL = {"name": "fill", "signature_complete": True, "return_type": "void",
        "parameters": [{"register": "x0", "type": "uint8_t *"}]}


class StackEscapeTests(unittest.TestCase):
    def _arm64(self, *rows, name, callees=None):
        context = {"kind": "elf", **({"callees": callees} if callees else {})}
        return generate_pseudoc(fn(*rows, name=name, pseudoc_context=context), "arm64", style="readable")

    def test_arithmetic_stack_address_is_a_local_and_callee_writes_are_read_back(self):
        # 与 libtersafe.so tss_unity_str 同形：add x0, sp, #8 传给构造函数，调用后 ldr x0, [sp, #8]。
        output = self._arm64(
            arm(0x00, "sub", "sp", "sp", "#0x50"), arm(0x04, "stp", "x29", "x30", "[sp, #0x30]"),
            arm(0x08, "add", "x29", "sp", "#0x30"), arm(0x0c, "add", "x0", "sp", "#8"),
            arm(0x10, "bl", "#0x100", kind="call", target=0x100), arm(0x14, "ldr", "x0", "[sp, #8]"),
            arm(0x18, "ldp", "x29", "x30", "[sp, #0x30]"), arm(0x1c, "add", "sp", "sp", "#0x50"),
            arm(0x20, "ret", kind="return"), name="escaped", callees={0x100: FILL})
        kinds = {item["kind"] for item in output.reconstruction["unresolved"]}
        self.assertNotIn("incoming_value", kinds, output.pseudoc)
        self.assertNotIn("incoming_stack_value", kinds, output.pseudoc)
        self.assertNotIn("unknown_value", output.pseudoc)
        self.assertNotIn("initialize_unknown_bytes", output.pseudoc)
        self.assertIn("fill(", output.pseudoc)
        compile_run(output.pseudoc, "return escaped() == 0x1122334455667788ull ? 0 : 1;",
                    "void fill(uint8_t *p) { uint64_t v = 0x1122334455667788ull; __builtin_memcpy(p, &v, 8); }\n")

    def test_read_before_the_escaping_call_is_still_reported(self):
        output = self._arm64(
            arm(0x00, "sub", "sp", "sp", "#0x20"), arm(0x04, "ldr", "x1", "[sp, #8]"),
            arm(0x08, "add", "x0", "sp", "#8"), arm(0x0c, "bl", "#0x100", kind="call", target=0x100),
            arm(0x10, "add", "sp", "sp", "#0x20"), arm(0x14, "ret", kind="return"), name="early_read")
        self.assertIn("incoming_stack_value", {item["kind"] for item in output.reconstruction["unresolved"]})

    def test_argument_written_in_a_predecessor_block_is_listed_for_incomplete_callee(self):
        # ldr x0, [sp, #8] ; cbz x0 ; bl thunk —— x0 在前一个块写入，跨分支后仍是显式实参。
        thunk = {"name": "thunk", "signature_complete": False, "parameters": []}
        output = self._arm64(
            arm(0x00, "sub", "sp", "sp", "#0x50"), arm(0x04, "add", "x0", "sp", "#8"),
            arm(0x08, "bl", "#0x100", kind="call", target=0x100), arm(0x0c, "ldr", "x0", "[sp, #8]"),
            arm(0x10, "cbz", "x0", "#0x18", kind="jump", target=0x18, conditional=True),
            arm(0x14, "bl", "#0x200", kind="call", target=0x200), arm(0x18, "add", "sp", "sp", "#0x50"),
            arm(0x1c, "ret", kind="return"), name="free_field", callees={0x200: thunk})
        self.assertRegex(output.pseudoc, r"thunk\(result, unknown_arguments\(\)\)")

    def test_incoming_argument_is_not_listed_as_explicit(self):
        # 入口参数 x0 未经改写就转交：仍只显示 unknown_arguments()，不把入口值当作显式实参。
        thunk = {"name": "thunk", "signature_complete": False, "parameters": []}
        output = self._arm64(arm(0x00, "b.eq", "#0x8", kind="jump", target=0x8, conditional=True),
                             arm(0x04, "nop"), arm(0x08, "bl", "#0x200", kind="call", target=0x200),
                             arm(0x0c, "ret", kind="return"), name="pass_through", callees={0x200: thunk})
        self.assertIn("thunk(unknown_arguments())", output.pseudoc)

    def test_frame_pointer_setup_is_not_an_escaped_local(self):
        output = self._arm64(
            arm(0x00, "stp", "x29", "x30", "[sp, #-16]!"), arm(0x04, "mov", "x29", "sp"),
            arm(0x08, "mov", "w0", "#7"), arm(0x0c, "ldp", "x29", "x30", "[sp], #16"),
            arm(0x10, "ret", kind="return"), name="plain")
        self.assertNotIn("local_", output.pseudoc)
        self.assertIn("return 7;", output.pseudoc)


if __name__ == "__main__":
    unittest.main()
