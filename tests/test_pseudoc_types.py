"""可读伪 C 中指针与整数混用处的类型一致性（reconstruct/typecheck.py 与相关的恢复改动）。

* 部分寄存器写入（setcc/mov 低字节）合并到被推断为指针的寄存器：按地址整数做位段合并，合并结果是整数，
  不能对指针做 &/|，也不能据此把返回值定成指针；
* 复制传播、按定义-使用网重定类型后出现的指针 ⇄ 整数：赋值、返回、下标、switch、条件选择两臂、比较、
  已知原型的实参处显式转换（值逐位不变），不改变任何变量的声明类型；
* 加减按字节计算：整数结果的加减里出现指针时先转为地址整数（否则 C 按元素大小缩放）；
* 存储目的上的右值转换 `(uint8_t)p[0] = v` 改为对同宽度左值赋值；经 const 指针写入时基址转为非 const；
* 结构化时循环头作为汇合块，标签只输出一次；
* 自递归调用：实参按本函数定义中的形参顺序与类型给出（栈形参取调用点的栈实参槽，签名保留全部栈形参），
  结果按本函数返回类型（调用摘要证明零扩展时与其它调用相同）；
* 左移的常量左操作数写成无符号常量（1U、1ULL），不再是 int 的 1 << 31；
* 函数名赋给对象指针、丢掉被指类型 const 限定的指针赋值/传参（C11 6.5.16.1 约束违例）显式转换；
* 指针结果的加减按节点类型的元素计（与 ordering.py、readability 的约定一致）。

每个合成函数都用 cc -fsyntax-only（-Werror=int-conversion、-Werror=incompatible-pointer-types，编译器支持时另加
-Werror=conditional-type-mismatch、-Werror=discarded-qualifiers）检查；能逐条执行的
叶子函数还加前导编译运行（开 UBSan），与微码逐条执行的结果（返回值与缓冲区内容）逐一比对：指针形参指向
按同一规则填充的缓冲区，落在缓冲区内的地址按（缓冲区, 偏移）比较。本机没有 C 编译器时跳过编译与运行部分。
"""
from __future__ import annotations

import functools
import random
import re
import subprocess
import unittest
from unittest import mock

from tests import test_pseudoc_compilable as compilable
from tests.test_lifter_gaps import _rows
from tests.test_pseudoc import function as fn
from fangida.plugins.pseudoc import generate_pseudoc, pseudoc_prelude
from fangida.plugins.pseudoc.reconstruct.expressions import format_value
from fangida.plugins.pseudoc.reconstruct.model import Statement, Value


def TypeCoercion(*args, **kwargs):  # noqa: N802  延迟导入：其余用例不依赖该模块是否存在
    from fangida.plugins.pseudoc.reconstruct.typecheck import TypeCoercion as coercion
    return coercion(*args, **kwargs)

_STRICT = ("-Werror=incompatible-pointer-types",)
# 只有部分编译器认识的告警（Clang：?: 两臂指针/整数不一致；GCC：丢掉 const 限定，Clang 已含在上面的选项里）。
_OPTIONAL_STRICT = ("-Werror=conditional-type-mismatch", "-Werror=discarded-qualifiers")
# 缓冲区：机器侧第 j 个缓冲区位于 _BASE + j * _STRIDE，指针形参指向其中的 _CENTER 处；C 侧按 4096 字节对齐。
_SIZE, _CENTER, _BASE, _STRIDE = 1024, 256, 0x50000000, 0x10000


def _pattern(index, offset):
    return (offset * 131 + index * 17 + 7) & 0xff


class _BufferMachine(compilable._Machine):
    """在只允许栈的参考机器上另加若干按 _pattern 填充的缓冲区（指针形参所指）。"""
    count = 0
    writes = ()
    last = None

    def __init__(self, architecture, registers):
        super().__init__(architecture, registers)
        for index in range(type(self).count):
            for offset in range(_SIZE):
                self.memory[_BASE + index * _STRIDE + offset] = _pattern(index, offset)
        for index, offset, data in type(self).writes:
            for position, byte in enumerate(data):
                self.memory[_BASE + index * _STRIDE + _CENTER + offset + position] = byte
        type(self).last = self

    def _check(self, address, size):
        for index in range(type(self).count):
            start = _BASE + index * _STRIDE
            if start <= address and address + size <= start + _SIZE:
                return
        super()._check(address, size)


def _branch_rows(architecture, texts):
    """_rows 并为条件/无条件跳转与调用补上分支信息（目标为操作数中的地址）。"""
    rows = _rows(architecture, texts)
    for row in rows:
        mnemonic = row["mnemonic"]
        if mnemonic in {"call", "bl"}:
            row["branch_info"] = {"kind": "call", "target": int(row["operands"][0].lstrip("#"), 0), "conditional": False}
        elif mnemonic == "jmp" or mnemonic == "b" or re.fullmatch(r"j[a-z]+|b\.[a-z]+|cbn?z|tbn?z", mnemonic):
            target = int(row["operands"][-1].lstrip("#"), 0)
            row["branch_info"] = {"kind": "jump", "target": target, "conditional": mnemonic not in {"jmp", "b"}}
    return rows


def _readable(architecture, texts, context=None, name="f"):
    function = fn(*_branch_rows(architecture, texts), name=name, pseudoc_context={"kind": "elf", **(context or {})})
    return function, generate_pseudoc(function, architecture, style="readable")


@functools.lru_cache(maxsize=None)
def _supported(flag):
    """本机编译器是否认识该告警选项（不认识的 -Werror= 选项本身会使编译失败）。"""
    checked = subprocess.run([compilable._compiler(), "-fsyntax-only", "-Werror", flag, "-x", "c", "-"],
                             input="int fangida_flag_probe;\n", capture_output=True, text=True)
    return checked.returncode == 0


def _strict(*extra):
    return _STRICT + tuple(flag for flag in _OPTIONAL_STRICT + extra if _supported(flag))


def _compiles(test, output):
    compilable._syntax_check(pseudoc_prelude(output) + "\n" + output.pseudoc + "\n", *_strict())


def _relative(value, count):
    for index in range(count):
        start = _BASE + index * _STRIDE
        if start <= value < start + _SIZE:
            return ("buffer", index, value - start)
    return value


def _memory_hash(machine, count):
    digest = 0xcbf29ce484222325
    for index in range(count):
        for offset in range(_SIZE):
            digest = ((digest ^ machine.memory[_BASE + index * _STRIDE + offset]) * 0x100000001b3) & ((1 << 64) - 1)
    return digest


def _assert_matches_microcode(test, architecture, function, output, cases, writes=()):
    """cases：[{寄存器: 整数 或 ("buffer", j)}]。微码逐条执行（缓冲区机器）与可读 C（UBSan）的返回值与缓冲区逐一相同。

    writes：[(缓冲区, 相对指针处的偏移, bytes)]，填充之后再写入（两侧相同），用于放置终止元素等。"""
    report = output.reconstruction
    parameters = [(item["storage"].split(":", 1)[-1], item["type"]) for item in report["parameters"]]
    count = 1 + max((value[1] for case in cases for value in case.values() if isinstance(value, tuple)), default=-1)
    returned = report["return_type"]
    width, signed = compilable._type_width(returned) or (64, False)
    rng = random.Random(len(output.pseudoc))
    garbage = {root: rng.getrandbits(64) for root in compilable._REGISTERS[architecture]}
    expected = []
    with mock.patch.object(compilable, "_Machine", _BufferMachine), \
            mock.patch.object(_BufferMachine, "count", count), mock.patch.object(_BufferMachine, "writes", tuple(writes)):
        for case in cases:
            state = dict(garbage)
            for root, ctype in parameters:
                value = case.get(root, 0)
                if isinstance(value, tuple):
                    state[root] = _BASE + value[1] * _STRIDE + _CENTER
                else:
                    kind = compilable._type_width(ctype) or (64, False)
                    state[root] = compilable._extend(value & ((1 << kind[0]) - 1), kind[0], kind[1], 64)
            result = compilable.run_microcode(list(output.microcode), function["start"], architecture, state)
            value = compilable._extend(result & ((1 << width) - 1), width, signed, 64)
            expected.append((_relative(value, count), _memory_hash(_BufferMachine.last, count)))
    name = re.search(r"^\S.*?\b([A-Za-z_]\w*)\(", output.pseudoc.splitlines()[1]).group(1)
    calls = []
    for case in cases:
        arguments = []
        for root, ctype in parameters:
            value = case.get(root, 0)
            arguments.append(f"({ctype})(fangida_buffers[{value[1]}] + {_CENTER})" if isinstance(value, tuple)
                             else f"({ctype}){value:#x}ULL")
        calls.append(f"    fangida_fill(); result = (unsigned long long)(uint64_t){name}({', '.join(arguments)});\n"
                     f"    printf(\"%llx %llx\\n\", result, fangida_hash());")
    buffers = max(count, 1)
    program = (pseudoc_prelude(output) + "\n#include <stdio.h>\n" + output.pseudoc + "\n"
               f"static _Alignas(4096) unsigned char fangida_buffers[{buffers}][{_SIZE}];\n"
               f"static void fangida_fill(void) {{ for (unsigned j = 0; j < {buffers}; j++) for (unsigned o = 0; o < {_SIZE}; o++) "
               "fangida_buffers[j][o] = (unsigned char)(o * 131u + j * 17u + 7u);\n"
               + "".join(f"    fangida_buffers[{index}][{_CENTER + offset + position}] = {byte};\n"
                         for index, offset, data in writes for position, byte in enumerate(data)) + "}\n"
               "static unsigned long long fangida_hash(void) { unsigned long long h = 0xcbf29ce484222325ULL; "
               f"for (unsigned j = 0; j < {count}; j++) for (unsigned o = 0; o < {_SIZE}; o++) {{ h ^= fangida_buffers[j][o]; h *= 0x100000001b3ULL; }} return h; }}\n"
               "int main(void) {\n    unsigned long long result;\n"
               f"    for (unsigned j = 0; j < {buffers}; j++) printf(\"%llx\\n\", (unsigned long long)(uintptr_t)fangida_buffers[j]);\n"
               + "\n".join(calls) + "\n    return 0;\n}\n")
    lines = compilable._run_c(program)
    bases, rows = [int(item, 16) for item in lines[:buffers]], lines[buffers:]
    test.assertEqual(len(rows), 2 * len(cases), output.pseudoc)
    for index, (case, (want, want_memory)) in enumerate(zip(cases, expected)):
        got, got_memory = int(rows[2 * index], 16), int(rows[2 * index + 1], 16)
        for buffer, base in enumerate(bases[:count]):
            if base <= got < base + _SIZE:
                got = ("buffer", buffer, got - base)
        test.assertEqual(got, want, (case, output.pseudoc))
        test.assertEqual(got_memory, want_memory, (case, "memory", output.pseudoc))


# ---------------------------------------------------------------------------
# 合成函数：编译通过（修复前是 C 约束违例），能执行的与微码逐一比对
# ---------------------------------------------------------------------------

class PointerIntegerMixTests(unittest.TestCase):
    def test_partial_write_into_copied_pointer_register_merges_as_integer(self):
        # rcx 复制自指针形参（类型随复制传播成指针），sete cl 只改写低字节：合并是地址整数上的位段运算。
        # 合并结果再作为地址按字节读取（缓冲区按 4096 对齐，两侧的低字节替换落在同一偏移）。
        function, output = _readable("x86_64", ["mov eax, dword ptr [rdi]", "mov rcx, rdi", "cmp eax, esi", "sete cl",
                                                "mov qword ptr [rdx], rax", "mov rax, rcx", "add rax, 4",
                                                "movzx eax, byte ptr [rax]", "ret"])
        self.assertNotRegex(output.pseudoc, r"\(arg_1 & 0x")
        self.assertIn("((uint64_t)arg_1 & 0xffffffffffffff00ULL)", output.pseudoc)
        _compiles(self, output)
        first = int.from_bytes(bytes(_pattern(0, _CENTER + offset) for offset in range(4)), "little")
        cases = [{"rdi": ("buffer", 0), "rsi": value, "rdx": ("buffer", 1)} for value in (0, 1, first, 0xffffffff)]
        _assert_matches_microcode(self, "x86_64", function, output, cases)

    def test_partial_write_result_does_not_make_the_return_value_a_pointer(self):
        function, output = _readable("x86_64", ["mov eax, dword ptr [rdi]", "mov rcx, rdi", "cmp eax, esi", "sete cl",
                                                "mov rax, rcx", "ret"])
        self.assertRegex(output.pseudoc.splitlines()[1], r"^uint64_t f\(")
        _compiles(self, output)
        first = int.from_bytes(bytes(_pattern(0, _CENTER + offset) for offset in range(4)), "little")
        _assert_matches_microcode(self, "x86_64", function, output,
                                  [{"rdi": ("buffer", 0), "rsi": value} for value in (0, first, 7)])

    def test_partial_write_into_register_typed_by_a_callee_parameter(self):
        # 被调函数的形参类型（char *）使 rdi 成为指针变量；setcc dil 之后的值是整数，不是指针。
        context = {"callees": {0x100: {"name": "consume", "parameters": [{"register": "rdi", "type": "char *"}],
                                       "signature_complete": True, "return_type": "uint32_t"}}}
        _, output = _readable("x86_64", ["mov rdi, qword ptr [rsi]", "call 0x100", "cmp eax, 0", "sete dil",
                                         "mov rax, rdi", "ret"], context)
        self.assertRegex(output.pseudoc.splitlines()[1], r"^uint64_t f\(")
        _compiles(self, output)

    def test_switch_on_a_web_retyped_to_integer(self):
        # x8 先作字节指针（ldrb 的基址），再装整数：比较链写成 switch 时控制表达式必须是整数。
        function, output = _readable("arm64", ["mov x8, x0", "ldrb w9, [x8]", "mov x8, x1", "cmp x8, #1", "b.eq 0x30",
                                               "cmp x8, #2", "b.eq 0x38", "cmp x8, #3", "b.eq 0x40", "mov w0, w9", "ret",
                                               "nop", "mov w0, #10", "ret", "mov w0, #20", "ret", "mov w0, #30", "ret"])
        self.assertIn("switch (arg_2) {", output.pseudoc)
        _compiles(self, output)
        _assert_matches_microcode(self, "arm64", function, output,
                                  [{"x0": ("buffer", 0), "x1": value} for value in (0, 1, 2, 3, 4, 1 << 40 | 1)])

    def test_subscript_index_is_an_integer(self):
        # rdx 先作 32 位读取的基址，再装符号扩展的下标：下标处不能是指针类型。
        function, output = _readable("x86_64", ["mov rdx, rsi", "movsxd rdx, dword ptr [rdx + 0x10]",
                                                "mov rax, qword ptr [rdi + rdx*8]", "ret"])
        self.assertIn("return arg_1[value_3];", output.pseudoc)
        _compiles(self, output)

    def test_conditional_select_of_loaded_value_and_constant_address(self):
        _, output = _readable("x86_64", ["mov rax, qword ptr [rdi + 0x18]", "mov rcx, qword ptr [rax]", "test rcx, rcx",
                                         "lea rax, [rip + 0x46d93]", "cmovne rax, rcx", "ret"])
        self.assertIn("return value_2 != 0 ? value_2 : 0x46d97;", output.pseudoc)
        _compiles(self, output)

    def test_conditional_select_of_pointer_and_integer(self):
        # cmov 在指针形参与整数常量之间选择：两臂一为指针一为整数的 ?: 是 C 约束违例（C11 6.5.15p3，
        # Clang -Wconditional-type-mismatch），指针臂按地址整数参与选择；结果与微码逐一比对（两种分支）。
        # 这里指针臂的转换来自 cmov 的提升；复制传播后裸露的指针臂由 typecheck._selection 转换（见 TypeCoercionTests）。
        texts = ["mov eax, dword ptr [rdi]", "mov ecx, 5", "test eax, eax", "cmovne rcx, rdi", "mov rax, rcx", "ret"]
        function, output = _readable("x86_64", texts)
        self.assertIn("? (uint64_t)arg_1 : 5", output.pseudoc)
        _compiles(self, output)
        _assert_matches_microcode(self, "x86_64", function, output, [{"rdi": ("buffer", 0)}])
        _assert_matches_microcode(self, "x86_64", function, output, [{"rdi": ("buffer", 0)}], writes=[(0, 0, bytes(4))])

    def test_function_address_and_const_strings_are_converted_explicitly(self):
        # 函数地址装入随后按 const char * 使用的变量（函数名 → 对象指针，GCC 14 默认报错）；只读字符串赋给
        # void * 变量、作 free 的 void * 实参（丢掉 const 限定，C11 6.5.16.1 约束违例）。转换不改变地址。
        references = {0x12345: {"kind": "function", "name": "handler"}, 0x22345: {"kind": "string", "value": "abc"}}
        chosen = ["mov rdi, 0x12345", "test esi, esi", "je 0x4", "mov rdi, qword ptr [rdx]", "call 0x100", "ret"]
        _, output = _readable("x86_64", chosen, {"callees": {0x100: {"name": "strlen"}}, "data_references": references})
        self.assertIn("str = (const char *)handler;", output.pseudoc)
        _compiles(self, output)
        context = {"callees": {0x100: {"name": "free"}}, "data_references": references}
        _, output = _readable("x86_64", ["mov rdi, 0x22345", "call 0x100", "ret"], context)
        self.assertIn('free((void *)"abc");', output.pseudoc)
        _compiles(self, output)
        _, output = _readable("x86_64", ["mov rdi, 0x22345"] + chosen[1:], context)
        self.assertIn('ptr = (void *)"abc";', output.pseudoc)
        _compiles(self, output)

    def test_store_through_rvalue_cast_writes_the_lvalue(self):
        # __errno() 返回 int *：写入 32 位值时直接对 error_slot[0] 赋值（C 不允许对转换结果赋值）。
        context = {"callees": {0x100: {"name": "__errno"}}}
        _, output = _readable("arm64", ["mov w19, w0", "bl #0x100", "mov x8, x0", "str w19, [x8]", "mov x0, #-1", "ret"],
                              context)
        self.assertIn("error_slot[0] = arg_1;", output.pseudoc)
        self.assertNotIn("(uint32_t)error_slot[0] =", output.pseudoc)
        _compiles(self, output)


class StructureLabelTests(unittest.TestCase):
    def test_loop_header_reached_by_goto_has_a_single_label(self):
        # 第二个循环的头是汇合块（两个前向前驱），又被第一个循环里的 goto 跳到：标签只输出一次。
        texts = ["mov rax, rdi", "mov rcx, qword ptr [rax]", "add rax, 8", "test rcx, rcx", "je 0xb", "cmp rcx, rsi",
                 "jne 0x1", "jmp 0xb", "mov rcx, qword ptr [rax]", "mov qword ptr [rax - 8], rcx", "add rax, 8",
                 "test rcx, rcx", "jne 0x8", "ret"]
        function, output = _readable("x86_64", texts)
        labels = re.findall(r"^(block_\d+):$", output.pseudoc, re.M)
        self.assertTrue(labels, output.pseudoc)
        self.assertEqual(len(labels), len(set(labels)), output.pseudoc)
        _compiles(self, output)
        # 以 0 结尾的 8 字节元素数组（第 6 个元素为 0）：找到 rsi 后把其后的元素依次前移；找不到时不改动。
        element = lambda index: int.from_bytes(bytes(_pattern(0, _CENTER + 8 * index + offset) for offset in range(8)), "little")
        cases = [{"rdi": ("buffer", 0), "rsi": value} for value in (element(0), element(2), element(4), 12345)]
        _assert_matches_microcode(self, "x86_64", function, output, cases, writes=[(0, 40, bytes(8))])


class ShiftLiteralTests(unittest.TestCase):
    def test_constant_left_operand_is_an_unsigned_literal(self):
        for texts, literal, counts in ((["mov eax, 1", "mov ecx, edi", "shl eax, cl", "ret"], "1U << ", range(0, 64)),
                                       (["mov eax, 1", "mov ecx, edi", "shl rax, cl", "ret"], "1ULL << ", range(0, 128))):
            function, output = _readable("x86_64", texts)
            with self.subTest(texts=texts):
                self.assertIn(literal, output.pseudoc)
                _compiles(self, output)
                _assert_matches_microcode(self, "x86_64", function, output, [{"rdi": count} for count in counts])


class SelfRecursionTests(unittest.TestCase):
    def _run(self, output, name, rows):
        """按函数定义的形参顺序调用（形参 → 寄存器取自报告），返回各行的结果。"""
        order = [item["storage"].split(":", 1)[-1] for item in output.reconstruction["parameters"]]
        calls = "\n".join(f"    printf(\"%llx\\n\", (unsigned long long){name}({', '.join(f'{row[root]:#x}U' for root in order)}));"
                          for row in rows)
        program = pseudoc_prelude(output) + "\n#include <stdio.h>\n" + output.pseudoc + "\nint main(void) {\n" + calls + "\n    return 0;\n}\n"
        return [int(line, 16) for line in compilable._run_c(program)]

    def test_recursive_call_matches_the_definition(self):
        context = {"callees": {0: {"name": "f"}}}
        texts = ["test edi, edi", "je 0x9", "push rbx", "mov ebx, edi", "lea edi, [rdi - 1]", "call 0x0", "add eax, ebx",
                 "pop rbx", "ret", "xor eax, eax", "ret"]
        _, output = _readable("x86_64", texts, context)
        self.assertIn("f((uint32_t)(arg_1 - 1))", output.pseudoc)
        self.assertNotIn("unknown_arguments", output.pseudoc)
        self.assertIn("own_signature", {call["argument_evidence"] for call in output.reconstruction["calls"]})
        _compiles(self, output)
        observed = self._run(output, "f", [{"rdi": n} for n in range(0, 200, 7)])
        self.assertEqual(observed, [n * (n + 1) // 2 & 0xffffffff for n in range(0, 200, 7)])

    def test_recursive_call_passes_arguments_in_definition_order(self):
        # f(a=rdi, b=rsi, c=rdx, d=rcx) = d == 0 ? a + 2b + 3c : f(b, c, a, d - 1) + d（32 位）。
        texts = ["test ecx, ecx", "je 0xd", "push rbx", "mov ebx, ecx", "mov eax, edi", "mov edi, esi", "mov esi, edx",
                 "mov edx, eax", "lea ecx, [rcx - 1]", "call 0x0", "add eax, ebx", "pop rbx", "ret",
                 "lea eax, [rdi + rsi*2]", "lea ecx, [rdx + rdx*2]", "add eax, ecx", "ret"]

        def reference(a, b, c, d):
            return (a + 2 * b + 3 * c) & 0xffffffff if d == 0 else (reference(b, c, a, d - 1) + d) & 0xffffffff

        for context in ({}, {"callees": {0: {"name": "f"}}}):
            _, output = _readable("x86_64", texts, context)
            with self.subTest(context=context):
                _compiles(self, output)
                rows = [{"rdi": a, "rsi": b, "rdx": c, "rcx": d} for a, b, c, d in
                        ((1, 2, 3, 0), (1, 2, 3, 1), (1, 2, 3, 2), (5, 7, 11, 5), (0xffffffff, 3, 0x80000000, 9))]
                self.assertEqual(self._run(output, "f", rows), [reference(row["rdi"], row["rsi"], row["rdx"], row["rcx"])
                                                                for row in rows])


    def test_stack_parameters_follow_the_call_site_argument_slots(self):
        # f(a=rdi, g=[rsp+8], h=[rsp+16]) = g == 0 ? a : f(a + 3, g - 1, 0) + g（64 位）。h 在入口读取后即被覆盖
        # （死读取），递归调用仍向第 2 个栈实参槽写 0：有自递归时签名保留全部栈形参，实参取调用点的栈实参槽。
        texts = ["mov rcx, qword ptr [rsp + 16]", "xor ecx, ecx", "mov rax, qword ptr [rsp + 8]", "test rax, rax",
                 "je 0x11", "push rbx", "mov rbx, rax", "sub rsp, 16", "lea rax, [rax - 1]", "mov qword ptr [rsp], rax",
                 "mov qword ptr [rsp + 8], rcx", "lea rdi, [rdi + 3]", "call 0x0", "add rsp, 16", "add rax, rbx",
                 "pop rbx", "ret", "mov rax, rdi", "ret"]
        _, output = _readable("x86_64", texts)
        self.assertEqual([item["storage"] for item in output.reconstruction["parameters"]], ["input:rdi", "stack:8", "stack:16"])
        call = next(line for line in output.pseudoc.splitlines() if " = f(" in line)
        self.assertNotIn("unknown_value", call)
        self.assertEqual(call.count(","), 2, output.pseudoc)
        self.assertIn("own_signature", {item["argument_evidence"] for item in output.reconstruction["calls"]})
        _compiles(self, output)
        mask = (1 << 64) - 1
        rows = [{"rdi": a, "8": g, "16": h} for a, g, h in ((5, 0, 9), (5, 1, 9), (7, 10, 0), (mask - 20, 30, 1))]
        self.assertEqual(self._run(output, "f", rows),
                         [(row["rdi"] + 3 * row["8"] + row["8"] * (row["8"] + 1) // 2) & mask for row in rows])

    def test_stack_parameters_of_compiled_arm64_recursion(self):
        # clang -O2 生成的 10 形参递归（AAPCS64：第 9、10 个实参在调用点的 [sp]、[sp, #8]，被调函数经 [x29, #0x10] 读取）：
        # rec(a..h, i, j) = j <= 0 ? a + 2b + … + 9i : rec(b, c, d, e, f, g, h, i, a, j - 1) * 3 + j。
        texts = ["sub sp, sp, #0x30", "stp x20, x19, [sp, #0x10]", "stp x29, x30, [sp, #0x20]", "add x29, sp, #0x20",
                 "ldp x8, x19, [x29, #0x10]", "cmp x19, #0x0", "b.le #0x54", "sub x9, x19, #0x1", "stp x0, x9, [sp]",
                 "mov x0, x1", "mov x1, x2", "mov x2, x3", "mov x3, x4", "mov x4, x5", "mov x5, x6", "mov x6, x7",
                 "mov x7, x8", "bl #0x0", "add x8, x0, x0, lsl #1", "add x0, x8, x19", "b #0x88",
                 "add x9, x0, x1, lsl #1", "add x10, x2, x2, lsl #1", "add x9, x9, x10", "add x9, x9, x3, lsl #2",
                 "add x10, x4, x4, lsl #2", "add x9, x9, x10", "mov w10, #0x6", "madd x9, x5, x10, x9", "sub x9, x9, x6",
                 "add x9, x9, x6, lsl #3", "add x9, x9, x7, lsl #3", "add x8, x8, x8, lsl #3", "add x0, x9, x8",
                 "ldp x29, x30, [sp, #0x20]", "ldp x20, x19, [sp, #0x10]", "add sp, sp, #0x30", "ret"]
        _, output = _readable("arm64", texts, {"callees": {0: {"name": "rec"}}}, name="rec")
        storages = [item["storage"].split(":", 1)[-1] for item in output.reconstruction["parameters"]]
        self.assertEqual(sorted(storages), sorted([f"x{index}" for index in range(8)] + ["0", "8"]))
        call = next(line for line in output.pseudoc.splitlines() if " = rec(" in line)
        self.assertNotIn("unknown_value", call)
        _compiles(self, output)
        mask = (1 << 64) - 1

        def reference(values, j):
            if j >= 1 << 63 or j == 0:  # j <= 0（带符号）
                return sum((index + 1) * value for index, value in enumerate(values)) & mask
            return (reference(values[1:] + values[:1], j - 1) * 3 + j) & mask

        cases = [(list(range(1, 10)), 0), (list(range(1, 10)), 3), ([mask, 7, 0, 5, 1 << 40, 3, 2, 1, 9], 9),
                 ([11 * index for index in range(9)], mask)]
        rows = [{**{f"x{index}": values[index] for index in range(8)}, "0": values[8], "8": j} for values, j in cases]
        self.assertEqual(self._run(output, "rec", rows), [reference(values, j) for values, j in cases])

    def test_zero_extended_own_result_keeps_known_upper_bits(self):
        # f(n) = n == 0 ? 0 : (uint32_t)(((uint64_t)f(n - 1) + 0xffffffff) >> 1)：递归结果按 64 位参与加法，进位
        # 进入第 32 位后再右移，依赖 f 写 eax 返回时 rax 的高 32 位为 0。调用摘要证明零扩展时与其它调用相同：
        # 结果高位已知，函数是完整的；摘要没有证明时高位未知（unknown_return_upper32），不自称完整。
        texts = ["test edi, edi", "je 0xb", "push rbx", "lea edi, [rdi - 1]", "call 0x0", "mov ebx, 0xffffffff",
                 "add rax, rbx", "shr rax, 1", "mov eax, eax", "pop rbx", "ret", "xor eax, eax", "ret"]
        _, output = _readable("x86_64", texts, {"callees": {0: {"name": "f", "return_zero_extended": True}}})
        self.assertNotIn("unknown_return_upper", output.pseudoc)
        self.assertTrue(output.pseudoc.splitlines()[0].endswith("| 完整"), output.pseudoc)
        self.assertEqual([item["return_extension"] for item in output.reconstruction["calls"]], ["declared_or_full_width"])
        _compiles(self, output)

        def reference(n):
            return 0 if n == 0 else ((reference(n - 1) + 0xffffffff) >> 1) & 0xffffffff

        self.assertEqual(self._run(output, "f", [{"rdi": n} for n in range(0, 60, 7)]), [reference(n) for n in range(0, 60, 7)])
        _, unknown = _readable("x86_64", texts, {"callees": {0: {"name": "f"}}})
        self.assertEqual([item["return_extension"] for item in unknown.reconstruction["calls"]], ["unknown_upper_bits"])
        self.assertIn("unknown_return_upper32(", unknown.pseudoc)


# ---------------------------------------------------------------------------
# TypeCoercion 本身
# ---------------------------------------------------------------------------

def _variable(name, ctype, width=64):
    return Value("variable", width, name=name, ctype=ctype)


class TypeCoercionTests(unittest.TestCase):
    def test_well_typed_values_are_returned_unchanged(self):
        coercion = TypeCoercion({"p": "uint8_t *", "x": "uint64_t", "n": "uint32_t"}, "uint64_t")
        p, x, n = _variable("p", "uint8_t *"), _variable("x", "uint64_t"), _variable("n", "uint32_t", 32)
        values = [Value("add", 64, (p, Value("constant", 64, number=1)), ctype="uint8_t *"),
                  Value("and", 64, (x, Value("constant", 64, number=0xff)), ctype="uint64_t"),
                  Value("compare", 1, (p, Value("constant", 64, number=0)), name="==", ctype="bool"),
                  Value("index", 8, (p, n), ctype="uint8_t"),
                  Value("select", 64, (Value("compare", 1, (x, n), name="<", ctype="bool"), x, Value("constant", 64, number=3)))]
        for value in values:
            self.assertIs(coercion.expression(value), value)
        statement = Statement("assign", x, "x")
        coercion.statement(statement)
        self.assertIs(statement.value, x)

    def test_integer_operations_on_pointers_use_the_address_integer(self):
        coercion = TypeCoercion({"p": "uint32_t *"}, "uint64_t")
        p = _variable("p", "uint32_t *")
        self.assertEqual(format_value(coercion.expression(Value("and", 64, (p, Value("constant", 64, number=0xff)), ctype="uint64_t"))),
                         "(uint64_t)p & 0xff")
        # 32 位运算只取地址的低 32 位（与微码一致）。
        self.assertEqual(format_value(coercion.expression(Value("or", 32, (p, Value("constant", 32, number=1)), ctype="uint32_t"))),
                         "(uint32_t)(uint64_t)p | 1")
        # 指针与非零整数比较、下标为指针、switch 控制表达式为指针。
        self.assertEqual(format_value(coercion.expression(Value("compare", 1, (p, Value("constant", 64, number=5)), name="<", ctype="bool"))),
                         "(uint64_t)p < 5")
        index = Value("index", 32, (p, Value("cast", 64, (_variable("x", "uint64_t"),), ctype="uint32_t *")), ctype="uint32_t")
        self.assertEqual(format_value(coercion.expression(index)), "p[x]")
        self.assertEqual(format_value(coercion.scalar(p)), "(uint64_t)p")

    def test_integer_result_addition_with_pointer_counts_bytes(self):
        """微码的加法按字节：整数结果的 p + k 不能写成 C 的指针加法（会按 sizeof(*p) 缩放）。"""
        coercion = TypeCoercion({"p": "uint32_t *"}, "uint64_t")
        p = _variable("p", "uint32_t *")
        added = coercion.expression(Value("add", 64, (p, Value("constant", 64, number=4)), ctype="uint64_t"))
        self.assertEqual(format_value(added), "(uint64_t)p + 4")
        # 字节地址运算（结果是指针，节点类型 uint8_t * 表示按字节计）而基址不是字节指针：按字节地址计算后再转回。
        moved = coercion.expression(Value("add", 64, (p, Value("constant", 64, number=4)), ctype="uint8_t *"))
        self.assertEqual(format_value(moved), "(uint8_t *)((uint64_t)p + 4)")
        program = (pseudoc_prelude() + "\n#include <stdio.h>\n"
                   f"static uint64_t added(uint32_t *p) {{ return {format_value(added)}; }}\n"
                   f"static uint8_t *moved(uint32_t *p) {{ return {format_value(moved)}; }}\n"
                   "int main(void) { static uint32_t buffer[8]; uint32_t *p = buffer + 2;\n"
                   "    printf(\"%d %d\\n\", (int)(added(p) - (uint64_t)(uintptr_t)p), (int)((char *)moved(p) - (char *)p));\n"
                   "    return 0; }\n")
        self.assertEqual(compilable._run_c(program), ["4", "4"])

    def test_pointer_arithmetic_counts_units_of_the_node_type(self):
        """指针结果的加减按节点类型的元素计（与 ordering._pointer、readability._index 的约定一致）：ordering 构造的
        arm_load_acquire_32(p + 2) 是 p 之后第 2 个 uint32_t（+8 字节），不能改写成 +2 字节；基址渲染成另一种
        元素大小（变量重定为字节指针）时先把基址转为节点类型。"""
        coercion = TypeCoercion({"p": "uint32_t *", "b": "uint8_t *"}, "uint64_t")
        p, b, two = _variable("p", "uint32_t *"), _variable("b", "uint8_t *"), Value("constant", 64, number=2)
        element = Value("add", 64, (p, two), ctype="uint32_t *")
        load = Value("call", 32, (element,), name="arm_load_acquire_32", ctype="uint32_t", effect=True)
        self.assertIs(coercion.expression(load), load)
        retyped = coercion.expression(Value("add", 64, (b, two), ctype="uint32_t *"))
        self.assertEqual(format_value(retyped), "(uint32_t *)b + 2")
        # void * 的加减按字节（GNU C）：基址不是字节指针时同样按字节地址计算。
        untyped = coercion.expression(Value("add", 64, (p, two), ctype="void *"))
        self.assertEqual(format_value(untyped), "(void *)((uint64_t)p + 2)")
        program = (pseudoc_prelude() + "\n#include <stdio.h>\n"
                   f"static uint32_t *element(uint32_t *p) {{ return {format_value(element)}; }}\n"
                   f"static uint32_t *retyped(uint8_t *b) {{ return {format_value(retyped)}; }}\n"
                   "int main(void) { static uint32_t buffer[8];\n"
                   "    printf(\"%d %d %u\\n\", (int)((char *)element(buffer) - (char *)buffer),\n"
                   "           (int)((char *)retyped((uint8_t *)buffer) - (char *)buffer), arm_load_acquire_32(buffer + 2));\n"
                   "    return 0; }\n")
        self.assertEqual(compilable._run_c(program), ["8", "8", "0"])

    def test_conditional_select_arms(self):
        coercion = TypeCoercion({"p": "uint32_t *", "q": "uint32_t *", "x": "uint64_t", "n": "uint32_t"}, "uint64_t")
        p, q, x, n = (_variable("p", "uint32_t *"), _variable("q", "uint32_t *"), _variable("x", "uint64_t"),
                      _variable("n", "uint32_t", 32))
        condition = Value("compare", 1, (x, Value("constant", 64, number=0)), name="!=", ctype="bool")
        five = Value("constant", 64, number=5)
        # 整数结果：指针臂按地址整数（更窄的选择截到其宽度）；指针结果：整数臂转为指针。
        self.assertEqual(format_value(coercion.expression(Value("select", 64, (condition, p, five), ctype="uint64_t"))),
                         "x != 0 ? (uint64_t)p : 5")
        self.assertEqual(format_value(coercion.expression(Value("select", 32, (condition, p, n), ctype="uint32_t"))),
                         "x != 0 ? (uint32_t)(uint64_t)p : n")
        self.assertEqual(format_value(coercion.expression(Value("select", 64, (condition, x, p), ctype="uint32_t *"))),
                         "x != 0 ? (uint32_t *)x : p")
        # 两臂是兼容的指针、或一臂是空指针常量：本来就合法，原样返回。
        for value in (Value("select", 64, (condition, p, q), ctype="uint64_t"),
                      Value("select", 64, (condition, p, Value("constant", 64, number=0)), ctype="uint64_t")):
            self.assertIs(coercion.expression(value), value)

    def test_narrow_comparison_with_a_pointer_compares_the_low_bits(self):
        # 32 位比较只看低 32 位（与微码一致）：指针操作数先转为地址整数再截到 32 位。
        coercion = TypeCoercion({"p": "uint32_t *", "n": "uint32_t"}, "uint64_t")
        compare = Value("compare", 1, (_variable("p", "uint32_t *", 32), _variable("n", "uint32_t", 32)), name="<", ctype="bool")
        self.assertEqual(format_value(coercion.expression(compare)), "(uint32_t)(uint64_t)p < n")

    def test_own_call_result_keeps_its_recorded_type(self):
        # 返回类型最终细化为指针、调用处记录的结果类型仍是整数：自递归调用的结果先转换回记录的类型，外层到更窄
        # 整数的转换因此不是“指针到更窄整数”（-Wpointer-to-int-cast）。
        coercion = TypeCoercion({"x": "uint32_t"}, "char *", function_name="f", parameter_types=[], check_all=True)
        call = Value("call", 64, (), name="f", ctype="uint64_t", effect=True)
        narrowed = coercion.expression(Value("cast", 8, (call,), ctype="uint8_t"))
        self.assertEqual(format_value(narrowed), "(uint8_t)(uint64_t)f()")
        compilable._syntax_check(pseudoc_prelude() + "\nchar *f(void);\n"
                                 f"uint8_t g(void) {{ return {format_value(narrowed)}; }}\n", *_strict("-Werror=pointer-to-int-cast"))

    def test_function_names_and_qualifiers_in_conversions(self):
        coercion = TypeCoercion({"s": "const char *", "c": "char *", "pp": "char **"}, "uint64_t")
        handler = Value("function", 64, name="handler", ctype="void *")
        s, c, pp = _variable("s", "const char *"), _variable("c", "char *"), _variable("pp", "char **")
        self.assertEqual(format_value(coercion.convert(handler, "const char *")), "(const char *)handler")
        self.assertIs(coercion.convert(handler, "void *"), handler)  # GNU C 扩展，不告警
        self.assertEqual(format_value(coercion.convert(s, "void *")), "(void *)s")
        self.assertEqual(format_value(coercion.convert(s, "char *")), "(char *)s")
        self.assertEqual(format_value(coercion.convert(pp, "const char **")), "(const char **)pp")
        self.assertIs(coercion.convert(c, "const char *"), c)  # 增加限定符是允许的
        self.assertIs(coercion.convert(s, "const void *"), s)
        # 比较两个限定符不同的指针本来就合法（C11 6.5.9），不转换。
        equal = Value("compare", 1, (s, c), name="==", ctype="bool")
        self.assertIs(coercion.expression(equal), equal)

    def test_assignments_returns_and_known_prototype_arguments(self):
        coercion = TypeCoercion({"p": "uint8_t *", "x": "uint64_t", "n": "uint32_t"}, "uint64_t")
        p, x = _variable("p", "uint8_t *"), _variable("x", "uint64_t")
        assigned = Statement("assign", p, "x")
        coercion.statement(assigned)
        self.assertEqual(format_value(assigned.value), "(uint64_t)p")
        narrow = Statement("assign", p, "n")
        coercion.statement(narrow)
        self.assertEqual(format_value(narrow.value), "(uint32_t)(uint64_t)p")
        back = Statement("assign", Value("cast", 64, (x,), ctype="uint64_t *"), "x")
        coercion.statement(back)
        self.assertIs(back.value.op, "variable")  # (uint64_t)(uint64_t *)x 就是 x
        returned = Statement("return", p)
        coercion.statement(returned)
        self.assertEqual(format_value(returned.value), "(uint64_t)p")
        call = coercion.expression(Value("call", 64, (x,), name="strlen", ctype="size_t", effect=True))
        self.assertEqual(format_value(call), "strlen((const char *)x)")
        # 空指针常量 0 与兼容的指针类型不加转换。
        self.assertIs(coercion.convert(Value("constant", 64, number=0), "uint8_t *").op, "constant")
        self.assertIs(coercion.convert(p, "char *"), p)

    def test_truncation_drops_constants_with_zero_low_bits(self):
        """部分写入合并在整数上进行后，(C & ~0xff) 会折叠成低位为 0 的常量：截取低位时它没有贡献。"""
        from fangida.plugins.pseudoc.reconstruct.readability import simplify_value
        flag = Value("select", 8, (Value("compare", 1, (_variable("x", "uint64_t"), Value("constant", 64, number=0)), name="==",
                                         ctype="bool"), Value("constant", 8, number=1), Value("constant", 8, number=0)))
        merged = Value("or", 64, (Value("constant", 64, number=0x100088300), Value("cast", 8, (flag,), ctype="uint8_t")),
                       ctype="uint64_t")
        self.assertEqual(format_value(simplify_value(Value("cast", 8, (merged,), ctype="uint8_t"))), "(uint8_t)(x == 0 ? 1 : 0)")
        # 常量的低位不全为 0 时保留。
        kept = Value("or", 64, (Value("constant", 64, number=0x100088301), Value("cast", 8, (flag,), ctype="uint8_t")), ctype="uint64_t")
        self.assertIn("0x100088301", format_value(simplify_value(Value("cast", 8, (kept,), ctype="uint8_t"))))

    def test_store_destinations_are_lvalues(self):
        coercion = TypeCoercion({"s": "const char *", "e": "int32_t *"}, "void")
        element = Value("index", 8, (_variable("s", "const char *"), Value("constant", 64, number=0)), ctype="char")
        store = Value("store", 8, (Value("cast", 8, (element,), ctype="uint8_t"), Value("constant", 8, number=0)), effect=True)
        statement = Statement("store", store)
        coercion.statement(statement)
        self.assertEqual(format_value(statement.value.args[0]), "((char *)s)[0]")
        slot = Value("index", 32, (_variable("e", "int32_t *"), Value("constant", 64, number=0)), ctype="int32_t")
        statement = Statement("store", Value("store", 32, (Value("cast", 32, (slot,), ctype="uint32_t"),
                                                           _variable("v", "uint32_t", 32)), effect=True))
        coercion.statement(statement)
        self.assertEqual(format_value(statement.value.args[0]), "e[0]")


if __name__ == "__main__":
    unittest.main()
