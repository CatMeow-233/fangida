"""指令控制流分类：助记符分类、ARM 操作数细化、目标提取，以及各解码路径的一致性。

Capstone 的指令组（JUMP/CALL/RET/IRET/BRANCH_RELATIVE）与 AArch32 的 PC 写入集合是
地面真值；陷阱（ud0/ud1/ud2/hlt/int3、brk/udf/hlt、udf/bkpt）是项目约定。
"""
from __future__ import annotations

import importlib.util
import inspect
import random
import struct
import unittest
from unittest.mock import patch

from fangida.core.kkagent import translator
from fangida.core.kkagent.binary import BinaryImage
from fangida.core.kkagent.cfg import build_entry_cfg
from fangida.core.kkagent.semantic import analyze_semantics
from fangida.models import Instruction
from fangida.processors import decoder as decoder_module
from fangida.processors.decoder import NativeDecoder, branch_info, decode_objdump


CAPSTONE = importlib.util.find_spec("capstone") is not None
ARM_CONDITIONS = ("eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le")


def _kind(mnemonic: str) -> tuple[str, bool] | None:
    info = branch_info(mnemonic, None)
    return None if info is None else (info["kind"], info["conditional"])


def _words(endian: str, *values: int) -> bytes:
    return struct.pack(("<" if endian == "little" else ">") + "I" * len(values), *values)


def _decode_all(test: unittest.TestCase, architecture: str, code: bytes, endian: str = "little"):
    """三条 Capstone 路径（逐条 IR、批量快路径、带数据元信息）必须给出同一分支信息。"""
    decoder = NativeDecoder(architecture, endian)
    slow, warnings = decoder.decode_bytes(code, 0x1000, max_instructions=len(code))
    fast, more = decoder.decode_bytes_fast(code, 0x1000, max_instructions=len(code))
    data, extra = decoder.decode_bytes(code, 0x1000, max_instructions=len(code), include_data=True)
    test.assertFalse(warnings + more + extra)
    test.assertEqual([item["branch_info"] for item in slow], [item["branch_info"] for item in fast])
    test.assertEqual([item["branch_info"] for item in slow], [item["branch_info"] for item in data])
    return [(item["mnemonic"], ", ".join(item["operands"]), item["branch_info"]) for item in slow]


def _branch(kind: str | None, target: int | None = None, conditional: bool = False) -> dict:
    return {} if kind is None else {"kind": kind, "target": target, "conditional": conditional}


class MnemonicClassificationTests(unittest.TestCase):
    def test_public_signature_and_record_shape_are_unchanged(self) -> None:
        self.assertEqual(list(inspect.signature(branch_info).parameters), ["mnemonic", "target"])
        self.assertIs(translator._branch, branch_info)
        for mnemonic in ("call", "jmp", "jne", "ret", "ud2", "bl", "b.eq", "bleq", "braa", "eret"):
            with self.subTest(mnemonic=mnemonic):
                self.assertEqual(set(branch_info(mnemonic, 0x40)), {"kind", "target", "conditional"})
        # 调用/跳转透传目标；返回、陷阱和段:偏移远转移没有线性目标。
        self.assertEqual(branch_info("call", 0x40)["target"], 0x40)
        self.assertEqual(branch_info("bne", 0x40)["target"], 0x40)
        for mnemonic in ("ret", "retf", "iretq", "ud2", "brk", "ljmp", "lcall"):
            self.assertIsNone(branch_info(mnemonic, 0x40)["target"], mnemonic)

    def test_x86_prefixed_control_flow_uses_the_core_mnemonic(self) -> None:
        cases = {
            "repz ret": ("return", False), "rep ret": ("return", False), "bnd ret": ("return", False),
            "bnd retf": ("return", False), "bnd jmp": ("jump", False), "bnd call": ("call", False),
            "notrack jmp": ("jump", False), "notrack call": ("call", False),
            "bnd notrack jmp": ("jump", False), "bnd jne": ("jump", True), "bnd jrcxz": ("jump", True),
            "repne jmp": ("jump", False),
        }
        for mnemonic, expected in cases.items():
            self.assertEqual(_kind(mnemonic), expected, mnemonic)
            self.assertEqual(_kind(mnemonic.upper()), expected, mnemonic)

    def test_x86_returns_traps_and_conditional_forms(self) -> None:
        for mnemonic in ("ret", "retf", "retfq", "iret", "iretd", "iretq", "sysret", "sysretq",
                         "sysexit", "sysexitq"):
            self.assertEqual(_kind(mnemonic), ("return", False), mnemonic)
        for mnemonic in ("ud0", "ud1", "ud2", "hlt", "int3"):
            self.assertEqual(_kind(mnemonic), ("trap", False), mnemonic)
        for mnemonic in ("jmp", "jmpq", "ljmp"):
            self.assertEqual(_kind(mnemonic), ("jump", False), mnemonic)
        for mnemonic in ("je", "jne", "jg", "jcxz", "jecxz", "jrcxz", "loop", "loope", "loopne", "xbegin"):
            self.assertEqual(_kind(mnemonic), ("jump", True), mnemonic)
        self.assertEqual(_kind("lcall"), ("call", False))

    def test_x86_bit_and_bound_mnemonics_are_not_branches(self) -> None:
        # int/int1/into/syscall 属于 Capstone INT 组，但执行后回到下一条，不终止基本块。
        for mnemonic in ("bt", "bts", "btr", "btc", "bound", "bsf", "bsr", "bswap", "bextr", "bzhi",
                         "blsr", "blsi", "blsmsk", "blci", "blcs", "blcic", "blsfill", "bndmk", "bndcl",
                         "bndmov", "int", "int1", "into", "syscall", "sysenter", "lock add", "rep stosb"):
            self.assertIsNone(branch_info(mnemonic, None), mnemonic)

    def test_arm64_branches_including_pointer_authentication(self) -> None:
        cases = {
            "b": ("jump", False), "br": ("jump", False), "b.eq": ("jump", True), "b.ne": ("jump", True),
            "b.al": ("jump", False), "b.nv": ("jump", False), "bc.eq": ("jump", True),
            "bc.al": ("jump", False), "cbz": ("jump", True), "cbnz": ("jump", True),
            "tbz": ("jump", True), "tbnz": ("jump", True), "braa": ("jump", False),
            "brab": ("jump", False), "braaz": ("jump", False), "brabz": ("jump", False),
            "bl": ("call", False), "blr": ("call", False), "blraa": ("call", False),
            "blrab": ("call", False), "blraaz": ("call", False), "blrabz": ("call", False),
            "ret": ("return", False), "retaa": ("return", False), "retab": ("return", False),
            "eret": ("return", False), "eretaa": ("return", False), "eretab": ("return", False),
            "drps": ("return", False), "brk": ("trap", False), "hlt": ("trap", False),
            "udf": ("trap", False),
        }
        for mnemonic, expected in cases.items():
            self.assertEqual(_kind(mnemonic), expected, mnemonic)
        for mnemonic in ("bti", "bic", "bics", "bfi", "bfc", "bfm", "bfxil", "bsl", "bif", "bit", "bcax",
                         "paciasp", "autiasp", "svc", "hvc", "smc", "adrp"):
            self.assertIsNone(branch_info(mnemonic, None), mnemonic)

    def test_arm32_condition_suffixes(self) -> None:
        for condition in ARM_CONDITIONS:
            with self.subTest(condition=condition):
                self.assertEqual(_kind("b" + condition), ("jump", True))
                self.assertEqual(_kind("bl" + condition), ("call", True))
                self.assertEqual(_kind("blx" + condition), ("call", True))
                self.assertEqual(_kind("bx" + condition), ("jump", True))
                self.assertEqual(_kind("bxj" + condition), ("jump", True))
        # "bls" 只能是 b+ls，"blls" 才是条件调用；历史拼写 bcs/bcc 保留。
        self.assertEqual(_kind("bls"), ("jump", True))
        self.assertEqual(_kind("blt"), ("jump", True))
        self.assertEqual(_kind("blls"), ("call", True))
        self.assertEqual(_kind("bllt"), ("call", True))
        self.assertEqual(_kind("bcs"), ("jump", True))
        self.assertEqual(_kind("bcc"), ("jump", True))
        for mnemonic in ("b", "bal", "bx", "bxj"):
            self.assertEqual(_kind(mnemonic), ("jump", False), mnemonic)
        for mnemonic in ("bl", "blx"):
            self.assertEqual(_kind(mnemonic), ("call", False), mnemonic)
        for mnemonic in ("eret", "rfeia", "rfeib", "rfeda", "rfedb"):
            self.assertEqual(_kind(mnemonic), ("return", False), mnemonic)
        for mnemonic in ("udf", "bkpt", "hlt"):
            self.assertEqual(_kind(mnemonic), ("trap", False), mnemonic)
        # 操作数决定的返回由解码器细化；单看助记符 pop/ldm/mov 不是分支。
        for mnemonic in ("pop", "popeq", "ldm", "ldmdb", "mov", "moveq", "bic", "bics", "biceq", "bfi",
                         "bfc", "blcs", "bxcs", "push", "svc", "smc"):
            self.assertIsNone(branch_info(mnemonic, None), mnemonic)

    def test_thumb_width_qualifiers_and_table_branches(self) -> None:
        self.assertEqual(_kind("b.w"), ("jump", False))
        self.assertEqual(_kind("b.n"), ("jump", False))
        self.assertEqual(_kind("beq.w"), ("jump", True))
        self.assertEqual(_kind("tbb"), ("jump", False))
        self.assertEqual(_kind("tbh"), ("jump", False))


@unittest.skipUnless(CAPSTONE, "Capstone unavailable")
class DecoderBranchTests(unittest.TestCase):
    def test_x86_64_targets_prefixes_and_far_transfers(self) -> None:
        records = _decode_all(self, "x86_64", bytes.fromhex(
            "c20800" "f3c3" "f2c3" "f2e800000000" "f2e900000000" "3effe0" "3eff142500000000"
            "48ff2c24" "ff2c24" "c7f800000000" "e300" "0f0b" "0fb9" "cf" "48cf" "0f07" "cc" "cd80"))
        self.assertEqual([(mnemonic, branch) for mnemonic, _, branch in records], [
            ("ret", _branch("return")),                       # 立即数是弹栈字节数，不是目标
            ("repz ret", _branch("return")),
            ("bnd ret", _branch("return")),
            ("bnd call", _branch("call", 0x100d)),
            ("bnd jmp", _branch("jump", 0x1013)),
            ("notrack jmp", _branch("jump")),
            ("notrack call", _branch("call")),
            ("ljmp", _branch("jump")),
            ("jmp", _branch("jump")),
            ("xbegin", _branch("jump", 0x102b, True)),
            ("jrcxz", _branch("jump", 0x102d, True)),
            ("ud2", _branch("trap")),
            ("ud1", _branch("trap")),
            ("iretd", _branch("return")),
            ("iretq", _branch("return")),
            ("sysret", _branch("return")),
            ("int3", _branch("trap")),
            ("int", {}),
        ])

    def test_x86_32_far_pointer_is_not_a_linear_target(self) -> None:
        records = _decode_all(self, "x86", bytes.fromhex("ea78563412cdab" "9a78563412cdab" "f3c3"))
        self.assertEqual([branch for _, _, branch in records],
                         [_branch("jump"), _branch("call"), _branch("return")])

    def test_arm64_test_bit_target_and_pointer_authentication(self) -> None:
        records = _decode_all(self, "arm64", _words(
            "little", 0x36180040, 0xb6f80040, 0xb4000040, 0x54000080, 0x5400008e, 0x54000090,
            0xd71f0820, 0xd61f081f, 0xd73f0820, 0xd63f0c1f, 0xd65f0bff, 0xd69f03e0, 0xd4200020,
            0x00000000, 0xd503245f, 0x0a200000))
        self.assertEqual([(mnemonic, branch) for mnemonic, _, branch in records], [
            ("tbz", _branch("jump", 0x1008, True)),           # 不是位号 #3
            ("tbz", _branch("jump", 0x100c, True)),           # 不是位号 #0x3f
            ("cbz", _branch("jump", 0x1010, True)),
            ("b.eq", _branch("jump", 0x101c, True)),
            ("b.al", _branch("jump", 0x1020, False)),
            ("bc.eq", _branch("jump", 0x1024, True)),
            ("braa", _branch("jump")), ("braaz", _branch("jump")),
            ("blraa", _branch("call")), ("blrabz", _branch("call")),
            ("retaa", _branch("return")), ("eret", _branch("return")),
            ("brk", _branch("trap")),                         # 注释号 #1 不是目标
            ("udf", _branch("trap")),
            ("bti", {}), ("bic", {}),
        ])

    def test_arm32_operand_refinement_in_both_byte_orders(self) -> None:
        direct = object()  # 直接目标 = 指令地址 + 8（PC 预取）+ imm24 * 4，imm24 = 2
        cases = [
            (0xe12fff1e, _branch("return")),                  # bx lr
            (0x012fff1e, _branch("jump", None, True)),        # bxeq lr：条件返回暂按条件间接跳转，保留落空边
            (0xe12fff13, _branch("jump")),                    # bx r3
            (0xe12fff33, _branch("call")),                    # blx r3
            (0x012fff33, _branch("call", None, True)),        # blxeq r3
            (0xe8bd8010, _branch("return")),                  # pop {r4, pc}
            (0x08bd8010, _branch("jump", None, True)),        # popeq {r4, pc}
            (0xe49df004, _branch("return")),                  # pop {pc}（ldr pc, [sp], #4）
            (0xe49df008, _branch("return")),                  # ldr pc, [sp], #8
            (0xe91ba830, _branch("return")),                  # ldmdb fp, {r4, r5, fp, sp, pc}（APCS）
            (0xe93ba830, _branch("return")),                  # ldmdb fp!, {r4, r5, fp, sp, pc}
            (0xe891800f, _branch("jump")),                    # ldm r1, {r0, r1, r2, r3, pc}：非栈基址
            (0xe8b08002, _branch("jump")),                    # ldm r0!, {r1, pc}：longjmp 式
            (0xe9bf01b7, _branch("jump")),                    # ldmib pc!, {..}：只经写回改写 pc
            (0xe8bf8000, _branch("jump")),                    # ldm pc!, {pc}
            (0xe91ea830, _branch("jump")),                    # ldmdb lr, {.., pc}：不是帧指针
            (0xe99ba830, _branch("jump")),                    # ldmib fp, {.., pc}：APCS 只用 ldmdb
            (0x0891800f, _branch("jump", None, True)),        # ldmeq r1, {.., pc}
            (0xe8fd8000, _branch("return")),                  # ldm sp!, {pc} ^
            (0xe8bd8000, _branch("return")),                  # ldm sp!, {pc}（ldmia/ldmfd sp!）
            (0xe89d8010, _branch("return")),                  # ldm sp, {r4, pc}
            (0xe9bd8010, _branch("return")),                  # ldmib sp!, {r4, pc}（ldmed）
            (0xe83d8010, _branch("return")),                  # ldmda sp!, {r4, pc}（ldmfa）
            (0xe93d8010, _branch("return")),                  # ldmdb sp!, {r4, pc}（ldmea）
            (0x093d8010, _branch("jump", None, True)),        # ldmdbeq sp!, {r4, pc}
            (0xe8bd0010, {}),                                 # ldm sp!, {r4}：不写 pc
            (0xe1a0f00e, _branch("return")),                  # mov pc, lr
            (0x01a0f00e, _branch("jump", None, True)),        # moveq pc, lr
            (0xe1b0f00e, _branch("return")),                  # movs pc, lr
            (0xe25ef004, _branch("return")),                  # subs pc, lr, #4
            (0xe1a0f003, _branch("jump")),                    # mov pc, r3
            (0xe08ff102, _branch("jump")),                    # add pc, pc, r2, lsl #2
            (0x908ff102, _branch("jump", None, True)),        # addls pc, pc, r2, lsl #2（跳转表）
            (0xe59ff004, _branch("jump")),                    # ldr pc, [pc, #4]
            (0xe79ff102, _branch("jump")),                    # ldr pc, [pc, r2, lsl #2]
            (0xe28ef000, _branch("jump")),                    # add pc, lr, #0：立即数不是目标
            (0xe160006e, _branch("return")),                  # eret
            (0xf8bd0a00, _branch("return")),                  # rfeia sp!
            (0xe7f000f0, _branch("trap")),                    # udf #0：立即数不是目标
            (0xe1200070, _branch("trap")),                    # bkpt #0
            (0x0b000002, _branch("call", direct, True)),      # bleq
            (0xfa000002, _branch("call", direct)),            # blx #imm
            (0x1a000002, _branch("jump", direct, True)),      # bne
            (0xe8bd4010, {}),                                 # pop {r4, lr}
            (0xe92d4010, {}),                                 # push {r4, lr}
            (0xe58df000, {}),                                 # str pc, [sp]
            (0xe1a0e00f, {}),                                 # mov lr, pc
            (0xe59f0004, {}),                                 # ldr r0, [pc, #4]
            (0xe15f0000, {}),                                 # cmp pc, r0
            (0xef000000, {}),                                 # svc #0
        ]
        cases = [(word, {**branch, "target": 0x1000 + 4 * index + 16}
                  if branch.get("target") is direct else branch)
                 for index, (word, branch) in enumerate(cases)]
        for endian in ("little", "big"):
            with self.subTest(endian=endian):
                records = _decode_all(self, "arm", _words(endian, *(word for word, _ in cases)), endian)
                self.assertEqual(len(records), len(cases))
                for (word, expected), (mnemonic, operands, branch) in zip(cases, records):
                    self.assertEqual(branch, expected, f"{word:08x} {mnemonic} {operands}")

    def test_arm_ldm_return_reproductions_and_register_spellings(self) -> None:
        # 复核复现：longjmp 式 ldm 与只经写回改写 pc 的 ldmib pc! 都不是返回。
        decoder = NativeDecoder("arm")
        for encoded in ("0280b0e8", "b701bfe9"):
            for method in (decoder.decode_bytes, decoder.decode_bytes_fast):
                with self.subTest(encoded=encoded, method=method.__name__):
                    records, warnings = method(bytes.fromhex(encoded), 0x1000)
                    self.assertFalse(warnings)
                    self.assertEqual(records[0]["branch_info"], _branch("jump"))
        # CS_OPT_SYNTAX_NOREGNAME 把 fp 打印为 r11（sp/pc 仍是别名）：APCS 返回不受拼写影响。
        import capstone
        decoder.disassembler.syntax = capstone.CS_OPT_SYNTAX_NOREGNAME
        code = _words("little", 0xe91ba830, 0xe8bd8000, 0xe8b08002)
        for method in (decoder.decode_bytes, decoder.decode_bytes_fast):
            records, _ = method(code, 0x1000)
            self.assertEqual([(item["mnemonic"], item["operands"][0], item["branch_info"]) for item in records], [
                ("ldmdb", "r11", _branch("return")), ("ldm", "sp!", _branch("return")),
                ("ldm", "r0!", _branch("jump"))])
        # 文本判定只看基址与寄存器列表；区间写法的端点为 pc 时同样含 pc。
        pc_write = decoder_module._arm_pc_write
        self.assertEqual(pc_write("ldmdb", "r11, {r4-pc}", False), _branch("return"))
        self.assertEqual(pc_write("ldmea", "fp, {r4, fp, sp, pc}", False), _branch("return"))
        self.assertEqual(pc_write("ldmia", "r13!, {r4, r15}", False), _branch("return"))
        self.assertEqual(pc_write("ldm.w", "sp!, {r4, pc}", False), _branch("return"))
        self.assertEqual(pc_write("ldm", "sp!, {r4, lr}", False), _branch("jump"))
        self.assertEqual(pc_write("ldm", "sp!", False), _branch("jump"))
        self.assertEqual(pc_write("ldmdb", "fp, {r4, fp, sp, pc}", True), _branch("jump", None, True))

    def test_random_arm_ldm_returns_follow_the_structured_base_register(self) -> None:
        # 独立真值：Capstone 结构化操作数（operands[0] 为基址，其余为寄存器列表）。
        import capstone
        rng = random.Random(20261002)
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        words = []
        for _ in range(3000):
            # cond、P/U/S/W 位、基址寄存器与寄存器列表随机；L=1（LDM）且列表或基址常含 pc。
            word = (rng.choice((0xe, 0xe, 0xe, 0x0, 0x1)) << 28) | (0x4 << 25) | (rng.getrandbits(4) << 21) \
                | (1 << 20) | (rng.choice((13, 13, 11, 11, rng.getrandbits(4))) << 16) | rng.getrandbits(16)
            if rng.random() < 0.8:
                word |= 1 << 15
            if next(md.disasm(_words("little", word), 0, count=1), None) is not None:
                words.append(word)
        stats = {"return": 0, "jump": 0}
        for endian in ("little", "big"):
            code = _words(endian, *words)
            records = _decode_all(self, "arm", code, endian)
            truth_md = capstone.Cs(capstone.CS_ARCH_ARM,
                                   capstone.CS_MODE_ARM | (capstone.CS_MODE_BIG_ENDIAN if endian == "big" else 0))
            truth_md.detail = True
            truth = list(truth_md.disasm(code, 0x1000))
            self.assertEqual(len(truth), len(records))
            for ins, (_, _, branch) in zip(truth, records):
                writes_pc = capstone.arm.ARM_REG_PC in ins.regs_access()[1]
                if not writes_pc:
                    self.assertEqual(branch, {}, f"{ins.mnemonic} {ins.op_str}")
                    continue
                conditional = ins.cc not in (capstone.arm.ARM_CC_AL, capstone.arm.ARM_CC_INVALID)
                registers = [operand.reg for operand in ins.operands]
                if ins.mnemonic.startswith("pop"):
                    base, listed = capstone.arm.ARM_REG_SP, registers
                else:
                    base, listed = registers[0], registers[1:]
                returns = capstone.arm.ARM_REG_PC in listed and (
                    base == capstone.arm.ARM_REG_SP
                    or (ins.mnemonic == "ldmdb" and base == capstone.arm.ARM_REG_R11))
                expected = (_branch("jump", None, True) if conditional else
                            _branch("return") if returns else _branch("jump"))
                self.assertEqual(branch, expected, f"{ins.mnemonic} {ins.op_str}")
                stats[expected["kind"]] += 1
        # 两类都确实出现，测试不会因生成器偏置而空转。
        self.assertGreater(stats["return"], 100)
        self.assertGreater(stats["jump"], 100)

    def test_third_party_classifier_keeps_two_arguments_and_is_not_refined(self) -> None:
        calls = []

        def classify(mnemonic, target):
            calls.append((mnemonic, target))
            if mnemonic.startswith("bx") or mnemonic == "bl":
                return {"kind": "jump" if mnemonic.startswith("bx") else "call", "target": 7,
                        "conditional": False}
            if mnemonic == "ret":
                return {"kind": "return", "target": 7, "conditional": False}
            return None

        decoder = NativeDecoder("arm")
        code = _words("little", 0xe12fff1e, 0xe8bd8010, 0xeb000002)
        for method in (decoder.decode_bytes, decoder.decode_bytes_fast):
            with self.subTest(method=method.__name__):
                calls.clear()
                records, _ = method(code, 0x1000, classify=classify)
                self.assertEqual(calls, [("bx", None), ("pop", None), ("bl", None)])
                # 只有默认分类才做 ARM 操作数细化；外部分类仍得到操作数立即数目标。
                self.assertEqual([item["branch_info"] for item in records],
                                 [{"kind": "jump", "target": None, "conditional": False}, {},
                                  {"kind": "call", "target": 0x1018, "conditional": False}])
        x86 = NativeDecoder("x86_64")
        for method in (x86.decode_bytes, x86.decode_bytes_fast):
            records, _ = method(bytes.fromhex("c20800"), 0x1000, classify=classify)
            # 返回不再被操作数立即数覆盖目标，保留外部分类给出的值。
            self.assertEqual(records[0]["branch_info"], {"kind": "return", "target": 7, "conditional": False})

    def test_entry_and_semantic_paths_share_the_refined_classification(self) -> None:
        code = _words("little", 0xe3500000, 0x012fff1e, 0xe3a00001, 0xe8bd8010, 0xe3a00002, 0xe12fff1e)
        image = BinaryImage("elf", "arm", 32, "little", entry_address=0x1000, entry_offset=0,
                            sections=[{"name": ".text", "address": 0x1000, "offset": 0,
                                       "size": len(code), "executable": True}])
        entry, warnings = translator.disassemble_entry(code, image)
        self.assertFalse(warnings)
        self.assertEqual([item["branch_info"].get("kind") for item in entry],
                         [None, "jump", None, "return", None, "return"])
        functions, _, _, _ = analyze_semantics(code, image)
        function = next(item for item in functions if item["start"] == 0x1000)
        reached = [ins["addr"] for block in function["blocks"] for ins in block["instructions"]]
        # 条件返回之后的顺序路径仍在 CFG 中；无条件 pop {.., pc} 终止函数，不落入下一段代码。
        self.assertEqual(reached, [0x1000, 0x1004, 0x1008, 0x100c])
        self.assertIn({"src": 0x1004, "dst": 0x1008, "kind": "fallthrough"}, function["cfg"]["edges"])
        self.assertEqual([item["reason"] for item in function["cfg"]["frontier"]], ["indirect_jump"])
        graph, seen = build_entry_cfg(entry, 0x1000)
        self.assertEqual(seen, {0x1000, 0x1004, 0x1008, 0x100c})

    def test_semantic_cfg_stops_at_prefixed_x86_returns_and_indirect_jumps(self) -> None:
        code = bytes.fromhex("f3c3" "90c3" "3effe0" "90c3")
        image = BinaryImage("elf", "x86_64", 64, "little", entry_address=0x1000, entry_offset=0,
                            sections=[{"name": ".text", "address": 0x1000, "offset": 0,
                                       "size": len(code), "executable": True}],
                            functions=[{"name": "a", "start": 0x1000, "size": None},
                                       {"name": "b", "start": 0x1004, "size": None}])
        functions, _, _, _ = analyze_semantics(code, image)
        by_start = {item["start"]: item for item in functions}
        self.assertEqual([ins["addr"] for block in by_start[0x1000]["blocks"] for ins in block["instructions"]],
                         [0x1000])
        self.assertTrue(by_start[0x1000]["cfg"]["complete"])
        self.assertEqual([ins["addr"] for block in by_start[0x1004]["blocks"] for ins in block["instructions"]],
                         [0x1004])
        self.assertEqual(by_start[0x1004]["cfg"]["frontier"],
                         [{"from": 0x1004, "to": None, "reason": "indirect_jump"}])

    def test_random_streams_match_capstone_ground_truth_on_every_path(self) -> None:
        import capstone

        def x86_stream(mode: int) -> bytes:
            md = capstone.Cs(capstone.CS_ARCH_X86, mode)
            prefixes = (0x66, 0x67, 0xf2, 0xf3, 0x3e, 0x2e)
            heads = [[0x70 + i] for i in range(16)] + [[x] for x in (
                0xe0, 0xe1, 0xe2, 0xe3, 0xe8, 0xe9, 0xeb, 0xc2, 0xc3, 0xca, 0xcb, 0xcc, 0xcd, 0xcf,
                0xf4, 0xff, 0xc7, 0xea, 0x9a)] + [[0x0f, x] for x in (0x05, 0x07, 0x0b, 0xb9, 0xff, 0x84)]
            out = bytearray()
            for _ in range(2500):
                raw = bytes([rng.choice(prefixes) for _ in range(rng.randint(0, 2))] + rng.choice(heads)
                            + [rng.getrandbits(8) for _ in range(10)]) if rng.random() < 0.6 else \
                    bytes(rng.getrandbits(8) for _ in range(15))
                first = next(md.disasm(raw, 0, count=1), None)
                if first is not None:
                    out += first.bytes
            return bytes(out)

        def word_stream(family: int, mode: int, endian: str, bias) -> bytes:
            md = capstone.Cs(family, mode)
            out = bytearray()
            for _ in range(2500):
                word = _words(endian, bias(rng.getrandbits(32)))
                if next(md.disasm(word, 0, count=1), None) is not None:
                    out += word
            return bytes(out)

        def arm_bias(word: int) -> int:
            choice = rng.random()
            if choice < 0.25:
                return word | (0xf << 12)                      # Rd/Rt = pc
            if choice < 0.4:
                return (word & ~(0x7 << 25)) | (0x4 << 25) | (1 << 20) | (1 << 15)   # LDM/POP 含 pc
            if choice < 0.55:
                return (word & ~(0x7 << 25)) | (0x5 << 25)   # B/BL/BLX
            if choice < 0.7:
                return (word & 0xf000000f) | 0x012fff10 | (rng.choice((1, 2, 3)) << 4)
            return word

        def arm64_bias(word: int) -> int:
            return (word & ~(0x7 << 26)) | (0x5 << 26) if rng.random() < 0.6 else word

        rng = random.Random(20261001)
        streams = [
            ("x86", "little", x86_stream(capstone.CS_MODE_32), capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            ("x86_64", "little", x86_stream(capstone.CS_MODE_64), capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            ("arm", "little", word_stream(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, "little", arm_bias),
             capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            ("arm", "big", word_stream(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN,
                                       "big", arm_bias),
             capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | capstone.CS_MODE_BIG_ENDIAN),
            ("arm64", "little", word_stream(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, "little", arm64_bias),
             capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        ]
        groups = {capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_RET,
                  capstone.CS_GRP_IRET, capstone.CS_GRP_BRANCH_RELATIVE}
        traps = {"ud0", "ud1", "ud2", "hlt", "int3", "brk", "udf", "bkpt"}
        returns = {"eret", "eretaa", "eretab", "drps", "rfeia", "rfeib", "rfeda", "rfedb"}
        for architecture, endian, code, family, mode in streams:
            with self.subTest(architecture=architecture, endian=endian):
                records = _decode_all(self, architecture, code, endian)
                md = capstone.Cs(family, mode)
                md.detail = True
                truth = list(md.disasm(code, 0x1000))
                self.assertEqual(len(truth), len(records))
                for ins, (_, _, branch) in zip(truth, records):
                    core = ins.mnemonic.rsplit(None, 1)[-1]
                    writes_pc = (family == capstone.CS_ARCH_ARM
                                 and capstone.arm.ARM_REG_PC in ins.regs_access()[1])
                    expected = (bool(set(ins.groups) & groups) or writes_pc or core in traps
                                or core in returns or core.startswith("bc."))
                    self.assertEqual(bool(branch), expected, f"{ins.address:#x} {ins.mnemonic} {ins.op_str}")
                    kind = branch.get("kind")
                    if capstone.CS_GRP_CALL in ins.groups:
                        self.assertEqual(kind, "call", ins.mnemonic)
                    elif capstone.CS_GRP_RET in ins.groups or capstone.CS_GRP_IRET in ins.groups:
                        self.assertEqual(kind, "return", ins.mnemonic)
                    if family == capstone.CS_ARCH_ARM and branch:
                        conditional = ins.cc not in (capstone.arm.ARM_CC_AL, capstone.arm.ARM_CC_INVALID)
                        self.assertEqual(branch["conditional"], conditional and kind != "trap", ins.mnemonic)
                    immediates = [operand.imm for operand in ins.operands
                                  if operand.type == capstone.CS_OP_IMM]
                    if kind in {"call", "jump"} and capstone.CS_GRP_BRANCH_RELATIVE in ins.groups and immediates:
                        self.assertEqual(branch["target"], immediates[-1], ins.mnemonic)
                    if kind in {"return", "trap"}:
                        self.assertIsNone(branch["target"], ins.mnemonic)

    def test_fast_path_operand_prefilter_loses_no_address_evidence(self) -> None:
        # 快路径不再为返回/陷阱展开 operands：强制展开时的数据元信息必须完全相同。
        rng = random.Random(7)
        code = {"x86_64": bytes.fromhex("c20800" "c3" "0fb90425" "10000000" "cc" "0f0b" "f4") * 3,
                "arm64": _words("little", 0xd4200020, 0xd65f03c0, 0x00000000, 0xd65f0bff) * 3,
                "arm": _words("little", 0xe1200070, 0xe7f000f0, 0xe12fff1e, 0xe8bd8010) * 3}
        code["x86_64"] += bytes(rng.getrandbits(8) for _ in range(4096))
        for architecture, data in code.items():
            with self.subTest(architecture=architecture):
                decoder = NativeDecoder(architecture)
                normal, _ = decoder.decode_bytes_fast(data, 0x1000, max_instructions=len(data),
                                                      include_data=True)
                with patch.object(decoder_module, "_TARGETLESS_KINDS", frozenset()):
                    forced, _ = decoder.decode_bytes_fast(data, 0x1000, max_instructions=len(data),
                                                          include_data=True)
                self.assertEqual([item["arch_meta"] for item in normal], [item["arch_meta"] for item in forced])

    def test_x86_small_decimal_absolutes_and_immediates_keep_data_metadata(self) -> None:
        # Capstone 把 0–9 打印为十进制（"[5]"、"eax, 5"、"push -1"）：预过滤不得漏掉绝对位移；
        # 十进制打印的小立即数按约定不作地址候选（避免基址为 0 的映像产生伪数据引用）。
        cases = [
            ("x86", "a105000000", "dword ptr [5]", {"memory_references": (5,)}),
            ("x86", "8b0c2509000000", "dword ptr [9]", {"memory_references": (9,)}),
            ("x86", "26a105000000", "dword ptr es:[5]", {"memory_references": (5,)}),
            ("x86", "64a105000000", "dword ptr fs:[5]", {}),           # FS/GS 偏移不是线性地址
            ("x86", "8d042505000000", "[5]", {"memory_references": (5,)}),
            ("x86", "b805000000", "5", {}),
            ("x86", "6aff", "-1", {}),
            ("x86", "b80a000000", "0xa", {"address_candidates": (10,)}),
            ("x86", "6af6", "-0xa", {"address_candidates": (0xfffffff6,)}),
            ("x86", "c7042505000000" "07000000", "7", {"memory_references": (5,)}),
            ("x86_64", "8b042505000000", "dword ptr [5]", {"memory_references": (5,)}),
            ("x86_64", "48b80500000000000000", "5", {}),
            ("x86_64", "6a05", "5", {}),
            ("x86_64", "8b0425f7ffffff", "dword ptr [0xfffffffffffffff7]",
             {"memory_references": (0xfffffffffffffff7,)}),
        ]
        for architecture, encoded, operand, expected in cases:
            with self.subTest(architecture=architecture, encoded=encoded):
                decoder = NativeDecoder(architecture)
                code = bytes.fromhex(encoded)
                fast, warnings = decoder.decode_bytes_fast(code, 0x1000, include_data=True)
                slow, more = decoder.decode_bytes(code, 0x1000, include_data=True)
                self.assertFalse(warnings + more)
                self.assertEqual(fast, slow)
                self.assertEqual(len(fast), 1)
                self.assertEqual(fast[0]["operands"][-1], operand)
                self.assertEqual(fast[0]["arch_meta"],
                                 {"engine": "capstone", "architecture": architecture, **expected})
                # 默认快照保持历史行为：只有 PC 相对引用，不描述绝对地址与立即数候选。
                plain, _ = decoder.decode_bytes_fast(code, 0x1000)
                self.assertEqual(plain[0]["arch_meta"], {"engine": "capstone", "architecture": architecture})

    def test_x86_prefilter_matches_forced_operand_expansion_on_random_streams(self) -> None:
        # 第三方分类器对每条指令都返回可取目标的分支：此时快路径对所有指令展开 operands，
        # 数据元信息与分支分类无关，因此可作"强制展开"的参照；预过滤结果必须逐条相同。
        def everything(mnemonic, target):
            return {"kind": "jump", "target": target, "conditional": False}

        opcodes = [b"\x8b\x04\x25", b"\x8b\x05", b"\xa1", b"\xa3", b"\xff\x24\x25", b"\x89\x04\x25", b"\x68",
                   b"\x6a", b"\xb8", b"\x48\xb8", b"\xc7\xc0", b"\x8d\x04\x25", b"\x26\xa1", b"\x64\xa1",
                   b"\x67\x8b\x06", b"\x8b\x04\xe5", b"\x80\x3c\x25", b"\xc7\x04\x25"]
        import capstone
        rng = random.Random(20261003)
        evidence = {"small_reference": 0, "hex_candidate": 0, "negative_candidate": 0}
        for architecture in ("x86", "x86_64"):
            md = capstone.Cs(capstone.CS_ARCH_X86,
                             capstone.CS_MODE_64 if architecture == "x86_64" else capstone.CS_MODE_32)
            code = bytearray()
            for _ in range(6000):
                if rng.random() < 0.4:
                    raw = bytes(rng.getrandbits(8) for _ in range(15))
                else:
                    value = rng.choice((rng.randint(0, 9), rng.getrandbits(32), (1 << 32) - rng.randint(1, 9)))
                    raw = rng.choice(opcodes) + struct.pack("<II", value, rng.randint(0, 9))
                # 只拼接可解码的首条指令，保证整段流不会在无效字节处提前结束。
                first = next(md.disasm(raw, 0, count=1), None)
                if first is not None:
                    code += first.bytes
            code = bytes(code)
            decoder = NativeDecoder(architecture)
            mask = (1 << (64 if architecture == "x86_64" else 32)) - 1
            for include_data in (False, True):
                with self.subTest(architecture=architecture, include_data=include_data):
                    normal, warnings = decoder.decode_bytes_fast(code, 0x400000, max_instructions=len(code),
                                                                 include_data=include_data)
                    forced, more = decoder.decode_bytes_fast(code, 0x400000, max_instructions=len(code),
                                                             include_data=include_data, classify=everything)
                    self.assertFalse(warnings + more)
                    self.assertEqual(len(normal), len(forced))
                    self.assertGreater(len(normal), 5000)
                    for left, right in zip(normal, forced):
                        self.assertEqual(left["arch_meta"], right["arch_meta"],
                                         f"{left['addr']:#x} {left['mnemonic']} {left['operands']}")
                    if include_data:
                        for item in normal:
                            metadata = item["arch_meta"]
                            evidence["small_reference"] += any(
                                0 < value < 10 for value in metadata.get("memory_references", ()))
                            candidates = metadata.get("address_candidates", ())
                            # 候选只来自十六进制打印的立即数；十进制打印的 -9…9 不作候选。
                            if candidates:
                                self.assertTrue(item["operands"][-1].startswith(("0x", "-0x")),
                                                f"{item['addr']:#x} {item['mnemonic']} {item['operands']}")
                            evidence["hex_candidate"] += bool(candidates)
                            evidence["negative_candidate"] += any(
                                value > mask >> 1 for value in candidates)
        # 随机流确实覆盖了十进制打印的小绝对位移、十六进制候选与负立即数候选。
        for name, count in evidence.items():
            self.assertGreater(count, 20, name)


class ObjdumpFallbackTests(unittest.TestCase):
    LLVM = "\n".join([
        "    1000: f3 c3                        \trep\t\tret",
        "    1002: f2 c3                        \trepne\t\tret",
        "    1004: f2 e9 00 00 00 00            \trepne\t\tjmp\t0x100a <.text+0xa>",
        "    100a: f2 ff e0                     \trepne\t\tjmp\trax",
        "    100d: c2 08 00                     \tret\t0x8",
        "    1010: 0f 0b                        \tud2",
        "    1012: 0f b9 00                     \tud1\teax, dword ptr [rax]",
        "    1015: 48 ff 2c 24                  \tljmp\t[rsp]",
        "    1019: cf                           \tiretd",
        "    101a: 0f 07                        \tsysret",
        "    101c: e3 fe                        \tjrcxz\t0x101c <.text+0x1c>",
        "    101e: c7 f8 00 00 00 00            \txbegin\t0x1024 <.text+0x24>",
        "    1024: f0 83 00 01                  \tlock\t\tadd\tdword ptr [rax], 0x1",
    ])
    GNU = "\n".join([
        "    1000:\tf3 c3                \trepz ret",
        "    1002:\t3e ff e0             \tnotrack jmp rax",
        "    1005:\tf2 e8 00 00 00 00    \tbnd call 0x100b",
        "    100b:\t3e f2 ff 24 25 00 00 00 00 \tnotrack bnd jmp QWORD PTR ds:0x0",
        "    1014:\tea 78 56 34 12 cd ab \tjmp    0xabcd:0x12345678",
    ])

    def _decode(self, rendered: str, architecture: str = "x86_64"):
        records, warnings = decode_objdump(b"x", 0x1000, architecture, render=lambda *_: (rendered, "llvm"))
        self.assertIn("Register read/write", warnings[0])
        return [(item["mnemonic"], item["operands"], item["branch_info"]) for item in records]

    def test_llvm_listing_folds_control_flow_prefixes_like_capstone(self) -> None:
        self.assertEqual(self._decode(self.LLVM), [
            ("rep ret", (), _branch("return")),
            ("repne ret", (), _branch("return")),
            ("repne jmp", ("0x100a <.text+0xa>",), _branch("jump", 0x100a)),
            ("repne jmp", ("rax",), _branch("jump")),
            ("ret", ("0x8",), _branch("return")),
            ("ud2", (), _branch("trap")),
            ("ud1", ("eax", "dword ptr [rax]"), _branch("trap")),
            ("ljmp", ("[rsp]",), _branch("jump")),
            ("iretd", (), _branch("return")),
            ("sysret", (), _branch("return")),
            ("jrcxz", ("0x101c <.text+0x1c>",), _branch("jump", 0x101c, True)),
            ("xbegin", ("0x1024 <.text+0x24>",), _branch("jump", 0x1024, True)),
            # 非控制流的带前缀指令保持历史 IR。
            ("lock", ("add\tdword ptr [rax]", "0x1"), {}),
        ])

    def test_gnu_listing_folds_notrack_and_bnd(self) -> None:
        self.assertEqual(self._decode(self.GNU, "x86"), [
            ("repz ret", (), _branch("return")),
            ("notrack jmp", ("rax",), _branch("jump")),
            ("bnd call", ("0x100b",), _branch("call", 0x100b)),
            ("notrack bnd jmp", ("QWORD PTR ds:0x0",), _branch("jump")),
            ("jmp", ("0xabcd:0x12345678",), _branch("jump")),
        ])

    def test_missing_capstone_uses_the_same_classification_through_the_decoder(self) -> None:
        rendered = "\n".join(self.LLVM.splitlines()[:5])
        with patch.dict("sys.modules", {"capstone": None}), \
                patch("fangida.processors.decoder.disassemble_bytes", return_value=(rendered, "llvm")):
            decoder = NativeDecoder("x86_64")
            self.assertEqual(decoder.engine, "objdump")
            fallback, _ = decoder.decode_bytes(b"x", 0x1000)
            fast, _ = decoder.decode_bytes_fast(b"x", 0x1000, include_data=True)
        self.assertEqual([item["branch_info"] for item in fallback], [item["branch_info"] for item in fast])
        if CAPSTONE:
            native, _ = NativeDecoder("x86_64").decode_bytes(
                bytes.fromhex("f3c3" "f2c3" "f2e900000000" "f2ffe0" "c20800"), 0x1000)
            self.assertEqual([item["branch_info"] for item in fallback],
                             [item["branch_info"] for item in native])


    @unittest.skipUnless(CAPSTONE and translator.objdump_available(), "Capstone or objdump unavailable")
    def test_installed_objdump_agrees_with_capstone(self) -> None:
        code = bytes.fromhex("f3c3" "f2c3" "f2e900000000" "f2ffe0" "3effe0" "c20800" "0f0b" "e800000000" "c3")
        fallback, _ = translator._objdump(code, 0x1000, "x86_64")
        native, _ = NativeDecoder("x86_64").decode_bytes(code, 0x1000)
        self.assertEqual([(item["addr"], item["branch_info"]) for item in fallback],
                         [(item["addr"], item["branch_info"]) for item in native])


class EntryCfgConditionalReturnTests(unittest.TestCase):
    def test_conditional_return_keeps_its_fallthrough_edge(self) -> None:
        def ins(addr: int, mnemonic: str, branch: dict | None = None) -> dict:
            return Instruction(addr, 4, mnemonic, branch_info=branch or {}).to_dict()

        # 处理器若显式给出条件返回（kind=return、conditional=True），入口 CFG 保留落空边。
        graph, reached = build_entry_cfg([
            ins(0x1000, "cmp"), ins(0x1004, "bxeq", _branch("return", None, True)),
            ins(0x1008, "mov"), ins(0x100c, "bx", _branch("return")), ins(0x1010, "nop")], 0x1000)
        self.assertEqual(reached, {0x1000, 0x1004, 0x1008, 0x100c})
        self.assertTrue(graph["complete"])
        self.assertEqual(graph["edges"], [{"src": 0x1004, "dst": 0x1008, "kind": "fallthrough"}])
        self.assertEqual([block["start"] for block in graph["blocks"]], [0x1000, 0x1008])


if __name__ == "__main__":
    unittest.main()
