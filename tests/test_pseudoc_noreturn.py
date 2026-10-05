"""伪 C 消费核心 CFG 的不返回调用记录（cfg.noreturn_calls）。

修复前：核心分析已截断 abort()/exit()/longjmp() 之后的落空边，但伪 C 按“地址相邻即落空”
重建控制流——调用之后要么输出 unresolved_fallthrough(...) 并标为不完整，要么（下一条指令
经其它边可达时）把不返回调用错误地接到下一块，生成“abort(); return 7;”这种语义错误的代码。
"""
from __future__ import annotations

import importlib.util
import platform
import re
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.microcode import lift_function

CAPSTONE = importlib.util.find_spec("capstone") is not None


def _decode_arm64(words, base=0x1000):
    """手工编码的真实 arm64 机器码，经与完整分析相同的处理器解码成快照行。"""
    from fangida.processors import get_processor
    code = b"".join(struct.pack("<I", word) for word in words)
    rows, _ = get_processor("arm64", "little").decode_bytes(code, base, max_instructions=len(words))
    return {row["addr"]: row for row in rows}


# 0x1000 cbz  w0, 0x1010      ; w0 == 0 → 0x1010
# 0x1004 cmp  w0, #5
# 0x1008 b.ne 0x1018
# 0x100c bl   0x2000          ; abort：不返回（核心 CFG 截断了落空边）
# 0x1010 mov  w0, #7          ; 只能经 cbz 到达，地址上紧挨着 bl
# 0x1014 ret
# 0x1018 mov  w0, #9
# 0x101c ret
_WORDS = (0x34000080, 0x7100141F, 0x54000081, 0x940003FD, 0x528000E0, 0xD65F03C0, 0x52800120, 0xD65F03C0)


def _function(*, noreturn_calls=None, cfg_extra=None, **extra):
    rows = _decode_arm64(_WORDS)
    layout = ((0x1000, (0x1000,), (0x1010, 0x1004)), (0x1004, (0x1004, 0x1008), (0x1018, 0x100c)),
              (0x100c, (0x100c,), ()), (0x1010, (0x1010, 0x1014), ()), (0x1018, (0x1018, 0x101c), ()))
    blocks = [{"start": start, "instructions": [rows[address] for address in addresses], "successors": list(successors)}
              for start, addresses, successors in layout]
    cfg = {"entry": 0x1000, "complete": True, "frontier": [], **(cfg_extra or {})}
    if noreturn_calls is not None:
        cfg["noreturn_calls"] = noreturn_calls
    return {"name": "guard", "start": 0x1000, "blocks": blocks, "cfg": cfg,
            "pseudoc_symbols": {0x2000: "abort"}, **extra}


_ABORT = {"from": 0x100c, "fallthrough": 0x1010, "target": 0x2000, "name": "abort", "evidence": "import_stub"}


@unittest.skipUnless(CAPSTONE, "capstone is not available")
class NoreturnCallSiteTests(unittest.TestCase):
    def test_call_is_a_dead_end_even_when_the_next_instruction_is_reachable(self):
        output = generate_pseudoc(_function(noreturn_calls=[_ABORT]), "arm64", style="readable")
        text = output.pseudoc
        self.assertNotIn("unresolved_fallthrough", text)
        self.assertFalse(output.truncated)
        # 语义：abort 之后不会执行 mov w0,#7; ret —— “return 7” 只能出现在 w0 == 0 的分支里。
        self.assertNotRegex(text, r"abort\(\);\s*\n\s*return 7")
        self.assertEqual(text.count("return 7"), 1, text)
        self.assertRegex(text, r"== 0\) \{\s*\n\s*return 7;")
        # 结构：w0==0 → 7；w0!=5 → 9；否则 abort() 作为函数的最后一条语句。
        self.assertTrue(text.rstrip().endswith("abort();\n}"), text)
        calls = [op for row in output.microcode for op in row["operations"] if op["opcode"] == "call"]
        self.assertEqual([(op["attributes"].get("noreturn"), op["attributes"].get("noreturn_evidence")) for op in calls],
                         [(True, "import_stub")])
        self.assertFalse([item for item in output.reconstruction.get("unresolved", ())
                          if item.get("kind") == "control_flow_target"])

    def test_machine_view_states_the_end_instead_of_falling_through(self):
        output = generate_pseudoc(_function(noreturn_calls=[_ABORT]), "arm64", style="machine")
        self.assertIn('__builtin_unreachable(); /* call does not return: "abort", evidence "import_stub" */',
                      output.pseudoc)
        self.assertNotIn("unresolved_fallthrough", output.pseudoc)
        # 紧挨着的 0x1010 只能经 cbz 到达：带标签，不会从 bl 词法落空进去。
        self.assertIn("L_1010:", output.pseudoc)
        self.assertFalse(output.truncated)
        lifted = lift_function(_function(noreturn_calls=[_ABORT]), "arm64")
        self.assertFalse(lifted["truncated"])

    def test_without_records_the_output_is_unchanged(self):
        # 没有记录（旧快照/其它来源）与空记录：不加任何属性，结果与修复前一致（按相邻关系落空）。
        missing = generate_pseudoc(_function(), "arm64", style="readable")
        empty = generate_pseudoc(_function(noreturn_calls=[]), "arm64", style="readable")
        self.assertEqual(missing.pseudoc, empty.pseudoc)
        self.assertEqual(missing.microcode, empty.microcode)
        self.assertFalse([op for row in missing.microcode for op in row["operations"]
                          if op.get("attributes", {}).get("noreturn")])
        # 修复前的（错误）语义：abort() 所在分支结束后继续执行到 “return 7”。
        self.assertRegex(missing.pseudoc, r"abort\(\);\s*\n\s*\}\s*\n\s*return 7;")

    def test_calls_followed_by_a_trap_keep_their_edge(self):
        # fallthrough_trap：核心保留了到陷阱的边，伪 C 也照常落空（陷阱本身是终点）。
        record = {**_ABORT, "fallthrough_trap": True}
        output = generate_pseudoc(_function(noreturn_calls=[record]), "arm64", style="readable")
        self.assertFalse([op for row in output.microcode for op in row["operations"]
                          if op.get("attributes", {}).get("noreturn")])

    def test_malformed_records_are_ignored(self):
        records = [None, "x", {"from": "0x100c"}, {"fallthrough": 0x1010}, {"from": 0x9999}]
        output = generate_pseudoc(_function(noreturn_calls=records), "arm64", style="readable")
        self.assertEqual(output.pseudoc, generate_pseudoc(_function(), "arm64", style="readable").pseudoc)


@unittest.skipUnless(CAPSTONE, "capstone is not available")
class NoreturnSignatureTests(unittest.TestCase):
    def _abort_only(self, **extra):
        rows = _decode_arm64((0x940003FF,))  # 0x1000 bl 0x1ffc（abort）
        return {"name": "fatal", "start": 0x1000, "pseudoc_symbols": {0x1ffc: "abort"},
                "blocks": [{"start": 0x1000, "instructions": [rows[0x1000]], "successors": []}],
                "cfg": {"entry": 0x1000, "complete": True, "frontier": [], "noreturn_calls": [
                    {"from": 0x1000, "fallthrough": 0x1004, "target": 0x1ffc, "name": "abort", "evidence": "symbol_name"}]},
                **extra}

    def test_proven_noreturn_function_is_void_and_labelled(self):
        function = self._abort_only(noreturn=True, noreturn_evidence={"name": "fatal", "evidence": "local_fixed_point"})
        text = generate_pseudoc(function, "arm64", style="readable").pseudoc
        header, signature = text.splitlines()[:2]
        self.assertIn("不返回（所有路径终止于不返回调用）", header)
        self.assertIn("完整", header)
        self.assertTrue(signature.startswith("void fatal("), signature)

    def test_void_needs_the_core_proof(self):
        # 只是“看不到 return”（没有核心证明）时不改返回类型，也不加标注。
        text = generate_pseudoc(self._abort_only(), "arm64", style="readable").pseudoc
        self.assertNotIn("不返回", text.splitlines()[0])
        self.assertFalse(text.splitlines()[1].startswith("void "), text)

    def test_reachable_return_wins_over_a_stale_flag(self):
        # 快照与标志不一致（有可达 ret）时不写 void：需要两个条件同时成立。
        function = _function(noreturn_calls=[_ABORT], noreturn=True, noreturn_evidence={"evidence": "symbol_name"})
        text = generate_pseudoc(function, "arm64", style="readable").pseudoc
        self.assertIn("不返回（已知不返回函数名）", text.splitlines()[0])
        self.assertFalse(text.splitlines()[1].startswith("void "), text)


_PROGRAM = r"""
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
static jmp_buf env;
__attribute__((noinline)) void die(const char *m) { fprintf(stderr, "%s\n", m); abort(); }
__attribute__((noinline)) int check(int v) { if (v < 0) die("negative"); return v * 2; }
__attribute__((noinline)) void jumper(int v) { longjmp(env, v); }
__attribute__((noinline)) int pick(int v) {
    if (v == 7) exit(3);
    if (v > 100) { fprintf(stderr, "big\n"); abort(); }
    return v + 1;
}
int main(int argc, char **argv) {
    if (setjmp(env)) return 9;
    if (argc > 5) jumper(argc);
    printf("%d %d\n", check(argc), pick(argc));
    if (argc > 3) exit(argc);
    return 0;
}
"""


@unittest.skipUnless(CAPSTONE and shutil.which("clang") and platform.system() == "Darwin",
                     "clang/capstone/macOS is not available")
class CompiledNoreturnPseudocTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        root = Path(cls.directory.name)
        (root / "t.c").write_text(_PROGRAM)
        cls.binaries = {}
        for arch in ("arm64", "x86_64"):
            binary = root / f"t_{arch}"
            if subprocess.run(["clang", "-O2", "-arch", arch, "-o", str(binary), str(root / "t.c")],
                              capture_output=True).returncode == 0:
                cls.binaries[arch] = binary

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_program_semantics(self):
        binary = self.binaries.get(platform.machine())
        if binary is None:
            self.skipTest("native binary was not built")
        # argc=1：正常返回；argc=5：exit(5)；argc=7：jumper → longjmp → main 返回 9。
        for arguments, code in (((), 0), (("a",) * 4, 5), (("a",) * 6, 9)):
            self.assertEqual(subprocess.run([str(binary), *arguments], capture_output=True).returncode, code)

    def test_full_analysis_pseudoc_ends_at_noreturn_calls(self):
        from fangida.core.kkagent import PluginImpl
        from fangida.models import AnalysisTask
        if not self.binaries:
            self.skipTest("no binary was built")
        for arch, binary in sorted(self.binaries.items()):
            result = PluginImpl().analyze(AnalysisTask(str(binary), "macho", full_analysis=True, semantic_threads=1))
            named = {fn["name"]: fn for fn in result.functions if fn.get("pseudoc")}
            for name in ("_pick", "_jumper", "_main", "_die", "_check"):
                function = named.get(name)
                if function is None or not function["cfg"].get("complete"):
                    # 既有限制：x86 线性扫描在不返回调用后的零填充处失步时，_die 入口未解码，
                    # 其调用者 _check 也就无从知道 die 不返回（CFG 不完整）。只检查 CFG 完整的函数。
                    continue
                with self.subTest(arch=arch, function=name):
                    self.assertNotIn("unresolved_fallthrough", function["pseudoc"])
                    self.assertTrue(function["microcode_complete"])
                    self.assertFalse(function["pseudoc_truncated"])
            pick = named["_pick"]["pseudoc"]
            self.assertIn("完整", pick.splitlines()[0])
            # exit(3)/abort() 都是分支的终点，不会再落到 “return arg + 1”。
            self.assertNotRegex(pick, r"(exit\(3\)|abort\(\));\s*\n\s*return")
            jumper = named["_jumper"]["pseudoc"]
            self.assertIn("不返回", jumper.splitlines()[0])
            self.assertTrue(jumper.splitlines()[1].startswith("void jumper("), jumper)
            main = named["_main"]["pseudoc"]
            # jumper() 不返回：它所在的分支不能继续执行到 exit(argc)。
            self.assertNotRegex(main, r"jumper\([^;]*\);\s*\n\s*\}\s*\n\s*exit\(argc\)")
            self.assertEqual(len(re.findall(r"exit\(argc\)", main)), 1)


if __name__ == "__main__":
    unittest.main()
