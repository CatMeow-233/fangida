"""源码重建的可读性、编译语义、快照边界和兼容性回归。"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tests.test_pseudoc import instruction as ins, function as fn
from fangida.models import AnalysisResult
from fangida.plugins.pseudoc import generate_pseudoc
from fangida.plugins.pseudoc.pipeline import populate_native_pseudoc
from fangida.plugins.pseudoc.reconstruct import reconstruct_function, recover_signature
from fangida.mcp_server import McpServer
from fangida.settings import Settings


def readable(*rows, name="example", **fields):
    return generate_pseudoc(fn(*rows, name=name, pseudoc_context={"kind": "elf"}, **fields),
                            "x86_64", style="readable")


def compile_run(text, main, prefix=""):
    if not shutil.which("cc"):
        raise unittest.SkipTest("需要 C 编译器")
    with tempfile.TemporaryDirectory() as tmp:
        source, binary = Path(tmp) / "check.c", Path(tmp) / "check"
        source.write_text("#include <stdint.h>\n#include <stdbool.h>\n#include <limits.h>\n" + prefix + text + "\nint main(void) {\n" + main + "\n}\n")
        compiled = subprocess.run([shutil.which("cc"), "-O2", "-Wall", "-Werror", str(source), "-o", str(binary)], capture_output=True, text=True)
        if compiled.returncode:
            raise AssertionError(compiled.stderr + "\n" + source.read_text())
        subprocess.run([str(binary)], check=True, capture_output=True)


class ReconstructionTests(unittest.TestCase):
    def test_arithmetic_renames_and_removes_register_copies(self):
        output = readable(ins(0, "mov", "eax", "edi"), ins(1, "add", "eax", "esi"), ins(2, "ret", kind="return"), name="add_values")
        self.assertIn("uint32_t add_values(uint32_t arg_1, uint32_t arg_2)", output.pseudoc)
        self.assertIn("return arg_1 + arg_2;", output.pseudoc)
        self.assertNotRegex(output.pseudoc, r"\b(?:rax|rdi|rsi|rsp|rbp|goto)\b")
        self.assertIn("rax", output.machine_pseudoc)
        compile_run(output.pseudoc, "return add_values(UINT32_MAX, 2) == 1 ? 0 : 1;")

    def test_signed_and_unsigned_comparisons_execute_boundary_values(self):
        for branch, ctype, test in (("jge", "int32_t", "minimum(INT32_MIN, 0) == INT32_MIN && minimum(-1, INT32_MAX) == -1"),
                                    ("jae", "uint32_t", "minimum(UINT32_MAX, 0) == 0 && minimum(4, 7) == 4")):
            with self.subTest(branch=branch):
                output = readable(ins(0, "cmp", "edi", "esi"), ins(1, branch, "0x5", kind="jump", target=5, conditional=True),
                    ins(2, "mov", "eax", "edi"), ins(3, "ret", kind="return"),
                    ins(5, "mov", "eax", "esi"), ins(6, "ret", kind="return"), name="minimum")
                self.assertIn(f"{ctype} minimum({ctype} arg_1, {ctype} arg_2)", output.pseudoc)
                self.assertIn("if (arg_1 >= arg_2)", output.pseudoc)
                self.assertNotIn("goto", output.pseudoc)
                compile_run(output.pseudoc, f"return ({test}) ? 0 : 1;")

    def test_diamond_merges_preserve_live_assignments(self):
        output = readable(ins(0, "test", "edi", "edi"), ins(1, "je", "0x5", kind="jump", target=5, conditional=True),
            ins(2, "mov", "eax", "3"), ins(3, "jmp", "0x6", kind="jump", target=6),
            ins(5, "mov", "eax", "4"), ins(6, "add", "eax", "2"), ins(7, "ret", kind="return"), name="diamond")
        self.assertIn("if (arg_1 == 0)", output.pseudoc)
        self.assertEqual(output.reconstruction["residual_gotos"], 0)
        compile_run(output.pseudoc, "return diamond(0) == 6 && diamond(1) == 5 ? 0 : 1;")

    def test_natural_loop_reconstructs_while(self):
        output = readable(ins(0, "xor", "eax", "eax"), ins(1, "xor", "ecx", "ecx"),
            ins(2, "cmp", "ecx", "edi"), ins(3, "jge", "0x8", kind="jump", target=8, conditional=True),
            ins(4, "add", "eax", "ecx"), ins(5, "inc", "ecx"), ins(6, "jmp", "0x2", kind="jump", target=2),
            ins(8, "ret", kind="return"), name="sum_to")
        self.assertIn("while (", output.pseudoc)
        self.assertEqual(output.reconstruction["structured_loops"], 1)
        self.assertNotIn("goto", output.pseudoc)
        compile_run(output.pseudoc, "for (int n=-3;n<100;n++) { uint32_t expected=0; for(int k=0;k<n;k++) expected+=k; if(sum_to(n)!=expected) return 1; } return 0;")

    def test_pointer_types_and_array_index_recovery(self):
        output = readable(ins(0, "mov", "eax", "dword ptr [rdi+rsi*4]"), ins(1, "ret", kind="return"), name="array_at")
        self.assertIn("uint32_t * arg_1", output.pseudoc)
        self.assertIn("arg_1[arg_2]", output.pseudoc)
        compile_run(output.pseudoc, "uint32_t a[]={3,9,12}; return array_at(a,2)==12 ? 0:1;")

    def test_stack_locals_replace_frame_scaffolding(self):
        output = readable(ins(0,"push","rbp"),ins(1,"mov","rbp","rsp"),ins(2,"sub","rsp","16"),
            ins(3,"mov","dword ptr [rbp-4]","edi"),ins(4,"mov","eax","dword ptr [rbp-4]"),
            ins(5,"add","eax","1"),ins(6,"leave"),ins(7,"ret",kind="return"), name="frame")
        self.assertIn("return arg_1 + 1;", output.pseudoc)
        self.assertNotRegex(output.pseudoc, r"\b(?:rsp|rbp|push|pop)\b")
        self.assertEqual(output.reconstruction["stack_frame"][0]["size"], 4)
        compile_run(output.pseudoc, "return frame(UINT32_MAX)==0 ? 0:1;")

    def test_overlapping_stack_accesses_share_one_storage(self):
        output = readable(ins(0,"push","rbp"),ins(1,"mov","rbp","rsp"),ins(2,"sub","rsp","16"),
            ins(3,"mov","dword ptr [rbp-4]","edi"),ins(4,"mov","byte ptr [rbp-3]","0x12"),
            ins(5,"mov","eax","dword ptr [rbp-4]"),ins(6,"leave"),ins(7,"ret",kind="return"),name="overlap")
        self.assertIn("uint8_t local_1[4];",output.pseudoc)
        self.assertEqual(len(output.reconstruction["stack_frame"]), 1)
        self.assertIn("&local_1[1]",output.pseudoc)
        compile_run(output.pseudoc, "return overlap(0x12345678)==0x12341278 ? 0:1;")

    def test_stack_address_escape_forms_buffer_and_restores_call_arguments(self):
        context = {"kind":"elf", "callees":{32:{"name":"fill","signature_complete":True,"parameters":[
            {"register":"rdi","type":"uint8_t *"},{"register":"rsi","type":"uint32_t"}],"return_type":"uint32_t", "return_zero_extended":True}}}
        snapshot = fn(ins(0,"push","rbp"),ins(1,"mov","rbp","rsp"),ins(2,"sub","rsp","16"),
            ins(3,"lea","rdi","[rbp-16]"),ins(4,"mov","esi","16"),ins(5,"call","0x20",kind="call",target=32),
            ins(6,"leave"),ins(7,"ret",kind="return"),name="buffer",pseudoc_context=context)
        output = generate_pseudoc(snapshot,"x86_64",style="readable")
        self.assertIn("uint8_t local_1[16];",output.pseudoc)
        self.assertIn("fill(local_1, 16)",output.pseudoc)
        self.assertTrue(output.reconstruction["calls"][0]["argument_count_known"])
        compile_run(output.pseudoc,"return buffer()==16 ? 0:1;", "uint32_t fill(uint8_t *p,uint32_t n) { p[n-1]=1; return n; }\n")

    def test_compare_captures_survive_intervening_write(self):
        output = readable(ins(0,"cmp","edi","0"),ins(1,"mov","edi","9"),
            ins(2,"je","0x6",kind="jump",target=6,conditional=True),ins(3,"mov","eax","edi"),ins(4,"ret",kind="return"),
            ins(6,"mov","eax","2"),ins(7,"ret",kind="return"),name="capture")
        compile_run(output.pseudoc,"return capture(0)==2 && capture(5)==9 ? 0:1;")

    def test_conditional_move_memory_load_is_unconditional(self):
        output = readable(ins(0,"cmp","edi","0"),ins(1,"mov","eax","7"),ins(2,"cmovne","eax","dword ptr [rsi]"),ins(3,"ret",kind="return"),name="choose")
        load, select = output.pseudoc.index("= arg_2[0];"), output.pseudoc.index(" ? ")
        self.assertLess(load,select)
        self.assertEqual(output.pseudoc.count("arg_2[0]"),1)
        compile_run(output.pseudoc,"uint32_t p=42; return choose(0,&p)==7 && choose(1,&p)==42 ? 0:1;")

    def test_unknown_abi_does_not_invent_register_parameters(self):
        snapshot = fn(ins(0,"mov","eax","edi"),ins(1,"ret",kind="return"))
        output = generate_pseudoc(snapshot,"x86_64",style="readable")
        self.assertEqual(output.reconstruction["abi"],"unknown")
        self.assertEqual(output.reconstruction["parameters"],[])
        self.assertIn("unknown_value()",output.pseudoc)
        self.assertFalse(output.reconstruction["complete"])

    def test_missing_branch_target_is_explicit(self):
        output = readable(ins(0,"test","edi","edi"),ins(1,"je","0x99",kind="jump",target=153,conditional=True),
            ins(2,"mov","eax","1"),ins(3,"ret",kind="return"))
        self.assertIn("tail_transfer(0x99,", output.pseudoc)
        self.assertNotIn("return unresolved_result();", output.pseudoc)
        self.assertFalse(output.reconstruction["complete"])

    def test_declared_void_return_and_parameter_name(self):
        output = readable(ins(0,"mov","dword ptr [rdi]","4"),ins(1,"ret",kind="return"),name="set_value",
            prototype={"return_type":"void","parameters":[{"name":"output","register":"rdi","type":"uint32_t *"}]})
        self.assertIn("void set_value(uint32_t * output)",output.pseudoc)
        self.assertIn("return;",output.pseudoc)
        compile_run(output.pseudoc,"uint32_t v=0;set_value(&v);return v==4 ? 0:1;")

    def test_callee_narrow_negative_return_keeps_zero_extension(self):
        callee=fn(ins(32,"cmp","edi","0"),ins(33,"jge","0x25",kind="jump",target=37,conditional=True),
            ins(34,"mov","eax","edi"),ins(35,"ret",kind="return"),ins(37,"mov","eax","0"),ins(38,"ret",kind="return"),name="negative")
        summary=recover_signature(callee,"x86_64",context={"kind":"elf"})
        self.assertTrue(summary["return_zero_extended"])
        caller=fn(ins(0,"mov","edi","-1"),ins(1,"call","0x20",kind="call",target=32),ins(2,"ret",kind="return"),name="caller",
            pseudoc_context={"kind":"elf","callees":{32:summary}})
        output=generate_pseudoc(caller,"x86_64",style="readable")
        compile_run(output.pseudoc,"return caller()==UINT32_MAX ? 0:1;","int32_t negative(int32_t value) { return value < 0 ? value : 0; }\n")

    def test_unknown_call_has_unresolved_tail(self):
        output=readable(ins(0,"mov","edi","4"),ins(1,"call","0x20",kind="call",target=32),ins(2,"ret",kind="return"))
        self.assertIn("unknown_function(4, unknown_arguments())",output.pseudoc)
        self.assertFalse(output.reconstruction["calls"][0]["argument_count_known"])
        self.assertFalse(output.reconstruction["complete"])

    def test_external_narrow_return_does_not_invent_high_bits(self):
        snapshot=fn(ins(0,"call","0x20",kind="call",target=32),ins(1,"ret",kind="return"),pseudoc_context={
            "kind":"elf","callees":{32:{"name":"external","return_type":"int32_t","signature_complete":True,"parameters":[]}}})
        output=generate_pseudoc(snapshot,"x86_64",style="readable")
        self.assertIn("unknown_return_upper32",output.pseudoc)
        self.assertFalse(output.reconstruction["complete"])

    def test_narrow_multiply_avoids_c_signed_promotion_overflow(self):
        from fangida.plugins.pseudoc.reconstruct.expressions import format_value
        from fangida.plugins.pseudoc.reconstruct.model import Value
        left=Value("variable",16,name="left",ctype="uint16_t")
        right=Value("variable",16,name="right",ctype="uint16_t")
        text=format_value(Value("mul",16,(left,right),ctype="uint16_t"))
        compile_run(f"uint16_t multiply(uint16_t left,uint16_t right) {{ return (uint16_t){text}; }}",
                    "return multiply(UINT16_MAX,UINT16_MAX)==1 ? 0:1;")

    def test_declared_unused_parameter_remains_in_signature(self):
        output=readable(ins(0,"mov","eax","1"),ins(1,"ret",kind="return"),
            prototype={"return_type":"uint32_t","parameters":[{"register":"rdi","name":"unused","type":"uint32_t"}]})
        self.assertIn("uint32_t unused",output.pseudoc)
        self.assertTrue(output.reconstruction["signature_complete"])

    def test_arm_integer_arguments_and_aliases(self):
        for architecture,destination,args,ret in (("arm64","w0",("w0","w1"),"ret"),("arm","r0",("r0","r1"),"bx")):
            with self.subTest(architecture=architecture):
                snapshot=fn(ins(0,"add",destination,*args),ins(1,ret,*([] if ret=="ret" else ["lr"]),kind="return"),
                    name="add_values",pseudoc_context={"kind":"elf"})
                output=generate_pseudoc(snapshot,architecture,style="readable")
                self.assertNotRegex(output.pseudoc,r"\b(?:w0|w1|x0|x1|r0|r1)\b")
                compile_run(output.pseudoc,"return add_values(UINT32_MAX,2)==1 ? 0:1;")

    def test_x86_stack_parameter_recovery(self):
        output=generate_pseudoc(fn(ins(0,"mov","eax","dword ptr [esp+4]"),ins(1,"ret",kind="return"),
            name="stack_value",pseudoc_context={"kind":"elf"}),"x86",style="readable")
        self.assertIn("uint32_t stack_arg_1",output.pseudoc)
        self.assertNotIn("esp",output.pseudoc)
        compile_run(output.pseudoc,"return stack_value(42)==42 ? 0:1;")

    def test_irreducible_flow_keeps_residual_labels(self):
        output=readable(ins(0,"test","edi","edi"),ins(1,"je","0x5",kind="jump",target=5,conditional=True),
            ins(2,"mov","eax","1"),ins(3,"jmp","0x6",kind="jump",target=6),ins(5,"mov","eax","2"),
            ins(6,"test","esi","esi"),ins(7,"jne","0x2",kind="jump",target=2,conditional=True),ins(8,"ret",kind="return"))
        self.assertGreater(output.reconstruction["residual_gotos"],0)
        labels=set(re.findall(r"(block_\d+):",output.pseudoc))
        self.assertTrue(set(re.findall(r"goto (block_\d+)",output.pseudoc)) <= labels)
        compile_run(output.pseudoc,"return example(0,0)==2 && example(1,0)==1 ? 0:1;")

    def test_fp_and_opaque_operations_do_not_claim_source_recovery(self):
        # 比较类浮点（ucomiss：FP 标志未重建为源比较）与未识别指令仍是 unresolved_operation；
        # 标量浮点算术（addss）渲染为依赖 FPCR 的占位辅助（fadd_32），不是 unresolved_operation，
        # 但同样不自称完整恢复（记为 fp_environment 未解析项）。
        for row in (ins(0,"ucomiss","xmm0","xmm1"),ins(0,"unknown_magic","eax")):
            with self.subTest(mnemonic=row["mnemonic"]):
                output=readable(row,ins(1,"ret",kind="return"))
                self.assertIn("unresolved_operation",output.pseudoc)
                self.assertFalse(output.reconstruction["complete"])
        fp=readable(ins(0,"addss","xmm0","xmm1"),ins(1,"ret",kind="return"))
        self.assertNotIn("unresolved_operation",fp.pseudoc)
        self.assertIn("fadd_32(",fp.pseudoc)
        self.assertFalse(fp.reconstruction["complete"])
        self.assertTrue(any(item.get("kind")=="fp_environment_operation" for item in fp.reconstruction["unresolved"]))

    def test_non_stack_frame_pointer_store_is_preserved(self):
        output=readable(ins(0,"mov","qword ptr [rdi]","rbp"),ins(1,"mov","eax","0"),ins(2,"ret",kind="return"))
        self.assertIn("arg_1[0] =",output.pseudoc)
        self.assertFalse(output.reconstruction["complete"])

    def test_saved_frame_pointer_read_remains_visible_data(self):
        output=readable(ins(0,"push","rbp"),ins(1,"mov","rax","qword ptr [rsp]"),ins(2,"pop","rbp"),ins(3,"ret",kind="return"))
        self.assertRegex(output.pseudoc,r"local_\d+ = value_\d+;")
        self.assertFalse(output.reconstruction["complete"])
        compile_run(output.pseudoc,"return example()==42 ? 0:1;","uint64_t unknown_value(void) { return 42; }\n")

    def test_read_before_stack_initialization_is_explicit(self):
        output=readable(ins(0,"mov","eax","dword ptr [rsp-4]"),ins(1,"ret",kind="return"))
        self.assertIn("local_1 = unknown_value();",output.pseudoc)
        self.assertFalse(output.reconstruction["complete"])
        compile_run(output.pseudoc,"return example()==42 ? 0:1;","uint32_t unknown_value(void) { return 42; }\n")

    def test_snapshot_is_not_mutated_and_recovery_never_decodes(self):
        snapshot=fn(ins(0,"mov","eax","edi"),ins(1,"ret",kind="return"),pseudoc_context={"kind":"elf"})
        machine=generate_pseudoc(snapshot,"x86_64")
        before=copy.deepcopy(snapshot)
        with patch("fangida.plugins.pseudoc.microcode.lift_function",side_effect=AssertionError("不应重新提升或解码")):
            output=reconstruct_function(snapshot,"x86_64",microcode=machine.microcode)
        self.assertIn("return arg_1;",output.pseudoc)
        self.assertEqual(snapshot,before)

    def test_source_failure_retains_machine_and_semantic_evidence(self):
        with patch("fangida.plugins.pseudoc.reconstruct.reconstruct_function",side_effect=RuntimeError("fixture")):
            output=readable(ins(0,"ret",kind="return"))
        self.assertTrue(output.microcode)
        self.assertIn("rax",output.pseudoc)
        self.assertEqual(output.reconstruction["style"],"machine")
        self.assertTrue(output.warnings)

    def test_output_budget_is_bounded(self):
        rows=[ins(i,"mov","dword ptr [rdi]",str(i)) for i in range(100)]+[ins(100,"ret",kind="return")]
        output=generate_pseudoc(fn(*rows,pseudoc_context={"kind":"elf"}),"x86_64",style="readable",max_chars=256)
        self.assertLessEqual(len(output.pseudoc),256)
        self.assertTrue(output.truncated)

    def test_source_work_budget_retains_larger_machine_snapshot(self):
        rows=[ins(i,"mov","eax",str(i)) for i in range(600)]+[ins(600,"ret",kind="return")]
        output=generate_pseudoc(fn(*rows,pseudoc_context={"kind":"elf"}),"x86_64",style="readable",max_instructions=8192,max_chars=131072)
        self.assertEqual(len(output.microcode),601)
        self.assertTrue(output.truncated)
        self.assertFalse(output.reconstruction["complete"])

    def test_both_views_and_recovery_report_survive_sqlite_without_source(self):
        from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase
        result=AnalysisResult("sample","elf","kkagent","complete",metadata={"architecture":"x86_64"},functions=[
            fn(ins(0,"mov","eax","edi"),ins(1,"ret",kind="return"))])
        populate_native_pseudoc(result)
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/"source.bin"
            source.write_bytes(b"\x89\xf8\xc3")
            result.path=str(source)
            database_path=Path(tmp)/"saved.fdb"
            with SQLiteAnalysisDatabase(database_path,create=True) as database:
                identifier=database.save_analysis(source,result)
            source.unlink()
            with SQLiteAnalysisDatabase(database_path,read_only=True) as database:
                restored=database.get_snapshot(identifier)["functions"][0]
                for key in ("pseudoc","machine_pseudoc","pseudoc_style","pseudoc_reconstruction"):
                    self.assertEqual(restored[key],result.functions[0][key])

    def test_pipeline_and_mcp_store_both_views_with_consistent_names(self):
        caller=fn(ins(0,"mov","edi","4"),ins(1,"call","0x20",kind="call",target=32),ins(2,"ret",kind="return"),name="sub_0")
        callee=fn(ins(32,"mov","eax","edi"),ins(33,"ret",kind="return"),name="sub_20")
        result=AnalysisResult("sample","elf","kkagent","complete",metadata={"architecture":"x86_64"},functions=[caller,callee])
        populate_native_pseudoc(result)
        self.assertIn("function_2(",caller["pseudoc"])
        self.assertIn("function_2(",callee["pseudoc"])
        self.assertEqual(caller["pseudoc_style"],"readable")
        snapshot=json.loads(json.dumps(result.to_dict()))
        server=McpServer(settings=Settings())
        try:
            server._snapshots["fixture"]=snapshot
            for style,key in (("readable","pseudoc"),("machine","machine_pseudoc")):
                response=server.call_tool("get_pseudoc",{"handle":"fixture","address":0,"style":style})["structuredContent"]
                self.assertEqual(response["pseudoc"],caller[key])
        finally:
            server.close()

    def test_mcp_reconstructs_legacy_saved_microcode(self):
        snapshot=fn(ins(0,"mov","eax","edi"),ins(1,"ret",kind="return"))
        output=generate_pseudoc(snapshot,"x86_64")
        snapshot.update(pseudoc=output.pseudoc,microcode=list(output.microcode),pseudoc_producer=output.producer)
        server=McpServer(settings=Settings())
        try:
            server._snapshots["fixture"]={"kind":"elf","metadata":{"architecture":"x86_64"},"functions":[snapshot]}
            with patch("fangida.plugins.pseudoc.microcode.lift_function",side_effect=AssertionError("只能用已有微码")):
                response=server.call_tool("get_pseudoc",{"handle":"fixture","address":0,"style":"readable"})["structuredContent"]
            self.assertIn("return arg_1;",response["pseudoc"])
            self.assertEqual(snapshot["pseudoc"],output.pseudoc)
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
