"""代码详情只展示完成的记录；工作区仍以原表键导航。"""
from __future__ import annotations

import copy
import unittest

from fangida.gui_modules.records import display_text, extra_tables
from fangida.gui_modules.workspace import FunctionSidebar, VIEW_LABELS, view_label


class CodeDisplayTests(unittest.TestCase):
    def test_native_instruction_is_readable_without_source_bytes_or_record_changes(self):
        row = {"addr": 0x401000, "size": 6, "mnemonic": "jne", "operands": ["0x401080"],
               "reads": ["rflags"], "writes": [],
               "branch_info": {"kind": "jump", "target": 0x401080, "conditional": True},
               "arch_meta": {"memory_references": [0x405000, 0x405008]}}
        before = copy.deepcopy(row)
        text = display_text("Disassembly", row)
        self.assertTrue(text.startswith("0x401000  jne 0x401080\n"))
        self.assertIn("读取寄存器：rflags", text)
        self.assertIn("jump → 0x401080（条件分支）", text)
        self.assertIn("内存引用：0x405000, 0x405008", text)
        self.assertNotIn("字节：", text)
        self.assertEqual(row, before)

    def test_member_source_and_stored_bytes_are_displayed_without_resolving_indirect_branch(self):
        row = {"addr": 0x84, "size": 3, "mnemonic": "invokevirtual", "operands": "#7",
               "bytes": bytes.fromhex("b60007"), "reads": [], "writes": ["stack"],
               "branch_info": {"kind": "call", "target": None},
               "arch_meta": {"container_member": "pkg/Foo.class", "address_space": "file_offset"}}
        text = display_text("Disassembly", row)
        self.assertIn("0x84  invokevirtual #7", text)
        self.assertIn("来源：pkg/Foo.class", text)
        self.assertIn("地址空间：file_offset", text)
        self.assertIn("字节：b6 00 07", text)
        self.assertIn("call → 未解析", text)
        self.assertNotIn("→ 0x", text)

    def test_pseudocode_is_verbatim_and_non_code_records_keep_json_fallback(self):
        code = "int 示例(void) {\n    return 42;\n}\n"
        row = {"name": "示例", "start": 0x2000, "pseudoc": code}
        self.assertIs(display_text("Pseudocode", row), code)
        self.assertIsNone(display_text("Functions", row))
        self.assertIsNone(display_text("Pseudocode", {"name": "未反编译"}))
        self.assertEqual(display_text("Disassembly", {"addr": 0, "mnemonic": "ret",
            "branch_info": {"kind": "return"}}), "0x0  ret\n\n分支：return\n")

    def test_extra_views_borrow_existing_results_and_keep_internal_names(self):
        functions = [{"name": "f", "pseudoc": "return;", "blocks": [{"start": 0x1000}]}]
        calls = [{"addr": 0x1000, "target": "api"}]
        snapshot = {"functions": functions, "metadata": {"api_calls": calls}}
        before = copy.deepcopy(snapshot)
        rows = extra_tables(snapshot)
        self.assertIs(rows["API Calls"], calls)
        self.assertIs(rows["Pseudocode"][0]["pseudoc"], functions[0]["pseudoc"])
        self.assertNotIn("blocks", rows["Pseudocode"][0])
        self.assertEqual(snapshot, before)
        self.assertEqual(view_label("Disassembly"), "汇编")
        self.assertEqual(view_label("custom_view"), "custom_view")
        self.assertTrue(all(len(label) <= 5 for label in VIEW_LABELS.values()))


class SidebarDisplayTests(unittest.TestCase):
    def test_last_page_and_filtered_member_keep_original_indices_and_full_count(self):
        try:
            import tkinter as tk
            from tkinter import ttk
            root = tk.Tk()
        except Exception as exc:
            self.skipTest(f"当前环境无法创建 Tk 窗口：{exc}")
        root.withdraw()
        self.addCleanup(root.destroy)
        opened, selected = [], []
        sidebar = FunctionSidebar(root, tk, ttk, opened.append, selected.append)
        sidebar.frame.pack(fill="both", expand=True)
        rows = [{"name": f"func_{index}", "start": 0x1000 + index * 16} for index in range(690)]
        sidebar.set_rows(rows)
        self.assertTrue(sidebar.select_index(689))
        self.assertEqual(sidebar.count.get(), "690 个 · 3/3 页")
        self.assertEqual(len(sidebar.tree.get_children()), 190)
        self.assertEqual(selected, [])
        sidebar.open_selected()
        self.assertEqual(opened, [689])
        sidebar.query.set("func_689")
        sidebar._apply_filter()
        self.assertEqual(sidebar.tree.get_children(), ("689",))
        self.assertEqual(sidebar.count.get(), "1 个 · 1/1 页")
        self.assertIs(sidebar._rows, rows)
        # 数量单占一行，在最小侧栏宽度也不会被两个翻页按钮挤掉。
        self.assertGreater(int(sidebar.count_label.grid_info()["row"]),
                           int(sidebar.previous.grid_info()["row"]))
        self.assertEqual(int(sidebar.count_label.grid_info()["columnspan"]), 2)


if __name__ == "__main__":
    unittest.main()
