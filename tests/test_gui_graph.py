"""图形视图保留真实 CFG、按视口绘制，并与分析层保持独立。"""
import copy
import random
import time
from types import SimpleNamespace
import unittest

from fangida.gui_modules.graph import (
    GraphView, MAX_RENDER_BLOCKS, MAX_RENDER_EDGES, MAX_SCALE, MIN_SCALE,
    build_layout,
)


def _block(address, mnemonic="ret", *, conditional=False):
    return {"start": address, "instructions": [
        {"addr": address, "size": 2, "mnemonic": mnemonic, "operands": ["eax", "1"],
         "branch_info": {"kind": "jump", "conditional": conditional}}],
        "successors": []}


def _sample():
    return {"entry": 0x1000, "complete": False,
            "blocks": [_block(0x1000, "jne", conditional=True),
                       _block(0x1010), _block(0x1020)],
            "edges": [{"src": 0x1000, "dst": 0x1010, "kind": "branch"},
                      {"src": 0x1000, "dst": 0x1020, "kind": "fallthrough"},
                      {"src": 0x1020, "dst": 0x1000, "kind": "branch"}],
            "frontier": [{"from": 0x1010, "to": 0x9000, "reason": "outside_window"}]}


class GraphLayoutTests(unittest.TestCase):
    def test_layout_borrows_ir_without_mutating_input(self):
        graph = _sample()
        before = copy.deepcopy(graph)
        layout = build_layout(graph)
        self.assertEqual(graph, before)
        self.assertEqual(set(layout.blocks), {0x1000, 0x1010, 0x1020})
        self.assertIs(layout.blocks[0x1000].block, graph["blocks"][0])
        self.assertIs(layout.blocks[0x1000].block["instructions"][0],
                      graph["blocks"][0]["instructions"][0])
        self.assertIs(layout.complete, False)

    def test_conditional_edges_and_back_edge_have_distinct_semantics(self):
        layout = build_layout(_sample())
        taken, fallthrough, backward, frontier = layout.paths
        self.assertNotEqual(taken.color, fallthrough.color)
        self.assertTrue(taken.conditional)
        self.assertTrue(fallthrough.conditional)
        self.assertFalse(backward.conditional)
        self.assertFalse(backward.unresolved)
        self.assertEqual(len(backward.points), 12)
        self.assertGreater(max(backward.points[::2]), layout.blocks[0x1020].bounds[2])
        self.assertTrue(frontier.unresolved)
        self.assertEqual(frontier.reason, "outside_window")

    def test_frontier_never_becomes_a_confirmed_edge_when_target_exists(self):
        graph = _sample()
        graph["frontier"][0]["to"] = 0x1000
        layout = build_layout(graph)
        path = layout.paths[-1]
        self.assertTrue(path.unresolved)
        self.assertEqual(path.target, 0x1000)
        self.assertEqual(len(path.points), 8)  # Stub, not a path to the existing block.

    def test_missing_or_mid_instruction_targets_and_invalid_sources_are_unresolved(self):
        graph = {"blocks": [_block(0x1000)],
                 "edges": [{"src": 0x1000, "dst": 0x1001},
                           {"src": 0x4000, "dst": 0x1000},
                           {"src": [], "dst": {}}, None],
                 "frontier": [None, {"from": 0x1000, "to": [], "reason": "indirect_jump"}]}
        layout = build_layout(graph)
        self.assertEqual(len(layout.unresolved), 6)
        self.assertEqual(layout.unresolved_count, 6)
        self.assertEqual(layout.orphaned_count, 4)
        self.assertEqual(layout.paths[0].reason, "target_not_a_block")
        self.assertEqual(layout.paths[1].reason, "source_not_in_graph")
        self.assertEqual(layout.paths[1].points, ())

    def test_large_graph_keeps_every_block_and_last_block_is_queryable(self):
        graph = {"blocks": [_block(index * 16) for index in range(5001)], "edges": []}
        layout = build_layout(graph)
        self.assertEqual(len(layout.blocks), 5001)
        last = layout.blocks[5000 * 16]
        self.assertIs(layout.block_for_address(last.start), last)
        visible = layout.visible_blocks(last.bounds)
        self.assertIn(last, visible)
        self.assertLess(len(visible), 10)
        entire = (0, 0, layout.width, layout.height)
        self.assertEqual(len(layout.visible_blocks(entire)), MAX_RENDER_BLOCKS)
        self.assertEqual(len(layout.visible_blocks(entire, 6000)), 5001)

    def test_interval_query_keeps_long_back_edges_and_enforces_render_budget(self):
        graph = {"blocks": [_block(index * 16) for index in range(200)],
                 "edges": [{"src": index * 16, "dst": 0, "kind": "branch"}
                           for index in range(1, 200)]}
        layout = build_layout(graph)
        region = (0, 0, layout.width, layout.height)
        self.assertEqual(len(layout.visible_paths(region, 7)), 7)
        self.assertEqual(len(layout.visible_paths(region, 300)), 199)
        loop = layout.paths[-1]
        middle = (loop.bounds[1] + loop.bounds[3]) / 2
        path_viewport = (loop.bounds[0], middle - 1, loop.bounds[2], middle + 1)
        self.assertIn(loop, layout.visible_paths(path_viewport, 300))

    def test_spatial_queries_match_brute_force_for_disjoint_and_overlapping_paths(self):
        generator = random.Random(91025)
        graph = {"blocks": [_block(index * 16) for index in range(75)],
                 "edges": [{"src": generator.randrange(75) * 16,
                            "dst": generator.randrange(75) * 16, "kind": "branch"}
                           for _ in range(240)]}
        layout = build_layout(graph)
        for _ in range(30):
            x = generator.uniform(0, layout.width)
            y = generator.uniform(0, layout.height)
            viewport = (x, y, x + 300, y + 800)
            expected = [path for path in layout.paths
                        if path.bounds[0] <= viewport[2] and path.bounds[2] >= viewport[0]
                        and path.bounds[1] <= viewport[3] and path.bounds[3] >= viewport[1]]
            actual = layout.visible_paths(viewport, 1000)
            self.assertEqual(set(actual), set(expected))
            self.assertEqual(len(actual), len(expected))

    def test_source_index_is_read_once_per_edge(self):
        class SourceCounter(dict):
            source_reads = 0

            def get(self, key, default=None):
                if key == "src":
                    type(self).source_reads += 1
                return super().get(key, default)

        graph = {"blocks": [_block(index * 16) for index in range(1000)],
                 "edges": [SourceCounter(src=index * 16, dst=(index + 1) * 16)
                           for index in range(999)]}
        layout = build_layout(graph)
        self.assertEqual(SourceCounter.source_reads, 999)
        self.assertEqual(len(layout.blocks), 1000)
        self.assertEqual(layout.unresolved_count, 0)

    def test_layout_is_deterministic_and_disconnected_components_remain_available(self):
        graph = _sample()
        graph["blocks"].append(_block(0x7000))
        first = build_layout(graph)
        graph["blocks"].reverse()
        second = build_layout(graph)
        self.assertEqual([(start, block.bounds) for start, block in first.blocks.items()],
                         [(start, block.bounds) for start, block in second.blocks.items()])
        self.assertEqual(first.paths, second.paths)
        self.assertGreater(first.blocks[0x7000].y, first.blocks[0x1020].y)

    def test_instruction_preview_is_bounded_and_interior_instruction_selects_block(self):
        instructions = [{"addr": 0x2000 + index, "mnemonic": "nop", "operands": []}
                        for index in range(10_000)]
        graph = {"blocks": [{"start": 0x2000, "instructions": instructions}]}
        layout = build_layout(graph)
        block = layout.blocks[0x2000]
        self.assertLessEqual(len(block.lines), 7)
        self.assertIn("10000", block.lines[-1][1])
        self.assertIs(block.block["instructions"], instructions)
        self.assertIs(layout.block_for_address(0x2000 + 9999), block)

    def test_empty_and_malformed_input_has_no_invented_blocks(self):
        for graph in (None, {}, {"blocks": [None, {}, {"start": True}, {"start": -1}]}):
            layout = build_layout(graph)
            self.assertEqual(layout.blocks, {})
            self.assertEqual(layout.visible_blocks((0, 0, 1000, 1000)), [])
            self.assertIsNone(layout.block_for_address(True))
        graph = {"blocks": [_block(12), _block(12)]}
        self.assertEqual(build_layout(graph).invalid_blocks, 1)


class GraphTkSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import tkinter as tk
            from tkinter import ttk
            cls.root = tk.Tk()
            cls.root.withdraw()
            cls.tk, cls.ttk = tk, ttk
        except (ImportError, RuntimeError) as exc:
            raise unittest.SkipTest(f"当前运行环境没有 Tk：{exc}") from exc
        except Exception as exc:
            # TclError is only available after the import; a headless Linux host
            # or a Python build without Tk can still run all pure layout checks.
            if type(exc).__name__ == "TclError":
                raise unittest.SkipTest(f"当前运行环境不能创建 Tk 窗口：{exc}") from exc
            raise

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self.navigated = []
        self.selected = []
        self.callback_errors = []
        self.root.report_callback_exception = lambda kind, value, tb: self.callback_errors.append(value)
        self.view = GraphView(self.root, self.tk, self.ttk, self.navigated.append,
                              on_select=self.selected.append)
        self.view.frame.pack(fill="both", expand=True)

    def tearDown(self):
        self.view.frame.destroy()
        self.root.update_idletasks()

    def _pump(self, predicate=None, *, reason="Tk 图形事件未在限定时间内完成"):
        import _tkinter
        deadline = time.monotonic() + 1.5
        remaining = 1000
        while True:
            handled = self.root.tk.dooneevent(_tkinter.DONT_WAIT)
            if self.callback_errors:
                self.fail(f"Tk 图形回调出现错误：{self.callback_errors!r}")
            if predicate is not None and predicate():
                return
            if predicate is None and not handled:
                return
            remaining -= 1
            if time.monotonic() >= deadline or not remaining:
                self.fail(reason)
            time.sleep(0.002)

    def test_actual_canvas_draws_and_clears_graph(self):
        self.view.set_cfg(_sample(), 0x1000)
        self.root.update_idletasks()
        self.assertEqual(self.view.selected_address, 0x1000)
        self.assertTrue(self.view.canvas.find_all())
        self.assertIn("3 个基本块", self.view.status.get())
        self.view.set_cfg(None)
        self.root.update_idletasks()
        self.assertIsNone(self.view.selected_address)
        self.assertEqual(self.view._items, {})
        self.assertIn("0 个基本块", self.view.status.get())

    def test_hidden_tab_opens_at_readable_scale_with_selected_block_visible(self):
        # The production graph is populated while its notebook tab is hidden.
        # A twelve-block chain must remain readable after the first real Map,
        # including when navigation selected its last block before the reveal.
        window = self.tk.Toplevel(self.root)
        window.geometry("760x420")
        notebook = self.ttk.Notebook(window)
        notebook.pack(fill="both", expand=True)
        placeholder = self.ttk.Frame(notebook)
        notebook.add(placeholder, text="文本")
        view = GraphView(notebook, self.tk, self.ttk)
        notebook.add(view.frame, text="图形")
        try:
            self._pump(lambda: window.winfo_ismapped() and notebook.winfo_width() > 100,
                       reason="显示环境未能在限定时间内映射测试宿主窗口；尚未执行图形映射断言")
            addresses = [0x1000 + index * 16 for index in range(12)]
            graph = {"entry": addresses[0], "blocks": [_block(address) for address in addresses],
                     "edges": [{"src": addresses[index], "dst": addresses[index + 1]}
                               for index in range(11)]}
            self.assertFalse(view.canvas.winfo_ismapped())
            view.set_cfg(graph, addresses[-1])
            notebook.select(view.frame)
            self._pump(lambda: (view.canvas.winfo_ismapped() and view.canvas.winfo_width() > 100
                                and view._pending is None),
                       reason="宿主窗口已映射，但图形标签未在限定时间内映射并完成绘制")
            self.assertTrue(view.canvas.winfo_ismapped())
            self.assertEqual(view.scale, 1.0)
            self.assertEqual(view.selected_address, addresses[-1])
            self.assertIn(addresses[-1], {start for start, _ in view._items.values()})
            text_items = [view.canvas.itemcget(item, "text") for item in view.canvas.find_all()
                          if view.canvas.type(item) == "text"]
            self.assertTrue(any(f"{addresses[-1]:x}  ret" in text for text in text_items))
            block = view.layout.blocks[addresses[-1]]
            visible_center = (block.x + block.width / 2) * view.scale - view.canvas.canvasx(0)
            self.assertAlmostEqual(visible_center, view.canvas.winfo_width() / 2, delta=25)

            view.zoom(1.2)
            window.geometry("650x360")
            self._pump(lambda: (window.winfo_width() == 650 and view.canvas.winfo_width() < 700
                                and view._pending is None),
                       reason="调整窗口尺寸后图形未在限定时间内完成绘制")
            self.assertEqual(view.scale, 1.2)  # Resize must preserve manual reading zoom.
            view.center_selection()
            self._pump(lambda: view._pending is None)
            self.assertIn(addresses[-1], {start for start, _ in view._items.values()})

            view.fit_view()
            self._pump(lambda: view._pending is None)
            self.assertLess(view.scale, 0.4)  # Explicit fit still provides a compact overview.
            self.assertEqual(len(view.layout.blocks), 12)
            self.assertEqual(len(view.layout.paths), 11)
        finally:
            window.destroy()

    def test_actual_large_graph_last_block_navigation_and_zoom_are_bounded(self):
        graph = {"blocks": [_block(index * 16) for index in range(3001)]}
        self.view.set_cfg(graph)
        self.assertTrue(self.view.select_address(3000 * 16))
        self.root.update_idletasks()
        self.assertIn(3000 * 16, {start for start, _ in self.view._items.values()})
        self.assertLessEqual(len(self.view.canvas.find_all()),
                             MAX_RENDER_BLOCKS * 11 + MAX_RENDER_EDGES * 2)
        self.view.zoom(10000)
        self.assertEqual(self.view.scale, MAX_SCALE)
        self.view.zoom(0.00001)
        self.assertEqual(self.view.scale, MIN_SCALE)
        self.assertFalse(self.view.select_address(99999999))
        self.assertEqual(self.view.selected_address, 3000 * 16)

    def test_actual_dense_loop_graph_does_not_create_unbounded_canvas_paths(self):
        graph = {"blocks": [_block(0)],
                 "edges": [{"src": 0, "dst": 0, "kind": "branch"} for _ in range(5000)]}
        self.view.set_cfg(graph, 0)
        self.root.update_idletasks()
        self.assertEqual(len(self.view.layout.paths), 5000)
        canvas_lines = [item for item in self.view.canvas.find_all()
                        if self.view.canvas.type(item) == "line"]
        self.assertLessEqual(len(canvas_lines), MAX_RENDER_EDGES + 1)  # Header separator.
        self.assertIn("5000 条路径", self.view.status.get())
        self.assertIn("过密", self.view.status.get())

    def test_click_selects_and_double_click_navigates_without_implicit_activation(self):
        self.view.set_cfg(_sample(), 0x1000)
        self.view.zoom(4)
        self.view.center_selection()
        self.root.update_idletasks()
        block = self.view.layout.blocks[0x1000]
        event = SimpleNamespace(x=block.x * self.view.scale - self.view.canvas.canvasx(0) + 10,
                                y=block.y * self.view.scale - self.view.canvas.canvasy(0) + 5,
                                keysym="")
        self.view._click(event)
        self.assertEqual(self.selected, [0x1000])
        self.assertEqual(self.navigated, [])
        self.view._activate(event)
        self.assertEqual(self.navigated, [0x1000])
        self.view._activate(SimpleNamespace(x=-1000, y=-1000, keysym=""))
        self.assertEqual(self.navigated, [0x1000])
        self.view._activate(SimpleNamespace(keysym="Return"))
        self.assertEqual(self.navigated, [0x1000, 0x1000])

    def test_unresolved_dialog_paginates_orphaned_paths(self):
        graph = {"blocks": [_block(0)], "frontier": [
            {"from": 9999, "to": index, "reason": "source_missing"}
            for index in range(501)]}
        self.view.set_cfg(graph)
        self.view.show_unresolved()
        self.root.update_idletasks()
        windows = [widget for widget in self.view.frame.winfo_children()
                   if isinstance(widget, self.tk.Toplevel)]
        try:
            window = windows[-1]
            tree = next(widget for widget in window.winfo_children()
                        if isinstance(widget, self.ttk.Treeview))
            controls = next(widget for widget in window.winfo_children()
                            if isinstance(widget, self.ttk.Frame))
            buttons = [widget for widget in controls.winfo_children()
                       if isinstance(widget, self.ttk.Button)]
            self.assertEqual(len(tree.get_children()), 200)
            buttons[1].invoke()
            self.assertEqual(tree.get_children()[0], "200")
            buttons[1].invoke()
            self.assertEqual(len(tree.get_children()), 101)
            self.assertEqual(tree.get_children()[-1], "500")
        finally:
            for window in windows:
                window.destroy()


if __name__ == "__main__":
    unittest.main()
