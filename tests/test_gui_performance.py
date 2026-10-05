"""GUI 分页保留所有记录，且避免隐藏页与 CFG 的重复处理。"""
import unittest
from unittest.mock import Mock

from fangida.gui import _Browser, TABLE_PAGE_ROWS, cfg_block_rows


class _Tree:
    def __init__(self):
        self.items = {}
        self.selected = ()

    def get_children(self):
        return tuple(self.items)

    def delete(self, *items):
        for item in items:
            del self.items[item]
        self.selected = ()

    def insert(self, parent, index, *, iid, values):
        if iid in self.items:
            raise AssertionError("旧分页回调重复插入行")
        self.items[iid] = values

    def selection(self):
        return self.selected


class _Tab:
    def __init__(self, name):
        self.name = name
        self.master = Mock()

    def __str__(self):
        return self.name


def _browser(rows):
    browser = _Browser.__new__(_Browser)
    browser._closed = False
    browser._generation = 1
    browser._tables = {name: _Tree() for name in rows}
    browser._rows = rows
    browser._details = {name: Mock() for name in rows}
    browser._tabs = {name: _Tab(name) for name in rows}
    browser._table_pages = {}
    browser._table_tokens = {}
    browser._table_loaded = set()
    browser._table_page_status = {name: Mock() for name in rows}
    browser._table_page_numbers = {name: Mock() for name in rows}
    browser._table_previous = {name: Mock() for name in rows}
    browser._table_next = {name: Mock() for name in rows}
    browser._set_text = Mock()
    browser._cfg_dirty = False
    browser.notebook = Mock()
    browser.notebook.select.return_value = "Overview"
    browser.root = Mock()
    pending = []
    browser.root.after.side_effect = lambda delay, callback, *args: pending.append(
        (delay, callback, args))
    browser._reset_table_pages()
    return browser, pending


def _pump(pending):
    while pending:
        delay, callback, arguments = pending.pop(0)
        if delay == 1:
            callback(*arguments)


class GuiPerformanceTests(unittest.TestCase):
    def test_hidden_tables_do_not_insert_but_all_pages_remain_accessible(self):
        rows = [{"src": index, "dst": index + 1, "kind": "jmp"}
                for index in range(10_031)]
        browser, pending = _browser({"Xrefs": rows, "Strings": [{"value": "hidden"}]})
        browser._show_selected_tab()
        self.assertFalse(pending)
        self.assertEqual(browser._tables["Xrefs"].items, {})
        self.assertEqual(browser._tables["Strings"].items, {})
        self.assertIs(browser._rows["Xrefs"], rows)
        browser.notebook.select.return_value = "Xrefs"
        browser._show_selected_tab()
        seen = set()
        for page in range(11):
            _pump(pending)
            tree = browser._tables["Xrefs"]
            self.assertLessEqual(len(tree.items), TABLE_PAGE_ROWS)
            seen.update(map(int, tree.items))
            expected = range(page * TABLE_PAGE_ROWS,
                             min((page + 1) * TABLE_PAGE_ROWS, len(rows)))
            self.assertEqual(set(map(int, tree.items)), set(expected))
            browser._change_table_page("Xrefs", 1)
        self.assertEqual(seen, set(range(len(rows))))
        self.assertEqual(browser._tables["Strings"].items, {})
        self.assertEqual(len(browser._rows["Xrefs"]), 10_031)

    def test_page_switch_cancels_old_callbacks_with_same_analysis_generation(self):
        rows = [{"location": index, "name": str(index)} for index in range(2_001)]
        browser, pending = _browser({"Functions": rows})
        browser._render_table_page("Functions", 0)
        obsolete = pending[0]
        browser._change_table_page("Functions", 1)
        _pump(pending)
        obsolete[1](*obsolete[2])
        self.assertEqual(set(map(int, browser._tables["Functions"].items)),
                         set(range(1_000, 2_000)))
        self.assertIs(browser._rows["Functions"], rows)
        browser._tables["Functions"].selected = ("1300",)
        self.assertIs(browser._selected_record("Functions"), rows[1_300])
        browser._show_detail("Functions")
        self.assertIn('"name": "1300"', browser._set_text.call_args.args[1])

    def test_page_bounds_and_direct_jump_are_complete(self):
        browser, pending = _browser({"Strings": [{"value": str(index)} for index in range(2_001)]})
        browser._table_page_numbers["Strings"].get.return_value = "3"
        browser._jump_table_page("Strings")
        _pump(pending)
        self.assertEqual(tuple(browser._tables["Strings"].items), ("2000",))
        browser._table_next["Strings"].configure.assert_called_with(state="disabled")
        browser._change_table_page("Strings", 1)
        _pump(pending)
        self.assertEqual(tuple(browser._tables["Strings"].items), ("2000",))
        browser._table_page_numbers["Strings"].get.return_value = "4"
        browser._jump_table_page("Strings")
        browser._table_page_status["Strings"].set.assert_called_with("请输入范围内的页码")
        self.assertEqual(tuple(browser._tables["Strings"].items), ("2000",))
        browser._render_table_page("Strings", -1_000)
        _pump(pending)
        browser._table_previous["Strings"].configure.assert_called_with(state="disabled")
        self.assertEqual(set(map(int, browser._tables["Strings"].items)), set(range(1_000)))

    def test_obsolete_generation_or_closed_window_does_not_insert(self):
        browser, pending = _browser({"Functions": [{"name": str(index)} for index in range(601)]})
        browser._render_table_page("Functions", 0)
        browser._generation += 1
        _pump(pending)
        self.assertEqual(len(browser._tables["Functions"].items), 200)
        browser._closed = True
        browser._insert_chunk("Functions", browser._generation, 200)
        self.assertEqual(len(browser._tables["Functions"].items), 200)

    def test_empty_page_has_no_callbacks_and_disabled_navigation(self):
        browser, pending = _browser({"Xrefs": []})
        browser._render_table_page("Xrefs", 0)
        self.assertFalse(pending)
        browser._table_previous["Xrefs"].configure.assert_called_with(state="disabled")
        browser._table_next["Xrefs"].configure.assert_called_with(state="disabled")
        browser._table_page_status["Xrefs"].set.assert_called_with("0–0 / 0 条 · 第 1/1 页")

    def test_cfg_first_render_is_delayed_until_cfg_tab_selected(self):
        browser, pending = _browser({"Xrefs": []})
        browser._cfg_tab = _Tab("CFG")
        browser._cfg_dirty = True
        browser._show_cfg = Mock()
        browser._show_selected_tab()
        browser._show_cfg.assert_not_called()
        browser.notebook.select.return_value = "CFG"
        browser._show_selected_tab()
        browser._show_selected_tab()
        browser._show_cfg.assert_called_once_with()
        self.assertFalse(browser._cfg_dirty)

    def test_cfg_sources_are_indexed_once_with_original_edge_order(self):
        class SourceCounter(dict):
            source_reads = 0
            def get(self, key, *args):
                if key in ("src", "from"):
                    type(self).source_reads += 1
                return super().get(key, *args)
        blocks = [{"start": index * 10,
                   "instructions": [{"addr": index * 10}, {"addr": index * 10 + 2}],
                   "successors": [index * 10 + 10]} for index in range(500)]
        edges = [SourceCounter(src=index * 10 + delta, dst=index * 10 + 10, kind="jmp")
                 for index in range(500) for delta in (2, 0)]
        frontiers = [SourceCounter({"from": index * 10 + 2, "to": 100_000,
                                    "reason": "unresolved"}) for index in range(500)]
        graph = {"blocks": blocks, "edges": edges, "frontier": frontiers}
        rows = cfg_block_rows(graph)
        self.assertEqual(SourceCounter.source_reads, len(edges) + len(frontiers))
        self.assertEqual(len(rows), 500)
        for index, row in enumerate(rows):
            self.assertEqual(row["outgoing"], edges[index * 2:index * 2 + 2])
            self.assertEqual(row["frontier"], [frontiers[index]])
            self.assertIs(row["instructions"], blocks[index]["instructions"])
            self.assertEqual(row["successors"], [index * 10 + 10])
        self.assertNotIn("outgoing", blocks[0])


if __name__ == "__main__":
    unittest.main()
