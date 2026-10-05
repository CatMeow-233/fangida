"""渐进式结果：完整分析解码完成后先交出只读预览，最终结果随后替换且与不开预览时一致。"""
from __future__ import annotations

import inspect
import threading
import unittest
from unittest.mock import Mock, patch

from fangida.api import AnalysisView
from fangida.gui import _Browser, _prepare
from fangida.models import AnalysisResult, AnalysisTask
from fangida.plugins.manager import PluginManager, _accepts_keyword
from tests.test_gui_workbench import _view


def _preview_of(view: AnalysisView) -> AnalysisView:
    """把测试用完整结果变成“解码完成、尚无 CFG”的预览（与分析器构造的预览同形）。"""
    snapshot = view._snapshot
    functions = [{key: value for key, value in item.items() if key not in {"blocks", "cfg"}}
                 for item in snapshot["functions"]]
    return AnalysisView._from_owned_result(AnalysisResult(
        snapshot["path"], snapshot["kind"], snapshot["analyzer"], "partial",
        metadata={**snapshot["metadata"], "full_analysis": {"enabled": True, "preview": True}},
        functions=functions, strings=snapshot["strings"], xrefs=[],
        stats={"full_analysis": True, "full_preview": True}))


class PluginForwardingTests(unittest.TestCase):
    def test_preview_reaches_only_plugins_that_accept_it(self):
        class Legacy:
            def analyze_with_control(self, task, on_progress=None, cancel=None):
                return "legacy"

        class Progressive:
            def analyze_with_control(self, task, on_progress=None, cancel=None, on_preview=None):
                on_preview("preview")
                return "progressive"

        seen = []
        manager = PluginManager()
        task = Mock(spec=AnalysisTask)
        for plugin, expected in ((Legacy(), "legacy"), (Progressive(), "progressive")):
            with self.subTest(plugin=type(plugin).__name__), patch.object(manager, "load", return_value=plugin):
                self.assertEqual(manager.analyze("native", task, on_preview=seen.append), expected)
        self.assertEqual(seen, ["preview"])
        self.assertTrue(_accepts_keyword(lambda **kwargs: None, "on_preview"))
        self.assertFalse(_accepts_keyword(len, "on_preview"))

    def test_native_plugin_signature_keeps_original_parameters(self):
        from fangida.core.kkagent import PluginImpl
        parameters = list(inspect.signature(PluginImpl.analyze_with_control).parameters)
        self.assertEqual(parameters[:4], ["self", "task", "on_progress", "cancel"])
        self.assertEqual(parameters[4], "on_preview")


class NativePreviewTests(unittest.TestCase):
    def test_full_analysis_emits_one_read_only_preview_and_identical_final_result(self):
        import os
        import struct
        import tempfile
        from fangida.benchmark import _evidence_digest
        from fangida.dispatcher import AnalysisService
        from fangida.settings import Settings
        # 最小 x86-64 ELF：一个可执行段，内含 call + ret 与一个被调函数。
        code = bytes.fromhex("e805000000c3909090" "b801000000c3")
        base, offset = 0x400000, 0x1000
        header = bytearray(64)
        header[:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
        struct.pack_into("<HHIQQQIHHHHHH", header, 16, 2, 62, 1, base + offset, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        program = struct.pack("<IIQQQQQQ", 1, 5, offset, base + offset, base + offset, len(code), len(code), 0x1000)
        image = bytes(header) + program + bytes(offset - 64 - len(program)) + code
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "tiny.elf")
            with open(path, "wb") as stream:
                stream.write(image)
            previews = []
            with AnalysisService(Settings(ghidra_enabled=False, analyze_threads=3, semantic_threads=2)) as service:
                plain = service.analyze(path, full_analysis=True)
                final = service.analyze(path, full_analysis=True, on_preview=previews.append)
                bounded = service.analyze(path, full_analysis=False, on_preview=previews.append)
        self.assertEqual(len(previews), 1, "只有完整分析发出且只发出一次预览")
        preview = previews[0]
        self.assertEqual(preview.status, "partial")
        self.assertTrue(preview.stats["full_preview"])
        self.assertIs(preview.metadata["full_disassembly"], final.metadata["full_disassembly"])
        self.assertTrue(all(not item.get("blocks") for item in preview.functions))
        self.assertEqual(_evidence_digest(final), _evidence_digest(plain))
        self.assertNotIn("full_preview", bounded.stats)

    def test_preview_callback_failure_does_not_break_analysis(self):
        from fangida.core.kkagent.full_analysis import analyze_full
        source = inspect.getsource(analyze_full)
        self.assertIn("Preview callback failed", source)


class GuiPreviewTests(unittest.TestCase):
    def setUp(self):
        try:
            import tkinter as tk
            from tkinter import ttk
            self.root = tk.Tk()
        except Exception as exc:
            self.skipTest(f"当前环境无法创建 Tk 窗口：{exc}")
        self.root.withdraw()
        self.browser = _Browser(self.root, tk, ttk, Mock(), Mock(), None, False, True,
                                semantic_threads=2, full_analysis=True)
        self.addCleanup(self._close)

    def _close(self):
        for identifier in self.root.tk.splitlist(self.root.tk.call("after", "info")):
            self.root.tk.call("after", "cancel", identifier)
        self.browser.close()

    def _loaded(self, view, preview=False):
        with patch("fangida.gui._verified_hex_source", return_value=(None, "fixture has no source", None)):
            loaded = _prepare(view, share_completed=True)
        loaded.preview = preview
        return loaded

    def test_preview_is_browsable_but_busy_until_final_result(self):
        browser = self.browser
        browser._generation = 5
        final_view = _view()
        browser._messages.put((5, self._loaded(_preview_of(final_view), preview=True)))
        browser._drain()
        self.assertIn("预览", browser.status.get())
        self.assertTrue(browser._busy, "预览期间分析仍在进行")
        self.assertEqual(str(browser.save_database_button.cget("state")), "disabled")
        self.assertEqual(len(browser._rows["Disassembly"]), 1602)
        self.assertEqual(browser._cfgs, [])
        browser._messages.put((5, self._loaded(final_view)))
        browser._drain()
        self.assertFalse(browser._busy)
        self.assertNotIn("预览", browser.status.get())
        self.assertEqual(len(browser._cfgs), 2)

    def test_late_preview_after_final_result_is_ignored(self):
        browser = self.browser
        browser._generation = 9
        final_view = _view()
        browser._messages.put((9, self._loaded(final_view)))
        browser._messages.put((9, self._loaded(_preview_of(final_view), preview=True)))
        browser._drain()
        self.assertFalse(browser._busy)
        self.assertEqual(len(browser._cfgs), 2, "迟到的预览不能覆盖最终结果")

    def test_preview_worker_hands_off_without_blocking_the_analysis_thread(self):
        browser = self.browser
        release = threading.Event()
        started = []

        def slow_prepare(view, share_completed=False):
            started.append(threading.current_thread().name)
            release.wait(5)
            return self._loaded(_view())

        with patch("fangida.gui._prepare", side_effect=slow_prepare):
            browser._start_preview(3, AnalysisResult("x", "elf", "kkagent", "partial"))
            # 立即返回：分析线程不会等待预览准备。
            self.assertTrue(browser._messages.empty())
            release.set()
            for _ in range(500):
                if not browser._messages.empty():
                    break
                threading.Event().wait(0.01)
        generation, loaded = browser._messages.get_nowait()
        self.assertEqual((generation, loaded.preview), (3, True))
        self.assertEqual(started, ["fangida-gui-preview"])


if __name__ == "__main__":
    unittest.main()
