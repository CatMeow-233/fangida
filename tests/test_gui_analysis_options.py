"""打开文件时选择分析范围的无显示集成检查。"""
from pathlib import Path
import queue
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import ANY, Mock, patch

from fangida.api import AnalysisView
from fangida.gui import DEFAULT_THREADS, _Browser, _Loaded, _analyze_file, main
from fangida.models import AnalysisResult
from fangida.settings import Settings


def _browser(*, max_bytes=4096, deep_analysis=None, full_analysis=False):
    browser = object.__new__(_Browser)
    browser.max_bytes = max_bytes
    browser.deep_analysis = deep_analysis
    browser.full_analysis = full_analysis
    browser.use_ghidra = None
    browser.semantic_threads = 3
    browser.database_path = None
    browser.storage_plugin = "sqlite_storage"
    browser._closed = False
    browser._busy = False
    browser._messages = queue.SimpleQueue()
    browser.open_button = Mock()
    browser.open_button.instate.return_value = False
    browser.filedialog = Mock()
    browser.status = Mock()
    return browser


class _Variable:
    def __init__(self, master=None, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class _Widget:
    def __init__(self, environment, kind, master=None, **options):
        self.environment = environment
        self.kind = kind
        self.options = dict(options)
        self.protocols = {}
        self.bindings = {}
        self.destroyed = False
        environment.widgets.append(self)

    def pack(self, *args, **kwargs):
        pass

    def grid(self, *args, **kwargs):
        pass

    def configure(self, **kwargs):
        self.options.update(kwargs)

    def columnconfigure(self, *args, **kwargs):
        pass

    def title(self, value):
        self.options["title"] = value

    def transient(self, parent):
        pass

    def resizable(self, *args):
        pass

    def protocol(self, name, callback):
        self.protocols[name] = callback

    def bind(self, sequence, callback):
        self.bindings[sequence] = callback

    def grab_set(self):
        pass

    def focus_set(self):
        pass

    def destroy(self):
        self.destroyed = True

    def wait_window(self, window=None):
        self.environment.interact(self if window is None else window)


class _DialogEnvironment:
    """只模拟用户选择；执行真实确认和取消回调。"""
    def __init__(self, interaction):
        self.widgets = []
        self.interaction = interaction
        self.root = SimpleNamespace(wait_window=self.interact)
        self.tk = SimpleNamespace(StringVar=_Variable, Toplevel=self._factory("window"))
        self.ttk = SimpleNamespace(**{name: self._factory(name)
            for name in ("Frame", "Label", "Button", "Radiobutton", "Checkbutton", "Spinbox")})

    def _factory(self, kind):
        return lambda master=None, **options: _Widget(self, kind, master, **options)

    def interact(self, window):
        self.interaction(self, window)

    def choose(self, value):
        radios = [widget for widget in self.widgets
                  if widget.kind == "Radiobutton" and widget.options.get("value") == value]
        if len(radios) != 1:
            raise AssertionError(f"找不到唯一的模式选项：{value}")
        radio = radios[0]
        if radio.options.get("state") == "disabled":
            raise AssertionError(f"模式选项已禁用：{value}")
        radio.options["variable"].set(value)

    def only(self, kind):
        widgets = [widget for widget in self.widgets if widget.kind == kind]
        if len(widgets) != 1:
            raise AssertionError(f"找不到唯一的 {kind}")
        return widgets[0]

    def set_multithread(self, enabled, threads=None):
        """模拟勾选/取消“启用多线程分析”并填写线程数，执行真实的切换回调。"""
        check = self.only("Checkbutton")
        check.options["variable"].set(check.options["onvalue"] if enabled else check.options["offvalue"])
        check.options["command"]()
        if threads is not None:
            self.only("Spinbox").options["textvariable"].set(str(threads))

    def start(self):
        buttons = [widget for widget in self.widgets if widget.kind == "Button"
                   and any(word in str(widget.options.get("text", "")).lower()
                           for word in ("start", "analyze", "开始", "确认"))]
        if len(buttons) != 1:
            raise AssertionError("找不到唯一的开始分析按钮")
        buttons[0].options["command"]()


class GuiAnalysisOptionsTests(unittest.TestCase):
    def test_actual_options_confirmation_applies_full_mode(self):
        browser = _browser()
        def confirm(environment, window):
            environment.choose("full")
            environment.start()
            self.assertTrue(window.destroyed)
        environment = _DialogEnvironment(confirm)
        browser.root, browser.tk, browser.ttk = environment.root, environment.tk, environment.ttk
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"\x7fELF\x02\x01\x01" + bytes(57))
            self.assertTrue(browser._choose_analysis_options(source))
        self.assertEqual((browser.max_bytes, browser.deep_analysis, browser.full_analysis),
                         (None, True, True))

    def test_actual_options_window_close_discards_radio_selection(self):
        browser = _browser()
        def cancel(environment, window):
            environment.choose("full")
            window.protocols["WM_DELETE_WINDOW"]()
        environment = _DialogEnvironment(cancel)
        browser.root, browser.tk, browser.ttk = environment.root, environment.tk, environment.ttk
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_bytes(b"\x7fELF\x02\x01\x01" + bytes(57))
            self.assertFalse(browser._choose_analysis_options(source))
        self.assertEqual((browser.max_bytes, browser.deep_analysis, browser.full_analysis),
                         (4096, None, False))

    def test_unknown_dialog_does_not_offer_unsupported_full_analysis(self):
        browser = _browser(full_analysis=True)
        def confirm(environment, window):
            radios = [widget for widget in environment.widgets
                      if widget.kind == "Radiobutton" and widget.options.get("value") == "full"]
            self.assertEqual(len(radios), 1)
            self.assertEqual(radios[0].options.get("state"), "disabled")
            self.assertEqual(radios[0].options["variable"].get(), "standard")
            environment.start()
        environment = _DialogEnvironment(confirm)
        browser.root, browser.tk, browser.ttk = environment.root, environment.tk, environment.ttk
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.unknown"
            source.write_bytes(b"unknown format")
            self.assertTrue(browser._choose_analysis_options(source))
        self.assertFalse(browser.full_analysis)
        self.assertEqual(browser._analysis_mode_name(), "standard")

    def test_dex_dialog_offers_plugin_full_analysis(self):
        browser = _browser()
        def confirm(environment, window):
            radios = [widget for widget in environment.widgets
                      if widget.kind == "Radiobutton" and widget.options.get("value") == "full"]
            self.assertEqual(radios[0].options.get("state"), "normal")
            environment.choose("full")
            environment.start()
        environment = _DialogEnvironment(confirm)
        browser.root, browser.tk, browser.ttk = environment.root, environment.tk, environment.ttk
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.dex"
            source.write_bytes(b"dex\n035\x00" + bytes(120))
            self.assertTrue(browser._choose_analysis_options(source))
        self.assertTrue(browser.full_analysis)

    def test_cancel_file_picker_does_not_show_options_or_start_analysis(self):
        browser = _browser()
        browser.filedialog.askopenfilename.return_value = ""
        browser._choose_analysis_options = Mock()
        browser.open_file = Mock()
        browser.open_dialog()
        browser._choose_analysis_options.assert_not_called()
        browser.open_file.assert_not_called()
        self.assertEqual((browser.max_bytes, browser.deep_analysis, browser.full_analysis),
                         (4096, None, False))

    def test_cancel_analysis_options_keeps_existing_analysis(self):
        browser = _browser()
        previous_view = object()
        browser._view = previous_view
        browser._generation = 7
        browser.filedialog.askopenfilename.return_value = "sample.elf"
        browser._choose_analysis_options = Mock(return_value=False)
        browser.open_file = Mock()
        browser.open_dialog()
        browser._choose_analysis_options.assert_called_once_with("sample.elf")
        browser.open_file.assert_not_called()
        self.assertIs(browser._view, previous_view)
        self.assertEqual(browser._generation, 7)
        self.assertEqual((browser.max_bytes, browser.deep_analysis, browser.full_analysis),
                         (4096, None, False))

    def test_open_file_waits_for_selected_mode(self):
        browser = _browser()
        browser.filedialog.askopenfilename.return_value = "sample.elf"
        actions = []
        def choose(path):
            actions.append(("choose", path))
            browser._apply_analysis_mode("full")
            return True
        browser._choose_analysis_options = choose
        browser.open_file = lambda path: actions.append(("open", path, browser.max_bytes,
            browser.deep_analysis, browser.full_analysis))
        browser.open_dialog()
        self.assertEqual(actions, [("choose", "sample.elf"),
                                  ("open", "sample.elf", None, True, True)])

    def test_busy_open_does_not_show_file_picker(self):
        browser = _browser()
        browser.open_button.instate.return_value = True
        browser._choose_analysis_options = Mock()
        browser.open_file = Mock()
        browser.open_dialog()
        browser.filedialog.askopenfilename.assert_not_called()
        browser._choose_analysis_options.assert_not_called()
        browser.open_file.assert_not_called()

    def test_full_mode_removes_byte_cap_and_mode_switch_restores_it(self):
        browser = _browser(max_bytes=1234)
        self.assertEqual(browser._analysis_mode_name(), "standard")
        browser._apply_analysis_mode("full")
        self.assertEqual(browser._analysis_mode_name(), "full")
        self.assertEqual((browser.max_bytes, browser.deep_analysis, browser.full_analysis),
                         (None, True, True))
        browser._apply_analysis_mode("fast")
        self.assertEqual(browser._analysis_mode_name(), "fast")
        self.assertEqual((browser.max_bytes, browser.deep_analysis, browser.full_analysis),
                         (1234, False, False))
        browser._apply_analysis_mode("standard")
        self.assertEqual(browser._analysis_mode_name(), "standard")
        self.assertEqual(browser.max_bytes, 1234)
        self.assertFalse(browser.full_analysis)
        self.assertIsNot(browser.deep_analysis, False)
        self.assertEqual(browser.semantic_threads, 3)
        self.assertIsNone(browser.use_ghidra)

    def test_invalid_mode_does_not_mutate_parameters(self):
        browser = _browser()
        with self.assertRaises(ValueError):
            browser._apply_analysis_mode("unknown")
        self.assertEqual((browser.max_bytes, browser.deep_analysis, browser.full_analysis),
                         (4096, None, False))

    def test_standard_selection_after_fast_start_enables_deeper_analysis(self):
        browser = _browser(deep_analysis=False)
        self.assertEqual(browser._analysis_mode_name(), "fast")
        browser._apply_analysis_mode("standard")
        self.assertEqual(browser._analysis_mode_name(), "standard")
        self.assertIs(browser.deep_analysis, True)
        self.assertFalse(browser.full_analysis)
        self.assertEqual(browser.max_bytes, 4096)

    def test_full_worker_receives_uncapped_analysis_on_background_thread(self):
        browser = _browser(max_bytes=1234)
        browser._apply_analysis_mode("full")
        view = AnalysisView(AnalysisResult("sample.elf", "elf", "kkagent", "partial"))
        prepared = _Loaded(view, "overview", {}, [], "sample.elf", "elf", "partial", [])
        threads = []
        def analyze(*args, **kwargs):
            threads.append(threading.get_ident())
            return view
        main_thread = threading.get_ident()
        with patch("fangida.gui._analyze_file", side_effect=analyze) as analyzer, \
             patch("fangida.gui._prepare", return_value=prepared):
            worker = threading.Thread(target=browser._worker, args=(3, "sample.elf"))
            worker.start()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
        # 完整分析额外请求渐进式预览（回调在分析线程里只转交预览线程）。
        analyzer.assert_called_once_with("sample.elf", None, None, True, 3, True, on_preview=ANY)
        self.assertTrue(callable(analyzer.call_args.kwargs["on_preview"]))
        self.assertEqual(browser._messages.get_nowait(), (3, prepared))
        self.assertEqual(len(threads), 1)
        self.assertNotEqual(threads[0], main_thread)

    def test_selected_bounded_mode_overrides_full_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.elf"
            source.write_bytes(b"fixture")
            result = AnalysisResult(str(source), "elf", "kkagent", "partial")
            settings = Settings(full_analysis=True)
            with patch("fangida.gui.load_settings", return_value=settings), \
                 patch("fangida.gui.AnalysisService") as constructor:
                service = constructor.return_value.__enter__.return_value
                service.analyze.return_value = result
                _analyze_file(source, 4096, None, False, 1, False)
            service.analyze.assert_called_once_with(source.resolve(), max_bytes=4096,
                use_ghidra=None, deep_analysis=False, full_analysis=False)

    def test_existing_command_line_full_and_fast_options_keep_launch_contract(self):
        with patch("fangida.gui.launch", return_value=0) as launch:
            self.assertEqual(main(["sample.elf", "--full", "--threads", "4"]), 0)
        launch.assert_called_once_with("sample.elf", max_bytes=None, use_ghidra=None,
            deep_analysis=None, semantic_threads=4, full_analysis=True)
        with patch("fangida.gui.launch", return_value=0) as launch:
            self.assertEqual(main(["sample.elf", "--fast", "--max-bytes", "4096"]), 0)
        launch.assert_called_once_with("sample.elf", max_bytes=4096, use_ghidra=None,
            deep_analysis=False, semantic_threads=None)


class GuiMultithreadOptionTests(unittest.TestCase):
    """打开文件对话框里的多线程分析选项。"""

    def _run(self, browser, interaction, name="input"):
        environment = _DialogEnvironment(interaction)
        browser.root, browser.tk, browser.ttk = environment.root, environment.tk, environment.ttk
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / name
            source.write_bytes(b"\x7fELF\x02\x01\x01" + bytes(57))
            return browser._choose_analysis_options(source), environment

    def test_dialog_offers_multithread_and_untouched_choice_keeps_settings(self):
        browser = _browser()
        def confirm(environment, window):
            check = environment.only("Checkbutton")
            self.assertIn("多线程", check.options["text"])
            self.assertEqual(check.options["variable"].get(), check.options["onvalue"])
            spin = environment.only("Spinbox")
            self.assertEqual((spin.options["from_"], spin.options["to"]), (2, 16))
            self.assertEqual((spin.options["state"], spin.options["textvariable"].get()), ("normal", "3"))
            environment.start()
        accepted, _ = self._run(browser, confirm)
        self.assertTrue(accepted)
        self.assertEqual((browser.semantic_threads, getattr(browser, "analyze_threads", None)), (3, None))

    def test_disabling_multithread_runs_decode_and_xref_on_one_thread(self):
        browser = _browser()
        def confirm(environment, window):
            environment.set_multithread(False)
            self.assertEqual(environment.only("Spinbox").options["state"], "disabled")
            environment.start()
        accepted, _ = self._run(browser, confirm)
        self.assertTrue(accepted)
        self.assertEqual((browser.semantic_threads, browser.analyze_threads), (1, 1))
        view = AnalysisView(AnalysisResult("sample.elf", "elf", "kkagent", "partial"))
        prepared = _Loaded(view, "overview", {}, [], "sample.elf", "elf", "partial", [])
        with patch("fangida.gui._analyze_file", return_value=view) as analyzer, \
             patch("fangida.gui._prepare", return_value=prepared):
            browser._worker(1, "sample.elf")
        analyzer.assert_called_once_with("sample.elf", 4096, None, None, 1, False, analyze_threads=1)

    def test_choosing_a_thread_count_sets_decoder_threads(self):
        browser = _browser()
        accepted, _ = self._run(browser, lambda environment, window: (
            environment.set_multithread(True, 8), environment.start()))
        self.assertTrue(accepted)
        self.assertEqual((browser.semantic_threads, browser.analyze_threads), (8, None))

    def test_invalid_thread_count_keeps_dialog_open_until_corrected(self):
        browser = _browser()
        def confirm(environment, window):
            environment.set_multithread(True, "99")
            environment.start()
            self.assertFalse(window.destroyed)
            messages = [widget.options["textvariable"].get() for widget in environment.widgets
                        if widget.kind == "Label" and "textvariable" in widget.options]
            self.assertTrue(any("2–16" in message for message in messages))
            environment.set_multithread(True, "abc")
            environment.start()
            self.assertFalse(window.destroyed)
            environment.set_multithread(True, 6)
            environment.start()
            self.assertTrue(window.destroyed)
        accepted, _ = self._run(browser, confirm)
        self.assertTrue(accepted)
        self.assertEqual(browser.semantic_threads, 6)

    def test_single_threaded_start_can_enable_multithreading(self):
        browser = _browser()
        browser.semantic_threads, browser.analyze_threads = 1, 1
        def confirm(environment, window):
            self.assertEqual(environment.only("Checkbutton").options["variable"].get(), "0")
            spin = environment.only("Spinbox")
            self.assertEqual((spin.options["state"], spin.options["textvariable"].get()), ("disabled", str(DEFAULT_THREADS)))
            environment.set_multithread(True)
            self.assertEqual(spin.options["state"], "normal")
            environment.start()
        accepted, _ = self._run(browser, confirm)
        self.assertTrue(accepted)
        self.assertEqual((browser.semantic_threads, browser.analyze_threads), (DEFAULT_THREADS, None))

    def test_cancel_keeps_thread_settings(self):
        browser = _browser()
        def cancel(environment, window):
            environment.set_multithread(False)
            window.protocols["WM_DELETE_WINDOW"]()
        accepted, _ = self._run(browser, cancel)
        self.assertFalse(accepted)
        self.assertEqual((browser.semantic_threads, getattr(browser, "analyze_threads", None)), (3, None))

    def test_single_thread_budget_reaches_analysis_service(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.elf"
            source.write_bytes(b"fixture")
            result = AnalysisResult(str(source), "elf", "kkagent", "partial")
            for threads, budget, expected in ((1, 1, (1, 1)), (6, None, (6, 8)), (None, None, (4, 8))):
                with self.subTest(threads=threads, budget=budget), \
                     patch("fangida.gui.load_settings", return_value=Settings(analyze_threads=8, semantic_threads=4)), \
                     patch("fangida.gui.AnalysisService") as constructor:
                    constructor.return_value.__enter__.return_value.analyze.return_value = result
                    _analyze_file(source, None, None, True, threads, True,
                                  **({"analyze_threads": budget} if budget is not None else {}))
                    settings = constructor.call_args.args[0]
                    self.assertEqual((settings.semantic_threads, settings.analyze_threads), expected)

    def test_status_text_names_the_thread_choice(self):
        browser = _browser()
        browser.analysis_mode_status = _Variable()
        browser._apply_thread_options(True, 5)
        self.assertIn("多线程 5", browser.analysis_mode_status.get())
        browser._apply_thread_options(False, 1)
        self.assertIn("单线程", browser.analysis_mode_status.get())
        with self.assertRaises(ValueError):
            browser._apply_thread_options(True, 1)


if __name__ == "__main__":
    unittest.main()
