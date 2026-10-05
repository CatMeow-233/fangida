"""命令共用调用入口及 Tk 按键隔离的无显示测试。"""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from fangida.gui_modules.commands import Command, CommandRegistry, IDA_COMMANDS
from fangida.gui_modules.shortcuts import (ShortcutBinder, command_keys, editable_focus,
                                           shortcut_label)


class _Window:
    def __init__(self):
        self.handlers = {}
        self.calls = []
        self.focus = None
        self.grab = None
        self.unbound = []

    def bind(self, sequence, callback, *, add):
        self.calls.append((sequence, add))
        self.handlers[sequence] = callback
        return f"handler-{sequence}"

    def unbind(self, sequence, identifier):
        self.unbound.append((sequence, identifier))

    def focus_get(self):
        return self.focus

    def grab_current(self):
        return self.grab


def _focus(widget_class, state="normal"):
    return SimpleNamespace(winfo_class=lambda: widget_class, cget=lambda _key: state)


class GuiCommandTests(unittest.TestCase):
    def test_unregistered_and_disabled_commands_never_call_handler(self):
        registry = CommandRegistry()
        handler = Mock()
        enabled = [False]
        registry.register(Command("jump", "跳转"), handler, lambda: enabled[0])
        self.assertFalse(registry.is_enabled("missing"))
        self.assertFalse(registry.execute("missing"))
        self.assertFalse(registry.execute("jump"))
        handler.assert_not_called()
        enabled[0] = True
        self.assertTrue(registry.execute("jump"))
        handler.assert_called_once_with(None)

    def test_menu_and_keyboard_share_handler_and_state_predicate(self):
        registry = CommandRegistry()
        handler = Mock()
        registry.register(Command("jump", "跳转", ("<g>",)), handler)
        window = _Window()
        ShortcutBinder(window, registry, platform="linux").bind_all()
        event = SimpleNamespace(state=0)
        self.assertTrue(registry.execute("jump"))
        self.assertEqual(window.handlers["<g>"](event), "break")
        self.assertEqual(handler.call_args_list[0].args, (None,))
        self.assertEqual(handler.call_args_list[1].args, (event,))

    def test_zero_argument_handler_and_internal_typeerror_are_not_retried(self):
        calls = []
        def handler():
            calls.append("run")
        registry = CommandRegistry()
        registry.register(Command("zero", "零参数"), handler)
        self.assertTrue(registry.execute("zero", SimpleNamespace(state=0)))
        self.assertEqual(calls, ["run"])
        def failure(event=None):
            calls.append("failure")
            raise TypeError("动作内部错误")
        registry.register(Command("failure", "失败"), failure)
        with self.assertRaisesRegex(TypeError, "动作内部错误"):
            registry.execute("failure")
        self.assertEqual(calls, ["run", "failure"])

    def test_descriptions_are_immutable_and_duplicate_registration_is_rejected(self):
        registry = CommandRegistry()
        command = Command("jump", "跳转", ["<g>"])
        registry.register(command, lambda: None)
        self.assertEqual(command.keys, ("<g>",))
        self.assertIs(registry.get("jump"), command)
        self.assertEqual(registry.commands(), (command,))
        with self.assertRaises(ValueError):
            registry.register(command, lambda: None)
        with self.assertRaises(ValueError):
            Command("bad", "非法", scope="unknown")
        with self.assertRaises(TypeError):
            registry.register(Command("bad", "非法"), lambda one, two: None)


class GuiShortcutTests(unittest.TestCase):
    def _binding(self, command_id="jump_address", platform="linux", enabled=None):
        registry = CommandRegistry()
        command = next(item for item in IDA_COMMANDS if item.id == command_id)
        handler = Mock()
        registry.register(command, handler, enabled)
        window = _Window()
        binder = ShortcutBinder(window, registry, platform=platform)
        binder.bind_all()
        return window, handler, binder, command

    def test_all_input_classes_and_editable_text_keep_view_keys(self):
        window, handler, _binder, command = self._binding()
        for widget_class in ("Entry", "TEntry", "Spinbox", "TSpinbox", "Combobox",
                             "TCombobox", "Text"):
            with self.subTest(widget_class=widget_class):
                window.focus = _focus(widget_class)
                self.assertIsNone(window.handlers[command.keys[0]](SimpleNamespace(state=0)))
        handler.assert_not_called()
        window.focus = _focus("Text", "disabled")
        self.assertEqual(window.handlers[command.keys[0]](SimpleNamespace(state=0)), "break")
        handler.assert_called_once()

    def test_ctrl_x_does_not_steal_cut_from_input_widgets(self):
        window, handler, _binder, command = self._binding("xrefs_incoming")
        window.focus = _focus("TEntry")
        self.assertIsNone(window.handlers[command.keys[0]](SimpleNamespace(state=4)))
        handler.assert_not_called()

    def test_global_function_key_also_respects_editable_focus(self):
        window, handler, _binder, command = self._binding("show_shortcuts")
        window.focus = _focus("Text")
        self.assertIsNone(window.handlers[command.keys[0]](SimpleNamespace(state=0)))
        handler.assert_not_called()
        window.focus = _focus("Text", "disabled")
        self.assertEqual(window.handlers[command.keys[0]](SimpleNamespace(state=0)), "break")
        handler.assert_called_once()

    def test_modal_grab_blocks_all_commands_including_open(self):
        window, handler, _binder, command = self._binding("open_file")
        window.grab = object()
        self.assertIsNone(window.handlers[command.keys[0]](SimpleNamespace(state=4)))
        handler.assert_not_called()

    def test_global_open_can_execute_with_entry_focus_when_not_modal(self):
        window, handler, _binder, command = self._binding("open_file")
        window.focus = _focus("TEntry")
        self.assertEqual(window.handlers[command.keys[0]](SimpleNamespace(state=4)), "break")
        handler.assert_called_once()

    def test_unavailable_command_does_not_consume_event(self):
        window, handler, _binder, command = self._binding(enabled=lambda: False)
        self.assertIsNone(window.handlers[command.keys[0]](SimpleNamespace(state=0)))
        handler.assert_not_called()

    def test_unmodified_keys_reject_alt_meta_and_control(self):
        for platform in ("linux", "win32", "darwin"):
            window, handler, _binder, command = self._binding(platform=platform)
            for mask in (4, 8, 32, 64, 128) + ((16,) if platform == "darwin" else ()):
                with self.subTest(platform=platform, mask=mask):
                    self.assertIsNone(window.handlers[command.keys[0]](SimpleNamespace(state=mask)))
            handler.assert_not_called()
            # Shift/CapsLock 与 X11 NumLock 不影响单键命令。
            allowed = 3 if platform == "darwin" else 3 | 16
            self.assertEqual(window.handlers[command.keys[0]](SimpleNamespace(state=allowed)),
                             "break")

    def test_mac_adds_command_aliases_and_preserves_control_bindings(self):
        for command_id, alias in (("open_file", "<Command-o>"),
                                  ("save_database", "<Command-s>"), ("find", "<Command-f>")):
            window, handler, _binder, command = self._binding(command_id, platform="darwin")
            self.assertIn(command.keys[0], window.handlers)
            self.assertIn(alias, window.handlers)
            self.assertEqual(window.handlers[alias](SimpleNamespace(state=8)), "break")
            handler.assert_called_once()
            self.assertNotIn(alias, command_keys(command, "linux"))

    def test_window_binding_uses_add_and_close_only_unbinds_own_ids(self):
        window, _handler, binder, _command = self._binding()
        self.assertTrue(all(add == "+" for _sequence, add in window.calls))
        original = list(window.calls)
        binder.bind_all()
        self.assertEqual(window.calls, original)
        binder.close()
        self.assertEqual(window.unbound, [(sequence, f"handler-{sequence}")
                                          for sequence, _add in original])
        binder.close()
        self.assertEqual(len(window.unbound), len(original))

    def test_unknown_focus_does_not_intercept_view_command(self):
        self.assertFalse(editable_focus(None))
        self.assertTrue(editable_focus(SimpleNamespace()))

    def test_shortcut_labels_and_required_command_coverage(self):
        descriptions = {command.id: command for command in IDA_COMMANDS}
        self.assertEqual(len(descriptions), 21)
        self.assertEqual(shortcut_label(descriptions["jump_address"], "linux"), "G")
        self.assertEqual(shortcut_label(descriptions["follow"], "linux"), "Enter")
        self.assertEqual(shortcut_label(descriptions["set_comment"], "linux"), "; / :")
        self.assertEqual(shortcut_label(descriptions["find"], "darwin"),
                         "Alt+T / Ctrl+F / Command+F")
        expected = {"jump_address": "<KeyPress-g>", "xrefs_operand": "<KeyPress-x>",
                    "xrefs_incoming": "<Control-x>", "xrefs_outgoing": "<Control-j>",
                    "toggle_graph": "<space>",
                    "rename_symbol": "<KeyPress-n>", "set_comment": "<semicolon>",
                    "back": "<Escape>", "forward": "<Control-Return>",
                    "show_strings": "<Shift-F12>", "show_shortcuts": "<F1>",
                    "save_database": "<Control-w>", "show_sections": "<Control-s>",
                    "show_functions": "<Control-p>", "jump_name": "<Control-l>",
                    "jump_entry": "<Control-e>", "find": "<Alt-t>",
                    "find_next": "<Control-t>", "show_pseudocode": "<F5>"}
        for command_id, key in expected.items():
            self.assertIn(key, descriptions[command_id].keys)

    def test_ida_save_segment_and_crossreference_keys_do_not_conflict(self):
        registry = CommandRegistry()
        calls = []
        for command in IDA_COMMANDS:
            registry.register(command, lambda _event=None, command_id=command.id:
                              calls.append(command_id))
        window = _Window()
        ShortcutBinder(window, registry, platform="linux").bind_all()
        for sequence, expected, state in (
            ("<Control-w>", "save_database", 4),
            ("<Control-s>", "show_sections", 4),
            ("<Control-x>", "xrefs_incoming", 4),
            ("<Control-j>", "xrefs_outgoing", 4),
            ("<KeyPress-x>", "xrefs_operand", 0),
            ("<Alt-t>", "find", 8),
            ("<Control-t>", "find_next", 4),
        ):
            with self.subTest(sequence=sequence):
                self.assertEqual(window.handlers[sequence](SimpleNamespace(state=state)), "break")
                self.assertEqual(calls[-1], expected)
        self.assertEqual(len(calls), 7)


if __name__ == "__main__":
    unittest.main()
