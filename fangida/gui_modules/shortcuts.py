"""Tk 快捷键适配层：保护输入焦点、模态窗口和平台修饰键。"""
from __future__ import annotations

import sys
from typing import Any

from .commands import Command, CommandRegistry


_MAC_ALIASES = {
    "open_file": "<Command-o>",
    "save_database": "<Command-s>",
    "find": "<Command-f>",
}
_INPUT_CLASSES = {"Entry", "TEntry", "Spinbox", "TSpinbox", "Combobox", "TCombobox"}
_MODIFIER_NAMES = {"Control", "Command", "Alt", "Option", "Meta", "Mod1", "Mod2",
                   "Mod3", "Mod4", "Mod5"}


def editable_focus(widget: Any) -> bool:
    """只读代码 Text 可接收命令；输入框及 Combobox 保留输入操作。"""
    if widget is None:
        return False
    try:
        widget_class = widget.winfo_class()
        if widget_class in _INPUT_CLASSES:
            return True
        if widget_class == "Text":
            return str(widget.cget("state")) != "disabled"
    except Exception:
        # 已销毁或外部窗口的焦点不可判定时，不抢走按键。
        return True
    return False


def command_keys(command: Command, platform: str | None = None) -> tuple[str, ...]:
    platform = sys.platform if platform is None else platform
    alias = _MAC_ALIASES.get(command.id) if platform == "darwin" else None
    return command.keys + ((alias,) if alias and alias not in command.keys else ())


def shortcut_label(command: Command, platform: str | None = None) -> str:
    """菜单／帮助使用同一键位描述，合并大小写及小键盘别名。"""
    labels = []
    for sequence in command_keys(command, platform):
        parts = sequence.strip("<>").split("-")
        parts = [part for part in parts if part not in {"Key", "KeyPress"}]
        names = {"Control": "Ctrl", "Command": "Command", "Return": "Enter",
                 "KP_Enter": "Enter", "Escape": "Esc", "space": "Space",
                 "semicolon": ";", "colon": ":"}
        label = "+".join(names.get(part, part.upper() if len(part) == 1 else part)
                         for part in parts)
        if label not in labels:
            labels.append(label)
    return " / ".join(labels)


class ShortcutBinder:
    """只在目标窗口绑定；close 仅移除本实例的绑定，不覆盖既有绑定。"""

    def __init__(self, window: Any, registry: CommandRegistry, *,
                 platform: str | None = None) -> None:
        self.window = window
        self.registry = registry
        self.platform = sys.platform if platform is None else platform
        self._bindings: list[tuple[str, str]] = []

    def bind_all(self) -> None:
        if self._bindings:
            return
        sequences: dict[str, Command] = {}
        for command in self.registry.commands():
            for sequence in command_keys(command, self.platform):
                if sequence in sequences and sequences[sequence].id != command.id:
                    raise ValueError(f"快捷键重复：{sequence}")
                sequences[sequence] = command
        try:
            for sequence, command in sequences.items():
                callback = self._handler(command, sequence)
                identifier = self.window.bind(sequence, callback, add="+")
                self._bindings.append((sequence, identifier))
        except Exception:
            self.close()
            raise

    def _handler(self, command: Command, sequence: str):
        modified = bool(set(sequence.strip("<>").split("-")) & _MODIFIER_NAMES)

        def invoke(event: Any = None) -> str | None:
            try:
                if self.window.grab_current() is not None:
                    return None
                focus = self.window.focus_get()
            except Exception:
                return None
            if editable_focus(focus) and (command.scope == "view" or not modified):
                return None
            # 单键与 Enter/Esc/F1 等无修饰命令不能被 Alt/Meta/Ctrl 组合误触发。
            # X11 的 Mod2 通常是 NumLock；macOS 同一位为 Option。
            forbidden = 4 | 8 | 32 | 64 | 128
            if self.platform == "darwin":
                forbidden |= 16
            if not modified and int(getattr(event, "state", 0)) & forbidden:
                return None
            return "break" if self.registry.execute(command.id, event) else None

        return invoke

    def close(self) -> None:
        bindings, self._bindings = self._bindings, []
        for sequence, identifier in bindings:
            if identifier:
                try:
                    self.window.unbind(sequence, identifier)
                except Exception:
                    pass  # 关闭窗口后 Tcl 控件可能已经销毁。
