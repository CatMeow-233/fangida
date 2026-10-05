"""GUI 命令描述及调用入口，不依赖 Tk 或分析器。

菜单、工具栏和键盘共享同一注册表；没有注册处理器的命令不会执行。
"""
from __future__ import annotations

from dataclasses import dataclass
from inspect import signature
from typing import Any, Callable


@dataclass(frozen=True)
class Command:
    id: str
    label: str
    keys: tuple[str, ...] = ()
    scope: str = "view"

    def __post_init__(self) -> None:
        if not self.id or not self.label:
            raise ValueError("命令必须有 id 和标签")
        if self.scope not in {"global", "view"}:
            raise ValueError("命令 scope 必须是 global 或 view")
        object.__setattr__(self, "keys", tuple(self.keys))


# 依据 Hex-Rays 官方键位表；Ctrl+O、Ctrl+F 为 Fangida 兼容／附加键位。
# https://hex-rays.com/hubfs/freefile/IDA_Pro_Shortcuts.pdf
# https://hex-rays.com/blog/igor-tip-of-the-week-16-cross-references
IDA_COMMANDS: tuple[Command, ...] = (
    Command("open_file", "打开文件…", ("<Control-o>",), "global"),
    Command("save_database", "保存分析数据库…", ("<Control-w>",), "global"),
    Command("jump_address", "跳转到地址…", ("<KeyPress-g>", "<KeyPress-G>")),
    Command("jump_name", "跳转到名称…", ("<Control-l>",)),
    Command("jump_entry", "跳转到入口点…", ("<Control-e>",)),
    Command("xrefs_operand", "查看操作数引用…", ("<KeyPress-x>", "<KeyPress-X>")),
    Command("xrefs_incoming", "查看引用到当前位置…", ("<Control-x>",)),
    Command("xrefs_outgoing", "查看当前位置引用…", ("<Control-j>",)),
    Command("follow", "跟随当前位置", ("<Return>", "<KP_Enter>")),
    Command("back", "返回上一位置", ("<Escape>",)),
    Command("forward", "前进到下一位置", ("<Control-Return>", "<Control-KP_Enter>")),
    Command("toggle_graph", "切换反汇编／流程图", ("<space>",)),
    Command("rename_symbol", "重命名当前位置…", ("<KeyPress-n>", "<KeyPress-N>")),
    Command("set_comment", "添加／修改注释…", ("<semicolon>", "<colon>")),
    Command("show_sections", "查看段／节", ("<Control-s>", "<Shift-F7>")),
    Command("show_functions", "查看函数", ("<Shift-F3>", "<Control-p>")),
    Command("show_strings", "查看字符串", ("<Shift-F12>",)),
    Command("show_pseudocode", "查看已有伪代码", ("<Tab>", "<F5>")),
    Command("find", "查找当前列表…", ("<Alt-t>", "<Control-f>")),
    Command("find_next", "查找下一项", ("<Control-t>", "<F3>")),
    Command("show_shortcuts", "快捷键帮助", ("<F1>",), "global"),
)

# Fangida 附加命令（不在 Hex-Rays 键位表中，单独列出，IDA_COMMANDS 保持原样）：
# 为没有伪 C 的当前函数在后台按需生成伪代码（F5 只浏览已有结果）。
PSEUDOCODE_COMMANDS: tuple[Command, ...] = (
    Command("generate_pseudocode", "生成当前函数伪代码", ("<Control-F5>", "<Shift-F5>")),
)


class CommandRegistry:
    """显式登记真实 GUI 动作，统一判断可用状态并执行。

    handler 可为零参数函数，或接收一个可选 event 参数的函数。菜单调用时
    event 为 None；键盘调用时为 Tk 事件。enabled 为零参数状态谓词。
    """

    def __init__(self) -> None:
        self._commands: dict[str, Command] = {}
        self._handlers: dict[str, Callable[[Any], Any]] = {}
        self._enabled: dict[str, Callable[[], bool]] = {}

    def register(self, command: Command, handler: Callable[..., Any],
                 enabled: Callable[[], bool] | None = None) -> None:
        if command.id in self._commands:
            raise ValueError(f"命令已登记：{command.id}")
        if not callable(handler) or (enabled is not None and not callable(enabled)):
            raise TypeError("命令处理器和可用状态必须可调用")
        # 在登记时决定参数形态，避免捕获 handler 内部 TypeError 后重复执行。
        try:
            handler_signature = signature(handler)
        except (TypeError, ValueError):
            adapted = lambda event: handler(event)
        else:
            try:
                handler_signature.bind(None)
            except TypeError:
                try:
                    handler_signature.bind()
                except TypeError as exc:
                    raise TypeError("命令处理器须接受零参数或一个 event 参数") from exc
                adapted = lambda _event: handler()
            else:
                adapted = lambda event: handler(event)
        self._commands[command.id] = command
        self._handlers[command.id] = adapted
        self._enabled[command.id] = enabled if enabled is not None else lambda: True

    def get(self, command_id: str) -> Command | None:
        return self._commands.get(command_id)

    def commands(self) -> tuple[Command, ...]:
        return tuple(self._commands.values())

    def is_enabled(self, command_id: str) -> bool:
        predicate = self._enabled.get(command_id)
        return bool(predicate()) if predicate is not None else False

    def execute(self, command_id: str, event: Any = None) -> bool:
        if not self.is_enabled(command_id):
            return False
        self._handlers[command_id](event)
        return True
