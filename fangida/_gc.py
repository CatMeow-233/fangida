"""批量构建大型分析结果期间暂停 Python 的自动循环垃圾回收。

完整分析会一次性创建数百万个长期存活的 dict/list（指令、块、xref、表格行）。
CPython 的分代 GC 在此期间反复触发，而全代回收每次都要遍历全部已跟踪对象，
却几乎回收不到东西：在 87 万条指令的样本上它占了分析与 GUI 准备总耗时的约 25%。

``bulk_allocation()`` 只暂停“自动触发”的循环回收：引用计数照常即时释放绝大多数
对象，退出时恢复进入前的 GC 状态，之后的回收会处理期间产生的少量循环垃圾。
多个线程或嵌套调用共享一个计数，最后一个退出者才恢复 GC，不会提前打开或误开
宿主程序自己关闭的 GC。设置环境变量 ``FANGIDA_GC_PAUSE=0`` 可完全停用此行为。
"""
from __future__ import annotations

import gc
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager

_lock = threading.Lock()
_depth = 0
_restore = False


def enabled() -> bool:
    """是否允许暂停自动 GC（环境变量每次读取，便于宿主程序运行时切换）。"""
    return os.environ.get("FANGIDA_GC_PAUSE", "1").strip().lower() not in {"0", "false", "no", "off"}


@contextmanager
def bulk_allocation() -> Iterator[None]:
    """在 with 块内暂停自动循环 GC；可嵌套、可跨线程并发使用。"""
    global _depth, _restore
    if not enabled():
        yield
        return
    with _lock:
        if _depth == 0:
            # 只记录最外层进入时的状态：宿主已关闭 GC 时退出后仍保持关闭。
            _restore = gc.isenabled()
            gc.disable()
        _depth += 1
    try:
        yield
    finally:
        with _lock:
            _depth -= 1
            if _depth == 0 and _restore:
                # 批量阶段新建的对象全部还在最年轻的一代：直接恢复 GC 会立刻触发一次遍历它们
                # 全部的回收（大文件约 0.5 秒）。先 freeze 再 unfreeze，把它们整体移入最老一代，
                # 不扫描；其中少量循环垃圾在之后的完整回收中照常清理，不会泄漏。
                gc.freeze()
                gc.unfreeze()
                gc.enable()
