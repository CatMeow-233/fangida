"""测试速度分级。

设置环境变量 FANGIDA_QUICK_TESTS=1 时跳过标记为慢的用例（真实样本全量扫描、
编译运行硬件对照等），用于日常快速回归；CI 与提交前仍应跑全量。
线程身份、串行/并行路径等价类测试不得标记为慢（见 AGENTS.md 第 5 条）。
"""
from __future__ import annotations

import os
import unittest

QUICK = os.environ.get("FANGIDA_QUICK_TESTS", "").strip().lower() not in ("", "0", "false", "no")


def slow(reason: str):
    """标记慢测试；可装饰测试方法或整个 TestCase 类（类级跳过同时省掉 setUpClass）。"""
    return unittest.skipIf(QUICK, f"慢测试：{reason}（FANGIDA_QUICK_TESTS=1 时跳过）")
