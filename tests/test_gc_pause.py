"""批量构建期间暂停自动 GC：嵌套、跨线程、宿主已关闭 GC、环境变量开关与异常退出。"""
from __future__ import annotations

import gc
import os
import threading
import unittest
from unittest.mock import patch

from fangida._gc import bulk_allocation


class GcPauseTests(unittest.TestCase):
    def setUp(self):
        self._was_enabled = gc.isenabled()
        gc.enable()

    def tearDown(self):
        (gc.enable if self._was_enabled else gc.disable)()

    def test_pauses_inside_and_restores_after(self):
        with bulk_allocation():
            self.assertFalse(gc.isenabled())
            with bulk_allocation():
                self.assertFalse(gc.isenabled())
            self.assertFalse(gc.isenabled(), "内层退出不能提前恢复 GC")
        self.assertTrue(gc.isenabled())

    def test_restores_after_exception(self):
        with self.assertRaises(RuntimeError):
            with bulk_allocation():
                raise RuntimeError("boom")
        self.assertTrue(gc.isenabled())

    def test_host_disabled_gc_stays_disabled(self):
        gc.disable()
        with bulk_allocation():
            self.assertFalse(gc.isenabled())
        self.assertFalse(gc.isenabled(), "宿主自己关闭的 GC 不能被打开")

    def test_environment_switch_disables_the_pause(self):
        with patch.dict(os.environ, {"FANGIDA_GC_PAUSE": "0"}):
            with bulk_allocation():
                self.assertTrue(gc.isenabled())
        self.assertTrue(gc.isenabled())

    def test_overlapping_threads_restore_only_after_the_last_exit(self):
        first_inside, release_first, second_done = threading.Event(), threading.Event(), threading.Event()
        observed = []

        def first():
            with bulk_allocation():
                first_inside.set()
                release_first.wait(5)

        def second():
            first_inside.wait(5)
            with bulk_allocation():
                pass
            observed.append(gc.isenabled())  # 第一个线程仍在批量阶段内
            second_done.set()

        threads = [threading.Thread(target=first), threading.Thread(target=second)]
        for thread in threads:
            thread.start()
        second_done.wait(5)
        release_first.set()
        for thread in threads:
            thread.join(5)
        self.assertEqual(observed, [False])
        self.assertTrue(gc.isenabled())


if __name__ == "__main__":
    unittest.main()
