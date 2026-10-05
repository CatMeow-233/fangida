"""Capstone 不可用时，内置 NativeDecoder 的 objdump 回退在多区域下仍并行解码。

full_decode 的窗口互斥锁只针对进程内 Capstone 快路径（GIL 下纯 CPU 绑定）；
objdump 回退是子进程 I/O，可真正并行，加锁只会把多个区域串行化。
这里让两个区域的首次渲染在 Barrier(2) 上会合：若窗口被串行化，持锁线程会在
屏障上超时，BrokenBarrierError 被记录为 "Processor decode failed" 警告。
渲染函数被替换，因此不依赖本机安装 objdump。
"""
from __future__ import annotations

import threading
import unittest
from unittest.mock import patch

from fangida.loaders.models import BinaryImage
from fangida.processors.full_decode import stream_decode_regions


class ObjdumpParallelTests(unittest.TestCase):
    def test_objdump_fallback_regions_still_decode_concurrently(self) -> None:
        gate = threading.Barrier(2, timeout=5)
        lock = threading.Lock()
        # 用 Thread 对象而非 get_ident()：ident 可能被先后存在的线程复用。
        arrived: set[threading.Thread] = set()

        def render(code: bytes, address: int, architecture: str) -> tuple[str, str]:
            thread = threading.current_thread()
            with lock:
                first = thread not in arrived
                arrived.add(thread)
            if first:
                gate.wait()
            return "\n".join(f"{address + n:x}: c3  ret" for n in range(len(code))), "gnu"

        data = b"\xc3" * 64
        image = BinaryImage("elf", "x86_64", 64, "little", sections=[
            {"name": f".text{n}", "address": 0x1000 * (n + 1), "offset": n * 32,
             "size": 32, "executable": True}
            for n in range(2)])
        with patch.dict("sys.modules", {"capstone": None}), \
                patch("fangida.processors.decoder.disassemble_bytes", side_effect=render):
            records, coverage, warnings = stream_decode_regions(data, image, workers=2)
        self.assertEqual({item["engine"] for item in coverage}, {"objdump"})
        self.assertFalse(any("decode failed" in warning for warning in warnings), warnings)
        self.assertEqual(len(arrived), 2)
        self.assertFalse(gate.broken)
        self.assertEqual(len(records), 64)
        self.assertEqual([item["instruction_count"] for item in coverage], [32, 32])


if __name__ == "__main__":
    unittest.main()
