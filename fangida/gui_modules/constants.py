"""桌面浏览器的常量与表格列定义；由 fangida.gui 门面再导出。"""
from __future__ import annotations

import os


HEX_BYTES_PER_ROW = 16
HEX_PAGE_ROWS = 64
MAX_HEX_ROWS = 256
MAX_CFG_BLOCKS = 2000
TABLE_PAGE_ROWS = 1000
ANALYSIS_MODE_LABELS = {"standard": "常规分析", "fast": "快速分析", "full": "完整分析"}
# 打开文件对话框里启用多线程时的建议线程数（与配置默认值一致：不超过 4，且至少 2）。
DEFAULT_THREADS = min(12, max(2, (os.cpu_count() or 2) - 2))


# Each table keeps the original result records for the selection detail pane.
TABLE_COLUMNS: dict[str, tuple[tuple[str, str, int], ...]] = {
    "Sections": (("name", "Name", 170), ("address", "Address", 130),
                 ("offset", "File offset", 100), ("size", "Size", 90),
                 ("type", "Type", 110), ("executable", "Executable", 95)),
    "Functions": (("location", "Address / offset", 140), ("name", "Name", 260),
                  ("descriptor", "Descriptor", 200), ("size", "Size", 85),
                  ("source", "Source", 130)),
    "Disassembly": (("source", "Source", 180), ("addr", "Address", 140), ("mnemonic", "Mnemonic", 130),
                    ("operands", "Operands", 350), ("reads", "Reads", 170),
                    ("writes", "Writes", 170)),
    "Strings": (("offset", "File offset", 130), ("address", "Address", 140), ("length", "Length", 90),
                ("value", "Value", 550)),
    "Imports": (("address", "Address", 150), ("library", "Library", 190),
                ("name", "Name", 350), ("kind", "Kind", 120), ("source", "Source", 140)),
    "Exports": (("address", "Address", 150), ("name", "Name", 350),
                ("kind", "Kind", 120), ("source", "Source", 140)),
    "API Calls": (("source", "Source", 160), ("caller", "Caller", 220),
                  ("addr", "File offset", 120), ("opcode", "Opcode", 130),
                  ("target", "Target", 300)),
    "Pseudocode": (("name", "Function", 240), ("start", "Address", 130),
                   ("pseudoc_producer", "Producer", 100), ("pseudoc", "Pseudo-C", 550),
                   ("pseudoc_status", "状态", 70)),
    "Xrefs": (("src", "Source", 140), ("dst", "Target", 140),
              ("kind", "Kind", 100), ("confidence", "Confidence", 100),
              ("src_space", "Source space", 120), ("dst_space", "Target space", 120)),
}
# 伪代码标签页是代码视图：左侧列表只显示这些列，完整代码在右侧代码区。
# 其余列（含原 Pseudo-C 列）仍保留在 TABLE_COLUMNS 中供查找和旧代码路径使用。
PSEUDOCODE_LIST_COLUMNS = ("name", "start", "pseudoc_status")
_PSEUDOCODE_LIST_WIDTHS = {"name": 150, "start": 104, "pseudoc_status": 56}
