"""MCP stdio 服务的拆分实现；公开入口与全部旧名字仍由 fangida.mcp_server 门面提供。

子模块里凡是原先在 mcp_server 模块全局中查找的名字（导入的服务、存储、复制与句柄
生成函数、常量、辅助函数和类），一律在调用时经 _facade() 向门面查找，因此对
fangida.mcp_server 上名字的补丁与拆分前一样生效。json、re、sys 等标准库模块对象是
共享的，直接导入即可；对其属性的补丁（例如 sys.stdin）本来就对所有模块可见。
"""
from __future__ import annotations

import sys
from types import ModuleType

_FACADE_NAME = "fangida.mcp_server"


def _facade() -> ModuleType:
    """返回兼容门面模块；只在调用时查找，避免导入期循环并让门面上的补丁生效。"""
    module = sys.modules.get(_FACADE_NAME)
    if module is None:
        # 直接导入子模块或以 -m 运行门面时，门面尚未以包路径登记，按需导入一次。
        from .. import mcp_server as module
    return module
