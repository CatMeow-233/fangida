"""拆分后的 GUI 子模块经 fangida.gui 门面查找可替换的名字。

测试与既有调用方会对 fangida.gui 上的名字打补丁（如 _analyze_file、_prepare、
_verified_hex_source、AnalysisService、PluginManager、fingerprint、load_settings、launch）。
子模块不在顶层导入门面（否则循环导入），而是在调用时经 _gui() 取得门面模块再查找。
拆分前函数体里引用的每个原模块级名字（函数、类、常量，以及 Path、replace、
SourceChangedError 等导入的名字）都这样查找，因此对门面打的补丁或重新赋值仍作用于
搬走后的实现，与拆分前的行为一致。json、os、threading 等模块对象仍直接导入：它们与门面上
的是同一模块对象，对其属性的补丁（如 fangida.gui.threading.Thread）本就全局生效。
参数默认值、装饰器等在定义时求值的引用与拆分前一样只在导入时读取一次。
gui_modules 不直接导入 api、dispatcher、plugins 等分析实现，运行时需要的
AnalysisView、AnalysisService、PluginManager 等同样经门面取得；注解里用到的 AnalysisView
由门面在导入后注入 adapters、operations、browser_jobs，使 typing.get_type_hints 与拆分前一样可解析。
"""
from __future__ import annotations

import sys
from types import ModuleType


def _gui() -> ModuleType:
    """返回 fangida.gui 门面模块；对门面打的补丁在此生效。"""
    # 已导入时直接取 sys.modules（热路径上不经过导入机制）；否则按需导入门面。
    module = sys.modules.get("fangida.gui")
    if module is None:
        from .. import gui as module
    return module
