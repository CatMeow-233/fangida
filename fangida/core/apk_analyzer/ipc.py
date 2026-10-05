"""保留旧 IPC 导入路径，连接逻辑属于插件桥接层。"""
import sys
from ...plugins.apk_bridge import ipc as _implementation
sys.modules[__name__] = _implementation
