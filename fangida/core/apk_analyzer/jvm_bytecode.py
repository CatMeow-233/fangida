"""旧导入路径的兼容门面；实现属于独立 APK Analyzer 项目。"""
import sys
from ...plugins.apk_bridge.runtime import import_backend_module
_backend = import_backend_module('analysis.jvm_bytecode')
sys.modules[__name__] = _backend
