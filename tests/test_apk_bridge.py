"""独立 APK Analyzer 的插件桥接、延迟加载及旧入口兼容。"""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from threading import Event
import time
import textwrap
import unittest
from unittest.mock import patch

from fangida.models import AnalysisTask
from fangida.plugins.apk_bridge import PluginImpl
from fangida.plugins.apk_bridge import runtime

PROJECT_ROOT=Path(__file__).resolve().parents[1]
BACKEND_ROOT=PROJECT_ROOT.parent/'apk-analyzer'
CONFIG_KEYS=('FANGIDA_APK_ANALYZER_PROJECT','FANGIDA_APK_ANALYZER_COMMAND')

def class_fixture() -> bytes:
    utf8=lambda text:b'\x01'+struct.pack('>H',len(text))+text
    entries=[utf8(b'BridgeClass'),b'\x07\x00\x01',utf8(b'java/lang/Object'),b'\x07\x00\x03',
             utf8(b'run'),utf8(b'()V'),utf8(b'Code')]
    code=b'\xb1'
    attribute=struct.pack('>HHI',0,0,len(code))+code+struct.pack('>HH',0,0)
    return (struct.pack('>IHHH',0xcafebabe,0,52,len(entries)+1)+b''.join(entries)+
            struct.pack('>HHHHH',0x21,2,4,0,0)+struct.pack('>H',1)+struct.pack('>HHHH',9,5,6,1)+
            struct.pack('>HI',7,len(attribute))+attribute+struct.pack('>H',0))

class ApkBridgeTests(unittest.TestCase):
    def run_fresh(self,script: str,*,environment=None):
        env={key:value for key,value in os.environ.items() if key not in CONFIG_KEYS}
        if environment: env.update(environment)
        process=subprocess.run([sys.executable,'-c',textwrap.dedent(script)],cwd=PROJECT_ROOT,
            env=env,capture_output=True,text=True,timeout=20)
        self.assertEqual(process.returncode,0,process.stderr)
        return json.loads(process.stdout)

    def test_plugin_load_does_not_import_backend_or_start_worker(self):
        payload=self.run_fresh('''
            import json,sys
            from unittest.mock import patch
            from fangida.plugins.manager import PluginManager
            with patch('subprocess.Popen',side_effect=AssertionError('load started a child')):
                manager=PluginManager()
                plugin=manager.load('apk_analyzer')
                assert plugin._client.pid is None
                manager.teardown()
            print(json.dumps({'backend_modules':[name for name in sys.modules if name=='apk_analyzer' or name.startswith('apk_analyzer.')]}))
        ''',environment={'FANGIDA_APK_ANALYZER_PROJECT':'/deliberately/missing/backend'})
        self.assertEqual(payload['backend_modules'],[])

    def test_analysis_uses_configured_backend_child_and_reaps_it(self):
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'with space.class';source.write_bytes(class_fixture())
            payload=self.run_fresh('''
                import json,os,sys
                from fangida.models import AnalysisTask
                from fangida.plugins.manager import PluginManager
                manager=PluginManager()
                plugin=manager.load('apk_analyzer')
                result=plugin.analyze(AnalysisTask(os.environ['BRIDGE_TEST_FILE'],'class',worker_timeout_seconds=10))
                child=plugin._client._process
                pid=plugin._client.pid
                manager.teardown()
                print(json.dumps({'status':result.status,'classes':result.metadata.get('class_count'),
                    'functions':len(result.functions),'child_pid':pid,'host_pid':os.getpid(),
                    'reaped':child is not None and child.poll() is not None,
                    'backend_modules':[name for name in sys.modules if name=='apk_analyzer' or name.startswith('apk_analyzer.')],
                    'warnings':result.warnings}))
            ''',environment={'FANGIDA_APK_ANALYZER_PROJECT':str(BACKEND_ROOT),'BRIDGE_TEST_FILE':str(source)})
        self.assertNotEqual(payload['status'],'error',payload['warnings'])
        self.assertEqual((payload['classes'],payload['functions']),(1,1))
        self.assertNotEqual(payload['child_pid'],payload['host_pid'])
        self.assertIsInstance(payload['child_pid'],int)
        self.assertTrue(payload['reaped'])
        self.assertEqual(payload['backend_modules'],[])

    def test_source_configuration_preserves_environment_and_paths_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix='apk backend ') as directory:
            path=Path(directory);(path/'apk_analyzer').mkdir();(path/'apk_analyzer'/'worker.py').write_text('')
            with patch.dict(os.environ,{'FANGIDA_APK_ANALYZER_PROJECT':str(path),'PYTHONPATH':'previous'},clear=True):
                command,environment=runtime.worker_launch()
            self.assertEqual(command,[sys.executable,'-m','apk_analyzer.worker'])
            self.assertEqual(environment['PYTHONPATH'],str(path.resolve())+os.pathsep+'previous')

    def test_installed_module_route_does_not_require_source_checkout(self):
        marker=object()
        with patch.dict(os.environ,{'PYTHONPATH':'existing'},clear=True),\
             patch.object(runtime,'project_directory',return_value=None),\
             patch.object(runtime.util,'find_spec',return_value=marker) as discover:
            command,environment=runtime.worker_launch()
        discover.assert_called_once_with('apk_analyzer')
        self.assertEqual(command,[sys.executable,'-m','apk_analyzer.worker'])
        self.assertEqual(environment['PYTHONPATH'],'existing')

    def test_missing_backend_returns_readable_plugin_error(self):
        with patch.dict(os.environ,{},clear=True),\
             patch.object(runtime,'project_directory',return_value=None),\
             patch.object(runtime.util,'find_spec',return_value=None):
            plugin=PluginImpl()
            try: result=plugin.analyze(AnalysisTask('not-opened.class','class'))
            finally: plugin.teardown()
        self.assertEqual(result.status,'error')
        self.assertTrue(any('独立项目' in warning and 'FANGIDA_APK_ANALYZER_PROJECT' in warning for warning in result.warnings))
        self.assertIsNone(plugin._client.pid)

    def test_invalid_explicit_backend_directory_returns_readable_error(self):
        with tempfile.TemporaryDirectory() as directory,\
             patch.dict(os.environ,{'FANGIDA_APK_ANALYZER_PROJECT':directory},clear=True):
            plugin=PluginImpl()
            try: result=plugin.analyze(AnalysisTask('not-opened.class','class'))
            finally: plugin.teardown()
        self.assertEqual(result.status,'error')
        self.assertTrue(any('FANGIDA_APK_ANALYZER_PROJECT' in warning for warning in result.warnings))

    def test_custom_command_argv_is_independent_of_backend_discovery(self):
        with patch.dict(os.environ,{'FANGIDA_APK_ANALYZER_COMMAND':'worker-program -m apk_analyzer.worker'},clear=True),\
             patch.object(runtime,'project_directory',side_effect=AssertionError('command override inspected source')):
            command,environment=runtime.worker_launch()
        self.assertEqual(command,['worker-program','-m','apk_analyzer.worker'])
        self.assertIsNone(environment)

    def test_json_argv_preserves_windows_paths_spaces_and_literal_arguments(self):
        expected=[r'C:\Program Files\Python\python.exe','-m','apk_analyzer.worker','literal argument with spaces']
        with patch.dict(os.environ,{'FANGIDA_APK_ANALYZER_COMMAND':json.dumps(expected)},clear=True):
            command,environment=runtime.worker_launch()
        self.assertEqual(command,expected)
        self.assertIsNone(environment)

    def test_invalid_json_command_returns_readable_error(self):
        for encoded in ('[]','[null]','[["nested"]]','[malformed'):
            with self.subTest(command=encoded),patch.dict(os.environ,{'FANGIDA_APK_ANALYZER_COMMAND':encoded},clear=True):
                plugin=PluginImpl()
                try: result=plugin.analyze(AnalysisTask('not-opened.class','class'))
                finally: plugin.teardown()
            self.assertEqual(result.status,'error')
            self.assertTrue(result.warnings)
            self.assertIsNone(plugin._client.pid)

    def test_cancelling_page_download_stops_next_page_and_releases_handle(self):
        from fangida.plugins.apk_bridge.ipc import IPCClient
        client=IPCClient();cancel=Event();methods=[]
        handle='a'*32
        def reply(method,params,*args):
            methods.append((method,params))
            if method=='analyze': return {'paged':True,'handle':handle,'pages':2,'size':2,'sha256':'b'*64}
            if method=='result_page':
                cancel.set()
                return {'index':0,'data':base64.b64encode(b'x').decode('ascii')}
            if method=='release_result': return True
            raise AssertionError(method)
        with patch.object(client,'_start'),patch.object(client,'_request',side_effect=reply):
            result=client.analyze(AnalysisTask('unused.class','class'),cancel=cancel)
        self.assertEqual(result.status,'error')
        self.assertTrue(any('cancelled' in warning for warning in result.warnings))
        self.assertEqual([method for method,_ in methods],['analyze','result_page','release_result'])
        self.assertEqual(methods[-1][1],{'handle':handle})

    def test_oversize_page_stops_at_descriptor_size_and_releases_handle(self):
        from fangida.plugins.apk_bridge.ipc import IPCClient,WorkerCrashed
        client=IPCClient();methods=[];handle='c'*32
        def reply(method,params,*args):
            methods.append((method,params))
            if method=='analyze': return {'paged':True,'handle':handle,'pages':3,'size':1,'sha256':'d'*64}
            if method=='result_page': return {'index':0,'data':base64.b64encode(b'xx').decode('ascii')}
            if method=='release_result': return True
            raise AssertionError(method)
        with patch.object(client,'_start'),patch.object(client,'_request',side_effect=reply):
            with self.assertRaisesRegex(WorkerCrashed,'exceed declared size'):
                client._analyze_once(AnalysisTask('unused.class','class'),time.monotonic()+3,None,None)
        self.assertEqual([method for method,_ in methods],['analyze','result_page','release_result'])
        self.assertEqual(methods[-1][1],{'handle':handle})

    def test_legacy_module_aliases_keep_monkeypatch_identity(self):
        payload=self.run_fresh('''
            import json
            from importlib import import_module
            pairs=(('dex_analyzer','analysis.dex_analyzer'),('dex_bytecode','analysis.dex_bytecode'),
                   ('jvm_analyzer','analysis.jvm_analyzer'),('jvm_bytecode','analysis.jvm_bytecode'),
                   ('kotlin_metadata','analysis.kotlin_metadata'),('pseudocode','analysis.pseudocode'),('worker','worker'))
            identities=[]
            for old,new in pairs:
                identities.append(import_module('fangida.core.apk_analyzer.'+old) is import_module('apk_analyzer.'+new))
            from fangida.core.apk_analyzer.ipc import IPCClient as old_client
            from fangida.plugins.apk_bridge.ipc import IPCClient as new_client
            print(json.dumps({'aliases':identities,'ipc_alias':old_client is new_client}))
        ''',environment={'FANGIDA_APK_ANALYZER_PROJECT':str(BACKEND_ROOT)})
        self.assertTrue(all(payload['aliases']))
        self.assertTrue(payload['ipc_alias'])
