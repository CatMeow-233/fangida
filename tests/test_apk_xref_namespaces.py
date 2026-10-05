"""地址筛选必须同时匹配端点的成员与地址空间。"""
import unittest
from fangida.api import AnalysisView
from fangida.scripts import ScriptContext
from fangida.models import AnalysisResult
from fangida.mcp_server import McpServer


def result():
    return AnalysisResult("sample.apk", "apk", "apk_analyzer", "ok", xrefs=[
        {"src": 10, "dst": 20, "src_source": "classes.dex", "dst_source": "classes2.dex",
         "address_space": "file_offset", "kind": "call"},
        {"src": 10, "dst": 20, "src_source": "classes2.dex", "dst_source": "classes.dex",
         "address_space": "file_offset", "kind": "string"},
        {"src": 10, "dst": 20, "source": "lib/x.so", "address_space": "virtual_address", "kind": "data"}])


class XrefNamespaceTests(unittest.TestCase):
    def test_old_queries_return_all_and_optional_filters_match_same_endpoint(self):
        for interface in (AnalysisView(result()), ScriptContext(result())):
            self.assertEqual(len(interface.xrefs(10)), 3)
            self.assertEqual([ref["kind"] for ref in interface.xrefs(10, source="classes.dex")], ["call"])
            self.assertEqual([ref["kind"] for ref in interface.xrefs(20, source="classes.dex")], ["string"])
            self.assertEqual(len(interface.xrefs(address_space="file_offset")), 2)
            self.assertEqual(interface.xrefs(10, source="classes.dex", address_space="virtual_address"), [])

    def test_mcp_source_is_queried_endpoint_member(self):
        server = McpServer()
        try:
            server._snapshots["s"] = result().to_dict()
            response = server.call_tool("xref_query", {"handle": "s", "address": 20, "direction": "to",
                "source": "classes.dex", "address_space": "file_offset"})
            self.assertFalse(response.get("isError"), response)
            self.assertEqual([ref["kind"] for ref in response["structuredContent"]["items"]], ["string"])
            response = server.call_tool("xref_query", {"handle": "s", "address": 10, "source": 1})
            self.assertTrue(response["isError"])
        finally:
            server.close()
