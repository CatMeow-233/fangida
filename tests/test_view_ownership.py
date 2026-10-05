"""视图快照的接管边界与有序反汇编索引：只在内置存储/私有完整结果上省掉深拷贝，行为与旧实现一致。"""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import random
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, create_autospec, patch

from fangida import api
from fangida.api import AnalysisView, open_database
from fangida.models import AnalysisResult
from fangida.plugins.sqlite_storage import SQLiteAnalysisDatabase
from fangida.settings import Settings
from fangida.tui import browse
from fangida.ui import main as cli_main


def _legacy_disassembly(view: AnalysisView, start, limit=100):
    """改动前 AnalysisView.disassembly 的冻结副本（每页重建并排序全部记录）。"""
    snapshot = view._snapshot
    if type(start) is not int or start < 0:
        raise ValueError("start must be a non-negative integer")
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    indexed = {}
    def collect(records, source=""):
        if not isinstance(records, list):
            return
        for instruction in records:
            if not isinstance(instruction, dict):
                continue
            address = instruction.get("addr", instruction.get("address", instruction.get("offset")))
            if type(address) is not int or address < start:
                continue
            record = dict(instruction)
            if source and "source" not in record:
                record["source"] = source
            indexed[(str(record.get("source", "")), address)] = record
    collect(snapshot["metadata"].get("disassembly"))
    collect(snapshot["metadata"].get("full_disassembly"))
    for function in snapshot["functions"]:
        if not isinstance(function, dict):
            continue
        source = str(function.get("source", "")) if snapshot["kind"] in {"apk", "dex", "jar", "class"} else ""
        collect(function.get("disassembly"), source)
        for block in function.get("blocks", []):
            if isinstance(block, dict):
                collect(block.get("instructions"), source)
    records = sorted(indexed.values(), key=lambda item: (int(item.get("addr", item.get("address", item.get("offset", 0)))), str(item.get("source", ""))))
    return deepcopy(records[:limit])


def _instruction(address, mnemonic="nop", **extra):
    return {"addr": address, "size": 1, "mnemonic": mnemonic, "operands": ["eax"],
            "branch_info": {"targets": []}, **extra}


def _full_result(path="sample.elf", count=40) -> AnalysisResult:
    shared = {"engine": "capstone"}
    instructions = [_instruction(0x1000 + index * 2, arch_meta=shared) for index in range(count)]
    return AnalysisResult(
        path, "elf", "kkagent", "partial",
        metadata={"full_disassembly": instructions, "disassembly": [_instruction(0x1000, "entry")],
                  "full_analysis": {"enabled": True}, "sections": [{"name": ".text"}]},
        functions=[{"name": "main", "start": 0x1000,
                    "blocks": [{"start": 0x1000, "instructions": instructions[:10]},
                               {"start": 0x2000, "instructions": [_instruction(0x2000, "ret")]}]},
                   {"name": "other", "start": 0x3000, "disassembly": [_instruction(0x3000, "call")]}],
        strings=[{"offset": 7, "value": "hello"}], imports=[{"name": "puts"}],
        xrefs=[{"src": 0x1000, "dst": 0x2000, "kind": "call"}],
        stats={"full_analysis": True}, warnings=["w"])


def _bytecode_snapshot() -> dict:
    """覆盖去重、source 注入/自带 source、address/offset 键、负地址、bool 地址等分支。"""
    rng = random.Random(5)
    functions = []
    for index in range(12):
        source = rng.choice(["La;", "Lb;", ""])
        blocks = [{"instructions": [
            {"offset": rng.randrange(0, 40), "op": "invoke", "n": index},
            {"address": rng.randrange(0, 40), "op": "move", "source": rng.choice(["Lc;", "La;"])},
            {"addr": rng.choice([-1, True, None, "7", rng.randrange(0, 40)]), "op": "odd"},
            "not a record", 17]} for _ in range(rng.randrange(1, 3))]
        functions.append({"name": f"f{index}", "source": source, "blocks": blocks,
                          "disassembly": [{"offset": rng.randrange(0, 40), "op": "listing"}]})
    functions.append("not a function")
    functions.append({"name": "no blocks"})
    return {"path": "classes.dex", "kind": "dex", "analyzer": "apk", "status": "partial",
            "schema_version": "1", "metadata": {
                "disassembly": [{"offset": index, "op": "entry"} for index in range(0, 40, 3)],
                "full_disassembly": "not a list"},
            "functions": functions, "stats": {}}


class DisassemblyIndexTests(unittest.TestCase):
    def assert_pages_match(self, view: AnalysisView, starts, limits=(1, 2, 7, 100, 1000)) -> None:
        for start in starts:
            for limit in limits:
                with self.subTest(start=start, limit=limit):
                    expected = _legacy_disassembly(view, start, limit)
                    actual = view.disassembly(start, limit)
                    self.assertEqual(json.dumps(actual), json.dumps(expected))
                    self.assertEqual(actual, expected)

    def test_full_and_partial_pages_match_legacy_scan(self):
        full = AnalysisView._from_owned_result(_full_result())
        partial = AnalysisView(AnalysisResult("x", "elf", "kkagent", "partial", metadata={
            "disassembly": [_instruction(0x10), _instruction(0x12)]}))
        for view in (full, partial, AnalysisView(_full_result())):
            addresses = sorted({record["addr"] for record in _legacy_disassembly(view, 0, 1000)})
            starts = {0, 1, addresses[-1], addresses[-1] + 1, 1 << 70}
            for address in addresses:
                starts.update((address - 1, address, address + 1))
            self.assert_pages_match(view, sorted(item for item in starts if item >= 0))

    def test_bytecode_sources_duplicates_and_odd_records_match_legacy_scan(self):
        view = AnalysisView.from_snapshot(_bytecode_snapshot())
        self.assert_pages_match(view, range(0, 45))
        self.assertIsNot(view._disassembly_cache, False)

    def test_non_plain_records_fall_back_to_the_legacy_scan(self):
        class Record(dict):
            pass
        cases = {
            "dict subclass": [Record(addr=4, mnemonic="sub"), _instruction(2)],
            "non-string source": [_instruction(4, source=7), _instruction(4, source="7"),
                                  _instruction(3, source=None)],
        }
        for name, records in cases.items():
            with self.subTest(name):
                view = AnalysisView._from_owned_snapshot({
                    "path": "x", "kind": "dex", "analyzer": "a", "status": "partial",
                    "schema_version": "1", "metadata": {"full_disassembly": records}})
                self.assert_pages_match(view, range(0, 6))
                self.assertIs(view._disassembly_cache, False)

    def test_argument_validation_and_errors_are_unchanged(self):
        view = AnalysisView._from_owned_result(_full_result())
        broken = AnalysisView._from_owned_snapshot({
            "path": "x", "kind": "elf", "analyzer": "a", "status": "partial", "schema_version": "1",
            "functions": [{"blocks": None}]})
        arguments = [(-1, 10), ("0", 10), (True, 10), (1.0, 10), (None, 10), (0, 0), (0, -5),
                     (0, 1001), (0, 10 ** 9), (0, 2.5), (0, None), (0, "5"), (0, True),
                     (1 << 70, 0), (5, 999.5)]
        for target in (view, broken):
            for start, limit in arguments:
                with self.subTest(target=target is view, start=start, limit=limit):
                    try:
                        expected = _legacy_disassembly(target, start, limit)
                    except Exception as error:  # noqa: BLE001 - 对比异常类型与消息
                        with self.assertRaises(type(error)) as caught:
                            target.disassembly(start, limit)
                        self.assertEqual(str(caught.exception), str(error))
                    else:
                        self.assertEqual(target.disassembly(start, limit), expected)
        self.assertIsNone(getattr(broken, "_disassembly_cache", None))

    def test_pages_are_isolated_copies_and_index_is_built_once(self):
        view = AnalysisView._from_owned_result(_full_result())
        baseline = view.snapshot()
        with patch.object(AnalysisView, "_build_disassembly_index", autospec=True,
                          side_effect=AnalysisView._build_disassembly_index) as build:
            first = view.disassembly(0x1000, 3)
            for start in range(0x1000, 0x1100, 7):
                view.disassembly(start, 5)
        build.assert_called_once()
        # 同一页内共享的嵌套对象在副本中仍共享（与旧实现的 deepcopy 一致），但与视图隔离。
        self.assertIs(first[1]["arch_meta"], first[2]["arch_meta"])
        legacy = _legacy_disassembly(view, 0x1000, 3)
        self.assertIs(legacy[1]["arch_meta"], legacy[2]["arch_meta"])
        first[1]["operands"].append("changed")
        first[1]["arch_meta"]["engine"] = "changed"
        first[2]["mnemonic"] = "changed"
        self.assertEqual(view.disassembly(0x1000, 3), _legacy_disassembly(view, 0x1000, 3))
        self.assertEqual(view.snapshot(), baseline)

    def test_public_getters_never_expose_the_indexed_graph(self):
        view = AnalysisView(_full_result())
        view.disassembly(0)
        view.functions()[0]["blocks"][0]["instructions"][0]["mnemonic"] = "changed"
        view.snapshot()["metadata"]["full_disassembly"][1]["addr"] = 1
        self.assertEqual(view.disassembly(0, 1000), _legacy_disassembly(view, 0, 1000))
        self.assertEqual(view.disassembly(0x1000, 1)[0]["mnemonic"], "nop")


class _FakeManager:
    """只提供 database_session 需要的 load_storage/teardown；数据库由测试给出。"""

    def __init__(self, database) -> None:
        self.database = database

    def load_storage(self, name):
        return SimpleNamespace(open_database=lambda *args, **kwargs: self.database)

    def teardown(self) -> None:
        pass


class _Declared:
    """声明可接管的第三方提供者：协议属性必须恰好为 True。"""
    fresh_snapshots = True

    def __init__(self, snapshot) -> None:
        self.snapshot = snapshot

    def get_snapshot(self, snapshot_id):
        return self.snapshot

    def close(self) -> None:
        pass


def _snapshot_dict() -> dict:
    return AnalysisView(_full_result()).snapshot()


class OpenDatabaseOwnershipTests(unittest.TestCase):
    def _saved(self, directory: str) -> Path:
        source = Path(directory) / "source.bin"
        source.write_bytes(b"\x7fELF bytes")
        path = Path(directory) / "saved.fdb"
        database = SQLiteAnalysisDatabase(path, create=True)
        try:
            database.save_analysis(source, _full_result(str(source)))
        finally:
            database.close()
        return path

    def test_builtin_storage_snapshot_is_owned_without_copy_and_stays_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._saved(directory)
            reader = SQLiteAnalysisDatabase(path, read_only=True)
            try:
                expected = reader.get_snapshot()
            finally:
                reader.close()
            with patch.object(AnalysisView, "from_snapshot", side_effect=AssertionError("copied")):
                first = open_database(path)
            second = open_database(path)
            self.assertEqual(first.snapshot(), expected)
            self.assertIsNot(first._snapshot, second._snapshot)
            first.functions()[0]["name"] = "changed"
            first.snapshot()["metadata"]["full_disassembly"][0]["mnemonic"] = "changed"
            first.disassembly(0)[0]["operands"].append("changed")
            self.assertEqual(first.snapshot(), second.snapshot())
            self.assertEqual(first.disassembly(0, 1000), _legacy_disassembly(first, 0, 1000))

    def test_mock_and_third_party_providers_are_still_copied(self):
        class Subclass(SQLiteAnalysisDatabase):
            """子类可能缓存快照，不继承可接管声明。"""
        with tempfile.TemporaryDirectory() as directory:
            path = self._saved(directory)
            subclass = Subclass(path, read_only=True)
            self.assertFalse(subclass.fresh_snapshots)
            self.assertTrue(SQLiteAnalysisDatabase(path, read_only=True).fresh_snapshots)
            view = open_database(path, manager=_FakeManager(subclass))
            self.assertEqual(view.functions()[0]["name"], "main")
        autospec = create_autospec(SQLiteAnalysisDatabase, instance=True)
        magic = MagicMock()
        truthy = SimpleNamespace(fresh_snapshots=1)
        for database in (autospec, magic, truthy):
            with self.subTest(database=type(database).__name__):
                supplied = _snapshot_dict()
                baseline = deepcopy(supplied)
                database.get_snapshot = lambda snapshot_id, supplied=supplied: supplied
                # 与既有审计测试相同：提供者在 close() 时清空自己持有的快照。
                database.close = lambda supplied=supplied: supplied.clear()
                view = open_database("unused.fdb", manager=_FakeManager(database))
                self.assertEqual(supplied, {})
                self.assertEqual(view.snapshot(), baseline)

    def test_declared_fresh_provider_and_non_dict_snapshots(self):
        supplied = _snapshot_dict()
        view = open_database("unused.fdb", manager=_FakeManager(_Declared(supplied)))
        self.assertIs(view._snapshot, supplied)
        class Mapping(dict):
            pass
        subclass_snapshot = Mapping(_snapshot_dict())
        view = open_database("unused.fdb", manager=_FakeManager(_Declared(subclass_snapshot)))
        self.assertIsNot(view._snapshot, subclass_snapshot)
        self.assertIs(type(view._snapshot), dict)


def _cli(arguments, *, result=None, view=None):
    output = io.StringIO()
    with patch("sys.argv", ["fangida", *arguments]), \
         patch("fangida.ui.AnalysisService") as service, \
         patch("fangida.ui.load_settings", return_value=Settings()), \
         redirect_stdout(output):
        if result is not None:
            service.return_value.__enter__.return_value.analyze.return_value = result
        if view is not None:
            with patch("fangida.ui.open_database", return_value=view):
                code = cli_main()
        else:
            code = cli_main()
    return code, output.getvalue()


class CliAndBrowserOwnershipTests(unittest.TestCase):
    def test_open_database_export_reads_internal_snapshot_without_copy(self):
        view = AnalysisView(_full_result())
        expected = "".join(json.JSONEncoder(indent=2, ensure_ascii=False)
                           .iterencode(view.snapshot())) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "导出.json"
            with patch.object(AnalysisView, "snapshot", side_effect=AssertionError("copied")):
                code, console = _cli(["--open-database", "saved.fdb", "--output", str(destination)],
                                     view=view)
            self.assertEqual(code, 0)
            self.assertEqual(destination.read_text(encoding="utf-8"), expected)
            self.assertEqual(json.loads(console)["output"], str(destination.resolve()))
        code, console = _cli(["--open-database", "saved.fdb"], view=view)
        self.assertEqual(console, "".join(json.JSONEncoder(indent=2, ensure_ascii=True)
                                          .iterencode(view.snapshot())) + "\n")

    def test_open_database_keeps_overridden_snapshot(self):
        class Filtered(AnalysisView):
            def snapshot(self):
                data = super().snapshot()
                data["warnings"] = ["filtered"]
                return data
        view = Filtered(_full_result())
        code, console = _cli(["--open-database", "saved.fdb"], view=view)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(console)["warnings"], ["filtered"])

    def test_full_interactive_hands_result_to_view_and_partial_still_copies(self):
        captured = []
        full = _full_result()
        partial = AnalysisResult("sample.elf", "elf", "kkagent", "partial",
                                 functions=[{"name": "main", "start": 1}])
        with patch("fangida.ui.browse", side_effect=captured.append):
            self.assertEqual(_cli(["sample.elf", "--full", "--interactive"], result=full)[0], 0)
            self.assertEqual(_cli(["sample.elf", "--interactive"], result=partial)[0], 0)
        owned, copied = captured
        self.assertIs(owned._snapshot["functions"], full.functions)
        self.assertEqual(owned.snapshot(), AnalysisView(full).snapshot())
        self.assertIsNot(copied._snapshot["functions"], partial.functions)
        self.assertEqual(copied.snapshot(), AnalysisView(partial).snapshot())

    def test_browse_reads_internal_snapshot_with_identical_output(self):
        class Copying(AnalysisView):
            """覆写 snapshot() 的视图走复制路径，作为旧行为的参照输出。"""
            def snapshot(self):
                return super().snapshot()
        commands = ["summary", "sections", "functions", "imports", "exports", "strings 1",
                    "strings 0", "disasm 3", "disasm x", "cfg", "xrefs", "pseudoc", "bogus",
                    "help", "", "quit"]
        result = _full_result()
        result.functions[0]["pseudoc"] = "int main() {}"
        result.metadata["entry_cfg"] = {"available": True, "blocks": [1]}
        view, reference = AnalysisView(result), Copying(result)
        baseline = view.snapshot()
        outputs = []
        for target in (view, reference):
            output = io.StringIO()
            with patch("builtins.input", side_effect=commands):
                if target is view:
                    with patch.object(AnalysisView, "snapshot", side_effect=AssertionError("copied")):
                        browse(target, output)
                else:
                    browse(target, output)
            outputs.append(output.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        self.assertIn('"pseudoc": "int main() {}"', outputs[0])
        self.assertEqual(view.snapshot(), baseline)

    def test_shared_snapshot_falls_back_for_foreign_views(self):
        stand_in = MagicMock()
        stand_in.snapshot.return_value = {"kind": "elf"}
        self.assertEqual(api._shared_snapshot(stand_in), {"kind": "elf"})
        spec = MagicMock(spec=AnalysisView)
        spec.snapshot.return_value = {"kind": "spec"}
        self.assertEqual(api._shared_snapshot(spec), {"kind": "spec"})
        view = AnalysisView(_full_result())
        self.assertIs(api._shared_snapshot(view), view._snapshot)


if __name__ == "__main__":
    unittest.main()
