import json
import tempfile
import unittest
from pathlib import Path
from fangida.settings import load_settings
from fangida.resource_scheduler import ResourceScheduler

class SettingsTests(unittest.TestCase):
    def test_precedence_and_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "global.json").write_text(json.dumps({"io_threads": 3}))
            (base / ".fangida.yaml").write_text('{"io_threads": 4}')
            config = load_settings(base, base / "global.json", {"io_threads": 5})
            self.assertEqual(config.io_threads, 5)
            with self.assertRaises(ValueError):
                load_settings(base, base / "global.json", {"io_threads": 0})

    def test_scheduler(self) -> None:
        with ResourceScheduler(load_settings(session={"analyze_threads": 1})) as scheduler:
            self.assertEqual(scheduler.submit("analyze", lambda a: a * 2, 3).result(), 6)

    def test_semantic_threads_share_global_budget(self) -> None:
        settings = load_settings(session={"analyze_threads": 8, "semantic_threads": 4})
        with ResourceScheduler(settings) as scheduler:
            self.assertEqual(scheduler.semantic_workers, 4)
            self.assertEqual(scheduler.xref_workers, 1)
            self.assertEqual(scheduler._pool_threads["analyze"], 1)
            self.assertLessEqual((scheduler.semantic_workers + scheduler.xref_workers) *
                                 scheduler._pool_threads["analyze"], settings.analyze_threads)
        with ResourceScheduler(load_settings(session={"analyze_threads": 1,
                                              "semantic_threads": 4})) as scheduler:
            self.assertEqual(scheduler.semantic_workers, 1)
            self.assertEqual(scheduler.xref_workers, 0)
        with ResourceScheduler(load_settings(session={"analyze_threads": 2,
                                              "semantic_threads": 4})) as scheduler:
            self.assertEqual((scheduler.semantic_workers, scheduler.xref_workers), (1, 1))
        with self.assertRaises(ValueError):
            load_settings(session={"semantic_threads": 17})

    def test_schema_lists_every_setting_with_matching_bounds(self) -> None:
        # schema 设了 additionalProperties:false：漏掉字段会让合法配置被外部校验器拒绝。
        from dataclasses import fields
        from fangida.settings import Settings
        schema = json.loads((Path(__file__).resolve().parents[1] / "settings" / "settings.schema.json").read_text())
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(sorted(schema["properties"]), sorted(item.name for item in fields(Settings)))
        bounds = schema["properties"]["pseudoc_max_instructions"]
        self.assertEqual((bounds["minimum"], bounds["maximum"]), (1, 8192))
        for value, valid in ((1, True), (8192, True), (0, False), (8193, False)):
            with self.subTest(value=value):
                if valid:
                    self.assertEqual(load_settings(session={"pseudoc_max_instructions": value}).pseudoc_max_instructions, value)
                else:
                    with self.assertRaises(ValueError):
                        load_settings(session={"pseudoc_max_instructions": value})
