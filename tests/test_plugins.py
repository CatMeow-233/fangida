import json
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fangida.models import AnalysisResult, AnalysisTask
from fangida.plugins import manager as plugin_manager
from fangida.plugins.interfaces import Plugin
from fangida.plugins.manager import PluginManager


class SamplePlugin:
    name = "custom"
    version = "1.0"

    def capabilities(self):
        return ("custom-format",)

    def analyze(self, task):
        return AnalysisResult(task.path, task.kind, self.name, "partial")

    def teardown(self):
        pass


class PluginRegistrationTests(unittest.TestCase):
    def test_registration_and_route_do_not_import_or_initialize(self):
        manager = PluginManager()
        factory = Mock(side_effect=SamplePlugin)
        with patch("fangida.plugins.manager.import_module") as importer:
            manager.register("custom", factory, kinds=("custom-format",), pool="parse")
            self.assertEqual(manager.route("custom-format"), ("custom", "parse"))
            self.assertEqual(manager.route("apk"), ("apk_analyzer", "parse"))
            factory.assert_not_called()
            importer.assert_not_called()
            plugin = manager.load("custom")
            self.assertIs(plugin, manager.load("custom"))
            factory.assert_called_once_with()
            importer.assert_not_called()
        self.assertIsInstance(plugin, Plugin)
        manager.teardown()

    def test_explicit_registration_is_per_manager(self):
        manager = PluginManager()
        other = PluginManager()
        manager.register("custom", SamplePlugin, kinds=("custom-format",))
        self.assertEqual(manager.route("custom-format"), ("custom", "analyze"))
        self.assertEqual(other.route("custom-format"), ("kkagent", "analyze"))
        self.assertNotIn("custom", plugin_manager.MODULES)
        with self.assertRaisesRegex(ValueError, "Unknown plugin"):
            other.load("custom")

    def test_concurrent_first_load_initializes_custom_plugin_once(self):
        manager = PluginManager()
        calls = []

        def factory():
            calls.append("created")
            time.sleep(0.02)
            return SamplePlugin()

        manager.register("custom", factory)
        with ThreadPoolExecutor(max_workers=8) as executor:
            plugins = list(executor.map(manager.load, ["custom"] * 16))
        self.assertEqual(calls, ["created"])
        self.assertTrue(all(plugin is plugins[0] for plugin in plugins))
        manager.teardown()

    def test_builtin_modules_and_import_patch_keep_legacy_behavior(self):
        manager = PluginManager()
        plugin = SamplePlugin()
        with patch("fangida.plugins.manager.import_module",
                   return_value=SimpleNamespace(PluginImpl=lambda: plugin)) as importer:
            self.assertIs(manager.load("kkagent"), plugin)
            self.assertIs(manager.load("kkagent"), plugin)
            importer.assert_called_once_with(plugin_manager.MODULES["kkagent"])
        manager.teardown()
        with patch.dict(plugin_manager.MODULES, {"legacy_extra": "legacy.module"}):
            with patch("fangida.plugins.manager.import_module",
                       return_value=SimpleNamespace(PluginImpl=SamplePlugin)) as importer:
                self.assertIsInstance(manager.load("legacy_extra"), SamplePlugin)
                importer.assert_called_once_with("legacy.module")
            manager.teardown()
        self.assertIs(plugin_manager.Plugin, Plugin)

    def test_default_routes_and_unknown_fallback(self):
        manager = PluginManager()
        for kind in ("apk", "dex", "jar", "class"):
            self.assertEqual(manager.route(kind), ("apk_analyzer", "parse"))
        for kind in ("elf", "pe", "macho", "unknown", "unregistered-format"):
            self.assertEqual(manager.route(kind), ("kkagent", "analyze"))

    def test_duplicate_names_and_routes_are_rejected_atomically(self):
        manager = PluginManager()
        manager.register("custom", SamplePlugin, kinds=("custom-format",))
        for name in ("kkagent", "apk_analyzer", "custom"):
            with self.assertRaisesRegex(ValueError, "already registered or loaded"):
                manager.register(name, SamplePlugin)
        for existing in ("apk", "elf", "custom-format"):
            with self.assertRaisesRegex(ValueError, "route already registered"):
                manager.register("rejected", SamplePlugin, kinds=("new-format", existing))
            self.assertEqual(manager.route("new-format"), ("kkagent", "analyze"))
            with self.assertRaisesRegex(ValueError, "Unknown plugin"):
                manager.load("rejected")

    def test_opt_in_route_replacement_requires_unloaded_previous_plugin(self):
        manager = PluginManager()
        manager.register("custom_apk", SamplePlugin, kinds=("apk",), pool="native",
                         replace_routes=True)
        self.assertEqual(manager.route("apk"), ("custom_apk", "native"))
        self.assertEqual(manager.route("dex"), ("apk_analyzer", "parse"))
        manager.load("custom_apk")
        with self.assertRaisesRegex(ValueError, "loaded plugin route"):
            manager.register("replacement", SamplePlugin, kinds=("apk",),
                             replace_routes=True)
        with self.assertRaisesRegex(ValueError, "already registered or loaded"):
            manager.register("custom_apk", SamplePlugin, replace_routes=True)
        with patch("fangida.plugins.manager.import_module",
                   return_value=SimpleNamespace(PluginImpl=SamplePlugin)):
            manager.load("kkagent")
        with self.assertRaisesRegex(ValueError, "loaded plugin route"):
            manager.register("replacement", SamplePlugin, kinds=("elf",),
                             replace_routes=True)
        manager.teardown()

    def test_invalid_registration_does_not_mutate_manager(self):
        invalid = [
            (("", SamplePlugin), {}, ValueError),
            (("custom", object()), {}, TypeError),
            (("custom", SamplePlugin), {"kinds": "custom-format"}, TypeError),
            (("custom", SamplePlugin), {"kinds": ("",)}, ValueError),
            (("custom", SamplePlugin), {"kinds": (1,)}, ValueError),
            (("custom", SamplePlugin), {"pool": "unbounded"}, ValueError),
            (("custom", SamplePlugin), {"replace_routes": 1}, TypeError),
        ]
        for args, kwargs, error in invalid:
            with self.subTest(args=args, kwargs=kwargs):
                manager = PluginManager()
                with self.assertRaises(error):
                    manager.register(*args, **kwargs)
                with self.assertRaises(ValueError):
                    manager.load("custom")
        for kind in ("", "  ", None, 1):
            with self.assertRaises(ValueError):
                PluginManager().route(kind)

    def test_factory_failure_is_visible_and_can_be_retried(self):
        manager = PluginManager()
        plugin = SamplePlugin()
        factory = Mock(side_effect=[RuntimeError("startup failed"), plugin])
        manager.register("custom", factory)
        with self.assertRaisesRegex(RuntimeError, "startup failed"):
            manager.load("custom")
        self.assertIs(manager.load("custom"), plugin)
        self.assertEqual(factory.call_count, 2)
        manager.teardown()

    def test_teardown_releases_other_plugins_then_raises_first_error(self):
        manager = PluginManager()
        calls = []
        first_error = RuntimeError("first cleanup failure")

        def factory(name, error=None):
            plugin = SamplePlugin()

            def teardown():
                calls.append(name)
                if error is not None:
                    raise error

            plugin.teardown = teardown
            return plugin

        manager.register("first", lambda: factory("first", first_error))
        manager.register("second", lambda: factory("second"))
        manager.register("third", lambda: factory("third", ValueError("later failure")))
        original = [manager.load(name) for name in ("first", "second", "third")]
        with self.assertRaises(RuntimeError) as caught:
            manager.teardown()
        self.assertIs(caught.exception, first_error)
        self.assertEqual(calls, ["first", "second", "third"])
        manager.teardown()
        self.assertEqual(calls, ["first", "second", "third"])
        self.assertIsNot(manager.load("second"), original[1])
        manager.teardown()

    def test_legacy_analyze_and_pre_dispatch_cancellation(self):
        manager = PluginManager()
        factory = Mock(side_effect=SamplePlugin)
        manager.register("custom", factory)
        cancel = Event()
        cancel.set()
        task = AnalysisTask("sample", "custom-format")
        cancelled = manager.analyze("custom", task, cancel=cancel)
        self.assertEqual(cancelled.status, "error")
        factory.assert_not_called()
        cancel.clear()
        result = manager.analyze("custom", task, lambda _: None, cancel)
        self.assertEqual((result.kind, result.analyzer), ("custom-format", "custom"))
        factory.assert_called_once_with()
        manager.teardown()

    def test_schema_accepts_custom_and_all_previous_plugin_kind_names(self):
        path = Path(__file__).resolve().parents[1] / "schemas" / "analysis-result.schema.json"
        properties = json.loads(path.read_text(encoding="utf-8"))["properties"]
        for field, values in (
            ("kind", ("elf", "pe", "macho", "apk", "dex", "jar", "class", "unknown", "custom-format")),
            ("analyzer", ("kkagent", "apk_analyzer", "custom")),
        ):
            self.assertEqual(properties[field], {"type": "string", "minLength": 1})
            for value in values:
                self.assertIsInstance(value, str)
                self.assertGreaterEqual(len(value), properties[field]["minLength"])


if __name__ == "__main__":
    unittest.main()
