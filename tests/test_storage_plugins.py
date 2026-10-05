"""Independent, lazy persistence plugins and deterministic cleanup."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
import unittest

from fangida.plugins import manager as plugin_manager
from fangida.plugins.interfaces import StoragePlugin
from fangida.plugins.manager import PluginManager
from fangida.storage import database_session


class Provider:
    name, version = "custom_storage", "1.0"

    def __init__(self):
        self.database = SimpleNamespace(path=Path("custom.fdb"), read_only=True, close=Mock())
        self.teardown = Mock()

    def capabilities(self):
        return ("analysis_database",)

    def open_database(self, path, *, read_only=False, create=False):
        return self.database


class StoragePluginTests(unittest.TestCase):
    def test_registration_is_lazy_and_does_not_change_analysis_routes(self):
        manager = PluginManager()
        factory = Mock(side_effect=Provider)
        with patch.object(plugin_manager, "import_module") as importer:
            manager.register_storage("custom_storage", factory)
            self.assertEqual(manager.route("elf"), ("kkagent", "analyze"))
            self.assertEqual(manager.route("apk"), ("apk_analyzer", "parse"))
            factory.assert_not_called()
            importer.assert_not_called()
            provider = manager.load_storage("custom_storage")
            self.assertIsInstance(provider, StoragePlugin)
            self.assertIs(provider, manager.load_storage("custom_storage"))
            self.assertEqual(manager._loaded, {})
            factory.assert_called_once()
        manager.teardown()
        provider.teardown.assert_called_once()

    def test_storage_and_analyzer_names_cannot_collide(self):
        manager = PluginManager()
        for name in ("kkagent", "apk_analyzer", "sqlite_storage"):
            with self.assertRaisesRegex(ValueError, "already registered"):
                manager.register_storage(name, Provider)
        manager.register_storage("custom_storage", Provider)
        with self.assertRaisesRegex(ValueError, "already registered"):
            manager.register("custom_storage", lambda: None)
        with self.assertRaisesRegex(ValueError, "already registered"):
            manager.register("sqlite_storage", lambda: None)
        with self.assertRaisesRegex(ValueError, "Unknown plugin"):
            manager.load("custom_storage")
        with self.assertRaisesRegex(ValueError, "Unknown storage"):
            manager.load_storage("kkagent")

    def test_concurrent_load_creates_one_storage_provider(self):
        manager = PluginManager()
        factory = Mock(side_effect=Provider)
        manager.register_storage("custom_storage", factory)
        with ThreadPoolExecutor(max_workers=8) as pool:
            providers = list(pool.map(lambda _: manager.load_storage("custom_storage"), range(16)))
        self.assertTrue(all(provider is providers[0] for provider in providers))
        factory.assert_called_once()
        manager.teardown()

    def test_default_provider_loads_only_storage_module(self):
        manager = PluginManager()
        provider = Provider()
        with patch.object(plugin_manager, "import_module",
                          return_value=SimpleNamespace(PluginImpl=lambda: provider)) as importer:
            self.assertIs(manager.load_storage(), provider)
            importer.assert_called_once_with("fangida.plugins.sqlite_storage")
        manager.teardown()

    def test_bad_factory_does_not_enter_the_loaded_registry(self):
        manager = PluginManager()
        manager.register_storage("bad", lambda: object())
        with self.assertRaisesRegex(TypeError, "storage protocol"):
            manager.load_storage("bad")
        self.assertEqual(manager._storage_loaded, {})

    def test_teardown_cleans_both_roles_even_when_one_fails(self):
        manager = PluginManager()
        analyzer = SimpleNamespace(teardown=Mock(side_effect=RuntimeError("analyzer failed")))
        provider = Provider()
        manager.register("custom_analyzer", lambda: analyzer)
        manager.register_storage("custom_storage", lambda: provider)
        manager.load("custom_analyzer")
        manager.load_storage("custom_storage")
        with self.assertRaisesRegex(RuntimeError, "analyzer failed"):
            manager.teardown()
        provider.teardown.assert_called_once()
        self.assertEqual(manager._storage_loaded, {})
        self.assertEqual(manager._loaded, {})

    def test_context_closes_database_but_preserves_supplied_manager(self):
        manager = PluginManager()
        provider = Provider()
        manager.register_storage("custom_storage", lambda: provider)
        with self.assertRaisesRegex(ValueError, "read failed"):
            with database_session("custom.fdb", manager=manager, storage_plugin="custom_storage"):
                raise ValueError("read failed")
        provider.database.close.assert_called_once()
        provider.teardown.assert_not_called()
        manager.teardown()
        provider.teardown.assert_called_once()

    def test_context_tears_down_temporary_manager_after_open_failure(self):
        registry = Mock()
        registry.load_storage.side_effect = ValueError("cannot load")
        with patch("fangida.storage.PluginManager", return_value=registry):
            with self.assertRaisesRegex(ValueError, "cannot load"):
                with database_session("missing.fdb"):
                    self.fail("opening should have failed")
        registry.teardown.assert_called_once()


if __name__ == "__main__":
    unittest.main()
