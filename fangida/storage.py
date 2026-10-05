"""Storage plugin access and errors, independent of analysis dispatch."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .plugins.interfaces import STORAGE_API_VERSION, StorageDatabase, StoragePlugin
from .plugins.manager import PluginManager
from .project import ProjectError, ProjectSchemaError

DEFAULT_STORAGE_PLUGIN = "sqlite_storage"


class StorageError(ProjectError):
    """A storage provider could not read or write an analysis database."""


class StorageSchemaError(StorageError, ProjectSchemaError):
    """The database has an incompatible storage format or schema."""


@contextmanager
def database_session(path: str | Path, *, read_only: bool = True,
                     create: bool = False, manager: PluginManager | None = None,
                     storage_plugin: str = DEFAULT_STORAGE_PLUGIN
                     ) -> Iterator[StorageDatabase]:
    """Open an explicit database and close it deterministically.

    A supplied manager remains owned by its caller; a temporary manager and
    its storage provider are torn down even when opening or reading fails.
    """
    own_manager = manager is None
    registry = manager if manager is not None else PluginManager()
    database: StorageDatabase | None = None
    try:
        database = registry.load_storage(storage_plugin).open_database(
            path, read_only=read_only, create=create)
        yield database
    finally:
        try:
            if database is not None:
                database.close()
        finally:
            if own_manager:
                registry.teardown()


__all__ = ["StorageDatabase", "StoragePlugin", "STORAGE_API_VERSION",
           "StorageError", "StorageSchemaError", "DEFAULT_STORAGE_PLUGIN", "database_session"]
