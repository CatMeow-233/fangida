"""Container registration, routing and compatibility without processor work."""
from __future__ import annotations

import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from fangida.core.kkagent import binary
from fangida.core.kkagent.test_native import elf64_with_symbols, macho64, pe64
from fangida.loaders import (
    BinaryFormatError, BinaryImage, ELFLoader, FormatProbe, Loader, LoaderMatch,
    LoaderRegistry, default_registry, identify_bytes, identify_file, load_binary,
)
from fangida.plugins import interfaces
from fangida.plugins.manager import Plugin


def fat_macho(count: int) -> bytes:
    thin = macho64()
    first_offset = 4096
    data = bytearray(first_offset + count * len(thin))
    struct.pack_into(">II", data, 0, 0xCAFEBABE, count)
    for index in range(count):
        offset = first_offset + index * len(thin)
        struct.pack_into(">IIIII", data, 8 + index * 20,
                         0x01000007, 3, offset, len(thin), 0)
        data[offset:offset + len(thin)] = thin
    return bytes(data)


class IndependentLoadersTests(unittest.TestCase):
    def test_loader_package_import_does_not_load_analysis_cores(self) -> None:
        source = (
            "import sys; import fangida.loaders; "
            "assert not any(name.startswith(('fangida.core.', 'fangida.processors.', "
            "'fangida.plugins.')) for name in sys.modules)"
        )
        result = subprocess.run([sys.executable, "-c", source], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_legacy_binary_names_keep_model_identity_and_parser_results(self) -> None:
        self.assertIs(binary.BinaryImage, BinaryImage)
        self.assertIs(binary.BinaryFormatError, BinaryFormatError)
        for data, kind, old_helper in (
            (elf64_with_symbols(), "elf", binary._elf),
            (pe64(), "pe", binary._pe),
            (macho64(), "macho", binary._macho),
            (fat_macho(1), "macho", binary._fat_macho),
        ):
            with self.subTest(kind=kind, helper=old_helper.__name__):
                self.assertEqual(binary.parse_binary(data, kind), old_helper(data))
                self.assertEqual(load_binary(data, kind), old_helper(data))
        self.assertEqual(binary._unpack(b"\x01\x00", 0, "<H"), (1,))
        self.assertTrue(binary._table(b"1234", 0, 2, 2, 2, 2))
        self.assertEqual(binary._name(b"test\0other", 0), "test")
        self.assertTrue(all(hasattr(binary, name) for name in
                            ("MAX_SECTIONS", "MAX_SEGMENTS", "MAX_SYMBOLS", "_elf_symbols")))

    def test_native_loading_keeps_signature_precedence_and_error_behavior(self) -> None:
        self.assertEqual(load_binary(pe64(), "elf").format, "pe")
        with self.assertRaisesRegex(BinaryFormatError, "Truncated ELF identification"):
            binary.parse_binary(b"\x7fELF", "elf")
        with self.assertRaisesRegex(BinaryFormatError, "Invalid fat Mach-O architecture count"):
            binary.parse_binary(bytes.fromhex("cafebabe00000100"), "class")
        with self.assertRaisesRegex(BinaryFormatError, "architecture table exceeds scan budget"):
            binary.parse_binary(bytes.fromhex("cafebabe00000034"), "class")
        with self.assertRaisesRegex(BinaryFormatError, "identified as unknown"):
            binary.parse_binary(b"not a container", "unknown")

    def test_identification_keeps_native_magic_and_archive_routing(self) -> None:
        for data, path, expected in (
            (b"\x7fELF", "false.apk", ("elf", "magic")),
            (b"MZ", "false.jar", ("pe", "magic")),
            (b"dex\n035\0", "unknown", ("dex", "magic")),
            (b"PK\x03\x04", "sample.APK", ("apk", "magic+extension")),
            (b"PK\x03\x04", "sample.zip", ("jar", "magic+extension")),
            (b"unknown", "sample.dll", ("pe", "extension")),
            (b"unknown", "sample.data", ("unknown", "unknown")),
        ):
            with self.subTest(path=path):
                self.assertEqual(identify_bytes(data, path), expected)

    def test_fat_33_to_64_slices_do_not_collide_with_java_versions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for count in (33, 44, 45, 52, 61, 64):
                with self.subTest(count=count):
                    data = fat_macho(count)
                    path = Path(directory) / f"universal-{count}.class"
                    path.write_bytes(data)
                    self.assertEqual(identify_file(path), ("macho", "magic"))
                    self.assertEqual(identify_bytes(data), ("macho", "magic"))
                    self.assertEqual(load_binary(data).fat_slice_offset, 4096)
            for major in (45, 52, 61, 64, 65, 70):
                with self.subTest(java_major=major):
                    data = struct.pack(">IHH", 0xCAFEBABE, 0, major) + b"\x00\x02\x01\x00\x01x"
                    self.assertEqual(identify_bytes(data, "Foo.class"), ("class", "magic"))

    def test_file_identification_reads_a_bounded_prefix(self) -> None:
        stream = io.BytesIO(b"\x7fELF" + b"x" * 10000)
        with patch("pathlib.Path.open", return_value=stream), patch.object(stream, "read", wraps=stream.read) as read:
            self.assertEqual(identify_file("sample"), ("elf", "magic"))
            read.assert_called_once_with(4096)

    def test_format_probes_and_loaders_have_distinct_contracts(self) -> None:
        registry = default_registry()
        self.assertIsInstance(registry.get("elf"), Loader)
        self.assertIsInstance(registry.get("jvm"), FormatProbe)
        self.assertNotIsInstance(registry.get("jvm"), Loader)
        image = ELFLoader().load(elf64_with_symbols())
        self.assertEqual([function["name"] for function in image.functions], ["known_func"])
        self.assertTrue(all(not function["blocks"] and not function["xrefs_out"]
                            for function in image.functions))

    def test_plugin_interface_remains_importable_through_manager(self) -> None:
        self.assertIs(Plugin, interfaces.Plugin)

        class LegacyPlugin:
            name = "legacy"
            version = "1"

            def capabilities(self):
                return ("metadata",)

            def analyze(self, task):
                return None

            def teardown(self):
                pass

        legacy = LegacyPlugin()
        self.assertIsInstance(legacy, interfaces.Plugin)
        self.assertNotIsInstance(legacy, interfaces.ControlledPlugin)


class RegistryTests(unittest.TestCase):
    def test_new_container_can_register_without_changing_dispatch_or_native_parser(self) -> None:
        class CustomLoader:
            name = "custom"
            extensions = {".custom": "custom"}

            def probe(self, data, path=None):
                return LoaderMatch("custom") if data.startswith(b"FGDA") else None

            def load(self, data, kind):
                return BinaryImage("custom", "x86_64", 64, "little", entry_address=0x1000)

        registry = default_registry()
        loader = CustomLoader()
        registry.register(loader)
        self.assertIs(registry.get("custom"), loader)
        self.assertEqual(registry.identify_bytes(b"FGDA", "fake.apk"), ("custom", "magic"))
        self.assertEqual(registry.identify_bytes(b"empty", "file.CUSTOM"), ("custom", "extension"))
        self.assertEqual(registry.load(b"FGDA").entry_address, 0x1000)
        with self.assertRaisesRegex(ValueError, "already registered"):
            registry.register(CustomLoader())
        registry.unregister("custom")
        self.assertEqual(registry.identify_bytes(b"FGDA"), ("unknown", "unknown"))

    def test_priority_is_explicit_and_original_registration_can_be_restored(self) -> None:
        class ReplacementElf(ELFLoader):
            name = "alternative-elf"

            def probe(self, data, path=None):
                return LoaderMatch("alternative") if data.startswith(b"\x7fELF") else None

        registry = default_registry()
        registry.register(ReplacementElf(), priority=1)
        self.assertEqual(registry.identify_bytes(b"\x7fELF"), ("alternative", "magic"))
        registry.unregister("alternative-elf")
        registry.register(ELFLoader(), replace=True)
        self.assertEqual(registry.identify_bytes(b"\x7fELF"), ("elf", "magic"))

    def test_invalid_probe_result_is_not_silently_used(self) -> None:
        class BrokenProbe:
            name = "broken"
            extensions = {}

            def probe(self, data, path=None):
                return LoaderMatch("broken", score=True)

        registry = LoaderRegistry()
        registry.register(BrokenProbe())
        with self.assertRaisesRegex(TypeError, "invalid format match"):
            registry.identify_bytes(b"anything")


if __name__ == "__main__":
    unittest.main()
