import tempfile
import unittest
from pathlib import Path
from fangida.dispatcher import identify, analyze

class MagicCollisionTests(unittest.TestCase):
    def test_class_and_fat_macho_do_not_share_route(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            class_file = Path(directory) / "Foo.class"
            class_file.write_bytes(bytes.fromhex("cafebabe00000034"))
            self.assertEqual(identify(class_file), ("class", "magic"))
            self.assertEqual(analyze(class_file).analyzer, "apk_analyzer")
            fat = Path(directory) / "universal"
            fat.write_bytes(bytes.fromhex("cafebabe00000002"))
            self.assertEqual(identify(fat), ("macho", "magic"))
            self.assertEqual(analyze(fat).analyzer, "kkagent")
