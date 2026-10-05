import struct
import unittest
from fangida.core.kkagent.binary import parse_binary
from fangida.core.kkagent.test_native import macho64

class FatMachoTests(unittest.TestCase):
    def test_selects_arm64_or_x86_64_and_maps_entry_file_offset(self) -> None:
        thin = macho64()
        data = bytearray(0x100 + len(thin))
        struct.pack_into(">II", data, 0, 0xcafebabe, 1)
        struct.pack_into(">IIIII", data, 8, 0x01000007, 3, 0x100, len(thin), 8)
        data[0x100:] = thin
        image = parse_binary(bytes(data), "macho")
        self.assertEqual(image.entry_offset, 0x300)
        self.assertEqual(image.fat_slice_offset, 0x100)
        self.assertEqual(image.sections[0]["offset"], 0x300)
