"""Evidence and safety behavior for the static auxiliary passes."""
import json
import unittest

from fangida.auxiliary import inspect_packing_indicators, simplify_transparent_dispatchers


def block(address: int, target: int, *, conditional: bool = False, writes: list[str] | None = None) -> dict:
    return {"start": address, "successors": [target],
            "instructions": [{"address": address, "size": 2, "mnemonic": "jmp",
                              "reads": [], "writes": writes or [],
                              "branch_info": {"kind": "jump", "target": target,
                                              "conditional": conditional}}]}


class CfgTests(unittest.TestCase):
    def test_chain_and_entry_are_rewritten_without_mutating_input(self) -> None:
        blocks = [block(1, 2), block(2, 3),
                  {"start": 3, "successors": [], "instructions": []},
                  {"start": 4, "successors": [1], "instructions": []}]
        result = simplify_transparent_dispatchers(1, blocks)
        self.assertEqual(result["entry"], 3)
        self.assertEqual([item["start"] for item in result["blocks"]], [3, 4])
        self.assertEqual(result["blocks"][1]["successors"], [3])
        self.assertEqual(result["bypassed"], [{"start": 1, "target": 3}, {"start": 2, "target": 3}])
        result["original_blocks"][0]["successors"][0] = 99
        self.assertEqual(blocks[0]["successors"], [2])
        json.dumps(result)

    def test_cycle_and_side_effect_blocks_remain(self) -> None:
        blocks = [block(1, 2), block(2, 1), block(3, 4, writes=["rax"]),
                  {"start": 4, "successors": [1], "instructions": []}, block(5, 1)]
        result = simplify_transparent_dispatchers(3, blocks)
        self.assertEqual(result["bypassed"], [])
        self.assertEqual(len(result["blocks"]), 5)

    def test_incomplete_graph_rejected(self) -> None:
        with self.assertRaises(ValueError):
            simplify_transparent_dispatchers(1, [block(1, 2)])
        with self.assertRaises(ValueError):
            simplify_transparent_dispatchers(1, [block(1, 1), block(1, 1)])
        malformed = block(1, 1)
        malformed["metadata"] = {"unserializable"}
        with self.assertRaises(ValueError):
            simplify_transparent_dispatchers(1, [malformed])


class UnpackingTests(unittest.TestCase):
    def test_signatures_and_entropy_are_evidence_only(self) -> None:
        data = b"UPX!" + bytes(range(256)) * 16
        result = inspect_packing_indicators(data)
        self.assertEqual(result["signatures"][0]["offset"], 0)
        self.assertTrue(result["windows"][0]["high_entropy"])
        self.assertIn("do not establish packing", result["interpretation"])
        json.dumps(result)

    def test_limits_and_low_entropy(self) -> None:
        result = inspect_packing_indicators(b"\0" * 2048 + b"PK\x03\x04", max_bytes=1024)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["entropy_bits_per_byte"], 0.0)
        self.assertEqual(result["signatures"], [])
        with self.assertRaises(ValueError):
            inspect_packing_indicators(b"x", max_bytes=MAX_TOO_LARGE)

    def test_short_input_has_global_entropy_but_no_window(self) -> None:
        result = inspect_packing_indicators(b"UPX!" + b"x" * 20)
        self.assertEqual(result["entropy_covered_bytes"], 0)
        self.assertEqual(result["windows"], [])
        self.assertGreater(result["entropy_bits_per_byte"], 0)


MAX_TOO_LARGE = 4 * 1024 * 1024 + 1


if __name__ == "__main__":
    unittest.main()
