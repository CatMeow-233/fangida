import io
import unittest
from unittest.mock import patch
from fangida.api import AnalysisView
from fangida.models import AnalysisResult
from fangida.tui import browse

class TuiTests(unittest.TestCase):
    def test_browse_snapshot(self) -> None:
        view = AnalysisView(AnalysisResult("sample", "elf", "kkagent", "partial"))
        output = io.StringIO()
        with patch("builtins.input", side_effect=["summary", "quit"]):
            browse(view, output)
        self.assertIn('"kind": "elf"', output.getvalue())
