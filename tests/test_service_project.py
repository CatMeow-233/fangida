import tempfile
import unittest
from pathlib import Path
from fangida.dispatcher import AnalysisService
from fangida.project import ProjectStore

class ServiceProjectTests(unittest.TestCase):
    def test_analysis_persists_content_bound_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "sample.elf"
            file.write_bytes(b"\x7fELFtest string\x00")
            db = Path(directory) / "sample.fangida"
            with AnalysisService(project_path=db) as service:
                result = service.analyze(file)
            snapshot_id = result.metadata["project_snapshot_id"]
            self.assertEqual(ProjectStore(db).get_snapshot(snapshot_id)["kind"], "elf")
            file.write_bytes(file.read_bytes() + b"changed")
            self.assertIsNone(ProjectStore(db).load_analysis(file))
