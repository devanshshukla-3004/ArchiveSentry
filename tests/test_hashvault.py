import json
import tempfile
import unittest
from pathlib import Path
from hashvault import create_baseline, sha256_file, verify_baseline

class HashVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "target"
        self.root.mkdir()
        (self.root / "alpha.txt").write_text("trusted content", encoding="utf-8")
        (self.root / "nested").mkdir()
        (self.root / "nested" / "beta.txt").write_text("second file", encoding="utf-8")
        self.baseline = Path(self.temp.name) / "baseline.json"

    def test_sha256_is_stable(self):
        self.assertEqual(sha256_file(self.root / "alpha.txt"), sha256_file(self.root / "alpha.txt"))
        self.assertEqual(len(sha256_file(self.root / "alpha.txt")), 64)

    def test_clean_baseline(self):
        create_baseline(self.root, self.baseline)
        report = verify_baseline(self.root, self.baseline)
        self.assertEqual(report["summary"]["status"], "CLEAN")

    def test_modified_file_detected(self):
        create_baseline(self.root, self.baseline)
        (self.root / "alpha.txt").write_text("tampered", encoding="utf-8")
        report = verify_baseline(self.root, self.baseline)
        self.assertIn("alpha.txt", report["modified"])

    def test_added_file_detected(self):
        create_baseline(self.root, self.baseline)
        (self.root / "new.txt").write_text("new", encoding="utf-8")
        self.assertIn("new.txt", verify_baseline(self.root, self.baseline)["added"])

    def test_deleted_file_detected(self):
        create_baseline(self.root, self.baseline)
        (self.root / "alpha.txt").unlink()
        self.assertIn("alpha.txt", verify_baseline(self.root, self.baseline)["deleted"])

    def test_manifest_has_expected_format(self):
        create_baseline(self.root, self.baseline)
        data = json.loads(self.baseline.read_text(encoding="utf-8"))
        self.assertEqual(data["algorithm"], "sha256")
        self.assertIn("alpha.txt", data["files"])

if __name__ == "__main__":
    unittest.main()
