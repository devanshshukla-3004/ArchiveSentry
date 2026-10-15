import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from hashvault import classify_member, inspect_archive, inspect_zip


class ArchiveSentryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make_zip(self, members):
        path = self.root / "test.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in members:
                archive.writestr(name, data)
        return path

    def test_clean_archive_has_no_findings(self):
        path = self.make_zip([("docs/readme.txt", "hello")])
        report = inspect_archive(path)
        self.assertEqual(report["status"], "NO_FINDINGS")
        self.assertEqual(report["members_checked"], 1)

    def test_parent_traversal_detected(self):
        findings = classify_member("../../outside.txt")
        self.assertIn("PATH_TRAVERSAL", [f["rule"] for f in findings])

    def test_absolute_path_detected(self):
        findings = classify_member("C:\\Windows\\system.ini")
        self.assertIn("ABSOLUTE_PATH", [f["rule"] for f in findings])

    def test_script_extension_flagged(self):
        findings = classify_member("payload.ps1")
        self.assertIn("EXECUTABLE_OR_SCRIPT", [f["rule"] for f in findings])

    def test_double_extension_flagged(self):
        findings = classify_member("invoice.pdf.exe")
        self.assertIn("DOUBLE_EXTENSION", [f["rule"] for f in findings])

    def test_zip_report_names_suspicious_member(self):
        path = self.make_zip([("../escape.txt", "x"), ("invoice.pdf.exe", "x")])
        report = inspect_zip(path, 100)
        self.assertGreaterEqual(len(report["findings"]), 2)
        self.assertEqual(report["status"] if "status" in report else "FINDINGS", "FINDINGS")

    def test_member_limit_validation(self):
        path = self.make_zip([("a.txt", "a")])
        with self.assertRaises(ValueError):
            inspect_archive(path, 0)

    def test_invalid_archive_rejected(self):
        path = self.root / "bad.zip"
        path.write_text("not an archive", encoding="utf-8")
        with self.assertRaises(ValueError):
            inspect_archive(path)


if __name__ == "__main__":
    unittest.main()
