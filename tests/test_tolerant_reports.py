"""reports/ belongs to the owner's desktop compiler: a bad report input must never block the feed."""
import json
import subprocess
import sys
import unittest

import support
from intelligence_hub.archive import validate_snapshot
from intelligence_hub.intelligence import REPORT_CATALOG, read_report_input


class ReadReportInputTest(unittest.TestCase):
    def setUp(self):
        self.copy = support.BuildCopy()

    def tearDown(self):
        self.copy.close()

    def test_valid_catalog_reads(self):
        value, digest, reason = read_report_input(self.copy.root, REPORT_CATALOG)
        self.assertIsNone(reason)
        self.assertEqual(value["schema_version"], 1)
        self.assertRegex(digest, r"^[a-f0-9]{64}$")

    def test_failures_become_reasons(self):
        cases = {
            b"{not json": "is not valid JSON",
            b"\xff\xfe\x00": "is not UTF-8 text",
            b'{"a": 1, "a": 2}': "has duplicate JSON members",
            b"[" * 40 + b"]" * 40: "exceeds the input structure bounds",
            b" " * 65537: "exceeds its 65,536-byte bound",
        }
        for data, expected in cases.items():
            with self.subTest(expected=expected):
                self.copy.write_report_input("catalog.json", data)
                value, digest, reason = read_report_input(self.copy.root, REPORT_CATALOG)
                self.assertIsNone(value)
                self.assertRegex(digest, r"^[a-f0-9]{64}$")
                self.assertIn(expected, reason)
        self.copy.remove_report_input("catalog.json")
        self.assertIn("is missing", read_report_input(self.copy.root, REPORT_CATALOG)[2])


class TolerantBuildTest(unittest.TestCase):
    """Each case runs the real entry point offline in a throwaway copy and must exit 0."""

    def setUp(self):
        self.copy = support.BuildCopy()

    def tearDown(self):
        self.copy.close()

    def build(self):
        code, result, output = self.copy.run()
        self.assertEqual(code, 0, output)
        feed = self.copy.feed()
        validate_snapshot(feed)
        self.assertGreater(len(feed["articles"]), 0)
        return result, feed

    def assert_unavailable(self, expected_reason):
        result, feed = self.build()
        self.assertEqual(result["reports"]["status"], "unavailable")
        self.assertIn(expected_reason, result["reports"]["reason"])
        self.assertTrue(any(note.startswith("Reports unavailable in this run:") for note in feed["coverage"]["notes"]))
        return feed

    def test_committed_catalog_is_available(self):
        result, feed = self.build()
        self.assertEqual(result["reports"], {"status": "available", "reason": None})
        self.assertGreater(len(feed["intelligence"]["reporting"]["latest_reports"]), 0)
        self.assertFalse(any(note.startswith("Reports unavailable") for note in feed["coverage"]["notes"]))

    def test_corrupt_catalog(self):
        self.copy.write_report_input("catalog.json", b'{"schema_version": 1, "reports": [')
        feed = self.assert_unavailable("reports/catalog.json is not valid JSON")
        reporting = feed["intelligence"]["reporting"]
        self.assertEqual((reporting["latest_reports"], reporting["indexes"], reporting["catalog_updated_at"]), ([], [], None))
        self.assertTrue(reporting["notes"][0].startswith("Report catalog unavailable in this snapshot"))
        self.assertEqual(feed["intelligence"]["revisions"]["state"], "not_run")

    def test_oversize_catalog(self):
        catalog = json.loads((support.ROOT / "reports/catalog.json").read_text(encoding="utf-8"))
        data = json.dumps(catalog, indent=2).encode("utf-8")
        data += b" " * (65537 - len(data))  # valid JSON, one byte over the bound
        self.assertGreater(len(data), 65536)
        self.copy.write_report_input("catalog.json", data)
        self.assert_unavailable("reports/catalog.json exceeds its 65,536-byte bound")

    def test_schema_mismatch_catalog(self):
        self.copy.write_report_input("catalog.json", b'{"schema_version": 2, "reports": []}')
        self.assert_unavailable("does not match the report catalog schema")

    def test_missing_catalog(self):
        self.copy.remove_report_input("catalog.json")
        self.assert_unavailable("reports/catalog.json is missing")

    def test_invalid_reporting_configuration(self):
        self.copy.write_report_input("reporting.json", b'{"schema_version": 1, "timezone": "UTC"}')
        feed = self.assert_unavailable("reports/reporting.json does not match the reporting schema")
        configuration = feed["intelligence"]["reporting"]["configuration"]
        self.assertEqual((configuration["schedule_state"], configuration["schedule_observed_at"]), ("planned", None))

    def test_curated_context_stays_strict(self):
        (self.copy.root / "config/intelligence-context.json").write_bytes(b"{broken")
        code, _, _ = self.copy.run()
        self.assertNotEqual(code, 0)

    def test_report_files_are_not_rewritten(self):
        before = {name: (self.copy.root / "reports" / name).read_bytes() for name in ("catalog.json", "reporting.json")}
        self.build()
        after = {name: (self.copy.root / "reports" / name).read_bytes() for name in ("catalog.json", "reporting.json")}
        self.assertEqual(before, after)


class SiteScriptTest(unittest.TestCase):
    def test_app_js_parses(self):
        try:
            completed = subprocess.run(["node", "--check", str(support.ROOT / "site/app.js")], capture_output=True, text=True, timeout=60)
        except FileNotFoundError:
            self.skipTest("node is not installed; the pull-request check runs node --check itself")
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    sys.exit(unittest.main())
