"""site/app.js reads briefs lazily from data/briefs.json and still reads a schema 6 feed.

The page script runs under Node with the stand-ins in tests/app_harness.js. The test is
skipped when Node is not installed; the pull-request check always has it.
"""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import support
from intelligence_hub.mitigations import join_publication

NODE = shutil.which("node")
CVE = "CVE-2026-99991"


@unittest.skipIf(NODE is None, "Node is not installed")
class AppBriefsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        copy = support.BuildCopy()
        try:
            code, _result, output = copy.run()
            if code != 0:
                raise AssertionError(output)
            cls.feed, cls.briefs = copy.feed(), copy.briefs()
        finally:
            copy.close()
        cls.directory = tempfile.TemporaryDirectory(prefix="hub-app-")
        cls.root = Path(cls.directory.name)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_case(self, case, feed, briefs=None):
        files = {}
        for url, value in (("./data/feed.json", feed), ("./data/briefs.json", briefs)):
            if value is not None:
                path = self.root / (case + "-" + url.rsplit("/", 1)[1])
                path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
                files[url] = str(path)
        scenario = self.root / (case + ".json")
        scenario.write_text(json.dumps({"case": case, "cve": CVE, "files": files}), encoding="utf-8")
        completed = subprocess.run([NODE, str(support.ROOT / "tests" / "app_harness.js"), str(support.ROOT / "site" / "app.js"), str(scenario)],
                                   capture_output=True, text=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        return json.loads(completed.stdout)

    def test_briefs_load_once_on_first_open(self):
        result = self.run_case("current", self.feed, self.briefs)
        self.assertFalse(result["briefs_inline"])
        self.assertEqual(result["index_size"], len(self.feed["brief_index"]["rows"]))
        self.assertEqual(result["light"]["kev_added"], "2026-10-27")
        self.assertEqual(result["opened"], ["#mitigation-dialog"])
        self.assertEqual(result["dialog_title"], CVE)
        self.assertGreater(result["dialog_sections"], 3)
        self.assertIsNone(result["error"])
        self.assertEqual(result["opened_again"], 2)
        # The page made one request: the briefs file, revalidated rather than refetched.
        self.assertEqual(result["requests"], ["./data/briefs.json no-cache"])
        self.assertEqual(result["register_title_before"], CVE)
        self.assertEqual(result["register_title_after"], self.briefs["briefs"][CVE]["title"] or CVE)

    def test_briefs_from_another_run_are_refused(self):
        briefs = {**self.briefs, "content_revision": "0" * 64}
        result = self.run_case("mismatch", self.feed, briefs)
        self.assertEqual(result["opened"], [])
        self.assertIn("different snapshot", result["error"])
        self.assertIn("./data/feed.json no-store", result["requests"])  # the page reads the feed again

    def test_missing_briefs_file_reports_an_error(self):
        result = self.run_case("missing", self.feed)
        self.assertEqual(result["opened"], [])
        self.assertIn("HTTP 404", result["error"])

    def test_schema_6_feed_keeps_inline_briefs(self):
        legacy = join_publication(self.feed, self.briefs)
        del legacy["brief_index"]
        legacy["schema_version"] = 6
        result = self.run_case("legacy", legacy)
        self.assertTrue(result["briefs_inline"])
        self.assertEqual(result["opened"], ["#mitigation-dialog"])
        self.assertEqual(result["requests"], [])

    def test_feed_over_its_bound_is_refused(self):
        result = self.run_case("oversize", self.feed)
        self.assertFalse(result["accepted"])
        self.assertTrue(result["accepted_at_size"])


if __name__ == "__main__":
    unittest.main()
