"""site/app.js reads briefs lazily from data/briefs.json and still reads a schema 6 feed.

The page script runs under Node with the stand-ins in tests/app_harness.js. The test is
skipped when Node is not installed; the pull-request check always has it.
"""
import copy
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
# A product name that appears only in the brief file, never in a feed title, summary or tag.
PRODUCT = "TelePresence Codec"
TITLE = "Example Gateway TelePresence Codec access-control bypass"


def with_products(briefs, title=TITLE):
    """The offline fixture has no CNA records; give the fixture CVE a CNA title and a product."""
    value = copy.deepcopy(briefs)
    brief = value["briefs"][CVE]
    brief["title"] = title
    brief["products"] = [{"vendor": "Example Vendor", "product": PRODUCT, "default_status": "unknown",
                          "versions": [{"version": "1.0", "status": "affected", "less_than": "",
                                        "less_than_or_equal": "", "version_type": ""}]}]
    return value


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

    def write_files(self, prefix, feed, briefs):
        files = {}
        for url, value in (("./data/feed.json", feed), ("./data/briefs.json", briefs)):
            if value is not None:
                path = self.root / (prefix + "-" + url.rsplit("/", 1)[1])
                path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
                files[url] = str(path)
        return files

    def run_case(self, case, feed, briefs=None, after=None, term=None):
        plan = {"case": case, "cve": CVE, "files": self.write_files(case, feed, briefs), "term": term}
        if after is not None:
            plan["files_after"] = self.write_files(case + "-after", *after)
        scenario = self.root / (case + ".json")
        scenario.write_text(json.dumps(plan), encoding="utf-8")
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

    def test_search_matches_product_names_from_the_brief_file(self):
        self.assertNotIn(PRODUCT.lower(), json.dumps(self.feed).lower())
        result = self.run_case("search", self.feed, with_products(self.briefs), term="telepresence")
        # The feed alone cannot match the term; the search reads the brief file and renders again.
        self.assertEqual(result["matches_before"], 0)
        self.assertGreaterEqual(len(result["matches_after"]), 1)
        self.assertEqual(result["matched_cves"], [CVE])
        self.assertEqual(result["requests"], ["./data/briefs.json no-cache"])
        self.assertNotIn("not loaded", result["status"])
        self.assertIsNone(result["error"])

    def test_register_refills_titles_after_a_changed_snapshot(self):
        later = {**self.feed, "generated_at": "2026-11-02T00:00:00Z", "content_revision": "1" * 64}
        later_briefs = {**with_products(self.briefs, "Later CNA title"), "generated_at": later["generated_at"],
                        "content_revision": later["content_revision"]}
        result = self.run_case("reload", self.feed, with_products(self.briefs), after=(later, later_briefs))
        self.assertEqual(result["title_first"], TITLE, result)
        self.assertTrue(result["replaced"])
        # The open register asks for the new snapshot's briefs without another click.
        self.assertTrue(result["briefs_loaded"])
        self.assertEqual(result["title_after"], "Later CNA title")
        self.assertEqual(result["requests"], ["./data/feed.json no-store", "./data/briefs.json no-cache",
                                              "./data/feed.json no-store", "./data/briefs.json no-cache"])
        self.assertIsNone(result["error"])

    def test_feed_over_its_bound_is_refused(self):
        result = self.run_case("oversize", self.feed)
        self.assertFalse(result["accepted"])
        self.assertTrue(result["accepted_at_size"])


if __name__ == "__main__":
    unittest.main()
