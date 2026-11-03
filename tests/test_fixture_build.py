import subprocess
import sys
import unittest

import support
from intelligence_hub.archive import validate_snapshot


class FixtureTest(unittest.TestCase):
    def test_committed_fixture_is_current(self):
        completed = subprocess.run([sys.executable, "-I", str(support.FIXTURES / "build_fixture.py"), "--check"],
                                   capture_output=True, text=True, timeout=120)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_offline_build_from_fixture(self):
        copy = support.BuildCopy()
        try:
            code, result, output = copy.run()
            self.assertEqual(code, 0, output)
            feed = copy.feed()
            validate_snapshot(feed)
            urls = {article["url"] for article in feed["articles"]}
            self.assertIn("https://www.cisa.gov/fixture/advisory-one", urls)
            kev = [article for article in feed["articles"] if article["origin"] == "cisa-kev"]
            self.assertEqual(sorted(article["cves"][0] for article in kev), ["CVE-2026-99991", "CVE-2026-99992"])
            self.assertEqual(result["coverage"]["kev_records"], 2)
            self.assertIn("CVE-2026-99991", feed["mitigations"])
            self.assertTrue(all(article["summary"] == "" for article in feed["articles"] if article["origin"] == "publisher-feed"))
        finally:
            copy.close()


if __name__ == "__main__":
    unittest.main()
