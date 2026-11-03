import tempfile
import unittest
from pathlib import Path

import support
import check_em_dash


class EmDashLintTest(unittest.TestCase):
    def test_detects_a_planted_em_dash(self):
        with tempfile.TemporaryDirectory() as directory:
            planted = Path(directory) / "planted.md"
            planted.write_text("clean line\nbad \u2014 line\n", encoding="utf-8")
            self.assertEqual(check_em_dash.hits([str(planted)]), [(str(planted), 2)])

    def test_reports_are_excluded(self):
        self.assertFalse(any(name.startswith("reports/") for name in check_em_dash.tracked_files()))

    def test_tracked_files_are_clean(self):
        self.assertEqual(check_em_dash.hits(check_em_dash.tracked_files()), [])

    def test_new_test_files_are_clean(self):
        names = [path.relative_to(support.ROOT).as_posix() for path in (support.ROOT / "tests").rglob("*") if path.is_file()]
        self.assertEqual(check_em_dash.hits(names), [])


if __name__ == "__main__":
    unittest.main()
