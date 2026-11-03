import unittest

import support  # noqa: F401
from intelligence_hub.collect import published


class PublishedTest(unittest.TestCase):
    def test_date_only_stays_a_date(self):
        self.assertEqual(published("2026-10-27"), "2026-10-27")
        self.assertEqual(published("  2026-10-27\n"), "2026-10-27")

    def test_iso_timestamps_normalize_to_utc(self):
        self.assertEqual(published("2026-10-27T09:30:00Z"), "2026-10-27T09:30:00+00:00")
        self.assertEqual(published("2026-10-27T09:30:00-05:00"), "2026-10-27T14:30:00+00:00")
        self.assertEqual(published("2026-10-27T09:30:00.123456+02:00"), "2026-10-27T07:30:00+00:00")

    def test_rfc_822_dates_normalize_to_utc(self):
        self.assertEqual(published("Mon, 26 Oct 2026 14:00:00 GMT"), "2026-10-26T14:00:00+00:00")
        self.assertEqual(published("Mon, 26 Oct 2026 14:00:00 -0500"), "2026-10-26T19:00:00+00:00")

    def test_invalid_values_return_none(self):
        for value in ("", "yesterday", "2026-02-30", "2026-13-01T00:00:00Z", None, 20261027, "Mon, 99 Foo 2026"):
            with self.subTest(value=value):
                self.assertIsNone(published(value))


if __name__ == "__main__":
    unittest.main()
