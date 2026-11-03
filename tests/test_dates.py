"""Publisher date zones: CET and CEST names, and stamps that carry no zone at all."""
import unittest

import support
from intelligence_hub.collect import ZONE_ASSUMED, feed_published, parse_feed, published


def rss(stamp, link="https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fixture"):
    return ("<rss version=\"2.0\"><channel><title>t</title><item><title>Fixture advisory</title><link>" + link +
            "</link><pubDate>" + stamp + "</pubDate></item></channel></rss>").encode("utf-8")


class NamedZoneTest(unittest.TestCase):
    def test_cest_stamp(self):
        # CERT-EU's format, two hours ahead of UTC in summer.
        self.assertEqual(published("Fri, 23 Oct 2026 16:36:26 CEST"), "2026-10-23T14:36:26+00:00")

    def test_cet_stamp(self):
        self.assertEqual(published("Mon, 02 Nov 2026 09:15:00 CET"), "2026-11-02T08:15:00+00:00")

    def test_cest_is_not_flagged(self):
        self.assertEqual(feed_published("Thu, 22 Oct 2026 11:14:22 CEST"), ("2026-10-22T09:14:22+00:00", False))

    def test_other_zones_are_unchanged(self):
        self.assertEqual(published("Mon, 26 Oct 2026 14:00:00 EST"), "2026-10-26T19:00:00+00:00")
        self.assertEqual(published("Mon, 26 Oct 2026 14:00:00 +0100"), "2026-10-26T13:00:00+00:00")


class NaiveStampTest(unittest.TestCase):
    def test_validators_still_refuse_naive_stamps(self):
        for value in ("2026-11-02 21:16:10.0", "2026-11-02T21:16:10", "Mon, 02 Nov 2026 21:16:10"):
            with self.subTest(value=value):
                self.assertIsNone(published(value))

    def test_cisco_stamp_is_read_as_utc_and_flagged(self):
        self.assertEqual(feed_published("2026-11-02 21:16:10.0"), ("2026-11-02T21:16:10+00:00", True))

    def test_other_naive_forms(self):
        self.assertEqual(feed_published("2026-11-02T21:16:10"), ("2026-11-02T21:16:10+00:00", True))
        self.assertEqual(feed_published("2026-11-02 21:16"), ("2026-11-02T21:16:00+00:00", True))
        self.assertEqual(feed_published("Mon, 02 Nov 2026 21:16:10"), ("2026-11-02T21:16:10+00:00", True))

    def test_zoned_and_invalid_values(self):
        self.assertEqual(feed_published("2026-11-02T21:16:10Z"), ("2026-11-02T21:16:10+00:00", False))
        self.assertEqual(feed_published("2026-10-27"), ("2026-10-27", False))
        for value in ("", "yesterday", "2026-02-30 10:00:00", "2026-11-02 25:00:00", None):
            with self.subTest(value=value):
                self.assertEqual(feed_published(value), (None, False))

    def test_parse_feed_marks_the_assumption(self):
        article = parse_feed(rss("2026-11-02 21:16:10.0"), support.source("cisco-psirt"))["articles"][0]
        self.assertEqual(article["published_at"], "2026-11-02T21:16:10+00:00")
        self.assertEqual(article["date_basis"], "publication" + ZONE_ASSUMED)
        self.assertLessEqual(len(article["date_basis"]), 60)

    def test_parse_feed_dates_cert_eu(self):
        link = "https://cert.europa.eu/publications/security-advisories/2026-012/"
        article = parse_feed(rss("Fri, 23 Oct 2026 16:36:26 CEST", link), support.source("cert-eu"))["articles"][0]
        self.assertEqual(article["published_at"], "2026-10-23T14:36:26+00:00")
        self.assertEqual(article["date_basis"], "publication")


if __name__ == "__main__":
    unittest.main()
