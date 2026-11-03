import unittest
import xml.etree.ElementTree as ET

import support
from intelligence_hub.collect import parse_feed

SOURCE = support.source("cisa-advisories")


def rss(items, prefix=""):
    return (prefix + "<rss version=\"2.0\"><channel><title>t</title>" + "".join(items) + "</channel></rss>").encode("utf-8")


def item(index, extra=""):
    return ("<item><title>Entry " + str(index) + "</title><link>https://www.cisa.gov/fixture/" + str(index) + "</link>"
            "<pubDate>Mon, 26 Oct 2026 14:00:00 GMT</pubDate>" + extra + "</item>")


class ParseFeedTest(unittest.TestCase):
    def test_fixture_feed(self):
        parsed = parse_feed((support.FIXTURES / "sample-feed.xml").read_bytes(), SOURCE)
        intake = parsed["intake"]
        self.assertEqual((intake["items_seen"], intake["items_admitted"], intake["items_rejected"]), (3, 2, 1))
        self.assertEqual(intake["rejection_reasons"]["invalid_link_or_title"], 1)
        first, second = parsed["articles"]
        self.assertEqual(first["cves"], ["CVE-2026-99991"])
        self.assertEqual(first["summary"], "")  # article bodies are never copied
        self.assertEqual(second["url"], "https://www.cisa.gov/fixture/advisory-two")  # tracking stripped

    def test_atom_alternate_link(self):
        raw = ("<feed xmlns=\"http://www.w3.org/2005/Atom\"><entry><title>Atom entry</title>"
               "<link rel=\"alternate\" href=\"https://www.cisa.gov/fixture/atom\"/>"
               "<updated>2026-10-27T10:00:00Z</updated></entry></feed>").encode("utf-8")
        article = parse_feed(raw, SOURCE)["articles"][0]
        self.assertEqual(article["url"], "https://www.cisa.gov/fixture/atom")
        self.assertEqual(article["date_basis"], "publisher update")

    def test_entry_limit_is_150(self):
        parsed = parse_feed(rss([item(index) for index in range(160)]), SOURCE)
        intake = parsed["intake"]
        self.assertEqual((intake["items_seen"], intake["items_processed"], intake["items_unprocessed"]), (160, 150, 10))
        self.assertEqual(len(parsed["articles"]), 150)

    def test_more_than_100_cves_rejects_the_entry(self):
        many = " ".join("CVE-2026-" + str(10000 + index) for index in range(101))
        exactly = " ".join("CVE-2026-" + str(20000 + index) for index in range(100))
        parsed = parse_feed(rss([item(1, "<description>" + many + "</description>"),
                                 item(2, "<description>" + exactly + "</description>")]), SOURCE)
        self.assertEqual(parsed["intake"]["rejection_reasons"]["cve_limit_exceeded"], 1)
        self.assertEqual([len(article["cves"]) for article in parsed["articles"]], [100])

    def test_titles_are_bounded_text(self):
        parsed = parse_feed(rss(["<item><title>&lt;b&gt;" + "x" * 400 + "</title><link>https://www.cisa.gov/f</link></item>"]), SOURCE)
        title = parsed["articles"][0]["title"]
        self.assertLessEqual(len(title), 240)
        self.assertNotIn("<b>", title)

    def test_rejects_dtd_entities_and_nul(self):
        for raw in (rss([item(1)], "<!DOCTYPE rss [<!ENTITY x \"y\">]>"), rss([item(1)], "<!doctype rss>"),
                    rss([item(1)]).replace(b"Entry", b"En\x00try")):
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                parse_feed(raw, SOURCE)

    def test_rejects_non_feed_documents(self):
        with self.assertRaises(ValueError):
            parse_feed(b"<html><body>not a feed</body></html>", SOURCE)
        with self.assertRaises((ValueError, ET.ParseError)):
            parse_feed(b"<rss><channel>", SOURCE)

    def test_rejects_excessive_depth(self):
        deep = "<x>" * 60 + "</x>" * 60
        with self.assertRaises(ValueError):
            parse_feed(rss(["<item>" + deep + "</item>"]), SOURCE)

    def test_rejects_excessive_node_count(self):
        with self.assertRaises(ValueError):
            parse_feed(rss(["<x/>" * 40001]), SOURCE)


if __name__ == "__main__":
    unittest.main()
