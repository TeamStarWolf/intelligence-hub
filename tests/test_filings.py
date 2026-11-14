"""SEC filing intake (intelligence_hub/filings.py): the EDGAR search URL, the row built from a
full-text-search hit, the Item 1.05 filter, and the offline cache path."""
from datetime import date
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse

import support
from intelligence_hub import collect, filings

CACHE = support.FIXTURES / "filings" / "filings-cache.json"
BODIES = json.loads(CACHE.read_text(encoding="utf-8"))
PAGE = json.loads(BODIES[0])


class FilingsTest(unittest.TestCase):
    def test_search_url_is_canonical_item_1_05_8k(self):
        url = filings.search_url(date(2026, 11, 13))
        self.assertEqual(collect.safe_url(url), url)
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        self.assertEqual(query["forms"], ["8-K"])
        self.assertEqual(query["q"], ['"Item 1.05"'])
        self.assertEqual(query["startdt"], ["2026-07-16"])  # 120 days before the end date
        self.assertEqual(query["enddt"], ["2026-11-13"])

    def test_filing_url_points_at_the_edgar_index(self):
        url = filings.filing_url("0000885725", "0000885725-26-000059")
        self.assertEqual(url, "https://www.sec.gov/Archives/edgar/data/885725/000088572526000059/0000885725-26-000059-index.htm")
        self.assertEqual(collect.safe_url(url), url)

    def test_only_structured_item_1_05_filings_become_rows(self):
        rows = filings.parse_search([body.encode("utf-8") for body in BODIES])
        # Three Item 1.05 filings; the 8.01/9.01-only hit is dropped.
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["published_at"] for row in rows], ["2026-09-23", "2026-09-08", "2026-08-31"])  # newest first
        self.assertNotIn("sec-0000930245-26-048428", {row["id"] for row in rows})

    def test_row_shape_and_provenance(self):
        row = filings.parse_search([body.encode("utf-8") for body in BODIES])[1]  # Boston Scientific
        self.assertEqual((row["kind"], row["origin"], row["source_id"], row["date_basis"]), ("filing", "sec-filing", "sec-edgar", "filing"))
        self.assertEqual(row["id"], "sec-0000885725-26-000059")
        self.assertIn("BOSTON SCIENTIFIC", row["title"])
        self.assertIn("Item 1.05", row["summary"])
        self.assertEqual(row["cves"], [])
        self.assertEqual(collect.safe_url(row["url"]), row["url"])
        self.assertTrue(row["url"].startswith("https://www.sec.gov/Archives/edgar/data/885725/"))
        self.assertEqual(len(row["references"]), 1)

    def test_sic_maps_to_a_cisa_sector_or_nothing(self):
        self.assertEqual(filings.sector_tags(["3841"]), [["sector:healthcare-public-health", "sec-sic", "medium"]])  # surgical instruments
        self.assertEqual(filings.sector_tags(["6022"]), [["sector:financial-services", "sec-sic", "medium"]])        # state commercial banks
        self.assertEqual(filings.sector_tags(["4813"]), [["sector:communications", "sec-sic", "medium"]])            # telephone communications
        self.assertEqual(filings.sector_tags(["2834"]), [["sector:healthcare-public-health", "sec-sic", "medium"]])  # drugs, carved out of chemicals
        self.assertEqual(filings.sector_tags(["4512"]), [["sector:transportation", "sec-sic", "medium"]])                # air transportation
        self.assertEqual(filings.sector_tags(["5411"]), [["sector:retail", "sec-sic", "medium"]])                       # grocery stores
        self.assertEqual(filings.sector_tags(["1500"]), [])   # construction: no clean CISA sector, so no tag
        self.assertEqual(filings.sector_tags([]), [])
        self.assertEqual(filings.sector_tags(["8000", "8011"]), [["sector:healthcare-public-health", "sec-sic", "medium"]])  # deduped

    def test_every_mapped_sector_is_a_real_vocabulary_id(self):
        import json
        vocab = {value["value"] for value in json.loads((support.ROOT / "config" / "vocab" / "sector.json").read_text(encoding="utf-8"))["values"]}
        for _low, _high, slug in filings.SIC_SECTORS:
            self.assertIn(slug, vocab, slug + " is not a config/vocab/sector.json id")

    def test_company_slug_is_stable_across_legal_forms(self):
        self.assertEqual(filings.company_slug("BOSTON SCIENTIFIC CORP"), "boston-scientific")
        self.assertEqual(filings.company_slug("Boston Scientific Corporation"), "boston-scientific")  # same slug, different suffix
        self.assertEqual(filings.company_slug("Astrana Health, Inc."), "astrana-health")
        self.assertEqual(filings.company_slug("The Kroger Co."), "kroger")  # leading "The" and trailing "Co" dropped
        self.assertEqual(filings.company_slug("UnitedHealth Group Incorporated"), "unitedhealth-group")  # brand word "Group" kept
        self.assertIsNone(filings.company_slug(""))

    def test_filing_row_is_tagged_by_sector_and_company(self):
        row = filings.parse_search([body.encode("utf-8") for body in BODIES])[1]  # Boston Scientific, SIC 3841
        self.assertEqual(row["tagging"]["sector"], [["sector:healthcare-public-health", "sec-sic", "medium"]])
        self.assertEqual(row["tagging"]["company"], [["company:boston-scientific", "sec-filer", "high"]])

    def test_a_filing_without_a_sic_still_tags_the_company(self):
        source = {"items": ["1.05"], "adsh": "0000320193-26-000010", "ciks": ["0000320193"], "file_date": "2026-10-01",
                  "display_names": ["Example Registrant LLC  (CIK 0000320193)"]}  # no sics, no ticker
        row = filings.row_for(source)
        self.assertNotIn("sector", row["tagging"])
        self.assertEqual(row["tagging"]["company"], [["company:example-registrant", "sec-filer", "high"]])

    def test_collect_filings_offline_reads_the_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / filings.CACHE).write_bytes(CACHE.read_bytes())
            rows, summary = filings.collect_filings(False, date(2026, 11, 1), state=state)
            self.assertEqual(summary["status"], "cached")
            self.assertEqual(summary["filings"], 3)
            self.assertEqual(len(rows), 3)

    def test_collect_filings_offline_without_a_cache_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows, summary = filings.collect_filings(False, date(2026, 11, 1), state=Path(tmp))
            self.assertEqual((rows, summary["status"], summary["filings"]), ([], "none", 0))

    def test_malformed_response_becomes_a_failed_summary_not_a_crash(self):
        # EDGAR is untrusted upstream data; an unexpected shape must not raise out of the collector.
        for body in (b"[]", b'"nope"', b"123", b'{"hits": []}', b"not json at all"):
            rows, summary = filings.collect_filings(True, date(2026, 11, 1), fetch=lambda *a, **k: body)
            self.assertEqual(rows, [])
            self.assertEqual(summary["status"], "failed")

    def test_unparseable_cache_is_empty_not_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / filings.CACHE).write_text('["not-an-object"]', encoding="utf-8")
            rows, summary = filings.collect_filings(False, date(2026, 11, 1), state=state)
            self.assertEqual(rows, [])
            self.assertEqual(summary["status"], "none")

    def test_integration_line_is_connected(self):
        line = collect.sec_integration({"status": "ok", "filings": 3})
        self.assertEqual(line["status"], "connected")
        self.assertIn("Item 1.05", line["message"])
        self.assertIn("3 in the current window", line["message"])


if __name__ == "__main__":
    unittest.main()
