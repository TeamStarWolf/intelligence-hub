"""FIRST's EPSS scores on the briefs (WP-03): the batched API read, the recorded answer for five
CVEs (tests/fixtures/epss/response.json, read from api.first.org on 2026-11-12), a failed batch
leaving the last good values, the model pin, the brief and index fields, the archive validator,
the export columns and the offline build."""
import copy
import json
import unittest
import urllib.parse
from unittest import mock

import support
from intelligence_hub import collect, epss, exports
from intelligence_hub.archive import validate_snapshot
from intelligence_hub.collect import published, safe_url, text
from intelligence_hub.mitigations import INDEX_FIELDS, INDEX_VERSION, blank, brief_index, build_briefs, index_row, join_publication, merge_retained, valid_projection
import test_exports
import test_publication

FIXTURE = support.ROOT / "tests" / "fixtures" / "epss" / "response.json"
RECORDED = ["CVE-2024-3400", "CVE-2021-44228", "CVE-2026-20320", "CVE-1999-0001", "CVE-2026-999999"]
STAMP = "2026-11-01T12:00:00+00:00"


def fixture_bytes():
    return FIXTURE.read_bytes()


def score(value=0.5, percentile=0.9, day="2026-11-10", model=epss.MODEL):
    return {"score": value, "percentile": percentile, "date": day, "model": model}


def ids_in(url):
    """The CVE ids a batch URL asks for."""
    return urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["cve"][0].split(",")


def answer(entries):
    return json.dumps({"status": "OK", "status-code": 200, "version": "1.0", "access": "public", "total": len(entries), "offset": 0, "limit": 100,
                       "data": entries}).encode("utf-8")


class RecordedAnswerTest(unittest.TestCase):
    def test_the_recorded_answer_scores_four_of_the_five_requested_cves(self):
        scores = epss.parse_scores(fixture_bytes(), RECORDED)
        self.assertEqual(sorted(scores), ["CVE-1999-0001", "CVE-2021-44228", "CVE-2024-3400", "CVE-2026-20320"])
        self.assertEqual(scores["CVE-2024-3400"], {"score": 0.99999, "percentile": 1.0, "date": "2026-11-10", "model": "v2026.06.15"})
        self.assertEqual(scores["CVE-2026-20320"], {"score": 0.00385, "percentile": 0.32917, "date": "2026-11-10", "model": "v2026.06.15"})
        self.assertNotIn("CVE-2026-999999", scores, "a CVE the API did not score has no score on that date, never 0")
        for block in scores.values():
            self.assertTrue(epss.valid_score(block))

    def test_the_model_is_pinned_and_dated(self):
        self.assertEqual(epss.MODEL, "v2026.06.15")
        self.assertTrue(epss.MODEL_FORM.fullmatch(epss.MODEL))
        self.assertEqual(published(epss.MODEL_CONFIRMED), epss.MODEL_CONFIRMED)
        self.assertEqual(epss.MAX_BATCHES * epss.BATCH, 15000, "one run can score the whole brief set")

    def test_entries_outside_the_request_or_out_of_range_are_left_out(self):
        entries = [{"cve": "CVE-2026-10001", "epss": "0.5", "percentile": "0.9", "date": "2026-11-10"},
                   {"cve": "CVE-2026-10001", "epss": "0.6", "percentile": "0.9", "date": "2026-11-10"},
                   {"cve": "CVE-2026-10002", "epss": "1.5", "percentile": "0.9", "date": "2026-11-10"},
                   {"cve": "CVE-2026-10003", "epss": "0.5", "percentile": "x", "date": "2026-11-10"},
                   {"cve": "CVE-2026-10004", "epss": "0.5", "percentile": "0.9", "date": "2026-13-10"},
                   {"cve": "CVE-2026-10005", "epss": "0.123456789", "percentile": "0.5", "date": "2026-11-10"},
                   {"cve": "CVE-2026-10009", "epss": "0.5", "percentile": "0.9", "date": "2026-11-10"}, "junk", None]
        scores = epss.parse_scores(answer(entries), ["CVE-2026-1000" + str(number) for number in range(1, 6)])
        self.assertEqual(sorted(scores), ["CVE-2026-10001", "CVE-2026-10005"])
        self.assertEqual(scores["CVE-2026-10001"]["score"], 0.5, "the first entry for a CVE is the one read")
        self.assertEqual(scores["CVE-2026-10005"]["score"], 0.12346, "scores keep five decimals")

    def test_a_document_that_is_not_the_api_answer_refuses_the_batch(self):
        for raw in (b"not json", b"[]", b'{"status":"ERROR","data":[]}', b'{"status":"OK","data":"x"}', b'{"status":"OK","data":' + b"[{}," * 300 + b"{}]}"):
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(ValueError):
                    epss.parse_scores(raw, ["CVE-2026-10001"])

    def test_valid_score_holds_the_block_to_its_shape(self):
        self.assertTrue(epss.valid_score(score()))
        for bad in (None, {}, {**score(), "extra": 1}, score(value=1.01), score(value=-0.1), score(value=True), score(percentile="0.9"),
                    score(day="2026-11-31"), score(day="2026-11-10T00:00:00Z"), score(day=None), score(day=20261110), score(model="2026.06.15"), score(model=5)):
            with self.subTest(bad=bad):
                self.assertFalse(epss.valid_score(bad))


class BatchTest(unittest.TestCase):
    def test_requests_go_in_sorted_batches_of_100(self):
        cves = ["CVE-2026-" + str(10000 + number) for number in range(250)]
        urls = []

        def fetch(url, maximum=None, **options):
            urls.append((url, maximum, options.get("accept")))
            ids = ids_in(url)
            return answer([{"cve": cve, "epss": "0.01", "percentile": "0.5", "date": "2026-11-10"} for cve in ids])

        scores, report = epss.collect_scores(list(reversed(cves)) + ["not-a-cve"], fetch)
        self.assertEqual([len(ids_in(url)) for url, _, _ in urls], [100, 100, 50])
        self.assertTrue(all(url.startswith(epss.API_URL + "?cve=CVE-") and url.endswith("&limit=100") for url, _, _ in urls))
        self.assertTrue(all(safe_url(url) == url for url, _, _ in urls), "every batch URL is in the collector's canonical form, so collect.fetch accepts it")
        self.assertEqual({maximum for _, maximum, _ in urls}, {epss.RESPONSE_MAX_BYTES})
        self.assertEqual({accept for _, _, accept in urls}, {"application/json"})
        first = ids_in(urls[0][0])
        self.assertEqual(first, sorted(cves)[:100], "batches are the sorted ids")
        self.assertEqual(len(scores), 250)
        self.assertEqual(report, {"status": "ok", "model": epss.MODEL, "cves": 250, "batches": 3, "completed": 3, "scored": 250, "date": "2026-11-10", "failed": None})

    def test_a_429_leaves_the_last_good_values_and_ends_the_reads(self):
        cves = ["CVE-2026-" + str(10000 + number) for number in range(250)]
        calls = []

        def fetch(url, maximum=None, **options):
            calls.append(url)
            ids = ids_in(url)
            if len(calls) == 2:
                raise OSError("HTTP 429")
            return answer([{"cve": cve, "epss": "0.02", "percentile": "0.6", "date": "2026-11-10"} for cve in ids[:-1]])

        scores, report = epss.collect_scores(cves, fetch)
        self.assertEqual(len(calls), 2, "the first failed batch ends the run's reads")
        # The first batch is complete: 99 scored, the batch's last CVE has no score on that date.
        self.assertEqual(len(scores), 100)
        self.assertEqual(sum(block is not None for block in scores.values()), 99)
        self.assertIsNone(scores[sorted(cves)[99]])
        # The second and third batches are absent, so their retained values stay.
        self.assertNotIn(sorted(cves)[100], scores)
        self.assertEqual((report["status"], report["completed"], report["scored"], report["failed"]), ("partial", 1, 99, "OSError: HTTP 429"))
        failed_first, report = epss.collect_scores(cves[:5], lambda url, maximum=None, **options: (_ for _ in ()).throw(OSError("HTTP 503")))
        self.assertEqual((failed_first, report["status"], report["completed"]), ({}, "failed", 0))

    def test_the_batch_limit_bounds_a_run(self):
        cves = ["CVE-2026-" + str(10000 + number) for number in range(250)]
        fetch = lambda url, maximum=None, **options: answer([{"cve": cve, "epss": "0.01", "percentile": "0.5", "date": "2026-11-10"} for cve in ids_in(url)])
        scores, report = epss.collect_scores(cves, fetch, limit=2)
        self.assertEqual((len(scores), report["status"], report["completed"], report["failed"]), (200, "partial", 2, "batch limit of 2 reached"))
        scores, report = epss.collect_scores([], fetch)
        self.assertEqual((scores, report["status"], report["batches"]), ({}, "ok", 0))
        self.assertEqual(epss.skipped(["CVE-2026-10001", "CVE-2026-10001", "x"], "offline")["cves"], 1)
        with self.assertRaisesRegex(ValueError, "Invalid EPSS batch"):
            epss.batch_url([])
        with self.assertRaisesRegex(ValueError, "Invalid EPSS batch"):
            epss.batch_url(["x"])


class BriefTest(unittest.TestCase):
    def briefs(self, retained=None, scores=None, cves=("CVE-2026-90001", "CVE-2026-90002")):
        return build_briefs([{"cves": list(cves)}], {}, retained or {}, False, 0, None, text, safe_url, published, STAMP, scores=scores)

    def test_a_read_value_lands_on_the_brief_and_a_missing_one_keeps_the_retained_value(self):
        retained = {"CVE-2026-90002": {**blank("CVE-2026-90002"), "epss": score(0.3, 0.8, "2026-11-09")}}
        briefs, projections, _ = self.briefs(retained, {"CVE-2026-90001": score()})
        self.assertEqual(briefs["CVE-2026-90001"]["epss"], score())
        self.assertEqual(briefs["CVE-2026-90002"]["epss"], score(0.3, 0.8, "2026-11-09"), "a CVE outside the completed batches keeps its retained value")
        self.assertEqual(projections["CVE-2026-90002"]["epss"], score(0.3, 0.8, "2026-11-09"), "the retained projections carry it to the next run")
        # A CVE the API did not score on the day loses its retained value: no score, never 0.
        briefs, _, _ = self.briefs(retained, {"CVE-2026-90002": None})
        self.assertIsNone(briefs["CVE-2026-90002"]["epss"])
        self.assertIsNone(blank("CVE-2026-90001")["epss"])
        with self.assertRaisesRegex(ValueError, "Invalid EPSS score"):
            self.briefs(None, {"CVE-2026-90001": {"score": 2}})

    def test_a_retained_record_with_a_bad_block_is_refused_and_one_without_the_field_reads_as_none(self):
        good = {**blank("CVE-2026-90001"), "epss": score()}
        self.assertTrue(valid_projection(good, "CVE-2026-90001", safe_url, published))
        self.assertTrue(valid_projection({**blank("CVE-2026-90001"), "epss": None}, "CVE-2026-90001", safe_url, published))
        older = blank("CVE-2026-90001")
        del older["epss"]
        self.assertTrue(valid_projection(older, "CVE-2026-90001", safe_url, published))
        briefs, _, _ = self.briefs({"CVE-2026-90001": older})
        self.assertIsNone(briefs["CVE-2026-90001"]["epss"])
        self.assertFalse(valid_projection({**good, "epss": {"score": 0.5}}, "CVE-2026-90001", safe_url, published))

    def test_a_resume_merges_the_newest_score_apart_from_the_cna_facts(self):
        cve = "CVE-2026-90001"
        local = {**blank(cve), "epss": score(0.3, 0.8, "2026-11-09")}
        remote = {**blank(cve), "epss": score(0.5, 0.9, "2026-11-10")}
        # Neither record has a successful CNA read: the facts are blank, the newest score still survives.
        self.assertEqual(merge_retained(local, remote, cve, safe_url, published)["epss"], score(0.5, 0.9, "2026-11-10"))
        self.assertEqual(merge_retained(remote, local, cve, safe_url, published)["epss"], score(0.5, 0.9, "2026-11-10"))
        self.assertEqual(merge_retained(local, None, cve, safe_url, published)["epss"], score(0.3, 0.8, "2026-11-09"))
        self.assertIsNone(merge_retained({**blank(cve), "epss": None}, None, cve, safe_url, published)["epss"])
        # A successful CNA read on the record without a score does not erase the other record's score.
        read = {**blank(cve), "source_status": "ok", "record_state": "PUBLISHED", "retrieved_at": STAMP, "source_attempted_at": STAMP, "source_sha256": "a" * 64}
        merged = merge_retained(read, local, cve, safe_url, published)
        self.assertEqual((merged["source_status"], merged["epss"]), ("ok", score(0.3, 0.8, "2026-11-09")))
        # Equal CNA clocks never decide: the newer score date wins whichever record carries it.
        older_read = {**read, "epss": score(0.1, 0.2, "2026-11-01")}
        newer_read = {**read, "epss": score(0.2, 0.3, "2026-11-10")}
        self.assertEqual(merge_retained(older_read, newer_read, cve, safe_url, published)["epss"], score(0.2, 0.3, "2026-11-10"))
        self.assertEqual(merge_retained(newer_read, older_read, cve, safe_url, published)["epss"], score(0.2, 0.3, "2026-11-10"))

    def test_the_index_carries_the_block_last(self):
        briefs, _, _ = self.briefs(None, {"CVE-2026-90001": score()})
        self.assertEqual(INDEX_FIELDS[-1], "epss")
        self.assertEqual(index_row(briefs["CVE-2026-90001"])[-1], score())
        self.assertIsNone(index_row(briefs["CVE-2026-90002"])[-1])
        self.assertEqual(brief_index(briefs)["version"], INDEX_VERSION)
        self.assertEqual(len(index_row(briefs["CVE-2026-90001"], 2)), len(INDEX_FIELDS) - 1)


class PublicationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_publication.BriefsFileTest.setUpClass()
        cls.feed_raw, cls.briefs_raw = test_publication.BriefsFileTest.feed_raw, test_publication.BriefsFileTest.briefs_raw

    def joined(self):
        return join_publication(json.loads(self.feed_raw), json.loads(self.briefs_raw))

    def test_the_offline_build_carries_no_score_and_says_so(self):
        feed, briefs = json.loads(self.feed_raw), json.loads(self.briefs_raw)
        self.assertTrue(all(brief["epss"] is None for brief in briefs["briefs"].values()), "an offline build reads nothing")
        self.assertEqual(feed["brief_index"]["version"], 3)
        self.assertTrue(all(row[-1] is None for row in feed["brief_index"]["rows"].values()))
        validate_snapshot(feed)
        validate_snapshot(self.joined())

    def test_a_scored_block_validates_fills_the_index_and_a_bad_one_is_refused(self):
        joined = self.joined()
        cve = next(iter(joined["mitigations"]))
        joined["mitigations"][cve]["epss"] = score()
        joined["brief_index"] = brief_index(joined["mitigations"])
        validate_snapshot(joined)
        self.assertEqual(joined["brief_index"]["rows"][cve][-1], score())
        feed = copy.deepcopy({key: item for key, item in joined.items() if key != "mitigations"})
        validate_snapshot(feed)
        feed["brief_index"]["rows"][cve][-1] = {"score": 0.5}
        with self.assertRaisesRegex(ValueError, "Invalid brief index EPSS"):
            validate_snapshot(feed)
        joined["mitigations"][cve]["epss"] = {"score": 1.5, "percentile": 0.9, "date": "2026-11-10", "model": epss.MODEL}
        with self.assertRaisesRegex(ValueError, "Invalid structured CVE provenance"):
            validate_snapshot(joined)
        joined["mitigations"][cve]["epss"] = score(0.4)
        with self.assertRaisesRegex(ValueError, "brief index differs"):
            validate_snapshot(joined)

    def test_the_index_counts_name_the_model_and_the_score_date(self):
        briefs = {"a": {"epss": score(day="2026-11-09")}, "b": {"epss": score(day="2026-11-10")}, "c": {"epss": None}}
        self.assertEqual(collect.epss_counts(briefs), {"epss_scored": 2, "epss_model": epss.MODEL, "epss_date": "2026-11-10", "epss_oldest_date": "2026-11-09"})
        self.assertEqual(collect.epss_counts({}), {"epss_scored": 0, "epss_model": epss.MODEL, "epss_date": None, "epss_oldest_date": None})

    def test_the_block_costs_a_bounded_number_of_bytes_per_brief(self):
        full = {"epss": {"score": 0.99999, "percentile": 1.0, "date": "2026-11-10", "model": "v2026.06.15"}}
        self.assertLessEqual(len(collect.public_bytes(full)) - len(collect.public_bytes({"epss": None})), 80)


class ExportTest(unittest.TestCase):
    def test_the_best_score_on_a_row_fills_the_four_columns_and_the_jsonl_block(self):
        rows = [test_exports.article("feed-e", "Two CVEs on one row", "2026-10-03T00:00:00+00:00", cves=["CVE-2026-90002", "CVE-2026-90001"]),
                test_exports.article("feed-f", "No score here", "2026-10-04T00:00:00+00:00", cves=["CVE-2026-90003"])]
        scores = {"CVE-2026-90001": score(0.2, 0.7), "CVE-2026-90002": score(0.8, 0.99, "2026-11-09")}
        files, blocks = test_exports.build(rows)
        ctx_files = exports.build_exports(rows, blocks, test_exports.REGISTRY, test_exports.INFO, {"cisa-kev": "government-cert"}, scores=scores)
        table = test_exports.parse(ctx_files["articles-2026.csv"])
        header = table[0]
        self.assertEqual(header[header.index("cvss_scorer") + 1:header.index("cvss_scorer") + 5], ["epss", "epss_percentile", "epss_date", "epss_model"])
        by_id = {line[0]: dict(zip(header, line)) for line in table[1:]}
        self.assertEqual([by_id["feed-e"][name] for name in ("epss", "epss_percentile", "epss_date", "epss_model")], ["0.8", "0.99", "2026-11-09", epss.MODEL])
        self.assertEqual([by_id["feed-f"][name] for name in ("epss", "epss_percentile", "epss_date", "epss_model")], ["", "", "", ""], "a missing score is empty, never 0")
        lines = {json.loads(line)["id"]: json.loads(line) for line in ctx_files["articles-2026.jsonl"].decode("utf-8").splitlines()}
        self.assertEqual(lines["feed-e"]["epss"], {**score(0.8, 0.99, "2026-11-09"), "cve": "CVE-2026-90002"})
        self.assertIsNone(lines["feed-f"]["epss"])
        self.assertEqual(exports.best_epss({"cves": ["CVE-2026-90001", "CVE-2026-90000"]}, {"CVE-2026-90000": score(0.2), "CVE-2026-90001": score(0.2)})["cve"], "CVE-2026-90000", "ties go to the lowest id")
        tiny = exports.epss_fields({"cves": ["CVE-2026-90001"]}, {"CVE-2026-90001": score(0.00004, 1.0)})
        self.assertEqual((tiny["epss"], tiny["epss_percentile"]), ("0.00004", "1"), "a plain decimal, never scientific notation")
        dictionary = ctx_files["data-dictionary.md"].decode("utf-8")
        self.assertIn("| `epss_model` |", dictionary)
        self.assertIn("FIRST asks for attribution", dictionary)
        # Without scores the files are the same as before: the columns are empty.
        self.assertEqual(files["articles-2026.csv"], exports.build_exports(rows, blocks, test_exports.REGISTRY, test_exports.INFO, {"cisa-kev": "government-cert"})["articles-2026.csv"])


if __name__ == "__main__":
    unittest.main()
