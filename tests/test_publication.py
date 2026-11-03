"""Schema 7 publication: the briefs file, per-file byte bounds and resuming from the deployed files."""
import contextlib
from datetime import date, timedelta
import hashlib
import io
import json
import unittest
from unittest import mock

import support
from intelligence_hub import collect
from intelligence_hub import archive
from intelligence_hub.archive import validate_snapshot
from intelligence_hub.mitigations import brief_index, join_publication, split_publication

FIXED = "2026-11-01T12:00:00+00:00"
START, END = date(1998, 1, 1), date(2026, 11, 1)


def sha(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def synthetic_cache(publisher_rows, kev_rows):
    """A retained public cache with synthetic publisher rows and KEV records. No real publisher text."""
    sources = [item for item in support.sources() if "include_terms" not in item and "entry_selection" not in item]
    observations, made = {}, 0
    for source in sources:
        count = min(600, publisher_rows - made)
        if count <= 0:
            break
        host = source["article_hosts"][0]
        articles = []
        for position in range(count):
            number = made + position
            url = "https://" + host + "/synthetic/" + source["id"] + "/" + str(position)
            day = END - timedelta(days=number % 9000)
            articles.append({"id": "feed-" + sha(url)[:20], "title": "Synthetic entry " + str(number) + " from " + source["name"], "url": url,
                             "source_id": source["id"], "source_name": source["name"], "kind": source["kind"],
                             "published_at": day.isoformat() + "T12:00:00+00:00", "event_date": None, "date_basis": "publication",
                             "summary": "", "cves": ["CVE-2026-" + str(10000 + number % kev_rows)] if number % 5 == 0 else [],
                             "tags": [], "exploitation": "unknown", "references": [], "origin": "publisher-feed"})
        made += count
        observations[source["id"]] = {"status": "ok", "last_attempt": FIXED, "last_success": FIXED, "error": None,
                                      "sha256": sha(source["id"]), "articles": articles, "intake": None}
    if made != publisher_rows:
        raise AssertionError("The source registry cannot hold the requested synthetic rows.")
    vulnerabilities = [{"cveID": "CVE-2026-" + str(10000 + number), "vendorProject": "Synthetic Vendor " + str(number % 40),
                        "product": "Synthetic Product " + str(number % 90), "vulnerabilityName": "Synthetic catalog record " + str(number),
                        "dateAdded": (END - timedelta(days=number % 1800)).isoformat(), "shortDescription": "Synthetic record for the bound test.",
                        "requiredAction": "Synthetic action text.", "dueDate": END.isoformat(), "knownRansomwareCampaignUse": "Unknown",
                        "notes": "", "cwes": []} for number in range(kev_rows)]
    catalog = {"title": "Synthetic catalog", "catalogVersion": "2026.11.01", "dateReleased": "2026-11-01T00:00:00.000Z",
               "count": kev_rows, "vulnerabilities": vulnerabilities}
    kev = {"status": "ok", "last_attempt": FIXED, "last_success": FIXED, "error": None, "sha256": sha("kev"), "catalog": catalog, "intake": None}
    return {"sources": observations, "kev": kev}


class Workspace:
    """A temporary copy of the build inputs, built in this process with a fixed clock."""

    def __init__(self, cache=None):
        self.copy = support.BuildCopy()
        self.root = self.copy.root
        if cache is not None:
            (self.root / ".state" / "public-cache.json").write_text(json.dumps(cache), encoding="utf-8")
        self.log = ""

    def build(self, **options):
        log = io.StringIO()
        try:
            with mock.patch.object(collect, "ROOT", self.root), mock.patch.object(collect, "STATE", self.root / ".state"), \
                    mock.patch.object(collect, "now", return_value=FIXED), contextlib.redirect_stderr(log):
                return collect.build_snapshot(START, END, refresh=False, **options)
        finally:
            self.log = log.getvalue()

    def raw(self, name):
        return (self.root / "site" / "data" / name).read_bytes()

    def json(self, name):
        return json.loads(self.raw(name).decode("utf-8"))

    def close(self):
        self.copy.close()


class BoundTest(unittest.TestCase):
    def test_9000_synthetic_rows_publish_within_bounds(self):
        cache = synthetic_cache(publisher_rows=7500, kev_rows=1500)
        workspace = Workspace(cache)
        try:
            result = workspace.build()
            feed_raw, briefs_raw = workspace.raw("feed.json"), workspace.raw("briefs.json")
            feed, briefs = workspace.json("feed.json"), workspace.json("briefs.json")
            self.assertNotIn("mitigations", feed)
            self.assertEqual(feed["schema_version"], 7)
            validate_snapshot(feed)
            validate_snapshot(join_publication(feed, briefs))
            # 9,000 synthetic rows plus the curated history: past the old 8,000-row abort.
            history = json.loads((support.ROOT / "config/history.json").read_text(encoding="utf-8"))["entries"]
            self.assertEqual(len(feed["articles"]), 9000 + len(history))
            self.assertGreater(len(feed["articles"]), collect.LEGACY_MAX_ARTICLES)
            kev_ids = {item["cveID"] for item in cache["kev"]["catalog"]["vulnerabilities"]}
            self.assertEqual({article["cves"][0] for article in feed["articles"] if article["origin"] == "cisa-kev"}, kev_ids)
            self.assertTrue({entry["id"] for entry in history} <= {article["id"] for article in feed["articles"]})
            self.assertTrue(kev_ids <= set(briefs["briefs"]))
            self.assertLessEqual(len(feed_raw), collect.FEED_MAX_BYTES)
            self.assertLessEqual(len(briefs_raw), collect.BRIEFS_MAX_BYTES)
            self.assertEqual([item["bytes"] for item in result["publication"]], [len(feed_raw), len(briefs_raw)])
            self.assertTrue(all(item["headroom"] == item["limit"] - item["bytes"] for item in result["publication"]))
            self.assertIn("data/feed.json: " + format(len(feed_raw), ",") + " of 8,388,608 bytes", workspace.log)
            self.assertIn("data/briefs.json: " + format(len(briefs_raw), ",") + " of 12,582,912 bytes", workspace.log)
            rows = len(feed["articles"])
            self.assertIn("data/feed.json: " + format(rows, ",") + " of 27,962 article rows, " + format(27962 - rows, ",") + " of headroom", workspace.log)
            self.assertIn("data/briefs.json: " + format(len(briefs["briefs"]), ",") + " of 15,000 CVE briefs", workspace.log)
            self.assertEqual([item["count"] for item in result["rows"]], [rows, len(briefs["briefs"])])
            workspace.build()
            self.assertEqual(workspace.raw("feed.json"), feed_raw, "the same inputs must give the same feed bytes")
            self.assertEqual(workspace.raw("briefs.json"), briefs_raw, "the same inputs must give the same briefs bytes")
        finally:
            workspace.close()

    def test_more_than_15000_rows_publish_under_the_byte_bound(self):
        # The old structure bound held every JSON array to 15,000 items. These 15,174
        # rows fit the 8 MiB feed bound, so they must publish.
        cache = synthetic_cache(publisher_rows=13500, kev_rows=1600)
        workspace = Workspace(cache)
        try:
            workspace.build()
            feed_raw, feed, briefs = workspace.raw("feed.json"), workspace.json("feed.json"), workspace.json("briefs.json")
        finally:
            workspace.close()
        history = json.loads((support.ROOT / "config/history.json").read_text(encoding="utf-8"))["entries"]
        self.assertEqual(len(feed["articles"]), 15100 + len(history))
        self.assertLessEqual(len(feed_raw), collect.FEED_MAX_BYTES)
        validate_snapshot(feed)
        validate_snapshot(join_publication(feed, briefs))

    def test_the_row_ceiling_is_derived_from_the_byte_bound(self):
        self.assertEqual(collect.MAX_FEED_ROWS, collect.FEED_MAX_BYTES // collect.MIN_ROW_BYTES)
        self.assertEqual(collect.MAX_FEED_ROWS, 27962)
        self.assertGreater(collect.MAX_FEED_ROWS, archive.MAX_ARRAY)
        self.assertEqual(archive.MAX_FEED_ROWS, collect.MAX_FEED_ROWS)
        rows = [{"id": str(number)} for number in range(archive.MAX_ARRAY + 1)]
        archive.tree({"articles": rows}, articles=collect.MAX_FEED_ROWS, nodes=archive.FEED_MAX_NODES)
        with self.assertRaisesRegex(ValueError, "JSON array exceeds archive bounds"):
            archive.tree({"articles": rows})
        with self.assertRaisesRegex(ValueError, "JSON array exceeds archive bounds"):
            archive.tree({"articles": [], "other": rows}, articles=collect.MAX_FEED_ROWS, nodes=archive.FEED_MAX_NODES)

    def test_crossing_the_row_ceiling_fails_with_a_clear_message(self):
        workspace = Workspace()
        try:
            with mock.patch.object(collect, "MAX_FEED_ROWS", 50):
                with self.assertRaisesRegex(ValueError, r"data/feed\.json would hold [0-9,]+ article rows, over its 50-row ceiling "
                                                        r"\(the 8,388,608-byte feed bound / 300 bytes per row\)\. Nothing was evicted"):
                    workspace.build()
            self.assertRegex(workspace.log, r"data/feed\.json: [0-9,]+ of 50 article rows, -[0-9,]+ of headroom \(0% free\)")
            self.assertFalse((workspace.root / "site" / "data").exists())
            self.assertFalse((workspace.root / ".state" / "collection-result.json").exists())
        finally:
            workspace.close()

    def test_the_validator_names_the_row_ceiling(self):
        workspace = Workspace()
        try:
            workspace.build()
            feed = workspace.json("feed.json")
        finally:
            workspace.close()
        ceiling = len(feed["articles"]) - 1
        with mock.patch.object(collect, "MAX_FEED_ROWS", ceiling), mock.patch.object(archive, "MAX_FEED_ROWS", ceiling):
            with self.assertRaisesRegex(ValueError, "over its " + format(ceiling, ",") + "-row ceiling"):
                validate_snapshot(feed)

    def test_crossing_the_cve_ceiling_fails_with_a_clear_message(self):
        workspace = Workspace()
        try:
            with mock.patch("intelligence_hub.mitigations.MAX_RECORDS", 3):
                with self.assertRaisesRegex(ValueError, r"CVEs, over the 3-brief ceiling\. Nothing was evicted"):
                    workspace.build()
            self.assertFalse((workspace.root / "site" / "data").exists())
        finally:
            workspace.close()

    def test_a_crossed_bound_fails_the_run_and_writes_nothing(self):
        for name in ("FEED_MAX_BYTES", "BRIEFS_MAX_BYTES"):
            with self.subTest(bound=name):
                workspace = Workspace()
                try:
                    with mock.patch.object(collect, name, 1000):
                        with self.assertRaisesRegex(ValueError, "Nothing was evicted"):
                            workspace.build()
                    self.assertFalse((workspace.root / "site" / "data").exists())
                    self.assertFalse((workspace.root / ".state" / "collection-result.json").exists())
                finally:
                    workspace.close()

    def test_validators_mirror_the_feed_bound(self):
        workspace = Workspace()
        try:
            workspace.build()
            feed = workspace.json("feed.json")
        finally:
            workspace.close()
        feed["coverage"]["notes"].append("x" * 2000)
        with mock.patch("intelligence_hub.archive.FEED_MAX_BYTES", len(collect.public_bytes(feed)) - 1):
            with self.assertRaisesRegex(ValueError, "byte bound"):
                validate_snapshot(feed)

    def test_app_and_workflow_mirror_the_bounds(self):
        app = (support.ROOT / "site" / "app.js").read_text(encoding="utf-8")
        self.assertIn("const maximumFeedBytes = " + str(collect.FEED_MAX_BYTES // 1048576) + " * 1024 * 1024;", app)
        self.assertIn("const maximumBriefsBytes = " + str(collect.BRIEFS_MAX_BYTES // 1048576) + " * 1024 * 1024;", app)
        self.assertIn("const maximumArticles = " + str(collect.MAX_FEED_ROWS) + ";", app)
        from intelligence_hub.mitigations import INDEX_FIELDS
        self.assertIn("const indexFields = " + json.dumps(list(INDEX_FIELDS)) + ";", app)
        workflow = (support.ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        # The package check, with its allowlist and caps, lives in intelligence_hub/shards.py.
        self.assertIn("run: python3 -m intelligence_hub.shards package site", workflow)
        from intelligence_hub import shards
        # The caps approved in decision O2 (gate G-H01).
        self.assertEqual((shards.PACKAGE_MAX_INPUT, shards.PACKAGE_MAX_COMPRESSED, shards.PACKAGE_MAX_FILES, shards.V7_FILE_MAX_BYTES),
                         (192 * 1024 * 1024, 48000000, 4000, 4 * 1024 * 1024))
        for text in ("4,000", "4 MiB per v7 shard or export file", "192 MiB input", "48,000,000-byte"):
            self.assertIn(text, workflow)
        self.assertLess(collect.FEED_MAX_BYTES + collect.BRIEFS_MAX_BYTES + 512 * 1024, shards.PACKAGE_MAX_INPUT)


class BriefsFileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workspace = Workspace()
        try:
            workspace.build()
            cls.feed, cls.briefs = workspace.json("feed.json"), workspace.json("briefs.json")
            cls.feed_raw, cls.briefs_raw = workspace.raw("feed.json"), workspace.raw("briefs.json")
        finally:
            workspace.close()

    def joined(self):
        return join_publication(json.loads(self.feed_raw), json.loads(self.briefs_raw))

    def test_feed_keeps_only_the_compact_index(self):
        self.assertNotIn("mitigations", self.feed)
        rows = self.feed["brief_index"]["rows"]
        self.assertEqual(set(rows), set(self.briefs["briefs"]))
        brief = self.briefs["briefs"]["CVE-2026-99991"]
        self.assertEqual(rows["CVE-2026-99991"][0:4], [brief["record_state"], brief["source_status"],
                                                       brief["analysis"]["guidance_status"], bool(brief["required_action"])])
        self.assertEqual(rows["CVE-2026-99991"][6], "2026-10-27")  # KEV date added

    def test_split_and_join_round_trip(self):
        joined = self.joined()
        validate_snapshot(joined)
        feed, briefs = split_publication(joined)
        self.assertEqual(collect.public_bytes(feed), self.feed_raw)
        self.assertEqual(collect.public_bytes(briefs), self.briefs_raw)

    def test_files_from_different_runs_are_refused(self):
        briefs = json.loads(self.briefs_raw)
        briefs["content_revision"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "different feed snapshot"):
            join_publication(json.loads(self.feed_raw), briefs)
        with self.assertRaises(ValueError):
            join_publication(self.joined(), json.loads(self.briefs_raw))

    def test_index_must_match_its_briefs(self):
        joined = self.joined()
        cve = next(iter(joined["brief_index"]["rows"]))
        joined["brief_index"]["rows"][cve][3] = not joined["brief_index"]["rows"][cve][3]
        with self.assertRaisesRegex(ValueError, "brief index differs"):
            validate_snapshot(joined)
        feed = json.loads(self.feed_raw)
        del feed["brief_index"]["rows"][cve]
        with self.assertRaisesRegex(ValueError, "exactly cover"):
            validate_snapshot(feed)

    def test_index_is_derived_in_cve_order(self):
        self.assertEqual(self.feed["brief_index"], brief_index(self.briefs["briefs"]))
        self.assertEqual(list(self.feed["brief_index"]["rows"]), sorted(self.briefs["briefs"]))


class ResumeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        BriefsFileTest.setUpClass()
        cls.feed_raw, cls.briefs_raw = BriefsFileTest.feed_raw, BriefsFileTest.briefs_raw

    def serve(self, files):
        def fetch(url, maximum=collect.MAX_BYTES, fresh=False):
            self.assertTrue(fresh, "resume reads must ask the CDN for a fresh copy")
            value = files[url]
            if isinstance(value, list):
                value = value.pop(0) if len(value) > 1 else value[0]
            if isinstance(value, Exception):
                raise value
            self.assertLessEqual(len(value), maximum)
            return value
        return mock.patch.object(collect, "fetch", side_effect=fetch)

    def resume(self):
        return collect.resume_deployed(support.sources(), {"sources": {}, "kev": {}})

    def test_resumes_from_feed_and_briefs(self):
        with self.serve({collect.PUBLIC_FEED: self.feed_raw, collect.PUBLIC_BRIEFS: self.briefs_raw}):
            previous, reason = self.resume()
        self.assertIsNone(reason)
        self.assertEqual(set(previous["mitigations"]), set(json.loads(self.briefs_raw)["briefs"]))

    def test_missing_briefs_stop_the_resume_with_a_reason(self):
        with self.serve({collect.PUBLIC_FEED: self.feed_raw, collect.PUBLIC_BRIEFS: OSError("HTTP Error 404: Not Found")}):
            previous, reason = self.resume()
        self.assertIsNone(previous)
        self.assertEqual(reason, "OSError: HTTP Error 404: Not Found")

    def test_mismatched_briefs_stop_the_resume_with_a_reason(self):
        briefs = json.loads(self.briefs_raw)
        briefs["generated_at"] = "2026-10-31T12:00:00+00:00"
        with self.serve({collect.PUBLIC_FEED: self.feed_raw, collect.PUBLIC_BRIEFS: collect.public_bytes(briefs)}):
            previous, reason = self.resume()
        self.assertIsNone(previous)
        self.assertEqual(reason, "ValueError: The briefs file belongs to a different feed snapshot.")

    def test_a_cdn_generation_mismatch_is_fetched_once_more(self):
        briefs = json.loads(self.briefs_raw)
        briefs["generated_at"] = "2026-10-31T12:00:00+00:00"
        stale = collect.public_bytes(briefs)
        with self.serve({collect.PUBLIC_FEED: [self.feed_raw], collect.PUBLIC_BRIEFS: [stale, self.briefs_raw]}) as fetch, \
                contextlib.redirect_stderr(io.StringIO()) as log:
            previous, reason = self.resume()
        self.assertIsNone(reason)
        self.assertIn("mitigations", previous)
        # One read of the undeployed v7 index, then the feed and briefs twice.
        self.assertEqual(fetch.call_count, 5)
        self.assertIn("fetching both once more", log.getvalue())

    def test_fresh_reads_send_no_cache_headers(self):
        seen = {}

        class Response:
            status, length = 200, None
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def geturl(self):
                return collect.PUBLIC_FEED

            def read1(self, _size):
                return b""

        class Opener:
            def open(self, request, timeout):
                seen.update({key.lower(): value for key, value in request.header_items()})
                return Response()

        with mock.patch.object(collect.urllib.request, "build_opener", return_value=Opener()):
            collect.fetch(collect.PUBLIC_FEED, collect.FETCH_CEILING, fresh=True)
        self.assertEqual((seen.get("cache-control"), seen.get("pragma")), ("no-cache", "no-cache"))
        seen.clear()
        with mock.patch.object(collect.urllib.request, "build_opener", return_value=Opener()):
            collect.fetch(collect.PUBLIC_FEED, collect.FETCH_CEILING)
        self.assertNotIn("cache-control", seen)

    def test_schema_6_feed_with_inline_briefs_still_resumes(self):
        legacy = join_publication(json.loads(self.feed_raw), json.loads(self.briefs_raw))
        del legacy["brief_index"]
        legacy["schema_version"] = 6
        with self.serve({collect.PUBLIC_FEED: collect.public_bytes(legacy)}) as fetch:
            previous, reason = self.resume()
        self.assertIsNone(reason)
        self.assertIn("mitigations", previous)
        self.assertEqual([call.args[0] for call in fetch.call_args_list], [collect.PUBLIC_V7 + "index.json", collect.PUBLIC_FEED])

    def test_build_reports_why_the_resume_failed(self):
        workspace = Workspace()
        try:
            with mock.patch.object(collect, "resume_deployed", return_value=(None, "OSError: timed out")):
                with self.assertRaisesRegex(ValueError, r"resumed safely \(OSError: timed out\)"):
                    workspace.build(resume_public=True)
        finally:
            workspace.close()


if __name__ == "__main__":
    unittest.main()
