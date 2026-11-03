"""The history framework: adapters against their fixtures, the row rules, the canonical files,
coverage agreement, the polite fetcher, and the publish step's merge into the v7 shards."""
import contextlib
import copy
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import support
from intelligence_hub import collect, shards
from intelligence_hub.history import ADAPTERS, STATIC_SOURCES, base, canonical, check, coverage, publish, registry
from intelligence_hub.history.adapters import msrc_bulletins, msrc_cvrf, nvd_cve, oracle_cpu

FIXTURES = support.ROOT / "tests" / "history" / "fixtures"
YEARS = range(coverage.FIRST_YEAR, coverage.END_YEAR + 1)


def golden(adapter):
    return [json.loads(line) for line in (FIXTURES / adapter / "golden.jsonl").read_text(encoding="utf-8").splitlines() if line]


def write_history(root, rows_by_adapter):
    """A complete, valid history/ tree: the given rows plus a coverage row for every source and year."""
    built = []
    for ident, module in ADAPTERS.items():
        rows = rows_by_adapter.get(ident, [])
        counts = canonical.write_adapter(root, ident, rows, set(YEARS))
        upstream = {}
        for row in rows:
            upstream[int(row["published"][:4])] = upstream.get(int(row["published"][:4]), 0) + 1
        built.extend(coverage.adapter_rows(module, {"upstream": upstream}, counts, YEARS, "2026-11-03"))
    canonical.write_coverage(root, coverage.merge(None, built))


class FixtureTest(unittest.TestCase):
    def test_every_adapter_has_a_fixture(self):
        self.assertEqual(sorted(item.name for item in FIXTURES.iterdir() if item.is_dir()), sorted(ADAPTERS))

    def test_every_fixture_reparses_to_its_golden_file(self):
        self.assertEqual(check.check_fixtures(support.ROOT), sorted(ADAPTERS))

    def test_parsing_is_deterministic(self):
        for name in sorted(ADAPTERS):
            with self.subTest(adapter=name):
                self.assertEqual(check.run_fixture(FIXTURES / name)[0], check.run_fixture(FIXTURES / name)[0])

    def test_fixture_rows_follow_the_row_rules(self):
        for name in sorted(ADAPTERS):
            for row in golden(name):
                base.validate_row(row, ADAPTERS)
                self.assertEqual(row["adapter"], name)


class MarinerTest(unittest.TestCase):
    """MSRC's update list files "Mariner Release Notes" under ids such as 1999-Sep; none may become a row."""

    def setUp(self):
        self.module, self.documents, self.years, self.context, _stats = check.load_fixture(FIXTURES / "msrc-cvrf")

    def test_mariner_documents_are_not_selected(self):
        updates = json.loads(self.documents["updates.json"].raw)
        mariner = {item["ID"] for item in updates["value"] if item["DocumentTitle"] == "Mariner Release Notes"}
        self.assertEqual(mariner, {"1999-Sep", "2024-Jul"})
        chosen = {ident for _month, ident, _url in msrc_cvrf.selected(self.documents["updates.json"].raw, set(range(1990, 2030)))}
        self.assertEqual(chosen, {"2016-Apr"})

    def test_mariner_cves_never_become_rows_even_when_the_document_is_present(self):
        rows, _stats = msrc_cvrf.parse(self.documents, set(range(1990, 2030)), {})
        self.assertNotIn("CVE-1999-0236", {row["native_id"] for row in rows})
        self.assertNotIn("CVE-2024-0001", {row["native_id"] for row in rows})
        self.assertTrue(rows)

    def test_a_mariner_document_under_a_normal_listing_title_is_still_excluded(self):
        rows, seen = msrc_cvrf.rows_from(self.documents["cvrf/1999-Sep.json"], "1999-09-02", None)
        self.assertEqual((rows, seen), ([], 0))

    def test_low_and_unrated_cves_are_filtered_and_exploited_ones_flagged(self):
        rows, _stats = msrc_cvrf.parse(self.documents, self.years, {})
        self.assertNotIn("CVE-2015-7511", {row["native_id"] for row in rows})
        flagged = {row["native_id"] for row in rows if row["exploited_flag"]}
        self.assertEqual(flagged, {"CVE-2016-0167"})


class BulletinPageTest(unittest.TestCase):
    """Bulletin pages state their posted date in four forms; every one must give the original date."""

    PAGE = ("---\ntitle: x\n---\n# Microsoft Security Bulletin MS05-002 - Critical\n\n"
            "## Vulnerability in Cursor and Icon Format Handling (891711)\n\n{stamp}\n\nCVE-2004-1049 is addressed.\n")

    def parsed(self, stamp):
        return msrc_bulletins.from_page(self.PAGE.format(stamp=stamp).encode("utf-8"))

    def test_published_and_updated(self):
        item = self.parsed("Published: January 11, 2005 | Updated: December 09, 2008")
        self.assertEqual((item["published"], item["updated"], item["severity"]), ("2005-01-11", "2008-12-09", "Critical"))
        self.assertEqual(item["cves"], {"CVE-2004-1049"})

    def test_originally_posted(self):
        item = self.parsed("Updated: December 09, 2008\n\nOriginally posted: January 11, 2005")
        self.assertEqual((item["published"], item["updated"]), ("2005-01-11", "2008-12-09"))

    def test_issued(self):
        item = self.parsed("Updated: December 09, 2008\n\n**Issued:** January 11, 2005**Updated:** December 9, 2008**Version:** 2.1")
        self.assertEqual((item["published"], item["updated"]), ("2005-01-11", "2008-12-09"))

    def test_first_revision_line(self):
        item = self.parsed("Updated: November 08, 2006\n\n- V1.0 (October 10, 2006): Bulletin published.\n- V2.0 (November 8, 2006): Re-offered.")
        self.assertEqual((item["published"], item["updated"]), ("2006-10-10", "2006-11-08"))

    def test_a_page_without_a_posted_date_is_unreadable(self):
        self.assertIsNone(self.parsed("Updated: November 08, 2006"))


class DateFormTest(unittest.TestCase):
    def test_publisher_date_forms(self):
        cases = {"June 01, 1998": "1998-06-01", "1 June 1998": "1998-06-01", "May 6th, 2021": "2021-05-06",
                 "January 23rd, 2024": "2024-01-23", "Sep 3, 2024": "2024-09-03", "Sept 6, 2024": "2024-09-06",
                 "Oct. 29, 2024": "2024-10-29", "2nd March 2003": "2003-03-02"}
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(base.long_date(value), expected)

    def test_a_month_without_a_day_or_an_unknown_month_is_not_a_date(self):
        for value in ("August, 2018", "Foo 3, 2024", "February 30, 2024", "Ma 3, 2024"):
            with self.subTest(value=value):
                self.assertIsNone(base.long_date(value))


class OracleLinkTest(unittest.TestCase):
    def test_the_retired_content_host_is_replaced(self):
        self.assertEqual(oracle_cpu.link("http://www-content.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html"),
                         "https://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html")

    def test_other_links_are_left_to_the_https_upgrade(self):
        self.assertEqual(oracle_cpu.link(" http://www.oracle.com/security-alerts/cpujan2025.html "),
                         "http://www.oracle.com/security-alerts/cpujan2025.html")


class NvdFeedTest(unittest.TestCase):
    def test_cve_years_before_2002_are_read_from_the_2002_feed(self):
        self.assertEqual(nvd_cve.feed_years({"CVE-1999-0001", "CVE-2001-0002", "CVE-2002-0003", "CVE-2017-0144", "not-a-cve"}),
                         [2002, 2017])

    def test_feeds_are_fetched_without_an_accept_type_the_host_refuses(self):
        fetcher = mock.Mock()
        fetcher.get.return_value = base.Document(b"x", "2026-11-03T00:00:00Z")
        documents = nvd_cve.fetch(fetcher, set(YEARS), {"referenced": {"CVE-1999-0001"}})
        self.assertEqual(list(documents), ["nvdcve-2.0-2002.json.gz"])
        self.assertEqual(fetcher.get.call_args.args[0], nvd_cve.FEED.format(year=2002))
        self.assertNotIn("accept", fetcher.get.call_args.kwargs)


class RowRuleTest(unittest.TestCase):
    def setUp(self):
        self.row = golden("msrc-bulletins")[0]

    def rejected(self, **change):
        row = dict(self.row, **change)
        with self.assertRaises(base.HistoryError):
            base.validate_row(row, ADAPTERS)

    def test_a_good_row_passes(self):
        base.validate_row(self.row, ADAPTERS)

    def test_unsafe_or_non_canonical_urls_are_refused(self):
        self.rejected(url="http://learn.microsoft.com/x")
        self.rejected(url="https://127.0.0.1/x")
        self.rejected(url="javascript:alert(1)")
        self.rejected(url="https://learn.microsoft.com/x?utm_source=feed")

    def test_identity_and_dates_are_checked(self):
        self.rejected(id="h-msrc-bulletins-MS98-999")
        self.rejected(adapter="not-an-adapter", id="h-not-an-adapter-MS98-001")
        self.rejected(published="1998-6-1")
        self.rejected(updated="1998-05-01")

    def test_exploited_flag_is_never_false(self):
        self.rejected(exploited_flag=False)

    def test_titles_are_plain_text_without_em_dashes(self):
        self.assertEqual(base.text("<b>Alert</b> " + chr(0x2014) + " Update &amp; fix"), "Alert - Update & fix")
        self.rejected(title="Alert " + chr(0x2014) + " Update")
        self.rejected(title="  padded  ")

    def test_lists_are_sorted_and_bounded(self):
        self.rejected(cve=["CVE-1999-0002", "CVE-1999-0001"])
        self.rejected(cve=["CVE-99-1"])
        self.rejected(product_raw=["b", "a"])
        self.rejected(vendor_raw=["v" + str(number) for number in range(21)])

    def test_a_cve_id_dated_after_retrieval_is_a_typo_and_is_dropped(self):
        self.rejected(cve=["CVE-2077-1748"])
        row = base.make_row(ADAPTERS["msrc-bulletins"], native_id="MS07-029", title="DNS RPC", url=self.row["url"],
                            published="2007-05-08", cve=["CVE-2077-1748", "CVE-2007-1748"],
                            retrieved="2026-11-03T00:00:00Z", raw_sha256=self.row["raw_sha256"])
        self.assertEqual(row["cve"], ["CVE-2007-1748"])

    def test_a_row_over_four_kilobytes_is_refused_and_make_row_trims_products_to_fit(self):
        long_names = ["Product " + str(number) + " " + "x" * 90 for number in range(40)]
        self.rejected(product_raw=sorted(long_names[:20]), title="t" * 240)
        row = base.make_row(ADAPTERS["msrc-bulletins"], native_id="MS98-001", title="t" * 240, url=self.row["url"],
                            published="1998-06-01", cve=["CVE-1999-%04d" % number for number in range(100)],
                            product_raw=long_names, retrieved=self.row["retrieved"], raw_sha256=self.row["raw_sha256"])
        base.validate_row(row, ADAPTERS)
        self.assertLess(len(row["product_raw"]), 20)

    def test_the_yearly_cap_keeps_the_priority_rows(self):
        module = ADAPTERS["nvd-cve"]
        rows = [base.make_row(module, native_id="CVE-2020-%05d" % number, title="CVE-2020-%05d" % number,
                              url="https://nvd.nist.gov/vuln/detail/CVE-2020-%05d" % number, published="2020-01-01",
                              cve=["CVE-2020-%05d" % number], exploited_flag=number % 400 == 0,
                              retrieved=self.row["retrieved"], raw_sha256=self.row["raw_sha256"]) for number in range(1600)]
        kept, dropped = base.cap(rows, module.priority)
        self.assertEqual((len(kept), dropped), (1500, {2020: 100}))
        self.assertTrue(all(row["native_id"] in {item["native_id"] for item in kept} for row in rows if row["exploited_flag"]))


class FilesTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hub-history-")
        self.root = Path(self.directory.name)
        self.rows = {name: golden(name) for name in ADAPTERS}
        write_history(self.root, self.rows)

    def tearDown(self):
        self.directory.cleanup()

    def test_a_complete_tree_passes_the_check(self):
        result = check.run(self.root, out=lambda line: None)
        self.assertEqual(result["rows"], sum(len(rows) for rows in self.rows.values()))

    def test_writing_the_same_rows_again_changes_no_byte(self):
        before = {path: path.read_bytes() for path in sorted(self.root.rglob("*")) if path.is_file()}
        write_history(self.root, {name: list(reversed(rows)) for name, rows in self.rows.items()})
        after = {path: path.read_bytes() for path in sorted(self.root.rglob("*")) if path.is_file()}
        self.assertEqual(before, after)

    def test_coverage_has_a_row_for_every_source_and_year(self):
        value = canonical.read_coverage(self.root)
        sources = {item["source_id"] for item in value["sources"]}
        self.assertEqual(sources, {module.SOURCE_ID for module in ADAPTERS.values()} | {item["source_id"] for item in STATIC_SOURCES})
        self.assertEqual({(row["source_id"], row["year"]) for row in value["rows"]}, {(source, year) for source in sources for year in YEARS})
        statuses = {row["source_id"]: row["status"] for row in value["rows"]}
        for name in ("adobe-psirt", "vmware-vmsa", "juniper-jsa", "citrix-bulletins", "sap-security-notes", "schneider-electric-psirt"):
            self.assertEqual(statuses[name], "unreachable")
        self.assertEqual(statuses["redhat-csaf"], "gap")
        self.assertTrue(all(row["reason"].startswith("adapter not built yet") for row in value["rows"] if row["source_id"] == "siemens-productcert"))

    def corrupt(self, path, raw):
        path.write_bytes(raw)
        with self.assertRaises(base.HistoryError):
            check.run(self.root, out=lambda line: None)

    def test_a_row_outside_its_year_fails(self):
        path = self.root / "history" / "msrc-bulletins" / "1998.jsonl"
        rows = canonical.read_year(path)[1]
        moved = dict(rows[0], published="1999-01-01")
        self.corrupt(path, canonical.encode([moved] + rows[1:]))

    def test_unsorted_or_non_canonical_bytes_fail(self):
        path = self.root / "history" / "msrc-bulletins" / "1998.jsonl"
        raw, rows = canonical.read_year(path)
        self.corrupt(path, b"".join(json.dumps(row, indent=1).encode() + b"\n" for row in rows))

    def test_a_duplicate_id_fails(self):
        path = self.root / "history" / "msrc-bulletins" / "1998.jsonl"
        rows = canonical.read_year(path)[1]
        self.corrupt(path, canonical.encode(rows + [dict(rows[0])]))

    def test_coverage_that_disagrees_with_the_files_fails(self):
        value = canonical.read_coverage(self.root)
        for row in value["rows"]:
            if row["adapter"] == "msrc-bulletins" and row["year"] == 1998:
                row["admitted"] += 1
        self.corrupt(self.root / "history" / "coverage.json", canonical.encode_json(value))

    def test_a_missing_coverage_year_fails(self):
        value = canonical.read_coverage(self.root)
        value["rows"] = [row for row in value["rows"] if not (row["source_id"] == "nvd" and row["year"] == 2004)]
        self.corrupt(self.root / "history" / "coverage.json", canonical.encode_json(value))

    def test_an_unexpected_file_fails(self):
        self.corrupt(self.root / "history" / "notes.txt", b"x")


class FakeResponse:
    def __init__(self, body, status=200, headers=None):
        self.body, self.status, self.headers = io.BytesIO(body), status, headers or {}

    def read(self, size=-1):
        return self.body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FetcherTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hub-raw-")
        self.opener = mock.Mock()
        self.opener.open.side_effect = lambda request, timeout: FakeResponse(b"x" * 100)

    def tearDown(self):
        self.directory.cleanup()

    def fetcher(self, **options):
        return base.Fetcher(self.directory.name, "test", ["example.org", "other.org"], opener=self.opener, interval=0.05, **options)

    def test_it_names_the_project_and_caches_the_response(self):
        fetcher = self.fetcher()
        first = fetcher.get("https://example.org/a")
        request = self.opener.open.call_args.args[0]
        self.assertIn(base.PROJECT_URL, request.get_header("User-agent"))
        second = self.fetcher().get("https://example.org/a")
        self.assertEqual(self.opener.open.call_count, 1)
        self.assertEqual((first.raw, first.sha256), (second.raw, second.sha256))

    def test_offline_never_fetches(self):
        with self.assertRaises(base.MissingRaw):
            self.fetcher(offline=True).get("https://example.org/missing")
        self.opener.open.assert_not_called()

    def test_hosts_and_byte_bounds_are_enforced(self):
        with self.assertRaises(base.HistoryError):
            self.fetcher().get("https://elsewhere.org/a")
        with self.assertRaises(base.HistoryError):
            self.fetcher().get("https://example.org/big", max_bytes=10)
        self.assertEqual(len(self.fetcher().get("https://example.org/head", max_bytes=10, head=True).raw), 10)

    def test_one_request_a_second_per_host(self):
        fetcher = self.fetcher()
        with mock.patch.object(base.time, "sleep") as sleep:
            fetcher.get("https://example.org/1")
            fetcher.get("https://example.org/2")
            fetcher.get("https://other.org/1")
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(base.MIN_INTERVAL, 1.0)

    def test_a_redirect_off_the_declared_hosts_is_refused(self):
        handler = base._Redirects({"example.org"})
        request = mock.Mock(full_url="https://example.org/a")
        with self.assertRaises(base.HistoryError):
            handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example.net/a")


class PublishTest(unittest.TestCase):
    """The publish step reads committed rows only, tags them and files them in the v7 history shards."""

    @classmethod
    def setUpClass(cls):
        from test_publication import Workspace
        cls.workspace = Workspace()
        write_history(cls.workspace.root, {name: golden(name) for name in ADAPTERS})
        with mock.patch.object(publish, "HISTORY_PUBLISHED", True):
            cls.result = cls.workspace.build()
        cls.v7 = cls.workspace.root / "site" / "data" / "v7"

    @classmethod
    def tearDownClass(cls):
        cls.workspace.close()

    def shard(self, path):
        return json.loads((self.v7 / path).read_text(encoding="utf-8"))

    def test_ms98_rows_land_in_the_1998_history_shard_tagged(self):
        rows = {row["id"]: row for row in self.shard("history/1998.json")["rows"]}
        self.assertIn("h-msrc-bulletins-MS98-002", rows)
        row = rows["h-msrc-bulletins-MS98-002"]
        self.assertEqual((row["origin"], row["summary"], row["kind"]), ("history:msrc-bulletins", "", "bulletin"))
        self.assertEqual(row["tagging"]["source_class"], "vendor-primary")
        self.assertEqual(self.result["v7"]["history"]["status"], "ok")

    def test_a_url_already_curated_is_left_to_the_curated_row(self):
        rows = self.shard("history/1998.json")["rows"]
        self.assertNotIn("h-msrc-bulletins-MS98-001", {row["id"] for row in rows})
        self.assertIn("library-curation", {row["origin"] for row in rows})

    def test_recent_history_rows_stay_out_of_the_live_window(self):
        live = [row for path in sorted(self.v7.glob("live/*.json")) for row in json.loads(path.read_text(encoding="utf-8"))["rows"]]
        self.assertFalse([row for row in live if row["origin"].startswith("history:")])
        self.assertIn("h-oracle-cpu-alert-cve-2026-114820", {row["id"] for row in self.shard("history/2026.json")["rows"]})

    def test_vendor_structured_exploitation_reaches_the_tagger(self):
        row = next(row for row in self.shard("history/2016.json")["rows"] if row["id"] == "h-msrc-cvrf-CVE-2016-0167")
        self.assertEqual(row["exploitation"], "known")
        self.assertEqual(row["tagging"]["exploitation"][:2], ["known", "vendor-structured"])

    def test_coverage_is_published_from_the_committed_file(self):
        value = self.shard("coverage.json")
        self.assertEqual((value["status"], value["first_year"], value["end_year"]), ("ok", 1998, coverage.END_YEAR))
        self.assertEqual(value["rows"], canonical.read_coverage(self.workspace.root)["rows"])

    def test_the_index_counts_history_rows(self):
        index = json.loads((self.v7 / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(index["counts"]["history_adapter_rows"], sum(len(golden(name)) for name in ADAPTERS) - 1)

    def test_resume_never_reads_history_rows_back(self):
        index = json.loads((self.v7 / "index.json").read_text(encoding="utf-8"))
        files = {collect.PUBLIC_V7 + path.relative_to(self.v7).as_posix(): path.read_bytes() for path in self.v7.rglob("*") if path.is_file()}
        files[collect.PUBLIC_BRIEFS] = self.workspace.raw("briefs.json")

        def fetch(url, maximum=collect.MAX_BYTES, fresh=False):
            if url not in files:
                raise OSError("HTTP Error 404: Not Found")
            return files[url]
        with mock.patch.object(collect, "fetch", side_effect=fetch), contextlib.redirect_stderr(io.StringIO()):
            previous, reason = collect.resume_deployed(support.sources(), {"sources": {}, "kev": {}})
        self.assertIsNone(reason)
        self.assertTrue(index["counts"]["history_adapter_rows"])
        self.assertFalse([row for row in previous["articles"] if row["origin"].startswith("history:")])


class SharedLinkTest(unittest.TestCase):
    """History rows that share a link (every CA-series row of a year links to that year's page) all publish."""

    def test_history_rows_never_displace_each_other_by_url(self):
        first = golden("certcc-ca")[0]
        second = dict(first, native_id="CA-2000-03", id="h-certcc-ca-CA-2000-03", cve=[])
        folder = Path(tempfile.mkdtemp())
        try:
            write_history(folder, {"certcc-ca": [first, second]})
            rows, summary = publish.articles(folder)
            self.assertEqual(sorted(row["id"] for row in rows), [first["id"], second["id"]])
            self.assertEqual(summary["duplicates_left_to_other_rows"], 0)
            # A feed, KEV or curated row with the same link still takes precedence over both.
            rows, summary = publish.articles(folder, {first["url"]})
            self.assertEqual((rows, summary["duplicates_left_to_other_rows"]), ([], 2))
        finally:
            shutil.rmtree(folder)


class FitTest(unittest.TestCase):
    """A year's history shard never passes the shard byte bound because of adapter rows."""

    @staticmethod
    def row(ident, origin, severity=None, exploitation="unknown"):
        value = {"id": ident, "origin": origin, "exploitation": exploitation, "title": "x" * 200, "published_at": "2020-01-01"}
        if severity:
            value["severity"] = severity
        return value

    def files(self):
        rows = [self.row("publisher-1", "publisher-feed"), self.row("curated-1", "library-curation"),
                self.row("h-msrc-cvrf-CVE-2020-0001", "history:msrc-cvrf", "Critical"),
                self.row("h-msrc-cvrf-CVE-2020-0002", "history:msrc-cvrf", "Important"),
                self.row("h-nvd-cve-CVE-2020-0003", "history:nvd-cve", "Critical 9.8", "known"),
                self.row("h-nvd-cve-CVE-2020-0004", "history:nvd-cve", "Low 2.1"),
                self.row("h-nvd-cve-CVE-2020-0005", "history:nvd-cve", "High 7.5")]
        return {"history/2020.json": {"kind": "articles", "rows": rows}, "live/2026-10.json": {"kind": "articles", "rows": rows[:1] * 50},
                "history/1998.json": {"kind": "articles", "rows": rows[2:3]}}

    def test_a_shard_inside_its_bound_is_untouched(self):
        files = self.files()
        before = copy.deepcopy(files)
        self.assertEqual(publish.fit(files, len(shards.canonical(files["history/2020.json"])), shards.canonical), [])
        self.assertEqual(files, before)

    def test_nvd_rows_go_first_lowest_severity_first_and_known_last(self):
        files = self.files()
        size = len(shards.canonical(files["history/2020.json"]))
        # One byte more than the lowest-priority row frees, so exactly two rows must go.
        lowest = next(row for row in files["history/2020.json"]["rows"] if row["id"] == "h-nvd-cve-CVE-2020-0004")
        limit = size - len(shards.canonical(lowest)) - 1
        held = publish.fit(files, limit, shards.canonical)
        self.assertEqual(held, [{"path": "history/2020.json", "adapter": "nvd-cve", "rows": 2}])
        kept = [row["id"] for row in files["history/2020.json"]["rows"]]
        self.assertNotIn("h-nvd-cve-CVE-2020-0004", kept)
        self.assertNotIn("h-nvd-cve-CVE-2020-0005", kept)
        self.assertIn("h-nvd-cve-CVE-2020-0003", kept)
        self.assertLessEqual(len(shards.canonical(files["history/2020.json"])), limit)

    def test_live_publisher_and_curated_rows_are_never_held_back(self):
        files = self.files()
        held = publish.fit(files, 10, shards.canonical)
        self.assertEqual({item["adapter"] for item in held}, {"msrc-cvrf", "nvd-cve"})
        self.assertEqual([row["id"] for row in files["history/2020.json"]["rows"]], ["publisher-1", "curated-1"])
        self.assertEqual(len(files["live/2026-10.json"]["rows"]), 50)

    def test_the_collector_names_held_back_rows_in_the_published_coverage(self):
        from test_publication import Workspace
        workspace = Workspace()
        real = publish.fit
        try:
            write_history(workspace.root, {name: golden(name) for name in ADAPTERS})

            def tight(files, limit, encode):
                return real(files, len(encode(files["history/2016.json"])) - 1, encode)
            with mock.patch.object(publish, "HISTORY_PUBLISHED", True), mock.patch.object(publish, "fit", side_effect=tight):
                result = workspace.build()
            v7 = workspace.root / "site" / "data" / "v7"
            value = json.loads((v7 / "coverage.json").read_text(encoding="utf-8"))
            self.assertTrue(value["held_back"])
            self.assertEqual(value["held_back"], result["v7"]["history"]["held_back"])
            index = json.loads((v7 / "index.json").read_text(encoding="utf-8"))
            published = sum(1 for path in v7.glob("history/*.json")
                            for row in json.loads(path.read_text(encoding="utf-8"))["rows"] if row["origin"].startswith("history:"))
            self.assertEqual(index["counts"]["history_adapter_rows"], published)
        finally:
            workspace.close()


class TolerantPublishTest(unittest.TestCase):
    def test_a_broken_history_tree_never_blocks_the_feed(self):
        from test_publication import Workspace
        workspace = Workspace()
        try:
            write_history(workspace.root, {"msrc-bulletins": golden("msrc-bulletins")})
            (workspace.root / "history" / "msrc-bulletins" / "1998.jsonl").write_bytes(b"{not json\n")
            with mock.patch.object(publish, "HISTORY_PUBLISHED", True):
                result = workspace.build()
            self.assertEqual(result["v7"]["history"]["status"], "unavailable")
            coverage_shard = json.loads((workspace.root / "site/data/v7/coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(coverage_shard["status"], "stub")
        finally:
            workspace.close()

    def test_with_publication_off_rows_stay_out_and_coverage_is_still_published(self):
        from test_publication import Workspace
        workspace = Workspace()
        try:
            write_history(workspace.root, {"msrc-bulletins": golden("msrc-bulletins")})
            with mock.patch.object(publish, "HISTORY_PUBLISHED", False):
                result = workspace.build()
            self.assertEqual(result["v7"]["history"]["status"], "unpublished")
            v7 = workspace.root / "site" / "data" / "v7"
            rows = [row for path in v7.glob("history/*.json") for row in json.loads(path.read_text(encoding="utf-8"))["rows"]]
            self.assertFalse([row for row in rows if row["origin"].startswith("history:")])
            value = json.loads((v7 / "coverage.json").read_text(encoding="utf-8"))
            self.assertEqual((value["status"], value["published_rows"]), ("ok", False))
        finally:
            workspace.close()

    def test_no_history_tree_is_an_empty_history(self):
        with mock.patch.object(publish, "HISTORY_PUBLISHED", True):
            rows, summary = publish.articles(Path(tempfile.gettempdir()) / "no-such-hub-root")
        self.assertEqual((rows, summary["status"]), ([], "empty"))

    def test_the_tagging_registry_covers_every_adapter(self):
        self.assertEqual({item["id"] for item in registry()}, {module.SOURCE_ID for module in ADAPTERS.values()})


class CommittedTreeTest(unittest.TestCase):
    """The repository's own history/ passes the same check CI runs."""

    def test_the_committed_history_passes_the_check(self):
        if not (support.ROOT / "history").is_dir():
            self.skipTest("no committed history/ in this checkout")
        result = check.run(support.ROOT, out=lambda line: None)
        self.assertGreater(result["rows"], 0)
        rows = canonical.read_year(support.ROOT / "history" / "msrc-bulletins" / "1998.jsonl")[1]
        self.assertTrue(all(row["native_id"].startswith("MS98-") for row in rows))


if __name__ == "__main__":
    unittest.main()
