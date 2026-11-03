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
from intelligence_hub.history.adapters import msrc_cvrf

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
