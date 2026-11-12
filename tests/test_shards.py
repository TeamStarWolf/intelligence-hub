"""Schema 7 shards beside feed.json: canonical bytes, the KEV ledger, the run chain,
resuming from data/v7/index.json and the manifest-checked Pages package."""
import contextlib
import copy
from datetime import date
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import xml.etree.ElementTree as ET

import support
from intelligence_hub import collect, shards
from test_publication import END, Workspace, synthetic_cache

ATOM = "{http://www.w3.org/2005/Atom}"


def v7_files(workspace):
    """Every v7 shard and index.json on disk; the analytics exports under exports/ and the Atom feeds under feeds/ are left out."""
    base = workspace.root / "site" / "data" / "v7"
    return {path.relative_to(base).as_posix(): path.read_bytes() for path in sorted(base.rglob("*"))
            if path.is_file() and not path.relative_to(base).as_posix().startswith(("exports/", "feeds/"))}


def feed_files(workspace):
    base = workspace.root / "site" / "data" / "v7" / "feeds"
    return {"feeds/" + path.name: path.read_bytes() for path in sorted(base.iterdir())} if base.is_dir() else {}


def atom_entries(raw):
    """The parsed feed element and its entries, as {child tag: text} with the links by rel."""
    feed = ET.fromstring(raw)
    entries = []
    for entry in feed.findall(ATOM + "entry"):
        item = {child.tag[len(ATOM):]: child.text for child in entry if child.tag != ATOM + "link"}
        item["links"] = {link.get("rel"): link.get("href") for link in entry.findall(ATOM + "link")}
        entries.append(item)
    return feed, entries


def index_of(workspace):
    return json.loads((workspace.root / "site" / "data" / "v7" / "index.json").read_text(encoding="utf-8"))


def kev_entry(cve, added, action, **extra):
    return {"cveID": cve, "vendorProject": "Example Vendor", "product": "Example Product", "vulnerabilityName": "Example record " + cve,
            "dateAdded": added, "shortDescription": "Synthetic description.", "requiredAction": action, "dueDate": "2026-11-20",
            "knownRansomwareCampaignUse": "Unknown", "forensicTriage": "No", "notes": "", "cwes": ["CWE-787"], **extra}


class LayoutTest(unittest.TestCase):
    def test_live_window_is_the_end_month_and_the_23_before_it(self):
        self.assertEqual(shards.live_start(date(2026, 11, 3)), date(2024, 12, 1))
        self.assertEqual(shards.live_start(date(2026, 12, 31)), date(2025, 1, 1))
        self.assertEqual(shards.live_start(date(2026, 1, 1)), date(2024, 2, 1))

    def test_rows_go_to_month_year_curated_and_undated_shards(self):
        live = date(2024, 12, 1)
        row = {"origin": "publisher-feed", "date_basis": "publication", "event_date": None, "id": "x"}
        self.assertEqual(shards.article_path({**row, "published_at": "2026-11-02T21:16:10+00:00"}, live), "live/2026-11.json")
        self.assertEqual(shards.article_path({**row, "published_at": "2024-12-01"}, live), "live/2024-12.json")
        self.assertEqual(shards.article_path({**row, "published_at": "2024-11-30T23:59:59+00:00"}, live), "history/2024.json")
        self.assertEqual(shards.article_path({**row, "published_at": None}, live), "live/undated.json")
        curated = {**row, "origin": "library-curation", "published_at": "2026-10-01"}
        self.assertEqual(shards.article_path(curated, live), "history/2026.json")

    def test_cve_buckets_use_year_and_thousand_block(self):
        self.assertEqual(shards.cve_bucket("CVE-2026-118527"), "cve/2026/118k.json")
        self.assertEqual(shards.cve_bucket("CVE-2021-44228"), "cve/2021/44k.json")
        self.assertEqual(shards.cve_bucket("CVE-1999-0001"), "cve/1999/0k.json")
        buckets = shards.cve_buckets({"CVE-2021-44228": {"cve": "CVE-2021-44228"}, "CVE-2021-44832": {"cve": "CVE-2021-44832"},
                                      "CVE-2026-118527": {"cve": "CVE-2026-118527"}})
        self.assertEqual(sorted(buckets), ["cve/2021/44k.json", "cve/2026/118k.json"])
        self.assertEqual(sorted(buckets["cve/2021/44k.json"]["briefs"]), ["CVE-2021-44228", "CVE-2021-44832"])
        for path in buckets:
            self.assertTrue(shards.SHARD_PATH.fullmatch(path))

    def test_canonical_bytes_do_not_depend_on_key_order(self):
        self.assertEqual(shards.canonical({"b": 1, "a": [2, {"d": 3, "c": "é"}]}), shards.canonical({"a": [2, {"c": "é", "d": 3}], "b": 1}))
        self.assertEqual(shards.canonical({"a": 1}), b'{"a":1}\n')

    def test_shard_bound_is_the_smaller_of_the_feed_bound_and_the_v7_file_cap(self):
        self.assertEqual(shards.SHARD_MAX_BYTES, min(collect.FEED_MAX_BYTES, shards.V7_FILE_MAX_BYTES))
        self.assertLessEqual(shards.SHARD_MAX_BYTES, shards.V7_FILE_MAX_BYTES)

    def test_a_shard_between_the_v7_file_cap_and_the_feed_bound_is_refused_at_build_time(self):
        size = (shards.V7_FILE_MAX_BYTES + collect.FEED_MAX_BYTES) // 2
        self.assertLess(shards.V7_FILE_MAX_BYTES, size)
        self.assertLess(size, collect.FEED_MAX_BYTES)
        shard = {"kind": "articles", "rows": [{"id": "feed-oversized", "title": "x" * size}]}
        with self.assertRaisesRegex(ValueError, "shard bound"):
            shards.serialize({"live/2026-10.json": shard})


class KevLedgerTest(unittest.TestCase):
    def test_directive_is_parsed_from_required_action(self):
        self.assertEqual(shards.parse_directive("Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, "
                                                "or discontinue use of the product if mitigations are unavailable."), "BOD 22-01")
        self.assertEqual(shards.parse_directive("Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA's BOD 26-04 "
                                                "Prioritizing Security Updates Based on Risk guidance. Follow applicable BOD 26-04 guidance "
                                                "for cloud services."), "BOD 26-04")
        self.assertIsNone(shards.parse_directive("Apply updates per vendor instructions."))
        self.assertIsNone(shards.parse_directive(None))
        self.assertEqual(shards.parse_directive("Follow BOD 26-04 and ED 24-01."), "BOD 26-04; ED 24-01")
        # The real requiredAction text of CVE-2026-20182 and CVE-2025-20362 (KEV catalogVersion 2026.10.30).
        self.assertEqual(shards.parse_directive(
            "Please adhere to CISA\u2019s guidelines to assess exposure and mitigate risks associated with Cisco SD-WAN devices as "
            "outlined in CISA\u2019s Emergency Directive 26-03 (URL listed below in Notes) and CISA\u2019s Hunt & Hardening Guidance "
            "for Cisco SD-WAN Devices (URL listed below in Notes). Adhere to the applicable BOD 22-01 guidance for cloud services "
            "or discontinue use of the product if mitigations are not available."), "BOD 22-01; ED 26-03")
        self.assertEqual(shards.parse_directive(
            "The KEV due date refers to the deadline by which FCEB agencies are expected to review and begin implementing the "
            "guidance outlined in Emergency Directive (ED) 25-03 (URL listed below in Notes). Agencies must follow the mitigation "
            "steps provided by CISA (URL listed below in Notes) and vendor\u2019s instructions (URL listed below in Notes). Adhere "
            "to the applicable BOD 22-01 guidance for cloud services or discontinue use of the product if mitigations are not "
            "available."), "BOD 22-01; ED 25-03")
        self.assertEqual(shards.parse_directive("Binding Operational Directive (BOD) 23-02 applies."), "BOD 23-02")
        self.assertIsNone(shards.parse_directive("An Emergency Directive may follow."))

    def test_ledger_keeps_every_entry_by_date_added(self):
        entries = [kev_entry("CVE-2026-10002", "2026-10-30", "Follow BOD 26-04 guidance.", knownRansomwareCampaignUse="Known", forensicTriage="Yes",
                             notes="http://vendor.example.com/advisory ; BOD 26-04: https://www.cisa.gov/news-events/directives/bod-26-04 ; ; "
                                   "https://nvd.nist.gov/vuln/detail/CVE-2026-10002"),
                   kev_entry("CVE-2026-10001", "2026-10-30", "Apply updates per vendor instructions."),
                   kev_entry("CVE-2021-44228", "2021-12-10", "Follow applicable BOD 22-01 guidance.", cwes=["CWE-917", "CWE-20", "not-a-cwe"]),
                   {"cveID": "CVE-2025-1000", "dateAdded": "2025-01-05", "vendorProject": "Minimal", "product": "Record",
                    "vulnerabilityName": "Older schema record", "shortDescription": "No triage or CWE fields."}]
        ledger = shards.kev_ledger({"vulnerabilities": entries})
        self.assertEqual(sorted(ledger), ["kev/2021.json", "kev/2025.json", "kev/2026.json"])
        self.assertEqual(sum(len(value["rows"]) for value in ledger.values()), len(entries))
        rows = ledger["kev/2026.json"]["rows"]
        self.assertEqual([row["cve"] for row in rows], ["CVE-2026-10001", "CVE-2026-10002"])
        known = rows[1]
        self.assertEqual((known["directive"], known["ransomware"], known["forensic_triage"], known["due_date"]), ("BOD 26-04", "Known", "Yes", "2026-11-20"))
        # Plain HTTP links are dropped; the two HTTPS links are kept in order.
        self.assertEqual(known["notes_urls"], ["https://www.cisa.gov/news-events/directives/bod-26-04", "https://nvd.nist.gov/vuln/detail/CVE-2026-10002"])
        self.assertEqual(known["required_action"], "Follow BOD 26-04 guidance.")
        self.assertIsNone(rows[0]["directive"])
        self.assertEqual(ledger["kev/2021.json"]["rows"][0]["cwe"], ["CWE-20", "CWE-917"])
        minimal = ledger["kev/2025.json"]["rows"][0]
        self.assertEqual((minimal["forensic_triage"], minimal["cwe"], minimal["due_date"], minimal["directive"]), (None, [], None, None))

    def test_per_day_counts_match_the_catalog(self):
        cache = synthetic_cache(publisher_rows=60, kev_rows=400)
        catalog = cache["kev"]["catalog"]
        ledger = shards.kev_ledger(catalog)
        by_day = {}
        for value in ledger.values():
            for row in value["rows"]:
                by_day[row["date_added"]] = by_day.get(row["date_added"], 0) + 1
        expected = {}
        for entry in catalog["vulnerabilities"]:
            expected[entry["dateAdded"]] = expected.get(entry["dateAdded"], 0) + 1
        self.assertEqual(by_day, expected)
        self.assertEqual(sum(by_day.values()), catalog["count"])


class RunChainTest(unittest.TestCase):
    def test_observed_interval_is_the_median_and_longest_gap(self):
        runs = [{"generated_at": stamp, "trigger": "schedule", "changed": True} for stamp in
                ("2026-11-03T12:00:00+00:00", "2026-11-03T08:00:00+00:00", "2026-11-03T02:00:00+00:00", "2026-11-02T16:00:00+00:00")]
        self.assertEqual(shards.observed_interval(runs), {"median": 6.0, "max": 10.0, "runs_counted": 4})
        self.assertEqual(shards.observed_interval(runs[:1]), {"median": None, "max": None, "runs_counted": 1})

    def test_chain_keeps_the_last_20_runs_newest_first(self):
        earlier = [{"generated_at": "2026-11-01T{:02d}:00:00+00:00".format(hour), "trigger": "schedule", "changed": True} for hour in range(23, -1, -1)]
        chain = shards.run_chain(earlier, "2026-11-02T01:00:00+00:00", "push")
        self.assertEqual(len(chain), shards.RUNS_KEPT)
        self.assertEqual(chain[0], {"generated_at": "2026-11-02T01:00:00+00:00", "trigger": "push", "changed": True})
        self.assertEqual(chain[1]["generated_at"], "2026-11-01T23:00:00+00:00")

    def test_first_v7_run_is_seeded_from_the_v6_feed_time(self):
        chain = shards.run_chain([], "2026-11-03T10:00:00+00:00", "push", seed="2026-11-03T05:30:00+00:00")
        self.assertEqual([run["trigger"] for run in chain], ["push", "unrecorded"])
        self.assertEqual(shards.observed_interval(chain)["median"], 4.5)
        self.assertEqual(len(shards.run_chain([], "2026-11-03T10:00:00+00:00", "push")), 1)

    def test_trigger_comes_from_the_workflow_event(self):
        with mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "schedule"}):
            self.assertEqual(shards.run_trigger(), "schedule")
        with mock.patch.dict(os.environ, {"GITHUB_EVENT_NAME": "pull_request"}):
            self.assertEqual(shards.run_trigger(), "local")


class BuildTest(unittest.TestCase):
    def test_two_offline_builds_give_identical_shards(self):
        first, second = Workspace(synthetic_cache(publisher_rows=900, kev_rows=200)), Workspace(synthetic_cache(publisher_rows=900, kev_rows=200))
        try:
            first.build()
            second.build()
            one, two = v7_files(first), v7_files(second)
            index = index_of(first)
            self.assertEqual(sorted(one), sorted(two))
            for path in one:
                if path != "index.json":
                    self.assertEqual(one[path], two[path], path)
            self.assertEqual(index["shards"], index_of(second)["shards"])
            # The index lists exactly the shard files on disk, with their bytes and sha256.
            self.assertEqual({entry["path"] for entry in index["shards"]}, set(one) - {"index.json"})
            for entry in index["shards"]:
                self.assertEqual((entry["bytes"], entry["sha256"]), (len(one[entry["path"]]), shards.sha256(one[entry["path"]])))
                self.assertEqual(one[entry["path"]], shards.canonical(json.loads(one[entry["path"]])))
            self.assertEqual(index["requested_cron"], "7 */2 * * *")
            self.assertEqual(index["counts"]["articles"], index["counts"]["live_rows"] + index["counts"]["history_rows"])
            self.assertEqual(index["counts"]["kev"], 200)
            feed = first.json("feed.json")
            self.assertEqual(index["counts"]["articles"], len(feed["articles"]))
            self.assertEqual(index["feed_content_revision"], feed["content_revision"])
            self.assertEqual([item["path"] for item in index["v6_files"]], ["data/feed.json", "data/briefs.json"])
            self.assertEqual(index["v6_files"][0]["sha256"], shards.sha256(first.raw("feed.json")))
            self.assertFalse(index["cve_buckets"]["published"])
            self.assertFalse(any(path.startswith("cve/") for path in one))
            self.assertEqual(json.loads(one["cve-index.json"])["briefs_file"], "data/briefs.json")
            cve_index = json.loads(one["cve-index.json"])
            self.assertEqual(cve_index["fields"][0], "cve")
            self.assertEqual([row[0] for row in cve_index["rows"]], sorted(first.json("briefs.json")["briefs"]))
            self.assertTrue(all(len(row) == len(cve_index["fields"]) and row[-1] is None for row in cve_index["rows"]))
            # Every feed row lands in exactly one article shard.
            rows = [row for path, raw in one.items() if path.startswith(("live/", "history/")) for row in json.loads(raw)["rows"]]
            self.assertEqual(sorted(row["id"] for row in rows), sorted(article["id"] for article in feed["articles"]))
            self.assertIn("data/v7: ", first.log)
        finally:
            first.close()
            second.close()

    def test_changing_one_month_changes_only_that_shard(self):
        cache = synthetic_cache(publisher_rows=900, kev_rows=200)
        workspace = Workspace(cache)
        try:
            workspace.build()
            before = {entry["path"]: entry["sha256"] for entry in index_of(workspace)["shards"]}
            month = next(article for observation in cache["sources"].values() for article in observation["articles"]
                         if article["published_at"].startswith("2026-09"))
            month["title"] = "Synthetic entry with a corrected headline"
            (workspace.root / ".state" / "public-cache.json").write_text(json.dumps(cache), encoding="utf-8")
            result = workspace.build()
            after = {entry["path"]: entry["sha256"] for entry in index_of(workspace)["shards"]}
            self.assertEqual(sorted(after), sorted(before))
            self.assertEqual([path for path in after if after[path] != before[path]], ["live/2026-09.json"])
            # The offline build compares against the index the previous build left.
            self.assertEqual(result["changed_shards"], ["live/2026-09.json"])
            self.assertEqual(result["removed_shards"], [])
            self.assertEqual(len(index_of(workspace)["runs"]), 1)  # the fixed test clock records no later run
        finally:
            workspace.close()

    def test_a_shard_that_empties_is_removed_from_disk_and_reported(self):
        cache = synthetic_cache(publisher_rows=900, kev_rows=200)
        workspace = Workspace(cache)
        try:
            workspace.build()
            gone = "live/2026-09.json"
            self.assertTrue((workspace.root / "site/data/v7" / gone).exists())
            for observation in cache["sources"].values():
                observation["articles"] = [article for article in observation["articles"] if not article["published_at"].startswith("2026-09")]
            catalog = cache["kev"]["catalog"]
            catalog["vulnerabilities"] = [entry for entry in catalog["vulnerabilities"] if not entry["dateAdded"].startswith("2026-09")]
            catalog["count"] = len(catalog["vulnerabilities"])
            (workspace.root / ".state" / "public-cache.json").write_text(json.dumps(cache), encoding="utf-8")
            result = workspace.build()
            self.assertIn(gone, result["removed_shards"])
            self.assertFalse((workspace.root / "site/data/v7" / gone).exists())
            self.assertTrue(result["changed"])
        finally:
            workspace.close()

    def test_cve_buckets_build_and_package_once_enabled(self):
        workspace = Workspace(synthetic_cache(publisher_rows=300, kev_rows=60))
        try:
            with mock.patch.object(shards, "CVE_BUCKETS_PUBLISHED", True):
                workspace.build()
            files = v7_files(workspace)
            buckets = {path: json.loads(raw)["briefs"] for path, raw in files.items() if path.startswith("cve/")}
            briefs = workspace.json("briefs.json")["briefs"]
            self.assertEqual(sorted(cve for rows in buckets.values() for cve in rows), sorted(briefs))
            self.assertTrue(all(shards.cve_bucket(cve) == path for path, rows in buckets.items() for cve in rows))
            index = json.loads(files["cve-index.json"])
            self.assertIsNone(index["briefs_file"])
            self.assertTrue(all(row[-1] == shards.cve_bucket(row[0]) for row in index["rows"]))
            shards.package_site(workspace.root / "site", out=io.StringIO())
        finally:
            workspace.close()

    def test_collection_result_carries_typed_shard_lists_under_its_bound(self):
        copy_ = support.BuildCopy()
        try:
            code, result, output = copy_.run()
            self.assertEqual(code, 0, output)
            raw = (copy_.root / ".state" / "collection-result.json").read_bytes()
            self.assertLessEqual(len(raw), collect.RESULT_MAX_BYTES)
            for field in ("changed_shards", "removed_shards"):
                self.assertIsInstance(result[field], list)
                self.assertTrue(all(shards.SHARD_PATH.fullmatch(path) for path in result[field]))
            self.assertIn("sources.json", result["changed_shards"])
            reports = json.loads((copy_.root / "site/data/v7/reports.json").read_text(encoding="utf-8"))
            self.assertEqual(reports["status"], result["reports"]["status"])
            # One headroom line per shard the index lists, with the bytes the index records.
            index = json.loads((copy_.root / "site/data/v7/index.json").read_text(encoding="utf-8"))
            for entry in index["shards"]:
                self.assertIn("data/v7/" + entry["path"] + ": " + format(entry["bytes"], ",") + " of 4,194,304 bytes (", output)
            self.assertIn("of headroom under the 3,145,728-byte history split threshold)", output)
        finally:
            copy_.close()

    def test_a_corrupt_catalog_publishes_reports_unavailable(self):
        copy_ = support.BuildCopy()
        try:
            copy_.write_report_input("catalog.json", b"{not json")
            code, result, output = copy_.run()
            self.assertEqual(code, 0, output)
            reports = json.loads((copy_.root / "site/data/v7/reports.json").read_text(encoding="utf-8"))
            self.assertEqual(reports["status"], "unavailable")
            self.assertIn("catalog.json", reports["reason"])
        finally:
            copy_.close()

    def test_workflow_typed_check_uses_the_shard_pattern(self):
        workflow = (support.ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("- cron: '7 */2 * * *'", workflow)
        # Every r'...' piece of the re.compile( call, up to the line that closes it.
        start = workflow.index("shard = re.compile(")
        call = workflow[start:workflow.index("')\n", start) + 2]
        pieces = re.findall(r"r'([^']*)'", call)
        self.assertEqual("".join(pieces), shards.SHARD_PATH.pattern)

    def test_the_page_validator_uses_the_shard_pattern(self):
        source = (support.ROOT / "site" / "js" / "validate.js").read_text(encoding="utf-8")
        found = re.findall(r"const SHARD_PATTERN = String\.raw`([^`]*)`;", source)
        self.assertEqual(found, [shards.SHARD_PATH.pattern])
        self.assertIn('const SHARD_PATH = new RegExp("^(?:" + SHARD_PATTERN + ")$");', source)


def history_row(year, month, number, title_bytes=400, adapter="nvd-cve"):
    """A history-adapter article row of about title_bytes + 300 canonical bytes."""
    day = "{:04d}-{:02d}-{:02d}".format(year, month, 1 + number % 28)
    return {"id": "h-{}-{:04d}-{:02d}-{:05d}".format(adapter, year, month, number), "title": "t" * title_bytes,
            "url": "https://advisories.example.org/{}/{}".format(year, number), "source_id": "example", "source_name": "Example",
            "kind": "advisory", "published_at": day, "event_date": None, "date_basis": "publication", "summary": "", "cves": [],
            "tags": [], "exploitation": "unknown", "references": [], "origin": "history:" + adapter}


def history_year(year, per_month, months=range(1, 13), **row):
    return [history_row(year, month, number, **row) for month in months for number in range(per_month)]


def built(articles, threshold):
    """build_shards over article rows only, with the history split threshold passed in."""
    return shards.build_shards(articles, [], None, {}, shards.reports_file({}, None, None), END, history_split=threshold)


class SplitTest(unittest.TestCase):
    """A history year over the split threshold is written as halves, quarters or months."""

    THRESHOLD = 64 * 1024

    def year_parts(self, files, year):
        return sorted(path for path in files if path.startswith("history/" + str(year)))

    def unsplit(self, rows, year):
        return shards.article_shard(str(year), sorted(rows, key=shards.row_order))

    def test_the_threshold_is_three_mebibytes_under_the_unchanged_caps(self):
        self.assertEqual(shards.HISTORY_SPLIT_BYTES, 3 * 1024 * 1024)
        self.assertEqual(shards.V7_FILE_MAX_BYTES, 4 * 1024 * 1024)
        self.assertEqual(shards.SHARD_MAX_BYTES, min(collect.FEED_MAX_BYTES, shards.V7_FILE_MAX_BYTES))
        self.assertLess(shards.HISTORY_SPLIT_BYTES, shards.SHARD_MAX_BYTES)
        for path in ("history/2025-h1.json", "history/2025-h2.json", "history/2025-q4.json", "history/2025-01.json", "history/2025-12.json"):
            self.assertTrue(shards.SHARD_PATH.fullmatch(path), path)
        for path in ("history/2025-h3.json", "history/2025-q5.json", "history/2025-13.json", "history/2025-00.json", "history/undated-h1.json"):
            self.assertIsNone(shards.SHARD_PATH.fullmatch(path), path)

    def test_a_year_over_the_threshold_splits_into_halves_listed_in_the_index(self):
        rows = history_year(2025, 10)
        unsplit = self.unsplit(rows, 2025)
        self.assertGreater(len(shards.canonical(unsplit)), self.THRESHOLD)
        files = built(rows, self.THRESHOLD)
        parts = self.year_parts(files, 2025)
        self.assertEqual(parts, ["history/2025-h1.json", "history/2025-h2.json"])
        for path in parts:
            self.assertLessEqual(len(shards.canonical(files[path])), self.THRESHOLD, path)
            self.assertEqual(files[path]["period"], path[len("history/"):-len(".json")])
        self.assertEqual([row for path in parts for row in files[path]["rows"]], unsplit["rows"])
        raw, entries = shards.serialize(files)
        run = {"generated_at": "2026-11-01T12:00:00+00:00", "trigger": "local", "changed": True}
        index = shards.build_index(entries, generated_at=run["generated_at"], end=END, feed_content_revision="a" * 64,
                                   layout_revision="b" * 64, runs=[run], counts={},
                                   v6_files=[shards.file_entry(name, b"x\n") for name in shards.V6_FILES])
        index_raw = shards.canonical(index)
        shards.read_index(index_raw)

        def write(path, data):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        with tempfile.TemporaryDirectory() as directory:
            shards.write_v7(directory, raw, index_raw, write)
            listed = {entry["path"]: entry for entry in json.loads(index_raw)["shards"]}
            for path in parts:
                data = (Path(directory) / shards.DIRECTORY / path).read_bytes()
                self.assertEqual((listed[path]["rows"], listed[path]["bytes"], listed[path]["sha256"]),
                                 (len(files[path]["rows"]), len(data), shards.sha256(data)), path)
            self.assertNotIn("history/2025.json", listed)
            self.assertFalse((Path(directory) / shards.DIRECTORY / "history" / "2025.json").exists())

    def test_halves_over_the_threshold_go_to_quarters_then_to_months(self):
        quarters = built(history_year(2024, 20), self.THRESHOLD)
        self.assertEqual(self.year_parts(quarters, 2024), ["history/2024-q" + str(number) + ".json" for number in range(1, 5)])
        months = built(history_year(2023, 40), self.THRESHOLD)
        self.assertEqual(self.year_parts(months, 2023), ["history/2023-{:02d}.json".format(month) for month in range(1, 13)])
        for files in (quarters, months):
            for path in files:
                if path.startswith("history/"):
                    self.assertLessEqual(len(shards.canonical(files[path])), self.THRESHOLD, path)
        # Rows in two months only: the first half and quarter pass, the months fit, and no empty part is written.
        sparse = built(history_year(2022, 50, months=(1, 2)), self.THRESHOLD)
        self.assertEqual(self.year_parts(sparse, 2022), ["history/2022-01.json", "history/2022-02.json"])
        # When even one month passes the threshold the months are kept; the shard bound still applies.
        heavy = built(history_year(2021, 130, months=(5,)), self.THRESHOLD)
        self.assertEqual(self.year_parts(heavy, 2021), ["history/2021-05.json"])
        self.assertGreater(len(shards.canonical(heavy["history/2021-05.json"])), self.THRESHOLD)

    def test_a_year_under_the_threshold_keeps_its_one_file_and_sha256(self):
        rows = history_year(2010, 2)
        before = shards.sha256(shards.canonical({"schema_version": 7, "kind": "articles", "period": "2010",
                                                 "rows": sorted(rows, key=shards.row_order)}))
        for threshold in (self.THRESHOLD, shards.HISTORY_SPLIT_BYTES):
            files = built(rows, threshold)
            self.assertEqual(self.year_parts(files, 2010), ["history/2010.json"])
            self.assertEqual(shards.sha256(shards.canonical(files["history/2010.json"])), before)

    def test_undated_and_live_rows_are_never_split(self):
        undated = [{**row, "published_at": None, "origin": "library-curation"} for row in history_year(2025, 10)]
        files = built(undated, self.THRESHOLD)
        self.assertEqual(sorted(path for path in files if path.startswith(("history/", "live/"))), ["history/undated.json"])
        live = [{**row, "origin": "publisher-feed", "id": "feed-" + row["id"]} for row in history_year(2026, 10, months=(10,))]
        files = built(live, self.THRESHOLD)
        self.assertEqual(sorted(path for path in files if path.startswith(("history/", "live/"))), ["live/2026-10.json"])

    def test_fit_holds_back_adapter_rows_from_a_part_and_names_it(self):
        from intelligence_hub.history import publish
        files = built(history_year(2020, 10), self.THRESHOLD)
        self.assertIn("history/2020-h1.json", files)
        # The second half is kept small, so only the first one passes the limit below.
        files["history/2020-h2.json"]["rows"] = files["history/2020-h2.json"]["rows"][:5]
        size = len(shards.canonical(files["history/2020-h1.json"]))
        held = publish.fit(files, size - 1, shards.canonical)
        self.assertEqual([(item["path"], item["adapter"]) for item in held], [("history/2020-h1.json", "nvd-cve")])
        self.assertLessEqual(len(shards.canonical(files["history/2020-h1.json"])), size - 1)
        self.assertEqual(len(files["history/2020-h1.json"]["rows"]) + held[0]["rows"], 60)


class RecentTest(unittest.TestCase):
    """recent.json is the Today view's bounded data file."""

    def test_recent_file_holds_exactly_what_today_reads(self):
        workspace = Workspace(synthetic_cache(publisher_rows=900, kev_rows=200))
        try:
            workspace.build()
            files = v7_files(workspace)
            index = index_of(workspace)
            recent = json.loads(files["recent.json"])
            entry = next(item for item in index["shards"] if item["path"] == "recent.json")
            self.assertEqual((entry["rows"], entry["from"], entry["to"]), (len(recent["rows"]), None, None))
            day = date.fromisoformat(index["content_date"])
            self.assertEqual(recent["content_date"], index["content_date"])
            self.assertEqual((recent["from"], recent["to"]), (str(day.fromordinal(day.toordinal() - 3)), str(day.fromordinal(day.toordinal() + 1))))
            self.assertEqual((recent["kev_from"], recent["due_until"]), (str(day.fromordinal(day.toordinal() - 6)), str(day.fromordinal(day.toordinal() + 14))))
            live = [row for path, raw in files.items() if path.startswith("live/") and path != "live/undated.json" for row in json.loads(raw)["rows"]]
            wanted = sorted(row["id"] for row in live if recent["from"] <= shards.row_day(row).isoformat() <= recent["to"])
            self.assertTrue(wanted, "the synthetic cache has rows in the last days")
            self.assertEqual(sorted(row["id"] for row in recent["rows"]), wanted)
            self.assertLess(len(recent["rows"]), len(live))
            ledger = [row for path, raw in files.items() if path.startswith("kev/") for row in json.loads(raw)["rows"]]
            kev = sorted(row["cve"] for row in ledger if recent["kev_from"] <= row["date_added"] <= recent["content_date"] or
                         (row["due_date"] and recent["content_date"] <= row["due_date"] <= recent["due_until"]))
            self.assertEqual(sorted(row["cve"] for row in recent["kev"]), kev)
            cve_index = json.loads(files["cve-index.json"])
            self.assertEqual(recent["cve_fields"], cve_index["fields"])
            named = {cve for row in recent["rows"] for cve in row["cves"]}
            self.assertEqual(recent["cves"], [row for row in cve_index["rows"] if row[0] in named])
        finally:
            workspace.close()

    def test_an_oversized_recent_file_is_left_out_and_the_run_still_builds(self):
        workspace = Workspace(synthetic_cache(publisher_rows=300, kev_rows=60))
        try:
            real = shards.canonical
            with mock.patch.object(shards, "canonical", side_effect=lambda value: (b"x" * (shards.SHARD_MAX_BYTES + 1)) if isinstance(value, dict) and value.get("kind") == "recent" else real(value)):
                workspace.build()
            self.assertNotIn("recent.json", v7_files(workspace))
            self.assertNotIn("recent.json", [entry["path"] for entry in index_of(workspace)["shards"]])
        finally:
            workspace.close()

    def test_the_windows_match_the_page_constants(self):
        page = (support.ROOT / "site" / "js" / "filters.js").read_text(encoding="utf-8")
        constants = {name: int(value) for name, value in re.findall(r"export const ([A-Z_]+) = (\d+);", page)}
        self.assertEqual(constants["TODAY_DAYS"], shards.RECENT_DAYS)
        self.assertEqual(constants["KEV_STRIP_DAYS"], shards.RECENT_KEV_DAYS)
        self.assertEqual(constants["ACT_WITHIN_DAYS"], shards.RECENT_DUE_DAYS)

    def test_an_index_without_recent_still_validates(self):
        # A deployed index written before recent.json existed must still resume.
        self.assertNotIn("recent.json", shards.NAMED)
        self.assertTrue(shards.SHARD_PATH.fullmatch("recent.json"))


class AtomFeedTest(unittest.TestCase):
    """The Hub's own Atom feeds under data/v7/feeds/, listed in index.json under feeds."""

    def entry(self, number, **extra):
        return {"id": shards.ATOM_TAG + ":test:" + str(number), "title": "Entry " + str(number), "link": shards.HUB_URL + "#/kev", "related": None,
                "updated": "2026-11-{:02d}T00:00:00Z".format(number), "published": "2026-11-{:02d}T00:00:00Z".format(number), "summary": "Summary " + str(number), **extra}

    def test_a_feed_is_well_formed_atom_with_the_newest_entry_as_its_clock(self):
        raw = shards.atom_document("kev", "A title", "A subtitle", "#/kev", [self.entry(3), self.entry(2, related="https://example.org/x")], "Rights.")
        feed, entries = atom_entries(raw)
        self.assertEqual(feed.tag, ATOM + "feed")
        self.assertEqual(feed.find(ATOM + "id").text, shards.ATOM_TAG + ":feeds/kev")
        self.assertEqual(feed.find(ATOM + "updated").text, "2026-11-03T00:00:00Z")
        self.assertEqual({link.get("rel"): link.get("href") for link in feed.findall(ATOM + "link")},
                         {"self": shards.HUB_URL + "data/v7/feeds/kev.xml", "alternate": shards.HUB_URL + "#/kev"})
        self.assertEqual(feed.find(ATOM + "author").find(ATOM + "name").text, "TeamStarWolf Intelligence Hub")
        self.assertEqual([item["title"] for item in entries], ["Entry 3", "Entry 2"])
        self.assertEqual(entries[1]["links"], {"alternate": shards.HUB_URL + "#/kev", "related": "https://example.org/x"})
        self.assertNotIn("related", entries[0]["links"])
        self.assertTrue(raw.startswith(b'<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom">'))

    def test_the_same_entries_give_the_same_bytes_and_no_entry_gives_the_fixed_epoch(self):
        entries = [self.entry(5), self.entry(4)]
        self.assertEqual(shards.atom_document("kev", "T", "S", "#/kev", entries, "R"), shards.atom_document("kev", "T", "S", "#/kev", list(entries), "R"))
        self.assertNotEqual(shards.atom_document("kev", "T", "S", "#/kev", entries, "R"), shards.atom_document("kev", "T", "S", "#/kev", entries[:1], "R"))
        feed, entries = atom_entries(shards.atom_document("incidents", "T", "S", "#/status", [], "R"))
        self.assertEqual((feed.find(ATOM + "updated").text, entries), (shards.ATOM_EPOCH, []))

    def test_text_is_escaped_and_control_characters_are_dropped(self):
        entry = self.entry(1, title="A <b>bold</b> & \x01tricky\x1f  title", summary="Quote \" and ' here")
        feed, entries = atom_entries(shards.atom_document("kev", "T", "S", "#/kev", [{**entry, "title": shards._atom_text(entry["title"])}], "R"))
        self.assertEqual(entries[0]["title"], "A <b>bold</b> & tricky title")
        self.assertEqual(entries[0]["summary"], "Quote \" and ' here")
        self.assertEqual(shards._atom_text("  many\n\twords  here "), "many words here")
        self.assertEqual(shards._atom_text("x" * 500, 10), "x" * 10)

    def test_an_oversized_feed_is_cut_from_the_end_until_it_fits(self):
        entries = [self.entry(number % 28 + 1, summary="s" * 20000) for number in range(shards.ATOM_ENTRIES)]
        raw = shards.atom_document("kev", "T", "S", "#/kev", entries, "R")
        self.assertLessEqual(len(raw), shards.ATOM_MAX_BYTES)
        _feed, kept = atom_entries(raw)
        self.assertTrue(0 < len(kept) < shards.ATOM_ENTRIES)
        self.assertEqual([item["summary"] for item in kept], [item["summary"] for item in entries[:len(kept)]])
        with self.assertRaisesRegex(ValueError, "no clock"):
            shards.atom_document("kev", "T", "S", "#/kev", [self.entry(1, updated=None)], "R")

    def test_clocks_and_labels(self):
        self.assertEqual(shards._atom_clock("2026-11-02"), "2026-11-02T00:00:00Z")
        self.assertEqual(shards._atom_clock("2026-11-02T10:30:00+00:00"), "2026-11-02T10:30:00Z")
        self.assertEqual(shards._atom_clock("2026-11-02T10:30:00Z"), "2026-11-02T10:30:00Z")
        self.assertEqual(shards._atom_clock("2026-11-02T12:30:00+02:00"), "2026-11-02T10:30:00Z")
        self.assertIsNone(shards._atom_clock("not a clock"))
        self.assertIsNone(shards._atom_clock(None))
        self.assertEqual(shards._day_label("2026-11-02T10:30:00Z"), "2 Nov 2026")
        self.assertEqual(shards._stamp_label("2026-11-02T10:30:00+00:00"), "2 Nov 2026 10:30 UTC")
        self.assertEqual(shards._stamp_label("2026-11-02"), "2 Nov 2026")

    def test_the_next_patch_tuesday_is_the_second_tuesday_on_or_after_the_day(self):
        self.assertEqual(shards.second_tuesday(2026, 11), date(2026, 11, 10))
        self.assertEqual(shards.second_tuesday(2026, 12), date(2026, 12, 8))
        self.assertEqual(shards.next_patch_tuesday(date(2026, 11, 1)), date(2026, 11, 10))
        self.assertEqual(shards.next_patch_tuesday(date(2026, 11, 10)), date(2026, 11, 10))
        self.assertEqual(shards.next_patch_tuesday(date(2026, 11, 11)), date(2026, 12, 8))
        self.assertEqual(shards.next_patch_tuesday(date(2026, 12, 9)), date(2027, 1, 12))
        self.assertEqual(shards.previous_patch_tuesday(date(2026, 11, 10)), date(2026, 10, 13))
        self.assertEqual(shards.previous_patch_tuesday(date(2027, 1, 12)), date(2026, 12, 8))

    def test_the_kev_feed_holds_the_newest_catalog_entries_with_hub_links(self):
        entries = [kev_entry("CVE-2026-10002", "2026-10-30", "Follow BOD 26-04 guidance.", knownRansomwareCampaignUse="Known"),
                   kev_entry("CVE-2026-10001", "2026-10-30", "Apply updates per vendor instructions."),
                   kev_entry("CVE-2021-44228", "2021-12-10", "Follow applicable BOD 22-01 guidance.")]
        files = shards.kev_ledger({"vulnerabilities": entries})
        items = shards.kev_feed_entries(files)
        self.assertEqual([item["id"] for item in items], [shards.ATOM_TAG + ":kev:CVE-2026-10002", shards.ATOM_TAG + ":kev:CVE-2026-10001", shards.ATOM_TAG + ":kev:CVE-2021-44228"])
        self.assertEqual(items[0]["title"], "CVE-2026-10002: Example Vendor Example Product")
        self.assertEqual(items[0]["link"], shards.HUB_URL + "#/cve/CVE-2026-10002")
        self.assertEqual(items[0]["updated"], "2026-10-30T00:00:00Z")
        self.assertIn("CISA names it: Example record CVE-2026-10002.", items[0]["summary"])
        self.assertIn("federal due date is 20 Nov 2026 under BOD 26-04.", items[0]["summary"])
        self.assertIn("known ransomware campaign use", items[0]["summary"])
        self.assertNotIn("ransomware", items[1]["summary"])
        many = {"vulnerabilities": [kev_entry("CVE-2026-" + str(20000 + number), "2026-10-01", "Apply updates.") for number in range(80)]}
        self.assertEqual(len(shards.kev_feed_entries(shards.kev_ledger(many))), shards.ATOM_ENTRIES)

    def test_the_incident_feed_orders_by_update_and_links_the_hub_and_the_vendor_page(self):
        def incident(source, ident, started, updated=None, resolved=None, url=None):
            return {"source": source, "vendor": None, "id": ident, "name": "Incident " + ident + " <" + source + ">", "status": "resolved" if resolved else "investigating",
                    "status_raw": None, "impact": "minor", "impact_raw": None, "components": ["API", "Git"], "started": started, "updated": updated or started,
                    "resolved": resolved, "url": url or "https://www." + source + "status.com/incidents/" + ident, "summary": None}
        files = {"status/current.json": {"sources": [{"id": "github", "name": "GitHub"}, {"id": "tenable", "name": "Tenable"}]},
                 "status/2026-11.json": {"rows": [incident("github", "a1", "2026-11-01T10:00:00+00:00", "2026-11-01T12:00:00+00:00", "2026-11-01T12:00:00+00:00"),
                                                  incident("tenable", "b2", "2026-11-02T09:00:00+00:00")]},
                 "status/2026-10.json": {"rows": [incident("github", "c3", "2026-10-05T10:00:00+00:00", resolved="2026-10-05T11:00:00+00:00")]}}
        items = shards.incident_feed_entries(files)
        self.assertEqual([item["title"] for item in items], ["Tenable: Incident b2 <tenable>", "GitHub: Incident a1 <github>", "GitHub: Incident c3 <github>"])
        self.assertEqual(items[0]["link"], shards.HUB_URL + "#/status?source=tenable")
        self.assertEqual(items[0]["related"], "https://www.tenablestatus.com/incidents/b2")
        self.assertEqual((items[0]["updated"], items[0]["published"]), ("2026-11-02T09:00:00Z", "2026-11-02T09:00:00Z"))
        self.assertEqual(items[0]["summary"], "Status investigating. Impact minor. Components: API, Git. Started 2 Nov 2026 09:00 UTC; not resolved at the collector's read.")
        self.assertEqual(items[1]["summary"], "Status resolved. Impact minor. Components: API, Git. Started 1 Nov 2026 10:00 UTC; resolved 1 Nov 2026 12:00 UTC.")
        self.assertEqual(items[1]["updated"], "2026-11-01T12:00:00Z")
        # A cancelled or completed incident is resolved by its normalized status even when the status
        # page recorded no resolution time (status.is_open reads both fields the same way).
        cancelled = {**incident("zscaler", "32496", "2026-11-02T05:41:00+00:00"), "status": "resolved", "status_raw": "Cancelled", "resolved": None}
        [item] = shards.incident_feed_entries({"status/2026-11.json": {"rows": [cancelled]}})
        self.assertEqual(item["summary"], "Status resolved. Impact minor. Components: API, Git. Started 2 Nov 2026 05:41 UTC; resolved, time not recorded.")
        self.assertNotIn("not resolved", item["summary"])
        self.assertEqual(len({item["id"] for item in items}), 3)
        self.assertEqual(shards.incident_feed_entries({}), [])
        raw = shards.atom_document("incidents", "T", "S", "#/status", items, "R")
        self.assertEqual(atom_entries(raw)[1][0]["title"], "Tenable: Incident b2 <tenable>")

    def test_the_patch_calendar_leads_with_the_next_release_then_every_built_month(self):
        month = {"month": "2026-10", "id": "2026-Oct", "title": "2026 October Security Updates", "initial_release": "2026-10-14T07:00:00Z",
                 "current_release": "2026-10-20T07:00:00Z", "path": "patch-tuesday/2026-10.json", "total": 120, "critical": 8, "important": 100,
                 "exploited": 3, "disclosed": 2, "in_kev": 4, "kev_added_in_month": 5, "adobe": 6, "sap": 7}
        items = shards.patch_feed_entries({"patch-tuesday/index.json": {"months": [month]}}, date(2026, 11, 1))
        self.assertEqual([item["title"] for item in items], ["Next Patch Tuesday: 10 Nov 2026", "Patch Tuesday October 2026: 120 CVEs, 8 Critical, 3 exploited"])
        self.assertEqual(items[0]["link"], shards.HUB_URL + "#/patch-tuesday")
        # The lead entry's clock is the day after the previous release (13 Oct 2026), never the future.
        self.assertEqual((items[0]["updated"], items[0]["published"]), ("2026-10-14T00:00:00Z", "2026-10-14T00:00:00Z"))
        self.assertLessEqual(items[0]["updated"][:10], "2026-11-01")
        self.assertEqual(items[1]["link"], shards.HUB_URL + "#/patch-tuesday/2026-10")
        self.assertEqual((items[1]["updated"], items[1]["published"]), ("2026-10-20T07:00:00Z", "2026-10-14T07:00:00Z"))
        self.assertEqual(items[1]["summary"], "Microsoft's 2026 October Security Updates, released 14 Oct 2026, revised 20 Oct 2026: 120 CVEs, 8 rated Critical, "
                                              "100 Important, 3 exploited at release, 2 publicly disclosed, 4 in CISA's KEV catalog. Adobe headline rows: 6. SAP headline rows: 7.")
        self.assertEqual(shards.patch_feed_entries({}, date(2026, 11, 1)), [])

    def test_a_build_writes_the_three_feeds_lists_them_and_gives_the_same_bytes_again(self):
        workspace = Workspace(synthetic_cache(publisher_rows=300, kev_rows=60))
        try:
            workspace.build()
            feeds = feed_files(workspace)
            self.assertEqual(sorted(feeds), ["feeds/incidents.xml", "feeds/kev.xml", "feeds/patch-calendar.xml"])
            index = index_of(workspace)
            self.assertEqual(index["feeds"]["status"], "ok")
            self.assertEqual([item["path"] for item in index["feeds"]["files"]], sorted(feeds))
            for item in index["feeds"]["files"]:
                self.assertEqual((item["bytes"], item["sha256"]), (len(feeds[item["path"]]), shards.sha256(feeds[item["path"]])))
                self.assertLessEqual(item["bytes"], shards.ATOM_MAX_BYTES)
            self.assertFalse(any(entry["path"].startswith("feeds/") for entry in index["shards"]), "feeds are not shards")
            _feed, kev = atom_entries(feeds["feeds/kev.xml"])
            self.assertEqual(len(kev), shards.ATOM_ENTRIES)
            self.assertEqual([item["updated"] for item in kev], sorted((item["updated"] for item in kev), reverse=True))
            self.assertTrue(all(item["links"]["alternate"].startswith(shards.HUB_URL + "#/cve/CVE-") for item in kev))
            # No service-health rows in this workspace: an empty incidents feed, still well formed. No Patch
            # Tuesday document is read offline, so the calendar carries the next expected release alone.
            feed, entries = atom_entries(feeds["feeds/incidents.xml"])
            self.assertEqual((entries, feed.find(ATOM + "updated").text), ([], shards.ATOM_EPOCH))
            feed, entries = atom_entries(feeds["feeds/patch-calendar.xml"])
            self.assertEqual([item["title"] for item in entries], ["Next Patch Tuesday: 10 Nov 2026"])
            self.assertEqual(feed.find(ATOM + "updated").text, "2026-10-14T00:00:00Z")
            workspace.build()
            self.assertEqual(feed_files(workspace), feeds, "the same inputs give the same feed bytes")
            self.assertFalse(shards.feeds_changed(index, index_of(workspace)["feeds"]))
            self.assertTrue(shards.feeds_changed(None, index["feeds"]))
            self.assertTrue(shards.feeds_changed({"shards": []}, index["feeds"]))
            self.assertFalse(shards.feeds_changed({"shards": []}, None))
            self.assertTrue(shards.feeds_changed(index, shards.feeds_entry(None, "left out")))
            self.assertEqual(shards.feeds_entry(None, "left out"), {"status": "unavailable", "reason": "left out", "files": []})
        finally:
            workspace.close()

    def test_an_index_without_feeds_still_validates_and_a_bad_feeds_entry_is_refused(self):
        workspace = Workspace(synthetic_cache(publisher_rows=300, kev_rows=60))
        try:
            workspace.build()
            index = index_of(workspace)
            without = {key: value for key, value in index.items() if key != "feeds"}
            shards.validate_index(copy.deepcopy(without))
            for bad in ({**index["feeds"], "files": [{**index["feeds"]["files"][0], "path": "feeds/other.xml"}]},
                        {**index["feeds"], "files": [{**index["feeds"]["files"][0], "path": "exports/kev.xml"}]},
                        {**index["feeds"], "status": "unavailable"},
                        {**index["feeds"], "files": index["feeds"]["files"] + index["feeds"]["files"][:1]},
                        {**index["feeds"], "files": [{**index["feeds"]["files"][0], "bytes": shards.ATOM_MAX_BYTES + 1}]}):
                with self.assertRaisesRegex(ValueError, "feed"):
                    shards.validate_index({**copy.deepcopy(without), "feeds": bad})
        finally:
            workspace.close()


class ResumeV7Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = Workspace(synthetic_cache(publisher_rows=900, kev_rows=200))
        cls.workspace.build()
        cls.files = {collect.PUBLIC_V7 + path: raw for path, raw in v7_files(cls.workspace).items()}
        cls.files[collect.PUBLIC_FEED] = cls.workspace.raw("feed.json")
        cls.files[collect.PUBLIC_BRIEFS] = cls.workspace.raw("briefs.json")

    @classmethod
    def tearDownClass(cls):
        cls.workspace.close()

    def serve(self, files):
        def fetch(url, maximum=collect.MAX_BYTES, fresh=False, ceiling=collect.FETCH_CEILING):
            self.assertTrue(fresh)
            self.assertLessEqual(maximum, ceiling)
            if url == collect.PUBLIC_BRIEFS:
                self.assertEqual((maximum, ceiling), (collect.BRIEFS_MAX_BYTES, collect.DEPLOYED_BRIEFS_CEILING))
            else:
                self.assertEqual(ceiling, collect.FETCH_CEILING)
            if url not in files:
                raise OSError("HTTP Error 404: Not Found")
            value = files[url]
            if isinstance(value, list):
                value = value.pop(0) if len(value) > 1 else value[0]
            self.assertLessEqual(len(value), maximum)
            return value
        return mock.patch.object(collect, "fetch", side_effect=fetch)

    def test_an_index_entry_between_the_v7_file_cap_and_the_feed_bound_is_invalid(self):
        index = json.loads(self.files[collect.PUBLIC_V7 + "index.json"])
        shards.validate_index(copy.deepcopy(index))
        index["shards"][0]["bytes"] = shards.V7_FILE_MAX_BYTES + 1
        self.assertLess(index["shards"][0]["bytes"], collect.FEED_MAX_BYTES)
        with self.assertRaisesRegex(ValueError, "Invalid v7 shard entry"):
            shards.validate_index(index)

    def test_resume_reads_the_index_and_shards_not_the_feed(self):
        with self.serve(dict(self.files)) as fetch, contextlib.redirect_stderr(io.StringIO()):
            previous, reason = collect.resume_deployed(support.sources(), {"sources": {}, "kev": {}})
        self.assertIsNone(reason)
        self.assertIn("v7_index", previous)
        urls = [call.args[0] for call in fetch.call_args_list]
        self.assertNotIn(collect.PUBLIC_FEED, urls)
        self.assertEqual(urls[0], collect.PUBLIC_V7 + "index.json")
        self.assertNotIn(collect.PUBLIC_V7 + "kev/2026.json", urls)
        feed = self.workspace.json("feed.json")
        self.assertEqual(sorted(article["id"] for article in previous["articles"]), sorted(article["id"] for article in feed["articles"]))
        self.assertEqual(previous["mitigations"], self.workspace.json("briefs.json")["briefs"])
        self.assertEqual(previous["content_revision"], feed["content_revision"])

    def test_a_shard_from_another_deploy_falls_back_to_the_feed(self):
        files = dict(self.files)
        shard = next(url for url in files if "/v7/live/" in url)
        raw = bytearray(files[shard])
        raw[-3] = ord("0") if raw[-3] != ord("0") else ord("1")
        files[shard] = bytes(raw)
        with self.serve(files) as fetch, contextlib.redirect_stderr(io.StringIO()) as log:
            previous, reason = collect.resume_deployed(support.sources(), {"sources": {}, "kev": {}})
        self.assertIsNone(reason)
        self.assertNotIn("v7_index", previous)
        self.assertIn("reading the index once more", log.getvalue())
        self.assertIn("reading data/feed.json", log.getvalue())
        self.assertIn(collect.PUBLIC_FEED, [call.args[0] for call in fetch.call_args_list])

    def test_an_undeployed_index_falls_back_to_the_feed(self):
        files = {url: raw for url, raw in self.files.items() if "/v7/" not in url}
        with self.serve(files), contextlib.redirect_stderr(io.StringIO()) as log:
            previous, reason = collect.resume_deployed(support.sources(), {"sources": {}, "kev": {}})
        self.assertIsNone(reason)
        self.assertNotIn("v7_index", previous)
        self.assertIn("HTTP Error 404", log.getvalue())

    def test_a_resumed_build_extends_the_deployed_run_chain(self):
        index = json.loads(self.files[collect.PUBLIC_V7 + "index.json"])
        earlier = dict(index, runs=[{"generated_at": "2026-11-01T04:00:00+00:00", "trigger": "schedule", "changed": True},
                                    {"generated_at": "2026-10-31T22:00:00+00:00", "trigger": "schedule", "changed": True}])
        files = dict(self.files)
        files[collect.PUBLIC_V7 + "index.json"] = shards.canonical(earlier)
        workspace = Workspace(synthetic_cache(publisher_rows=900, kev_rows=200))
        try:
            with self.serve(files):
                result = workspace.build(resume_public=True)
            chain = index_of(workspace)["runs"]
            self.assertEqual([run["generated_at"] for run in chain],
                             ["2026-11-01T12:00:00+00:00", "2026-11-01T04:00:00+00:00", "2026-10-31T22:00:00+00:00"])
            self.assertEqual(index_of(workspace)["observed_interval_hours"], {"median": 7.0, "max": 8.0, "runs_counted": 3})
            self.assertEqual(result["v7"]["runs_recorded"], 3)
        finally:
            workspace.close()


class PackageTest(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace(synthetic_cache(publisher_rows=300, kev_rows=60))
        self.workspace.build()
        self.site = self.workspace.root / "site"

    def tearDown(self):
        self.workspace.close()

    def package(self, **caps):
        return shards.package_site(self.site, out=io.StringIO(), **caps)

    def test_the_built_site_matches_its_manifest(self):
        report = self.package()
        index = index_of(self.workspace)
        self.assertTrue(index["exports"]["files"])
        self.assertEqual(len(index["feeds"]["files"]), 3)
        # The page files site/files.json lists (and files.json), index.json and the two v6 files.
        self.assertEqual(report["files"], len(index["shards"]) + len(index["exports"]["files"]) + len(index["feeds"]["files"]) + len(support.site_files()) + 3)
        self.assertEqual((report["exports"], report["feeds"]), (len(index["exports"]["files"]), 3))
        self.assertLess(report["compressed_estimate"], report["input_bytes"])

    def test_the_report_prints_every_cap_with_its_headroom(self):
        out = io.StringIO()
        report = shards.package_site(self.site, out=out)
        text = out.getvalue()
        self.assertEqual((report["files_cap"], report["v7_file_cap"], report["input_cap"], report["compressed_cap"]),
                         (4000, 4 * 1024 * 1024, 192 * 1024 * 1024, 48000000))
        for key in ("files_headroom", "v7_file_headroom", "input_headroom", "compressed_headroom"):
            self.assertIn(format(report[key], ",") + " of headroom", text, key)

    def test_the_report_prints_every_v7_file_before_the_caps(self):
        out = io.StringIO()
        shards.package_site(self.site, out=out)
        lines = out.getvalue().splitlines()
        index = index_of(self.workspace)
        base = self.site / "data" / "v7"
        paths = sorted([entry["path"] for entry in index["shards"]] + [item["path"] for item in index["exports"]["files"]] +
                       [item["path"] for item in index["feeds"]["files"]] + ["index.json"])
        prefix = [line.split(": ", 1)[0] for line in lines[:len(paths)]]
        self.assertEqual(prefix, ["data/v7/" + path for path in paths])
        for path, line in zip(paths, lines):
            size = (base / path).stat().st_size
            self.assertTrue(line.startswith("data/v7/{}: {:,} of 4,194,304 bytes ({:,} of headroom".format(path, size, 4194304 - size)), line)
            self.assertEqual(path.startswith("history/"), "3,145,728-byte history split threshold" in line, line)
        self.assertEqual([line.split(":", 1)[0] for line in lines[len(paths):]],
                         ["Public files", "Largest v7 file", "Public input bytes", "Estimated compressed artifact bytes"])
        self.assertEqual(shards.headroom_line("history/2025-01.json", 3145730),
                         "data/v7/history/2025-01.json: 3,145,730 of 4,194,304 bytes (1,048,574 of headroom; "
                         "2 over the 3,145,728-byte history split threshold)")

    def test_an_unlisted_export_is_refused(self):
        (self.site / "data" / "v7" / "exports" / "articles-2099.csv").write_bytes(b"id\n")
        with self.assertRaisesRegex(shards.PackageError, "not listed in the manifest"):
            self.package()

    def test_an_export_outside_the_patterns_is_refused(self):
        (self.site / "data" / "v7" / "exports" / "notes.txt").write_bytes(b"private\n")
        with self.assertRaisesRegex(shards.PackageError, "outside the allowlisted patterns"):
            self.package()

    def test_a_changed_export_is_refused(self):
        path = self.site / "data" / "v7" / "exports" / "data-dictionary.md"
        path.write_bytes(path.read_bytes() + b"x")
        with self.assertRaisesRegex(shards.PackageError, "Byte count differs"):
            self.package()

    def test_a_missing_export_is_refused(self):
        (self.site / "data" / "v7" / "exports" / "manifest.json").unlink()
        with self.assertRaisesRegex(shards.PackageError, "missing"):
            self.package()

    def test_a_feed_outside_the_patterns_an_unlisted_a_changed_and_a_missing_feed_are_refused(self):
        feeds = self.site / "data" / "v7" / "feeds"
        (feeds / "notes.xml").write_bytes(b"<feed/>\n")
        with self.assertRaisesRegex(shards.PackageError, "outside the allowlisted patterns"):
            self.package()
        (feeds / "notes.xml").unlink()
        path = self.site / "data" / "v7" / "index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        kept = index["feeds"]["files"]
        index["feeds"]["files"] = [item for item in kept if item["path"] != "feeds/kev.xml"]
        path.write_bytes(shards.canonical(index))
        with self.assertRaisesRegex(shards.PackageError, "not listed in the manifest.*feeds/kev.xml"):
            self.package()
        index["feeds"]["files"] = kept
        path.write_bytes(shards.canonical(index))
        self.package()
        kev = feeds / "kev.xml"
        original = kev.read_bytes()
        kev.write_bytes(original + b"\n")
        with self.assertRaisesRegex(shards.PackageError, "Byte count differs.*feeds/kev.xml"):
            self.package()
        kev.unlink()
        with self.assertRaisesRegex(shards.PackageError, "missing.*feeds/kev.xml"):
            self.package()

    def test_the_per_file_cap_binds_v7_files_but_not_the_v6_files(self):
        # Without exports the largest v7 file is a shard, and the feed (every row) is larger.
        path = self.site / "data" / "v7" / "index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        index["exports"] = shards.exports_entry(None, "left out by this test")
        path.write_bytes(shards.canonical(index))
        shutil.rmtree(self.site / "data" / "v7" / "exports")
        report = self.package()
        largest = report["largest_v7_file"]
        feed = (self.site / "data" / "feed.json").stat().st_size
        self.assertGreater(feed, largest, "the synthetic feed is larger than every v7 file")
        self.assertEqual(self.package(max_v7_file=largest)["v7_file_headroom"], 0)
        with self.assertRaisesRegex(shards.PackageError, "per-file cap"):
            self.package(max_v7_file=largest - 1)

    def test_the_file_count_cap_binds(self):
        files = self.package()["files"]
        self.assertEqual(self.package(max_files=files)["files_headroom"], 0)
        with self.assertRaisesRegex(shards.PackageError, "file cap"):
            self.package(max_files=files - 1)

    def test_a_bad_exports_entry_is_refused(self):
        path = self.site / "data" / "v7" / "index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        index["exports"]["files"][0]["path"] = "exports/../../index.html"
        path.write_bytes(shards.canonical(index))
        with self.assertRaisesRegex(shards.PackageError, "manifest is invalid"):
            self.package()

    def test_an_extra_file_is_refused(self):
        (self.site / "data" / "v7" / "live" / "2099-01.json").write_bytes(b"{}\n")
        with self.assertRaisesRegex(shards.PackageError, "not listed in the manifest"):
            self.package()

    def test_a_file_outside_the_patterns_is_refused(self):
        (self.site / "notes.txt").write_bytes(b"private\n")
        with self.assertRaisesRegex(shards.PackageError, "outside the allowlisted patterns"):
            self.package()

    def test_a_missing_file_is_refused(self):
        path = next((self.site / "data" / "v7" / "kev").iterdir())
        path.unlink()
        with self.assertRaisesRegex(shards.PackageError, "missing"):
            self.package()

    def test_a_sha_mismatch_is_refused(self):
        path = self.site / "data" / "v7" / "sources.json"
        raw = bytearray(path.read_bytes())
        raw[-3] = ord("0") if raw[-3] != ord("0") else ord("1")
        path.write_bytes(bytes(raw))
        with self.assertRaisesRegex(shards.PackageError, "sha256 differs"):
            self.package()

    def test_a_v6_file_is_checked_too(self):
        path = self.site / "data" / "feed.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(shards.PackageError, "Byte count differs"):
            self.package()

    def test_a_symlink_is_refused(self):
        target = self.site / "data" / "v7" / "coverage.json"
        link = self.site / "data" / "v7" / "history" / "1990.json"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError) as error:
            self.skipTest("symbolic links cannot be created here: " + str(error))
        with self.assertRaisesRegex(shards.PackageError, "Links are not permitted"):
            self.package()

    def test_a_hard_link_is_refused(self):
        os.link(self.site / "data" / "v7" / "coverage.json", self.workspace.root / "coverage-copy.json")
        with self.assertRaisesRegex(shards.PackageError, "single-link"):
            self.package()

    def test_an_unexpected_directory_is_refused(self):
        (self.site / "data" / "v7" / "drafts").mkdir()
        with self.assertRaisesRegex(shards.PackageError, "unexpected directory"):
            self.package()

    def test_the_caps_still_bind(self):
        with self.assertRaisesRegex(shards.PackageError, "package input cap"):
            self.package(max_input=100000)
        with self.assertRaisesRegex(shards.PackageError, "compressed artifact"):
            self.package(max_compressed=1000)

    def test_a_bad_manifest_is_refused(self):
        path = self.site / "data" / "v7" / "index.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        index["shards"][0]["path"] = "../index.html"
        path.write_bytes(shards.canonical(index))
        with self.assertRaisesRegex(shards.PackageError, "manifest is invalid"):
            self.package()


class SiteTest(unittest.TestCase):
    def test_csp_allows_only_this_site(self):
        page = (support.ROOT / "site" / "index.html").read_text(encoding="utf-8")
        policy = re.search(r'Content-Security-Policy" content="([^"]+)"', page)[1]
        # This site, plus exactly the vendor status hosts the Service health live board reads.
        from intelligence_hub import status
        hosts = status.live_hosts(status.load_registry(support.ROOT))
        self.assertIn("connect-src 'self' " + " ".join("https://" + host for host in hosts) + ";", policy)
        for name in support.site_files():
            self.assertNotIn("api.github.com", (support.ROOT / "site" / name).read_text(encoding="utf-8"))

    def test_no_ten_minute_cadence_claim_outside_reports(self):
        claim = re.compile(r"\b(?:10|ten)[ -]minutes?\b", re.I)
        tracked = subprocess.run(["git", "ls-files"], cwd=support.ROOT, capture_output=True, text=True, check=True).stdout.split()
        found = []
        for name in tracked:
            if name.startswith("reports/") or not name.endswith((".md", ".py", ".js", ".html", ".css", ".yml", ".json")):
                continue
            text = (support.ROOT / name).read_text(encoding="utf-8", errors="replace")
            found += [name + ": " + match[0] for match in claim.finditer(text)]
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
