"""Service health (intelligence_hub/status.py): the registry, every normalizer on trimmed real
responses, observation and fallback, the month files and their caps, Explorer rows, the
publication decision, and the page's connect-src list."""
from datetime import date, datetime, timedelta, timezone
import io
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest import mock
import urllib.error
import urllib.parse

import support
from intelligence_hub import collect, shards, status

DOCS = support.FIXTURES / "status" / "documents"
REGISTRY = status.load_registry(support.ROOT)
SOURCES = {source["id"]: source for source in REGISTRY["sources"]}
CLOCK = "2026-11-01T12:00:00+00:00"


def doc(name):
    return (DOCS / name).read_bytes()


def parse(source_id, **documents):
    source = SOURCES[source_id]
    return status.PARSERS[source["format"]](source, {key: doc(value) for key, value in documents.items()})


def cache():
    return json.loads((support.FIXTURES / "status-cache.json").read_text(encoding="utf-8"))["sources"]


class RegistryTest(unittest.TestCase):
    def test_the_registry_validates_and_every_endpoint_is_canonical_https(self):
        self.assertGreaterEqual(len(status.tracked(REGISTRY)), 25)
        for source in REGISTRY["sources"]:
            for url in source["endpoints"].values():
                self.assertEqual(collect.safe_url(url), url)
                self.assertTrue(url.startswith("https://"))

    def test_no_complaint_or_scraped_source_is_registered(self):
        text = (support.ROOT / "config" / "status.json").read_text(encoding="utf-8").lower()
        self.assertNotIn("downdetector", text)
        for source in REGISTRY["sources"]:
            self.assertNotRegex(" ".join(source["endpoints"].values()), r"\.html?\b")

    def test_a_bad_registry_is_refused(self):
        def broken(change):
            value = json.loads((support.ROOT / "config" / "status.json").read_text(encoding="utf-8"))
            change(value)
            return value
        cases = [lambda value: value["sources"][0].update(id="Bad Id"),
                 lambda value: value["sources"][0]["endpoints"].update(status="http://status.tenable.com/api/v2/status.json"),
                 lambda value: value["sources"][0]["endpoints"].update(status="https://status.tenable.com/api/v2/summary.json"),
                 lambda value: value["sources"][0].update(group="elsewhere"),
                 lambda value: value["sources"][0].update(cors="yes"),
                 lambda value: value["sources"].append(dict(value["sources"][0])),
                 lambda value: value["page_only"].append({"id": "tenable", "name": "x", "vendor": None, "home": None, "reason": "x"}),
                 lambda value: value.update(extra=1)]
        for change in cases:
            with self.assertRaises(status.StatusError):
                status.validate_registry(broken(change))

    def test_connect_src_lists_exactly_the_live_hosts(self):
        page = (support.ROOT / "site" / "index.html").read_text(encoding="utf-8")
        policy = re.search(r'Content-Security-Policy" content="([^"]+)"', page)[1]
        connect = next(part.strip() for part in policy.split(";") if part.strip().startswith("connect-src"))
        hosts = connect.split()[2:]
        self.assertEqual(connect.split()[1], "'self'")
        self.assertEqual(hosts, ["https://" + host for host in status.live_hosts(REGISTRY)])
        # Only CORS-open Statuspage status endpoints are read by a browser.
        for source in REGISTRY["sources"]:
            url = status.live_url(source)
            if url:
                self.assertTrue(source["cors"])
                self.assertEqual(urllib.parse.urlsplit(url).path, "/api/v2/status.json")
            if not source["cors"]:
                self.assertIsNone(url)

    def test_vendor_and_library_ids_exist_and_library_ids_open_a_platform_page(self):
        from intelligence_hub import vocab
        loaded = vocab.load(support.ROOT)
        library = (support.ROOT / "site" / "js" / "library.js").read_text(encoding="utf-8")
        for item in REGISTRY["sources"] + REGISTRY["page_only"]:
            if item.get("vendor"):
                self.assertIn(item["vendor"], loaded.entities, item["id"])
            if item.get("library"):
                self.assertRegex(library, re.escape(json.dumps(item["library"])) + r': "https://teamstarwolf\.github\.io/TeamStarWolf/#/platforms/')

    def test_page_only_vendors_are_never_polled(self):
        ids = {item["id"] for item in REGISTRY["page_only"]}
        self.assertTrue({"crowdstrike", "okta", "datadog"} <= ids)
        self.assertFalse(ids & set(SOURCES))


class NormalizerTest(unittest.TestCase):
    def test_statuspage_summary_and_incidents(self):
        snap = parse("check-point", summary="statuspage/summary.json", incidents="statuspage/incidents.json")
        self.assertEqual(snap["indicator"], "minor")
        self.assertEqual(snap["description"], "Minor Service Outage")
        rows = {row["id"]: row for row in snap["incidents"]}
        self.assertEqual({row["id"] for row in rows.values() if status.is_open(row)}, {"ctxpqx5z4nb4", "dnncywl1n491"})
        october = rows["lng6p1wpj7l2"]
        self.assertEqual((october["status"], october["impact"], october["url"]), ("resolved", "major", "https://status.checkpoint.com/incidents/lng6p1wpj7l2"))
        self.assertEqual(rows["h2cvvr768kn1"]["status"], "resolved", "postmortem reads as resolved")
        self.assertEqual(rows["h2cvvr768kn1"]["status_raw"], "postmortem")
        self.assertEqual(rows["bqhbqv8pf8gw"]["impact"], "none")
        for row in rows.values():
            self.assertTrue(status.valid_incident(row, "check-point"))
            self.assertLessEqual(len(row["summary"] or ""), status.SUMMARY_MAX)
            self.assertNotIn("<", row["summary"] or "")

    def test_statuspage_maintenance_is_not_an_incident(self):
        source = SOURCES["check-point"]
        self.assertIsNone(status.statuspage_incident(source, {"id": "abcd1234", "name": "Window", "impact": "maintenance", "status": "completed", "created_at": "2026-10-01T00:00:00Z"}))
        self.assertIsNone(status.statuspage_incident(source, {"id": "abcd1234", "name": "Window", "impact": "minor", "status": "scheduled", "created_at": "2026-10-01T00:00:00Z"}))
        self.assertIsNone(status.statuspage_incident(source, {"id": "../etc", "name": "Bad id", "impact": "minor", "status": "resolved", "created_at": "2026-10-01T00:00:00Z"}))

    def test_google_incidents_json(self):
        snap = parse("google-cloud", incidents="google/incidents.json")
        row = snap["incidents"][0]
        self.assertEqual(row["url"], "https://status.cloud.google.com/incidents/" + row["id"])
        self.assertEqual(row["impact_raw"], "SERVICE_DISRUPTION severity medium")
        self.assertEqual(row["impact"], "minor")
        self.assertEqual(row["status"], "resolved")
        self.assertIn("AlloyDB for PostgreSQL", row["components"])
        self.assertNotIn("**", row["name"])

    def test_aws_events_in_utf16_with_a_byte_order_mark(self):
        raw = doc("aws/currentevents.json")
        self.assertEqual(raw[:2], b"\xff\xfe")
        snap = parse("aws", events="aws/currentevents.json")
        row = snap["incidents"][0]
        self.assertTrue(row["id"].startswith("arn:aws:health:"))
        self.assertEqual((row["impact"], row["impact_raw"]), ("major", "AWS status 3"))
        self.assertTrue(status.is_open(row))
        self.assertEqual(row["url"], "https://health.aws.amazon.com/health/status")
        self.assertEqual(snap["indicator"], "major")
        self.assertIn("Multiple services", row["components"])

    def test_azure_rss_empty_channel_and_one_item(self):
        self.assertEqual(parse("azure", feed="azure/feed.xml"), {"indicator": "none", "description": None, "incidents": []})
        item = doc("azure/feed.xml").replace(b"</channel>", b"<item><title>Azure Front Door: degraded connectivity</title><link>https://azure.status.microsoft/en-us/status</link>"
                                             b"<guid isPermaLink=\"false\">AFD-1</guid><pubDate>Tue, 03 Nov 2026 10:00:00 Z</pubDate><description>&lt;p&gt;Mitigation in progress&lt;/p&gt;</description></item></channel>")
        snap = status.parse_azure(SOURCES["azure"], {"feed": item})
        self.assertEqual(snap["indicator"], "minor")
        self.assertEqual(snap["incidents"][0]["summary"], "Mitigation in progress")
        self.assertIsNone(snap["incidents"][0]["impact_raw"], "Azure states no level; the minor floor keeps impact_raw null")

    def test_an_incident_link_off_the_vendor_host_falls_back_to_its_status_page(self):
        row = status.incident(SOURCES["slack"], "1", "Name", started="2026-11-01T00:00:00+00:00", url="https://evil.example.net/phish")
        self.assertEqual(row["url"], "https://slack-status.com/")
        row = status.incident(SOURCES["slack"], "1", "Name", started="2026-11-01T00:00:00+00:00", url="https://slack-status.com/2026-10/58a30c7fc8aa3e80")
        self.assertEqual(row["url"], "https://slack-status.com/2026-10/58a30c7fc8aa3e80")

    def test_rss_with_a_dtd_is_refused(self):
        with self.assertRaises(ValueError):
            status.parse_azure(SOURCES["azure"], {"feed": b'<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY x "y">]><rss><channel></channel></rss>'})

    def test_zscaler_recent_incidents_only(self):
        snap = parse("zscaler", feed="zscaler/rss-feed.xml")
        self.assertEqual(len(snap["incidents"]), 2, "scheduled maintenance is left out")
        open_rows = [row for row in snap["incidents"] if status.is_open(row)]
        self.assertEqual([row["id"] for row in open_rows], ["32531"])
        self.assertEqual(open_rows[0]["status"], "investigating")
        self.assertEqual(open_rows[0]["components"], ["zscalerthree.net"])

    def test_statuspage_rss_oracle(self):
        snap = parse("oracle-cloud", status="statuspage-rss/status.json", feed="statuspage-rss/history.rss")
        self.assertEqual((snap["indicator"], snap["description"]), ("none", "Normal Performance"))
        row = snap["incidents"][0]
        self.assertEqual(row["status"], "resolved")
        self.assertEqual(row["started"], "2026-03-04T10:10:00+00:00", "the start comes from the update's Start Time line")
        self.assertEqual(row["url"], "https://ocistatus.oraclecloud.com/")

    def test_json_formats(self):
        slack = parse("slack", current="slack/current.json", history="slack/history.json")
        self.assertEqual(slack["indicator"], "none")
        self.assertTrue(all(row["url"].startswith("https://slack-status.com/") for row in slack["incidents"]))
        heroku = parse("heroku", current="heroku/current-status.json")
        self.assertEqual((heroku["indicator"], heroku["incidents"]), ("none", []), "scheduled maintenance is not an incident")
        salesforce = parse("salesforce", active="salesforce/active.json")
        self.assertEqual(salesforce["incidents"][0]["name"], "Communities: Degradation on 5 instances")
        self.assertEqual(salesforce["incidents"][0]["started"], "2026-10-27T19:00:00+00:00")
        gitlab = parse("gitlab", status="statusio/status.json")
        self.assertEqual((gitlab["indicator"], gitlab["description"]), ("none", "Operational"))
        azdo = parse("azure-devops", health="azure-devops/health.json")
        self.assertEqual((azdo["indicator"], azdo["description"]), ("none", "Service maintenance is in effect"))
        better = parse("chainguard", index="betterstack/index.json")
        self.assertEqual(better["indicator"], "none")
        self.assertTrue(all(row["url"].startswith("https://status.chainguard.dev/incident/") for row in better["incidents"]))
        self.assertTrue(all(row["components"] for row in better["incidents"]))

    def test_ioda_events(self):
        until = datetime(2026, 11, 4, 6, 0, tzinfo=timezone.utc)
        rows, notice = status.parse_ioda(doc("ioda/events.json"), until)
        self.assertEqual(len(rows), 4)
        self.assertTrue(notice.startswith("This data is Copyright"))
        for row in rows:
            self.assertRegex(row["url"], r"^https://ioda\.inetintel\.cc\.gatech\.edu/country/[A-Z]{2}$")
            self.assertEqual(row["entity_type"], "country")
        url = status.ioda_url(SOURCES["ioda"], until)
        self.assertEqual(collect.safe_url(url), url)
        self.assertIn("from=" + str(int(until.timestamp()) - 86400), url)

    def test_radar_annotations_from_the_documented_example(self):
        example = {"result": {"annotations": [{"id": "550", "asnsDetails": [{"asn": "189", "name": "LUMEN"}], "description": "Cable cut", "endDate": None,
                   "linkedUrl": "http://example.com", "locationsDetails": [{"code": "US", "name": "United States"}], "outage": {"outageCause": "CABLE_CUT", "outageType": "NATIONWIDE"},
                   "scope": "Colima", "startDate": "2026-11-03T18:11:19.117Z"}]}, "success": True}
        rows = status.parse_radar(json.dumps(example).encode())
        self.assertEqual(rows[0]["locations"], ["United States"])
        self.assertEqual(rows[0]["url"], "https://radar.cloudflare.com/outage-center", "a non-HTTPS link falls back to Radar's own page")


class ObserveTest(unittest.TestCase):
    def test_only_registry_urls_are_read_and_radar_waits_for_its_token(self):
        seen = []

        def fetch(url, maximum=None, fresh=False):
            seen.append(url)
            raise OSError("offline")
        observations = status.observe(REGISTRY, fetch, clock=CLOCK)
        endpoints = {url for source in REGISTRY["sources"] for url in source["endpoints"].values()}
        for url in seen:
            self.assertTrue(url in endpoints or urllib.parse.urlunsplit(urllib.parse.urlsplit(url)._replace(query="")) in endpoints, url)
        self.assertFalse(any("cloudflare.com/client" in url for url in seen))
        self.assertEqual(observations["cloudflare-radar"]["status"], "not_configured")
        self.assertTrue(all(item["status"] == "failed" for key, item in observations.items() if key != "cloudflare-radar"))

    def test_a_failed_read_keeps_the_last_good_snapshot(self):
        old = cache()["check-point"]
        retained = {"check-point": {"indicator": old["indicator"], "description": old["description"], "incidents": [row for row in old["incidents"] if status.is_open(row)],
                                    "last_success": old["last_success"]}}
        chosen = {**REGISTRY, "sources": [SOURCES["check-point"]]}
        observations = status.observe(chosen, lambda *args, **kwargs: (_ for _ in ()).throw(OSError("HTTP 503")), previous=retained, clock="2026-11-02T00:00:00+00:00")
        item = observations["check-point"]
        self.assertEqual((item["status"], item["indicator"], item["last_success"]), ("failed", "minor", CLOCK))
        self.assertEqual(len(item["incidents"]), 2)
        files, _summary = status.build_files(REGISTRY, observations, {}, date(2026, 11, 2), "2026-11-02T00:00:00+00:00")
        board = next(source for source in files["status/current.json"]["sources"] if source["id"] == "check-point")
        self.assertEqual((board["status"], board["indicator"], len(board["open"])), ("failed", "minor", 2), "a failure never blanks a card")

    def test_the_radar_token_is_checked_and_never_reported(self):
        with self.assertRaises(ValueError):
            status.authorized_fetch("https://api.cloudflare.com/client/v4/radar/annotations/outages", "short")
        value, error = status.read_source(SOURCES["cloudflare-radar"], None, datetime(2026, 11, 1, tzinfo=timezone.utc), "x" * 40 + "\n")
        self.assertIsNone(value)
        self.assertNotIn("x" * 40, error)

    def test_the_cache_fixture_is_current_and_valid(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("status_build_cache", support.FIXTURES / "status" / "build_cache.py")
        build_cache = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build_cache)
        self.assertEqual(build_cache.build(), (support.FIXTURES / "status-cache.json").read_bytes().replace(b"\r\n", b"\n"))
        status.validate_observations({"schema_version": 1, "sources": cache()}, REGISTRY)
        bad = cache()
        bad["check-point"]["incidents"][0]["url"] = "javascript:alert(1)"
        with self.assertRaises(status.StatusError):
            status.validate_observations({"schema_version": 1, "sources": bad}, REGISTRY)


class FilesTest(unittest.TestCase):
    def build(self, previous=None, end=date(2026, 11, 1)):
        return status.build_files(REGISTRY, cache(), previous or {}, end, CLOCK)

    def test_the_files_and_their_paths(self):
        files, summary = self.build()
        self.assertTrue({"status/current.json", "status/outages.json", "status/index.json", "status/2026-10.json"} <= set(files))
        for path in files:
            self.assertRegex(path, shards.SHARD_PATH)
            self.assertLessEqual(len(shards.canonical(files[path])), shards.SHARD_MAX_BYTES)
        current = files["status/current.json"]
        self.assertEqual([source["id"] for source in current["sources"]], [source["id"] for source in status.tracked(REGISTRY)])
        self.assertEqual(summary["status"], "ok")
        index = files["status/index.json"]
        self.assertEqual([item["path"] for item in index["months"]], sorted(path for path in files if status.MONTH_PATH.fullmatch(path)))
        self.assertEqual(files["status/outages.json"]["radar"]["status"], "not_fetched")

    def test_rows_are_deduplicated_and_a_later_update_is_folded_in(self):
        files, _summary = self.build()
        october = files["status/2026-10.json"]["rows"]
        row = next(item for item in october if item["id"] == "lng6p1wpj7l2")
        later = {**row, "status": "resolved", "updated": "2026-10-30T00:00:00+00:00", "summary": "Later text"}
        earlier = {**row, "updated": "2026-10-01T00:00:00+00:00", "summary": "Earlier text"}
        files, _summary = self.build({"2026-10": [later, earlier]})
        rows = [item for item in files["status/2026-10.json"]["rows"] if item["id"] == "lng6p1wpj7l2"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["summary"], "Later text")

    def test_thirteen_months_are_kept_and_later_incidents_wait(self):
        old = {**cache()["check-point"]["incidents"][0], "id": "old00001", "started": "2025-10-01T00:00:00+00:00", "updated": "2025-10-01T00:00:00+00:00"}
        kept = {**old, "id": "kept0001", "started": "2025-11-01T00:00:00+00:00", "updated": "2025-11-01T00:00:00+00:00"}
        files, _summary = self.build({"2025-10": [old], "2025-11": [kept]})
        self.assertNotIn("status/2025-10.json", files)
        self.assertIn("status/2025-11.json", files)
        self.assertEqual(len(status.months_window(date(2026, 11, 1))), 13)
        self.assertFalse(any(row["started"][:10] > "2026-11-01" for path in files if status.MONTH_PATH.fullmatch(path) for row in files[path]["rows"]))

    def test_the_board_digest_ignores_clocks(self):
        files, _summary = self.build()
        current = files["status/current.json"]
        moved = json.loads(json.dumps(current))
        moved["generated_at"] = "2026-11-02T00:00:00+00:00"
        for source in moved["sources"]:
            source["fetched_at"] = "2026-11-02T00:00:00+00:00"
        self.assertEqual(status.board_digest(current), status.board_digest(moved))
        moved["sources"][0]["indicator"] = "critical"
        self.assertNotEqual(status.board_digest(current), status.board_digest(moved))
        _files, summary = status.build_files(REGISTRY, cache(), {}, date(2026, 11, 1), CLOCK, status.board_digest(current))
        self.assertFalse(summary["board_changed"])

    def test_the_outages_digest_ignores_clocks(self):
        files, summary = self.build()
        outages = files["status/outages.json"]
        self.assertTrue(summary["outages_changed"], "no previous digest counts as a change")
        moved = json.loads(json.dumps(outages))
        moved["generated_at"] = "2026-11-02T00:00:00+00:00"
        for block in ("ioda", "radar"):
            moved[block]["fetched_at"] = "2026-11-02T00:00:00+00:00"
            moved[block]["last_success"] = "2026-11-02T00:00:00+00:00"
        self.assertEqual(status.outages_digest(outages), status.outages_digest(moved))
        moved["ioda"]["rows"] = moved["ioda"]["rows"][1:]
        self.assertNotEqual(status.outages_digest(outages), status.outages_digest(moved))
        _files, summary = status.build_files(REGISTRY, cache(), {}, date(2026, 11, 1), CLOCK, None, status.outages_digest(outages))
        self.assertFalse(summary["outages_changed"])

    def test_a_month_over_the_shard_bound_drops_its_oldest_rows_to_fit(self):
        template = cache()["check-point"]["incidents"][0]
        base = datetime(2026, 10, 1, tzinfo=timezone.utc)
        big = []
        for number in range(2400):
            clock = (base + timedelta(minutes=number)).isoformat(timespec="seconds")
            big.append({**template, "id": "big{:05d}".format(number), "name": "N" * status.NAME_MAX, "summary": "S" * status.SUMMARY_MAX,
                        "components": ["C" * status.COMPONENT_MAX] * status.COMPONENTS_MAX, "started": clock, "updated": clock,
                        "resolved": clock, "status": "resolved"})
        self.assertTrue(all(status.valid_incident(row) for row in big))
        self.assertGreater(len(shards.canonical({"rows": big})), shards.SHARD_MAX_BYTES, "the rows really are over the bound")
        files, summary = self.build({"2026-10": big})
        path = "status/2026-10.json"
        month = files[path]
        self.assertLessEqual(len(shards.canonical(month)), shards.SHARD_MAX_BYTES)
        kept = {row["id"] for row in month["rows"]}
        dropped = [row for row in big if row["id"] not in kept]
        self.assertTrue(dropped)
        self.assertLess(max(row["started"] for row in dropped), min(row["started"] for row in month["rows"]), "the oldest rows go first")
        # No more than needed: one dropped row back puts the month over the bound.
        self.assertGreater(len(shards.canonical({**month, "rows": [dropped[-1]] + month["rows"]})), shards.SHARD_MAX_BYTES)
        self.assertEqual(summary["truncated_rows"], len(dropped))
        self.assertEqual(files["status/index.json"]["truncated_rows"], len(dropped))
        self.assertEqual(next(entry["rows"] for entry in files["status/index.json"]["months"] if entry["path"] == path), len(month["rows"]))
        shards.serialize(files)  # every file fits, so serialization no longer fails the run

    def test_shard_rows_and_spans(self):
        files, _summary = self.build()
        raw, entries = shards.serialize(files)
        by_path = {entry["path"]: entry for entry in entries}
        self.assertEqual(by_path["status/current.json"]["rows"], len(status.tracked(REGISTRY)))
        self.assertEqual(by_path["status/2026-10.json"]["from"][:7], "2026-10")
        self.assertEqual(by_path["status/outages.json"]["rows"], 4)
        for path in raw:
            self.assertTrue(shards.headroom_line(path, len(raw[path])).startswith("data/v7/" + path + ": "))


class ExplorerRowTest(unittest.TestCase):
    def test_minor_and_above_become_tagged_outage_rows_with_the_vendor(self):
        files, _summary = status.build_files(REGISTRY, cache(), {}, date(2026, 11, 1), CLOCK)
        rows = status.explorer_rows(files, REGISTRY)
        every = [row for path in files if status.MONTH_PATH.fullmatch(path) for row in files[path]["rows"]]
        self.assertEqual(len(rows), sum(1 for row in every if row["impact"] in status.EXPLORER_IMPACTS))
        for row in rows:
            self.assertEqual((row["origin"], row["kind"], row["date_basis"]), ("service-status", "incident", status.DATE_BASIS))
            self.assertRegex(row["id"], r"^status-[a-z0-9-]+-[A-Za-z0-9._:-]+$")
            self.assertLessEqual(len(row["id"]), 100)
            self.assertEqual(collect.safe_url(row["url"]), row["url"])
            self.assertTrue(row["source_id"].startswith("status-"))
        from intelligence_hub import tagging, vocab
        context = tagging.build_context(vocab.load(support.ROOT), [], None, {})
        tagged = status.tag_rows(rows, REGISTRY, context, None, {})
        checkpoint = next(row for row in tagged if row["source_id"] == "status-check-point")
        self.assertIn(["outage", "status-incident", "high"], checkpoint["tagging"]["event_type"])
        self.assertIn(["vendor:check-point", "source-identity", "high"], checkpoint["tagging"]["vendor"])
        self.assertTrue(all(["outage", "status-incident", "high"] in row["tagging"]["event_type"] for row in tagged))
        self.assertFalse(any(item[0] == "unclassified" for row in tagged for item in row["tagging"]["event_type"]))

    def test_an_unsafe_incident_id_is_hashed_into_the_row_id(self):
        row = {**cache()["aws"]["incidents"][0]}
        self.assertTrue(status.row_id(row).startswith("status-aws-"))
        self.assertRegex(status.row_id(row), r"^status-aws-[a-f0-9]{16}$")


class LiveShardBoundTest(unittest.TestCase):
    def test_a_month_of_six_thousand_minor_incidents_never_pushes_its_live_shard_over_the_bound(self):
        template = cache()["check-point"]["incidents"][0]
        base = datetime(2026, 10, 1, tzinfo=timezone.utc)
        incidents = []
        for number in range(6000):
            clock = (base + timedelta(minutes=7 * number)).isoformat(timespec="seconds")
            incidents.append({**template, "id": "minor{:05d}".format(number), "name": "Degraded performance in region " + str(number % 40) + " " + "N" * 60,
                              "summary": "S" * 160, "impact": "minor", "impact_raw": "minor", "started": clock, "updated": clock, "resolved": clock,
                              "status": "resolved"})
        self.assertTrue(all(status.valid_incident(row) for row in incidents))
        files, _summary = status.build_files(REGISTRY, {}, {"2026-10": incidents}, date(2026, 11, 1), CLOCK)
        month = files["status/2026-10.json"]
        self.assertLessEqual(len(shards.canonical(month)), shards.SHARD_MAX_BYTES, "fit_month bounds the status month file")
        explorer = status.explorer_rows(files, REGISTRY)
        self.assertEqual(len(explorer), len(month["rows"]))
        self.assertGreater(len(explorer), 5000)
        # The month's publisher rows share live/2026-10.json with the status rows.
        publisher = [{**explorer[number], "id": "feed-row-{:05d}".format(number), "origin": "feed", "kind": "news", "source_id": "example-feed"}
                     for number in range(0, len(explorer), 3)]
        end = date(2026, 11, 1)
        live = shards.live_start(end)
        path = shards.article_path(explorer[0], live)
        self.assertEqual(path, "live/2026-10.json")
        whole = shards.article_shard("2026-10", sorted(publisher + explorer, key=shards.row_order))
        self.assertGreater(len(shards.canonical(whole)), shards.SHARD_MAX_BYTES, "together the rows really are over the bound")
        kept, held = collect.fit_status_rows(publisher, explorer, end)
        self.assertGreater(held, 0)
        self.assertEqual(len(kept) + held, len(explorer))
        shard = shards.article_shard("2026-10", sorted(publisher + kept, key=shards.row_order))
        self.assertLessEqual(len(shards.canonical(shard)), shards.SHARD_MAX_BYTES)
        self.assertEqual(sum(row["origin"] == "feed" for row in shard["rows"]), len(publisher), "publisher rows are never dropped")
        kept_ids = {row["id"] for row in kept}
        dropped = sorted((row for row in explorer if row["id"] not in kept_ids), key=shards.row_order)
        self.assertLessEqual(max(shards.row_order(row) for row in dropped), min(shards.row_order(row) for row in kept), "the oldest rows go first")
        # No more than needed: the newest held-back row put back passes the bound again.
        again = shards.article_shard("2026-10", sorted(publisher + kept + [dropped[-1]], key=shards.row_order))
        self.assertGreater(len(shards.canonical(again)), shards.SHARD_MAX_BYTES)
        shards.serialize({"live/2026-10.json": shard})
        # A month inside the bound keeps every row.
        self.assertEqual(collect.fit_status_rows([], explorer[:100], end), (explorer[:100], 0))


class BuildTest(unittest.TestCase):
    def test_the_offline_build_writes_the_status_files_and_explorer_rows(self):
        workspace = support.BuildCopy()
        try:
            code, result, output = workspace.run()
            self.assertEqual(code, 0, output[-2000:])
            base = workspace.root / "site" / "data" / "v7"
            index = json.loads((base / "index.json").read_text(encoding="utf-8"))
            listed = {entry["path"]: entry for entry in index["shards"]}
            for path in ("status/current.json", "status/outages.json", "status/index.json", "status/2026-10.json"):
                self.assertIn(path, listed)
                raw = (base / path).read_bytes()
                self.assertEqual((len(raw), shards.sha256(raw)), (listed[path]["bytes"], listed[path]["sha256"]))
            self.assertGreater(index["counts"]["status_rows"], 0)
            october = json.loads((base / "live" / "2026-10.json").read_text(encoding="utf-8"))["rows"]
            incident = [row for row in october if row["origin"] == "service-status"]
            self.assertTrue(incident)
            self.assertTrue(any(["vendor:check-point", "source-identity", "high"] in row["tagging"].get("vendor", []) for row in incident))
            self.assertEqual(result["status"]["status"], "ok")
            self.assertEqual(result["status"]["explorer_rows_held"], 0)
            self.assertIn("data/v7/status/current.json: ", output)
            # The v6 feed is unchanged by service health: its rows stay publisher, KEV and curated.
            self.assertFalse(any(row["origin"] == "service-status" for row in workspace.feed()["articles"]))
        finally:
            workspace.close()

    def test_a_broken_registry_never_blocks_the_feed(self):
        workspace = support.BuildCopy()
        try:
            (workspace.root / "config" / "status.json").write_text("{}", encoding="utf-8")
            code, result, output = workspace.run()
            self.assertEqual(code, 0, output[-2000:])
            self.assertEqual(result["status"]["status"], "unavailable")
            index = json.loads((workspace.root / "site" / "data" / "v7" / "index.json").read_text(encoding="utf-8"))
            self.assertFalse(any(entry["path"].startswith("status/") for entry in index["shards"]))
        finally:
            workspace.close()

    def test_clock_only_changes_never_republish(self):
        self.assertEqual(status.QUIET, ("status/current.json", "status/index.json", "status/outages.json"))
        source = (support.ROOT / "intelligence_hub" / "collect.py").read_text(encoding="utf-8")
        self.assertIn('changed = publication_changed(changed, v7["changed_shards"], v7["removed_shards"], v7["exports_changed"], service_health["summary"])', source)
        quiet = {"board_changed": False, "outages_changed": False}
        clocks = ["sources.json", "status/current.json", "status/index.json", "status/outages.json"]
        self.assertFalse(collect.publication_changed(False, clocks, [], False, quiet))
        self.assertTrue(collect.publication_changed(False, clocks, [], False, {**quiet, "outages_changed": True}))
        self.assertTrue(collect.publication_changed(False, clocks, [], False, {**quiet, "board_changed": True}))
        self.assertTrue(collect.publication_changed(False, clocks + ["status/2026-10.json"], [], False, quiet))
        self.assertTrue(collect.publication_changed(False, [], ["status/2025-10.json"], False, quiet))
        self.assertTrue(collect.publication_changed(True, [], [], False, quiet))
        self.assertTrue(collect.publication_changed(False, [], [], True, quiet))

    def test_two_builds_whose_status_clocks_differ_and_nothing_else_publish_nothing(self):
        workspace = support.BuildCopy()
        try:
            code, _result, output = workspace.run()
            self.assertEqual(code, 0, output[-2000:])
            path = workspace.root / ".state" / "status-cache.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            for item in value["sources"].values():
                for field in ("fetched_at", "last_success"):
                    if item.get(field):
                        item[field] = (datetime.fromisoformat(item[field]) + timedelta(hours=1)).isoformat(timespec="seconds")
            path.write_text(json.dumps(value), encoding="utf-8")
            code, result, output = workspace.run()
            self.assertEqual(code, 0, output[-2000:])
            # The clocks did move: the board, its index and the outage file have new bytes.
            self.assertTrue({"status/current.json", "status/index.json", "status/outages.json"} <= set(result["changed_shards"]), result["changed_shards"])
            self.assertFalse(result["status"]["board_changed"])
            self.assertFalse(result["status"]["outages_changed"])
            self.assertEqual(result["removed_shards"], [])
            self.assertFalse(result["exports_changed"])
            # An offline --cached build has no deployed snapshot, so its v6 content always counts as
            # new; with the v6 content unchanged, as it is when only status clocks move, nothing deploys.
            self.assertFalse(collect.publication_changed(False, result["changed_shards"], result["removed_shards"], result["exports_changed"], result["status"]),
                             "clock-only changes must not deploy")
        finally:
            workspace.close()


class PreviousPublicationTest(unittest.TestCase):
    """A read failure never costs incident history: Statuspage lists only the 50 most recent
    incidents, so a month the vendors no longer list exists only in the published month file."""
    END = date(2026, 11, 1)

    def publication(self):
        """(raw bytes by path, previous v7 index) with a May month the observations no longer hold."""
        row = cache()["check-point"]["incidents"][0]
        may = {**row, "id": "may00001", "started": "2026-05-04T10:00:00+00:00", "updated": "2026-05-04T12:00:00+00:00",
               "resolved": "2026-05-04T12:00:00+00:00", "url": "https://status.checkpoint.com/incidents/may00001"}
        self.assertTrue(status.valid_incident(may))
        files, _summary = status.build_files(REGISTRY, cache(), {"2026-05": [may]}, self.END, CLOCK)
        raw, entries = shards.serialize(files)
        self.assertIn("status/2026-05.json", raw)
        return raw, {"shards": entries}

    @staticmethod
    def reader(raw, failing=(), failures=10 ** 6):
        """read(entry) over raw bytes; each path in failing raises OSError on its first failures reads."""
        seen = {}

        def read(entry):
            seen[entry["path"]] = seen.get(entry["path"], 0) + 1
            if entry["path"] in failing and seen[entry["path"]] <= failures:
                raise OSError("simulated transient read failure")
            data = raw[entry["path"]]
            collect.require(len(data) == entry["bytes"] and shards.sha256(data) == entry["sha256"], "A status file differs from the index.")
            return data
        return read

    def site(self, raw, registry=None):
        """A throwaway root whose site/data/v7 holds the previous status files (local mode)."""
        directory = tempfile.TemporaryDirectory(prefix="hub-status-")
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "config").mkdir()
        shutil.copyfile(support.ROOT / "config" / "status.json", root / "config" / "status.json")
        if registry is not None:
            (root / "config" / "status.json").write_text(registry, encoding="utf-8")
        for path, data in raw.items():
            target = root / "site" / "data" / "v7" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (root / ".state").mkdir()
        shutil.copyfile(support.FIXTURES / "status-cache.json", root / ".state" / "status-cache.json")
        return root

    def collect(self, root, index):
        return status.collect_status(root, refresh=False, previous_index=index, deployed=False, end=self.END)

    def assert_may_kept(self, files):
        self.assertIn("status/2026-05.json", files)
        self.assertEqual([row["id"] for row in files["status/2026-05.json"]["rows"]], ["may00001"])

    def test_a_month_read_once_more_after_a_transient_failure_keeps_its_rows(self):
        raw, index = self.publication()
        months, current = status.read_previous(index, self.reader(raw, failing={"status/2026-05.json"}, failures=1))
        self.assertEqual([row["id"] for row in months["2026-05"]], ["may00001"])
        self.assertIsNotNone(current)

    def test_one_unreadable_month_holds_the_run_and_never_publishes_a_removal(self):
        raw, index = self.publication()
        with self.assertRaises(status.StatusHold) as caught:
            status.read_previous(index, self.reader(raw, failing={"status/2026-05.json"}))
        self.assertIn("status/2026-05.json", str(caught.exception))
        # On disk: the local reader refuses the changed bytes, and the step holds with no files.
        changed = dict(raw)
        changed["status/2026-05.json"] = raw["status/2026-05.json"].replace(b"may00001", b"may00002")
        result = self.collect(self.site(changed), index)
        self.assertEqual(result["summary"]["status"], "held")
        self.assertEqual(result["files"], {})
        self.assertIn("status/2026-05.json", result["summary"]["reason"])
        # A file that parses but does not serialize back to its own bytes holds too.
        loose = dict(raw)
        loose["status/2026-05.json"] = raw["status/2026-05.json"].replace(b",", b", ", 1)
        entries = [{**entry, "bytes": len(loose[entry["path"]]), "sha256": shards.sha256(loose[entry["path"]])} for entry in index["shards"]]
        with self.assertRaises(status.StatusHold):
            status.read_previous({"shards": entries}, self.reader(loose))

    def test_a_failed_step_publishes_the_previous_status_files_byte_for_byte(self):
        raw, index = self.publication()
        # The registry breaks: nothing can be rebuilt, so the previous files are carried as they are.
        result = self.collect(self.site(raw, registry="{}"), index)
        self.assertEqual(result["summary"]["status"], "carried")
        self.assertFalse(result["summary"]["board_changed"])
        self.assertEqual(set(result["files"]), set(raw))
        for path, data in raw.items():
            self.assertEqual(shards.canonical(result["files"][path]), data, path)
        self.assert_may_kept(result["files"])
        self.assertEqual(result["rows"], [])
        # The step raises after the registry loaded: the files are carried and the Explorer rows rebuilt from them.
        root = self.site(raw)
        with mock.patch.object(status, "build_files", side_effect=ValueError("simulated failure")):
            result = self.collect(root, index)
        self.assertEqual(result["summary"]["status"], "carried")
        self.assertEqual({path: shards.canonical(value) for path, value in result["files"].items()}, raw)
        self.assert_may_kept(result["files"])
        self.assertIn("status-check-point-may00001", {row["id"] for row in result["rows"]})
        self.assertEqual(result["summary"]["months"], sum(1 for path in raw if status.MONTH_PATH.fullmatch(path)))

    def test_a_failed_outage_read_after_a_good_publication_keeps_its_rows(self):
        raw, index = self.publication()
        before = json.loads(raw["status/outages.json"].decode("utf-8"))["ioda"]
        self.assertEqual((before["status"], before["last_success"]), ("ok", CLOCK))
        self.assertTrue(before["rows"])
        # current.json lists only the tracked status pages; the outage blocks come from outages.json.
        self.assertNotIn("ioda", {item["id"] for item in json.loads(raw["status/current.json"].decode("utf-8"))["sources"]})
        root = self.site(raw)

        def fail(url, maximum=None, fresh=False):
            raise OSError("simulated IODA outage")
        with mock.patch.dict(status.os.environ, {status.RADAR_TOKEN_ENV: ""}):
            result = status.collect_status(root, refresh=True, previous_index=index, deployed=False, end=self.END, fetch=fail,
                                           clock="2026-11-01T18:00:00+00:00")
        self.assertEqual(result["summary"]["status"], "ok")
        after = result["files"]["status/outages.json"]["ioda"]
        self.assertEqual(after["status"], "failed")
        self.assertIn("simulated IODA outage", after["error"])
        self.assertEqual(after["fetched_at"], "2026-11-01T18:00:00+00:00")
        self.assertEqual((after["rows"], after["copyright"], after["last_success"]), (before["rows"], before["copyright"], CLOCK),
                         "a failed IODA read never blanks the last good outage snapshot")
        self.assertEqual(result["files"]["status/outages.json"]["radar"]["status"], "not_configured")

    def test_a_failed_step_with_no_previous_files_publishes_none(self):
        result = self.collect(self.site({}, registry="{}"), None)
        self.assertEqual(result["summary"]["status"], "unavailable")
        self.assertEqual(result["files"], {})

    def test_a_feed_json_resume_reads_the_deployed_index_or_holds(self):
        raw, index = self.publication()
        listed = json.dumps({**index, "shards": index["shards"] + [{"path": "live/2026-10.json", "bytes": 1, "sha256": "0" * 64}]}).encode("utf-8")
        found = status.deployed_index(lambda url, maximum, fresh=False: listed)
        self.assertEqual([entry["path"] for entry in found["shards"]], sorted(raw))

        def missing(url, maximum, fresh=False):
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, io.BytesIO(b""))
        self.assertIsNone(status.deployed_index(missing))

        def down(url, maximum, fresh=False):
            raise OSError("simulated network failure")
        with self.assertRaises(status.StatusHold):
            status.deployed_index(down)
        # The collector's own path: a resume from data/feed.json whose index read fails holds the run.
        with mock.patch.object(collect, "fetch", side_effect=OSError("simulated network failure")):
            result = collect.collect_status(False, {"schema_version": 7}, self.END)
        self.assertEqual(result["summary"]["status"], "held")

    def test_the_offline_build_holds_on_an_unreadable_month_and_carries_on_a_broken_registry(self):
        workspace = support.BuildCopy()
        try:
            code, _result, output = workspace.run()
            self.assertEqual(code, 0, output[-2000:])
            base = workspace.root / "site" / "data" / "v7"
            before = {path.relative_to(base).as_posix(): path.read_bytes() for path in (base / "status").iterdir()}
            index_before = (base / "index.json").read_bytes()
            # A changed month file: the run stops before writing anything.
            (base / "status" / "2026-10.json").write_bytes(before["status/2026-10.json"] + b" ")
            code, _result, output = workspace.run()
            self.assertNotEqual(code, 0)
            self.assertIn("holding this run so no incident history is lost", output)
            self.assertEqual((base / "index.json").read_bytes(), index_before)
            self.assertEqual((base / "status" / "2026-10.json").read_bytes(), before["status/2026-10.json"] + b" ")
            # Restored, then the registry breaks: the run publishes and the status files are unchanged.
            (base / "status" / "2026-10.json").write_bytes(before["status/2026-10.json"])
            (workspace.root / "config" / "status.json").write_text("{}", encoding="utf-8")
            code, result, output = workspace.run()
            self.assertEqual(code, 0, output[-2000:])
            self.assertEqual(result["status"]["status"], "carried")
            self.assertEqual({path.relative_to(base).as_posix(): path.read_bytes() for path in (base / "status").iterdir()}, before)
            listed = {entry["path"] for entry in json.loads((base / "index.json").read_text(encoding="utf-8"))["shards"]}
            self.assertTrue(set(before) <= listed)
            # Explorer rows need the registry, so only the status files themselves must stay listed.
            self.assertFalse([path for path in result["removed_shards"] if path.startswith("status/")])
        finally:
            workspace.close()


class PageTest(unittest.TestCase):
    def test_the_tab_is_the_infrastructure_desk_view_and_the_explorer_stays_first(self):
        page = (support.ROOT / "site" / "index.html").read_text(encoding="utf-8")
        strip = page[page.index('<nav class="tabs"'):page.index("</nav>", page.index('<nav class="tabs"'))]
        tabs = re.findall(r'<a href="#/([a-z-]+)" data-view="[a-z-]+" data-desk="([a-z]+)">', strip)
        self.assertEqual(tabs[0], ("explore", "explore"))
        self.assertIn(("status", "infrastructure"), tabs)
        self.assertEqual([view for view, desk in tabs if desk == "infrastructure"], ["status"])
        desks = re.findall(r'<a href="#/([a-z-]+)" data-desk="([a-z]+)">', strip)
        self.assertEqual(desks, [("explore", "explore"), ("today", "security"), ("status", "infrastructure"), ("history", "reference")])
        self.assertIn("js/views/status.js", json.loads((support.ROOT / "site" / "files.json").read_text(encoding="utf-8"))["files"])

    def test_the_method_view_and_docs_carry_the_privacy_sentence(self):
        method = (support.ROOT / "site" / "js" / "views" / "method.js").read_text(encoding="utf-8")
        sentence = re.search(r'export const PRIVACY_SENTENCE = "([^"]+)";', method)[1]
        self.assertIn("requests from your browser to the listed vendor status hosts", sentence)
        self.assertIn("Pause live updates stops them", sentence)
        for name in ("docs/METHOD.md", "docs/OPERATIONS.md"):
            self.assertIn(sentence, (support.ROOT / name).read_text(encoding="utf-8").replace("\n", " "), name)


if __name__ == "__main__":
    unittest.main()
