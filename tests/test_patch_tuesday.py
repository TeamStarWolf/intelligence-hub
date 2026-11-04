"""Patch Tuesday briefs: the MSRC parser, the fixed priority rules, the KEV, Adobe and SAP joins,
the per-run plan, the golden fixture month, the offline build and the Pages package."""
import contextlib
import copy
from datetime import datetime
import hashlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest

import support
from intelligence_hub import collect, patch_tuesday as pt, shards
from test_publication import Workspace

FIXTURE = support.FIXTURES / "patch-tuesday"
DOCUMENTS = FIXTURE / "documents"
CONFIG = pt.load_config(json.loads((support.ROOT / "config/sources.json").read_text(encoding="utf-8")), collect.safe_url)
OCTOBER = {"id": "2026-Oct", "month": "2026-10", "title": "October 2026 Security Updates", "initial_release": "2026-10-13T07:00:00Z",
           "current_release": "2026-11-03T14:45:49Z"}


def load_golden_module():
    spec = importlib.util.spec_from_file_location("build_golden", FIXTURE / "build_golden.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def document(vulnerabilities, ident="2026-Oct"):
    """A minimal CVRF document: one Windows product (1) and one Azure Linux package (2)."""
    tree = {"Branch": [{"Items": [{"Name": "Windows", "Items": [{"ProductID": "1", "Value": "Windows 11"}]},
                                  {"Name": "Azure Linux", "Items": [{"ProductID": "2", "Value": "azl3 curl 8.0"}]}]}],
            "FullProductName": [{"ProductID": "1", "Value": "Windows 11"}, {"ProductID": "2", "Value": "azl3 curl 8.0"}]}
    return json.dumps({"DocumentTracking": {"Identification": {"ID": {"Value": ident}}}, "ProductTree": tree,
                       "Vulnerability": vulnerabilities}).encode("utf-8")


def vulnerability(cve, *, products=("1",), severity="Important", impact="Remote Code Execution", threat=None, component="Windows Shell",
                  score=7.8, cna="Microsoft", threat_products=None):
    scoped = list(threat_products if threat_products is not None else products)
    return {"CVE": cve, "Title": {"Value": "Windows Shell " + impact + " Vulnerability"},
            "Notes": [{"Type": 7, "Value": component}, {"Type": 8, "Value": cna}],
            "ProductStatuses": [{"Type": 3, "ProductID": list(products)}],
            "Threats": [{"Type": 3, "Description": {"Value": severity}, "ProductID": list(products)},
                        {"Type": 0, "Description": {"Value": impact}, "ProductID": list(products)},
                        {"Type": 1, "Description": {"Value": threat or "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely"},
                         "ProductID": scoped}],
            "CVSSScoreSets": [{"BaseScore": score, "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "ProductID": list(products)}],
            "CWE": [{"ID": "CWE-787"}], "RevisionHistory": [{"Number": "1.0", "Date": "2026-10-13T07:00:00"}]}


def row_of(unit, cve):
    return dict(zip(pt.FIELDS, next(row for row in unit["rows"] if row[0] == cve)))


class ParserTest(unittest.TestCase):
    def test_exploited_and_disclosed_flags_come_from_the_exploitation_threat(self):
        unit = pt.parse_document(document([
            vulnerability("CVE-2026-0001", threat="Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected"),
            vulnerability("CVE-2026-0002", threat="Publicly Disclosed:Yes;Exploited:No;Latest Software Release:Exploitation More Likely;DOS:N/A"),
            vulnerability("CVE-2026-0003")]), OCTOBER, "2026-11-03T12:00:00Z")
        first, second, third = (row_of(unit, cve) for cve in ("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"))
        self.assertEqual((first["exploited"], first["disclosed"], first["exploitability"]), (True, False, "Exploitation Detected"))
        self.assertEqual((second["exploited"], second["disclosed"], second["exploitability"]), (False, True, "Exploitation More Likely"))
        self.assertEqual((third["exploited"], third["disclosed"]), (False, False))

    def test_a_flag_on_a_third_party_package_does_not_mark_the_microsoft_row(self):
        unit = pt.parse_document(document([vulnerability("CVE-2026-0004", products=("1", "2"), threat_products=("2",),
                                                         threat="Publicly Disclosed:Yes;Exploited:Yes")]), OCTOBER, "2026-11-03T12:00:00Z")
        row = row_of(unit, "CVE-2026-0004")
        self.assertEqual((row["exploited"], row["disclosed"]), (False, False))
        self.assertEqual(row["families"], ["Windows"])

    def test_package_only_cves_are_counted_and_left_out(self):
        unit = pt.parse_document(document([vulnerability("CVE-2026-0005"), vulnerability("CVE-2026-0006", products=("2",))]),
                                 OCTOBER, "2026-11-03T12:00:00Z")
        self.assertEqual([row[0] for row in unit["rows"]], ["CVE-2026-0005"])
        self.assertEqual((unit["msrc"]["listed"], unit["msrc"]["left_out"]), (2, 1))

    def test_rows_carry_score_vector_impact_component_and_cna(self):
        unit = pt.parse_document(document([vulnerability("CVE-2026-0007", severity="Critical", score=9.8, component="Microsoft Exchange Server")]),
                                 OCTOBER, "2026-11-03T12:00:00Z")
        row = row_of(unit, "CVE-2026-0007")
        self.assertEqual((row["severity"], row["impact"], row["cvss"], row["component"], row["cna"], row["cwe"], row["released"]),
                         ("Critical", "Remote Code Execution", 9.8, "Microsoft Exchange Server", "Microsoft", ["CWE-787"], "2026-10-13"))
        self.assertTrue(row["vector"].startswith("CVSS:3.1/"))
        self.assertEqual(unit["msrc"]["url"], "https://msrc.microsoft.com/update-guide/releaseNote/2026-Oct")

    def test_a_document_for_another_release_is_refused(self):
        with self.assertRaises(pt.PatchTuesdayError):
            pt.parse_document(document([], ident="2026-Sep"), OCTOBER, "2026-11-03T12:00:00Z")

    def test_the_updates_list_skips_mariner_notes_and_keeps_microsofts_dates(self):
        raw = (DOCUMENTS / "updates.json").read_bytes()
        entries = pt.listing(raw)
        self.assertEqual([entry["id"] for entry in entries], ["2016-Jan", "2024-Jan", "2026-Sep", "2026-Oct"])
        october = entries[-1]
        self.assertEqual((october["month"], october["initial_release"]), ("2026-10", "2026-10-13T07:00:00Z"))
        # February 2017's release came on the 21st, not the second Tuesday: the date is Microsoft's.
        late = json.dumps({"value": [{"ID": "2017-Feb", "DocumentTitle": "February 2017 Security Updates", "InitialReleaseDate": "2017-02-21T08:00:00Z",
                                      "CurrentReleaseDate": "2017-03-14T07:00:00Z", "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2017-Feb"}]})
        self.assertEqual(pt.listing(late)[0]["initial_release"], "2017-02-21T08:00:00Z")


class RulesTest(unittest.TestCase):
    def rows(self):
        def row(cve, severity, impact, cvss, component, exploited=False):
            return [cve, "Title " + cve, severity, impact, cvss, None, ["Windows"], component, "Microsoft", exploited, False, None, [], "2026-10-13", None]
        return [row("CVE-2026-0010", "Important", "Elevation of Privilege", 7.8, "Windows Kernel"),
                row("CVE-2026-0011", "Important", "Security Feature Bypass", 5.4, "Windows Shell", exploited=True),
                row("CVE-2026-0012", "Critical", "Remote Code Execution", 9.8, "Windows Message Queuing"),
                row("CVE-2026-0013", "Critical", "Remote Code Execution", 9.9, "Windows DHCP Server"),
                row("CVE-2026-0014", "Critical", "Remote Code Execution", 8.1, "Microsoft Exchange Server"),
                row("CVE-2026-0015", "Important", "Elevation of Privilege", 7.0, "Windows Kernel"),
                row("CVE-2026-0016", "Critical", "Elevation of Privilege", 8.8, "Active Directory Domain Services")]

    def test_kev_first_then_exploited_then_exposed_critical_rce_then_cvss(self):
        order = pt.prioritize(self.rows(), {"CVE-2026-0015": {}})
        self.assertEqual(order, [["CVE-2026-0015", "kev"], ["CVE-2026-0011", "exploited"], ["CVE-2026-0012", "critical-rce-exposed"],
                                 ["CVE-2026-0014", "critical-rce-exposed"], ["CVE-2026-0013", "cvss"], ["CVE-2026-0016", "cvss"],
                                 ["CVE-2026-0010", "cvss"]])

    def test_an_exploited_cve_in_kev_is_listed_once_under_kev(self):
        order = pt.prioritize(self.rows(), {"CVE-2026-0011": {}})
        self.assertEqual(order[0], ["CVE-2026-0011", "kev"])
        self.assertEqual(sum(item[0] == "CVE-2026-0011" for item in order), 1)

    def test_only_ten_rows_of_the_last_rule_are_listed(self):
        rows = [[("CVE-2026-%04d" % number), "T", "Important", "Spoofing", 5.0, None, [], None, None, False, False, None, [], None, None]
                for number in range(100, 140)]
        order = pt.prioritize(rows, {})
        self.assertEqual(len(order), pt.REST_SHOWN)
        self.assertEqual(order[0][0], "CVE-2026-0100")

    def test_dhcp_and_exchange_online_are_not_exposed_components(self):
        self.assertIsNone(pt.EXPOSED.search("Windows DHCP Server"))
        self.assertIsNone(pt.EXPOSED.search("Microsoft Exchange Online"))
        for component in ("Remote Desktop Gateway Service", "Windows Kerberos", "Role: DNS Server", "Microsoft SharePoint Server", "Windows LDAP"):
            self.assertIsNotNone(pt.EXPOSED.search(component), component)


class JoinTest(unittest.TestCase):
    def test_kev_listed_and_microsoft_additions_in_the_month(self):
        unit = {"parser_version": pt.PARSER_VERSION, "month": "2026-10", "msrc": {**OCTOBER, "listed": 1, "left_out": 0}, "fields": list(pt.FIELDS),
                "rows": [["CVE-2026-0020", "T", "Important", None, 7.0, None, [], None, "Microsoft", False, False, None, [], None, None]]}
        catalog = {"vulnerabilities": [
            {"cveID": "CVE-2026-0020", "vendorProject": "Microsoft", "dateAdded": "2026-11-02", "dueDate": "2026-11-23"},
            {"cveID": "CVE-2025-0021", "vendorProject": "Microsoft", "dateAdded": "2026-10-20", "dueDate": "2026-11-10"},
            {"cveID": "CVE-2026-0022", "vendorProject": "Fortinet", "dateAdded": "2026-10-21", "dueDate": "2026-11-11"}]}
        value = pt.month_shard(unit, pt.kev_map(catalog), {"CVE-2026-0020": {}}, None, None, {}, {"adobe": CONFIG["adobe"]["home"], "sap": CONFIG["sap"]["home"]})
        self.assertEqual(value["kev"]["listed"], [["CVE-2026-0020", "2026-11-02", "2026-11-23"]])
        # Only Microsoft additions dated in the release month; a later addition of this release's CVE is listed above, not here.
        self.assertEqual(value["kev"]["added_in_month"], [["CVE-2025-0021", "2026-10-20", False]])
        self.assertEqual(value["briefs"], ["CVE-2026-0020"])
        self.assertEqual(value["counts"]["in_kev"], 1)
        self.assertEqual(value["priority"], [["CVE-2026-0020", "kev"]])
        self.assertEqual(value["adobe"]["status"], "unavailable")
        self.assertEqual(value["sap"]["status"], "unavailable")

    def test_adobe_rows_are_bulletins_first_posted_on_the_release_day(self):
        rows = pt.parse_adobe((DOCUMENTS / "adobe-security.html").read_bytes(), collect.safe_url)
        self.assertTrue(all(row[0].startswith("APSB") and row[3].startswith("https://helpx.adobe.com/security/products/") for row in rows))
        january = pt.adobe_block({"status": "ok", "rows": rows}, "2024-01-09T08:00:00Z", CONFIG["adobe"]["home"])
        self.assertEqual([row[0] for row in january["rows"]], ["APSB24-06"])
        self.assertEqual(january["rows"][0][2], ["Adobe Substance 3D Stager"])
        october = pt.adobe_block({"status": "ok", "rows": rows}, "2026-10-13T07:00:00Z", CONFIG["adobe"]["home"])
        self.assertEqual(october["rows"], [])
        self.assertEqual(october["latest_posted"], max(row[4] for row in rows))

    def test_adobe_rows_that_are_advisories_mismatched_or_offsite_are_dropped(self):
        page = ('<h2 id="x">Adobe Example</h2><table><tr><td><a href="/security/products/example/apsb26-01.html"><b>APSB26-01</b>: Update</a></td>'
                '<td>01/13/2026</td><td>01/13/2026</td></tr><tr><td><a href="/security/products/example/apsa12-01.html">APSA12-01 Advisory</a></td>'
                '<td>01/13/2026</td><td>01/13/2026</td></tr><tr><td><a href="/security/products/example/apsb07-17.html">APSB07-17 Old</a></td>'
                '<td>01/13/2026</td><td>01/13/2026</td></tr><tr><td><a href="https://evil.example.net/apsb26-02.html">APSB26-02: Elsewhere</a></td>'
                '<td>01/13/2026</td><td>01/13/2026</td></tr></table>').encode("utf-8")
        rows = pt.parse_adobe(page, collect.safe_url)
        self.assertEqual([row[0] for row in rows], ["APSB26-01"])
        self.assertEqual(rows[0][1], "Update")

    def test_sap_month_page_and_year_page_rows(self):
        october = pt.parse_sap((DOCUMENTS / "sap-october-2026.html").read_bytes(), collect.safe_url, "2026-10")["2026-10"]
        self.assertEqual(october[0][:5], ["GHSA-4mv3-jxxm-9cx2", "OAuth2 SSRF vulnerability in SAP Cloud SDK for Python", ["CVE-2026-89111"], "Critical", 10.0])
        year = pt.parse_sap((DOCUMENTS / "sap-bulletin-2024.html").read_bytes(), collect.safe_url)
        self.assertEqual(list(year), ["2024-01"])
        self.assertTrue(all(row[5] is None or row[5].startswith("https://me.sap.com/") for row in year["2024-01"]))
        links = pt.sap_month_links((DOCUMENTS / "sap-index.html").read_bytes(), collect.safe_url)
        self.assertEqual(links["2026-10"], "https://support.sap.com/en/my-support/knowledge-base/security-notes-news/october-2026.html")

    def test_tags_join_the_vocabulary_like_other_rows(self):
        from intelligence_hub import tagging, vocab
        from intelligence_hub.history import registry
        context = tagging.build_context(vocab.load(support.ROOT), registry(), {"vulnerabilities": []}, {})
        unit = pt.parse_document(document([vulnerability("CVE-2026-0030", component="Microsoft Exchange Server")]), OCTOBER, "2026-11-03T12:00:00Z")
        unit["rows"][0][1] = "Microsoft Exchange Server Remote Code Execution Vulnerability"
        tags = pt.tag_rows(unit, context, CONFIG["msrc"]["name"])
        self.assertIn("vendor:microsoft", [item[0] for item in tags["CVE-2026-0030"]["vendor"]])


class PlanTest(unittest.TestCase):
    def entries(self):
        return pt.listing((DOCUMENTS / "updates.json").read_bytes())

    def unit(self, entry, read_at, parser=pt.PARSER_VERSION, current=None):
        return {"parser_version": parser, "month": entry["month"], "fields": list(pt.FIELDS), "rows": [],
                "msrc": {**entry, "current_release": current or entry["current_release"], "retrieved_at": read_at}}

    def test_new_months_come_first_newest_first(self):
        state = pt.empty_state()
        self.assertEqual([entry["id"] for entry in pt.plan(self.entries(), state, 3, 0)], ["2026-Oct", "2026-Sep", "2024-Jan"])

    def test_a_revised_month_is_read_again_once_a_day_and_the_newest_at_once(self):
        entries = self.entries()
        state = pt.empty_state()
        for entry in entries:
            state["months"][entry["month"]] = self.unit(entry, "2026-11-03T07:00:00Z", current="2020-01-01T00:00:00Z")
        an_hour_later = datetime.fromisoformat("2026-11-03T08:00:00+00:00").timestamp()
        self.assertEqual([entry["id"] for entry in pt.plan(entries, state, 10, an_hour_later)], ["2026-Oct"])
        two_days_later = an_hour_later + 2 * 86400
        self.assertEqual([entry["id"] for entry in pt.plan(entries, state, 10, two_days_later)], ["2026-Oct", "2016-Jan", "2024-Jan", "2026-Sep"])

    def test_an_unchanged_month_is_not_read_and_an_older_parser_is(self):
        entries = self.entries()
        state = pt.empty_state()
        for entry in entries:
            state["months"][entry["month"]] = self.unit(entry, "2026-11-03T12:00:00Z")
        self.assertEqual(pt.plan(entries, state, 10, 0), [])
        state["months"]["2024-01"]["parser_version"] = "0"
        self.assertEqual([entry["id"] for entry in pt.plan(entries, state, 10, 0)], ["2024-Jan"])

    def test_the_limit_binds(self):
        self.assertEqual(pt.plan(self.entries(), pt.empty_state(), 0, 0), [])
        with self.assertRaises(pt.PatchTuesdayError):
            pt.collect("unused", CONFIG, pt.Reader(offline=DOCUMENTS), limit=pt.MAX_DOCUMENTS + 1, safe_url=collect.safe_url)


class CollectTest(unittest.TestCase):
    def test_a_failed_updates_list_never_raises_and_keeps_the_saved_months(self):
        class Broken:
            def get(self, *args, **kwargs):
                raise OSError("HTTP 503")

        with tempfile.TemporaryDirectory(prefix="hub-pt-state-") as directory:
            golden = load_golden_module()
            state, _ = pt.collect(directory, CONFIG, pt.Reader(offline=DOCUMENTS), limit=10, safe_url=collect.safe_url,
                                  clock_now=lambda: golden.RETRIEVED)
            pt.save_state(directory, state, collect.write_raw)
            again, report = pt.collect(directory, CONFIG, Broken(), limit=10, safe_url=collect.safe_url)
        self.assertEqual(again["listing_status"]["status"], "unavailable")
        self.assertEqual(sorted(again["months"]), ["2024-01", "2026-10"])
        self.assertEqual(report["documents_read"], 0)
        built = pt.build(again, {}, {}, limit=shards.SHARD_MAX_BYTES, config=CONFIG)
        self.assertIn("patch-tuesday/2026-10.json", built)
        self.assertEqual(built[pt.INDEX_PATH]["status"]["msrc"]["status"], "unavailable")

    def test_months_are_resumed_from_deployed_briefs_only_when_their_bytes_match(self):
        golden = support.FIXTURES / "patch-tuesday" / "golden" / "2026-10.json"
        raw = golden.read_bytes()
        good = {"path": "patch-tuesday/2026-10.json", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        state = pt.empty_state()
        self.assertEqual(pt.resume_deployed(state, {"shards": [good]}, lambda entry: raw), 1)
        self.assertEqual(state["months"]["2026-10"]["msrc"]["id"], "2026-Oct")
        self.assertEqual(state["sap"]["2026-10"]["status"], "ok")
        state = pt.empty_state()
        self.assertEqual(pt.resume_deployed(state, {"shards": [{**good, "sha256": "0" * 64}]}, lambda entry: raw), 0)
        self.assertEqual(state["months"], {})

    def test_an_oversized_brief_sheds_tags_then_minor_rows_then_is_held(self):
        value = json.loads((FIXTURE / "golden" / "2026-10.json").read_text(encoding="utf-8"))
        value["tags"] = {row[0]: {"product": [["product:x", "title-match", "medium"]] * 40} for row in value["rows"]}
        size = len(pt.canonical(value))
        trimmed = pt.fit(copy.deepcopy(value), size - 1)
        self.assertEqual(trimmed["tags"], {})
        self.assertEqual(trimmed["counts"], value["counts"])
        no_tags = len(pt.canonical(trimmed))
        smaller = pt.fit(copy.deepcopy(value), no_tags - 1)
        self.assertGreater(smaller["trimmed"]["rows"], 0)
        self.assertTrue(all(row[2] in ("Critical", "Important") or row[9] or row[10] for row in smaller["rows"]))
        self.assert_every_named_cve_is_a_row(smaller)
        self.assertIsNone(pt.fit(copy.deepcopy(value), 100))

    def assert_every_named_cve_is_a_row(self, value):
        # The rule normalizePatchTuesday in site/js/validate.js applies to kev.listed, priority and briefs.
        rows = {row[0] for row in value["rows"]}
        self.assertLessEqual({item[0] for item in value["kev"]["listed"]}, rows)
        self.assertLessEqual({item[0] for item in value["priority"]}, rows)
        self.assertLessEqual(set(value["briefs"]), rows)

    def trim_with(self, kev=(), briefs=()):
        """The golden October brief with the named CVEs KEV-listed or given a Hub brief, trimmed to drop rows."""
        value = json.loads((FIXTURE / "golden" / "2026-10.json").read_text(encoding="utf-8"))
        for cve in kev:
            value["kev"]["listed"].append([cve, "2026-10-20", "2026-11-10"])
            value["priority"] = [[cve, "kev"]] + [item for item in value["priority"] if item[0] != cve]
        value["briefs"].extend(briefs)
        value["tags"] = {row[0]: {"product": [["product:x", "title-match", "medium"]] * 40} for row in value["rows"]}
        no_tags = len(pt.canonical({**value, "tags": {}, "trimmed": {"tags": True, "rows": 0}}))
        trimmed = pt.fit(copy.deepcopy(value), no_tags - 1)
        self.assertEqual(trimmed["counts"], value["counts"])
        self.assertEqual(trimmed["trimmed"]["rows"], 1)
        self.assert_every_named_cve_is_a_row(trimmed)
        return {row[0] for row in trimmed["rows"]}, trimmed

    def test_trimming_keeps_a_kev_listed_moderate_row(self):
        value = json.loads((FIXTURE / "golden" / "2026-10.json").read_text(encoding="utf-8"))
        rows = {row[0]: row for row in value["rows"]}
        # The only two rows the second stage can drop: Moderate and Low, neither exploited nor disclosed.
        for cve, severity in (("CVE-2026-85330", "Moderate"), ("CVE-2026-20942", "Low")):
            self.assertEqual((rows[cve][2], rows[cve][9], rows[cve][10]), (severity, False, False))
        kept, trimmed = self.trim_with(kev=["CVE-2026-85330"])
        self.assertIn("CVE-2026-85330", kept)
        self.assertNotIn("CVE-2026-20942", kept)
        self.assertIn(["CVE-2026-85330", "kev"], trimmed["priority"])
        self.assertNotIn("CVE-2026-20942", {item[0] for item in trimmed["priority"]})

    def test_trimming_keeps_a_low_row_with_a_hub_brief(self):
        kept, trimmed = self.trim_with(briefs=["CVE-2026-20942"])
        self.assertIn("CVE-2026-20942", kept)
        self.assertNotIn("CVE-2026-85330", kept)
        self.assertIn("CVE-2026-20942", trimmed["briefs"])


class GoldenTest(unittest.TestCase):
    def test_the_fixture_months_match_their_golden_briefs(self):
        module = load_golden_module()
        built = module.build()
        self.assertEqual(sorted(built), ["2024-01.json", "2026-10.json", "index.json"])
        for name, raw in built.items():
            self.assertEqual(raw, (FIXTURE / "golden" / name).read_bytes(), name)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(module.main(["--check"]), 0)

    def test_the_golden_october_brief_holds_the_msrc_flags(self):
        value = json.loads((FIXTURE / "golden" / "2026-10.json").read_text(encoding="utf-8"))
        rows = {row[0]: dict(zip(value["fields"], row)) for row in value["rows"]}
        self.assertEqual(sorted(cve for cve, row in rows.items() if row["exploited"]), ["CVE-2026-96951"])
        self.assertEqual(sorted(cve for cve, row in rows.items() if row["disclosed"]), ["CVE-2026-108398", "CVE-2026-111497", "CVE-2026-92707"])
        self.assertEqual(value["priority"][:2], [["CVE-2026-96951", "kev"], ["CVE-2026-111497", "kev"]])
        self.assertEqual(value["kev"]["added_in_month"], [["CVE-2026-96951", "2026-10-13", True]])
        self.assertEqual(value["msrc"]["left_out"], 2)


class ConfigTest(unittest.TestCase):
    def test_hosts_and_byte_bounds_are_checked(self):
        registry = json.loads((support.ROOT / "config/sources.json").read_text(encoding="utf-8"))
        for change in ({"msrc": {**registry["patch_tuesday"]["msrc"], "document": "https://api.example.org/cvrf/{id}"}},
                       {"msrc": {**registry["patch_tuesday"]["msrc"], "document_max_bytes": collect.LARGE_DOCUMENT_CEILING + 1}},
                       {"adobe": {**registry["patch_tuesday"]["adobe"], "max_bytes": collect.FETCH_CEILING + 1}},
                       {"sap": {**registry["patch_tuesday"]["sap"], "extra": 1}}):
            broken = {**registry, "patch_tuesday": {**registry["patch_tuesday"], **change}}
            with self.assertRaises(pt.PatchTuesdayError):
                pt.load_config(broken, collect.safe_url)

    def test_fetch_takes_the_large_ceiling_only_by_name(self):
        with self.assertRaises(ValueError):
            collect.fetch("https://api.msrc.microsoft.com/cvrf/v3.0/updates", collect.FETCH_CEILING + 1)
        with self.assertRaises(ValueError):
            collect.fetch("https://api.msrc.microsoft.com/cvrf/v3.0/updates", 10, ceiling=collect.LARGE_DOCUMENT_CEILING * 2)
        with self.assertRaises(ValueError):
            collect.fetch("https://api.msrc.microsoft.com/cvrf/v3.0/updates", 10, accept="text/javascript")


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.workspace = Workspace()
        shutil.copytree(DOCUMENTS, self.workspace.root / ".state" / pt.DOCUMENTS_NAME)

    def tearDown(self):
        self.workspace.close()

    def test_the_offline_build_writes_the_fixture_months_listed_with_sha256(self):
        result = self.workspace.build()
        base = self.workspace.root / "site" / "data" / "v7"
        index = json.loads((base / "index.json").read_text(encoding="utf-8"))
        listed = {entry["path"]: entry for entry in index["shards"] if entry["path"].startswith("patch-tuesday/")}
        self.assertEqual(sorted(listed), ["patch-tuesday/2024-01.json", "patch-tuesday/2026-10.json", "patch-tuesday/index.json"])
        for path, entry in listed.items():
            raw = (base / path).read_bytes()
            self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (entry["bytes"], entry["sha256"]), path)
        october = json.loads((base / "patch-tuesday/2026-10.json").read_text(encoding="utf-8"))
        self.assertEqual(october["msrc"]["id"], "2026-Oct")
        self.assertTrue(october["tags"], "the build tags the rows from the vocabulary")
        self.assertEqual(index["counts"]["patch_tuesday_months"], 2)
        self.assertEqual(result["patch_tuesday"]["months"], 2)
        self.assertIn("Patch Tuesday: data/v7/patch-tuesday/2026-10.json", self.workspace.log)
        report = shards.package_site(self.workspace.root / "site", out=io.StringIO())
        self.assertEqual(report["files"], len(index["shards"]) + len(index.get("exports", {}).get("files", [])) + len(support.site_files()) + 3)

    def test_an_unlisted_patch_tuesday_file_is_refused_by_the_package(self):
        self.workspace.build()
        (self.workspace.root / "site" / "data" / "v7" / "patch-tuesday" / "2099-01.json").write_bytes(b"{}\n")
        with self.assertRaisesRegex(shards.PackageError, "not listed in the manifest"):
            shards.package_site(self.workspace.root / "site", out=io.StringIO())

    def test_a_broken_patch_tuesday_block_never_blocks_the_feed(self):
        path = self.workspace.root / "config" / "sources.json"
        registry = json.loads(path.read_text(encoding="utf-8"))
        registry["patch_tuesday"]["msrc"]["updates"] = "http://api.msrc.microsoft.com/cvrf/v3.0/updates"
        path.write_text(json.dumps(registry), encoding="utf-8")
        result = self.workspace.build()
        self.assertEqual(result["patch_tuesday"]["status"], "unavailable")
        index = json.loads((self.workspace.root / "site" / "data" / "v7" / "index.json").read_text(encoding="utf-8"))
        self.assertFalse(any(entry["path"].startswith("patch-tuesday/") for entry in index["shards"]))
        self.assertGreater(result["articles"], 0)


if __name__ == "__main__":
    unittest.main()
