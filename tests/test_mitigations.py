"""CISA's ADP block on a brief (WP-04): the bounded SSVC and CVSS read from the record the collector
already fetches, the not_projected re-projection path, the ssvc_exploitation index field and the
validators that accept the new fields beside briefs published before them."""
import copy
import json
import unittest

import support
from intelligence_hub import collect
from intelligence_hub.archive import validate_snapshot
from intelligence_hub.collect import published, safe_url, text
from intelligence_hub.mitigations import (ADP_CONTAINERS, ADP_TEXT, INDEX_FIELDS, INDEX_FIELDS_V1, INDEX_FIELDS_V2, INDEX_FIELDS_V3, INDEX_VERSION, METRIC_ENTRIES,
                                          blank, brief_index, build_briefs, index_row, join_publication, merge_retained,
                                          poc_count, project_record, record_url, valid_projection, validate_adp)
import test_publication

STAMP = "2026-11-01T12:00:00+00:00"
CVE = "CVE-2026-90001"
LONG = "x" * 5000


def ssvc_metric(exploitation="active", automatable="yes", impact="total", timestamp="2026-10-20T04:00:13.543064Z"):
    return {"other": {"type": "ssvc", "content": {"id": CVE, "role": "CISA Coordinator", "version": "2.0.3", "timestamp": timestamp,
                                                  "options": [{"Exploitation": exploitation}, {"Automatable": automatable}, {"Technical Impact": impact}]}}}


def kev_metric():
    return {"other": {"type": "kev", "content": {"dateAdded": "2026-10-21", "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=" + CVE}}}


def cvss_metric(key="cvssV3_1", version="3.1", score=8.8, vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"):
    return {"format": "CVSS", "scenarios": [{"lang": "en", "value": "GENERAL"}],
            key: {"version": version, "baseScore": score, "baseSeverity": "HIGH", "vectorString": vector}}


def adp_container(short_name="CISA-ADP", metrics=None, updated="2026-10-22T10:00:00.000Z"):
    return {"providerMetadata": {"orgId": "00000000-0000-0000-0000-000000000000", "shortName": short_name, "dateUpdated": updated},
            "metrics": [ssvc_metric(), kev_metric()] if metrics is None else metrics, "title": "Synthetic ADP title"}


def record(adp=None, cve=CVE):
    """A synthetic cvelistV5-shaped record: the shape only, no real CNA text."""
    value = {"dataType": "CVE_RECORD", "dataVersion": "5.1",
             "cveMetadata": {"cveId": cve, "state": "PUBLISHED", "dateUpdated": "2026-10-23T09:00:00.000Z"},
             "containers": {"cna": {"title": "Synthetic record title", "descriptions": [{"lang": "en", "value": "Synthetic description."}],
                                    "affected": [], "references": [], "problemTypes": [],
                                    "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}}
    if adp is not None:
        value["containers"]["adp"] = adp
    return json.dumps(value).encode("utf-8")


def project(raw, cve=CVE):
    return project_record(raw, cve, text, safe_url, published, STAMP)


SUPPLIED = {"provider": "CISA-ADP", "date": "2026-10-22T10:00:00+00:00",
            "ssvc": {"exploitation": "active", "automatable": "yes", "technical_impact": "total", "timestamp": "2026-10-20T04:00:13+00:00"},
            "cvss": {"version": "3.1", "score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}}


class ProjectionTest(unittest.TestCase):
    def test_cisa_ssvc_and_cvss_are_projected_beside_the_cna_metric(self):
        brief = project(record([adp_container(metrics=[cvss_metric(), ssvc_metric(), kev_metric()])]))
        self.assertEqual((brief["adp"], brief["adp_status"]), (SUPPLIED, "supplied"))
        # The CNA's metric stays the CNA's: not replaced by CISA's and not averaged with it.
        self.assertEqual(brief["cvss"], {"score": 9.8, "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                         "source_url": "https://www.cve.org/CVERecord?id=" + CVE})
        self.assertTrue(valid_projection(brief, CVE, safe_url, published))
        self.assertEqual(validate_adp(brief, published), (SUPPLIED, "supplied"))

    def test_a_record_without_a_cisa_adp_container_is_not_supplied(self):
        other = {"providerMetadata": {"orgId": "00000000-0000-0000-0000-000000000000", "shortName": "CVE", "dateUpdated": "2026-10-22T10:00:00.000Z"}, "references": []}
        for adp in (None, [], [other], [adp_container("Other-ADP")]):
            with self.subTest(adp=adp):
                brief = project(record(adp))
                self.assertEqual((brief["adp"], brief["adp_status"]), (None, "not_supplied"))
                self.assertEqual(brief["cvss"]["score"], 9.8)
                self.assertTrue(valid_projection(brief, CVE, safe_url, published))

    def test_a_cisa_container_without_ssvc_or_cvss_is_supplied_with_empty_blocks(self):
        # The kev metric is not projected: KEV facts come from the catalog, separately attributed.
        brief = project(record([adp_container(metrics=[kev_metric()])]))
        self.assertEqual(brief["adp"], {"provider": "CISA-ADP", "date": "2026-10-22T10:00:00+00:00", "ssvc": None, "cvss": None})
        self.assertEqual(brief["adp_status"], "supplied")
        self.assertTrue(valid_projection(brief, CVE, safe_url, published))

    def test_an_oversized_cisa_container_is_bounded(self):
        options = [{"Exploitation": "poc" + LONG}, {"Automatable": "no"}, {"Technical Impact": "partial"}] + [{"Point " + str(n): LONG} for n in range(60)]
        oversized = {"other": {"type": "ssvc", "content": {"options": options, "timestamp": LONG}}}
        metrics = [cvss_metric(score=7.5), oversized, ssvc_metric(exploitation="active"), cvss_metric("cvssV4_0", "4.0", 9.3, "CVSS:4.0/" + LONG)] + [kev_metric()] * 200
        container = adp_container(metrics=metrics, updated=LONG)
        container["title"] = LONG
        brief = project(record([adp_container("Other-ADP")] * 5 + [container]))
        adp = brief["adp"]
        self.assertEqual(brief["adp_status"], "supplied")
        # The first ssvc metric is the one read, its values cut to the text bound; the junk clock is unknown.
        self.assertEqual(len(adp["ssvc"]["exploitation"]), ADP_TEXT)
        self.assertTrue(adp["ssvc"]["exploitation"].startswith("poc"))
        self.assertEqual((adp["ssvc"]["automatable"], adp["ssvc"]["technical_impact"], adp["ssvc"]["timestamp"]), ("no", "partial", None))
        # The CVSS read prefers the highest supported version and bounds the vector like the CNA's.
        self.assertEqual((adp["cvss"]["version"], adp["cvss"]["score"], len(adp["cvss"]["vector"])), ("4.0", 9.3, 250))
        self.assertIsNone(adp["date"])
        self.assertLess(len(json.dumps(adp)), 600)
        self.assertTrue(valid_projection(brief, CVE, safe_url, published))
        # Entries past the inspected windows are not read: a container after the tenth, a metric after the fortieth.
        late = project(record([adp_container("Other-ADP")] * ADP_CONTAINERS + [adp_container()]))
        self.assertEqual((late["adp"], late["adp_status"]), (None, "not_supplied"))
        deep = project(record([adp_container(metrics=[kev_metric()] * METRIC_ENTRIES + [ssvc_metric(), cvss_metric()])]))
        self.assertEqual((deep["adp"]["ssvc"], deep["adp"]["cvss"]), (None, None))

    def test_unexpected_option_shapes_are_skipped_not_invented(self):
        content = {"options": [5, {"Exploitation": "active", "Automatable": "yes"}, {"Exploitation": 7}, {"Exploitation": "none"}, {"Exploitation": "active"}, {"Automatable": ""}], "timestamp": 12}
        brief = project(record([adp_container(metrics=[{"other": {"type": "ssvc", "content": content}}, 5, {"other": "ssvc"}, {"other": {"type": "ssvc", "content": "x"}}])]))
        self.assertEqual(brief["adp"]["ssvc"], {"exploitation": "none", "automatable": None, "technical_impact": None, "timestamp": None})
        self.assertIsNone(brief["adp"]["cvss"])
        self.assertTrue(valid_projection(brief, CVE, safe_url, published))

    def test_malformed_adp_containers_refuse_the_projection(self):
        for adp in ("text", {}, [1], [{"providerMetadata": "x"}], [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": "x"}]):
            with self.subTest(adp=adp):
                with self.assertRaises(ValueError):
                    project(record(adp))


class RetainedProjectionTest(unittest.TestCase):
    def test_a_projection_made_before_the_pair_existed_reads_not_projected(self):
        brief = project(record([adp_container()]))
        del brief["adp"]
        del brief["adp_status"]
        self.assertTrue(valid_projection(brief, CVE, safe_url, published))
        self.assertEqual(validate_adp(brief, published, legacy=True), (None, "not_projected"))
        with self.assertRaisesRegex(ValueError, "Incomplete ADP projection"):
            validate_adp(brief, published)
        merged = merge_retained(brief, None, CVE, safe_url, published)
        self.assertEqual((merged["adp"], merged["adp_status"]), (None, "not_projected"))
        self.assertEqual(merged["cvss"]["score"], 9.8, "the retained CNA facts are kept")
        self.assertEqual((blank(CVE)["adp"], blank(CVE)["adp_status"]), (None, "not_projected"))

    def test_an_inconsistent_or_oversized_pair_is_refused(self):
        brief = project(record([adp_container(metrics=[cvss_metric(), ssvc_metric()])]))
        self.assertTrue(valid_projection(brief, CVE, safe_url, published))
        cases = {"status without a block": {"adp": None, "adp_status": "supplied"}, "block without supplied": {"adp_status": "not_supplied"},
                 "unknown status": {"adp_status": "bounded"}, "half a pair": {"adp_status": None}}
        for name, changes in cases.items():
            with self.subTest(case=name):
                value = {**brief, **changes}
                if name == "half a pair":
                    del value["adp_status"]
                self.assertFalse(valid_projection(value, CVE, safe_url, published))
        edits = {"exploitation over the bound": (("ssvc", "exploitation"), "x" * (ADP_TEXT + 1)), "empty value": (("ssvc", "automatable"), " "),
                 "vector over the bound": (("cvss", "vector"), "x" * 251), "score over 10": (("cvss", "score"), 11), "boolean score": (("cvss", "score"), True),
                 "unknown version": (("cvss", "version"), "5.0"), "junk date": (("date",), "yesterday"), "junk timestamp": (("ssvc", "timestamp"), "x"),
                 "empty provider": (("provider",), ""), "extra key": (("extra",), 1), "extra ssvc key": (("ssvc", "decision"), "Act")}
        for name, (path, bad) in edits.items():
            with self.subTest(case=name):
                value = copy.deepcopy(brief)
                target = value["adp"]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = bad
                self.assertFalse(valid_projection(value, CVE, safe_url, published))
        value = copy.deepcopy(brief)
        del value["adp"]["ssvc"]
        self.assertFalse(valid_projection(value, CVE, safe_url, published))


class ReprojectionTest(unittest.TestCase):
    def build(self, retained, budget, calls):
        articles = [{"cves": [cve]} for cve in retained]

        def fetch(url):
            calls.append(url)
            return record([adp_container(metrics=[cvss_metric(), ssvc_metric(), kev_metric()])], cve=url.rsplit("/", 1)[1][:-5])
        return build_briefs(articles, {}, retained, True, budget, fetch, text, safe_url, published, STAMP)

    def test_a_successful_projection_without_the_pair_is_due_within_the_budget(self):
        # Three retained records attempted at the run's own clock, so none is due by age: one
        # projected with the pair (nothing to add) and two made before it existed.
        complete = project(record(None, "CVE-2026-90001"), "CVE-2026-90001")
        old = {cve: {key: item for key, item in project(record(None, cve), cve).items() if key not in ("adp", "adp_status")}
               for cve in ("CVE-2026-90002", "CVE-2026-90003")}
        retained = {"CVE-2026-90001": complete, **old}
        calls = []
        briefs, projections, stats = self.build(retained, 1, calls)
        self.assertEqual(stats["attempted_this_run"], 1)
        self.assertEqual(calls, [record_url("CVE-2026-90003")], "the budget holds, highest identifier first among equal clocks")
        self.assertEqual((projections["CVE-2026-90003"]["adp_status"], briefs["CVE-2026-90003"]["adp"]), ("supplied", SUPPLIED))
        self.assertEqual((projections["CVE-2026-90002"]["adp_status"], briefs["CVE-2026-90002"]["adp"]), ("not_projected", None), "waits for a later run")
        self.assertEqual(briefs["CVE-2026-90001"]["adp_status"], "not_supplied", "a complete fresh projection is not attempted")
        calls = []
        briefs, projections, stats = self.build(retained, 40, calls)
        self.assertEqual(sorted(calls), [record_url("CVE-2026-90002"), record_url("CVE-2026-90003")])
        self.assertEqual({cve: briefs[cve]["adp_status"] for cve in briefs}, {"CVE-2026-90001": "not_supplied", "CVE-2026-90002": "supplied", "CVE-2026-90003": "supplied"})
        # A refreshed projection keeps the pair on the next run and is no longer due.
        calls = []
        self.build(projections, 40, calls)
        self.assertEqual(calls, [])

    def test_a_projection_without_the_poc_count_is_due_within_the_budget(self):
        # A retained projection complete on the weakness pair and the ADP block but made before the
        # poc field: it is read again to fill the count, not published as 0 until its 24-hour interval.
        complete = project(record([adp_container()], "CVE-2026-90004"), "CVE-2026-90004")
        self.assertEqual((complete["adp_status"], complete["weaknesses_status"]), ("supplied", "not_supplied"))
        no_poc = {key: item for key, item in complete.items() if key != "poc"}
        self.assertNotIn("poc", no_poc)
        calls = []
        briefs, projections, stats = self.build({"CVE-2026-90004": no_poc}, 40, calls)
        self.assertEqual(calls, [record_url("CVE-2026-90004")], "a record with no stored poc is due ahead of its interval")
        self.assertIn("poc", projections["CVE-2026-90004"])
        self.assertEqual(briefs["CVE-2026-90004"]["poc"], 0, "the fresh read fills the count")
        # The refreshed projection carries poc and is no longer due on that account.
        calls = []
        self.build(projections, 40, calls)
        self.assertEqual(calls, [])

    def test_resume_from_projections_without_poc_does_not_crash_and_fills_the_count(self):
        # Every brief on the live site predates the poc field. collect.py resumes by calling
        # merge_retained for each; this walks the real path (merge_retained, build_briefs, index_row)
        # from such projections and must not raise, must keep the record due, and must publish 0 until
        # a fresh read fills the true count.
        cves = ["CVE-2026-90005", "CVE-2026-90006"]
        old = {cve: {key: item for key, item in project(record([adp_container()], cve), cve).items() if key != "poc"} for cve in cves}
        fresh = {**project(record([adp_container()], cves[0]), cves[0]), "poc": 2, "retrieved_at": "2026-12-01T00:00:00Z"}
        # The three resume merges Codex reproduced the KeyError on: old alone, old with old, old with fresh.
        self.assertNotIn("poc", merge_retained(old[cves[0]], None, cves[0], safe_url, published), "old alone keeps poc missing")
        self.assertNotIn("poc", merge_retained(old[cves[0]], old[cves[0]], cves[0], safe_url, published), "old with old keeps it missing")
        with_fresh = merge_retained(old[cves[0]], fresh, cves[0], safe_url, published)
        self.assertEqual(with_fresh.get("poc"), 2, "a newer projection with the field fills it")

        def no_fetch(_url):
            raise AssertionError("no record should be fetched at budget 0")
        retained = {cve: merge_retained(old[cve], None, cve, safe_url, published) for cve in cves}
        briefs, projections, _ = build_briefs([{"cves": cves}], {}, retained, True, 0, no_fetch, text, safe_url, published, STAMP)
        for cve in cves:
            # Published with no stored count, not a made-up 0, so the next resume stays due; the derived
            # index column still carries 0.
            self.assertNotIn("poc", briefs[cve], "a record not re-read publishes no poc key")
            self.assertEqual(index_row(briefs[cve])[-1], 0)

        # The next run resumes from the published briefs (no local cache): the record is still due.
        resumed = {cve: merge_retained(None, briefs[cve], cve, safe_url, published) for cve in cves}
        for cve in cves:
            self.assertNotIn("poc", resumed[cve], "a published brief with no count stays due on resume")

        def fetch(url):
            cve = url.rsplit("/", 1)[1][:-5]
            doc = json.loads(record([adp_container()], cve).decode("utf-8"))
            doc["containers"]["cna"]["references"] = [{"url": "https://research.example.org/poc", "tags": ["exploit"]}]
            return json.dumps(doc).encode("utf-8")
        briefs, _, stats = build_briefs([{"cves": cves}], {}, resumed, True, 40, fetch, text, safe_url, published, STAMP)
        self.assertEqual(stats["attempted_this_run"], 2, "both no-count records were due ahead of their interval")
        for cve in cves:
            self.assertEqual(briefs[cve]["poc"], 1, "the fresh read fills the true count and the key appears")
            self.assertEqual(index_row(briefs[cve])[-1], 1)

    def test_a_failed_attempt_keeps_the_retained_facts_and_stays_due(self):
        old = {key: item for key, item in project(record(None, "CVE-2026-90002"), "CVE-2026-90002").items() if key not in ("adp", "adp_status")}

        def fetch(_url):
            raise OSError("HTTP Error 503")
        briefs, projections, stats = build_briefs([{"cves": ["CVE-2026-90002"]}], {}, {"CVE-2026-90002": old}, True, 40, fetch, text, safe_url, published, STAMP)
        self.assertEqual(stats["attempted_this_run"], 1)
        self.assertEqual((briefs["CVE-2026-90002"]["source_status"], briefs["CVE-2026-90002"]["adp_status"]), ("failed", "not_projected"))
        self.assertEqual(briefs["CVE-2026-90002"]["cvss"]["score"], 9.8)
        self.assertTrue(valid_projection(projections["CVE-2026-90002"], "CVE-2026-90002", safe_url, published))


class IndexTest(unittest.TestCase):
    def test_ssvc_exploitation_then_epss_then_poc_end_the_index_fields(self):
        self.assertEqual(INDEX_FIELDS[-3:], ("ssvc_exploitation", "epss", "poc"))
        self.assertEqual(INDEX_FIELDS_V3, INDEX_FIELDS[:-1])
        self.assertEqual(INDEX_FIELDS_V2, INDEX_FIELDS[:-2])
        self.assertEqual(INDEX_FIELDS_V1, INDEX_FIELDS[:-3])
        self.assertEqual(INDEX_VERSION, 4)
        briefs, _, _ = build_briefs([{"cves": [CVE]}], {}, {CVE: project(record([adp_container()]))}, False, 0, None, text, safe_url, published, STAMP)
        row = index_row(briefs[CVE])
        self.assertEqual(len(row), len(INDEX_FIELDS))
        # ssvc_exploitation, then epss (no score in this build), then poc (0 exploit references here).
        self.assertEqual(row[-3:], ["active", None, 0])
        self.assertEqual(row[4:6], [9.8, "3.1"], "the score columns stay the CNA's metric")
        self.assertEqual(index_row(briefs[CVE], 3), row[:-1])
        self.assertEqual(index_row(briefs[CVE], 2), row[:-2])
        self.assertEqual(index_row(briefs[CVE], 1), row[:-3])
        self.assertEqual(brief_index(briefs), {"version": 4, "fields": list(INDEX_FIELDS), "rows": {CVE: row}})
        self.assertEqual(brief_index(briefs, 3), {"version": 3, "fields": list(INDEX_FIELDS_V3), "rows": {CVE: row[:-1]}})
        self.assertEqual(brief_index(briefs, 2), {"version": 2, "fields": list(INDEX_FIELDS_V2), "rows": {CVE: row[:-2]}})
        self.assertEqual(brief_index(briefs, 1), {"version": 1, "fields": list(INDEX_FIELDS_V1), "rows": {CVE: row[:-3]}})
        with self.assertRaisesRegex(ValueError, "Unsupported brief index version"):
            brief_index(briefs, 5)
        pending = blank(CVE)
        pending.update(required_action=None, analysis={"guidance_status": "needs-review"})
        self.assertEqual(index_row(pending)[-3:], [None, None, 0])

    def test_an_exploit_tagged_reference_is_a_public_exploit_signal(self):
        # The CVE 5.x reference taxonomy tags a public exploit or PoC "exploit"; a reference also
        # tagged a guidance kind is still an exploit. The others keep their existing classification.
        refs = [{"url": "https://research.example.org/poc", "tags": ["exploit"], "name": "PoC"},
                {"url": "https://research.example.org/both", "tags": ["exploit", "patch"]},
                {"url": "https://vendor.example.org/advisory", "tags": ["vendor-advisory"]},
                {"url": "https://example.org/plain", "tags": ["third-party-advisory"]}]
        document = json.loads(record().decode("utf-8"))
        document["containers"]["cna"]["references"] = refs
        brief = project(json.dumps(document).encode("utf-8"))
        # references[0] is always the official CVE record; the four CNA references follow in order.
        self.assertEqual([item["kind"] for item in brief["references"]][1:], ["exploit", "exploit", "vendor-guidance", "record"])
        self.assertEqual(poc_count(brief), 2)
        self.assertTrue(valid_projection(brief, CVE, safe_url, published))
        # A brief with no exploit reference counts zero and still validates.
        plain = project(record())
        self.assertEqual(poc_count(plain), 0)
        self.assertTrue(valid_projection(plain, CVE, safe_url, published))

    def test_an_exploit_reference_past_the_display_cap_is_counted_and_still_shown(self):
        # Nineteen plain references then an exploit reference at position 20, past the fifteen-reference
        # display cap. poc counts it, and one exploit reference is kept among the displayed ones.
        refs = [{"url": "https://example.org/ref%d" % i, "tags": ["third-party-advisory"]} for i in range(19)]
        refs.append({"url": "https://research.example.org/poc", "tags": ["exploit"], "name": "PoC"})
        document = json.loads(record().decode("utf-8"))
        document["containers"]["cna"]["references"] = refs
        brief = project(json.dumps(document).encode("utf-8"))
        self.assertEqual(brief["poc"], 1, "the count is uncapped")
        self.assertEqual(poc_count(brief), 1)
        self.assertLessEqual(len(brief["references"]), 16, "the record plus up to fifteen CNA references")
        self.assertTrue(any(item["kind"] == "exploit" for item in brief["references"]), "an exploit reference stays visible")
        self.assertTrue(valid_projection(brief, CVE, safe_url, published))
        # Three exploit references past the cap: all are counted, one is shown.
        more = [{"url": "https://example.org/p%d" % i, "tags": ["third-party-advisory"]} for i in range(15)]
        more += [{"url": "https://research.example.org/e%d" % i, "tags": ["exploit"]} for i in range(3)]
        document["containers"]["cna"]["references"] = more
        brief = project(json.dumps(document).encode("utf-8"))
        self.assertEqual(brief["poc"], 3)
        self.assertEqual(sum(1 for item in brief["references"] if item["kind"] == "exploit"), 1)

    def test_the_page_mirrors_the_index_fields_and_the_fixture_follows_them(self):
        limits = (support.ROOT / "site" / "js" / "limits.js").read_text(encoding="utf-8")
        self.assertIn("export const indexFields = " + json.dumps(list(INDEX_FIELDS)) + ";", limits)
        fixtures = (support.ROOT / "tests" / "js" / "fixtures.js").read_text(encoding="utf-8")
        self.assertIn(json.dumps(["cve", *INDEX_FIELDS, "bucket"]), fixtures)


class PublicationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_publication.BriefsFileTest.setUpClass()
        cls.feed_raw, cls.briefs_raw = test_publication.BriefsFileTest.feed_raw, test_publication.BriefsFileTest.briefs_raw

    def joined(self):
        return join_publication(json.loads(self.feed_raw), json.loads(self.briefs_raw))

    def test_the_built_publication_carries_the_pair_and_the_new_index_column(self):
        feed, briefs = json.loads(self.feed_raw), json.loads(self.briefs_raw)
        brief = briefs["briefs"]["CVE-2026-99991"]
        # The offline build makes no record request, so the fixture's briefs are pending and unprojected.
        self.assertEqual((brief["adp"], brief["adp_status"]), (None, "not_projected"))
        self.assertEqual(feed["brief_index"]["version"], 4)
        self.assertEqual(feed["brief_index"]["fields"], list(INDEX_FIELDS))
        # Pending briefs: ssvc_exploitation and epss unset, and no exploit reference, so poc is 0.
        self.assertTrue(all(row[-3] is None and row[-2] is None and row[-1] == 0 for row in feed["brief_index"]["rows"].values()))
        validate_snapshot(feed)
        validate_snapshot(self.joined())

    def test_a_supplied_block_validates_and_fills_the_index_column(self):
        joined = self.joined()
        cve = next(iter(joined["mitigations"]))
        joined["mitigations"][cve].update(adp=copy.deepcopy(SUPPLIED), adp_status="supplied")
        joined["brief_index"] = brief_index(joined["mitigations"])
        validate_snapshot(joined)
        # ssvc_exploitation is the third-from-last column now that epss and poc follow it.
        self.assertEqual(joined["brief_index"]["rows"][cve][-3], "active")
        joined["mitigations"][cve]["adp_status"] = "not_supplied"
        with self.assertRaisesRegex(ValueError, "Invalid structured CVE provenance"):
            validate_snapshot(joined)
        joined["mitigations"][cve]["adp_status"] = "supplied"
        joined["brief_index"]["rows"][cve][-3] = "poc"
        with self.assertRaisesRegex(ValueError, "brief index differs"):
            validate_snapshot(joined)
        joined["brief_index"]["rows"][cve][-3] = "x" * 41
        with self.assertRaisesRegex(ValueError, "Invalid brief index SSVC exploitation"):
            validate_snapshot(joined)

    def test_the_poc_index_column_carries_the_stored_count_and_refuses_a_bad_one(self):
        joined = self.joined()
        cve = next(iter(joined["mitigations"]))
        # poc is the stored count the collector derived uncapped; it can exceed the displayed references.
        joined["mitigations"][cve]["poc"] = 23
        joined["mitigations"][cve]["references"] = joined["mitigations"][cve]["references"] + [
            {"label": "Proof of concept", "url": "https://research.example.org/poc", "kind": "exploit"}]
        joined["brief_index"] = brief_index(joined["mitigations"])
        validate_snapshot(joined)
        self.assertEqual(joined["brief_index"]["rows"][cve][-1], 23, "poc is the stored exploit-reference count")
        for bad in (-1, 101, True, "2", 1.5):
            joined["brief_index"]["rows"][cve][-1] = bad
            with self.assertRaisesRegex(ValueError, "Invalid brief index PoC count"):
                validate_snapshot(joined)

    def test_files_published_before_this_change_still_validate(self):
        # The feed published before WP-04 carries no pair and a version 1 index; the one before
        # WP-03 carries the pair, no epss and a version 2 index. Both stay valid resume and archive
        # inputs. A later version number on the old columns is refused.
        joined = self.joined()
        for brief in joined["mitigations"].values():
            del brief["adp"]
            del brief["adp_status"]
            del brief["epss"]
        joined["brief_index"] = brief_index(joined["mitigations"], 1)
        validate_snapshot(joined)
        feed = {key: item for key, item in joined.items() if key != "mitigations"}
        validate_snapshot(feed)
        feed["brief_index"]["version"] = 2
        with self.assertRaisesRegex(ValueError, "Unsupported brief index"):
            validate_snapshot(feed)
        before_epss = self.joined()
        for brief in before_epss["mitigations"].values():
            del brief["epss"]
        before_epss["brief_index"] = brief_index(before_epss["mitigations"], 2)
        validate_snapshot(before_epss)
        before_epss["brief_index"]["version"] = 3
        with self.assertRaisesRegex(ValueError, "Unsupported brief index"):
            validate_snapshot(before_epss)
        # The pair is optional on every modern snapshot, like the schema 5 weakness pair, so the
        # schema 6 relabel the resume test makes from a build still validates with it.
        relabelled = self.joined()
        del relabelled["brief_index"]
        relabelled["schema_version"] = 6
        validate_snapshot(relabelled)
        self.assertIn("adp", next(iter(relabelled["mitigations"].values())))

    def test_the_pair_costs_a_bounded_number_of_bytes_per_brief(self):
        briefs = json.loads(self.briefs_raw)
        with_pair = len(collect.public_bytes(briefs))
        for brief in briefs["briefs"].values():
            del brief["adp"]
            del brief["adp_status"]
        without = len(collect.public_bytes(briefs))
        per_brief = (with_pair - without) / len(briefs["briefs"])
        self.assertLessEqual(per_brief, 40, "an unprojected pair is a few dozen bytes per brief")
        full = {"adp": SUPPLIED, "adp_status": "supplied"}
        self.assertLessEqual(len(collect.public_bytes(full)) - len(collect.public_bytes({"adp": None, "adp_status": "not_projected"})), 320)


if __name__ == "__main__":
    unittest.main()
