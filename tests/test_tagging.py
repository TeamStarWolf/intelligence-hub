"""The tagging engine: evidence rules, false positives, determinism, resolution and v6 labels."""
import copy
import json
import random
import re
import unittest

import support
from intelligence_hub import tagging, vocab
from intelligence_hub.tagging.engine import compact, export_fields, long_tags, tag_row

VOCAB = vocab.load()
REGISTRY = support.sources()
SOURCES = {source["id"]: source for source in REGISTRY}

# Synthetic KEV and CVE-record inputs in the published schemas. Not CISA or CNA text.
KEV = {"vulnerabilities": [
    {"cveID": "CVE-2026-90001", "vendorProject": "Microsoft", "product": "Windows", "dateAdded": "2026-10-01", "dueDate": "2026-10-22",
     "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-79"], "vulnerabilityName": "Synthetic", "shortDescription": "Synthetic"},
    {"cveID": "CVE-2026-90002", "vendorProject": "Cisco", "product": "IOS Software", "dateAdded": "2026-10-02", "dueDate": "2026-10-23",
     "knownRansomwareCampaignUse": "Unknown", "cwes": [], "vulnerabilityName": "Synthetic", "shortDescription": "Synthetic"},
    {"cveID": "CVE-2026-90003", "vendorProject": "Cisco", "product": "IOS software", "dateAdded": "2026-10-03", "dueDate": "2026-10-24",
     "knownRansomwareCampaignUse": "Unknown", "cwes": [], "vulnerabilityName": "Synthetic", "shortDescription": "Synthetic"},
    {"cveID": "CVE-2026-90004", "vendorProject": "Apple", "product": "iOS", "dateAdded": "2026-10-04", "dueDate": "2026-10-25",
     "knownRansomwareCampaignUse": "Unknown", "cwes": [], "vulnerabilityName": "Synthetic", "shortDescription": "Synthetic"},
]}
BRIEFS = {"CVE-2026-90005": {"products": [{"vendor": "Fortinet", "product": "FortiGate"}], "weaknesses": [{"id": "CWE-79"}],
                             "cvss": {"score": 9.8, "version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}


def context(kev=KEV, briefs=BRIEFS):
    return tagging.build_context(VOCAB, REGISTRY, kev, briefs)


CONTEXT = context()


def row(title, source_id="bleepingcomputer", cves=(), origin="publisher-feed", tags=(), exploitation="unknown", ident=None, kind=None):
    source = SOURCES.get(source_id, {"name": "Curated", "kind": kind or "incident"})
    return {"id": ident or "feed-" + str(abs(hash((title, source_id))) % 10 ** 12), "title": title, "url": "https://example.com/" + source_id,
            "source_id": source_id, "source_name": source["name"], "kind": kind or source["kind"], "published_at": "2026-10-05",
            "event_date": None, "date_basis": "publication", "summary": "", "cves": list(cves), "tags": list(tags),
            "exploitation": exploitation, "references": [], "origin": origin}


def values(block, field):
    return [item["value"] for item in block.get(field, [])]


class FalsePositiveTest(unittest.TestCase):
    """Ordinary words that are also ATT&CK names must not tag an actor or malware."""

    HEADLINES = [
        "DSA-6605-1 chromium - security update",
        "Two characters open up a world of typosquatting opportunities in Chromium browsers",
        "PAN-SA-2026-0013 Chromium: Monthly Vulnerability Update",
        "Smashing Security podcast: How websites are tracking you with silence",
        "Break the silence on breach reporting",
        "Silence is golden for incident responders",
        "A Bitter pill: lessons from a failed audit",
        "Proton pledges to open-source internal AI tools after backlash",
        "Proton Black Friday deals go live on VPN, Mail, Drive, and Pass",
        "Google says Gemini 4 Carbon beats its predecessors",
        "Data centres and their carbon footprint",
        "Security anchors a modern hybrid sovereign architecture",
        "External Teams Chats Anchor 15-Minute Malware Delivery",
        "Apache Spark patches a deserialization bug",
        "The spark that lit the ransomware economy",
        "ConnectWise customers hit by supply-chain attack",
        "French NGO reporters without borders targeted by Calisto",
    ]

    def test_ordinary_words_tag_no_actor_or_malware(self):
        for title in self.HEADLINES:
            with self.subTest(title=title):
                block = tag_row(row(title), CONTEXT)
                self.assertEqual(values(block, "actor") + values(block, "malware"), [])

    def test_a_weak_name_needs_its_context_word_and_is_low(self):
        block = tag_row(row("Turla deploys the Carbon backdoor against embassies"), CONTEXT)
        carbon = [item for item in block["malware"] if item["value"] == "malware:S0335"]
        self.assertEqual(len(carbon), 1)
        self.assertEqual(carbon[0]["confidence"], "low")
        self.assertIn("actor:G0010", values(block, "actor"))

    def test_calisto_the_backdoor_needs_a_malware_word(self):
        block = tag_row(row("Calisto backdoor for macOS found in a fake installer"), CONTEXT)
        self.assertEqual([(item["value"], item["confidence"]) for item in block["malware"]], [("malware:S0274", "low")])

    def test_a_group_name_shared_with_its_malware_tags_the_group(self):
        for title in ("Sednit reloaded: Back in the trenches", "Sofacy targets European government agencies"):
            with self.subTest(title=title):
                block = tag_row(row(title), CONTEXT)
                self.assertEqual([(item["value"], item["confidence"]) for item in block["actor"]], [("actor:G0007", "medium")])
                self.assertEqual(values(block, "malware"), [])

    def test_a_shared_name_with_a_malware_word_tags_both(self):
        block = tag_row(row("Sednit adds a new backdoor to its toolkit"), CONTEXT)
        self.assertEqual(values(block, "actor"), ["actor:G0007"])
        self.assertEqual(values(block, "malware"), ["malware:S0044"])
        block = tag_row(row("Sofacy trojan spreads through phishing"), CONTEXT)
        self.assertEqual(values(block, "malware"), ["malware:S0137"])

    def test_a_name_allowed_as_both_tags_both(self):
        block = tag_row(row("Akira hits a regional hospital network"), CONTEXT)
        self.assertEqual(values(block, "actor"), ["actor:G1024"])
        self.assertEqual(values(block, "malware"), ["malware:S1129"])

    def test_matching_is_case_sensitive(self):
        self.assertIn("actor:G1017", values(tag_row(row("Volt Typhoon returns"), CONTEXT), "actor"))
        self.assertEqual(values(tag_row(row("volt typhoon returns"), CONTEXT), "actor"), [])

    def test_ambiguous_and_stopped_names_are_never_matched(self):
        for entity in VOCAB.entities.values():
            for name in entity.get("ambiguous_aliases", []) + entity.get("stop_aliases", []):
                if (entity["id"], name) in {(item["id"], item["alias"]) for item in VOCAB.hub["matching"]["context"]}:
                    continue
                found = [ident for _key, ids, _weak in CONTEXT.find(name) for ident in ids if ident == entity["id"]]
                self.assertEqual(found, [], (entity["id"], name))


class ExploitationTest(unittest.TestCase):
    def test_kev(self):
        block = tag_row(row("Microsoft patches a flaw", cves=["CVE-2026-90001"]), CONTEXT)
        self.assertEqual(block["exploitation"], {"value": "known", "method": "kev", "confidence": "high"})
        self.assertIn("exploitation", values(block, "event_type"))

    def test_vendor_structured(self):
        item = row("Security bulletin", source_id="cisco-psirt")
        item["exploitation_evidence"] = {"basis": "vendor-structured", "exploited": True}
        self.assertEqual(tag_row(item, CONTEXT)["exploitation"], {"value": "known", "method": "vendor-structured", "confidence": "high"})

    def test_title_term_by_source_class(self):
        researcher = tag_row(row("Ivanti zero-day exploited in the wild", source_id="unit42"), CONTEXT)["exploitation"]
        press = tag_row(row("Ivanti zero-day exploited in the wild", source_id="bleepingcomputer"), CONTEXT)["exploitation"]
        self.assertEqual(researcher, {"value": "reported", "method": "title-term", "confidence": "medium"})
        self.assertEqual(press, {"value": "reported", "method": "title-term", "confidence": "low"})

    def test_zero_day_needs_an_attack_verb(self):
        self.assertEqual(tag_row(row("Zero-day bug bounty programme opens"), CONTEXT)["exploitation"]["value"], "unknown")
        self.assertEqual(tag_row(row("Zero-day used to attack routers"), CONTEXT)["exploitation"]["value"], "reported")

    def test_negation_and_research_wording_stay_unknown(self):
        for title in ("Vendor says there is no evidence of exploitation", "PoC released for the flaw, not exploited yet",
                      "Fickle PDFs: exploiting browser rendering discrepancies"):
            with self.subTest(title=title):
                self.assertEqual(tag_row(row(title, source_id="portswigger-research"), CONTEXT)["exploitation"],
                                 {"value": "unknown", "method": "none", "confidence": "high"})

    def test_curated_rows_keep_their_reviewed_label(self):
        item = row("Curated incident", source_id="okta", origin="library-curation", exploitation="known", kind="incident")
        self.assertEqual(tag_row(item, CONTEXT)["exploitation"], {"value": "known", "method": "curated-primary", "confidence": "medium"})

    def test_no_value_outside_the_vocabulary(self):
        for title in FalsePositiveTest.HEADLINES + ["Exploited in the wild", "Under active attack"]:
            self.assertIn(tag_row(row(title), CONTEXT)["exploitation"]["value"], {"known", "reported", "unknown"})


class FieldTest(unittest.TestCase):
    def test_structured_vendor_product_cwe_attack_cvss_and_kev(self):
        block = tag_row(row("A firewall flaw", cves=["CVE-2026-90005", "CVE-2026-90001"]), CONTEXT)
        self.assertIn({"value": "vendor:fortinet", "method": "cna-affected", "confidence": "high"}, block["vendor"])
        self.assertIn({"value": "vendor:microsoft", "method": "kev-vendor", "confidence": "high"}, block["vendor"])
        self.assertIn("product:fortinet-fortigate", values(block, "product"))
        self.assertEqual(values(block, "cwe"), ["CWE-79"])
        self.assertEqual(block["cvss"]["base"], 9.8)
        self.assertEqual(block["cvss"]["scorer"], "cna")
        self.assertEqual(block["kev"]["added"], "2026-10-01")
        self.assertEqual(block["kev"]["ransomware"], "Known")
        for item in block.get("attack", []):
            self.assertEqual((item["method"], item["confidence"]), ("cwe-capec", "low"))
            self.assertEqual(item["path"][0], "CWE-79")
            self.assertTrue(item["tactics"])

    def test_revoked_techniques_move_to_their_successor(self):
        revoked = next(old for old, new in VOCAB.superseded.items() if new and new in VOCAB.tactics)
        self.assertEqual(CONTEXT.forward(revoked), VOCAB.superseded[revoked])
        deprecated = next(old for old, new in VOCAB.superseded.items() if new is None)
        self.assertIsNone(CONTEXT.forward(deprecated))

    def test_event_type_analysis_and_unclassified(self):
        self.assertEqual(values(tag_row(row("Notes from a conference talk", source_id="unit42"), CONTEXT), "event_type"), ["analysis"])
        self.assertEqual(values(tag_row(row("Notes from a conference talk"), CONTEXT), "event_type"), ["unclassified"])
        advisory = tag_row(row("Security advisory for a router", source_id="cisco-psirt"), CONTEXT)
        self.assertTrue({"disclosure", "patch"} <= set(values(advisory, "event_type")))
        self.assertIn("vendor:cisco", values(advisory, "vendor"))

    def test_region_carries_a_role(self):
        block = tag_row(row("Iranian hackers target water utilities", source_id="cisa-advisories"), CONTEXT)
        regions = {(item["value"], item["role"]) for item in block["region"]}
        self.assertIn(("US", "publisher"), regions)
        self.assertIn(("IR", "mentioned"), regions)
        self.assertEqual(values(block, "sector"), ["sector:water-wastewater"])
        self.assertNotIn("MX", values(tag_row(row("New Mexico hospital diverts patients"), CONTEXT), "region"))

    def test_actor_and_malware_ids(self):
        block = tag_row(row("APT28 drops X-Agent while Storm-0940 abuses ScreenConnect RMM"), CONTEXT)
        self.assertIn("actor:G0007", values(block, "actor"))
        self.assertIn("actor:storm-0940", values(block, "actor"))
        for ident in values(block, "actor"):
            self.assertRegex(ident, r"^actor:(?:G[0-9]{4}|[a-z0-9-]+)$")
        for ident in values(block, "malware"):
            self.assertRegex(ident, r"^malware:S[0-9]{4}$")
        self.assertIn("malware:S0591", values(block, "malware"))


def golden():
    return [json.loads(line) for line in (support.FIXTURES / "golden_headlines.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def golden_row(item):
    source = SOURCES[item["source_id"]]
    return {"id": item["id"], "title": item["title"], "url": item["url"], "source_id": source["id"], "source_name": source["name"],
            "kind": source["kind"], "published_at": None, "event_date": None, "date_basis": "publication", "summary": "",
            "cves": [], "tags": [], "exploitation": "unknown", "references": [], "origin": "publisher-feed"}


class GoldenTest(unittest.TestCase):
    """About 300 real headlines (titles and URLs only) with reviewed tags."""

    def test_golden_fixture_is_titles_and_urls_only(self):
        items = golden()
        self.assertGreaterEqual(len(items), 280)
        for item in items:
            self.assertEqual(set(item), {"id", "title", "url", "source_id", "expected"})
            self.assertTrue(item["url"].startswith("https://"))

    def test_golden_headlines_pass(self):
        offline = context(kev=None, briefs={})
        failures = []
        for item in golden():
            got = compact(tag_row(golden_row(item), offline))
            if got != item["expected"]:
                failures.append(item["id"] + " " + item["title"][:60] + ": expected " + json.dumps(item["expected"]) + " got " + json.dumps(got))
        self.assertEqual(failures, [], "\n".join(failures[:10]))

    def test_every_emitted_typed_tag_resolves(self):
        rows = [golden_row(item) for item in golden()]
        rows += [row("Microsoft patches a flaw", cves=["CVE-2026-90001", "CVE-2026-90005"]),
                 row("Turla deploys the Carbon backdoor in Iranian banks", source_id="unit42")]
        for block in tagging.tag_rows(rows, CONTEXT).values():
            for field in ("kind", "source_class", "exploitation"):
                self.assertTrue(VOCAB.resolves(field, block[field]["value"]), (field, block[field]))
            for field in ("event_type", "vendor", "product", "actor", "malware", "sector", "region", "cwe"):
                for item in block.get(field, []):
                    self.assertTrue(VOCAB.resolves(field, item["value"]), (field, item))
                    self.assertIn(item["confidence"], {"high", "medium", "low"})
                    self.assertTrue(item["method"])
            for item in block.get("attack", []):
                self.assertTrue(VOCAB.resolves("attack_technique", item["value"]), item)
                for tactic in item["tactics"]:
                    self.assertTrue(VOCAB.resolves("attack_tactic", tactic), tactic)


class PropertyTest(unittest.TestCase):
    def rows(self):
        items = [golden_row(item) for item in golden()]
        items += [row("Microsoft patches a flaw", cves=["CVE-2026-90001"], origin="cisa-kev", tags=["Microsoft", "Windows"], ident="kev-CVE-2026-90001", kind="kev"),
                  row("Curated", source_id="okta", origin="library-curation", tags=["windows", "linux", "identity"], ident="hist-1", kind="incident")]
        return items

    def test_deterministic_across_runs_and_input_order(self):
        rows = self.rows()
        first = tagging.tag_rows(rows, context())
        shuffled = rows[:]
        random.Random(5).shuffle(shuffled)
        second = tagging.tag_rows(shuffled, context())
        self.assertEqual(first, second)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(tagging.tag_rows(copy.deepcopy(rows), context()), sort_keys=True))

    def test_idempotent_on_its_own_output(self):
        rows = self.rows()
        ctx = context()
        blocks = tagging.tag_rows(rows, ctx)
        fold = tagging.Fold(rows, ctx)
        once = [{**item, "tags": tagging.v6_tags(item, blocks[item["id"]], ctx, fold)} for item in rows]
        blocks_again = tagging.tag_rows(once, ctx)
        fold_again = tagging.Fold(once, ctx)
        twice = [{**item, "tags": tagging.v6_tags(item, blocks_again[item["id"]], ctx, fold_again)} for item in once]
        self.assertEqual(blocks, blocks_again)
        self.assertEqual(once, twice)

    def test_tags_are_sorted_and_unique(self):
        for block in tagging.tag_rows(self.rows(), CONTEXT).values():
            for field in ("event_type", "vendor", "product", "actor", "malware", "sector", "cwe", "attack"):
                found = values(block, field)
                self.assertEqual(found, sorted(set(found)), field)


class V6TagTest(unittest.TestCase):
    MEASURED = [("Linux", "linux"), ("Windows", "windows"), ("N-Central", "N-central"), ("Server", "server"), ("Android", "android"),
                ("Edge", "edge"), ("IOS Software", "IOS software"), ("Drupal Core", "Drupal core")]

    def test_measured_case_collisions_fold(self):
        catalog = {"vulnerabilities": [
            {"cveID": "CVE-2026-9100" + str(index), "vendorProject": vendor, "product": product, "dateAdded": "2026-10-01"}
            for index, (vendor, product) in enumerate([("Linux", "Kernel"), ("Microsoft", "Windows"), ("N-able", "N-Central"),
                                                        ("Microsoft", "Server"), ("Google", "Android"), ("Microsoft", "Edge"),
                                                        ("Cisco", "IOS Software"), ("Drupal", "Drupal Core"), ("Cisco", "IOS"), ("Apple", "iOS")])]}
        ctx = tagging.build_context(VOCAB, REGISTRY, catalog, {})
        rows = []
        for entry in catalog["vulnerabilities"]:
            rows.append(row(entry["cveID"], source_id="cisa-kev", cves=[entry["cveID"]], origin="cisa-kev",
                            tags=[entry["vendorProject"], entry["product"]], ident="kev-" + entry["cveID"], kind="kev"))
        rows.append(row("Second spellings", source_id="cisa-kev", origin="cisa-kev", tags=["N-able", "N-central"], ident="kev-x", kind="kev"))
        rows.append(row("Cisco second spelling", source_id="cisa-kev", origin="cisa-kev", tags=["Cisco", "IOS software"], ident="kev-y", kind="kev"))
        rows.append(row("Drupal second spelling", source_id="cisa-kev", origin="cisa-kev", tags=["Drupal", "Drupal core"], ident="kev-z", kind="kev"))
        rows.append(row("Curated words", source_id="okta", origin="library-curation", tags=["linux", "windows", "server", "android", "edge"],
                        ident="hist-x", kind="incident"))
        blocks = tagging.tag_rows(rows, ctx)
        fold = tagging.Fold(rows, ctx)
        seen = {}
        for item in rows:
            for value in tagging.v6_tags(item, blocks[item["id"]], ctx, fold):
                seen.setdefault((item["tags"][0].casefold() if item["origin"] == "cisa-kev" else "", value.casefold()), set()).add(value)
        spellings = {}
        for (_vendor, folded), found in seen.items():
            spellings.setdefault(folded, set()).update(found)
        for first, second in self.MEASURED:
            self.assertEqual(len(spellings.get(first.casefold(), set())), 1, (first, second, spellings.get(first.casefold())))
        # Cisco IOS and Apple iOS are different products; folding is keyed on the vendor.
        self.assertEqual(spellings["ios"], {"IOS", "iOS"})

    def test_kev_rows_show_vocabulary_labels(self):
        item = row("CVE-2026-90001", source_id="cisa-kev", cves=["CVE-2026-90001"], origin="cisa-kev", tags=["Microsoft", "Windows"],
                   ident="kev-CVE-2026-90001", kind="kev")
        block = tag_row(item, CONTEXT)
        self.assertEqual(tagging.v6_tags(item, block, CONTEXT, tagging.Fold([item], CONTEXT))[:2], ["Microsoft", "Windows"])

    def test_publisher_rows_get_labels_and_stay_in_bounds(self):
        item = row("Volt Typhoon exploits Cisco and Fortinet devices in the wild")
        tags = tagging.v6_tags(item, tag_row(item, CONTEXT), CONTEXT, tagging.Fold([item], CONTEXT))
        self.assertTrue({"Cisco", "Fortinet", "Volt Typhoon"} <= set(tags))
        self.assertLessEqual(len(tags), 30)
        self.assertTrue(all(len(value) <= 100 for value in tags))

    def test_publisher_rows_ignore_stale_tags(self):
        item = row("Plain headline", tags=["Old Label"])
        self.assertEqual(tagging.v6_tags(item, tag_row(item, CONTEXT), CONTEXT, tagging.Fold([item], CONTEXT)), [])


class DeskTest(unittest.TestCase):
    """The desk comes from the source's registry entry, never from a headline (WP-01)."""

    def test_every_registry_source_names_a_desk_the_vocabulary_holds(self):
        self.assertEqual(set(VOCAB.values["desk"]), {"security", "infrastructure", "it"})
        for source in REGISTRY:
            self.assertIn(source["desk"], VOCAB.values["desk"], source["id"])

    def test_feed_kev_and_curated_rows_sit_on_the_security_desk(self):
        for item in (row("Vendor fixes an exploited flaw"),
                     row("CVE-2026-90001", source_id="cisa-kev", cves=["CVE-2026-90001"], origin="cisa-kev", ident="kev-CVE-2026-90001", kind="kev"),
                     row("A curated incident", source_id="microsoft-msrc", origin="library-curation", ident="hist-1", kind="incident")):
            block = tag_row(item, CONTEXT)
            self.assertEqual(block["desk"], {"value": "security", "method": "source-registry", "confidence": "high"}, item["id"])
            self.assertEqual(compact(block)["desk"], "security")
            self.assertEqual(export_fields(item, block)["desk"], "security")
            self.assertIn(("desk", "security", "high", "source-registry", ""), long_tags(block))

    def test_a_headline_never_sets_the_desk(self):
        block = tag_row(row("Infrastructure outage hits IT lifecycle planning"), CONTEXT)
        self.assertEqual(block["desk"]["value"], "security")

    def test_status_rows_sit_on_the_infrastructure_desk(self):
        from intelligence_hub import status
        registry = status.load_registry(support.ROOT)
        ctx = tagging.build_context(VOCAB, status.tag_registry(registry), KEV, BRIEFS)
        item = row("GitHub: Incident with Actions", source_id="status-github", origin="service-status", ident="status-github-1", kind="incident")
        block = tag_row(item, ctx)
        self.assertEqual(block["desk"], {"value": "infrastructure", "method": "source-registry", "confidence": "high"})

    def test_a_source_entry_without_a_desk_falls_back_to_security(self):
        ctx = tagging.build_context(VOCAB, [{"id": "old-source", "source_class": "press"}], KEV, BRIEFS)
        block = tag_row(row("Headline", source_id="old-source"), ctx)
        self.assertEqual(block["desk"]["value"], "security")


class CompactTest(unittest.TestCase):
    def test_compact_form_matches_the_layout(self):
        block = tag_row(row("Iranian hackers exploit Cisco flaw", source_id="unit42", cves=["CVE-2026-90005"]), CONTEXT)
        small = compact(block)
        self.assertNotIn("kind", small)
        self.assertNotIn("tagger_version", small)
        self.assertEqual(small["source_class"], "researcher")
        self.assertEqual(small["desk"], "security")
        self.assertEqual(len(small["exploitation"]), 3)
        self.assertTrue(all(len(item) == 4 for item in small["region"]))
        self.assertTrue(all(isinstance(item, str) and re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", item) for item in small.get("attack", [])))


class AttackCompletenessTest(unittest.TestCase):
    """A CWE set that reaches more than 40 techniques keeps every one, in the block, the shard form and the exports."""

    def test_a_broad_cwe_set_keeps_every_technique(self):
        cwes = ["CWE-200", "CWE-284"]
        briefs = {"CVE-2026-90006": {"products": [], "weaknesses": [{"id": cwe} for cwe in cwes]}}
        ctx = context(briefs=briefs)
        expected = sorted({technique for cwe in cwes for _capec, technique, _path in ctx.cwe_chain(cwe)})
        self.assertGreater(len(expected), 40, "the pinned CWE and CAPEC lists no longer give this set more than 40 techniques")
        block = tag_row(row("An information disclosure flaw", cves=["CVE-2026-90006"]), ctx)
        self.assertEqual(sorted(values(block, "cwe")), cwes)
        self.assertEqual(sorted(values(block, "attack")), expected)
        self.assertEqual(sorted(compact(block)["attack"]), expected)
        flat = export_fields(row("An information disclosure flaw", cves=["CVE-2026-90006"]), block)
        self.assertEqual(flat["attack_technique"].split(";"), expected)
        tactics = sorted({tactic for technique in expected for tactic in VOCAB.tactics[technique]["tactics"]})
        self.assertEqual(flat["attack_tactic"].split(";"), tactics)
        self.assertEqual(sorted({value for field, value, *_rest in long_tags(block) if field == "attack_technique"}), expected)


if __name__ == "__main__":
    unittest.main()
