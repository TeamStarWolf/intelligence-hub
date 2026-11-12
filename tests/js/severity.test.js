// The CVE brief's Severity sources block (WP-04): the CNA's CVSS, CISA's ADP CVSS and CISA's SSVC
// decision-point values, each named by its issuer and never blended; the Elsewhere row of links
// built from the CVE id through safeUrl; the register's sort control naming the CNA CVSS; and the
// validators that accept the adp block and the ssvc_exploitation index column.
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { ADP, CVE_ROWS, brief, files, page, server, settle, storage } from "./fixtures.js";
import { createApp } from "../../site/js/main.js";
import { indexFields } from "../../site/js/limits.js";
import { safeUrl } from "../../site/js/util.js";
import { ELSEWHERE, elsewhereRow, severityBlock } from "../../site/js/views/cves.js";
import { FormatError, normalizeBrief, normalizeCveIndex, normalizeRecent } from "../../site/js/validate.js";
import { normalize as normalizeFeed } from "../../site/js/legacy.js";

async function boot({ hash = "", site = files() } = {}) {
  const shell = page(hash, "");
  const http = server(site.bodies);
  const app = createApp({ doc: shell.doc, win: shell.win, location: shell.location, history: shell.history, storage: storage(), session: storage(), fetchImpl: http.fetch,
    subtle: webcrypto.subtle, moduleUrl: null, every: () => 0, loadLabels: async () => ({ default: {} }) });
  await app.start();
  await settle(60);
  return { ...shell, http, app, site };
}

const blocks = doc => [...doc.querySelectorAll("#cve-body .detail-block")];
const severityOf = doc => blocks(doc).find(item => item.querySelector("h3").textContent === "Severity sources");
const scoresIn = text => (text.match(/\b\d{1,2}\.\d\b/g) || []).filter(token => token !== "3.1" && token !== "4.0");

test("the brief names the issuer of every severity value and shows CISA's SSVC values as published", async () => {
  const { doc } = await boot({ hash: "#/cve/CVE-2026-1000" });
  await settle(60);
  const severity = severityOf(doc);
  assert.ok(severity, "the Severity sources block is rendered");
  const text = severity.textContent;
  assert.ok(text.includes("CNA CVSS v3.1: 9.8") && text.includes("CVSS:3.1/AV:N"), text);
  assert.ok(text.includes("CISA ADP CVSS v3.1: 8.8") && text.includes(ADP.cvss.vector), text);
  assert.ok(text.includes("CISA SSVC decision points, 30 Oct 2026, 04:00 UTC: Exploitation active · Automatable yes · Technical Impact total"), text);
  assert.ok(text.includes("CISA ADP container updated 31 Oct 2026"), text);
  // Every score in the block is one of the two issuers' own; nothing is blended or averaged.
  assert.deepEqual(scoresIn(text).sort(), ["8.8", "9.8"]);
  for (const token of scoresIn(text)) assert.ok(text.includes("CVSS v3.1: " + token), token + " is labelled by its issuer");
  assert.ok(!/\b(risk|urgency|priority)\b/i.test(text), text);
  // The overview chip names the CNA as the scorer of the headline metric.
  const chips = [...doc.querySelectorAll("#cve-body .chip")].map(chip => chip.textContent);
  assert.ok(chips.includes("CNA CVSS 9.8 (v3.1)"), chips.join(" | "));
  assert.ok(!chips.some(chip => /^CVSS /.test(chip)), "no severity chip is unlabelled");
  // The block sits right after the overview, before the CISA catalog action.
  assert.deepEqual(blocks(doc).slice(0, 3).map(item => item.querySelector("h3").textContent), ["CNA title for CVE-2026-1000", "Severity sources", "CISA catalog action"]);
});

test("a brief without CISA's container, and one not projected yet, say so instead of inventing values", async () => {
  const absent = await boot({ hash: "#/cve/CVE-2026-1001" });
  await settle(60);
  let text = severityOf(absent.doc).textContent;
  assert.ok(text.includes("CNA CVSS v3.1: 9.8") && text.includes("CISA ADP: no CISA ADP container in the saved CVE record."), text);
  assert.ok(!text.includes("SSVC decision points"), text);
  const pending = await boot({ hash: "#/cve/CVE-2026-1002" });
  await settle(60);
  text = severityOf(pending.doc).textContent;
  assert.ok(text.includes("CISA ADP: not read for this saved record yet"), text);
  // Rendered directly: no CNA metric and a supplied block without metrics.
  const bare = severityBlock(brief("CVE-2026-1003", { cvss: null, adp: { provider: "CISA-ADP", date: null, ssvc: null, cvss: null }, adp_status: "supplied" })).textContent;
  assert.ok(bare.includes("CNA CVSS: none supplied") && bare.includes("CISA ADP CVSS: none supplied.") && bare.includes("CISA SSVC: none supplied."), bare);
  assert.deepEqual(scoresIn(bare), []);
});

test("the Elsewhere row links the CVE on each surveyed site by id pattern only, every link through safeUrl", async () => {
  const { doc, http } = await boot({ hash: "#/cve/CVE-2026-1000" });
  await settle(60);
  const row = doc.querySelector("#cve-body .elsewhere");
  assert.ok(row, "the Elsewhere row is rendered");
  const anchors = [...row.querySelectorAll("a")];
  assert.deepEqual(anchors.map(anchor => anchor.textContent), ["CVE.org record", "NVD", "FIRST EPSS (API JSON)", "Rapid7 vulnerability database"]);
  assert.deepEqual(anchors.map(anchor => anchor.href), [
    "https://www.cve.org/CVERecord?id=CVE-2026-1000", "https://nvd.nist.gov/vuln/detail/CVE-2026-1000",
    "https://api.first.org/data/v1/epss?cve=CVE-2026-1000", "https://www.rapid7.com/db/?q=CVE-2026-1000"
  ]);
  for (const anchor of anchors) {
    assert.equal(safeUrl(anchor.href), anchor.href, anchor.href + " passes safeUrl unchanged");
    assert.ok(anchor.rel.includes("noopener") && anchor.rel.includes("noreferrer"), anchor.rel);
    assert.equal(anchor.target, "_blank");
  }
  assert.ok(row.textContent.includes("this site fetched none of these pages"));
  for (const name of ["GreyNoise", "Vulners", "AttackerKB"]) assert.ok(!doc.querySelector("#cve-body").textContent.includes(name), name + " is not listed");
  assert.ok(http.requests.every(request => request.url.startsWith("./data/")), "no request leaves the site");
  // The patterns themselves: four sites, every URL safe for a well-formed id, text (no anchor) for a malformed one.
  assert.equal(ELSEWHERE.length, 4);
  assert.ok(ELSEWHERE.every(([, pattern]) => safeUrl(pattern("CVE-2024-3400")) === pattern("CVE-2024-3400")));
  assert.equal(elsewhereRow("CVE-2026-1000 <b>x</b>").querySelectorAll("a").length, 0);
});

test("the register names the CNA CVSS as the basis of its score column and sort", async () => {
  const { doc } = await boot({ hash: "#/cves" });
  const options = [...doc.querySelectorAll("#view select option")].map(option => option.textContent);
  assert.ok(options.includes("CNA CVSS highest") && options.includes("CNA CVSS lowest"), options.join(" | "));
  assert.ok(!options.some(option => /^CVSS /.test(option)), "no sort option leaves the scorer unnamed");
  assert.deepEqual([...doc.querySelectorAll("#view th")].map(cell => cell.textContent), ["CVE", "Guidance", "KEV added", "CNA CVSS", "CWE"]);
  assert.ok(doc.querySelector("#view caption").textContent.includes("CNA's metric"));
});

test("the CVE index and recent.json carry ssvc_exploitation as the last field before the bucket", () => {
  assert.equal(indexFields[indexFields.length - 1], "ssvc_exploitation");
  const site = files();
  const index = normalizeCveIndex(JSON.parse(site.bodies["./data/v7/cve-index.json"]));
  assert.equal(index.rows.get("CVE-2026-1000").ssvc_exploitation, "active");
  assert.equal(index.rows.get("CVE-2026-1001").ssvc_exploitation, null);
  const recent = normalizeRecent(JSON.parse(site.bodies["./data/v7/recent.json"]));
  assert.equal(recent.cves.get("CVE-2026-1000").ssvc_exploitation, "active");
  // The layout published before the field, and a row that leaves it out, are refused whole.
  const old = JSON.parse(site.bodies["./data/v7/cve-index.json"]);
  old.fields = old.fields.filter(field => field !== "ssvc_exploitation");
  old.rows = CVE_ROWS.map(row => [...row.slice(0, 9), row[10]]);
  assert.throws(() => normalizeCveIndex(old), FormatError);
  const short = JSON.parse(site.bodies["./data/v7/cve-index.json"]);
  short.rows[0] = [...CVE_ROWS[0].slice(0, 9), null];
  assert.throws(() => normalizeCveIndex(short), FormatError);
  const typed = JSON.parse(site.bodies["./data/v7/cve-index.json"]);
  typed.rows[0] = [...CVE_ROWS[0].slice(0, 9), 7, null];
  assert.throws(() => normalizeCveIndex(typed), FormatError);
});

test("the brief validator accepts the adp block field by field and refuses an inconsistent pair", () => {
  const supplied = normalizeBrief(brief("CVE-2026-1000", { adp: { ...ADP, extra: "dropped" }, adp_status: "supplied" }), "CVE-2026-1000");
  assert.deepEqual(supplied.adp, ADP);
  assert.equal(supplied.adp_status, "supplied");
  const absent = normalizeBrief(brief("CVE-2026-1001"), "CVE-2026-1001");
  assert.deepEqual([absent.adp, absent.adp_status], [null, "not_supplied"]);
  const before = brief("CVE-2026-1002"); delete before.adp; delete before.adp_status;
  const unprojected = normalizeBrief(before, "CVE-2026-1002");
  assert.deepEqual([unprojected.adp, unprojected.adp_status], [null, "not_projected"]);
  const bare = normalizeBrief(brief("CVE-2026-1003", { adp: { provider: "CISA-ADP", date: null, ssvc: null, cvss: null }, adp_status: "supplied" }), "CVE-2026-1003");
  assert.deepEqual(bare.adp, { provider: "CISA-ADP", date: null, ssvc: null, cvss: null });
  const refused = [
    { adp: null, adp_status: "supplied" }, { adp: ADP, adp_status: "not_supplied" }, { adp: null, adp_status: "bounded" }, { adp: ADP },
    { adp: { ...ADP, cvss: { ...ADP.cvss, score: 11 } }, adp_status: "supplied" },
    { adp: { ...ADP, cvss: { ...ADP.cvss, score: "9.8" } }, adp_status: "supplied" },
    { adp: { ...ADP, ssvc: { exploitation: "active", automatable: "yes", technical_impact: "total" } }, adp_status: "supplied" },
    { adp: { ...ADP, ssvc: { ...ADP.ssvc, timestamp: "last week" } }, adp_status: "supplied" },
    { adp: { ...ADP, provider: "" }, adp_status: "supplied" }, { adp: "CISA-ADP", adp_status: "supplied" }
  ];
  for (const fields of refused) {
    const value = brief("CVE-2026-1000", fields);
    if (!Object.hasOwn(fields, "adp_status")) delete value.adp_status;
    assert.throws(() => normalizeBrief(value, "CVE-2026-1000"), FormatError, JSON.stringify(fields));
  }
});

test("the feed reader for the fallback path reads the version 2 brief index with the new column", () => {
  const feed = (version, row) => ({ schema_version: 7, generated_at: "2026-11-03T12:00:00+00:00", window: { start: "1998-01-01", end: "2026-11-01" },
    articles: [{ id: "a-1", title: "An advisory", url: "https://psirt.example.org/a-1", source_id: "vendor-psirt", source_name: "Vendor PSIRT", kind: "advisory", published_at: "2026-10-30", event_date: null, date_basis: "publication", summary: "", cves: ["CVE-2026-1000"], tags: [], exploitation: "unknown", references: [], origin: "publisher-feed" }],
    sources: [], history_reviewed_at: null, brief_index: { version, fields: ["record_state", "source_status", "guidance_status", "required_action", "cvss_score", "cvss_version", "kev_date_added", "weaknesses", ...(version === 2 ? ["ssvc_exploitation"] : [])], rows: { "CVE-2026-1000": row } },
    mitigation_coverage: {}, deduplication: { url_duplicates_removed: 0 },
    refresh: { requested_minutes: 120, mode: "scheduled-check", status_url: "https://github.com/TeamStarWolf/intelligence-hub/actions", notes: [] },
    coverage: { kev_records: 0, curated_events: 0, feed_articles: 1, notes: [] },
    integrations: { xai: { status: "not_connected", message: "None." }, x: { status: "not_connected", message: "None." }, sec: { status: "not_connected", message: "None." } },
    content_revision: "a".repeat(64), layout_revision: "b".repeat(64),
    intelligence: { schema_version: 1, catalog: { version: "1", reviewed_at: null, source_sha256: "a".repeat(64), status: "unreviewed", entities: [], relationships: [], notes: [] },
      reporting: { config_sha256: "a".repeat(64), catalog_sha256: "a".repeat(64), catalog_updated_at: null, configuration: { schema_version: 1, timezone: "America/Chicago", daily_hours: [6, 14, 22], weekday_lookback_hours: 24, weekend_lookback_hours: 48, weekend_iso_days: [6, 7], periodic_hour: 6, weekly_iso_day: 1, fortnight_anchor_start: "2026-10-19", fortnight_days: 14, rolling_months: 6, cadences: ["daily", "weekly", "weekend", "fortnightly", "monthly", "quarterly", "six-month"], schedule_state: "planned", schedule_observed_at: null, notes: [] }, latest_reports: [], indexes: [], notes: [] },
      revisions: { lookback_hours: 96, priority_hours: 48, max_sources: 12, min_success_interval_hours: 8, min_failure_interval_hours: 24, state: "not_run", report_id: null, recorded_at: null, nominal_cutoff: null, records: [], notes: [] }, notes: [] } });
  const current = feed(2, ["PUBLISHED", "ok", "publisher-guidance", true, 9.8, "3.1", "2026-11-02", ["CWE-787"], "active"]);
  const snapshot = normalizeFeed(current, JSON.stringify(current).length);
  assert.equal(snapshot.mitigations.get("CVE-2026-1000").ssvc_exploitation, "active");
  assert.equal(snapshot.mitigations.get("CVE-2026-1000").cvss.score, 9.8);
  const old = feed(1, ["PUBLISHED", "ok", "publisher-guidance", true, 9.8, "3.1", "2026-11-02", ["CWE-787"]]);
  assert.throws(() => normalizeFeed(old, JSON.stringify(old).length), FormatError);
});
