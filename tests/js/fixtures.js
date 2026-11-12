// A small synthetic schema 7 site for the node tests, with real sha256 values in its index.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseHtml } from "./dom.js";

export const ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const CONTENT_DATE = "2026-11-03";
const sha = text => createHash("sha256").update(text).digest("hex");
const json = value => JSON.stringify(value) + "\n";

export function row(id, fields = {}) {
  return {
    id, title: "Headline " + id, url: "https://publisher.example.org/" + id, source_id: "vendor-psirt", source_name: "Vendor PSIRT", kind: "advisory",
    origin: "publisher-feed", published_at: CONTENT_DATE, event_date: null, date_basis: "publication", summary: "", cves: [], tags: [], exploitation: "unknown",
    references: [], tagging: { source_class: "vendor-primary", desk: "security", event_type: [["disclosure", "kind-default", "high"]], exploitation: ["unknown", "none", "high"], region: [["US", "publisher", "source-identity", "high"]] },
    ...fields
  };
}

// A service-health incident row as intelligence_hub/status.py writes it into a live month: the
// infrastructure desk, origin service-status, no CVEs.
export function statusRow(id, fields = {}) {
  return row(id, { title: "Vendor: Incident with the API", url: "https://status.vendor.example.org/incidents/" + id, source_id: "status-vendor", source_name: "Vendor status page", kind: "incident",
    origin: "service-status", date_basis: "incident start", published_at: "2026-09-20T10:00:00+00:00",
    tagging: { source_class: "vendor-primary", desk: "infrastructure", event_type: [["outage", "status-incident", "high"]], exploitation: ["unknown", "none", "high"] }, ...fields });
}

export function brief(cve, fields = {}) {
  return {
    cve, title: "CNA title for " + cve, description: "A description.", source_status: "ok", record_state: "PUBLISHED", source_updated_at: "2026-10-30T00:00:00Z",
    retrieved_at: "2026-11-01T00:00:00Z", source_attempted_at: "2026-11-01T00:00:00Z", source_sha256: "a".repeat(64), products: [], solutions: [], workarounds: [],
    cvss: { score: 9.8, version: "3.1", vector: "CVSS:3.1/AV:N", source_url: null }, references: [], required_action: null, required_action_source_url: null, kev: null,
    analysis: { priority: "review", guidance_status: "needs-review", assessment: "Review it.", steps: [], limitations: [] }, weaknesses: [], weaknesses_status: "not_supplied",
    ...fields
  };
}

// The CVE index cases: a KEV CVE whose guidance label is publisher guidance (the case the old
// "CISA action" guidance filter dropped), a KEV CVE labelled CISA action, and a CVE not in KEV.
export const CVE_ROWS = [
  ["CVE-2026-1000", "PUBLISHED", "ok", "publisher-guidance", true, 9.8, "3.1", "2026-11-02", ["CWE-787"], null],
  ["CVE-2026-1001", "PUBLISHED", "ok", "cisa-action", true, 7.5, "3.1", "2026-10-20", [], null],
  ["CVE-2026-1002", "PUBLISHED", "ok", "needs-review", false, null, null, null, [], null]
];

export function files({ schema = 7, layout = "b".repeat(64), extra = {}, omit = [] } = {}) {
  const base = {
    "live/2026-11.json": { schema_version: 7, kind: "articles", period: "2026-11", rows: [
      row("a-kev-guidance", { cves: ["CVE-2026-1000"], title: "Vendor fixes exploited flaw", tagging: { ...row("x").tagging, vendor: [["vendor:fortinet", "cna-affected", "high"]], kev: { cves: ["CVE-2026-1000"], added: "2026-11-02", due: "2026-11-10", ransomware: "Unknown", at_publication: false }, exploitation: ["known", "kev", "high"] }, exploitation: "known" }),
      row("a-research", { kind: "research", source_id: "lab", source_name: "Research Lab", published_at: "2026-11-02", tagging: { ...row("x").tagging, source_class: "researcher", actor: [["actor:G0016", "title-alias", "medium"]] } }),
      row("a-press", { kind: "reporting", source_id: "news", source_name: "News Desk", published_at: "2026-11-01", cves: ["CVE-2026-1002"], tagging: { ...row("x").tagging, source_class: "press", sector: [["sector:healthcare-public-health", "title-term", "medium"]] } })
    ] },
    "live/2026-10.json": { schema_version: 7, kind: "articles", period: "2026-10", rows: [
      row("a-october", { published_at: "2026-10-15", cves: ["CVE-2026-1001"], title: "October advisory" }),
      row("kev-CVE-2026-1001", { kind: "kev", origin: "cisa-kev", source_id: "cisa-kev", source_name: "CISA Known Exploited Vulnerabilities", published_at: "2026-10-20", date_basis: "CISA catalog addition", cves: ["CVE-2026-1001"], exploitation: "known", tagging: { source_class: "government-cert", exploitation: ["known", "kev", "high"] } })
    ] },
    "history/2003.json": { schema_version: 7, kind: "articles", period: "2003", rows: [row("h-ms03-026", { kind: "bulletin", origin: "history:msrc-bulletins", source_id: "msrc", source_name: "Microsoft", published_at: "2003-07-16", title: "MS03-026" })] },
    "kev/2026.json": { schema_version: 7, kind: "kev", year: 2026, rows: [
      { cve: "CVE-2026-1001", cwe: [], date_added: "2026-10-20", directive: "BOD 22-01", due_date: "2026-11-30", forensic_triage: "No", name: "Example Two Vulnerability", notes_urls: [], product_raw: "Two", ransomware: "Unknown", required_action: "Apply mitigations per vendor instructions.", short_description: "CISA text two.", vendor_raw: "Example" },
      { cve: "CVE-2026-1000", cwe: ["CWE-787"], date_added: "2026-11-02", directive: "BOD 26-04", due_date: "2026-11-10", forensic_triage: "No", name: "Example One Vulnerability", notes_urls: ["https://www.cisa.gov/example"], product_raw: "FortiOS", ransomware: "Known", required_action: "Apply mitigations per vendor instructions.", short_description: "CISA text one.", vendor_raw: "Fortinet" }
    ] },
    "cve-index.json": { schema_version: 7, kind: "cve-index", fields: ["cve", "record_state", "source_status", "guidance_status", "required_action", "cvss_score", "cvss_version", "kev_date_added", "weaknesses", "bucket"], briefs_file: "data/briefs.json", rows: CVE_ROWS },
    "sources.json": { schema_version: 7, kind: "sources", rows: [
      { id: "vendor-psirt", name: "Vendor PSIRT", kind: "advisory", url: "https://psirt.example.org/", status: "ok", last_attempt: "2026-11-03T10:00:00+00:00", last_success: "2026-11-03T10:00:00+00:00", error: null, sha256: null, articles: 4, intake: null, configured_selection: "document-order-v1" },
      { id: "cisa-kev", name: "CISA Known Exploited Vulnerabilities", kind: "kev", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", status: "ok", last_attempt: "2026-11-03T10:00:00+00:00", last_success: "2026-11-03T10:00:00+00:00", error: null, sha256: null, articles: 1, intake: null, configured_selection: null }
    ] },
    "reports.json": { schema_version: 7, kind: "reports", status: "available", catalog_sha256: "c".repeat(64), catalog: { schema_version: 1, updated_at: "2026-11-01T00:00:00Z", notes: ["A note."], indexes: [{ label: "Report archive", url: "https://github.com/TeamStarWolf/intelligence-hub/blob/main/reports/README.md" }],
      reports: [{ id: "SW-DAILY-2026-11-01", title: "November 1 daily", cadence: "daily", status: "partial", origin: "generated_report", coverage: "source_subset", period_start: "2026-10-31T11:00:00Z", period_end: "2026-11-01T11:00:00Z", period_kind: "rolling_elapsed", compiled_at: "2026-11-01T16:35:01Z", compilation_precision: "timestamp", prior_report_id: null, report_url: "https://github.com/TeamStarWolf/intelligence-hub/blob/main/reports/daily/2026-11-01/README.md", data_url: "https://github.com/TeamStarWolf/intelligence-hub/blob/main/reports/daily/2026-11-01/data.json" }],
      revision_review: { state: "partial", nominal_cutoff: "2026-11-01T12:00:00Z", notes: ["Review note."], records: [] } } }
  };
  // recent.json as the collector cuts it: live rows from three days before the content date to
  // the day after, KEV entries added in the last week or due in the next two weeks, and the
  // CVE index rows the live rows name.
  const live = base["live/2026-11.json"].rows.concat(base["live/2026-10.json"].rows).filter(item => item.published_at.slice(0, 10) >= "2026-10-31" && item.published_at.slice(0, 10) <= "2026-11-04");
  const named = new Set(live.flatMap(item => item.cves));
  base["recent.json"] = { schema_version: 7, kind: "recent", content_date: CONTENT_DATE, from: "2026-10-31", to: "2026-11-04", kev_from: "2026-10-28", due_until: "2026-11-17",
    rows: live, kev: base["kev/2026.json"].rows.filter(item => (item.date_added >= "2026-10-28" && item.date_added <= CONTENT_DATE) || (item.due_date >= CONTENT_DATE && item.due_date <= "2026-11-17")),
    cve_fields: base["cve-index.json"].fields, cves: CVE_ROWS.filter(item => named.has(item[0])) };
  const shards = { ...base, ...extra };
  for (const path of omit) delete shards[path];
  const bodies = {};
  const entries = [];
  for (const [path, value] of Object.entries(shards)) {
    const text = json(value); bodies["./data/v7/" + path] = text;
    const rows = Array.isArray(value.rows) ? value.rows.length : value.rows instanceof Object ? Object.keys(value.rows).length : 0;
    entries.push({ path, rows, bytes: Buffer.byteLength(text), sha256: sha(text), from: null, to: null });
  }
  const feedRevision = "d".repeat(64);
  const briefs = { schema_version: 1, feed_schema_version: 7, generated_at: "2026-11-03T12:00:00+00:00", content_revision: feedRevision,
    briefs: { "CVE-2026-1000": brief("CVE-2026-1000", { required_action: "Apply mitigations per vendor instructions.", kev: { date_added: "2026-11-02", due_date: "2026-11-10", ransomware: "Known" }, analysis: { priority: "known-exploited", guidance_status: "publisher-guidance", assessment: "Exploited.", steps: [], limitations: [] } }),
      "CVE-2026-1001": brief("CVE-2026-1001"), "CVE-2026-1002": brief("CVE-2026-1002") } };
  bodies["./data/briefs.json"] = json(briefs);
  const index = {
    schema_version: schema, generated_at: "2026-11-03T12:00:00+00:00", content_date: CONTENT_DATE, content_revision: sha(entries.map(item => item.path + item.sha256).join("")),
    feed_content_revision: feedRevision, layout_revision: layout, window: { history_start: "1998-01-01", live_start: "2024-12-01", end: CONTENT_DATE },
    runs: [{ generated_at: "2026-11-03T12:00:00+00:00", trigger: "schedule", changed: true }, { generated_at: "2026-11-03T07:42:00+00:00", trigger: "schedule", changed: true }],
    observed_interval_hours: { median: 4.3, max: 10.2, runs_counted: 10 }, requested_cron: "7 */2 * * *", counts: { articles: 6, kev: 2, cves: 3, live_rows: 5, history_rows: 1 },
    shards: entries, v6_files: [{ path: "data/feed.json", bytes: 10, sha256: "e".repeat(64) }, { path: "data/briefs.json", bytes: 10, sha256: "f".repeat(64) }],
    cve_buckets: { published: false, note: "Not yet." }, notices: ["Publisher rows carry headlines and links only."],
    exports: { status: "ok", reason: null, files: [{ path: "exports/articles-2026.csv", bytes: 100, sha256: "1".repeat(64) }, { path: "exports/manifest.json", bytes: 50, sha256: "2".repeat(64) }, { path: "exports/data-dictionary.md", bytes: 50, sha256: "3".repeat(64) }] },
    feeds: { status: "ok", reason: null, files: [{ path: "feeds/incidents.xml", bytes: 900, sha256: "4".repeat(64) }, { path: "feeds/kev.xml", bytes: 800, sha256: "5".repeat(64) }, { path: "feeds/patch-calendar.xml", bytes: 700, sha256: "6".repeat(64) }] }
  };
  bodies["./data/v7/index.json"] = json(index);
  return { bodies, index };
}

// A fetch stand-in over the files above. Query strings are ignored, as GitHub Pages does.
// Each request is logged; If-None-Match against the served ETag returns 304.
export function server(bodies) {
  const state = { bodies, requests: [], etag: path => "\"" + sha(state.bodies[path] || "").slice(0, 12) + "\"" };
  state.fetch = async (url, options = {}) => {
    const path = url.split("?")[0];
    state.requests.push({ url, path, ifNoneMatch: options.headers?.["If-None-Match"] || null, cache: options.cache || null });
    if (!Object.hasOwn(state.bodies, path)) return { ok: false, status: 404, headers: { get: () => null }, body: null, arrayBuffer: async () => new ArrayBuffer(0) };
    const etag = state.etag(path);
    if (options.headers?.["If-None-Match"] === etag) return { ok: false, status: 304, headers: { get: key => key.toLowerCase() === "etag" ? etag : null }, body: null, arrayBuffer: async () => new ArrayBuffer(0) };
    const bytes = new TextEncoder().encode(state.bodies[path]);
    return { ok: true, status: 200, headers: { get: key => key.toLowerCase() === "etag" ? etag : key.toLowerCase() === "content-length" ? String(bytes.byteLength) : null }, body: null, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
  };
  return state;
}

export function storage(initial = {}) {
  const values = new Map(Object.entries(initial));
  return { getItem: key => values.has(key) ? values.get(key) : null, setItem: (key, value) => values.set(key, String(value)), removeItem: key => values.delete(key), values };
}

// The page's own index.html in the small DOM, with location, history and window stand-ins.
export function page(hash = "", search = "") {
  const doc = parseHtml(readFileSync(ROOT + "site/index.html", "utf8"));
  const location = { hash, search, pathname: "/intelligence-hub/", reloads: 0, reload() { this.reloads++; } };
  const entries = [{ state: null, hash }];
  let position = 0;
  const history = {
    get state() { return entries[position].state; },
    pushState(state, _, url) { entries.splice(position + 1); entries.push({ state, hash: url.slice(url.indexOf("#")) }); position++; location.hash = entries[position].hash; location.search = ""; },
    replaceState(state, _, url) { entries[position] = { state, hash: url.slice(url.indexOf("#")) }; location.hash = entries[position].hash; location.search = ""; },
    back() { if (position > 0) { position--; location.hash = entries[position].hash; win.dispatch("hashchange"); } },
    entries
  };
  const listeners = {};
  const win = { addEventListener: (type, handler) => (listeners[type] ||= []).push(handler), dispatch: type => (listeners[type] || []).forEach(handler => handler({ type })), matchMedia: () => ({ matches: false }) };
  globalThis.document = doc;
  return { doc, location, history, win };
}

export const settle = (ms = 30) => new Promise(resolve => setTimeout(resolve, ms));
