// Validators for every file the page reads. A file that fails is refused whole: nothing from
// it is rendered. Every validator returns plain objects built field by field, so unexpected
// fields never reach the page.
import { indexFields, maximumShardBytes } from "./limits.js";
import { normalized, safeUrl } from "./util.js";

export class FormatError extends Error {
  constructor(message = "The saved data does not match the supported snapshot format.") { super(message); this.name = "FormatError"; this.format = true; }
}

export function requireValue(condition, message) { if (!condition) throw new FormatError(message); }
export function isObject(value) { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }

export function boundedText(value, maximum, empty = false) {
  requireValue(typeof value === "string" && value.length <= maximum && (empty || value.trim().length > 0));
  return value;
}
export function optionalText(value, maximum) { return value == null ? null : boundedText(value, maximum, true); }
export function list(value, limit) { requireValue(Array.isArray(value) && value.length <= limit); return value; }
export function textList(value, limit, textLimit) { return list(value, limit).map(item => boundedText(item, textLimit)); }
export function nonnegative(value) { requireValue(Number.isSafeInteger(value) && value >= 0); return value; }
export function exactKeys(value, keys) {
  requireValue(isObject(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)));
}
export function hash(value, nullable = false) { requireValue((nullable && value === null) || (typeof value === "string" && /^[a-f0-9]{64}$/.test(value))); return value; }

export function calendarDay(value) {
  requireValue(typeof value === "string" && /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value) && value.slice(0, 4) !== "0000");
  const calendar = new Date(value + "T00:00:00Z");
  requireValue(Number.isFinite(calendar.getTime()) && calendar.toISOString().slice(0, 10) === value);
  return value;
}

// A date or a date-time with a zone. Null is allowed when nullable.
export function timestamp(value, nullable = true) {
  if (nullable && value === null) return null;
  boundedText(value, 80);
  requireValue(/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?$/.test(value));
  calendarDay(value.slice(0, 10));
  requireValue(Number.isFinite(new Date(value).getTime()));
  return value;
}

const KINDS = ["advisory", "research", "reporting", "incident", "kev", "filing", "bulletin", "note", "change", "lifecycle"];
const EXPLOITATION = ["known", "reported", "unknown"];
const ORIGIN = /^(?:publisher-feed|cisa-kev|library-curation|service-status|sec-filing|history:[a-z0-9][a-z0-9-]{0,39})$/;
const CVE = /^CVE-\d{4}-\d{4,19}$/;
// The same pattern as SHARD_PATH in intelligence_hub/shards.py and the typed check in publish.yml;
// tests/test_shards.py holds the three in step.
const SHARD_PATTERN = String.raw`(?:sources|coverage|reports|cve-index|recent)\.json|live/(?:[0-9]{4}-(?:0[1-9]|1[0-2])|undated)\.json|history/(?:[0-9]{4}(?:-(?:h[12]|q[1-4]|0[1-9]|1[0-2]))?|undated)\.json|kev/[0-9]{4}\.json|cve/[0-9]{4}/[0-9]{1,5}k\.json|patch-tuesday/(?:index|[0-9]{4}-(?:0[1-9]|1[0-2]))\.json|status/(?:current|outages|index|[0-9]{4}-(?:0[1-9]|1[0-2]))\.json`;
const SHARD_PATH = new RegExp("^(?:" + SHARD_PATTERN + ")$");
const EXPORT_PATH = /^exports\/(?:articles-(?:[0-9]{4}(?:-(?:0[1-9]|1[0-2]))?|undated)\.(?:csv|jsonl)|tags-(?:[0-9]{4}(?:-(?:0[1-9]|1[0-2]))?|undated)\.csv|manifest\.json|data-dictionary\.md)$/;
// The Hub's own Atom feeds (intelligence_hub/shards.py build_feeds), listed under feeds.
const FEED_PATH = /^feeds\/(?:kev|incidents|patch-calendar)\.xml$/;

// data/v7/index.json. Known fields are checked; fields a later collector adds are ignored.
export function normalizeIndex(raw) {
  requireValue(isObject(raw) && raw.schema_version === 7, "The saved index is not a schema 7 index.");
  const value = {
    schema_version: 7, generated_at: timestamp(raw.generated_at, false), content_date: raw.content_date === null ? null : calendarDay(raw.content_date),
    content_revision: hash(raw.content_revision), feed_content_revision: hash(raw.feed_content_revision), layout_revision: hash(raw.layout_revision)
  };
  requireValue(value.generated_at.includes("T"));
  requireValue(isObject(raw.window));
  value.window = { history_start: calendarDay(raw.window.history_start), live_start: calendarDay(raw.window.live_start), end: calendarDay(raw.window.end) };
  value.runs = list(raw.runs, 20).map(run => {
    requireValue(isObject(run) && typeof run.changed === "boolean");
    return { generated_at: timestamp(run.generated_at, false), trigger: boundedText(run.trigger, 40), changed: run.changed };
  });
  requireValue(value.runs.length >= 1);
  const interval = raw.observed_interval_hours;
  requireValue(isObject(interval));
  const hours = item => { requireValue(item === null || (typeof item === "number" && Number.isFinite(item) && item >= 0 && item <= 100000)); return item; };
  value.interval = { median: hours(interval.median), max: hours(interval.max), runs_counted: nonnegative(interval.runs_counted) };
  requireValue((value.interval.median === null) === (value.interval.max === null));
  value.requested_cron = boundedText(raw.requested_cron, 40);
  requireValue(isObject(raw.counts));
  value.counts = {};
  for (const [key, item] of Object.entries(raw.counts)) {
    if (/^[a-z_]{1,40}$/.test(key) && (Number.isSafeInteger(item) && item >= 0)) value.counts[key] = item;
    else if (/^[a-z_]{1,40}$/.test(key) && typeof item === "string" && item.length <= 40) value.counts[key] = item;
  }
  const seen = new Set();
  value.shards = list(raw.shards, 1000).map(entry => {
    requireValue(isObject(entry) && typeof entry.path === "string" && SHARD_PATH.test(entry.path) && !seen.has(entry.path));
    seen.add(entry.path);
    requireValue(Number.isSafeInteger(entry.bytes) && entry.bytes > 0 && entry.bytes <= maximumShardBytes);
    return { path: entry.path, rows: nonnegative(entry.rows), bytes: entry.bytes, sha256: hash(entry.sha256), from: entry.from === null ? null : calendarDay(entry.from), to: entry.to === null ? null : calendarDay(entry.to) };
  });
  for (const name of ["sources.json", "reports.json", "cve-index.json"]) requireValue(seen.has(name), "The saved index does not list " + name + ".");
  value.v6_files = list(raw.v6_files, 4).map(item => { requireValue(isObject(item)); return { path: boundedText(item.path, 80), bytes: nonnegative(item.bytes), sha256: hash(item.sha256) }; });
  value.notices = textList(raw.notices || [], 20, 600);
  value.exports = { status: "unavailable", reason: "This index lists no exports.", files: [] };
  if (raw.exports !== undefined) {
    requireValue(isObject(raw.exports) && ["ok", "unavailable"].includes(raw.exports.status));
    value.exports = {
      status: raw.exports.status, reason: optionalText(raw.exports.reason, 300),
      files: list(raw.exports.files, 1000).map(item => {
        requireValue(isObject(item) && typeof item.path === "string" && EXPORT_PATH.test(item.path));
        return { path: item.path, bytes: nonnegative(item.bytes), sha256: hash(item.sha256) };
      })
    };
  }
  value.feeds = { status: "unavailable", reason: null, files: [] };
  if (raw.feeds !== undefined) {
    requireValue(isObject(raw.feeds) && ["ok", "unavailable"].includes(raw.feeds.status));
    const seenFeeds = new Set();
    value.feeds = {
      status: raw.feeds.status, reason: optionalText(raw.feeds.reason, 300),
      files: list(raw.feeds.files, 3).map(item => {
        requireValue(isObject(item) && typeof item.path === "string" && FEED_PATH.test(item.path) && !seenFeeds.has(item.path));
        seenFeeds.add(item.path);
        return { path: item.path, bytes: nonnegative(item.bytes), sha256: hash(item.sha256) };
      })
    };
  }
  value.tagging = null;
  if (isObject(raw.tagging)) {
    const library = isObject(raw.tagging.library) ? raw.tagging.library : {};
    value.tagging = { status: boundedText(raw.tagging.status, 40), tagger_version: optionalText(raw.tagging.tagger_version, 40), vocab_version: optionalText(raw.tagging.vocab_version, 80),
      library_commit: typeof library.commit === "string" && /^[a-f0-9]{40}$/.test(library.commit) ? library.commit : null };
  }
  value.cve_buckets = { published: Boolean(isObject(raw.cve_buckets) && raw.cve_buckets.published === true) };
  return value;
}

function triples(value, width, limit = 500) {
  return list(value, limit).map(item => {
    requireValue(Array.isArray(item) && item.length === width && item.every(part => typeof part === "string" && part.length > 0 && part.length <= 160));
    return item;
  });
}

// The row's tagging block (index.json tagging.layout). Fields the page does not read are dropped.
function normalizeTagging(raw) {
  const tags = { source_class: null, desk: null, event_type: [], vendor: [], product: [], actor: [], malware: [], sector: [], company: [], region: [], cwe: [], attack: [], exploitation: null, kev: null, cvss: null };
  if (raw === undefined || raw === null) return tags;
  requireValue(isObject(raw));
  if (raw.source_class !== undefined) tags.source_class = boundedText(raw.source_class, 40);
  if (raw.desk !== undefined) tags.desk = boundedText(raw.desk, 40);
  for (const field of ["event_type", "vendor", "product", "actor", "malware", "sector", "company", "cwe"]) if (raw[field] !== undefined) tags[field] = triples(raw[field], 3);
  if (raw.region !== undefined) tags.region = triples(raw.region, 4);
  if (raw.attack !== undefined) tags.attack = list(raw.attack, 5000).map(item => { requireValue(typeof item === "string" && /^T\d{4}(?:\.\d{3})?$/.test(item)); return item; });
  if (raw.exploitation !== undefined) { requireValue(Array.isArray(raw.exploitation) && raw.exploitation.length === 3 && EXPLOITATION.includes(raw.exploitation[0])); tags.exploitation = raw.exploitation.map(part => boundedText(part, 60)); }
  if (raw.kev !== undefined && raw.kev !== null) {
    const kev = raw.kev; requireValue(isObject(kev));
    tags.kev = { cves: list(kev.cves, 100).map(cve => { requireValue(typeof cve === "string" && CVE.test(cve)); return cve; }), added: kev.added == null ? null : calendarDay(kev.added), due: kev.due == null ? null : calendarDay(kev.due), ransomware: optionalText(kev.ransomware, 40), at_publication: kev.at_publication === true };
  }
  if (raw.cvss !== undefined && raw.cvss !== null) {
    const cvss = raw.cvss; requireValue(isObject(cvss) && typeof cvss.base === "number" && Number.isFinite(cvss.base) && cvss.base >= 0 && cvss.base <= 10);
    tags.cvss = { base: cvss.base, version: optionalText(cvss.version, 20), vector: optionalText(cvss.vector, 400), scorer: optionalText(cvss.scorer, 40), cve: optionalText(cvss.cve, 40) };
  }
  return tags;
}

// One article row from a live or history shard (or a converted schema 6 feed row).
export function normalizeRow(raw) {
  requireValue(isObject(raw) && KINDS.includes(raw.kind) && typeof raw.origin === "string" && ORIGIN.test(raw.origin) && EXPLOITATION.includes(raw.exploitation));
  const row = {
    id: boundedText(raw.id, 160), title: boundedText(raw.title, 1000), url: boundedText(raw.url, 4000),
    source_id: boundedText(raw.source_id, 160), source_name: boundedText(raw.source_name, 240), kind: raw.kind, origin: raw.origin,
    published_at: timestamp(raw.published_at), event_date: timestamp(raw.event_date), date_basis: boundedText(raw.date_basis, 1000, true),
    summary: boundedText(raw.summary, 500, true), exploitation: raw.exploitation,
    cves: list(raw.cves, 100).map(cve => { requireValue(typeof cve === "string" && CVE.test(cve)); return cve; }),
    tags: raw.tags === undefined ? [] : textList(raw.tags, 100, 160),
    native_id: raw.native_id === undefined ? null : optionalText(raw.native_id, 160),
    references: list(raw.references, 50).map(reference => { requireValue(isObject(reference)); return { label: boundedText(reference.label, 300), url: boundedText(reference.url, 4000) }; }),
    t: normalizeTagging(raw.tagging)
  };
  return derive(row);
}

// Fields every view sorts and filters on.
export function derive(row) {
  row.primary_date = row.date_basis === "event" ? row.event_date : row.published_at;
  row.time = row.primary_date === null ? null : new Date(row.primary_date.length === 10 ? row.primary_date + "T00:00:00Z" : row.primary_date).getTime();
  row.day = row.time === null ? null : new Date(row.time).toISOString().slice(0, 10);
  row.year = row.day ? row.day.slice(0, 4) : "unknown";
  row.month = row.day ? row.day.slice(5, 7) : "unknown";
  row.score = row.t.cvss ? row.t.cvss.base : null;
  row.cve_key = [...row.cves].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))[0] || null;
  row.kev_linked = row.kind === "kev" || row.t.kev !== null;
  row.exploited = row.t.exploitation ? row.t.exploitation[0] : row.exploitation;
  const values = field => row.t[field].map(item => item[0]);
  row.search = normalized([row.title, row.summary, row.source_name, row.source_id, row.native_id || "", ...row.cves, ...row.tags,
    ...["vendor", "product", "actor", "malware", "sector", "company"].flatMap(field => values(field).map(id => id.replace(/^[a-z]+:/, "").replaceAll("-", " ")))].join("\n"));
  return row;
}

export function normalizeArticleShard(raw, path) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "articles" && typeof raw.period === "string");
  requireValue(path.endsWith("/" + raw.period + ".json"), "A shard does not match its path.");
  return list(raw.rows, 30000).map(normalizeRow);
}

function normalizeKevRow(item) {
  requireValue(isObject(item) && typeof item.cve === "string" && CVE.test(item.cve));
  return {
    cve: item.cve, name: boundedText(item.name, 2000, true), vendor: boundedText(item.vendor_raw, 400, true), product: boundedText(item.product_raw, 400, true),
    date_added: calendarDay(item.date_added), due_date: item.due_date === null ? null : calendarDay(item.due_date), directive: optionalText(item.directive, 40),
    ransomware: boundedText(item.ransomware, 40, true), forensic_triage: optionalText(item.forensic_triage, 40),
    cwe: list(item.cwe, 20).map(id => boundedText(id, 40)), required_action: boundedText(item.required_action, 12000, true),
    short_description: boundedText(item.short_description, 12000, true), notes_urls: list(item.notes_urls, 20).map(url => boundedText(url, 4000))
  };
}

export function normalizeKevShard(raw, path) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "kev" && Number.isSafeInteger(raw.year) && path === "kev/" + raw.year + ".json");
  return list(raw.rows, 5000).map(normalizeKevRow);
}

// data/v7/cve-index.json: the compact list-view row per CVE and where its brief lives.
export function normalizeCveIndex(raw) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "cve-index");
  requireValue(raw.briefs_file === null || raw.briefs_file === "data/briefs.json");
  return { rows: cveRows(raw.fields, raw.rows), briefs_file: raw.briefs_file };
}

// data/v7/recent.json: the Today view's file. Live rows for the last days, the KEV entries
// added in the last week or due in the next two weeks, and the CVE index rows those rows name.
export function normalizeRecent(raw) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "recent");
  const value = { content_date: calendarDay(raw.content_date), from: calendarDay(raw.from), to: calendarDay(raw.to), kev_from: calendarDay(raw.kev_from), due_until: calendarDay(raw.due_until) };
  requireValue(value.from <= value.content_date && value.content_date <= value.to && value.kev_from <= value.content_date && value.content_date <= value.due_until);
  value.rows = list(raw.rows, 30000).map(normalizeRow);
  value.kev = list(raw.kev, 5000).map(normalizeKevRow);
  value.cves = cveRows(raw.cve_fields, raw.cves);
  return value;
}

// FIRST's EPSS block on a brief and an index row: {score, percentile, date, model} or null.
const EPSS_MODEL = /^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}$/;
export function normalizeEpss(value) {
  if (value === null || value === undefined) return null;
  requireValue(isObject(value) && typeof value.model === "string" && EPSS_MODEL.test(value.model));
  const fraction = item => { requireValue(typeof item === "number" && Number.isFinite(item) && item >= 0 && item <= 1); return item; };
  return { score: fraction(value.score), percentile: fraction(value.percentile), date: calendarDay(value.date), model: value.model };
}

function cveRows(rawFields, rawRows) {
  const fields = ["cve", ...indexFields, "bucket"];
  requireValue(Array.isArray(rawFields) && rawFields.length === fields.length && rawFields.every((field, position) => field === fields[position]));
  const rows = new Map();
  for (const row of list(rawRows, 30000)) {
    requireValue(Array.isArray(row) && row.length === fields.length);
    const [cve, state, status, guidance, action, score, version, added, weaknesses, exploitation, epss, bucket] = row;
    requireValue(typeof cve === "string" && CVE.test(cve) && !rows.has(cve));
    requireValue(["PUBLISHED", "REJECTED", "UNKNOWN"].includes(state) && ["ok", "failed", "pending"].includes(status) && ["publisher-guidance", "cisa-action", "needs-review"].includes(guidance) && typeof action === "boolean");
    requireValue(score === null || (typeof score === "number" && Number.isFinite(score) && score >= 0 && score <= 10));
    requireValue(bucket === null || (typeof bucket === "string" && /^cve\/[0-9]{4}\/[0-9]{1,5}k\.json$/.test(bucket)));
    rows.set(cve, {
      cve, record_state: state, source_status: status, guidance: state === "REJECTED" ? "needs-review" : guidance, required_action: action,
      score, version: optionalText(version, 100), kev_added: added === null ? null : calendarDay(added),
      weaknesses: list(weaknesses, 8).map(id => { requireValue(typeof id === "string" && /^CWE-[1-9][0-9]{0,5}$/.test(id)); return id; }),
      // CISA's SSVC Exploitation value from its ADP container, as published, or null; FIRST's EPSS block or null.
      ssvc_exploitation: optionalText(exploitation, 100), epss: normalizeEpss(epss), bucket
    });
  }
  return rows;
}

function intakeCount(value, maximum) { nonnegative(value); requireValue(value <= maximum); return value; }

function normalizeSelection(value, sourceId) {
  exactKeys(value, ["version", "basis", "cutoff_date"]);
  requireValue(value.version === 1 && ["document-order-v1", "publisher-date-desc-v1"].includes(value.basis));
  if (value.basis === "document-order-v1") requireValue(value.cutoff_date === null);
  else { requireValue(sourceId === "f5-labs"); calendarDay(value.cutoff_date); }
  return { version: 1, basis: value.basis, cutoff_date: value.cutoff_date };
}

function normalizeIntake(value, source) {
  if (source.id === "cisa-kev") { requireValue(value == null && source.status !== "partial"); return null; }
  if (value == null) { requireValue(source.status !== "partial"); return null; }
  requireValue(source.status !== "not_fetched");
  const hasSelection = Object.hasOwn(value, "selection");
  const keys = ["items_seen", "items_processed", "items_admitted", "items_rejected", "items_filtered", "items_unprocessed", "entry_limit", "cve_limit", "rejection_reasons", "attempted_at", "response_sha256"];
  exactKeys(value, hasSelection ? [...keys, "selection"] : keys);
  exactKeys(value.rejection_reasons, ["invalid_link_or_title", "cve_limit_exceeded"]);
  requireValue(value.entry_limit === 150 && value.cve_limit === 100);
  const report = {
    items_seen: intakeCount(value.items_seen, 40000), items_processed: intakeCount(value.items_processed, 150),
    items_admitted: intakeCount(value.items_admitted, 150), items_rejected: intakeCount(value.items_rejected, 150),
    items_filtered: intakeCount(value.items_filtered, 150), items_unprocessed: intakeCount(value.items_unprocessed, 40000),
    entry_limit: 150, cve_limit: 100,
    rejection_reasons: { invalid_link_or_title: intakeCount(value.rejection_reasons.invalid_link_or_title, 150), cve_limit_exceeded: intakeCount(value.rejection_reasons.cve_limit_exceeded, 150) },
    attempted_at: timestamp(value.attempted_at, false), response_sha256: hash(value.response_sha256),
    selection: hasSelection ? normalizeSelection(value.selection, source.id) : null
  };
  requireValue(report.items_processed === Math.min(report.items_seen, report.entry_limit) && report.items_seen === report.items_processed + report.items_unprocessed);
  requireValue(report.items_processed === report.items_admitted + report.items_rejected + report.items_filtered);
  return report;
}

// One source ledger record (data/v7/sources.json rows, or the schema 6 feed's sources).
export function normalizeSource(source) {
  requireValue(isObject(source) && ["ok", "partial", "failed", "not_fetched"].includes(source.status));
  const item = {
    id: boundedText(source.id, 160), name: boundedText(source.name, 240), url: boundedText(source.url, 4000), kind: boundedText(source.kind, 160), status: source.status,
    last_success: timestamp(source.last_success), last_attempt: timestamp(source.last_attempt), error: source.error === null ? null : boundedText(source.error, 4000, true),
    articles: nonnegative(source.articles), sha256: source.sha256 == null ? null : hash(source.sha256)
  };
  const basis = source.configured_selection;
  requireValue(basis === null || basis === undefined || ["document-order-v1", "publisher-date-desc-v1"].includes(basis));
  item.configured_selection = basis || null;
  item.intake = normalizeIntake(source.intake, item);
  return item;
}

export function normalizeSources(raw) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "sources");
  const ids = new Set();
  return list(raw.rows, 200).map(source => { const item = normalizeSource(source); requireValue(!ids.has(item.id)); ids.add(item.id); return item; });
}

const REPORT_URL = /^https:\/\/github\.com\/TeamStarWolf\/intelligence-hub\/blob\/main\/reports\/[A-Za-z0-9_.\/-]+$/;
function reportUrl(value) {
  if (value === null) return null;
  requireValue(typeof value === "string" && REPORT_URL.test(value) && !value.includes("/../") && safeUrl(value) !== null);
  return value;
}

// data/v7/reports.json. A catalog that fails here is shown as unavailable; it never blocks another view.
export function normalizeReports(raw) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "reports" && ["available", "unavailable"].includes(raw.status));
  if (raw.status === "unavailable") return { status: "unavailable", reason: boundedText(raw.reason, 600), reports: [], indexes: [], notes: [], review: null, updated_at: null };
  const catalog = raw.catalog;
  requireValue(isObject(catalog));
  const reports = list(catalog.reports, 512).map(item => {
    requireValue(isObject(item) && typeof item.id === "string" && /^SW-[A-Z0-9][A-Z0-9._-]{0,119}$/.test(item.id));
    return {
      id: item.id, title: boundedText(item.title, 200), cadence: boundedText(item.cadence, 40), status: boundedText(item.status, 40), origin: boundedText(item.origin, 40),
      coverage: boundedText(item.coverage, 60), period_start: timestamp(item.period_start, false), period_end: timestamp(item.period_end, false),
      compiled_at: timestamp(item.compiled_at), report_url: reportUrl(item.report_url), data_url: reportUrl(item.data_url)
    };
  });
  const indexes = list(catalog.indexes || [], 16).map(item => { requireValue(isObject(item)); return { label: boundedText(item.label, 120), url: reportUrl(item.url) }; });
  let review = null;
  if (isObject(catalog.revision_review)) {
    const source = catalog.revision_review;
    review = { state: optionalText(source.state, 40), nominal_cutoff: timestamp(source.nominal_cutoff ?? null), notes: textList(source.notes || [], 12, 600), records: Array.isArray(source.records) ? Math.min(source.records.length, 100) : 0 };
  }
  return { status: "available", reason: null, reports, indexes, notes: textList(catalog.notes || [], 40, 1200), review, updated_at: timestamp(catalog.updated_at ?? null) };
}

export const COVERAGE_STATUSES = ["complete", "filtered", "partial", "sample", "gap", "unreachable"];

// data/v7/coverage.json: one statement per history source and year. A stub (no history in this
// run) carries no rows and is shown as "coverage not published", never as a claim.
export function normalizeCoverage(raw) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "coverage" && ["ok", "stub"].includes(raw.status));
  if (raw.status === "stub") return { status: "stub", note: optionalText(raw.note ?? null, 600), first_year: null, end_year: null, sources: [], rows: [], held_back: [] };
  requireValue(Number.isSafeInteger(raw.first_year) && Number.isSafeInteger(raw.end_year) && raw.first_year >= 1998 && raw.first_year <= raw.end_year && raw.end_year <= 2100);
  requireValue(Array.isArray(raw.statuses) && raw.statuses.every(status => COVERAGE_STATUSES.includes(status)));
  const ids = new Set();
  const sources = list(raw.sources, 200).map(item => {
    requireValue(isObject(item) && typeof item.source_id === "string" && /^[a-z0-9][a-z0-9-]{0,79}$/.test(item.source_id) && !ids.has(item.source_id));
    ids.add(item.source_id);
    return { source_id: item.source_id, name: boundedText(item.name, 240), adapter: optionalText(item.adapter, 80), home: optionalText(item.home, 4000),
      first_year: item.first_year === null || item.first_year === undefined ? null : nonnegative(item.first_year), last_year: item.last_year === null || item.last_year === undefined ? null : nonnegative(item.last_year),
      filter: optionalText(item.filter, 600), licence: optionalText(item.licence, 600) };
  });
  const seen = new Set();
  const rows = list(raw.rows, 20000).map(item => {
    requireValue(isObject(item) && ids.has(item.source_id) && Number.isSafeInteger(item.year) && item.year >= raw.first_year && item.year <= raw.end_year && COVERAGE_STATUSES.includes(item.status));
    const key = item.source_id + " " + item.year; requireValue(!seen.has(key)); seen.add(key);
    // given_up: rows another source's row already held by link; in_feed: rows the source's own feed or
    // KEV row already held; shown: rows the year's shards carry under this source. A file written
    // before these existed reads as nothing given up, nothing in the feed, all shown.
    const admitted = nonnegative(item.admitted);
    const given_up = item.given_up === undefined ? 0 : nonnegative(item.given_up);
    const in_feed = item.in_feed === undefined ? 0 : nonnegative(item.in_feed);
    const shown = item.shown === undefined ? admitted : nonnegative(item.shown);
    requireValue(given_up + in_feed + shown <= admitted);
    return { source_id: item.source_id, year: item.year, status: item.status, admitted, given_up, in_feed, shown,
      upstream_count: item.upstream_count === null ? null : nonnegative(item.upstream_count), filter: optionalText(item.filter, 600), reason: optionalText(item.reason, 600),
      checked_at: item.checked_at == null ? null : calendarDay(item.checked_at), licence: optionalText(item.licence, 600) };
  });
  const held_back = list(raw.held_back || [], 200).map(item => { requireValue(isObject(item)); return { path: boundedText(item.path, 80), adapter: boundedText(item.adapter, 80), rows: nonnegative(item.rows) }; });
  return { status: "ok", note: null, first_year: raw.first_year, end_year: raw.end_year, sources, rows, held_back };
}

// The adp block on a brief: CISA's ADP container, with its SSVC decision-point values and the
// CVSS metric CISA supplied, when it did. adp_status has the semantics of weaknesses_status.
export const ADP_STATUSES = ["not_projected", "not_supplied", "supplied"];
function normalizeAdp(value) {
  requireValue(isObject(value));
  const adp = { provider: boundedText(value.provider, 100), date: timestamp(value.date), ssvc: null, cvss: null };
  if (value.ssvc !== null) {
    requireValue(isObject(value.ssvc));
    adp.ssvc = { exploitation: optionalText(value.ssvc.exploitation, 100), automatable: optionalText(value.ssvc.automatable, 100),
      technical_impact: optionalText(value.ssvc.technical_impact, 100), timestamp: timestamp(value.ssvc.timestamp) };
  }
  if (value.cvss !== null) {
    requireValue(isObject(value.cvss) && typeof value.cvss.score === "number" && Number.isFinite(value.cvss.score) && value.cvss.score >= 0 && value.cvss.score <= 10);
    adp.cvss = { version: boundedText(value.cvss.version, 100), score: value.cvss.score, vector: optionalText(value.cvss.vector, 2000) };
  }
  return adp;
}

// One full CVE brief, schema 7 shape.
export function normalizeBrief(value, key) {
  requireValue(isObject(value) && CVE.test(key) && value.cve === key && ["ok", "failed", "pending"].includes(value.source_status) && ["PUBLISHED", "REJECTED", "UNKNOWN"].includes(value.record_state));
  requireValue(isObject(value.analysis) && ["known-exploited", "review"].includes(value.analysis.priority) && ["publisher-guidance", "cisa-action", "needs-review"].includes(value.analysis.guidance_status));
  const record = {
    cve: key, title: boundedText(value.title, 2000, true), description: boundedText(value.description, 100000, true),
    source_status: value.source_status, record_state: value.record_state,
    source_updated_at: timestamp(value.source_updated_at), retrieved_at: timestamp(value.retrieved_at),
    source_attempted_at: value.source_attempted_at == null ? null : timestamp(value.source_attempted_at),
    products: list(value.products, 1000).map(product => ({
      vendor: boundedText(product.vendor, 2000, true), product: boundedText(product.product, 2000, true), default_status: optionalText(product.default_status, 100),
      versions: list(product.versions, 2000).map(version => ({
        version: optionalText(version.version, 2000), status: optionalText(version.status, 100),
        less_than: optionalText(version.less_than, 2000), less_than_or_equal: optionalText(version.less_than_or_equal, 2000), version_type: optionalText(version.version_type, 200)
      }))
    })),
    solutions: list(value.solutions, 1000).map(item => ({ text: boundedText(item.text, 100000, true), source_url: optionalText(item.source_url, 4000) })),
    workarounds: list(value.workarounds, 1000).map(item => ({ text: boundedText(item.text, 100000, true), source_url: optionalText(item.source_url, 4000) })),
    required_action: optionalText(value.required_action, 100000), required_action_source_url: optionalText(value.required_action_source_url, 4000),
    kev: value.kev === null ? null : { date_added: timestamp(value.kev.date_added), due_date: timestamp(value.kev.due_date), ransomware: optionalText(value.kev.ransomware, 200) },
    cvss: null,
    references: list(value.references, 1000).map(item => ({ label: boundedText(item.label, 1000, true), url: boundedText(item.url, 4000), kind: boundedText(item.kind, 200, true) })),
    analysis: {
      priority: value.analysis.priority, guidance_status: value.analysis.guidance_status, assessment: boundedText(value.analysis.assessment, 20000, true),
      steps: list(value.analysis.steps, 100).map(item => ({ title: boundedText(item.title, 2000, true), detail: boundedText(item.detail, 20000, true), evidence_url: optionalText(item.evidence_url, 4000) })),
      limitations: textList(value.analysis.limitations, 100, 20000)
    },
    weaknesses: [], weaknesses_status: "not_projected", adp: null, adp_status: "not_projected", epss: null
  };
  if (value.cvss !== null) {
    requireValue(isObject(value.cvss) && (value.cvss.score === null || (typeof value.cvss.score === "number" && Number.isFinite(value.cvss.score) && value.cvss.score >= 0 && value.cvss.score <= 10)));
    record.cvss = { score: value.cvss.score, version: optionalText(value.cvss.version, 100), vector: optionalText(value.cvss.vector, 2000), source_url: optionalText(value.cvss.source_url, 4000) };
  }
  if (Object.hasOwn(value, "weaknesses")) {
    requireValue(["not_projected", "not_supplied", "supplied", "bounded"].includes(value.weaknesses_status));
    record.weaknesses = list(value.weaknesses, 8).map(item => {
      requireValue(isObject(item) && typeof item.id === "string" && /^CWE-[1-9][0-9]{0,5}$/.test(item.id));
      return { id: item.id, description: optionalText(item.description, 200), source_url: optionalText(item.source_url, 4000) };
    });
    record.weaknesses_status = value.weaknesses_status;
  }
  if (Object.hasOwn(value, "adp") || Object.hasOwn(value, "adp_status")) {
    requireValue(ADP_STATUSES.includes(value.adp_status) && (value.adp_status === "supplied" ? value.adp !== null : value.adp === null));
    record.adp_status = value.adp_status;
    if (value.adp !== null) record.adp = normalizeAdp(value.adp);
  }
  if (Object.hasOwn(value, "epss")) record.epss = normalizeEpss(value.epss);
  return record;
}

// data/briefs.json, held to the index that is displayed.
export function normalizeBriefsFile(raw, index) {
  requireValue(isObject(raw) && raw.schema_version === 1 && raw.feed_schema_version === 7 && isObject(raw.briefs));
  if (raw.content_revision !== index.feed_content_revision) {
    const error = new FormatError("The brief file belongs to a different snapshot than the one displayed. The page reads the index again; open the brief once it has reloaded.");
    error.briefMismatch = true; throw error;
  }
  const entries = Object.entries(raw.briefs); requireValue(entries.length <= 30000);
  return new Map(entries.map(([key, value]) => [key, normalizeBrief(value, key)]));
}

// data/v7/cve/<year>/<n>k.json, once the collector publishes buckets.
export function normalizeBucket(raw, path) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "cve-briefs" && "cve/" + raw.bucket + ".json" === path && isObject(raw.briefs));
  return new Map(Object.entries(raw.briefs).map(([key, value]) => [key, normalizeBrief(value, key)]));
}

// Service health (intelligence_hub/status.py): data/v7/status/current.json, the month files
// status/YYYY-MM.json, status/outages.json and status/index.json, and the Statuspage status.json
// the live board reads from a vendor's host. Every link must pass safeUrl; text is rendered as
// text nodes only.
export const STATUS_GROUPS = ["security-platforms", "cloud-and-saas", "developer-services", "internet"];
export const STATUS_INDICATORS = ["none", "minor", "major", "critical", "maintenance", "unknown"];
const STATUS_IMPACTS = ["none", "minor", "major", "critical"];
const STATUS_STATES = ["investigating", "identified", "monitoring", "resolved", "other"];
const STATUS_ID = /^[a-z0-9][a-z0-9-]{0,40}$/;
const STATUS_VOCAB = /^(?:vendor|product):[a-z0-9][a-z0-9-]{0,80}$/;
const STATUS_MONTH = /^status\/([0-9]{4}-(?:0[1-9]|1[0-2]))\.json$/;
export const LIVE_STATUS_PATH = "/api/v2/status.json";

function statusLink(value, nullable = false) {
  if (nullable && value === null) return null;
  requireValue(typeof value === "string" && safeUrl(value) !== null, "A service-health link is not a safe HTTPS link.");
  return value;
}
function vocabId(value) { requireValue(value === null || (typeof value === "string" && STATUS_VOCAB.test(value))); return value; }
function statusId(value) { requireValue(typeof value === "string" && STATUS_ID.test(value)); return value; }

// The only URLs the live board may read: https, the Statuspage status path, no query or fragment.
export function liveStatusUrl(value) {
  if (value === null) return null;
  const url = safeUrl(value);
  requireValue(url !== null && url === value, "A live status URL is not canonical.");
  const parsed = new URL(url);
  requireValue(parsed.pathname === LIVE_STATUS_PATH && !parsed.search && !parsed.hash, "A live status URL is not a Statuspage status.json.");
  return value;
}

export function normalizeIncident(item, source = null) {
  requireValue(isObject(item) && STATUS_STATES.includes(item.status) && (item.impact === null || STATUS_IMPACTS.includes(item.impact)));
  const row = {
    source: statusId(item.source), vendor: vocabId(item.vendor), id: boundedText(item.id, 200), name: boundedText(item.name, 200),
    status: item.status, status_raw: optionalText(item.status_raw, 60), impact: item.impact, impact_raw: optionalText(item.impact_raw, 60),
    components: textList(item.components, 12, 120), started: timestamp(item.started, false), updated: timestamp(item.updated),
    resolved: timestamp(item.resolved), url: statusLink(item.url), summary: optionalText(item.summary, 280)
  };
  requireValue(source === null || row.source === source, "An incident sits under another source.");
  return row;
}

export function normalizeStatusCurrent(raw) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "status-current", "The service-health board is not a schema 7 file.");
  const groups = list(raw.groups, 8).map(group => { requireValue(isObject(group) && STATUS_GROUPS.includes(group.id)); return { id: group.id, label: boundedText(group.label, 60) }; });
  const seen = new Set();
  const sources = list(raw.sources, 120).map(item => {
    requireValue(isObject(item) && STATUS_GROUPS.includes(item.group) && ["ok", "failed", "not_fetched", "not_configured"].includes(item.status) && STATUS_INDICATORS.includes(item.indicator) && typeof item.cors === "boolean");
    const id = statusId(item.id);
    requireValue(!seen.has(id), "A service-health source is listed twice.");
    seen.add(id);
    return { id, name: boundedText(item.name, 80), vendor: vocabId(item.vendor), group: item.group, class: boundedText(item.class, 20), format: boundedText(item.format, 30),
      home: statusLink(item.home), library: vocabId(item.library), cors: item.cors, live: liveStatusUrl(item.live), status: item.status,
      fetched_at: timestamp(item.fetched_at), last_success: timestamp(item.last_success), error: optionalText(item.error, 400),
      indicator: item.indicator, description: optionalText(item.description, 160), open: list(item.open, 25).map(row => normalizeIncident(row, id)) };
  });
  const pageOnly = list(raw.page_only, 40).map(item => {
    requireValue(isObject(item));
    return { id: statusId(item.id), name: boundedText(item.name, 80), vendor: vocabId(item.vendor), home: statusLink(item.home, true), reason: boundedText(item.reason, 300) };
  });
  return { generated_at: timestamp(raw.generated_at, false), groups, sources, page_only: pageOnly, notes: textList(raw.notes, 12, 600) };
}

export function normalizeStatusMonth(raw, path) {
  const match = STATUS_MONTH.exec(path);
  requireValue(match && isObject(raw) && raw.schema_version === 7 && raw.kind === "status-month" && raw.period === match[1], "A service-health month file does not match its path.");
  return list(raw.rows, 6000).map(row => normalizeIncident(row));
}

function outageBlock(value, kind) {
  if (value === undefined) return null;
  requireValue(isObject(value) && ["ok", "failed", "not_fetched", "not_configured"].includes(value.status));
  const rows = list(value.rows, 300).map(item => {
    requireValue(isObject(item));
    if (kind === "ioda") {
      requireValue(["country", "region", "asn"].includes(item.entity_type) && (item.duration_seconds === null || nonnegative(item.duration_seconds) >= 0) && (item.score === null || Number.isSafeInteger(item.score)));
      return { id: boundedText(item.id, 80), entity_type: item.entity_type, entity_code: boundedText(item.entity_code, 20), entity_name: boundedText(item.entity_name, 80),
        datasource: optionalText(item.datasource, 40), start: timestamp(item.start, false), end: timestamp(item.end), duration_seconds: item.duration_seconds, score: item.score, url: statusLink(item.url) };
    }
    return { id: boundedText(item.id, 40), locations: textList(item.locations, 12, 80), asns: textList(item.asns, 12, 80), cause: optionalText(item.cause, 60), type: optionalText(item.type, 60),
      scope: optionalText(item.scope, 120), description: optionalText(item.description, 280), start: timestamp(item.start), end: timestamp(item.end), url: statusLink(item.url) };
  });
  return { name: boundedText(value.name, 80), home: statusLink(value.home), status: value.status, fetched_at: timestamp(value.fetched_at), last_success: timestamp(value.last_success),
    error: optionalText(value.error, 400), copyright: optionalText(value.copyright, 200), note: optionalText(value.note, 300), rows };
}

export function normalizeStatusOutages(raw) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "status-outages", "The outage file is not a schema 7 file.");
  return { generated_at: timestamp(raw.generated_at, false), window_hours: nonnegative(raw.window_hours), ioda: outageBlock(raw.ioda, "ioda"), radar: outageBlock(raw.radar, "radar") };
}

export function normalizeStatusIndex(raw) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "status-index", "The service-health index is not a schema 7 file.");
  const months = list(raw.months, 24).map(item => {
    requireValue(isObject(item) && typeof item.path === "string" && STATUS_MONTH.test(item.path) && item.path === "status/" + item.period + ".json");
    return { period: item.period, path: item.path, rows: nonnegative(item.rows) };
  });
  const coverage = list(raw.coverage, 80).map(item => { requireValue(isObject(item)); return { source: statusId(item.source), first_incident: calendarDay(item.first_incident), incidents: nonnegative(item.incidents) }; });
  return { generated_at: timestamp(raw.generated_at, false), months, coverage, sources: nonnegative(raw.sources), page_only: nonnegative(raw.page_only), notes: textList(raw.notes, 12, 600) };
}

// The Statuspage status.json a vendor's host returns to the live board: only the indicator and its
// description are read.
export function normalizeLiveStatus(raw) {
  requireValue(isObject(raw) && isObject(raw.status) && STATUS_INDICATORS.includes(raw.status.indicator), "The status page answered in an unexpected format.");
  const description = typeof raw.status.description === "string" ? raw.status.description.replace(/\s+/g, " ").trim().slice(0, 160) : null;
  return { indicator: raw.status.indicator, description: description || null };
}

// Patch Tuesday briefs (intelligence_hub/patch_tuesday.py): data/v7/patch-tuesday/index.json and
// one data/v7/patch-tuesday/YYYY-MM.json per Microsoft monthly release. Rows arrive as arrays in
// the order of PATCH_TUESDAY_FIELDS; every link must start with its vendor's own prefix and pass
// safeUrl, and the view builds MSRC, KEV and Hub links from checked CVE ids only.
export const PATCH_TUESDAY_FIELDS = ["cve", "title", "severity", "impact", "cvss", "vector", "families", "component", "cna", "exploited", "disclosed", "exploitability", "cwe", "released", "revised"];
export const PATCH_TUESDAY_TIERS = ["kev", "exploited", "critical-rce-exposed", "cvss"];
const PT_MONTH = /^[0-9]{4}-(?:0[1-9]|1[0-2])$/;
const PT_SEVERITIES = ["Critical", "Important", "Moderate", "Low"];
const PT_CVE = /^CVE-\d{4}-\d{4,19}$/;
function prefixed(value, prefixes, nullable = true) {
  if (nullable && value === null) return null;
  const url = safeUrl(value);
  requireValue(url !== null && url === value && prefixes.some(prefix => value.startsWith(prefix)), "A Patch Tuesday link is not a vendor link.");
  return value;
}
function score(value) { requireValue(value === null || (typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 10)); return value; }
function day(value) { return value === null ? null : calendarDay(value); }
function month(value) { requireValue(typeof value === "string" && PT_MONTH.test(value)); return value; }
function countMap(value, limit = 80) {
  requireValue(isObject(value) && Object.keys(value).length <= limit);
  const out = new Map();
  for (const [key, item] of Object.entries(value)) { boundedText(key, 80); out.set(key, nonnegative(item)); }
  return out;
}
function sourceStatus(value) {
  requireValue(isObject(value) && ["ok", "unavailable"].includes(value.status));
  return { status: value.status, reason: optionalText(value.reason, 300) };
}

export function normalizePatchTuesdayIndex(raw) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "patch-tuesday-index", "The Patch Tuesday index is not a schema 7 index.");
  const months = list(raw.months, 600).map(item => {
    requireValue(isObject(item) && item.path === "patch-tuesday/" + month(item.month) + ".json");
    return { month: item.month, id: boundedText(item.id, 20), title: boundedText(item.title, 120), initial_release: timestamp(item.initial_release, false),
      current_release: timestamp(item.current_release, false), path: item.path, total: nonnegative(item.total), critical: nonnegative(item.critical),
      important: nonnegative(item.important), exploited: nonnegative(item.exploited), disclosed: nonnegative(item.disclosed), in_kev: nonnegative(item.in_kev),
      kev_added_in_month: nonnegative(item.kev_added_in_month), adobe: nonnegative(item.adobe), sap: nonnegative(item.sap) };
  });
  const pending = list(raw.pending, 600).map(item => {
    requireValue(isObject(item));
    return { month: month(item.month), id: boundedText(item.id, 20), reason: boundedText(item.reason, 400) };
  });
  requireValue(isObject(raw.status));
  return { months, pending, rules: textList(raw.rules, 12, 600), notes: textList(raw.notes, 12, 600),
    status: { msrc: sourceStatus(raw.status.msrc), adobe: sourceStatus(raw.status.adobe), sap: sourceStatus(raw.status.sap) },
    first_month: raw.first_month === null ? null : month(raw.first_month), last_month: raw.last_month === null ? null : month(raw.last_month) };
}

function patchRow(item) {
  requireValue(Array.isArray(item) && item.length === PATCH_TUESDAY_FIELDS.length);
  const [cve, title, severity, impact, cvss, vector, families, component, cna, exploited, disclosed, exploitability, cwe, released, revised] = item;
  requireValue(typeof cve === "string" && PT_CVE.test(cve) && (severity === null || PT_SEVERITIES.includes(severity)) && typeof exploited === "boolean" && typeof disclosed === "boolean");
  requireValue(vector === null || (typeof vector === "string" && /^CVSS:[0-9.]+\/[A-Za-z:/.]{1,200}$/.test(vector)));
  return { cve, title: boundedText(title, 240), severity, impact: optionalText(impact, 60), cvss: score(cvss), vector, families: textList(families, 12, 80),
    component: optionalText(component, 120), cna: optionalText(cna, 60), exploited, disclosed, exploitability: optionalText(exploitability, 60),
    cwe: list(cwe, 10).map(value => { requireValue(typeof value === "string" && /^CWE-[1-9][0-9]{0,5}$/.test(value)); return value; }), released: day(released), revised: day(revised) };
}

export function normalizePatchTuesday(raw, path) {
  requireValue(isObject(raw) && raw.schema_version === 7 && raw.kind === "patch-tuesday" && path === "patch-tuesday/" + month(raw.month) + ".json",
    "A Patch Tuesday brief does not match its path.");
  requireValue(Array.isArray(raw.fields) && raw.fields.join(",") === PATCH_TUESDAY_FIELDS.join(","), "A Patch Tuesday brief has an unknown row layout.");
  const msrc = raw.msrc;
  requireValue(isObject(msrc) && isObject(raw.counts) && isObject(raw.kev));
  const rows = list(raw.rows, 20000).map(patchRow);
  const cves = new Set(rows.map(row => row.cve));
  const counts = raw.counts;
  const kevListed = list(raw.kev.listed, 20000).map(item => { requireValue(Array.isArray(item) && item.length === 3 && cves.has(item[0])); return { cve: item[0], added: calendarDay(item[1]), due: day(item[2]) }; });
  const kevAdded = list(raw.kev.added_in_month, 2000).map(item => {
    requireValue(Array.isArray(item) && item.length === 3 && typeof item[0] === "string" && PT_CVE.test(item[0]) && typeof item[2] === "boolean");
    return { cve: item[0], added: calendarDay(item[1]), inRelease: item[2] };
  });
  const priority = list(raw.priority, 20000).map(item => { requireValue(Array.isArray(item) && item.length === 2 && cves.has(item[0]) && PATCH_TUESDAY_TIERS.includes(item[1])); return { cve: item[0], tier: item[1] }; });
  const briefs = new Set(list(raw.briefs, 20000).map(value => { requireValue(cves.has(value)); return value; }));
  const adobe = raw.adobe;
  requireValue(isObject(adobe) && Array.isArray(adobe.fields) && adobe.fields.join(",") === "id,title,products,url,posted,updated");
  const adobeRows = list(adobe.rows, 200).map(item => {
    requireValue(Array.isArray(item) && item.length === 6 && typeof item[0] === "string" && /^APSB\d{2}-\d{1,4}$/.test(item[0]));
    return { id: item[0], title: boundedText(item[1], 240), products: textList(item[2], 6, 100), url: prefixed(item[3], ["https://helpx.adobe.com/security/products/"], false),
      posted: calendarDay(item[4]), updated: day(item[5]) };
  });
  const sap = raw.sap;
  requireValue(isObject(sap) && Array.isArray(sap.fields) && sap.fields.join(",") === "note,title,cves,priority,cvss,url");
  const sapRows = list(sap.rows, 200).map(item => {
    requireValue(Array.isArray(item) && item.length === 6);
    return { note: boundedText(item[0], 60), title: boundedText(item[1], 240), cves: list(item[2], 20).map(value => { requireValue(typeof value === "string" && PT_CVE.test(value)); return value; }),
      priority: boundedText(item[3], 20), cvss: score(item[4]),
      url: prefixed(item[5], ["https://me.sap.com/", "https://launchpad.support.sap.com/", "https://github.com/SAP/", "https://support.sap.com/"]) };
  });
  return {
    month: raw.month,
    msrc: { id: boundedText(msrc.id, 20), title: boundedText(msrc.title, 120), initial_release: timestamp(msrc.initial_release, false), current_release: timestamp(msrc.current_release, false),
      listed: nonnegative(msrc.listed), left_out: nonnegative(msrc.left_out), url: prefixed(msrc.url, ["https://msrc.microsoft.com/update-guide/"], false) },
    rows, kev: { listed: kevListed, addedInMonth: kevAdded }, priority, briefs,
    counts: { total: nonnegative(counts.total), critical: nonnegative(counts.critical), exploited: nonnegative(counts.exploited), disclosed: nonnegative(counts.disclosed),
      in_kev: nonnegative(counts.in_kev), severity: countMap(counts.severity, 10), impact: countMap(counts.impact), family: countMap(counts.family), cna: countMap(counts.cna, 200) },
    adobe: { ...sourceStatus(adobe), url: prefixed(adobe.url, ["https://helpx.adobe.com/"], false), rows: adobeRows, latest_posted: adobe.latest_posted == null ? null : calendarDay(adobe.latest_posted) },
    sap: { ...sourceStatus(sap), url: prefixed(sap.url, ["https://support.sap.com/"], false), rows: sapRows }
  };
}
