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

const KINDS = ["advisory", "research", "reporting", "incident", "kev", "filing", "bulletin", "note"];
const EXPLOITATION = ["known", "reported", "unknown"];
const ORIGIN = /^(?:publisher-feed|cisa-kev|library-curation|history:[a-z0-9][a-z0-9-]{0,39})$/;
const CVE = /^CVE-\d{4}-\d{4,19}$/;
const SHARD_PATH = /^(?:(?:sources|coverage|reports|cve-index|recent)\.json|live\/(?:[0-9]{4}-(?:0[1-9]|1[0-2])|undated)\.json|history\/(?:[0-9]{4}|undated)\.json|kev\/[0-9]{4}\.json|cve\/[0-9]{4}\/[0-9]{1,5}k\.json)$/;
const EXPORT_PATH = /^exports\/(?:articles-(?:[0-9]{4}(?:-(?:0[1-9]|1[0-2]))?|undated)\.(?:csv|jsonl)|tags-(?:[0-9]{4}(?:-(?:0[1-9]|1[0-2]))?|undated)\.csv|manifest\.json|data-dictionary\.md)$/;

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
  const tags = { source_class: null, event_type: [], vendor: [], product: [], actor: [], malware: [], sector: [], region: [], cwe: [], attack: [], exploitation: null, kev: null, cvss: null };
  if (raw === undefined || raw === null) return tags;
  requireValue(isObject(raw));
  if (raw.source_class !== undefined) tags.source_class = boundedText(raw.source_class, 40);
  for (const field of ["event_type", "vendor", "product", "actor", "malware", "sector", "cwe"]) if (raw[field] !== undefined) tags[field] = triples(raw[field], 3);
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
    ...["vendor", "product", "actor", "malware", "sector"].flatMap(field => values(field).map(id => id.replace(/^[a-z]+:/, "").replaceAll("-", " ")))].join("\n"));
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

function cveRows(rawFields, rawRows) {
  const fields = ["cve", ...indexFields, "bucket"];
  requireValue(Array.isArray(rawFields) && rawFields.length === fields.length && rawFields.every((field, position) => field === fields[position]));
  const rows = new Map();
  for (const row of list(rawRows, 30000)) {
    requireValue(Array.isArray(row) && row.length === fields.length);
    const [cve, state, status, guidance, action, score, version, added, weaknesses, bucket] = row;
    requireValue(typeof cve === "string" && CVE.test(cve) && !rows.has(cve));
    requireValue(["PUBLISHED", "REJECTED", "UNKNOWN"].includes(state) && ["ok", "failed", "pending"].includes(status) && ["publisher-guidance", "cisa-action", "needs-review"].includes(guidance) && typeof action === "boolean");
    requireValue(score === null || (typeof score === "number" && Number.isFinite(score) && score >= 0 && score <= 10));
    requireValue(bucket === null || (typeof bucket === "string" && /^cve\/[0-9]{4}\/[0-9]{1,5}k\.json$/.test(bucket)));
    rows.set(cve, {
      cve, record_state: state, source_status: status, guidance: state === "REJECTED" ? "needs-review" : guidance, required_action: action,
      score, version: optionalText(version, 100), kev_added: added === null ? null : calendarDay(added),
      weaknesses: list(weaknesses, 8).map(id => { requireValue(typeof id === "string" && /^CWE-[1-9][0-9]{0,5}$/.test(id)); return id; }), bucket
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
    weaknesses: [], weaknesses_status: "not_projected"
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
