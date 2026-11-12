// The schema 6 and early schema 7 feed reader (data/feed.json), ported unchanged from the
// single-file app. The page uses it in two places: as the fallback when data/v7/index.json is
// absent, and for the curated threat context and revision review that only the feed carries.
import { safeUrl } from "./util.js";
import { maximumArticles, maximumFeedBytes, indexFields } from "./limits.js";
import { FormatError, derive, normalizeEpss } from "./validate.js";

const kinds = { advisory: "ADVISORY", research: "RESEARCH", reporting: "REPORTING", incident: "INCIDENT", kev: "CISA KEV", filing: "SEC FILING", change: "CHANGE", lifecycle: "LIFECYCLE" };
const origins = { "publisher-feed": "PUBLISHER FEED", "cisa-kev": "CATALOG RECORD", "library-curation": "CURATED ARCHIVE" };
const day = 86400000;
const cvePattern = /^CVE-\d{4}-\d{4,19}$/;

function requireValue(condition) {
  if (!condition) throw new FormatError("The saved feed does not match the supported snapshot format.");
}

function boundedText(value, maximum, empty = false) {
  requireValue(typeof value === "string" && value.length <= maximum && (empty || value.trim().length > 0));
  return value;
}

function optionalText(value, maximum) { return value == null ? null : boundedText(value, maximum, true); }

function timestamp(value, nullable = true) {
  if (nullable && value === null) return null;
  boundedText(value, 80);
  requireValue(/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?$/.test(value));
  const date = new Date(value);
  const calendar = new Date(value.slice(0, 10) + "T00:00:00Z");
  requireValue(Number.isFinite(date.getTime()) && Number.isFinite(calendar.getTime()) && calendar.toISOString().slice(0, 10) === value.slice(0, 10));
  return value;
}

function list(value, limit) { requireValue(Array.isArray(value) && value.length <= limit); return value; }
function textList(value, limit, textLimit) { return list(value, limit).map(item => boundedText(item, textLimit)); }
function nonnegative(value) { requireValue(Number.isSafeInteger(value) && value >= 0); return value; }
function normalized(value) { return value.normalize("NFKC").toLocaleLowerCase(); }

function exactKeys(value, keys) {
  requireValue(value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)));
}

// Only the schema5 additions use scalar/code-point text limits. Legacy fields keep their original validators.
function intelligenceText(value, maximum, empty = false) {
  requireValue(typeof value === "string" && (empty || value.trim().length > 0));
  let length = 0;
  for (const char of value) {
    const point = char.codePointAt(0); length++;
    requireValue(length <= maximum && point >= 32 && !(point >= 0x7f && point <= 0x9f) && !(point >= 0xd800 && point <= 0xdfff) && ![0x061c, 0x200e, 0x200f, 0xfeff].includes(point) && !(point >= 0x202a && point <= 0x202e) && !(point >= 0x2066 && point <= 0x2069));
  }
  return value;
}

function intelligenceNotes(value) { list(value, 12).forEach(item => intelligenceText(item, 600)); }
function intelligenceHash(value, nullable = false) { requireValue(nullable && value === null || typeof value === "string" && /^[a-f0-9]{64}$/.test(value)); }
function intelligenceUnique(values) { requireValue(new Set(values).size === values.length); }
function intelligenceId(value, pattern) { requireValue(typeof value === "string" && pattern.test(value)); return value; }

function intelligenceClock(value, nullable = false, source = false) {
  if (nullable && value === null) return null;
  requireValue(typeof value === "string" && value.length <= 40 && value.slice(0, 4) !== "0000");
  if (source && /^\d{4}-\d{2}-\d{2}$/.test(value)) { selectionDate(value); return value; }
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(?:Z|([+-])(\d{2}):(\d{2}))$/.exec(value);
  requireValue(match && Number(match[2]) < 24 && Number(match[3]) < 60 && Number(match[4]) < 60 && (!match[5] || Number(match[6]) < 24 && Number(match[7]) < 60));
  selectionDate(match[1]); requireValue(Number.isFinite(new Date(value).getTime()));
  return value;
}

function intelligenceTick(value) {
  // Date supplies milliseconds; retain the validated source's remaining microseconds for comparisons.
  const fraction = /\.(\d{1,6})/.exec(value)?.[1] || "";
  return BigInt(new Date(value).getTime()) * 1000n + BigInt(fraction.padEnd(6, "0").slice(3) || "0");
}

function intelligenceUri(value, report = false, request = false) {
  requireValue(typeof value === "string" && value.length > 0 && value.length <= 4000 && /^[\x21-\x7e]+$/.test(value));
  const match = /^https:\/\/([a-z0-9.-]+)(\/[A-Za-z0-9._~\/-]*)(?:\?([A-Za-z0-9._~=&-]+))?(?:#([A-Za-z0-9._~-]+))?$/.exec(value);
  requireValue(match !== null && match[0] === value);
  const [, host, path, query, fragment] = match, labels = host.split(".");
  requireValue(host.length <= 253 && labels.length >= 2 && /^[a-z]{2,63}$/.test(labels.at(-1)) && labels.every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label) && !label.startsWith("xn--")));
  requireValue(path.split("/").every(segment => ![".", ".."].includes(segment)));
  const queryKeys = [];
  if (query !== undefined) {
    const pairs = query.split("&"); requireValue(pairs.length <= 40);
    for (const pair of pairs) {
      const pieces = pair.split("="); requireValue(pieces.length === 2 && pieces.every(piece => /^[A-Za-z0-9._~-]+$/.test(piece)));
      const key = pieces[0], lowered = key.toLowerCase();
      requireValue(!["auth", "token", "signature", "session", "password"].some(token => lowered.includes(token)) && !lowered.startsWith("utm_") && !["fbclid", "gclid", "mc_cid", "mc_eid"].includes(lowered));
      queryKeys.push(key);
    }
    intelligenceUnique(queryKeys);
  }
  requireValue(safeUrl(value));
  if (request) requireValue(fragment === undefined);
  if (report) {
    const prefix = "/TeamStarWolf/intelligence-hub/blob/main/reports/";
    requireValue(host === "github.com" && query === undefined && fragment === undefined && path.startsWith(prefix) && path.length > prefix.length && path.slice(prefix.length).split("/").every(part => /^[A-Za-z0-9_.-]+$/.test(part) && ![".", ".."].includes(part)));
  }
  return value;
}

function intelligenceEvidence(rows, confidence) {
  requireValue(["source_stated", "corroborated", "uncertain"].includes(confidence));
  requireValue(list(rows, 4).length > 0);
  for (const item of rows) {
    exactKeys(item, ["source_url", "publisher", "published_at", "updated_at", "event_at", "observed_at", "source_version", "source_sha256", "claim"]);
    intelligenceUri(item.source_url); intelligenceText(item.publisher, 160); intelligenceText(item.claim, 600);
    for (const field of ["published_at", "updated_at", "event_at"]) intelligenceClock(item[field], true, true);
    intelligenceClock(item.observed_at); intelligenceHash(item.source_sha256);
    if (item.source_version !== null) intelligenceText(item.source_version, 100);
  }
  requireValue(confidence !== "corroborated" || new Set(rows.map(item => item.source_url)).size >= 2);
}

function intelligenceCatalog(value, admitted) {
  exactKeys(value, ["version", "reviewed_at", "source_sha256", "status", "entities", "relationships", "notes"]);
  intelligenceText(value.version, 80); intelligenceClock(value.reviewed_at, true); intelligenceHash(value.source_sha256); intelligenceNotes(value.notes);
  requireValue(value.status === (value.reviewed_at === null ? "unreviewed" : "review_recorded"));
  const entities = new Map();
  for (const item of list(value.entities, 128)) {
    exactKeys(item, ["id", "type", "label", "aliases", "summary", "confidence", "evidence"]);
    requireValue(["cwe", "capec", "actor", "campaign", "product", "mitigation"].includes(item.type));
    const pattern = item.type === "cwe" ? /^CWE-[1-9][0-9]{0,5}$/ : item.type === "capec" ? /^CAPEC-[1-9][0-9]{0,5}$/ : new RegExp("^" + item.type.toUpperCase() + "-[a-z0-9][a-z0-9-]{0,63}$");
    intelligenceId(item.id, pattern); requireValue(!entities.has(item.id)); entities.set(item.id, item.type);
    intelligenceText(item.label, 200); intelligenceText(item.summary, 600);
    list(item.aliases, 12).forEach(alias => intelligenceText(alias, 160)); intelligenceUnique(item.aliases);
    intelligenceEvidence(item.evidence, item.confidence);
  }
  const ids = [];
  for (const item of list(value.relationships, 256)) {
    exactKeys(item, ["id", "source_id", "target_id", "relation", "basis", "summary", "confidence", "evidence"]);
    ids.push(intelligenceId(item.id, /^REL-[a-z0-9][a-z0-9-]{0,95}$/));
    requireValue(typeof item.source_id === "string" && typeof item.target_id === "string" && item.source_id !== item.target_id && [item.source_id, item.target_id].every(id => entities.has(id) || admitted.has(id)));
    const left = entities.get(item.source_id) || "cve", right = entities.get(item.target_id) || "cve";
    requireValue(["taxonomy_mapping", "attributed_to", "affects_product", "recommended_mitigation", "associated_with"].includes(item.relation));
    intelligenceEvidence(item.evidence, item.confidence); intelligenceText(item.summary, 600);
    if (item.relation === "taxonomy_mapping") requireValue(left === "cwe" && right === "capec" && item.basis === "catalogue" && item.evidence.every(row => ["cwe.mitre.org", "capec.mitre.org"].includes(new URL(row.source_url).hostname)));
    else {
      requireValue(item.basis === "publisher_claim");
      if (item.relation === "attributed_to") requireValue(left === "campaign" && right === "actor");
      if (item.relation === "affects_product") requireValue(["cve", "campaign"].includes(left) && right === "product");
      if (item.relation === "recommended_mitigation") requireValue(["cve", "cwe", "capec", "campaign", "product"].includes(left) && right === "mitigation");
    }
  }
  intelligenceUnique(ids);
}

function intelligenceConfiguration(value) {
  const fixed = { schema_version: 1, timezone: "America/Chicago", daily_hours: [6, 14, 22], weekday_lookback_hours: 24, weekend_lookback_hours: 48, weekend_iso_days: [6, 7], periodic_hour: 6, weekly_iso_day: 1, fortnight_anchor_start: "2026-10-19", fortnight_days: 14, rolling_months: 6, cadences: ["daily", "weekly", "weekend", "fortnightly", "monthly", "quarterly", "six-month"] };
  exactKeys(value, [...Object.keys(fixed), "schedule_state", "schedule_observed_at", "notes"]);
  for (const [key, expected] of Object.entries(fixed)) requireValue(JSON.stringify(value[key]) === JSON.stringify(expected));
  requireValue(["planned", "configured", "paused"].includes(value.schedule_state));
  intelligenceClock(value.schedule_observed_at, value.schedule_state === "planned"); intelligenceNotes(value.notes);
}

function intelligenceReports(rows, indexes) {
  const reports = new Map();
  const reportId = /^SW-[A-Z0-9][A-Z0-9._-]{0,119}$/;
  for (const item of list(rows, 128)) {
    exactKeys(item, ["id", "origin", "cadence", "title", "period_start", "period_end", "period_kind", "compiled_at", "compilation_precision", "status", "coverage", "report_url", "data_url", "prior_report_id"]);
    intelligenceId(item.id, reportId); requireValue(!reports.has(item.id)); reports.set(item.id, item);
    requireValue(["daily", "weekly", "weekend", "fortnightly", "monthly", "quarterly", "six-month"].includes(item.cadence) && ["generated_report", "legacy_report"].includes(item.origin) && ["published", "partial", "insufficient_evidence", "planned"].includes(item.status));
    intelligenceText(item.title, 200);
    const legacy = item.origin === "legacy_report";
    intelligenceClock(item.period_start, false, legacy); intelligenceClock(item.period_end, false, legacy); intelligenceClock(item.compiled_at, true, legacy);
    requireValue(item.period_start.includes("T") === item.period_end.includes("T"));
    requireValue(legacy ? intelligenceTick(item.period_start) <= intelligenceTick(item.period_end) : intelligenceTick(item.period_start) < intelligenceTick(item.period_end));
    requireValue(item.compilation_precision === (item.compiled_at === null ? "unknown" : item.compiled_at.includes("T") ? "timestamp" : "date"));
    if (legacy) requireValue(item.period_kind === "legacy_declared" && item.status !== "planned" && item.coverage === "not_reassessed");
    else requireValue(["rolling_elapsed", "calendar", "month_to_date", "historical_calendar"].includes(item.period_kind));
    if (item.status === "planned") requireValue(item.compiled_at === null && item.report_url === null && item.data_url === null && item.coverage === "not_yet_available");
    else { requireValue(legacy || item.compiled_at !== null && ["source_subset", "insufficient"].includes(item.coverage)); intelligenceUri(item.report_url, true); intelligenceUri(item.data_url, true); }
    if (item.prior_report_id !== null) { intelligenceId(item.prior_report_id, reportId); requireValue(item.prior_report_id !== item.id); }
  }
  const labels = [], urls = [];
  for (const item of list(indexes, 16)) { exactKeys(item, ["label", "url"]); labels.push(intelligenceText(item.label, 120)); urls.push(intelligenceUri(item.url, true)); }
  intelligenceUnique(labels); intelligenceUnique(urls); return reports;
}

function intelligenceRevisions(value, reports) {
  const fixed = { lookback_hours: 96, priority_hours: 48, max_sources: 12, min_success_interval_hours: 8, min_failure_interval_hours: 24 };
  exactKeys(value, [...Object.keys(fixed), "state", "report_id", "recorded_at", "nominal_cutoff", "records", "notes"]);
  for (const [key, expected] of Object.entries(fixed)) requireValue(value[key] === expected);
  requireValue(["not_run", "completed", "partial"].includes(value.state)); list(value.records, 12); intelligenceNotes(value.notes);
  if (value.state === "not_run") { requireValue(value.report_id === null && value.recorded_at === null && value.nominal_cutoff === null && value.records.length === 0); return; }
  requireValue(reports.has(value.report_id) && reports.get(value.report_id).status !== "planned");
  intelligenceClock(value.recorded_at); intelligenceClock(value.nominal_cutoff);
  const recorded = intelligenceTick(value.recorded_at), cutoff = intelligenceTick(value.nominal_cutoff); requireValue(cutoff <= recorded);
  const reviewed = ["material_field_change", "timestamp_only", "raw_response_changed_unqualified", "no_baseline", "unchanged_supported"], ids = [], urls = [];
  for (const item of value.records) {
    exactKeys(item, ["id", "source_url", "status", "recorded_at", "last_cited_at", "last_attempt_at", "checked_at", "prior_checked_at", "old_sha256", "new_sha256", "source_published_at", "source_updated_at", "eligibility_state", "next_eligible_at", "summary", "previous_report_id", "previous_report_url", "evidence_urls", "comparison_scope", "comparison_versions"]);
    ids.push(intelligenceId(item.id, /^REV-[a-z0-9][a-z0-9-]{0,95}$/)); urls.push(intelligenceUri(item.source_url, false, true));
    requireValue([...reviewed, "refused", "failed", "not_checked"].includes(item.status));
    for (const field of ["recorded_at", "last_cited_at"]) intelligenceClock(item[field]);
    for (const field of ["last_attempt_at", "checked_at", "prior_checked_at", "next_eligible_at"]) intelligenceClock(item[field], true);
    const time = field => item[field] === null ? null : intelligenceTick(item[field]);
    const event = time("recorded_at"), cited = time("last_cited_at"), attempt = time("last_attempt_at"), checked = time("checked_at"), prior = time("prior_checked_at"), next = time("next_eligible_at");
    requireValue(event <= recorded && cited >= cutoff - 345600000000n && cited <= cutoff && (attempt === null || attempt <= event) && (checked === null || checked <= event) && (prior === null || prior <= (checked ?? event)));
    intelligenceHash(item.old_sha256, true); intelligenceHash(item.new_sha256, true);
    intelligenceClock(item.source_published_at, true, true); intelligenceClock(item.source_updated_at, true, true); intelligenceText(item.summary, 600);
    requireValue(["eligible", "cooldown", "deactivated", "unknown"].includes(item.eligibility_state));
    if (item.previous_report_id !== null) intelligenceId(item.previous_report_id, /^SW-[A-Z0-9][A-Z0-9._-]{0,119}$/);
    if (item.previous_report_url !== null) intelligenceUri(item.previous_report_url, true);
    list(item.evidence_urls, 4).forEach(url => intelligenceUri(url)); intelligenceUnique(item.evidence_urls);
    if (item.comparison_scope !== null) intelligenceText(item.comparison_scope, 200);
    exactKeys(item.comparison_versions, ["prior", "current"]);
    Object.values(item.comparison_versions).forEach(version => { if (version !== null) intelligenceId(version, /^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/); });
    const versions = item.comparison_versions;
    const deactivated = item.eligibility_state === "deactivated" && next === null;
    if (reviewed.includes(item.status)) {
      requireValue(attempt !== null && checked !== null && attempt <= checked && item.new_sha256 !== null && next !== null && next >= attempt + 28800000000n);
      if (item.status === "no_baseline") requireValue(item.old_sha256 === null && prior === null && versions.prior === null);
      else requireValue(item.old_sha256 !== null && prior !== null);
      if (["raw_response_changed_unqualified", "material_field_change"].includes(item.status)) requireValue(item.old_sha256 !== item.new_sha256);
      if (item.status === "unchanged_supported") requireValue(item.old_sha256 === item.new_sha256);
      if (["material_field_change", "timestamp_only"].includes(item.status)) requireValue(item.comparison_scope !== null && item.evidence_urls.length > 0 && versions.prior !== null && versions.prior === versions.current);
    } else {
      requireValue(checked === null && item.comparison_scope === null && versions.prior === null && versions.current === null && value.state === "partial");
      if (item.status === "refused") requireValue(deactivated);
      else if (attempt !== null) requireValue(deactivated || next !== null && next >= attempt + 86400000000n);
    }
  }
  intelligenceUnique(ids); intelligenceUnique(urls);
}

export function normalizeIntelligence(value, admitted) {
  exactKeys(value, ["schema_version", "catalog", "reporting", "revisions", "notes"]); requireValue(value.schema_version === 1);
  intelligenceNotes(value.notes); intelligenceCatalog(value.catalog, admitted);
  const reporting = value.reporting;
  exactKeys(reporting, ["config_sha256", "catalog_sha256", "catalog_updated_at", "configuration", "latest_reports", "indexes", "notes"]);
  intelligenceHash(reporting.config_sha256); intelligenceHash(reporting.catalog_sha256); intelligenceClock(reporting.catalog_updated_at, true); intelligenceNotes(reporting.notes);
  intelligenceConfiguration(reporting.configuration); const reports = intelligenceReports(reporting.latest_reports, reporting.indexes);
  intelligenceRevisions(value.revisions, reports);
  requireValue(new TextEncoder().encode(JSON.stringify(value)).byteLength <= 131072);
  return value;
}

function intakeCount(value, maximum) { nonnegative(value); requireValue(value <= maximum); return value; }

function selectionDate(value) {
  requireValue(typeof value === "string" && /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value) && value.slice(0, 4) !== "0000");
  const calendar = new Date(value + "T00:00:00Z");
  requireValue(Number.isFinite(calendar.getTime()) && calendar.toISOString().slice(0, 10) === value);
  return value;
}

function normalizeSelection(value, sourceId) {
  exactKeys(value, ["version", "basis", "cutoff_date"]);
  requireValue(Number.isSafeInteger(value.version) && value.version === 1 && ["document-order-v1", "publisher-date-desc-v1"].includes(value.basis));
  if (value.basis === "document-order-v1") requireValue(value.cutoff_date === null);
  else { requireValue(sourceId === "f5-labs"); selectionDate(value.cutoff_date); }
  return { version: 1, basis: value.basis, cutoff_date: value.cutoff_date };
}

function normalizeConfiguredSelection(value, sourceId, schemaVersion) {
  if (![4, 5, 6, 7].includes(schemaVersion)) { requireValue(!Object.hasOwn(value, "configured_selection")); return null; }
  requireValue(Object.hasOwn(value, "configured_selection"));
  const basis = value.configured_selection;
  if (sourceId === "cisa-kev") { requireValue(basis === null); return null; }
  requireValue(["document-order-v1", "publisher-date-desc-v1"].includes(basis));
  requireValue(basis !== "publisher-date-desc-v1" || sourceId === "f5-labs");
  return basis;
}

function normalizeIntake(value, source, schemaVersion) {
  if (source.id === "cisa-kev") { requireValue(value == null && source.status !== "partial"); return null; }
  if (value == null) { requireValue(source.status !== "partial"); return null; }
  requireValue(source.status !== "not_fetched");
  const hasSelection = Object.hasOwn(value, "selection");
  requireValue([4, 5, 6, 7].includes(schemaVersion) || !hasSelection);
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
    attempted_at: timestamp(value.attempted_at, false), response_sha256: boundedText(value.response_sha256, 64),
    selection: hasSelection ? normalizeSelection(value.selection, source.id) : null
  };
  requireValue(/^[a-f0-9]{64}$/.test(report.response_sha256) && report.attempted_at.includes("T") && report.attempted_at.length <= 40 && report.attempted_at === source.last_attempt);
  requireValue(report.items_processed === Math.min(report.items_seen, report.entry_limit) && report.items_seen === report.items_processed + report.items_unprocessed);
  requireValue(report.items_processed === report.items_admitted + report.items_rejected + report.items_filtered);
  requireValue(report.rejection_reasons.invalid_link_or_title + report.rejection_reasons.cve_limit_exceeded === report.items_rejected);
  if (source.status === "ok" || source.status === "partial") {
    requireValue(source.error === null && source.last_success !== null && source.last_success.includes("T") && source.last_success.length <= 40 && source.sha256 === report.response_sha256 && new Date(source.last_success).getTime() >= new Date(report.attempted_at).getTime());
    if (source.status === "partial") requireValue(report.items_admitted > 0 && (report.items_rejected > 0 || report.items_unprocessed > 0));
    else requireValue(report.items_rejected === 0 && report.items_unprocessed === 0);
  } else {
    // A failed window's hash belongs to this attempt, not retained last-good input.
    requireValue(source.status === "failed" && report.items_admitted === 0 && source.error !== null && source.error.trim().length > 0);
  }
  return report;
}

export function normalizeMitigation(value, key, schemaVersion) {
  requireValue(value && cvePattern.test(key) && value.cve === key && ["ok", "failed", "pending"].includes(value.source_status) && ["PUBLISHED", "REJECTED", "UNKNOWN"].includes(value.record_state));
  requireValue(value.analysis && ["known-exploited", "review"].includes(value.analysis.priority) && ["publisher-guidance", "cisa-action", "needs-review"].includes(value.analysis.guidance_status));
  const record = {
    cve: key, title: boundedText(value.title, 2000, true), description: boundedText(value.description, 100000, true),
    source_status: value.source_status, record_state: value.record_state,
    source_updated_at: timestamp(value.source_updated_at), retrieved_at: timestamp(value.retrieved_at),
    source_attempted_at: value.source_attempted_at == null ? null : timestamp(value.source_attempted_at),
    products: list(value.products, 1000).map(product => ({
      vendor: boundedText(product.vendor, 2000, true), product: boundedText(product.product, 2000, true), default_status: optionalText(product.default_status, 100),
      versions: list(product.versions, 2000).map(version => ({
        version: optionalText(version.version, 2000), status: optionalText(version.status, 100),
        less_than: optionalText(version.less_than, 2000), less_than_or_equal: optionalText(version.less_than_or_equal, 2000),
        version_type: optionalText(version.version_type, 200)
      }))
    })),
    solutions: list(value.solutions, 1000).map(item => ({ text: boundedText(item.text, 100000, true), source_url: optionalText(item.source_url, 4000) })),
    workarounds: list(value.workarounds, 1000).map(item => ({ text: boundedText(item.text, 100000, true), source_url: optionalText(item.source_url, 4000) })),
    required_action: optionalText(value.required_action, 100000),
    required_action_source_url: optionalText(value.required_action_source_url, 4000),
    kev: value.kev === null ? null : { date_added: timestamp(value.kev.date_added), due_date: timestamp(value.kev.due_date), ransomware: optionalText(value.kev.ransomware, 200) },
    cvss: null,
    references: list(value.references, 1000).map(item => ({ label: boundedText(item.label, 1000, true), url: boundedText(item.url, 4000), kind: boundedText(item.kind, 200, true) })),
    analysis: {
      priority: value.analysis.priority, guidance_status: value.analysis.guidance_status,
      assessment: boundedText(value.analysis.assessment, 20000, true),
      steps: list(value.analysis.steps, 100).map(item => ({ title: boundedText(item.title, 2000, true), detail: boundedText(item.detail, 20000, true), evidence_url: optionalText(item.evidence_url, 4000) })),
      limitations: textList(value.analysis.limitations, 100, 20000)
    }
  };
  if (value.cvss !== null) {
    requireValue(value.cvss && (value.cvss.score === null || (typeof value.cvss.score === "number" && Number.isFinite(value.cvss.score) && value.cvss.score >= 0 && value.cvss.score <= 10)));
    record.cvss = { score: value.cvss.score, version: optionalText(value.cvss.version, 100), vector: optionalText(value.cvss.vector, 2000), source_url: optionalText(value.cvss.source_url, 4000) };
  }
  if ([5, 6, 7].includes(schemaVersion)) {
    requireValue(/^CVE-[0-9]{4}-[0-9]{4,8}$/.test(key));
    exactKeys(value, ["cve", "title", "description", "source_status", "record_state", "source_updated_at", "retrieved_at", "source_attempted_at", "source_sha256", "products", "solutions", "workarounds", "cvss", "references", "required_action", "required_action_source_url", "kev", "analysis", "weaknesses", "weaknesses_status"]);
    intelligenceHash(value.source_sha256, true);
    record.source_sha256 = value.source_sha256;
    for (const field of ["source_updated_at", "retrieved_at", "source_attempted_at"]) requireValue(value[field] === null || typeof value[field] === "string" && value[field].length <= 40);
    requireValue(value.source_status !== "ok" || record.retrieved_at !== null && record.source_attempted_at !== null && record.source_sha256 !== null && record.record_state !== "UNKNOWN");
    record.weaknesses = list(value.weaknesses, 8).map(item => {
      exactKeys(item, ["id", "description", "source_url"]);
      requireValue(typeof item.id === "string" && /^CWE-[1-9][0-9]{0,5}$/.test(item.id) && item.source_url === "https://www.cve.org/CVERecord?id=" + key);
      return { id: item.id, description: intelligenceText(item.description, 200, true), source_url: item.source_url };
    });
    record.weaknesses_status = value.weaknesses_status;
    requireValue(["not_projected", "not_supplied", "supplied", "bounded"].includes(record.weaknesses_status));
    requireValue(record.weaknesses_status === "bounded" || (record.weaknesses_status === "supplied" ? record.weaknesses.length > 0 : record.weaknesses.length === 0));
    requireValue(new Set(record.weaknesses.map(item => item.id)).size === record.weaknesses.length);
  } else {
    requireValue(!Object.hasOwn(value, "weaknesses") && !Object.hasOwn(value, "weaknesses_status"));
    record.weaknesses = []; record.weaknesses_status = "not_projected";
  }
  return record;
}

// A schema 7 feed lists each CVE as one compact row; the full brief is read from data/briefs.json when needed.
function indexRecord(key, row) {
  requireValue(/^CVE-[0-9]{4}-[0-9]{4,8}$/.test(key) && Array.isArray(row) && row.length === indexFields.length);
  const [state, status, guidance, action, score, version, added, weaknesses, exploitation, epss] = row;
  requireValue(["PUBLISHED", "REJECTED", "UNKNOWN"].includes(state) && ["ok", "failed", "pending"].includes(status) && ["publisher-guidance", "cisa-action", "needs-review"].includes(guidance) && typeof action === "boolean");
  requireValue(score === null || (typeof score === "number" && Number.isFinite(score) && score >= 0 && score <= 10));
  const ids = list(weaknesses, 8).map(id => intelligenceId(id, /^CWE-[1-9][0-9]{0,5}$/)); intelligenceUnique(ids);
  return {
    cve: key, title: "", record_state: state, source_status: status, analysis: { guidance_status: guidance }, required_action_present: action,
    cvss: score === null && version === null ? null : { score, version: optionalText(version, 100) },
    kev: added === null ? null : { date_added: timestamp(added, false) }, weaknesses: ids.map(id => ({ id })), products: [],
    ssvc_exploitation: optionalText(exploitation, 100), epss: normalizeEpss(epss)
  };
}

function normalizeIndex(value) {
  exactKeys(value, ["version", "fields", "rows"]);
  requireValue(value.version === 3 && Array.isArray(value.fields) && value.fields.length === indexFields.length && value.fields.every((field, position) => field === indexFields[position]));
  requireValue(value.rows && typeof value.rows === "object" && !Array.isArray(value.rows));
  const entries = Object.entries(value.rows); requireValue(entries.length <= 15000);
  return new Map(entries.map(([key, row]) => [key, indexRecord(key, row)]));
}

// The brief fields a search reads: the CNA title, weakness identifiers and vendor and product names.
function recordTerms(record) {
  return [record.title, ...record.weaknesses.map(weakness => weakness.id), ...record.products.flatMap(product => [product.vendor, product.product])];
}

export function normalize(raw, byteLength) {
  const current = Boolean(raw) && raw.schema_version === 7;
  const modern = Boolean(raw) && [5, 6, 7].includes(raw.schema_version);
  requireValue(raw && [2, 3, 4, 5, 6, 7].includes(raw.schema_version) && Array.isArray(raw.articles) && raw.articles.length <= (current ? maximumArticles : 8000) && Array.isArray(raw.sources) && raw.sources.length <= 200);
  if (current) {
    requireValue(byteLength <= maximumFeedBytes && typeof raw.content_revision === "string" && /^[a-f0-9]{64}$/.test(raw.content_revision));
    exactKeys(raw, ["schema_version", "generated_at", "window", "articles", "sources", "history_reviewed_at", "brief_index", "mitigation_coverage", "deduplication", "refresh", "coverage", "integrations", "content_revision", "layout_revision", "intelligence"]);
  } else if (modern) exactKeys(raw, ["schema_version", "generated_at", "window", "articles", "sources", "history_reviewed_at", "mitigations", "mitigation_coverage", "deduplication", "refresh", "coverage", "integrations", "content_revision", "layout_revision", "intelligence"]);
  else requireValue(!Object.hasOwn(raw, "intelligence"));
  timestamp(raw.generated_at, false);
  requireValue(raw.window && raw.coverage && raw.integrations && raw.refresh && raw.deduplication && (current || (raw.mitigations && typeof raw.mitigations === "object" && !Array.isArray(raw.mitigations))));
  timestamp(raw.window.start, false);
  timestamp(raw.window.end, false);
  const start = new Date(raw.window.start).getTime();
  const end = new Date(raw.window.end).getTime();
  requireValue(end >= start && end - start <= (raw.schema_version >= 6 ? 14610 : raw.schema_version === 5 ? 7306 : 3661) * day);
  if (modern) { selectionDate(raw.window.start); selectionDate(raw.window.end); }
  if (raw.schema_version >= 6) requireValue(raw.window.start >= "1998-01-01");
  let mitigations;
  if (current) mitigations = normalizeIndex(raw.brief_index);
  else {
    const mitigationEntries = Object.entries(raw.mitigations);
    requireValue(mitigationEntries.length <= 15000);
    mitigations = new Map(mitigationEntries.map(([key, value]) => [key, normalizeMitigation(value, key, raw.schema_version)]));
  }
  const intelligence = modern ? normalizeIntelligence(raw.intelligence, new Set(mitigations.keys())) : null;
  const ids = new Set();
  const articles = raw.articles.map(article => {
    if (modern) exactKeys(article, ["id", "title", "url", "source_id", "source_name", "kind", "published_at", "event_date", "date_basis", "summary", "cves", "tags", "exploitation", "references", "origin"]);
    requireValue(article && Object.hasOwn(kinds, article.kind) && Object.hasOwn(origins, article.origin) && ["known", "reported", "unknown"].includes(article.exploitation));
    const item = {
      id: boundedText(article.id, 160), title: boundedText(article.title, 1000), url: boundedText(article.url, 4000),
      source_id: boundedText(article.source_id, 160), source_name: boundedText(article.source_name, 240),
      kind: article.kind, origin: article.origin, published_at: timestamp(article.published_at), event_date: timestamp(article.event_date),
      date_basis: boundedText(article.date_basis, 1000, true), summary: boundedText(article.summary, 500, true),
      cves: textList(article.cves, 100, 80), tags: textList(article.tags, 100, 160), exploitation: article.exploitation
    };
    requireValue(!ids.has(item.id) && item.cves.every(cve => cvePattern.test(cve) && mitigations.has(cve)));
    ids.add(item.id);
    item.references = list(article.references, 50).map(reference => {
      if (modern) exactKeys(reference, ["label", "url"]);
      return { label: boundedText(reference.label, 300), url: boundedText(reference.url, 4000) };
    });
    item.primary_date = item.date_basis === "event" ? item.event_date : item.published_at;
    item.date = item.primary_date === null ? null : new Date(item.primary_date);
    item.month = item.date ? item.date.toISOString().slice(0, 7) : "unknown";
    item.year = item.date ? item.date.toISOString().slice(0, 4) : "unknown";
    const records = item.cves.map(cve => mitigations.get(cve));
    const scores = records.map(record => record.cvss?.score).filter(score => typeof score === "number");
    item.score = scores.length ? Math.max(...scores) : null;
    item.cve_key = [...item.cves].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))[0] || null;
    const directContext = intelligence ? intelligence.catalog.relationships.filter(relation => item.cves.includes(relation.source_id) || item.cves.includes(relation.target_id)).flatMap(relation => [relation.summary, ...intelligence.catalog.entities.filter(entity => [relation.source_id, relation.target_id].includes(entity.id)).flatMap(entity => [entity.label, ...entity.aliases])]) : [];
    item.search = normalized([item.title, item.summary, item.source_name, item.source_id, ...item.cves, ...item.tags, ...directContext, ...records.flatMap(recordTerms)].join("\n"));
    return item;
  });
  const sourceIds = new Set();
  const sources = raw.sources.map(source => {
    if (modern) exactKeys(source, ["id", "name", "kind", "url", "status", "last_attempt", "last_success", "error", "sha256", "intake", "articles", "configured_selection"]);
    requireValue(source && ["ok", "partial", "failed", "not_fetched"].includes(source.status));
    const item = { id: boundedText(source.id, 160), name: boundedText(source.name, 240), url: boundedText(source.url, 4000), kind: boundedText(source.kind, 160), status: source.status, last_success: timestamp(source.last_success), last_attempt: timestamp(source.last_attempt), error: source.error === null ? null : boundedText(source.error, 4000, true), articles: nonnegative(source.articles) };
    item.sha256 = source.sha256 == null ? null : boundedText(source.sha256, 64);
    requireValue(item.sha256 === null || /^[a-f0-9]{64}$/.test(item.sha256));
    item.configured_selection = normalizeConfiguredSelection(source, item.id, raw.schema_version);
    item.intake = normalizeIntake(source.intake, item, raw.schema_version);
    requireValue(!sourceIds.has(item.id)); sourceIds.add(item.id); return item;
  });
  const coverage = { kev_records: nonnegative(raw.coverage.kev_records), curated_events: nonnegative(raw.coverage.curated_events), feed_articles: nonnegative(raw.coverage.feed_articles), notes: textList(raw.coverage.notes, 100, 4000) };
  const integrations = {};
  for (const key of ["xai", "x", "sec"]) {
    requireValue(raw.integrations[key]?.status === "not_connected");
    integrations[key] = { status: "not_connected", message: boundedText(raw.integrations[key].message, 4000, true) };
  }
  requireValue(Number.isSafeInteger(raw.refresh.requested_minutes) && raw.refresh.requested_minutes > 0 && raw.refresh.requested_minutes <= 1440 && raw.refresh.mode === "scheduled-check");
  const refresh = { requested_minutes: raw.refresh.requested_minutes, mode: raw.refresh.mode, status_url: boundedText(raw.refresh.status_url, 4000), notes: textList(raw.refresh.notes, 100, 4000) };
  if (modern) requireValue(new Set(articles.flatMap(article => article.cves)).size === mitigations.size);
  // Older feeds carry their briefs inline; a schema 7 feed reads them on first use.
  return { schema_version: raw.schema_version, generated_at: raw.generated_at, content_revision: current ? raw.content_revision : null, window: { start: raw.window.start, end: raw.window.end }, articles, sources, coverage, integrations, mitigations, briefs: current ? null : mitigations, briefsRequest: null, refresh, intelligence, deduplication: { url_duplicates_removed: nonnegative(raw.deduplication.url_duplicates_removed) } };
}

// The same rows, index and ledger the schema 7 views read, built from a normalized feed.
export function legacyData(snapshot) {
  const cveIndex = new Map();
  for (const [cve, record] of snapshot.mitigations) {
    cveIndex.set(cve, {
      cve, record_state: record.record_state, source_status: record.source_status,
      guidance: record.record_state === "REJECTED" ? "needs-review" : record.analysis.guidance_status,
      required_action: record.required_action_present ?? Boolean(record.required_action),
      score: record.cvss?.score ?? null, version: record.cvss?.version ?? null, kev_added: record.kev?.date_added ?? null,
      weaknesses: record.weaknesses.map(item => item.id), bucket: null,
      // The version 3 index columns the register, the chips and the EPSS sort read (null on an inline brief).
      ssvc_exploitation: record.ssvc_exploitation ?? null, epss: record.epss ?? null
    });
  }
  const rows = snapshot.articles.map(article => {
    const linked = article.cves.filter(cve => cveIndex.get(cve)?.kev_added);
    const scores = article.cves.map(cve => cveIndex.get(cve)?.score).filter(score => typeof score === "number");
    const t = { source_class: null, event_type: [], vendor: [], product: [], actor: [], malware: [], sector: [], region: [], cwe: [], attack: [], exploitation: null,
      kev: linked.length ? { cves: linked, added: cveIndex.get(linked[0]).kev_added, due: null, ransomware: null, at_publication: false } : null,
      cvss: scores.length ? { base: Math.max(...scores), version: null, vector: null, scorer: null, cve: null } : null };
    return derive({ id: article.id, title: article.title, url: article.url, source_id: article.source_id, source_name: article.source_name, kind: article.kind,
      origin: article.origin, published_at: article.published_at, event_date: article.event_date, date_basis: article.date_basis, summary: article.summary,
      exploitation: article.exploitation, cves: article.cves, tags: article.tags, native_id: null, references: article.references, t });
  });
  return { rows, cveIndex, sources: snapshot.sources, briefs: snapshot.briefs, window: snapshot.window, generated_at: snapshot.generated_at, intelligence: snapshot.intelligence };
}
