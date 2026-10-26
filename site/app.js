"use strict";

(() => {
  const $ = selector => document.querySelector(selector);
  const kinds = { advisory: "ADVISORY", research: "RESEARCH", reporting: "REPORTING", incident: "INCIDENT", kev: "CISA KEV", filing: "SEC FILING" };
  const origins = { "publisher-feed": "PUBLISHER FEED", "cisa-kev": "CATALOG RECORD", "library-curation": "CURATED ARCHIVE" };
  const guidanceLabels = { "publisher-guidance": "Publisher guidance", "cisa-action": "CISA action", "needs-review": "Needs review", unavailable: "Source failed / pending" };
  const day = 86400000;
  const pollInterval = 600000;
  const pageSize = 24;
  const maximumFeedBytes = 16 * 1024 * 1024;
  const workflowApi = "https://api.github.com/repos/TeamStarWolf/intelligence-hub/actions/workflows/395429963/runs";
  const workflowQueries = { recent: workflowApi + "?branch=main&per_page=10", schedule: workflowApi + "?event=schedule&branch=main&per_page=1" };
  const maximumWorkflowBytes = 512 * 1024;
  const workflowEvents = { workflow_dispatch: "Manual dispatch", push: "Push", schedule: "Automatic schedule" };
  const workflowStatuses = { queued: "Queued", in_progress: "In progress", waiting: "Waiting", requested: "Requested", pending: "Pending", completed: "Completed" };
  const workflowConclusions = { success: "Success", failure: "Failure", neutral: "Neutral", cancelled: "Cancelled", skipped: "Skipped", timed_out: "Timed out", action_required: "Action required", stale: "Stale", startup_failure: "Startup failure" };
  const cvePattern = /^CVE-\d{4}-\d{4,19}$/;
  const controls = Object.fromEntries(["search", "kind", "source", "exploitation", "mitigation", "year", "month", "preset", "sort"].map(key => [key, $("#" + key)]));
  let snapshot = null;
  let snapshotText = null;
  let visibleCount = pageSize;
  let view = "feed";
  let loading = false;
  let searchTimer = null;
  let lastAttempt = null;
  let lastRead = null;
  let lastWorkflowAttempt = null;
  let lastWorkflowAttemptTick = null;
  let workflowController = null;
  const workflowObservations = Object.fromEntries(["recent", "schedule"].map(key => [key, { value: null, read_at: null, attempted_at: null, error: null }]));

  function node(tag, className = "", text = "") {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== "") element.textContent = String(text);
    return element;
  }

  function requireValue(condition) {
    if (!condition) throw new Error("The saved feed does not match the supported snapshot format.");
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

  function normalizeIntelligence(value, admitted) {
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
    if (![4, 5, 6].includes(schemaVersion)) { requireValue(!Object.hasOwn(value, "configured_selection")); return null; }
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
    requireValue([4, 5, 6].includes(schemaVersion) || !hasSelection);
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

  function normalizeMitigation(value, key, schemaVersion) {
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
    if ([5, 6].includes(schemaVersion)) {
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

  function normalize(raw) {
    requireValue(raw && [2, 3, 4, 5, 6].includes(raw.schema_version) && Array.isArray(raw.articles) && raw.articles.length <= 8000 && Array.isArray(raw.sources) && raw.sources.length <= 200);
    if ([5, 6].includes(raw.schema_version)) exactKeys(raw, ["schema_version", "generated_at", "window", "articles", "sources", "history_reviewed_at", "mitigations", "mitigation_coverage", "deduplication", "refresh", "coverage", "integrations", "content_revision", "layout_revision", "intelligence"]);
    else requireValue(!Object.hasOwn(raw, "intelligence"));
    timestamp(raw.generated_at, false);
    requireValue(raw.window && raw.coverage && raw.integrations && raw.refresh && raw.deduplication && raw.mitigations && typeof raw.mitigations === "object" && !Array.isArray(raw.mitigations));
    timestamp(raw.window.start, false);
    timestamp(raw.window.end, false);
    const start = new Date(raw.window.start).getTime();
    const end = new Date(raw.window.end).getTime();
    requireValue(end >= start && end - start <= (raw.schema_version === 6 ? 14610 : raw.schema_version === 5 ? 7306 : 3661) * day);
    if ([5, 6].includes(raw.schema_version)) { selectionDate(raw.window.start); selectionDate(raw.window.end); }
    if (raw.schema_version === 6) requireValue(raw.window.start >= "1998-01-01");
    const mitigationEntries = Object.entries(raw.mitigations);
    requireValue(mitigationEntries.length <= 15000);
    const mitigations = new Map(mitigationEntries.map(([key, value]) => [key, normalizeMitigation(value, key, raw.schema_version)]));
    const intelligence = [5, 6].includes(raw.schema_version) ? normalizeIntelligence(raw.intelligence, new Set(mitigations.keys())) : null;
    const ids = new Set();
    const articles = raw.articles.map(article => {
      if ([5, 6].includes(raw.schema_version)) exactKeys(article, ["id", "title", "url", "source_id", "source_name", "kind", "published_at", "event_date", "date_basis", "summary", "cves", "tags", "exploitation", "references", "origin"]);
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
        if ([5, 6].includes(raw.schema_version)) exactKeys(reference, ["label", "url"]);
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
      item.search = normalized([item.title, item.summary, item.source_name, item.source_id, ...item.cves, ...item.tags, ...directContext, ...records.flatMap(record => [record.title, ...record.weaknesses.map(weakness => weakness.id), ...record.products.flatMap(product => [product.vendor, product.product])])].join("\n"));
      return item;
    });
    const sourceIds = new Set();
    const sources = raw.sources.map(source => {
      if ([5, 6].includes(raw.schema_version)) exactKeys(source, ["id", "name", "kind", "url", "status", "last_attempt", "last_success", "error", "sha256", "intake", "articles", "configured_selection"]);
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
    if ([5, 6].includes(raw.schema_version)) requireValue(new Set(articles.flatMap(article => article.cves)).size === mitigations.size);
    return { generated_at: raw.generated_at, window: { start: raw.window.start, end: raw.window.end }, articles, sources, coverage, integrations, mitigations, refresh, intelligence, deduplication: { url_duplicates_removed: nonnegative(raw.deduplication.url_duplicates_removed) } };
  }

  function safeUrl(value) {
    try {
      if (typeof value !== "string" || value.length > 4000 || /[\u0000-\u0020\u007f\\]/.test(value)) return null;
      const url = new URL(value);
      const host = url.hostname.toLowerCase().replace(/\.$/, "");
      if (url.protocol !== "https:" || url.username || url.password || url.port || !host || !host.includes(".") || host.startsWith("[") || /^(?:\d+\.)*\d+$/.test(host) || host === "localhost" || /\.(?:localhost|local|localdomain|internal|lan|home|home\.arpa|test|invalid|example)$/.test(host)) return null;
      return url.href;
    } catch (_) { return null; }
  }

  function link(label, value, className = "") {
    const url = safeUrl(value);
    if (!url) return node("span", className, label);
    const anchor = node("a", className, label);
    anchor.href = url; anchor.target = "_blank"; anchor.rel = "noopener noreferrer nofollow"; anchor.referrerPolicy = "no-referrer";
    return anchor;
  }

  function dateLabel(value, full = false) {
    return value ? new Date(value).toLocaleDateString(undefined, { day: "numeric", month: full ? "long" : "short", year: "numeric", timeZone: "UTC" }) : "Not recorded";
  }
  function stamp(value) {
    return value ? new Date(value).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" }) : "Not recorded";
  }
  function monthLabel(value) { return value === "unknown" ? "Date unknown" : new Date(value + "-01T00:00:00Z").toLocaleDateString(undefined, { month: "short", year: "numeric", timeZone: "UTC" }); }

  function calendarMonths() {
    const cursor = new Date(snapshot.window.start.slice(0, 7) + "-01T00:00:00Z");
    const end = snapshot.window.end.slice(0, 7);
    const months = [];
    while (cursor.toISOString().slice(0, 7) <= end) { months.push(cursor.toISOString().slice(0, 7)); cursor.setUTCMonth(cursor.getUTCMonth() + 1); }
    return months;
  }

  function replaceOptions(select, choices, allLabel) {
    const previous = select.value;
    const oldLabel = (select.selectedOptions[0]?.textContent || previous).replace(/ · absent from this snapshot$/, "");
    if (previous && !choices.some(choice => choice.value === previous)) choices.push({ value: previous, label: oldLabel + " · absent from this snapshot" });
    select.replaceChildren(new Option(allLabel, ""), ...choices.map(choice => new Option(choice.label, choice.value)));
    select.value = previous;
  }

  function configureFilters() {
    const sources = new Map(snapshot.sources.map(source => [source.id, source.name]));
    for (const article of snapshot.articles) if (!sources.has(article.source_id)) sources.set(article.source_id, article.source_name);
    replaceOptions(controls.source, [...sources].sort((a, b) => a[1].localeCompare(b[1])).map(([value, label]) => ({ value, label })), "All sources");
    const months = calendarMonths().map(value => ({ value, label: monthLabel(value) }));
    const years = [...new Set(calendarMonths().map(value => value.slice(0, 4)))].map(value => ({ value, label: value }));
    if (snapshot.articles.some(article => !article.date)) { months.push({ value: "unknown", label: "Date unknown" }); years.push({ value: "unknown", label: "Date unknown" }); }
    replaceOptions(controls.month, months, "All months"); replaceOptions(controls.year, years, "All years");
  }

  function guidanceStatus(record) {
    return record.record_state === "REJECTED" ? "needs-review" : record.analysis.guidance_status;
  }

  function recordMatches(record) {
    if (controls.mitigation.value === "unavailable") return record.source_status !== "ok";
    return !controls.mitigation.value || guidanceStatus(record) === controls.mitigation.value;
  }

  function matches(article, ignoreDates = false) {
    const terms = normalized(controls.search.value.trim()).split(/\s+/).filter(Boolean);
    if (!terms.every(term => article.search.includes(term)) || (controls.kind.value && controls.kind.value !== article.kind) || (controls.source.value && controls.source.value !== article.source_id) || (controls.exploitation.value && controls.exploitation.value !== article.exploitation)) return false;
    if (controls.mitigation.value === "no-cve" ? article.cves.length > 0 : controls.mitigation.value && !article.cves.some(cve => recordMatches(snapshot.mitigations.get(cve)))) return false;
    if (ignoreDates) return true;
    if ((controls.year.value && article.year !== controls.year.value) || (controls.month.value && article.month !== controls.month.value)) return false;
    const days = { day: 1, week: 7, month: 30, year: 365 }[controls.preset.value];
    if (days) {
      const last = new Date(snapshot.window.end.slice(0, 10) + "T00:00:00Z").getTime();
      return article.date !== null && article.date.getTime() >= last - (days - 1) * day && article.date.getTime() < last + day;
    }
    return true;
  }

  function setDates(year = "", month = "") {
    controls.year.value = year; controls.month.value = month; controls.preset.value = "full"; visibleCount = pageSize; render();
  }

  function timelineButton(label, count, selected, focusKey, action, className) {
    const button = node("button", className + (selected ? " selected" : "") + (count ? "" : " empty-month"));
    button.type = "button"; button.setAttribute("aria-pressed", String(selected)); button.dataset.focusKey = focusKey;
    button.setAttribute("aria-label", label + ": " + count.toLocaleString() + " entries matching non-date filters. Filter by this date.");
    button.append(node("span", "month-name", label), node("span", "month-count", count.toLocaleString()));
    button.addEventListener("click", action); return button;
  }

  function renderTimeline() {
    const candidates = snapshot.articles.filter(article => matches(article, true));
    const years = new Map(); const months = new Map();
    for (const article of candidates) { years.set(article.year, (years.get(article.year) || 0) + 1); months.set(article.month, (months.get(article.month) || 0) + 1); }
    const allYears = [...new Set(calendarMonths().map(month => month.slice(0, 4)))];
    const yearButtons = [timelineButton("All history", candidates.length, !controls.year.value && !controls.month.value && controls.preset.value === "full", "year-all", () => setDates(), "year-button")];
    for (const year of allYears) {
      const button = timelineButton(year, years.get(year) || 0, controls.year.value === year, "year-" + year, () => setDates(controls.year.value === year ? "" : year), "year-button");
      if (year === snapshot.window.start.slice(0, 4) || year === snapshot.window.end.slice(0, 4)) button.title = "The archive boundary may cover only part of this calendar year.";
      yearButtons.push(button);
    }
    if (snapshot.articles.some(article => !article.date)) yearButtons.push(timelineButton("Unknown date", years.get("unknown") || 0, controls.year.value === "unknown", "year-unknown", () => setDates("unknown", "unknown"), "year-button"));
    $("#year-timeline").replaceChildren(...yearButtons);
    const shortcutYear = controls.year.value && controls.year.value !== "unknown" ? controls.year.value : snapshot.window.end.slice(0, 4);
    $("#month-context").textContent = controls.year.value === "unknown" ? "Unknown primary dates selected" : "Month shortcuts · " + shortcutYear + (controls.year.value ? "" : " · choose a year above for older months");
    const monthButtons = controls.year.value === "unknown" ? [] : calendarMonths().filter(month => month.startsWith(shortcutYear + "-")).map(month => {
      const button = timelineButton(new Date(month + "-01T00:00:00Z").toLocaleDateString(undefined, { month: "short", timeZone: "UTC" }), months.get(month) || 0, controls.month.value === month, "month-" + month, () => setDates(month.slice(0, 4), controls.month.value === month ? "" : month), "month-button");
      button.setAttribute("aria-label", monthLabel(month) + ": " + (months.get(month) || 0).toLocaleString() + " entries matching non-date filters. Filter by this month.");
      const lastDay = new Date(Date.UTC(Number(month.slice(0, 4)), Number(month.slice(5)), 0)).getUTCDate();
      if ((month === snapshot.window.start.slice(0, 7) && snapshot.window.start.slice(8, 10) !== "01") || (month === snapshot.window.end.slice(0, 7) && Number(snapshot.window.end.slice(8, 10)) !== lastDay)) { button.classList.add("partial"); button.title = "Partial month within the archive window."; }
      return button;
    });
    $("#month-timeline").replaceChildren(...monthButtons);
    const presetDays = { day: 1, week: 7, month: 30, year: 365 }[controls.preset.value];
    $("#date-filter-note").textContent = presetDays ? "Preset: " + presetDays + " calendar day" + (presetDays === 1 ? "" : "s") + " ending " + dateLabel(snapshot.window.end) + " UTC; unknown primary dates excluded." : "Archive: " + dateLabel(snapshot.window.start) + " — " + dateLabel(snapshot.window.end) + ". Year/month filters use primary dates; unknown dates remain explicit.";
  }

  function cveButton(cve, focusKey) {
    const button = node("button", "article-tag cve-tag", cve);
    button.type = "button"; button.dataset.focusKey = focusKey; button.setAttribute("aria-label", "Inspect source-led guidance for " + cve);
    button.addEventListener("click", () => openMitigation(cve)); return button;
  }

  function scoreLabel(record) {
    return typeof record.cvss?.score === "number" ? record.cvss.score.toFixed(1) + " · CVSS " + (record.cvss.version || "version unknown") : "CVSS unknown";
  }

  function kevCatalogNote(article) {
    if (article.origin === "cisa-kev") return "";
    const matches = article.cves.flatMap(cve => {
      const kev = snapshot.mitigations.get(cve)?.kev;
      return kev ? [{ cve, kev }] : [];
    });
    if (!matches.length) return "";
    const shown = matches.slice(0, 3).map(item => item.cve + (matches.length === 1 && item.kev.date_added ? " (catalog added " + dateLabel(item.kev.date_added) + ")" : ""));
    const extra = matches.length > 3 ? " +" + (matches.length - 3).toLocaleString() + " more" : "";
    return "CISA KEV catalog includes " + shown.join(", ") + extra + ". That match is separate from this entry's exploitation label.";
  }

  function articleCard(article, openDetails) {
    const card = node("article", "article-card card-kind-" + article.kind + (article.exploitation === "known" ? " card-known-exploitation" : "")); card.dataset.entryId = article.id;
    const top = node("div", "article-topline");
    const date = node("div", "article-date", article.date ? dateLabel(article.primary_date) : "Date unknown");
    date.append(node("span", "", !article.date ? "UNKNOWN" : article.date_basis === "event" ? "EVENT DATE" : article.date_basis === "filing" ? "FILED" : article.kind === "kev" ? "CATALOG ADDED" : article.date_basis === "publisher update" ? "UPDATED" : "PUBLISHED"));
    top.append(node("span", "kind-badge kind-" + article.kind, kinds[article.kind]), date);
    const title = node("h3"); const titleLink = link(article.title, article.url, "article-title"); titleLink.dataset.focusKey = article.id + "-title"; title.append(titleLink);
    card.append(top, title); if (article.summary) card.append(node("p", "article-summary", article.summary));
    const tags = node("div", "article-tags");
    for (const cve of article.cves.slice(0, 6)) tags.append(cveButton(cve, article.id + "-" + cve));
    for (const tag of article.tags.slice(0, 3)) tags.append(node("span", "article-tag", tag));
    if (tags.children.length) card.append(tags);
    if (article.cves.length) {
      const counts = new Map();
      for (const cve of article.cves) { const status = guidanceStatus(snapshot.mitigations.get(cve)); counts.set(status, (counts.get(status) || 0) + 1); }
      const guidance = node("div", "guidance-summary", [...counts].map(([status, count]) => count + " " + guidanceLabels[status].toLocaleLowerCase()).join(" / "));
      const incomplete = article.cves.filter(cve => snapshot.mitigations.get(cve).source_status !== "ok").length;
      if (incomplete) guidance.append(node("span", "row-secondary", incomplete + " CNA lookup" + (incomplete === 1 ? "" : "s") + " pending / failed; CISA actions shown separately."));
      if (article.score !== null) {
        const record = article.cves.map(cve => snapshot.mitigations.get(cve)).find(item => item.cvss?.score === article.score);
        guidance.append(node("span", "score-summary", scoreLabel(record) + (article.cves.length > 1 ? " · highest linked score" : "")));
      }
      card.append(guidance);
    } else card.append(node("p", "guidance-summary", "No CVE linked in this entry."));
    const bottom = node("div", "article-bottom");
    const source = node("div", "article-source"); source.append(node("span", "", article.source_name), node("span", "article-origin", origins[article.origin]));
    const exploitation = { known: "Known exploitation recorded by the source", reported: "Exploitation reported; read the source context", unknown: "Exploitation status unknown in this entry" }[article.exploitation];
    bottom.append(source, node("p", "exploitation exploitation-" + article.exploitation, exploitation));
    const catalogNote = kevCatalogNote(article);
    if (catalogNote) bottom.append(node("p", "kev-catalog-note", catalogNote));
    const detail = node("details", "article-detail"); detail.open = openDetails.has(article.id);
    const summary = node("summary", "", "Sources & date context" + (article.cves.length > 6 ? " · all " + article.cves.length + " CVEs" : "")); summary.dataset.focusKey = article.id + "-details";
    detail.append(summary, node("p", "", "Date basis: " + (article.date_basis || "Not specified.")), node("p", "", (article.date_basis === "filing" ? "SEC filing date: " : article.kind === "kev" ? "Catalog addition date: " : article.date_basis === "publisher update" ? "Publisher update date: " : "Publisher date: ") + dateLabel(article.published_at)), node("p", "", "Event date: " + dateLabel(article.event_date)));
    if (article.cves.length > 6) { const allCves = node("div", "article-tags"); for (const cve of article.cves) allCves.append(cveButton(cve, article.id + "-all-" + cve)); detail.append(allCves); }
    if (article.tags.length > 3) detail.append(node("p", "", "All topic tags: " + article.tags.join(", ")));
    if (article.kind === "kev") detail.append(node("p", "", "CISA catalog addition is separate from disclosure and exploitation dates. This entry is not an incident report."));
    if (article.kind === "filing") detail.append(node("p", "", "This selected SEC cyber-related filing is a disclosure record. Its filing date is not the incident date; not every Form 8-K concerns a cyber incident."));
    const references = node("ul"); const original = node("li"); const originalLink = link("Original publisher record ↗", article.url); originalLink.dataset.focusKey = article.id + "-original"; original.append(originalLink); references.append(original);
    for (const reference of article.references) { const item = node("li"); const referenceLink = link(reference.label + " ↗", reference.url); referenceLink.dataset.focusKey = article.id + "-reference-" + reference.url; item.append(referenceLink); references.append(item); }
    detail.append(references); bottom.append(detail); card.append(bottom); return card;
  }

  function compareNullable(a, b, direction, numeric = false) {
    if (a === null && b !== null) return 1;
    if (a !== null && b === null) return -1;
    if (a === null && b === null) return 0;
    return (numeric ? a - b : a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" })) * direction;
  }

  function sortRows(rows) {
    const [key, order] = controls.sort.value.split("-");
    const direction = order === "desc" ? -1 : 1;
    return rows.sort((a, b) => {
      let result = 0;
      if (key === "date") result = compareNullable(a.date?.getTime() ?? null, b.date?.getTime() ?? null, direction, true);
      else if (key === "cvss") result = compareNullable(a.score, b.score, direction, true);
      else if (key === "cve") result = compareNullable(a.cve_key, b.cve_key, direction);
      else if (key === "title") result = a.title.localeCompare(b.title) * direction;
      else if (key === "source") result = a.source_name.localeCompare(b.source_name) * direction;
      return result || a.title.localeCompare(b.title) || a.id.localeCompare(b.id);
    });
  }

  function cveRows(articles) {
    const grouped = new Map();
    for (const article of articles) for (const cve of new Set(article.cves)) {
      const record = snapshot.mitigations.get(cve);
      if (!recordMatches(record)) continue;
      if (!grouped.has(cve)) grouped.set(cve, { id: cve, cve_key: cve, record, title: record.title || cve, score: record.cvss?.score ?? null, date: null, sources: new Set(), count: 0 });
      const row = grouped.get(cve); row.count++; row.sources.add(article.source_name);
      if (article.date && (!row.date || article.date > row.date)) row.date = article.date;
    }
    return [...grouped.values()].map(row => ({ ...row, source_name: [...row.sources].sort().join(", ") }));
  }

  function renderCveRegister(rows) {
    const table = node("table", "cve-table");
    const caption = node("caption", "", "Unique CVEs linked by matching entries. The guidance filter also applies per CVE. Entry date is the latest matching entry date; CVSS versions are not normalized.");
    const head = node("thead"); const headings = node("tr");
    for (const label of ["CVE / source record", "Guidance", "CVSS / version", "Matching context"]) { const cell = node("th", "", label); cell.scope = "col"; headings.append(cell); }
    head.append(headings); const body = node("tbody");
    for (const row of rows) {
      const tr = node("tr");
      const identity = node("td"); identity.append(cveButton(row.id, "register-" + row.id), node("p", "cve-row-title", row.title));
      if (row.record.record_state !== "PUBLISHED") identity.append(node("span", "record-state", row.record.record_state + " record"));
      const status = node("td"); status.append(node("span", "guidance-badge guidance-" + guidanceStatus(row.record), guidanceLabels[guidanceStatus(row.record)]));
      if (row.record.source_status !== "ok") status.append(node("span", "row-secondary", "CNA lookup: " + row.record.source_status));
      if (row.record.kev) status.append(node("span", "row-secondary", "CISA KEV catalog match"));
      const score = node("td", "cve-score", scoreLabel(row.record));
      const context = node("td"); context.append(node("span", "", row.count + " matching entr" + (row.count === 1 ? "y" : "ies")), node("span", "row-secondary", row.source_name), node("span", "row-secondary", row.date ? "Entry date: " + dateLabel(row.date.toISOString()) : "Entry date unknown"));
      tr.append(identity, status, score, context); body.append(tr);
    }
    table.append(caption, head, body); $("#cve-register").replaceChildren(table);
  }

  function renderStats(articles) {
    const counts = items => ({ exploited: items.filter(item => item.exploitation === "known").length, sources: new Set(items.map(item => item.source_id)).size, cves: new Set(items.flatMap(item => item.cves)).size });
    const filtered = counts(articles); const totals = counts(snapshot.articles);
    for (const [key, value, total] of [["matches", articles.length, snapshot.articles.length], ["exploited", filtered.exploited, totals.exploited], ["cves", filtered.cves, totals.cves], ["sources", filtered.sources, totals.sources]]) {
      $("#count-" + key).textContent = value.toLocaleString(); $("#total-" + key).textContent = "of " + total.toLocaleString() + " in the whole snapshot";
    }
  }

  function render() {
    if (!snapshot) return;
    const focusedKey = document.activeElement?.dataset.focusKey;
    const timelineScroll = { years: $("#year-timeline").scrollLeft, months: $("#month-timeline").scrollLeft };
    const articles = snapshot.articles.filter(article => matches(article));
    renderStats(articles); renderTimeline();
    const rows = sortRows(view === "cves" ? cveRows(articles) : articles);
    const visible = rows.slice(0, visibleCount);
    const openDetails = new Set([...document.querySelectorAll(".article-card")].filter(card => card.querySelector("details")?.open).map(card => card.dataset.entryId));
    $("#articles").hidden = view !== "feed"; $("#cve-register").hidden = view !== "cves";
    if (view === "feed") $("#articles").replaceChildren(...visible.map(article => articleCard(article, openDetails)));
    else renderCveRegister(visible);
    $("#view-feed").setAttribute("aria-pressed", String(view === "feed")); $("#view-cves").setAttribute("aria-pressed", String(view === "cves"));
    $("#view-note").textContent = view === "feed" ? "Original stories and advisory records" : "Unique CVEs in matching entries · guidance is not exposure confirmation";
    $("#results-status").textContent = articles.length.toLocaleString() + " matching entries / " + snapshot.articles.length.toLocaleString() + " total" + (view === "cves" ? " · " + rows.length.toLocaleString() + " matching CVEs" : "");
    $("#empty-state").hidden = rows.length > 0;
    $("#empty-title").textContent = !snapshot.articles.length ? "This snapshot has no entries yet" : view === "cves" ? "No linked CVEs match" : "No matching intelligence";
    $("#empty-message").textContent = !snapshot.articles.length ? "Inspect the source ledger for collection outcomes, then read a later snapshot." : view === "cves" && articles.length ? "Matching stories may have no CVE identifier, or their CVEs do not match the guidance filter. The intelligence stream still contains these stories." : "Broaden the search or clear a date, source, exploitation or guidance filter. Source collection gaps remain in the ledger.";
    $("#empty-reset").hidden = !snapshot.articles.length;
    $("#load-more").hidden = visible.length >= rows.length;
    $("#load-more").textContent = "Load " + Math.min(pageSize, rows.length - visible.length) + " more " + (view === "cves" ? "CVEs" : "entries") + " +";
    const undated = articles.filter(article => !article.date).length;
    $("#page-status").textContent = "Showing " + visible.length.toLocaleString() + " / " + rows.length.toLocaleString() + (view === "cves" ? " CVEs" : " entries") + " · " + undated.toLocaleString() + " matching entries have unknown dates · Unknown sort values last";
    $("#year-timeline").scrollLeft = timelineScroll.years; $("#month-timeline").scrollLeft = timelineScroll.months;
    if (focusedKey) [...document.querySelectorAll("[data-focus-key]")].find(element => element.dataset.focusKey === focusedKey)?.focus({ preventScroll: true });
  }

  function selectionName(basis) {
    return basis === "document-order-v1" ? "Document order" : "Publisher date ranking (F5)";
  }

  function selectionDescription(selection) {
    if (selection === null) return "Not recorded";
    return selectionName(selection.basis) + (selection.cutoff_date === null ? "" : " · Declared cutoff: " + selection.cutoff_date);
  }

  function renderSources() {
    $("#source-dialog-stamp").textContent = "Snapshot generated " + stamp(snapshot.generated_at) + ". Attempt dates, last accepted input and recorded response entry windows are separate. None establishes exhaustive publisher coverage.";
    $("#source-ledger").replaceChildren(...snapshot.sources.map(source => {
      const card = node("article", "ledger-source"); const heading = node("div", "ledger-source-heading");
      const title = node("h3"); title.append(link(source.name, source.url));
      const states = { ok: "INPUT ACCEPTED", partial: "PARTIAL INPUT", failed: "FETCH / INTAKE FAILED", not_fetched: "NOT FETCHED" };
      const statusClass = { ok: "", partial: " partial", failed: " failed", not_fetched: " not-fetched" }[source.status];
      heading.append(title, node("span", "source-status" + statusClass, states[source.status]));
      card.append(heading, node("p", "", source.kind + " · Saved entry count: " + source.articles.toLocaleString() + " (separate from this response's admissions)"), node("p", "", "Last accepted input: " + stamp(source.last_success)), node("p", "", "Last attempt: " + stamp(source.last_attempt)));
      if (source.id !== "cisa-kev") {
        const recorded = source.intake?.selection ?? null;
        const accepted = ["ok", "partial"].includes(source.status) && recorded !== null && source.sha256 === source.intake.response_sha256 ? recorded : null;
        card.append(node("p", "", "Configured selection: " + (source.configured_selection === null ? "Not recorded" : selectionName(source.configured_selection))),
          node("p", "", "Recorded response selection: " + selectionDescription(recorded)),
          node("p", "", "Last accepted response-window selection: " + (accepted === null ? "Unknown" : selectionDescription(accepted))));
      }
      if (source.intake) card.append(renderIntake(source));
      else card.append(node("p", "source-window-unknown", source.id === "cisa-kev" ? "Separate KEV catalog input; RSS entry-window counts are not applicable." : "Item-window counts were not supplied for this observation. Missing or legacy reports do not establish complete intake."));
      if (source.error) card.append(node("p", "source-error", source.error)); return card;
    }));
    if (!snapshot.sources.length) $("#source-ledger").append(node("p", "ledger-empty", "No source-fetch records were supplied. Publisher labels do not establish collection health."));
  }

  function renderIntake(source) {
    const report = source.intake;
    const block = node("section", "source-intake");
    block.append(node("h4", "", "Recorded response entry window"));
    const counts = node("dl", "intake-counts");
    for (const [label, key] of [["Seen", "items_seen"], ["Processed", "items_processed"], ["Admitted", "items_admitted"], ["Rejected", "items_rejected"], ["Filtered", "items_filtered"], ["Unprocessed", "items_unprocessed"]]) {
      const item = node("div"); item.append(node("dt", "", label), node("dd", "", report[key].toLocaleString())); counts.append(item);
    }
    block.append(counts, node("p", "", "Window attempted: " + stamp(report.attempted_at) + " · Entry limit: " + report.entry_limit + " · CVE limit per article: " + report.cve_limit));
    if (report.selection?.basis === "publisher-date-desc-v1") block.append(node("p", "", "Supported publisher dates through the declared cutoff rank first; unknown dates, then future dates, use document order. The calendar cutoff is not a confirmed publication time or a freshness guarantee."));
    const reasons = node("ul", "intake-reasons");
    reasons.append(node("li", "", "Invalid / missing HTTPS publisher link or title: " + report.rejection_reasons.invalid_link_or_title.toLocaleString()), node("li", "", "More than " + report.cve_limit + " unique CVE mentions: " + report.rejection_reasons.cve_limit_exceeded.toLocaleString()));
    block.append(reasons, node("p", "intake-hash", "Current response SHA-256: " + report.response_sha256));
    const outcome = source.status === "partial" ? "Some entries were admitted from this response; rejected or unprocessed entries make this intake partial." : source.status === "failed" ? "No entries were admitted from this response; its report hash is separate from any retained last-good input." : "No rejected or unprocessed entries are reported in this response window.";
    block.append(node("p", "intake-boundary", outcome + " Unprocessed entries are outside this selection window and may include recent items. Counts describe the received window, not unique saved URLs or the publisher's archive. Selection does not guarantee the latest 150 valid articles. Filtered entries are intentional exclusions, not errors. Entire rejected entries are excluded without clipping CVEs; older versions may remain in saved history under different policies. The hash identifies response bytes, not a publisher signature."));
    return block;
  }

  function section(title) { const item = node("section", "mitigation-section"); item.append(node("h3", "", title)); return item; }

  function guidanceItems(title, values) {
    const item = section(title);
    if (!values.length) item.append(node("p", "muted", "No " + title.toLocaleLowerCase() + " supplied by this saved source record. Absence is not evidence that none exist."));
    if (values.length) item.append(node("p", "muted", "Bounded source excerpts; consult the original guidance for complete conditions."));
    for (const value of values) { const block = node("div", "guidance-item"); block.append(node("p", "", value.text || "Source text not supplied.")); if (value.source_url) block.append(link("Original guidance ↗", value.source_url)); item.append(block); }
    return item;
  }

  function linkedCoverage(cve, savedSnapshot) {
    const item = section("Linked coverage in this snapshot");
    item.append(node("p", "muted", "Saved entries mentioning this exact CVE, across all entries in this dialog's snapshot and independently of stream filters. A shared identifier does not establish independent confirmation, separate incidents or exploitation of every mentioned CVE."));
    const entries = savedSnapshot.articles.filter(article => article.cves.includes(cve)).sort((a, b) =>
      compareNullable(a.date?.getTime() ?? null, b.date?.getTime() ?? null, -1, true) || a.id.localeCompare(b.id));
    const sourceCount = new Set(entries.map(article => article.source_id)).size;
    const count = node("p", "linked-coverage-count");
    count.setAttribute("role", "status"); count.setAttribute("aria-live", "polite");
    const list = node("ol", "linked-coverage-list");
    const more = node("button", "linked-coverage-more"); more.type = "button";
    let shown = 0;
    function appendEntries() {
      const moveFocus = document.activeElement === more;
      const fragment = document.createDocumentFragment();
      let firstNew = null;
      for (const article of entries.slice(shown, shown + 10)) {
        const entry = node("li", "linked-coverage-entry"); entry.tabIndex = -1;
        entry.append(link(article.title, article.url, "linked-coverage-title"), node("p", "linked-coverage-meta", article.source_name + " · " + kinds[article.kind] + " · " + origins[article.origin]));
        const basis = article.date_basis === "event" ? "Event date" : article.kind === "filing" ? "Filing date" : article.kind === "kev" ? "CISA catalog added" : article.date_basis === "publisher update" ? "Publisher updated" : "Publisher date";
        entry.append(node("p", "linked-coverage-date", article.date ? basis + ": " + dateLabel(article.primary_date) + " UTC" : "Primary date unknown"));
        if (article.kind === "kev") entry.append(node("p", "linked-coverage-meta", "Catalog entry; addition is separate from disclosure and exploitation dates."));
        if (!firstNew) firstNew = entry;
        fragment.append(entry);
      }
      shown = Math.min(shown + 10, entries.length); list.append(fragment);
      count.textContent = "Showing " + shown.toLocaleString() + " of " + entries.length.toLocaleString() + " saved entries from " + sourceCount.toLocaleString() + " recorded source" + (sourceCount === 1 ? "" : "s") + ". Latest primary entry dates first; unknown dates last.";
      more.hidden = shown >= entries.length;
      more.textContent = "Load " + Math.min(10, entries.length - shown) + " more saved entries";
      if (moveFocus && firstNew) (firstNew.querySelector("a") || firstNew).focus({ preventScroll: true });
    }
    more.addEventListener("click", appendEntries);
    item.append(count, list, more); appendEntries();
    if (!entries.length) item.append(node("p", "muted", "No linked entries are available in this saved snapshot. This does not establish that reporting or exploitation is absent."));
    return item;
  }

  function contextClock(value) {
    return value === null ? "Not supplied" : value.includes("T") ? stamp(value) : value + " (date only; time unspecified)";
  }

  function evidenceList(rows) {
    const result = node("ul", "record-limitations");
    for (const evidence of rows) {
      const item = node("li");
      item.append(link(evidence.publisher + " ↗", evidence.source_url), node("p", "", evidence.claim),
        node("p", "muted", "Published: " + contextClock(evidence.published_at) + " · Updated: " + contextClock(evidence.updated_at) + " · Event: " + contextClock(evidence.event_at)),
        node("p", "muted", "Source observed: " + stamp(evidence.observed_at) + " · Source version: " + (evidence.source_version || "Not supplied")));
      result.append(item);
    }
    return result;
  }

  function relationCard(relation, catalog) {
    const labels = new Map(catalog.entities.map(entity => [entity.id, entity.label]));
    const item = node("details", "product-record");
    item.append(node("summary", "", (labels.get(relation.source_id) || relation.source_id) + " → " + (labels.get(relation.target_id) || relation.target_id) + " · " + relation.relation.replaceAll("_", " ")),
      node("p", "", relation.summary), node("p", "muted", "Basis: " + relation.basis.replaceAll("_", " ") + " · Recorded confidence: " + relation.confidence.replaceAll("_", " ")),
      node("p", "guidance-boundary", relation.relation === "taxonomy_mapping" ? "Taxonomy relationship only. This does not establish an observed attack, exploitation or actor involvement." : "A cited source assertion within its stated scope and dates. It does not establish installed exposure or a transitive actor relationship."),
      evidenceList(relation.evidence));
    return item;
  }

  function weaknessSection(record, savedSnapshot) {
    const result = section("CNA weaknesses & related context");
    const explanations = {
      not_projected: "CWE information was not projected in this retained record. This is unknown, rather than a claim that no weakness exists.",
      not_supplied: "No usable canonical CWE identifier was supplied to this projection. Consult the original CNA record.",
      supplied: "These CWE IDs come only from explicit CNA problemTypes fields; they do not establish an observed attack.",
      bounded: "The CNA weakness projection reached a bound and may omit identifiers or descriptions. Consult the original record."
    };
    result.append(node("p", "muted", explanations[record.weaknesses_status]));
    for (const item of record.weaknesses) {
      const row = node("p"); row.append(node("strong", "", item.id), node("span", "", item.description ? " · " + item.description + " · " : " · "),
        link("CNA source ↗", item.source_url), node("span", "", " · "), link("Definition ↗", "https://cwe.mitre.org/data/definitions/" + item.id.slice(4) + ".html"));
      result.append(row);
    }
    const catalog = savedSnapshot.intelligence?.catalog;
    if (!catalog) result.append(node("p", "muted", "Curated entity and relationship context was not supplied in this snapshot."));
    else {
      const direct = catalog.relationships.filter(item => [item.source_id, item.target_id].includes(record.cve));
      const taxonomy = catalog.relationships.filter(item => item.relation === "taxonomy_mapping" && record.weaknesses.some(weakness => weakness.id === item.source_id));
      for (const relation of [...direct, ...taxonomy]) result.append(relationCard(relation, catalog));
      if (!direct.length && !taxonomy.length) result.append(node("p", "muted", "No direct curated relationship is supplied for this CVE or its projected CWE IDs. The catalog is a selected subset."));
    }
    return result;
  }

  function renderKnowledge() {
    const target = $("#knowledge-results"), status = $("#knowledge-status");
    if (!target || !status || !snapshot) return;
    const catalog = snapshot.intelligence?.catalog;
    if (!catalog) { target.replaceChildren(); status.textContent = "Entity context was not supplied in this legacy snapshot; coverage is unknown."; return; }
    const terms = normalized($("#knowledge-filter")?.value || "").trim().split(/\s+/).filter(Boolean);
    const kind = $("#knowledge-kind")?.value || "";
    const entities = catalog.entities.filter(item => (!kind || item.type === kind) && terms.every(term => normalized([item.id, item.label, item.summary, ...item.aliases].join(" ")).includes(term)));
    status.textContent = entities.length + " / " + catalog.entities.length + " selected entities · " + catalog.relationships.length + " explicit relationships · " + catalog.status.replaceAll("_", " ") + " as of " + contextClock(catalog.reviewed_at) + ". Source confidence is recorded context, not observed attack activity or exhaustive coverage.";
    target.replaceChildren(...entities.map(entity => {
      const card = node("details", "product-record");
      card.append(node("summary", "", entity.id + " · " + entity.label + " · " + entity.type), node("p", "", entity.summary),
        node("p", "muted", "Recorded confidence: " + entity.confidence.replaceAll("_", " ") + (entity.aliases.length ? " · Source-attributed aliases: " + entity.aliases.join(", ") : " · No aliases supplied")), evidenceList(entity.evidence));
      for (const relation of catalog.relationships.filter(item => [item.source_id, item.target_id].includes(entity.id))) card.append(relationCard(relation, catalog));
      return card;
    }));
    if (!entities.length) target.append(node("p", "muted", "No selected entity matches. This does not establish the absence of actors, campaigns, products or attack patterns."));
  }

  function nextChicagoSlot(now = Date.now()) {
    try {
      const formatter = new Intl.DateTimeFormat("en-US", { timeZone: "America/Chicago", hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
      const first = (Math.floor(now / 3600000) + 1) * 3600000;
      for (let tick = first; tick <= now + 30 * 3600000; tick += 3600000) {
        const parts = Object.fromEntries(formatter.formatToParts(new Date(tick)).filter(item => item.type !== "literal").map(item => [item.type, item.value]));
        if ([6, 14, 22].includes(Number(parts.hour)) && parts.minute === "00") return parts.year + "-" + parts.month + "-" + parts.day + " " + parts.hour + ":00 America/Chicago (" + new Date(tick).toISOString() + ")";
      }
    } catch (_) { /* An unavailable time-zone database leaves scheduling unknown. */ }
    return null;
  }

  function renderReportSchedule() {
    const target = $("#report-schedule"); if (!target || !snapshot) return;
    const config = snapshot.intelligence?.reporting.configuration;
    if (!config) { target.textContent = "The reporting schedule was not supplied in this legacy snapshot. Next report and revision-review cycle are unknown."; return; }
    const slot = config.schedule_state === "configured" ? nextChicagoSlot() : null;
    const policy = "Daily editions: 06:00, 14:00 and 22:00 America/Chicago · rolling 24 hours on weekdays / 48 hours on weekends. Weekly, end-weekend, every-two-weeks, monthly, quarterly and latest six completed months use the reporting protocol.";
    target.textContent = policy + " " + (config.schedule_state === "configured" ? slot ? "Next scheduled report and revision-review cycle: " + slot + "." : "Next scheduled slot is unknown because time-zone calculation is unavailable." : "Schedule state: " + config.schedule_state + "; no active next-run claim.") + " Configuration observed: " + contextClock(config.schedule_observed_at) + ". Scheduled times do not prove execution or delivery. Each review item's next eligibility is separate. Feed collection requests " + snapshot.refresh.requested_minutes + "-minute checks. The browser reads saved data on nominal ten-minute visible-page checks; visibility, workflow freshness and manual reloads can request earlier checks. A next-browser eligibility timestamp is not asserted.";
  }

  function renderReports() {
    const target = $("#report-list"), status = $("#report-status");
    if (!target || !status || !snapshot) return;
    const reporting = snapshot.intelligence?.reporting;
    if (!reporting) { target.replaceChildren(); status.textContent = "A typed report catalog was not supplied in this legacy snapshot. Existing report links remain available."; renderReportSchedule(); return; }
    status.textContent = reporting.latest_reports.length + " indexed editions · Catalog recorded " + contextClock(reporting.catalog_updated_at) + ". This is a bounded latest subset; published means a report file exists, not every claim has been independently verified.";
    target.replaceChildren(...reporting.latest_reports.map(report => {
      const item = node("details", "product-record");
      item.append(node("summary", "", report.title + " · " + report.status.replaceAll("_", " ")), node("p", "muted", report.id + " · " + report.cadence + " · Coverage: " + report.coverage.replaceAll("_", " ")),
        node("p", "", "Period: " + contextClock(report.period_start) + " → " + contextClock(report.period_end) + (report.origin === "legacy_report" ? " · Original declared period; timezone and end inclusivity are not inferred." : " · Half-open [start, end).")),
        node("p", "muted", "Compiled: " + contextClock(report.compiled_at) + " · Precision: " + report.compilation_precision + (report.prior_report_id ? " · Prior edition: " + report.prior_report_id : "")));
      if (report.report_url) item.append(link("Read report ↗", report.report_url), node("span", "", " · "), link("Evidence data ↗", report.data_url));
      else item.append(node("p", "muted", "Planned edition; no generated report, evidence or future facts are claimed."));
      return item;
    }));
    for (const index of reporting.indexes) { const item = node("p"); item.append(link(index.label + " ↗", index.url)); target.append(item); }
    renderReportSchedule();
  }

  function renderRevisions() {
    const target = $("#revision-watch-list"), summary = $("#revision-watch-summary");
    if (!target || !summary || !snapshot) return;
    const review = snapshot.intelligence?.revisions;
    if (!review) { target.replaceChildren(); summary.textContent = "Revision-review evidence was not supplied in this legacy snapshot; earlier article changes are unknown."; return; }
    if (review.state === "not_run") { target.replaceChildren(); summary.textContent = "No qualified revision-review run is recorded. The policy reviews recently cited sources from the past 96 hours, prioritizing 48 hours; this is not a claim that prior articles are already being rechecked."; return; }
    const count = status => review.records.filter(item => status.includes(item.status)).length;
    summary.textContent = "Latest review: " + review.state + " · " + review.records.length + " selected / " + count(["material_field_change", "timestamp_only", "raw_response_changed_unqualified", "no_baseline", "unchanged_supported"]) + " qualified responses / " + count(["refused"]) + " refused / " + count(["failed"]) + " failed / " + count(["not_checked"]) + " not checked · Cutoff " + stamp(review.nominal_cutoff) + ". First baselines and raw-byte differences are separate from qualified publisher changes; this is not every article or source.";
    target.replaceChildren(...review.records.map(record => {
      const item = node("details", "product-record");
      item.append(node("summary", "", record.status.replaceAll("_", " ") + " · " + new URL(record.source_url).hostname), link("Source ↗", record.source_url), node("p", "", record.summary),
        node("p", "muted", "Last cited: " + stamp(record.last_cited_at) + " · Attempt: " + stamp(record.last_attempt_at) + " · Qualified check: " + stamp(record.checked_at) + " · Prior qualified check: " + stamp(record.prior_checked_at)),
        node("p", "muted", "Publisher published: " + contextClock(record.source_published_at) + " · Updated: " + contextClock(record.source_updated_at)),
        node("p", "muted", "Eligibility: " + record.eligibility_state + " · Next eligible after: " + stamp(record.next_eligible_at) + ". This is a cooldown boundary, not a promised request."),
        node("p", "muted", "Qualified comparison scope: " + (record.comparison_scope || "Not supplied") + " · Profiles: " + (record.comparison_versions.prior || "Unknown") + " → " + (record.comparison_versions.current || "Unknown")));
      if (record.previous_report_url) item.append(link("Previous report ↗", record.previous_report_url));
      for (const url of record.evidence_urls) { const row = node("p"); row.append(link("Supporting evidence ↗", url)); item.append(row); }
      return item;
    }));
  }

  function openMitigation(cve) {
    const savedSnapshot = snapshot;
    const record = savedSnapshot?.mitigations.get(cve);
    if (!record) { showError("This CVE is not present in the current saved snapshot. No external lookup was made."); return; }
    const dialog = $("#mitigation-dialog");
    if ($("#source-dialog").open || dialog.open) return;
    $("#mitigation-title").textContent = cve;
    $("#mitigation-stamp").textContent = "Snapshot generated " + stamp(savedSnapshot.generated_at) + " · CNA source updated " + stamp(record.source_updated_at) + " · Retrieved " + stamp(record.retrieved_at) + " · Last CNA attempt " + stamp(record.source_attempted_at) + ". This open detail stays on that snapshot; close and reopen for newer data.";
    const content = $("#mitigation-content"); const overview = section(record.title || "Source record title not supplied");
    const badges = node("div", "mitigation-badges"); badges.append(node("span", "guidance-badge guidance-" + guidanceStatus(record), guidanceLabels[guidanceStatus(record)]), node("span", "record-state", record.record_state + " · CNA " + record.source_status.toUpperCase()), node("span", "cve-score", scoreLabel(record)));
    overview.append(badges);
    if (record.record_state === "REJECTED") overview.append(node("p", "notice", "This CVE record is rejected. Review its original disposition and do not treat the identifier as a confirmed active vulnerability."));
    if (record.source_status !== "ok") overview.append(node("p", "notice", "CNA enrichment is " + record.source_status + ". Retained CNA information keeps its original retrieval date. CISA action data is collected separately; a missing CNA record does not negate a displayed CISA action."));
    overview.append(node("p", "", record.description || "Description not supplied in this saved record."));
    if (record.cvss?.vector) overview.append(node("p", "cvss-vector", "Vector: " + record.cvss.vector));
    if (record.cvss?.source_url) overview.append(link("CVSS source ↗", record.cvss.source_url));
    const assessment = section("Assessment & review steps");
    assessment.append(node("p", "", record.analysis.assessment || "No assessment supplied."));
    const steps = node("ol", "review-steps");
    for (const step of record.analysis.steps) { const item = node("li"); item.append(node("strong", "", step.title), node("p", "", step.detail)); if (step.evidence_url) item.append(link("Supporting source ↗", step.evidence_url)); steps.append(item); }
    if (steps.children.length) assessment.append(steps); else assessment.append(node("p", "muted", "No review steps supplied."));
    const limitations = node("ul", "record-limitations"); for (const text of record.analysis.limitations) limitations.append(node("li", "", text)); if (limitations.children.length) assessment.append(limitations);
    const products = section("Source-reported products & version ranges");
    products.append(node("p", "muted", "These are bounded publisher excerpts. Affected / unaffected statuses and ranges are not verified installed versions or a list of fixed releases. Consult the original record for omitted conditions."));
    for (const product of record.products) {
      const item = node("details", "product-record"); item.append(node("summary", "", (product.vendor || "Vendor unknown") + " / " + (product.product || "Product unknown") + " · " + product.versions.length + " version statements"));
      item.append(node("p", "muted", "Source default status: " + (product.default_status || "unknown")));
      const versions = node("ul");
      for (const version of product.versions) versions.append(node("li", "", (version.version || "Version not specified") + (version.less_than ? " to < " + version.less_than : "") + (version.less_than_or_equal ? " to ≤ " + version.less_than_or_equal : "") + " · status: " + (version.status || "unknown") + (version.version_type ? " · range type: " + version.version_type : "")));
      if (versions.children.length) item.append(versions); else item.append(node("p", "muted", "No version ranges supplied.")); products.append(item);
    }
    if (!record.products.length) products.append(node("p", "muted", "No product/version statements supplied in this snapshot."));
    const action = section("CISA catalog action");
    action.append(node("p", "", record.required_action || "No CISA required action supplied for this record."));
    if (record.required_action_source_url) action.append(link("CISA action source ↗", record.required_action_source_url));
    if (record.kev) action.append(node("p", "", "Catalog added: " + dateLabel(record.kev.date_added) + " · Federal catalog due date: " + dateLabel(record.kev.due_date) + " · Ransomware association: " + (record.kev.ransomware || "Unknown")), node("p", "guidance-boundary", "The CISA catalog due date applies to the federal catalog requirement. It is not a deadline assigned to you. Catalog addition is not the disclosure or exploitation date."));
    const references = section("Original references");
    const referenceList = node("ul");
    for (const reference of record.references) { const item = node("li"); item.append(link((reference.label || "Original reference") + (reference.kind ? " · " + reference.kind : "") + " ↗", reference.url)); referenceList.append(item); }
    if (referenceList.children.length) references.append(referenceList); else references.append(node("p", "muted", "No original reference links supplied."));
    content.replaceChildren(overview, assessment, weaknessSection(record, savedSnapshot), guidanceItems("Solutions", record.solutions), guidanceItems("Workarounds", record.workarounds), action, products, linkedCoverage(cve, savedSnapshot), references);
    try { dialog.showModal(); dialog.scrollTop = 0; } catch (_) { showError("The guidance dialog could not open in this document. No external lookup or device action occurred."); }
  }

  function requireWorkflow(condition) {
    if (!condition) throw new Error("The public workflow response did not match this repository's supported run format.");
  }

  function workflowTime(value) {
    requireWorkflow(typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value));
    const parsed = new Date(value);
    requireWorkflow(Number.isFinite(parsed.getTime()) && parsed.toISOString() === value.replace("Z", ".000Z") && parsed.getTime() <= Date.now() + 300000);
    return value;
  }

  function workflowRepository(value) {
    requireWorkflow(value && typeof value === "object" && value.id === 1432598602 && value.full_name === "TeamStarWolf/intelligence-hub" && value.private === false && value.owner?.login === "TeamStarWolf");
  }

  function normalizeWorkflow(value, key) {
    requireWorkflow(value && typeof value === "object" && !Array.isArray(value) && Number.isSafeInteger(value.total_count) && value.total_count >= 0);
    const maximum = key === "schedule" ? 1 : 10;
    requireWorkflow(Array.isArray(value.workflow_runs) && value.workflow_runs.length === Math.min(value.total_count, maximum));
    const ids = new Set();
    const runs = value.workflow_runs.map(run => {
      requireWorkflow(run && typeof run === "object" && !Array.isArray(run) && Number.isSafeInteger(run.id) && run.id > 0 && !ids.has(run.id)); ids.add(run.id);
      requireWorkflow(run.workflow_id === 395429963 && run.path === ".github/workflows/publish.yml" && run.head_branch === "main" && typeof run.head_sha === "string" && /^[a-f0-9]{40}$/.test(run.head_sha));
      workflowRepository(run.repository); workflowRepository(run.head_repository);
      requireWorkflow(Object.hasOwn(workflowEvents, run.event) && (key !== "schedule" || run.event === "schedule") && Object.hasOwn(workflowStatuses, run.status));
      requireWorkflow(run.status === "completed" ? Object.hasOwn(workflowConclusions, run.conclusion) : run.conclusion === null);
      requireWorkflow(Number.isSafeInteger(run.run_attempt) && run.run_attempt > 0 && run.html_url === "https://github.com/TeamStarWolf/intelligence-hub/actions/runs/" + run.id && run.url === "https://api.github.com/repos/TeamStarWolf/intelligence-hub/actions/runs/" + run.id);
      const created_at = workflowTime(run.created_at); const updated_at = workflowTime(run.updated_at);
      const started_at = run.run_started_at === null ? null : workflowTime(run.run_started_at);
      requireWorkflow(new Date(updated_at).getTime() >= new Date(created_at).getTime() && (started_at === null || new Date(started_at).getTime() >= new Date(created_at).getTime()) && (run.status !== "completed" || started_at !== null));
      return { id: run.id, event: run.event, status: run.status, conclusion: run.conclusion, attempt: run.run_attempt, created_at, updated_at, started_at };
    });
    runs.sort((left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime() || right.id - left.id);
    return { runs, total_count: value.total_count };
  }

  function workflowRunBlock(run) {
    const block = node("div", "workflow-run-detail");
    const state = run.status === "completed" ? workflowConclusions[run.conclusion] : workflowStatuses[run.status];
    const tone = run.status !== "completed" ? "pending" : run.conclusion === "success" ? "success" : "attention";
    block.append(node("p", "workflow-run-result workflow-result-" + tone, state + " · " + workflowEvents[run.event]), node("p", "", "Run started: " + stamp(run.started_at) + " · Workflow updated: " + stamp(run.updated_at)), link("Run " + run.id + " · attempt " + run.attempt + " ↗", "https://github.com/TeamStarWolf/intelligence-hub/actions/runs/" + run.id));
    return block;
  }

  function renderWorkflowHealth() {
    const scroll = { x: window.scrollX, y: window.scrollY };
    const focusedLink = document.activeElement?.closest("#workflow-health a")?.href;
    const observations = Object.values(workflowObservations);
    const failures = observations.filter(item => item.error !== null).length;
    $("#workflow-health-message").textContent = workflowController ? "Reading public workflow records; the content timestamp stays unchanged." : failures ? "Workflow evidence is partly or wholly unavailable. Any earlier successful observations remain dated below; current health is unknown where a read failed." : lastWorkflowAttempt ? "Public workflow records are separate from the published content date and the browser's snapshot read." : "Public workflow observations pending. No run or schedule result has been established this session.";
    for (const [key, selector, title] of [["recent", "#workflow-run", "Latest returned workflow run"], ["schedule", "#workflow-schedule", "Automatic schedule evidence"]]) {
      const observation = workflowObservations[key]; const content = $(selector);
      content.replaceChildren(node("h3", "", title));
      if (observation.value) {
        const runs = observation.value.runs;
        if (runs.length) content.append(workflowRunBlock(runs[0]));
        else content.append(node("p", "workflow-run-result", key === "schedule" ? "No scheduled run observed in this API result." : "No workflow run observed in this API result."));
        if (key === "recent") {
          content.append(node("p", "workflow-health-scope", "Most recently created of up to 10 returned main-branch runs; later activity on older runs may fall outside this window."));
          if (runs[0]?.conclusion !== "success") {
            const success = runs.filter(run => run.status === "completed" && run.conclusion === "success").sort((left, right) => new Date(right.updated_at).getTime() - new Date(left.updated_at).getTime())[0];
            if (success) { content.append(node("p", "workflow-health-scope", "Most recently updated successful run in this returned window:"), workflowRunBlock(success)); }
            else content.append(node("p", "workflow-health-scope", "No successful run observed in this returned window; earlier history is not assessed."));
          }
        } else content.append(node("p", "workflow-health-scope", "Separate schedule-only query. An empty result does not prove scheduling is disabled or that no news exists."));
        content.append(node("p", "workflow-observation-clock", (observation.error ? "Retained observation read: " : "API observation read: ") + stamp(observation.read_at)));
      } else content.append(node("p", "", "Unknown · no successful API read this session."));
      if (observation.error) content.append(node("p", "workflow-health-error", "Read failed " + stamp(observation.attempted_at) + ". " + observation.error));
    }
    const nextEstimate = lastWorkflowAttemptTick === null ? null : new Date(Date.now() + Math.max(0, pollInterval - (performance.now() - lastWorkflowAttemptTick))).toISOString();
    $("#workflow-health-clocks").textContent = lastWorkflowAttempt ? "API attempt: " + stamp(lastWorkflowAttempt) + " · Next eligible attempt (clock estimate): " + stamp(nextEstimate) + ". Visible-page reads only, at least 10 elapsed minutes apart during this loaded page session. Full browser reload resets this volatile state. Reload snapshot does not bypass this cooldown." : "Workflow API read time is separate from run activity and saved content. No API attempt has started this session.";
    if (focusedLink) [...$("#workflow-health").querySelectorAll("a")].find(anchor => anchor.href === focusedLink)?.focus({ preventScroll: true });
    window.scrollTo({ left: scroll.x, top: scroll.y, behavior: "instant" });
  }

  async function readWorkflow(response) {
    if (!response.ok) { await response.body?.cancel(); throw new Error(response.status === 403 || response.status === 429 ? "Public API access was refused or rate-limited (HTTP " + response.status + "). No authenticated fallback is used." : "Public API read failed (HTTP " + response.status + ")."); }
    if (!/^application\/json(?:;|$)/i.test(response.headers.get("content-type") || "")) { await response.body?.cancel(); throw new Error("The public API did not return JSON."); }
    const length = Number(response.headers.get("content-length"));
    if (Number.isFinite(length) && length > maximumWorkflowBytes) { await response.body?.cancel(); throw new Error("The public API response exceeds the 512 KiB bound."); }
    let bytes;
    if (response.body) {
      const reader = response.body.getReader(); const chunks = []; let total = 0;
      while (true) { const { done, value } = await reader.read(); if (done) break; total += value.byteLength; if (total > maximumWorkflowBytes) { await reader.cancel(); throw new Error("The public API response exceeds the 512 KiB bound."); } chunks.push(value); }
      bytes = new Uint8Array(total); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    } else { bytes = new Uint8Array(await response.arrayBuffer()); if (bytes.byteLength > maximumWorkflowBytes) throw new Error("The public API response exceeds the 512 KiB bound."); }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  }

  function workflowDue() { return lastWorkflowAttemptTick === null || performance.now() - lastWorkflowAttemptTick >= pollInterval; }

  async function loadWorkflowHealth() {
    if (document.hidden || workflowController || !workflowDue()) return;
    lastWorkflowAttemptTick = performance.now(); lastWorkflowAttempt = new Date().toISOString();
    const controller = new AbortController(); workflowController = controller;
    const timeout = setTimeout(() => controller.abort(), 20000);
    renderWorkflowHealth();
    try {
      await Promise.all(Object.entries(workflowQueries).map(async ([key, url]) => {
        const observation = workflowObservations[key]; observation.attempted_at = lastWorkflowAttempt;
        try {
          const response = await fetch(url, { credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer", headers: { Accept: "application/vnd.github+json" }, signal: controller.signal });
          const value = normalizeWorkflow(await readWorkflow(response), key);
          observation.value = value; observation.read_at = new Date().toISOString(); observation.error = null;
        } catch (error) {
          observation.error = error.name === "AbortError" ? "The read timed out or was interrupted when the page became hidden." : error instanceof SyntaxError || error instanceof TypeError ? "The public API could not be read or decoded. Current status is unknown." : error.message || "The public API could not be read.";
        }
      }));
    } finally { clearTimeout(timeout); workflowController = null; renderWorkflowHealth(); }
  }

  function renderFreshness() {
    if (!snapshot) return;
    const age = Date.now() - new Date(snapshot.generated_at).getTime(); const stale = age > day;
    $("#snapshot-status").textContent = age < -300000 ? "Snapshot clock differs" : stale ? "Snapshot older than 24 hours" : "Saved snapshot · " + Math.max(0, Math.floor(age / 60000)) + " min old";
    $("#snapshot-mark").classList.toggle("stale", stale || age < -300000);
    renderReportSchedule();
  }

  function renderSnapshot() {
    renderFreshness();
    renderReports(); renderRevisions(); renderKnowledge();
    $("#generated-at").textContent = "Content as of " + stamp(snapshot.generated_at);
    $("#archive-window").textContent = dateLabel(snapshot.window.start) + " — " + dateLabel(snapshot.window.end);
    const coverage = [["KEV catalog records", snapshot.coverage.kev_records], ["Curated archive events", snapshot.coverage.curated_events], ["Publisher feed articles", snapshot.coverage.feed_articles], ["Linked CVE records", snapshot.mitigations.size], ["URL duplicates removed", snapshot.deduplication.url_duplicates_removed]];
    $("#coverage").replaceChildren(...coverage.map(([label, count]) => { const item = node("div"); item.append(node("dt", "", label), node("dd", "", count.toLocaleString())); return item; }));
    const ok = snapshot.sources.filter(source => source.status === "ok").length;
    const partial = snapshot.sources.filter(source => source.status === "partial").length;
    const failed = snapshot.sources.filter(source => source.status === "failed").length;
    const unfetched = snapshot.sources.filter(source => source.status === "not_fetched").length;
    const uncounted = snapshot.sources.filter(source => source.id !== "cisa-kev" && source.intake === null).length;
    $("#source-health-summary").textContent = snapshot.sources.length ? "Recorded source outcomes: " + ok + " input accepted / " + partial + " partial / " + failed + " failed / " + unfetched + " not fetched. " + uncounted + " publisher observations have no item-window report; completeness is unknown." : "Source collection outcomes were not supplied.";
    $("#coverage-notes").replaceChildren(...[...snapshot.coverage.notes, ...snapshot.refresh.notes].map(note => node("li", "", note)));
    if (!$("#coverage-notes").children.length) $("#coverage-notes").append(node("li", "", "No additional notes supplied."));
    $("#integrations").replaceChildren(...[["xai", "Grok / xAI"], ["x", "X"], ["sec", "SEC cyber filings"]].map(([key, name]) => { const item = node("div", "integration-row"); const heading = node("div", "integration-heading"); heading.append(node("span", "", name), node("span", "integration-state", "NOT CONNECTED")); item.append(heading, node("p", "", snapshot.integrations[key].message)); return item; }));
    const refresh = $("#refresh-policy");
    refresh.replaceChildren(node("span", "", "Collection requests a " + snapshot.refresh.requested_minutes + "-minute schedule; execution and deployment may be delayed. "));
    const statusUrl = safeUrl(snapshot.refresh.status_url);
    if (statusUrl) {
      const url = new URL(statusUrl);
      if (url.hostname === "github.com" && /^\/teamstarwolf\/intelligence-hub\/actions(?:\/|$)/i.test(url.pathname)) refresh.append(link("Collection workflow ↗", statusUrl));
    }
    for (const button of document.querySelectorAll("[data-open-sources]")) button.disabled = false;
    // Open dialogs retain their original snapshot and scroll position until explicitly reopened.
  }

  function showError(message) { $("#feed-error").hidden = false; $("#feed-error-message").textContent = message; }

  async function readFeed(response) {
    if (!response.ok) throw new Error("The feed snapshot could not be read (HTTP " + response.status + ").");
    const length = Number(response.headers.get("content-length"));
    if (Number.isFinite(length) && length > maximumFeedBytes) throw new Error("The snapshot exceeds the supported 16 MiB download size.");
    let bytes;
    if (response.body) {
      const reader = response.body.getReader(); const chunks = []; let total = 0;
      while (true) { const { done, value } = await reader.read(); if (done) break; total += value.byteLength; if (total > maximumFeedBytes) { await reader.cancel(); throw new Error("The snapshot exceeds the supported 16 MiB download size."); } chunks.push(value); }
      bytes = new Uint8Array(total); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    } else { bytes = new Uint8Array(await response.arrayBuffer()); if (bytes.byteLength > maximumFeedBytes) throw new Error("The snapshot exceeds the supported 16 MiB download size."); }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return { value: JSON.parse(text), text };
  }

  async function load() {
    if (loading) return;
    loading = true; lastAttempt = new Date().toISOString();
    $("#reload").disabled = true; $("#reload").textContent = "Reading snapshot…"; $("#loading-cards").hidden = Boolean(snapshot);
    $("#poll-status").textContent = "Checking the saved snapshot on this site…";
    const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 45000);
    try {
      const response = await fetch("./data/feed.json", { credentials: "omit", cache: "no-store", redirect: "error", signal: controller.signal });
      const result = await readFeed(response);
      const changed = snapshotText !== result.text;
      const value = changed ? normalize(result.value) : snapshot;
      lastRead = new Date().toISOString();
      $("#feed-error").hidden = true;
      if (changed) {
        const scroll = { x: window.scrollX, y: window.scrollY, years: $("#year-timeline").scrollLeft, months: $("#month-timeline").scrollLeft, register: $("#cve-register").scrollLeft };
        const focused = document.activeElement?.dataset.focusKey;
        snapshot = value; snapshotText = result.text;
        configureFilters(); renderSnapshot(); render();
        $("#year-timeline").scrollLeft = scroll.years; $("#month-timeline").scrollLeft = scroll.months;
        $("#cve-register").scrollLeft = scroll.register;
        if (focused) {
          const target = [...document.querySelectorAll("[data-focus-key]")].find(element => element.dataset.focusKey === focused);
          (target || $("#results-status")).focus({ preventScroll: true });
        }
        window.scrollTo({ left: scroll.x, top: scroll.y, behavior: "instant" });
      } else renderFreshness();
      $("#poll-status").textContent = "Browser read " + stamp(lastRead) + " · " + (changed ? "snapshot updated" : "same saved snapshot") + " · Checks every 10 minutes while visible; publishers are not contacted by this browser.";
    } catch (error) {
      showError((error.name === "AbortError" ? "The snapshot read timed out." : error instanceof SyntaxError ? "The saved feed is not valid JSON." : error.message || "The saved feed could not load.") + (snapshot ? " The prior snapshot generated " + stamp(snapshot.generated_at) + " remains displayed with its original dates." : " No feed data is displayed. Read a later valid snapshot."));
      $("#poll-status").textContent = "Browser check failed " + stamp(lastAttempt) + (lastRead ? " · Last successful read " + stamp(lastRead) : " · No successful snapshot read this session");
      if (!snapshot) { $("#snapshot-status").textContent = "Snapshot unavailable"; $("#snapshot-mark").classList.add("stale"); $("#results-status").textContent = "No snapshot loaded · Counts and source outcomes are unknown"; }
    } finally {
      clearTimeout(timeout); $("#loading-cards").hidden = true;
      try { await loadWorkflowHealth(); }
      finally { loading = false; $("#reload").disabled = false; $("#reload").textContent = "Reload snapshot ↻"; }
    }
  }

  function reset() {
    clearTimeout(searchTimer);
    for (const control of [controls.search, controls.kind, controls.source, controls.exploitation, controls.mitigation, controls.year, controls.month]) control.value = "";
    controls.preset.value = "full"; controls.sort.value = "date-desc"; visibleCount = pageSize; render();
  }

  $("#filters").addEventListener("submit", event => { event.preventDefault(); clearTimeout(searchTimer); visibleCount = pageSize; render(); });
  controls.search.addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { visibleCount = pageSize; render(); }, 150); });
  for (const select of [controls.kind, controls.source, controls.exploitation, controls.mitigation, controls.sort]) select.addEventListener("change", () => { visibleCount = pageSize; render(); });
  controls.year.addEventListener("change", () => { controls.month.value = ""; controls.preset.value = "full"; visibleCount = pageSize; render(); });
  controls.month.addEventListener("change", () => { controls.year.value = controls.month.value ? controls.month.value.slice(0, 4) : controls.year.value; if (controls.month.value === "unknown") controls.year.value = "unknown"; controls.preset.value = "full"; visibleCount = pageSize; render(); });
  controls.preset.addEventListener("change", () => { controls.year.value = ""; controls.month.value = ""; visibleCount = pageSize; render(); });
  $("#clear-dates").addEventListener("click", () => setDates());
  $("#reset").addEventListener("click", reset); $("#empty-reset").addEventListener("click", reset); $("#reload").addEventListener("click", load);
  $("#load-more").addEventListener("click", () => { visibleCount += pageSize; render(); });
  for (const [id, mode] of [["#view-feed", "feed"], ["#view-cves", "cves"]]) $(id).addEventListener("click", () => { view = mode; visibleCount = pageSize; render(); });
  for (const button of document.querySelectorAll("[data-open-sources]")) button.addEventListener("click", () => {
    if (!snapshot || $("#mitigation-dialog").open || $("#source-dialog").open) return;
    renderSources(); try { $("#source-dialog").showModal(); $("#source-dialog").scrollTop = 0; } catch (_) { showError("The source ledger could not open in this document. The displayed snapshot is unchanged."); }
  });
  $("#close-sources").addEventListener("click", () => $("#source-dialog").close());
  $("#close-mitigation").addEventListener("click", () => $("#mitigation-dialog").close());
  $("#knowledge-filter")?.addEventListener("input", renderKnowledge);
  $("#knowledge-kind")?.addEventListener("change", renderKnowledge);
  document.addEventListener("visibilitychange", () => { if (document.hidden) { workflowController?.abort(); return; } renderFreshness(); if (!lastAttempt || Date.now() - new Date(lastAttempt).getTime() >= pollInterval || workflowDue()) load(); });
  setInterval(() => { if (!document.hidden && (!lastAttempt || Date.now() - new Date(lastAttempt).getTime() >= pollInterval || workflowDue())) load(); }, pollInterval);
  setInterval(renderFreshness, 60000);
  load();
})();
