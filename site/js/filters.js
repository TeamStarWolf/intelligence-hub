// Pure filter, facet and sort functions over validated rows. Views call these; nothing here
// touches the DOM, so tests/js runs them directly.
import { LIST_VIEWS, defaultRange, defaultSort } from "./router.js";
import { addDays, normalized } from "./util.js";

// The source class a row counts under. Rows without a tagging block (the schema 6 fallback)
// fall back to their kind.
export function classOf(row) {
  if (row.t.source_class) return row.t.source_class;
  return { advisory: "vendor-primary", bulletin: "vendor-primary", note: "government-cert", kev: "government-cert", research: "researcher", reporting: "press" }[row.kind] || null;
}

// The desk a row sits on. Rows tagged before the desk existed, and schema 6 rows, fall back by
// origin: service-health incidents are infrastructure, everything else is security.
export function deskOf(row) {
  return row.t.desk || (row.origin === "service-status" ? "infrastructure" : "security");
}

// KEV-linked: the row is a KEV entry, its tagging names a KEV CVE, or one of its CVEs has a
// KEV dateAdded in the CVE index. This is the catalog match, separate from the guidance label.
export function kevLinked(row, cveIndex) {
  return row.kev_linked || row.cves.some(cve => Boolean(cveIndex && cveIndex.get(cve)?.kev_added));
}

// CISA required action: one of the row's CVEs carries CISA's requiredAction text.
export function requiredAction(row, cveIndex) {
  return row.cves.some(cve => Boolean(cveIndex && cveIndex.get(cve)?.required_action));
}

// The calendar-day window a list view shows: a year (and month), or the last N days ending on
// the content date, or null for the whole loaded scope.
export function dateWindow(view, query, contentDate) {
  if (query.year) {
    if (query.month) {
      const last = new Date(Date.UTC(Number(query.year), Number(query.month), 0)).getUTCDate();
      return { from: query.year + "-" + query.month + "-01", to: query.year + "-" + query.month + "-" + String(last).padStart(2, "0") };
    }
    return { from: query.year + "-01-01", to: query.year + "-12-31" };
  }
  const range = query.range || defaultRange(view);
  if (range === "all" || !contentDate) return null;
  return { from: addDays(contentDate, 1 - Number(range)), to: contentDate };
}

function terms(text) { return normalized(text || "").trim().split(/\s+/).filter(Boolean); }
const has = (items, id) => items.some(item => item[0] === id);

export function rowMatches(row, query, { view = "explore", cveIndex = null, window = null } = {}) {
  const constraint = LIST_VIEWS[view];
  if (constraint && (row.kind === "kev" || !constraint.includes(classOf(row)))) return false;
  if (window && (row.day === null || row.day < window.from || row.day > window.to)) return false;
  if (query.q && !terms(query.q).every(term => row.search.includes(term))) return false;
  if (query.desk && deskOf(row) !== query.desk) return false;
  if (query.kind && row.kind !== query.kind) return false;
  if (query.class && classOf(row) !== query.class) return false;
  if (query.event && !has(row.t.event_type, query.event)) return false;
  if (query.exp && row.exploited !== query.exp) return false;
  if (query.kev && !kevLinked(row, cveIndex)) return false;
  if (query.action && !requiredAction(row, cveIndex)) return false;
  if (query.vendor && !has(row.t.vendor, "vendor:" + query.vendor)) return false;
  if (query.product && !has(row.t.product, "product:" + query.product)) return false;
  if (query.actor && !has(row.t.actor, "actor:" + query.actor)) return false;
  if (query.malware && !has(row.t.malware, "malware:" + query.malware)) return false;
  if (query.cwe && !has(row.t.cwe, query.cwe)) return false;
  if (query.tech && !row.t.attack.includes(query.tech)) return false;
  if (query.sector && !has(row.t.sector, "sector:" + query.sector)) return false;
  if (query.region && !row.t.region.some(item => item[0] === query.region)) return false;
  if (query.source && row.source_id !== query.source) return false;
  return true;
}

function compareNullable(a, b, direction, numeric = false) {
  if (a === null && b !== null) return 1;
  if (a !== null && b === null) return -1;
  if (a === null && b === null) return 0;
  return (numeric ? a - b : a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" })) * direction;
}

// Sorts in place and returns rows. Unknown values sort last in both directions.
export function sortRows(rows, sort = "date-desc") {
  const [key, order] = sort.split("-");
  const direction = order === "desc" ? -1 : 1;
  return rows.sort((a, b) => {
    let result = 0;
    if (key === "date") result = compareNullable(a.time, b.time, direction, true);
    else if (key === "cvss") result = compareNullable(a.score, b.score, direction, true);
    else if (key === "cve") result = compareNullable(a.cve_key, b.cve_key, direction);
    else if (key === "title") result = a.title.localeCompare(b.title) * direction;
    else if (key === "source") result = a.source_name.localeCompare(b.source_name) * direction;
    return result || compareNullable(a.time, b.time, -1, true) || a.id.localeCompare(b.id);
  });
}

export function filterRows(rows, route, { cveIndex = null, contentDate = null } = {}) {
  const window = dateWindow(route.view, route.query, contentDate);
  return sortRows(rows.filter(row => rowMatches(row, route.query, { view: route.view, cveIndex, window })), route.query.sort || defaultSort(route.view));
}

// Value counts for every filter over rows (the loaded scope under the view's fixed constraint).
export function facets(rows, view = "explore") {
  const result = { desk: new Map(), kind: new Map(), class: new Map(), event: new Map(), exp: new Map(), vendor: new Map(), product: new Map(), actor: new Map(), malware: new Map(), cwe: new Map(), tech: new Map(), sector: new Map(), region: new Map(), source: new Map() };
  const add = (map, key, label) => { const entry = map.get(key); if (entry) entry.count++; else map.set(key, { count: 1, label }); };
  const constraint = LIST_VIEWS[view];
  for (const row of rows) {
    if (constraint && (row.kind === "kev" || !constraint.includes(classOf(row)))) continue;
    add(result.desk, deskOf(row)); add(result.kind, row.kind); add(result.exp, row.exploited); add(result.source, row.source_id, row.source_name);
    const rowClass = classOf(row); if (rowClass) add(result.class, rowClass);
    for (const field of ["event_type", "vendor", "product", "actor", "malware", "sector"]) {
      const target = result[field === "event_type" ? "event" : field];
      for (const id of new Set(row.t[field].map(item => item[0]))) add(target, id.replace(/^[a-z]+:/, ""), id);
    }
    for (const code of new Set(row.t.region.map(item => item[0]))) add(result.region, code);
    for (const id of new Set(row.t.cwe.map(item => item[0]))) add(result.cwe, id);
    for (const id of new Set(row.t.attack)) add(result.tech, id);
  }
  return result;
}

// CVE register rows from the CVE index. kev=1 keeps every CVE with a KEV dateAdded, whatever
// its guidance label; action=1 keeps every CVE whose brief carries CISA's requiredAction.
export function cveRegister(cveIndex, query) {
  const words = terms(query.q);
  const rows = [...cveIndex.values()].filter(row => (!query.kev || row.kev_added) && (!query.action || row.required_action) &&
    words.every(word => normalized(row.cve + " " + row.weaknesses.join(" ") + " " + row.guidance).includes(word)));
  const [key, order] = (query.sort || "cve-desc").split("-");
  const direction = order === "desc" ? -1 : 1;
  return rows.sort((a, b) => (key === "cvss" ? compareNullable(a.score, b.score, direction, true) : key === "kev" ? compareNullable(a.kev_added, b.kev_added, direction) : 0) ||
    a.cve.localeCompare(b.cve, undefined, { numeric: true }) * (key === "cve" ? direction : -1));
}

// The Known exploited view: KEV ledger rows by dateAdded window, search and sort.
export function kevLedger(rows, query, contentDate) {
  const window = dateWindow("kev", query, contentDate);
  const words = terms(query.q);
  const kept = rows.filter(row => (!window || (row.date_added >= window.from && row.date_added <= window.to)) &&
    words.every(word => normalized([row.cve, row.name, row.vendor, row.product, row.directive || "", row.cwe.join(" ")].join(" ")).includes(word)));
  const [key, order] = (query.sort || "added-desc").split("-");
  const direction = order === "desc" ? -1 : 1;
  const field = key === "due" ? "due_date" : key === "cve" ? "cve" : "date_added";
  return kept.sort((a, b) => compareNullable(a[field], b[field], direction) || b.date_added.localeCompare(a.date_added) || a.cve.localeCompare(b.cve, undefined, { numeric: true }));
}

// The Today view: the content date and the two days before it (72 hours of calendar days),
// KEV additions for the last week and KEV due dates in the next two weeks. The collector's
// recent.json is cut to the same windows (intelligence_hub/shards.py RECENT_*).
export const TODAY_DAYS = 3;
export const KEV_STRIP_DAYS = 7;
export const ACT_WITHIN_DAYS = 14;

export function today(rows, kevRows, contentDate) {
  const from = addDays(contentDate, 1 - TODAY_DAYS);
  const inWindow = rows.filter(row => row.day !== null && row.day >= from && row.day <= contentDate && row.kind !== "kev");
  sortRows(inWindow, "date-desc");
  const days = [];
  for (let offset = 0; offset < KEV_STRIP_DAYS; offset++) {
    const day = addDays(contentDate, -offset);
    days.push({ day, entries: kevRows.filter(row => row.date_added === day).sort((a, b) => a.cve.localeCompare(b.cve, undefined, { numeric: true })) });
  }
  const until = addDays(contentDate, ACT_WITHIN_DAYS);
  const act = kevRows.filter(row => row.due_date && row.due_date >= contentDate && row.due_date <= until)
    .sort((a, b) => a.due_date.localeCompare(b.due_date) || a.cve.localeCompare(b.cve, undefined, { numeric: true }));
  return {
    from, to: contentDate, days, act, until,
    advisories: inWindow.filter(row => ["vendor-primary", "government-cert"].includes(classOf(row))),
    research: inWindow.filter(row => classOf(row) === "researcher"),
    news: inWindow.filter(row => classOf(row) === "press")
  };
}
