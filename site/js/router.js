// The hash router. parseRoute and formatRoute are pure: a route is
// {view, id, query}, the hash is "#/<view>[/<id>][?key=value&...]", and every key and value is
// checked against an allowlist. Unknown keys, unknown values and unknown views are dropped,
// so nothing from the address bar is ever reflected into the page. docs/URLS.md publishes
// this contract for links from the library.

export const VIEWS = ["explore", "today", "advisories", "kev", "research", "news", "cves", "cve", "history", "vendors", "vendor", "tags", "actors", "actor", "malware", "reports", "sources", "method", "data", "about", "patch-tuesday", "status", "subscribe"];
// Views that are the Explorer with a fixed source-class constraint.
export const LIST_VIEWS = { explore: null, advisories: ["vendor-primary", "government-cert"], research: ["researcher"], news: ["press"] };

const KINDS = ["advisory", "research", "reporting", "incident", "kev", "filing", "bulletin", "note", "change", "lifecycle"];
const CLASSES = ["vendor-primary", "government-cert", "researcher", "press"];
// The desks (config/vocab/desk.json). Every view sits under one desk tab; "it" has no view yet.
export const DESKS = ["security", "infrastructure", "it"];
export const VIEW_DESK = { explore: "explore", today: "security", advisories: "security", kev: "security", research: "security", news: "security", cves: "security", cve: "security",
  actors: "security", actor: "security", malware: "security", "patch-tuesday": "security", status: "infrastructure",
  history: "reference", vendors: "reference", vendor: "reference", tags: "reference", reports: "reference", sources: "reference", method: "reference", data: "reference", about: "reference",
  subscribe: "reference" };
const EVENTS = ["disclosure", "exploitation", "patch", "breach", "outage", "takedown", "policy", "analysis", "unclassified", "maintenance", "end-of-support"];
const EXPLOITATION = ["known", "reported", "unknown"];
export const RANGES = ["3", "7", "30", "90", "365", "all"];
export const SORTS = {
  list: ["date-desc", "date-asc", "title-asc", "title-desc", "source-asc", "source-desc", "cve-asc", "cve-desc", "cvss-desc", "cvss-asc", "epss-desc", "epss-asc"],
  kev: ["added-desc", "added-asc", "due-asc", "due-desc", "cve-desc", "cve-asc"],
  cves: ["cve-desc", "cve-asc", "cvss-desc", "cvss-asc", "epss-desc", "epss-asc", "kev-desc"]
};
export const CVE_ID = /^CVE-\d{4}-\d{4,19}$/;

const year = value => /^(?:199[89]|20[0-9]{2})$/.test(value);
const slug = value => /^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$/.test(value);
const entity = value => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?$/.test(value);
const oneOf = values => value => values.includes(value);

// Every query key, in the order formatRoute writes them, with its value check.
const KEYS = [
  // Free text, rendered only with textContent; angle brackets and control characters are refused.
  ["q", value => value.length > 0 && value.length <= 200 && !/[\u0000-\u001f\u007f<>]/.test(value)],
  ["desk", oneOf(DESKS)],
  ["kind", oneOf(KINDS)],
  ["class", oneOf(CLASSES)],
  ["event", oneOf(EVENTS)],
  ["exp", oneOf(EXPLOITATION)],
  ["kev", value => value === "1"],
  ["action", value => value === "1"],
  ["vendor", slug],
  ["product", slug],
  ["actor", entity],
  ["malware", entity],
  ["cwe", value => /^CWE-[1-9][0-9]{0,5}$/.test(value)],
  ["tech", value => /^T[0-9]{4}(?:\.[0-9]{3})?$/.test(value)],
  ["sector", slug],
  ["region", value => /^(?:[A-Z]{2}|M49-[0-9]{3})$/.test(value)],
  ["source", slug],
  ["year", year],
  ["month", value => /^(?:0[1-9]|1[0-2])$/.test(value)],
  ["range", oneOf(RANGES)],
  ["sort", value => Object.values(SORTS).some(list => list.includes(value))],
  ["page", value => /^[1-9][0-9]{0,3}$/.test(value)],
  ["open", value => /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/.test(value)],
  // Wall mode on Today and Service health: controls hidden, larger type, nothing more read.
  ["wall", value => value === "1"]
];
const KEY_NAMES = KEYS.map(([name]) => name);
const CHECKS = Object.fromEntries(KEYS);

// The keys each view reads. Anything else in the hash is dropped for that view.
const VIEW_KEYS = {
  list: ["q", "desk", "kind", "class", "event", "exp", "kev", "action", "vendor", "product", "actor", "malware", "cwe", "tech", "sector", "region", "source", "year", "month", "range", "sort", "page", "open"],
  today: ["wall"],
  kev: ["q", "year", "range", "sort", "page"],
  cves: ["q", "kev", "action", "sort", "page"],
  cve: ["q", "kev", "action", "sort", "page"],
  // history is the year index; a history/<year> page reads the "history-year" keys.
  history: [], "history-year": ["source", "month", "page"],
  vendors: [], vendor: ["page"], tags: ["year"], actors: ["year"], actor: ["page"], malware: ["page"],
  reports: [], sources: [], method: [], data: [], about: [], subscribe: [], "patch-tuesday": [],
  // #/status?source=<id> shows one service-health source; wall=1 is the monitor layout.
  status: ["source", "wall"]
};

// Views with an id in the path: #/cve/<CVE-id>, #/history/<year>, #/vendor/<id>, #/actor/<id>,
// #/malware/<id> and #/patch-tuesday/<YYYY-MM>. Without a valid id, a view that needs one falls
// back to its index view; #/patch-tuesday with no month opens the latest brief.
export const ID_VIEWS = {
  cve: { check: value => CVE_ID.test(value), fallback: "cves" },
  history: { check: year, fallback: null },
  vendor: { check: slug, fallback: "vendors" },
  actor: { check: entity, fallback: "actors" },
  malware: { check: entity, fallback: "actors" },
  "patch-tuesday": { check: value => /^(?:199[89]|20[0-9]{2})-(?:0[1-9]|1[0-2])$/.test(value), fallback: null }
};

export function viewKeys(view, id = null) {
  if (view === "history") return VIEW_KEYS[id ? "history-year" : "history"];
  return VIEW_KEYS[Object.hasOwn(LIST_VIEWS, view) ? "list" : view] || [];
}

export function defaultRange(view) {
  return { explore: "all", advisories: "30", research: "30", news: "7", kev: "30" }[view] || "all";
}

export function defaultSort(view) {
  return view === "kev" ? "added-desc" : view === "cves" || view === "cve" ? "cve-desc" : "date-desc";
}

function sortsFor(view) { return view === "kev" ? SORTS.kev : view === "cves" || view === "cve" ? SORTS.cves : SORTS.list; }

// Keeps only allowlisted keys with valid values for the view, and drops values equal to the default.
export function cleanQuery(view, query, id = null) {
  const clean = {};
  for (const name of viewKeys(view, id)) {
    const value = query[name];
    if (typeof value !== "string" || !CHECKS[name](value)) continue;
    if (name === "sort" && (!sortsFor(view).includes(value) || value === defaultSort(view))) continue;
    if (name === "range" && value === defaultRange(view)) continue;
    if (name === "page" && value === "1") continue;
    if (name === "q") { const text = value.trim().replace(/\s+/g, " "); if (text) clean.q = text; continue; }
    clean[name] = value;
  }
  // A month needs its year (a history year page carries it in the path); a year replaces the date range.
  if (clean.month && !clean.year && view !== "history") delete clean.month;
  if (clean.year) delete clean.range;
  return clean;
}

function readParams(text) {
  const values = {};
  if (!text) return values;
  let params;
  try { params = new URLSearchParams(text); } catch (_) { return values; }
  for (const [key, value] of params) if (KEY_NAMES.includes(key) || LEGACY_KEYS.includes(key)) if (!Object.hasOwn(values, key)) values[key] = value;
  return values;
}

// The A4 link keys (?tag=vendor:fortinet&kind=kev#briefing) and the old section anchors.
const LEGACY_KEYS = ["tag", "view", "cve"];
const LEGACY_ANCHORS = { briefing: "explore", timeline: "explore", top: "explore", knowledge: "about", method: "method", reports: "reports" };
const TAG_FIELDS = { vendor: slug, product: slug, actor: entity, malware: entity, sector: slug };
// #/tag/<field>/<value> is an alias for the Explorer filter a tag value stands for. A field is
// named by its query key or by its name in the row's tagging block.
export const TAG_ROUTE_FIELDS = { kind: "kind", desk: "desk", class: "class", source_class: "class", event: "event", event_type: "event", exp: "exp", exploitation: "exp",
  vendor: "vendor", product: "product", actor: "actor", malware: "malware", cwe: "cwe", tech: "tech", attack: "tech", sector: "sector", region: "region", source: "source" };

function legacyQuery(values) {
  const query = { ...values };
  let view = null, id = null, legacy = false;
  if (typeof values.tag === "string") {
    legacy = true;
    const match = /^([a-z]+):(.+)$/.exec(values.tag);
    if (match && Object.hasOwn(TAG_FIELDS, match[1]) && TAG_FIELDS[match[1]](match[2]) && !query[match[1]]) query[match[1]] = match[2];
  }
  if (typeof values.month === "string" && /^\d{4}-(?:0[1-9]|1[0-2])$/.test(values.month)) {
    legacy = true; query.year = values.month.slice(0, 4); query.month = values.month.slice(5);
  }
  if (values.view !== undefined) { legacy = true; if (values.view === "cves") view = "cves"; else if (values.view === "feed") view = "explore"; }
  if (values.cve !== undefined) { legacy = true; if (CVE_ID.test(values.cve)) { view = "cve"; id = values.cve; } }
  for (const key of LEGACY_KEYS) delete query[key];
  return { query, view, id, legacy };
}

// hash is location.hash, search is location.search. Returns {view, id, query, rewrite}:
// rewrite is true when the address should be replaced by formatRoute(route) (legacy keys,
// unknown keys or values, or a query string before the hash).
export function parseRoute(hash = "", search = "") {
  let view = "explore", id = null, rewrite = false;
  let raw = typeof hash === "string" ? hash.replace(/^#/, "") : "";
  let values = {};
  if (raw.startsWith("/")) {
    const mark = raw.indexOf("?");
    const path = mark === -1 ? raw : raw.slice(0, mark);
    values = readParams(mark === -1 ? "" : raw.slice(mark + 1));
    const parts = path.split("/").filter(Boolean);
    const spec = parts.length && Object.hasOwn(ID_VIEWS, parts[0]) ? ID_VIEWS[parts[0]] : null;
    if (parts.length === 0) view = "explore";
    else if (parts[0] === "tag") {
      view = "explore"; rewrite = true;
      const key = parts.length === 3 && Object.hasOwn(TAG_ROUTE_FIELDS, parts[1]) ? TAG_ROUTE_FIELDS[parts[1]] : null;
      if (key && CHECKS[key](parts[2]) && !Object.hasOwn(values, key)) values[key] = parts[2];
    }
    else if (VIEWS.includes(parts[0]) && parts.length === 1 && !(spec && spec.fallback)) view = parts[0];
    else if (spec && parts.length === 2 && spec.check(parts[1])) { view = parts[0]; id = parts[1]; }
    else { view = spec ? spec.fallback || parts[0] : "explore"; rewrite = true; }
  } else if (raw) {
    // An old section anchor, or an in-page anchor the router does not know.
    view = LEGACY_ANCHORS[raw] || "explore";
    rewrite = true;
  }
  const fromSearch = readParams(typeof search === "string" ? search.replace(/^\?/, "") : "");
  if (typeof search === "string" && search.replace(/^\?/, "")) rewrite = true;
  values = { ...fromSearch, ...values };
  const legacy = legacyQuery(values);
  if (legacy.legacy) rewrite = true;
  if (legacy.view) { view = legacy.view; id = legacy.id; }
  const query = cleanQuery(view, legacy.query, id);
  const route = { view, id, query };
  if (!rewrite && hash && formatRoute(route) !== (hash.startsWith("#") ? hash : "#" + hash) && !(hash === "#/" && view === "explore" && !Object.keys(query).length)) rewrite = true;
  return { ...route, rewrite };
}

export function formatRoute(route) {
  let view = VIEWS.includes(route.view) ? route.view : "explore";
  const spec = Object.hasOwn(ID_VIEWS, view) ? ID_VIEWS[view] : null;
  const id = spec && typeof route.id === "string" && spec.check(route.id) ? route.id : null;
  if (spec && !id && spec.fallback) view = spec.fallback;
  const path = "#/" + view + (id ? "/" + id : "");
  const query = cleanQuery(view, route.query || {}, id);
  const parts = KEY_NAMES.filter(name => Object.hasOwn(query, name)).map(name => name + "=" + encodeURIComponent(query[name]).replace(/%20/g, "+"));
  return path + (parts.length ? "?" + parts.join("&") : "");
}

// A copy of route with some query keys changed (null removes a key). Filter changes reset the page.
export function withQuery(route, changes, keepPage = false) {
  const query = { ...route.query };
  for (const [key, value] of Object.entries(changes)) {
    if (value === null || value === undefined || value === "") delete query[key];
    else query[key] = String(value);
  }
  if (!keepPage && !Object.hasOwn(changes, "page")) delete query.page;
  return { view: route.view, id: route.id, query: cleanQuery(route.view, query, route.id) };
}
