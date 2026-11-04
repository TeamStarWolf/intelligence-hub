// The Intelligence Explorer: the default route. Advisories, Research and News are the same
// view with a fixed source-class constraint and a shorter default date range.
import { defaultRange, defaultSort, formatRoute, withQuery } from "../router.js";
import { classOf, dateWindow, facets, filterRows, kevLinked, requiredAction } from "../filters.js";
import { count, dateLabel, link, monthLabel, node, routeLink, stamp } from "../util.js";
import { EXPLOITATION_LABELS, KIND_LABELS, cveOrgLink, dateBasisLabel, facetOptions, fillSelect, label, libraryDoor, pager, pinnedDoor, resultCard } from "./common.js";

const TITLES = { explore: "Intelligence Explorer", advisories: "Advisories", research: "Research", news: "News" };
const INTROS = {
  advisories: "Vendor and government advisories, newest first. KEV catalog entries have their own tab.",
  research: "Research teams' posts, newest first.",
  news: "Press reporting: publisher headlines and links only."
};
const SELECTS = ["kind", "class", "event", "exp", "sector", "region", "vendor", "product", "actor", "malware", "cwe", "tech", "source", "year", "month"];
const FILTER_KEYS = [...SELECTS, "kev", "action", "range"];

export function activeFilters(route) {
  return FILTER_KEYS.filter(key => Object.hasOwn(route.query, key)).length;
}

function scopeText(route, store) {
  if (store.state.mode === "legacy") return "the schema 6 feed";
  if (route.query.year) return (route.query.month ? monthLabel(route.query.year + "-" + route.query.month) : route.query.year) + " (live months and history rows)";
  if (dateWindow(route.view, route.query, store.contentDate())) return "the last " + count(Number(route.query.range || defaultRange(route.view)), "day");
  const index = store.state.index;
  return "the live window, " + monthLabel(index.window.live_start.slice(0, 7)) + " to " + monthLabel(index.window.end.slice(0, 7)) + " (pick a year for history back to 1998)";
}

// Copies the route into the form controls. The search box is left alone while it has focus.
function syncControls(ctx) {
  const { route, el, doc } = ctx;
  const search = el("#q");
  if (doc.activeElement !== search) search.value = route.query.q || "";
  el("#f-sort").value = route.query.sort || defaultSort(route.view);
  el("#f-kev").checked = route.query.kev === "1";
  el("#f-action").checked = route.query.action === "1";
  el("#f-range").value = route.query.range || defaultRange(route.view);
  el("#f-range").disabled = Boolean(route.query.year);
  el("#f-month").disabled = !route.query.year;
  const active = activeFilters(route);
  el("#filter-count").textContent = active ? " (" + active + ")" : "";
}

function fillFilters(ctx, rows) {
  const { route, el, store } = ctx;
  const found = facets(rows, route.view);
  const plain = (value, entry) => entry && entry.label ? label(entry.label) : value;
  fillSelect(el("#f-kind"), "All kinds", facetOptions(found.kind, value => KIND_LABELS[value] || value), route.query.kind);
  fillSelect(el("#f-class"), "All source classes", facetOptions(found.class, value => label("class:" + value)), route.query.class);
  fillSelect(el("#f-event"), "All event types", facetOptions(found.event, value => label("event:" + value)), route.query.event);
  fillSelect(el("#f-exp"), "All exploitation states", facetOptions(found.exp, value => EXPLOITATION_LABELS[value] || value), route.query.exp);
  fillSelect(el("#f-sector"), "All sectors", facetOptions(found.sector, plain), route.query.sector);
  fillSelect(el("#f-region"), "All regions", facetOptions(found.region, value => label("region:" + value)), route.query.region);
  fillSelect(el("#f-vendor"), "All vendors", facetOptions(found.vendor, plain), route.query.vendor);
  fillSelect(el("#f-product"), "All products", facetOptions(found.product, plain), route.query.product);
  fillSelect(el("#f-actor"), "All actors", facetOptions(found.actor, plain), route.query.actor);
  fillSelect(el("#f-malware"), "All malware", facetOptions(found.malware, plain), route.query.malware);
  fillSelect(el("#f-cwe"), "All weaknesses", facetOptions(found.cwe, value => value), route.query.cwe);
  fillSelect(el("#f-tech"), "All techniques", facetOptions(found.tech, value => value), route.query.tech);
  fillSelect(el("#f-source"), "All sources", facetOptions(found.source, (value, entry) => entry.label), route.query.source);
  const first = store.state.mode === "v7" ? Number(store.state.index.window.history_start.slice(0, 4)) : 1998;
  const last = Number(store.contentDate().slice(0, 4));
  const years = [];
  for (let year = last; year >= first; year--) years.push({ value: String(year), label: String(year) });
  fillSelect(el("#f-year"), "Live window", years, route.query.year);
  const months = [];
  for (let month = 1; month <= 12; month++) { const value = String(month).padStart(2, "0"); months.push({ value, label: route.query.year ? monthLabel(route.query.year + "-" + value) : value }); }
  fillSelect(el("#f-month"), "All months", months, route.query.month);
}

export async function renderExplore(ctx) {
  const { route, el, store } = ctx;
  el("#explore-title").textContent = TITLES[route.view] || TITLES.explore;
  el("#explore").dataset.view = route.view;
  syncControls(ctx);
  const paths = store.articlePaths(route);
  const indexRequest = store.cveIndex().catch(() => null);
  const paint = cveIndex => {
    if (!ctx.current()) return;
    const rows = store.rows(paths);
    fillFilters(ctx, rows);
    const matching = filterRows(rows, route, { cveIndex, contentDate: store.contentDate() });
    const page = pager(el("#pager"), route, matching.length);
    el("#results").replaceChildren(...matching.slice(page.start, page.start + 25).map(row => resultCard(row, route, cveIndex)));
    const waiting = paths.filter(path => !store.loaded([path])).length;
    const intro = INTROS[route.view] ? INTROS[route.view] + " " : "";
    el("#results-status").textContent = intro + count(matching.length, "entry", "entries") + " in " + scopeText(route, store) + ". Content date " + dateLabel(store.contentDate()) + "." +
      (waiting ? " Reading " + count(waiting, "more file") + "." : "");
    if (!matching.length && !waiting) el("#results").append(node("li", "empty", rows.length ? "No loaded entry matches. Clear a filter or choose another year." : "No entries in this date range."));
  };
  if (!store.loaded(paths)) el("#results-status").textContent = "Reading " + count(paths.length, "file") + " for " + scopeText(route, store) + ".";
  const [cveIndex] = await Promise.all([indexRequest, store.ensure(paths.slice(0, 1))]);
  paint(cveIndex);
  await store.ensure(paths, () => paint(cveIndex));
  paint(cveIndex);
  return { rows: store.rows(paths), cveIndex };
}

// Wires the form once. Every change replaces the address, so Back leaves the view, not each keystroke.
export function bindExplore(ctx) {
  const { el, navigate, route: current } = ctx;
  let timer = null;
  el("#explore-form").addEventListener("submit", event => { event.preventDefault(); clearTimeout(timer); navigate(withQuery(current(), { q: el("#q").value }), { replace: true }); });
  el("#q").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => navigate(withQuery(current(), { q: el("#q").value }), { replace: true }), 250); });
  for (const key of SELECTS) {
    const select = el("#f-" + key);
    select.addEventListener("change", () => {
      const changes = { [key]: select.value || null };
      if (key === "year") changes.month = null;
      navigate(withQuery(current(), changes), { replace: true });
    });
  }
  el("#f-range").addEventListener("change", () => navigate(withQuery(current(), { range: el("#f-range").value }), { replace: true }));
  el("#f-sort").addEventListener("change", () => navigate(withQuery(current(), { sort: el("#f-sort").value }), { replace: true }));
  for (const key of ["kev", "action"]) el("#f-" + key).addEventListener("change", () => navigate(withQuery(current(), { [key]: el("#f-" + key).checked ? "1" : null }), { replace: true }));
  el("#f-reset").addEventListener("click", () => {
    const route = current();
    navigate({ view: route.view, id: null, query: route.query.sort ? { sort: route.query.sort } : {} }, { replace: true });
  });
  el("#filters-toggle").addEventListener("click", () => {
    const rail = el("#filter-rail");
    const open = !rail.classList.contains("open");
    rail.classList.toggle("open", open);
    el("#filters-toggle").setAttribute("aria-expanded", String(open));
  });
}

function tagList(title, items, render) {
  if (!items.length) return null;
  const block = node("section", "detail-block");
  block.append(node("h3", "", title));
  const list = node("ul", "detail-list");
  for (const item of items) list.append(render(item));
  block.append(list);
  return block;
}

const confidence = item => " (" + item[item.length - 1] + " confidence, " + item[item.length - 2].replaceAll("-", " ") + ")";

// The detail dialog for one entry (open=<id>): every date, tag, method and confidence, and links.
// lib is the library-door module (common.js loadLibrary); without it no library door is shown.
export function recordDetail(row, route, cveIndex, lib = null) {
  const body = [];
  const head = node("section", "detail-block");
  head.append(node("p", "card-meta", (KIND_LABELS[row.kind] || row.kind) + " · " + row.source_name + " · " + label("class:" + (classOf(row) || "unknown"))));
  const title = node("p", "detail-title"); title.append(link(row.title + " (opens the publisher)", row.url)); head.append(title);
  if (row.summary) head.append(node("p", "", row.summary + (row.kind === "kev" ? " (CISA's catalog text)" : "")));
  body.push(head);
  const dates = node("section", "detail-block");
  dates.append(node("h3", "", "Dates"),
    node("p", "", dateBasisLabel(row) + ": " + (row.primary_date ? stamp(row.primary_date.length === 10 ? row.primary_date + "T00:00:00Z" : row.primary_date) : "not recorded")),
    node("p", "", "Publisher date: " + (row.published_at ? dateLabel(row.published_at.slice(0, 10)) : "not recorded") + " · Event date: " + (row.event_date ? dateLabel(row.event_date.slice(0, 10)) : "not recorded")),
    node("p", "muted", "Date basis: " + (row.date_basis || "not stated") + ". Publication, event and catalog dates are kept separate."));
  if (row.t.kev) dates.append(node("p", "", "KEV catalog: added " + (row.t.kev.added ? dateLabel(row.t.kev.added) : "date not recorded") + (row.t.kev.due ? ", federal due date " + dateLabel(row.t.kev.due) : "") + ". The due date is CISA's federal requirement, not a deadline for you."));
  body.push(dates);
  if (row.cves.length) {
    const block = node("section", "detail-block");
    block.append(node("h3", "", "CVEs on this entry"));
    const chips = node("p", "chips");
    for (const cve of row.cves) chips.append(routeLink(cve, formatRoute({ view: "cve", id: cve, query: {} }), "chip chip-cve"));
    block.append(chips);
    const records = node("p", "muted", "CVE.org records: ");
    row.cves.slice(0, 10).forEach((cve, position) => { if (position) records.append(", "); records.append(cveOrgLink(cve, cve)); });
    block.append(records);
    const flags = [];
    if (kevLinked(row, cveIndex)) flags.push("KEV-linked: at least one CVE is in CISA's KEV catalog.");
    if (requiredAction(row, cveIndex)) flags.push("CISA required action: at least one CVE carries CISA's requiredAction text.");
    for (const flag of flags) block.append(node("p", "muted", flag));
    body.push(block);
  }
  const exploitation = row.t.exploitation;
  const tags = node("section", "detail-block");
  tags.append(node("h3", "", "Exploitation"), node("p", "", (EXPLOITATION_LABELS[row.exploited] || row.exploited) + (exploitation ? " (basis " + exploitation[1].replaceAll("-", " ") + ", " + exploitation[2] + " confidence)" : "") + ". Unknown never means safe."));
  if (row.t.cvss) tags.append(node("p", "", "CVSS " + row.t.cvss.base.toFixed(1) + (row.t.cvss.version ? " (version " + row.t.cvss.version + ")" : "") + (row.t.cvss.scorer ? ", scored by " + row.t.cvss.scorer : "") + (row.t.cvss.cve ? ", for " + row.t.cvss.cve : "") + ". Scores across versions are not normalized."));
  body.push(tags);
  // An entry opened from a year (a History card's Details link) keeps that year on its entity
  // links, so the Explorer they open still holds the history row they came from.
  const year = route && route.query && route.query.year ? { year: route.query.year } : {};
  const entity = (field, key) => item => {
    const entry = node("li");
    entry.append(routeLink(label(item[0]), formatRoute({ view: "explore", id: null, query: { [key]: item[0].replace(/^[a-z]+:/, ""), ...year } })), node("span", "muted", confidence(item)));
    const door = libraryDoor(lib, item[0], "library page");
    if (door) entry.append(node("span", "", " · "), door);
    return entry;
  };
  const blocks = [
    tagList("Event type", row.t.event_type, item => node("li", "", label("event:" + item[0]) + confidence(item))),
    tagList("Vendors", row.t.vendor, entity("vendor", "vendor")),
    tagList("Products", row.t.product, entity("product", "product")),
    tagList("Actors", row.t.actor, entity("actor", "actor")),
    tagList("Malware", row.t.malware, entity("malware", "malware")),
    tagList("Sectors", row.t.sector, entity("sector", "sector")),
    tagList("Regions", row.t.region, item => node("li", "", label("region:" + item[0]) + " as " + item[1] + confidence(item))),
    tagList("Weaknesses (CWE)", row.t.cwe, item => node("li", "", item[0] + confidence(item)))
  ];
  for (const block of blocks) if (block) body.push(block);
  if (row.t.attack.length) {
    const block = node("section", "detail-block");
    block.append(node("h3", "", "ATT&CK techniques reached through CWE and CAPEC"), node("p", "muted", "Low confidence: these are taxonomy paths from the row's weaknesses, not observed attacker behaviour."), node("p", "mono", row.t.attack.join(", ")));
    body.push(block);
  }
  const references = node("section", "detail-block");
  references.append(node("h3", "", "Links"));
  const list = node("ul", "detail-list");
  const original = node("li"); original.append(link("Original publisher record", row.url)); list.append(original);
  for (const reference of row.references) {
    const item = node("li"); item.append(link(reference.label, reference.url));
    const door = pinnedDoor(lib, reference.url);
    if (door) item.append(node("span", "", " · "), door);
    list.append(item);
  }
  references.append(list);
  body.push(references);
  return body;
}
