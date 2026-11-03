// Building blocks shared by the views: result cards, chips, the pager, select filling and the
// doors to the TeamStarWolf library.
import { CVE_ID, LIST_VIEWS, formatRoute, withQuery } from "../router.js";
import { kevLinked } from "../filters.js";
import { count, dateLabel, humanize, link, node, routeLink, safeUrl } from "../util.js";
import { pageSize } from "../limits.js";

export const KIND_LABELS = { advisory: "Advisory", research: "Research", reporting: "Reporting", incident: "Incident", kev: "KEV entry", filing: "Filing", bulletin: "Bulletin", note: "Vulnerability note" };
export const EXPLOITATION_LABELS = { known: "Known exploited", reported: "Reported exploited", unknown: "Exploitation unknown" };

// Display labels from the generated vocabulary module, once it has loaded.
let labels = null;
export function setLabels(value) { labels = value; }
export function label(id) { return (labels && Object.hasOwn(labels, id) && labels[id]) || humanize(id); }

// The library doors. site/js/library.js is generated from the vendored vocabulary's
// library_path and library_anchor (python -m intelligence_hub.site labels); the page renders
// no library link from anywhere else, and every one must start with LIBRARY_PREFIX and pass
// safeUrl. The module loads on first use; when it cannot load, no door is shown.
export const LIBRARY_PREFIX = "https://teamstarwolf.github.io/TeamStarWolf/#/";
const NO_LIBRARY = { LINKS: {}, PINNED: {}, KEV: {}, PRODUCTS: {} };
let library = null;
export function loadLibrary() {
  if (!library) library = import("../library.js").then(module => ({ LINKS: module.LINKS, PINNED: module.PINNED, KEV: module.KEV, PRODUCTS: module.PRODUCTS }), () => NO_LIBRARY);
  return library;
}
export function libraryUrl(value) {
  const url = safeUrl(value);
  return url && url.startsWith(LIBRARY_PREFIX) ? url : null;
}
// A door for a vocabulary id, or null when the library has no page for it.
export function libraryDoor(lib, id, text) {
  const url = lib && Object.hasOwn(lib.LINKS, id) ? libraryUrl(lib.LINKS[id]) : null;
  return url ? link(text, url, "library-link") : null;
}
// The rendered library page beside a commit-pinned library evidence link, or null.
export function pinnedDoor(lib, evidenceUrl, text = "Read it on the library site") {
  const url = lib && Object.hasOwn(lib.PINNED, evidenceUrl) ? libraryUrl(lib.PINNED[evidenceUrl]) : null;
  return url ? link(text, url, "library-link") : null;
}
// The CVE Program's record page for a CVE id.
export function cveOrgLink(cve, text = "CVE.org record") {
  return CVE_ID.test(cve) ? link(text, "https://www.cve.org/CVERecord?id=" + cve) : null;
}

// The route a card's chips use: the list view it sits in, or the Explorer when the card sits on
// another view. On a History year page the Explorer keeps the row's year, so the history row the
// reader was looking at is in scope; on a vendor, actor or malware page it is the live window.
// The Details link always keeps the row's year, so the opened row is in scope.
const YEAR = /^\d{4}$/;
export function listRoute(route, row = null) {
  if (Object.hasOwn(LIST_VIEWS, route.view)) return route;
  const year = route.view === "history" ? (row && YEAR.test(row.year) ? row.year : YEAR.test(route.id || "") ? route.id : null) : null;
  return { view: "explore", id: null, query: year ? { year } : {} };
}
export function detailsRoute(row, route) {
  if (Object.hasOwn(LIST_VIEWS, route.view)) return withQuery(route, { open: row.id }, true);
  return { view: "explore", id: null, query: { ...(YEAR.test(row.year) ? { year: row.year } : {}), open: row.id } };
}

export function dateBasisLabel(row) {
  if (!row.time) return "Date unknown";
  if (row.date_basis === "event") return "Event date";
  if (row.kind === "kev") return "Catalog added";
  if (row.date_basis.startsWith("publisher update")) return "Updated";
  return "Published";
}

// One result row: kind, date and source, the publisher headline as a link, then chips.
export function resultCard(row, route, cveIndex) {
  const card = node("li", "card kind-" + row.kind);
  card.dataset.id = row.id;
  const meta = node("p", "card-meta");
  meta.append(node("span", "badge badge-" + row.kind, KIND_LABELS[row.kind] || row.kind), node("span", "card-date", (row.day ? dateLabel(row.day) : "Date unknown") + " · " + dateBasisLabel(row)), node("span", "card-source", row.source_name));
  const title = node("h3", "card-title");
  title.append(link(row.title, row.url));
  card.append(meta, title);
  const chips = node("p", "chips");
  for (const cve of row.cves.slice(0, 4)) chips.append(routeLink(cve, formatRoute({ view: "cve", id: cve, query: {} }), "chip chip-cve"));
  if (row.cves.length > 4) chips.append(node("span", "chip chip-more", "+" + (row.cves.length - 4) + " CVEs"));
  if (kevLinked(row, cveIndex) && row.kind !== "kev") chips.append(node("span", "chip chip-kev", "KEV-linked"));
  if (row.exploited !== "unknown") chips.append(node("span", "chip chip-exp-" + row.exploited, EXPLOITATION_LABELS[row.exploited]));
  if (row.score !== null) chips.append(node("span", "chip", "CVSS " + row.score.toFixed(1) + (row.t.cvss && row.t.cvss.version ? " (v" + row.t.cvss.version + ")" : "")));
  for (const [field, key] of [["vendor", "vendor"], ["product", "product"], ["actor", "actor"], ["malware", "malware"]]) {
    for (const item of row.t[field].slice(0, 2)) chips.append(routeLink(label(item[0]), formatRoute(withQuery(listRoute(route, row), { [key]: item[0].replace(/^[a-z]+:/, "") })), "chip chip-entity"));
  }
  const details = routeLink("Details", formatRoute(detailsRoute(row, route)), "card-details");
  details.setAttribute("aria-label", "Details for " + row.title.slice(0, 120));
  chips.append(details);
  card.append(chips);
  return card;
}

// Replaces a select's options only when the set of options changed, so focus and the open
// state of a select survive a re-render. The current value stays selectable even at zero.
export function fillSelect(select, allLabel, options, value) {
  const choices = [...options];
  if (value && !choices.some(choice => choice.value === value)) choices.push({ value, label: value + " (0 loaded)" });
  const signature = JSON.stringify([allLabel, choices]);
  if (select.dataset.signature !== signature) {
    select.replaceChildren(...[{ value: "", label: allLabel }, ...choices].map(choice => { const option = node("option", "", choice.label); option.value = choice.value; return option; }));
    select.dataset.signature = signature;
  }
  select.value = value || "";
}

export function facetOptions(map, labelOf, limit = 400) {
  return [...map].sort((a, b) => b[1].count - a[1].count || String(labelOf(a[0], a[1])).localeCompare(String(labelOf(b[0], b[1]))))
    .slice(0, limit).map(([value, entry]) => ({ value, label: labelOf(value, entry) + " (" + entry.count.toLocaleString("en-US") + ")" }));
}

// "Page 2 of 9" with previous and next links that keep every other key.
export function pager(target, route, total) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.min(pages, Number(route.query.page || 1));
  const parts = [];
  if (page > 1) parts.push(routeLink("Previous", formatRoute(withQuery(route, { page: page - 1 === 1 ? null : page - 1 }, true)), "pager-link"));
  parts.push(node("span", "pager-status", "Page " + page.toLocaleString("en-US") + " of " + pages.toLocaleString("en-US")));
  if (page < pages) parts.push(routeLink("Next", formatRoute(withQuery(route, { page: page + 1 }, true)), "pager-link"));
  target.replaceChildren(...(total > pageSize ? parts : []));
  return { page, pages, start: (page - 1) * pageSize };
}

export function section(title, className = "panel") {
  const item = node("section", className);
  item.append(node("h2", "panel-title", title));
  return item;
}

export function definitionList(pairs) {
  const list = node("dl", "facts");
  for (const [term, value] of pairs) { const row = node("div"); row.append(node("dt", "", term), node("dd", "", value)); list.append(row); }
  return list;
}

export { count };
