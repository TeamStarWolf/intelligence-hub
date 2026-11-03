// Building blocks shared by the views: result cards, chips, the pager and select filling.
import { formatRoute, withQuery } from "../router.js";
import { kevLinked } from "../filters.js";
import { count, dateLabel, humanize, link, node, routeLink } from "../util.js";
import { pageSize } from "../limits.js";

export const KIND_LABELS = { advisory: "Advisory", research: "Research", reporting: "Reporting", incident: "Incident", kev: "KEV entry", filing: "Filing", bulletin: "Bulletin", note: "Vulnerability note" };
export const EXPLOITATION_LABELS = { known: "Known exploited", reported: "Reported exploited", unknown: "Exploitation unknown" };

// Display labels from the generated vocabulary module, once it has loaded.
let labels = null;
export function setLabels(value) { labels = value; }
export function label(id) { return (labels && Object.hasOwn(labels, id) && labels[id]) || humanize(id); }

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
    for (const item of row.t[field].slice(0, 2)) chips.append(routeLink(label(item[0]), formatRoute(withQuery(route, { [key]: item[0].replace(/^[a-z]+:/, "") })), "chip chip-entity"));
  }
  const details = routeLink("Details", formatRoute(withQuery(route, { open: row.id }, true)), "card-details");
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
