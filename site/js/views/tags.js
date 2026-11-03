// Tags (#/tags): every vocabulary value that tags at least one loaded entry, with its count and
// a door: a page for vendors, actors and malware, otherwise the Explorer filter for that value.
// Values with no entry in the scope are not listed. The scope is the live window, or one year
// (that year's live months and history rows) with ?year=.
import { formatRoute, withQuery } from "../router.js";
import { facets, kevLinked } from "../filters.js";
import { count, node, routeLink } from "../util.js";
import { EXPLOITATION_LABELS, KIND_LABELS, label } from "./common.js";
import { historyYears } from "./history.js";

const explore = query => formatRoute({ view: "explore", id: null, query });

// Field, heading, how a value reads, and where it leads.
export const TAG_FIELDS = [
  ["kind", "Kind", value => KIND_LABELS[value] || value, (value, year) => explore({ kind: value, ...year })],
  ["class", "Source class", value => label("class:" + value), (value, year) => explore({ class: value, ...year })],
  ["event", "Event type", value => label("event:" + value), (value, year) => explore({ event: value, ...year })],
  ["exp", "Exploitation", value => EXPLOITATION_LABELS[value] || value, (value, year) => explore({ exp: value, ...year })],
  ["vendor", "Vendor", value => label("vendor:" + value), value => formatRoute({ view: "vendor", id: value, query: {} })],
  ["product", "Product", value => label("product:" + value), (value, year) => explore({ product: value, ...year })],
  ["actor", "Actor", value => label("actor:" + value), value => formatRoute({ view: "actor", id: value, query: {} })],
  ["malware", "Malware and tools", value => label("malware:" + value), value => formatRoute({ view: "malware", id: value, query: {} })],
  ["sector", "Sector", value => label("sector:" + value), (value, year) => explore({ sector: value, ...year })],
  ["region", "Region", value => label("region:" + value), (value, year) => explore({ region: value, ...year })],
  ["cwe", "Weakness (CWE)", value => value, (value, year) => explore({ cwe: value, ...year })],
  ["tech", "ATT&CK technique (low confidence, through CWE and CAPEC)", value => value, (value, year) => explore({ tech: value, ...year })],
  ["source", "Source", (value, entry) => entry.label || value, (value, year) => explore({ source: value, ...year })]
];

// [{field, title, values: [{value, text, count, href}]}] for rows, zero-count values excluded.
export function tagIndex(rows, cveIndex, year = null) {
  const found = facets(rows);
  const scope = year ? { year } : {};
  const groups = [];
  for (const [field, title, text, href] of TAG_FIELDS) {
    const values = [...found[field]].filter(([, entry]) => entry.count > 0)
      .map(([value, entry]) => ({ value, text: String(text(value, entry)), count: entry.count, href: href(value, scope) }))
      .sort((a, b) => b.count - a.count || a.text.localeCompare(b.text));
    if (values.length) groups.push({ field, title, values });
  }
  const linked = rows.filter(row => kevLinked(row, cveIndex)).length;
  if (linked) groups.splice(4, 0, { field: "kev", title: "KEV-linked", values: [{ value: "1", text: "KEV-linked", count: linked, href: explore({ kev: "1", ...scope }) }] });
  return groups;
}

export async function renderTags(ctx) {
  const { target, store, route, navigate } = ctx;
  const status = node("p", "results-status", "Reading the entries for this scope.");
  status.setAttribute("role", "status");
  const form = node("form", "view-controls");
  const choose = node("label", "field");
  const select = node("select");
  for (const value of ["", ...historyYears(store).map(String)]) { const option = node("option", "", value || "Live window"); option.value = value; select.append(option); }
  select.value = route.query.year || "";
  select.addEventListener("change", () => navigate(withQuery(route, { year: select.value || null }), { replace: true }));
  choose.append(node("span", "", "Count tags in"), select);
  form.append(choose);
  form.addEventListener("submit", event => event.preventDefault());
  target.replaceChildren(node("h1", "view-title", "Tags"),
    node("p", "view-intro", "Every tag value on at least one entry, with its count. Vendors, actors and malware open their own page; every other value opens the Explorer filtered to it. Values with no entry in this scope are not listed."), form, status);
  const paths = store.articlePaths({ view: "explore", id: null, query: route.query.year ? { year: route.query.year } : {} });
  const [cveIndex] = await Promise.all([store.cveIndex().catch(() => null), store.ensure(paths, () => { if (ctx.current()) status.textContent = "Still reading."; })]);
  if (!ctx.current()) return;
  const rows = store.rows(paths);
  const groups = tagIndex(rows, cveIndex, route.query.year || null);
  for (const group of groups) {
    const block = node("section", "panel tag-group");
    block.dataset.field = group.field;
    block.append(node("h2", "panel-title", group.title + " (" + count(group.values.length, "value") + ")"));
    const chips = node("p", "chips");
    for (const item of group.values) chips.append(routeLink(item.text + " " + item.count.toLocaleString("en-US"), item.href, "chip chip-entity"));
    if (group.values.length > 40) {
      const more = node("details", "cell-details");
      more.append(node("summary", "", "Show all " + group.values.length.toLocaleString("en-US") + " values"), chips);
      block.append(more);
    } else block.append(chips);
    target.append(block);
  }
  status.textContent = count(rows.length, "entry", "entries") + " in " + (route.query.year ? route.query.year + " (live months and history rows)" : "the live window") + "; " + count(groups.reduce((total, group) => total + group.values.length, 0), "tag value") + ".";
  return groups;
}
