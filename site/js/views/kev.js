// Known exploited: CISA's KEV ledger by dateAdded, with the directive each entry's
// requiredAction cites. Every text field is CISA's, unchanged.
import { defaultRange, formatRoute, withQuery } from "../router.js";
import { kevLedger } from "../filters.js";
import { count, dateLabel, link, node, routeLink } from "../util.js";
import { pager } from "./common.js";
import { pageSize } from "../limits.js";

function controls(ctx) {
  const { route, navigate, store } = ctx;
  const form = node("form", "view-controls");
  form.setAttribute("role", "search");
  const search = node("input", "search-input");
  search.type = "search"; search.maxLength = 200; search.placeholder = "Search CVE, vendor, product or directive"; search.value = route.query.q || ""; search.setAttribute("aria-label", "Search the KEV ledger");
  form.addEventListener("submit", event => { event.preventDefault(); navigate(withQuery(route, { q: search.value }), { replace: true }); });
  const range = node("select");
  range.setAttribute("aria-label", "Added in");
  for (const [value, text] of [["30", "Added in the last 30 days"], ["7", "Last 7 days"], ["90", "Last 90 days"], ["365", "Last 365 days"], ["all", "Every year"]]) { const option = node("option", "", text); option.value = value; range.append(option); }
  range.value = route.query.range || defaultRange("kev");
  range.disabled = Boolean(route.query.year);
  range.addEventListener("change", () => navigate(withQuery(route, { range: range.value }), { replace: true }));
  const year = node("select");
  year.setAttribute("aria-label", "Year added");
  const none = node("option", "", "Any year"); none.value = ""; year.append(none);
  for (const path of store.listed("kev/").sort().reverse()) { const value = path.slice(4, 8); const option = node("option", "", value); option.value = value; year.append(option); }
  year.value = route.query.year || "";
  year.addEventListener("change", () => navigate(withQuery(route, { year: year.value || null }), { replace: true }));
  const sort = node("select");
  sort.setAttribute("aria-label", "Sort");
  for (const [value, text] of [["added-desc", "Newest additions"], ["added-asc", "Oldest additions"], ["due-asc", "Due date, soonest"], ["due-desc", "Due date, latest"], ["cve-desc", "CVE descending"], ["cve-asc", "CVE ascending"]]) { const option = node("option", "", text); option.value = value; sort.append(option); }
  sort.value = route.query.sort || "added-desc";
  sort.addEventListener("change", () => navigate(withQuery(route, { sort: sort.value }), { replace: true }));
  const button = node("button", "bar-button", "Search"); button.type = "submit";
  form.append(search, button, range, year, sort);
  return form;
}

export function kevTable(rows) {
  const table = node("table", "data-table");
  table.append(node("caption", "", "CISA KEV entries. Name, description and required action are CISA's text. Date added is the catalog date, not disclosure or first exploitation."));
  const head = node("tr");
  for (const label of ["CVE", "Vendor and product", "Added", "Due", "Directive", "Ransomware", "CWE"]) { const cell = node("th", "", label); cell.scope = "col"; head.append(cell); }
  const thead = node("thead"); thead.append(head);
  const body = node("tbody");
  for (const row of rows) {
    const tr = node("tr");
    const id = node("td"); id.append(routeLink(row.cve, formatRoute({ view: "cve", id: row.cve, query: {} }), "chip chip-cve"));
    const what = node("td"); what.append(node("strong", "", row.vendor + " " + row.product), node("span", "cell-note", row.name));
    const action = node("details", "cell-details"); action.append(node("summary", "", "Required action"), node("p", "", row.required_action), node("p", "muted", row.short_description));
    for (const url of row.notes_urls.slice(0, 4)) { const item = node("p"); item.append(link("CISA note link", url)); action.append(item); }
    what.append(action);
    tr.append(id, what, node("td", "", dateLabel(row.date_added)), node("td", "", row.due_date ? dateLabel(row.due_date) : "Not set"), node("td", "", row.directive || "None cited"), node("td", "", row.ransomware), node("td", "", row.cwe.join(", ") || "None listed"));
    body.append(tr);
  }
  table.append(thead, body);
  return table;
}

export async function renderKev(ctx) {
  const { target, store, route } = ctx;
  const title = node("h1", "view-title", "Known exploited vulnerabilities");
  const intro = node("p", "view-intro", "CISA's Known Exploited Vulnerabilities catalog, by the date CISA added each entry. The KEV catalog is published by CISA under CC0 1.0.");
  if (store.state.mode === "legacy") { target.replaceChildren(title, intro, node("p", "notice-inline", "The KEV ledger is part of the schema 7 data, which this fallback does not have. KEV entries still appear in the Explorer as kind KEV entry.")); return; }
  const status = node("p", "results-status", "Reading the KEV ledger.");
  status.setAttribute("role", "status");
  const table = node("div", "table-wrap");
  const pages = node("nav", "pager"); pages.setAttribute("aria-label", "KEV pages");
  target.replaceChildren(title, intro, controls(ctx), status, table, pages);
  const paths = store.kevPaths(route);
  await store.ensure(paths);
  if (!ctx.current()) return;
  const rows = kevLedger(store.kevRows(paths), route.query, store.contentDate());
  const page = pager(pages, route, rows.length);
  table.replaceChildren(kevTable(rows.slice(page.start, page.start + pageSize)));
  status.textContent = count(rows.length, "KEV entry", "KEV entries") + " match. Content date " + dateLabel(store.contentDate()) + ".";
  return rows;
}
