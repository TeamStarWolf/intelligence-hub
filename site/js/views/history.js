// History (#/history and #/history/<year>): security events from 1998 on, one page per year.
// The year index needs only index.json and coverage.json; a year page reads that year's history
// shard. Every year page opens with the per-source coverage statement, so a quiet year is never
// read as a year when nothing happened.
import { formatRoute, withQuery } from "../router.js";
import { sortRows } from "../filters.js";
import { count, link, monthLabel, node, routeLink } from "../util.js";
import { pageSize } from "../limits.js";
import { pager, resultCard, section } from "./common.js";

export const STATUS_LABELS = { complete: "complete", filtered: "filtered", partial: "partial", sample: "sample", gap: "gap", unreachable: "unreachable" };
const STATUS_ORDER = ["complete", "filtered", "partial", "sample", "gap", "unreachable"];

export function historyYears(store) {
  const first = store.state.mode === "v7" ? Number(store.state.index.window.history_start.slice(0, 4)) : 1998;
  const last = Number(store.contentDate().slice(0, 4));
  const years = [];
  for (let year = last; year >= first; year--) years.push(year);
  return years;
}

function sourceNames(coverage) { return new Map(coverage.sources.map(source => [source.source_id, source.name])); }

// "3 complete, 1 filtered, 12 gap" for one year's coverage rows.
export function statusSummary(rows) {
  const counts = new Map();
  for (const row of rows) counts.set(row.status, (counts.get(row.status) || 0) + 1);
  return STATUS_ORDER.filter(status => counts.has(status)).map(status => counts.get(status) + " " + STATUS_LABELS[status]).join(", ");
}

// One coverage statement as a sentence: who, the status, how many rows, and why.
export function coverageSentence(row, name) {
  const rows = row.admitted ? ", " + count(row.admitted, "row") + (row.upstream_count !== null && row.upstream_count !== row.admitted ? " of " + row.upstream_count.toLocaleString("en-US") + " listed" : "") : "";
  const why = row.reason || row.filter;
  return name + ": " + STATUS_LABELS[row.status] + rows + (why ? " (" + why + ")" : "") + ".";
}

export function yearCoverage(coverage, year) {
  const names = sourceNames(coverage);
  return coverage.rows.filter(row => row.year === year)
    .map(row => ({ ...row, name: names.get(row.source_id) || row.source_id }))
    .sort((a, b) => b.admitted - a.admitted || STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) || a.name.localeCompare(b.name));
}

export async function renderHistory(ctx) {
  return ctx.route.id ? renderYear(ctx) : renderIndex(ctx);
}

async function renderIndex(ctx) {
  const { target, store } = ctx;
  const status = node("p", "results-status", "Reading the coverage statements.");
  status.setAttribute("role", "status");
  target.replaceChildren(node("h1", "view-title", "History"),
    node("p", "view-intro", "Security events from 1998 to today, one page per year. Each year page says which sources it covers and how completely, so a quiet year is never mistaken for a year without incidents."), status);
  const coverage = await store.coverage();
  if (!ctx.current()) return;
  const table = node("table", "data-table");
  table.append(node("caption", "", "History rows per year, the sources that supplied them and the coverage statuses recorded for that year. Live entries for a year are in the Explorer."));
  const head = node("tr");
  for (const text of ["Year", "History rows", "Sources with rows", "Coverage statements"]) { const cell = node("th", "", text); cell.scope = "col"; head.append(cell); }
  const thead = node("thead"); thead.append(head);
  const body = node("tbody");
  for (const year of historyYears(store)) {
    const entry = store.entry("history/" + year + ".json");
    const rows = coverage.status === "ok" ? yearCoverage(coverage, year) : [];
    const supplied = rows.filter(row => row.admitted > 0);
    const tr = node("tr");
    const cell = node("th"); cell.scope = "row"; cell.append(routeLink(String(year), formatRoute({ view: "history", id: String(year), query: {} })));
    const sources = node("td", "", supplied.length ? supplied.slice(0, 3).map(row => row.name + " " + row.admitted.toLocaleString("en-US")).join(", ") + (supplied.length > 3 ? ", and " + count(supplied.length - 3, "more source") : "") : "None");
    tr.append(cell, node("td", "", entry ? entry.rows.toLocaleString("en-US") : "No shard"), sources, node("td", "", rows.length ? statusSummary(rows) : "Not published"));
    body.append(tr);
  }
  table.append(thead, body);
  const wrap = node("div", "table-wrap"); wrap.append(table);
  status.textContent = coverage.status === "ok" ? count(coverage.sources.length, "history source") + " with a coverage statement for every year from " + coverage.first_year + " to " + coverage.end_year + "." : "Coverage statements are not published in this snapshot: " + (coverage.note || "no reason recorded") + ".";
  const method = node("p", "more"); method.append(routeLink("The full source-by-year coverage matrix", formatRoute({ view: "sources", id: null, query: {} }), "more-link"), node("span", "muted", " · "), routeLink("What each status means", formatRoute({ view: "method", id: null, query: {} }), "more-link"));
  target.append(wrap, method);
  return coverage;
}

function monthStrip(route, rows) {
  const counts = new Map();
  for (const row of rows) counts.set(row.month, (counts.get(row.month) || 0) + 1);
  const strip = node("p", "chips month-strip");
  strip.setAttribute("aria-label", "Rows per month");
  const months = [...Array(12).keys()].map(month => String(month + 1).padStart(2, "0"));
  for (const month of [...months, ...(counts.has("unknown") ? ["unknown"] : [])]) {
    const total = counts.get(month) || 0;
    const text = (month === "unknown" ? "Date unknown" : monthLabel(route.id + "-" + month).split(" ")[0]) + " " + total.toLocaleString("en-US");
    if (!total || month === "unknown") { strip.append(node("span", "chip chip-quiet", text)); continue; }
    const chosen = route.query.month === month;
    const chip = routeLink(text, formatRoute(withQuery(route, { month: chosen ? null : month })), "chip" + (chosen ? " chip-on" : ""));
    if (chosen) chip.setAttribute("aria-current", "true");
    strip.append(chip);
  }
  return strip;
}

function sourceTable(route, rows) {
  const counts = new Map();
  for (const row of rows) { const entry = counts.get(row.source_id) || { name: row.source_name, count: 0 }; entry.count++; counts.set(row.source_id, entry); }
  const table = node("table", "data-table");
  table.append(node("caption", "", "Rows this year by source. Choose a source to list only its rows."));
  const head = node("tr");
  for (const text of ["Source", "Rows"]) { const cell = node("th", "", text); cell.scope = "col"; head.append(cell); }
  const thead = node("thead"); thead.append(head);
  const body = node("tbody");
  for (const [id, entry] of [...counts].sort((a, b) => b[1].count - a[1].count || a[1].name.localeCompare(b[1].name))) {
    const tr = node("tr");
    const name = node("td");
    const chosen = route.query.source === id;
    name.append(routeLink(entry.name, formatRoute(withQuery(route, { source: chosen ? null : id }))));
    if (chosen) name.append(node("span", "cell-note", "Showing only this source; choose it again to show every source."));
    tr.append(name, node("td", "", entry.count.toLocaleString("en-US")));
    body.append(tr);
  }
  table.append(thead, body);
  const wrap = node("div", "table-wrap"); wrap.append(table);
  return wrap;
}

async function renderYear(ctx) {
  const { target, store, route } = ctx;
  const year = Number(route.id);
  const years = historyYears(store);
  const nav = node("nav", "year-nav");
  nav.setAttribute("aria-label", "Other years");
  nav.append(routeLink("All years", formatRoute({ view: "history", id: null, query: {} })));
  if (years.includes(year - 1)) nav.append(routeLink("Previous year, " + (year - 1), formatRoute({ view: "history", id: String(year - 1), query: {} })));
  if (years.includes(year + 1)) nav.append(routeLink("Next year, " + (year + 1), formatRoute({ view: "history", id: String(year + 1), query: {} })));
  const status = node("p", "results-status", "Reading the coverage statements and the " + year + " history file.");
  status.setAttribute("role", "status");
  const statement = section("Coverage this year");
  statement.append(node("p", "muted", "Reading the coverage statements."));
  target.replaceChildren(nav, node("h1", "view-title", "History: " + year), statement, status);
  const path = "history/" + year + ".json";
  const listed = Boolean(store.entry(path));
  const [coverage] = await Promise.all([store.coverage(), listed ? store.ensure([path]) : Promise.resolve([])]);
  if (!ctx.current()) return;
  statement.replaceChildren(node("h2", "panel-title", "Coverage this year"));
  if (coverage.status === "ok") {
    const rows = yearCoverage(coverage, year);
    const supplied = rows.filter(row => row.admitted > 0 || ["partial", "filtered", "sample"].includes(row.status));
    const silent = rows.filter(row => !supplied.includes(row));
    const list = node("ul", "detail-list");
    for (const row of supplied) list.append(node("li", "", coverageSentence(row, row.name)));
    if (supplied.length) statement.append(list);
    if (silent.length) {
      const quiet = node("details", "cell-details");
      quiet.append(node("summary", "", count(silent.length, "source") + " with no rows this year (" + statusSummary(silent) + ")"));
      const more = node("ul", "detail-list");
      for (const row of silent) more.append(node("li", "", coverageSentence(row, row.name)));
      quiet.append(more);
      statement.append(quiet);
    }
    const held = coverage.held_back.filter(item => item.path === path);
    for (const item of held) statement.append(node("p", "notice-inline", count(item.rows, "row") + " from " + item.adapter + " were held back to keep this year's file inside its size bound."));
    statement.append(node("p", "muted", "Curated rows and press feeds are not part of these statements. A source's own archive can hold more than the Hub keeps."));
  } else statement.append(node("p", "muted", "Coverage statements are not published in this snapshot: " + (coverage.note || "no reason recorded") + "."));
  if (!listed) {
    status.textContent = "This snapshot has no history file for " + year + ".";
    return coverage;
  }
  const all = store.rows([path]);
  const scoped = all.filter(row => (!route.query.source || row.source_id === route.query.source) && (!route.query.month || row.month === route.query.month));
  sortRows(scoped, "date-asc");
  const pages = node("nav", "pager"); pages.setAttribute("aria-label", "History pages");
  const page = pager(pages, route, scoped.length);
  const list = node("ol", "results-list");
  list.append(...scoped.slice(page.start, page.start + pageSize).map(row => resultCard(row, route, null)));
  if (!scoped.length) list.append(node("li", "empty", "No row matches. Clear the month or source choice."));
  status.textContent = count(scoped.length, "row") + " of " + all.length.toLocaleString("en-US") + " in " + year + (route.query.month ? ", " + monthLabel(year + "-" + route.query.month) : "") + ", oldest first.";
  const explore = node("p", "more");
  explore.append(routeLink("Search and filter " + year + " in the Explorer, with that year's live entries", formatRoute({ view: "explore", id: null, query: { year: String(year) } }), "more-link"));
  const sourceBlock = node("div", "history-sources"); sourceBlock.append(sourceTable(route, all));
  target.append(monthStrip(route, all), sourceBlock, list, pages, explore);
  return { coverage, rows: scoped };
}

// The source-by-year matrix for the Sources view: one cell per source and year.
export function coverageMatrix(coverage) {
  const years = [];
  for (let year = coverage.first_year; year <= coverage.end_year; year++) years.push(year);
  const byKey = new Map(coverage.rows.map(row => [row.source_id + " " + row.year, row]));
  const table = node("table", "data-table coverage-matrix");
  table.append(node("caption", "", "Coverage by source and year. Letters: C complete, F filtered, P partial, S sample, G gap, U unreachable; the number is the rows kept. A cell's title gives the reason."));
  const head = node("tr");
  const corner = node("th", "", "Source"); corner.scope = "col"; head.append(corner);
  for (const year of years) { const cell = node("th", "", String(year)); cell.scope = "col"; head.append(cell); }
  const thead = node("thead"); thead.append(head);
  const body = node("tbody");
  const letters = { complete: "C", filtered: "F", partial: "P", sample: "S", gap: "G", unreachable: "U" };
  for (const source of [...coverage.sources].sort((a, b) => a.name.localeCompare(b.name))) {
    const tr = node("tr");
    const name = node("th"); name.scope = "row";
    name.append(source.home ? link(source.name, source.home) : node("span", "", source.name));
    tr.append(name);
    for (const year of years) {
      const row = byKey.get(source.source_id + " " + year);
      const cell = node("td", row ? "cov cov-" + row.status : "cov", row ? letters[row.status] + (row.admitted ? " " + row.admitted.toLocaleString("en-US") : "") : "");
      if (row) cell.setAttribute("title", coverageSentence(row, source.name + " " + year));
      tr.append(cell);
    }
    body.append(tr);
  }
  table.append(thead, body);
  const wrap = node("div", "table-wrap"); wrap.append(table);
  return wrap;
}
