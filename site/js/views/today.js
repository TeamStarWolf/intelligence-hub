// Today: KEV additions by calendar day, the act-today strip, then the last three calendar days
// of advisories, research and press. It reads index.json and data/v7/recent.json, nothing else:
// recent.json holds the rows of those days, the KEV entries for the strips and the CVE index
// rows those rows name, so the first load stays small on any day of the month. An index written
// before recent.json existed falls back to the live months and the KEV ledger for 60 days.
import { formatRoute } from "../router.js";
import { ACT_WITHIN_DAYS, KEV_STRIP_DAYS, TODAY_DAYS, today } from "../filters.js";
import { addDays, count, dateLabel, dayLabel, node, routeLink } from "../util.js";
import { resultCard, section } from "./common.js";

export const KEV_DAYS = 60;
export const RECENT_PATH = "recent.json";

// True when recent.json was written for this content date and covers every Today window.
export function recentCovers(recent, end) {
  return Boolean(recent && !Array.isArray(recent) && recent.content_date === end && recent.from <= addDays(end, 1 - TODAY_DAYS) && recent.to >= end &&
    recent.kev_from <= addDays(end, 1 - KEV_STRIP_DAYS) && recent.due_until >= addDays(end, ACT_WITHIN_DAYS));
}

export function kevStrip(data, compact = false) {
  const block = node("div", "kev-days");
  const list = node("ul", "day-list");
  for (const entry of data.days) {
    const item = node("li", entry.entries.length ? "day has-kev" : "day");
    item.append(node("span", "day-name", dayLabel(entry.day)), node("span", "day-count", count(entry.entries.length, "KEV addition")));
    if (!compact && entry.entries.length) {
      const cves = node("span", "chips");
      for (const row of entry.entries) cves.append(routeLink(row.cve, formatRoute({ view: "cve", id: row.cve, query: {} }), "chip chip-cve"));
      item.append(cves);
    }
    list.append(item);
  }
  block.append(list);
  return block;
}

export function actStrip(data, compact = false) {
  const block = node("div", "act-today");
  block.append(node("p", "act-head", data.act.length ? count(data.act.length, "KEV entry", "KEV entries") + (data.act.length === 1 ? " reaches" : " reach") + " CISA's federal due date by " + dateLabel(data.until) + "." : "No KEV entry reaches its federal due date by " + dateLabel(data.until) + "."));
  if (data.act.length) {
    const list = node("ul", "act-list");
    for (const row of (compact ? data.act.slice(0, 5) : data.act)) {
      const item = node("li");
      item.append(routeLink(row.cve, formatRoute({ view: "cve", id: row.cve, query: {} }), "chip chip-cve"), node("span", "", " " + row.vendor + " " + row.product + ": due " + dateLabel(row.due_date) + (row.directive ? " (" + row.directive + ")" : "")));
      list.append(item);
    }
    block.append(list);
    if (compact && data.act.length > 5) block.append(node("p", "muted", "and " + count(data.act.length - 5, "more entry", "more entries") + " on the Today tab."));
  }
  block.append(node("p", "muted", "The due date is CISA's requirement for US federal agencies under its binding directives; it is not a deadline set for you."));
  return block;
}

// The Today data and the CVE index rows its cards need (null when the caller should read the
// full CVE index), from recent.json when the index lists one that covers the content date.
export async function todayData(store) {
  const end = store.contentDate();
  if (store.state.mode === "v7" && store.entry(RECENT_PATH)) {
    const [recent] = await store.ensure([RECENT_PATH]);
    if (recentCovers(recent, end)) return { ...today(recent.rows, recent.kev, end), cveIndex: recent.cves, source: RECENT_PATH };
  }
  const paths = store.todayPaths();
  const kevPaths = store.kevPaths(null, KEV_DAYS);
  await Promise.all([store.ensure(paths), store.ensure(kevPaths)]);
  return { ...today(store.rows(paths), store.kevRows(kevPaths), end), cveIndex: null, source: "months" };
}

export async function renderToday(ctx) {
  const { target, store, route } = ctx;
  target.replaceChildren(node("h1", "view-title", "Today"), node("p", "view-intro", "Reading the latest days."));
  const data = await todayData(store);
  const cveIndex = data.cveIndex || await store.cveIndex().catch(() => null);
  if (!ctx.current()) return;
  const intro = node("p", "view-intro", "The content date is " + dateLabel(data.to) + ". This view covers it and the " + (TODAY_DAYS - 1) + " days before it (" + dateLabel(data.from) + " to " + dateLabel(data.to) + ", UTC calendar days).");
  const kev = section("KEV additions by calendar day");
  kev.append(store.state.mode === "legacy" ? node("p", "muted", "The KEV ledger is part of the schema 7 data, which this fallback does not have.") : kevStrip(data));
  const act = section("Act today: KEV due dates in the next " + ACT_WITHIN_DAYS + " days");
  act.append(actStrip(data));
  const parts = [node("h1", "view-title", "Today"), intro, act, kev];
  for (const [title, rows, view] of [["Vendor and government advisories", data.advisories, "advisories"], ["Research", data.research, "research"], ["Press", data.news, "news"]]) {
    const block = section(title + " (" + rows.length.toLocaleString("en-US") + ")");
    const list = node("ol", "results-list");
    list.append(...rows.slice(0, 30).map(row => resultCard(row, { view, id: null, query: {} }, cveIndex)));
    if (!rows.length) list.append(node("li", "empty", "Nothing in these three days."));
    block.append(list);
    if (rows.length > 30) block.append(routeLink("All " + rows.length.toLocaleString("en-US") + " in " + title.toLowerCase(), formatRoute({ view, id: null, query: { range: "3" } }), "more-link"));
    parts.push(block);
  }
  target.replaceChildren(...parts);
  return data;
}
