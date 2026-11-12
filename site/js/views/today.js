// Today: the brief head (the day's counts, the service-health board, the Patch Tuesday index
// and what is new since this browser's last visit), KEV additions by calendar day, the
// act-today strip, then the last three calendar days of advisories, research and press. It
// reads index.json and data/v7/recent.json, plus status/current.json and
// patch-tuesday/index.json when the index lists them, nothing else: recent.json holds the rows
// of those days, the KEV entries for the strips and the CVE index rows those rows name, so the
// first load stays small on any day of the month. An index written before recent.json existed
// falls back to the live months and the KEV ledger for 60 days.
import { formatRoute } from "../router.js";
import { ACT_WITHIN_DAYS, KEV_STRIP_DAYS, TODAY_DAYS, today } from "../filters.js";
import { addDays, count, dateLabel, dayLabel, monthLabel, node, routeLink, stamp } from "../util.js";
import { resultCard, section } from "./common.js";

export const KEV_DAYS = 60;
export const RECENT_PATH = "recent.json";
export const BOARD_PATH = "status/current.json";
export const SEEN_KEY = "tsw-hub-today-seen";
const SEEN_LIMIT = 5000;
const TROUBLE = ["minor", "major", "critical"];

// What this browser saw on its last visit to Today, kept in localStorage as a per-browser
// convenience: {at: the content date of that visit, ids: the entry ids and KEV CVEs shown}.
// Storage may be missing, blocked or full, so every read and write is wrapped and the view
// renders without it.
export function readSeen(storage) {
  try {
    const raw = storage && storage.getItem(SEEN_KEY);
    if (!raw) return null;
    const value = JSON.parse(raw);
    if (!value || typeof value !== "object" || typeof value.at !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value.at) || !Array.isArray(value.ids)) return null;
    return { at: value.at, ids: new Set(value.ids.filter(id => typeof id === "string").slice(0, SEEN_LIMIT)) };
  } catch (_) { return null; }
}

export function writeSeen(storage, at, ids) {
  try {
    if (!storage) return false;
    storage.setItem(SEEN_KEY, JSON.stringify({ at, ids: [...ids].slice(0, SEEN_LIMIT) }));
    return true;
  } catch (_) { return false; }
}

// The second Tuesday of the month on or after day (YYYY-MM-DD): Microsoft's monthly release day.
export function nextPatchTuesday(day) {
  const second = (year, month) => { const first = new Date(Date.UTC(year, month - 1, 1)); return addDays(first.toISOString().slice(0, 10), (2 - first.getUTCDay() + 7) % 7 + 7); };
  const year = Number(day.slice(0, 4)), month = Number(day.slice(5, 7));
  const candidate = second(year, month);
  return candidate >= day ? candidate : month === 12 ? second(year + 1, 1) : second(year, month + 1);
}

// "a", "a and b", "a, b and c".
function joinWords(parts) { return parts.length < 2 ? parts.join("") : parts.slice(0, -1).join(", ") + " and " + parts[parts.length - 1]; }

function shownIds(data) {
  const ids = new Set([...data.advisories, ...data.research, ...data.news].map(row => row.id));
  for (const entry of data.days) for (const row of entry.entries) ids.add("kev:" + row.cve);
  return ids;
}

// The since-last-visit line. visit is the page session's baseline (main.js): the stored set is
// read once per page session and compared on every render, and what is shown is written back
// so the next session starts from it.
export function sinceLastVisit(data, storage, visit) {
  const ids = shownIds(data);
  if (!visit.today) visit.today = { previous: readSeen(storage), kept: writeSeen(storage, data.to, ids) };
  else if (visit.today.kept) writeSeen(storage, data.to, ids);
  const { previous, kept } = visit.today;
  if (!kept) return node("p", "brief-since muted", "This browser keeps no record between visits, so nothing is marked new.");
  if (!previous) return node("p", "brief-since muted", "This browser has no record of an earlier visit. From the next visit, this line counts what is new since the last one.");
  const fresh = [...ids].filter(id => !previous.ids.has(id));
  const kev = fresh.filter(id => id.startsWith("kev:")).length;
  const rows = fresh.length - kev;
  const words = rows === 0 && kev === 0 ? "Nothing new" : count(rows, "new entry", "new entries") + " and " + count(kev, "new KEV addition");
  return node("p", "brief-since", words + " since you last opened Today (content date " + dateLabel(previous.at) + ").");
}

// The brief head: one line each for the KEV windows, the three-day lists, the service-health
// board and the Patch Tuesday index, from what Today already has plus the two small files when
// the index lists them. Zero is said in words; a file the index does not list leaves its line out.
export function briefHead(data, board, patch, since) {
  const block = node("section", "panel brief-head");
  block.append(node("h2", "panel-title", "The brief"));
  const list = node("ul", "brief-list");
  const added = data.days.reduce((total, entry) => total + entry.entries.length, 0);
  const due = data.act.length === 1 ? "1 KEV entry reaches" : data.act.length ? data.act.length.toLocaleString("en-US") + " KEV entries reach" : "no KEV entry reaches";
  list.append(node("li", "", (added ? count(added, "KEV addition") : "No KEV addition") + " in the last " + KEV_STRIP_DAYS + " days; " + due + " a federal due date within " + ACT_WITHIN_DAYS + " days."));
  const lists = [[data.advisories.length, "advisory", "advisories"], [data.research.length, "research entry", "research entries"], [data.news.length, "press entry", "press entries"]]
    .filter(([total]) => total > 0).map(([total, one, many]) => count(total, one, many));
  list.append(node("li", "", lists.length ? joinWords(lists) + " in the last " + TODAY_DAYS + " days." : "No advisory, research or press entry in the last " + TODAY_DAYS + " days."));
  if (board) {
    const open = board.sources.reduce((sum, source) => sum + source.open.length, 0);
    const trouble = board.sources.filter(source => TROUBLE.includes(source.indicator)).length;
    const item = node("li");
    item.append(node("span", "", "Service health: " + (open ? count(open, "open incident") : "no open incident") + " and " + (trouble ? count(trouble, "status page") + " reporting a problem" : "no status page reporting a problem") +
      " across " + count(board.sources.length, "source") + ", read " + stamp(board.generated_at) + ". "), routeLink("Open the board", formatRoute({ view: "status", id: null, query: {} })));
    list.append(item);
  }
  if (patch) {
    const latest = [...patch.months].sort((a, b) => b.month.localeCompare(a.month))[0] || null;
    const item = node("li");
    const inWords = (total, words) => (total ? total.toLocaleString("en-US") : "none") + " " + words;
    item.append(node("span", "", "Patch Tuesday: " + (latest ? "the latest brief is " + monthLabel(latest.month) + " with " + count(latest.total, "CVE") + ", " + inWords(latest.exploited, "exploited at release") + " and " + inWords(latest.in_kev, "in KEV; ") : "no brief is built yet; ") +
      "the next release is expected " + dateLabel(nextPatchTuesday(data.to)) + ". "), routeLink(latest ? "Open the brief" : "Open Patch Tuesday", formatRoute({ view: "patch-tuesday", id: latest ? latest.month : null, query: {} })));
    list.append(item);
  }
  block.append(list);
  if (since) block.append(since);
  return block;
}

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
  const { target, store, route, storage = null, visit = {} } = ctx;
  target.replaceChildren(node("h1", "view-title", "Today"), node("p", "view-intro", "Reading the latest days."));
  const data = await todayData(store);
  // The service-health board and the Patch Tuesday index are read only when the index lists
  // them; a failed read leaves that line out of the brief head.
  const [cveIndex, board, patch] = await Promise.all([data.cveIndex ? data.cveIndex : store.cveIndex().catch(() => null),
    store.statusFile(BOARD_PATH).catch(() => null), store.patchTuesdayIndex().catch(() => null)]);
  if (!ctx.current()) return;
  const intro = node("p", "view-intro", "The content date is " + dateLabel(data.to) + ". This view covers it and the " + (TODAY_DAYS - 1) + " days before it (" + dateLabel(data.from) + " to " + dateLabel(data.to) + ", UTC calendar days).");
  const head = briefHead(data, board, patch, sinceLastVisit(data, storage, visit));
  const kev = section("KEV additions by calendar day");
  kev.append(store.state.mode === "legacy" ? node("p", "muted", "The KEV ledger is part of the schema 7 data, which this fallback does not have.") : kevStrip(data));
  const act = section("Act today: KEV due dates in the next " + ACT_WITHIN_DAYS + " days");
  act.append(actStrip(data));
  const parts = [node("h1", "view-title", "Today"), intro, head, act, kev];
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
