// Service health (#/status, #/status?source=<id>): the vendors' own status pages, cloud health
// feeds and internet outage signals that the collector reads (intelligence_hub/status.py).
//
// 1. The live board: one card per tracked source, grouped. For a source whose Statuspage status.json
//    sends Access-Control-Allow-Origin, this browser reads that one file when the view opens and every
//    five minutes while the tab is visible and live updates are on. Every other card shows the
//    collector's snapshot with its fetch time, and a failed live read falls back to that snapshot.
// 2. Open incidents, 3. internet outage signals, 4. the last 30 days of incidents.
//
// The live board reads only the live URLs that data/v7/status/current.json lists (validated by
// liveStatusUrl: https, the Statuspage status path, no query), with no credentials, no cache, no
// redirects and a 64 KiB bound, and renders text nodes only. The page's connect-src lists the same
// hosts, so no other host can be read.
import { createFetcher } from "../fetcher.js";
import { formatRoute } from "../router.js";
import { addDays, count, dateLabel, link, node, routeLink, stamp } from "../util.js";
import { libraryDoor, loadLibrary, section } from "./common.js";
import { normalizeLiveStatus } from "../validate.js";

export const LIVE_INTERVAL = 300000;
export const LIVE_MAX_BYTES = 65536;
export const LIVE_TIMEOUT = 15000;
const LIVE_BATCH = 6;
const RECENT_DAYS = 30;
const RECENT_SHOWN = 150;
const ATTENTION_SHOWN = 16;
const RELIABILITY_WEEKS = 13;
const RELIABILITY_DAYS = RELIABILITY_WEEKS * 7;
const COMPONENTS_SHOWN = 8;

export const INDICATOR_LABELS = { none: "Operational", minor: "Minor incident", major: "Major incident", critical: "Critical incident", maintenance: "Maintenance", unknown: "Not known" };
const INDICATOR_CLASS = { none: "status-ok", minor: "status-minor", major: "status-major", critical: "status-major", maintenance: "status-quiet", unknown: "status-quiet" };
// Problems sort first and read first in the posture summary; higher rank is more urgent.
const INDICATOR_RANK = { critical: 5, major: 4, minor: 3, maintenance: 2, unknown: 1, none: 0 };
// The short word for each state in a group heading's tally (none is left for "all operational").
const TALLY_WORD = { critical: "critical", major: "major", minor: "minor", maintenance: "in maintenance", unknown: "not known" };
const IMPACT_LABELS = { none: "No impact stated", minor: "Minor", major: "Major", critical: "Critical" };
const STATE_LABELS = { investigating: "Investigating", identified: "Identified", monitoring: "Monitoring", resolved: "Resolved", other: "Open" };

// The live reader. One per page; main.js stops it whenever another view renders.
export function createLiveBoard({ fetchImpl, every = (fn, ms) => setInterval(fn, ms), clear = id => clearInterval(id), now = () => Date.now(), doc = null } = {}) {
  const fetcher = createFetcher({ fetchImpl, timeout: LIVE_TIMEOUT });
  const results = new Map();
  const stats = { ticks: 0, requests: 0, failures: 0, skippedHidden: 0 };
  let urls = [];
  let listener = null;
  let timer = null;
  let paused = false;
  let running = null;
  // Each start() and stop() opens a new generation; a round from an older one ends at its next batch.
  let generation = 0;

  async function readOne(url, round) {
    stats.requests++;
    try {
      const { value } = await fetcher.getJson(url, { maximum: LIVE_MAX_BYTES, label: "status page", cacheMode: "no-store" });
      results.set(url, { ok: true, ...normalizeLiveStatus(value), at: now() });
    } catch (error) {
      stats.failures++;
      results.set(url, { ok: false, error: error && error.message ? error.message.slice(0, 200) : "The status page could not be read.", at: now() });
    }
    if (listener && round === generation) listener(url, results.get(url));
  }

  async function tick() {
    if (paused || !urls.length) return;
    if (doc && doc.hidden) { stats.skippedHidden++; return; }
    if (running) return running;
    stats.ticks++;
    // The round walks the list it started with; a source switch starts a fresh round over the new list.
    const round = generation;
    const list = urls;
    const current = (async () => {
      // Pause, a hidden tab, stop() or a new start() between batches ends the round: no further batch starts.
      for (let start = 0; start < list.length; start += LIVE_BATCH) {
        if (paused || (doc && doc.hidden) || round !== generation) break;
        await Promise.all(list.slice(start, start + LIVE_BATCH).map(url => readOne(url, round)));
      }
    })().finally(() => { if (running === current) running = null; });
    running = current;
    return current;
  }

  function stop() {
    if (timer !== null) clear(timer);
    timer = null; listener = null; urls = [];
    generation++; running = null;
  }

  // Starts reading urls now and every LIVE_INTERVAL; onResult(url, result) runs after each read.
  function start(list, onResult) {
    stop();
    urls = [...list]; listener = onResult;
    timer = every(() => { tick(); }, LIVE_INTERVAL);
    return tick();
  }

  function setPaused(value) { paused = Boolean(value); if (!paused) return tick(); return null; }

  return { start, stop, tick, setPaused, paused: () => paused, result: url => results.get(url) || null, active: () => timer !== null, stats };
}

function timeLabel(ms) {
  return new Date(ms).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC";
}

function badge(indicator) { return node("span", "badge status-badge " + INDICATOR_CLASS[indicator], INDICATOR_LABELS[indicator]); }

function snapshotLabel(source) {
  if (source.status === "failed") {
    return "Snapshot. The collector's last read at " + stamp(source.fetched_at) + " failed (" + (source.error || "no reason recorded") + ")" +
      (source.last_success ? "; showing its read of " + stamp(source.last_success) + "." : "; no earlier read is held.");
  }
  if (!source.last_success) return "Not read by the collector yet.";
  return "Snapshot from the collector's read at " + stamp(source.fetched_at) + ".";
}

// One card: name, indicator, the vendor's own description, where the reading came from, open count.
function card(source, lib, filtered) {
  const item = node("li", "status-card");
  item.dataset.source = source.id;
  const head = node("h3", "status-name"); head.append(link(source.name, source.home));
  const state = node("p", "status-state");
  const indicator = badge(source.indicator);
  const words = node("span", "status-words", source.description || "");
  state.append(indicator, words);
  const basis = node("p", "status-basis muted", snapshotLabel(source));
  item.append(head, state, basis);
  if (source.open.length) {
    const more = node("p", "status-open");
    more.append(filtered ? node("span", "", count(source.open.length, "open incident")) : routeLink(count(source.open.length, "open incident"), formatRoute({ view: "status", id: null, query: { source: source.id } })));
    item.append(more);
  }
  const door = source.library ? libraryDoor(lib, source.library, "Library platform page") : null;
  if (door) { const doorLine = node("p", "status-door"); doorLine.append(door); item.append(doorLine); }
  return { item, state, basis, source };
}

function applyLive(view, result) {
  const { source } = view;
  if (result.ok) {
    view.state.replaceChildren(badge(result.indicator), node("span", "status-words", result.description || ""));
    view.basis.textContent = "Live: read from " + new URL(source.live).hostname + " by this browser at " + timeLabel(result.at) + ".";
    view.item.classList.add("status-live");
  } else {
    // Back to the snapshot's own indicator and words, so an earlier live read never sits under a Snapshot label.
    view.state.replaceChildren(badge(source.indicator), node("span", "status-words", source.description || ""));
    view.basis.textContent = "Live read failed at " + timeLabel(result.at) + " (" + result.error + "). " + snapshotLabel(source);
    view.item.classList.remove("status-live");
  }
}

function incidentTable(rows, sources, caption) {
  const table = node("table", "data-table");
  table.append(node("caption", "", caption));
  const head = node("tr");
  for (const text of ["Source", "Incident", "Status", "Impact", "Affected", "Started", "Updated"]) { const cell = node("th", "", text); cell.scope = "col"; head.append(cell); }
  const thead = node("thead"); thead.append(head);
  const body = node("tbody");
  for (const row of rows) {
    const tr = node("tr");
    const name = node("td"); name.append(link(row.name, row.url));
    if (row.summary) name.append(node("span", "cell-note", row.summary));
    const status = row.status === "other" && row.status_raw ? row.status_raw : STATE_LABELS[row.status];
    const impact = row.impact ? IMPACT_LABELS[row.impact] + (row.impact_raw && row.impact_raw !== row.impact ? " (" + row.impact_raw + ")" : "") : "Not stated";
    tr.append(node("td", "", (sources.get(row.source) || { name: row.source }).name), name, node("td", "", status), node("td", "", impact),
      node("td", "", row.components.join(", ") || "Not listed"), node("td", "", stamp(row.started)), node("td", "", row.resolved ? "Resolved " + stamp(row.resolved) : stamp(row.updated)));
    body.append(tr);
  }
  table.append(thead, body);
  const wrap = node("div", "table-wrap"); wrap.append(table);
  return wrap;
}

function durationLabel(seconds) {
  if (seconds === null) return "Not stated";
  const hours = seconds / 3600;
  return hours >= 48 ? Math.round(hours / 24) + " days" : hours >= 1 ? hours.toFixed(1) + " h" : Math.max(1, Math.round(seconds / 60)) + " min";
}

function outagesSection(outages) {
  const block = section("Internet outage signals");
  block.append(node("p", "", "Measured signals, not complaints: IODA, from Georgia Tech, watches routing (BGP), active probing and other reachability data by country, and Cloudflare Radar annotates outages it verifies. A row is a signal to read on the source's own dashboard, not a confirmed cause."));
  if (!outages) { block.append(node("p", "notice-inline", "This snapshot carries no outage file.")); return block; }
  const ioda = outages.ioda;
  if (ioda) {
    block.append(node("h3", "status-subtitle", ioda.name));
    if (ioda.status !== "ok") block.append(node("p", "notice-inline", "The collector's last IODA read " + (ioda.status === "failed" ? "failed (" + (ioda.error || "no reason") + ")." : "has not run.")));
    if (ioda.rows.length) {
      // After a failed read the collector keeps the last good rows: date them by that read, not the failed one.
      const retained = ioda.status !== "ok" && Boolean(ioda.last_success);
      const basis = retained
        ? "the collector's last good read at " + stamp(ioda.last_success) + (ioda.status === "failed" && ioda.fetched_at ? "; the read at " + stamp(ioda.fetched_at) + " failed" : "")
        : "the collector's read at " + stamp(ioda.fetched_at);
      const table = node("table", "data-table");
      table.append(node("caption", "", "IODA outage events for countries in the " + outages.window_hours + " hours before " + basis + ". Score is IODA's own severity score."));
      const head = node("tr");
      for (const text of ["Country", "Signal", "Started", "Duration", "Score"]) { const cell = node("th", "", text); cell.scope = "col"; head.append(cell); }
      const thead = node("thead"); thead.append(head);
      const body = node("tbody");
      for (const row of ioda.rows) {
        const tr = node("tr"); const where = node("td"); where.append(link(row.entity_name, row.url));
        tr.append(where, node("td", "", row.datasource || "Not stated"), node("td", "", stamp(row.start)), node("td", "", row.end ? durationLabel(row.duration_seconds) : retained ? "Ongoing at that read" : "Ongoing at the read"), node("td", "", row.score === null ? "Not stated" : row.score.toLocaleString("en-US")));
        body.append(tr);
      }
      table.append(thead, body);
      const wrap = node("div", "table-wrap"); wrap.append(table); block.append(wrap);
    } else if (ioda.status === "ok") block.append(node("p", "muted", "IODA listed no country outage event in that window."));
    if (ioda.copyright) block.append(node("p", "muted", "IODA data: " + ioda.copyright));
  }
  const radar = outages.radar;
  if (radar) {
    block.append(node("h3", "status-subtitle", radar.name));
    if (radar.status === "not_configured") block.append(node("p", "muted", radar.note || "Cloudflare Radar is not configured, so no Radar request is made."));
    else if (radar.status !== "ok") block.append(node("p", "notice-inline", "The collector's last Radar read failed (" + (radar.error || "no reason") + ")."));
    const radarRetained = radar.status === "failed" && Boolean(radar.last_success) && radar.rows.length > 0;
    if (radarRetained) block.append(node("p", "muted", "These Radar rows are from the collector's last good read at " + stamp(radar.last_success) + "."));
    for (const row of radar.rows) {
      const line = node("p");
      line.append(link((row.locations.join(", ") || row.scope || "Outage") + (row.cause ? ": " + row.cause.toLowerCase().replaceAll("_", " ") : ""), row.url), node("span", "muted", " " + stamp(row.start) + (row.end ? " to " + stamp(row.end) : radarRetained ? ", ongoing at that read" : ", ongoing")));
      block.append(line);
    }
  }
  return block;
}

// A source needs a look when a vendor states an incident, or the collector could not read it this run.
function needsAttention(source) { return source.indicator === "minor" || source.indicator === "major" || source.indicator === "critical" || source.status !== "ok"; }

// Problems first: by the vendor's stated severity, then an unread collector read, then open-incident
// count, then name. Operational, fully read sources fall to the end of their group.
function compareAttention(a, b) {
  return (INDICATOR_RANK[b.indicator] - INDICATOR_RANK[a.indicator])
    || ((b.status !== "ok") - (a.status !== "ok"))
    || (b.open.length - a.open.length)
    || a.name.localeCompare(b.name);
}

function tallyIndicators(sources) {
  const counts = { critical: 0, major: 0, minor: 0, maintenance: 0, unknown: 0, none: 0 };
  for (const source of sources) counts[source.indicator] = (counts[source.indicator] || 0) + 1;
  return counts;
}

// A group heading's own count: "16, all operational" or "16: 1 major, 2 minor, 1 not read".
function groupTally(members) {
  const counts = tallyIndicators(members);
  const unread = members.filter(source => source.status !== "ok").length;
  const parts = [];
  for (const indicator of ["critical", "major", "minor", "maintenance", "unknown"]) if (counts[indicator]) parts.push(counts[indicator] + " " + TALLY_WORD[indicator]);
  if (unread) parts.push(unread + " not read");
  return " (" + (parts.length ? members.length + ": " + parts.join(", ") : members.length + ", all operational") + ")";
}

// One colour-coded tally chip: "42 Operational", "1 Major incident".
function badgeCount(indicator, total) {
  return node("span", "badge status-badge " + INDICATOR_CLASS[indicator], total.toLocaleString("en-US") + " " + INDICATOR_LABELS[indicator]);
}

// The posture summary at the top of the full board: a headline, a colour-coded tally of the vendors'
// stated states, a freshness note when a read failed, and quick links to anything that needs a look.
// Every number is the vendors' own wording at the collector's read, not a reading of your own tenant.
function postureBlock(sources) {
  const counts = tallyIndicators(sources);
  const unread = sources.filter(source => source.status !== "ok").length;
  const total = sources.length;
  const incidents = counts.critical + counts.major + counts.minor;
  const notOperational = total - counts.none;
  const wrap = node("div", "status-posture");
  const headline = node("p", "status-posture-headline");
  if (notOperational === 0 && unread === 0) {
    headline.append(node("strong", "", "All " + count(total, "tracked source") + " operational"), node("span", "", " at the collector's read."));
  } else if (notOperational === 0) {
    headline.append(node("strong", "", "Every source read was operational"), node("span", "", "; " + count(unread, "source") + " of " + total + " could not be read this run and " + (unread === 1 ? "shows" : "show") + " an earlier reading."));
  } else if (incidents) {
    headline.append(node("strong", "status-major", count(incidents, "source") + " with a vendor-stated incident"), node("span", "", " of " + count(total, "tracked source") + " at the collector's read."));
  } else {
    headline.append(node("strong", "", count(notOperational, "source") + " in maintenance or not known"), node("span", "", " of " + count(total, "tracked source") + "; none reported an incident at the collector's read."));
  }
  wrap.append(headline);
  const tally = node("ul", "status-tally");
  for (const indicator of ["critical", "major", "minor", "maintenance", "unknown", "none"]) {
    if (!counts[indicator]) continue;
    const item = node("li", "status-tally-item"); item.append(badgeCount(indicator, counts[indicator])); tally.append(item);
  }
  wrap.append(tally);
  if (unread && notOperational > 0) wrap.append(node("p", "status-posture-note muted", count(unread, "source") + " could not be read this run; each shows an earlier read or none, dated on its card."));
  const attention = sources.filter(needsAttention).sort(compareAttention);
  if (attention.length) {
    const line = node("p", "status-posture-attention");
    line.append(node("span", "", "Needs a look: "));
    attention.slice(0, ATTENTION_SHOWN).forEach((source, position) => {
      if (position) line.append(node("span", "", " · "));
      line.append(routeLink(source.name, formatRoute({ view: "status", id: null, query: { source: source.id } })));
    });
    if (attention.length > ATTENTION_SHOWN) line.append(node("span", "muted", " and " + (attention.length - ATTENTION_SHOWN) + " more below"));
    wrap.append(line);
  }
  return wrap;
}

// The vendors' own incident history is the Hub's lawful stand-in for a crowd-report trend: how often
// a service has had an incident, by week, over the last 13 weeks. It counts the vendor's own posted
// incidents in the status month files, not user reports, and says nothing about any one tenant.
function weeklyCounts(rows, endDay) {
  const counts = new Array(RELIABILITY_WEEKS).fill(0);
  const endMs = Date.parse(endDay + "T00:00:00Z");
  for (const row of rows) {
    const ageDays = Math.floor((endMs - Date.parse(row.started.slice(0, 10) + "T00:00:00Z")) / 86400000);
    if (ageDays < 0 || ageDays >= RELIABILITY_DAYS) continue;
    counts[RELIABILITY_WEEKS - 1 - Math.floor(ageDays / 7)]++;
  }
  return counts;
}

// A class-only cell strip (no inline style, so it holds under the page's style-src 'self'): one cell
// per week, oldest first, shaded by how many incidents fell in that week. The reading is in the text
// label and the aria-label; the cells are a decorative summary of it.
function reliabilityStrip(counts) {
  const total = counts.reduce((sum, value) => sum + value, 0);
  const summary = total ? count(total, "incident") + " in the last " + RELIABILITY_WEEKS + " weeks" : "No incident in the last " + RELIABILITY_WEEKS + " weeks";
  const wrap = node("p", "status-reliability");
  const strip = node("span", "rel-strip");
  strip.setAttribute("role", "img");
  strip.setAttribute("aria-label", summary + ", the vendor's own posted incidents by week");
  for (const value of counts) {
    const level = value === 0 ? 0 : value <= 2 ? 1 : 2;
    const cell = node("span", "rel-cell rel-" + level); cell.setAttribute("aria-hidden", "true"); strip.append(cell);
  }
  wrap.append(strip, node("span", "rel-count muted", summary));
  return wrap;
}

// Which sub-services the vendor named most often across its posted incidents in the window: the Hub's
// lawful stand-in for a "most reported problems" breakdown, from the vendor's component labels.
function componentTally(rows) {
  const counts = new Map();
  for (const row of rows) for (const component of row.components) counts.set(component, (counts.get(component) || 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

export async function renderStatus(ctx) {
  const { target, store, route, live } = ctx;
  const title = node("h1", "view-title", "Service health");
  const intro = node("p", "view-intro", "When a service you depend on stops working, start here: the vendors' own status pages, the cloud providers' health feeds and internet outage signals, in one place. Every entry is the vendor's statement or a measurement, never a count of user complaints, and none of it says anything about your own tenant or region.");
  if (store.state.mode !== "v7") { target.replaceChildren(title, intro, node("p", "notice-inline", "Service health is part of the schema 7 data, which this fallback does not have.")); return; }
  const status = node("p", "results-status", "Reading the service-health snapshot.");
  status.setAttribute("role", "status");
  target.replaceChildren(title, intro, status);
  const [current, outages, index, lib] = await Promise.all([store.statusFile("status/current.json"), store.statusFile("status/outages.json").catch(() => null),
    store.statusFile("status/index.json").catch(() => null), loadLibrary()]);
  if (!ctx.current()) return;
  if (!current) { status.textContent = "This snapshot carries no service-health files yet."; return; }
  const sources = new Map(current.sources.map(source => [source.id, source]));
  const chosen = route.query.source && sources.has(route.query.source) ? sources.get(route.query.source) : null;
  const shown = chosen ? [chosen] : current.sources;

  // 1. The live board.
  const board = section(chosen ? chosen.name : "Live board");
  const liveSources = shown.filter(source => source.live);
  const controls = node("p", "status-controls");
  const toggle = node("button", "bar-button", live.paused() ? "Resume live updates" : "Pause live updates");
  toggle.type = "button"; toggle.setAttribute("aria-pressed", String(live.paused()));
  const liveNote = node("span", "muted", " " + count(liveSources.length, "card") + " " + (liveSources.length === 1 ? "is" : "are") + " read live from this browser every five minutes while this tab is visible; the others show the collector's snapshot.");
  controls.append(toggle, liveNote);
  if (chosen) { const all = routeLink("Show every source", formatRoute({ view: "status", id: null, query: {} })); controls.append(node("span", "", " "), all); }
  if (!chosen) board.append(postureBlock(current.sources));
  board.append(node("p", "", "The collector read every source at " + stamp(current.generated_at) + ". It runs when GitHub starts the scheduled workflow, which is every few hours in practice; the Sources view lists the observed gap between runs."), controls);
  const views = new Map();
  const cards = new Map();
  for (const group of current.groups) {
    const members = shown.filter(source => source.group === group.id).sort(compareAttention);
    if (!members.length) continue;
    board.append(node("h3", "status-subtitle", chosen ? group.label : group.label + groupTally(members)));
    const grid = node("ul", "status-grid");
    for (const source of members) { const view = card(source, lib, Boolean(chosen)); grid.append(view.item); cards.set(source.id, view); if (source.live) views.set(source.live, view); }
    board.append(grid);
  }
  if (!chosen && current.page_only.length) {
    const pages = node("details", "status-pages");
    pages.append(node("summary", "", "Vendors with no machine-readable status source (" + current.page_only.length + "): linked, never read"));
    const list = node("ul", "detail-list");
    for (const item of current.page_only) { const entry = node("li"); entry.append(item.home ? link(item.name, item.home) : node("strong", "", item.name), node("span", "muted", " " + item.reason)); list.append(entry); }
    pages.append(list);
    board.append(pages);
  }

  // 2. Open incidents.
  const openRows = shown.flatMap(source => source.open).sort((a, b) => b.started.localeCompare(a.started));
  const open = section("Open incidents");
  open.append(openRows.length ? incidentTable(openRows, sources, "Incidents each vendor lists as not resolved at the collector's read. Status and impact are the vendor's words; components are what the vendor names.")
    : node("p", "muted", "No vendor listed an open incident at the collector's read."));

  // 3. Internet outage signals.
  const parts = [title, intro, status, board, open];
  if (!chosen) parts.push(outagesSection(outages));

  // 4. The last 30 days.
  const recent = section("The last 30 days");
  const day = current.generated_at.slice(0, 10);
  const first = addDays(day, -RECENT_DAYS);
  const firstReliability = addDays(day, -RELIABILITY_DAYS);
  const monthsAll = store.listed("status/").filter(path => /^status\/\d{4}-\d{2}\.json$/.test(path) && path.slice(7, 14) >= firstReliability.slice(0, 7)).sort().reverse();
  const months = monthsAll.filter(path => path.slice(7, 14) >= first.slice(0, 7));
  const files = node("p", "muted");
  files.append(node("span", "", "Month files: "));
  months.forEach((path, position) => {
    if (position) files.append(node("span", "", " · "));
    const anchor = node("a", "", path.slice(7, 14)); anchor.href = "./data/v7/" + path; files.append(anchor);
  });
  recent.append(files);
  parts.push(recent);
  target.replaceChildren(...parts);
  status.textContent = count(current.sources.length, "source") + " tracked, " + count(openRows.length, "open incident") + (chosen ? " for " + chosen.name : "") + ". Snapshot " + stamp(current.generated_at) + ".";

  toggle.addEventListener("click", () => {
    const next = !live.paused();
    live.setPaused(next);
    toggle.textContent = next ? "Resume live updates" : "Pause live updates";
    toggle.setAttribute("aria-pressed", String(next));
  });
  const onResult = (url, result) => { const view = views.get(url); if (view && ctx.current()) applyLive(view, result); };
  for (const [url, view] of views) { const known = live.result(url); if (known) applyLive(view, known); }
  live.start([...views.keys()], onResult);

  const monthRows = (await Promise.all(monthsAll.map(path => store.statusFile(path).catch(() => [])))).flat();
  if (!ctx.current()) return;

  // The vendor-incident trend, by source, over the reliability window. Each card gets a weekly strip.
  const historyBySource = new Map();
  for (const row of monthRows) {
    if (row.started.slice(0, 10) < firstReliability) continue;
    if (!historyBySource.has(row.source)) historyBySource.set(row.source, []);
    historyBySource.get(row.source).push(row);
  }
  for (const [id, view] of cards) view.item.append(reliabilityStrip(weeklyCounts(historyBySource.get(id) || [], day)));
  if (chosen) {
    const components = componentTally(historyBySource.get(chosen.id) || []);
    const line = node("p", "status-components muted");
    if (components.length) {
      line.append(node("span", "", "Most affected components in the last " + RELIABILITY_WEEKS + " weeks: "));
      components.slice(0, COMPONENTS_SHOWN).forEach(([name, total], position) => { if (position) line.append(node("span", "", ", ")); line.append(node("span", "", name + " (" + total + ")")); });
    } else line.append(node("span", "", "No component was named on an incident in the last " + RELIABILITY_WEEKS + " weeks."));
    recent.append(line);
  }

  const rows = monthRows.filter(row => row.started.slice(0, 10) >= first && (!chosen || row.source === chosen.id)).sort((a, b) => b.started.localeCompare(a.started));
  recent.append(rows.length ? incidentTable(rows.slice(0, RECENT_SHOWN), sources, count(rows.length, "incident") + " started from " + dateLabel(first) + " to " + dateLabel(day) + (rows.length > RECENT_SHOWN ? "; the newest " + RECENT_SHOWN + " are shown, and the month files hold every one." : "."))
    : node("p", "muted", "No incident in the month files started in that window."));
  const explorer = node("p", "more");
  explorer.append(routeLink("Incidents of minor impact and above in the Explorer timeline", formatRoute({ view: "explore", id: null, query: { kind: "incident", event: "outage" } }), "more-link"));
  recent.append(explorer);
  if (index) recent.append(node("p", "muted", "Each source's history starts at the first incident its feed still lists; Statuspage feeds list their 50 most recent incidents."));
  return { sources: shown.length, open: openRows.length, recent: rows.length };
}
