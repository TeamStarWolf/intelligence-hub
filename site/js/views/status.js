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

export const INDICATOR_LABELS = { none: "Operational", minor: "Minor incident", major: "Major incident", critical: "Critical incident", maintenance: "Maintenance", unknown: "Not known" };
const INDICATOR_CLASS = { none: "status-ok", minor: "status-minor", major: "status-major", critical: "status-major", maintenance: "status-quiet", unknown: "status-quiet" };
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
      const table = node("table", "data-table");
      table.append(node("caption", "", "IODA outage events for countries in the " + outages.window_hours + " hours before the collector's read at " + stamp(ioda.fetched_at) + ". Score is IODA's own severity score."));
      const head = node("tr");
      for (const text of ["Country", "Signal", "Started", "Duration", "Score"]) { const cell = node("th", "", text); cell.scope = "col"; head.append(cell); }
      const thead = node("thead"); thead.append(head);
      const body = node("tbody");
      for (const row of ioda.rows) {
        const tr = node("tr"); const where = node("td"); where.append(link(row.entity_name, row.url));
        tr.append(where, node("td", "", row.datasource || "Not stated"), node("td", "", stamp(row.start)), node("td", "", row.end ? durationLabel(row.duration_seconds) : "Ongoing at the read"), node("td", "", row.score === null ? "Not stated" : row.score.toLocaleString("en-US")));
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
    for (const row of radar.rows) {
      const line = node("p");
      line.append(link((row.locations.join(", ") || row.scope || "Outage") + (row.cause ? ": " + row.cause.toLowerCase().replaceAll("_", " ") : ""), row.url), node("span", "muted", " " + stamp(row.start) + (row.end ? " to " + stamp(row.end) : ", ongoing")));
      block.append(line);
    }
  }
  return block;
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
  board.append(node("p", "", "The collector read every source at " + stamp(current.generated_at) + ". It runs when GitHub starts the scheduled workflow, which is every few hours in practice; the Sources view lists the observed gap between runs."), controls);
  const views = new Map();
  for (const group of current.groups) {
    const members = shown.filter(source => source.group === group.id);
    if (!members.length) continue;
    board.append(node("h3", "status-subtitle", group.label));
    const grid = node("ul", "status-grid");
    for (const source of members) { const view = card(source, lib, Boolean(chosen)); grid.append(view.item); if (source.live) views.set(source.live, view); }
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
  const months = store.listed("status/").filter(path => /^status\/\d{4}-\d{2}\.json$/.test(path) && path.slice(7, 14) >= first.slice(0, 7)).sort().reverse();
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

  const monthRows = (await Promise.all(months.map(path => store.statusFile(path).catch(() => [])))).flat();
  if (!ctx.current()) return;
  const rows = monthRows.filter(row => row.started.slice(0, 10) >= first && (!chosen || row.source === chosen.id)).sort((a, b) => b.started.localeCompare(a.started));
  recent.append(rows.length ? incidentTable(rows.slice(0, RECENT_SHOWN), sources, count(rows.length, "incident") + " started from " + dateLabel(first) + " to " + dateLabel(day) + (rows.length > RECENT_SHOWN ? "; the newest " + RECENT_SHOWN + " are shown, and the month files hold every one." : "."))
    : node("p", "muted", "No incident in the month files started in that window."));
  const explorer = node("p", "more");
  explorer.append(routeLink("Incidents of minor impact and above in the Explorer timeline", formatRoute({ view: "explore", id: null, query: { kind: "incident", event: "outage" } }), "more-link"));
  recent.append(explorer);
  if (index) recent.append(node("p", "muted", "Each source's history starts at the first incident its feed still lists; Statuspage feeds list their 50 most recent incidents."));
  return { sources: shown.length, open: openRows.length, recent: rows.length };
}
