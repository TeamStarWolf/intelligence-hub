// The data the page has read, per view. The shell reads data/v7/index.json first, then only
// the shards the current view needs. When index.json is absent (HTTP 404) the page falls back
// to the single schema 6 feed. Shards are kept per sha256, so a poll that brings a new index
// drops only the shards whose bytes changed.
import { maximumBriefsBytes, maximumIndexBytes, maximumLegacyFeedBytes, maximumShardBytes } from "./limits.js";
import { HttpError } from "./fetcher.js";
import { normalizeArticleShard, normalizeBriefsFile, normalizeBucket, normalizeCoverage, normalizeCveIndex, normalizeIndex, normalizeKevShard, normalizeRecent, normalizeReports, normalizeSources } from "./validate.js";
import { normalizeStatusCurrent, normalizeStatusIndex, normalizeStatusMonth, normalizeStatusOutages } from "./validate.js";
import { addDays, monthsBetween } from "./util.js";
import { dateWindow } from "./filters.js";

export function createStore(fetcher) {
  const state = { mode: null, index: null, legacy: null, feedSnapshot: null };
  const files = new Map();   // path -> {sha256, value} for v7 shards
  const pending = new Map(); // path -> promise
  let briefs = null;         // {revision, map}
  let briefsRequest = null;
  let feedRequest = null;

  const entry = path => state.index ? state.index.shards.find(item => item.path === path) || null : null;
  const listed = prefix => state.index ? state.index.shards.filter(item => item.path.startsWith(prefix)).map(item => item.path) : [];

  // Every listed history file for a year in period order: history/YYYY.json, or the calendar
  // parts a large year is written as (history/YYYY-h1.json and -h2.json, quarters or months).
  function yearPaths(year) {
    // The index validator admits only SHARD_PATH names, so "history/YYYY-" can only start a part.
    const single = "history/" + year + ".json"; const part = "history/" + year + "-";
    return listed("history/").filter(path => path === single || path.startsWith(part)).sort();
  }

  // Reads index.json (conditional). Returns {status: "loaded" | "same" | "unchanged", index}.
  // A 404 switches the store to the schema 6 feed.
  async function loadIndex() {
    try {
      const result = await fetcher.getJson("./data/v7/index.json", { maximum: maximumIndexBytes, label: "index", conditional: true });
      if (result.notModified && state.index) return { status: "unchanged", index: state.index };
      const index = normalizeIndex(result.value);
      if (state.index && state.index.content_revision === index.content_revision && state.index.generated_at === index.generated_at) {
        state.index = index; return { status: "same", index };
      }
      for (const [path, file] of files) { const next = index.shards.find(item => item.path === path); if (!next || next.sha256 !== file.sha256) files.delete(path); }
      if (briefs && briefs.revision !== index.feed_content_revision) briefs = null;
      state.mode = "v7"; state.index = index;
      return { status: "loaded", index };
    } catch (error) {
      if (error instanceof HttpError && error.status === 404 && state.mode !== "v7") return loadLegacy();
      throw error;
    }
  }

  // Returns the normalized feed, or null when a conditional read found it unchanged.
  async function readFeed() {
    const result = await fetcher.getJson("./data/feed.json", { maximum: maximumLegacyFeedBytes, label: "feed snapshot", conditional: true });
    if (result.notModified && state.feedSnapshot) return null;
    // The feed reader loads only when a page needs the feed, so the schema 7 path never pays for it.
    const { normalize } = await import("./legacy.js");
    return normalize(result.value, new TextEncoder().encode(result.text).byteLength);
  }

  async function loadLegacy() {
    const snapshot = await readFeed();
    if (!snapshot) return { status: "unchanged", index: null };
    const { legacyData } = await import("./legacy.js");
    state.mode = "legacy"; state.feedSnapshot = snapshot; state.legacy = legacyData(snapshot);
    briefs = snapshot.briefs ? { revision: null, map: snapshot.briefs } : null;
    return { status: "loaded", index: null };
  }

  // The schema 6 feed, read on demand for the curated threat context it alone carries.
  function feed() {
    if (state.feedSnapshot) return Promise.resolve(state.feedSnapshot);
    if (!feedRequest) feedRequest = readFeed().then(snapshot => { state.feedSnapshot = snapshot || state.feedSnapshot; return state.feedSnapshot; }).finally(() => { feedRequest = null; });
    return feedRequest;
  }

  function contentDate() {
    if (state.mode === "legacy") return state.legacy.window.end.slice(0, 10);
    return state.index.content_date || state.index.window.end;
  }

  // The article shards a list view needs for its date window, newest first.
  function articlePaths(route) {
    if (state.mode !== "v7") return [];
    const live = listed("live/").filter(path => path !== "live/undated.json").sort().reverse();
    const window = dateWindow(route.view, route.query, contentDate());
    if (route.query.year) {
      const months = live.filter(path => path.slice(5, 9) === route.query.year && (!route.query.month || path.slice(10, 12) === route.query.month));
      return [...months, ...yearPaths(route.query.year)];
    }
    if (window) {
      const months = monthsBetween(window.from, window.to);
      return live.filter(path => months.includes(path.slice(5, 12)));
    }
    return entry("live/undated.json") ? [...live, "live/undated.json"] : live;
  }

  // The fallback for an index written before recent.json existed: the live months the Today
  // window touches. Today and the sidebar read recent.json whenever the index lists it.
  function todayPaths() {
    const end = contentDate();
    const months = monthsBetween(addDays(end, -2), end);
    return listed("live/").filter(path => months.includes(path.slice(5, 12))).sort().reverse();
  }

  // KEV ledger shards (by dateAdded year) covering a view: a chosen year, every year, or the
  // years from the window's first day to the content date.
  function kevPaths(route, days = 30) {
    if (state.mode !== "v7") return [];
    if (route && route.query.year) return entry("kev/" + route.query.year + ".json") ? ["kev/" + route.query.year + ".json"] : [];
    const range = route && route.view === "kev" ? route.query.range || "30" : String(days);
    if (range === "all") return listed("kev/").sort().reverse();
    const end = contentDate();
    const first = addDays(end, 1 - Math.max(Number(range), days));
    const years = [];
    for (let year = Number(first.slice(0, 4)); year <= Number(end.slice(0, 4)); year++) years.push("kev/" + year + ".json");
    return years.filter(path => entry(path)).reverse();
  }

  const readers = {
    article: (value, path) => normalizeArticleShard(value, path),
    kev: (value, path) => normalizeKevShard(value, path),
    "cve-index.json": value => normalizeCveIndex(value),
    "sources.json": value => normalizeSources(value),
    "coverage.json": value => normalizeCoverage(value),
    "reports.json": value => normalizeReports(value),
    "recent.json": value => normalizeRecent(value),
    // Service health (views/status.js): the board, the outage signals, the index and the months.
    status: (value, path) => path === "status/current.json" ? normalizeStatusCurrent(value) : path === "status/outages.json" ? normalizeStatusOutages(value) :
      path === "status/index.json" ? normalizeStatusIndex(value) : normalizeStatusMonth(value, path)
  };

  function reader(path) {
    if (path.startsWith("live/") || path.startsWith("history/")) return readers.article;
    if (path.startsWith("kev/")) return readers.kev;
    if (path.startsWith("status/")) return readers.status;
    return readers[path];
  }

  async function load(path) {
    if (files.has(path)) return files.get(path).value;
    if (pending.has(path)) return pending.get(path);
    const item = entry(path);
    if (!item) throw new Error("The index does not list " + path + ".");
    const promise = fetcher.getShard(path, item, maximumShardBytes, path).then(result => {
      const value = reader(path)(result.value, path);
      if (state.index && entry(path)?.sha256 === item.sha256) files.set(path, { sha256: item.sha256, value });
      return value;
    }).finally(() => pending.delete(path));
    pending.set(path, promise);
    return promise;
  }

  // Loads paths newest first, three at a time, calling progress after each batch.
  async function ensure(paths, progress = null) {
    const missing = paths.filter(path => !files.has(path));
    for (let start = 0; start < missing.length; start += 3) {
      await Promise.all(missing.slice(start, start + 3).map(load));
      if (progress && start + 3 < missing.length) progress();
    }
    return paths.map(path => files.get(path)?.value || []);
  }

  function loaded(paths) { return paths.every(path => files.has(path)); }

  function rows(paths) {
    if (state.mode === "legacy") return state.legacy.rows;
    const seen = new Set(); const result = [];
    for (const path of paths) for (const row of files.get(path)?.value || []) if (!seen.has(row.id)) { seen.add(row.id); result.push(row); }
    return result;
  }

  function kevRows(paths) {
    if (state.mode === "legacy") return [];
    return paths.flatMap(path => files.get(path)?.value || []);
  }

  async function cveIndex() { return state.mode === "legacy" ? state.legacy.cveIndex : (await load("cve-index.json")).rows; }
  async function sources() { return state.mode === "legacy" ? state.legacy.sources : load("sources.json"); }
  async function reports() {
    if (state.mode === "legacy") return { status: "unavailable", reason: "The schema 6 fallback does not carry the report catalog file.", reports: [], indexes: [], notes: [], review: null, updated_at: null };
    try { return await load("reports.json"); }
    catch (error) { if (error.format) return { status: "unavailable", reason: "The report catalog file did not validate: " + error.message, reports: [], indexes: [], notes: [], review: null, updated_at: null }; throw error; }
  }
  // The history coverage statements. A missing, stub or invalid file reads as unavailable, so
  // the History and Sources views still render their other parts.
  async function coverage() {
    const unavailable = reason => ({ status: "unavailable", note: reason, first_year: null, end_year: null, sources: [], rows: [], held_back: [] });
    if (state.mode !== "v7") return unavailable("The schema 6 fallback does not carry history coverage.");
    if (!entry("coverage.json")) return unavailable("This index lists no coverage file.");
    try { return await load("coverage.json"); }
    catch (error) { if (error.format) return unavailable("The coverage file did not validate: " + error.message); throw error; }
  }
  function cached(path) { return files.get(path)?.value || null; }
  // A service-health file the index lists, validated; null when this index lists none.
  async function statusFile(path) { return state.mode === "v7" && entry(path) ? load(path) : null; }

  // One CVE brief: from its bucket when buckets are published, otherwise from data/briefs.json.
  async function brief(cve) {
    if (briefs) return briefs.map.get(cve) || null;
    if (state.mode === "legacy") {
      if (!briefsRequest) briefsRequest = fetcher.getJson("./data/briefs.json", { maximum: maximumBriefsBytes, label: "brief file", cacheMode: "no-cache" })
        .then(result => { briefs = { revision: state.feedSnapshot.content_revision, map: normalizeBriefsFile(result.value, { feed_content_revision: state.feedSnapshot.content_revision }) }; })
        .finally(() => { briefsRequest = null; });
      await briefsRequest; return briefs.map.get(cve) || null;
    }
    const index = await cveIndex();
    const row = index.get(cve);
    if (!row) return null;
    if (row.bucket) {
      const path = row.bucket;
      const item = entry(path);
      if (!item) throw new Error("The index does not list " + path + ".");
      const result = await fetcher.getShard(path, item, maximumShardBytes, path);
      return normalizeBucket(result.value, path).get(cve) || null;
    }
    const revision = state.index.feed_content_revision;
    if (!briefsRequest) briefsRequest = fetcher.getJson("./data/briefs.json?v=" + revision.slice(0, 16), { maximum: maximumBriefsBytes, label: "brief file" })
      .then(result => { briefs = { revision, map: normalizeBriefsFile(result.value, state.index) }; })
      .finally(() => { briefsRequest = null; });
    await briefsRequest;
    return briefs.map.get(cve) || null;
  }

  return { state, loadIndex, articlePaths, yearPaths, todayPaths, kevPaths, ensure, loaded, rows, kevRows, cveIndex, sources, reports, coverage, brief, feed, contentDate, cached, listed, entry, statusFile };
}
