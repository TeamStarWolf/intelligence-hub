// The page validators accept every file a real collector build writes. The pull-request check
// runs this after its offline --cached build; without a local build in site/data it is skipped.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { ROOT } from "./fixtures.js";
import { normalizeArticleShard, normalizeBriefsFile, normalizeCoverage, normalizeCveIndex, normalizeIndex, normalizeKevShard, normalizePatchTuesday, normalizePatchTuesdayIndex, normalizeRecent, normalizeReports, normalizeSources } from "../../site/js/validate.js";
import { normalizeStatusCurrent, normalizeStatusIndex, normalizeStatusMonth, normalizeStatusOutages } from "../../site/js/validate.js";
import { recentCovers } from "../../site/js/views/today.js";
import { cveRegister, filterRows } from "../../site/js/filters.js";

const base = ROOT + "site/data/";
const built = existsSync(base + "v7/index.json");

test("every shard of the offline build validates and matches its manifest sha256", { skip: !built && "no local build in site/data" }, () => {
  const index = normalizeIndex(JSON.parse(readFileSync(base + "v7/index.json", "utf8")));
  let rows = 0;
  const articles = [];
  let recent = null;
  let patchIndex = null;
  const patchMonths = [];
  const status = { current: null, incidents: 0 };
  for (const entry of index.shards) {
    const raw = readFileSync(base + "v7/" + entry.path);
    assert.equal(createHash("sha256").update(raw).digest("hex"), entry.sha256, entry.path);
    const value = JSON.parse(raw.toString("utf8"));
    if (entry.path.startsWith("live/") || entry.path.startsWith("history/")) { const shard = normalizeArticleShard(value, entry.path); rows += shard.length; articles.push(...shard); }
    else if (entry.path.startsWith("kev/")) rows += normalizeKevShard(value, entry.path).length;
    else if (entry.path === "cve-index.json") rows += normalizeCveIndex(value).rows.size;
    else if (entry.path === "sources.json") rows += normalizeSources(value).length;
    else if (entry.path === "reports.json") normalizeReports(value);
    else if (entry.path === "recent.json") recent = normalizeRecent(value);
    // Service health: the board, the outage signals, the index and every month file.
    else if (entry.path === "status/current.json") status.current = normalizeStatusCurrent(value);
    else if (entry.path === "status/outages.json") normalizeStatusOutages(value);
    else if (entry.path === "status/index.json") normalizeStatusIndex(value);
    else if (entry.path.startsWith("status/")) status.incidents += normalizeStatusMonth(value, entry.path).length;
    else if (entry.path === "patch-tuesday/index.json") patchIndex = normalizePatchTuesdayIndex(value);
    else if (entry.path.startsWith("patch-tuesday/")) patchMonths.push(normalizePatchTuesday(value, entry.path).month);
  }
  // Every brief the Patch Tuesday index lists is a shard the manifest lists too.
  if (patchIndex) assert.deepEqual(patchIndex.months.map(item => item.month).sort(), patchMonths.sort());
  assert.ok(status.current && status.current.sources.length > 0, "the build writes status/current.json");
  // The Hub's Atom feeds: listed under feeds with matching bytes and sha256, an Atom document each.
  assert.equal(index.feeds.status, "ok");
  assert.deepEqual(index.feeds.files.map(file => file.path), ["feeds/incidents.xml", "feeds/kev.xml", "feeds/patch-calendar.xml"]);
  for (const file of index.feeds.files) {
    const raw = readFileSync(base + "v7/" + file.path);
    assert.equal(raw.length, file.bytes, file.path);
    assert.equal(createHash("sha256").update(raw).digest("hex"), file.sha256, file.path);
    assert.ok(raw.toString("utf8").startsWith('<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom">'), file.path);
  }
  assert.ok(status.incidents > 0, "the build writes a status month file");
  // recent.json covers the content date and holds only live rows the live shards also hold.
  assert.ok(recent, "the build writes recent.json");
  assert.ok(recentCovers(recent, index.content_date || index.window.end));
  const ids = new Set(articles.map(row => row.id));
  assert.ok(recent.rows.every(row => ids.has(row.id)));
  assert.ok(rows > 0);
  const briefs = normalizeBriefsFile(JSON.parse(readFileSync(base + "briefs.json", "utf8")), index);
  const cveIndex = normalizeCveIndex(JSON.parse(readFileSync(base + "v7/cve-index.json", "utf8"))).rows;
  assert.equal(briefs.size, cveIndex.size);
  // The KEV-linked register keeps every CVE with a KEV dateAdded, whatever its guidance label.
  const kev = [...cveIndex.values()].filter(row => row.kev_added).length;
  assert.equal(cveRegister(cveIndex, { kev: "1" }).length, kev);
  const route = { view: "explore", id: null, query: { kev: "1" } };
  const linked = filterRows(articles, route, { cveIndex, contentDate: index.content_date });
  assert.ok(linked.every(row => row.kind === "kev" || row.t.kev || row.cves.some(cve => cveIndex.get(cve)?.kev_added)));
});

// Every coverage statement with an adapter shows exactly the rows its source has in that year's
// history shard or calendar parts, after rows left to another source's row and rows held back.
test("every history coverage statement agrees with the rows its year's shards show under that source", { skip: !built && "no local build in site/data" }, () => {
  const index = normalizeIndex(JSON.parse(readFileSync(base + "v7/index.json", "utf8")));
  const raw = JSON.parse(readFileSync(base + "v7/coverage.json", "utf8"));
  const coverage = normalizeCoverage(raw);
  if (coverage.status !== "ok") return;
  const adapters = new Map(raw.rows.filter(row => row.adapter !== null).map(row => [row.source_id + " " + row.year, row]));
  const adapterSources = new Set(raw.sources.filter(source => source.adapter !== null).map(source => source.source_id));
  assert.ok(raw.rows.every(row => Number.isSafeInteger(row.given_up) && Number.isSafeInteger(row.in_feed) && Number.isSafeInteger(row.shown)), "the collector writes given_up, in_feed and shown on every row");
  const counted = new Map();
  for (const entry of index.shards.filter(item => item.path.startsWith("history/"))) {
    const year = Number(entry.path.slice(8, 12));
    for (const row of JSON.parse(readFileSync(base + "v7/" + entry.path, "utf8")).rows) {
      const key = row.source_id + " " + year;
      if (adapterSources.has(row.source_id)) counted.set(key, (counted.get(key) || 0) + 1);
    }
  }
  for (const [key, row] of adapters) assert.equal(counted.get(key) || 0, row.shown, key);
  for (const [key, rows] of counted) assert.equal(adapters.get(key)?.shown, rows, key + " has rows without a statement that shows them");
  for (const row of raw.rows.filter(item => item.adapter === null)) assert.deepEqual([row.given_up, row.in_feed, row.shown], [0, 0, 0], row.source_id + " " + row.year);
});
