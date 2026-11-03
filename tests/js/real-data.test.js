// The page validators accept every file a real collector build writes. The pull-request check
// runs this after its offline --cached build; without a local build in site/data it is skipped.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { ROOT } from "./fixtures.js";
import { normalizeArticleShard, normalizeBriefsFile, normalizeCveIndex, normalizeIndex, normalizeKevShard, normalizeReports, normalizeSources } from "../../site/js/validate.js";
import { cveRegister, filterRows } from "../../site/js/filters.js";

const base = ROOT + "site/data/";
const built = existsSync(base + "v7/index.json");

test("every shard of the offline build validates and matches its manifest sha256", { skip: !built && "no local build in site/data" }, () => {
  const index = normalizeIndex(JSON.parse(readFileSync(base + "v7/index.json", "utf8")));
  let rows = 0;
  const articles = [];
  for (const entry of index.shards) {
    const raw = readFileSync(base + "v7/" + entry.path);
    assert.equal(createHash("sha256").update(raw).digest("hex"), entry.sha256, entry.path);
    const value = JSON.parse(raw.toString("utf8"));
    if (entry.path.startsWith("live/") || entry.path.startsWith("history/")) { const shard = normalizeArticleShard(value, entry.path); rows += shard.length; articles.push(...shard); }
    else if (entry.path.startsWith("kev/")) rows += normalizeKevShard(value, entry.path).length;
    else if (entry.path === "cve-index.json") rows += normalizeCveIndex(value).rows.size;
    else if (entry.path === "sources.json") rows += normalizeSources(value).length;
    else if (entry.path === "reports.json") normalizeReports(value);
  }
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
