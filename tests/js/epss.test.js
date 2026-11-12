// FIRST's EPSS on the page (WP-03): the register's EPSS column, caption and sort, the brief's
// EPSS block with the model and the score date, the Explorer's EPSS sort and chip from the CVE
// index, the validators that accept the block and refuse a bad one, and the fallback reader.
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { CVE_ROWS, EPSS_HIGH, EPSS_LOW, brief, files, page, server, settle, storage } from "./fixtures.js";
import { createApp } from "../../site/js/main.js";
import { parseRoute } from "../../site/js/router.js";
import { epssOf, filterRows, sortRows } from "../../site/js/filters.js";
import { epssPercent } from "../../site/js/util.js";
import { epssBlock, epssCell, registerEpssNote } from "../../site/js/views/cves.js";
import { FormatError, normalizeBrief, normalizeCveIndex, normalizeEpss, normalizeRecent } from "../../site/js/validate.js";

async function boot({ hash = "", site = files() } = {}) {
  const shell = page(hash, "");
  const http = server(site.bodies);
  const app = createApp({ doc: shell.doc, win: shell.win, location: shell.location, history: shell.history, storage: storage(), session: storage(), fetchImpl: http.fetch,
    subtle: webcrypto.subtle, moduleUrl: null, every: () => 0, loadLabels: async () => ({ default: {} }) });
  await app.start();
  await settle(60);
  return { ...shell, http, app, site };
}

async function go(shell, hash) { shell.app.navigate(parseRoute(hash, "")); await settle(80); return shell.doc.querySelector("#view"); }

test("the register shows each CVE's EPSS as a percentage with its percentile, names FIRST, the model and the score date, and says No score in words", async () => {
  const { doc } = await boot({ hash: "#/cves" });
  const cells = [...doc.querySelectorAll("#view tbody tr")].map(tr => [tr.querySelector("td a").textContent, tr.children[4].textContent]);
  // The low score was kept from an earlier read, so its cell names its own date; the high one has the newest date.
  assert.deepEqual(cells, [["CVE-2026-1002", "No score"], ["CVE-2026-1001", "<0.1% (p12.3), 1 Nov 2026"], ["CVE-2026-1000", "94.3% (p99.9)"]]);
  const caption = doc.querySelector("#view caption").textContent;
  assert.ok(caption.includes("EPSS by FIRST, model v2026.06.15, score date 2 Nov 2026 (the newest; scores kept from an earlier read date back to 1 Nov 2026, and a cell names its own date and model when they differ)"), caption);
  assert.ok(caption.includes("reads No score, never 0"), caption);
  assert.ok(!/\b0\.0%/.test(cells.map(cell => cell[1]).join(" ")), "a missing score is never 0");
  assert.equal(epssCell(null), "No score");
  const counts = { epss_model: "v2026.06.15", epss_date: "2026-11-02", epss_oldest_date: "2026-11-02" };
  assert.equal(epssCell(EPSS_HIGH, counts), "94.3% (p99.9)");
  assert.equal(epssCell({ ...EPSS_HIGH, model: "v2025.03.14" }, counts), "94.3% (p99.9), model v2025.03.14", "an older model is named");
  assert.equal(epssCell(EPSS_HIGH, null), "94.3% (p99.9), 2 Nov 2026, model v2026.06.15", "without the counts every cell names its date and model");
  assert.equal(registerEpssNote(counts), "EPSS by FIRST, model v2026.06.15, score date 2 Nov 2026", "one date: no range");
  assert.equal(epssPercent(0.0004), "<0.1%");
  assert.equal(epssPercent(0.001), "0.1%");
  assert.equal(epssPercent(1), "100.0%");
});

test("the register sorts by EPSS in both directions with unscored CVEs last, and the sort control names it", async () => {
  const shell = await boot({ hash: "#/cves?sort=epss-desc" });
  const order = view => [...view.querySelectorAll("tbody tr td a")].map(anchor => anchor.textContent);
  assert.deepEqual(order(shell.doc.querySelector("#view")), ["CVE-2026-1000", "CVE-2026-1001", "CVE-2026-1002"]);
  assert.deepEqual(order(await go(shell, "#/cves?sort=epss-asc")), ["CVE-2026-1001", "CVE-2026-1000", "CVE-2026-1002"]);
  const options = [...shell.doc.querySelectorAll("#view select option")].map(option => option.textContent);
  assert.ok(options.includes("EPSS highest") && options.includes("EPSS lowest"), options.join(" | "));
});

test("the brief carries an EPSS block with FIRST, the model and the score date, and a brief without a score says so", async () => {
  const { doc } = await boot({ hash: "#/cve/CVE-2026-1000" });
  await settle(60);
  const blocks = [...doc.querySelectorAll("#cve-body .detail-block")];
  const epss = blocks.find(item => item.querySelector("h3").textContent === "Exploitation probability (EPSS)");
  assert.ok(epss, "the EPSS block is rendered");
  assert.ok(epss.textContent.includes("EPSS by FIRST, model v2026.06.15, score date 2 Nov 2026: 0.94333 (94.3%), percentile 0.99901."), epss.textContent);
  assert.ok(epss.textContent.includes("not a severity"), epss.textContent);
  // The block follows the Severity sources block and never sits inside it.
  assert.deepEqual(blocks.slice(0, 3).map(item => item.querySelector("h3").textContent), ["CNA title for CVE-2026-1000", "Severity sources", "Exploitation probability (EPSS)"]);
  assert.ok(!blocks[1].textContent.includes("EPSS"), "the Severity sources block carries no EPSS value");
  const chips = [...doc.querySelectorAll("#cve-body .chip")].map(chip => chip.textContent);
  assert.ok(chips.includes("FIRST EPSS 94.3%"), chips.join(" | "));
  const none = epssBlock(brief("CVE-2026-1002"), { epss_model: "v2026.06.15", epss_date: "2026-11-02" }).textContent;
  assert.ok(none.includes("EPSS by FIRST, model v2026.06.15, score date 2 Nov 2026: no EPSS score on that date."), none);
  assert.ok(!/\b0(\.0+)?%/.test(none) && !none.includes(" 0 "), "no score is never 0");
  const bare = epssBlock(brief("CVE-2026-1002"), null).textContent;
  assert.ok(bare.includes("EPSS by FIRST: no EPSS score on that date."), bare);
});

test("the Explorer sorts rows by the highest EPSS among their CVEs and shows it as a chip", async () => {
  const shell = await boot({ hash: "#/explore?sort=epss-desc" });
  const titles = [...shell.doc.querySelectorAll("#results .card-title")].map(item => item.textContent);
  assert.equal(titles[0], "Vendor fixes exploited flaw", titles.join(" | "));
  // The two rows naming the low-scored CVE come next, newest first; rows with no scored CVE last.
  assert.deepEqual(titles.slice(1, 3), ["Headline kev-CVE-2026-1001", "October advisory"], titles.join(" | "));
  const chips = [...shell.doc.querySelectorAll("#results .card")].map(card => [...card.querySelectorAll(".chip")].map(chip => chip.textContent));
  assert.ok(chips[0].includes("FIRST EPSS 94.3%"), chips[0].join(" | "));
  assert.ok(chips[1].includes("FIRST EPSS <0.1%") && chips[2].includes("FIRST EPSS <0.1%"), chips.slice(1, 3).map(list => list.join(" | ")).join(" / "));
  assert.ok(chips.slice(3).every(list => !list.some(chip => chip.includes("EPSS"))), "rows without a scored CVE carry no EPSS chip");
  const index = normalizeCveIndex(JSON.parse(shell.site.bodies["./data/v7/cve-index.json"])).rows;
  assert.equal(epssOf({ cves: ["CVE-2026-1001", "CVE-2026-1000"] }, index), 0.94333);
  assert.equal(epssOf({ cves: ["CVE-2026-1002"] }, index), null);
  assert.equal(epssOf({ cves: ["CVE-2026-1000"] }, null), null);
  const rows = [{ id: "a", cves: ["CVE-2026-1001"], time: 3, title: "a" }, { id: "b", cves: [], time: 2, title: "b" }, { id: "c", cves: ["CVE-2026-1000"], time: 1, title: "c" }];
  assert.deepEqual(sortRows([...rows], "epss-desc", index).map(row => row.id), ["c", "a", "b"]);
  assert.deepEqual(sortRows([...rows], "epss-asc", index).map(row => row.id), ["a", "c", "b"]);
  assert.deepEqual(sortRows([...rows], "epss-desc").map(row => row.id), ["a", "b", "c"], "without the index every row is unknown and the date decides");
  assert.equal(typeof filterRows, "function");
});

test("the validators accept the EPSS block field by field and refuse one out of range", () => {
  assert.deepEqual(normalizeEpss({ ...EPSS_HIGH, extra: "dropped" }), EPSS_HIGH);
  assert.equal(normalizeEpss(null), null);
  assert.equal(normalizeEpss(undefined), null);
  for (const bad of [{ ...EPSS_HIGH, score: 1.5 }, { ...EPSS_HIGH, score: -0.1 }, { ...EPSS_HIGH, score: "0.5" }, { ...EPSS_HIGH, percentile: 2 }, { ...EPSS_HIGH, date: "2026-11-31" },
    { ...EPSS_HIGH, date: "2026-11-02T00:00:00Z" }, { ...EPSS_HIGH, model: "2026.06.15" }, { ...EPSS_HIGH, model: null }, "0.5", 0.5]) {
    assert.throws(() => normalizeEpss(bad), FormatError, JSON.stringify(bad));
  }
  const site = files();
  const index = normalizeCveIndex(JSON.parse(site.bodies["./data/v7/cve-index.json"]));
  assert.deepEqual(index.rows.get("CVE-2026-1000").epss, EPSS_HIGH);
  assert.deepEqual(index.rows.get("CVE-2026-1001").epss, EPSS_LOW);
  assert.equal(index.rows.get("CVE-2026-1002").epss, null);
  const recent = normalizeRecent(JSON.parse(site.bodies["./data/v7/recent.json"]));
  assert.deepEqual(recent.cves.get("CVE-2026-1000").epss, EPSS_HIGH);
  const typed = JSON.parse(site.bodies["./data/v7/cve-index.json"]);
  typed.rows[0] = [...CVE_ROWS[0].slice(0, 10), { score: 0.5 }, null];
  assert.throws(() => normalizeCveIndex(typed), FormatError);
  const scored = normalizeBrief(brief("CVE-2026-1000", { epss: EPSS_HIGH }), "CVE-2026-1000");
  assert.deepEqual(scored.epss, EPSS_HIGH);
  const before = brief("CVE-2026-1001"); delete before.epss;
  assert.equal(normalizeBrief(before, "CVE-2026-1001").epss, null, "a brief published before the field reads as no score");
  assert.throws(() => normalizeBrief(brief("CVE-2026-1000", { epss: { ...EPSS_HIGH, score: 7 } }), "CVE-2026-1000"), FormatError);
});
