// The Patch Tuesday view on site/index.html, fed the golden briefs that
// tests/fixtures/patch-tuesday/build_golden.py writes: the route, the tab after the existing
// tabs, the Explorer still first on the default route, the headline numbers, the priority order,
// the exploited and disclosed table, the KEV join, the Adobe and SAP rows, the month history,
// and every link either a hash route or an https link that passes safeUrl to MSRC, CISA, the
// Hub, Adobe or SAP.
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { inOrder } from "./dom.js";
import { ROOT, files, page, server, settle, storage } from "./fixtures.js";
import { createApp } from "../../site/js/main.js";
import { formatRoute, parseRoute } from "../../site/js/router.js";
import { safeUrl } from "../../site/js/util.js";
import { normalizePatchTuesday, normalizePatchTuesdayIndex } from "../../site/js/validate.js";

const golden = name => JSON.parse(readFileSync(ROOT + "tests/fixtures/patch-tuesday/golden/" + name, "utf8"));
const BRIEFS = { "patch-tuesday/index.json": golden("index.json"), "patch-tuesday/2026-10.json": golden("2026-10.json"), "patch-tuesday/2024-01.json": golden("2024-01.json") };
const HOSTS = ["msrc.microsoft.com", "www.cisa.gov", "helpx.adobe.com", "support.sap.com", "me.sap.com", "github.com"];

async function boot(hash = "", extra = BRIEFS) {
  const shell = page(hash, "");
  const http = server(files({ extra }).bodies);
  const app = createApp({ doc: shell.doc, win: shell.win, location: shell.location, history: shell.history, storage: storage(), session: storage(), fetchImpl: http.fetch,
    subtle: webcrypto.subtle, every: () => 0, loadLabels: async () => ({ default: {} }) });
  await app.start();
  await settle(80);
  return { ...shell, http, app };
}

async function go(shell, hash) { shell.app.navigate(parseRoute(hash, "")); await settle(80); return shell.doc.querySelector("#view"); }

test("the route contract: #/patch-tuesday, #/patch-tuesday/<YYYY-MM>, and a bad month falls back to the latest brief", () => {
  assert.deepEqual(parseRoute("#/patch-tuesday", ""), { view: "patch-tuesday", id: null, query: {}, rewrite: false });
  assert.deepEqual(parseRoute("#/patch-tuesday/2026-10", ""), { view: "patch-tuesday", id: "2026-10", query: {}, rewrite: false });
  for (const hash of ["#/patch-tuesday/2026-13", "#/patch-tuesday/26-10", "#/patch-tuesday/2026-10/extra", "#/patch-tuesday?q=x"]) {
    const route = parseRoute(hash, "");
    assert.equal(route.view, "patch-tuesday", hash);
    assert.equal(route.id, null, hash);
    assert.equal(route.rewrite, true, hash);
  }
  assert.equal(formatRoute({ view: "patch-tuesday", id: "2024-01", query: { q: "x" } }), "#/patch-tuesday/2024-01");
});

test("the tab sits after the existing tabs, and the default route renders the Explorer first and reads no brief", async () => {
  const shell = await boot();
  const { doc } = shell;
  const tabs = [...doc.querySelectorAll(".tabs a")].map(tab => tab.getAttribute("data-view"));
  assert.equal(tabs[0], "explore");
  assert.equal(tabs[tabs.length - 1], "patch-tuesday");
  assert.equal(doc.querySelector("#explore").hidden, false);
  assert.equal(doc.querySelector("#view").hidden, true);
  assert.ok(!shell.http.requests.some(request => request.path.includes("patch-tuesday")), "the Explorer reads no Patch Tuesday file");
  const all = inOrder(doc);
  const target = await go(shell, "#/patch-tuesday");
  assert.equal(doc.querySelector("#explore").hidden, true);
  assert.ok(all.indexOf(target) > all.indexOf(doc.querySelector("#results")), "the view sits after the Explorer in the DOM");
  assert.equal(doc.querySelector(".tabs a[aria-current=page]").getAttribute("data-view"), "patch-tuesday");
  assert.equal(doc.title, "Patch Tuesday · Intelligence Hub · TeamStarWolf");
});

test("the latest brief renders its headline numbers, priority order and the exploited and disclosed rows", async () => {
  const shell = await boot("#/patch-tuesday");
  const view = shell.doc.querySelector("#view");
  const text = view.textContent;
  assert.equal(view.querySelector("h1").textContent, "Patch Tuesday");
  assert.ok(text.includes("October 2026 Security Updates"));
  assert.ok(text.includes("CVEs in the release14"));
  assert.ok(text.includes("Critical7"));
  assert.ok(text.includes("Exploited in the wild1"));
  assert.ok(text.includes("Publicly disclosed3"));
  assert.ok(text.includes("Already in CISA KEV2"));
  assert.ok(text.includes("Microsoft KEV additions this month1"));
  const order = [...view.querySelectorAll("ol li")].map(item => item.querySelector("a").textContent);
  assert.deepEqual(order.slice(0, 5), ["CVE-2026-96951", "CVE-2026-111497", "CVE-2026-100202", "CVE-2026-70187", "CVE-2026-70571"]);
  const flagged = [...view.querySelectorAll("section")].find(section => section.querySelector("h2").textContent === "Exploited and publicly disclosed");
  const cves = [...flagged.querySelectorAll("tbody tr")].map(row => row.querySelector("a").textContent).sort();
  assert.deepEqual(cves, ["CVE-2026-108398", "CVE-2026-111497", "CVE-2026-92707", "CVE-2026-96951"]);
  const msrc = flagged.querySelector("a[href='https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-96951']");
  assert.ok(msrc, "each CVE links its MSRC page");
  assert.ok(flagged.querySelector("a[href='#/cve/CVE-2026-96951']"), "a CVE with a Hub brief links it");
  assert.ok(!flagged.querySelector("a[href='#/cve/CVE-2026-92707']"), "a CVE without a Hub brief gets no Hub link");
  assert.ok(flagged.querySelector("a[href='https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-96951']"));
});

test("the KEV join, Adobe and SAP headline rows, and the month history with a link to each brief", async () => {
  const shell = await boot("#/patch-tuesday/2026-10");
  let view = shell.doc.querySelector("#view");
  const kev = [...view.querySelectorAll("section")].find(section => section.querySelector("h2").textContent === "CISA KEV");
  assert.ok(kev.textContent.includes("CVE-2026-96951") && kev.textContent.includes("CVE-2026-111497"));
  assert.ok(kev.textContent.includes("Microsoft KEV additions in Oct 2026."));
  assert.ok(view.textContent.includes("Adobe's bulletin index lists no bulletin first posted on 13 Oct 2026. Its latest posting date is 8 Sept 2026.") ||
    view.textContent.includes("Adobe's bulletin index lists no bulletin first posted on 13 Oct 2026. Its latest posting date is 8 Sep 2026."));
  assert.ok(view.textContent.includes("OAuth2 SSRF vulnerability in SAP Cloud SDK for Python"));
  const history = [...view.querySelectorAll("a")].filter(anchor => anchor.getAttribute("href") === "#/patch-tuesday/2024-01");
  assert.equal(history.length, 1);
  view = await go(shell, "#/patch-tuesday/2024-01");
  assert.ok(view.textContent.includes("January 2024 Security Updates"));
  assert.ok(view.textContent.includes("APSB24-06"));
  assert.ok(view.textContent.includes("No, an earlier CVE"), "a Microsoft KEV addition outside the release is marked");
  assert.ok(view.textContent.includes("2016-Jan: the release document was not read"));
});

test("every link on the view is a hash route or an https vendor link that passes safeUrl", async () => {
  const shell = await boot("#/patch-tuesday");
  for (const hash of ["#/patch-tuesday", "#/patch-tuesday/2024-01"]) {
    const view = await go(shell, hash);
    for (const anchor of view.querySelectorAll("a")) {
      const href = anchor.getAttribute("href");
      if (href.startsWith("#/")) { assert.equal(formatRoute(parseRoute(href, "")), href, href); continue; }
      assert.equal(safeUrl(href), href, href);
      assert.ok(HOSTS.includes(new URL(href).hostname), href);
      assert.equal(anchor.getAttribute("rel"), "noopener noreferrer nofollow");
    }
  }
});

test("an index without briefs says so, and a month with no brief shows the history", async () => {
  const shell = await boot("#/patch-tuesday", {});
  assert.ok(shell.doc.querySelector("#view").textContent.includes("No Patch Tuesday brief is published in this snapshot yet."));
  const other = await boot("#/patch-tuesday/2025-05");
  assert.ok(other.doc.querySelector("#view").textContent.includes("No brief is built for May 2025."));
});

test("the validators refuse a brief with a foreign link, an unknown tier or a row for another path", () => {
  const brief = golden("2026-10.json");
  assert.equal(normalizePatchTuesday(brief, "patch-tuesday/2026-10.json").rows.length, 14);
  assert.throws(() => normalizePatchTuesday(brief, "patch-tuesday/2026-09.json"));
  const foreign = structuredClone(brief); foreign.msrc.url = "https://msrc.example.net/update-guide/releaseNote/2026-Oct";
  assert.throws(() => normalizePatchTuesday(foreign, "patch-tuesday/2026-10.json"));
  const script = structuredClone(brief); script.sap.rows[0][5] = "javascript:alert(1)";
  assert.throws(() => normalizePatchTuesday(script, "patch-tuesday/2026-10.json"));
  const tier = structuredClone(brief); tier.priority[0][1] = "urgent";
  assert.throws(() => normalizePatchTuesday(tier, "patch-tuesday/2026-10.json"));
  const layout = structuredClone(brief); layout.fields = layout.fields.slice(1);
  assert.throws(() => normalizePatchTuesday(layout, "patch-tuesday/2026-10.json"));
  const index = golden("index.json");
  assert.equal(normalizePatchTuesdayIndex(index).months[0].month, "2026-10");
  const path = structuredClone(index); path.months[0].path = "live/2026-10.json";
  assert.throws(() => normalizePatchTuesdayIndex(path));
});
