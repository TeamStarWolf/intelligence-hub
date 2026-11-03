// The History, Vendors, Tags, Actors and malware, Reports, Data, Sources and Method views on
// site/index.html with a synthetic schema 7 site: each is a routed tab and a sidebar entry and
// never renders above the Explorer, every tag value has a page or a filter, zero counts are
// hidden, a bad report catalog degrades only the Reports view, and every library link the page
// renders comes from site/js/library.js and is a https://teamstarwolf.github.io/TeamStarWolf/#/ URL.
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { inOrder } from "./dom.js";
import { files, page, server, settle, storage, row } from "./fixtures.js";
import { createApp } from "../../site/js/main.js";
import { parseRoute, formatRoute } from "../../site/js/router.js";
import { filterRows } from "../../site/js/filters.js";
import { normalizeArticleShard, normalizeCoverage } from "../../site/js/validate.js";
import { safeUrl } from "../../site/js/util.js";
import { LIBRARY_PREFIX } from "../../site/js/views/common.js";
import * as library from "../../site/js/library.js";

const PINNED_EVIDENCE = Object.keys(library.PINNED)[0];
const MSRC = { source_id: "microsoft-bulletins", source_name: "Microsoft Security Bulletins", kind: "bulletin", origin: "history:msrc-bulletins", tagging: { source_class: "vendor-primary", event_type: [["disclosure", "kind-default", "high"]], exploitation: ["unknown", "none", "high"], vendor: [["vendor:microsoft", "source-identity", "high"]] } };

function coverage() {
  const sources = [
    { source_id: "adobe-psirt", name: "Adobe Security Bulletins", adapter: null, home: "https://helpx.adobe.com/security/security-bulletin.html", first_year: null, last_year: null, filter: null, licence: null },
    { source_id: "microsoft-bulletins", name: "Microsoft Security Bulletins", adapter: "msrc-bulletins", home: "https://learn.microsoft.com/en-us/security-updates/securitybulletins/securitybulletins", first_year: 1998, last_year: 2017, filter: null, licence: "Microsoft; ids, titles, dates and links only." }
  ];
  const rows = [];
  for (const source of sources) for (let year = 1998; year <= 2026; year++) {
    const ms = source.adapter !== null;
    rows.push({ source_id: source.source_id, adapter: source.adapter, year, status: ms ? (year === 1998 ? "complete" : year <= 2017 ? "partial" : "gap") : "unreachable",
      upstream_count: ms ? (year === 1998 ? 2 : year <= 2017 ? 5 : 0) : null, admitted: ms && year === 1998 ? 2 : ms && year <= 2017 ? 4 : 0, filter: null,
      reason: ms ? (year > 2017 ? "the series ended in 2017" : year === 1998 ? null : "1 listed item could not be read") : "the bulletin index returned HTTP 403 to automated reads (2026-11-03)", checked_at: "2026-11-03", licence: ms ? "Microsoft; ids, titles, dates and links only." : null });
  }
  return { schema_version: 7, kind: "coverage", status: "ok", published_rows: true, first_year: 1998, end_year: 2026, statuses: ["complete", "filtered", "partial", "sample", "gap", "unreachable"], sources, rows, held_back: [] };
}

function site({ reports = null } = {}) {
  const extra = {
    "coverage.json": coverage(),
    "history/1998.json": { schema_version: 7, kind: "articles", period: "1998", rows: [
      row("h-ms98-001", { ...MSRC, published_at: "1998-06-01", title: "MS98-001: Disabling Creation of Local Groups on a Domain by Non-Administrative Users" }),
      row("h-ms98-002", { ...MSRC, published_at: "1998-06-25", title: "MS98-002: Error in Admin Rights in Microsoft Windows NT" }),
      row("hist-curated-1998", { source_id: "curated", source_name: "Curated history", kind: "incident", origin: "library-curation", published_at: "1998-07-15", title: "A curated 1998 event",
        references: [{ label: "Pinned library discovery reference", url: PINNED_EVIDENCE }], tagging: { source_class: "researcher", event_type: [["analysis", "kind-default", "high"]], exploitation: ["unknown", "none", "high"] } })
    ] },
    // A history year whose rows carry a vendor, an actor and a malware tag, none of them in the
    // live window, so a year-scoped door that drops the year finds nothing.
    "history/2010.json": { schema_version: 7, kind: "articles", period: "2010", rows: [
      row("h-ms10-046", { ...MSRC, published_at: "2010-08-02", title: "MS10-046: Vulnerability in Windows Shell Could Allow Remote Code Execution" }),
      row("hist-curated-2010", { source_id: "curated", source_name: "Curated history", kind: "incident", origin: "library-curation", published_at: "2010-07-15", title: "A curated 2010 event",
        tagging: { source_class: "researcher", event_type: [["analysis", "kind-default", "high"]], exploitation: ["unknown", "none", "high"], vendor: [["vendor:microsoft", "title-alias", "medium"]],
          actor: [["actor:G0016", "title-alias", "medium"]], malware: [["malware:S0154", "title-alias", "medium"]] } })
    ] }
  };
  if (reports) extra["reports.json"] = reports;
  return files({ extra });
}

async function boot({ hash = "", app: base = site(), matches = false } = {}) {
  const shell = page(hash, "");
  if (matches) shell.win.matchMedia = () => ({ matches: true });
  const http = server(base.bodies);
  const app = createApp({ doc: shell.doc, win: shell.win, location: shell.location, history: shell.history, storage: storage(), session: storage(), fetchImpl: http.fetch,
    subtle: webcrypto.subtle, every: () => 0, loadLabels: async () => ({ default: { "vendor:fortinet": "Fortinet", "vendor:microsoft": "Microsoft", "actor:G0016": "APT29", "sector:healthcare-public-health": "Healthcare and Public Health" } }) });
  await app.start();
  await settle(80);
  return { ...shell, http, app };
}

async function go(shell, hash) { shell.app.navigate(parseRoute(hash, "")); await settle(80); return shell.doc.querySelector("#view"); }

const NEW_VIEWS = [["history", "History"], ["vendors", "Vendors"], ["tags", "Tags"], ["actors", "Actors and malware"], ["reports", "Reports"], ["data", "Data downloads"], ["sources", "Sources and coverage"], ["method", "Method"]];

test("the default route still renders the Explorer first and none of the new views", async () => {
  const shell = await boot();
  const { doc } = shell;
  const all = inOrder(doc);
  const search = all.indexOf(doc.querySelector("#q"));
  const before = all.slice(all.indexOf(doc.body) + 1, search);
  assert.deepEqual(before.filter(element => !(element.closest("header.bar") || element.closest("nav.tabs") || element.closest("#explore") || ["layout", "main"].includes(element.getAttribute("id")))).map(element => element.localName), []);
  assert.equal(doc.querySelector("#view").hidden, true);
  assert.equal(doc.querySelector("#view").children.length, 0, "no other view renders on the default route");
  assert.ok(!shell.http.requests.some(request => /coverage\.json|kev\/|history\//.test(request.path)), "the default route reads no coverage, KEV or history file");
});

test("every new view is a tab and a sidebar entry, and renders below the Explorer's place", async () => {
  const shell = await boot();
  const { doc } = shell;
  const tabs = [...doc.querySelectorAll(".tabs a")].map(tab => tab.getAttribute("href"));
  for (const [view] of NEW_VIEWS) assert.ok(tabs.includes("#/" + view), "tab for " + view);
  doc.querySelector("#sidebar-toggle").dispatchEvent({ type: "click" });
  await settle(80);
  const side = [...doc.querySelectorAll("#sidebar-body .side-views a")].map(anchor => anchor.getAttribute("href"));
  for (const [view] of NEW_VIEWS) assert.ok(side.includes("#/" + view), "sidebar entry for " + view);
  for (const [view, title] of NEW_VIEWS) {
    const target = await go(shell, "#/" + view);
    assert.equal(doc.querySelector("#explore").hidden, true, view);
    assert.equal(target.hidden, false, view);
    assert.equal(target.querySelector("h1").textContent, title, view);
    assert.equal(doc.querySelector(".tabs a[aria-current=page]").getAttribute("data-view"), view);
    const all = inOrder(doc);
    assert.ok(all.indexOf(target) > all.indexOf(doc.querySelector("#results")), view + " sits after the Explorer in the DOM");
  }
  await go(shell, "#/explore");
  assert.equal(doc.querySelector("#explore").hidden, false);
  assert.equal(doc.querySelector("#view").hidden, true);
});

test("History lists every year from 1998 with its coverage, and a year page states coverage before its rows", async () => {
  const shell = await boot({ hash: "#/history" });
  const view = shell.doc.querySelector("#view");
  const years = [...view.querySelectorAll("tbody th a")].map(anchor => anchor.textContent);
  assert.equal(years[0], "2026");
  assert.equal(years[years.length - 1], "1998");
  assert.equal(years.length, 29);
  assert.ok(view.textContent.includes("Microsoft Security Bulletins 2"));
  assert.ok(view.textContent.includes("1 complete, 1 unreachable"));
  const year = await go(shell, "#/history/1998");
  const text = year.textContent;
  assert.ok(text.indexOf("Coverage this year") < text.indexOf("MS98-001"), "the coverage statement comes first");
  assert.ok(text.includes("Microsoft Security Bulletins: complete, 2 rows."));
  assert.ok(text.includes("Adobe Security Bulletins: unreachable (the bulletin index returned HTTP 403"));
  assert.ok(text.includes("3 rows of 3 in 1998"));
  assert.ok(text.indexOf("MS98-001") < text.indexOf("MS98-002"), "oldest first");
  assert.ok(shell.http.requests.some(request => request.path === "./data/v7/history/1998.json"));
  const source = await go(shell, "#/history/1998?source=microsoft-bulletins&month=06");
  assert.ok(source.textContent.includes("2 rows of 3 in 1998, Jun 1998"));
  assert.ok(!source.textContent.includes("A curated 1998 event"));
  const partial = await go(shell, "#/history/2003");
  assert.ok(partial.textContent.includes("Microsoft Security Bulletins: partial, 4 rows of 5 listed (1 listed item could not be read)."));
});

test("a vendor page links its library platform page and its KEV entries", async () => {
  const shell = await boot({ hash: "#/vendors" });
  let view = shell.doc.querySelector("#view");
  assert.ok(view.textContent.includes("Fortinet"));
  assert.ok(!view.textContent.includes("Palo Alto Networks"), "a vendor with no entry is not listed");
  view = await go(shell, "#/vendor/fortinet");
  const door = view.querySelector("a.library-link");
  assert.equal(door.getAttribute("href"), "https://teamstarwolf.github.io/TeamStarWolf/#/platforms/fortinet");
  assert.equal(door.getAttribute("href"), library.LINKS["vendor:fortinet"]);
  assert.ok(view.textContent.includes("CVE-2026-1000"), "the KEV entry whose vendorProject is Fortinet");
  assert.ok(!view.textContent.includes("CVE-2026-1001"), "a KEV entry for another vendor is not listed");
  assert.ok(view.textContent.includes("Vendor fixes exploited flaw"));
  const microsoft = await go(shell, "#/vendor/microsoft");
  const pages = [...microsoft.querySelectorAll("a.library-link")].map(anchor => anchor.getAttribute("href"));
  assert.ok(pages.includes("https://teamstarwolf.github.io/TeamStarWolf/#/platforms/entra-id"), "a vendor lists its products' library pages");
});

test("an actor page links back to the library's ATT&CK group page", async () => {
  const shell = await boot({ hash: "#/actors" });
  let view = shell.doc.querySelector("#view");
  assert.ok(view.textContent.includes("APT29"));
  assert.ok([...view.querySelectorAll("a.library-link")].some(anchor => anchor.getAttribute("href") === "https://teamstarwolf.github.io/TeamStarWolf/#/mitre/groups/G0016"));
  view = await go(shell, "#/actor/G0016");
  assert.equal(view.querySelector("a.library-link").getAttribute("href"), "https://teamstarwolf.github.io/TeamStarWolf/#/mitre/groups/G0016");
  assert.ok(view.textContent.includes("Headline a-research"));
  const malware = await go(shell, "#/malware/S0154");
  assert.equal(malware.querySelector("a.library-link").getAttribute("href"), "https://teamstarwolf.github.io/TeamStarWolf/#/mitre/software/S0154");
  assert.ok(malware.textContent.includes("No entry in the live window names this"));
});

test("every tag value has a page or a filter that finds its entries, and zero counts are hidden", async () => {
  const shell = await boot({ hash: "#/tags" });
  const view = shell.doc.querySelector("#view");
  const groups = [...view.querySelectorAll(".tag-group")];
  const fields = groups.map(group => group.getAttribute("data-field"));
  for (const field of ["kind", "class", "event", "exp", "kev", "vendor", "actor", "sector", "region", "source"]) assert.ok(fields.includes(field), field);
  assert.ok(!fields.includes("malware") && !fields.includes("cwe") && !fields.includes("tech"), "a field with no value in scope is not shown");
  const rows = [...JSON.parse(files().bodies["./data/v7/live/2026-11.json"]).rows, ...JSON.parse(files().bodies["./data/v7/live/2026-10.json"]).rows];
  const normalized = [...normalizeArticleShard({ schema_version: 7, kind: "articles", period: "2026-11", rows }, "live/2026-11.json")];
  let checked = 0;
  for (const anchor of view.querySelectorAll(".tag-group a.chip")) {
    const href = anchor.getAttribute("href");
    const shown = Number(anchor.textContent.split(" ").pop());
    assert.ok(shown > 0, "no zero-count value: " + anchor.textContent);
    const route = parseRoute(href, "");
    assert.equal(route.rewrite, false, href + " is canonical");
    if (route.view === "explore") { assert.equal(filterRows(normalized, route, { contentDate: "2026-11-03", cveIndex: null }).length >= 1, true, href); checked++; }
    else assert.ok(["vendor", "actor", "malware"].includes(route.view), href);
  }
  assert.ok(checked >= 10);
  const scoped = await go(shell, "#/tags?year=1998");
  assert.ok(scoped.textContent.includes("Microsoft Security Bulletins 2"));
  assert.ok(scoped.querySelector("a[href='#/explore?kind=bulletin&year=1998']"), "a value's filter keeps the chosen year");
});

// The Explorer's entry cards for hash, without the empty-state line.
async function explorerEntries(shell, hash) {
  await go(shell, hash);
  assert.equal(shell.doc.querySelector("#explore").hidden, false, hash + " opens the Explorer");
  return [...shell.doc.querySelectorAll("#results li")].filter(item => item.getAttribute("class") !== "empty");
}

test("with a year chosen, every tag value, vendors, actors and malware included, links to that year's entries", async () => {
  const shell = await boot();
  const view = await go(shell, "#/tags?year=2010");
  const fields = [...view.querySelectorAll(".tag-group")].map(group => group.getAttribute("data-field"));
  for (const field of ["vendor", "actor", "malware"]) assert.ok(fields.includes(field), field + " has a value in 2010");
  const links = [...view.querySelectorAll(".tag-group a.chip")].map(anchor => [anchor.closest(".tag-group").getAttribute("data-field"), anchor.getAttribute("href"), Number(anchor.textContent.split(" ").pop())]);
  assert.ok(links.length >= 8, links.length);
  for (const [field] of [["vendor"], ["actor"], ["malware"]]) assert.ok(links.some(([name]) => name === field), field);
  assert.ok(links.some(([, href]) => href === "#/explore?vendor=microsoft&year=2010"), "the vendor door keeps the year");
  assert.ok(links.some(([, href]) => href === "#/explore?actor=G0016&year=2010"), "the actor door keeps the year");
  assert.ok(links.some(([, href]) => href === "#/explore?malware=S0154&year=2010"), "the malware door keeps the year");
  for (const [field, href, shown] of links) {
    const route = parseRoute(href, "");
    assert.equal(route.view, "explore", field + " " + href + " opens the Explorer");
    assert.equal(route.query.year, "2010", href + " keeps the year");
    const entries = await explorerEntries(shell, href);
    assert.ok(entries.length >= 1, href + " finds at least one entry");
    assert.equal(entries.length, shown, href + " finds the entries the tag page counted");
  }
  const live = await go(shell, "#/tags");
  assert.ok(live.querySelector("a[href='#/vendor/fortinet']"), "without a year, a vendor still opens its own page");
});

test("with a year chosen, each actor and malware row links to that year's entries", async () => {
  const shell = await boot();
  const view = await go(shell, "#/actors?year=2010");
  const rows = [...view.querySelectorAll("tbody tr")].map(tr => [tr.querySelector("th a").getAttribute("href"), Number(tr.querySelectorAll("td")[1].textContent)]);
  assert.deepEqual(rows.map(([href]) => href).sort(), ["#/explore?actor=G0016&year=2010", "#/explore?malware=S0154&year=2010"]);
  for (const [href, shown] of rows) {
    const entries = await explorerEntries(shell, href);
    assert.ok(entries.length >= 1, href);
    assert.equal(entries.length, shown, href + " finds the entries the row counted");
  }
  const live = await go(shell, "#/actors");
  assert.ok(live.querySelector("tbody a[href='#/actor/G0016']"), "without a year, an actor still opens its own page");
});

test("the tag alias route opens the Explorer filtered to that value", async () => {
  const shell = await boot({ hash: "#/tag/vendor/fortinet" });
  assert.equal(shell.location.hash, "#/explore?vendor=fortinet");
  assert.equal(shell.doc.querySelectorAll("#results li").length, 1);
  const cwe = parseRoute("#/tag/cwe/CWE-787", "");
  assert.equal(formatRoute(cwe), "#/explore?cwe=CWE-787");
});

test("a bad report catalog shows catalog unavailable and leaves every other view working", async () => {
  const bad = site({ reports: { schema_version: 7, kind: "reports", status: "available", catalog_sha256: "c".repeat(64), catalog: { schema_version: 1, reports: [{ id: "not-a-valid-id", title: "x" }] } } });
  const shell = await boot({ hash: "#/reports", app: bad });
  const view = shell.doc.querySelector("#view");
  assert.ok(view.textContent.includes("Report catalog unavailable"), view.textContent.slice(0, 300));
  assert.ok(view.textContent.includes("Collector runs and cadence"), "the run record still renders");
  assert.equal(shell.location.reloads, 0, "a bad catalog never reloads the page");
  assert.equal(shell.doc.querySelector("#notice").hidden, true);
  for (const [hash, phrase] of [["#/history/1998", "MS98-001"], ["#/vendors", "Fortinet"], ["#/explore", ""], ["#/method", "Exploitation evidence"], ["#/sources", "History coverage by source and year"]]) {
    const target = await go(shell, hash);
    if (hash === "#/explore") assert.ok(shell.doc.querySelectorAll("#results li").length >= 4);
    else assert.ok(target.textContent.includes(phrase), hash);
  }
  shell.doc.querySelector("#sidebar-toggle").dispatchEvent({ type: "click" });
  await settle(80);
  assert.ok(shell.doc.querySelector("#sidebar-body").textContent.includes("Report catalog unavailable"));
});

test("Reports holds every edition and the run record; Sources holds the coverage matrix; Method and Data hold the licence table", async () => {
  const shell = await boot({ hash: "#/reports" });
  let view = shell.doc.querySelector("#view");
  assert.ok(view.textContent.includes("November 1 daily") && view.textContent.includes("Editions by cadence: daily 1"));
  assert.ok(view.textContent.includes("cron 7 */2 * * *"));
  view = await go(shell, "#/sources");
  const matrix = view.querySelector("table.coverage-matrix");
  assert.ok(matrix, "the matrix renders");
  assert.equal(matrix.querySelectorAll("thead th").length, 30, "a column per year from 1998 to 2026");
  assert.ok(matrix.textContent.includes("C 2") && matrix.textContent.includes("U"));
  for (const hash of ["#/method", "#/data"]) {
    view = await go(shell, hash);
    for (const phrase of ["Creative Commons Zero 1.0", "CVE Program Terms of Use", "© 2026 The MITRE Corporation", "Common Weakness Enumeration (CWE™)", "MIT License"]) assert.ok(view.textContent.includes(phrase), hash + " " + phrase);
  }
  view = await go(shell, "#/method");
  const terms = [...view.querySelectorAll("tbody th")].map(cell => cell.textContent);
  for (const term of ["known", "reported", "unknown", "high", "medium", "low", "complete", "filtered", "partial", "sample", "gap", "unreachable"]) assert.ok(terms.includes(term), term);
});

test("CVE ids link CVE.org, and a curated row's pinned library evidence gets its rendered library page beside it", async () => {
  const shell = await boot({ hash: "#/explore?open=a-kev-guidance" });
  const body = shell.doc.querySelector("#record-body");
  assert.ok([...body.querySelectorAll("a")].some(anchor => anchor.getAttribute("href") === "https://www.cve.org/CVERecord?id=CVE-2026-1000"));
  assert.ok([...body.querySelectorAll("a.library-link")].some(anchor => anchor.getAttribute("href") === "https://teamstarwolf.github.io/TeamStarWolf/#/platforms/fortinet"));
  shell.doc.querySelector("#record-close").dispatchEvent({ type: "click" });
  await go(shell, "#/explore?year=1998&open=hist-curated-1998");
  const curated = shell.doc.querySelector("#record-body");
  const links = [...curated.querySelectorAll("a")].map(anchor => anchor.getAttribute("href"));
  assert.ok(links.includes(PINNED_EVIDENCE), "the pinned evidence link stays");
  assert.ok(links.includes(library.PINNED[PINNED_EVIDENCE]), "the rendered library page sits beside it");
  await go(shell, "#/cve/CVE-2026-1000");
  await settle(80);
  assert.ok([...shell.doc.querySelectorAll("#cve-body a")].some(anchor => anchor.getAttribute("href") === "https://www.cve.org/CVERecord?id=CVE-2026-1000"));
});

test("every library link in the generated module and on every view is a library site URL that passes safeUrl", async () => {
  const values = [...Object.values(library.LINKS), ...Object.values(library.PINNED)];
  assert.ok(values.length > 1000);
  for (const url of values) {
    assert.ok(url.startsWith(LIBRARY_PREFIX), url);
    assert.equal(safeUrl(url), url, url);
  }
  assert.equal(library.SITE + "#/", LIBRARY_PREFIX);
  const shell = await boot();
  const seen = new Set();
  const collect = () => { for (const anchor of shell.doc.querySelectorAll("a")) { const href = anchor.getAttribute("href") || ""; if (href.includes("teamstarwolf.github.io/TeamStarWolf/#")) seen.add(href); } };
  for (const hash of ["#/vendors", "#/vendor/fortinet", "#/vendor/microsoft", "#/actors", "#/actor/G0016", "#/tags", "#/explore?open=a-kev-guidance", "#/explore?year=1998&open=hist-curated-1998"]) { await go(shell, hash); collect(); }
  assert.ok(seen.size >= 5, [...seen].join(" "));
  for (const href of seen) {
    assert.ok(href.startsWith(LIBRARY_PREFIX), href);
    assert.equal(safeUrl(href), href);
    assert.ok(values.includes(href), href + " comes from site/js/library.js");
  }
});

test("the coverage validator refuses a status outside the list and reads a stub as no claim", () => {
  const good = coverage();
  assert.equal(normalizeCoverage(good).rows.length, 58);
  assert.throws(() => normalizeCoverage({ ...good, rows: [{ ...good.rows[0], status: "everything" }] }));
  assert.throws(() => normalizeCoverage({ ...good, rows: [good.rows[0], good.rows[0]] }), "a duplicate source and year");
  assert.equal(normalizeCoverage({ schema_version: 7, kind: "coverage", status: "stub", rows: [], note: "Not yet." }).status, "stub");
});

test("a narrow window closes the sidebar after a view is chosen from it", async () => {
  const shell = await boot({ matches: true });
  shell.doc.querySelector("#sidebar-toggle").dispatchEvent({ type: "click" });
  await settle(80);
  const entry = [...shell.doc.querySelectorAll("#sidebar-body .side-views a")].find(anchor => anchor.getAttribute("href") === "#/history");
  shell.doc.dispatchEvent({ type: "click", target: entry, button: 0, preventDefault() { this.defaultPrevented = true; } });
  await settle(80);
  assert.equal(shell.location.hash, "#/history");
  assert.equal(shell.doc.querySelector("#sidebar").hidden, true);
});
