// The page shell run on site/index.html in a small DOM with a synthetic schema 7 site:
// Explorer-first DOM order, the collapsed sidebar, URL state, the poll (no read while hidden,
// no parse on a 304), the deploy-skew guard (reload once per session) and its toast, Today's
// bounded recent.json, the brief file checks and the cadence statement.
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { inOrder } from "./dom.js";
import { CONTENT_DATE, ROOT, files, page, row, server, settle, statusRow, storage } from "./fixtures.js";
import { createApp } from "../../site/js/main.js";
import { RELOAD_KEY } from "../../site/js/guard.js";
import { SEEN_KEY, nextPatchTuesday } from "../../site/js/views/today.js";
import { cveRegister, exportCsv, exportJson, rowMatches, today as todayBuckets } from "../../site/js/filters.js";
import { normalizeIntake } from "../../site/js/validate.js";
import { normalizeCveIndex } from "../../site/js/validate.js";

async function boot({ hash = "", search = "", site = files(), session = storage(), local = storage(), moduleUrl = null, hidden = false } = {}) {
  const shell = page(hash, search);
  shell.doc.hidden = hidden;
  const http = server(site.bodies);
  const app = createApp({ doc: shell.doc, win: shell.win, location: shell.location, history: shell.history, storage: local, session, fetchImpl: http.fetch,
    subtle: webcrypto.subtle, moduleUrl, every: () => 0, loadLabels: async () => ({ default: { "vendor:fortinet": "Fortinet", "actor:G0016": "APT29" } }) });
  await app.start();
  await settle(60);
  return { ...shell, http, app, site, session, local };
}

const ids = elements => elements.map(element => element.getAttribute("id")).filter(Boolean);

test("the Explorer is first: only the brand bar and tab strip precede the search box and results", async () => {
  const { doc } = await boot();
  const all = inOrder(doc);
  const body = all.filter(element => element.parentNode === doc.body);
  assert.deepEqual(body.slice(0, 3).map(element => element.localName + (element.getAttribute("class") ? "." + element.getAttribute("class") : "")), ["header.bar", "nav.tabs", "div.layout"]);
  const position = selector => all.indexOf(doc.querySelector(selector));
  const search = position("#q");
  const firstRow = position("#results li");
  assert.ok(search > 0 && firstRow > search, "the search box comes before the first result row");
  for (const selector of ["#filter-rail", "#f-sort", "#results"]) assert.ok(position(selector) > search - 3 && position(selector) < firstRow + 1, selector);
  // Nothing before the search box except the bar, the tab strip and the Explorer's own heading and form.
  const before = all.slice(all.indexOf(doc.body) + 1, search);
  const allowed = element => element.closest("header.bar") || element.closest("nav.tabs") || element.closest("#explore") || ["layout", "main"].includes(element.getAttribute("id"));
  assert.deepEqual(before.filter(element => !allowed(element)).map(element => element.localName + "#" + element.getAttribute("id")), []);
  // Every other reporting element comes after the results, and the sidebar starts collapsed.
  for (const selector of ["#view", "#sidebar", "#notice"]) assert.ok(position(selector) > firstRow, selector);
  assert.equal(doc.querySelector("#sidebar").hidden, true);
  assert.equal(doc.querySelector("#sidebar-toggle").getAttribute("aria-expanded"), "false");
  assert.equal(doc.querySelector("#view").hidden, true);
  assert.ok(doc.querySelectorAll("#results li").length >= 4);
  assert.equal(doc.querySelector(".tabs a[aria-current=page]").getAttribute("data-view"), "explore");
});

test("the top bar carries a persistent Feeds and exports link to Subscribe, visible on the landing", async () => {
  const { doc, app } = await boot();
  const link = doc.querySelector(".bar-actions a[href='#/subscribe']");
  assert.ok(link, "a header shortcut surfaces the feeds and exports from every view");
  assert.ok(!link.hidden);
  assert.equal(link.textContent, "Feeds and exports");
  app.navigate({ view: "subscribe", id: null, query: {} });
  await settle(40);
  assert.equal(doc.querySelector(".tabs a[aria-current=page]").getAttribute("data-view"), "subscribe");
});

test("Today lists service-health incidents in their own section, not as advisories", async () => {
  const defaults = files();
  const recent = JSON.parse(defaults.bodies["./data/v7/recent.json"]);
  recent.rows = [...recent.rows, statusRow("inc-1", { published_at: "2026-11-02T09:00:00+00:00", source_name: "Example status page", title: "Example: API latency incident" })];
  const { doc } = await boot({ hash: "#/today", site: files({ extra: { "recent.json": recent } }) });
  const view = doc.querySelector("#view");
  const sectionOf = prefix => [...view.querySelectorAll("section")].find(section => { const h2 = section.querySelector("h2"); return h2 && h2.textContent.startsWith(prefix); });
  const advisories = sectionOf("Vendor and government advisories");
  const incidents = sectionOf("Service-health incidents");
  assert.ok(incidents, "a Service-health incidents section renders");
  assert.ok(incidents.querySelector("h2").textContent.includes("(1)"));
  assert.ok(incidents.textContent.includes("API latency incident"), "the incident shows in its own section");
  assert.ok(!advisories.textContent.includes("API latency incident"), "the incident is not mislabelled as an advisory");
  assert.ok(incidents.querySelector("a[href='#/status']"), "the section links to the Service health board");
});

test("the Today press list clusters the same story from several outlets into one card", async () => {
  const defaults = files();
  const recent = JSON.parse(defaults.bodies["./data/v7/recent.json"]);
  const aPress = recent.rows.find(item => item.id === "a-press");
  const dupe = { ...aPress, id: "a-press-2", url: "https://publisher.example.org/a-press-2", source_id: "news-2", source_name: "Second Outlet" };
  recent.rows = [...recent.rows, dupe];
  const { doc } = await boot({ hash: "#/today", site: files({ extra: { "recent.json": recent } }) });
  const view = doc.querySelector("#view");
  const press = [...view.querySelectorAll("section")].find(section => { const h2 = section.querySelector("h2"); return h2 && h2.textContent.startsWith("Press"); });
  assert.ok(press, "the Press section renders");
  assert.ok(press.querySelector("h2").textContent.includes("2 entries in 1 story"), press.querySelector("h2").textContent);
  assert.equal(press.querySelectorAll("li.card").length, 1, "the two outlets collapse to one card");
  assert.ok(press.querySelector(".also-reported"), "the card carries an also-reported line");
  assert.ok(press.textContent.includes("Also reported by Second Outlet"), press.textContent);
});

test("the News view clusters the same story from several outlets, like Today's press list", async () => {
  const defaults = files();
  const live = JSON.parse(defaults.bodies["./data/v7/live/2026-11.json"]);
  const press = live.rows.find(row => row.source_id === "news");
  live.rows = [...live.rows, { ...press, id: "a-press-2", url: "https://publisher.example.org/a-press-2", source_id: "news-2", source_name: "Second Outlet" }];
  const { doc } = await boot({ hash: "#/news", site: files({ extra: { "live/2026-11.json": live } }) });
  const results = doc.querySelector("#results");
  assert.equal(results.querySelectorAll("li.card").length, 1, "the two outlets collapse to one card");
  assert.ok(results.querySelector(".also-reported"), "the card names the other outlet");
  assert.ok(doc.querySelector("#results-status").textContent.includes("2 entries in 1 story"), doc.querySelector("#results-status").textContent);
});

test("the page's intake validator accepts a capped source (entry_limit below 150)", () => {
  const intake = entryLimit => ({ items_seen: 30, items_processed: 30, items_admitted: 30, items_rejected: 0, items_filtered: 0, items_unprocessed: 0,
    entry_limit: entryLimit, cve_limit: 100, rejection_reasons: { invalid_link_or_title: 0, cve_limit_exceeded: 0 },
    attempted_at: "2026-11-01T12:00:00+00:00", response_sha256: "a".repeat(64) });
  const source = { id: "pod", status: "ok" };
  assert.equal(normalizeIntake(intake(30), source).entry_limit, 30, "a capped podcast source is accepted on the page");
  assert.equal(normalizeIntake(intake(150), source).entry_limit, 150, "the default still works");
  assert.throws(() => normalizeIntake(intake(0), source));
  assert.throws(() => normalizeIntake(intake(151), source));
});

test("the CVE register keeps published records above rejected or unknown ones", () => {
  const index = new Map([
    ["CVE-2026-9999", { cve: "CVE-2026-9999", record_state: "UNKNOWN", guidance: "needs-review", required_action: false, source_status: "failed", kev_added: null, score: null, version: null, epss: null, weaknesses: [] }],
    ["CVE-2026-1000", { cve: "CVE-2026-1000", record_state: "PUBLISHED", guidance: "needs-review", required_action: false, source_status: "ok", kev_added: null, score: 9.8, version: "3.1", epss: null, weaknesses: ["CWE-787"] }],
  ]);
  assert.deepEqual(cveRegister(index, {}).map(row => row.cve), ["CVE-2026-1000", "CVE-2026-9999"], "published first despite the lower CVE number under cve-desc");
  assert.deepEqual(cveRegister(index, { sort: "cvss-desc" }).map(row => row.cve), ["CVE-2026-1000", "CVE-2026-9999"], "the unknown record stays last by CVSS too");
});

test("the CVE register drops the Needs review label but keeps an informative one", async () => {
  const { doc } = await boot({ hash: "#/cves" });
  const text = doc.querySelector("#view").textContent;
  assert.ok(!text.includes("Needs review"), "the uninformative default label is not shown");
  assert.ok(text.includes("CISA action"), "an informative guidance label is kept");
});

test("the Explorer surfaces one-click Exploited and KEV-linked quick filters", async () => {
  const { doc, app } = await boot();
  const chipText = () => [...doc.querySelectorAll("#quick-filters a.quick-chip")].map(anchor => anchor.textContent);
  assert.ok(chipText().some(text => text.startsWith("Known exploited")), chipText().join(" | "));
  assert.ok(chipText().some(text => text.startsWith("Reported exploited")));
  assert.ok(chipText().some(text => text.startsWith("KEV-linked")));
  const known = () => [...doc.querySelectorAll("#quick-filters a.quick-chip")].find(anchor => anchor.textContent.startsWith("Known exploited"));
  assert.ok(known().getAttribute("href").includes("exp=known"), "the chip sets the exploited filter");
  assert.equal(known().getAttribute("aria-pressed"), "false");
  app.navigate({ view: "explore", id: null, query: { exp: "known" } });
  await settle(40);
  assert.equal(known().getAttribute("aria-pressed"), "true", "the active filter reads as pressed");
  assert.ok(known().getAttribute("class").includes("quick-chip-on"));
});

test("the kind=podcast guard: podcasts match only the Podcasts view, never News, and drop from Today's press bucket", () => {
  const pod = { id: "pod-1", time: 1, kind: "podcast", day: "2026-11-02", cves: [], source_name: "Darknet Diaries", title: "Episode", search: "episode", source_id: "darknet-diaries", exploited: "unknown", t: { source_class: "press", desk: "podcasts" } };
  const press = { ...pod, id: "press-1", time: 2, kind: "reporting", source_id: "news", source_name: "News Desk" };
  assert.equal(rowMatches(pod, {}, { view: "podcasts" }), true, "the Podcasts view matches podcast rows");
  assert.equal(rowMatches(pod, {}, { view: "news" }), false, "a podcast never matches the News view");
  assert.equal(rowMatches(pod, {}, { view: "advisories" }), false, "a podcast never matches Advisories");
  assert.equal(rowMatches(press, {}, { view: "news" }), true, "ordinary press is unaffected by the guard");
  assert.equal(rowMatches(press, {}, { view: "podcasts" }), false, "the Podcasts view shows only podcasts");
  const day = todayBuckets([pod, press], [], "2026-11-02");
  assert.ok(day.news.includes(press) && !day.news.includes(pod), "Today's press bucket keeps press and drops podcasts");
});

test("the Podcasts view shows podcast episodes, kept out of News and Today's press feed", async () => {
  const defaults = files();
  const podcast = row("pod-1", { kind: "podcast", source_id: "darknet-diaries", source_name: "Darknet Diaries", published_at: "2026-11-02", title: "Darknet Diaries 182 Example Episode", url: "https://darknetdiaries.com/episode/182/", tagging: { source_class: "press", desk: "podcasts", event_type: [["disclosure", "kind-default", "high"]], exploitation: ["unknown", "none", "high"] } });
  const live = JSON.parse(defaults.bodies["./data/v7/live/2026-11.json"]); live.rows = [...live.rows, podcast];
  const recent = JSON.parse(defaults.bodies["./data/v7/recent.json"]); recent.rows = [...recent.rows, podcast];
  const make = hash => boot({ hash, site: files({ extra: { "live/2026-11.json": live, "recent.json": recent } }) });
  const pods = await make("#/podcasts");
  const results = pods.doc.querySelector("#results");
  assert.equal([...results.querySelectorAll("li.card")].length, 1, "the episode shows on the Podcasts desk");
  assert.ok(results.textContent.includes("Darknet Diaries 182 Example Episode"));
  assert.ok(results.querySelector(".badge-podcast"), "it carries the Podcast badge");
  const news = await make("#/news");
  assert.ok(!news.doc.querySelector("#results").textContent.includes("Darknet Diaries 182 Example Episode"), "the episode is kept out of News");
  const today = await make("#/today");
  assert.ok(!today.doc.querySelector("#view").textContent.includes("Darknet Diaries 182 Example Episode"), "the episode is kept out of Today's press feed");
});

test("the Podcasts desk suppresses CVE badges on episode rows and hides the CVE-centric sorts and filters", async () => {
  const defaults = files();
  // A real episode whose title mentions a CVE carries that CVE id, but the desk shows no CVE, KEV, CVSS or EPSS signal.
  const podcast = row("pod-cve", { kind: "podcast", source_id: "darknet-diaries", source_name: "Darknet Diaries", published_at: "2026-11-02", title: "Darknet Diaries 183 Supply Chain Episode", url: "https://darknetdiaries.com/episode/183/", cves: ["CVE-2026-1000"], tagging: { source_class: "press", desk: "podcasts", event_type: [["disclosure", "kind-default", "high"]], exploitation: ["unknown", "none", "high"] } });
  const live = JSON.parse(defaults.bodies["./data/v7/live/2026-11.json"]); live.rows = [...live.rows, podcast];
  const recent = JSON.parse(defaults.bodies["./data/v7/recent.json"]); recent.rows = [...recent.rows, podcast];
  const make = hash => boot({ hash, site: files({ extra: { "live/2026-11.json": live, "recent.json": recent } }) });

  const pods = await make("#/podcasts");
  const card = pods.doc.querySelector("#results li.card");
  assert.ok(card && card.textContent.includes("Darknet Diaries 183 Supply Chain Episode"), "the episode shows on the Podcasts desk");
  assert.equal(pods.doc.querySelector("#results .chip-cve"), null, "no CVE badge renders on a podcast row that carries a CVE");
  assert.equal(pods.doc.querySelector('#f-sort option[value="cvss-desc"]').hidden, true, "the CVSS sort is hidden on Podcasts");
  assert.equal(pods.doc.querySelector('#f-sort option[value="epss-desc"]').hidden, true, "the EPSS sort is hidden on Podcasts");
  assert.equal(pods.doc.querySelector('#f-sort option[value="cve-desc"]').hidden, true, "the CVE sort is hidden on Podcasts");
  assert.equal(pods.doc.querySelector("#f-kev").closest("label").hidden, true, "the KEV-linked filter is hidden on Podcasts");
  assert.equal(pods.doc.querySelector("#f-action").closest("label").hidden, true, "the required-action filter is hidden on Podcasts");

  // Every other view keeps the CVE badges, sorts and filters.
  const news = await make("#/news");
  assert.ok(news.doc.querySelector("#results .chip-cve"), "CVE badges still render on News rows");
  assert.equal(news.doc.querySelector('#f-sort option[value="cvss-desc"]').hidden, false, "the CVSS sort stays on News");
  assert.equal(news.doc.querySelector('#f-sort option[value="cve-desc"]').hidden, false, "the CVE sort stays on News");
  assert.equal(news.doc.querySelector("#f-kev").closest("label").hidden, false, "the KEV-linked filter stays on News");
});

test("exportCsv and exportJson serialize the rows in view: headline, link and metadata only, properly escaped", () => {
  const rows = [
    { day: "2026-11-02", kind: "reporting", source_name: "News, Desk", title: "A \"quoted\" title\nwith newline", url: "https://ex.org/a", cves: ["CVE-2026-1", "CVE-2026-2"], exploited: "known", t: { source_class: "press", desk: "security" } },
    { day: "", kind: "podcast", source_name: "Darknet Diaries", title: "Plain episode", url: "https://ex.org/b", cves: [], exploited: "unknown", t: { desk: "podcasts" } }
  ];
  const csv = exportCsv(rows);
  const lines = csv.split("\r\n");
  assert.equal(lines[0], "date,kind,source,title,url,cves,desk,source_class,exploitation", "the header names every column");
  assert.ok(lines[1].startsWith("2026-11-02,reporting,\"News, Desk\","), "a comma in a value is quoted");
  assert.ok(lines[1].includes("\"A \"\"quoted\"\" title\nwith newline\""), "quotes are doubled and a newline is kept inside the quoted cell");
  assert.ok(lines[1].includes(",CVE-2026-1 CVE-2026-2,"), "multiple CVEs join with a space");
  assert.ok(csv.endsWith("\r\n"), "the file ends with a trailing CRLF");
  const json = JSON.parse(exportJson(rows));
  assert.equal(json.length, 2);
  assert.deepEqual(json[0], { date: "2026-11-02", kind: "reporting", source: "News, Desk", title: "A \"quoted\" title\nwith newline", url: "https://ex.org/a", cves: "CVE-2026-1 CVE-2026-2", desk: "security", source_class: "press", exploitation: "known" });
  assert.equal(json[1].cves, "", "an entry with no CVE exports an empty cves field");
  assert.equal(json[1].source_class, "", "a podcast with no explicit class exports an empty class, never a CVE-implying default");
});

test("exportCsv neutralizes spreadsheet formula injection in untrusted headline text", () => {
  const rows = ["=cmd|' /c calc'!A1", "+1+2", "-3", "@SUM(A1)", "\tlead tab", "safe title"].map((title, index) =>
    ({ day: "2026-11-02", kind: "reporting", source_name: "Src", title, url: "https://ex.org/" + index, cves: [], exploited: "unknown", t: { source_class: "press", desk: "security" } }));
  const dataLines = exportCsv(rows).trimEnd().split("\r\n").slice(1);
  // A formula-leading title is prefixed with an apostrophe (and then quoted if it also needs quoting).
  assert.ok(dataLines[0].includes("\"'=cmd|' /c calc'!A1\"") || dataLines[0].includes("'=cmd|"), "an = formula is neutralized");
  assert.ok(dataLines[1].includes(",'+1+2,"), "a + formula is neutralized");
  assert.ok(dataLines[2].includes(",'-3,"), "a - formula is neutralized");
  assert.ok(dataLines[3].includes(",'@SUM(A1),"), "an @ formula is neutralized");
  assert.ok(dataLines[5].includes(",safe title,"), "an ordinary title is left untouched");
});

test("the Explorer exports the rows now in view: a click builds a CSV from the filtered set", async () => {
  const captured = [];
  const view = await boot({ hash: "#/news" });
  // The page uses an object URL where the browser has one; stub it to capture the serialized text.
  view.win.Blob = function (parts) { this.text = parts[0]; };
  view.win.URL = { createObjectURL(blob) { captured.push(blob.text); return "blob:x"; }, revokeObjectURL() {} };
  view.doc.querySelector("#export-csv").dispatchEvent({ type: "click" });
  await settle(20);
  assert.equal(captured.length, 1, "a CSV was produced on click");
  const csv = captured[0];
  assert.ok(csv.startsWith("date,kind,source,title,url,cves,desk,source_class,exploitation\r\n"), "the CSV carries the header");
  assert.ok(csv.trimEnd().split("\r\n").length >= 2, "at least one data row is exported");
  // The default fixture's press row carries CVE-2026-1002 and shows on News, so the export is the view's rows.
  assert.ok(csv.includes("CVE-2026-1002"), "the exported rows are the ones the News view shows");
});

test("Copy link copies a shareable link to the current view and announces the result", async () => {
  const copied = [];
  const view = await boot({ hash: "#/news" });
  view.win.navigator = { clipboard: { writeText(text) { copied.push(text); return Promise.resolve(); } } };
  view.location.href = "https://teamstarwolf.github.io/intelligence-hub/#/news?q=fortinet";
  view.doc.querySelector("#copy-link").dispatchEvent({ type: "click" });
  await settle(20);
  assert.deepEqual(copied, ["https://teamstarwolf.github.io/intelligence-hub/#/news?q=fortinet"], "the current view's URL is copied");
  assert.equal(view.doc.querySelector("#copy-status").textContent, "Link to this view copied to the clipboard.", "the result is announced for assistive tech");
  assert.equal(view.doc.querySelector("#copy-link").textContent, "Copied", "the button confirms the copy");
});

test("Copy link reports a failure instead of silently dropping it when the clipboard write is rejected", async () => {
  const view = await boot({ hash: "#/explore" });
  view.win.navigator = { clipboard: { writeText() { return Promise.reject(new Error("denied")); } } };
  view.location.href = "https://teamstarwolf.github.io/intelligence-hub/#/explore";
  view.doc.querySelector("#copy-link").dispatchEvent({ type: "click" });
  await settle(20);
  assert.ok(view.doc.querySelector("#copy-status").textContent.startsWith("Could not copy"), "a rejected copy is reported");
  assert.equal(view.doc.querySelector("#copy-link").textContent, "Copy link", "the button label is not left on Copied after a failure");
});

test("the / key jumps to the search box on a list view, but never while typing, in a dialog, or with a modifier", async () => {
  const { doc } = await boot({ hash: "#/explore" });
  const search = doc.querySelector("#q");
  assert.equal(doc.querySelector(".search-kbd").textContent, "/", "a visible / hint renders in the search field");
  assert.equal(search.getAttribute("aria-keyshortcuts"), "/", "the search box advertises its shortcut to assistive tech");
  // Nothing focused: / focuses search and is consumed so it is not also typed.
  let prevented = false;
  doc.dispatchEvent({ type: "keydown", key: "/", preventDefault() { prevented = true; } });
  assert.equal(doc.activeElement, search, "/ focuses the search box");
  assert.equal(prevented, true, "the key is consumed");
  // The search box now has focus (an input): / is left alone so the character is typed.
  prevented = false;
  doc.dispatchEvent({ type: "keydown", key: "/", preventDefault() { prevented = true; } });
  assert.equal(prevented, false, "/ is not hijacked while an input has focus");
  // A modifier combo is left to the browser.
  doc.activeElement = doc.querySelector("#main");
  prevented = false;
  doc.dispatchEvent({ type: "keydown", key: "/", ctrlKey: true, preventDefault() { prevented = true; } });
  assert.equal(prevented, false, "Ctrl+/ is left alone");
});

test("the / key does nothing on a view without a search box", async () => {
  const { doc } = await boot({ hash: "#/status" });
  const before = doc.activeElement;
  let prevented = false;
  doc.dispatchEvent({ type: "keydown", key: "/", preventDefault() { prevented = true; } });
  assert.equal(prevented, false, "/ is not consumed off a list view");
  assert.equal(doc.activeElement, before, "focus is unchanged");
});

test("the tab strip is two rows: the desks, then only the active desk's views, and the Panels list groups by desk", async () => {
  const { doc, app } = await boot();
  const desks = [...doc.querySelectorAll(".tabs .desks a")];
  assert.deepEqual(desks.map(tab => tab.getAttribute("data-desk")), ["security", "infrastructure", "podcasts", "reference"]);
  assert.deepEqual(desks.map(tab => tab.getAttribute("href")), ["#/today", "#/status", "#/podcasts", "#/history"]);
  const views = [...doc.querySelectorAll(".tabs .views a")];
  assert.equal(views.length, 20, "every view link stays in the DOM");
  const shown = () => views.filter(tab => !tab.hidden).map(tab => tab.getAttribute("data-view"));
  // The Explorer landing sits on the Security desk, so its reading views are in the top nav at once.
  assert.equal(desks.find(tab => tab.getAttribute("aria-current") === "location").getAttribute("data-desk"), "security");
  assert.equal(doc.querySelector(".tabs .views").hidden, false);
  assert.deepEqual(shown(), ["explore", "today", "advisories", "kev", "research", "news", "cves", "actors", "patch-tuesday"]);
  for (const view of ["kev", "cves", "patch-tuesday", "advisories", "news", "research", "actors"]) assert.ok(shown().includes(view), view + " is on the top nav from arrival, not only behind the Panels button");
  assert.equal(doc.querySelector(".tabs a[aria-current=page]").getAttribute("data-view"), "explore");
  app.navigate({ view: "kev", id: null, query: {} });
  await settle(40);
  assert.equal(desks.find(tab => tab.getAttribute("aria-current") === "location").getAttribute("data-desk"), "security");
  assert.equal(doc.querySelector(".tabs .views").hidden, false);
  assert.deepEqual(shown(), ["explore", "today", "advisories", "kev", "research", "news", "cves", "actors", "patch-tuesday"]);
  assert.equal(doc.querySelector(".tabs a[aria-current=page]").getAttribute("data-view"), "kev");
  app.navigate({ view: "vendor", id: "fortinet", query: {} });
  await settle(40);
  assert.equal(desks.find(tab => tab.getAttribute("aria-current") === "location").getAttribute("data-desk"), "reference");
  assert.deepEqual(shown(), ["history", "vendors", "tags", "reports", "data", "subscribe", "sources", "method", "about"]);
  assert.equal(doc.querySelector(".tabs a[aria-current=page]").getAttribute("data-view"), "vendors", "a vendor page lights the Vendors tab");
  app.navigate({ view: "status", id: null, query: {} });
  await settle(40);
  assert.equal(desks.find(tab => tab.getAttribute("aria-current") === "location").getAttribute("data-desk"), "infrastructure");
  assert.deepEqual(shown(), ["status"]);
  assert.equal(doc.querySelector(".tabs .views").hidden, true, "a desk with one view shows no second row");
  doc.querySelector("#sidebar-toggle").dispatchEvent({ type: "click" });
  await settle(80);
  assert.deepEqual([...doc.querySelectorAll("#sidebar-body .side-desk")].map(item => item.textContent), ["Security desk", "Infrastructure desk", "Reference"]);
  const lists = [...doc.querySelectorAll("#sidebar-body .side-views")].map(list => [...list.querySelectorAll("a")].map(anchor => anchor.getAttribute("href")));
  assert.deepEqual(lists[1], ["#/status"]);
  assert.ok(lists[0].includes("#/today") && lists[2].includes("#/history"));
});

test("the Desk filter keeps rows of one desk, lists desks with counts, and status rows fall on the infrastructure desk", async () => {
  const site = files({ extra: { "live/2026-09.json": { schema_version: 7, kind: "articles", period: "2026-09", rows: [statusRow("status-vendor-1")] } } });
  const { doc, app } = await boot({ hash: "#/explore?desk=infrastructure", site });
  const rows = () => [...doc.querySelectorAll("#results li")].map(item => item.getAttribute("data-id"));
  assert.deepEqual(rows(), ["status-vendor-1"]);
  const options = [...doc.querySelectorAll("#f-desk option")].map(option => [option.value, option.textContent]);
  assert.deepEqual(options, [["", "All desks"], ["security", "Security (5)"], ["infrastructure", "Infrastructure (1)"]]);
  assert.equal(doc.querySelector("#f-desk").value, "infrastructure");
  app.navigate({ view: "explore", id: null, query: { desk: "security" } });
  await settle(40);
  assert.ok(!rows().includes("status-vendor-1") && rows().length === 5);
  // A row tagged before the desk existed sits on the security desk unless it is a status incident.
  const legacy = files({ extra: { "live/2026-09.json": { schema_version: 7, kind: "articles", period: "2026-09", rows: [
    statusRow("status-untagged", { tagging: { source_class: "vendor-primary", exploitation: ["unknown", "none", "high"] } }),
    statusRow("press-untagged", { origin: "publisher-feed", kind: "reporting", source_id: "news", source_name: "News Desk", tagging: { source_class: "press", exploitation: ["unknown", "none", "high"] } })
  ] } } });
  const second = await boot({ hash: "#/explore?desk=infrastructure", site: legacy });
  assert.deepEqual([...second.doc.querySelectorAll("#results li")].map(item => item.getAttribute("data-id")), ["status-untagged"]);
});

test("wall mode marks the document on Today and Service health only, and reads nothing more", async () => {
  const { doc, app, http } = await boot({ hash: "#/today?wall=1" });
  assert.equal(doc.documentElement.getAttribute("data-wall"), "1");
  const read = http.requests.length;
  app.navigate({ view: "today", id: null, query: {} });
  await settle(40);
  assert.equal(doc.documentElement.hasAttribute("data-wall"), false);
  assert.equal(http.requests.length, read, "leaving wall mode reads nothing");
  app.navigate({ view: "explore", id: null, query: { wall: "1" } });
  await settle(40);
  assert.equal(doc.documentElement.hasAttribute("data-wall"), false, "the Explorer drops the key");
  assert.equal(app.route().query.wall, undefined);
  app.navigate({ view: "status", id: null, query: { wall: "1" } });
  await settle(40);
  assert.equal(doc.documentElement.getAttribute("data-wall"), "1");
});

test("no hero, snapshot, report or ledger text sits in the Explorer", async () => {
  const { doc } = await boot();
  const text = doc.querySelector("#explore").textContent;
  for (const phrase of ["Signal. Context.", "SITUATION", "Reports &", "Source ledger", "Evidence over noise", "COLLECTOR INTEGRATIONS"]) assert.ok(!text.includes(phrase), phrase);
});

test("the sidebar opens from one button and fills only then", async () => {
  const { doc, http } = await boot();
  const before = http.requests.length;
  assert.equal(doc.querySelector("#sidebar-body").children.length, 0);
  doc.querySelector("#sidebar-toggle").dispatchEvent({ type: "click" });
  await settle(60);
  assert.equal(doc.querySelector("#sidebar").hidden, false);
  assert.equal(doc.querySelector("#layout").classList.contains("sidebar-open"), true);
  const text = doc.querySelector("#sidebar-body").textContent;
  for (const phrase of ["Today", "Snapshot", "Reports", "Sources", "Data exports", "Method and limits", "November 1 daily"]) assert.ok(text.includes(phrase), phrase);
  assert.ok(http.requests.length > before, "the panels read their data when opened");
  doc.querySelector("#sidebar-close").dispatchEvent({ type: "click" });
  assert.equal(doc.querySelector("#sidebar").hidden, true);
});

test("a filter change writes the hash with replaceState, and Back restores the earlier view", async () => {
  const { doc, history, location, win, app } = await boot({ hash: "#/explore?kind=advisory" });
  assert.equal(doc.querySelector("#f-kind").value, "advisory");
  const select = doc.querySelector("#f-exp"); select.value = "known"; select.dispatchEvent({ type: "change" });
  await settle(60);
  assert.equal(location.hash, "#/explore?kind=advisory&exp=known");
  assert.equal(history.entries.length, 1, "a filter change adds no history entry");
  assert.equal(doc.querySelectorAll("#results li").length, 1);
  app.navigate({ view: "today", id: null, query: {} });
  await settle(60);
  assert.equal(location.hash, "#/today");
  assert.equal(doc.querySelector("#explore").hidden, true);
  history.back();
  await settle(60);
  assert.equal(location.hash, "#/explore?kind=advisory&exp=known");
  assert.equal(doc.querySelector("#f-exp").value, "known");
  assert.equal(doc.querySelector("#explore").hidden, false);
  void win;
});

test("legacy A4 links are rewritten to the hash route on load", async () => {
  const { location, doc } = await boot({ hash: "#briefing", search: "?tag=vendor:fortinet&kind=advisory&utm_source=x" });
  assert.equal(location.hash, "#/explore?kind=advisory&vendor=fortinet");
  assert.equal(location.search, "");
  assert.equal(doc.querySelectorAll("#results li").length, 1);
  assert.ok(doc.querySelector("#results").textContent.includes("Vendor fixes exploited flaw"));
});

test("the KEV-linked filter keeps rows whose CVE guidance label is publisher guidance", async () => {
  const { doc } = await boot({ hash: "#/explore?kev=1" });
  const titles = doc.querySelector("#results").textContent;
  assert.ok(titles.includes("Vendor fixes exploited flaw"), "the publisher-guidance KEV row is shown");
  assert.ok(titles.includes("October advisory"));
  assert.ok(!titles.includes("Headline a-press"));
  // The CVE register: the old guidance filter (cisa-action) dropped CVE-2026-1000; kev=1 keeps it.
  const index = normalizeCveIndex(JSON.parse(files().bodies["./data/v7/cve-index.json"])).rows;
  const oldFilter = [...index.values()].filter(row => row.guidance === "cisa-action").map(row => row.cve);
  const kev = cveRegister(index, { kev: "1" }).map(row => row.cve);
  assert.deepEqual(oldFilter, ["CVE-2026-1001"]);
  assert.deepEqual(kev.sort(), ["CVE-2026-1000", "CVE-2026-1001"]);
  assert.deepEqual(cveRegister(index, { action: "1" }).map(row => row.cve).sort(), ["CVE-2026-1000", "CVE-2026-1001"]);
});

test("a pasted #/cve/<id> link opens the CVE dialog over the register with the saved brief", async () => {
  const { doc, http, location } = await boot({ hash: "#/cve/CVE-2026-1000" });
  await settle(60);
  assert.equal(doc.querySelector("#cve-dialog").open, true);
  assert.equal(doc.querySelector("#cve-title").textContent, "CVE-2026-1000");
  assert.ok(doc.querySelector("#cve-body").textContent.includes("CNA title for CVE-2026-1000"));
  assert.ok(doc.querySelector("#view").textContent.includes("CVE register"));
  assert.ok(http.requests.some(request => request.path === "./data/briefs.json"));
  doc.querySelector("#cve-close").dispatchEvent({ type: "click" });
  await settle(60);
  assert.equal(location.hash, "#/cves", "closing a pasted dialog replaces it with the register");
  assert.equal(doc.querySelector("#cve-dialog").open, false);
});

test("an open record in the URL opens its detail dialog", async () => {
  const { doc } = await boot({ hash: "#/explore?open=a-kev-guidance" });
  assert.equal(doc.querySelector("#record-dialog").open, true);
  const text = doc.querySelector("#record-body").textContent;
  assert.ok(text.includes("Vendor fixes exploited flaw") && text.includes("Fortinet") && text.includes("KEV-linked"));
});

test("Today opens with the brief head: the windows in words, zero said in words, and what is new since this browser's last visit", async () => {
  const local = storage();
  const first = await boot({ hash: "#/today", local });
  let text = first.doc.querySelector("#view").textContent;
  assert.ok(text.includes("The brief"), text.slice(0, 300));
  assert.ok(text.includes("1 KEV addition in the last 7 days; 1 KEV entry reaches a federal due date within 14 days."), text.slice(0, 600));
  assert.ok(text.includes("1 advisory, 1 research entry and 1 press entry in the last 3 days."), text.slice(0, 600));
  assert.ok(!text.includes("Service health:") && !text.includes("Patch Tuesday:"), "a file the index does not list leaves its line out");
  assert.ok(text.includes("This browser has no record of an earlier visit."), text.slice(0, 900));
  // The brief head comes right after the intro, before the act-today strip and the KEV days.
  const view = first.doc.querySelector("#view");
  assert.equal(view.children[2].className, "panel brief-head");
  const seen = JSON.parse(local.getItem(SEEN_KEY));
  assert.equal(seen.at, CONTENT_DATE);
  assert.deepEqual([...seen.ids].sort(), ["a-kev-guidance", "a-press", "a-research", "kev:CVE-2026-1000"]);
  // The same browser again, with nothing new.
  const second = await boot({ hash: "#/today", local });
  text = second.doc.querySelector("#view").textContent;
  assert.ok(text.includes("Nothing new since you last opened Today (content date 3 Nov 2026)."), text.slice(0, 900));
  // A later run with one more entry and one more KEV addition.
  const site = files();
  const recent = JSON.parse(site.bodies["./data/v7/recent.json"]);
  recent.rows.push({ ...recent.rows[0], id: "a-fresh", title: "A fresh advisory" });
  recent.kev.push({ ...recent.kev[0], cve: "CVE-2026-1003", date_added: CONTENT_DATE });
  const third = await boot({ hash: "#/today", local, site: files({ extra: { "recent.json": recent } }) });
  text = third.doc.querySelector("#view").textContent;
  assert.ok(text.includes("1 new entry and 1 new KEV addition since you last opened Today (content date 3 Nov 2026)."), text.slice(0, 900));
  assert.ok(text.includes("2 KEV additions in the last 7 days"));
  // A re-render in the same page session keeps the baseline: still 1 new entry.
  third.app.navigate({ view: "explore", id: null, query: {} });
  await settle(40);
  third.app.navigate({ view: "today", id: null, query: {} });
  await settle(60);
  assert.ok(third.doc.querySelector("#view").textContent.includes("1 new entry and 1 new KEV addition since"));
  // Storage blocked: the line says so, and the view still renders.
  const blocked = { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); }, removeItem() {} };
  const fourth = await boot({ hash: "#/today", local: blocked });
  text = fourth.doc.querySelector("#view").textContent;
  assert.ok(text.includes("This browser keeps no record between visits, so nothing is marked new."), text.slice(0, 900));
  assert.ok(text.includes("1 KEV addition in the last 7 days"));
  // Zero rows: words, not numbers.
  const empty = await boot({ hash: "#/today", site: files({ extra: { "recent.json": { ...recent, rows: [], kev: [], cves: [] } } }) });
  text = empty.doc.querySelector("#view").textContent;
  assert.ok(text.includes("No KEV addition in the last 7 days; no KEV entry reaches a federal due date within 14 days."), text.slice(0, 900));
  assert.ok(text.includes("No advisory, service-health incident, research or press entry in the last 3 days."), text.slice(0, 900));
  assert.ok(text.includes("Nothing in these three days."));
});

test("the next Patch Tuesday is the second Tuesday on or after the day", () => {
  assert.equal(nextPatchTuesday("2026-11-01"), "2026-11-10");
  assert.equal(nextPatchTuesday("2026-11-10"), "2026-11-10");
  assert.equal(nextPatchTuesday("2026-11-11"), "2026-12-08");
  assert.equal(nextPatchTuesday("2026-12-09"), "2027-01-12");
});

test("Today shows KEV additions by calendar day and the act-today strip", async () => {
  const { doc } = await boot({ hash: "#/today" });
  const text = doc.querySelector("#view").textContent;
  assert.ok(text.includes("KEV additions by calendar day"));
  assert.ok(text.includes("1 KEV entry reaches CISA's federal due date by 17 Nov 2026."), text.slice(0, 400));
  assert.ok(text.includes("CVE-2026-1000"));
  assert.ok(!text.includes("CVE-2026-1001: due"), "an entry due outside the next 14 days is not in the strip");
  assert.ok(text.includes("Headline a-research") && text.includes("Headline a-press"));
});

test("history years load only when a year is chosen", async () => {
  const { http, doc } = await boot({ hash: "#/explore?year=2003" });
  assert.ok(http.requests.some(request => request.path === "./data/v7/history/2003.json"));
  assert.ok(doc.querySelector("#results").textContent.includes("MS03-026"));
  const fresh = await boot();
  assert.ok(!fresh.http.requests.some(request => request.path.includes("/history/")), "the default route reads no history shard");
});

test("no fetch while the tab is hidden, and a 304 is not parsed", async () => {
  const { app, http, doc } = await boot();
  const requests = http.requests.length;
  doc.hidden = true;
  assert.equal(await app.poll(), null);
  assert.equal(http.requests.length, requests, "a hidden page reads nothing");
  assert.equal(app.stats.skippedHidden, 1);
  doc.hidden = false;
  const parses = app.fetcher.stats.parses;
  const renders = app.stats.renders;
  const result = await app.poll();
  assert.equal(result.status, "unchanged");
  const last = http.requests[http.requests.length - 1];
  assert.equal(last.path, "./data/v7/index.json");
  assert.ok(last.ifNoneMatch, "the poll sends If-None-Match");
  assert.equal(app.fetcher.stats.notModified, 1);
  assert.equal(app.fetcher.stats.parses, parses, "a 304 skips the parse");
  assert.equal(app.stats.renders, renders, "a 304 does not re-render");
});

test("a changed index re-renders with only the changed shards read again", async () => {
  const { app, http, doc } = await boot();
  const next = files({ extra: { "live/2026-11.json": { schema_version: 7, kind: "articles", period: "2026-11", rows: [JSON.parse(files().bodies["./data/v7/live/2026-11.json"]).rows[0]] } } });
  http.bodies = next.bodies;
  const before = http.requests.length;
  const result = await app.poll();
  await settle(60);
  assert.equal(result.status, "loaded");
  const reads = http.requests.slice(before).map(request => request.path);
  assert.ok(reads.includes("./data/v7/live/2026-11.json"));
  assert.ok(!reads.includes("./data/v7/live/2026-10.json"), "an unchanged shard is not read again");
  assert.equal(doc.querySelectorAll("#results li").length, 3);
});

test("a successful read that fails validation reloads the page once per session", async () => {
  const session = storage();
  const bad = files({ schema: 8 });
  const first = await boot({ site: bad, session });
  assert.equal(first.location.reloads, 1);
  assert.equal(session.getItem(RELOAD_KEY), "format");
  const second = await boot({ site: bad, session });
  assert.equal(second.location.reloads, 0, "the second load shows the error instead of reloading again");
  assert.equal(second.doc.querySelector("#notice").hidden, false);
  assert.ok(second.doc.querySelector("#notice").textContent.includes("schema 7"));
  // Without session storage the page never reloads, so it cannot loop.
  const third = await boot({ site: bad, session: { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); } } });
  assert.equal(third.location.reloads, 0);
});

test("an index for a newer page layout reloads a stamped page once", async () => {
  const session = storage();
  const site = files({ layout: "1234567890abcdef" + "0".repeat(48) });
  const stale = await boot({ site, session, moduleUrl: "https://teamstarwolf.github.io/intelligence-hub/js/main.js?v=fedcba0987654321" });
  assert.equal(stale.location.reloads, 1);
  assert.equal(session.getItem(RELOAD_KEY), "layout");
  const again = await boot({ site, session, moduleUrl: "https://teamstarwolf.github.io/intelligence-hub/js/main.js?v=fedcba0987654321" });
  assert.equal(again.location.reloads, 0);
  assert.ok(again.doc.querySelectorAll("#results li").length > 0, "after the one reload the page keeps working");
  const current = await boot({ site, session: storage(), moduleUrl: "https://teamstarwolf.github.io/intelligence-hub/js/main.js?v=1234567890abcdef" });
  assert.equal(current.location.reloads, 0);
  const unstamped = await boot({ site, session: storage() });
  assert.equal(unstamped.location.reloads, 0);
});

test("the schema 6 feed is the fallback when index.json is absent", async () => {
  const legacy = { "./data/feed.json": JSON.stringify({ schema_version: 6, generated_at: "2026-10-01T00:00:00Z", window: { start: "1998-01-01", end: "2026-10-01" },
    articles: [{ id: "old-1", title: "Old advisory", url: "https://psirt.example.org/old", source_id: "vendor-psirt", source_name: "Vendor PSIRT", kind: "advisory", published_at: "2026-09-30", event_date: null, date_basis: "publication", summary: "", cves: [], tags: [], exploitation: "unknown", references: [], origin: "publisher-feed" }],
    sources: [], history_reviewed_at: null, mitigations: {}, mitigation_coverage: {}, deduplication: { url_duplicates_removed: 0 },
    refresh: { requested_minutes: 120, mode: "scheduled-check", status_url: "https://github.com/TeamStarWolf/intelligence-hub/actions", notes: [] },
    coverage: { kev_records: 0, curated_events: 0, feed_articles: 1, notes: [] },
    integrations: { xai: { status: "not_connected", message: "None." }, x: { status: "not_connected", message: "None." }, sec: { status: "not_connected", message: "None." } },
    content_revision: "a".repeat(64), layout_revision: "b".repeat(64),
    intelligence: { schema_version: 1, catalog: { version: "1", reviewed_at: null, source_sha256: "a".repeat(64), status: "unreviewed", entities: [], relationships: [], notes: [] },
      reporting: { config_sha256: "a".repeat(64), catalog_sha256: "a".repeat(64), catalog_updated_at: null, configuration: { schema_version: 1, timezone: "America/Chicago", daily_hours: [6, 14, 22], weekday_lookback_hours: 24, weekend_lookback_hours: 48, weekend_iso_days: [6, 7], periodic_hour: 6, weekly_iso_day: 1, fortnight_anchor_start: "2026-10-19", fortnight_days: 14, rolling_months: 6, cadences: ["daily", "weekly", "weekend", "fortnightly", "monthly", "quarterly", "six-month"], schedule_state: "planned", schedule_observed_at: null, notes: [] }, latest_reports: [], indexes: [], notes: [] },
      revisions: { lookback_hours: 96, priority_hours: 48, max_sources: 12, min_success_interval_hours: 8, min_failure_interval_hours: 24, state: "not_run", report_id: null, recorded_at: null, nominal_cutoff: null, records: [], notes: [] }, notes: [] } }) + "\n" };
  const { doc } = await boot({ site: { bodies: legacy } });
  assert.ok(doc.querySelector("#results").textContent.includes("Old advisory"));
  assert.ok(doc.querySelector("#results-status").textContent.includes("schema 6 feed"));
  void CONTENT_DATE;
});

test("the theme follows the system until a reader picks one, and the pick survives blocked storage", async () => {
  const { initTheme, THEME_KEY } = await import("../../site/js/theme.js");
  const { doc, win } = page();
  const button = doc.querySelector("#theme-toggle");
  const saved = storage();
  initTheme({ doc, win, storage: saved, button });
  assert.equal(doc.documentElement.getAttribute("data-theme"), null, "no pick: styles.css follows prefers-color-scheme");
  assert.equal(button.textContent, "Light");
  button.dispatchEvent({ type: "click" });
  assert.equal(doc.documentElement.getAttribute("data-theme"), "light");
  assert.equal(saved.getItem(THEME_KEY), "light");
  assert.equal(button.getAttribute("aria-label"), "Switch to the dark theme");
  const next = page();
  initTheme({ doc: next.doc, win: next.win, storage: saved, button: next.doc.querySelector("#theme-toggle") });
  assert.equal(next.doc.documentElement.getAttribute("data-theme"), "light", "the pick is restored");
  const blocked = page();
  const broken = { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); } };
  initTheme({ doc: blocked.doc, win: blocked.win, storage: broken, button: blocked.doc.querySelector("#theme-toggle") });
  blocked.doc.querySelector("#theme-toggle").dispatchEvent({ type: "click" });
  assert.equal(blocked.doc.documentElement.getAttribute("data-theme"), "light");
});

test("the sidebar stays collapsed on first load at a narrow width too", async () => {
  const shell = page();
  shell.win.matchMedia = query => ({ matches: query.includes("max-width: 1023px") });
  const http = server(files().bodies);
  const app = createApp({ doc: shell.doc, win: shell.win, location: shell.location, history: shell.history, storage: storage(), session: storage(), fetchImpl: http.fetch, subtle: webcrypto.subtle, every: () => 0, loadLabels: async () => ({ default: {} }) });
  await app.start();
  await settle(60);
  assert.equal(shell.doc.querySelector("#sidebar").hidden, true);
  assert.ok(!http.requests.some(request => request.path === "./data/v7/sources.json" || request.path === "./data/v7/reports.json"), "the panels read nothing until opened");
});

test("closing a dialog the page opened goes Back to the view underneath", async () => {
  const { doc, app, location } = await boot({ hash: "#/explore?kind=advisory" });
  app.navigate({ view: "cve", id: "CVE-2026-1001", query: {} });
  await settle(80);
  assert.equal(doc.querySelector("#cve-dialog").open, true);
  doc.querySelector("#cve-close").dispatchEvent({ type: "click" });
  await settle(80);
  assert.equal(location.hash, "#/explore?kind=advisory");
  assert.equal(doc.querySelector("#cve-dialog").open, false);
  assert.equal(doc.querySelector("#explore").hidden, false);
  app.navigate({ view: "explore", id: null, query: { kind: "advisory", open: "a-october" } });
  await settle(80);
  assert.equal(doc.querySelector("#record-dialog").open, true);
  doc.querySelector("#record-close").dispatchEvent({ type: "click" });
  await settle(80);
  assert.equal(location.hash, "#/explore?kind=advisory");
  assert.equal(doc.querySelector("#record-dialog").open, false);
});

test("Today's first load reads index.json and recent.json only", async () => {
  const { http, doc } = await boot({ hash: "#/today" });
  assert.deepEqual([...new Set(http.requests.map(request => request.path))].sort(), ["./data/v7/index.json", "./data/v7/recent.json"],
    "no live month, KEV year or CVE index is read for Today");
  const text = doc.querySelector("#view").textContent;
  assert.ok(text.includes("1 KEV entry reaches CISA's federal due date by 17 Nov 2026."), text.slice(0, 400));
  assert.ok(text.includes("Headline a-research") && text.includes("Headline a-press") && text.includes("KEV-linked"));
  assert.ok(!text.includes("October advisory"), "rows before the three days stay out");
});

test("the sidebar's Today panel reads recent.json too", async () => {
  const { doc, http } = await boot();
  doc.querySelector("#sidebar-toggle").dispatchEvent({ type: "click" });
  await settle(60);
  const paths = http.requests.map(request => request.path);
  assert.ok(paths.includes("./data/v7/recent.json"));
  assert.ok(!paths.includes("./data/v7/kev/2026.json"), "the sidebar reads no KEV year");
  assert.ok(doc.querySelector("#sidebar-body").textContent.includes("CVE-2026-1000"));
});

test("without a usable recent.json Today falls back to the live months and the KEV ledger", async () => {
  const recent = JSON.parse(files().bodies["./data/v7/recent.json"]);
  for (const site of [files({ omit: ["recent.json"] }), files({ extra: { "recent.json": { ...recent, content_date: "2026-11-02" } } })]) {
    const { http, doc } = await boot({ hash: "#/today", site });
    const paths = http.requests.map(request => request.path);
    assert.ok(paths.includes("./data/v7/live/2026-11.json") && paths.includes("./data/v7/kev/2026.json") && paths.includes("./data/v7/cve-index.json"), paths.join(" "));
    const text = doc.querySelector("#view").textContent;
    assert.ok(text.includes("1 KEV entry reaches CISA's federal due date by 17 Nov 2026."), text.slice(0, 400));
    assert.ok(text.includes("Headline a-research"));
  }
});

test("a briefs file from another run is refused, nothing from it is shown, and the index is read again", async () => {
  const site = files();
  const briefs = JSON.parse(site.bodies["./data/briefs.json"]);
  briefs.content_revision = "0".repeat(64);
  site.bodies["./data/briefs.json"] = JSON.stringify(briefs) + "\n";
  const { doc, http, app, location } = await boot({ hash: "#/cve/CVE-2026-1000", site });
  await settle(60);
  const text = doc.querySelector("#cve-body").textContent;
  assert.ok(text.includes("different snapshot"), text);
  assert.ok(text.includes("No external lookup was made."));
  assert.ok(!text.includes("CNA title for CVE-2026-1000"), "nothing from the refused file is rendered");
  assert.equal(app.stats.polls, 1, "the refusal asks for the index again");
  assert.equal(http.requests.filter(request => request.path === "./data/v7/index.json").length, 2);
  assert.ok(http.requests[http.requests.length - 1].ifNoneMatch, "the re-read is the conditional index poll");
  assert.equal(location.reloads, 0, "a refused brief file does not reload the page");
});

test("a missing briefs file shows an error and makes no external lookup", async () => {
  const site = files();
  delete site.bodies["./data/briefs.json"];
  const { doc, http } = await boot({ hash: "#/cve/CVE-2026-1000", site });
  await settle(60);
  assert.equal(doc.querySelector("#cve-dialog").open, true);
  const text = doc.querySelector("#cve-body").textContent;
  assert.ok(text.includes("HTTP 404") && text.includes("No external lookup was made."), text);
  assert.ok(http.requests.some(request => request.path === "./data/briefs.json"));
  assert.ok(http.requests.every(request => request.url.startsWith("./data/")), http.requests.map(request => request.url).join(" "));
});

test("the sidebar and the Sources tab state the observed gap between runs with the cron", async () => {
  const { cadenceText } = await import("../../site/js/views/panels.js");
  const statement = "Observed gap between published runs: median 4.3 h, longest 10.2 h over the last 10 runs";
  const { doc, app } = await boot();
  doc.querySelector("#sidebar-toggle").dispatchEvent({ type: "click" });
  await settle(60);
  const side = doc.querySelector("#sidebar-body").textContent;
  for (const phrase of [statement, "cron 7 */2 * * *", "Content date 3 Nov 2026", "Last published run "]) assert.ok(side.includes(phrase), phrase);
  app.navigate({ view: "sources", id: null, query: {} });
  await settle(60);
  assert.ok(doc.querySelector("#view").textContent.includes(statement));
  assert.ok(cadenceText(null).includes("could not be read"));
  assert.ok(!cadenceText(null).includes("median"), "no observed schedule is claimed without the run record");
});

test("the notice is a toast fixed above the results, after them in the DOM, and dismissable", async () => {
  const css = readFileSync(ROOT + "site/styles.css", "utf8");
  const rule = css.match(/\n\.toast \{([^}]*)\}/);
  assert.ok(rule, "styles.css has a .toast rule");
  assert.match(rule[1], /position:\s*(fixed|sticky)/);
  const sidebar = css.match(/\n\.sidebar \{[^}]*z-index:\s*(\d+)/);
  assert.ok(Number(rule[1].match(/z-index:\s*(\d+)/)[1]) > Number(sidebar[1]), "the toast sits above the sidebar drawer");
  assert.match(css, /\.toast\[hidden\] \{ display: none; \}/);
  const session = storage();
  const site = files({ layout: "1234567890abcdef" + "0".repeat(48) });
  await boot({ site, session, moduleUrl: "https://teamstarwolf.github.io/intelligence-hub/js/main.js?v=fedcba0987654321" });
  const { doc } = await boot({ site, session, moduleUrl: "https://teamstarwolf.github.io/intelligence-hub/js/main.js?v=fedcba0987654321" });
  const notice = doc.querySelector("#notice");
  assert.ok(notice.classList.contains("toast"));
  assert.equal(notice.hidden, false);
  assert.ok(notice.textContent.includes("A newer version of this page is published"));
  const all = inOrder(doc);
  assert.ok(all.indexOf(notice) > all.indexOf(doc.querySelector("#results li")), "the notice stays after the results in DOM order");
  doc.querySelector("#notice-close").dispatchEvent({ type: "click" });
  assert.equal(notice.hidden, true);
});

test("the theme button follows a system scheme change until a reader picks a theme", async () => {
  const { initTheme } = await import("../../site/js/theme.js");
  const { doc, win } = page();
  const listeners = [];
  const query = { matches: false, addEventListener: (type, handler) => { if (type === "change") listeners.push(handler); } };
  win.matchMedia = () => query;
  const button = doc.querySelector("#theme-toggle");
  initTheme({ doc, win, storage: storage(), button });
  assert.equal(button.textContent, "Light", "a dark system scheme offers the light theme");
  query.matches = true;
  listeners.forEach(handler => handler({ matches: true }));
  assert.equal(button.textContent, "Dark", "after the system turns light the button offers dark");
  assert.equal(button.getAttribute("aria-label"), "Switch to the dark theme");
  button.dispatchEvent({ type: "click" });
  assert.equal(doc.documentElement.getAttribute("data-theme"), "dark");
  query.matches = false;
  listeners.forEach(handler => handler({ matches: false }));
  assert.equal(button.textContent, "Light", "a reader's pick is not relabelled by the system scheme");
  const blocked = page();
  blocked.win.matchMedia = () => { throw new Error("blocked"); };
  initTheme({ doc: blocked.doc, win: blocked.win, storage: storage(), button: blocked.doc.querySelector("#theme-toggle") });
  assert.equal(blocked.doc.querySelector("#theme-toggle").textContent, "Light");
});
