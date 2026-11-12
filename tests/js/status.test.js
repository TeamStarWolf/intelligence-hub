// The Service health view (site/js/views/status.js) on site/index.html with a synthetic schema 7
// site: the tab is last and the Explorer stays first, the live board reads only the CORS-open
// Statuspage hosts that status/current.json lists, a failed read falls back to the snapshot,
// pausing, leaving the view and a hidden tab stop the reads, the deep link filters one source,
// an incident row sits in the Explorer timeline tagged outage with its vendor, and the validators
// refuse anything outside their rules.
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { inOrder } from "./dom.js";
import { ROOT, files, page, row, server, settle, storage } from "./fixtures.js";
import { createApp } from "../../site/js/main.js";
import { parseRoute, formatRoute } from "../../site/js/router.js";
import { liveStatusUrl, normalizeIncident, normalizeStatusCurrent, normalizeLiveStatus } from "../../site/js/validate.js";
import { LIVE_INTERVAL, createLiveBoard } from "../../site/js/views/status.js";
import { PRIVACY_SENTENCE } from "../../site/js/views/method.js";

const GITHUB = "https://www.githubstatus.com/api/v2/status.json";
const TENABLE = "https://status.tenable.com/api/v2/status.json";

function incident(source, id, fields = {}) {
  return { source, vendor: null, id, name: "Incident " + id, status: "resolved", status_raw: "resolved", impact: "minor", impact_raw: "minor", components: ["API"],
    started: "2026-11-02T10:00:00+00:00", updated: "2026-11-02T11:00:00+00:00", resolved: "2026-11-02T11:00:00+00:00", url: "https://www.githubstatus.com/incidents/" + id, summary: "Resolved.", ...fields };
}

function source(id, fields = {}) {
  return { id, name: id.toUpperCase(), vendor: null, group: "developer-services", class: "statuspage", format: "statuspage", home: "https://" + id + ".example.org/", library: null,
    cors: true, live: null, status: "ok", fetched_at: "2026-11-03T12:00:00+00:00", last_success: "2026-11-03T12:00:00+00:00", error: null, indicator: "none",
    description: "All Systems Operational", open: [], ...fields };
}

function statusSite(adjust = outages => outages) {
  const open = incident("tenable", "abcd1234", { status: "investigating", status_raw: "investigating", impact: "major", impact_raw: "major", resolved: null, url: "https://status.tenable.com/incidents/abcd1234", vendor: "vendor:tenable" });
  const current = { schema_version: 7, kind: "status-current", generated_at: "2026-11-03T12:00:00+00:00",
    groups: [{ id: "security-platforms", label: "Security platforms" }, { id: "cloud-and-saas", label: "Cloud and SaaS" }, { id: "developer-services", label: "Developer services" }, { id: "internet", label: "Internet outage signals" }],
    sources: [
      source("tenable", { name: "Tenable", group: "security-platforms", vendor: "vendor:tenable", library: "vendor:tenable", home: "https://status.tenable.com/", live: TENABLE, indicator: "major", description: "Partial System Outage", open: [open] }),
      source("aws", { name: "Amazon Web Services", group: "cloud-and-saas", class: "json", format: "aws", vendor: "vendor:aws", home: "https://health.aws.amazon.com/health/status", cors: false, live: null, description: null }),
      source("github", { name: "GitHub", home: "https://www.githubstatus.com/", live: GITHUB })
    ],
    page_only: [{ id: "okta", name: "Okta", vendor: "vendor:okta", home: "https://status.okta.com/", reason: "HTML page only." }], notes: ["A note."] };
  const month = { schema_version: 7, kind: "status-month", period: "2026-11", rows: [incident("github", "zzzz0001"), open] };
  const outages = { schema_version: 7, kind: "status-outages", generated_at: "2026-11-03T12:00:00+00:00", window_hours: 24,
    ioda: { id: "ioda", name: "IODA (Georgia Tech)", home: "https://ioda.inetintel.cc.gatech.edu/", status: "ok", fetched_at: "2026-11-03T12:00:00+00:00", last_success: "2026-11-03T12:00:00+00:00", error: null,
      copyright: "This data is Copyright (c) 2021-2025 Georgia Tech Research Corporation. All Rights Reserved.",
      rows: [{ source: "ioda", id: "country/TL@1", entity_type: "country", entity_code: "TL", entity_name: "Timor-Leste", datasource: "gtr", start: "2026-11-03T00:00:00+00:00", end: null, duration_seconds: 22858, score: 8570, url: "https://ioda.inetintel.cc.gatech.edu/country/TL" }] },
    radar: { id: "cloudflare-radar", name: "Cloudflare Radar outage annotations", home: "https://radar.cloudflare.com/", status: "not_configured", fetched_at: null, last_success: null, error: null, copyright: null, rows: [],
      note: "Cloudflare Radar needs an API token." } };
  adjust(outages);
  const index = { schema_version: 7, kind: "status-index", generated_at: "2026-11-03T12:00:00+00:00", months_kept: 13, months: [{ period: "2026-11", path: "status/2026-11.json", rows: 2 }],
    coverage: [{ source: "github", first_incident: "2026-11-02", incidents: 1 }], sources: 3, page_only: 1, truncated_rows: 0, board_sha256: "a".repeat(64), notes: ["A note."] };
  const outage = row("status-github-zzzz0001", { title: "GitHub: Incident zzzz0001", url: "https://www.githubstatus.com/incidents/zzzz0001", source_id: "status-github", source_name: "GitHub status page",
    kind: "incident", origin: "service-status", published_at: "2026-11-02T10:00:00+00:00", date_basis: "status page incident start", summary: "Impact minor. Status resolved.",
    tagging: { source_class: "vendor-primary", event_type: [["outage", "status-incident", "high"]], exploitation: ["unknown", "none", "high"], vendor: [["vendor:cloudflare", "source-identity", "high"]] } });
  const base = files().bodies["./data/v7/live/2026-11.json"];
  const live = JSON.parse(base);
  live.rows.push(outage);
  return files({ extra: { "status/current.json": current, "status/2026-11.json": month, "status/outages.json": outages, "status/index.json": index, "live/2026-11.json": live } });
}

// The site's own files, plus the vendor status hosts: answers maps a URL to a status body or an HTTP code.
function network(site, answers) {
  const http = server(site.bodies);
  const vendor = [];
  const fetchImpl = async (url, options = {}) => {
    if (!url.startsWith("https://")) return http.fetch(url, options);
    vendor.push({ url, options });
    const answer = answers[url];
    if (typeof answer === "number" || answer === undefined) return { ok: false, status: answer || 404, headers: { get: () => null }, body: null, arrayBuffer: async () => new ArrayBuffer(0) };
    const bytes = new TextEncoder().encode(JSON.stringify(answer));
    return { ok: true, status: 200, headers: { get: key => key.toLowerCase() === "content-length" ? String(bytes.byteLength) : null }, body: null, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
  };
  return { http, vendor, fetchImpl };
}

async function boot({ hash = "", answers = { [GITHUB]: { page: {}, status: { indicator: "minor", description: "Minor Service Outage" } }, [TENABLE]: 503 }, hidden = false, site = statusSite() } = {}) {
  const shell = page(hash, "");
  shell.doc.hidden = hidden;
  const net = network(site, answers);
  const timers = [];
  const app = createApp({ doc: shell.doc, win: shell.win, location: shell.location, history: shell.history, storage: storage(), session: storage(), fetchImpl: net.fetchImpl,
    subtle: webcrypto.subtle, every: (fn, ms) => { timers.push({ fn, ms, cleared: false }); return timers.length; }, clear: id => { if (timers[id - 1]) timers[id - 1].cleared = true; },
    loadLabels: async () => ({ default: { "vendor:cloudflare": "Cloudflare" } }) });
  await app.start();
  await settle(120);
  return { ...shell, app, net, timers };
}

async function go(shell, hash) { shell.app.navigate(parseRoute(hash, "")); await settle(120); return shell.doc.querySelector("#view"); }
const cards = doc => Object.fromEntries([...doc.querySelectorAll(".status-card")].map(item => [item.getAttribute("data-source"), item]));
const liveTimer = timers => timers.find(timer => timer.ms === LIVE_INTERVAL);

test("Today's brief head reads the service-health board when the index lists it, sums its open incidents and names retained and unread sources", async () => {
  const shell = await boot({ hash: "#/today" });
  const text = shell.doc.querySelector("#view").textContent;
  assert.ok(text.includes("Service health: 1 open incident and 1 status page reporting a problem across 3 sources, from the collector's read at 3 Nov 2026, 12:00 UTC."), text.slice(0, 900));
  assert.ok(!text.includes("earlier reading") && !text.includes("not read yet"), "every source on this board was read");
  const link = [...shell.doc.querySelectorAll("#view .brief-list a")].find(anchor => anchor.textContent === "Open the board");
  assert.equal(link.getAttribute("href"), "#/status");
  assert.ok(shell.net.http.requests.some(request => request.path === "./data/v7/status/current.json"));
  assert.ok(!shell.net.http.requests.some(request => request.path.includes("status/2026-11.json")), "no month file is read for the brief head");
  // A source whose latest read failed keeps its earlier reading and its open incident; one never
  // read has nothing. Both count in the totals and both are named, so the board clock dates only
  // the sources it read (the retrieval dates stay apart).
  const base = statusSite();
  const current = JSON.parse(base.bodies["./data/v7/status/current.json"]);
  const retained = incident("zscaler", "32496", { status: "investigating", status_raw: "investigating", impact: "major", impact_raw: "major", resolved: null, url: "https://trust.zscaler.com/incidents/32496", vendor: "vendor:zscaler" });
  current.sources.push(source("zscaler", { name: "Zscaler", group: "security-platforms", vendor: "vendor:zscaler", home: "https://trust.zscaler.com/", status: "failed", fetched_at: "2026-11-03T12:00:00+00:00",
    last_success: "2026-11-01T12:00:00+00:00", error: "HTTP 503", indicator: "major", description: "Partial outage", open: [retained] }));
  current.sources.push(source("newone", { name: "New One", status: "not_fetched", fetched_at: null, last_success: null, indicator: "unknown", description: null, open: [] }));
  const extra = Object.fromEntries(["status/2026-11.json", "status/outages.json", "status/index.json", "live/2026-11.json"].map(path => [path, JSON.parse(base.bodies["./data/v7/" + path])]));
  const mixed = await boot({ hash: "#/today", site: files({ extra: { ...extra, "status/current.json": current } }) });
  const line = mixed.doc.querySelector("#view").textContent;
  assert.ok(line.includes("Service health: 2 open incidents and 2 status pages reporting a problem across 5 sources, from the collector's read at 3 Nov 2026, 12:00 UTC; " +
    "1 source shows an earlier reading because the latest read failed; 1 source not read yet."), line.slice(0, 1200));
});

test("the Service health tab is the infrastructure desk's view, the Explorer stays first, and the default route reads no status file and no vendor host", async () => {
  const shell = await boot();
  const tabs = [...shell.doc.querySelectorAll(".tabs .views a")].map(tab => tab.getAttribute("data-view"));
  assert.equal(tabs[0], "explore");
  assert.ok(tabs.includes("status"));
  assert.equal(shell.doc.querySelector(".tabs .views a[data-view=status]").getAttribute("data-desk"), "infrastructure");
  assert.equal(shell.doc.querySelector("#view").hidden, true);
  assert.equal(shell.app.route().view, "explore");
  assert.ok(!shell.net.http.requests.some(request => request.path.includes("/status/")), "no status file on the default route");
  assert.equal(shell.net.vendor.length, 0, "no vendor host on the default route");
  const target = await go(shell, "#/status");
  assert.equal(target.querySelector("h1").textContent, "Service health");
  const all = inOrder(shell.doc);
  assert.ok(all.indexOf(target) > all.indexOf(shell.doc.querySelector("#results")), "the view sits after the Explorer in the DOM");
  assert.equal(shell.doc.querySelector(".tabs a[aria-current=page]").getAttribute("data-view"), "status");
  assert.equal(formatRoute(parseRoute("#/status?source=github&q=x", "")), "#/status?source=github");
});

test("the live board reads only the listed CORS-open status hosts and labels each card live or snapshot", async () => {
  const shell = await boot({ hash: "#/status" });
  assert.deepEqual(shell.net.vendor.map(request => request.url).sort(), [TENABLE, GITHUB].sort());
  for (const request of shell.net.vendor) {
    assert.equal(request.options.credentials, "omit");
    assert.equal(request.options.cache, "no-store");
    assert.equal(request.options.redirect, "error");
  }
  const found = cards(shell.doc);
  assert.match(found.github.querySelector(".status-basis").textContent, /^Live: read from www\.githubstatus\.com by this browser at \d{2}:\d{2} UTC\.$/);
  assert.equal(found.github.querySelector(".status-badge").textContent, "Minor incident");
  assert.equal(found.github.querySelector(".status-words").textContent, "Minor Service Outage");
  assert.match(found.aws.querySelector(".status-basis").textContent, /^Snapshot from the collector's read at /);
  assert.ok(found.tenable.querySelector("a.library-link").getAttribute("href").startsWith("https://teamstarwolf.github.io/TeamStarWolf/#/platforms/tenable"));
});

test("a failed live read falls back to the snapshot and never blanks the card", async () => {
  const shell = await boot({ hash: "#/status" });
  const tenable = cards(shell.doc).tenable;
  assert.equal(tenable.querySelector(".status-badge").textContent, "Major incident");
  assert.equal(tenable.querySelector(".status-words").textContent, "Partial System Outage");
  assert.match(tenable.querySelector(".status-basis").textContent, /^Live read failed at \d{2}:\d{2} UTC \(The status page could not be read \(HTTP 503\)\.\)\. Snapshot from the collector's read/);
});

test("pausing stops the reads, resuming reads again, a hidden tab reads nothing and leaving the view stops the timer", async () => {
  const shell = await boot({ hash: "#/status" });
  const timer = liveTimer(shell.timers);
  assert.ok(timer && !timer.cleared);
  const before = shell.net.vendor.length;
  const toggle = shell.doc.querySelector(".status-controls button");
  toggle.dispatchEvent({ type: "click" });
  assert.equal(toggle.textContent, "Resume live updates");
  assert.equal(toggle.getAttribute("aria-pressed"), "true");
  await timer.fn(); await settle(40);
  assert.equal(shell.net.vendor.length, before, "no read while paused");
  toggle.dispatchEvent({ type: "click" }); await settle(60);
  assert.equal(shell.net.vendor.length, before + 2, "resuming reads at once");
  shell.doc.hidden = true;
  await timer.fn(); await settle(40);
  assert.equal(shell.net.vendor.length, before + 2, "a hidden tab reads nothing");
  shell.doc.hidden = false;
  await timer.fn(); await settle(60);
  assert.equal(shell.net.vendor.length, before + 4, "a visible tab reads every five minutes");
  await go(shell, "#/explore");
  assert.equal(timer.cleared, true, "leaving the view stops the timer");
  const after = shell.net.vendor.length;
  await timer.fn(); await settle(40);
  assert.equal(shell.net.vendor.length, after, "a stopped board reads nothing");
});

test("a refresh that fails after a live read puts the snapshot's indicator and words back on the card", async () => {
  const answers = { [GITHUB]: { page: {}, status: { indicator: "minor", description: "Minor Service Outage" } }, [TENABLE]: 503 };
  const shell = await boot({ hash: "#/status", answers });
  const github = () => cards(shell.doc).github;
  assert.equal(github().querySelector(".status-badge").textContent, "Minor incident");
  assert.ok(github().classList.contains("status-live"));
  answers[GITHUB] = 503;
  await liveTimer(shell.timers).fn(); await settle(60);
  assert.equal(github().querySelector(".status-badge").textContent, "Operational", "the snapshot's indicator, not the earlier live one");
  assert.equal(github().querySelector(".status-words").textContent, "All Systems Operational");
  assert.equal(github().querySelectorAll(".status-badge").length, 1);
  assert.match(github().querySelector(".status-basis").textContent, /^Live read failed at \d{2}:\d{2} UTC \(The status page could not be read \(HTTP 503\)\.\)\. Snapshot from the collector's read/);
  assert.ok(!github().classList.contains("status-live"));
});

test("pausing or hiding the tab during the first batch starts no further batch", async () => {
  const urls = Array.from({ length: 12 }, (_, position) => "https://status" + position + ".example.org/api/v2/status.json");
  const body = new TextEncoder().encode(JSON.stringify({ status: { indicator: "none", description: "All Systems Operational" } }));
  for (const how of ["pause", "hide"]) {
    const doc = { hidden: false };
    const requested = [];
    const release = [];
    let held = true;
    const reply = () => ({ ok: true, status: 200, headers: { get: () => null }, body: null, arrayBuffer: async () => body.buffer.slice(0) });
    // The first batch is held until the test pauses or hides; any later read would answer at once.
    const fetchImpl = url => { requested.push(url); return held ? new Promise(resolve => release.push(() => resolve(reply()))) : Promise.resolve(reply()); };
    const board = createLiveBoard({ fetchImpl, every: () => 1, clear: () => {}, now: () => Date.UTC(2026, 10, 3, 12, 0), doc });
    const round = board.start(urls, () => {});
    await settle(20);
    assert.equal(requested.length, 6, how + ": the first batch is six reads");
    if (how === "pause") board.setPaused(true); else doc.hidden = true;
    held = false;
    for (const done of release.splice(0)) done();
    await round; await settle(20);
    assert.equal(requested.length, 6, how + ": no second batch starts");
    assert.equal(board.stats.requests, 6);
    board.stop();
  }
});

test("switching to one source during a live batch reads the chosen source at once", async () => {
  const urls = Array.from({ length: 12 }, (_, position) => "https://status" + position + ".example.org/api/v2/status.json");
  const chosen = "https://chosen.example.org/api/v2/status.json";
  const body = new TextEncoder().encode(JSON.stringify({ status: { indicator: "minor", description: "Partial outage" } }));
  const requested = [];
  const release = [];
  const heard = [];
  let held = true;
  const reply = () => ({ ok: true, status: 200, headers: { get: () => null }, body: null, arrayBuffer: async () => body.buffer.slice(0) });
  const fetchImpl = url => { requested.push(url); return held ? new Promise(resolve => release.push(() => resolve(reply()))) : Promise.resolve(reply()); };
  const board = createLiveBoard({ fetchImpl, every: () => 1, clear: () => {}, now: () => Date.UTC(2026, 10, 3, 12, 0) });
  const first = board.start(urls, () => {});
  await settle(20);
  assert.equal(requested.length, 6, "the first batch is six reads");
  // The source changes while the first batch is still in flight.
  held = false;
  const second = board.start([chosen], url => heard.push(url));
  for (const done of release.splice(0)) done();
  await Promise.all([first, second]); await settle(20);
  assert.ok(requested.includes(chosen), "the chosen source is read in this round, not five minutes later");
  assert.equal(board.result(chosen).indicator, "minor");
  assert.deepEqual(heard, [chosen], "the old round's reads never reach the new listener");
  assert.equal(requested.length, 7, "the old round starts no second batch over the new list");
  board.stop();
});

test("the deep link shows one source, its open incidents and its recent incidents", async () => {
  const shell = await boot({ hash: "#/status?source=tenable" });
  const found = cards(shell.doc);
  assert.deepEqual(Object.keys(found), ["tenable"]);
  assert.deepEqual(shell.net.vendor.map(request => request.url), [TENABLE]);
  const tables = [...shell.doc.querySelectorAll("#view table")];
  assert.ok(tables[0].textContent.includes("Incident abcd1234"));
  assert.ok(tables[0].textContent.includes("Investigating"));
  assert.ok(!shell.doc.querySelector("#view").textContent.includes("Internet outage signals"));
  assert.ok([...shell.doc.querySelectorAll("#view a")].some(anchor => anchor.getAttribute("href") === "#/status"));
});

test("the whole view shows open incidents, internet outage signals with IODA's notice, page-only vendors and month links", async () => {
  const shell = await boot({ hash: "#/status" });
  const view = shell.doc.querySelector("#view");
  const text = view.textContent;
  assert.ok(text.includes("Internet outage signals"));
  assert.ok(text.includes("Timor-Leste"));
  assert.ok(text.includes("IODA data: This data is Copyright"));
  assert.ok(text.includes("Cloudflare Radar needs an API token."));
  assert.ok(text.includes("Okta"));
  assert.ok([...view.querySelectorAll("a")].some(anchor => anchor.getAttribute("href") === "./data/v7/status/2026-11.json"));
  assert.ok([...view.querySelectorAll("a")].some(anchor => anchor.getAttribute("href") === "#/explore?kind=incident&event=outage"));
  assert.ok(text.includes("Incident zzzz0001"), "the last 30 days lists the month file's incidents");
});

test("after a failed outage read the kept IODA and Radar rows are dated by the last good read, not the failed one", async () => {
  const good = "2026-11-04T07:20:23+00:00";
  const failed = "2026-11-10T12:00:00+00:00";
  const site = statusSite(outages => {
    outages.generated_at = failed;
    Object.assign(outages.ioda, { status: "failed", fetched_at: failed, last_success: good, error: "IODA answered HTTP 503." });
    Object.assign(outages.radar, { status: "failed", fetched_at: failed, last_success: good, error: "Radar answered HTTP 503.", note: null,
      rows: [{ id: "radar-1", locations: ["Timor-Leste"], asns: [], cause: "POWER_OUTAGE", type: "NATIONWIDE", scope: null, description: null, start: "2026-11-04T01:00:00+00:00", end: null, url: "https://radar.cloudflare.com/outage-center" }] });
  });
  const shell = await boot({ hash: "#/status", site });
  const view = shell.doc.querySelector("#view");
  const caption = [...view.querySelectorAll("caption")].find(item => item.textContent.startsWith("IODA outage events"));
  assert.ok(caption, "the IODA table is still shown");
  const goodLabel = "4 Nov 2026, 07:20 UTC";
  const failedLabel = "10 Nov 2026, 12:00 UTC";
  assert.equal(caption.textContent, "IODA outage events for countries in the 24 hours before the collector's last good read at " + goodLabel + "; the read at " + failedLabel + " failed. Score is IODA's own severity score.");
  assert.ok(!caption.textContent.includes("hours before the collector's read at " + failedLabel), "the caption does not date the kept rows by the failed read");
  const ioda = [...caption.closest("table").querySelectorAll("tbody tr")];
  assert.equal(ioda.length, 1);
  assert.ok(ioda[0].textContent.includes("Ongoing at that read"));
  assert.ok(view.textContent.includes("The collector's last IODA read failed (IODA answered HTTP 503.)."));
  assert.ok(view.textContent.includes("The collector's last Radar read failed (Radar answered HTTP 503.)."));
  assert.ok(view.textContent.includes("These Radar rows are from the collector's last good read at " + goodLabel + "."));
  assert.ok(view.textContent.includes(", ongoing at that read"));
  assert.ok(!view.textContent.includes("last good read at " + failedLabel));
});

test("an incident row sits in the Explorer timeline tagged outage with its vendor", async () => {
  const shell = await boot({ hash: "#/explore?event=outage" });
  const results = [...shell.doc.querySelectorAll("#results li")];
  const card = results.find(item => item.getAttribute("data-id") === "status-github-zzzz0001");
  assert.ok(card, "the outage row is listed");
  assert.ok(card.textContent.includes("Incident start"));
  assert.ok(card.textContent.includes("Cloudflare"));
  assert.equal(shell.net.vendor.length, 0, "the Explorer reads no vendor host");
});

test("the Method view carries the privacy sentence", async () => {
  const shell = await boot({ hash: "#/method" });
  assert.ok(shell.doc.querySelector("#view").textContent.includes(PRIVACY_SENTENCE));
  assert.match(PRIVACY_SENTENCE, /requests from your browser to the listed vendor status hosts/);
});

test("the validators refuse links and live URLs outside their rules", () => {
  assert.equal(liveStatusUrl(GITHUB), GITHUB);
  for (const bad of ["http://www.githubstatus.com/api/v2/status.json", "https://www.githubstatus.com/api/v2/summary.json", "https://www.githubstatus.com/api/v2/status.json?x=1", "javascript:alert(1)"]) {
    assert.throws(() => liveStatusUrl(bad));
  }
  assert.throws(() => normalizeIncident(incident("github", "x", { url: "javascript:alert(1)" })));
  assert.throws(() => normalizeIncident(incident("github", "x", { impact: "huge" })));
  assert.throws(() => normalizeLiveStatus({ status: { indicator: "<b>" } }));
  assert.deepEqual(normalizeLiveStatus({ status: { indicator: "none", description: "  All   good " } }), { indicator: "none", description: "All good" });
  const current = JSON.parse(statusSite().bodies["./data/v7/status/current.json"]);
  current.sources[0].live = "https://evil.example.net/api/v2/status.json?steal=1";
  assert.throws(() => normalizeStatusCurrent(current));
});

test("the live reader bounds its reads and never throws", async () => {
  const big = new TextEncoder().encode(JSON.stringify({ status: { indicator: "none", description: "x".repeat(70000) } }));
  const results = [];
  const board = createLiveBoard({ fetchImpl: async () => ({ ok: true, status: 200, headers: { get: key => key === "content-length" ? String(big.byteLength) : null }, body: null, arrayBuffer: async () => big.buffer }),
    every: () => 1, clear: () => {}, now: () => Date.UTC(2026, 10, 3, 12, 0) });
  await board.start([GITHUB], (url, result) => results.push(result));
  assert.equal(results.length, 1);
  assert.equal(results[0].ok, false);
  assert.match(results[0].error, /exceeds the supported/);
});

test("an oversized live response names the 64 KiB bound, with or without a content-length", async () => {
  const big = new TextEncoder().encode(JSON.stringify({ status: { indicator: "none", description: "x".repeat(70000) } }));
  const stream = () => {
    let sent = false;
    return { getReader: () => ({ read: async () => { if (sent) return { done: true }; sent = true; return { done: false, value: big }; }, cancel: async () => {} }) };
  };
  const replies = [
    { ok: true, status: 200, headers: { get: key => key === "content-length" ? String(big.byteLength) : null }, body: null, arrayBuffer: async () => big.buffer },
    { ok: true, status: 200, headers: { get: () => null }, body: stream(), arrayBuffer: async () => big.buffer },
    { ok: true, status: 200, headers: { get: () => null }, body: null, arrayBuffer: async () => big.buffer },
  ];
  for (const reply of replies) {
    const results = [];
    const board = createLiveBoard({ fetchImpl: async () => reply, every: () => 1, clear: () => {}, now: () => Date.UTC(2026, 10, 3, 12, 0) });
    await board.start([GITHUB], (url, result) => results.push(result));
    board.stop();
    assert.equal(results.length, 1);
    assert.equal(results[0].ok, false);
    assert.equal(results[0].error, "The status page exceeds the supported 64 KiB download size.");
    assert.doesNotMatch(results[0].error, / 0 MiB/);
  }
});

test("site/files.json lists the view and index.html names it in no other way", () => {
  const listed = JSON.parse(readFileSync(ROOT + "site/files.json", "utf8")).files;
  assert.ok(listed.includes("js/views/status.js"));
  const html = readFileSync(ROOT + "site/index.html", "utf8");
  assert.ok(!html.includes("views/status.js"), "the view loads through main.js, so the deploy-skew stamp covers it");
});
