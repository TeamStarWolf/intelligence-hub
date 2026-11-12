// The route contract (docs/URLS.md): every view and filter round-trips through the hash, the
// A4 link keys are rewritten, and hostile or unknown parameters never survive.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DESKS, ID_VIEWS, VIEWS, VIEW_DESK, formatRoute, parseRoute, withQuery } from "../../site/js/router.js";

const roundTrip = hash => formatRoute(parseRoute(hash, ""));

test("every view round-trips", () => {
  for (const view of VIEWS.filter(name => !(Object.hasOwn(ID_VIEWS, name) && ID_VIEWS[name].fallback))) assert.equal(roundTrip("#/" + view), "#/" + view);
  assert.equal(roundTrip("#/cve/CVE-2026-118527"), "#/cve/CVE-2026-118527");
  assert.deepEqual(parseRoute("#/cve/CVE-2026-118527", ""), { view: "cve", id: "CVE-2026-118527", query: {}, rewrite: false });
  for (const hash of ["#/history/1998", "#/history/2026", "#/vendor/palo-alto-networks", "#/actor/G0016", "#/actor/storm-0940", "#/malware/S0154"]) assert.equal(roundTrip(hash), hash);
  assert.deepEqual(parseRoute("#/history/2003", ""), { view: "history", id: "2003", query: {}, rewrite: false });
});

test("a view that needs an id falls back to its index, and a bad id is never reflected", () => {
  assert.equal(roundTrip("#/vendor"), "#/vendors");
  assert.equal(roundTrip("#/actor"), "#/actors");
  assert.equal(roundTrip("#/malware/"), "#/actors");
  assert.equal(roundTrip("#/vendor/%3Cscript%3E"), "#/vendors");
  assert.equal(roundTrip("#/vendor/Fortinet"), "#/vendors", "vendor ids are lowercase slugs");
  assert.equal(roundTrip("#/actor/G0016%22onload"), "#/actors");
  assert.equal(roundTrip("#/history/1997"), "#/history");
  assert.equal(roundTrip("#/history/2003/extra"), "#/history");
  assert.equal(parseRoute("#/vendor", "").rewrite, true);
});

test("a Patch Tuesday month round-trips, and a bad month opens the latest brief without reflecting it", () => {
  for (const hash of ["#/patch-tuesday", "#/patch-tuesday/2016-01", "#/patch-tuesday/2026-10"]) assert.equal(roundTrip(hash), hash);
  assert.deepEqual(parseRoute("#/patch-tuesday/2026-10", ""), { view: "patch-tuesday", id: "2026-10", query: {}, rewrite: false });
  for (const hash of ["#/patch-tuesday/2026-00", "#/patch-tuesday/2026-1", "#/patch-tuesday/1997-12", "#/patch-tuesday/%3Cscript%3E"]) {
    assert.equal(roundTrip(hash), "#/patch-tuesday", hash);
    assert.equal(parseRoute(hash, "").rewrite, true, hash);
  }
  // The view reads no query key, so one is dropped and the month stays.
  assert.equal(roundTrip("#/patch-tuesday/2026-10?page=2"), "#/patch-tuesday/2026-10");
  assert.equal(parseRoute("#/patch-tuesday/2026-10?page=2", "").rewrite, true);
});

test("Service health round-trips, keeps its source and drops every other key and a bad source", () => {
  assert.equal(roundTrip("#/status"), "#/status");
  assert.deepEqual(parseRoute("#/status", ""), { view: "status", id: null, query: {}, rewrite: false });
  assert.equal(roundTrip("#/status?source=github"), "#/status?source=github");
  assert.deepEqual(parseRoute("#/status?source=github", ""), { view: "status", id: null, query: { source: "github" }, rewrite: false });
  assert.equal(formatRoute({ view: "status", id: null, query: { source: "github" } }), "#/status?source=github");
  // Unknown keys and keys other views read are dropped; the source stays.
  for (const hash of ["#/status?source=github&q=x", "#/status?kind=incident&source=github&utm_source=z", "#/status?source=github&page=2&event=outage"]) {
    assert.equal(roundTrip(hash), "#/status?source=github", hash);
    assert.equal(parseRoute(hash, "").rewrite, true, hash);
  }
  // A source that is not a lowercase slug is never reflected.
  for (const hash of ["#/status?source=GitHub", "#/status?source=%3Cscript%3E", "#/status?source=..%2Fetc", "#/status?source=", "#/status?source=github%20x", "#/status?q=x"]) {
    assert.equal(roundTrip(hash), "#/status", hash);
    assert.equal(parseRoute(hash, "").rewrite, true, hash);
  }
});

test("history, vendor, tag and actor views keep only their own keys", () => {
  assert.equal(roundTrip("#/history/2003?month=07&source=microsoft-bulletins&page=2"), "#/history/2003?source=microsoft-bulletins&month=07&page=2");
  assert.equal(roundTrip("#/history?month=07&source=x&page=2"), "#/history", "the year index reads no key");
  assert.equal(roundTrip("#/history/2003?q=x&kind=advisory&year=2004"), "#/history/2003");
  assert.equal(roundTrip("#/vendor/fortinet?page=3&kind=kev"), "#/vendor/fortinet?page=3");
  assert.equal(roundTrip("#/tags?year=2003&vendor=x"), "#/tags?year=2003");
  assert.equal(roundTrip("#/actors?year=1999"), "#/actors?year=1999");
  assert.equal(roundTrip("#/method?q=x"), "#/method");
  assert.equal(roundTrip("#/explore?cwe=CWE-79&tech=T1059.001"), "#/explore?cwe=CWE-79&tech=T1059.001");
  assert.equal(roundTrip("#/explore?cwe=79&tech=T1059.1"), "#/explore", "malformed CWE and technique ids are dropped");
});

test("#/tag/<field>/<value> is rewritten to the Explorer filter for that value", () => {
  const cases = [
    ["#/tag/vendor/fortinet", "#/explore?vendor=fortinet"],
    ["#/tag/event_type/breach", "#/explore?event=breach"],
    ["#/tag/source_class/press", "#/explore?class=press"],
    ["#/tag/exploitation/known", "#/explore?exp=known"],
    ["#/tag/attack/T1190", "#/explore?tech=T1190"],
    ["#/tag/cwe/CWE-787?year=2024", "#/explore?cwe=CWE-787&year=2024"],
    ["#/tag/region/US", "#/explore?region=US"],
    ["#/tag/vendor/%3Cx%3E", "#/explore"],
    ["#/tag/password/hunter2", "#/explore"],
    ["#/tag/vendor", "#/explore"]
  ];
  for (const [hash, expected] of cases) {
    const route = parseRoute(hash, "");
    assert.equal(route.rewrite, true, hash);
    assert.equal(formatRoute(route), expected, hash);
  }
});

test("every list filter, sort, page and open record round-trips in canonical order", () => {
  const hash = "#/explore?q=remote+code&kind=advisory&class=vendor-primary&event=exploitation&exp=known&kev=1&action=1&vendor=palo-alto-networks&product=pan-os" +
    "&actor=G0016&malware=S0154&sector=healthcare-public-health&region=US&source=cisa-advisories&year=2025&month=03&sort=cvss-desc&page=3&open=feed-3f41d3f2c16c88f054f7";
  const route = parseRoute(hash, "");
  assert.equal(route.rewrite, false);
  assert.equal(formatRoute(route), hash);
  assert.equal(route.query.q, "remote code");
  // Shuffled keys come back in canonical order.
  assert.equal(roundTrip("#/explore?page=2&q=x&kind=kev"), "#/explore?q=x&kind=kev&page=2");
  for (const view of ["advisories", "research", "news"]) assert.equal(roundTrip("#/" + view + "?range=90&exp=reported"), "#/" + view + "?exp=reported&range=90");
  assert.equal(roundTrip("#/kev?q=fortinet&year=2024&sort=due-asc&page=2"), "#/kev?q=fortinet&year=2024&sort=due-asc&page=2");
  assert.equal(roundTrip("#/cves?kev=1&action=1&sort=cvss-desc"), "#/cves?kev=1&action=1&sort=cvss-desc");
  assert.equal(roundTrip("#/cves?sort=epss-desc"), "#/cves?sort=epss-desc");
  assert.equal(roundTrip("#/explore?sort=epss-asc"), "#/explore?sort=epss-asc");
  assert.equal(roundTrip("#/kev?sort=epss-desc"), "#/kev", "the KEV ledger has no EPSS sort");
});

test("defaults are dropped and a year replaces the date range", () => {
  assert.equal(roundTrip("#/explore?sort=date-desc&page=1&range=all"), "#/explore");
  assert.equal(roundTrip("#/advisories?range=30"), "#/advisories");
  assert.equal(roundTrip("#/explore?year=2003&range=30"), "#/explore?year=2003");
  assert.equal(roundTrip("#/explore?month=05"), "#/explore", "a month needs its year");
  assert.equal(roundTrip("#/kev?sort=date-desc"), "#/kev", "a sort from another view is dropped");
});

test("hostile and unknown parameters are ignored and never reflected", () => {
  const hostile = [
    "#/explore?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&kind=%3Cimg%3E",
    "#/explore?vendor=..%2F..%2Fetc&actor=%22onmouseover%3D&region=us&year=1997&month=13&page=0&sort=__proto__",
    "#/explore?__proto__=x&constructor=y&utm_source=z&token=secret&open=%20bad",
    "#/explore?q=" + "a".repeat(201)
  ];
  for (const hash of hostile) {
    const route = parseRoute(hash, "");
    const text = formatRoute(route);
    assert.equal(route.rewrite, true, hash);
    assert.equal(text, "#/explore", hash + " reflected a value in " + text);
  }
  // Free text is data the page renders with textContent, bounded to 200 characters.
  assert.equal(parseRoute("#/explore?q=%3Cb%3E", "").query.q, undefined);
  assert.equal(parseRoute("#/explore?q=Microsoft%27s+patch", "").query.q, "Microsoft's patch");
  assert.equal(parseRoute("#/explore?q=" + "a".repeat(201), "").query.q, undefined);
  assert.equal(Object.getPrototypeOf(parseRoute("#/explore?__proto__=x", "").query), Object.prototype);
  assert.deepEqual(parseRoute("#/nowhere/at/all?kind=kev", "").view, "explore");
  assert.deepEqual(parseRoute("#/cve/not-a-cve", "").view, "cves");
  assert.equal(parseRoute("#/cves?open=x&vendor=y", "").query.open, undefined, "keys are per view");
});

test("A4 query keys and old anchors are accepted as legacy aliases and rewritten", () => {
  const cases = [
    [["#briefing", "?tag=vendor:fortinet&kind=kev"], "#/explore?kind=kev&vendor=fortinet"],
    [["", "?tag=actor:G0016"], "#/explore?actor=G0016"],
    [["", "?tag=malware:S0154&q=beacon"], "#/explore?q=beacon&malware=S0154"],
    [["", "?tag=sector:healthcare-public-health"], "#/explore?sector=healthcare-public-health"],
    [["#timeline", "?year=2021"], "#/explore?year=2021"],
    [["", "?month=2021-12"], "#/explore?year=2021&month=12"],
    [["", "?year=2021&month=12"], "#/explore?year=2021&month=12"],
    [["", "?view=cves"], "#/cves"],
    [["", "?view=feed&kind=advisory"], "#/explore?kind=advisory"],
    [["", "?cve=CVE-2021-44228"], "#/cve/CVE-2021-44228"],
    [["#reports", ""], "#/reports"],
    [["#method", ""], "#/method"],
    [["#knowledge", ""], "#/about"],
    [["", "?tag=vendor:%3Cx%3E&cve=nope&view=../../"], "#/explore"]
  ];
  for (const [[hash, search], expected] of cases) {
    const route = parseRoute(hash, search);
    assert.equal(route.rewrite, true, hash + search);
    assert.equal(formatRoute(route), expected, hash + search);
  }
});

test("the desk key, the reserved kinds and event types and the wall key round-trip, and bad values are dropped", () => {
  assert.deepEqual(DESKS, ["security", "infrastructure", "it"]);
  for (const desk of DESKS) assert.equal(roundTrip("#/explore?desk=" + desk), "#/explore?desk=" + desk);
  assert.equal(roundTrip("#/news?desk=it&range=30"), "#/news?desk=it&range=30");
  assert.equal(roundTrip("#/explore?kind=advisory&desk=security"), "#/explore?desk=security&kind=advisory", "desk is written right after q");
  for (const hash of ["#/explore?desk=Security", "#/explore?desk=%3Cx%3E", "#/explore?desk=cloud", "#/kev?desk=security", "#/status?desk=infrastructure"]) {
    assert.equal(roundTrip(hash), hash.slice(0, hash.indexOf("?")), hash);
    assert.equal(parseRoute(hash, "").rewrite, true, hash);
  }
  assert.equal(roundTrip("#/explore?kind=change&event=end-of-support"), "#/explore?kind=change&event=end-of-support");
  assert.equal(roundTrip("#/explore?kind=lifecycle&event=maintenance"), "#/explore?kind=lifecycle&event=maintenance");
  const route = parseRoute("#/tag/desk/infrastructure", "");
  assert.equal(route.rewrite, true);
  assert.equal(formatRoute(route), "#/explore?desk=infrastructure");
  // Wall mode is a key of Today and Service health only.
  assert.equal(roundTrip("#/today?wall=1"), "#/today?wall=1");
  assert.equal(roundTrip("#/status?source=github&wall=1"), "#/status?source=github&wall=1");
  for (const hash of ["#/today?wall=2", "#/today?wall=", "#/today?wall=%3Cx%3E"]) assert.equal(roundTrip(hash), "#/today", hash);
  assert.equal(roundTrip("#/explore?wall=1"), "#/explore", "the Explorer has no wall mode");
  assert.equal(roundTrip("#/kev?wall=1"), "#/kev");
});

test("every view sits under exactly one desk, and the desk row's targets are views on their desk", () => {
  for (const view of VIEWS) assert.ok(["explore", "security", "infrastructure", "reference"].includes(VIEW_DESK[view]), view);
  assert.deepEqual(Object.keys(VIEW_DESK).sort(), [...VIEWS].sort());
  assert.equal(VIEW_DESK.explore, "explore");
  assert.equal(VIEW_DESK.today, "security");
  assert.equal(VIEW_DESK.status, "infrastructure");
  assert.equal(VIEW_DESK.history, "reference");
  assert.equal(VIEW_DESK.subscribe, "reference");
  assert.equal(roundTrip("#/subscribe?q=x&wall=1"), "#/subscribe", "Subscribe reads no key");
  // A page with an id sits where its index sits.
  assert.equal(VIEW_DESK.cve, VIEW_DESK.cves);
  assert.equal(VIEW_DESK.vendor, VIEW_DESK.vendors);
  assert.equal(VIEW_DESK.actor, VIEW_DESK.actors);
  assert.equal(VIEW_DESK.malware, VIEW_DESK.actors);
});

test("withQuery changes keys, resets the page on a filter change and keeps it otherwise", () => {
  const route = parseRoute("#/explore?kind=kev&page=4", "");
  assert.equal(formatRoute(withQuery(route, { exp: "known" })), "#/explore?kind=kev&exp=known");
  assert.equal(formatRoute(withQuery(route, { open: "a-1" }, true)), "#/explore?kind=kev&page=4&open=a-1");
  assert.equal(formatRoute(withQuery(route, { kind: null })), "#/explore");
});

test("every example link in docs/URLS.md is already in canonical form", () => {
  const page = readFileSync(new URL("../../docs/URLS.md", import.meta.url), "utf8");
  const examples = page.slice(page.indexOf("## Examples"));
  const links = [...examples.matchAll(/`https:\/\/teamstarwolf\.github\.io\/intelligence-hub\/(#\/[^`]*)`/g)].map(match => match[1]);
  assert.ok(links.length >= 7, "the examples table is read");
  for (const hash of links) {
    const route = parseRoute(hash, "");
    assert.equal(route.rewrite, false, hash);
    assert.equal(formatRoute(route), hash, hash + " is what the page would rewrite it to");
  }
});
