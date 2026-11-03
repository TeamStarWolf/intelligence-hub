// The route contract (docs/URLS.md): every view and filter round-trips through the hash, the
// A4 link keys are rewritten, and hostile or unknown parameters never survive.
import { test } from "node:test";
import assert from "node:assert/strict";
import { VIEWS, formatRoute, parseRoute, withQuery } from "../../site/js/router.js";

const roundTrip = hash => formatRoute(parseRoute(hash, ""));

test("every view round-trips", () => {
  for (const view of VIEWS.filter(name => name !== "cve")) assert.equal(roundTrip("#/" + view), "#/" + view);
  assert.equal(roundTrip("#/cve/CVE-2026-118527"), "#/cve/CVE-2026-118527");
  assert.deepEqual(parseRoute("#/cve/CVE-2026-118527", ""), { view: "cve", id: "CVE-2026-118527", query: {}, rewrite: false });
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
    [["#method", ""], "#/about"],
    [["#knowledge", ""], "#/about"],
    [["", "?tag=vendor:%3Cx%3E&cve=nope&view=../../"], "#/explore"]
  ];
  for (const [[hash, search], expected] of cases) {
    const route = parseRoute(hash, search);
    assert.equal(route.rewrite, true, hash + search);
    assert.equal(formatRoute(route), expected, hash + search);
  }
});

test("withQuery changes keys, resets the page on a filter change and keeps it otherwise", () => {
  const route = parseRoute("#/explore?kind=kev&page=4", "");
  assert.equal(formatRoute(withQuery(route, { exp: "known" })), "#/explore?kind=kev&exp=known");
  assert.equal(formatRoute(withQuery(route, { open: "a-1" }, true)), "#/explore?kind=kev&page=4&open=a-1");
  assert.equal(formatRoute(withQuery(route, { kind: null })), "#/explore");
});
