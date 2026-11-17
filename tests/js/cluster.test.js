// Story clustering (site/js/filters.js clusterStories): the conservative grouping of one event
// reported by several outlets into a single primary row. The tests that matter most are the ones
// that prove it does not merge two distinct stories; clustering is allowed to miss a true
// duplicate, but must never fold unrelated rows together.
import { test } from "node:test";
import assert from "node:assert/strict";
import { clusterStories } from "../../site/js/filters.js";

function row(id, title, day, cves = []) {
  return { id, title, day, cves, source_name: id };
}

test("identical and near-identical headlines on the same day group under one primary", () => {
  const rows = [
    row("a", "Optimizely supply chain attack infects major brands with malware", "2026-11-17"),
    row("b", "Optimizely supply chain attack infects major brands with malware", "2026-11-17"),
    row("c", "Optimizely supply chain attack infects major brands and sites with malware", "2026-11-17"),
  ];
  const groups = clusterStories(rows);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].primary.id, "a");
  assert.deepEqual(groups[0].others.map(item => item.id), ["b", "c"]);
});

test("the same non-empty CVE set within a day groups even when the headlines differ", () => {
  const groups = clusterStories([
    row("a", "Vendor ships an emergency fix for its appliance", "2026-11-10", ["CVE-2026-1"]),
    row("b", "Appliance bug is under active exploitation, researchers say", "2026-11-11", ["CVE-2026-1"]),
  ]);
  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0].others.map(item => item.id), ["b"]);
});

test("two different stories that share only generic security words are NOT merged", () => {
  // Both say patches/critical/remote/code/execution/flaw; only the product words differ.
  const groups = clusterStories([
    row("ms", "Microsoft patches critical Exchange remote code execution flaw", "2026-11-10"),
    row("cisco", "Cisco patches critical firewall remote code execution flaw", "2026-11-10"),
  ]);
  assert.equal(groups.length, 2);
});

test("two different supply-chain stories with partial overlap are NOT merged", () => {
  const groups = clusterStories([
    row("optimizely", "Optimizely supply chain attack infects major brands with malware", "2026-11-17"),
    row("npm", "npm supply chain attack infects many packages", "2026-11-17"),
  ]);
  assert.equal(groups.length, 2);
});

test("a gap of more than one day keeps even identical headlines apart", () => {
  const groups = clusterStories([
    row("a", "Optimizely supply chain attack infects major brands with malware", "2026-11-13"),
    row("b", "Optimizely supply chain attack infects major brands with malware", "2026-11-17"),
  ]);
  assert.equal(groups.length, 2);
});

test("the same CVE on days more than one apart does not group", () => {
  const groups = clusterStories([
    row("a", "Appliance advisory", "2026-11-10", ["CVE-2026-1"]),
    row("b", "Appliance follow up", "2026-11-15", ["CVE-2026-1"]),
  ]);
  assert.equal(groups.length, 2);
});

test("unrelated no-CVE stories on the same day each stand alone", () => {
  const groups = clusterStories([
    row("a", "California sues OpenAI over its agents", "2026-11-16"),
    row("b", "Fortinet discloses an SSL VPN authentication bypass", "2026-11-16"),
    row("c", "Uber says a breach exposed driver licence records", "2026-11-16"),
  ]);
  assert.equal(groups.length, 3);
  assert.ok(groups.every(group => group.others.length === 0));
});

test("rows without a day never group, and empty input yields no groups", () => {
  assert.deepEqual(clusterStories([]), []);
  const groups = clusterStories([
    row("a", "Optimizely supply chain attack infects major brands with malware", null),
    row("b", "Optimizely supply chain attack infects major brands with malware", null),
  ]);
  assert.equal(groups.length, 2);
});

test("input order is preserved: the first row of a group is its primary", () => {
  const groups = clusterStories([
    row("first", "Google Project Zero cuts bug disclosure to thirty day deadline", "2026-11-16"),
    row("unrelated", "Barracuda links a cloud incident to an automated campaign", "2026-11-16"),
    row("second", "Google Project Zero cuts bug disclosure to thirty day deadline", "2026-11-16"),
  ]);
  assert.equal(groups.length, 2);
  assert.equal(groups[0].primary.id, "first");
  assert.deepEqual(groups[0].others.map(item => item.id), ["second"]);
  assert.equal(groups[1].primary.id, "unrelated");
});
