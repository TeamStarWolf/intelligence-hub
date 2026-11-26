// The public-exploit signal on the page: the unified rule (the CNA exploit tag or CISA's SSVC
// Exploitation poc/active), the Explorer filter and chip, the CVE register filter and note, the
// brief badge and its source line, and the validators that carry the stored poc count.
import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { CVE_ROWS, brief, files, page, server, settle, storage } from "./fixtures.js";
import { createApp } from "../../site/js/main.js";
import { parseRoute } from "../../site/js/router.js";
import { EXPLOIT_LABEL, cveExploitState, cvePublicExploit, cveRegister, publicExploit, rowExploitState } from "../../site/js/filters.js";
import { briefBody } from "../../site/js/views/cves.js";
import { FormatError, normalizeBrief, normalizeCveIndex, normalizePoc, normalizeRecent } from "../../site/js/validate.js";

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

test("the exploitation state is public for the CNA tag or SSVC poc, active for SSVC active, and null otherwise", () => {
  // The CNA exploit tag and SSVC poc both mean a public exploit exists; SSVC active means exploited
  // in the wild, worded apart because it does not itself say exploit code is public.
  assert.equal(cveExploitState({ poc: 1, ssvc_exploitation: null }), "public", "CNA tag");
  assert.equal(cveExploitState({ poc: 0, ssvc_exploitation: "poc" }), "public", "SSVC poc");
  assert.equal(cveExploitState({ poc: 2, ssvc_exploitation: "active" }), "public", "tag outranks active");
  assert.equal(cveExploitState({ poc: 0, ssvc_exploitation: "active" }), "active", "SSVC active only");
  assert.equal(cveExploitState({ poc: 0, ssvc_exploitation: "none" }), null, "SSVC none, no tag");
  assert.equal(cveExploitState({ poc: 0, ssvc_exploitation: null }), null, "nothing");
  assert.equal(cveExploitState(null), null);
  // The filter predicate covers both states; the row state prefers public over active.
  for (const e of [{ poc: 1, ssvc_exploitation: null }, { poc: 0, ssvc_exploitation: "poc" }, { poc: 0, ssvc_exploitation: "active" }]) assert.equal(cvePublicExploit(e), true);
  assert.equal(cvePublicExploit({ poc: 0, ssvc_exploitation: "none" }), false);
  const index = new Map([["CVE-A", { poc: 0, ssvc_exploitation: "active" }], ["CVE-B", { poc: 3, ssvc_exploitation: null }]]);
  assert.equal(rowExploitState({ cves: ["CVE-A", "CVE-B"] }, index), "public", "a public CVE outranks an active one on the row");
  assert.equal(rowExploitState({ cves: ["CVE-A"] }, index), "active");
  assert.equal(rowExploitState({ cves: [] }, index), null);
});

test("the wording keeps \"Public exploit\" off SSVC active alone", () => {
  // The chip, register note and brief badge all read EXPLOIT_LABEL[state]; active never maps to the
  // words "Public exploit".
  assert.equal(EXPLOIT_LABEL.public, "Public exploit");
  assert.equal(EXPLOIT_LABEL.active, "Exploited (CISA SSVC)");
  assert.ok(!EXPLOIT_LABEL.active.includes("Public exploit"), "active is not labelled a public exploit");
  const activeOnly = { poc: 0, ssvc_exploitation: "active" };
  assert.equal(EXPLOIT_LABEL[cveExploitState(activeOnly)], "Exploited (CISA SSVC)");
});

test("the Explorer filter and chip reflect the unified public-exploit signal", async () => {
  const site = files();
  const index = normalizeCveIndex(JSON.parse(site.bodies["./data/v7/cve-index.json"])).rows;
  // CVE-2026-1000 is public exploit (poc 2 and SSVC active); 1001 and 1002 are not.
  assert.equal(publicExploit({ cves: ["CVE-2026-1000"] }, index), true);
  assert.equal(publicExploit({ cves: ["CVE-2026-1001", "CVE-2026-1002"] }, index), false);
  assert.equal(publicExploit({ cves: [] }, index), false);
  const shell = await boot({ hash: "#/explore?sort=epss-desc" });
  const cards = () => [...shell.doc.querySelectorAll("#results .card")];
  const hasChip = card => [...card.querySelectorAll(".chip")].some(chip => chip.textContent === "Public exploit");
  const all = cards();
  // The top card is the CVE-2026-1000 story (highest EPSS); it is a public exploit, so it carries the chip.
  assert.ok(all.length > 0 && hasChip(all[0]), "the matching card carries the Public exploit chip");
  assert.ok(all.some(card => !hasChip(card)), "and some card does not");
  // Filtering by poc=1 keeps only rows with a public-exploit CVE, and every kept card carries the chip.
  await go(shell, "#/explore?poc=1&sort=epss-desc");
  const filtered = cards();
  assert.ok(filtered.length >= 1 && filtered.length < all.length, "the filter narrows the set");
  assert.ok(filtered.every(hasChip), "every filtered card has the Public exploit chip");
});

test("the CVE register notes a public exploit and filters on it", async () => {
  const shell = await boot({ hash: "#/cves" });
  const noteFor = (view, cve) => {
    const tr = [...view.querySelectorAll("#view tbody tr")].find(row => row.querySelector("td a")?.textContent === cve);
    return tr ? [...tr.querySelectorAll(".cell-note")].map(note => note.textContent) : null;
  };
  assert.ok(noteFor(shell.doc.querySelector("#view"), "CVE-2026-1000").includes("Public exploit"), "the matching CVE is noted");
  assert.ok(!(noteFor(shell.doc.querySelector("#view"), "CVE-2026-1001") || []).includes("Public exploit"), "a non-matching CVE is not");
  const filtered = await go(shell, "#/cves?poc=1");
  const cves = [...filtered.querySelectorAll("#view tbody tr td a")].map(anchor => anchor.textContent);
  assert.deepEqual(cves, ["CVE-2026-1000"], cves.join(" | "));
  // The register filter helper agrees.
  const site = files();
  const index = normalizeCveIndex(JSON.parse(site.bodies["./data/v7/cve-index.json"])).rows;
  assert.deepEqual(cveRegister(index, { poc: "1" }).map(row => row.cve), ["CVE-2026-1000"]);
  assert.equal(cveRegister(index, {}).length, 3, "no filter keeps every CVE");
});

test("the brief badges a public exploit, names the source and counts the CNA references, and a plain CVE does not", async () => {
  const shell = await boot({ hash: "#/cve/CVE-2026-1000" });
  await settle(60);
  const body = shell.doc.querySelector("#cve-body");
  assert.ok([...body.querySelectorAll(".chip")].some(chip => chip.textContent === "Public exploit"), "the badge is shown");
  assert.ok(body.textContent.includes("Public exploit: the CNA tagged 2 references as a public exploit; CISA's SSVC Exploitation is active"), body.textContent);
  assert.ok(body.textContent.includes("The CNA tagged 2 references as a public exploit"), "the references block names the count");
  // CVE-2026-1002 has no CNA tag and no SSVC poc/active, so no badge.
  await go(shell, "#/cve/CVE-2026-1002");
  await settle(60);
  const plain = shell.doc.querySelector("#cve-body");
  assert.ok(![...plain.querySelectorAll(".chip")].some(chip => chip.textContent === "Public exploit"), "a plain CVE shows no badge");
  // A brief with the poc key absent (a record not re-read on resume) renders with no badge, no error.
  const noPoc = brief("CVE-2026-1002"); delete noPoc.poc;
  const chips = briefBody(noPoc, null, [], null, null).flatMap(part => [...part.querySelectorAll(".chip")].map(chip => chip.textContent));
  assert.ok(!chips.includes("Public exploit") && !chips.includes("Exploited (CISA SSVC)"), chips.join(" | "));
});

test("the validators carry the stored poc count and refuse a bad one", () => {
  assert.equal(normalizePoc(0), 0);
  assert.equal(normalizePoc(5), 5);
  assert.equal(normalizePoc(100), 100);
  assert.equal(normalizePoc(null), 0);
  assert.equal(normalizePoc(undefined), 0);
  for (const bad of [-1, 101, 1.5, "2", true]) assert.throws(() => normalizePoc(bad), FormatError, JSON.stringify(bad));
  const site = files();
  const index = normalizeCveIndex(JSON.parse(site.bodies["./data/v7/cve-index.json"]));
  assert.equal(index.rows.get("CVE-2026-1000").poc, 2);
  assert.equal(index.rows.get("CVE-2026-1001").poc, 0);
  const recent = normalizeRecent(JSON.parse(site.bodies["./data/v7/recent.json"]));
  assert.equal(recent.cves.get("CVE-2026-1000").poc, 2);
  const typed = JSON.parse(site.bodies["./data/v7/cve-index.json"]);
  typed.rows[0] = [...CVE_ROWS[0].slice(0, 11), -1, null];
  assert.throws(() => normalizeCveIndex(typed), FormatError);
  const stored = normalizeBrief(brief("CVE-2026-1000", { poc: 7 }), "CVE-2026-1000");
  assert.equal(stored.poc, 7);
  const before = brief("CVE-2026-1001"); delete before.poc;
  assert.equal(normalizeBrief(before, "CVE-2026-1001").poc, 0, "a brief published before the field reads as 0");
});
