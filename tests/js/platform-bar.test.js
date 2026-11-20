// The platform bar on site/index.html. The menu is static markup (generated from platform-nav.json),
// so this test checks it against the copy and then that platform-bar.js enhances it: carets and
// chevrons, open and close, the keyboard, the side fly-out and the click-away close. No pending
// entry may appear in the markup.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ROOT, page } from "./fixtures.js";
import { createPlatformBar } from "../../site/js/platform-bar.js";

const MENU = JSON.parse(readFileSync(ROOT + "site/platform-nav.json", "utf8"));

function boot() {
  const shell = page();
  const bar = createPlatformBar({ doc: shell.doc, win: shell.win });
  return { ...shell, bar };
}

const hrefsIn = root => [...root.querySelectorAll("a")].map(a => a.getAttribute("href"));
const pendingHrefs = () => {
  const out = [];
  const walk = node => { for (const entry of node.menu || []) { if (entry.pending) out.push(entry.href); walk(entry); } };
  for (const item of MENU.items) walk(item);
  return out;
};

test("the static top-level links match the menu file, in order, and no pending address is in the markup", async () => {
  const { doc } = boot();
  const items = [...doc.querySelectorAll(".tsw-bar__item")];
  assert.deepEqual(items.map(li => li.dataset.tswItem), MENU.items.map(item => item.id));
  for (const li of items) {
    const item = MENU.items.find(entry => entry.id === li.dataset.tswItem);
    const link = li.querySelector(".tsw-bar__link");
    assert.equal(link.getAttribute("href"), item.href, item.id + " href");
    assert.equal(link.textContent, item.label, item.id + " label");
  }
  const pending = pendingHrefs();
  assert.ok(pending.length >= 2, "the fixture still has pending entries to exclude");
  const barHrefs = hrefsIn(doc.querySelector("[data-tsw-bar]"));
  for (const href of pending) assert.ok(!barHrefs.includes(href), "pending address absent: " + href);
});

test("enhancing adds a caret per item and a chevron per category, and sets a roving tabindex", async () => {
  const { doc, bar } = boot();
  bar.init();
  assert.ok(doc.querySelector("[data-tsw-bar]").classList.contains("tsw-bar--js"));
  const home = bar.record("home");
  assert.ok(home.caret, "home has a caret");
  assert.equal(home.caret.getAttribute("aria-expanded"), "false");
  assert.deepEqual(home.entries.map(entry => entry.link.textContent), ["Front page", "Design system"]);
  for (const entry of home.entries) assert.equal(entry.link.getAttribute("tabindex"), "-1");

  const hub = MENU.items.find(item => item.id === "hub");
  assert.deepEqual(bar.record("hub").entries.map(entry => entry.link.textContent), hub.menu.map(entry => entry.label));

  // Bookmarks has categories with their own chevron and sub-entries.
  const parents = bar.record("bookmarks").entries.filter(entry => entry.subcaret);
  assert.ok(parents.length >= 1, "a bookmarks category carries a chevron");
  const sub = parents[0].subLinks.map(a => a.textContent);
  assert.ok(sub.length >= 2 && parents[0].subLinks.every(a => a.getAttribute("tabindex") === "-1"));
});

test("the caret opens and closes the panel; only one is open at a time", async () => {
  const { bar } = boot();
  bar.init();
  const home = bar.record("home");
  home.caret.dispatchEvent({ type: "click", detail: 1 });
  assert.equal(bar.isOpen("home"), true);
  assert.equal(home.caret.getAttribute("aria-expanded"), "true");
  bar.open("library");
  assert.equal(bar.isOpen("home"), false);
  assert.equal(home.caret.getAttribute("aria-expanded"), "false");
  assert.equal(bar.isOpen("library"), true);
});

test("ArrowDown opens and focuses the first entry; Escape closes and returns focus to the caret", async () => {
  const { doc, bar } = boot();
  bar.init();
  const home = bar.record("home");
  home.caret.dispatchEvent({ type: "keydown", key: "ArrowDown", preventDefault() {} });
  assert.equal(bar.isOpen("home"), true);
  assert.equal(doc.activeElement, home.entries[0].link);
  home.entries[0].link.dispatchEvent({ type: "keydown", key: "Escape", preventDefault() {} });
  assert.equal(bar.isOpen("home"), false);
  assert.equal(doc.activeElement, home.caret);
});

test("ArrowRight opens a category's fly-out and moves in; ArrowLeft closes it and returns", async () => {
  const { doc, bar } = boot();
  bar.init();
  const record = bar.record("bookmarks");
  const index = record.entries.findIndex(entry => entry.subcaret);
  const entry = record.entries[index];
  bar.open("bookmarks");
  entry.link.dispatchEvent({ type: "keydown", key: "ArrowRight", preventDefault() {} });
  assert.equal(bar.isFlyoutOpen("bookmarks", index), true);
  assert.equal(doc.activeElement, entry.subLinks[0]);
  entry.subLinks[0].dispatchEvent({ type: "keydown", key: "ArrowLeft", preventDefault() {} });
  assert.equal(bar.isFlyoutOpen("bookmarks", index), false);
  assert.equal(doc.activeElement, entry.link);
});

test("the chevron button toggles its fly-out, and only one fly-out is open at a time", async () => {
  const { bar } = boot();
  bar.init();
  const record = bar.record("bookmarks");
  const parents = record.entries.map((entry, index) => ({ entry, index })).filter(pair => pair.entry.subcaret);
  bar.open("bookmarks");
  parents[0].entry.subcaret.dispatchEvent({ type: "click", detail: 1 });
  assert.equal(bar.isFlyoutOpen("bookmarks", parents[0].index), true);
  parents[1].entry.subcaret.dispatchEvent({ type: "click", detail: 1 });
  assert.equal(bar.isFlyoutOpen("bookmarks", parents[0].index), false, "opening the second closes the first");
  assert.equal(bar.isFlyoutOpen("bookmarks", parents[1].index), true);
});

test("a click outside the bar closes an open panel; a click inside does not", async () => {
  const { doc, bar } = boot();
  bar.init();
  bar.open("home");
  doc.dispatchEvent({ type: "click", target: bar.record("home").entries[0].link });
  assert.equal(bar.isOpen("home"), true);
  doc.dispatchEvent({ type: "click", target: doc.querySelector("#q") });
  assert.equal(bar.isOpen("home"), false);
});
