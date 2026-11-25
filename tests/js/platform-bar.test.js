// The platform bar on site/index.html. The menu is static markup (generated from platform-nav.json),
// so this test checks the markup against the copy (top-level links, and all 291 external Bookmarks
// leaves with their new-tab attributes and screen-reader note), then that platform-bar.js enhances
// it: carets at every level, the three Bookmarks levels opening one path at a time, the keyboard,
// the side fly-out with its left flip, hover with a delayed close, and the click-away close. No
// pending entry may appear in the markup.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ROOT, page } from "./fixtures.js";
import { createPlatformBar } from "../../site/js/platform-bar.js";

const MENU = JSON.parse(readFileSync(ROOT + "site/platform-nav.json", "utf8"));
const BOOKMARKS = MENU.items.find(item => item.id === "bookmarks");
const SR_NOTE = "(opens in a new tab on an external site)";

function boot(env = {}) {
  const shell = page();
  const bar = createPlatformBar({ doc: shell.doc, win: shell.win, ...env });
  return { ...shell, bar };
}

const isLeaf = entry => !Array.isArray(entry.menu);
function countExternal(entries) {
  let total = 0;
  for (const entry of entries || []) {
    if (isLeaf(entry)) { if (entry.external === true) total += 1; }
    else total += countExternal(entry.menu);
  }
  return total;
}
function pendingHrefs() {
  const out = [];
  const walk = node => { for (const entry of node.menu || []) { if (entry.pending) out.push(entry.href); walk(entry); } };
  for (const item of MENU.items) walk(item);
  return out;
}

test("the static top-level links match the menu file, in order, and no pending address is in the markup", async () => {
  const { doc } = boot();
  const items = [...doc.querySelectorAll(".tsw-bar__item")];
  assert.deepEqual(items.map(li => li.dataset.tswItem), MENU.items.map(item => item.id));
  for (const li of items) {
    const item = MENU.items.find(entry => entry.id === li.dataset.tswItem);
    const link = [...li.children].find(child => child.classList.contains("tsw-bar__link"));
    assert.equal(link.getAttribute("href"), item.href, item.id + " href");
    assert.equal(link.textContent, item.label, item.id + " label");
  }
  const pending = pendingHrefs();
  assert.ok(pending.length >= 1, "the fixture still has a pending entry to exclude");
  const hrefs = [...doc.querySelector("[data-tsw-bar]").querySelectorAll("a")].map(a => a.getAttribute("href"));
  for (const href of pending) assert.ok(!hrefs.includes(href), "pending address absent: " + href);
  const names = [...doc.querySelectorAll(".tsw-bar__mlink")].map(a => a.textContent);
  assert.ok(!names.some(name => name.startsWith("Security policy")), "pending label absent");
});

test("every external Bookmarks leaf renders with the new-tab attributes, a hidden marker and the note", async () => {
  const { doc } = boot();
  const expected = countExternal(BOOKMARKS.menu);
  assert.equal(expected, 291, "the menu still carries 291 external leaves");
  const ext = [...doc.querySelectorAll(".tsw-bar__mlink--ext")];
  assert.equal(ext.length, expected, "every external leaf is rendered");
  for (const link of ext) {
    assert.equal(link.getAttribute("target"), "_blank", link.getAttribute("href") + " target");
    assert.equal(link.getAttribute("rel"), "noopener noreferrer", link.getAttribute("href") + " rel");
    const marker = [...link.children].find(child => child.classList.contains("tsw-bar__ext"));
    assert.ok(marker && marker.getAttribute("aria-hidden") === "true", "a hidden arrow marker");
    const note = [...link.children].find(child => child.classList.contains("tsw-bar__sr"));
    assert.ok(note && note.textContent.includes(SR_NOTE), "a screen-reader note");
    assert.ok(link.textContent.trimEnd().endsWith(SR_NOTE), "the accessible name ends with the note");
    assert.ok(link.getAttribute("href").startsWith("https://"), "an https address");
  }
  // A header (a category or subsection) is an internal link, not external.
  const headers = [...doc.querySelectorAll(".tsw-bar__mitem--parent")].map(li => [...li.children].find(c => c.classList.contains("tsw-bar__mlink")));
  assert.ok(headers.length >= 42, "categories and subsections are present");
  for (const header of headers) {
    assert.ok(!header.classList.contains("tsw-bar__mlink--ext"), "a header is not external");
    assert.ok(header.getAttribute("href").startsWith("https://github.com/TeamStarWolf/"), "a header is an internal link");
  }
});

test("enhancing adds a caret per item and per nested parent, a Menu toggle, and a roving tabindex", async () => {
  const { doc, bar } = boot();
  bar.init();
  assert.ok(doc.querySelector("[data-tsw-bar]").classList.contains("tsw-bar--js"));
  assert.ok(doc.querySelector(".tsw-bar__toggle"), "a small-screen Menu toggle");
  assert.equal([...doc.querySelectorAll(".tsw-bar__disc")].length, MENU.items.length, "one top caret per item");
  // Categories (12) plus subsections (30) each carry a chevron.
  assert.equal([...doc.querySelectorAll(".tsw-bar__mdisc")].length, 42, "a chevron per category and subsection");
  for (const link of doc.querySelectorAll(".tsw-bar__mlink")) assert.equal(link.getAttribute("tabindex"), "-1");

  const hub = MENU.items.find(item => item.id === "hub");
  assert.deepEqual(bar.node("hub").links.map(a => a.textContent), hub.menu.map(entry => entry.label));
  assert.equal(bar.node("bookmarks").children.length, BOOKMARKS.menu.length, "a node per category");
});

test("the caret opens and closes the panel; only one top panel is open at a time", async () => {
  const { bar } = boot();
  bar.init();
  const home = bar.node("home");
  home.caret.dispatchEvent({ type: "click", detail: 1 });
  assert.equal(bar.isOpen("home"), true);
  assert.equal(home.caret.getAttribute("aria-expanded"), "true");
  bar.open("library");
  assert.equal(bar.isOpen("home"), false);
  assert.equal(home.caret.getAttribute("aria-expanded"), "false");
  assert.equal(bar.isOpen("library"), true);
});

test("the three Bookmarks levels open, one path at a time at each level", async () => {
  const { bar } = boot();
  bar.init();
  bar.open("bookmarks");
  const cats = bar.node("bookmarks").children;
  const subsCat = cats.find(cat => cat.children.length > 0);
  const otherCat = cats.find(cat => cat !== subsCat);
  assert.ok(subsCat && otherCat, "a category with subsections and another category");

  subsCat.caret.dispatchEvent({ type: "click", detail: 1 });
  assert.equal(subsCat.expanded, true, "the category fly-out opens");
  otherCat.caret.dispatchEvent({ type: "click", detail: 1 });
  assert.equal(subsCat.expanded, false, "opening a sibling category closes the first");
  assert.equal(otherCat.expanded, true);

  subsCat.caret.dispatchEvent({ type: "click", detail: 1 });
  const [sub0, sub1] = subsCat.children;
  assert.ok(sub0 && sub1, "the category has at least two subsections");
  sub0.caret.dispatchEvent({ type: "click", detail: 1 });
  assert.equal(sub0.expanded, true, "a subsection fly-out opens");
  sub1.caret.dispatchEvent({ type: "click", detail: 1 });
  assert.equal(sub0.expanded, false, "opening a sibling subsection closes the first");
  assert.equal(sub1.expanded, true);
});

test("ArrowDown opens and focuses the first entry; Escape closes and returns focus to the caret", async () => {
  const { doc, bar } = boot();
  bar.init();
  const home = bar.node("home");
  home.caret.dispatchEvent({ type: "keydown", key: "ArrowDown", preventDefault() {} });
  assert.equal(bar.isOpen("home"), true);
  assert.equal(doc.activeElement, home.links[0]);
  home.links[0].dispatchEvent({ type: "keydown", key: "Escape", preventDefault() {} });
  assert.equal(bar.isOpen("home"), false);
  assert.equal(doc.activeElement, home.caret);
});

test("ArrowRight opens a category's fly-out and moves in; ArrowLeft closes it and returns", async () => {
  const { doc, bar } = boot();
  bar.init();
  bar.open("bookmarks");
  const node = bar.node("bookmarks");
  const subsCat = node.children.find(cat => cat.children.length > 0);
  const header = subsCat.headerLink;
  header.dispatchEvent({ type: "keydown", key: "ArrowRight", preventDefault() {} });
  assert.equal(subsCat.expanded, true);
  assert.equal(doc.activeElement, subsCat.links[0]);
  subsCat.links[0].dispatchEvent({ type: "keydown", key: "ArrowLeft", preventDefault() {} });
  assert.equal(subsCat.expanded, false);
  assert.equal(doc.activeElement, header);
});

test("Escape walks back out one open level at a time, deepest first", async () => {
  const { doc, bar } = boot();
  bar.init();
  bar.open("bookmarks");
  const top = bar.node("bookmarks");
  const cat = top.children.find(c => c.children.length > 0);
  bar.node("bookmarks");
  cat.caret.dispatchEvent({ type: "click", detail: 0 });   // open the category, focus its first entry
  const sub = cat.children[0];
  sub.caret.dispatchEvent({ type: "click", detail: 0 });    // open a subsection, focus its first leaf
  assert.equal(sub.expanded, true);
  // Escape on the deepest entry closes the subsection and returns to its caret.
  doc.activeElement.dispatchEvent({ type: "keydown", key: "Escape", preventDefault() {} });
  assert.equal(sub.expanded, false);
  assert.equal(cat.expanded, true, "the category stays open");
  // Escape on the category caret closes the category; the panel stays open.
  cat.caret.dispatchEvent({ type: "keydown", key: "Escape", preventDefault() {} });
  assert.equal(cat.expanded, false);
  assert.equal(bar.isOpen("bookmarks"), true);
});

test("a click outside the bar closes an open panel; a click inside does not", async () => {
  const { doc, bar } = boot();
  bar.init();
  bar.open("home");
  doc.dispatchEvent({ type: "click", target: bar.node("home").links[0] });
  assert.equal(bar.isOpen("home"), true);
  doc.dispatchEvent({ type: "click", target: doc.querySelector("#q") });
  assert.equal(bar.isOpen("home"), false);
});

// A captured-timer stand-in so the delayed close can be driven without waiting.
function timerStub() {
  const calls = [];
  let id = 0;
  return {
    setTimeoutImpl: (fn, ms) => { const made = ++id; calls.push({ id: made, fn, ms }); return made; },
    clearTimeoutImpl: cleared => { const at = calls.findIndex(call => call.id === cleared); if (at >= 0) calls.splice(at, 1); },
    pending: () => calls,
    fire: () => { const call = calls.shift(); if (call) call.fn(); },
  };
}

test("on a fine pointer, hover opens a menu immediately", async () => {
  const { bar, doc } = boot({ matchMediaImpl: () => ({ matches: true }) });
  bar.init();
  bar.node("home").owner.dispatchEvent({ type: "pointerenter" });
  assert.equal(bar.isOpen("home"), true);
  void doc;
});

test("the menu closes after the delay when the pointer leaves, and a re-enter cancels the close", async () => {
  const timers = timerStub();
  const { bar, doc } = boot({ matchMediaImpl: () => ({ matches: true }), setTimeoutImpl: timers.setTimeoutImpl, clearTimeoutImpl: timers.clearTimeoutImpl });
  bar.init();
  const nav = doc.querySelector("[data-tsw-bar]");
  bar.open("home");
  nav.dispatchEvent({ type: "pointerleave" });
  assert.equal(bar.isOpen("home"), true, "it stays open until the timer fires");
  assert.equal(timers.pending()[0].ms, 220, "close is scheduled for 220ms");
  nav.dispatchEvent({ type: "pointerenter" });
  assert.equal(timers.pending().length, 0, "a re-enter cancels the pending close");
  assert.equal(bar.isOpen("home"), true);
  nav.dispatchEvent({ type: "pointerleave" });
  timers.fire();
  assert.equal(bar.isOpen("home"), false, "the delayed close runs when the timer fires");
});

test("a fly-out opens to the right, and flips left when its right edge would cross the viewport", async () => {
  const shell = page();
  shell.win.innerWidth = 1000;
  shell.win.innerHeight = 900;
  const bar = createPlatformBar({ doc: shell.doc, win: shell.win, matchMediaImpl: () => ({ matches: true }) });
  bar.init();
  bar.open("bookmarks");
  const cat = bar.node("bookmarks").children.find(c => c.children.length > 0);
  cat.region.getBoundingClientRect = () => ({ left: 400, right: 600, top: 50, bottom: 300 });
  cat.caret.dispatchEvent({ type: "click", detail: 1 });
  assert.equal(cat.region.classList.contains("tsw-bar__flyout--left"), false, "opens right when it fits");
  cat.caret.dispatchEvent({ type: "click", detail: 1 }); // close
  cat.region.getBoundingClientRect = () => ({ left: 900, right: 1200, top: 50, bottom: 300 });
  cat.caret.dispatchEvent({ type: "click", detail: 1 }); // reopen near the edge
  assert.equal(cat.region.classList.contains("tsw-bar__flyout--left"), true, "flips left near the right edge");
});
