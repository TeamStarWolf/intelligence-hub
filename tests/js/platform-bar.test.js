// The platform bar on site/index.html: it renders the cross-site menu from an identical copy of
// platform-nav.json, skips entries still marked "pending", nests one level, and opens from a real
// button with the keyboard and a click-away close. The static top-level links are checked against
// the menu file so the two cannot drift.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ROOT, page } from "./fixtures.js";
import { createPlatformBar } from "../../site/js/platform-bar.js";

const MENU_TEXT = readFileSync(ROOT + "site/platform-nav.json", "utf8");
const MENU = JSON.parse(MENU_TEXT);

function boot() {
  const shell = page();
  const fetchImpl = async () => ({ json: async () => JSON.parse(MENU_TEXT) });
  const bar = createPlatformBar({ doc: shell.doc, win: shell.win, fetchImpl, menuUrl: "platform-nav.json" });
  return { ...shell, bar };
}

const labelsIn = panel => [...panel.querySelectorAll("a")].map(a => a.textContent);
const hrefsIn = root => [...root.querySelectorAll("a")].map(a => a.getAttribute("href"));

test("the static top-level links match the menu file, in order", async () => {
  const { doc } = boot();
  const items = [...doc.querySelectorAll(".tsw-bar__item")];
  assert.deepEqual(items.map(li => li.dataset.tswItem), MENU.items.map(item => item.id));
  for (const li of items) {
    const item = MENU.items.find(entry => entry.id === li.dataset.tswItem);
    const link = li.querySelector(".tsw-bar__link");
    assert.equal(link.getAttribute("href"), item.href, item.id + " href");
    assert.equal(link.textContent, item.label, item.id + " label");
  }
});

test("each item gains a caret and a panel of its non-pending entries; pending entries never reach the markup", async () => {
  const { doc, bar } = boot();
  await bar.init();
  // Every pending address in the whole file must be absent from the rendered bar.
  const pending = [];
  const walk = node => { for (const entry of node.menu || []) { if (entry.pending) pending.push(entry.href); walk(entry); } };
  for (const item of MENU.items) walk(item);
  assert.ok(pending.length >= 2, "the fixture still has pending entries to exclude");
  const barHrefs = hrefsIn(doc.querySelector("[data-tsw-bar]"));
  for (const href of pending) assert.ok(!barHrefs.includes(href), "pending address absent: " + href);

  // Home ships only its two shippable entries, in order.
  const home = bar.record("home");
  assert.equal(home.caret.getAttribute("aria-expanded"), "false");
  assert.equal(home.panel.hidden, true);
  assert.deepEqual(labelsIn(home.panel), ["Front page", "Design system"]);

  // The Hub item carries all ten of its views.
  const hub = MENU.items.find(item => item.id === "hub");
  assert.deepEqual(labelsIn(bar.record("hub").panel), hub.menu.map(entry => entry.label));
});

test("a top-level entry nests one level of sub-entries", async () => {
  const { bar } = boot();
  await bar.init();
  const panel = bar.record("bookmarks").panel;
  const submenu = panel.querySelector(".tsw-bar__submenu");
  assert.ok(submenu, "bookmarks nests sub-entries");
  const sub = [...submenu.querySelectorAll(".tsw-bar__sublink")].map(a => a.textContent);
  assert.ok(sub.includes("Scanners"), "a known sub-entry renders: " + sub.join(", "));
  // No third level: a sublink's list item holds no further submenu.
  assert.equal(submenu.querySelectorAll(".tsw-bar__submenu").length, 0);
});

test("the caret opens and closes the panel and reflects aria-expanded", async () => {
  const { doc, bar } = boot();
  await bar.init();
  const home = bar.record("home");
  home.caret.dispatchEvent({ type: "click", detail: 1 });
  assert.equal(bar.isOpen("home"), true);
  assert.equal(home.panel.hidden, false);
  assert.equal(home.caret.getAttribute("aria-expanded"), "true");
  home.caret.dispatchEvent({ type: "click", detail: 1 });
  assert.equal(bar.isOpen("home"), false);
  assert.equal(home.panel.hidden, true);
  assert.equal(home.caret.getAttribute("aria-expanded"), "false");
});

test("opening one panel closes another", async () => {
  const { bar } = boot();
  await bar.init();
  bar.open("home");
  bar.open("library");
  assert.equal(bar.isOpen("home"), false);
  assert.equal(bar.isOpen("library"), true);
});

test("ArrowDown opens and focuses the first entry; Escape closes and returns focus to the caret", async () => {
  const { doc, bar } = boot();
  await bar.init();
  const home = bar.record("home");
  home.caret.dispatchEvent({ type: "keydown", key: "ArrowDown", preventDefault() {} });
  assert.equal(bar.isOpen("home"), true);
  assert.equal(doc.activeElement, home.focusables[0]);
  home.focusables[0].dispatchEvent({ type: "keydown", key: "Escape", preventDefault() {} });
  assert.equal(bar.isOpen("home"), false);
  assert.equal(doc.activeElement, home.caret);
});

test("a click outside the bar closes an open panel", async () => {
  const { doc, bar } = boot();
  await bar.init();
  bar.open("home");
  doc.dispatchEvent({ type: "click", target: doc.querySelector("#q") });
  assert.equal(bar.isOpen("home"), false);
});

test("a click inside the bar does not close the panel it opened", async () => {
  const { doc, bar } = boot();
  await bar.init();
  bar.open("home");
  doc.dispatchEvent({ type: "click", target: bar.record("home").focusables[0] });
  assert.equal(bar.isOpen("home"), true);
});
