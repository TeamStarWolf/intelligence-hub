// The TeamStarWolf platform bar: the one cross-site menu, shown identically on every site. The menu
// is static markup in index.html (generated from an identical copy of platform-nav.json), so with
// JavaScript off every top-level link and category link still works and the stylesheet opens the
// menus on :hover and :focus-within. This module enhances that markup: it adds the caret buttons,
// switches the stylesheet to open from aria-expanded, times the hover close, flips a fly-out that
// would leave the viewport, and gives the whole thing keyboard and touch control. It renders no
// site control of its own. createPlatformBar takes every browser object it uses, so tests/js can
// run it with stand-ins; the real page boots it at the end.
//
// Behaviour the reference build settled, held here and in the stylesheet:
//   - A menu opens on hover and from its button (aria-expanded); only one is open at a time.
//   - A category with sub-entries gets a chevron button; its fly-out opens to the right, or to the
//     left when the right edge would cross the viewport.
//   - Open is immediate; close waits CLOSE_DELAY so a diagonal move into a fly-out does not shut it.
//   - A coarse pointer (touch) ignores hover and uses the buttons.

const HOVER_POINTER = "(hover: hover) and (pointer: fine)";
const CLOSE_DELAY = 220;

export function createPlatformBar(env) {
  const {
    doc,
    win = null,
    matchMediaImpl = null,
    setTimeoutImpl = null,
    clearTimeoutImpl = null,
  } = env;

  const nav = doc.querySelector("[data-tsw-bar]");
  if (!nav) return null;
  const records = new Map(); // id -> { li, link, caret, panel, entries, caretIndex }
  const carets = [];
  let openId = null;
  let closeTimer = null;

  const media = matchMediaImpl || (win && typeof win.matchMedia === "function" ? win.matchMedia.bind(win) : null);
  const setTimer = setTimeoutImpl || (win && win.setTimeout ? win.setTimeout.bind(win) : (typeof setTimeout === "function" ? setTimeout : null));
  const clearTimer = clearTimeoutImpl || (win && win.clearTimeout ? win.clearTimeout.bind(win) : (typeof clearTimeout === "function" ? clearTimeout : null));

  function finePointer() {
    try { return media ? Boolean(media(HOVER_POINTER).matches) : false; } catch (_) { return false; }
  }

  function make(tag, cls) {
    const node = doc.createElement(tag);
    if (cls) node.setAttribute("class", cls);
    return node;
  }

  // Put a button right before a panel inside its list item. append moves a node, so appending the
  // button and then the panel again leaves the order link, button, panel (the order the stylesheet's
  // adjacent-sibling rules need).
  function insertBefore(parent, button, panel) {
    parent.append(button);
    parent.append(panel);
  }

  function focusIn(list, current, delta) {
    if (!list.length) return;
    const index = list.indexOf(current);
    const at = ((index < 0 ? 0 : index + delta) + list.length) % list.length;
    list[at].focus();
  }

  function openPanel(id) {
    cancelClose();
    if (openId && openId !== id) closePanel(openId);
    const record = records.get(id);
    if (!record) return;
    record.caret.setAttribute("aria-expanded", "true");
    nav.classList.add("tsw-bar--open");
    openId = id;
  }

  function closePanel(id) {
    const record = records.get(id);
    if (!record) return;
    for (const entry of record.entries) closeFlyout(entry);
    record.caret.setAttribute("aria-expanded", "false");
    if (openId === id) openId = null;
    if (!openId) nav.classList.remove("tsw-bar--open");
  }

  function togglePanel(id) { if (openId === id) closePanel(id); else openPanel(id); }

  function closeEverything() { cancelClose(); if (openId) closePanel(openId); }

  function scheduleClose() {
    if (!setTimer) { closeEverything(); return; }
    cancelClose();
    closeTimer = setTimer(() => { closeTimer = null; closeEverything(); }, CLOSE_DELAY);
  }

  function cancelClose() { if (closeTimer && clearTimer) { clearTimer(closeTimer); closeTimer = null; } }

  function openFlyout(record, entry) {
    if (!entry.subcaret) return;
    for (const other of record.entries) if (other !== entry) closeFlyout(other);
    entry.subcaret.setAttribute("aria-expanded", "true");
    placeFlyout(entry);
  }

  function closeFlyout(entry) {
    if (!entry.subcaret) return;
    entry.subcaret.setAttribute("aria-expanded", "false");
    if (entry.submenu) entry.submenu.classList.remove("tsw-bar__submenu--flip");
  }

  function toggleFlyout(record, entry) {
    if (!entry.subcaret) return;
    if (entry.subcaret.getAttribute("aria-expanded") === "true") closeFlyout(entry);
    else openFlyout(record, entry);
  }

  // A fly-out opens to the right; if its right edge would cross the viewport it flips to the left.
  function placeFlyout(entry) {
    if (!entry.submenu || typeof entry.submenu.getBoundingClientRect !== "function") return;
    entry.submenu.classList.remove("tsw-bar__submenu--flip");
    try {
      const width = (win && win.innerWidth) || 0;
      const rect = entry.submenu.getBoundingClientRect();
      if (width && rect.right > width - 4) entry.submenu.classList.add("tsw-bar__submenu--flip");
    } catch (_) { /* no layout: leave it opening to the right */ }
  }

  function focusCaret(index) {
    if (!carets.length) return;
    carets[(index + carets.length) % carets.length].focus();
  }

  function wireCaret(id, record) {
    const caret = record.caret;
    const firstLink = () => record.entries[0] && record.entries[0].link;
    caret.addEventListener("click", event => {
      togglePanel(id);
      if (openId === id && event && event.detail === 0) { const link = firstLink(); if (link) link.focus(); }
    });
    caret.addEventListener("keydown", event => {
      const key = event.key;
      if (key === "ArrowDown") { event.preventDefault?.(); openPanel(id); const link = firstLink(); if (link) link.focus(); }
      else if (key === "ArrowUp") { event.preventDefault?.(); openPanel(id); const last = record.entries[record.entries.length - 1]; if (last) last.link.focus(); }
      else if (key === "Escape") { closePanel(id); }
      else if (key === "ArrowRight") { event.preventDefault?.(); focusCaret(record.caretIndex + 1); }
      else if (key === "ArrowLeft") { event.preventDefault?.(); focusCaret(record.caretIndex - 1); }
    });
  }

  function wirePanel(id, record) {
    const links = record.entries.map(entry => entry.link);
    for (const entry of record.entries) {
      entry.link.addEventListener("keydown", event => {
        const key = event.key;
        if (key === "ArrowDown") { event.preventDefault?.(); focusIn(links, entry.link, 1); }
        else if (key === "ArrowUp") { event.preventDefault?.(); focusIn(links, entry.link, -1); }
        else if (key === "Home") { event.preventDefault?.(); links[0].focus(); }
        else if (key === "End") { event.preventDefault?.(); links[links.length - 1].focus(); }
        else if (key === "ArrowRight" && entry.subLinks.length) { event.preventDefault?.(); openFlyout(record, entry); entry.subLinks[0].focus(); }
        else if (key === "Escape") { event.preventDefault?.(); closePanel(id); record.caret.focus(); }
        else if (key === "Tab") { closePanel(id); }
      });
      if (entry.subcaret) {
        entry.subcaret.addEventListener("click", event => {
          toggleFlyout(record, entry);
          if (entry.subcaret.getAttribute("aria-expanded") === "true" && event && event.detail === 0) entry.subLinks[0].focus();
        });
      }
      for (const sub of entry.subLinks) {
        sub.addEventListener("keydown", event => {
          const key = event.key;
          if (key === "ArrowDown") { event.preventDefault?.(); focusIn(entry.subLinks, sub, 1); }
          else if (key === "ArrowUp") { event.preventDefault?.(); focusIn(entry.subLinks, sub, -1); }
          else if (key === "Home") { event.preventDefault?.(); entry.subLinks[0].focus(); }
          else if (key === "End") { event.preventDefault?.(); entry.subLinks[entry.subLinks.length - 1].focus(); }
          else if (key === "ArrowLeft" || key === "Escape") { event.preventDefault?.(); closeFlyout(entry); entry.link.focus(); }
          else if (key === "Tab") { closePanel(id); }
        });
      }
    }
  }

  function wireHover(id, record) {
    if (!finePointer()) return;
    record.li.addEventListener("pointerenter", () => openPanel(id));
    for (const entry of record.entries) {
      if (!entry.subcaret) continue;
      entry.menuitem.addEventListener("pointerenter", () => { if (openId === id) openFlyout(record, entry); });
    }
  }

  // Read one top-level item's static markup and add its caret and its categories' chevrons.
  function enhanceItem(li) {
    const id = li.dataset.tswItem;
    const link = li.querySelector(".tsw-bar__link");
    const panel = li.querySelector(".tsw-bar__panel");
    if (!id || !link || !panel) return;

    const caret = make("button", "tsw-bar__caret");
    caret.setAttribute("type", "button");
    caret.setAttribute("aria-haspopup", "true");
    caret.setAttribute("aria-expanded", "false");
    caret.setAttribute("aria-controls", panel.getAttribute("id") || ("tsw-bar-panel-" + id));
    caret.setAttribute("aria-label", (link.textContent || id) + " menu");
    insertBefore(li, caret, panel);

    const entries = [];
    for (const menuitem of panel.querySelectorAll(".tsw-bar__menuitem")) {
      const menulink = menuitem.querySelector(".tsw-bar__menulink");
      if (!menulink) continue;
      menulink.setAttribute("tabindex", "-1");
      const submenu = menuitem.querySelector(".tsw-bar__submenu");
      const entry = { menuitem, link: menulink, subcaret: null, submenu: submenu || null, subLinks: [] };
      if (submenu) {
        const subcaret = make("button", "tsw-bar__subcaret");
        subcaret.setAttribute("type", "button");
        subcaret.setAttribute("aria-haspopup", "true");
        subcaret.setAttribute("aria-expanded", "false");
        subcaret.setAttribute("aria-controls", submenu.getAttribute("id") || "");
        subcaret.setAttribute("aria-label", (menulink.textContent || "") + " submenu");
        insertBefore(menuitem, subcaret, submenu);
        entry.subcaret = subcaret;
        for (const subLink of submenu.querySelectorAll(".tsw-bar__sublink")) {
          subLink.setAttribute("tabindex", "-1");
          entry.subLinks.push(subLink);
        }
      }
      entries.push(entry);
    }

    const record = { li, link, caret, panel, entries, caretIndex: carets.length };
    records.set(id, record);
    carets.push(caret);
    wireCaret(id, record);
    wirePanel(id, record);
    wireHover(id, record);
  }

  function enhance() {
    for (const li of nav.querySelectorAll(".tsw-bar__item")) enhanceItem(li);

    const list = nav.querySelector(".tsw-bar__list");
    if (list) {
      const toggle = make("button", "tsw-bar__toggle");
      toggle.textContent = "Menu";
      toggle.setAttribute("type", "button");
      toggle.setAttribute("aria-expanded", "false");
      toggle.setAttribute("aria-controls", list.getAttribute("id") || "");
      toggle.setAttribute("aria-label", "Platform menu");
      toggle.addEventListener("click", () => {
        const open = toggle.getAttribute("aria-expanded") === "true";
        toggle.setAttribute("aria-expanded", String(!open));
        nav.classList.toggle("tsw-bar--list-open", !open);
        if (open) closeEverything();
      });
      nav.prepend(toggle);
    }

    if (finePointer()) {
      nav.addEventListener("pointerleave", scheduleClose);
      nav.addEventListener("pointerenter", cancelClose);
    }
    doc.addEventListener("click", event => {
      if (!openId) return;
      const target = event.target;
      if (target && typeof target.closest === "function" && target.closest("[data-tsw-bar]")) return;
      closeEverything();
    });
    doc.addEventListener("keydown", event => {
      if (event.key === "Escape" && openId) { const record = records.get(openId); closeEverything(); if (record) record.caret.focus(); }
    });
    nav.classList.add("tsw-bar--js", "tsw-bar--ready");
  }

  const controller = {
    nav,
    init() { try { enhance(); } catch (_) { /* leave the plain static markup on any failure */ } return controller; },
    open: openPanel,
    close: closePanel,
    toggle: togglePanel,
    isOpen: id => openId === id,
    isFlyoutOpen: (id, index) => {
      const record = records.get(id);
      const entry = record && record.entries[index];
      return Boolean(entry && entry.subcaret && entry.subcaret.getAttribute("aria-expanded") === "true");
    },
    openId: () => openId,
    record: id => records.get(id) || null,
  };
  return controller;
}

if (typeof document !== "undefined" && typeof window !== "undefined" && document.querySelector && document.querySelector("[data-tsw-bar]")) {
  createPlatformBar({ doc: document, win: window }).init();
}
