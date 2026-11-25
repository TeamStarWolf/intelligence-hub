// The TeamStarWolf platform bar: the one cross-site menu, shown identically on every site. The menu
// is static markup in index.html (generated from an identical copy of platform-nav.json), so with
// JavaScript off every top-level link and header link still works and the stylesheet opens the menus
// on :hover and :focus-within. This module enhances that markup: it adds the caret buttons, switches
// the stylesheet to open from aria-expanded, times the hover close, flips and clamps a fly-out that
// would leave the viewport, and gives the whole thing keyboard and touch control. It renders no site
// control of its own. createPlatformBar takes every browser object it uses, so tests/js can run it
// with stand-ins; the real page boots it at the end.
//
// The Bookmarks menu nests three levels (category, then subsection, then the links); every other menu
// is one level. The model is the same at every level: a node is a caret button plus the region it
// opens (a top-level item's panel, or a category's or subsection's fly-out), holding links and child
// nodes. Behaviour the reference build settled, held here and in the stylesheet:
//   - A menu opens on hover and from its caret button (aria-expanded); one open path shows at a time.
//   - A category or subsection with children gets a chevron button; its fly-out opens to the right,
//     flips left when the right edge would cross the viewport, and is pulled up near the bottom.
//   - Open is immediate; close waits CLOSE_DELAY so a diagonal move into a fly-out does not shut it.
//   - A coarse pointer (touch) ignores hover and uses the buttons.

const HOVER_POINTER = "(hover: hover) and (pointer: fine)";
const WIDE_SCREEN = "(min-width: 761px)";
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
  const tops = new Map();      // id -> top node
  const topCarets = [];        // the top-level caret buttons, in order, for Left/Right
  const linkOwner = new Map(); // a link -> the node whose list holds it
  const caretNode = new Map(); // a caret button -> the node it opens
  let openTop = null;
  let closeTimer = null;
  let ids = 0;

  const media = matchMediaImpl || (win && typeof win.matchMedia === "function" ? win.matchMedia.bind(win) : null);
  const setTimer = setTimeoutImpl || (win && win.setTimeout ? win.setTimeout.bind(win) : (typeof setTimeout === "function" ? setTimeout : null));
  const clearTimer = clearTimeoutImpl || (win && win.clearTimeout ? win.clearTimeout.bind(win) : (typeof clearTimeout === "function" ? clearTimeout : null));

  function matchesQuery(query, fallback) {
    try { return media ? Boolean(media(query).matches) : fallback; } catch (_) { return fallback; }
  }
  const finePointer = () => matchesQuery(HOVER_POINTER, false);
  const wideScreen = () => matchesQuery(WIDE_SCREEN, true);

  function make(tag, cls) {
    const node = doc.createElement(tag);
    if (cls) node.setAttribute("class", cls);
    return node;
  }

  const childrenWith = (parent, cls) => Array.from(parent.children).filter(child => child.classList && child.classList.contains(cls));
  const childWith = (parent, cls) => childrenWith(parent, cls)[0] || null;

  // Put a button right before a region inside its container. append moves a node, so appending the
  // button and then the region again leaves the order link, button, region (the order the
  // stylesheet's adjacent-sibling rules need).
  function insertBefore(container, button, region) {
    container.append(button);
    container.append(region);
  }

  function caretButton(cls, controls, label) {
    const caret = make("button", cls);
    caret.setAttribute("type", "button");
    caret.setAttribute("aria-haspopup", "true");
    caret.setAttribute("aria-expanded", "false");
    caret.setAttribute("aria-controls", controls || "");
    caret.setAttribute("aria-label", label);
    return caret;
  }

  // Build a node for a region (a panel or a fly-out) and, recursively, a child node for every entry
  // in it that has its own fly-out. A list item's link is kept but given tabindex -1 (the carets are
  // the tab stops); a parent item gets an mdisc chevron inserted before its fly-out.
  function makeNode(spec) {
    const node = { ...spec, links: [], children: [], childByLink: new Map(), openChild: null, expanded: false };
    caretNode.set(spec.caret, node);
    for (const mitem of childrenWith(spec.list, "tsw-bar__mitem")) {
      const link = childWith(mitem, "tsw-bar__mlink");
      if (link) {
        link.setAttribute("tabindex", "-1");
        node.links.push(link);
        linkOwner.set(link, node);
      }
      const flyout = childWith(mitem, "tsw-bar__flyout");
      if (flyout) {
        const fid = flyout.getAttribute("id") || ("tsw-bar-flyout-" + (++ids));
        flyout.setAttribute("id", fid);
        const mdisc = caretButton("tsw-bar__mdisc", fid, ((link && link.textContent) || "") + " submenu");
        insertBefore(mitem, mdisc, flyout);
        const child = makeNode({ owner: mitem, caret: mdisc, region: flyout, list: flyout, parent: node, headerLink: link });
        node.children.push(child);
        if (link) node.childByLink.set(link, child);
      }
    }
    return node;
  }

  function focusFirst(node) { if (node.links[0]) node.links[0].focus(); }
  function focusLast(node) { const last = node.links[node.links.length - 1]; if (last) last.focus(); }

  function focusIn(list, current, delta) {
    if (!list.length) return;
    const index = list.indexOf(current);
    const at = ((index < 0 ? 0 : index + delta) + list.length) % list.length;
    list[at].focus();
  }

  function openNode(node) {
    cancelClose();
    const parent = node.parent;
    if (parent) {
      if (parent.openChild && parent.openChild !== node) closeNode(parent.openChild);
      parent.openChild = node;
    } else {
      if (openTop && openTop !== node) closeNode(openTop);
      openTop = node;
      nav.classList.add("tsw-bar--open");
    }
    node.expanded = true;
    node.caret.setAttribute("aria-expanded", "true");
    place(node);
  }

  function closeNode(node) {
    if (node.openChild) { closeNode(node.openChild); node.openChild = null; }
    node.expanded = false;
    node.caret.setAttribute("aria-expanded", "false");
    if (node.region && node.region.classList) node.region.classList.remove("tsw-bar__flyout--left", "tsw-bar__flyout--up");
    const parent = node.parent;
    if (parent) { if (parent.openChild === node) parent.openChild = null; }
    else { if (openTop === node) openTop = null; if (!openTop) nav.classList.remove("tsw-bar--open"); }
  }

  function toggleNode(node) { if (node.expanded) closeNode(node); else openNode(node); }

  function closeEverything() { cancelClose(); if (openTop) closeNode(openTop); }

  function scheduleClose() {
    if (!setTimer) { closeEverything(); return; }
    cancelClose();
    closeTimer = setTimer(() => { closeTimer = null; closeEverything(); }, CLOSE_DELAY);
  }

  function cancelClose() { if (closeTimer && clearTimer) { clearTimer(closeTimer); closeTimer = null; } }

  // A fly-out opens to the right and below its caret. It flips to the left when its right edge would
  // cross the viewport, and is pulled up when its bottom would (the stylesheet also caps its height so
  // it scrolls inside itself only when the viewport is too short). The top-level panel opens below and
  // is not placed. Each level is measured on its own.
  function place(node) {
    const region = node.region;
    if (!node.parent || !region || typeof region.getBoundingClientRect !== "function") return;
    region.classList.remove("tsw-bar__flyout--left", "tsw-bar__flyout--up", "tsw-bar__flyout--scroll");
    if (!wideScreen()) return;
    try {
      const width = (win && win.innerWidth) || 0;
      const height = (win && win.innerHeight) || 0;
      const rect = region.getBoundingClientRect();
      if (width && rect.right > width - 4) region.classList.add("tsw-bar__flyout--left");
      if (height && typeof rect.height === "number" && rect.height > height - 8) {
        // Taller than the viewport can hold: cap it and let it scroll inside itself.
        region.classList.add("tsw-bar__flyout--scroll");
      } else if (height && typeof rect.bottom === "number" && rect.bottom > height - 4) {
        // Fits, but its bottom would cross the edge: anchor it to its bottom so it grows upward.
        region.classList.add("tsw-bar__flyout--up");
      }
    } catch (_) { /* no layout: leave it opening to the right */ }
  }

  function focusTopCaret(index) {
    if (!topCarets.length) return;
    topCarets[(index + topCarets.length) % topCarets.length].focus();
  }

  function wireCaret(node, top) {
    const caret = node.caret;
    caret.addEventListener("click", event => {
      toggleNode(node);
      if (node.expanded && event && event.detail === 0) focusFirst(node);
    });
    caret.addEventListener("keydown", event => {
      const key = event.key;
      if (key === "ArrowDown") { event.preventDefault?.(); openNode(node); focusFirst(node); }
      else if (key === "ArrowUp") { event.preventDefault?.(); openNode(node); focusLast(node); }
      else if (key === "ArrowRight") {
        if (top) { event.preventDefault?.(); focusTopCaret(node.caretIndex + 1); }
        else { event.preventDefault?.(); openNode(node); focusFirst(node); }
      }
      else if (key === "ArrowLeft") { if (top) { event.preventDefault?.(); focusTopCaret(node.caretIndex - 1); } }
      else if (key === "Escape") { closeNode(node); if (!top && node.headerLink) node.headerLink.focus(); }
    });
  }

  function wireLink(link) {
    link.addEventListener("keydown", event => {
      const key = event.key;
      const owner = linkOwner.get(link);
      if (!owner) return;
      if (key === "ArrowDown") { event.preventDefault?.(); focusIn(owner.links, link, 1); }
      else if (key === "ArrowUp") { event.preventDefault?.(); focusIn(owner.links, link, -1); }
      else if (key === "Home") { event.preventDefault?.(); owner.links[0].focus(); }
      else if (key === "End") { event.preventDefault?.(); owner.links[owner.links.length - 1].focus(); }
      else if (key === "ArrowRight") {
        const child = owner.childByLink.get(link);
        if (child) { event.preventDefault?.(); openNode(child); focusFirst(child); }
      }
      else if (key === "ArrowLeft") {
        if (owner.parent) { event.preventDefault?.(); closeNode(owner); if (owner.headerLink) owner.headerLink.focus(); }
      }
      else if (key === "Escape") { event.preventDefault?.(); closeNode(owner); owner.caret.focus(); }
      else if (key === "Tab") { closeEverything(); }
    });
  }

  function wireHover(node) {
    if (!finePointer()) return;
    node.owner.addEventListener("pointerenter", () => openNode(node));
  }

  // Walk a node tree, wiring every caret, link and hover target.
  function wireTree(node, top) {
    wireCaret(node, top);
    wireHover(node);
    for (const link of node.links) wireLink(link);
    for (const child of node.children) wireTree(child, false);
  }

  function enhanceItem(li) {
    const id = li.dataset.tswItem;
    const link = childWith(li, "tsw-bar__link");
    const panel = childWith(li, "tsw-bar__panel");
    if (!id || !link || !panel) return;
    const controls = panel.getAttribute("id") || ("tsw-bar-panel-" + id);
    const caret = caretButton("tsw-bar__disc", controls, (link.textContent || id) + " menu");
    insertBefore(li, caret, panel);
    const list = childWith(panel, "tsw-bar__flyout");
    if (!list) return;
    const node = makeNode({ owner: li, caret, region: panel, list, parent: null, headerLink: null });
    node.id = id;
    node.caretIndex = topCarets.length;
    tops.set(id, node);
    topCarets.push(caret);
    wireTree(node, true);
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
      if (!openTop) return;
      const target = event.target;
      if (target && typeof target.closest === "function" && target.closest("[data-tsw-bar]")) return;
      closeEverything();
    });
    doc.addEventListener("keydown", event => {
      if (event.key === "Escape" && openTop) { const caret = openTop.caret; closeEverything(); if (caret) caret.focus(); }
    });
    nav.classList.add("tsw-bar--js", "tsw-bar--ready");
  }

  const controller = {
    nav,
    init() { try { enhance(); } catch (_) { /* leave the plain static markup on any failure */ } return controller; },
    open: id => { const node = tops.get(id); if (node) openNode(node); },
    close: id => { const node = tops.get(id); if (node) closeNode(node); },
    toggle: id => { const node = tops.get(id); if (node) toggleNode(node); },
    isOpen: id => Boolean(tops.get(id) && tops.get(id).expanded),
    node: id => tops.get(id) || null,
    openId: () => (openTop ? openTop.id : null),
  };
  return controller;
}

if (typeof document !== "undefined" && typeof window !== "undefined" && document.querySelector && document.querySelector("[data-tsw-bar]")) {
  createPlatformBar({ doc: document, win: window }).init();
}
