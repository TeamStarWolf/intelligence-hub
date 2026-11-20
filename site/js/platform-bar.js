// The TeamStarWolf platform bar: the one cross-site menu, shown identically on every site.
// The top-level links live in index.html so they work with JavaScript off. This module reads an
// identical local copy of the published platform-nav.json, reveals a caret button beside each
// top-level link, builds that item's dropdown panel from the menu file, skips any entry still
// marked "pending", and wires the keyboard and pointer behaviour. It renders no site control of
// its own. createPlatformBar takes every browser object it uses, so tests/js can run it with
// stand-ins; the real page boots it at the bottom of the file.

const MOBILE_QUERY = "(max-width: 759px)";

export function createPlatformBar(env) {
  const {
    doc,
    win = null,
    fetchImpl,
    menuUrl = new URL("../platform-nav.json", import.meta.url).href,
    matchMediaImpl = null,
  } = env;

  const nav = doc.querySelector("[data-tsw-bar]");
  if (!nav) return null;
  const items = [...nav.querySelectorAll(".tsw-bar__item")];
  const records = new Map(); // id -> { li, link, caret, panel, focusables, caretIndex }
  const carets = []; // caret buttons in bar order, for left/right movement
  let openId = null;

  function make(tag, cls, text) {
    const node = doc.createElement(tag);
    if (cls) node.setAttribute("class", cls);
    if (text != null) node.textContent = text;
    return node;
  }

  function isMobile() {
    const mm = matchMediaImpl || (win && typeof win.matchMedia === "function" ? win.matchMedia.bind(win) : null);
    try { return mm ? Boolean(mm(MOBILE_QUERY).matches) : false; } catch (_) { return false; }
  }

  // A link for a menu entry. A sub-entry carries its own one-level menu; deeper menus are ignored.
  function entryNode(entry, linkClass, listClass, subLinkClass) {
    const li = make("li", null);
    const link = make("a", linkClass, entry.label);
    link.setAttribute("href", entry.href);
    link.setAttribute("rel", "noopener noreferrer");
    link.setAttribute("tabindex", "-1");
    li.append(link);
    const focusables = [link];
    if (listClass && Array.isArray(entry.menu)) {
      const subList = make("ul", listClass);
      let shown = 0;
      for (const sub of entry.menu) {
        if (sub.pending) continue;
        const subLi = make("li", null);
        const subLink = make("a", subLinkClass, sub.label);
        subLink.setAttribute("href", sub.href);
        subLink.setAttribute("rel", "noopener noreferrer");
        subLink.setAttribute("tabindex", "-1");
        subLi.append(subLink);
        subList.append(subLi);
        focusables.push(subLink);
        shown++;
      }
      if (shown) li.append(subList);
    }
    return { li, focusables };
  }

  function buildPanel(id, data) {
    const panel = make("div", "tsw-bar__panel");
    panel.setAttribute("id", "tsw-bar-panel-" + id);
    panel.hidden = true;
    const list = make("ul", "tsw-bar__menu");
    list.setAttribute("aria-label", data.label);
    const focusables = [];
    for (const entry of data.menu) {
      if (entry.pending) continue;
      const built = entryNode(entry, "tsw-bar__menulink", "tsw-bar__submenu", "tsw-bar__sublink");
      list.append(built.li);
      for (const node of built.focusables) focusables.push(node);
    }
    panel.append(list);
    return { panel, focusables };
  }

  function focusAt(record, index) {
    const list = record.focusables;
    if (!list.length) return;
    const at = (index + list.length) % list.length;
    list[at].focus();
  }

  function indexInFocusables(record, element) {
    return record.focusables.indexOf(element);
  }

  function openItem(id) {
    if (openId && openId !== id) closeItem(openId);
    const record = records.get(id);
    if (!record) return;
    record.panel.hidden = false;
    record.caret.setAttribute("aria-expanded", "true");
    nav.classList.add("tsw-bar--open");
    openId = id;
  }

  function closeItem(id) {
    const record = records.get(id);
    if (!record) return;
    record.panel.hidden = true;
    record.caret.setAttribute("aria-expanded", "false");
    if (openId === id) openId = null;
    if (!openId) nav.classList.remove("tsw-bar--open");
  }

  function closeAll() { if (openId) closeItem(openId); }

  function toggleItem(id) { if (openId === id) closeItem(id); else openItem(id); }

  function focusCaret(index) {
    if (!carets.length) return;
    const at = (index + carets.length) % carets.length;
    carets[at].focus();
  }

  function wireCaret(id, record) {
    const caret = record.caret;
    // A pointer click toggles the panel. A keyboard activation of a button fires a click whose
    // detail is 0; that case also moves focus into the open panel, as a menu button should.
    caret.addEventListener("click", event => {
      toggleItem(id);
      if (openId === id && event && event.detail === 0) focusAt(record, 0);
    });
    caret.addEventListener("keydown", event => {
      const key = event.key;
      if (key === "ArrowDown") { event.preventDefault?.(); openItem(id); focusAt(record, 0); }
      else if (key === "ArrowUp") { event.preventDefault?.(); openItem(id); focusAt(record, record.focusables.length - 1); }
      else if (key === "Escape") { closeItem(id); }
      else if (key === "ArrowRight") { event.preventDefault?.(); focusCaret(record.caretIndex + 1); }
      else if (key === "ArrowLeft") { event.preventDefault?.(); focusCaret(record.caretIndex - 1); }
    });
  }

  function wirePanel(id, record) {
    for (const element of record.focusables) {
      element.addEventListener("keydown", event => {
        const key = event.key;
        const at = indexInFocusables(record, element);
        if (key === "ArrowDown") { event.preventDefault?.(); focusAt(record, at + 1); }
        else if (key === "ArrowUp") { event.preventDefault?.(); focusAt(record, at - 1); }
        else if (key === "Home") { event.preventDefault?.(); focusAt(record, 0); }
        else if (key === "End") { event.preventDefault?.(); focusAt(record, record.focusables.length - 1); }
        else if (key === "Escape") { event.preventDefault?.(); closeItem(id); record.caret.focus(); }
        else if (key === "Tab") { closeItem(id); }
      });
    }
  }

  function render(menu) {
    const byId = new Map((menu.items || []).map(item => [item.id, item]));
    for (const li of items) {
      const id = li.dataset.tswItem;
      const data = byId.get(id);
      const link = li.querySelector(".tsw-bar__link");
      if (!data || !Array.isArray(data.menu) || !data.menu.length || !link) continue;
      // Does any entry survive the pending filter? If not, the item stays a plain link.
      if (!data.menu.some(entry => !entry.pending)) continue;

      const caret = make("button", "tsw-bar__caret");
      caret.setAttribute("type", "button");
      caret.setAttribute("aria-haspopup", "true");
      caret.setAttribute("aria-expanded", "false");
      caret.setAttribute("aria-controls", "tsw-bar-panel-" + id);
      caret.setAttribute("aria-label", data.label + " menu");

      const built = buildPanel(id, data);
      // The caret sits right after the top-level link; the panel is the item's last child.
      li.append(caret);
      li.append(built.panel);

      const record = { li, link, caret, panel: built.panel, focusables: built.focusables, caretIndex: carets.length };
      records.set(id, record);
      carets.push(caret);
      wireCaret(id, record);
      wirePanel(id, record);
    }

    // Under 760px the bar collapses behind one button that opens the list as an accordion. The
    // button is created here, so a no-JavaScript page keeps the plain row of top-level links.
    const list = nav.querySelector(".tsw-bar__list");
    if (list) {
      list.setAttribute("id", "tsw-bar-list");
      const toggle = make("button", "tsw-bar__toggle", "Menu");
      toggle.setAttribute("type", "button");
      toggle.setAttribute("aria-expanded", "false");
      toggle.setAttribute("aria-controls", "tsw-bar-list");
      toggle.setAttribute("aria-label", "Platform menu");
      toggle.addEventListener("click", () => {
        const open = toggle.getAttribute("aria-expanded") === "true";
        toggle.setAttribute("aria-expanded", String(!open));
        nav.classList.toggle("tsw-bar--list-open", !open);
        if (open) closeAll();
      });
      nav.prepend(toggle);
    }

    // A click outside the bar, or Escape, closes any open panel. In a real browser the inner
    // clicks bubble here; the guard keeps a click on the bar from closing what it just opened.
    doc.addEventListener("click", event => {
      if (!openId) return;
      const target = event.target;
      if (target && typeof target.closest === "function" && target.closest("[data-tsw-bar]")) return;
      closeAll();
    });
    doc.addEventListener("keydown", event => {
      if (event.key === "Escape" && openId) { const record = records.get(openId); closeAll(); if (record) record.caret.focus(); }
    });
    nav.classList.add("tsw-bar--ready");
    if (isMobile()) nav.classList.add("tsw-bar--mobile");
  }

  const controller = {
    nav,
    async init() {
      let menu;
      try {
        const response = await fetchImpl(menuUrl);
        menu = typeof response.json === "function" ? await response.json() : response;
      } catch (_) {
        // The static top-level links already work; without the menu file the bar stays that row.
        return controller;
      }
      try { render(menu); } catch (_) { /* a malformed menu leaves the plain top-level row */ }
      return controller;
    },
    open: openItem,
    close: closeItem,
    closeAll,
    toggle: toggleItem,
    isOpen: id => openId === id,
    openId: () => openId,
    record: id => records.get(id) || null,
  };
  return controller;
}

if (typeof document !== "undefined" && typeof window !== "undefined" && document.querySelector && document.querySelector("[data-tsw-bar]")) {
  createPlatformBar({ doc: document, win: window, fetchImpl: window.fetch.bind(window) }).init();
}
