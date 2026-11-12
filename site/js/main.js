// The page shell: routing, view dispatch, dialogs, the sidebar and the index poll.
// createApp takes every browser object it uses, so tests/js can run it with stand-ins.
import { LIST_VIEWS, VIEW_DESK, formatRoute, parseRoute, withQuery } from "./router.js";
import { createFetcher } from "./fetcher.js";
import { createStore } from "./store.js";
import { layoutSkew, reloadOnce, runningRevision } from "./guard.js";
import { initTheme } from "./theme.js";
import { pollInterval } from "./limits.js";
import { node } from "./util.js";
import { loadLibrary, setLabels } from "./views/common.js";
import { bindExplore, recordDetail, renderExplore } from "./views/explore.js";
import { renderToday } from "./views/today.js";
import { renderKev } from "./views/kev.js";
import { briefBody, renderCves } from "./views/cves.js";
import { renderAbout, renderData, renderReports, renderSidebar, renderSources, renderSubscribe } from "./views/panels.js";
import { renderHistory } from "./views/history.js";
import { renderVendor, renderVendors } from "./views/vendors.js";
import { renderTags } from "./views/tags.js";
import { renderActors, renderEntity } from "./views/actors.js";
import { renderMethod } from "./views/method.js";
import { renderPatchTuesday } from "./views/patch-tuesday.js";
import { createLiveBoard, renderStatus } from "./views/status.js";

const TITLES = { explore: "Explorer", today: "Today", advisories: "Advisories", kev: "Known exploited", research: "Research", news: "News", cves: "CVE register", cve: "CVE",
  history: "History", vendors: "Vendors", vendor: "Vendor", tags: "Tags", actors: "Actors and malware", actor: "Actor", malware: "Malware", reports: "Reports", sources: "Sources", method: "Method", data: "Data", about: "About", "patch-tuesday": "Patch Tuesday", status: "Service health",
  subscribe: "Subscribe" };
const OTHER_VIEWS = { today: renderToday, kev: renderKev, cves: renderCves, cve: renderCves, history: renderHistory, vendors: renderVendors, vendor: renderVendor, tags: renderTags,
  actors: renderActors, actor: renderEntity, malware: renderEntity, reports: renderReports, sources: renderSources, method: renderMethod, data: renderData, about: renderAbout,
  "patch-tuesday": renderPatchTuesday, status: renderStatus, subscribe: renderSubscribe };
// The tab a view sits under: a page with an id lights its index tab.
const TAB_OF = { cve: "cves", vendor: "vendors", actor: "actors", malware: "actors" };

export function createApp(env) {
  const { doc, win, location, history, storage = null, session = null, fetchImpl, subtle, moduleUrl = null, now = () => Date.now(), every = (fn, ms) => setInterval(fn, ms), clear = id => clearInterval(id), loadLabels = () => import("./labels.js") } = env;
  const el = selector => doc.querySelector(selector);
  const fetcher = createFetcher({ fetchImpl, subtle });
  const store = createStore(fetcher);
  const running = runningRevision(moduleUrl);
  // The Service health view's live board: it reads the listed vendor status pages from this
  // browser only while that view is open and the tab is visible, and stops when the view closes.
  const live = createLiveBoard({ fetchImpl, every, clear, now, doc });
  const stats = { renders: 0, polls: 0, skippedHidden: 0, reloads: 0 };
  let route = parseRoute(location.hash, location.search);
  if (route.rewrite) history.replaceState(null, "", location.pathname + formatRoute(route));
  let token = 0;
  let sidebarToken = 0;
  let lastPoll = 0;
  let pollTimer = null;
  let fatal = false;
  // Today's since-last-visit baseline (views/today.js): what this browser had seen before this
  // page session, read from storage once and compared on every render of Today.
  const visit = { today: null };

  // The notice is a toast fixed to the bottom of the viewport (styles.css .toast), so a reader
  // sees it wherever the results are scrolled; Dismiss hides it until the next notice.
  function showNotice(message) { const notice = el("#notice"); notice.hidden = !message; el("#notice-text").textContent = message || ""; }

  // replace: a filter change (no new history entry). Otherwise a new entry Back can leave.
  function navigate(next, { replace = false } = {}) {
    const hash = formatRoute(next);
    if (replace) history.replaceState(history.state, "", location.pathname + hash);
    else history.pushState({ hub: true }, "", location.pathname + hash);
    route = parseRoute(hash, "");
    render();
  }

  function onHashChange() {
    const parsed = parseRoute(location.hash, "");
    if (parsed.rewrite) history.replaceState(history.state, "", location.pathname + formatRoute(parsed));
    route = parsed;
    render();
  }

  // On a narrow window the tab strip scrolls sideways inside itself. When the active tab
  // changes it is brought into the strip's view, sideways only, so the page never jumps.
  let revealedTab = null;
  function revealTab(tab) {
    try {
      const strip = tab.parentNode;
      const box = tab.getBoundingClientRect();
      const frame = strip.getBoundingClientRect();
      const pad = 16;
      if (box.left < frame.left + pad) strip.scrollLeft -= frame.left + pad - box.left;
      else if (box.right > frame.right - pad) strip.scrollLeft += box.right - (frame.right - pad);
    } catch (_) { /* a strip without layout stays where it is */ }
  }

  // The two tab rows: the desks, then the active desk's views. Every view link stays in the
  // DOM; the ones on other desks are hidden, and a desk with one view hides the second row.
  function updateTabs() {
    const active = TAB_OF[route.view] || route.view;
    const desk = VIEW_DESK[route.view] || "explore";
    let activeTab = null;
    for (const tab of doc.querySelectorAll(".tabs .desks a")) {
      if (tab.dataset.desk === desk) tab.setAttribute("aria-current", "location"); else tab.removeAttribute("aria-current");
    }
    let shown = 0;
    for (const tab of doc.querySelectorAll(".tabs .views a")) {
      tab.hidden = tab.dataset.desk !== desk;
      if (!tab.hidden) shown++;
      if (tab.dataset.view === active) { tab.setAttribute("aria-current", "page"); activeTab = tab; } else tab.removeAttribute("aria-current");
    }
    const row = el(".tabs .views");
    if (row) row.hidden = shown < 2;
    if (activeTab && activeTab !== revealedTab) { revealedTab = activeTab; revealTab(activeTab); }
    // Wall mode (?wall=1 on Today and Service health): a data attribute the stylesheet reads.
    const html = doc.documentElement;
    if (html) { if (route.query.wall === "1") html.setAttribute("data-wall", "1"); else html.removeAttribute("data-wall"); }
    doc.title = (TITLES[route.view] || "Explorer") + " · Intelligence Hub · TeamStarWolf";
  }

  // A reader closing a dialog leaves its record: Back when this page opened it, otherwise a
  // replace. A dialog the page closed itself (the route no longer names it) changes nothing.
  function leaveRecord(kind) {
    const named = kind === "cve" ? route.view === "cve" : Boolean(route.query.open) && Object.hasOwn(LIST_VIEWS, route.view);
    if (!named) return;
    if (history.state && history.state.hub) { history.back(); return; }
    navigate(kind === "cve" ? { view: "cves", id: null, query: route.query } : withQuery(route, { open: null }, true), { replace: true });
  }

  function openDialog(dialog) { if (!dialog.open) { try { dialog.showModal(); } catch (_) { dialog.setAttribute("open", ""); } } }
  function closeDialog(dialog) { if (dialog.open) dialog.close(); }

  async function syncRecord(current, rows, cveIndex) {
    const dialog = el("#record-dialog");
    if (!route.query.open || !Object.hasOwn(LIST_VIEWS, route.view)) { closeDialog(dialog); return; }
    const row = rows.find(item => item.id === route.query.open);
    const lib = row ? await loadLibrary() : null;
    if (!current()) return;
    el("#record-title").textContent = row ? "Entry details" : "Entry not loaded";
    el("#record-body").replaceChildren(...(row ? recordDetail(row, route, cveIndex, lib) : [node("p", "", "This entry is not in the data loaded for this view. Clear the filters or choose its year, then open it again.")]));
    openDialog(dialog);
  }

  async function syncCve(current) {
    const dialog = el("#cve-dialog");
    if (route.view !== "cve") { closeDialog(dialog); return; }
    const cve = route.id;
    const shown = store.state.mode === "v7" ? store.state.index.feed_content_revision : "legacy";
    if (dialog.open && dialog.dataset.cve === cve && dialog.dataset.revision === shown) return;
    dialog.dataset.cve = cve; dialog.dataset.revision = "";
    el("#cve-title").textContent = cve;
    el("#cve-body").replaceChildren(node("p", "muted", "Reading the saved brief. No lookup leaves this site."));
    openDialog(dialog);
    try {
      const [record, index, lib] = await Promise.all([store.brief(cve), store.cveIndex(), loadLibrary()]);
      if (!current()) return;
      // The entries already read (live months, and Today's recent.json) that name this CVE.
      const loadedRows = store.state.mode === "legacy" ? store.rows([]) : store.rows(store.listed("live/").filter(path => store.cached(path)));
      const seen = new Set(loadedRows.map(row => row.id));
      for (const row of store.state.mode === "v7" ? store.cached("recent.json")?.rows || [] : []) if (!seen.has(row.id)) { seen.add(row.id); loadedRows.push(row); }
      el("#cve-body").replaceChildren(...(record ? briefBody(record, index.get(cve), loadedRows, lib) : [node("p", "", "This CVE has no saved brief in this snapshot. No external lookup was made.")]));
      dialog.dataset.revision = shown;
    } catch (error) {
      if (!current()) return;
      el("#cve-body").replaceChildren(node("p", "notice-inline", error.message + " No external lookup was made."));
      if (error.briefMismatch) poll(true);
    }
  }

  async function render() {
    const mine = ++token;
    const current = () => mine === token;
    stats.renders++;
    updateTabs();
    const list = Object.hasOwn(LIST_VIEWS, route.view);
    el("#explore").hidden = !list;
    el("#view").hidden = list;
    if (route.view !== "status") live.stop();
    if (!store.state.mode || fatal) return;
    const ctx = { route, store, el, doc, navigate, current, target: el("#view"), live, storage, visit };
    try {
      if (list) {
        const { rows, cveIndex } = await renderExplore(ctx);
        if (current()) await syncRecord(current, rows, cveIndex);
      } else {
        closeDialog(el("#record-dialog"));
        await OTHER_VIEWS[route.view](ctx);
      }
      if (current()) await syncCve(current);
    } catch (error) {
      if (!current()) return;
      if (error.format && reloadOnce({ storage: session, location, reason: "format" })) { stats.reloads++; return; }
      showNotice(error.message + " The data already on screen stays as it was.");
    }
  }

  function narrow() { try { return Boolean(win.matchMedia && win.matchMedia("(max-width: 1023px)").matches); } catch (_) { return false; } }
  function sidebarOpen() { return !el("#sidebar").hidden; }
  function setSidebar(open) {
    const sidebar = el("#sidebar");
    sidebar.hidden = !open;
    el("#layout").classList.toggle("sidebar-open", open);
    el("#sidebar-toggle").setAttribute("aria-expanded", String(open));
    if (!open) return;
    const mine = ++sidebarToken;
    if (store.state.mode) renderSidebar({ target: el("#sidebar-body"), store, current: () => mine === sidebarToken && sidebarOpen() }).catch(error => { el("#sidebar-body").replaceChildren(node("p", "notice-inline", error.message)); });
    else el("#sidebar-body").replaceChildren(node("p", "muted", "The panels fill in once the index has loaded."));
    el("#sidebar-close").focus();
  }

  function applySkew() {
    if (!layoutSkew(store.state.index, running)) return false;
    if (reloadOnce({ storage: session, location, reason: "layout" })) { stats.reloads++; return true; }
    showNotice("A newer version of this page is published. Reload the page when convenient to use it.");
    return false;
  }

  // Asks whether index.json changed. Nothing is read while the tab is hidden; a 304 reads no body.
  async function poll(force = false) {
    if (doc.hidden && !force) { stats.skippedHidden++; return null; }
    stats.polls++;
    lastPoll = now();
    try {
      const result = await store.loadIndex();
      if (result.status === "loaded") { if (applySkew()) return result; showNotice(""); render(); if (sidebarOpen()) setSidebar(true); }
      return result;
    } catch (error) {
      if (error.format && reloadOnce({ storage: session, location, reason: "format" })) { stats.reloads++; return null; }
      showNotice("The latest index could not be read: " + error.message + " The data on screen stays as it was.");
      return null;
    }
  }

  function bind() {
    win.addEventListener("hashchange", onHashChange);
    doc.addEventListener("click", event => {
      const anchor = event.target && event.target.closest ? event.target.closest("a[href^='#/']") : null;
      if (anchor && !event.defaultPrevented && event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) {
        event.preventDefault();
        const next = parseRoute(anchor.getAttribute("href"), "");
        const sameView = next.view === route.view && next.id === route.id;
        navigate(next, { replace: false });
        if (!sameView && narrow()) setSidebar(false);
      }
    });
    const skip = el("[data-skip]");
    if (skip) skip.addEventListener("click", event => { event.preventDefault(); (Object.hasOwn(LIST_VIEWS, route.view) ? el("#q") : el("#main")).focus(); });
    bindExplore({ el, navigate, route: () => route });
    for (const [dialog, button, kind] of [["#record-dialog", "#record-close", "record"], ["#cve-dialog", "#cve-close", "cve"]]) {
      el(button).addEventListener("click", () => closeDialog(el(dialog)));
      el(dialog).addEventListener("close", () => leaveRecord(kind));
    }
    el("#notice-close").addEventListener("click", () => showNotice(""));
    el("#sidebar-toggle").addEventListener("click", () => setSidebar(!sidebarOpen()));
    el("#sidebar-close").addEventListener("click", () => { setSidebar(false); el("#sidebar-toggle").focus(); });
    doc.addEventListener("keydown", event => { if (event.key === "Escape" && sidebarOpen() && !el("#record-dialog").open && !el("#cve-dialog").open) { setSidebar(false); el("#sidebar-toggle").focus(); } });
    doc.addEventListener("visibilitychange", () => { if (!doc.hidden && now() - lastPoll >= pollInterval) poll(); });
    pollTimer = every(() => { if (now() - lastPoll >= pollInterval - 1000) poll(); }, pollInterval);
  }

  async function start() {
    initTheme({ doc, win, storage, button: el("#theme-toggle") });
    bind();
    updateTabs();
    lastPoll = now();
    try {
      await store.loadIndex();
      if (store.state.mode === "v7" && applySkew()) return app;
    } catch (error) {
      if (error.format && reloadOnce({ storage: session, location, reason: "format" })) { stats.reloads++; return app; }
      fatal = true;
      showNotice(error.message + " No data is displayed. Reload the page later.");
      el("#results-status").textContent = "No data loaded.";
      return app;
    }
    loadLabels().then(module => { setLabels(module.default); render(); }, () => {});
    await render();
    return app;
  }

  const app = { start, poll, render, navigate, store, fetcher, stats, live, route: () => route, stop: () => { clearInterval(pollTimer); live.stop(); } };
  return app;
}

function storageOf(name) { try { return window[name]; } catch (_) { return null; } }

if (typeof document !== "undefined" && document.documentElement && document.documentElement.hasAttribute("data-hub-shell")) {
  createApp({ doc: document, win: window, location: window.location, history: window.history, storage: storageOf("localStorage"), session: storageOf("sessionStorage"),
    fetchImpl: window.fetch.bind(window), subtle: window.crypto && window.crypto.subtle, moduleUrl: import.meta.url }).start();
}
