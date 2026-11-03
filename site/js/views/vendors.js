// Vendors (#/vendors and #/vendor/<id>). Counts come from the entries loaded for the live window
// and from CISA's KEV ledger, matched by the vocabulary's exact KEV vendorProject spellings.
// Each vendor links to its TeamStarWolf library pages where the vocabulary names one.
import { formatRoute } from "../router.js";
import { facets, sortRows } from "../filters.js";
import { count, dateLabel, node, routeLink } from "../util.js";
import { pageSize } from "../limits.js";
import { label, libraryDoor, loadLibrary, pager, resultCard, section } from "./common.js";

const LIVE = { view: "explore", id: null, query: {} };

// The vendor ids and product ids whose KEV spellings stand for this vendor.
export function kevSpellings(lib, vendorId) {
  const spellings = new Set(lib.KEV[vendorId] || []);
  for (const product of lib.PRODUCTS[vendorId] || []) for (const name of lib.KEV[product] || []) spellings.add(name);
  return spellings;
}

export function kevByVendor(lib, kevRows) {
  const owner = new Map();
  for (const [id, names] of Object.entries(lib.KEV)) {
    const vendor = id.startsWith("product:") ? Object.keys(lib.PRODUCTS).find(key => lib.PRODUCTS[key].includes(id)) || null : id;
    if (vendor) for (const name of names) owner.set(name, vendor);
  }
  const counts = new Map();
  for (const row of kevRows) { const vendor = owner.get(row.vendor); if (vendor) counts.set(vendor, (counts.get(vendor) || 0) + 1); }
  return counts;
}

async function readScope(ctx, status, what) {
  const { store } = ctx;
  const paths = store.articlePaths(LIVE);
  const kevPaths = store.kevPaths({ view: "kev", id: null, query: { range: "all" } });
  if (!store.loaded([...paths, ...kevPaths])) status.textContent = "Reading " + count(paths.length + kevPaths.length, "file") + " for " + what + ".";
  const [lib] = await Promise.all([loadLibrary(), store.ensure(paths, () => { if (ctx.current()) status.textContent = "Still reading the live window."; }), store.ensure(kevPaths)]);
  return { lib, rows: store.rows(paths), kevRows: store.kevRows(kevPaths) };
}

function libraryList(lib, vendorId) {
  const doors = [];
  const own = libraryDoor(lib, vendorId, label(vendorId));
  if (own) doors.push(own);
  for (const product of lib.PRODUCTS[vendorId] || []) { const door = libraryDoor(lib, product, label(product)); if (door) doors.push(door); }
  return doors;
}

export async function renderVendors(ctx) {
  const { target } = ctx;
  const status = node("p", "results-status", "Reading the live window and the KEV ledger.");
  status.setAttribute("role", "status");
  target.replaceChildren(node("h1", "view-title", "Vendors"),
    node("p", "view-intro", "Every vendor with at least one entry in the live window or in CISA's KEV catalog, with a link to its TeamStarWolf library page where the library has one."), status);
  const { lib, rows, kevRows } = await readScope(ctx, status, "the vendor index");
  if (!ctx.current()) return;
  const entries = facets(rows).vendor;
  const kev = kevByVendor(lib, kevRows);
  const ids = new Set([...[...entries.keys()].map(id => "vendor:" + id), ...kev.keys()]);
  const vendors = [...ids].map(id => ({ id, slug: id.slice("vendor:".length), entries: entries.get(id.slice("vendor:".length))?.count || 0, kev: kev.get(id) || 0 }))
    .filter(item => item.entries + item.kev > 0)
    .sort((a, b) => b.entries + b.kev - (a.entries + a.kev) || label(a.id).localeCompare(label(b.id)));
  const table = node("table", "data-table");
  table.append(node("caption", "", "Entries are tagged rows in the live window; KEV entries are CISA catalog entries whose vendorProject is one of the vendor's recorded spellings, in every year of the ledger."));
  const head = node("tr");
  for (const text of ["Vendor", "Entries", "KEV entries", "Library"]) { const cell = node("th", "", text); cell.scope = "col"; head.append(cell); }
  const thead = node("thead"); thead.append(head);
  const body = node("tbody");
  for (const item of vendors) {
    const tr = node("tr");
    const name = node("th"); name.scope = "row"; name.append(routeLink(label(item.id), formatRoute({ view: "vendor", id: item.slug, query: {} })));
    const doors = node("td");
    libraryList(lib, item.id).forEach((door, position) => { if (position) doors.append(node("span", "", ", ")); doors.append(door); });
    if (!doors.childNodes.length) doors.append(node("span", "muted", "No library page yet"));
    tr.append(name, node("td", "", item.entries.toLocaleString("en-US")), node("td", "", item.kev.toLocaleString("en-US")), doors);
    body.append(tr);
  }
  table.append(thead, body);
  const wrap = node("div", "table-wrap"); wrap.append(table);
  status.textContent = count(vendors.length, "vendor") + " with entries. Vendors with none in this snapshot are not listed.";
  target.append(wrap);
  return vendors;
}

export async function renderVendor(ctx) {
  const { target, route } = ctx;
  const vendorId = "vendor:" + route.id;
  const status = node("p", "results-status", "Reading the live window and the KEV ledger.");
  status.setAttribute("role", "status");
  const back = node("p", "more"); back.append(routeLink("All vendors", formatRoute({ view: "vendors", id: null, query: {} }), "more-link"));
  target.replaceChildren(back, node("h1", "view-title", label(vendorId)), status);
  const { lib, rows, kevRows } = await readScope(ctx, status, label(vendorId));
  if (!ctx.current()) return;
  const library = section("In the TeamStarWolf library");
  const doors = libraryList(lib, vendorId);
  if (doors.length) { const list = node("ul", "detail-list"); for (const door of doors) { const item = node("li"); item.append(door); list.append(item); } library.append(list); }
  else library.append(node("p", "muted", "The library has no platform page for this vendor yet."));
  const mine = sortRows(rows.filter(row => row.t.vendor.some(item => item[0] === vendorId)), "date-desc");
  const spellings = kevSpellings(lib, vendorId);
  const kev = kevRows.filter(row => spellings.has(row.vendor)).sort((a, b) => b.date_added.localeCompare(a.date_added) || a.cve.localeCompare(b.cve, undefined, { numeric: true }));
  const kevBlock = section("Known exploited (CISA KEV)");
  if (kev.length) {
    const years = new Map();
    for (const row of kev) years.set(row.date_added.slice(0, 4), (years.get(row.date_added.slice(0, 4)) || 0) + 1);
    const strip = node("p", "chips");
    strip.setAttribute("aria-label", "KEV entries by year added");
    for (const [year, total] of [...years].sort()) strip.append(node("span", "chip", year + ": " + total.toLocaleString("en-US")));
    const table = node("table", "data-table");
    table.append(node("caption", "", count(kev.length, "KEV entry", "KEV entries") + " whose vendorProject is " + [...spellings].sort().join(" or ") + (kev.length > 50 ? ". The newest 50 are listed." : ".")));
    const head = node("tr");
    for (const text of ["CVE", "Name (CISA)", "Added", "Federal due date"]) { const cell = node("th", "", text); cell.scope = "col"; head.append(cell); }
    const thead = node("thead"); thead.append(head);
    const body = node("tbody");
    for (const row of kev.slice(0, 50)) {
      const tr = node("tr");
      const cve = node("td"); cve.append(routeLink(row.cve, formatRoute({ view: "cve", id: row.cve, query: {} }), "chip chip-cve"));
      tr.append(cve, node("td", "", row.name), node("td", "", dateLabel(row.date_added)), node("td", "", row.due_date ? dateLabel(row.due_date) : "Not set"));
      body.append(tr);
    }
    table.append(thead, body);
    const wrap = node("div", "table-wrap"); wrap.append(table);
    kevBlock.append(strip, wrap);
  } else kevBlock.append(node("p", "muted", spellings.size ? "No KEV entry names this vendor." : "The vocabulary records no KEV vendorProject spelling for this vendor, so no KEV entry is matched."));
  const products = facets(mine).product;
  const productBlock = section("Products in its entries");
  if (products.size) {
    const chips = node("p", "chips");
    for (const [id, entry] of [...products].sort((a, b) => b[1].count - a[1].count)) chips.append(routeLink(label(entry.label) + " " + entry.count.toLocaleString("en-US"), formatRoute({ view: "explore", id: null, query: { vendor: route.id, product: id } }), "chip chip-entity"));
    productBlock.append(chips);
  } else productBlock.append(node("p", "muted", "No product tag on this vendor's entries in the live window."));
  const entries = section("Entries in the live window");
  const pages = node("nav", "pager"); pages.setAttribute("aria-label", "Vendor entry pages");
  const page = pager(pages, route, mine.length);
  const list = node("ol", "results-list");
  list.append(...mine.slice(page.start, page.start + pageSize).map(row => resultCard(row, route, null)));
  if (!mine.length) list.append(node("li", "empty", "No entry in the live window is tagged with this vendor."));
  const explore = node("p", "more");
  explore.append(routeLink("Filter the Explorer by " + label(vendorId), formatRoute({ view: "explore", id: null, query: { vendor: route.id } }), "more-link"));
  entries.append(list, pages, explore);
  status.textContent = count(mine.length, "entry", "entries") + " in the live window and " + count(kev.length, "KEV entry", "KEV entries") + ".";
  target.append(library, kevBlock, productBlock, entries);
  return { entries: mine, kev };
}
