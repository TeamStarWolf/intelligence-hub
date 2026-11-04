// Actors and malware (#/actors, #/actor/<id> and #/malware/<id>): entries tagged with a threat
// group or a piece of software, with a back-link to its TeamStarWolf library page (the MITRE
// ATT&CK group and software pages there) taken from the vendored vocabulary.
import { formatRoute, withQuery } from "../router.js";
import { facets, sortRows } from "../filters.js";
import { count, node, routeLink } from "../util.js";
import { pageSize } from "../limits.js";
import { label, libraryDoor, loadLibrary, pager, resultCard, section } from "./common.js";
import { historyYears } from "./history.js";
import { entityDoor } from "./tags.js";

const KINDS = { actor: { title: "Actors", key: "actor", noun: "actor" }, malware: { title: "Malware and tools", key: "malware", noun: "malware family or tool" } };

function attackId(id) { return /^[GS]\d{4}$/.test(id) ? id : null; }

function entityTable(kind, map, lib, year = null) {
  const spec = KINDS[kind];
  const table = node("table", "data-table");
  table.append(node("caption", "", spec.title + " named on loaded entries, by how many entries carry the tag. Names are matched case-sensitively from the library vocabulary; see Method for the confidence of each match."));
  const head = node("tr");
  for (const text of ["Name", "ATT&CK id", "Entries", "Library"]) { const cell = node("th", "", text); cell.scope = "col"; head.append(cell); }
  const thead = node("thead"); thead.append(head);
  const body = node("tbody");
  for (const [id, entry] of [...map].sort((a, b) => b[1].count - a[1].count || label(a[1].label).localeCompare(label(b[1].label)))) {
    const tr = node("tr");
    const name = node("th"); name.scope = "row"; name.append(routeLink(label(entry.label), entityDoor(kind, id, year ? { year } : {})));
    const door = node("td");
    const link = libraryDoor(lib, entry.label, "Library page");
    door.append(link || node("span", "muted", "No library page"));
    tr.append(name, node("td", "mono", attackId(id) || "Not in ATT&CK"), node("td", "", entry.count.toLocaleString("en-US")), door);
    body.append(tr);
  }
  table.append(thead, body);
  const wrap = node("div", "table-wrap"); wrap.append(table);
  return wrap;
}

export async function renderActors(ctx) {
  const { target, store, route, navigate } = ctx;
  const status = node("p", "results-status", "Reading the entries for this scope.");
  status.setAttribute("role", "status");
  const form = node("form", "view-controls");
  const choose = node("label", "field");
  const select = node("select");
  for (const value of ["", ...historyYears(store).map(String)]) { const option = node("option", "", value || "Live window"); option.value = value; select.append(option); }
  select.value = route.query.year || "";
  select.addEventListener("change", () => navigate(withQuery(route, { year: select.value || null }), { replace: true }));
  choose.append(node("span", "", "Count entries in"), select);
  form.append(choose);
  form.addEventListener("submit", event => event.preventDefault());
  target.replaceChildren(node("h1", "view-title", "Actors and malware"),
    node("p", "view-intro", "Threat groups, malware and tools that entries name, each with its entries and a link to its page in the TeamStarWolf library. " + (route.query.year ? "A name opens the Explorer filtered to it in " + route.query.year + ". " : "") + "A name in a headline is a mention, not attribution."), form, status);
  const paths = store.articlePaths({ view: "explore", id: null, query: route.query.year ? { year: route.query.year } : {} });
  const [lib] = await Promise.all([loadLibrary(), store.ensure(paths, () => { if (ctx.current()) status.textContent = "Still reading."; })]);
  if (!ctx.current()) return;
  const found = facets(store.rows(paths));
  const parts = [];
  for (const kind of ["actor", "malware"]) {
    const block = section(KINDS[kind].title);
    if (found[kind].size) block.append(entityTable(kind, found[kind], lib, route.query.year || null));
    else block.append(node("p", "muted", "No loaded entry names one in this scope."));
    parts.push(block);
  }
  target.append(...parts);
  status.textContent = count(found.actor.size, "actor") + " and " + count(found.malware.size, "malware family or tool", "malware families and tools") + " in " + (route.query.year ? route.query.year : "the live window") + ". Names with no entry are not listed.";
  return found;
}

export async function renderEntity(ctx) {
  const { target, store, route } = ctx;
  const kind = route.view === "malware" ? "malware" : "actor";
  const spec = KINDS[kind];
  const entityId = kind + ":" + route.id;
  const status = node("p", "results-status", "Reading the live window.");
  status.setAttribute("role", "status");
  const back = node("p", "more"); back.append(routeLink("All actors and malware", formatRoute({ view: "actors", id: null, query: {} }), "more-link"));
  target.replaceChildren(back, node("h1", "view-title", label(entityId)), status);
  const paths = store.articlePaths({ view: "explore", id: null, query: {} });
  const [lib] = await Promise.all([loadLibrary(), store.ensure(paths, () => { if (ctx.current()) status.textContent = "Still reading the live window."; })]);
  if (!ctx.current()) return;
  const about = section("In the TeamStarWolf library");
  const facts = node("p", "", (attackId(route.id) ? "MITRE ATT&CK " + (kind === "actor" ? "group " : "software ") + route.id + ". " : "A name ATT&CK does not track. "));
  about.append(facts);
  const door = libraryDoor(lib, entityId, "Read the " + label(entityId) + " page in the library");
  about.append(door ? (() => { const line = node("p"); line.append(door); return line; })() : node("p", "muted", "The library has no page for this " + spec.noun + " yet."));
  const mine = sortRows(store.rows(paths).filter(row => row.t[kind].some(item => item[0] === entityId)), "date-desc");
  const entries = section("Entries in the live window");
  const pages = node("nav", "pager"); pages.setAttribute("aria-label", "Entry pages");
  const page = pager(pages, route, mine.length);
  const list = node("ol", "results-list");
  list.append(...mine.slice(page.start, page.start + pageSize).map(row => resultCard(row, route, null)));
  if (!mine.length) list.append(node("li", "empty", "No entry in the live window names this " + spec.noun + ". Choose a year in the Explorer to search history rows."));
  const explore = node("p", "more");
  explore.append(routeLink("Filter the Explorer by " + label(entityId), formatRoute({ view: "explore", id: null, query: { [spec.key]: route.id } }), "more-link"));
  entries.append(list, pages, explore);
  status.textContent = count(mine.length, "entry", "entries") + " in the live window name " + label(entityId) + ".";
  target.append(about, entries);
  return mine;
}
