// The CVE register (#/cves) and the CVE page (#/cve/<id>), which opens the brief in a dialog
// over the register. The register reads data/v7/cve-index.json; a brief is read on first open,
// from its bucket when buckets are published, otherwise from data/briefs.json.
import { formatRoute, withQuery } from "../router.js";
import { cveRegister, kevLinked } from "../filters.js";
import { count, dateLabel, epssPercent, link, node, routeLink, stamp } from "../util.js";
import { libraryDoor, pager } from "./common.js";
import { pageSize } from "../limits.js";

export const GUIDANCE = { "publisher-guidance": "Publisher guidance", "cisa-action": "CISA action", "needs-review": "Needs review" };

function controls(ctx) {
  const { route, navigate } = ctx;
  const base = route.view === "cve" ? { view: "cves", id: null, query: route.query } : route;
  const form = node("form", "view-controls");
  form.setAttribute("role", "search");
  const search = node("input", "search-input");
  search.type = "search"; search.maxLength = 200; search.placeholder = "Search a CVE id or CWE id"; search.value = route.query.q || ""; search.setAttribute("aria-label", "Search the CVE register");
  form.addEventListener("submit", event => { event.preventDefault(); navigate(withQuery(base, { q: search.value }), { replace: true }); });
  const button = node("button", "bar-button", "Search"); button.type = "submit";
  form.append(search, button);
  for (const [key, text] of [["kev", "KEV-linked"], ["action", "CISA required action"]]) {
    const wrap = node("label", "check");
    const box = node("input"); box.type = "checkbox"; box.checked = route.query[key] === "1";
    box.addEventListener("change", () => navigate(withQuery(base, { [key]: box.checked ? "1" : null }), { replace: true }));
    wrap.append(box, node("span", "", text));
    form.append(wrap);
  }
  const sort = node("select"); sort.setAttribute("aria-label", "Sort");
  for (const [value, text] of [["cve-desc", "CVE descending"], ["cve-asc", "CVE ascending"], ["cvss-desc", "CNA CVSS highest"], ["cvss-asc", "CNA CVSS lowest"], ["epss-desc", "EPSS highest"], ["epss-asc", "EPSS lowest"], ["kev-desc", "Newest KEV additions"]]) { const option = node("option", "", text); option.value = value; sort.append(option); }
  sort.value = route.query.sort || "cve-desc";
  sort.addEventListener("change", () => navigate(withQuery(base, { sort: sort.value }), { replace: true }));
  form.append(sort);
  return form;
}

// An EPSS cell: the percentage and the percentile, or the words for no score (never 0).
export function epssCell(epss) {
  return epss ? epssPercent(epss.score) + " (p" + (epss.percentile * 100).toFixed(1) + ")" : "No score";
}

// The EPSS attribution for a register or a brief: the scorer, the model and the score date the index records.
export function epssNote(counts) {
  const model = counts && typeof counts.epss_model === "string" ? counts.epss_model : null;
  const day = counts && typeof counts.epss_date === "string" ? counts.epss_date : null;
  return "EPSS by FIRST" + (model ? ", model " + model : "") + (day ? ", score date " + dateLabel(day) : "");
}

export function registerTable(rows, counts = null) {
  const table = node("table", "data-table");
  table.append(node("caption", "", "CVEs that saved entries mention. Guidance is the brief's own label; KEV and the CISA required action are separate catalog facts. The CVSS column is the CNA's metric, versions not normalized; CISA's ADP CVSS and SSVC values are in the brief. " +
    epssNote(counts) + ": the probability that the CVE is exploited in the next 30 days with its percentile; a CVE without a score on that date reads No score, never 0."));
  const head = node("tr");
  for (const label of ["CVE", "Guidance", "KEV added", "CNA CVSS", "EPSS", "CWE"]) { const cell = node("th", "", label); cell.scope = "col"; head.append(cell); }
  const thead = node("thead"); thead.append(head);
  const body = node("tbody");
  for (const row of rows) {
    const tr = node("tr");
    const id = node("td"); id.append(routeLink(row.cve, formatRoute({ view: "cve", id: row.cve, query: {} }), "chip chip-cve"));
    if (row.record_state !== "PUBLISHED") id.append(node("span", "cell-note", row.record_state + " record"));
    const guidance = node("td", "", GUIDANCE[row.guidance]);
    if (row.required_action) guidance.append(node("span", "cell-note", "CISA required action"));
    if (row.source_status !== "ok") guidance.append(node("span", "cell-note", "CNA lookup " + row.source_status));
    tr.append(id, guidance, node("td", "", row.kev_added ? dateLabel(row.kev_added) : "Not in KEV"), node("td", "", row.score === null ? "Unknown" : row.score.toFixed(1) + " (v" + (row.version || "?") + ")"),
      node("td", "", epssCell(row.epss)), node("td", "", row.weaknesses.join(", ") || "None supplied"));
    body.append(tr);
  }
  table.append(thead, body);
  return table;
}

export async function renderCves(ctx) {
  const { target, store, route } = ctx;
  const status = node("p", "results-status", "Reading the CVE index.");
  status.setAttribute("role", "status");
  const table = node("div", "table-wrap");
  const pages = node("nav", "pager"); pages.setAttribute("aria-label", "CVE pages");
  target.replaceChildren(node("h1", "view-title", "CVE register"), node("p", "view-intro", "Every CVE a saved entry mentions, with its brief's guidance label, KEV state, CNA CVSS and EPSS. Open a CVE for the source-led brief."), controls(ctx), status, table, pages);
  const index = await store.cveIndex();
  if (!ctx.current()) return;
  const rows = cveRegister(index, route.query);
  const listRoute = route.view === "cve" ? { view: "cves", id: null, query: route.query } : route;
  const page = pager(pages, listRoute, rows.length);
  table.replaceChildren(registerTable(rows.slice(page.start, page.start + pageSize), store.state.mode === "v7" ? store.state.index.counts : null));
  status.textContent = count(rows.length, "CVE") + " of " + index.size.toLocaleString("en-US") + " match.";
  return rows;
}

function block(title) { const item = node("section", "detail-block"); item.append(node("h3", "", title)); return item; }

function guidanceItems(title, values) {
  const item = block(title);
  if (!values.length) item.append(node("p", "muted", "None supplied by this saved record. Absence is not evidence that none exist."));
  for (const value of values) { item.append(node("p", "", value.text || "Source text not supplied.")); if (value.source_url) { const row = node("p"); row.append(link("Original guidance", value.source_url)); item.append(row); } }
  return item;
}

// Outbound links built from the CVE id alone, so a reader reaches the surveyed products without
// this site fetching any of them. Each pattern answered for a real KEV CVE on 2026-11-12 (the
// pull request that added the row records the status codes). GreyNoise's /cve/ page pattern and
// Vulners did not answer, so they are not listed; AttackerKB was retired on 2026-08-18.
export const ELSEWHERE = [
  ["CVE.org record", cve => "https://www.cve.org/CVERecord?id=" + cve],
  ["NVD", cve => "https://nvd.nist.gov/vuln/detail/" + cve],
  ["FIRST EPSS (API JSON)", cve => "https://api.first.org/data/v1/epss?cve=" + cve],
  ["Rapid7 vulnerability database", cve => "https://www.rapid7.com/db/?q=" + cve]
];

// The Elsewhere row: every link goes through link(), so it passes safeUrl or renders as text.
export function elsewhereRow(cve, lib = null) {
  const row = node("p", "elsewhere");
  row.append(node("strong", "", "Elsewhere: "));
  ELSEWHERE.forEach(([label, pattern], position) => { if (position) row.append(node("span", "", " · ")); row.append(link(label, pattern(cve))); });
  const door = libraryDoor(lib, "cve:" + cve, "TeamStarWolf library notes on " + cve);
  if (door) row.append(node("span", "", " · "), door);
  row.append(node("span", "muted", " Links built from the CVE id; this site fetched none of these pages."));
  return row;
}

function cvssLine(issuer, cvss) {
  const row = node("p");
  row.append(node("strong", "", issuer + " CVSS v" + (cvss.version || "?") + ": "), node("span", "", typeof cvss.score === "number" ? cvss.score.toFixed(1) : "score not supplied"));
  if (cvss.vector) row.append(node("span", "mono", " " + cvss.vector));
  return row;
}

// Every severity value with its issuer: the CNA's CVSS, CISA's ADP CVSS when CISA supplied one,
// and CISA's SSVC decision-point values with their date. Nothing is blended, averaged or ranked.
export function severityBlock(record) {
  const item = block("Severity sources");
  if (record.cvss) item.append(cvssLine("CNA", record.cvss));
  else item.append(node("p", "muted", "CNA CVSS: none supplied in this saved record."));
  const adp = record.adp;
  if (record.adp_status === "not_projected") item.append(node("p", "muted", "CISA ADP: not read for this saved record yet; a later collector run projects it from the same CVE record."));
  else if (!adp) item.append(node("p", "muted", "CISA ADP: no CISA ADP container in the saved CVE record."));
  else {
    if (adp.cvss) item.append(cvssLine("CISA ADP", adp.cvss));
    else item.append(node("p", "muted", "CISA ADP CVSS: none supplied."));
    if (adp.ssvc) {
      const row = node("p");
      row.append(node("strong", "", "CISA SSVC decision points" + (adp.ssvc.timestamp ? ", " + stamp(adp.ssvc.timestamp) : "") + ": "),
        node("span", "", ["Exploitation " + (adp.ssvc.exploitation || "not stated"), "Automatable " + (adp.ssvc.automatable || "not stated"), "Technical Impact " + (adp.ssvc.technical_impact || "not stated")].join(" · ")));
      item.append(row);
    } else item.append(node("p", "muted", "CISA SSVC: none supplied."));
    if (adp.date) item.append(node("p", "muted", "CISA ADP container updated " + stamp(adp.date) + "."));
  }
  item.append(node("p", "muted", "Each value is shown as its issuer published it, with the CVSS version. Nothing here is combined or averaged; the register's CVSS sort uses the CNA CVSS only."));
  return item;
}

// The brief for one CVE, built from the saved record only. No lookup leaves this site.
// lib is the library-door module: a CVE the shared vocabulary covers links its library notes.
// FIRST's EPSS block on the brief: the score as published for its date and model, or the words
// for no score on that date. Never a severity, never a change across model versions.
export function epssBlock(record, counts = null) {
  const item = block("Exploitation probability (EPSS)");
  if (record.epss) {
    item.append(node("p", "", "EPSS by FIRST, model " + record.epss.model + ", score date " + dateLabel(record.epss.date) + ": " + record.epss.score.toFixed(5) + " (" + epssPercent(record.epss.score) + "), percentile " + record.epss.percentile.toFixed(5) + "."));
  } else item.append(node("p", "muted", epssNote(counts) + ": no EPSS score on that date."));
  item.append(node("p", "muted", "The score is FIRST's estimated probability that the CVE is exploited in the next 30 days, as the model scores it on that date. It is not a severity, it is not blended with any CVSS value, and the Hub records no change across model versions."));
  return item;
}

export function briefBody(record, indexRow, rows, lib = null, counts = null) {
  const parts = [];
  const overview = block(record.title || "Source record title not supplied");
  overview.append(node("p", "chips", ""));
  const badges = overview.lastChild;
  const guidance = record.record_state === "REJECTED" ? "needs-review" : record.analysis.guidance_status;
  badges.append(node("span", "chip", GUIDANCE[guidance]), node("span", "chip", record.record_state + " record, CNA " + record.source_status), node("span", "chip", typeof record.cvss?.score === "number" ? "CNA CVSS " + record.cvss.score.toFixed(1) + " (v" + (record.cvss.version || "?") + ")" : "CNA CVSS not supplied"));
  if (record.kev) badges.append(node("span", "chip chip-kev", "KEV added " + dateLabel(record.kev.date_added)));
  if (record.record_state === "REJECTED") overview.append(node("p", "notice-inline", "This CVE record is rejected. Read its original disposition before treating it as a vulnerability."));
  overview.append(node("p", "", record.description || "Description not supplied in this saved record."));
  overview.append(node("p", "muted", "CNA source updated " + stamp(record.source_updated_at) + " · retrieved " + stamp(record.retrieved_at) + ". Review affected products and your installed version before acting; this is not a device assessment."));
  if (record.epss) badges.append(node("span", "chip", "EPSS " + epssPercent(record.epss.score)));
  overview.append(elsewhereRow(record.cve, lib));
  parts.push(overview, severityBlock(record), epssBlock(record, counts));
  const action = block("CISA catalog action");
  action.append(node("p", "", record.required_action || "No CISA required action is supplied for this record."));
  if (record.required_action_source_url) { const row = node("p"); row.append(link("CISA action source", record.required_action_source_url)); action.append(row); }
  if (record.kev) action.append(node("p", "muted", "Catalog added " + dateLabel(record.kev.date_added) + " · federal due date " + (record.kev.due_date ? dateLabel(record.kev.due_date) : "not set") + " · ransomware association " + (record.kev.ransomware || "unknown") + ". The due date is CISA's federal requirement, not a deadline set for you."));
  parts.push(action);
  const assessment = block("Assessment and review steps");
  assessment.append(node("p", "", record.analysis.assessment || "No assessment supplied."));
  const steps = node("ol", "detail-list");
  for (const step of record.analysis.steps) { const item = node("li"); item.append(node("strong", "", step.title), node("p", "", step.detail)); if (step.evidence_url) item.append(link("Supporting source", step.evidence_url)); steps.append(item); }
  if (steps.children.length) assessment.append(steps);
  for (const text of record.analysis.limitations) assessment.append(node("p", "muted", text));
  parts.push(assessment);
  const weaknesses = block("CNA weaknesses");
  if (!record.weaknesses.length) weaknesses.append(node("p", "muted", "No CWE identifier is projected for this record. That is unknown, not a claim that no weakness exists."));
  for (const item of record.weaknesses) {
    const row = node("p");
    row.append(node("strong", "", item.id), node("span", "", item.description ? " " + item.description + " " : " "), link("CWE definition", "https://cwe.mitre.org/data/definitions/" + item.id.slice(4) + ".html"));
    weaknesses.append(row);
  }
  parts.push(weaknesses, guidanceItems("Solutions", record.solutions), guidanceItems("Workarounds", record.workarounds));
  const products = block("Source-reported products and version ranges");
  products.append(node("p", "muted", "Bounded publisher excerpts. Affected and unaffected ranges are not verified installed versions or a list of fixed releases."));
  for (const product of record.products.slice(0, 50)) {
    const item = node("details", "cell-details");
    item.append(node("summary", "", (product.vendor || "Vendor unknown") + " / " + (product.product || "Product unknown") + " · " + count(product.versions.length, "version statement")));
    const versions = node("ul", "detail-list");
    for (const version of product.versions.slice(0, 200)) versions.append(node("li", "", (version.version || "Version not specified") + (version.less_than ? " to below " + version.less_than : "") + (version.less_than_or_equal ? " to " + version.less_than_or_equal + " inclusive" : "") + " · " + (version.status || "status unknown")));
    item.append(versions);
    products.append(item);
  }
  if (!record.products.length) products.append(node("p", "muted", "No product or version statements in this saved record."));
  parts.push(products);
  const references = block("Original references");
  const list = node("ul", "detail-list");
  for (const reference of record.references.slice(0, 100)) { const item = node("li"); item.append(link((reference.label || "Original reference") + (reference.kind ? " (" + reference.kind + ")" : ""), reference.url)); list.append(item); }
  if (!list.children.length) references.append(node("p", "muted", "No original reference links supplied."));
  else references.append(list);
  parts.push(references);
  const linked = block("Entries in the loaded data");
  const mentions = rows.filter(row => row.cves.includes(record.cve));
  linked.append(node("p", "muted", mentions.length ? count(mentions.length, "loaded entry", "loaded entries") + " mention this CVE. A shared identifier is not independent confirmation." : "No loaded entry mentions this CVE yet."));
  const items = node("ul", "detail-list");
  for (const row of mentions.slice(0, 20)) { const item = node("li"); item.append(link(row.title, row.url), node("span", "muted", " · " + row.source_name + (row.day ? " · " + dateLabel(row.day) : ""))); items.append(item); }
  if (items.children.length) linked.append(items);
  const search = node("p"); search.append(routeLink("Search the Explorer for " + record.cve, formatRoute({ view: "explore", id: null, query: { q: record.cve } }))); linked.append(search);
  parts.push(linked);
  if (indexRow && kevLinked({ kev_linked: false, cves: [record.cve] }, new Map([[record.cve, indexRow]]))) parts.push(node("p", "muted", "This CVE is KEV-linked: CISA lists it in the Known Exploited Vulnerabilities catalog."));
  return parts;
}
