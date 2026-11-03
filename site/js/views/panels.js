// Everything that is not the Explorer: the sidebar panels and the Reports, Sources, Data and
// About tabs. The sidebar starts collapsed and reads its data only when it is opened.
import { formatRoute } from "../router.js";
import { count, dateLabel, hoursLabel, link, node, routeLink, stamp } from "../util.js";
import { definitionList, section } from "./common.js";
import { actStrip, kevStrip, todayData } from "./today.js";

export function cadenceText(index) {
  if (!index) return "The collector's run record could not be read, so no observed schedule is shown. The workflow asks GitHub for a run every two hours, and GitHub does not guarantee it.";
  const gap = index.interval.median === null ? "Not enough published runs are recorded yet to state the gap between them" :
    "Observed gap between published runs: median " + hoursLabel(index.interval.median) + ", longest " + hoursLabel(index.interval.max) + " over the last " + index.interval.runs_counted + " runs";
  return "Content date " + (index.content_date ? dateLabel(index.content_date) : "not recorded") + ". Last published run " + stamp(index.runs[0].generated_at) + ". " + gap +
    ". The workflow asks GitHub for a run every two hours (cron " + index.requested_cron + "); GitHub starts scheduled runs late or skips them, so a new item can take several hours to appear and the content date is the only freshness promise.";
}

function more(text, view) { const item = node("p", "more"); item.append(routeLink(text, formatRoute({ view, id: null, query: {} }), "more-link")); return item; }

function sourceSummary(sources) {
  const by = status => sources.filter(source => source.status === status).length;
  return count(sources.length, "source") + ": " + by("ok") + " accepted, " + by("partial") + " partial, " + by("failed") + " failed, " + by("not_fetched") + " not fetched in the last published run.";
}

export async function renderSidebar(ctx) {
  const { target, store } = ctx;
  const parts = [];
  const todayPanel = section("Today", "panel side-panel");
  todayPanel.append(node("p", "muted", "Reading the KEV ledger."));
  const snapshot = section("Snapshot", "panel side-panel");
  snapshot.append(node("p", "", store.state.mode === "legacy" ? "This page is reading the schema 6 feed because data/v7/index.json is missing." : cadenceText(store.state.index)));
  if (store.state.mode === "v7") {
    const counts = store.state.index.counts;
    snapshot.append(definitionList([["Live entries", (counts.live_rows ?? 0).toLocaleString("en-US")], ["History rows", (counts.history_rows ?? 0).toLocaleString("en-US")], ["KEV entries", (counts.kev ?? 0).toLocaleString("en-US")], ["CVEs with briefs", (counts.cves ?? 0).toLocaleString("en-US")]]));
  }
  snapshot.append(more("Sources and run record", "sources"));
  const reports = section("Reports", "panel side-panel");
  const sources = section("Sources", "panel side-panel");
  const data = section("Data exports", "panel side-panel");
  const method = section("Method and limits", "panel side-panel");
  method.append(node("p", "", "A selected collection, not every incident. Publisher headlines link to their sources; no article body is copied. Unknown exploitation never means safe."), more("How the Hub works", "about"));
  parts.push(todayPanel, snapshot, reports, sources, data, method);
  target.replaceChildren(...parts);
  const [today, reportFile, ledger] = await Promise.all([todayData(store).catch(() => null), store.reports().catch(() => null), store.sources().catch(() => null)]);
  if (!ctx.current()) return;
  todayPanel.replaceChildren(node("h2", "panel-title", "Today"));
  if (today) todayPanel.append(node("p", "muted", "Content date " + dateLabel(today.to) + "."), actStrip(today, true), kevStrip({ days: today.days.slice(0, 3) }, true));
  else todayPanel.append(node("p", "muted", "The KEV ledger could not be read."));
  todayPanel.append(more("Open Today", "today"));
  if (reportFile && reportFile.status === "available") {
    const list = node("ul", "detail-list");
    for (const report of [...reportFile.reports].sort((a, b) => b.period_end.localeCompare(a.period_end)).slice(0, 5)) {
      const item = node("li");
      item.append(report.report_url ? link(report.title, report.report_url) : node("span", "", report.title), node("span", "muted", " · " + report.cadence + ", " + report.status.replaceAll("_", " ")));
      list.append(item);
    }
    reports.append(list);
  } else reports.append(node("p", "muted", "Report catalog unavailable" + (reportFile ? ": " + reportFile.reason : ".")));
  reports.append(more("All report editions", "reports"));
  sources.append(node("p", "", ledger ? sourceSummary(ledger) : "The source ledger could not be read."), more("Source ledger", "sources"));
  const exports = store.state.mode === "v7" ? store.state.index.exports : null;
  data.append(node("p", "", exports && exports.status === "ok" ? count(exports.files.length, "export file") + ": per-year CSV and JSONL with every tag, a manifest and a data dictionary." : "No exports are listed in this index."), more("Data downloads", "data"));
}

export async function renderReports(ctx) {
  const { target, store } = ctx;
  target.replaceChildren(node("h1", "view-title", "Reports"), node("p", "view-intro", "Report editions come from a separate desktop compiler and live in the repository's reports folder. This tab lists the catalog that the last published run validated."));
  const file = await store.reports();
  if (!ctx.current()) return;
  if (file.status !== "available") { target.append(node("p", "notice-inline", "Report catalog unavailable: " + file.reason + " Other views are not affected.")); return file; }
  const table = node("table", "data-table");
  table.append(node("caption", "", count(file.reports.length, "edition") + (file.updated_at ? ". Catalog updated " + stamp(file.updated_at) : "") + ". Published means a report file exists, not that every claim was independently verified."));
  const head = node("tr");
  for (const label of ["Edition", "Cadence", "Period", "Status", "Files"]) { const cell = node("th", "", label); cell.scope = "col"; head.append(cell); }
  const thead = node("thead"); thead.append(head);
  const body = node("tbody");
  for (const report of [...file.reports].sort((a, b) => b.period_end.localeCompare(a.period_end))) {
    const tr = node("tr");
    const files = node("td");
    if (report.report_url) files.append(link("Report", report.report_url));
    if (report.data_url) { files.append(node("span", "", " · ")); files.append(link("Data", report.data_url)); }
    if (!report.report_url) files.append(node("span", "muted", "Planned; no report yet"));
    tr.append(node("td", "", report.title), node("td", "", report.cadence), node("td", "", dateLabel(report.period_start.slice(0, 10)) + " to " + dateLabel(report.period_end.slice(0, 10))), node("td", "", report.status.replaceAll("_", " ") + " · " + report.coverage.replaceAll("_", " ")), files);
    body.append(tr);
  }
  table.append(thead, body);
  const wrap = node("div", "table-wrap"); wrap.append(table);
  target.append(wrap);
  if (file.indexes.length) { const list = node("ul", "detail-list"); for (const index of file.indexes) { const item = node("li"); item.append(link(index.label, index.url)); list.append(item); } const block = section("Report indexes"); block.append(list); target.append(block); }
  if (file.review) {
    const block = section("Revision review of earlier citations");
    block.append(node("p", "", "State: " + (file.review.state || "not recorded").replaceAll("_", " ") + (file.review.nominal_cutoff ? " · nominal cutoff " + stamp(file.review.nominal_cutoff) : "") + "."));
    for (const note of file.review.notes) block.append(node("p", "muted", note));
    target.append(block);
  }
  if (file.notes.length) { const block = section("Catalog notes"); for (const note of file.notes) block.append(node("p", "muted", note)); target.append(block); }
  return file;
}

function intakeLine(source) {
  const report = source.intake;
  if (!report) return source.id === "cisa-kev" ? "The KEV catalog is read separately; feed entry windows do not apply." : "No entry-window counts were recorded for this observation; completeness is unknown.";
  return "Last response window: " + report.items_seen + " seen, " + report.items_admitted + " admitted, " + report.items_rejected + " rejected, " + report.items_filtered + " filtered, " + report.items_unprocessed + " unprocessed (entry limit " + report.entry_limit + ").";
}

export async function renderSources(ctx) {
  const { target, store } = ctx;
  const parts = [node("h1", "view-title", "Sources and run record"), node("p", "view-intro", "Who the Hub reads, what the last published run recorded for each source, and how often GitHub actually ran the collector.")];
  const cadence = section("Run record");
  cadence.append(node("p", "", store.state.mode === "v7" ? cadenceText(store.state.index) : cadenceText(null)));
  if (store.state.mode === "v7") {
    const list = node("ul", "detail-list");
    for (const run of store.state.index.runs) list.append(node("li", "", stamp(run.generated_at) + " · " + run.trigger.replaceAll("_", " ")));
    cadence.append(list);
  }
  parts.push(cadence);
  target.replaceChildren(...parts);
  const sources = await store.sources();
  if (!ctx.current()) return;
  const ledger = section("Source ledger");
  ledger.append(node("p", "", sourceSummary(sources)), node("p", "muted", "Recorded collection outcomes, not live connectivity checks. Last accepted input is not exhaustive publisher coverage."));
  const states = { ok: "Input accepted", partial: "Partial input", failed: "Fetch or intake failed", not_fetched: "Not fetched" };
  const list = node("ul", "ledger");
  for (const source of [...sources].sort((a, b) => a.name.localeCompare(b.name))) {
    const item = node("li", "ledger-item status-" + source.status);
    const name = node("p", "ledger-name"); name.append(link(source.name, source.url), node("span", "chip", states[source.status]));
    item.append(name, node("p", "muted", source.kind + " · " + count(source.articles, "saved entry", "saved entries") + " · last accepted " + stamp(source.last_success) + " · last attempt " + stamp(source.last_attempt)), node("p", "muted", intakeLine(source)));
    if (source.error) item.append(node("p", "notice-inline", source.error));
    list.append(item);
  }
  ledger.append(list);
  target.append(ledger);
  return sources;
}

export function renderData(ctx) {
  const { target, store } = ctx;
  const parts = [node("h1", "view-title", "Data downloads"), node("p", "view-intro", "Per-year analytics exports: one CSV and one JSONL row per entry with every tag field, and a long CSV with one row per tag, confidence and method. Load them into a spreadsheet or a notebook.")];
  const exports = store.state.mode === "v7" ? store.state.index.exports : null;
  if (!exports || exports.status !== "ok") { parts.push(node("p", "notice-inline", "No exports are listed in this index" + (exports && exports.reason ? ": " + exports.reason : ".") )); target.replaceChildren(...parts); return; }
  const fixed = section("Start here");
  const fixedList = node("ul", "detail-list");
  const years = new Map();
  for (const file of exports.files) {
    const name = file.path.slice("exports/".length);
    const anchor = node("a", "", name + " (" + Math.max(1, Math.round(file.bytes / 1024)).toLocaleString("en-US") + " KB)");
    anchor.href = "./data/v7/" + file.path; anchor.setAttribute("download", name);
    const year = /-(\d{4}|undated)/.exec(name);
    if (!year) { const item = node("li"); item.append(anchor); fixedList.append(item); continue; }
    if (!years.has(year[1])) years.set(year[1], []);
    years.get(year[1]).push(anchor);
  }
  fixed.append(fixedList);
  const table = node("ul", "year-files");
  for (const [year, anchors] of [...years].sort((a, b) => b[0].localeCompare(a[0]))) {
    const item = node("li"); item.append(node("strong", "", year + ": "));
    anchors.forEach((anchor, position) => { if (position) item.append(node("span", "", " · ")); item.append(anchor); });
    table.append(item);
  }
  const byYear = section("By year"); byYear.append(table);
  const licences = section("Licences and notices");
  for (const text of ["Publisher rows carry headlines and links only; the articles belong to their publishers.", "KEV rows carry CISA's catalog text, which CISA publishes under CC0 1.0.", "CVE record fields come from the CVE Program's records under the CVE terms of use.", "Curated history rows are original paraphrases backed by a dated primary source.", "The Hub's code is MIT-licensed."]) licences.append(node("p", "", text));
  parts.push(fixed, byYear, licences);
  target.replaceChildren(...parts);
}

const MITRE_NOTICES = [
  "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.",
  "© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/",
  "© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/"
];

export function renderAbout(ctx) {
  const { target, store } = ctx;
  const parts = [node("h1", "view-title", "About the Intelligence Hub"),
    node("p", "view-lead", "Open security news, advisories, and known exploited vulnerabilities for the community, linked to their original sources."),
    node("p", "", "The Hub is part of TeamStarWolf. A collector run by GitHub Actions reads public RSS and Atom feeds, CISA's Known Exploited Vulnerabilities catalog and CVE records, tags every entry from controlled vocabularies, and publishes the result as static files. Your browser reads only those files, from this site.")];
  const method = section("Dates, scores and boundaries");
  for (const text of ["Published and updated dates are the publisher's own. Event dates are separate. A KEV date is the day CISA added the entry to its catalog, not disclosure or first exploitation.",
    "CVSS versions stay labelled; scores across versions are not normalized. Affected ranges are not a list of fixed versions.",
    "Exploitation is known, reported or unknown. Unknown means this entry does not establish exploitation; it never means safe.",
    "Tags carry their method and confidence. ATT&CK techniques reached through CWE and CAPEC are low-confidence taxonomy paths, not observed behaviour.",
    "CVE guidance needs applicability review. No entry proves that a device is exposed. CISA federal due dates are not your deadlines."]) method.append(node("p", "", text));
  const scope = section("What the Hub covers");
  for (const text of ["A selected collection within a declared window, not every incident, article or vulnerability. History rows reach back to 1998 from the sources each year's coverage statement names.",
    "Publisher rows carry headlines and links only. KEV rows carry CISA's text. Curated summaries are original paraphrases.",
    "The Explorer starts with the live window (the last 24 months). Choose a year to add that year's history rows."]) scope.append(node("p", "", text));
  const cadence = section("How fresh the data is");
  cadence.append(node("p", "", store.state.mode === "v7" ? cadenceText(store.state.index) : cadenceText(null)), node("p", "muted", "While this page stays open and visible it asks the site whether the index changed, and reads nothing while the tab is hidden."));
  const notices = section("Notices");
  for (const text of store.state.mode === "v7" ? store.state.index.notices : []) notices.append(node("p", "", text));
  for (const text of MITRE_NOTICES) notices.append(node("p", "muted", text));
  const context = section("Curated threat context");
  const status = node("p", "muted", "The curated CWE, CAPEC, actor, campaign, product and mitigation context lives in data/feed.json. It loads only when you ask.");
  const button = node("button", "bar-button", "Load the curated context"); button.type = "button";
  const results = node("div", "context-list");
  button.addEventListener("click", async () => {
    button.disabled = true; status.textContent = "Reading data/feed.json.";
    try {
      const snapshot = await store.feed();
      const catalog = snapshot.intelligence?.catalog;
      if (!catalog) { status.textContent = "This feed carries no curated context."; return; }
      status.textContent = count(catalog.entities.length, "entity", "entities") + " and " + count(catalog.relationships.length, "relationship") + ". Taxonomy links are definitions, not proof that an attack occurred.";
      results.replaceChildren(...catalog.entities.map(entity => {
        const item = node("details", "cell-details");
        item.append(node("summary", "", entity.id + " · " + entity.label + " · " + entity.type), node("p", "", entity.summary), node("p", "muted", "Recorded confidence: " + entity.confidence.replaceAll("_", " ")));
        for (const evidence of entity.evidence) { const row = node("p"); row.append(link(evidence.publisher, evidence.source_url)); item.append(row); }
        return item;
      }));
    } catch (error) { status.textContent = "The curated context could not load: " + error.message; button.disabled = false; }
  });
  context.append(status, button, results);
  parts.push(method, scope, cadence, context, notices);
  const source = node("p"); source.append(link("Source code and issues on GitHub", "https://github.com/TeamStarWolf/intelligence-hub")); parts.push(source);
  target.replaceChildren(...parts);
}
