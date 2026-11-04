// Patch Tuesday (#/patch-tuesday and #/patch-tuesday/<YYYY-MM>): Microsoft's monthly security
// release as a brief built from data. The page reads data/v7/patch-tuesday/index.json, then the
// one month it shows. Every number, table and the priority list come from the collector's brief
// (intelligence_hub/patch_tuesday.py) and its fixed rules; the page adds no text of its own about
// a CVE. MSRC, KEV and Hub links are built from checked CVE ids; Adobe and SAP links are the
// vendors' own, checked by validate.js.
import { formatRoute } from "../router.js";
import { count, dateLabel, link, monthLabel, node, routeLink, stamp } from "../util.js";
import { definitionList, section } from "./common.js";

export const MSRC_CVE = "https://msrc.microsoft.com/update-guide/vulnerability/";
export const KEV_CVE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=";
export const TIER_LABELS = { kev: "In CISA KEV", exploited: "Exploited, not yet in KEV", "critical-rce-exposed": "Critical RCE, exposed component", cvss: "By CVSS" };
// Rows shown per table before the rest is left to MSRC's own release notes.
export const TABLE_LIMIT = 200;

function table(caption, headings, rows) {
  const wrap = node("div", "table-wrap");
  const item = node("table", "data-table");
  item.append(node("caption", "", caption));
  const head = node("tr");
  for (const text of headings) { const cell = node("th", "", text); cell.scope = "col"; head.append(cell); }
  const thead = node("thead"); thead.append(head);
  const body = node("tbody");
  for (const cells of rows) {
    const tr = node("tr");
    for (const value of cells) {
      const cell = node("td");
      // An element built above is appended; anything else is text.
      if (value !== null && typeof value === "object") cell.append(value); else cell.textContent = value === null || value === undefined ? "" : String(value);
      tr.append(cell);
    }
    body.append(tr);
  }
  item.append(thead, body);
  wrap.append(item);
  return wrap;
}

function cveCell(cve, brief) {
  const cell = node("span", "chips");
  cell.append(link(cve, MSRC_CVE + cve, "chip chip-cve"));
  if (brief) cell.append(routeLink("Hub brief", formatRoute({ view: "cve", id: cve, query: {} }), "chip"));
  return cell;
}

function kevCell(cve, added) {
  if (!added) return "Not in KEV";
  const cell = node("span");
  cell.append(link("Added " + dateLabel(added), KEV_CVE + cve));
  return cell;
}

const score = value => value === null ? "Not scored" : value.toFixed(1);

// The brief's rows as objects keyed by CVE, with the KEV date beside each.
export function briefRows(brief) {
  const kev = new Map(brief.kev.listed.map(item => [item.cve, item.added]));
  return new Map(brief.rows.map(row => [row.cve, { ...row, kevAdded: kev.get(row.cve) || null, brief: brief.briefs.has(row.cve) }]));
}

export function headline(brief) {
  const severity = brief.counts.severity;
  const microsoft = brief.counts.cna.get("Microsoft") || 0;
  return [
    ["CVEs in the release", brief.counts.total.toLocaleString("en-US")],
    ["Issued by Microsoft", microsoft.toLocaleString("en-US")],
    ["Issued by other CNAs", (brief.counts.total - microsoft).toLocaleString("en-US")],
    ["Critical", (severity.get("Critical") || 0).toLocaleString("en-US")],
    ["Important", (severity.get("Important") || 0).toLocaleString("en-US")],
    ["Moderate", (severity.get("Moderate") || 0).toLocaleString("en-US")],
    ["Low", (severity.get("Low") || 0).toLocaleString("en-US")],
    ["Not rated", (severity.get("Not rated") || 0).toLocaleString("en-US")],
    ["Exploited in the wild", brief.counts.exploited.toLocaleString("en-US")],
    ["Publicly disclosed", brief.counts.disclosed.toLocaleString("en-US")],
    ["Already in CISA KEV", brief.counts.in_kev.toLocaleString("en-US")],
    ["Microsoft KEV additions this month", brief.kev.addedInMonth.length.toLocaleString("en-US")]
  ];
}

function priorityList(brief, rows) {
  const box = section("What to prioritize");
  box.append(node("p", "muted", "Ordered by the fixed rules below: KEV first, then exploited, then Critical remote code execution in an internet-facing or identity component, then the rest by CVSS. The list shows every row of the first three rules and the ten highest-scored of the rest."));
  if (!brief.priority.length) { box.append(node("p", "", "This release lists no CVE.")); return box; }
  const list = node("ol", "detail-list");
  for (const item of brief.priority) {
    const row = rows.get(item.cve);
    const entry = node("li");
    entry.append(node("strong", "", TIER_LABELS[item.tier] + ": "), cveCell(row.cve, row.brief), node("span", "", " " + row.title + " · " + (row.severity || "Not rated") + " · CVSS " + score(row.cvss)));
    list.append(entry);
  }
  box.append(list);
  return box;
}

function flaggedTable(brief, rows) {
  const flagged = [...rows.values()].filter(row => row.exploited || row.disclosed);
  const box = section("Exploited and publicly disclosed");
  if (!flagged.length) { box.append(node("p", "", "Microsoft marks no CVE in this release as exploited or publicly disclosed.")); return box; }
  box.append(table("Microsoft's Exploited and Publicly Disclosed flags at the document's last revision, with the CISA KEV date where KEV lists the CVE.",
    ["CVE", "Title", "Severity", "CVSS", "Exploited", "Disclosed", "CISA KEV"],
    flagged.map(row => [cveCell(row.cve, row.brief), row.title, row.severity || "Not rated", score(row.cvss), row.exploited ? "Yes" : "No", row.disclosed ? "Yes" : "No", kevCell(row.cve, row.kevAdded)])));
  return box;
}

function criticalTable(brief, rows) {
  const critical = [...rows.values()].filter(row => row.severity === "Critical").sort((a, b) => (b.cvss ?? -1) - (a.cvss ?? -1) || a.cve.localeCompare(b.cve));
  const box = section("Critical");
  if (!critical.length) { box.append(node("p", "", "Microsoft rates no CVE in this release Critical.")); return box; }
  box.append(table(count(critical.length, "Critical CVE") + (critical.length > TABLE_LIMIT ? ", the " + TABLE_LIMIT + " highest-scored shown" : "") + ", highest CVSS first. Component is Microsoft's tag for the CVE.",
    ["CVE", "Title", "Impact", "Component", "CVSS", "Exploitability"],
    critical.slice(0, TABLE_LIMIT).map(row => [cveCell(row.cve, row.brief), row.title, row.impact || "Not stated", row.component || "Not stated", score(row.cvss), row.exploitability || "Not stated"])));
  return box;
}

function familyTable(brief) {
  const box = section("By product family");
  const families = [...brief.counts.family].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  box.append(table("CVEs per Microsoft product family. A CVE that affects several families counts in each.", ["Product family", "CVEs"],
    families.map(([name, value]) => [name, value.toLocaleString("en-US")])));
  const issuers = [...brief.counts.cna].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  box.append(table("CVEs per issuing CNA. Chromium CVEs that Microsoft ships in Edge are issued by Chrome.", ["Issuing CNA", "CVEs"],
    issuers.map(([name, value]) => [name, value.toLocaleString("en-US")])));
  return box;
}

function kevSection(brief, rows) {
  const box = section("CISA KEV");
  box.append(node("p", "muted", "KEV dates are CISA's catalog additions. The first table lists this release's CVEs that the catalog holds; the second lists every Microsoft entry CISA added in " + monthLabel(brief.month) + ", in this release or not."));
  if (brief.kev.listed.length) {
    box.append(table("This release's CVEs in the KEV catalog.", ["CVE", "Title", "Added", "Due"],
      brief.kev.listed.map(item => [cveCell(item.cve, rows.get(item.cve).brief), rows.get(item.cve).title, kevCell(item.cve, item.added), item.due ? dateLabel(item.due) : "Not set"])));
  } else box.append(node("p", "", "The KEV catalog holds none of this release's CVEs."));
  if (brief.kev.addedInMonth.length) {
    box.append(table("Microsoft KEV additions in " + monthLabel(brief.month) + ".", ["CVE", "Added", "In this release"],
      brief.kev.addedInMonth.map(item => [link(item.cve, KEV_CVE + item.cve, "chip chip-cve"), dateLabel(item.added), item.inRelease ? "Yes" : "No, an earlier CVE"])));
  } else box.append(node("p", "", "CISA added no Microsoft entry to the KEV catalog in " + monthLabel(brief.month) + "."));
  return box;
}

function vendorSection(brief) {
  const box = section("Adobe and SAP the same day");
  box.append(node("p", "muted", "Headline rows only: the vendors' bulletin ids, titles, priorities and links. Read each bulletin on the vendor's page."));
  const adobe = node("div");
  adobe.append(node("h3", "", "Adobe"));
  if (brief.adobe.status !== "ok") adobe.append(node("p", "notice-inline", "Adobe's bulletin index was not read: " + (brief.adobe.reason || "no reason recorded") + "."));
  else if (!brief.adobe.rows.length) adobe.append(node("p", "", "Adobe's bulletin index lists no bulletin first posted on " + dateLabel(brief.msrc.initial_release.slice(0, 10)) + "." + (brief.adobe.latest_posted ? " Its latest posting date is " + dateLabel(brief.adobe.latest_posted) + "." : "")));
  else adobe.append(table("Adobe bulletins first posted on Microsoft's release day.", ["Bulletin", "Title", "Products", "Posted"],
    brief.adobe.rows.map(row => [link(row.id, row.url), row.title, row.products.join(", "), dateLabel(row.posted)])));
  const index = node("p"); index.append(link("Adobe security bulletins and advisories", brief.adobe.url)); adobe.append(index);
  const sap = node("div");
  sap.append(node("h3", "", "SAP"));
  if (brief.sap.status !== "ok") sap.append(node("p", "notice-inline", "No SAP Security Patch Day page was read for this month: " + (brief.sap.reason || "no reason recorded") + "."));
  else sap.append(table(count(brief.sap.rows.length, "SAP Security Note") + " on SAP's Security Patch Day page for " + monthLabel(brief.month) + ".", ["Note", "Title", "CVEs", "Priority", "CVSS"],
    brief.sap.rows.map(row => [row.url ? link(row.note, row.url) : row.note, row.title, row.cves.join(", ") || "None listed", row.priority, score(row.cvss)])));
  const page = node("p"); page.append(link("SAP Security Patch Day", brief.sap.url)); sap.append(page);
  box.append(adobe, sap);
  return box;
}

function historyTable(index, shown) {
  const box = section("Month by month");
  const first = index.first_month ? monthLabel(index.first_month) : null;
  box.append(node("p", "muted", index.months.length ? count(index.months.length, "monthly brief") + " from " + first + " to " + monthLabel(index.last_month) + "." +
    (index.pending.length ? " " + count(index.pending.length, "release") + " Microsoft lists are not built yet; the collector reads a bounded number of release documents per run." : "") : "No brief is built yet."));
  box.append(table("Each month's release, newest first. Totals count every CVE in the brief.", ["Month", "Release", "CVEs", "Critical", "Exploited", "Disclosed", "In KEV"],
    index.months.map(item => [item.month === shown ? node("strong", "", monthLabel(item.month)) : routeLink(monthLabel(item.month), formatRoute({ view: "patch-tuesday", id: item.month, query: {} })),
      item.id, item.total.toLocaleString("en-US"), item.critical.toLocaleString("en-US"), item.exploited.toLocaleString("en-US"), item.disclosed.toLocaleString("en-US"), item.in_kev.toLocaleString("en-US")])));
  if (index.pending.length) {
    const details = node("details", "cell-details");
    details.append(node("summary", "", "Releases not built yet"));
    const list = node("ul", "detail-list");
    for (const item of index.pending.slice(0, 200)) list.append(node("li", "", item.id + ": " + item.reason));
    details.append(list);
    box.append(details);
  }
  return box;
}

function rulesSection(index) {
  const box = section("Rules and limits");
  const rules = node("ul", "detail-list");
  for (const text of index.rules) rules.append(node("li", "", text));
  const notes = node("ul", "detail-list");
  for (const text of index.notes) notes.append(node("li", "", text));
  box.append(node("h3", "", "Priority rules"), rules, node("h3", "", "What the brief covers"), notes);
  return box;
}

export async function renderPatchTuesday(ctx) {
  const { target, store, route } = ctx;
  const title = node("h1", "view-title", "Patch Tuesday");
  const intro = node("p", "view-intro", "Microsoft's monthly security release, month by month, from the Microsoft Security Response Center's CVRF data. The CISA KEV catalog and Adobe's and SAP's same-day bulletins sit beside it. Every number and table comes from the vendors' published data and the fixed rules at the end of the page.");
  if (store.state.mode !== "v7") { target.replaceChildren(title, intro, node("p", "notice-inline", "The Patch Tuesday briefs are part of the schema 7 data, which this fallback does not have.")); return; }
  const status = node("p", "results-status", "Reading the Patch Tuesday briefs.");
  status.setAttribute("role", "status");
  target.replaceChildren(title, intro, status);
  const index = await store.patchTuesdayIndex();
  if (!ctx.current()) return;
  if (!index || !index.months.length) { status.textContent = "No Patch Tuesday brief is published in this snapshot yet."; if (index) target.append(historyTable(index, null), rulesSection(index)); return; }
  const chosen = route.id ? index.months.find(item => item.month === route.id) : index.months[0];
  if (!chosen) { status.textContent = "No brief is built for " + monthLabel(route.id) + "."; target.append(historyTable(index, null), rulesSection(index)); return; }
  const brief = await store.patchTuesday(chosen.path);
  if (!ctx.current()) return;
  const rows = briefRows(brief);
  const header = section(brief.msrc.title, "panel");
  const facts = definitionList([["Release", brief.msrc.id], ["Released", dateLabel(brief.msrc.initial_release.slice(0, 10), true)],
    ["Last revised", stamp(brief.msrc.current_release)], ["Package CVEs left out", brief.msrc.left_out.toLocaleString("en-US") + " of " + brief.msrc.listed.toLocaleString("en-US") + " listed"]]);
  const notes = node("p"); notes.append(link("MSRC release notes for " + brief.msrc.id, brief.msrc.url));
  header.append(facts, notes);
  const numbers = section("Headline numbers");
  numbers.append(definitionList(headline(brief)));
  status.textContent = monthLabel(brief.month) + ": " + count(brief.counts.total, "CVE") + ", " + brief.counts.exploited.toLocaleString("en-US") + " exploited, " + brief.counts.disclosed.toLocaleString("en-US") + " publicly disclosed, " + brief.counts.in_kev.toLocaleString("en-US") + " in CISA KEV.";
  target.replaceChildren(title, intro, status, header, numbers, priorityList(brief, rows), flaggedTable(brief, rows), criticalTable(brief, rows), familyTable(brief),
    kevSection(brief, rows), vendorSection(brief), historyTable(index, brief.month), rulesSection(index));
  return brief;
}
