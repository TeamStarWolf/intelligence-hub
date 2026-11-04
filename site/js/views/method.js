// Method (#/method): the evidence rules behind every tag, what each confidence level and
// coverage status means, how dates and scores are kept apart, and the licence and notice table.
// docs/METHOD.md carries the same rules for readers of the repository.
import { link, node, routeLink } from "../util.js";
import { formatRoute } from "../router.js";
import { section } from "./common.js";

// The live board's privacy statement; docs/METHOD.md and docs/OPERATIONS.md carry the same words.
export const PRIVACY_SENTENCE = "The Service health view's live board makes requests from your browser to the listed vendor status hosts when the view opens and every five minutes while it stays open and the tab is visible. Pause live updates stops them, and so does leaving the view.";

// The designations, as the TeamStarWolf library records them in THIRD_PARTY_NOTICES.md.
export const MITRE_NOTICES = [
  "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.",
  "© The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/",
  "© The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/"
];

// [material, where it comes from, terms, link]
export const LICENCES = [
  ["Publisher headlines and links", "The publishers of the configured RSS and Atom feeds", "The articles belong to their publishers. The Hub keeps the headline, the date and the link, never the article body.", null],
  ["KEV catalog entries", "CISA, Known Exploited Vulnerabilities catalog", "CISA distributes the KEV data under Creative Commons Zero 1.0. The Hub keeps CISA's text as published and attributes it to CISA.", "https://github.com/cisagov/kev-data"],
  ["CVE record fields", "The CVE Program, through the cvelistV5 repository", "Used under the CVE Program Terms of Use.", "https://www.cve.org/Legal/TermsOfUse"],
  ["History rows", "The sources each year's coverage statement names", "Ids, titles, dates, CVE ids and links only; each source's licence note is in the coverage matrix on the Sources view.", null],
  ["ATT&CK groups, software, techniques and tactics", "MITRE ATT&CK, through the TeamStarWolf library's pinned files", MITRE_NOTICES[0], "https://attack.mitre.org/resources/legal-and-branding/terms-of-use/"],
  ["CWE weaknesses", "MITRE CWE, through the library's pinned CWE list", MITRE_NOTICES[1], "https://cwe.mitre.org/"],
  ["CAPEC attack patterns", "MITRE CAPEC, through the library's pinned CAPEC list", MITRE_NOTICES[2], "https://capec.mitre.org/"],
  ["Curated summaries", "Written for the Hub", "Original paraphrases, each backed by a dated primary source that the row links.", null],
  ["Service-health entries", "The vendors' official status pages and feeds, IODA from Georgia Tech, and Cloudflare Radar once it is configured", "Incident names, states, impact levels, affected components, times, a short excerpt of the vendor's latest update and the link. The status pages belong to their vendors, and IODA rows repeat IODA's own copyright line.", null],
  ["The Hub's code", "TeamStarWolf/intelligence-hub", "MIT License.", "https://github.com/TeamStarWolf/intelligence-hub/blob/main/LICENSE"]
];

export function licenceTable() {
  const table = node("table", "data-table");
  table.append(node("caption", "", "What the Hub republishes, where it comes from and on what terms."));
  const head = node("tr");
  for (const text of ["Material", "From", "Terms"]) { const cell = node("th", "", text); cell.scope = "col"; head.append(cell); }
  const thead = node("thead"); thead.append(head);
  const body = node("tbody");
  for (const [material, from, terms, url] of LICENCES) {
    const tr = node("tr");
    const termsCell = node("td", "", terms);
    if (url) { termsCell.append(node("span", "", " ")); termsCell.append(link("Terms", url)); }
    const name = node("th", "", material); name.scope = "row";
    tr.append(name, node("td", "", from), termsCell);
    body.append(tr);
  }
  table.append(thead, body);
  const wrap = node("div", "table-wrap"); wrap.append(table);
  return wrap;
}

function rows(title, pairs, caption) {
  const block = section(title);
  const table = node("table", "data-table");
  table.append(node("caption", "", caption));
  const body = node("tbody");
  for (const [term, meaning] of pairs) { const tr = node("tr"); const cell = node("th", "", term); cell.scope = "row"; tr.append(cell, node("td", "", meaning)); body.append(tr); }
  table.append(body);
  const wrap = node("div", "table-wrap"); wrap.append(table);
  block.append(wrap);
  return block;
}

export const CONFIDENCE = [
  ["high", "Read from a structured field of a primary source, or from the source's own identity: KEV catalog entries, a CVE record's CNA problemTypes and affected fields, the source class and publisher vendor in the source registry."],
  ["medium", "An exact, case-sensitive name or a headline term with no conflicting signal, such as a threat group's name or a product name in a headline."],
  ["low", "Derived through a taxonomy chain (ATT&CK techniques from CWE through CAPEC), a weak name confirmed by a context word, or exploitation wording in a press headline."]
];

export const EXPLOITATION_RULES = [
  ["known", "A CVE on the entry is in CISA's KEV catalog (high), a vendor's structured field marks the flaw exploited (high), or a curated row's cited primary source confirms malicious activity (medium)."],
  ["reported", "A curated row's source reports exploitation (medium), or a headline states exploitation in plain terms or names a zero-day with an attack verb: medium for government, CERT, vendor and researcher sources, low for press. Negations and proof-of-concept wording never count."],
  ["unknown", "Everything else. There is no \"not exploited\" value: unknown never means safe, patched or unaffected."]
];

export const COVERAGE_RULES = [
  ["complete", "Every item the source lists for that year is a row."],
  ["filtered", "The adapter's stated filter, or the 1,500-row yearly cap, chose the rows. The statement names the filter."],
  ["partial", "Some listed items could not be read, link to pages that no longer resolve, or carry only a later posting date. The statement says how many of each."],
  ["sample", "A fixed sample by design."],
  ["gap", "No rows that year: the source had not started, the series had ended, or the adapter is not built yet. The statement says which."],
  ["unreachable", "The source refused automated reads, is JavaScript-only or needs a login."]
];

export function renderMethod(ctx) {
  const { target } = ctx;
  const parts = [node("h1", "view-title", "Method"),
    node("p", "view-intro", "How every tag, date and coverage statement on the Hub is decided, so you can judge how far to trust a row before you act on it. The rules are deterministic: the same inputs give the same tags, with no model, no network call and no randomness.")];
  parts.push(rows("Exploitation evidence", EXPLOITATION_RULES, "The evidence each exploitation value needs."));
  parts.push(rows("Confidence", CONFIDENCE, "Every tag records its method and one of three confidence levels. The Explorer shows every level."));
  const tags = section("Tags and their limits");
  for (const text of [
    "Vendor, product, actor and malware names match case-sensitively as whole words, using the match names in the TeamStarWolf library's shared vocabulary. Ordinary words, command names and names two entities share are never matched. A name in a headline is a mention, not attribution.",
    "Vendor, product, CWE and CVSS facts from KEV and from CVE records take precedence over headline matches, because they are structured.",
    "ATT&CK techniques come only from an entry's CWEs through CAPEC. Many common CWEs reach no technique, and a technique reached this way is taxonomy, not observed attacker behaviour.",
    "A region tag says why the place is there: the publisher's country, or a country named in the headline. A mention does not say whether the place is a target, an origin or neither.",
    "Event types: advisories, bulletins and notes are disclosures; vendor advisories are also patches; exploitation mirrors the exploitation tag; breach, outage, takedown and policy come from headline terms. A research entry with none of these is analysis, anything else is unclassified, so no label is forced."]) tags.append(node("p", "", text));
  parts.push(tags);
  const dates = section("Dates and scores");
  for (const text of [
    "Published and updated dates are the publisher's own. Event dates are kept separately. A KEV date is the day CISA added the entry to its catalog, not disclosure or first exploitation.",
    "CISA's federal due dates apply to US federal civilian agencies. They are not your deadlines.",
    "CVSS versions stay labelled, with the scorer named. Scores across versions are never merged into one number.",
    "No entry proves that a device is exposed. Affected version ranges are what the CNA published, not a list of fixed releases."]) dates.append(node("p", "", text));
  parts.push(dates);
  const coverage = rows("History coverage statuses", COVERAGE_RULES, "Every history source has one statement per year from 1998. Curated rows and press feeds are outside these statements.");
  const matrix = node("p", "more"); matrix.append(routeLink("The source-by-year matrix", formatRoute({ view: "sources", id: null, query: {} }), "more-link"));
  coverage.append(matrix);
  parts.push(coverage);
  const privacy = section("Service health and your browser");
  privacy.append(node("p", "", PRIVACY_SENTENCE),
    node("p", "", "Each live read asks for one small status.json, without cookies or credentials and with no referrer, and only the hosts the snapshot lists can be read: the page's content security policy names the same hosts. Every other view reads this site only."));
  parts.push(privacy);
  const cadence = section("How often the data changes");
  cadence.append(node("p", "", "A collector run by GitHub Actions publishes the data. The workflow asks GitHub for a run every two hours, and GitHub starts scheduled runs late or skips them, so the gap between runs varies. The content date is the only freshness promise. The Reports and Sources views list the recent runs and the observed gap between them."));
  parts.push(cadence);
  const licences = section("Licences and notices");
  licences.append(licenceTable());
  for (const text of MITRE_NOTICES) licences.append(node("p", "muted", text));
  parts.push(licences);
  const docs = node("p");
  docs.append(link("The same rules in the repository: docs/METHOD.md", "https://github.com/TeamStarWolf/intelligence-hub/blob/main/docs/METHOD.md"));
  parts.push(docs);
  target.replaceChildren(...parts);
}
