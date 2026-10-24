"use strict";

(() => {
  const $ = selector => document.querySelector(selector);
  const kinds = { advisory: "ADVISORY", research: "RESEARCH", reporting: "REPORTING", incident: "INCIDENT", kev: "CISA KEV", filing: "SEC FILING" };
  const origins = { "publisher-feed": "PUBLISHER FEED", "cisa-kev": "CATALOG RECORD", "library-curation": "CURATED ARCHIVE" };
  const guidanceLabels = { "publisher-guidance": "Publisher guidance", "cisa-action": "CISA action", "needs-review": "Needs review", unavailable: "Source failed / pending" };
  const day = 86400000;
  const pollInterval = 300000;
  const pageSize = 24;
  const maximumFeedBytes = 16 * 1024 * 1024;
  const cvePattern = /^CVE-\d{4}-\d{4,19}$/;
  const controls = Object.fromEntries(["search", "kind", "source", "exploitation", "mitigation", "year", "month", "preset", "sort"].map(key => [key, $("#" + key)]));
  let snapshot = null;
  let snapshotText = null;
  let visibleCount = pageSize;
  let view = "feed";
  let loading = false;
  let searchTimer = null;
  let lastAttempt = null;
  let lastRead = null;

  function node(tag, className = "", text = "") {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== "") element.textContent = String(text);
    return element;
  }

  function requireValue(condition) {
    if (!condition) throw new Error("The saved feed does not match the supported snapshot format.");
  }

  function boundedText(value, maximum, empty = false) {
    requireValue(typeof value === "string" && value.length <= maximum && (empty || value.trim().length > 0));
    return value;
  }

  function optionalText(value, maximum) { return value == null ? null : boundedText(value, maximum, true); }

  function timestamp(value, nullable = true) {
    if (nullable && value === null) return null;
    boundedText(value, 80);
    requireValue(/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?$/.test(value));
    const date = new Date(value);
    const calendar = new Date(value.slice(0, 10) + "T00:00:00Z");
    requireValue(Number.isFinite(date.getTime()) && Number.isFinite(calendar.getTime()) && calendar.toISOString().slice(0, 10) === value.slice(0, 10));
    return value;
  }

  function list(value, limit) { requireValue(Array.isArray(value) && value.length <= limit); return value; }
  function textList(value, limit, textLimit) { return list(value, limit).map(item => boundedText(item, textLimit)); }
  function nonnegative(value) { requireValue(Number.isSafeInteger(value) && value >= 0); return value; }
  function normalized(value) { return value.normalize("NFKC").toLocaleLowerCase(); }

  function normalizeMitigation(value, key) {
    requireValue(value && cvePattern.test(key) && value.cve === key && ["ok", "failed", "pending"].includes(value.source_status) && ["PUBLISHED", "REJECTED", "UNKNOWN"].includes(value.record_state));
    requireValue(value.analysis && ["known-exploited", "review"].includes(value.analysis.priority) && ["publisher-guidance", "cisa-action", "needs-review"].includes(value.analysis.guidance_status));
    const record = {
      cve: key, title: boundedText(value.title, 2000, true), description: boundedText(value.description, 100000, true),
      source_status: value.source_status, record_state: value.record_state,
      source_updated_at: timestamp(value.source_updated_at), retrieved_at: timestamp(value.retrieved_at),
      source_attempted_at: value.source_attempted_at == null ? null : timestamp(value.source_attempted_at),
      products: list(value.products, 1000).map(product => ({
        vendor: boundedText(product.vendor, 2000, true), product: boundedText(product.product, 2000, true), default_status: optionalText(product.default_status, 100),
        versions: list(product.versions, 2000).map(version => ({
          version: optionalText(version.version, 2000), status: optionalText(version.status, 100),
          less_than: optionalText(version.less_than, 2000), less_than_or_equal: optionalText(version.less_than_or_equal, 2000),
          version_type: optionalText(version.version_type, 200)
        }))
      })),
      solutions: list(value.solutions, 1000).map(item => ({ text: boundedText(item.text, 100000, true), source_url: optionalText(item.source_url, 4000) })),
      workarounds: list(value.workarounds, 1000).map(item => ({ text: boundedText(item.text, 100000, true), source_url: optionalText(item.source_url, 4000) })),
      required_action: optionalText(value.required_action, 100000),
      required_action_source_url: optionalText(value.required_action_source_url, 4000),
      kev: value.kev === null ? null : { date_added: timestamp(value.kev.date_added), due_date: timestamp(value.kev.due_date), ransomware: optionalText(value.kev.ransomware, 200) },
      cvss: null,
      references: list(value.references, 1000).map(item => ({ label: boundedText(item.label, 1000, true), url: boundedText(item.url, 4000), kind: boundedText(item.kind, 200, true) })),
      analysis: {
        priority: value.analysis.priority, guidance_status: value.analysis.guidance_status,
        assessment: boundedText(value.analysis.assessment, 20000, true),
        steps: list(value.analysis.steps, 100).map(item => ({ title: boundedText(item.title, 2000, true), detail: boundedText(item.detail, 20000, true), evidence_url: optionalText(item.evidence_url, 4000) })),
        limitations: textList(value.analysis.limitations, 100, 20000)
      }
    };
    if (value.cvss !== null) {
      requireValue(value.cvss && (value.cvss.score === null || (typeof value.cvss.score === "number" && Number.isFinite(value.cvss.score) && value.cvss.score >= 0 && value.cvss.score <= 10)));
      record.cvss = { score: value.cvss.score, version: optionalText(value.cvss.version, 100), vector: optionalText(value.cvss.vector, 2000), source_url: optionalText(value.cvss.source_url, 4000) };
    }
    return record;
  }

  function normalize(raw) {
    requireValue(raw && raw.schema_version === 2 && Array.isArray(raw.articles) && raw.articles.length <= 8000 && Array.isArray(raw.sources) && raw.sources.length <= 200);
    timestamp(raw.generated_at, false);
    requireValue(raw.window && raw.coverage && raw.integrations && raw.refresh && raw.deduplication && raw.mitigations && typeof raw.mitigations === "object" && !Array.isArray(raw.mitigations));
    timestamp(raw.window.start, false);
    timestamp(raw.window.end, false);
    const start = new Date(raw.window.start).getTime();
    const end = new Date(raw.window.end).getTime();
    requireValue(end >= start && end - start <= 3661 * day);
    const mitigationEntries = Object.entries(raw.mitigations);
    requireValue(mitigationEntries.length <= 15000);
    const mitigations = new Map(mitigationEntries.map(([key, value]) => [key, normalizeMitigation(value, key)]));
    const ids = new Set();
    const articles = raw.articles.map(article => {
      requireValue(article && Object.hasOwn(kinds, article.kind) && Object.hasOwn(origins, article.origin) && ["known", "reported", "unknown"].includes(article.exploitation));
      const item = {
        id: boundedText(article.id, 160), title: boundedText(article.title, 1000), url: boundedText(article.url, 4000),
        source_id: boundedText(article.source_id, 160), source_name: boundedText(article.source_name, 240),
        kind: article.kind, origin: article.origin, published_at: timestamp(article.published_at), event_date: timestamp(article.event_date),
        date_basis: boundedText(article.date_basis, 1000, true), summary: boundedText(article.summary, 500, true),
        cves: textList(article.cves, 100, 80), tags: textList(article.tags, 100, 160), exploitation: article.exploitation
      };
      requireValue(!ids.has(item.id) && item.cves.every(cve => cvePattern.test(cve) && mitigations.has(cve)));
      ids.add(item.id);
      item.references = list(article.references, 50).map(reference => ({ label: boundedText(reference.label, 300), url: boundedText(reference.url, 4000) }));
      item.primary_date = item.date_basis === "event" ? item.event_date : item.published_at;
      item.date = item.primary_date === null ? null : new Date(item.primary_date);
      item.month = item.date ? item.date.toISOString().slice(0, 7) : "unknown";
      item.year = item.date ? item.date.toISOString().slice(0, 4) : "unknown";
      const records = item.cves.map(cve => mitigations.get(cve));
      const scores = records.map(record => record.cvss?.score).filter(score => typeof score === "number");
      item.score = scores.length ? Math.max(...scores) : null;
      item.cve_key = [...item.cves].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))[0] || null;
      item.search = normalized([item.title, item.summary, item.source_name, item.source_id, ...item.cves, ...item.tags, ...records.flatMap(record => [record.title, ...record.products.flatMap(product => [product.vendor, product.product])])].join("\n"));
      return item;
    });
    const sourceIds = new Set();
    const sources = raw.sources.map(source => {
      requireValue(source && ["ok", "failed", "not_fetched"].includes(source.status));
      const item = { id: boundedText(source.id, 160), name: boundedText(source.name, 240), url: boundedText(source.url, 4000), kind: boundedText(source.kind, 160), status: source.status, last_success: timestamp(source.last_success), last_attempt: timestamp(source.last_attempt), error: source.error === null ? null : boundedText(source.error, 4000, true), articles: nonnegative(source.articles) };
      requireValue(!sourceIds.has(item.id)); sourceIds.add(item.id); return item;
    });
    const coverage = { kev_records: nonnegative(raw.coverage.kev_records), curated_events: nonnegative(raw.coverage.curated_events), feed_articles: nonnegative(raw.coverage.feed_articles), notes: textList(raw.coverage.notes, 100, 4000) };
    const integrations = {};
    for (const key of ["xai", "x", "sec"]) {
      requireValue(raw.integrations[key]?.status === "not_connected");
      integrations[key] = { status: "not_connected", message: boundedText(raw.integrations[key].message, 4000, true) };
    }
    requireValue(Number.isSafeInteger(raw.refresh.requested_minutes) && raw.refresh.requested_minutes > 0 && raw.refresh.requested_minutes <= 1440 && raw.refresh.mode === "scheduled-check");
    const refresh = { requested_minutes: raw.refresh.requested_minutes, mode: raw.refresh.mode, status_url: boundedText(raw.refresh.status_url, 4000), notes: textList(raw.refresh.notes, 100, 4000) };
    return { generated_at: raw.generated_at, window: { start: raw.window.start, end: raw.window.end }, articles, sources, coverage, integrations, mitigations, refresh, deduplication: { url_duplicates_removed: nonnegative(raw.deduplication.url_duplicates_removed) } };
  }

  function safeUrl(value) {
    try {
      if (typeof value !== "string" || value.length > 4000 || /[\u0000-\u0020\u007f\\]/.test(value)) return null;
      const url = new URL(value);
      const host = url.hostname.toLowerCase().replace(/\.$/, "");
      if (url.protocol !== "https:" || url.username || url.password || url.port || !host || !host.includes(".") || host.startsWith("[") || /^(?:\d+\.)*\d+$/.test(host) || host === "localhost" || /\.(?:localhost|local|localdomain|internal|lan|home|home\.arpa|test|invalid|example)$/.test(host)) return null;
      return url.href;
    } catch (_) { return null; }
  }

  function link(label, value, className = "") {
    const url = safeUrl(value);
    if (!url) return node("span", className, label);
    const anchor = node("a", className, label);
    anchor.href = url; anchor.target = "_blank"; anchor.rel = "noopener noreferrer nofollow"; anchor.referrerPolicy = "no-referrer";
    return anchor;
  }

  function dateLabel(value, full = false) {
    return value ? new Date(value).toLocaleDateString(undefined, { day: "numeric", month: full ? "long" : "short", year: "numeric", timeZone: "UTC" }) : "Not recorded";
  }
  function stamp(value) {
    return value ? new Date(value).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" }) : "Not recorded";
  }
  function monthLabel(value) { return value === "unknown" ? "Date unknown" : new Date(value + "-01T00:00:00Z").toLocaleDateString(undefined, { month: "short", year: "numeric", timeZone: "UTC" }); }

  function calendarMonths() {
    const cursor = new Date(snapshot.window.start.slice(0, 7) + "-01T00:00:00Z");
    const end = snapshot.window.end.slice(0, 7);
    const months = [];
    while (cursor.toISOString().slice(0, 7) <= end) { months.push(cursor.toISOString().slice(0, 7)); cursor.setUTCMonth(cursor.getUTCMonth() + 1); }
    return months;
  }

  function replaceOptions(select, choices, allLabel) {
    const previous = select.value;
    const oldLabel = (select.selectedOptions[0]?.textContent || previous).replace(/ · absent from this snapshot$/, "");
    if (previous && !choices.some(choice => choice.value === previous)) choices.push({ value: previous, label: oldLabel + " · absent from this snapshot" });
    select.replaceChildren(new Option(allLabel, ""), ...choices.map(choice => new Option(choice.label, choice.value)));
    select.value = previous;
  }

  function configureFilters() {
    const sources = new Map(snapshot.sources.map(source => [source.id, source.name]));
    for (const article of snapshot.articles) if (!sources.has(article.source_id)) sources.set(article.source_id, article.source_name);
    replaceOptions(controls.source, [...sources].sort((a, b) => a[1].localeCompare(b[1])).map(([value, label]) => ({ value, label })), "All sources");
    const months = calendarMonths().map(value => ({ value, label: monthLabel(value) }));
    const years = [...new Set(calendarMonths().map(value => value.slice(0, 4)))].map(value => ({ value, label: value }));
    if (snapshot.articles.some(article => !article.date)) { months.push({ value: "unknown", label: "Date unknown" }); years.push({ value: "unknown", label: "Date unknown" }); }
    replaceOptions(controls.month, months, "All months"); replaceOptions(controls.year, years, "All years");
  }

  function guidanceStatus(record) {
    return record.record_state === "REJECTED" ? "needs-review" : record.analysis.guidance_status;
  }

  function recordMatches(record) {
    if (controls.mitigation.value === "unavailable") return record.source_status !== "ok";
    return !controls.mitigation.value || guidanceStatus(record) === controls.mitigation.value;
  }

  function matches(article, ignoreDates = false) {
    const terms = normalized(controls.search.value.trim()).split(/\s+/).filter(Boolean);
    if (!terms.every(term => article.search.includes(term)) || (controls.kind.value && controls.kind.value !== article.kind) || (controls.source.value && controls.source.value !== article.source_id) || (controls.exploitation.value && controls.exploitation.value !== article.exploitation)) return false;
    if (controls.mitigation.value === "no-cve" ? article.cves.length > 0 : controls.mitigation.value && !article.cves.some(cve => recordMatches(snapshot.mitigations.get(cve)))) return false;
    if (ignoreDates) return true;
    if ((controls.year.value && article.year !== controls.year.value) || (controls.month.value && article.month !== controls.month.value)) return false;
    const days = { day: 1, week: 7, month: 30, year: 365 }[controls.preset.value];
    if (days) {
      const last = new Date(snapshot.window.end.slice(0, 10) + "T00:00:00Z").getTime();
      return article.date !== null && article.date.getTime() >= last - (days - 1) * day && article.date.getTime() < last + day;
    }
    return true;
  }

  function setDates(year = "", month = "") {
    controls.year.value = year; controls.month.value = month; controls.preset.value = "full"; visibleCount = pageSize; render();
  }

  function timelineButton(label, count, selected, focusKey, action, className) {
    const button = node("button", className + (selected ? " selected" : "") + (count ? "" : " empty-month"));
    button.type = "button"; button.setAttribute("aria-pressed", String(selected)); button.dataset.focusKey = focusKey;
    button.setAttribute("aria-label", label + ": " + count.toLocaleString() + " entries matching non-date filters. Filter by this date.");
    button.append(node("span", "month-name", label), node("span", "month-count", count.toLocaleString()));
    button.addEventListener("click", action); return button;
  }

  function renderTimeline() {
    const candidates = snapshot.articles.filter(article => matches(article, true));
    const years = new Map(); const months = new Map();
    for (const article of candidates) { years.set(article.year, (years.get(article.year) || 0) + 1); months.set(article.month, (months.get(article.month) || 0) + 1); }
    const allYears = [...new Set(calendarMonths().map(month => month.slice(0, 4)))];
    const yearButtons = [timelineButton("All history", candidates.length, !controls.year.value && !controls.month.value && controls.preset.value === "full", "year-all", () => setDates(), "year-button")];
    for (const year of allYears) {
      const button = timelineButton(year, years.get(year) || 0, controls.year.value === year, "year-" + year, () => setDates(controls.year.value === year ? "" : year), "year-button");
      if (year === snapshot.window.start.slice(0, 4) || year === snapshot.window.end.slice(0, 4)) button.title = "The archive boundary may cover only part of this calendar year.";
      yearButtons.push(button);
    }
    if (snapshot.articles.some(article => !article.date)) yearButtons.push(timelineButton("Unknown date", years.get("unknown") || 0, controls.year.value === "unknown", "year-unknown", () => setDates("unknown", "unknown"), "year-button"));
    $("#year-timeline").replaceChildren(...yearButtons);
    const shortcutYear = controls.year.value && controls.year.value !== "unknown" ? controls.year.value : snapshot.window.end.slice(0, 4);
    $("#month-context").textContent = controls.year.value === "unknown" ? "Unknown primary dates selected" : "Month shortcuts · " + shortcutYear + (controls.year.value ? "" : " · choose a year above for older months");
    const monthButtons = controls.year.value === "unknown" ? [] : calendarMonths().filter(month => month.startsWith(shortcutYear + "-")).map(month => {
      const button = timelineButton(new Date(month + "-01T00:00:00Z").toLocaleDateString(undefined, { month: "short", timeZone: "UTC" }), months.get(month) || 0, controls.month.value === month, "month-" + month, () => setDates(month.slice(0, 4), controls.month.value === month ? "" : month), "month-button");
      button.setAttribute("aria-label", monthLabel(month) + ": " + (months.get(month) || 0).toLocaleString() + " entries matching non-date filters. Filter by this month.");
      const lastDay = new Date(Date.UTC(Number(month.slice(0, 4)), Number(month.slice(5)), 0)).getUTCDate();
      if ((month === snapshot.window.start.slice(0, 7) && snapshot.window.start.slice(8, 10) !== "01") || (month === snapshot.window.end.slice(0, 7) && Number(snapshot.window.end.slice(8, 10)) !== lastDay)) { button.classList.add("partial"); button.title = "Partial month within the archive window."; }
      return button;
    });
    $("#month-timeline").replaceChildren(...monthButtons);
    const presetDays = { day: 1, week: 7, month: 30, year: 365 }[controls.preset.value];
    $("#date-filter-note").textContent = presetDays ? "Preset: " + presetDays + " calendar day" + (presetDays === 1 ? "" : "s") + " ending " + dateLabel(snapshot.window.end) + " UTC; unknown primary dates excluded." : "Archive: " + dateLabel(snapshot.window.start) + " — " + dateLabel(snapshot.window.end) + ". Year/month filters use primary dates; unknown dates remain explicit.";
  }

  function cveButton(cve, focusKey) {
    const button = node("button", "article-tag cve-tag", cve);
    button.type = "button"; button.dataset.focusKey = focusKey; button.setAttribute("aria-label", "Inspect source-led guidance for " + cve);
    button.addEventListener("click", () => openMitigation(cve)); return button;
  }

  function scoreLabel(record) {
    return typeof record.cvss?.score === "number" ? record.cvss.score.toFixed(1) + " · CVSS " + (record.cvss.version || "version unknown") : "CVSS unknown";
  }

  function articleCard(article, openDetails) {
    const card = node("article", "article-card card-kind-" + article.kind + (article.exploitation === "known" ? " card-known-exploitation" : "")); card.dataset.entryId = article.id;
    const top = node("div", "article-topline");
    const date = node("div", "article-date", article.date ? dateLabel(article.primary_date) : "Date unknown");
    date.append(node("span", "", !article.date ? "UNKNOWN" : article.date_basis === "event" ? "EVENT DATE" : article.date_basis === "filing" ? "FILED" : article.kind === "kev" ? "CATALOG ADDED" : article.date_basis === "publisher update" ? "UPDATED" : "PUBLISHED"));
    top.append(node("span", "kind-badge kind-" + article.kind, kinds[article.kind]), date);
    const title = node("h3"); const titleLink = link(article.title, article.url, "article-title"); titleLink.dataset.focusKey = article.id + "-title"; title.append(titleLink);
    card.append(top, title); if (article.summary) card.append(node("p", "article-summary", article.summary));
    const tags = node("div", "article-tags");
    for (const cve of article.cves.slice(0, 6)) tags.append(cveButton(cve, article.id + "-" + cve));
    for (const tag of article.tags.slice(0, 3)) tags.append(node("span", "article-tag", tag));
    if (tags.children.length) card.append(tags);
    if (article.cves.length) {
      const counts = new Map();
      for (const cve of article.cves) { const status = guidanceStatus(snapshot.mitigations.get(cve)); counts.set(status, (counts.get(status) || 0) + 1); }
      const guidance = node("div", "guidance-summary", [...counts].map(([status, count]) => count + " " + guidanceLabels[status].toLocaleLowerCase()).join(" / "));
      const incomplete = article.cves.filter(cve => snapshot.mitigations.get(cve).source_status !== "ok").length;
      if (incomplete) guidance.append(node("span", "row-secondary", incomplete + " CNA lookup" + (incomplete === 1 ? "" : "s") + " pending / failed; CISA actions shown separately."));
      if (article.score !== null) {
        const record = article.cves.map(cve => snapshot.mitigations.get(cve)).find(item => item.cvss?.score === article.score);
        guidance.append(node("span", "score-summary", scoreLabel(record) + (article.cves.length > 1 ? " · highest linked score" : "")));
      }
      card.append(guidance);
    } else card.append(node("p", "guidance-summary", "No CVE linked in this entry."));
    const bottom = node("div", "article-bottom");
    const source = node("div", "article-source"); source.append(node("span", "", article.source_name), node("span", "article-origin", origins[article.origin]));
    const exploitation = { known: "Known exploitation recorded by the source", reported: "Exploitation reported; read the source context", unknown: "Exploitation status unknown in this entry" }[article.exploitation];
    bottom.append(source, node("p", "exploitation exploitation-" + article.exploitation, exploitation));
    const detail = node("details", "article-detail"); detail.open = openDetails.has(article.id);
    const summary = node("summary", "", "Sources & date context" + (article.cves.length > 6 ? " · all " + article.cves.length + " CVEs" : "")); summary.dataset.focusKey = article.id + "-details";
    detail.append(summary, node("p", "", "Date basis: " + (article.date_basis || "Not specified.")), node("p", "", (article.date_basis === "filing" ? "SEC filing date: " : article.kind === "kev" ? "Catalog addition date: " : article.date_basis === "publisher update" ? "Publisher update date: " : "Publisher date: ") + dateLabel(article.published_at)), node("p", "", "Event date: " + dateLabel(article.event_date)));
    if (article.cves.length > 6) { const allCves = node("div", "article-tags"); for (const cve of article.cves) allCves.append(cveButton(cve, article.id + "-all-" + cve)); detail.append(allCves); }
    if (article.tags.length > 3) detail.append(node("p", "", "All topic tags: " + article.tags.join(", ")));
    if (article.kind === "kev") detail.append(node("p", "", "CISA catalog addition is separate from disclosure and exploitation dates. This entry is not an incident report."));
    if (article.kind === "filing") detail.append(node("p", "", "This selected SEC cyber-related filing is a disclosure record. Its filing date is not the incident date; not every Form 8-K concerns a cyber incident."));
    const references = node("ul"); const original = node("li"); const originalLink = link("Original publisher record ↗", article.url); originalLink.dataset.focusKey = article.id + "-original"; original.append(originalLink); references.append(original);
    for (const reference of article.references) { const item = node("li"); const referenceLink = link(reference.label + " ↗", reference.url); referenceLink.dataset.focusKey = article.id + "-reference-" + reference.url; item.append(referenceLink); references.append(item); }
    detail.append(references); bottom.append(detail); card.append(bottom); return card;
  }

  function compareNullable(a, b, direction, numeric = false) {
    if (a === null && b !== null) return 1;
    if (a !== null && b === null) return -1;
    if (a === null && b === null) return 0;
    return (numeric ? a - b : a.localeCompare(b, undefined, { numeric: true, sensitivity: "base" })) * direction;
  }

  function sortRows(rows) {
    const [key, order] = controls.sort.value.split("-");
    const direction = order === "desc" ? -1 : 1;
    return rows.sort((a, b) => {
      let result = 0;
      if (key === "date") result = compareNullable(a.date?.getTime() ?? null, b.date?.getTime() ?? null, direction, true);
      else if (key === "cvss") result = compareNullable(a.score, b.score, direction, true);
      else if (key === "cve") result = compareNullable(a.cve_key, b.cve_key, direction);
      else if (key === "title") result = a.title.localeCompare(b.title) * direction;
      else if (key === "source") result = a.source_name.localeCompare(b.source_name) * direction;
      return result || a.title.localeCompare(b.title) || a.id.localeCompare(b.id);
    });
  }

  function cveRows(articles) {
    const grouped = new Map();
    for (const article of articles) for (const cve of new Set(article.cves)) {
      const record = snapshot.mitigations.get(cve);
      if (!recordMatches(record)) continue;
      if (!grouped.has(cve)) grouped.set(cve, { id: cve, cve_key: cve, record, title: record.title || cve, score: record.cvss?.score ?? null, date: null, sources: new Set(), count: 0 });
      const row = grouped.get(cve); row.count++; row.sources.add(article.source_name);
      if (article.date && (!row.date || article.date > row.date)) row.date = article.date;
    }
    return [...grouped.values()].map(row => ({ ...row, source_name: [...row.sources].sort().join(", ") }));
  }

  function renderCveRegister(rows) {
    const table = node("table", "cve-table");
    const caption = node("caption", "", "Unique CVEs linked by matching entries. The guidance filter also applies per CVE. Entry date is the latest matching entry date; CVSS versions are not normalized.");
    const head = node("thead"); const headings = node("tr");
    for (const label of ["CVE / source record", "Guidance", "CVSS / version", "Matching context"]) { const cell = node("th", "", label); cell.scope = "col"; headings.append(cell); }
    head.append(headings); const body = node("tbody");
    for (const row of rows) {
      const tr = node("tr");
      const identity = node("td"); identity.append(cveButton(row.id, "register-" + row.id), node("p", "cve-row-title", row.title));
      if (row.record.record_state !== "PUBLISHED") identity.append(node("span", "record-state", row.record.record_state + " record"));
      const status = node("td"); status.append(node("span", "guidance-badge guidance-" + guidanceStatus(row.record), guidanceLabels[guidanceStatus(row.record)]));
      if (row.record.source_status !== "ok") status.append(node("span", "row-secondary", "CNA lookup: " + row.record.source_status));
      if (row.record.analysis.priority === "known-exploited") status.append(node("span", "row-secondary", "Known exploited"));
      const score = node("td", "cve-score", scoreLabel(row.record));
      const context = node("td"); context.append(node("span", "", row.count + " matching entr" + (row.count === 1 ? "y" : "ies")), node("span", "row-secondary", row.source_name), node("span", "row-secondary", row.date ? "Entry date: " + dateLabel(row.date.toISOString()) : "Entry date unknown"));
      tr.append(identity, status, score, context); body.append(tr);
    }
    table.append(caption, head, body); $("#cve-register").replaceChildren(table);
  }

  function renderStats(articles) {
    const counts = items => ({ exploited: items.filter(item => item.exploitation === "known").length, sources: new Set(items.map(item => item.source_id)).size, cves: new Set(items.flatMap(item => item.cves)).size });
    const filtered = counts(articles); const totals = counts(snapshot.articles);
    for (const [key, value, total] of [["matches", articles.length, snapshot.articles.length], ["exploited", filtered.exploited, totals.exploited], ["cves", filtered.cves, totals.cves], ["sources", filtered.sources, totals.sources]]) {
      $("#count-" + key).textContent = value.toLocaleString(); $("#total-" + key).textContent = "of " + total.toLocaleString() + " in the whole snapshot";
    }
  }

  function render() {
    if (!snapshot) return;
    const focusedKey = document.activeElement?.dataset.focusKey;
    const timelineScroll = { years: $("#year-timeline").scrollLeft, months: $("#month-timeline").scrollLeft };
    const articles = snapshot.articles.filter(article => matches(article));
    renderStats(articles); renderTimeline();
    const rows = sortRows(view === "cves" ? cveRows(articles) : articles);
    const visible = rows.slice(0, visibleCount);
    const openDetails = new Set([...document.querySelectorAll(".article-card")].filter(card => card.querySelector("details")?.open).map(card => card.dataset.entryId));
    $("#articles").hidden = view !== "feed"; $("#cve-register").hidden = view !== "cves";
    if (view === "feed") $("#articles").replaceChildren(...visible.map(article => articleCard(article, openDetails)));
    else renderCveRegister(visible);
    $("#view-feed").setAttribute("aria-pressed", String(view === "feed")); $("#view-cves").setAttribute("aria-pressed", String(view === "cves"));
    $("#view-note").textContent = view === "feed" ? "Original stories and advisory records" : "Unique CVEs in matching entries · guidance is not exposure confirmation";
    $("#results-status").textContent = articles.length.toLocaleString() + " matching entries / " + snapshot.articles.length.toLocaleString() + " total" + (view === "cves" ? " · " + rows.length.toLocaleString() + " matching CVEs" : "");
    $("#empty-state").hidden = rows.length > 0;
    $("#empty-title").textContent = !snapshot.articles.length ? "This snapshot has no entries yet" : view === "cves" ? "No linked CVEs match" : "No matching intelligence";
    $("#empty-message").textContent = !snapshot.articles.length ? "Inspect the source ledger for collection outcomes, then read a later snapshot." : view === "cves" && articles.length ? "Matching stories may have no CVE identifier, or their CVEs do not match the guidance filter. The intelligence stream still contains these stories." : "Broaden the search or clear a date, source, exploitation or guidance filter. Source collection gaps remain in the ledger.";
    $("#empty-reset").hidden = !snapshot.articles.length;
    $("#load-more").hidden = visible.length >= rows.length;
    $("#load-more").textContent = "Load " + Math.min(pageSize, rows.length - visible.length) + " more " + (view === "cves" ? "CVEs" : "entries") + " +";
    const undated = articles.filter(article => !article.date).length;
    $("#page-status").textContent = "Showing " + visible.length.toLocaleString() + " / " + rows.length.toLocaleString() + (view === "cves" ? " CVEs" : " entries") + " · " + undated.toLocaleString() + " matching entries have unknown dates · Unknown sort values last";
    $("#year-timeline").scrollLeft = timelineScroll.years; $("#month-timeline").scrollLeft = timelineScroll.months;
    if (focusedKey) [...document.querySelectorAll("[data-focus-key]")].find(element => element.dataset.focusKey === focusedKey)?.focus({ preventScroll: true });
  }

  function renderSources() {
    $("#source-dialog-stamp").textContent = "Snapshot generated " + stamp(snapshot.generated_at) + ". Source collection dates are separate.";
    $("#source-ledger").replaceChildren(...snapshot.sources.map(source => {
      const card = node("article", "ledger-source"); const heading = node("div", "ledger-source-heading");
      const title = node("h3"); title.append(link(source.name, source.url));
      const states = { ok: "FETCH SUCCEEDED", failed: "FETCH FAILED", not_fetched: "NOT FETCHED" };
      heading.append(title, node("span", "source-status" + (source.status === "failed" ? " failed" : source.status === "not_fetched" ? " not-fetched" : ""), states[source.status]));
      card.append(heading, node("p", "", source.kind + " · Reported entry count: " + source.articles.toLocaleString()), node("p", "", "Last successful collection: " + stamp(source.last_success)), node("p", "", "Last attempt: " + stamp(source.last_attempt)));
      if (source.error) card.append(node("p", "source-error", source.error)); return card;
    }));
    if (!snapshot.sources.length) $("#source-ledger").append(node("p", "ledger-empty", "No source-fetch records were supplied. Publisher labels do not establish collection health."));
  }

  function section(title) { const item = node("section", "mitigation-section"); item.append(node("h3", "", title)); return item; }

  function guidanceItems(title, values) {
    const item = section(title);
    if (!values.length) item.append(node("p", "muted", "No " + title.toLocaleLowerCase() + " supplied by this saved source record. Absence is not evidence that none exist."));
    if (values.length) item.append(node("p", "muted", "Bounded source excerpts; consult the original guidance for complete conditions."));
    for (const value of values) { const block = node("div", "guidance-item"); block.append(node("p", "", value.text || "Source text not supplied.")); if (value.source_url) block.append(link("Original guidance ↗", value.source_url)); item.append(block); }
    return item;
  }

  function openMitigation(cve) {
    const record = snapshot?.mitigations.get(cve);
    if (!record) { showError("This CVE is not present in the current saved snapshot. No external lookup was made."); return; }
    const dialog = $("#mitigation-dialog");
    if ($("#source-dialog").open || dialog.open) return;
    $("#mitigation-title").textContent = cve;
    $("#mitigation-stamp").textContent = "Snapshot generated " + stamp(snapshot.generated_at) + " · CNA source updated " + stamp(record.source_updated_at) + " · Retrieved " + stamp(record.retrieved_at) + " · Last CNA attempt " + stamp(record.source_attempted_at) + ". This open detail stays on that snapshot; close and reopen for newer data.";
    const content = $("#mitigation-content"); const overview = section(record.title || "Source record title not supplied");
    const badges = node("div", "mitigation-badges"); badges.append(node("span", "guidance-badge guidance-" + guidanceStatus(record), guidanceLabels[guidanceStatus(record)]), node("span", "record-state", record.record_state + " · CNA " + record.source_status.toUpperCase()), node("span", "cve-score", scoreLabel(record)));
    overview.append(badges);
    if (record.record_state === "REJECTED") overview.append(node("p", "notice", "This CVE record is rejected. Review its original disposition and do not treat the identifier as a confirmed active vulnerability."));
    if (record.source_status !== "ok") overview.append(node("p", "notice", "CNA enrichment is " + record.source_status + ". Retained CNA information keeps its original retrieval date. CISA action data is collected separately; a missing CNA record does not negate a displayed CISA action."));
    overview.append(node("p", "", record.description || "Description not supplied in this saved record."));
    if (record.cvss?.vector) overview.append(node("p", "cvss-vector", "Vector: " + record.cvss.vector));
    if (record.cvss?.source_url) overview.append(link("CVSS source ↗", record.cvss.source_url));
    const assessment = section("Assessment & review steps");
    assessment.append(node("p", "", record.analysis.assessment || "No assessment supplied."));
    const steps = node("ol", "review-steps");
    for (const step of record.analysis.steps) { const item = node("li"); item.append(node("strong", "", step.title), node("p", "", step.detail)); if (step.evidence_url) item.append(link("Supporting source ↗", step.evidence_url)); steps.append(item); }
    if (steps.children.length) assessment.append(steps); else assessment.append(node("p", "muted", "No review steps supplied."));
    const limitations = node("ul", "record-limitations"); for (const text of record.analysis.limitations) limitations.append(node("li", "", text)); if (limitations.children.length) assessment.append(limitations);
    const products = section("Source-reported products & version ranges");
    products.append(node("p", "muted", "These are bounded publisher excerpts. Affected / unaffected statuses and ranges are not verified installed versions or a list of fixed releases. Consult the original record for omitted conditions."));
    for (const product of record.products) {
      const item = node("details", "product-record"); item.append(node("summary", "", (product.vendor || "Vendor unknown") + " / " + (product.product || "Product unknown") + " · " + product.versions.length + " version statements"));
      item.append(node("p", "muted", "Source default status: " + (product.default_status || "unknown")));
      const versions = node("ul");
      for (const version of product.versions) versions.append(node("li", "", (version.version || "Version not specified") + (version.less_than ? " to < " + version.less_than : "") + (version.less_than_or_equal ? " to ≤ " + version.less_than_or_equal : "") + " · status: " + (version.status || "unknown") + (version.version_type ? " · range type: " + version.version_type : "")));
      if (versions.children.length) item.append(versions); else item.append(node("p", "muted", "No version ranges supplied.")); products.append(item);
    }
    if (!record.products.length) products.append(node("p", "muted", "No product/version statements supplied in this snapshot."));
    const action = section("CISA catalog action");
    action.append(node("p", "", record.required_action || "No CISA required action supplied for this record."));
    if (record.required_action_source_url) action.append(link("CISA action source ↗", record.required_action_source_url));
    if (record.kev) action.append(node("p", "", "Catalog added: " + dateLabel(record.kev.date_added) + " · Federal catalog due date: " + dateLabel(record.kev.due_date) + " · Ransomware association: " + (record.kev.ransomware || "Unknown")), node("p", "guidance-boundary", "The CISA catalog due date applies to the federal catalog requirement. It is not a deadline assigned to you. Catalog addition is not the disclosure or exploitation date."));
    const references = section("Original references");
    const referenceList = node("ul");
    for (const reference of record.references) { const item = node("li"); item.append(link((reference.label || "Original reference") + (reference.kind ? " · " + reference.kind : "") + " ↗", reference.url)); referenceList.append(item); }
    if (referenceList.children.length) references.append(referenceList); else references.append(node("p", "muted", "No original reference links supplied."));
    content.replaceChildren(overview, assessment, guidanceItems("Solutions", record.solutions), guidanceItems("Workarounds", record.workarounds), action, products, references);
    try { dialog.showModal(); dialog.scrollTop = 0; } catch (_) { showError("The guidance dialog could not open in this document. No external lookup or device action occurred."); }
  }

  function renderFreshness() {
    if (!snapshot) return;
    const age = Date.now() - new Date(snapshot.generated_at).getTime(); const stale = age > day;
    $("#snapshot-status").textContent = age < -300000 ? "Snapshot clock differs" : stale ? "Snapshot older than 24 hours" : "Saved snapshot";
    $("#snapshot-mark").classList.toggle("stale", stale || age < -300000);
  }

  function renderSnapshot() {
    renderFreshness();
    $("#generated-at").textContent = "Generated " + stamp(snapshot.generated_at);
    $("#archive-window").textContent = dateLabel(snapshot.window.start) + " — " + dateLabel(snapshot.window.end);
    const coverage = [["KEV catalog records", snapshot.coverage.kev_records], ["Curated archive events", snapshot.coverage.curated_events], ["Publisher feed articles", snapshot.coverage.feed_articles], ["Linked CVE records", snapshot.mitigations.size], ["URL duplicates removed", snapshot.deduplication.url_duplicates_removed]];
    $("#coverage").replaceChildren(...coverage.map(([label, count]) => { const item = node("div"); item.append(node("dt", "", label), node("dd", "", count.toLocaleString())); return item; }));
    const ok = snapshot.sources.filter(source => source.status === "ok").length;
    const failed = snapshot.sources.filter(source => source.status === "failed").length;
    const unfetched = snapshot.sources.filter(source => source.status === "not_fetched").length;
    $("#source-health-summary").textContent = snapshot.sources.length ? "Recorded source outcomes: " + ok + " successful / " + failed + " failed / " + unfetched + " not fetched." : "Source collection outcomes were not supplied.";
    $("#coverage-notes").replaceChildren(...[...snapshot.coverage.notes, ...snapshot.refresh.notes].map(note => node("li", "", note)));
    if (!$("#coverage-notes").children.length) $("#coverage-notes").append(node("li", "", "No additional notes supplied."));
    $("#integrations").replaceChildren(...[["xai", "Grok / xAI"], ["x", "X"], ["sec", "SEC cyber filings"]].map(([key, name]) => { const item = node("div", "integration-row"); const heading = node("div", "integration-heading"); heading.append(node("span", "", name), node("span", "integration-state", "NOT CONNECTED")); item.append(heading, node("p", "", snapshot.integrations[key].message)); return item; }));
    const refresh = $("#refresh-policy");
    refresh.replaceChildren(node("span", "", "Collection requests a " + snapshot.refresh.requested_minutes + "-minute schedule; execution and deployment may be delayed. "));
    const statusUrl = safeUrl(snapshot.refresh.status_url);
    if (statusUrl) {
      const url = new URL(statusUrl);
      if (url.hostname === "github.com" && /^\/teamstarwolf\/intelligence-hub\/actions(?:\/|$)/i.test(url.pathname)) refresh.append(link("Collection workflow ↗", statusUrl));
    }
    for (const button of document.querySelectorAll("[data-open-sources]")) button.disabled = false;
    // Open dialogs retain their original snapshot and scroll position until explicitly reopened.
  }

  function showError(message) { $("#feed-error").hidden = false; $("#feed-error-message").textContent = message; }

  async function readFeed(response) {
    if (!response.ok) throw new Error("The feed snapshot could not be read (HTTP " + response.status + ").");
    const length = Number(response.headers.get("content-length"));
    if (Number.isFinite(length) && length > maximumFeedBytes) throw new Error("The snapshot exceeds the supported 16 MiB download size.");
    let bytes;
    if (response.body) {
      const reader = response.body.getReader(); const chunks = []; let total = 0;
      while (true) { const { done, value } = await reader.read(); if (done) break; total += value.byteLength; if (total > maximumFeedBytes) { await reader.cancel(); throw new Error("The snapshot exceeds the supported 16 MiB download size."); } chunks.push(value); }
      bytes = new Uint8Array(total); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    } else { bytes = new Uint8Array(await response.arrayBuffer()); if (bytes.byteLength > maximumFeedBytes) throw new Error("The snapshot exceeds the supported 16 MiB download size."); }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return { value: JSON.parse(text), text };
  }

  async function load() {
    if (loading) return;
    loading = true; lastAttempt = new Date().toISOString();
    $("#reload").disabled = true; $("#reload").textContent = "Reading snapshot…"; $("#loading-cards").hidden = Boolean(snapshot);
    $("#poll-status").textContent = "Checking the saved snapshot on this site…";
    const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 45000);
    try {
      const response = await fetch("./data/feed.json", { credentials: "omit", cache: "no-store", redirect: "error", signal: controller.signal });
      const result = await readFeed(response);
      const changed = snapshotText !== result.text;
      const value = changed ? normalize(result.value) : snapshot;
      lastRead = new Date().toISOString();
      $("#feed-error").hidden = true;
      if (changed) {
        const scroll = { x: window.scrollX, y: window.scrollY, years: $("#year-timeline").scrollLeft, months: $("#month-timeline").scrollLeft, register: $("#cve-register").scrollLeft };
        const focused = document.activeElement?.dataset.focusKey;
        snapshot = value; snapshotText = result.text;
        configureFilters(); renderSnapshot(); render();
        $("#year-timeline").scrollLeft = scroll.years; $("#month-timeline").scrollLeft = scroll.months;
        $("#cve-register").scrollLeft = scroll.register;
        if (focused) {
          const target = [...document.querySelectorAll("[data-focus-key]")].find(element => element.dataset.focusKey === focused);
          (target || $("#results-status")).focus({ preventScroll: true });
        }
        window.scrollTo({ left: scroll.x, top: scroll.y, behavior: "instant" });
      } else renderFreshness();
      $("#poll-status").textContent = "Browser read " + stamp(lastRead) + " · " + (changed ? "snapshot updated" : "same saved snapshot") + " · Checks every 5 minutes while visible; publishers are not contacted by this browser.";
    } catch (error) {
      showError((error.name === "AbortError" ? "The snapshot read timed out." : error instanceof SyntaxError ? "The saved feed is not valid JSON." : error.message || "The saved feed could not load.") + (snapshot ? " The prior snapshot generated " + stamp(snapshot.generated_at) + " remains displayed with its original dates." : " No feed data is displayed. Read a later valid snapshot."));
      $("#poll-status").textContent = "Browser check failed " + stamp(lastAttempt) + (lastRead ? " · Last successful read " + stamp(lastRead) : " · No successful snapshot read this session");
      if (!snapshot) { $("#snapshot-status").textContent = "Snapshot unavailable"; $("#snapshot-mark").classList.add("stale"); $("#results-status").textContent = "No snapshot loaded · Counts and source outcomes are unknown"; }
    } finally {
      clearTimeout(timeout); loading = false; $("#reload").disabled = false; $("#reload").textContent = "Reload snapshot ↻"; $("#loading-cards").hidden = true;
    }
  }

  function reset() {
    clearTimeout(searchTimer);
    for (const control of [controls.search, controls.kind, controls.source, controls.exploitation, controls.mitigation, controls.year, controls.month]) control.value = "";
    controls.preset.value = "full"; controls.sort.value = "date-desc"; visibleCount = pageSize; render();
  }

  $("#filters").addEventListener("submit", event => { event.preventDefault(); clearTimeout(searchTimer); visibleCount = pageSize; render(); });
  controls.search.addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { visibleCount = pageSize; render(); }, 150); });
  for (const select of [controls.kind, controls.source, controls.exploitation, controls.mitigation, controls.sort]) select.addEventListener("change", () => { visibleCount = pageSize; render(); });
  controls.year.addEventListener("change", () => { controls.month.value = ""; controls.preset.value = "full"; visibleCount = pageSize; render(); });
  controls.month.addEventListener("change", () => { controls.year.value = controls.month.value ? controls.month.value.slice(0, 4) : controls.year.value; if (controls.month.value === "unknown") controls.year.value = "unknown"; controls.preset.value = "full"; visibleCount = pageSize; render(); });
  controls.preset.addEventListener("change", () => { controls.year.value = ""; controls.month.value = ""; visibleCount = pageSize; render(); });
  $("#clear-dates").addEventListener("click", () => setDates());
  $("#reset").addEventListener("click", reset); $("#empty-reset").addEventListener("click", reset); $("#reload").addEventListener("click", load);
  $("#load-more").addEventListener("click", () => { visibleCount += pageSize; render(); });
  for (const [id, mode] of [["#view-feed", "feed"], ["#view-cves", "cves"]]) $(id).addEventListener("click", () => { view = mode; visibleCount = pageSize; render(); });
  for (const button of document.querySelectorAll("[data-open-sources]")) button.addEventListener("click", () => {
    if (!snapshot || $("#mitigation-dialog").open || $("#source-dialog").open) return;
    renderSources(); try { $("#source-dialog").showModal(); $("#source-dialog").scrollTop = 0; } catch (_) { showError("The source ledger could not open in this document. The displayed snapshot is unchanged."); }
  });
  $("#close-sources").addEventListener("click", () => $("#source-dialog").close());
  $("#close-mitigation").addEventListener("click", () => $("#mitigation-dialog").close());
  document.addEventListener("visibilitychange", () => { if (!document.hidden) { renderFreshness(); if (!lastAttempt || Date.now() - new Date(lastAttempt).getTime() >= pollInterval) load(); } });
  setInterval(() => { if (!document.hidden && (!lastAttempt || Date.now() - new Date(lastAttempt).getTime() >= pollInterval)) load(); }, pollInterval);
  setInterval(renderFreshness, 60000);
  load();
})();
