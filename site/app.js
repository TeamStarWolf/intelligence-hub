"use strict";

(() => {
  const $ = selector => document.querySelector(selector);
  const kinds = { advisory: "ADVISORY", research: "RESEARCH", reporting: "REPORTING", incident: "INCIDENT", kev: "CISA KEV" };
  const origins = { "publisher-feed": "PUBLISHER FEED", "cisa-kev": "CATALOG RECORD", "library-curation": "CURATED ARCHIVE" };
  const pageSize = 24;
  const maximumFeedBytes = 16 * 1024 * 1024;
  const controls = { search: $("#search"), kind: $("#kind"), source: $("#source"), month: $("#month"), sort: $("#sort") };
  let snapshot = null;
  let visibleCount = pageSize;
  let loading = false;
  let searchTimer = null;

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

  function timestamp(value, nullable = true) {
    if (nullable && value === null) return null;
    boundedText(value, 80);
    requireValue(/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))?$/.test(value));
    const day = new Date(value.slice(0, 10) + "T00:00:00Z");
    const parsed = new Date(value);
    requireValue(Number.isFinite(parsed.getTime()) && Number.isFinite(day.getTime()) && day.toISOString().slice(0, 10) === value.slice(0, 10));
    return value;
  }

  function textList(value, limit, textLimit) {
    requireValue(Array.isArray(value) && value.length <= limit);
    return value.map(item => boundedText(item, textLimit));
  }

  function nonnegative(value) { requireValue(Number.isSafeInteger(value) && value >= 0); return value; }

  function normalize(raw) {
    requireValue(raw && raw.schema_version === 1 && Array.isArray(raw.articles) && raw.articles.length <= 20000 && Array.isArray(raw.sources) && raw.sources.length <= 200);
    timestamp(raw.generated_at, false);
    requireValue(raw.window && raw.coverage && raw.integrations);
    timestamp(raw.window.start, false);
    timestamp(raw.window.end, false);
    const start = new Date(raw.window.start).getTime();
    const end = new Date(raw.window.end).getTime();
    requireValue(end >= start && end - start <= 732 * 86400000);
    const ids = new Set();
    const articles = raw.articles.map(article => {
      requireValue(article && Object.hasOwn(kinds, article.kind) && Object.hasOwn(origins, article.origin) && ["known", "reported", "unknown"].includes(article.exploitation));
      const item = { id: boundedText(article.id, 160), title: boundedText(article.title, 1000), url: boundedText(article.url, 4000), source_id: boundedText(article.source_id, 160), source_name: boundedText(article.source_name, 240), kind: article.kind, origin: article.origin, published_at: timestamp(article.published_at), event_date: timestamp(article.event_date), date_basis: boundedText(article.date_basis, 1000, true), summary: boundedText(article.summary, 500, true), cves: textList(article.cves, 100, 80), tags: textList(article.tags, 100, 160), exploitation: article.exploitation };
      requireValue(!ids.has(item.id) && Array.isArray(article.references) && article.references.length <= 50);
      ids.add(item.id);
      item.references = article.references.map(reference => ({ label: boundedText(reference.label, 300), url: boundedText(reference.url, 4000) }));
      item.primary_date = item.date_basis === "event" ? item.event_date : item.published_at;
      item.date = item.primary_date === null ? null : new Date(item.primary_date);
      item.month = item.date ? item.date.toISOString().slice(0, 7) : "unknown";
      item.search = [item.title, item.summary, item.source_name, item.source_id, ...item.cves, ...item.tags].join("\n").normalize("NFKC").toLocaleLowerCase();
      return item;
    });
    const sourceIds = new Set();
    const sources = raw.sources.map(source => {
      requireValue(source && ["ok", "failed", "not_fetched"].includes(source.status));
      const item = { id: boundedText(source.id, 160), name: boundedText(source.name, 240), url: boundedText(source.url, 4000), kind: boundedText(source.kind, 160), status: source.status, last_success: timestamp(source.last_success), last_attempt: timestamp(source.last_attempt), error: source.error === null ? null : boundedText(source.error, 4000, true), articles: nonnegative(source.articles) };
      requireValue(!sourceIds.has(item.id));
      sourceIds.add(item.id);
      return item;
    });
    const coverage = { kev_records: nonnegative(raw.coverage.kev_records), curated_events: nonnegative(raw.coverage.curated_events), feed_articles: nonnegative(raw.coverage.feed_articles), notes: textList(raw.coverage.notes, 100, 4000) };
    const integrations = {};
    for (const key of ["xai", "x"]) {
      requireValue(raw.integrations[key]?.status === "not_connected");
      integrations[key] = { status: "not_connected", message: boundedText(raw.integrations[key].message, 4000, true) };
    }
    return { generated_at: raw.generated_at, window: { start: raw.window.start, end: raw.window.end }, articles, sources, coverage, integrations };
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
    anchor.href = url;
    anchor.target = "_blank";
    anchor.rel = "noopener noreferrer nofollow";
    anchor.referrerPolicy = "no-referrer";
    return anchor;
  }

  function dateLabel(value, full = false) {
    if (!value) return "Not recorded";
    return new Date(value).toLocaleDateString(undefined, { day: "numeric", month: full ? "long" : "short", year: "numeric", timeZone: "UTC" });
  }

  function stamp(value) {
    if (!value) return "Not recorded";
    return new Date(value).toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC", timeZoneName: "short" });
  }

  function monthLabel(value) {
    return value === "unknown" ? "Date unknown" : new Date(value + "-01T00:00:00Z").toLocaleDateString(undefined, { month: "short", year: "numeric", timeZone: "UTC" });
  }

  function calendarMonths() {
    const first = new Date(snapshot.window.start);
    const last = new Date(snapshot.window.end);
    const months = new Set(snapshot.articles.filter(article => article.date).map(article => article.month));
    const cursor = new Date(Date.UTC(first.getUTCFullYear(), first.getUTCMonth(), 1));
    while (cursor <= last) {
      months.add(cursor.toISOString().slice(0, 7));
      cursor.setUTCMonth(cursor.getUTCMonth() + 1);
    }
    return [...months].sort();
  }

  function replaceOptions(select, choices, allLabel) {
    const previous = select.value;
    select.replaceChildren(new Option(allLabel, ""), ...choices.map(choice => new Option(choice.label, choice.value)));
    if (choices.some(choice => choice.value === previous)) select.value = previous;
  }

  function configureFilters() {
    const sources = new Map(snapshot.sources.map(source => [source.id, source.name]));
    for (const article of snapshot.articles) if (!sources.has(article.source_id)) sources.set(article.source_id, article.source_name);
    replaceOptions(controls.source, [...sources].sort((a, b) => a[1].localeCompare(b[1])).map(([value, label]) => ({ value, label })), "All sources");
    const months = calendarMonths().map(value => ({ value, label: monthLabel(value) }));
    if (snapshot.articles.some(article => !article.date)) months.push({ value: "unknown", label: "Date unknown" });
    replaceOptions(controls.month, months, "All months");
  }

  function matches(article, ignoreMonth = false) {
    const query = controls.search.value.trim().normalize("NFKC").toLocaleLowerCase();
    return (!query || article.search.includes(query)) && (!controls.kind.value || controls.kind.value === article.kind) && (!controls.source.value || controls.source.value === article.source_id) && (ignoreMonth || !controls.month.value || controls.month.value === article.month);
  }

  function renderTimeline() {
    const candidates = snapshot.articles.filter(article => matches(article, true));
    const counts = new Map();
    for (const article of candidates) counts.set(article.month, (counts.get(article.month) || 0) + 1);
    const months = calendarMonths();
    if (snapshot.articles.some(article => !article.date)) months.push("unknown");
    $("#month-timeline").replaceChildren(...months.map(month => {
      const count = counts.get(month) || 0;
      const item = node("button", "month-button" + (controls.month.value === month ? " selected" : "") + (count ? "" : " empty-month"));
      item.type = "button";
      item.setAttribute("aria-pressed", String(controls.month.value === month));
      item.setAttribute("aria-label", monthLabel(month) + ": " + count + " entries matching search, kind and source. Filter by this month.");
      if (month !== "unknown") {
        const date = new Date(month + "-01T00:00:00Z");
        item.append(node("span", "month-name", date.toLocaleDateString(undefined, { month: "short", timeZone: "UTC" })), node("span", "month-year", String(date.getUTCFullYear())));
        const firstDay = snapshot.window.start.slice(0, 10);
        const lastDay = snapshot.window.end.slice(0, 10);
        const lastOfMonth = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 0)).getUTCDate();
        if ((month === firstDay.slice(0, 7) && firstDay.slice(8) !== "01") || (month === lastDay.slice(0, 7) && Number(lastDay.slice(8)) !== lastOfMonth)) { item.classList.add("partial"); item.title = "Partial month within the selected archive window."; }
      } else item.append(node("span", "month-name", "Unknown"), node("span", "month-year", "DATE"));
      item.append(node("span", "month-count", count.toLocaleString()));
      item.addEventListener("click", () => { controls.month.value = controls.month.value === month ? "" : month; visibleCount = pageSize; render(); });
      return item;
    }));
  }

  function articleCard(article) {
    const card = node("article", "article-card");
    const top = node("div", "article-topline");
    const date = node("div", "article-date", article.date ? dateLabel(article.primary_date) : "Date unknown");
    date.append(node("span", "", !article.date ? "UNKNOWN" : article.date_basis === "event" ? "EVENT DATE" : article.kind === "kev" ? "CATALOG ADDED" : article.date_basis === "publisher update" ? "UPDATED" : "PUBLISHED"));
    top.append(node("span", "kind-badge kind-" + article.kind, kinds[article.kind]), date);
    const title = node("h3");
    title.append(link(article.title, article.url, "article-title"));
    card.append(top, title);
    if (article.summary) card.append(node("p", "article-summary", article.summary));
    const tags = node("div", "article-tags");
    for (const cve of article.cves.slice(0, 8)) tags.append(node("span", "article-tag cve-tag", cve));
    for (const tag of article.tags.slice(0, 4)) tags.append(node("span", "article-tag", tag));
    if (tags.children.length) card.append(tags);
    const bottom = node("div", "article-bottom");
    const source = node("div", "article-source");
    source.append(node("span", "", article.source_name), node("span", "article-origin", origins[article.origin]));
    const exploitation = { known: "Known exploitation recorded by the source", reported: "Exploitation reported; read the source context", unknown: "Exploitation status unknown in this record" }[article.exploitation];
    bottom.append(source, node("p", "exploitation exploitation-" + article.exploitation, exploitation));
    const detail = node("details", "article-detail");
    detail.append(node("summary", "", "Sources & date context"), node("p", "", "Date basis: " + (article.date_basis || "Not specified in this record.")), node("p", "", (article.kind === "kev" ? "Catalog addition date: " : "Publisher date: ") + (article.published_at ? dateLabel(article.published_at) : "Not recorded.")), node("p", "", "Event date: " + (article.event_date ? dateLabel(article.event_date) : "Not separately recorded.")));
    if (article.cves.length > 8) detail.append(node("p", "", "All CVE identifiers: " + article.cves.join(", ")));
    if (article.tags.length > 4) detail.append(node("p", "", "All topic tags: " + article.tags.join(", ")));
    if (article.kind === "kev") detail.append(node("p", "", "CISA catalog addition is separate from disclosure or exploitation dates. This catalog record is not an incident report."));
    const references = node("ul");
    const original = node("li");
    original.append(link("Original publisher record ↗", article.url));
    references.append(original);
    for (const reference of article.references) { const item = node("li"); item.append(link(reference.label + " ↗", reference.url)); references.append(item); }
    detail.append(references);
    bottom.append(detail);
    card.append(bottom);
    return card;
  }

  function renderStats(articles) {
    const all = snapshot.articles;
    const counts = items => ({ exploited: items.filter(item => item.exploitation === "known").length, sources: new Set(items.map(item => item.source_id)).size, undated: items.filter(item => !item.date).length });
    const filtered = counts(articles);
    const totals = counts(all);
    for (const [key, value, total] of [["matches", articles.length, all.length], ["exploited", filtered.exploited, totals.exploited], ["sources", filtered.sources, totals.sources], ["undated", filtered.undated, totals.undated]]) {
      $("#count-" + key).textContent = value.toLocaleString();
      $("#total-" + key).textContent = "of " + total.toLocaleString() + " in the whole snapshot";
    }
  }

  function render() {
    if (!snapshot) return;
    const articles = snapshot.articles.filter(article => matches(article));
    articles.sort((a, b) => {
      if (!a.date && b.date) return 1;
      if (a.date && !b.date) return -1;
      const dates = a.date && b.date ? a.date.getTime() - b.date.getTime() : 0;
      return (controls.sort.value === "oldest" ? dates : -dates) || a.title.localeCompare(b.title) || a.id.localeCompare(b.id);
    });
    renderStats(articles);
    renderTimeline();
    const visible = articles.slice(0, visibleCount);
    $("#articles").replaceChildren(...visible.map(articleCard));
    $("#results-status").textContent = articles.length.toLocaleString() + " matching entries / " + snapshot.articles.length.toLocaleString() + " in snapshot";
    $("#empty-state").hidden = articles.length > 0;
    $("#empty-title").textContent = snapshot.articles.length ? "No matching intelligence" : "This snapshot has no entries yet";
    $("#empty-message").textContent = snapshot.articles.length ? "Try a broader search or choose another source, kind or month. The source ledger explains collection gaps." : "Inspect the source ledger for recorded collection outcomes, then reload a later snapshot.";
    $("#empty-reset").hidden = !snapshot.articles.length;
    $("#load-more").hidden = visible.length >= articles.length;
    $("#load-more").textContent = "Load " + Math.min(pageSize, articles.length - visible.length) + " more entries +";
    $("#page-status").textContent = "Showing " + visible.length.toLocaleString() + " of " + articles.length.toLocaleString() + " matching entries · Unknown primary dates sort last";
  }

  function renderSources() {
    $("#source-dialog-stamp").textContent = "Snapshot prepared " + stamp(snapshot.generated_at) + ". Publication dates and source fetch dates are separate.";
    $("#source-ledger").replaceChildren(...snapshot.sources.map(source => {
      const card = node("article", "ledger-source");
      const heading = node("div", "ledger-source-heading");
      const title = node("h3"); title.append(link(source.name, source.url));
      const states = { ok: "FETCH SUCCEEDED", failed: "FETCH FAILED", not_fetched: "NOT FETCHED" };
      heading.append(title, node("span", "source-status" + (source.status === "failed" ? " failed" : source.status === "not_fetched" ? " not-fetched" : ""), states[source.status]));
      card.append(heading, node("p", "", source.kind + " · Reported entry count: " + source.articles.toLocaleString()), node("p", "", "Last successful collection: " + stamp(source.last_success)), node("p", "", "Last attempt: " + stamp(source.last_attempt)));
      if (source.error) card.append(node("p", "source-error", source.error));
      return card;
    }));
    if (!snapshot.sources.length) $("#source-ledger").append(node("p", "ledger-empty", "No source-fetch records were supplied. Article publisher labels do not establish collection health."));
  }

  function renderFreshness() {
    if (!snapshot) return;
    const age = Date.now() - new Date(snapshot.generated_at).getTime();
    const stale = age > 86400000;
    $("#snapshot-status").textContent = age < -300000 ? "Snapshot clock differs" : stale ? "Snapshot older than 24 hours" : "Saved snapshot";
    $("#snapshot-mark").classList.toggle("stale", stale || age < -300000);
  }

  function renderSnapshot() {
    renderFreshness();
    $("#generated-at").textContent = "Prepared " + stamp(snapshot.generated_at);
    $("#archive-window").textContent = dateLabel(snapshot.window.start) + " — " + dateLabel(snapshot.window.end);
    const coverage = $("#coverage");
    coverage.replaceChildren(...[["KEV catalog records", snapshot.coverage.kev_records], ["Curated archive events", snapshot.coverage.curated_events], ["Publisher feed articles", snapshot.coverage.feed_articles]].map(([label, count]) => { const item = node("div"); item.append(node("dt", "", label), node("dd", "", count.toLocaleString())); return item; }));
    const ok = snapshot.sources.filter(source => source.status === "ok").length;
    const failed = snapshot.sources.filter(source => source.status === "failed").length;
    const unfetched = snapshot.sources.filter(source => source.status === "not_fetched").length;
    $("#source-health-summary").textContent = snapshot.sources.length ? "Recorded source outcomes: " + ok + " successful / " + failed + " failed / " + unfetched + " not fetched." : "Source collection outcomes were not supplied.";
    $("#coverage-notes").replaceChildren(...snapshot.coverage.notes.map(note => node("li", "", note)));
    if (!snapshot.coverage.notes.length) $("#coverage-notes").append(node("li", "", "No additional coverage notes were supplied."));
    $("#integrations").replaceChildren(...[["xai", "Grok / xAI"], ["x", "X"]].map(([key, name]) => { const item = node("div", "integration-row"); const heading = node("div", "integration-heading"); heading.append(node("span", "", name), node("span", "integration-state", "NOT CONNECTED")); item.append(heading, node("p", "", snapshot.integrations[key].message)); return item; }));
    for (const button of document.querySelectorAll("[data-open-sources]")) button.disabled = false;
    renderSources();
  }

  async function readFeed(response) {
    if (!response.ok) throw new Error("The feed snapshot could not be read (HTTP " + response.status + ").");
    const length = Number(response.headers.get("content-length"));
    if (Number.isFinite(length) && length > maximumFeedBytes) throw new Error("The snapshot exceeds the supported download size.");
    let bytes;
    if (response.body) {
      const reader = response.body.getReader();
      const chunks = [];
      let total = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maximumFeedBytes) { await reader.cancel(); throw new Error("The snapshot exceeds the supported download size."); }
        chunks.push(value);
      }
      bytes = new Uint8Array(total);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    } else { bytes = new Uint8Array(await response.arrayBuffer()); if (bytes.byteLength > maximumFeedBytes) throw new Error("The snapshot exceeds the supported download size."); }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  }

  async function load() {
    if (loading) return;
    loading = true;
    $("#reload").disabled = true;
    $("#reload").textContent = "Reading snapshot…";
    $("#loading-cards").hidden = Boolean(snapshot);
    try {
      const response = await fetch("./data/feed.json", { credentials: "omit", cache: "no-store", redirect: "error" });
      const value = normalize(await readFeed(response));
      snapshot = value;
      $("#feed-error").hidden = true;
      configureFilters();
      renderSnapshot();
      visibleCount = pageSize;
      render();
    } catch (error) {
      $("#feed-error").hidden = false;
      $("#feed-error-message").textContent = (error instanceof SyntaxError ? "The saved feed is not valid JSON." : error.message || "The saved feed could not load.") + (snapshot ? " The prior snapshot from " + stamp(snapshot.generated_at) + " remains displayed with its original dates." : " No feed data is displayed. Reload after a valid snapshot has been prepared.");
      if (!snapshot) {
        $("#snapshot-status").textContent = "Snapshot unavailable";
        $("#snapshot-mark").classList.add("stale");
        $("#results-status").textContent = "No snapshot loaded · Counts and source outcomes are unknown";
      }
    } finally {
      loading = false;
      $("#reload").disabled = false;
      $("#reload").textContent = "Reload snapshot ↻";
      $("#loading-cards").hidden = true;
    }
  }

  function reset() {
    controls.search.value = "";
    controls.kind.value = "";
    controls.source.value = "";
    controls.month.value = "";
    controls.sort.value = "newest";
    visibleCount = pageSize;
    render();
  }

  $("#filters").addEventListener("submit", event => { event.preventDefault(); clearTimeout(searchTimer); visibleCount = pageSize; render(); });
  controls.search.addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { visibleCount = pageSize; render(); }, 150); });
  for (const select of [controls.kind, controls.source, controls.month, controls.sort]) select.addEventListener("change", () => { visibleCount = pageSize; render(); });
  $("#reset").addEventListener("click", reset);
  $("#empty-reset").addEventListener("click", reset);
  $("#reload").addEventListener("click", load);
  $("#load-more").addEventListener("click", () => { visibleCount += pageSize; render(); });
  for (const button of document.querySelectorAll("[data-open-sources]")) button.addEventListener("click", () => { if (snapshot) { try { $("#source-dialog").showModal(); } catch (_) { $("#feed-error").hidden = false; $("#feed-error-message").textContent = "The source ledger could not open in this document. The displayed snapshot is unchanged."; } } });
  $("#close-sources").addEventListener("click", () => $("#source-dialog").close());
  document.addEventListener("visibilitychange", () => { if (!document.hidden) renderFreshness(); });
  setInterval(renderFreshness, 60000);
  load();
})();
