"use strict";
// Runs site/app.js with small stand-ins for the DOM and fetch, so its data logic can
// be tested offline. Usage: node tests/app_harness.js site/app.js scenario.json
// The scenario names a case and the feed and briefs files to serve; the result is
// printed as one JSON object.
const fs = require("fs");
const vm = require("vm");

const [appPath, scenarioPath] = process.argv.slice(2);
const scenario = JSON.parse(fs.readFileSync(scenarioPath, "utf8"));
const files = Object.fromEntries(Object.entries(scenario.files).map(([url, path]) => [url, fs.readFileSync(path, "utf8")]));
const requests = [];
const opened = [];

function element(name) {
  return {
    name, children: [], dataset: {}, style: {}, hidden: false, open: false, textContent: "", value: "", disabled: false, scrollLeft: 0, scrollTop: 0,
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    append(...nodes) { this.children.push(...nodes); }, prepend(...nodes) { this.children.unshift(...nodes); },
    replaceChildren(...nodes) { this.children = nodes; }, setAttribute(key, value) { this[key] = value; }, removeAttribute(key) { delete this[key]; },
    getAttribute() { return null; }, addEventListener() {}, querySelector() { return null; }, querySelectorAll() { return []; }, focus() {},
    showModal() { this.open = true; opened.push(name); }, close() { this.open = false; }
  };
}

const elements = new Map();
// Every message the page shows in its error banner, in order.
const errors = [];
const banner = element("#feed-error-message");
Object.defineProperty(banner, "textContent", { get() { return errors[errors.length - 1] || ""; }, set(value) { errors.push(value); } });
elements.set("#feed-error-message", banner);
globalThis.document = {
  hidden: false, activeElement: null, body: element("body"),
  querySelector(selector) { if (!elements.has(selector)) elements.set(selector, element(selector)); return elements.get(selector); },
  querySelectorAll() { return []; }, createElement: tag => element(tag), createDocumentFragment: () => element("fragment"), addEventListener() {}
};
globalThis.window = { scrollX: 0, scrollY: 0, scrollTo() {} };
globalThis.setInterval = () => 0;
globalThis.fetch = async (url, options = {}) => {
  requests.push({ url, cache: options.cache || null });
  if (!Object.hasOwn(files, url)) return { ok: false, status: 404, headers: { get: () => null }, body: null, arrayBuffer: async () => new ArrayBuffer(0), json: async () => ({}) };
  const bytes = new TextEncoder().encode(files[url]);
  return { ok: true, status: 200, headers: { get: key => key.toLowerCase() === "content-length" ? String(bytes.byteLength) : null }, body: null, arrayBuffer: async () => bytes.buffer };
};

const source = fs.readFileSync(appPath, "utf8");
const ending = "\n  load();\n})();";
if (!source.includes(ending)) throw new Error("site/app.js no longer ends with load(); update the test harness.");
// Expose the functions under test instead of starting the page's first network read.
vm.runInThisContext(source.replace(ending, "\n  globalThis.hub = { normalize, normalizeBriefs, openMitigation, cveRows, use: value => { snapshot = value; } };\n})();"), { filename: appPath });

const settle = () => new Promise(resolve => setTimeout(resolve, 50));

async function main() {
  const hub = globalThis.hub;
  const feedText = files["./data/feed.json"];
  const result = { case: scenario.case };
  if (scenario.case === "oversize") {
    try { hub.normalize(JSON.parse(feedText), 8 * 1024 * 1024 + 1); result.accepted = true; } catch (_) { result.accepted = false; }
    try { hub.normalize(JSON.parse(feedText), new TextEncoder().encode(feedText).byteLength); result.accepted_at_size = true; } catch (_) { result.accepted_at_size = false; }
    return result;
  }
  const snapshot = hub.normalize(JSON.parse(feedText), new TextEncoder().encode(feedText).byteLength);
  hub.use(snapshot);
  const light = snapshot.mitigations.get(scenario.cve);
  result.briefs_inline = snapshot.briefs !== null;
  result.index_size = snapshot.mitigations.size;
  result.light = { guidance: light.analysis.guidance_status, source_status: light.source_status, kev_added: light.kev ? light.kev.date_added : null };
  result.register_title_before = hub.cveRows(snapshot.articles).find(row => row.id === scenario.cve).title;
  hub.openMitigation(scenario.cve);
  await settle();
  result.opened = [...opened];
  result.dialog_title = document.querySelector("#mitigation-title").textContent;
  result.dialog_sections = document.querySelector("#mitigation-content").children.length;
  result.error = errors[0] || null;
  document.querySelector("#mitigation-dialog").close();
  hub.openMitigation(scenario.cve);
  await settle();
  result.opened_again = opened.length;
  result.register_title_after = hub.cveRows(snapshot.articles).find(row => row.id === scenario.cve).title;
  result.requests = requests.map(item => item.url + (item.cache ? " " + item.cache : ""));
  return result;
}

main().then(result => { process.stdout.write(JSON.stringify(result)); }, error => { process.stdout.write(JSON.stringify({ crashed: String(error && error.stack || error) })); process.exitCode = 1; });
