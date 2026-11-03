// Small DOM and text helpers shared by every view. The page builds every element with
// createElement and sets text with textContent only; publisher text is never parsed as markup.

export const DAY = 86400000;

export function node(tag, className = "", text = "") {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== "" && text !== null && text !== undefined) element.textContent = String(text);
  return element;
}

export function normalized(value) { return String(value).normalize("NFKC").toLocaleLowerCase(); }

// The only gate for every outbound link: https, a public host name, no credentials or port.
export function safeUrl(value) {
  try {
    if (typeof value !== "string" || value.length > 4000 || /[\u0000- \u007f\\]/.test(value)) return null;
    const url = new URL(value);
    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    if (url.protocol !== "https:" || url.username || url.password || url.port || !host || !host.includes(".") || host.startsWith("[") ||
      /^(?:\d+\.)*\d+$/.test(host) || host === "localhost" ||
      /\.(?:localhost|local|localdomain|internal|lan|home|home\.arpa|test|invalid|example)$/.test(host)) return null;
    return url.href;
  } catch (_) { return null; }
}

// An outbound link that opens in a new tab, or plain text when the URL fails safeUrl.
export function link(label, value, className = "") {
  const url = safeUrl(value);
  if (!url) return node("span", className, label);
  const anchor = node("a", className, label);
  anchor.href = url; anchor.target = "_blank"; anchor.rel = "noopener noreferrer nofollow"; anchor.referrerPolicy = "no-referrer";
  return anchor;
}

// A link to a route inside this page. The hash is built by router.formatRoute, never from row text.
export function routeLink(label, hash, className = "") {
  const anchor = node("a", className, label);
  anchor.href = hash;
  return anchor;
}

export function dateLabel(value, full = false) {
  if (!value) return "Not recorded";
  const date = new Date(value.length === 10 ? value + "T00:00:00Z" : value);
  if (!Number.isFinite(date.getTime())) return "Not recorded";
  return date.toLocaleDateString("en-GB", { day: "numeric", month: full ? "long" : "short", year: "numeric", timeZone: "UTC" });
}

export function dayLabel(value) {
  const date = new Date(value + "T00:00:00Z");
  return date.toLocaleDateString("en-GB", { weekday: "short", day: "numeric", month: "short", timeZone: "UTC" });
}

export function stamp(value) {
  if (!value) return "Not recorded";
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return "Not recorded";
  return date.toLocaleString("en-GB", { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC";
}

export function monthLabel(value) {
  if (value === "unknown") return "Date unknown";
  return new Date(value + "-01T00:00:00Z").toLocaleDateString("en-GB", { month: "short", year: "numeric", timeZone: "UTC" });
}

export function count(value, singular, plural = singular + "s") {
  return value.toLocaleString("en-US") + " " + (value === 1 ? singular : plural);
}

export function hoursLabel(value) { return value.toLocaleString("en-US", { maximumFractionDigits: 1 }) + " h"; }

// "vendor:palo-alto-networks" reads "Palo Alto Networks" until the vocabulary labels load.
export function humanize(id) {
  const value = String(id).replace(/^[a-z]+:/, "");
  if (/^[A-Z]\d{4}$/.test(value) || /^[A-Z]{2}$/.test(value)) return value;
  return value.split("-").map(word => word ? word[0].toUpperCase() + word.slice(1) : word).join(" ");
}

// ISO day arithmetic on YYYY-MM-DD strings, in UTC.
export function addDays(day, delta) {
  const date = new Date(day + "T00:00:00Z");
  date.setUTCDate(date.getUTCDate() + delta);
  return date.toISOString().slice(0, 10);
}

export function monthsBetween(first, last) {
  const months = [];
  const cursor = new Date(first.slice(0, 7) + "-01T00:00:00Z");
  while (cursor.toISOString().slice(0, 7) <= last.slice(0, 7) && months.length < 600) {
    months.push(cursor.toISOString().slice(0, 7));
    cursor.setUTCMonth(cursor.getUTCMonth() + 1);
  }
  return months;
}
