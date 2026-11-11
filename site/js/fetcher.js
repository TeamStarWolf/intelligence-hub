// Every network read the page makes goes through here. Reads are same-origin, without
// credentials, bounded in bytes, decoded as strict UTF-8 and parsed only when the bytes are new:
// the index is read with If-None-Match, and a 304 returns the value already parsed. Shards
// carry the first 16 characters of their manifest sha256 in the query, so a new deploy never
// reuses a stale browser copy, and the bytes are checked against that sha256 before parsing.

export class HttpError extends Error {
  constructor(message, status) { super(message); this.name = "HttpError"; this.status = status; }
}

function hex(buffer) { return [...new Uint8Array(buffer)].map(byte => byte.toString(16).padStart(2, "0")).join(""); }

// A byte bound as people read it: whole MiB from 1 MiB up, KiB below (the live board's 64 KiB).
export function sizeLabel(bytes) {
  return bytes >= 1048576 ? Math.round(bytes / 1048576) + " MiB" : Math.max(1, Math.round(bytes / 1024)) + " KiB";
}

export function createFetcher({ fetchImpl = globalThis.fetch, subtle = globalThis.crypto?.subtle, parse = JSON.parse, timeout = 45000 } = {}) {
  const cache = new Map();
  const stats = { requests: 0, parses: 0, notModified: 0 };

  async function readBytes(response, maximum, label) {
    const tooLarge = "The " + label + " exceeds the supported " + sizeLabel(maximum) + " download size.";
    const length = Number(response.headers.get("content-length"));
    if (Number.isFinite(length) && length > maximum) throw new Error(tooLarge);
    if (response.body && typeof response.body.getReader === "function") {
      const reader = response.body.getReader(); const chunks = []; let total = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maximum) { await reader.cancel(); throw new Error(tooLarge); }
        chunks.push(value);
      }
      const bytes = new Uint8Array(total); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return bytes;
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maximum) throw new Error(tooLarge);
    return bytes;
  }

  // Returns {value, text, notModified}. With conditional, a cached ETag is sent and a 304
  // returns the previous value without reading or parsing a body.
  async function getJson(url, { maximum, label = "file", conditional = false, cacheMode = "default", sha256 = null } = {}) {
    const controller = typeof AbortController === "function" ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeout) : null;
    try {
      const previous = conditional ? cache.get(url) : null;
      const headers = previous && previous.etag ? { "If-None-Match": previous.etag } : {};
      stats.requests++;
      const response = await fetchImpl(url, { credentials: "omit", cache: conditional ? "no-store" : cacheMode, redirect: "error", headers, signal: controller ? controller.signal : undefined });
      if (response.status === 304 && previous) { stats.notModified++; return { value: previous.value, text: previous.text, notModified: true }; }
      if (!response.ok) throw new HttpError("The " + label + " could not be read (HTTP " + response.status + ").", response.status);
      const bytes = await readBytes(response, maximum, label);
      if (sha256 && subtle) {
        const digest = hex(await subtle.digest("SHA-256", bytes));
        if (digest !== sha256) { const error = new Error("The " + label + " does not match its manifest sha256."); error.mismatch = true; throw error; }
      }
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      stats.parses++;
      const value = parse(text);
      if (conditional) cache.set(url, { etag: response.headers.get("etag"), value, text });
      return { value, text, notModified: false };
    } catch (error) {
      if (error && error.name === "AbortError") throw new Error("The " + label + " read timed out.");
      if (error instanceof SyntaxError) throw new Error("The " + label + " is not valid JSON.");
      throw error;
    } finally { if (timer) clearTimeout(timer); }
  }

  // A shard listed in the index: versioned URL, sha256 check, one retry past the browser cache.
  async function getShard(path, entry, maximum, label) {
    const url = "./data/v7/" + path + "?v=" + entry.sha256.slice(0, 16);
    try { return await getJson(url, { maximum, label, sha256: entry.sha256 }); }
    catch (error) {
      if (!error.mismatch) throw error;
      return getJson(url, { maximum, label, sha256: entry.sha256, cacheMode: "reload" });
    }
  }

  return { getJson, getShard, stats, forget: url => cache.delete(url) };
}
