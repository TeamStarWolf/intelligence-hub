// The read path: bounded bytes, strict JSON, ETag revalidation without a parse, and shards held
// to their manifest sha256 with one retry past the browser cache.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { createFetcher, HttpError } from "../../site/js/fetcher.js";

const response = (status, text = "", etag = null) => {
  const bytes = new TextEncoder().encode(text);
  return { ok: status >= 200 && status < 300, status, body: null, headers: { get: key => key.toLowerCase() === "etag" ? etag : key.toLowerCase() === "content-length" ? String(bytes.byteLength) : null }, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
};

test("a conditional read sends the ETag and a 304 returns the parsed value without parsing", async () => {
  const calls = [];
  let parses = 0;
  const fetcher = createFetcher({ subtle: webcrypto.subtle, parse: text => { parses++; return JSON.parse(text); },
    fetchImpl: async (url, options) => { calls.push(options); return options.headers["If-None-Match"] === "\"v1\"" ? response(304) : response(200, "{\"a\":1}", "\"v1\""); } });
  const first = await fetcher.getJson("./data/v7/index.json", { maximum: 1024, conditional: true });
  const second = await fetcher.getJson("./data/v7/index.json", { maximum: 1024, conditional: true });
  assert.deepEqual(first.value, { a: 1 });
  assert.equal(second.notModified, true);
  assert.equal(second.value, first.value);
  assert.equal(parses, 1);
  assert.equal(calls[0].cache, "no-store");
  assert.equal(calls[1].headers["If-None-Match"], "\"v1\"");
  assert.equal(calls[0].credentials, "omit");
  assert.equal(calls[0].redirect, "error");
});

test("bounds, status and JSON errors are refused", async () => {
  const fetcher = createFetcher({ fetchImpl: async url => url.includes("big") ? response(200, "x".repeat(2048)) : url.includes("gone") ? response(404) : response(200, "{bad") });
  await assert.rejects(fetcher.getJson("./big.json", { maximum: 1024, label: "big file" }), /exceeds/);
  await assert.rejects(fetcher.getJson("./gone.json", { maximum: 1024 }), error => error instanceof HttpError && error.status === 404);
  await assert.rejects(fetcher.getJson("./bad.json", { maximum: 1024 }), /not valid JSON/);
});

test("a shard is versioned by its sha256, checked, and read once more past the cache on a mismatch", async () => {
  const good = "{\"rows\":[]}\n";
  const sha = createHash("sha256").update(good).digest("hex");
  const calls = [];
  const fetcher = createFetcher({ subtle: webcrypto.subtle, fetchImpl: async (url, options) => { calls.push([url, options.cache]); return response(200, calls.length === 1 ? "{\"stale\":true}\n" : good); } });
  const result = await fetcher.getShard("live/2026-11.json", { sha256: sha }, 4096, "shard");
  assert.deepEqual(result.value, { rows: [] });
  assert.deepEqual(calls, [["./data/v7/live/2026-11.json?v=" + sha.slice(0, 16), "default"], ["./data/v7/live/2026-11.json?v=" + sha.slice(0, 16), "reload"]]);
  const always = createFetcher({ subtle: webcrypto.subtle, fetchImpl: async () => response(200, "{\"stale\":true}\n") });
  await assert.rejects(always.getShard("live/2026-11.json", { sha256: sha }, 4096, "shard"), /does not match its manifest/);
});
