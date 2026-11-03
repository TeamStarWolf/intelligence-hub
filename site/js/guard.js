// The deploy-skew guard. GitHub Pages lets browsers keep a script for a while after a deploy,
// so an open page can hold an older script than the data it reads. When a read succeeds but
// the data fails validation, or the index names a newer page layout than the one running, the
// page reloads itself once per browser session before it shows an error. The session flag
// lives in sessionStorage; when storage is unavailable the page never reloads, so it cannot loop.

export const RELOAD_KEY = "tsw-hub-reloaded";

export function reloadOnce({ storage, location, reason = "skew" }) {
  try {
    if (!storage || storage.getItem(RELOAD_KEY)) return false;
    storage.setItem(RELOAD_KEY, reason);
    if (storage.getItem(RELOAD_KEY) !== reason) return false;
  } catch (_) { return false; }
  location.reload();
  return true;
}

// The revision the running scripts were stamped with at publish time (?v=<16 hex> on this
// module's URL), or null for an unstamped local copy.
export function runningRevision(moduleUrl) {
  const match = /[?&]v=([a-f0-9]{16})(?:&|$)/.exec(String(moduleUrl || ""));
  return match ? match[1] : null;
}

// True when the index was written for a different page layout than the running scripts.
export function layoutSkew(index, running) {
  return Boolean(running && index && typeof index.layout_revision === "string" && index.layout_revision.slice(0, 16) !== running);
}
