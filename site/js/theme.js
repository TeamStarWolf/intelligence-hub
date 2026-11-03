// Light and dark themes. Until a reader picks one, styles.css follows prefers-color-scheme;
// a pick sets data-theme on the root element and is kept in localStorage (a per-browser
// convenience: when storage is unavailable the pick lasts for this page only).

export const THEME_KEY = "tsw-hub-theme";

function stored(storage) {
  try { const value = storage && storage.getItem(THEME_KEY); return value === "light" || value === "dark" ? value : null; } catch (_) { return null; }
}

export function systemTheme(win) {
  try { return win && win.matchMedia && win.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"; } catch (_) { return "dark"; }
}

export function currentTheme(doc, win) {
  const chosen = doc.documentElement.getAttribute("data-theme");
  return chosen === "light" || chosen === "dark" ? chosen : systemTheme(win);
}

function label(button, theme) {
  const next = theme === "light" ? "dark" : "light";
  button.textContent = next === "light" ? "Light" : "Dark";
  button.setAttribute("aria-label", "Switch to the " + next + " theme");
}

export function initTheme({ doc, win, storage, button }) {
  const pick = stored(storage);
  if (pick) doc.documentElement.setAttribute("data-theme", pick);
  if (!button) return;
  label(button, currentTheme(doc, win));
  button.addEventListener("click", () => {
    const next = currentTheme(doc, win) === "light" ? "dark" : "light";
    doc.documentElement.setAttribute("data-theme", next);
    try { storage && storage.setItem(THEME_KEY, next); } catch (_) { /* The pick lasts for this page only. */ }
    label(button, next);
  });
}
