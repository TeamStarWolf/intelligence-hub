"""Measure the site's colour pairs in both themes and fail below WCAG 2.2 AA.

site/styles.css defines every colour as a --tsw-* token, once for the dark theme
(":root, :root[data-theme="dark"]"), once for the light theme (":root[data-theme="light"]")
and again for prefers-color-scheme: light, which must repeat the light block exactly. PAIRS
lists each text and background pair the stylesheet uses, with the minimum it needs: 4.5:1 for
text and 3:1 for non-text indicators such as the focus ring and control borders (WCAG 2.2
success criteria 1.4.3 and 1.4.11). Ported from the TeamStarWolf library's
scripts/check_contrast.py.

Usage: python -I tests/check_contrast.py   (prints every pair; exit 1 on a failure)
"""
from pathlib import Path
import re
import sys

CSS = Path(__file__).resolve().parent.parent / "site" / "styles.css"
TEXT, UI = 4.5, 3.0

# (foreground token, background token, minimum, where it is used)
PAIRS = [
    ("--tsw-text", "--tsw-bg", TEXT, "body text"),
    ("--tsw-text", "--tsw-surface", TEXT, "cards, bar, inputs"),
    ("--tsw-text", "--tsw-surface-2", TEXT, "buttons, dialog heading bar"),
    ("--tsw-text", "--tsw-bg-alt", TEXT, "sidebar"),
    ("--tsw-heading", "--tsw-bg", TEXT, "view titles"),
    ("--tsw-heading", "--tsw-surface", TEXT, "card titles, panel titles"),
    ("--tsw-heading", "--tsw-surface-2", TEXT, "table header cells, dialog titles"),
    ("--tsw-heading", "--tsw-bg-alt", TEXT, "sidebar title"),
    ("--tsw-text-muted", "--tsw-bg", TEXT, "status lines, intros"),
    ("--tsw-text-muted", "--tsw-surface", TEXT, "card meta, labels, placeholder, footer"),
    ("--tsw-text-muted", "--tsw-surface-2", TEXT, "muted text on buttons"),
    ("--tsw-text-muted", "--tsw-bg-alt", TEXT, "sidebar notes"),
    ("--tsw-link", "--tsw-bg", TEXT, "links"),
    ("--tsw-link", "--tsw-surface", TEXT, "links on cards and panels"),
    ("--tsw-link", "--tsw-surface-2", TEXT, "links in table headers and dialogs"),
    ("--tsw-link", "--tsw-bg-alt", TEXT, "sidebar links"),
    ("--tsw-link-hover", "--tsw-surface", TEXT, "hovered links"),
    ("--tsw-chip-fg", "--tsw-chip-bg", TEXT, "chips and badges"),
    ("--tsw-red-text", "--tsw-chip-bg", TEXT, "KEV and known-exploited chips"),
    ("--tsw-amber-text", "--tsw-chip-bg", TEXT, "reported-exploited chips, minor service-health badges"),
    ("--tsw-text-muted", "--tsw-chip-bg", TEXT, "quiet chips, maintenance and unknown service-health badges"),
    ("--tsw-red-text", "--tsw-surface", TEXT, "KEV day counts"),
    ("--tsw-red-text", "--tsw-bg-alt", TEXT, "KEV day counts in the sidebar"),
    ("--tsw-btn-fg", "--tsw-btn-bg", TEXT, "skip link"),
    ("--tsw-focus", "--tsw-bg", UI, "focus ring"),
    ("--tsw-focus", "--tsw-surface", UI, "focus ring on cards and inputs"),
    ("--tsw-focus", "--tsw-bg-alt", UI, "focus ring in the sidebar"),
    ("--tsw-red", "--tsw-surface", UI, "active tab rule, notice border"),
    ("--tsw-border-strong", "--tsw-surface", UI, "input and button borders"),
    ("--tsw-border-strong", "--tsw-bg", UI, "input borders on the page"),
]

BLOCKS = {
    "dark": re.compile(r':root,\s*:root\[data-theme="dark"\]\s*\{(.*?)\n\}', re.S),
    "light": re.compile(r'^:root\[data-theme="light"\]\s*\{(.*?)\n\}', re.S | re.M),
    "system-light": re.compile(r'@media \(prefers-color-scheme: light\)\s*\{\s*:root:not\(\[data-theme="dark"\]\)\s*\{(.*?)\n\s*\}', re.S),
}
DECL = re.compile(r"(--tsw-[\w-]+)\s*:\s*([^;]+);")
HEX = re.compile(r"#([0-9a-fA-F]{6})\b")
RGBA = re.compile(r"rgba?\(\s*([\d.]+)\s*,\s*([\d.]+)\s*,\s*([\d.]+)\s*(?:,\s*([\d.]+)\s*)?\)")


def tokens(css):
    found = {}
    for theme, pattern in BLOCKS.items():
        match = pattern.search(css)
        if not match:
            raise SystemExit("site/styles.css: no " + theme + " token block")
        found[theme] = {name: re.sub(r"/\*.*?\*/", "", value).strip() for name, value in DECL.findall(match.group(1))}
    return found


def colour(value):
    match = HEX.search(value)
    if match:
        text = match.group(1)
        return tuple(int(text[i:i + 2], 16) for i in (0, 2, 4)) + (1.0,)
    match = RGBA.search(value)
    if match:
        return (float(match[1]), float(match[2]), float(match[3]), float(match[4]) if match[4] else 1.0)
    raise SystemExit("no colour in " + repr(value))


def luminance(c):
    def channel(v):
        v /= 255
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
    return 0.2126 * channel(c[0]) + 0.7152 * channel(c[1]) + 0.0722 * channel(c[2])


def ratio(a, b):
    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def measure(theme_tokens):
    rows = []
    for fg, bg, need, where in PAIRS:
        rows.append((where, fg, bg, ratio(colour(theme_tokens[fg]), colour(theme_tokens[bg])), need))
    return rows


def failures(css=None):
    """Every failing pair and token problem, as text lines; empty when the stylesheet passes."""
    css = CSS.read_text(encoding="utf-8") if css is None else css
    themes = tokens(css)
    problems = []
    if themes["system-light"] != themes["light"]:
        problems.append("the prefers-color-scheme light block differs from :root[data-theme=\"light\"]")
    if set(themes["light"]) != set(themes["dark"]) - {"--tsw-mono", "--tsw-sans"}:
        problems.append("the light block does not define the same colour tokens as the dark block")
    for theme in ("dark", "light"):
        for where, fg, bg, value, need in measure(themes[theme]):
            if value < need:
                problems.append("{}: {:.2f}:1 (needs {}) {} on {} ({})".format(theme, value, need, fg, bg, where))
    return problems


def main():
    css = CSS.read_text(encoding="utf-8")
    themes = tokens(css)
    for theme in ("dark", "light"):
        print("== " + theme + " theme ==")
        for where, fg, bg, value, need in measure(themes[theme]):
            print("  {} {:6.2f}:1 (needs {}) {} on {}  {}".format("ok  " if value >= need else "FAIL", value, need, fg, bg, where))
    problems = failures(css)
    for line in problems:
        print("FAIL: " + line)
    if problems:
        return 1
    print("OK: all " + str(2 * len(PAIRS)) + " colour pairs meet WCAG AA")
    return 0


if __name__ == "__main__":
    sys.exit(main())
