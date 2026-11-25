"""Validate the vendored platform menu, keep the static bar in index.html in step with it, and,
when asked, compare the copy to the published canonical file.

site/platform-nav.json is an identical copy of the one cross-site menu every TeamStarWolf site
shows in its top bar. site/index.html carries the menu as static markup between the
"platform-bar" markers, so that with JavaScript off every link still works and the stylesheet opens
the menus on :hover and :focus-within; site/js/platform-bar.js only enhances that markup. This
check holds the three in step and runs several ways:

  python -I tests/check_platform_nav.py
      Offline: the copy is plain ASCII, parses, has the agreed shape (a version, a home brand
      target, items whose menus nest at most one level and hold at most 14 entries, every "pending"
      entry noted), and the static bar in index.html matches what the copy generates. The
      pull-request check runs this.

  python -I tests/check_platform_nav.py --emit
      Print the static bar markup for index.html (what the check compares against). Paste it between
      the platform-bar markers when the menu changes.

  python -I tests/check_platform_nav.py --canonical [URL]
      Also fetch the canonical file (default https://teamstarwolf.com/platform-nav.json) and require
      the vendored copy to match it byte for byte, tolerating "not published yet". For the publish
      workflow, which has network access.

Exit 0 when valid (and, with --canonical, matching or not-yet-published); exit 1 otherwise.
"""
from pathlib import Path
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
COPY = ROOT / "site" / "platform-nav.json"
INDEX = ROOT / "site" / "index.html"
CANONICAL_DEFAULT = "https://teamstarwolf.com/platform-nav.json"
TIMEOUT = 8
MAX_ENTRIES = 14
START = "<!-- platform-bar:start"
END = "<!-- platform-bar:end -->"
# Every address in the menu must be https and point at a TeamStarWolf property. The copy is later
# refreshed from a file another site publishes, so the check covers where the links go, not just the
# shape. github.com is allowed only under the TeamStarWolf account.
ALLOWED_HOSTS = frozenset({"teamstarwolf.com", "library.teamstarwolf.com", "teamstarwolf.github.io", "github.com"})


def href_problem(href, where):
    """Why this address is not an allowed TeamStarWolf https link, or None when it is fine."""
    if not isinstance(href, str) or not href.startswith("https://"):
        return where + " is not an https address"
    # A browser reads a backslash (literal or percent-encoded) as a slash, so it would re-segment
    # the path and slip past the prefix test.
    if "\\" in href or "\\" in urllib.parse.unquote(href):
        return where + " contains a backslash, which a browser reads as a slash"
    parts = urllib.parse.urlsplit(href)
    # Credentials before the host (userinfo) are rejected outright, as the other TeamStarWolf sites
    # do, so the allowed host cannot be dressed up with an "@".
    if "@" in parts.netloc:
        return where + " has userinfo (an @ before the host)"
    host = (parts.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        return where + " points to a host that is not a TeamStarWolf property: " + (host or "(none)")
    try:
        port = parts.port
    except ValueError:
        return where + " has an invalid port"
    if port is not None:
        return where + " has an explicit port, a different origin: " + str(port)
    # A "." or ".." segment (plain or percent-encoded, e.g. %2e%2e) resolves away in a browser, so
    # github.com/TeamStarWolf/../someone would pass the prefix test but load another account.
    for segment in parts.path.split("/"):
        if urllib.parse.unquote(segment).lower() in (".", ".."):
            return where + " has a dot path segment, which a browser resolves away: " + parts.path
    if host == "github.com" and not (parts.path == "/TeamStarWolf" or parts.path.startswith("/TeamStarWolf/")):
        return where + " is a github.com address outside /TeamStarWolf: " + parts.path
    return None


def problems(raw):
    """Every validation problem with the vendored bytes, as text lines; empty when it is valid."""
    found = []
    try:
        raw.decode("ascii")
    except UnicodeDecodeError:
        return ["the file is not plain ASCII; non-ASCII characters in an address are percent-encoded"]
    try:
        menu = json.loads(raw.decode("ascii"))
    except json.JSONDecodeError as error:
        return ["the file is not valid JSON: " + str(error)]
    if not isinstance(menu, dict):
        return ["the top level is not an object"]
    if not isinstance(menu.get("version"), int):
        found.append("version is not an integer")
    home = menu.get("home")
    if not (isinstance(home, dict) and isinstance(home.get("label"), str) and isinstance(home.get("href"), str)):
        found.append("home is not a label and href")
    else:
        bad = href_problem(home["href"], "home")
        if bad:
            found.append(bad)
    items = menu.get("items")
    if not isinstance(items, list) or not items:
        return found + ["items is not a non-empty list"]
    ids = set()
    for item in items:
        where = "item " + repr(item.get("id") if isinstance(item, dict) else item)
        if not isinstance(item, dict):
            found.append(where + " is not an object")
            continue
        for key in ("id", "label", "href"):
            if not isinstance(item.get(key), str) or not item[key]:
                found.append(where + " has no " + key)
        if isinstance(item.get("href"), str):
            bad = href_problem(item["href"], where)
            if bad:
                found.append(bad)
        if item.get("id") in ids:
            found.append(where + " repeats an id")
        ids.add(item.get("id"))
        found += entry_problems(item.get("menu"), where, depth=1)
    return found


def entry_problems(menu, where, depth):
    """Problems in a menu list: labels, https or noted addresses, at most 14 entries, one nested level."""
    out = []
    if menu is None:
        return out
    if not isinstance(menu, list):
        return [where + " menu is not a list"]
    if len(menu) > MAX_ENTRIES:
        out.append(where + " menu has " + str(len(menu)) + " entries, more than the " + str(MAX_ENTRIES) + " cap")
    for entry in menu:
        at = where + " > " + repr(entry.get("label") if isinstance(entry, dict) else entry)
        if not isinstance(entry, dict):
            out.append(at + " is not an object")
            continue
        if not isinstance(entry.get("label"), str) or not entry["label"]:
            out.append(at + " has no label")
        pending = entry.get("pending")
        if pending is not None and (not isinstance(pending, str) or not pending):
            out.append(at + " has an empty pending note")
        if entry.get("href") is not None:
            bad = href_problem(entry.get("href"), at)
            if bad:
                out.append(bad)
        if "menu" in entry:
            if depth >= 2:
                out.append(at + " nests deeper than one level")
            else:
                out += entry_problems(entry.get("menu"), at, depth + 1)
    return out


def escape(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def render_bar(menu, indent="    "):
    """The static platform-bar markup for index.html: top-level links and the dropdown panels, with
    one level of fly-out sub-menus, every pending entry left out. platform-bar.js enhances this; it
    adds the caret buttons, so the markup here is links only and works without JavaScript."""
    pad = lambda level: indent + "  " * level
    home = menu["home"]
    # The wordmark is off by default (the stylesheet hides it); add the tsw-bar--wordmark class to
    # the nav to show it before Home. It points at the home brand target.
    lines = [indent + '<nav class="tsw-bar" aria-label="TeamStarWolf platform" data-tsw-bar>',
             pad(1) + '<a class="tsw-bar__wordmark" href="' + escape(home["href"]) + '" rel="noopener noreferrer">' + escape(home["label"]) + '</a>',
             pad(1) + '<ul class="tsw-bar__list">']
    for item in menu["items"]:
        shippable = [entry for entry in item.get("menu", []) if not entry.get("pending")]
        lines.append(pad(2) + '<li class="tsw-bar__item" data-tsw-item="' + escape(item["id"]) + '">')
        lines.append(pad(3) + '<a class="tsw-bar__link" href="' + escape(item["href"]) + '" rel="noopener noreferrer">' + escape(item["label"]) + '</a>')
        if shippable:
            lines.append(pad(3) + '<div class="tsw-bar__panel" id="tsw-bar-panel-' + escape(item["id"]) + '">')
            lines.append(pad(4) + '<ul class="tsw-bar__menu" aria-label="' + escape(item["label"]) + '">')
            for index, entry in enumerate(shippable):
                subs = [sub for sub in entry.get("menu", []) if not sub.get("pending")]
                link = '<a class="tsw-bar__menulink" href="' + escape(entry["href"]) + '" rel="noopener noreferrer">' + escape(entry["label"]) + '</a>'
                if not subs:
                    lines.append(pad(5) + '<li class="tsw-bar__menuitem">' + link + '</li>')
                    continue
                lines.append(pad(5) + '<li class="tsw-bar__menuitem tsw-bar__menuitem--parent">')
                lines.append(pad(6) + link)
                lines.append(pad(6) + '<ul class="tsw-bar__submenu" id="tsw-bar-sub-' + escape(item["id"]) + "-" + str(index) + '" aria-label="' + escape(entry["label"]) + '">')
                for sub in subs:
                    lines.append(pad(7) + '<li class="tsw-bar__subitem"><a class="tsw-bar__sublink" href="' + escape(sub["href"]) + '" rel="noopener noreferrer">' + escape(sub["label"]) + '</a></li>')
                lines.append(pad(6) + '</ul>')
                lines.append(pad(5) + '</li>')
            lines.append(pad(4) + '</ul>')
            lines.append(pad(3) + '</div>')
        lines.append(pad(2) + '</li>')
    lines.append(pad(1) + '</ul>')
    lines.append(indent + '</nav>')
    return "\n".join(lines)


def index_region(html):
    """The lines between the platform-bar markers in index.html, or None if the markers are missing."""
    start = html.find(START)
    end = html.find(END)
    if start < 0 or end < 0 or end < start:
        return None
    start = html.find("\n", start)
    return html[start + 1:end].rstrip("\n").rstrip()


def markup_problems(menu):
    """The static bar in index.html must equal what the copy generates."""
    html = INDEX.read_text(encoding="utf-8")
    region = index_region(html)
    if region is None:
        return ["site/index.html is missing the platform-bar markers"]
    if region != render_bar(menu):
        return ["site/index.html's platform bar does not match platform-nav.json; run "
                "`python -I tests/check_platform_nav.py --emit` and paste the result between the markers"]
    return []


def compare_canonical(url, copy_bytes):
    request = urllib.request.Request(url, headers={"User-Agent": "platform-nav-check"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            canonical = response.read()
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return True, "canonical not published yet (404 at " + url + ")"
        return True, "canonical not readable yet (HTTP " + str(error.code) + " at " + url + ")"
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return True, "canonical unreachable, treated as not published yet (" + str(error) + ")"
    if canonical == copy_bytes:
        return True, "canonical matches the vendored copy byte for byte"
    return False, "the vendored copy differs from the published canonical file at " + url


def main(argv):
    raw = COPY.read_bytes()
    if "--emit" in argv:
        print(render_bar(json.loads(raw.decode("ascii"))))
        return 0
    issues = problems(raw)
    if not issues:
        issues = markup_problems(json.loads(raw.decode("ascii")))
    for line in issues:
        print("FAIL: " + line)
    if issues:
        return 1
    print("OK: site/platform-nav.json is valid and the static bar in index.html matches it (" + str(len(raw)) + " bytes)")
    if "--canonical" in argv:
        rest = [arg for arg in argv if arg != "--canonical"]
        url = rest[0] if rest else CANONICAL_DEFAULT
        ok, message = compare_canonical(url, raw)
        print(("OK: " if ok else "FAIL: ") + message)
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
