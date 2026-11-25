"""Validate the vendored platform menu, keep the static bar in index.html in step with it, and,
when asked, compare the copy to the published canonical file.

site/platform-nav.json is an identical copy of the one cross-site menu every TeamStarWolf site
shows in its top bar. site/index.html carries the menu as static markup between the
"platform-bar" markers, so that with JavaScript off every link still works and the stylesheet opens
the menus on :hover and :focus-within; site/js/platform-bar.js only enhances that markup. This
check holds the three in step and runs several ways:

  python -I tests/check_platform_nav.py
      Offline: the copy is plain ASCII, parses, has the agreed shape (a version, a home brand
      target, items that each carry a link and may or may not carry a menu, whose menus hold the
      allowed number of entries and nest only where allowed, every "pending" entry noted), every
      address passes the rule that fits it, and the static bar in index.html matches what the copy
      generates. The pull-request check runs this.

  python -I tests/check_platform_nav.py --emit
      Print the static bar markup for index.html (what the check compares against). Paste it between
      the platform-bar markers when the menu changes.

  python -I tests/check_platform_nav.py --canonical [URL]
      Also fetch the canonical file (default https://teamstarwolf.com/platform-nav.json) and require
      the vendored copy to match it byte for byte, tolerating "not published yet". For the publish
      workflow, which has network access. A file: URL or path works too, for checking against a local
      copy of the canonical file before it is published.

Two address rules apply. Every address that is not an external Bookmarks leaf (every item, the home
brand target, every section header and every entry outside Bookmarks) must be an https link to a
TeamStarWolf property; that is the rule every version used, unchanged. A leaf inside the Bookmarks
item may point outside, and only there, when it carries "external": true; such a leaf obeys a
separate, stricter rule and must not be an address the TeamStarWolf rule would accept.

Exit 0 when valid (and, with --canonical, matching or not-yet-published); exit 1 otherwise.
"""
from pathlib import Path
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
COPY = ROOT / "site" / "platform-nav.json"
INDEX = ROOT / "site" / "index.html"
CANONICAL_DEFAULT = "https://teamstarwolf.com/platform-nav.json"
TIMEOUT = 8
MAX_ENTRIES = 14          # every menu outside the Bookmarks item
BOOKMARKS_MAX = 16        # a list inside the Bookmarks item (categories, subsections or leaves)
EXTERNAL_MAX = 512        # an external leaf address
BOOKMARKS_ID = "bookmarks"
START = "<!-- platform-bar:start"
END = "<!-- platform-bar:end -->"
# Every address that is not an external leaf must be https and point at a TeamStarWolf property. The
# copy is later refreshed from a file another site publishes, so the check covers where the links go,
# not just the shape. github.com is allowed only under the TeamStarWolf account.
ALLOWED_HOSTS = frozenset({"teamstarwolf.com", "library.teamstarwolf.com", "teamstarwolf.github.io", "github.com"})
# One DNS label: letters, digits and hyphens, not starting or ending with a hyphen, at most 63 long.
DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def href_problem(href, where):
    """Why this address is not an allowed TeamStarWolf https link, or None when it is fine. This is
    the rule every version has used for every address outside an external Bookmarks leaf; it stays
    exactly this strict."""
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


def external_problem(href, where):
    """Why this external-leaf address is not allowed, or None when it is fine. Stricter than the
    TeamStarWolf rule: it is the only place an address off the four hosts may appear, so it is pinned
    down on the raw string, parses to a real DNS host, and must not be an address the TeamStarWolf
    rule would already accept (so the flag cannot smuggle an internal address, nor be dropped)."""
    if not isinstance(href, str):
        return where + " external address is not a string"
    if not href.startswith("https://"):
        return where + " external address is not https"
    if len(href) > EXTERNAL_MAX:
        return where + " external address is longer than " + str(EXTERNAL_MAX) + " characters"
    # Only printable ASCII is allowed, so no whitespace or control character, and no character the
    # file carried as a \uXXXX escape (which decodes to a non-ASCII character the raw-byte ASCII test
    # does not see). Everything above "~" and below "!" is rejected.
    for char in href:
        if ord(char) < 0x21 or ord(char) > 0x7e:
            return where + " external address has a non-printable or non-ASCII character"
    if "\\" in href:
        return where + " external address has a backslash"
    parts = urllib.parse.urlsplit(href)
    if "@" in parts.netloc:
        return where + " external address has userinfo (an @ before the host)"
    try:
        port = parts.port
    except ValueError:
        return where + " external address has an invalid port"
    if port is not None:
        return where + " external address has an explicit port: " + str(port)
    host = parts.hostname or ""
    if not host:
        return where + " external address has no host"
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        return where + " external address host is not ASCII"
    # An IP literal (v4 or bracketed v6) is rejected: an external bookmark names a DNS host.
    try:
        ipaddress.ip_address(host)
        return where + " external address host is an IP literal: " + host
    except ValueError:
        pass
    if "." not in host:
        return where + " external address host is a single label (no dot): " + host
    labels = host.split(".")
    # A browser also reads several shorthand forms as an IP address that ipaddress does not, such as
    # 127.1, 1.2.3 and hosts with a hex or decimal final part (0x7f.0.0.1, 1.2.3.0x7f). A real host
    # never ends in an all-digit or 0x label, so reject that last label.
    last = labels[-1].lower()
    if last.isdigit() or last.startswith("0x"):
        return where + " external address host looks like an IP address (numeric or hex last label): " + host
    for label in labels:
        if not DNS_LABEL.fullmatch(label):
            return where + " external address host has an invalid DNS label: " + host
        if label.lower().startswith("xn--"):
            return where + " external address host is punycode: " + host
    # The path alone (query and fragment already split off): no dot segment in any form, and no
    # encoded slash or backslash that a browser would turn back into a path separator.
    for segment in parts.path.split("/"):
        if urllib.parse.unquote(segment).lower() in (".", ".."):
            return where + " external address has a dot path segment: " + parts.path
    low = parts.path.lower()
    if "%2f" in low or "%5c" in low:
        return where + " external address has an encoded slash or backslash in the path: " + parts.path
    # The flag must not dress up an address the TeamStarWolf rule would accept, so a four-host link
    # cannot wear it and an internal link cannot hide behind it.
    if href_problem(href, where) is None:
        return where + " is an internal TeamStarWolf address wearing the external flag"
    return None


def entry_label(entry):
    return repr(entry.get("label") if isinstance(entry, dict) else entry)


def common_entry_problems(entry, at):
    """Label and pending-note checks every menu entry shares."""
    out = []
    if not isinstance(entry.get("label"), str) or not entry["label"]:
        out.append(at + " has no label")
    pending = entry.get("pending")
    if pending is not None and (not isinstance(pending, str) or not pending):
        out.append(at + " has an empty pending note")
    return out


def plain_entry_problems(menu, where, depth):
    """A menu outside the Bookmarks item: labels, TeamStarWolf https addresses, no external flag, at
    most MAX_ENTRIES entries, one nested level and no deeper."""
    out = []
    if menu is None:
        return out
    if not isinstance(menu, list):
        return [where + " menu is not a list"]
    if len(menu) > MAX_ENTRIES:
        out.append(where + " menu has " + str(len(menu)) + " entries, more than the " + str(MAX_ENTRIES) + " cap")
    for entry in menu:
        at = where + " > " + entry_label(entry)
        if not isinstance(entry, dict):
            out.append(at + " is not an object")
            continue
        out += common_entry_problems(entry, at)
        if entry.get("external") is not None:
            out.append(at + " carries an external flag outside the Bookmarks item")
        if entry.get("href") is not None:
            bad = href_problem(entry.get("href"), at)
            if bad:
                out.append(bad)
        if "menu" in entry:
            if depth >= 2:
                out.append(at + " nests deeper than one level")
            else:
                out += plain_entry_problems(entry.get("menu"), at, depth + 1)
    return out


def bookmarks_entry_problems(menu, where, level):
    """A list inside the Bookmarks item. level 1 is the categories, 2 is a category's children
    (subsections or leaves), 3 is a subsection's leaves. A header (an entry with a menu) is an
    internal TeamStarWolf link; a leaf with "external": true is an external address and carries no
    menu; nothing nests past a subsection's leaves."""
    out = []
    if not isinstance(menu, list):
        return [where + " menu is not a list"]
    if len(menu) > BOOKMARKS_MAX:
        out.append(where + " menu has " + str(len(menu)) + " entries, more than the " + str(BOOKMARKS_MAX) + " cap")
    for entry in menu:
        at = where + " > " + entry_label(entry)
        if not isinstance(entry, dict):
            out.append(at + " is not an object")
            continue
        out += common_entry_problems(entry, at)
        is_external = entry.get("external") is True
        has_menu = "menu" in entry
        if is_external:
            if has_menu:
                out.append(at + " is flagged external but has a menu")
            out_bad = external_problem(entry.get("href"), at)
            if out_bad:
                out.append(out_bad)
        else:
            if entry.get("external") is not None:
                out.append(at + " has an external flag that is not true")
            bad = href_problem(entry.get("href"), at)
            if bad:
                out.append(bad)
            if has_menu:
                if level >= 3:
                    out.append(at + " nests deeper than the Bookmarks item allows (category, subsection, leaf)")
                else:
                    out += bookmarks_entry_problems(entry.get("menu"), at, level + 1)
    return out


def source_problems(source, where):
    """The Bookmarks item names the snapshot it was generated from; accept it, do not render it."""
    if source is None:
        return []
    if not isinstance(source, dict):
        return [where + " source is not an object"]
    out = []
    for key in ("repo", "path", "commit"):
        if not isinstance(source.get(key), str) or not source[key]:
            out.append(where + " source has no " + key)
    return out


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
        if "source" in item and item.get("id") != BOOKMARKS_ID:
            found.append(where + " carries a source field outside the Bookmarks item")
        if item.get("id") == BOOKMARKS_ID:
            found += source_problems(item.get("source"), where)
            found += bookmarks_entry_problems(item.get("menu"), where, level=1)
        else:
            found += plain_entry_problems(item.get("menu"), where, depth=1)
    return found


def escape(text):
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def render_bar(menu, indent="    "):
    """The static platform-bar markup for index.html: the top-level links and their dropdown panels.
    Every menu and fly-out link is a real <a>; an external Bookmarks leaf opens in a new tab and
    carries its marker and screen-reader note. Pending entries are left out. A top-level item with no
    menu, or whose menu holds nothing shippable, is written as a plain link with no panel.
    platform-bar.js enhances this: it adds the caret buttons, so the markup here is links only and
    works without JavaScript."""
    pad = lambda level: indent + "  " * level

    def mlink(entry):
        external = entry.get("external") is True and "menu" not in entry
        classes = "tsw-bar__mlink tsw-bar__mlink--ext" if external else "tsw-bar__mlink"
        rel = ' target="_blank" rel="noopener noreferrer"' if external else ' rel="noopener noreferrer"'
        inner = escape(entry["label"])
        if external:
            inner += ('<span class="tsw-bar__ext" aria-hidden="true"></span>'
                      '<span class="tsw-bar__sr"> (opens in a new tab on an external site)</span>')
        return '<a class="' + classes + '" href="' + escape(entry["href"]) + '"' + rel + '>' + inner + '</a>'

    def render_list(entries, level, label):
        lines = [pad(level) + '<ul class="tsw-bar__flyout" aria-label="' + escape(label) + '">']
        for entry in entries:
            subs = [sub for sub in entry.get("menu", []) if not sub.get("pending")]
            if subs:
                lines.append(pad(level + 1) + '<li class="tsw-bar__mitem tsw-bar__mitem--parent">')
                lines.append(pad(level + 2) + mlink(entry))
                lines += render_list(subs, level + 2, entry["label"])
                lines.append(pad(level + 1) + '</li>')
            else:
                lines.append(pad(level + 1) + '<li class="tsw-bar__mitem">' + mlink(entry) + '</li>')
        lines.append(pad(level) + '</ul>')
        return lines

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
            lines += render_list(shippable, 4, item["label"])
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


def emit(markup):
    """Write the markup to stdout as UTF-8, whatever the console encoding. A menu label can hold a
    non-ASCII character (carried in the ASCII file as a \\uXXXX escape, such as an arrow), so a plain
    print() crashes with a UnicodeEncodeError when stdout is a redirected Windows console (cp1252).
    The maintainer's documented repair is to run --emit and paste the result, so it must not crash."""
    data = (markup + "\n").encode("utf-8")
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        buffer.flush()
    else:
        sys.stdout.write(markup + "\n")


def main(argv):
    raw = COPY.read_bytes()
    if "--emit" in argv:
        emit(render_bar(json.loads(raw.decode("ascii"))))
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
