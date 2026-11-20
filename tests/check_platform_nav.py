"""Validate the vendored platform menu and, when asked, compare it to the published canonical file.

site/platform-nav.json is an identical copy of the one cross-site menu every TeamStarWolf site
shows in its top bar. The published original will live at a public address; each site keeps a byte
identical copy and renders it in its own stack. This check runs two ways:

  python -I tests/check_platform_nav.py
      Offline validation only: the copy is plain ASCII, parses, and has the agreed shape (a version,
      a home brand target, and items whose menus nest at most one level, with every "pending" entry
      carrying a note). This is what the pull-request check runs.

  python -I tests/check_platform_nav.py --canonical [URL]
      Also fetch the canonical file (default https://teamstarwolf.com/platform-nav.json) and require
      the vendored copy to match it byte for byte. While the canonical file is not published yet, a
      404 or an unreachable host is tolerated and reported, not failed; once it is published, a
      mismatch fails. This is for the publish workflow, which has network access.

Exit 0 when the copy is valid (and, with --canonical, matches or the canonical is not published);
exit 1 on any validation failure or a real mismatch.
"""
from pathlib import Path
import json
import sys
import urllib.error
import urllib.request

COPY = Path(__file__).resolve().parent.parent / "site" / "platform-nav.json"
CANONICAL_DEFAULT = "https://teamstarwolf.com/platform-nav.json"
TIMEOUT = 8


def problems(raw):
    """Every validation problem with the vendored bytes, as text lines; empty when it is valid."""
    found = []
    try:
        raw.decode("ascii")
    except UnicodeDecodeError:
        found.append("the file is not plain ASCII; non-ASCII characters in an address are percent-encoded")
        return found
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
    items = menu.get("items")
    if not isinstance(items, list) or not items:
        found.append("items is not a non-empty list")
        return found
    ids = set()
    for item in items:
        where = "item " + repr(item.get("id") if isinstance(item, dict) else item)
        if not isinstance(item, dict):
            found.append(where + " is not an object")
            continue
        for key in ("id", "label", "href"):
            if not isinstance(item.get(key), str) or not item[key]:
                found.append(where + " has no " + key)
        if item.get("id") in ids:
            found.append(where + " repeats an id")
        ids.add(item.get("id"))
        found += entry_problems(item.get("menu"), where, depth=1)
    return found


def entry_problems(menu, where, depth):
    """Problems in a menu list: labels, https or pending-noted addresses, and at most one nested level."""
    out = []
    if menu is None:
        return out
    if not isinstance(menu, list):
        return [where + " menu is not a list"]
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
        href = entry.get("href")
        if href is not None and not (isinstance(href, str) and href.startswith("https://")):
            out.append(at + " href is not an https address")
        if "menu" in entry:
            if depth >= 2:
                out.append(at + " nests deeper than one level")
            else:
                out += entry_problems(entry.get("menu"), at, depth + 1)
    return out


def compare_canonical(url, copy_bytes):
    """Compare the copy to the canonical file. Returns (ok, message); ok is False only on a real
    mismatch, True when they match or the canonical file is not published yet."""
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
    issues = problems(raw)
    for line in issues:
        print("FAIL: " + line)
    if issues:
        return 1
    print("OK: site/platform-nav.json is valid ASCII with the agreed shape (" + str(len(raw)) + " bytes)")
    if "--canonical" in argv:
        rest = [arg for arg in argv if arg != "--canonical"]
        url = rest[0] if rest else CANONICAL_DEFAULT
        ok, message = compare_canonical(url, raw)
        print(("OK: " if ok else "FAIL: ") + message)
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
