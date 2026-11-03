"""Fail when any font size in the site's stylesheet or scripts is under 12 px.

Every font-size and font shorthand in site/*.css is resolved through the --text-* tokens and
read with a 16 px root: px values must be at least 12, rem, em and percentage values at least
0.75rem, 0.75em and 75%, and the keywords smaller, x-small and xx-small are refused. Scripts
under site/ may not set a font size at all. The root font size is not pinned, so a reader's
browser setting still scales every size.

Usage: python -I tests/check_font_size.py   (exit 1 with every offending declaration)
"""
from pathlib import Path
import re
import sys

SITE = Path(__file__).resolve().parent.parent / "site"
FLOOR_PX = 12
ROOT_PX = 16
DECLARATION = re.compile(r"(?<![\w-])(font-size|font)\s*:\s*([^;}]+)")
TOKEN = re.compile(r"(--text-[\w-]+)\s*:\s*([^;]+);")
SIZE = re.compile(r"(?<![\w.-])(\d*\.?\d+)(px|rem|em|%)(?![\w-])")
KEYWORDS = {"smaller", "x-small", "xx-small"}


def px(number, unit):
    value = float(number)
    return value if unit == "px" else value * ROOT_PX if unit in ("rem", "em") else value / 100 * ROOT_PX


def problems(site=SITE):
    found = []
    for path in sorted(site.rglob("*.css")):
        css = re.sub(r"/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.S)
        tokens = {name: value.strip() for name, value in TOKEN.findall(css)}
        for name, value in tokens.items():
            for number, unit in SIZE.findall(value):
                if px(number, unit) < FLOOR_PX:
                    found.append(path.name + ": token " + name + ": " + value)
        for line_number, line in enumerate(css.splitlines(), 1):
            if re.match(r"\s*--", line):
                continue
            for prop, value in DECLARATION.findall(line):
                resolved = re.sub(r"var\((--text-[\w-]+)\)", lambda match: tokens.get(match[1], match[0]), value)
                if prop == "font":
                    # Only the size before an optional /line-height counts in the shorthand.
                    resolved = re.split(r"/", resolved)[0]
                if prop == "font-size" and "var(" in resolved:
                    found.append(path.name + ":" + str(line_number) + ": unresolved size token: " + value.strip())
                for keyword in KEYWORDS:
                    if re.search(r"(?<![\w-])" + keyword + r"(?![\w-])", resolved):
                        found.append(path.name + ":" + str(line_number) + ": " + prop + ": " + value.strip())
                for number, unit in SIZE.findall(resolved):
                    if px(number, unit) < FLOOR_PX:
                        found.append(path.name + ":" + str(line_number) + ": " + prop + ": " + value.strip())
        if re.search(r"(?<![\w-])html\s*\{[^}]*font-size", css):
            found.append(path.name + ": the root font size is pinned")
    for path in sorted(site.rglob("*.js")):
        if re.search(r"fontSize|font-size", path.read_text(encoding="utf-8")):
            found.append(path.relative_to(site).as_posix() + ": a script sets a font size")
    return found


def main():
    found = problems()
    for line in found:
        print("FAIL: " + line)
    if found:
        return 1
    print("OK: no font size under " + str(FLOOR_PX) + " px in site/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
