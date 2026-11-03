"""Fail when a tracked text file outside reports/ contains an em dash (U+2014).

reports/ is written by the owner's separate desktop compiler and is not linted here.

    python -I tests/check_em_dash.py
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
EM_DASH = chr(0x2014)
EXCLUDED = ("reports/",)


def tracked_files():
    listing = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return [name for name in listing.decode("utf-8").split("\0") if name and not name.startswith(EXCLUDED)]


def hits(names):
    found = []
    for name in names:
        path = ROOT / name
        try:
            text = path.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # binary or unreadable files carry no prose
        for number, line in enumerate(text.splitlines(), 1):
            if EM_DASH in line:
                found.append((name, number))
    return found


def main():
    found = hits(tracked_files())
    for name, number in found:
        print(name + ":" + str(number) + ": em dash (U+2014); use a comma, colon, parentheses or a new sentence.")
    if found:
        return 1
    print("No em dashes outside reports/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
