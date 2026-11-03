"""The committed history files: history/<adapter>/<year>.jsonl and history/coverage.json.

A year file is one canonical JSON row per line (sorted keys, compact separators,
UTF-8, LF), rows ordered by publication date and then id, with a trailing newline.
The same rows always give the same bytes, so an unchanged year never shows in a diff.
"""
import json
import re
from pathlib import Path

from . import base

DIRECTORY = "history"
COVERAGE = "coverage.json"
YEAR_FILE = re.compile(r"([0-9]{4})\.jsonl")


def encode(rows):
    return b"".join(base.canonical_row(row) + b"\n" for row in sorted(rows, key=base.order))


def _compact(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def encode_json(value):
    """coverage.json: canonical JSON with each source and each row on its own line, so a diff shows one row per change."""
    head = {key: item for key, item in value.items() if key not in ("rows", "sources")}
    parts = [_compact(head)[:-1]]
    for key in ("rows", "sources"):
        if key in value:
            parts.append(',"' + key + '":[\n' + ",\n".join(_compact(item) for item in value[key]) + "\n]")
    return ("".join(parts) + "}\n").encode("utf-8")


def directory(root):
    return Path(root) / DIRECTORY


def write_adapter(root, adapter, rows, years):
    """Write one adapter's year files for the built years; remove built years that now have no rows.

    Returns {year: rows written}. Years outside `years` are left as they are.
    """
    folder = directory(root) / adapter
    by_year = {}
    for row in rows:
        by_year.setdefault(int(row["published"][:4]), []).append(row)
    counts = {}
    for year in sorted(years):
        path = folder / (str(year) + ".jsonl")
        items = by_year.get(year, [])
        if items:
            folder.mkdir(parents=True, exist_ok=True)
            raw = encode(items)
            if not path.exists() or path.read_bytes() != raw:
                path.write_bytes(raw)
            counts[year] = len(items)
        elif path.exists():
            path.unlink()
    return counts


def read_year(path):
    raw = path.read_bytes()
    try:
        rows = [json.loads(line) for line in raw.decode("utf-8").split("\n") if line]
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise base.HistoryError(path.parent.name + "/" + path.name + " is not one JSON row per line: " + str(error)[:120]) from error
    return raw, rows


def year_files(root):
    """{(adapter, year): path} for every year file under history/."""
    found = {}
    folder = directory(root)
    if not folder.is_dir():
        return found
    for adapter in sorted(item for item in folder.iterdir() if item.is_dir()):
        for path in sorted(adapter.iterdir()):
            match = YEAR_FILE.fullmatch(path.name)
            base.require(match is not None and path.is_file() and not path.is_symlink(),
                         "Unexpected file in history/" + adapter.name + "/: " + path.name)
            found[(adapter.name, int(match.group(1)))] = path
    return found


def read_rows(root, adapters=None):
    """Every committed row, validated, as a list (adapter and year order)."""
    rows = []
    for (adapter, _year), path in sorted(year_files(root).items()):
        if adapters is None or adapter in adapters:
            _raw, items = read_year(path)
            rows.extend(items)
    return rows


def read_coverage(root):
    path = directory(root) / COVERAGE
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def write_coverage(root, value):
    folder = directory(root)
    folder.mkdir(parents=True, exist_ok=True)
    raw = encode_json(value)
    path = folder / COVERAGE
    if not path.exists() or path.read_bytes() != raw:
        path.write_bytes(raw)
