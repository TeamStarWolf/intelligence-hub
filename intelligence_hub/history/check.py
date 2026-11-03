"""The offline history check: every rule the committed history/ files and the fixtures must meet.

No network. It validates the schema of every row, the canonical bytes and sort order
of every year file, unique ids across all files, URL safety, dates inside the file's
year, the 1,500-row and 4 KB caps, coverage.json's agreement with the row counts, and
re-parses every fixture under tests/history/fixtures/ to its golden file.
"""
import json
from pathlib import Path

from . import ADAPTERS, base, canonical, coverage

FIXTURES = Path("tests") / "history" / "fixtures"


def check_files(root):
    """(row counts {(adapter, year): n}, total bytes, total rows). Raises HistoryError on the first broken rule."""
    counts, seen, total_bytes = {}, set(), 0
    folder = canonical.directory(root)
    if folder.is_dir():
        for item in folder.iterdir():
            base.require(item.name == canonical.COVERAGE or item.name == "README.md" or (item.is_dir() and item.name in ADAPTERS),
                         "Unexpected entry under history/: " + item.name)
    for (adapter, year), path in sorted(canonical.year_files(root).items()):
        base.require(adapter in ADAPTERS, "history/" + adapter + "/ is not a registered adapter.")
        base.require(coverage.FIRST_YEAR <= year <= 2100, "history/" + adapter + "/" + path.name + " is outside the archive years.")
        raw, rows = canonical.read_year(path)
        name = "history/" + adapter + "/" + path.name
        base.require(rows, name + " is empty; a year with no rows has no file.")
        base.require(len(rows) <= base.MAX_ROWS_PER_YEAR, name + " has more than " + format(base.MAX_ROWS_PER_YEAR, ",") + " rows.")
        for row in rows:
            base.validate_row(row, ADAPTERS)
            base.require(row["adapter"] == adapter, name + " holds a row of another adapter: " + row["id"])
            base.require(int(row["published"][:4]) == year, name + " holds a row dated outside its year: " + row["id"])
            base.require(row["id"] not in seen, "Duplicate history row id " + row["id"] + ".")
            seen.add(row["id"])
        base.require([base.order(row) for row in rows] == sorted(base.order(row) for row in rows), name + " is not sorted by date and id.")
        base.require(raw == canonical.encode(rows), name + " is not in canonical form (sorted keys, compact JSON, LF).")
        counts[(adapter, year)] = len(rows)
        total_bytes += len(raw)
    return counts, total_bytes, len(seen)


def check_coverage(root, counts):
    value = canonical.read_coverage(root)
    base.require(value is not None, "history/coverage.json is missing.")
    path = canonical.directory(root) / canonical.COVERAGE
    base.require(path.read_bytes() == canonical.encode_json(value), "history/coverage.json is not in canonical form.")
    coverage.validate(value, counts)
    return value


def load_fixture(folder):
    """(adapter module, documents, years, context, expected stats) from one fixture folder."""
    spec = json.loads((folder / "fixture.json").read_text(encoding="utf-8"))
    module = ADAPTERS[spec["adapter"]]
    documents = {name: base.Document((folder / "documents" / relative).read_bytes(), spec["fetched_at"])
                 for name, relative in spec["documents"].items()}
    years = set(range(spec["years"][0], spec["years"][1] + 1))
    context = {key: set(value) for key, value in (spec.get("context") or {}).items()}
    return module, documents, years, context, spec.get("stats")


def run_fixture(folder):
    module, documents, years, context, _stats = load_fixture(folder)
    rows, stats = module.parse(documents, years, context)
    for row in rows:
        base.validate_row(row, ADAPTERS)
    return canonical.encode(rows), stats


def _plain(stats):
    return {key: {str(year): count for year, count in sorted(value.items())} for key, value in sorted(stats.items())}


def check_fixtures(root):
    folder = Path(root) / FIXTURES
    names = sorted(item.name for item in folder.iterdir() if item.is_dir()) if folder.is_dir() else []
    for name in names:
        raw, stats = run_fixture(folder / name)
        golden = (folder / name / "golden.jsonl").read_bytes()
        base.require(raw == golden, "Fixture " + name + " no longer parses to its golden file.")
        expected = load_fixture(folder / name)[4]
        if expected is not None:
            base.require(_plain(stats) == expected, "Fixture " + name + " gives different upstream counts: " + json.dumps(_plain(stats)))
    return names


def run(root, out=print):
    counts, total_bytes, total_rows = check_files(root)
    value = check_coverage(root, counts)
    fixtures = check_fixtures(root)
    by_adapter = {}
    for (adapter, _year), count in counts.items():
        by_adapter[adapter] = by_adapter.get(adapter, 0) + count
    statuses = {}
    for row in value["rows"]:
        statuses[row["status"]] = statuses.get(row["status"], 0) + 1
    out("History check passed: {:,} rows in {:,} files, {:,} bytes; coverage {:,} rows for {} sources, {}-{}; {} fixtures.".format(
        total_rows, len(counts), total_bytes, len(value["rows"]), len(value["sources"]), value["first_year"], value["end_year"], len(fixtures)))
    out("Rows by adapter: " + ", ".join(adapter + " " + format(count, ",") for adapter, count in sorted(by_adapter.items())))
    out("Coverage statuses: " + ", ".join(status + " " + str(count) for status, count in sorted(statuses.items())))
    return {"rows": total_rows, "files": len(counts), "bytes": total_bytes, "by_adapter": by_adapter, "fixtures": fixtures}
