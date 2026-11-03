"""History command line: build, check and coverage.

  build     fetch (or reuse the raw cache), parse and write history/<adapter>/<year>.jsonl
            and history/coverage.json. Run locally at below-normal priority and commit the
            result through a pull request; the publish workflow never runs it.
  check     the offline check (CI runs it on every pull request).
  coverage  rewrite coverage.json's source list and static rows without fetching, and print
            a per-source summary.
  fixtures  rewrite the golden files from the fixtures (after a reviewed parser change).

Examples:
  python -E -s -m intelligence_hub.history build --adapter msrc-bulletins --years 1998-2017
  python -E -s -m intelligence_hub.history check
"""
import argparse
import json
import sys
from datetime import date
from pathlib import Path

from . import ADAPTERS, base, canonical, check, coverage
from ..collect import CATALOG_URL, ROOT

CACHE = ROOT / ".state" / "history-raw"
KEV_HOSTS = ("www.cisa.gov",)
# Adapters whose rows only count as references for the adapters listed after them.
REFERENCE_SOURCES = {"ubuntu-usn": set(ADAPTERS) - {"ubuntu-usn", "nvd-cve"}, "nvd-cve": set(ADAPTERS) - {"nvd-cve"}}


def year_range(value):
    first, _, last = value.partition("-")
    first, last = int(first), int(last or first)
    if not base.FIRST_YEAR <= first <= last <= 2100:
        raise argparse.ArgumentTypeError("years run from 1998, as FIRST-LAST")
    return set(range(first, last + 1))


def kev_cves(offline, refresh):
    fetcher = base.Fetcher(CACHE, "cisa-kev", KEV_HOSTS, offline=offline, refresh=refresh)
    catalog = json.loads(fetcher.get(CATALOG_URL, 8 * 1024 * 1024, accept="application/json").raw)
    return {entry["cveID"] for entry in catalog.get("vulnerabilities") or [] if isinstance(entry, dict) and isinstance(entry.get("cveID"), str)}


def referenced(root, adapters):
    found = set()
    for row in canonical.read_rows(root, adapters):
        found.update(row["cve"])
    return found


def build(root, chosen, years, offline=False, refresh=False, out=print):
    previous = canonical.read_coverage(root)
    built, today = [], date.today().isoformat()
    kev = None
    for ident in [name for name in ADAPTERS if name in chosen]:
        module = ADAPTERS[ident]
        context = {}
        if ident in REFERENCE_SOURCES:
            if kev is None:
                kev = kev_cves(offline, refresh)
            context = {"kev": kev, "referenced": referenced(root, REFERENCE_SOURCES[ident])}
        fetcher = base.Fetcher(CACHE, getattr(module, "CACHE", module.ID), module.HOSTS, offline=offline, refresh=refresh, log=out)
        documents = module.fetch(fetcher, years, context)
        rows, stats = module.parse(documents, years, context)
        for row in rows:
            base.validate_row(row, ADAPTERS)
            base.require(int(row["published"][:4]) in years, ident + " returned a row outside the built years: " + row["id"])
        counts = canonical.write_adapter(root, ident, rows, years)
        built.extend(coverage.adapter_rows(module, stats, counts, years, today))
        out("{}: {:,} documents ({:,} fetched), {:,} rows in {:,} year files".format(
            ident, len(documents), fetcher.requests, len(rows), len(counts)))
        # Later adapters read this adapter's rows, so write coverage after each one.
        previous = coverage.merge(previous, built)
        canonical.write_coverage(root, previous)
    return previous


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m intelligence_hub.history", description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("build", help="fetch, parse and write history files")
    make.add_argument("--adapter", action="append", choices=sorted(ADAPTERS), help="adapter id (repeatable); default every adapter")
    make.add_argument("--years", type=year_range, default=set(range(base.FIRST_YEAR, coverage.END_YEAR + 1)))
    make.add_argument("--offline", action="store_true", help="read the raw cache only; never fetch")
    make.add_argument("--refresh", action="store_true", help="fetch again even when the raw cache has a document")
    commands.add_parser("check", help="the offline check")
    commands.add_parser("coverage", help="rewrite coverage.json's static rows and print a summary")
    commands.add_parser("fixtures", help="rewrite the golden files from the fixtures")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            build(ROOT, set(args.adapter or ADAPTERS), args.years, args.offline, args.refresh)
            check.run(ROOT)
        elif args.command == "check":
            check.run(ROOT)
        elif args.command == "coverage":
            value = coverage.merge(canonical.read_coverage(ROOT), [])
            canonical.write_coverage(ROOT, value)
            counts, _bytes, _rows = check.check_files(ROOT)
            coverage.validate(value, counts)
            for source in value["sources"]:
                rows = [row for row in value["rows"] if row["source_id"] == source["source_id"]]
                statuses = {}
                for row in rows:
                    statuses[row["status"]] = statuses.get(row["status"], 0) + 1
                print("{:<28} {:>7,} rows  {}".format(source["source_id"], sum(row["admitted"] for row in rows),
                                                     ", ".join(key + " " + str(count) for key, count in sorted(statuses.items()))))
        elif args.command == "fixtures":
            folder = Path(ROOT) / check.FIXTURES
            for name in sorted(item.name for item in folder.iterdir() if item.is_dir()):
                raw, _stats = check.run_fixture(folder / name)
                (folder / name / "golden.jsonl").write_bytes(raw)
                print("golden " + name + ": " + str(raw.count(b"\n")) + " rows")
    except (base.HistoryError, OSError, KeyError, json.JSONDecodeError) as error:
        print("History " + args.command + " failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
