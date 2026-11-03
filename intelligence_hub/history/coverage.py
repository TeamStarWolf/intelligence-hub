"""Coverage statements: one row per source and year from 1998, so "since 1998" never implies "everything since 1998".

status is one of:
- complete: every item the source lists for that year is a row;
- filtered: the adapter's stated filter (or the 1,500-row yearly cap) chose the rows;
- partial: some listed items could not be read;
- sample: a fixed sample by design;
- gap: no items that year (the source had not started, the series had ended, or the
  adapter is not built yet, which the reason says);
- unreachable: the source refused automated reads, is JavaScript-only or needs a login.
"""
from . import ADAPTERS, CHECKED, STATIC_SOURCES, base

SCHEMA_VERSION = 1
FIRST_YEAR = base.FIRST_YEAR
END_YEAR = 2026
STATUSES = ("complete", "filtered", "partial", "sample", "gap", "unreachable")
ROW_KEYS = ("source_id", "adapter", "year", "status", "upstream_count", "admitted", "filter", "reason", "checked_at", "licence")


def source_entries():
    entries = [{"source_id": module.SOURCE_ID, "name": module.SOURCE_NAME, "adapter": module.ID, "home": module.HOME,
                "first_year": module.FIRST_YEAR, "last_year": module.LAST_YEAR, "filter": module.FILTER, "licence": module.LICENCE}
               for module in ADAPTERS.values()]
    entries += [{"source_id": item["source_id"], "name": item["name"], "adapter": None, "home": item["home"],
                 "first_year": None, "last_year": None, "filter": None, "licence": None} for item in STATIC_SOURCES]
    return sorted(entries, key=lambda item: item["source_id"])


def adapter_rows(module, stats, counts, years, checked_at, end_year=END_YEAR):
    """Coverage rows for one built adapter, for the built years only."""
    rows = []
    for year in sorted(years):
        if year < FIRST_YEAR or year > end_year:
            continue
        upstream = (stats.get("upstream") or {}).get(year, 0)
        missing = (stats.get("missing") or {}).get(year, 0)
        capped = (stats.get("capped") or {}).get(year, 0)
        admitted = counts.get(year, 0)
        row = {"source_id": module.SOURCE_ID, "adapter": module.ID, "year": year, "upstream_count": upstream,
               "admitted": admitted, "filter": module.FILTER, "reason": None, "checked_at": checked_at, "licence": module.LICENCE}
        if year < module.FIRST_YEAR:
            row.update(status="gap", upstream_count=0, filter=None, reason="the source's first item is from " + str(module.FIRST_YEAR))
        elif module.LAST_YEAR and year > module.LAST_YEAR:
            row.update(status="gap", upstream_count=0, filter=None, reason="the series ended in " + str(module.LAST_YEAR))
        elif upstream == 0 and admitted == 0 and missing == 0:
            row.update(status="gap", filter=None, reason="the source lists no items for this year")
        elif missing:
            row.update(status="partial", reason=format(missing, ",") + " listed items could not be read")
        elif module.FILTER or capped:
            row.update(status="filtered", reason=(format(capped, ",") + " rows over the 1,500-row yearly cap were left out") if capped else None)
        else:
            base.require(admitted == upstream, module.ID + " " + str(year) + ": admitted rows differ from the upstream count without a filter.")
            row.update(status="complete")
        rows.append(row)
    return rows


def static_rows(end_year=END_YEAR):
    rows = []
    for item in STATIC_SOURCES:
        for year in range(FIRST_YEAR, end_year + 1):
            rows.append({"source_id": item["source_id"], "adapter": None, "year": year, "status": item["status"],
                         "upstream_count": None, "admitted": 0, "filter": None, "reason": item["reason"],
                         "checked_at": CHECKED, "licence": None})
    return rows


def merge(previous, built, end_year=END_YEAR):
    """coverage.json from the previous file's adapter rows, replaced by this build's rows, plus the static rows."""
    keep = {}
    for row in (previous or {}).get("rows") or []:
        if row.get("adapter") in ADAPTERS and FIRST_YEAR <= row.get("year", 0) <= end_year:
            keep[(row["source_id"], row["year"])] = row
    for row in built:
        keep[(row["source_id"], row["year"])] = row
    rows = list(keep.values()) + static_rows(end_year)
    return {"schema_version": SCHEMA_VERSION, "kind": "history-coverage", "first_year": FIRST_YEAR, "end_year": end_year,
            "statuses": list(STATUSES), "sources": source_entries(),
            "rows": sorted(rows, key=lambda row: (row["source_id"], row["year"]))}


def validate(value, counts):
    """coverage.json agrees with itself and with the committed row counts {(adapter, year): rows}."""
    base.require(isinstance(value, dict) and value.get("schema_version") == SCHEMA_VERSION and value.get("kind") == "history-coverage",
                 "history/coverage.json has the wrong schema.")
    end_year = value.get("end_year")
    base.require(value.get("first_year") == FIRST_YEAR and isinstance(end_year, int) and END_YEAR <= end_year <= 2100,
                 "history/coverage.json must run from 1998 to at least " + str(END_YEAR) + ".")
    base.require(value.get("statuses") == list(STATUSES) and value.get("sources") == source_entries(),
                 "history/coverage.json's statuses or source list are stale; run the history coverage command.")
    sources = {item["source_id"]: item for item in value["sources"]}
    seen = {}
    for row in value.get("rows") or []:
        base.require(isinstance(row, dict) and sorted(row) == sorted(ROW_KEYS) and row["status"] in STATUSES and
                     row["source_id"] in sources and isinstance(row["year"], int) and FIRST_YEAR <= row["year"] <= end_year and
                     type(row["admitted"]) is int and row["admitted"] >= 0 and
                     (row["upstream_count"] is None or type(row["upstream_count"]) is int and row["upstream_count"] >= 0),
                     "Invalid coverage row: " + repr(row)[:200])
        key = (row["source_id"], row["year"])
        base.require(key not in seen, "Duplicate coverage row for " + row["source_id"] + " " + str(row["year"]) + ".")
        seen[key] = row
        base.require(row["adapter"] == sources[row["source_id"]]["adapter"], "Coverage row names the wrong adapter: " + repr(key))
        if row["adapter"] is None:
            base.require(row["admitted"] == 0 and row["status"] in ("unreachable", "gap"), "A source without an adapter admits no rows: " + repr(key))
        else:
            base.require(row["admitted"] == counts.get((row["adapter"], row["year"]), 0),
                         "Coverage for " + row["adapter"] + " " + str(row["year"]) + " says " + str(row["admitted"]) +
                         " rows; the committed file has " + str(counts.get((row["adapter"], row["year"]), 0)) + ".")
            if row["status"] == "complete":
                base.require(row["upstream_count"] == row["admitted"], "A complete year admits every upstream item: " + repr(key))
            if row["status"] in ("gap", "unreachable"):
                base.require(row["admitted"] == 0, "A gap year has no rows: " + repr(key))
    for source_id in sources:
        for year in range(FIRST_YEAR, end_year + 1):
            base.require((source_id, year) in seen, "coverage.json has no row for " + source_id + " " + str(year) + ".")
    for (adapter, year), count in counts.items():
        base.require(count == 0 or (ADAPTERS[adapter].SOURCE_ID, year) in seen, "Rows without a coverage row: " + adapter + " " + str(year))
    order = [(row["source_id"], row["year"]) for row in value["rows"]]
    base.require(order == sorted(order), "coverage.json rows are not sorted by source and year.")
