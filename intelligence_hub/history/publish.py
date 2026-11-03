"""The publish step's view of history/: committed rows as v7 article rows, and the v7 coverage file.

The publish workflow never fetches a history source. It reads the committed
history/<adapter>/<year>.jsonl files, checks every row, turns each into a v7 article
row with origin "history:<adapter>" and an empty summary, tags it with the same engine
as every other row, and the shard writer files it under history/YYYY.json.

A missing, unreadable or invalid history/ never blocks the feed: the run continues
without adapter rows and records why.
"""
from . import ADAPTERS, base, canonical, check, coverage

# Whether this run's v7 shards carry the adapter rows. The rows are built, tagged and
# measured either way; publishing them is a package-cap question (see the PR that sets it).
HISTORY_PUBLISHED = True
ORIGIN_PREFIX = "history:"


def is_history(row):
    return isinstance(row, dict) and str(row.get("origin", "")).startswith(ORIGIN_PREFIX)


def load(root):
    """(validated committed rows, None) or ([], reason)."""
    try:
        counts, _bytes, _rows = check.check_files(root)
        if not counts:
            return [], "no committed history rows"
        return canonical.read_rows(root), None
    except (base.HistoryError, OSError, ValueError, KeyError, TypeError) as error:
        return [], (str(error) or type(error).__name__)[:300]


def article(row):
    """A committed history row as a v7 article row (the shard row shape, before tagging)."""
    module = ADAPTERS[row["adapter"]]
    value = {"id": row["id"], "title": row["title"], "url": row["url"], "source_id": row["source_id"],
             "source_name": module.SOURCE_NAME, "kind": row["kind"], "published_at": row["published"], "event_date": None,
             "date_basis": "publication" if row["date_basis"] == "publication" else "cross-reference",
             "summary": "", "cves": row["cve"], "tags": [], "exploitation": "known" if row["exploited_flag"] else "unknown",
             "references": [], "origin": ORIGIN_PREFIX + row["adapter"], "native_id": row["native_id"]}
    if row["severity"]:
        value["severity"] = row["severity"]
    if row["exploited_flag"]:
        value["exploitation_evidence"] = {"basis": "vendor-structured", "exploited": True}
    return value


def articles(root, existing_urls=()):
    """(v7 article rows, summary). A row whose URL is already a feed, KEV or curated row is left to that row."""
    if not HISTORY_PUBLISHED:
        return [], {"status": "unpublished", "reason": "HISTORY_PUBLISHED is off; committed rows are checked but not published"}
    rows, reason = load(root)
    if reason:
        return [], {"status": "empty" if reason == "no committed history rows" else "unavailable", "reason": reason}
    taken = set(existing_urls)
    out, duplicates = [], 0
    for row in rows:
        if row["url"] in taken:
            duplicates += 1
            continue
        taken.add(row["url"])
        out.append(article(row))
    by_adapter = {}
    for row in out:
        by_adapter[row["origin"][len(ORIGIN_PREFIX):]] = by_adapter.get(row["origin"][len(ORIGIN_PREFIX):], 0) + 1
    return out, {"status": "ok", "rows": len(out), "duplicates_left_to_other_rows": duplicates, "by_adapter": dict(sorted(by_adapter.items()))}


def coverage_file(root, schema_version):
    """data/v7/coverage.json: history/coverage.json when it is valid, else a stub that says why."""
    try:
        value = canonical.read_coverage(root)
        if value is None:
            raise base.HistoryError("history/coverage.json is not committed")
        counts, _bytes, _rows = check.check_files(root)
        coverage.validate(value, counts)
    except (base.HistoryError, OSError, ValueError, KeyError, TypeError) as error:
        return {"schema_version": schema_version, "kind": "coverage", "status": "stub", "rows": [],
                "note": "History coverage is unavailable in this run: " + (str(error) or type(error).__name__)[:300]}
    return {"schema_version": schema_version, "kind": "coverage", "status": "ok", "published_rows": HISTORY_PUBLISHED,
            "first_year": value["first_year"], "end_year": value["end_year"], "statuses": value["statuses"],
            "sources": value["sources"], "rows": value["rows"]}
