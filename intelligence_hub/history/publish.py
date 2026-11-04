"""The publish step's view of history/: committed rows as v7 article rows, and the v7 coverage file.

The publish workflow never fetches a history source. It reads the committed
history/<adapter>/<year>.jsonl files, checks every row, turns each into a v7 article
row with origin "history:<adapter>" and an empty summary, tags it with the same engine
as every other row, and the shard writer files it under history/YYYY.json (or that year's
calendar parts, history/YYYY-h1.json and so on, when the year passes the split threshold).

A missing, unreadable or invalid history/ never blocks the feed: the run continues
without adapter rows and records why. Nor can the adapter rows push a year's shard past
the shard byte bound: fit() holds back that year's lowest-priority adapter rows until
the shard fits, and the v7 coverage file says how many were held back.

The committed history/coverage.json states what each adapter admitted. The published
data/v7/coverage.json adds two numbers per row (annotate_coverage): given_up, the rows
whose link was already a feed, KEV or curated row of another source in this run, and
shown, the rows that source actually has in the year's shards (admitted minus given_up
minus the rows fit() held back).
"""
from . import ADAPTERS, base, canonical, check, coverage

# Whether this run's v7 shards carry the adapter rows. The rows are built, tagged and
# measured either way; publishing them is a package-cap question (see the PR that sets it).
HISTORY_PUBLISHED = True
ORIGIN_PREFIX = "history:"
# When a year's shard would pass its byte bound, adapter rows are held back in this order:
# NVD metadata rows first (their CVEs are already cited by another row), then the filtered
# Ubuntu notices, then the per-CVE Microsoft rows; publisher, KEV and curated rows never.
HOLD_BACK_ORDER = ("nvd-cve", "ubuntu-usn", "msrc-cvrf", "cisa-alerts", "certcc-vu", "cisa-ics-csaf", "mozilla-mfsa",
                   "certcc-ca", "oracle-cpu", "msrc-bulletins")
SEVERITY_RANK = {"critical": 4, "high": 3, "important": 3, "moderate": 2, "medium": 2, "low": 1}


def is_history(row):
    return isinstance(row, dict) and str(row.get("origin", "")).startswith(ORIGIN_PREFIX)


def hold_back_order(row):
    """Rows that sort first are held back first: by adapter, then unexploited before known, lower severity first."""
    adapter = row["origin"][len(ORIGIN_PREFIX):]
    rank = HOLD_BACK_ORDER.index(adapter) if adapter in HOLD_BACK_ORDER else len(HOLD_BACK_ORDER)
    severity = str(row.get("severity") or "").split(" ", 1)[0].lower()
    return (rank, row.get("exploitation") == "known", SEVERITY_RANK.get(severity, 0), row["id"])


def fit(files, limit, encode):
    """Hold back adapter rows from every history shard (a year or one of its parts) whose encode() bytes pass limit.

    files is the shard map from shards.build_shards and is changed in place. Returns
    [{"path", "adapter", "rows"}] for every adapter with rows held back. A shard that is
    still over the bound with no adapter rows left is left for the shard writer to refuse.
    """
    held = []
    for path in sorted(files):
        value = files[path]
        if not path.startswith("history/") or not isinstance(value, dict) or value.get("kind") != "articles":
            continue
        size = len(encode(value))
        if size <= limit:
            continue
        dropped = set()
        for row in sorted((row for row in value["rows"] if is_history(row)), key=hold_back_order):
            if size <= limit:
                break
            # A row costs its canonical bytes plus one separator; encode() adds one newline, so they cancel.
            size -= len(encode(row))
            dropped.add(row["id"])
        counts = {}
        for row in value["rows"]:
            if row["id"] in dropped:
                adapter = row["origin"][len(ORIGIN_PREFIX):]
                counts[adapter] = counts.get(adapter, 0) + 1
        value["rows"] = [row for row in value["rows"] if row["id"] not in dropped]
        held.extend({"path": path, "adapter": adapter, "rows": count} for adapter, count in sorted(counts.items()))
    return held


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


def articles(root, existing=None):
    """(v7 article rows, summary). A row whose URL is already a feed, KEV or curated row is left to that row.

    existing maps each URL already taken by a feed, KEV or curated row to that row's
    source_id. The summary's given_up lists, per adapter and year, how many rows were left
    to such a row and which sources took them; duplicates_left_to_other_rows is their total.

    History rows never displace each other by URL: their ids are unique, and several of
    them can share one link by design (every CA-series row of a year links to that year's
    compiled advisories page).
    """
    if not HISTORY_PUBLISHED:
        return [], {"status": "unpublished", "reason": "HISTORY_PUBLISHED is off; committed rows are checked but not published"}
    rows, reason = load(root)
    if reason:
        return [], {"status": "empty" if reason == "no committed history rows" else "unavailable", "reason": reason}
    taken = dict(existing or {})
    out, duplicates, given = [], 0, {}
    for row in rows:
        if row["url"] in taken:
            duplicates += 1
            entry = given.setdefault((row["adapter"], row["source_id"], int(row["published"][:4])), {"rows": 0, "taken_by": set()})
            entry["rows"] += 1
            entry["taken_by"].add(str(taken[row["url"]]))
            continue
        out.append(article(row))
    by_adapter = {}
    for row in out:
        by_adapter[row["origin"][len(ORIGIN_PREFIX):]] = by_adapter.get(row["origin"][len(ORIGIN_PREFIX):], 0) + 1
    given_up = [{"adapter": adapter, "source_id": source_id, "year": year, "rows": entry["rows"], "taken_by": sorted(entry["taken_by"])}
                for (adapter, source_id, year), entry in sorted(given.items())]
    return out, {"status": "ok", "rows": len(out), "duplicates_left_to_other_rows": duplicates, "given_up": given_up,
                 "by_adapter": dict(sorted(by_adapter.items()))}


def shard_year(path):
    """The calendar year of a history shard path: history/2025.json and history/2025-h1.json are both 2025."""
    return int(path.split("/", 1)[1][:4])


def annotate_coverage(value, given_up, held, published=True):
    """Add given_up and shown to every row of a published v7 coverage file, in place.

    given_up is the articles() summary list and held is fit()'s result. For an adapter row,
    shown = admitted - given_up - the rows fit() held back for that adapter and year; a
    source without an adapter, or a run that publishes no adapter rows, shows 0. Raises
    HistoryError when a number cannot be placed or shown would be negative, so the caller
    publishes the stub instead of a statement that disagrees with the shards.
    """
    gave = {}
    for item in given_up:
        key = (item["adapter"], item["year"])
        gave[key] = gave.get(key, 0) + item["rows"]
    kept_back = {}
    for item in held:
        key = (item["adapter"], shard_year(item["path"]))
        kept_back[key] = kept_back.get(key, 0) + item["rows"]
    for row in value["rows"]:
        key = (row["adapter"], row["year"])
        if row["adapter"] is None or not published:
            row["given_up"], row["shown"] = 0, 0
            continue
        row["given_up"] = gave.pop(key, 0)
        row["shown"] = row["admitted"] - row["given_up"] - kept_back.pop(key, 0)
        base.require(row["shown"] >= 0, "Coverage for " + row["adapter"] + " " + str(row["year"]) + " would show " +
                     str(row["shown"]) + " rows after cross-source deduplication.")
    if published:
        left = sorted(set(gave) | set(kept_back))
        base.require(not left, "Given-up or held-back rows without a coverage row: " + repr(left[:3]))
    return value


def stub(schema_version, reason):
    return {"schema_version": schema_version, "kind": "coverage", "status": "stub", "rows": [],
            "note": "History coverage is unavailable in this run: " + reason[:300]}


def coverage_file(root, schema_version):
    """data/v7/coverage.json: history/coverage.json when it is valid, else a stub that says why."""
    try:
        value = canonical.read_coverage(root)
        if value is None:
            raise base.HistoryError("history/coverage.json is not committed")
        counts, _bytes, _rows = check.check_files(root)
        coverage.validate(value, counts)
    except (base.HistoryError, OSError, ValueError, KeyError, TypeError) as error:
        return stub(schema_version, str(error) or type(error).__name__)
    return {"schema_version": schema_version, "kind": "coverage", "status": "ok", "published_rows": HISTORY_PUBLISHED,
            "first_year": value["first_year"], "end_year": value["end_year"], "statuses": value["statuses"],
            "sources": value["sources"], "rows": value["rows"],
            # Filled by the collector: adapter rows held back to keep a year shard inside its bound (fit),
            # and each row's given_up and shown numbers (annotate_coverage).
            "held_back": []}
