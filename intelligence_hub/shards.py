"""Schema 7 data shards, written beside the v6 feed in site/data/v7/.

Every shard is canonical JSON: sorted keys, compact separators, UTF-8 and one
trailing newline, with its rows in a fixed order. The same inputs therefore give
the same bytes, and a shard's sha256 changes only when that shard's content does.
data/v7/index.json lists every shard with its path, rows, bytes and sha256, keeps
the last published runs, and is the manifest that publish.yml checks the Pages
package against (package_site below).

Article rows keep the v6 feed record unchanged; the tagged record arrives later.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import statistics
import sys
import tarfile
import zlib
from datetime import date, datetime

from .collect import (FEED_MAX_BYTES, article_date, published, reject_constant, require,
                      safe_url as collector_safe_url)
from .mitigations import CVE_ID, index_row, INDEX_FIELDS

SCHEMA_VERSION = 7
DIRECTORY = "data/v7"
LIVE_MONTHS = 24
RUNS_KEPT = 20
REQUESTED_CRON = "7 */2 * * *"
# Bounds already in force elsewhere: a shard never exceeds the feed's own byte bound,
# and a resume never reads more index than that either.
SHARD_MAX_BYTES = FEED_MAX_BYTES
INDEX_MAX_BYTES = 1024 * 1024
MAX_SHARDS = 1000
# Today's Pages package caps (publish.yml). New cap numbers are an owner decision.
PACKAGE_MAX_INPUT = 21 * 1024 * 1024
PACKAGE_MAX_COMPRESSED = 3000000
# CVE brief buckets would copy every brief that data/briefs.json already carries
# (about 9 MB), which crosses today's 21 MiB package input cap. They are built and
# tested here but stay unpublished until the owner approves new caps or the v6
# briefs file retires; cve-index.json says where each brief is read from.
CVE_BUCKETS_PUBLISHED = False
CVE_BUCKETS_PENDING = ("CVE brief buckets wait for the owner's package cap decision; "
                       "full briefs are read from data/briefs.json until then.")
TRIGGERS = {"schedule", "push", "workflow_dispatch", "local", "unrecorded"}
DIRECTIVE = re.compile(r"\b(BOD|ED)\s?([0-9]{2}-[0-9]{2})\b")
KEV_CWE = re.compile(r"CWE-[1-9][0-9]{0,5}|NVD-CWE-(?:noinfo|Other)")
HEX = re.compile(r"[a-f0-9]{64}")
DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
NAMED = ("sources.json", "coverage.json", "reports.json", "cve-index.json")
SHARD_PATH = re.compile(r"(?:sources|coverage|reports|cve-index)\.json"
                        r"|live/(?:[0-9]{4}-(?:0[1-9]|1[0-2])|undated)\.json"
                        r"|history/(?:[0-9]{4}|undated)\.json"
                        r"|kev/[0-9]{4}\.json"
                        r"|cve/[0-9]{4}/[0-9]{1,5}k\.json")
SHARD_DIRECTORY = re.compile(r"live|history|kev|cve|cve/[0-9]{4}")
SITE_FILES = ("index.html", "styles.css", "app.js", "icon.svg")
V6_FILES = ("data/feed.json", "data/briefs.json")
INDEX_KEYS = {"schema_version", "generated_at", "content_date", "content_revision", "feed_content_revision",
              "layout_revision", "window", "runs", "observed_interval_hours", "requested_cron", "counts",
              "shards", "v6_files", "cve_buckets", "notices"}
NOTICES = ["Publisher rows carry headlines and links only; article bodies stay with their publishers.",
           "KEV rows carry CISA's catalog text unchanged. The KEV catalog is published by CISA under CC0 1.0.",
           "Curated archive rows are original paraphrases backed by a dated primary source.",
           "Run times are the collector's own clocks for published runs. GitHub does not guarantee the schedule."]


def canonical(value):
    """The one byte form every v7 file uses."""
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def live_start(end):
    """First day of the oldest month in the live window: the end month plus the 23 before it."""
    year, month = end.year, end.month - (LIVE_MONTHS - 1)
    while month <= 0:
        month += 12
        year -= 1
    return date(year, month, 1)


def row_day(article):
    value = article_date(article)[:10]
    try:
        return date.fromisoformat(value) if DAY.fullmatch(value) else None
    except ValueError:
        return None


def article_path(article, live_from):
    """live/YYYY-MM.json inside the live window, history/YYYY.json before it; curated rows are history."""
    day = row_day(article)
    if article["origin"] == "library-curation":
        return "history/" + (format(day.year, "04d") if day else "undated") + ".json"
    if day is None:
        return "live/undated.json"
    if day >= live_from:
        return "live/{:04d}-{:02d}.json".format(day.year, day.month)
    return "history/{:04d}.json".format(day.year)


def row_order(article):
    return (article_date(article), article["id"])


def parse_directive(value):
    """The directive a KEV entry cites in its own requiredAction text, or None.

    "BOD 22-01" and "BOD 26-04" are the common cases; an entry that cites more than
    one distinct directive gets them sorted and joined with "; ".
    """
    if not isinstance(value, str):
        return None
    found = sorted({match[1] + " " + match[2] for match in DIRECTIVE.finditer(value)})
    return "; ".join(found) or None


def notes_urls(value, safe_url=collector_safe_url):
    """The safe HTTPS links in a KEV notes field, in order, without duplicates."""
    if not isinstance(value, str):
        return []
    urls = []
    for candidate in re.findall(r"https://[^\s;]+", value):
        url = safe_url(candidate)
        if url and url not in urls:
            urls.append(url)
    return urls[:12]


def _kev_text(entry, field, maximum=12000):
    value = entry.get(field)
    return value if isinstance(value, str) and len(value) <= maximum else None


def _kev_date(entry, field):
    value = entry.get(field)
    return value if isinstance(value, str) and DAY.fullmatch(value) and published(value) == value else None


def kev_row(entry, safe_url=collector_safe_url):
    """One KEV ledger row. CISA's text is kept unchanged; only the directive and links are derived."""
    cwes = entry.get("cwes") if isinstance(entry.get("cwes"), list) else []
    return {"cve": entry["cveID"], "vendor_raw": _kev_text(entry, "vendorProject"), "product_raw": _kev_text(entry, "product"),
            "name": _kev_text(entry, "vulnerabilityName"), "date_added": entry["dateAdded"], "due_date": _kev_date(entry, "dueDate"),
            "directive": parse_directive(entry.get("requiredAction")), "ransomware": _kev_text(entry, "knownRansomwareCampaignUse", 60),
            "forensic_triage": _kev_text(entry, "forensicTriage", 60),
            "cwe": sorted({value for value in cwes if isinstance(value, str) and KEV_CWE.fullmatch(value)}),
            "required_action": _kev_text(entry, "requiredAction"), "short_description": _kev_text(entry, "shortDescription"),
            "notes_urls": notes_urls(entry.get("notes"), safe_url)}


def kev_ledger(catalog, safe_url=collector_safe_url):
    """kev/YYYY.json by dateAdded year, rows ordered by (date_added, cve). Every catalog entry is kept."""
    years = {}
    for entry in (catalog or {}).get("vulnerabilities", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("cveID"), str) or not CVE_ID.fullmatch(entry["cveID"]):
            continue
        if _kev_date(entry, "dateAdded") is None:
            continue
        row = kev_row(entry, safe_url)
        years.setdefault("kev/" + row["date_added"][:4] + ".json", []).append(row)
    return {path: {"schema_version": SCHEMA_VERSION, "kind": "kev", "year": int(path[4:8]),
                   "rows": sorted(rows, key=lambda row: (row["date_added"], row["cve"]))} for path, rows in years.items()}


def cve_bucket(cve):
    """cve/YYYY/NNNk.json: the CVE year and its thousand block (CVE-2026-118527 is cve/2026/118k.json)."""
    year, number = cve.split("-")[1:]
    return "cve/" + year + "/" + str(int(number) // 1000) + "k.json"


def cve_buckets(briefs):
    buckets = {}
    for cve in sorted(briefs):
        buckets.setdefault(cve_bucket(cve), {})[cve] = briefs[cve]
    return {path: {"schema_version": SCHEMA_VERSION, "kind": "cve-briefs", "bucket": path[4:-5], "briefs": rows}
            for path, rows in buckets.items()}


def cve_index(briefs):
    """One compact row per CVE in CVE order: the list-view fields and the bucket that holds its brief."""
    rows = [[cve, *index_row(briefs[cve]), cve_bucket(cve) if CVE_BUCKETS_PUBLISHED else None] for cve in sorted(briefs)]
    return {"schema_version": SCHEMA_VERSION, "kind": "cve-index", "fields": ["cve", *INDEX_FIELDS, "bucket"],
            "briefs_file": None if CVE_BUCKETS_PUBLISHED else "data/briefs.json", "rows": rows}


def reports_file(status, catalog, catalog_sha):
    """A copy of the validated report catalog, or the reason it is unavailable. reports/ itself is never written."""
    if status.get("status") == "available" and isinstance(catalog, dict):
        return {"schema_version": SCHEMA_VERSION, "kind": "reports", "status": "available", "catalog_sha256": catalog_sha, "catalog": catalog}
    return {"schema_version": SCHEMA_VERSION, "kind": "reports", "status": "unavailable",
            "reason": status.get("reason") or "the report catalog was not read in this run"}


def coverage_stub():
    return {"schema_version": SCHEMA_VERSION, "kind": "coverage", "status": "stub", "rows": [],
            "note": "Per-source and per-year coverage rows arrive with the history adapters. This file makes no coverage claim yet."}


def build_shards(articles, sources, catalog, briefs, reports, end, safe_url=collector_safe_url):
    """Every v7 shard except index.json, as {relative path: value}."""
    live_from = live_start(end)
    groups = {}
    for article in articles:
        groups.setdefault(article_path(article, live_from), []).append(article)
    shards = {}
    for path, rows in groups.items():
        period = path.split("/", 1)[1][:-5]
        shards[path] = {"schema_version": SCHEMA_VERSION, "kind": "articles", "period": period, "rows": sorted(rows, key=row_order)}
    shards.update(kev_ledger(catalog, safe_url))
    if CVE_BUCKETS_PUBLISHED:
        shards.update(cve_buckets(briefs))
    shards["cve-index.json"] = cve_index(briefs)
    shards["sources.json"] = {"schema_version": SCHEMA_VERSION, "kind": "sources", "rows": sources}
    shards["coverage.json"] = coverage_stub()
    shards["reports.json"] = reports
    for path in shards:
        require(SHARD_PATH.fullmatch(path), "Unexpected v7 shard path " + path + ".")
    return shards


def _span(value):
    if value["kind"] == "articles":
        days = sorted(day.isoformat() for day in (row_day(row) for row in value["rows"]) if day)
    elif value["kind"] == "kev":
        days = [row["date_added"] for row in value["rows"]]
    else:
        return None, None
    return (days[0], days[-1]) if days else (None, None)


def _rows(value):
    if value["kind"] == "cve-briefs":
        return len(value["briefs"])
    if value["kind"] == "reports":
        return len(value["catalog"]["reports"]) if value["status"] == "available" else 0
    return len(value["rows"])


def serialize(shards):
    """({path: bytes}, manifest entries in path order). A shard over its byte bound fails the run."""
    raw, entries = {}, []
    for path in sorted(shards):
        data = canonical(shards[path])
        require(len(data) <= SHARD_MAX_BYTES, "data/v7/" + path + " would be " + format(len(data), ",") + " bytes, over its " +
                format(SHARD_MAX_BYTES, ",") + "-byte shard bound. Nothing was evicted; the deployed publication is preserved.")
        start, finish = _span(shards[path])
        raw[path] = data
        entries.append({"path": path, "rows": _rows(shards[path]), "bytes": len(data), "sha256": sha256(data), "from": start, "to": finish})
    require(len(entries) <= MAX_SHARDS, "The v7 index would list more shards than its bound.")
    return raw, entries


def content_revision(entries):
    """sha256 over every shard's path and sha256 in path order."""
    return sha256("".join(entry["path"] + " " + entry["sha256"] + "\n" for entry in sorted(entries, key=lambda item: item["path"])).encode("utf-8"))


def compare(previous, entries):
    """(changed_shards, removed_shards) against the previous index; with no index, every shard is new."""
    before = {entry["path"]: entry["sha256"] for entry in (previous or {}).get("shards", [])}
    now = {entry["path"]: entry["sha256"] for entry in entries}
    changed = sorted(path for path, digest in now.items() if before.get(path) != digest)
    removed = sorted(path for path in before if path not in now)
    return changed, removed


def _clock(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def observed_interval(runs):
    """Median and longest gap, in hours, between the recorded published runs (newest first)."""
    stamps = sorted((_clock(run["generated_at"]) for run in runs), reverse=True)
    gaps = [(newer - older).total_seconds() / 3600 for newer, older in zip(stamps, stamps[1:])]
    if not gaps:
        return {"median": None, "max": None, "runs_counted": len(stamps)}
    return {"median": round(statistics.median(gaps), 1), "max": round(max(gaps), 1), "runs_counted": len(stamps)}


def run_trigger():
    value = os.environ.get("GITHUB_EVENT_NAME", "")
    return value if value in {"schedule", "push", "workflow_dispatch"} else "local"


def run_chain(previous_runs, generated_at, trigger, seed=None):
    """This run first, then up to 19 earlier runs. seed is an earlier published run time known only from the v6 feed."""
    earlier = [run for run in previous_runs if _clock(run["generated_at"]) < _clock(generated_at)]
    if not earlier and seed and published(seed) and _clock(seed) < _clock(generated_at):
        earlier = [{"generated_at": seed, "trigger": "unrecorded", "changed": True}]
    return ([{"generated_at": generated_at, "trigger": trigger, "changed": True}] + earlier)[:RUNS_KEPT]


def build_index(entries, *, generated_at, end, feed_content_revision, layout_revision, runs, counts, v6_files):
    days = [entry["to"] for entry in entries if entry["to"] and (entry["path"].startswith(("live/", "history/")))]
    content_date = max((day for day in days if day <= end.isoformat()), default=None)
    return {"schema_version": SCHEMA_VERSION, "generated_at": generated_at, "content_date": content_date,
            "content_revision": content_revision(entries), "feed_content_revision": feed_content_revision,
            "layout_revision": layout_revision,
            "window": {"history_start": "1998-01-01", "live_start": live_start(end).isoformat(), "end": end.isoformat()},
            "runs": runs, "observed_interval_hours": observed_interval(runs), "requested_cron": REQUESTED_CRON,
            "counts": counts, "shards": entries, "v6_files": v6_files,
            "cve_buckets": {"published": CVE_BUCKETS_PUBLISHED, "note": None if CVE_BUCKETS_PUBLISHED else CVE_BUCKETS_PENDING},
            "notices": NOTICES}


def file_entry(path, raw):
    return {"path": path, "bytes": len(raw), "sha256": sha256(raw)}


def validate_index(index):
    """Check an index read back from disk or from the deployed site before anything trusts it."""
    require(type(index) is dict and set(index) == INDEX_KEYS and type(index["schema_version"]) is int and
            index["schema_version"] == SCHEMA_VERSION, "Unsupported v7 index.")
    require(isinstance(index["generated_at"], str) and published(index["generated_at"]) and "T" in index["generated_at"], "Invalid v7 index clock.")
    for field in ("content_revision", "feed_content_revision", "layout_revision"):
        require(isinstance(index[field], str) and HEX.fullmatch(index[field]), "Invalid v7 index revision.")
    runs = index["runs"]
    require(type(runs) is list and 1 <= len(runs) <= RUNS_KEPT, "Invalid v7 run chain.")
    for run in runs:
        require(type(run) is dict and set(run) == {"generated_at", "trigger", "changed"} and isinstance(run["generated_at"], str) and
                published(run["generated_at"]) and "T" in run["generated_at"] and run["trigger"] in TRIGGERS and
                type(run["changed"]) is bool, "Invalid v7 run record.")
    shards = index["shards"]
    require(type(shards) is list and 1 <= len(shards) <= MAX_SHARDS, "Invalid v7 shard list.")
    seen = set()
    for entry in shards:
        require(type(entry) is dict and set(entry) == {"path", "rows", "bytes", "sha256", "from", "to"} and
                isinstance(entry["path"], str) and SHARD_PATH.fullmatch(entry["path"]) and entry["path"] not in seen and
                type(entry["rows"]) is int and 0 <= entry["rows"] and type(entry["bytes"]) is int and
                0 < entry["bytes"] <= SHARD_MAX_BYTES and isinstance(entry["sha256"], str) and HEX.fullmatch(entry["sha256"]),
                "Invalid v7 shard entry.")
        for field in ("from", "to"):
            require(entry[field] is None or isinstance(entry[field], str) and DAY.fullmatch(entry[field]), "Invalid v7 shard dates.")
        seen.add(entry["path"])
    require(all(name in seen for name in NAMED), "The v7 index is missing a named file.")
    require(type(index["v6_files"]) is list and [item.get("path") for item in index["v6_files"] if type(item) is dict] == list(V6_FILES), "Invalid v6 file list.")
    for item in index["v6_files"]:
        require(set(item) == {"path", "bytes", "sha256"} and type(item["bytes"]) is int and item["bytes"] > 0 and
                isinstance(item["sha256"], str) and HEX.fullmatch(item["sha256"]), "Invalid v6 file entry.")
    return index


def read_index(raw):
    require(len(raw) <= INDEX_MAX_BYTES, "The v7 index exceeds its byte bound.")
    return validate_index(json.loads(raw.decode("utf-8"), parse_constant=reject_constant))


def local_index(site):
    """The index a previous local build left, or None."""
    path = Path(site) / DIRECTORY / "index.json"
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return None
        with path.open("rb") as stream:
            return read_index(stream.read(INDEX_MAX_BYTES + 1))
    except (OSError, ValueError, TypeError, KeyError):
        return None


def write_v7(site, raw, index_raw, write_raw):
    """Write the shards, then index.json, then remove v7 files the new index no longer lists."""
    base = Path(site) / DIRECTORY
    for path in sorted(raw):
        write_raw(base / path, raw[path])
    write_raw(base / "index.json", index_raw)
    keep = set(raw) | {"index.json"}
    for directory, folders, names in os.walk(base, topdown=False):
        for name in names:
            relative = (Path(directory) / name).relative_to(base).as_posix()
            if relative not in keep:
                (Path(directory) / name).unlink()
        if Path(directory) != base and not any(Path(directory).iterdir()):
            Path(directory).rmdir()


class PackageError(SystemExit):
    """Raised when the Pages package differs from its manifest or crosses a cap."""


def _refuse(condition, message):
    if not condition:
        raise PackageError(message)


def package_site(site, max_input=PACKAGE_MAX_INPUT, max_compressed=PACKAGE_MAX_COMPRESSED, out=None):
    """Check the site directory against data/v7/index.json, then tar it and estimate its compressed size.

    Fixed files: the four page files, the two v6 data files and data/v7/index.json.
    Data files: exactly the shards the index lists, each with the listed bytes and
    sha256. No links, no hard links, no other directories. Returns a report dict.
    """
    out = out or sys.stdout
    root = Path(site)
    info = os.lstat(root)
    _refuse(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), "The public site must be an ordinary directory.")
    files, directories = set(), set()
    for directory, folders, names in os.walk(root):
        for name in folders + names:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            detail = os.lstat(path)
            _refuse(not stat.S_ISLNK(detail.st_mode), "Links are not permitted in the site artifact: " + relative)
            if stat.S_ISDIR(detail.st_mode):
                _refuse(relative in {"data", DIRECTORY} or (relative.startswith(DIRECTORY + "/") and
                        SHARD_DIRECTORY.fullmatch(relative[len(DIRECTORY) + 1:])), "The public artifact contains an unexpected directory: " + relative)
                directories.add(relative)
            elif stat.S_ISREG(detail.st_mode) and detail.st_nlink == 1:
                files.add(relative)
            else:
                raise PackageError("Only ordinary single-link files may enter the public artifact: " + relative)
    index_path = DIRECTORY + "/index.json"
    _refuse(index_path in files, "The public artifact has no data/v7/index.json manifest.")
    with (root / index_path).open("rb") as stream:
        raw_index = stream.read(INDEX_MAX_BYTES + 1)
    try:
        index = read_index(raw_index)
    except (ValueError, TypeError, KeyError) as error:
        raise PackageError("The v7 manifest is invalid: " + str(error)) from error
    listed = {DIRECTORY + "/" + entry["path"]: entry for entry in index["shards"]}
    listed.update({item["path"]: item for item in index["v6_files"]})
    expected = set(SITE_FILES) | {index_path} | set(listed)
    for name in sorted(files):
        _refuse(name in SITE_FILES or name in V6_FILES or name == index_path or
                (name.startswith(DIRECTORY + "/") and SHARD_PATH.fullmatch(name[len(DIRECTORY) + 1:])),
                "A file outside the allowlisted patterns would be published: " + name)
    _refuse(not files - expected, "Files not listed in the manifest would be published: " + ", ".join(sorted(files - expected)))
    _refuse(not expected - files, "Files listed in the manifest are missing: " + ", ".join(sorted(expected - files)))
    total = 0
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for directory in ["."] + sorted(directories):
            entry = tarfile.TarInfo(directory if directory == "." else "./" + directory)
            entry.type = tarfile.DIRTYPE
            entry.mode = 0o755
            tar.addfile(entry)
        for name in sorted(expected):
            path = root / name
            _refuse(path.stat().st_size <= max_input - total, "The public site exceeds its " + format(max_input, ",") + "-byte package input cap.")
            with path.open("rb") as source:
                content = source.read(max_input - total + 1)
            total += len(content)
            _refuse(total <= max_input, "The public site exceeds its " + format(max_input, ",") + "-byte package input cap.")
            if name in listed:
                _refuse(len(content) == listed[name]["bytes"], "Byte count differs from the manifest: " + name)
                _refuse(sha256(content) == listed[name]["sha256"], "sha256 differs from the manifest: " + name)
            entry = tarfile.TarInfo("./" + name)
            entry.mode = 0o644
            entry.size = len(content)
            tar.addfile(entry, io.BytesIO(content))
    # Estimate the pinned upload action's default level-6 compression.
    # Its actual tar/ZIP metadata and account-wide storage remain separate.
    tar_bytes = archive.getvalue()
    estimate = max(len(gzip.compress(tar_bytes, compresslevel=6, mtime=0)), len(zlib.compress(tar_bytes, level=6)))
    report = {"files": len(expected), "input_bytes": total, "input_cap": max_input, "input_headroom": max_input - total,
              "compressed_estimate": estimate, "compressed_cap": max_compressed, "compressed_headroom": max_compressed - estimate}
    print("Public files: {files:,} (all match data/v7/index.json)".format(**report), file=out)
    print("Public input bytes: {input_bytes:,} of {input_cap:,} ({input_headroom:,} of headroom)".format(**report), file=out)
    print("Estimated compressed artifact bytes: {compressed_estimate:,} of {compressed_cap:,} ({compressed_headroom:,} of headroom)".format(**report), file=out)
    _refuse(estimate <= max_compressed, "The estimated compressed artifact exceeds the " + format(max_compressed, ",") +
            "-byte budget; publication is blocked.")
    return report


def main(argv=None):
    """python -m intelligence_hub.shards package [site]: the publish workflow's package check."""
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) not in (1, 2) or argv[0] != "package":
        raise SystemExit("usage: python -m intelligence_hub.shards package [site]")
    package_site(argv[1] if len(argv) == 2 else "site")


if __name__ == "__main__":
    main()
