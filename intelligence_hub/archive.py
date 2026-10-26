"""Private, offline snapshot archive. No collector, listener or automatic import."""
import argparse
from contextlib import contextmanager
from datetime import date, datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import time

from .collect import published, safe_url, validate_article, validate_observation, validate_window
from .mitigations import valid_projection
from .intelligence import validate_intelligence, validate_weaknesses
from .mitigations import brief_url

ROOT = Path(__file__).absolute().parents[1]
HOME = ROOT / ".state" / "archive-foundation"
INBOX = HOME / "inbox" / "feed.json"
DATABASE = HOME / "archive.sqlite3"
EXPORTS = HOME / "exports"
MAX_INPUT = 16 * 1024 * 1024
MAX_DATABASE = 1024 * 1024 * 1024
MAX_RECORD = 256 * 1024
MAX_SNAPSHOTS = 10000
APPLICATION_ID = 0x49484152
DIGEST = re.compile(r"[a-f0-9]{64}")
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,8}")
TOP = {"schema_version", "generated_at", "window", "articles", "sources", "history_reviewed_at",
       "mitigations", "mitigation_coverage", "deduplication", "refresh", "coverage", "integrations",
       "content_revision", "layout_revision"}
ARTICLE = {"id", "title", "url", "source_id", "source_name", "kind", "published_at", "event_date",
           "date_basis", "summary", "cves", "tags", "exploitation", "references", "origin"}
SOURCE = {"id", "name", "kind", "url", "status", "last_attempt", "last_success", "error", "sha256", "intake", "articles"}
SOURCE_V4 = SOURCE | {"configured_selection"}
BRIEF = {"cve", "title", "description", "source_status", "record_state", "source_updated_at", "retrieved_at",
         "source_attempted_at", "source_sha256", "products", "solutions", "workarounds", "cvss", "references",
         "required_action", "required_action_source_url", "kev", "analysis"}
SCHEMA = {
    "snapshots": """CREATE TABLE snapshots (
        sha256 TEXT PRIMARY KEY, canonical_sha256 TEXT NOT NULL, generated_at TEXT NOT NULL,
        imported_at TEXT NOT NULL, input_bytes INTEGER NOT NULL, header TEXT NOT NULL,
        articles INTEGER NOT NULL, cves INTEGER NOT NULL, sources INTEGER NOT NULL)""",
    "versions": """CREATE TABLE versions (
        kind TEXT NOT NULL CHECK(kind IN ('article','cve','source')), entity_id TEXT NOT NULL,
        sha256 TEXT NOT NULL, payload TEXT NOT NULL, title TEXT NOT NULL, url TEXT NOT NULL,
        PRIMARY KEY(kind,entity_id,sha256))""",
    "members": """CREATE TABLE members (
        snapshot_sha256 TEXT NOT NULL REFERENCES snapshots(sha256), kind TEXT NOT NULL,
        position INTEGER NOT NULL, entity_id TEXT NOT NULL, version_sha256 TEXT NOT NULL,
        PRIMARY KEY(snapshot_sha256,kind,entity_id), UNIQUE(snapshot_sha256,kind,position),
        FOREIGN KEY(kind,entity_id,version_sha256) REFERENCES versions(kind,entity_id,sha256))""",
    "article_cves": """CREATE TABLE article_cves (
        article_id TEXT NOT NULL, article_sha256 TEXT NOT NULL, cve_id TEXT NOT NULL,
        PRIMARY KEY(article_id,article_sha256,cve_id))""",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def pairs(values):
    result = {}
    for key, value in values:
        require(key not in result, "Duplicate JSON member.")
        result[key] = value
    return result


def decode(raw):
    def reject(_value):
        raise ValueError("Nonfinite JSON number.")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject)


def tree(value):
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        require(count <= 500000 and depth <= 32, "JSON structure exceeds archive bounds.")
        if isinstance(item, dict):
            require(len(item) <= 15000 and all(isinstance(key, str) and len(key) <= 160 for key in item), "Invalid JSON members.")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            require(len(item) <= 15000, "JSON array exceeds archive bounds.")
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            require(len(item) <= 100000 and "\x00" not in item and not any(0xD800 <= ord(char) <= 0xDFFF for char in item), "Invalid JSON text.")
        else:
            require(item is None or type(item) in (bool, int, float), "Invalid JSON type.")
            require(type(item) is not float or math.isfinite(item), "Invalid JSON number.")
            require(type(item) is not int or abs(item) <= 10**12, "JSON integer exceeds archive bounds.")


def keys(value, expected):
    require(isinstance(value, dict) and set(value) == expected, "Unexpected public snapshot fields.")


def strings(value, maximum=2000, nullable=False):
    require(nullable and value is None or isinstance(value, str) and len(value) <= maximum, "Invalid bounded public text.")


def stamp(value, nullable=False):
    if nullable and value is None:
        return
    require(isinstance(value, str) and len(value) <= 40 and "T" in value, "Invalid snapshot timestamp.")
    require(datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None, "Snapshot timestamp needs a timezone.")


def validate_archive_source(source, snapshot_version):
    require(type(snapshot_version) is int and snapshot_version in (3, 4, 5, 6), "Unsupported archive source snapshot version.")
    context = None
    if snapshot_version in (4, 5, 6):
        configured = source["configured_selection"]
        if source["id"] == "cisa-kev":
            require(configured is None, "KEV cannot carry RSS selection configuration.")
        else:
            require(type(configured) is str and configured in {"document-order-v1", "publisher-date-desc-v1"}, "Invalid archived selection configuration.")
            if source["id"] == "f5-labs":
                require(source["name"] == "F5 Labs" and source["kind"] == "research" and
                        source["url"] == "https://www.f5.com/labs", "Unsupported archived F5 ledger identity.")
                # Validate a supported producer contract, never adopt or store configuration.
                context = {"id": "f5-labs", "url": "https://www.f5.com/labs/rss-feeds/all.xml",
                           "article_hosts": ["www.f5.com"]}
            else:
                require(configured == "document-order-v1", "Publisher-date configuration requires the supported F5 ledger.")
    validate_observation(source, source=context, kev=source["id"] == "cisa-kev", allow_selection=snapshot_version in (4, 5, 6))


def validate_snapshot(value):
    tree(value)
    require(type(value) is dict and type(value.get("schema_version")) is int and value["schema_version"] in (3, 4, 5, 6), "Archive requires snapshot schema3,4,5 or6.")
    modern = value["schema_version"] in (5, 6)
    keys(value, TOP | {"intelligence"} if modern else TOP)
    stamp(value["generated_at"])
    reviewed = value["history_reviewed_at"]
    if isinstance(reviewed, str) and "T" not in reviewed:
        require(date.fromisoformat(reviewed).isoformat() == reviewed, "Invalid historical review date.")
    else:
        stamp(reviewed, nullable=True)
    keys(value["window"], {"start", "end"})
    start, end = (date.fromisoformat(value["window"][key]) for key in ("start", "end"))
    validate_window(start, end, value["schema_version"])
    if modern:
        require(start.isoformat() == value["window"]["start"] and end.isoformat() == value["window"]["end"], "Schema5/6 coverage needs canonical dates.")
    for field in ("content_revision", "layout_revision"):
        require(isinstance(value[field], str) and DIGEST.fullmatch(value[field]), "Invalid supplied revision.")
    require(isinstance(value["articles"], list) and 1 <= len(value["articles"]) <= 8000, "Invalid archive article count.")
    require(isinstance(value["sources"], list) and 1 <= len(value["sources"]) <= 97, "Invalid archive source count.")
    require(isinstance(value["mitigations"], dict) and len(value["mitigations"]) <= 15000, "Invalid archive CVE count.")
    source_ids, identities, urls, wanted = set(), set(), set(), set()
    source_by_id = {}
    for source in value["sources"]:
        keys(source, SOURCE if value["schema_version"] == 3 else SOURCE_V4)
        require(isinstance(source["id"], str) and re.fullmatch(r"[a-z0-9-]{1,80}", source["id"]) and source["id"] not in source_ids, "Invalid or duplicate source.")
        source_ids.add(source["id"])
        source_by_id[source["id"]] = source
        strings(source["name"], 100)
        require(source["name"] and source["kind"] in {"research", "advisory", "reporting", "filing"} and safe_url(source["url"]), "Invalid source provenance.")
        if source["id"] == "cisa-kev":
            require(source["name"] == "CISA KEV" and source["kind"] == "advisory", "Invalid KEV ledger identity.")
        require(type(source["articles"]) is int and 0 <= source["articles"] <= 8000, "Invalid retained source count.")
        validate_archive_source(source, value["schema_version"])
    for article in value["articles"]:
        keys(article, ARTICLE)
        validate_article(article)
        require(article["id"] not in identities and article["url"] not in urls, "Duplicate article identity or URL.")
        require(len(set(article["cves"])) == len(article["cves"]), "Duplicate article CVE.")
        require(article["origin"] == "library-curation" or article["source_id"] in source_ids, "Article source missing from snapshot.")
        if article["origin"] == "publisher-feed":
            ledger = source_by_id[article["source_id"]]
            require(article["source_id"] != "cisa-kev" and article["source_name"] == ledger["name"] and article["kind"] == ledger["kind"], "Publisher article attribution differs from its ledger.")
        elif article["origin"] == "cisa-kev":
            require(article["source_id"] == "cisa-kev" and article["kind"] == "kev" and
                    article["source_name"] == "CISA Known Exploited Vulnerabilities", "Invalid KEV article provenance.")
        for reference in article["references"]:
            keys(reference, {"label", "url"})
        identities.add(article["id"])
        urls.add(article["url"])
        wanted.update(article["cves"])
    require(set(value["mitigations"]) == wanted, "CVE briefs must exactly cover article mentions.")
    for cve, brief in value["mitigations"].items():
        keys(brief, BRIEF | {"weaknesses", "weaknesses_status"} if modern else BRIEF)
        require(CVE.fullmatch(cve) and valid_projection(brief, cve, safe_url, published), "Invalid structured CVE provenance.")
        if modern:
            validate_weaknesses(brief, cve, brief_url)
        for product in brief["products"]:
            keys(product, {"vendor", "product", "default_status", "versions"})
            for version in product["versions"]:
                keys(version, {"version", "status", "less_than", "less_than_or_equal", "version_type"})
        for field in ("solutions", "workarounds"):
            for item in brief[field]:
                keys(item, {"text", "source_url"})
        for reference in brief["references"]:
            keys(reference, {"label", "url", "kind"})
        if brief["cvss"] is not None:
            keys(brief["cvss"], {"score", "version", "vector", "source_url"})
        strings(brief["required_action"], 1200, nullable=True)
        require(brief["required_action_source_url"] is None or safe_url(brief["required_action_source_url"]), "Invalid CISA action URL.")
        if brief["kev"] is not None:
            keys(brief["kev"], {"date_added", "due_date", "ransomware"})
            for field in ("date_added", "due_date"):
                item = brief["kev"][field]
                require(item is None and field == "due_date" or isinstance(item, str) and published(item) == item and len(item) == 10, "Invalid KEV date.")
            strings(brief["kev"]["ransomware"], 60)
        analysis = brief["analysis"]
        keys(analysis, {"priority", "guidance_status", "assessment", "steps", "limitations"})
        require(analysis["priority"] in {"known-exploited", "review"} and analysis["guidance_status"] in {"publisher-guidance", "cisa-action", "needs-review"}, "Invalid guidance state.")
        strings(analysis["assessment"], 2000)
        require(isinstance(analysis["steps"], list) and len(analysis["steps"]) <= 12 and isinstance(analysis["limitations"], list) and len(analysis["limitations"]) <= 20, "Invalid guidance lists.")
        for step in analysis["steps"]:
            keys(step, {"title", "detail", "evidence_url"})
            strings(step["title"], 200)
            strings(step["detail"], 2000)
            require(step["evidence_url"] is None or safe_url(step["evidence_url"]), "Invalid guidance link.")
        for limitation in analysis["limitations"]:
            strings(limitation)
    for field in ("mitigation_coverage", "deduplication", "coverage", "refresh", "integrations"):
        require(isinstance(value[field], dict), "Invalid snapshot header.")
    metrics = value["mitigation_coverage"]
    keys(metrics, {"total", "cna_loaded", "cisa_actions", "publisher_guidance", "needs_review", "attempted_this_run"})
    require(all(type(item) is int and 0 <= item <= 15000 for item in metrics.values()) and
            metrics["total"] == len(wanted) and metrics["attempted_this_run"] <= 2000, "Invalid CVE coverage metrics.")
    for field, count in (("cna_loaded", sum(item["source_status"] == "ok" for item in value["mitigations"].values())),
                         ("cisa_actions", sum(bool(item["required_action"]) for item in value["mitigations"].values())),
                         ("publisher_guidance", sum(item["analysis"]["guidance_status"] == "publisher-guidance" for item in value["mitigations"].values())),
                         ("needs_review", sum(item["analysis"]["guidance_status"] == "needs-review" for item in value["mitigations"].values()))):
        require(metrics[field] == count, "CVE coverage metric differs from its records.")
    keys(value["deduplication"], {"url_duplicates_removed"})
    require(type(value["deduplication"]["url_duplicates_removed"]) is int and 0 <= value["deduplication"]["url_duplicates_removed"] <= 100000, "Invalid deduplication count.")
    coverage = value["coverage"]
    keys(coverage, {"kev_records", "curated_events", "feed_articles", "notes"})
    for field, origin in (("kev_records", "cisa-kev"), ("curated_events", "library-curation"), ("feed_articles", "publisher-feed")):
        require(type(coverage[field]) is int and coverage[field] == sum(item["origin"] == origin for item in value["articles"]), "Invalid article coverage count.")
    refresh = value["refresh"]
    keys(refresh, {"requested_minutes", "mode", "status_url", "notes"})
    require(type(refresh["requested_minutes"]) is int and 1 <= refresh["requested_minutes"] <= 1440 and
            refresh["mode"] == "scheduled-check" and safe_url(refresh["status_url"]), "Invalid refresh metadata.")
    for notes in (coverage["notes"], refresh["notes"]):
        require(isinstance(notes, list) and len(notes) <= 30, "Invalid coverage notes.")
        for note in notes:
            strings(note)
    keys(value["integrations"], {"xai", "x", "sec"})
    for integration in value["integrations"].values():
        keys(integration, {"status", "message"})
        require(integration["status"] == "not_connected", "Unsupported integration metadata.")
        strings(integration["message"])
    if modern:
        validate_intelligence(value["intelligence"], wanted, safe_url)
    header = {key: item for key, item in value.items() if key not in {"articles", "sources", "mitigations"}}
    require(len(encoded(header)) <= MAX_RECORD, "Snapshot header exceeds archive bound.")
    return header


def plain(path, directory=False):
    info = path.lstat()
    require(not path.is_symlink() and not getattr(info, "st_file_attributes", 0) & (0x400 | 0x1000), "Archive path is a link, reparse point or offline item.")
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "Archive path has an unsupported type.")
    return info


def directories(path, create=False):
    require(path.is_relative_to(ROOT), "Archive directory is outside the fixed workspace.")
    plain(ROOT, directory=True)
    current = ROOT
    for component in path.relative_to(ROOT).parts:
        current = current / component
        if create:
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
        plain(current, directory=True)


def signature(info):
    # Windows path-stat and handle-stat disagree on ctime and extension-derived execute bits.
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_nlink, info.st_size, info.st_mtime_ns


def full_signature(info):
    return signature(info), info.st_mode, info.st_ctime_ns, getattr(info, "st_file_attributes", 0)


def read_fixed(path, maximum):
    directories(path.parent)
    before = plain(path)
    require(0 < before.st_size <= maximum, "Private input exceeds its byte bound.")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(signature(before) == signature(opened), "Private input changed before read.")
        raw = stream.read(maximum + 1)
        require(full_signature(opened) == full_signature(os.fstat(stream.fileno())), "Private input changed during read.")
    require(full_signature(before) == full_signature(plain(path)) and len(raw) == before.st_size, "Private input changed after read.")
    return raw


def schema_check(db):
    require(db.execute("PRAGMA user_version").fetchone()[0] == 1 and db.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID, "Unrecognized archive database version.")
    rows = db.execute("SELECT name,type,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").fetchall()
    require(len(rows) == len(SCHEMA), "Unexpected archive schema objects.")
    for row in rows:
        require(row[0] in SCHEMA and row[1] == "table" and " ".join(row[2].split()) == " ".join(SCHEMA[row[0]].split()), "Archive schema differs from the fixed contract.")
    require(db.execute("PRAGMA page_size").fetchone()[0] == 4096 and db.execute("PRAGMA page_count").fetchone()[0] * 4096 <= MAX_DATABASE, "Archive database exceeds its page bound.")


@contextmanager
def connection(write=False):
    directories(HOME, create=write)
    created = False
    if write and not DATABASE.exists():
        descriptor = os.open(DATABASE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        created = True
    info = plain(DATABASE)
    require(info.st_size <= MAX_DATABASE, "Archive database exceeds its physical byte bound.")
    for suffix in ("-wal", "-shm", "-journal"):
        require(not os.path.lexists(DATABASE.with_name(DATABASE.name + suffix)), "Archive has an active or unresolved SQLite sidecar; preserve it for review.")
    db = sqlite3.connect(DATABASE.as_uri() + ("?mode=rw" if write else "?mode=ro"), uri=True, timeout=5)
    try:
        db.enable_load_extension(False)
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA temp_store=MEMORY")
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_INPUT)
        db.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 8192)
        db.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        deadline = time.monotonic() + (30 if write else 10)
        db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        if not created:
            # Refuse an unknown existing archive before any persistent writer pragma.
            schema_check(db)
        if write:
            if created:
                db.execute("PRAGMA page_size=4096")
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA max_page_count=262144")
        else:
            db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        if created:
            for statement in SCHEMA.values():
                db.execute(statement)
            db.execute("PRAGMA user_version=1")
            db.execute(f"PRAGMA application_id={APPLICATION_ID}")
        schema_check(db)
        yield db
        if write:
            schema_check(db)
            db.commit()
        else:
            db.rollback()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def sha_argument(value):
    require(isinstance(value, str) and DIGEST.fullmatch(value), "Expected a lowercase SHA256 identity.")
    return value


def ingest(expected):
    sha_argument(expected)
    raw = read_fixed(INBOX, MAX_INPUT)
    require(digest(raw) == expected, "Inbox bytes differ from the explicit operator pin.")
    value = decode(raw)
    header = validate_snapshot(value)
    canonical = digest(encoded(value))
    existing_bytes = plain(DATABASE).st_size if DATABASE.exists() else 0
    require(shutil.disk_usage(HOME).free >= max(64 * 1024 * 1024, existing_bytes + 4 * len(raw)), "Insufficient free space for conservative archive growth and journal headroom.")
    with connection(write=True) as db:
        previous = db.execute("SELECT canonical_sha256 FROM snapshots WHERE sha256=?", (expected,)).fetchone()
        if previous:
            require(previous[0] == canonical, "Saved snapshot identity differs.")
            return {"status": "already-imported", "snapshot_sha256": expected, "new_snapshot": False}
        require(db.execute("SELECT count(*) FROM snapshots").fetchone()[0] < MAX_SNAPSHOTS, "Archive snapshot count reached its guard; no automatic pruning.")
        db.execute("INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?,?)", (expected, canonical, value["generated_at"], now(), len(raw), encoded(header).decode("utf-8"), len(value["articles"]), len(value["mitigations"]), len(value["sources"])))
        groups = (("source", [(item["id"], item) for item in value["sources"]]),
                  ("article", [(item["id"], item) for item in value["articles"]]),
                  ("cve", list(value["mitigations"].items())))
        inserted = 0
        for kind, records in groups:
            for position, (entity, record) in enumerate(records):
                payload = encoded(record)
                require(len(payload) <= MAX_RECORD, "An archive record exceeds its byte bound.")
                version = digest(payload)
                title = record.get("title", record.get("name", ""))
                url = record.get("url", "https://www.cve.org/CVERecord?id=" + entity if kind == "cve" else "")
                payload_text = payload.decode("utf-8")
                inserted += db.execute("INSERT OR IGNORE INTO versions VALUES(?,?,?,?,?,?)", (kind, entity, version, payload_text, title, url)).rowcount
                require(db.execute("SELECT payload FROM versions WHERE kind=? AND entity_id=? AND sha256=?", (kind, entity, version)).fetchone()[0] == payload_text, "Saved version differs from its content identity.")
                db.execute("INSERT INTO members VALUES(?,?,?,?,?)", (expected, kind, position, entity, version))
                if kind == "article":
                    db.executemany("INSERT OR IGNORE INTO article_cves VALUES(?,?,?)", ((entity, version, cve) for cve in record["cves"]))
        # Detect ordinary replacement while work was being prepared; not an adversarial filesystem guarantee.
        require(digest(read_fixed(INBOX, MAX_INPUT)) == expected, "Inbox changed before archive commit.")
    return {"status": "imported", "snapshot_sha256": expected, "new_snapshot": True,
            "articles": len(value["articles"]), "cves": len(value["mitigations"]), "sources": len(value["sources"]), "new_versions": inserted}


def status():
    if not DATABASE.exists():
        return {"status": "missing", "ready": False, "network_enabled": False, "public_api": False}
    with connection() as db:
        counts = {table: db.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in ("snapshots", "versions", "members", "article_cves")}
        latest = db.execute("SELECT sha256,generated_at,imported_at,articles,cves,sources FROM snapshots ORDER BY imported_at DESC,sha256 DESC LIMIT 1").fetchone()
        pages = db.execute("PRAGMA page_count").fetchone()[0]
    return {"status": "available", "ready": True, "counts": counts, "database_page_bytes": pages * 4096,
            "database_limit_bytes": MAX_DATABASE, "latest_imported": dict(zip(("sha256", "generated_at", "imported_at", "articles", "cves", "sources"), latest)) if latest else None,
            "network_enabled": False, "public_api": False, "restore_verified": False}


def selected(db, snapshot):
    sha_argument(snapshot)
    row = db.execute("SELECT canonical_sha256,generated_at,imported_at,header,articles,cves,sources FROM snapshots WHERE sha256=?", (snapshot,)).fetchone()
    require(row is not None, "Selected archived snapshot is absent.")
    return row


def search(snapshot, kind, query, limit):
    require(kind in {"article", "cve", "source"} and isinstance(query, str) and 1 <= len(query.strip()) <= 120 and "\x00" not in query, "Select a kind and bounded nonempty query.")
    require(type(limit) is int and 1 <= limit <= 100, "Search limit must be1..100.")
    pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    with connection() as db:
        row = selected(db, snapshot)
        records = db.execute("""SELECT v.entity_id,v.sha256,v.title,v.url FROM members m
            JOIN versions v ON (v.kind,v.entity_id,v.sha256)=(m.kind,m.entity_id,m.version_sha256)
            WHERE m.snapshot_sha256=? AND m.kind=? AND
            (v.entity_id LIKE ? ESCAPE '\\' OR v.title LIKE ? ESCAPE '\\' OR v.url LIKE ? ESCAPE '\\' OR
             EXISTS(SELECT 1 FROM article_cves a WHERE v.kind='article' AND a.article_id=v.entity_id
                    AND a.article_sha256=v.sha256 AND a.cve_id LIKE ? ESCAPE '\\'))
            ORDER BY v.entity_id LIMIT ?""", (snapshot, kind, pattern, pattern, pattern, pattern, limit + 1)).fetchall()
    return {"snapshot_sha256": snapshot, "generated_at": row[1], "imported_at": row[2], "kind": kind,
            "scope": "Selected historical snapshot identity, title, URL and article CVE mentions; SQLite LIKE is not full Unicode search.",
            "more_matches": len(records) > limit, "results": [dict(zip(("id", "version_sha256", "title", "url"), item)) for item in records[:limit]]}


def history(kind, entity, limit):
    require(kind in {"article", "cve", "source"} and isinstance(entity, str) and 1 <= len(entity) <= 100 and "\x00" not in entity, "Invalid history identity.")
    require(type(limit) is int and 1 <= limit <= 100, "History limit must be1..100.")
    with connection() as db:
        rows = db.execute("""SELECT m.version_sha256,min(s.imported_at),max(s.imported_at),count(*)
            FROM members m JOIN snapshots s ON s.sha256=m.snapshot_sha256
            WHERE m.kind=? AND m.entity_id=? GROUP BY m.version_sha256
            ORDER BY max(s.imported_at) DESC,m.version_sha256 LIMIT ?""", (kind, entity, limit + 1)).fetchall()
    return {"kind": kind, "id": entity, "scope": "Observed version membership; import times are not publication/event times.",
            "more_versions": len(rows) > limit, "versions": [dict(zip(("sha256", "first_imported_at", "last_imported_at", "snapshots"), row)) for row in rows[:limit]]}


def reconstruct(db, snapshot):
    row = selected(db, snapshot)
    require(isinstance(row[3], str) and len(row[3].encode("utf-8")) <= MAX_RECORD, "Saved header exceeds its bound.")
    value = decode(row[3].encode("utf-8"))
    total_bytes = len(row[3].encode("utf-8"))
    for kind, field, maximum, expected in (("source", "sources", 97, row[6]), ("article", "articles", 8000, row[4]), ("cve", "mitigations", 15000, row[5])):
        require(type(expected) is int and 0 <= expected <= maximum, "Invalid archived membership count.")
        records = db.execute("""SELECT m.entity_id,m.version_sha256,v.payload,m.position FROM members m
            JOIN versions v ON (v.kind,v.entity_id,v.sha256)=(m.kind,m.entity_id,m.version_sha256)
            WHERE m.snapshot_sha256=? AND m.kind=? ORDER BY m.position LIMIT ?""", (snapshot, kind, maximum + 1))
        items = []
        for position, (entity, version, payload, saved_position) in enumerate(records):
            require(position < expected and position == saved_position and isinstance(payload, str), "Archived membership order differs.")
            raw = payload.encode("utf-8")
            require(len(raw) <= MAX_RECORD and digest(raw) == version, "Archived record digest differs.")
            total_bytes += len(raw)
            require(total_bytes <= MAX_INPUT, "Saved snapshot records exceed the export budget.")
            item = decode(raw)
            require(isinstance(item, dict) and item.get("cve" if kind == "cve" else "id") == entity, "Archived record identity differs.")
            items.append((entity, item))
        require(len(items) == expected, "Archived membership count differs.")
        value[field] = dict(items) if kind == "cve" else [item for _entity, item in items]
    validate_snapshot(value)
    require(digest(encoded(value)) == row[0], "Reconstructed snapshot differs from saved values.")
    return value


def write_new(path, raw):
    require(len(raw) <= MAX_INPUT, "Private export exceeds its byte bound.")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(read_fixed(path, MAX_INPUT) == raw, "Private export readback differs; preserve partial output for review.")


def export(snapshot):
    sha_argument(snapshot)
    with connection() as db:
        value = reconstruct(db, snapshot)
    # Keep the saved mitigation member order; canonical validation already checked values and arrays.
    raw = (json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")
    require(len(raw) <= MAX_INPUT, "Reconstructed export exceeds its byte bound.")
    directories(EXPORTS, create=True)
    require(shutil.disk_usage(EXPORTS).free >= 2 * len(raw) + 1024 * 1024, "Insufficient free space for the selected private export.")
    output = EXPORTS / (snapshot + ".private.json")
    receipt = EXPORTS / (snapshot + ".receipt.private.json")
    require(not output.exists() and not receipt.exists(), "Selected private export already exists; preserve it rather than overwrite.")
    write_new(output, raw)
    metadata = {"schema_version": 1, "status": "exported", "created_at": now(), "input_snapshot_sha256": snapshot,
                "export_sha256": digest(raw), "export_bytes": len(raw), "private": True, "share_approved": False,
                "publication_approved": False, "byte_identical_to_input": False,
                "boundary": "Reconstructed structured values and array/membership order; original whitespace/key ordering is not retained. No declassification or authenticity guarantee."}
    write_new(receipt, encoded(metadata) + b"\n")
    return metadata


def main():
    parser = argparse.ArgumentParser(description="Private offline public-source snapshot archive; no server or collection.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    intake = commands.add_parser("ingest")
    intake.add_argument("--sha256", required=True)
    find = commands.add_parser("search")
    find.add_argument("--snapshot", required=True)
    find.add_argument("--kind", choices=("article", "cve", "source"), required=True)
    find.add_argument("--query", required=True)
    find.add_argument("--limit", type=int, default=20)
    versions = commands.add_parser("history")
    versions.add_argument("--kind", choices=("article", "cve", "source"), required=True)
    versions.add_argument("--id", required=True)
    versions.add_argument("--limit", type=int, default=20)
    out = commands.add_parser("export")
    out.add_argument("--snapshot", required=True)
    args = parser.parse_args()
    try:
        if args.command == "ingest":
            result = ingest(args.sha256)
        elif args.command == "status":
            result = status()
        elif args.command == "search":
            result = search(args.snapshot, args.kind, args.query, args.limit)
        elif args.command == "history":
            result = history(args.kind, args.id, args.limit)
        else:
            result = export(args.snapshot)
        response = encoded(result)
        require(len(response) <= 128 * 1024, "Command output exceeds its bound.")
        print(response.decode("utf-8"))
        return 0
    except Exception:
        print('{"status":"failed","message":"Archive operation refused or did not complete; preserve private inputs, database and outputs for source review."}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('{"status":"interrupted","message":"Preserve private state and reconcile the selected snapshot before retrying."}', file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
