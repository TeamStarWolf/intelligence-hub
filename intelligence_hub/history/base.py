"""Shared pieces for the history adapters: the row schema, its checks and a polite, bounded fetcher.

A history adapter turns one public archive (a bulletin index, an advisory API, a
repository of advisories) into history rows: identifiers, publisher titles, dates,
CVE ids and links. Rows never carry advisory bodies. Each adapter runs in two parts:

- fetch(fetcher, years, context) asks the fetcher for raw documents. The fetcher
  keeps every response in .state/history-raw/ (ignored by git), so a later build,
  or a run with --offline, reuses exactly the same bytes.
- parse(documents, years, context) is pure: the same documents give the same rows.
  The fixtures under tests/history/fixtures/ run through parse() and must match
  their golden files.

The build, check and coverage commands live in intelligence_hub.history.__main__.
"""
import gzip
import hashlib
import html
import http.client
import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from pathlib import Path

from ..collect import safe_url

PROJECT_URL = "https://github.com/TeamStarWolf/intelligence-hub"
USER_AGENT = "TeamStarWolf-IntelligenceHub-history/1.0 (+" + PROJECT_URL + ")"
FIRST_YEAR = 1998
MAX_ROWS_PER_YEAR = 1500
MAX_ROW_BYTES = 4096
DEFAULT_MAX_BYTES = 8 * 1024 * 1024
FETCH_CEILING = 128 * 1024 * 1024
MIN_INTERVAL = 1.0
READ_DEADLINE = 900
RETRY_PAUSES = (10, 60)
ROW_KEYS = ("id", "adapter", "source_id", "source_class", "kind", "native_id", "title", "url", "published",
            "date_basis", "updated", "cve", "severity", "vendor_raw", "product_raw", "exploited_flag", "retrieved",
            "raw_sha256")
KINDS = {"advisory", "bulletin", "note"}
SOURCE_CLASSES = {"vendor-primary", "government-cert", "researcher", "press"}
DATE_BASES = {"publication", "cross-reference"}
CVE_ID = re.compile(r"CVE-(?:199[0-9]|20[0-9]{2})-[0-9]{4,8}")
CVE_IN_TEXT = re.compile(r"\bCVE-(?:199[0-9]|20[0-9]{2})-[0-9]{4,8}\b")
DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
CLOCK = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
HEX = re.compile(r"[a-f0-9]{64}")
NATIVE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,70}")
MONTHS = {name: number for number, name in enumerate(
    ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"), 1)}


class HistoryError(ValueError):
    """A row, a file or a raw document broke a history rule."""


class MissingRaw(HistoryError):
    """An offline build asked for a document that is not in the raw cache."""


def require(condition, message):
    if not condition:
        raise HistoryError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def text(value, maximum=240):
    """One line of plain text: tags removed, entities decoded, whitespace folded, bounded.

    An em dash (U+2014) becomes a spaced hyphen: the repository carries none outside reports/.
    """
    value = html.unescape(re.sub(r"<[^>]*>", " ", str(value or ""))).replace("—", " - ")
    value = re.sub(r"\s+", " ", value).strip()
    return value if len(value) <= maximum else value[:maximum - 1].rstrip() + "…"


def day(value):
    """YYYY-MM-DD from an ISO date or clock, or None."""
    if not isinstance(value, str):
        return None
    match = DAY.match(value.strip())
    if not match:
        return None
    try:
        return date.fromisoformat(match.group(0)).isoformat()
    except ValueError:
        return None


def long_date(value):
    """'June 01, 1998' or '1 June 1998' as YYYY-MM-DD, or None."""
    match = re.search(r"\b([A-Za-z]+)\s+([0-9]{1,2}),?\s+([0-9]{4})\b", value or "")
    if match and match.group(1).lower() in MONTHS:
        month, number, year = MONTHS[match.group(1).lower()], int(match.group(2)), int(match.group(3))
    else:
        match = re.search(r"\b([0-9]{1,2})\s+([A-Za-z]+)\s+([0-9]{4})\b", value or "")
        if not match or match.group(2).lower() not in MONTHS:
            return None
        month, number, year = MONTHS[match.group(2).lower()], int(match.group(1)), int(match.group(3))
    try:
        return date(year, month, number).isoformat()
    except ValueError:
        return None


def cves(*values):
    """Sorted CVE ids found in strings or lists of strings."""
    found = set()
    for value in values:
        if isinstance(value, str):
            found.update(CVE_IN_TEXT.findall(value.upper()))
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                found.update(cves(item))
    return sorted(found)


def https(url, hosts=None):
    """The canonical HTTPS form of a source link; http:// is upgraded, anything else unsafe gives None."""
    if not isinstance(url, str):
        return None
    url = url.strip()
    if url.startswith("http://"):
        url = "https://" + url[len("http://"):]
    return safe_url(url, hosts)


def canonical_row(row):
    return json.dumps(row, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def make_row(adapter, *, native_id, title, url, published, kind=None, cve=(), severity=None, vendor_raw=(), product_raw=(),
             exploited_flag=None, updated=None, retrieved, raw_sha256, date_basis="publication"):
    """A history row in its canonical shape; the adapter module supplies the fixed fields."""
    products = sorted({text(value, 100) for value in product_raw if text(value, 100)})
    row = {"id": "h-" + adapter.ID + "-" + native_id, "adapter": adapter.ID, "source_id": adapter.SOURCE_ID,
           "source_class": adapter.SOURCE_CLASS, "kind": kind or adapter.KIND, "native_id": native_id,
           "title": text(title), "url": url, "published": published, "date_basis": date_basis,
           "updated": updated if updated and updated > published else None,
           "cve": sorted(set(cve))[:100], "severity": text(severity, 40) or None,
           "vendor_raw": sorted({text(value, 100) for value in vendor_raw if text(value, 100)})[:20],
           "product_raw": products[:20], "exploited_flag": True if exploited_flag is True else None,
           "retrieved": retrieved, "raw_sha256": raw_sha256}
    # A row stays inside its byte bound by giving up product names first; identifiers stay.
    while len(canonical_row(row)) > MAX_ROW_BYTES and row["product_raw"]:
        row["product_raw"] = row["product_raw"][:-1]
    return row


def validate_row(row, adapters=None):
    """Every rule a committed history row must meet."""
    require(isinstance(row, dict) and sorted(row) == sorted(ROW_KEYS), "A history row has the wrong fields.")
    ident = row["id"] if isinstance(row["id"], str) else repr(row["id"])[:80]
    require(isinstance(row["adapter"], str) and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", row["adapter"]) and
            (adapters is None or row["adapter"] in adapters), "Unknown history adapter in " + ident + ".")
    require(isinstance(row["native_id"], str) and NATIVE_ID.fullmatch(row["native_id"]), "Invalid native id in " + ident + ".")
    require(row["id"] == "h-" + row["adapter"] + "-" + row["native_id"] and len(row["id"]) <= 100,
            "History row id does not match its adapter and native id: " + ident + ".")
    require(isinstance(row["source_id"], str) and re.fullmatch(r"[a-z0-9-]{1,80}", row["source_id"]), "Invalid history source id in " + ident + ".")
    require(row["source_class"] in SOURCE_CLASSES and row["kind"] in KINDS, "Invalid history class or kind in " + ident + ".")
    require(isinstance(row["title"], str) and 1 <= len(row["title"]) <= 240 and row["title"] == text(row["title"]), "Invalid history title in " + ident + ".")
    require(isinstance(row["url"], str) and safe_url(row["url"]) == row["url"], "Unsafe or non-canonical history URL in " + ident + ".")
    require(isinstance(row["published"], str) and day(row["published"]) == row["published"], "Invalid history date in " + ident + ".")
    require(row["date_basis"] in DATE_BASES, "Invalid history date basis in " + ident + ".")
    require(row["updated"] is None or isinstance(row["updated"], str) and day(row["updated"]) == row["updated"] and
            row["updated"] > row["published"], "Invalid history update date in " + ident + ".")
    require(isinstance(row["cve"], list) and len(row["cve"]) <= 100 and row["cve"] == sorted(set(row["cve"])) and
            all(isinstance(value, str) and CVE_ID.fullmatch(value) for value in row["cve"]), "Invalid history CVE list in " + ident + ".")
    require(row["severity"] is None or isinstance(row["severity"], str) and 1 <= len(row["severity"]) <= 40, "Invalid history severity in " + ident + ".")
    for field in ("vendor_raw", "product_raw"):
        require(isinstance(row[field], list) and len(row[field]) <= 20 and row[field] == sorted(set(row[field])) and
                all(isinstance(value, str) and 1 <= len(value) <= 100 for value in row[field]), "Invalid history " + field + " in " + ident + ".")
    require(row["exploited_flag"] in (True, None), "exploited_flag is true or null, never false, in " + ident + ".")
    require(isinstance(row["retrieved"], str) and CLOCK.fullmatch(row["retrieved"]), "Invalid history retrieval clock in " + ident + ".")
    require(isinstance(row["raw_sha256"], str) and HEX.fullmatch(row["raw_sha256"]), "Invalid raw sha256 in " + ident + ".")
    require(len(canonical_row(row)) <= MAX_ROW_BYTES, "History row " + ident + " is over " + str(MAX_ROW_BYTES) + " bytes.")


def order(row):
    return (row["published"], row["id"])


def unique(rows):
    """One row per id: the earliest publication wins, then the lowest id order."""
    best = {}
    for row in rows:
        if row["id"] not in best or order(row) < order(best[row["id"]]):
            best[row["id"]] = row
    return list(best.values())


def cap(rows, priority=None):
    """At most MAX_ROWS_PER_YEAR rows per year, keeping those the priority sorts first.

    Returns (kept rows in canonical order, {year: rows left out}).
    """
    by_year = {}
    for row in rows:
        by_year.setdefault(int(row["published"][:4]), []).append(row)
    kept, dropped = [], {}
    for year, items in by_year.items():
        items.sort(key=priority or order)
        kept.extend(items[:MAX_ROWS_PER_YEAR])
        if len(items) > MAX_ROWS_PER_YEAR:
            dropped[year] = len(items) - MAX_ROWS_PER_YEAR
    return sorted(kept, key=order), dropped


class Document:
    """One raw response: its bytes, when it was fetched and its sha256."""

    __slots__ = ("raw", "fetched_at", "sha256")

    def __init__(self, raw, fetched_at):
        self.raw = raw
        self.fetched_at = fetched_at
        self.sha256 = sha256(raw)


def utc_clock(moment=None):
    return (moment or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")


class _Redirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only to a canonical HTTPS URL on the adapter's declared hosts."""

    def __init__(self, hosts):
        super().__init__()
        self.hosts = hosts

    def redirect_request(self, request, fp, code, message, headers, url):
        target = safe_url(urllib.parse.urljoin(request.full_url, url), self.hosts)
        if target is None:
            raise HistoryError("Redirect left the adapter's declared hosts: " + str(url)[:200])
        return super().redirect_request(request, fp, code, message, headers, target)


class Fetcher:
    """Bounded HTTPS reads with a raw cache, at most one request a second per host.

    Every response is stored under <cache>/<adapter>/ with its URL, size, sha256 and
    fetch time, and is reused by the next build unless refresh is set. In offline mode
    nothing is fetched, and a missing document raises MissingRaw.
    """

    def __init__(self, cache, adapter, hosts, offline=False, refresh=False, interval=MIN_INTERVAL, opener=None, log=None):
        self.cache = Path(cache) / adapter
        self.hosts = set(hosts)
        self.offline = offline
        self.refresh = refresh
        self.interval = interval
        self.opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), _Redirects(self.hosts))
        self.last = {}
        self.requests = 0
        self.log = log or (lambda message: None)

    def _paths(self, url):
        key = sha256(url.encode("utf-8"))[:32]
        return self.cache / (key + ".bin"), self.cache / (key + ".json")

    def cached(self, url):
        body, meta = self._paths(url)
        if not (body.exists() and meta.exists()):
            return None
        info = json.loads(meta.read_text(encoding="utf-8"))
        raw = body.read_bytes()
        require(info.get("url") == url and info.get("sha256") == sha256(raw), "Raw cache entry does not match its record: " + url)
        if info.get("missing"):
            return False
        return Document(raw, info["fetched_at"])

    def _store(self, url, raw, missing=False):
        body, meta = self._paths(url)
        body.parent.mkdir(parents=True, exist_ok=True)
        fetched_at = utc_clock()
        body.write_bytes(raw)
        meta.write_text(json.dumps({"url": url, "bytes": len(raw), "sha256": sha256(raw), "fetched_at": fetched_at,
                                    "missing": missing}, sort_keys=True) + "\n", encoding="utf-8")
        return Document(raw, fetched_at)

    def get(self, url, max_bytes=DEFAULT_MAX_BYTES, accept="*/*", optional=False, head=False):
        """The document at url, from the cache or the network.

        optional=True returns None for HTTP 404 or 410 (and remembers that in the cache).
        head=True keeps only the first max_bytes of the response instead of refusing a
        longer one: enough for a page's title and date, without its body.
        """
        require(safe_url(url, self.hosts) == url, "Not a canonical HTTPS URL on the adapter's hosts: " + url)
        require(type(max_bytes) is int and 1 <= max_bytes <= FETCH_CEILING, "Invalid max_bytes for " + url)
        if not self.refresh:
            document = self.cached(url)
            if document is False:
                return None
            if document is not None:
                return document
        if self.offline:
            raise MissingRaw("Not in the raw cache (offline build): " + url)
        for attempt, pause in enumerate(RETRY_PAUSES + (None,)):
            try:
                return self._download(url, max_bytes, accept, optional, head)
            except HistoryError as error:
                if pause is None or not str(error).startswith(("HTTP 429 ", "HTTP 500 ", "HTTP 502 ", "HTTP 503 ", "HTTP 504 ")):
                    raise
            except OSError:
                if pause is None:
                    raise
            self.log(self.cache.name + ": retrying " + url + " (attempt " + str(attempt + 2) + ")")
            time.sleep(pause)

    def _download(self, url, max_bytes, accept, optional, head):
        host = urllib.parse.urlsplit(url).hostname
        wait = self.last.get(host, -1e9) + self.interval - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self.requests += 1
        if self.requests % 200 == 0:
            self.log(self.cache.name + ": " + format(self.requests, ",") + " requests")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept, "Accept-Encoding": "identity"})
        started, chunks, size = time.monotonic(), [], 0
        try:
            with self.opener.open(request, timeout=60) as response:
                require(response.status == 200, "HTTP " + str(response.status) + " for " + url)
                require(response.headers.get("Content-Encoding", "identity").lower() == "identity", "Compressed transfer refused for " + url)
                while True:
                    require(time.monotonic() - started < READ_DEADLINE, "Read deadline passed for " + url)
                    block = response.read(1 << 16)
                    if not block:
                        break
                    size += len(block)
                    if head and size >= max_bytes:
                        chunks.append(block[:len(block) - (size - max_bytes)])
                        break
                    require(size <= max_bytes, "Response over its declared max_bytes (" + format(max_bytes, ",") + ") for " + url)
                    chunks.append(block)
        except urllib.error.HTTPError as error:
            if optional and error.code in (404, 410):
                self._store(url, b"", missing=True)
                return None
            raise HistoryError("HTTP " + str(error.code) + " for " + url) from error
        except http.client.HTTPException as error:
            raise OSError(type(error).__name__ + " for " + url) from error
        finally:
            self.last[host] = time.monotonic()
        return self._store(url, b"".join(chunks))


def xml(raw):
    """Parse XML that declares no document type, so no entity can be defined or expanded."""
    lowered = raw.lower()
    require(b"<!doctype" not in lowered and b"<!entity" not in lowered, "XML with a document type or entities is refused.")
    return ET.fromstring(raw)


def gunzip(raw, limit):
    """Bounded gzip decompression."""
    out, size = io.BytesIO(), 0
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        while True:
            block = stream.read(1 << 20)
            if not block:
                break
            size += len(block)
            require(size <= limit, "Decompressed size over its bound.")
            out.write(block)
    return out.getvalue()


def front_matter(raw):
    """Top-level scalar keys and simple lists from a YAML front-matter block or a flat YAML file.

    Enough for advisory metadata (title, announced, impact, fixed_in); nested maps are
    skipped, and CVE ids are read from the whole text by the caller. No YAML library.
    """
    value = raw.decode("utf-8", "replace").replace("\r\n", "\n")
    if value.startswith("---\n"):
        end = value.find("\n---", 4)
        value = value[4:end if end > 0 else len(value)]
    out, key = {}, None
    for line in value.split("\n"):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$", line)
        if match and not line[0].isspace():
            key, rest = match.group(1), match.group(2).strip()
            out[key] = [] if not rest else ("" if rest in ("|", ">", "|-", ">-") else _scalar(rest))
            continue
        item = re.match(r"-\s+(.*)$", line.strip())
        if key and item and isinstance(out.get(key), list):
            out[key].append(_scalar(item.group(1).strip()))
        elif key and out.get(key) == "" and line[0].isspace():
            out[key] = _scalar(line.strip())
    return out


def _scalar(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    return value
