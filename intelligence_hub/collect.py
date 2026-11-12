"""Bounded public-feed collection. No article bodies, account access or model calls."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import gzip
import hashlib
import html
import http.client
import ipaddress
import json
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).absolute().parent.parent
STATE = ROOT / ".state"
CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Default response bound for one publisher feed. A source may set its own
# max_bytes in config/sources.json, never above FETCH_CEILING.
MAX_BYTES = 3 * 1024 * 1024
FETCH_CEILING = 16 * 1024 * 1024
# The one unbounded read: a Microsoft CVRF monthly release document (intelligence_hub/patch_tuesday.py).
# The October 2026 document was 30,083,214 bytes when read on 2026-11-03, mostly Azure Linux rows,
# and the owner directed on 2026-11-11 that these documents carry no byte ceiling. fetch() takes
# UNBOUNDED only by name, with maximum None; the 30-second read deadline still applies to it.
UNBOUNDED = None
# Byte bounds for the two public data files. Rows are never evicted to fit:
# a run that would cross a bound fails and the deployed publication stays.
FEED_MAX_BYTES = 8 * 1024 * 1024
# 24 MiB since 2026-11-11, raised from 12 MiB with the owner's approval (WP-00 of the revision
# plan): the deployed file was 10,795,310 bytes that day and had grown about 173 KB a day over
# the week before, so the old bound would have closed around 2026-11-22.
BRIEFS_MAX_BYTES = 24 * 1024 * 1024
# The deployed briefs file is the one read that may pass FETCH_CEILING, up to its own bound,
# and the largest file the collector writes; every publisher read keeps the 16 MiB ceiling.
DEPLOYED_BRIEFS_CEILING = BRIEFS_MAX_BYTES
OUTPUT_CEILING = max(FETCH_CEILING, FEED_MAX_BYTES, BRIEFS_MAX_BYTES)
# The two retained state files (.state/public-cache.json and .state/cve-projections.json) are
# written through write_raw, so they are read back under the same ceiling: a cache the previous
# run could save is never refused by the next run's read.
STATE_INPUT_BYTES = OUTPUT_CEILING
# The feed's article-row ceiling is derived from its byte bound, so it is not a
# second, hidden wall: the smallest live row is 363 bytes (publisher rows average
# about 480, KEV rows about 794), so at real sizes the byte bound is crossed first.
# It stays a structure guard for readers and is printed with its headroom every run.
MIN_ROW_BYTES = 300
MAX_FEED_ROWS = FEED_MAX_BYTES // MIN_ROW_BYTES
MAX_CVE_BRIEFS = 15000  # mirrors mitigations.MAX_RECORDS
SNAPSHOT_VERSION = 7
LEGACY_MAX_ARTICLES = 8000
HISTORY_START = date(1998, 1, 1)
KINDS = {"advisory", "research", "reporting", "incident", "kev", "filing"}
SOURCE_CLASSES = {"vendor-primary", "government-cert", "researcher", "press"}
CVE = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,8}\b", re.I)
PUBLIC_FEED = "https://teamstarwolf.github.io/intelligence-hub/data/feed.json"
PUBLIC_BRIEFS = "https://teamstarwolf.github.io/intelligence-hub/data/briefs.json"
PUBLIC_V7 = "https://teamstarwolf.github.io/intelligence-hub/data/v7/"
V7_MISMATCH = "A v7 shard differs from the deployed index."
# The workflow reads .state/collection-result.json with this bound and a typed check.
RESULT_MAX_BYTES = 65536
ZONE_ASSUMED = ", zone not stated, read as UTC"
NAMED_ZONES = {"CET": "+0100", "CEST": "+0200"}
NAIVE_STAMP = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2})[T ]([0-9]{2}:[0-9]{2}(?::[0-9]{2})?)(?:\.[0-9]{1,9})?")
RESPONSE_BYTE_LIMIT_REASON = "response_byte_limit_exceeded: source response exceeded its configured byte bound."


def require(value, message):
    if not value:
        raise ValueError(message)


def validate_window(start, end, snapshot_version):
    require(type(snapshot_version) is int and snapshot_version in (1, 2, 3, 4, 5, 6, 7), "Unsupported snapshot coverage version.")
    maximum = {1: 3661, 2: 3661, 3: 3661, 4: 3661, 5: 7306, 6: 14610, 7: 14610}[snapshot_version]
    require(type(start) is date and type(end) is date and start <= end and (end - start).days <= maximum,
            "History window must be date-only and within its schema's span.")
    require(snapshot_version < 6 or start >= HISTORY_START, "Schema 6 and 7 coverage must start on or after 1998-01-01.")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_url(value, hosts=None):
    if not isinstance(value, str) or len(value) > 4000 or any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value:
        return None
    try:
        parts = urllib.parse.urlsplit(value)
        host = parts.hostname or ""
        if parts.scheme != "https" or parts.username is not None or parts.password is not None or parts.port not in (None, 443):
            return None
        if not host.isascii() or host.endswith(".") or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", host) or host.endswith((".local", ".localhost", ".internal", ".test", ".invalid", ".localdomain", ".lan", ".home", ".home.arpa", ".example")):
            return None
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        if hosts is not None and host not in hosts:
            return None
        query = [(key, val) for key, val in urllib.parse.parse_qsl(parts.query, max_num_fields=40) if not key.lower().startswith("utm_") and key.lower() not in {"fbclid", "gclid", "mc_cid", "mc_eid"}]
        return urllib.parse.urlunsplit(("https", host, parts.path or "/", urllib.parse.urlencode(query), ""))
    except ValueError:
        return None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        raise ValueError("Publisher redirected; the source needs a reviewed canonical URL.")


class ResponseByteLimitExceeded(ValueError):
    """The existing fetch loop crossed its configured response byte bound."""


def fetch(url, maximum=MAX_BYTES, fresh=False, *, accept=None, language=None, ceiling=FETCH_CEILING):
    """One bounded HTTPS read. accept and language replace the default Accept header and add an
    Accept-Language header (Adobe's bulletin index refuses a read without both); ceiling is
    FETCH_CEILING, DEPLOYED_BRIEFS_CEILING for this Hub's own deployed briefs file, or UNBOUNDED
    (None, with maximum None) for an MSRC release document."""
    require(safe_url(url) == url, "Source URL must be a canonical public HTTPS URL.")
    require(ceiling in (FETCH_CEILING, DEPLOYED_BRIEFS_CEILING) or ceiling is UNBOUNDED, "Invalid fetch ceiling.")
    if ceiling is UNBOUNDED:
        require(maximum is None, "An unbounded read takes no byte bound.")
    else:
        require(type(maximum) is int and 1 <= maximum <= ceiling, "Invalid bounded read size.")
    require(accept is None or accept in {"application/json", "text/html"}, "Invalid Accept value.")
    require(language is None or language == "en-US", "Invalid Accept-Language value.")
    started = time.monotonic()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    headers = {"User-Agent": "TeamStarWolf-IntelligenceHub/0.1 (public feed reader)", "Accept": accept or "application/rss+xml, application/atom+xml, application/json, text/xml, application/xml", "Accept-Encoding": "identity"}
    if language:
        headers["Accept-Language"] = language
    if fresh:
        # The deployed files are served through a CDN cache; ask for the current copy.
        headers.update({"Cache-Control": "no-cache", "Pragma": "no-cache"})
    request = urllib.request.Request(url, headers=headers)
    chunks, size = [], 0
    try:
        with opener.open(request, timeout=12) as response:
            require(response.status == 200 and response.geturl() == url, "Unexpected publisher response.")
            require(response.headers.get("Content-Encoding", "identity").lower() == "identity", "Compressed responses are not accepted.")
            while True:
                require(time.monotonic() - started < 30, "Source exceeded its read deadline.")
                # read1 returns what the connection has delivered instead of waiting
                # to fill 64 KiB, so the deadline above is checked between short reads.
                block = response.read1(65536)
                if not block:
                    break
                size += len(block)
                if maximum is not None and size > maximum:
                    raise ResponseByteLimitExceeded("Source exceeded its bounded read limit.")
                chunks.append(block)
            if getattr(response, "length", None):
                raise http.client.IncompleteRead(b"", response.length)
    except http.client.HTTPException as error:
        # http.client errors (a truncated chunked body, a dropped connection) are
        # network failures: report them as OSError so every caller records them.
        raise OSError(type(error).__name__ + ": the publisher response ended early or was malformed") from error
    return b"".join(chunks)


def failure_reason(error, fallback):
    """One short public reason for a failed request, naming its cause."""
    if isinstance(error, ResponseByteLimitExceeded):
        return RESPONSE_BYTE_LIMIT_REASON
    if isinstance(error, urllib.error.HTTPError):
        return "HTTP " + str(error.code)
    detail = "".join(char for char in " ".join(str(error).split()) if ord(char) >= 32 and ord(char) != 127)[:300]
    return type(error).__name__ + ": " + (detail or fallback)


def public_bytes(value):
    """The exact bytes write_json(compact=True) gives a public data file."""
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode("utf-8")


def reject_constant(_value):
    raise ValueError("Nonfinite JSON numbers are not accepted.")


def read_json(path, limit=16 * 1024 * 1024):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "Local JSON input exceeds its limit.")
    return json.loads(raw, parse_constant=reject_constant)


def _context_string(value, maximum):
    require(type(value) is str and value.strip() and len(value) <= maximum, "Invalid mitigation context text.")
    require(not any(ord(char) < 32 or ord(char) == 127 or
                    0xD800 <= ord(char) <= 0xDFFF for char in value), "Invalid mitigation context characters.")
    return value


def _context_pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate mitigation context JSON key.")
        value[key] = item
    return value


def load_mitigation_context(path):
    """Read optional local curation before any public-source request or write."""
    try:
        path.lstat()
    except FileNotFoundError:
        return []
    require(path.is_file() and not path.is_symlink(), "Mitigation context must be an ordinary file.")
    with path.open("rb") as stream:
        raw = stream.read(64 * 1024 + 1)
    require(len(raw) <= 64 * 1024, "Mitigation context exceeds its byte limit.")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_context_pairs, parse_constant=reject_constant)
    require(type(value) is dict and set(value) == {"schema_version", "entries"} and
            type(value["schema_version"]) is int and value["schema_version"] == 1, "Invalid mitigation context format.")
    entries = value["entries"]
    require(type(entries) is list and len(entries) <= 20, "Mitigation context exceeds its entry limit.")
    seen = set()
    for entry in entries:
        require(type(entry) is dict and set(entry) == {"cve", "steps", "limitations"}, "Invalid mitigation context entry.")
        cve = entry["cve"]
        require(type(cve) is str and cve.isascii() and cve == cve.upper() and
                CVE.fullmatch(cve) and cve not in seen, "Invalid or duplicate mitigation context CVE.")
        seen.add(cve)
        require(type(entry["steps"]) is list and 1 <= len(entry["steps"]) <= 6 and
                type(entry["limitations"]) is list and len(entry["limitations"]) <= 4, "Invalid mitigation context lists.")
        total = len(cve)
        for step in entry["steps"]:
            require(type(step) is dict and set(step) == {"title", "detail", "evidence_url"}, "Invalid mitigation context step.")
            _context_string(step["title"], 160)
            _context_string(step["detail"], 2000)
            url = _context_string(step["evidence_url"], 4000)
            require(url.isascii() and safe_url(url) == url, "Invalid mitigation context evidence URL.")
            total += sum(len(item) for item in step.values())
        for item in entry["limitations"]:
            total += len(_context_string(item, 1000))
        require(total <= 4000, "Mitigation context exceeds its total text limit.")
    return entries


def _context_ui_text(value, maximum, nullable=False, empty=True):
    if value is None:
        return nullable
    if type(value) is not str or sum(2 if ord(char) > 0xFFFF else 1 for char in value) > maximum:
        return False
    # Match JavaScript String.trim for the existing nonempty limitation field.
    whitespace = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
    return empty or bool(value.strip(whitespace))


def _context_ui_limits(analysis):
    require(type(analysis) is dict and type(analysis.get("steps")) is list and
            type(analysis.get("limitations")) is list and len(analysis["steps"]) <= 100 and
            len(analysis["limitations"]) <= 100, "Mitigation context exceeds the existing detail list limits.")
    for step in analysis["steps"]:
        require(type(step) is dict and _context_ui_text(step.get("title"), 2000) and
                _context_ui_text(step.get("detail"), 20000) and
                _context_ui_text(step.get("evidence_url"), 4000, nullable=True), "Mitigation context exceeds the existing detail field limits.")
    require(all(_context_ui_text(item, 20000, empty=False) for item in analysis["limitations"]),
            "Mitigation context exceeds the existing limitation limits.")


def apply_mitigation_context(briefs, entries):
    """Append only to isolated copies of existing briefs after all matches fit."""
    planned = {}
    for entry in entries:
        cve = entry["cve"]
        if cve not in briefs:
            continue
        record = briefs[cve]
        require(type(record) is dict and record.get("cve") == cve, "Mitigation context brief identity differs.")
        if record.get("record_state") == "REJECTED":
            continue
        candidate = deepcopy(record)
        analysis = candidate.get("analysis")
        _context_ui_limits(analysis)
        for step in analysis["steps"]:
            if (step["title"] == "Vendor guidance needs review" and step["detail"] ==
                    "No patch version or workaround is established in the loaded structured inputs. Follow the CVE/vendor references; this hub will not invent a fix."):
                step["detail"] = "No solution/workaround was supplied by the loaded CNA fields. Supplementary publisher context below is separate; verify its dated product and deployment scope."
        analysis["steps"].extend(deepcopy(entry["steps"]))
        analysis["limitations"].extend(deepcopy(entry["limitations"]))
        _context_ui_limits(analysis)
        planned[cve] = candidate
    return {**briefs, **planned} if planned else briefs


def write_json(path, value, compact=False):
    raw = (json.dumps(value, ensure_ascii=False, allow_nan=False, indent=None if compact else 2, separators=(",", ":") if compact else None) + "\n").encode("utf-8")
    write_raw(path, raw)


def write_raw(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    require(len(raw) <= OUTPUT_CEILING, "Snapshot output exceeds its limit.")
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("xb") as stream:
        stream.write(raw)
    temporary.replace(path)


def text(value, maximum=240):
    # Markup is stripped to text, never interpreted by the browser.
    return " ".join(html.unescape(re.sub(r"<[^>]{0,2000}>", " ", value or "")).split())[:maximum]


def _parse_stamp(value):
    value = value.strip()
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        return date.fromisoformat(value)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        pass
    # email.utils knows the North American zone names but not the Central European
    # ones that CERT-EU uses ("Fri, 23 Oct 2026 16:36:26 CEST").
    named = re.fullmatch(r"(.+?)\s+(CET|CEST)", value)
    if named:
        value = named[1] + " " + NAMED_ZONES[named[2]]
    return parsedate_to_datetime(value)


def published(value):
    """A UTC ISO stamp (or a bare ISO date), or None. Stamps without a zone are refused."""
    try:
        stamp = _parse_stamp(value)
        if type(stamp) is date:
            return stamp.isoformat()
        if stamp.tzinfo is None:
            return None
        return stamp.astimezone(timezone.utc).isoformat(timespec="seconds")
    except (ValueError, TypeError, AttributeError, OverflowError, IndexError):
        return None


def feed_published(value):
    """Publisher feed date: (UTC ISO stamp or None, True when no zone was given and UTC was assumed).

    Cisco PSIRT writes "2026-11-02 21:16:10.0" with no zone. Such stamps are read as
    UTC, and the caller marks the row's date basis so the assumption stays visible.
    """
    stamp = published(value)
    if stamp is not None or not isinstance(value, str):
        return stamp, False
    value = value.strip()
    try:
        match = NAIVE_STAMP.fullmatch(value)
        if match:
            clock = match[2] if match[2].count(":") == 2 else match[2] + ":00"
            naive = datetime.strptime(match[1] + " " + clock, "%Y-%m-%d %H:%M:%S")
        else:
            naive = parsedate_to_datetime(value)
            if naive.tzinfo is not None:
                return None, False
    except (ValueError, TypeError, AttributeError, OverflowError, IndexError):
        return None, False
    return naive.replace(tzinfo=timezone.utc).isoformat(timespec="seconds"), True


class BoundedTreeBuilder(ET.TreeBuilder):
    def __init__(self):
        super().__init__()
        self.nodes = 0
        self.depth = 0

    def start(self, tag, attrs):
        self.nodes += 1
        self.depth += 1
        require(self.nodes <= 40000 and self.depth <= 48, "XML structure exceeds its bounds.")
        return super().start(tag, attrs)

    def end(self, tag):
        element = super().end(tag)
        self.depth -= 1
        return element


def source_selection(source):
    basis = source.get("entry_selection", "document-order-v1")
    require(type(basis) is str and basis in {"document-order-v1", "publisher-date-desc-v1"}, "Invalid source entry selection.")
    if basis == "publisher-date-desc-v1":
        require(source.get("id") == "f5-labs" and source.get("url") == "https://www.f5.com/labs/rss-feeds/all.xml" and
                source.get("article_hosts") == ["www.f5.com"], "Publisher-date selection requires the exact F5 source definition.")
    return basis


def selection_context(source, selection_cutoff_date):
    basis = source_selection(source)
    if basis == "publisher-date-desc-v1":
        require(type(selection_cutoff_date) is date, "Publisher-date selection requires the declared window end date.")
    return {"version": 1, "basis": basis,
            "cutoff_date": selection_cutoff_date.isoformat() if basis == "publisher-date-desc-v1" else None}


def ranked_feed_entries(entries, source, *, selection_cutoff_date=None):
    selection = selection_context(source, selection_cutoff_date)
    if selection["basis"] == "document-order-v1":
        return entries[:150], selection

    def rank(candidate):
        index, element = candidate
        fields = {}
        for child in element:
            key = child.tag.rsplit("}", 1)[-1]
            if key in {"pubDate", "published", "date", "updated"}:
                fields.setdefault(key, child)
        normalized = None
        for key in ("pubDate", "published", "date", "updated"):
            child = fields.get(key)
            if child is None:
                continue
            if len(child):
                break
            value = child.text or ""
            if not value:
                continue
            if len(value) <= 128:
                normalized = published(value)
            break
        if normalized is None:
            return (1, 0, 0, 0, 0, 0, 0, index)
        day = date.fromisoformat(normalized[:10])
        if day > selection_cutoff_date:
            return (2, 0, 0, 0, 0, 0, 0, index)
        # Midnight is only a comparison key for date-only publisher metadata.
        stamp = datetime.fromisoformat(normalized)
        return (0, -day.year, -day.month, -day.day, -stamp.hour, -stamp.minute, -stamp.second, index)

    ranked = sorted(enumerate(entries), key=rank)
    return [element for _, element in ranked[:150]], selection


def parse_feed(raw, source, *, selection_cutoff_date=None):
    decoded = raw.decode("utf-8-sig")
    require("\x00" not in decoded and "<!DOCTYPE" not in decoded.upper() and "<!ENTITY" not in decoded.upper(), "DTD/entity/binary XML is not accepted.")
    root = ET.fromstring(decoded, parser=ET.XMLParser(target=BoundedTreeBuilder()))
    stack, count = [(root, 0)], 0
    while stack:
        element, depth = stack.pop()
        count += 1
        require(count <= 40000 and depth <= 48, "XML structure exceeds its bounds.")
        stack.extend((child, depth + 1) for child in element)
    require(root.tag.rsplit("}", 1)[-1].lower() in {"rss", "feed", "rdf"}, "Response is not RSS or Atom.")
    entries = [element for element in root.iter() if element.tag.rsplit("}", 1)[-1] in {"item", "entry"}]
    selected, selection = ranked_feed_entries(entries, source, selection_cutoff_date=selection_cutoff_date)
    articles = []
    intake = {"items_seen": len(entries), "items_processed": min(len(entries), 150),
        "items_admitted": 0, "items_rejected": 0, "items_filtered": 0,
        "items_unprocessed": max(0, len(entries) - 150), "entry_limit": 150, "cve_limit": 100,
        "rejection_reasons": {"invalid_link_or_title": 0, "cve_limit_exceeded": 0}, "selection": selection}
    for element in selected:
        fields, links = {}, []
        for child in element:
            key = child.tag.rsplit("}", 1)[-1]
            fields.setdefault(key, "".join(child.itertext()))
            if key == "link":
                if child.get("href") and child.get("rel", "alternate") == "alternate":
                    links.append(child.get("href"))
                elif child.text:
                    links.append(child.text.strip())
        url = next((safe_url(link, source["article_hosts"]) for link in links if safe_url(link, source["article_hosts"])), None)
        title = text(fields.get("title"))
        if not url or not title:
            intake["items_rejected"] += 1
            intake["rejection_reasons"]["invalid_link_or_title"] += 1
            continue
        stamp, zone_assumed = feed_published(fields.get("pubDate") or fields.get("published") or fields.get("date") or fields.get("updated") or "")
        basis = "publication" if (fields.get("pubDate") or fields.get("published") or fields.get("date")) else "publisher update" if fields.get("updated") else "unknown"
        if stamp is not None and zone_assumed:
            basis += ZONE_ASSUMED
        # Display titles stay bounded; mention counting uses the complete source fields.
        mention_text = fields.get("title", "") + " " + " ".join(fields.get(key, "") for key in ("description", "summary", "content", "encoded"))
        if source.get("include_terms") and not any(term.casefold() in text(mention_text, MAX_BYTES).casefold() for term in source["include_terms"]):
            intake["items_filtered"] += 1
            continue
        cves = sorted(set(CVE.findall(mention_text.upper())))
        if len(cves) > 100:
            intake["items_rejected"] += 1
            intake["rejection_reasons"]["cve_limit_exceeded"] += 1
            continue
        articles.append({"id": "feed-" + hashlib.sha256(url.encode()).hexdigest()[:20], "title": title, "url": url,
            "source_id": source["id"], "source_name": source["name"], "kind": source["kind"], "published_at": stamp,
            "event_date": None, "date_basis": "filing" if source["kind"] == "filing" else basis, "summary": "", "cves": cves,
            "tags": [], "exploitation": "unknown", "references": [], "origin": "publisher-feed"})
    intake["items_admitted"] = len(articles)
    return {"articles": articles, "intake": intake}


def update_source(source, cached, *, selection_cutoff_date=None):
    attempted = now()
    try:
        selection_context(source, selection_cutoff_date)
        raw = fetch(source["url"], source.get("max_bytes", MAX_BYTES))
        parsed = parse_feed(raw, source, selection_cutoff_date=selection_cutoff_date)
        incoming = parsed["articles"]
        intake = {**parsed["intake"], "attempted_at": attempted, "response_sha256": hashlib.sha256(raw).hexdigest()}
        incomplete = intake["items_rejected"] > 0 or intake["items_unprocessed"] > 0
        if not incoming and (incomplete or not source.get("include_terms")):
            return {**cached, "status": "failed", "last_attempt": attempted,
                "last_success": cached.get("last_success"), "error": "No acceptable entries were admitted in the bounded response window.",
                "articles": cached.get("articles", []), "intake": intake}
        combined = {article["url"]: article for article in cached.get("articles", [])}
        combined.update({article["url"]: article for article in incoming})
        articles = sorted(combined.values(), key=lambda article: article.get("published_at") or "", reverse=True)[:600]
        return {"status": "partial" if incomplete else "ok", "last_attempt": attempted, "last_success": now(), "error": None,
                "sha256": intake["response_sha256"], "articles": articles, "intake": intake}
    except (OSError, ValueError, ET.ParseError) as error:
        reason = failure_reason(error, "source unavailable or rejected by intake policy")
        return {**cached, "status": "failed", "last_attempt": attempted, "last_success": cached.get("last_success"),
                "error": reason, "articles": cached.get("articles", []), "intake": None}


def update_kev(cached):
    attempted = now()
    try:
        raw = fetch(CATALOG_URL)
        catalog = json.loads(raw, parse_constant=reject_constant)
        validate_catalog(catalog)
        return {"status": "ok", "last_attempt": attempted, "last_success": now(), "error": None,
                "sha256": hashlib.sha256(raw).hexdigest(), "catalog": catalog, "intake": None}
    except (OSError, ValueError) as error:
        reason = failure_reason(error, "catalog unavailable or rejected")
        return {**cached, "status": "failed", "last_attempt": attempted, "last_success": cached.get("last_success"), "error": reason, "intake": None}


def validate_catalog(catalog):
    require(isinstance(catalog, dict) and isinstance(catalog.get("vulnerabilities"), list) and 1 <= len(catalog["vulnerabilities"]) <= 15000, "Unexpected KEV catalog.")
    require(type(catalog.get("count")) is int and catalog["count"] == len(catalog["vulnerabilities"]), "KEV count does not match its records.")
    for entry in catalog["vulnerabilities"]:
        require(isinstance(entry, dict), "Invalid KEV record.")
        for field in ("cveID", "dateAdded", "vulnerabilityName", "shortDescription", "vendorProject", "product"):
            require(isinstance(entry.get(field), str) and len(entry[field]) <= 12000, "Invalid KEV field.")
        require(CVE.fullmatch(entry["cveID"]) and published(entry["dateAdded"]) == entry["dateAdded"], "Invalid KEV identity or addition date.")


def validate_article(article):
    require(isinstance(article, dict) and article.get("kind") in KINDS, "Invalid article kind.")
    for field, maximum in (("id", 100), ("source_id", 80), ("source_name", 100), ("title", 300), ("date_basis", 60)):
        require(isinstance(article.get(field), str) and 1 <= len(article[field]) <= maximum, "Invalid article identity or title.")
    require(re.fullmatch(r"[a-z0-9-]{1,80}", article["source_id"]), "Invalid article source identity.")
    require(safe_url(article.get("url")) is not None, "Invalid article URL.")
    require(article.get("origin") in {"publisher-feed", "cisa-kev", "library-curation"} and article.get("exploitation") in {"known", "reported", "unknown"}, "Invalid article provenance.")
    require(isinstance(article.get("summary"), str) and len(article["summary"]) <= 500, "Invalid article summary.")
    for field in ("published_at", "event_date"):
        require(article.get(field) is None or isinstance(article[field], str) and len(article[field]) <= 40 and published(article[field]) is not None, "Invalid article date.")
    for field, maximum in (("cves", 100), ("tags", 30), ("references", 12)):
        require(isinstance(article.get(field), list) and len(article[field]) <= maximum, "Invalid article list.")
    require(all(isinstance(value, str) and CVE.fullmatch(value) for value in article["cves"]), "Invalid CVE identifier.")
    require(all(isinstance(value, str) and len(value) <= 100 for value in article["tags"]), "Invalid article tag.")
    require(all(isinstance(item, dict) and isinstance(item.get("label"), str) and len(item["label"]) <= 150 and safe_url(item.get("url")) for item in article["references"]), "Invalid reference.")


def article_date(article):
    # Publication-based rows retain a separate event date without silently changing chronology.
    return (article.get("event_date") if article.get("date_basis") == "event" else article.get("published_at")) or ""


def validate_cache(cache, sources):
    require(isinstance(cache, dict) and isinstance(cache.get("sources"), dict) and isinstance(cache.get("kev"), dict), "Invalid retained public cache.")
    for source in sources:
        observation = cache["sources"].get(source["id"], {})
        require(isinstance(observation, dict) and isinstance(observation.get("articles", []), list) and len(observation.get("articles", [])) <= 600, "Invalid retained source cache.")
        validate_observation(observation, source=source)
        for article in observation.get("articles", []):
            validate_article(article)
            require(article["source_id"] == source["id"] and article["source_name"] == source["name"] and article["kind"] == source["kind"] and article["origin"] == "publisher-feed" and safe_url(article["url"], source["article_hosts"]), "Retained article source mismatch.")
    validate_observation(cache["kev"], kev=True)
    if "catalog" in cache["kev"]:
        validate_catalog(cache["kev"]["catalog"])


def validate_intake(intake, observation, source=None, *, allow_selection=True):
    counts = {"items_seen", "items_processed", "items_admitted", "items_rejected", "items_filtered", "items_unprocessed"}
    expected = counts | {"entry_limit", "cve_limit", "rejection_reasons", "attempted_at", "response_sha256"}
    require(isinstance(intake, dict) and set(intake) in (expected, expected | {"selection"}) and
            (allow_selection or "selection" not in intake), "Invalid source intake fields.")
    if "selection" in intake:
        selection = intake["selection"]
        require(type(selection) is dict and set(selection) == {"version", "basis", "cutoff_date"} and
                type(selection["version"]) is int and selection["version"] == 1 and
                type(selection["basis"]) is str and selection["basis"] in {"document-order-v1", "publisher-date-desc-v1"},
                "Invalid source selection metadata.")
        if selection["basis"] == "document-order-v1":
            require(selection["cutoff_date"] is None, "Document-order selection cannot carry a cutoff date.")
        else:
            require(source is not None, "Publisher-date selection requires a known F5 source.")
            source_selection({**source, "entry_selection": selection["basis"]})
            cutoff = selection["cutoff_date"]
            require(type(cutoff) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", cutoff) and
                    date.fromisoformat(cutoff).isoformat() == cutoff, "Invalid source selection cutoff date.")
    require(all(type(intake[key]) is int and 0 <= intake[key] <= 40000 for key in counts), "Invalid source intake counts.")
    require(type(intake["entry_limit"]) is int and intake["entry_limit"] == 150 and
            type(intake["cve_limit"]) is int and intake["cve_limit"] == 100, "Invalid source intake limits.")
    require(intake["items_processed"] == min(intake["items_seen"], 150) and
            intake["items_seen"] == intake["items_processed"] + intake["items_unprocessed"] and
            intake["items_processed"] == intake["items_admitted"] + intake["items_rejected"] + intake["items_filtered"],
            "Source intake counts do not reconcile.")
    reasons = intake["rejection_reasons"]
    require(isinstance(reasons, dict) and set(reasons) == {"invalid_link_or_title", "cve_limit_exceeded"} and
            all(type(value) is int and 0 <= value <= 150 for value in reasons.values()) and
            sum(reasons.values()) == intake["items_rejected"], "Invalid source intake rejection counts.")
    attempted = intake["attempted_at"]
    normalized_attempt = published(attempted) if isinstance(attempted, str) else None
    require(isinstance(attempted, str) and len(attempted) <= 40 and "T" in attempted and normalized_attempt and
            "T" in normalized_attempt and attempted == observation.get("last_attempt"), "Invalid source intake attempt date.")
    digest = intake["response_sha256"]
    require(isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest), "Invalid source intake digest.")
    status = observation.get("status")
    incomplete = intake["items_rejected"] > 0 or intake["items_unprocessed"] > 0
    require(status in {"ok", "partial", "failed"}, "Source intake has no matching attempt status.")
    if status in {"ok", "partial"}:
        accepted = datetime.fromisoformat((observation.get("last_success") or "").replace("Z", "+00:00"))
        attempt_time = datetime.fromisoformat(attempted.replace("Z", "+00:00"))
        require(accepted.tzinfo is not None and attempt_time.tzinfo is not None and accepted >= attempt_time and
                digest == observation.get("sha256"),
                "Accepted source intake provenance differs.")
        require(incomplete if status == "partial" else not incomplete, "Source intake status differs from its coverage.")
        if status == "partial":
            require(intake["items_admitted"] > 0, "Partial source intake requires accepted entries.")
        elif source is not None and intake["items_admitted"] == 0:
            require(bool(source.get("include_terms")), "An empty accepted source requires a configured filter.")
    else:
        # A current rejected response has its own hash, distinct from older accepted input.
        require(intake["items_admitted"] == 0 and isinstance(observation.get("error"), str) and observation["error"].strip(),
                "Failed source intake must have zero accepted entries and a reason.")
        if source is not None and source.get("include_terms"):
            require(incomplete, "Complete filter-empty input is not a source failure.")


def validate_observation(observation, source=None, kev=False, *, allow_selection=True):
    require(isinstance(observation, dict), "Invalid source observation.")
    require(observation.get("status", "not_fetched") in {"ok", "partial", "failed", "not_fetched"}, "Invalid source observation status.")
    for field in ("last_attempt", "last_success"):
        value = observation.get(field)
        require(value is None or isinstance(value, str) and len(value) <= 40 and published(value) is not None, "Invalid source observation date.")
    reason = observation.get("error")
    require(reason is None or isinstance(reason, str) and len(reason) <= 500, "Invalid source observation error.")
    digest = observation.get("sha256")
    require(digest is None or isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest), "Invalid source digest.")
    if observation.get("status") in {"ok", "partial"}:
        require(observation.get("last_success") and observation.get("last_attempt") and digest and reason is None, "Incomplete successful source observation.")
    intake = observation.get("intake")
    if kev:
        require(observation.get("status") != "partial" and intake is None, "KEV cannot carry a partial RSS intake report.")
    elif intake is not None:
        validate_intake(intake, observation, source, allow_selection=allow_selection)
    else:
        require(observation.get("status") != "partial", "Partial source observation requires an intake report.")


def validate_registry(registry):
    require(registry.get("schema_version") == 1 and isinstance(registry.get("sources"), list) and 1 <= len(registry["sources"]) <= 96, "Unexpected source registry.")
    seen = set()
    for source in registry["sources"]:
        require(re.fullmatch(r"[a-z0-9-]{1,80}", source["id"]) and source["id"] not in seen, "Invalid source identity.")
        seen.add(source["id"])
        require(source["kind"] in KINDS and isinstance(source["name"], str) and len(source["name"]) <= 100, "Invalid source metadata.")
        require(safe_url(source["url"]) == source["url"] and safe_url(source["home"]) is not None, "Invalid source URL.")
        require(isinstance(source["article_hosts"], list) and 1 <= len(source["article_hosts"]) <= 8 and all(safe_url("https://" + host + "/") is not None for host in source["article_hosts"]), "Invalid publisher hosts.")
        if "include_terms" in source:
            require(isinstance(source["include_terms"], list) and 1 <= len(source["include_terms"]) <= 12 and all(isinstance(term, str) and 1 <= len(term) <= 80 for term in source["include_terms"]), "Invalid source selection terms.")
        if "max_bytes" in source:
            require(type(source["max_bytes"]) is int and 1 <= source["max_bytes"] <= FETCH_CEILING, "Invalid source byte bound.")
        # Tagging metadata. Its values are checked against config/vocab by vocab --check;
        # here only the shape is checked, so a vocabulary problem never stops collection.
        require(source.get("source_class") in SOURCE_CLASSES, "Invalid or missing source_class.")
        require(source.get("publisher_vendor") is None or isinstance(source["publisher_vendor"], str) and
                re.fullmatch(r"vendor:[a-z0-9][a-z0-9-]{0,80}", source["publisher_vendor"]), "Invalid publisher_vendor.")
        require(source.get("country") is None or isinstance(source["country"], str) and re.fullmatch(r"[A-Z]{2}", source["country"]),
                "Invalid source country.")
        source_selection(source)
    return registry["sources"]


def wire_articles(articles):
    """Group rows by origin and source for compression; readers sort rows themselves."""
    by_date = sorted(articles, key=article_date, reverse=True)
    return sorted(by_date, key=lambda article: (article["origin"], article["source_id"], " ".join(article["tags"]).casefold()))


def bound_report(name, raw, limit):
    compressed = len(gzip.compress(raw, compresslevel=6, mtime=0))
    return {"file": name, "bytes": len(raw), "limit": limit, "headroom": limit - len(raw), "gzip_estimate": compressed}


def rows_over_message(count):
    return ("data/feed.json would hold " + format(count, ",") + " article rows, over its " + format(MAX_FEED_ROWS, ",") +
            "-row ceiling (the " + format(FEED_MAX_BYTES, ",") + "-byte feed bound / " + str(MIN_ROW_BYTES) +
            " bytes per row). Nothing was evicted; the deployed publication is preserved.")


def cves_over_message(count):
    return ("data/briefs.json would hold " + format(count, ",") + " CVE briefs, over its " + format(MAX_CVE_BRIEFS, ",") +
            "-brief ceiling. Nothing was evicted; the deployed publication is preserved.")


def check_rows(articles, cves):
    """Print the row and CVE headroom every run, and refuse a publication that crosses either ceiling."""
    reports = [{"file": "data/feed.json", "count": articles, "unit": "article rows", "limit": MAX_FEED_ROWS},
               {"file": "data/briefs.json", "count": cves, "unit": "CVE briefs", "limit": MAX_CVE_BRIEFS}]
    for report in reports:
        report["headroom"] = report["limit"] - report["count"]
        print("{file}: {count:,} of {limit:,} {unit}, {headroom:,} of headroom ({percent}% free)".format(
            percent=max(0, report["headroom"]) * 100 // report["limit"], **report), file=sys.stderr)
    require(articles <= MAX_FEED_ROWS, rows_over_message(articles))
    require(cves <= MAX_CVE_BRIEFS, cves_over_message(cves))
    return reports


def check_bounds(feed_raw, briefs_raw):
    """Refuse a publication whose data files cross their byte bounds; never drop rows to fit."""
    reports = [bound_report("data/feed.json", feed_raw, FEED_MAX_BYTES), bound_report("data/briefs.json", briefs_raw, BRIEFS_MAX_BYTES)]
    for report in reports:
        print("{file}: {bytes:,} of {limit:,} bytes, {headroom:,} bytes of headroom ({percent}% free); gzip estimate {gzip_estimate:,} bytes".format(
            percent=max(0, report["headroom"]) * 100 // report["limit"], **report), file=sys.stderr)
    for report in reports:
        require(report["headroom"] >= 0, report["file"] + " would be " + format(report["bytes"], ",") + " bytes, over its " +
                format(report["limit"], ",") + "-byte bound. Nothing was evicted; the deployed publication is preserved.")
    return reports


def publication_changed(content_changed, changed_shards, removed_shards, exports_changed, status_summary):
    """Whether this run deploys: the typed 'changed' decision.

    sources.json carries every run's attempt clocks, so on its own it never republishes; the v6
    content revision ignores those clocks in the same way. A change in the published export files
    (for example a new dictionary) republishes too. The service-health board, its index and the
    outage signals carry fetch clocks too; the board and the outage signals republish when their
    digests without clocks change, and incident history republishes through its month files.
    """
    from .status import QUIET as status_quiet
    quiet = {"sources.json", *status_quiet}
    return bool(content_changed or removed_shards != [] or any(path not in quiet for path in changed_shards) or exports_changed or
                status_summary.get("board_changed") is True or status_summary.get("outages_changed") is True)


def build_snapshot(start, end, refresh=True, resume_public=False, enrich_limit=40, patch_limit=None):
    from .mitigations import brief_index, build_briefs, merge_retained, split_publication
    from .intelligence import compose_with_reports, load_inputs
    from .archive import validate_snapshot
    from .site import layout_revision as site_layout_revision

    from . import patch_tuesday

    validate_window(start, end, SNAPSHOT_VERSION)
    patch_limit = patch_tuesday.DEFAULT_DOCUMENTS if patch_limit is None else patch_limit
    require(type(patch_limit) is int and 0 <= patch_limit <= patch_tuesday.MAX_DOCUMENTS,
            "The Patch Tuesday document limit must be 0 to " + str(patch_tuesday.MAX_DOCUMENTS) + ".")
    intelligence_inputs = load_inputs(ROOT)
    require(type(enrich_limit) is int and 0 <= enrich_limit <= 2000, "CVE enrichment limit must be 0 to 2000.")
    context = load_mitigation_context(ROOT / "config/mitigation-context.json")
    registry = read_json(ROOT / "config/sources.json", 128 * 1024)
    sources = validate_registry(registry)
    cache_path = STATE / "public-cache.json"
    cache = read_json(cache_path, STATE_INPUT_BYTES) if cache_path.exists() else {"sources": {}, "kev": {}}
    validate_cache(cache, sources)
    previous, resume_reason = resume_deployed(sources, cache) if resume_public else (None, None)
    require(not resume_public or previous is not None,
            "The deployed snapshot could not be resumed safely (" + str(resume_reason) + "); preserving the current publication.")
    cve_path = STATE / "cve-projections.json"
    retained = read_json(cve_path, STATE_INPUT_BYTES) if cve_path.exists() else {}
    require(isinstance(retained, dict) and len(retained) <= 15000, "Invalid retained CVE projections.")
    if previous and isinstance(previous.get("mitigations"), dict):
        require(len(previous["mitigations"]) <= 15000, "Invalid deployed CVE projection count.")
        for cve, candidate in previous["mitigations"].items():
            retained[cve] = merge_retained(retained.get(cve), candidate, cve, safe_url, published)
        require(len(retained) <= 15000, "Merged CVE projections exceed their bound.")
    if refresh:
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {source["id"]: pool.submit(update_source, source, cache["sources"].get(source["id"], {}), selection_cutoff_date=end) for source in sources}
            kev_future = pool.submit(update_kev, cache["kev"])
            cache = {"sources": {key: future.result() for key, future in futures.items()}, "kev": kev_future.result()}
        validate_cache(cache, sources)
        require(any(item.get("status") in {"ok", "partial"} for item in [*cache["sources"].values(), cache["kev"]]), "No live source succeeded; the previously deployed snapshot must remain available.")
    # Service health (intelligence_hub/status.py): vendor status pages, cloud health feeds and
    # internet outage signals. A later failure in that step publishes the previous status files
    # again and never blocks the feed; a previous status file that cannot be read holds the run,
    # because the month files are the only copy of incidents the vendors no longer list.
    service_health = collect_status(refresh, previous, end)
    require(service_health["summary"].get("status") != "held", "Service health: " + str(service_health["summary"].get("reason")) +
            ". Nothing was written; the deployed publication is preserved and the next run reads the status files again.")
    patch = collect_patch_tuesday(registry, refresh, previous, patch_limit)
    failures = [{"id": key, "error": item.get("error")} for key, item in [*sorted(cache["sources"].items()), ("cisa-kev", cache["kev"])]
                if item.get("status") == "failed"]
    for failure in failures:
        print("Source " + failure["id"] + " failed: " + str(failure["error"]), file=sys.stderr)
    health, articles = [], []
    for source in sources:
        observation = cache["sources"].get(source["id"], {})
        health.append({"id": source["id"], "name": source["name"], "kind": source["kind"], "url": source["home"],
            "status": observation.get("status", "not_fetched"), "last_attempt": observation.get("last_attempt"),
            "last_success": observation.get("last_success"), "error": observation.get("error"), "sha256": observation.get("sha256"),
            "intake": observation.get("intake"), "configured_selection": source_selection(source),
            "articles": len(observation.get("articles", []))})
        articles.extend(observation.get("articles", []))
    kev = cache["kev"]
    for item in kev.get("catalog", {}).get("vulnerabilities", []):
        if not isinstance(item, dict) or not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,8}", item.get("cveID", "")):
            continue
        added = item.get("dateAdded", "")
        try:
            if not start <= date.fromisoformat(added) <= end:
                continue
        except ValueError:
            continue
        ident = item["cveID"]
        articles.append({"id": "kev-" + ident, "title": ident + " · " + text(item.get("vulnerabilityName"), 220),
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=" + ident,
            "source_id": "cisa-kev", "source_name": "CISA Known Exploited Vulnerabilities", "kind": "kev", "published_at": added,
            "event_date": None, "date_basis": "CISA catalog addition", "summary": text(item.get("shortDescription"), 420),
            "cves": [ident], "tags": [value for value in (text(item.get("vendorProject"), 80), text(item.get("product"), 100)) if value],
            "exploitation": "known", "references": [{"label": "CVE record", "url": "https://www.cve.org/CVERecord?id=" + ident}], "origin": "cisa-kev"})
    health.append({"id": "cisa-kev", "name": "CISA KEV", "kind": "advisory", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "status": kev.get("status", "not_fetched"), "last_attempt": kev.get("last_attempt"), "last_success": kev.get("last_success"),
        "error": kev.get("error"), "sha256": kev.get("sha256"), "intake": None, "configured_selection": None,
        "articles": sum(article["origin"] == "cisa-kev" for article in articles)})
    history_path = ROOT / "config/history.json"
    history = read_json(history_path, 2 * 1024 * 1024) if history_path.exists() else {"entries": []}
    require(isinstance(history.get("entries"), list) and len(history["entries"]) <= 500, "Invalid history collection.")
    for entry in history["entries"]:
        validate_article(entry)
        require(entry["origin"] == "library-curation", "History entries require curated provenance.")
        articles.append(entry)
    selected, duplicates = {}, 0
    for article in articles:
        validate_article(article)
        stamp = article_date(article)[:10]
        if stamp:
            try:
                if not start <= date.fromisoformat(stamp) <= end:
                    continue
            except ValueError:
                continue
        canonical = safe_url(article.get("url"))
        require(canonical is not None, "An article contains an unsafe link.")
        # Source URL identity preserves distinct publisher coverage; curated explanations take precedence.
        if canonical in selected:
            duplicates += 1
            article = {**article, "cves": sorted(set(article["cves"]) | set(selected[canonical]["cves"]))}
            validate_article(article)
        selected[canonical] = {**article, "url": canonical}
    ordered = sorted(selected.values(), key=article_date, reverse=True)
    require(ordered, "No articles are available in the selected window; preserving the previous deployment.")
    require(len({article["id"] for article in ordered}) == len(ordered), "Article identities must be unique.")
    counts = {origin: sum(article["origin"] == origin for article in ordered) for origin in ("cisa-kev", "library-curation", "publisher-feed")}
    prepared_at = now()
    briefs, projections, mitigation_stats = build_briefs(ordered, kev.get("catalog", {}), retained, refresh, enrich_limit, fetch, text, safe_url, published, prepared_at)
    briefs = apply_mitigation_context(briefs, context)
    tagged = tag_snapshot(ordered, sources, kev.get("catalog"), briefs)
    ordered = tagged["articles"]
    # Report inputs belong to the owner's desktop compiler; a bad catalog never blocks the feed.
    intelligence, reports = compose_with_reports(ROOT, briefs, safe_url, inputs=intelligence_inputs)
    snapshot = {"schema_version": SNAPSHOT_VERSION, "generated_at": now(), "window": {"start": start.isoformat(), "end": end.isoformat()},
        "articles": ordered, "sources": health, "history_reviewed_at": history.get("curated_at"),
        "mitigations": briefs, "mitigation_coverage": mitigation_stats, "deduplication": {"url_duplicates_removed": duplicates},
        "refresh": {"requested_minutes": 120, "mode": "scheduled-check", "status_url": "https://github.com/TeamStarWolf/intelligence-hub/actions/workflows/publish.yml",
            "notes": ["The workflow asks GitHub for a run every two hours (cron 7 */2 * * *). GitHub does not guarantee scheduled runs: they start late, are sometimes dropped, and stop after long repository inactivity.", "data/v7/index.json records the last 20 published runs and the observed gap between them. The content date is the only freshness promise; a new item can take several hours to appear.", "Snapshot and source dates describe the last published collection; a run that finds nothing new does not republish."]},
        "coverage": {"kev_records": counts["cisa-kev"], "curated_events": counts["library-curation"], "feed_articles": counts["publisher-feed"],
            "notes": ["This is a selected collection within the declared date window, not every cyber incident, article or vulnerability.", "KEV dates indicate catalog addition, not first disclosure or first exploitation.", "RSS usually exposes recent posts; historical curation and legacy feeds do not form a complete historical archive.", "Unknown dates remain explicit. Failed sources retain last-good input when available; public snapshot resume helps retain prior publisher items.", "Per-feed retained history is bounded to 600 articles. Missing, evicted or changed inputs can leave coverage gaps.", "Publisher intake reports describe only the latest bounded response selection window of at most 150 processed entries. Rejected or unprocessed entries are not newly admitted; unprocessed entries may include recent items, and older retained versions may remain.", "Last accepted input is not exhaustive publisher coverage. Legacy observations without intake reports have unknown window completeness.", "Canonical article URLs are deduplicated; distinct publishers covering one CVE remain separate evidence.", "CVE mentions can come from RSS metadata/body text; they do not mean every mentioned CVE was exploited.", "Headlines link to publishers; full article bodies are not copied. No environment exposure is inferred.", "Threatpost is a legacy archive with observed August 2022 items; a successful fetch does not imply current reporting.", "SEC direct filing access is pending after HTTP 403; news reporting about filings is not complete Item 1.05 or 8.01 coverage."]},
        "integrations": {"xai": {"status": "not_connected", "message": "The collector makes no Grok or xAI calls and runs no model. Report editions come from a separate desktop compiler and name their own tools."},
                         "x": {"status": "not_connected", "message": "The collector reads no X timeline or bookmarks and posts nothing to X. Any future article sharing needs the owner's review."},
                         "sec": {"status": "not_connected", "message": "The collector has no direct SEC filing intake: the filing feed returned HTTP 403. No direct filings are claimed."}}}
    if reports["status"] == "unavailable":
        snapshot["coverage"]["notes"].append("Reports unavailable in this run: " + reports["reason"] + ". Feed collection continued without report listings.")
    snapshot["intelligence"] = intelligence
    snapshot["brief_index"] = brief_index(briefs)
    snapshot["content_revision"] = content_revision(snapshot)
    # Every page file site/files.json lists; publish.yml stamps the same revision into the page.
    snapshot["layout_revision"] = site_layout_revision(ROOT / "site")
    # Refuse before replacing either public output or newly collected caches.
    rows = check_rows(len(snapshot["articles"]), len(snapshot["mitigations"]))
    validate_snapshot(snapshot)
    changed = previous is None or previous.get("content_revision") != snapshot["content_revision"] or previous.get("layout_revision") != snapshot["layout_revision"]
    # Group final wire members for compression; canonical content meaning is unchanged.
    snapshot["mitigations"] = dict(sorted(snapshot["mitigations"].items(), key=lambda item: (
        " ".join(product.get("vendor", "") + " " + product.get("product", "")
                 for product in item[1]["products"]).casefold(), item[0])))
    snapshot["articles"] = wire_articles(snapshot["articles"])
    feed, briefs_file = split_publication(snapshot)
    feed_raw, briefs_raw = public_bytes(feed), public_bytes(briefs_file)
    bounds = check_bounds(feed_raw, briefs_raw)
    # Exports are built (never written) before the index, so the index can list every export file.
    export_files, exported = build_analytics_exports(snapshot["articles"], tagged, sources)
    v7 = build_v7(snapshot, previous, kev.get("catalog"), reports, intelligence_inputs, end, feed_raw, briefs_raw, tagged,
                  exports_index(export_files, exported), patch, service_health=service_health)
    changed = publication_changed(changed, v7["changed_shards"], v7["removed_shards"], v7["exports_changed"], service_health["summary"])
    if refresh:
        write_json(cache_path, cache)
        write_json(cve_path, projections, compact=True)
        if patch["state"] is not None:
            patch_tuesday.save_state(STATE, patch["state"], write_raw)
    # Exports, then v7, then briefs: a reader that sees the new feed can then also read its
    # briefs, and the v7 clean-up keeps exactly the export files the new index lists.
    exported = write_analytics_exports(export_files, exported)
    from .shards import write_v7
    write_v7(ROOT / "site", v7["raw"], v7["index_raw"], write_raw, keep_also=v7["export_paths"])
    write_raw(ROOT / "site/data/briefs.json", briefs_raw)
    write_raw(ROOT / "site/data/feed.json", feed_raw)
    result = {"articles": len(ordered), "source_ok": sum(item["status"] == "ok" for item in health),
        "source_partial": sum(item["status"] == "partial" for item in health), "source_total": len(health),
        "coverage": snapshot["coverage"], "mitigations": mitigation_stats, "reports": reports, "changed": changed, "generated_at": snapshot["generated_at"],
        "schema_version": SNAPSHOT_VERSION, "publication": bounds, "rows": rows, "source_failures": failures[:100],
        "changed_shards": v7["changed_shards"], "removed_shards": v7["removed_shards"], "exports_changed": v7["exports_changed"], "v7": v7["summary"],
        "tagging": tagged["summary"], "exports": exported, "patch_tuesday": v7["patch_tuesday"], "status": service_health["summary"]}
    result_raw = (json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode("utf-8")
    require(len(result_raw) <= RESULT_MAX_BYTES, "The collection result would exceed its " + format(RESULT_MAX_BYTES, ",") + "-byte bound.")
    write_raw(STATE / "collection-result.json", result_raw)
    return result


def tag_snapshot(articles, sources, catalog, briefs, root=None):
    """Tag every row from the controlled vocabularies.

    Returns the rows with their v6 display tags replaced by vocabulary labels and
    folded spellings, the full tagging block per row id, the index entry and a summary.
    A missing or invalid vocabulary never fails the run: rows keep their raw tags
    (publisher rows none), the v7 rows carry no tagging block, and the reason is reported.
    """
    from . import vocab as vocabulary
    from . import tagging
    try:
        loaded = vocabulary.load(root or ROOT)
        context = tagging.build_context(loaded, sources, catalog, briefs)
        blocks = tagging.tag_rows(articles, context)
        fold = tagging.Fold(articles, context)
        rows = []
        for article in articles:
            row = {**article, "tags": tagging.v6_tags(article, blocks[article["id"]], context, fold)}
            validate_article(row)
            rows.append(row)
    except (vocabulary.VocabularyError, ValueError, TypeError, KeyError, AttributeError, OSError) as error:
        reason = (str(error) or type(error).__name__)[:300]
        print("Tagging: vocabulary unavailable (" + reason + "); rows keep their raw tags.", file=sys.stderr)
        rows = [{**article, "tags": tagging.raw_tags(article)} for article in articles]
        index = {"status": "unavailable", "reason": reason, "tagger_version": tagging.TAGGER_VERSION}
        return {"articles": rows, "blocks": {}, "index": index, "vocabulary": None,
                "summary": {"status": "unavailable", "reason": reason}}
    counts = {}
    for block in blocks.values():
        for field, value in block.items():
            if isinstance(value, list):
                counts[field] = counts.get(field, 0) + len(value)
    tagged_rows = {field: sum(1 for block in blocks.values() if block.get(field)) for field in sorted(counts)}
    info = {"tagger_version": tagging.TAGGER_VERSION, "vocab_version": loaded.version,
            "library": {"repo": vocabulary.LIBRARY_REPO, "commit": loaded.library_commit, "attack_release": loaded.attack_release}}
    index = {"status": "ok", **info, "layout": tagging.engine.SHARD_LAYOUT}
    print("Tagging: " + format(len(blocks), ",") + " rows; " + ", ".join(
        field + " " + format(tagged_rows[field], ",") + " rows" for field in sorted(tagged_rows)), file=sys.stderr)
    return {"articles": rows, "blocks": blocks, "index": index, "vocabulary": info, "context": context,
            "summary": {"status": "ok", **info, "rows_with": tagged_rows, "tags": dict(sorted(counts.items()))}}


def build_analytics_exports(articles, tagged, sources):
    """(files, report): the per-year CSV and JSONL exports, built in memory and not written.

    files is None when tagging was unavailable or the build failed (for example a file that
    cannot be kept under the per-file cap); the feed is then published without exports.
    """
    from . import exports
    if not tagged.get("blocks"):
        return None, {"status": "skipped", "reason": "tagging unavailable in this run"}
    try:
        classes = {key: value["source_class"] for key, value in tagged["context"].vocab.hub["source_class"].get("sources", {}).items()}
        files = exports.build_exports(articles, tagged["blocks"], sources, tagged["vocabulary"], classes)
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        reason = (str(error) or type(error).__name__)[:300]
        print("Exports: not built (" + reason + ").", file=sys.stderr)
        return None, {"status": "failed", "reason": reason}
    return files, {"status": "ok"}


def exports_index(files, report):
    """index.json's exports entry when the exports are published, else None (no entry)."""
    from . import exports, shards
    if not exports.EXPORTS_PUBLISHED:
        return None
    return shards.exports_entry(files, None if files else report.get("reason"))


def write_analytics_exports(files, report):
    """Write the built exports (only files whose bytes changed) and return the run report.

    Published exports go to site/data/v7/exports/, which data/v7/index.json lists, so a write
    failure there fails the run like any other public write. Unpublished exports go to
    dist/exports/ and a failure there is only reported.
    """
    from . import exports
    if files is None:
        return report
    directory = ROOT / (exports.PUBLISHED_DIRECTORY if exports.EXPORTS_PUBLISHED else exports.LOCAL_DIRECTORY)
    try:
        written, removed = exports.write_exports(directory, files)
    except (OSError, ValueError) as error:
        if exports.EXPORTS_PUBLISHED:
            raise
        reason = (str(error) or type(error).__name__)[:300]
        print("Exports: not written (" + reason + ").", file=sys.stderr)
        return {"status": "failed", "reason": reason}
    total = sum(len(value) for value in files.values())
    print("Exports: {:,} files, {:,} bytes in {}; {:,} rewritten, {:,} removed".format(
        len(files), total, directory.relative_to(ROOT).as_posix(), len(written), len(removed)), file=sys.stderr)
    return {"status": "ok", "published": exports.EXPORTS_PUBLISHED, "directory": directory.relative_to(ROOT).as_posix(),
            "files": len(files), "bytes": total, "written": len(written), "removed": len(removed)}


def tag_history(snapshot, tagged, catalog):
    """The committed history-adapter rows as tagged v7 rows, and a summary. Never blocks the feed.

    Rows come from history/ in the repository (the publish run fetches no history source).
    They are tagged by the same engine as every other row, with the adapters' own source
    entries; when tagging is unavailable in this run they keep no tagging block.
    """
    from .history import publish as history_publish, registry
    from . import tagging
    from .tagging.engine import compact
    # Each URL a feed, KEV or curated row already holds, with that row's source (the first one wins).
    existing = {}
    for article in snapshot["articles"]:
        existing.setdefault(article["url"], article.get("source_id") or "unknown")
    rows, summary = history_publish.articles(ROOT, existing)
    context = (tagged or {}).get("context")
    if rows and context is not None:
        try:
            history_context = tagging.build_context(context.vocab, registry(), catalog, snapshot["mitigations"])
            blocks = tagging.tag_rows(rows, history_context)
            rows = [{**row, "tagging": compact(blocks[row["id"]])} for row in rows]
            summary["tagging"] = "ok"
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            summary["tagging"] = "unavailable: " + (str(error) or type(error).__name__)[:200]
    elif rows:
        summary["tagging"] = "unavailable in this run"
    print("History: " + summary["status"] + ", " + format(len(rows), ",") + " adapter rows" +
          (" (" + summary["reason"] + ")" if summary.get("reason") else ""), file=sys.stderr)
    return rows, summary


def collect_status(refresh, previous, end):
    """This run's service-health files, untagged Explorer rows and summary (intelligence_hub/status.py).

    Incident history is folded into the month files of the previous publication: the deployed
    one on a --resume-public run, otherwise the files a previous local build left in site/.
    A run that resumed from data/feed.json reads the deployed v7 index once more for its status
    entries; when that read fails, the step holds the run (status.deployed_index).
    """
    from . import shards, status
    deployed = previous is not None
    if previous is None:
        index = shards.local_index(ROOT / "site")
    elif "v7_index" in previous:
        index = previous["v7_index"]
    else:
        try:
            index = status.deployed_index(fetch)
        except status.StatusHold as error:
            return status.held(str(error))
    return status.collect_status(ROOT, refresh=refresh, previous_index=index, deployed=deployed, end=end, fetch=fetch, state=STATE)


def status_shards(service_health, tagged, catalog, briefs):
    """(status files, tagged Explorer rows). Rows keep no tagging block when tagging is unavailable."""
    from . import status
    service_health = service_health or {}
    files, rows = service_health.get("files") or {}, service_health.get("rows") or []
    context = (tagged or {}).get("context")
    if rows and context is not None:
        try:
            rows = status.tag_rows(rows, service_health["registry"], context, catalog, briefs)
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            print("Status: incident rows untagged (" + (str(error) or type(error).__name__)[:200] + ").", file=sys.stderr)
    if files:
        print("Status: {:,} sources, {:,} incidents in {:,} month files, {:,} Explorer rows".format(
            service_health["summary"]["sources"], service_health["summary"]["incidents"], service_health["summary"]["months"], len(rows)), file=sys.stderr)
    return files, rows


def fit_status_rows(articles, status_rows, end, limit=None):
    """(status rows kept, how many were held back) so no live month shard passes its byte bound.

    fit_month bounds each status month file, but the Explorer rows built from it share the
    live/YYYY-MM.json article shard with the month's publisher rows, and a shard over the bound
    would fail shards.serialize and hold the whole feed. In a month whose shard would pass the
    bound, the oldest status rows are held back until it fits; publisher, KEV and curated rows are
    never dropped here. Done before build_shards, so recent.json never names a held-back row.
    """
    from . import shards
    limit = shards.SHARD_MAX_BYTES if limit is None else limit
    if not status_rows:
        return status_rows, 0
    live_from = shards.live_start(end)
    groups = {}
    for article in list(articles) + list(status_rows):
        groups.setdefault(shards.article_path(article, live_from), []).append(article)
    owned = {id(row) for row in status_rows}
    held = set()
    for path in sorted(groups):
        items = groups[path]
        mine = sorted((row for row in items if id(row) in owned), key=shards.row_order)
        if not mine:
            continue
        period = path.split("/", 1)[1][:-5]
        excess = len(shards.canonical(shards.article_shard(period, sorted(items, key=shards.row_order)))) - limit
        # A row costs its canonical bytes less the newline, plus the comma that joins it: the same count.
        dropped = 0
        while excess > 0 and dropped < len(mine):
            excess -= len(shards.canonical(mine[dropped]))
            dropped += 1
        while 0 < dropped < len(mine):
            gone = {id(row) for row in mine[:dropped]}
            kept = sorted((row for row in items if id(row) not in gone), key=shards.row_order)
            if len(shards.canonical(shards.article_shard(period, kept))) <= limit:
                break
            dropped += 1
        held.update(id(row) for row in mine[:dropped])
    if not held:
        return status_rows, 0
    return [row for row in status_rows if id(row) not in held], len(held)


def collect_patch_tuesday(registry, refresh, previous, limit):
    """The Patch Tuesday state for this run: {"state", "report", "config", "reason"}. Never raises.

    A live run reads the MSRC updates list and the documents the plan names; a --cached build
    reads the same files from .state/patch-tuesday-documents/ when they are there. Either way
    the months already built come from .state/patch-tuesday.json, and a resumed run also
    takes the months that cache lacks from the deployed briefs.
    """
    from . import patch_tuesday
    try:
        config = patch_tuesday.load_config(registry, safe_url)
        reader = patch_tuesday.Reader(fetch=fetch) if refresh else patch_tuesday.Reader(offline=STATE / patch_tuesday.DOCUMENTS_NAME)
        index = previous.get("v7_index") if previous is not None else None

        def deployed(entry):
            from .shards import SHARD_MAX_BYTES
            return fetch(PUBLIC_V7 + entry["path"], SHARD_MAX_BYTES, fresh=True)

        state, report = patch_tuesday.collect(STATE, config, reader, limit=limit, previous_index=index,
                                              deployed_read=deployed if index is not None else None, safe_url=safe_url)
        print("Patch Tuesday: {:,} release documents read, {:,} failed, {:,} months resumed from the deployed briefs, {:,} pending".format(
            report["documents_read"], len(report["failed"]), report["resumed"], len(report["pending"])), file=sys.stderr)
        return {"state": state, "report": report, "config": config, "reason": None}
    except (ValueError, OSError, TypeError, KeyError, AttributeError) as error:
        reason = (str(error) or type(error).__name__)[:300]
        print("Patch Tuesday: not collected (" + reason + ").", file=sys.stderr)
        return {"state": None, "report": {}, "config": None, "reason": reason}


def build_patch_tuesday(patch, catalog, briefs, tagged):
    """The Patch Tuesday shards ({} when the step was unavailable) and the run summary."""
    from . import patch_tuesday, shards
    if not patch or patch.get("state") is None:
        return {}, {"status": "unavailable", "reason": (patch or {}).get("reason") or "not collected in this run"}
    context = None
    if (tagged or {}).get("context") is not None:
        from .history import registry as history_registry
        from . import tagging
        try:
            context = tagging.build_context(tagged["context"].vocab, history_registry(), catalog, briefs)
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            print("Patch Tuesday: tags unavailable (" + (str(error) or type(error).__name__)[:200] + ").", file=sys.stderr)
    try:
        files = patch_tuesday.build(patch["state"], catalog, briefs, tagging_context=context, limit=shards.SHARD_MAX_BYTES,
                                    config=patch["config"])
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        reason = (str(error) or type(error).__name__)[:300]
        print("Patch Tuesday: briefs not built (" + reason + ").", file=sys.stderr)
        return {}, {"status": "unavailable", "reason": reason}
    patch_tuesday.print_headroom(files, shards.SHARD_MAX_BYTES)
    return files, {"status": "ok", **patch_tuesday.summary(files, patch["report"])}


def build_v7(snapshot, previous, catalog, reports, inputs, end, feed_raw, briefs_raw, tagged=None, exports_entry=None, patch=None, service_health=None):
    """The schema 7 shards and index for this run, compared with the previous index. Nothing is written here."""
    from . import shards
    from .tagging.engine import compact
    catalog_value, catalog_sha, _reason = inputs[2]
    from .history import base as history_base, publish as history_publish
    blocks = (tagged or {}).get("blocks", {})
    rows = [{**article, "tagging": compact(blocks[article["id"]])} if article["id"] in blocks else article for article in snapshot["articles"]]
    history_rows, history_summary = tag_history(snapshot, tagged, catalog)
    patch_files, patch_summary = build_patch_tuesday(patch, catalog, snapshot["mitigations"], tagged)
    health_files, health_rows = status_shards(service_health, tagged, catalog, snapshot["mitigations"])
    health_rows, health_held = fit_status_rows(rows + history_rows, health_rows, end)
    if isinstance((service_health or {}).get("summary"), dict):
        service_health["summary"]["explorer_rows_held"] = health_held
    if health_held:
        print("Status: " + format(health_held, ",") + " Explorer incident rows held back to keep their live month shards inside the shard bound",
              file=sys.stderr)
    files = shards.build_shards(rows + history_rows + health_rows, snapshot["sources"], catalog, snapshot["mitigations"],
                                shards.reports_file(reports, catalog_value, catalog_sha), end,
                                coverage=history_publish.coverage_file(ROOT, shards.SCHEMA_VERSION), extra=patch_files)
    # Adapter rows never push a year's history shard past its byte bound; any held back are named.
    held = history_publish.fit(files, shards.SHARD_MAX_BYTES, shards.canonical)
    if files["coverage.json"].get("status") == "ok":
        files["coverage.json"]["held_back"] = held
        # Each statement also says how many rows another source's row took, how many the source's own
        # feed or KEV row already holds, and how many the shards show.
        # A statement that cannot agree with the shards is replaced by the stub; the feed carries on.
        try:
            history_publish.annotate_coverage(files["coverage.json"], history_summary.get("given_up", []), held,
                                              published=history_summary["status"] == "ok",
                                              in_feed=history_summary.get("in_feed", []))
        except (history_base.HistoryError, KeyError, TypeError, ValueError) as error:
            reason = (str(error) or type(error).__name__)[:300]
            files["coverage.json"] = history_publish.stub(shards.SCHEMA_VERSION, reason)
            history_summary["coverage"] = "stub: " + reason
            print("History: coverage published as the stub (" + reason + ")", file=sys.stderr)
    if held:
        history_summary["held_back"] = held
        print("History: " + format(sum(item["rows"] for item in held), ",") + " adapter rows held back to keep " +
              ", ".join(sorted({item["path"] for item in held})) + " inside the shard bound", file=sys.stderr)
    for path, value in health_files.items():
        require(shards.SHARD_PATH.fullmatch(path) and path not in files, "Unexpected service-health shard " + path + ".")
        files[path] = value
    raw, entries = shards.serialize(files)
    # Every shard's size against the per-file cap, and each history file's against its split threshold.
    for path in sorted(raw):
        print(shards.headroom_line(path, len(raw[path])), file=sys.stderr)
    previous_index = previous.get("v7_index") if previous is not None else shards.local_index(ROOT / "site")
    changed_shards, removed_shards = shards.compare(previous_index, entries)
    # A first v7 run knows the previous publication only from the v6 feed's generation time.
    seed = previous.get("generated_at") if previous is not None and previous_index is None else None
    runs = shards.run_chain(previous_index["runs"] if previous_index else [], snapshot["generated_at"], shards.run_trigger(), seed)
    articles = snapshot["articles"]
    version = (catalog or {}).get("catalogVersion")
    counts = {"articles": len(articles),
              "live_rows": sum(entry["rows"] for entry in entries if entry["path"].startswith("live/")),
              "history_rows": sum(entry["rows"] for entry in entries if entry["path"].startswith("history/")),
              "curated_rows": sum(article["origin"] == "library-curation" for article in articles),
              "history_adapter_rows": len(history_rows) - sum(item["rows"] for item in held),
              "kev": sum(entry["rows"] for entry in entries if entry["path"].startswith("kev/")),
              "kev_catalog_version": version if isinstance(version, str) and len(version) <= 40 else None,
              "cves": len(snapshot["mitigations"]), "sources": len(snapshot["sources"]), "shards": len(entries),
              "patch_tuesday_months": sum(1 for entry in entries if shards.PATCH_TUESDAY_MONTH.fullmatch(entry["path"])),
              "status_sources": (service_health or {}).get("summary", {}).get("sources", 0),
              "status_incidents": (service_health or {}).get("summary", {}).get("incidents", 0), "status_rows": len(health_rows)}
    index = shards.build_index(entries, generated_at=snapshot["generated_at"], end=end, feed_content_revision=snapshot["content_revision"],
                               layout_revision=snapshot["layout_revision"], runs=runs, counts=counts,
                               v6_files=[shards.file_entry("data/feed.json", feed_raw), shards.file_entry("data/briefs.json", briefs_raw)],
                               tagging=(tagged or {}).get("index"), exports=exports_entry)
    index_raw = shards.canonical(index)
    shards.read_index(index_raw)
    total = sum(len(item) for item in raw.values()) + len(index_raw)
    print("data/v7: {:,} shards, {:,} bytes; {:,} changed and {:,} removed since the previous index".format(
        len(entries), total, len(changed_shards), len(removed_shards)), file=sys.stderr)
    summary = {"shards": len(entries), "bytes": total, "content_revision": index["content_revision"],
               "observed_interval_hours": index["observed_interval_hours"], "runs_recorded": len(runs), "history": history_summary}
    export_paths = [item["path"] for item in (exports_entry or {}).get("files", [])]
    return {"raw": raw, "index_raw": index_raw, "index": index, "changed_shards": changed_shards,
            "removed_shards": removed_shards, "summary": summary, "export_paths": export_paths, "patch_tuesday": patch_summary,
            "exports_changed": shards.exports_changed(previous_index, exports_entry)}


def content_revision(snapshot):
    # Retrieval clocks alone do not create a new public artifact or reset source freshness.
    # brief_index is derived from mitigations, so it adds nothing to the revision.
    value = {key: item for key, item in snapshot.items() if key not in {"generated_at", "content_revision", "layout_revision", "brief_index"}}
    source_values = []
    for source in snapshot["sources"]:
        item = {key: value for key, value in source.items() if key not in {"last_attempt", "last_success", "sha256"}}
        if source.get("intake") is not None:
            item["intake"] = {key: value for key, value in source["intake"].items() if key not in {"attempted_at", "response_sha256"}}
        source_values.append(item)
    value["sources"] = source_values
    value["mitigations"] = {cve: {key: item for key, item in record.items() if key not in {"retrieved_at", "source_attempted_at"}} for cve, record in snapshot["mitigations"].items()}
    value["mitigation_coverage"] = {key: item for key, item in snapshot["mitigation_coverage"].items() if key != "attempted_this_run"}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def deployed_v7():
    """Resume from data/v7/index.json: the article and source shards it lists, plus data/briefs.json.

    Every file is checked against the index's byte count and sha256, so files from two
    different deploys are refused. data/feed.json is not read on this path.
    """
    from . import shards
    from .mitigations import BRIEFS_KEYS
    index = shards.read_index(fetch(PUBLIC_V7 + "index.json", shards.INDEX_MAX_BYTES, fresh=True))
    wanted = [entry for entry in index["shards"] if entry["path"].startswith(("live/", "history/")) or entry["path"] == "sources.json"]

    def read(entry):
        raw = fetch(PUBLIC_V7 + entry["path"], shards.SHARD_MAX_BYTES, fresh=True)
        require(len(raw) == entry["bytes"] and shards.sha256(raw) == entry["sha256"], V7_MISMATCH)
        return entry["path"], json.loads(raw, parse_constant=reject_constant)

    with ThreadPoolExecutor(max_workers=4) as pool:
        files = dict(pool.map(read, wanted))
    briefs_entry = next(item for item in index["v6_files"] if item["path"] == "data/briefs.json")
    require(briefs_entry["bytes"] <= BRIEFS_MAX_BYTES, "The deployed briefs file exceeds its byte bound.")
    briefs_raw = fetch(PUBLIC_BRIEFS, BRIEFS_MAX_BYTES, fresh=True, ceiling=DEPLOYED_BRIEFS_CEILING)
    require(len(briefs_raw) == briefs_entry["bytes"] and shards.sha256(briefs_raw) == briefs_entry["sha256"], V7_MISMATCH)
    briefs = json.loads(briefs_raw, parse_constant=reject_constant)
    require(isinstance(briefs, dict) and set(briefs) == BRIEFS_KEYS and isinstance(briefs["briefs"], dict) and
            briefs["content_revision"] == index["feed_content_revision"], V7_MISMATCH)
    articles = []
    for path in sorted(files):
        if path == "sources.json":
            continue
        value = files[path]
        require(isinstance(value, dict) and value.get("kind") == "articles" and isinstance(value.get("rows"), list), "Invalid deployed v7 article shard.")
        # Tags are derived again on every run; the deployed tagging block is never an input.
        # History-adapter rows are read from the repository on every run, never resumed; service-health
        # rows are rebuilt on every run from the status month files (intelligence_hub/status.py).
        articles.extend({key: item for key, item in row.items() if key != "tagging"} if isinstance(row, dict) else row
                        for row in value["rows"] if not (isinstance(row, dict) and (str(row.get("origin", "")).startswith("history:") or
                                                                                     row.get("origin") == "service-status")))
    sources = files.get("sources.json")
    require(isinstance(sources, dict) and sources.get("kind") == "sources" and isinstance(sources.get("rows"), list), "Invalid deployed v7 source ledger.")
    return {"schema_version": 7, "generated_at": index["generated_at"], "articles": articles, "sources": sources["rows"],
            "mitigations": briefs["briefs"], "content_revision": index["feed_content_revision"],
            "layout_revision": index["layout_revision"], "v7_index": index}


def deployed_files():
    """Resume from the v7 index when it is deployed; otherwise from the feed and its briefs file.

    Both are fetched with no-cache headers. If the CDN still hands back files from two
    different runs (a deploy landed between the two reads), both are fetched once more.
    """
    from .mitigations import SNAPSHOT_MISMATCH, join_publication
    for attempt in (1, 2):
        try:
            return deployed_v7()
        except (OSError, ValueError, TypeError, KeyError, StopIteration, RecursionError) as error:
            if attempt == 1 and str(error) == V7_MISMATCH:
                print("Resume: a v7 shard came from a different deploy; reading the index once more.", file=sys.stderr)
                continue
            print("Resume: data/v7/index.json was not used (" + failure_reason(error, "v7 index unavailable or rejected") +
                  "); reading data/feed.json.", file=sys.stderr)
            break
    for attempt in (1, 2):
        raw = fetch(PUBLIC_FEED, FETCH_CEILING, fresh=True)
        previous = json.loads(raw, parse_constant=reject_constant)
        require(isinstance(previous, dict) and type(previous.get("schema_version")) is int and previous["schema_version"] in (1, 2, 3, 4, 5, 6, 7), "Unsupported deployed snapshot.")
        if previous["schema_version"] != 7:
            return previous
        require(len(raw) <= FEED_MAX_BYTES, "The deployed feed exceeds its byte bound.")
        briefs_raw = fetch(PUBLIC_BRIEFS, BRIEFS_MAX_BYTES, fresh=True, ceiling=DEPLOYED_BRIEFS_CEILING)
        require(len(briefs_raw) <= BRIEFS_MAX_BYTES, "The deployed briefs file exceeds its byte bound.")
        try:
            return join_publication(previous, json.loads(briefs_raw, parse_constant=reject_constant))
        except ValueError as error:
            if attempt == 2 or str(error) != SNAPSHOT_MISMATCH:
                raise
            print("Resume: the deployed feed and briefs came from different runs; fetching both once more.", file=sys.stderr)


def resume_deployed(sources, cache):
    """Use only this hub's fixed public snapshot as an additional, validated history input.

    Returns (snapshot, None), or (None, reason) when the deployed files cannot be used.
    A schema 7 snapshot is two files; both must load and belong to the same run.
    """
    try:
        previous = deployed_files()
        if "v7_index" in previous:
            # Shards were checked against the index; every row and observation is validated
            # below, and every brief passes valid_projection before it is merged.
            require(isinstance(previous["articles"], list) and len(previous["articles"]) <= MAX_FEED_ROWS and
                    len(previous["mitigations"]) <= MAX_CVE_BRIEFS, "Invalid deployed v7 row counts.")
        elif previous["schema_version"] in (5, 6, 7):
            from .archive import validate_snapshot
            validate_snapshot(previous)
        else:
            require("intelligence" not in previous, "Legacy snapshot cannot carry schema5 context.")
            require(isinstance(previous.get("mitigations", {}), dict) and all(isinstance(brief, dict) and
                    not {"weaknesses", "weaknesses_status"} & set(brief) for brief in previous.get("mitigations", {}).values()),
                    "Legacy snapshot cannot carry schema5 CNA fields.")
            window = previous.get("window", {})
            require(isinstance(window, dict) and set(window) == {"start", "end"}, "Missing legacy coverage window.")
            begin, finish = (date.fromisoformat(window[key]) for key in ("start", "end"))
            validate_window(begin, finish, previous["schema_version"])
        require(isinstance(previous.get("articles"), list) and (previous["schema_version"] == 7 or len(previous["articles"]) <= LEGACY_MAX_ARTICLES), "Invalid deployed articles.")
        require(isinstance(previous.get("sources"), list) and len(previous["sources"]) <= 100, "Invalid deployed source ledger.")
        registry = {source["id"]: source for source in sources}
        retained = {}
        for article in previous["articles"]:
            validate_article(article)
            source = registry.get(article["source_id"])
            if article["origin"] == "publisher-feed" and source and article["source_name"] == source["name"] and article["kind"] == source["kind"] and safe_url(article["url"], source["article_hosts"]):
                # Publisher rows have no tags of their own; published tags are derived, so they are derived again.
                retained.setdefault(source["id"], {})[article["url"]] = {**article, "tags": []}
        proposed = {"sources": dict(cache["sources"]), "kev": cache["kev"]}
        observations = {}
        for observation in previous["sources"]:
            require(isinstance(observation, dict) and isinstance(observation.get("id"), str), "Invalid deployed source identity.")
            source_id = observation["id"]
            require(source_id not in observations, "Duplicate deployed source identity.")
            if previous["schema_version"] in (4, 5, 6, 7):
                require("configured_selection" in observation, "Missing deployed selection configuration.")
                configured = observation["configured_selection"]
                if source_id == "cisa-kev":
                    require(configured is None, "KEV cannot carry RSS selection configuration.")
                else:
                    require(type(configured) is str and configured in {"document-order-v1", "publisher-date-desc-v1"}, "Invalid deployed selection configuration.")
                    if configured == "publisher-date-desc-v1":
                        require(source_id in registry, "Publisher-date configuration requires a known F5 source.")
                        source_selection({**registry[source_id], "entry_selection": configured})
            else:
                require("configured_selection" not in observation, "Legacy deployed sources cannot carry selection configuration.")
            projected = {key: observation.get(key) for key in ("status", "last_attempt", "last_success", "error", "sha256", "intake")}
            # The initial schema did not publish response hashes; preserve dates without inventing a hash.
            if projected["status"] == "ok" and projected["sha256"] is None and previous["schema_version"] == 1:
                projected["status"] = "not_fetched"
            validate_observation(projected, source=registry.get(source_id), kev=source_id == "cisa-kev", allow_selection=previous["schema_version"] in (4, 5, 6, 7))
            observations[source_id] = projected
        for source_id, articles in retained.items():
            old = cache["sources"].get(source_id, {})
            remote = observations.get(source_id, {})
            def observed_at(observation):
                return published(observation.get("last_attempt") or "") or ""
            observation = remote if observed_at(remote) > observed_at(old) else old
            combined = {**articles, **{article["url"]: article for article in old.get("articles", [])}}
            proposed["sources"][source_id] = {**observation, "articles": sorted(combined.values(), key=article_date, reverse=True)[:600]}
        validate_cache(proposed, sources)
        cache.update(proposed)
        return previous, None
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        return None, failure_reason(error, "deployed snapshot unavailable or rejected")
