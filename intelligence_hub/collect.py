"""Bounded public-feed collection. No article bodies, account access or model calls."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import html
import ipaddress
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ROOT = Path(__file__).absolute().parent.parent
STATE = ROOT / ".state"
CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_BYTES = 3 * 1024 * 1024
MAX_ARTICLES = 8000
KINDS = {"advisory", "research", "reporting", "incident", "kev", "filing"}
CVE = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,8}\b", re.I)
PUBLIC_FEED = "https://teamstarwolf.github.io/intelligence-hub/data/feed.json"
RESPONSE_BYTE_LIMIT_REASON = "response_byte_limit_exceeded: source response exceeded its configured byte bound."


def require(value, message):
    if not value:
        raise ValueError(message)


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


def fetch(url, maximum=MAX_BYTES):
    require(safe_url(url) == url, "Source URL must be a canonical public HTTPS URL.")
    require(type(maximum) is int and 1 <= maximum <= 16 * 1024 * 1024, "Invalid bounded read size.")
    started = time.monotonic()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "TeamStarWolf-IntelligenceHub/0.1 (public feed reader)", "Accept": "application/rss+xml, application/atom+xml, application/json, text/xml, application/xml", "Accept-Encoding": "identity"})
    chunks, size = [], 0
    with opener.open(request, timeout=12) as response:
        require(response.status == 200 and response.geturl() == url, "Unexpected publisher response.")
        require(response.headers.get("Content-Encoding", "identity").lower() == "identity", "Compressed responses are not accepted.")
        while True:
            require(time.monotonic() - started < 30, "Source exceeded its read deadline.")
            block = response.read(65536)
            if not block:
                break
            size += len(block)
            if size > maximum:
                raise ResponseByteLimitExceeded("Source exceeded its bounded read limit.")
            chunks.append(block)
    return b"".join(chunks)


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
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=False, allow_nan=False, indent=None if compact else 2, separators=(",", ":") if compact else None) + "\n").encode("utf-8")
    require(len(raw) <= 16 * 1024 * 1024, "Snapshot output exceeds its limit.")
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("xb") as stream:
        stream.write(raw)
    temporary.replace(path)


def text(value, maximum=240):
    # Markup is stripped to text, never interpreted by the browser.
    return " ".join(html.unescape(re.sub(r"<[^>]{0,2000}>", " ", value or "")).split())[:maximum]


def published(value):
    try:
        value = value.strip()
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
            return date.fromisoformat(value).isoformat()
        try:
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            stamp = parsedate_to_datetime(value)
        if stamp.tzinfo is None:
            return None
        return stamp.astimezone(timezone.utc).isoformat(timespec="seconds")
    except (ValueError, TypeError, AttributeError, OverflowError):
        return None


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
        stamp = published(fields.get("pubDate") or fields.get("published") or fields.get("date") or fields.get("updated") or "")
        basis = "publication" if (fields.get("pubDate") or fields.get("published") or fields.get("date")) else "publisher update" if fields.get("updated") else "unknown"
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
        raw = fetch(source["url"])
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
        if isinstance(error, ResponseByteLimitExceeded):
            reason = RESPONSE_BYTE_LIMIT_REASON
        else:
            reason = ("HTTP " + str(error.code)) if isinstance(error, urllib.error.HTTPError) else type(error).__name__ + ": source unavailable or rejected by intake policy"
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
        if isinstance(error, ResponseByteLimitExceeded):
            reason = RESPONSE_BYTE_LIMIT_REASON
        else:
            reason = ("HTTP " + str(error.code)) if isinstance(error, urllib.error.HTTPError) else type(error).__name__ + ": catalog unavailable or rejected"
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
        source_selection(source)
    return registry["sources"]


def build_snapshot(start, end, refresh=True, resume_public=False, enrich_limit=40):
    from .mitigations import build_briefs, merge_retained
    from .intelligence import compose, load_inputs
    from .archive import validate_snapshot

    require(type(start) is date and type(end) is date and start <= end and (end - start).days <= 7306, "History window must be date-only and at most twenty years.")
    intelligence_inputs = load_inputs(ROOT)
    require(type(enrich_limit) is int and 0 <= enrich_limit <= 2000, "CVE enrichment limit must be0..2000.")
    context = load_mitigation_context(ROOT / "config/mitigation-context.json")
    sources = validate_registry(read_json(ROOT / "config/sources.json", 128 * 1024))
    cache_path = STATE / "public-cache.json"
    cache = read_json(cache_path) if cache_path.exists() else {"sources": {}, "kev": {}}
    validate_cache(cache, sources)
    previous = resume_deployed(sources, cache) if resume_public else None
    require(not resume_public or previous is not None, "The deployed snapshot could not be resumed safely; preserving the current publication.")
    cve_path = STATE / "cve-projections.json"
    retained = read_json(cve_path) if cve_path.exists() else {}
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
    require(len(selected) <= MAX_ARTICLES, "Article collection exceeds its limit.")
    ordered = sorted(selected.values(), key=article_date, reverse=True)
    require(ordered, "No articles are available in the selected window; preserving the previous deployment.")
    require(len({article["id"] for article in ordered}) == len(ordered), "Article identities must be unique.")
    counts = {origin: sum(article["origin"] == origin for article in ordered) for origin in ("cisa-kev", "library-curation", "publisher-feed")}
    prepared_at = now()
    briefs, projections, mitigation_stats = build_briefs(ordered, kev.get("catalog", {}), retained, refresh, enrich_limit, fetch, text, safe_url, published, prepared_at)
    briefs = apply_mitigation_context(briefs, context)
    snapshot = {"schema_version": 5, "generated_at": now(), "window": {"start": start.isoformat(), "end": end.isoformat()},
        "articles": ordered, "sources": health, "history_reviewed_at": history.get("curated_at"),
        "mitigations": briefs, "mitigation_coverage": mitigation_stats, "deduplication": {"url_duplicates_removed": duplicates},
        "refresh": {"requested_minutes": 10, "mode": "scheduled-check", "status_url": "https://github.com/TeamStarWolf/intelligence-hub/actions/workflows/publish.yml",
            "notes": ["GitHub requests collection every ten minutes; scheduling can be delayed, dropped or disabled after repository inactivity.", "The visible page checks the saved snapshot every ten minutes. This is not a guaranteed ten-minute news delivery service.", "Snapshot and source dates describe the last published collection; unchanged checks can complete without republishing. Latest workflow outcomes are linked separately."]},
        "coverage": {"kev_records": counts["cisa-kev"], "curated_events": counts["library-curation"], "feed_articles": counts["publisher-feed"],
            "notes": ["This is a selected twenty-year collection, not every cyber incident, article or vulnerability.", "KEV dates indicate catalog addition, not first disclosure or first exploitation.", "RSS usually exposes recent posts; historical curation and legacy feeds do not form a complete twenty-year archive.", "Unknown dates remain explicit. Failed sources retain last-good input when available; public snapshot resume helps retain prior publisher items.", "Per-feed retained history is bounded to600articles. Missing, evicted or changed inputs can leave coverage gaps.", "Publisher intake reports describe only the latest bounded response selection window of at most150processed entries. Rejected or unprocessed entries are not newly admitted; unprocessed entries may include recent items, and older retained versions may remain.", "Last accepted input is not exhaustive publisher coverage. Legacy observations without intake reports have unknown window completeness.", "Canonical article URLs are deduplicated; distinct publishers covering one CVE remain separate evidence.", "CVE mentions can come from RSS metadata/body text; they do not mean every mentioned CVE was exploited.", "Headlines link to publishers; full article bodies are not copied. No environment exposure is inferred.", "Threatpost is a legacy archive with observed August2022 items; a successful fetch does not imply current reporting.", "SEC direct filing access is pending after HTTP403; news reporting about filings is not complete Item1.05/8.01 coverage."]},
        "integrations": {"xai": {"status": "not_connected", "message": "Grok X Search is a separate supported API route; access and zero-additional-spend eligibility are not established. No model calls are enabled."},
                         "x": {"status": "not_connected", "message": "Personal X timeline/bookmarks are not connected or published. Future article sharing is recorded for owner review; no automatic posts are enabled."},
                         "sec": {"status": "not_connected", "message": "Direct SEC filing-feed intake returned HTTP403. Operational contact and accepted access/schema remain prerequisites; no direct filings are claimed."}}}
    snapshot["intelligence"] = compose(ROOT, briefs, safe_url, inputs=intelligence_inputs)
    snapshot["content_revision"] = content_revision(snapshot)
    snapshot["layout_revision"] = hashlib.sha256(b"".join((ROOT / "site" / name).read_bytes() for name in ("index.html", "styles.css", "app.js", "icon.svg"))).hexdigest()
    # Refuse before replacing either public output or newly collected caches.
    validate_snapshot(snapshot)
    require(len(json.dumps(snapshot, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")) <= 16 * 1024 * 1024,
            "Snapshot exceeds its existing whole-input byte bound.")
    changed = previous is None or previous.get("content_revision") != snapshot["content_revision"] or previous.get("layout_revision") != snapshot["layout_revision"]
    if refresh:
        write_json(cache_path, cache)
        write_json(cve_path, projections, compact=True)
    # Group final wire members for compression; canonical content meaning is unchanged.
    snapshot["mitigations"] = dict(sorted(snapshot["mitigations"].items(), key=lambda item: (
        " ".join(product.get("vendor", "") + " " + product.get("product", "")
                 for product in item[1]["products"]).casefold(), item[0])))
    write_json(ROOT / "site/data/feed.json", snapshot, compact=True)
    result = {"articles": len(ordered), "source_ok": sum(item["status"] == "ok" for item in health),
        "source_partial": sum(item["status"] == "partial" for item in health), "source_total": len(health),
        "coverage": snapshot["coverage"], "mitigations": mitigation_stats, "changed": changed, "generated_at": snapshot["generated_at"]}
    write_json(STATE / "collection-result.json", result)
    return result


def content_revision(snapshot):
    # Retrieval clocks alone do not create a new public artifact or reset source freshness.
    value = {key: item for key, item in snapshot.items() if key not in {"generated_at", "content_revision", "layout_revision"}}
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


def resume_deployed(sources, cache):
    """Use only this hub's fixed public snapshot as an additional, validated history input."""
    try:
        previous = json.loads(fetch(PUBLIC_FEED, 16 * 1024 * 1024), parse_constant=reject_constant)
        require(isinstance(previous, dict) and type(previous.get("schema_version")) is int and previous["schema_version"] in (1, 2, 3, 4, 5), "Unsupported deployed snapshot.")
        if previous["schema_version"] == 5:
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
            require(begin <= finish and (finish - begin).days <= 3661, "Legacy coverage exceeds its date profile.")
        require(isinstance(previous.get("articles"), list) and len(previous["articles"]) <= MAX_ARTICLES, "Invalid deployed articles.")
        require(isinstance(previous.get("sources"), list) and len(previous["sources"]) <= 100, "Invalid deployed source ledger.")
        registry = {source["id"]: source for source in sources}
        retained = {}
        for article in previous["articles"]:
            validate_article(article)
            source = registry.get(article["source_id"])
            if article["origin"] == "publisher-feed" and source and article["source_name"] == source["name"] and article["kind"] == source["kind"] and safe_url(article["url"], source["article_hosts"]):
                retained.setdefault(source["id"], {})[article["url"]] = article
        proposed = {"sources": dict(cache["sources"]), "kev": cache["kev"]}
        observations = {}
        for observation in previous["sources"]:
            require(isinstance(observation, dict) and isinstance(observation.get("id"), str), "Invalid deployed source identity.")
            source_id = observation["id"]
            require(source_id not in observations, "Duplicate deployed source identity.")
            if previous["schema_version"] in (4, 5):
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
            validate_observation(projected, source=registry.get(source_id), kev=source_id == "cisa-kev", allow_selection=previous["schema_version"] in (4, 5))
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
        return previous
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        return None
