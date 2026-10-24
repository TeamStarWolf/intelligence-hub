"""Bounded public-feed collection. No article bodies, account access or model calls."""
from concurrent.futures import ThreadPoolExecutor
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
KINDS = {"advisory", "research", "reporting", "incident", "kev"}
CVE = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,8}\b", re.I)


def require(value, message):
    if not value:
        raise ValueError(message)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def safe_url(value, hosts=None):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) <= 32 for c in value) or "\\" in value:
        return None
    try:
        parts = urllib.parse.urlsplit(value)
        host = parts.hostname or ""
        if parts.scheme != "https" or parts.username is not None or parts.password is not None or parts.port not in (None, 443):
            return None
        if not host.isascii() or host.endswith(".") or not re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", host) or host.endswith((".local", ".localhost", ".internal", ".test", ".invalid")):
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


def fetch(url):
    require(safe_url(url) == url, "Source URL must be a canonical public HTTPS URL.")
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
            require(size <= MAX_BYTES, "Source exceeded the three-MiB read limit.")
            chunks.append(block)
    return b"".join(chunks)


def read_json(path, limit=16 * 1024 * 1024):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "Local JSON input exceeds its limit.")
    return json.loads(raw)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
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


def parse_feed(raw, source):
    decoded = raw.decode("utf-8-sig")
    require("\x00" not in decoded and "<!DOCTYPE" not in decoded.upper() and "<!ENTITY" not in decoded.upper(), "DTD/entity/binary XML is not accepted.")
    root = ET.fromstring(decoded)
    stack, count = [(root, 0)], 0
    while stack:
        element, depth = stack.pop()
        count += 1
        require(count <= 40000 and depth <= 48, "XML structure exceeds its bounds.")
        stack.extend((child, depth + 1) for child in element)
    require(root.tag.rsplit("}", 1)[-1].lower() in {"rss", "feed", "rdf"}, "Response is not RSS or Atom.")
    articles = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] not in {"item", "entry"}:
            continue
        if len(articles) >= 150:
            break
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
            continue
        stamp = published(fields.get("pubDate") or fields.get("published") or fields.get("date") or fields.get("updated") or "")
        basis = "publication" if (fields.get("pubDate") or fields.get("published") or fields.get("date")) else "publisher update" if fields.get("updated") else "unknown"
        articles.append({"id": "feed-" + hashlib.sha256(url.encode()).hexdigest()[:20], "title": title, "url": url,
            "source_id": source["id"], "source_name": source["name"], "kind": source["kind"], "published_at": stamp,
            "event_date": None, "date_basis": basis, "summary": "", "cves": sorted(set(CVE.findall(title.upper()))),
            "tags": [], "exploitation": "unknown", "references": [], "origin": "publisher-feed"})
    require(articles, "No safe article links were available in the publisher feed.")
    return articles


def update_source(source, cached):
    attempted = now()
    try:
        raw = fetch(source["url"])
        incoming = parse_feed(raw, source)
        combined = {article["url"]: article for article in cached.get("articles", [])}
        combined.update({article["url"]: article for article in incoming})
        articles = sorted(combined.values(), key=lambda article: article.get("published_at") or "", reverse=True)[:600]
        return {"status": "ok", "last_attempt": attempted, "last_success": now(), "error": None,
                "sha256": hashlib.sha256(raw).hexdigest(), "articles": articles}
    except (OSError, ValueError, ET.ParseError) as error:
        reason = ("HTTP " + str(error.code)) if isinstance(error, urllib.error.HTTPError) else type(error).__name__ + ": source unavailable or rejected by intake policy"
        return {**cached, "status": "failed", "last_attempt": attempted, "last_success": cached.get("last_success"), "error": reason, "articles": cached.get("articles", [])}


def update_kev(cached):
    attempted = now()
    try:
        raw = fetch(CATALOG_URL)
        catalog = json.loads(raw)
        validate_catalog(catalog)
        return {"status": "ok", "last_attempt": attempted, "last_success": now(), "error": None,
                "sha256": hashlib.sha256(raw).hexdigest(), "catalog": catalog}
    except (OSError, ValueError) as error:
        reason = ("HTTP " + str(error.code)) if isinstance(error, urllib.error.HTTPError) else type(error).__name__ + ": catalog unavailable or rejected"
        return {**cached, "status": "failed", "last_attempt": attempted, "last_success": cached.get("last_success"), "error": reason}


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
        validate_observation(observation)
        for article in observation.get("articles", []):
            validate_article(article)
            require(article["source_id"] == source["id"] and article["source_name"] == source["name"] and article["kind"] == source["kind"] and article["origin"] == "publisher-feed" and safe_url(article["url"], source["article_hosts"]), "Retained article source mismatch.")
    validate_observation(cache["kev"])
    if "catalog" in cache["kev"]:
        validate_catalog(cache["kev"]["catalog"])


def validate_observation(observation):
    require(observation.get("status", "not_fetched") in {"ok", "failed", "not_fetched"}, "Invalid source observation status.")
    for field in ("last_attempt", "last_success"):
        value = observation.get(field)
        require(value is None or isinstance(value, str) and len(value) <= 40 and published(value) is not None, "Invalid source observation date.")
    reason = observation.get("error")
    require(reason is None or isinstance(reason, str) and len(reason) <= 500, "Invalid source observation error.")
    digest = observation.get("sha256")
    require(digest is None or isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest), "Invalid source digest.")
    if observation.get("status") == "ok":
        require(observation.get("last_success") and observation.get("last_attempt") and digest and reason is None, "Incomplete successful source observation.")


def validate_registry(registry):
    require(registry.get("schema_version") == 1 and isinstance(registry.get("sources"), list) and 1 <= len(registry["sources"]) <= 32, "Unexpected source registry.")
    seen = set()
    for source in registry["sources"]:
        require(re.fullmatch(r"[a-z0-9-]{1,80}", source["id"]) and source["id"] not in seen, "Invalid source identity.")
        seen.add(source["id"])
        require(source["kind"] in KINDS and isinstance(source["name"], str) and len(source["name"]) <= 100, "Invalid source metadata.")
        require(safe_url(source["url"]) == source["url"] and safe_url(source["home"]) is not None, "Invalid source URL.")
        require(isinstance(source["article_hosts"], list) and 1 <= len(source["article_hosts"]) <= 8 and all(safe_url("https://" + host + "/") is not None for host in source["article_hosts"]), "Invalid publisher hosts.")
    return registry["sources"]


def build_snapshot(start, end, refresh=True):
    require(start <= end and (end - start).days <= 370, "History window must be at most370days.")
    sources = validate_registry(read_json(ROOT / "config/sources.json", 128 * 1024))
    cache_path = STATE / "public-cache.json"
    cache = read_json(cache_path) if cache_path.exists() else {"sources": {}, "kev": {}}
    validate_cache(cache, sources)
    if refresh:
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {source["id"]: pool.submit(update_source, source, cache["sources"].get(source["id"], {})) for source in sources}
            kev_future = pool.submit(update_kev, cache["kev"])
            cache = {"sources": {key: future.result() for key, future in futures.items()}, "kev": kev_future.result()}
        validate_cache(cache, sources)
        require(any(item.get("status") == "ok" for item in [*cache["sources"].values(), cache["kev"]]), "No live source succeeded; the previously deployed snapshot must remain available.")
    health, articles = [], []
    for source in sources:
        observation = cache["sources"].get(source["id"], {})
        health.append({"id": source["id"], "name": source["name"], "kind": source["kind"], "url": source["home"],
            "status": observation.get("status", "not_fetched"), "last_attempt": observation.get("last_attempt"),
            "last_success": observation.get("last_success"), "error": observation.get("error"), "articles": len(observation.get("articles", []))})
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
            "cves": [ident], "tags": [text(item.get("vendorProject"), 80), text(item.get("product"), 100)],
            "exploitation": "known", "references": [{"label": "CVE record", "url": "https://www.cve.org/CVERecord?id=" + ident}], "origin": "cisa-kev"})
    health.append({"id": "cisa-kev", "name": "CISA KEV", "kind": "advisory", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "status": kev.get("status", "not_fetched"), "last_attempt": kev.get("last_attempt"), "last_success": kev.get("last_success"), "error": kev.get("error"), "articles": sum(article["origin"] == "cisa-kev" for article in articles)})
    history_path = ROOT / "config/history.json"
    history = read_json(history_path, 2 * 1024 * 1024) if history_path.exists() else {"entries": []}
    require(isinstance(history.get("entries"), list) and len(history["entries"]) <= 500, "Invalid history collection.")
    for entry in history["entries"]:
        validate_article(entry)
        require(entry["origin"] == "library-curation", "History entries require curated provenance.")
        articles.append(entry)
    selected = {}
    for article in articles:
        validate_article(article)
        stamp = article_date(article)[:10]
        if stamp:
            try:
                if not start <= date.fromisoformat(stamp) <= end:
                    continue
            except ValueError:
                continue
        require(safe_url(article.get("url")) is not None, "An article contains an unsafe link.")
        # Source URL identity preserves distinct publisher coverage; curated explanations take precedence.
        selected[article["url"]] = article
    require(len(selected) <= MAX_ARTICLES, "Article collection exceeds its limit.")
    ordered = sorted(selected.values(), key=article_date, reverse=True)
    require(ordered, "No articles are available in the selected window; preserving the previous deployment.")
    counts = {origin: sum(article["origin"] == origin for article in ordered) for origin in ("cisa-kev", "library-curation", "publisher-feed")}
    snapshot = {"schema_version": 1, "generated_at": now(), "window": {"start": start.isoformat(), "end": end.isoformat()},
        "articles": ordered, "sources": health, "history_reviewed_at": history.get("curated_at"),
        "coverage": {"kev_records": counts["cisa-kev"], "curated_events": counts["library-curation"], "feed_articles": counts["publisher-feed"],
            "notes": ["This is a growing selection, not every cyber incident or vulnerability.", "KEV dates indicate catalog addition, not first disclosure or first exploitation.", "RSS feeds usually expose recent posts only; the full year is not a backfill of every publisher.", "Unknown publication dates remain explicit; stale or failed sources retain their last successful cache.", "Headlines link to publishers; full article bodies are not copied. No environment exposure is inferred."]},
        "integrations": {"xai": {"status": "not_connected", "message": "Grok X Search is a separate supported API route; access and zero-additional-spend eligibility are not established. No model calls are enabled."},
                         "x": {"status": "not_connected", "message": "Personal X timeline/bookmarks are not connected or published. Public X search is not account authorization."}}}
    if refresh:
        write_json(cache_path, cache)
    write_json(ROOT / "site/data/feed.json", snapshot)
    return {"articles": len(ordered), "source_ok": sum(item["status"] == "ok" for item in health), "source_total": len(health), "coverage": snapshot["coverage"], "generated_at": snapshot["generated_at"]}
