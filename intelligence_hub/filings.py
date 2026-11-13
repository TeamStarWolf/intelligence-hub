"""SEC filing intake: 8-K disclosures under Item 1.05 (Material Cybersecurity Incidents).

The collector reads SEC EDGAR full-text search (efts.sec.gov), the public, free, no-key index of
filing text. Each run asks for 8-K forms carrying structured Item 1.05 in a recent window, keeps
only filings whose structured item list actually contains 1.05 (not a passing text mention), and
turns each into one Explorer row (origin "sec-filing", kind "filing"). Item 8.01 cyber notices are
not read: 8.01 is a generic "other events" item and telling a cyber 8.01 from any other needs the
filing body, which this intake does not fetch. Tenant or issuer specifics beyond the filing's own
header are never inferred.

A run that cannot read EDGAR keeps the last good response it cached and records the failure; it
never blocks the feed. The rows are rebuilt from the cache on every run, like the service-health
rows, so nothing here is resumed from the deployed feed.
"""
import json
import re
import urllib.parse
from datetime import date, timedelta

from . import collect
from .collect import published, safe_url, text

SEARCH_URL = "https://efts.sec.gov/LATEST/search-index"
ARCHIVE = "https://www.sec.gov/Archives/edgar/data/"
WINDOW_DAYS = 120            # recent filings land in the live month shards the Explorer reads first
MAX_FILINGS = 100            # a hard cap on rows produced in one run
PAGE_SIZE = 10               # EDGAR full-text search returns ten hits per page
MAX_PAGES = 12
MAX_BYTES = 4 * 1024 * 1024
CACHE = "filings-cache.json"
ORIGIN = "sec-filing"
SOURCE_ID = "sec-edgar"
SOURCE_NAME = "SEC EDGAR"
CIK_RE = re.compile(r"(\d{1,10})")
ADSH_RE = re.compile(r"^[0-9]{10}-[0-9]{2}-[0-9]{6}$")
NAME_RE = re.compile(r"^(.*?)\s*(?:\(([^)]*)\)\s*)?\(CIK (\d+)\)\s*$")


def search_url(end, start=None, page=0):
    start = start or (end - timedelta(days=WINDOW_DAYS))
    query = urllib.parse.urlencode({"q": '"Item 1.05"', "forms": "8-K",
                                    "startdt": start.isoformat(), "enddt": end.isoformat(), "from": page * PAGE_SIZE})
    url = SEARCH_URL + "?" + query
    if safe_url(url) != url:
        raise ValueError("EDGAR search URL is not canonical.")
    return url


def filing_url(cik, adsh):
    folder = adsh.replace("-", "")
    url = ARCHIVE + str(int(cik)) + "/" + folder + "/" + adsh + "-index.htm"
    return url if safe_url(url) == url else None


def parse_name(display):
    match = NAME_RE.match(display or "")
    if not match:
        return (display or "").strip(), None, None
    ticker = (match.group(2) or "").split(",")[0].strip() or None
    return match.group(1).strip(), ticker, match.group(3)


def row_for(source):
    """One Explorer row from a full-text-search hit whose structured items include 1.05, or None."""
    if not isinstance(source, dict) or "1.05" not in (source.get("items") or []):
        return None
    adsh = source.get("adsh")
    cik = (source.get("ciks") or [None])[0]
    filed = source.get("file_date")
    if not (isinstance(adsh, str) and ADSH_RE.match(adsh) and isinstance(cik, str) and CIK_RE.fullmatch(cik) and published(filed)):
        return None
    name, ticker, _cik = parse_name((source.get("display_names") or [""])[0])
    name = text(name, 200) or "A registrant"
    url = filing_url(cik, adsh)
    if url is None:
        return None
    label = name + (" (" + ticker + ")" if ticker else "")
    items = ", ".join(sorted(source.get("items") or []))
    state = (source.get("biz_states") or [""])[0]
    summary = (label + " filed a Form 8-K under Item 1.05 (Material Cybersecurity Incidents) with the SEC on "
               + filed + "." + (" Principal office in " + state + "." if state else "") + " Items reported: " + items
               + ". Read the filing on EDGAR; the SEC filing is the only claim made here.")
    return {"id": "sec-" + adsh, "title": text(label + ": 8-K material cybersecurity incident (Item 1.05)", 300),
            "url": url, "source_id": SOURCE_ID, "source_name": SOURCE_NAME, "kind": "filing",
            "published_at": filed, "event_date": None, "date_basis": "filing", "summary": text(summary, 500),
            "cves": [], "tags": [], "exploitation": "unknown",
            "references": [{"label": "8-K filing on SEC EDGAR", "url": url}], "origin": ORIGIN}


def parse_search(documents):
    """Every page's JSON, in order, to de-duplicated rows newest first."""
    rows = {}
    for raw in documents:
        payload = json.loads(raw.decode("utf-8"), parse_constant=collect.reject_constant)
        for hit in (payload.get("hits", {}).get("hits") or []):
            row = row_for(hit.get("_source") if isinstance(hit, dict) else None)
            if row and row["id"] not in rows:
                rows[row["id"]] = row
            if len(rows) >= MAX_FILINGS:
                break
    return sorted(rows.values(), key=lambda row: (row["published_at"], row["id"]), reverse=True)


def read_edgar(fetch, end):
    """Fetch successive full-text-search pages until a page is empty or the caps are reached."""
    documents = []
    total = None
    for page in range(MAX_PAGES):
        payload = fetch(search_url(end, page=page), maximum=MAX_BYTES, accept="application/json")
        documents.append(payload)
        data = json.loads(payload.decode("utf-8"), parse_constant=collect.reject_constant)
        hits = data.get("hits", {}).get("hits") or []
        total = data.get("hits", {}).get("total", {}).get("value") if total is None else total
        if len(hits) < PAGE_SIZE or (page + 1) * PAGE_SIZE >= min(MAX_FILINGS, total or 0) + PAGE_SIZE:
            break
    return documents


def collect_filings(refresh, end, *, fetch=collect.fetch, state=None):
    """(Explorer rows, summary). Never raises: a failed read keeps the cached response, if any."""
    cache_path = (state / CACHE) if state is not None else None
    if refresh:
        try:
            documents = read_edgar(fetch, end)
            rows = parse_search(documents)
            if cache_path is not None:
                collect.write_raw(cache_path, (json.dumps(documents_as_text(documents), ensure_ascii=False) + "\n").encode("utf-8"))
            return rows, {"status": "ok", "filings": len(rows), "error": None}
        except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
            reason = collect.failure_reason(error, "SEC EDGAR unavailable")
            rows = _from_cache(cache_path)
            return rows, {"status": "failed" if rows is None else "stale", "filings": len(rows or []), "error": reason}
    rows = _from_cache(cache_path)
    return (rows or []), {"status": "cached" if rows else "none", "filings": len(rows or []), "error": None}


def documents_as_text(documents):
    return [raw.decode("utf-8") for raw in documents]


def _from_cache(cache_path):
    if cache_path is None or not cache_path.exists():
        return []
    try:
        stored = json.loads(cache_path.read_text(encoding="utf-8"), parse_constant=collect.reject_constant)
        return parse_search([part.encode("utf-8") for part in stored])
    except (OSError, ValueError, TypeError) as error:
        return []
