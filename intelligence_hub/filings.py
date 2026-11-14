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

# SIC (Standard Industrial Classification) ranges mapped to CISA critical-infrastructure
# sector ids (config/vocab/sector.json). The filer's SIC is a structured EDGAR field, so the
# sector it implies is tagged at medium confidence (method "sec-sic"); a SIC outside every
# range yields no sector tag rather than a guess. Narrow carve-outs come before the broad
# range that contains them (drugs out of chemicals, medical and defence out of manufacturing,
# computing and communications equipment out of manufacturing): the first match wins.
SIC_SECTORS = (
    (100, 999, "food-agriculture"),             # agriculture, forestry and fishing
    (2000, 2199, "food-agriculture"),           # food, beverages and tobacco
    (2833, 2836, "healthcare-public-health"),   # drugs and biological products (out of chemicals)
    (2800, 2899, "chemical"),                    # chemicals and allied products
    (1300, 1399, "energy"),                      # oil and gas extraction
    (2900, 2999, "energy"),                      # petroleum refining
    (4600, 4699, "energy"),                      # pipelines
    (4900, 4939, "energy"),                      # electric and gas services
    (4940, 4971, "water-wastewater"),            # water supply and sanitary services
    (3826, 3851, "healthcare-public-health"),   # medical, surgical and ophthalmic instruments
    (3570, 3579, "information-technology"),      # computer and office equipment
    (3670, 3679, "information-technology"),      # semiconductors and electronic components
    (7370, 7379, "information-technology"),      # computer programming and data processing
    (3660, 3669, "communications"),             # communications equipment
    (4800, 4899, "communications"),             # communications services
    (3480, 3489, "defense-industrial-base"),    # ordnance
    (3760, 3769, "defense-industrial-base"),    # guided missiles and space vehicles
    (6000, 6299, "financial-services"),         # credit institutions and brokers
    (6300, 6499, "financial-services"),         # insurance
    (6500, 6799, "financial-services"),         # real estate, holding and investment
    (8000, 8099, "healthcare-public-health"),   # health services
    (3000, 3599, "critical-manufacturing"),     # rubber, metal and machinery
    (3700, 3799, "critical-manufacturing"),     # transportation equipment
    (4000, 4099, "transportation"),             # railroads
    (4200, 4299, "transportation"),             # motor freight and trucking
    (4400, 4599, "transportation"),             # water and air transportation
    (4700, 4789, "transportation"),             # transportation services
    (5200, 5999, "retail"),                      # retail trade
    (7000, 7021, "commercial-facilities"),      # hotels and lodging
    (7900, 7999, "commercial-facilities"),      # amusement and recreation
    (8200, 8299, "education"),                   # educational services
    (9100, 9999, "government-facilities"),       # public administration
)

# Legal-form tokens stripped from a filer name before it is slugged, so the same company tags
# the same way whether a filing writes "Corp", "Corporation" or nothing. Brand words that vary
# between real companies ("Group", "Holdings") are kept.
NAME_SUFFIXES = {"inc", "incorporated", "corp", "corporation", "co", "company", "ltd", "limited",
                 "llc", "lp", "lllp", "plc", "sa", "nv", "ag", "se", "ab", "oyj", "spa"}
SLUG_RE = re.compile(r"[a-z0-9]+")


def sector_tags(sics):
    """Compact sector tags for a filer's SIC codes: [[sector:<id>, method, confidence], ...], deduped."""
    found = []
    for raw in sics or []:
        digits = re.sub(r"\D", "", str(raw))
        if not digits:
            continue
        code = int(digits)
        slug = next((sector for low, high, sector in SIC_SECTORS if low <= code <= high), None)
        if slug and slug not in found:
            found.append(slug)
    return [["sector:" + slug, "sec-sic", "medium"] for slug in sorted(found)]


def company_slug(name):
    """A stable, readable company id slug from a filer name, or None. Legal-form suffixes and a
    leading "The" are dropped so a company's filings share one slug; the slug is bounded for the
    tag-length limit."""
    words = SLUG_RE.findall((name or "").lower())
    while words and words[-1] in NAME_SUFFIXES:
        words.pop()
    if words and words[0] == "the":
        words.pop(0)
    slug = "-".join(words)[:80].strip("-")
    return slug or None


def tagging_for(name, sics):
    """The compact tagging block for a filing row: sector(s) from the SIC, company from the filer.
    Only non-empty facets are included; an empty block is returned as {} (the site fills defaults)."""
    block = {}
    sectors = sector_tags(sics)
    if sectors:
        block["sector"] = sectors
    slug = company_slug(name)
    if slug:
        block["company"] = [["company:" + slug, "sec-filer", "high"]]
    return block


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
    parsed_name, ticker, _cik = parse_name((source.get("display_names") or [""])[0])
    name = text(parsed_name, 200) or "A registrant"
    url = filing_url(cik, adsh)
    if url is None:
        return None
    label = name + (" (" + ticker + ")" if ticker else "")
    items = ", ".join(sorted(source.get("items") or []))
    state = (source.get("biz_states") or [""])[0]
    summary = (label + " filed a Form 8-K under Item 1.05 (Material Cybersecurity Incidents) with the SEC on "
               + filed + "." + (" Principal office in " + state + "." if state else "") + " Items reported: " + items
               + ". Read the filing on EDGAR; the SEC filing is the only claim made here.")
    row = {"id": "sec-" + adsh, "title": text(label + ": 8-K material cybersecurity incident (Item 1.05)", 300),
           "url": url, "source_id": SOURCE_ID, "source_name": SOURCE_NAME, "kind": "filing",
           "published_at": filed, "event_date": None, "date_basis": "filing", "summary": text(summary, 500),
           "cves": [], "tags": [], "exploitation": "unknown",
           "references": [{"label": "8-K filing on SEC EDGAR", "url": url}], "origin": ORIGIN}
    tagging = tagging_for(parsed_name, source.get("sics"))
    if tagging:
        row["tagging"] = tagging
    return row


def hits_of(payload):
    """(hits list, total or None) from a search response. The response is untrusted upstream data, so
    an unexpected shape raises ValueError rather than letting an AttributeError abort the whole run."""
    if not isinstance(payload, dict):
        raise ValueError("EDGAR search response is not an object.")
    block = payload.get("hits")
    if not isinstance(block, dict):
        raise ValueError("EDGAR search response has no hits object.")
    count = block.get("total")
    total = count.get("value") if isinstance(count, dict) else None
    hits = block.get("hits")
    return (hits if isinstance(hits, list) else []), (total if isinstance(total, int) and total >= 0 else None)


def parse_search(documents):
    """Every page's JSON, in order, to de-duplicated rows newest first."""
    rows = {}
    for raw in documents:
        hits, _total = hits_of(json.loads(raw.decode("utf-8"), parse_constant=collect.reject_constant))
        for hit in hits:
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
        hits, count = hits_of(json.loads(payload.decode("utf-8"), parse_constant=collect.reject_constant))
        if total is None:
            total = count or 0
        if len(hits) < PAGE_SIZE or (page + 1) * PAGE_SIZE >= min(MAX_FILINGS, total) + PAGE_SIZE:
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
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError) as error:
            reason = collect.failure_reason(error, "SEC EDGAR unavailable")
            rows = _from_cache(cache_path)
            return (rows or []), {"status": "failed" if rows is None else "stale", "filings": len(rows or []), "error": reason}
    rows = _from_cache(cache_path)
    return (rows or []), {"status": "cached" if rows else "none", "filings": len(rows or []), "error": None}


def documents_as_text(documents):
    return [raw.decode("utf-8") for raw in documents]


def _from_cache(cache_path):
    if cache_path is None or not cache_path.exists():
        return None
    try:
        stored = json.loads(cache_path.read_text(encoding="utf-8"), parse_constant=collect.reject_constant)
        return parse_search([part.encode("utf-8") for part in stored])
    except (OSError, ValueError, TypeError, AttributeError, RecursionError) as error:
        return []
