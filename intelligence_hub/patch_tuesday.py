"""Patch Tuesday briefs: Microsoft's monthly security release as data, with KEV, Adobe and SAP joins.

A brief is built from data, never written by a model. The source of truth is the Microsoft
Security Response Center CVRF v3 API: the updates list names every monthly release (ids such
as 2026-Oct) with its initial and current release dates, and each release document lists its
CVEs with product trees, severities, CVSS scores and the exploitation threat that says
Exploited, Publicly Disclosed and the exploitability index. Every collector run reads the
updates list; a month is rebuilt when its release first appears or its current release date
changes. The second Tuesday is never assumed: the release dates are Microsoft's.

Rows: one per CVE in the release document that affects at least one Microsoft product (the
Azure Linux, CBL-Mariner and open-source package CVEs that the documents also carry are
counted and left out, by the same rule as the msrc-cvrf history adapter). Joins, recomputed
every run: the CISA KEV catalog (which of the month's CVEs KEV lists, and every Microsoft KEV
addition dated in the release month), the Hub's CVE briefs, the vocabulary tags, Adobe's
bulletin index (bulletins first posted on the release day) and SAP's Security Patch Day page
for the month. Adobe and SAP are headline rows only: ids, titles, dates, priorities and links.

The fixed prioritization rules (RULES below) order the month's CVEs: KEV-listed first, then
exploited in the wild, then Critical remote code execution in an internet-facing or identity
component, then the rest by CVSS base score.

Output: data/v7/patch-tuesday/YYYY-MM.json per month and data/v7/patch-tuesday/index.json,
canonical shards that data/v7/index.json lists with bytes and sha256 like every other shard.
State between runs: .state/patch-tuesday.json (the parsed months and the revision last seen
per month), with the deployed shards as the fallback when that cache is gone. Nothing here
can fail the feed: a source error leaves the last good month in place and says why.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
import hashlib
import html
import json
import math
from pathlib import Path
import re
import sys
import time

from .history import base
from .history.adapters import msrc_cvrf

PARSER_VERSION = "1"
SCHEMA_VERSION = 7
DIRECTORY = "patch-tuesday"
INDEX_PATH = DIRECTORY + "/index.json"
MONTH_PATH = re.compile(DIRECTORY + r"/([0-9]{4}-(?:0[1-9]|1[0-2]))\.json")
STATE_NAME = "patch-tuesday.json"
# Offline inputs for a --cached build: the same files the network would return, by name.
DOCUMENTS_NAME = "patch-tuesday-documents"
STATE_MAX_BYTES = 64 * 1024 * 1024
# The first month the updates list carries as a monthly Security Update Guide release.
FIRST_MONTH = "2016-01"
# Documents read per run. The publish workflow passes a larger number on a push, so a merge
# backfills every month at once; scheduled runs then rebuild the months whose revision changed.
DEFAULT_DOCUMENTS = 12
MAX_DOCUMENTS = 200
WORKERS = 4
# The whole Patch Tuesday step stops starting new reads after this many seconds.
RUN_DEADLINE = 420
# A month whose revision changed is read again at most once a day, except the newest month.
REFRESH_SECONDS = 24 * 3600
# SAP pages per run: this year's month pages and the two year bulletins hold every month from 2024.
SAP_PAGES_PER_RUN = 16
MONTH_NAMES = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
LONG_MONTHS = ("january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
               "november", "december")
CVE_URL = "https://msrc.microsoft.com/update-guide/vulnerability/"
RELEASE_URL = "https://msrc.microsoft.com/update-guide/releaseNote/"
KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve="
FIELDS = ("cve", "title", "severity", "impact", "cvss", "vector", "families", "component", "cna", "exploited",
          "disclosed", "exploitability", "cwe", "released", "revised")
ADOBE_FIELDS = ("id", "title", "products", "url", "posted", "updated")
# The link prefixes site/js/validate.js accepts for an SAP note row.
SAP_LINKS = ("https://me.sap.com/", "https://launchpad.support.sap.com/", "https://github.com/SAP/", "https://support.sap.com/")
SAP_FIELDS = ("note", "title", "cves", "priority", "cvss", "url")
SEVERITIES = ("Critical", "Important", "Moderate", "Low")
NOT_RATED = "Not rated"
# Microsoft's impact names, the most serious first. A CVE with several takes the first.
IMPACTS = ("Remote Code Execution", "Elevation of Privilege", "Security Feature Bypass", "Information Disclosure",
           "Spoofing", "Tampering", "Denial of Service")
# Microsoft's exploitability index values, the most urgent first.
EXPLOITABILITY = ("Exploitation Detected", "Exploitation More Likely", "Exploitation Less Likely", "Exploitation Unlikely")
# Internet-facing or identity components, matched against the CVE's component (MSRC's tag).
EXPOSED = re.compile(r"\b(?:Exchange Server|SharePoint|IIS|HTTP\.sys|HTTP Protocol Stack|Remote Desktop|RD Gateway|"
                     r"DNS Server|Routing and Remote Access|RRAS|TCP/IP|IKE|Internet Key Exchange|LDAP|"
                     r"Lightweight Directory Access Protocol|Kerberos|Netlogon|NTLM|Active Directory|"
                     r"Local Security Authority|LSASS|Entra|SMB|QUIC|Message Queuing|MSMQ|Server Update Service|WSUS|"
                     r"Network Device Enrollment|NDES)\b", re.I)
TIERS = ("kev", "exploited", "critical-rce-exposed", "cvss")
REST_SHOWN = 10
RULES = [
    "1. In CISA's KEV catalog: every CVE of the month that KEV lists, whatever its date added.",
    "2. Exploited: Microsoft marks the CVE Exploited:Yes and KEV does not list it yet.",
    "3. Critical remote code execution in an internet-facing or identity component: Microsoft severity Critical, "
    "impact Remote Code Execution, and a component that names Exchange Server, SharePoint, IIS or HTTP.sys, Remote Desktop, "
    "DNS Server, RRAS, TCP/IP, IKE, LDAP, Kerberos, Netlogon, NTLM, Active Directory, LSA, Entra, SMB, QUIC, Message Queuing, "
    "WSUS or the Network Device Enrollment Service.",
    "4. The rest, by CVSS base score, highest first; ties by CVE id.",
    "Inside each rule, rows are ordered by CVSS base score, highest first, then by CVE id."]
NOTES = [
    "Microsoft data only: rows, severities, scores and flags are the MSRC CVRF document's, read through the public API.",
    "A row is a CVE in the month's release document that affects at least one Microsoft product. Azure Linux, CBL-Mariner and "
    "open-source package CVEs listed in the same document are counted and left out.",
    "Chromium CVEs that Microsoft ships in Edge are rows with their issuing CNA named; they count in the totals.",
    "Adobe and SAP appear as headline rows only: bulletin ids, titles, dates, priorities and links to the vendor's page.",
    "Exploited and publicly disclosed are Microsoft's flags at the document's last revision, not the Hub's assessment.",
    "KEV dates are CISA's catalog additions, not disclosure or first exploitation."]


class PatchTuesdayError(ValueError):
    """A Patch Tuesday input that cannot be used."""


def require(condition, message):
    if not condition:
        raise PatchTuesdayError(message)


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def reject_constant(_value):
    raise PatchTuesdayError("Nonfinite JSON numbers are not accepted.")


def loads(raw):
    return json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw, parse_constant=reject_constant)


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def text(value, maximum=240):
    return base.text(value, maximum) or None


def document_month(ident):
    """"2026-Oct" is "2026-10"; anything else is None."""
    match = re.fullmatch(r"([0-9]{4})-([A-Za-z]{3})", ident or "")
    if not match or match.group(2).lower() not in MONTH_NAMES:
        return None
    return match.group(1) + "-" + format(MONTH_NAMES.index(match.group(2).lower()) + 1, "02d")


def clock(value):
    """An MSRC date-time as YYYY-MM-DDTHH:MM:SSZ (MSRC writes UTC with or without the Z), or None."""
    match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.[0-9]+)?Z?", str(value or "").strip())
    if not match:
        return None
    try:
        datetime.fromisoformat(match.group(1) + "T" + match.group(2))
    except ValueError:
        return None
    return match.group(1) + "T" + match.group(2) + "Z"


# Configuration ---------------------------------------------------------------------------

def load_config(registry, safe_url):
    """The patch_tuesday block of config/sources.json, checked. Raises PatchTuesdayError."""
    value = registry.get("patch_tuesday") if isinstance(registry, dict) else None
    require(isinstance(value, dict) and set(value) == {"msrc", "adobe", "sap"}, "config/sources.json has no valid patch_tuesday block.")
    from .collect import FETCH_CEILING, LARGE_DOCUMENT_CEILING
    checks = {"msrc": ({"name", "home", "updates", "updates_max_bytes", "document", "document_max_bytes"}, {"api.msrc.microsoft.com"}),
              "adobe": ({"name", "home", "index", "max_bytes"}, {"helpx.adobe.com"}),
              "sap": ({"name", "home", "index", "year", "max_bytes"}, {"support.sap.com"})}
    for key, (fields, hosts) in checks.items():
        entry = value[key]
        require(isinstance(entry, dict) and set(entry) == fields, "Invalid patch_tuesday." + key + " entry.")
        require(isinstance(entry["name"], str) and 1 <= len(entry["name"]) <= 100, "Invalid patch_tuesday." + key + " name.")
        for field in fields - {"name"}:
            if field.endswith("max_bytes"):
                ceiling = LARGE_DOCUMENT_CEILING if field == "document_max_bytes" else FETCH_CEILING
                require(type(entry[field]) is int and 1 <= entry[field] <= ceiling, "Invalid patch_tuesday." + key + " byte bound.")
                continue
            sample = entry[field].replace("{id}", "2026-Oct").replace("{year}", "2025")
            require(isinstance(entry[field], str) and safe_url(sample) == sample and (field == "home" or
                    sample.split("/")[2] in hosts), "Invalid patch_tuesday." + key + " URL.")
    return value


# MSRC ------------------------------------------------------------------------------------

def listing(updates_raw):
    """The monthly releases in the updates list, oldest first: id, month, title and the two release dates."""
    value = loads(updates_raw)
    require(isinstance(value, dict) and isinstance(value.get("value"), list) and len(value["value"]) <= 2000, "Unexpected MSRC updates list.")
    found = {}
    for item in value["value"]:
        if not isinstance(item, dict):
            continue
        month = document_month(item.get("ID"))
        title = text(item.get("DocumentTitle"), 120)
        if month is None or month < FIRST_MONTH or not title or title.lower() in msrc_cvrf.EXCLUDED_TITLES:
            continue
        initial, current = clock(item.get("InitialReleaseDate")), clock(item.get("CurrentReleaseDate"))
        if initial is None or current is None:
            continue
        entry = {"id": item["ID"], "month": month, "title": title, "initial_release": initial, "current_release": current}
        # One release per month; a second id for the same month keeps the earlier release.
        if month not in found or (initial, item["ID"]) < (found[month]["initial_release"], found[month]["id"]):
            found[month] = entry
    return [found[month] for month in sorted(found)]


LISTING_KEYS = {"id", "month", "title", "initial_release", "current_release"}


def _threat_fields(description):
    """{"publicly disclosed": "No", "exploited": "No", "latest software release": "..."} from an MSRC threat string."""
    fields = {}
    for part in str(description or "").split(";"):
        if ":" in part:
            key, value = part.split(":", 1)
            fields[" ".join(key.split()).lower()] = " ".join(value.split())
    return fields


def _applies(threat, products):
    ids = {str(ident) for ident in threat.get("ProductID") or []}
    return not ids or bool(ids & products)


def _rank(value, order):
    return order.index(value) if value in order else len(order)


def cve_key(cve):
    year, number = cve.split("-")[1:]
    return int(year), int(number)


def parse_document(raw, entry, retrieved_at):
    """(month unit) for one release document: the document facts and one row per Microsoft-product CVE."""
    value = loads(raw)
    require(isinstance(value, dict) and isinstance(value.get("Vulnerability"), list), "Unexpected CVRF document.")
    tracking = value.get("DocumentTracking") if isinstance(value.get("DocumentTracking"), dict) else {}
    ident = ((tracking.get("Identification") or {}).get("ID") or {}).get("Value")
    require(ident == entry["id"], "The CVRF document is not release " + entry["id"] + ".")
    families = msrc_cvrf._families(value.get("ProductTree"))
    names = msrc_cvrf._names(value.get("ProductTree"))
    rows, listed, left_out, seen = [], 0, 0, set()
    for item in value["Vulnerability"]:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("CVE") or "")
        if not base.CVE_ID.fullmatch(cve) or cve in seen:
            continue
        seen.add(cve)
        listed += 1
        products = set()
        for status in item.get("ProductStatuses") or []:
            if isinstance(status, dict) and status.get("Type") == 3:
                products.update(str(product) for product in status.get("ProductID") or [])
        microsoft = {product for product in products if msrc_cvrf.microsoft_product(product, families, names)}
        if not microsoft:
            left_out += 1
            continue
        severities, impacts, exploitability = set(), set(), set()
        exploited = disclosed = False
        for threat in item.get("Threats") or []:
            if not isinstance(threat, dict) or not _applies(threat, microsoft):
                continue
            description = str((threat.get("Description") or {}).get("Value") or "").strip()
            if threat.get("Type") == 3:
                severities.add(description)
            elif threat.get("Type") == 0:
                impacts.add(description)
            elif threat.get("Type") == 1:
                fields = _threat_fields(description)
                exploited = exploited or fields.get("exploited", "").lower() == "yes"
                disclosed = disclosed or fields.get("publicly disclosed", "").lower() == "yes"
                if fields.get("latest software release"):
                    exploitability.add(fields["latest software release"])
        severity = msrc_cvrf.highest(severities)
        severity = severity.capitalize() if severity and severity.capitalize() in SEVERITIES else None
        impact = min(impacts, key=lambda name: (_rank(name, IMPACTS), name), default=None)
        scores = []
        for score in item.get("CVSSScoreSets") or []:
            if not isinstance(score, dict) or not _applies(score, microsoft):
                continue
            number = score.get("BaseScore")
            vector = score.get("Vector") if isinstance(score.get("Vector"), str) and re.fullmatch(r"CVSS:[0-9.]+/[A-Za-z:/.]{1,200}", score["Vector"]) else None
            if isinstance(number, (int, float)) and not isinstance(number, bool) and math.isfinite(number) and 0 < number <= 10:
                scores.append((-float(number), vector or ""))
        best = min(scores, default=None)
        notes = {note.get("Type"): note.get("Value") for note in reversed(item.get("Notes") or []) if isinstance(note, dict)}
        affected = sorted({families.get(product, "") for product in microsoft} - {""})
        title = msrc_cvrf.headline(base.text((item.get("Title") or {}).get("Value"), maximum=400), cve, affected)
        dates = sorted(day for day in (base.day(revision.get("Date")) for revision in item.get("RevisionHistory") or []
                                       if isinstance(revision, dict)) if day)
        cwe = sorted({str(weakness.get("ID")) for weakness in item.get("CWE") or []
                      if isinstance(weakness, dict) and re.fullmatch(r"CWE-[1-9][0-9]{0,5}", str(weakness.get("ID") or ""))})
        best_exploitability = min(exploitability, key=lambda name: (_rank(name, EXPLOITABILITY), name), default=None)
        rows.append([cve, text(title), severity, text(impact, 60), round(-best[0], 1) if best else None, (best[1] or None) if best else None,
                     affected[:12], text(notes.get(7), 120), text(notes.get(8), 60), exploited, disclosed,
                     text(best_exploitability, 60), cwe[:10], dates[0] if dates else None,
                     dates[-1] if dates and dates[-1] != dates[0] else None])
    rows.sort(key=lambda row: cve_key(row[0]))
    msrc = {"id": entry["id"], "title": entry["title"], "initial_release": entry["initial_release"],
            "current_release": entry["current_release"], "listed": listed, "left_out": left_out,
            "document_sha256": hashlib.sha256(raw).hexdigest(), "retrieved_at": retrieved_at,
            "url": RELEASE_URL + entry["id"]}
    return {"parser_version": PARSER_VERSION, "month": entry["month"], "msrc": msrc, "fields": list(FIELDS), "rows": rows}


# Adobe and SAP ---------------------------------------------------------------------------

def _cell_text(value, maximum=240):
    return text(re.sub(r"<br\s*/?>", " ", value or "", flags=re.I).replace("\xa0", " "), maximum)


def _us_date(value):
    """MM/DD/YYYY, or MM/DD/YY read as 20YY (Adobe dates some 2022 rows 09/13/22)."""
    match = re.fullmatch(r"([0-9]{1,2})/([0-9]{1,2})/([0-9]{4}|[0-9]{2})", value or "")
    if not match:
        return None
    year = int(match.group(3)) + (2000 if len(match.group(3)) == 2 else 0)
    try:
        return date(year, int(match.group(1)), int(match.group(2))).isoformat()
    except ValueError:
        return None


def parse_adobe(raw, safe_url):
    """Adobe's bulletin index: one row per APSB bulletin with its title, products, link and dates."""
    page = raw.decode("utf-8", "replace")
    headings = [(match.start(), _cell_text(match.group(1), 100)) for match in re.finditer(r"<h2[^>]{0,400}>(.{0,600}?)</h2>", page, re.S)]
    found = {}
    # One <tr> block at a time: the block never crosses a </tr> or the next <tr>, so a row with an
    # extra trailing cell (Adobe ends some rows with <th>&nbsp;</th> or an empty fourth <td>) cannot
    # swallow its neighbour. The first three <td> cells are the bulletin, posted and updated dates.
    for match in re.finditer(r"<tr[^>]{0,200}>((?:(?!</?tr[\s>]).){0,6000})</tr>", page, re.S | re.I):
        cells = re.findall(r"<td[^>]{0,200}>((?:(?!</?t[dhr][\s>]).){0,3000})</td>", match.group(1), re.S | re.I)
        if len(cells) < 3:
            continue
        cell = cells[0]
        anchor = re.search(r'href="([^"]{1,300})"', cell)
        label = _cell_text(cell, 300) or ""
        ident = re.match(r"(APSB(\d{2})-\d{1,4})\s*:?\s*(.*)", label)
        posted, updated = _us_date(_cell_text(cells[1][:200], 20)), _us_date(_cell_text(cells[2][:200], 20))
        if not anchor or not ident or posted is None:
            continue
        href = anchor.group(1)
        # The id comes from the link's apsbNN-NN slug, not the visible label: Adobe's index labels
        # the Substance 3D Stager row APSB26-22 while it links to apsb26-29.html, and keying on the
        # label would fold that bulletin into the real APSB26-22. The label is the fallback only
        # when the link carries no slug.
        slug = re.search(r"/apsb(\d{2})-(\d{1,4})\.html?(?:[?#]|$)", href, re.I)
        key, year = ("APSB%s-%s" % (slug.group(1), slug.group(2)), slug.group(1)) if slug else (ident.group(1), ident.group(2))
        if posted[2:4] != year:
            continue
        url = safe_url(("https://helpx.adobe.com" + href) if href.startswith("/") else href)
        if url is None or not url.startswith("https://helpx.adobe.com/security/products/"):
            continue
        product = next((name for start, name in reversed(headings) if start < match.start()), None)
        title = text(ident.group(3).lstrip(":").strip(), 200) or key
        row = found.setdefault(key, [key, title, [], url, posted, updated if updated and updated > posted else None])
        if product and product not in row[2]:
            row[2].append(product)
    rows = []
    for key in sorted(found, key=lambda value: (value[4:6], int(value.split("-")[1]))):
        row = found[key]
        row[2] = sorted(row[2])[:6]
        rows.append(row)
    require(rows, "The Adobe bulletin index held no bulletin rows.")
    return rows


def adobe_block(index, initial_release, home):
    """The Adobe bulletins first posted on the release day (UTC date of Microsoft's release)."""
    if index is None or index.get("status") != "ok":
        return {"status": "unavailable", "reason": (index or {}).get("reason") or "the bulletin index was not read", "url": home, "rows": [],
                "latest_posted": None}
    release = initial_release[:10]
    return {"status": "ok", "reason": None, "url": home, "rows": [row for row in index["rows"] if row[4] == release],
            "latest_posted": max((row[4] for row in index["rows"]), default=None)}


def sap_month_links(raw, safe_url):
    """{YYYY-MM: month page URL} from SAP's Security Notes and News page."""
    page = raw.decode("utf-8", "replace")
    links = {}
    for match in re.finditer(r'href="(/en/my-support/knowledge-base/security-notes-news/(' + "|".join(LONG_MONTHS) +
                             r')-([0-9]{4})\.html)"', page):
        url = safe_url("https://support.sap.com" + match.group(1))
        if url:
            links[match.group(3) + "-" + format(LONG_MONTHS.index(match.group(2)) + 1, "02d")] = url
    return dict(sorted(links.items()))


def _sap_rows(fragment, safe_url):
    rows = []
    for match in re.finditer(r"<tr[^>]{0,400}>(.{0,20000}?)</tr>", fragment, re.S):
        cells = re.findall(r"<td[^>]{0,400}>(.{0,20000}?)</td>", match.group(1), re.S)
        if len(cells) != 4:
            continue
        # A screen-reader hint ("(opens in new tab)") is not part of the note id.
        note = _cell_text(re.sub(r'<span class="sr-only">.{0,200}?</span>', " ", cells[0], flags=re.S), 60)
        bold = re.search(r"<b>(.{1,2000}?)</b>", cells[1], re.S)
        title = _cell_text(bold.group(1) if bold else cells[1], 240)
        cves = sorted(set(re.findall(r"CVE-[0-9]{4}-[0-9]{4,8}", cells[1])), key=cve_key)[:20]
        priority = _cell_text(cells[2], 20)
        score = re.search(r"\b(10\.0|[0-9]\.[0-9])\b", _cell_text(cells[3], 40) or "")
        href = re.search(r'href="([^"]{1,300})"', cells[0])
        url = safe_url(href.group(1)) if href else None
        # Only SAP's own note, support and GitHub organization links; the page refuses any other host.
        url = url if url and url.startswith(SAP_LINKS) else None
        if not note or not title or not priority:
            continue
        rows.append([note, title, cves, priority, float(score.group(1)) if score else None, url])
    return rows[:80]


def parse_sap(raw, safe_url, month=None):
    """{YYYY-MM: rows}: a year bulletin page by its month headings, or one month page as month."""
    page = raw.decode("utf-8", "replace")
    pattern = re.compile(r"<h2[^>]{0,400}>\s*SAP Security Patch Day\s*\W{0,6}\s*(" + "|".join(LONG_MONTHS) + r")\s+([0-9]{4})\s*</h2>", re.I)
    sections = list(pattern.finditer(page))
    if not sections:
        require(month is not None, "The SAP page has no month sections.")
        return {month: _sap_rows(page, safe_url)}
    found = {}
    for number, match in enumerate(sections):
        end = sections[number + 1].start() if number + 1 < len(sections) else len(page)
        key = match.group(2) + "-" + format(LONG_MONTHS.index(match.group(1).lower()) + 1, "02d")
        found[key] = _sap_rows(page[match.end():end], safe_url)
    return found


def sap_links(block):
    """The block with every note link outside SAP_LINKS dropped, for rows read before that rule or resumed."""
    return {**block, "rows": [[*row[:5], row[5] if isinstance(row[5], str) and row[5].startswith(SAP_LINKS) else None] for row in block["rows"]]}


def sap_block(rows, url, reason=None):
    if rows is None:
        return {"status": "unavailable", "reason": reason or "no Security Patch Day page was read for this month", "url": url, "rows": [], "counts": {}}
    counts = {}
    for row in rows:
        counts[row[3]] = counts.get(row[3], 0) + 1
    return {"status": "ok", "reason": None, "url": url, "rows": rows, "counts": dict(sorted(counts.items()))}


# State -----------------------------------------------------------------------------------

def empty_state():
    return {"schema_version": 1, "months": {}, "adobe": None, "sap": {}, "listing": None, "listing_status": None, "failed": {}}


def valid_unit(unit):
    return (isinstance(unit, dict) and isinstance(unit.get("month"), str) and re.fullmatch(r"[0-9]{4}-(?:0[1-9]|1[0-2])", unit["month"]) and
            isinstance(unit.get("msrc"), dict) and isinstance(unit["msrc"].get("current_release"), str) and
            unit.get("fields") == list(FIELDS) and isinstance(unit.get("rows"), list) and
            all(isinstance(row, list) and len(row) == len(FIELDS) and isinstance(row[0], str) and base.CVE_ID.fullmatch(row[0])
                for row in unit["rows"]))


def load_state(directory):
    """.state/patch-tuesday.json, or an empty state when it is missing or invalid."""
    path = Path(directory) / STATE_NAME
    try:
        with path.open("rb") as stream:
            raw = stream.read(STATE_MAX_BYTES + 1)
        require(len(raw) <= STATE_MAX_BYTES, "The Patch Tuesday state exceeds its bound.")
        value = loads(raw)
        require(isinstance(value, dict) and value.get("schema_version") == 1 and isinstance(value.get("months"), dict), "Invalid Patch Tuesday state.")
    except (OSError, ValueError, UnicodeDecodeError) as error:
        if not isinstance(error, FileNotFoundError):
            print("Patch Tuesday: state not used (" + (str(error) or type(error).__name__)[:200] + ").", file=sys.stderr)
        return empty_state()
    state = empty_state()
    state["months"] = {month: unit for month, unit in value["months"].items() if valid_unit(unit) and unit["month"] == month}
    adobe = value.get("adobe")
    if isinstance(adobe, dict) and adobe.get("status") == "ok" and isinstance(adobe.get("rows"), list):
        state["adobe"] = adobe
    # The last updates list read, so a run whose read fails still knows the releases.
    if isinstance(value.get("listing"), list) and all(isinstance(entry, dict) and set(entry) == LISTING_KEYS for entry in value["listing"]):
        state["listing"] = value["listing"]
    if isinstance(value.get("sap"), dict):
        state["sap"] = {month: block for month, block in value["sap"].items() if isinstance(block, dict) and block.get("status") == "ok"}
    return state


def save_state(directory, state, write_raw):
    raw = (json.dumps(state, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(raw) <= STATE_MAX_BYTES:
        write_raw(Path(directory) / STATE_NAME, raw)


def resume_deployed(state, previous_index, read):
    """Months the state lacks, read from the deployed shards that previous_index lists. read(entry) returns the bytes.
    A trimmed brief is not resumed, so its month is read again from MSRC with its rows whole."""
    entries = [entry for entry in (previous_index or {}).get("shards", []) if MONTH_PATH.fullmatch(entry.get("path", ""))]
    wanted = [entry for entry in entries if MONTH_PATH.fullmatch(entry["path"]).group(1) not in state["months"]]
    resumed = 0

    def one(entry):
        try:
            raw = read(entry)
            require(len(raw) == entry["bytes"] and hashlib.sha256(raw).hexdigest() == entry["sha256"], "A deployed brief differs from its index.")
            return loads(raw)
        except (OSError, ValueError, UnicodeDecodeError) as error:
            print("Patch Tuesday: " + entry["path"] + " not resumed (" + (str(error) or type(error).__name__)[:200] + ").", file=sys.stderr)
            return None

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for value in pool.map(one, wanted):
            if not isinstance(value, dict) or value.get("kind") != "patch-tuesday":
                continue
            if value.get("trimmed"):
                # fit() dropped rows or tags from this brief, and its counts cover rows it no longer
                # carries: resuming it would shrink the totals and lose the marker. Read it from MSRC.
                print("Patch Tuesday: " + str(value.get("month"))[:7] + " not resumed (the deployed brief is trimmed).", file=sys.stderr)
                continue
            unit = {"parser_version": value.get("parser_version"), "month": value.get("month"), "msrc": value.get("msrc"),
                    "fields": value.get("fields"), "rows": value.get("rows")}
            if valid_unit(unit):
                state["months"][unit["month"]] = unit
                resumed += 1
                sap = value.get("sap")
                if isinstance(sap, dict) and sap.get("status") == "ok" and unit["month"] not in state["sap"]:
                    state["sap"][unit["month"]] = sap
                adobe = value.get("adobe")
                if isinstance(adobe, dict) and adobe.get("status") == "ok":
                    unit["adobe"] = adobe
    return resumed


def plan(entries, state, limit, now_epoch):
    """The releases to read this run, in order: new months newest first, then the newest month when revised,
    then other revised or older-parser months, the least recently read first (at most once a day each)."""
    newest = entries[-1]["month"] if entries else None
    missing, revised = [], []
    for entry in reversed(entries):
        unit = state["months"].get(entry["month"])
        if unit is None:
            missing.append(entry)
            continue
        stale = unit.get("parser_version") != PARSER_VERSION or unit["msrc"].get("id") != entry["id"]
        if not stale and unit["msrc"].get("current_release") == entry["current_release"]:
            continue
        read_at = unit["msrc"].get("retrieved_at") or ""
        try:
            age = now_epoch - datetime.fromisoformat(read_at.replace("Z", "+00:00")).timestamp()
        except ValueError:
            age = REFRESH_SECONDS
        if entry["month"] == newest or stale or age >= REFRESH_SECONDS:
            revised.append((entry["month"] != newest, read_at, entry["month"], entry))
    revised.sort(key=lambda item: item[:3])
    return (missing + [item[3] for item in revised])[:limit]


# Collection ------------------------------------------------------------------------------

class Reader:
    """Network reads in a live run, or the same names from the offline documents folder in a --cached build."""

    def __init__(self, fetch=None, offline=None):
        self.fetch, self.offline = fetch, Path(offline) if offline else None

    def get(self, url, maximum, accept, name, large=False):
        if self.offline is not None:
            path = self.offline / name
            if not path.is_file():
                raise OSError(name + " is not in the offline documents")
            with path.open("rb") as stream:
                raw = stream.read(maximum + 1)
            require(len(raw) <= maximum, name + " exceeds its byte bound.")
            return raw
        from .collect import FETCH_CEILING, LARGE_DOCUMENT_CEILING
        return self.fetch(url, maximum, accept=accept, language="en-US" if accept == "text/html" else None,
                          ceiling=LARGE_DOCUMENT_CEILING if large else FETCH_CEILING)


def _reason(error):
    from .collect import failure_reason
    return failure_reason(error, "source unavailable or rejected")


def collect(state_dir, config, reader, *, limit=DEFAULT_DOCUMENTS, previous_index=None, deployed_read=None,
            safe_url=None, clock_now=utc_now, monotonic=time.monotonic):
    """Bring the state up to date. Returns (state, report). Never raises for a source problem."""
    require(type(limit) is int and 0 <= limit <= MAX_DOCUMENTS, "The Patch Tuesday document limit must be 0 to " + str(MAX_DOCUMENTS) + ".")
    started = monotonic()
    state = load_state(state_dir)
    report = {"documents_read": 0, "failed": [], "resumed": 0}
    if previous_index is not None and deployed_read is not None:
        report["resumed"] = resume_deployed(state, previous_index, deployed_read)
    msrc, adobe, sap = config["msrc"], config["adobe"], config["sap"]
    try:
        state["listing"] = listing(reader.get(msrc["updates"], msrc["updates_max_bytes"], "application/json", "updates.json"))
        state["listing_status"] = {"status": "ok", "reason": None}
    except (OSError, ValueError, UnicodeDecodeError) as error:
        state["listing_status"] = {"status": "unavailable", "reason": _reason(error)}
        print("Patch Tuesday: the MSRC updates list was not read (" + state["listing_status"]["reason"] + ").", file=sys.stderr)
    entries = state["listing"] or []
    queue = plan(entries, state, limit, time.time())
    rebuilt = []

    def read_document(entry):
        if monotonic() - started > RUN_DEADLINE:
            return entry, None, "the run's Patch Tuesday time budget was spent"
        try:
            raw = reader.get(msrc["document"].replace("{id}", entry["id"]), msrc["document_max_bytes"], "application/json",
                             "cvrf/" + entry["id"] + ".json", large=True)
            return entry, parse_document(raw, entry, clock_now()), None
        except (OSError, ValueError, UnicodeDecodeError, KeyError, TypeError, AttributeError) as error:
            return entry, None, _reason(error)

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for entry, unit, error in pool.map(read_document, queue):
            if unit is not None:
                state["months"][entry["month"]] = unit
                rebuilt.append(entry["month"])
                report["documents_read"] += 1
                state["failed"].pop(entry["month"], None)
            else:
                report["failed"].append({"month": entry["month"], "id": entry["id"], "reason": error[:200]})
                state["failed"][entry["month"]] = error[:200]
    try:
        rows = parse_adobe(reader.get(adobe["index"], adobe["max_bytes"], "text/html", "adobe-security.html"), safe_url)
        state["adobe"] = {"status": "ok", "reason": None, "rows": rows}
    except (OSError, ValueError, UnicodeDecodeError) as error:
        reason = _reason(error)
        if state["adobe"] is None:
            state["adobe"] = {"status": "unavailable", "reason": reason, "rows": []}
        report["adobe"] = reason
    report["sap"] = _collect_sap(state, sap, reader, rebuilt, entries, safe_url, started, monotonic)
    report["pending"] = [entry["month"] for entry in entries if entry["month"] not in state["months"]]
    report["rebuilt"] = sorted(rebuilt)
    return state, report


def _collect_sap(state, sap, reader, rebuilt, entries, safe_url, started, monotonic):
    """SAP Security Patch Day rows for months rebuilt this run and months that have none yet, a few pages a run."""
    try:
        links = sap_month_links(reader.get(sap["index"], sap["max_bytes"], "text/html", "sap-index.html"), safe_url)
    except (OSError, ValueError, UnicodeDecodeError) as error:
        return "index not read: " + _reason(error)
    months = [entry["month"] for entry in reversed(entries)]
    wanted = [month for month in months if month in rebuilt or month not in state["sap"]]
    pages, done = 0, set()
    for month in wanted:
        if pages >= SAP_PAGES_PER_RUN or monotonic() - started > RUN_DEADLINE or month in done:
            continue
        if month in links:
            url, name, page_month = links[month], "sap-" + links[month].rsplit("/", 1)[1], month
        elif month[:4] < max(links, default="0000")[:4] and month[:4] >= "2024":
            url = sap["year"].replace("{year}", month[:4])
            name, page_month = "sap-bulletin-" + month[:4] + ".html", None
        else:
            continue
        pages += 1
        try:
            found = parse_sap(reader.get(url, sap["max_bytes"], "text/html", name), safe_url, page_month)
        except (OSError, ValueError, UnicodeDecodeError) as error:
            print("Patch Tuesday: SAP page for " + month + " not read (" + _reason(error) + ").", file=sys.stderr)
            continue
        for key, rows in found.items():
            if rows:
                state["sap"][key] = sap_block(rows, url)
                done.add(key)
    return "ok"


# Shards ----------------------------------------------------------------------------------

def kev_map(catalog):
    found = {}
    for entry in (catalog or {}).get("vulnerabilities", []) if isinstance(catalog, dict) else []:
        if isinstance(entry, dict) and isinstance(entry.get("cveID"), str) and base.CVE_ID.fullmatch(entry["cveID"]) and \
                isinstance(entry.get("dateAdded"), str) and base.day(entry["dateAdded"]) == entry["dateAdded"]:
            found[entry["cveID"]] = entry
    return found


def tier(row, kev):
    values = dict(zip(FIELDS, row))
    if values["cve"] in kev:
        return "kev"
    if values["exploited"]:
        return "exploited"
    if (values["severity"] == "Critical" and values["impact"] == "Remote Code Execution" and values["component"] and
            EXPOSED.search(values["component"])):
        return "critical-rce-exposed"
    return "cvss"


def prioritize(rows, kev):
    """[[cve, tier], ...]: every row of the first three rules, then the first REST_SHOWN of the rest."""
    ordered = sorted(rows, key=lambda row: (TIERS.index(tier(row, kev)), -(row[4] if row[4] is not None else -1), cve_key(row[0])))
    out, rest = [], 0
    for row in ordered:
        value = tier(row, kev)
        if value == "cvss":
            if rest >= REST_SHOWN:
                break
            rest += 1
        out.append([row[0], value])
    return out


def counts(rows, kev):
    values = [dict(zip(FIELDS, row)) for row in rows]
    severity = {name: 0 for name in (*SEVERITIES, NOT_RATED)}
    impact, family, cna = {}, {}, {}
    for row in values:
        severity[row["severity"] or NOT_RATED] += 1
        impact[row["impact"] or "Not stated"] = impact.get(row["impact"] or "Not stated", 0) + 1
        for name in row["families"] or ["Not stated"]:
            family[name] = family.get(name, 0) + 1
        cna[row["cna"] or "Not stated"] = cna.get(row["cna"] or "Not stated", 0) + 1
    return {"total": len(values), "severity": severity, "impact": dict(sorted(impact.items())), "family": dict(sorted(family.items())),
            "cna": dict(sorted(cna.items())), "exploited": sum(row["exploited"] for row in values),
            "disclosed": sum(row["disclosed"] for row in values), "in_kev": sum(row["cve"] in kev for row in values),
            "critical": severity["Critical"]}


def tag_rows(unit, tagging_context, source_name):
    """{cve: compact tags} from the vocabulary tagger, or {} when tagging is unavailable."""
    if tagging_context is None:
        return {}
    from .tagging import tag_rows as tag_all
    from .tagging.engine import compact
    rows = []
    for row in unit["rows"]:
        values = dict(zip(FIELDS, row))
        article = {"id": "pt-" + values["cve"], "title": values["title"], "url": CVE_URL + values["cve"], "source_id": msrc_cvrf.SOURCE_ID,
                   "source_name": source_name, "kind": "advisory", "published_at": unit["msrc"]["initial_release"][:10], "event_date": None,
                   "date_basis": "publication", "summary": "", "cves": [values["cve"]], "tags": [],
                   "exploitation": "known" if values["exploited"] else "unknown", "references": [], "origin": "history:" + msrc_cvrf.ID}
        if values["exploited"]:
            article["exploitation_evidence"] = {"basis": "vendor-structured", "exploited": True}
        rows.append(article)
    blocks = tag_all(rows, tagging_context)
    keep = ("exploitation", "event_type", "vendor", "product", "cwe")
    return {row["cves"][0]: {key: value for key, value in compact(blocks[row["id"]]).items() if key in keep} for row in rows}


def month_shard(unit, kev, briefs, adobe_index, sap, tags, homes):
    rows = unit["rows"]
    month = unit["month"]
    in_kev = [[row[0], kev[row[0]]["dateAdded"], base.day(kev[row[0]].get("dueDate"))] for row in rows if row[0] in kev]
    released = {row[0] for row in rows}
    added = sorted(([entry["cveID"], entry["dateAdded"], entry["cveID"] in released] for entry in kev.values()
                    if str(entry.get("vendorProject") or "").strip().lower() == "microsoft" and entry["dateAdded"][:7] == month),
                   key=lambda item: (item[1], cve_key(item[0])))
    adobe = adobe_block(adobe_index, unit["msrc"]["initial_release"], homes["adobe"])
    if adobe["status"] != "ok" and isinstance(unit.get("adobe"), dict):
        adobe = unit["adobe"]
    return {"schema_version": SCHEMA_VERSION, "kind": "patch-tuesday", "month": month, "parser_version": unit["parser_version"],
            "msrc": unit["msrc"], "fields": list(FIELDS), "rows": rows, "counts": counts(rows, kev),
            "kev": {"listed": in_kev, "added_in_month": added}, "briefs": [row[0] for row in rows if row[0] in briefs],
            "priority": prioritize(rows, kev), "tags": tags, "adobe": {**adobe, "fields": list(ADOBE_FIELDS)},
            "sap": {**sap_links(sap or sap_block(None, homes["sap"])), "fields": list(SAP_FIELDS)}}


def fit(value, limit):
    """value inside limit bytes: tags go first, then Moderate, Low and unrated rows (counts stay whole). None if it cannot fit.

    A row that the KEV join, a Hub brief or one of the first three priority rules names is kept
    whatever its severity, and the "rest by CVSS" priority list keeps only the rows that remain,
    so every CVE the brief names is still in its rows (site/js/validate.js refuses one that is not).
    """
    if len(canonical(value)) <= limit:
        return value
    value = {**value, "tags": {}, "trimmed": {"tags": True, "rows": 0}}
    if len(canonical(value)) <= limit:
        return value
    named = ({item[0] for item in value["kev"]["listed"]} | set(value["briefs"]) |
             {item[0] for item in value["priority"] if item[1] != "cvss"})
    kept = [row for row in value["rows"] if row[2] in ("Critical", "Important") or row[9] or row[10] or row[0] in named]
    remaining = {row[0] for row in kept}
    value = {**value, "rows": kept, "priority": [item for item in value["priority"] if item[0] in remaining],
             "trimmed": {"tags": True, "rows": len(value["rows"]) - len(kept)}}
    return value if len(canonical(value)) <= limit else None


def build(state, catalog, briefs, *, tagging_context=None, limit, config):
    """{shard path: value} for every built month and the Patch Tuesday index. Pure: no network, no clock."""
    kev = kev_map(catalog)
    homes = {"adobe": config["adobe"]["home"], "sap": config["sap"]["home"]}
    entries = {entry["month"]: entry for entry in state.get("listing") or []}
    shards, months, held = {}, [], []
    for month in sorted(state["months"]):
        unit = state["months"][month]
        if entries and month not in entries:
            continue  # Microsoft no longer lists the release
        try:
            tags = tag_rows(unit, tagging_context, config["msrc"]["name"])
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            print("Patch Tuesday: " + month + " tags unavailable (" + (str(error) or type(error).__name__)[:200] + ").", file=sys.stderr)
            tags = {}
        value = fit(month_shard(unit, kev, briefs, state.get("adobe"), state["sap"].get(month), tags, homes), limit)
        if value is None:
            held.append({"month": month, "id": unit["msrc"]["id"], "reason": "the brief would pass the " + format(limit, ",") + "-byte shard bound"})
            continue
        path = DIRECTORY + "/" + month + ".json"
        shards[path] = value
        total = value["counts"]
        months.append({"month": month, "id": unit["msrc"]["id"], "title": unit["msrc"]["title"], "initial_release": unit["msrc"]["initial_release"],
                       "current_release": unit["msrc"]["current_release"], "path": path, "total": total["total"], "critical": total["critical"],
                       "important": total["severity"]["Important"], "exploited": total["exploited"], "disclosed": total["disclosed"],
                       "in_kev": total["in_kev"], "kev_added_in_month": len(value["kev"]["added_in_month"]),
                       "adobe": len(value["adobe"]["rows"]), "sap": len(value["sap"]["rows"])})
    built = {item["month"] for item in months}
    failed = state.get("failed") or {}
    pending = [{"month": month, "id": entry["id"], "reason": ("the release document was not read: " + failed[month]) if month in failed else
                "not read yet; the collector reads a bounded number of release documents per run"}
               for month, entry in sorted(entries.items()) if month not in built and month not in {item["month"] for item in held}]
    months.sort(key=lambda item: item["month"], reverse=True)
    status = {"msrc": state.get("listing_status") or {"status": "unavailable", "reason": "the updates list was not read in this run"},
              "adobe": {"status": (state.get("adobe") or {}).get("status", "unavailable"), "reason": (state.get("adobe") or {}).get("reason")},
              "sap": {"status": "ok" if state["sap"] else "unavailable", "reason": None if state["sap"] else "no Security Patch Day page has been read"}}
    shards[INDEX_PATH] = {"schema_version": SCHEMA_VERSION, "kind": "patch-tuesday-index", "parser_version": PARSER_VERSION,
                          "first_month": months[-1]["month"] if months else None, "last_month": months[0]["month"] if months else None,
                          "months": months, "pending": pending + held, "rules": RULES, "notes": NOTES, "status": status,
                          "sources": {key: {"name": config[key]["name"], "home": config[key]["home"]} for key in ("msrc", "adobe", "sap")}}
    return shards


def summary(shards, report):
    index = shards.get(INDEX_PATH) or {}
    largest = max((len(canonical(value)) for path, value in shards.items() if path != INDEX_PATH), default=0)
    return {"months": len(index.get("months", [])), "first_month": index.get("first_month"), "last_month": index.get("last_month"),
            "pending": len(index.get("pending", [])), "documents_read": report.get("documents_read", 0),
            "failed": report.get("failed", [])[:5], "resumed": report.get("resumed", 0), "largest_shard_bytes": largest}


def print_headroom(shards, limit, out=None):
    """One line per brief with its bytes and headroom under the per-file bound, then the totals."""
    out = out or sys.stderr
    total = 0
    for path in sorted(shards):
        size = len(canonical(shards[path]))
        total += size
        print("Patch Tuesday: data/v7/{} {:,} of {:,} bytes ({:,} of headroom)".format(path, size, limit, limit - size), file=out)
    print("Patch Tuesday: {:,} files, {:,} bytes".format(len(shards), total), file=out)
