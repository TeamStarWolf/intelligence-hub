"""Microsoft Security Update Guide entries from the MSRC CVRF API, April 2016 onward.

One row per CVE that Microsoft rated Critical or Important, or marked exploited, in a
monthly security update document. The update list also carries documents labelled
"Mariner Release Notes" under ids such as 1999-Sep: they describe Azure Linux
packages, not Windows-era updates, and are excluded by title and by date.
"""
import json
import re
import sys

from .. import base

ID = "msrc-cvrf"
SOURCE_ID = "microsoft-msrc-cvrf"
SOURCE_NAME = "Microsoft Security Update Guide (CVRF)"
SOURCE_CLASS = "vendor-primary"
PUBLISHER_VENDOR = "vendor:microsoft"
COUNTRY = "US"
KIND = "advisory"
FIRST_YEAR = 2016
LAST_YEAR = None
HOME = "https://msrc.microsoft.com/update-guide/"
HOSTS = ("api.msrc.microsoft.com",)
MAX_BYTES = 64 * 1024 * 1024
FILTER = ("Microsoft severity Critical or Important, or Exploited:Yes in the CVE's exploitability threat; "
          "the first 1,500 a year by exploited, severity and CVE id")
LICENCE = "MSRC CVRF API; CVE ids, Microsoft titles, severities, product families, dates and links only."
UPDATES = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
FIRST_DOCUMENT = (2016, 4)
EXCLUDED_TITLES = {"mariner release notes"}
MONTHS = {name: number for number, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
RANK = {"critical": 0, "important": 1}
THIS = sys.modules[__name__]


def document_month(ident):
    match = re.fullmatch(r"([0-9]{4})-([A-Za-z]{3})", ident or "")
    if not match or match.group(2).lower() not in MONTHS:
        return None
    return int(match.group(1)), MONTHS[match.group(2).lower()]


def selected(updates_raw, years):
    """The monthly documents to read: April 2016 onward, inside the years, never Mariner Release Notes."""
    chosen = []
    for item in json.loads(updates_raw).get("value") or []:
        if not isinstance(item, dict):
            continue
        month = document_month(item.get("ID"))
        title = str(item.get("DocumentTitle") or "").strip().lower()
        url = base.https(item.get("CvrfUrl"), HOSTS)
        if month is None or month < FIRST_DOCUMENT or title in EXCLUDED_TITLES or month[0] not in years or url is None:
            continue
        chosen.append((month, item["ID"], url))
    return sorted(chosen)


def fetch(fetcher, years, context):
    documents = {"updates.json": fetcher.get(UPDATES, accept="application/json")}
    for _month, ident, url in selected(documents["updates.json"].raw, years):
        documents["cvrf/" + ident + ".json"] = fetcher.get(url, MAX_BYTES, accept="application/json")
    return documents


def _families(tree):
    families = {}
    for branch in (tree or {}).get("Branch") or []:
        for family in branch.get("Items") or []:
            for product in family.get("Items") or []:
                if isinstance(product, dict) and product.get("ProductID"):
                    families[str(product["ProductID"])] = str(family.get("Name") or "")
    return families


def rows_from(document, month_day, raw):
    value = json.loads(document.raw)
    if str(value.get("DocumentTitle", {}).get("Value", "")).strip().lower() in EXCLUDED_TITLES:
        return [], 0
    families = _families(value.get("ProductTree"))
    rows, seen = [], 0
    for item in value.get("Vulnerability") or []:
        cve = str(item.get("CVE") or "")
        if not base.CVE_ID.fullmatch(cve):
            continue
        seen += 1
        severities, exploited = set(), False
        for threat in item.get("Threats") or []:
            description = str((threat.get("Description") or {}).get("Value") or "")
            if threat.get("Type") == 3:
                severities.add(description.strip())
            elif threat.get("Type") == 1 and re.search(r"(?:^|;)\s*Exploited:\s*Yes\b", description, re.I):
                exploited = True
        severity = min(severities, key=lambda name: RANK.get(name.lower(), 9), default=None)
        if not exploited and (severity or "").lower() not in RANK:
            continue
        affected = set()
        for status in item.get("ProductStatuses") or []:
            if status.get("Type") == 3:
                affected.update(families.get(str(ident), "") for ident in status.get("ProductID") or [])
        title = base.text((item.get("Title") or {}).get("Value"))
        rows.append(base.make_row(
            THIS, native_id=cve, title=title or cve, url="https://msrc.microsoft.com/update-guide/vulnerability/" + cve,
            published=month_day, cve=[cve], severity=severity, vendor_raw=["Microsoft"], product_raw=affected - {""},
            exploited_flag=exploited, retrieved=document.fetched_at, raw_sha256=document.sha256))
    return rows, seen


def priority(row):
    return (row["exploited_flag"] is not True, RANK.get((row["severity"] or "").lower(), 9), row["native_id"])


def parse(documents, years, context):
    rows, upstream = [], {}
    for month, ident, _url in selected(documents["updates.json"].raw, years):
        document = documents.get("cvrf/" + ident + ".json")
        if document is None:
            continue
        initial = base.day(json.loads(document.raw).get("DocumentTracking", {}).get("InitialReleaseDate")) or "{:04d}-{:02d}-01".format(*month)
        found, seen = rows_from(document, initial, document.raw)
        upstream[month[0]] = upstream.get(month[0], 0) + seen
        rows.extend(found)
    # A CVE listed again in a later month keeps its first month.
    rows = base.unique(rows)
    kept, dropped = base.cap(rows, priority)
    return kept, {"upstream": upstream, "capped": dropped}
