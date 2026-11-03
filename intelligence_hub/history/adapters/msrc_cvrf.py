"""Microsoft Security Update Guide entries from the MSRC CVRF API, April 2016 onward.

One row per CVE that Microsoft rated Critical or Important, or marked exploited, in a
monthly security update document. The update list also carries documents labelled
"Mariner Release Notes" under ids such as 1999-Sep: they describe Azure Linux
packages, not Windows-era updates, and are excluded by title and by date.

The regular monthly documents also list third-party CVEs that Microsoft ships in Azure
Linux (formerly CBL-Mariner) packages, under the families "Mariner", "Azure Linux" and
"Open Source Software". A CVE becomes a row only when at least one product it affects
is a Microsoft product: a product in any other family, or a product the document lists
without a family whose name is not an Azure Linux or CBL-Mariner package. For those
third-party CVEs Microsoft's Title field holds the upstream description, so a title
that reads like a description is replaced by the CVE id and its Microsoft families.
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
FILTER = ("Microsoft severity Critical or Important, or Exploited:Yes in the CVE's exploitability threat, "
          "for CVEs that affect at least one Microsoft product (Azure Linux, CBL-Mariner and open-source package CVEs are left out); "
          "the first 1,500 a year by exploited, severity and CVE id")
LICENCE = "MSRC CVRF API; CVE ids, Microsoft titles, severities, product families, dates and links only."
UPDATES = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
FIRST_DOCUMENT = (2016, 4)
EXCLUDED_TITLES = {"mariner release notes"}
# Families that hold third-party packages, not Microsoft products.
THIRD_PARTY_FAMILIES = {"Mariner", "Azure Linux", "Open Source Software"}
# A product listed without a family is a third-party package when its name says so
# ("cbl2 kernel 5.15.180.1-1", "azl3 qemu 8.2.0-16 on Azure Linux 3.0").
THIRD_PARTY_PRODUCT = re.compile(r"\b(?:CBL[- ]?Mariner|Azure Linux)\b|^(?:cm1|cbl2|azl3)\s", re.I)
NO_PRODUCT = {"", "none available"}
# Upstream descriptions that Microsoft files as the Title of a third-party CVE.
DESCRIPTION = re.compile(r"(?:It was discovered|A flaw (?:was found|in)|In the Linux kernel|An issue was discovered|"
                         r"A crafted|An? (?:[\w-]+ ){0,6}(?:issue|vulnerability|flaw|bug) (?:was|in|exists))\b", re.I)
MAX_HEADLINE = 160
MONTHS = {name: number for number, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
# Microsoft's severity ratings, highest first. Only Critical and Important admit a row on
# their own; the full order picks one rating when a CVE carries several, the same way every run.
RANK = {"critical": 0, "important": 1, "moderate": 2, "low": 3}
ADMITTED = {"critical", "important"}
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


def _names(tree):
    return {str(item["ProductID"]): str(item.get("Value") or "") for item in (tree or {}).get("FullProductName") or []
            if isinstance(item, dict) and item.get("ProductID")}


def microsoft_product(ident, families, names):
    """True for a Microsoft product, False for a third-party package or an unnamed product."""
    family = families.get(ident)
    if family:
        return family not in THIRD_PARTY_FAMILIES
    name = names.get(ident, "").strip()
    return name.lower() not in NO_PRODUCT and not THIRD_PARTY_PRODUCT.search(name)


def headline(title, cve, families):
    """Microsoft's title, or "CVE id: families" when the title is an upstream description."""
    if title and len(title) <= MAX_HEADLINE and not title.endswith(".") and not DESCRIPTION.match(title):
        return title
    return cve + (": " + ", ".join(sorted(families)) if families else "")


def severity_order(name):
    """Sort key for a severity: Microsoft's rank, then the name, so ties never depend on set order."""
    return (RANK.get((name or "").lower(), 9), name or "")


def highest(severities):
    """Microsoft's highest rating among severities, or None."""
    return min((name for name in severities if name), key=severity_order, default=None)


def combine(rows):
    """One row per CVE listed in several monthly documents.

    The earliest listing keeps its date, id, title and links; the CVE is flagged exploited
    when any listing says so and carries the highest severity any listing gives it.
    """
    groups = {}
    for row in rows:
        groups.setdefault(row["id"], []).append(row)
    combined = []
    for items in groups.values():
        items.sort(key=base.order)
        row = dict(items[0])
        if any(item["exploited_flag"] is True for item in items):
            row["exploited_flag"] = True
        row["severity"] = highest({item["severity"] for item in items})
        combined.append(row)
    return combined


def rows_from(document, month_day, raw):
    value = json.loads(document.raw)
    if str(value.get("DocumentTitle", {}).get("Value", "")).strip().lower() in EXCLUDED_TITLES:
        return [], 0
    families = _families(value.get("ProductTree"))
    names = _names(value.get("ProductTree"))
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
        severity = highest(severities)
        if not exploited and (severity or "").lower() not in ADMITTED:
            continue
        products = set()
        for status in item.get("ProductStatuses") or []:
            if status.get("Type") == 3:
                products.update(str(ident) for ident in status.get("ProductID") or [])
        microsoft = {ident for ident in products if microsoft_product(ident, families, names)}
        if not microsoft:
            continue
        affected = {families.get(ident, "") for ident in microsoft} - {""}
        title = headline(base.text((item.get("Title") or {}).get("Value"), maximum=400), cve, affected)
        rows.append(base.make_row(
            THIS, native_id=cve, title=base.text(title), url="https://msrc.microsoft.com/update-guide/vulnerability/" + cve,
            published=month_day, cve=[cve], severity=severity, vendor_raw=["Microsoft"], product_raw=affected,
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
    # A CVE listed again in a later month keeps its first month, with what any month adds.
    rows = base.unique(combine(rows))
    kept, dropped = base.cap(rows, priority)
    return kept, {"upstream": upstream, "capped": dropped}
