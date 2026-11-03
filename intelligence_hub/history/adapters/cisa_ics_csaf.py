"""CISA ICS advisories from CISA's CSAF repository (TLP:WHITE), 2010 onward.

The ROLIE feed lists every OT advisory with its id, title and CSAF document link;
each CSAF document gives the initial release date, CVE ids, and vendor and product
names. Rows link to the advisory's page on cisa.gov.
"""
import json
import re
import sys

from .. import base

ID = "cisa-ics-csaf"
SOURCE_ID = "cisa-ics-advisories"
SOURCE_NAME = "CISA ICS Advisories (CSAF)"
SOURCE_CLASS = "government-cert"
PUBLISHER_VENDOR = None
COUNTRY = "US"
KIND = "advisory"
FIRST_YEAR = 2010
LAST_YEAR = None
HOME = "https://www.cisa.gov/news-events/cybersecurity-advisories"
HOSTS = ("raw.githubusercontent.com",)
MAX_BYTES = 16 * 1024 * 1024
FILTER = None
LICENCE = "US Government work, TLP:WHITE (cisagov/CSAF); ids, titles, dates, CVE ids, vendor and product names and links only."
FEED = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json"
DOCUMENT = re.compile(r"https://raw\.githubusercontent\.com/cisagov/CSAF/develop/csaf_files/OT/white/[0-9]{4}/[a-z0-9-]+\.json")
ADVISORY = re.compile(r"ICS[A-Z]{0,2}-[0-9]{2}-[0-9]{3}-[0-9]{2}[A-Z]{0,2}")
THIS = sys.modules[__name__]


def entries(feed_raw):
    """[(id, title, published day, document url)] from the ROLIE feed."""
    found = []
    for entry in (json.loads(feed_raw).get("feed") or {}).get("entry") or []:
        ident = str(entry.get("id") or "").upper()
        links = [link.get("href") for link in entry.get("link") or [] if isinstance(link, dict) and link.get("rel") == "self"]
        url = (entry.get("content") or {}).get("src") or (links[0] if links else None)
        if ADVISORY.fullmatch(ident) and isinstance(url, str) and DOCUMENT.fullmatch(url):
            found.append((ident, base.text(entry.get("title")), base.day(entry.get("published")), url))
    return sorted(found)


def fetch(fetcher, years, context):
    documents = {"feed.json": fetcher.get(FEED, MAX_BYTES, accept="application/json")}
    for ident, _title, published, url in entries(documents["feed.json"].raw):
        if published and int(published[:4]) in years:
            document = fetcher.get(url, MAX_BYTES, accept="application/json", optional=True)
            if document is not None:
                documents["csaf/" + ident.lower() + ".json"] = document
    return documents


def _branches(nodes, vendors, products):
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        if node.get("category") == "vendor":
            vendors.add(str(node.get("name") or ""))
        elif node.get("category") in ("product_name", "product_family"):
            products.add(str(node.get("name") or ""))
        _branches(node.get("branches"), vendors, products)


def parse(documents, years, context):
    rows, upstream, missing = [], {}, {}
    for ident, title, published, url in entries(documents["feed.json"].raw):
        if not published or int(published[:4]) not in years:
            continue
        document = documents.get("csaf/" + ident.lower() + ".json")
        if document is None:
            year = int(published[:4])
            upstream[year] = upstream.get(year, 0) + 1
            missing[year] = missing.get(year, 0) + 1
            continue
        value = json.loads(document.raw)
        head = value.get("document") or {}
        tracking = head.get("tracking") or {}
        published = base.day(tracking.get("initial_release_date")) or published
        year = int(published[:4])
        upstream[year] = upstream.get(year, 0) + 1
        if year not in years:
            continue
        page = next((base.https(item.get("url"), {"www.cisa.gov"}) for item in head.get("references") or []
                     if isinstance(item, dict) and item.get("category") == "self" and base.https(item.get("url"), {"www.cisa.gov"})),
                    "https://www.cisa.gov/news-events/ics-advisories/" + ident.lower())
        vendors, products = set(), set()
        _branches((value.get("product_tree") or {}).get("branches"), vendors, products)
        rows.append(base.make_row(
            THIS, native_id=ident, title=head.get("title") or title, url=page, published=published,
            updated=base.day(tracking.get("current_release_date")),
            cve=[item.get("cve") for item in value.get("vulnerabilities") or [] if base.CVE_ID.fullmatch(str(item.get("cve") or ""))],
            severity=(head.get("aggregate_severity") or {}).get("text"), vendor_raw=vendors - {""}, product_raw=products - {""},
            retrieved=document.fetched_at, raw_sha256=document.sha256))
    return base.unique(rows), {"upstream": upstream, "missing": missing}
