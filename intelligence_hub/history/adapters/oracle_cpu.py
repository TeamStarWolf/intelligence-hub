"""Oracle Critical Patch Updates and Security Alerts from Oracle's security RSS, 2005 onward.

The feed lists every Critical Patch Update and Security Alert since October 2005 (the
January and April 2005 updates were posted to it in October 2005). Titles, dates and
links come from the feed; links are upgraded to HTTPS.
"""
import re
import sys

from .. import base

ID = "oracle-cpu"
SOURCE_ID = "oracle-security-alerts"
SOURCE_NAME = "Oracle Critical Patch Updates and Security Alerts"
SOURCE_CLASS = "vendor-primary"
PUBLISHER_VENDOR = "vendor:oracle"
COUNTRY = "US"
KIND = "bulletin"
FIRST_YEAR = 2005
LAST_YEAR = None
HOME = "https://www.oracle.com/security-alerts/"
HOSTS = ("www.oracle.com",)
# One feed link names www-content.oracle.com, which no longer resolves; the same path on
# www.oracle.com redirects to the advisory (checked 2026-11-03).
RETIRED_HOSTS = {"http://www-content.oracle.com/": "https://www.oracle.com/"}
MAX_BYTES = 4 * 1024 * 1024
FILTER = None
LICENCE = "Oracle; titles, dates and links only."
FEED = "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml"
THIS = sys.modules[__name__]
MONTH = {name: number for number, name in enumerate(
    ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}


def rss_day(value):
    match = re.search(r"([0-9]{1,2})\s+([A-Za-z]{3})[a-z]*\s+([0-9]{4})", value or "")
    if not match or match.group(2).lower() not in MONTH:
        return None
    return base.day("{}-{:02d}-{:02d}".format(match.group(3), MONTH[match.group(2).lower()], int(match.group(1))))


def link(value):
    """The feed link, with a retired Oracle host replaced by www.oracle.com."""
    value = (value or "").strip()
    for old, new in RETIRED_HOSTS.items():
        if value.startswith(old) or value.startswith("https://" + old[len("http://"):]):
            return new + value.split("/", 3)[3]
    return value


def fetch(fetcher, years, context):
    return {"feed.xml": fetcher.get(FEED, MAX_BYTES, accept="application/rss+xml")}


def parse(documents, years, context):
    document = documents["feed.xml"]
    rows, upstream, missing = [], {}, {}
    for item in base.xml(document.raw).iter("item"):
        title = base.text(item.findtext("title"))
        url = base.https(link(item.findtext("link")), set(HOSTS))
        published = rss_day(item.findtext("pubDate"))
        if not published or int(published[:4]) not in years:
            continue
        year = int(published[:4])
        upstream[year] = upstream.get(year, 0) + 1
        if not title or not url:
            missing[year] = missing.get(year, 0) + 1
            continue
        stem = re.sub(r"\.[a-z]+$", "", url.rstrip("/").rsplit("/", 1)[-1])
        native = re.sub(r"[^A-Za-z0-9._-]+", "-", stem)[:60].strip("-.") or base.sha256(url.encode())[:16]
        kind = "bulletin" if "critical patch update" in title.lower() else "advisory"
        rows.append(base.make_row(THIS, native_id=native, title=title, url=url, published=published, kind=kind,
                                  cve=base.cves(title), vendor_raw=["Oracle"], retrieved=document.fetched_at,
                                  raw_sha256=document.sha256))
    return base.unique(rows), {"upstream": upstream, "missing": missing}
