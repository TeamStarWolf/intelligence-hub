"""Oracle Critical Patch Updates and Security Alerts from Oracle's security RSS, 2005 onward.

The feed lists every Critical Patch Update and Security Alert since October 2005 (the
January and April 2005 updates were posted to it in October 2005). Titles, dates and
links come from the feed; links are upgraded to HTTPS.

Many 2005 to 2009 feed links point at retired technetwork and technology pages. Three
of those advisories now live under /security-alerts/ and are linked there; the others
no longer resolve anywhere on oracle.com, so they are not published and coverage counts
them. An item whose title names an earlier month than its feed date (the January and
April 2005 updates carry the October 2005 posting date) has no publication date in the
feed, so it is not published either, and coverage counts it.
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
# Retired feed links (after the HTTPS upgrade), checked with a browser user agent on 2026-11-03.
# MOVED: the advisory answers 200 at its /security-alerts/ address. DEAD: the link and the
# /security-alerts/ address for its month both answer 404.
MOVED = {
    "https://www.oracle.com/technetwork/topics/security/cpujul2005-090619.html": "https://www.oracle.com/security-alerts/cpujul2005.html",
    "https://www.oracle.com/technetwork/topics/security/cpuoct2005-090497.html": "https://www.oracle.com/security-alerts/cpuoct2005.html",
    "https://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuoct2007.html": "https://www.oracle.com/security-alerts/cpuoct2007.html",
}
DEAD = {"https://www.oracle.com/technology/deploy/security/pdf/" + name for name in ("cpu-jan-2005_advisory.pdf", "cpuapr2005.pdf")} | {
    "https://www.oracle.com/technetwork/topics/security/" + name + ".html" for name in (
        "cpujan2006-082403", "cpuapr2006-090826", "cpuoct2006-095368", "cpujan2007-101493", "cpuapr2007-090632",
        "cpuoct2007-092913", "cpujan2008-086860", "cpuapr2008-082075", "cpujul2008-090335", "cpuoct2008-100299",
        "cpujan2009-097901", "cpuapr2009-099563", "cpujul2009-091332", "cpuoct2009-096303")}
TITLE_MONTH = re.compile(r"\b([A-Za-z]+)\s+([0-9]{4})\s*$")
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


def title_month(title):
    """(year, month) named at the end of a title such as "Critical Patch Update - January 2005", or None."""
    match = TITLE_MONTH.search(title or "")
    number = base.month_number(match.group(1)) if match else None
    return (int(match.group(2)), number) if number else None


def listed_later(title, published):
    """True when the title names an earlier month than the feed date: the feed date is a posting date."""
    named = title_month(title)
    return named is not None and named < (int(published[:4]), int(published[5:7]))


def fetch(fetcher, years, context):
    return {"feed.xml": fetcher.get(FEED, MAX_BYTES, accept="application/rss+xml")}


def parse(documents, years, context):
    document = documents["feed.xml"]
    rows, upstream, missing, dead, undated = [], {}, {}, {}, {}
    for item in base.xml(document.raw).iter("item"):
        title = base.text(item.findtext("title"))
        feed_url = base.https(link(item.findtext("link")), set(HOSTS))
        published = rss_day(item.findtext("pubDate"))
        if not published or int(published[:4]) not in years:
            continue
        year = int(published[:4])
        upstream[year] = upstream.get(year, 0) + 1
        if not title or not feed_url:
            missing[year] = missing.get(year, 0) + 1
            continue
        if feed_url in DEAD:
            dead[year] = dead.get(year, 0) + 1
            continue
        if listed_later(title, published):
            undated[year] = undated.get(year, 0) + 1
            continue
        url = MOVED.get(feed_url, feed_url)
        # The native id keeps the feed link's stem, so a moved page keeps its row id.
        stem = re.sub(r"\.[a-z]+$", "", feed_url.rstrip("/").rsplit("/", 1)[-1])
        native = re.sub(r"[^A-Za-z0-9._-]+", "-", stem)[:60].strip("-.") or base.sha256(url.encode())[:16]
        kind = "bulletin" if "critical patch update" in title.lower() else "advisory"
        rows.append(base.make_row(THIS, native_id=native, title=title, url=url, published=published, kind=kind,
                                  cve=base.cves(title), vendor_raw=["Oracle"], retrieved=document.fetched_at,
                                  raw_sha256=document.sha256))
    return base.unique(rows), {"upstream": upstream, "missing": missing, "dead": dead, "undated": undated}
