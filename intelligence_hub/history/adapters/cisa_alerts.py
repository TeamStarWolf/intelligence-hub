"""CISA (and US-CERT) alerts and cybersecurity advisories listed in cisa.gov's sitemap, 2004 onward.

The sitemap lists every alert under /news-events/alerts/YYYY/MM/DD/<slug> and every
joint advisory under /news-events/cybersecurity-advisories/<id>. The title is read
from the head of each page (only the first bytes are fetched); an alert's date is
the one in its URL, and an advisory's date is the first <time datetime> on its page.
"""
import re
import sys

from .. import base

ID = "cisa-alerts"
SOURCE_ID = "cisa-alerts"
SOURCE_NAME = "CISA Alerts and Advisories"
SOURCE_CLASS = "government-cert"
PUBLISHER_VENDOR = None
COUNTRY = "US"
KIND = "advisory"
FIRST_YEAR = 2004
LAST_YEAR = None
HOME = "https://www.cisa.gov/news-events/cybersecurity-advisories"
HOSTS = ("www.cisa.gov",)
MAX_BYTES = 8 * 1024 * 1024
HEAD_BYTES = 16 * 1024
ADVISORY_BYTES = 96 * 1024
FILTER = None
LICENCE = "US Government work (cisa.gov); titles, dates and links only."
SITEMAP = "https://www.cisa.gov/default/sitemap.xml"
ALERT = re.compile(r"https://www\.cisa\.gov/news-events/alerts/([0-9]{4})/([0-9]{2})/([0-9]{2})/([a-z0-9-]{1,200})")
ADVISORY = re.compile(r"https://www\.cisa\.gov/news-events/cybersecurity-advisories/(aa[0-9]{2}-[0-9]{3}[a-z])")
THIS = sys.modules[__name__]


def alert_id(url, match):
    """alert-YYYYMMDD-<slug>; a slug over 40 characters is cut and given 8 hex of the URL's sha256."""
    slug = match.group(4)
    if len(slug) > 40:
        slug = slug[:40].strip("-") + "-" + base.sha256(url.encode("utf-8"))[:8]
    return "alert-" + "".join(match.group(1, 2, 3)) + "-" + slug


def pages(sitemap_raw):
    """[(url, kind, native id, day or None, year)] from the sitemap."""
    found = []
    for element in base.xml(sitemap_raw).iter():
        if not element.tag.endswith("loc") or not element.text:
            continue
        url = element.text.strip()
        alert = ALERT.fullmatch(url)
        if alert:
            stamp = base.day("-".join(alert.group(1, 2, 3)))
            if stamp:
                native = alert_id(url, alert)
                found.append((url, "alert", native, stamp, int(alert.group(1))))
            continue
        advisory = ADVISORY.fullmatch(url)
        if advisory:
            found.append((url, "advisory", advisory.group(1).upper(), None, 2000 + int(advisory.group(1)[2:4])))
    return sorted(set(found))


def fetch(fetcher, years, context):
    documents = {"sitemap.xml": fetcher.get(SITEMAP, MAX_BYTES, accept="application/xml")}
    for url, kind, native, _stamp, year in pages(documents["sitemap.xml"].raw):
        if year in years:
            limit = HEAD_BYTES if kind == "alert" else ADVISORY_BYTES
            page = fetcher.get(url, limit, accept="text/html", optional=True, head=True)
            if page is not None:
                documents["page/" + native + ".html"] = page
    return documents


def page_title(raw):
    value = raw.decode("utf-8", "replace")
    match = re.search(r"<title[^>]*>(.*?)</title>", value, re.S | re.I)
    if not match:
        return None
    title = base.text(match.group(1))
    return re.sub(r"\s*\|\s*CISA$", "", title).strip() or None


def page_day(raw):
    match = re.search(r'<time[^>]*datetime="([0-9]{4}-[0-9]{2}-[0-9]{2})', raw.decode("utf-8", "replace"))
    return base.day(match.group(1)) if match else None


def parse(documents, years, context):
    rows, upstream, missing = [], {}, {}
    for url, kind, native, stamp, year in pages(documents["sitemap.xml"].raw):
        if year not in years:
            continue
        upstream[year] = upstream.get(year, 0) + 1
        page = documents.get("page/" + native + ".html")
        title = page_title(page.raw) if page else None
        published = stamp or (page_day(page.raw) if page else None)
        if not title or not published or int(published[:4]) != year:
            missing[year] = missing.get(year, 0) + 1
            continue
        rows.append(base.make_row(THIS, native_id=native, title=title, url=url, published=published,
                                  cve=base.cves(title), retrieved=page.fetched_at, raw_sha256=page.sha256))
    return base.unique(rows), {"upstream": upstream, "missing": missing}
