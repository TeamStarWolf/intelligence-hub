"""Ubuntu Security Notices from ubuntu.com's notices API, October 2004 onward, filtered.

The API pages every notice newest first. A notice is kept only when one of its CVE
ids is in the CISA KEV catalog or is cited by a row of another history adapter, so
that Ubuntu rows mark the fixes for vulnerabilities the rest of the archive already
tracks. notices.json carries no priority field, so no severity filter is applied.
"""
import json
import re
import sys

from .. import base

ID = "ubuntu-usn"
SOURCE_ID = "ubuntu-usn"
SOURCE_NAME = "Ubuntu Security Notices"
SOURCE_CLASS = "vendor-primary"
PUBLISHER_VENDOR = None
COUNTRY = None
KIND = "advisory"
FIRST_YEAR = 2004
LAST_YEAR = None
HOME = "https://ubuntu.com/security/notices"
HOSTS = ("ubuntu.com",)
MAX_BYTES = 16 * 1024 * 1024
PAGE_SIZE = 100
MAX_PAGES = 400
REFERENCE_FILTER = True
FILTER = "a CVE id in the CISA KEV catalog or cited by another history adapter's row (notices.json has no priority field)"
LICENCE = "Canonical, ubuntu.com; notice ids, titles, dates, CVE ids and links only."
PAGE = "https://ubuntu.com/security/notices.json?limit={limit}&offset={offset}"
NOTICE = re.compile(r"USN-[0-9]{1,5}-[0-9]{1,3}")
THIS = sys.modules[__name__]


def fetch(fetcher, years, context):
    documents, offset = {}, 0
    for number in range(MAX_PAGES):
        document = fetcher.get(PAGE.format(limit=PAGE_SIZE, offset=offset), MAX_BYTES, accept="application/json")
        documents["page/" + format(number, "04d") + ".json"] = document
        value = json.loads(document.raw)
        notices = value.get("notices") or []
        offset += len(notices)
        if not notices or offset >= int(value.get("total_results") or 0):
            break
        oldest = min((base.day(item.get("published")) or "9999") for item in notices)
        if int(oldest[:4]) < min(years):
            break
    return documents


def parse(documents, years, context):
    wanted = set(context.get("kev") or ()) | set(context.get("referenced") or ())
    notices = {}
    for name in sorted(documents):
        if not name.startswith("page/"):
            continue
        document = documents[name]
        for item in json.loads(document.raw).get("notices") or []:
            ident = str(item.get("id") or "")
            published = base.day(item.get("published"))
            if NOTICE.fullmatch(ident) and published and int(published[:4]) in years and ident not in notices:
                notices[ident] = (item, published, document)
    rows, upstream = [], {}
    for ident, (item, published, document) in sorted(notices.items()):
        year = int(published[:4])
        upstream[year] = upstream.get(year, 0) + 1
        found = base.cves(item.get("cves_ids") or [])
        if not set(found) & wanted:
            continue
        releases = [str(release.get("codename") or "") for release in item.get("releases") or [] if isinstance(release, dict)]
        rows.append(base.make_row(
            THIS, native_id=ident, title=item.get("title") or ident, url="https://ubuntu.com/security/notices/" + ident,
            published=published, cve=found, vendor_raw=["Canonical"], product_raw=[name for name in releases if name],
            retrieved=document.fetched_at, raw_sha256=document.sha256))
    kept, dropped = base.cap(rows)
    return kept, {"upstream": upstream, "capped": dropped}
