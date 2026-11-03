"""CERT/CC Advisories (the CA series, 1988 to 2004) as cross-referenced by Vulnerability Notes.

The CA series has no structured index: today each year is one compiled PDF on the
SEI library page. This adapter reads no PDF. It lists the CA ids that the
Vulnerability Notes cite in their certadvisory field, with the CVE ids of those notes,
and links each id to its year's SEI page. The date is the earliest public date of a
citing note inside the advisory's own year, so date_basis is "cross-reference".
"""
import re
import sys

from .. import base
from . import certcc_vu

ID = "certcc-ca"
SOURCE_ID = "certcc-advisories"
SOURCE_NAME = "CERT/CC Advisories (CA series)"
SOURCE_CLASS = "government-cert"
PUBLISHER_VENDOR = None
COUNTRY = "US"
KIND = "advisory"
FIRST_YEAR = 1998
LAST_YEAR = 2004
HOME = "https://www.sei.cmu.edu/library/1998-cert-advisories/"
HOSTS = certcc_vu.HOSTS
CACHE = certcc_vu.ID
MAX_BYTES = certcc_vu.MAX_BYTES
FILTER = "CA ids cross-referenced by at least one Vulnerability Note; advisories no note cites are not listed"
LICENCE = "CERT/CC; CA ids, cross-reference dates, CVE ids and links only."
YEAR_PAGE = "https://www.sei.cmu.edu/library/{year}-cert-advisories/"
CA_ID = re.compile(r"\bCA-((?:19|20)[0-9]{2})-([0-9]{2})\b")
THIS = sys.modules[__name__]


def fetch(fetcher, years, context):
    # Every note year can cite an older CA id, so read every note year the VU adapter covers.
    return certcc_vu.fetch(fetcher, set(range(certcc_vu.FIRST_YEAR, max(years) + 1)) | set(years), context)


def parse(documents, years, context):
    note_years = set(range(certcc_vu.FIRST_YEAR, 2100))
    found = {}
    for _year, number, detail, document in certcc_vu.details(documents, note_years):
        for match in CA_ID.finditer(str(detail.get("certadvisory") or "")):
            year = int(match.group(1))
            if year not in years:
                continue
            ident = "CA-" + match.group(1) + "-" + match.group(2)
            item = found.setdefault(ident, {"year": year, "notes": [], "cves": set()})
            item["notes"].append((number, detail, document))
            item["cves"].update(base.cves(detail.get("cveids") or []))
    rows, missing = [], {}
    for ident, item in sorted(found.items()):
        dates = sorted((date_value, number, detail, document) for number, detail, document in item["notes"]
                       for date_value in [base.day(detail.get("publicdate")), base.day(detail.get("datefirstpublished"))]
                       if date_value and int(date_value[:4]) == item["year"])
        if not dates:
            missing[item["year"]] = missing.get(item["year"], 0) + 1
            continue
        published, number, detail, document = dates[0]
        title = "CERT Advisory " + ident + " (cited by VU#" + str(number) + ": " + base.text(detail.get("name"), 160) + ")"
        rows.append(base.make_row(
            THIS, native_id=ident, title=title, url=YEAR_PAGE.format(year=item["year"]), published=published,
            cve=item["cves"], retrieved=document.fetched_at, raw_sha256=document.sha256, date_basis="cross-reference"))
    upstream = {}
    for row in rows:
        year = int(row["published"][:4])
        upstream[year] = upstream.get(year, 0) + 1
    for year, count in missing.items():
        upstream[year] = upstream.get(year, 0) + count
    return rows, {"upstream": upstream, "missing": missing}
