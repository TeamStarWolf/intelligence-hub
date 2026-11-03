"""Mozilla Foundation Security Advisories from mozilla/foundation-security-advisories, 2005 onward.

One tarball of the repository's main branch is read in memory (nothing is extracted
to disk). Each announce/YYYY/mfsaYYYY-NN file gives the title, announcement date and
impact in its front matter; CVE ids are read from the file. The repository is MPL-2.0.
"""
import io
import re
import sys
import tarfile

from .. import base

ID = "mozilla-mfsa"
SOURCE_ID = "mozilla-mfsa"
SOURCE_NAME = "Mozilla Foundation Security Advisories"
SOURCE_CLASS = "vendor-primary"
PUBLISHER_VENDOR = "vendor:mozilla"
COUNTRY = "US"
KIND = "advisory"
FIRST_YEAR = 2005
LAST_YEAR = None
HOME = "https://www.mozilla.org/en-US/security/advisories/"
HOSTS = ("codeload.github.com",)
MAX_BYTES = 64 * 1024 * 1024
FILTER = None
LICENCE = "MPL-2.0 (mozilla/foundation-security-advisories); ids, titles, dates, impact, CVE ids and links only."
TARBALL = "https://codeload.github.com/mozilla/foundation-security-advisories/tar.gz/refs/heads/main"
MEMBER = re.compile(r"[^/]+/announce/([0-9]{4})/mfsa([0-9]{4})-([0-9]{2,3})\.(?:md|yml|yaml)")
THIS = sys.modules[__name__]


def fetch(fetcher, years, context):
    return {"repository.tar.gz": fetcher.get(TARBALL, MAX_BYTES, accept="application/gzip")}


def advisories(raw):
    """{(year, number): file bytes} for every advisory file in the tarball."""
    found = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            match = MEMBER.fullmatch(member.name)
            if not match or not member.isfile() or member.size > 2 * 1024 * 1024 or match.group(1) != match.group(2):
                continue
            stream = archive.extractfile(member)
            found[(int(match.group(1)), match.group(3))] = stream.read() if stream else b""
    return found


def parse(documents, years, context):
    document = documents["repository.tar.gz"]
    rows, upstream, missing = [], {}, {}
    for (year, number), raw in sorted(advisories(document.raw).items()):
        if year not in years:
            continue
        upstream[year] = upstream.get(year, 0) + 1
        meta = base.front_matter(raw)
        published = base.day(str(meta.get("announced") or "")) or base.long_date(str(meta.get("announced") or ""))
        title = base.text(meta.get("title"))
        if not published or not title or int(published[:4]) != year:
            missing[year] = missing.get(year, 0) + 1
            continue
        ident = "MFSA-" + str(year) + "-" + number
        fixed = meta.get("fixed_in") if isinstance(meta.get("fixed_in"), list) else []
        rows.append(base.make_row(
            THIS, native_id=ident, title=title, url="https://www.mozilla.org/en-US/security/advisories/mfsa" + str(year) + "-" + number + "/",
            published=published, cve=base.cves(raw.decode("utf-8", "replace")), severity=str(meta.get("impact") or "") or None,
            vendor_raw=["Mozilla"], product_raw=[re.sub(r"\s+[0-9][0-9.]*.*$", "", str(item)) for item in fixed],
            retrieved=document.fetched_at, raw_sha256=document.sha256))
    return rows, {"upstream": upstream, "missing": missing}
