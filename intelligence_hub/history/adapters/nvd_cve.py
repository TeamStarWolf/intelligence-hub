"""NVD CVE metadata for the CVEs that other history rows cite, and for no other CVE.

The NVD's yearly JSON 2.0 feeds (one gzip file per CVE year) are read as a stream,
one record at a time, and only cited CVEs are kept: the NVD publication date, the
primary CVSS base severity and score, CWE ids, CPE vendor and product names, and
CISA's KEV addition date where the NVD records one (which sets exploited_flag). The
title is a metadata line built from those fields; NVD description text is not kept.
"""
import gzip
import io
import json
import re
import sys

from .. import base

ID = "nvd-cve"
SOURCE_ID = "nvd"
SOURCE_NAME = "NIST National Vulnerability Database"
SOURCE_CLASS = "government-cert"
PUBLISHER_VENDOR = None
COUNTRY = "US"
KIND = "note"
FIRST_YEAR = 1998
LAST_YEAR = None
HOME = "https://nvd.nist.gov/"
HOSTS = ("nvd.nist.gov",)
MAX_BYTES = 96 * 1024 * 1024
REFERENCE_FILTER = True
FILTER = ("CVE ids cited by another history adapter's row only (never a bulk CVE list); "
          "the first 1,500 a year by KEV addition, CVSS base score and CVE id")
LICENCE = "NVD data, a US Government work; this product uses data from the NVD API but is not endorsed or certified by the NVD."
FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
# The 2002 feed carries every CVE year from 1999 to 2002; no earlier yearly feed exists.
FIRST_FEED_YEAR = 2002
THIS = sys.modules[__name__]
SEPARATORS = re.compile(r"[\s,]*")
METRICS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def feed_years(referenced):
    """The yearly feeds that hold the referenced CVEs (CVE years 1999 to 2001 are in the 2002 feed)."""
    return sorted({max(int(cve[4:8]), FIRST_FEED_YEAR) for cve in referenced if base.CVE_ID.fullmatch(cve)})


def fetch(fetcher, years, context):
    documents = {}
    for year in feed_years(context.get("referenced") or ()):
        document = fetcher.get(FEED.format(year=year), MAX_BYTES)  # the feed host answers 406 to Accept: application/gzip
        if document is not None:
            documents["nvdcve-2.0-" + str(year) + ".json.gz"] = document
    return documents


def records(raw, limit=4 * 1024 * 1024 * 1024):
    """Each item of the feed's "vulnerabilities" array, decoded one at a time from the gzip stream."""
    decoder = json.JSONDecoder()
    stream = io.TextIOWrapper(gzip.GzipFile(fileobj=io.BytesIO(raw)), encoding="utf-8")
    buffer, position, read, started = "", 0, 0, False
    while True:
        block = stream.read(1 << 22)
        read += len(block)
        base.require(read <= limit, "NVD feed expands past its bound.")
        buffer = buffer[position:] + block
        position = 0
        if not started:
            at = buffer.find('"vulnerabilities"')
            bracket = buffer.find("[", at) if at >= 0 else -1
            if bracket < 0:
                base.require(block, "NVD feed has no vulnerabilities array.")
                if at < 0:
                    buffer = buffer[-64:]
                continue
            position, started = bracket + 1, True
        while True:
            position = SEPARATORS.match(buffer, position).end()
            if buffer.startswith("]", position):
                return
            try:
                item, position = decoder.raw_decode(buffer, position)
            except json.JSONDecodeError:
                break
            yield item
        if not block:
            base.require(not SEPARATORS.sub("", buffer[position:]).strip("]}"), "NVD feed ended inside a record.")
            return


def metric(cve):
    for name in METRICS:
        for item in (cve.get("metrics") or {}).get(name) or []:
            data = item.get("cvssData") or {}
            if item.get("type") == "Primary" or len((cve.get("metrics") or {}).get(name) or []) == 1:
                severity = data.get("baseSeverity") or item.get("baseSeverity")
                score = data.get("baseScore")
                version = data.get("version") or name[len("cvssMetricV"):]
                if isinstance(score, (int, float)):
                    return str(version), float(score), str(severity or "")
    return None, None, None


def cpe_names(cve):
    vendors, products = set(), set()
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = str(match.get("criteria") or "").split(":")
                if len(parts) > 4 and match.get("vulnerable"):
                    vendors.add(parts[3].replace("_", " "))
                    products.add(parts[3].replace("_", " ") + " " + parts[4].replace("_", " "))
    return sorted(vendors)[:5], sorted(products)[:5]


def priority(row):
    score = row["severity"].rsplit(" ", 1)[-1] if row["severity"] else "0"
    try:
        value = float(score)
    except ValueError:
        value = 0.0
    return (row["exploited_flag"] is not True, -value, row["native_id"])


def parse(documents, years, context):
    referenced = set(context.get("referenced") or ())
    rows, upstream = [], {}
    for name in sorted(documents):
        document = documents[name]
        for item in records(document.raw):
            cve = item.get("cve") or {}
            ident = str(cve.get("id") or "")
            if ident not in referenced:
                continue
            published = base.day(cve.get("published"))
            if not published or int(published[:4]) not in years or str(cve.get("vulnStatus")) == "Rejected":
                continue
            year = int(published[:4])
            upstream[year] = upstream.get(year, 0) + 1
            version, score, severity = metric(cve)
            weaknesses = sorted({str(entry.get("value")) for weakness in cve.get("weaknesses") or []
                                 for entry in weakness.get("description") or [] if str(entry.get("value", "")).startswith("CWE-")})
            parts = [ident]
            if score is not None:
                parts.append("CVSS " + version + " " + format(score, ".1f") + (" " + severity.title() if severity else ""))
            if weaknesses:
                parts.append(", ".join(weaknesses[:3]))
            if cve.get("cisaExploitAdd"):
                parts.append("in KEV since " + str(cve["cisaExploitAdd"])[:10])
            vendors, products = cpe_names(cve)
            rows.append(base.make_row(
                THIS, native_id=ident, title="; ".join(parts), url="https://nvd.nist.gov/vuln/detail/" + ident,
                published=published, updated=base.day(cve.get("lastModified")), cve=[ident],
                severity=(severity.title() + " " + format(score, ".1f")) if score is not None and severity else None,
                vendor_raw=vendors, product_raw=products, exploited_flag=bool(cve.get("cisaExploitAdd")),
                retrieved=document.fetched_at, raw_sha256=document.sha256))
    kept, dropped = base.cap(base.unique(rows), priority)
    return kept, {"upstream": upstream, "capped": dropped}
