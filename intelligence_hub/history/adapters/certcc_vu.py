"""CERT/CC Vulnerability Notes from the kb.cert.org API, December 2000 onward.

The yearly summary lists the note ids published in a year; each note's detail gives
its name, first-published and updated dates, CVE ids and the CA-series advisory it
cross-references (read by the certcc-ca adapter). Note bodies are not kept.
"""
import json
import re
import sys

from .. import base

ID = "certcc-vu"
SOURCE_ID = "certcc-vu"
SOURCE_NAME = "CERT/CC Vulnerability Notes"
SOURCE_CLASS = "government-cert"
PUBLISHER_VENDOR = None
COUNTRY = "US"
KIND = "note"
FIRST_YEAR = 2000
LAST_YEAR = None
HOME = "https://kb.cert.org/vuls/"
HOSTS = ("kb.cert.org",)
MAX_BYTES = 2 * 1024 * 1024
FILTER = None
LICENCE = "CERT/CC Vulnerability Notes Database; ids, names, dates, CVE ids and links only."
SUMMARY = "https://kb.cert.org/vuls/api/{year}/summary/"
DETAIL = "https://kb.cert.org/vuls/api/{number}/"
THIS = sys.modules[__name__]


def note_ids(raw):
    value = json.loads(raw)
    return sorted({int(match.group(1)) for note in value.get("notes") or [] for match in [re.fullmatch(r"VU#([0-9]{1,8})", str(note))] if match})


def fetch(fetcher, years, context):
    documents = {}
    for year in sorted(years):
        if year < FIRST_YEAR:
            continue
        summary = fetcher.get(SUMMARY.format(year=year), accept="application/json", optional=True)
        if summary is None:
            continue
        documents["summary/" + str(year) + ".json"] = summary
        for number in note_ids(summary.raw):
            detail = fetcher.get(DETAIL.format(number=number), MAX_BYTES, accept="application/json", optional=True)
            if detail is not None:
                documents["vu/" + str(number) + ".json"] = detail
    return documents


def details(documents, years):
    """(year, number, detail dict, document) for every note listed in a yearly summary."""
    found = []
    for year in sorted(years):
        summary = documents.get("summary/" + str(year) + ".json")
        if summary is None:
            continue
        for number in note_ids(summary.raw):
            document = documents.get("vu/" + str(number) + ".json")
            if document is not None:
                found.append((year, number, json.loads(document.raw), document))
    return found


def parse(documents, years, context):
    rows, upstream, missing = [], {}, {}
    for year in sorted(years):
        summary = documents.get("summary/" + str(year) + ".json")
        if summary is not None:
            upstream[year] = len(note_ids(summary.raw))
    seen = set()
    for year, number, detail, document in details(documents, years):
        seen.add((year, number))
        published = base.day(detail.get("datefirstpublished"))
        name = base.text(detail.get("name"))
        if not published or not name:
            missing[year] = missing.get(year, 0) + 1
            continue
        rows.append(base.make_row(
            THIS, native_id="VU-" + str(number), title=name, url="https://kb.cert.org/vuls/id/" + str(number),
            published=published, updated=base.day(detail.get("dateupdated")), cve=base.cves(detail.get("cveids") or []),
            retrieved=document.fetched_at, raw_sha256=document.sha256))
    for year in upstream:
        listed = upstream[year] - sum(1 for item in seen if item[0] == year)
        if listed > 0:
            missing[year] = missing.get(year, 0) + listed
    return base.unique(rows), {"upstream": upstream, "missing": missing}
