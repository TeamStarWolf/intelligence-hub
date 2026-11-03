"""Microsoft security bulletins, MS98-001 to MS17-023.

The bulletin list comes from the security-updates table of contents (toc.json).
BulletinSearch.xlsx supplies the posted date, title, severity, affected products and
CVE ids for the bulletins it lists (it starts in 2004 and is complete from about 2009).
Every bulletin it does not list is read from its own page in Markdown form: the H2
heading is the title, "Published:" the date and the H1 suffix the severity.
"""
import io
import json
import re
import sys
import zipfile
from datetime import date, timedelta

from .. import base

ID = "msrc-bulletins"
SOURCE_ID = "microsoft-bulletins"
SOURCE_NAME = "Microsoft Security Bulletins"
SOURCE_CLASS = "vendor-primary"
PUBLISHER_VENDOR = "vendor:microsoft"
COUNTRY = "US"
KIND = "bulletin"
FIRST_YEAR = 1998
LAST_YEAR = 2017
HOME = "https://learn.microsoft.com/en-us/security-updates/"
HOSTS = ("learn.microsoft.com", "download.microsoft.com")
MAX_BYTES = 8 * 1024 * 1024
FILTER = None
LICENCE = "Microsoft Learn content; ids, titles, dates, severities and links only."
TOC = "https://learn.microsoft.com/en-us/security-updates/toc.json"
XLSX = "https://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx"
PAGE = "https://learn.microsoft.com/en-us/security-updates/securitybulletins/{year}/{ident}"
BULLETIN = re.compile(r"securitybulletins/([0-9]{4})/(ms[0-9]{2}-[0-9]{3})$", re.I)
SEVERITY = {"critical": 4, "important": 3, "moderate": 2, "low": 1}
NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
THIS = sys.modules[__name__]


def bulletins(toc_raw):
    """{bulletin id: (year, page url)} from toc.json."""
    found = {}

    def walk(nodes):
        for node in nodes:
            if not isinstance(node, dict):
                continue
            match = BULLETIN.search(str(node.get("href", "")))
            if match:
                ident = match.group(2).upper()
                found[ident] = (int(match.group(1)), PAGE.format(year=match.group(1), ident=ident.lower()))
            walk(node.get("children") or [])
    walk(json.loads(toc_raw).get("items") or [])
    return found


def _column(ref):
    letters = re.match(r"[A-Z]+", ref).group(0)
    number = 0
    for letter in letters:
        number = number * 26 + ord(letter) - 64
    return number - 1


def workbook(raw):
    """Rows of the first sheet as lists of strings (shared strings resolved)."""
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        base.require(sum(item.file_size for item in archive.infolist()) <= 256 * 1024 * 1024, "BulletinSearch.xlsx expands too far.")
        strings = []
        if "xl/sharedStrings.xml" in archive.namelist():
            for item in base.xml(archive.read("xl/sharedStrings.xml")).findall("m:si", NS):
                strings.append("".join(node.text or "" for node in item.iter("{" + NS["m"] + "}t")))
        sheet = base.xml(archive.read("xl/worksheets/sheet1.xml"))
    rows = []
    for row in sheet.iter("{" + NS["m"] + "}row"):
        values = {}
        for cell in row.findall("m:c", NS):
            value = cell.find("m:v", NS)
            if value is None or value.text is None:
                inline = cell.find("m:is", NS)
                text = "".join(node.text or "" for node in inline.iter("{" + NS["m"] + "}t")) if inline is not None else ""
            else:
                text = strings[int(value.text)] if cell.get("t") == "s" else value.text
            values[_column(cell.get("r"))] = text
        if values:
            rows.append([values.get(index, "") for index in range(max(values) + 1)])
    return rows


def _excel_day(value):
    try:
        return (date(1899, 12, 30) + timedelta(days=int(float(value)))).isoformat()
    except (TypeError, ValueError, OverflowError):
        return base.day(value) or base.long_date(value)


def from_workbook(raw):
    """{bulletin id: {published, title, severity, products, cves}} from BulletinSearch.xlsx."""
    rows = workbook(raw)
    header = [value.strip().lower() for value in rows[0]]
    need = {"date posted", "bulletin id", "severity", "title", "affected product", "cves"}
    base.require(need <= set(header), "BulletinSearch.xlsx lacks an expected column.")
    at = {name: header.index(name) for name in need}
    found = {}
    for values in rows[1:]:
        values = values + [""] * (len(header) - len(values))
        ident = values[at["bulletin id"]].strip().upper()
        if not re.fullmatch(r"MS[0-9]{2}-[0-9]{3}", ident):
            continue
        item = found.setdefault(ident, {"published": None, "title": "", "severity": None, "products": set(), "cves": set()})
        posted = _excel_day(values[at["date posted"]])
        if posted and (item["published"] is None or posted < item["published"]):
            item["published"] = posted
        item["title"] = item["title"] or base.text(values[at["title"]])
        severity = values[at["severity"]].strip()
        if SEVERITY.get(severity.lower(), 0) > SEVERITY.get((item["severity"] or "").lower(), 0):
            item["severity"] = severity
        if values[at["affected product"]].strip():
            item["products"].add(values[at["affected product"]].strip())
        item["cves"].update(base.cves(values[at["cves"]]))
    return found


# The posted date in the forms the bulletin pages use, newest form first: "Published:
# <date> | Updated: <date>", "Originally posted: <date>", "**Issued:** <date>", and the
# first revision line, "V1.0 (<date>): Bulletin published".
POSTED = (re.compile(r"Published:\s*([A-Za-z]+ [0-9]{1,2}, [0-9]{4})"),
          re.compile(r"Originally posted:?\**:?\s*([A-Za-z]+ [0-9]{1,2}, [0-9]{4})", re.I),
          re.compile(r"Issued:\**:?\s*([A-Za-z]+ [0-9]{1,2}, [0-9]{4})"),
          re.compile(r"\bV1\.0 \(([A-Za-z]+ [0-9]{1,2}, [0-9]{4})\):\s*Bulletin published"))
UPDATED = (re.compile(r"Published:\s*[A-Za-z]+ [0-9]{1,2}, [0-9]{4}\s*\|\s*Updated:\s*([A-Za-z]+ [0-9]{1,2}, [0-9]{4})"),
           re.compile(r"^Updated:\s*([A-Za-z]+ [0-9]{1,2}, [0-9]{4})", re.M),
           re.compile(r"Updated:\**:?\s*([A-Za-z]+ [0-9]{1,2}, [0-9]{4})"))


def _first(patterns, body):
    for pattern in patterns:
        match = pattern.search(body)
        if match and base.long_date(match.group(1)):
            return base.long_date(match.group(1))
    return None


def from_page(raw):
    """{published, updated, title, severity, cves} from a bulletin page in Markdown form, or None."""
    value = raw.decode("utf-8", "replace")
    # Only the front matter is cut: bulletin bodies have their own "---" table rules.
    body = value.split("\n---", 1)[-1] if value.startswith("---") else value
    heading = re.search(r"^#\s+Microsoft Security Bulletin\s+(MS[0-9]{2}-[0-9]{3})(?:\s*-\s*([A-Za-z]+))?", body, re.M)
    title = re.search(r"^##\s+(.+)$", body, re.M)
    published = _first(POSTED, body)
    if not (heading and title and published):
        return None
    return {"published": published, "updated": _first(UPDATED, body), "title": base.text(title.group(1)),
            "severity": heading.group(2), "cves": set(base.cves(body))}


def fetch(fetcher, years, context):
    documents = {"toc.json": fetcher.get(TOC, accept="application/json")}
    documents["BulletinSearch.xlsx"] = fetcher.get(XLSX, MAX_BYTES)
    listed = from_workbook(documents["BulletinSearch.xlsx"].raw)
    for ident, (year, url) in sorted(bulletins(documents["toc.json"].raw).items()):
        if year in years and not (ident in listed and listed[ident]["published"] and listed[ident]["title"]):
            page = fetcher.get(url + "?accept=text%2Fmarkdown", 2 * 1024 * 1024, accept="text/markdown", optional=True)
            if page is not None:
                documents["page/" + ident.lower() + ".md"] = page
    return documents


def parse(documents, years, context):
    listed = bulletins(documents["toc.json"].raw)
    sheet = documents.get("BulletinSearch.xlsx")
    workbook_rows = from_workbook(sheet.raw) if sheet else {}
    rows, upstream, missing = [], {}, {}
    for ident, (year, url) in sorted(listed.items()):
        if year not in years:
            continue
        item, source = workbook_rows.get(ident), sheet
        if not (item and item["published"] and item["title"]):
            page = documents.get("page/" + ident.lower() + ".md")
            item, source = (from_page(page.raw) if page else None), page
        if not item or not item["published"] or not item["title"]:
            # Unreadable: counted in the year its id names.
            upstream[year] = upstream.get(year, 0) + 1
            missing[year] = missing.get(year, 0) + 1
            continue
        # A bulletin is counted in the year it was published, which can differ from its id year.
        published_year = int(item["published"][:4])
        if published_year not in years:
            continue
        upstream[published_year] = upstream.get(published_year, 0) + 1
        rows.append(base.make_row(
            THIS, native_id=ident, title=item["title"], url=url, published=item["published"],
            updated=item.get("updated"), cve=item["cves"], severity=item["severity"], vendor_raw=["Microsoft"],
            product_raw=item.get("products", ()), retrieved=source.fetched_at, raw_sha256=source.sha256))
    return rows, {"upstream": upstream, "missing": missing}
