"""Write the history adapter fixtures under tests/history/fixtures/.

Each fixture is a handful of raw documents in the source's own format, holding only
identifiers, titles, dates, severities and CVE ids (no advisory bodies), and a
fixture.json that names them. The golden files are written by
`python -E -s -m intelligence_hub.history fixtures` and checked by `history check`.
Run this script only when a fixture itself must change; its output is deterministic.

  python -I tests/history/make_fixtures.py
"""
import gzip
import io
import json
import tarfile
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(HERE.parent.parent.parent))
FETCHED = "2026-11-03T00:00:00Z"


def dump(value):
    return (json.dumps(value, indent=1, sort_keys=True) + "\n").encode("utf-8")


def write(adapter, years, documents, context=None, stats=None):
    folder = HERE / adapter
    names = {}
    for name, raw in documents.items():
        path = folder / "documents" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        names[name] = name
    spec = {"adapter": adapter, "years": list(years), "fetched_at": FETCHED, "documents": names}
    if context:
        spec["context"] = {key: sorted(value) for key, value in context.items()}
    if stats is not None:
        spec["stats"] = stats
    (folder / "fixture.json").write_bytes(dump(spec))


def xlsx(rows):
    strings, index = [], {}

    def ref(value):
        if value not in index:
            index[value] = len(strings)
            strings.append(value)
        return index[value]

    lines = []
    for number, row in enumerate(rows, 1):
        cells = []
        for column, value in enumerate(row):
            letter = chr(65 + column)
            if isinstance(value, int):
                cells.append('<c r="%s%d"><v>%d</v></c>' % (letter, number, value))
            else:
                cells.append('<c r="%s%d" t="s"><v>%d</v></c>' % (letter, number, ref(value)))
        lines.append('<row r="%d">%s</row>' % (number, "".join(cells)))
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    sheet = '<?xml version="1.0"?><worksheet xmlns="%s"><sheetData>%s</sheetData></worksheet>' % (ns, "".join(lines))
    shared = '<?xml version="1.0"?><sst xmlns="%s">%s</sst>' % (ns, "".join("<si><t>%s</t></si>" % value for value in strings))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, data in (("xl/worksheets/sheet1.xml", sheet), ("xl/sharedStrings.xml", shared)):
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 3, 0, 0, 0))
            archive.writestr(info, data)
    return out.getvalue()


def msrc_bulletins():
    toc = {"items": [{"href": "./", "toc_title": "Security Updates", "children": [
        {"href": "securitybulletins/2016/securitybulletins2016", "toc_title": "2016", "children": [
            {"href": "securitybulletins/2016/ms16-001", "toc_title": "MS16-001"}]},
        {"href": "securitybulletinsummaries/2016/ms16-jan", "toc_title": "MS16-jan"},
        {"href": "securitybulletins/1998/securitybulletins1998", "toc_title": "1998", "children": [
            {"href": "securitybulletins/1998/ms98-002", "toc_title": "MS98-002"},
            {"href": "securitybulletins/1998/ms98-001", "toc_title": "MS98-001"},
            {"href": "securitybulletins/1998/ms98-003", "toc_title": "MS98-003"}]}]}]}
    sheet = xlsx([
        ["Date Posted", "Bulletin Id", "Bulletin KB", "Severity", "Impact", "Title", "Affected Product", "Component KB",
         "Affected Component", "Supersedes", "Reboot", "CVEs"],
        [42381, "MS16-001", "3124903", "Critical", "Remote Code Execution", "Cumulative Security Update for Internet Explorer",
         "Windows 7 for 32-bit Systems Service Pack 1", "3124275", "Internet Explorer 8", "", "Yes", "CVE-2016-0002,CVE-2016-0005"],
        [42381, "MS16-001", "3124903", "Moderate", "Remote Code Execution", "Cumulative Security Update for Internet Explorer",
         "Windows Server 2008 R2 for x64-based Systems Service Pack 1", "3124275", "Internet Explorer 11", "", "Yes", "CVE-2016-0002"]])
    page1 = ("---\ntitle: Microsoft Security Bulletin MS98-001 - Critical | Microsoft Learn\n---\n\n"
             "# Microsoft Security Bulletin MS98-001 - Critical\n\n"
             "## Disabling Creation of Local Groups on a Domain by Non-Administrative Users\n\n"
             "Published: June 01, 1998 | Updated: March 24, 1999\n").encode("utf-8")
    page2 = ("---\ntitle: Microsoft Security Bulletin MS98-002 - Important | Microsoft Learn\n---\n\n"
             "# Microsoft Security Bulletin MS98-002 - Important\n\n"
             "## Error in Microsoft PPTP Implementation\n\nPublished: June 05, 1998\n\nSee CVE-1999-0140.\n").encode("utf-8")
    write("msrc-bulletins", (1998, 2017), {"toc.json": dump(toc), "BulletinSearch.xlsx": sheet,
                                           "page/ms98-001.md": page1, "page/ms98-002.md": page2},
          stats={"missing": {"1998": 1}, "upstream": {"1998": 3, "2016": 1}})


def msrc_cvrf():
    updates = {"value": [
        {"ID": "1999-Sep", "Alias": "1999-Sep", "DocumentTitle": "Mariner Release Notes", "InitialReleaseDate": "1999-09-02T00:00:00Z",
         "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/1999-Sep"},
        {"ID": "2016-Mar", "Alias": "2016-Mar", "DocumentTitle": "March 2016 Security Updates", "InitialReleaseDate": "2016-03-08T08:00:00Z",
         "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2016-Mar"},
        {"ID": "2016-Apr", "Alias": "2016-Apr", "DocumentTitle": "April 2016 Security Updates", "InitialReleaseDate": "2016-04-12T07:00:00Z",
         "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2016-Apr"},
        {"ID": "2024-Jul", "Alias": "2024-Jul", "DocumentTitle": "Mariner Release Notes", "InitialReleaseDate": "2024-07-09T07:00:00Z",
         "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2024-Jul"}]}

    def threat(kind, value):
        return {"Type": kind, "Description": {"Value": value}, "ProductID": ["10735"]}

    def vulnerability(cve, title, severity, exploited="No", products=("10735",)):
        return {"CVE": cve, "Title": {"Value": title}, "ProductStatuses": [{"Type": 3, "ProductID": list(products)}],
                "Threats": [threat(3, severity), threat(1, "Publicly Disclosed:No;Exploited:" + exploited + ";Latest Software Release:Exploitation Detected")]}

    tree = {"Branch": [{"Type": 0, "Name": "Microsoft", "Items": [
        {"Type": 3, "Name": "Windows", "Items": [{"ProductID": "10735", "Value": "Windows 10 for x64-based Systems"}]},
        {"Type": 3, "Name": "Microsoft Office", "Items": [{"ProductID": "10670", "Value": "Microsoft Office 2016"}]}]}]}
    april = {"DocumentTitle": {"Value": "April 2016 Security Updates"},
             "DocumentTracking": {"InitialReleaseDate": "2016-04-12T07:00:00Z"}, "ProductTree": tree, "Vulnerability": [
                 vulnerability("CVE-2016-0135", "Secondary Logon Elevation of Privilege Vulnerability", "Important"),
                 vulnerability("CVE-2016-0167", "Win32k Elevation of Privilege Vulnerability", "Important", exploited="Yes"),
                 vulnerability("CVE-2016-0127", "Microsoft Office Memory Corruption Vulnerability", "Critical", products=("10670",)),
                 vulnerability("CVE-2015-7511", "Libgcrypt elliptic-curve side channel", "Low")]}
    mariner = {"DocumentTitle": {"Value": "Mariner Release Notes"}, "DocumentTracking": {"InitialReleaseDate": "1999-09-02T00:00:00Z"},
               "ProductTree": tree, "Vulnerability": [vulnerability("CVE-1999-0236", "Mariner package update", "Critical", exploited="Yes")]}
    mariner_2024 = dict(mariner, DocumentTracking={"InitialReleaseDate": "2024-07-09T07:00:00Z"},
                        Vulnerability=[vulnerability("CVE-2024-0001", "Mariner package update", "Critical")])
    write("msrc-cvrf", (2016, 2026), {"updates.json": dump(updates), "cvrf/2016-Apr.json": dump(april),
                                      "cvrf/1999-Sep.json": dump(mariner), "cvrf/2024-Jul.json": dump(mariner_2024)},
          stats={"capped": {}, "upstream": {"2016": 4}})


def certcc():
    summary = {"count": 3, "notes": ["VU#20851", "VU#17566", "VU#999999"]}
    note1 = {"vuid": "VU#20851", "idnumber": "20851", "name": "SGI IRIX df buffer overflow in directory argument",
             "cveids": ["CVE-1999-0025"], "certadvisory": "CA-1997-21", "publicdate": "1997-05-24T00:00:00Z",
             "datefirstpublished": "2000-12-15T20:00:29Z", "dateupdated": "2000-12-15T20:00:31Z"}
    note2 = {"vuid": "VU#17566", "idnumber": "17566", "name": "Microsoft IIS 4.0 / 5.0 vulnerable to directory traversal",
             "cveids": ["CVE-2000-0884"], "certadvisory": "CA-2000-02", "publicdate": "2000-10-17T00:00:00Z",
             "datefirstpublished": "2000-12-18T15:00:00Z", "dateupdated": "2001-01-05T00:00:00Z"}
    documents = {"summary/2000.json": dump(summary), "vu/20851.json": dump(note1), "vu/17566.json": dump(note2)}
    write("certcc-vu", (2000, 2000), documents, stats={"missing": {"2000": 1}, "upstream": {"2000": 3}})
    write("certcc-ca", (1998, 2004), documents, stats={"missing": {}, "upstream": {"2000": 1}})


def cisa_ics():
    feed = {"feed": {"entry": [
        {"id": "ICSA-10-147-01", "title": "Example ICS Advisory One", "published": "2010-05-27T00:00:00.000000Z",
         "link": [{"href": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2010/icsa-10-147-01.json", "rel": "self"}],
         "content": {"src": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2010/icsa-10-147-01.json"}},
        {"id": "ICSA-17-012-01", "title": "Advantech WebAccess", "published": "2017-01-12T00:00:00.000000Z",
         "content": {"src": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2017/icsa-17-012-01.json"}},
        {"id": "ICSA-17-061-01", "title": "Not fetched in this fixture", "published": "2017-03-02T00:00:00.000000Z",
         "content": {"src": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2017/icsa-17-061-01.json"}}]}}
    one = {"document": {"title": "Example ICS Advisory One", "tracking": {"initial_release_date": "2010-05-27T00:00:00.000000Z",
                                                                        "current_release_date": "2010-05-27T00:00:00.000000Z"}},
           "product_tree": {"branches": [{"category": "vendor", "name": "Example Vendor", "branches": [{"category": "product_name", "name": "Example HMI"}]}]},
           "vulnerabilities": [{"cve": "CVE-2010-2772"}]}
    two = {"document": {"title": "Advantech WebAccess", "aggregate_severity": {"text": "High"},
                        "references": [{"category": "self", "url": "https://www.cisa.gov/news-events/ics-advisories/icsa-17-012-01"}],
                        "tracking": {"initial_release_date": "2017-01-12T00:00:00.000000Z", "current_release_date": "2017-02-01T00:00:00.000000Z"}},
           "product_tree": {"branches": [{"category": "vendor", "name": "Advantech", "branches": [
               {"category": "product_name", "name": "WebAccess", "branches": [{"category": "product_version", "name": "8.1"}]}]}]},
           "vulnerabilities": [{"cve": "CVE-2017-5154"}, {"cve": "CVE-2017-5152"}]}
    write("cisa-ics-csaf", (2010, 2026), {"feed.json": dump(feed), "csaf/icsa-10-147-01.json": dump(one), "csaf/icsa-17-012-01.json": dump(two)},
          stats={"missing": {"2017": 1}, "upstream": {"2010": 1, "2017": 2}})


def cisa_alerts():
    sitemap = ('<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
               "<url><loc>https://www.cisa.gov/news-events/alerts/2008/12/17/microsoft-internet-explorer-data-binding-vulnerability</loc></url>"
               "<url><loc>https://www.cisa.gov/news-events/cybersecurity-advisories/aa18-337a</loc></url>"
               "<url><loc>https://www.cisa.gov/news-events/alerts/2003/01/01/before-the-archive-starts</loc></url>"
               "<url><loc>https://www.cisa.gov/about</loc></url></urlset>").encode("utf-8")
    alert = b"<!-- head only --><html><head><title>Microsoft Internet Explorer Data Binding Vulnerability | CISA</title>"
    advisory = b'<html><head><title>SamSam Ransomware | CISA</title></head><body><time datetime="2018-12-03T12:00:00Z">December 03, 2018</time>'
    from intelligence_hub.history.adapters import cisa_alerts as adapter
    url = "https://www.cisa.gov/news-events/alerts/2008/12/17/microsoft-internet-explorer-data-binding-vulnerability"
    write("cisa-alerts", (2004, 2026), {"sitemap.xml": sitemap,
                                        "page/" + adapter.alert_id(url, adapter.ALERT.fullmatch(url)) + ".html": alert,
                                        "page/AA18-337A.html": advisory},
          stats={"missing": {}, "upstream": {"2008": 1, "2018": 1}})


def ubuntu():
    page = {"notices": [
        {"id": "USN-2-1", "title": "xpdf vulnerabilities", "published": "2004-10-23T02:11:46", "cves_ids": ["CVE-2004-0889"],
         "releases": [{"codename": "warty"}]},
        {"id": "USN-1-1", "title": "PNG library vulnerabilities", "published": "2004-10-22T00:00:00", "cves_ids": ["CVE-2004-0597"],
         "releases": [{"codename": "warty"}]},
        {"id": "USN-3-1", "title": "Example notice outside every filter", "published": "2004-10-24T00:00:00", "cves_ids": ["CVE-2004-0001"]}],
        "offset": 0, "limit": 100, "total_results": 3}
    write("ubuntu-usn", (2004, 2026), {"page/0000.json": dump(page)},
          context={"kev": {"CVE-2004-0597"}, "referenced": {"CVE-2004-0889"}}, stats={"capped": {}, "upstream": {"2004": 3}})


def mozilla():
    files = {
        "foundation-security-advisories-main/announce/2005/mfsa2005-01.md":
            "---\nannounced: January 21, 2005\nfixed_in:\n- Firefox 1.0\n- Mozilla Suite 1.7.5\nimpact: Low\n"
            "title: Link opened in new tab can load a local file\n---\n\n<h3>Description</h3>\n<p>Body text is not kept.</p>\n",
        "foundation-security-advisories-main/announce/2024/mfsa2024-01.yml":
            "announced: January 23, 2024\nimpact: high\nfixed_in:\n- Firefox 122\ntitle: Security Vulnerabilities fixed in Firefox 122\n"
            "advisories:\n  CVE-2024-0741:\n    title: Out of bounds write in ANGLE\n",
        "foundation-security-advisories-main/README.md": "not an advisory\n"}
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as packed:
        with tarfile.open(fileobj=packed, mode="w") as archive:
            for name, value in sorted(files.items()):
                data = value.encode("utf-8")
                info = tarfile.TarInfo(name)
                info.size, info.mtime = len(data), 0
                archive.addfile(info, io.BytesIO(data))
    write("mozilla-mfsa", (2005, 2026), {"repository.tar.gz": out.getvalue()},
          stats={"missing": {}, "upstream": {"2005": 1, "2024": 1}})


def oracle():
    feed = ('<?xml version="1.0" encoding="utf-8"?><rss version="2.0"><channel><title>Oracle Security Alerts</title>'
            "<item><title>Oracle Security Alert for CVE-2026-114820\n</title>"
            "<link>https://www.oracle.com/security-alerts/alert-cve-2026-114820.html\n</link>"
            "<pubDate>Fri, 30 Oct 2026 16:00:00 -0700</pubDate></item>"
            "<item><title>Critical Patch Update - July 2005</title>"
            "<link>http://www.oracle.com/technetwork/topics/security/cpujul2005-090619.html</link>"
            "<pubDate>Tue, 12 Jul 2005 12:46:55 -0700</pubDate></item>"
            "<item><title>Unsafe link</title><link>ftp://example.org/x</link><pubDate>Tue, 12 Jul 2005 12:46:55 -0700</pubDate></item>"
            "</channel></rss>").encode("utf-8")
    write("oracle-cpu", (2005, 2026), {"feed.xml": feed}, stats={"missing": {"2005": 1}, "upstream": {"2005": 2, "2026": 1}})


def nvd():
    records = {"resultsPerPage": 3, "format": "NVD_CVE", "version": "2.0", "vulnerabilities": [
        {"cve": {"id": "CVE-1999-0001", "published": "1999-12-30T05:00:00.000", "lastModified": "2025-04-03T01:03:51.193",
                 "vulnStatus": "Modified", "weaknesses": [{"description": [{"value": "CWE-20"}]}],
                 "metrics": {"cvssMetricV2": [{"type": "Primary", "baseSeverity": "MEDIUM", "cvssData": {"version": "2.0", "baseScore": 5.0}}]},
                 "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:o:freebsd:freebsd:2.2.8:*:*:*:*:*:*:*"}]}]}]}},
        {"cve": {"id": "CVE-1999-0002", "published": "1998-10-12T04:00:00.000", "lastModified": "2025-04-03T01:03:51.193",
                 "vulnStatus": "Modified", "cisaExploitAdd": "2022-03-25",
                 "metrics": {"cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH", "cvssData": {"version": "2.0", "baseScore": 10.0}}]}}},
        {"cve": {"id": "CVE-1999-0003", "published": "1998-04-01T05:00:00.000", "vulnStatus": "Analyzed"}}]}
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as packed:
        packed.write(json.dumps(records).encode("utf-8"))
    write("nvd-cve", (1998, 2026), {"nvdcve-2.0-1999.json.gz": out.getvalue()},
          context={"referenced": {"CVE-1999-0001", "CVE-1999-0002"}}, stats={"capped": {}, "upstream": {"1998": 1, "1999": 1}})


if __name__ == "__main__":
    for build in (msrc_bulletins, msrc_cvrf, certcc, cisa_ics, cisa_alerts, ubuntu, mozilla, oracle, nvd):
        build()
    print("fixtures written to " + str(HERE))
