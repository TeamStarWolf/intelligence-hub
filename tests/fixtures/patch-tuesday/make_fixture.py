"""Rebuild the trimmed Patch Tuesday fixture documents from full copies of the public pages.

    python -I tests/fixtures/patch-tuesday/make_fixture.py <folder with the full documents>

The folder holds what the collector would read: updates.json and cvrf/<id>.json from the
MSRC CVRF API, adobe-security.html (https://helpx.adobe.com/security.html), sap-index.html
and the SAP month or year pages under their own file names. The fixture keeps a few CVEs per
month (the exploited and disclosed ones, Critical remote code execution in and outside the
exposed-component rule, every severity, a Chromium row and two left-out package rows), the
products those CVEs name, and short excerpts of the vendor pages. Descriptions, FAQs,
acknowledgments and remediation tables are dropped: the collector reads none of them.
Run build_golden.py afterwards to refresh the golden briefs.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "documents"
MONTHS = {"2026-Oct": ["CVE-2026-96951", "CVE-2026-111497", "CVE-2026-92707", "CVE-2026-108398", "CVE-2026-100202",
                       "CVE-2026-70571", "CVE-2026-70187", "CVE-2026-88117", "CVE-2026-100209", "CVE-2026-96185"],
          "2024-Jan": ["CVE-2024-20674", "CVE-2024-20700", "CVE-2024-0057", "CVE-2024-20677", "CVE-2022-35737"]}
# Per month, also the first CVE of each of these kinds.
KINDS = ("Important", "Moderate", "Low", "Chrome", "left-out")
MAX_PRODUCTS = 3
UPDATES = ("2016-Jan", "2024-Jan", "2026-Sep", "2026-Oct", "1999-Sep")
ADOBE_SECTIONS = ("Adobe Acrobat", "Adobe Substance 3D Stager", "Adobe Dreamweaver", "Adobe Photoshop")
# Rows on these posting dates are kept beside the first three of each section.
ADOBE_DAYS = ("01/09/2024", "10/13/2026")
# Per section, also these bulletins: True strips the row's trailing <th> cell, so a plain three-cell
# row sits beside rows that end with <th>&nbsp;</th>, and a row with an empty fourth <td> follows.
ADOBE_SHAPES = {"Adobe Photoshop": (("APSB26-40", True), ("APSB25-75", False))}
SAP_ROWS = 6


def write(name, raw):
    path = OUT / name
    path.parent.mkdir(parents=True, exist_ok=True)
    text = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False, indent=1) + "\n"
    if chr(0x2014) in text:
        raise SystemExit(name + " would carry an em dash; pick other rows.")
    path.write_bytes(text.encode("utf-8"))


def notes(item):
    return {note.get("Type"): note.get("Value") for note in item.get("Notes") or []}


def severities(item):
    return {threat["Description"].get("Value") for threat in item.get("Threats") or [] if threat.get("Type") == 3}


def kind(item, families):
    products = {str(ident) for status in item.get("ProductStatuses") or [] for ident in status.get("ProductID") or []}
    if products and all(families.get(ident) in {"Mariner", "Azure Linux", "Open Source Software"} for ident in products):
        return "left-out"
    if notes(item).get(8) == "Chrome":
        return "Chrome"
    if notes(item).get(8) == "Microsoft":
        found = severities(item)
        return next((name for name in ("Important", "Moderate", "Low") if found == {name}), None)
    return None


def trim_document(source, ident):
    value = json.loads((source / "cvrf" / (ident + ".json")).read_text(encoding="utf-8"))
    families = {}
    for branch in value["ProductTree"].get("Branch") or []:
        for family in branch.get("Items") or []:
            for product in family.get("Items") or []:
                families[str(product["ProductID"])] = family.get("Name")
    chosen, seen = [], set()
    wanted = set(MONTHS[ident])
    for item in value["Vulnerability"]:
        if item["CVE"] in wanted:
            chosen.append(item)
    for name in KINDS:
        for item in value["Vulnerability"]:
            if item["CVE"] not in wanted and kind(item, families) == name and item["CVE"] not in {entry["CVE"] for entry in chosen}:
                chosen.append(item)
                if name != "left-out" or sum(kind(entry, families) == "left-out" for entry in chosen) >= 2:
                    break
    vulnerabilities = []
    for item in chosen:
        products = []
        for status in item.get("ProductStatuses") or []:
            for product in status.get("ProductID") or []:
                if str(product) not in products:
                    products.append(str(product))
        keep = set(products[:MAX_PRODUCTS])
        seen |= keep

        def scoped(entries):
            out = []
            for entry in entries or []:
                ids = [str(product) for product in entry.get("ProductID") or [] if str(product) in keep]
                if ids or not entry.get("ProductID"):
                    out.append({**entry, "ProductID": ids})
            return out

        vulnerabilities.append({
            "Title": item.get("Title"), "Notes": [note for note in item.get("Notes") or [] if note.get("Type") in (7, 8)],
            "CVE": item["CVE"], "CWE": item.get("CWE") or [],
            "ProductStatuses": [{**status, "ProductID": [product for product in status.get("ProductID") or [] if str(product) in keep]}
                                for status in item.get("ProductStatuses") or []],
            "Threats": scoped(item.get("Threats")), "CVSSScoreSets": scoped(item.get("CVSSScoreSets")),
            "Ordinal": item.get("Ordinal"),
            "RevisionHistory": [{"Number": revision.get("Number"), "Date": revision.get("Date")} for revision in item.get("RevisionHistory") or []]})
    tree = value["ProductTree"]
    branches = []
    for branch in tree.get("Branch") or []:
        items = []
        for family in branch.get("Items") or []:
            products = [product for product in family.get("Items") or [] if str(product["ProductID"]) in seen]
            if products:
                items.append({**family, "Items": products})
        branches.append({**branch, "Items": items})
    product_tree = {"Branch": branches, "FullProductName": [entry for entry in tree.get("FullProductName") or [] if str(entry["ProductID"]) in seen]}
    tracking = value["DocumentTracking"]
    return {"DocumentTitle": value["DocumentTitle"], "DocumentType": value["DocumentType"], "DocumentPublisher": value.get("DocumentPublisher"),
            "DocumentTracking": {**tracking, "RevisionHistory": tracking.get("RevisionHistory", [])[-1:]}, "ProductTree": product_tree,
            "Vulnerability": vulnerabilities}


def adobe(source):
    page = (source / "adobe-security.html").read_text(encoding="utf-8")
    parts = ["<!DOCTYPE HTML>\n<html lang=\"en-US\"><head><title>Security Bulletins and Advisories</title></head><body>\n",
             "<!-- Excerpt of https://helpx.adobe.com/security.html: four product sections, a few rows each. -->\n"]
    headings = list(re.finditer(r"<h2[^>]{0,400}>(.{0,600}?)</h2>", page, re.S))
    for name in ADOBE_SECTIONS:
        match = next((item for item in headings if re.sub(r"<[^>]+>|\s+", " ", item.group(1)).strip() == name), None)
        if match is None:
            raise SystemExit("Adobe section " + name + " not found.")
        table = re.search(r"<table.*?</table>", page[match.end():], re.S).group(0)
        rows = re.findall(r"<tr>.*?</tr>", table, re.S)
        kept = rows[:3] + [row for row in rows[3:] if any(day in row for day in ADOBE_DAYS)]
        for ident, strip in ADOBE_SHAPES.get(name, ()):
            row = next((row for row in rows if "/" + ident.lower() + ".html\"" in row), None)
            if row is None:
                raise SystemExit("Adobe bulletin " + ident + " not found.")
            kept.append(re.sub(r"<th>[^<]{0,20}</th>\s*(?=</tr>)", "", row) if strip else row)
        parts.append(match.group(0) + "\n<table width=\"100%\" cellspacing=\"0\" cellpadding=\"1\" border=\"1\">\n<tbody>" +
                     "".join(kept) + "</tbody></table>\n")
    parts.append("</body></html>\n")
    return "".join(parts)


def sap_index(source):
    page = (source / "sap-index.html").read_text(encoding="utf-8")
    links = re.findall(r'<a[^>]+href="/en/my-support/knowledge-base/security-notes-news/[a-z]+-[0-9]{4}\.html"[^>]*>[^<]*</a>', page)
    return ("<!DOCTYPE html>\n<html lang=\"en\"><head><title>SAP Security Notes &amp; News</title></head><body>\n"
            "<!-- Excerpt of https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html: the month links. -->\n"
            "<h2>SAP Security Patch Day</h2>\n<p>" + " ".join(links) + "</p>\n</body></html>\n")


def sap_page(source, name, heading=None):
    page = (source / name).read_text(encoding="utf-8")
    if heading:
        found = re.search(r"SAP Security Patch Day\W{1,6}" + heading, page)
        if not found:
            raise SystemExit("SAP heading " + heading + " not found.")
        end = page.find("<h2", found.end())
        page = page[page.rfind("<h2", 0, found.start()):end]
        heading = found.group(0)
    table = re.search(r"<table.*?</table>", page, re.S).group(0)
    rows = re.findall(r"<tr.*?</tr>", table, re.S)
    head = ("<h2 class='text-start'>" + heading + "</h2>\n") if heading else ""
    return ("<!DOCTYPE html>\n<html lang=\"en\"><head><title>SAP Security Patch Day</title></head><body>\n"
            "<!-- Excerpt of the SAP Security Patch Day page: the first rows of the notes table. -->\n" + head +
            "<table>" + "".join(rows[:SAP_ROWS + 1]) + "</table>\n</body></html>\n")


def main(argv):
    source = Path(argv[1])
    updates = json.loads((source / "updates.json").read_text(encoding="utf-8"))
    write("updates.json", {"@odata.context": updates.get("@odata.context"),
                           "value": [item for item in updates["value"] if item["ID"] in UPDATES]})
    for ident in MONTHS:
        write("cvrf/" + ident + ".json", trim_document(source, ident))
    write("adobe-security.html", adobe(source))
    write("sap-index.html", sap_index(source))
    write("sap-october-2026.html", sap_page(source, "sap-october-2026.html"))
    write("sap-bulletin-2024.html", sap_page(source, "sap-bulletin-2024.html", "January 2024"))
    print("Wrote " + str(OUT))


if __name__ == "__main__":
    main(sys.argv)
