"""Per-year analytics exports of the tagged rows: CSV and JSON Lines with a data dictionary.

For every year that has rows (and "undated" for rows without a date) the collector
builds three files:

- articles-YYYY.csv: one row per article with every tag field (the wide view).
- articles-YYYY.jsonl: the full tagged record, one per line.
- tags-YYYY.csv: one row per (article, field, value) with confidence and method (the long
  view, the one to load into a spreadsheet or notebook for counting).

plus manifest.json (every file with rows, bytes and sha256, the licence note of every
source, the vocabulary pin and the notices) and data-dictionary.md (every column).
docs/DATA-DICTIONARY.md is the same text, kept in the repository.

Bytes are deterministic: rows are sorted by (published, id), multi-valued cells are
sorted and joined with ";", CSV uses RFC 4180 quoting, UTF-8 and LF, and nothing in
any file is a clock. A year whose rows did not change keeps byte-identical files, and
write_exports() rewrites only the files whose bytes differ.

Every file stays under the package's per-file cap for v7 files (shards.V7_FILE_MAX_BYTES,
4 MiB). A year whose files would pass it is written as one set per month instead
(articles-YYYY-MM.csv, articles-YYYY-MM.jsonl, tags-YYYY-MM.csv); the manifest gives every
file its year and month. A month or an undated set that still passes the cap is an error,
and the collector then publishes the feed without exports.

Publication: EXPORTS_PUBLISHED is True since the package caps were raised in pull
request #7, so the collector writes the files to site/data/v7/exports/ and lists
every one in data/v7/index.json, which the Pages package is checked against. With the flag
off, a run writes them to dist/exports/ for local analysis only.
"""
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import re

from .shards import EXPORT_NAME, V7_FILE_MAX_BYTES  # noqa: F401  (EXPORT_NAME is part of this module's interface)
from .tagging import TAGGER_VERSION, export_fields, long_tags

EXPORTS_PUBLISHED = True
PUBLISHED_DIRECTORY = "site/data/v7/exports"
PUBLIC_URL = "https://teamstarwolf.github.io/intelligence-hub/data/v7/exports/"
LOCAL_DIRECTORY = "dist/exports"
SCHEMA_VERSION = 1
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")

ARTICLE_COLUMNS = (
    ("id", "Row id, stable across runs (feed-, kev- or hist- prefix)."),
    ("published", "Primary date of the row: the event date for event-dated curated rows, otherwise the publication or KEV addition date. ISO 8601; empty when undated."),
    ("year", "Year of published, or undated."),
    ("month", "Month of published as YYYY-MM, or empty."),
    ("source_id", "Source id from config/sources.json, or a curated or KEV source id."),
    ("source_class", "Who publishes the row: vendor-primary, government-cert, researcher or press (config/vocab/source_class.json)."),
    ("desk", "The desk the row sits on: security, infrastructure or it (config/vocab/desk.json), set per source and never inferred from a headline. Publisher feeds, KEV, curated and history rows are security; service-health incident rows are infrastructure; it is reserved for the lifecycle, standards and IT press sources the revision plan adds."),
    ("kind", "What the row is: advisory, research, reporting, incident, kev, filing, bulletin, note, change or lifecycle (config/vocab/kind.json)."),
    ("origin", "publisher-feed (headline and link only), cisa-kev (CISA's catalog text) or library-curation (original paraphrase)."),
    ("title", "Publisher headline, CISA's vulnerability name or the curated title. A cell that would start with =, +, -, @, tab or CR is prefixed with ' so that spreadsheets do not read it as a formula."),
    ("url", "Link to the publisher, CISA or the curated row's primary source."),
    ("cve", "CVE ids on the row, sorted, joined with ;."),
    ("cwe", "CWE ids from the CVE record's CNA problemTypes and from KEV, resolved against the pinned library CWE list."),
    ("cvss_version", "CVSS version of the highest CNA base score among the row's CVEs. Versions are never merged."),
    ("cvss_base", "That CNA base score."),
    ("cvss_scorer", "Who scored it: cna (the CVE record's CNA container)."),
    ("epss", "The highest EPSS score among the row's CVEs: FIRST's estimated probability, 0 to 1, that the CVE is exploited in the next 30 days, as scored on epss_date. Empty when no CVE on the row has a score on that date; a missing score is never written as 0."),
    ("epss_percentile", "That score's percentile among every CVE FIRST scored that day, 0 to 1."),
    ("epss_date", "The score date FIRST published that score for, YYYY-MM-DD."),
    ("epss_model", "The EPSS model version that produced it, for example v2026.06.15. Scores from different model versions are not compared, and no change across versions is recorded."),
    ("kev_added", "Earliest CISA KEV dateAdded among the row's CVEs."),
    ("kev_due", "That entry's KEV dueDate (the federal catalog requirement, not a deadline for the reader)."),
    ("kev_ransomware", "That entry's knownRansomwareCampaignUse, as CISA publishes it."),
    ("exploitation", "known, reported or unknown. unknown never means unexploited (config/vocab/exploitation.json)."),
    ("exploitation_basis", "The evidence: kev, vendor-structured, curated-primary, title-term or none."),
    ("event_type", "disclosure, exploitation, patch, breach, outage, takedown, policy, analysis, unclassified, maintenance or end-of-support (config/vocab/event_type.json)."),
    ("vendor", "Library vendor ids (vendor:<slug>)."),
    ("product", "Library product ids (product:<slug>)."),
    ("attack_technique", "MITRE ATT&CK technique ids reached from the row's CWEs through CAPEC, every one with no cap. Taxonomic and sparse, never observed behaviour."),
    ("attack_tactic", "ATT&CK tactics of those techniques."),
    ("actor", "Library actor ids: actor:G#### for ATT&CK groups, actor:<slug> for names ATT&CK does not track."),
    ("malware", "Library software ids: malware:S#### (ATT&CK malware and tools)."),
    ("sector", "Library sector ids (sector:<slug>), from headline terms."),
    ("region", "value/role pairs: ISO 3166-1 alpha-2 code, EU or M49-<code>, with role publisher or mentioned."),
    ("min_confidence", "The lowest confidence among the row's tags: high, medium or low."),
    ("tagger_version", "Version of the tagging rules that produced the row."),
)
TAG_COLUMNS = (
    ("id", "Row id, as in articles-YYYY.csv."),
    ("published", "Primary date of the row, as in articles-YYYY.csv."),
    ("field", "kind, source_class, desk, exploitation, event_type, vendor, product, actor, malware, sector, region, cwe, attack_technique or attack_tactic."),
    ("value", "The tag value. Region values carry their role as value/role."),
    ("confidence", "high (structured field or source identity), medium (exact headline name or term) or low (taxonomy chain, context-confirmed name, press wording)."),
    ("method", "How the tag was found, for example source-registry, kev, cna-affected, title-match, title-term or cwe-capec."),
    ("basis_path", "For ATT&CK tags, the chain CWE>CAPEC>technique (and the successor id when ATT&CK revoked the original). Empty otherwise."),
)
JSONL_FIELDS = (
    ("id, title, url, source_id, source_name, kind, origin, date_basis, event_date, summary, references", "As in the v6 feed row. summary is empty for publisher rows (headlines and links only)."),
    ("published, year, cve", "As in articles-YYYY.csv; cve is a list."),
    ("source_class, desk, exploitation", "One tag each: {value, method, confidence}."),
    ("event_type, vendor, product, actor, malware, sector, cwe", "Lists of {value, method, confidence}."),
    ("region", "List of {value, role, method, confidence}."),
    ("attack", "List of {value, method, confidence, tactics, path}."),
    ("cvss", "{base, version, vector, scorer, cve} or null."),
    ("epss", "{score, percentile, date, model, cve} or null: the highest EPSS score among the row's CVEs, by FIRST, with the CVE it belongs to."),
    ("kev", "{cves, added, due, ransomware, at_publication} or null."),
    ("tagger_version", "Version of the tagging rules."),
)
LICENCE = {
    "publisher-feed": "Headline and link only. The article and its text stay with the publisher under the publisher's own terms.",
    "cisa-kev": "Text from CISA's Known Exploited Vulnerabilities catalog, unchanged and attributed to CISA. CISA publishes the catalog under CC0 1.0.",
    "library-curation": "Original paraphrase written for this project (MIT licence), linked to its dated primary publication.",
}
NOTICES = [
    "ATT&CK: © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. "
    "License: ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® "
    "are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.",
    "CWE: © The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/",
    "CAPEC: © The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/",
    "CVE ids and CNA fields come from the CVE Program's records (cvelistV5).",
    "Vendor, product, actor, malware and sector ids come from the TeamStarWolf library's shared vocabulary (data/vocab/vocabulary.json) at the pinned commit.",
    "EPSS scores come from FIRST's Exploit Prediction Scoring System (https://www.first.org/epss/), read from api.first.org. "
    "FIRST asks for attribution when EPSS data is used in publications or products.",
]


def published(article):
    value = (article.get("event_date") if article.get("date_basis") == "event" else article.get("published_at")) or ""
    return value


def year_of(article):
    value = published(article)[:4]
    return value if re.fullmatch(r"[0-9]{4}", value) else "undated"


def cell(value):
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_START) else text


def csv_bytes(header, rows):
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(header)
    for row in rows:
        writer.writerow([cell(value) for value in row])
    return stream.getvalue().encode("utf-8")


def json_line(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def best_epss(article, scores):
    """The highest EPSS block among the row's CVEs with the CVE it belongs to, or None. Ties go to the lowest CVE id."""
    scores = scores or {}
    best = None
    for cve in sorted(set(article.get("cves") or [])):
        block = scores.get(cve)
        if isinstance(block, dict) and (best is None or block["score"] > best["score"]):
            best = {**block, "cve": cve}
    return best


def epss_fields(article, scores):
    """The four CSV columns of the row's best EPSS score, empty when there is none."""
    best = best_epss(article, scores)
    if best is None:
        return {"epss": "", "epss_percentile": "", "epss_date": "", "epss_model": ""}
    return {"epss": _decimal(best["score"]), "epss_percentile": _decimal(best["percentile"]), "epss_date": best["date"], "epss_model": best["model"]}


def _decimal(value):
    """A probability as a plain decimal with up to five places (0.00004, never 4e-05)."""
    text = format(value, ".5f").rstrip("0").rstrip(".")
    return text or "0"


def record(article, block, source_class, scores=None):
    block = block or {}
    out = {key: article.get(key) for key in ("id", "title", "url", "source_id", "source_name", "kind", "origin", "date_basis",
                                              "event_date", "summary", "references")}
    out.update({"published": published(article) or None, "year": year_of(article), "cve": sorted(set(article.get("cves") or []))})
    if article.get("origin") == "publisher-feed":
        out["summary"] = ""
    for key in ("source_class", "desk", "exploitation", "event_type", "vendor", "product", "actor", "malware", "sector", "region", "cwe",
                "attack", "cvss", "kev"):
        out[key] = block.get(key, [] if key not in {"source_class", "desk", "exploitation", "cvss", "kev"} else None)
    out["epss"] = best_epss(article, scores)
    out["tagger_version"] = block.get("tagger_version") or TAGGER_VERSION
    return out


def month_of(article):
    value = published(article)
    return value[:7] if re.fullmatch(r"[0-9]{4}-(?:0[1-9]|1[0-2])", value[:7]) else None


def year_files(year, articles, blocks, label=None, scores=None):
    """The three files for one year (label = the year) or one month of a split year (label = YYYY-MM)."""
    label = label or year
    rows = sorted(articles, key=lambda article: (published(article), article["id"]))
    wide, long_rows, lines = [], [], []
    header = [name for name, _ in ARTICLE_COLUMNS]
    for article in rows:
        block = blocks.get(article["id"]) or {}
        view = export_fields(article, block)
        date = published(article)
        base = {"id": article["id"], "published": date, "year": year, "month": date[:7] if len(date) >= 7 else "",
                "source_id": article["source_id"], "kind": article["kind"], "origin": article["origin"], "title": article["title"],
                "url": article["url"], "cve": ";".join(sorted(set(article.get("cves") or [])))}
        base.update(view)
        base.update(epss_fields(article, scores))
        if not base["tagger_version"]:
            base["tagger_version"] = ""
        wide.append([base[name] for name in header])
        for field, value, confidence, method, path in long_tags(block):
            long_rows.append([article["id"], date, field, value, confidence, method, path])
        lines.append(json_line(record(article, block, view["source_class"], scores)))
    return {
        "articles-" + label + ".csv": csv_bytes(header, wide),
        "articles-" + label + ".jsonl": ("".join(line + "\n" for line in lines)).encode("utf-8"),
        "tags-" + label + ".csv": csv_bytes([name for name, _ in TAG_COLUMNS], long_rows),
    }, len(rows), len(long_rows)


def period_files(year, articles, blocks, limit=None, scores=None):
    """[(month or None, files, rows, tag rows)]: the year as one set, or one set per month when a file passes the cap."""
    limit = V7_FILE_MAX_BYTES if limit is None else limit
    built, rows, tag_rows = year_files(year, articles, blocks, scores=scores)
    if all(len(data) <= limit for data in built.values()):
        return [(None, built, rows, tag_rows)]
    months = {}
    for article in articles:
        month = month_of(article)
        if year == "undated" or month is None:
            raise ValueError("The " + year + " exports pass the " + format(limit, ",") + "-byte per-file cap and cannot be split by month.")
        months.setdefault(month, []).append(article)
    periods = []
    for month in sorted(months):
        built, rows, tag_rows = year_files(year, months[month], blocks, label=month, scores=scores)
        for name, data in built.items():
            if len(data) > limit:
                raise ValueError("The export " + name + " passes the " + format(limit, ",") + "-byte per-file cap.")
        periods.append((month, built, rows, tag_rows))
    return periods


def dictionary():
    """docs/DATA-DICTIONARY.md and exports/data-dictionary.md: the same text."""
    lines = ["# Intelligence Hub export data dictionary", "",
             "The collector writes one set of files per year of rows: `articles-YYYY.csv`, `articles-YYYY.jsonl` and "
             "`tags-YYYY.csv`, plus `manifest.json` and this dictionary. Rows without a date go into the `undated` files.", "",
             "Every file is UTF-8 with LF line endings. CSV files follow RFC 4180 quoting and always start with a header. "
             "Multi-valued cells are sorted and joined with `;`. Rows are ordered by (published, id). No file carries a clock, "
             "so a year whose rows did not change keeps byte-identical files.", "",
             "Publisher rows carry headlines and links only, never article bodies. KEV text is CISA's. Curated summaries are "
             "original paraphrases. Tags come from controlled vocabularies (config/vocab/ and the library's shared vocabulary); "
             "each records how it was found (method) and how far to trust it (confidence).", "",
             "The files are published at `data/v7/exports/` on the site (" + PUBLIC_URL + "manifest.json lists them), and "
             "`data/v7/index.json` lists each one with its bytes and sha256. Every file is at most 4 MiB: a year whose files "
             "would pass that is written as one set per month instead (`articles-YYYY-MM.csv`, `articles-YYYY-MM.jsonl`, "
             "`tags-YYYY-MM.csv`).", "",
             "The exports keep one set of files per year even when the year's history shard on the site is written as calendar "
             "parts. A history shard (`data/v7/history/YYYY.json`) whose bytes would pass 3 MiB (3,145,728 bytes) is written "
             "instead as halves (`history/YYYY-h1.json`, `history/YYYY-h2.json`), then quarters (`-q1` to `-q4`), then months "
             "(`history/YYYY-01.json` to `-12.json`), the first rung whose every part is at or under 3 MiB. If a single month "
             "still passes it, the months are kept and the 4 MiB shard bound applies. Each part's "
             "`period` is its label (`2025-h1`), `data/v7/index.json` lists every part with its rows, bytes and sha256, and a "
             "part with no rows is not written.", "",
             "## articles-YYYY.csv", "", "| Column | Meaning |", "| --- | --- |"]
    lines += ["| `" + name + "` | " + text + " |" for name, text in ARTICLE_COLUMNS]
    lines += ["", "## tags-YYYY.csv", "", "| Column | Meaning |", "| --- | --- |"]
    lines += ["| `" + name + "` | " + text + " |" for name, text in TAG_COLUMNS]
    lines += ["", "## articles-YYYY.jsonl", "", "One JSON object per line, keys sorted.", "", "| Keys | Meaning |", "| --- | --- |"]
    lines += ["| " + ", ".join("`" + key.strip() + "`" for key in names.split(",")) + " | " + text + " |" for names, text in JSONL_FIELDS]
    lines += ["", "## manifest.json", "",
              "`files` lists every export with its year, its month (`YYYY-MM` for a year split by month, otherwise null), row count, "
              "bytes and sha256. `sources` gives each source id its name, "
              "source_class, desk and licence note. `vocabulary` records the tagger version, the Hub vocabulary versions and the pinned "
              "library commit. `notices` carries the designations for MITRE ATT&CK, CWE and CAPEC content.", "",
              "## Notices", ""]
    lines += ["- " + notice for notice in NOTICES]
    return ("\n".join(lines) + "\n").encode("utf-8")


def source_notes(articles, registry, blocks=None):
    """One note per source id: name, source_class, desk and licence. A source outside the registry
    (KEV, curated, history, status) takes its desk from its rows' tagging blocks."""
    names = {source["id"]: source for source in registry}
    blocks = blocks or {}
    seen = {}
    for article in articles:
        info = names.get(article["source_id"], {})
        desk = info.get("desk") or ((blocks.get(article["id"]) or {}).get("desk") or {}).get("value")
        note = seen.setdefault(article["source_id"], {"id": article["source_id"], "name": article["source_name"],
                                                       "source_class": info.get("source_class"), "desk": desk,
                                                       "licence": LICENCE[article["origin"]]})
        if note["desk"] is None and desk:
            note["desk"] = desk
    return [seen[key] for key in sorted(seen)]


def build_exports(articles, blocks, registry, vocabulary_info, source_classes=None, limit=None, scores=None):
    """{file name: bytes} for every export, the manifest and the dictionary.

    Raises ValueError when a file cannot be kept under the per-file cap (limit, by default
    V7_FILE_MAX_BYTES); the collector then publishes the feed without exports. scores maps a
    CVE to its EPSS block for the epss columns.
    """
    limit = V7_FILE_MAX_BYTES if limit is None else limit
    years = {}
    for article in articles:
        years.setdefault(year_of(article), []).append(article)
    files, entries = {}, []
    for year in sorted(years):
        for month, built, rows, tag_rows in period_files(year, years[year], blocks, limit, scores):
            for name in sorted(built):
                data = built[name]
                files[name] = data
                entries.append({"name": name, "year": year, "month": month, "rows": tag_rows if name.startswith("tags-") else rows,
                                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    files["data-dictionary.md"] = dictionary()
    sources = source_notes(articles, registry, blocks)
    for item in sources:
        if item["source_class"] is None and source_classes:
            item["source_class"] = source_classes.get(item["id"])
    manifest = {"schema_version": SCHEMA_VERSION, "kind": "exports", "files": entries,
                "dictionary": {"name": "data-dictionary.md", "sha256": hashlib.sha256(files["data-dictionary.md"]).hexdigest()},
                "columns": {"articles": [name for name, _ in ARTICLE_COLUMNS], "tags": [name for name, _ in TAG_COLUMNS]},
                "sources": sources, "vocabulary": vocabulary_info, "notices": NOTICES,
                "published": EXPORTS_PUBLISHED}
    files["manifest.json"] = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode("utf-8")
    for name in ("manifest.json", "data-dictionary.md"):
        if len(files[name]) > V7_FILE_MAX_BYTES:
            raise ValueError("The export " + name + " passes the " + format(V7_FILE_MAX_BYTES, ",") + "-byte per-file cap.")
    return files


def write_exports(directory, files):
    """Write only files whose bytes changed, remove exports no longer built. Returns (written, removed)."""
    base = Path(directory)
    base.mkdir(parents=True, exist_ok=True)
    written, removed = [], []
    for name in sorted(files):
        if not EXPORT_NAME.fullmatch(name):
            raise ValueError("Unexpected export file name " + name)
        path = base / name
        try:
            same = path.is_file() and not path.is_symlink() and path.read_bytes() == files[name]
        except OSError:
            same = False
        if not same:
            temporary = path.with_name(path.name + ".tmp")
            temporary.write_bytes(files[name])
            os.replace(temporary, path)
            written.append(name)
    for path in sorted(base.iterdir()):
        if path.is_file() and EXPORT_NAME.fullmatch(path.name) and path.name not in files:
            path.unlink()
            removed.append(path.name)
    return written, removed
