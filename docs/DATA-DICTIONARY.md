# Intelligence Hub export data dictionary

The collector writes one set of files per year of rows: `articles-YYYY.csv`, `articles-YYYY.jsonl` and `tags-YYYY.csv`, plus `manifest.json` and this dictionary. Rows without a date go into the `undated` files.

Every file is UTF-8 with LF line endings. CSV files follow RFC 4180 quoting and always start with a header. Multi-valued cells are sorted and joined with `;`. Rows are ordered by (published, id). No file carries a clock, so a year whose rows did not change keeps byte-identical files.

Publisher rows carry headlines and links only, never article bodies. KEV text is CISA's. Curated summaries are original paraphrases. Tags come from controlled vocabularies (config/vocab/ and the library's shared vocabulary); each records how it was found (method) and how far to trust it (confidence).

The files are published at `data/v7/exports/` on the site (https://teamstarwolf.github.io/intelligence-hub/data/v7/exports/manifest.json lists them), and `data/v7/index.json` lists each one with its bytes and sha256. Every file is at most 4 MiB: a year whose files would pass that is written as one set per month instead (`articles-YYYY-MM.csv`, `articles-YYYY-MM.jsonl`, `tags-YYYY-MM.csv`).

The exports keep one set of files per year even when the year's history shard on the site is written as calendar parts. A history shard (`data/v7/history/YYYY.json`) whose bytes would pass 3 MiB (3,145,728 bytes) is written instead as halves (`history/YYYY-h1.json`, `history/YYYY-h2.json`), then quarters (`-q1` to `-q4`), then months (`history/YYYY-01.json` to `-12.json`), the first rung whose every part is at or under 3 MiB. If a single month still passes it, the months are kept and the 4 MiB shard bound applies. Each part's `period` is its label (`2025-h1`), `data/v7/index.json` lists every part with its rows, bytes and sha256, and a part with no rows is not written.

## articles-YYYY.csv

| Column | Meaning |
| --- | --- |
| `id` | Row id, stable across runs (feed-, kev- or hist- prefix). |
| `published` | Primary date of the row: the event date for event-dated curated rows, otherwise the publication or KEV addition date. ISO 8601; empty when undated. |
| `year` | Year of published, or undated. |
| `month` | Month of published as YYYY-MM, or empty. |
| `source_id` | Source id from config/sources.json, or a curated or KEV source id. |
| `source_class` | Who publishes the row: vendor-primary, government-cert, researcher or press (config/vocab/source_class.json). |
| `desk` | The desk the row sits on: security, infrastructure or it (config/vocab/desk.json), set per source and never inferred from a headline. Publisher feeds, KEV, curated and history rows are security; service-health incident rows are infrastructure; it is reserved for the lifecycle, standards and IT press sources the revision plan adds. |
| `kind` | What the row is: advisory, research, reporting, incident, kev, filing, bulletin, note, change or lifecycle (config/vocab/kind.json). |
| `origin` | publisher-feed (headline and link only), cisa-kev (CISA's catalog text) or library-curation (original paraphrase). |
| `title` | Publisher headline, CISA's vulnerability name or the curated title. A cell that would start with =, +, -, @, tab or CR is prefixed with ' so that spreadsheets do not read it as a formula. |
| `url` | Link to the publisher, CISA or the curated row's primary source. |
| `cve` | CVE ids on the row, sorted, joined with ;. |
| `cwe` | CWE ids from the CVE record's CNA problemTypes and from KEV, resolved against the pinned library CWE list. |
| `cvss_version` | CVSS version of the highest CNA base score among the row's CVEs. Versions are never merged. |
| `cvss_base` | That CNA base score. |
| `cvss_scorer` | Who scored it: cna (the CVE record's CNA container). |
| `epss` | The highest EPSS score among the row's CVEs: FIRST's estimated probability, 0 to 1, that the CVE is exploited in the next 30 days, as scored on epss_date. Empty when no CVE on the row has a score on that date; a missing score is never written as 0. |
| `epss_percentile` | That score's percentile among every CVE FIRST scored that day, 0 to 1. |
| `epss_date` | The score date FIRST published that score for, YYYY-MM-DD. |
| `epss_model` | The EPSS model version that produced it, for example v2026.06.15. Scores from different model versions are not compared, and no change across versions is recorded. |
| `kev_added` | Earliest CISA KEV dateAdded among the row's CVEs. |
| `kev_due` | That entry's KEV dueDate (the federal catalog requirement, not a deadline for the reader). |
| `kev_ransomware` | That entry's knownRansomwareCampaignUse, as CISA publishes it. |
| `exploitation` | known, reported or unknown. unknown never means unexploited (config/vocab/exploitation.json). |
| `exploitation_basis` | The evidence: kev, vendor-structured, curated-primary, title-term or none. |
| `event_type` | disclosure, exploitation, patch, breach, outage, takedown, policy, analysis, unclassified, maintenance or end-of-support (config/vocab/event_type.json). |
| `vendor` | Library vendor ids (vendor:<slug>). |
| `product` | Library product ids (product:<slug>). |
| `attack_technique` | MITRE ATT&CK technique ids reached from the row's CWEs through CAPEC, every one with no cap. Taxonomic and sparse, never observed behaviour. |
| `attack_tactic` | ATT&CK tactics of those techniques. |
| `actor` | Library actor ids: actor:G#### for ATT&CK groups, actor:<slug> for names ATT&CK does not track. |
| `malware` | Library software ids: malware:S#### (ATT&CK malware and tools). |
| `sector` | Library sector ids (sector:<slug>), from headline terms. |
| `region` | value/role pairs: ISO 3166-1 alpha-2 code, EU or M49-<code>, with role publisher or mentioned. |
| `min_confidence` | The lowest confidence among the row's tags: high, medium or low. |
| `tagger_version` | Version of the tagging rules that produced the row. |

## tags-YYYY.csv

| Column | Meaning |
| --- | --- |
| `id` | Row id, as in articles-YYYY.csv. |
| `published` | Primary date of the row, as in articles-YYYY.csv. |
| `field` | kind, source_class, desk, exploitation, event_type, vendor, product, actor, malware, sector, region, cwe, attack_technique or attack_tactic. |
| `value` | The tag value. Region values carry their role as value/role. |
| `confidence` | high (structured field or source identity), medium (exact headline name or term) or low (taxonomy chain, context-confirmed name, press wording). |
| `method` | How the tag was found, for example source-registry, kev, cna-affected, title-match, title-term or cwe-capec. |
| `basis_path` | For ATT&CK tags, the chain CWE>CAPEC>technique (and the successor id when ATT&CK revoked the original). Empty otherwise. |

## articles-YYYY.jsonl

One JSON object per line, keys sorted.

| Keys | Meaning |
| --- | --- |
| `id`, `title`, `url`, `source_id`, `source_name`, `kind`, `origin`, `date_basis`, `event_date`, `summary`, `references` | As in the v6 feed row. summary is empty for publisher rows (headlines and links only). |
| `published`, `year`, `cve` | As in articles-YYYY.csv; cve is a list. |
| `source_class`, `desk`, `exploitation` | One tag each: {value, method, confidence}. |
| `event_type`, `vendor`, `product`, `actor`, `malware`, `sector`, `cwe` | Lists of {value, method, confidence}. |
| `region` | List of {value, role, method, confidence}. |
| `attack` | List of {value, method, confidence, tactics, path}. |
| `cvss` | {base, version, vector, scorer, cve} or null. |
| `epss` | {score, percentile, date, model, cve} or null: the highest EPSS score among the row's CVEs, by FIRST, with the CVE it belongs to. |
| `kev` | {cves, added, due, ransomware, at_publication} or null. |
| `tagger_version` | Version of the tagging rules. |

## manifest.json

`files` lists every export with its year, its month (`YYYY-MM` for a year split by month, otherwise null), row count, bytes and sha256. `sources` gives each source id its name, source_class, desk and licence note. `vocabulary` records the tagger version, the Hub vocabulary versions and the pinned library commit. `notices` carries the designations for MITRE ATT&CK, CWE and CAPEC content.

## Notices

- ATT&CK: © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: ATT&CK Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.
- CWE: © The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/
- CAPEC: © The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/
- CVE ids and CNA fields come from the CVE Program's records (cvelistV5).
- Vendor, product, actor, malware and sector ids come from the TeamStarWolf library's shared vocabulary (data/vocab/vocabulary.json) at the pinned commit.
- EPSS scores come from FIRST's Exploit Prediction Scoring System (https://www.first.org/epss/), read from api.first.org. FIRST asks for attribution when EPSS data is used in publications or products.
