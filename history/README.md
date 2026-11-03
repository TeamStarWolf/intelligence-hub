# History archive

This folder holds the Hub's history rows: public advisories, bulletins and vulnerability notes from 1998 onward, one file per source and year. Each row carries the publisher's identifier, title, dates, CVE ids, severity where the source states one, and a link. No advisory body is copied.

The rows are built on a contributor's machine and committed through a pull request. The publish workflow never fetches a history source: it reads these files, tags each row with the same engine as the live rows, and writes it into `site/data/v7/history/YYYY.json`.

## Files

- `<adapter>/<year>.jsonl`: one canonical JSON row per line (sorted keys, compact separators, UTF-8, LF), ordered by publication date and then id. A year with no rows has no file. The same input always gives the same bytes.
- `coverage.json`: one statement per source and year from 1998, published as `site/data/v7/coverage.json`.

Nothing here is written under `reports/`, which belongs to the owner's report app.

## Row fields

| Field | Meaning |
| --- | --- |
| `id` | `h-<adapter>-<native_id>`, stable across builds. |
| `adapter`, `source_id`, `source_class`, `kind` | Which adapter wrote the row, the publisher's source id, its class (vendor-primary or government-cert) and the row kind (bulletin, advisory or note). |
| `native_id` | The publisher's own identifier, such as `MS98-001`, `VU-20851`, `ICSA-17-012-01` or `CVE-2016-0167`. |
| `title` | The publisher's title. For `nvd-cve` it is a metadata line (CVSS, CWE, KEV date), because the NVD has no titles. For `certcc-ca` it names the citing Vulnerability Note. |
| `url` | A canonical HTTPS link to the publisher's page, as the publisher lists it. A retired link is replaced by the publisher's current address for the same page when one was found; a row whose link no longer resolves anywhere is not published, and coverage counts it. |
| `published`, `updated`, `date_basis` | Publication day, the last update day when it is later, and how the date was found: `publication`, or `cross-reference` for CA-series advisories dated by the earliest citing note. |
| `cve`, `severity`, `vendor_raw`, `product_raw` | CVE ids, the publisher's severity text, and vendor and product names as the source spells them (at most 20 each). A CVE id dated after the retrieval year is a publisher typo and is dropped. |
| `exploited_flag` | `true` only when the source's own structured field says exploited (MSRC's "Exploited:Yes", or a KEV addition recorded by the NVD); otherwise `null`. It is never `false`: no row claims that something was not exploited. |
| `retrieved`, `raw_sha256` | When the raw document was fetched and its sha256. |

Caps: at most 1,500 rows per adapter and year, 4 KB per row. Each adapter declares a byte bound for its responses, and the fetcher makes at most one request a second per host with a user agent that names this repository.

## Sources

| Adapter | Source | Years | What is kept |
| --- | --- | --- | --- |
| `msrc-bulletins` | Microsoft security bulletins: the security-updates table of contents, BulletinSearch.xlsx, and each bulletin page the workbook does not list | 1998 to 2017 | Every bulletin. |
| `msrc-cvrf` | MSRC CVRF API monthly documents | April 2016 onward | CVEs Microsoft rated Critical or Important, or marked exploited, that affect at least one Microsoft product. Documents titled "Mariner Release Notes" (filed under ids such as 1999-Sep) describe Azure Linux packages and are excluded, and so are the Azure Linux, CBL-Mariner and open-source package CVEs listed inside the regular monthly documents. When Microsoft's title for a kept CVE is the upstream description, the row's title is the CVE id and its Microsoft product families. |
| `certcc-vu` | CERT/CC Vulnerability Notes API | December 2000 onward | Every note. |
| `certcc-ca` | CERT/CC Advisories (CA series), through the notes that cite them | 1998 to 2004 | CA ids cited by at least one note. Each links to its year's page in the SEI library, which holds the compiled advisories. |
| `cisa-ics-csaf` | CISA ICS advisories in CISA's CSAF repository | 2010 onward | Every advisory. |
| `cisa-alerts` | Alerts and cybersecurity advisories in cisa.gov's sitemap | 2004 onward | Every alert and advisory page the sitemap lists. |
| `mozilla-mfsa` | mozilla/foundation-security-advisories (MPL-2.0) | 2005 onward | Every advisory with a full announcement date. |
| `oracle-cpu` | Oracle's security alerts RSS | 2005 onward | Every Critical Patch Update and Security Alert in the feed whose page still resolves. Three retired 2005 and 2007 links are replaced by their `/security-alerts/` addresses; 16 items from 2005 to 2009 link to pages that answer 404 (checked 2026-11-03) and are counted in coverage, not published. An item whose title names an earlier month than its feed date has no publication date in the feed and is counted the same way. |
| `ubuntu-usn` | Ubuntu Security Notices API | October 2004 onward | Notices with a CVE that is in KEV or that another adapter's row cites. The notices API carries no priority field, so no severity filter is applied. |
| `nvd-cve` | NVD yearly JSON 2.0 feeds (the 2002 feed also holds the 1999 to 2001 CVEs) | 1999 onward | Only CVEs that another adapter's row cites, never a bulk CVE list. |

`coverage.json` also states the sources this archive does not collect. Adobe, VMware (Broadcom), Juniper, Citrix, SAP note details and Schneider Electric's own pages are `unreachable`: when checked they refused automated reads, served only a JavaScript application or needed a login. Red Hat, Siemens, Palo Alto Networks, Project Zero, Talos reports, Cisco openVuln and research blog archives are `gap` with the reason "adapter not built yet".

## Coverage statuses

| Status | Meaning |
| --- | --- |
| `complete` | Every item the source lists for that year is a row. |
| `filtered` | The adapter's stated filter, or the yearly cap, chose the rows. The filter text is in the row. |
| `partial` | Some listed items could not be read, link to pages that no longer resolve, or carry only a later posting date. The reason says how many of each. |
| `sample` | A fixed sample by design. |
| `gap` | No items that year: the source had not started, the series had ended, or no adapter exists yet. |
| `unreachable` | The source could not be read automatically. |

"Since 1998" never means "everything since 1998". For every source and year, coverage.json states what was collected and what was not.

## Publication

The publish step adds these rows to the v7 history shards, one per year. A row whose link is already a feed, KEV or curated row is left to that row. A year's shard never passes the shard byte bound because of these rows: if it would, that year's lowest-priority adapter rows are held back (NVD metadata rows first, then Ubuntu notices, then the per-CVE Microsoft rows; publisher, KEV and curated rows never), and `site/data/v7/coverage.json` lists each held-back count under `held_back`. The committed files here are unchanged either way.

## Commands

```sh
# Build one adapter (or all of them) at below-normal priority, then commit history/ in a pull request.
cmd /c start /belownormal /b /wait python -E -s -m intelligence_hub.history build --adapter msrc-bulletins --years 1998-2017

# The offline check that CI runs on every pull request.
python -E -s -m intelligence_hub.history check

# Rewrite coverage.json's source list and the rows for sources without an adapter, and print a summary.
python -E -s -m intelligence_hub.history coverage
```

`-E -s` keeps isolated mode apart from the path rule: `-I` would drop the checkout from `sys.path`, and the package is not installed. Raw responses are kept in `.state/history-raw/` (ignored by git), so `build --offline` repeats a build from exactly the same bytes. Build `ubuntu-usn` and then `nvd-cve` after the other adapters, because they read the CVE ids the others cite. A build ends with the full check, which fails until every adapter has been built at least once.

The fixtures in `tests/history/fixtures/` hold a few documents in each source's own format (identifiers, titles and dates only), and `history check` parses each one back to its golden file. `python -I tests/history/make_fixtures.py` rewrites the fixture documents and `python -E -s -m intelligence_hub.history fixtures` rewrites the golden files after a reviewed parser change.
