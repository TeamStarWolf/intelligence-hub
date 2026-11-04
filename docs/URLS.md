# Intelligence Hub URLs

Every view, filter, sort, page and open record on the Intelligence Hub has its own address,
so a reader can bookmark a view or share it and the TeamStarWolf library can link straight to
the entries for a vendor, a year or a CVE. This page is the route contract. The library's link
generator builds Hub links from it, and `tests/js/router.test.js` holds the page to it.

## Form

```
https://teamstarwolf.github.io/intelligence-hub/#/<view>[/<id>][?<key>=<value>&...]
```

The route lives after `#`, so GitHub Pages serves the same `index.html` for every view and no
server rewrite is needed. Values are percent-encoded; a space in `q` may be written `+`.

## Views

| Route | What it shows | Default date range |
| --- | --- | --- |
| `#/` or `#/explore` | The Intelligence Explorer: search, filters, sort and results over the live window (the last 24 months) | whole live window |
| `#/today` | KEV additions by calendar day, KEV entries whose CISA federal due date falls in the next 14 days, then the last three calendar days of advisories, research and press | fixed: the content date and the 2 days before it |
| `#/advisories` | The Explorer limited to vendor-primary and government or CERT sources (KEV catalog entries excluded) | last 30 days |
| `#/kev` | CISA's KEV ledger by date added, with the directive each entry's required action cites | added in the last 30 days |
| `#/research` | The Explorer limited to research sources | last 30 days |
| `#/news` | The Explorer limited to press sources | last 7 days |
| `#/cves` | The CVE register: every CVE a saved entry mentions | none |
| `#/cve/<CVE-id>` | The register with that CVE's saved brief open in a dialog | none |
| `#/history` | The year index from 1998: history rows, the sources that supplied them and the coverage statuses for each year | none |
| `#/history/<year>` | One year: the per-source coverage statements first, then rows per month and per source, oldest first | none |
| `#/vendors` | Every vendor with an entry in the live window or in the KEV catalog, with its library pages | live window |
| `#/vendor/<id>` | One vendor: its library pages, its KEV entries by year added, products and entries | live window |
| `#/tags` | Every tag value on at least one entry, with its count and a page or Explorer filter | live window, or `year` |
| `#/actors` | Threat groups, malware and tools named on entries, with their library pages | live window, or `year` |
| `#/actor/<id>`, `#/malware/<id>` | One actor or one piece of software: its library page and entries | live window |
| `#/reports` | Every report edition from the validated report catalog, the collector's run record and the catalog's review notes | none |
| `#/sources` | The run record, the history coverage matrix by source and year, and the source ledger | none |
| `#/method` | Evidence rules, confidence levels, coverage statuses, dates and scores, and the licence and notice table | none |
| `#/data` | Per-year analytics exports, the manifest, the data dictionary and the licence table | none |
| `#/about` | What the Hub is, what it covers, how fresh it is, and the notices | none |
| `#/status` | Service health: the live board of vendor status pages and cloud health feeds by group, open incidents, internet outage signals and the incidents of the last 30 days | the 30 days before the snapshot's read |
| `#/status?source=<id>` | Service health for one source from `config/status.json`, such as `github` | the 30 days before the snapshot's read |

A `<CVE-id>` matches `CVE-YYYY-NNNN` with 4 to 19 digits after the year. A `<year>` is `1998` to
`2099`. A vendor `<id>` is a vocabulary vendor id without its prefix (`fortinet`); an actor or
malware `<id>` is an ATT&CK id (`G0016`, `S0154`) or a vocabulary slug (`storm-0940`). Any other
path opens the Explorer; `#/cve`, `#/vendor`, `#/actor` and `#/malware` with no valid id open
their index view, and `#/history/<year>` with an invalid year opens the year index.

`#/tag/<field>/<value>` is an alias: the page rewrites it to the Explorer filter for that value,
so `#/tag/vendor/fortinet` becomes `#/explore?vendor=fortinet`. `<field>` is a query key from the
table below or the field's name in a row's tagging block (`source_class`, `event_type`,
`exploitation`, `attack`).

## Query keys

The list views are `explore`, `advisories`, `research` and `news`. Keys a view does not read
are dropped.

| Key | Views | Values | Effect |
| --- | --- | --- | --- |
| `q` | list, `kev`, `cves` | free text, 1 to 200 characters, no `<`, `>` or control characters | every word must appear in the entry |
| `kind` | list | `advisory`, `research`, `reporting`, `incident`, `kev`, `filing`, `bulletin`, `note` | entry kind |
| `class` | list | `vendor-primary`, `government-cert`, `researcher`, `press` | source class |
| `event` | list | `disclosure`, `exploitation`, `patch`, `breach`, `outage`, `takedown`, `policy`, `analysis`, `unclassified` | event type tag |
| `exp` | list | `known`, `reported`, `unknown` | exploitation state |
| `kev` | list, `cves` | `1` | KEV-linked: the entry is a KEV entry or one of its CVEs is in CISA's KEV catalog |
| `action` | list, `cves` | `1` | one of the entry's CVEs carries CISA's required action |
| `vendor` | list | a vocabulary vendor id without its prefix, such as `fortinet` | vendor tag `vendor:<value>` |
| `product` | list | a product id without its prefix, such as `pan-os` | product tag `product:<value>` |
| `actor` | list | an actor id without its prefix, such as `G0016` | actor tag `actor:<value>` |
| `malware` | list | a malware id without its prefix, such as `S0154` | malware tag `malware:<value>` |
| `cwe` | list | a CWE id, such as `CWE-787` | weakness tag |
| `tech` | list | an ATT&CK technique id, such as `T1190` or `T1059.001` | technique tag (reached through CWE and CAPEC, low confidence) |
| `sector` | list | a sector id without its prefix, such as `healthcare-public-health` | sector tag `sector:<value>` |
| `region` | list | an ISO 3166-1 alpha-2 code, `EU`, or `M49-` and three digits | region tag |
| `source` | list, `history/<year>` | a source id from `config/sources.json`, a history source id from `data/v7/coverage.json`, or `status-` and a service-health source id for its incident rows, such as `cisa-advisories`, `microsoft-bulletins` or `status-github` | one source |
| `source` | `status` | a service-health source id from `config/status.json`, such as `github` | that source's card, open incidents and recent incidents |
| `year` | list, `kev`, `tags`, `actors` | `1998` to `2099` | that calendar year; on a list view, `tags` and `actors` it also reads that year's history rows |
| `month` | list, `history/<year>` | `01` to `12`, with `year` on a list view | that month |
| `range` | list, `kev` | `3`, `7`, `30`, `90`, `365`, `all` | the last N days ending on the content date; `year` replaces it |
| `sort` | list | `date-desc`, `date-asc`, `title-asc`, `title-desc`, `source-asc`, `source-desc`, `cve-asc`, `cve-desc`, `cvss-desc`, `cvss-asc` | result order |
| `sort` | `kev` | `added-desc`, `added-asc`, `due-asc`, `due-desc`, `cve-desc`, `cve-asc` | ledger order |
| `sort` | `cves` | `cve-desc`, `cve-asc`, `cvss-desc`, `cvss-asc`, `kev-desc` | register order |
| `page` | list, `kev`, `cves`, `history/<year>`, `vendor`, `actor`, `malware` | `1` to `9999` | result page, 25 rows each |
| `open` | list | an entry id, such as `feed-3f41d3f2c16c88f054f7` | opens that entry's detail dialog |

The page writes keys in the order of this table and leaves out default values (`sort` at its
view default, `page=1`, `range` at its view default). Vocabulary ids come from the library's
shared vocabulary (`config/vocabulary.json`, vendored from the library's
`data/vocab/entities.jsonl`); a link generator takes them from that file and never builds
them by hand.

## How the page treats an address

- A key that is not in the table, or a value that fails its check, is dropped. Nothing from the
  address is written into the page as markup; text is set with `textContent` only.
- The page replaces the address with the canonical form, so a cleaned link is what a reader
  copies afterwards.
- A filter, sort or search change replaces the current history entry. Opening a view, a page,
  an entry or a CVE adds one, so Back closes the dialog or returns to the earlier view.

## Earlier link forms

Links written before the routed shell keep working. The page reads them once, rewrites the
address to the hash route and drops the query string.

| Earlier form | Becomes |
| --- | --- |
| `?tag=vendor:<id>`, `?tag=product:<id>`, `?tag=actor:<id>`, `?tag=malware:<id>`, `?tag=sector:<id>` | the matching key, such as `#/explore?vendor=<id>` |
| `?kind=<kind>`, `?q=<text>`, `?year=<YYYY>` | the same key on `#/explore` |
| `?month=<YYYY-MM>` | `#/explore?year=<YYYY>&month=<MM>` |
| `?view=feed` | `#/explore` |
| `?view=cves` | `#/cves` |
| `?cve=<CVE-id>` | `#/cve/<CVE-id>` |
| `#briefing`, `#timeline`, `#top` | `#/explore` |
| `#reports` | `#/reports` |
| `#method` | `#/method` |
| `#knowledge` | `#/about` |

## Examples

| Purpose | Link |
| --- | --- |
| Everything tagged with a vendor | `https://teamstarwolf.github.io/intelligence-hub/#/explore?vendor=fortinet` |
| That vendor's KEV-linked entries | `https://teamstarwolf.github.io/intelligence-hub/#/explore?kev=1&vendor=fortinet` |
| A year, history rows included | `https://teamstarwolf.github.io/intelligence-hub/#/explore?year=2003` |
| Reporting in one year | `https://teamstarwolf.github.io/intelligence-hub/#/explore?kind=reporting&year=2025` |
| One CVE's brief | `https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-44228` |
| An actor's entries in the Explorer | `https://teamstarwolf.github.io/intelligence-hub/#/explore?actor=G0016` |
| An actor's page | `https://teamstarwolf.github.io/intelligence-hub/#/actor/G0016` |
| A vendor's page | `https://teamstarwolf.github.io/intelligence-hub/#/vendor/fortinet` |
| One year of history with its coverage | `https://teamstarwolf.github.io/intelligence-hub/#/history/1998` |
| Every tag value in one year | `https://teamstarwolf.github.io/intelligence-hub/#/tags?year=2024` |
| KEV additions in the last 90 days | `https://teamstarwolf.github.io/intelligence-hub/#/kev?range=90` |

A change to this contract changes `site/js/router.js`, its tests and this page in the same pull
request, and the library's generator follows.
