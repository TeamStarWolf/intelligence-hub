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
| `#/reports` | Report editions from the validated report catalog | none |
| `#/sources` | The run record and the source ledger | none |
| `#/data` | Per-year analytics exports, the manifest and the data dictionary | none |
| `#/about` | What the Hub is, its method and limits, and the notices | none |

A `<CVE-id>` matches `CVE-YYYY-NNNN` with 4 to 19 digits after the year. Any other path opens
the Explorer, and `#/cve` with no valid id opens the register.

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
| `sector` | list | a sector id without its prefix, such as `healthcare-public-health` | sector tag `sector:<value>` |
| `region` | list | an ISO 3166-1 alpha-2 code, `EU`, or `M49-` and three digits | region tag |
| `source` | list | a source id from `config/sources.json`, such as `cisa-advisories` | one source |
| `year` | list, `kev` | `1998` to `2099` | that calendar year; on a list view it also reads that year's history rows |
| `month` | list | `01` to `12`, with `year` | that month |
| `range` | list, `kev` | `3`, `7`, `30`, `90`, `365`, `all` | the last N days ending on the content date; `year` replaces it |
| `sort` | list | `date-desc`, `date-asc`, `title-asc`, `title-desc`, `source-asc`, `source-desc`, `cve-asc`, `cve-desc`, `cvss-desc`, `cvss-asc` | result order |
| `sort` | `kev` | `added-desc`, `added-asc`, `due-asc`, `due-desc`, `cve-desc`, `cve-asc` | ledger order |
| `sort` | `cves` | `cve-desc`, `cve-asc`, `cvss-desc`, `cvss-asc`, `kev-desc` | register order |
| `page` | list, `kev`, `cves` | `1` to `9999` | result page, 25 rows each |
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
| `#method`, `#knowledge` | `#/about` |

## Examples

| Purpose | Link |
| --- | --- |
| Everything tagged with a vendor | `https://teamstarwolf.github.io/intelligence-hub/#/explore?vendor=fortinet` |
| That vendor's KEV-linked entries | `https://teamstarwolf.github.io/intelligence-hub/#/explore?kev=1&vendor=fortinet` |
| A year, history rows included | `https://teamstarwolf.github.io/intelligence-hub/#/explore?year=2003` |
| Reporting in one year | `https://teamstarwolf.github.io/intelligence-hub/#/explore?kind=reporting&year=2025` |
| One CVE's brief | `https://teamstarwolf.github.io/intelligence-hub/#/cve/CVE-2021-44228` |
| An actor | `https://teamstarwolf.github.io/intelligence-hub/#/explore?actor=G0016` |
| KEV additions in the last 90 days | `https://teamstarwolf.github.io/intelligence-hub/#/kev?range=90` |

A change to this contract changes `site/js/router.js`, its tests and this page in the same pull
request, and the library's generator follows.
