# TeamStarWolf Intelligence Hub

Open security news, advisories, and known exploited vulnerabilities for the community, linked to
their original sources. Every item links back to the publisher that wrote it, and every tag says
how it was found and how far to trust it.

**Site:** <https://teamstarwolf.github.io/intelligence-hub/>

## What you can do here

The page opens on the **Intelligence Explorer**: one search box, a filter rail, ten sort orders
and the results, over the live window (the last 24 months). Choose a year to add that year's
history rows, back to 1998. Everything else is a tab under one of four desks (Explore,
Security, Infrastructure, Reference; an IT lifecycle desk opens with its first view), and
every tab is also listed in the **Panels** sidebar, which starts closed:

| Tab | What it holds |
| --- | --- |
| Explore | Search, filters (desk, kind, source class, event type, exploitation, KEV-linked, CISA required action, sector, region, vendor, product, actor, malware, CWE, ATT&CK technique, source, year, month, date range), sort and results. |
| Today | The brief head (the day's counts in words, the service-health board, the latest Patch Tuesday brief and what is new since this browser's last visit), KEV additions by calendar day, KEV entries due in the next 14 days, then the last three days of advisories, research and press. |
| Advisories, Research, News | The Explorer limited to vendor and government sources, research teams, or the press. |
| Known exploited | CISA's KEV ledger by date added, with the directive each required action cites. |
| CVEs | Every CVE an entry mentions, with its guidance label, KEV state, CNA CVSS and FIRST's EPSS score (with the model and the score date); a CVE opens its source-led brief, its severity sources, its EPSS block and its CVE.org record. |
| History | One page per year from 1998. Each year opens with its per-source coverage statements, so a quiet year is never read as a year when nothing happened. |
| Vendors | Every vendor with entries or KEV entries, its KEV entries by year added, its products, and its TeamStarWolf library pages. |
| Tags | Every tag value on at least one entry, with its count and a page or Explorer filter. Values with no entry are not listed. |
| Actors and malware | Threat groups, malware and tools that entries name, each linking back to its library page. |
| Reports | Every report edition, the collector's run record and cadence, and the catalog's review notes. |
| Data | Per-year CSV and JSON Lines exports, the manifest, the data dictionary and the licence table. |
| Subscribe | The Hub's three Atom feeds (KEV additions, service-health incidents, the Patch Tuesday calendar) with the address to copy into a feed reader, then podcasts and newsletters as titles and links only. |
| Sources | The run record, the history coverage matrix by source and year, and the source ledger. |
| Method | The evidence rules, confidence levels, coverage statuses and licence notices. |
| About | What the Hub is and what it covers. |
| Patch Tuesday | Microsoft's monthly security release from the MSRC CVRF data: the headline numbers, what to prioritize by fixed rules, the exploited and publicly disclosed CVEs, the Critical CVEs, the product families, the KEV join, Adobe's and SAP's same-day bulletins as headline rows, and a brief for every monthly release back to January 2016. |
| Service health | The vendors' own status pages and cloud health feeds by group, open incidents, internet outage signals from IODA, and the last 30 days of incidents. |

Today and Service health take `?wall=1` for a monitor: the tab rows, controls and footer are
hidden and the type is larger, and nothing more is read.

The collector also writes three Atom feeds under `data/v7/feeds/`: `kev.xml` (the latest KEV
additions), `incidents.xml` (the latest service-health incidents) and `patch-calendar.xml` (the
next expected Patch Tuesday and every built monthly brief). Each carries the Hub's own titles,
dates and links to the Hub's routes, at most 50 entries, and changes only when its entries do.

Every view, filter, page and open entry has its own address; [docs/URLS.md](docs/URLS.md) is the
route contract that the TeamStarWolf library's links follow.

What the site shows is a publisher headline and link, CISA's own KEV text, or an original summary
written for this project. Full article bodies are not copied.

## How it works

A Python collector (standard library only, in `intelligence_hub/`) runs in GitHub Actions. It
reads 62 configured RSS and Atom feeds, the CISA KEV catalog, FIRST's EPSS API for the CVEs it
shows, and 46 official status sources plus
IODA's internet outage signals under strict size, time and format bounds, enriches mentioned CVEs
from the CVE Program's records, tags every row from controlled vocabularies, merges the committed
history files, and writes static files that the page in `site/` reads. Your browser reads those
files from this site; it never contacts publishers or the GitHub API. The one exception is the
Service health view's live board, described below.

- `data/v7/index.json` lists every data file with its size and sha256, the content date and the
  collector's run record. Views read only the files they need: the Explorer reads the live months,
  a History year reads that year's file, and Vendors reads the KEV ledger.
- History rows from 1998 come from adapters under `intelligence_hub/history/` that run locally and
  are committed under `history/`; each source has a coverage statement for every year
  ([SOURCES.md](docs/SOURCES.md), [METHOD.md](docs/METHOD.md)).
- Tags come from `config/vocab/` and a pinned copy of the library's shared vocabulary
  ([TAGGING.md](docs/TAGGING.md)). Links to the TeamStarWolf library are generated from that
  vocabulary into `site/js/library.js`; the page builds no library link by hand.
- Patch Tuesday briefs come from the Microsoft Security Response Center CVRF API. Every run reads MSRC's list of monthly releases and
  rebuilds a month when its release first appears or its revision changes; the second Tuesday is never assumed. The CISA KEV
  catalog, the Hub's CVE briefs, Adobe's bulletin index and SAP's Security Patch Day page are joined to each month
  ([OPERATIONS.md](docs/OPERATIONS.md#patch-tuesday-briefs)).
- Service health reads each vendor's own status page API or feed, the cloud providers' public
  health feeds and IODA's outage events ([SOURCES.md](docs/SOURCES.md#service-health-sources)).
  Incidents of minor impact and above also appear in the Explorer as outage entries with their
  vendor. The Service health view's live board makes requests from your browser to the listed vendor status hosts when the view opens and every five minutes while it stays open and the tab is visible. Pause live updates stops them, and so does leaving the view.
- Report editions in `reports/` come from a separate desktop compiler that the owner runs; the
  collector only lists them. If the report catalog is missing, too large or invalid, the data still
  publishes and the Reports tab says the catalog is unavailable.

The publish workflow asks GitHub for a run every two hours (`7 */2 * * *`), and pushes to `main` and
manual runs add more. GitHub starts scheduled runs late or skips them, so a new item can take
several hours to appear. The content date is the only freshness promise; the Reports and Sources
tabs and the sidebar show the last published runs and the observed gap between them.

Publishing fails closed. Official GitHub actions are pinned to commits, checkout has read-only
access without persisted credentials, and only a separate deploy job can write to Pages. A failed
collection, invalid output or a package-budget failure blocks that publication and keeps the
previous live site.

## Run the collector locally

Python 3.10 or newer, standard library only. From the repository folder:

```sh
python -m intelligence_hub                                       # 1 January 1998 to today, live reads
python -m intelligence_hub --start 1998-01-01 --end 2026-11-01   # a fixed window
python -m intelligence_hub --cached                              # rebuild from local caches, no network
```

The collector writes `site/data/`. CI adds `--resume-public` to recover retained history and CNA
progress from this Hub's own published snapshot; `--cached` cannot be combined with it. The default
CNA enrichment budget is 40 CVE record requests per run; push-triggered CI runs use 2,000, and
`--enrich-limit 0` turns the lookups off. See the [operator guide](docs/OPERATIONS.md),
[feed intake](docs/FEEDS.md) and [CVE guidance](docs/MITIGATIONS.md).

## Contributing

Every change arrives as a pull request and is squash-merged by someone other than its author after
review; [AGENTS.md](AGENTS.md) holds the full rules and the local gates. The pull-request check runs
the unit tests, the fixture and history checks, an offline build on a committed fixture, the
page-file and stamping check, the generated label and library-link modules, a syntax check of every
module in `site/files.json`, the site tests (`node --test`, no npm), a contrast check of both
themes, the 12 px type floor and an em-dash lint. New code needs tests.

## Limits

- **Selected, not complete.** The Hub is a selected collection, not every incident, article or
  vulnerability. History coverage differs by source and year, and each year page says how.
- **Bounded intake.** Each accepted feed response yields at most 150 entries, and an entry with an
  invalid link or title or more than 100 unique CVE mentions is rejected whole. Partial means some
  safe input was accepted with a gap. See
  [intake accounting](docs/FEEDS.md#partial-intake-and-entry-accounting).
- **Subsets are subsets.** The
  [Talos Threat Advisory category](docs/FEEDS.md#talos-threat-advisory-category-subset), the
  [CISA Cybersecurity Advisories category](docs/FEEDS.md#cisa-cybersecurity-advisories-category-subset)
  and the [Qualys Security Blog](docs/FEEDS.md#qualys-security-blog-dated-partial-admission) do
  not establish complete coverage of those publishers. Threatpost is a legacy archive with observed
  August 2022 items.
- **Dates mean different things.** Publication, update, event and CISA catalog-addition dates stay
  distinct. A KEV date marks catalog addition, not first disclosure or first exploitation.
- **Tags are evidence, not verdicts.** Unknown exploitation never means safe. A name in a headline
  is a mention, not attribution. ATT&CK techniques reached through CWE and CAPEC are taxonomy, not
  observed behaviour.
- **Briefs are not patch orders.** Affected version ranges are not fixed versions, CVSS versions
  are not merged, and no entry proves that a device is exposed. CISA's federal due dates are not
  your deadlines.
- **Collector integrations.** The collector makes no Grok or xAI calls, reads no X timeline or
  bookmarks and posts nothing to X. Direct SEC filing intake is pending after HTTP 403.
- **No delivery promise.** GitHub can delay, drop or disable scheduled runs. Check the
  [workflow history](https://github.com/TeamStarWolf/intelligence-hub/actions/workflows/publish.yml)
  when the content date looks old.
- **Package budget.** Only the page files `site/files.json` lists and the data files
  `data/v7/index.json` lists enter Pages. A publication must fit 192 MiB of input, at most 4,000
  files, at most 4 MiB for each v7 file and a 48,000,000-byte compressed-size estimate, and the
  artifact is kept for one day.
- **Patch Tuesday is Microsoft's data.** Rows, severities, CVSS scores and the exploited, publicly disclosed and exploitability
  values are the MSRC CVRF document's at its last revision. Azure Linux, CBL-Mariner and open-source package CVEs that the
  documents also list are counted and left out. Adobe and SAP appear as headline rows only (ids, titles, dates, priorities and
  links), and SAP rows start in 2024 because earlier years are PDF bulletins. The priority list follows fixed rules, not an
  assessment of your environment.
- **Service health is the vendor's word.** A status entry is what the vendor states about its
  own service, and an IODA row is a measured signal, not a confirmed cause. Neither says anything
  about your tenant, region or account, and the collector's snapshot is only as fresh as its last
  run; the live board refreshes the CORS-open Statuspage cards from your browser.
- **Read-only.** The site has no accounts, trackers or paid API fallback.

## Licences and notices

The Hub's code is MIT-licensed. Publisher headlines and links belong to their publishers; KEV
entries are CISA's text, which CISA distributes under CC0 1.0; CVE record fields are used under the
CVE Program Terms of Use; EPSS scores are FIRST's, shown with attribution as FIRST asks; curated
summaries are original paraphrases. MITRE ATT&CK, CWE and CAPEC
content carries the designations in [METHOD.md](docs/METHOD.md#licences-and-notices). This project
is not affiliated with MITRE, with Nintendo or with any news publisher.
