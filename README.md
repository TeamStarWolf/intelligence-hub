# TeamStarWolf Intelligence Hub

A free, public security news desk for defenders. It gathers current publisher
headlines, CISA's Known Exploited Vulnerabilities (KEV), source-linked CVE briefs
and dated report editions in one place, and every item links back to the
publisher that wrote it.

**Site:** <https://teamstarwolf.github.io/intelligence-hub/>

## What you can do here

- Read headlines from **62 configured publisher RSS/Atom feeds** plus CISA's KEV
  catalog. The count is feed definitions, not unique publishers. Feeds can fail,
  and every outcome stays visible in the source ledger.
- Browse by year and month or a date preset, filter by source, kind, exploitation
  and guidance, and sort ten ways by date, title, source, CVE and CVSS.
- Open a CVE brief with CISA's required action where one exists, the CNA's
  product and version data, guidance excerpts and the original references.
- Look back through selected history since 1998: curated primary publications,
  starting with the 1 June 1998 MS98-001 bulletin, with the gaps listed openly.
- Read the daily, weekly, monthly and longer [report editions](reports/README.md).

What the site shows is a publisher headline and link, CISA's own KEV text, or an
original summary written for this project. Full article bodies are not copied.

## How it works

A Python collector (standard library only, in `intelligence_hub/`) runs in GitHub
Actions. It reads the configured feeds and the KEV catalog under strict size,
time and format bounds, enriches mentioned CVEs from official CVE records, and
writes one snapshot that the static site in `site/` renders. The browser never
contacts publishers.

The publish workflow asks GitHub for a run every two hours (`7 */2 * * *`).
GitHub does not guarantee scheduled runs: between 30 October and 3 November 2026
they came about every 3 to 10 hours, so a new item can take several hours to
appear. Pushes to `main` and manual runs add extra collections. The page header
shows the content date, the last published run and the observed gap between
published runs, all read from `data/v7/index.json`.

Report editions in `reports/` come from a separate desktop compiler that the
owner runs; the collector only lists them. Requested daily slots are
**06:00, 14:00 and 22:00 America/Chicago**, with 24-hour weekday or 48-hour
weekend lookbacks. Weekly, weekend, fortnightly, monthly, quarterly and rolling
six-completed-month editions follow the [calendar method](reports/REPORTING.md).
If the report catalog is missing, too large or invalid, the feed still publishes
and the report listing says it is unavailable.

Schemas 5 and 6 carry bounded, source-led context for CWE weaknesses, CAPEC
taxonomy, actors and campaigns, products and mitigations. CVE-to-CWE links come
only from the CNA's structured problemTypes, and official CWE-to-CAPEC links are
taxonomy, not observed attacks. No CVE is guessed from a headline, and a KEV
match does not rewrite an entry's own exploitation label. The 48 to 96-hour
citation review stays `not_run` until a separately recorded pass.

Publishing fails closed. Official GitHub actions are pinned to commits, checkout
has read-only access without persisted credentials, and only a separate deploy
job can write to Pages. Failed collection, invalid output or a package budget
failure blocks that publication and keeps the previous live site. The collector
rejects redirects, DTDs and entities, oversized inputs and article links outside
each publisher's allowlist.

## Run the collector locally

Python 3.10 or newer, standard library only. From the repository folder:

```sh
python -m intelligence_hub
```

An explicit historical window:

```sh
python -m intelligence_hub --start 1998-01-01 --end 2026-10-26
```

These commands make bounded public HTTPS reads and write the snapshot to
`site/data/feed.json` and its CVE briefs to `site/data/briefs.json`. CI adds `--resume-public` to recover retained history and
CNA progress from this hub's own fixed, validated public snapshot; that is not an
arbitrary URL import. `--cached` rebuilds from retained local public inputs
without network access and cannot be combined with `--resume-public`.

The default CNA enrichment budget is **40 official CVE record requests per run**.
Scheduled and manual CI runs keep that limit; push-triggered runs use a
**2,000-request bootstrap budget** through `--enrich-limit`, and
`--enrich-limit 0` disables the lookups. The collection job has a 15-minute
timeout. Neither budget means every CVE has been enriched.

Run the unit tests. They include offline `--cached` builds in a throwaway copy
of the repository, so they never touch your own `.state/` or `reports/`:

```sh
python -I -m unittest discover -s tests
```

See [historical sources](docs/SOURCES.md), [feed intake](docs/FEEDS.md),
[CVE guidance](docs/MITIGATIONS.md) and the [operator guide](docs/OPERATIONS.md)
for evidence states, retention and commands. Local caches and research receipts
stay outside Git.

## Contributing

Every change arrives as a pull request and is squash-merged by someone other
than its author after review; [AGENTS.md](AGENTS.md) holds the full rules. The
pull-request check runs the unit tests, an offline build on a committed fixture,
the page-file and stamping check, a syntax check of every module in `site/files.json`,
the site tests (`node --test`, no npm), a contrast check of both themes, the 12 px type
floor and an em-dash lint. New code needs tests. Hub links follow the route contract in
[docs/URLS.md](docs/URLS.md).

## Limits

- **Selected, not complete.** The hub is a selected collection within its date
  window, not every incident, article or vulnerability. The schema 6 and 7 window runs
  from 1 January 1998 to the run date, within a 14,610-day technical review
  horizon; that is not forty years of coverage. Schema 5 keeps its 7,306-day
  profile and legacy schemas 2 to 4 keep 3,661 days.
- **Bounded intake.** Each accepted feed response yields at most **150 entries**.
  An invalid link or title, or more than **100 unique CVE mentions**, rejects that
  whole entry. `data/feed.json` is bounded at **8 MiB** and `data/briefs.json` at
  **12 MiB**; a run that would cross either bound fails without evicting rows. **Partial** means some safe input was accepted with a gap, not
  that the publisher's archive is complete. See
  [intake accounting](docs/FEEDS.md#partial-intake-and-entry-accounting) and the
  [F5 date ranking](docs/FEEDS.md#f5-date-ranking-and-selection-provenance).
- **Subsets are subsets.** The
  [Talos Threat Advisory category](docs/FEEDS.md#talos-threat-advisory-category-subset),
  the [CISA Cybersecurity Advisories category](docs/FEEDS.md#cisa-cybersecurity-advisories-category-subset)
  and the [Qualys Security Blog](docs/FEEDS.md#qualys-security-blog-dated-partial-admission)
  are separate inputs that do not establish complete coverage of those
  publishers. Threatpost is a **legacy archive with observed August 2022 items**;
  a successful fetch does not make those stories current.
- **Dates mean different things.** Publication, update, incident and CISA
  catalog-addition dates stay distinct. KEV dates mark catalog addition, not first
  disclosure or first exploitation.
- **Briefs are not patch orders.** Affected version ranges are not fixed
  versions, and CVSS versions are not normalized into an environment risk score.
  A CVE mention does not prove exploitation or device exposure. Where no
  solution or workaround is established, the brief says **Needs review** and
  links the original material. Rejected CVE records need reconciliation before
  older claims are treated as active.
- **Collector integrations.** The collector makes no Grok or xAI calls, reads no
  X timeline or bookmarks and posts nothing to X. Direct SEC filing intake is
  **pending after HTTP 403**, so news coverage of filings is not complete
  Item 1.05 or 8.01 coverage.
- **No delivery promise.** GitHub can delay, drop or disable scheduled runs, and
  an unchanged run can succeed without a newer snapshot. Check the
  [workflow history](https://github.com/TeamStarWolf/intelligence-hub/actions/workflows/publish.yml)
  when the desk looks stale.
- **Package budget.** Only allowlisted files that `data/v7/index.json` lists
  enter Pages: the four page files, `data/feed.json`, `data/briefs.json`, the v7
  shards and the analytics exports. A changed publication must fit **192 MiB of
  input**, at most **4,000 files**, at most **4 MiB** for each v7 shard or export
  file and a **48,000,000-byte** level-6 compressed-size estimate, and the
  artifact is kept for one day. At the requested twelve scheduled publications a
  day that is at most **576 MB** a day; actual scheduled runs are fewer. This
  bounds the project's estimated footprint, not account-wide billing.
  [GitHub documents separate runner and storage allowances](https://docs.github.com/en/billing/concepts/product-billing/github-actions).
- **Read-only.** The public site has no accounts, trackers or paid API fallback.
  Owner changes to sources, curation, scheduling or publication happen through
  this repository. Never put credentials or private social material into the
  public site.

## License

The original implementation is MIT licensed. Publisher headlines, articles,
trademarks and linked material keep their owners' rights. This project is not
affiliated with Nintendo or with any news publisher.
