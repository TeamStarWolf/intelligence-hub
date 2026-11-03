# Intelligence Hub operator guide

## Read the desk

Open the public GitHub Pages address in a desktop or phone browser. Reading does
not require sign-in. Actual rendering and assistive-technology behavior still
require owner review.

Use **Intelligence explorer** to search; all entered words must match. Filter by
Kind, Source, Exploitation or CVE guidance, then navigate calendar years/months or
a date preset. Presets use the snapshot window's end, not a promise that its data
is current to the device's clock. The selected archive's boundary years and months can be
partial.

Ten sort choices cover newest/oldest date, title, source, CVE and CVSS direction.
Unknown scores remain unknown, and different CVSS versions are not normalized.
The CVE register collects referenced identifiers across articles; one CVE can
have several publisher accounts. A CVE mention is not evidence that the
article's entire incident exploited that CVE.

Open **CVE guidance** for an attributed brief and **Source ledger** for recorded
collection outcomes. An open dialog keeps its original snapshot and date; close
and reopen it to inspect newer saved data. Search choices and loaded-page count
are retained during background snapshot updates.

## Interpret evidence before action

The configured inputs are **62 RSS/Atom publisher feeds**, CISA KEV and **74 curated
primary publications**. A configured feed is not necessarily healthy. Recent RSS,
bounded retained items and manual curation do not form a complete historical archive.
See [feed evidence](FEEDS.md) and [history coverage](SOURCES.md).

The count is feed definitions, not unique publishers. **Cisco Talos Threat Advisory
(category subset)** is a separate, narrower source with its own dates and outcomes.
It does not establish the original all-Talos source's outcome or supply a complete
archive; see its [dated intake scope](FEEDS.md#talos-threat-advisory-category-subset).

**CISA Cybersecurity Advisories (category subset)** likewise has a separate ledger
entry. Its accepted category response does not repair the original all-advisories
source or cover every CISA publication. See its
[dated intake scope](FEEDS.md#cisa-cybersecurity-advisories-category-subset).

**Qualys Security Blog** mixes vendor research and product posts. A previous
whole-feed rejection is retained as historical evidence; the newer entry policy
can admit safe articles while rejecting an entire article with too many CVE
mentions. Its source ledger can therefore show **partial** with retained history.
See [Qualys admission scope](FEEDS.md#qualys-security-blog-dated-partial-admission); neither that status
nor a successful transport establishes a complete advisory archive.

Publication dates, publisher update dates, separate event dates and KEV catalog
addition dates have different meanings. Unknown dates are not replaced with
retrieval time. Threatpost's observed returned dates end in **August 2022**;
those entries belong to the historical window and are not current news.

CVE briefs combine separately attributed inputs:

- **Publisher guidance** means structured CNA solutions or workarounds were available. Excerpts and product/version conditions are bounded; follow the original advisory.
- **CISA action** presents the catalog's required action. It can remain available while CNA lookup is pending or failed.
- **Needs review** means the loaded structured data does not establish a solution/workaround, or the official record is rejected. Missing guidance is unknown, not no action required.
- CNA retrieval states **pending**, **ok** and **failed** describe that lookup. A retained successful record keeps its original retrieval date after a failed attempt.
- Affected ranges are not a list of fixed versions. CISA's federal due dates are not deadlines assigned to site visitors. KEV presence does not establish local applicability.
- A rejected CVE record requires reconciliation with its explanation and any replacement identifier before selecting remediation.

The brief's next-step checklist is deterministic source-based guidance. It does
not scan an environment, patch a device, execute commands or verify remediation.
After any separately authorized change, verify the installed product/configuration
against current vendor guidance and retain evidence.

## Collection schedule and publication

GitHub Actions requests collection every two hours at minute 7 (`7 */2 * * *`),
as well as on pushes to `main` and manual dispatch. Manual action:
repository **Actions → Refresh and publish Intelligence Hub → Run workflow**.

GitHub does not guarantee scheduled runs. Between 30 October and 3 November 2026,
under the older request for six runs an hour, the gaps between scheduled
runs were about 3 to 10 hours. The two-hour request asks for no more than GitHub
actually delivered; it is not the real cadence either.

GitHub documents a five-minute minimum, default-branch execution, possible delays
or dropped jobs under load, and disabling after 60 days of public-repository
inactivity. The offset avoids the top of the hour but cannot guarantee timing.
See [schedule behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).
Check the [workflow history](https://github.com/TeamStarWolf/intelligence-hub/actions/workflows/publish.yml)
when the desk appears stale; an owner can re-enable a disabled workflow.

### The run record in data/v7/index.json

Every published run appends itself to `runs` in `data/v7/index.json`, which keeps
the last 20 runs, newest first. Each entry has the collector's own `generated_at`
clock and the event that started it (`schedule`, `push`, `workflow_dispatch`, or
`local` for a build outside Actions). The first run after schema 7 shards were
added has no earlier index, so it records the previous v6 feed's generation time
as one `unrecorded` entry. `observed_interval_hours` gives the median and the
longest gap between the recorded runs, and `requested_cron` repeats the request.

Only published runs are recorded: a run that finds nothing new does not publish,
so it leaves no entry, and the gaps measure time between publications. The page
header reads the content date, the last published run and the observed median
from this file. The site makes no request to the GitHub API.

The browser rechecks this site's saved snapshot while the page stays visible.
Refreshing the browser does not start publisher collection. Publisher cadence,
the workflow, collection duration, deployment and browser visibility all affect
arrival time. This is not continuous monitoring or a delivery SLA. The snapshot
badge shows its age in minutes independently of the latest browser read; reading
the same saved file never claims a new publisher collection.

On its first successful read, the page says **published snapshot loaded**. An
identical saved file says **same saved snapshot**. A different file says
**different saved snapshot** and whether the browser detects a later generation
time, an earlier one, or no difference at its timestamp precision, compared with
the snapshot previously displayed in this page session. No detected difference
does not establish exact timestamp equality. These labels compare saved files
and clocks, not newly collected intelligence. An earlier generation can still be
displayed with its original time.

The snapshot marker changes when its generation time is more than 24 hours old
or more than five minutes ahead of the device clock. This is an age/clock warning,
not an assessment of workflow health or source freshness. A normal marker does
not establish that collection is current.

### The publication decision

The collector records a typed Boolean `changed` decision in
`.state/collection-result.json`, with `changed_shards` and `removed_shards`: the
v7 paths whose sha256 differs from the previous index, and the paths it no longer
lists. Article, guidance, source-outcome, intake-count/reason and layout changes
can trigger publication, and so can any changed or removed shard except
`sources.json`, which carries every run's attempt clocks. Publisher-feed response
hashes and collection attempt clocks alone do not; changes to retained CVE
evidence, including its response hash, can. The workflow reads the file under a
64 KiB bound and checks every field's type before the package step runs.

An unchanged successful check therefore keeps the prior deployed snapshot time.
The **Snapshot generated** clock remains the saved snapshot's generation time. A browser
read or successful workflow result never replaces that date or the source dates.

### Schema 7 shards

Beside `data/feed.json` and `data/briefs.json`, which the page still reads, the
collector writes `site/data/v7/`:

| File | Content |
| --- | --- |
| `index.json` | Schema, clocks, content date, the run record, counts, and every shard with path, rows, bytes, sha256 and date span |
| `live/YYYY-MM.json` | Publisher and KEV rows whose primary date falls in that month, for the current month and the 23 before it; `live/undated.json` holds rows without a date |
| `history/YYYY.json` | Rows older than the live window, plus every curated archive row and every committed history-adapter row (`history/` at the repository root, see [history/README.md](../history/README.md)) for that year |
| `kev/YYYY.json` | The whole KEV catalog by `dateAdded` year: due date, the directive parsed from `requiredAction` (for example BOD 22-01, BOD 26-04 or an Emergency Directive such as ED 26-03, which CISA writes out as "Emergency Directive 26-03" or "Emergency Directive (ED) 25-03"; several are joined as "BOD 22-01; ED 26-03"; null when none is cited), ransomware use, forensic triage, CWE and CISA's own text |
| `cve-index.json` | One row per CVE with the list-view fields and where its full brief is read |
| `sources.json` | The source ledger |
| `coverage.json` | One coverage statement per source and year from 1998 (complete, filtered, partial, sample, gap or unreachable), copied from the committed `history/coverage.json`, plus any adapter rows held back to keep a year shard inside its byte bound; a stub that says why when the committed file is missing or invalid |
| `reports.json` | A copy of the validated `reports/catalog.json`, or status `unavailable` with the reason |

Every file is canonical JSON: sorted keys, compact separators, UTF-8 and one
trailing newline, rows in a fixed order. The same inputs give the same bytes, so
a shard's sha256 changes only when its content does. Article rows keep the v6
feed record unchanged. A `--resume-public` run reads `index.json`, the article and
source shards it lists and `data/briefs.json`, checks each against its listed
bytes and sha256, and never reads `data/feed.json`. If the index is missing or a
file differs from it after one retry, the run resumes from the feed instead.

CVE brief buckets (`cve/YYYY/NNNk.json`) are built and tested but not published:
they would copy every brief in `data/briefs.json` (about 9 MB). They stay off until
a later change retires the v6 briefs file, and `cve-index.json` names
`data/briefs.json` as the brief source until then.

The analytics exports (`data/v7/exports/`: per-year CSV and JSON Lines files, their
`manifest.json` and `data-dictionary.md`) are published, and `index.json` lists each
under `exports` with its bytes and sha256. A run whose tagging is unavailable, or
whose exports cannot be kept under the per-file cap, publishes the feed and shards
without exports and records `exports.status: unavailable` with the reason.

## Failure and retention behavior

Each source records its attempt, result and **Last accepted input** independently.
That last date can describe a partially accepted response; it never establishes
exhaustive publisher history. The ledger distinguishes **OK**, **partial**,
**failed** and **not fetched**, and shows the latest available entry report.
Legacy observations without that report have unknown window coverage.

Open the source's ledger entry to inspect seen, processed, admitted, rejected,
topic-filtered and unprocessed counts, rejection reasons and report clock/hash.
At most 150 entries are processed under the recorded selection policy. Document
order is the default. F5 Labs ranks supported publisher dates first; unknown
dates follow, then future dates. Schema 4 publisher rows also separate configured
selection, the selection recorded for that response, and the last accepted
response-window selection. A missing, failed or legacy report leaves the accepted
window's basis unknown. See [selection provenance](FEEDS.md#f5-date-ranking-and-selection-provenance).
An unsafe/missing title or link, or
more than 100 unique CVE mentions, excludes the entire article; CVEs are not
clipped. Other safe articles can be admitted with a partial status. Counts
precede date filtering and retained-URL deduplication, so they need not equal
saved article totals. See [entry accounting](FEEDS.md#partial-intake-and-entry-accounting).

Whole fetch/XML failure clears the latest intake report and retains last-good
history. A parsed zero-admission failure may show its own current report while
the last accepted input remains older. A currently rejected URL can still have
an older saved version. Neither case makes that retained article fresh.

A mixture of failed, partial and successful sources can publish. If no fresh
feed or KEV input is accepted, collection fails before publication. A new file
does not make a failed source fresh. Missing data is never a zero-incident claim.

CI caches exactly two public-data files: the feed cache and CNA projections. The
key is tied to collector/source configuration and UTC day. GitHub caches are
immutable after creation, so that cache can lag later checks on the same day.

`--resume-public` additionally reads this hub's fixed deployed snapshot and
validates its schema, public articles and matching configured publisher identities
before using retained history. It also supplies previously published CNA
projections as another retained input; neither input is necessarily complete.
Newest successful CNA fact fields and the latest attempt/status are merged by
their separate timestamps. This requires a network read, and is not arbitrary
URL import. An unavailable or invalid bootstrap stops a `--resume-public` run
before publication rather than silently deploying from incomplete retained data.
Retry after accepted access recovers; an intentional local run without this flag
is a separate operator choice and can have less retained history.

CNA enrichment attempts up to **40 official records per collection** by default.
Scheduled and manually dispatched CI runs keep that limit. Push-triggered CI
runs pass a fixed **2,000-record bootstrap budget** with the quoted
`--enrich-limit` argument; this is an upper bound on eligible lookups, not proof
of complete guidance. The collection job has a **15-minute timeout**. It can fail
before publication without replacing the previous live site.
Never-fetched and older eligible records progress across checks when retained
inputs survive. Eligibility uses the retained attempt timestamp: 24 hours for a
successful record and one hour for a failed lookup. This is not a durable cooldown
ledger across runs: skipped publication and immutable caches can lose later
attempt clocks and cause repeated reads sooner. One run does not establish a
complete CNA archive, nor does a pending CNA record negate an existing CISA action.

Per-feed retention is bounded to **600 items**. Cache eviction/expiry, changed
configuration, unavailable bootstrap or never-collected stories can leave gaps.
Private receipts are never cached. This workflow does not increase cache quotas,
delete existing artifacts or provision larger paid runners.

## Run an intentional local collection

Use Python 3.10 or newer from the repository folder. No third-party Python
dependency is required.

```sh
python -m intelligence_hub
```

This makes real bounded public HTTPS reads, with a rolling ten-year UTC window,
and writes the generated public snapshot plus local public caches. For a fixed
window and no additional CNA lookups:

```sh
python -m intelligence_hub --start 2016-10-24 --end 2026-10-24 --enrich-limit 0
```

To include retained history and progress from the fixed deployed public snapshot:

```sh
python -m intelligence_hub --resume-public
```

To rebuild only from already retained local inputs, without network access:

```sh
python -m intelligence_hub --cached
```

`--cached` and `--resume-public` cannot be combined. None of these commands
publishes, posts to X, starts a server or changes a device. They do write generated
local output; keep it outside Git. A local collection is distinct from successful
workflow packaging, Pages deployment and browser review.

## Packaging, storage and deployment

Use **GitHub Actions** as the Pages publishing source. Only `main` in the intended
repository can run the collection job. It has `contents: read`; only the separate
deploy job receives `pages: write` and `id-token: write`. Checkout does not retain
credentials, official actions keep immutable commit pins, and no pull-request
trigger executes untrusted fork code.

The package must match `data/v7/index.json` exactly. Fixed files:

- `index.html`, `styles.css`, `app.js` and `icon.svg`
- `data/feed.json` and `data/briefs.json`, each with the bytes and sha256 the index lists
- `data/v7/index.json`

Data files: every path the index lists under `shards` and under `exports`, each
with its listed bytes and sha256, and nothing else. `python -m intelligence_hub.shards package site`
checks that every file matches an allowlisted pattern, that the set of files
equals the manifest set, and that each byte count and sha256 agree. Symlinks,
hard-linked files, other file types and unexpected directories are rejected.
The package holds at most **4,000 files**; every file under `data/v7/` (shards and
exports) is at most **4 MiB**, while `data/feed.json` and `data/briefs.json` keep
the collector's own byte bounds (8 MiB and 12 MiB). Actual file content must total
at most **192 MiB**. The check builds an in-memory tar and estimates compression
using both gzip and zlib at level 6. If the larger estimate exceeds **48,000,000
bytes**, it fails before artifact upload, and it prints every cap with its headroom
on every run. The previous live site remains in place. The package caps (192 MiB
input, 4,000 files, 4 MiB per v7 file, 48,000,000-byte estimate) were raised in pull
request #7; a further change needs the owner's approval in the pull request that
makes it.

Final JSON serialization groups CVE-map members by their recorded vendor/product
text, with the CVE identifier as a tie-breaker, to improve compression. This only
changes object-member order: record fields, values and array order are preserved.
It does not create new intelligence, refresh source dates or establish a new
semantic content revision by itself. Compression gains provide finite headroom;
they do not remove the unchanged package guard or guarantee space for future
growth. Actual package estimates still determine whether a publication proceeds.

This is an estimate, not a byte-for-byte reproduction of the upload action's
tar/ZIP metadata or proof of actual billed storage. The
[pinned official upload action](https://github.com/actions/upload-pages-artifact/blob/7b1f4a764d45c48632c6b24a0339c27f5614fb0b/action.yml)
creates the real artifact, retained for **one day**.

At the requested maximum of 12 scheduled publications/day (actual scheduled
runs are fewer), the estimate budget corresponds to
**36 MB (about 34 MiB)** for those artifacts. Manual/push runs, existing artifacts, other
repositories/Packages usage, actual compression and retention processing remain
separate. GitHub documents a **500 MB** Free-plan artifact allowance shared with
Packages; public standard-runner minutes being free does not remove storage limits.
No account billing, payment, spending limit or quota setting is changed, and no
zero-bill guarantee is made.
See [Actions billing and storage](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

GitHub's Pages ten-builds/hour soft limit
[does not apply to a custom Actions build/deploy workflow](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits).
Other Pages limits and possible rate limiting remain. This exception is not
unlimited capacity or an availability SLA.

If the package budget fails, inspect the fixed public output and retention needs
before proposing a smaller source selection or design. Do not automatically raise
quotas, delete artifacts, buy capacity or claim the failed update reached the site.

## Owner configuration and public/private boundary

The site is public and read-only for visitors. Adding a publisher requires an
owner-authorized change to `config/sources.json`, a canonical HTTPS feed and exact
article-host allowlists. Historical additions belong in `config/history.json`
with independently checked primary dates and references. Repository/Pages/workflow
changes require the owner's GitHub permissions; site access does not confer them.

The collector has no caller-provided URL endpoint, consumer-session scraping,
cookies or proxy relay. Raw feed markup is never browser content. Article text,
CVE records and references are untrusted data and are treated as such.

Only public source, source URLs and approved public curation belong in Git.
Credentials, local machine paths, research receipts and personal account records
remain outside Git and Pages.

The collector does not call Grok or xAI and does not read X timelines or
bookmarks. Report editions come from a separate desktop compiler, which names
its own tools in each edition. Future article sharing from the collector needs
owner review, supported access and settled eligibility/billing; automatic
posting is not enabled. API keys must never enter JavaScript.

Direct SEC filing intake is pending after HTTP 403. The SEC filter is not evidence
that filings have been connected, and reporting about a filing is not complete
Item 1.05/8.01 coverage. Accepted access and an operational contact policy remain
prerequisites; do not bypass a source's access refusal.

### Supplemental publisher context

The optional local `config/mitigation-context.json` catalog adds reviewed publisher
context to existing CVE detail steps and limitations. Its absence or an empty
catalog preserves the baseline. It does not add articles, sources or CVE records,
change CNA fields, CVSS, KEV data or guidance classifications, or establish device
exposure. Rejected records and identifiers absent from the current briefs receive
no appended note. The initial catalog concerns only the two original PHP CVEs;
its separately qualified follow-up text does not create a third CVE brief.

The exact version-1 object has `schema_version` and `entries`. Each unique uppercase
CVE entry has `cve`, `steps` and `limitations`; each step has only `title`,
`detail` and canonical public HTTPS `evidence_url`. Publisher publication/revision
dates are identified in the note, separately from snapshot and CNA retrieval
clocks. Quotes of publisher plans are not proof of a later shipped fix, registry
history or an installed vendor backport. Public curation needs source/privacy
review; visitors cannot configure it through the site.

The loader rejects duplicate JSON keys, extra fields, malformed types/IDs/links
and exceeded bounds before source requests: at most 64 KiB, 20 entries, six steps
and four limitations per entry. Each entry is limited to 4,000 Unicode codepoints
across **all** string values, including its ID and URLs. Title/detail/limitation
caps are 160/2,000/1,000 codepoints, with canonical ASCII URLs at most 4,000
characters. No invalid content is silently shortened or promoted.

Before appending, all matching briefs are copied and checked against the existing
100-step/100-limitation detail caps and JavaScript UTF-16 field limits. A later
failure leaves original briefs, CNA projections and cache evidence untouched.
Context changes participate in the existing content revision. Original intake,
retention and the 48,000,000-byte artifact/one-day storage guards remain unchanged;
an oversized publication stays blocked rather than widening those guards.

## Evidence and troubleshooting

| Observation | Interpret and act |
| --- | --- |
| Site time is old, Actions check succeeded unchanged | Expected when facts/layout did not change; read source dates and the workflow outcome separately. |
| No recent scheduled run | Check workflow enablement, default branch and GitHub status; schedule delay/inactivity are possible. |
| Public refresh evidence is unknown or retained | Check its attempt/read dates and fixed workflow history link; API refusal/rate limits do not establish collector failure. |
| A publisher failed | Inspect Last accepted input and any current report; retained content is historical and a failure is not no news. |
| A publisher is partial | Inspect rejected/unprocessed counts and reasons; safe admissions do not establish full coverage. |
| CNA pending or failed | Read any separately available CISA action and original references; do not invent missing fixes. |
| Package exceeds its budget | Update was blocked; review scope before changing limits. |
| SEC filter has no filings | Direct intake is pending, not a zero-incident finding. |
| A story looks old | Check its publication/event/catalog date and origin; legacy feeds and curation intentionally include history. |

Keep actual collection/deployment dates, counts and scoped scanner input evidence
privately. Distinguish source review, collection, packaging, deployment and browser
behavior. A static scan proves neither vulnerability-free software nor exhaustive
or accurate intelligence; a successful deployment does not prove every device
was exercised.

## Reporting desk and prior-source revisions

Schemas 5 and 6 carry reviewed local `reports/reporting.json`, `reports/catalog.json`
and `config/intelligence-context.json` projections, with whole-file digests.
A missing, unknown, malformed or oversized `config/intelligence-context.json`
refuses the candidate. The two `reports/` inputs are written by the owner's
separate desktop compiler, so they are tolerant: if either is missing, larger
than its bound (65,536 bytes for the catalog, 16,384 for the configuration) or
invalid, the run still publishes the feed, the report listing is marked
unavailable, and both a coverage note on the site and the `reports` field of
`.state/collection-result.json` name the reason. No remote resume metadata becomes local configuration. The public report files remain
GitHub-linked outside the six-file Pages artifact.

The reporting policy has daily slots at **06:00, 14:00 and 22:00 America/Chicago**,
covering the prior 24 elapsed hours on weekdays and 48 on weekends. It also
defines weekly, end-weekend, every-two-weeks, monthly, quarterly and latest-six-
completed-month editions. See the [reporting protocol](../reports/REPORTING.md)
for calendar boundaries, corrections and evidence coverage. Closed calendar
periods do not imply complete evidence. Future planned editions contain no
future facts. Legacy reports retain their actual date precision and are labeled
not reassessed, without invented midnight clocks.

The desk shows a next **scheduled** report/revision-review cycle only when the
recorded configuration says configured. It computes Chicago slots using the
platform time-zone database, including daylight-saving changes; planned,
paused or unavailable time-zone calculation is displayed explicitly. The
configuration's observation time is not live scheduler or delivery proof.
Browser polling and the separate feed schedule (requested every two hours,
run by GitHub when it can) remain distinct from reporting slots and source
freshness.

New intelligence-context URLs use the same conservative raw syntax in producer
and client: lowercase ASCII DNS hosts with an alphabetic final label and no
`xn--` label; slash/unreserved-character paths without dot segments or escapes;
and optional nonempty, unique unreserved `key=value` query pairs. Private/tracking
parameters refuse. Citation fragments are unreserved tokens; request identities
and report URLs forbid them. Unsupported syntax is refused without normalizing,
re-encoding or rerouting an approved source. Existing article URL rules remain.
The browser's polling is not an eligibility guarantee: visibility and manual
reloads can request earlier checks.

Revision-review records concern sources cited in precise report observations
within the prior 96 hours, prioritizing 48 hours, with at most twelve selected
sources. A `not_run` catalog means no qualified run is recorded. First baselines,
identical response bytes, unqualified byte changes, qualified timestamp changes
and material tracked-field changes are separate outcomes. Material or timestamp
comparisons require a real prior qualified scope and equal known extraction
profile versions; exposing a new CWE field on unchanged bytes is not a
publisher change. Refused, failed and uncompleted reads never become fact changes.

Each item's next eligible time is a cooldown boundary, separate from the global
cycle: successful checks wait at least eight hours, failed/uncertain attempts at
least 24; refusal deactivates the source pending separate review. The public
wire records outcomes and limits; this collector does not fetch article bodies
or execute the reporting/revision process. Missing or capped review work is
unknown, rather than an assertion that all earlier articles are unchanged.

The read-only knowledge catalog shows direct cited actor, campaign, product and
mitigation relationships plus taxonomy-only CWE/CAPEC mappings. CVE details add
CNA-provided weakness IDs, while existing CNA/KEV classifications and PHP notes
remain separate. No taxonomy path proves an attack or an actor's involvement.
No view scans, patches, modifies a trust store, runs models or assesses a device.

Schema 6 defaults to 1998-01-01 through the UTC run date and requires a start
on or after that floor plus a maximum 14,610-day difference. The fixed-floor
default reaches its technical review boundary on 2038-01-01; this is not a
coverage promise. Schema 5 retains 7,306 days and legacy 2/3/4 retain 3,661.
Producer/client/resume/archive and deployment must roll forward coherently;
older code must refuse 6 rather than strip or relabel its metadata. All other publisher, XML, entry, CVE, history, article, resume,
archive, package and retention guards remain unchanged. Full source acceptance,
necessary exact static analysis, production collection, packaging, deployment
and fixed HTTPS observation are separate gates; source code is not runtime proof.
