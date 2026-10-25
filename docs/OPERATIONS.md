# Intelligence Hub operator guide

## Read the desk

Open the public GitHub Pages address in a desktop or phone browser. Reading does
not require sign-in or a connection to the owner's home network. Actual rendering
and assistive-technology behavior still require owner review.

Use **Intelligence explorer** to search; all entered words must match. Filter by
Kind, Source, Exploitation or CVE guidance, then navigate calendar years/months or
a date preset. Presets use the snapshot window's end, not a promise that its data
is current to the device's clock. The decade boundary years and months can be
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

The configured inputs are **60 RSS/Atom publisher feeds**, CISA KEV and **63 curated
primary publications**. A configured feed is not necessarily healthy. Recent RSS,
bounded retained items and manual curation do not form a complete decade archive.
See [feed evidence](FEEDS.md) and [history coverage](SOURCES.md).

The count is feed definitions, not unique publishers. **Cisco Talos Threat Advisory
(category subset)** is a separate, narrower source with its own dates and outcomes.
It does not establish the original all-Talos source's outcome or supply a complete
archive; see its [dated intake scope](FEEDS.md#talos-threat-advisory-category-subset).

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

## Ten-minute checks and publication

GitHub Actions requests collection at minutes **2, 12, 22, 32, 42 and 52** of every UTC hour,
as well as on pushes to `main` and manual dispatch. Manual action:
repository **Actions → Refresh and publish Intelligence Hub → Run workflow**.

GitHub documents a five-minute minimum, default-branch execution, possible delays
or dropped jobs under load, and disabling after 60 days of public-repository
inactivity. The offset avoids the top of the hour but cannot guarantee timing.
See [schedule behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).
Check the [workflow history](https://github.com/TeamStarWolf/intelligence-hub/actions/workflows/publish.yml)
when the desk appears stale; an owner can re-enable a disabled workflow.

The browser reads this site's saved snapshot every ten minutes while visible,
and separately observes the fixed public GitHub workflow API as described below.
Refreshing the browser does not start publisher collection. Publisher
cadence, the workflow, collection duration, deployment and browser visibility all
affect arrival time. This is not continuous monitoring or a ten-minute delivery SLA.
The snapshot badge shows its age in minutes independently of the latest browser
read; reading the same saved file never claims a new publisher collection.

The collector records a typed Boolean `changed` decision. Article, guidance,
source-outcome, intake-count/reason and layout changes can trigger publication.
Publisher-feed response hashes and collection attempt clocks alone do not;
changes to retained CVE evidence,
including its response hash, can. Package/upload/deploy steps run only when
`changed` is true.

An unchanged successful check therefore keeps the prior deployed snapshot time.
The **Content as of** clock remains the saved snapshot's generation time. A browser
read or successful workflow result never replaces that date or the source dates.

### Read public refresh evidence

**Refresh evidence** distinguishes three observations: saved content time, returned
workflow run activity and the time this browser successfully read the public API.
The latest-run panel displays the most recently created of up to ten returned
`main`-branch runs for this repository's fixed publishing workflow. It labels
manual dispatch, push and automatic schedule separately, and shows pending,
successful and other completed outcomes without treating them as new content.
If the latest returned run is not successful, any separately displayed success is
limited to that same returned window. Later activity on older runs can fall outside
the window; the fixed **Workflow history** link is the place to inspect further.

A separate schedule-only query requests one run. **No scheduled run observed in
this API result** means exactly that; it does not establish that scheduling is
disabled. A schedule run can itself be queued, running or unsuccessful. Run start
and workflow update times are GitHub run fields, not the collector-step timestamp.
These endpoints do not establish whether publication was needed, whether every
publisher was admitted or whether new unadmitted news exists. They do not expose
job-level output or prove the last deployment.

The two fixed HTTPS reads omit credentials and referrers, reject redirects and
use no authenticated fallback. Each response is bounded to 512 KiB and both share
a 20-second deadline. They share the page's single in-flight load cycle and one
API-attempt cooldown of at least ten minutes during this loaded page session, run only while visible,
and are interrupted if the page becomes hidden. **Reload snapshot** does not
bypass the API cooldown. Eligibility uses a monotonic elapsed-time clock; displayed
wall-clock dates are observations, and the next eligible date is only an estimate.
Public GitHub requests can fail or hit the unauthenticated
60-request/hour allowance, including usage from other tabs or clients. No token
is requested or stored. Failed reads retain each endpoint's prior successful
observation and its original API-read date; without one, the status stays unknown.
Observations live only in page memory and are not a durable collection log. A full
browser reload resets this volatile observation and cooldown state; the in-page
**Reload snapshot** button does not bypass the cooldown.

The workflow API's read time is never presented as a successful collection time.
Use the Actions link for job-level evidence; do not relabel old source evidence
as freshly collected just because either public file or API was read.

## Failure and retention behavior

Each source records its attempt, result and **Last accepted input** independently.
That last date can describe a partially accepted response; it never establishes
exhaustive publisher history. The ledger distinguishes **OK**, **partial**,
**failed** and **not fetched**, and shows the latest available entry report.
Legacy observations without that report have unknown window coverage.

Open the source's ledger entry to inspect seen, processed, admitted, rejected,
topic-filtered and unprocessed counts, rejection reasons and report clock/hash.
Only the first 150 entries are processed. An unsafe/missing title or link, or
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

The package must contain exactly:

- `index.html`
- `styles.css`
- `app.js`
- `icon.svg`
- `data/feed.json`

Symlinks, hard-linked files, other file types and unexpected directories are
rejected. Actual file content must total at most **21 MiB**. The workflow builds
an in-memory tar from those five contents and estimates compression using both
gzip and zlib at level 6. If the larger estimate exceeds **1,200,000 bytes**, it
fails before artifact upload. The previous live site remains in place.

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

At 144 scheduled publications/day, the estimate budget corresponds to
**172.8 MB (about 165 MiB)** for those artifacts. Manual/push runs, existing artifacts, other
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
CVE records and references are untrusted data, not instructions for agents.

Only public source, source URLs and approved public curation belong in Git.
Credentials, local machine paths, research receipts and personal account records
remain outside Git and Pages. Clifford conversations, device/network inventory
and private imported collections are separate; this site does not publish them.

Grok and personal X feeds/bookmarks are not connected. Future article sharing
needs owner review, supported access and settled eligibility/billing; automatic
posting is not enabled. API keys must never enter JavaScript.

Direct SEC filing intake is pending after HTTP 403. The SEC filter is not evidence
that filings have been connected, and reporting about a filing is not complete
Item 1.05/8.01 coverage. Accepted access and an operational contact policy remain
prerequisites; do not bypass a source's access refusal.

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
