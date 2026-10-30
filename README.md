# Team Star Wolf · Intelligence Hub

A public security intelligence desk with current headlines, primary research,
advisories, known exploited vulnerabilities, source-linked threat context and reports over time.

**Site:** <https://teamstarwolf.github.io/intelligence-hub/>

## What it does

- Collects **61 configured publisher RSS/Atom feeds**, plus CISA's separate KEV catalog. This counts feed definitions, not unique publishers. Configured sources can fail; their outcomes remain visible.
- Retains selected curated primary publications. The original 63-row historical collection is preserved; source-qualified additions and honest gaps are listed in the archive. This is selective coverage, not a complete incident archive.
- Provides year/month navigation, date presets, source/kind/exploitation/guidance filters, and ten date, title, source, CVE and CVSS sort choices.
- Provides a CVE register and source-led briefs with CISA required actions, available CNA product/version information, guidance excerpts and original references.
- Shows source health, partial article intake and dates separately from guidance availability. Missing enrichment remains unknown; a CVE mention does not prove exploitation or device exposure.
- Requests collection every **ten minutes** through GitHub Actions and publishes when articles, guidance, source outcomes or layout change. A visible browser checks the saved public snapshot every ten minutes, with the saved snapshot's age shown separately from browser reads.
- Runs on GitHub Pages independently of the owner's laptop, with a responsive interface and original SVG artwork.

The schema 6 collector defaults to **1 January 1998 through the UTC run date**.
This is selected historical context, not a complete archive: the earliest
qualified anchor is the 1 June 1998 MS98-001 bulletin, with explicit gaps. Schema 6
requires a start on or after 1998-01-01 and a bounded 14,610-day span; this is a
technical review horizon, not forty years of coverage. Schema 5 keeps its
7,306-day profile and legacy schema 2/3/4 keep 3,661 days. Threatpost is a **legacy archive with observed August 2022 items**; a
successful fetch does not make those stories current news.

The separately named [Talos Threat Advisory category subset](docs/FEEDS.md#talos-threat-advisory-category-subset)
adds a narrower publisher stream. It does not replace the original Talos feed,
erase its recorded failure or establish complete Talos coverage.

The [CISA Cybersecurity Advisories category subset](docs/FEEDS.md#cisa-cybersecurity-advisories-category-subset)
is also a separate input. It preserves the original all-advisories source and its
recorded failure; a category response does not establish complete CISA coverage.

RSS/Atom collection processes at most **150 entries** from each accepted bounded
response. Document order is the default. The F5 Labs feed instead ranks supported
publisher dates through the declared window end, then unknown dates, then future
dates; see [F5 selection](docs/FEEDS.md#f5-date-ranking-and-selection-provenance).
An invalid article link/title or more than **100 unique CVE mentions**
rejects that whole entry while other safe entries can be retained. The source
ledger reports admitted, rejected, filtered and unprocessed counts; **partial**
means some safe input was accepted with a gap. It does not mean the publisher's
archive is complete. See [intake accounting](docs/FEEDS.md#partial-intake-and-entry-accounting).

The [Qualys Security Blog](docs/FEEDS.md#qualys-security-blog-dated-partial-admission) adds vendor research
and product posts. Its admission uses the same whole-entry CVE rejection policy;
an accepted subset does not establish complete Qualys coverage or a healthy
future response. Source outcomes and publication dates remain visible.

Publication, update, incident and CISA catalog-addition dates are distinct.
Affected version ranges are not automatically fixed versions, and CVSS versions
are not normalized into an environment-specific risk score.

## Reports and connected threat context

The [reports archive](reports/README.md) keeps immutable narrative/data/chart
editions. Requested daily slots are **06:00,14:00,22:00 America/Chicago** with
24-hour weekday or48-hour weekend lookbacks. Weekly, weekend, fortnightly,
monthly, quarterly and rolling six-completed-month editions use the explicit
[calendar method](reports/REPORTING.md). The recorded activation state and
latest report/revision outcomes are separate from the next nominal opportunity.

Schemas 5 and 6 carry bounded source-led context for CWE weaknesses, CAPEC taxonomy,
actors/campaigns, products and mitigations. CVE-to-CWE comes only from the CNA's
structured problemTypes; official CWE-to-CAPEC links are taxonomy rather than
observed attacks. Curated attribution and mitigation relationships need their
own dated evidence. Missing or unreviewed fields stay unknown. No CVE is guessed
from an article headline, and a KEV catalog match does not rewrite an entry's
exploitation label.

The dedicated48–96-hour citation review records semantic, raw-hash-only,
timestamp, no-baseline, incompatible, refusal, failure and unchecked outcomes.
It is explicitly not_run until a separately recorded pass; ordinary feed refresh
is not a systematic prior-article review. Reports, source clocks, source health
and per-URL eligibility remain distinct. The browser executes no publisher or
model requests.

## Run the collector locally

Python 3.10 or newer; standard library only. From the repository folder:

```sh
python -m intelligence_hub
```

An explicit historical window:

```sh
python -m intelligence_hub --start 1998-01-01 --end 2026-10-26
```

These commands perform bounded public HTTPS reads and write the generated snapshot.
CI uses `--resume-public` to recover additional retained
history and CNA progress from this hub's **fixed, validated public snapshot**.
This is not an arbitrary URL import or access to a private account.

The default CNA enrichment budget is **40 official CVE record requests per run**.
Scheduled and manual CI checks keep that limit; push-triggered CI runs use a fixed
**2,000-request bootstrap budget** through `--enrich-limit`. The collection job
has a 15-minute timeout. Neither budget means every CVE has been enriched.
`--enrich-limit 0` disables those
additional lookups. `--cached` rebuilds from retained local public inputs without
network access and cannot be combined with `--resume-public`.

Local public-data caches and research receipts stay outside Git. See
[historical sources](docs/SOURCES.md), [feed intake](docs/FEEDS.md),
[CVE guidance](docs/MITIGATIONS.md) and the
[operator guide](docs/OPERATIONS.md) for evidence states, retention and commands.

## Guidance and connections

CVE briefs are deterministic projections of structured public inputs, without
model calls. CISA actions remain visible independently of a pending or failed
CNA lookup. If no solution or workaround is established, the hub says **Needs
review** and links the original material; it does not invent a patch or perform
one. Rejected CVE records require reconciliation before treating older claims as
an active vulnerability.

The public site is read-only. Owner changes to sources, curation, scheduling or
publication happen through the GitHub repository and its authorized configuration.
Visitors do not receive those permissions.

Grok and personal X timeline/bookmarks are **not connected**. Article sharing to X
is a future owner-reviewed integration, with no automatic posts. API eligibility,
billing and permitted data use remain separate prerequisites. Direct SEC filing
intake is **pending after HTTP 403**; related news coverage is not complete
Item 1.05/8.01 filing coverage.

No credentials, trackers, browser-side publisher collection or paid API fallback
are required. Never put account credentials or private social material into the
public site.

## Deployment and limits

The workflow runs on pushes to `main`, manual dispatch and a ten-minute schedule
offset from the hour. The latest checks are visible in
[Actions](https://github.com/TeamStarWolf/intelligence-hub/actions/workflows/publish.yml).
An unchanged check can succeed without a new Pages artifact or a newer displayed
snapshot timestamp. GitHub's minimum schedule interval is five minutes; delays,
dropped jobs and inactivity disabling still apply. This is not a delivery SLA.

Only five allowlisted public files enter Pages. A changed publication must fit
both **21 MiB of input** and a **3,000,000-byte level-6 compressed-size estimate**.
The artifact retains for one day. At 144 scheduled publications/day, that estimate
is at most **432 MB (about 412 MiB)** for those publications. This limits this
project's estimated footprint, not account-wide billing or actual artifact size;
push/manual runs and other account usage are separate. No billing setting or quota is
changed. [GitHub documents separate runner and storage allowances](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

Official GitHub actions retain immutable commit pins. Checkout has read-only
repository access without persisted credentials; only a separate deployment job
has Pages/OIDC write permission. Failed collection, invalid output or a package
budget failure blocks that publication and preserves the previous live site.
The collector rejects redirects, DTD/entities, oversized inputs and article links
outside each configured publisher allowlist.

Original implementation is MIT licensed. Publisher headlines, articles, trademarks
and linked material retain their respective owners' rights. Full article bodies
are not reproduced. This project is not affiliated with Nintendo or a news publisher.
