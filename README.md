# Team Star Wolf · Intelligence Hub

A public security intelligence desk with current headlines, primary research,
advisories, known exploited vulnerabilities and a sourced decade timeline.

**Site:** <https://teamstarwolf.github.io/intelligence-hub/>

## What it does

- Collects **60 configured publisher RSS/Atom feeds**, plus CISA's separate KEV catalog. This counts feed definitions, not unique publishers. Configured sources can fail; their outcomes remain visible.
- Retains **63 curated primary publications**, including 41 decade additions and the original 22 recent-year entries. This is selective coverage, not a complete incident archive.
- Provides year/month navigation, date presets, source/kind/exploitation/guidance filters, and ten date, title, source, CVE and CVSS sort choices.
- Provides a CVE register and source-led briefs with CISA required actions, available CNA product/version information, guidance excerpts and original references.
- Shows source health, partial article intake and dates separately from guidance availability. Missing enrichment remains unknown; a CVE mention does not prove exploitation or device exposure.
- Requests collection every **ten minutes** through GitHub Actions and publishes when articles, guidance, source outcomes or layout change. A visible browser checks the saved public snapshot every ten minutes, with the saved snapshot's age shown separately from browser reads.
- Runs on GitHub Pages independently of the owner's laptop, with a responsive interface and original SVG artwork.

The curated history covers **2016-10-24 through 2026-10-24**. The collector's default
window rolls forward ten calendar years from the UTC run date. There are gaps in
every year; selected history and recent RSS cannot reconstruct every publisher's
archive. Threatpost is a **legacy archive with observed August 2022 items**; a
successful fetch does not make those stories current news.

The separately named [Talos Threat Advisory category subset](docs/FEEDS.md#talos-threat-advisory-category-subset)
adds a narrower publisher stream. It does not replace the original Talos feed,
erase its recorded failure or establish complete Talos coverage.

RSS/Atom collection examines the first **150 entries** of each accepted bounded
response. An invalid article link/title or more than **100 unique CVE mentions**
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

## Run the collector locally

Python 3.10 or newer; standard library only. From the repository folder:

```sh
python -m intelligence_hub
```

An explicit historical window:

```sh
python -m intelligence_hub --start 2016-10-24 --end 2026-10-24
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
both **21 MiB of input** and a **1,200,000-byte level-6 compressed-size estimate**.
The artifact retains for one day. At 144 scheduled publications/day, that estimate
is at most **172.8 MB (about 165 MiB)** for those publications. This limits this
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
