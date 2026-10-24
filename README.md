# Team Star Wolf · Intelligence Hub

A personal, public security intelligence desk: current headlines, primary research,
advisories, known exploited vulnerabilities and a sourced historical timeline.

**Site:** <https://teamstarwolf.github.io/intelligence-hub/>

## What it does

- Collects ten configured publisher feeds and CISA's KEV catalog without a paid API.
- Shows source health, retrieval times, coverage limits and original publisher links.
- Searches titles, summaries, CVEs and tags; filters by source, category and month.
- Keeps news, research, advisories, curated incidents and KEV records distinguishable.
- Offers a responsive, keyboard-accessible Star Wolf inspired interface with original SVG artwork.
- Runs on GitHub Pages independently of the owner's laptop. GitHub Actions requests hourly updates.

The initial historical selection covers **2025-10-24 through 2026-10-24**.
The automatically collected window rolls forward one calendar year from the UTC run date.
This is a growing collection, not an exhaustive record of every event or vulnerability.
RSS feeds generally expose recent posts; historical entries are explicitly curated.
KEV dates mean catalog addition, not initial disclosure. Feed items do not establish
that a reader's devices are affected.

## Run the collector locally

Python 3.10 or newer; standard library only. From the repository folder:

```sh
python -m intelligence_hub
```

An explicit historical window:

```sh
python -m intelligence_hub --start 2025-10-24 --end 2026-10-24
```

This performs actual bounded public HTTPS reads and writes `site/data/feed.json`.
The retained public-data cache lives in ignored `.state/public-cache.json`.
`--cached` rebuilds from retained inputs without network access. Generated output
and private research receipts stay outside Git. See [sources](docs/SOURCES.md) and
the [operator guide](docs/OPERATIONS.md).

## Connections

No credentials, model calls, trackers, browser-side publisher requests or paid
fallbacks are required. Grok and a personal X timeline/bookmarks are **not connected**.
Grok's public X Search API is distinct from access to a private account's feed;
API eligibility, billing and permitted data use must be settled before activation.
The public site must never contain account credentials or private social material.

## Deployment and security

The workflow collects on pushes to `main`, manual dispatch and at minute17 each hour.
Only five allowlisted public files enter the Pages artifact. Publication permissions
are isolated in the deployment job; source checkout does not retain credentials.
Official GitHub actions are pinned to commit IDs. The collector rejects redirects,
DTD/entities, oversized responses and off-publisher article links.

GitHub schedules can be delayed or disabled after prolonged repository inactivity.
The site shows its actual generated time and source failures; it is not a real-time
monitoring service or an availability guarantee. See [operations](docs/OPERATIONS.md).

Original implementation is MIT licensed. Publisher headlines, articles, trademarks
and linked material retain their respective owners' rights. Full article bodies
are not reproduced. This project is not affiliated with Nintendo or a news publisher.
