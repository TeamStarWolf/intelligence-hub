# Intelligence Hub operator guide

## Daily use

Open the GitHub Pages address in a desktop or phone browser. Search for a product,
CVE or topic, select sources/categories/months and open the original publisher.
Read the source panel and generated timestamp before treating an item as current.
No sign-in or connection to the owner's home network is needed for this public site.
Device rendering and assistive-technology behavior require actual owner review.

## Refreshes and failures

The hourly GitHub Actions workflow requests new public data; a publisher's feed
update frequency and GitHub scheduling determine arrival time. Manual refresh:
repository **Actions → Refresh and publish Intelligence Hub → Run workflow**.
A browser refresh reads the deployed snapshot; it does not run publisher collection.

Each source has an independent attempt/result/last-success record. Partial failure
can publish alongside the retained last-good source data when available. If all
fresh reads fail, the workflow fails before publication and the prior deployed site
remains. If a source never succeeded, its failed status does not become a zero-news
claim. A newly generated file does not make failed sources fresh.

Local runs retain the latest cache. CI restores a public-data cache keyed once per
UTC day and collector/source configuration. That daily cache can lag later successful
runs on the same day. Cache expiry, eviction or a changed collector can remove this
fallback; the site must show the resulting coverage gap. No private files are cached.
The cache is bounded by input/output and per-source limits; the workflow does not
raise GitHub cache quotas or use larger paid runners. Pages artifacts retain for one day.

GitHub's scheduled workflows can be delayed, dropped under load or disabled in a
public repository after60days without activity. Check the Actions run history when
the timestamp is stale. Re-enable the workflow if GitHub disabled it; do not claim
the scheduler guarantees continuous monitoring.

## Source policy

Edit `config/sources.json` only after checking a publisher's official site and feed.
Use canonical HTTPS URLs and exact publisher article-host allowlists. The network
collector has no user-supplied URL endpoint, redirects, session cookies or proxy relay.
Raw feed markup is never browser content. RSS contributes attributed headline links;
curated summaries are brief original descriptions with primary references.

For historical entries, add independently sourced records to `config/history.json`.
Preserve publication and event dates separately; `date_basis` selects the chronology.
Unknown dates remain unknown. Record corrections in place with a supporting source;
do not inflate history totals with repeated headlines about the same source URL.

## Public/private boundary

The repository contains source, source URLs and sanitized public historical curation.
The Pages artifact contains only the site and generated public feed. `.state/`,
credentials, local paths, research receipts and personal account records never belong
in Git or Pages. Source content is untrusted data and cannot authorize an agent action.

Grok/X, device inventory, network topology, Clifford conversations and private imported
collections are separate integrations. None are enabled by this feed. Never put API
keys into JavaScript or turn a consumer browser session into an unofficial API relay.

## Deployment mechanics

Use GitHub Pages with **GitHub Actions** as its publishing source. The workflow runs
on the default `main` branch. The build job has `contents: read`; only the separate
deploy job receives `pages: write` and `id-token: write`. No pull-request-triggered
workflow executes untrusted fork code. Actions use immutable official commit pins.

GitHub documents [Pages availability](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages),
[workflow deployment](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages),
[Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions) and
[schedule limitations](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).
Free standard-runner minutes do not imply unlimited artifact storage; keep the one-day
retention and bounded artifact size. No billing setting is changed by this project.

## Evidence and limits

Record actual collection/deployment times, counts and scoped scanner inputs privately.
Distinguish source review, successful collection, successful deployment and browser
behavior. A successful static scan does not prove vulnerability-free software or
accurate/exhaustive intelligence. A successful Pages deployment does not prove every
phone or browser was exercised.
