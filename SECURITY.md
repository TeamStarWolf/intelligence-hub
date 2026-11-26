# Security Policy

This repository builds the TeamStarWolf Intelligence Hub: a Python collector under `intelligence_hub/` that reads public security advisories and reporting, the static site under `site/` that displays them, and the GitHub Actions workflows that publish them. It runs no service and has no user accounts; your browser reads static files and contacts no one. What can go wrong here is a wrong summary, tag or CVE fact, a broken link or one that now leads somewhere it should not, a published file that carries something it should not, or a fault in the collector, the site code or a workflow.

## What to report, and how

| You found | Report it through |
|---|---|
| A wrong summary, tag, CVE fact, date or guidance label | A [public issue](https://github.com/TeamStarWolf/intelligence-hub/issues) or a pull request |
| A broken link, or a link that now leads somewhere it should not, such as a lapsed domain or a page replaced by something unrelated | A [public issue](https://github.com/TeamStarWolf/intelligence-hub/issues). Say so in the title if the destination looks harmful |
| A vulnerability in the collector (`intelligence_hub/`), the site code (`site/js/`), a validator, or a workflow (`.github/workflows/`), or anything else you would rather not disclose in public | The contact published in [teamstarwolf.com/.well-known/security.txt](https://teamstarwolf.com/.well-known/security.txt) |

Please do not open a public issue for anything sensitive. In a private report, say which file, route or address it concerns, what you found and how to reproduce it.

## Scope

- In scope: the collector under `intelligence_hub/`, the site under `site/` (including `site/js/`), the validators and tests under `tests/`, the workflows under `.github/workflows/`, and the data and Atom feeds published under `site/data/`.
- Out of scope: the publishers, advisories and catalogs the Hub reads and links to, such as vendor feeds, CISA, FIRST and the CVE Program. They belong to their operators, and the content a headline links to is the publisher's, not this project's; report a problem with one of them to its owner.

## Response

This is a volunteer, community-maintained project with no formal SLA. Reports are reviewed on a best-effort basis.
