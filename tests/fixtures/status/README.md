# Service-health fixtures

`documents/` holds trimmed copies of real responses from the sources in `config/status.json`,
read on 4 November 2026 (the Microsoft documents on 12 November 2026). `make_fixtures.py` made them
from the untrimmed responses: it keeps each response's own shape and drops only rows and long text.

| Document | Source and endpoint |
| --- | --- |
| `statuspage/summary.json`, `statuspage/incidents.json` | Check Point, `status.checkpoint.com/api/v2/` (Statuspage API v2) |
| `google/incidents.json` | Google Cloud, `status.cloud.google.com/incidents.json` |
| `aws/currentevents.json` | AWS, `health.aws.amazon.com/public/currentevents` (UTF-16 with a byte-order mark, as served) |
| `azure/feed.xml` | Azure status RSS; the channel had no item on that date |
| `slack/current.json`, `slack/history.json` | Slack, `slack-status.com/api/v2.0.0/` |
| `heroku/current-status.json` | Heroku, `status.heroku.com/api/v4/current-status` |
| `salesforce/active.json` | Salesforce, `api.status.salesforce.com/v1/incidents/active` |
| `statusio/status.json` | GitLab, `status.gitlab.com/1.0/status/...` (status.io) |
| `azure-devops/health.json` | Azure DevOps, `status.dev.azure.com/_apis/status/health` |
| `microsoft/mac.json` | Microsoft 365, `status.cloud.microsoft/api/posts/mac` (one JSON post, here a service degradation) |
| `microsoft/ppac.json` | Power Platform, `status.cloud.microsoft/api/posts/ppac` (Available, the healthy shape) |
| `betterstack/index.json` | Chainguard, `status.chainguard.dev/index.json` |
| `zscaler/rss-feed.xml` | Zscaler, `trust.zscaler.com/rss-feed` (descriptions emptied) |
| `statuspage-rss/status.json`, `statuspage-rss/history.rss` | Oracle Cloud, `ocistatus.oraclecloud.com` |
| `ioda/events.json` | IODA, `api.ioda.inetintel.cc.gatech.edu/v2/outages/events` |

Two inputs are built inside `tests/test_status.py` rather than read, because no live example
existed on that date: an Azure feed item, in the feed's own RSS 2.0 shape, and a Cloudflare Radar
response, from the example in Cloudflare's API reference for `GET /radar/annotations/outages`.

`build_cache.py` runs the real normalizers over these documents with a fixed clock and writes
`tests/fixtures/status-cache.json`, which the pull-request check copies to `.state/` before its
offline build. Run it again after changing a document or a normalizer; `--check` fails when the
committed cache is out of date.
