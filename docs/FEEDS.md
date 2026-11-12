# Publisher feeds and bookmark intake

## Schema 7: a separate briefs file, byte bounds and date zones

The collector writes schema 7. Each run turns one validated snapshot into two
public data files:

- `data/feed.json` holds the articles, the source ledger, the curated context and
  `brief_index`: one compact row per linked CVE with the fields that list views,
  filters and counts use (`record_state`, `source_status`, `guidance_status`,
  `required_action`, `cvss_score`, `cvss_version`, `kev_date_added` and
  `weaknesses`).
- `data/briefs.json` holds the full CVE briefs. Its `generated_at` and
  `content_revision` match the feed it belongs to. CNA titles and
  vendor and product names live only here, so the site reads it the first time
  a reader opens a brief, opens the CVE register or searches; search results
  gain those names once it has loaded, and an open register reads the new file
  when a later snapshot arrives. The site refuses a briefs file from a
  different run.

The owner's separate desktop compiler read schema 6 feeds, which carried the
briefs inline. From schema 7 it must read `data/briefs.json` as well, matched to
the feed on `generated_at` and `content_revision`, or its report editions lose
their CVE brief rows.

There is no longer an 8,000-article abort. Each file has a byte bound instead:
**8 MiB** for `data/feed.json` and **24 MiB** for `data/briefs.json`. Two count
ceilings sit beside them. The feed holds at most **27,962 article rows**, a number
derived from its byte bound (8,388,608 bytes / 300 bytes per row). The smallest
live row is 363 bytes and the average is about 480, so at real sizes the byte
bound is reached first. The briefs file holds at most **15,000 CVE briefs**. Every
run prints each file's size, its byte headroom and a gzip estimate, then the row
count and row headroom for both ceilings. A run that would cross a bound or a
ceiling fails with a message that names it, and the deployed publication stays.
No row is evicted to make room, because the deployed files are the only durable
store of live rows, and KEV and curated rows are never trimmed. The site and the
archive validator check the same bounds and ceilings.

These bounds are the next wall, not a permanent one. A bounded run on
3 November 2026 wrote 9,019,252 briefs bytes (2,385 briefs, about 3,780 bytes
each). The deployed file was 10,795,310 bytes on 11 November 2026 after a week
at about 173 KB a day (the CVE count went from 2,435 to 2,793), which would have
crossed the former 12 MiB bound around 22 November. The owner approved raising
the briefs bound to 24 MiB on 11 November 2026 (WP-00 of the revision plan) as
the interim step; the structural fix is to publish the CVE brief buckets and
retire schema 6 once the owner's desktop compiler reads them. The publish input
cap is 192 MiB (the whole package was 90,858,121 bytes on 11 November 2026), so
the briefs bound still binds first. A run that crosses it fails and the site
keeps its last publication; every run prints the bound's headroom.

Publisher responses keep the **3 MiB** default bound. A source can set its own
`max_bytes` in `config/sources.json`, up to a **16 MiB** fetch ceiling. The CISA
all-advisories feed (5,897,554 bytes on 3 November 2026) and the CISA ICS
advisories feed (6,176,856 bytes) carry 8 MiB. Reads use `read1`, so the
30-second deadline is checked between short reads. A truncated chunked body or a
body shorter than its declared length is a failed read for that source, not an
aborted run. Each failure records its cause in the ledger and the run log, and a
failed resume of the deployed snapshot names its reason.

CET and CEST zone names, which CERT-EU uses, convert to UTC. A stamp with no zone
at all (Cisco PSIRT writes `2026-11-02 21:16:10.0`) is read as UTC, and the row's
date basis says so: `publication, zone not stated, read as UTC`. Rows retained
from earlier runs keep the dates they were stored with, so a row stored undated
before this change stays undated.

The collector and the site still read a schema 6 feed, which carries its briefs
inline under `mitigations`, so the first run after the change resumes from the
deployed schema 6 snapshot.

## Schema 6 since 1998 window and unchanged source intake

Schema 6 was the producer format before schema 7; its publisher ledgers and partial-intake
contract retain schema 4's exact selection/configuration/hash/time/count
semantics. Other sources still use document order and F5 alone uses the reviewed
bounded date ranking below. Rejected, filtered and duplicate entries consume
the same 150 processed slots, without refill. The older dated schema 3/4 intake
observations in this document remain historical observations, not new captures.

Schema 5 introduced the bounded, local source-attributed intelligence/reporting metadata
and CNA-only CWE projections. These do not fetch linked source bodies, manufacture
article/CVE admission or adopt remote catalog configuration. An article without
an admitted CVE remains without a linked brief; matching a CVE in CISA KEV remains
separate from the article's own exploitation label. See
[CWE and context semantics](MITIGATIONS.md#cwe-capec-and-source-attributed-context)
and the [reporting desk](OPERATIONS.md#reporting-desk-and-prior-source-revisions).

Schema 6 retains the exact schema 5 modern fields, requires a window starting
on or after 1998-01-01 and limits the date difference to 14,610 days. Its default
is fixed since 1998; the limit is a technical review horizon, not full coverage.
Schema 5 keeps 7,306 days and older readers keep their 3,661-day profile. The existing 3 MiB publisher response, strict UTF-8, DTD/entity rejection,
40,000-node/depth-48 XML, 100-CVE whole-entry rejection, 150 normalization,
600 retained articles per source, 500 curation entries, 8,000 total articles,
16 MiB resume (24 MiB for the deployed briefs file), compressed package estimate (now 48,000,000 bytes) and one-day artifact-retention guards applied
to schema 6. Schema 7 replaces the 8,000-article limit with the per-file byte bounds above and the 27,962-row ceiling derived from the feed bound.
Neither the broader window nor a source's accepted input proves complete history
or timely reporting. Known modern schema 5/6 fields on legacy labels are refused;
there is no metadata stripping or silent downconversion.

## How often feeds are read

The publish workflow asks GitHub for a run every two hours (`7 */2 * * *`), but
GitHub does not guarantee scheduled runs: between 30 October and 3 November 2026
the gaps were about 3 to 10 hours. `data/v7/index.json` records the last 20
published runs and the observed median and longest gap. Each run reads every configured feed once, so a
new publisher item can take several hours to reach the site. Pushes to `main`
and manual runs add extra collections.

## Service-health feeds

Vendor status pages, cloud health feeds and internet outage signals are a separate input with
their own registry, [config/status.json](../config/status.json), described source by source in
[SOURCES.md](SOURCES.md#service-health-sources). They are read once per run through the same
bounded fetch as publisher feeds: canonical HTTPS only, no redirects, identity encoding, a
12-second connection timeout, a 30-second read deadline and the 3 MiB default byte bound. A
failed read keeps that source's last good snapshot with its own fetch time and records the
failure. Statuspage incident lists return only the 50 most recent incidents, so the published
month files are the only copy of older incidents. Every status file the previous publication
lists is read and checked first (each one gets a second read); if one still cannot be read, the
run stops before writing anything and the deployed publication stays, so a read failure never
removes or shrinks a month. A failure later in the step, such as a broken registry, publishes
the previous status files again byte for byte and never blocks the feed. These sources are not
counted among the publisher feeds below.

## What is configured

The catalog contains **62 publisher RSS/Atom sources**, counting feed definitions rather than unique publishers. The first 29 comprise ten retained sources, sixteen additions from the repository owner's public [cybersecurity-resources bookmarks](https://github.com/TeamStarWolf/cybersecurity-resources/blob/f95fb4a3fae14acfa172c22507a1554339cb3655/LINKS.md), and three further requested publishers: watchTowr Labs, Dark Reading and the legacy Threatpost archive. A further 30 advisory, research and reporting feeds (including the CISA ICS advisories feed added with schema 7), one separately scoped Talos category feed, the Qualys Security Blog and a separately scoped CISA category feed are listed below. The fixed configuration is [sources.json](../config/sources.json). CISA KEV is a separate JSON catalog and is not included in this RSS count. Curated historical publications are also a separate input. SEC filings are not connected by this feed intake.

Configured does not mean every source is currently healthy. The site records each collection attempt and last accepted input. The retained CISA advisory feed failed the initial production intake. Since schema 7 it is read under its own 8 MiB bound, and a run reports it as partial when it rejects entries that break the 100-CVE whole-entry rule. No replacement CISA advisory URL was established by this expansion. A failed source is not evidence that its publisher has no new advisories.

The nineteen additions returned direct HTTPS 200 responses with bounded, parseable RSS/Atom and usable HTTPS article links during intake on **24 October 2026**. Threatpost's returned publication dates stop in August 2022: its live transport does not make its reporting current. These are dated transport and structure observations, not promises of continued availability, complete archives, publisher authenticity beyond the observed HTTPS endpoint, factual correctness or permission to reproduce full articles. Scheduled collection and browser behavior are separate evidence.

## Retained sources

| Publisher | Feed | Source role |
| --- | --- | --- |
| [CISA](https://www.cisa.gov/cybersecurity-advisories) | [RSS](https://www.cisa.gov/cybersecurity-advisories/all.xml) | Government advisories; read under its own 8 MiB bound since schema 7 |
| [CISA ICS advisories](https://www.cisa.gov/news-events/ics-advisories) | [RSS](https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml) | Government industrial control system advisories; added with schema 7 under an 8 MiB bound |
| [CERT-EU](https://cert.europa.eu/publications/security-advisories/) | [RSS](https://cert.europa.eu/publications/security-advisories-rss) | Government/CERT advisories |
| [Microsoft Security](https://www.microsoft.com/en-us/security/blog/) | [RSS](https://www.microsoft.com/en-us/security/blog/feed/) | Vendor research |
| [Google Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence) | [RSS](https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v) | Vendor research; publisher-linked FeedBurner endpoint |
| [Cisco Talos](https://blog.talosintelligence.com/) | [RSS](https://blog.talosintelligence.com/rss/) | Vendor research |
| [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/) | [RSS](https://unit42.paloaltonetworks.com/feed/) | Vendor research |
| [BleepingComputer](https://www.bleepingcomputer.com/) | [RSS](https://www.bleepingcomputer.com/feed/) | Independent reporting |
| [SecurityWeek](https://www.securityweek.com/) | [RSS](https://www.securityweek.com/feed/) | Reporting |
| [Krebs on Security](https://krebsonsecurity.com/) | [RSS](https://krebsonsecurity.com/feed/) | Independent reporting |
| [The Record](https://therecord.media/) | [RSS](https://therecord.media/feed) | Reporting |

## Verified additions

| Publisher | Feed | Source role and intake qualification |
| --- | --- | --- |
| [SANS Internet Storm Center](https://isc.sans.edu/xml.html) | [RSS](https://isc.sans.edu/rssfeed.xml) | Handler diaries and observations; publisher's title-only feed |
| [Ubuntu](https://ubuntu.com/security/notices) | [RSS](https://ubuntu.com/security/notices/rss.xml) | Distribution security notices |
| [CERT/CC](https://www.kb.cert.org/vuls/) | [Atom](https://www.kb.cert.org/vuls/atomfeed/) | Coordinated vulnerability notes; article host is `kb.cert.org` |
| [UK NCSC](https://www.ncsc.gov.uk/information/rss-feeds) | [RSS](https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml) | Broad government guidance, research and announcements; not only vulnerability alerts |
| [Canadian Cyber Centre](https://www.cyber.gc.ca/en) | [Atom](https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en) | Alerts/advisories; legacy official RSS route advertised this canonical endpoint |
| [Debian](https://www.debian.org/security/) | [RSS](https://www.debian.org/security/dsa-long) | Distribution advisories; article host is `lists.debian.org` |
| [AWS](https://aws.amazon.com/security/security-bulletins/) | [RSS](https://aws.amazon.com/security/security-bulletins/rss/feed/) | Vendor security bulletins |
| [ESET WeLiveSecurity](https://www.welivesecurity.com/en/) | [RSS](https://www.welivesecurity.com/en/rss/feed/) | Vendor research and security analysis |
| [Check Point Research](https://research.checkpoint.com/) | [RSS](https://research.checkpoint.com/feed/) | Vendor research; direct publisher RSS endpoint |
| [Volexity](https://www.volexity.com/blog/) | [RSS](https://www.volexity.com/feed/) | Vendor research; root feed works, blog-specific feed redirected to HTML |
| [The DFIR Report](https://thedfirreport.com/) | [RSS](https://thedfirreport.com/feed/) | Published intrusion analysis; paid products are not connected |
| [Kaspersky Securelist](https://securelist.com/) | [RSS](https://securelist.com/feed/) | Vendor research |
| [Sekoia](https://www.sekoia.com/blog) | [RSS](https://www.sekoia.com/blog/rss.xml) | Vendor research; canonical destination inspected separately after legacy redirect |
| [The Hacker News](https://thehackernews.com/) | [RSS](https://feeds.feedburner.com/TheHackersNews) | Reporting; FeedBurner URL linked by the publisher |
| [Help Net Security](https://www.helpnetsecurity.com/) | [RSS](https://www.helpnetsecurity.com/feed/) | Reporting, including vendor/product announcements |
| [Schneier on Security](https://www.schneier.com/) | [Atom](https://www.schneier.com/feed/atom/) | Commentary and reporting, including broader policy and occasional non-security posts |
| [watchTowr Labs](https://labs.watchtowr.com/) | [RSS](https://labs.watchtowr.com/rss/) | Vendor vulnerability and exploitation research; added from the owner's further request |
| [Dark Reading](https://www.darkreading.com/) | [RSS](https://www.darkreading.com/rss.xml) | Reporting; publisher's home page advertises this feed |
| [Threatpost](https://threatpost.com/) | [RSS](https://threatpost.com/feed/) | Legacy archive; ten returned items are dated 18–31 August 2022, inside the collector's window from 1 January 1998 |

Publisher role describes the source, not independent corroboration of every item. Research can contain demonstrations or hypotheses; reporting can repeat another publisher's claims. A source entry does not establish exploitation, urgency, a required patch or exposure of the reader's devices.

## Admission and collection boundaries

Discovery used official publisher pages, advertised feed links or direct publisher-hosted RSS/Atom endpoints. Redirects were recorded and never followed automatically. Canadian and Sekoia canonical destinations were inspected as new fixed requests. Intake used no proxies, cookies, credentials, API keys, trial accounts or paid services. Official discovery/explanation pages, including Microsoft's feed notice, were read; destination articles linked from feed entries were not crawled.

Each addition has a retained private receipt with the exact URL, retrieval interval, response size, SHA-256 of received bytes, XML structure count and observed article hosts. The byte hash identifies the response received; it is not a signed publisher attestation or an underlying article-content hash. Research receipts remain outside Git.

Admission used a 3 MiB uncompressed response cap, strict UTF-8 and pre-parse NUL/DOCTYPE/ENTITY rejection, with post-parse node/depth bounds. The post-parse checks do not establish a parser memory/CPU bound. Socket/read deadlines are best effort. No adversarial parser test or full source-security audit is claimed by admission. The production collector has its own validation and can reject a feed that changes later.

Exact article-host allowlists are recorded per source. Publisher feed and article hosts can differ, as with CERT/CC and Debian. No wildcard or arbitrary-source endpoint is enabled. No feed text or publisher markup becomes executable page content. The hub publishes headlines, dates and links, with separately curated short summaries where available; it does not republish full RSS article bodies. RSS retention and future failures remain limits on historical coverage.

### Partial intake and entry accounting

New snapshots use schema 7. The site reads validated schemas 2 to 7; the
collector can resume validated schemas 1 through 7. Legacy observations without
an intake report have **unknown entry-window coverage**. A legacy report without
selection metadata has an **unrecorded selection basis**, even if its status was
successful or it is retained inside a schema 4/5/6 snapshot. CISA KEV is a separate
catalog and does not carry RSS entry accounting or selection policy.

After the whole response passes transport and XML validation, the collector
counts its RSS items or Atom entries and selects at most **150** entry elements
under the recorded policy. Document order is the default; only the existing F5
Labs feed explicitly opts into publisher-date ranking, described below. This is
a normalization budget, including rejected, filtered and duplicate entries, not
a target of 150 accepted articles. There is no refill after a rejection, filter
or duplicate. The ledger distinguishes:

| Count | Meaning |
| --- | --- |
| Seen | All entry elements in the accepted bounded XML tree. |
| Processed | Up to 150 entry elements selected under the recorded policy, or all if fewer. |
| Admitted | Entries accepted by the parser before retained-URL deduplication and date-window filtering. |
| Rejected | Whole entries excluded for an invalid/missing title or allowed HTTPS link, or more than 100 unique CVE mentions. |
| Filtered | Entries excluded by a configured topic filter, not validation failures. |
| Unprocessed | Entries outside that selection window; these may include recent items. |

Processed equals admitted plus rejected plus filtered; seen equals processed plus
unprocessed. Rejection reasons are counted without persisting rejected bodies or
titles. CVEs are counted from the full extracted title and content fields before
display-title shortening. A rejected article's CVE list is never clipped to fit.
This does not identify CVEs in linked articles that the feed did not include.

**OK** means no entries were rejected or left unprocessed in that response, not
complete publisher history. **Partial** requires at least one admitted entry and
at least one rejected or unprocessed entry. Safe admissions merge with retained
history under the existing 600-item source bound. **Failed** retains last-good
history when the whole response is rejected or no safe admission is possible.
Only a fully processed, rejection-free configured topic filter may normally
admit zero entries without failing. A zero-admission partial window fails.

The report belongs to the latest attempt and carries that response's hash. A
whole fetch/XML failure clears the latest report rather than presenting old
counts as current. A parsed zero-admission failure can retain its own report
and hash while the source's last accepted input and digest remain historical.
A rejected current article can coexist with its older retained version; the
counts describe the latest response window, not the archive's saved-row count.

The 3 MiB response, read deadline, UTF-8/DTD/entity, 40,000-node/48-depth and
100-CVE-per-entry gates remain in force. Whole-response rejection is never a
permission to parse a prefix, raise a bound or bypass publisher access refusal.
Neither successful nor partial intake guarantees factual accuracy or completeness.

### F5 date ranking and selection provenance

The existing `f5-labs` definition uses `publisher-date-desc-v1` through the
optional `entry_selection` setting. Other feeds retain `document-order-v1`.
Before normalizing the selected articles, F5 ranking inspects only the first
direct date-field occurrences, using `pubDate`, `published`, `date`, then
`updated`. An empty leaf can fall through; a chosen whitespace-only, nested,
over-128-character, naive or invalid date ranks as unknown without trying a
lower-priority field. This bounded rank probe does not inspect every entry's
title, link, body or CVEs. Normal validation still applies to the selected entries,
and an unknown-ranked item may later receive a display date from that parser.

Supported dates normalize to UTC where a timezone is supplied. Valid dates whose
UTC/calendar day is at or before the declared collection window's end rank
newest first. Ties keep document order. Unknown dates follow, then future dates;
each of those groups keeps document order. Date-only values use a midnight
boundary solely for ordering, without asserting an actual publication time.
The cutoff has calendar-day precision: later hours on the same date are not
classified as future. A historical window deliberately supplies its historical
end date. No retrieval, HTTP or current clock becomes a publication date.
Publisher dates remain claims, so this is not a guarantee of the latest 150 valid
articles or complete coverage.

Schema 4 separates **configured selection**, **recorded response selection** and
**last accepted response-window selection**. The typed response metadata records
its policy version, basis and declared cutoff; an older recorded cutoff need not
equal the currently viewed window. An accepted-window label requires an accepted
status and matching response/last-good hash under the normal time/count checks.
Failed, missing or legacy reports cannot establish that historical basis. Saved
rows may mix policies; configuration alone does not prove an attempt succeeded.
Whole-response failures still clear the latest report while preserving last-good
history. A parsed zero-admission failure's report belongs to that failed attempt,
alongside any retained last-good history.

On public resume, remote configured-policy metadata is validated but does not set
local policy: future behavior comes from the local catalog. The full recorded
intake, selection, attempt and hash are preserved. This intentional local-policy
projection does not strip or downconvert intake evidence or backfill legacy
selection metadata.

The catalog, collector, schema 4/5 producer and compatible readers require a
coordinated release and rollback. Older collectors can ignore the new catalog
option and retain document order; older site readers can reject schema 4. Do not
silently strip selection fields, relabel new data as legacy or mix incompatible
versions. Existing safeguards remain: 150 normalizations, 100 CVEs per entry,
600 retained articles per source, the schema 7 per-file byte bounds, 16 MiB public-resume input (24 MiB for the deployed briefs file),
the 48,000,000-byte compressed artifact estimate guard and one-day artifact
retention, alongside the whole-response/XML bounds above.

### Response byte-limit failures

The fixed reason `response_byte_limit_exceeded` identifies an attempt that
crossed its configured response-byte bound before a complete input was accepted.
The default publisher-feed and KEV response cap is **3 MiB**; a source's own
`max_bytes` can raise it up to 16 MiB. A failed read does not
establish the full response size, a complete-body hash, valid XML or admitted
entries. The collector does not parse or admit a truncated prefix.

The source remains **Failed**, with no entry-intake report for that attempt.
Retained articles, the last accepted input hash and its success date remain
historical; the new attempt date and failure reason do not make them current.
This diagnostic also applies to KEV reads that exceed their bound. HTTP failures
and other intake failures keep their existing separate reporting.

Older generic policy errors do not establish a byte-limit cause. The explicit
reason describes only the attempt that records it; it does not repair intake,
increase any limit or imply complete publisher coverage.

## Patch Tuesday sources

The Patch Tuesday briefs read three vendor sources besides the feeds above. They live in the
`patch_tuesday` block of [sources.json](../config/sources.json), not in the RSS list, and the
collector checks each URL's host and byte bound before it reads anything
(`intelligence_hub/patch_tuesday.py`).

| Source | Read | Bound | What is taken |
| --- | --- | --- | --- |
| [MSRC CVRF API](https://api.msrc.microsoft.com/cvrf/v3.0/updates) updates list | every run | 1 MiB | Each monthly release's id (`2026-Oct`), title, initial release date and current release date. Mariner Release Notes are skipped. |
| MSRC CVRF release document, `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<id>` | when a month is new or its current release date changed | no byte bound | Per CVE: Microsoft's title, severity and impact (for the Microsoft products, or the highest across the CVE's package products when MSRC rates only those, matching MSRC's Max Severity), CVSS base score and vector, product families, component tag, issuing CNA, the Exploited and Publicly Disclosed flags, the exploitability index, CWE ids and revision dates. Descriptions, FAQs, acknowledgments and remediation tables are not read. |
| [Adobe Security Bulletins and Advisories](https://helpx.adobe.com/security.html) | every run | 2 MiB | Each APSB bulletin's id, title, product sections, link and posted dates. |
| [SAP Security Patch Day](https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html) and its month and year pages | for months rebuilt this run and months with no SAP rows yet, at most 16 pages a run | 1 MiB each | Each Security Note's number, title, CVE ids, priority, CVSS score and link. |

The MSRC release documents carry the Azure Linux and CBL-Mariner package CVEs that Microsoft
ships, which makes recent months large: the October 2026 document was 30,083,214 bytes when
read on 3 November 2026. That one document type has no byte bound: the owner directed on
11 November 2026 that there is no document ceiling, so `fetch()` reads it as `UNBOUNDED` in
`intelligence_hub/collect.py` under the 30-second read deadline alone, and the `patch_tuesday.msrc`
block of the registry carries no `document_max_bytes`. Every other read keeps the 16 MiB
`FETCH_CEILING`. Adobe's index answers an automated read only when it sends `Accept: text/html`
and `Accept-Language: en-US`, so those two reads send both. Every read keeps the collector's
user agent, the 30-second deadline, `read1` and the refusal of redirects and compressed bodies.

## Bookmarks that are not connected feeds

The bookmark repository is a discovery catalog, not a declaration that every listed service is integrated. This expansion reviewed a selected publisher subset. Other bookmarked news sources remain unreviewed unless listed above; they are not labeled unavailable merely because they were not attempted.

| Class | Examples from the bookmarks | Treatment |
| --- | --- | --- |
| Lookup/data services | NVD, CVE.org, EPSS, OSV, VirusTotal, Shodan, GreyNoise, ThreatFox, certificate search | Keep as references. Their search APIs, IOC exports, accounts and device queries are not RSS article subscriptions. KEV is already a separate explicit catalog input. |
| Tools and software repositories | Scanners, recon tools, DFIR utilities, reverse-engineering tools, container scanners | Keep as tools/reference links. Listing a tool neither installs it nor runs a scan or exercise. |
| Standards and frameworks | ATT&CK, D3FEND, CWE, NIST, CIS, OWASP, STIX/TAXII | Reference material; not silently converted into news feeds or automated actions. |
| Training, labs and reports | Cyber ranges, academies, yearly threat reports, research libraries | Reference/learning material. No lab, exploit, download, purchase or login is initiated. |
| Social/community sources | Reddit communities and social links | Unverified leads until independently sourced. No consumer account, private timeline or paid search integration is enabled. |
| Publisher/access gaps | MSRC RSS, Chrome Releases, SEC EDGAR intake | See the specific dated limitations below. No login, HTTP downgrade or permissive redirect fallback is used. |

### Dated access and compatibility gaps

- Microsoft's original [MSRC RSS link](https://msrc.microsoft.com/blog/rss/) redirected to the new HTML blog during intake. The official [Microsoft article advertising that link](https://www.microsoft.com/en-us/security/blog/2025/03/13/how-msrc-coordinates-vulnerability-research-and-disclosure-while-building-community/) was checked. This review did not establish a direct current MSRC RSS endpoint. The separate Microsoft Security Blog feed remains configured; it is not a substitute for complete Security Update Guide coverage.
- Chrome Releases advertises a feed whose redirect points to FeedBurner. A separately inspected [HTTPS FeedBurner endpoint](https://feeds.feedburner.com/GoogleChromeReleases) returned Atom, but its alternate article links used HTTP. The current collector requires HTTPS article URLs, so Chrome was not added. No URL-upgrade exception or redirect relaxation was implemented.
- CISA's advisory feed remains configured from the original catalog, with its initial production failure disclosed. The advisory landing page did not establish a reviewed replacement during this expansion. No precise cause is inferred from its generic production error. CISA KEV is separate and does not replace all advisory coverage.
- Threatpost's feed was accessible, but all ten returned items were dated August 2022. It is labeled a legacy archive in the configuration. Those dates fall inside the collector's window, which runs from 1 January 1998. A successful feed fetch records transport/retrieval, not renewed publication; the latest production snapshot determines retained article counts.

### SEC cybersecurity filings: access prerequisite, not a connected feed

The SEC documents [EDGAR RSS searches](https://www.sec.gov/about/developer-resources) with Form Type filters. A direct fixed request for [current Form 8-K Atom entries](https://www.sec.gov/cgi-bin/browse-edgar?action=getcurrent&type=8-K&company=&dateb=&owner=include&start=0&count=100&output=atom) returned HTTP 403 during this intake. The direct developer-page request also returned 403, although the official documentation could be read separately through the research browser. No feed entries, live Atom schema or Item 1.05 filter were established. There is no SEC entry in the configured collector and no alternate provider, browser-session bypass or repeated automated retry.

The SEC's [fair-access guidance](https://www.sec.gov/search-filings/edgar-search-assistance/accessing-edgar-data) requires moderated access, currently no more than ten requests per second across machines, and a declared User-Agent identifying the organization/contact. This intake used an honest project identifier and invented no contact information. Any later production connection needs an owner-approved operational contact and access-policy review; a contact header would not prove that access will succeed. The underlying reason for the observed 403 is unestablished.

A Form 8-K feed includes many non-cybersecurity reports. The SEC's [Item 1.05 explanation](https://www.sec.gov/newsroom/whats-new/gerding-cybersecurity-incidents-05212024) distinguishes incidents determined material by the registrant from voluntary other cybersecurity disclosures, which may use Item 8.01. Thus an Item 1.05 selection could not claim all cyber filings. Future intake must verify actual filing metadata, amendments and item matching, preserve filing dates separately from incident dates, and label issuer disclosures accurately. No filing-document crawl, company contact, investment recommendation or remediation action was performed by this feed review.

Source expansion authorizes no automatic remediation, network/device inspection, credential use, social posting or model call. Deployment health and current source outcomes must come from the dated site snapshot and workflow evidence.

## Further source expansion

The owner requested broader coverage after the first 29-source intake. A further **29 feeds** passed bounded public HTTPS intake, bringing that checkpoint to **58 configured feeds**. The separately scoped Talos category brought the next checkpoint to **59**; Qualys brought it to **60**, and the separately scoped CISA category below brought it to **61**, and the CISA ICS advisories feed added with schema 7 brings the current total to **62**, plus the separate CISA KEV catalog. These are configured inputs, not a guarantee that all remain healthy or that their items are distinct incidents.

| Publisher | Feed | Role |
| --- | --- | --- |
| [Cisco Systems, Inc. PSIRT](https://sec.cloudapps.cisco.com/security/center/home.x) | [RSS / Atom](https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml) | Advisory |
| [Tenable](https://www.tenable.com/blog) | [RSS / Atom](https://www.tenable.com/blog/feed) | Research |
| [Red Hat Security Advisories](https://access.redhat.com/security/data) | [RSS / Atom](https://security.access.redhat.com/data/meta/v1/rhsa.rss) | Advisory |
| [Mozilla Security Blog](https://blog.mozilla.org/security/) | [RSS / Atom](https://blog.mozilla.org/security/feed/) | Research |
| [Sonatype](https://www.sonatype.com/blog) | [RSS / Atom](https://www.sonatype.com/blog/rss.xml) | Research |
| [Snyk](https://snyk.io/blog/) | [RSS / Atom](https://snyk.io/blog/feed/) | Research |
| [Cloudflare Security](https://blog.cloudflare.com/tag/security/) | [RSS / Atom](https://blog.cloudflare.com/tag/security/rss) | Research |
| [SentinelLabs](https://www.sentinelone.com/labs/) | [RSS / Atom](https://www.sentinelone.com/labs/feed/) | Research |
| [Google Security Blog](https://blog.google/security/) | [RSS / Atom](https://blog.google/security/rss/) | Research |
| [Apple Security Research](https://security.apple.com/blog/) | [RSS / Atom](https://security.apple.com/blog/feed.rss) | Research |
| [Palo Alto Networks Security Advisories](https://security.paloaltonetworks.com/) | [RSS / Atom](https://security.paloaltonetworks.com/rss.xml) | Advisory |
| [Splunk Security Advisories](https://advisory.splunk.com/) | [RSS / Atom](https://advisory.splunk.com/feed.xml) | Advisory |
| [PortSwigger Research](https://portswigger.net/research) | [RSS / Atom](https://portswigger.net/research/rss) | Research |
| [F5 Labs](https://www.f5.com/labs) | [RSS / Atom](https://www.f5.com/labs/rss-feeds/all.xml) | Research |
| [CyberScoop](https://cyberscoop.com/) | [RSS / Atom](https://cyberscoop.com/feed/) | Reporting |
| [Graham Cluley](https://grahamcluley.com/) | [RSS / Atom](https://grahamcluley.com/feed/) | Reporting |
| [Troy Hunt](https://www.troyhunt.com/) | [RSS / Atom](https://www.troyhunt.com/rss/) | Research |
| [CSO](https://www.csoonline.com/) | [RSS / Atom](https://www.csoonline.com/feed/) | Reporting |
| [Hackread](https://hackread.com/) | [RSS / Atom](https://hackread.com/feed/) | Reporting |
| [Ars Technica Security](https://arstechnica.com/security/) | [RSS / Atom](https://arstechnica.com/security/feed/) | Reporting |
| [TechCrunch Security](https://techcrunch.com/category/security/) | [RSS / Atom](https://techcrunch.com/category/security/feed/) | Reporting |
| [DataBreaches.net](https://databreaches.net/) | [RSS / Atom](https://databreaches.net/feed/) | Reporting |
| [CyberInsider](https://cyberinsider.com/) | [RSS / Atom](https://cyberinsider.com/feed/) | Reporting |
| [WIRED Security](https://www.wired.com/category/security/) | [RSS / Atom](https://www.wired.com/feed/category/security/latest/rss) | Reporting |
| [Infosecurity Magazine](https://www.infosecurity-magazine.com/) | [RSS / Atom](https://www.infosecurity-magazine.com/rss/news/) | Reporting |
| [Cybersecurity Dive](https://www.cybersecuritydive.com/) | [RSS / Atom](https://www.cybersecuritydive.com/feeds/news/) | Reporting |
| [Security Affairs](https://securityaffairs.com/) | [RSS / Atom](https://securityaffairs.com/feed) | Reporting |
| [Risky Business Newsletters](https://risky.biz/feeds/) | [RSS / Atom](https://risky.biz/feeds/newsletters/) | Reporting |
| [The Register Security](https://www.theregister.com/security/) | [RSS / Atom](https://www.theregister.com/security/?lab_viewport=rss) | Reporting |

Discovery used the publishers’ own sites or advertised endpoints and the same bounded collector. Each proposed endpoint returned HTTP 200 without following redirects, parsed as RSS/Atom and yielded accepted HTTPS article links on its recorded exact hosts. Private receipts retain the received-byte hashes, UTC intervals, safe item counts and source-specific limits; no full article bodies enter the public output. Admission is a dated observation, not a future availability or correctness guarantee.

Cisco PSIRT’s 50 admitted items had unknown dates under this parser, so they may appear as undated records without calendar-year matches. Snyk, F5 and Infosecurity reached the 150-item intake ceiling. F5 also returned older publications; the normal date filter still applies. Graham Cluley’s first observed response yielded six accepted same-publisher links; no extra article hosts were silently admitted. Counts in discovery receipts are neither net new articles nor evidence of complete archives.

This further intake rejected or held other attempts: Rapid7’s advertised feed was malformed XML; Fortinet yielded no accepted HTTPS article links; Elastic and Wordfence exceeded the response cap; ZDI contained rejected DTD/entity syntax. Some alternate news endpoints redirected, failed access or produced no accepted entries. Last Watchdog’s mixed press-release material and BankInfoSecurity’s undated results were held for editorial/date review. Those attempts are not configured sources, and the collector’s safeguards were not loosened to accept them. Qualys also failed the earlier **24 October 2026 UTC** whole-feed intake because one item exceeded the per-item CVE mention bound; its later admission under explicit partial accounting is documented below. Other sources not attempted remain unreviewed.

## Talos Threat Advisory category subset

The distinct source **Cisco Talos Threat Advisory (category subset)** uses the
publisher's [Threat Advisory RSS](https://blog.talosintelligence.com/category/threat-advisory/rss/)
and [category page](https://blog.talosintelligence.com/category/threat-advisory/),
with article links restricted to `blog.talosintelligence.com`. Its source ID is
`talos-threat-advisories`; its role remains research.

On **24 October 2026**, the direct HTTPS response returned 15 accepted entries
dated **5 June 2025 through 21 October 2026**. The largest item contained five
unique CVE mentions, within the unchanged 100-CVE-per-article limit. These are
dated intake observations, not a fresh availability check on every page view.
The rolling category selection is not the full Talos archive or all Talos topics.
Its response was larger in bytes than the separately observed all-feed response;
the narrower scope is a content category, not a smaller-response guarantee.

The official Talos HTML identifies the category and Ghost generator but advertises
only the generic all-posts RSS. The category RSS itself returned the matching
category title and exact RSS self URL. This establishes an observed
publisher-served route; it is not an explicitly linked category RSS advertisement
in that HTML or a verified platform-documentation rule.

The original `talos` all-posts source remains configured and separate. Its earlier
24 October whole-feed observation failed because one item exceeded 100 CVE
mentions. The newer partial-intake policy can reject that whole article while
admitting other safe all-posts entries; only a new recorded attempt establishes
that outcome. Its historical failure is not relabeled as a successful category
fetch. No CVEs are clipped and no reader limit is relaxed. Category entries remain
subject to the same validation. This establishes no replacement CISA advisory route.

## Qualys Security Blog: dated partial admission

The source **Qualys Security Blog** uses the official blog's advertised
[RSS endpoint](https://blog.qualys.com/feed) and
[home page](https://blog.qualys.com/). Its source ID is `qualys`, its role is
research and its article-host allowlist is exactly `blog.qualys.com`. The blog
mixes vulnerability research, product guidance and vendor announcements; it is
not exclusively a vulnerability-advisory stream.

A separate bounded request on **25 October 2026 at 00:40:44 UTC** returned HTTPS
200 and a valid response with **10 entries seen and processed, nine admitted and
one rejected whole** for exceeding 100 unique CVE mentions. No entries were
filtered or left unprocessed. The resulting observation is **partial**, not a
complete-input success. The admitted entries' publisher-provided publication
dates range from **29 September through 24 October 2026 UTC**; those dates are
separate from retrieval and do not establish incident occurrence. Accepted
entries contained at most ten CVE mentions each.

The **24 October UTC** rejection remains a historical observation under the
earlier whole-feed policy. The new attempt used the same canonical URL and
received the same response bytes; schema 3's whole-entry rejection permits the
other safe entries without clipping the rejected item's CVEs. No redirect,
alternate host, response-prefix parsing or access workaround was used. Response
hashes and exact intake provenance remain in private receipts.

The unchanged 3 MiB response, strict UTF-8, DTD/entity rejection, XML node/depth,
150-processed-entry and 100-CVE-per-entry gates still apply. Later responses can
fail these whole-response gates or yield no safe admission. Accepted items merge
with retained history under the 600-item source limit and the normal date
filter; a rolling ten-entry response is not a complete Qualys archive. Admission
does not establish live deployment, a later scheduled collection outcome,
independent factual verification, exploitation or exposure of the reader's devices.

## CISA Cybersecurity Advisories category subset

The distinct source **CISA Cybersecurity Advisories (category subset)** uses the
official [category RSS](https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml).
The returned channel identifies itself as **CISA Cybersecurity Advisories** and
links to [CISA](https://www.cisa.gov/). Its source ID is
`cisa-cybersecurity-advisories`, its role is advisory and article links are
restricted to `www.cisa.gov`.

One direct request on **25 October 2026 at 05:35:06 UTC** returned HTTPS 200 and a
complete **1,370,400-byte** response within the unchanged 3 MiB bound. All ten
entries were seen, processed and admitted, with no rejected, filtered or
unprocessed entries. Their publisher-provided publication dates ranged from
**6 April through 19 October 2026 UTC**, with 18 distinct CVE mentions across the
accepted input. Those are dated intake facts, not net new article counts,
incident dates, confirmed exploitation or a fresh check on each page view.

The original `cisa-advisories` all-advisories feed remains configured with its own
outcomes. Its byte-bound failure is not relabeled as a successful category read.
This category is not every CISA advisory, topic, alert or historical publication;
the retained response does not establish current news or a complete archive.
CISA KEV remains a separate catalog. Canonical article URLs are deduplicated and
their CVE mentions combined, while source-ledger outcomes remain separate.

The same response, XML, 150-processed-entry, 100-CVE-per-entry and 600-retained-item
limits apply. No response prefix is parsed, redirect followed or bound relaxed.
Admission does not establish a later production outcome, punctual scheduling or
the reader's device exposure. Those need their own dated evidence.
