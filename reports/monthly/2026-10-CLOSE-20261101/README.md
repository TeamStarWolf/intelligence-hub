# October 2026 · completed-month closing edition

**Late publication; partial source subset.** Period: [2026-10-01T05:00:00Z, 2026-11-01T05:00:00Z), America/Chicago calendar as specified below. Nominal reporting opportunity: **November 1, 2026 at 06:00 CST (12:00 UTC)**. Actual compilation: **2026-11-01T16:35:01.913Z**. Publication time was not observed at compilation; it is not asserted here.

Input generation: **2026-10-30T23:03:35+00:00**; original capture **2026-10-30T23:21:46.745324+00:00 through 2026-10-30T23:21:48.291337+00:00**. The later qualification and analysis do not make this a newer snapshot. [Data and exact membership](data.json). [Immutable prior edition](https://github.com/TeamStarWolf/intelligence-hub/blob/e11be8c5447054c1cb940161bee83b069ee8ec13/reports/monthly/2026-10/README.md).

## Executive summary

The main selection contains **1830** declared publication entries: **1750** explicit timestamps and **80** full dates selected under a UTC-calendar convention. They mention **321 unique CVEs**, with **33 KEV catalog-addition rows** and **85 main CVEs in captured current KEV context**. These are distinct, overlapping units, not incident or newly disclosed/exploited counts.

The input precedes period end by **107785 seconds**; snapshot generation precedes the shared nominal publication opportunity by **132,985 seconds**. Missing coverage is not filled by compilation. The source status projection contains 53 ok, 7 partial and 2 failed sources; it does not establish that every publisher was admitted.

## Selected developments

- **[Enclave-tool version scope](https://aws.amazon.com/security/security-bulletins/rss/2026-157-aws/)** - The retained AWS publication entry is dated October 30 and declares two CVE identifiers; the technical context below covers only the enclave-tool record. Source: AWS Security Bulletins; declared publication 2026-10-30T16:34:46+00:00. Declared identifiers: CVE-2026-119116, CVE-2026-119148.
- **[FreeRTOS interval review](https://aws.amazon.com/security/security-bulletins/rss/2026-158-aws/)** - The captured AWS entry associates its October 30 bulletin with a FreeRTOS-Kernel identifier; the version interval below comes from retained CNA metadata. Source: AWS Security Bulletins; declared publication 2026-10-30T17:39:33+00:00. Declared identifiers: CVE-2026-119086.
- **[AWS bulletin 159](https://aws.amazon.com/security/security-bulletins/rss/2026-159-aws/)** - The retained AWS feed records bulletin 159 on October 30 and associates it with CVE-2026-119117; no technical assessment is included for that identifier here. Source: AWS Security Bulletins; declared publication 2026-10-30T18:18:40+00:00. Declared identifiers: CVE-2026-119117.
- **[Commerce version boundaries](https://cyber.gc.ca/en/alerts-advisories/drupal-security-advisory-av26-1105)** - The Canadian cyber centre entry is dated October 30 and associated in the Hub with a Commerce Core identifier; the two recorded version intervals remain separate. Source: Canadian Centre for Cyber Security; declared publication 2026-10-30T15:43:17+00:00. Declared identifiers: CVE-2026-118539.
- **[Access-platform advisory context](https://cyber.gc.ca/en/alerts-advisories/ivanti-security-advisory-av26-1035)** - The Canadian advisory entry declares multiple Ivanti identifiers; the selected product context covers one Connect Secure record and preserves a separate failed enrichment. Source: Canadian Centre for Cyber Security; declared publication 2026-10-30T18:01:12+00:00. Declared identifiers: CVE-2026-104935, CVE-2026-109412, CVE-2026-111357, CVE-2026-118527.
- **[Linux branch applicability](https://cyber.gc.ca/en/alerts-advisories/linux-security-advisory-av26-1108)** - The Canadian cyber centre publication entry links to a Linux identifier; its captured version data requires branch-specific interpretation. Source: Canadian Centre for Cyber Security; declared publication 2026-10-30T21:34:05+00:00. Declared identifiers: CVE-2026-98432.
- **[SD-WAN record follow-up](https://blog.talosintelligence.com/uat-11473-keydrift/)** - The retained Talos entry is dated October 28 and associated in the Hub with a Cisco management-platform identifier; this is a publication selection, not an actor or campaign finding. Source: Cisco Talos Threat Advisory (category subset); declared publication 2026-10-28T21:32:02+00:00. Declared identifiers: CVE-2026-20127.

These are selected retained publication records; original article bodies were not rechecked and no headline was treated as technical or exposure evidence.

## KEV additions vs current context

The main union has **33** catalog-addition rows covering **33** distinct CVE IDs. Separately, **85** main CVEs have captured current KEV context. Date-boundary rows remain outside main counts. Zero main-window additions does not mean zero uncertain-date additions or no exploitation. Complete IDs and entry membership are in data.json.

## CVE products, versions, CVSS and mitigation limits

Technical facts below are a selected retained CNA/CISA projection, not new primary-record requests, an as-of-close reconstruction, a tested remediation plan or evidence of the reader's exposure. Longer overlapping editions link to the first eligible full context.

### CVE-2026-119116

[Full technical context](https://github.com/TeamStarWolf/intelligence-hub/blob/main/reports/daily/2026-11-01/0600-CST/README.md#cve-2026-119116) is kept in its first eligible edition. This compact reference does not duplicate the product table or treat missing text as missing source data.

### CVE-2026-119086

[Full technical context](https://github.com/TeamStarWolf/intelligence-hub/blob/main/reports/daily/2026-11-01/0600-CST/README.md#cve-2026-119086) is kept in its first eligible edition. This compact reference does not duplicate the product table or treat missing text as missing source data.

### CVE-2026-118539

[Full technical context](https://github.com/TeamStarWolf/intelligence-hub/blob/main/reports/daily/2026-11-01/0600-CST/README.md#cve-2026-118539) is kept in its first eligible edition. This compact reference does not duplicate the product table or treat missing text as missing source data.

### CVE-2026-104935

[Full technical context](https://github.com/TeamStarWolf/intelligence-hub/blob/main/reports/daily/2026-11-01/0600-CST/README.md#cve-2026-104935) is kept in its first eligible edition. This compact reference does not duplicate the product table or treat missing text as missing source data.

### CVE-2026-98432

[Full technical context](https://github.com/TeamStarWolf/intelligence-hub/blob/main/reports/daily/2026-11-01/0600-CST/README.md#cve-2026-98432) is kept in its first eligible edition. This compact reference does not duplicate the product table or treat missing text as missing source data.

### CVE-2026-20127

[Retained record reference](https://www.cve.org/CVERecord?id=CVE-2026-20127). Captured status: **ok / PUBLISHED**; record-declared update 2026-06-16T17:57:59+00:00. Technical CNA/CISA projection retained in the October 30 input; not primary-rechecked or established as historically known at the article publication instant.

Cisco Catalyst SD-WAN Manager. The record enumerates twelve affected version rows and has an unknown default; no continuous range or universal fixed release is inferred.

**Cisco / Cisco Catalyst SD-WAN Manager** - default status: **unknown**. Empty cells below are not supplied bounds.

| Version | Status | Less than | Less than or equal | Version scheme |
| --- | --- | --- | --- | --- |
| 20.1.12 | affected | not supplied | not supplied | not supplied |
| 19.2.1 | affected | not supplied | not supplied | not supplied |
| 18.4.4 | affected | not supplied | not supplied | not supplied |
| 18.4.5 | affected | not supplied | not supplied | not supplied |
| 20.1.1.1 | affected | not supplied | not supplied | not supplied |
| 20.1.1 | affected | not supplied | not supplied | not supplied |
| 19.3.0 | affected | not supplied | not supplied | not supplied |
| 19.2.2 | affected | not supplied | not supplied | not supplied |
| 19.2.099 | affected | not supplied | not supplied | not supplied |
| 18.3.6 | affected | not supplied | not supplied | not supplied |
| 18.3.7 | affected | not supplied | not supplied | not supplied |
| 19.2.0 | affected | not supplied | not supplied | not supplied |

Captured CVSS 3.1: **10**, vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H ([metric source](https://www.cve.org/CVERecord?id=CVE-2026-20127)). This is not a local risk score.

Captured CISA context refers to agency/vendor guidance. It does not establish a new campaign event, current exploitation on a reader asset, or an applicable visitor deadline.

Solutions/workarounds in the selected structured arrays: **empty**. This is missing structured guidance, not proof of a complete fix or no available fix. Captured catalog context only; not first-exploitation time, local exposure or an automatic mitigation instruction.

Captured KEV catalog metadata: added 2026-02-25, catalog due date 2026-02-27, ransomware field Unknown. These are catalog/agency metadata, not a reader deadline or first-exploitation timestamp.

CNA weakness identifiers: [CWE-287](https://www.cve.org/CVERecord?id=CVE-2026-20127). No observed CAPEC/attack mapping is established.


### CVE-2026-118527

[Full technical context](https://github.com/TeamStarWolf/intelligence-hub/blob/main/reports/daily/2026-11-01/0600-CST/README.md#cve-2026-118527) is kept in its first eligible edition. This compact reference does not duplicate the product table or treat missing text as missing source data.

## CWE/CAPEC, actors, supply chain and AI

CNA weakness IDs, when present in the selected full contexts, are CVE-to-CWE associations. No observed CAPEC/attack mapping is asserted. Actor/campaign, AI and supply-chain-compromise claims are **not assessed**; a package advisory, URL wording or co-mention is not enough.

## Watchlist and date precision

| Classification | Entry count | Scope |
| --- | --- | --- |
| Explicit timestamp | 1750 | Declared timestamp inside half-open period |
| Full UTC calendar date | 80 | UTC-calendar convention; publisher timezone unknown |
| Date-boundary uncertain | 3 | Separate from main union |
| After-generation uncertain | 0 | Separate from main union |
| Undated | 65 | Separate from main union |
| Outside period | 2792 | Separate from main union |

| Boundary-watch entry | Declared date | CVE identifiers |
| --- | --- | --- |
| kev-CVE-2026-104286 | 2026-10-01 | CVE-2026-104286 |
| kev-CVE-2026-111357 | 2026-10-30 | CVE-2026-111357 |
| kev-CVE-2026-118527 | 2026-10-30 | CVE-2026-118527 |

Date-only days do not establish an exact publication instant or guaranteed elapsed-hour membership. Undated, outside-window and after-generation uncertainty are not zero activity. The six groups partition all 4,690 saved input entries; only the two admitted main groups form period metrics.

## Charts and source limits

![Six date cohorts](charts/date-cohorts.svg)

![Source activity in the main union](charts/source-activity.svg)

![Three nonadditive CVE context counts](charts/cve-context.svg)

Each chart uses the exact data.json membership, count recipe and retained input. Source bars describe admitted publication entries; CVE bars overlap and must never be added together. Source labels use the captured source-health display name for each source ID, or the ID when that display metadata is missing; entry-level name variants remain in data.json.

| Source status metadata | Status | Stored articles | Last attempt | Last success |
| --- | --- | --- | --- | --- |
| [CISA Advisories](https://www.cisa.gov/cybersecurity-advisories) | failed | 0 | 2026-10-30T23:03:29+00:00 | unknown |
| [F5 Labs](https://www.f5.com/labs) | partial | 237 | 2026-10-30T23:03:32+00:00 | 2026-10-30T23:03:33+00:00 |
| [Graham Cluley](https://grahamcluley.com/) | partial | 7 | 2026-10-30T23:03:32+00:00 | 2026-10-30T23:03:33+00:00 |
| [Infosecurity Magazine](https://www.infosecurity-magazine.com/) | partial | 177 | 2026-10-30T23:03:33+00:00 | 2026-10-30T23:03:33+00:00 |
| [Microsoft Security](https://www.microsoft.com/en-us/security/blog/) | partial | 21 | 2026-10-30T23:03:29+00:00 | 2026-10-30T23:03:29+00:00 |
| [Qualys Security Blog](https://blog.qualys.com/) | partial | 12 | 2026-10-30T23:03:34+00:00 | 2026-10-30T23:03:34+00:00 |
| [SANS Internet Storm Center](https://isc.sans.edu/) | failed | 20 | 2026-10-30T23:03:30+00:00 | 2026-10-30T22:29:12+00:00 |
| [Snyk](https://snyk.io/blog/) | partial | 152 | 2026-10-30T23:03:32+00:00 | 2026-10-30T23:03:32+00:00 |
| [Cisco Talos](https://blog.talosintelligence.com/) | partial | 20 | 2026-10-30T23:03:29+00:00 | 2026-10-30T23:03:29+00:00 |

Source URLs above are display/home status metadata, not proof of a new exact endpoint request. Selected long-term coverage is nonexhaustive; an empty month or failed source does not establish absence of events. The full eight-field source-health projection is in data.json.

## Prior-citation review

The dedicated offline inventory attempt **failed without an accepted URL inventory**. Citation occurrence/URL/eligibility/selection/changed/unresolved/cap-excluded totals remain **unknown (null)**. No new original-article GET, qualified article check or comparison was completed. Empty records and zero operations do not mean unchanged content, all-updated sources or source-wide absence. Held routes remain inactive; no per-URL next eligibility result is established.

## Primary-first references

- [CVE record/reference metadata](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-rpa-EHchtZk) - retained-CNA-projection; not body rechecked.
- [CVE record/reference metadata](https://www.cve.org/CVERecord?id=CVE-2026-104935) - retained-CNA-projection; not body rechecked.
- [CVE record/reference metadata](https://www.cve.org/CVERecord?id=CVE-2026-118527) - retained-CNA-projection; not body rechecked.
- [CVE record/reference metadata](https://www.cve.org/CVERecord?id=CVE-2026-118539) - retained-CNA-projection; not body rechecked.
- [CVE record/reference metadata](https://www.cve.org/CVERecord?id=CVE-2026-119086) - retained-CNA-projection; not body rechecked.
- [CVE record/reference metadata](https://www.cve.org/CVERecord?id=CVE-2026-119116) - retained-CNA-projection; not body rechecked.
- [CVE record/reference metadata](https://www.cve.org/CVERecord?id=CVE-2026-20127) - retained-CNA-projection; not body rechecked.
- [CVE record/reference metadata](https://www.cve.org/CVERecord?id=CVE-2026-98432) - retained-CNA-projection; not body rechecked.
- [Enclave-tool version scope](https://aws.amazon.com/security/security-bulletins/rss/2026-157-aws/) - captured-feed-metadata.
- [FreeRTOS interval review](https://aws.amazon.com/security/security-bulletins/rss/2026-158-aws/) - captured-feed-metadata.
- [AWS bulletin 159](https://aws.amazon.com/security/security-bulletins/rss/2026-159-aws/) - captured-feed-metadata.
- [SD-WAN record follow-up](https://blog.talosintelligence.com/uat-11473-keydrift/) - captured-feed-metadata.
- [Commerce version boundaries](https://cyber.gc.ca/en/alerts-advisories/drupal-security-advisory-av26-1105) - captured-feed-metadata.
- [Access-platform advisory context](https://cyber.gc.ca/en/alerts-advisories/ivanti-security-advisory-av26-1035) - captured-feed-metadata.
- [Linux branch applicability](https://cyber.gc.ca/en/alerts-advisories/linux-security-advisory-av26-1108) - captured-feed-metadata.

Reference URLs were present in the retained projection; listing them is not an HTTP check or source-body qualification. No direct article quotes are reproduced.

## Next nominal report/revision opportunity

**November 1, 2026 at 14:00 America/Chicago (CST; 20:00 UTC)**. This is a requested opportunity, subject to app/computer availability, with no punctual delivery guarantee. Per-URL eligibility, the requested ten-minute feed checks, actual snapshot clocks and actual report publication are separate.
