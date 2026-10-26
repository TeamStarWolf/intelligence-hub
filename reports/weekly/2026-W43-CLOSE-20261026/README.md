# Week 43 closing intelligence review — 19–26 October 2026

**Partial retrospective review.** Declared period: 2026-10-19T00:00:00-05:00 inclusive to 2026-10-26T00:00:00-05:00 exclusive (America/Chicago). The reporting opportunity was 26 October at 06:00 CDT / 11:00 UTC; this edition was compiled later.

## Executive summary

The main selection contains **539 source-declared timestamp rows plus 22 selected UTC-calendar rows**, with **127 unique CVE identifiers supplied by those rows**. The 22 date-only rows are a declared UTC-calendar convention with unknown publisher timezone, not proven publication instants or a guaranteed elapsed-hour cohort. Older identifiers in this set are mentions, not newly disclosed vulnerabilities. The captured context marks **27** of the main mentioned CVEs as KEV-listed, while the selected period contains **8 source-declared CISA catalog-addition rows**. These are different measures; neither counts new exploitation events.

125 of 127 main CVE contexts have a successful loaded CNA status; 2 do not. CVSS is supplied for 115, and CWE IDs for 110. Missing enrichment stays unknown. Advisory rows without explicit CVE IDs are not assumed to contain no vulnerabilities.

The input was generated **22596 seconds after this period ended**, then captured and analyzed later. It supports a retrospective selection of declared dates and bounded source/CNA context, **not an as-of-cutoff reconstruction**. This later snapshot cannot establish complete coverage at the cutoff. No new article checks or comparisons were performed in the revision pass.

## Dates and scope

| Clock | Recorded value |
| --- | --- |
| Period end, exclusive | 2026-10-26T05:00:00Z |
| Nominal reporting opportunity | 2026-10-26T11:00:00Z |
| Saved input generation | 2026-10-26T11:16:36+00:00 |
| Transport capture | 2026-10-26T12:11:03.087237+00:00 to 2026-10-26T12:11:04.706663+00:00 |
| Offline analysis complete | 2026-10-26T12:48:59.084465+00:00 |
| This compilation | 2026-10-26T13:36:45.448Z |
| Publication observation | Not assigned by this compilation |

Source publication/update/retrieval dates inside the records remain separate. Event dates do not drive selection. CISA dates mean catalog addition; due dates are catalog/federal data, not deadlines assigned to readers.

![Retained row coverage](charts/coverage.svg)

## Selected notable developments

### PHP: initial pair, deployment conditions and separate follow-up

The loaded PHP context separates the initial pair from a later conditional issue. Upstream release numbers do not settle distribution backports, and the SAPI/request prerequisites differ. The later follow-up must not inherit the initial pair’s shipped fixes.

Counted identifiers: [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618), [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619). References: [Source 1](https://www.cve.org/CVERecord?id=CVE-2026-109618); [Source 2](https://www.php.net/archive/2026.php); [Source 3](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w); [Source 4](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp). Retained structured context; no new publisher-body check.

### SiteGuard: captured KEV context with a local, low-privilege metric

The CNA projection identifies SiteGuard product/version ranges and a CVSS 4.0 score of 8.5 with AV:L and PR:L. It must not be described as a generic remote unauthenticated issue. The captured KEV entry is dated October 20; that is catalog context, not a new incident here.

Counted identifiers: [CVE-2026-106931](https://www.cve.org/CVERecord?id=CVE-2026-106931). References: [Source 1](https://www.cve.org/CVERecord?id=CVE-2026-106931); [Source 2](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-106931). Retained structured context; no new publisher-body check.

### Signal RingRTC: preserve the range and metric conditions

The retained record marks RingRTC versions below 2.72.0 as affected and supplies CVSS 4.0 9.3. Its vector and product statement are retained in data.json. The projection supplies no solution or workaround text, so the range boundary alone is not a verified shipped-fix claim.

Counted identifiers: [CVE-2026-113380](https://www.cve.org/CVERecord?id=CVE-2026-113380). References: [Source 1](https://www.cve.org/CVERecord?id=CVE-2026-113380). Retained structured context; no new publisher-body check.

### Collabora and VeloCloud: version trains and catalog context

Collabora’s Built-in CODE Server and Arista VeloCloud Orchestrator have distinct CNA version statements. The VeloCloud solution lists train-specific releases; Collabora’s captured range is not itself proof of deployment or remediation. CISA catalog dates and federal due dates are not visitor-specific incident or patch deadlines.

Counted identifiers: [CVE-2026-110447](https://www.cve.org/CVERecord?id=CVE-2026-110447), [CVE-2026-114625](https://www.cve.org/CVERecord?id=CVE-2026-114625). References: [Source 1](https://www.cve.org/CVERecord?id=CVE-2026-110447); [Source 2](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-110447); [Source 3](https://www.cve.org/CVERecord?id=CVE-2026-114625); [Source 4](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-114625). Retained structured context; no new publisher-body check.

### AWS MCP, agent and runtime components require separate applicability checks

The captured records cover different MCP servers, agent components and supporting software. Their versions and CVSS 4.0 vectors are not interchangeable. OpenSearch Dashboards and Amazon OpenSearch Service also have different affected/unaffected statements; do not transfer a finding between those products.

Counted identifiers: [CVE-2026-85787](https://www.cve.org/CVERecord?id=CVE-2026-85787), [CVE-2026-85788](https://www.cve.org/CVERecord?id=CVE-2026-85788), [CVE-2026-87911](https://www.cve.org/CVERecord?id=CVE-2026-87911), [CVE-2026-87912](https://www.cve.org/CVERecord?id=CVE-2026-87912), [CVE-2026-87913](https://www.cve.org/CVERecord?id=CVE-2026-87913), [CVE-2026-89049](https://www.cve.org/CVERecord?id=CVE-2026-89049). References: [Source 1](https://www.cve.org/CVERecord?id=CVE-2026-85787); [Source 2](https://www.cve.org/CVERecord?id=CVE-2026-85788); [Source 3](https://www.cve.org/CVERecord?id=CVE-2026-87911); [Source 4](https://www.cve.org/CVERecord?id=CVE-2026-87912). Retained structured context; no new publisher-body check.

### Node.js record set: preserve per-CVE boundaries

The weekly set contains several Node.js CNA records with different version statements and CVSS 3.0 metrics. The full statements are retained; a numeric boundary is not automatically a shipped fix or an inventory finding. These scores should not be ordered against CVSS 4.0 as operational risk.

Counted identifiers: [CVE-2026-105481](https://www.cve.org/CVERecord?id=CVE-2026-105481), [CVE-2026-105482](https://www.cve.org/CVERecord?id=CVE-2026-105482), [CVE-2026-105483](https://www.cve.org/CVERecord?id=CVE-2026-105483), [CVE-2026-106069](https://www.cve.org/CVERecord?id=CVE-2026-106069), [CVE-2026-106070](https://www.cve.org/CVERecord?id=CVE-2026-106070), [CVE-2026-106071](https://www.cve.org/CVERecord?id=CVE-2026-106071), [CVE-2026-106072](https://www.cve.org/CVERecord?id=CVE-2026-106072), [CVE-2026-106073](https://www.cve.org/CVERecord?id=CVE-2026-106073), [CVE-2026-106074](https://www.cve.org/CVERecord?id=CVE-2026-106074). References: [Source 1](https://www.cve.org/CVERecord?id=CVE-2026-105481); [Source 2](https://www.cve.org/CVERecord?id=CVE-2026-105482); [Source 3](https://www.cve.org/CVERecord?id=CVE-2026-105483); [Source 4](https://www.cve.org/CVERecord?id=CVE-2026-106069). Retained structured context; no new publisher-body check.

### CISA advisory coverage includes previously assigned CVEs

The selected CISA advisory entry lists five older CVE identifiers. Its publication belongs to this selection, but the identifiers are not five newly disclosed vulnerabilities, victims or exploitation events.

Counted identifiers: [CVE-2020-3259](https://www.cve.org/CVERecord?id=CVE-2020-3259), [CVE-2023-20269](https://www.cve.org/CVERecord?id=CVE-2023-20269), [CVE-2023-27532](https://www.cve.org/CVERecord?id=CVE-2023-27532), [CVE-2024-40711](https://www.cve.org/CVERecord?id=CVE-2024-40711), [CVE-2024-40766](https://www.cve.org/CVERecord?id=CVE-2024-40766). References: [Source 1](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a). CISA advisory entry metadata and explicit CVE associations; article body not rechecked.

## CISA catalog additions and captured KEV context

The main set contains 8 catalog-addition rows. Their date-only values are selected under the UTC-calendar convention; no exact addition hour is established.

| CVE | Source-declared addition date |
| --- | --- |
| [CVE-2026-106931](https://www.cve.org/CVERecord?id=CVE-2026-106931) | 2026-10-20 |
| [CVE-2026-110936](https://www.cve.org/CVERecord?id=CVE-2026-110936) | 2026-10-20 |
| [CVE-2026-96652](https://www.cve.org/CVERecord?id=CVE-2026-96652) | 2026-10-20 |
| [CVE-2026-96654](https://www.cve.org/CVERecord?id=CVE-2026-96654) | 2026-10-20 |
| [CVE-2026-96655](https://www.cve.org/CVERecord?id=CVE-2026-96655) | 2026-10-20 |
| [CVE-2026-96656](https://www.cve.org/CVERecord?id=CVE-2026-96656) | 2026-10-20 |
| [CVE-2026-110447](https://www.cve.org/CVERecord?id=CVE-2026-110447) | 2026-10-23 |
| [CVE-2026-114625](https://www.cve.org/CVERecord?id=CVE-2026-114625) | 2026-10-23 |

Captured KEV membership among the main mentioned CVEs: [CVE-2012-1823](https://www.cve.org/CVERecord?id=CVE-2012-1823), [CVE-2019-11043](https://www.cve.org/CVERecord?id=CVE-2019-11043), [CVE-2020-3259](https://www.cve.org/CVERecord?id=CVE-2020-3259), [CVE-2021-44228](https://www.cve.org/CVERecord?id=CVE-2021-44228), [CVE-2023-20269](https://www.cve.org/CVERecord?id=CVE-2023-20269), [CVE-2023-27532](https://www.cve.org/CVERecord?id=CVE-2023-27532), [CVE-2024-40711](https://www.cve.org/CVERecord?id=CVE-2024-40711), [CVE-2024-40766](https://www.cve.org/CVERecord?id=CVE-2024-40766), [CVE-2024-4577](https://www.cve.org/CVERecord?id=CVE-2024-4577), [CVE-2025-8088](https://www.cve.org/CVERecord?id=CVE-2025-8088), [CVE-2026-0257](https://www.cve.org/CVERecord?id=CVE-2026-0257), [CVE-2026-102764](https://www.cve.org/CVERecord?id=CVE-2026-102764), [CVE-2026-104935](https://www.cve.org/CVERecord?id=CVE-2026-104935), [CVE-2026-106931](https://www.cve.org/CVERecord?id=CVE-2026-106931), [CVE-2026-110447](https://www.cve.org/CVERecord?id=CVE-2026-110447), [CVE-2026-110936](https://www.cve.org/CVERecord?id=CVE-2026-110936), [CVE-2026-114625](https://www.cve.org/CVERecord?id=CVE-2026-114625), [CVE-2026-33825](https://www.cve.org/CVERecord?id=CVE-2026-33825), [CVE-2026-60004](https://www.cve.org/CVERecord?id=CVE-2026-60004), [CVE-2026-85706](https://www.cve.org/CVERecord?id=CVE-2026-85706), [CVE-2026-88771](https://www.cve.org/CVERecord?id=CVE-2026-88771), [CVE-2026-88772](https://www.cve.org/CVERecord?id=CVE-2026-88772), [CVE-2026-96652](https://www.cve.org/CVERecord?id=CVE-2026-96652), [CVE-2026-96654](https://www.cve.org/CVERecord?id=CVE-2026-96654), [CVE-2026-96655](https://www.cve.org/CVERecord?id=CVE-2026-96655), [CVE-2026-96656](https://www.cve.org/CVERecord?id=CVE-2026-96656), [CVE-2026-96951](https://www.cve.org/CVERecord?id=CVE-2026-96951). Catalog membership is later retained context, not evidence of first disclosure or current exposure.

## Product, version, CVSS and mitigation context

All **127** main CVE contexts, including complete bounded product/version statements, supplied solutions/workarounds, vectors, source clocks and limitations, are retained in [data.json](data.json). The index below is not a fixed-version or applicability determination. A range boundary is a fixed-release claim only when the source separately supplies that resolution. CVSS 3.0, 3.1 and 4.0 remain versioned metrics, not an operational risk ranking. A workaround object with null text or only a reference is not a usable workaround.

### PHP applicability and mitigation conditions

For the initial pair, the retained PHP notice lists upstream **8.2.35, 8.3.36, 8.4.27 and 8.5.12**. It also describes distribution/LTS fixes and minimal backports for 7.4, 8.0 and 8.1. A lower displayed version alone does not establish an unpatched package; vendor package/backport evidence remains necessary.

The source context distinguishes a pre-application mod_php demonstration from other SAPI susceptibility qualifications and configuration-dependent, same-worker request-state paths. Do not transfer the demonstration to every SAPI, configuration or installation. CISA’s retained conditional guidance concerns inability to update immediately or unsupported PHP 8.1 and earlier; it does not prove that every numerically older build is unpatchable.

The separate later follow-up must not inherit the pair’s shipped release list. The retained notice describes a planned regular-release fix and an interim upload-progress setting only for a particular session-serializer switch before session start. That measure is not complete mitigation of the initial pair, and these inputs do not establish a shipped third fix. 

References: [Dated publisher context 1](https://www.php.net/archive/2026.php); [Dated publisher context 2](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w); [Dated publisher context 3](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp); [Dated publisher context 4](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching).

### Version statements worth distinguishing

- **[CVE-2026-106931](https://www.cve.org/CVERecord?id=CVE-2026-106931)** — EG Secure Solutions Inc. / SiteGuard Server Edition for Apache httpd; default unaffected; Ver2.20 to &lt; Ver8.00 Update 5 [affected; semver]; EG Secure Solutions Inc. / SiteGuard Server Edition for Nginx; default unaffected; Ver2.20 to &lt; Ver8.00 Update 5 [affected; semver]; EG Secure Solutions Inc. / SiteGuard Server Edition for IIS; default unaffected; Ver2.20 to &lt; Ver8.00 Update 5 [affected; semver]; EG Secure Solutions Inc. / SiteGuard Server Edition for Apache httpd on FreeBSD; default unaffected; Ver2.20 to &lt; Ver7.00 Update 6 [affected; semver]; EG Secure Solutions Inc. / SiteGuard Server Edition for Nginx on FreeBSD; default unaffected; Ver2.20 to &lt; Ver7.00 Update 6 [affected; semver]. CVSS 8.5 / v4.0. Its retained vector is AV:L/PR:L; do not call it generic remote unauthenticated exposure. No supplied solution text establishes a shipped fix here.

- **[CVE-2026-113380](https://www.cve.org/CVERecord?id=CVE-2026-113380)** — Signal / RingRTC; default unaffected; 0 to &lt; 2.72.0 [affected; semver]. CVSS 9.3 / v4.0. No supplied solution text establishes a shipped fix here.

- **[CVE-2026-110447](https://www.cve.org/CVERecord?id=CVE-2026-110447)** — Collabora / Collabora Online - Built-in CODE Server; default affected; 0 to &lt; 26.4.303 [affected; semver]. CVSS 9.2 / v4.0. No supplied solution text establishes a shipped fix here.

- **[CVE-2026-114625](https://www.cve.org/CVERecord?id=CVE-2026-114625)** — Arista Networks / VeloCloud Orchestrator; default unaffected; 5.2.0 to &lt; 5.2.3.18 [affected; custom]; 6.1.0 to &lt; 6.1.3.10 [affected; custom]; 6.4.0 to &lt; 6.4.2.12 [affected; custom]. CVSS 9.4 / v4.0. Source solution text is supplied in data.json; keep its product and train conditions.

- **[CVE-2026-85787](https://www.cve.org/CVERecord?id=CVE-2026-85787)** — Amazon / postgres-mcp-server; default unaffected; 0 to &lt; 1.1.7 [affected; custom]. CVSS 7.1 / v4.0. No supplied solution text establishes a shipped fix here.

- **[CVE-2026-85788](https://www.cve.org/CVERecord?id=CVE-2026-85788)** — AWS / AWS Labs MySQL MCP Server; default unaffected; 0 to &lt;= 1.0.21 [affected; custom]. CVSS 5.7 / v4.0. No supplied solution text establishes a shipped fix here.

- **[CVE-2026-87911](https://www.cve.org/CVERecord?id=CVE-2026-87911)** — AWS / AWS Labs postgres MCP Server; default unaffected; 0 to &lt; 1.1.7 [affected; custom]. CVSS 9 / v4.0. No supplied solution text establishes a shipped fix here.

- **[CVE-2026-87913](https://www.cve.org/CVERecord?id=CVE-2026-87913)** — AWS / AWS Security Agent MCP server; default unaffected; 0.1.0 to &lt;= 0.1.5 [affected; custom]. CVSS 5.1 / v4.0. No supplied solution text establishes a shipped fix here.

- **[CVE-2026-89049](https://www.cve.org/CVERecord?id=CVE-2026-89049)** — AWS / Amazon SSM Agent; default unaffected; 0 to &lt; 3.3.4851.0 [affected; custom]. CVSS 8.5 / v4.0. No supplied solution text establishes a shipped fix here.

- **[CVE-2026-84942](https://www.cve.org/CVERecord?id=CVE-2026-84942)** — AWS / Amazon OpenSearch Service; default unaffected; v2.3.0 to &lt;= v3.5.0 [unaffected; custom]; OpenSearch / OpenSearch Dashboards; default unaffected; v2.0.0 to &lt;= v3.5.0 [affected; custom]. CVSS 6.3 / v4.0. No supplied solution text establishes a shipped fix here.

### Main CVE context index

Product names are a compact index; full version/default-status statements remain in data.json. “KEV” means captured catalog membership. No missing record is treated as CVE-registry absence.

| CVE | Product index | CNA / state | CVSS score / version | Captured KEV | CWE IDs |
| --- | --- | --- | --- | --- | --- |
| [CVE-2012-1823](https://www.cve.org/CVERecord?id=CVE-2012-1823) | n/a | ok / PUBLISHED | Not supplied | Yes; 2022-03-25 | Not supplied |
| [CVE-2019-11043](https://www.cve.org/CVERecord?id=CVE-2019-11043) | PHP | ok / PUBLISHED | 8.7 / v3.1 | Yes; 2022-03-25 | CWE-120 |
| [CVE-2020-22217](https://www.cve.org/CVERecord?id=CVE-2020-22217) | n/a | ok / PUBLISHED | Not supplied | Not supplied | Not supplied |
| [CVE-2020-3259](https://www.cve.org/CVERecord?id=CVE-2020-3259) | Cisco Adaptive Security Appliance (ASA) Software | ok / PUBLISHED | 7.5 / v3.0 | Yes; 2024-02-15 | CWE-200 |
| [CVE-2021-44228](https://www.cve.org/CVERecord?id=CVE-2021-44228) | Apache Log4j2 | ok / PUBLISHED | Not supplied | Yes; 2021-12-10 | CWE-502, CWE-400, CWE-20 |
| [CVE-2022-21894](https://www.cve.org/CVERecord?id=CVE-2022-21894) | Windows 10 Version 1809; Windows Server 2019 (+3 more) | ok / PUBLISHED | 4.4 / v3.1 | Not supplied | Not supplied |
| [CVE-2022-4904](https://www.cve.org/CVERecord?id=CVE-2022-4904) | c-ares | ok / PUBLISHED | Not supplied | Not supplied | CWE-20 |
| [CVE-2023-20269](https://www.cve.org/CVERecord?id=CVE-2023-20269) | Cisco Adaptive Security Appliance (ASA) Software; Cisco Firepower Threat Defense Software | ok / PUBLISHED | 5 / v3.1 | Yes; 2023-09-13 | CWE-288 |
| [CVE-2023-27532](https://www.cve.org/CVERecord?id=CVE-2023-27532) | Veeam Backup &amp; Replication | ok / PUBLISHED | Not supplied | Yes; 2023-08-22 | CWE-306 |
| [CVE-2023-54397](https://www.cve.org/CVERecord?id=CVE-2023-54397) | tornado | ok / PUBLISHED | 9 / v4.0 | Not supplied | CWE-444 |
| [CVE-2024-14029](https://www.cve.org/CVERecord?id=CVE-2024-14029) | tornado | ok / PUBLISHED | 9 / v4.0 | Not supplied | CWE-444 |
| [CVE-2024-40711](https://www.cve.org/CVERecord?id=CVE-2024-40711) | Backup and Recovery | ok / PUBLISHED | 9.8 / v3.0 | Yes; 2024-10-17 | Not supplied |
| [CVE-2024-40766](https://www.cve.org/CVERecord?id=CVE-2024-40766) | SonicOS | ok / PUBLISHED | Not supplied | Yes; 2024-09-09 | CWE-284 |
| [CVE-2024-4577](https://www.cve.org/CVERecord?id=CVE-2024-4577) | PHP | ok / PUBLISHED | 9.8 / v3.1 | Yes; 2024-06-12 | CWE-78 |
| [CVE-2025-8088](https://www.cve.org/CVERecord?id=CVE-2025-8088) | WinRAR | ok / PUBLISHED | 8.4 / v4.0 | Yes; 2025-08-12 | CWE-35 |
| [CVE-2026-0257](https://www.cve.org/CVERecord?id=CVE-2026-0257) | Cloud NGFW; PAN-OS (+1 more) | ok / PUBLISHED | 7.8 / v4.0 | Yes; 2026-05-29 | CWE-565 |
| [CVE-2026-101258](https://www.cve.org/CVERecord?id=CVE-2026-101258) | Red Hat Enterprise Linux 10; Red Hat Enterprise Linux 8 (+3 more) | ok / PUBLISHED | 7.8 / v3.1 | Not supplied | CWE-787 |
| [CVE-2026-101809](https://www.cve.org/CVERecord?id=CVE-2026-101809) | Workflow | ok / PUBLISHED | 10 / v3.1 | Not supplied | Not supplied |
| [CVE-2026-102764](https://www.cve.org/CVERecord?id=CVE-2026-102764) | Remote Support | ok / PUBLISHED | 9.3 / v4.0 | Yes; 2026-10-16 | CWE-290 |
| [CVE-2026-103226](https://www.cve.org/CVERecord?id=CVE-2026-103226) | Ghostscript | ok / PUBLISHED | 5.3 / v4.0 | Not supplied | CWE-121, CWE-119 |
| [CVE-2026-103262](https://www.cve.org/CVERecord?id=CVE-2026-103262) | tornado | ok / PUBLISHED | 8.7 / v4.0 | Not supplied | CWE-409 |
| [CVE-2026-103263](https://www.cve.org/CVERecord?id=CVE-2026-103263) | tornado | ok / PUBLISHED | 8.2 / v4.0 | Not supplied | CWE-59 |
| [CVE-2026-104935](https://www.cve.org/CVERecord?id=CVE-2026-104935) | Connect Secure | ok / PUBLISHED | 8.6 / v3.1 | Yes; 2026-10-13 | CWE-290 |
| [CVE-2026-105481](https://www.cve.org/CVERecord?id=CVE-2026-105481) | node | ok / PUBLISHED | 6.5 / v3.0 | Not supplied | CWE-367 |
| [CVE-2026-105482](https://www.cve.org/CVERecord?id=CVE-2026-105482) | node | ok / PUBLISHED | 7.4 / v3.0 | Not supplied | CWE-284 |
| [CVE-2026-105483](https://www.cve.org/CVERecord?id=CVE-2026-105483) | node | ok / PUBLISHED | 7.4 / v3.0 | Not supplied | CWE-295 |
| [CVE-2026-106069](https://www.cve.org/CVERecord?id=CVE-2026-106069) | node | ok / PUBLISHED | 7.4 / v3.0 | Not supplied | CWE-295 |
| [CVE-2026-106070](https://www.cve.org/CVERecord?id=CVE-2026-106070) | node | ok / PUBLISHED | 3.7 / v3.0 | Not supplied | CWE-840 |
| [CVE-2026-106071](https://www.cve.org/CVERecord?id=CVE-2026-106071) | node | ok / PUBLISHED | 3.6 / v3.0 | Not supplied | CWE-284 |
| [CVE-2026-106072](https://www.cve.org/CVERecord?id=CVE-2026-106072) | node | ok / PUBLISHED | 6.7 / v3.0 | Not supplied | CWE-295 |
| [CVE-2026-106073](https://www.cve.org/CVERecord?id=CVE-2026-106073) | node | ok / PUBLISHED | 3.3 / v3.0 | Not supplied | CWE-284 |
| [CVE-2026-106074](https://www.cve.org/CVERecord?id=CVE-2026-106074) | node | ok / PUBLISHED | 4.8 / v3.0 | Not supplied | CWE-330 |
| [CVE-2026-106173](https://www.cve.org/CVERecord?id=CVE-2026-106173) | FortiSIEM | ok / PUBLISHED | 9.4 / v3.1 | Not supplied | CWE-22 |
| [CVE-2026-106931](https://www.cve.org/CVERecord?id=CVE-2026-106931) | SiteGuard Server Edition for Apache httpd; SiteGuard Server Edition for Nginx (+3 more) | ok / PUBLISHED | 8.5 / v4.0 | Yes; 2026-10-20 | CWE-78 |
| [CVE-2026-109125](https://www.cve.org/CVERecord?id=CVE-2026-109125) | Unbound | ok / PUBLISHED | 5.3 / v3.1 | Not supplied | CWE-205 |
| [CVE-2026-10961](https://www.cve.org/CVERecord?id=CVE-2026-10961) | Chrome | ok / PUBLISHED | Not supplied | Not supplied | CWE-416 |
| [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618) | PHP | ok / PUBLISHED | 9.2 / v4.0 | Not supplied | CWE-416, CWE-755, CWE-824, CWE-1325, CWE-1419 |
| [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619) | PHP | ok / PUBLISHED | 9.2 / v4.0 | Not supplied | CWE-416, CWE-755, CWE-824, CWE-1325, CWE-1419 |
| [CVE-2026-110264](https://www.cve.org/CVERecord?id=CVE-2026-110264) | GitLab | ok / PUBLISHED | 10 / v3.1 | Not supplied | CWE-190 |
| [CVE-2026-110447](https://www.cve.org/CVERecord?id=CVE-2026-110447) | Collabora Online - Built-in CODE Server | ok / PUBLISHED | 9.2 / v4.0 | Yes; 2026-10-23 | CWE-78 |
| [CVE-2026-110936](https://www.cve.org/CVERecord?id=CVE-2026-110936) | Siemens Software Center | ok / PUBLISHED | 8.4 / v4.0 | Yes; 2026-10-20 | CWE-427 |
| [CVE-2026-111497](https://www.cve.org/CVERecord?id=CVE-2026-111497) | Brotli | ok / PUBLISHED | 9.2 / v4.0 | Not supplied | CWE-787, CWE-252 |
| [CVE-2026-111943](https://www.cve.org/CVERecord?id=CVE-2026-111943) | crypto/x509 | ok / PUBLISHED | Not supplied | Not supplied | Not supplied |
| [CVE-2026-111944](https://www.cve.org/CVERecord?id=CVE-2026-111944) | Not supplied | failed / UNKNOWN | Not supplied | Not supplied | Not supplied |
| [CVE-2026-112380](https://www.cve.org/CVERecord?id=CVE-2026-112380) | Kiro Crew | ok / PUBLISHED | 9 / v4.0 | Not supplied | CWE-862, CWE-863 |
| [CVE-2026-112407](https://www.cve.org/CVERecord?id=CVE-2026-112407) | CICD-toolchain-for-serverless-applications | ok / PUBLISHED | 8.7 / v4.0 | Not supplied | CWE-266 |
| [CVE-2026-112408](https://www.cve.org/CVERecord?id=CVE-2026-112408) | Amazon SageMaker Python SDK | ok / PUBLISHED | 9.4 / v4.0 | Not supplied | CWE-940 |
| [CVE-2026-112900](https://www.cve.org/CVERecord?id=CVE-2026-112900) | Pillow | ok / PUBLISHED | 9.2 / v4.0 | Not supplied | CWE-78, CWE-88 |
| [CVE-2026-113380](https://www.cve.org/CVERecord?id=CVE-2026-113380) | RingRTC | ok / PUBLISHED | 9.3 / v4.0 | Not supplied | CWE-754 |
| [CVE-2026-114625](https://www.cve.org/CVERecord?id=CVE-2026-114625) | VeloCloud Orchestrator | ok / PUBLISHED | 9.4 / v4.0 | Yes; 2026-10-23 | CWE-89 |
| [CVE-2026-115414](https://www.cve.org/CVERecord?id=CVE-2026-115414) | aws-sam-cli | ok / PUBLISHED | 8.4 / v4.0 | Not supplied | CWE-78 |
| [CVE-2026-115416](https://www.cve.org/CVERecord?id=CVE-2026-115416) | Amazon Athena | ok / PUBLISHED | 6.3 / v4.0 | Not supplied | CWE-863, CWE-653 |
| [CVE-2026-115417](https://www.cve.org/CVERecord?id=CVE-2026-115417) | aws-c-mqtt | ok / PUBLISHED | 8.2 / v4.0 | Not supplied | CWE-789 |
| [CVE-2026-115419](https://www.cve.org/CVERecord?id=CVE-2026-115419) | strands-agents; strands-agents/sdk | ok / PUBLISHED | 8.6 / v4.0 | Not supplied | CWE-488 |
| [CVE-2026-115560](https://www.cve.org/CVERecord?id=CVE-2026-115560) | Not supplied | failed / UNKNOWN | Not supplied | Not supplied | Not supplied |
| [CVE-2026-115812](https://www.cve.org/CVERecord?id=CVE-2026-115812) | multi-model-server | ok / PUBLISHED | 9.3 / v4.0 | Not supplied | CWE-23 |
| [CVE-2026-115813](https://www.cve.org/CVERecord?id=CVE-2026-115813) | multi-model-server | ok / PUBLISHED | 6.9 / v4.0 | Not supplied | CWE-918 |
| [CVE-2026-115845](https://www.cve.org/CVERecord?id=CVE-2026-115845) | AWS MCP Server | ok / PUBLISHED | 5.3 / v4.0 | Not supplied | CWE-184 |
| [CVE-2026-15176](https://www.cve.org/CVERecord?id=CVE-2026-15176) | NGINX Plus; NGINX Open Source | ok / PUBLISHED | 9.2 / v4.0 | Not supplied | CWE-122 |
| [CVE-2026-15723](https://www.cve.org/CVERecord?id=CVE-2026-15723) | GitLab | ok / PUBLISHED | 8.2 / v3.1 | Not supplied | CWE-90 |
| [CVE-2026-18061](https://www.cve.org/CVERecord?id=CVE-2026-18061) | AWS Advanced JDBC Wrapper | ok / PUBLISHED | 6 / v4.0 | Not supplied | CWE-611 |
| [CVE-2026-19630](https://www.cve.org/CVERecord?id=CVE-2026-19630) | BIND 9 | ok / PUBLISHED | 7.5 / v3.1 | Not supplied | CWE-407 |
| [CVE-2026-20896](https://www.cve.org/CVERecord?id=CVE-2026-20896) | Gitea Open Source Git Server | ok / PUBLISHED | 9.8 / v3.1 | Not supplied | CWE-284 |
| [CVE-2026-23631](https://www.cve.org/CVERecord?id=CVE-2026-23631) | redis | ok / PUBLISHED | 6.1 / v4.0 | Not supplied | CWE-416 |
| [CVE-2026-25243](https://www.cve.org/CVERecord?id=CVE-2026-25243) | redis | ok / PUBLISHED | 7.7 / v4.0 | Not supplied | CWE-122 |
| [CVE-2026-25588](https://www.cve.org/CVERecord?id=CVE-2026-25588) | RedisTimeSeries | ok / PUBLISHED | 7.7 / v4.0 | Not supplied | CWE-122 |
| [CVE-2026-28328](https://www.cve.org/CVERecord?id=CVE-2026-28328) | SolarWinds Observability Self-Hosted | ok / PUBLISHED | 8.8 / v3.1 | Not supplied | CWE-863 |
| [CVE-2026-30612](https://www.cve.org/CVERecord?id=CVE-2026-30612) | n/a | ok / PUBLISHED | Not supplied | Not supplied | Not supplied |
| [CVE-2026-33825](https://www.cve.org/CVERecord?id=CVE-2026-33825) | Microsoft Defender Antimalware Platform | ok / PUBLISHED | 7.8 / v3.1 | Yes; 2026-04-22 | CWE-1220 |
| [CVE-2026-35029](https://www.cve.org/CVERecord?id=CVE-2026-35029) | litellm | ok / PUBLISHED | 8.7 / v4.0 | Not supplied | CWE-863 |
| [CVE-2026-35501](https://www.cve.org/CVERecord?id=CVE-2026-35501) | Unbound | ok / PUBLISHED | 3.7 / v3.1 | Not supplied | CWE-354 |
| [CVE-2026-4271](https://www.cve.org/CVERecord?id=CVE-2026-4271) | Red Hat Enterprise Linux 10; Red Hat Enterprise Linux 10.0 Extended Update Support (+3 more) | ok / PUBLISHED | 5.3 / v3.1 | Not supplied | CWE-416 |
| [CVE-2026-4272](https://www.cve.org/CVERecord?id=CVE-2026-4272) | Barcode Scanners | ok / PUBLISHED | 8.1 / v3.1 | Not supplied | CWE-306 |
| [CVE-2026-50106](https://www.cve.org/CVERecord?id=CVE-2026-50106) | Unbound | ok / PUBLISHED | 6.5 / v3.1 | Not supplied | CWE-807 |
| [CVE-2026-5119](https://www.cve.org/CVERecord?id=CVE-2026-5119) | Red Hat Enterprise Linux 10; Red Hat Enterprise Linux 10.0 Extended Update Support (+2 more) | ok / PUBLISHED | 5.9 / v3.1 | Not supplied | CWE-319 |
| [CVE-2026-59823](https://www.cve.org/CVERecord?id=CVE-2026-59823) | litellm | ok / PUBLISHED | 5.3 / v4.0 | Not supplied | CWE-918 |
| [CVE-2026-60004](https://www.cve.org/CVERecord?id=CVE-2026-60004) | Gitea | ok / PUBLISHED | 9.8 / v3.1 | Yes; 2026-08-25 | CWE-94 |
| [CVE-2026-6324](https://www.cve.org/CVERecord?id=CVE-2026-6324) | Red Hat Enterprise Linux 10; Red Hat Enterprise Linux 6 (+3 more) | ok / PUBLISHED | 4.8 / v3.1 | Not supplied | CWE-444 |
| [CVE-2026-66339](https://www.cve.org/CVERecord?id=CVE-2026-66339) | Red Hat Enterprise Linux 10; Red Hat Enterprise Linux 6 (+3 more) | ok / PUBLISHED | 6.5 / v3.1 | Not supplied | CWE-201 |
| [CVE-2026-69184](https://www.cve.org/CVERecord?id=CVE-2026-69184) | c-ares | ok / PUBLISHED | 7.5 / v3.1 | Not supplied | CWE-407 |
| [CVE-2026-69186](https://www.cve.org/CVERecord?id=CVE-2026-69186) | c-ares | ok / PUBLISHED | 5.3 / v3.1 | Not supplied | CWE-400 |
| [CVE-2026-70774](https://www.cve.org/CVERecord?id=CVE-2026-70774) | Oracle Warehouse Management | ok / PUBLISHED | 7.1 / v3.1 | Not supplied | Not supplied |
| [CVE-2026-74220](https://www.cve.org/CVERecord?id=CVE-2026-74220) | u-boot | ok / PUBLISHED | 8.8 / v4.0 | Not supplied | CWE-195 |
| [CVE-2026-74221](https://www.cve.org/CVERecord?id=CVE-2026-74221) | u-boot | ok / PUBLISHED | 8.8 / v4.0 | Not supplied | CWE-195 |
| [CVE-2026-74222](https://www.cve.org/CVERecord?id=CVE-2026-74222) | u-boot | ok / PUBLISHED | 8.8 / v4.0 | Not supplied | CWE-416 |
| [CVE-2026-74225](https://www.cve.org/CVERecord?id=CVE-2026-74225) | u-boot | ok / PUBLISHED | 7.1 / v4.0 | Not supplied | CWE-787 |
| [CVE-2026-77014](https://www.cve.org/CVERecord?id=CVE-2026-77014) | Red Hat Enterprise Linux 10; Red Hat Enterprise Linux 6 (+2 more) | ok / PUBLISHED | 5.3 / v3.1 | Not supplied | CWE-197 |
| [CVE-2026-77680](https://www.cve.org/CVERecord?id=CVE-2026-77680) | Red Hat Enterprise Linux 10 | ok / PUBLISHED | 5.3 / v3.1 | Not supplied | CWE-407 |
| [CVE-2026-84942](https://www.cve.org/CVERecord?id=CVE-2026-84942) | Amazon OpenSearch Service; OpenSearch Dashboards | ok / PUBLISHED | 6.3 / v4.0 | Not supplied | CWE-79 |
| [CVE-2026-85197](https://www.cve.org/CVERecord?id=CVE-2026-85197) | Red Hat Enterprise Linux 10; Red Hat Enterprise Linux 10.0 Extended Update Support (+4 more) | ok / PUBLISHED | 7.6 / v3.1 | Not supplied | CWE-416 |
| [CVE-2026-85228](https://www.cve.org/CVERecord?id=CVE-2026-85228) | Deep Java Library | ok / PUBLISHED | 8.8 / v4.0 | Not supplied | CWE-190 |
| [CVE-2026-85534](https://www.cve.org/CVERecord?id=CVE-2026-85534) | Red Hat Enterprise Linux 10; Red Hat Enterprise Linux 6 (+3 more) | ok / PUBLISHED | 5.9 / v3.1 | Not supplied | CWE-617 |
| [CVE-2026-85706](https://www.cve.org/CVERecord?id=CVE-2026-85706) | GitLab | ok / PUBLISHED | 10 / v3.1 | Yes; 2026-09-11 | CWE-22 |
| [CVE-2026-85787](https://www.cve.org/CVERecord?id=CVE-2026-85787) | postgres-mcp-server | ok / PUBLISHED | 7.1 / v4.0 | Not supplied | CWE-184 |
| [CVE-2026-85788](https://www.cve.org/CVERecord?id=CVE-2026-85788) | AWS Labs MySQL MCP Server | ok / PUBLISHED | 5.7 / v4.0 | Not supplied | CWE-184 |
| [CVE-2026-87337](https://www.cve.org/CVERecord?id=CVE-2026-87337) | Oracle Access Manager | ok / PUBLISHED | 10 / v3.1 | Not supplied | Not supplied |
| [CVE-2026-87911](https://www.cve.org/CVERecord?id=CVE-2026-87911) | AWS Labs postgres MCP Server | ok / PUBLISHED | 9 / v4.0 | Not supplied | CWE-78, CWE-184 |
| [CVE-2026-87912](https://www.cve.org/CVERecord?id=CVE-2026-87912) | AWS Security Agent plugin | ok / PUBLISHED | 5.1 / v4.0 | Not supplied | CWE-283, CWE-341 |
| [CVE-2026-87913](https://www.cve.org/CVERecord?id=CVE-2026-87913) | AWS Security Agent MCP server | ok / PUBLISHED | 5.1 / v4.0 | Not supplied | CWE-283, CWE-341 |
| [CVE-2026-88771](https://www.cve.org/CVERecord?id=CVE-2026-88771) | ADC; Gateway | ok / PUBLISHED | 9.5 / v4.0 | Yes; 2026-09-27 | CWE-20 |
| [CVE-2026-88772](https://www.cve.org/CVERecord?id=CVE-2026-88772) | ADC; Gateway | ok / PUBLISHED | 9.5 / v4.0 | Yes; 2026-09-27 | Not supplied |
| [CVE-2026-89049](https://www.cve.org/CVERecord?id=CVE-2026-89049) | Amazon SSM Agent | ok / PUBLISHED | 8.5 / v4.0 | Not supplied | CWE-918, CWE-1289 |
| [CVE-2026-89065](https://www.cve.org/CVERecord?id=CVE-2026-89065) | projen | ok / PUBLISHED | 6.8 / v4.0 | Not supplied | CWE-23 |
| [CVE-2026-89066](https://www.cve.org/CVERecord?id=CVE-2026-89066) | projen | ok / PUBLISHED | 8.4 / v4.0 | Not supplied | CWE-78, CWE-88 |
| [CVE-2026-89090](https://www.cve.org/CVERecord?id=CVE-2026-89090) | AWS SDK for Go v2 | ok / PUBLISHED | 8.2 / v4.0 | Not supplied | CWE-248 |
| [CVE-2026-91216](https://www.cve.org/CVERecord?id=CVE-2026-91216) | Oracle SOA Suite | ok / PUBLISHED | 10 / v3.1 | Not supplied | Not supplied |
| [CVE-2026-91221](https://www.cve.org/CVERecord?id=CVE-2026-91221) | Oracle SOA Suite | ok / PUBLISHED | 10 / v3.1 | Not supplied | Not supplied |
| [CVE-2026-91231](https://www.cve.org/CVERecord?id=CVE-2026-91231) | Oracle SOA Suite | ok / PUBLISHED | 10 / v3.1 | Not supplied | Not supplied |
| [CVE-2026-91299](https://www.cve.org/CVERecord?id=CVE-2026-91299) | JD Edwards EnterpriseOne Orchestrator | ok / PUBLISHED | 10 / v3.1 | Not supplied | Not supplied |
| [CVE-2026-91990](https://www.cve.org/CVERecord?id=CVE-2026-91990) | tornado | ok / PUBLISHED | 8.7 / v4.0 | Not supplied | CWE-770 |
| [CVE-2026-91992](https://www.cve.org/CVERecord?id=CVE-2026-91992) | tornado | ok / PUBLISHED | 8.2 / v4.0 | Not supplied | CWE-200 |
| [CVE-2026-93479](https://www.cve.org/CVERecord?id=CVE-2026-93479) | NGINX Plus; NGINX Open Source | ok / PUBLISHED | 9.2 / v4.0 | Not supplied | CWE-122 |
| [CVE-2026-94300](https://www.cve.org/CVERecord?id=CVE-2026-94300) | BIND 9 | ok / PUBLISHED | 8.1 / v3.1 | Not supplied | CWE-415, CWE-362 |
| [CVE-2026-95101](https://www.cve.org/CVERecord?id=CVE-2026-95101) | NGINX Plus; NGINX Open Source | ok / PUBLISHED | 6.9 / v4.0 | Not supplied | CWE-172 |
| [CVE-2026-96405](https://www.cve.org/CVERecord?id=CVE-2026-96405) | Unbound | ok / PUBLISHED | 5.3 / v3.1 | Not supplied | CWE-770 |
| [CVE-2026-96652](https://www.cve.org/CVERecord?id=CVE-2026-96652) | Media Server | ok / PUBLISHED | 5.3 / v4.0 | Yes; 2026-10-20 | CWE-918 |
| [CVE-2026-96654](https://www.cve.org/CVERecord?id=CVE-2026-96654) | Media Server | ok / PUBLISHED | 6.9 / v4.0 | Yes; 2026-10-20 | CWE-84 |
| [CVE-2026-96655](https://www.cve.org/CVERecord?id=CVE-2026-96655) | Media Server | ok / PUBLISHED | 5.3 / v4.0 | Yes; 2026-10-20 | CWE-918 |
| [CVE-2026-96656](https://www.cve.org/CVERecord?id=CVE-2026-96656) | Media Server | ok / PUBLISHED | 8.6 / v4.0 | Yes; 2026-10-20 | CWE-73 |
| [CVE-2026-96888](https://www.cve.org/CVERecord?id=CVE-2026-96888) | BIND 9 | ok / PUBLISHED | 7.5 / v3.1 | Not supplied | CWE-476, CWE-617 |
| [CVE-2026-96951](https://www.cve.org/CVERecord?id=CVE-2026-96951) | Outlook.com; Windows 10 Version 1607 (+4 more) | ok / PUBLISHED | 8.8 / v3.1 | Yes; 2026-10-13 | CWE-77 |
| [CVE-2026-97205](https://www.cve.org/CVERecord?id=CVE-2026-97205) | NGINX Plus; NGINX Open Source | ok / PUBLISHED | 9.2 / v4.0 | Not supplied | CWE-416 |
| [CVE-2026-97206](https://www.cve.org/CVERecord?id=CVE-2026-97206) | Unbound | ok / PUBLISHED | 7.5 / v3.1 | Not supplied | CWE-416 |
| [CVE-2026-97229](https://www.cve.org/CVERecord?id=CVE-2026-97229) | GitLab | ok / PUBLISHED | 10 / v3.1 | Not supplied | CWE-190 |
| [CVE-2026-97313](https://www.cve.org/CVERecord?id=CVE-2026-97313) | BIND 9 | ok / PUBLISHED | 7.5 / v3.1 | Not supplied | CWE-617 |
| [CVE-2026-97406](https://www.cve.org/CVERecord?id=CVE-2026-97406) | Console API | ok / PUBLISHED | Not supplied | Not supplied | Not supplied |
| [CVE-2026-97629](https://www.cve.org/CVERecord?id=CVE-2026-97629) | NGINX Plus; NGINX Open Source | ok / PUBLISHED | 8.3 / v4.0 | Not supplied | CWE-908 |

## CWE and CAPEC context

110 of 127 main CVE contexts supply CWE IDs; 17 do not. One CVE may have several weakness IDs, so membership counts overlap. The retained catalog provides CWE 4.20 context where supplied. Qualified CAPEC 3.9 definitions are limited to 63, 66, 88, 115, 126 and 593; other retained names/mappings are not qualified definitions. A CNA weakness or taxonomy edge does not establish an observed exploit, attack pattern or actor.

![Captured CNA weakness context](charts/weakness-context.svg)

| Supplied CWE | Unique main CVE memberships |
| --- | --- |
| CWE-416 | 9 |
| CWE-78 | 7 |
| CWE-284 | 5 |
| CWE-918 | 5 |
| CWE-122 | 4 |
| CWE-184 | 4 |
| CWE-863 | 4 |
| CWE-190 | 3 |
| CWE-20 | 3 |
| CWE-295 | 3 |
| CWE-407 | 3 |
| CWE-444 | 3 |

Full membership and explicitly supplied taxonomy references are in data.json.

## Campaigns and actors

Microsoft’s dated account attributes ConnectWise-linked application abuse to Storm-0940. That is publisher attribution, not independent actor identity. The retained account describes compromised application credentials and qualified downstream activity; neither application presence nor authentication alone establishes universal compromise or data theft. The source was published October 21, updated October 23 and observed October 25; its event date is null. The observation clock is not an event or publication time. [Microsoft account](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/).

## Supply chain, AI and watchlist

- **[NCSC AI research agenda](https://www.ncsc.gov.uk/blogs/introducing-new-ai-chapter-ncsc-research-problem-book)** — source-declared publication 2026-10-20T12:00:00+00:00. Research priorities are source context, not a report of a newly observed incident.

- **[AI-assisted coding quality tooling](https://www.helpnetsecurity.com/2026/10/26/google-elephant-goldfish-model-plugin/)** — source-declared publication 2026-10-26T04:25:59+00:00. A publication lead only; functionality, efficacy and security assurances were not independently checked.

- **[Splunk SOAR dependency-update advisory entry](https://advisory.splunk.com/advisories/SVD-2026-1012)** — source-declared publication 2026-10-21T00:00:00+00:00. No CVE identifiers are supplied by this row; do not infer the advisory’s complete vulnerability inventory.

**Next nominal opportunity: 26 October 2026 at 14:00 America/Chicago / 19:00 UTC.** This is a planned opportunity, not a completed check or an automatic request. Missing CNA guidance, source gaps and the prior held AWS route remain review items.

## Prior-source revision review

The shared 11:00 UTC metadata pass covers **462 citation occurrences**, **378 canonical URLs** and 12 prior reports. **377** histories remain unknown and **1** prior route remains held. It selected 0 sources, made **0 new requests**, and completed **0 qualified checks / 0 comparisons**. Material change is null, not a finding of no change. Unknown, held and not selected do not mean updated or unchanged. The held URI is not automatically followed or checked. This later pass is retrospective revision context for the 05:00 UTC closing period, not an as-of-close review.

## Coverage and limitations

The saved input contains 3817 article/catalog rows, 2180 CNA contexts and 62 sources. 60 rows have no primary date and 3196 are outside this period; neither raw list is published here. Source health in data.json uses only the eight approved public fields and may represent retained last-good input. This selection includes 103 Red Hat advisory rows; absent CVE metadata is not a claim that their advisories contain no CVEs. The main row count is independent of how many safe links remain.

![Selected rows by source](charts/publisher-intake.svg)

- Publication clocks drive inclusion; event dates are context only.
- The source graph counts main declared-time/calendar rows, not publisher intake, requests, incident volume or completeness.
- Failed/UNKNOWN CNA enrichment, absent CVSS and null guidance stay unknown. Product conditions and supplier backports control applicability.
- Catalog addition dates and current KEV context are different from disclosure/exploitation times or environment exposure.
- Source claims, versions, confidence and dates stay attributed. No publisher body, device, patch or control efficacy was newly checked for this report.
- Overlapping periods and multi-CWE/CVE memberships must not be summed.
- Unsafe links and raw/private titles are omitted or replaced by neutral labels without changing date/CVE membership.

## Sources, primary first

Official CVE links appear in the complete context index above. The retained dated context and original-source references include:

- [Retained source 1](https://www.cve.org/CVERecord?id=CVE-2026-109618)
- [Retained source 2](https://www.php.net/archive/2026.php)
- [Retained source 3](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [Retained source 4](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Retained source 5](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
- [Retained source 6](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-106931)
- [Retained source 7](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-110447)
- [Retained source 8](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-114625)
- [Retained source 9](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-293a)
- [Retained source 10](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/)

The source classification identifies an original reference, not a new whole-document observation. The full deduplicated citation list and all main CVE context are in [data.json](data.json).

Prior edition: **SW-WEEKLY-2026-W43**. The legacy W43 report keeps its original date precision; this is a separate closing edition.
