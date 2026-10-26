# Reporting schedule and evidence method

Intelligence Hub publishes selective threat-intelligence editions for analysis over time. Each edition has an immutable report ID, a narrative, a matching data file, actual-data charts, source references and explicit coverage limits. A report is a source-supported analysis, not a device assessment or an exhaustive incident census.

## Requested editions

All publication slots use **America/Chicago**, including daylight-saving transitions. The recorded activation state is in [reporting.json](reporting.json); the Hub displays the next nominal opportunity and actual saved outcomes separately.

| Edition | Covered period | Publication opportunity |
| --- | --- | --- |
| Daily | Previous 24 elapsed hours on weekdays; 48 elapsed hours on Saturday and Sunday | Every day at 06:00, 14:00 and 22:00 |
| Weekly | Previous Monday 00:00 through Monday 00:00 | Monday 06:00 |
| Weekend | Previous Saturday 00:00 through Monday 00:00 | Monday 06:00 |
| Fortnightly | Consecutive 14-calendar-day windows, anchored October 19, 2026 | Every second Monday 06:00; first close November 2, 2026 |
| Monthly | Previous completed calendar month | First day of the next month, 06:00 |
| Quarterly | Previous completed calendar quarter | January, April, July and October 1, 06:00 |
| Six-month | Latest six completed calendar months | Monthly at the same calendar close; initial April–September 2026 |

Windows are half-open: the start is included and the end is excluded. Daily lookbacks subtract elapsed hours from the intended slot's UTC instant. Calendar periods retain zoned boundaries; a daylight-saving weekend can contain 47 or 49 elapsed hours. Intended slot, UTC offset, actual execution, source publication/update/event, retrieval, compilation and publication clocks remain separate.

The three daily opportunities also handle any periodic editions due at that point. Overlapping daily windows are intentional. A delayed run processes the latest due unpublished slot without an unlimited historical catch-up burst. A partially completed edition resumes with its original identity and frozen inputs; this does not permit retrying a refused or uncertain source request. Existing report files remain immutable. Corrections and calendar-closing editions use new IDs and link their predecessors.

## 2026 retrospective editions

January–September reports summarize the available retained source subset. October is a dated month-to-date edition until the month closes. November and December remain future plans with no invented metrics, stories or source clocks. The initial rolling six-month edition covers April 1 through October 1 in Chicago.

Retrospective compilation does not recreate what was known at the historical cutoff. A current CNA record or mitigation shown beside an older article is labeled as later retained context. Missing source dates are unassigned; a source failure or empty subset is not evidence that nothing happened.

## What each report contains

- Executive summary and selected notable developments, without a forced story count.
- Distinct article, unique-CVE and KEV-addition measures. A KEV addition date is not an incident, disclosure or first-exploitation date.
- Source-reported affected products, version/configuration conditions, available fixes or mitigations, and unresolved applicability.
- CNA-provided CWE identifiers and qualified official CWE-to-CAPEC taxonomy where available. Taxonomy does not establish an observed attack.
- Separately sourced actor/campaign attribution, with uncertainty and conflicting claims retained. Names, aliases and co-mentions alone do not establish identity or participation.
- A watchlist, source/revision outcomes, limitations and references. Sections without qualifying evidence say so.
- Charts generated from the edition's data file, with units, denominators, dates and missingness. Changes in intake or taxonomy are not presented as threat growth.

CVE, CWE, CAPEC, actors and mitigations remain different evidence types. A headline does not automatically identify a CVE, prove exploitation or establish an installed system's exposure. CVSS retains its source and metric version and is not converted into a local risk score.

## Previous-source changes: 48–96 hours

The dedicated revision pass considers public URLs cited by reports compiled in the preceding 96 elapsed hours, prioritizing the most recent 48 hours. The article itself may be older. Each edition selects at most 12 distinct URLs: up to eight recent citations and four older citations, with deterministic spillover and oldest-attempt rotation. This shares a ceiling of 24 primary documents with the edition's other research.

A successful source is eligible no sooner than eight elapsed hours after its last attempt; a failed source waits at least 24 hours. A blocked or refused source is deactivated until separately reviewed. An exclusive URL-and-edition intent precedes each request. An uncertain attempt is not replayed. Complete responses are bounded to 3 MiB, without redirects, retries, authentication, access bypass or executing source content.

The public revision ledger distinguishes qualified security-field changes, timestamp-only observations, raw-response changes without semantic qualification, unchanged supported content, no baseline, not comparable, refused, failed and not checked. Hash changes alone do not establish corrected claims. Comparisons require compatible extraction versions and a qualified prior field baseline. A projection upgrade on identical source bytes is not a publisher update. Selection, attempts, complete/comparable reads, changes, unresolved outcomes and cap exclusions remain visible.

The saved ledger explicitly reports **not run** before the first dedicated pass. Ordinary feed/CNA refreshes do not prove that every earlier article was checked. Raw bodies, request intents and private proofs are excluded from public Git content; public summaries contain only qualified paraphrases and safe provenance.

## Four different next times

The Hub distinguishes the next report/revision cycle, each URL's earliest eligibility, the requested ten-minute feed collection and the browser's next saved-snapshot check. These are opportunities, not delivery guarantees. A successful unchanged feed run need not publish a new snapshot. A report may be published in the GitHub report archive before a later saved Hub snapshot links it.

Scheduled local reporting requires the computer to be available and the app to be open. The public feed and Pages workflow are separate. A source, capacity or publication failure preserves the previous accepted output and records the failure; limits are not raised to force a release. The existing 1,200,000-byte compressed artifact estimate and one-day retention remain unchanged.
