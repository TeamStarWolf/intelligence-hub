# CVE guidance and mitigation evidence

## What a brief represents

The collector writes a **schema 4** snapshot. The site still reads schemas 2, 3
and 4. Each of those snapshots has one `mitigations` entry for each unique CVE
in its loaded articles' `cves` arrays, including KEV, feed and curated articles.
This is not every CVE ever published, nor every identifier in full linked articles.
The projection is deterministic; it makes no model call or device assessment.

## Two separate evidence sources

- **CNA facts** come from the CNA container in the [CVE Program's public records](https://github.com/CVEProject/cvelistV5). A validated identifier selects a fixed record path; the returned identity and publication/rejection state must match.
- **CISA evidence** comes from the [Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Its required action, catalog-added date, federal due date and ransomware-use field stay separately attributed.
- CISA descriptions, product names and references are not used to fill missing CNA source fields. KEV articles retain their own CISA description and attribution.
- Linked vendor advisories are references, not pages automatically fetched or independent confirmation that a solution was reviewed.

A missing CNA record does not remove an available CISA action. Conversely, absence
from the loaded KEV input does not establish absence of exploitation. A CVE mentioned
by an article is not proof that every event in that article exploited it.

## Bounded CNA projection

The implementation reads structured fields, not an entire advisory as instructions:

| Field | Current selection limit |
| --- | --- |
| Description or rejection explanation | First English value, up to 600 characters |
| Solutions and workarounds | Up to two English excerpts of each kind, up to 600 characters each |
| Affected products | First six entries |
| Version statements per product | First twelve, retaining status, bounds and version type |
| References | Official record link plus up to fifteen accepted CNA references |
| CVSS | First supplied valid metric at the highest available supported metric version |

Version text/bounds are bounded to 160 characters each; version status and type are
also bounded. These excerpts can omit additional products, conditions and guidance.
Affected, unaffected and unknown statuses remain distinct. An affected range is
**not** a claimed fixed version; the original record and vendor advisory control.

CVSS preference is **4.0, then 3.1, 3.0 and 2.0**, checking a bounded metric list.
The displayed score, version, vector and source stay together. The choice is not
the highest score across every product, a normalized cross-version comparison,
or an organization-specific risk ranking. Missing metrics stay unknown.

## Guidance state is separate from lookup state

| Guidance label | Meaning |
| --- | --- |
| Publisher guidance | Structured CNA solutions or workarounds were loaded; read the attributed excerpts and original guidance. |
| CISA action | A catalog required action is available even if no structured CNA fix was loaded. |
| Needs review | Neither input establishes the displayed solution/workaround, or the CVE is rejected. No fix is invented. |

CNA lookup states **pending**, **ok** and **failed** describe retrieval, not whether
guidance exists or a device is vulnerable. A vendor-advisory link alone does not
promote a brief to Publisher guidance. A **REJECTED** record always needs review:
reconcile its explanation and any replacement identifier before applying older
claims. The checklist asks for reconciliation before selecting remediation.

CISA's due date is catalog/federal-directive evidence, **not a deadline assigned to
this site's visitors**. An unknown ransomware-use field does not mean no ransomware.

## Dates, hashes and retained history

- `source_updated_at` is the CVE metadata's update time when supplied.
- `retrieved_at` records completion of a successful record retrieval.
- `source_attempted_at` records the latest retained request's start; `source_status` records its result.
- `source_sha256` identifies the received JSON bytes behind the retained successful CNA facts. It is not a publisher signature, proof of correctness or an installed-software hash.
- Snapshot generation, article publication, incident and KEV-added dates have separate meanings.

Validated retained inputs are merged per CVE: the newest successful CNA fact
whitelist is chosen by retrieval time, while the latest attempt and its status are
chosen separately. A later failure can therefore accompany older successful facts,
their original retrieval time and byte hash. Missing facts remain missing; a new
snapshot does not make every record freshly retrieved.

The workflow's `--resume-public` uses only this hub's fixed validated public
snapshot. An unavailable or invalid bootstrap stops that run before publication.
It is not an arbitrary URL import. Daily caches and published snapshots are bounded,
incomplete history inputs; see [operations](OPERATIONS.md) for retention limits.

## Progressive enrichment and action boundaries

The default and scheduled/manual workflow budget is **40 official record requests
per run**, with up to four workers. Push-triggered publication allows up to
**2,000** to initialize or catch up the public record set. `--enrich-limit 0`
disables additional CNA lookups; cached rebuilding makes none. The projection set
is bounded to 15,000 CVEs.

Never-retrieved records and older eligible attempts progress first. Ties retain
descending CVE-identifier ordering, including identifier years; this is **not
severity prioritization**. Eligibility uses retained attempt times: 24 hours for
successful records and one hour for failed lookups. Skipped publications and
immutable caches can lose newer attempt clocks, so this is not a durable cooldown
ledger or a guarantee that all records become enriched.

Check exact installed products, versions and conditions before any separately
authorized remediation. Confirm the resulting version/configuration afterwards
and preserve evidence. The hub neither patches nor verifies a device, executes
the checklist, or proves that prior compromise was removed. All fetched text stays
untrusted data; current vendor guidance and applicability review remain necessary.
