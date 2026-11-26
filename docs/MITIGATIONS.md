# CVE guidance and mitigation evidence

## What a brief represents

The collector writes a **schema 7** snapshot. The site reads schemas 2 to 7. Each
of those snapshots has one brief for each unique CVE in its loaded articles'
`cves` arrays, including KEV, feed and curated articles. Schemas 2 to 6 carry the
briefs inline under `mitigations`. Schema 7 keeps them in `data/briefs.json` and
puts one compact row per CVE in the feed's `brief_index`; the site reads the
briefs file the first time a reader opens a brief, opens the CVE register or
searches, since CNA titles and vendor and product names are only in that file.
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
| References | Official record link plus up to fifteen accepted CNA references, each classified `record`, `vendor-guidance` or `exploit` |
| CVSS | First supplied valid metric at the highest available supported metric version |
| CNA weaknesses (schemas 5/6) | Explicit `cna.problemTypes[].descriptions[].cweId` only; at most twenty types, twenty descriptions per type and eight unique canonical CWE IDs |

Version text/bounds are bounded to 160 characters each; version status and type are
also bounded. These excerpts can omit additional products, conditions and guidance.
Affected, unaffected and unknown statuses remain distinct. An affected range is
**not** a claimed fixed version; the original record and vendor advisory control.

CVSS preference is **4.0, then 3.1, 3.0 and 2.0**, checking a bounded metric list.
The displayed score, version, vector and source stay together. The choice is not
the highest score across every product, a normalized cross-version comparison,
or an organization-specific risk ranking. Missing metrics stay unknown.

## Bounded CISA ADP projection

The same CVE record carries ADP containers beside the CNA's. The collector reads one
of them: CISA's, whose `providerMetadata.shortName` is `CISA-ADP`. No other ADP
container is read, and no new source is fetched; the data is in the record the
collector already retrieves. Each brief carries an `adp` block (`provider`, `date`,
`ssvc`, `cvss`) and an `adp_status`:

| Field | Current selection limit |
| --- | --- |
| Containers | The first ten ADP containers are inspected for CISA's |
| Metrics | The first forty metric entries of CISA's container are inspected and at most two are read: the first `other.type == "ssvc"` metric and the first valid CVSS metric at the highest supported version (4.0, then 3.1, 3.0 and 2.0) |
| SSVC decision points | The first ten `content.options` entries; Exploitation, Automatable and Technical Impact are kept, each up to 40 characters, with the SSVC timestamp |
| ADP CVSS | Version, score and vector (up to 250 characters), as CISA supplied them |
| Container date | `providerMetadata.dateUpdated`, normalized to UTC |

The `kev` metric in CISA's container is not read: KEV facts come from the catalog,
separately attributed. Option entries that are not one name with one text value are
skipped, never guessed. A malformed container list refuses that projection under the
existing last-good/failure policy.

`adp_status` has the semantics of `weaknesses_status`: `not_projected` means the
retained projection was made before this field existed; `not_supplied` means the fully
inspected record has no CISA ADP container; `supplied` means CISA's container was
projected, even when it carries neither an SSVC metric nor a CVSS metric. A successful
projection whose `adp_status` is `not_projected` becomes due for a real re-projection
within the existing 2,000-record push / 40-record scheduled budget, exactly as a missing
weakness pair does, so existing records gain their ADP data over the following runs
without a bigger budget.

The brief names the issuer of every value: the CNA's CVSS with its version, score and
vector; CISA's ADP CVSS where present; and CISA's SSVC values with their date. Nothing
is blended, averaged or ranked, the register's CVSS sort uses the CNA CVSS only, and
SSVC values appear as CISA's decision-point values, never as a priority label.
`cve-index.json` (brief index version 2) carries CISA's SSVC Exploitation value per
CVE as `ssvc_exploitation`, null when none; the feed published before this field, with
its version 1 index and briefs without the pair, stays a valid resume and archive input.

### Elsewhere links

The brief's Elsewhere row links the CVE on the CVE Program's site, NVD, the FIRST EPSS
API (its JSON answer) and Rapid7's vulnerability database. Every link is built from the
CVE id by a fixed pattern and passes the page's `safeUrl`; the Hub fetches none of those
pages, so a listed site says nothing about what it holds for that CVE. GreyNoise's
`/cve/` page pattern and Vulners did not answer a plain request for a real KEV CVE on
2026-11-12 and are not listed; AttackerKB was retired on 2026-08-18.

## EPSS by FIRST

Every brief carries an `epss` block, FIRST's Exploit Prediction Scoring System value for
the CVE: `score` (the estimated probability, 0 to 1, that the CVE is exploited in the next
30 days), `percentile` (its rank among every CVE FIRST scored that day), `date` (the score
date FIRST published it for) and `model` (the model version, for example `v2026.06.15`),
or null when FIRST had no score for the CVE on that date. The collector reads the API at
`api.first.org` once a run for the CVEs of the brief set, in sorted batches of 100
(`intelligence_hub/epss.py`), with a 256 KiB bound on each answer and at most 150 batches
a run. The daily CSV is not read: it is reached through a redirect and is gzip-encoded,
both of which the collector refuses.

| Rule | What it means |
| --- | --- |
| A missing score is no score | A CVE the API did not return reads as null, in the brief, the index and the exports; the page says "no EPSS score on that date" and never writes 0 |
| A failed read keeps the last good value | A batch that fails (a 429, a timeout, a malformed answer) leaves every CVE in it as it was, and the first failed batch ends the run's reads; the retained value travels in the retained projections and in the deployed briefs file, so a `--resume-public` run keeps it too |
| The model is named and pinned | The API carries no model version. `MODEL` in `epss.py` is the version the daily CSV header named on `MODEL_CONFIRMED`; a new model is a reviewed change of that constant, and a value keeps the model it was scored under |
| No change across a model boundary | The Hub shows each score as published for its date and model; it records no delta between runs and compares no two model versions |
| Attribution on every value | FIRST asks for attribution when EPSS data is used in publications or products; the register caption, the brief and the export dictionary name FIRST, the model and the score date |

`cve-index.json` (brief index version 3) carries the block per CVE as `epss`, after
`ssvc_exploitation`, and `index.json` records `epss_scored`, `epss_model` and `epss_date`
in its counts. The feeds published before this field, with their version 1 or version 2
index and briefs without the block, stay valid resume and archive inputs. The register's
EPSS column and sort, the brief's EPSS block and the Explorer's EPSS sort and chip read
these values; the exports carry `epss`, `epss_percentile`, `epss_date` and `epss_model`
per row (the highest score among the row's CVEs).

## Public exploit signal

The register, the Explorer and the brief mark a CVE from two sources, worded by what each
source actually says. The wording is deliberate: one source says exploit code is public, the
other says the CVE is being exploited, and those are not the same claim.

- **"Public exploit"** when the CVE record's CNA tagged a reference `exploit`, or CISA's SSVC
  Exploitation value is `poc`. The CVE Program reference taxonomy
  ([reference-tags.json](https://raw.githubusercontent.com/CVEProject/cve-schema/main/schema/tags/reference-tags.json))
  defines `exploit` as a reference with "an in-depth/detailed description of steps to exploit a
  vulnerability" or legitimate proof-of-concept code or an exploit kit. CERT/CC SSVC
  ([Exploitation ssvc:E:1.1.0](https://certcc.github.io/SSVC/reference/decision_points/exploitation/))
  defines `poc` as "One of the following is true: (1) Typical public PoC exists in sources such
  as Metasploit or websites like ExploitDB; or (2) the vulnerability has a well-known method of
  exploitation". Both the tag and `poc` say a public exploit exists.
- **"Exploited (CISA SSVC)"** when SSVC Exploitation is `active`, which CERT/CC defines as
  "Shared, observable, reliable evidence that the exploit is being used in the wild by real
  attackers; there is credible public reporting". That reports exploitation in the wild, not
  that exploit code is public, so it is never worded "Public exploit".

One filter ("Public exploit or exploited") covers both, because the CNA tag alone is sparse.
Measured on a full read of the 3,135 CVE records in one live brief set: 214 (6.8%) had a CNA
`exploit` tag, and of the 1,805 KEV CVEs only 198 (11%) did; the tagging CNAs are a mix of
vendor and researcher CNAs (mitre 53, microsoft 48, adobe 15, redhat 14, VulnCheck 13, and a
tail). CISA's SSVC marked 1,921 CVEs (60%) `poc` or `active` (poc 117, active 1,804); the CNA
tag added only 11 CVEs beyond those. So most of the indication rests on SSVC `active`, which
is why `active` carries the "Exploited" wording, not "Public exploit".

The collector classifies each CNA reference as `exploit`, `vendor-guidance` (a vendor
advisory, patch, mitigation or release note) or `record`; a reference tagged both ways is an
`exploit`. Only the CNA container is read for the tag: CISA's assessment is the SSVC value, so
reading the ADP container's references for the tag would double-count CISA. The CNA tag adds
no network read, no new source and no new bound; it is derived from the record the collector
already reads.

`poc`, stored on the brief and in `cve-index.json` (brief index version 4, after `epss`), is
the count of `exploit` references counted uncapped across every reference the record carries
(up to the 100 the collector reads), so a cap on the displayed references never hides one. The
displayed list keeps the official record plus up to fifteen CNA references, and always keeps
one `exploit` reference when any exist, so the count is backed by a visible link.

A projection made before the `poc` field carries no stored count. Such a record is read again
ahead of its 24-hour interval (as the weakness pair and the ADP block are), so the count is
filled from a fresh read rather than published as 0. Filling the whole live set is bounded by
the enrichment budget (up to 2,000 records on the build that follows a merge, then 40 per
scheduled run every two hours), so the count becomes complete over the first few days after
this ships; the 214-of-3,135 figure above is a full read, which the live site reaches after
that fill.

| Rule | What it means |
| --- | --- |
| It is not complete | CNAs tag references inconsistently, so no `exploit` tag is not a claim that no exploit exists; the SSVC value fills much of the gap but is itself CISA's assessment |
| Public exploit is not exploitation | A public exploit, or SSVC `poc`, is not evidence of exploitation in the wild; SSVC `active` and the KEV catalog are the signals for that, and a public exploit does not imply active exploitation |
| Exploited is not public code | SSVC `active` says the CVE is exploited in the wild, not that exploit code is public, so it is worded "Exploited (CISA SSVC)" and never "Public exploit" |
| It is not an exposure claim | None of these establishes that any device is exposed; the brief's review steps still apply |

The feeds published before `poc`, with their version 1, 2 or 3 index and no `poc` column, stay
valid resume and archive inputs. The brief lists its `exploit` references in the Original
references block and shows the badge with its source; the register adds the same note; the
Explorer offers the filter and a quick chip.

## CWE, CAPEC and source-attributed context

Schema 5 introduced exact `weaknesses` and `weaknesses_status` fields to each brief.
Every weakness has its CNA-supplied canonical ID, a bounded description and the
exact CVE-record source URL. No ID is inferred from prose, product names,
references or ADP containers. New descriptions use Unicode code-point limits;
unpaired surrogates, control, bidi-format and U+FEFF byte-order-mark characters are rejected.

`not_projected` means the retained projection did not contain this field;
`not_supplied` means a fully inspected bounded CNA selection supplied no usable
canonical ID; `supplied` means at least one ID was projected; `bounded` means a
type, description or unique-ID limit was exceeded and the projection may be
incomplete. None establishes the absence of a weakness. Malformed supplied
containers refuse that projection under the existing last-good/failure policy.

Old raw projection-cache entries normalize missing pairs to empty/
`not_projected` without advancing source clocks. An otherwise successful old
projection becomes due for a real CWE re-projection within the existing
2,000-record push / 40-record scheduled budget and four-worker bound. Failed
attempts keep their existing one-hour cooldown. Other successful projections
keep the existing 24-hour interval. A newly projected field on identical source
bytes is a local projection change, not a publisher revision.

The separate, bounded public context catalog can describe CWE/CAPEC definitions,
actors, campaigns, products and mitigations with explicit evidence, source
versions, source-byte digests and separate publisher/event/observation clocks.
CWE-to-CAPEC mappings require official MITRE evidence and mean **taxonomy only**.
They do not establish observed attacks or connect an actor to an article.
Campaign/actor attribution and other relationships remain explicit, cited
publisher claims; no transitive association or new CVE admission is inferred.
A generated CWE definition link is labeled Definition, not a captured source.
Empty or unreviewed context remains unknown, not a fabricated entity inventory.

Legacy schema 2/3/4 snapshots retain their old shape. Known modern schema 5/6 context
or weakness fields on a legacy-labeled snapshot are rejected rather than
silently stripped. Raw unversioned CNA-cache compatibility is a distinct input
policy. The read-only views do not run models, scans, commands or device actions.

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
