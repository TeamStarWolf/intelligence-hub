# Method: evidence rules, confidence and coverage

The Hub is for people who need to decide what to read and act on first. This page says how every
tag, date and coverage statement on the site is decided, so a reader can judge how far to trust a
row. The same rules appear on the site's **Method** tab (`#/method`). The rules are deterministic:
the same inputs give the same tags, with no model, no network call and no randomness.
[TAGGING.md](TAGGING.md) documents the vocabularies, methods and tests behind them.

## Exploitation

Every row has one exploitation value, the method that set it and a confidence.

| Value | Evidence it needs |
| --- | --- |
| known | A CVE on the row is in the CISA KEV catalog loaded in that run (method `kev`, high); or a vendor-primary structured field marks the flaw exploited (`vendor-structured`, high; used by the history adapters); or a curated row's cited primary source confirms malicious activity, as [SOURCES.md](SOURCES.md) defines (`curated-primary`, medium). |
| reported | A curated row's source reports exploitation (`curated-primary`, medium), or a headline states exploitation in plain terms such as "exploited", "in the wild" or "under active attack", or names a zero-day with an attack verb (`title-term`: medium for government, CERT, vendor and researcher sources, low for press). Negations such as "no evidence of exploitation" and proof-of-concept wording never count. |
| unknown | Everything else (`none`). There is no "not exploited" value. Unknown never means safe, patched or unaffected. |

The term lists are in `config/vocab/exploitation.json`.

## Confidence

| Level | Meaning | Examples |
| --- | --- | --- |
| high | Read from a structured field of a primary source, or from the source's own identity. | KEV catalog entries; a CVE record's CNA `problemTypes` and `affected` fields; `source_class` and `publisher_vendor` in `config/sources.json`. |
| medium | An exact, case-sensitive name or a headline term, with no conflicting signal. | A threat group's name or a product name in a headline; "hospital" for the healthcare sector. |
| low | Derived through a taxonomy chain, a weak name confirmed by a context word, or exploitation wording in a press headline. | ATT&CK techniques reached from CWE through CAPEC. |

The Explorer shows rows at every confidence level, and each tag in an entry's detail dialog names
its method and confidence. The exports carry the same fields.

## What the tags do not say

- A vendor, product, actor or malware name in a headline is a mention, not attribution.
- An ATT&CK technique on a row comes only from the row's CWEs through CAPEC. Many common CWEs
  reach no technique, and a technique reached this way is taxonomy, not observed behaviour.
- A region tag carries a role: `publisher` (the source's country) or `mentioned` (a country named
  in the headline). A mention does not say whether a place is a target, an origin or neither.
- `analysis` and `unclassified` event types exist so that no row is forced into a label.

## Dates and scores

- Published and updated dates are the publisher's own; event dates are kept separately. Unknown
  dates stay unknown and are never replaced by the retrieval time.
- A KEV date is the day CISA added the entry to its catalog, not disclosure or first exploitation.
  CISA's federal due dates apply to US federal civilian agencies; they are not a reader's deadline.
- CVSS versions stay labelled, with the scorer named. Scores across versions are never merged.
- Affected version ranges are what the CNA published, not a list of fixed releases. No row proves
  that a device is exposed.

## History coverage

Every history source has one coverage statement per year from 1998, in
`history/coverage.json` (published as `data/v7/coverage.json`). The History tab shows each year's
statements above its rows, and the Sources tab shows the whole source-by-year matrix.

| Status | Meaning |
| --- | --- |
| complete | Every item the source lists for that year is a row. |
| filtered | The adapter's stated filter, or the 1,500-row yearly cap, chose the rows. The statement names the filter. |
| partial | Some listed items could not be read, link to pages that no longer resolve, or carry only a later posting date. The statement says how many of each. |
| sample | A fixed sample by design. |
| gap | No rows that year: the source had not started, the series had ended, or the adapter is not built yet. The statement says which. |
| unreachable | The source refused automated reads, is JavaScript-only or needs a login. |

`python -E -s -m intelligence_hub.history check` holds the statements to the committed rows: a
complete year keeps every listed item, and a gap or unreachable year keeps none. Curated rows and
the live RSS and Atom feeds are outside these statements. A quiet year in History is a coverage
fact, never a claim that nothing happened.

## Links to the TeamStarWolf library

The vendor, actor and malware pages and indexes, and the tag list in a row's detail dialog
(vendors, products, actors, malware and sectors), link to the matching page on the [TeamStarWolf library site](https://teamstarwolf.github.io/TeamStarWolf/).
Every such link comes from `site/js/library.js`, which
`python -E -s -m intelligence_hub.site labels` generates from the `library_path` and
`library_anchor` of each entity in the vendored vocabulary (`config/vocabulary.json`). The
generator refuses an entity whose recorded `library_url` does not match its path and anchor, and
the site renders a library link only when it starts with
`https://teamstarwolf.github.io/TeamStarWolf/#/` and passes the page's `safeUrl` check. The Hub
never computes a heading slug of its own.

A curated history row that cites a commit-pinned library page keeps that pinned link as its
evidence and shows the same page on the library site beside it. A CVE links to its CVE.org record;
it links to library notes only when the shared vocabulary carries an entry for that CVE, and the
vocabulary has no CVE, CAPEC or CWE entries yet, so those library links are not shown.

## Licences and notices

| Material | From | Terms |
| --- | --- | --- |
| Publisher headlines and links | The publishers of the configured RSS and Atom feeds | The articles belong to their publishers. The Hub keeps the headline, the date and the link, never the article body. |
| KEV catalog entries | CISA, Known Exploited Vulnerabilities catalog | CISA distributes the KEV data under Creative Commons Zero 1.0 ([kev-data](https://github.com/cisagov/kev-data)). The Hub keeps CISA's text as published and attributes it to CISA. |
| CVE record fields | The CVE Program, through the cvelistV5 repository | Used under the [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse). |
| History rows | The sources each year's coverage statement names | Ids, titles, dates, CVE ids and links only; each adapter's licence note is in `history/coverage.json` and on the Sources tab. |
| ATT&CK groups, software, techniques and tactics | MITRE ATT&CK, through the library's pinned files | The ATT&CK notice below. |
| CWE weaknesses | MITRE CWE, through the library's pinned CWE list | The CWE notice below. |
| CAPEC attack patterns | MITRE CAPEC, through the library's pinned CAPEC list | The CAPEC notice below. |
| Curated summaries | Written for the Hub | Original paraphrases, each backed by a dated primary source that the row links. |
| The Hub's code | This repository | [MIT License](../LICENSE). |

The MITRE designations, as the TeamStarWolf library records them in its
[THIRD_PARTY_NOTICES.md](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/THIRD_PARTY_NOTICES.md):

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

> © The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/

> © The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/
