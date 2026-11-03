# Tags and vocabularies

People who read the Hub ask the same questions of it: which vendors had exploited flaws this month, which sectors keep turning up in breach reporting, how often a CERT names a threat group before the press does. Free-text tags cannot answer those questions, so every row is tagged from controlled vocabularies, and every tag says how it was found and how far to trust it. The rules are deterministic: the same inputs always give the same tags, with no model, no network call and no randomness.

## Where the vocabularies live

| File | Owner | What it holds |
| --- | --- | --- |
| `config/vocab/kind.json` | Hub | What a row is: advisory, research, reporting, incident, kev, filing, bulletin, note. |
| `config/vocab/source_class.json` | Hub | Who publishes it: vendor-primary, government-cert, researcher, press. Also the class of KEV and curated source ids that are not in `config/sources.json`. |
| `config/vocab/exploitation.json` | Hub | known, reported, unknown, the evidence each needs, and the headline terms and negations. |
| `config/vocab/event_type.json` | Hub | disclosure, exploitation, patch, breach, outage, takedown, policy, analysis, unclassified, with headline terms. |
| `config/vocab/sector.json` | Hub | The library's 18 sector ids with headline terms. |
| `config/vocab/region.json` | Hub | ISO 3166-1 alpha-2 countries, EU and UN M49 regions with the names that match them, and the roles a place can have. |
| `config/vocab/matching.json` | Hub | Extra stop names, context-word rules and the short-name rule for entity matching. |
| `config/vocabulary.json` | Library | A pinned copy of the TeamStarWolf library's `data/vocab/vocabulary.json`: vendors, products, actors (ATT&CK groups and named clusters), malware (ATT&CK software) and sectors, with ids, labels, match names and stop names. |
| `config/library/*.json` | Library | Pinned extracts of the library's CWE list (CWE to CAPEC), CAPEC list (CAPEC to ATT&CK), technique tactics and the ATT&CK `superseded_by` table. |
| `config/library/lock.json` | Generated | The library commit and the SHA-256 of every upstream file and every local copy. |

Every source in `config/sources.json` carries a `source_class`, and vendor channels and vendor research blogs carry `publisher_vendor`. Government and vendor channels carry a `country` where the publisher's country is clear.

## Keeping the library copy pinned

The library copy is never edited by hand. To move the pin to a newer library commit:

```sh
python -E -s -m intelligence_hub.vocab --sync <40-character library commit>
python -E -s -m intelligence_hub.vocab --check
python -E -s -m intelligence_hub.vocab --check --remote   # re-fetch upstream and re-derive every copy
```

`--check` runs offline in the unit tests on every pull request. It fails when a pinned file differs from its recorded hash, when a Hub vocabulary file is malformed, or when any registry, KEV or curated source id lacks a valid `source_class`. `--remote` also fetches each upstream file at the pinned commit from raw.githubusercontent.com and fails if it no longer has the recorded hash or no longer derives to the local copy. Line endings are normalised before hashing, so a Windows checkout and CI agree. (`-E -s` keep isolated mode apart from the checkout on `sys.path`; `-I` would hide the package.)

## Confidence and method

| Confidence | Meaning | Examples |
| --- | --- | --- |
| high | Read from a structured field of a primary source, or from the source's own identity. | KEV catalog entries, the CVE record's CNA `problemTypes` and `affected` fields, `source_class` and `publisher_vendor` from the registry. |
| medium | An exact, case-sensitive name, or a headline term, with no conflicting signal. | "Volt Typhoon" or "Citrix NetScaler" in a headline; "hospital" for the healthcare sector. |
| low | Derived through a taxonomy chain, a weak name confirmed by a context word, or exploitation wording in a press headline. | ATT&CK techniques from CWE through CAPEC; "Carbon" only beside "backdoor" or "Turla". |

Every tag records its `method`: `source-kind`, `source-registry`, `source-identity`, `source-primary`, `kind-default`, `kev`, `kev-vendor`, `kev-product`, `kev-cwes`, `cna-affected`, `cna-problemtypes`, `product-vendor`, `title-match`, `title-term`, `exploitation-tag`, `curated-primary`, `vendor-structured`, `cwe-capec` or `none`.

## The exploitation evidence rule

- **known**: a CVE on the row is in the CISA KEV catalog loaded in that run (method `kev`, high); or a vendor-primary structured field marks the flaw exploited (`vendor-structured`, high; used by the history adapters); or a curated row's cited primary source confirms malicious activity, as `docs/SOURCES.md` defines (`curated-primary`, medium).
- **reported**: a curated row's source reports exploitation (`curated-primary`, medium), or a headline states exploitation in plain terms such as "exploited", "in the wild" or "under active attack", or names a zero-day with an attack verb (`title-term`; medium for government, CERT, vendor and researcher sources, low for press). Negations such as "no evidence of exploitation" and proof-of-concept wording never count.
- **unknown**: everything else (`none`). There is no "not exploited" value. Unknown never means safe, patched or unaffected.

The v6 feed keeps its own `exploitation` field unchanged; the evidence rule applies to the tagging block.

## Matching names in headlines

Vendor, product, actor and malware names match case-sensitively, as whole words, using the `match` names in the library vocabulary. The library already removes ordinary words (Silence, Carbon, Bitter, Proton, Anchor, Spark), command names and names two entities share. The Hub adds:

- a stop list (`matching.json` `stop`) for names that are also product or browser words, such as Chromium and Edge;
- context rules (`matching.json` `context`): a weak name matches only beside one of its context words, at low confidence. ConnectWise and ScreenConnect tag ATT&CK software S0591 only when the headline talks about abuse of the remote access tool, never when ConnectWise the company is the subject;
- a short-name rule: an actor or malware name shorter than five characters matches only when it has a digit or an inner capital (FIN7, QBot), or is on the `allow_short` list (Clop, Ryuk, Duqu, Dyre, Pysa, Sogu).

Where two entities of one type share a matched name, neither is tagged. A product tag also tags its vendor. Vendor, product, CWE and CVSS facts from KEV and from CVE records take precedence over headline matches, because they are structured.

## Fields

- `event_type`: advisories, bulletins and notes get `disclosure` by kind (high when the source is vendor-primary or the row names a CVE, medium otherwise); vendor-primary advisories also get `patch`; `exploitation` mirrors a known or reported exploitation tag; `breach`, `outage`, `takedown`, `policy`, `patch` and `disclosure` also come from headline terms. A research row with none of these is `analysis`; any other row is `unclassified`.
- `region`: each tag has a `role`. `publisher` comes from the source's country (high). `mentioned` comes from a country name or demonym in the headline (medium); a mention does not say whether the place is a target, an origin or neither. `target` and `vendor-hq` are reserved for structured fields from the history adapters.
- `sector`: headline terms from `sector.json` (medium) and the library's multi-word sector names.
- `cwe`: CNA `problemTypes` and KEV `cwes`, resolved against the pinned CWE list. Never from headline text.
- `attack`: techniques reached from the row's CWEs through CAPEC (`cwe-capec`, low), moved forward through `superseded_by` to the current ATT&CK release, with tactics from the library's technique profiles. This tag is sparse and taxonomic: many common CWEs reach no technique, and a technique reached this way is not observed adversary behaviour.
- `cvss`: the highest CNA base score among the row's CVEs, with its own version and vector. Versions are never merged.
- `kev`: the earliest KEV addition among the row's CVEs, its due date and ransomware field, and whether it was in KEV on the row's publication day.

## Where the tags go

- **v7 shards**: every article row in `site/data/v7/live/` and `history/` carries a `tagging` block in the compact form that `index.json` describes under `tagging.layout`. `index.json` also records the tagger version, the Hub vocabulary versions and the pinned library commit.
- **v6 feed**: `data/feed.json` keeps its record shape. Its `tags` now hold vocabulary labels (for example "Microsoft", "Citrix NetScaler", "Volt Typhoon") after the row's own tags, so the page shows and searches them. KEV vendor and product strings and curated topic words are folded so that spellings that differ only in case appear once: a vocabulary label wins, then the KEV catalog's most frequent spelling. Products fold within their vendor, so Cisco IOS and Apple iOS stay apart.
- **Exports**: per-year CSV and JSON Lines files with a data dictionary, described in [DATA-DICTIONARY.md](DATA-DICTIONARY.md). They do not fit today's Pages package caps, so until the owner approves new caps a run writes them to `dist/exports/` for local analysis only.

## When a vocabulary is broken

A missing, changed or malformed vocabulary never blocks publication. The collector reports the reason, rows keep their raw tags (publisher rows have none), the v7 rows carry no tagging block, `index.json` records `tagging.status` as `unavailable`, and no exports are written in that run.

## Tests

- `tests/test_vocab.py`: the pin check, a changed pinned file failing the check, sync and the remote check against a stand-in upstream, and `source_class` for every source.
- `tests/test_tagging.py`: the false-positive headlines, the exploitation evidence rule, structured fields, regions with roles, actor and software id forms, about 300 real headlines in `tests/fixtures/golden_headlines.jsonl` (titles and URLs only), resolution of every emitted tag, determinism, idempotence and case folding.
- `tests/test_exports.py`: columns against the dictionary, manifest hashes, byte-identical unchanged years, the offline build and a corrupt vocabulary.

The golden file is refreshed with `python -I tests/fixtures/build_golden.py --refresh`. Review the diff before committing it.

## Notices

Actor and malware names, techniques and tactics come from MITRE ATT&CK through the library's pinned files:

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

> © The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/

> © The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/
