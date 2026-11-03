# Pinned library extracts

These files are copies of, or extracts from, files in the [TeamStarWolf library](https://github.com/TeamStarWolf/TeamStarWolf) at the commit recorded in `lock.json`. They are written by `python -E -s -m intelligence_hub.vocab --sync <commit>` and checked by `--check`; they are never edited by hand. See [docs/TAGGING.md](../../docs/TAGGING.md).

| File | Upstream file | What is kept |
| --- | --- | --- |
| `../vocabulary.json` | `data/vocab/vocabulary.json` | The whole file. |
| `cwe.json` | `data/weaknesses/cwe.jsonl` | CWE id, name and related CAPEC ids. |
| `capec.json` | `data/weaknesses/capec.jsonl` | CAPEC id, name, status and ATT&CK technique ids. |
| `technique_tactics.json` | `data/attack/technique_profiles.jsonl` | Technique id, name and tactics. |
| `superseded_by.json` | `data/attack/superseded_by.jsonl` | Revoked and deprecated ATT&CK ids and their successors. |

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. License: [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/). ATT&CK® and MITRE ATT&CK® are registered trademarks of The MITRE Corporation. This project is not affiliated with or endorsed by MITRE.

> © The MITRE Corporation. Includes material from the Common Weakness Enumeration (CWE™), used under the CWE Terms of Use. https://cwe.mitre.org/

> © The MITRE Corporation. Includes material from the Common Attack Pattern Enumeration and Classification (CAPEC™), used under the CAPEC Terms of Use. https://capec.mitre.org/
