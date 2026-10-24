# Intelligence Hub sources and historical coverage

## What the collection represents

The initial historical selection contains **22 primary publications** dated **24 October 2025 through 24 October 2026**, inclusive. It covers supply-chain compromises, identity and AI-related campaigns, application/edge vulnerabilities, browser exploitation and operational-technology disruption. It is a reading and investigation aid, not a complete list of incidents or a device-exposure assessment.

There is at least one selected publication in each calendar-month bucket touched by that window. Coverage is uneven: six entries fall in the partial 2025 fourth quarter, four in 2026 Q1, four in Q2, five in Q3 and three in the partial Q4. Those are publication counts, not counts of unique attacks, victims or vulnerabilities. Missing stories remain possible in every period.

Live publisher feeds, the historical selection and CISA KEV are separate inputs. RSS commonly retains only recent posts, so fetching it cannot establish a full-year archive. Source failures and old cached data must remain visible. Reporting outlets provide useful leads and context; curated historical claims here were checked against an official advisory, publisher's original research or a first-party incident account.

## Dates and evidence

- `published_at` is the supported publication day. It is not silently replaced by retrieval time, a search-engine estimate or the latest update date.
- The initial history uses `date_basis: publication` for filtering and chronology. `event_date` separately records an exact incident day only when supported; otherwise it is null. Neither a null event date nor an in-window publication says when a campaign began.
- Anthropic's November 2025 disclosure describes September detection; the FBI's December 2025 warning updates activity dating back to 2023. Their summaries make that earlier activity explicit.
- CISA KEV dates identify **catalog addition**, not original disclosure, exploitation start or a personal remediation deadline. A KEV row and an article about the same CVE are different evidence, not two incidents.
- `known` denotes a first-party incident or official confirmation of malicious activity in the cited material. `reported` retains a research publisher's observed/assessed activity or attempts; it does not assert independent corroboration or successful compromise. `unknown` means this selection does not establish exploitation; it never means safe or unexploited.
- A demonstrated capability, experimental sample or aggregate research finding is not presented as a deployed campaign. PromptSpy's lack of observation in ESET telemetry is retained explicitly.

Published corrections take priority over preliminary theories. The October LiteLLM entry cites the **23 October canonical investigation** for the **21 October incident**, and stays separate from the March compromise. No severity, attribution certainty, victim total or CVE is inferred from a headline. Exact product versions and current vendor response guidance still need review before action.

## Primary publishers in the initial history

| Publisher | Original material used |
| --- | --- |
| CERT-EU | [WSUS advisory](https://cert.europa.eu/publications/security-advisories/2025-040/) |
| Google Threat Intelligence Group / Mandiant | [November AI threat tracker](https://cloud.google.com/blog/topics/threat-intelligence/threat-actor-usage-of-ai-tools), [September tracker](https://cloud.google.com/blog/topics/threat-intelligence/from-prompting-to-autonomy-the-evolution-of-adversarial-ai), [AOMEI update investigation](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering/) |
| Google Security | [Public-web prompt-injection study](https://blog.google/security/prompt-injections-web/) |
| Anthropic | [Espionage disclosure](https://www.anthropic.com/news/disrupting-AI-espionage), [Project Glasswing update](https://www.anthropic.com/news/glasswing-initial-update) |
| GitLab | [November npm campaign research](https://about.gitlab.com/blog/gitlab-discovers-widespread-npm-supply-chain-attack/) |
| React Team | [React Server Components disclosure](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components) |
| FBI IC3 and joint US government authors | [Impersonation warning](https://www.ic3.gov/PSA/2025/PSA251219), [PLC advisory](https://www.ic3.gov/CSA/2026/260407.pdf) |
| Canadian Centre for Cyber Security | [Ivanti EPMM advisory and updates](https://www.cyber.gc.ca/en/alerts-advisories/ivanti-security-advisory-av26-068) |
| ESET Research | [PromptSpy analysis](https://www.welivesecurity.com/en/eset-research/promptspy-ushers-in-era-android-threats-using-genai/) |
| Aqua Security | [Trivy incident advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23) |
| LiteLLM | [March notice](https://docs.litellm.ai/blog/security-update-march-2026), [March follow-up](https://docs.litellm.ai/blog/security-townhall-updates), [corrected October investigation](https://docs.litellm.ai/blog/security-incident-oct-21-2026-attack-chain) |
| Oracle | [PeopleSoft security alert](https://www.oracle.com/security-alerts/alert-cve-2026-35273.html) |
| Sysdig Threat Research | [JADEPUFFER analysis](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) |
| Hugging Face | [July incident technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline) |
| Cyber Security Agency of Singapore | [Keyv-related npm advisory](https://www.csa.gov.sg/alerts-and-advisories/advisories/ad-2026-009/) |
| Microsoft | [Passkey-themed identity campaign](https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/), [browser patch-gap research](https://microsoftedge.github.io/edgevr/posts/AI-And-Rise-Patch-Gap-Abuse/) |

These are source citations, not endorsements, verified build artifacts or proof that a cited organization is unaffected by other incidents. Summaries are short original paraphrases; full articles and publisher markup are not republished.

## Existing library attribution and curation process

The finding aid was the existing [TeamStarWolf AI case study](https://github.com/TeamStarWolf/TeamStarWolf/blob/d85c7667dbcac953f27354c76f625085e632d71c/case-studies/AI_THREATS_2026.md), published 7 October 2026. Its [case-study method](https://github.com/TeamStarWolf/TeamStarWolf/blob/d85c7667dbcac953f27354c76f625085e632d71c/case-studies/README.md) separates confirmed, reported and demonstrated evidence. Its [research index](https://github.com/TeamStarWolf/TeamStarWolf/blob/d85c7667dbcac953f27354c76f625085e632d71c/research/README.md) treats catalogs as dated finding aids. These references were read at the pinned commit, without modifying the existing library.

The library covers a longer period than this hub's window. Older incidents were not copied wholesale. Linked primary pages were opened separately, their dates and qualifications checked, and new primary sources added for broader cybersecurity coverage. `origin: library-curation` labels that curated workflow; it does not mean every entry originated in the library or that the library independently verifies every claim.

Keep the public curation in `config/history.json`. Research receipts, raw library imports, access failures and excluded candidates belong in ignored local state. A source that cannot be read is not admitted from a search snippet alone. A current update date is not substituted for an unknown original publication date. Additional sources can be added through the same bounded, attributed review.

Treat all article/feed text as untrusted data. Render text and validated HTTPS links, with no publisher HTML, embedded scripts or active instructions. Reading a story authorizes no network probe, patch, credential change, model call or publication of private account data. Personal X content and a supported Grok search integration require their own explicit access and eligibility; a public source link does not connect either account.
