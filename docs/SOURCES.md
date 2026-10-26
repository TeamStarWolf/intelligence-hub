# Intelligence Hub sources and historical coverage

## What the collection represents

The historical selection contains **73 primary publications** within **25 October 2006 through 25 October 2026**, inclusive. The original **63 rows** remain unchanged; **10 newly qualified primary publications** add selected 2006–2015 context. The collection includes advisories, phishing and identity abuse, first-party breach accounts, memory disclosure and availability attacks alongside the retained later history.

This is a reading and investigation aid, not an exhaustive incident archive or a device-exposure assessment. Counts represent **publications**, not unique attacks, victims or vulnerabilities. Related publications can describe the same activity.

At least one selected publication falls in each calendar year touched by the window. The earliest is **14 November 2006**, after the window begins. There are **184 calendar-month buckets** and **43 calendar-quarter buckets** with no selection. These are explicit selection gaps, not evidence that no incidents occurred.

| Publication year | Selected publications |
| --- | --- |
| 2006 (partial window) | 1 |
| 2007 | 1 |
| 2008 | 1 |
| 2009 | 1 |
| 2010 | 1 |
| 2011 | 1 |
| 2012 | 1 |
| 2013 | 1 |
| 2014 | 1 |
| 2015 | 1 |
| 2016 | 1 |
| 2017 | 4 |
| 2018 | 4 |
| 2019 | 4 |
| 2020 | 4 |
| 2021 | 5 |
| 2022 | 4 |
| 2023 | 5 |
| 2024 | 5 |
| 2025 | 11 |
| 2026 (partial window) | 16 |

The boundary years are partial, and coverage within every year remains uneven. A twenty-year date window does not establish twenty years of complete source coverage. The original 63 rows were retained from the accepted earlier curation without a new source-body review; the ten additions were checked against the exact primary pages captured on October 25, 2026.

Live feeds, curated history and CISA KEV remain separate inputs. RSS usually contains only recent posts, so a successful refresh cannot reconstruct a publisher's archive. Source failures, retrieval dates and retained old data stay visible. Current archived pages can contain later edits; original publication, later update, incident and capture clocks are distinct.

## Dates and evidence

- `published_at` is a supported original publication day. It is not silently replaced by retrieval time, a search estimate, a detection day or the latest update date.
- All curated rows use `date_basis: publication` for chronology and filtering. `event_date` records an exact supported incident or action day separately; otherwise it is null.
- A publication in a particular year does not place all described activity in that year. ShadowHammer's March 2019 disclosure describes 2018 activity; Okta's April 2022 investigation concerns January; the Citrix Bleed investigation describes activity before its October 2023 publication.
- Twitter's page explicitly retains an **18 July 2020 initial publication** while showing a **30 July update**. Twilio's archived article explicitly identifies its **7 August 2022 initial post**, despite a later October header. The summaries preserve those distinctions.
- CISA KEV dates identify **catalog addition**, not original disclosure, exploitation start or a personal remediation deadline. A KEV row and an article about the same CVE are different evidence, not automatically two incidents.
- `known` denotes first-party confirmation or official confirmation of malicious activity in the cited material. `reported` retains a research publisher's observed or assessed activity, or explicitly reported exploitation. It is not independent corroboration of every claim.
- `unknown` means this selection does not establish exploitation. It never means safe, unexploited today or unaffected. An initial advisory's lack of observed exploitation is a dated statement, not a current verdict.
- Research proofs of concept and blocked attempts are not silently promoted to successful compromises. Cloudflare's 2022 phishing account explicitly says its security keys prevented access.
- The **July 2024 CrowdStrike review concerns a defective update and availability failure**, not a documented malicious intrusion. Its publication, the July 19 event and the subsequent full root-cause report are separate.

Current source pages may contain updates that were not present on the initial publication day. Advisory histories and explicit original-publication statements support the selected dates; summaries identify material later findings. The collection is not a byte-preserved archive of each page as it appeared at publication.

Published corrections take priority over preliminary theories. The retained October LiteLLM entry cites the **23 October 2026 canonical investigation** for the **21 October incident**, separate from March. Okta's concluding 2022 report is used instead of treating early maximum-impact estimates as final findings. No severity, attribution certainty, victim total or CVE is inferred from a headline.

The CVE arrays are selective source-supported indexes, not exhaustive lists or one-to-one incident mappings. An empty array can mean that no specific identifier was indexed, rather than that no vulnerability was involved.

Historical mitigation text is not a current patch plan. Check supported vendor guidance, exact versions, enabled features and deployment context before action. A successful update does not by itself prove that prior access, stolen sessions or credentials were removed.

## Selected 2006–2015 primary publications

These ten additions use the same historical row interface and source-attributed evidence labels. Dates come from explicit publication statements or qualified same-page metadata, not search estimates. Microsoft platform-migration dates are not substituted for original bulletins. The OpenSSL item uses only the associated CVE-2014-0160 entry in the captured index. Google’s literal article fallback was read without executing its template. Later changes to these pages remain possible.

| Publication day | Primary publication selected | Publisher |
| --- | --- | --- |
| 2006-11-14 | [Microsoft publishes Workstation Service memory-corruption bulletin](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2006/ms06-070) | Microsoft Security Response Center |
| 2007-04-12 | [Microsoft documents DNS RPC vulnerability and bulletin follow-up](https://learn.microsoft.com/en-us/security-updates/securityadvisories/2007/935964) | Microsoft Security Response Center |
| 2008-10-23 | [Microsoft reports targeted exploitation attempts against Server Service flaw](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2008/ms08-067) | Microsoft Security Response Center |
| 2009-01-13 | [Microsoft publishes SMB vulnerability bulletin MS09-001](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-001) | Microsoft Security Response Center |
| 2010-07-16 | [Microsoft records Windows Shell shortcut-icon vulnerability](https://learn.microsoft.com/en-us/security-updates/securityadvisories/2010/2286198) | Microsoft Security Response Center |
| 2011-06-01 | [Google discloses targeted password theft and email-account hijacking](https://googleblog.blogspot.com/2011/06/ensuring-your-information-is-safe.html) | Google Official Blog |
| 2012-06-12 | [Microsoft publishes Internet Explorer bulletin MS12-037](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-037) | Microsoft Security Response Center |
| 2013-10-03 | [Adobe discloses attacks involving customer information and source code](https://blog.adobe.com/en/publish/2013/10/03/important-customer-security-announcement) | Adobe |
| 2014-04-07 | [OpenSSL records Heartbleed TLS heartbeat memory disclosure](https://openssl-library.org/news/vulnerabilities/index.html) | OpenSSL Project |
| 2015-03-27 | [GitHub reports a large distributed denial-of-service attack](https://github.blog/news-insights/company-news/large-scale-ddos-attack-on-github-com/) | GitHub |

The CVE lists are selected indexes, not every vulnerability mentioned in a cumulative bulletin. Historical negative exploitation statements are not current safety verdicts. Google and Adobe describe dated first-party incidents; the source does not establish every subsequent victim or actor claim. GitHub’s March 27, 2015 publication, March 26 event and 2019 page update remain separate.

## Earlier decade reading list

Each entry in `config/history.json` carries its primary URL, original summary, date basis, any supported CVEs, evidence label and references. The following list identifies the **41 additions**, without copying article bodies.

| Publication day | Primary publication selected | Publisher |
| --- | --- | --- |
| 2016-11-01 | [Microsoft details STRONTIUM Flash and Windows zero-day attacks](https://www.microsoft.com/en-us/security/blog/2016/11/01/our-commitment-to-our-customers-security/) | Microsoft Security Team |
| 2017-02-23 | [Cloudflare explains its parser memory-leak incident](https://blog.cloudflare.com/incident-report-on-memory-leak-caused-by-cloudflare-parser-bug/) | Cloudflare |
| 2017-05-12 | [Microsoft analyzes WannaCry's SMB-based ransomware spread](https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/) | Microsoft Defender Security Research |
| 2017-06-27 | [Microsoft traces the Petya outbreak through updates and lateral movement](https://www.microsoft.com/en-us/security/blog/2017/06/27/new-ransomware-old-techniques-petya-adds-worm-capabilities/) | Microsoft Defender Security Research |
| 2017-09-18 | [Cisco Talos finds a malicious payload in signed CCleaner releases](https://blog.talosintelligence.com/avast-distributes-malware/) | Cisco Talos |
| 2018-01-03 | [Project Zero publishes speculative-execution memory-disclosure research](https://projectzero.google/2018/01/reading-privileged-memory-with-side.html) | Google Project Zero |
| 2018-03-01 | [GitHub reports a memcached-amplification DDoS outage](https://github.blog/news-insights/company-news/ddos-incident-report/) | GitHub |
| 2018-03-28 | [Drupal discloses unauthenticated remote code execution in core](https://www.drupal.org/sa-core-2018-002) | Drupal Security Team |
| 2018-09-28 | [Facebook discloses access-token theft through View As bugs](https://about.fb.com/news/2018/09/security-update/) | Facebook / Meta |
| 2019-02-11 | [Kubernetes explains the runc container-escape vulnerability](https://kubernetes.io/blog/2019/02/11/runc-and-cve-2019-5736/) | Kubernetes Product Security Committee |
| 2019-02-20 | [Drupal warns of code execution through web-service field handling](https://www.drupal.org/sa-core-2019-003) | Drupal Security Team |
| 2019-03-25 | [Kaspersky details the ASUS Live Update supply-chain attack](https://securelist.com/operation-shadowhammer/89992/) | Kaspersky GReAT |
| 2019-05-14 | [Microsoft releases BlueKeep Remote Desktop Services guidance](https://www.microsoft.com/en-us/msrc/blog/2019/05/prevent-a-worm-by-updating-remote-desktop-services-cve-2019-0708) | Microsoft Security Response Center |
| 2020-07-14 | [Check Point discloses SIGRed in Windows DNS Server](https://research.checkpoint.com/2020/resolving-your-way-into-domain-admin-exploiting-a-17-year-old-bug-in-windows-dns-servers/) | Check Point Research |
| 2020-07-18 | [Twitter explains employee phishing behind account takeovers](https://blog.x.com/en/company/an-update-on-our-security-incident) | Twitter / X |
| 2020-09-15 | [CERT-EU tracks Zerologon domain-controller risk and exploitation](https://cert.europa.eu/publications/security-advisories/2020-046/) | CERT-EU |
| 2020-12-13 | [FireEye reveals SUNBURST in SolarWinds Orion updates](https://cloud.google.com/blog/topics/threat-intelligence/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor) | FireEye / Mandiant |
| 2021-03-02 | [Microsoft reports Exchange zero-day exploitation](https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/) | Microsoft Threat Intelligence |
| 2021-04-15 | [Codecov discloses its Bash Uploader credential-exfiltration incident](https://about.codecov.io/security-update/) | Codecov |
| 2021-05-10 | [FBI confirms DarkSide ransomware in Colonial Pipeline compromise](https://www.fbi.gov/news/press-releases/fbi-statement-on-compromise-of-colonial-pipeline-networks) | Federal Bureau of Investigation |
| 2021-05-27 | [Microsoft tracks NOBELIUM abuse of a legitimate mailing service](https://www.microsoft.com/en-us/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/) | Microsoft Threat Intelligence |
| 2021-12-10 | [CERT-EU issues Log4Shell guidance and tracks later Log4j flaws](https://cert.europa.eu/publications/security-advisories/2021-067/) | CERT-EU |
| 2022-04-20 | [Okta concludes its January support-vendor compromise investigation](https://www.okta.com/en-ca/blog/company-and-culture/okta-concludes-its-investigation-into-the-january-2022-compromise/) | Okta |
| 2022-08-07 | [Twilio discloses employee phishing and customer-data access](https://www.twilio.com/en-us/blog/archive/2022/august-2022-social-engineering-attack) | Twilio |
| 2022-08-09 | [Cloudflare explains how security keys blocked a phishing intrusion](https://blog.cloudflare.com/2022-07-sms-phishing-attacks/) | Cloudflare |
| 2022-09-16 | [Uber describes contractor-account compromise and internal access](https://www.uber.com/in/en/newsroom/security-update/) | Uber |
| 2023-04-20 | [Mandiant links 3CX compromise to an earlier poisoned software package](https://cloud.google.com/blog/topics/threat-intelligence/3cx-software-supply-chain-compromise) | Mandiant |
| 2023-06-02 | [Singapore CSA warns of active MOVEit Transfer exploitation](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2023-073/) | Cyber Security Agency of Singapore |
| 2023-07-11 | [Microsoft discloses forged-token access to cloud email](https://www.microsoft.com/en-us/msrc/blog/2023/07/microsoft-mitigates-china-based-threat-actor-storm-0558-targeting-of-customer-email) | Microsoft Security Response Center |
| 2023-10-20 | [Okta reports unauthorized access to support-case files](https://sec.okta.com/articles/2023/10/tracking-unauthorized-access-oktas-support-system/) | Okta Security |
| 2023-10-31 | [Mandiant investigates Citrix Bleed session hijacking](https://cloud.google.com/blog/topics/threat-intelligence/session-hijacking-citrix-cve-2023-4966) | Mandiant |
| 2024-01-10 | [Volexity identifies an Ivanti VPN zero-day exploit chain](https://www.volexity.com/blog/2024/01/10/active-exploitation-of-two-zero-day-vulnerabilities-in-ivanti-connect-secure-vpn/) | Volexity |
| 2024-02-20 | [US and UK authorities announce LockBit infrastructure disruption](https://www.justice.gov/archives/opa/pr/us-and-uk-disrupt-lockbit-ransomware-variant) | US Department of Justice |
| 2024-03-29 | [Red Hat warns of malicious code in XZ Utils release packages](https://www.redhat.com/en/blog/urgent-security-alert-fedora-40-and-rawhide-users) | Red Hat Product Security |
| 2024-06-10 | [Mandiant tracks stolen credentials targeting Snowflake customer instances](https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion) | Mandiant |
| 2024-07-24 | [CrowdStrike publishes its preliminary Windows outage review](https://www.crowdstrike.com/en-us/blog/falcon-content-update-preliminary-post-incident-report/) | CrowdStrike |
| 2025-02-24 | [Chainalysis traces the February Bybit cryptocurrency theft](https://www.chainalysis.com/blog/bybit-exchange-hack-february-2025-crypto-security-dprk/) | Chainalysis |
| 2025-03-14 | [StepSecurity detects poisoned tj-actions changed-files releases](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised) | StepSecurity |
| 2025-07-19 | [Microsoft issues SharePoint guidance for active ToolShell attacks](https://www.microsoft.com/en-us/msrc/blog/2025/07/customer-guidance-for-sharepoint-vulnerability-cve-2025-53770) | Microsoft Security Response Center |
| 2025-08-26 | [Google tracks OAuth-token theft through Salesloft Drift integrations](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift/) | Google Threat Intelligence Group |
| 2025-10-22 | [F5 publishes lessons and customer guidance after its security incident](https://www.f5.com/company/blog/lessons-we-are-learning-from-our-security-incident) | F5 |

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

The initial recent-year finding aid was the existing [TeamStarWolf AI case study](https://github.com/TeamStarWolf/TeamStarWolf/blob/d85c7667dbcac953f27354c76f625085e632d71c/case-studies/AI_THREATS_2026.md), published 7 October 2026. Its [case-study method](https://github.com/TeamStarWolf/TeamStarWolf/blob/d85c7667dbcac953f27354c76f625085e632d71c/case-studies/README.md) separates confirmed, reported and demonstrated evidence. Its [research index](https://github.com/TeamStarWolf/TeamStarWolf/blob/d85c7667dbcac953f27354c76f625085e632d71c/research/README.md) treats catalogs as dated finding aids. Those references were read at the pinned commit during the initial curation, without modifying the library.

The decade extension was curated independently from primary pages. The original 22 records remain unchanged. `origin: library-curation` labels the manual curation workflow; it does not mean every record originated in the library or that the library independently verifies each claim.

Keep public curation in `config/history.json`. Research receipts, baseline preservation, access failures and excluded candidates belong in ignored local state. A page that cannot be read is not admitted from a search snippet alone. A current update date is not substituted for an unknown original date. The readable primary page and its explicit date must support each addition.

Summaries are short original paraphrases. Full publisher articles, markup, private account data and local source locators are not republished. Primary-source status does not make a publisher infallible or establish the provenance or security of software it distributes.

Treat all article and feed text as untrusted data. Render text and validated HTTPS links, with no publisher HTML, embedded scripts or active instructions. Reading a story authorizes no network probe, patch, credential change, model call or publication of private account data. Personal X content and a supported Grok search integration require their own explicit access and eligibility; a public source link does not connect either account.
