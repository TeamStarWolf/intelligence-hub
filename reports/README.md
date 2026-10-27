# Reports

Threat-intelligence editions for analysis over time. Each report keeps its sources, dates, narrative, data and charts together. Selected source coverage does not establish device exposure or a complete incident history.

The [Intelligence Hub reports view](https://teamstarwolf.github.io/intelligence-hub/#reports) shows the bounded latest catalog, recorded scheduling state and next nominal opportunity. [Schedule and method](REPORTING.md) describes Chicago periods, revision checks and coverage. Report links render on GitHub; the public Hub remains read-only.

## Publication cadence

Daily editions are requested at **06:00, 14:00 and 22:00 America/Chicago**, covering 24 elapsed hours on weekdays or 48 on Saturday/Sunday. Weekly and weekend editions publish Monday06:00. Fortnightly means every two weeks, first close November2,2026. Monthly, quarterly and rolling six-completed-month reports publish after calendar close. Activation is recorded separately in [reporting.json](reporting.json); this index alone does not prove that a scheduler ran.

## Daily

- [October 27, 2026 · 14:00 Chicago · 24-hour edition](daily/2026-10-27/1400-CDT/README.md) · [data](daily/2026-10-27/1400-CDT/data.json) · [source activity](daily/2026-10-27/1400-CDT/charts/source-activity.svg) · [CVE context](daily/2026-10-27/1400-CDT/charts/cve-context.svg) · [coverage](daily/2026-10-27/1400-CDT/charts/data-coverage.svg) · 145 explicitly timestamped source entries mentioning 17 unique CVEs; late, partial coverage; compiled October 27 at 20:30 UTC from the frozen 17:41:42 UTC input. The 19:00 UTC cutoff has a 4,698-second unobserved tail. **Next nominal report/revision opportunity: October 27 at 22:00 America/Chicago (October 28 at 03:00 UTC)**.
- [October 27, 2026 · 06:00 Chicago · 24-hour edition](daily/2026-10-27/0600-CDT/README.md) · [data](daily/2026-10-27/0600-CDT/data.json) · 144 explicitly timestamped source entries mentioning 20 unique CVEs; late, partial coverage; compiled October 27 at 16:37 UTC from the frozen 06:14 UTC input.
- [October 26, 2026 · 22:00 Chicago · 24-hour edition](daily/2026-10-26/2200-CDT/README.md) · [data](daily/2026-10-26/2200-CDT/data.json) · 185 explicitly timestamped source entries mentioning 22 unique CVEs; partial coverage, compiled late on October 27 at 05:31:08 UTC. The fixed window ends at October 27 03:00 UTC; input generation at 00:54:32 UTC leaves a 2-hour 5-minute 28-second unobserved tail. Two date-boundary rows remain separate; no new article-body checks or comparisons were completed. **Next nominal report/revision opportunity: October 27 at 06:00 America/Chicago (11:00 UTC)**, subject to app/computer availability.

- [October 26, 2026 · 14:00 Chicago · 24-hour edition](daily/2026-10-26/1400-CDT/README.md) · [data](daily/2026-10-26/1400-CDT/data.json) · 148 explicitly timestamped source entries mentioning 17 unique CVEs; partial coverage, compiled late at 21:04:31 UTC. The fixed window ends at 19:00 UTC; input generation at 17:27:38 UTC leaves a 92-minute 22-second unobserved tail. No new article-body comparisons were completed. **Next nominal report/revision opportunity: October 26 at 22:00 America/Chicago (October 27 at 03:00 UTC)**, subject to app/computer availability.

- [October 26, 2026 · 06:00 Chicago · 24-hour edition](daily/2026-10-26/0600-CDT/README.md) · [data](daily/2026-10-26/0600-CDT/data.json) · 75 explicitly timestamped source entries mentioning 7 unique CVEs; partial, retrospective coverage, compiled late at 13:36:45 UTC. The fixed window ends at 11:00 UTC; the retained input was generated later at 11:16:36 UTC. **Next nominal report/revision opportunity: October 26 at 14:00 America/Chicago (19:00 UTC)**, subject to app/computer availability.

- [October 25, 2026 · 22:00 Chicago · 48-hour edition](daily/2026-10-25/2200-CDT/README.md) · [data](daily/2026-10-25/2200-CDT/data.json) · partial source coverage, compiled late on October 26 at 07:21:59 UTC. The fixed period is October 24 at 03:00 UTC through October 26 at 03:00 UTC; the retained input ends 25 minutes 43 seconds before that cutoff. One prior-citation request was refused (HTTP 301); no qualified article comparison was completed. That edition recorded its next nominal reporting opportunity as **October 26 at 06:00 America/Chicago (11:00 UTC)**, subject to app/computer availability.

## Weekly

- [2026-W43 · closing edition](weekly/2026-W43-CLOSE-20261026/README.md) · [data](weekly/2026-W43-CLOSE-20261026/data.json) · October 19 at 00:00 through October 26 at 00:00 Chicago. The source subset has 539 timestamped rows plus 22 rows selected under an explicit UTC date-only calendar convention, mentioning 127 unique CVEs. Compiled retrospectively at 13:36:45 UTC; this separate closing edition preserves the legacy W43 report below.

- [2026-W43 · October19–25,2026](weekly/2026-W43/README.md), with [data](weekly/2026-W43/data.json) and charts. This legacy report retains its original date-only compilation/period and source-attributed claims; catalog inclusion does not reassess them.

## Weekend

- [October 24–25, 2026 · weekend closing edition](weekend/2026-10-24_2026-10-26/README.md) · [data](weekend/2026-10-24_2026-10-26/data.json) · local Saturday 00:00 through Monday 00:00. The partial subset has 72 timestamped main rows mentioning 20 unique CVEs, with one date-boundary row kept separately on watch. Compiled retrospectively at 13:36:45 UTC. The next nominal report/revision opportunity is **October 26 at 14:00 America/Chicago (19:00 UTC)**.

## 2026 monthly editions

- [January 2026 · retrospective](monthly/2026-01/README.md) · [data](monthly/2026-01/data.json) · selective, incomplete coverage.
- [February 2026 · retrospective](monthly/2026-02/README.md) · [data](monthly/2026-02/data.json) · selective, incomplete coverage.
- [March 2026 · retrospective](monthly/2026-03/README.md) · [data](monthly/2026-03/data.json) · selective, incomplete coverage.
- [April 2026 · retrospective](monthly/2026-04/README.md) · [data](monthly/2026-04/data.json) · selective, incomplete coverage.
- [May 2026 · retrospective](monthly/2026-05/README.md) · [data](monthly/2026-05/data.json) · selective, incomplete coverage.
- [June 2026 · retrospective](monthly/2026-06/README.md) · [data](monthly/2026-06/data.json) · selective, incomplete coverage.
- [July 2026 · retrospective](monthly/2026-07/README.md) · [data](monthly/2026-07/data.json) · selective, incomplete coverage.
- [August 2026 · retrospective](monthly/2026-08/README.md) · [data](monthly/2026-08/data.json) · selective, incomplete coverage.
- [September 2026 · retrospective](monthly/2026-09/README.md) · [data](monthly/2026-09/data.json) · selective, incomplete coverage.
- [October 2026 · month to date](monthly/2026-10/README.md) · [data](monthly/2026-10/data.json) · selective, incomplete coverage.

November and December2026 remain planned after calendar close, with no report files, metrics or future facts. October will receive a separate closing edition rather than overwriting this dated month-to-date report.

## Rolling six months

- [April–September2026 · six completed months](six-month/2026-04_2026-09/README.md), with [data](six-month/2026-04_2026-09/data.json) and charts. The saved subset contains794entries,175KEV addition rows and264unique CVEs. These are different units, not incident counts.

Later editions advance monthly; six-month windows overlap. This edition is a retrospective source subset, not complete historical coverage.

## Reading comparisons

Article activity, unique CVEs, KEV additions and campaign counts are different units. Missing source dates are unassigned. Current CNA guidance attached to historical rows is later context, not proof it was known then. CWE/CAPEC links describe qualified taxonomy; actor and mitigation relationships need their own source support. Every edition retains source gaps and a dedicated revision-review state. See [the format](templates/README.md).
