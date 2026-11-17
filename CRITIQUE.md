# Intelligence Hub — Harsh Product Critique

**What this is:** a ruthless, worst-first product review of the live TeamStarWolf Intelligence Hub
(`teamstarwolf.github.io/intelligence-hub/`), driven desk-by-desk as someone who actually wants to
stay on top of security news. Engineering quality is not the subject here — a prior review already
called the build solid. The question this document answers is colder: **would a working analyst open
this every morning instead of CISA KEV, BleepingComputer and a couple of vendor status pages? Mostly,
no — not yet.** Below is why.

Driven on content date 17 Nov 2026: Explorer (`#/explore`), Today (`#/today`), Service health
(`#/status`), History (`#/history`), Patch Tuesday (`#/patch-tuesday`), KEV (`#/kev`), CVE register
(`#/cves`), Actors & malware (`#/actors`), plus deep links, search, mobile, empty state and the
network waterfall.

---

## A) What sucks (worst first)

### A1. The product's depth is invisible on arrival
The top nav is four words — **Explore / Security / Infrastructure / Reference** — and none say what they
open ("Reference" is a 1998→today archive; "Infrastructure" is a status board). The views a security
reader comes for — **Known exploited, CVEs, Advisories, News, Research, Actors & malware, Patch
Tuesday**, *and* the ones that answer half of section D (**Subscribe**, **Data downloads**,
**Reports**) — live in a second, desk-scoped nav row. *(Precise mechanism, from `site/js/main.js`
`updateTabs()`: that row renders only the active desk's views and is hidden entirely when a desk has
fewer than two — which is exactly the case on the default Explore landing.)* So a first-time visitor
lands on a page showing four vague words and **no hint the other fifteen views exist**; they must guess
that "Security" unfolds into eight desks and that feeds/exports hide under "Reference." A redundant
**"Panels"** sidebar duplicates some of this as a third surface. This is the single most damaging flaw
in the product — damaging enough that a reviewer who deliberately opened every desk *still* missed
Subscribe, Data and Reports (see §D). If the reviewer missed them, every user does.

### A2. The Explorer downloads two years of shards to search
*(Corrected after reading `site/js/store.js`: the app is more disciplined than the raw network trace
suggested. `briefs.json` (12.1 MB raw / 1.1 MB gzip) is **lazy-loaded** on the first brief/register/
search, not on paint; the store diffs shards by sha256 and Today reads only `recent.json` plus the
months its window touches. So the critique is narrower, and aimed at one path.)* Opening the
**Explorer** eagerly fetches **all ~24 monthly live shards** (2024-12 → 2026-10) — a single month
(`2026-10.json`) is 1.64 MB raw / 258 KB gzip, so the set is **~6 MB gzip / ~20 MB parsed**, fanned out
as a chatty fetch — because search and filtering run entirely client-side over the whole window with no
server index. Versioned URLs cache well on repeat visits, but the first Explorer search still means
"download two years before the first result," which is heavy on mobile or a cold cache, and the browser
then holds the full window in memory for the session. The fix is an architecture choice (prebuilt
search index / load-on-scroll), not a rewrite — see the plan's P2.1.

### A3. The Patch Tuesday headline number is misleading
`#/patch-tuesday/2026-11` leads with **"1,387 CVEs."** That conflates Microsoft's *full* MSRC CVRF
export — which now sweeps in Azure Linux / Mariner / bundled-package CVEs ("Package CVEs left out: 259
of 1,646 listed") — with the **Windows / Office / Edge patch scope an admin actually acts on**, which
is an order of magnitude smaller. "1,096 issued by Microsoft, 73 Critical" is not the shape of a
Windows Patch Tuesday; it's the shape of a package-advisory dump. The one number every reader anchors
on first is the least trustworthy on the page. The *prioritization recipe below it* (KEV → exploited →
critical RCE in exposed component → CVSS) is genuinely good — it's buried under a scary, wrong total.

### A4. Most desks are a thinner reskin of free primary sources
The KEV desk (`#/kev`) is CISA's catalog with fewer features — **no export control on the desk itself,
where CISA's own page hands you CSV/JSON** (the Hub does publish bulk per-year exports, but on a
separate, nav-buried `#/data` tab — see D4). The CVE register is NVD + FIRST EPSS restated. The status board is 118
vendor status pages you could already bookmark. The brief re-states BleepingComputer / The Register /
CISA. Aggregation has value, but across several desks the Hub *subtracts* capability (export, native
filtering, the vendor's own incident detail) rather than adding judgment. The parts that add real value
(the Patch Tuesday recipe, the single-CVE brief that unifies CVE.org/NVD/EPSS/KEV/Rapid7 links, the
"Act today / KEV due in 14 days" list) are the exception, not the rule.

---

## B) Half-baked or pointless desks/features

### B1. Actors & malware (`#/actors`) — a tag cloud pretending to be threat tracking
The desk's own disclaimer gives it away: *"A name in a headline is a mention, not attribution."* That's
exactly what it is — a **frequency count of group/malware names matched against a vocabulary**.
ShinyHunters = 13 mentions over two years; the long tail is rows with **1 mention** (APT32, MuddyWater,
Storm-0940, NGate…). No TTPs, no campaign, no timeline, no "what did they do this week." An analyst
tracking an actor gets nothing here they couldn't get by searching the Explorer for the name. It looks
like intel and delivers a word tally.

### B2. History / Reference (`#/history`) — a truncated sample dressed as an archive
Every single year from 1998–2026 shows **NIST NVD capped at exactly 1,500 rows.** Real NVD volume is
~25–40k CVEs/year now, so "2026: NVD 1,500" is a hard truncation, not a count — and the coverage
column openly admits "**9 gap, 6 unreachable**" sources for most years. So it is neither complete nor
representative, *and* it's the wrong product for the mission: nobody "staying on top of security news"
needs a thin 2003 archive. It inflates the nav ("1998 to today!") while being dead weight on a daily
tool.

### B3. CVE register "Guidance" column is empty signal
In `#/cves` nearly every row's Guidance reads **"Needs review."** A column where ~99% of values are
identical conveys nothing. Worse, the register surfaces its own data gaps to the user's face —
**"CVE-2026-154010 · UNKNOWN record · CNA lookup failed"** sits at the top of the default sort. If the
label can't distinguish rows, drop it; if "Needs review" is the honest default, don't lead with it.

### B4. Service health (`#/status`) — a wall of green hiding 15 cards that matter
118 status pages tracked, **100 of them "OPERATIONAL."** The useful content is the *15* with a stated
incident — and the page already prints that as a one-line "Needs a look: AWS · Elastic · Tenable…"
summary. Then it makes you **scroll past ~100 "All Systems Operational" cards** to see them in context.
Two more problems: (1) it **mixes live-read and collector-snapshot cards inconsistently** — some say
"read by this browser at 03:02 UTC," neighbors say "snapshot from the collector's read at 02:54 UTC,"
with no visual grouping of which is which; (2) the honest disclaimer concedes it says **"nothing about
your own tenant or region,"** which is the *only* thing you need during an outage. It's a cleaner
Downdetector-for-vendor-pages, not an answer to "is it me?"

---

## C) UX friction

- **C1. Navigation (see A1).** Burying KEV/CVEs/Advisories/News behind "Panels" is friction #1.
- **C2. Label vs content mismatch on Today.** The section headed **"Vendor and government advisories
  (57)"** is full of **status-page INCIDENT rows** — Sumo Logic, Twilio, Zoom, Qualys outages — not
  advisories. The count, the label and the contents disagree. Outages and advisories are different jobs
  and shouldn't share a bucket.
- **C3. The exploitation facet is 88% one value.** "Exploitation unknown (7,314)" of 8,277 entries.
  Filtering by exploitation state barely narrows anything, so the facet mostly occupies rail space.
  The "Known exploited (855) / Reported exploited (108)" split *is* the useful signal — it should be a
  one-click toggle at the top, not the third option in a dropdown dominated by "unknown."
- **C4. Implementation detail leaks into copy.** "Search every loaded entry," "0 entries in the live
  window," "No loaded entry matches" — "loaded" is an internals word. The user doesn't know or care
  that data is client-side paged; it reads like a bug.
- **C5. Deep-link clutter.** Hitting `#/cve/CVE-2026-125350` renders the single-CVE brief (good) but
  *also* dumps the full 2,884-row register underneath it ("Page 1 of 116"). A permalink to one CVE
  should be that CVE, not that CVE plus the entire index.
- **C6. Duplicate stories, no clustering.** The same story lands three–four times from different
  outlets on one day ("California sues OpenAI…" via CyberScoop, The Record, BleepingComputer;
  "Project Zero cuts to 30 days" via Dark Reading + BleepingComputer). The feed shows all of them as
  separate cards. Reading the news here means re-reading the same headline.
- **C7. Press feed carries affiliate/SEO filler.** The Today press list includes Hackread crypto
  fluff — "Five Situations Where Crypto Sentiment Deserves a Closer Look," "How XRP has Become a Go-To
  Institutional Altcoin." That is not security news; it's content-marketing bleed from the source RSS,
  and it erodes trust in the whole feed.

*(What works, in fairness: the mobile layout collapses the huge facet rail to a "Filters" button and
reads cleanly at 375 px; the empty state is clear ("No loaded entry matches. Clear a filter or choose
another year."); theme toggle and the "Act today / KEV due in 14 days" block are both good.)*

---

## D) What's missing (what a real analyst actually wants)

1. **Push I can tune.** *(Correction after reading the code: the Hub does ship 3 Atom feeds —
   `feeds/kev.xml`, `incidents.xml`, `patch-calendar.xml` — surfaced in a `#/subscribe` tab I never
   found while driving the live app, because the nav buries it. The gap is narrower than "no feeds.")*
   The feeds are **global** (all KEV, all incidents); there is **no per-vendor/per-watchlist feed** and
   no email/Slack push. A daily-habit tool has to come to you *about the things you care about* — that
   it can't do, and it's the strongest evidence for how badly the navigation hurts the product (A1).
2. **Watchlists / saved searches.** You built a 60-facet filter rail and then can't **save** a view.
   "Alert me on Fortinet / Ivanti / my vendor stack" is the obvious ask and it's absent.
3. **"Affects me" layer.** No way to upload a vendor/product list and see only relevant KEV/CVE/advisory
   items. Every analyst's first question is "is this in my environment?" — the Hub can't help.
4. **Export the view I'm looking at.** *(Correction: per-year CSV + JSONL + tags-CSV + manifest exports
   do exist, on a `#/data` tab — also hidden by the nav.)* What's missing is **exporting the current
   filtered result set** — the bulk per-year files don't help once I've filtered to 40 rows — and the
   KEV desk itself still has no export control where CISA's own catalog hands you one.
5. **Story clustering / dedup** (see C6).
6. **Change tracking on a CVE.** EPSS moved, CISA added it to KEV, CVSS was revised — a CVE brief should
   show *what changed and when*, not just the current snapshot.
7. **"Why you should care" per item.** The brief links out authoritatively but rarely says, in one line,
   *who is affected and what to do*. That one line is the entire value of a human-curated feed over a raw
   aggregator.

---

## E) Concrete make-it-better moves (prioritized)

1. **Fix the nav (cheap, highest impact).** Promote KEV, CVEs, Advisories, News, Patch Tuesday into the
   top bar. Delete or demote "Panels." No one should hunt for the KEV desk.
2. **Fix the Patch Tuesday headline.** Lead with the number admins act on (Windows/Office/Edge CVEs),
   show the full-CVRF package total as a secondary, clearly-labeled figure. Keep the prioritization
   recipe — it's the best thing on the page.
3. **Ship a watchlist + RSS/email digest.** This is the one feature that converts "a site I sometimes
   open" into "a habit." Everything else is secondary to retention.
4. **Cut first-paint weight.** Lazy-load `briefs.json` and older months on demand; Today should not need
   24 months + a 12 MB brief blob. Target <1 MB to first meaningful paint; load history only when the
   History desk is opened.
5. **Cluster duplicate stories** across outlets into one card with "also reported by: …".
6. **Collapse the status board to problems-first.** Show the ~15 incident cards; hide the green wall
   behind a "show all operational" toggle. Group live-read vs snapshot cards explicitly.
7. **Make the exploitation split a one-click toggle** ("Known/Reported exploited only") instead of a
   dropdown drowned in "unknown."
8. **Kill the dead weight or make it real.** Either bury Actors and History, or make Actors link mentions
   to campaigns/TTPs and give History an honest "sample, not complete" header instead of fake 1,500 caps.
9. **Drop or fix the "Needs review" guidance label.** A column that's identical on every row is clutter.
10. **Scrub the press feed** of affiliate/crypto filler at ingest (source all/deny rules per RSS).

---

## F) Blunt verdict

The Intelligence Hub is a well-engineered aggregator wearing the costume of an intelligence product, and
right now it is **closer to a worse-organized reskin of free primary sources than a tool that beats
reading them directly.** Three or four things are genuinely good — the Patch Tuesday prioritization
recipe, the unified single-CVE brief, the "KEV due in 14 days" nudge, the vendor-status board — and they
are buried behind a nav that hides most of the product on arrival (feeds, exports and digests
included — see D), a misleading headline CVE count, an Explorer that downloads two years of shards to
search, and whole desks (Actors-as-tag-cloud, History-as-truncated-archive) that add nav bulk and no
daily value. It would **not** become my morning habit, because it gives me little reason to return —
the push it ships is global, not "my vendors," and there's no watchlist or "affects me" — and makes me
re-read the same four headlines I already saw on BleepingComputer. The bones are strong enough that
the fix is mostly editorial and product discipline, not engineering: **surface the good desks, delete the
pointless ones, lead with honest numbers, and give me a reason to come back without visiting.** Do that
and it's a daily tab. As shipped, it's an impressive demo I'd open once.
