# Intelligence Hub — Improvement Plan

Companion to `CRITIQUE.md`. The critique was driven from the outside (the live app only).
Writing this plan meant reading the code, and that changed the picture in ways worth stating up
front — because the single biggest correction *is itself the headline problem*.

---

## 0. Corrected baseline — read this first

While driving the live app for the critique I concluded the product was "missing" push feeds,
exports and digests. **It is not. All three already exist** — I never found them live because the
navigation hides them (see §1). For an improvement plan to be honest it has to start by crediting
what's there and narrowing the real gaps:

| Critique said "missing" | Reality in the code | So the real task is |
|---|---|---|
| No RSS/Atom, no push | **3 Atom feeds** ship today: `feeds/kev.xml`, `feeds/incidents.xml`, `feeds/patch-calendar.xml`, rebuilt by the collector (`intelligence_hub/shards.py`, surfaced in `#/subscribe`). | Make them **discoverable** and add **per-watchlist** feeds, not "add feeds." |
| No export | **Per-year CSV + JSONL + tags-CSV + manifest + data dictionary** (`intelligence_hub/exports.py`, surfaced in `#/data`). | Add **export-the-current-filtered-view**; surface the Data tab. |
| No digests | **Daily/weekly/weekend/fortnightly/monthly/quarterly/six-month report editions** (`reports/`, `#/reports`). | Surface them; wire a notification. |
| First load pulls the 12 MB `briefs.json` | `briefs.json` is **lazy-loaded** on first brief/register/search (`site/js/store.js` `loadBrief`); `store` does **sha256 incremental shard diffing**. | Target the **Explorer's full-window shard load** specifically, not "the app is heavy." |

**The meta-finding:** a reviewer who deliberately opened every desk still missed Subscribe, Data
downloads and Reports. If the reviewer missed them, every first-time user does. The engineering is
better than the critique assumed; the **product packaging is the problem**. That reframes the work
as ~70% editorial/front-end and ~30% new features, which is good news — most of the value is cheap.

What genuinely remains weak or absent (the honest gap list): discoverability/IA, the Patch Tuesday
headline, per-user watchlists + "my vendors" filtering, story de-duplication, per-CVE change
history, the Explorer's load path, and two desks (Actors, History) that don't earn their nav slot.

---

## How this plan is ordered

Three priority bands, highest ROI first. Each item: **problem** (desk + file), **change**,
**effort** (S ≤ half-day, M ≈ 1–3 days, L > 3 days), **payoff**. Effort assumes the existing
vanilla-JS / static-build architecture is kept (no backend) unless noted.

---

## P0 — Packaging and honesty (cheap, do first; mostly `site/` + copy)

### P0.1 Rebuild the navigation so the product is visible on arrival **[M]**
- **Problem:** `site/index.html` has two nav rows — desks (Explore/Security/Infrastructure/Reference)
  and a per-desk views row — but `site/js/main.js` `updateTabs()` hides the views row whenever the
  active desk has `< 2` views. The landing desk (Explore) has one view, so **on arrival you see four
  vague words and zero hint that KEV, CVEs, Patch Tuesday, Subscribe, Data or Reports exist.** A
  third surface, the "Panels" sidebar (`#sidebar-toggle`), duplicates navigation and confuses rather
  than clarifies.
- **Change:**
  1. Always render the views row; on the Explore landing, show the full desk menu (don't collapse).
     Change the `row.hidden = shown < 2` rule in `main.js` to keep the row and, for single-view
     desks, show the *other desks'* top views as a "jump to" strip.
  2. Rename desks to what's inside them: **Explore · Threats · Service health · Archive & data**
     (or similar). "Security/Infrastructure/Reference" describe the builder's taxonomy, not the
     reader's intent. Map `data-desk` labels in `index.html`; update `VIEW_DESK`/`TITLES` in `main.js`.
  3. Promote **Subscribe** and **Data downloads** out of the "Reference" tail into a persistent
     top-bar affordance (a "Feeds & data" button beside Theme). They answer three "missing" items and
     nobody sees them.
  4. Demote or delete the "Panels" sidebar; fold anything unique in it into the views row.
- **Payoff:** The highest-leverage change in the whole plan. Turns hidden features into used ones at
  near-zero data cost.

### P0.2 Fix the Patch Tuesday headline number **[S]**
- **Problem:** `#/patch-tuesday/2026-11` leads with **"1,387 CVEs."** `intelligence_hub/patch_tuesday.py`
  already excludes Azure Linux / CBL-Mariner / OSS package CVEs ("259 of 1,646 left out"), but the
  headline still bundles **every CNA plus Chromium-in-Edge** into one total an order of magnitude
  above what a Windows admin recognizes as Patch Tuesday.
- **Change:** Split the headline in `patch_tuesday.py` (count fields) and `site/js/views/patch-tuesday.js`
  (render): lead with **"Windows / Office / Edge: N CVEs"** (Microsoft-product rows, Edge/Chromium
  broken out), then show **"Full MSRC document: 1,387"** as a labeled secondary with a one-line
  explanation of what it includes. Keep the excellent prioritization recipe exactly as is.
- **Payoff:** The first number on the page stops being the least trustworthy one. Restores credibility.

### P0.3 Service health: problems-first, not a wall of green **[S–M]**
- **Problem:** `#/status` renders ~100 "All Systems Operational" cards you scroll past to reach the
  ~15 that matter — which the "Needs a look:" line already named. Live-read vs collector-snapshot
  cards are interleaved with no grouping.
- **Change (in `site/js/views/status.js`):** Default to **incidents + maintenance only**; put
  "Show all 118 (incl. operational)" behind a toggle. Group/sort by severity
  (major → minor → maintenance → operational). Add a small **"live" vs "snapshot" badge** and sort
  live-read cards first so the freshness model is legible. (`?wall=1` wall mode already exists for
  the kiosk case — keep it, and document it in `#/method`.)
- **Payoff:** The board becomes answer-first for "what's broken right now."

### P0.4 Exploitation signal: promote the useful split, retire the dead facet **[S]**
- **Problem:** The Explorer "Exploitation" dropdown is 88% one value ("unknown", 7,314/8,277), so it
  barely filters. The real signal — Known (855) / Reported (108) exploited — is buried as options 2–3.
- **Change:** In `site/index.html` / `site/js/filters.js`, replace the dropdown's prominence with a
  top-of-results **"Exploited only (Known · Reported)"** toggle chip; keep the full dropdown for
  completeness but stop it occupying prime rail space.
- **Payoff:** One click to the rows that matter most.

### P0.5 Stop mislabeling outages as advisories **[S]**
- **Problem:** On `#/today` the section headed **"Vendor and government advisories (57)"** is full of
  status-page **incident** rows (Sumo Logic, Twilio, Zoom). Label, count and contents disagree.
- **Change:** In `site/js/views/today.js`, split that block into **"Advisories"** (kind=advisory) and
  **"Service-health incidents"** (kind=incident), each with its own honest count. The data already
  carries `kind`, so this is a grouping change, not a data change.
- **Payoff:** Removes a credibility-denting inconsistency on the most-viewed desk.

### P0.6 Scrub press-feed filler at ingest **[S]**
- **Problem:** The Today press list carries Hackread crypto/affiliate filler ("XRP institutional
  altcoin", "Crypto Sentiment"). Content-marketing bleed erodes trust in the feed.
- **Change:** Add per-source title/keyword deny rules in `config/sources.json` (or the tagging step)
  to drop non-security items; `intelligence_hub/collect.py` already filters intake, so extend its rules.
- **Payoff:** The feed reads like security news, not an RSS dump.

### P0.7 De-leak implementation copy **[S]**
- **Problem:** "Search every loaded entry", "0 entries in the live window", "No loaded entry matches",
  "Reading the saved index" expose internals.
- **Change:** Reword in `site/index.html` and the view renderers to reader language ("Search all
  entries", "No matches — clear a filter or pick another year").
- **Payoff:** Small polish; stops reading like a debug build.

### P0.8 Kill the empty "Needs review" guidance column / fix deep-link clutter **[S]**
- **Problem:** `#/cves` shows "Needs review" on ~99% of rows (no signal), and surfaces
  "CNA lookup failed / UNKNOWN record" at the top of the default sort; deep-linking `#/cve/<id>`
  renders the brief *plus* the full 2,884-row register underneath.
- **Change (`site/js/views/cves.js`):** Drop the guidance column unless it has >1 distinct value in
  view; sort `UNKNOWN record` rows to the bottom by default; when a single CVE id is routed, render
  **only** that brief with a "Back to register" link, not the whole index.
- **Payoff:** The register stops advertising its own gaps and the permalink behaves like a permalink.

---

## P1 — The real feature gaps (new build, static-friendly)

### P1.1 Watchlists + "my vendors" + per-watch feeds **[M–L]**
- **Problem:** The 60-facet rail can't be **saved**, and the 3 Atom feeds are global (all KEV, all
  incidents) — there's no "Fortinet + Ivanti only." This is the #1 reason it won't become a habit.
- **Change:**
  1. Client-side **saved searches / watchlists** in `localStorage` (vendor/product/CVE/keyword sets),
     surfaced as one-click chips on the Explorer and highlighted in list rows.
  2. Make the existing **"new since last visit"** baseline (already in `today.js`) *watchlist-aware*:
     "3 new on your watchlist" at the top of Today.
  3. Static-site push can't do per-user email, but **two achievable feeds**: (a) make the Atom feeds
     filterable by a query the feed reader can't do, by pre-generating a small set of popular-vendor
     feeds in `shards.py`; (b) ship a GitHub Action that emails/Slacks **the owner** a daily watchlist
     digest (the Reports pipeline already produces editions to attach).
- **Payoff:** Converts "a site I remember to check" into "a thing that tells me when my stack is hit."

### P1.2 De-duplicate / cluster stories across outlets **[M]**
- **Problem:** "California sues OpenAI" and "Project Zero 30-day" each appear 3–4× from different
  outlets as separate cards; reading the news here means re-reading headlines.
- **Change:** In the tagging/build step (`intelligence_hub/tagging/`), cluster same-event rows
  (shared CVE set + title similarity + same day) into one primary card with an "also reported by:
  BleepingComputer, The Record (+2)" line. Render the cluster in `today.js` / `explore.js`.
- **Payoff:** The feed density stops being an illusion; one scroll = the day's distinct events.

### P1.3 Per-CVE change history **[M]**
- **Problem:** The single-CVE brief is a strong feature but shows only the current snapshot. Analysts
  care about *what changed*: EPSS moved, CISA added it to KEV, CVSS was revised.
- **Change:** The collector already runs every few hours and diffs shards by sha256; persist a small
  per-CVE event log (added to KEV on date X, EPSS 0.2%→1.0% on date Y) in `briefs.json` and render a
  timeline in `cves.js` `briefBody`.
- **Payoff:** Turns the brief from a mirror of NVD into something NVD doesn't give you.

### P1.4 Export the current filtered view **[S–M]**
- **Problem:** Exports exist but only as whole-year bulk files (`#/data`). You can't export "the 40
  rows I just filtered to."
- **Change:** Add a **"Download these results (CSV/JSON)"** button to the Explorer results header,
  generated client-side from the in-memory filtered set (reuse `exports.py` column order for parity).
- **Payoff:** Closes the loop between the powerful filters and getting data out.

---

## P2 — Earn the nav slot, or lose it (bigger / architectural)

### P2.1 Make the Explorer's load path lighter **[L]**
- **Problem:** The Explorer eagerly fetches **all ~24 monthly live shards** (~6 MB gzip) so it can
  search/filter the whole window client-side (`store.js` `articleShards`). Defensible for a static
  site, but it's the one genuinely heavy path.
- **Change (pick one):** (a) build a compact **prebuilt search index** (title + tags only, a few
  hundred KB) loaded first, hydrating full rows on demand; (b) load newest-month-first and fetch
  older months on scroll/filter; (c) ship a tiny WASM/FlexSearch index. Keep the no-backend model.
- **Payoff:** Explorer first-result time drops from "download two years" to "sub-second."

### P2.2 Make Actors real, or demote it **[M to fix / S to demote]**
- **Problem:** `#/actors` is a headline name-frequency tally ("a mention, not attribution") — a tag
  cloud, with a long tail of single-mention rows. It occupies a prime view slot.
- **Change:** Either (fix) link each actor to its library page with a **campaign/TTP rollup** (group
  the entries into events, show ATT&CK techniques observed, a timeline), or (demote) move it to a
  facet of the Explorer and reclaim the nav slot. Don't ship a tag cloud as "threat tracking."

### P2.3 Give History an honest frame, or bury it **[S]**
- **Problem:** `#/history` shows NVD capped at exactly **1,500 rows/year** (real volume ~25k+) with
  "9 gap, 6 unreachable" sources — a truncated sample dressed as a 1998→today archive, and the wrong
  product for a daily-news tool.
- **Change:** Relabel the header to "a curated sample per year, not a complete index" and state the
  cap explicitly (the coverage matrix already tracks this); move History under "Archive & data"
  rather than a top desk, so it stops competing with the daily desks for attention.

---

## Sequencing

- **Milestone 1 — "Make it honest and findable" (P0.1, P0.2, P0.5, P0.7, P0.8):** one focused
  front-end/copy pass. Biggest perceived-quality jump, no data pipeline risk. Ship first.
- **Milestone 2 — "Make it answer-first" (P0.3, P0.4, P0.6, P2.3):** status board, exploitation
  toggle, feed hygiene, History reframing.
- **Milestone 3 — "Make it a habit" (P1.1, P1.2, P1.4):** watchlists, clustering, export-view. This
  is the retention milestone — the difference between "impressive demo" and "daily tab."
- **Milestone 4 — "Depth" (P1.3, P2.1, P2.2):** CVE change history, Explorer index, Actors rework.

## What NOT to build (already shipped — surface, don't rebuild)
Atom feeds (§0), per-year CSV/JSONL exports (§0), the daily→six-month Reports pipeline (§0),
lazy brief loading, incremental sha256 shard diffing, wall mode (`?wall=1`), the Patch Tuesday
prioritization recipe, the unified single-CVE brief, the "KEV due in 14 days" nudge, mobile filter
collapse. These are good; the plan's job is to put them in front of the reader, not redo them.

## One-line target state
When a reader lands, the depth is visible in one glance; every headline number is one an analyst
trusts; the board and feed lead with what's wrong and what's new *for them*; and they leave with a
watchlist that brings them back — without paying a two-year download for the privilege.
