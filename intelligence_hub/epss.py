"""FIRST's EPSS scores for the CVEs the Hub shows (WP-03).

The Exploit Prediction Scoring System (EPSS) is published by FIRST with Empirical Security: a
daily probability that a CVE is exploited in the next 30 days, with its percentile among every
scored CVE. The collector reads the API at api.first.org once a run for the CVEs of the brief
set, in sorted batches of BATCH ids, and keeps each score with its percentile, its score date
and the model version. The daily CSV is not read: it is reached through a redirect and is
gzip-encoded, both of which collect.fetch refuses.

FIRST asks for attribution when EPSS data is used in publications or products
(https://www.first.org/epss/faq); every value the Hub shows names FIRST. The API carries no
model version: MODEL is the version the daily CSV header named on MODEL_CONFIRMED
(#model_version in https://epss.empiricalsecurity.com/epss_scores-current.csv.gz), and a new
model is a reviewed change of that constant. A value keeps the model it was scored under, and
the Hub never computes a change in score across model versions.

A CVE's retained value (the brief's epss block, kept in the retained projections and in the
deployed briefs file) survives a failed read: a batch that fails leaves every CVE in it as it
was, and the first failed batch ends the run's reads. A CVE the API did not score on the day
reads as no score, never as 0.
"""
from datetime import date
import json
import re
import urllib.parse

API_URL = "https://api.first.org/data/v1/epss"
MODEL = "v2026.06.15"
MODEL_CONFIRMED = "2026-11-12"
MODEL_FORM = re.compile(r"v[0-9]{4}\.[0-9]{2}\.[0-9]{2}")
BATCH = 100
MAX_BATCHES = 150   # mitigations.MAX_RECORDS / BATCH: the whole brief set in one run
RESPONSE_MAX_BYTES = 256 * 1024
DECIMALS = 5
CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,8}")
SCORE_KEYS = {"score", "percentile", "date", "model"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _reject_constant(_value):
    raise ValueError("Nonfinite JSON numbers are not accepted.")


def batch_url(cves):
    """The API address for one batch: the ids joined with commas in the cve parameter, the limit the
    batch size, in the canonical form collect.safe_url gives (the commas percent-encoded)."""
    require(0 < len(cves) <= BATCH and all(isinstance(cve, str) and CVE.fullmatch(cve) for cve in cves), "Invalid EPSS batch.")
    return API_URL + "?" + urllib.parse.urlencode([("cve", ",".join(cves)), ("limit", str(BATCH))])


def _fraction(value):
    """A probability or percentile from the API's decimal string, rounded to DECIMALS, or None."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    if not 0 <= number <= 1:
        return None
    return round(number, DECIMALS)


def _day(value):
    if not isinstance(value, str) or len(value) != 10:
        return None
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError:
        return None


def valid_score(value):
    """True for a score block as the Hub stores it: {score, percentile, date, model}, each in range."""
    if not isinstance(value, dict) or set(value) != SCORE_KEYS:
        return False
    for key in ("score", "percentile"):
        if type(value[key]) not in (int, float) or not 0 <= value[key] <= 1:
            return False
    return (_day(value["date"]) == value["date"] and isinstance(value["model"], str) and
            MODEL_FORM.fullmatch(value["model"]) is not None)


def parse_scores(raw, cves, model=MODEL):
    """{cve: block} for the requested CVEs the API scored.

    A requested CVE the answer leaves out has no score on that date. An entry with an unreadable
    score, percentile or date is left out the same way. A document that is not the API's answer
    refuses the whole batch.
    """
    value = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    require(isinstance(value, dict) and value.get("status") == "OK" and isinstance(value.get("data"), list) and
            len(value["data"]) <= 2 * BATCH, "Unexpected EPSS API response.")
    wanted = set(cves)
    scores = {}
    for item in value["data"]:
        if not isinstance(item, dict) or item.get("cve") not in wanted or item["cve"] in scores:
            continue
        score, percentile, day = _fraction(item.get("epss")), _fraction(item.get("percentile")), _day(item.get("date"))
        if score is None or percentile is None or day is None:
            continue
        scores[item["cve"]] = {"score": score, "percentile": percentile, "date": day, "model": model}
    return scores


def collect_scores(cves, fetch, *, limit=MAX_BATCHES, model=MODEL):
    """(scores, report) for the CVEs, read in sorted batches of BATCH.

    scores maps every CVE of a completed batch to its block, or to None when the API gave it no
    score on the day. A CVE of a batch that failed, or past the batch limit, is absent, so its
    retained value stays. The first failed batch ends the run's reads; the next run reads again.
    """
    from .collect import failure_reason
    ids = sorted({cve for cve in cves if isinstance(cve, str) and CVE.fullmatch(cve)})
    batches = [ids[start:start + BATCH] for start in range(0, len(ids), BATCH)]
    scores = {}
    report = {"status": "ok", "model": model, "cves": len(ids), "batches": len(batches), "completed": 0, "scored": 0, "date": None, "failed": None}
    dates = set()
    for batch in batches[:limit]:
        try:
            found = parse_scores(fetch(batch_url(batch), RESPONSE_MAX_BYTES, accept="application/json"), batch, model)
        except (OSError, ValueError, TypeError, RecursionError) as error:
            report["failed"] = failure_reason(error, "the EPSS API read failed")
            break
        for cve in batch:
            scores[cve] = found.get(cve)
        report["completed"] += 1
        report["scored"] += len(found)
        dates.update(item["date"] for item in found.values())
    if report["failed"] is None and len(batches) > limit:
        report["failed"] = "batch limit of " + str(limit) + " reached"
    if report["failed"] is not None:
        report["status"] = "partial" if report["completed"] else "failed"
    report["date"] = max(dates) if dates else None
    return scores, report


def skipped(cves, reason):
    """The report of a run that read no score (an offline build)."""
    ids = [cve for cve in cves if isinstance(cve, str) and CVE.fullmatch(cve)]
    return {"status": "skipped", "model": MODEL, "cves": len(set(ids)), "batches": 0, "completed": 0, "scored": 0, "date": None, "failed": reason}
