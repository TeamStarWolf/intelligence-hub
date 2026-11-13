"""Service health: official vendor status pages, cloud health feeds and internet outage signals.

config/status.json is the registry. Every source in it is an official, free, machine-readable
status source: a Statuspage-format JSON API, a cloud provider's own incident JSON or RSS feed, or
an internet-measurement API (IODA from Georgia Tech, and Cloudflare Radar's outage annotations
when the owner has added a token). Complaint counts, scraped HTML pages and signed-in tenant APIs
are never read.

Each run reads every source once through the collector's bounded fetch (its deadline, byte bound,
no-redirect rule and safe-URL check), normalizes what came back into incident rows, folds them into
the month files a previous run published, and writes four kinds of file under data/v7/status/:

    current.json   every tracked source with its overall indicator, open incidents and fetch time
                   (the one file the live board reads), plus the vendors that are linked only
    YYYY-MM.json   incident history by start month, deduplicated on source and incident id, with a
                   later update folded into the row it updates; the current month and the 12 before
    outages.json   IODA outage events of the last 24 hours, and Radar outage annotations
    index.json     the month files, per-source coverage and the board digest

Incidents of impact minor or above also become Explorer rows (origin "service-status", kind
"incident"), tagged with the outage event type and the source's vendor.

A failed read never blanks a source: it keeps the last good snapshot with its own fetch time and
records the failure. Vendor incident lists reach back only so far (Statuspage returns the 50 most
recent), so the published month files are the only copy of older rows and are never given up to a
read failure: every status file the previous index lists is read and checked first, and a run that
cannot read one of them holds (the collector stops and the deployed publication stays). A failure
later in this step publishes the previous status files again byte for byte and never blocks the feed.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
import hashlib
import html
import http.client
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from . import collect
from .collect import published, require, safe_url, text

REGISTRY = "config/status.json"
REGISTRY_MAX_BYTES = 128 * 1024
CACHE = "status-cache.json"
CACHE_MAX_BYTES = 16 * 1024 * 1024
SCHEMA_VERSION = 7
DIRECTORY = "status"
GROUPS = ("security-platforms", "cloud-and-saas", "developer-services", "internet")
# class -> the formats it may use; format -> the endpoint names it reads.
CLASSES = {"statuspage": {"statuspage"}, "json": {"aws", "google", "slack", "salesforce", "statusio", "azure-devops", "heroku", "betterstack", "microsoft"},
           "rss": {"azure", "zscaler", "statuspage-rss"}, "ioda": {"ioda"}, "radar": {"radar"}}
ENDPOINTS = {"statuspage": {"status", "summary", "incidents"}, "aws": {"events"}, "google": {"incidents"}, "slack": {"current", "history"},
             "salesforce": {"active"}, "statusio": {"status"}, "azure-devops": {"health"}, "heroku": {"current"}, "betterstack": {"index"},
             "azure": {"feed"}, "zscaler": {"feed"}, "statuspage-rss": {"status", "feed"}, "microsoft": {"posts"}, "ioda": {"events"}, "radar": {"outages"}}
OUTAGE_FORMATS = {"ioda", "radar"}
INDICATORS = ("none", "minor", "major", "critical", "maintenance", "unknown")
IMPACTS = ("none", "minor", "major", "critical")
STATUSES = ("investigating", "identified", "monitoring", "resolved", "other")
EXPLORER_IMPACTS = ("minor", "major", "critical")
RANK = {"none": 0, "maintenance": 0, "unknown": 0, "minor": 1, "major": 2, "critical": 3}
MONTHS_KEPT = 13
MAX_SOURCES = 120
MAX_PAGE_ONLY = 40
MAX_PARSED = 500
MAX_OPEN = 25
MAX_MONTH_ROWS = 6000
MAX_OUTAGE_ROWS = 300
NAME_MAX = 200
SUMMARY_MAX = 280
DESCRIPTION_MAX = 160
COMPONENT_MAX = 120
COMPONENTS_MAX = 12
ID_MAX = 200
ORIGIN = "service-status"
DATE_BASIS = "status page incident start"
SOURCE_PREFIX = "status-"
LIVE_PATH = "/api/v2/status.json"
RADAR_TOKEN_ENV = "CLOUDFLARE_RADAR_TOKEN"
RADAR_TOKEN = re.compile(r"[A-Za-z0-9_-]{20,200}")
IODA_WINDOW = timedelta(hours=24)
RADAR_DATE_RANGE = "7d"
SOURCE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")
VOCAB_ID = re.compile(r"(?:vendor|product):[a-z0-9][a-z0-9-]{0,80}")
SAFE_ROW_ID = re.compile(r"[A-Za-z0-9._:-]{1,60}")
MONTH_PATH = re.compile(r"status/([0-9]{4}-(?:0[1-9]|1[0-2]))\.json")
PATH = re.compile(r"status/(?:current|outages|index|[0-9]{4}-(?:0[1-9]|1[0-2]))\.json")
# Shards that change on every run only because of their clocks; publication follows the board and
# outage digests instead, which leave the clocks out.
QUIET = ("status/current.json", "status/index.json", "status/outages.json")
INCIDENT_FIELDS = ("source", "vendor", "id", "name", "status", "status_raw", "impact", "impact_raw", "components", "started", "updated",
                   "resolved", "url", "summary")
NOTES = [
    "Each status entry is the vendor's own statement on its official status page or feed, read by the collector. It says nothing about any one customer's tenant, region or account.",
    "Statuspage incident lists return the 50 most recent incidents, so a busy vendor's history starts later than twelve months; index.json gives the first incident each source's history holds.",
    "Impact is the vendor's level where the source gives one. A source that files an incident without a level is shown as minor, the lowest level that is still an incident, and impact_raw is null.",
    "IODA rows are measurements of reachability by country from Georgia Tech's Internet Outage Detection and Analysis project. A row is a signal to read on IODA's dashboard, not a confirmed outage.",
    "The collector runs when GitHub starts the scheduled workflow, which is every few hours in practice; data/v7/index.json records the observed gap. On the Service health view the board reads the CORS-open status pages again from the visitor's browser.",
]


class StatusError(ValueError):
    """The registry or a status file does not meet its rules."""


class StatusHold(StatusError):
    """A status file the previous publication lists could not be read or checked, so this run must
    not replace the publication: building without it would drop incident history."""


def _check(condition, message):
    if not condition:
        raise StatusError(message)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Registry -----------------------------------------------------------------------------------

def validate_registry(registry):
    _check(isinstance(registry, dict) and registry.get("schema_version") == 1 and
           set(registry) == {"schema_version", "comment", "probed_at", "groups", "sources", "page_only"}, "config/status.json has unexpected fields.")
    _check(isinstance(registry["probed_at"], str) and published(registry["probed_at"]) == registry["probed_at"], "Invalid probed_at date.")
    _check([group.get("id") for group in registry["groups"] if isinstance(group, dict)] == list(GROUPS) and
           all(set(group) == {"id", "label"} and isinstance(group["label"], str) and 0 < len(group["label"]) <= 60 for group in registry["groups"]),
           "The status groups must be " + ", ".join(GROUPS) + ".")
    sources = registry["sources"]
    _check(isinstance(sources, list) and 1 <= len(sources) <= MAX_SOURCES, "Invalid status source list.")
    seen = set()
    keys = {"id", "name", "vendor", "group", "desk", "class", "format", "endpoints", "home", "cors", "library"}
    for source in sources:
        _check(isinstance(source, dict) and set(source) == keys, "A status source has unexpected fields.")
        _check(isinstance(source["id"], str) and SOURCE_ID.fullmatch(source["id"]) and source["id"] not in seen, "Invalid status source id.")
        seen.add(source["id"])
        _check(isinstance(source["name"], str) and 0 < len(source["name"]) <= 80, "Invalid status source name: " + source["id"])
        for field in ("vendor", "library"):
            _check(source[field] is None or isinstance(source[field], str) and VOCAB_ID.fullmatch(source[field]), "Invalid " + field + ": " + source["id"])
        _check(source["vendor"] is None or source["vendor"].startswith("vendor:"), "A status vendor must be a vendor id: " + source["id"])
        _check(source["group"] in GROUPS, "Invalid status group: " + source["id"])
        _check(source["desk"] == "infrastructure", "A status source's rows sit on the infrastructure desk: " + source["id"])
        _check(source["class"] in CLASSES and source["format"] in CLASSES[source["class"]], "Invalid status class or format: " + source["id"])
        _check((source["group"] == "internet") == (source["format"] in OUTAGE_FORMATS), "Only outage signals sit in the internet group: " + source["id"])
        endpoints = source["endpoints"]
        _check(isinstance(endpoints, dict) and set(endpoints) == ENDPOINTS[source["format"]], "Invalid endpoints: " + source["id"])
        for url in endpoints.values():
            _check(isinstance(url, str) and safe_url(url) == url, "A status endpoint is not a canonical public HTTPS URL: " + source["id"])
        if "status" in endpoints and source["format"] in {"statuspage", "statuspage-rss"}:
            _check(urllib.parse.urlsplit(endpoints["status"]).path == LIVE_PATH, "A Statuspage status endpoint must end in " + LIVE_PATH + ": " + source["id"])
        _check(isinstance(source["home"], str) and safe_url(source["home"]) is not None, "Invalid status home page: " + source["id"])
        _check(type(source["cors"]) is bool, "cors must be true or false: " + source["id"])
    page_only = registry["page_only"]
    _check(isinstance(page_only, list) and len(page_only) <= MAX_PAGE_ONLY, "Invalid page_only list.")
    for item in page_only:
        _check(isinstance(item, dict) and set(item) == {"id", "name", "vendor", "home", "reason"}, "A page_only entry has unexpected fields.")
        _check(isinstance(item["id"], str) and SOURCE_ID.fullmatch(item["id"]) and item["id"] not in seen, "Invalid page_only id.")
        seen.add(item["id"])
        _check(isinstance(item["name"], str) and 0 < len(item["name"]) <= 80, "Invalid page_only name.")
        _check(item["vendor"] is None or isinstance(item["vendor"], str) and VOCAB_ID.fullmatch(item["vendor"]) and item["vendor"].startswith("vendor:"), "Invalid page_only vendor.")
        _check(item["home"] is None or isinstance(item["home"], str) and safe_url(item["home"]) is not None, "Invalid page_only home.")
        _check(isinstance(item["reason"], str) and 0 < len(item["reason"]) <= 300, "Invalid page_only reason.")
    return registry


def load_registry(root):
    path = Path(root) / REGISTRY
    raw = path.read_bytes()
    _check(len(raw) <= REGISTRY_MAX_BYTES, "config/status.json exceeds its byte bound.")
    return validate_registry(json.loads(raw.decode("utf-8"), parse_constant=collect.reject_constant))


def live_url(source):
    """The Statuspage-format status.json a visitor's browser may read for this source, or None."""
    endpoint = source["endpoints"].get("status")
    if source["cors"] and source["format"] in {"statuspage", "statuspage-rss"} and endpoint:
        return endpoint
    return None


def live_hosts(registry):
    """Every host the live board reads: the connect-src list site/index.html must carry."""
    return sorted({urllib.parse.urlsplit(url).hostname for url in (live_url(source) for source in registry["sources"]) if url})


def tracked(registry):
    return [source for source in registry["sources"] if source["format"] not in OUTAGE_FORMATS]


# Text and time helpers ---------------------------------------------------------------------

def clean(value, maximum):
    """Plain text: markup and Markdown emphasis removed, whitespace folded, bounded."""
    if not isinstance(value, str):
        return ""
    value = re.sub(r"\*\*|__|`|^#+\s*", " ", value, flags=re.M)
    return text(value, maximum)


def stamp(value):
    """A UTC timestamp from an ISO or RFC 822 string or Unix epoch seconds, or None."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)) or isinstance(value, str) and re.fullmatch(r"[0-9]{9,11}", value.strip()):
        try:
            return datetime.fromtimestamp(int(value), timezone.utc).isoformat(timespec="seconds")
        except (ValueError, OverflowError, OSError):
            return None
    if not isinstance(value, str) or len(value) > 80:
        return None
    result = published(value)
    return result if result and "T" in result else None


def normalized_status(value):
    word = value.strip().lower() if isinstance(value, str) else ""
    for status in ("investigating", "identified", "monitoring", "resolved"):
        if status[:6] in word:
            return status
    if word in {"postmortem", "completed", "complete", "closed", "cancelled", "canceled", "available", "fixed"}:
        return "resolved"
    return "other"


def incident(source, ident, name, *, status_raw=None, status=None, impact=None, impact_raw=None, components=(), started=None,
             updated=None, resolved=None, url=None, summary=None):
    """One normalized incident row, or None when it lacks an id, a name or a date."""
    ident = text(str(ident), ID_MAX) if ident is not None else ""
    name = clean(name, NAME_MAX)
    started = started or updated
    if not ident or not name or not started:
        return None
    status = status or normalized_status(status_raw)
    if resolved and status != "resolved":
        status = "resolved"
    names = []
    for item in components:
        value = clean(item, COMPONENT_MAX)
        if value and value not in names:
            names.append(value)
    return {"source": source["id"], "vendor": source["vendor"], "id": ident, "name": name, "status": status,
            "status_raw": clean(status_raw, 60) or None, "impact": impact if impact in IMPACTS else None, "impact_raw": clean(impact_raw, 60) or None,
            "components": names[:COMPONENTS_MAX], "started": started, "updated": updated or started, "resolved": resolved,
            "url": safe_url(url, {home_host(source)}) or source["home"], "summary": clean(summary, SUMMARY_MAX) or None}


def home_host(source):
    """An incident link must stay on the source's own status host; any other link falls back to its home page."""
    return urllib.parse.urlsplit(source["home"]).hostname


def is_open(row):
    return row["resolved"] is None and row["status"] != "resolved"


def indicator_from(rows):
    """The overall indicator a source without one of its own gets: its worst open incident, else none."""
    worst = max((RANK.get(row["impact"] or "minor", 1) for row in rows if is_open(row)), default=0)
    return ("none", "minor", "major", "critical")[worst]


def read_json_bytes(raw):
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        decoded = raw.decode("utf-16")
    else:
        decoded = raw.decode("utf-8-sig")
    return json.loads(decoded, parse_constant=collect.reject_constant)


def read_xml(raw):
    decoded = raw.decode("utf-8-sig")
    require("\x00" not in decoded and "<!DOCTYPE" not in decoded.upper() and "<!ENTITY" not in decoded.upper(), "DTD/entity/binary XML is not accepted.")
    root = ET.fromstring(decoded, parser=ET.XMLParser(target=collect.BoundedTreeBuilder()))
    require(root.tag.rsplit("}", 1)[-1].lower() == "rss", "Response is not RSS.")
    return root.findall("./channel/item")[:MAX_PARSED]


def child_text(element, name):
    for child in element:
        if child.tag.rsplit("}", 1)[-1] == name:
            return "".join(child.itertext())
    return None


def snapshot(indicator, description, rows):
    rows = [row for row in rows if row is not None][:MAX_PARSED]
    return {"indicator": indicator if indicator in INDICATORS else "unknown", "description": clean(description, DESCRIPTION_MAX) or None, "incidents": rows}


# Normalizers: one per format ----------------------------------------------------------------

SP_IMPACT = {"none": "none", "minor": "minor", "major": "major", "critical": "critical"}
SP_MAINTENANCE = {"scheduled", "in_progress", "verifying", "completed"}


def statuspage_incident(source, item):
    if not isinstance(item, dict) or item.get("impact") == "maintenance" or item.get("status") in SP_MAINTENANCE:
        return None
    ident = item.get("id")
    if not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9]{4,40}", ident):
        return None
    updates = [update for update in item.get("incident_updates") or [] if isinstance(update, dict)]
    updates.sort(key=lambda update: stamp(update.get("display_at") or update.get("created_at")) or "", reverse=True)
    components = []
    for update in updates:
        for component in update.get("affected_components") or []:
            if isinstance(component, dict):
                components.append(component.get("name"))
    for component in item.get("components") or []:
        if isinstance(component, dict):
            components.append(component.get("name"))
    return incident(source, ident, item.get("name"), status_raw=item.get("status"), impact=SP_IMPACT.get(item.get("impact")), impact_raw=item.get("impact"),
                    components=components, started=stamp(item.get("started_at")) or stamp(item.get("created_at")), updated=stamp(item.get("updated_at")),
                    resolved=stamp(item.get("resolved_at")), url=source["home"] + "incidents/" + ident,
                    summary=updates[0].get("body") if updates else None)


def parse_statuspage(source, documents):
    """summary.json gives the indicator and the unresolved incidents; incidents.json the 50 most recent."""
    summary = read_json_bytes(documents["summary"])
    require(isinstance(summary, dict) and isinstance(summary.get("status"), dict), "Unexpected Statuspage summary.")
    rows = {}
    for item in (read_json_bytes(documents["incidents"]).get("incidents") or [])[:MAX_PARSED] + (summary.get("incidents") or []):
        row = statuspage_incident(source, item)
        if row:
            rows[row["id"]] = row
    return snapshot(summary["status"].get("indicator"), summary["status"].get("description"), list(rows.values()))


GOOGLE_IMPACT = {"SERVICE_OUTAGE": "major", "SERVICE_DISRUPTION": "minor", "SERVICE_INFORMATION": "none"}


def google_name(value):
    lines = [line.strip() for line in clean_lines(value)]
    for index, line in enumerate(lines):
        if re.fullmatch(r"summary:?", line, re.I) and index + 1 < len(lines):
            return lines[index + 1]
        if line:
            return re.sub(r"^summary:\s*", "", line, flags=re.I)
    return None


def clean_lines(value):
    if not isinstance(value, str):
        return []
    return [line for line in (re.sub(r"\*\*|__|`|^#+\s*", "", raw).strip() for raw in value.splitlines()) if line]


def parse_google(source, documents):
    """Google Cloud and Google Workspace publish the same incidents.json shape."""
    items = read_json_bytes(documents["incidents"])
    require(isinstance(items, list), "Unexpected Google incidents list.")
    rows = []
    for item in items[:MAX_PARSED]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not re.fullmatch(r"[A-Za-z0-9]{4,40}", item["id"]):
            continue
        recent = item.get("most_recent_update") if isinstance(item.get("most_recent_update"), dict) else {}
        uri = item.get("uri") if isinstance(item.get("uri"), str) and re.fullmatch(r"incidents/[A-Za-z0-9]{4,40}", item["uri"]) else None
        impact_raw = " ".join(value for value in (item.get("status_impact"), "severity " + item["severity"] if isinstance(item.get("severity"), str) else None) if value)
        rows.append(incident(source, item["id"], google_name(item.get("external_desc")), status_raw=recent.get("status"),
                             status="resolved" if item.get("end") else "other", impact=GOOGLE_IMPACT.get(item.get("status_impact")), impact_raw=impact_raw,
                             components=[product.get("title") for product in item.get("affected_products") or [] if isinstance(product, dict)],
                             started=stamp(item.get("begin")) or stamp(item.get("created")), updated=stamp(item.get("modified")),
                             resolved=stamp(item.get("end")), url=source["home"] + uri if uri else None, summary=recent.get("text")))
    rows = [row for row in rows if row]
    return snapshot(indicator_from(rows), None, rows)


AWS_IMPACT = {"1": "none", "2": "minor", "3": "major"}


def parse_aws(source, documents):
    """health.aws.amazon.com/public/currentevents: JSON in UTF-16 with a byte-order mark; every event listed is current."""
    items = read_json_bytes(documents["events"])
    require(isinstance(items, list), "Unexpected AWS events list.")
    rows = []
    for item in items[:MAX_PARSED]:
        if not isinstance(item, dict) or not isinstance(item.get("arn"), str):
            continue
        log = [entry for entry in item.get("event_log") or [] if isinstance(entry, dict)]
        log.sort(key=lambda entry: entry.get("timestamp") if isinstance(entry.get("timestamp"), int) else 0)
        latest = log[-1] if log else {}
        status = str(item.get("status", ""))
        name = " ".join(value for value in (item.get("service_name"), "(" + item["region_name"] + "):" if isinstance(item.get("region_name"), str) else None,
                                            item.get("summary")) if isinstance(value, str))
        # impacted_services maps a service key to {service_name, current, max}.
        impacted = item.get("impacted_services") if isinstance(item.get("impacted_services"), dict) else {}
        components = [item.get("service_name")] + [service.get("service_name") for _key, service in sorted(impacted.items()) if isinstance(service, dict)]
        rows.append(incident(source, item["arn"], name, status_raw=latest.get("summary"), impact=AWS_IMPACT.get(status), impact_raw="AWS status " + status if status else None,
                             components=components, started=stamp(item.get("date")), updated=stamp(latest.get("timestamp")), url=source["home"],
                             summary=latest.get("message")))
    rows = [row for row in rows if row]
    return snapshot(indicator_from(rows), None, rows)


SLACK_IMPACT = {"outage": "major", "incident": "minor", "notice": "none"}


def slack_row(source, item):
    if not isinstance(item, dict) or not isinstance(item.get("id"), int) or item.get("type") == "scheduled":
        return None
    notes = [note for note in item.get("notes") or [] if isinstance(note, dict)]
    notes.sort(key=lambda note: stamp(note.get("date_created")) or "", reverse=True)
    resolved = stamp(item.get("date_updated")) if item.get("status") == "resolved" else None
    return incident(source, str(item["id"]), item.get("title"), status_raw=item.get("status"), status="resolved" if resolved else "other",
                    impact=SLACK_IMPACT.get(item.get("type")), impact_raw=item.get("type"), components=item.get("services") or [],
                    started=stamp(item.get("date_created")), updated=stamp(item.get("date_updated")), resolved=resolved, url=item.get("url"),
                    summary=notes[0].get("body") if notes else None)


def parse_slack(source, documents):
    current = read_json_bytes(documents["current"])
    history = read_json_bytes(documents["history"])
    require(isinstance(current, dict) and isinstance(history, list), "Unexpected Slack status documents.")
    rows = {}
    for item in history[:MAX_PARSED] + (current.get("active_incidents") or []):
        row = slack_row(source, item)
        if row:
            rows[row["id"]] = row
    rows = list(rows.values())
    worst = indicator_from(rows)
    return snapshot("none" if current.get("status") == "ok" and worst == "none" else worst, None, rows)


HEROKU_IMPACT = {"red": "major", "yellow": "minor", "green": "minor"}


def parse_heroku(source, documents):
    current = read_json_bytes(documents["current"])
    require(isinstance(current, dict) and isinstance(current.get("status"), list), "Unexpected Heroku status document.")
    colours = [item.get("status") for item in current["status"] if isinstance(item, dict)]
    indicator = "major" if "red" in colours else "minor" if "yellow" in colours else "none"
    rows = []
    for item in (current.get("incidents") or [])[:MAX_PARSED]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), int):
            continue
        systems = [system for system in item.get("systems") or [] if isinstance(system, dict)]
        worst = "red" if any(system.get("status") == "red" for system in systems) else "yellow" if any(system.get("status") == "yellow" for system in systems) else "green"
        updates = sorted((update for update in item.get("updates") or [] if isinstance(update, dict)), key=lambda update: stamp(update.get("created_at")) or "", reverse=True)
        rows.append(incident(source, str(item["id"]), item.get("title"), status_raw=item.get("state"), impact=HEROKU_IMPACT[worst], impact_raw=worst,
                             components=[system.get("name") for system in systems], started=stamp(item.get("created_at")), updated=stamp(item.get("updated_at")),
                             resolved=stamp(item.get("resolved_at")) if item.get("resolved") else None, url=item.get("full_url"),
                             summary=updates[0].get("contents") if updates else None))
    return snapshot(indicator, None, [row for row in rows if row])


def parse_salesforce(source, documents):
    """Active Salesforce incidents; Salesforce gives no title, so the name is the services and the incident type."""
    items = read_json_bytes(documents["active"])
    require(isinstance(items, list), "Unexpected Salesforce incident list.")
    rows = []
    for item in items[:MAX_PARSED]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), int):
            continue
        impacts = [impact for impact in item.get("IncidentImpacts") or [] if isinstance(impact, dict)]
        worst = max((impact.get("severity") for impact in impacts if impact.get("severity") in IMPACTS), key=lambda value: RANK[value], default=None)
        events = sorted((event for event in item.get("IncidentEvents") or [] if isinstance(event, dict)), key=lambda event: stamp(event.get("createdAt")) or "", reverse=True)
        services = [value for value in item.get("serviceKeys") or [] if isinstance(value, str)]
        instances = len(item.get("instanceKeys") or [])
        name = ", ".join(services[:4]) + ": " + (item.get("type") if isinstance(item.get("type"), str) else "incident") + \
            (" on " + format(instances, ",") + " instances" if instances else "")
        starts = [stamp(impact.get("startTime")) for impact in impacts if stamp(impact.get("startTime"))]
        rows.append(incident(source, str(item["id"]), name, status_raw=item.get("status"), impact=worst, impact_raw=item.get("type"),
                             components=services, started=min(starts) if starts else stamp(item.get("createdAt")), updated=stamp(item.get("updatedAt")),
                             resolved=None if item.get("status") == "Active" else stamp(item.get("updatedAt")),
                             url="https://status.salesforce.com/incidents/" + str(item["id"]), summary=events[0].get("message") if events else None))
    rows = [row for row in rows if row]
    return snapshot(indicator_from(rows), None, rows)


STATUSIO_INDICATOR = {100: "none", 200: "maintenance", 300: "minor", 400: "major", 500: "critical", 600: "critical"}


def parse_statusio(source, documents):
    """status.io's public status document: the overall code, and the components that are not operational."""
    value = read_json_bytes(documents["status"])
    result = value.get("result") if isinstance(value, dict) else None
    require(isinstance(result, dict) and isinstance(result.get("status_overall"), dict), "Unexpected status.io document.")
    overall = result["status_overall"]
    rows = []
    for item in (result.get("incidents") or [])[:MAX_PARSED]:
        if isinstance(item, dict):
            rows.append(incident(source, item.get("_id") or item.get("id"), item.get("name"), status_raw=item.get("current_status") or "open", status="other",
                                 impact="minor", started=stamp(item.get("datetime_open")) or stamp(overall.get("updated")), updated=stamp(item.get("datetime_open"))))
    return snapshot(STATUSIO_INDICATOR.get(overall.get("status_code"), "unknown"), overall.get("status"), [row for row in rows if row])


AZDO_INDICATOR = {"healthy": "none", "advisory": "none", "degraded": "minor", "unhealthy": "major"}


def parse_azure_devops(source, documents):
    value = read_json_bytes(documents["health"])
    require(isinstance(value, dict) and isinstance(value.get("status"), dict), "Unexpected Azure DevOps health document.")
    return snapshot(AZDO_INDICATOR.get(value["status"].get("health"), "unknown"), value["status"].get("message"), [])


BETTERSTACK_IMPACT = {"degraded": "minor", "downtime": "major", "resolved": None}
BETTERSTACK_INDICATOR = {"operational": "none", "degraded": "minor", "downtime": "major", "maintenance": "maintenance"}


def parse_betterstack(source, documents):
    """A Better Stack status page's index.json: the page state, its reports and their updates."""
    value = read_json_bytes(documents["index"])
    data = value.get("data") if isinstance(value, dict) else None
    require(isinstance(data, dict) and isinstance(data.get("attributes"), dict), "Unexpected status page document.")
    included = [item for item in value.get("included") or [] if isinstance(item, dict) and isinstance(item.get("attributes"), dict)]
    updates = {item.get("id"): item["attributes"] for item in included if item.get("type") == "status_update"}
    resources = {item.get("id"): item["attributes"].get("public_name") for item in included if item.get("type") == "status_page_resource"}
    rows = []
    for item in included[:MAX_PARSED]:
        if item.get("type") != "status_report" or not isinstance(item.get("id"), str) or not item["id"].isdigit():
            continue
        report = item["attributes"]
        if report.get("report_type") == "maintenance":
            continue
        linked = [updates[link.get("id")] for link in ((item.get("relationships") or {}).get("status_updates") or {}).get("data") or []
                  if isinstance(link, dict) and link.get("id") in updates]
        linked.sort(key=lambda update: stamp(update.get("published_at")) or "", reverse=True)
        affected = [entry for entry in report.get("affected_resources") or [] if isinstance(entry, dict)]
        states = {entry.get("status") for entry in affected}
        state = report.get("aggregate_state")
        worst = "major" if "downtime" in states or state == "downtime" else "minor"
        resolved = stamp(report.get("ends_at")) or (stamp(linked[0].get("published_at")) if state == "resolved" and linked else None)
        rows.append(incident(source, item["id"], report.get("title"), status_raw=state, impact=worst, impact_raw=None if state == "resolved" else state,
                             components=[resources.get(entry.get("status_page_resource_id")) for entry in affected],
                             started=stamp(report.get("starts_at")), updated=stamp(linked[0].get("published_at")) if linked else None,
                             resolved=resolved, url=source["home"] + "incident/" + item["id"], summary=linked[0].get("message") if linked else None))
    rows = [row for row in rows if row]
    return snapshot(BETTERSTACK_INDICATOR.get(data["attributes"].get("aggregate_state"), "unknown"), None, rows)


def parse_azure(source, documents):
    """The Azure status RSS feed lists current incidents only; an empty channel means none is posted."""
    rows = []
    for item in read_xml(documents["feed"]):
        link = child_text(item, "link")
        guid = child_text(item, "guid") or link or child_text(item, "title")
        ident = hashlib.sha256((guid or "").encode("utf-8")).hexdigest()[:16]
        rows.append(incident(source, ident, child_text(item, "title"), status="other", impact="minor", started=stamp(child_text(item, "pubDate")),
                             url=link, summary=child_text(item, "description")))
    rows = [row for row in rows if row]
    return snapshot(indicator_from(rows), None, rows)


ZSCALER_IMPACT = {"service disruption": "major", "service degradation": "minor"}


def parse_zscaler(source, documents):
    """trust.zscaler.com's RSS: only items in the Recent incident category are incidents."""
    rows = []
    for item in read_xml(documents["feed"]):
        if (child_text(item, "category") or "").strip() != "Recent incident":
            continue
        guid = (child_text(item, "guid") or "").split(" ")[0]
        if not guid.isdigit():
            continue
        title = child_text(item, "title") or ""
        clouds = title.rsplit(" - ", 1)[1].split(",") if " - " in title else []
        event = (child_text(item, "eventType") or "").strip()
        state = (child_text(item, "Status") or "").strip()
        resolved = stamp(child_text(item, "ResolvedDate")) or (stamp(child_text(item, "endTime")) if state in {"Resolved", "Completed", "Cancelled"} else None)
        rows.append(incident(source, guid, title, status_raw=state or event, status="resolved" if state in {"Resolved", "Completed", "Cancelled"} else normalized_status(event),
                             impact=ZSCALER_IMPACT.get(event.lower(), "minor"), impact_raw=event or None, components=clouds,
                             started=stamp(child_text(item, "startTime")) or stamp(child_text(item, "pubDate")), updated=stamp(child_text(item, "pubDate")),
                             resolved=resolved, url=child_text(item, "link"), summary=child_text(item, "customerImpact")))
    rows = [row for row in rows if row]
    return snapshot(indicator_from(rows), None, rows)


def parse_statuspage_rss(source, documents):
    """Oracle Cloud: a Statuspage-format status.json for the indicator and an incident-history RSS feed."""
    status = read_json_bytes(documents["status"])
    require(isinstance(status, dict) and isinstance(status.get("status"), dict), "Unexpected status document.")
    rows = []
    for item in read_xml(documents["feed"]):
        guid = (child_text(item, "guid") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{8,200}", guid):
            continue
        description = child_text(item, "description") or ""
        word = re.search(r"<strong>\s*([A-Za-z ]{3,30}?)\s*</strong>", description)
        parts = [part.strip() for part in (child_text(item, "title") or "").split("|")]
        body = re.sub(r"^.*?</strong>\s*-\s*", "", description, count=1, flags=re.S)
        state = word.group(1) if word else None
        when = stamp(child_text(item, "pubDate"))
        # Oracle writes the start as "<b>Start Time </b>: March 04, 2026 10:10 UTC" in the newest update.
        begun = re.search(r"Start Time\s*</b>\s*:\s*([A-Z][a-z]+ [0-9]{1,2}, [0-9]{4} [0-9]{2}:[0-9]{2}) UTC", description)
        try:
            started = datetime.strptime(begun.group(1), "%B %d, %Y %H:%M").replace(tzinfo=timezone.utc).isoformat(timespec="seconds") if begun else when
        except ValueError:
            started = when
        rows.append(incident(source, guid, " | ".join(parts[:2]) or child_text(item, "title"), status_raw=state, impact="minor",
                             components=parts[:2], started=started, updated=when,
                             resolved=when if normalized_status(state) == "resolved" else None, url=source["home"], summary=body))
    rows = [row for row in rows if row]
    return snapshot(status["status"].get("indicator"), status["status"].get("description"), rows)


MICROSOFT_IMPACT = {"service degradation": "major", "service interruption": "critical", "extended recovery": "minor",
                    "restoring service": "minor", "investigating": "minor", "advisory": "minor", "informational": "none"}
MICROSOFT_HEALTHY = {"", "available", "service restored", "restored", "resolved", "normal service"}


def microsoft_text(message):
    """The vendor's HTML message as bounded plain text."""
    if not isinstance(message, str):
        return None
    return clean(html.unescape(re.sub(r"<[^>]+>", " ", message)), SUMMARY_MAX) or None


def parse_microsoft(source, documents):
    """status.cloud.microsoft/api/posts/<service>: one JSON post. Microsoft publishes here only when a
    significant issue may keep administrators out of the admin center, so a status other than Available
    is a live incident in the vendor's own words. Tenant-specific service health still needs a signed-in
    Microsoft Graph call, which the Hub does not make."""
    post = read_json_bytes(documents["posts"])
    require(isinstance(post, dict) and isinstance(post.get("Status"), str), "Unexpected Microsoft status post.")
    word = post["Status"].strip()
    if word.lower() in MICROSOFT_HEALTHY:
        return snapshot("none", word or "Available", [])
    impact = MICROSOFT_IMPACT.get(word.lower(), "major")
    title = post.get("Title") or word
    row = incident(source, post.get("Id"), title, status_raw=word, impact=impact,
                   started=stamp(post.get("AuthoredDateTime")), updated=stamp(post.get("LastUpdatedTime")),
                   url=source["home"], summary=microsoft_text(post.get("Message")))
    return snapshot(impact if row else "unknown", title, [row] if row else [])


PARSERS = {"statuspage": parse_statuspage, "google": parse_google, "aws": parse_aws, "slack": parse_slack, "heroku": parse_heroku,
           "salesforce": parse_salesforce, "statusio": parse_statusio, "azure-devops": parse_azure_devops, "betterstack": parse_betterstack,
           "azure": parse_azure, "zscaler": parse_zscaler, "statuspage-rss": parse_statuspage_rss, "microsoft": parse_microsoft}
# Endpoints a run reads for each format. The Statuspage status.json is the live board's file; the
# collector reads the summary, which carries the same indicator.
READ = {"statuspage": ("summary", "incidents"), "statuspage-rss": ("status", "feed")}


# Internet-level outage signals ----------------------------------------------------------------

def ioda_url(source, until):
    end = int(until.timestamp())
    start = int((until - IODA_WINDOW).timestamp())
    return source["endpoints"]["events"] + "?" + urllib.parse.urlencode({"entityType": "country", "from": start, "until": end})


def parse_ioda(raw, until):
    value = read_json_bytes(raw)
    require(isinstance(value, dict) and isinstance(value.get("data"), list), "Unexpected IODA events document.")
    rows = []
    for item in value["data"][:MAX_OUTAGE_ROWS]:
        if not isinstance(item, dict) or not isinstance(item.get("location"), str):
            continue
        match = re.fullmatch(r"(country|region|asn)/([A-Za-z0-9-]{1,20})", item["location"])
        start = item.get("start")
        if not match or not isinstance(start, int) or isinstance(start, bool):
            continue
        duration = item.get("duration") if isinstance(item.get("duration"), int) and item["duration"] >= 0 else None
        finish = start + duration if duration is not None else None
        score = item.get("score")
        rows.append({"source": "ioda", "id": match.group(1) + "/" + match.group(2) + "@" + str(start), "entity_type": match.group(1),
                     "entity_code": match.group(2), "entity_name": clean(item.get("location_name"), 80) or match.group(2),
                     "datasource": clean(item.get("datasource"), 40) or None, "start": stamp(start),
                     "end": stamp(finish) if finish is not None and finish < int(until.timestamp()) else None,
                     "duration_seconds": duration, "score": round(score) if isinstance(score, (int, float)) and not isinstance(score, bool) and score == score and abs(score) < 1e15 else None,
                     "url": "https://ioda.inetintel.cc.gatech.edu/" + match.group(1) + "/" + match.group(2)})
    copyright_line = clean(value.get("copyright"), 200) or None
    rows.sort(key=lambda row: (row["start"] or "", row["id"]), reverse=True)
    return rows, copyright_line


def radar_url(source):
    return source["endpoints"]["outages"] + "?" + urllib.parse.urlencode({"dateRange": RADAR_DATE_RANGE, "format": "json", "limit": 100})


def parse_radar(raw):
    value = read_json_bytes(raw)
    result = value.get("result") if isinstance(value, dict) else None
    require(isinstance(result, dict) and isinstance(result.get("annotations"), list), "Unexpected Radar annotations document.")
    rows = []
    for item in result["annotations"][:MAX_OUTAGE_ROWS]:
        if not isinstance(item, dict) or not isinstance(item.get("id"), (str, int)) or isinstance(item.get("id"), bool):
            continue
        outage = item.get("outage") if isinstance(item.get("outage"), dict) else {}
        places = [clean(place.get("name"), 80) for place in item.get("locationsDetails") or [] if isinstance(place, dict)]
        networks = [clean(str(network.get("asn")) + " " + str(network.get("name") or ""), 80) for network in item.get("asnsDetails") or [] if isinstance(network, dict)]
        rows.append({"source": "cloudflare-radar", "id": clean(str(item["id"]), 40), "locations": [place for place in places if place][:12],
                     "asns": [network for network in networks if network][:12], "cause": clean(outage.get("outageCause"), 60) or None,
                     "type": clean(outage.get("outageType"), 60) or None, "scope": clean(item.get("scope"), 120) or None,
                     "description": clean(item.get("description"), SUMMARY_MAX) or None, "start": stamp(item.get("startDate")),
                     "end": stamp(item.get("endDate")), "url": safe_url(item.get("linkedUrl")) or "https://radar.cloudflare.com/outage-center"})
    rows.sort(key=lambda row: (row["start"] or "", row["id"]), reverse=True)
    return rows


def authorized_fetch(url, token, maximum=collect.MAX_BYTES):
    """The Radar read: the collector's fetch rules (canonical HTTPS URL, no proxy, no redirect, identity
    encoding, a 12-second connection timeout, a 30-second read deadline and a byte bound) plus a bearer
    token. collect.fetch sends no Authorization header, so this one read has its own loop."""
    require(safe_url(url) == url, "Source URL must be a canonical public HTTPS URL.")
    require(isinstance(token, str) and RADAR_TOKEN.fullmatch(token) is not None, "The Radar token is malformed.")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), collect.NoRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "TeamStarWolf-IntelligenceHub/0.1 (public feed reader)", "Accept": "application/json",
                                                   "Accept-Encoding": "identity", "Authorization": "Bearer " + token})
    started = time.monotonic()
    chunks, size = [], 0
    try:
        with opener.open(request, timeout=12) as response:
            require(response.status == 200 and response.geturl() == url, "Unexpected publisher response.")
            require(response.headers.get("Content-Encoding", "identity").lower() == "identity", "Compressed responses are not accepted.")
            while True:
                require(time.monotonic() - started < 30, "Source exceeded its read deadline.")
                block = response.read1(65536)
                if not block:
                    break
                size += len(block)
                if size > maximum:
                    raise collect.ResponseByteLimitExceeded("Source exceeded its bounded read limit.")
                chunks.append(block)
    except http.client.HTTPException as error:
        raise OSError(type(error).__name__ + ": the publisher response ended early or was malformed") from error
    return b"".join(chunks)


# Collection ---------------------------------------------------------------------------------

def read_source(source, fetch, until, token):
    """(snapshot or outage rows, error). Never raises."""
    try:
        if source["format"] == "ioda":
            rows, notice = parse_ioda(fetch(ioda_url(source, until)), until)
            return {"rows": rows, "copyright": notice}, None
        if source["format"] == "radar":
            if not token:
                return None, "not_configured"
            return {"rows": parse_radar(authorized_fetch(radar_url(source), token)), "copyright": None}, None
        names = READ.get(source["format"], tuple(sorted(source["endpoints"])))
        documents = {name: fetch(source["endpoints"][name]) for name in names}
        return PARSERS[source["format"]](source, documents), None
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError, ET.ParseError, RecursionError, UnicodeError) as error:
        return None, collect.failure_reason(error, "status source unavailable")


def observe(registry, fetch=collect.fetch, *, previous=None, token=None, clock=None):
    """One observation per registry source: this run's read, or the last good one with the failure recorded."""
    previous = previous or {}
    attempted = clock or now()
    until = datetime.fromisoformat(attempted)

    def one(source):
        value, error = read_source(source, fetch, until, token)
        old = previous.get(source["id"]) if isinstance(previous.get(source["id"]), dict) else {}
        if value is not None:
            return source["id"], {"status": "ok", "fetched_at": attempted, "last_success": attempted, "error": None, **value}
        if error == "not_configured":
            return source["id"], {"status": "not_configured", "fetched_at": None, "last_success": None, "error": None,
                                  "rows": [], "copyright": None}
        kept = {key: old[key] for key in ("indicator", "description", "incidents", "rows", "copyright") if key in old}
        return source["id"], {"status": "failed", "fetched_at": attempted, "last_success": old.get("last_success"), "error": error, **kept}

    with ThreadPoolExecutor(max_workers=6) as pool:
        observations = dict(pool.map(one, registry["sources"]))
    for ident, item in sorted(observations.items()):
        if item["status"] == "failed":
            print("Status source " + ident + " failed: " + str(item["error"]), file=sys.stderr)
    return observations


def validate_observations(value, registry):
    """A retained .state/status-cache.json, or a cache fixture, before anything trusts it."""
    _check(isinstance(value, dict) and value.get("schema_version") == 1 and isinstance(value.get("sources"), dict), "Invalid status cache.")
    known = {source["id"]: source for source in registry["sources"]}
    for ident, item in value["sources"].items():
        _check(ident in known and isinstance(item, dict) and item.get("status") in {"ok", "failed", "not_configured"}, "Invalid status observation " + str(ident) + ".")
        for field in ("fetched_at", "last_success"):
            _check(item.get(field) is None or isinstance(item[field], str) and stamp(item[field]) == item[field], "Invalid status clock.")
        if known[ident]["format"] in OUTAGE_FORMATS:
            _check(isinstance(item.get("rows", []), list) and len(item.get("rows", [])) <= MAX_OUTAGE_ROWS, "Invalid outage rows.")
        else:
            rows = item.get("incidents", [])
            _check(isinstance(rows, list) and len(rows) <= MAX_PARSED and all(valid_incident(row, ident) for row in rows), "Invalid status incidents for " + ident + ".")
            _check(item.get("indicator", "unknown") in INDICATORS, "Invalid status indicator.")
    return value["sources"]


def valid_incident(row, source=None):
    if not isinstance(row, dict) or tuple(sorted(row)) != tuple(sorted(INCIDENT_FIELDS)):
        return False
    if source is not None and row["source"] != source:
        return False
    return (isinstance(row["id"], str) and 0 < len(row["id"]) <= ID_MAX and isinstance(row["name"], str) and 0 < len(row["name"]) <= NAME_MAX and
            row["status"] in STATUSES and row["impact"] in IMPACTS + (None,) and isinstance(row["components"], list) and len(row["components"]) <= COMPONENTS_MAX and
            all(isinstance(item, str) and len(item) <= COMPONENT_MAX for item in row["components"]) and
            all(row[field] is None or isinstance(row[field], str) and stamp(row[field]) == row[field] for field in ("started", "updated", "resolved")) and
            row["started"] is not None and isinstance(row["url"], str) and safe_url(row["url"]) == row["url"] and
            (row["summary"] is None or isinstance(row["summary"], str) and len(row["summary"]) <= SUMMARY_MAX) and
            all(row[field] is None or isinstance(row[field], str) and len(row[field]) <= 60 for field in ("status_raw", "impact_raw")) and
            (row["vendor"] is None or isinstance(row["vendor"], str) and VOCAB_ID.fullmatch(row["vendor"]) is not None))


# Files ---------------------------------------------------------------------------------------

def month_of(row):
    return row["started"][:7]


def months_window(end):
    """The current month and the MONTHS_KEPT - 1 before it, oldest first, as YYYY-MM."""
    year, month = end.year, end.month
    found = []
    for _ in range(MONTHS_KEPT):
        found.append("{:04d}-{:02d}".format(year, month))
        month -= 1
        if month == 0:
            year, month = year - 1, 12
    return list(reversed(found))


def fold(rows):
    """One row per (source, id): the one with the latest update wins; ties keep the earlier row."""
    kept = {}
    for row in rows:
        key = (row["source"], row["id"])
        if key not in kept or (row["updated"] or "") > (kept[key]["updated"] or ""):
            kept[key] = row
    return kept


def fit_month(document):
    """Drops the oldest rows of a month file until its canonical bytes fit under the shard bound;
    returns how many were dropped. A month over the bound would otherwise fail shards.serialize
    outside this step and hold the whole feed."""
    from . import shards
    rows = document["rows"]
    excess = len(shards.canonical(document)) - shards.SHARD_MAX_BYTES
    drop = 0
    # A row costs its own canonical bytes less the newline, plus the comma that joins it: the same count.
    while excess > 0 and drop < len(rows):
        excess -= len(shards.canonical(rows[drop]))
        drop += 1
    document["rows"] = rows[drop:]
    while document["rows"] and len(shards.canonical(document)) > shards.SHARD_MAX_BYTES:
        document["rows"] = document["rows"][1:]
        drop += 1
    return drop


def build_files(registry, observations, previous_months, end, generated_at, previous_board=None, previous_outages=None):
    """({path under data/v7: value}, summary). previous_months is {YYYY-MM: [rows]} from the last publication;
    previous_board and previous_outages are the digests of the last publication's current.json and outages.json."""
    window = months_window(end)
    known = {source["id"] for source in tracked(registry)}
    rows = [row for month, items in (previous_months or {}).items() if month in window for row in items
            if valid_incident(row) and row["source"] in known]
    for source in tracked(registry):
        rows.extend((observations.get(source["id"]) or {}).get("incidents") or [])
    # Months outside the window leave; an incident that starts after the window's last day waits for a later run.
    last = end.isoformat()
    folded = fold(row for row in rows if month_of(row) in window and row["started"][:10] <= last)
    months = {}
    for row in folded.values():
        months.setdefault(month_of(row), []).append(row)
    files, entries, coverage = {}, [], {}
    truncated = 0
    for month in sorted(months):
        items = sorted(months[month], key=lambda row: (row["started"], row["source"], row["id"]))
        if len(items) > MAX_MONTH_ROWS:
            truncated += len(items) - MAX_MONTH_ROWS
            items = items[-MAX_MONTH_ROWS:]
        path = DIRECTORY + "/" + month + ".json"
        files[path] = {"schema_version": SCHEMA_VERSION, "kind": "status-month", "period": month, "rows": items}
        truncated += fit_month(files[path])
        items = files[path]["rows"]
        entries.append({"period": month, "path": path, "rows": len(items)})
        for row in items:
            item = coverage.setdefault(row["source"], {"source": row["source"], "first_incident": row["started"][:10], "incidents": 0})
            item["incidents"] += 1
            item["first_incident"] = min(item["first_incident"], row["started"][:10])
    current = current_file(registry, observations, folded, generated_at)
    files[DIRECTORY + "/current.json"] = current
    outages = outages_file(registry, observations, generated_at)
    files[DIRECTORY + "/outages.json"] = outages
    digest = board_digest(current)
    outages_sha = outages_digest(outages)
    files[DIRECTORY + "/index.json"] = {"schema_version": SCHEMA_VERSION, "kind": "status-index", "generated_at": generated_at,
                                        "months_kept": MONTHS_KEPT, "months": entries, "coverage": [coverage[key] for key in sorted(coverage)],
                                        "sources": len(tracked(registry)), "page_only": len(registry["page_only"]), "truncated_rows": truncated,
                                        "board_sha256": digest, "notes": NOTES}
    for path in files:
        require(PATH.fullmatch(path), "Unexpected status file path " + path + ".")
    summary = {"status": "ok", "sources": len(tracked(registry)), "ok": sum(1 for source in tracked(registry) if (observations.get(source["id"]) or {}).get("status") == "ok"),
               "failed": sorted(source["id"] for source in registry["sources"] if (observations.get(source["id"]) or {}).get("status") == "failed"),
               "incidents": len(folded), "open": sum(len(item["open"]) for item in current["sources"]), "months": len(entries),
               "board_changed": previous_board is None or previous_board != digest,
               "outages_changed": previous_outages is None or previous_outages != outages_sha, "truncated_rows": truncated}
    return files, summary


def current_file(registry, observations, folded, generated_at):
    groups = registry["groups"]
    sources = []
    for source in tracked(registry):
        item = observations.get(source["id"]) or {}
        own = [row for row in folded.values() if row["source"] == source["id"] and is_open(row)]
        # Open incidents are this read's own open rows; history rows are never reopened.
        seen = {(row["source"], row["id"]) for row in (item.get("incidents") or []) if is_open(row)}
        open_rows = sorted((row for row in own if (row["source"], row["id"]) in seen), key=lambda row: row["started"], reverse=True)[:MAX_OPEN]
        sources.append({"id": source["id"], "name": source["name"], "vendor": source["vendor"], "group": source["group"], "class": source["class"],
                        "format": source["format"], "home": source["home"], "library": source["library"], "cors": source["cors"], "live": live_url(source),
                        "status": item.get("status", "not_fetched"), "fetched_at": item.get("fetched_at"), "last_success": item.get("last_success"),
                        "error": item.get("error"), "indicator": item.get("indicator", "unknown") if item.get("last_success") else "unknown",
                        "description": item.get("description"), "open": open_rows})
    return {"schema_version": SCHEMA_VERSION, "kind": "status-current", "generated_at": generated_at, "groups": groups, "sources": sources,
            "page_only": registry["page_only"], "notes": NOTES}


def outages_file(registry, observations, generated_at):
    blocks = {}
    for source in registry["sources"]:
        if source["format"] not in OUTAGE_FORMATS:
            continue
        item = observations.get(source["id"]) or {}
        blocks[source["format"]] = {"id": source["id"], "name": source["name"], "home": source["home"], "status": item.get("status", "not_fetched"),
                                    "fetched_at": item.get("fetched_at"), "last_success": item.get("last_success"), "error": item.get("error"),
                                    "copyright": item.get("copyright"), "rows": (item.get("rows") or [])[:MAX_OUTAGE_ROWS]}
    if "radar" in blocks and blocks["radar"]["status"] == "not_configured":
        blocks["radar"]["note"] = "Cloudflare Radar needs an API token. The owner adds it as the repository secret " + RADAR_TOKEN_ENV + "; until then no Radar request is made."
    return {"schema_version": SCHEMA_VERSION, "kind": "status-outages", "generated_at": generated_at,
            "window_hours": int(IODA_WINDOW.total_seconds() // 3600), **blocks}


def board_digest(current):
    """sha256 of current.json without its clocks: the board changed only when an indicator, an open
    incident, a description, an error or the source list changed."""
    def strip(value):
        return {key: item for key, item in value.items() if key not in {"fetched_at", "last_success", "generated_at"}}
    value = {**strip(current), "sources": [strip(source) for source in current["sources"]]}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def outages_digest(outages):
    """sha256 of outages.json without its clocks (generated_at and each block's fetched_at and
    last_success): the outage signals changed only when a row, a status, an error or a note changed."""
    clocks = {"fetched_at", "last_success", "generated_at"}
    value = {key: ({name: part for name, part in item.items() if name not in clocks} if isinstance(item, dict) else item)
             for key, item in outages.items() if key not in clocks}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


# Explorer rows -------------------------------------------------------------------------------

def row_id(row):
    ident = row["id"] if SAFE_ROW_ID.fullmatch(row["id"]) else hashlib.sha256(row["id"].encode("utf-8")).hexdigest()[:16]
    return ("status-" + row["source"] + "-" + ident)[:100]


def explorer_rows(files, registry):
    """Every incident of impact minor or above in the month files, as a v7 article row."""
    names = {source["id"]: source for source in registry["sources"]}
    articles = []
    for path in sorted(files):
        if not MONTH_PATH.fullmatch(path):
            continue
        for row in files[path]["rows"]:
            if row["impact"] not in EXPLORER_IMPACTS or row["source"] not in names:
                continue
            source = names[row["source"]]
            parts = ["Impact " + row["impact"] + (" (" + row["impact_raw"] + ")" if row["impact_raw"] and row["impact_raw"] != row["impact"] else "") + ".",
                     "Status " + (row["status"] if row["status"] != "other" or not row["status_raw"] else row["status_raw"]) + "."]
            if row["components"]:
                parts.append("Affected: " + ", ".join(row["components"][:6]) + ".")
            if row["resolved"]:
                parts.append("Resolved " + row["resolved"][:16].replace("T", " ") + " UTC.")
            articles.append({"id": row_id(row), "title": text(source["name"] + ": " + row["name"], 300), "url": row["url"],
                             "source_id": SOURCE_PREFIX + source["id"], "source_name": source["name"] + " status page", "kind": "incident",
                             "published_at": row["started"], "event_date": None, "date_basis": DATE_BASIS, "summary": text(" ".join(parts), 500),
                             "cves": [], "tags": [], "exploitation": "unknown", "references": [{"label": source["name"] + " status page", "url": source["home"]}],
                             "origin": ORIGIN})
    return articles


def tag_registry(registry):
    """The tagging engine's source entries for status rows: the vendor's own statement, with its vendor id."""
    return [{"id": SOURCE_PREFIX + source["id"], "source_class": "vendor-primary", "publisher_vendor": source["vendor"], "country": None,
             "desk": source["desk"]}
            for source in tracked(registry)]


def tag_rows(rows, registry, context, catalog, briefs):
    """Rows with their compact tagging block: the engine's tags plus the outage event (method status-incident)."""
    from . import tagging
    from .tagging import fields
    from .tagging.engine import compact
    status_context = tagging.build_context(context.vocab, tag_registry(registry), catalog, briefs)
    blocks = tagging.tag_rows(rows, status_context)
    tagged = []
    for row in rows:
        block = dict(blocks[row["id"]])
        events = [item for item in block.get("event_type", []) if item["value"] != "unclassified"]
        block["event_type"] = fields.best(events + [fields.tag("outage", "status-incident", "high")])
        tagged.append({**row, "tagging": compact(block)})
    return tagged


# Previous publication ------------------------------------------------------------------------

KINDS = {"current": "status-current", "outages": "status-outages", "index": "status-index"}
READ_ATTEMPTS = 2


def previous_entries(index):
    """The status files a previous publication's v7 index lists, in path order."""
    return sorted((entry for entry in (index or {}).get("shards", []) if isinstance(entry, dict) and isinstance(entry.get("path"), str) and
                   PATH.fullmatch(entry["path"])), key=lambda entry: entry["path"])


def expected_kind(path):
    return "status-month" if MONTH_PATH.fullmatch(path) else KINDS[path[len(DIRECTORY) + 1:-len(".json")]]


def read_previous_files(index, read):
    """{path: value} for every status file the previous index lists, each one checked.

    read(entry) returns the file's bytes after checking them against the entry. A file must parse,
    carry its kind and serialize again to exactly the bytes read, so carrying it forward publishes
    the same bytes. Each file gets READ_ATTEMPTS reads; one that still fails raises StatusHold.
    """
    from .shards import canonical
    found = {}
    for entry in previous_entries(index):
        path = entry["path"]
        for attempt in range(1, READ_ATTEMPTS + 1):
            try:
                raw = read(entry)
                value = json.loads(raw.decode("utf-8"), parse_constant=collect.reject_constant)
                require(isinstance(value, dict) and value.get("kind") == expected_kind(path), "It is not a " + expected_kind(path) + " file.")
                require(not MONTH_PATH.fullmatch(path) or isinstance(value.get("rows"), list), "Its rows are not a list.")
                require(canonical(value) == raw, "It does not serialize again to the bytes read.")
            except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError) as error:
                reason = collect.failure_reason(error, "unreadable")
                if attempt < READ_ATTEMPTS:
                    print("Status: " + path + " from the previous publication was not read (" + reason + "); reading it once more.", file=sys.stderr)
                    continue
                raise StatusHold("data/v7/" + path + " from the previous publication could not be read or checked (" + reason + ")") from error
            found[path] = value
            break
    return found


def previous_state(files):
    """({YYYY-MM: rows}, current.json or None) from the previous publication's checked status files."""
    months, current = {}, None
    for path, value in files.items():
        match = MONTH_PATH.fullmatch(path)
        if match:
            months[match.group(1)] = [row for row in value["rows"] if valid_incident(row)]
            dropped = len(value["rows"]) - len(months[match.group(1)])
            if dropped:
                print("Status: {:,} rows of {} from the previous publication do not meet the incident rules and were left out.".format(dropped, path),
                      file=sys.stderr)
        elif path == DIRECTORY + "/current.json" and isinstance(value.get("sources"), list):
            current = value
    return months, current


def read_previous(index, read):
    """({YYYY-MM: rows}, current.json or None) from a previous publication's status files.

    index is that publication's v7 index (or None); read(entry) returns the file's bytes after
    checking them against the entry. A listed file that cannot be read or checked raises StatusHold.
    """
    return previous_state(read_previous_files(index, read))


def carried_summary(files, reason):
    """The run summary when the previous status files are published again unchanged."""
    index = files.get(DIRECTORY + "/index.json") or {}
    months = [path for path in files if MONTH_PATH.fullmatch(path)]
    return {"status": "carried", "reason": reason, "sources": index["sources"] if isinstance(index.get("sources"), int) else 0,
            "incidents": sum(len(files[path]["rows"]) for path in months), "months": len(months), "board_changed": False, "outages_changed": False,
            "carried": sorted(files)}


def previous_observations(current):
    """The last good snapshot per source, from a previous current.json, so a failed read keeps it."""
    found = {}
    for item in (current or {}).get("sources", []):
        if isinstance(item, dict) and isinstance(item.get("id"), str) and item.get("last_success"):
            found[item["id"]] = {"indicator": item.get("indicator", "unknown"), "description": item.get("description"),
                                 "incidents": [row for row in item.get("open") or [] if valid_incident(row, item["id"])],
                                 "last_success": item.get("last_success")}
    return found


def previous_outage_observations(outages):
    """The last good IODA and Radar reads, from a previous outages.json, so a failed read keeps them.

    current.json lists only the tracked status pages, so the outage blocks are seeded from here.
    """
    found = {}
    for name in sorted(OUTAGE_FORMATS):
        block = (outages or {}).get(name)
        if not isinstance(block, dict) or not isinstance(block.get("id"), str) or not block.get("last_success"):
            continue
        rows = block.get("rows")
        found[block["id"]] = {"rows": [row for row in rows if isinstance(row, dict)][:MAX_OUTAGE_ROWS] if isinstance(rows, list) else [],
                              "copyright": block.get("copyright"), "last_success": block["last_success"]}
    return found


def deployed_index(fetch):
    """The deployed v7 index's status entries, for a run that resumed from data/feed.json because the
    v7 index was not usable for articles: the deployed status files are still the only copy of older
    incidents. None when no v7 index is deployed (HTTP 404) or the deployed one cannot be parsed, so
    it names no file to keep. Any other failure to read it raises StatusHold.
    """
    from .shards import INDEX_MAX_BYTES
    try:
        raw = fetch(collect.PUBLIC_V7 + "index.json", INDEX_MAX_BYTES, fresh=True)
    except urllib.error.HTTPError as error:
        error.close()
        if error.code == 404:
            return None
        raise StatusHold("the deployed data/v7/index.json could not be read (HTTP " + str(error.code) + ")") from error
    except (OSError, ValueError) as error:
        raise StatusHold("the deployed data/v7/index.json could not be read (" + collect.failure_reason(error, "unreadable") + ")") from error
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=collect.reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        print("Status: the deployed data/v7/index.json does not parse; it names no status file to keep.", file=sys.stderr)
        return None
    if not isinstance(value, dict) or not isinstance(value.get("shards"), list):
        return None
    return {"shards": previous_entries(value)}


def deployed_reader(base, fetch):
    def read(entry):
        raw = fetch(base + entry["path"], 4 * 1024 * 1024, fresh=True)
        require(len(raw) == entry["bytes"] and hashlib.sha256(raw).hexdigest() == entry["sha256"], "A status file differs from the deployed index.")
        return raw
    return read


def local_reader(site):
    base = Path(site) / "data" / "v7"

    def read(entry):
        raw = (base / entry["path"]).read_bytes()
        require(len(raw) == entry["bytes"] and hashlib.sha256(raw).hexdigest() == entry["sha256"], "A status file differs from the local index.")
        return raw
    return read


def read_time(observations, end):
    """The latest fetch clock among the observations, else midnight UTC at the start of the window's last day."""
    clocks = [item["fetched_at"] for item in observations.values() if isinstance(item, dict) and item.get("fetched_at")]
    return max(clocks) if clocks else end.isoformat() + "T00:00:00+00:00"


def held(reason):
    """The step's result when a previous status file cannot be read: the collector stops on it."""
    print("Status: " + reason + "; holding this run so no incident history is lost.", file=sys.stderr)
    return {"files": {}, "rows": [], "registry": None, "summary": {"status": "held", "reason": reason[:300], "board_changed": False, "outages_changed": False}}


def collect_status(root, *, refresh, previous_index, deployed, end, fetch=None, state=None, clock=None):
    """The status files, Explorer rows (untagged) and run summary. Never raises.

    The previous publication's status files are read first. If one it lists cannot be read or
    checked, the summary status is "held" and the collector stops before writing anything. A
    failure after that publishes the previous status files again, byte for byte (status
    "carried"); with no previous status files it returns none (status "unavailable").
    """
    state = Path(state) if state is not None else Path(root) / ".state"
    # Looked up at call time, so a test that replaces collect.fetch replaces every read here too.
    fetch = fetch if fetch is not None else collect.fetch
    try:
        read = deployed_reader(collect.PUBLIC_V7, fetch) if deployed else local_reader(Path(root) / "site")
        carried = read_previous_files(previous_index, read)
    except StatusHold as error:
        return held(str(error))
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        return held("the previous status files could not be read (" + (str(error) or type(error).__name__)[:200] + ")")
    registry = None
    try:
        registry = load_registry(root)
        months, current = previous_state(carried)
        retained = previous_observations(current)
        outages = carried.get(DIRECTORY + "/outages.json")
        retained.update(previous_outage_observations(outages if isinstance(outages, dict) else None))
        cache_path = state / CACHE
        if refresh:
            token = os.environ.get(RADAR_TOKEN_ENV, "").strip() or None
            observations = observe(registry, fetch, previous=retained, token=token, clock=clock)
            collect.write_json(cache_path, {"schema_version": 1, "sources": observations})
        elif cache_path.exists():
            raw = cache_path.read_bytes()
            require(len(raw) <= CACHE_MAX_BYTES, "The status cache exceeds its byte bound.")
            observations = validate_observations(json.loads(raw.decode("utf-8"), parse_constant=collect.reject_constant), registry)
        else:
            observations = {}
        # The files carry the collector's read time, not the build time, so a --cached rebuild of
        # the same observations gives the same bytes.
        generated = read_time(observations, end)
        before = carried.get(DIRECTORY + "/outages.json")
        files, summary = build_files(registry, observations, months, end, generated, board_digest(current) if current else None,
                                     outages_digest(before) if isinstance(before, dict) else None)
        return {"files": files, "rows": explorer_rows(files, registry), "registry": registry, "summary": summary}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as error:
        reason = (str(error) or type(error).__name__)[:300]
        if carried:
            print("Status: service health not rebuilt (" + reason + "); the previous " + format(len(carried), ",") +
                  " status files are published again unchanged.", file=sys.stderr)
            try:
                rows = explorer_rows(carried, registry) if registry is not None else []
            except (ValueError, TypeError, KeyError, AttributeError):
                rows = []
            return {"files": carried, "rows": rows, "registry": registry if rows else None, "summary": carried_summary(carried, reason)}
        print("Status: service health not built (" + reason + ").", file=sys.stderr)
        return {"files": {}, "rows": [], "registry": None, "summary": {"status": "unavailable", "reason": reason, "board_changed": False, "outages_changed": False}}


def headroom(files, canonical, cap):
    """One line per status file with its bytes and headroom under the per-file cap."""
    return ["data/v7/{}: {:,} of {:,} bytes ({:,} of headroom)".format(path, len(canonical(files[path])), cap, cap - len(canonical(files[path])))
            for path in sorted(files)]
