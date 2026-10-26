"""Bounded, attributed local intelligence context. No fetching or automatic actions."""
from datetime import date, datetime, timedelta
import hashlib
import json
import math
import re
from urllib.parse import urlsplit

MAX_INTELLIGENCE = 128 * 1024
CADENCES = ["daily", "weekly", "weekend", "fortnightly", "monthly", "quarterly", "six-month"]
DIGEST = re.compile(r"[a-f0-9]{64}")
CWE = re.compile(r"CWE-[1-9][0-9]{0,5}")
REPORT = re.compile(r"SW-[A-Z0-9][A-Z0-9._-]{0,119}")
TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})")
REVIEWED = {"material_field_change", "timestamp_only", "raw_response_changed_unqualified", "no_baseline", "unchanged_supported"}


def require(condition, message="Invalid bounded intelligence context."):
    if not condition:
        raise ValueError(message)


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), "Unexpected intelligence fields.")


def plain(value, maximum, *, empty=False):
    # New text uses Unicode scalar/code-point lengths; legacy text rules are separate.
    require(type(value) is str and len(value) <= maximum and (empty or bool(value.strip())), "Invalid intelligence text.")
    require(not any(ord(char) < 32 or 0x7f <= ord(char) <= 0x9f or
                    0xd800 <= ord(char) <= 0xdfff or ord(char) in {0x061c, 0x200e, 0x200f, 0xfeff} or
                    0x202a <= ord(char) <= 0x202e or 0x2066 <= ord(char) <= 0x2069 for char in value),
            "Unsafe intelligence text.")
    return value


def array(value, maximum):
    require(type(value) is list and len(value) <= maximum, "Intelligence list exceeds its bound.")
    return value


def notes(value):
    for item in array(value, 12):
        plain(item, 600)


def sha(value, nullable=False):
    require(nullable and value is None or type(value) is str and DIGEST.fullmatch(value), "Invalid intelligence source digest.")


def clock(value, *, nullable=False, source=False):
    if nullable and value is None:
        return None
    require(type(value) is str and len(value) <= 40, "Invalid intelligence clock.")
    if source and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        require(date.fromisoformat(value).isoformat() == value, "Invalid intelligence date.")
        return date.fromisoformat(value)
    require(TIME.fullmatch(value), "Intelligence timestamp needs an explicit timezone.")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None and result.utcoffset() is not None, "Invalid intelligence timezone.")
    return result


def uri(value, safe_url, *, report=False, request=False):
    require(type(value) is str and value.isascii() and 0 < len(value) <= 4000, "Invalid intelligence HTTPS URI.")
    # Accept one conservative raw spelling; never normalize or reroute an approved source.
    match = re.fullmatch(r"https://([a-z0-9.-]+)(/[A-Za-z0-9._~/-]*)(?:\?([A-Za-z0-9._~=&-]+))?(?:#([A-Za-z0-9._~-]+))?", value)
    require(match is not None, "Unsupported intelligence URI syntax.")
    host, path, query, fragment = match.groups()
    labels = host.split(".")
    require(len(host) <= 253 and len(labels) >= 2 and re.fullmatch(r"[a-z]{2,63}", labels[-1]) and
            all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) and not label.startswith("xn--") for label in labels),
            "Unsupported intelligence URI host.")
    require(all(segment not in {".", ".."} for segment in path.split("/")), "Unsupported intelligence URI path.")
    query_keys = []
    if query is not None:
        pairs = query.split("&")
        require(len(pairs) <= 40, "Intelligence URI query exceeds its bound.")
        for pair in pairs:
            pieces = pair.split("=")
            require(len(pieces) == 2 and all(re.fullmatch(r"[A-Za-z0-9._~-]+", piece) for piece in pieces), "Unsupported intelligence URI query.")
            key = pieces[0]
            lowered = key.lower()
            require(not any(token in lowered for token in ("auth", "token", "signature", "session", "password")) and
                    not lowered.startswith("utm_") and lowered not in {"fbclid", "gclid", "mc_cid", "mc_eid"},
                    "Private or tracking request parameters are not public context.")
            query_keys.append(key)
        unique(query_keys)
    require(safe_url(value), "Unsafe intelligence HTTPS URI.")
    if request:
        require(fragment is None, "Revision source identity cannot have a fragment.")
    if report:
        prefix = "/TeamStarWolf/intelligence-hub/blob/main/reports/"
        require(host == "github.com" and query is None and fragment is None and path.startswith(prefix) and len(path) > len(prefix) and
                all(re.fullmatch(r"[A-Za-z0-9_.-]+", segment) and segment not in {".", ".."} for segment in path[len(prefix):].split("/")),
                "Report link must identify this repository's public reports.")
    return value


def identifier(value, pattern):
    require(type(value) is str and pattern.fullmatch(value), "Invalid intelligence identity.")
    return value


def unique(values):
    require(len(values) == len(set(values)), "Duplicate intelligence identity.")


def bounded_tree(value):
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        require(count <= 20000 and depth <= 16, "Intelligence input structure exceeds its bound.")
        if type(item) is dict:
            require(len(item) <= 15000 and all(type(key) is str and len(key) <= 160 for key in item))
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            array(item, 15000)
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            require(len(item) <= 4000 and not any(0xd800 <= ord(char) <= 0xdfff for char in item))
        else:
            require(item is None or type(item) in (bool, int, float))
            require(type(item) is not int or abs(item) <= 10**12)
            require(type(item) is not float or math.isfinite(item))


def duplicate_pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, "Duplicate intelligence JSON member.")
        value[key] = item
    return value


def reject_number(_value):
    raise ValueError("Nonfinite intelligence JSON number.")


def read_input(path, maximum):
    # Missing input refuses production; no remote catalog/configuration is adopted.
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "Intelligence input exceeds its byte bound.")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=duplicate_pairs, parse_constant=reject_number)
    bounded_tree(value)
    return value, hashlib.sha256(raw).hexdigest()


def validate_weaknesses(value, cve, brief_url, *, legacy=False):
    present = {"weaknesses", "weaknesses_status"} & set(value)
    if not present and legacy:
        return [], "not_projected"
    require(present == {"weaknesses", "weaknesses_status"}, "Incomplete CNA weakness projection.")
    items, status = array(value["weaknesses"], 8), value["weaknesses_status"]
    require(status in {"not_projected", "not_supplied", "supplied", "bounded"}, "Invalid CNA weakness status.")
    require(status == "bounded" or (bool(items) if status == "supplied" else not items), "CNA weakness status differs from its projection.")
    ids = []
    for item in items:
        keys(item, {"id", "description", "source_url"})
        ids.append(identifier(item["id"], CWE))
        plain(item["description"], 200, empty=True)
        require(item["source_url"] == brief_url(cve), "CNA weakness source identity differs.")
    unique(ids)
    return items, status


def validate_evidence(values, safe_url, confidence):
    evidence = array(values, 4)
    require(evidence, "Intelligence assertions need source evidence.")
    urls = []
    for item in evidence:
        keys(item, {"source_url", "publisher", "published_at", "updated_at", "event_at", "observed_at", "source_version", "source_sha256", "claim"})
        urls.append(uri(item["source_url"], safe_url))
        plain(item["publisher"], 160)
        plain(item["claim"], 600)
        for field in ("published_at", "updated_at", "event_at"):
            clock(item[field], nullable=True, source=True)
        clock(item["observed_at"])
        if item["source_version"] is not None:
            plain(item["source_version"], 100)
        sha(item["source_sha256"])
    require(confidence in {"source_stated", "corroborated", "uncertain"}, "Invalid evidence confidence.")
    require(confidence != "corroborated" or len(set(urls)) >= 2, "Corroboration needs distinct cited sources.")


def validate_catalog(value, admitted, safe_url):
    keys(value, {"version", "reviewed_at", "source_sha256", "status", "entities", "relationships", "notes"})
    plain(value["version"], 80)
    clock(value["reviewed_at"], nullable=True)
    sha(value["source_sha256"])
    require(value["status"] == ("unreviewed" if value["reviewed_at"] is None else "review_recorded"), "Catalog review state differs.")
    notes(value["notes"])
    entities = {}
    for item in array(value["entities"], 128):
        keys(item, {"id", "type", "label", "aliases", "summary", "confidence", "evidence"})
        kind = item["type"]
        require(kind in {"cwe", "capec", "actor", "campaign", "product", "mitigation"}, "Unknown intelligence entity type.")
        pattern = CWE if kind == "cwe" else re.compile(r"CAPEC-[1-9][0-9]{0,5}") if kind == "capec" else re.compile(kind.upper() + r"-[a-z0-9][a-z0-9-]{0,63}")
        ident = identifier(item["id"], pattern)
        require(ident not in entities, "Duplicate intelligence entity.")
        entities[ident] = kind
        plain(item["label"], 200)
        plain(item["summary"], 600)
        for alias in array(item["aliases"], 12):
            plain(alias, 160)
        unique(item["aliases"])
        validate_evidence(item["evidence"], safe_url, item["confidence"])
    relation_ids = []
    for item in array(value["relationships"], 256):
        keys(item, {"id", "source_id", "target_id", "relation", "basis", "summary", "confidence", "evidence"})
        relation_ids.append(identifier(item["id"], re.compile(r"REL-[a-z0-9][a-z0-9-]{0,95}")))
        left, right = item["source_id"], item["target_id"]
        require(type(left) is str and type(right) is str and left != right and left in entities.keys() | admitted and right in entities.keys() | admitted,
                "Unresolved intelligence relationship.")
        left_kind, right_kind = entities.get(left, "cve"), entities.get(right, "cve")
        relation, basis = item["relation"], item["basis"]
        require(relation in {"taxonomy_mapping", "attributed_to", "affects_product", "recommended_mitigation", "associated_with"})
        if relation == "taxonomy_mapping":
            require(left_kind == "cwe" and right_kind == "capec" and basis == "catalogue", "Invalid taxonomy relationship.")
            require(all(urlsplit(row["source_url"]).hostname in {"cwe.mitre.org", "capec.mitre.org"} for row in array(item["evidence"], 4)),
                    "Taxonomy mappings need official MITRE evidence.")
        else:
            require(basis == "publisher_claim", "Activity context requires a publisher claim.")
            if relation == "attributed_to":
                require(left_kind == "campaign" and right_kind == "actor")
            elif relation == "affects_product":
                require(left_kind in {"cve", "campaign"} and right_kind == "product")
            elif relation == "recommended_mitigation":
                require(left_kind in {"cve", "cwe", "capec", "campaign", "product"} and right_kind == "mitigation")
        plain(item["summary"], 600)
        validate_evidence(item["evidence"], safe_url, item["confidence"])
    unique(relation_ids)


def validate_configuration(value):
    fixed = {"schema_version": 1, "timezone": "America/Chicago", "daily_hours": [6, 14, 22],
             "weekday_lookback_hours": 24, "weekend_lookback_hours": 48, "weekend_iso_days": [6, 7],
             "periodic_hour": 6, "weekly_iso_day": 1, "fortnight_anchor_start": "2026-10-19",
             "fortnight_days": 14, "rolling_months": 6, "cadences": CADENCES}
    keys(value, set(fixed) | {"schedule_state", "schedule_observed_at", "notes"})
    for field, expected in fixed.items():
        require(type(value[field]) is type(expected) and value[field] == expected, "Unsupported report schedule configuration.")
        if type(expected) is list:
            require(all(type(item) is type(reference) for item, reference in zip(value[field], expected)))
    require(value["schedule_state"] in {"planned", "configured", "paused"}, "Invalid report schedule state.")
    clock(value["schedule_observed_at"], nullable=value["schedule_state"] == "planned")
    notes(value["notes"])


def validate_reports(reports, indexes, safe_url):
    ids = {}
    for item in array(reports, 128):
        keys(item, {"id", "origin", "cadence", "title", "period_start", "period_end", "period_kind", "compiled_at", "compilation_precision", "status", "coverage", "report_url", "data_url", "prior_report_id"})
        ident = identifier(item["id"], REPORT)
        require(ident not in ids)
        ids[ident] = item
        require(item["cadence"] in CADENCES and item["origin"] in {"generated_report", "legacy_report"})
        require(item["status"] in {"published", "partial", "insufficient_evidence", "planned"})
        plain(item["title"], 200)
        legacy = item["origin"] == "legacy_report"
        start = clock(item["period_start"], source=legacy)
        end = clock(item["period_end"], source=legacy)
        require(type(start) is type(end) and (start <= end if legacy else start < end), "Invalid report period.")
        compiled = clock(item["compiled_at"], nullable=True, source=legacy)
        precision = "unknown" if compiled is None else "timestamp" if isinstance(compiled, datetime) else "date"
        require(item["compilation_precision"] == precision, "Report compilation precision differs.")
        if legacy:
            require(item["period_kind"] == "legacy_declared" and item["status"] != "planned" and item["coverage"] == "not_reassessed", "Legacy reports retain their declared date basis.")
        else:
            require(item["period_kind"] in {"rolling_elapsed", "calendar", "month_to_date", "historical_calendar"})
        if item["status"] == "planned":
            require(compiled is None and item["report_url"] is None and item["data_url"] is None and item["coverage"] == "not_yet_available", "Planned reports cannot claim delivery.")
        else:
            require(legacy or compiled is not None and item["coverage"] in {"source_subset", "insufficient"}, "Generated reports need actual compilation evidence.")
            uri(item["report_url"], safe_url, report=True)
            uri(item["data_url"], safe_url, report=True)
        if item["prior_report_id"] is not None:
            identifier(item["prior_report_id"], REPORT)
            require(item["prior_report_id"] != ident)
    labels, urls = [], []
    for item in array(indexes, 16):
        keys(item, {"label", "url"})
        labels.append(plain(item["label"], 120))
        urls.append(uri(item["url"], safe_url, report=True))
    unique(labels)
    unique(urls)
    return ids


def validate_revisions(value, reports, safe_url):
    fixed = {"lookback_hours": 96, "priority_hours": 48, "max_sources": 12,
             "min_success_interval_hours": 8, "min_failure_interval_hours": 24}
    keys(value, set(fixed) | {"state", "report_id", "recorded_at", "nominal_cutoff", "records", "notes"})
    for field, expected in fixed.items():
        require(type(value[field]) is int and value[field] == expected)
    require(value["state"] in {"not_run", "completed", "partial"})
    records = array(value["records"], 12)
    notes(value["notes"])
    if value["state"] == "not_run":
        require(value["report_id"] is None and value["recorded_at"] is None and value["nominal_cutoff"] is None and not records)
        return
    require(type(value["report_id"]) is str and value["report_id"] in reports and reports[value["report_id"]]["status"] != "planned", "Revision review needs an available report.")
    recorded, cutoff = clock(value["recorded_at"]), clock(value["nominal_cutoff"])
    require(cutoff <= recorded)
    urls, ids = [], []
    for item in records:
        keys(item, {"id", "source_url", "status", "recorded_at", "last_cited_at", "last_attempt_at", "checked_at", "prior_checked_at", "old_sha256", "new_sha256", "source_published_at", "source_updated_at", "eligibility_state", "next_eligible_at", "summary", "previous_report_id", "previous_report_url", "evidence_urls", "comparison_scope", "comparison_versions"})
        ids.append(identifier(item["id"], re.compile(r"REV-[a-z0-9][a-z0-9-]{0,95}")))
        urls.append(uri(item["source_url"], safe_url, request=True))
        status = item["status"]
        require(status in REVIEWED | {"refused", "failed", "not_checked"})
        event = clock(item["recorded_at"])
        cited = clock(item["last_cited_at"])
        require(event <= recorded and cutoff - timedelta(hours=96) <= cited <= cutoff)
        attempt = clock(item["last_attempt_at"], nullable=True)
        checked = clock(item["checked_at"], nullable=True)
        prior = clock(item["prior_checked_at"], nullable=True)
        next_at = clock(item["next_eligible_at"], nullable=True)
        require(attempt is None or attempt <= event)
        require(checked is None or checked <= event)
        require(prior is None or prior <= (checked or event))
        for field in ("old_sha256", "new_sha256"):
            sha(item[field], nullable=True)
        for field in ("source_published_at", "source_updated_at"):
            clock(item[field], nullable=True, source=True)
        plain(item["summary"], 600)
        require(item["eligibility_state"] in {"eligible", "cooldown", "deactivated", "unknown"})
        if item["previous_report_id"] is not None:
            identifier(item["previous_report_id"], REPORT)
        if item["previous_report_url"] is not None:
            uri(item["previous_report_url"], safe_url, report=True)
        evidence = [uri(url, safe_url) for url in array(item["evidence_urls"], 4)]
        unique(evidence)
        if item["comparison_scope"] is not None:
            plain(item["comparison_scope"], 200)
        versions = item["comparison_versions"]
        keys(versions, {"prior", "current"})
        for version in versions.values():
            if version is not None:
                identifier(version, re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}"))
        if status in REVIEWED:
            require(attempt is not None and checked is not None and attempt <= checked and item["new_sha256"] is not None, "Successful source review needs a completed qualified response.")
            require(next_at is not None and next_at >= attempt + timedelta(hours=8), "Successful review cooldown is missing.")
            if status == "no_baseline":
                require(item["old_sha256"] is None and prior is None and versions["prior"] is None)
            else:
                require(item["old_sha256"] is not None and prior is not None)
            if status in {"raw_response_changed_unqualified", "material_field_change"}:
                require(item["old_sha256"] != item["new_sha256"])
            if status == "unchanged_supported":
                require(item["old_sha256"] == item["new_sha256"])
            if status in {"material_field_change", "timestamp_only"}:
                require(item["comparison_scope"] is not None and evidence and versions["prior"] is not None and versions["prior"] == versions["current"], "Semantic comparison needs a compatible qualified prior scope.")
        else:
            require(checked is None and item["comparison_scope"] is None and versions == {"prior": None, "current": None}, "Unqualified outcomes cannot claim a fact comparison.")
            if status == "refused":
                require(item["eligibility_state"] == "deactivated" and next_at is None)
            elif attempt is not None:
                require(item["eligibility_state"] == "deactivated" and next_at is None or next_at is not None and next_at >= attempt + timedelta(hours=24), "Failed or uncertain attempt needs a cooldown.")
            require(value["state"] == "partial", "Incomplete source outcomes require a partial review.")
    unique(urls)
    unique(ids)


def validate_intelligence(value, admitted, safe_url):
    keys(value, {"schema_version", "catalog", "reporting", "revisions", "notes"})
    require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    notes(value["notes"])
    validate_catalog(value["catalog"], set(admitted), safe_url)
    reporting = value["reporting"]
    keys(reporting, {"config_sha256", "catalog_sha256", "catalog_updated_at", "configuration", "latest_reports", "indexes", "notes"})
    sha(reporting["config_sha256"])
    sha(reporting["catalog_sha256"])
    clock(reporting["catalog_updated_at"], nullable=True)
    validate_configuration(reporting["configuration"])
    reports = validate_reports(reporting["latest_reports"], reporting["indexes"], safe_url)
    notes(reporting["notes"])
    validate_revisions(value["revisions"], reports, safe_url)
    require(len(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")) <= MAX_INTELLIGENCE,
            "Intelligence wire exceeds its byte bound.")
    return value


def load_inputs(root):
    return (read_input(root / "config/intelligence-context.json", 131072),
            read_input(root / "reports/reporting.json", 16384),
            read_input(root / "reports/catalog.json", 65536))


def compose(root, admitted, safe_url, *, inputs=None):
    (context, context_sha), (configuration, config_sha), (catalog, catalog_sha) = load_inputs(root) if inputs is None else inputs
    keys(context, {"schema_version", "catalog_version", "reviewed_at", "entities", "relationships", "notes"})
    keys(catalog, {"schema_version", "updated_at", "reports", "indexes", "revision_review", "notes"})
    require(type(context["schema_version"]) is int and context["schema_version"] == 1 and
            type(catalog["schema_version"]) is int and catalog["schema_version"] == 1)
    value = {"schema_version": 1,
             "catalog": {"version": context["catalog_version"], "reviewed_at": context["reviewed_at"], "source_sha256": context_sha,
                         "status": "unreviewed" if context["reviewed_at"] is None else "review_recorded",
                         "entities": context["entities"], "relationships": context["relationships"], "notes": context["notes"]},
             "reporting": {"config_sha256": config_sha, "catalog_sha256": catalog_sha, "catalog_updated_at": catalog["updated_at"],
                           "configuration": configuration, "latest_reports": catalog["reports"], "indexes": catalog["indexes"], "notes": catalog["notes"]},
             "revisions": catalog["revision_review"], "notes": []}
    return validate_intelligence(value, admitted, safe_url)
