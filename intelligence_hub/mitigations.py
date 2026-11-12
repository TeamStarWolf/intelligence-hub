"""Attributed CVE briefs from public CVE records and CISA actions, without model calls."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import re

from .epss import valid_score
from .intelligence import CWE, plain, validate_weaknesses

CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,8}")
MAX_RECORDS = 15000
SNAPSHOT_MISMATCH = "The briefs file belongs to a different feed snapshot."


def reject_constant(_value):
    raise ValueError("Nonfinite JSON numbers are not accepted.")


def record_url(cve):
    if not isinstance(cve, str) or not CVE_ID.fullmatch(cve):
        raise ValueError("Invalid CVE identity.")
    _, year, number = cve.split("-")
    return f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{int(number) // 1000}xxx/{cve}.json"


def brief_url(cve):
    return "https://www.cve.org/CVERecord?id=" + cve


def english_values(values, clean, limit=2):
    if not isinstance(values, list):
        return []
    return [clean(item["value"], 600) for item in values[:100]
            if isinstance(item, dict) and isinstance(item.get("value"), str)
            and str(item.get("lang", "en")).lower().startswith("en") and item["value"].strip()][:limit]


def project_weaknesses(cna, cve, clean):
    """Only explicit CNA cweId fields establish a direct CVE/weakness association."""
    types = cna.get("problemTypes", [])
    if not isinstance(types, list):
        raise ValueError("Invalid CNA problemTypes.")
    result, seen, bounded = [], set(), len(types) > 20
    for item in types[:20]:
        if not isinstance(item, dict) or not isinstance(item.get("descriptions", []), list):
            raise ValueError("Invalid CNA problem type descriptions.")
        descriptions = item.get("descriptions", [])
        bounded = bounded or len(descriptions) > 20
        for descriptor in descriptions[:20]:
            if not isinstance(descriptor, dict):
                raise ValueError("Invalid CNA weakness descriptor.")
            description = descriptor.get("description", "")
            if not isinstance(description, str):
                raise ValueError("Invalid CNA weakness description.")
            if "cweId" not in descriptor:
                continue
            ident = descriptor["cweId"]
            if not isinstance(ident, str):
                raise ValueError("Invalid CNA cweId type.")
            if not CWE.fullmatch(ident) or ident in seen:
                continue
            seen.add(ident)
            if len(result) == 8:
                bounded = True
                continue
            description = clean(description, 200)
            plain(description, 200, empty=True)
            result.append({"id": ident, "description": description, "source_url": brief_url(cve)})
    return result, "bounded" if bounded else "supplied" if result else "not_supplied"


def normalize_retained(value, cve):
    """A validated retained projection with the pairs later changes added, read as not_projected when absent."""
    items, status = validate_weaknesses(value, cve, brief_url, legacy=True)
    return {**value, "weaknesses": items, "weaknesses_status": status,
            "adp": value.get("adp"), "adp_status": value.get("adp_status", "not_projected"), "epss": value.get("epss")}

# CISA's ADP container on the same record carries its SSVC decision-point values and, when CISA
# supplied one, its own CVSS metric. It is read beside the CNA's metric and never blended with it.
ADP_PROVIDER = "CISA-ADP"
ADP_STATUSES = {"not_projected", "not_supplied", "supplied"}
ADP_CONTAINERS = 10   # ADP containers inspected for CISA's
METRIC_ENTRIES = 40   # metric entries inspected in a container; the ADP read keeps at most two
ADP_OPTIONS = 10      # SSVC decision points inspected
ADP_TEXT = 40         # characters kept per SSVC value and provider name
SSVC_POINTS = (("Exploitation", "exploitation"), ("Automatable", "automatable"), ("Technical Impact", "technical_impact"))
CVSS_KEYS = (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0"))
CVSS_VERSIONS = {"2.0", "3.0", "3.1", "4.0"}


def first_cvss(metrics, clean):
    """The first supplied valid metric at the highest supported CVSS version in a bounded metric list, or None."""
    for key, version in CVSS_KEYS:
        for metric in metrics[:METRIC_ENTRIES]:
            candidate = metric.get(key) if isinstance(metric, dict) else None
            if not isinstance(candidate, dict):
                continue
            score = candidate.get("baseScore")
            if type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 10:
                return {"score": score, "version": version, "vector": clean(str(candidate.get("vectorString", "")), 250)}
    return None


def project_adp(containers, clean, normalize_date):
    """CISA's ADP container, bounded like the CNA projection: (block, status).

    Only the container whose providerMetadata.shortName is CISA-ADP is read. Its first ssvc
    metric gives the decision-point values and their timestamp; its first valid CVSS metric at
    the highest supported version gives CISA's own score. The kev metric is not read: KEV facts
    come from the catalog. A record without CISA's container is not_supplied.
    """
    adps = containers.get("adp", [])
    if not isinstance(adps, list):
        raise ValueError("Invalid ADP container list.")
    for container in adps[:ADP_CONTAINERS]:
        if not isinstance(container, dict):
            raise ValueError("Invalid ADP container.")
        provider = container.get("providerMetadata", {})
        if not isinstance(provider, dict):
            raise ValueError("Invalid ADP provider metadata.")
        if provider.get("shortName") != ADP_PROVIDER:
            continue
        metrics = container.get("metrics", [])
        if not isinstance(metrics, list):
            raise ValueError("Invalid ADP metrics.")
        ssvc = None
        for metric in metrics[:METRIC_ENTRIES]:
            other = metric.get("other") if isinstance(metric, dict) else None
            if not isinstance(other, dict) or other.get("type") != "ssvc" or not isinstance(other.get("content"), dict):
                continue
            content = other["content"]
            options = content.get("options")
            values = {}
            for option in (options[:ADP_OPTIONS] if isinstance(options, list) else []):
                if isinstance(option, dict) and len(option) == 1:
                    (name, value), = option.items()
                    if isinstance(name, str) and isinstance(value, str) and name not in values:
                        values[name] = clean(value, ADP_TEXT) or None
            ssvc = {field: values.get(name) for name, field in SSVC_POINTS}
            ssvc["timestamp"] = normalize_date(content["timestamp"]) if isinstance(content.get("timestamp"), str) else None
            break
        updated = provider.get("dateUpdated")
        return {"provider": ADP_PROVIDER, "date": normalize_date(updated) if isinstance(updated, str) else None,
                "ssvc": ssvc, "cvss": first_cvss(metrics, clean)}, "supplied"
    return None, "not_supplied"


def validate_adp(value, normalize_date, *, legacy=False):
    """The adp/adp_status pair of a brief or retained projection: (block, status), or ValueError.

    legacy=True reads a projection made before the pair existed as not_projected.
    """
    present = {"adp", "adp_status"} & set(value)
    if not present and legacy:
        return None, "not_projected"
    if present != {"adp", "adp_status"}:
        raise ValueError("Incomplete ADP projection.")
    adp, status = value["adp"], value["adp_status"]
    if status not in ADP_STATUSES:
        raise ValueError("Invalid ADP status.")
    if status != "supplied":
        if adp is not None:
            raise ValueError("ADP status differs from its projection.")
        return None, status

    def clock(item):
        if item is not None and (not isinstance(item, str) or len(item) > 40 or normalize_date(item) is None):
            raise ValueError("Invalid ADP clock.")

    def bounded(item, maximum, *, nullable=True, empty=False):
        if nullable and item is None:
            return
        if not isinstance(item, str) or len(item) > maximum or not (empty or item.strip()):
            raise ValueError("Invalid ADP text.")

    if not isinstance(adp, dict) or set(adp) != {"provider", "date", "ssvc", "cvss"}:
        raise ValueError("Invalid ADP projection.")
    bounded(adp["provider"], ADP_TEXT, nullable=False)
    clock(adp["date"])
    ssvc = adp["ssvc"]
    if ssvc is not None:
        if not isinstance(ssvc, dict) or set(ssvc) != {"exploitation", "automatable", "technical_impact", "timestamp"}:
            raise ValueError("Invalid SSVC projection.")
        for field in ("exploitation", "automatable", "technical_impact"):
            bounded(ssvc[field], ADP_TEXT)
        clock(ssvc["timestamp"])
    cvss = adp["cvss"]
    if cvss is not None:
        if (not isinstance(cvss, dict) or set(cvss) != {"version", "score", "vector"} or cvss["version"] not in CVSS_VERSIONS
                or type(cvss["score"]) not in (int, float) or not math.isfinite(cvss["score"]) or not 0 <= cvss["score"] <= 10):
            raise ValueError("Invalid ADP CVSS metric.")
        bounded(cvss["vector"], 250, nullable=False, empty=True)
    return adp, status


def project_record(raw, cve, clean, safe_url, normalize_date, stamp):
    value = json.loads(raw, parse_constant=reject_constant)
    if not isinstance(value, dict) or not isinstance(value.get("cveMetadata"), dict):
        raise ValueError("Unsupported CVE record.")
    meta = value["cveMetadata"]
    if meta.get("cveId") != cve or meta.get("state") not in {"PUBLISHED", "REJECTED"}:
        raise ValueError("CVE record identity/state differs.")
    containers = value.get("containers", {})
    cna = containers.get("cna", {}) if isinstance(containers, dict) else {}
    if not isinstance(cna, dict):
        raise ValueError("Invalid CNA container.")
    url = brief_url(cve)
    products = []
    affected = cna.get("affected", [])
    if not isinstance(affected, list):
        raise ValueError("Invalid affected product list.")
    for item in affected[:6]:
        if not isinstance(item, dict):
            continue
        versions = []
        values = item.get("versions", [])
        if not isinstance(values, list):
            continue
        for version in values[:12]:
            if isinstance(version, dict):
                versions.append({"version": clean(str(version.get("version", "Not stated")), 160),
                    "status": clean(str(version.get("status", "unknown")), 40),
                    "less_than": clean(str(version.get("lessThan", "")), 160),
                    "less_than_or_equal": clean(str(version.get("lessThanOrEqual", "")), 160),
                    "version_type": clean(str(version.get("versionType", "")), 80)})
        products.append({"vendor": clean(str(item.get("vendor", "Not stated")), 150),
            "product": clean(str(item.get("product") or item.get("packageName") or "Not stated"), 200),
            "default_status": clean(str(item.get("defaultStatus", "unknown")), 40), "versions": versions})
    references = [{"label": "Official CVE record", "url": url, "kind": "record"}]
    values = cna.get("references", [])
    if isinstance(values, list):
        for item in values[:100]:
            if not isinstance(item, dict) or not safe_url(item.get("url")):
                continue
            tags = item.get("tags", [])
            guidance = isinstance(tags, list) and bool(set(str(tag) for tag in tags) & {"vendor-advisory", "patch", "mitigation", "release-notes"})
            references.append({"label": clean(str(item.get("name") or ("CNA guidance reference" if guidance else "CNA reference")), 150),
                "url": safe_url(item["url"]), "kind": "vendor-guidance" if guidance else "record"})
            if len(references) == 16:
                break
    metrics = cna.get("metrics", [])
    cvss = first_cvss(metrics, clean) if isinstance(metrics, list) else None
    if cvss is not None:
        cvss["source_url"] = url
    adp, adp_status = project_adp(containers if isinstance(containers, dict) else {}, clean, normalize_date)
    descriptions = english_values(cna.get("descriptions"), clean, 1)
    rejected = english_values(cna.get("rejectedReasons"), clean, 1)
    weaknesses, weakness_status = project_weaknesses(cna, cve, clean)
    return {"cve": cve, "title": clean(str(cna.get("title") or cve), 300),
        "description": (rejected or descriptions or [""])[0],
        "record_state": meta["state"], "source_status": "ok", "retrieved_at": stamp,
        "source_attempted_at": stamp, "source_updated_at": normalize_date(meta.get("dateUpdated") or ""),
        "source_sha256": hashlib.sha256(raw).hexdigest(), "products": products,
        "solutions": [{"text": text, "source_url": url} for text in english_values(cna.get("solutions"), clean)],
        "workarounds": [{"text": text, "source_url": url} for text in english_values(cna.get("workarounds"), clean)],
        "cvss": cvss, "references": references, "weaknesses": weaknesses, "weaknesses_status": weakness_status,
        "adp": adp, "adp_status": adp_status,
        "projection_notes": ["CNA fields are bounded excerpts; consult the original record and vendor advisories for complete product/version conditions.",
            "Product statements can include unaffected versions. An affected version range is not a fixed-version claim.",
            "The displayed metric is the first supplied metric of the highest available CVSS version, not a product-specific applicability assessment."]}


def valid_projection(value, cve, safe_url, normalize_date):
    """Validate retained public projections before reusing their facts or URLs."""
    if not isinstance(value, dict) or value.get("cve") != cve or not CVE_ID.fullmatch(cve):
        return False
    try:
        validate_weaknesses(value, cve, brief_url, legacy=True)
        validate_adp(value, normalize_date, legacy=True)
    except (ValueError, TypeError, KeyError):
        return False
    if value.get("source_status") not in {"ok", "failed", "pending"} or value.get("record_state") not in {"PUBLISHED", "REJECTED", "UNKNOWN"}:
        return False
    # FIRST's EPSS block (WP-03) rides on the record: absent or null before a read, else a valid block.
    if value.get("epss") is not None and not valid_score(value["epss"]):
        return False
    for field in ("source_updated_at", "retrieved_at", "source_attempted_at"):
        item = value.get(field)
        if item is not None and (not isinstance(item, str) or len(item) > 40 or normalize_date(item) is None):
            return False
    for field, maximum in (("title", 300), ("description", 600)):
        if not isinstance(value.get(field), str) or len(value[field]) > maximum:
            return False
    digest = value.get("source_sha256")
    if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)):
        return False
    if value["source_status"] == "ok" and (not value.get("retrieved_at") or not value.get("source_attempted_at") or not digest or value["record_state"] == "UNKNOWN"):
        return False
    for field in ("solutions", "workarounds"):
        if not isinstance(value.get(field), list) or len(value[field]) > 2:
            return False
        if any(not isinstance(item, dict) or not isinstance(item.get("text"), str) or len(item["text"]) > 600 or not safe_url(item.get("source_url")) for item in value[field]):
            return False
    refs = value.get("references")
    if not isinstance(refs, list) or len(refs) > 20 or any(not isinstance(item, dict) or not isinstance(item.get("label"), str) or len(item["label"]) > 150 or not safe_url(item.get("url")) or item.get("kind") not in {"record", "vendor-guidance"} for item in refs):
        return False
    products = value.get("products")
    if not isinstance(products, list) or len(products) > 6:
        return False
    for product in products:
        if not isinstance(product, dict):
            return False
        for field, maximum in (("vendor", 150), ("product", 200), ("default_status", 40)):
            if not isinstance(product.get(field), str) or len(product[field]) > maximum:
                return False
        if not isinstance(product.get("versions"), list) or len(product["versions"]) > 12:
            return False
        for version in product["versions"]:
            if not isinstance(version, dict) or any(not isinstance(version.get(field), str) or len(version[field]) > maximum for field, maximum in (("version", 160), ("status", 40), ("less_than", 160), ("less_than_or_equal", 160), ("version_type", 80))):
                return False
    cvss = value.get("cvss")
    if cvss is not None and (not isinstance(cvss, dict) or type(cvss.get("score")) not in (int, float) or not math.isfinite(cvss["score"]) or not 0 <= cvss["score"] <= 10 or cvss.get("version") not in {"2.0", "3.0", "3.1", "4.0"} or not isinstance(cvss.get("vector"), str) or len(cvss["vector"]) > 250 or not safe_url(cvss.get("source_url"))):
        return False
    return True


def blank(cve):
    return {"cve": cve, "title": cve, "description": "", "source_status": "pending", "record_state": "UNKNOWN",
        "source_updated_at": None, "retrieved_at": None, "source_attempted_at": None, "source_sha256": None,
        "products": [], "solutions": [], "workarounds": [], "cvss": None, "weaknesses": [], "weaknesses_status": "not_projected",
        "adp": None, "adp_status": "not_projected", "epss": None,
        "references": [{"label": "Official CVE record", "url": brief_url(cve), "kind": "record"}], "projection_notes": []}


def merge_retained(local, remote, cve, safe_url, normalize_date):
    """Keep newest retrieved facts and the latest independently recorded attempt."""
    values = [item for item in (local, remote) if valid_projection(item, cve, safe_url, normalize_date)]
    if not values:
        return blank(cve)
    def clock(item, field):
        return normalize_date(item.get(field) or "") or ""
    successful = [item for item in values if item.get("retrieved_at") and item.get("source_sha256")]
    facts = normalize_retained(max(successful, key=lambda item: clock(item, "retrieved_at")), cve) if successful else blank(cve)
    result = {key: facts[key] for key in blank(cve) if key != "projection_notes"}
    result["projection_notes"] = []
    latest = max(values, key=lambda item: clock(item, "source_attempted_at"))
    result.update(source_status=latest["source_status"], source_attempted_at=latest.get("source_attempted_at"))
    # FIRST's EPSS block is read apart from the CNA record, so it is merged apart: the block with the
    # newest score date among the valid records, whichever record carried it and whether or not that
    # record's CNA read succeeded, so a retained score survives a resume and a failed batch.
    blocks = [item["epss"] for item in values if valid_score(item.get("epss"))]
    result["epss"] = max(blocks, key=lambda block: block["date"]) if blocks else None
    return result


def build_briefs(articles, catalog, retained, refresh, budget, fetch, clean, safe_url, normalize_date, stamp, scores=None):
    """The briefs, the retained projections to keep and the coverage counts.

    scores is epss.collect_scores' map for this run: a CVE in it takes that value (a block, or
    None for no score on the day); a CVE absent from it keeps the retained value.
    """
    wanted = sorted({cve for article in articles for cve in article["cves"]}, reverse=True)
    if not isinstance(retained, dict):
        raise ValueError("Invalid retained CVE projections.")
    if len(wanted) > MAX_RECORDS:
        raise ValueError("The articles link " + format(len(wanted), ",") + " CVEs, over the " + format(MAX_RECORDS, ",") +
                         "-brief ceiling. Nothing was evicted; the deployed publication is preserved.")
    records = {cve: normalize_retained(retained[cve], cve) if cve in retained and valid_projection(retained[cve], cve, safe_url, normalize_date) else blank(cve) for cve in wanted}
    current = datetime.fromisoformat(stamp)

    def due(cve):
        record = records[cve]
        # A successful projection made before a later field existed is read again within the
        # budget, ahead of its 24-hour interval: the weakness pair (schema 5) and CISA's ADP block.
        if record["source_status"] == "ok" and "not_projected" in (record["weaknesses_status"], record["adp_status"]):
            return True
        previous = record.get("source_attempted_at")
        if previous is None:
            return True
        try:
            age = current - datetime.fromisoformat(previous.replace("Z", "+00:00"))
            return age >= timedelta(hours=1 if record["source_status"] == "failed" else 24)
        except (ValueError, TypeError):
            return True

    pending = sorted((cve for cve in wanted if due(cve)), key=lambda cve: (records[cve].get("retrieved_at") is not None, records[cve].get("source_attempted_at") or ""))[:budget]

    def update(cve):
        attempted = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            raw = fetch(record_url(cve))
            completed = datetime.now(timezone.utc).isoformat(timespec="seconds")
            projection = project_record(raw, cve, clean, safe_url, normalize_date, completed)
            # The EPSS block is read separately (epss.py); a fresh CNA projection keeps the retained one.
            return cve, {**projection, "source_attempted_at": attempted, "epss": records[cve].get("epss")}
        except (OSError, ValueError, TypeError, RecursionError):
            return cve, {**records[cve], "source_status": "failed", "source_attempted_at": attempted}

    if refresh and pending:
        with ThreadPoolExecutor(max_workers=4) as pool:
            records.update(pool.map(update, pending))
    for cve, value in (scores or {}).items():
        if cve in records:
            require_score = value is None or valid_score(value)
            if not require_score:
                raise ValueError("Invalid EPSS score for " + cve + ".")
            records[cve] = {**records[cve], "epss": value}
    kev_by_id = {item["cveID"]: item for item in catalog.get("vulnerabilities", [])}
    result = {}
    for cve, projection in records.items():
        record = {key: projection[key] for key in ("cve", "title", "description", "source_status", "record_state", "source_updated_at", "retrieved_at", "source_attempted_at", "source_sha256", "products", "solutions", "workarounds", "cvss", "references", "weaknesses", "weaknesses_status", "adp", "adp_status", "epss")}
        item = kev_by_id.get(cve)
        cisa_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=" + cve
        action = clean(item.get("requiredAction", ""), 1200) if item else ""
        record["required_action"] = action or None
        record["required_action_source_url"] = cisa_url if action else None
        record["kev"] = {"date_added": item["dateAdded"], "due_date": normalize_date(item.get("dueDate", "")),
            "ransomware": clean(str(item.get("knownRansomwareCampaignUse", "Unknown")), 60)} if item else None
        rejected = record["record_state"] == "REJECTED"
        guidance = "needs-review" if rejected else "publisher-guidance" if record["solutions"] or record["workarounds"] else "cisa-action" if action else "needs-review"
        assessment = ("The official CVE record is rejected. Reconcile the current record and any older publisher/CISA references before treating it as an active vulnerability." if rejected else
            "CISA records exploitation in the wild. Prioritize checking affected assets and the cited required action; this does not establish exposure on your devices." if item else
            "Check the publisher's product/version statements and guidance. Absence from this KEV input does not establish that exploitation is absent.")
        steps = [{"title": "Establish applicability", "detail": "Compare the exact installed product, version and deployment conditions with the cited publisher record; no environment inventory was checked by this hub.", "evidence_url": brief_url(cve)}]
        if rejected:
            steps.append({"title": "Resolve the rejected record", "detail": "Use the current CVE explanation and any replacement identifier before selecting remediation.", "evidence_url": brief_url(cve)})
        elif action:
            steps.append({"title": "Review the CISA action", "detail": action, "evidence_url": cisa_url})
        for value in ([] if rejected else record["solutions"]):
            steps.append({"title": "Publisher solution excerpt", "detail": value["text"], "evidence_url": value["source_url"]})
        for value in ([] if rejected else record["workarounds"]):
            steps.append({"title": "Publisher workaround excerpt", "detail": value["text"], "evidence_url": value["source_url"]})
        if not action and not record["solutions"] and not record["workarounds"] and not rejected:
            steps.append({"title": "Vendor guidance needs review", "detail": "No patch version or workaround is established in the loaded structured inputs. Follow the CVE/vendor references; this hub will not invent a fix.", "evidence_url": brief_url(cve)})
        steps.append({"title": "Confirm remediation", "detail": "After an authorized change, confirm the installed version/configuration against vendor guidance and retain evidence. This feed does not patch or verify a device.", "evidence_url": None})
        limitations = ["This is a deterministic source-grounded briefing, not an environment assessment or an automatic patch instruction.", "Product/version conditions and guidance excerpts are bounded; the original vendor advisory controls applicability."]
        if item:
            limitations.append("The displayed CISA due date is a catalog/federal directive datum, not a deadline assigned to this site's visitors.")
        if record["source_status"] != "ok":
            limitations.append("CNA enrichment is pending or its last attempt failed. Any retained successful record keeps its original retrieval date; missing guidance is unknown.")
        if record["cvss"]:
            limitations.append("CVSS versions and product contexts differ; a numeric sort is not an organization-specific risk ranking.")
        record["analysis"] = {"priority": "known-exploited" if item else "review", "guidance_status": guidance,
            "assessment": assessment, "steps": steps, "limitations": limitations}
        result[cve] = record
    stats = {"total": len(result), "cna_loaded": sum(value["source_status"] == "ok" for value in result.values()),
        "cisa_actions": sum(bool(value["required_action"]) for value in result.values()),
        "publisher_guidance": sum(value["analysis"]["guidance_status"] == "publisher-guidance" for value in result.values()),
        "needs_review": sum(value["analysis"]["guidance_status"] == "needs-review" for value in result.values()),
        "attempted_this_run": len(pending) if refresh else 0}
    return result, records, stats


# The public site splits one snapshot into two files. data/feed.json keeps a
# compact row per CVE for list views; data/briefs.json holds the full briefs and
# is read only when a reader opens one.
# Index version 2 added ssvc_exploitation, CISA's SSVC Exploitation value (WP-04); version 3 adds
# epss, FIRST's EPSS block {score, percentile, date, model} or null (WP-03). cvss_score and
# cvss_version are the CNA's metric; CISA's ADP CVSS is only in the brief.
INDEX_VERSION = 3
INDEX_FIELDS = ("record_state", "source_status", "guidance_status", "required_action",
                "cvss_score", "cvss_version", "kev_date_added", "weaknesses", "ssvc_exploitation", "epss")
# The earlier layouts, as the feeds published before WP-04 and before WP-03 carry them; the
# archive validator still reads both.
INDEX_FIELDS_V2 = INDEX_FIELDS[:-1]
INDEX_FIELDS_V1 = INDEX_FIELDS[:-2]
INDEX_VERSIONS = (1, 2, INDEX_VERSION)
BRIEFS_KEYS = {"schema_version", "feed_schema_version", "generated_at", "content_revision", "briefs"}


def index_fields(version):
    if version not in INDEX_VERSIONS:
        raise ValueError("Unsupported brief index version.")
    return {1: INDEX_FIELDS_V1, 2: INDEX_FIELDS_V2, INDEX_VERSION: INDEX_FIELDS}[version]


def index_row(brief, version=INDEX_VERSION):
    cvss = brief.get("cvss") or {}
    kev = brief.get("kev") or {}
    row = [brief["record_state"], brief["source_status"], brief["analysis"]["guidance_status"],
           bool(brief["required_action"]), cvss.get("score"), cvss.get("version"), kev.get("date_added"),
           [item["id"] for item in brief.get("weaknesses", [])]]
    if version >= 2:
        row.append(((brief.get("adp") or {}).get("ssvc") or {}).get("exploitation"))
    if version >= INDEX_VERSION:
        row.append(brief.get("epss"))
    return row


def brief_index(briefs, version=INDEX_VERSION):
    """The per-CVE fields that list views, filters and counts need, in CVE order."""
    fields = index_fields(version)
    return {"version": version, "fields": list(fields), "rows": {cve: index_row(briefs[cve], version) for cve in sorted(briefs)}}


def split_publication(snapshot):
    """One validated snapshot becomes the feed file and the briefs file."""
    feed = {key: value for key, value in snapshot.items() if key != "mitigations"}
    briefs = {"schema_version": 1, "feed_schema_version": snapshot["schema_version"], "generated_at": snapshot["generated_at"],
              "content_revision": snapshot["content_revision"], "briefs": snapshot["mitigations"]}
    return feed, briefs


def join_publication(feed, briefs):
    """Rejoin the two public files of one run; files from different runs are refused."""
    if not isinstance(feed, dict) or "mitigations" in feed or not isinstance(briefs, dict) or set(briefs) != BRIEFS_KEYS:
        raise ValueError("Unexpected feed or briefs file fields.")
    if type(briefs["schema_version"]) is not int or briefs["schema_version"] != 1 or not isinstance(briefs["briefs"], dict):
        raise ValueError("Unsupported briefs file.")
    if (briefs["feed_schema_version"] != feed.get("schema_version") or briefs["generated_at"] != feed.get("generated_at")
            or briefs["content_revision"] != feed.get("content_revision")):
        raise ValueError(SNAPSHOT_MISMATCH)
    return {**feed, "mitigations": briefs["briefs"]}
