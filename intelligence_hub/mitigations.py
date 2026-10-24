"""Attributed CVE briefs from public CVE records and CISA actions, without model calls."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import re

CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,8}")
MAX_RECORDS = 15000


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
    cvss = None
    metrics = cna.get("metrics", [])
    if isinstance(metrics, list):
        for key, version in (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0")):
            for metric in metrics[:40]:
                candidate = metric.get(key) if isinstance(metric, dict) else None
                if not isinstance(candidate, dict):
                    continue
                score = candidate.get("baseScore")
                if type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 10:
                    cvss = {"score": score, "version": version,
                        "vector": clean(str(candidate.get("vectorString", "")), 250), "source_url": url}
                    break
            if cvss is not None:
                break
    descriptions = english_values(cna.get("descriptions"), clean, 1)
    rejected = english_values(cna.get("rejectedReasons"), clean, 1)
    return {"cve": cve, "title": clean(str(cna.get("title") or cve), 300),
        "description": (rejected or descriptions or [""])[0],
        "record_state": meta["state"], "source_status": "ok", "retrieved_at": stamp,
        "source_attempted_at": stamp, "source_updated_at": normalize_date(meta.get("dateUpdated") or ""),
        "source_sha256": hashlib.sha256(raw).hexdigest(), "products": products,
        "solutions": [{"text": text, "source_url": url} for text in english_values(cna.get("solutions"), clean)],
        "workarounds": [{"text": text, "source_url": url} for text in english_values(cna.get("workarounds"), clean)],
        "cvss": cvss, "references": references,
        "projection_notes": ["CNA fields are bounded excerpts; consult the original record and vendor advisories for complete product/version conditions.",
            "Product statements can include unaffected versions. An affected version range is not a fixed-version claim.",
            "The displayed metric is the first supplied metric of the highest available CVSS version, not a product-specific applicability assessment."]}


def valid_projection(value, cve, safe_url, normalize_date):
    """Validate retained public projections before reusing their facts or URLs."""
    if not isinstance(value, dict) or value.get("cve") != cve or not CVE_ID.fullmatch(cve):
        return False
    if value.get("source_status") not in {"ok", "failed", "pending"} or value.get("record_state") not in {"PUBLISHED", "REJECTED", "UNKNOWN"}:
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
        "products": [], "solutions": [], "workarounds": [], "cvss": None,
        "references": [{"label": "Official CVE record", "url": brief_url(cve), "kind": "record"}], "projection_notes": []}


def merge_retained(local, remote, cve, safe_url, normalize_date):
    """Keep newest retrieved facts and the latest independently recorded attempt."""
    values = [item for item in (local, remote) if valid_projection(item, cve, safe_url, normalize_date)]
    if not values:
        return blank(cve)
    def clock(item, field):
        return normalize_date(item.get(field) or "") or ""
    successful = [item for item in values if item.get("retrieved_at") and item.get("source_sha256")]
    facts = max(successful, key=lambda item: clock(item, "retrieved_at")) if successful else blank(cve)
    result = {key: facts[key] for key in blank(cve) if key != "projection_notes"}
    result["projection_notes"] = []
    latest = max(values, key=lambda item: clock(item, "source_attempted_at"))
    result.update(source_status=latest["source_status"], source_attempted_at=latest.get("source_attempted_at"))
    return result


def build_briefs(articles, catalog, retained, refresh, budget, fetch, clean, safe_url, normalize_date, stamp):
    wanted = sorted({cve for article in articles for cve in article["cves"]}, reverse=True)
    if len(wanted) > MAX_RECORDS or not isinstance(retained, dict):
        raise ValueError("CVE projection count exceeds its bound.")
    records = {cve: retained[cve] if cve in retained and valid_projection(retained[cve], cve, safe_url, normalize_date) else blank(cve) for cve in wanted}
    current = datetime.fromisoformat(stamp)

    def due(cve):
        record = records[cve]
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
            return cve, {**projection, "source_attempted_at": attempted}
        except (OSError, ValueError, TypeError, RecursionError):
            return cve, {**records[cve], "source_status": "failed", "source_attempted_at": attempted}

    if refresh and pending:
        with ThreadPoolExecutor(max_workers=4) as pool:
            records.update(pool.map(update, pending))
    kev_by_id = {item["cveID"]: item for item in catalog.get("vulnerabilities", [])}
    result = {}
    for cve, projection in records.items():
        record = {key: projection[key] for key in ("cve", "title", "description", "source_status", "record_state", "source_updated_at", "retrieved_at", "source_attempted_at", "source_sha256", "products", "solutions", "workarounds", "cvss", "references")}
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
