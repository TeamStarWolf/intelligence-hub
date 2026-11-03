"""One pure tagger per field. Each takes (row, context) and returns its tags, sorted.

A row is a v6 feed article. The context (engine.Context) holds the vocabulary, the
source registry, the KEV catalog by CVE and the CVE briefs by CVE; it is read-only.
"""
from .match import words

NEVER_VENDOR = {"multiple products", "multiple", "unknown", "n/a", "na", "none", "various", "multiple vendors"}
ADVISORY_KINDS = {"advisory", "bulletin", "note"}
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def tag(value, method, confidence, **extra):
    item = {"value": value, "method": method, "confidence": confidence}
    item.update({key: field for key, field in extra.items() if field is not None})
    return item


def best(tags):
    """One tag per value: the most confident, then the first method in sort order. Sorted by value."""
    chosen = {}
    for item in tags:
        key = (item["value"], item.get("role"))
        current = chosen.get(key)
        rank = (CONFIDENCE_ORDER[item["confidence"]], item["method"], tuple(item.get("path", ())))
        if current is None or rank < (CONFIDENCE_ORDER[current["confidence"]], current["method"], tuple(current.get("path", ()))):
            chosen[key] = item
    return [chosen[key] for key in sorted(chosen, key=lambda key: (key[0], key[1] or ""))]


def source_info(row, context):
    return context.source(row["source_id"])


def tag_kind(row, context):
    return [tag(row["kind"], "source-kind", "high")] if row["kind"] in context.vocab.values["kind"] else []


def tag_source_class(row, context):
    info = source_info(row, context)
    return [tag(info["source_class"], "source-registry", "high")] if info else []


def _row_cves(row):
    return sorted(set(row.get("cves") or []))


def tag_exploitation(row, context):
    """The evidence rule: kev, vendor-structured, curated-primary, title-term, else unknown. Never 'not exploited'."""
    if any(cve in context.kev for cve in _row_cves(row)):
        return [tag("known", "kev", "high")]
    evidence = row.get("exploitation_evidence")
    if isinstance(evidence, dict) and evidence.get("basis") == "vendor-structured" and evidence.get("exploited") is True:
        return [tag("known", "vendor-structured", "high")]
    if row.get("origin") == "library-curation" and row.get("exploitation") in {"known", "reported"}:
        return [tag(row["exploitation"], "curated-primary", "medium")]
    if context.exploitation_terms(row["title"]):
        info = source_info(row, context)
        confidence = "low" if not info or info["source_class"] == "press" else "medium"
        return [tag("reported", "title-term", confidence)]
    return [tag("unknown", "none", "high")]


def tag_event_type(row, context, exploitation):
    info = source_info(row, context) or {}
    found = []
    if row["kind"] in ADVISORY_KINDS:
        strong = info.get("source_class") == "vendor-primary" or bool(row.get("cves"))
        found.append(tag("disclosure", "kind-default", "high" if strong else "medium"))
        if info.get("source_class") == "vendor-primary":
            found.append(tag("patch", "source-primary", "high"))
    if exploitation and exploitation[0]["value"] in {"known", "reported"}:
        found.append(tag("exploitation", "exploitation-tag", exploitation[0]["confidence"]))
    for value in context.event_terms(row["title"]):
        found.append(tag(value, "title-term", "medium"))
    found = best(found)
    if not found:
        found = [tag("analysis", "kind-default", "medium")] if row["kind"] == "research" else [tag("unclassified", "none", "high")]
    return found


def _entity_tags(matches, context, kinds, method, confidence):
    found = []
    for phrase, ids, weak in matches:
        typed = {}
        for ident in ids:
            typed.setdefault(ident.split(":", 1)[0], []).append(ident)
        for kind, members in typed.items():
            # Two entities of one type behind one name: ambiguous, so neither is tagged.
            if kind in kinds and len(members) == 1:
                found.append(tag(members[0], method, "low" if weak else confidence))
    return found


def _structured_vendor(context, value):
    """Vendor ids named by a structured vendor string (a CNA or KEV vendor field)."""
    if not isinstance(value, str) or value.strip().casefold() in NEVER_VENDOR:
        return []
    exact = context.vendor_spellings.get(value.strip())
    if exact:
        return [exact]
    return sorted({ident for _phrase, ids, _weak in context.find(value) for ident in ids if ident.startswith("vendor:")})


def _structured_products(context, vendor, product):
    if not isinstance(product, str) or product.strip().casefold() in NEVER_VENDOR:
        return []
    text = (vendor or "") + " " + product
    return sorted({ident for _phrase, ids, _weak in context.find(text) for ident in ids if ident.startswith("product:")})


def tag_entities(row, context):
    """vendor, product, actor and malware tags as {field: [tags]}."""
    found = {"vendor": [], "product": [], "actor": [], "malware": []}
    info = source_info(row, context) or {}
    if info.get("source_class") == "vendor-primary" and info.get("publisher_vendor") in context.vocab.entities:
        found["vendor"].append(tag(info["publisher_vendor"], "source-identity", "high"))
    for cve in _row_cves(row):
        entry = context.kev.get(cve)
        if entry:
            for ident in _structured_vendor(context, entry.get("vendorProject")):
                found["vendor"].append(tag(ident, "kev-vendor", "high"))
            for ident in _structured_products(context, entry.get("vendorProject"), entry.get("product")):
                found["product"].append(tag(ident, "kev-product", "high"))
        brief = context.briefs.get(cve) or {}
        for affected in brief.get("products") or []:
            if isinstance(affected, dict):
                for ident in _structured_vendor(context, affected.get("vendor")):
                    found["vendor"].append(tag(ident, "cna-affected", "high"))
                for ident in _structured_products(context, affected.get("vendor"), affected.get("product")):
                    found["product"].append(tag(ident, "cna-affected", "high"))
    for field, items in _split(_entity_tags(context.find(row["title"]), context, set(found), "title-match", "medium")).items():
        found[field].extend(items)
    # A product names its vendor.
    for item in list(found["product"]):
        vendor = context.vocab.entities[item["value"]].get("vendor")
        if vendor in context.vocab.entities:
            found["vendor"].append(tag(vendor, "product-vendor", item["confidence"]))
    return {field: best(items) for field, items in found.items()}


def _split(tags):
    out = {}
    for item in tags:
        out.setdefault(item["value"].split(":", 1)[0], []).append(item)
    return out


def tag_sector(row, context):
    found = [tag(value, "title-term", "medium") for value in context.sector_terms(row["title"])]
    return best(found)


def tag_region(row, context):
    found = []
    info = source_info(row, context) or {}
    if info.get("country") in context.vocab.values["region"]:
        found.append(tag(info["country"], "source-identity", "high", role="publisher"))
    for value in context.region_names(row["title"]):
        found.append(tag(value, "title-match", "medium", role="mentioned"))
    return best(found)


def tag_cwe(row, context):
    found = []
    for cve in _row_cves(row):
        for weakness in (context.briefs.get(cve) or {}).get("weaknesses") or []:
            if isinstance(weakness, dict) and weakness.get("id") in context.vocab.cwe:
                found.append(tag(weakness["id"], "cna-problemtypes", "high"))
        entry = context.kev.get(cve) or {}
        for value in entry.get("cwes") or []:
            if value in context.vocab.cwe:
                found.append(tag(value, "kev-cwes", "high"))
    return best(found)


def tag_attack(row, context, cwes):
    """ATT&CK techniques reached from the row's CWEs through CAPEC. Sparse and taxonomic, never observed behaviour."""
    found = []
    for item in cwes:
        for capec, technique, path in context.cwe_chain(item["value"]):
            found.append(tag(technique, "cwe-capec", "low", tactics=context.vocab.tactics[technique]["tactics"], path=path))
    return best(found)


def tag_cvss(row, context):
    """The highest CNA CVSS base score among the row's CVEs, with its version and vector. Versions are never merged."""
    scores = []
    for cve in _row_cves(row):
        cvss = (context.briefs.get(cve) or {}).get("cvss")
        if isinstance(cvss, dict) and isinstance(cvss.get("score"), (int, float)):
            scores.append((-float(cvss["score"]), cve, cvss))
    if not scores:
        return None
    _score, cve, cvss = sorted(scores, key=lambda item: (item[0], item[1]))[0]
    return {"base": cvss["score"], "version": cvss.get("version"), "vector": cvss.get("vector"), "scorer": "cna", "cve": cve}


def tag_kev(row, context):
    """KEV facts for the row's CVEs that are in the catalog: the earliest addition and its due date."""
    entries = sorted((context.kev[cve].get("dateAdded"), cve) for cve in _row_cves(row) if cve in context.kev)
    if not entries:
        return None
    added, cve = entries[0]
    entry = context.kev[cve]
    published = (row.get("published_at") or "")[:10]
    return {"cves": [item[1] for item in entries], "added": added, "due": entry.get("dueDate") or None,
            "ransomware": entry.get("knownRansomwareCampaignUse") or None,
            "at_publication": bool(published) and added <= published}
