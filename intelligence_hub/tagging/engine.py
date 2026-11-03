"""The tagging engine: builds the read-only context once, then tags rows in a fixed order."""
import re

from . import fields
from .match import PhraseIndex, term_pattern, tokens, words

TAGGER_VERSION = "2026.11.1"
ENTITY_FIELDS = ("vendor", "product", "actor", "malware")
MULTI_FIELDS = ("event_type", "vendor", "product", "actor", "malware", "sector", "region", "cwe", "attack")
V6_TAG_LIMIT = 30


class Context:
    """Everything a tagger may read. Built once per run from the vocabulary and this run's inputs."""

    def __init__(self, vocab, registry, kev_catalog, briefs):
        self.vocab = vocab
        self._sources = {}
        for ident, item in vocab.hub["source_class"].get("sources", {}).items():
            self._sources[ident] = {"source_class": item["source_class"], "publisher_vendor": item.get("publisher_vendor"),
                                    "country": item.get("country")}
        for source in registry:
            self._sources[source["id"]] = {"source_class": source.get("source_class"), "publisher_vendor": source.get("publisher_vendor"),
                                           "country": source.get("country")}
        self.kev = {}
        for entry in (kev_catalog or {}).get("vulnerabilities", []) if isinstance(kev_catalog, dict) else []:
            if isinstance(entry, dict) and isinstance(entry.get("cveID"), str):
                self.kev[entry["cveID"]] = entry
        self.briefs = briefs if isinstance(briefs, dict) else {}
        self._build_entities()
        self._build_terms()
        self._chains = {}

    def source(self, ident):
        item = self._sources.get(ident)
        return item if item and item.get("source_class") in self.vocab.values["source_class"] else None

    # Entities ------------------------------------------------------------------------

    def _build_entities(self):
        rules = self.vocab.hub["matching"]
        stop = {item["alias"] for item in rules.get("stop", [])}
        allow_short = set(rules["allow_short"])
        minimum = rules["min_length"]
        # A name with a context rule is only ever matched weakly, with one of its context words.
        weak_only = {(item["id"], item["alias"]) for item in rules.get("context", [])}
        self.strong = PhraseIndex()
        self.weak = PhraseIndex()
        self.context_words = {}
        self.vendor_spellings = {}
        spellings = {}
        for ident, entity in sorted(self.vocab.entities.items()):
            kind = entity["type"]
            if kind == "sector":
                continue
            blocked = set(entity.get("stop_aliases", [])) | set(entity.get("ambiguous_aliases", [])) | stop
            for name in entity.get("match", []):
                if name in blocked or (ident, name) in weak_only:
                    continue
                if kind in {"actor", "malware"} and len(name) < minimum and name not in allow_short and not (
                        re.search(r"[0-9]", name) or re.search(r"[A-Z]", name[1:])):
                    continue
                self.strong.add(name, ident)
            if kind == "vendor":
                for name in [entity["label"], *entity.get("kev_vendor_project", []), *entity.get("match", [])]:
                    spellings.setdefault(name, set()).add(ident)
        self.vendor_spellings = {name: next(iter(ids)) for name, ids in spellings.items() if len(ids) == 1}
        for item in rules.get("context", []):
            if item["id"] in self.vocab.entities:
                self.weak.add(item["alias"], item["id"])
                self.context_words.setdefault(tokens(item["alias"]), {}).setdefault(item["id"], {word.casefold() for word in item["words"]})

    def find(self, text):
        """[(phrase, ids, weak)]: strong matches, then context-confirmed weak ones that overlap no strong match."""
        strong = self.strong.find(text)
        covered = set()
        out = []
        for start, key, ids in strong:
            covered.update(range(start, start + len(key)))
            out.append((key, ids, False))
        present = words(text)
        for start, key, ids in self.weak.find(text):
            if covered & set(range(start, start + len(key))):
                continue
            confirmed = [ident for ident in ids if self._confirmed(key, ident, present, text)]
            if confirmed:
                out.append((key, confirmed, True))
        return out

    def _confirmed(self, key, ident, present, text):
        wanted = self.context_words.get(key, {}).get(ident, set())
        return any((word in present) if " " not in word else (word in text.casefold()) for word in wanted)

    # Terms ---------------------------------------------------------------------------

    def _build_terms(self):
        hub = self.vocab.hub
        exploitation = hub["exploitation"]
        self._exploit = term_pattern(exploitation["title_terms"])
        self._zero_day = term_pattern(exploitation["zero_day_terms"])
        self._zero_day_verbs = term_pattern(exploitation["zero_day_verbs"])
        self._negation = term_pattern(exploitation["negations"])
        self._events = [(item["value"], term_pattern(item.get("terms", []))) for item in hub["event_type"]["values"] if item.get("terms")]
        self._sectors = [("sector:" + item["value"], term_pattern(item.get("terms", []))) for item in hub["sector"]["values"] if item.get("terms")]
        self._sector_names = PhraseIndex()
        for ident, entity in self.vocab.entities.items():
            if entity["type"] == "sector":
                # One-word sector names (Communications, Energy) are product words too; only longer names match.
                for name in entity.get("match", []):
                    if len(tokens(name)) >= 2:
                        self._sector_names.add(name, ident)
        self._regions = PhraseIndex()
        for item in hub["region"]["values"]:
            for name in item.get("names", []):
                self._regions.add(name, item["value"])

    def exploitation_terms(self, title):
        if self._negation and self._negation.search(title):
            return False
        if self._exploit and self._exploit.search(title):
            return True
        return bool(self._zero_day and self._zero_day.search(title) and self._zero_day_verbs and self._zero_day_verbs.search(title))

    def event_terms(self, title):
        return sorted({value for value, pattern in self._events if pattern and pattern.search(title)})

    def sector_terms(self, title):
        found = {value for value, pattern in self._sectors if pattern and pattern.search(title)}
        found.update(ident for _start, _key, ids in self._sector_names.find(title) for ident in ids)
        return sorted(found)

    def region_names(self, title):
        return sorted({ident for _start, _key, ids in self._regions.find(title) for ident in ids})

    # ATT&CK chain --------------------------------------------------------------------

    def forward(self, technique):
        """Follow revoked ATT&CK ids to their successors; None when the id is deprecated or unknown."""
        seen = set()
        while technique not in self.vocab.tactics:
            if technique in seen or technique not in self.vocab.superseded:
                return None
            seen.add(technique)
            technique = self.vocab.superseded[technique]
            if technique is None:
                return None
        return technique

    def cwe_chain(self, cwe):
        if cwe not in self._chains:
            chain = []
            for capec in self.vocab.cwe.get(cwe, {}).get("related_capec", []):
                pattern = self.vocab.capec.get(capec)
                if not pattern or pattern.get("status") in {"Deprecated", "Obsolete"}:
                    continue
                for original in pattern.get("attack_techniques", []):
                    technique = self.forward(original)
                    if technique:
                        path = [cwe, capec, original] + ([technique] if technique != original else [])
                        chain.append((capec, technique, path))
            self._chains[cwe] = sorted(chain)
        return self._chains[cwe]


def build_context(vocab, registry, kev_catalog, briefs):
    return Context(vocab, registry, kev_catalog, briefs)


def tag_row(row, context):
    """The tagging block for one row. Empty lists and nulls are left out to keep shards small."""
    exploitation = fields.tag_exploitation(row, context)
    entities = fields.tag_entities(row, context)
    cwe = fields.tag_cwe(row, context)
    block = {
        "tagger_version": TAGGER_VERSION,
        "kind": (fields.tag_kind(row, context) or [None])[0],
        "source_class": (fields.tag_source_class(row, context) or [None])[0],
        "exploitation": exploitation[0],
        "event_type": fields.tag_event_type(row, context, exploitation),
        **entities,
        "sector": fields.tag_sector(row, context),
        "region": fields.tag_region(row, context),
        "cwe": cwe,
        "attack": fields.tag_attack(row, context, cwe),
        "cvss": fields.tag_cvss(row, context),
        "kev": fields.tag_kev(row, context),
    }
    return {key: value for key, value in block.items() if value not in (None, [])}


SHARD_LAYOUT = {
    "source_class": "value (method source-registry, confidence high)",
    "exploitation": "[value, method, confidence]",
    "event_type, vendor, product, actor, malware, sector, cwe": "[[value, method, confidence], ...]",
    "region": "[[value, role, method, confidence], ...]",
    "attack": "[technique, ...]: every one reached from the row's CWE tags through CAPEC, with no cap (method cwe-capec, confidence low); "
              "the exports carry each tactic and path",
    "cvss": "{base, version, vector, scorer, cve}",
    "kev": "{cves, added, due, ransomware, at_publication}",
}


def compact(block):
    """The shard form of a tagging block: tags as short arrays, kind left out (the row carries it)."""
    out = {}
    for key, value in block.items():
        if key in {"tagger_version", "kind"}:
            continue
        if key == "source_class":
            out[key] = value["value"]
        elif key == "exploitation":
            out[key] = [value["value"], value["method"], value["confidence"]]
        elif key == "region":
            out[key] = [[item["value"], item["role"], item["method"], item["confidence"]] for item in value]
        elif key == "attack":
            out[key] = [item["value"] for item in value]
        elif key in MULTI_FIELDS:
            out[key] = [[item["value"], item["method"], item["confidence"]] for item in value]
        else:
            out[key] = value
    return out


def tag_rows(rows, context):
    """{row id: tagging block} for every row, in row order."""
    return {row["id"]: tag_row(row, context) for row in rows}


# v6 feed tags --------------------------------------------------------------------------

class Fold:
    """Case-collision folding for the free-text v6 tags.

    KEV product strings fold within their vendor (so Cisco "IOS Software" and "IOS software"
    become one, while Cisco IOS and Apple iOS stay apart). Vendor strings and curated topic
    words fold to a vocabulary label, else to the KEV spelling, else to their most frequent
    spelling, preferring a spelling the KEV catalog uses; ties go to the spelling that sorts first.
    """

    def __init__(self, rows, context):
        counts, products = {}, {}
        for row in rows:
            for value in raw_tags(row):
                counts.setdefault(value.casefold(), {}).setdefault(value, 0)
                counts[value.casefold()][value] += 1
        kev_spellings = set()
        for entry in context.kev.values():
            vendor, product = entry.get("vendorProject"), entry.get("product")
            kev_spellings.update(value for value in (vendor, product) if isinstance(value, str))
            if isinstance(vendor, str) and isinstance(product, str):
                products.setdefault((vendor.casefold(), product.casefold()), {}).setdefault(product, 0)
                products[(vendor.casefold(), product.casefold())][product] += 1
            if isinstance(vendor, str):
                counts.setdefault(vendor.casefold(), {}).setdefault(vendor, 0)
                counts[vendor.casefold()][vendor] += 1
        labels = {}
        for entity in context.vocab.entities.values():
            if entity["type"] in {"vendor", "product"}:
                labels.setdefault(entity["label"].casefold(), set()).add(entity["label"])
        self.words = {}
        for folded, spellings in counts.items():
            label = labels.get(folded)
            named = {value: count for value, count in spellings.items() if value in kev_spellings}
            if label and len(label) == 1:
                self.words[folded] = next(iter(label))
            else:
                self.words[folded] = sorted((named or spellings).items(), key=lambda item: (-item[1], item[0]))[0][0]
        self.products = {key: sorted(spellings.items(), key=lambda item: (-item[1], item[0]))[0][0] for key, spellings in products.items()}

    def word(self, value):
        return self.words.get(value.casefold(), value)

    def product(self, vendor, value):
        return self.products.get(((vendor or "").casefold(), value.casefold()), self.word(value))


def raw_tags(row):
    """The row's own tags before tagging. Publisher rows carry none of their own."""
    return [] if row.get("origin") == "publisher-feed" else [value for value in row.get("tags") or [] if isinstance(value, str)]


def v6_tags(row, block, context, fold):
    """Display tags for the v6 feed: folded raw tags, then vocabulary labels of medium or high confidence."""
    out, seen = [], set()

    def add(value):
        if isinstance(value, str) and value.strip() and value.casefold() not in seen and len(out) < V6_TAG_LIMIT:
            value = value.strip()[:100]
            seen.add(value.casefold())
            out.append(value)

    raw = raw_tags(row)
    if row.get("origin") == "cisa-kev" and len(raw) == 2:
        vendor_ids = [item["value"] for item in block.get("vendor", []) if item["method"] == "kev-vendor"]
        add(context.vocab.label(vendor_ids[0]) if len(vendor_ids) == 1 else fold.word(raw[0]))
        add(fold.product(raw[0], raw[1]))
    else:
        for value in raw:
            add(fold.word(value))
    for field in ENTITY_FIELDS:
        for item in sorted(block.get(field, []), key=lambda item: context.vocab.label(item["value"]) or item["value"]):
            if item["confidence"] in {"high", "medium"}:
                add(context.vocab.label(item["value"]))
    return out


# Export view ---------------------------------------------------------------------------

def _joined(values):
    return ";".join(sorted({value for value in values if value}))


def export_fields(row, block):
    """The flat, wide view of one tagged row used by the CSV export (documented in docs/DATA-DICTIONARY.md)."""
    block = block or {}
    cvss = block.get("cvss") or {}
    kev = block.get("kev") or {}
    tags = [item for field in MULTI_FIELDS for item in block.get(field, [])]
    tags += [block[field] for field in ("kind", "source_class", "exploitation") if field in block]
    confidence = max((fields.CONFIDENCE_ORDER[item["confidence"]] for item in tags), default=None)
    return {
        "source_class": (block.get("source_class") or {}).get("value", ""),
        "cwe": _joined(item["value"] for item in block.get("cwe", [])),
        "cvss_version": cvss.get("version") or "", "cvss_base": "" if cvss.get("base") is None else format(cvss["base"], "g"),
        "cvss_scorer": cvss.get("scorer") or "",
        "kev_added": kev.get("added") or "", "kev_due": kev.get("due") or "", "kev_ransomware": kev.get("ransomware") or "",
        "exploitation": (block.get("exploitation") or {}).get("value", ""),
        "exploitation_basis": (block.get("exploitation") or {}).get("method", ""),
        "event_type": _joined(item["value"] for item in block.get("event_type", [])),
        "vendor": _joined(item["value"] for item in block.get("vendor", [])),
        "product": _joined(item["value"] for item in block.get("product", [])),
        "attack_technique": _joined(item["value"] for item in block.get("attack", [])),
        "attack_tactic": _joined(tactic for item in block.get("attack", []) for tactic in item.get("tactics", [])),
        "actor": _joined(item["value"] for item in block.get("actor", [])),
        "malware": _joined(item["value"] for item in block.get("malware", [])),
        "sector": _joined(item["value"] for item in block.get("sector", [])),
        "region": _joined(item["value"] + "/" + item["role"] for item in block.get("region", [])),
        "min_confidence": "" if confidence is None else ("high", "medium", "low")[confidence],
        "tagger_version": block.get("tagger_version", ""),
    }


def long_tags(block):
    """(field, value, confidence, method, basis_path) for every tag, for the long tags export."""
    block = block or {}
    rows = []
    for field in ("kind", "source_class", "exploitation"):
        if field in block:
            rows.append((field, block[field]["value"], block[field]["confidence"], block[field]["method"], ""))
    for field in MULTI_FIELDS:
        for item in block.get(field, []):
            name = "attack_technique" if field == "attack" else field
            value = item["value"] + ("/" + item["role"] if field == "region" else "")
            rows.append((name, value, item["confidence"], item["method"], ">".join(item.get("path", []))))
            if field == "attack":
                for tactic in item.get("tactics", []):
                    rows.append(("attack_tactic", tactic, item["confidence"], item["method"], ">".join(item.get("path", []))))
    return sorted(set(rows))
