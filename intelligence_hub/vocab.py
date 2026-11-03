"""Controlled vocabularies for tagging: the Hub's own field lists and a pinned library copy.

Two kinds of file feed the taggers:

- config/vocab/*.json are owned here: kind, source_class, event_type, exploitation,
  sector, region and the matching rules (stop names, context words). They are edited
  by hand and checked by this module.
- config/vocabulary.json and config/library/* are copies of TeamStarWolf library
  files at one pinned commit. config/library/lock.json records the commit and the
  SHA-256 of every upstream file and every local copy. They are never edited by hand.

    python -E -s -m intelligence_hub.vocab --sync <library commit>   # refresh the pinned copies
    python -E -s -m intelligence_hub.vocab --check                   # offline: hashes, schemas, sources
    python -E -s -m intelligence_hub.vocab --check --remote          # also re-fetch and re-derive upstream

The collector calls load(). Any problem raises VocabularyError, and the collector
then keeps raw tags for that run instead of failing (a bad vocabulary never blocks
the feed).
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.request

ROOT = Path(__file__).absolute().parent.parent
CONFIG = ROOT / "config"
LIBRARY_REPO = "TeamStarWolf/TeamStarWolf"
RAW_URL = "https://raw.githubusercontent.com/" + LIBRARY_REPO + "/{commit}/{path}"
LOCK = "config/library/lock.json"
COMMIT = re.compile(r"[0-9a-f]{40}")
HEX = re.compile(r"[0-9a-f]{64}")
FETCH_LIMIT = 8 * 1024 * 1024
HUB_FILES = ("kind", "source_class", "event_type", "exploitation", "sector", "region", "matching")
ENTITY_TYPES = ("vendor", "product", "actor", "malware", "sector")
CONFIDENCE = ("high", "medium", "low")
VALUE = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
REGION_VALUE = re.compile(r"[A-Z]{2}|M49-[0-9]{3}")
CWE_ID = re.compile(r"CWE-[1-9][0-9]{0,5}")
CAPEC_ID = re.compile(r"CAPEC-[1-9][0-9]{0,5}")
TECHNIQUE_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")
TACTIC = re.compile(r"[a-z][a-z-]{1,40}")
ENTITY_ID = re.compile(r"(?:vendor|product|actor|malware|sector):[A-Za-z0-9][A-Za-z0-9._-]{0,80}")


class VocabularyError(ValueError):
    """A vocabulary file is missing, changed or malformed."""


def need(condition, message):
    if not condition:
        raise VocabularyError(message)


def lf(raw):
    """Line endings are normalised before hashing, so a Windows checkout hashes like CI."""
    return raw.replace(b"\r\n", b"\n")


def digest(raw):
    return hashlib.sha256(lf(raw)).hexdigest()


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode("utf-8")


def _jsonl(raw, label):
    rows = []
    for number, line in enumerate(lf(raw).decode("utf-8").split("\n"), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except ValueError as error:
                raise VocabularyError(label + " line " + str(number) + " is not JSON.") from error
    return rows


# Derived copies. Each takes the upstream bytes and returns the local bytes; the remote
# check runs the same function again, so a copy can never drift from its source.

def derive_vocabulary(raw):
    value = json.loads(lf(raw).decode("utf-8"))
    need(isinstance(value, dict) and value.get("schema_version") == 1 and isinstance(value.get("entities"), list),
         "The library vocabulary has an unexpected shape.")
    return lf(raw)


def derive_cwe(raw):
    rows = {}
    for row in _jsonl(raw, "cwe.jsonl"):
        need(isinstance(row.get("cwe_id"), str) and CWE_ID.fullmatch(row["cwe_id"]), "cwe.jsonl has an invalid id.")
        rows[row["cwe_id"]] = {"name": row.get("name") or "", "related_capec": sorted(
            {value for value in row.get("related_capec") or [] if isinstance(value, str) and CAPEC_ID.fullmatch(value)})}
    return canonical({"source": "data/weaknesses/cwe.jsonl", "rows": dict(sorted(rows.items(), key=lambda item: int(item[0][4:])))})


def derive_capec(raw):
    rows = {}
    for row in _jsonl(raw, "capec.jsonl"):
        need(isinstance(row.get("capec_id"), str) and CAPEC_ID.fullmatch(row["capec_id"]), "capec.jsonl has an invalid id.")
        rows[row["capec_id"]] = {"name": row.get("name") or "", "status": row.get("status") or "", "attack_techniques": sorted(
            {value for value in row.get("attack_techniques") or [] if isinstance(value, str) and TECHNIQUE_ID.fullmatch(value)})}
    return canonical({"source": "data/weaknesses/capec.jsonl", "rows": dict(sorted(rows.items(), key=lambda item: int(item[0][6:])))})


def derive_tactics(raw):
    rows = {}
    for row in _jsonl(raw, "technique_profiles.jsonl"):
        need(isinstance(row.get("technique_id"), str) and TECHNIQUE_ID.fullmatch(row["technique_id"]), "technique_profiles.jsonl has an invalid id.")
        rows[row["technique_id"]] = {"name": row.get("name") or "", "tactics": sorted(
            {value for value in row.get("tactics") or [] if isinstance(value, str) and TACTIC.fullmatch(value)})}
    return canonical({"source": "data/attack/technique_profiles.jsonl", "rows": dict(sorted(rows.items()))})


def derive_superseded(raw):
    rows = []
    for row in _jsonl(raw, "superseded_by.jsonl"):
        need(isinstance(row.get("old_id"), str) and row.get("reason") in {"revoked", "deprecated"}, "superseded_by.jsonl has an invalid row.")
        rows.append({"old_id": row["old_id"], "new_id": row.get("new_id"), "domain": row.get("domain"), "reason": row["reason"]})
    return canonical({"source": "data/attack/superseded_by.jsonl", "rows": sorted(rows, key=lambda row: (row["old_id"], row["domain"] or ""))})


# (local path, upstream path, derive). The entity list is verified against
# entities.jsonl at sync time but is not copied twice.
PINNED = (
    ("config/vocabulary.json", "data/vocab/vocabulary.json", derive_vocabulary),
    ("config/library/cwe.json", "data/weaknesses/cwe.jsonl", derive_cwe),
    ("config/library/capec.json", "data/weaknesses/capec.jsonl", derive_capec),
    ("config/library/technique_tactics.json", "data/attack/technique_profiles.jsonl", derive_tactics),
    ("config/library/superseded_by.json", "data/attack/superseded_by.jsonl", derive_superseded),
)
ENTITIES_PATH = "data/vocab/entities.jsonl"


def fetch(commit, path):
    request = urllib.request.Request(RAW_URL.format(commit=commit, path=path), headers={"User-Agent": "TeamStarWolf-Intelligence-Hub/vocab"})
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(FETCH_LIMIT + 1)
    need(len(raw) <= FETCH_LIMIT, path + " is larger than the fetch limit.")
    return raw


def verify_vocabulary(vocabulary_raw, entities_raw):
    value = json.loads(lf(vocabulary_raw).decode("utf-8"))
    need(value.get("entities_sha256") == digest(entities_raw), "vocabulary.json does not match entities.jsonl at this commit.")
    need(value["entities"] == _jsonl(entities_raw, "entities.jsonl"), "vocabulary.json and entities.jsonl list different rows.")


def sync(commit, root=ROOT, fetcher=fetch):
    """Fetch every pinned file at one library commit, write the copies and the lock."""
    need(COMMIT.fullmatch(commit or ""), "--sync needs a full 40-character library commit.")
    files = []
    for local, upstream, derive in PINNED:
        raw = fetcher(commit, upstream)
        if upstream == "data/vocab/vocabulary.json":
            verify_vocabulary(raw, fetcher(commit, ENTITIES_PATH))
        data = derive(raw)
        target = Path(root) / local
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files.append({"path": local, "upstream": upstream, "upstream_sha256": digest(raw), "upstream_bytes": len(lf(raw)),
                      "sha256": digest(data), "bytes": len(data)})
    lock = {"repo": LIBRARY_REPO, "commit": commit, "files": files,
            "note": "Written by python -E -s -m intelligence_hub.vocab --sync. Do not edit by hand."}
    (Path(root) / LOCK).write_bytes(canonical(lock))
    return lock


def read_lock(root=ROOT):
    try:
        lock = json.loads((Path(root) / LOCK).read_bytes().decode("utf-8"))
    except (OSError, ValueError) as error:
        raise VocabularyError("config/library/lock.json is missing or invalid.") from error
    need(isinstance(lock, dict) and lock.get("repo") == LIBRARY_REPO and COMMIT.fullmatch(str(lock.get("commit"))) and
         [item.get("path") for item in lock.get("files", [])] == [item[0] for item in PINNED], "config/library/lock.json does not list the pinned files.")
    for item in lock["files"]:
        need(all(HEX.fullmatch(str(item.get(key))) for key in ("sha256", "upstream_sha256")), "config/library/lock.json has an invalid hash.")
    return lock


def check_pins(root=ROOT, remote=False, fetcher=fetch):
    """Every pinned copy matches its recorded hash; with remote, upstream still gives the same copy."""
    lock = read_lock(root)
    for (local, upstream, derive), item in zip(PINNED, lock["files"]):
        try:
            raw = (Path(root) / local).read_bytes()
        except OSError as error:
            raise VocabularyError(local + " is missing.") from error
        need(digest(raw) == item["sha256"], local + " differs from the copy pinned in config/library/lock.json. "
             "Run python -E -s -m intelligence_hub.vocab --sync <commit> instead of editing it.")
        if remote:
            source = fetcher(lock["commit"], upstream)
            need(digest(source) == item["upstream_sha256"], upstream + " at " + lock["commit"] + " no longer has the pinned hash.")
            need(digest(derive(source)) == item["sha256"], local + " is not what " + upstream + " derives to.")
    return lock


def read_json(path):
    try:
        return json.loads(Path(path).read_bytes().decode("utf-8"))
    except (OSError, ValueError) as error:
        raise VocabularyError(str(Path(path).name) + " is missing or not JSON.") from error


def _strings(value, maximum=200, limit=400):
    return isinstance(value, list) and len(value) <= limit and all(isinstance(item, str) and 1 <= len(item) <= maximum for item in value)


def check_hub_file(name, value):
    need(isinstance(value, dict) and value.get("vocab") == name and isinstance(value.get("version"), str), "config/vocab/" + name + ".json has no vocab header.")
    if name == "matching":
        need(_strings(value.get("allow_short")) and type(value.get("min_length")) is int, "matching.json needs allow_short and min_length.")
        for item in value.get("stop", []):
            need(isinstance(item, dict) and isinstance(item.get("alias"), str) and isinstance(item.get("reason"), str), "matching.json has an invalid stop entry.")
        for item in value.get("context", []):
            need(isinstance(item, dict) and ENTITY_ID.fullmatch(str(item.get("id"))) and isinstance(item.get("alias"), str) and
                 _strings(item.get("words"), 40, 20) and item["words"], "matching.json has an invalid context entry.")
        return
    values = value.get("values")
    need(isinstance(values, list) and values and type(value.get("multi")) is bool, "config/vocab/" + name + ".json has no values.")
    seen = set()
    for item in values:
        pattern = REGION_VALUE if name == "region" else VALUE
        need(isinstance(item, dict) and isinstance(item.get("value"), str) and pattern.fullmatch(item["value"]) and
             item["value"] not in seen and isinstance(item.get("label"), str) and isinstance(item.get("definition", ""), str),
             "config/vocab/" + name + ".json has an invalid or repeated value.")
        for key in ("terms", "names"):
            need(key not in item or _strings(item[key], 80), "config/vocab/" + name + ".json has invalid " + key + ".")
        seen.add(item["value"])


def load_hub(root=ROOT):
    files = {}
    for name in HUB_FILES:
        value = read_json(Path(root) / "config/vocab" / (name + ".json"))
        check_hub_file(name, value)
        files[name] = value
    return files


def check_sources(hub, root=ROOT):
    """Every registry source and every curated or KEV source id has a source_class."""
    classes = {item["value"] for item in hub["source_class"]["values"]}
    registry = read_json(Path(root) / "config/sources.json")["sources"]
    problems = []
    for source in registry:
        if source.get("source_class") not in classes:
            problems.append(source["id"])
    overlay = hub["source_class"].get("sources", {})
    for ident, item in overlay.items():
        if item.get("source_class") not in classes:
            problems.append(ident)
    known = {source["id"] for source in registry} | set(overlay)
    history = read_json(Path(root) / "config/history.json")
    for entry in history.get("entries", []):
        if entry.get("source_id") not in known:
            problems.append(entry.get("source_id"))
    need(not problems, "Sources without a valid source_class: " + ", ".join(sorted(set(map(str, problems)))))
    return len(registry), len(overlay)


class Vocabulary:
    """Everything the taggers read, loaded and checked once per run."""

    def __init__(self, hub, library, cwe, capec, tactics, superseded, lock):
        self.hub = hub
        self.lock = lock
        self.library_commit = lock["commit"]
        self.attack_release = library.get("attack_release")
        self.entities = {}
        for entity in library["entities"]:
            need(isinstance(entity, dict) and ENTITY_ID.fullmatch(str(entity.get("id"))) and entity.get("type") in ENTITY_TYPES and
                 entity["id"].split(":", 1)[0] == entity["type"] and entity["id"] not in self.entities and
                 isinstance(entity.get("label"), str) and _strings(entity.get("match", []), 200, 400) and
                 _strings(entity.get("stop_aliases", []), 200, 400) and _strings(entity.get("ambiguous_aliases", []), 200, 400) and
                 _strings(entity.get("kev_vendor_project", []), 200, 400), "The pinned library vocabulary has an invalid entity.")
            self.entities[entity["id"]] = entity
        self.cwe = cwe["rows"]
        self.capec = capec["rows"]
        self.tactics = tactics["rows"]
        self.superseded = {}
        for row in superseded["rows"]:
            self.superseded.setdefault(row["old_id"], row["new_id"])
        self.values = {name: {item["value"]: item for item in hub[name]["values"]} for name in HUB_FILES if name != "matching"}
        for item in self.values["sector"]:
            need("sector:" + item in self.entities, "config/vocab/sector.json names a sector the library vocabulary lacks: " + item)
        self.version = "+".join(sorted({hub[name]["version"] for name in HUB_FILES})) + "/library@" + self.library_commit[:12]

    def label(self, ident):
        entity = self.entities.get(ident)
        return entity["label"] if entity else None

    def resolves(self, field, value):
        """True when an emitted value belongs to its vocabulary."""
        if field == "sector":
            return value.startswith("sector:") and value[7:] in self.values["sector"] and value in self.entities
        if field == "region":
            value = value.split("/", 1)[0]
        if field in self.values:
            return value in self.values[field]
        if field in ENTITY_TYPES:
            return value in self.entities and value.startswith(field + ":")
        if field == "cwe":
            return value in self.cwe
        if field == "attack_technique":
            return value in self.tactics
        if field == "attack_tactic":
            return any(value in row["tactics"] for row in self.tactics.values())
        return False


def load(root=ROOT):
    """The checked vocabulary for one run. Raises VocabularyError on any problem."""
    lock = check_pins(root)
    hub = load_hub(root)
    library = read_json(Path(root) / "config/vocabulary.json")
    pieces = [read_json(Path(root) / path) for path in ("config/library/cwe.json", "config/library/capec.json",
                                                         "config/library/technique_tactics.json", "config/library/superseded_by.json")]
    for piece in pieces:
        need(isinstance(piece, dict) and isinstance(piece.get("rows"), (dict, list)), "A pinned library extract is malformed.")
    return Vocabulary(hub, library, *pieces, lock)


def check(root=ROOT, remote=False, out=sys.stdout):
    lock = check_pins(root, remote)
    vocabulary = load(root)
    registry, overlay = check_sources(vocabulary.hub, root)
    counts = {}
    for entity in vocabulary.entities.values():
        counts[entity["type"]] = counts.get(entity["type"], 0) + 1
    print("Library pin: " + LIBRARY_REPO + "@" + lock["commit"] + (" (re-fetched and re-derived)" if remote else ""), file=out)
    print("Entities: " + ", ".join(key + " " + str(counts[key]) for key in sorted(counts)), file=out)
    print("Hub vocabularies: " + ", ".join(name + " " + str(len(vocabulary.values[name])) for name in sorted(vocabulary.values)), file=out)
    print("Sources with a source_class: " + str(registry) + " in the registry, " + str(overlay) + " curated or KEV ids", file=out)
    return vocabulary


def main(argv=None):
    parser = argparse.ArgumentParser(description="Pin, sync and check the tagging vocabularies.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sync", metavar="COMMIT", help="Fetch the pinned library files at this commit.")
    group.add_argument("--check", action="store_true", help="Verify the pinned copies and the Hub vocabularies.")
    parser.add_argument("--remote", action="store_true", help="With --check, also re-fetch upstream and re-derive every copy.")
    args = parser.parse_args(argv)
    try:
        if args.sync:
            lock = sync(args.sync)
            print("Pinned " + LIBRARY_REPO + "@" + lock["commit"] + ": " + ", ".join(item["path"] for item in lock["files"]))
        check(remote=args.remote)
    except VocabularyError as error:
        raise SystemExit("vocab: " + str(error)) from error


if __name__ == "__main__":
    main()
