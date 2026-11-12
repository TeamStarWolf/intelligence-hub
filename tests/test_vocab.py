"""The pinned library vocabulary and the Hub's own field vocabularies."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import support
from intelligence_hub import vocab


def copy_repository():
    directory = tempfile.TemporaryDirectory(prefix="hub-vocab-")
    root = Path(directory.name)
    shutil.copytree(support.ROOT / "intelligence_hub", root / "intelligence_hub", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copytree(support.ROOT / "config", root / "config")
    return directory, root


def run_check(root, *extra):
    return subprocess.run([sys.executable, "-E", "-s", "-m", "intelligence_hub.vocab", "--check", *extra],
                          cwd=root, capture_output=True, text=True, timeout=120)


class PinTest(unittest.TestCase):
    def test_check_is_green_on_the_committed_files(self):
        completed = run_check(support.ROOT)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Library pin: TeamStarWolf/TeamStarWolf@", completed.stdout)

    def test_check_fails_when_a_pinned_library_file_changes(self):
        for name in ("config/vocabulary.json", "config/library/cwe.json", "config/library/capec.json",
                     "config/library/technique_tactics.json", "config/library/superseded_by.json"):
            with self.subTest(name=name):
                directory, root = copy_repository()
                try:
                    path = root / name
                    path.write_bytes(path.read_bytes().replace(b'"', b"'", 1))
                    completed = run_check(root)
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn("differs from the copy pinned", completed.stdout + completed.stderr)
                finally:
                    directory.cleanup()

    def test_line_endings_do_not_change_a_pin(self):
        directory, root = copy_repository()
        try:
            path = root / "config/library/superseded_by.json"
            path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
            vocab.check_pins(root)
        finally:
            directory.cleanup()

    def test_remote_check_fails_when_upstream_moves(self):
        def fetcher(commit, path):
            return b'{"changed": true}\n'

        with self.assertRaises(vocab.VocabularyError):
            vocab.check_pins(support.ROOT, remote=True, fetcher=fetcher)

    def test_sync_writes_copies_and_a_lock_that_check_accepts(self):
        directory, root = copy_repository()
        entities = [{"id": "vendor:example", "type": "vendor", "label": "Example", "match": ["Example"]}]
        entities_raw = "".join(json.dumps(row) + "\n" for row in entities).encode("utf-8")
        files = {
            "data/vocab/entities.jsonl": entities_raw,
            "data/vocab/vocabulary.json": json.dumps({"schema_version": 1, "entities": entities,
                                                      "entities_sha256": vocab.digest(entities_raw)}).encode("utf-8"),
            "data/weaknesses/cwe.jsonl": b'{"cwe_id": "CWE-79", "name": "XSS", "related_capec": ["CAPEC-63"]}\n',
            "data/weaknesses/capec.jsonl": b'{"capec_id": "CAPEC-63", "name": "XSS", "status": "Draft", "attack_techniques": ["T1059.007"]}\n',
            "data/attack/technique_profiles.jsonl": b'{"technique_id": "T1059.007", "name": "JavaScript", "tactics": ["execution"]}\n',
            "data/attack/superseded_by.jsonl": b'{"old_id": "T0001", "new_id": null, "domain": "enterprise", "reason": "deprecated"}\n',
        }
        try:
            lock = vocab.sync("a" * 40, root, fetcher=lambda commit, path: files[path])
            self.assertEqual(lock["commit"], "a" * 40)
            vocab.check_pins(root)
            vocab.check_pins(root, remote=True, fetcher=lambda commit, path: files[path])
            tactics = json.loads((root / "config/library/technique_tactics.json").read_text(encoding="utf-8"))
            self.assertEqual(tactics["rows"]["T1059.007"]["tactics"], ["execution"])
        finally:
            directory.cleanup()

    def test_sync_refuses_a_vocabulary_that_does_not_match_its_entities(self):
        directory, root = copy_repository()
        try:
            files = {"data/vocab/vocabulary.json": json.dumps({"schema_version": 1, "entities": [], "entities_sha256": "0" * 64}).encode(),
                     "data/vocab/entities.jsonl": b""}
            with self.assertRaises(vocab.VocabularyError):
                vocab.sync("b" * 40, root, fetcher=lambda commit, path: files[path])
        finally:
            directory.cleanup()

    def test_sync_needs_a_full_commit(self):
        with self.assertRaises(vocab.VocabularyError):
            vocab.sync("main")


class SourceClassTest(unittest.TestCase):
    def test_every_source_has_a_source_class(self):
        loaded = vocab.load()
        classes = set(loaded.values["source_class"])
        self.assertEqual(classes, {"vendor-primary", "government-cert", "researcher", "press"})
        registry = support.sources()
        self.assertGreaterEqual(len(registry), 61)
        for source in registry:
            self.assertIn(source["source_class"], classes, source["id"])
            self.assertIn(source["desk"], loaded.values["desk"], source["id"])
            if "publisher_vendor" in source:
                self.assertIn(source["publisher_vendor"], loaded.entities, source["id"])
            if "country" in source:
                self.assertIn(source["country"], loaded.values["region"], source["id"])
        vocab.check_sources(loaded.hub)

    def test_curated_and_kev_source_ids_have_a_source_class(self):
        loaded = vocab.load()
        history = json.loads((support.ROOT / "config/history.json").read_text(encoding="utf-8"))
        known = {source["id"] for source in support.sources()} | set(loaded.hub["source_class"]["sources"])
        self.assertIn("cisa-kev", known)
        for entry in history["entries"]:
            self.assertIn(entry["source_id"], known, entry["id"])

    def test_a_source_without_a_class_fails_the_check(self):
        directory, root = copy_repository()
        try:
            path = root / "config/sources.json"
            path.write_text(path.read_text(encoding="utf-8").replace('"source_class":"press",', "", 1), encoding="utf-8")
            completed = run_check(root)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("source_class", completed.stdout + completed.stderr)
        finally:
            directory.cleanup()

    def test_a_source_without_a_desk_fails_the_check(self):
        directory, root = copy_repository()
        try:
            path = root / "config/sources.json"
            path.write_text(path.read_text(encoding="utf-8").replace('"desk":"security",', "", 1), encoding="utf-8")
            completed = run_check(root)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("desk", completed.stdout + completed.stderr)
        finally:
            directory.cleanup()

    def test_split_publisher_ids_are_merged(self):
        history = json.loads((support.ROOT / "config/history.json").read_text(encoding="utf-8"))
        ids = {entry["source_id"] for entry in history["entries"]}
        self.assertNotIn("cisco-talos", ids)
        self.assertNotIn("canada-cyber-centre", ids)
        registry = {source["id"]: source["name"] for source in support.sources()}
        names = {}
        for entry in history["entries"]:
            names.setdefault(entry["source_name"], set()).add(entry["source_id"])
        for name, source_ids in names.items():
            in_registry = {ident for ident, label in registry.items() if label == name}
            if in_registry:
                self.assertLessEqual(source_ids, in_registry, name)


class HubVocabularyTest(unittest.TestCase):
    def test_hub_vocabularies_hold_the_documented_values(self):
        loaded = vocab.load()
        self.assertEqual(set(loaded.values["exploitation"]), {"known", "reported", "unknown"})
        self.assertNotIn("not-exploited", loaded.values["exploitation"])
        self.assertEqual(set(loaded.values["event_type"]), {"disclosure", "exploitation", "patch", "breach", "outage", "takedown",
                                                             "policy", "analysis", "unclassified", "maintenance", "end-of-support"})
        # The reserved values carry no headline terms, so no headline sets them (WP-01).
        for value in ("maintenance", "end-of-support"):
            self.assertFalse(loaded.values["event_type"][value].get("terms"), value)
        self.assertEqual(set(loaded.values["desk"]), {"security", "infrastructure", "it"})
        self.assertEqual(len(loaded.values["sector"]), 18)
        for value in loaded.values["sector"]:
            self.assertIn("sector:" + value, loaded.entities)
        self.assertTrue({"advisory", "research", "reporting", "incident", "kev", "filing", "bulletin", "note", "change", "lifecycle"} <= set(loaded.values["kind"]))

    def test_a_malformed_hub_file_is_refused(self):
        directory, root = copy_repository()
        try:
            (root / "config/vocab/region.json").write_text('{"vocab": "region"}', encoding="utf-8")
            with self.assertRaises(vocab.VocabularyError):
                vocab.load(root)
        finally:
            directory.cleanup()


if __name__ == "__main__":
    unittest.main()
