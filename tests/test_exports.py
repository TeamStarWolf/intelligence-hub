"""Per-year exports: columns, dictionary, manifest hashes, stable bytes and the offline build."""
import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

import support
from intelligence_hub import exports, tagging, vocab
from intelligence_hub.tagging.engine import compact

VOCAB = vocab.load()
REGISTRY = support.sources()
SOURCES = {source["id"]: source for source in REGISTRY}
INFO = {"tagger_version": tagging.TAGGER_VERSION, "vocab_version": VOCAB.version, "library": {"commit": VOCAB.library_commit}}


def article(ident, title, date, source_id="bleepingcomputer", origin="publisher-feed", summary="", cves=()):
    source = SOURCES.get(source_id, {"name": "CISA Known Exploited Vulnerabilities", "kind": "kev"})
    return {"id": ident, "title": title, "url": "https://example.com/" + ident, "source_id": source_id, "source_name": source["name"],
            "kind": source["kind"], "published_at": date, "event_date": None, "date_basis": "publication", "summary": summary,
            "cves": list(cves), "tags": [], "exploitation": "unknown", "references": [], "origin": origin}


ROWS = [
    article("feed-a", "Volt Typhoon targets US water utilities", "2025-03-04T10:00:00+00:00"),
    article("feed-b", "=HYPERLINK(\"https://example.com\") headline", "2025-07-01T00:00:00+00:00"),
    article("feed-c", "Iranian hackers exploit Cisco flaw in the wild", "2026-10-02T00:00:00+00:00", source_id="unit42"),
    article("kev-CVE-2026-90001", "CVE-2026-90001 · Synthetic", "2026-10-01", source_id="cisa-kev", origin="cisa-kev",
            summary="Synthetic catalog text.", cves=["CVE-2026-90001"]),
    article("feed-d", "Undated headline", None),
]
KEV = {"vulnerabilities": [{"cveID": "CVE-2026-90001", "vendorProject": "Microsoft", "product": "Windows", "dateAdded": "2026-10-01",
                            "cwes": ["CWE-79"]}]}


def build(rows=ROWS):
    ctx = tagging.build_context(VOCAB, REGISTRY, KEV, {})
    blocks = tagging.tag_rows(rows, ctx)
    return exports.build_exports(rows, blocks, REGISTRY, INFO, {"cisa-kev": "government-cert"}), blocks


def parse(data):
    return list(csv.reader(io.StringIO(data.decode("utf-8"))))


class ExportTest(unittest.TestCase):
    def test_files_per_year_and_undated(self):
        files, _ = build()
        for year in ("2025", "2026", "undated"):
            for name in ("articles-" + year + ".csv", "articles-" + year + ".jsonl", "tags-" + year + ".csv"):
                self.assertIn(name, files)
        self.assertIn("manifest.json", files)
        self.assertIn("data-dictionary.md", files)

    def test_columns_match_the_dictionary(self):
        files, _ = build()
        dictionary = files["data-dictionary.md"].decode("utf-8")
        header = parse(files["articles-2026.csv"])[0]
        self.assertEqual(header, [name for name, _ in exports.ARTICLE_COLUMNS])
        self.assertEqual(parse(files["tags-2026.csv"])[0], [name for name, _ in exports.TAG_COLUMNS])
        for name in header + [name for name, _ in exports.TAG_COLUMNS]:
            self.assertIn("| `" + name + "` |", dictionary)
        for line in parse(files["articles-2026.csv"]):
            self.assertEqual(len(line), len(header))

    def test_docs_copy_of_the_dictionary_is_current(self):
        committed = (support.ROOT / "docs/DATA-DICTIONARY.md").read_bytes().replace(b"\r\n", b"\n")
        self.assertEqual(committed, exports.dictionary(), "Regenerate docs/DATA-DICTIONARY.md from exports.dictionary().")

    def test_manifest_hashes_and_counts_match(self):
        files, _ = build()
        manifest = json.loads(files["manifest.json"])
        self.assertEqual(manifest["columns"]["articles"], [name for name, _ in exports.ARTICLE_COLUMNS])
        names = {entry["name"] for entry in manifest["files"]}
        self.assertEqual(names, {name for name in files if name not in {"manifest.json", "data-dictionary.md"}})
        for entry in manifest["files"]:
            self.assertEqual(entry["sha256"], hashlib.sha256(files[entry["name"]]).hexdigest())
            self.assertEqual(entry["bytes"], len(files[entry["name"]]))
            if entry["name"].startswith("articles-") and entry["name"].endswith(".csv"):
                self.assertEqual(entry["rows"], len(parse(files[entry["name"]])) - 1)
        self.assertEqual(manifest["dictionary"]["sha256"], hashlib.sha256(files["data-dictionary.md"]).hexdigest())
        notes = {item["id"]: item for item in manifest["sources"]}
        self.assertEqual(notes["cisa-kev"]["source_class"], "government-cert")
        self.assertIn("CC0", notes["cisa-kev"]["licence"])
        self.assertIn("Headline and link only", notes["bleepingcomputer"]["licence"])
        self.assertFalse(manifest["published"])
        self.assertTrue(any("MITRE" in notice for notice in manifest["notices"]))

    def test_an_unchanged_year_stays_byte_identical(self):
        first, _ = build()
        changed = [dict(item) for item in ROWS]
        changed[2]["title"] = "Iranian hackers exploit Fortinet flaw in the wild"
        second, _ = build(changed)
        for name in ("articles-2025.csv", "articles-2025.jsonl", "tags-2025.csv", "articles-undated.csv"):
            self.assertEqual(first[name], second[name], name)
        self.assertNotEqual(first["articles-2026.csv"], second["articles-2026.csv"])
        with tempfile.TemporaryDirectory() as directory:
            written, removed = exports.write_exports(directory, first)
            self.assertEqual(sorted(written), sorted(first))
            stamp = (Path(directory) / "articles-2025.csv").stat().st_mtime_ns
            written, removed = exports.write_exports(directory, second)
            self.assertEqual(sorted(written), ["articles-2026.csv", "articles-2026.jsonl", "manifest.json", "tags-2026.csv"])
            self.assertEqual(removed, [])
            self.assertEqual((Path(directory) / "articles-2025.csv").stat().st_mtime_ns, stamp)
            fewer = {name: data for name, data in second.items() if "undated" not in name}
            written, removed = exports.write_exports(directory, fewer)
            self.assertEqual(sorted(removed), ["articles-undated.csv", "articles-undated.jsonl", "tags-undated.csv"])

    def test_deterministic(self):
        self.assertEqual(build()[0], build(list(reversed(ROWS)))[0])

    def test_rows_and_cells(self):
        files, blocks = build()
        rows = {line[0]: dict(zip(parse(files["articles-2025.csv"])[0], line)) for line in parse(files["articles-2025.csv"])[1:]}
        self.assertTrue(rows["feed-b"]["title"].startswith("'="), "formula-like cells are neutralised")
        self.assertEqual(rows["feed-a"]["actor"], "actor:G1017")
        self.assertIn("US/mentioned", rows["feed-a"]["region"])
        self.assertEqual(rows["feed-a"]["sector"], "sector:water-wastewater")
        lines = [json.loads(line) for line in files["articles-2026.jsonl"].decode("utf-8").splitlines()]
        keys = [(line["published"], line["id"]) for line in lines]
        self.assertEqual(keys, sorted(keys))
        for line in lines:
            if line["origin"] == "publisher-feed":
                self.assertEqual(line["summary"], "")
        kev = next(line for line in lines if line["origin"] == "cisa-kev")
        self.assertEqual(kev["exploitation"]["value"], "known")
        long_rows = parse(files["tags-2026.csv"])[1:]
        self.assertIn(["kev-CVE-2026-90001", "2026-10-01", "exploitation", "known", "high", "kev", ""], long_rows)
        for line in long_rows:
            self.assertIn(line[4], {"high", "medium", "low"})

    def test_unexpected_file_names_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                exports.write_exports(directory, {"../escape.csv": b""})


class BuildTest(unittest.TestCase):
    def test_offline_build_tags_rows_writes_exports_and_resolves_every_tag(self):
        copy = support.BuildCopy()
        try:
            code, result, output = copy.run()
            self.assertEqual(code, 0, output)
            self.assertEqual(result["tagging"]["status"], "ok")
            self.assertEqual(result["exports"]["status"], "ok")
            self.assertEqual(result["exports"]["directory"], "dist/exports")
            self.assertIn("Tagging: ", output)
            index = json.loads((copy.root / "site/data/v7/index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["tagging"]["status"], "ok")
            self.assertEqual(index["tagging"]["library"]["commit"], VOCAB.library_commit)
            rows = []
            for entry in index["shards"]:
                if entry["path"].startswith(("live/", "history/")):
                    rows += json.loads((copy.root / "site/data/v7" / entry["path"]).read_text(encoding="utf-8"))["rows"]
            self.assertTrue(rows)
            for item in rows:
                block = item["tagging"]
                self.assertIn(block["source_class"], VOCAB.values["source_class"])
                self.assertIn(block["exploitation"][0], {"known", "reported", "unknown"})
                for field in ("event_type", "vendor", "product", "actor", "malware", "sector", "cwe"):
                    for value in block.get(field, []):
                        self.assertTrue(VOCAB.resolves(field, value[0]), (field, value))
                for value in block.get("region", []):
                    self.assertTrue(VOCAB.resolves("region", value[0]), value)
            kev = [item for item in rows if item["origin"] == "cisa-kev"]
            self.assertTrue(kev and all(item["tagging"]["exploitation"] == ["known", "kev", "high"] for item in kev))
            manifest = json.loads((copy.root / "dist/exports/manifest.json").read_text(encoding="utf-8"))
            for entry in manifest["files"]:
                data = (copy.root / "dist/exports" / entry["name"]).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
            self.assertFalse((copy.root / "site/data/v7/exports").exists(), "exports stay unpublished until new caps are approved")
            feed = copy.feed()
            for item in feed["articles"]:
                self.assertNotIn("tagging", item)
        finally:
            copy.close()

    def test_a_corrupt_vocabulary_does_not_block_the_feed(self):
        for name, data in (("config/vocabulary.json", b"{not json"), ("config/vocab/event_type.json", b"[]"),
                           ("config/library/lock.json", b"")):
            with self.subTest(name=name):
                copy = support.BuildCopy()
                try:
                    (copy.root / name).write_bytes(data)
                    code, result, output = copy.run()
                    self.assertEqual(code, 0, output)
                    self.assertEqual(result["tagging"]["status"], "unavailable")
                    self.assertEqual(result["exports"]["status"], "skipped")
                    self.assertIn("rows keep their raw tags", output)
                    feed = copy.feed()
                    kev = [item for item in feed["articles"] if item["origin"] == "cisa-kev"]
                    self.assertEqual(sorted(item["tags"][0] for item in kev), ["Example Vendor", "Example Vendor"])
                    self.assertTrue(all(item["tags"] == [] for item in feed["articles"] if item["origin"] == "publisher-feed"))
                    index = json.loads((copy.root / "site/data/v7/index.json").read_text(encoding="utf-8"))
                    self.assertEqual(index["tagging"]["status"], "unavailable")
                finally:
                    copy.close()


class ResumeTest(unittest.TestCase):
    def test_resumed_rows_are_tagged_again_not_carried(self):
        import contextlib
        from intelligence_hub import collect
        from test_publication import Workspace, synthetic_cache
        from test_shards import v7_files
        workspace = Workspace(synthetic_cache(publisher_rows=40, kev_rows=5))
        try:
            workspace.build()
            files = {collect.PUBLIC_V7 + path: raw for path, raw in v7_files(workspace).items()}
            files[collect.PUBLIC_BRIEFS] = workspace.raw("briefs.json")
            shard = next(json.loads(raw) for path, raw in files.items() if "/live/" in path)
            self.assertTrue(all("tagging" in row for row in shard["rows"]))

            def fetch(url, maximum=collect.MAX_BYTES, fresh=False):
                if url not in files:
                    raise OSError("HTTP Error 404: Not Found")
                return files[url]

            cache = {"sources": {}, "kev": {}}
            from unittest import mock
            with mock.patch.object(collect, "fetch", side_effect=fetch), contextlib.redirect_stderr(io.StringIO()):
                previous, reason = collect.resume_deployed(support.sources(), cache)
            self.assertIsNone(reason)
            self.assertTrue(previous["articles"])
            self.assertTrue(all("tagging" not in row for row in previous["articles"]))
            for observation in cache["sources"].values():
                self.assertTrue(all(row["tags"] == [] for row in observation.get("articles", [])))
        finally:
            workspace.close()


if __name__ == "__main__":
    unittest.main()
