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
        self.assertTrue(manifest["published"])
        self.assertTrue(all(entry["month"] is None for entry in manifest["files"]), "small years stay one set of files")
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

    def test_a_year_past_the_per_file_cap_is_split_by_month(self):
        rows = ROWS + [article("feed-e", "November headline", "2026-11-02T00:00:00+00:00")]
        ctx = tagging.build_context(VOCAB, REGISTRY, KEV, {})
        blocks = tagging.tag_rows(rows, ctx)
        whole = exports.build_exports(rows, blocks, REGISTRY, INFO, {"cisa-kev": "government-cert"})
        limit = max(len(whole[name]) for name in whole if "2026" in name) - 1
        self.assertGreaterEqual(limit, max(len(whole[name]) for name in whole if "2025" in name))
        split = exports.build_exports(rows, blocks, REGISTRY, INFO, {"cisa-kev": "government-cert"}, limit=limit)
        names = sorted(name for name in split if "2026" in name)
        self.assertEqual(names, ["articles-2026-10.csv", "articles-2026-10.jsonl", "articles-2026-11.csv", "articles-2026-11.jsonl",
                                 "tags-2026-10.csv", "tags-2026-11.csv"])
        for name in ("articles-2025.csv", "articles-2025.jsonl", "tags-2025.csv", "articles-undated.csv"):
            self.assertEqual(split[name], whole[name], name)
        self.assertTrue(all(len(data) <= limit for name, data in split.items() if name != "data-dictionary.md" and name != "manifest.json"))
        manifest = json.loads(split["manifest.json"])
        months = {entry["name"]: (entry["year"], entry["month"]) for entry in manifest["files"]}
        self.assertEqual(months["articles-2026-10.csv"], ("2026", "2026-10"))
        self.assertEqual(months["articles-2025.csv"], ("2025", None))
        october = parse(split["articles-2026-10.csv"])
        self.assertEqual({line[2] for line in october[1:]}, {"2026"})
        self.assertEqual(sum(len(parse(split[name])) - 1 for name in names if name.startswith("articles-") and name.endswith(".csv")),
                         len(parse(whole["articles-2026.csv"])) - 1)
        for name in split:
            self.assertTrue(exports.EXPORT_NAME.fullmatch(name), name)

    def test_a_set_that_cannot_fit_the_cap_is_an_error(self):
        ctx = tagging.build_context(VOCAB, REGISTRY, KEV, {})
        blocks = tagging.tag_rows(ROWS, ctx)
        with self.assertRaisesRegex(ValueError, "per-file cap"):
            exports.build_exports(ROWS, blocks, REGISTRY, INFO, limit=100)

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
            self.assertEqual(result["exports"]["directory"], "site/data/v7/exports")
            self.assertTrue(result["exports"]["published"])
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
            base = copy.root / "site/data/v7/exports"
            manifest = json.loads((base / "manifest.json").read_text(encoding="utf-8"))
            for entry in manifest["files"]:
                data = (base / entry["name"]).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
            self.assertFalse((copy.root / "dist/exports").exists(), "published exports are not also written to dist/")
            # index.json lists every export file, and the Pages package check accepts the site.
            self.assertEqual(index["exports"]["status"], "ok")
            listed = {item["path"]: item for item in index["exports"]["files"]}
            self.assertEqual(set(listed), {"exports/" + path.name for path in base.iterdir()})
            for path, item in listed.items():
                data = (copy.root / "site/data/v7" / path).read_bytes()
                self.assertEqual((item["bytes"], item["sha256"]), (len(data), hashlib.sha256(data).hexdigest()))
            from intelligence_hub import shards
            report = shards.package_site(copy.root / "site", out=io.StringIO())
            self.assertEqual(report["exports"], len(listed))
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
                    self.assertEqual((index["exports"]["status"], index["exports"]["files"]), ("unavailable", []))
                    self.assertFalse((copy.root / "site/data/v7/exports").exists())
                finally:
                    copy.close()


class PublishedExportsTest(unittest.TestCase):
    def test_exports_past_the_cap_do_not_block_the_feed(self):
        from intelligence_hub import shards
        copy = support.BuildCopy()
        try:
            # The build runs in a subprocess on the copy, so the copy's cap is lowered on disk.
            path = copy.root / "intelligence_hub" / "shards.py"
            source = path.read_text(encoding="utf-8")
            self.assertIn("V7_FILE_MAX_BYTES = 4 * 1024 * 1024", source)
            path.write_text(source.replace("V7_FILE_MAX_BYTES = 4 * 1024 * 1024", "V7_FILE_MAX_BYTES = 100"), encoding="utf-8")
            code, result, output = copy.run()
            self.assertEqual(code, 0, output)
            self.assertEqual(result["tagging"]["status"], "ok")
            self.assertEqual(result["exports"]["status"], "failed")
            self.assertIn("per-file cap", result["exports"]["reason"])
            index = json.loads((copy.root / "site/data/v7/index.json").read_text(encoding="utf-8"))
            self.assertEqual(index["exports"]["status"], "unavailable")
            self.assertIn("per-file cap", index["exports"]["reason"])
            self.assertFalse((copy.root / "site/data/v7/exports").exists())
            self.assertTrue(copy.feed()["articles"])
            shards.package_site(copy.root / "site", out=io.StringIO())
        finally:
            copy.close()

    def test_a_second_build_rewrites_no_export_file(self):
        copy = support.BuildCopy()
        try:
            code, first, output = copy.run()
            self.assertEqual(code, 0, output)
            base = copy.root / "site/data/v7/exports"
            stamps = {path.name: path.stat().st_mtime_ns for path in base.iterdir()}
            code, second, output = copy.run()
            self.assertEqual(code, 0, output)
            self.assertEqual(second["exports"]["written"], 0)
            self.assertEqual({path.name: path.stat().st_mtime_ns for path in base.iterdir()}, stamps)
        finally:
            copy.close()

    def test_an_index_without_exports_republishes(self):
        from intelligence_hub import shards
        entry = shards.exports_entry({"manifest.json": b"{}\n", "data-dictionary.md": b"# d\n"})
        self.assertTrue(shards.exports_changed(None, entry))
        self.assertTrue(shards.exports_changed({"shards": []}, entry))
        self.assertFalse(shards.exports_changed({"exports": entry}, entry))
        self.assertFalse(shards.exports_changed({"shards": []}, None))
        self.assertTrue(shards.exports_changed({"exports": entry}, shards.exports_entry(None, "tagging unavailable")))


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
