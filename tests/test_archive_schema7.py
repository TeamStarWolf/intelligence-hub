"""The private archive imports a schema 7 feed together with its briefs file and exports it whole."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import support  # noqa: F401
from intelligence_hub import archive
from intelligence_hub.mitigations import join_publication
import test_publication


class ArchiveSchema7Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_publication.BriefsFileTest.setUpClass()
        cls.feed_raw, cls.briefs_raw = test_publication.BriefsFileTest.feed_raw, test_publication.BriefsFileTest.briefs_raw

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hub-archive-")
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name).resolve()
        home = root / ".state" / "archive-foundation"
        (home / "inbox").mkdir(parents=True)
        paths = {"ROOT": root, "HOME": home, "INBOX": home / "inbox" / "feed.json", "BRIEFS_INBOX": home / "inbox" / "briefs.json",
                 "DATABASE": home / "archive.sqlite3", "EXPORTS": home / "exports"}
        for name, value in paths.items():
            patcher = mock.patch.object(archive, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.home = home

    def stage(self, briefs=True):
        (self.home / "inbox" / "feed.json").write_bytes(self.feed_raw)
        if briefs:
            (self.home / "inbox" / "briefs.json").write_bytes(self.briefs_raw)
        return hashlib.sha256(self.feed_raw).hexdigest()

    def test_import_and_export_round_trip(self):
        identity = self.stage()
        result = archive.ingest(identity)
        self.assertEqual(result["status"], "imported")
        self.assertEqual(result["cves"], len(json.loads(self.briefs_raw)["briefs"]))
        receipt = archive.export(identity)
        exported = json.loads((self.home / "exports" / (identity + ".private.json")).read_text(encoding="utf-8"))
        self.assertEqual(receipt["export_bytes"], len((self.home / "exports" / (identity + ".private.json")).read_bytes()))
        expected = join_publication(json.loads(self.feed_raw), json.loads(self.briefs_raw))
        self.assertEqual(archive.encoded(exported), archive.encoded(expected))
        self.assertEqual(archive.ingest(identity)["status"], "already-imported")

    def test_import_needs_the_briefs_file(self):
        identity = self.stage(briefs=False)
        with self.assertRaises((ValueError, OSError)):
            archive.ingest(identity)


if __name__ == "__main__":
    unittest.main()
