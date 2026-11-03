"""Shared helpers for the unit tests. Standard library only."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SITE_FILES = ("index.html", "styles.css", "app.js", "icon.svg")
WINDOW = ("--start", "1998-01-01", "--end", "2026-11-01")


def sources():
    from intelligence_hub.collect import validate_registry
    return validate_registry(json.loads((ROOT / "config/sources.json").read_text(encoding="utf-8")))


def source(source_id):
    return next(item for item in sources() if item["id"] == source_id)


class BuildCopy:
    """A throwaway copy of the repository inputs for one offline --cached build.

    Only the collector, config/, the four site files, the two report inputs and the
    committed fixture cache are copied. Nothing under the real reports/ or .state/
    is read or written.
    """

    def __init__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="hub-build-")
        self.root = Path(self.directory.name)
        shutil.copytree(ROOT / "intelligence_hub", self.root / "intelligence_hub",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copytree(ROOT / "config", self.root / "config")
        (self.root / "site").mkdir()
        for name in SITE_FILES:
            shutil.copyfile(ROOT / "site" / name, self.root / "site" / name)
        (self.root / "reports").mkdir()
        for name in ("reporting.json", "catalog.json"):
            shutil.copyfile(ROOT / "reports" / name, self.root / "reports" / name)
        (self.root / ".state").mkdir()
        shutil.copyfile(FIXTURES / "public-cache.json", self.root / ".state" / "public-cache.json")

    def write_report_input(self, name, data):
        (self.root / "reports" / name).write_bytes(data)

    def remove_report_input(self, name):
        (self.root / "reports" / name).unlink()

    def run(self):
        """Run the real entry point offline; return (exit code, result dict or None, output text)."""
        completed = subprocess.run([sys.executable, "-E", "-s", "-m", "intelligence_hub", "--cached", *WINDOW],
                                   cwd=self.root, capture_output=True, text=True, timeout=300)
        result_path = self.root / ".state" / "collection-result.json"
        result = json.loads(result_path.read_text(encoding="utf-8")) if completed.returncode == 0 and result_path.exists() else None
        return completed.returncode, result, completed.stdout + completed.stderr

    def feed(self):
        return json.loads((self.root / "site" / "data" / "feed.json").read_text(encoding="utf-8"))

    def briefs(self):
        return json.loads((self.root / "site" / "data" / "briefs.json").read_text(encoding="utf-8"))

    def close(self):
        self.directory.cleanup()
