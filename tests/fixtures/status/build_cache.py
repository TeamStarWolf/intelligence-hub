"""Build tests/fixtures/status-cache.json from the fixture documents, offline.

    python -I tests/fixtures/status/build_cache.py           # rewrite the cache fixture
    python -I tests/fixtures/status/build_cache.py --check   # fail when it is out of date

The cache is what a live run writes to .state/status-cache.json: one observation per source,
made by the real normalizers in intelligence_hub/status.py from the committed documents, with a
fixed read clock. The pull-request check copies it to .state/ before its offline --cached build,
so that build writes status/current.json, the month files, outages.json and status/index.json.
"""
import json
from pathlib import Path
import sys
import urllib.parse

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from intelligence_hub import status  # noqa: E402

DOCUMENTS = Path(__file__).resolve().parent / "documents"
TARGET = ROOT / "tests" / "fixtures" / "status-cache.json"
CLOCK = "2026-11-01T12:00:00+00:00"
# Registry source id -> {endpoint name: fixture document}.
SOURCES = {
    "check-point": {"summary": "statuspage/summary.json", "incidents": "statuspage/incidents.json"},
    "google-cloud": {"incidents": "google/incidents.json"},
    "aws": {"events": "aws/currentevents.json"},
    "azure": {"feed": "azure/feed.xml"},
    "slack": {"current": "slack/current.json", "history": "slack/history.json"},
    "heroku": {"current": "heroku/current-status.json"},
    "salesforce": {"active": "salesforce/active.json"},
    "gitlab": {"status": "statusio/status.json"},
    "azure-devops": {"health": "azure-devops/health.json"},
    "microsoft-365": {"posts": "microsoft/mac.json"},
    "power-platform": {"posts": "microsoft/ppac.json"},
    "chainguard": {"index": "betterstack/index.json"},
    "zscaler": {"feed": "zscaler/rss-feed.xml"},
    "oracle-cloud": {"status": "statuspage-rss/status.json", "feed": "statuspage-rss/history.rss"},
    "ioda": {"events": "ioda/events.json"},
}


def fixture_fetch(registry):
    """A fetch that serves the fixture documents for the registry's own endpoint URLs only."""
    served = {}
    for source in registry["sources"]:
        for name, document in SOURCES.get(source["id"], {}).items():
            served[source["endpoints"][name]] = DOCUMENTS / document

    def fetch(url, maximum=None, fresh=False):
        base = urllib.parse.urlunsplit(urllib.parse.urlsplit(url)._replace(query=""))
        path = served.get(url) or served.get(base)
        if path is None:
            raise OSError("no fixture document for " + url)
        return path.read_bytes()
    return fetch


def build():
    registry = status.load_registry(ROOT)
    chosen = {**registry, "sources": [source for source in registry["sources"] if source["id"] in SOURCES]}
    observations = status.observe(chosen, fixture_fetch(registry), clock=CLOCK)
    value = {"schema_version": 1, "sources": observations}
    status.validate_observations(value, registry)
    return (json.dumps(value, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")


if __name__ == "__main__":
    raw = build()
    if sys.argv[1:] == ["--check"]:
        current = TARGET.read_bytes().replace(b"\r\n", b"\n") if TARGET.exists() else b""
        if current != raw:
            raise SystemExit("tests/fixtures/status-cache.json is out of date; run python -I tests/fixtures/status/build_cache.py")
        print("tests/fixtures/status-cache.json is current")
    else:
        TARGET.write_bytes(raw)
        print("Wrote", TARGET.relative_to(ROOT))
