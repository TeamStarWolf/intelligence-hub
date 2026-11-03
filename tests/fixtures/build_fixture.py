"""Build tests/fixtures/public-cache.json, the offline snapshot input for the PR check.

The cache is produced by the collector's own parse_feed and validate_catalog, with
fixed clocks, so the same inputs always give the same bytes.

    python -I tests/fixtures/build_fixture.py          # rewrite the fixture
    python -I tests/fixtures/build_fixture.py --check  # fail if it is stale
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

from intelligence_hub.collect import parse_feed, validate_cache, validate_catalog, validate_registry  # noqa: E402

OUTPUT = HERE / "public-cache.json"
FEED = HERE / "sample-feed.xml"
SOURCE_ID = "cisa-advisories"
ATTEMPTED = "2026-11-01T12:00:00+00:00"
SUCCEEDED = "2026-11-01T12:00:05+00:00"

# Synthetic records in the KEV schema. Not CISA text; the CVE ids are placeholders.
KEV = {
    "title": "Fixture catalog for offline tests",
    "catalogVersion": "2026.11.01",
    "dateReleased": "2026-11-01T00:00:00.000Z",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2026-99991", "vendorProject": "Example Vendor", "product": "Example Gateway",
         "vulnerabilityName": "Example Gateway fixture vulnerability", "dateAdded": "2026-10-27",
         "shortDescription": "Synthetic record used only by the offline build test.",
         "requiredAction": "Synthetic action text for the offline build test.", "dueDate": "2026-11-17",
         "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": []},
        {"cveID": "CVE-2026-99992", "vendorProject": "Example Vendor", "product": "Example Portal",
         "vulnerabilityName": "Example Portal fixture vulnerability", "dateAdded": "2026-10-29",
         "shortDescription": "Second synthetic record used only by the offline build test.",
         "requiredAction": "Synthetic action text for the offline build test.", "dueDate": "2026-11-19",
         "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": []},
    ],
}


def build():
    sources = validate_registry(json.loads((ROOT / "config/sources.json").read_text(encoding="utf-8")))
    source = next(item for item in sources if item["id"] == SOURCE_ID)
    raw = FEED.read_bytes().replace(b"\r\n", b"\n")
    parsed = parse_feed(raw, source)
    digest = hashlib.sha256(raw).hexdigest()
    intake = {**parsed["intake"], "attempted_at": ATTEMPTED, "response_sha256": digest}
    incomplete = intake["items_rejected"] > 0 or intake["items_unprocessed"] > 0
    observation = {"status": "partial" if incomplete else "ok", "last_attempt": ATTEMPTED, "last_success": SUCCEEDED,
                   "error": None, "sha256": digest, "articles": parsed["articles"], "intake": intake}
    validate_catalog(KEV)
    kev_raw = json.dumps(KEV, sort_keys=True, separators=(",", ":")).encode("utf-8")
    kev = {"status": "ok", "last_attempt": ATTEMPTED, "last_success": SUCCEEDED, "error": None,
           "sha256": hashlib.sha256(kev_raw).hexdigest(), "catalog": KEV, "intake": None}
    cache = {"sources": {SOURCE_ID: observation}, "kev": kev}
    validate_cache(cache, sources)
    return (json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="Fail when the committed fixture differs.")
    args = parser.parse_args()
    expected = build()
    if args.check:
        current = OUTPUT.read_bytes().replace(b"\r\n", b"\n") if OUTPUT.exists() else b""
        if current != expected:
            raise SystemExit("tests/fixtures/public-cache.json is stale; run tests/fixtures/build_fixture.py.")
        print("fixture up to date")
        return
    OUTPUT.write_bytes(expected)
    print("wrote", OUTPUT.relative_to(ROOT).as_posix())


if __name__ == "__main__":
    main()
