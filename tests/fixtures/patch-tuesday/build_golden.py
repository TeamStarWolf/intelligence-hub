"""Build, or check, the golden Patch Tuesday briefs from the trimmed fixture documents.

    python -I tests/fixtures/patch-tuesday/build_golden.py           # rewrite golden/
    python -I tests/fixtures/patch-tuesday/build_golden.py --check   # compare, exit 1 on a difference

The inputs are documents/ (the trimmed MSRC, Adobe and SAP pages that make_fixture.py writes),
kev.json (three CISA KEV entries) and a fixed retrieval clock, so the bytes never depend on
the day the test runs. Tags are left out (no tagging context), so a vocabulary change never
moves the golden files; tests/test_patch_tuesday.py covers the tag join on its own.
"""
import json
from pathlib import Path
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from intelligence_hub import collect, patch_tuesday  # noqa: E402
from intelligence_hub.shards import SHARD_MAX_BYTES  # noqa: E402

RETRIEVED = "2026-11-03T12:00:00Z"
# The Hub holds a CVE brief for this CVE in the golden build.
BRIEFS = {"CVE-2026-96951": {}}


def build():
    """{golden file name: bytes} for every brief and the index."""
    config = patch_tuesday.load_config(json.loads((ROOT / "config/sources.json").read_text(encoding="utf-8")), collect.safe_url)
    with tempfile.TemporaryDirectory(prefix="hub-pt-") as state_dir:
        state, _report = patch_tuesday.collect(state_dir, config, patch_tuesday.Reader(offline=HERE / "documents"), limit=patch_tuesday.MAX_DOCUMENTS,
                                               safe_url=collect.safe_url, clock_now=lambda: RETRIEVED, monotonic=lambda: 0.0)
    catalog = json.loads((HERE / "kev.json").read_text(encoding="utf-8"))
    shards = patch_tuesday.build(state, catalog, BRIEFS, limit=SHARD_MAX_BYTES, config=config)
    return {path.split("/", 1)[1]: patch_tuesday.canonical(value) for path, value in shards.items()}


def main(argv):
    built = build()
    golden = HERE / "golden"
    if "--check" in argv:
        names = sorted(path.name for path in golden.glob("*.json"))
        stale = [name for name in sorted(built) if not (golden / name).is_file() or (golden / name).read_bytes() != built[name]]
        extra = [name for name in names if name not in built]
        if stale or extra:
            print("Golden Patch Tuesday briefs differ: " + ", ".join(stale + extra) + ". Run build_golden.py and review the diff.")
            return 1
        print("Golden Patch Tuesday briefs are current (" + str(len(built)) + " files).")
        return 0
    golden.mkdir(exist_ok=True)
    for name, raw in built.items():
        (golden / name).write_bytes(raw)
    print("Wrote " + str(len(built)) + " golden files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
