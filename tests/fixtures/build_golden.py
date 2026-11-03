"""Golden headlines for the tagging tests: real publisher titles and URLs, nothing else.

tests/fixtures/golden_headlines.jsonl holds about 300 headlines taken from the live
feed on 2026-11-03 (titles and URLs only, never article text), each with the tags a
reviewer accepted. The tags come from the headline and the source identity alone:
the test tags each row with no CVE, no KEV catalog and no CVE briefs.

    python -I tests/fixtures/build_golden.py --refresh   # recompute "expected" for every row

--refresh rewrites the expected tags from the current rules. Review the diff line by
line before committing it: the point of the file is that a rule change shows up as a
visible change in reviewed output, not that it passes.
"""
import argparse
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))

GOLDEN = HERE / "golden_headlines.jsonl"


def context():
    from intelligence_hub import tagging, vocab
    from intelligence_hub.collect import validate_registry
    registry = validate_registry(json.loads((ROOT / "config/sources.json").read_text(encoding="utf-8")))
    return tagging.build_context(vocab.load(ROOT), registry, None, {}), {source["id"]: source for source in registry}


def row(item, sources):
    source = sources[item["source_id"]]
    return {"id": item["id"], "title": item["title"], "url": item["url"], "source_id": source["id"], "source_name": source["name"],
            "kind": source["kind"], "published_at": None, "event_date": None, "date_basis": "publication", "summary": "",
            "cves": [], "tags": [], "exploitation": "unknown", "references": [], "origin": "publisher-feed"}


def expected(item, ctx, sources):
    from intelligence_hub.tagging.engine import compact, tag_row
    return compact(tag_row(row(item, sources), ctx))


def read():
    return [json.loads(line) for line in GOLDEN.read_text(encoding="utf-8").splitlines() if line.strip()]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--refresh", action="store_true", help="Recompute the expected tags; review the diff before committing.")
    args = parser.parse_args()
    if not args.refresh:
        parser.error("nothing to do; the unit test compares the file, --refresh rewrites it")
    ctx, sources = context()
    items = read()
    lines = []
    for item in items:
        item = {**item, "expected": expected(item, ctx, sources)}
        lines.append(json.dumps(item, ensure_ascii=False, sort_keys=True))
    GOLDEN.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("refreshed", len(lines), "rows")


if __name__ == "__main__":
    main()
