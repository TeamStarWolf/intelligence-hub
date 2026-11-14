"""Build tests/fixtures/filings/filings-cache.json from trimmed real EDGAR full-text-search hits.

The cache is what intelligence_hub/filings.py writes to .state/filings-cache.json on a live run: a
JSON list of the raw search-response bodies, one per page. The pull-request check copies it to
.state/ before the offline --cached build, so filings.collect_filings reads it offline and the run
produces SEC filing rows without a network read.

    python -I tests/fixtures/filings/build_cache.py           # rewrite the cache fixture
    python -I tests/fixtures/filings/build_cache.py --check   # fail when it is out of date
"""
import json
from pathlib import Path
import sys

TARGET = Path(__file__).resolve().parent / "filings-cache.json"

# Trimmed real Item 1.05 (Material Cybersecurity Incidents) 8-K hits, read 13 November 2026.
# sics is the filer's EDGAR SIC code; filings.py maps it to a CISA sector tag.
HITS = [
    {"_source": {"items": ["1.05"], "adsh": "0000885725-26-000059", "ciks": ["0000885725"], "file_date": "2026-09-08",
                 "display_names": ["BOSTON SCIENTIFIC CORP  (BSX)  (CIK 0000885725)"], "sics": ["3841"], "biz_states": ["MA"]}},
    {"_source": {"items": ["1.05"], "adsh": "0001104659-26-109813", "ciks": ["0001083446"], "file_date": "2026-09-23",
                 "display_names": ["Astrana Health, Inc.  (ASTH)  (CIK 0001083446)"], "sics": ["8000"], "biz_states": ["CA"]}},
    {"_source": {"items": ["1.05", "9.01"], "adsh": "0001628280-26-059602", "ciks": ["0001479681"], "file_date": "2026-08-31",
                 "display_names": ["Nutex Health Inc.  (NUTX)  (CIK 0001479681)"], "sics": ["8011"], "biz_states": ["TX"]}},
    # A text match whose structured items do NOT include 1.05: must be dropped by the parser.
    {"_source": {"items": ["8.01", "9.01"], "adsh": "0000930245-26-048428", "ciks": ["0000930245"], "file_date": "2026-09-01",
                 "display_names": ["Agassi Sports Entertainment Corp.  (AASP)  (CIK 0000930245)"], "sics": ["7900"], "biz_states": ["NV"]}},
]
PAGE = {"hits": {"total": {"value": len(HITS)}, "hits": HITS}}


def build():
    bodies = [json.dumps(PAGE, ensure_ascii=False)]
    return (json.dumps(bodies, ensure_ascii=False, indent=1) + "\n").encode("utf-8")


if __name__ == "__main__":
    raw = build()
    if sys.argv[1:] == ["--check"]:
        current = TARGET.read_bytes().replace(b"\r\n", b"\n") if TARGET.exists() else b""
        if current != raw:
            raise SystemExit("tests/fixtures/filings/filings-cache.json is out of date; run python -I tests/fixtures/filings/build_cache.py")
        print("tests/fixtures/filings/filings-cache.json is current")
    else:
        TARGET.write_bytes(raw)
        print("Wrote", TARGET)
