"""Build the actual public intelligence snapshot; no server or model is started."""
import argparse
from datetime import date, datetime, timezone
import json
from .collect import HISTORY_START, build_snapshot


def main():
    today = datetime.now(timezone.utc).date()
    parser = argparse.ArgumentParser(description="Build attributed Team Star Wolf Intelligence Hub snapshots.")
    parser.add_argument("--start", type=date.fromisoformat, default=HISTORY_START)
    parser.add_argument("--end", type=date.fromisoformat, default=today)
    parser.add_argument("--cached", action="store_true", help="Build from retained public data without network access.")
    parser.add_argument("--resume-public", action="store_true", help="Retain additional history from this hub's fixed public snapshot.")
    parser.add_argument("--enrich-limit", type=int, default=40, help="Bound the number of official CVE records requested in this collection.")
    args = parser.parse_args()
    if args.cached and args.resume_public:
        parser.error("--cached cannot contact the public snapshot.")
    print(json.dumps(build_snapshot(args.start, args.end, refresh=not args.cached, resume_public=args.resume_public, enrich_limit=args.enrich_limit), ensure_ascii=True))


if __name__ == "__main__":
    main()
