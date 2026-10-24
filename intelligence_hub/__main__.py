"""Build the actual public intelligence snapshot; no server or model is started."""
import argparse
from datetime import date, datetime, timezone
import json
from .collect import build_snapshot


def main():
    today = datetime.now(timezone.utc).date()
    parser = argparse.ArgumentParser(description="Build attributed Team Star Wolf Intelligence Hub snapshots.")
    parser.add_argument("--start", type=date.fromisoformat, default=today.replace(year=today.year - 1) if (today.month, today.day) != (2, 29) else date(today.year - 1, 2, 28))
    parser.add_argument("--end", type=date.fromisoformat, default=today)
    parser.add_argument("--cached", action="store_true", help="Build from retained public data without network access.")
    args = parser.parse_args()
    print(json.dumps(build_snapshot(args.start, args.end, refresh=not args.cached), ensure_ascii=True))


if __name__ == "__main__":
    main()
