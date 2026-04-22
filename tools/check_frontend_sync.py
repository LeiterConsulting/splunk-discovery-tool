"""Check whether the shipped static frontend assets match the legacy inline source."""

import argparse
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from frontend_delivery import get_frontend_sync_status  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Check frontend static bundle sync status.")
    parser.add_argument("--quiet", action="store_true", help="Suppress success output.")
    parser.add_argument("--json", action="store_true", help="Emit the full status payload as JSON.")
    args = parser.parse_args()

    status = get_frontend_sync_status()

    if args.json:
        sys.stdout.write(f"{json.dumps(status, indent=2)}\n")
    elif not args.quiet or not status["ok"]:
        if status["ok"]:
            sys.stdout.write("Frontend static assets are current.\n")
        else:
            sys.stdout.write("Frontend static assets are out of sync or incomplete.\n")
            for issue in status["issues"]:
                sys.stdout.write(f"- {issue}\n")

    return 0 if status["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())