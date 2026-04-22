"""Render the legacy inline frontend HTML so build tooling can extract stable assets."""

from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from frontend_legacy import get_frontend_html  # noqa: E402


def main() -> None:
    sys.stdout.buffer.write(get_frontend_html().encode("utf-8"))


if __name__ == "__main__":
    main()