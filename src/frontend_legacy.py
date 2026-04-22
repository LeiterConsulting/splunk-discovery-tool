"""Legacy frontend template loader shared by runtime and build tooling."""

from functools import lru_cache
from pathlib import Path


FRONTEND_LEGACY_TEMPLATE_PATH = Path(__file__).with_name("frontend_legacy_template.html")


@lru_cache(maxsize=1)
def get_frontend_html() -> str:
    """Return the extracted legacy frontend HTML fallback."""
    return FRONTEND_LEGACY_TEMPLATE_PATH.read_text(encoding="utf-8")