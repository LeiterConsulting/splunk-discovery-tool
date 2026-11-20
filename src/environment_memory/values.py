"""Names, times, and numbers as the environment record stores them."""

from __future__ import annotations

import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

ENVIRONMENT_MEMORY_DIR_NAME = "environment_memory"
KINDS = ("index", "sourcetype", "host", "source")

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_INDEX_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-]*$")
_MAX_NAME_LENGTH = {"index": 80, "sourcetype": 200, "host": 255, "source": 500}
_PLACEHOLDERS = frozenset({"*", "-", "null", "none", "n/a", "unknown", "other"})
_EARLIEST_EVENT = datetime(2000, 1, 1, tzinfo=timezone.utc)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(moment: Optional[datetime]) -> Optional[str]:
    if moment is None:
        return None
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def stored_moment(value: Any) -> Optional[datetime]:
    """A moment the record stored with to_iso."""
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def parse_time(value: Any, *, naive_is_local: bool = False, latest: Optional[datetime] = None) -> Optional[datetime]:
    """A moment from epoch seconds or ISO 8601 text, or None when the value is not a plausible event time."""
    if value is None or isinstance(value, bool):
        return None
    moment: Optional[datetime] = None
    seconds: Optional[float] = None
    if isinstance(value, (int, float)):
        seconds = float(value)
    else:
        text = str(value).strip()
        if not text:
            return None
        try:
            seconds = float(text)
        except ValueError:
            try:
                moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                return None
            if moment.tzinfo is None:
                # Discovery stamps its reports in the server's local time.
                moment = moment.astimezone(timezone.utc) if naive_is_local else moment.replace(tzinfo=timezone.utc)
    if moment is None:
        if seconds is None or not math.isfinite(seconds):
            return None
        try:
            moment = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    moment = moment.astimezone(timezone.utc)
    if moment < _EARLIEST_EVENT or moment > (latest or utc_now()) + timedelta(days=1):
        return None
    return moment


def safe_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return int(number) if math.isfinite(number) else None


def safe_float(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return round(number, 2) if math.isfinite(number) else None


def clean_name(kind: str, value: Any) -> Optional[str]:
    """The name as the record keeps it, or None when the value cannot be a real index, sourcetype, host, or source."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value).strip()
    if not text or len(text) > _MAX_NAME_LENGTH.get(kind, 200) or _CONTROL.search(text):
        return None
    if text.lower() in _PLACEHOLDERS:
        return None
    if kind == "index" and not _INDEX_NAME.match(text):
        return None
    return text


def name_key(name: str) -> str:
    return name.lower()


def is_internal_index(name: Any) -> bool:
    return isinstance(name, str) and name.startswith("_")
