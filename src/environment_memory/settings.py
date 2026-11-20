"""Admin settings for environment memory, saved in the global environment_memory folder."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from incognito.vault import write_private_file

from .values import ENVIRONMENT_MEMORY_DIR_NAME, to_iso, utc_now

SETTINGS_FILENAME = "settings.json"
CHECK_INTERVAL_RANGE = (1, 168)
QUIET_HOURS_RANGE = (1, 720)


@dataclass
class EnvironmentMemorySettings:
    learn_from_chat: bool = True
    scheduled_check: bool = False
    check_interval_hours: int = 6
    quiet_hours: int = 24
    updated_at: str = ""
    updated_by: str = ""
    unreadable: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Any) -> "EnvironmentMemorySettings":
        settings = cls()
        if not isinstance(data, Mapping):
            return settings
        for key in ("learn_from_chat", "scheduled_check"):
            if isinstance(data.get(key), bool):
                setattr(settings, key, data[key])
        for key, (low, high) in (("check_interval_hours", CHECK_INTERVAL_RANGE), ("quiet_hours", QUIET_HOURS_RANGE)):
            value = data.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high:
                setattr(settings, key, value)
        for key in ("updated_at", "updated_by"):
            if isinstance(data.get(key), str):
                setattr(settings, key, data[key])
        return settings


def apply_settings_updates(current: EnvironmentMemorySettings, payload: Mapping[str, Any]) -> EnvironmentMemorySettings:
    """A copy of ``current`` with the payload's changes; raises ValueError naming the first bad value."""
    updated = EnvironmentMemorySettings.from_dict(current.to_dict())
    for key in ("learn_from_chat", "scheduled_check"):
        if key in payload:
            if not isinstance(payload[key], bool):
                raise ValueError(f"{key} must be true or false")
            setattr(updated, key, payload[key])
    for key, (low, high) in (("check_interval_hours", CHECK_INTERVAL_RANGE), ("quiet_hours", QUIET_HOURS_RANGE)):
        if key in payload:
            value = payload[key]
            if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                raise ValueError(f"{key} must be a whole number of hours from {low} to {high}")
            setattr(updated, key, value)
    return updated


class EnvironmentSettingsStore:
    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = Path(path) if path is not None else None

    @property
    def path(self) -> Path:
        # Resolved at each use, so the store follows the working folder the app runs in.
        return self._path or Path("output") / ENVIRONMENT_MEMORY_DIR_NAME / SETTINGS_FILENAME

    def load(self) -> EnvironmentMemorySettings:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return EnvironmentMemorySettings()
        except OSError:
            settings = EnvironmentMemorySettings()
            settings.unreadable = True
            return settings
        try:
            return EnvironmentMemorySettings.from_dict(json.loads(raw))
        except ValueError:
            settings = EnvironmentMemorySettings()
            settings.unreadable = True
            return settings

    def save(self, settings: EnvironmentMemorySettings, *, updated_by: str = "") -> EnvironmentMemorySettings:
        saved = EnvironmentMemorySettings.from_dict(settings.to_dict())
        saved.updated_at = to_iso(utc_now()) or ""
        saved.updated_by = updated_by
        data = saved.to_dict()
        data.pop("unreadable", None)
        write_private_file(self.path, json.dumps(data, indent=2).encode("utf-8"))
        return saved
