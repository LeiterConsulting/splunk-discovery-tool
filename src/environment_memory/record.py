"""The environment record for one discovery scope: what has been seen there, its state now, and a change log.

Each scope (Global, one per saved MCP connection, and No MCP) keeps its record in its own discovery folder,
under ``environment_memory/``, so it follows the same access rules as that scope's discovery reports. The
Knowledge Base does not index that folder.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, TypeVar

from incognito.vault import file_lock, write_private_file

from .observations import COUNT_TSTATS_24H, observation_from_blueprint
from .values import ENVIRONMENT_MEMORY_DIR_NAME, KINDS, safe_int, stored_moment, to_iso, utc_now

RECORD_FILENAME = "record.json"
RECORD_VERSION = 1
# Sources are remembered but not reported as changes: rotated log files would flood the log.
CHANGE_KINDS = ("index", "sourcetype", "host")
CHANGE_TYPES = ("new", "went_quiet", "back", "volume_shift", "gone")
ENTITY_CAPS = {"index": 2000, "sourcetype": 5000, "host": 5000, "source": 2000}
MAX_CHANGES = 500
MAX_OBSERVATIONS = 50
MAX_DISCOVERY_REFS = 200
MAX_INDEXES_PER_ITEM = 10
MIN_SHIFT_EVENTS = 100
BACKFILL_RUNS = 2
# A report this young may still be being written; it is read again on the next pass instead.
UNREADABLE_REPORT_GRACE_SECONDS = 120
BLUEPRINT_NAME = re.compile(r"^v2_intelligence_blueprint_(\d{8}_\d{6})\.json$")
ORIGIN_LABELS = {"discovery": "a discovery run", "chat": "a chat search", "check": "a scheduled check"}

T = TypeVar("T")


def record_path(folder: Path) -> Path:
    return Path(folder) / ENVIRONMENT_MEMORY_DIR_NAME / RECORD_FILENAME


def empty_record() -> Dict[str, Any]:
    return {
        "version": RECORD_VERSION,
        "created_at": None,
        "updated_at": None,
        "baseline": {},
        "entities": {kind: {} for kind in KINDS},
        "changes": [],
        "next_change_id": 1,
        "observations": [],
        "discovery_refs": [],
        "last": {},
        "last_check": None,
    }


def normalize_record(data: Any) -> Dict[str, Any]:
    record = empty_record()
    if not isinstance(data, dict):
        return record
    for key in ("created_at", "updated_at"):
        if isinstance(data.get(key), str):
            record[key] = data[key]
    if isinstance(data.get("last_check"), dict):
        record["last_check"] = data["last_check"]
    for key in ("baseline", "last"):
        if isinstance(data.get(key), dict):
            record[key] = data[key]
    for key in ("changes", "observations", "discovery_refs"):
        if isinstance(data.get(key), list):
            record[key] = data[key]
    entities = data.get("entities")
    if isinstance(entities, dict):
        for kind in KINDS:
            if isinstance(entities.get(kind), dict):
                record["entities"][kind] = entities[kind]
    record["next_change_id"] = max(safe_int(data.get("next_change_id")) or 1, len(record["changes"]) + 1)
    return record


def discovery_blueprints(folder: Path) -> List[Tuple[str, Path]]:
    """Discovery reports in a scope folder as (run timestamp, path), oldest first."""
    found: List[Tuple[str, Path]] = []
    for path in Path(folder).glob("v2_intelligence_blueprint_*.json"):
        match = BLUEPRINT_NAME.match(path.name)
        if match and path.is_file():
            found.append((match.group(1), path))
    return sorted(found)


def format_moment(value: Any) -> str:
    moment = stored_moment(value)
    return moment.strftime("%Y-%m-%d %H:%M UTC") if moment else ""


def _later(current: Any, candidate: Any) -> Any:
    current_moment, candidate_moment = stored_moment(current), stored_moment(candidate)
    if candidate_moment is None:
        return current
    if current_moment is None or candidate_moment > current_moment:
        return candidate
    return current


def _earlier(current: Any, candidate: Any) -> Any:
    current_moment, candidate_moment = stored_moment(current), stored_moment(candidate)
    if candidate_moment is None:
        return current
    if current_moment is None or candidate_moment < current_moment:
        return candidate
    return current


def _new_entity(name: str, at_iso: str) -> Dict[str, Any]:
    return {"name": name, "first_seen": at_iso, "last_seen": at_iso, "status": "unknown", "origins": {}}


def _apply_facts(entity: Dict[str, Any], item: Mapping[str, Any], at_iso: str, origin: str, covered: bool) -> None:
    entity["last_seen"] = _later(entity.get("last_seen"), at_iso)
    entity["first_seen"] = _earlier(entity.get("first_seen"), at_iso)
    origins = entity.setdefault("origins", {})
    origins[origin] = _later(origins.get(origin), at_iso)
    if item.get("last_event"):
        entity["last_event"] = _later(entity.get("last_event"), item["last_event"])
    if item.get("listed"):
        entity["listed"] = True
    if covered:
        # Seen by an observation that covers its kind in full, so a later one can judge it by its absence.
        entity["covered"] = True
    for key in ("total_events", "size_mb", "retention_days", "max_size_mb"):
        if item.get(key) is not None:
            entity[key] = item[key]
    if item.get("indexes"):
        merged = list(dict.fromkeys(list(entity.get("indexes") or []) + list(item["indexes"])))
        entity["indexes"] = merged[-MAX_INDEXES_PER_ITEM:]


def _volume_shift(entity: Dict[str, Any], item: Mapping[str, Any], at_iso: str) -> Optional[Tuple[int, int]]:
    """Store the item's 24-hour count; return (before, now) when it rose or fell by more than half."""
    count, method = safe_int(item.get("count")), item.get("count_method")
    if count is None or not method:
        return None
    previous, previous_method = safe_int(entity.get("count_24h")), entity.get("count_method")
    entity["count_24h"], entity["count_method"], entity["count_at"] = count, method, at_iso
    if previous is not None:
        entity["previous_count_24h"] = previous
    # Metadata totals cover whole buckets, so only tstats counts are exact enough to compare.
    if method != COUNT_TSTATS_24H or previous_method != method or previous is None or previous <= 0:
        return None
    if max(previous, count) < MIN_SHIFT_EVENTS:
        return None
    if count > previous * 1.5 or count < previous * 0.5:
        return previous, count
    return None


def _recent(
    item: Mapping[str, Any],
    entity: Mapping[str, Any],
    at: datetime,
    threshold: timedelta,
    window: Optional[timedelta],
) -> Optional[bool]:
    """Whether the item had events within the quiet threshold before the observation; None when unknown."""
    if stored_moment(item.get("last_event")) is not None:
        # The entity already holds the later of its known last event and this one.
        last_event = stored_moment(entity.get("last_event")) or stored_moment(item.get("last_event"))
        return at - last_event <= threshold
    active = item.get("active")
    if window is None or active is None:
        return None
    if active:
        return True if threshold >= window else None
    return _recent_when_absent(entity, at, threshold, window)


def _recent_when_absent(entity: Mapping[str, Any], at: datetime, threshold: timedelta, window: timedelta) -> Optional[bool]:
    """For something a complete observation did not see: it had no events in the observation's window."""
    stored = stored_moment(entity.get("last_event"))
    if stored is not None and stored >= at - window:
        return None
    if threshold <= window:
        return False
    if stored is not None and at - stored > threshold:
        return False
    return None


def _quiet_detail(entity: Mapping[str, Any], window_hours: Optional[int]) -> str:
    last_event = format_moment(entity.get("last_event"))
    if last_event:
        return f"No events since {last_event}"
    return f"No events in the last {window_hours or 24} hours"


def _transition(entity: Dict[str, Any], recent: Optional[bool], at_iso: str, allow_quiet: bool) -> Optional[str]:
    """Move the entity's status for this observation and return the change type it causes, if any."""
    if recent is None:
        return None
    status_at = stored_moment(entity.get("status_at"))
    at = stored_moment(at_iso)
    if status_at is not None and at is not None and at < status_at:
        return None
    status = entity.get("status") or "unknown"
    if recent:
        entity["status"], entity["status_at"] = "active", at_iso
        entity.pop("quiet_since", None)
        was_active = bool(entity.get("ever_active"))
        entity["ever_active"] = True
        if status == "quiet":
            return "back"
        if status == "idle" and not was_active:
            return "started"
        return None
    if not allow_quiet:
        return None
    entity["status_at"] = at_iso
    if status == "active":
        entity["status"] = "quiet"
        entity["quiet_since"] = entity.get("last_event") or at_iso
        return "went_quiet"
    if status == "unknown":
        entity["status"] = "idle"
    return None


def _make_change(record: Dict[str, Any], kind: str, entity: Mapping[str, Any], change: str, origin: str, at_iso: str,
                 detail: str, **extra: Any) -> Dict[str, Any]:
    entry = {
        "id": record["next_change_id"],
        "at": at_iso,
        "kind": kind,
        "name": entity.get("name"),
        "change": change,
        "origin": origin,
        "detail": detail,
    }
    entry.update({key: value for key, value in extra.items() if value is not None})
    record["next_change_id"] += 1
    return entry


def _status_change(record: Dict[str, Any], kind: str, entity: Mapping[str, Any], outcome: str, origin: str, at_iso: str,
                   window_hours: Optional[int]) -> Dict[str, Any]:
    if outcome == "went_quiet":
        return _make_change(record, kind, entity, "went_quiet", origin, at_iso, _quiet_detail(entity, window_hours),
                            last_event=entity.get("last_event"))
    if outcome == "back":
        return _make_change(record, kind, entity, "back", origin, at_iso, "Sending events again", last_event=entity.get("last_event"))
    return _make_change(record, kind, entity, "new", origin, at_iso, "First events seen", last_event=entity.get("last_event"))


def _enforce_caps(record: Dict[str, Any]) -> None:
    for kind, cap in ENTITY_CAPS.items():
        bucket = record["entities"][kind]
        if len(bucket) <= cap:
            continue
        oldest = sorted(bucket, key=lambda key: str(bucket[key].get("last_seen") or ""))
        for key in oldest[: len(bucket) - cap]:
            del bucket[key]


def merge_observation(record: Dict[str, Any], observation: Mapping[str, Any], *, quiet_hours: int) -> List[Dict[str, Any]]:
    """Fold one observation into the record and return the changes it caused.

    A kind reports changes only once an observation has covered it in full (its baseline), so the first
    discovery run or check records what exists without calling all of it new.
    """
    at_iso = str(observation["at"])
    at = stored_moment(at_iso) or utc_now()
    origin = str(observation.get("origin") or "chat")
    threshold = timedelta(hours=max(1, int(quiet_hours)))
    window_hours = observation.get("window_hours")
    window = timedelta(hours=window_hours) if window_hours else None
    allow_quiet = origin != "chat"
    complete = observation.get("complete") or {}
    baseline = record["baseline"]
    changes: List[Dict[str, Any]] = []

    for kind in KINDS:
        items = (observation.get("items") or {}).get(kind) or {}
        bucket = record["entities"][kind]
        reported = kind in CHANGE_KINDS
        covered = bool(window and complete.get(kind))
        for key, item in items.items():
            entity = bucket.get(key)
            created = entity is None
            if created:
                entity = _new_entity(item["name"], at_iso)
                bucket[key] = entity
                # Indexes listed with no activity need a listing baseline, or a first discovery after
                # checks alone would call every empty index new.
                listing_only = kind == "index" and item.get("listed") and not item.get("active")
                if reported and baseline.get("index_listing" if listing_only else kind):
                    changes.append(_make_change(record, kind, entity, "new", origin, at_iso,
                                                f"First seen in {ORIGIN_LABELS.get(origin, origin)}"))
            elif entity.get("status") == "gone" and item.get("listed"):
                entity["status"], entity["status_at"] = "unknown", at_iso
                if reported and baseline.get("index_listing"):
                    changes.append(_make_change(record, kind, entity, "new", origin, at_iso, "Listed again after it was gone"))
            _apply_facts(entity, item, at_iso, origin, covered)
            shift = _volume_shift(entity, item, at_iso)
            if shift and reported and not created:
                before, now = shift
                direction = "up" if now > before else "down"
                percent = round(abs(now - before) * 100 / before)
                changes.append(_make_change(
                    record, kind, entity, "volume_shift", origin, at_iso,
                    f"Events in 24 hours went from {before:,} to {now:,} ({direction} {percent}%)",
                    previous=before, current=now,
                ))
            outcome = _transition(entity, _recent(item, entity, at, threshold, window), at_iso, allow_quiet)
            if outcome and reported and not created and baseline.get(kind):
                changes.append(_status_change(record, kind, entity, outcome, origin, at_iso, window_hours))

        if kind == "index" and observation.get("listing_complete"):
            for key, entity in bucket.items():
                if entity.get("status") == "gone" or not entity.get("listed"):
                    continue
                item = items.get(key)
                if item is not None and item.get("listed"):
                    continue
                entity["status"], entity["status_at"], entity["listed"] = "gone", at_iso, False
                if baseline.get("index_listing"):
                    changes.append(_make_change(record, kind, entity, "gone", origin, at_iso, "No longer listed by discovery"))

        if covered:
            for key, entity in bucket.items():
                if key in items or entity.get("status") == "gone" or not entity.get("covered"):
                    continue
                outcome = _transition(entity, _recent_when_absent(entity, at, threshold, window), at_iso, allow_quiet)
                if outcome and reported and baseline.get(kind):
                    changes.append(_status_change(record, kind, entity, outcome, origin, at_iso, window_hours))

    if window:
        for kind in KINDS:
            if complete.get(kind):
                baseline[kind] = True
    if observation.get("listing_complete"):
        baseline["index_listing"] = True

    _enforce_caps(record)
    record["changes"] = (record["changes"] + changes)[-MAX_CHANGES:]
    record["observations"] = (record["observations"] + [{
        "at": at_iso,
        "origin": origin,
        "ref": str(observation.get("ref") or ""),
        "complete": sorted(kind for kind in KINDS if complete.get(kind)),
        "items": {kind: len((observation.get("items") or {}).get(kind) or {}) for kind in KINDS},
        "changes": len(changes),
    }])[-MAX_OBSERVATIONS:]
    record["last"][origin] = _later(record["last"].get(origin), at_iso)
    return changes


class EnvironmentMemory:
    """Reads and updates one scope's record. Every update holds a file lock, so processes never lose each other's writes."""

    def __init__(self, folder: Path) -> None:
        self.folder = Path(folder)
        self.path = record_path(self.folder)
        self._lock_path = self.path.with_name(f"{RECORD_FILENAME}.lock")

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> Dict[str, Any]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError:
            return empty_record()
        try:
            return normalize_record(json.loads(raw))
        except ValueError:
            # The record only holds what Splunk showed, so an unreadable one starts over rather than stopping chat.
            return empty_record()

    def _save(self, record: Dict[str, Any]) -> None:
        write_private_file(self.path, json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))

    def update(self, mutate: Callable[[Dict[str, Any]], T]) -> T:
        with file_lock(self._lock_path):
            record = self.load()
            result = mutate(record)
            now = to_iso(utc_now())
            record["created_at"] = record.get("created_at") or now
            record["updated_at"] = now
            self._save(record)
        return result

    def apply(self, observation: Optional[Mapping[str, Any]], *, quiet_hours: int) -> List[Dict[str, Any]]:
        if not observation:
            return []
        return self.update(lambda record: merge_observation(record, observation, quiet_hours=quiet_hours))

    def pending_discovery(self, record: Optional[Mapping[str, Any]] = None) -> List[Tuple[str, Path]]:
        """Discovery runs not merged yet. A new record starts from the last BACKFILL_RUNS runs, so it shows changes at once."""
        current = record if record is not None else self.load()
        reports = discovery_blueprints(self.folder)
        done = set(current.get("discovery_refs") or [])
        if not done:
            return reports[-BACKFILL_RUNS:]
        newest = max(done)
        return [(ref, path) for ref, path in reports if ref > newest]

    def sync_discovery(self, *, quiet_hours: int) -> int:
        """Merge discovery runs this record has not seen yet; return how many were merged."""
        if not self.pending_discovery():
            return 0

        def mutate(record: Dict[str, Any]) -> int:
            merged = 0
            for ref, path in self.pending_discovery(record):
                try:
                    blueprint = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    try:
                        young = time.time() - path.stat().st_mtime < UNREADABLE_REPORT_GRACE_SECONDS
                    except OSError:
                        young = False
                    if young:
                        break
                    blueprint = None
                observation = observation_from_blueprint(blueprint, ref) if blueprint is not None else None
                if observation is not None:
                    merge_observation(record, observation, quiet_hours=quiet_hours)
                    merged += 1
                record["discovery_refs"] = (record["discovery_refs"] + [ref])[-MAX_DISCOVERY_REFS:]
            return merged

        return self.update(mutate)

    def record_check(self, at: datetime, *, status: str, error: str = "", changes: int = 0) -> None:
        entry: Dict[str, Any] = {"at": to_iso(at), "status": status, "changes": changes}
        if error:
            entry["error"] = error[:300]

        def mutate(record: Dict[str, Any]) -> None:
            record["last_check"] = entry

        self.update(mutate)

    def clear(self) -> None:
        """Forget everything learned here. Discovery runs that exist now are not read again, so the record starts
        over from the next run, check, or chat search instead of rebuilding itself from old runs."""

        def mutate(record: Dict[str, Any]) -> None:
            fresh = empty_record()
            fresh["discovery_refs"] = [ref for ref, _path in discovery_blueprints(self.folder)][-MAX_DISCOVERY_REFS:]
            record.clear()
            record.update(fresh)

        self.update(mutate)
