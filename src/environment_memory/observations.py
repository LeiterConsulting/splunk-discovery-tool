"""Turn discovery reports, chat search results, and scheduled checks into observations the record merges.

An observation lists items by kind. An item can say whether it had events in the observation's window
(``active``), when its latest event was (``last_event``), and an event count for the last 24 hours with
the method that counted it. ``complete`` names the kinds the observation covers in full for its window,
so anything missing from it had no events in that window. ``listing_complete`` means the observation
lists every index that exists, empty or not.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence, Tuple

from .values import KINDS, clean_name, is_internal_index, name_key, parse_time, safe_float, safe_int, to_iso, utc_now

COUNT_TSTATS_24H = "tstats_24h"
COUNT_METADATA_24H = "metadata_24h"

CHECK_WINDOW = "-24h"
CHECK_ROW_LIMIT = 5000
_ROUND_ROW_CAPS = frozenset({50, 100, 200, 250, 500, 1000, 2000, 2500, 5000, 10000, 50000})
# Index activity covers internal indexes too; sourcetypes and hosts cover only the indexes a plain
# index=* search reaches, as discovery's metadata inventory does, so the two compare like for like.
CHECK_QUERIES = (
    ("by_sourcetype", "| tstats count max(_time) as lastTime where index=* OR index=_* by index sourcetype"),
    ("by_host", "| tstats count max(_time) as lastTime where index=* by host"),
)

HARVEST_TOOL_NAMES = frozenset({
    "splunk_run_query", "run_splunk_query", "splunk_get_indexes", "get_indexes", "splunk_get_metadata", "get_metadata",
})
CHAT_ROW_LIMIT = 5000
_ROW_TIME_FIELDS = ("lastTime", "latest", "latest_time", "last_event", "last_seen", "lastSeen", "maxTime", "_time")
_ROW_COUNT_FIELDS = ("count", "totalCount", "event_count", "events")
_INVENTORY_KEYS = {"index": "indexes", "sourcetype": "sourcetypes", "host": "hosts", "source": "sources"}
_STEP_NAMES = {"index": "indexes", "sourcetype": "sourcetypes", "host": "hosts", "source": "sources"}


def new_observation(origin: str, at: datetime, *, ref: str = "", window_hours: Optional[int] = None) -> Dict[str, Any]:
    return {
        "origin": origin,
        "at": to_iso(at),
        "ref": ref,
        "window_hours": window_hours,
        "complete": {},
        "listing_complete": False,
        "items": {kind: {} for kind in KINDS},
    }


def has_items(observation: Optional[Mapping[str, Any]]) -> bool:
    return bool(observation) and any(observation["items"].get(kind) for kind in KINDS)


def _item(observation: Dict[str, Any], kind: str, value: Any) -> Optional[Dict[str, Any]]:
    name = clean_name(kind, value)
    if name is None:
        return None
    items = observation["items"][kind]
    return items.setdefault(name_key(name), {"name": name})


def _note_event(item: Dict[str, Any], moment: Optional[datetime]) -> None:
    if moment is None:
        return
    current = parse_time(item.get("last_event"))
    if current is None or moment > current:
        item["last_event"] = to_iso(moment)


def _add_index(item: Dict[str, Any], index_name: Optional[str]) -> None:
    if index_name and index_name not in item.setdefault("indexes", []):
        item["indexes"].append(index_name)


def _add_count(item: Dict[str, Any], count: int, method: str) -> None:
    item["count"] = (item.get("count") or 0) + count
    item["count_method"] = method


def observation_from_blueprint(
    blueprint: Any,
    ref: str,
    *,
    fallback_at: Optional[datetime] = None,
) -> Optional[Dict[str, Any]]:
    """What one discovery run saw: every index, and the sourcetypes, hosts, and sources with events in its 24-hour window."""
    if not isinstance(blueprint, Mapping):
        return None
    at = parse_time(blueprint.get("generated_at"), naive_is_local=True) or fallback_at or utc_now()
    observation = new_observation("discovery", at, ref=ref, window_hours=24)
    steps = blueprint.get("discovery_step_status") if isinstance(blueprint.get("discovery_step_status"), Mapping) else {}
    ledger_summary = blueprint.get("finding_ledger_summary") if isinstance(blueprint.get("finding_ledger_summary"), Mapping) else {}
    inventory = blueprint.get("discovered_inventory") if isinstance(blueprint.get("discovered_inventory"), Mapping) else {}

    def covered_in_full(kind: str) -> bool:
        status = steps.get(_STEP_NAMES[kind])
        if not isinstance(status, Mapping) or status.get("status") != "ok" or status.get("truncated"):
            return False
        summary = ledger_summary.get(kind)
        ledger_truncated = isinstance(summary, Mapping) and bool(summary.get("truncated"))
        inventory_truncated = bool(inventory.get(f"{_INVENTORY_KEYS[kind]}_total"))
        return not (ledger_truncated and inventory_truncated)

    activity_window_start = at.timestamp() - 24 * 3600
    index_activity: Optional[Mapping[str, Any]] = None
    for entry in blueprint.get("finding_ledger") or ():
        if not isinstance(entry, Mapping) or not isinstance(entry.get("data"), Mapping):
            continue
        kind = str(entry.get("kind") or "")
        data = entry["data"]
        if kind == "index":
            item = _item(observation, "index", data.get("name") or data.get("title"))
            if item is not None:
                item["listed"] = True
                total = safe_int(data.get("totalEventCount"))
                size = safe_float(data.get("currentDBSizeMB"))
                if total is not None:
                    item["total_events"] = total
                if size is not None:
                    item["size_mb"] = size
        elif kind == "index_detail":
            item = _item(observation, "index", data.get("name") or data.get("title"))
            if item is not None:
                item["listed"] = True
                retention = safe_int(data.get("frozenTimePeriodInSecs"))
                max_size = safe_float(data.get("maxTotalDataSizeMB"))
                if retention is not None and retention > 0:
                    item["retention_days"] = round(retention / 86400, 1)
                if max_size is not None:
                    item["max_size_mb"] = max_size
                for field, key, convert in (("totalEventCount", "total_events", safe_int), ("currentDBSizeMB", "size_mb", safe_float)):
                    value = convert(data.get(field))
                    if value is not None and key not in item:
                        item[key] = value
        elif kind in ("sourcetype", "host", "source"):
            item = _item(observation, kind, data.get(kind))
            if item is None:
                continue
            last_event = parse_time(data.get("lastTime") or data.get("lastTimeIso"), latest=at)
            _note_event(item, last_event)
            count = safe_int(data.get("totalCount"))
            if count is not None and count > 0:
                item["count"] = count
                item["count_method"] = COUNT_METADATA_24H
            item["active"] = True if last_event is None else last_event.timestamp() >= activity_window_start
        elif kind == "analytics" and data.get("analytics_id") == "recent_index_activity" and isinstance(data.get("data"), Mapping):
            index_activity = data["data"]

    for kind, key in _INVENTORY_KEYS.items():
        for value in inventory.get(key) or ():
            item = _item(observation, kind, value)
            if item is not None and kind == "index":
                item["listed"] = True

    if index_activity is not None:
        counts = index_activity.get("recent_event_counts") if isinstance(index_activity.get("recent_event_counts"), Mapping) else {}
        for name, value in counts.items():
            count = safe_int(value)
            item = _item(observation, "index", name)
            if item is None or count is None or count <= 0:
                continue
            item["count"] = count
            item["count_method"] = COUNT_TSTATS_24H
            item["active"] = True
        for name in index_activity.get("indexes_without_recent_events") or ():
            item = _item(observation, "index", name)
            if item is not None and not item.get("active"):
                item["active"] = False
        observation["complete"]["index"] = not index_activity.get("truncated")

    observation["listing_complete"] = covered_in_full("index")
    for kind in ("sourcetype", "host", "source"):
        observation["complete"][kind] = covered_in_full(kind)
    return observation


def observation_from_rows(row_sets: Iterable[Tuple[str, Sequence[Any]]], at: datetime) -> Optional[Dict[str, Any]]:
    """Names that chat searches returned.

    Only values from result rows count, never names from the question or the SPL. A chat search covers
    only what it asked for, so the observation is never complete and carries no 24-hour counts.
    """
    observation = new_observation("chat", at)
    scanned = 0
    for tool_name, rows in row_sets:
        if str(tool_name or "").strip().lower() not in HARVEST_TOOL_NAMES:
            continue
        for row in rows or ():
            if scanned >= CHAT_ROW_LIMIT:
                break
            scanned += 1
            if not isinstance(row, Mapping):
                continue
            count = next((safe_int(row.get(field)) for field in _ROW_COUNT_FIELDS if safe_int(row.get(field)) is not None), None)
            if count is not None and count <= 0:
                continue
            last_event = next(
                (moment for moment in (parse_time(row.get(field), latest=at) for field in _ROW_TIME_FIELDS) if moment is not None),
                None,
            )
            index_value = row.get("index")
            listed = False
            if index_value is None and "totalEventCount" in row:
                index_value = row.get("title") or row.get("name")
                listed = True
            index_item = _item(observation, "index", index_value) if index_value is not None else None
            if index_item is not None:
                _note_event(index_item, last_event)
                if listed:
                    index_item["listed"] = True
                    total = safe_int(row.get("totalEventCount"))
                    if total is not None:
                        index_item["total_events"] = total
                if is_internal_index(index_item["name"]):
                    continue
            for kind in ("sourcetype", "host", "source"):
                if row.get(kind) is None:
                    continue
                item = _item(observation, kind, row.get(kind))
                if item is None:
                    continue
                _note_event(item, last_event)
                if kind == "sourcetype" and index_item is not None:
                    _add_index(item, index_item["name"])
    return observation if has_items(observation) else None


def check_rows_complete(row_count: int, *, total_rows: Optional[int] = None, truncated: bool = False) -> bool:
    """Whether a check search returned every row, so anything missing from it had no events in the window.

    Servers that cap results tend to cap at a round number, so a result of exactly that size may be cut short.
    """
    if row_count <= 0 or truncated:
        return False
    if total_rows is not None and total_rows > row_count:
        return False
    return row_count < CHECK_ROW_LIMIT and row_count not in _ROUND_ROW_CAPS


def observation_from_check(
    sourcetype_rows: Sequence[Any],
    host_rows: Sequence[Any],
    *,
    at: datetime,
    sourcetype_complete: bool,
    host_complete: bool,
) -> Dict[str, Any]:
    """What the scheduled check's two tstats searches (CHECK_QUERIES) found over the last 24 hours."""
    observation = new_observation("check", at, window_hours=24)
    for row in sourcetype_rows or ():
        if not isinstance(row, Mapping):
            continue
        count = safe_int(row.get("count"))
        if count is None or count <= 0:
            continue
        last_event = parse_time(row.get("lastTime"), latest=at)
        index_item = _item(observation, "index", row.get("index"))
        if index_item is not None:
            _add_count(index_item, count, COUNT_TSTATS_24H)
            _note_event(index_item, last_event)
            index_item["active"] = True
            if is_internal_index(index_item["name"]):
                continue
        sourcetype_item = _item(observation, "sourcetype", row.get("sourcetype"))
        if sourcetype_item is not None:
            _add_count(sourcetype_item, count, COUNT_TSTATS_24H)
            _note_event(sourcetype_item, last_event)
            sourcetype_item["active"] = True
            _add_index(sourcetype_item, index_item["name"] if index_item else None)
    for row in host_rows or ():
        if not isinstance(row, Mapping):
            continue
        count = safe_int(row.get("count"))
        if count is None or count <= 0:
            continue
        host_item = _item(observation, "host", row.get("host"))
        if host_item is not None:
            _add_count(host_item, count, COUNT_TSTATS_24H)
            _note_event(host_item, parse_time(row.get("lastTime"), latest=at))
            host_item["active"] = True
    observation["complete"] = {"index": sourcetype_complete, "sourcetype": sourcetype_complete, "host": host_complete}
    return observation
