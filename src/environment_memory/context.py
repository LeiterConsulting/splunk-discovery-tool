"""Views of an environment record: the chat block, the API payload, and the busiest index."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Mapping, Optional

from .observations import COUNT_TSTATS_24H
from .record import CHANGE_TYPES, format_moment
from .values import KINDS, is_internal_index, safe_int, stored_moment

STATUS_RANK = {"active": 0, "unknown": 1, "idle": 2, "quiet": 3, "gone": 4}
KIND_LABELS = {"index": "Indexes", "sourcetype": "Sourcetypes", "host": "Hosts", "source": "Sources"}
RECENT_CHANGE_DAYS = 7
_ENTITY_FIELDS = (
    "name", "status", "first_seen", "last_seen", "last_event", "quiet_since", "count_24h", "count_method",
    "count_at", "previous_count_24h", "total_events", "size_mb", "max_size_mb", "retention_days", "indexes", "origins", "listed",
)


def _entities(record: Mapping[str, Any], kind: str) -> List[Dict[str, Any]]:
    bucket = (record.get("entities") or {}).get(kind) or {}
    return [entity for entity in bucket.values() if isinstance(entity, dict) and entity.get("name")]


def ranked_entities(record: Mapping[str, Any], kind: str, *, include_gone: bool = False) -> List[Dict[str, Any]]:
    """Sending first, own indexes before Splunk's internal ones, then by 24-hour count and most recently seen."""
    entities = [entity for entity in _entities(record, kind) if include_gone or entity.get("status") != "gone"]
    entities.sort(key=lambda entity: str(entity.get("last_seen") or ""), reverse=True)
    entities.sort(key=lambda entity: -(safe_int(entity.get("count_24h")) or 0))
    entities.sort(key=lambda entity: (is_internal_index(entity.get("name")), STATUS_RANK.get(entity.get("status"), 1)))
    return entities


def busiest_index(record: Mapping[str, Any]) -> str:
    """The deployment's own index with the most events, for suggestions that need a real index name."""
    for entity in ranked_entities(record, "index"):
        name = str(entity.get("name") or "")
        if name and not is_internal_index(name) and entity.get("status") in ("active", "unknown"):
            return name
    return ""


def sorted_changes(record: Mapping[str, Any]) -> List[Dict[str, Any]]:
    changes = [change for change in record.get("changes") or [] if isinstance(change, dict)]
    return sorted(changes, key=lambda change: (str(change.get("at") or ""), safe_int(change.get("id")) or 0), reverse=True)


def change_phrase(change: Mapping[str, Any]) -> str:
    kind, name, kind_change = change.get("kind"), change.get("name"), change.get("change")
    if kind_change == "new":
        return f"new {kind} {name}"
    if kind_change == "went_quiet":
        return f"{kind} {name} went quiet"
    if kind_change == "back":
        return f"{kind} {name} is sending again"
    if kind_change == "volume_shift":
        return f"{kind} {name}: {str(change.get('detail') or '').lower()}"
    if kind_change == "gone":
        return f"index {name} is no longer listed"
    return f"{kind} {name}"


def _count_text(entity: Mapping[str, Any]) -> str:
    count = safe_int(entity.get("count_24h"))
    if count is None or entity.get("count_method") != COUNT_TSTATS_24H:
        return ""
    return f" ({count:,} in 24h)"


def known_environment_block(record: Mapping[str, Any], *, now: datetime, compact: bool = False) -> str:
    """The KNOWN ENVIRONMENT section of chat instructions; empty when nothing is known yet."""
    if not any(_entities(record, kind) for kind in ("index", "sourcetype", "host")):
        return ""
    limit = 6 if compact else 12
    updated = format_moment(record.get("updated_at"))
    lines = [
        "KNOWN ENVIRONMENT (names this app has seen in this Splunk deployment through discovery runs, chat searches, "
        f"and scheduled checks{f'; last updated {updated}' if updated else ''}). Counts may be out of date, so run a "
        "search before relying on them:"
    ]
    for kind in ("index", "sourcetype", "host"):
        ranked = [entity for entity in ranked_entities(record, kind) if entity.get("status") != "quiet"]
        if not ranked:
            continue
        shown = [f"{entity['name']}{_count_text(entity)}" for entity in ranked[:limit]]
        extra = len(ranked) - len(shown)
        lines.append(f"- {KIND_LABELS[kind]}: {', '.join(shown)}{f', and {extra} more' if extra > 0 else ''}")

    quiet = [
        (kind, entity)
        for kind in ("index", "sourcetype", "host")
        for entity in _entities(record, kind)
        if entity.get("status") == "quiet"
    ]
    if quiet:
        quiet.sort(key=lambda pair: str(pair[1].get("status_at") or ""), reverse=True)
        quiet_limit = 3 if compact else 6
        parts = []
        for kind, entity in quiet[:quiet_limit]:
            last_event = format_moment(entity.get("last_event"))
            parts.append(f"{kind} {entity['name']}" + (f" (last event {last_event})" if last_event else ""))
        more = len(quiet) - quiet_limit
        lines.append(f"- Quiet now: {'; '.join(parts)}{f'; and {more} more' if more > 0 else ''}")

    cutoff = now - timedelta(days=RECENT_CHANGE_DAYS)
    recent = [change for change in sorted_changes(record) if (stored_moment(change.get("at")) or cutoff) > cutoff]
    if recent:
        change_limit = 3 if compact else 6
        parts = [f"{format_moment(change.get('at'))[:10]} {change_phrase(change)}" for change in recent[:change_limit]]
        more = len(recent) - change_limit
        lines.append(f"- Changes in the last {RECENT_CHANGE_DAYS} days: {'; '.join(parts)}{f'; and {more} more' if more > 0 else ''}")
    return "\n".join(lines)


def entity_view(entity: Mapping[str, Any]) -> Dict[str, Any]:
    return {field: entity[field] for field in _ENTITY_FIELDS if entity.get(field) is not None}


def changes_view(
    record: Mapping[str, Any],
    *,
    limit: int = 100,
    change: Optional[str] = None,
    kind: Optional[str] = None,
) -> List[Dict[str, Any]]:
    selected = [
        entry for entry in sorted_changes(record)
        if (not change or entry.get("change") == change) and (not kind or entry.get("kind") == kind)
    ]
    return selected[: max(0, limit)]


def memory_view(
    record: Mapping[str, Any],
    *,
    limit: int = 50,
    change_limit: int = 100,
    include_errors: bool = False,
) -> Dict[str, Any]:
    counts: Dict[str, Dict[str, int]] = {}
    entities: Dict[str, List[Dict[str, Any]]] = {}
    for kind in KINDS:
        all_entities = _entities(record, kind)
        tally = {"total": len(all_entities)}
        for status in STATUS_RANK:
            tally[status] = sum(1 for entity in all_entities if entity.get("status") == status)
        counts[kind] = tally
        ranked = ranked_entities(record, kind, include_gone=True)
        entities[kind] = [entity_view(entity) for entity in ranked[: max(0, limit)]]
    change_counts = {change_type: 0 for change_type in CHANGE_TYPES}
    for entry in record.get("changes") or []:
        if isinstance(entry, dict) and entry.get("change") in change_counts:
            change_counts[entry["change"]] += 1
    last_check = record.get("last_check") if isinstance(record.get("last_check"), dict) else None
    if last_check and not include_errors:
        last_check = {key: value for key, value in last_check.items() if key != "error"}
    observations = [entry for entry in record.get("observations") or [] if isinstance(entry, dict)]
    return {
        "has_data": any(counts[kind]["total"] for kind in KINDS),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
        "baseline": sorted(key for key, value in (record.get("baseline") or {}).items() if value),
        "counts": counts,
        "entities": entities,
        "changes": changes_view(record, limit=change_limit),
        "change_counts": change_counts,
        "observations": list(reversed(observations[-10:])),
        "last": dict(record.get("last") or {}),
        "last_check": last_check,
    }
