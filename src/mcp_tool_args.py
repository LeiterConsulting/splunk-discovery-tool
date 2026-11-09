"""Map tool-call arguments onto a Splunk MCP server's advertised input schemas.

The GA Splunk MCP server validates arguments strictly (for example
``splunk_get_index_info`` requires ``index_name`` and
``splunk_get_knowledge_objects`` requires ``type`` from a fixed enum), while
callers and LLMs use several spellings. These helpers are pure so both the
chat agent and the discovery engine can share them.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Mapping, Optional, Tuple

__all__ = ["adapt_tool_arguments", "parse_jsonrpc_error"]

_ARGUMENT_ALIASES: Tuple[Tuple[str, ...], ...] = (
    ("index_name", "index"),
    ("type", "object_type"),
    ("row_limit", "count", "limit", "max_results"),
    ("earliest_time", "earliest"),
    ("latest_time", "latest"),
)

_ENUM_SYNONYMS = {
    "saved_search": "saved_searches",
    "savedsearches": "saved_searches",
    "savedsearch": "saved_searches",
    "searches": "saved_searches",
    "alert": "alerts",
    "macro": "macros",
    "lookup": "lookups",
    "datamodel": "data_models",
    "datamodels": "data_models",
    "data_model": "data_models",
    "tag": "tags",
    "view": "views",
    "dashboards": "views",
    "dashboard": "views",
    "app": "apps",
    "host": "hosts",
    "source": "sources",
}


def _coerce_to_schema(value: Any, spec: Any) -> Any:
    if not isinstance(spec, Mapping):
        return value
    expected = spec.get("type")
    if expected == "integer":
        try:
            number = int(float(value))
        except (TypeError, ValueError):
            return value
        minimum = spec.get("minimum")
        maximum = spec.get("maximum")
        if isinstance(minimum, (int, float)):
            number = max(int(minimum), number)
        if isinstance(maximum, (int, float)):
            number = min(int(maximum), number)
        return number
    if expected == "string" and isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    enum_values = spec.get("enum")
    if isinstance(enum_values, list) and isinstance(value, str) and value not in enum_values:
        lowered = value.strip().lower().replace(" ", "_").replace("-", "_")
        candidate = _ENUM_SYNONYMS.get(lowered, lowered)
        if candidate in enum_values:
            return candidate
    return value


def adapt_tool_arguments(args: Optional[Mapping[str, Any]], schema: Any) -> Tuple[Dict[str, Any], List[str]]:
    """Map argument names onto the tool's advertised input schema.

    Returns ``(arguments, dropped_keys)``. Aliases such as ``index`` ->
    ``index_name`` or ``row_limit`` -> ``count`` are renamed when the schema
    only knows the other spelling, values are coerced to the schema type and
    clamped to its bounds, and keys the schema does not declare are dropped.
    Without a usable schema the arguments are returned unchanged.
    """

    source = dict(args or {})
    if not isinstance(schema, Mapping) or schema.get("type", "object") != "object":
        return source, []
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return source, []
    if not properties:
        return {}, sorted(source)

    adapted: Dict[str, Any] = {}
    dropped: List[str] = []
    for key, value in source.items():
        target = key if key in properties else None
        if target is None:
            for group in _ARGUMENT_ALIASES:
                if key in group:
                    target = next((alias for alias in group if alias in properties), None)
                    break
        if target is None or (target in adapted and key not in properties):
            dropped.append(key)
            continue
        adapted[target] = _coerce_to_schema(value, properties.get(target))
    return adapted, dropped


def parse_jsonrpc_error(payload: Any) -> Optional[Dict[str, Any]]:
    """Return ``{code, message}`` for a JSON-RPC error body, else None."""

    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            return None
    if not isinstance(payload, Mapping):
        return None
    error = payload.get("error")
    if isinstance(error, Mapping):
        return {"code": error.get("code"), "message": str(error.get("message") or error.get("data") or "MCP error")}
    if isinstance(error, str) and error.strip():
        return {"code": payload.get("status_code"), "message": error.strip()}
    return None
