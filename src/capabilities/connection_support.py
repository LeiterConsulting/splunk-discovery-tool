"""Whether a Splunk connection offers the MCP tools a capability needs."""

from typing import Any, Callable, Dict, Iterable, Optional

SchemaCheck = Callable[[str, Any], Optional[str]]


def evaluate_connection_support(
    required_tools: Iterable[str],
    catalog: Optional[Dict[str, Any]],
    schema_check: Optional[SchemaCheck] = None,
) -> Dict[str, Any]:
    """Return the support state for one connection's tool catalog.

    States: ``available`` (every tool is listed and matches), ``potential`` (the Splunk environment
    lacks the tools, so the Splunk-side software must be installed there), ``incompatible`` (the tools
    are listed but their arguments do not match), and ``unknown`` (no connection, or its tool list
    could not be read). ``catalog`` is None when there is no connection.
    """
    required = [str(name) for name in required_tools or []]
    if not required:
        return {"state": "not_required", "message": ""}
    if catalog is None:
        return {
            "state": "unknown",
            "reason": "no_connection",
            "message": "No Splunk connection is set for you, so this cannot be checked.",
        }
    checked_at = catalog.get("checked_at")
    if not catalog.get("ok"):
        return {
            "state": "unknown",
            "reason": "catalog_unavailable",
            "message": "Could not read the tool list from this Splunk connection. Check the connection and try again.",
            "checked_at": checked_at,
        }
    listed = set(catalog.get("tools") or [])
    missing = [name for name in required if name not in listed]
    if missing:
        return {
            "state": "potential",
            "missing_tools": missing,
            "message": "This Splunk environment does not offer the tools this capability needs. Install the Splunk apps listed below in that environment to use it.",
            "checked_at": checked_at,
        }
    schemas = catalog.get("schemas") if isinstance(catalog.get("schemas"), dict) else {}
    problems = []
    if schema_check is not None:
        for name in required:
            issue = schema_check(name, schemas.get(name))
            if issue:
                problems.append(f"{name} {issue}.")
    if problems:
        return {
            "state": "incompatible",
            "problems": problems,
            "message": "This Splunk environment lists the tools, but they do not match the version this app supports. Update the Splunk apps listed below.",
            "checked_at": checked_at,
        }
    return {
        "state": "available",
        "message": "This Splunk connection offers the tools this capability needs.",
        "checked_at": checked_at,
    }
