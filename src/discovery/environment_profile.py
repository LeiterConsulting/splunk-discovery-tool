"""Normalize the Splunk facts the knowledge library maps to documentation: deployment type and installed apps."""

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

CLOUD_HOST_SUFFIXES = (".splunkcloud.com", ".splunkcloudgc.com")
# Splunk Cloud Platform versions carry a YYMM release component, for example 9.3.2408.104.
CLOUD_VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d{4}(?:\.|$)")

# Apps that ship with Splunk Enterprise or Splunk Cloud Platform rather than coming from Splunkbase.
BUILTIN_APP_NAMES = frozenset(
    name.lower()
    for name in (
        "alert_logevent",
        "alert_webhook",
        "appsbrowser",
        "cloud_administration",
        "dmc",
        "dynamic-data-self-storage-app",
        "framework",
        "gettingstarted",
        "introspection_generator_addon",
        "journald_input",
        "launcher",
        "learned",
        "legacy",
        "python_upgrade_readiness_app",
        "sample_app",
        "search",
        "splunk-dashboard-studio",
        "splunk_archiver",
        "splunk_assist",
        "splunk_gdi",
        "splunk_httpinput",
        "splunk_ingest_actions",
        "splunk_instrumentation",
        "splunk_internal_metrics",
        "splunk_metrics_workspace",
        "splunk_monitoring_console",
        "splunk_rapid_diag",
        "splunk_secure_gateway",
        "splunkforwarder",
        "splunklightforwarder",
        "tos",
        "user-prefs",
    )
)
BUILTIN_APP_PREFIXES = ("splunk_cloud", "splunkcloud", "_cluster")


def _truthy(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "t", "y"}:
        return True
    if text in {"0", "false", "no", "off", "f", "n"}:
        return False
    return None


def splunk_version_line(version: Any) -> str:
    """Documentation version for a Splunk build: 9.4.2 -> 9.4, Cloud 9.3.2408.104 -> 9.3.2408."""
    text = str(version or "").strip()
    parts = re.findall(r"\d+", text)
    if len(parts) < 2:
        return ""
    if CLOUD_VERSION_PATTERN.match(text):
        return ".".join(parts[:3])
    return ".".join(parts[:2])


def detect_deployment_type(system_info: Optional[Dict[str, Any]], mcp_url: str = "") -> Tuple[str, str]:
    """Return ("cloud" | "enterprise" | "unknown", reason) from server info and the MCP endpoint."""
    info = system_info if isinstance(system_info, dict) else {}
    instance_type = str(info.get("instance_type") or "").strip().lower()
    if instance_type == "cloud":
        return "cloud", "Server info reports instance_type=cloud"
    host = (urlparse(str(mcp_url or "")).hostname or "").lower()
    if host.endswith(CLOUD_HOST_SUFFIXES):
        return "cloud", "The MCP endpoint is a Splunk Cloud Platform host"
    version = str(info.get("version") or "").strip()
    if CLOUD_VERSION_PATTERN.match(version):
        return "cloud", "The version number uses Splunk Cloud Platform release numbering"
    if version and version.lower() != "unknown":
        return "enterprise", "Server info has no Splunk Cloud Platform markers"
    return "unknown", "Server info was not available"


def is_builtin_app(name: str, core_flag: Optional[bool] = None) -> bool:
    if core_flag:
        return True
    lowered = str(name or "").strip().lower()
    if not lowered:
        return False
    if lowered in BUILTIN_APP_NAMES or lowered.startswith(BUILTIN_APP_PREFIXES):
        return True
    # Splunk Cloud Platform ships numbered service apps such as 000-self-service and 100-cloudworks-wlm.
    return bool(re.match(r"^\d{3}-", lowered))


def _first_text(row: Dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = row.get(key)
        if value not in (None, "") and not isinstance(value, (dict, list)):
            return str(value).strip()
    return ""


def normalize_installed_app_rows(rows: Any, limit: int = 1000) -> List[Dict[str, Any]]:
    """Flatten app rows from splunk_get_knowledge_objects(type=apps) or | rest /services/apps/local."""
    apps: Dict[str, Dict[str, Any]] = {}
    for raw in rows if isinstance(rows, list) else []:
        if not isinstance(raw, dict):
            continue
        row = dict(raw)
        content = row.get("content")
        if isinstance(content, dict):
            row = {**content, **{key: value for key, value in row.items() if key != "content"}}
        name = _first_text(row, ("title", "name", "app", "appid", "app_name"))
        if not name:
            entry_id = _first_text(row, ("id",))
            name = entry_id.rstrip("/").rsplit("/", 1)[-1] if entry_id else ""
        if not name or name.lower() in apps:
            continue
        core_flag = _truthy(row.get("core"))
        apps[name.lower()] = {
            "name": name,
            "label": _first_text(row, ("label", "display_name")) or name,
            "version": _first_text(row, ("version", "app_version")),
            "author": _first_text(row, ("author",)),
            "disabled": bool(_truthy(row.get("disabled"))),
            "visible": _truthy(row.get("visible")),
            "builtin": is_builtin_app(name, core_flag),
            "details_url": _first_text(row, ("details",)),
        }
        if len(apps) >= limit:
            break
    return sorted(apps.values(), key=lambda item: item["name"].lower())
