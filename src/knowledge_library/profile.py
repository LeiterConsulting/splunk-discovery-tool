"""Build the environment profile the knowledge library maps to sources, from a discovery blueprint."""

from typing import Any, Dict, List, Optional

from discovery.environment_profile import (
    CLOUD_VERSION_PATTERN,
    normalize_installed_app_rows,
    splunk_version_line,
)


def _safe_int(value: Any) -> Optional[int]:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _sourcetypes_from_ledger(blueprint: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for entry in blueprint.get("finding_ledger") or []:
        if not isinstance(entry, dict) or entry.get("kind") != "sourcetype":
            continue
        data = entry.get("data") if isinstance(entry.get("data"), dict) else {}
        name = str(data.get("sourcetype") or data.get("name") or "").strip()
        if name:
            rows.append({"name": name, "events": _safe_int(data.get("totalCount")), "last_seen_utc": None})
    return rows


def build_environment_profile(blueprint: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(blueprint, dict):
        return {"available": False, "reason": "no_discovery"}
    overview = blueprint.get("overview") if isinstance(blueprint.get("overview"), dict) else {}
    env = blueprint.get("environment_profile") if isinstance(blueprint.get("environment_profile"), dict) else {}
    inventory = blueprint.get("discovered_inventory") if isinstance(blueprint.get("discovered_inventory"), dict) else {}
    if not (overview or env or inventory or blueprint.get("finding_ledger")):
        return {"available": False, "reason": "empty_discovery"}

    version = str(env.get("splunk_version") or overview.get("splunk_version") or "").strip()
    if version.lower() == "unknown":
        version = ""
    deployment_type = str(env.get("deployment_type") or overview.get("deployment_type") or "").strip().lower()
    deployment_basis = str(env.get("deployment_basis") or "")
    if deployment_type not in {"cloud", "enterprise"}:
        if CLOUD_VERSION_PATTERN.match(version):
            deployment_type, deployment_basis = "cloud", "The version number uses Splunk Cloud Platform release numbering"
        elif version:
            deployment_type = "enterprise"
            deployment_basis = deployment_basis or "Assumed from the version number; run discovery again to confirm"
        else:
            deployment_type = "unknown"
    roles = env.get("server_roles") if isinstance(env.get("server_roles"), list) else overview.get("server_roles")
    roles = [str(role) for role in roles] if isinstance(roles, list) else []

    apps_block = env.get("installed_apps") if isinstance(env.get("installed_apps"), dict) else None
    if apps_block is None:
        apps = {"collected": False, "status": "not_collected", "error": "", "items": []}
    else:
        status = str(apps_block.get("status") or "")
        apps = {
            "collected": status == "ok",
            "status": status or "not_collected",
            "error": str(apps_block.get("error") or "")[:300],
            "fallback": str(apps_block.get("fallback") or ""),
            "items": normalize_installed_app_rows(apps_block.get("items") or []),
        }

    sourcetypes: List[Dict[str, Any]] = []
    for row in env.get("sourcetypes") or []:
        if isinstance(row, dict) and str(row.get("name") or "").strip():
            sourcetypes.append({
                "name": str(row["name"]).strip(),
                "events": _safe_int(row.get("events")),
                "last_seen_utc": row.get("last_seen_utc"),
            })
    if not sourcetypes:
        sourcetypes = _sourcetypes_from_ledger(blueprint)
    if not sourcetypes:
        sourcetypes = [{"name": str(name), "events": None, "last_seen_utc": None} for name in inventory.get("sourcetypes") or [] if str(name or "").strip()]
    unique: Dict[str, Dict[str, Any]] = {}
    for row in sourcetypes:
        unique.setdefault(row["name"].lower(), row)
    sourcetypes = sorted(unique.values(), key=lambda row: (row["events"] is None, -(row["events"] or 0), row["name"].lower()))

    artifact = blueprint.get("_artifact") if isinstance(blueprint.get("_artifact"), dict) else {}
    return {
        "available": True,
        "discovery": {
            "artifact": str(artifact.get("name") or ""),
            "generated_at": str(blueprint.get("generated_at") or artifact.get("modified") or ""),
            "has_environment_profile": bool(env),
        },
        "splunk": {
            "version": version,
            "version_line": splunk_version_line(version),
            "build": str(env.get("splunk_build") or overview.get("splunk_build") or ""),
            "deployment_type": deployment_type,
            "deployment_basis": deployment_basis,
            "server_roles": roles,
        },
        "apps": apps,
        "sourcetypes": sourcetypes,
        "indexes": [str(name) for name in inventory.get("indexes") or []],
    }
