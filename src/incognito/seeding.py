"""Collect a deployment's own names from a discovery blueprint so they are masked everywhere."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple

from .masker import spl_field_values
from .vocabulary import is_shipped_content_app

SAVED_SEARCH_TYPES = frozenset({"saved_searches", "savedsearches", "alerts", "reports"})
_NAMESPACES = ("host", "index", "user", "email", "app", "search", "object", "kv", "role")


def _strings(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable) and not isinstance(value, (bytes, Mapping)):
        return [item for item in value if isinstance(item, str)]
    return []


def _split_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.replace(";", ",").split(",") if part.strip()]
    return _strings(value)


def inventory_from_blueprint(blueprint: Any) -> Dict[str, List[str]]:
    """Names by kind (host, index, user, ...) found in a v2 intelligence blueprint.

    Sourcetypes, sources, and Splunk's own apps are left out: sourcetypes and shipped content
    stay visible, and source paths are masked piece by piece where they mention known names.
    """
    found: Dict[str, List[str]] = {namespace: [] for namespace in _NAMESPACES}
    if not isinstance(blueprint, Mapping):
        return found

    def add(namespace: str, values: Any) -> None:
        found[namespace].extend(value for value in _strings(values) if value.strip())

    inventory = blueprint.get("discovered_inventory")
    if isinstance(inventory, Mapping):
        add("host", inventory.get("hosts"))
        add("index", inventory.get("indexes"))
        add("kv", inventory.get("kv_collections"))

    for item in blueprint.get("finding_ledger") or ():
        if not isinstance(item, Mapping) or not isinstance(item.get("data"), Mapping):
            continue
        kind = str(item.get("kind") or "")
        data = item["data"]
        if kind == "host":
            add("host", data.get("host"))
        elif kind == "index":
            add("index", data.get("name") or data.get("title"))
        elif kind == "index_detail":
            add("index", data.get("name"))
            add("index", data.get("title"))
            add("host", data.get("splunk_server"))
        elif kind == "user":
            add("user", data.get("username") or data.get("name") or data.get("title"))
            add("user", data.get("realname"))
            add("email", data.get("email"))
            add("role", _split_list(data.get("roles")))
            add("app", data.get("defaultApp"))
        elif kind == "knowledge_object":
            app = str(data.get("app") or data.get("eai:acl.app") or data.get("eai:appName") or "")
            add("app", app)
            if app and is_shipped_content_app(app):
                continue
            ko_type = str(data.get("ko_type") or "").lower()
            add("search" if ko_type in SAVED_SEARCH_TYPES else "object", data.get("name") or data.get("title"))
            # Saved searches and macros often name specific hosts, users, and indexes in their SPL.
            spl = data.get("search") or data.get("qualifiedSearch") or data.get("definition")
            for namespace, value in spl_field_values(spl):
                namespace = "host" if namespace == "ip_or_host" else namespace
                if namespace in found:
                    add(namespace, value)
        elif kind == "kv_collection":
            add("kv", data.get("collection") or data.get("name") or data.get("title"))

    profile = blueprint.get("environment_profile")
    installed = profile.get("installed_apps") if isinstance(profile, Mapping) else None
    for app in (installed.get("items") if isinstance(installed, Mapping) else None) or ():
        if not isinstance(app, Mapping) or app.get("builtin") is True:
            continue
        name = str(app.get("name") or "")
        if not name or is_shipped_content_app(name):
            continue
        add("app", name)
        add("app", app.get("label"))

    overview = blueprint.get("overview")
    if isinstance(overview, Mapping):
        add("user", overview.get("authenticated_user"))
        add("role", _split_list(overview.get("authenticated_user_roles")))

    return {namespace: list(dict.fromkeys(values)) for namespace, values in found.items()}


BLUEPRINT_GLOB = "v2_intelligence_blueprint_*.json"
BLUEPRINTS_PER_FOLDER = 20


def blueprint_files(output_root: Path) -> List[Path]:
    """Recent discovery blueprints in the output folder and each scoped subfolder, newest first."""
    root = Path(output_root)
    folders = [root]
    scopes = root / "scopes"
    if scopes.is_dir():
        folders.extend(sorted(path for path in scopes.iterdir() if path.is_dir()))
    found: List[Tuple[float, Path]] = []
    for folder in folders:
        dated: List[Tuple[float, Path]] = []
        for path in folder.glob(BLUEPRINT_GLOB):
            try:
                dated.append((path.stat().st_mtime, path))
            except OSError:
                continue
        dated.sort(reverse=True)
        found.extend(dated[:BLUEPRINTS_PER_FOLDER])
    return [path for _mtime, path in sorted(found, reverse=True)]


def seed_from_outputs(masker: Any, output_root: Path) -> int:
    """Register names from discovery blueprints with a masker's vault, once per set of files.

    The set of files already used is kept in the vault, so other processes sharing it (and a
    fresh mapping after stand-ins are rotated) know whether seeding is still needed.
    """
    files = blueprint_files(output_root)
    signature = []
    for path in files:
        try:
            stat = path.stat()
        except OSError:
            continue
        signature.append([path.name, path.parent.name, stat.st_mtime_ns, stat.st_size])
    vault = masker.vault
    if vault.get_meta("seeded_from") == signature:
        return 0
    total = 0
    for path in files:
        try:
            blueprint = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        total += masker.seed(inventory_from_blueprint(blueprint))
    vault.set_meta("seeded_from", signature)
    return total
