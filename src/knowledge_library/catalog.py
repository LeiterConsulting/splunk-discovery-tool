"""Map the environment profile to library sources: data source references, add-ons, and documentation."""

import fnmatch
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from knowledge_library.sources import (
    DOC_PRODUCTS,
    help_doc_url,
    security_content_file_url,
    splunkbase_app_url,
)

# (manual path, title, why it matters, server roles that make it relevant; None means always)
PLATFORM_MANUALS: List[Tuple[str, str, str, Optional[frozenset]]] = [
    ("search/spl-search-reference", "SPL Search Reference", "Syntax for every search command the assistant writes", None),
    ("search/search-manual", "Search Manual", "How searches run and how to make them efficient", None),
    ("manage-knowledge-objects/knowledge-management-manual", "Knowledge Manager Manual", "Fields, lookups, event types, tags, and data models", None),
    ("administer/admin-manual", "Admin Manual", "Configuration files and day-to-day administration", None),
    ("get-started/get-data-in", "Getting Data In", "Inputs, sourcetypes, and parsing", None),
    ("alert-and-respond/alerting-manual", "Alerting Manual", "Alerts, triggers, and actions", None),
    ("administer/troubleshoot", "Troubleshooting Manual", "Diagnosing platform problems", None),
    ("administer/monitor", "Monitoring", "The Monitoring Console and platform health", None),
    ("administer/manage-users-and-security", "Securing the Platform", "Roles, capabilities, and authentication", None),
    ("create-dashboards-and-reports/dashboard-studio", "Dashboard Studio", "Building dashboards", None),
    ("leverage-rest-apis/rest-api-reference", "REST API Reference", "REST endpoints behind the MCP tools", None),
    ("release-notes-and-updates/release-notes", "Release Notes", "Known issues and changes in this version", None),
    (
        "administer/manage-indexers-and-indexer-clusters", "Managing Indexers and Clusters", "Indexer and cluster operations",
        frozenset({"indexer", "cluster_master", "cluster_manager", "cluster_slave", "cluster_peer"}),
    ),
    (
        "administer/distributed-search", "Distributed Search", "Search heads, peers, and search head clusters",
        frozenset({"search_head", "shc_captain", "shc_member", "shc_deployer", "cluster_search_head"}),
    ),
    (
        "administer/update-your-deployment", "Updating Instances", "Deployment server and forwarder management",
        frozenset({"deployment_server"}),
    ),
    (
        "forward-and-process-data/forwarding-and-receiving-data", "Forwarding Data", "Forwarder to indexer data flow",
        frozenset({"indexer", "heavyweight_forwarder", "universal_forwarder"}),
    ),
]
# Installed app folder name -> manual path inside the platform documentation.
APP_MANUALS: Dict[str, Tuple[str, str]] = {
    "splunk_app_db_connect": ("connect-relational-databases/deploy-and-use-splunk-db-connect", "Splunk DB Connect"),
    "splunk_sa_cim": ("common-information-model", "Common Information Model"),
    "splunk_ml_toolkit": ("apply-machine-learning/use-ai-toolkit", "AI Toolkit"),
    "splunk_ai_toolkit": ("apply-machine-learning/use-ai-toolkit", "AI Toolkit"),
    "mltk-container": ("apply-machine-learning/use-splunk-app-for-data-science-and-deep-learning", "Splunk App for Data Science and Deep Learning"),
    "splunk_app_stream": ("collect-stream-data/install-and-configure-splunk-stream", "Splunk Stream"),
    "splunk_ta_stream": ("collect-stream-data/install-and-configure-splunk-stream", "Splunk Stream"),
    "infosec_app_for_splunk": ("infosec-app-for-splunk/use-infosec-app-for-splunk", "InfoSec App for Splunk"),
    "lookup_editor": ("manage-knowledge-objects/splunk-app-for-lookup-file-editing", "Splunk App for Lookup File Editing"),
    "splunk_mcp_server": ("mcp-server-for-splunk-platform", "Splunk MCP Server"),
}
# Installed app folder name -> documentation product of its own.
APP_PRODUCTS: Dict[str, str] = {
    "splunkenterprisesecuritysuite": "splunk-enterprise-security",
    "itsi": "splunk-it-service-intelligence",
    "sa-itoa": "splunk-it-service-intelligence",
}
ADDON_DOC_PRODUCT = "supported-add-ons"
ADDON_DOC_PREFIX = "splunk-supported-add-ons/"
_ADDON_NAME_NOISE = re.compile(r"\b(splunk|supported|add[- ]?on|addon|for|the|technology|ta|app)\b", re.I)
STATUS_RANK = {"current": 0, "installed": 1, "outdated": 2, "disabled": 3, "missing": 4, "unknown": 5}
MAX_LISTED_DATA_SOURCES = 5


def version_tuple(value: Any) -> Tuple[int, ...]:
    parts = [int(part) for part in re.findall(r"\d+", str(value or ""))]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def compare_versions(left: Any, right: Any) -> Optional[int]:
    a, b = version_tuple(left), version_tuple(right)
    if not a or not b:
        return None
    return (a > b) - (a < b)


def choose_doc_version(available: Iterable[str], wanted: str) -> Tuple[str, str]:
    """Pick the documentation version for a product version: exact, same major.minor, nearest lower, then nearest higher."""
    versions = sorted({version for version in available if version}, key=version_tuple)
    if not versions:
        return "", "none"
    target = version_tuple(wanted)
    if not target:
        return versions[-1], "latest"
    for version in versions:
        if version_tuple(version) == target:
            return version, "exact"
    same_line = [version for version in versions if version_tuple(version)[:2] == target[:2]]
    if same_line:
        return same_line[-1], "same_line"
    lower = [version for version in versions if version_tuple(version) < target]
    if lower:
        return lower[-1], "nearest_lower"
    return versions[0], "nearest_higher"


class DataSourceIndex:
    def __init__(self, data_sources: Iterable[Dict[str, Any]]):
        self.by_sourcetype: Dict[str, List[Dict[str, Any]]] = {}
        self.by_source: Dict[str, List[Dict[str, Any]]] = {}
        self.patterns: List[Tuple[str, Dict[str, Any]]] = []
        for entry in data_sources:
            sourcetype = str(entry.get("sourcetype") or "").strip().lower()
            source = str(entry.get("source") or "").strip().lower()
            if sourcetype:
                if "*" in sourcetype:
                    self.patterns.append((sourcetype, entry))
                else:
                    self.by_sourcetype.setdefault(sourcetype, []).append(entry)
            if source and "*" not in source:
                self.by_source.setdefault(source, []).append(entry)

    @staticmethod
    def _aliases(key: str) -> List[str]:
        # The Windows add-on writes WinEventLog or XmlWinEventLog depending on renderXml.
        aliases = [key]
        if key.startswith("wineventlog"):
            aliases.append("xml" + key)
        elif key.startswith("xmlwineventlog"):
            aliases.append(key[3:])
        return aliases

    def match(self, sourcetype: str) -> Tuple[List[Dict[str, Any]], str]:
        key = str(sourcetype or "").strip().lower()
        if not key:
            return [], ""
        for alias in self._aliases(key):
            if alias in self.by_sourcetype:
                return self.by_sourcetype[alias], "sourcetype"
        for alias in self._aliases(key):
            if alias in self.by_source:
                return self.by_source[alias], "source"
        hits = [entry for pattern, entry in self.patterns if fnmatch.fnmatchcase(key, pattern)]
        return (hits, "pattern") if hits else ([], "")


def _addon_tokens(name: str) -> List[str]:
    cleaned = _ADDON_NAME_NOISE.sub(" ", str(name or "").lower())
    return [token for token in re.split(r"[^a-z0-9]+", cleaned) if token]


def _addon_doc_index(docs: Optional[Dict[str, Any]]) -> Dict[str, str]:
    product = ((docs or {}).get("products") or {}).get(ADDON_DOC_PRODUCT) or {}
    index: Dict[str, str] = {}
    for manual in (product.get("manuals") or {}):
        if manual.startswith(ADDON_DOC_PREFIX):
            slug = manual[len(ADDON_DOC_PREFIX):]
            url = help_doc_url(ADDON_DOC_PRODUCT, manual)
            if slug and url:
                index[slug] = url
    return index


def match_addon_doc(names: Iterable[str], slugs: Dict[str, str]) -> Optional[Dict[str, str]]:
    best: Tuple[float, str] = (0.0, "")
    for name in names:
        tokens = _addon_tokens(name)
        if not tokens:
            continue
        exact = "-".join(tokens)
        if exact in slugs:
            return {"slug": exact, "url": slugs[exact]}
        token_set = set(tokens)
        for slug in slugs:
            slug_set = set(slug.split("-"))
            score = len(token_set & slug_set) / len(token_set | slug_set)
            if score > best[0]:
                best = (score, slug)
    if best[0] >= 0.6:
        return {"slug": best[1], "url": slugs[best[1]]}
    return None


def _manual_root_url(product: str, manual: str, version: str, bucket: Dict[str, Any]) -> str:
    pages = bucket.get("pages") or [""]
    return help_doc_url(product, manual, version, pages[0]) or help_doc_url(product, manual, version)


def _manual_entry(product: str, manual: str, versions: Dict[str, Any], wanted: str, title: str, reason: str) -> Optional[Dict[str, Any]]:
    version, match = choose_doc_version(versions.keys(), wanted)
    bucket = versions.get(version) or versions.get("")
    if not bucket:
        return None
    version = version if version in versions else ""
    url = _manual_root_url(product, manual, version, bucket)
    if not url:
        return None
    return {
        "entry_id": f"doc:{product}/{manual}/{version or 'current'}",
        "product": product,
        "manual": manual,
        "title": title,
        "reason": reason,
        "version": version,
        "version_match": match if version else "unversioned",
        "page_count": len(bucket.get("pages") or []),
        "lastmod": bucket.get("lastmod") or "",
        "url": url,
    }


def _find_manual(manuals: Dict[str, Any], path: str) -> Optional[str]:
    if path in manuals:
        return path
    leaf = path.rsplit("/", 1)[-1]
    return next((name for name in manuals if name.rsplit("/", 1)[-1] == leaf), None)


def select_platform_docs(profile: Dict[str, Any], docs: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    splunk = profile.get("splunk") or {}
    product = "splunk-cloud-platform" if splunk.get("deployment_type") == "cloud" else "splunk-enterprise"
    result: Dict[str, Any] = {
        "product": product,
        "product_title": DOC_PRODUCTS[product],
        "requested_version": splunk.get("version_line") or "",
        "manuals": [],
    }
    index = ((docs or {}).get("products") or {}).get(product)
    if not index:
        result["status"] = "needs_source"
        return result
    manuals = index.get("manuals") or {}
    anchor = _find_manual(manuals, "administer/admin-manual") or max(manuals, key=lambda name: sum(len(b.get("pages") or []) for b in manuals[name].values()), default=None)
    anchor_versions = list((manuals.get(anchor) or {}).keys()) if anchor else []
    doc_version, match = choose_doc_version(anchor_versions, result["requested_version"])
    result.update({
        "status": "ok",
        "doc_version": doc_version,
        "version_match": match,
        "available_versions": sorted({v for v in anchor_versions if v}, key=version_tuple, reverse=True)[:12],
    })
    roles = {str(role).lower() for role in splunk.get("server_roles") or []}
    for path, title, reason, relevant_roles in PLATFORM_MANUALS:
        if relevant_roles is not None and not (roles & relevant_roles):
            continue
        manual = _find_manual(manuals, path)
        if not manual:
            continue
        entry = _manual_entry(product, manual, manuals[manual], doc_version or result["requested_version"], title, reason)
        if entry:
            result["manuals"].append(entry)
    return result


def _app_product(app_name: str, version: str) -> Optional[str]:
    product = APP_PRODUCTS.get(app_name.lower())
    if product == "splunk-enterprise-security":
        major = version_tuple(version)[:1]
        return "splunk-enterprise-security-7" if major and major[0] < 8 else "splunk-enterprise-security-8"
    return product


def select_app_docs(profile: Dict[str, Any], docs: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    products = (docs or {}).get("products") or {}
    deployment = (profile.get("splunk") or {}).get("deployment_type")
    platform_order = ["splunk-cloud-platform", "splunk-enterprise"] if deployment == "cloud" else ["splunk-enterprise", "splunk-cloud-platform"]
    entries: List[Dict[str, Any]] = []
    seen = set()
    for app in (profile.get("apps") or {}).get("items") or []:
        name = str(app.get("name") or "")
        version = str(app.get("version") or "")
        key = name.lower()
        if key in APP_MANUALS:
            manual_path, title = APP_MANUALS[key]
            for product in platform_order:
                manuals = (products.get(product) or {}).get("manuals") or {}
                manual = _find_manual(manuals, manual_path)
                if manual and (product, manual) not in seen:
                    entry = _manual_entry(product, manual, manuals[manual], version, title, f"Installed app {app.get('label') or name}")
                    if entry:
                        seen.add((product, manual))
                        entries.append({**entry, "app": name})
                    break
        product = _app_product(key, version)
        if product and product in products and product not in seen:
            seen.add(product)
            manuals = products[product].get("manuals") or {}
            # A product also lists related apps with their own version numbers (for example the AI Toolkit under
            # Enterprise Security), so only manuals published for the installed app's documentation version count.
            doc_version, _match = choose_doc_version({v for versions in manuals.values() for v in versions if v}, version)
            matching = [(manual, versions) for manual, versions in manuals.items() if (doc_version or "") in versions]
            ranked = sorted(matching, key=lambda item: -len((item[1][doc_version or ""] or {}).get("pages") or []))[:6]
            for manual, versions in ranked:
                title = manual.rsplit("/", 1)[-1].replace("-", " ").capitalize()
                entry = _manual_entry(product, manual, versions, version, title, f"Installed app {app.get('label') or name}")
                if entry:
                    entries.append({**entry, "app": name})
    return entries


def _installed_maps(profile: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    items = (profile.get("apps") or {}).get("items") or []
    by_name = {str(app.get("name") or "").lower(): app for app in items if app.get("name")}
    by_label = {str(app.get("label") or "").lower(): app for app in items if app.get("label")}
    return by_name, by_label


def _latest_for(record: Optional[Dict[str, Any]], deployment_type: str) -> str:
    if not record:
        return ""
    if deployment_type == "cloud" and record.get("latest_cloud_version"):
        return str(record["latest_cloud_version"])
    return str(record.get("latest_version") or "")


def _app_status(app: Dict[str, Any], latest: str) -> str:
    if app.get("disabled"):
        return "disabled"
    comparison = compare_versions(app.get("version"), latest) if latest else None
    if comparison is None:
        return "installed"
    return "outdated" if comparison < 0 else "current"


def build_catalog(profile: Dict[str, Any], sources: Dict[str, Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    security_content = sources.get("security_content") or {}
    splunkbase = sources.get("splunkbase") or {}
    docs = sources.get("help_docs") or {}
    deployment_type = str((profile.get("splunk") or {}).get("deployment_type") or "")
    apps_collected = bool((profile.get("apps") or {}).get("collected"))
    installed_by_name, installed_by_label = _installed_maps(profile)
    splunkbase_apps: Dict[str, Dict[str, Any]] = splunkbase.get("apps") or {}
    splunkbase_by_uid = {record.get("uid"): record for record in splunkbase_apps.values() if record.get("uid")}
    not_found = {str(name).lower() for name in splunkbase.get("not_found") or []}
    ref = str(security_content.get("ref") or "")
    index = DataSourceIndex(security_content.get("data_sources") or [])
    addon_docs = _addon_doc_index(docs)

    def resolve_addon(ta: Dict[str, Any]) -> Dict[str, Any]:
        uid = ta.get("splunkbase_uid")
        record = splunkbase_by_uid.get(uid)
        app = installed_by_name.get(str(record.get("appid") or "").lower()) if record else None
        if app is None:
            app = installed_by_label.get(str(ta.get("name") or "").lower())
        if app is None and record:
            app = installed_by_label.get(str(record.get("title") or "").lower())
        latest = _latest_for(record, deployment_type)
        if not apps_collected:
            status = "unknown"
        elif app is None:
            status = "missing"
        else:
            status = _app_status(app, latest)
        doc = match_addon_doc([ta.get("name") or "", (record or {}).get("title") or ""], addon_docs)
        return {
            "name": ta.get("name") or (record or {}).get("title") or "",
            "splunkbase_uid": uid,
            "splunkbase_url": splunkbase_app_url(uid),
            "appid": (record or {}).get("appid") or "",
            "tested_version": ta.get("version") or "",
            "latest_version": latest,
            "installed_app": (app or {}).get("name") or "",
            "installed_version": (app or {}).get("version") or "",
            "status": status,
            "cloud_compatible": (record or {}).get("cloud_compatible"),
            "archived": bool((record or {}).get("archived")),
            "doc_url": (doc or {}).get("url") or "",
        }

    sourcetype_entries: List[Dict[str, Any]] = []
    app_supports: Dict[str, List[str]] = {}
    for row in profile.get("sourcetypes") or []:
        matches, how = index.match(row["name"])
        addons: Dict[Any, Dict[str, Any]] = {}
        for entry in matches:
            for ta in entry.get("supported_tas") or []:
                key = ta.get("splunkbase_uid") or str(ta.get("name") or "").lower()
                if key not in addons:
                    addons[key] = resolve_addon(ta)
        addon_list = sorted(addons.values(), key=lambda item: STATUS_RANK.get(item["status"], 9))
        for addon in addon_list:
            if addon["installed_app"]:
                app_supports.setdefault(addon["installed_app"].lower(), []).append(row["name"])
        sourcetype_entries.append({
            "entry_id": f"sourcetype:{row['name']}",
            "name": row["name"],
            "events": row.get("events"),
            "last_seen_utc": row.get("last_seen_utc"),
            "match": how,
            "data_source_count": len(matches),
            "data_sources": [
                {"name": entry["name"], "id": entry.get("id") or "", "url": security_content_file_url(ref, entry.get("file") or "")}
                for entry in matches[:MAX_LISTED_DATA_SOURCES]
            ],
            "fields_count": max((int(entry.get("fields_count") or 0) for entry in matches), default=0),
            "add_ons": addon_list,
            "addon_status": addon_list[0]["status"] if addon_list else "",
        })

    app_entries: List[Dict[str, Any]] = []
    for app in (profile.get("apps") or {}).get("items") or []:
        name = str(app.get("name") or "")
        record = splunkbase_apps.get(name.lower())
        latest = _latest_for(record, deployment_type)
        if app.get("builtin"):
            status = "builtin"
        elif record is None:
            status = "not_on_splunkbase" if name.lower() in not_found else "unknown"
        else:
            status = _app_status(app, latest)
        doc = match_addon_doc([app.get("label") or "", (record or {}).get("title") or ""], addon_docs) if not app.get("builtin") else None
        app_entries.append({
            "entry_id": f"app:{name}",
            "name": name,
            "label": app.get("label") or name,
            "version": app.get("version") or "",
            "disabled": bool(app.get("disabled")),
            "builtin": bool(app.get("builtin")),
            "status": status,
            "latest_version": latest,
            "splunkbase_uid": (record or {}).get("uid"),
            "splunkbase_url": splunkbase_app_url((record or {}).get("uid")),
            "splunkbase_title": (record or {}).get("title") or "",
            "type": (record or {}).get("type") or "",
            "cloud_compatible": (record or {}).get("cloud_compatible"),
            "fedramp_validation": (record or {}).get("fedramp_validation") or "",
            "archived": bool((record or {}).get("archived")),
            "doc_url": (doc or {}).get("url") or "",
            "supports_sourcetypes": app_supports.get(name.lower(), [])[:20],
        })

    return {
        "sourcetypes": sourcetype_entries,
        "apps": app_entries,
        "platform_docs": select_platform_docs(profile, docs),
        "app_docs": select_app_docs(profile, docs),
        "pending_splunkbase_lookups": sorted(
            app["name"] for app in (profile.get("apps") or {}).get("items") or []
            if not app.get("builtin") and app["name"].lower() not in splunkbase_apps and app["name"].lower() not in not_found
        ),
        "splunkbase_uids": sorted({
            ta.get("splunkbase_uid")
            for entry in security_content.get("data_sources") or []
            for ta in entry.get("supported_tas") or []
            if ta.get("splunkbase_uid")
        }),
    }
