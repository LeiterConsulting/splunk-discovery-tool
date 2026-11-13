"""Score how well the library covers the discovered environment and list the gaps worth fixing."""

import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from knowledge_library.sources import SOURCE_TITLES, parse_iso

TOP_SOURCETYPES = 25
TOP_GAP_SOURCETYPES = 10
STALE_SOURCE_DAYS = 30
INTERNAL_SOURCETYPE_PREFIXES = ("splunk", "mongod", "kvstore", "django", "stash")
INTERNAL_SOURCETYPES = frozenset({"scheduler", "audittrail", "searches", "conf", "first_install", "http_event_collector_metrics"})
PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}
INSTALLED_STATUSES = {"current", "installed", "outdated"}
DOC_MATCH_SCORES = {"exact": 100, "same_line": 100, "unversioned": 100, "nearest_lower": 70, "nearest_higher": 50, "latest": 50}


def is_internal_sourcetype(name: str) -> bool:
    lowered = str(name or "").strip().lower()
    return (
        lowered in INTERNAL_SOURCETYPES
        or lowered.startswith(INTERNAL_SOURCETYPE_PREFIXES)
        or lowered.endswith("-too_small")
    )


def _pct(covered: float, total: float) -> Optional[int]:
    return int(round(100 * covered / total)) if total else None


def _fmt_count(value: Optional[int]) -> str:
    return f"{value:,}" if isinstance(value, int) else "unknown"


def _dimension(key: str, label: str, score: Optional[int], status: str, basis: str, covered: int = 0, total: int = 0) -> Dict[str, Any]:
    return {"key": key, "label": label, "score": score, "status": status, "basis": basis, "covered": covered, "total": total}


def _asset_text(asset: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in ("title", "description", "summary", "source_label", "preview"):
        value = asset.get(key)
        if isinstance(value, str):
            parts.append(value)
    for key in ("tags", "focus_terms", "headings", "key_points"):
        value = asset.get(key)
        if isinstance(value, list):
            parts.extend(str(item) for item in value if isinstance(item, (str, int, float)))
    attributes = asset.get("attributes")
    if isinstance(attributes, dict):
        parts.extend(str(value) for value in attributes.values() if isinstance(value, (str, int, float)))
    return "\n".join(parts).lower()


class KnowledgeBaseMatcher:
    def __init__(self, assets: Iterable[Dict[str, Any]]):
        self.texts: List[str] = []
        self.entry_ids = set()
        for asset in assets:
            if not isinstance(asset, dict) or asset.get("library_status") == "checked_out":
                continue
            self.texts.append(_asset_text(asset))
            attributes = asset.get("attributes") if isinstance(asset.get("attributes"), dict) else {}
            ids = attributes.get("library_entry_ids")
            if isinstance(ids, list):
                self.entry_ids.update(str(item) for item in ids)

    def covers(self, entry_id: str, *terms: str) -> bool:
        if entry_id in self.entry_ids:
            return True
        for term in terms:
            cleaned = str(term or "").strip().lower()
            if len(cleaned) < 3:
                continue
            pattern = re.compile(r"(?<![\w])" + re.escape(cleaned) + r"(?![\w])")
            if any(pattern.search(text) for text in self.texts):
                return True
        return False


def _gap(gap_id: str, priority: str, category: str, title: str, detail: str, action: str, **extra: Any) -> Dict[str, Any]:
    return {"id": gap_id, "priority": priority, "category": category, "title": title, "detail": detail, "action": action, **extra}


def _list_names(names: List[str], limit: int = 3) -> str:
    shown = ", ".join(names[:limit])
    return f"{shown} and {len(names) - limit} more" if len(names) > limit else shown


def build_scorecard(
    profile: Dict[str, Any],
    catalog: Optional[Dict[str, Any]],
    kb_assets: Optional[List[Dict[str, Any]]],
    sources_summary: Dict[str, Dict[str, Any]],
    now: Optional[datetime] = None,
    doc_text: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    gaps: List[Dict[str, Any]] = []
    dimensions: List[Dict[str, Any]] = []
    loaded = {name for name, entry in sources_summary.items() if entry.get("available")}

    if not loaded:
        gaps.append(_gap(
            "sources_missing", "high", "sources", "Library sources are not loaded",
            "The library needs at least one source to map your environment to documentation and add-ons.",
            "Turn on online library sources and select Refresh sources, or import a library pack.",
        ))
    else:
        for name, entry in sources_summary.items():
            if not entry.get("available"):
                gaps.append(_gap(
                    f"source_missing:{name}", "medium", "sources", f"{SOURCE_TITLES[name]} is not loaded",
                    "Scores that depend on this source are not calculated.",
                    "Select Refresh sources, or import a library pack that includes it.",
                ))
                continue
            fetched = parse_iso(entry.get("fetched_at"))
            if fetched is not None:
                age_days = (now - fetched).days
                if age_days > STALE_SOURCE_DAYS:
                    gaps.append(_gap(
                        f"source_stale:{name}", "low", "sources", f"{SOURCE_TITLES[name]} is {age_days} days old",
                        "New add-on releases and documentation changes since then are not reflected.",
                        "Select Refresh sources, or import a newer library pack.",
                    ))

    if not profile.get("available"):
        gaps.insert(0, _gap(
            "no_discovery", "high", "environment", "No discovery results yet",
            "The library maps documentation to what discovery finds in your Splunk environment.",
            "Run discovery, then come back to this page.",
        ))
        return {"overall_score": None, "dimensions": [], "gaps": gaps, "gap_counts": _gap_counts(gaps)}

    splunk = profile.get("splunk") or {}
    apps = profile.get("apps") or {}
    sourcetypes = profile.get("sourcetypes") or []

    # Environment facts
    facts = {
        "version": bool(splunk.get("version")),
        "deployment type": splunk.get("deployment_type") in {"cloud", "enterprise"},
        "installed apps": bool(apps.get("collected")),
        "sourcetypes": bool(sourcetypes),
    }
    missing_facts = [name for name, ok in facts.items() if not ok]
    deployment_label = {"cloud": "Splunk Cloud Platform", "enterprise": "Splunk Enterprise"}.get(splunk.get("deployment_type"), "unknown deployment")
    dimensions.append(_dimension(
        "environment", "Environment facts", 25 * sum(facts.values()), "ok",
        f"{deployment_label} {splunk.get('version') or ''}".strip()
        + f", {len(apps.get('items') or [])} apps, {len(sourcetypes)} sourcetypes"
        + (f". Missing: {', '.join(missing_facts)}." if missing_facts else "."),
        sum(facts.values()), len(facts),
    ))
    if not apps.get("collected"):
        if not (profile.get("discovery") or {}).get("has_environment_profile") or apps.get("status") == "not_collected":
            gaps.append(_gap(
                "apps_not_collected", "high", "environment", "Run discovery again to record installed apps",
                "The latest discovery ran before this version of the app collected installed apps and add-ons.",
                "Run discovery. Add-on checks and app documentation start working after that run.",
            ))
        else:
            gaps.append(_gap(
                "apps_failed", "high", "environment", "Installed apps could not be collected",
                apps.get("error") or "The MCP server did not return the app list.",
                "Give the MCP account permission to list apps (the apps knowledge object type or the rest search command), then run discovery again.",
            ))

    catalog = catalog or {}
    st_entries = catalog.get("sourcetypes") or []
    external = [entry for entry in st_entries if not is_internal_sourcetype(entry["name"])]
    ranked = sorted(external, key=lambda entry: -(entry.get("events") or 0))
    top_names = {entry["name"] for entry in ranked[:TOP_GAP_SOURCETYPES]}

    # Reference coverage
    if "security_content" not in loaded:
        dimensions.append(_dimension("reference_coverage", "Data source references", None, "needs_sources", "Load the Security Content source to score this."))
    elif not external:
        dimensions.append(_dimension("reference_coverage", "Data source references", None, "not_applicable", "Discovery found no customer sourcetypes."))
    else:
        matched = [entry for entry in external if entry.get("match")]
        total_events = sum(entry.get("events") or 0 for entry in external)
        matched_events = sum(entry.get("events") or 0 for entry in matched)
        score = _pct(matched_events, total_events) if total_events else _pct(len(matched), len(external))
        basis = f"{len(matched)} of {len(external)} sourcetypes have a public data source definition"
        if total_events:
            basis += f" ({_pct(matched_events, total_events)}% of events)"
        dimensions.append(_dimension("reference_coverage", "Data source references", score, "ok", basis + ". Splunk internal sourcetypes are not counted.", len(matched), len(external)))
        unmatched = [entry for entry in ranked if not entry.get("match")]
        for entry in unmatched[:TOP_GAP_SOURCETYPES]:
            gaps.append(_gap(
                f"no_reference:{entry['name']}", "medium" if entry["name"] in top_names else "low", "references",
                f"No public reference for sourcetype {entry['name']}",
                f"{_fmt_count(entry.get('events'))} events in the last 24 hours. Neither Splunk Security Content nor Splunkbase describes this data, so the assistant has only your own notes to go on.",
                "Add a Knowledge Base item that explains what produces this data, its key fields, and useful searches.",
                target=entry["name"], events=entry.get("events"),
            ))
        if len(unmatched) > TOP_GAP_SOURCETYPES:
            rest = unmatched[TOP_GAP_SOURCETYPES:]
            gaps.append(_gap(
                "no_reference:more", "low", "references", f"{len(rest)} more sourcetypes have no public reference",
                f"For example {_list_names([entry['name'] for entry in rest])}.",
                "Document the ones your team searches most.",
            ))

    # Add-on coverage
    with_addons = [entry for entry in external if entry.get("add_ons")]
    if "security_content" not in loaded:
        dimensions.append(_dimension("addon_coverage", "Add-ons for your data", None, "needs_sources", "Load the Security Content source to score this."))
    elif not apps.get("collected"):
        dimensions.append(_dimension("addon_coverage", "Add-ons for your data", None, "needs_discovery", "Run discovery again so the installed apps are known."))
    elif not with_addons:
        dimensions.append(_dimension("addon_coverage", "Add-ons for your data", None, "not_applicable", "None of your sourcetypes list a supporting add-on."))
    else:
        installed = [entry for entry in with_addons if entry.get("addon_status") in INSTALLED_STATUSES]
        dimensions.append(_dimension(
            "addon_coverage", "Add-ons for your data", _pct(len(installed), len(with_addons)), "ok",
            f"{len(installed)} of {len(with_addons)} sourcetypes with a known add-on have it installed on the search head this app connects to.",
            len(installed), len(with_addons),
        ))
        missing: Dict[str, Dict[str, Any]] = {}
        for entry in with_addons:
            if entry.get("addon_status") not in {"missing", "disabled"}:
                continue
            addon = entry["add_ons"][0]
            bucket = missing.setdefault(addon["name"], {"addon": addon, "sourcetypes": [], "events": 0, "top": False, "status": entry["addon_status"]})
            bucket["sourcetypes"].append(entry["name"])
            bucket["events"] += entry.get("events") or 0
            bucket["top"] = bucket["top"] or entry["name"] in top_names
        for name, bucket in sorted(missing.items(), key=lambda item: -item[1]["events"]):
            addon = bucket["addon"]
            version = addon.get("latest_version") or addon.get("tested_version")
            if bucket["status"] == "disabled":
                title = f"Turn on {name}"
                action = f"Enable the {addon.get('installed_app') or name} app on the search head."
            else:
                title = f"Install {name} on the search head"
                action = f"Install {name}{f' {version}' if version else ''} from Splunkbase."
            gaps.append(_gap(
                f"addon_missing:{name}", "high" if bucket["top"] else "medium", "add-ons", title,
                f"{len(bucket['sourcetypes'])} sourcetype{'s depend' if len(bucket['sourcetypes']) != 1 else ' depends'} on it "
                f"({_list_names(bucket['sourcetypes'])}, {bucket['events']:,} events in the last 24 hours). "
                "Without it, search-time field extractions and CIM mappings for this data are missing.",
                action, target=name, url=addon.get("splunkbase_url") or "", events=bucket["events"],
            ))

    # Add-on currency
    app_entries = [entry for entry in catalog.get("apps") or [] if not entry.get("builtin")]
    if "splunkbase" not in loaded:
        dimensions.append(_dimension("addon_currency", "App versions", None, "needs_sources", "Load the Splunkbase source to score this."))
    elif not apps.get("collected"):
        dimensions.append(_dimension("addon_currency", "App versions", None, "needs_discovery", "Run discovery again so the installed apps are known."))
    else:
        comparable = [entry for entry in app_entries if entry["status"] in {"current", "outdated"}]
        current = [entry for entry in comparable if entry["status"] == "current"]
        if comparable:
            dimensions.append(_dimension(
                "addon_currency", "App versions", _pct(len(current), len(comparable)), "ok",
                f"{len(current)} of {len(comparable)} Splunkbase apps are on the latest release.",
                len(current), len(comparable),
            ))
        else:
            dimensions.append(_dimension("addon_currency", "App versions", None, "not_applicable", "No installed apps could be compared with Splunkbase releases."))
        for entry in sorted(comparable, key=lambda item: (not item["supports_sourcetypes"], item["label"].lower())):
            if entry["status"] != "outdated":
                continue
            gaps.append(_gap(
                f"addon_outdated:{entry['name']}", "medium" if entry["supports_sourcetypes"] else "low", "add-ons",
                f"Update {entry['label']} from {entry['version']} to {entry['latest_version']}",
                (f"It supports {_list_names(entry['supports_sourcetypes'])}. " if entry["supports_sourcetypes"] else "")
                + "Newer releases can change field extractions, so read the release notes first.",
                "Test the update outside production, then upgrade.",
                target=entry["name"], url=entry.get("splunkbase_url") or "",
            ))
        for entry in app_entries:
            if entry.get("archived"):
                gaps.append(_gap(
                    f"app_archived:{entry['name']}", "medium", "add-ons", f"{entry['label']} is archived on Splunkbase",
                    "Archived apps no longer get fixes or compatibility updates.",
                    "Plan a replacement or confirm the app is still needed.",
                    target=entry["name"], url=entry.get("splunkbase_url") or "",
                ))
            if splunk.get("deployment_type") == "cloud" and entry.get("cloud_compatible") is False and not entry.get("disabled"):
                gaps.append(_gap(
                    f"app_not_cloud:{entry['name']}", "medium", "add-ons", f"{entry['label']} is not marked Cloud compatible",
                    "Splunkbase does not list this app as compatible with Splunk Cloud Platform.",
                    "Confirm with the app owner or Splunk support that this version is supported in your stack.",
                    target=entry["name"], url=entry.get("splunkbase_url") or "",
                ))
        pending = catalog.get("pending_splunkbase_lookups") or []
        if pending:
            gaps.append(_gap(
                "splunkbase_pending", "low", "sources", f"{len(pending)} installed apps have not been checked on Splunkbase",
                f"For example {_list_names(pending)}.",
                "Select Refresh sources to look them up.",
            ))

    # Documentation
    docs = catalog.get("platform_docs") or {}
    if "help_docs" not in loaded or docs.get("status") == "needs_source":
        dimensions.append(_dimension("documentation", "Documentation for your version", None, "needs_sources", "Load the help.splunk.com source to score this."))
    else:
        manuals = docs.get("manuals") or []
        match = docs.get("version_match") or "none"
        score = DOC_MATCH_SCORES.get(match, 0) if manuals else 0
        pages = sum(entry.get("page_count") or 0 for entry in manuals)
        dimensions.append(_dimension(
            "documentation", "Documentation for your version", score, "ok",
            f"{docs.get('product_title')} {docs.get('doc_version') or ''}: {len(manuals)} relevant manuals, {pages:,} pages.".replace("  ", " "),
            len(manuals), len(manuals),
        ))
        if manuals and match in {"nearest_lower", "nearest_higher"}:
            gaps.append(_gap(
                "docs_version", "medium", "documentation",
                f"help.splunk.com does not list version {docs.get('requested_version')}",
                f"The library uses {docs.get('doc_version')}, the closest version it has. Some steps or settings can differ.",
                "Confirm details against your version, or plan an upgrade to a version Splunk still documents.",
            ))

    # Downloaded documentation text
    if doc_text is not None:
        coverage = doc_text.get("coverage") or {}
        planned = int(coverage.get("planned_pages") or 0)
        downloaded = int(coverage.get("downloaded_pages") or 0)
        if "help_docs" not in loaded or doc_text.get("plan_status") == "needs_source":
            dimensions.append(_dimension("doc_text", "Searchable documentation", None, "needs_sources", "Load the help.splunk.com source to plan which manuals to download."))
        elif not planned:
            dimensions.append(_dimension("doc_text", "Searchable documentation", None, "not_applicable", "No manuals on help.splunk.com match this environment."))
        else:
            dimensions.append(_dimension(
                "doc_text", "Searchable documentation", coverage.get("pct") or 0, "ok",
                f"{downloaded:,} of {planned:,} pages from {coverage.get('planned_manuals') or 0} manuals for your environment are downloaded for chat to search.",
                downloaded, planned,
            ))
            if not downloaded:
                gaps.append(_gap(
                    "docs_not_downloaded", "medium", "documentation", "Splunk documentation text is not downloaded",
                    f"Chat can search {planned:,} pages from the manuals for your version and installed apps once they are downloaded.",
                    "Turn on online library sources and select Download documentation, or import a library pack that includes documentation.",
                ))
            else:
                missing_manuals = int(coverage.get("missing_manuals") or 0)
                outdated_manuals = int(coverage.get("outdated_manuals") or 0)
                if missing_manuals:
                    gaps.append(_gap(
                        "docs_missing", "low", "documentation",
                        f"{missing_manuals} manual{'s are' if missing_manuals != 1 else ' is'} not downloaded yet",
                        "They match your environment, but chat cannot search them until they are downloaded.",
                        "Select Download documentation, or import a newer library pack.",
                    ))
                if outdated_manuals:
                    gaps.append(_gap(
                        "docs_outdated", "low", "documentation",
                        f"{outdated_manuals} downloaded manual{'s have' if outdated_manuals != 1 else ' has'} changes or missing pages",
                        "help.splunk.com updated them after the download, or some pages could not be downloaded.",
                        "Select Download documentation to download them again.",
                    ))

    # Knowledge Base coverage
    if kb_assets is None:
        dimensions.append(_dimension("knowledge_base", "Knowledge Base coverage", None, "unavailable", "The Knowledge Base is not available on this server."))
    else:
        matcher = KnowledgeBaseMatcher(kb_assets)
        targets = [(entry["entry_id"], entry["name"], (entry["name"],)) for entry in ranked[:TOP_SOURCETYPES]]
        targets += [
            (entry["entry_id"], entry["label"], (entry["name"], entry["label"]))
            for entry in app_entries if not entry.get("disabled")
        ]
        if not targets:
            dimensions.append(_dimension("knowledge_base", "Knowledge Base coverage", None, "not_applicable", "There is nothing to compare yet."))
        else:
            uncovered = [label for entry_id, label, terms in targets if not matcher.covers(entry_id, *terms)]
            covered = len(targets) - len(uncovered)
            dimensions.append(_dimension(
                "knowledge_base", "Knowledge Base coverage", _pct(covered, len(targets)), "ok",
                f"{covered} of {len(targets)} top sourcetypes and installed add-ons are described in imported Knowledge Base items.",
                covered, len(targets),
            ))
            if uncovered:
                gaps.append(_gap(
                    "kb_uncovered", "low", "knowledge base",
                    f"{len(uncovered)} top sourcetypes and add-ons have no Knowledge Base items",
                    f"Start with {_list_names(uncovered, 5)}.",
                    "Import notes, runbooks, or vendor documentation for them so chat answers use them.",
                ))

    scored = [entry["score"] for entry in dimensions if isinstance(entry.get("score"), int)]
    gaps.sort(key=lambda gap: (PRIORITY_ORDER.get(gap["priority"], 9), -(gap.get("events") or 0)))
    # Without any source, only the environment facts and Knowledge Base dimensions can score, and their
    # average says nothing about library coverage.
    return {
        "overall_score": int(round(sum(scored) / len(scored))) if scored and loaded else None,
        "dimensions": dimensions,
        "gaps": gaps,
        "gap_counts": _gap_counts(gaps),
    }


def _gap_counts(gaps: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0}
    for gap in gaps:
        counts[gap["priority"]] = counts.get(gap["priority"], 0) + 1
    return counts
