"""Managed knowledge-asset storage for RAG import and context building."""

import hashlib
from io import BytesIO
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


SUPPORTED_KNOWLEDGE_ASSET_TYPES = {
    "spl_query_library",
    "splunk_documentation",
    "monitored_system_context",
    "connected_system_context",
    "integration_context",
    "runbook_context",
    "reference_document",
}

SUPPORTED_KNOWLEDGE_LIBRARY_STATUSES = {
    "checked_in",
    "checked_out",
}

SUPPORTED_IMPORT_SUFFIXES = {".md", ".txt", ".json", ".log", ".csv", ".pdf", ".docx"}

FOCUS_TERM_STOPWORDS = {
    "and",
    "about",
    "after",
    "are",
    "also",
    "before",
    "because",
    "between",
    "build",
    "can",
    "context",
    "document",
    "even",
    "from",
    "have",
    "into",
    "just",
    "knowledge",
    "must",
    "need",
    "note",
    "notes",
    "only",
    "other",
    "same",
    "should",
    "that",
    "the",
    "their",
    "them",
    "these",
    "this",
    "through",
    "used",
    "using",
    "what",
    "when",
    "with",
    "your",
}

ASSET_TYPE_USAGE_HINTS = {
    "spl_query_library": [
        "Use when the operator needs a saved SPL starting point that can be run in Splunk Web, reused in chat, or refined later.",
    ],
    "splunk_documentation": [
        "Use for Splunk product behavior, configuration expectations, and platform limits.",
    ],
    "monitored_system_context": [
        "Use when the question depends on the role, behavior, or risks of a monitored system.",
    ],
    "connected_system_context": [
        "Use when upstream, downstream, or dependency context matters to the answer.",
    ],
    "integration_context": [
        "Use for interface, dependency, and data-flow questions involving connected services.",
    ],
    "runbook_context": [
        "Use for procedure, triage, escalation, and operator handoff questions.",
    ],
    "reference_document": [
        "Use as supporting reference context when no more specific asset type applies.",
    ],
}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_whitespace(text: Any) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def normalize_knowledge_asset_type(value: Any) -> str:
    candidate = re.sub(r"[^a-z0-9_]+", "_", str(value or "").strip().lower()).strip("_")
    if candidate in SUPPORTED_KNOWLEDGE_ASSET_TYPES:
        return candidate
    return "reference_document"


def normalize_knowledge_asset_library_status(value: Any) -> str:
    candidate = re.sub(r"[^a-z0-9_]+", "_", str(value or "").strip().lower()).strip("_")
    if candidate in SUPPORTED_KNOWLEDGE_LIBRARY_STATUSES:
        return candidate
    return "checked_in"


def normalize_knowledge_asset_tags(value: Any) -> List[str]:
    raw_tags: List[str]
    if isinstance(value, list):
        raw_tags = [str(item) for item in value]
    else:
        raw_tags = re.split(r"[,\n]", str(value or ""))

    tags: List[str] = []
    seen = set()
    for raw_tag in raw_tags:
        cleaned = re.sub(r"\s+", " ", str(raw_tag or "").strip())
        if not cleaned:
            continue
        normalized = cleaned.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        tags.append(cleaned)
    return tags[:12]


def _normalize_knowledge_asset_attribute_value(value: Any, depth: int = 0) -> Any:
    if depth > 3 or value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return str(value).strip()
    if isinstance(value, list):
        items: List[Any] = []
        for item in value[:12]:
            normalized_item = _normalize_knowledge_asset_attribute_value(item, depth + 1)
            if normalized_item in (None, "", [], {}):
                continue
            items.append(normalized_item)
        return items
    if isinstance(value, dict):
        normalized: Dict[str, Any] = {}
        for raw_key, raw_item in list(value.items())[:12]:
            key = re.sub(r"[^a-z0-9_]+", "_", str(raw_key or "").strip().lower()).strip("_")
            if not key:
                continue
            normalized_item = _normalize_knowledge_asset_attribute_value(raw_item, depth + 1)
            if normalized_item in (None, "", [], {}):
                continue
            normalized[key] = normalized_item
        return normalized
    return str(value).strip()


def normalize_knowledge_asset_attributes(value: Any) -> Dict[str, Any]:
    normalized = _normalize_knowledge_asset_attribute_value(value)
    if isinstance(normalized, dict):
        return normalized
    return {}


def _normalize_string_list(value: Any, limit: int = 6) -> List[str]:
    raw_items: List[Any]
    if isinstance(value, list):
        raw_items = list(value)
    elif value is None:
        raw_items = []
    else:
        raw_items = re.split(r"[,\n|]+", str(value))

    items: List[str] = []
    seen = set()
    for raw_item in raw_items:
        cleaned = _normalize_whitespace(raw_item).strip(" -")
        if not cleaned:
            continue
        normalized = cleaned.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        items.append(cleaned)
        if len(items) >= limit:
            break
    return items


def _slugify(value: Any) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return slug or "knowledge-asset"


def _strip_markdown(text: str) -> str:
    cleaned = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    cleaned = re.sub(r"`([^`]+)`", r"\1", cleaned)
    cleaned = re.sub(r"^#+\s*", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"^[-*]\s+", "", cleaned, flags=re.MULTILINE)
    cleaned = re.sub(r"\[(.*?)\]\((.*?)\)", r"\1", cleaned)
    return _normalize_whitespace(cleaned)


def _extract_context_body(text: str) -> str:
    raw_text = str(text or "")
    marker = "## Context"
    if marker in raw_text:
        return raw_text.split(marker, 1)[1].strip()
    return raw_text.strip()


def _extract_markdown_section(text: Any, heading: str) -> str:
    raw_text = str(text or "")
    if not raw_text.strip() or not heading:
        return ""

    pattern = rf"(?ms)^##\s+{re.escape(heading)}\s*$\n(.*?)(?=^##\s+|\Z)"
    match = re.search(pattern, raw_text)
    if not match:
        return ""
    return str(match.group(1) or "").strip()


def _looks_like_spl_query(candidate: Any) -> bool:
    normalized = _normalize_whitespace(candidate)
    if not normalized:
        return False

    return bool(
        re.match(
            r"(?is)^(?:search\s+|index=|\|\s*(?:tstats|mstats|from|inputlookup|metadata|rest|makeresults|dbinspect|walklex|pivot|savedsearch|multisearch|union|set))",
            normalized,
        )
    )


def _extract_legacy_spl_query_reference(content: Any) -> str:
    raw_text = str(content or "")
    if not raw_text.strip():
        return ""

    query_section = _normalize_whitespace(_extract_markdown_section(raw_text, "Query"))
    if _looks_like_spl_query(query_section):
        return query_section

    patterns = [
        r"(?im)^#\s*SPL Library:\s*(.+)$",
        r"(?im)^\s*Query summary:\s*(.+)$",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw_text)
        if not match:
            continue
        candidate = _normalize_whitespace(match.group(1))
        if _looks_like_spl_query(candidate):
            return candidate

    return ""


def _is_legacy_spl_library_asset(title: Any, tags: Any, content: Any, attributes: Any) -> bool:
    query_identity = _extract_spl_query_identity("reference_document", content, attributes)
    if not query_identity:
        return False

    normalized_title = _normalize_whitespace(title).lower()
    normalized_tags = {tag.lower() for tag in normalize_knowledge_asset_tags(tags or [])}
    raw_content = str(content or "").lower()
    return (
        normalized_title.startswith("spl library:")
        or "spl-library" in normalized_tags
        or "saved spl query" in raw_content
    )


def _extract_spl_query_identity(asset_type: Any, content: Any, attributes: Any) -> str:
    normalized_attributes = normalize_knowledge_asset_attributes(attributes or {})
    direct_query = _normalize_whitespace(normalized_attributes.get("spl_query"))
    if _looks_like_spl_query(direct_query):
        return direct_query

    query_section = _normalize_whitespace(_extract_markdown_section(content, "Query"))
    if _looks_like_spl_query(query_section):
        return query_section

    return _extract_legacy_spl_query_reference(content)


def _normalize_spl_clause_value(value: Any) -> str:
    cleaned = str(value or "").strip().strip(",")
    if len(cleaned) >= 2 and cleaned[0] in {'"', "'"} and cleaned[-1] == cleaned[0]:
        cleaned = cleaned[1:-1]
    return cleaned.strip()


def _extract_spl_field_values(query: Any, field_names: List[str], limit: int = 8) -> List[str]:
    if not field_names:
        return []

    pattern = rf"(?i)\b(?:{'|'.join(re.escape(name) for name in field_names)})\s*=\s*(\"[^\"]+\"|'[^']+'|[^\s|,\)]+)"
    values = []
    seen = set()
    for match in re.finditer(pattern, str(query or "")):
        cleaned = _normalize_spl_clause_value(match.group(1))
        if not cleaned:
            continue
        normalized = cleaned.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        values.append(cleaned)
        if len(values) >= limit:
            break
    return values


def _extract_spl_commands(query: Any, limit: int = 10) -> List[str]:
    commands: List[str] = []
    seen = set()
    raw_query = str(query or "")

    initial_match = re.match(
        r"(?is)^\s*(search|tstats|mstats|from|inputlookup|metadata|rest|makeresults|dbinspect|walklex|pivot|savedsearch|multisearch|union|set)\b",
        raw_query,
    )
    if initial_match:
        command = str(initial_match.group(1) or "").strip().lower()
        seen.add(command)
        commands.append(command)

    for match in re.finditer(r"(?i)\|\s*([a-z_][a-z0-9_]*)", raw_query):
        command = str(match.group(1) or "").strip().lower()
        if not command or command in seen:
            continue
        seen.add(command)
        commands.append(command)
        if len(commands) >= limit:
            break

    return commands


def _extract_spl_macros(query: Any, limit: int = 6) -> List[str]:
    macros: List[str] = []
    seen = set()
    for match in re.finditer(r"`([^`]+)`", str(query or "")):
        cleaned = _normalize_whitespace(match.group(1)).strip()
        if not cleaned:
            continue
        normalized = cleaned.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        macros.append(cleaned)
        if len(macros) >= limit:
            break
    return macros


def _detect_spl_query_intent(query: Any, commands: List[str], indexes: List[str], sourcetypes: List[str]) -> str:
    lowered = str(query or "").lower()
    command_set = {command.lower() for command in commands or []}

    if any(keyword in lowered for keyword in ("failed", "denied", "suspicious", "threat", "malware", "brute force", "authentication")):
        return "security_detection"
    if any(command in command_set for command in {"timechart", "chart", "trendline"}) or "trend" in lowered:
        return "trend_analysis"
    if any(command in command_set for command in {"stats", "tstats", "mstats"}):
        if any(token in lowered for token in (" by host", " by sourcetype", " by source", " by index")):
            return "inventory_aggregation"
        return "aggregation"
    if any(command in command_set for command in {"metadata", "rest", "inputlookup"}):
        return "inventory_discovery"
    if any(keyword in lowered for keyword in ("latency", "queue", "throughput", "performance", "error", "health", "availability")):
        return "platform_health"
    if indexes or sourcetypes:
        return "targeted_search"
    return "exploration"


def _safe_json_load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _latest_matching_file(source_dir: Optional[Path], pattern: str) -> Optional[Path]:
    if source_dir is None or not source_dir.exists():
        return None
    matches = sorted(source_dir.glob(pattern), key=lambda item: item.name, reverse=True)
    for match in matches:
        if match.exists() and match.is_file():
            return match
    return None


def _append_environment_anchor(target: List[str], seen: set, value: Any, limit: int = 64) -> None:
    cleaned = _normalize_spl_clause_value(value)
    if not cleaned:
        return
    normalized = cleaned.lower()
    if normalized in seen:
        return
    seen.add(normalized)
    target.append(cleaned)
    if len(target) > limit:
        del target[limit:]


def _build_environment_profile(source_dir: Optional[Path]) -> Dict[str, Any]:
    profile = {
        "indexes": [],
        "sourcetypes": [],
        "hosts": [],
        "sources": [],
        "tools": [],
        "splunk_version": "",
        "snapshot_timestamp": "",
        "readiness_score": 0,
    }

    if source_dir is None or not source_dir.exists():
        return profile

    seen_indexes = set()
    seen_sourcetypes = set()
    seen_hosts = set()
    seen_sources = set()

    sessions_payload = _safe_json_load(source_dir / "discovery_sessions.json")
    latest_session = sessions_payload[0] if isinstance(sessions_payload, list) and sessions_payload else {}
    if isinstance(latest_session, dict):
        overview = latest_session.get("overview", {}) if isinstance(latest_session.get("overview"), dict) else {}
        capabilities = latest_session.get("mcp_capabilities", {}) if isinstance(latest_session.get("mcp_capabilities"), dict) else {}
        tools = capabilities.get("tools", []) if isinstance(capabilities.get("tools"), list) else []
        profile["tools"] = [str(tool).strip() for tool in tools[:12] if str(tool).strip()]
        profile["splunk_version"] = str(overview.get("splunk_version") or "").strip()
        profile["snapshot_timestamp"] = str(latest_session.get("timestamp") or latest_session.get("created_at") or "").strip()
        profile["readiness_score"] = int(latest_session.get("readiness_score") or 0)

    blueprint_path = None
    if isinstance(latest_session, dict):
        report_paths = latest_session.get("report_paths", []) if isinstance(latest_session.get("report_paths"), list) else []
        for report_path in report_paths:
            candidate_name = Path(str(report_path or "")).name
            if not candidate_name.startswith("v2_intelligence_blueprint_"):
                continue
            candidate_path = source_dir / candidate_name
            if candidate_path.exists() and candidate_path.is_file():
                blueprint_path = candidate_path
                break
    if blueprint_path is None:
        blueprint_path = _latest_matching_file(source_dir, "v2_intelligence_blueprint_*.json")

    blueprint_payload = _safe_json_load(blueprint_path) if blueprint_path is not None else None
    if isinstance(blueprint_payload, dict):
        overview = blueprint_payload.get("overview", {}) if isinstance(blueprint_payload.get("overview"), dict) else {}
        if not profile["splunk_version"]:
            profile["splunk_version"] = str(overview.get("splunk_version") or "").strip()
        if not profile["snapshot_timestamp"]:
            profile["snapshot_timestamp"] = str(blueprint_payload.get("generated_at") or "").strip()
        if not profile["readiness_score"]:
            profile["readiness_score"] = int(blueprint_payload.get("readiness_score") or 0)

        known_entities = blueprint_payload.get("known_entities", {}) if isinstance(blueprint_payload.get("known_entities"), dict) else {}
        for item in known_entities.get("indexes", []) if isinstance(known_entities.get("indexes"), list) else []:
            _append_environment_anchor(profile["indexes"], seen_indexes, item)
        for item in known_entities.get("sourcetypes", []) if isinstance(known_entities.get("sourcetypes"), list) else []:
            _append_environment_anchor(profile["sourcetypes"], seen_sourcetypes, item)
        for item in known_entities.get("hosts", []) if isinstance(known_entities.get("hosts"), list) else []:
            _append_environment_anchor(profile["hosts"], seen_hosts, item)
        for item in known_entities.get("sources", []) if isinstance(known_entities.get("sources"), list) else []:
            _append_environment_anchor(profile["sources"], seen_sources, item)

        finding_ledger = blueprint_payload.get("finding_ledger", []) if isinstance(blueprint_payload.get("finding_ledger"), list) else []
        for item in finding_ledger:
            if not isinstance(item, dict):
                continue
            data = item.get("data", {}) if isinstance(item.get("data"), dict) else {}
            title = str(item.get("title") or "").strip().lower()
            if title.startswith("analyzing index:") or (data.get("title") is not None and data.get("totalEventCount") is not None):
                _append_environment_anchor(profile["indexes"], seen_indexes, data.get("title"))
            if title.startswith("analyzing sourcetype:") or data.get("sourcetype") is not None:
                _append_environment_anchor(profile["sourcetypes"], seen_sourcetypes, data.get("sourcetype"))
            if title.startswith("analyzing host:") or data.get("host") is not None:
                _append_environment_anchor(profile["hosts"], seen_hosts, data.get("host"))
            if title.startswith("analyzing source:") or data.get("source") is not None:
                _append_environment_anchor(profile["sources"], seen_sources, data.get("source"))

    return profile


def _normalize_spl_validation(value: Any) -> Dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    success_count = max(0, int(payload.get("success_count") or 0))
    failure_count = max(0, int(payload.get("failure_count") or 0))
    execution_count = max(
        success_count + failure_count,
        int(payload.get("execution_count") or 0),
    )
    last_status = str(payload.get("last_status") or "").strip().lower()
    if success_count > 0 and failure_count == 0:
        status = "known_good"
    elif success_count == 0 and failure_count > 0:
        status = "failing"
    elif success_count > 0 and failure_count > 0:
        status = "mixed"
    else:
        status = "unvalidated"
    if last_status in {"success", "failure"}:
        status = "known_good" if last_status == "success" and success_count > 0 and failure_count == 0 else status

    return {
        "status": status,
        "execution_count": execution_count,
        "success_count": success_count,
        "failure_count": failure_count,
        "last_status": last_status,
        "last_validated_at": str(payload.get("last_validated_at") or "").strip(),
        "last_error": str(payload.get("last_error") or "").strip(),
        "last_row_count": max(0, int(payload.get("last_row_count") or 0)),
        "last_earliest": str(payload.get("last_earliest") or "").strip(),
        "last_latest": str(payload.get("last_latest") or "").strip(),
    }


def _build_spl_environment_fit(
    indexes: List[str],
    sourcetypes: List[str],
    hosts: List[str],
    commands: List[str],
    environment_profile: Dict[str, Any],
) -> Dict[str, Any]:
    known_indexes = {value.lower() for value in environment_profile.get("indexes", []) if isinstance(value, str)}
    known_sourcetypes = {value.lower() for value in environment_profile.get("sourcetypes", []) if isinstance(value, str)}
    known_hosts = {value.lower() for value in environment_profile.get("hosts", []) if isinstance(value, str)}
    available_tools = {str(tool).strip().lower() for tool in environment_profile.get("tools", []) if str(tool).strip()}

    generic_indexes = [value for value in indexes if "*" in value]
    targeted_indexes = [value for value in indexes if value and "*" not in value]
    matched_indexes = [value for value in targeted_indexes if value.lower() in known_indexes]
    missing_indexes = [value for value in targeted_indexes if value.lower() not in known_indexes]

    matched_sourcetypes = [value for value in sourcetypes if value.lower() in known_sourcetypes]
    missing_sourcetypes = [value for value in sourcetypes if value.lower() not in known_sourcetypes]

    matched_hosts = [value for value in hosts if value.lower() in known_hosts]
    missing_hosts = [value for value in hosts if value.lower() not in known_hosts]

    score = 35
    reasons: List[str] = []
    if targeted_indexes:
        if matched_indexes:
            score += 30
            reasons.append(f"Matched index anchors: {', '.join(matched_indexes[:4])}.")
        if missing_indexes:
            score -= 18
            reasons.append(f"Unknown indexes: {', '.join(missing_indexes[:4])}.")
        elif matched_indexes:
            score += 12
    elif generic_indexes:
        score += 6
        reasons.append("Uses a wildcard index scope that is flexible but not environment-specific.")
    else:
        reasons.append("No explicit index anchor was found in the query.")

    if sourcetypes:
        if matched_sourcetypes:
            score += 14
            reasons.append(f"Matched sourcetypes: {', '.join(matched_sourcetypes[:4])}.")
        if missing_sourcetypes:
            score -= 8
            reasons.append(f"Unknown sourcetypes: {', '.join(missing_sourcetypes[:4])}.")

    if hosts:
        if matched_hosts:
            score += 10
            reasons.append(f"Matched hosts: {', '.join(matched_hosts[:4])}.")
        if missing_hosts:
            score -= 6
            reasons.append(f"Unknown hosts: {', '.join(missing_hosts[:4])}.")

    if "splunk_run_query" in available_tools:
        score += 5
        reasons.append("Live query execution is available through MCP.")
    if "tstats" in {command.lower() for command in commands or []}:
        score += 4
    if "rest" in {command.lower() for command in commands or []} and "splunk_get_info" not in available_tools:
        score -= 4

    score = max(0, min(100, score))
    if score >= 70 and not missing_indexes and not missing_sourcetypes and not missing_hosts:
        status = "strong"
    elif score >= 60:
        status = "partial"
    elif score >= 40:
        status = "unknown"
    else:
        status = "low"

    return {
        "status": status,
        "score": score,
        "reason": " ".join(reasons[:4]).strip(),
        "matched_indexes": matched_indexes[:6],
        "missing_indexes": missing_indexes[:6],
        "matched_sourcetypes": matched_sourcetypes[:6],
        "missing_sourcetypes": missing_sourcetypes[:6],
        "matched_hosts": matched_hosts[:6],
        "missing_hosts": missing_hosts[:6],
        "environment_snapshot": str(environment_profile.get("snapshot_timestamp") or "").strip(),
        "splunk_version": str(environment_profile.get("splunk_version") or "").strip(),
    }


def _build_spl_reuse_profile(environment_fit: Dict[str, Any], validation: Dict[str, Any]) -> Dict[str, Any]:
    score = int(environment_fit.get("score") or 0)
    validation_status = str(validation.get("status") or "unvalidated").strip().lower()
    success_count = int(validation.get("success_count") or 0)
    failure_count = int(validation.get("failure_count") or 0)

    if validation_status == "known_good":
        score += 28
    elif validation_status == "mixed":
        score += 6
    elif validation_status == "failing":
        score -= 18

    score += min(12, success_count * 3)
    score -= min(12, failure_count * 3)
    score = max(0, min(100, score))

    if validation_status == "known_good" and score >= 80:
        tier = "known_good"
        guidance = "Prefer adapting this known-good query before generating a new one."
    elif score >= 70:
        tier = "preferred"
        guidance = "Prefer reusing this query as a starting point when the request is similar."
    elif score >= 50:
        tier = "candidate"
        guidance = "Reasonable starting point, but validate the fit before relying on it."
    else:
        tier = "exploratory"
        guidance = "Treat as exploratory context rather than a preferred reusable query."

    return {
        "tier": tier,
        "score": score,
        "known_good": validation_status == "known_good",
        "guidance": guidance,
    }


def _derive_spl_intelligence(attributes: Dict[str, Any], content: str, environment_profile: Dict[str, Any]) -> Dict[str, Any]:
    query = _extract_spl_query_identity("spl_query_library", content, attributes)
    if not query:
        return {}

    commands = _extract_spl_commands(query)
    indexes = _extract_spl_field_values(query, ["index"])
    sourcetypes = _extract_spl_field_values(query, ["sourcetype"])
    hosts = _extract_spl_field_values(query, ["host"])
    sources = _extract_spl_field_values(query, ["source"])
    data_models = _extract_spl_field_values(query, ["datamodel", "data_model"])
    validation = _normalize_spl_validation(
        (attributes.get("spl_intelligence") or {}).get("validation")
        if isinstance(attributes.get("spl_intelligence"), dict)
        else {}
    )
    environment_fit = _build_spl_environment_fit(
        indexes=indexes,
        sourcetypes=sourcetypes,
        hosts=hosts,
        commands=commands,
        environment_profile=environment_profile,
    )
    reuse = _build_spl_reuse_profile(environment_fit=environment_fit, validation=validation)
    return {
        "query_intent": _detect_spl_query_intent(query, commands, indexes, sourcetypes),
        "commands": commands,
        "indexes": indexes,
        "sourcetypes": sourcetypes,
        "hosts": hosts,
        "sources": sources,
        "data_models": data_models,
        "macros": _extract_spl_macros(query),
        "environment_fit": environment_fit,
        "validation": validation,
        "reuse": reuse,
    }


def _carry_forward_spl_validation(existing_attributes: Dict[str, Any], incoming_attributes: Dict[str, Any]) -> Dict[str, Any]:
    merged_attributes = dict(incoming_attributes or {})
    existing_intelligence = existing_attributes.get("spl_intelligence") if isinstance(existing_attributes.get("spl_intelligence"), dict) else {}
    existing_validation = existing_intelligence.get("validation") if isinstance(existing_intelligence.get("validation"), dict) else {}
    if not existing_validation:
        return merged_attributes

    incoming_intelligence = merged_attributes.get("spl_intelligence") if isinstance(merged_attributes.get("spl_intelligence"), dict) else {}
    if not incoming_intelligence.get("validation"):
        incoming_intelligence = dict(incoming_intelligence)
        incoming_intelligence["validation"] = dict(existing_validation)
        merged_attributes["spl_intelligence"] = incoming_intelligence
    return merged_attributes


def _extract_spl_context_text(content: Any) -> str:
    context_section = _extract_markdown_section(content, "Context")
    if context_section:
        return context_section

    stripped = str(content or "").strip()
    if not stripped:
        return "Saved SPL query for reuse."

    without_query = re.sub(r"(?ms)^##\s+Query\s*$\n.*?(?=^##\s+|\Z)", "", stripped)
    without_intelligence = re.sub(r"(?ms)^##\s+Query Intelligence\s*$\n.*?(?=^##\s+|\Z)", "", without_query)
    cleaned = without_intelligence.strip()
    return cleaned or "Saved SPL query for reuse."


def _hydrate_spl_library_attributes(attributes: Dict[str, Any], content: str, environment_profile: Dict[str, Any]) -> Dict[str, Any]:
    normalized_attributes = normalize_knowledge_asset_attributes(attributes or {})
    query = _extract_spl_query_identity("spl_query_library", content, normalized_attributes)
    if query and not _normalize_whitespace(normalized_attributes.get("spl_query")):
        normalized_attributes["spl_query"] = query

    spl_intelligence = _derive_spl_intelligence(normalized_attributes, content, environment_profile)
    if spl_intelligence:
        normalized_attributes = dict(normalized_attributes)
        normalized_attributes["spl_intelligence"] = spl_intelligence
    return normalized_attributes


def _build_stored_sections(text: str) -> List[Dict[str, Any]]:
    sections: List[Dict[str, Any]] = []
    current_title = "Overview"
    current_lines: List[str] = []

    def flush_section(title: str, lines: List[str]) -> None:
        raw_content = "\n".join(line.rstrip() for line in lines).strip()
        if not raw_content:
            return

        items: List[str] = []
        for line in lines:
            bullet_match = re.match(r"^\s*(?:[-*+]\s+|\d+\.\s+)(.+)$", line)
            if not bullet_match:
                continue
            cleaned = _normalize_whitespace(bullet_match.group(1))
            if cleaned:
                items.append(cleaned)

        sections.append(
            {
                "title": title or "Section",
                "content": raw_content,
                "items": items,
                "line_count": len([line for line in lines if str(line).strip()]),
                "character_count": len(raw_content),
            }
        )

    for raw_line in str(text or "").splitlines():
        heading_match = re.match(r"^##\s+(.*?)\s*$", raw_line)
        if raw_line.startswith("# "):
            continue
        if heading_match:
            flush_section(current_title, current_lines)
            current_title = heading_match.group(1).strip() or "Section"
            current_lines = []
            continue
        current_lines.append(raw_line)

    flush_section(current_title, current_lines)
    return sections


def _build_preview(text: str, limit: int = 220) -> str:
    cleaned = _strip_markdown(text)
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[: max(40, limit - 3)].rstrip()}..."


def _extract_text_from_pdf_bytes(content_bytes: bytes) -> str:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ValueError("PDF upload support requires the pypdf package to be installed.") from exc

    try:
        reader = PdfReader(BytesIO(content_bytes or b""))
    except Exception as exc:
        raise ValueError(f"Failed to read uploaded PDF: {exc}") from exc

    pages: List[str] = []
    for index, page in enumerate(reader.pages, start=1):
        try:
            page_text = str(page.extract_text() or "").strip()
        except Exception as exc:
            raise ValueError(f"Failed to extract text from PDF page {index}: {exc}") from exc
        if not page_text:
            continue
        normalized_page_text = re.sub(r"\n{3,}", "\n\n", page_text)
        pages.append(f"## PDF Page {index}\n{normalized_page_text}")

    if not pages:
        raise ValueError("The uploaded PDF did not contain extractable text.")
    return "\n\n".join(pages)


def _extract_text_from_docx_bytes(content_bytes: bytes) -> str:
    try:
        from docx import Document
        from docx.document import Document as DocumentType
        from docx.oxml.table import CT_Tbl
        from docx.oxml.text.paragraph import CT_P
        from docx.table import Table
        from docx.text.paragraph import Paragraph
    except ImportError as exc:
        raise ValueError("DOCX upload support requires the python-docx package to be installed.") from exc

    try:
        document = Document(BytesIO(content_bytes or b""))
    except Exception as exc:
        raise ValueError(f"Failed to read uploaded DOCX: {exc}") from exc

    def iter_blocks(parent: DocumentType) -> Any:
        for child in parent.element.body.iterchildren():
            if isinstance(child, CT_P):
                yield Paragraph(child, parent)
            elif isinstance(child, CT_Tbl):
                yield Table(child, parent)

    parts: List[str] = []
    table_index = 0
    for block in iter_blocks(document):
        if block.__class__.__name__ == "Paragraph":
            paragraph_text = _normalize_whitespace(block.text)
            if not paragraph_text:
                continue
            style_name = str(getattr(getattr(block, "style", None), "name", "") or "").strip().lower()
            if style_name.startswith("heading") or style_name == "title":
                parts.append(f"## {paragraph_text}")
            else:
                parts.append(paragraph_text)
            continue

        rows: List[str] = []
        for row in block.rows:
            cells = [_normalize_whitespace(cell.text) for cell in row.cells]
            cleaned_cells = [cell for cell in cells if cell]
            if cleaned_cells:
                rows.append(" | ".join(cleaned_cells))
        if rows:
            table_index += 1
            parts.append(f"## DOCX Table {table_index}")
            parts.extend(rows)

    if not parts:
        raise ValueError("The uploaded DOCX did not contain extractable text.")
    return "\n\n".join(parts)


def _extract_headings(text: str, limit: int = 6) -> List[str]:
    headings: List[str] = []
    for line in str(text or "").splitlines():
        candidate = None
        heading_match = re.match(r"^\s{0,3}#{1,6}\s+(.*?)\s*$", line)
        if heading_match:
            candidate = heading_match.group(1)
        else:
            stripped = line.strip()
            if stripped.endswith(":") and len(stripped) <= 80 and not stripped.startswith("{"):
                candidate = stripped.rstrip(":")

        if candidate:
            headings.extend(_normalize_string_list([candidate], limit=limit))
            if len(headings) >= limit:
                break
    return _normalize_string_list(headings, limit=limit)


def _extract_key_points(text: str, limit: int = 4) -> List[str]:
    bullet_candidates: List[str] = []
    for line in str(text or "").splitlines():
        bullet_match = re.match(r"^\s*(?:[-*+]\s+|\d+\.\s+)(.+)$", line)
        if not bullet_match:
            continue
        cleaned = _normalize_whitespace(bullet_match.group(1)).strip(".")
        if len(cleaned) >= 25:
            bullet_candidates.append(cleaned)
        if len(bullet_candidates) >= limit:
            break

    if bullet_candidates:
        return _normalize_string_list(bullet_candidates, limit=limit)

    sentences = [
        sentence.strip().rstrip(".")
        for sentence in re.split(r"(?<=[.!?])\s+", _strip_markdown(text))
        if sentence.strip() and len(sentence.strip()) >= 30
    ]
    return _normalize_string_list(sentences, limit=limit)


def _extract_focus_terms(
    title: str,
    description: str,
    source_label: str,
    tags: List[str],
    headings: List[str],
    key_points: List[str],
    content: str,
    limit: int = 8,
) -> List[str]:
    scores: Dict[str, int] = {}
    labels: Dict[str, str] = {}

    def add_phrase(value: Any, weight: int) -> None:
        cleaned = _normalize_whitespace(value).strip(".,:;")
        if not cleaned:
            return
        if len(cleaned.split()) > 4 or len(cleaned) > 32:
            return
        normalized = cleaned.lower()
        if normalized in FOCUS_TERM_STOPWORDS:
            return
        scores[normalized] = scores.get(normalized, 0) + weight
        labels.setdefault(normalized, cleaned)

    def add_tokens(value: Any, weight: int) -> None:
        for token in re.findall(r"[a-zA-Z][a-zA-Z0-9_]{2,}", str(value or "").lower()):
            if token in FOCUS_TERM_STOPWORDS:
                continue
            scores[token] = scores.get(token, 0) + weight
            labels.setdefault(token, token)

    for tag in tags:
        add_phrase(tag, 6)
        add_tokens(tag, 4)
    for phrase, weight in ((title, 5), (source_label, 4), (description, 2)):
        add_phrase(phrase, weight)
        add_tokens(phrase, weight)
    for heading in headings:
        add_phrase(heading, 4)
        add_tokens(heading, 3)
    for point in key_points[:3]:
        add_tokens(point, 2)
    add_tokens(str(content or "")[:2000], 1)

    ranked = sorted(
        scores.items(),
        key=lambda item: (-item[1], len(labels.get(item[0], item[0])), labels.get(item[0], item[0])),
    )
    return [labels[key] for key, _ in ranked[:limit]]


def _build_usage_guidance(asset_type: str, source_label: str, tags: List[str], content: str, key_points: List[str]) -> List[str]:
    guidance: List[str] = []
    seen = set()

    def add(item: str) -> None:
        cleaned = _normalize_whitespace(item).rstrip(".")
        if not cleaned:
            return
        normalized = cleaned.lower()
        if normalized in seen:
            return
        seen.add(normalized)
        guidance.append(f"{cleaned}.")

    for base_hint in ASSET_TYPE_USAGE_HINTS.get(asset_type, []):
        add(base_hint)

    keyword_text = " ".join([source_label, " ".join(tags), " ".join(key_points[:2]), str(content or "")[:1200]]).lower()
    if any(keyword in keyword_text for keyword in ("dependency", "depends", "integration", "api", "forwarder", "certificate", "queue", "pipeline", "shared service")):
        add("Use when the assistant needs dependency or integration context")
    if any(keyword in keyword_text for keyword in ("owner", "team", "contact", "on-call", "escalat", "support group")):
        add("Use for ownership, escalation, and support-routing questions")
    if any(keyword in keyword_text for keyword in ("index", "sourcetype", "search", "savedsearch", "props", "transforms", "search head", "indexer", "cluster")):
        add("Use for Splunk platform behavior, configuration, and search workflow questions")
    if any(keyword in keyword_text for keyword in ("runbook", "validate", "triage", "procedure", "step", "response", "playbook")):
        add("Use for operator procedures, triage flow, and runbook questions")
    return guidance[:4]


def _format_token(value: Any) -> str:
    cleaned = str(value or "").strip().lower()
    if not cleaned:
        return ""
    return " ".join(part.upper() if part in {"rag", "llm", "mcp"} else part.capitalize() for part in cleaned.split("_"))


def _build_summary(
    title: str,
    asset_type: str,
    source_label: str,
    description: str,
    tags: List[str],
    key_points: List[str],
    content: str,
) -> str:
    title_text = _normalize_whitespace(title)
    description_text = _normalize_whitespace(description)
    body_text = _strip_markdown(content)
    sentences = [
        sentence.strip()
        for sentence in re.split(r"(?<=[.!?])\s+", body_text)
        if sentence.strip() and len(sentence.strip()) >= 30
    ]

    parts = [f"{title_text}." if title_text else "Knowledge asset."]
    if source_label:
        parts.append(f"{_format_token(asset_type)} for {source_label}.")
    else:
        parts.append(f"{_format_token(asset_type)} context.")

    if description_text:
        parts.append(f"{description_text.rstrip('.')}.")

    if key_points:
        parts.append(key_points[0].rstrip(".") + ".")
        if len(key_points) > 1 and len(" ".join(parts)) < 260:
            parts.append(key_points[1].rstrip(".") + ".")
    elif sentences:
        parts.append(sentences[0].rstrip(".") + ".")
        if len(sentences) > 1 and len(" ".join(parts)) < 260:
            parts.append(sentences[1].rstrip(".") + ".")
    elif body_text:
        parts.append(_build_preview(body_text, limit=180).rstrip(".") + ".")

    if tags:
        parts.append(f"Tags: {', '.join(tags[:5])}.")

    summary = _normalize_whitespace(" ".join(parts))
    return summary[:320].rstrip()


def _derive_asset_enrichment(
    title: str,
    asset_type: str,
    source_label: str,
    description: str,
    tags: List[str],
    content: str,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    normalized_content = str(content or "").strip()
    normalized_attributes = normalize_knowledge_asset_attributes(attributes or {})
    if asset_type == "spl_query_library":
        query = _extract_spl_query_identity(asset_type, normalized_content, normalized_attributes)
        context_text = _extract_spl_context_text(normalized_content)
        combined_parts = []
        if query:
            combined_parts.extend(["## Query", query])
        if context_text:
            combined_parts.extend(["## Context", context_text])
        normalized_content = "\n\n".join(part for part in combined_parts if part)

    headings = _extract_headings(normalized_content)
    key_points = _extract_key_points(normalized_content)
    focus_terms = _extract_focus_terms(
        title=title,
        description=description,
        source_label=source_label,
        tags=tags,
        headings=headings,
        key_points=key_points,
        content=normalized_content,
    )
    usage_guidance = _build_usage_guidance(
        asset_type=asset_type,
        source_label=source_label,
        tags=tags,
        content=normalized_content,
        key_points=key_points,
    )
    summary = _build_summary(
        title=title,
        asset_type=asset_type,
        source_label=source_label,
        description=description,
        tags=tags,
        key_points=key_points,
        content=normalized_content,
    )
    return {
        "headings": headings,
        "key_points": key_points,
        "focus_terms": focus_terms,
        "usage_guidance": usage_guidance,
        "summary": summary,
        "preview": _build_preview(normalized_content),
    }


@dataclass
class ManagedKnowledgeAsset:
    """User-managed knowledge asset stored for retrieval use."""

    asset_id: str
    title: str
    asset_type: str
    source_label: str
    description: str
    summary: str
    preview: str
    headings: List[str] = field(default_factory=list)
    key_points: List[str] = field(default_factory=list)
    focus_terms: List[str] = field(default_factory=list)
    usage_guidance: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)
    library_status: str = "checked_in"
    checked_out_at: Optional[str] = None
    last_checked_in_at: Optional[str] = None
    content_path: str = ""
    import_method: str = "text"
    original_filename: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""
    text_char_count: int = 0
    word_count: int = 0
    last_import_action: str = field(default="created", repr=False, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "title": self.title,
            "asset_type": self.asset_type,
            "source_label": self.source_label,
            "description": self.description,
            "summary": self.summary,
            "preview": self.preview,
            "headings": list(self.headings),
            "key_points": list(self.key_points),
            "focus_terms": list(self.focus_terms),
            "usage_guidance": list(self.usage_guidance),
            "tags": list(self.tags),
            "attributes": dict(self.attributes),
            "library_status": self.library_status,
            "checked_out_at": self.checked_out_at,
            "last_checked_in_at": self.last_checked_in_at,
            "content_path": self.content_path,
            "import_method": self.import_method,
            "original_filename": self.original_filename,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "text_char_count": self.text_char_count,
            "word_count": self.word_count,
        }


class KnowledgeAssetManager:
    """Persist and describe user-managed knowledge assets."""

    def __init__(self, asset_dir: Path, manifest_path: Path, source_dir: Optional[Path] = None):
        self.asset_dir = asset_dir
        self.manifest_path = manifest_path
        self.source_dir = source_dir

    def list_assets(self) -> Dict[str, Any]:
        assets = self._load_assets()
        asset_type_counts: Dict[str, int] = {}
        library_status_counts: Dict[str, int] = {
            "checked_in": 0,
            "checked_out": 0,
        }
        for asset in assets:
            asset_type_counts[asset.asset_type] = asset_type_counts.get(asset.asset_type, 0) + 1
            library_status_counts[asset.library_status] = library_status_counts.get(asset.library_status, 0) + 1

        return {
            "asset_count": len(assets),
            "checked_in_asset_count": library_status_counts.get("checked_in", 0),
            "checked_out_asset_count": library_status_counts.get("checked_out", 0),
            "library_status_counts": library_status_counts,
            "asset_type_counts": asset_type_counts,
            "assets": [asset.to_dict() for asset in assets],
        }

    def get_asset(self, asset_id: str) -> Optional[ManagedKnowledgeAsset]:
        for asset in self._load_assets():
            if asset.asset_id == asset_id:
                return asset
        return None

    def get_asset_detail(self, asset_id: str) -> Optional[Dict[str, Any]]:
        asset = self.get_asset(asset_id)
        if asset is None:
            return None

        content_path = self.asset_dir / asset.content_path
        if not content_path.exists() or not content_path.is_file():
            return None

        stored_text = content_path.read_text(encoding="utf-8", errors="ignore")
        context_body = _extract_context_body(stored_text)
        return {
            "asset": asset.to_dict(),
            "stored_path": asset.content_path,
            "stored_sections": _build_stored_sections(stored_text),
            "context_body": context_body,
            "context_character_count": len(context_body),
        }

    def import_text_asset(
        self,
        title: str,
        asset_type: str,
        content: str,
        source_label: str = "",
        description: str = "",
        tags: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
        original_filename: Optional[str] = None,
        import_method: str = "text",
    ) -> ManagedKnowledgeAsset:
        normalized_title = _normalize_whitespace(title)
        normalized_content = str(content or "").strip()
        if not normalized_title:
            raise ValueError("Asset title is required.")
        if not normalized_content:
            raise ValueError("Asset content is required.")

        normalized_type = normalize_knowledge_asset_type(asset_type)
        normalized_source_label = _normalize_whitespace(source_label)
        normalized_description = _normalize_whitespace(description)
        normalized_tags = normalize_knowledge_asset_tags(tags or [])
        normalized_attributes = normalize_knowledge_asset_attributes(attributes or {})

        self.asset_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        assets = self._load_assets()
        existing_asset = self._find_existing_import_asset(
            assets=assets,
            asset_type=normalized_type,
            content=normalized_content,
            attributes=normalized_attributes,
        )
        if existing_asset and normalized_type == "spl_query_library":
            normalized_attributes = _carry_forward_spl_validation(existing_asset.attributes, normalized_attributes)
        if normalized_type == "spl_query_library":
            normalized_attributes = _hydrate_spl_library_attributes(
                normalized_attributes,
                normalized_content,
                _build_environment_profile(self.source_dir),
            )
        import_timestamp = _utc_now_iso()
        created_at = existing_asset.created_at if existing_asset else import_timestamp
        updated_at = import_timestamp

        if existing_asset:
            asset_id = existing_asset.asset_id
            content_path = self.asset_dir / existing_asset.content_path
        else:
            asset_id = hashlib.sha1(f"{normalized_title}|{created_at}|{normalized_content[:200]}".encode("utf-8")).hexdigest()
            file_timestamp = created_at.replace(":", "").replace("-", "")[:15]
            filename = f"knowledge_asset_{file_timestamp}_{_slugify(original_filename or normalized_title)}.md"
            content_path = self.asset_dir / filename

        enrichment = _derive_asset_enrichment(
            title=normalized_title,
            asset_type=normalized_type,
            source_label=normalized_source_label,
            description=normalized_description,
            tags=normalized_tags,
            content=normalized_content,
            attributes=normalized_attributes,
        )
        summary = enrichment["summary"]
        preview = enrichment["preview"]
        stored_markdown = self._build_asset_markdown(
            title=normalized_title,
            asset_type=normalized_type,
            source_label=normalized_source_label,
            description=normalized_description,
            summary=summary,
            headings=enrichment["headings"],
            key_points=enrichment["key_points"],
            focus_terms=enrichment["focus_terms"],
            usage_guidance=enrichment["usage_guidance"],
            tags=normalized_tags,
            created_at=created_at,
            attributes=normalized_attributes,
            content=normalized_content,
        )
        content_path.write_text(stored_markdown, encoding="utf-8")

        asset = ManagedKnowledgeAsset(
            asset_id=asset_id,
            title=normalized_title,
            asset_type=normalized_type,
            source_label=normalized_source_label,
            description=normalized_description,
            summary=summary,
            preview=preview,
            headings=enrichment["headings"],
            key_points=enrichment["key_points"],
            focus_terms=enrichment["focus_terms"],
            usage_guidance=enrichment["usage_guidance"],
            tags=normalized_tags,
            attributes=normalized_attributes,
            content_path=content_path.name,
            import_method=import_method,
            original_filename=original_filename or (existing_asset.original_filename if existing_asset else None),
            created_at=created_at,
            updated_at=updated_at,
            text_char_count=len(normalized_content),
            word_count=len(re.findall(r"\S+", normalized_content)),
            library_status=existing_asset.library_status if existing_asset else "checked_in",
            checked_out_at=existing_asset.checked_out_at if existing_asset else None,
            last_checked_in_at=(
                existing_asset.last_checked_in_at
                if existing_asset
                else created_at
            ),
            last_import_action="updated" if existing_asset else "created",
        )

        if existing_asset:
            assets = [asset if item.asset_id == existing_asset.asset_id else item for item in assets]
        else:
            assets.append(asset)
        self._save_assets(assets)
        return asset

    def import_file_asset(
        self,
        filename: str,
        content_bytes: bytes,
        title: Optional[str] = None,
        asset_type: str = "reference_document",
        source_label: str = "",
        description: str = "",
        tags: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> ManagedKnowledgeAsset:
        safe_name = Path(str(filename or "")).name
        suffix = Path(safe_name).suffix.lower()
        if suffix and suffix not in SUPPORTED_IMPORT_SUFFIXES:
            raise ValueError("Only markdown, text, JSON, log, CSV, PDF, and DOCX assets are supported in this release.")

        if suffix == ".pdf":
            content_text = _extract_text_from_pdf_bytes(content_bytes)
        elif suffix == ".docx":
            content_text = _extract_text_from_docx_bytes(content_bytes)
        else:
            try:
                content_text = (content_bytes or b"").decode("utf-8", errors="ignore")
            except Exception as exc:
                raise ValueError(f"Failed to decode uploaded asset: {exc}") from exc

        normalized_title = title or Path(safe_name).stem or "Imported Knowledge Asset"
        return self.import_text_asset(
            title=normalized_title,
            asset_type=asset_type,
            content=content_text,
            source_label=source_label,
            description=description,
            tags=tags,
            attributes=attributes,
            original_filename=safe_name or None,
            import_method="file_upload",
        )

    def delete_asset(self, asset_id: str) -> Optional[ManagedKnowledgeAsset]:
        assets = self._load_assets()
        remaining: List[ManagedKnowledgeAsset] = []
        deleted: Optional[ManagedKnowledgeAsset] = None

        for asset in assets:
            if asset.asset_id == asset_id and deleted is None:
                deleted = asset
                continue
            remaining.append(asset)

        if deleted is None:
            return None

        asset_path = self.asset_dir / deleted.content_path
        if asset_path.exists() and asset_path.is_file():
            asset_path.unlink()
        self._save_assets(remaining)
        return deleted

    def record_spl_query_feedback(self, query: str, status: str, feedback: Optional[Dict[str, Any]] = None) -> Optional[ManagedKnowledgeAsset]:
        query_identity = _extract_spl_query_identity("spl_query_library", "", {"spl_query": query})
        if not query_identity:
            return None

        normalized_status = str(status or "").strip().lower()
        if normalized_status not in {"success", "failure"}:
            return None

        feedback_payload = feedback if isinstance(feedback, dict) else {}
        assets = self._load_assets()
        updated_asset: Optional[ManagedKnowledgeAsset] = None
        next_assets: List[ManagedKnowledgeAsset] = []

        for asset in assets:
            if updated_asset is not None or self._get_asset_import_identity(asset) != query_identity:
                next_assets.append(asset)
                continue

            attributes = normalize_knowledge_asset_attributes(asset.attributes)
            intelligence = attributes.get("spl_intelligence") if isinstance(attributes.get("spl_intelligence"), dict) else {}
            validation = _normalize_spl_validation(intelligence.get("validation"))
            validation["execution_count"] = int(validation.get("execution_count") or 0) + 1
            if normalized_status == "success":
                validation["success_count"] = int(validation.get("success_count") or 0) + 1
                validation["last_error"] = ""
            else:
                validation["failure_count"] = int(validation.get("failure_count") or 0) + 1
                validation["last_error"] = str(feedback_payload.get("error") or feedback_payload.get("detail") or "").strip()
            validation["last_status"] = normalized_status
            validation["last_validated_at"] = _utc_now_iso()
            if feedback_payload.get("row_count") is not None:
                validation["last_row_count"] = max(0, int(feedback_payload.get("row_count") or 0))
            if feedback_payload.get("earliest_time") is not None:
                validation["last_earliest"] = str(feedback_payload.get("earliest_time") or "").strip()
            if feedback_payload.get("latest_time") is not None:
                validation["last_latest"] = str(feedback_payload.get("latest_time") or "").strip()

            intelligence = dict(intelligence)
            intelligence["validation"] = validation
            attributes = dict(attributes)
            attributes["spl_intelligence"] = intelligence

            asset_path = self.asset_dir / asset.content_path
            stored_text = asset_path.read_text(encoding="utf-8", errors="ignore") if asset_path.exists() and asset_path.is_file() else ""
            asset_content = _extract_context_body(stored_text) or stored_text
            attributes = _hydrate_spl_library_attributes(
                attributes,
                asset_content,
                _build_environment_profile(self.source_dir),
            )

            payload = asset.to_dict()
            payload.update(
                {
                    "attributes": attributes,
                    "updated_at": _utc_now_iso(),
                }
            )
            updated_asset = ManagedKnowledgeAsset(**payload)
            next_assets.append(updated_asset)

        if updated_asset is None:
            return None

        self._save_assets(next_assets)
        return updated_asset

    def check_in_asset(self, asset_id: str) -> Optional[ManagedKnowledgeAsset]:
        return self._set_asset_library_status(asset_id, "checked_in")

    def check_out_asset(self, asset_id: str) -> Optional[ManagedKnowledgeAsset]:
        return self._set_asset_library_status(asset_id, "checked_out")

    def _set_asset_library_status(self, asset_id: str, library_status: str) -> Optional[ManagedKnowledgeAsset]:
        normalized_status = normalize_knowledge_asset_library_status(library_status)
        assets = self._load_assets()
        updated_asset: Optional[ManagedKnowledgeAsset] = None
        next_assets: List[ManagedKnowledgeAsset] = []

        for asset in assets:
            if asset.asset_id != asset_id or updated_asset is not None:
                next_assets.append(asset)
                continue

            if asset.library_status == normalized_status:
                updated_asset = asset
                next_assets.append(asset)
                continue

            updated_at = _utc_now_iso()
            payload = asset.to_dict()
            payload.update(
                {
                    "library_status": normalized_status,
                    "updated_at": updated_at,
                    "checked_out_at": updated_at if normalized_status == "checked_out" else None,
                    "last_checked_in_at": updated_at if normalized_status == "checked_in" else asset.last_checked_in_at,
                }
            )
            updated_asset = ManagedKnowledgeAsset(**payload)
            next_assets.append(updated_asset)

        if updated_asset is None:
            return None

        self._save_assets(next_assets)
        return updated_asset

    def _build_asset_markdown(
        self,
        title: str,
        asset_type: str,
        source_label: str,
        description: str,
        summary: str,
        headings: List[str],
        key_points: List[str],
        focus_terms: List[str],
        usage_guidance: List[str],
        tags: List[str],
        created_at: str,
        attributes: Optional[Dict[str, Any]],
        content: str,
    ) -> str:
        normalized_attributes = normalize_knowledge_asset_attributes(attributes or {})
        lines = [f"# {title}", ""]
        lines.append(f"Asset Type: {asset_type}")
        if source_label:
            lines.append(f"Source Label: {source_label}")
        if tags:
            lines.append(f"Tags: {', '.join(tags)}")
        lines.append(f"Imported At: {created_at}")
        lines.append("")
        if description:
            lines.extend(["## Description", "", description, ""])
        if asset_type == "spl_query_library":
            spl_query = _extract_spl_query_identity(asset_type, content, normalized_attributes)
            if spl_query:
                lines.extend(["## Query", "", spl_query, ""])
            intelligence = normalized_attributes.get("spl_intelligence") if isinstance(normalized_attributes.get("spl_intelligence"), dict) else {}
            if intelligence:
                environment_fit = intelligence.get("environment_fit") if isinstance(intelligence.get("environment_fit"), dict) else {}
                validation = intelligence.get("validation") if isinstance(intelligence.get("validation"), dict) else {}
                reuse = intelligence.get("reuse") if isinstance(intelligence.get("reuse"), dict) else {}
                lines.extend(["## Query Intelligence", ""])
                if intelligence.get("query_intent"):
                    lines.append(f"- Intent: {intelligence.get('query_intent')}")
                if intelligence.get("commands"):
                    lines.append(f"- Commands: {', '.join(intelligence.get('commands')[:8])}")
                if intelligence.get("indexes"):
                    lines.append(f"- Indexes: {', '.join(intelligence.get('indexes')[:8])}")
                if intelligence.get("sourcetypes"):
                    lines.append(f"- Sourcetypes: {', '.join(intelligence.get('sourcetypes')[:8])}")
                if environment_fit:
                    lines.append(
                        f"- Environment Fit: {environment_fit.get('status', 'unknown')} ({environment_fit.get('score', 0)}/100)"
                    )
                    if environment_fit.get("reason"):
                        lines.append(f"- Fit Reason: {environment_fit.get('reason')}")
                if validation:
                    lines.append(
                        f"- Validation: {validation.get('status', 'unvalidated')} ({validation.get('success_count', 0)} success / {validation.get('failure_count', 0)} failure)"
                    )
                if reuse:
                    lines.append(
                        f"- Reuse: {reuse.get('tier', 'exploratory')} ({reuse.get('score', 0)}/100)"
                    )
                    if reuse.get("guidance"):
                        lines.append(f"- Reuse Guidance: {reuse.get('guidance')}")
                lines.append("")
        if focus_terms:
            lines.extend(["## Focus Terms", ""])
            lines.extend([f"- {term}" for term in focus_terms])
            lines.append("")
        if key_points:
            lines.extend(["## Key Points", ""])
            lines.extend([f"- {point}" for point in key_points])
            lines.append("")
        if usage_guidance:
            lines.extend(["## Suggested Use", ""])
            lines.extend([f"- {item}" for item in usage_guidance])
            lines.append("")
        if headings:
            lines.extend(["## Headings", ""])
            lines.extend([f"- {heading}" for heading in headings])
            lines.append("")
        context_body = _extract_spl_context_text(content) if asset_type == "spl_query_library" else content.strip()
        lines.extend(["## Summary", "", summary, "", "## Context", "", context_body, ""])
        return "\n".join(lines)

    def _find_existing_import_asset(
        self,
        assets: List[ManagedKnowledgeAsset],
        asset_type: str,
        content: str,
        attributes: Dict[str, Any],
    ) -> Optional[ManagedKnowledgeAsset]:
        incoming_identity = _extract_spl_query_identity(asset_type, content, attributes)
        if not incoming_identity:
            return None

        for asset in assets:
            existing_identity = self._get_asset_import_identity(asset)
            if existing_identity and existing_identity == incoming_identity:
                return asset
        return None

    def _get_asset_import_identity(self, asset: ManagedKnowledgeAsset) -> str:
        stored_content = ""
        if not _normalize_whitespace(asset.attributes.get("spl_query")):
            content_path = self.asset_dir / asset.content_path
            if content_path.exists() and content_path.is_file():
                stored_content = content_path.read_text(encoding="utf-8", errors="ignore")

        return _extract_spl_query_identity(
            asset_type=asset.asset_type,
            content=stored_content,
            attributes=asset.attributes,
        )

    def _load_assets(self) -> List[ManagedKnowledgeAsset]:
        if not self.manifest_path.exists():
            return []
        try:
            payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except Exception:
            return []

        items = payload.get("assets", []) if isinstance(payload, dict) else []
        assets: List[ManagedKnowledgeAsset] = []
        manifest_changed = False
        for item in items:
            if not isinstance(item, dict):
                manifest_changed = True
                continue
            content_path = self.asset_dir / str(item.get("content_path") or "")
            if not content_path.exists() or not content_path.is_file():
                manifest_changed = True
                continue
            try:
                title = str(item.get("title") or "Knowledge Asset")
                asset_type = normalize_knowledge_asset_type(item.get("asset_type"))
                source_label = str(item.get("source_label") or "")
                description = str(item.get("description") or "")
                tags = normalize_knowledge_asset_tags(item.get("tags") or [])
                raw_attributes = item.get("attributes")
                attributes = normalize_knowledge_asset_attributes(raw_attributes)
                stored_text = content_path.read_text(encoding="utf-8", errors="ignore")
                if asset_type != "spl_query_library" and _is_legacy_spl_library_asset(title, tags, stored_text, attributes):
                    legacy_query = _extract_spl_query_identity(asset_type, stored_text, attributes)
                    asset_type = "spl_query_library"
                    next_attributes = dict(attributes)
                    if legacy_query and not _normalize_whitespace(next_attributes.get("spl_query")):
                        next_attributes["spl_query"] = legacy_query
                    attributes = next_attributes
                    manifest_changed = True
                asset_content = _extract_context_body(stored_text) or stored_text
                if asset_type == "spl_query_library":
                    attributes = _carry_forward_spl_validation(attributes, attributes)
                    attributes = _hydrate_spl_library_attributes(
                        attributes,
                        stored_text,
                        _build_environment_profile(self.source_dir),
                    )
                created_at = str(item.get("created_at") or item.get("updated_at") or _utc_now_iso())
                updated_at = str(item.get("updated_at") or created_at)
                raw_library_status = str(item.get("library_status") or "").strip()
                library_status = normalize_knowledge_asset_library_status(raw_library_status)
                checked_out_at = str(item.get("checked_out_at") or "").strip() or None
                last_checked_in_at = str(item.get("last_checked_in_at") or "").strip() or None
                if not raw_library_status or library_status != raw_library_status.replace("-", "_").lower():
                    manifest_changed = True
                if library_status == "checked_out" and checked_out_at is None:
                    checked_out_at = updated_at
                    manifest_changed = True
                if library_status == "checked_in" and last_checked_in_at is None:
                    last_checked_in_at = updated_at
                    manifest_changed = True
                if attributes != (raw_attributes if isinstance(raw_attributes, dict) else {}):
                    manifest_changed = True
                enrichment = _derive_asset_enrichment(
                    title=title,
                    asset_type=asset_type,
                    source_label=source_label,
                    description=description,
                    tags=tags,
                    content=asset_content,
                    attributes=attributes,
                )
                headings = enrichment["headings"]
                key_points = enrichment["key_points"]
                focus_terms = enrichment["focus_terms"]
                usage_guidance = enrichment["usage_guidance"]
                summary = enrichment["summary"]
                preview = enrichment["preview"]
                rebuilt_markdown = self._build_asset_markdown(
                    title=title,
                    asset_type=asset_type,
                    source_label=source_label,
                    description=description,
                    summary=summary,
                    headings=headings,
                    key_points=key_points,
                    focus_terms=focus_terms,
                    usage_guidance=usage_guidance,
                    tags=tags,
                    created_at=created_at,
                    attributes=attributes,
                    content=asset_content,
                )
                derived_changed = (
                    _normalize_string_list(item.get("headings"), limit=6) != headings
                    or _normalize_string_list(item.get("key_points"), limit=4) != key_points
                    or _normalize_string_list(item.get("focus_terms"), limit=8) != focus_terms
                    or _normalize_string_list(item.get("usage_guidance"), limit=4) != usage_guidance
                    or _normalize_whitespace(item.get("summary")) != summary
                    or _normalize_whitespace(item.get("preview")) != preview
                    or stored_text != rebuilt_markdown
                )
                if derived_changed:
                    updated_at = _utc_now_iso()
                    content_path.write_text(rebuilt_markdown, encoding="utf-8")
                    manifest_changed = True
                assets.append(ManagedKnowledgeAsset(
                    asset_id=str(item.get("asset_id") or ""),
                    title=title,
                    asset_type=asset_type,
                    source_label=source_label,
                    description=description,
                    summary=summary,
                    preview=preview,
                    headings=headings,
                    key_points=key_points,
                    focus_terms=focus_terms,
                    usage_guidance=usage_guidance,
                    tags=tags,
                    attributes=attributes,
                    library_status=library_status,
                    checked_out_at=checked_out_at,
                    last_checked_in_at=last_checked_in_at,
                    content_path=content_path.name,
                    import_method=str(item.get("import_method") or "text"),
                    original_filename=item.get("original_filename"),
                    created_at=created_at,
                    updated_at=updated_at,
                    text_char_count=int(item.get("text_char_count") or len(asset_content)),
                    word_count=int(item.get("word_count") or len(re.findall(r"\S+", asset_content))),
                ))
            except Exception:
                manifest_changed = True

        assets.sort(key=lambda asset: asset.updated_at or asset.created_at, reverse=True)
        if manifest_changed:
            self._save_assets(assets)
        return assets

    def _save_assets(self, assets: List[ManagedKnowledgeAsset]) -> None:
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self.manifest_path.write_text(
            json.dumps({"assets": [asset.to_dict() for asset in assets]}, indent=2),
            encoding="utf-8",
        )