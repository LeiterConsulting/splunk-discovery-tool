"""M-26-14 advisory rubric, validation catalog, and discovery-backed profile helpers."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Optional


_MATURITY_ELEMENT_LABELS = {
    "inventory_visibility": "Inventory Visibility",
    "collection_coverage": "Collection Coverage",
    "collection_operations": "Collection Operations",
    "data_retention": "Data Retention",
    "log_management": "Log Management",
}

_CURATED_VALIDATION_PACKS: List[Dict[str, Any]] = [
    {
        "id": "retention_and_searchability",
        "title": "Retention and Searchability",
        "control_area": "data_retention",
        "priority_objective": "thirf",
        "required_role": "analyst",
        "execution_mode": "mcp_search",
        "description": "Approximate retention coverage from Splunk index settings and flag indexes that appear short for M-26-14 expectations.",
        "query": (
            "| rest /services/data/indexes splunk_server=local "
            "| eval retention_days=round(frozenTimePeriodInSecs/86400,1) "
            "| eval retention_status=case(retention_days>=365, \"meets_retrievable_floor\", retention_days>=180, \"below_retrievable_floor\", 1=1, \"critical_gap\") "
            "| table title homePath coldPath thawedPath retention_days retention_status maxDataSize maxHotBuckets"
        ),
        "expected_evidence": [
            "Indexes with at least 365 days of configured retention approximate the one-year retrievable floor.",
            "Indexes under 180 days indicate likely M-26-14 retention gaps for affected data sets.",
        ],
        "limitations": [
            "Index settings approximate retrievable retention and do not prove six months of immediately searchable storage.",
            "Hot, warm, and cold tier design still requires architecture review outside the search result itself.",
        ],
    },
    {
        "id": "audit_and_admin_activity",
        "title": "Audit and Admin Activity Coverage",
        "control_area": "collection_operations",
        "priority_objective": "cem",
        "required_role": "analyst",
        "execution_mode": "mcp_search",
        "description": "Check for live audit visibility into authentication and administrative actions.",
        "query": (
            "search index=_audit earliest=-30d "
            "| eval action_group=case(match(action, \"login|logout|authentication\"), \"auth\", match(action, \"edit|create|delete|update|enable|disable\"), \"config_change\", 1=1, \"other\") "
            "| stats count dc(user) as distinct_users values(info) as infos by action_group action "
            "| sort - count"
        ),
        "expected_evidence": [
            "Authentication and configuration actions in _audit indicate baseline identity and admin-event collection.",
            "Distinct user counts help confirm that audit activity is not isolated to one administrative account.",
        ],
        "limitations": [
            "This validates Splunk audit activity, not enterprise-wide application or infrastructure audit completeness.",
        ],
    },
    {
        "id": "network_visibility_coverage",
        "title": "Network Visibility Coverage",
        "control_area": "collection_coverage",
        "priority_objective": "cem",
        "required_role": "analyst",
        "execution_mode": "mcp_search",
        "description": "Look for common network, firewall, proxy, and flow-oriented sourcetypes to estimate source and destination visibility.",
        "query": (
            "| metadata type=sourcetypes index=* "
            "| eval network_hint=if(match(lower(sourcetype), \"netflow|zeek|suricata|firewall|proxy|pan:traffic|stream:http|stream:tcp|ids|ips\"), 1, 0) "
            "| where network_hint=1 "
            "| eval last_seen_hours=round((now()-lastTime)/3600,2) "
            "| table sourcetype totalCount firstTime lastTime last_seen_hours"
        ),
        "expected_evidence": [
            "Recent network-oriented sourcetypes support M-26-14 source and destination telemetry objectives.",
            "Last-seen timing helps distinguish active collection from historical remnants.",
        ],
        "limitations": [
            "Sourcetype presence does not prove protocol, port, and session-attribute completeness for every asset class.",
        ],
    },
    {
        "id": "privileged_change_monitoring",
        "title": "Privileged Change Monitoring",
        "control_area": "collection_operations",
        "priority_objective": "cem",
        "required_role": "analyst",
        "execution_mode": "mcp_search",
        "description": "Look for Splunk-side role and privilege administration events that indicate change visibility around elevated access.",
        "query": (
            "search index=_audit earliest=-30d (action=edit_* OR action=create_* OR action=grant_* OR action=remove_*) "
            "| eval privilege_hint=if(match(lower(info), \"role|capab|permission|sharing|owner\"), \"privilege_related\", \"other\") "
            "| stats count values(user) as actors values(object) as objects by action privilege_hint info "
            "| sort - count"
        ),
        "expected_evidence": [
            "Privilege-related audit entries indicate at least local visibility into access and role changes.",
        ],
        "limitations": [
            "This does not validate identity-provider, operating-system, or cloud privilege changes unless those logs are also ingested elsewhere.",
        ],
    },
    {
        "id": "infrastructure_change_visibility",
        "title": "Infrastructure Change Visibility",
        "control_area": "collection_coverage",
        "priority_objective": "thirf",
        "required_role": "analyst",
        "execution_mode": "mcp_search",
        "description": "Check for recent host and source churn to support endpoint addition, removal, and modification review.",
        "query": (
            "| metadata type=hosts index=* "
            "| eval last_seen_hours=round((now()-lastTime)/3600,2) "
            "| sort - lastTime "
            "| head 200 "
            "| table host firstTime lastTime last_seen_hours totalCount"
        ),
        "expected_evidence": [
            "Recent host metadata provides a starting point for observed infrastructure presence and recency.",
        ],
        "limitations": [
            "Host metadata is not equivalent to a centralized HWAM or SWAM inventory and cannot prove asset completeness on its own.",
        ],
    },
    {
        "id": "alert_and_detection_posture",
        "title": "Alert and Detection Posture",
        "control_area": "collection_operations",
        "priority_objective": "cem",
        "required_role": "analyst",
        "execution_mode": "mcp_search",
        "description": "Inspect enabled saved searches and notable-alert style content as a proxy for actionable alert coverage.",
        "query": (
            "| rest /servicesNS/-/-/saved/searches splunk_server=local "
            "| eval is_alert=if(alert_type!=\"always\" OR is_scheduled=1, 1, 0) "
            "| where disabled=0 AND is_alert=1 "
            "| eval detection_hint=case(match(lower(title), \"anomal|threat|ioc|malware|privilege|audit|network|firewall|lateral\"), \"security_or_compliance\", 1=1, \"other\") "
            "| stats count by detection_hint alert_type"
        ),
        "expected_evidence": [
            "Enabled alerts with security or compliance-oriented titles indicate some operational detection coverage.",
        ],
        "limitations": [
            "Alert counts and titles do not prove alert quality, tuning depth, or outcome-based coverage percentages.",
        ],
    },
    {
        "id": "ioc_and_anomaly_signals",
        "title": "IOC and Anomaly Signals",
        "control_area": "collection_operations",
        "priority_objective": "thirf",
        "required_role": "analyst",
        "execution_mode": "mcp_search",
        "description": "Estimate whether stored detections reference IOC, anomaly, or hunting language that aligns with M-26-14 objectives.",
        "query": (
            "| rest /servicesNS/-/-/saved/searches splunk_server=local "
            "| search disabled=0 "
            "| eval signal_hint=case(match(lower(search), \"ioc|indicator of compromise|anomal|rare|outlier|risk|threat|hunt\"), \"matching_logic\", match(lower(title), \"ioc|anomal|hunt|threat\"), \"matching_title\", 1=1, \"none\") "
            "| stats count values(title) as sample_titles by signal_hint"
        ),
        "expected_evidence": [
            "Search content referencing IOC or anomaly logic supports monitoring and hunting alignment.",
        ],
        "limitations": [
            "Keyword inspection is only a proxy and cannot certify true detection efficacy.",
        ],
    },
    {
        "id": "timestamp_freshness_sanity",
        "title": "Timestamp and Freshness Sanity",
        "control_area": "log_management",
        "priority_objective": "cem",
        "required_role": "analyst",
        "execution_mode": "mcp_search",
        "description": "Use recent host activity as a basic freshness check to flag potential time drift or stale ingest paths.",
        "query": (
            "| metadata type=hosts index=* "
            "| eval last_seen_minutes=round((now()-lastTime)/60,1) "
            "| where last_seen_minutes>=0 "
            "| sort - last_seen_minutes "
            "| head 50 "
            "| table host last_seen_minutes totalCount"
        ),
        "expected_evidence": [
            "Unexpected last-seen gaps can indicate stale telemetry, delayed forwarding, or timestamp problems that warrant review.",
        ],
        "limitations": [
            "This is a freshness heuristic and does not prove NTP or authoritative time synchronization compliance.",
        ],
    },
]


def list_validation_packs() -> List[Dict[str, Any]]:
    """Return a copy of the curated M-26-14 validation pack catalog."""
    return deepcopy(_CURATED_VALIDATION_PACKS)


def get_validation_pack(pack_id: str) -> Optional[Dict[str, Any]]:
    """Return one curated validation pack by identifier."""
    normalized_pack_id = str(pack_id or "").strip()
    for pack in _CURATED_VALIDATION_PACKS:
        if pack.get("id") == normalized_pack_id:
            return deepcopy(pack)
    return None


def build_capability_state_snapshot(config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build lightweight capability summary state for the advisor workspace."""
    normalized_config = dict(config or {})
    output_dir = Path(str(normalized_config.get("output_dir") or "output"))
    cache_dir = Path(str(normalized_config.get("profile_cache_dir") or output_dir / "m26_14"))
    latest_blueprint = _find_latest_blueprint(output_dir)
    validation_packs = list_validation_packs()
    return {
        "framework": "OMB M-26-14",
        "non_authoritative": True,
        "output_dir": str(output_dir),
        "profile_cache_dir": str(cache_dir),
        "validation_pack_count": len(validation_packs),
        "validation_control_areas": sorted(
            {str(pack.get("control_area") or "").strip() for pack in validation_packs if str(pack.get("control_area") or "").strip()}
        ),
        "has_discovery_blueprint": latest_blueprint is not None,
        "latest_discovery_blueprint": latest_blueprint.name if latest_blueprint else None,
        "allow_bespoke_follow_up": bool(normalized_config.get("allow_bespoke_follow_up", True)),
        "require_live_validation_confirmation": bool(normalized_config.get("require_live_validation_confirmation", True)),
        "live_validation_limit": max(1, int(normalized_config.get("live_validation_limit", 6) or 6)),
    }


def build_latest_profile_preview(output_dir: Optional[Path | str] = None) -> Dict[str, Any]:
    """Build a lightweight preview profile from the most recent V2 blueprint if available."""
    normalized_output_dir = Path(str(output_dir or "output"))
    latest_blueprint = _find_latest_blueprint(normalized_output_dir)
    if latest_blueprint is None:
        return {
            "has_data": False,
            "message": "No discovery blueprint available for M-26-14 profiling.",
        }

    try:
        blueprint = _read_json_file(latest_blueprint)
    except Exception as exc:
        return {
            "has_data": False,
            "message": f"Failed to read discovery blueprint: {exc}",
            "artifact": {"name": latest_blueprint.name},
        }

    profile = build_profile_from_blueprint(blueprint)
    profile["artifact"] = {"name": latest_blueprint.name}
    return profile


def build_profile_from_blueprint(blueprint: Dict[str, Any]) -> Dict[str, Any]:
    """Derive a non-authoritative M-26-14 profile from a persisted V2 discovery blueprint."""
    if not isinstance(blueprint, dict):
        return {
            "has_data": False,
            "message": "M-26-14 profile generation requires a dictionary-like V2 blueprint.",
        }

    overview = blueprint.get("overview", {}) if isinstance(blueprint.get("overview"), dict) else {}
    classifications = _normalize_classification_map(blueprint.get("classification_map", {}))
    trend_signals = blueprint.get("trend_signals", {}) if isinstance(blueprint.get("trend_signals"), dict) else {}
    coverage_gaps = blueprint.get("coverage_gaps", []) if isinstance(blueprint.get("coverage_gaps"), list) else []
    recommendations = blueprint.get("recommendations", []) if isinstance(blueprint.get("recommendations"), list) else []
    text_corpus = _collect_text_corpus(blueprint)

    inventory_signal = _build_inventory_visibility_signal(overview, text_corpus)
    coverage_signal = _build_collection_coverage_signal(overview, classifications, text_corpus)
    operations_signal = _build_collection_operations_signal(trend_signals, recommendations, text_corpus)
    retention_signal = _build_data_retention_signal(text_corpus, coverage_gaps)
    log_management_signal = _build_log_management_signal(text_corpus)

    maturity_elements = [
        inventory_signal,
        coverage_signal,
        operations_signal,
        retention_signal,
        log_management_signal,
    ]

    evidence_count = sum(len(element.get("evidence", [])) for element in maturity_elements)
    gap_count = sum(1 for element in maturity_elements if element.get("status") == "gap")
    unknown_count = sum(1 for element in maturity_elements if element.get("status") == "unknown")

    readiness_estimate = max(
        0,
        min(
            100,
            34 + min(30, evidence_count * 5) - min(26, gap_count * 10) - min(20, unknown_count * 4),
        ),
    )

    maturity_floor = _derive_maturity_floor(maturity_elements)
    cem_signal = _build_priority_objective_signal(
        "cem",
        readiness_estimate,
        text_corpus,
        [coverage_signal, operations_signal, log_management_signal],
    )
    thirf_signal = _build_priority_objective_signal(
        "thirf",
        readiness_estimate,
        text_corpus,
        [coverage_signal, retention_signal, log_management_signal],
    )

    return {
        "has_data": True,
        "framework": "OMB M-26-14",
        "non_authoritative": True,
        "readiness_estimate": readiness_estimate,
        "confidence": _derive_confidence(evidence_count, gap_count, unknown_count),
        "maturity_floor": maturity_floor,
        "priority_objectives": {
            "cem": cem_signal,
            "thirf": thirf_signal,
        },
        "maturity_elements": maturity_elements,
        "live_validation": {
            "curated_pack_count": len(_CURATED_VALIDATION_PACKS),
            "recommended_pack_ids": _build_recommended_pack_ids(maturity_elements),
        },
        "source_summary": {
            "total_indexes": _safe_int(overview.get("total_indexes")),
            "total_hosts": _safe_int(overview.get("total_hosts")),
            "total_sources": _safe_int(overview.get("total_sources")),
            "security_source_count": _safe_int(classifications.get("security", {}).get("source_count")),
            "compliance_source_count": _safe_int(classifications.get("compliance", {}).get("source_count")),
        },
    }


def summarize_validation_results(pack: Dict[str, Any], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize one curated validation result set for immediate UI rendering."""
    normalized_pack = pack if isinstance(pack, dict) else {}
    normalized_rows = [row for row in (rows or []) if isinstance(row, dict)]
    pack_id = str(normalized_pack.get("id") or "").strip()
    summary = {
        "status": "observed" if normalized_rows else "warn",
        "row_count": len(normalized_rows),
        "headline": f"Returned {len(normalized_rows)} result row(s)." if normalized_rows else "No result rows returned.",
        "findings": [],
        "sample_rows": normalized_rows[:5],
        "sample_fields": sorted(list(normalized_rows[0].keys()))[:8] if normalized_rows else [],
    }

    if pack_id == "retention_and_searchability":
        below_floor = [
            row
            for row in normalized_rows
            if str(row.get("retention_status") or "").strip().lower() in {"below_retrievable_floor", "critical_gap"}
        ]
        if below_floor:
            summary["status"] = "gap"
            summary["headline"] = f"{len(below_floor)} index entries appear below the one-year retrievable floor."
            summary["findings"].append("Configured index retention suggests at least some data sets may fall short of the M-26-14 retrievable baseline.")
        elif normalized_rows:
            summary["findings"].append("Observed index settings meet or approximate the one-year retrievable floor for the returned rows.")

    elif pack_id == "audit_and_admin_activity":
        has_admin_activity = any(str(row.get("action_group") or "") == "config_change" for row in normalized_rows)
        summary["findings"].append(
            "Audit rows include configuration or identity activity." if has_admin_activity else "Returned audit rows did not clearly show configuration-change activity."
        )
        if not has_admin_activity:
            summary["status"] = "warn"

    elif pack_id == "network_visibility_coverage":
        if normalized_rows:
            summary["findings"].append("Network-oriented sourcetypes were observed in recent metadata.")
        else:
            summary["status"] = "gap"
            summary["headline"] = "No network-oriented sourcetypes matched the curated coverage probe."

    elif pack_id == "alert_and_detection_posture":
        security_alert_rows = [
            row for row in normalized_rows if str(row.get("detection_hint") or "").strip().lower() == "security_or_compliance"
        ]
        if security_alert_rows:
            summary["findings"].append("Enabled security or compliance-oriented alert definitions were observed.")
        else:
            summary["status"] = "warn"
            summary["headline"] = "No clearly security-oriented alert definitions were returned by the curated probe."

    elif pack_id == "ioc_and_anomaly_signals":
        matched_rows = [
            row for row in normalized_rows if str(row.get("signal_hint") or "").strip().lower() in {"matching_logic", "matching_title"}
        ]
        if matched_rows:
            summary["findings"].append("Saved search content includes IOC or anomaly-related hints.")
        else:
            summary["status"] = "warn"

    elif pack_id == "timestamp_freshness_sanity":
        stale_rows = [
            row
            for row in normalized_rows
            if _safe_int(row.get("last_seen_minutes")) > 1440
        ]
        if stale_rows:
            summary["status"] = "warn"
            summary["headline"] = f"{len(stale_rows)} hosts were last seen more than 24 hours ago in the sampled result."
        elif normalized_rows:
            summary["findings"].append("Sampled host metadata appears reasonably fresh.")

    if not summary["findings"]:
        summary["findings"].append("Use the returned rows to inspect field coverage and confirm whether the observed evidence is representative.")

    return summary


def _find_latest_blueprint(output_dir: Path) -> Optional[Path]:
    if not output_dir.exists():
        return None
    matches = sorted(output_dir.glob("v2_intelligence_blueprint_*.json"), reverse=True)
    return matches[0] if matches else None


def _read_json_file(path: Path) -> Dict[str, Any]:
    import json

    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return payload if isinstance(payload, dict) else {}


def _normalize_classification_map(value: Any) -> Dict[str, Dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    normalized: Dict[str, Dict[str, Any]] = {}
    for key, payload in value.items():
        normalized[str(key or "").strip().lower()] = payload if isinstance(payload, dict) else {}
    return normalized


def _collect_text_corpus(blueprint: Dict[str, Any]) -> str:
    parts: List[str] = []
    for gap in blueprint.get("coverage_gaps", []) if isinstance(blueprint.get("coverage_gaps"), list) else []:
        if isinstance(gap, dict):
            parts.extend([str(gap.get("gap") or ""), str(gap.get("why_it_matters") or "")])
    for recommendation in blueprint.get("recommendations", []) if isinstance(blueprint.get("recommendations"), list) else []:
        if isinstance(recommendation, dict):
            parts.extend(
                [
                    str(recommendation.get("title") or ""),
                    str(recommendation.get("description") or ""),
                    str(recommendation.get("category") or ""),
                ]
            )
    for entry in blueprint.get("finding_ledger", []) if isinstance(blueprint.get("finding_ledger"), list) else []:
        if not isinstance(entry, dict):
            continue
        parts.append(str(entry.get("title") or ""))
        for finding in entry.get("findings", []) if isinstance(entry.get("findings"), list) else []:
            parts.append(str(finding or ""))
    return "\n".join(part for part in parts if part).lower()


def _build_inventory_visibility_signal(overview: Dict[str, Any], text_corpus: str) -> Dict[str, Any]:
    host_count = _safe_int(overview.get("total_hosts"))
    source_count = _safe_int(overview.get("total_sources"))
    evidence = []
    unknowns = [
        "Discovery results do not currently include HWAM, SWAM, or CDM coverage percentages required for formal M-26-14 inventory maturity scoring.",
    ]
    if host_count > 0:
        evidence.append(f"Discovery observed {host_count} hosts across the current telemetry footprint.")
    if source_count > 0:
        evidence.append(f"Discovery observed {source_count} source paths, which helps bound visible telemetry sources.")
    return _build_signal(
        "inventory_visibility",
        status="unknown" if evidence else "gap",
        confidence="low",
        estimated_level=None,
        evidence=evidence,
        gaps=[] if evidence else ["No telemetry-backed asset footprint was visible in the current discovery artifact."],
        unknowns=unknowns,
        remediation=["Add centralized HWAM or SWAM evidence or a live validation path that approximates asset coverage."],
    )


def _build_collection_coverage_signal(overview: Dict[str, Any], classifications: Dict[str, Dict[str, Any]], text_corpus: str) -> Dict[str, Any]:
    security_source_count = _safe_int(classifications.get("security", {}).get("source_count"))
    compliance_source_count = _safe_int(classifications.get("compliance", {}).get("source_count"))
    total_indexes = _safe_int(overview.get("total_indexes"))
    evidence = []
    gaps = []
    if total_indexes > 0:
        evidence.append(f"Discovery observed {total_indexes} indexes that can contribute telemetry to M-26-14-aligned controls.")
    if security_source_count > 0:
        evidence.append(f"Discovery classified {security_source_count} security-oriented data sources.")
    if compliance_source_count > 0:
        evidence.append(f"Discovery classified {compliance_source_count} compliance-oriented data sources.")
    if security_source_count <= 0:
        gaps.append("No discovery-classified security sources were observed in the current blueprint.")
    status = "partial" if evidence and not gaps else "gap" if gaps and not evidence else "unknown"
    if evidence and gaps:
        status = "partial"
    return _build_signal(
        "collection_coverage",
        status=status,
        confidence="low" if status == "partial" else "very_low",
        estimated_level=1 if status == "partial" and security_source_count > 0 else None,
        evidence=evidence,
        gaps=gaps,
        unknowns=[
            "Discovery does not prove what percentage of all assets have searchable and retrievable logging coverage.",
        ],
        remediation=[
            "Run curated network, audit, and infrastructure validation packs to replace source-presence heuristics with fresher evidence.",
        ],
    )


def _build_collection_operations_signal(trend_signals: Dict[str, Any], recommendations: List[Dict[str, Any]], text_corpus: str) -> Dict[str, Any]:
    evidence = []
    gaps = []
    security_recommendations = _safe_int((trend_signals.get("recommendation_by_domain") or {}).get("security"))
    compliance_recommendations = _safe_int((trend_signals.get("recommendation_by_domain") or {}).get("compliance"))
    if any(term in text_corpus for term in ["alert", "anomal", "ioc", "threat", "hunt"]):
        evidence.append("Discovery findings reference alerting, anomaly, IOC, or hunting-oriented language.")
    if security_recommendations > 0 or compliance_recommendations > 0:
        evidence.append(
            f"Discovery produced {security_recommendations + compliance_recommendations} security or compliance recommendations that can be turned into detection and validation tracks."
        )
    if not any(term in text_corpus for term in ["alert", "anomal", "ioc", "threat", "hunt"]):
        gaps.append("Discovery artifacts do not yet show strong detection-language evidence for M-26-14 collection operations.")
    status = "partial" if evidence else "gap"
    return _build_signal(
        "collection_operations",
        status=status,
        confidence="low",
        estimated_level=1 if evidence else 0,
        evidence=evidence,
        gaps=gaps,
        unknowns=[
            "Detection quality, tuned alert coverage percentages, and SOC investigation reuse are not directly measured in the current blueprint.",
        ],
        remediation=[
            "Run curated alert, IOC, and privilege-change validation packs to confirm that operational controls exist beyond narrative hints.",
        ],
    )


def _build_data_retention_signal(text_corpus: str, coverage_gaps: List[Dict[str, Any]]) -> Dict[str, Any]:
    evidence = []
    gaps = []
    if "long retention" in text_corpus:
        evidence.append("Discovery findings include at least one index with longer retention settings.")
    if any(term in text_corpus for term in ["short retention", "retention policy", "retention_optimization", "compliance risk"]):
        gaps.append("Discovery findings already suggest retention settings may not satisfy the M-26-14 baseline for all data sets.")
    if not evidence and not gaps:
        gaps.append("No direct discovery evidence yet proves six months searchable and one year retrievable retention coverage.")
    status = "gap" if gaps else "partial"
    return _build_signal(
        "data_retention",
        status=status,
        confidence="low" if evidence else "very_low",
        estimated_level=0 if gaps else 1,
        evidence=evidence,
        gaps=gaps,
        unknowns=[
            "Searchable-versus-retrievable retention tiers are not fully inferable from the current discovery artifact alone.",
        ],
        remediation=[
            "Run the curated retention and searchability validation pack before assigning an implementation maturity level.",
        ],
    )


def _build_log_management_signal(text_corpus: str) -> Dict[str, Any]:
    evidence = []
    gaps = []
    if any(term in text_corpus for term in ["audit", "security monitoring", "compliance monitoring"]):
        evidence.append("Discovery artifacts indicate that some audit or compliance-oriented telemetry is already being ingested.")
    gaps.append("The current blueprint does not prove encryption-at-rest, encryption-in-transit, hash veracity, or privileged access workflows for logs.")
    return _build_signal(
        "log_management",
        status="unknown" if evidence else "gap",
        confidence="very_low",
        estimated_level=None,
        evidence=evidence,
        gaps=gaps,
        unknowns=[
            "Formal log-management maturity requires storage, encryption, and access-control evidence not present in current discovery artifacts.",
        ],
        remediation=[
            "Use curated live validation plus architecture review to verify transport security, storage controls, and SOC access design.",
        ],
    )


def _build_priority_objective_signal(
    objective: str,
    readiness_estimate: int,
    text_corpus: str,
    contributing_elements: List[Dict[str, Any]],
) -> Dict[str, Any]:
    status = "partial" if any(item.get("status") == "partial" for item in contributing_elements) else "unknown"
    if any(item.get("status") == "gap" for item in contributing_elements):
        status = "gap" if status != "partial" else "partial"
    evidence = []
    if objective == "cem" and any(term in text_corpus for term in ["alert", "anomal", "threat", "network"]):
        evidence.append("Discovery findings suggest some real-time monitoring and threat-detection signal is present.")
    if objective == "thirf" and any(term in text_corpus for term in ["investigat", "retention", "ioc", "lateral", "forensic"]):
        evidence.append("Discovery findings suggest some investigative and retention-oriented capability signal is present.")
    return {
        "objective": objective.upper(),
        "status": status,
        "confidence": "low",
        "evidence": evidence,
        "notes": [
            "Priority-objective status is derived from discovery evidence and should be strengthened with explicit live validation.",
        ],
    }


def _build_signal(
    element_id: str,
    *,
    status: str,
    confidence: str,
    estimated_level: Optional[int],
    evidence: List[str],
    gaps: List[str],
    unknowns: List[str],
    remediation: List[str],
) -> Dict[str, Any]:
    return {
        "id": element_id,
        "label": _MATURITY_ELEMENT_LABELS.get(element_id, element_id.replace("_", " ").title()),
        "status": status,
        "confidence": confidence,
        "estimated_level_floor": estimated_level,
        "evidence": evidence,
        "gaps": gaps,
        "unknowns": unknowns,
        "remediation": remediation,
    }


def _derive_maturity_floor(maturity_elements: List[Dict[str, Any]]) -> Dict[str, Any]:
    known_levels = [element.get("estimated_level_floor") for element in maturity_elements if element.get("estimated_level_floor") is not None]
    if not known_levels:
        return {
            "status": "unknown",
            "level": None,
            "explanation": "Discovery evidence alone does not yet prove a defensible M-26-14 maturity floor.",
        }
    level_floor = min(int(level) for level in known_levels)
    return {
        "status": f"level_{level_floor}",
        "level": level_floor,
        "explanation": "Lowest evidentiary maturity floor across currently scored elements.",
    }


def _derive_confidence(evidence_count: int, gap_count: int, unknown_count: int) -> str:
    if evidence_count >= 8 and gap_count <= 1 and unknown_count <= 1:
        return "medium"
    if evidence_count >= 4 and gap_count <= 2:
        return "low"
    return "very_low"


def _build_recommended_pack_ids(maturity_elements: List[Dict[str, Any]]) -> List[str]:
    recommended = []
    if any(element.get("id") == "data_retention" and element.get("status") in {"gap", "unknown"} for element in maturity_elements):
        recommended.append("retention_and_searchability")
    if any(element.get("id") == "collection_coverage" and element.get("status") in {"gap", "unknown"} for element in maturity_elements):
        recommended.extend(["network_visibility_coverage", "infrastructure_change_visibility"])
    if any(element.get("id") == "collection_operations" and element.get("status") in {"gap", "unknown"} for element in maturity_elements):
        recommended.extend(["audit_and_admin_activity", "alert_and_detection_posture", "ioc_and_anomaly_signals"])
    if any(element.get("id") == "log_management" and element.get("status") in {"gap", "unknown"} for element in maturity_elements):
        recommended.append("timestamp_freshness_sanity")

    deduped = []
    for pack_id in recommended:
        if pack_id not in deduped:
            deduped.append(pack_id)
    return deduped[:6]


def _safe_int(value: Any) -> int:
    try:
        if value in (None, ""):
            return 0
        return int(float(value))
    except Exception:
        return 0