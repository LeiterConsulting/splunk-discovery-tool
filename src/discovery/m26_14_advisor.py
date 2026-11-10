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
        "description": "Reads index retention settings and flags indexes that may not keep data as long as M-26-14 requires.",
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
        "description": "Checks the Splunk audit log for sign-ins and admin changes.",
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
        "description": "Looks for network, firewall, proxy, and flow data to estimate how much network traffic Splunk can see.",
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
        "description": "Looks for Splunk role and permission changes to see whether changes to elevated access are logged.",
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
        "description": "Lists recently active hosts so you can review hosts that were added, removed, or changed.",
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
        "title": "Alert and Detection Coverage",
        "control_area": "collection_operations",
        "priority_objective": "cem",
        "required_role": "analyst",
        "execution_mode": "mcp_search",
        "description": "Reviews enabled alerts and scheduled searches to estimate how much alert coverage exists.",
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
        "description": "Checks whether saved searches look for indicators of compromise (IOCs), anomalies, or threat hunting patterns.",
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
        "title": "Timestamp and Data Freshness",
        "control_area": "log_management",
        "priority_objective": "cem",
        "required_role": "analyst",
        "execution_mode": "mcp_search",
        "description": "Uses the last time each host sent data to flag stale data or possible clock problems.",
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
            "message": "No discovery results yet. Run discovery to create a readiness estimate.",
        }

    try:
        blueprint = _read_json_file(latest_blueprint)
    except Exception as exc:
        return {
            "has_data": False,
            "message": f"Could not read the latest discovery results: {exc}",
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
            "message": "The latest discovery results could not be read. Run discovery again to create a readiness estimate.",
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
        "headline": f"The search returned {_count_label(len(normalized_rows), 'row')}." if normalized_rows else "The search returned no rows.",
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
            summary["headline"] = f"{_count_label(len(below_floor), 'index', 'indexes')} keep data for less than 1 year."
            summary["findings"].append("Some indexes may not keep data long enough to meet the M-26-14 requirement that logs stay retrievable for 1 year.")
        elif normalized_rows:
            summary["findings"].append("The returned indexes keep data for about 1 year or longer.")

    elif pack_id == "audit_and_admin_activity":
        has_admin_activity = any(str(row.get("action_group") or "") == "config_change" for row in normalized_rows)
        summary["findings"].append(
            "The audit log shows configuration or account changes." if has_admin_activity else "The audit results did not clearly show configuration changes."
        )
        if not has_admin_activity:
            summary["status"] = "warn"

    elif pack_id == "network_visibility_coverage":
        if normalized_rows:
            summary["findings"].append("Recent network data was found.")
        else:
            summary["status"] = "gap"
            summary["headline"] = "No network data was found."

    elif pack_id == "alert_and_detection_posture":
        security_alert_rows = [
            row for row in normalized_rows if str(row.get("detection_hint") or "").strip().lower() == "security_or_compliance"
        ]
        if security_alert_rows:
            summary["findings"].append("Enabled security or compliance alerts were found.")
        else:
            summary["status"] = "warn"
            summary["headline"] = "No clearly security-related alerts were found."

    elif pack_id == "ioc_and_anomaly_signals":
        matched_rows = [
            row for row in normalized_rows if str(row.get("signal_hint") or "").strip().lower() in {"matching_logic", "matching_title"}
        ]
        if matched_rows:
            summary["findings"].append("Some saved searches look for IOCs or anomalies.")
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
            summary["headline"] = f"{_count_label(len(stale_rows), 'host')} last sent data more than 24 hours ago."
        elif normalized_rows:
            summary["findings"].append("The sampled hosts sent data recently.")

    if not summary["findings"]:
        summary["findings"].append("Review the returned rows to see which fields are present and whether the results are typical for this environment.")

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
        "Discovery does not measure hardware and software asset coverage (HWAM, SWAM, or CDM), which formal M-26-14 inventory scoring needs.",
    ]
    if host_count > 0:
        evidence.append(f"Discovery saw {_count_label(host_count, 'host')} sending data.")
    if source_count > 0:
        evidence.append(f"Discovery saw {_count_label(source_count, 'data source')}, which shows what data Splunk can see.")
    return _build_signal(
        "inventory_visibility",
        status="unknown" if evidence else "gap",
        confidence="low",
        estimated_level=None,
        evidence=evidence,
        gaps=[] if evidence else ["Discovery did not find any hosts sending data."],
        unknowns=unknowns,
        remediation=["Add asset inventory data (HWAM or SWAM), or run a live check that estimates asset coverage."],
    )


def _build_collection_coverage_signal(overview: Dict[str, Any], classifications: Dict[str, Dict[str, Any]], text_corpus: str) -> Dict[str, Any]:
    security_source_count = _safe_int(classifications.get("security", {}).get("source_count"))
    compliance_source_count = _safe_int(classifications.get("compliance", {}).get("source_count"))
    total_indexes = _safe_int(overview.get("total_indexes"))
    evidence = []
    gaps = []
    if total_indexes > 0:
        evidence.append(f"Discovery found {_count_label(total_indexes, 'index', 'indexes')} that hold data relevant to M-26-14.")
    if security_source_count > 0:
        evidence.append(f"Discovery classified {_count_label(security_source_count, 'data source')} as security data.")
    if compliance_source_count > 0:
        evidence.append(f"Discovery classified {_count_label(compliance_source_count, 'data source')} as compliance data.")
    if security_source_count <= 0:
        gaps.append("Discovery did not classify any data sources as security data.")
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
            "Discovery cannot show what share of all assets send logs you can search and retrieve.",
        ],
        remediation=[
            "Run the network, audit, and infrastructure live checks to confirm coverage with current data.",
        ],
    )


def _build_collection_operations_signal(trend_signals: Dict[str, Any], recommendations: List[Dict[str, Any]], text_corpus: str) -> Dict[str, Any]:
    evidence = []
    gaps = []
    security_recommendations = _safe_int((trend_signals.get("recommendation_by_domain") or {}).get("security"))
    compliance_recommendations = _safe_int((trend_signals.get("recommendation_by_domain") or {}).get("compliance"))
    if any(term in text_corpus for term in ["alert", "anomal", "ioc", "threat", "hunt"]):
        evidence.append("Discovery findings mention alerts, anomalies, IOCs, or threat hunting.")
    if security_recommendations > 0 or compliance_recommendations > 0:
        evidence.append(
            f"Discovery made {_count_label(security_recommendations + compliance_recommendations, 'security or compliance recommendation')} you can turn into detections and checks."
        )
    if not any(term in text_corpus for term in ["alert", "anomal", "ioc", "threat", "hunt"]):
        gaps.append("Discovery found little evidence of detection work, such as alerts or threat hunting searches.")
    status = "partial" if evidence else "gap"
    return _build_signal(
        "collection_operations",
        status=status,
        confidence="low",
        estimated_level=1 if evidence else 0,
        evidence=evidence,
        gaps=gaps,
        unknowns=[
            "Discovery does not measure detection quality, alert tuning, or how often the SOC reuses searches in investigations.",
        ],
        remediation=[
            "Run the alert, IOC, and privilege change live checks to confirm detections are in place.",
        ],
    )


def _build_data_retention_signal(text_corpus: str, coverage_gaps: List[Dict[str, Any]]) -> Dict[str, Any]:
    evidence = []
    gaps = []
    if "long retention" in text_corpus:
        evidence.append("Discovery found at least one index with long retention.")
    if any(term in text_corpus for term in ["short retention", "retention policy", "retention_optimization", "compliance risk"]):
        gaps.append("Discovery findings suggest some indexes may not keep data as long as M-26-14 requires.")
    if not evidence and not gaps:
        gaps.append("Discovery has no direct evidence that logs stay searchable for 6 months and retrievable for 1 year.")
    status = "gap" if gaps else "partial"
    return _build_signal(
        "data_retention",
        status=status,
        confidence="low" if evidence else "very_low",
        estimated_level=0 if gaps else 1,
        evidence=evidence,
        gaps=gaps,
        unknowns=[
            "Discovery results alone cannot tell which data stays searchable and which can only be restored from archive.",
        ],
        remediation=[
            "Run the Retention and Searchability live check before you assign a maturity level.",
        ],
    )


def _build_log_management_signal(text_corpus: str) -> Dict[str, Any]:
    evidence = []
    gaps = []
    if any(term in text_corpus for term in ["audit", "security monitoring", "compliance monitoring"]):
        evidence.append("Discovery shows that some audit or compliance data is already collected.")
    gaps.append("Discovery cannot confirm that logs are encrypted at rest and in transit, protected by hashes, or limited to authorized users.")
    return _build_signal(
        "log_management",
        status="unknown" if evidence else "gap",
        confidence="very_low",
        estimated_level=None,
        evidence=evidence,
        gaps=gaps,
        unknowns=[
            "Formal log management scoring needs evidence about storage, encryption, and access control that discovery does not collect.",
        ],
        remediation=[
            "Run the live checks and review the architecture to confirm transport security, storage controls, and SOC access.",
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
        evidence.append("Discovery findings show some real-time monitoring and threat detection.")
    if objective == "thirf" and any(term in text_corpus for term in ["investigat", "retention", "ioc", "lateral", "forensic"]):
        evidence.append("Discovery findings show some investigation and retention capability.")
    return {
        "objective": objective.upper(),
        "status": status,
        "confidence": "low",
        "evidence": evidence,
        "notes": [
            "This status comes from discovery results. Run live checks to confirm it.",
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
            "explanation": "Discovery results alone are not enough to set a maturity level.",
        }
    level_floor = min(int(level) for level in known_levels)
    return {
        "status": f"level_{level_floor}",
        "level": level_floor,
        "explanation": "The lowest maturity level across the scored areas.",
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


def _count_label(count: int, singular: str, plural: Optional[str] = None) -> str:
    return f"{count} {singular if count == 1 else (plural or f'{singular}s')}"


def _safe_int(value: Any) -> int:
    try:
        if value in (None, ""):
            return 0
        return int(float(value))
    except Exception:
        return 0