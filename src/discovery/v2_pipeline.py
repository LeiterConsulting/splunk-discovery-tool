"""
Discovery pipeline for Splunk Discovery Tool.

This module defines a modern, developer-friendly discovery execution path that:
- runs purposeful phases with explicit intent,
- produces reusable intelligence artifacts,
- exports a structured session bundle for downstream apps.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from discovery.local_analyzer import (
    KIND_HOST,
    KIND_INDEX,
    KIND_INDEX_DETAIL,
    KIND_KNOWLEDGE_OBJECT,
    KIND_KV_COLLECTION,
    KIND_SOURCE,
    KIND_SOURCETYPE,
    KIND_USER,
    result_kind,
    safe_int,
)


LEDGER_MAX_PER_KIND = 200
LEDGER_LIST_CAP = 200
INVENTORY_NAME_CAP = 1000
CAPPED_LEDGER_KINDS = {
    KIND_INDEX,
    KIND_SOURCETYPE,
    KIND_HOST,
    KIND_SOURCE,
    KIND_KNOWLEDGE_OBJECT,
    KIND_KV_COLLECTION,
    KIND_USER,
    KIND_INDEX_DETAIL,
}

# Readiness score weights (sum to 100).
SURFACE_WEIGHTS: Dict[str, int] = {
    "indexes": 15,
    "sourcetypes": 10,
    "hosts": 10,
    "sources": 5,
    "knowledge_objects:saved_searches": 5,
    "platform_info": 5,
}
FRESHNESS_WEIGHT = 30
RELIABILITY_WEIGHT = 20
RELIABILITY_PENALTY_PER_GROUP = 4

SURFACE_OVERVIEW_KEYS: Dict[str, str] = {
    "indexes": "total_indexes",
    "sourcetypes": "total_sourcetypes",
    "hosts": "total_hosts",
    "sources": "total_sources",
    "knowledge_objects:saved_searches": "total_knowledge_objects",
    "platform_info": "splunk_version",
}


@dataclass
class V2PhaseResult:
    phase: str
    summary: str
    details: Dict[str, Any]


def _entity_events(kind: str, data: Dict[str, Any]) -> int:
    if kind in {KIND_INDEX, KIND_INDEX_DETAIL}:
        return safe_int(data.get("totalEventCount"))
    if kind == KIND_KV_COLLECTION:
        return safe_int(data.get("record_count"))
    return safe_int(data.get("totalCount") or data.get("count") or data.get("eventCount"))


def _cap_lists(value: Any, truncated: Dict[str, int], path: str = "", depth: int = 0) -> Any:
    """Copy value, truncating any list longer than LEDGER_LIST_CAP and recording original lengths."""
    if depth > 4:
        return value
    if isinstance(value, dict):
        return {
            key: _cap_lists(item, truncated, f"{path}.{key}" if path else str(key), depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        if len(value) > LEDGER_LIST_CAP:
            truncated[path or "<root>"] = len(value)
        return [_cap_lists(item, truncated, path, depth + 1) for item in value[:LEDGER_LIST_CAP]]
    return value


class DiscoveryV2Pipeline:
    """Current orchestrator over the existing DiscoveryEngine capabilities."""

    def __init__(self, discovery_engine: Any, output_root: Optional[Path] = None):
        self.discovery_engine = discovery_engine
        self.output_root = Path(output_root) if output_root is not None else Path("output")
        self.pipeline_errors: List[Dict[str, str]] = []

    @staticmethod
    def _display(display: Any, level: str, message: str) -> None:
        handler = getattr(display, level, None) or getattr(display, "info", None)
        if callable(handler):
            try:
                handler(message)
            except Exception:
                pass

    def _record_pipeline_error(self, display: Any, stage: str, exc: BaseException) -> None:
        self.pipeline_errors.append({"stage": stage, "error": str(exc)[:500]})
        self._display(display, "warning", f"⚠️ {stage} did not complete: {str(exc)[:200]}. Continuing with partial results.")

    async def run(self, display: Any, progress: Any) -> Dict[str, Any]:
        """Execute the current discovery flow and export a session artifact bundle."""
        self.pipeline_errors = []
        engine = self.discovery_engine
        try:
            return await self._run(display, progress)
        finally:
            closer = getattr(engine, "aclose", None)
            if callable(closer):
                try:
                    await closer()
                except Exception:
                    pass

    async def _run(self, display: Any, progress: Any) -> Dict[str, Any]:
        engine = self.discovery_engine
        if hasattr(progress, "update_progress"):
            await progress.update_progress(2, "Starting discovery...")
        display.phase("🧠 Surveying the environment")
        display.info("Looking at the overall environment and platform...")
        # A failure here means the index inventory itself is unreachable, which is fatal by design.
        overview = await engine.get_quick_overview()
        estimated_steps = max(1, int(getattr(overview, "estimated_discovery_steps", 10) or 10))
        progress.set_total_steps(100)
        await progress.update_progress(10, "Survey complete. Collecting details...")
        display.show_overview_summary(overview)

        display.phase("🧭 Collecting details")
        display.info("Checking indexes, sourcetypes, hosts, and platform settings...")
        step_count = 0
        try:
            async for result in engine.discover_environment():
                step_count += 1
                max_steps = max(estimated_steps, step_count)
                collection_progress = min(76, 10 + int((step_count / max_steps) * 66))
                await progress.update_progress(collection_progress, f"Step {step_count}/{max_steps}: {result.description}")
        except Exception as exc:
            self._record_pipeline_error(display, "Evidence collection", exc)

        await progress.update_progress(78, f"Collected details in {step_count} discovery steps.")

        display.phase("🔬 Classifying data")
        display.info("Grouping the collected data by what it is used for...")
        await progress.update_progress(82, "Classifying data...")
        try:
            classifications = await engine.classify_data()
        except Exception as exc:
            self._record_pipeline_error(display, "Classification", exc)
            classifications = {}

        display.phase("📋 Recommending actions")
        display.info("Writing prioritized recommendations from the findings...")
        await progress.update_progress(88, "Writing recommendations...")
        try:
            recommendations = await engine.generate_recommendations()
        except Exception as exc:
            self._record_pipeline_error(display, "Recommendation generation", exc)
            fallback = getattr(engine, "_build_fallback_recommendations", None)
            recommendations = fallback() if callable(fallback) else []
        recommendations = [item for item in (recommendations or []) if isinstance(item, dict)]

        display.phase("🧪 Suggesting use cases")
        display.info("Suggesting use cases for admins, analysts, and executives...")
        await progress.update_progress(92, "Suggesting use cases...")
        try:
            suggested_use_cases = await engine.generate_suggested_use_cases()
        except Exception as exc:
            self._record_pipeline_error(display, "Use case generation", exc)
            fallback = getattr(engine, "_generate_creative_fallback_use_cases", None)
            suggested_use_cases = fallback() if callable(fallback) else []
        suggested_use_cases = [item for item in (suggested_use_cases or []) if isinstance(item, dict)]

        llm_status = self._engine_dict(engine, "get_llm_status")
        degraded = [stage for stage, status in llm_status.items() if isinstance(status, dict) and status.get("status") != "ok"]
        if degraded:
            self._display(
                display,
                "warning",
                "⚠️ The AI step did not finish for: " + ", ".join(degraded) + ". These results come from the discovered data only.",
            )

        discovery_results = engine.get_all_results()
        display.phase("🧱 Assembling results")
        await progress.update_progress(95, "Assembling results...")
        artifact_payload = self._build_v2_payload(
            overview=overview,
            discovery_results=discovery_results,
            classifications=classifications,
            recommendations=recommendations,
            suggested_use_cases=suggested_use_cases,
        )

        display.phase("📦 Saving reports")
        display.info("Writing the results file, runbooks, and reports to the output folder...")
        await progress.update_progress(98, "Saving reports...")
        export_result = self._export_v2_bundle(artifact_payload)

        return {
            "overview": overview,
            "classifications": classifications,
            "recommendations": recommendations,
            "suggested_use_cases": suggested_use_cases,
            "discovery_step_count": step_count,
            "timestamp": export_result["timestamp"],
            "report_paths": export_result["report_paths"],
            "artifact_payload": artifact_payload,
            "llm_status": artifact_payload.get("llm_status", {}),
            "pipeline_errors": list(self.pipeline_errors),
        }

    @staticmethod
    def _engine_dict(engine: Any, method_name: str) -> Dict[str, Any]:
        getter = getattr(engine, method_name, None)
        if not callable(getter):
            return {}
        try:
            value = getter()
        except Exception:
            return {}
        return value if isinstance(value, dict) else {}

    def _build_finding_ledger(self, discovery_results: List[Any]) -> Dict[str, Any]:
        entries: List[Dict[str, Any]] = []
        kinds: List[str] = []
        for item in discovery_results or []:
            data = getattr(item, "data", {}) if not isinstance(item, dict) else item.get("data", {})
            data = data if isinstance(data, dict) else {}
            kinds.append(result_kind(item) or "other")
            entries.append({"item": item, "data": data})

        totals: Dict[str, int] = {}
        for kind in kinds:
            totals[kind] = totals.get(kind, 0) + 1

        keep_indices = set(range(len(entries)))
        for kind, total in totals.items():
            if kind not in CAPPED_LEDGER_KINDS or total <= LEDGER_MAX_PER_KIND:
                continue
            positions = [i for i, k in enumerate(kinds) if k == kind]
            ranked = sorted(positions, key=lambda i: _entity_events(kind, entries[i]["data"]), reverse=True)
            for position in ranked[LEDGER_MAX_PER_KIND:]:
                keep_indices.discard(position)

        ledger: List[Dict[str, Any]] = []
        included: Dict[str, int] = {}
        for position, (entry, kind) in enumerate(zip(entries, kinds)):
            if position not in keep_indices:
                continue
            item = entry["item"]
            data = entry["data"]
            truncated_lists: Dict[str, int] = {}
            capped_data = _cap_lists(data, truncated_lists)
            timestamp = getattr(item, "timestamp", None)
            ledger_entry = {
                "step": getattr(item, "step", 0),
                "title": getattr(item, "description", "Discovery Step"),
                "kind": kind,
                "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp or ""),
                "findings": list(getattr(item, "interesting_findings", []) or []),
                "data": capped_data,
                "data_keys": sorted(data.keys()),
            }
            if truncated_lists:
                ledger_entry["data_truncated"] = truncated_lists
            ledger.append(ledger_entry)
            included[kind] = included.get(kind, 0) + 1

        summary = {
            kind: {"total": total, "included": included.get(kind, 0), "truncated": included.get(kind, 0) < total}
            for kind, total in totals.items()
        }
        return {"ledger": ledger, "summary": summary}

    @staticmethod
    def _build_inventory(discovery_results: List[Any]) -> Dict[str, Any]:
        fields = {
            KIND_INDEX: ("indexes", ("title", "name")),
            KIND_SOURCETYPE: ("sourcetypes", ("sourcetype",)),
            KIND_HOST: ("hosts", ("host",)),
            KIND_SOURCE: ("sources", ("source",)),
            KIND_KV_COLLECTION: ("kv_collections", ("name", "title")),
        }
        names: Dict[str, List[str]] = {target: [] for target, _ in fields.values()}
        for item in discovery_results or []:
            kind = result_kind(item)
            if kind not in fields:
                continue
            data = getattr(item, "data", {}) if not isinstance(item, dict) else item.get("data", {})
            if not isinstance(data, dict):
                continue
            target, keys = fields[kind]
            name = next((data.get(key) for key in keys if data.get(key)), None)
            if name:
                names[target].append(str(name))
        inventory: Dict[str, Any] = {}
        for target, values in names.items():
            unique = list(dict.fromkeys(values))
            inventory[target] = unique[:INVENTORY_NAME_CAP]
            if len(unique) > INVENTORY_NAME_CAP:
                inventory[f"{target}_total"] = len(unique)
        return inventory

    @staticmethod
    def _compute_readiness(
        overview: Any,
        step_status: Dict[str, Any],
        metrics: Dict[str, Any],
    ) -> Dict[str, Any]:
        surfaces_ok: List[str] = []
        surfaces_missing: List[str] = []
        coverage_points = 0
        for step, weight in SURFACE_WEIGHTS.items():
            status = step_status.get(step) if isinstance(step_status, dict) else None
            if isinstance(status, dict):
                ok = status.get("status") == "ok"
            else:
                value = getattr(overview, SURFACE_OVERVIEW_KEYS[step], None)
                ok = bool(value) and value != "unknown"
            if ok:
                coverage_points += weight
                surfaces_ok.append(step)
            else:
                surfaces_missing.append(step)

        freshness = metrics.get("freshness", {}) if isinstance(metrics, dict) else {}
        checked = safe_int(freshness.get("checked_indexes")) if isinstance(freshness, dict) else 0
        if isinstance(freshness, dict) and freshness.get("status") == "measured" and checked > 0:
            active = safe_int(freshness.get("active_indexes"))
            freshness_points = FRESHNESS_WEIGHT * active / checked
            freshness_basis = f"{active} of {checked} enabled event indexes received events in the last 24h"
        else:
            freshness_points = FRESHNESS_WEIGHT / 2
            freshness_basis = "index freshness could not be measured; half credit assigned"

        failed_groups = sorted({
            name.split(":", 1)[0]
            for name, status in (step_status or {}).items()
            if isinstance(status, dict) and status.get("status") in {"error", "skipped"}
        })
        reliability_points = max(0, RELIABILITY_WEIGHT - RELIABILITY_PENALTY_PER_GROUP * len(failed_groups))

        score = int(round(max(0, min(100, coverage_points + freshness_points + reliability_points))))
        max_coverage = sum(SURFACE_WEIGHTS.values())
        explanation = (
            f"Surface coverage {coverage_points}/{max_coverage} ({len(surfaces_ok)} of {len(SURFACE_WEIGHTS)} core surfaces collected); "
            f"data freshness {freshness_points:.1f}/{FRESHNESS_WEIGHT} ({freshness_basis}); "
            f"collection reliability {reliability_points}/{RELIABILITY_WEIGHT} "
            f"({len(failed_groups)} step {'group' if len(failed_groups) == 1 else 'groups'} failed or skipped)."
        )
        return {
            "score": score,
            "basis": {
                "method": "evidence_weighted_v1",
                "components": {
                    "surface_coverage": {
                        "points": coverage_points,
                        "max": max_coverage,
                        "weights": dict(SURFACE_WEIGHTS),
                        "collected": surfaces_ok,
                        "missing": surfaces_missing,
                    },
                    "data_freshness": {
                        "points": round(freshness_points, 1),
                        "max": FRESHNESS_WEIGHT,
                        "basis": freshness_basis,
                    },
                    "collection_reliability": {
                        "points": reliability_points,
                        "max": RELIABILITY_WEIGHT,
                        "penalty_per_failed_group": RELIABILITY_PENALTY_PER_GROUP,
                        "failed_or_skipped_groups": failed_groups,
                    },
                },
                "explanation": explanation,
            },
        }

    def _build_v2_payload(
        self,
        overview: Any,
        discovery_results: List[Any],
        classifications: Dict[str, Any],
        recommendations: List[Dict[str, Any]],
        suggested_use_cases: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        recommendations = [r for r in (recommendations or []) if isinstance(r, dict)]
        suggested_use_cases = [u for u in (suggested_use_cases or []) if isinstance(u, dict)]
        ledger_bundle = self._build_finding_ledger(discovery_results)
        finding_ledger = ledger_bundle["ledger"]

        step_status = self._engine_dict(self.discovery_engine, "get_step_status")
        llm_status = self._engine_dict(self.discovery_engine, "get_llm_status")
        metrics = self._engine_dict(self.discovery_engine, "get_discovery_metrics")

        high_priority = [
            r for r in recommendations
            if str(r.get("priority", "")).lower() == "high"
        ]

        capability_graph = {
            "data_surface": {
                "indexes": getattr(overview, "total_indexes", 0),
                "sourcetypes": getattr(overview, "total_sourcetypes", 0),
                "hosts": getattr(overview, "total_hosts", 0),
                "sources": getattr(overview, "total_sources", 0),
                "truncated": dict(getattr(overview, "truncated", {}) or {}),
            },
            "operations_surface": {
                "users": getattr(overview, "total_users", 0),
                "users_scope": getattr(overview, "user_scope", "authenticated_user_context"),
                "knowledge_objects": getattr(overview, "total_knowledge_objects", 0),
                "knowledge_objects_by_type": dict(getattr(overview, "knowledge_object_counts", {}) or {}),
                "kv_collections": getattr(overview, "total_kv_collections", 0),
            },
            "platform_surface": {
                "splunk_version": getattr(overview, "splunk_version", "unknown"),
                "license_state": getattr(overview, "license_state", "unknown"),
                "server_roles": list(getattr(overview, "server_roles", []) or []),
            },
        }

        coverage_gaps = [
            {
                "gap": rec.get("title", "Coverage Gap"),
                "why_it_matters": rec.get("description", ""),
                "priority": rec.get("priority", "medium"),
            }
            for rec in high_priority[:10]
        ]

        risk_register = []
        for rec in recommendations:
            risk_register.append({
                "risk": rec.get("title", "Operational Risk"),
                "severity": str(rec.get("priority", "medium")).lower(),
                "domain": rec.get("category", "general"),
                "impact": rec.get("description", ""),
                "mitigation": rec.get("suggested_actions", rec.get("next_steps", ""))
            })

        def _count_category(predicate) -> int:
            return len([r for r in recommendations if predicate(str(r.get("category", "")).lower())])

        trend_signals = {
            "evidence_steps": len(discovery_results or []),
            "high_priority_recommendations": len(high_priority),
            "coverage_gap_count": len(coverage_gaps),
            "recommendation_by_domain": {
                "security": _count_category(lambda c: "security" in c),
                "performance": _count_category(lambda c: "performance" in c),
                "data_quality": _count_category(lambda c: "data" in c or "quality" in c),
                "compliance": _count_category(lambda c: "compliance" in c),
            }
        }

        vulnerability_hypotheses = [
            {
                "hypothesis": f"Potential weak control: {gap.get('gap', 'Unknown gap')}",
                "rationale": gap.get("why_it_matters", ""),
                "validation_loop": "Run targeted SPL baselines, compare 7d/30d movement, and verify control efficacy.",
                "priority": gap.get("priority", "medium")
            }
            for gap in coverage_gaps[:8]
        ]

        recursive_investigations = [
            {
                "loop": "Trend Baseline Expansion",
                "objective": "Track shifts in index/sourcetype/host activity over recurring discovery runs.",
                "next_iteration_trigger": "Material change in recommendation volume or risk severity.",
                "output": "Updated trend deltas + anomaly shortlist."
            },
            {
                "loop": "Risk-to-Query Verification",
                "objective": "Convert each high-severity risk into one verification SPL and one remediation SPL.",
                "next_iteration_trigger": "Any unresolved high risk remains after runbook execution.",
                "output": "Verified closure evidence and residual-risk register."
            },
            {
                "loop": "Coverage Gap Deep Dive",
                "objective": "Iteratively split broad coverage gaps into concrete controls and detections.",
                "next_iteration_trigger": "Gap remains high-priority for 2 consecutive runs.",
                "output": "Control backlog with owner, SLA, and measurable success criteria."
            }
        ]

        readiness = self._compute_readiness(overview, step_status, metrics)

        return {
            "schema_version": "2.0",
            "generated_at": datetime.now().isoformat(),
            "analysis_depth": "v2_deep_intelligence",
            "readiness_score": readiness["score"],
            "score_basis": readiness["basis"],
            "overview": dict(overview.__dict__) if hasattr(overview, "__dict__") else overview,
            "capability_graph": capability_graph,
            "finding_ledger": finding_ledger,
            "finding_ledger_summary": ledger_bundle["summary"],
            "discovered_inventory": self._build_inventory(discovery_results),
            "classification_map": classifications if isinstance(classifications, dict) else {},
            "coverage_gaps": coverage_gaps,
            "risk_register": risk_register[:20],
            "trend_signals": trend_signals,
            "vulnerability_hypotheses": vulnerability_hypotheses,
            "recursive_investigations": recursive_investigations,
            "recommendations": recommendations,
            "suggested_use_cases": suggested_use_cases,
            "llm_status": llm_status,
            "discovery_step_status": step_status,
            "discovery_metrics": metrics,
            "pipeline_errors": list(self.pipeline_errors),
        }

    def _export_v2_bundle(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_root = self.output_root
        output_root.mkdir(parents=True, exist_ok=True)

        report_paths: List[str] = []

        blueprint_path = output_root / f"v2_intelligence_blueprint_{timestamp}.json"
        blueprint_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        report_paths.append(str(blueprint_path.name))

        insights_path = output_root / f"v2_insights_brief_{timestamp}.md"
        insights_path.write_text(self._build_insights_markdown(payload), encoding="utf-8")
        report_paths.append(str(insights_path.name))

        runbook_path = output_root / f"v2_operator_runbook_{timestamp}.md"
        runbook_path.write_text(self._build_runbook_markdown(payload), encoding="utf-8")
        report_paths.append(str(runbook_path.name))

        handoff_path = output_root / f"v2_developer_handoff_{timestamp}.md"
        handoff_path.write_text(self._build_handoff_markdown(payload, timestamp=timestamp), encoding="utf-8")
        report_paths.append(str(handoff_path.name))

        return {"timestamp": timestamp, "report_paths": report_paths}

    @staticmethod
    def _display_count(overview: Dict[str, Any], surface: str, total_key: str) -> str:
        display = overview.get("count_display", {}) if isinstance(overview.get("count_display"), dict) else {}
        if display.get(surface):
            return str(display[surface])
        count = safe_int(overview.get(total_key))
        truncated = overview.get("truncated", {}) if isinstance(overview.get("truncated"), dict) else {}
        return f"≥{count}" if truncated.get(surface) else str(count)

    def _build_insights_markdown(self, payload: Dict[str, Any]) -> str:
        overview = payload.get("overview", {}) if isinstance(payload.get("overview", {}), dict) else {}
        gaps = payload.get("coverage_gaps", []) if isinstance(payload.get("coverage_gaps", []), list) else []
        risk_register = payload.get("risk_register", []) if isinstance(payload.get("risk_register", []), list) else []
        trend_signals = payload.get("trend_signals", {}) if isinstance(payload.get("trend_signals", {}), dict) else {}
        vulnerabilities = payload.get("vulnerability_hypotheses", []) if isinstance(payload.get("vulnerability_hypotheses", []), list) else []
        llm_status = payload.get("llm_status", {}) if isinstance(payload.get("llm_status"), dict) else {}
        step_status = payload.get("discovery_step_status", {}) if isinstance(payload.get("discovery_step_status"), dict) else {}
        score_basis = payload.get("score_basis", {}) if isinstance(payload.get("score_basis"), dict) else {}

        ko_counts = overview.get("knowledge_object_counts", {}) if isinstance(overview.get("knowledge_object_counts"), dict) else {}
        ko_text = ", ".join(f"{ko_type}={count}" for ko_type, count in ko_counts.items()) if ko_counts else str(overview.get("total_knowledge_objects", 0))

        user = overview.get("authenticated_user") or "unknown"
        roles = overview.get("authenticated_user_roles") or []
        roles_text = ", ".join(str(role) for role in roles) if roles else "none reported"

        if overview.get("data_volume_24h"):
            volume_text = f"{overview.get('data_volume_24h')} (source: {overview.get('data_volume_24h_source') or 'license usage'})"
        else:
            volume_text = f"Unavailable ({overview.get('data_volume_24h_source') or 'not measured'})"

        index_size = overview.get("total_index_size_mb")
        index_size_text = f"{float(index_size):,.1f} MB" if isinstance(index_size, (int, float)) else "unknown"

        truncated = overview.get("truncated", {}) if isinstance(overview.get("truncated"), dict) else {}

        lines = [
            "# Intelligence Brief",
            "",
            f"Readiness Score: **{payload.get('readiness_score', 'N/A')}**",
        ]
        if score_basis.get("explanation"):
            lines.append(f"Score basis: {score_basis['explanation']}")
        lines.extend([
            "",
            "## Environment Snapshot",
            f"- Indexes: {self._display_count(overview, 'indexes', 'total_indexes')}",
            f"- Sourcetypes (last 24h): {self._display_count(overview, 'sourcetypes', 'total_sourcetypes')}",
            f"- Hosts (last 24h): {self._display_count(overview, 'hosts', 'total_hosts')}",
            f"- Sources (last 24h): {self._display_count(overview, 'sources', 'total_sources')}",
            f"- Knowledge objects by type: {ko_text}",
            f"- KV store collections: {self._display_count(overview, 'kv_collections', 'total_kv_collections')}",
            f"- Authenticated user context: {user} (roles: {roles_text}); user accounts are not enumerated",
            f"- 24h ingest volume: {volume_text}",
            f"- Total on-disk index size (all retained data): {index_size_text}",
            f"- Version: {overview.get('splunk_version', 'unknown')}",
        ])
        if any(truncated.values()):
            lines.append("- Counts marked ≥ reached the discovery row limit and are lower bounds.")

        lines.extend(["", "## AI Enrichment Status"])
        if llm_status:
            for stage, status in llm_status.items():
                if not isinstance(status, dict):
                    continue
                suffix = " (deterministic fallback used)" if status.get("fallback_used") else ""
                lines.append(f"- {stage}: {status.get('status', 'unknown')}{suffix}")
        else:
            lines.append("- No AI enrichment status recorded.")

        issues = [
            (name, status) for name, status in step_status.items()
            if isinstance(status, dict) and status.get("status") in {"error", "skipped"}
        ]
        lines.extend(["", "## Discovery Coverage"])
        if issues:
            for name, status in issues[:20]:
                lines.append(f"- {status.get('label') or name}: {status.get('status')} - {status.get('error', '')}")
        else:
            lines.append("- All discovery steps completed.")

        lines.extend([
            "",
            "## Trend Signals",
            f"- Evidence steps captured: {trend_signals.get('evidence_steps', 0)}",
            f"- High-priority recommendations: {trend_signals.get('high_priority_recommendations', 0)}",
            f"- Coverage gaps: {trend_signals.get('coverage_gap_count', 0)}",
            "",
            "## Highest Value Gaps",
        ])
        if gaps:
            for gap in gaps[:8]:
                lines.append(f"- [{gap.get('priority', 'medium')}] {gap.get('gap', 'Gap')}: {gap.get('why_it_matters', '')}")
        else:
            lines.append("- No high-priority gaps detected.")

        lines.extend([
            "",
            "## Risk Register",
        ])
        if risk_register:
            for risk in risk_register[:10]:
                lines.append(
                    f"- [{risk.get('severity', 'medium')}] {risk.get('risk', 'Risk')}: {risk.get('impact', '')}"
                )
        else:
            lines.append("- No explicit risks extracted.")

        lines.extend([
            "",
            "## Vulnerability Hypotheses",
        ])
        if vulnerabilities:
            for item in vulnerabilities[:8]:
                lines.append(f"- {item.get('hypothesis', 'Hypothesis')}")
                lines.append(f"  - Why: {item.get('rationale', '')}")
                lines.append(f"  - Validate: {item.get('validation_loop', '')}")
        else:
            lines.append("- No vulnerability hypotheses generated.")

        return "\n".join(lines) + "\n"

    def _build_runbook_markdown(self, payload: Dict[str, Any]) -> str:
        recs = payload.get("recommendations", []) if isinstance(payload.get("recommendations", []), list) else []
        recursive = payload.get("recursive_investigations", []) if isinstance(payload.get("recursive_investigations", []), list) else []
        llm_status = payload.get("llm_status", {}) if isinstance(payload.get("llm_status"), dict) else {}
        rec_status = llm_status.get("recommendations", {}) if isinstance(llm_status.get("recommendations"), dict) else {}
        lines = [
            "# Operator Runbook",
            "",
        ]
        if rec_status.get("fallback_used"):
            lines.extend([
                f"> AI recommendations were not available ({rec_status.get('status', 'unknown')}); "
                "the action queue below is derived from discovered facts only.",
                "",
            ])
        lines.append("## Action Queue")
        if recs:
            for idx, rec in enumerate(recs[:12], 1):
                if not isinstance(rec, dict):
                    continue
                lines.append(f"{idx}. {rec.get('title', 'Recommendation')} ({rec.get('priority', 'medium')})")
                lines.append(f"   - Category: {rec.get('category', 'general')}")
                lines.append(f"   - Why: {rec.get('description', '')}")
        else:
            lines.append("1. No recommendations returned.")

        lines.extend([
            "",
            "## Recursive Analysis Loops",
        ])
        if recursive:
            for idx, item in enumerate(recursive, 1):
                if not isinstance(item, dict):
                    continue
                lines.append(f"{idx}. {item.get('loop', 'Recursive Loop')}")
                lines.append(f"   - Objective: {item.get('objective', '')}")
                lines.append(f"   - Trigger: {item.get('next_iteration_trigger', '')}")
                lines.append(f"   - Deliverable: {item.get('output', '')}")
        else:
            lines.append("1. No recursive loops generated.")
        return "\n".join(lines) + "\n"

    def _build_handoff_markdown(self, payload: Dict[str, Any], timestamp: Optional[str] = None) -> str:
        suffix = timestamp or "<timestamp>"
        return "\n".join([
            "# Developer Handoff",
            "",
            "## What this bundle contains",
            f"- `v2_intelligence_blueprint_{suffix}.json`: machine-readable discovery output schema",
            f"- `v2_insights_brief_{suffix}.md`: human summary for stakeholders",
            f"- `v2_operator_runbook_{suffix}.md`: action queue from recommendations",
            f"- `v2_developer_handoff_{suffix}.md`: this guide",
            "",
            "## Repurpose strategy",
            "1. Use `finding_ledger` + `trend_signals` for trend, seasonality, and anomaly scoring.",
            "2. Use `risk_register` to build owner/SLA-driven remediation dashboards.",
            "3. Use `vulnerability_hypotheses` for threat hunting and control validation playbooks.",
            "4. Use `recursive_investigations` to orchestrate continuous discovery loops.",
            "5. Keep MCP/LLM settings contract from web settings APIs.",
            "",
            "## Contract notes",
            "- This schema is additive and intended for app-level composition.",
            "- `finding_ledger` keeps at most 200 entries per entity kind (highest event counts first); "
            "`finding_ledger_summary` reports totals and truncation.",
            "- `discovery_step_status` records ok/error/skipped per MCP step; `llm_status` records AI enrichment per stage.",
            "- `overview.data_volume_24h` is real 24h license usage when measurable, otherwise null "
            "(see `overview.data_volume_24h_source`); `overview.total_index_size_mb` is on-disk size.",
            "- `readiness_score` is evidence-weighted; `score_basis` explains each component.",
            "- Paths are relative to `output/` for easy archiving and sync.",
            "- Legacy compatibility exports are intentionally removed.",
        ]) + "\n"
