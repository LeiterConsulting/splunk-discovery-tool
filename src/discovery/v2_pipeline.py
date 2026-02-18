"""
Discovery V2 pipeline for DT4SMS.

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


@dataclass
class V2PhaseResult:
    phase: str
    summary: str
    details: Dict[str, Any]


class DiscoveryV2Pipeline:
    """V2 orchestrator over the existing DiscoveryEngine capabilities."""

    def __init__(self, discovery_engine: Any):
        self.discovery_engine = discovery_engine

    async def run(self, display: Any, progress: Any) -> Dict[str, Any]:
        """Execute v2 discovery flow and export a session artifact bundle."""
        await progress.update_progress(2, "Initializing V2 discovery pipeline...") if hasattr(progress, "update_progress") else None
        display.phase("🧠 V2 Discovery: Environment Signal Capture")
        display.info("Collecting high-level environment topology and platform signals...")
        overview = await self.discovery_engine.get_quick_overview()
        estimated_steps = max(1, int(getattr(overview, "estimated_discovery_steps", 10) or 10))
        progress.set_total_steps(100)
        await progress.update_progress(10, "Signal capture complete. Beginning evidence collection...")
        display.show_overview_summary(overview)

        display.phase("🧭 V2 Discovery: Evidence Collection")
        display.info("Running iterative discovery tasks across indexes, sourcetypes, hosts, and platform controls...")
        step_count = 0
        async for result in self.discovery_engine.discover_environment():
            step_count += 1
            max_steps = max(estimated_steps, step_count)
            collection_progress = min(76, 10 + int((step_count / max_steps) * 66))
            await progress.update_progress(collection_progress, f"Evidence {step_count}/{max_steps}: {result.description}")

        await progress.update_progress(78, f"Evidence collection complete with {step_count} discovery steps.")

        display.phase("🔬 V2 Discovery: Intelligence Synthesis")
        display.info("Synthesizing classifications from discovered telemetry...")
        await progress.update_progress(82, "Synthesizing classification map...")
        classifications = await self.discovery_engine.classify_data()

        display.info("Generating prioritized recommendations based on detected patterns...")
        await progress.update_progress(88, "Building recommendation queue...")
        recommendations = await self.discovery_engine.generate_recommendations()

        display.info("Generating cross-functional use cases for admin, analyst, and executive personas...")
        await progress.update_progress(92, "Generating suggested use cases...")
        suggested_use_cases = await self.discovery_engine.generate_suggested_use_cases()

        discovery_results = self.discovery_engine.get_all_results()
        await progress.update_progress(95, "Assembling intelligence blueprint payload...")
        artifact_payload = self._build_v2_payload(
            overview=overview,
            discovery_results=discovery_results,
            classifications=classifications,
            recommendations=recommendations,
            suggested_use_cases=suggested_use_cases,
        )

        display.phase("📦 V2 Discovery: Artifact Packaging")
        display.info("Writing blueprint, runbook, insights, and handoff artifacts to output/ ...")
        await progress.update_progress(98, "Packaging artifacts to output directory...")
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
        }

    def _build_v2_payload(
        self,
        overview: Any,
        discovery_results: List[Any],
        classifications: Dict[str, Any],
        recommendations: List[Dict[str, Any]],
        suggested_use_cases: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        finding_ledger = []
        for item in discovery_results:
            finding_ledger.append(
                {
                    "step": getattr(item, "step", 0),
                    "title": getattr(item, "description", "Discovery Step"),
                    "timestamp": getattr(item, "timestamp", datetime.now()).isoformat()
                    if hasattr(getattr(item, "timestamp", None), "isoformat")
                    else str(getattr(item, "timestamp", "")),
                    "findings": list(getattr(item, "interesting_findings", []) or []),
                    "data": getattr(item, "data", {}) if isinstance(getattr(item, "data", {}), dict) else {},
                    "data_keys": sorted(list((getattr(item, "data", {}) or {}).keys())) if isinstance(getattr(item, "data", {}), dict) else [],
                }
            )

        high_priority = [
            r for r in (recommendations or [])
            if isinstance(r, dict) and str(r.get("priority", "")).lower() == "high"
        ]

        capability_graph = {
            "data_surface": {
                "indexes": getattr(overview, "total_indexes", 0),
                "sourcetypes": getattr(overview, "total_sourcetypes", 0),
                "hosts": getattr(overview, "total_hosts", 0),
                "sources": getattr(overview, "total_sources", 0),
            },
            "operations_surface": {
                "users": getattr(overview, "total_users", 0),
                "knowledge_objects": getattr(overview, "total_knowledge_objects", 0),
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
            if isinstance(rec, dict)
        ]

        risk_register = []
        for rec in (recommendations or []):
            if not isinstance(rec, dict):
                continue
            risk_register.append({
                "risk": rec.get("title", "Operational Risk"),
                "severity": str(rec.get("priority", "medium")).lower(),
                "domain": rec.get("category", "general"),
                "impact": rec.get("description", ""),
                "mitigation": rec.get("suggested_actions", rec.get("next_steps", "Investigate and remediate through targeted Splunk validation."))
            })

        trend_signals = {
            "evidence_steps": len(finding_ledger),
            "high_priority_recommendations": len(high_priority),
            "coverage_gap_count": len(coverage_gaps),
            "recommendation_by_domain": {
                "security": len([r for r in recommendations if isinstance(r, dict) and "security" in str(r.get("category", "")).lower()]),
                "performance": len([r for r in recommendations if isinstance(r, dict) and "performance" in str(r.get("category", "")).lower()]),
                "data_quality": len([r for r in recommendations if isinstance(r, dict) and ("data" in str(r.get("category", "")).lower() or "quality" in str(r.get("category", "")).lower())]),
                "compliance": len([r for r in recommendations if isinstance(r, dict) and "compliance" in str(r.get("category", "")).lower()]),
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
            if isinstance(gap, dict)
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

        readiness_score = max(
            0,
            min(
                100,
                62
                + min(18, len(finding_ledger))
                + min(10, len(high_priority))
                - min(22, len(coverage_gaps) * 2)
            )
        )

        return {
            "schema_version": "2.0",
            "generated_at": datetime.now().isoformat(),
            "analysis_depth": "v2_deep_intelligence",
            "readiness_score": readiness_score,
            "overview": overview.__dict__ if hasattr(overview, "__dict__") else overview,
            "capability_graph": capability_graph,
            "finding_ledger": finding_ledger,
            "classification_map": classifications,
            "coverage_gaps": coverage_gaps,
            "risk_register": risk_register[:20],
            "trend_signals": trend_signals,
            "vulnerability_hypotheses": vulnerability_hypotheses,
            "recursive_investigations": recursive_investigations,
            "recommendations": recommendations,
            "suggested_use_cases": suggested_use_cases,
        }

    def _export_v2_bundle(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_root = Path("output")
        output_root.mkdir(exist_ok=True)

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
        handoff_path.write_text(self._build_handoff_markdown(payload), encoding="utf-8")
        report_paths.append(str(handoff_path.name))

        return {"timestamp": timestamp, "report_paths": report_paths}

    def _build_insights_markdown(self, payload: Dict[str, Any]) -> str:
        overview = payload.get("overview", {}) if isinstance(payload.get("overview", {}), dict) else {}
        gaps = payload.get("coverage_gaps", []) if isinstance(payload.get("coverage_gaps", []), list) else []
        risk_register = payload.get("risk_register", []) if isinstance(payload.get("risk_register", []), list) else []
        trend_signals = payload.get("trend_signals", {}) if isinstance(payload.get("trend_signals", {}), dict) else {}
        vulnerabilities = payload.get("vulnerability_hypotheses", []) if isinstance(payload.get("vulnerability_hypotheses", []), list) else []

        lines = [
            "# V2 Intelligence Brief",
            "",
            f"Readiness Score: **{payload.get('readiness_score', 'N/A')}**",
            "",
            "## Environment Snapshot",
            f"- Indexes: {overview.get('total_indexes', 0)}",
            f"- Sourcetypes: {overview.get('total_sourcetypes', 0)}",
            f"- Hosts: {overview.get('total_hosts', 0)}",
            f"- Version: {overview.get('splunk_version', 'unknown')}",
            "",
            "## Trend Signals",
            f"- Evidence steps captured: {trend_signals.get('evidence_steps', 0)}",
            f"- High-priority recommendations: {trend_signals.get('high_priority_recommendations', 0)}",
            f"- Coverage gaps: {trend_signals.get('coverage_gap_count', 0)}",
            "",
            "## Highest Value Gaps",
        ]
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
        lines = [
            "# V2 Operator Runbook",
            "",
            "## Action Queue",
        ]
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

    def _build_handoff_markdown(self, payload: Dict[str, Any]) -> str:
        return "\n".join([
            "# V2 Developer Handoff",
            "",
            "## What this bundle contains",
            "- `intelligence_blueprint.json`: machine-readable discovery output schema",
            "- `insights_brief.md`: human summary for stakeholders",
            "- `operator_runbook.md`: action queue from recommendations",
            "- `developer_handoff.md`: this guide",
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
            "- Paths are relative to `output/` for easy archiving and sync.",
            "- Non-V2 compatibility exports are intentionally removed.",
        ]) + "\n"
