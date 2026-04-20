"""
Smart Discovery Context Manager

Provides lazy-loading and intelligent context retrieval for Splunk discovery data.
Prefers V2 intelligence blueprints while retaining compatibility with legacy exports.
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class DiscoveryContextManager:
    """Manages discovery context with lazy loading and caching."""

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("output")
        self._discovery_file: Optional[Path] = None
        self._discovery_data: Optional[Dict[str, Any]] = None
        self._metadata: Optional[Dict[str, Any]] = None
        self._cached_contexts: Dict[str, Any] = {}
        self._file_mtime: Optional[float] = None
        self._discovery_format: str = "legacy"

    @staticmethod
    def _safe_int(value: Any) -> int:
        try:
            if value in (None, ""):
                return 0
            return int(float(value))
        except Exception:
            return 0

    @staticmethod
    def _safe_float(value: Any) -> float:
        try:
            if value in (None, ""):
                return 0.0
            return float(value)
        except Exception:
            return 0.0

    def _parse_timestamp_from_file(self, discovery_file: Path) -> str:
        stem = discovery_file.stem
        prefixes = [
            "v2_intelligence_blueprint_",
            "discovery_export_",
        ]
        for prefix in prefixes:
            if stem.startswith(prefix):
                return stem.replace(prefix, "", 1)
        return ""

    def get_latest_discovery_file(self) -> Optional[Path]:
        """Find the most recent discovery export file, preferring V2 artifacts."""
        if not self.output_dir.exists():
            return None

        v2_files = sorted(self.output_dir.glob("v2_intelligence_blueprint_*.json"), reverse=True)
        if v2_files:
            return v2_files[0]

        legacy_files = sorted(self.output_dir.glob("discovery_export_*.json"), reverse=True)
        return legacy_files[0] if legacy_files else None

    def _is_v2(self) -> bool:
        return self._discovery_format == "v2" or (
            isinstance(self._discovery_data, dict)
            and "finding_ledger" in self._discovery_data
            and "discovery_results" not in self._discovery_data
        )

    def _load_discovery_data(self, force_reload: bool = False) -> bool:
        """Load discovery data into memory. Returns True if successful."""
        discovery_file = self.get_latest_discovery_file()

        if not discovery_file:
            logger.warning("No discovery file found")
            return False

        current_mtime = discovery_file.stat().st_mtime
        if not force_reload and self._discovery_data and self._file_mtime == current_mtime:
            return True

        try:
            with open(discovery_file, "r", encoding="utf-8") as f:
                self._discovery_data = json.load(f)
            self._discovery_file = discovery_file
            self._file_mtime = current_mtime
            self._cached_contexts.clear()
            self._metadata = None
            self._discovery_format = "v2" if discovery_file.name.startswith("v2_intelligence_blueprint_") else "legacy"
            logger.info("Loaded discovery data from %s", discovery_file.name)
            return True
        except Exception as e:
            logger.error("Failed to load discovery data: %s", e)
            return False

    def _iter_entries(self) -> List[Dict[str, Any]]:
        if not isinstance(self._discovery_data, dict):
            return []
        key = "finding_ledger" if self._is_v2() else "discovery_results"
        entries = self._discovery_data.get(key, [])
        return [entry for entry in entries if isinstance(entry, dict)]

    def _parse_notable_patterns(self) -> List[Dict[str, Any]]:
        overview = self._discovery_data.get("overview", {}) if isinstance(self._discovery_data, dict) else {}
        raw_patterns = overview.get("notable_patterns", []) if isinstance(overview.get("notable_patterns", []), list) else []
        for item in raw_patterns:
            payload = item
            if isinstance(item, str):
                try:
                    payload = json.loads(item)
                except Exception:
                    continue
            if isinstance(payload, dict) and isinstance(payload.get("patterns"), list):
                return [pattern for pattern in payload.get("patterns", []) if isinstance(pattern, dict)]
        return []

    def get_metadata(self) -> Dict[str, Any]:
        """Get lightweight metadata about available discovery data."""
        if self._metadata:
            return self._metadata

        discovery_file = self.get_latest_discovery_file()
        if not discovery_file:
            return {
                "available": False,
                "message": "No discovery data found. Run a discovery first.",
            }

        timestamp_str = self._parse_timestamp_from_file(discovery_file)
        try:
            discovery_datetime = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
            age_seconds = (datetime.now() - discovery_datetime).total_seconds()
            age_days = max(0, int(age_seconds / 86400))
        except Exception:
            age_days = 0

        if not self._load_discovery_data():
            return {"available": False, "message": "Failed to load discovery data"}

        overview = self._discovery_data.get("overview", {}) if isinstance(self._discovery_data, dict) else {}
        trend_signals = self._discovery_data.get("trend_signals", {}) if isinstance(self._discovery_data, dict) else {}
        self._metadata = {
            "available": True,
            "format": self._discovery_format,
            "timestamp": timestamp_str,
            "age_days": age_days,
            "age_warning": age_days > 7,
            "readiness_score": self._safe_int(self._discovery_data.get("readiness_score")) if isinstance(self._discovery_data, dict) else 0,
            "overview": {
                "splunk_version": overview.get("splunk_version", "unknown"),
                "total_indexes": self._safe_int(overview.get("total_indexes", 0)),
                "total_sourcetypes": self._safe_int(overview.get("total_sourcetypes", 0)),
                "total_hosts": self._safe_int(overview.get("total_hosts", 0)),
                "total_sources": self._safe_int(overview.get("total_sources", 0)),
                "total_users": self._safe_int(overview.get("total_users", 0)),
                "data_volume_24h": overview.get("data_volume_24h", "unknown"),
                "license_state": overview.get("license_state", "unknown"),
            },
            "trend_signals": trend_signals if isinstance(trend_signals, dict) else {},
        }
        return self._metadata

    def get_context_for_query(self, user_query: str) -> Dict[str, Any]:
        """Analyze user query and return relevant discovery context."""
        if not self._load_discovery_data():
            return {}

        query_lower = user_query.lower()
        context: Dict[str, Any] = {}

        if any(term in query_lower for term in ["summary", "overview", "environment", "readiness"]):
            context["overview"] = self._get_overview_context()
        if any(term in query_lower for term in ["recommend", "improve", "optimize", "priority", "next step"]):
            context["recommendations"] = self._get_recommendation_context()
        if any(term in query_lower for term in ["risk", "risks", "weak spot", "weak spots", "exposure"]):
            context["risks"] = self._get_risk_context()
        if any(term in query_lower for term in ["gap", "gaps", "coverage", "missing"]):
            context["coverage_gaps"] = self._get_coverage_gap_context()
        if any(term in query_lower for term in ["use case", "use cases", "detection", "dashboard should", "monitoring opportunity"]):
            context["suggested_use_cases"] = self._get_use_case_context()
        if any(term in query_lower for term in ["index", "indexes", "indices", "idx"]):
            context["indexes"] = self._get_index_context()
        if any(term in query_lower for term in ["sourcetype", "source type", "data type", "log type"]):
            context["sourcetypes"] = self._get_sourcetype_context()
        if any(term in query_lower for term in ["host", "hosts", "server", "servers", "machine"]):
            context["hosts"] = self._get_host_context()
        if any(term in query_lower for term in ["alert", "alerts", "correlation", "saved search"]):
            context["alerts"] = self._get_alert_context()
        if any(term in query_lower for term in ["dashboard", "dashboards", "visualization"]):
            context["dashboards"] = self._get_dashboard_context()
        if any(term in query_lower for term in ["user", "users", "account", "accounts", "permission", "role"]):
            context["users"] = self._get_user_context()
        if any(term in query_lower for term in ["lookup", "lookups", "kv store", "collection"]):
            context["kv_stores"] = self._get_kv_context()

        return context

    def get_specific_context(self, context_type: str) -> Any:
        """Get a specific type of context (indexes, hosts, recommendations, etc.)."""
        if not self._load_discovery_data():
            return None

        context_methods = {
            "overview": self._get_overview_context,
            "indexes": self._get_index_context,
            "sourcetypes": self._get_sourcetype_context,
            "hosts": self._get_host_context,
            "alerts": self._get_alert_context,
            "dashboards": self._get_dashboard_context,
            "users": self._get_user_context,
            "kv_collections": self._get_kv_context,
            "kv_stores": self._get_kv_context,
            "recommendations": self._get_recommendation_context,
            "risks": self._get_risk_context,
            "coverage_gaps": self._get_coverage_gap_context,
            "suggested_use_cases": self._get_use_case_context,
        }
        method = context_methods.get(context_type.lower())
        return method() if method else None

    def _get_index_context(self) -> List[Dict[str, Any]]:
        if "indexes" in self._cached_contexts:
            return self._cached_contexts["indexes"]

        indexes: List[Dict[str, Any]] = []
        for entry in self._iter_entries():
            data = entry.get("data", {}) if isinstance(entry.get("data", {}), dict) else {}
            if "title" not in data or "totalEventCount" not in data:
                continue
            if str(data.get("disabled", "0")) == "1":
                continue
            indexes.append({
                "name": str(data.get("title", "")).strip(),
                "events": self._safe_int(data.get("totalEventCount", 0)),
                "size_mb": self._safe_float(data.get("currentDBSizeMB", 0)),
                "datatype": data.get("datatype", "event"),
                "max_time": data.get("maxTime") or data.get("lastTimeIso") or "",
                "min_time": data.get("minTime") or data.get("firstTimeIso") or "",
            })

        indexes.sort(key=lambda item: item.get("events", 0), reverse=True)
        self._cached_contexts["indexes"] = indexes[:20]
        return self._cached_contexts["indexes"]

    def _get_sourcetype_context(self) -> Dict[str, Any]:
        if "sourcetypes" in self._cached_contexts:
            return self._cached_contexts["sourcetypes"]

        overview = self._discovery_data.get("overview", {}) if isinstance(self._discovery_data, dict) else {}
        sourcetypes: List[Dict[str, Any]] = []
        for entry in self._iter_entries():
            data = entry.get("data", {}) if isinstance(entry.get("data", {}), dict) else {}
            name = data.get("sourcetype")
            if not name and str(data.get("type", "")).lower() in {"sourcetypes", "source_types"}:
                name = data.get("title")
            if not isinstance(name, str) or not name.strip():
                continue
            sourcetypes.append({
                "name": name.strip(),
                "events": self._safe_int(data.get("totalCount") or data.get("count") or data.get("eventCount")),
                "recent_time": data.get("recentTimeIso") or data.get("lastTimeIso") or "",
            })

        sourcetypes.sort(key=lambda item: item.get("events", 0), reverse=True)
        patterns = self._parse_notable_patterns()
        self._cached_contexts["sourcetypes"] = {
            "total": self._safe_int(overview.get("total_sourcetypes", len(sourcetypes))),
            "active": len([item for item in sourcetypes if item.get("events", 0) > 0]),
            "most_active": sourcetypes[:5],
            "patterns": patterns[:3],
        }
        return self._cached_contexts["sourcetypes"]

    def _get_host_context(self) -> List[Dict[str, Any]]:
        if "hosts" in self._cached_contexts:
            return self._cached_contexts["hosts"]

        hosts: List[Dict[str, Any]] = []
        for entry in self._iter_entries():
            data = entry.get("data", {}) if isinstance(entry.get("data", {}), dict) else {}
            host_name = data.get("host") or data.get("hostname")
            if not host_name and "Analyzing host:" in str(entry.get("title") or entry.get("description") or ""):
                host_name = data.get("title")
            if not isinstance(host_name, str) or not host_name.strip():
                continue
            event_count = self._safe_int(data.get("totalCount") or data.get("count") or data.get("eventCount"))
            if event_count <= 0:
                continue
            hosts.append({
                "name": host_name.strip(),
                "events": event_count,
            })

        hosts.sort(key=lambda item: item.get("events", 0), reverse=True)
        self._cached_contexts["hosts"] = hosts[:20]
        return self._cached_contexts["hosts"]

    def _get_alert_context(self) -> List[Dict[str, Any]]:
        if "alerts" in self._cached_contexts:
            return self._cached_contexts["alerts"]

        alerts: List[Dict[str, Any]] = []
        for entry in self._iter_entries():
            data = entry.get("data", {}) if isinstance(entry.get("data", {}), dict) else {}
            title = str(data.get("name") or data.get("title") or "").strip()
            if not title:
                continue
            description = str(entry.get("title") or entry.get("description") or title)
            ko_type = str(data.get("ko_type") or data.get("type") or "").lower()
            if ko_type not in {"saved_searches", "alerts", "correlation_search", "savedsearches"} and "alert" not in description.lower() and "fraud" not in description.lower():
                continue
            if str(data.get("disabled", "0")) == "1":
                continue
            joined_findings = " ".join(entry.get("findings", [])) if isinstance(entry.get("findings", []), list) else ""
            severity = "medium"
            lowered = f"{title} {description} {joined_findings}".lower()
            if any(token in lowered for token in ["security", "fraud", "threat", "critical"]):
                severity = "high"
            alerts.append({
                "name": title,
                "severity": severity,
                "cron": data.get("cron_schedule", ""),
            })

        self._cached_contexts["alerts"] = alerts[:15]
        return self._cached_contexts["alerts"]

    def _get_dashboard_context(self) -> List[str]:
        if "dashboards" in self._cached_contexts:
            return self._cached_contexts["dashboards"]

        dashboards: List[str] = []
        for entry in self._iter_entries():
            data = entry.get("data", {}) if isinstance(entry.get("data", {}), dict) else {}
            title = str(data.get("name") or data.get("title") or "").strip()
            ko_type = str(data.get("ko_type") or data.get("type") or "").lower()
            descriptor = str(entry.get("title") or entry.get("description") or title).lower()
            if not title:
                continue
            if ko_type in {"views", "dashboard", "dashboards"} or "dashboard" in descriptor:
                dashboards.append(title)

        deduped = list(dict.fromkeys(dashboards))
        self._cached_contexts["dashboards"] = deduped[:15]
        return self._cached_contexts["dashboards"]

    def _get_user_context(self) -> Dict[str, Any]:
        if "users" in self._cached_contexts:
            return self._cached_contexts["users"]

        overview = self._discovery_data.get("overview", {}) if isinstance(self._discovery_data, dict) else {}
        admin_users: List[str] = []
        total_users = 0
        for entry in self._iter_entries():
            data = entry.get("data", {}) if isinstance(entry.get("data", {}), dict) else {}
            name = data.get("name")
            roles = data.get("roles", [])
            if not isinstance(name, str) or not name.strip() or not roles:
                continue
            total_users += 1
            if isinstance(roles, str):
                roles = [role.strip() for role in roles.split(",") if role.strip()]
            if isinstance(roles, list) and any(str(role).lower() == "admin" for role in roles):
                admin_users.append(name.strip())

        if total_users == 0:
            total_users = self._safe_int(overview.get("total_users", 0))

        self._cached_contexts["users"] = {
            "total": total_users,
            "admins": len(admin_users),
            "admin_list": admin_users[:5] if admin_users else [],
        }
        return self._cached_contexts["users"]

    def _get_kv_context(self) -> Dict[str, Any]:
        if "kv_stores" in self._cached_contexts:
            return self._cached_contexts["kv_stores"]

        threat_intel: List[str] = []
        asset_collections: List[str] = []
        total_kv = 0
        for entry in self._iter_entries():
            data = entry.get("data", {}) if isinstance(entry.get("data", {}), dict) else {}
            name = str(data.get("name") or data.get("title") or "").strip()
            lowered = name.lower()
            if not name:
                continue
            ko_type = str(data.get("ko_type") or data.get("type") or "").lower()
            if ko_type not in {"kv_store", "kv_store_collections", "collections", "lookup"} and "collection" not in lowered and "lookup" not in lowered:
                continue
            total_kv += 1
            if any(term in lowered for term in ["threat", "intel", "ioc", "malware"]):
                threat_intel.append(name)
            if any(term in lowered for term in ["asset", "inventory", "cmdb"]):
                asset_collections.append(name)

        if total_kv == 0 and isinstance(self._discovery_data, dict):
            overview = self._discovery_data.get("overview", {}) if isinstance(self._discovery_data.get("overview", {}), dict) else {}
            total_kv = self._safe_int(overview.get("total_kv_collections", 0))

        self._cached_contexts["kv_stores"] = {
            "total": total_kv,
            "threat_intel": threat_intel[:5],
            "asset_collections": asset_collections[:5],
        }
        return self._cached_contexts["kv_stores"]

    def _get_overview_context(self) -> Dict[str, Any]:
        metadata = self.get_metadata()
        overview = metadata.get("overview", {}) if isinstance(metadata.get("overview", {}), dict) else {}
        return {
            **overview,
            "readiness_score": metadata.get("readiness_score", 0),
            "top_indexes": self._get_index_context()[:5],
            "top_hosts": self._get_host_context()[:5],
        }

    def _get_recommendation_context(self) -> List[Dict[str, Any]]:
        recommendations = self._discovery_data.get("recommendations", []) if isinstance(self._discovery_data, dict) else []
        return [item for item in recommendations[:6] if isinstance(item, dict)]

    def _get_risk_context(self) -> List[Dict[str, Any]]:
        risks = self._discovery_data.get("risk_register", []) if isinstance(self._discovery_data, dict) else []
        return [item for item in risks[:6] if isinstance(item, dict)]

    def _get_coverage_gap_context(self) -> List[Dict[str, Any]]:
        gaps = self._discovery_data.get("coverage_gaps", []) if isinstance(self._discovery_data, dict) else []
        return [item for item in gaps[:6] if isinstance(item, dict)]

    def _get_use_case_context(self) -> List[Dict[str, Any]]:
        use_cases = self._discovery_data.get("suggested_use_cases", []) if isinstance(self._discovery_data, dict) else []
        return [item for item in use_cases[:5] if isinstance(item, dict)]

    def format_context_for_llm(self, context: Dict[str, Any]) -> str:
        """Format context data into a readable string for LLM."""
        if not context:
            return ""

        lines = ["🔍 RELEVANT DISCOVERY CONTEXT:"]

        if "overview" in context and isinstance(context["overview"], dict):
            overview = context["overview"]
            lines.append("\n📌 Environment Overview:")
            lines.append(
                f"  - Readiness: {overview.get('readiness_score', 0)}/100 | "
                f"Indexes: {overview.get('total_indexes', 0)} | "
                f"Sourcetypes: {overview.get('total_sourcetypes', 0)} | "
                f"Hosts: {overview.get('total_hosts', 0)}"
            )
            if overview.get("data_volume_24h"):
                lines.append(f"  - Data volume (24h): {overview.get('data_volume_24h')}")
            if overview.get("top_indexes"):
                top_indexes = ", ".join([idx.get("name", "") for idx in overview.get("top_indexes", [])[:5] if isinstance(idx, dict)])
                if top_indexes:
                    lines.append(f"  - Top indexes: {top_indexes}")

        if "recommendations" in context:
            lines.append("\n💡 Recommendations:")
            for item in context["recommendations"][:4]:
                if isinstance(item, dict) and item.get("title"):
                    lines.append(f"  - {item.get('title')} ({item.get('priority', 'medium')})")

        if "risks" in context:
            lines.append("\n⚠️ Risks:")
            for item in context["risks"][:4]:
                if isinstance(item, dict) and item.get("risk"):
                    lines.append(f"  - {item.get('risk')} ({item.get('severity', 'medium')})")

        if "coverage_gaps" in context:
            lines.append("\n🧩 Coverage Gaps:")
            for item in context["coverage_gaps"][:4]:
                if isinstance(item, dict) and item.get("gap"):
                    lines.append(f"  - {item.get('gap')} ({item.get('priority', 'medium')})")

        if "suggested_use_cases" in context:
            lines.append("\n🚀 Suggested Use Cases:")
            for item in context["suggested_use_cases"][:3]:
                if isinstance(item, dict) and item.get("title"):
                    lines.append(f"  - {item.get('title')}")

        if "indexes" in context:
            lines.append("\n📁 Active Indexes:")
            for idx in context["indexes"][:10]:
                if isinstance(idx, dict):
                    lines.append(f"  - {idx['name']}: {idx['events']:,} events, {idx['size_mb']:.1f}MB")

        if "sourcetypes" in context and isinstance(context["sourcetypes"], dict):
            st_info = context["sourcetypes"]
            lines.append(f"\n📋 Sourcetypes: {st_info.get('total', 'unknown')} total, {st_info.get('active', 'unknown')} active")
            most_active = st_info.get("most_active", [])
            if isinstance(most_active, list) and most_active:
                preview = ", ".join([item.get("name", "") for item in most_active[:3] if isinstance(item, dict)])
                if preview:
                    lines.append(f"  Most Active: {preview}")

        if "hosts" in context:
            lines.append(f"\n🖥️ Active Hosts (top {min(10, len(context['hosts']))}):")
            for host in context["hosts"][:10]:
                if isinstance(host, dict):
                    lines.append(f"  - {host['name']}: {host['events']:,} events")

        if "alerts" in context:
            lines.append(f"\n🚨 Alerts ({len(context['alerts'])} configured):")
            for alert in context["alerts"][:5]:
                if isinstance(alert, dict):
                    lines.append(f"  - {alert['name']} (severity: {alert['severity']})")

        if "dashboards" in context:
            lines.append(f"\n📊 Dashboards ({len(context['dashboards'])} available):")
            for dash in context["dashboards"][:5]:
                lines.append(f"  - {dash}")

        if "users" in context and isinstance(context["users"], dict):
            user_info = context["users"]
            lines.append(f"\n👥 Users: {user_info.get('total', 0)} total, {user_info.get('admins', 0)} admins")

        if "kv_stores" in context and isinstance(context["kv_stores"], dict):
            kv_info = context["kv_stores"]
            lines.append(f"\n🗄️ KV Store: {kv_info.get('total', 0)} collections")
            if kv_info.get("threat_intel"):
                lines.append(f"  Threat Intel: {', '.join(kv_info['threat_intel'][:3])}")

        return "\n".join(lines)

    def _recommendation_hint_for_text(self, text: str) -> str:
        if not isinstance(text, str) or not isinstance(self._discovery_data, dict):
            return ""
        lowered = text.lower()
        recommendations = self._discovery_data.get("recommendations", [])
        if not isinstance(recommendations, list):
            return ""

        keyword_groups = [
            (["wineventlog", "endpoint", "auth", "login", "security"], "windows security"),
            (["_internal", "_audit", "_introspection", "license", "scheduler", "ingestion"], "platform health"),
            (["wmata", "api", "collector"], "wmata"),
            (["ping", "netops", "interface", "latency", "packet"], "network"),
        ]
        for keywords, hint in keyword_groups:
            if any(keyword in lowered for keyword in keywords):
                for item in recommendations[:10]:
                    if isinstance(item, dict) and hint in str(item.get("title", "")).lower():
                        return str(item.get("title", ""))
        return ""

    def get_context_after_tool_call(self, tool_name: str, tool_args: Dict, tool_result: Dict) -> str:
        """Provide relevant discovery context after a tool execution."""
        if not self._load_discovery_data():
            return ""

        context_lines: List[str] = []
        if tool_name in {"run_splunk_query", "splunk_run_query"}:
            query = tool_args.get("query", "")
            index_match = re.search(r'index=([^\s\|]+)', query)
            if index_match:
                index_name = index_match.group(1)
                index_info = next((idx for idx in self._get_index_context() if idx.get("name") == index_name), None)
                if index_info:
                    context_lines.append(
                        f"📍 Context: {index_name} has {index_info['events']:,} total events, {index_info['size_mb']:.1f}MB"
                    )

            sourcetype_match = re.search(r'sourcetype=([^\s\|]+)', query)
            if sourcetype_match:
                context_lines.append(f"📋 Searching sourcetype: {sourcetype_match.group(1)}")

            recommendation_hint = self._recommendation_hint_for_text(query)
            if recommendation_hint:
                context_lines.append(f"🧠 Related discovery recommendation: {recommendation_hint}")

        elif tool_name in {"get_indexes", "splunk_get_indexes"}:
            indexes = self._get_index_context()
            context_lines.append(f"📁 Total indexes with data: {len(indexes)}")

        elif tool_name in {"get_metadata", "splunk_get_metadata"}:
            metadata_type = tool_args.get("type", "")
            if metadata_type == "hosts":
                hosts = self._get_host_context()
                context_lines.append(f"🖥️ Top active hosts: {', '.join([host['name'] for host in hosts[:5]])}")

        return "\n".join(context_lines) if context_lines else ""


_context_manager: Optional[DiscoveryContextManager] = None


def get_context_manager() -> DiscoveryContextManager:
    """Get or create the global context manager instance."""
    global _context_manager
    if _context_manager is None:
        _context_manager = DiscoveryContextManager()
    return _context_manager
