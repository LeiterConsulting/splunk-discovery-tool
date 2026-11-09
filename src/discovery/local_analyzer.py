"""
Local data analyzer for Splunk discovery - processes data without LLM.

This module provides intelligent local analysis of Splunk environment data,
reducing the need for expensive LLM API calls by handling structural
analysis, pattern detection, and summarization locally.
"""

import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def safe_int(value: Any, default: int = 0) -> int:
    """Convert Splunk-style values ("12", "12.0", "1,234", 12.5, None) to int without raising."""
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) else default
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text:
            return default
        try:
            return int(text)
        except ValueError:
            try:
                parsed = float(text)
            except ValueError:
                return default
            return int(parsed) if math.isfinite(parsed) else default
    return default


def safe_float(value: Any, default: float = 0.0) -> float:
    """Convert Splunk-style values to float without raising."""
    if value is None:
        return default
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        result = float(value)
        return result if math.isfinite(result) else default
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text:
            return default
        try:
            result = float(text)
        except ValueError:
            return default
        return result if math.isfinite(result) else default
    return default


def metadata_recent_epoch(row: Any) -> Optional[float]:
    """Latest-event time of a Splunk metadata row as epoch seconds, or None.

    The MCP metadata tool's recentTimeIso/lastTimeIso values carry a "Z" suffix
    but have been observed in the Splunk server's local time, so the epoch
    recentTime/lastTime fields win whenever they are present.
    """
    if not isinstance(row, dict):
        return None
    for key in ("recentTime", "lastTime"):
        value = safe_float(row.get(key))
        if value > 0:
            return value
    for key in ("recentTimeIso", "lastTimeIso"):
        text = str(row.get(key) or "").strip()
        if not text:
            continue
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
    return None


def metadata_recent_time_utc(row: Any) -> str:
    """Latest-event time of a metadata row as ``YYYY-MM-DDTHH:MM:SSZ`` in UTC, or ''."""
    epoch = metadata_recent_epoch(row)
    if epoch is None:
        return ""
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_truthy_flag(value: Any) -> bool:
    """Interpret Splunk boolean-ish flags ("1", "true", 1, True)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "t"}
    return False


# Result kinds recorded on DiscoveryResult.kind by the discovery engine.
KIND_INDEX = "index"
KIND_SOURCETYPE = "sourcetype"
KIND_HOST = "host"
KIND_SOURCE = "source"
KIND_KNOWLEDGE_OBJECT = "knowledge_object"
KIND_INDEX_DETAIL = "index_detail"
KIND_USER = "user"
KIND_KV_COLLECTION = "kv_collection"
KIND_ANALYTICS = "analytics"
KIND_STEP_STATUS = "step_status"


def infer_result_kind(data: Any) -> str:
    """Best-effort kind inference for results that were not tagged by the engine."""
    if not isinstance(data, dict):
        return ""
    if "discovery_step" in data and "status" in data:
        return KIND_STEP_STATUS
    if "title" in data and ("currentDBSizeMB" in data or "totalEventCount" in data):
        return KIND_INDEX
    if "sourcetype" in data and "totalCount" in data:
        return KIND_SOURCETYPE
    if "host" in data and "totalCount" in data:
        return KIND_HOST
    if "source" in data and "totalCount" in data:
        return KIND_SOURCE
    if "ko_type" in data:
        return KIND_KNOWLEDGE_OBJECT
    if "findings" in data and "description" in data:
        return KIND_ANALYTICS
    return ""


def result_kind(result: Any) -> str:
    kind = getattr(result, "kind", "") if not isinstance(result, dict) else result.get("kind", "")
    if isinstance(kind, str) and kind:
        return kind
    data = getattr(result, "data", None) if not isinstance(result, dict) else result.get("data", result)
    return infer_result_kind(data)


class LocalDataAnalyzer:
    """Analyzes Splunk discovery data locally without requiring LLM calls."""

    def __init__(self):
        self.current_date = datetime.now()

    def summarize_discovery(self, discovery_results: List[Any]) -> Dict[str, Any]:
        """
        Create a compact summary of discovery results for LLM analysis.

        Args:
            discovery_results: List of DiscoveryResult objects

        Returns:
            Compact summary dict suitable for LLM (5-10KB instead of 500KB+)
        """
        buckets: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for result in discovery_results or []:
            data = getattr(result, "data", None) if not isinstance(result, dict) else result.get("data", result)
            if not isinstance(data, dict):
                continue
            buckets[result_kind(result) or "other"].append(data)

        indexes = buckets.get(KIND_INDEX, [])
        sourcetypes = buckets.get(KIND_SOURCETYPE, [])
        knowledge_objects = buckets.get(KIND_KNOWLEDGE_OBJECT, [])

        ko_by_type: Dict[str, int] = defaultdict(int)
        for ko in knowledge_objects:
            ko_by_type[str(ko.get("ko_type") or "unknown")] += 1

        step_issues = [
            {
                "step": data.get("discovery_step"),
                "status": data.get("status"),
                "error": str(data.get("error") or "")[:300],
            }
            for data in buckets.get(KIND_STEP_STATUS, [])
        ]

        summary = {
            "environment_overview": {
                "current_date": self.current_date.strftime('%Y-%m-%d'),
                "size_category": self._categorize_environment_size(indexes, sourcetypes),
                "total_indexes": len(indexes),
                "total_sourcetypes": len(sourcetypes),
                "total_hosts": len(buckets.get(KIND_HOST, [])),
                "total_sources": len(buckets.get(KIND_SOURCE, [])),
                "total_knowledge_objects": len(knowledge_objects),
                "knowledge_objects_by_type": dict(ko_by_type),
                "authenticated_user_records": len(buckets.get(KIND_USER, [])),
                "total_kv_collections": len(buckets.get(KIND_KV_COLLECTION, [])),
            },
            "index_analysis": self.analyze_indexes(indexes),
            "sourcetype_analysis": self.analyze_sourcetypes(sourcetypes),
            "data_quality": self.analyze_data_quality(indexes, sourcetypes),
            "capability_gaps": self.detect_gaps(sourcetypes),
            "interesting_findings": self._extract_interesting_findings(discovery_results or []),
        }
        if step_issues:
            summary["discovery_step_issues"] = step_issues[:20]

        return summary

    def analyze_indexes(self, indexes_data: List[Dict]) -> Dict[str, Any]:
        """Analyze index data locally and return compact summary."""
        if not indexes_data:
            return {"total": 0, "active": 0, "empty": 0}

        active_indexes = []
        empty_indexes = []
        sizes = []
        event_counts = []

        for idx in indexes_data:
            if not isinstance(idx, dict):
                continue
            size_mb = safe_float(idx.get('currentDBSizeMB'))
            event_count = safe_int(idx.get('totalEventCount'))
            name = idx.get('title') or idx.get('name')

            if size_mb > 0 or event_count > 0:
                active_indexes.append({
                    "name": name,
                    "size_mb": size_mb,
                    "events": event_count
                })
                sizes.append(size_mb)
                event_counts.append(event_count)
            else:
                empty_indexes.append(name)

        active_indexes.sort(key=lambda x: x['size_mb'], reverse=True)

        return {
            "total": len(indexes_data),
            "active": len(active_indexes),
            "empty": len(empty_indexes),
            "empty_index_names": empty_indexes[:10],
            "largest_indexes": active_indexes[:5],
            "total_data_mb": round(sum(sizes), 2),
            "total_events": sum(event_counts),
            "size_distribution": self._categorize_sizes(sizes)
        }

    def analyze_sourcetypes(self, sourcetypes_data: List[Dict]) -> Dict[str, Any]:
        """Analyze sourcetype data locally and return compact summary."""
        if not sourcetypes_data:
            return {"total": 0, "platforms": {}, "categories": {}, "category_totals": {}}

        platforms = defaultdict(list)
        categories = defaultdict(list)
        top_sourcetypes = []
        time_ranges = []

        for st in sourcetypes_data:
            if not isinstance(st, dict):
                continue
            st_name = str(st.get('sourcetype', st.get('type', st.get('name', ''))) or '')
            count = safe_int(st.get('totalCount'))

            if count > 0:
                platform = self._identify_platform(st_name)
                platforms[platform].append(st_name)

                category = self._identify_category(st_name)
                categories[category].append({
                    "name": st_name,
                    "events": count,
                    "platform": platform
                })

                top_sourcetypes.append({
                    "name": st_name,
                    "events": count,
                    "platform": platform,
                    "category": category
                })

                if 'firstTime' in st:
                    time_ranges.append(st.get('firstTime'))
                if 'recentTime' in st:
                    time_ranges.append(st.get('recentTime'))

        top_sourcetypes.sort(key=lambda x: x['events'], reverse=True)
        for entries in categories.values():
            entries.sort(key=lambda x: x['events'], reverse=True)

        return {
            "total": len(sourcetypes_data),
            "active": len(top_sourcetypes),
            "platforms": {k: len(v) for k, v in platforms.items()},
            "platform_examples": {k: v[:5] for k, v in platforms.items()},
            "categories": {k: len(v) for k, v in categories.items()},
            # Prompt-friendly sample; use category_totals for counts and volumes.
            "category_details": {k: v[:10] for k, v in categories.items()},
            "category_totals": {
                k: {"count": len(v), "events": sum(item["events"] for item in v)}
                for k, v in categories.items()
            },
            "top_5_sourcetypes": top_sourcetypes[:5],
            "data_span": self._analyze_time_range(time_ranges) if time_ranges else "Unknown"
        }

    def analyze_data_quality(self, indexes_data: List[Dict], sourcetypes_data: List[Dict]) -> Dict[str, Any]:
        """Analyze data quality without LLM."""
        issues = []
        score = 100

        valid_indexes = [idx for idx in indexes_data if isinstance(idx, dict)]
        empty_count = sum(
            1 for idx in valid_indexes
            if safe_float(idx.get('currentDBSizeMB')) == 0 and safe_int(idx.get('totalEventCount')) == 0
        )
        if valid_indexes and empty_count > len(valid_indexes) * 0.5:
            issues.append(f"High number of empty indexes ({empty_count}/{len(valid_indexes)})")
            score -= 15

        for st in sourcetypes_data:
            if not isinstance(st, dict) or 'firstTime' not in st:
                continue
            first_epoch = safe_int(st.get('firstTime'))
            if first_epoch <= 0:
                continue
            try:
                age_days = (self.current_date - datetime.fromtimestamp(first_epoch)).days
            except (OverflowError, OSError, ValueError):
                continue
            if age_days > 365 * 3:
                issues.append(f"Data spans multiple years (oldest: {age_days} days)")
                break

        recent_count = 0
        timed_count = 0
        for st in sourcetypes_data:
            if not isinstance(st, dict) or 'recentTime' not in st:
                continue
            recent_epoch = safe_int(st.get('recentTime'))
            if recent_epoch <= 0:
                continue
            timed_count += 1
            try:
                age_hours = (self.current_date - datetime.fromtimestamp(recent_epoch)).total_seconds() / 3600
            except (OverflowError, OSError, ValueError):
                continue
            if age_hours < 24:
                recent_count += 1

        if timed_count and recent_count < timed_count * 0.3:
            issues.append(f"Limited recent data activity ({recent_count}/{timed_count} active in last 24h)")
            score -= 10

        return {
            "score": max(0, score),
            "issues": issues,
            "recommendations": self._generate_quality_recommendations(issues)
        }

    def detect_gaps(self, sourcetypes_data: List[Dict]) -> Dict[str, List[str]]:
        """Identify missing monitoring capabilities with detailed analysis."""
        platforms = set()
        categories = set()

        for st in sourcetypes_data:
            if not isinstance(st, dict):
                continue
            st_name = str(st.get('sourcetype', st.get('type', st.get('name', ''))) or '')

            if st_name:
                platforms.add(self._identify_platform(st_name).lower())
                categories.add(self._identify_category(st_name).lower())

        common_platforms = {'windows', 'unix/linux', 'network', 'cloud', 'database', 'web server'}
        common_categories = {'security', 'infrastructure', 'business', 'compliance'}

        missing_platforms = common_platforms - platforms
        missing_categories = common_categories - categories

        return {
            "missing_platforms": sorted(missing_platforms),
            "missing_categories": sorted(missing_categories),
            "detected_platforms": sorted(platforms),
            "detected_categories": sorted(categories),
            "recommendations": self._generate_gap_recommendations(missing_platforms, missing_categories)
        }

    def _categorize_environment_size(self, indexes: List, sourcetypes: List) -> str:
        """Categorize environment as Small/Medium/Large."""
        idx_count = len(indexes)
        st_count = len(sourcetypes)

        if idx_count < 20 and st_count < 20:
            return "Small"
        elif idx_count < 100 and st_count < 100:
            return "Medium"
        else:
            return "Large"

    def _categorize_sizes(self, sizes: List[float]) -> Dict[str, int]:
        """Categorize index sizes."""
        if not sizes:
            return {"small": 0, "medium": 0, "large": 0}

        return {
            "small": sum(1 for s in sizes if s < 100),
            "medium": sum(1 for s in sizes if 100 <= s < 1000),
            "large": sum(1 for s in sizes if s >= 1000)
        }

    def _identify_platform(self, sourcetype_name: str) -> str:
        """Identify platform from sourcetype name with comprehensive pattern matching."""
        st_lower = sourcetype_name.lower()

        if any(pattern in st_lower for pattern in ['wineventlog', 'windows', 'win:', 'perfmon', 'msad:', 'ms:', 'iis', 'mssql']):
            return "Windows"
        elif any(pattern in st_lower for pattern in ['unix:', 'linux', 'syslog', 'linux_', 'bash', 'sh_history', 'secure.log', 'messages.log', 'apt_', 'yum_', 'dpkg']):
            return "Unix/Linux"
        elif any(pattern in st_lower for pattern in ['network', 'firewall', 'cisco', 'juniper', 'palo alto', 'pan:', 'fortinet', 'fortigate', 'netflow', 'router', 'switch', 'vpn']):
            return "Network"
        elif any(pattern in st_lower for pattern in ['cloud', 'aws', 'azure', 'gcp', 'cloudtrail', 's3:', 'ec2:', 'lambda']):
            return "Cloud"
        elif any(pattern in st_lower for pattern in ['database', 'sql', 'oracle', 'mysql', 'postgres', 'mongodb', 'db2', 'cassandra']):
            return "Database"
        elif any(pattern in st_lower for pattern in ['access_combined', 'access_', 'apache', 'nginx', 'tomcat', 'weblogic']):
            return "Web Server"
        elif any(pattern in st_lower for pattern in ['application', 'app:', 'app_']):
            return "Application"
        elif any(pattern in st_lower for pattern in ['cpu', 'memory', 'disk', 'interfaces', 'uptime', 'vmstat', 'iostat', 'netstat']):
            return "System Metrics"
        else:
            return "Application"

    def _identify_category(self, sourcetype_name: str) -> str:
        """Identify use case category (Security, Infrastructure, Business, Compliance) from sourcetype."""
        st_lower = sourcetype_name.lower()

        if any(pattern in st_lower for pattern in [
            'security', 'auth', 'wineventlog:security', 'linux_secure', 'sudo', 'passwd',
            'firewall', 'ids', 'ips', 'antivirus', 'malware', 'threat',
            'vpn', 'proxy', 'ssl', 'certificate', 'login', 'authentication'
        ]):
            return "Security"
        elif any(pattern in st_lower for pattern in [
            'audit', 'compliance', 'regulatory', 'policy', 'governance',
            'pci', 'hipaa', 'sox', 'gdpr', 'license'
        ]):
            return "Compliance"
        elif any(pattern in st_lower for pattern in [
            'business', 'transaction', 'order', 'customer', 'crm', 'erp',
            'salesforce', 'workday', 'sap', 'analytics', 'bi_'
        ]):
            return "Business"
        else:
            return "Infrastructure"

    def _analyze_time_range(self, time_values: List) -> str:
        """Analyze time range of data."""
        timestamps = [safe_int(tv) for tv in time_values]
        timestamps = [ts for ts in timestamps if ts > 0]
        if not timestamps:
            return "Unknown"
        try:
            earliest = datetime.fromtimestamp(min(timestamps))
            latest = datetime.fromtimestamp(max(timestamps))
        except (OverflowError, OSError, ValueError):
            return "Unknown"
        span_days = (latest - earliest).days
        return f"{span_days} days (from {earliest.strftime('%Y-%m-%d')} to {latest.strftime('%Y-%m-%d')})"

    def _extract_interesting_findings(self, discovery_results: List) -> List[str]:
        """Extract interesting findings from discovery results (deterministic order)."""
        findings: List[str] = []
        for result in discovery_results:
            items = getattr(result, "interesting_findings", None)
            if isinstance(result, dict):
                items = result.get("interesting_findings") or result.get("findings")
            if items:
                findings.extend(str(item) for item in items)

        return list(dict.fromkeys(findings))[:10]

    def _generate_quality_recommendations(self, issues: List[str]) -> List[str]:
        """Generate recommendations based on quality issues."""
        recs = []

        for issue in issues:
            if "empty indexes" in issue.lower():
                recs.append("Consider disabling or removing unused indexes to optimize storage")
            if "old data" in issue.lower() or "spans" in issue.lower():
                recs.append("Review data retention policies - very old data may not be needed")
            if "recent data" in issue.lower():
                recs.append("Investigate why many data sources haven't sent recent data")

        return recs

    def _generate_gap_recommendations(self, missing_platforms: set, missing_capabilities: set) -> List[str]:
        """Generate recommendations for capability gaps."""
        recs = []

        if 'network' in missing_platforms:
            recs.append("Consider adding network traffic monitoring (firewalls, switches, routers)")
        if 'cloud' in missing_platforms:
            recs.append("Add cloud infrastructure monitoring (AWS, Azure, GCP)")
        if 'database' in missing_platforms:
            recs.append("Include database monitoring for performance and security")

        if 'compliance' in missing_capabilities:
            recs.append("Implement compliance monitoring for regulatory requirements")
        if 'business' in missing_capabilities:
            recs.append("Add business analytics data sources for KPI tracking")

        return recs
