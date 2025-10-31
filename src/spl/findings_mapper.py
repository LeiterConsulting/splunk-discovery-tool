"""
Findings-to-Query Mapper - Generates targeted SPL queries based on specific findings.

This module takes extracted findings from reports and creates highly specific,
actionable SPL queries that directly address discovered issues.
"""

from typing import Dict, List, Any
from datetime import datetime


class FindingsQueryMapper:
    """Maps specific findings to targeted SPL queries."""
    
    def __init__(self, findings: Dict[str, List[Dict[str, Any]]], 
                 indexes: List[str], 
                 sourcetypes: List[str]):
        self.findings = findings
        self.indexes = indexes or ['*']
        self.sourcetypes = sourcetypes or []
        
    def generate_finding_based_queries(self) -> List[Dict[str, Any]]:
        """Generate queries targeting specific findings."""
        queries = []
        
        # Security findings
        for finding in self.findings.get('security_issues', []):
            queries.extend(self._map_security_finding(finding))
        
        # Performance findings
        for finding in self.findings.get('performance_issues', []):
            queries.extend(self._map_performance_finding(finding))
        
        # Data quality findings
        for finding in self.findings.get('data_quality_issues', []):
            queries.extend(self._map_data_quality_finding(finding))
        
        # Optimization findings
        for finding in self.findings.get('optimization_opportunities', []):
            queries.extend(self._map_optimization_finding(finding))
        
        # Anomalies
        for finding in self.findings.get('anomalies', []):
            queries.extend(self._map_anomaly_finding(finding))
        
        # Gaps
        for finding in self.findings.get('gaps', []):
            queries.extend(self._map_gap_finding(finding))
        
        return queries
    
    def _map_security_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map security findings to queries."""
        queries = []
        
        if finding['type'] == 'failed_authentications':
            count = finding.get('count', 0)
            severity_emoji = "🔴" if finding['severity'] == 'high' else "🟡"
            
            queries.append({
                "title": f"🎯 Investigate {count} Failed Authentication Attempts",
                "description": f"Discovery found {count} failed authentication attempts. This query identifies the sources and targets.",
                "use_case": "Security Investigation",
                "category": "Security & Compliance",
                "finding_reference": finding['description'],
                "spl": self._generate_failed_auth_investigation_spl(count),
                "execution_time": "< 30 seconds",
                "business_value": f"Directly addresses the {count} failed authentication attempts found in your environment. Identifies attackers and compromised accounts.",
                "priority": "🔴 HIGH" if finding['severity'] == 'high' else "🟡 MEDIUM",
                "difficulty": "Beginner",
                "dashboard_type": "Table + Timeline"
            })
            
            # Add real-time alert
            queries.append({
                "title": f"{severity_emoji} Real-Time Alert for Failed Authentication Spikes",
                "description": f"Get immediate notification when failed auth attempts exceed {max(10, count // 2)} in 5 minutes",
                "use_case": "Security Alerting",
                "category": "Security & Compliance",
                "finding_reference": finding['description'],
                "spl": self._generate_failed_auth_alert_spl(max(10, count // 2)),
                "execution_time": "Real-time",
                "business_value": f"Prevents recurrence of the {count} failed attempts by alerting on suspicious patterns immediately",
                "priority": "🔴 HIGH",
                "difficulty": "Intermediate",
                "dashboard_type": "Alert"
            })
        
        elif finding['type'] == 'account_lockouts':
            count = finding.get('count', 0)
            queries.append({
                "title": f"🔒 Track {count} Account Lockout Events",
                "description": f"Discovery found {count} account lockouts. Investigate causes and patterns.",
                "use_case": "Security Monitoring",
                "category": "Security & Compliance",
                "finding_reference": finding['description'],
                "spl": self._generate_lockout_investigation_spl(),
                "execution_time": "< 1 minute",
                "business_value": f"Understand why {count} accounts were locked out - potential attacks or user issues",
                "priority": "🟡 MEDIUM",
                "difficulty": "Beginner",
                "dashboard_type": "Table + Heatmap"
            })
        
        elif finding['type'] == 'missing_alerts':
            queries.append({
                "title": "🚨 Comprehensive Security Alert Coverage",
                "description": "Discovery identified gaps in security monitoring. This creates a baseline security alerting dashboard.",
                "use_case": "Security Monitoring",
                "category": "Security & Compliance",
                "finding_reference": "Addressing security monitoring gaps identified in discovery",
                "spl": self._generate_security_baseline_spl(),
                "execution_time": "< 2 minutes",
                "business_value": "Fills the security monitoring gaps identified in your environment",
                "priority": "🔴 HIGH",
                "difficulty": "Intermediate",
                "dashboard_type": "Multi-panel Dashboard"
            })
        
        return queries
    
    def _map_performance_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map performance findings to queries."""
        queries = []
        
        if finding['type'] == 'high_cpu':
            value = finding.get('value', 0)
            queries.append({
                "title": f"📊 Monitor {value}% CPU Utilization Trend",
                "description": f"Discovery found {value}% CPU usage. Track trends and identify root causes.",
                "use_case": "Performance Monitoring",
                "category": "Infrastructure & Performance",
                "finding_reference": finding['description'],
                "spl": self._generate_cpu_investigation_spl(value),
                "execution_time": "< 1 minute",
                "business_value": f"Investigate the {value}% CPU usage detected - prevent performance degradation",
                "priority": "🔴 HIGH" if value > 90 else "🟡 MEDIUM",
                "difficulty": "Beginner",
                "dashboard_type": "Timechart + Table"
            })
        
        elif finding['type'] == 'high_memory':
            value = finding.get('value', 0)
            queries.append({
                "title": f"💾 Analyze {value}% Memory Utilization",
                "description": f"Discovery found {value}% memory usage. Identify memory pressure and prevent OOM.",
                "use_case": "Capacity Planning",
                "category": "Infrastructure & Performance",
                "finding_reference": finding['description'],
                "spl": self._generate_memory_investigation_spl(value),
                "execution_time": "< 1 minute",
                "business_value": f"Address the {value}% memory usage - plan upgrades before system crashes",
                "priority": "🔴 CRITICAL" if value > 95 else "🟡 HIGH",
                "difficulty": "Intermediate",
                "dashboard_type": "Timechart + Single Value"
            })
        
        elif finding['type'] == 'disk_space':
            value = finding.get('value', 0)
            queries.append({
                "title": f"💽 Critical: {value}% Disk Space Used",
                "description": f"Discovery found {value}% disk usage. Identify space consumers and plan expansion.",
                "use_case": "Storage Management",
                "category": "Infrastructure & Performance",
                "finding_reference": finding['description'],
                "spl": self._generate_disk_investigation_spl(value),
                "execution_time": "< 30 seconds",
                "business_value": f"Prevent disk full situation from {value}% usage - avoid service outages",
                "priority": "🔴 CRITICAL" if value > 90 else "🟠 HIGH",
                "difficulty": "Beginner",
                "dashboard_type": "Table + Pie Chart"
            })
        
        return queries
    
    def _map_data_quality_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map data quality findings to queries."""
        queries = []
        
        if finding['type'] == 'empty_indexes':
            count = finding.get('count', 0)
            queries.append({
                "title": f"🔍 Audit {count} Empty Indexes",
                "description": f"Discovery found {count} indexes with no data. Verify configuration and data collection.",
                "use_case": "Data Quality",
                "category": "Capacity Planning",
                "finding_reference": finding['description'],
                "spl": self._generate_empty_index_audit_spl(),
                "execution_time": "< 10 seconds",
                "business_value": f"Fix data collection issues for {count} empty indexes - ensure complete visibility",
                "priority": "🟡 MEDIUM",
                "difficulty": "Beginner",
                "dashboard_type": "Table"
            })
        
        elif finding['type'] == 'data_gaps':
            queries.append({
                "title": "📉 Identify Data Collection Gaps",
                "description": "Discovery detected gaps in data collection. Find missing time periods and sources.",
                "use_case": "Data Quality",
                "category": "Data Exploration",
                "finding_reference": finding['description'],
                "spl": self._generate_data_gap_analysis_spl(),
                "execution_time": "< 1 minute",
                "business_value": "Fix data collection gaps identified in discovery - ensure compliance and complete visibility",
                "priority": "🟡 MEDIUM",
                "difficulty": "Intermediate",
                "dashboard_type": "Timeline + Table"
            })
        
        return queries
    
    def _map_optimization_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map optimization findings to queries."""
        queries = []
        
        if finding['type'] == 'retention_optimization':
            queries.append({
                "title": "⚙️ Retention Policy Optimization Analysis",
                "description": "Discovery found suboptimal retention policies. Analyze usage patterns to optimize.",
                "use_case": "Cost Optimization",
                "category": "Capacity Planning",
                "finding_reference": finding['description'],
                "spl": self._generate_retention_optimization_spl(),
                "execution_time": "< 1 minute",
                "business_value": "Optimize storage costs while maintaining compliance - save $$ on storage",
                "priority": "🟢 LOW",
                "difficulty": "Advanced",
                "dashboard_type": "Table + Recommendations"
            })
        
        elif finding['type'] == 'acceleration_opportunity':
            queries.append({
                "title": "🚀 Data Model Acceleration Candidates",
                "description": "Discovery identified large indexes without acceleration. Find best candidates for acceleration.",
                "use_case": "Performance Optimization",
                "category": "Infrastructure & Performance",
                "finding_reference": finding['description'],
                "spl": self._generate_acceleration_candidates_spl(),
                "execution_time": "< 30 seconds",
                "business_value": "Speed up searches by 10-100x on frequently accessed data",
                "priority": "🟡 MEDIUM",
                "difficulty": "Advanced",
                "dashboard_type": "Table + Recommendations"
            })
        
        return queries
    
    def _map_anomaly_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map anomaly findings to queries."""
        queries = []
        
        if finding['type'] == 'volume_anomaly':
            queries.append({
                "title": "📈 Investigate Volume Spike Detected in Discovery",
                "description": "Discovery detected unusual data volume. Identify source and cause.",
                "use_case": "Anomaly Detection",
                "category": "Data Exploration",
                "finding_reference": finding['description'],
                "spl": self._generate_volume_anomaly_spl(),
                "execution_time": "< 1 minute",
                "business_value": "Understand volume spikes - could indicate attacks, misconfig, or new data sources",
                "priority": "🟡 MEDIUM",
                "difficulty": "Intermediate",
                "dashboard_type": "Timechart + Table"
            })
        
        elif finding['type'] == 'after_hours_activity':
            queries.append({
                "title": "🌙 After-Hours Access Pattern Analysis",
                "description": "Discovery detected unusual after-hours activity. Identify users and patterns.",
                "use_case": "Threat Detection",
                "category": "Security & Compliance",
                "finding_reference": finding['description'],
                "spl": self._generate_after_hours_analysis_spl(),
                "execution_time": "< 1 minute",
                "business_value": "Detect insider threats or compromised credentials from after-hours activity",
                "priority": "🟠 HIGH",
                "difficulty": "Intermediate",
                "dashboard_type": "Heatmap + Table"
            })
        
        return queries
    
    def _map_gap_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map gap findings to queries."""
        queries = []
        
        gap_titles = {
            "firewall_logs": "🛡️ Firewall Log Collection Gap",
            "auth_logs": "🔐 Authentication Log Collection Gap",
            "web_logs": "🌐 Web Traffic Log Collection Gap",
            "database_logs": "💾 Database Log Collection Gap"
        }
        
        if finding['type'] in gap_titles:
            queries.append({
                "title": gap_titles[finding['type']],
                "description": f"Discovery identified missing {finding['description']}. This query helps verify and configure collection.",
                "use_case": "Configuration Validation",
                "category": "Data Exploration",
                "finding_reference": finding['description'],
                "spl": self._generate_gap_verification_spl(finding['type']),
                "execution_time": "< 10 seconds",
                "business_value": f"Address the {finding['description']} gap - improve security visibility",
                "priority": "🟡 MEDIUM",
                "difficulty": "Beginner",
                "dashboard_type": "Verification + Setup Guide"
            })
        
        return queries
    
    # SPL Generation Methods for Findings
    
    def _generate_failed_auth_investigation_spl(self, count: int) -> str:
        threshold = max(5, count // 10)  # 10% of discovered failures
        return f"""index=* (EventCode=4625 OR action=failure OR action=failed OR result=fail*)
    (user=* OR Account_Name=* OR src_user=*)
| eval user=coalesce(user, Account_Name, src_user, "unknown")
| eval src_ip=coalesce(src_ip, Source_Network_Address, src, "unknown")
| stats count as failed_attempts,
        earliest(_time) as first_attempt,
        latest(_time) as last_attempt,
        dc(ComputerName) as systems_targeted,
        values(ComputerName) as target_systems
  by user, src_ip
| where failed_attempts > {threshold}
| eval first_attempt=strftime(first_attempt, "%Y-%m-%d %H:%M:%S"),
       last_attempt=strftime(last_attempt, "%Y-%m-%d %H:%M:%S")
| eval severity=case(
    failed_attempts > {count}, "🔴 CRITICAL - Exceeds discovery baseline",
    failed_attempts > {count // 2}, "🟠 HIGH - Approaching discovery levels",
    1=1, "🟡 MEDIUM - Monitor closely"
)
| eval discovery_note="Discovery found {count} total failures. Investigate these specific sources."
| sort - failed_attempts
| head 50
| rename user as "User Account",
         src_ip as "Source IP",
         failed_attempts as "Failed Attempts",
         systems_targeted as "# Systems",
         target_systems as "Targets",
         severity as "Severity",
         first_attempt as "First Attempt",
         last_attempt as "Last Attempt",
         discovery_note as "Context"
| table Severity, "User Account", "Source IP", "Failed Attempts", "# Systems", "First Attempt", "Last Attempt", Context, Targets"""

    def _generate_failed_auth_alert_spl(self, threshold: int) -> str:
        return f"""index=* (EventCode=4625 OR action=failure OR action=failed OR result=fail*)
    (user=* OR Account_Name=* OR src_user=*)
| eval user=coalesce(user, Account_Name, src_user, "unknown")
| bin _time span=5m
| stats count as failures_5min by _time, user, src_ip
| where failures_5min > {threshold}
| eval alert_reason="Failed authentication spike: " + failures_5min + " attempts in 5 minutes (threshold: {threshold})"
| eval recommended_action=if(failures_5min > {threshold * 2}, "🔴 IMMEDIATE: Block source IP and investigate", "🟡 INVESTIGATE: Check for brute force attack")
| table _time, user, src_ip, failures_5min, alert_reason, recommended_action"""

    def _generate_lockout_investigation_spl(self) -> str:
        return """index=* (EventCode=4740 OR "account lockout" OR "account locked")
| eval user=coalesce(user, Account_Name, Targeted_User_Name, "unknown")
| eval locker=coalesce(Caller_Computer_Name, src, host, "unknown")
| stats count as lockout_count,
        earliest(_time) as first_lockout,
        latest(_time) as last_lockout,
        values(locker) as lockout_sources
  by user
| eval first_lockout=strftime(first_lockout, "%Y-%m-%d %H:%M:%S"),
       last_lockout=strftime(last_lockout, "%Y-%m-%d %H:%M:%S")
| eval hours_span=round((strptime(last_lockout, "%Y-%m-%d %H:%M:%S") - strptime(first_lockout, "%Y-%m-%d %H:%M:%S")) / 3600, 1)
| eval pattern=case(
    lockout_count > 10, "🔴 REPEATED - Possible attack",
    lockout_count > 5, "🟠 FREQUENT - Investigate",
    lockout_count > 1, "🟡 MULTIPLE - Monitor",
    1=1, "🟢 SINGLE - Likely user error"
)
| sort - lockout_count
| table pattern, user, lockout_count, hours_span, first_lockout, last_lockout, lockout_sources"""

    def _generate_security_baseline_spl(self) -> str:
        return """index=* earliest=-24h
| eval security_category=case(
    (EventCode>=4624 AND EventCode<=4634) OR action="login" OR action="logon", "Authentication",
    (EventCode>=4740 AND EventCode<=4767) OR "account lock", "Account Management",
    EventCode=4625 OR action="failure" OR result="failed", "Failed Access",
    action="blocked" OR action="deny", "Network Security",
    Type="Error" OR Level="Error", "System Errors",
    1=1, "Other"
)
| stats count by security_category, index, sourcetype
| eventstats sum(count) as total by security_category
| eval pct=round(count/total*100, 1)
| fields - total
| sort - count
| head 100"""

    def _generate_cpu_investigation_spl(self, threshold: int) -> str:
        return f"""index=* (PercentProcessorTime=* OR cpu_usage=* OR "cpu" OR "processor")
| eval cpu_pct=coalesce(PercentProcessorTime, cpu_usage, CPU, Processor)
| where isnotnull(cpu_pct) AND cpu_pct > {max(50, threshold - 20)}
| eval severity=case(
    cpu_pct > {threshold}, "🔴 CRITICAL - Above discovery baseline ({threshold}%)",
    cpu_pct > {threshold - 10}, "🟠 HIGH - Approaching discovery levels",
    cpu_pct > {threshold - 20}, "🟡 ELEVATED - Monitor trend",
    1=1, "🟢 NORMAL"
)
| timechart span=5m avg(cpu_pct) as avg_cpu, max(cpu_pct) as max_cpu by host
| addtotals fieldname=total_avg_cpu
| eval discovery_baseline="{threshold}%" """

    def _generate_memory_investigation_spl(self, threshold: int) -> str:
        return f"""index=* (PercentMemoryUsed=* OR memory_usage=* OR "memory" OR "mem")
| eval mem_pct=coalesce(PercentMemoryUsed, memory_usage, MemoryUsage, MemPct)
| where isnotnull(mem_pct) AND mem_pct > {max(60, threshold - 20)}
| eval severity=case(
    mem_pct > {threshold}, "🔴 CRITICAL - Above discovery baseline ({threshold}%)",
    mem_pct > {threshold - 10}, "🟠 HIGH - Risk of OOM",
    mem_pct > {threshold - 20}, "🟡 ELEVATED - Monitor closely",
    1=1, "🟢 NORMAL"
)
| timechart span=5m avg(mem_pct) as avg_memory, max(mem_pct) as max_memory by host
| eval discovery_baseline="{threshold}%"
| eval recommendation=if(max_memory > {threshold}, "Consider memory upgrade or application optimization", "Monitor trend")"""

    def _generate_disk_investigation_spl(self, threshold: int) -> str:
        return f"""index=* (PercentDiskUsed=* OR disk_usage=* OR "disk" OR "storage")
| eval disk_pct=coalesce(PercentDiskUsed, disk_usage, DiskUsage, Storage)
| where isnotnull(disk_pct) AND disk_pct > {max(70, threshold - 15)}
| eval mount=coalesce(mount, MountPoint, Drive, "unknown")
| stats avg(disk_pct) as avg_usage, max(disk_pct) as max_usage, latest(_time) as last_seen by host, mount
| eval severity=case(
    max_usage > {threshold}, "🔴 CRITICAL - Above discovery baseline ({threshold}%)",
    max_usage > {threshold - 10}, "🟠 HIGH - Plan expansion",
    max_usage > {threshold - 15}, "🟡 ELEVATED - Monitor growth",
    1=1, "🟢 NORMAL"
)
| eval days_until_full=case(
    max_usage > 95, "< 7 days",
    max_usage > 90, "< 30 days",
    max_usage > 85, "< 90 days",
    1=1, "> 90 days"
)
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort - max_usage
| table severity, host, mount, max_usage, avg_usage, days_until_full, last_seen"""

    def _generate_empty_index_audit_spl(self) -> str:
        return """| rest /services/data/indexes 
| search disabled=0
| eval size_mb=if(isnull(currentDBSizeMB), 0, currentDBSizeMB)
| eval events=if(isnull(totalEventCount), 0, totalEventCount)
| where events=0
| eval status=case(
    size_mb > 0, "🟡 Has data files but no events - Check indexing",
    1=1, "🔴 Completely empty - Verify configuration"
)
| eval action=case(
    size_mb > 0, "Run validation query to check for parsing errors",
    1=1, "Verify data inputs and forwarder configuration"
)
| table title, status, size_mb, events, action
| rename title as "Index Name", status as "Status", size_mb as "Size (MB)", events as "Events", action as "Recommended Action"
| sort "Index Name" """

    def _generate_data_gap_analysis_spl(self) -> str:
        return """index=* earliest=-7d latest=now
| bin _time span=1h
| stats count by _time, index, sourcetype
| eval expected_count=avg(count)
| where count < (expected_count * 0.5)
| eval gap_severity=case(
    count=0, "🔴 CRITICAL - Complete data loss",
    count < (expected_count * 0.25), "🟠 HIGH - Significant gap",
    1=1, "🟡 MEDIUM - Reduced volume"
)
| eval _time=strftime(_time, "%Y-%m-%d %H:%M")
| table _time, index, sourcetype, count, expected_count, gap_severity
| rename _time as "Time Period", gap_severity as "Severity", expected_count as "Expected Count"
| sort - Severity, "Time Period" """

    def _generate_retention_optimization_spl(self) -> str:
        return """| rest /services/data/indexes
| eval retention_days=frozenTimePeriodInSecs/86400
| eval size_gb=currentDBSizeMB/1024
| eval events_per_day=totalEventCount/retention_days
| eval cost_per_day=size_gb*0.10
| eval recommendation=case(
    events_per_day < 1000 AND retention_days > 90, "🟢 REDUCE retention to 90 days - Low activity index",
    size_gb > 100 AND retention_days > 365, "🟡 REVIEW retention - Large index, consider archiving",
    events_per_day > 100000 AND retention_days < 30, "🟠 INCREASE retention - High activity, compliance risk",
    1=1, "✅ Current retention appears appropriate"
)
| eval annual_savings=if(match(recommendation, "REDUCE"), cost_per_day*365*0.5, 0)
| table title, retention_days, size_gb, events_per_day, cost_per_day, annual_savings, recommendation
| sort - annual_savings"""

    def _generate_acceleration_candidates_spl(self) -> str:
        return """| rest /services/data/indexes
| eval size_gb=currentDBSizeMB/1024
| eval events_millions=totalEventCount/1000000
| where size_gb > 10 AND acceleration=0
| eval search_frequency="Check search.log for actual usage"
| eval speed_improvement="10-100x faster searches"
| eval recommendation=case(
    size_gb > 100, "🔴 HIGH PRIORITY - Large index, significant performance gains",
    size_gb > 50, "🟡 MEDIUM PRIORITY - Moderate gains expected",
    1=1, "🟢 LOW PRIORITY - Consider if heavily searched"
)
| table title, size_gb, events_millions, recommendation, speed_improvement
| rename title as "Index", size_gb as "Size (GB)", events_millions as "Events (M)", recommendation as "Priority"
| sort - "Size (GB)" """

    def _generate_volume_anomaly_spl(self) -> str:
        return """index=* earliest=-7d latest=now
| bin _time span=1h
| stats count by _time, index, sourcetype
| eventstats avg(count) as avg_count, stdev(count) as std_count by index, sourcetype
| eval z_score=abs((count - avg_count) / std_count)
| where z_score > 3
| eval anomaly_type=case(
    count > avg_count, "🔴 SPIKE - Unusual increase",
    count < avg_count, "🟠 DROP - Unusual decrease",
    1=1, "Unknown"
)
| eval _time=strftime(_time, "%Y-%m-%d %H:%M")
| table _time, index, sourcetype, count, avg_count, z_score, anomaly_type
| rename _time as "Time", count as "Actual Events", avg_count as "Expected Events", z_score as "Std Deviations", anomaly_type as "Anomaly Type"
| sort - "Std Deviations" """

    def _generate_after_hours_analysis_spl(self) -> str:
        return """index=* (EventCode=4624 OR action=login OR action=logon)
| eval hour=tonumber(strftime(_time, "%H"))
| eval day=strftime(_time, "%A")
| eval user=coalesce(user, Account_Name, User_Name, "unknown")
| where (hour < 7 OR hour > 19) OR day IN ("Saturday", "Sunday")
| eval time_category=case(
    hour < 6, "🌙 Late Night (12am-6am)",
    hour > 20, "🌙 Late Evening (8pm-12am)",
    day IN ("Saturday", "Sunday"), "📅 Weekend",
    1=1, "🕐 Early Morning/Late Evening"
)
| stats count as access_count,
        dc(ComputerName) as systems_accessed,
        earliest(_time) as first_seen,
        latest(_time) as last_seen,
        values(time_category) as patterns
  by user
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M"),
       last_seen=strftime(last_seen, "%Y-%m-%d %H:%M")
| eval risk_level=case(
    access_count > 20, "🔴 HIGH - Frequent after-hours access",
    access_count > 10, "🟡 MEDIUM - Moderate after-hours access",
    1=1, "🟢 LOW - Occasional access"
)
| sort - access_count
| table risk_level, user, access_count, systems_accessed, patterns, first_seen, last_seen"""

    def _generate_gap_verification_spl(self, gap_type: str) -> str:
        search_patterns = {
            "firewall_logs": "firewall OR cisco OR palo OR fortinet OR asa",
            "auth_logs": "authentication OR login OR logon OR EventCode=4624 OR EventCode=4625",
            "web_logs": "access_combined OR http OR GET OR POST OR url=",
            "database_logs": "database OR sql OR oracle OR postgres OR mongo"
        }
        pattern = search_patterns.get(gap_type, "*")
        
        return f"""index=* {pattern}
| stats count by index, sourcetype, host
| eval coverage=case(
    count > 1000, "✅ GOOD - Active data collection",
    count > 100, "🟡 LOW - Limited data",
    1=1, "🔴 MINIMAL - Check configuration"
)
| table coverage, index, sourcetype, host, count
| sort - count"""
