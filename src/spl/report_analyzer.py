"""
Report-Driven SPL Generator - Creates queries based on actual findings in reports.

This module analyzes executive summaries, detailed findings, and classification reports
to generate highly targeted SPL queries that address specific issues discovered.
"""

from typing import Dict, List, Any, Optional
import re
import json


class ReportAnalyzer:
    """Analyze discovery reports to extract actionable findings."""
    
    def __init__(self, executive_summary: str = "", detailed_findings: str = "", classification_report: str = ""):
        self.executive_summary = executive_summary
        self.detailed_findings = detailed_findings
        self.classification_report = classification_report
        
    def extract_findings(self) -> Dict[str, List[Dict[str, Any]]]:
        """Extract structured findings from reports."""
        findings = {
            "security_issues": self._extract_security_findings(),
            "performance_issues": self._extract_performance_findings(),
            "data_quality_issues": self._extract_data_quality_findings(),
            "optimization_opportunities": self._extract_optimization_findings(),
            "anomalies": self._extract_anomalies(),
            "gaps": self._extract_gaps()
        }
        return findings
    
    def _extract_security_findings(self) -> List[Dict[str, Any]]:
        """Extract security-related findings."""
        findings = []
        combined = f"{self.executive_summary}\n{self.detailed_findings}"
        
        # Failed login patterns
        failed_login_pattern = r'(\d+)\s+failed.*?(?:login|authentication|logon).*?(?:admin|administrator|user)'
        matches = re.finditer(failed_login_pattern, combined, re.IGNORECASE)
        for match in matches:
            count = int(match.group(1))
            if count > 5:
                findings.append({
                    "type": "failed_authentications",
                    "severity": "high" if count > 50 else "medium" if count > 20 else "low",
                    "count": count,
                    "description": match.group(0),
                    "recommended_action": "Investigate source IPs and implement account lockout policies"
                })
        
        # Account lockout patterns
        lockout_pattern = r'(\d+)\s+(?:account|user).*?lock(?:out|ed)'
        matches = re.finditer(lockout_pattern, combined, re.IGNORECASE)
        for match in matches:
            findings.append({
                "type": "account_lockouts",
                "severity": "medium",
                "count": int(match.group(1)),
                "description": match.group(0),
                "recommended_action": "Monitor for brute force attacks and assist locked users"
            })
        
        # Security gaps
        gap_patterns = [
            (r'no.*?(?:alert|monitoring|detection).*?(?:for|on)', "missing_alerts"),
            (r'insufficient.*?(?:logging|auditing)', "insufficient_logging"),
            (r'(?:missing|lack of).*?(?:security|compliance)', "security_gaps")
        ]
        
        for pattern, gap_type in gap_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                findings.append({
                    "type": gap_type,
                    "severity": "medium",
                    "description": "Security monitoring gap identified",
                    "recommended_action": "Implement comprehensive security monitoring"
                })
        
        return findings
    
    def _extract_performance_findings(self) -> List[Dict[str, Any]]:
        """Extract performance-related findings."""
        findings = []
        combined = f"{self.executive_summary}\n{self.detailed_findings}"
        
        # High CPU patterns
        cpu_pattern = r'(\d+)%?\s+(?:CPU|processor).*?(?:utilization|usage)'
        matches = re.finditer(cpu_pattern, combined, re.IGNORECASE)
        for match in matches:
            usage = int(match.group(1))
            if usage > 70:
                findings.append({
                    "type": "high_cpu",
                    "severity": "high" if usage > 90 else "medium",
                    "value": usage,
                    "description": match.group(0),
                    "recommended_action": "Monitor CPU trends and plan capacity upgrades"
                })
        
        # Memory patterns
        memory_pattern = r'(\d+)%?\s+(?:memory|RAM).*?(?:utilization|usage|used)'
        matches = re.finditer(memory_pattern, combined, re.IGNORECASE)
        for match in matches:
            usage = int(match.group(1))
            if usage > 80:
                findings.append({
                    "type": "high_memory",
                    "severity": "high" if usage > 95 else "medium",
                    "value": usage,
                    "description": match.group(0),
                    "recommended_action": "Monitor memory trends and prevent OOM situations"
                })
        
        # Disk space patterns
        disk_pattern = r'(\d+)%?\s+(?:disk|storage).*?(?:full|used|utilization)'
        matches = re.finditer(disk_pattern, combined, re.IGNORECASE)
        for match in matches:
            usage = int(match.group(1))
            if usage > 75:
                findings.append({
                    "type": "disk_space",
                    "severity": "critical" if usage > 90 else "high" if usage > 85 else "medium",
                    "value": usage,
                    "description": match.group(0),
                    "recommended_action": "Monitor disk usage and plan storage expansion"
                })
        
        return findings
    
    def _extract_data_quality_findings(self) -> List[Dict[str, Any]]:
        """Extract data quality issues."""
        findings = []
        combined = f"{self.executive_summary}\n{self.detailed_findings}"
        
        # Empty indexes
        empty_pattern = r'(\d+)\s+empty\s+(?:index|indexes)'
        matches = re.finditer(empty_pattern, combined, re.IGNORECASE)
        for match in matches:
            count = int(match.group(1))
            if count > 0:
                findings.append({
                    "type": "empty_indexes",
                    "severity": "low",
                    "count": count,
                    "description": match.group(0),
                    "recommended_action": "Review index configuration and data collection"
                })
        
        # Data gaps
        gap_pattern = r'(?:gap|missing).*?(?:data|events|logs)'
        if re.search(gap_pattern, combined, re.IGNORECASE):
            findings.append({
                "type": "data_gaps",
                "severity": "medium",
                "description": "Data collection gaps detected",
                "recommended_action": "Verify forwarders and data inputs"
            })
        
        # Parsing errors
        parse_pattern = r'(\d+).*?(?:parsing|parse).*?(?:error|fail)'
        matches = re.finditer(parse_pattern, combined, re.IGNORECASE)
        for match in matches:
            findings.append({
                "type": "parsing_errors",
                "severity": "medium",
                "description": match.group(0),
                "recommended_action": "Review source type configurations and field extractions"
            })
        
        return findings
    
    def _extract_optimization_findings(self) -> List[Dict[str, Any]]:
        """Extract optimization opportunities."""
        findings = []
        combined = f"{self.executive_summary}\n{self.detailed_findings}"
        
        # Retention optimization
        if re.search(r'retention.*?(?:not optimized|suboptimal|default)', combined, re.IGNORECASE):
            findings.append({
                "type": "retention_optimization",
                "severity": "low",
                "description": "Retention policies could be optimized",
                "recommended_action": "Align retention with compliance and storage capacity"
            })
        
        # Data model acceleration
        if re.search(r'(?:without|no).*?(?:acceleration|accelerate)', combined, re.IGNORECASE):
            findings.append({
                "type": "acceleration_opportunity",
                "severity": "medium",
                "description": "Large indexes without data model acceleration",
                "recommended_action": "Enable acceleration for frequently searched indexes"
            })
        
        # Index consolidation
        index_count_pattern = r'(\d+)\s+(?:index|indexes)'
        matches = re.finditer(index_count_pattern, combined, re.IGNORECASE)
        for match in matches:
            count = int(match.group(1))
            if count > 50:
                findings.append({
                    "type": "index_proliferation",
                    "severity": "low",
                    "count": count,
                    "description": f"High number of indexes ({count})",
                    "recommended_action": "Consider consolidating rarely-used indexes"
                })
        
        return findings
    
    def _extract_anomalies(self) -> List[Dict[str, Any]]:
        """Extract anomalous patterns."""
        findings = []
        combined = f"{self.executive_summary}\n{self.detailed_findings}"
        
        # Unusual volume patterns
        spike_pattern = r'(?:spike|surge|unusual|unexpected).*?(?:volume|events|traffic)'
        if re.search(spike_pattern, combined, re.IGNORECASE):
            findings.append({
                "type": "volume_anomaly",
                "severity": "medium",
                "description": "Unusual data volume detected",
                "recommended_action": "Investigate source of volume change"
            })
        
        # After-hours activity
        after_hours_pattern = r'(?:after.?hours|unusual time|odd hours).*?(?:access|activity|login)'
        if re.search(after_hours_pattern, combined, re.IGNORECASE):
            findings.append({
                "type": "after_hours_activity",
                "severity": "medium",
                "description": "After-hours access detected",
                "recommended_action": "Review access patterns for policy violations or threats"
            })
        
        return findings
    
    def _extract_gaps(self) -> List[Dict[str, Any]]:
        """Extract gaps in monitoring or coverage."""
        findings = []
        combined = f"{self.executive_summary}\n{self.detailed_findings}"
        
        # Missing data sources
        missing_patterns = [
            (r'no.*?(?:firewall|network).*?(?:data|logs)', "firewall_logs", "Network security visibility"),
            (r'no.*?(?:authentication|auth).*?(?:data|logs)', "auth_logs", "Authentication monitoring"),
            (r'no.*?(?:web|http).*?(?:data|logs)', "web_logs", "Web traffic visibility"),
            (r'no.*?(?:database|db).*?(?:data|logs)', "database_logs", "Database activity monitoring")
        ]
        
        for pattern, gap_type, description in missing_patterns:
            if re.search(pattern, combined, re.IGNORECASE):
                findings.append({
                    "type": gap_type,
                    "severity": "medium",
                    "description": f"Missing {description}",
                    "recommended_action": f"Configure {description} collection"
                })
        
        return findings
    
    def extract_key_metrics(self) -> Dict[str, Any]:
        """Extract numerical metrics from reports."""
        combined = f"{self.executive_summary}\n{self.detailed_findings}"
        metrics = {}
        
        # Event counts
        event_pattern = r'(\d{1,3}(?:,\d{3})*)\s+events?'
        matches = re.findall(event_pattern, combined)
        if matches:
            metrics['event_counts'] = [int(m.replace(',', '')) for m in matches]
        
        # Index counts
        index_pattern = r'(\d+)\s+(?:index|indexes)'
        matches = re.findall(index_pattern, combined, re.IGNORECASE)
        if matches:
            metrics['index_count'] = max([int(m) for m in matches])
        
        # Sourcetype counts
        st_pattern = r'(\d+)\s+(?:sourcetype|source type)s?'
        matches = re.findall(st_pattern, combined, re.IGNORECASE)
        if matches:
            metrics['sourcetype_count'] = max([int(m) for m in matches])
        
        # Host counts
        host_pattern = r'(\d+)\s+hosts?'
        matches = re.findall(host_pattern, combined, re.IGNORECASE)
        if matches:
            metrics['host_count'] = max([int(m) for m in matches])
        
        return metrics
    
    def extract_indexes_mentioned(self) -> List[str]:
        """Extract index names mentioned in reports."""
        combined = f"{self.executive_summary}\n{self.detailed_findings}"
        indexes = []
        
        # Common index patterns
        patterns = [
            r'\bindex[=\s]+["\']?(\w+)["\']?',
            r'\b(main|security|firewall|web|network|os|wineventlog)\b',
            r'the\s+["\']?(\w+)["\']?\s+index'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, combined, re.IGNORECASE)
            indexes.extend(matches)
        
        # Deduplicate and filter
        return list(set([idx.lower() for idx in indexes if len(idx) > 1]))
    
    def extract_sourcetypes_mentioned(self) -> List[str]:
        """Extract sourcetype names mentioned in reports."""
        combined = f"{self.executive_summary}\n{self.detailed_findings}"
        sourcetypes = []
        
        # Sourcetype patterns
        patterns = [
            r'sourcetype[=\s]+["\']?([:\w\-]+)["\']?',
            r'source\s+type\s+["\']?([:\w\-]+)["\']?',
            r'\b(WinEventLog:\w+)\b',
            r'\b(access_combined|syslog|linux_secure)\b'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, combined, re.IGNORECASE)
            sourcetypes.extend(matches)
        
        return list(set(sourcetypes))
