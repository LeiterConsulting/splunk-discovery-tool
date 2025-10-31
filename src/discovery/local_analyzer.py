"""
Local data analyzer for Splunk discovery - processes data without LLM.

This module provides intelligent local analysis of Splunk environment data,
reducing the need for expensive LLM API calls by handling structural
analysis, pattern detection, and summarization locally.
"""

from typing import Dict, List, Any
from datetime import datetime, timedelta
from collections import defaultdict


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
        # Separate results by type
        indexes = []
        sourcetypes = []
        knowledge_objects = []
        
        for result in discovery_results:
            data = result.data
            if isinstance(data, dict):
                if 'title' in data and 'currentDBSizeMB' in data:
                    indexes.append(data)
                elif 'sourcetype' in data and 'totalCount' in data:
                    sourcetypes.append(data)
                else:
                    knowledge_objects.append(data)
        
        summary = {
            "environment_overview": {
                "current_date": self.current_date.strftime('%Y-%m-%d'),
                "size_category": self._categorize_environment_size(indexes, sourcetypes),
                "total_indexes": len(indexes),
                "total_sourcetypes": len(sourcetypes),
                "total_knowledge_objects": len(knowledge_objects)
            },
            "index_analysis": self.analyze_indexes(indexes),
            "sourcetype_analysis": self.analyze_sourcetypes(sourcetypes),
            "data_quality": self.analyze_data_quality(indexes, sourcetypes),
            "capability_gaps": self.detect_gaps(sourcetypes),
            "interesting_findings": self._extract_interesting_findings(discovery_results)
        }
        
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
            try:
                size_mb = float(idx.get('currentDBSizeMB', 0))
                event_count = int(idx.get('totalEventCount', 0))
                
                if size_mb > 0 or event_count > 0:
                    active_indexes.append({
                        "name": idx.get('title'),
                        "size_mb": size_mb,
                        "events": event_count
                    })
                    sizes.append(size_mb)
                    event_counts.append(event_count)
                else:
                    empty_indexes.append(idx.get('title'))
            except (ValueError, TypeError):
                continue
        
        # Find largest indexes
        active_indexes.sort(key=lambda x: x['size_mb'], reverse=True)
        top_5 = active_indexes[:5]
        
        return {
            "total": len(indexes_data),
            "active": len(active_indexes),
            "empty": len(empty_indexes),
            "empty_index_names": empty_indexes[:10],  # First 10 only
            "largest_indexes": top_5,
            "total_data_mb": sum(sizes),
            "total_events": sum(event_counts),
            "size_distribution": self._categorize_sizes(sizes)
        }
    
    def analyze_sourcetypes(self, sourcetypes_data: List[Dict]) -> Dict[str, Any]:
        """Analyze sourcetype data locally and return compact summary."""
        if not sourcetypes_data:
            return {"total": 0, "platforms": {}, "categories": {}}
        
        platforms = defaultdict(list)
        categories = defaultdict(list)  # Security, Infrastructure, Business, Compliance
        top_sourcetypes = []
        time_ranges = []
        
        for st in sourcetypes_data:
            # Get the actual sourcetype name - try multiple field names
            st_name = st.get('sourcetype', st.get('type', st.get('name', '')))
            try:
                count = int(st.get('totalCount', 0))
            except (ValueError, TypeError):
                count = 0
            
            if count > 0:
                # Categorize by platform
                platform = self._identify_platform(st_name)
                platforms[platform].append(st_name)
                
                # Categorize by use case type (Security, Infrastructure, Business, Compliance)
                category = self._identify_category(st_name)
                categories[category].append({
                    "name": st_name,
                    "events": count,
                    "platform": platform
                })
                
                # Track top sourcetypes
                top_sourcetypes.append({
                    "name": st_name,
                    "events": count,
                    "platform": platform,
                    "category": category
                })
                
                # Track time ranges
                if 'firstTime' in st:
                    time_ranges.append(st.get('firstTime'))
                if 'recentTime' in st:
                    time_ranges.append(st.get('recentTime'))
        
        # Sort and limit top sourcetypes
        top_sourcetypes.sort(key=lambda x: x['events'], reverse=True)
        
        return {
            "total": len(sourcetypes_data),
            "active": len(top_sourcetypes),
            "platforms": {k: len(v) for k, v in platforms.items()},
            "platform_examples": {k: v[:5] for k, v in platforms.items()},  # Top 5 per platform
            "categories": {k: len(v) for k, v in categories.items()},
            "category_details": {k: v[:10] for k, v in categories.items()},  # Top 10 per category
            "top_5_sourcetypes": top_sourcetypes[:5],
            "data_span": self._analyze_time_range(time_ranges) if time_ranges else "Unknown"
        }
    
    def analyze_data_quality(self, indexes_data: List[Dict], sourcetypes_data: List[Dict]) -> Dict[str, Any]:
        """Analyze data quality without LLM."""
        issues = []
        score = 100
        
        # Check for empty indexes
        empty_count = sum(1 for idx in indexes_data if float(idx.get('currentDBSizeMB', 0)) == 0)
        if empty_count > len(indexes_data) * 0.5:
            issues.append(f"High number of empty indexes ({empty_count}/{len(indexes_data)})")
            score -= 15
        
        # Check for very old data
        for st in sourcetypes_data:
            if 'firstTime' in st:
                first_time_str = st.get('firstTime', '')
                try:
                    # Parse epoch time
                    if first_time_str.isdigit():
                        first_time = datetime.fromtimestamp(int(first_time_str))
                        age_days = (self.current_date - first_time).days
                        if age_days > 365 * 3:  # Older than 3 years
                            issues.append(f"Data spans multiple years (oldest: {age_days} days)")
                            break
                except:
                    pass
        
        # Check for data recency
        recent_count = 0
        for st in sourcetypes_data:
            if 'recentTime' in st:
                recent_time_str = st.get('recentTime', '')
                try:
                    if recent_time_str.isdigit():
                        recent_time = datetime.fromtimestamp(int(recent_time_str))
                        age_hours = (self.current_date - recent_time).total_seconds() / 3600
                        if age_hours < 24:
                            recent_count += 1
                except:
                    pass
        
        if recent_count < len(sourcetypes_data) * 0.3:
            issues.append(f"Limited recent data activity ({recent_count}/{len(sourcetypes_data)} active in last 24h)")
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
            # Get the actual sourcetype name - try multiple field names
            st_name = st.get('sourcetype', st.get('type', st.get('name', '')))
            
            if st_name:
                # Detect platforms
                platform = self._identify_platform(st_name)
                platforms.add(platform.lower())
                
                # Detect categories
                category = self._identify_category(st_name)
                categories.add(category.lower())
        
        # Define comprehensive monitoring expectations
        common_platforms = {'windows', 'unix/linux', 'network', 'cloud', 'database', 'web server'}
        common_categories = {'security', 'infrastructure', 'business', 'compliance'}
        
        missing_platforms = common_platforms - platforms
        missing_categories = common_categories - categories
        
        return {
            "missing_platforms": list(missing_platforms),
            "missing_categories": list(missing_categories),
            "detected_platforms": list(platforms),
            "detected_categories": list(categories),
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
        
        # Windows platform indicators
        if any(pattern in st_lower for pattern in ['wineventlog', 'windows', 'win:', 'perfmon', 'msad:', 'ms:', 'iis', 'mssql']):
            return "Windows"
        
        # Unix/Linux platform indicators
        elif any(pattern in st_lower for pattern in ['unix:', 'linux', 'syslog', 'linux_', 'bash', 'sh_history', 'secure.log', 'messages.log', 'apt_', 'yum_', 'dpkg']):
            return "Unix/Linux"
        
        # Network device indicators
        elif any(pattern in st_lower for pattern in ['network', 'firewall', 'cisco', 'juniper', 'palo alto', 'fortinet', 'f5', 'netflow', 'router', 'switch', 'vpn']):
            return "Network"
        
        # Cloud platform indicators
        elif any(pattern in st_lower for pattern in ['cloud', 'aws', 'azure', 'gcp', 'cloudtrail', 's3:', 'ec2:', 'lambda']):
            return "Cloud"
        
        # Database indicators
        elif any(pattern in st_lower for pattern in ['database', 'sql', 'oracle', 'mysql', 'postgres', 'mongodb', 'db2', 'cassandra']):
            return "Database"
        
        # Web server indicators
        elif any(pattern in st_lower for pattern in ['access_combined', 'access_', 'apache', 'nginx', 'tomcat', 'weblogic']):
            return "Web Server"
        
        # Application indicators
        elif any(pattern in st_lower for pattern in ['application', 'app:', 'app_']):
            return "Application"
        
        # Performance/metrics indicators
        elif any(pattern in st_lower for pattern in ['cpu', 'memory', 'disk', 'interfaces', 'uptime', 'vmstat', 'iostat', 'netstat']):
            return "System Metrics"
        
        else:
            return "Application"  # Default fallback
    
    def _identify_category(self, sourcetype_name: str) -> str:
        """Identify use case category (Security, Infrastructure, Business, Compliance) from sourcetype."""
        st_lower = sourcetype_name.lower()
        
        # SECURITY category - authentication, security events, threats, access control
        if any(pattern in st_lower for pattern in [
            'security', 'auth', 'wineventlog:security', 'linux_secure', 'sudo', 'passwd',
            'firewall', 'ids', 'ips', 'antivirus', 'malware', 'threat',
            'vpn', 'proxy', 'ssl', 'certificate', 'login', 'authentication'
        ]):
            return "Security"
        
        # COMPLIANCE category - audit, regulatory, policy
        elif any(pattern in st_lower for pattern in [
            'audit', 'compliance', 'regulatory', 'policy', 'governance',
            'pci', 'hipaa', 'sox', 'gdpr', 'license'
        ]):
            return "Compliance"
        
        # BUSINESS category - business apps, user activity, transactions, analytics
        elif any(pattern in st_lower for pattern in [
            'business', 'transaction', 'order', 'customer', 'crm', 'erp',
            'salesforce', 'workday', 'sap', 'analytics', 'bi_'
        ]):
            return "Business"
        
        # INFRASTRUCTURE category - systems, performance, operations
        elif any(pattern in st_lower for pattern in [
            'wineventlog:system', 'wineventlog:application', 'syslog', 'messages',
            'cpu', 'memory', 'disk', 'network', 'interfaces', 'uptime',
            'performance', 'metric', 'vmstat', 'iostat', 'ps',
            'apache', 'nginx', 'iis', 'tomcat', 'weblogic',
            'application', 'app', 'error', 'exception'
        ]):
            return "Infrastructure"
        
        else:
            return "Infrastructure"  # Default fallback for operational data
    
    def _analyze_time_range(self, time_values: List) -> str:
        """Analyze time range of data."""
        try:
            timestamps = []
            for tv in time_values:
                if isinstance(tv, str) and tv.isdigit():
                    timestamps.append(int(tv))
            
            if timestamps:
                earliest = datetime.fromtimestamp(min(timestamps))
                latest = datetime.fromtimestamp(max(timestamps))
                span_days = (latest - earliest).days
                
                return f"{span_days} days (from {earliest.strftime('%Y-%m-%d')} to {latest.strftime('%Y-%m-%d')})"
        except:
            pass
        
        return "Unknown"
    
    def _extract_interesting_findings(self, discovery_results: List) -> List[str]:
        """Extract interesting findings from discovery results."""
        findings = []
        for result in discovery_results:
            if result.interesting_findings:
                findings.extend(result.interesting_findings)
        
        # Deduplicate and limit
        unique_findings = list(set(findings))
        return unique_findings[:10]  # Top 10 only
    
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
