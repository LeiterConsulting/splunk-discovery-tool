"""
SPL Query Generator - Creates contextual Splunk queries based on discovered data.
"""

from typing import Dict, List, Any
import json


class SPLGenerator:
    """Generate contextual SPL queries based on discovered environment data."""
    
    def __init__(self, discovery_context):
        # Handle both list (discovery_results) and dict (analyzed context) formats
        if isinstance(discovery_context, list):
            self.context = self._parse_discovery_results(discovery_context)
        else:
            self.context = discovery_context
        self.indexes = self._extract_indexes()
        self.sourcetypes = self._extract_sourcetypes()
    
    def _parse_discovery_results(self, discovery_results: List[Dict]) -> Dict[str, Any]:
        """Parse raw discovery_results into structured context."""
        indexes = []
        sourcetypes = []
        
        for result in discovery_results:
            data = result.get('data', {})
            
            # Parse indexes
            if 'title' in data and 'totalEventCount' in data:
                indexes.append({
                    'name': data['title'],
                    'events': int(data.get('totalEventCount', 0)),
                    'size_mb': float(data.get('currentDBSizeMB', 0))
                })
            
            # Parse sourcetypes
            elif 'sourcetype' in data and 'totalCount' in data:
                sourcetypes.append({
                    'name': data['sourcetype'],
                    'events': int(data.get('totalCount', 0)),
                    'category': 'Unknown',  # Will be determined by pattern matching
                    'platform': 'Unknown'
                })
        
        return {
            'indexes': indexes,
            'sourcetypes': sourcetypes
        }
        
    def _extract_indexes(self) -> List[str]:
        """Extract list of active indexes from context."""
        indexes = []
        
        # From parsed discovery results
        if 'indexes' in self.context:
            indexes = [idx['name'] for idx in self.context['indexes'] if idx.get('events', 0) > 0]
        # From local analyzer
        elif 'index_analysis' in self.context:
            largest = self.context['index_analysis'].get('largest_indexes', [])
            indexes = [idx['name'] for idx in largest if idx.get('events', 0) > 0]
        
        return indexes or ['*']
    
    def _extract_sourcetypes(self) -> List[Dict[str, Any]]:
        """Extract sourcetype details from context."""
        sourcetypes = []
        
        # From parsed discovery results
        if 'sourcetypes' in self.context:
            sourcetypes = self.context['sourcetypes']
        # From local analyzer
        elif 'sourcetype_analysis' in self.context:
            category_details = self.context['sourcetype_analysis'].get('category_details', {})
            for category, sources in category_details.items():
                for source in sources:
                    sourcetypes.append({
                        'name': source['name'],
                        'category': category,
                        'events': source['events'],
                        'platform': source.get('platform', 'Unknown')
                    })
        
        return sourcetypes
    
    async def generate_all_queries(self) -> List[Dict[str, Any]]:
        """Generate all applicable SPL queries for the discovered environment."""
        queries = []
        
        # Security queries
        queries.extend(self.generate_security_queries())
        
        # Infrastructure queries
        queries.extend(self.generate_infrastructure_queries())
        
        # Performance queries
        queries.extend(self.generate_performance_queries())
        
        # Custom/Unknown data queries
        queries.extend(self.generate_exploratory_queries())
        
        return queries
    
    def generate_security_queries(self) -> List[Dict[str, Any]]:
        """Generate security-focused SPL queries."""
        queries = []
        
        # Check for Windows Security logs
        winsec_sources = [st for st in self.sourcetypes if 'wineventlog:security' in st['name'].lower()]
        if winsec_sources:
            queries.append({
                "title": "Failed Login Monitoring Dashboard",
                "description": "Track failed Windows authentication attempts to identify brute force attacks and unauthorized access",
                "use_case": "Security Monitoring",
                "category": "Security",
                "spl": self._generate_failed_login_spl(),
                "execution_time": "< 1 minute",
                "business_value": "Identify potential security breaches, brute force attacks, and compromised accounts before they cause damage",
                "indexes": ["wineventlog"] if any('wineventlog' in idx for idx in self.indexes) else self.indexes,
                "difficulty": "Beginner",
                "dashboard_type": "Single Value + Table"
            })
            
            queries.append({
                "title": "Account Lockout Real-Time Alert",
                "description": "Immediate notification when user accounts are locked out",
                "use_case": "Security Alerting",
                "category": "Security",
                "spl": self._generate_lockout_alert_spl(),
                "execution_time": "Real-time",
                "business_value": "Quickly respond to potential attacks or help desk issues, reducing downtime and security risk",
                "indexes": ["wineventlog"],
                "difficulty": "Beginner",
                "dashboard_type": "Alert"
            })
            
            queries.append({
                "title": "User Behavior Analytics - After Hours Access",
                "description": "Identify users logging in outside normal business hours",
                "use_case": "Threat Detection",
                "category": "Security",
                "spl": self._generate_after_hours_spl(),
                "execution_time": "< 2 minutes",
                "business_value": "Detect insider threats, compromised credentials, or policy violations",
                "indexes": ["wineventlog"],
                "difficulty": "Intermediate",
                "dashboard_type": "Timeline + Table"
            })
        
        # Check for firewall/network security
        firewall_sources = [st for st in self.sourcetypes if any(term in st['name'].lower() for term in ['firewall', 'cisco', 'palo', 'fortinet'])]
        if firewall_sources:
            queries.append({
                "title": "Top Blocked Traffic Sources",
                "description": "Identify most frequently blocked IP addresses and ports",
                "use_case": "Network Security",
                "category": "Security",
                "spl": self._generate_blocked_traffic_spl(firewall_sources[0]['name']),
                "execution_time": "< 30 seconds",
                "business_value": "Spot persistent threats, optimize firewall rules, and identify attack patterns",
                "indexes": self.indexes,
                "difficulty": "Beginner",
                "dashboard_type": "Geo Map + Table"
            })
        
        return queries
    
    def generate_infrastructure_queries(self) -> List[Dict[str, Any]]:
        """Generate infrastructure monitoring SPL queries."""
        queries = []
        
        # CPU monitoring
        cpu_sources = [st for st in self.sourcetypes if 'cpu' in st['name'].lower()]
        if cpu_sources:
            queries.append({
                "title": "CPU Utilization Trend Analysis",
                "description": "Track CPU usage over time with threshold highlighting for capacity planning",
                "use_case": "Capacity Planning",
                "category": "Infrastructure",
                "spl": self._generate_cpu_monitoring_spl(cpu_sources[0]['name']),
                "execution_time": "< 1 minute",
                "business_value": "Proactively identify performance bottlenecks and plan infrastructure upgrades before issues impact users",
                "indexes": self.indexes,
                "difficulty": "Beginner",
                "dashboard_type": "Timechart + Heatmap"
            })
        
        # Windows Application logs
        winapp_sources = [st for st in self.sourcetypes if 'wineventlog:application' in st['name'].lower()]
        if winapp_sources:
            queries.append({
                "title": "Application Error Tracking Dashboard",
                "description": "Monitor application errors, warnings, and crashes across Windows systems",
                "use_case": "Application Health",
                "category": "Infrastructure",
                "spl": self._generate_app_error_spl(),
                "execution_time": "< 1 minute",
                "business_value": "Reduce MTTR by quickly identifying and prioritizing application issues",
                "indexes": ["wineventlog"],
                "difficulty": "Beginner",
                "dashboard_type": "Single Value + Pie Chart + Table"
            })
        
        # System logs
        winsys_sources = [st for st in self.sourcetypes if 'wineventlog:system' in st['name'].lower()]
        if winsys_sources:
            queries.append({
                "title": "System Health Overview",
                "description": "Monitor Windows system events, service status, and hardware issues",
                "use_case": "System Monitoring",
                "category": "Infrastructure",
                "spl": self._generate_system_health_spl(),
                "execution_time": "< 1 minute",
                "business_value": "Maintain system reliability and catch hardware failures before they cause outages",
                "indexes": ["wineventlog"],
                "difficulty": "Beginner",
                "dashboard_type": "Single Value + Table"
            })
        
        return queries
    
    def generate_performance_queries(self) -> List[Dict[str, Any]]:
        """Generate performance monitoring queries."""
        queries = []
        
        # Memory monitoring
        memory_sources = [st for st in self.sourcetypes if any(term in st['name'].lower() for term in ['memory', 'mem', 'vmstat'])]
        if memory_sources:
            queries.append({
                "title": "Memory Usage and Swap Activity",
                "description": "Track memory utilization and identify memory pressure",
                "use_case": "Performance Monitoring",
                "category": "Infrastructure",
                "spl": self._generate_memory_monitoring_spl(memory_sources[0]['name']),
                "execution_time": "< 1 minute",
                "business_value": "Prevent out-of-memory issues and optimize resource allocation",
                "indexes": self.indexes,
                "difficulty": "Intermediate",
                "dashboard_type": "Timechart + Single Value"
            })
        
        # Disk monitoring
        disk_sources = [st for st in self.sourcetypes if 'disk' in st['name'].lower() or 'iostat' in st['name'].lower()]
        if disk_sources:
            queries.append({
                "title": "Disk Space and I/O Performance",
                "description": "Monitor disk utilization and I/O bottlenecks",
                "use_case": "Storage Management",
                "category": "Infrastructure",
                "spl": self._generate_disk_monitoring_spl(disk_sources[0]['name']),
                "execution_time": "< 1 minute",
                "business_value": "Avoid disk full situations and identify storage performance issues",
                "indexes": self.indexes,
                "difficulty": "Intermediate",
                "dashboard_type": "Single Value + Timechart"
            })
        
        return queries
    
    def generate_exploratory_queries(self) -> List[Dict[str, Any]]:
        """Generate exploratory queries for unknown/custom data."""
        queries = []
        
        # Generic data exploration query
        if self.sourcetypes:
            queries.append({
                "title": "Data Source Activity Overview",
                "description": "See which data sources are most active and their event patterns",
                "use_case": "Data Exploration",
                "category": "Analytics",
                "spl": self._generate_data_overview_spl(),
                "execution_time": "< 30 seconds",
                "business_value": "Understand your data landscape and identify high-value sources for monitoring",
                "indexes": self.indexes,
                "difficulty": "Beginner",
                "dashboard_type": "Bar Chart + Table"
            })
        
        return queries
    
    # SPL Generation Methods
    
    def _generate_failed_login_spl(self) -> str:
        """Generate SPL for failed login monitoring."""
        return """index=wineventlog EventCode=4625 
| stats count as failed_attempts, 
        dc(ComputerName) as target_systems,
        values(ComputerName) as targets
  by user, src_ip 
| where failed_attempts > 5 
| eval severity=case(
    failed_attempts > 50, "🔴 Critical",
    failed_attempts > 20, "🟠 High",
    failed_attempts > 10, "🟡 Medium",
    1=1, "🟢 Low"
)
| sort - failed_attempts 
| head 20
| rename user as "User Account", 
         src_ip as "Source IP", 
         failed_attempts as "Failed Attempts",
         target_systems as "# Systems Targeted",
         targets as "Target Systems",
         severity as "Threat Level"
| table "Threat Level", "User Account", "Source IP", "Failed Attempts", "# Systems Targeted", "Target Systems"
"""
    
    def _generate_lockout_alert_spl(self) -> str:
        """Generate SPL for account lockout alerting."""
        return """index=wineventlog EventCode=4740 
| eval lockout_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| eval hours_since=round((now() - _time) / 3600, 1)
| where hours_since < 1
| stats count as lockout_count,
        latest(lockout_time) as last_lockout,
        values(Caller_Computer_Name) as systems
  by user, src_ip
| rename user as "Locked Account", 
         src_ip as "Source IP", 
         lockout_count as "Lockouts (Last Hour)",
         systems as "Systems Involved",
         last_lockout as "Most Recent Lockout"
| table "Locked Account", "Source IP", "Lockouts (Last Hour)", "Most Recent Lockout", "Systems Involved"
"""
    
    def _generate_after_hours_spl(self) -> str:
        """Generate SPL for after-hours access detection."""
        return """index=wineventlog EventCode=4624 
| eval hour=tonumber(strftime(_time, "%H"))
| eval day=strftime(_time, "%A")
| where (hour < 7 OR hour > 19) OR day="Saturday" OR day="Sunday"
| stats count as login_count,
        earliest(_time) as first_seen,
        latest(_time) as last_seen,
        dc(ComputerName) as system_count,
        values(ComputerName) as systems
  by user, src_ip
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"),
       last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort - login_count
| head 20
| rename user as "User", 
         src_ip as "Source IP",
         login_count as "After-Hours Logins",
         system_count as "# Systems",
         systems as "Systems Accessed",
         first_seen as "First Seen",
         last_seen as "Last Seen"
| table User, "Source IP", "After-Hours Logins", "# Systems", "First Seen", "Last Seen", "Systems Accessed"
"""
    
    def _generate_blocked_traffic_spl(self, sourcetype: str) -> str:
        """Generate SPL for blocked traffic analysis."""
        return f"""index=* sourcetype="{sourcetype}" action=blocked OR action=deny OR action=drop
| stats count as block_count,
        dc(dest_port) as ports_targeted,
        values(dest_port) as ports
  by src_ip, dest_ip
| sort - block_count
| head 20
| eval threat_score=case(
    block_count > 1000, "Critical",
    block_count > 100, "High",
    block_count > 10, "Medium",
    1=1, "Low"
)
| rename src_ip as "Source IP",
         dest_ip as "Destination IP",
         block_count as "Blocked Attempts",
         ports_targeted as "# Ports",
         ports as "Targeted Ports",
         threat_score as "Threat Level"
| table "Threat Level", "Source IP", "Destination IP", "Blocked Attempts", "# Ports", "Targeted Ports"
"""
    
    def _generate_cpu_monitoring_spl(self, sourcetype: str) -> str:
        """Generate SPL for CPU monitoring."""
        return f"""index=* sourcetype="{sourcetype}"
| timechart span=5m avg(PercentProcessorTime) as avg_cpu, 
                       max(PercentProcessorTime) as max_cpu 
  by host
| foreach avg_cpu* max_cpu* 
    [eval <<FIELD>>=round('<<FIELD>>', 2)]
"""
    
    def _generate_app_error_spl(self) -> str:
        """Generate SPL for application error tracking."""
        return """index=wineventlog sourcetype="WinEventLog:Application" (Type=Error OR Type=Warning)
| stats count by Type, SourceName, Message
| sort - count
| head 20
| eval severity=if(Type="Error", "🔴 Error", "🟡 Warning")
| rename SourceName as "Application/Service",
         Message as "Error Message",
         count as "Occurrences",
         severity as "Severity"
| table Severity, "Application/Service", "Error Message", Occurrences
"""
    
    def _generate_system_health_spl(self) -> str:
        """Generate SPL for system health monitoring."""
        return """index=wineventlog sourcetype="WinEventLog:System" 
    (EventCode=6008 OR EventCode=1074 OR EventCode=6005 OR EventCode=6006)
| eval event_type=case(
    EventCode=6008, "🔴 Unexpected Shutdown",
    EventCode=1074, "🟡 Planned Reboot",
    EventCode=6005, "🟢 System Start",
    EventCode=6006, "🔴 System Stop",
    1=1, "Unknown"
)
| stats count by ComputerName, event_type, EventCode
| sort ComputerName, - count
| rename ComputerName as "System",
         event_type as "Event Type",
         count as "Occurrences"
| table System, "Event Type", EventCode, Occurrences
"""
    
    def _generate_memory_monitoring_spl(self, sourcetype: str) -> str:
        """Generate SPL for memory monitoring."""
        return f"""index=* sourcetype="{sourcetype}"
| timechart span=5m avg(PercentMemoryUsed) as avg_memory,
                       max(PercentMemoryUsed) as max_memory
  by host
| foreach avg_memory* max_memory*
    [eval <<FIELD>>=round('<<FIELD>>', 2)]
"""
    
    def _generate_disk_monitoring_spl(self, sourcetype: str) -> str:
        """Generate SPL for disk monitoring."""
        return f"""index=* sourcetype="{sourcetype}"
| stats avg(PercentDiskUsed) as avg_usage,
        max(PercentDiskUsed) as max_usage
  by host, mount
| eval status=case(
    max_usage > 90, "🔴 Critical",
    max_usage > 80, "🟠 Warning",
    max_usage > 70, "🟡 Monitor",
    1=1, "🟢 OK"
)
| sort - max_usage
| rename host as "Host",
         mount as "Mount Point",
         avg_usage as "Avg Usage %",
         max_usage as "Max Usage %",
         status as "Status"
| table Status, Host, "Mount Point", "Avg Usage %", "Max Usage %"
"""
    
    def _generate_data_overview_spl(self) -> str:
        """Generate SPL for data source overview."""
        return """index=* earliest=-24h
| stats count as events, 
        earliest(_time) as first,
        latest(_time) as last
  by index, sourcetype
| eval first=strftime(first, "%Y-%m-%d %H:%M"),
       last=strftime(last, "%Y-%m-%d %H:%M"),
       events_per_hour=round(events/24, 0)
| sort - events
| head 20
| rename index as "Index",
         sourcetype as "Sourcetype",
         events as "Total Events (24h)",
         events_per_hour as "Events/Hour",
         first as "First Event",
         last as "Last Event"
| table Index, Sourcetype, "Total Events (24h)", "Events/Hour", "First Event", "Last Event"
"""
