"""
SPL Query Generator - Creates contextual Splunk queries based on discovered data.

Templates only reference indexes and sourcetypes that discovery observed. When
the index holding a sourcetype is unknown, queries use the ``index=*`` wildcard
rather than guessing an index name.
"""

from typing import Any, Dict, List, Optional

from discovery.local_analyzer import (
    KIND_INDEX,
    KIND_SOURCETYPE,
    infer_result_kind,
    safe_float,
    safe_int,
)


MAX_INDEX_CLAUSE_TERMS = 8


class SPLGenerator:
    """Generate contextual SPL queries based on discovered environment data."""

    def __init__(self, discovery_context):
        if isinstance(discovery_context, list):
            self.context = self._parse_discovery_results(discovery_context)
        elif isinstance(discovery_context, dict):
            self.context = discovery_context
        else:
            self.context = {}
        self.discovered_indexes = self._extract_all_index_names()
        self.indexes = self._extract_indexes()
        self.sourcetypes = self._extract_sourcetypes()

    def _parse_discovery_results(self, discovery_results: List[Dict]) -> Dict[str, Any]:
        """Parse raw discovery_results (or blueprint finding_ledger entries) into structured context."""
        indexes = []
        sourcetypes = []

        for result in discovery_results:
            if isinstance(result, dict):
                data = result.get('data', result)
                kind = result.get('kind') or infer_result_kind(data)
            else:
                data = getattr(result, 'data', None)
                kind = getattr(result, 'kind', '') or infer_result_kind(data)
            if not isinstance(data, dict):
                continue

            if kind == KIND_INDEX and data.get('title'):
                indexes.append({
                    'name': str(data['title']),
                    'events': safe_int(data.get('totalEventCount')),
                    'size_mb': safe_float(data.get('currentDBSizeMB')),
                })
            elif kind == KIND_SOURCETYPE and data.get('sourcetype'):
                sourcetypes.append({
                    'name': str(data['sourcetype']),
                    'events': safe_int(data.get('totalCount')),
                    'category': 'Unknown',
                    'platform': 'Unknown'
                })

        return {
            'indexes': indexes,
            'sourcetypes': sourcetypes
        }

    def _extract_all_index_names(self) -> List[str]:
        names: List[str] = []
        if isinstance(self.context.get('indexes'), list):
            names = [str(idx.get('name')) for idx in self.context['indexes'] if isinstance(idx, dict) and idx.get('name')]
        elif isinstance(self.context.get('index_analysis'), dict):
            largest = self.context['index_analysis'].get('largest_indexes', [])
            names = [str(idx.get('name')) for idx in largest if isinstance(idx, dict) and idx.get('name')]
        return list(dict.fromkeys(names))

    def _extract_indexes(self) -> List[str]:
        """Extract discovered indexes that hold events, most active first; ['*'] when none are known."""
        candidates: List[Dict[str, Any]] = []
        if isinstance(self.context.get('indexes'), list):
            candidates = [idx for idx in self.context['indexes'] if isinstance(idx, dict)]
        elif isinstance(self.context.get('index_analysis'), dict):
            candidates = [idx for idx in self.context['index_analysis'].get('largest_indexes', []) if isinstance(idx, dict)]

        active = [idx for idx in candidates if safe_int(idx.get('events')) > 0 and idx.get('name')]
        active.sort(key=lambda idx: safe_int(idx.get('events')), reverse=True)
        names = list(dict.fromkeys(str(idx['name']) for idx in active))
        return names or ['*']

    def _extract_sourcetypes(self) -> List[Dict[str, Any]]:
        """Extract sourcetype details from context."""
        sourcetypes: List[Dict[str, Any]] = []

        if isinstance(self.context.get('sourcetypes'), list):
            sourcetypes = [st for st in self.context['sourcetypes'] if isinstance(st, dict) and st.get('name')]
        elif isinstance(self.context.get('sourcetype_analysis'), dict):
            category_details = self.context['sourcetype_analysis'].get('category_details', {})
            for category, sources in category_details.items():
                for source in sources:
                    if not isinstance(source, dict) or not source.get('name'):
                        continue
                    sourcetypes.append({
                        'name': source['name'],
                        'category': category,
                        'events': safe_int(source.get('events')),
                        'platform': source.get('platform', 'Unknown')
                    })

        return sourcetypes

    # ------------------------------------------------------------------
    # Index clause helpers
    # ------------------------------------------------------------------

    def _non_internal_active_indexes(self) -> List[str]:
        return [name for name in self.indexes if name != '*' and not name.startswith('_')]

    def _index_clause(self, preferred_terms: Optional[List[str]] = None) -> str:
        """Build an index clause from discovered index names, or index=* when unknown."""
        if preferred_terms:
            preferred = [
                name for name in self.discovered_indexes
                if any(term in name.lower() for term in preferred_terms)
            ]
            if len(preferred) == 1:
                return f"index={self._quote(preferred[0])}"
            if preferred:
                return "(" + " OR ".join(f"index={self._quote(name)}" for name in preferred[:MAX_INDEX_CLAUSE_TERMS]) + ")"
        return "index=*"

    def _primary_index_clause(self) -> str:
        active = self._non_internal_active_indexes()
        if len(active) == 1:
            return f"index={self._quote(active[0])}"
        if active:
            return "(" + " OR ".join(f"index={self._quote(name)}" for name in active[:MAX_INDEX_CLAUSE_TERMS]) + ")"
        return "index=*"

    def _clause_indexes(self, clause: str) -> List[str]:
        if clause == "index=*":
            return ['*']
        names = []
        for part in clause.strip("()").split(" OR "):
            value = part.split("=", 1)[-1].strip('"')
            if value:
                names.append(value)
        return names

    @staticmethod
    def _quote(value: str) -> str:
        if any(ch in value for ch in ' "()=|'):
            return '"' + value.replace('"', '\\"') + '"'
        return value

    def _has_index(self, name: str) -> bool:
        return name in self.discovered_indexes

    def _sourcetypes_matching(self, predicate) -> List[Dict[str, Any]]:
        matched = [st for st in self.sourcetypes if predicate(str(st.get('name', '')).lower())]
        matched.sort(key=lambda st: safe_int(st.get('events')), reverse=True)
        return matched

    async def generate_all_queries(self) -> List[Dict[str, Any]]:
        """Generate all applicable SPL queries for the discovered environment."""
        queries = []
        queries.extend(self.generate_security_queries())
        queries.extend(self.generate_infrastructure_queries())
        queries.extend(self.generate_performance_queries())
        queries.extend(self.generate_exploratory_queries())
        return queries

    def generate_security_queries(self) -> List[Dict[str, Any]]:
        """Generate security-focused SPL queries."""
        queries = []

        if not self.sourcetypes:
            clause = self._primary_index_clause()
            queries.append({
                "title": "Security Event Monitoring - Failed Authentications",
                "description": "Monitor authentication failures across discovered data sources",
                "use_case": "Security Monitoring",
                "category": "Security",
                "spl": f'{clause} (failed OR failure OR denied OR invalid) (login OR authentication OR logon OR auth) earliest=-24h | stats count by host, sourcetype, user | sort -count',
                "execution_time": "< 1 minute",
                "business_value": "Identify potential brute force attacks and unauthorized access attempts",
                "indexes": self._clause_indexes(clause),
                "difficulty": "Beginner",
                "dashboard_type": "Table"
            })

            queries.append({
                "title": "Security Anomaly Detection - Unusual Activity Patterns",
                "description": "Detect unusual patterns in security events that may indicate threats",
                "use_case": "Threat Detection",
                "category": "Security",
                "spl": f'{clause} (error OR warning OR alert OR critical OR suspicious) earliest=-24h | timechart span=1h count by sourcetype',
                "execution_time": "< 30 seconds",
                "business_value": "Early detection of security incidents and anomalous behavior",
                "indexes": self._clause_indexes(clause),
                "difficulty": "Beginner",
                "dashboard_type": "Timechart"
            })

            return queries

        winsec_sources = self._sourcetypes_matching(lambda name: 'wineventlog:security' in name)
        if winsec_sources:
            sourcetype = winsec_sources[0]['name']
            clause = self._index_clause(['wineventlog', 'windows', 'winevent'])
            indexes = self._clause_indexes(clause)
            queries.append({
                "title": "Failed Login Monitoring Dashboard",
                "description": "Track failed Windows authentication attempts to identify brute force attacks and unauthorized access",
                "use_case": "Security Monitoring",
                "category": "Security",
                "spl": self._generate_failed_login_spl(sourcetype, clause),
                "execution_time": "< 1 minute",
                "business_value": "Identify potential security breaches, brute force attacks, and compromised accounts before they cause damage",
                "indexes": indexes,
                "difficulty": "Beginner",
                "dashboard_type": "Single Value + Table"
            })

            queries.append({
                "title": "Account Lockout Real-Time Alert",
                "description": "Immediate notification when user accounts are locked out",
                "use_case": "Security Alerting",
                "category": "Security",
                "spl": self._generate_lockout_alert_spl(sourcetype, clause),
                "execution_time": "Real-time",
                "business_value": "Quickly respond to potential attacks or help desk issues, reducing downtime and security risk",
                "indexes": indexes,
                "difficulty": "Beginner",
                "dashboard_type": "Alert"
            })

            queries.append({
                "title": "User Behavior Analytics - After Hours Access",
                "description": "Identify users logging in outside normal business hours",
                "use_case": "Threat Detection",
                "category": "Security",
                "spl": self._generate_after_hours_spl(sourcetype, clause),
                "execution_time": "< 2 minutes",
                "business_value": "Detect insider threats, compromised credentials, or policy violations",
                "indexes": indexes,
                "difficulty": "Intermediate",
                "dashboard_type": "Timeline + Table"
            })

        firewall_sources = self._sourcetypes_matching(
            lambda name: any(term in name for term in ['firewall', 'cisco:asa', 'cisco:ftd', 'pan:', 'palo', 'fortinet', 'fortigate', 'fgt_'])
        )
        if firewall_sources:
            queries.append({
                "title": "Top Blocked Traffic Sources",
                "description": "Identify most frequently blocked IP addresses and ports",
                "use_case": "Network Security",
                "category": "Security",
                "spl": self._generate_blocked_traffic_spl(firewall_sources[0]['name']),
                "execution_time": "< 30 seconds",
                "business_value": "Spot persistent threats, optimize firewall rules, and identify attack patterns",
                "indexes": ['*'],
                "difficulty": "Beginner",
                "dashboard_type": "Geo Map + Table"
            })

        return queries

    def generate_infrastructure_queries(self) -> List[Dict[str, Any]]:
        """Generate infrastructure monitoring SPL queries."""
        queries = []

        if not self.sourcetypes:
            clause = self._primary_index_clause()
            queries.append({
                "title": "System Health Overview - Event Volume Monitoring",
                "description": "Monitor hourly event ingestion per host to detect collection issues",
                "use_case": "Infrastructure Health",
                "category": "Infrastructure",
                "spl": f'{clause} earliest=-24h | timechart span=1h limit=20 useother=true count by host',
                "execution_time": "< 1 minute",
                "business_value": "Ensure continuous data collection and identify systems with collection issues",
                "indexes": self._clause_indexes(clause),
                "difficulty": "Beginner",
                "dashboard_type": "Timechart"
            })

            queries.append({
                "title": "Data Source Health Check",
                "description": "Find sourcetype/host pairs that reported in the last 7 days but have been silent for more than 24 hours",
                "use_case": "Data Quality",
                "category": "Infrastructure",
                "spl": self._generate_source_health_spl(clause),
                "execution_time": "< 30 seconds",
                "business_value": "Quickly identify gaps in monitoring coverage",
                "indexes": self._clause_indexes(clause),
                "difficulty": "Beginner",
                "dashboard_type": "Table"
            })

            return queries

        cpu_sources = self._sourcetypes_matching(lambda name: 'cpu' in name)
        if cpu_sources:
            queries.append({
                "title": "CPU Utilization Trend Analysis",
                "description": "Track CPU usage over time with threshold highlighting for capacity planning",
                "use_case": "Capacity Planning",
                "category": "Infrastructure",
                "spl": self._generate_cpu_monitoring_spl(cpu_sources[0]['name']),
                "execution_time": "< 1 minute",
                "business_value": "Proactively identify performance bottlenecks and plan infrastructure upgrades before issues impact users",
                "indexes": ['*'],
                "difficulty": "Beginner",
                "dashboard_type": "Timechart + Heatmap"
            })

        winapp_sources = self._sourcetypes_matching(lambda name: 'wineventlog:application' in name)
        if winapp_sources:
            clause = self._index_clause(['wineventlog', 'windows', 'winevent'])
            queries.append({
                "title": "Application Error Tracking Dashboard",
                "description": "Monitor application errors, warnings, and crashes across Windows systems",
                "use_case": "Application Health",
                "category": "Infrastructure",
                "spl": self._generate_app_error_spl(winapp_sources[0]['name'], clause),
                "execution_time": "< 1 minute",
                "business_value": "Reduce MTTR by quickly identifying and prioritizing application issues",
                "indexes": self._clause_indexes(clause),
                "difficulty": "Beginner",
                "dashboard_type": "Single Value + Pie Chart + Table"
            })

        winsys_sources = self._sourcetypes_matching(lambda name: 'wineventlog:system' in name)
        if winsys_sources:
            clause = self._index_clause(['wineventlog', 'windows', 'winevent'])
            queries.append({
                "title": "System Health Overview",
                "description": "Monitor Windows system events, service status, and hardware issues",
                "use_case": "System Monitoring",
                "category": "Infrastructure",
                "spl": self._generate_system_health_spl(winsys_sources[0]['name'], clause),
                "execution_time": "< 1 minute",
                "business_value": "Maintain system reliability and catch hardware failures before they cause outages",
                "indexes": self._clause_indexes(clause),
                "difficulty": "Beginner",
                "dashboard_type": "Single Value + Table"
            })

        return queries

    def generate_performance_queries(self) -> List[Dict[str, Any]]:
        """Generate performance monitoring queries."""
        queries = []

        if not self.sourcetypes:
            clause = self._primary_index_clause()
            queries.append({
                "title": "Performance Analysis - High Volume Sourcetypes",
                "description": "Identify sourcetypes with high event volumes in the last 24 hours that may impact performance",
                "use_case": "Capacity Planning",
                "category": "Performance",
                "spl": f'| tstats count where {clause} earliest=-24h by sourcetype | where count > 10000 | sort - count',
                "execution_time": "< 30 seconds",
                "business_value": "Optimize data ingestion and identify potential storage concerns",
                "indexes": self._clause_indexes(clause),
                "difficulty": "Beginner",
                "dashboard_type": "Table + Chart"
            })
            queries.append(self._data_growth_query())
            return queries

        memory_sources = self._sourcetypes_matching(lambda name: any(term in name for term in ['memory', 'mem', 'vmstat']))
        if memory_sources:
            queries.append({
                "title": "Memory Usage and Swap Activity",
                "description": "Track memory utilization and identify memory pressure",
                "use_case": "Performance Monitoring",
                "category": "Infrastructure",
                "spl": self._generate_memory_monitoring_spl(memory_sources[0]['name']),
                "execution_time": "< 1 minute",
                "business_value": "Prevent out-of-memory issues and optimize resource allocation",
                "indexes": ['*'],
                "difficulty": "Intermediate",
                "dashboard_type": "Timechart + Single Value"
            })

        disk_sources = self._sourcetypes_matching(lambda name: 'disk' in name or 'iostat' in name or name == 'df')
        if disk_sources:
            queries.append({
                "title": "Disk Space and I/O Performance",
                "description": "Monitor disk utilization and I/O bottlenecks",
                "use_case": "Storage Management",
                "category": "Infrastructure",
                "spl": self._generate_disk_monitoring_spl(disk_sources[0]['name']),
                "execution_time": "< 1 minute",
                "business_value": "Avoid disk full situations and identify storage performance issues",
                "indexes": ['*'],
                "difficulty": "Intermediate",
                "dashboard_type": "Single Value + Timechart"
            })

        return queries

    def _data_growth_query(self) -> Dict[str, Any]:
        if self._has_index('_internal'):
            return {
                "title": "Daily License Usage (Ingest Volume)",
                "description": "Daily licensed ingest volume from license_usage.log over the last 7 complete days",
                "use_case": "Capacity Planning",
                "category": "Performance",
                "spl": 'index=_internal source=*license_usage.log* type=Usage earliest=-7d@d latest=@d | eval GB=b/1024/1024/1024 | timechart span=1d sum(GB) as ingest_GB',
                "execution_time": "< 1 minute",
                "business_value": "Forecast license and storage needs from actual ingest volume",
                "indexes": ['_internal'],
                "difficulty": "Intermediate",
                "dashboard_type": "Timechart"
            }
        clause = self._primary_index_clause()
        return {
            "title": "Daily Event Count Trend",
            "description": "Daily event counts over the last 7 complete days (event counts, not license volume)",
            "use_case": "Capacity Planning",
            "category": "Performance",
            "spl": f'| tstats count where {clause} earliest=-7d@d latest=@d by _time span=1d',
            "execution_time": "< 30 seconds",
            "business_value": "Track ingestion growth to plan capacity",
            "indexes": self._clause_indexes(clause),
            "difficulty": "Beginner",
            "dashboard_type": "Timechart"
        }

    def generate_exploratory_queries(self) -> List[Dict[str, Any]]:
        """Generate exploratory queries for unknown/custom data."""
        queries = []
        clause = self._primary_index_clause()

        queries.append({
            "title": "Data Source Discovery - All Active Sources",
            "description": "Discover data sources currently sending events to Splunk",
            "use_case": "Data Exploration",
            "category": "Analytics",
            "spl": f'| tstats count as events latest(_time) as latest earliest(_time) as earliest where {clause} earliest=-24h by sourcetype, source, host | eval hours_active=round((latest-earliest)/3600, 1) | sort - events',
            "execution_time": "< 30 seconds",
            "business_value": "Understand your complete data landscape and identify monitoring opportunities",
            "indexes": self._clause_indexes(clause),
            "difficulty": "Beginner",
            "dashboard_type": "Table"
        })

        queries.append({
            "title": "Event Pattern Analysis - Time Distribution",
            "description": "Analyze when events occur to understand usage patterns and peak times",
            "use_case": "Data Exploration",
            "category": "Analytics",
            "spl": f'| tstats count where {clause} earliest=-7d by _time, sourcetype span=1h | timechart span=1h sum(count) as events by sourcetype limit=10',
            "execution_time": "< 1 minute",
            "business_value": "Optimize monitoring windows and understand business activity patterns",
            "indexes": self._clause_indexes(clause),
            "difficulty": "Intermediate",
            "dashboard_type": "Timechart + Heatmap"
        })

        if self.sourcetypes:
            queries.append({
                "title": "Data Source Activity Overview",
                "description": "See which data sources are most active and their event patterns",
                "use_case": "Data Exploration",
                "category": "Analytics",
                "spl": self._generate_data_overview_spl(),
                "execution_time": "< 30 seconds",
                "business_value": "Identify high-value sources for focused monitoring and analysis",
                "indexes": ['*'],
                "difficulty": "Beginner",
                "dashboard_type": "Bar Chart + Table"
            })

        return queries

    # SPL Generation Methods

    def _generate_source_health_spl(self, index_clause: str = "index=*") -> str:
        """Sourcetype/host pairs seen in the last 7 days that have been silent for more than 24 hours."""
        return (
            f'| tstats latest(_time) as latest count where {index_clause} earliest=-7d by sourcetype, host '
            '| eval hours_since=round((now()-latest)/3600, 1) | where hours_since > 24 | sort - hours_since'
        )

    def _generate_failed_login_spl(self, sourcetype: str = "WinEventLog:Security", index_clause: str = "index=*") -> str:
        """Generate SPL for failed login monitoring."""
        return f"""{index_clause} sourcetype="{sourcetype}" EventCode=4625 earliest=-24h
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

    def _generate_lockout_alert_spl(self, sourcetype: str = "WinEventLog:Security", index_clause: str = "index=*") -> str:
        """Generate SPL for account lockout alerting."""
        return f"""{index_clause} sourcetype="{sourcetype}" EventCode=4740 earliest=-1h
| eval lockout_time=strftime(_time, "%Y-%m-%d %H:%M:%S")
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

    def _generate_after_hours_spl(self, sourcetype: str = "WinEventLog:Security", index_clause: str = "index=*") -> str:
        """Generate SPL for after-hours access detection."""
        return f"""{index_clause} sourcetype="{sourcetype}" EventCode=4624 earliest=-7d
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
        return f"""index=* sourcetype="{sourcetype}" (action=blocked OR action=deny OR action=drop) earliest=-24h
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
        return f"""index=* sourcetype="{sourcetype}" earliest=-24h
| timechart span=5m avg(PercentProcessorTime) as avg_cpu,
                       max(PercentProcessorTime) as max_cpu
  by host
| foreach avg_cpu* max_cpu*
    [eval <<FIELD>>=round('<<FIELD>>', 2)]
"""

    def _generate_app_error_spl(self, sourcetype: str = "WinEventLog:Application", index_clause: str = "index=*") -> str:
        """Generate SPL for application error tracking."""
        return f"""{index_clause} sourcetype="{sourcetype}" (Type=Error OR Type=Warning) earliest=-24h
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

    def _generate_system_health_spl(self, sourcetype: str = "WinEventLog:System", index_clause: str = "index=*") -> str:
        """Generate SPL for system health monitoring."""
        return f"""{index_clause} sourcetype="{sourcetype}" earliest=-7d
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
        return f"""index=* sourcetype="{sourcetype}" earliest=-24h
| timechart span=5m avg(PercentMemoryUsed) as avg_memory,
                       max(PercentMemoryUsed) as max_memory
  by host
| foreach avg_memory* max_memory*
    [eval <<FIELD>>=round('<<FIELD>>', 2)]
"""

    def _generate_disk_monitoring_spl(self, sourcetype: str) -> str:
        """Generate SPL for disk monitoring."""
        return f"""index=* sourcetype="{sourcetype}" earliest=-24h
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
        return """| tstats count as events earliest(_time) as first latest(_time) as last where index=* earliest=-24h by index, sourcetype
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
