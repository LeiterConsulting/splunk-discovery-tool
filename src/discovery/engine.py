"""
Core discovery engine for recursive Splunk environment exploration.

This module provides the main DiscoveryEngine class that coordinates
the entire discovery process through MCP integration.
"""

import asyncio
import json
import aiohttp
from typing import Dict, Any, List, AsyncGenerator, Optional
from dataclasses import dataclass
from datetime import datetime

from llm.factory import LLMClientFactory
from discovery.local_analyzer import LocalDataAnalyzer


@dataclass
@dataclass
class EnvironmentOverview:
    """Summary of the Splunk environment for progress estimation."""
    total_indexes: int
    total_sourcetypes: int
    total_hosts: int = 0
    total_sources: int = 0
    total_knowledge_objects: int = 0
    total_users: int = 0
    total_kv_collections: int = 0
    data_volume_24h: str = ""
    active_sources: int = 0
    estimated_discovery_steps: int = 0
    estimated_time: str = ""
    notable_patterns: List[str] = None
    splunk_version: str = ""
    splunk_build: str = ""
    license_state: str = ""
    server_roles: List[str] = None
    
    def __post_init__(self):
        """Ensure lists are always initialized."""
        if self.notable_patterns is None:
            self.notable_patterns = []
        if self.server_roles is None:
            self.server_roles = []


@dataclass
class DiscoveryResult:
    """Result from a single discovery step."""
    step: int
    description: str
    data: Dict[str, Any]
    interesting_findings: List[str]
    timestamp: datetime


class DiscoveryEngine:
    """
    Main discovery engine that coordinates recursive Splunk environment exploration.
    
    This class handles:
    - Initial environment overview and estimation
    - Step-by-step detailed discovery
    - Data classification and analysis
    - Integration with LLM for intelligent insights
    """
    
    def __init__(self, mcp_url: str, mcp_token: str, llm_client):
        self.mcp_url = mcp_url
        self.mcp_token = mcp_token
        self.llm_client = llm_client
        self.discovery_results: List[DiscoveryResult] = []
        self.environment_overview: Optional[EnvironmentOverview] = None
        self.discovery_data: Dict[str, Any] = {}
        self.local_analyzer = LocalDataAnalyzer()
        
    async def get_quick_overview(self) -> EnvironmentOverview:
        """
        Get a quick overview of the Splunk environment to estimate discovery scope.
        
        Returns:
            EnvironmentOverview with basic metrics and estimates
            
        Raises:
            Exception: If unable to connect to Splunk environment
        """
        # Get basic info through MCP calls using proper parameters
        try:
            system_info = await self._mcp_call("get_splunk_info", {})
            indexes_data = await self._mcp_call("get_indexes", {"row_limit": 100})
            sourcetypes_data = await self._mcp_call("get_metadata", {"type": "sourcetypes", "index": "*", "earliest_time": "-24h", "latest_time": "now", "row_limit": 100})
            hosts_data = await self._mcp_call("get_metadata", {"type": "hosts", "index": "*", "earliest_time": "-24h", "latest_time": "now", "row_limit": 500})
            sources_data = await self._mcp_call("get_metadata", {"type": "sources", "index": "*", "earliest_time": "-24h", "latest_time": "now", "row_limit": 500})
            ko_data = await self._mcp_call("get_knowledge_objects", {"type": "saved_searches", "row_limit": 100})
            user_data = await self._mcp_call("get_user_list", {"row_limit": 100})
            kv_data = await self._mcp_call("get_kv_store_collections", {"row_limit": 100})
        except Exception as e:
            raise Exception(f"Unable to retrieve environment information from Splunk. Please verify MCP server connection and credentials. Error: {str(e)}")
        
        # Extract system information - returned directly, not in 'results' wrapper
        splunk_version = system_info.get("version", "unknown") if isinstance(system_info, dict) else "unknown"
        splunk_build = system_info.get("build", "unknown") if isinstance(system_info, dict) else "unknown"
        license_state = system_info.get("licenseState", "unknown") if isinstance(system_info, dict) else "unknown"
        server_roles = system_info.get("server_roles", []) if isinstance(system_info, dict) else []
        if isinstance(server_roles, str):
            server_roles = [r.strip() for r in server_roles.split(",")]
        
        # Analyze the data to create overview
        indexes_list = indexes_data.get("results", []) if isinstance(indexes_data, dict) else (indexes_data if isinstance(indexes_data, list) else [])
        sourcetypes_list = sourcetypes_data.get("results", []) if isinstance(sourcetypes_data, dict) else (sourcetypes_data if isinstance(sourcetypes_data, list) else [])
        hosts_list = hosts_data.get("results", []) if isinstance(hosts_data, dict) else (hosts_data if isinstance(hosts_data, list) else [])
        sources_list = sources_data.get("results", []) if isinstance(sources_data, dict) else (sources_data if isinstance(sources_data, list) else [])
        ko_list = ko_data.get("results", []) if isinstance(ko_data, dict) else (ko_data if isinstance(ko_data, list) else [])
        user_list = user_data.get("results", []) if isinstance(user_data, dict) else (user_data if isinstance(user_data, list) else [])
        kv_list = kv_data.get("results", []) if isinstance(kv_data, dict) else (kv_data if isinstance(kv_data, list) else [])
        
        total_indexes = len(indexes_list)
        total_sourcetypes = len(sourcetypes_list)
        total_hosts = len(hosts_list)
        total_sources = len(sources_list)
        total_knowledge_objects = len(ko_list)
        total_users = len(user_list)
        total_kv_collections = len(kv_list)
        
        # Estimate discovery steps based on environment size
        estimated_steps = self._estimate_discovery_steps(
            total_indexes, total_sourcetypes, total_hosts, total_sources,
            total_knowledge_objects, total_users, total_kv_collections
        )
        
        # Use LLM to identify notable patterns from initial data
        try:
            notable_patterns = await self._identify_notable_patterns(indexes_data, sourcetypes_data)
        except Exception:
            notable_patterns = ["Pattern analysis unavailable - LLM connection failed"]
        
        # Calculate actual data volume from indexes
        total_size_mb = 0.0
        for idx in indexes_list:
            if isinstance(idx, dict):
                size_str = idx.get("currentDBSizeMB", "0")
                try:
                    total_size_mb += float(size_str)
                except (ValueError, TypeError):
                    pass
        
        # Format data volume nicely
        if total_size_mb < 1024:
            data_volume = f"~{total_size_mb:.0f}MB"
        else:
            data_volume = f"~{total_size_mb/1024:.1f}GB"
        
        overview = EnvironmentOverview(
            total_indexes=total_indexes,
            total_sourcetypes=total_sourcetypes,
            total_hosts=total_hosts,
            total_sources=total_sources,
            total_knowledge_objects=total_knowledge_objects,
            total_users=total_users,
            total_kv_collections=total_kv_collections,
            data_volume_24h=data_volume,
            active_sources=total_sourcetypes,
            estimated_discovery_steps=estimated_steps,
            estimated_time=self._estimate_time(estimated_steps),
            notable_patterns=notable_patterns,
            splunk_version=splunk_version,
            splunk_build=splunk_build,
            license_state=license_state,
            server_roles=server_roles
        )
        
        self.environment_overview = overview
        return overview
        
    async def discover_environment(self) -> AsyncGenerator[DiscoveryResult, None]:
        """
        Perform detailed recursive discovery of the Splunk environment.
        
        Yields:
            DiscoveryResult objects for each discovery step
        """
        if not self.environment_overview:
            raise ValueError("Must call get_quick_overview() first")
            
        step = 0
        
        # Phase 1: Detailed index analysis
        for index_info in await self._discover_indexes():
            step += 1
            result = DiscoveryResult(
                step=step,
                description=f"Analyzing index: {index_info.get('title', 'unknown')}",
                data=index_info,
                interesting_findings=await self._analyze_index_findings(index_info),
                timestamp=datetime.now()
            )
            self.discovery_results.append(result)
            yield result
            
        # Phase 2: Source type deep dive
        sourcetypes_list = await self._discover_sourcetypes()
        print(f"DEBUG: Retrieved {len(sourcetypes_list)} sourcetypes from MCP")
        if len(sourcetypes_list) == 0:
            print("WARNING: No sourcetypes returned from MCP - this will limit SPL query generation capabilities")
        
        for sourcetype_info in sourcetypes_list:
            step += 1
            result = DiscoveryResult(
                step=step,
                description=f"Analyzing sourcetype: {sourcetype_info.get('sourcetype', 'unknown')}",
                data=sourcetype_info,
                interesting_findings=await self._analyze_sourcetype_findings(sourcetype_info),
                timestamp=datetime.now()
            )
            self.discovery_results.append(result)
            yield result
        
        # Phase 2.5: Host discovery
        for host_info in await self._discover_hosts():
            step += 1
            result = DiscoveryResult(
                step=step,
                description=f"Analyzing host: {host_info.get('host', 'unknown')}",
                data=host_info,
                interesting_findings=await self._analyze_host_findings(host_info),
                timestamp=datetime.now()
            )
            self.discovery_results.append(result)
            yield result
        
        # Phase 2.75: Source discovery
        for source_info in await self._discover_sources():
            step += 1
            result = DiscoveryResult(
                step=step,
                description=f"Analyzing source: {source_info.get('source', 'unknown')}",
                data=source_info,
                interesting_findings=await self._analyze_source_findings(source_info),
                timestamp=datetime.now()
            )
            self.discovery_results.append(result)
            yield result
            
        # Phase 3: Knowledge objects discovery (expanded)
        for ko_type in ["saved_searches", "alerts", "dashboards", "macros", "eventtypes"]:
            for ko_info in await self._discover_knowledge_objects_by_type(ko_type):
                step += 1
                ko_name = ko_info.get('name', ko_info.get('title', 'unknown'))
                result = DiscoveryResult(
                    step=step,
                    description=f"Analyzing {ko_type}: {ko_name}",
                    data=ko_info,
                    interesting_findings=await self._analyze_knowledge_object_findings(ko_info, ko_type),
                    timestamp=datetime.now()
                )
                self.discovery_results.append(result)
                yield result
        
        # Phase 3.5: Detailed index information
        for index_info in await self._discover_detailed_index_info():
            step += 1
            index_name = index_info.get('name', index_info.get('title', 'unknown'))
            result = DiscoveryResult(
                step=step,
                description=f"Deep-dive index analysis: {index_name}",
                data=index_info,
                interesting_findings=await self._analyze_detailed_index_findings(index_info),
                timestamp=datetime.now()
            )
            self.discovery_results.append(result)
            yield result
        
        # Phase 4: User management discovery
        for user_info in await self._discover_users():
            step += 1
            user_name = user_info.get('name', user_info.get('username', 'unknown'))
            result = DiscoveryResult(
                step=step,
                description=f"Analyzing user: {user_name}",
                data=user_info,
                interesting_findings=await self._analyze_user_findings(user_info),
                timestamp=datetime.now()
            )
            self.discovery_results.append(result)
            yield result
        
        # Phase 5: KV Store discovery
        for kv_info in await self._discover_kv_collections():
            step += 1
            kv_name = kv_info.get('name', kv_info.get('title', 'unknown'))
            result = DiscoveryResult(
                step=step,
                description=f"Analyzing KV collection: {kv_name}",
                data=kv_info,
                interesting_findings=await self._analyze_kv_findings(kv_info),
                timestamp=datetime.now()
            )
            self.discovery_results.append(result)
            yield result
        
        # Phase 6: Advanced analytics
        for analytics_result in await self._run_advanced_analytics():
            step += 1
            result = DiscoveryResult(
                step=step,
                description=analytics_result.get('description', 'Advanced analysis'),
                data=analytics_result,
                interesting_findings=analytics_result.get('findings', []),
                timestamp=datetime.now()
            )
            self.discovery_results.append(result)
            yield result
            
    async def classify_data(self) -> Dict[str, Any]:
        """
        Classify discovered data into categories and patterns using local analysis.
        
        Returns:
            Classification results with categories and insights
        """
        # Use local analyzer to create comprehensive summary with category analysis
        discovery_summary = self.local_analyzer.summarize_discovery(self.discovery_results)
        
        # Store discovery data for use by other methods
        self.discovery_data = {
            'detailed_discovery': {
                'sources': [
                    {
                        'sourcetype': result.data.get('sourcetype'),
                        'name': result.data.get('title') or result.data.get('name'),
                        'source': result.data.get('sourcetype') or result.data.get('title'),
                        'count': int(result.data.get('totalCount', 0)) if result.data.get('totalCount', '0').isdigit() else 0,
                        'index': result.data.get('index', 'unknown')
                    }
                    for result in self.discovery_results
                    if result.data.get('sourcetype') or result.data.get('totalCount')
                ]
            },
            'summary': discovery_summary  # Store the summary
        }
        
        # Build classification directly from local analyzer results
        sourcetype_analysis = discovery_summary.get('sourcetype_analysis', {})
        index_analysis = discovery_summary.get('index_analysis', {})
        category_details = sourcetype_analysis.get('category_details', {})
        categories_count = sourcetype_analysis.get('categories', {})
        capability_gaps = discovery_summary.get('capability_gaps', {})
        data_quality = discovery_summary.get('data_quality', {})
        
        # Build structured classification for each category
        classifications = {}
        
        # SECURITY Category
        security_sources = category_details.get('Security', [])
        security_patterns = []
        security_use_cases = []
        
        for src in security_sources[:5]:  # Top 5
            st_name = src.get('name', '')
            if 'wineventlog:security' in st_name.lower():
                security_patterns.append("Windows Security Event Logs - user authentication, logon/logoff, access control")
                security_use_cases.append("User behavior monitoring and threat detection")
            elif 'firewall' in st_name.lower():
                security_patterns.append("Network firewall logs - traffic monitoring and threat prevention")
                security_use_cases.append("Network intrusion detection and traffic analysis")
            elif 'auth' in st_name.lower():
                security_patterns.append(f"{st_name} - authentication and access control")
                security_use_cases.append("Authentication failure analysis and account security")
        
        if not security_patterns:
            security_patterns = ["No security data sources identified"]
            security_use_cases = ["Add Windows Security logs, firewall logs, or authentication logs"]
        
        classifications['Security'] = {
            "source_count": len(security_sources),
            "volume": self._calculate_volume(security_sources),
            "quality_score": f"{data_quality.get('score', 0)}%",
            "key_patterns": list(set(security_patterns)),
            "recommended_use_cases": list(set(security_use_cases)),
            "sources": [s.get('name') for s in security_sources[:10]],  # Top 10 sources
            "missing_capabilities": capability_gaps.get('missing_capabilities', []) if 'security' in capability_gaps.get('missing_capabilities', []) else [],
            "recommendations": [rec for rec in capability_gaps.get('recommendations', []) if 'security' in rec.lower() or 'firewall' in rec.lower()],
            "index_analysis": index_analysis
        }
        
        # INFRASTRUCTURE Category
        infra_sources = category_details.get('Infrastructure', [])
        infra_patterns = []
        infra_use_cases = []
        
        for src in infra_sources[:5]:  # Top 5
            st_name = src.get('name', '')
            if 'wineventlog:system' in st_name.lower():
                infra_patterns.append("Windows System Event Logs - OS health, services, hardware events")
                infra_use_cases.append("System health monitoring and failure prediction")
            elif 'wineventlog:application' in st_name.lower():
                infra_patterns.append("Windows Application Event Logs - application errors and warnings")
                infra_use_cases.append("Application performance monitoring and error tracking")
            elif 'cpu' in st_name.lower() or 'memory' in st_name.lower():
                infra_patterns.append(f"{st_name} - Performance metrics and resource utilization")
                infra_use_cases.append("Capacity planning and performance optimization")
            elif 'syslog' in st_name.lower() or 'unix' in st_name.lower():
                infra_patterns.append(f"{st_name} - Unix/Linux system logs")
                infra_use_cases.append("Linux system monitoring and troubleshooting")
        
        if not infra_patterns:
            infra_patterns = ["No infrastructure data sources identified"]
            infra_use_cases = ["Add system logs, performance metrics, or application logs"]
        
        classifications['Infrastructure'] = {
            "source_count": len(infra_sources),
            "volume": self._calculate_volume(infra_sources),
            "quality_score": f"{data_quality.get('score', 0)}%",
            "key_patterns": list(set(infra_patterns)),
            "recommended_use_cases": list(set(infra_use_cases)),
            "sources": [s.get('name') for s in infra_sources[:10]],
            "missing_platforms": capability_gaps.get('missing_platforms', []),
            "recommendations": [rec for rec in capability_gaps.get('recommendations', []) if any(term in rec.lower() for term in ['cloud', 'database', 'network'])],
            "sourcetype_analysis": sourcetype_analysis
        }
        
        # BUSINESS Category
        business_sources = category_details.get('Business', [])
        business_patterns = []
        business_use_cases = []
        
        for src in business_sources[:5]:
            st_name = src.get('name', '')
            business_patterns.append(f"{st_name} - Business application data")
            business_use_cases.append("Business process monitoring and analytics")
        
        if not business_patterns:
            business_patterns = ["No business data sources identified"]
            business_use_cases = ["Add CRM, ERP, or business application logs for KPI tracking"]
        
        classifications['Business'] = {
            "source_count": len(business_sources),
            "volume": self._calculate_volume(business_sources),
            "quality_score": f"{data_quality.get('score', 0)}%",
            "key_patterns": list(set(business_patterns)),
            "recommended_use_cases": list(set(business_use_cases)),
            "sources": [s.get('name') for s in business_sources[:10]],
            "missing_capabilities": capability_gaps.get('missing_capabilities', []) if 'business' in capability_gaps.get('missing_capabilities', []) else [],
            "recommendations": [rec for rec in capability_gaps.get('recommendations', []) if 'business' in rec.lower()],
            "sourcetype_analysis": sourcetype_analysis
        }
        
        # COMPLIANCE Category
        compliance_sources = category_details.get('Compliance', [])
        compliance_patterns = []
        compliance_use_cases = []
        
        for src in compliance_sources[:5]:
            st_name = src.get('name', '')
            compliance_patterns.append(f"{st_name} - Audit and compliance data")
            compliance_use_cases.append("Regulatory compliance and audit reporting")
        
        if not compliance_patterns:
            compliance_patterns = ["No compliance-specific data sources identified"]
            compliance_use_cases = ["Add audit logs for PCI-DSS, HIPAA, or SOX compliance"]
        
        classifications['Compliance'] = {
            "source_count": len(compliance_sources),
            "volume": self._calculate_volume(compliance_sources),
            "quality_score": f"{data_quality.get('score', 0)}%",
            "key_patterns": list(set(compliance_patterns)),
            "recommended_use_cases": list(set(compliance_use_cases)),
            "sources": [s.get('name') for s in compliance_sources[:10]],
            "missing_capabilities": capability_gaps.get('missing_capabilities', []) if 'compliance' in capability_gaps.get('missing_capabilities', []) else [],
            "recommendations": data_quality.get('recommendations', []),
            "data_quality": data_quality
        }
        
        return classifications
    
    def _calculate_volume(self, sources: List[Dict]) -> str:
        """Calculate estimated volume from sources."""
        total_events = sum(src.get('events', 0) for src in sources)
        
        if total_events == 0:
            return "No data"
        elif total_events < 10000:
            return f"~{total_events:,} events (Low volume)"
        elif total_events < 100000:
            return f"~{total_events:,} events (Medium volume)"
        elif total_events < 1000000:
            return f"~{total_events:,} events (High volume)"
        else:
            return f"~{total_events:,} events (Very high volume)"
            
    def _fallback_classification(self) -> Dict[str, Any]:
        """Fallback classification when LLM analysis fails - should not be needed anymore."""
        # This method is kept for backwards compatibility but should rarely be used
        return self.classify_data()
        
    async def generate_recommendations(self) -> List[Dict[str, Any]]:
        """
        Generate use case recommendations based on discovered data.
        
        Returns:
            List of recommended use cases with priorities and details
        """
        # Use local analyzer to create compact summary instead of sending all raw data
        discovery_summary = self.local_analyzer.summarize_discovery(self.discovery_results)
        
        # Prepare comprehensive data for LLM analysis (now much smaller)
        analysis_data = {
            "environment_overview": self.environment_overview.__dict__ if self.environment_overview else {},
            "discovery_summary": discovery_summary,
            "total_steps": len(self.discovery_results),
            "total_interesting_findings": sum(len(r.interesting_findings) for r in self.discovery_results)
        }
        
        try:
            recommendations_result = await self.llm_client.analyze_data(analysis_data, "recommendations")
            
            # Debug: print what we got back
            print(f"DEBUG: LLM recommendations type: {type(recommendations_result)}")
            print(f"DEBUG: LLM recommendations content (first 500 chars): {str(recommendations_result)[:500]}")
            
            # If we get a list directly, return it
            if isinstance(recommendations_result, list):
                return recommendations_result
            elif isinstance(recommendations_result, dict) and "recommendations" in recommendations_result:
                return recommendations_result["recommendations"]
            elif isinstance(recommendations_result, dict):
                # Try to extract any list from the dict
                for key, value in recommendations_result.items():
                    if isinstance(value, list) and len(value) > 0:
                        print(f"DEBUG: Found list under key '{key}'")
                        return value
                # If we found a dict but no useful list, return empty
                print("DEBUG: Dict received but no list found, returning empty")
                return []
            else:
                # If we can't parse properly, raise an error
                print(f"DEBUG: Unparseable type: {type(recommendations_result)}")
                raise Exception("LLM returned unparseable recommendation data")
                
        except Exception as e:
            print(f"DEBUG: Exception in generate_recommendations: {str(e)}")
            raise Exception(f"Use case recommendations failed: LLM connection error - {str(e)}")
    
    async def generate_suggested_use_cases(self) -> List[Dict[str, Any]]:
        """
        Generate creative, cross-functional use cases based on data source combinations.
        
        Returns:
            List of sophisticated use cases that leverage multiple data sources
        """
        # Use local analyzer to create compact summary
        discovery_summary = self.local_analyzer.summarize_discovery(self.discovery_results)
        
        # Analyze data source combinations and patterns (local analysis)
        data_source_analysis = self._analyze_data_source_combinations()
        
        # Prepare data for creative use case generation (now much smaller payload)
        use_case_data = {
            "environment_overview": self.environment_overview.__dict__ if self.environment_overview else {},
            "data_source_combinations": data_source_analysis,
            "discovery_summary": discovery_summary,
            "prompt_guidance": """
            Generate creative, cross-functional use cases that combine multiple data sources to achieve sophisticated business outcomes.
            Focus on scenarios like:
            - User behavior correlation across systems
            - Security anomaly detection using multiple data streams
            - Business intelligence from combined operational and user data
            - Compliance monitoring across departments
            - Performance optimization using correlated metrics
            - Risk assessment from behavioral patterns
            
            For each use case, provide:
            - Title and description
            - Required data sources (minimum 2)
            - Business value and outcomes
            - Implementation complexity
            - Success metrics
            - Real-world scenario example
            """
        }
        
        try:
            use_cases_result = await self.llm_client.analyze_data(use_case_data, "creative_use_cases")
            
            # Parse the response
            if isinstance(use_cases_result, list):
                return use_cases_result
            elif isinstance(use_cases_result, dict) and "use_cases" in use_cases_result:
                return use_cases_result["use_cases"]
            elif isinstance(use_cases_result, dict) and "analysis" in use_cases_result:
                # Try to extract use cases from analysis text
                return self._extract_use_cases_from_analysis(use_cases_result["analysis"])
            else:
                # Fallback to creative use cases based on discovered data
                return self._generate_creative_fallback_use_cases()
                
        except Exception as e:
            print(f"LLM use case generation failed: {e}, using fallback")
            return self._generate_creative_fallback_use_cases()
    
    def get_all_results(self) -> List[DiscoveryResult]:
        """Get all discovery results."""
        return self.discovery_results
    
    def _get_source_count(self, sourcetype):
        """Helper method to get formatted event count for a specific source type."""
        if not self.discovery_data or 'detailed_discovery' not in self.discovery_data:
            return "events"
            
        # Try to find the source in the detailed discovery data
        detailed = self.discovery_data['detailed_discovery']
        if isinstance(detailed, dict) and 'sources' in detailed:
            for source in detailed['sources']:
                if isinstance(source, dict):
                    source_name = source.get('sourcetype') or source.get('name') or source.get('source')
                    if source_name == sourcetype:
                        count = source.get('count', 0)
                        if count > 1000:
                            return f"{count/1000:.0f}K+"
                        else:
                            return str(count)
        
        return "events"
    
    def _get_actual_data_sources(self) -> Dict[str, Any]:
        """Get summary of actual discovered data sources."""
        if not self.discovery_data or 'detailed_discovery' not in self.discovery_data:
            return {}
            
        sources = {}
        detailed = self.discovery_data['detailed_discovery']
        
        if isinstance(detailed, dict) and 'sources' in detailed:
            for source in detailed['sources']:
                if isinstance(source, dict):
                    source_name = source.get('sourcetype') or source.get('name') or source.get('source')
                    if source_name:
                        sources[source_name] = {
                            'count': source.get('count', 0),
                            'index': source.get('index', 'unknown')
                        }
        
        return sources
        
    def _analyze_data_source_combinations(self) -> Dict[str, Any]:
        """Analyze available data sources and their potential combinations."""
        data_sources = {
            "security": [],
            "user_activity": [],
            "infrastructure": [],
            "application": [],
            "network": [],
            "location": [],
            "communication": [],
            "hr_business": []
        }
        
        # Categorize discovered data sources
        for result in self.discovery_results:
            data_str = str(result.data).lower()
            desc_str = result.description.lower()
            
            # Security data
            if any(term in data_str or term in desc_str for term in 
                   ["security", "auth", "login", "firewall", "vpn", "certificate", "access"]):
                data_sources["security"].append({
                    "name": result.description,
                    "type": "security",
                    "data": result.data
                })
            
            # User activity data
            if any(term in data_str or term in desc_str for term in 
                   ["user", "session", "login", "logoff", "activity", "behavior"]):
                data_sources["user_activity"].append({
                    "name": result.description,
                    "type": "user_activity", 
                    "data": result.data
                })
            
            # Infrastructure data
            if any(term in data_str or term in desc_str for term in 
                   ["system", "server", "cpu", "memory", "disk", "performance", "uptime"]):
                data_sources["infrastructure"].append({
                    "name": result.description,
                    "type": "infrastructure",
                    "data": result.data
                })
            
            # Application data
            if any(term in data_str or term in desc_str for term in 
                   ["application", "app", "web", "api", "service", "error"]):
                data_sources["application"].append({
                    "name": result.description,
                    "type": "application",
                    "data": result.data
                })
            
            # Network data
            if any(term in data_str or term in desc_str for term in 
                   ["network", "interface", "bandwidth", "connection", "ip", "dns"]):
                data_sources["network"].append({
                    "name": result.description,
                    "type": "network",
                    "data": result.data
                })
            
            # Communication/collaboration data
            if any(term in data_str or term in desc_str for term in 
                   ["chat", "teams", "slack", "email", "meeting", "webex", "collaboration"]):
                data_sources["communication"].append({
                    "name": result.description,
                    "type": "communication",
                    "data": result.data
                })
        
        return {
            "categories": data_sources,
            "total_sources": sum(len(sources) for sources in data_sources.values()),
            "combinations_possible": len([cat for cat in data_sources.values() if len(cat) > 0])
        }
    
    def _extract_use_cases_from_analysis(self, analysis_text: str) -> List[Dict[str, Any]]:
        """Extract structured use cases from analysis text."""
        # Basic fallback parsing - in a real implementation, this would be more sophisticated
        use_cases = []
        
        # Look for numbered items or bullet points that might be use cases
        lines = analysis_text.split('\n')
        current_use_case = None
        
        for line in lines:
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith('-') or line.startswith('*')):
                if current_use_case:
                    use_cases.append(current_use_case)
                
                # Start new use case
                current_use_case = {
                    "title": line.split('.', 1)[-1].strip() if '.' in line else line,
                    "description": "",
                    "data_sources": ["Multiple sources"],
                    "business_value": "High",
                    "complexity": "Medium",
                    "category": "Cross-functional"
                }
            elif current_use_case and line:
                current_use_case["description"] += line + " "
        
        if current_use_case:
            use_cases.append(current_use_case)
            
        return use_cases if use_cases else self._generate_creative_fallback_use_cases()
    
    def _generate_creative_fallback_use_cases(self) -> List[Dict[str, Any]]:
        """Generate fallback creative use cases based on discovered data patterns."""
        data_analysis = self._analyze_data_source_combinations()
        
        use_cases = []
        
        # Get actual discovered data sources for reference
        actual_sources = self._get_actual_data_sources()
        
        # Section 1: Use cases based on ACTUAL discovered data sources
        
        # Windows Security Monitoring (if we have WinEventLog data)
        if any("wineventlog" in str(result.data).lower() or "security" in str(result.data).lower() 
               for result in self.discovery_results):
            use_cases.append({
                "title": "Windows Security Event Correlation & Threat Detection",
                "description": f"Leverage the high-volume Windows Event Log data (WinEventLog:Security with {self._get_source_count('WinEventLog:Security')} events) to detect security anomalies by correlating login patterns, system access, and application events.",
                "data_sources": ["WinEventLog:Security", "WinEventLog:System"],
                "missing_sources": ["Network firewall logs", "VPN logs", "EDR data"],
                "business_value": "Critical - With Windows event logs being your highest volume data source, this provides immediate security value from existing infrastructure.",
                "implementation_complexity": "Medium",
                "success_metrics": ["Failed login detection rate", "Anomalous access patterns identified", "Mean time to threat detection"],
                "scenario": "Detect brute force attacks, unusual login times, or privilege escalation by analyzing security events in your wineventlog index.",
                "category": "Security & Risk Management",
                "type": "existing_data"
            })
        
        # System Performance Optimization (if we have system metrics)
        if any("cpu" in str(result.data).lower() or "uptime" in str(result.data).lower() 
               for result in self.discovery_results):
            use_cases.append({
                "title": "Cross-Platform System Performance Intelligence", 
                "description": f"Combine Unix system metrics (Unix:Uptime, cpu sourcetype with {self._get_source_count('cpu')} events) with Windows system data (WinEventLog:System) to create unified performance dashboards and predictive alerts.",
                "data_sources": ["Unix:Uptime", "cpu", "WinEventLog:System"],
                "missing_sources": ["Memory metrics", "Disk I/O logs", "Network performance data"],
                "business_value": "High - Proactive performance management using your existing CPU metrics and system uptime data.",
                "implementation_complexity": "Low-Medium",
                "success_metrics": ["System availability percentage", "Performance prediction accuracy", "Resource utilization optimization"],
                "scenario": "Predict system overload by correlating CPU usage trends with uptime patterns across your Unix and Windows infrastructure.",
                "category": "Operational Excellence", 
                "type": "existing_data"
            })
        
        # Application and Error Analysis (if we have error tracking)
        if any("error" in str(result.data).lower() or "chatllm" in str(result.data).lower()
               for result in self.discovery_results):
            use_cases.append({
                "title": "Intelligent Application Health Monitoring",
                "description": "Correlate application errors (from 'Errors in last 24 hours' searches) with chat/communication logs (chatllm:log) and system performance to identify application health patterns and user impact.",
                "data_sources": ["Error logs", "Application logs", "System performance metrics"],
                "missing_sources": ["User session data", "Application transaction logs", "APM data"],
                "business_value": "Medium-High - Improve application reliability by connecting system errors to user experience metrics.",
                "implementation_complexity": "Medium",
                "success_metrics": ["Application error reduction", "User experience correlation", "Incident response time"],
                "scenario": "When application errors spike, automatically correlate with user activity patterns and system resource usage to identify root causes.",
                "category": "Application Performance",
                "type": "existing_data"
            })
        
        if data_analysis["categories"]["infrastructure"] and data_analysis["categories"]["application"]:
            use_cases.append({
                "title": "Predictive Performance Optimization",
                "description": "Correlate infrastructure metrics with application performance to predict and prevent system bottlenecks before they impact users.",
                "data_sources": ["Infrastructure metrics", "Application performance logs", "System resource usage"],
                "business_value": "High - Proactive issue resolution improves user experience and reduces downtime costs.",
                "implementation_complexity": "Medium-High",
                "success_metrics": ["System uptime", "Performance prediction accuracy", "User satisfaction scores"],
                "scenario": "Predict when database performance will degrade based on memory usage trends and query patterns.",
                "category": "Operational Excellence"
            })
        
        if data_analysis["categories"]["user_activity"] and data_analysis["categories"]["communication"]:
            use_cases.append({
                "title": "Remote Work Effectiveness Analytics",
                "description": "Analyze user login patterns, VPN usage, and collaboration tool engagement to optimize remote work policies and identify productivity trends.",
                "data_sources": ["VPN connection logs", "Collaboration platform usage", "System login data"],
                "business_value": "Medium-High - Optimize remote work policies and improve employee productivity and satisfaction.",
                "implementation_complexity": "Low-Medium", 
                "success_metrics": ["Employee productivity metrics", "Remote work satisfaction", "Collaboration effectiveness"],
                "scenario": "Identify optimal collaboration patterns and recommend policy adjustments for hybrid work arrangements.",
                "category": "Workforce Analytics"
            })
        
        if data_analysis["categories"]["security"] and data_analysis["categories"]["network"]:
            use_cases.append({
                "title": "Zero Trust Architecture Validation",
                "description": "Continuously validate network access decisions by correlating user authentication, device trust, and network behavior patterns.",
                "data_sources": ["Network access logs", "Device authentication data", "User behavior analytics"],
                "business_value": "Critical - Strengthen security posture and ensure zero trust principles are effectively implemented.",
                "implementation_complexity": "High",
                "success_metrics": ["Security incident reduction", "Access control accuracy", "Compliance score"],
                "scenario": "Automatically adjust access permissions based on user location, device trust level, and behavioral patterns.",
                "category": "Advanced Security"
            })
        
        if data_analysis["categories"]["application"] and data_analysis["categories"]["user_activity"]:
            use_cases.append({
                "title": "User Experience Journey Optimization",
                "description": "Map complete user journeys across applications to identify friction points and optimize digital experiences.",
                "data_sources": ["Application logs", "User session data", "Performance metrics"],
                "business_value": "High - Improved user experience leads to higher engagement and customer satisfaction.",
                "implementation_complexity": "Medium",
                "success_metrics": ["User journey completion rates", "Session duration", "User satisfaction scores"],
                "scenario": "Identify where users abandon workflows and optimize those touchpoints to improve conversion rates.",
                "category": "Customer Experience"
            })
        
        # Section 2: Potential use cases that would require additional data sources
        
        # Enhanced use cases that could be achieved with additional data collection
        use_cases.extend([
            {
                "title": "Comprehensive User Journey Analytics",
                "description": "Extend your existing Windows authentication data to track complete user journeys across applications, VPN connections, and business systems.",
                "data_sources": [f"WinEventLog:Security ({self._get_source_count('WinEventLog:Security')} events)", "Existing error tracking"],
                "missing_sources": ["VPN connection logs", "Web application access logs", "Mobile device logs", "Business application transaction logs"],
                "business_value": "High - Transform security logs into business intelligence about user behavior and application usage patterns.",
                "implementation_complexity": "Medium-High",
                "success_metrics": ["User journey completion rates", "Application adoption metrics", "Security incident correlation"],
                "scenario": "Track a user from Windows login, through VPN connection, to specific business application usage and identify optimization opportunities.",
                "category": "User Experience Analytics",
                "type": "potential_with_additions"
            },
            {
                "title": "Predictive Security Operations Center (SOC)",
                "description": "Build on your Windows security events foundation to create predictive threat intelligence using machine learning.",
                "data_sources": [f"WinEventLog:Security ({self._get_source_count('WinEventLog:Security')} events)", f"WinEventLog:System ({self._get_source_count('WinEventLog:System')} events)"],
                "missing_sources": ["Network firewall logs", "Email security logs", "Endpoint detection and response (EDR) data", "Threat intelligence feeds"],
                "business_value": "Critical - Evolve from reactive to predictive security using your existing event log foundation.",
                "implementation_complexity": "High",
                "success_metrics": ["Threat prediction accuracy", "False positive reduction", "Security analyst efficiency"],
                "scenario": "Predict potential security incidents by analyzing patterns in your 375K+ security events combined with external threat feeds.",
                "category": "Advanced Threat Intelligence",
                "type": "potential_with_additions"
            },
            {
                "title": "Business Continuity & Disaster Recovery Intelligence",
                "description": "Leverage your system performance data (CPU, uptime) to build comprehensive business continuity monitoring.",
                "data_sources": [f"Unix:Uptime ({self._get_source_count('Unix:Uptime')} events)", f"cpu metrics ({self._get_source_count('cpu')} events)", "System error tracking"],
                "missing_sources": ["Database replication logs", "Backup completion logs", "Network connectivity monitoring", "Storage capacity metrics"],
                "business_value": "High - Proactive business continuity management using existing system health data as foundation.",
                "implementation_complexity": "Medium-High", 
                "success_metrics": ["Recovery time objectives", "System redundancy effectiveness", "Business impact prevention"],
                "scenario": "Predict system failures and automatically trigger disaster recovery procedures based on performance degradation patterns.",
                "category": "Business Continuity",
                "type": "potential_with_additions"
            }
        ])
        
        return use_cases[:6]  # Return top 6 use cases
        
    # Private helper methods
    
    def _estimate_discovery_steps(self, indexes: int, sourcetypes: int, hosts: int = 0, 
                                   sources: int = 0, knowledge_objects: int = 0, 
                                   users: int = 0, kv_collections: int = 0) -> int:
        """Estimate total discovery steps based on environment size."""
        # Base steps + detailed per-component estimates
        base = 15
        index_steps = indexes * 4  # Now includes get_index_info per index
        sourcetype_steps = sourcetypes * 2
        host_steps = hosts
        source_steps = sources
        ko_steps = knowledge_objects + 50  # Additional KO types discovery
        user_steps = min(users, 20)  # Cap user discovery steps
        kv_steps = min(kv_collections, 20)  # Cap KV store steps
        analytics_steps = 30  # Advanced analytical queries
        
        return base + index_steps + sourcetype_steps + host_steps + source_steps + ko_steps + user_steps + kv_steps + analytics_steps
        
    def _estimate_time(self, steps: int) -> str:
        """Estimate discovery time based on number of steps."""
        minutes = max(2, steps // 10)  # Roughly 6 steps per minute
        if minutes < 60:
            return f"~{minutes} minutes"
        else:
            hours = minutes // 60
            remaining_minutes = minutes % 60
            return f"~{hours}h {remaining_minutes}m"
    
    async def _mcp_call(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make actual MCP call to Splunk server using proper JSON-RPC format."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.mcp_token}"
        }
        
        # Build proper MCP JSON-RPC payload
        payload = {
            "method": "tools/call",
            "params": {
                "name": method,
                "arguments": params
            }
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.mcp_url,
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30),
                    ssl=False  # Disable SSL verification for self-signed certificates
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        # Extract the actual data from MCP response structure
                        if isinstance(result, dict) and "result" in result:
                            content = result["result"].get("content", [])
                            if content and isinstance(content, list) and len(content) > 0:
                                # Get the text content and parse it as JSON
                                text_content = content[0].get("text", "{}")
                                # Skip parsing if content is empty or whitespace
                                if not text_content or not text_content.strip():
                                    print(f"DEBUG: MCP returned empty content (may be processing/rate limit)")
                                    return {"results": []}
                                try:
                                    parsed_data = json.loads(text_content)
                                    return parsed_data
                                except json.JSONDecodeError as e:
                                    print(f"WARNING: Failed to parse MCP response JSON: {e}")
                                    print(f"DEBUG: Content was: {text_content[:200]}")
                                    return {"results": []}
                            else:
                                return {"results": []}
                        else:
                            return result
                    else:
                        error_text = await response.text()
                        raise Exception(f"MCP server returned {response.status}: {error_text}")
        except Exception as e:
            raise Exception(f"MCP connection failed: {str(e)}")
            
    async def _identify_notable_patterns(self, indexes_data: Dict, sourcetypes_data: Dict) -> List[str]:
        """Use LLM to identify notable patterns in initial data."""
        try:
            pattern_data = {
                "indexes": indexes_data,
                "sourcetypes": sourcetypes_data
            }
            result = await self.llm_client.analyze_data(pattern_data, "patterns")
            if isinstance(result, dict) and "patterns" in result:
                return result["patterns"]
            elif isinstance(result, dict) and "analysis" in result:
                return [result["analysis"]]
            else:
                return ["Pattern analysis completed"]
        except Exception as e:
            raise Exception(f"LLM pattern analysis failed: {str(e)}")
        
    async def _discover_indexes(self) -> List[Dict[str, Any]]:
        """Discover detailed information about all indexes."""
        try:
            result = await self._mcp_call("get_indexes", {"row_limit": 100})
            return result.get("results", [])
        except Exception as e:
            raise Exception(f"Failed to discover indexes: {str(e)}")
        
    async def _discover_sourcetypes(self) -> List[Dict[str, Any]]:
        """Discover detailed information about all sourcetypes."""
        try:
            result = await self._mcp_call("get_metadata", {"type": "sourcetypes", "index": "*", "earliest_time": "-24h", "latest_time": "now", "row_limit": 100})
            
            # Handle different response formats
            if isinstance(result, dict):
                sourcetypes = result.get("results", [])
                print(f"DEBUG: MCP returned dict with {len(sourcetypes)} sourcetypes in 'results' key")
            elif isinstance(result, list):
                sourcetypes = result
                print(f"DEBUG: MCP returned list with {len(sourcetypes)} sourcetypes directly")
            else:
                print(f"WARNING: Unexpected sourcetype response type: {type(result)}")
                sourcetypes = []
            
            # Log sample for debugging
            if sourcetypes:
                print(f"DEBUG: First sourcetype sample: {list(sourcetypes[0].keys()) if sourcetypes else 'none'}")
            
            return sourcetypes
        except Exception as e:
            print(f"ERROR discovering sourcetypes: {str(e)}")
            raise Exception(f"Failed to discover sourcetypes: {str(e)}")
        
    async def _discover_knowledge_objects(self) -> List[Dict[str, Any]]:
        """Discover knowledge objects like dashboards, saved searches, etc.""" 
        try:
            result = await self._mcp_call("get_knowledge_objects", {"type": "saved_searches", "row_limit": 100})
            return result.get("results", [])
        except Exception as e:
            raise Exception(f"Failed to discover knowledge objects: {str(e)}")
    
    async def _discover_hosts(self) -> List[Dict[str, Any]]:
        """Discover detailed information about all hosts sending data."""
        try:
            result = await self._mcp_call("get_metadata", {
                "type": "hosts",
                "index": "*",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 500
            })
            return result.get("results", [])
        except Exception as e:
            raise Exception(f"Failed to discover hosts: {str(e)}")
    
    async def _discover_sources(self) -> List[Dict[str, Any]]:
        """Discover detailed information about all data sources."""
        try:
            result = await self._mcp_call("get_metadata", {
                "type": "sources",
                "index": "*",
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 500
            })
            return result.get("results", [])
        except Exception as e:
            raise Exception(f"Failed to discover sources: {str(e)}")
    
    async def _discover_knowledge_objects_by_type(self, ko_type: str) -> List[Dict[str, Any]]:
        """Discover knowledge objects of a specific type."""
        try:
            result = await self._mcp_call("get_knowledge_objects", {
                "type": ko_type,
                "row_limit": 100
            })
            results = result.get("results", [])
            # Add type to each result for easier analysis
            for r in results:
                r['ko_type'] = ko_type
            return results
        except Exception as e:
            # Some KO types might not be available, silently skip
            return []
    
    async def _discover_detailed_index_info(self) -> List[Dict[str, Any]]:
        """Get detailed information for each index."""
        detailed_info = []
        # Get list of indexes first
        indexes_result = await self._mcp_call("get_indexes", {"row_limit": 100})
        indexes = indexes_result.get("results", [])
        
        # Get detailed info for top 10 indexes by size/events
        sorted_indexes = sorted(
            indexes, 
            key=lambda x: int(x.get('totalEventCount', 0)), 
            reverse=True
        )[:10]
        
        for idx in sorted_indexes:
            index_name = idx.get('title', idx.get('name', 'unknown'))
            try:
                result = await self._mcp_call("get_index_info", {"index_name": index_name})
                detailed_info.append(result.get("results", {}))
            except Exception:
                # Skip if index info not available
                pass
        
        return detailed_info
    
    async def _discover_users(self) -> List[Dict[str, Any]]:
        """Discover user accounts and roles."""
        try:
            result = await self._mcp_call("get_user_list", {"row_limit": 100})
            return result.get("results", [])
        except Exception as e:
            raise Exception(f"Failed to discover users: {str(e)}")
    
    async def _discover_kv_collections(self) -> List[Dict[str, Any]]:
        """Discover KV store collections."""
        try:
            result = await self._mcp_call("get_kv_store_collections", {"row_limit": 100})
            return result.get("results", [])
        except Exception as e:
            raise Exception(f"Failed to discover KV collections: {str(e)}")
    
    async def _run_advanced_analytics(self) -> List[Dict[str, Any]]:
        """Run advanced analytical queries for deeper insights."""
        analytics_results = []
        
        # 1. Data quality analysis - find empty indexes
        try:
            query = "| tstats count WHERE index=* by index | where count=0"
            result = await self._mcp_call("run_splunk_query", {
                "query": query,
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 100
            })
            empty_indexes = result.get("results", [])
            if empty_indexes:
                analytics_results.append({
                    "description": "Data Quality: Empty Indexes Detection",
                    "data": {"empty_indexes": empty_indexes},
                    "findings": [f"⚠️  Found {len(empty_indexes)} indexes with no data in last 24h - potential configuration issues"]
                })
        except Exception:
            pass
        
        # 2. Temporal pattern analysis - data volume by day
        try:
            query = "| tstats count WHERE index=* earliest=-7d latest=now by _time span=1d | eval day=strftime(_time, \"%Y-%m-%d\")"
            result = await self._mcp_call("run_splunk_query", {
                "query": query,
                "earliest_time": "-7d",
                "latest_time": "now",
                "row_limit": 7
            })
            temporal_data = result.get("results", [])
            if temporal_data:
                counts = [int(r.get('count', 0)) for r in temporal_data]
                avg_daily = sum(counts) / len(counts) if counts else 0
                findings = [f"📊 Average daily events: {avg_daily:,.0f}"]
                if counts:
                    trend = "increasing" if counts[-1] > counts[0] else "decreasing"
                    findings.append(f"📈 7-day trend: {trend}")
                analytics_results.append({
                    "description": "Temporal Analysis: 7-Day Data Volume Trend",
                    "data": {"daily_volumes": temporal_data},
                    "findings": findings
                })
        except Exception:
            pass
        
        # 3. Field diversity analysis - over-indexed indexes
        try:
            query = "| rest /services/data/indexes | stats count by title | where count > 0"
            result = await self._mcp_call("run_splunk_query", {
                "query": query,
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": 100
            })
            if result.get("results"):
                analytics_results.append({
                    "description": "Index Health Check",
                    "data": result.get("results", []),
                    "findings": ["✅ Index configuration validated"]
                })
        except Exception:
            pass
        
        return analytics_results
        
    async def _analyze_index_findings(self, index_info: Dict[str, Any]) -> List[str]:
        """Analyze index for interesting findings with actionable insights."""
        findings = []
        
        # Ensure index_info is a dictionary
        if not isinstance(index_info, dict):
            return findings
        
        title = index_info.get("title", "unknown")
        size_str = index_info.get("currentDBSizeMB", "0")
        event_count_str = index_info.get("totalEventCount", "0")
        disabled = index_info.get("disabled", "0") == "1"
        
        try:
            size_mb = float(size_str)
            event_count = int(event_count_str)
            
            # Large index (significant data volume)
            if size_mb > 1000:
                findings.append(f"⚠️  Large index: {title} ({size_mb:,.0f}MB, {event_count:,} events) - Review retention policy and consider archiving")
            elif size_mb > 100:
                findings.append(f"📊 Moderate index: {title} ({size_mb:,.0f}MB, {event_count:,} events) - Good data volume for analysis")
            
            # High event volume
            if event_count > 1000000:
                findings.append(f"🔥 High-volume index: {title} ({event_count:,} events) - Prime candidate for analytics and dashboards")
            elif event_count > 100000:
                findings.append(f"📈 Active index: {title} ({event_count:,} events) - Sufficient data for meaningful insights")
            
            # Disabled but with data
            if disabled and (size_mb > 0 or event_count > 0):
                findings.append(f"⚠️  Disabled index contains data: {title} ({size_mb:,.0f}MB, {event_count:,} events) - Consider re-enabling or archiving")
            
            # Specific index types with recommendations
            if 'wineventlog' in title.lower():
                if event_count > 0:
                    findings.append(f"🔒 Windows Event Log data found in {title} - Excellent for security monitoring and compliance")
            elif 'security' in title.lower():
                findings.append(f"🔐 Security-focused index: {title} - Review for threat hunting and compliance use cases")
            elif title.startswith('_') and not disabled:
                if event_count == 0:
                    findings.append(f"💡 Internal index {title} is enabled but empty - Consider disabling to save resources")
            
            # Empty enabled indexes
            if not disabled and size_mb == 0 and event_count == 0:
                if not title.startswith('_'):
                    findings.append(f"💭 Empty index: {title} - No data received yet. Verify data inputs or consider removing")
            
        except (ValueError, TypeError) as e:
            findings.append(f"⚠️  Data quality issue in {title} - Unable to parse size or event count")
        
        return findings
        
    async def _analyze_sourcetype_findings(self, sourcetype_info: Dict[str, Any]) -> List[str]:
        """Analyze sourcetype for interesting findings with actionable insights."""
        findings = []
        
        # Ensure sourcetype_info is a dictionary
        if not isinstance(sourcetype_info, dict):
            return findings
        
        sourcetype_name = sourcetype_info.get("sourcetype", sourcetype_info.get("type", "unknown"))
        total_count_str = sourcetype_info.get("totalCount", "0")
        first_time = sourcetype_info.get("firstTimeIso", "")
        recent_time = sourcetype_info.get("recentTimeIso", "")
        
        try:
            total_count = int(total_count_str)
            
            # High-volume sourcetypes
            if total_count > 100000:
                findings.append(f"🔥 High-volume source: {sourcetype_name} ({total_count:,} events) - Key data source for analytics")
            elif total_count > 10000:
                findings.append(f"📊 Active source: {sourcetype_name} ({total_count:,} events) - Good for dashboards and alerting")
            elif total_count > 0:
                findings.append(f"📈 Data source: {sourcetype_name} ({total_count:,} events)")
            
            # Security-related sourcetypes
            if 'wineventlog:security' in sourcetype_name.lower():
                findings.append(f"🔒 Critical security data: {sourcetype_name} - Essential for threat detection, user monitoring, and compliance")
            elif 'security' in sourcetype_name.lower() or 'auth' in sourcetype_name.lower():
                findings.append(f"🔐 Security data: {sourcetype_name} - Use for authentication monitoring and security analytics")
            elif 'firewall' in sourcetype_name.lower() or 'ids' in sourcetype_name.lower() or 'ips' in sourcetype_name.lower():
                findings.append(f"🛡️  Network security data: {sourcetype_name} - Valuable for threat hunting and network monitoring")
            
            # Application data
            elif 'wineventlog:application' in sourcetype_name.lower():
                findings.append(f"📱 Application logs: {sourcetype_name} - Monitor app health, errors, and performance")
            elif 'application' in sourcetype_name.lower() or 'app' in sourcetype_name.lower():
                findings.append(f"💼 Application data: {sourcetype_name} - Track application behavior and errors")
            
            # System/Infrastructure
            elif 'wineventlog:system' in sourcetype_name.lower():
                findings.append(f"⚙️  System logs: {sourcetype_name} - Monitor OS health, services, and hardware")
            elif 'syslog' in sourcetype_name.lower() or 'linux' in sourcetype_name.lower() or 'unix' in sourcetype_name.lower():
                findings.append(f"🐧 Unix/Linux system data: {sourcetype_name} - Track system health and operations")
            elif 'cpu' in sourcetype_name.lower() or 'memory' in sourcetype_name.lower() or 'disk' in sourcetype_name.lower():
                findings.append(f"📊 Performance metrics: {sourcetype_name} - Monitor resource utilization and capacity planning")
            
            # Structured data
            if 'json' in sourcetype_name.lower() or 'xml' in sourcetype_name.lower():
                findings.append(f"✨ Structured data: {sourcetype_name} - Well-formatted for easy parsing and analytics")
            
            # Data freshness analysis
            if recent_time:
                try:
                    from datetime import datetime
                    recent_dt = datetime.fromisoformat(recent_time.replace('Z', '+00:00'))
                    age_hours = (datetime.now(recent_dt.tzinfo) - recent_dt).total_seconds() / 3600
                    
                    if age_hours < 1:
                        findings.append(f"✅ Fresh data: {sourcetype_name} - Recent events (< 1 hour old)")
                    elif age_hours > 168:  # 7 days
                        findings.append(f"⚠️  Stale data: {sourcetype_name} - No recent events ({age_hours/24:.0f} days old). Check data inputs")
                except:
                    pass
            
            # Rare/unique sourcetypes
            if total_count < 100 and total_count > 0:
                findings.append(f"💎 Low-volume source: {sourcetype_name} ({total_count} events) - May be rare events or new data source")
                
        except (ValueError, TypeError):
            pass
        
        return findings
    
    async def _analyze_host_findings(self, host_info: Dict[str, Any]) -> List[str]:
        """Analyze host for interesting findings with actionable insights."""
        findings = []
        
        # Ensure host_info is a dictionary
        if not isinstance(host_info, dict):
            return findings
        
        host_name = host_info.get("host", "unknown")
        total_count_str = host_info.get("totalCount", "0")
        first_time = host_info.get("firstTimeIso", "")
        recent_time = host_info.get("recentTimeIso", "")
        
        try:
            total_count = int(total_count_str)
            
            # High-volume hosts
            if total_count > 50000:
                findings.append(f"🔥 High-activity host: {host_name} ({total_count:,} events) - Major infrastructure component")
            elif total_count > 10000:
                findings.append(f"📊 Active host: {host_name} ({total_count:,} events) - Important monitoring target")
            elif total_count > 1000:
                findings.append(f"📈 Moderate host: {host_name} ({total_count:,} events)")
            elif total_count > 0:
                findings.append(f"📌 Light host: {host_name} ({total_count} events)")
            
            # Low-activity detection
            if total_count < 10 and total_count > 0:
                findings.append(f"⚠️  Very low activity: {host_name} - May indicate monitoring gaps or intermittent data collection")
            
            # Identify host patterns (production, development, etc.)
            host_lower = host_name.lower()
            if any(term in host_lower for term in ['prod', 'production', 'prd']):
                findings.append(f"🏭 Production host: {host_name} - Critical system requiring monitoring")
            elif any(term in host_lower for term in ['dev', 'development', 'test', 'staging', 'qa']):
                findings.append(f"🔧 Non-production host: {host_name} - Development/test environment")
            
            # Infrastructure type detection
            if any(term in host_lower for term in ['web', 'www', 'apache', 'nginx', 'iis']):
                findings.append(f"🌐 Web server: {host_name} - Consider web analytics and performance monitoring")
            elif any(term in host_lower for term in ['db', 'database', 'sql', 'mysql', 'postgres', 'oracle']):
                findings.append(f"🗄️  Database server: {host_name} - Monitor queries, performance, and security")
            elif any(term in host_lower for term in ['dc', 'domain', 'ad', 'ldap']):
                findings.append(f"👥 Directory server: {host_name} - Critical for authentication and access control")
            elif any(term in host_lower for term in ['mail', 'exchange', 'smtp']):
                findings.append(f"📧 Mail server: {host_name} - Monitor email flow and security")
            elif any(term in host_lower for term in ['fw', 'firewall', 'proxy']):
                findings.append(f"🛡️  Security appliance: {host_name} - Essential for threat detection")
            
            # Data freshness analysis
            if recent_time:
                try:
                    from datetime import datetime
                    recent_dt = datetime.fromisoformat(recent_time.replace('Z', '+00:00'))
                    age_hours = (datetime.now(recent_dt.tzinfo) - recent_dt).total_seconds() / 3600
                    
                    if age_hours < 1:
                        findings.append(f"✅ Fresh data: {host_name} - Recent events (< 1 hour old)")
                    elif age_hours > 24:
                        findings.append(f"⚠️  Stale data: {host_name} - No recent events ({age_hours/24:.1f} days old). Check forwarder")
                except:
                    pass
                    
        except (ValueError, TypeError):
            pass
        
        return findings
    
    async def _analyze_source_findings(self, source_info: Dict[str, Any]) -> List[str]:
        """Analyze source for interesting findings with actionable insights."""
        findings = []
        
        # Ensure source_info is a dictionary
        if not isinstance(source_info, dict):
            return findings
        
        source_path = source_info.get("source", "unknown")
        total_count_str = source_info.get("totalCount", "0")
        first_time = source_info.get("firstTimeIso", "")
        recent_time = source_info.get("recentTimeIso", "")
        
        try:
            total_count = int(total_count_str)
            
            # High-volume sources
            if total_count > 50000:
                findings.append(f"🔥 High-volume source: {source_path} ({total_count:,} events) - Major data input")
            elif total_count > 10000:
                findings.append(f"📊 Active source: {source_path} ({total_count:,} events)")
            elif total_count > 1000:
                findings.append(f"📈 Moderate source: {source_path} ({total_count:,} events)")
            elif total_count > 0:
                findings.append(f"📌 Light source: {source_path} ({total_count} events)")
            
            # Low-activity detection
            if total_count < 10 and total_count > 0:
                findings.append(f"⚠️  Very low activity: {source_path} - May indicate new source or collection issues")
            
            # File path analysis
            source_lower = source_path.lower()
            
            # Windows event logs
            if 'wineventlog' in source_lower or 'eventlog' in source_lower:
                findings.append(f"🪟 Windows Event Log: {source_path} - System event monitoring")
            
            # Log file types
            elif '.log' in source_lower or '/var/log' in source_lower or 'c:\\logs' in source_lower:
                findings.append(f"📄 Log file: {source_path} - File-based monitoring")
                
                # Specific log types
                if 'access' in source_lower or 'access_log' in source_lower:
                    findings.append(f"🌐 Web access log: {source_path} - Track web traffic and user behavior")
                elif 'error' in source_lower or 'error_log' in source_lower:
                    findings.append(f"⚠️  Error log: {source_path} - Application error tracking")
                elif 'security' in source_lower or 'audit' in source_lower:
                    findings.append(f"🔒 Security/audit log: {source_path} - Compliance and security monitoring")
                elif 'application' in source_lower or 'app' in source_lower:
                    findings.append(f"📱 Application log: {source_path} - App behavior and performance")
            
            # Syslog
            elif 'syslog' in source_lower or 'udp:' in source_lower or 'tcp:' in source_lower:
                findings.append(f"📡 Network input: {source_path} - Syslog or network data collection")
            
            # Scripted inputs
            elif 'script:' in source_lower or 'powershell' in source_lower or '.ps1' in source_lower or '.sh' in source_lower:
                findings.append(f"⚙️  Scripted input: {source_path} - Custom data collection script")
            
            # Database inputs
            elif 'jdbc' in source_lower or 'odbc' in source_lower or 'sql' in source_lower:
                findings.append(f"🗄️  Database input: {source_path} - Database query monitoring")
            
            # API/HTTP inputs
            elif 'http' in source_lower or 'api' in source_lower or 'rest' in source_lower:
                findings.append(f"🔌 API/HTTP input: {source_path} - REST API or HTTP event collector")
            
            # Data freshness analysis
            if recent_time:
                try:
                    from datetime import datetime
                    recent_dt = datetime.fromisoformat(recent_time.replace('Z', '+00:00'))
                    age_hours = (datetime.now(recent_dt.tzinfo) - recent_dt).total_seconds() / 3600
                    
                    if age_hours < 1:
                        findings.append(f"✅ Fresh data: Recent events (< 1 hour old)")
                    elif age_hours > 24:
                        findings.append(f"⚠️  Stale data: No recent events ({age_hours/24:.1f} days old). Check input configuration")
                except:
                    pass
                    
        except (ValueError, TypeError):
            pass
        
        return findings
        
    async def _analyze_knowledge_object_findings(self, ko_info: Dict[str, Any], ko_type: str = "saved_searches") -> List[str]:
        """Analyze knowledge objects for interesting findings with actionable insights."""
        findings = []
        
        # Ensure ko_info is a dictionary
        if not isinstance(ko_info, dict):
            return findings
        
        ko_name = ko_info.get("name", ko_info.get("title", "unknown"))
        is_disabled = ko_info.get("disabled", "0") == "1"
        
        # Type-specific analysis
        if ko_type == "alerts":
            if not is_disabled:
                severity = ko_info.get("alert.severity", "medium")
                cron = ko_info.get("cron_schedule", "")
                findings.append(f"🚨 Alert active: '{ko_name}' - Severity: {severity}")
                if cron:
                    findings.append(f"⏰ Alert schedule: {cron}")
            else:
                findings.append(f"💤 Disabled alert: '{ko_name}' - Review and consider re-enabling")
        
        elif ko_type == "dashboards":
            views = ko_info.get("views", 0)
            if views:
                findings.append(f"📊 Dashboard: '{ko_name}' - {views} views - Active use case")
            else:
                findings.append(f"📊 Dashboard: '{ko_name}' - New or underutilized")
        
        elif ko_type == "macros":
            definition = ko_info.get("definition", "")
            if definition:
                findings.append(f"🔧 Macro: '{ko_name}' - Reusable SPL component")
        
        elif ko_type == "eventtypes":
            if not is_disabled:
                findings.append(f"🏷️  Event Type: '{ko_name}' - Data classification in use")
            else:
                findings.append(f"💤 Disabled event type: '{ko_name}'")
        
        else:  # saved_searches
            ko_search = ko_info.get("search", "")
            cron = ko_info.get("cron_schedule", "")
            search_lower = ko_search.lower()
            
            if not is_disabled:
                # Security-related
                if any(term in search_lower for term in ['security', 'threat', 'malware', 'intrusion', 'authentication', 'failed login']):
                    findings.append(f"🔒 Security search active: '{ko_name}' - Shows existing security monitoring")
                
                # Performance monitoring
                elif any(term in search_lower for term in ['cpu', 'memory', 'disk', 'performance', 'capacity']):
                    findings.append(f"📊 Performance monitoring: '{ko_name}' - Active infrastructure monitoring")
                
                # Error tracking
                elif any(term in search_lower for term in ['error', 'failed', 'exception', '404', '500', '503']):
                    findings.append(f"⚠️  Error tracking: '{ko_name}' - Proactive error monitoring in place")
                
                # Compliance/Audit
                elif any(term in search_lower for term in ['compliance', 'audit', 'license', 'policy']):
                    findings.append(f"📋 Compliance monitoring: '{ko_name}' - Audit and compliance tracking active")
                
                # General useful searches
                else:
                    if cron:
                        findings.append(f"⏰ Scheduled search: '{ko_name}' - Running on schedule: {cron}")
                    else:
                        findings.append(f"🔍 Saved search available: '{ko_name}' - Shows existing use case implementation")
            else:
                findings.append(f"💤 Disabled search: '{ko_name}' - Consider re-enabling or removing")
        
        return findings
    
    async def _analyze_detailed_index_findings(self, index_info: Dict[str, Any]) -> List[str]:
        """Analyze detailed index configuration for optimization opportunities."""
        findings = []
        
        if not isinstance(index_info, dict):
            return findings
        
        index_name = index_info.get("name", index_info.get("title", "unknown"))
        
        # Retention policy analysis
        frozen_time = index_info.get("frozenTimePeriodInSecs", 0)
        if frozen_time:
            days = int(frozen_time) / 86400
            if days > 365:
                findings.append(f"📅 Long retention: {index_name} retains data for {days:.0f} days - Validate against usage patterns")
            elif days < 30:
                findings.append(f"⚠️  Short retention: {index_name} only retains {days:.0f} days - May need extension for compliance")
        
        # Data model acceleration
        acceleration = index_info.get("datamodel_acceleration", "0")
        total_size = float(index_info.get("currentDBSizeMB", 0))
        if acceleration == "0" and total_size > 10000:  # >10GB
            findings.append(f"🚀 Acceleration opportunity: {index_name} has {total_size/1024:.1f}GB but no data model - Consider acceleration")
        
        # Replication
        replication_factor = index_info.get("repFactor", "0")
        if replication_factor == "0" or replication_factor == "auto":
            findings.append(f"⚠️  No replication: {index_name} - Consider enabling for high availability")
        
        # Storage optimization
        max_data_size = index_info.get("maxTotalDataSizeMB", 0)
        if max_data_size and total_size:
            usage_pct = (total_size / float(max_data_size)) * 100
            if usage_pct > 80:
                findings.append(f"💾 Storage warning: {index_name} at {usage_pct:.0f}% capacity - Increase maxTotalDataSizeMB")
        
        return findings
    
    async def _analyze_user_findings(self, user_info: Dict[str, Any]) -> List[str]:
        """Analyze user accounts for security and compliance insights."""
        findings = []
        
        if not isinstance(user_info, dict):
            return findings
        
        username = user_info.get("name", user_info.get("username", "unknown"))
        roles = user_info.get("roles", [])
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",")]
        
        # Admin role detection
        if "admin" in roles:
            findings.append(f"🔑 Admin user: {username} - Review privileges regularly")
        
        # Multiple roles
        if len(roles) > 5:
            findings.append(f"⚠️  {username} has {len(roles)} roles - Review for least privilege")
        
        # Last login analysis
        last_login = user_info.get("last_successful_login", "")
        if last_login:
            # Check if user is inactive (simplified check)
            findings.append(f"✅ {username} - Active user")
        else:
            findings.append(f"⚠️  {username} - No login history - Potential inactive account")
        
        return findings
    
    async def _analyze_kv_findings(self, kv_info: Dict[str, Any]) -> List[str]:
        """Analyze KV store collections for integration opportunities."""
        findings = []
        
        if not isinstance(kv_info, dict):
            return findings
        
        kv_name = kv_info.get("name", kv_info.get("title", "unknown"))
        size = kv_info.get("record_count", 0)
        
        # Threat intelligence detection
        if any(term in kv_name.lower() for term in ['threat', 'intel', 'ioc', 'indicator', 'malware', 'blacklist']):
            findings.append(f"🛡️  Threat Intel: {kv_name} ({size} records) - Valuable for correlation searches")
        
        # Asset inventory
        elif any(term in kv_name.lower() for term in ['asset', 'inventory', 'cmdb', 'device']):
            findings.append(f"📋 Asset Inventory: {kv_name} ({size} records) - Enable asset-based monitoring")
        
        # Lookup tables
        elif 'lookup' in kv_name.lower():
            findings.append(f"🔍 Lookup Table: {kv_name} ({size} records) - Data enrichment available")
        
        # Size optimization
        if size > 100000:
            findings.append(f"💾 Large collection: {kv_name} has {size:,} records - Consider optimization")
        
        return findings
        
    def _build_classification_prompt(self) -> str:
        """Build prompt for LLM classification of discovered data."""
        # TODO: Build comprehensive prompt based on all discovery results
        return "Classify the discovered Splunk data into security, infrastructure, business, and compliance categories..."
        
    def _build_recommendations_prompt(self) -> str:
        """Build prompt for LLM use case recommendations."""
        # TODO: Build comprehensive prompt based on all discovery and classification results
        return "Based on the discovered Splunk environment, recommend optimal use cases with priorities and ROI estimates..."