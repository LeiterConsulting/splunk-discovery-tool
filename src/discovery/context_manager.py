"""
Smart Discovery Context Manager

Provides lazy-loading and intelligent context retrieval for Splunk discovery data.
Reduces memory overhead and improves LLM performance by loading only relevant context.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class DiscoveryContextManager:
    """Manages discovery context with lazy loading and caching."""
    
    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("output")
        self._discovery_file: Optional[Path] = None
        self._discovery_data: Optional[Dict] = None
        self._metadata: Optional[Dict] = None
        self._cached_contexts: Dict[str, Any] = {}
        self._file_mtime: Optional[float] = None
        
    def get_latest_discovery_file(self) -> Optional[Path]:
        """Find the most recent discovery export file."""
        if not self.output_dir.exists():
            return None
            
        discovery_files = sorted(
            self.output_dir.glob("discovery_export_*.json"), 
            reverse=True
        )
        return discovery_files[0] if discovery_files else None
    
    def _load_discovery_data(self, force_reload: bool = False) -> bool:
        """Load discovery data into memory. Returns True if successful."""
        discovery_file = self.get_latest_discovery_file()
        
        if not discovery_file:
            logger.warning("No discovery file found")
            return False
        
        # Check if we need to reload
        current_mtime = discovery_file.stat().st_mtime
        if not force_reload and self._discovery_data and self._file_mtime == current_mtime:
            return True  # Already loaded and up-to-date
        
        try:
            with open(discovery_file, 'r', encoding='utf-8') as f:
                self._discovery_data = json.load(f)
                self._discovery_file = discovery_file
                self._file_mtime = current_mtime
                self._cached_contexts.clear()  # Clear cache on reload
                logger.info(f"Loaded discovery data from {discovery_file.name}")
                return True
        except Exception as e:
            logger.error(f"Failed to load discovery data: {e}")
            return False
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get lightweight metadata about available discovery data."""
        if self._metadata:
            return self._metadata
        
        discovery_file = self.get_latest_discovery_file()
        if not discovery_file:
            return {
                "available": False,
                "message": "No discovery data found. Run a discovery first."
            }
        
        # Parse timestamp from filename
        timestamp_str = discovery_file.stem.replace('discovery_export_', '')
        try:
            discovery_datetime = datetime.strptime(timestamp_str, '%Y%m%d_%H%M%S')
            age_seconds = (datetime.now() - discovery_datetime).total_seconds()
            age_days = int(age_seconds / 86400)
        except ValueError:
            age_days = 0
        
        # Load just overview data for metadata
        if not self._load_discovery_data():
            return {"available": False, "message": "Failed to load discovery data"}
        
        overview = self._discovery_data.get('overview', {})
        
        self._metadata = {
            "available": True,
            "timestamp": timestamp_str,
            "age_days": age_days,
            "age_warning": age_days > 7,
            "overview": {
                "splunk_version": overview.get('splunk_version', 'unknown'),
                "total_indexes": overview.get('total_indexes', 0),
                "total_sourcetypes": overview.get('total_sourcetypes', 0),
                "total_hosts": overview.get('total_hosts', 0),
                "total_sources": overview.get('total_sources', 0),
                "total_users": overview.get('total_users', 0),
                "data_volume_24h": overview.get('data_volume_24h', 'unknown'),
                "license_state": overview.get('license_state', 'unknown')
            }
        }
        
        return self._metadata
    
    def get_context_for_query(self, user_query: str) -> Dict[str, Any]:
        """
        Analyze user query and return relevant discovery context.
        
        Returns dict with sections like: {'indexes': [...], 'sourcetypes': [...]}
        """
        if not self._load_discovery_data():
            return {}
        
        query_lower = user_query.lower()
        context = {}
        
        # Detect what user is asking about
        if any(term in query_lower for term in ['index', 'indexes', 'indices', 'idx']):
            context['indexes'] = self._get_index_context()
        
        if any(term in query_lower for term in ['sourcetype', 'source type', 'data type', 'log type']):
            context['sourcetypes'] = self._get_sourcetype_context()
        
        if any(term in query_lower for term in ['host', 'hosts', 'server', 'servers', 'machine']):
            context['hosts'] = self._get_host_context()
        
        if any(term in query_lower for term in ['alert', 'alerts', 'correlation', 'correlations', 'saved search']):
            context['alerts'] = self._get_alert_context()
        
        if any(term in query_lower for term in ['dashboard', 'dashboards', 'visualization']):
            context['dashboards'] = self._get_dashboard_context()
        
        if any(term in query_lower for term in ['user', 'users', 'account', 'accounts', 'permission', 'role']):
            context['users'] = self._get_user_context()
        
        if any(term in query_lower for term in ['lookup', 'lookups', 'kv store', 'collection']):
            context['kv_collections'] = self._get_kv_context()
        
        return context
    
    def get_specific_context(self, context_type: str) -> Any:
        """Get a specific type of context (indexes, hosts, etc.)."""
        if not self._load_discovery_data():
            return None
        
        context_methods = {
            'indexes': self._get_index_context,
            'sourcetypes': self._get_sourcetype_context,
            'hosts': self._get_host_context,
            'alerts': self._get_alert_context,
            'dashboards': self._get_dashboard_context,
            'users': self._get_user_context,
            'kv_collections': self._get_kv_context,
            'overview': lambda: self._discovery_data.get('overview', {})
        }
        
        method = context_methods.get(context_type.lower())
        if method:
            return method()
        return None
    
    def _get_index_context(self) -> List[Dict]:
        """Get index information from discovery data."""
        if 'indexes' in self._cached_contexts:
            return self._cached_contexts['indexes']
        
        indexes = []
        results = self._discovery_data.get('discovery_results', [])
        
        for result in results:
            if isinstance(result, dict) and 'data' in result:
                data = result['data']
                if isinstance(data, dict) and 'title' in data:
                    index_name = data['title']
                    is_disabled = data.get('disabled') == '1'
                    
                    if not is_disabled:
                        indexes.append({
                            'name': index_name,
                            'events': int(data.get('totalEventCount', 0)),
                            'size_mb': float(data.get('currentDBSizeMB', 0)),
                            'datatype': data.get('datatype', 'event'),
                            'max_time': data.get('maxTime', ''),
                            'min_time': data.get('minTime', '')
                        })
        
        # Sort by event count
        indexes.sort(key=lambda x: x['events'], reverse=True)
        self._cached_contexts['indexes'] = indexes[:20]  # Top 20
        return self._cached_contexts['indexes']
    
    def _get_sourcetype_context(self) -> List[Dict]:
        """Get sourcetype information."""
        if 'sourcetypes' in self._cached_contexts:
            return self._cached_contexts['sourcetypes']
        
        # Try to get from notable_patterns first
        overview = self._discovery_data.get('overview', {})
        if 'notable_patterns' in overview:
            try:
                patterns_list = overview['notable_patterns']
                if patterns_list:
                    patterns_str = patterns_list[0]
                    if isinstance(patterns_str, dict):
                        patterns_data = patterns_str
                    else:
                        patterns_data = json.loads(patterns_str)
                    
                    if 'patterns' in patterns_data:
                        for pattern in patterns_data['patterns']:
                            if 'source_types_characteristics' in pattern:
                                st_info = pattern['source_types_characteristics']
                                self._cached_contexts['sourcetypes'] = {
                                    'total': st_info.get('total_source_types', 0),
                                    'active': st_info.get('active_source_types', 0),
                                    'most_active': st_info.get('most_active_source_type', {})
                                }
                                return self._cached_contexts['sourcetypes']
            except:
                pass
        
        # Fallback: minimal info
        self._cached_contexts['sourcetypes'] = {
            'total': overview.get('total_sourcetypes', 'unknown'),
            'note': 'Run metadata query for detailed sourcetype list'
        }
        return self._cached_contexts['sourcetypes']
    
    def _get_host_context(self) -> List[Dict]:
        """Get host information."""
        if 'hosts' in self._cached_contexts:
            return self._cached_contexts['hosts']
        
        hosts = []
        results = self._discovery_data.get('discovery_results', [])
        
        for result in results:
            if isinstance(result, dict) and 'description' in result:
                if 'Analyzing host:' in result.get('description', ''):
                    data = result.get('data', {})
                    if isinstance(data, dict) and 'host' in data:
                        event_count = int(data.get('totalCount', 0))
                        if event_count > 0:
                            hosts.append({
                                'name': data['host'],
                                'events': event_count
                            })
        
        hosts.sort(key=lambda x: x['events'], reverse=True)
        self._cached_contexts['hosts'] = hosts[:20]  # Top 20
        return self._cached_contexts['hosts']
    
    def _get_alert_context(self) -> List[Dict]:
        """Get alert information."""
        if 'alerts' in self._cached_contexts:
            return self._cached_contexts['alerts']
        
        alerts = []
        results = self._discovery_data.get('discovery_results', [])
        
        for result in results:
            if isinstance(result, dict) and 'description' in result:
                if 'Analyzing alerts:' in result.get('description', ''):
                    data = result.get('data', {})
                    if isinstance(data, dict) and data.get('disabled', '0') != '1':
                        alerts.append({
                            'name': data.get('name', data.get('title', '')),
                            'severity': data.get('alert.severity', 'medium'),
                            'cron': data.get('cron_schedule', '')
                        })
        
        self._cached_contexts['alerts'] = alerts[:15]  # Top 15
        return self._cached_contexts['alerts']
    
    def _get_dashboard_context(self) -> List[str]:
        """Get dashboard names."""
        if 'dashboards' in self._cached_contexts:
            return self._cached_contexts['dashboards']
        
        dashboards = []
        results = self._discovery_data.get('discovery_results', [])
        
        for result in results:
            if isinstance(result, dict) and 'description' in result:
                if 'Analyzing dashboards:' in result.get('description', ''):
                    data = result.get('data', {})
                    if isinstance(data, dict):
                        name = data.get('name', data.get('title', ''))
                        if name:
                            dashboards.append(name)
        
        self._cached_contexts['dashboards'] = dashboards[:15]
        return self._cached_contexts['dashboards']
    
    def _get_user_context(self) -> Dict[str, Any]:
        """Get user information."""
        if 'users' in self._cached_contexts:
            return self._cached_contexts['users']
        
        admin_users = []
        total_users = 0
        results = self._discovery_data.get('discovery_results', [])
        
        for result in results:
            if isinstance(result, dict) and 'description' in result:
                if 'Analyzing user:' in result.get('description', ''):
                    total_users += 1
                    data = result.get('data', {})
                    if isinstance(data, dict):
                        roles = data.get('roles', [])
                        if isinstance(roles, str):
                            roles = [r.strip() for r in roles.split(",")]
                        if 'admin' in roles:
                            admin_users.append(data.get('name', 'unknown'))
        
        self._cached_contexts['users'] = {
            'total': total_users,
            'admins': len(admin_users),
            'admin_list': admin_users[:5] if len(admin_users) <= 5 else f"{len(admin_users)} admin accounts"
        }
        return self._cached_contexts['users']
    
    def _get_kv_context(self) -> Dict[str, Any]:
        """Get KV Store collection information."""
        if 'kv_collections' in self._cached_contexts:
            return self._cached_contexts['kv_collections']
        
        threat_intel = []
        asset_collections = []
        total_kv = 0
        results = self._discovery_data.get('discovery_results', [])
        
        for result in results:
            if isinstance(result, dict) and 'description' in result:
                if 'Analyzing KV collection:' in result.get('description', ''):
                    total_kv += 1
                    data = result.get('data', {})
                    if isinstance(data, dict):
                        kv_name = data.get('name', data.get('title', ''))
                        if any(term in kv_name.lower() for term in ['threat', 'intel', 'ioc', 'malware']):
                            threat_intel.append(kv_name)
                        elif any(term in kv_name.lower() for term in ['asset', 'inventory', 'cmdb']):
                            asset_collections.append(kv_name)
        
        self._cached_contexts['kv_collections'] = {
            'total': total_kv,
            'threat_intel': threat_intel[:5],
            'asset_collections': asset_collections[:5]
        }
        return self._cached_contexts['kv_collections']
    
    def format_context_for_llm(self, context: Dict[str, Any]) -> str:
        """Format context data into a readable string for LLM."""
        if not context:
            return ""
        
        lines = ["🔍 RELEVANT DISCOVERY CONTEXT:"]
        
        if 'indexes' in context:
            lines.append("\n📁 Active Indexes:")
            for idx in context['indexes'][:10]:
                lines.append(f"  - {idx['name']}: {idx['events']:,} events, {idx['size_mb']:.1f}MB")
        
        if 'sourcetypes' in context:
            st_info = context['sourcetypes']
            lines.append(f"\n📋 Sourcetypes: {st_info.get('total', 'unknown')} total, {st_info.get('active', 'unknown')} active")
            if 'most_active' in st_info:
                ma = st_info['most_active']
                lines.append(f"  Most Active: {ma.get('sourcetype', 'unknown')} ({ma.get('total_count', 0)} events)")
        
        if 'hosts' in context:
            lines.append(f"\n🖥️  Active Hosts (top {min(10, len(context['hosts']))}):")
            for host in context['hosts'][:10]:
                lines.append(f"  - {host['name']}: {host['events']:,} events")
        
        if 'alerts' in context:
            lines.append(f"\n🚨 Alerts ({len(context['alerts'])} configured):")
            for alert in context['alerts'][:5]:
                lines.append(f"  - {alert['name']} (severity: {alert['severity']})")
        
        if 'dashboards' in context:
            lines.append(f"\n📊 Dashboards ({len(context['dashboards'])} available):")
            for dash in context['dashboards'][:5]:
                lines.append(f"  - {dash}")
        
        if 'users' in context:
            user_info = context['users']
            lines.append(f"\n👥 Users: {user_info['total']} total, {user_info['admins']} admins")
        
        if 'kv_collections' in context:
            kv_info = context['kv_collections']
            lines.append(f"\n🗄️  KV Store: {kv_info['total']} collections")
            if kv_info.get('threat_intel'):
                lines.append(f"  Threat Intel: {', '.join(kv_info['threat_intel'][:3])}")
        
        return "\n".join(lines)
    
    def get_context_after_tool_call(self, tool_name: str, tool_args: Dict, tool_result: Dict) -> str:
        """
        Provide relevant discovery context after a tool execution.
        Helps LLM interpret results by giving additional environment context.
        """
        if not self._load_discovery_data():
            return ""
        
        context_lines = []
        
        if tool_name == 'run_splunk_query':
            query = tool_args.get('query', '')
            
            # Extract index from query
            index_match = re.search(r'index=(\w+)', query)
            if index_match:
                index_name = index_match.group(1)
                indexes = self._get_index_context()
                index_info = next((idx for idx in indexes if idx['name'] == index_name), None)
                if index_info:
                    context_lines.append(f"📍 Context: {index_name} has {index_info['events']:,} total events, {index_info['size_mb']:.1f}MB")
            
            # Check for sourcetype
            sourcetype_match = re.search(r'sourcetype=(\w+)', query)
            if sourcetype_match:
                sourcetype_name = sourcetype_match.group(1)
                context_lines.append(f"📋 Searching sourcetype: {sourcetype_name}")
        
        elif tool_name == 'get_indexes':
            indexes = self._get_index_context()
            context_lines.append(f"📁 Total indexes with data: {len(indexes)}")
        
        elif tool_name == 'get_metadata':
            metadata_type = tool_args.get('type', '')
            if metadata_type == 'hosts':
                hosts = self._get_host_context()
                context_lines.append(f"🖥️  Top active hosts: {', '.join([h['name'] for h in hosts[:5]])}")
        
        return "\n".join(context_lines) if context_lines else ""


# Global instance for the application
_context_manager: Optional[DiscoveryContextManager] = None

def get_context_manager() -> DiscoveryContextManager:
    """Get or create the global context manager instance."""
    global _context_manager
    if _context_manager is None:
        _context_manager = DiscoveryContextManager()
    return _context_manager
