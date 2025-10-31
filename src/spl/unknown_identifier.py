"""
Unknown Data Identifier - Detects ambiguous data sources and generates contextual questions.
"""

from typing import Dict, List, Any
from collections import defaultdict


class UnknownDataIdentifier:
    """Identify and generate questions about unknown/ambiguous data sources."""
    
    # Known EXACT patterns for indexes and sourcetypes (must match fully)
    KNOWN_INDEX_EXACT = {
        'main', '_internal', '_audit', '_introspection', '_telemetry',
        '_thefishbucket', '_configtracker', 'summary', 'history'
    }
    
    # Known partial patterns (must be complete word boundaries)
    KNOWN_INDEX_PATTERNS = {
        'wineventlog', 'security', 'firewall', 'network', 'web',
        'linux', 'unix', 'windows', 'sysmon', 'endpoint'
    }
    
    KNOWN_SOURCETYPE_EXACT = {
        'access_combined', 'access_common', 'linux_secure', 'syslog',
        'vmstat', 'iostat', 'cpu', 'df', 'ps', 'top', 'netstat',
        'interfaces', 'protocol', 'openports'
    }
    
    # Known vendor prefixes (require exact prefix match)
    KNOWN_SOURCETYPE_PREFIXES = {
        'WinEventLog:', 'XmlWinEventLog:',
        'cisco:', 'cisco_', 
        'paloalto:', 'pan:',
        'fortinet:', 'fgt_',
        'aws:', 'aws_',
        'azure:', 'azure_',
        'gcp:', 'google:',
        'linux:', 'unix:',
        'json', 'xml', 'csv', 'kv'
    }
    
    def __init__(self, discovery_results: List[Any]):
        self.discovery_results = discovery_results
        
    def identify_unknown_items(self) -> List[Dict[str, Any]]:
        """Find data sources that don't match known patterns AND low-confidence items."""
        unknown = []
        
        for result in self.discovery_results:
            # Handle both dict and object formats
            if isinstance(result, dict):
                data = result
            else:
                data = result.data if hasattr(result, 'data') else result
            
            # Check indexes
            if 'title' in data and 'currentDBSizeMB' in data:
                index_name = data.get('title', '')
                if not self._is_known_index(index_name):
                    size_mb = float(data.get('currentDBSizeMB', 0))
                    events = int(data.get('totalEventCount', 0))
                    
                    # Only flag if it has significant data OR is completely unknown
                    confidence = self._calculate_confidence(index_name, 'index')
                    if (size_mb > 1 or events > 100) or confidence < 30:
                        unknown.append({
                            "type": "index",
                            "name": index_name,
                            "size_mb": size_mb,
                            "events": events,
                            "confidence": confidence
                        })
            
            # Check sourcetypes
            elif 'sourcetype' in data and 'totalCount' in data:
                st_name = data.get('sourcetype', '')
                if not self._is_known_sourcetype(st_name):
                    events = int(data.get('totalCount', 0))
                    
                    # Only flag if it has significant data OR is completely unknown
                    confidence = self._calculate_confidence(st_name, 'sourcetype')
                    if (events > 100) or confidence < 30:
                        unknown.append({
                            "type": "sourcetype",
                            "name": st_name,
                            "events": events,
                            "confidence": confidence
                        })
        
        # ALWAYS return items for user validation
        # Sort by confidence (lowest first - most unknown)
        unknown.sort(key=lambda x: x['confidence'])
        
        # If we have fewer than 5 unknowns, add some "low confidence known" items
        if len(unknown) < 5:
            additional = self._find_least_confident_items(5 - len(unknown))
            unknown.extend(additional)
        
        # Return top 10 for user review (even if "known", users can validate)
        return unknown[:10]
    
    def _is_known_index(self, index_name: str) -> bool:
        """Check if index matches known patterns with EXACT matching."""
        name_lower = index_name.lower()
        
        # Internal indexes (exact underscore prefix)
        if name_lower.startswith('_'):
            return True
        
        # Exact matches
        if name_lower in self.KNOWN_INDEX_EXACT:
            return True
        
        # Partial patterns (must match as complete word/component)
        for pattern in self.KNOWN_INDEX_PATTERNS:
            # Must be the entire word or a clear component (separated by _, -, etc.)
            if name_lower == pattern:
                return True
            # Check if it's a compound word like "security_logs" (security is known)
            if name_lower.startswith(pattern + '_') or name_lower.startswith(pattern + '-'):
                return True
            if name_lower.endswith('_' + pattern) or name_lower.endswith('-' + pattern):
                return True
            if f'_{pattern}_' in name_lower or f'-{pattern}-' in name_lower:
                return True
        
        return False
    
    def _is_known_sourcetype(self, sourcetype: str) -> bool:
        """Check if sourcetype matches known patterns with EXACT matching."""
        st_lower = sourcetype.lower()
        
        # Exact matches
        if st_lower in self.KNOWN_SOURCETYPE_EXACT:
            return True
        
        # Vendor prefixes (must match from start)
        for prefix in self.KNOWN_SOURCETYPE_PREFIXES:
            if sourcetype.startswith(prefix):  # Case-sensitive for prefixes like "WinEventLog:"
                return True
            if st_lower.startswith(prefix.lower()):  # Also check lowercase
                return True
        
        return False
    
    def _find_least_confident_items(self, count: int) -> List[Dict[str, Any]]:
        """Find items that are 'known' but have low confidence for user validation."""
        all_items = []
        
        for result in self.discovery_results:
            if isinstance(result, dict):
                data = result
            else:
                data = result.data if hasattr(result, 'data') else result
            
            # Check indexes
            if 'title' in data and 'currentDBSizeMB' in data:
                index_name = data.get('title', '')
                confidence = self._calculate_confidence(index_name, 'index')
                size_mb = float(data.get('currentDBSizeMB', 0))
                events = int(data.get('totalEventCount', 0))
                
                if (size_mb > 1 or events > 100) and confidence < 70:
                    all_items.append({
                        "type": "index",
                        "name": index_name,
                        "size_mb": size_mb,
                        "events": events,
                        "confidence": confidence
                    })
            
            # Check sourcetypes
            elif 'sourcetype' in data and 'totalCount' in data:
                st_name = data.get('sourcetype', '')
                confidence = self._calculate_confidence(st_name, 'sourcetype')
                events = int(data.get('totalCount', 0))
                
                if events > 100 and confidence < 70:
                    all_items.append({
                        "type": "sourcetype",
                        "name": st_name,
                        "events": events,
                        "confidence": confidence
                    })
        
        # Sort by confidence and return lowest
        all_items.sort(key=lambda x: x['confidence'])
        return all_items[:count]
    
    def _calculate_confidence(self, name: str, item_type: str) -> float:
        """Calculate confidence score (0-100, higher = more confident we know it)."""
        confidence = 0
        name_lower = name.lower()
        
        # Common technology keywords increase confidence
        tech_keywords = [
            'windows', 'linux', 'unix', 'cisco', 'apache', 'nginx', 'sql',
            'database', 'web', 'api', 'log', 'metric', 'event', 'syslog',
            'firewall', 'network', 'security', 'auth', 'access'
        ]
        
        for keyword in tech_keywords:
            if keyword in name_lower:
                confidence += 30
        
        # Structure hints
        if ':' in name:  # Colon suggests structured naming
            confidence += 20
        if '_' in name:  # Underscore suggests deliberate naming
            confidence += 10
        
        # Length (very short or very long names are suspicious)
        if 3 <= len(name) <= 30:
            confidence += 10
        
        return min(confidence, 100)
    
    def generate_contextual_questions(self, unknown_items: List[Dict]) -> List[Dict[str, Any]]:
        """Generate smart questions about unknown data sources."""
        questions = []
        
        for item in unknown_items:
            question_data = {
                "type": item['type'],
                "name": item['name'],
                "question": self._generate_question(item),
                "suggestions": self._generate_suggestions(item),
                "context": self._extract_context(item)
            }
            questions.append(question_data)
        
        return questions
    
    def _generate_question(self, item: Dict) -> str:
        """Generate contextual question based on item characteristics."""
        name = item['name']
        item_type = item['type']
        name_lower = name.lower()
        
        if item_type == 'index':
            # Application-related
            if any(term in name_lower for term in ['app', 'application', 'svc', 'service']):
                return f"I found an index called '{name}' that appears to contain application data. What type of application is this?"
            
            # Business/custom
            elif any(term in name_lower for term in ['custom', 'prod', 'dev', 'test']):
                return f"The index '{name}' seems to be a custom index. What business function or team owns this data?"
            
            # Generic
            else:
                return f"I'm not familiar with the '{name}' index. Can you help me understand what data it contains?"
        
        else:  # sourcetype
            # Custom format
            if ':' in name and not any(known in name_lower for known in ['win', 'linux', 'cisco']):
                return f"I found a custom sourcetype '{name}'. What system or application generates this data?"
            
            # Generic
            else:
                return f"The sourcetype '{name}' is not in my knowledge base. What kind of data does this represent?"
    
    def _generate_suggestions(self, item: Dict) -> List[Dict[str, str]]:
        """Generate intelligent suggestions based on name patterns."""
        name_lower = item['name'].lower()
        
        # Application patterns
        if any(term in name_lower for term in ['app', 'application', 'service', 'svc', 'api']):
            return [
                {
                    "value": "web_application",
                    "label": "Web Application",
                    "description": "User-facing web application logs (HTTP requests, user sessions)"
                },
                {
                    "value": "api_service",
                    "label": "API/Microservice",
                    "description": "Backend API or microservice logs (REST, GraphQL, RPC)"
                },
                {
                    "value": "business_application",
                    "label": "Business Application",
                    "description": "Enterprise app (CRM, ERP, HR system, custom LOB app)"
                },
                {
                    "value": "middleware",
                    "label": "Middleware/Integration",
                    "description": "Message queue, ESB, integration platform"
                }
            ]
        
        # Payment/Financial patterns
        elif any(term in name_lower for term in ['pay', 'payment', 'transaction', 'billing', 'invoice', 'financial', 'money']):
            return [
                {
                    "value": "payment_processing",
                    "label": "Payment Processing",
                    "description": "Credit card transactions, payment gateway logs"
                },
                {
                    "value": "e_commerce",
                    "label": "E-Commerce Platform",
                    "description": "Online shopping cart, order processing"
                },
                {
                    "value": "financial_transactions",
                    "label": "Financial Transactions",
                    "description": "Banking, money transfers, financial operations"
                },
                {
                    "value": "billing_invoicing",
                    "label": "Billing/Invoicing",
                    "description": "Invoice generation, billing cycles, subscription management"
                }
            ]
        
        # Database patterns
        elif any(term in name_lower for term in ['db', 'database', 'sql', 'mongo', 'oracle', 'postgres']):
            return [
                {
                    "value": "database_logs",
                    "label": "Database Logs",
                    "description": "Database query logs, slow queries, errors"
                },
                {
                    "value": "database_audit",
                    "label": "Database Audit",
                    "description": "Schema changes, user access, data modifications"
                },
                {
                    "value": "database_performance",
                    "label": "Database Performance",
                    "description": "Query performance, connection pools, cache stats"
                }
            ]
        
        # Security patterns
        elif any(term in name_lower for term in ['sec', 'security', 'auth', 'access', 'vpn', 'proxy']):
            return [
                {
                    "value": "authentication_logs",
                    "label": "Authentication Logs",
                    "description": "User login/logout, SSO, MFA events"
                },
                {
                    "value": "access_control",
                    "label": "Access Control",
                    "description": "Permission checks, authorization decisions"
                },
                {
                    "value": "security_device",
                    "label": "Security Device",
                    "description": "IDS/IPS, WAF, security appliance logs"
                },
                {
                    "value": "vpn_proxy",
                    "label": "VPN/Proxy",
                    "description": "Remote access, proxy server logs"
                }
            ]
        
        # IoT/Device patterns
        elif any(term in name_lower for term in ['iot', 'device', 'sensor', 'telemetry']):
            return [
                {
                    "value": "iot_devices",
                    "label": "IoT Devices",
                    "description": "Smart devices, sensors, connected hardware"
                },
                {
                    "value": "telemetry",
                    "label": "Telemetry Data",
                    "description": "Device metrics, health data, diagnostic info"
                },
                {
                    "value": "industrial_control",
                    "label": "Industrial Control",
                    "description": "SCADA, PLC, industrial automation"
                }
            ]
        
        # Default suggestions
        return [
            {
                "value": "application_logs",
                "label": "Application Logs",
                "description": "General application logging (errors, info, debug)"
            },
            {
                "value": "system_infrastructure",
                "label": "System/Infrastructure",
                "description": "OS, server, network infrastructure logs"
            },
            {
                "value": "security_compliance",
                "label": "Security/Compliance",
                "description": "Security events, audit logs, compliance data"
            },
            {
                "value": "business_analytics",
                "label": "Business/Analytics",
                "description": "Business metrics, KPIs, analytics data"
            },
            {
                "value": "custom_integration",
                "label": "Custom Integration",
                "description": "Third-party integration, vendor-specific data"
            }
        ]
    
    def _extract_context(self, item: Dict) -> Dict[str, Any]:
        """Extract contextual information about the item."""
        context = {
            "has_volume": item.get('events', 0) > 1000,
            "volume_category": self._categorize_volume(item.get('events', 0))
        }
        
        if item['type'] == 'index':
            context['has_significant_data'] = item.get('size_mb', 0) > 10
        
        return context
    
    def _categorize_volume(self, events: int) -> str:
        """Categorize event volume."""
        if events > 1000000:
            return "very_high"
        elif events > 100000:
            return "high"
        elif events > 10000:
            return "medium"
        elif events > 1000:
            return "low"
        else:
            return "very_low"
