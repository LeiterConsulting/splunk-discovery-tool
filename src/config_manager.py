"""
Encrypted Configuration Manager
Handles secure storage of MCP and LLM credentials using Fernet encryption
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
from dataclasses import dataclass, asdict, field

from capabilities.models import CapabilityConfig

@dataclass
class MCPConfig:
    """MCP Server configuration"""
    url: str = "https://splunk:8089/services/mcp"
    token: str = ""
    verify_ssl: bool = False
    ca_bundle_path: Optional[str] = None

@dataclass
class LLMCredential:
    """Saved LLM credential configuration"""
    name: str
    provider: str
    api_key: str
    model: str
    endpoint_url: Optional[str] = None
    max_tokens: int = 16000
    temperature: float = 0.7

@dataclass
class MCPCredential:
    """Saved MCP server configuration"""
    name: str
    url: str
    token: str
    verify_ssl: bool = False
    ca_bundle_path: Optional[str] = None
    description: Optional[str] = None  # User-friendly description

@dataclass
class LLMConfig:
    """LLM configuration (active settings)"""
    provider: str = "openai"  # openai, azure, anthropic, gemini, custom
    api_key: str = ""
    model: str = "gpt-4o-mini"
    endpoint_url: Optional[str] = None
    max_tokens: int = 16000
    temperature: float = 0.7

@dataclass
class ServerConfig:
    """Web server configuration"""
    port: int = 8003
    host: str = "0.0.0.0"
    cors_origins: list = None
    trusted_hosts: list = None
    debug_mode: bool = False  # Enable debug logging to popup window
    
    def __post_init__(self):
        if self.cors_origins is None:
            self.cors_origins = ["*"]
        if self.trusted_hosts is None:
            self.trusted_hosts = ["*"]

@dataclass
class OIDCConfig:
    """OIDC provider settings for DT4SMS external authentication."""
    issuer_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    audience: Optional[str] = None
    scopes: list = field(default_factory=lambda: ["openid", "profile", "email"])
    username_claim: str = "preferred_username"
    email_claim: str = "email"
    role_claim: str = "roles"
    default_role: str = "viewer"
    mcp_assignment_claim: Optional[str] = None

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = ["openid", "profile", "email"]

@dataclass
class SecurityConfig:
    """Install-wide security feature toggles and defaults."""
    auth_enabled: bool = False
    auth_provider: str = "local_password"
    external_api_enabled: bool = False
    external_mcp_enabled: bool = False
    external_api_rate_limit_requests: int = 30
    external_api_rate_limit_window_seconds: int = 60
    external_mcp_rate_limit_requests: int = 30
    external_mcp_rate_limit_window_seconds: int = 60
    session_timeout_minutes: int = 480
    password_min_length: int = 12
    require_password_reset_on_first_login: bool = True
    oidc: OIDCConfig = field(default_factory=OIDCConfig)

    def __post_init__(self):
        if isinstance(self.oidc, dict):
            self.oidc = OIDCConfig(**self.oidc)
        elif self.oidc is None:
            self.oidc = OIDCConfig()

@dataclass
class AppConfig:
    """Complete application configuration"""
    mcp: MCPConfig
    llm: LLMConfig
    server: ServerConfig
    security: SecurityConfig = field(default_factory=SecurityConfig)
    saved_credentials: Dict[str, LLMCredential] = None  # name -> credential mapping
    saved_mcp_configs: Dict[str, MCPCredential] = None  # name -> MCP config mapping
    capabilities: Dict[str, CapabilityConfig] = field(default_factory=dict)
    active_credential_name: Optional[str] = None  # Currently active credential
    active_mcp_config_name: Optional[str] = None  # Currently active MCP config
    version: str = "1.0.0"
    
    def __post_init__(self):
        if self.security is None:
            self.security = SecurityConfig()
        if self.saved_credentials is None:
            self.saved_credentials = {}
        if self.saved_mcp_configs is None:
            self.saved_mcp_configs = {}
        if self.capabilities is None:
            self.capabilities = {}

class ConfigManager:
    """Manages encrypted configuration storage"""
    
    def __init__(self, config_path: str = "config.encrypted"):
        self.config_path = Path(config_path)
        self.key_path = Path(".config.key")
        self._key = None
        self._config = None
        
        # Initialize encryption key
        self._init_key()
        
        # Load or create default config
        if self.config_path.exists():
            self._config = self.load()
        else:
            self._config = self._create_default_config()
            self.save(self._config)
    
    def _init_key(self):
        """Initialize or load encryption key"""
        if self.key_path.exists():
            with open(self.key_path, 'rb') as f:
                self._key = f.read()
        else:
            self._key = Fernet.generate_key()
            with open(self.key_path, 'wb') as f:
                f.write(self._key)
            # Secure the key file (Unix only)
            try:
                if os.name != 'nt':  # Not Windows
                    os.chmod(self.key_path, 0o600)
            except Exception as chmod_error:
                print(f"Warning: Could not set file permissions: {chmod_error}")
    
    def _create_default_config(self) -> AppConfig:
        """Create default configuration"""
        return AppConfig(
            mcp=MCPConfig(),
            llm=LLMConfig(),
            server=ServerConfig(),
            security=SecurityConfig(),
        )
    
    def _encrypt(self, data: Dict[str, Any]) -> bytes:
        """Encrypt configuration data"""
        fernet = Fernet(self._key)
        json_data = json.dumps(data).encode()
        return fernet.encrypt(json_data)
    
    def _decrypt(self, encrypted_data: bytes) -> Dict[str, Any]:
        """Decrypt configuration data"""
        fernet = Fernet(self._key)
        decrypted_data = fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    
    def load(self) -> AppConfig:
        """Load and decrypt configuration"""
        try:
            with open(self.config_path, 'rb') as f:
                encrypted_data = f.read()
            
            config_dict = self._decrypt(encrypted_data)
            
            # Reconstruct AppConfig from dict
            mcp = MCPConfig(**config_dict.get('mcp', {}))
            llm = LLMConfig(**config_dict.get('llm', {}))
            server = ServerConfig(**config_dict.get('server', {}))
            security = SecurityConfig(**config_dict.get('security', {}))
            
            # Reconstruct saved credentials
            saved_creds_dict = config_dict.get('saved_credentials', {})
            saved_credentials = {
                name: LLMCredential(**cred_data) 
                for name, cred_data in saved_creds_dict.items()
            }
            
            # Reconstruct saved MCP configs
            saved_mcp_dict = config_dict.get('saved_mcp_configs', {})
            saved_mcp_configs = {
                name: MCPCredential(**mcp_data)
                for name, mcp_data in saved_mcp_dict.items()
            }

            saved_capabilities_dict = config_dict.get('capabilities', {})
            capabilities = {
                name: CapabilityConfig(**capability_data)
                for name, capability_data in saved_capabilities_dict.items()
            }
            
            return AppConfig(
                mcp=mcp,
                llm=llm,
                server=server,
                security=security,
                saved_credentials=saved_credentials,
                saved_mcp_configs=saved_mcp_configs,
                capabilities=capabilities,
                active_credential_name=config_dict.get('active_credential_name'),
                active_mcp_config_name=config_dict.get('active_mcp_config_name'),
                version=config_dict.get('version', '1.0.0')
            )
        except Exception as e:
            print(f"Error loading config: {e}")
            return self._create_default_config()
    
    def save(self, config: AppConfig):
        """Encrypt and save configuration"""
        try:
            # Convert to dict
            saved_creds_dict = {
                name: asdict(cred) 
                for name, cred in config.saved_credentials.items()
            }
            
            saved_mcp_dict = {
                name: asdict(mcp_config)
                for name, mcp_config in config.saved_mcp_configs.items()
            }

            saved_capabilities_dict = {
                name: asdict(capability)
                for name, capability in config.capabilities.items()
            }
            
            config_dict = {
                'mcp': asdict(config.mcp),
                'llm': asdict(config.llm),
                'server': asdict(config.server),
                'security': asdict(config.security),
                'saved_credentials': saved_creds_dict,
                'saved_mcp_configs': saved_mcp_dict,
                'capabilities': saved_capabilities_dict,
                'active_credential_name': config.active_credential_name,
                'active_mcp_config_name': config.active_mcp_config_name,
                'version': config.version
            }
            
            # Encrypt and save
            encrypted_data = self._encrypt(config_dict)
            with open(self.config_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Secure the config file (Unix only)
            try:
                if os.name != 'nt':  # Not Windows
                    os.chmod(self.config_path, 0o600)
            except Exception as chmod_error:
                print(f"Warning: Could not set file permissions: {chmod_error}")
            
            self._config = config
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get(self) -> AppConfig:
        """Get current configuration"""
        return self._config
    
    def update_mcp(self, **kwargs) -> bool:
        """Update MCP configuration"""
        for key, value in kwargs.items():
            if hasattr(self._config.mcp, key):
                setattr(self._config.mcp, key, value)
        return self.save(self._config)
    
    def update_llm(self, **kwargs) -> bool:
        """Update LLM configuration"""
        for key, value in kwargs.items():
            if hasattr(self._config.llm, key):
                setattr(self._config.llm, key, value)
        return self.save(self._config)
    
    def update_server(self, **kwargs) -> bool:
        """Update server configuration"""
        for key, value in kwargs.items():
            if hasattr(self._config.server, key):
                setattr(self._config.server, key, value)
        return self.save(self._config)

    def update_security(self, **kwargs) -> bool:
        """Update install-wide security configuration."""
        for key, value in kwargs.items():
            if key == 'oidc':
                current_oidc = self._config.security.oidc if isinstance(self._config.security.oidc, OIDCConfig) else OIDCConfig()
                merged_oidc = asdict(current_oidc)
                incoming_oidc = asdict(value) if isinstance(value, OIDCConfig) else dict(value or {}) if isinstance(value, dict) else {}
                allowed_fields = set(OIDCConfig.__dataclass_fields__.keys())
                for oidc_key, oidc_value in incoming_oidc.items():
                    if oidc_key not in allowed_fields:
                        continue
                    if oidc_key == 'client_secret' and str(oidc_value or '').strip() in {'', '***'}:
                        continue
                    merged_oidc[oidc_key] = oidc_value
                self._config.security.oidc = OIDCConfig(**merged_oidc)
                continue
            if hasattr(self._config.security, key):
                setattr(self._config.security, key, value)
        return self.save(self._config)

    def get_capability(self, name: str) -> Optional[CapabilityConfig]:
        """Get a saved capability state by name."""
        return self._config.capabilities.get(name)

    def list_capabilities(self) -> Dict[str, CapabilityConfig]:
        """List saved capability state."""
        return self._config.capabilities.copy()

    def save_capability(self, capability: CapabilityConfig) -> bool:
        """Save one capability state entry."""
        self._config.capabilities[capability.name] = capability
        return self.save(self._config)

    def update_capability(self, name: str, **kwargs) -> bool:
        """Update a capability state record."""
        capability = self.get_capability(name)
        if capability is None:
            return False

        for key, value in kwargs.items():
            if key == 'config' and isinstance(value, dict):
                merged = dict(capability.config)
                merged.update(value)
                capability.config = merged
                continue
            if hasattr(capability, key):
                setattr(capability, key, value)
        return self.save(self._config)
    
    # Credential Vault Management
    def save_credential(self, name: str, provider: str, api_key: str, model: str, 
                       endpoint_url: Optional[str] = None, max_tokens: int = 16000, 
                       temperature: float = 0.7) -> bool:
        """Save a named LLM credential"""
        credential = LLMCredential(
            name=name,
            provider=provider,
            api_key=api_key,
            model=model,
            endpoint_url=endpoint_url,
            max_tokens=max_tokens,
            temperature=temperature
        )
        self._config.saved_credentials[name] = credential
        return self.save(self._config)
    
    def get_credential(self, name: str) -> Optional[LLMCredential]:
        """Get a saved credential by name"""
        return self._config.saved_credentials.get(name)
    
    def list_credentials(self) -> Dict[str, LLMCredential]:
        """List all saved credentials"""
        return self._config.saved_credentials.copy()
    
    def delete_credential(self, name: str) -> bool:
        """Delete a saved credential"""
        if name in self._config.saved_credentials:
            del self._config.saved_credentials[name]
            # Clear active credential if it's the one being deleted
            if self._config.active_credential_name == name:
                self._config.active_credential_name = None
            return self.save(self._config)
        return False
    
    def load_credential(self, name: str) -> bool:
        """Load a saved credential into active LLM config"""
        credential = self.get_credential(name)
        if credential:
            self._config.llm.provider = credential.provider
            self._config.llm.api_key = credential.api_key
            self._config.llm.model = credential.model
            self._config.llm.endpoint_url = credential.endpoint_url
            self._config.llm.max_tokens = credential.max_tokens
            self._config.llm.temperature = credential.temperature
            self._config.active_credential_name = name  # Track active credential
            return self.save(self._config)
        return False
    
    def export_safe(self) -> Dict[str, Any]:
        """Export configuration with sensitive data masked"""
        config = self.get()
        
        # Export saved credentials with masked API keys
        safe_creds = {}
        for name, cred in config.saved_credentials.items():
            safe_creds[name] = {
                'name': cred.name,
                'provider': cred.provider,
                'api_key': '***' if cred.api_key else '',
                'model': cred.model,
                'endpoint_url': cred.endpoint_url,
                'max_tokens': cred.max_tokens,
                'temperature': cred.temperature
            }
        
        # Export saved MCP configs with masked tokens
        safe_mcp_configs = {}
        for name, mcp_config in config.saved_mcp_configs.items():
            safe_mcp_configs[name] = {
                'name': mcp_config.name,
                'url': mcp_config.url,
                'token': '***' if mcp_config.token else '',
                'verify_ssl': mcp_config.verify_ssl,
                'ca_bundle_path': mcp_config.ca_bundle_path,
                'description': mcp_config.description
            }

        safe_capabilities = {
            name: asdict(capability)
            for name, capability in config.capabilities.items()
        }
        
        return {
            'mcp': {
                'url': config.mcp.url,
                'token': '***' if config.mcp.token else '',
                'verify_ssl': config.mcp.verify_ssl,
                'ca_bundle_path': config.mcp.ca_bundle_path
            },
            'llm': {
                'provider': config.llm.provider,
                'api_key': '***' if config.llm.api_key else '',
                'model': config.llm.model,
                'endpoint_url': config.llm.endpoint_url,
                'max_tokens': config.llm.max_tokens,
                'temperature': config.llm.temperature
            },
            'saved_credentials': safe_creds,
            'saved_mcp_configs': safe_mcp_configs,
            'capabilities': safe_capabilities,
            'active_credential_name': config.active_credential_name,
            'active_mcp_config_name': config.active_mcp_config_name,
            'server': {
                'port': config.server.port,
                'host': config.server.host,
                'cors_origins': config.server.cors_origins,
                'trusted_hosts': config.server.trusted_hosts,
                'debug_mode': config.server.debug_mode,
            },
            'security': {
                'auth_enabled': config.security.auth_enabled,
                'auth_provider': config.security.auth_provider,
                'external_api_enabled': config.security.external_api_enabled,
                'external_mcp_enabled': config.security.external_mcp_enabled,
                'external_api_rate_limit_requests': config.security.external_api_rate_limit_requests,
                'external_api_rate_limit_window_seconds': config.security.external_api_rate_limit_window_seconds,
                'external_mcp_rate_limit_requests': config.security.external_mcp_rate_limit_requests,
                'external_mcp_rate_limit_window_seconds': config.security.external_mcp_rate_limit_window_seconds,
                'session_timeout_minutes': config.security.session_timeout_minutes,
                'password_min_length': config.security.password_min_length,
                'require_password_reset_on_first_login': config.security.require_password_reset_on_first_login,
                'oidc': {
                    'issuer_url': config.security.oidc.issuer_url,
                    'client_id': config.security.oidc.client_id,
                    'client_secret': '***' if config.security.oidc.client_secret else '',
                    'client_secret_configured': bool(config.security.oidc.client_secret),
                    'audience': config.security.oidc.audience,
                    'scopes': list(config.security.oidc.scopes or []),
                    'username_claim': config.security.oidc.username_claim,
                    'email_claim': config.security.oidc.email_claim,
                    'role_claim': config.security.oidc.role_claim,
                    'default_role': config.security.oidc.default_role,
                    'mcp_assignment_claim': config.security.oidc.mcp_assignment_claim,
                },
            },
            'version': config.version
        }
    
    # MCP Configuration Vault Management
    def save_mcp_config(self, name: str, url: str, token: str, 
                       verify_ssl: bool = False, ca_bundle_path: Optional[str] = None,
                       description: Optional[str] = None) -> bool:
        """Save a named MCP configuration"""
        mcp_config = MCPCredential(
            name=name,
            url=url,
            token=token,
            verify_ssl=verify_ssl,
            ca_bundle_path=ca_bundle_path,
            description=description
        )
        self._config.saved_mcp_configs[name] = mcp_config
        return self.save(self._config)
    
    def get_mcp_config(self, name: str) -> Optional[MCPCredential]:
        """Get a saved MCP configuration by name"""
        return self._config.saved_mcp_configs.get(name)
    
    def list_mcp_configs(self) -> Dict[str, MCPCredential]:
        """List all saved MCP configurations"""
        return self._config.saved_mcp_configs.copy()
    
    def delete_mcp_config(self, name: str) -> bool:
        """Delete a saved MCP configuration"""
        if name in self._config.saved_mcp_configs:
            del self._config.saved_mcp_configs[name]
            # Clear active config if it's the one being deleted
            if self._config.active_mcp_config_name == name:
                self._config.active_mcp_config_name = None
            return self.save(self._config)
        return False
    
    def load_mcp_config(self, name: str) -> bool:
        """Load a saved MCP configuration into active MCP config"""
        mcp_config = self.get_mcp_config(name)
        if mcp_config:
            self._config.mcp.url = mcp_config.url
            self._config.mcp.token = mcp_config.token
            self._config.mcp.verify_ssl = mcp_config.verify_ssl
            self._config.mcp.ca_bundle_path = mcp_config.ca_bundle_path
            self._config.active_mcp_config_name = name  # Track active config
            return self.save(self._config)
        return False
