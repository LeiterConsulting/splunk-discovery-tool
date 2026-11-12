"""
Encrypted Configuration Manager
Handles secure storage of MCP and LLM credentials using Fernet encryption
"""

import copy
import json
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Any, Optional, Tuple
from cryptography.fernet import Fernet
from dataclasses import dataclass, asdict, field

from capabilities.models import CapabilityConfig


MASKED_SECRET = "***"


def is_unset_secret(value: Any) -> bool:
    """Blank values and the mask the API hands to the browser both mean "keep the stored secret"."""
    return str(value or "").strip() in {"", MASKED_SECRET}


def clean_secret(value: Any) -> str:
    """Drop whitespace and a pasted "Bearer " prefix; HTTP clients reject header values with stray whitespace."""
    cleaned = str(value or "").strip()
    if cleaned[:7].lower() == "bearer ":
        cleaned = cleaned[7:].strip()
    return cleaned


def _same_endpoint(left: Any, right: Any) -> bool:
    return str(left or "").strip().rstrip("/").lower() == str(right or "").strip().rstrip("/").lower()


def _known_fields(dataclass_type, values: Any) -> Dict[str, Any]:
    """Keep only keys the dataclass defines, so configs written by other versions still load."""
    if not isinstance(values, dict):
        return {}
    allowed = set(getattr(dataclass_type, '__dataclass_fields__', {}).keys())
    return {key: value for key, value in values.items() if key in allowed}

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
    auto_tune: bool = True
    context_window: int = 0  # 0 = derive from the model profile
    request_timeout: int = 0  # seconds; 0 = derive from the model profile
    reasoning_effort: str = ""  # "", "low", "medium", or "high"

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
    provider: str = "openai"  # openai, azure, anthropic, gemini, ollama, custom
    api_key: str = ""
    model: str = "gpt-4o-mini"
    endpoint_url: Optional[str] = None
    max_tokens: int = 16000
    temperature: float = 0.7
    # When auto_tune is on, the app picks output budget, temperature, context, and
    # timeouts from the model profile; max_tokens and temperature apply only when off.
    auto_tune: bool = True
    context_window: int = 0  # 0 = derive from the model profile
    request_timeout: int = 0  # seconds; 0 = derive from the model profile
    reasoning_effort: str = ""  # "", "low", "medium", or "high"

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
    """OIDC provider settings for Splunk Discovery Tool external authentication."""
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
class LibraryConfig:
    """Knowledge library settings. Online sources stay off until an admin turns them on."""
    allow_online_sources: bool = False

@dataclass
class AppConfig:
    """Complete application configuration"""
    mcp: MCPConfig
    llm: LLMConfig
    server: ServerConfig
    security: SecurityConfig = field(default_factory=SecurityConfig)
    library: LibraryConfig = field(default_factory=LibraryConfig)
    saved_credentials: Dict[str, LLMCredential] = None  # name -> credential mapping
    saved_mcp_configs: Dict[str, MCPCredential] = None  # name -> MCP config mapping
    capabilities: Dict[str, CapabilityConfig] = field(default_factory=dict)
    active_credential_name: Optional[str] = None  # Currently active credential
    active_mcp_config_name: Optional[str] = None  # Currently active MCP config
    version: str = "1.0.0"
    
    def __post_init__(self):
        if self.security is None:
            self.security = SecurityConfig()
        if self.library is None:
            self.library = LibraryConfig()
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
        self.last_save_error: Optional[str] = None
        
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
            mcp = MCPConfig(**_known_fields(MCPConfig, config_dict.get('mcp', {})))
            llm = LLMConfig(**_known_fields(LLMConfig, config_dict.get('llm', {})))
            server = ServerConfig(**_known_fields(ServerConfig, config_dict.get('server', {})))
            security = SecurityConfig(**_known_fields(SecurityConfig, config_dict.get('security', {})))
            library = LibraryConfig(**_known_fields(LibraryConfig, config_dict.get('library', {})))
            
            # Reconstruct saved credentials
            saved_creds_dict = config_dict.get('saved_credentials', {})
            saved_credentials = {
                name: LLMCredential(**_known_fields(LLMCredential, cred_data))
                for name, cred_data in saved_creds_dict.items()
            }
            
            # Reconstruct saved MCP configs
            saved_mcp_dict = config_dict.get('saved_mcp_configs', {})
            saved_mcp_configs = {
                name: MCPCredential(**_known_fields(MCPCredential, mcp_data))
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
                library=library,
                saved_credentials=saved_credentials,
                saved_mcp_configs=saved_mcp_configs,
                capabilities=capabilities,
                active_credential_name=config_dict.get('active_credential_name'),
                active_mcp_config_name=config_dict.get('active_mcp_config_name'),
                version=config_dict.get('version', '1.0.0')
            )
        except Exception as e:
            print(f"Error loading config: {e}")
            self._preserve_unreadable_config()
            return self._create_default_config()

    def _preserve_unreadable_config(self) -> None:
        """Keep a copy of a config that cannot be decrypted so the next save does not destroy it."""
        try:
            if not self.config_path.exists():
                return
            stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
            backup_path = self.config_path.with_name(f"{self.config_path.name}.corrupted-{stamp}")
            if not backup_path.exists():
                shutil.copy2(self.config_path, backup_path)
                print(f"Unreadable config preserved at {backup_path} (check that {self.key_path} matches it)")
        except Exception as backup_error:
            print(f"Warning: Could not preserve unreadable config: {backup_error}")

    def _write_config_bytes(self, data: bytes) -> None:
        target = self.config_path
        directory = target.parent if str(target.parent) else Path(".")
        fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(directory))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.replace(temp_name, target)
                return
            except OSError:
                # Windows can refuse the rename while another process holds the file open.
                with open(target, "wb") as handle:
                    handle.write(data)
        finally:
            if os.path.exists(temp_name):
                try:
                    os.unlink(temp_name)
                except OSError:
                    pass
    
    @staticmethod
    def _config_to_dict(config: AppConfig) -> Dict[str, Any]:
        return {
            'mcp': asdict(config.mcp),
            'llm': asdict(config.llm),
            'server': asdict(config.server),
            'security': asdict(config.security),
            'library': asdict(config.library),
            'saved_credentials': {name: asdict(cred) for name, cred in config.saved_credentials.items()},
            'saved_mcp_configs': {name: asdict(mcp_config) for name, mcp_config in config.saved_mcp_configs.items()},
            'capabilities': {name: asdict(capability) for name, capability in config.capabilities.items()},
            'active_credential_name': config.active_credential_name,
            'active_mcp_config_name': config.active_mcp_config_name,
            'version': config.version
        }

    def probe_save(self, apply: Optional[Callable[[AppConfig], None]] = None) -> Dict[str, Any]:
        """Run the save pipeline on a copy of the config without replacing the config file.

        The encrypted result goes to a temporary file next to the config file, is read back
        and decrypted, then removed. Raises whatever a real save would raise.
        """
        candidate = copy.deepcopy(self._config)
        if apply is not None:
            apply(candidate)
        config_dict = self._config_to_dict(candidate)
        encrypted_data = self._encrypt(config_dict)
        directory = self.config_path.parent if str(self.config_path.parent) else Path(".")
        fd, temp_name = tempfile.mkstemp(prefix=f".{self.config_path.name}.probe.", suffix=".tmp", dir=str(directory))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(encrypted_data)
                handle.flush()
                os.fsync(handle.fileno())
            with open(temp_name, "rb") as handle:
                round_trip = self._decrypt(handle.read())
            if round_trip != json.loads(json.dumps(config_dict)):
                raise ValueError("The settings read back from the test file did not match what was written")
        finally:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
        return {"bytes": len(encrypted_data), "directory": str(directory.resolve())}

    def save(self, config: AppConfig):
        """Encrypt and save configuration"""
        try:
            encrypted_data = self._encrypt(self._config_to_dict(config))
            self._write_config_bytes(encrypted_data)
            
            # Secure the config file (Unix only)
            try:
                if os.name != 'nt':  # Not Windows
                    os.chmod(self.config_path, 0o600)
            except Exception as chmod_error:
                print(f"Warning: Could not set file permissions: {chmod_error}")
            
            self._config = config
            self.last_save_error = None
            return True
        except Exception as e:
            self.last_save_error = f"{type(e).__name__}: {e} (config file: {self.config_path.resolve()})"
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
            if key == 'token':
                if str(value or '').strip() == MASKED_SECRET:
                    continue
                value = clean_secret(value)
            if hasattr(self._config.mcp, key):
                setattr(self._config.mcp, key, value)
        return self.save(self._config)
    
    def update_llm(self, **kwargs) -> bool:
        """Update LLM configuration"""
        for key, value in kwargs.items():
            if key == 'api_key':
                if str(value or '').strip() == MASKED_SECRET:
                    continue
                value = clean_secret(value)
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

    def update_library(self, **kwargs) -> bool:
        """Update knowledge library settings."""
        for key, value in kwargs.items():
            if hasattr(self._config.library, key):
                setattr(self._config.library, key, value)
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
                       temperature: float = 0.7, auto_tune: bool = True,
                       context_window: int = 0, request_timeout: int = 0,
                       reasoning_effort: str = "", activate: bool = False) -> bool:
        """Save a named LLM credential.

        A blank or masked api_key keeps the key already stored under this name, or the
        active key when the credential points at the same provider and endpoint.
        """
        name = str(name or "").strip()
        if not name:
            self.last_save_error = "Credential name is required"
            return False
        if is_unset_secret(api_key):
            api_key = self.resolve_llm_api_key(name, provider, endpoint_url)
        api_key = clean_secret(api_key)
        credential = LLMCredential(
            name=name,
            provider=provider,
            api_key=api_key,
            model=model,
            endpoint_url=endpoint_url,
            max_tokens=max_tokens,
            temperature=temperature,
            auto_tune=bool(auto_tune),
            context_window=int(context_window or 0),
            request_timeout=int(request_timeout or 0),
            reasoning_effort=str(reasoning_effort or ""),
        )
        self._config.saved_credentials[name] = credential
        if activate:
            self._apply_llm_credential(name, credential)
        return self.save(self._config)

    def resolve_llm_api_key(self, name: Optional[str], provider: Any, endpoint_url: Any) -> str:
        return self.resolve_llm_api_key_with_source(name, provider, endpoint_url)[0]

    def resolve_llm_api_key_with_source(self, name: Optional[str], provider: Any, endpoint_url: Any) -> Tuple[str, str]:
        """Return the key to use for a blank/masked entry and where it came from ("saved", "active", or "")."""
        existing = self._config.saved_credentials.get(str(name or "").strip())
        if existing is not None and not is_unset_secret(existing.api_key):
            return existing.api_key, "saved"
        active = self._config.llm
        if (
            str(provider or "").strip().lower() == str(active.provider or "").strip().lower()
            and _same_endpoint(endpoint_url, active.endpoint_url)
            and not is_unset_secret(active.api_key)
        ):
            return active.api_key, "active"
        return "", ""

    def _apply_llm_credential(self, name: str, credential: LLMCredential) -> None:
        self._config.llm.provider = credential.provider
        self._config.llm.api_key = "" if is_unset_secret(credential.api_key) else credential.api_key
        self._config.llm.model = credential.model
        self._config.llm.endpoint_url = credential.endpoint_url
        self._config.llm.max_tokens = credential.max_tokens
        self._config.llm.temperature = credential.temperature
        self._config.llm.auto_tune = credential.auto_tune
        self._config.llm.context_window = credential.context_window
        self._config.llm.request_timeout = credential.request_timeout
        self._config.llm.reasoning_effort = credential.reasoning_effort
        self._config.active_credential_name = name
    
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
            self._apply_llm_credential(name, credential)
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
                'api_key': '' if is_unset_secret(cred.api_key) else MASKED_SECRET,
                'model': cred.model,
                'endpoint_url': cred.endpoint_url,
                'max_tokens': cred.max_tokens,
                'temperature': cred.temperature,
                'auto_tune': cred.auto_tune,
                'context_window': cred.context_window,
                'request_timeout': cred.request_timeout,
                'reasoning_effort': cred.reasoning_effort,
            }
        
        # Export saved MCP configs with masked tokens
        safe_mcp_configs = {}
        for name, mcp_config in config.saved_mcp_configs.items():
            safe_mcp_configs[name] = {
                'name': mcp_config.name,
                'url': mcp_config.url,
                'token': '' if is_unset_secret(mcp_config.token) else MASKED_SECRET,
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
                'token': '' if is_unset_secret(config.mcp.token) else MASKED_SECRET,
                'verify_ssl': config.mcp.verify_ssl,
                'ca_bundle_path': config.mcp.ca_bundle_path
            },
            'llm': {
                'provider': config.llm.provider,
                'api_key': '' if is_unset_secret(config.llm.api_key) else MASKED_SECRET,
                'model': config.llm.model,
                'endpoint_url': config.llm.endpoint_url,
                'max_tokens': config.llm.max_tokens,
                'temperature': config.llm.temperature,
                'auto_tune': config.llm.auto_tune,
                'context_window': config.llm.context_window,
                'request_timeout': config.llm.request_timeout,
                'reasoning_effort': config.llm.reasoning_effort,
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
                       description: Optional[str] = None, activate: bool = False) -> bool:
        """Save a named MCP configuration.

        A blank or masked token keeps the token already stored under this name, or the
        active token when the profile points at the active server URL.
        """
        name = str(name or "").strip()
        if not name:
            self.last_save_error = "MCP configuration name is required"
            return False
        if is_unset_secret(token):
            token = self.resolve_mcp_token(name, url)
        token = clean_secret(token)
        mcp_config = MCPCredential(
            name=name,
            url=url,
            token=token,
            verify_ssl=verify_ssl,
            ca_bundle_path=ca_bundle_path,
            description=description
        )
        self._config.saved_mcp_configs[name] = mcp_config
        if activate:
            self._apply_mcp_profile(name, mcp_config)
        return self.save(self._config)

    def resolve_mcp_token(self, name: Optional[str], url: Any) -> str:
        return self.resolve_mcp_token_with_source(name, url)[0]

    def resolve_mcp_token_with_source(self, name: Optional[str], url: Any) -> Tuple[str, str]:
        """Return the token to use for a blank/masked entry and where it came from ("saved", "active", or "")."""
        existing = self._config.saved_mcp_configs.get(str(name or "").strip())
        if existing is not None and not is_unset_secret(existing.token):
            return existing.token, "saved"
        active = self._config.mcp
        if _same_endpoint(url, active.url) and not is_unset_secret(active.token):
            return active.token, "active"
        return "", ""

    def _apply_mcp_profile(self, name: str, mcp_config: MCPCredential) -> None:
        self._config.mcp.url = mcp_config.url
        self._config.mcp.token = "" if is_unset_secret(mcp_config.token) else mcp_config.token
        self._config.mcp.verify_ssl = mcp_config.verify_ssl
        self._config.mcp.ca_bundle_path = mcp_config.ca_bundle_path
        self._config.active_mcp_config_name = name
    
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
            self._apply_mcp_profile(name, mcp_config)
            return self.save(self._config)
        return False
