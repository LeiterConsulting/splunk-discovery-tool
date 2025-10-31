"""
Encrypted Configuration Manager
Handles secure storage of MCP and LLM credentials using Fernet encryption
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
from dataclasses import dataclass, asdict

@dataclass
class MCPConfig:
    """MCP Server configuration"""
    url: str = "https://splunk:8089/services/mcp"
    token: str = ""
    verify_ssl: bool = False
    ca_bundle_path: Optional[str] = None

@dataclass
class LLMConfig:
    """LLM configuration"""
    provider: str = "openai"  # openai, custom
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
class AppConfig:
    """Complete application configuration"""
    mcp: MCPConfig
    llm: LLMConfig
    server: ServerConfig
    version: str = "1.0.0"

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
            server=ServerConfig()
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
            
            return AppConfig(
                mcp=mcp,
                llm=llm,
                server=server,
                version=config_dict.get('version', '1.0.0')
            )
        except Exception as e:
            print(f"Error loading config: {e}")
            return self._create_default_config()
    
    def save(self, config: AppConfig):
        """Encrypt and save configuration"""
        try:
            # Convert to dict
            config_dict = {
                'mcp': asdict(config.mcp),
                'llm': asdict(config.llm),
                'server': asdict(config.server),
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
    
    def export_safe(self) -> Dict[str, Any]:
        """Export configuration with sensitive data masked"""
        config = self.get()
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
            'server': {
                'port': config.server.port,
                'host': config.server.host,
                'cors_origins': config.server.cors_origins,
                'trusted_hosts': config.server.trusted_hosts
            },
            'version': config.version
        }
