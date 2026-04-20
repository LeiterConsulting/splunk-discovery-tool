"""Shared models for optional capability packs."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CapabilityDefinition:
    """Static definition for a known capability pack."""

    name: str
    title: str
    category: str
    description: str
    install_method: str = "internal"
    dependency_packages: List[str] = field(default_factory=list)
    module_probes: List[str] = field(default_factory=list)
    default_config: Dict[str, Any] = field(default_factory=dict)
    runtime_available: bool = True
    requires_restart_on_install: bool = False
    enabled_by_default: bool = False
    priority: int = 100
    maturity: str = "foundation"


@dataclass
class CapabilityConfig:
    """Persistent config and state for a capability pack."""

    name: str
    installed: bool = False
    enabled: bool = False
    version: Optional[str] = None
    install_method: str = "internal"
    health_status: str = "not_installed"
    health_message: str = "Capability is not installed."
    config: Dict[str, Any] = field(default_factory=dict)
    last_tested_at: Optional[str] = None
    last_error: Optional[str] = None
    restart_required: bool = False
    installed_at: Optional[str] = None


@dataclass
class CapabilityHealthReport:
    """Normalized health payload returned by capability checks."""

    name: str
    status: str
    message: str
    checked_at: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "checked_at": self.checked_at,
            "details": dict(self.details),
        }


@dataclass
class CapabilityActionResult:
    """Result payload for install/enable/disable/test actions."""

    ok: bool
    capability: str
    action: str
    message: str
    state: Optional[Dict[str, Any]] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "ok": self.ok,
            "capability": self.capability,
            "action": self.action,
            "message": self.message,
            "details": dict(self.details),
        }
        if self.state is not None:
            payload["state"] = dict(self.state)
        return payload
