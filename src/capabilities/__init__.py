"""Capability framework for optional Splunk Discovery Tool features."""

from capabilities.health import CapabilityHealthService
from capabilities.install_manager import CapabilityManager
from capabilities.registry import CapabilityRegistry

__all__ = [
    "CapabilityHealthService",
    "CapabilityManager",
    "CapabilityRegistry",
]
