"""Registry of known optional capabilities."""

from typing import Dict, List, Optional

from capabilities.models import CapabilityDefinition


KNOWN_CAPABILITIES: Dict[str, CapabilityDefinition] = {
    "rag_local": CapabilityDefinition(
        name="rag_local",
        title="Local Artifact Search",
        category="rag",
        description="Quick search across recent DT4SMS discovery outputs stored locally.",
        install_method="internal",
        default_config={
            "source_dir": "output",
            "max_files": 8,
            "max_scan_chars": 12000,
            "max_block_chars": 420,
            "allowed_extensions": [".md", ".txt", ".json"],
        },
        runtime_available=True,
        requires_restart_on_install=False,
        enabled_by_default=False,
        priority=10,
        maturity="foundation",
    ),
    "rag_chromadb": CapabilityDefinition(
        name="rag_chromadb",
        title="Indexed Artifact Search",
        category="rag",
        description="Indexed artifact search for larger discovery histories and faster lookups.",
        install_method="pip",
        dependency_packages=["chromadb"],
        module_probes=["chromadb"],
        default_config={
            "source_dir": "output",
            "allowed_extensions": [".md", ".txt", ".json"],
            "storage_dir": "output/rag/chromadb",
            "collection_prefix": "dt4sms",
            "max_files": 24,
            "max_scan_chars": 16000,
            "max_document_chars": 1800,
            "max_documents": 80,
            "max_sections_per_file": 8,
        },
        runtime_available=True,
        requires_restart_on_install=True,
        enabled_by_default=False,
        priority=20,
        maturity="phase4",
    ),
    "splunk_deeplink_tools": CapabilityDefinition(
        name="splunk_deeplink_tools",
        title="Splunk Deeplink Tools",
        category="tool_pack",
        description="Deep link generation for investigations and operator pivots.",
        install_method="internal",
        default_config={
            "web_base_url": "",
            "default_app": "search",
            "default_earliest": "-24h",
            "default_latest": "now",
        },
        runtime_available=True,
        requires_restart_on_install=False,
        enabled_by_default=False,
        priority=30,
        maturity="phase5",
    ),
    "visualization_tools": CapabilityDefinition(
        name="visualization_tools",
        title="Visualization Tools",
        category="tool_pack",
        description="Charting and visual artifact generation from Splunk results.",
        install_method="internal",
        default_config={
            "preview_enabled": True,
            "max_preview_points": 8,
        },
        runtime_available=True,
        requires_restart_on_install=False,
        enabled_by_default=False,
        priority=40,
        maturity="phase5",
    ),
    "export_tools": CapabilityDefinition(
        name="export_tools",
        title="Export Tools",
        category="tool_pack",
        description="Create report packages for reports and presentations.",
        install_method="internal",
        default_config={
            "source_dir": "output",
            "export_dir": "output/exports",
            "formats": ["bundle_zip", "manifest_json", "summary_markdown"],
            "max_bundle_files": 12,
        },
        runtime_available=True,
        requires_restart_on_install=False,
        enabled_by_default=False,
        priority=50,
        maturity="phase5",
    ),
}


class CapabilityRegistry:
    """Read-only registry for supported capabilities."""

    def __init__(self, definitions: Optional[Dict[str, CapabilityDefinition]] = None):
        self._definitions = dict(definitions or KNOWN_CAPABILITIES)

    def list_definitions(self) -> List[CapabilityDefinition]:
        return sorted(self._definitions.values(), key=lambda item: (item.category, item.priority, item.name))

    def get_definition(self, name: str) -> Optional[CapabilityDefinition]:
        return self._definitions.get(name)

    def has_definition(self, name: str) -> bool:
        return name in self._definitions

    def rag_definitions(self) -> List[CapabilityDefinition]:
        return [definition for definition in self.list_definitions() if definition.category == "rag"]
