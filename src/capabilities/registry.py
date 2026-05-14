"""Registry of known optional capabilities."""

from typing import Dict, List, Optional

from capabilities.models import CapabilityDefinition


KNOWN_CAPABILITIES: Dict[str, CapabilityDefinition] = {
    "rag_local": CapabilityDefinition(
        name="rag_local",
        title="Local Artifact Search",
        category="rag",
        description="Quick search across recent DT4SMS discovery outputs stored locally.",
        purpose="Provide lightweight local retrieval over recent discovery outputs without requiring an external index service.",
        intent="Help operators quickly reference generated artifacts and reports during active investigation or follow-on questioning.",
        capability_set=[
            "Search recent discovery reports, summaries, and runbooks stored in the local output workspace.",
            "Extract short context snippets from matching files for assistant follow-up questions.",
            "Operate with bundled application logic and no additional runtime services.",
        ],
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
        description="Indexed artifact search plus managed knowledge assets for context-rich retrieval.",
        purpose="Provide indexed retrieval and managed knowledge assets for deeper, reusable operator context.",
        intent="Support context-rich investigations where generated artifacts alone are not enough and the assistant needs indexed history, documentation, and operator-authored context.",
        capability_set=[
            "Index discovery artifacts into persistent retrieval storage for higher-recall context assembly.",
            "Manage imported knowledge assets such as runbooks, reference notes, and connected-system context.",
            "Preview the exact context chunks retrieval will assemble before using them in chat.",
        ],
        install_method="pip",
        dependency_packages=["chromadb"],
        module_probes=["chromadb"],
        default_config={
            "source_dir": "output",
            "allowed_extensions": [".md", ".txt", ".json"],
            "storage_dir": "output/rag/chromadb",
            "asset_dir": "",
            "collection_prefix": "dt4sms",
            "max_files": 24,
            "max_scan_chars": 16000,
            "max_document_chars": 1800,
            "max_documents": 80,
            "max_sections_per_file": 8,
            "auto_reindex_on_asset_change": True,
            "context_preview_limit": 4,
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
        purpose="Generate direct Splunk Web links that turn assistant output into an operator handoff path.",
        intent="Reduce friction between analysis in DT4SMS and action in Splunk by making searches easy to open, validate, and share.",
        capability_set=[
            "Build deep links for SPL searches with app and time-range controls.",
            "Expose open-in-Splunk actions from assistant query responses and capability tools.",
            "Resolve and validate the target Splunk Web base URL used for pivots.",
        ],
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
        purpose="Turn chartable query results into visual previews that are easier to scan than raw tables.",
        intent="Improve operator comprehension when a trend, breakdown, or aggregate is better understood visually than text-only output.",
        capability_set=[
            "Render inline preview charts for supported query results.",
            "Support common operational chart types such as line and bar views.",
            "Control preview limits and supported result-shape handling.",
        ],
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
        purpose="Package discovery outputs into reusable report bundles for handoff, review, and presentations.",
        intent="Give operators a fast way to collect the current session narrative, artifacts, and supporting files into a portable deliverable.",
        capability_set=[
            "Build downloadable report packages from discovery outputs and runbook content.",
            "Emit manifest and summary-note artifacts alongside bundle exports.",
            "Track available sessions and recently generated packages inside the app.",
        ],
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
