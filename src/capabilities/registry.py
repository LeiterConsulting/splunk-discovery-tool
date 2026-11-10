"""Registry of known optional capabilities."""

from typing import Dict, List, Optional

from capabilities.models import CapabilityDefinition


KNOWN_CAPABILITIES: Dict[str, CapabilityDefinition] = {
    "m26_14_advisor": CapabilityDefinition(
        name="m26_14_advisor",
        title="M-26-14 Readiness Advisor",
        category="advisor",
        description="Estimates readiness for OMB M-26-14 logging and network visibility rules. Advisory only, not an official assessment.",
        purpose="Combines discovery results and targeted live checks into an M-26-14 readiness estimate that shows its evidence.",
        intent="See how your Splunk data lines up with M-26-14, where the evidence is thin, and which checks to run next.",
        capability_set=[
            "Builds an M-26-14 readiness profile from saved discovery results.",
            "Offers ready-made SPL checks for retention, audit coverage, network visibility, privilege changes, and detection.",
            "Keeps discovery estimates separate from live check results and follow-up analysis.",
        ],
        install_method="internal",
        default_config={
            "output_dir": "output",
            "profile_cache_dir": "output/m26_14",
            "live_validation_limit": 6,
            "allow_bespoke_follow_up": True,
            "require_live_validation_confirmation": True,
            "default_validation_pack_ids": [
                "retention_and_searchability",
                "audit_and_admin_activity",
                "network_visibility_coverage",
                "privileged_change_monitoring",
            ],
        },
        runtime_available=True,
        requires_restart_on_install=False,
        enabled_by_default=False,
        priority=25,
        maturity="phase6",
    ),
    "rag_local": CapabilityDefinition(
        name="rag_local",
        title="Quick Report Search",
        category="rag",
        description="Searches your recent discovery reports on this machine. Needs no extra software.",
        purpose="Finds matching text in recent discovery reports without a separate search index.",
        intent="Lets chat answers quote your recent reports while you investigate.",
        capability_set=[
            "Searches recent discovery reports, summaries, and runbooks in the output folder.",
            "Pulls short passages from matching files into chat answers.",
            "Runs inside the app with no extra services.",
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
        title="Knowledge Base",
        category="rag",
        description="Indexes your reports and imported documents so the AI assistant can find relevant context.",
        purpose="Keeps a searchable index of your reports plus documents you import, such as runbooks and notes.",
        intent="Use it when reports alone are not enough and the assistant also needs history, documentation, or your own notes.",
        capability_set=[
            "Indexes discovery reports so chat can find more relevant passages.",
            "Stores documents you import, such as runbooks, reference notes, and system details.",
            "Shows which passages chat would use before you ask.",
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
        title="Splunk Search Links",
        category="tool_pack",
        description="Adds links that open searches directly in Splunk Web.",
        purpose="Builds Splunk Web links for searches the assistant suggests.",
        intent="Go from a finding here to the matching search in Splunk with one click, and share the link.",
        capability_set=[
            "Builds links for SPL searches with an app and time range.",
            "Adds Open in Splunk buttons to chat answers and saved searches.",
            "Finds and checks your Splunk Web address.",
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
        title="Charts",
        category="tool_pack",
        description="Shows charts for Splunk search results in chat.",
        purpose="Turns search results into charts that are easier to read than tables.",
        intent="Use it when a trend or breakdown is clearer as a chart than as text.",
        capability_set=[
            "Draws charts inside chat for supported results.",
            "Supports line and bar charts.",
            "Lets you limit how many points each chart shows.",
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
        title="Report Packages",
        category="tool_pack",
        description="Bundles discovery reports into a zip file you can download and share.",
        purpose="Packages discovery reports for handoff, review, and presentations.",
        intent="Collect a run's summary, reports, and supporting files into one download.",
        capability_set=[
            "Builds a zip of discovery reports and the runbook.",
            "Adds a file list and a summary note to each package.",
            "Lists available runs and recent packages in the app.",
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
