"""Capability health probes and status normalization."""

import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from capabilities.models import CapabilityConfig, CapabilityDefinition, CapabilityHealthReport
from capabilities.rag.indexer import ArtifactSourceIndexer
from capabilities.tools import DeterministicExportProvider, SplunkDeepLinkProvider, VisualizationPreviewProvider


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CapabilityHealthService:
    """Evaluate capability availability and operational readiness."""

    def __init__(self, config_manager=None):
        self.config_manager = config_manager

    def check(self, definition: CapabilityDefinition, config: CapabilityConfig) -> CapabilityHealthReport:
        checked_at = _utc_now_iso()

        if not definition.runtime_available:
            return CapabilityHealthReport(
                name=definition.name,
                status="unavailable",
                message="Capability is registered but its runtime implementation is not available yet.",
                checked_at=checked_at,
                details={"maturity": definition.maturity},
            )

        if not config.installed:
            return CapabilityHealthReport(
                name=definition.name,
                status="not_installed",
                message="Capability is not installed.",
                checked_at=checked_at,
            )

        if config.restart_required:
            return CapabilityHealthReport(
                name=definition.name,
                status="restart-required",
                message="Capability changes require an application restart before use.",
                checked_at=checked_at,
            )

        if not config.enabled:
            return CapabilityHealthReport(
                name=definition.name,
                status="disabled",
                message="Capability is installed but disabled.",
                checked_at=checked_at,
            )

        missing_modules = self._missing_modules(definition)
        if missing_modules:
            return CapabilityHealthReport(
                name=definition.name,
                status="degraded",
                message="Capability dependencies are missing.",
                checked_at=checked_at,
                details={"missing_modules": missing_modules},
            )

        if definition.name == "rag_local":
            return self._check_rag_local(definition, config, checked_at)

        if definition.name == "rag_chromadb":
            return self._check_rag_chromadb(definition, config, checked_at)

        if definition.name == "splunk_deeplink_tools":
            return self._check_splunk_deeplink_tools(definition, config, checked_at)

        if definition.name == "visualization_tools":
            return self._check_visualization_tools(definition, config, checked_at)

        if definition.name == "export_tools":
            return self._check_export_tools(definition, config, checked_at)

        return CapabilityHealthReport(
            name=definition.name,
            status="ready",
            message="Capability is installed and ready.",
            checked_at=checked_at,
        )

    def _missing_modules(self, definition: CapabilityDefinition) -> List[str]:
        return [module_name for module_name in definition.module_probes if importlib.util.find_spec(module_name) is None]

    def _check_rag_local(
        self,
        definition: CapabilityDefinition,
        config: CapabilityConfig,
        checked_at: str,
    ) -> CapabilityHealthReport:
        source_dir = Path(str(config.config.get("source_dir") or definition.default_config.get("source_dir") or "output"))
        allowed_extensions = {
            str(extension).lower()
            for extension in (config.config.get("allowed_extensions") or definition.default_config.get("allowed_extensions") or [])
        }

        if not source_dir.exists():
            return CapabilityHealthReport(
                name=definition.name,
                status="degraded",
                message="Artifact source directory does not exist yet.",
                checked_at=checked_at,
                details={"source_dir": str(source_dir)},
            )

        file_count, sample_files = self._count_candidate_files(source_dir, allowed_extensions)
        if file_count <= 0:
            return CapabilityHealthReport(
                name=definition.name,
                status="degraded",
                message="Artifact source directory has no retrievable files yet.",
                checked_at=checked_at,
                details={
                    "source_dir": str(source_dir),
                    "allowed_extensions": sorted(allowed_extensions),
                },
            )

        return CapabilityHealthReport(
            name=definition.name,
            status="ready",
            message="Local artifact search is ready.",
            checked_at=checked_at,
            details={
                "source_dir": str(source_dir),
                "candidate_file_count": file_count,
                "sample_files": sample_files,
            },
        )

    def _check_rag_chromadb(
        self,
        definition: CapabilityDefinition,
        config: CapabilityConfig,
        checked_at: str,
    ) -> CapabilityHealthReport:
        indexer = ArtifactSourceIndexer(config=config, definition=definition)
        source_dir = indexer.get_source_dir()
        storage_dir = indexer.get_storage_dir()
        summary = indexer.get_index_summary()
        document_count = self._safe_positive_int(summary.get("document_count"), 0)

        if not source_dir.exists():
            return CapabilityHealthReport(
                name=definition.name,
                status="degraded",
                message="Configured source directory does not exist yet.",
                checked_at=checked_at,
                details={
                    "source_dir": str(source_dir),
                    "storage_dir": str(storage_dir),
                },
            )

        if not storage_dir.exists() or document_count <= 0:
            return CapabilityHealthReport(
                name=definition.name,
                status="degraded",
                message="Chroma index is empty. Run reindex after enabling the capability.",
                checked_at=checked_at,
                details={
                    "source_dir": str(source_dir),
                    "storage_dir": str(storage_dir),
                    "document_count": document_count,
                },
            )

        return CapabilityHealthReport(
            name=definition.name,
            status="ready",
            message="Indexed artifact search is ready.",
            checked_at=checked_at,
            details={
                "source_dir": str(source_dir),
                "storage_dir": str(storage_dir),
                "document_count": document_count,
                "source_file_count": self._safe_positive_int(summary.get("source_file_count"), 0),
                "source_type_counts": summary.get("source_type_counts", {}),
                "last_indexed_at": summary.get("last_indexed_at"),
                "sample_sources": summary.get("sample_sources", []),
            },
        )

    def _check_splunk_deeplink_tools(
        self,
        definition: CapabilityDefinition,
        config: CapabilityConfig,
        checked_at: str,
    ) -> CapabilityHealthReport:
        mcp_url = ""
        if self.config_manager is not None:
            try:
                mcp_url = str(self.config_manager.get().mcp.url or "").strip()
            except Exception:
                mcp_url = ""

        provider = SplunkDeepLinkProvider(config=config, definition=definition, mcp_url=mcp_url)
        base_url = provider.resolve_web_base_url()
        if not base_url:
            return CapabilityHealthReport(
                name=definition.name,
                status="degraded",
                message="Splunk Web base URL could not be resolved from capability config or MCP settings.",
                checked_at=checked_at,
                details=provider.get_runtime_summary(),
            )

        summary = provider.get_runtime_summary()
        return CapabilityHealthReport(
            name=definition.name,
            status="ready",
            message="Splunk deeplink generation is ready.",
            checked_at=checked_at,
            details=summary,
        )

    def _check_visualization_tools(
        self,
        definition: CapabilityDefinition,
        config: CapabilityConfig,
        checked_at: str,
    ) -> CapabilityHealthReport:
        provider = VisualizationPreviewProvider(config=config, definition=definition)
        summary = provider.get_runtime_summary()
        if not summary.get("preview_enabled"):
            return CapabilityHealthReport(
                name=definition.name,
                status="degraded",
                message="Visualization runtime is installed, but preview generation is disabled in capability config.",
                checked_at=checked_at,
                details=summary,
            )

        return CapabilityHealthReport(
            name=definition.name,
            status="ready",
            message="Visualization preview generation is ready.",
            checked_at=checked_at,
            details=summary,
        )

    def _check_export_tools(
        self,
        definition: CapabilityDefinition,
        config: CapabilityConfig,
        checked_at: str,
    ) -> CapabilityHealthReport:
        provider = DeterministicExportProvider(config=config, definition=definition)
        summary = provider.get_runtime_summary()
        output_dir = Path(str(summary.get("output_dir") or "output"))
        session_count = self._safe_positive_int(summary.get("available_session_count"), 0)

        if not output_dir.exists():
            return CapabilityHealthReport(
                name=definition.name,
                status="degraded",
                message="Export runtime is installed, but the output directory does not exist yet.",
                checked_at=checked_at,
                details=summary,
            )

        if session_count <= 0:
            return CapabilityHealthReport(
                name=definition.name,
                status="degraded",
                message="Export runtime is ready, but there are no discovery sessions to package yet.",
                checked_at=checked_at,
                details=summary,
            )

        return CapabilityHealthReport(
            name=definition.name,
            status="ready",
            message="Report package generation is ready.",
            checked_at=checked_at,
            details=summary,
        )

    def _count_candidate_files(self, source_dir: Path, allowed_extensions: set) -> Tuple[int, List[str]]:
        files = []
        for path in sorted(source_dir.glob("*")):
            if not path.is_file():
                continue
            if allowed_extensions and path.suffix.lower() not in allowed_extensions:
                continue
            files.append(path.name)
        return len(files), files[:5]

    def _safe_positive_int(self, value, default: int) -> int:
        try:
            parsed = int(value)
            return parsed if parsed >= 0 else default
        except (TypeError, ValueError):
            return default
