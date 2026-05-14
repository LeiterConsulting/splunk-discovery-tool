"""Capability install, state, and health orchestration."""

import re
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from importlib import metadata
from typing import Any, Dict, Optional

from capabilities.health import CapabilityHealthService
from capabilities.models import CapabilityActionResult, CapabilityConfig, CapabilityDefinition
from capabilities.rag.chromadb_provider import ChromaRAGProvider
from capabilities.rag.lightweight import LightweightRAGProvider
from capabilities.registry import CapabilityRegistry
from capabilities.tools import DeterministicExportProvider, SplunkDeepLinkProvider, VisualizationPreviewProvider


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"0", "false", "no", "off", ""}
    return bool(value)


class CapabilityManager:
    """Coordinate registry definitions with persisted config and health."""

    def __init__(self, config_manager, registry: Optional[CapabilityRegistry] = None, health_service: Optional[CapabilityHealthService] = None):
        self.config_manager = config_manager
        self.registry = registry or CapabilityRegistry()
        self.health_service = health_service or CapabilityHealthService(config_manager=self.config_manager)
        if getattr(self.health_service, "config_manager", None) is None:
            self.health_service.config_manager = self.config_manager
        self._bootstrap_known_capabilities()

    def refresh(self) -> None:
        """Re-apply registry defaults after the underlying config reloads."""
        self._bootstrap_known_capabilities()

    def _bootstrap_known_capabilities(self) -> None:
        changed = False
        for definition in self.registry.list_definitions():
            config = self.config_manager.get_capability(definition.name)
            if config is None:
                config = CapabilityConfig(
                    name=definition.name,
                    install_method=definition.install_method,
                    config=dict(definition.default_config),
                )
                self.config_manager._config.capabilities[definition.name] = config
                changed = True
                continue

            if config.install_method != definition.install_method:
                config.install_method = definition.install_method
                changed = True

            merged_config = dict(definition.default_config)
            merged_config.update(config.config or {})
            normalized_config = self._normalize_capability_config(definition, merged_config)
            if normalized_config != (config.config or {}):
                config.config = normalized_config
                changed = True

            if config.restart_required and definition.runtime_available and self._dependencies_available(definition):
                config.restart_required = False
                changed = True

            if not config.health_message:
                config.health_message = "Capability is not installed." if not config.installed else "Capability state not tested yet."
                changed = True

        if changed:
            self.config_manager.save(self.config_manager.get())

    def list_capabilities(self, refresh_health: bool = True) -> Dict[str, Dict[str, Any]]:
        capabilities = {}
        for definition in self.registry.list_definitions():
            capabilities[definition.name] = self.get_capability_state(definition.name, refresh_health=refresh_health)
        return capabilities

    def get_summary(self) -> Dict[str, int]:
        capabilities = list(self.list_capabilities().values())
        return {
            "total": len(capabilities),
            "installed": sum(1 for item in capabilities if item.get("installed")),
            "enabled": sum(1 for item in capabilities if item.get("enabled")),
            "ready": sum(1 for item in capabilities if item.get("health_status") == "ready"),
            "restart_required": sum(1 for item in capabilities if item.get("restart_required")),
        }

    def get_capability_state(self, name: str, refresh_health: bool = False) -> Dict[str, Any]:
        definition = self.registry.get_definition(name)
        if definition is None:
            raise KeyError(name)
        config = self._get_or_create_config(definition)
        if refresh_health:
            self._sync_health_state(definition, config)
        payload = asdict(config)
        payload.update(
            {
                "title": definition.title,
                "category": definition.category,
                "description": definition.description,
                "purpose": definition.purpose,
                "intent": definition.intent,
                "capability_set": list(definition.capability_set),
                "dependency_packages": list(definition.dependency_packages),
                "runtime_available": definition.runtime_available,
                "requires_restart_on_install": definition.requires_restart_on_install,
                "maturity": definition.maturity,
            }
        )
        payload.update(self._extra_capability_state(definition, config))
        return payload

    def install_capability(self, name: str) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "install", "Unknown capability.")
        config = self._get_or_create_config(definition)

        if not definition.runtime_available and definition.install_method == "internal":
            return self._result(definition.name, "install", False, "Capability runtime is not implemented yet.")

        if config.installed and not config.restart_required:
            return self._result(definition.name, "install", True, "Capability is already installed.")

        if definition.install_method == "internal":
            config.installed = True
            config.version = config.version or "bundled"
            config.installed_at = config.installed_at or _utc_now_iso()
            config.restart_required = False
            config.last_error = None
            config.health_status = "disabled"
            config.health_message = "Capability is installed but disabled."
            self.config_manager.save_capability(config)
            return self._result(definition.name, "install", True, "Capability installed.")

        if not definition.runtime_available:
            return self._result(definition.name, "install", False, "Capability runtime is not implemented yet.")

        return self._install_python_capability(definition, config)

    def enable_capability(self, name: str) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "enable", "Unknown capability.")
        config = self._get_or_create_config(definition)

        if not config.installed:
            return self._result(definition.name, "enable", False, "Install the capability before enabling it.")
        if config.restart_required:
            return self._result(definition.name, "enable", False, "Restart the application before enabling this capability.")
        if not definition.runtime_available:
            return self._result(definition.name, "enable", False, "Capability runtime is not implemented yet.")

        config.enabled = True
        report = self._sync_health_state(definition, config)
        message = report.message if report.status == "ready" else f"Capability enabled. {report.message}"
        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="enable",
            message=message,
            state=self.get_capability_state(definition.name),
            details=report.to_dict(),
        )

    def disable_capability(self, name: str) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "disable", "Unknown capability.")
        config = self._get_or_create_config(definition)

        config.enabled = False
        config.health_status = "disabled" if config.installed else "not_installed"
        config.health_message = "Capability is installed but disabled." if config.installed else "Capability is not installed."
        self.config_manager.save_capability(config)
        return self._result(definition.name, "disable", True, "Capability disabled.")

    def test_capability(self, name: str, action: str = "test") -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, action, "Unknown capability.")
        config = self._get_or_create_config(definition)
        report = self._sync_health_state(definition, config)

        ok = report.status in {"ready", "disabled"}
        details = report.to_dict()
        if definition.name == "splunk_deeplink_tools" and report.status == "ready":
            provider = self._get_deeplink_provider(definition, config)
            if provider is not None:
                details["sample_deeplink"] = provider.build_sample_search_link()
        return CapabilityActionResult(
            ok=ok,
            capability=definition.name,
            action=action,
            message=report.message,
            state=self.get_capability_state(definition.name),
            details=details,
        )

    def update_capability_config(self, name: str, updates: Dict[str, Any]) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "update-config", "Unknown capability.")
        config = self._get_or_create_config(definition)
        merged = dict(config.config)
        merged.update(updates or {})
        config.config = self._normalize_capability_config(definition, merged)
        self.config_manager.save_capability(config)
        return self._result(definition.name, "update-config", True, "Capability configuration updated.")

    def reindex_capability(self, name: str) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "reindex", "Unknown capability.")

        config = self._get_or_create_config(definition)
        if not config.installed:
            return self._result(definition.name, "reindex", False, "Install the capability before indexing content.")
        if config.restart_required:
            return self._result(definition.name, "reindex", False, "Restart the application before indexing this capability.")

        provider = self._get_rag_provider(definition, config)
        if provider is None or not hasattr(provider, "reindex"):
            return self._result(definition.name, "reindex", False, "Capability does not expose indexing controls.")

        try:
            index_summary = provider.reindex()
        except Exception as exc:
            config.last_error = str(exc)
            self.config_manager.save_capability(config)
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="reindex",
                message="Capability reindex failed.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        report = self._sync_health_state(definition, config)
        message = "Capability reindex completed."
        if report.status == "ready":
            message = "Capability reindex completed and the index is ready."
        elif report.status == "degraded":
            message = f"Capability reindex completed. {report.message}"

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="reindex",
            message=message,
            state=self.get_capability_state(definition.name),
            details={
                "index_summary": index_summary,
                "health": report.to_dict(),
            },
        )

    def list_rag_assets(self, name: str = "rag_chromadb") -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "list-assets", "Unknown capability.")

        config = self._get_or_create_config(definition)
        provider = self._get_rag_provider(definition, config)
        if provider is None or not hasattr(provider, "list_managed_assets"):
            return self._result(definition.name, "list-assets", False, "Capability does not expose managed knowledge assets.")

        try:
            asset_summary = provider.list_managed_assets()
        except Exception as exc:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="list-assets",
                message="Failed to load managed knowledge assets.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="list-assets",
            message="Managed knowledge assets loaded.",
            state=self.get_capability_state(definition.name),
            details=asset_summary,
        )

    def get_rag_asset_detail(self, name: str, asset_id: str) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "get-asset-detail", "Unknown capability.")

        config = self._get_or_create_config(definition)
        provider = self._get_rag_provider(definition, config)
        if provider is None or not hasattr(provider, "get_managed_asset_detail"):
            return self._result(definition.name, "get-asset-detail", False, "Capability does not expose managed knowledge asset detail.")

        try:
            detail = provider.get_managed_asset_detail(asset_id)
        except Exception as exc:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="get-asset-detail",
                message="Failed to load managed knowledge asset detail.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        if detail is None:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="get-asset-detail",
                message="Knowledge asset was not found.",
                state=self.get_capability_state(definition.name),
                details={},
            )

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="get-asset-detail",
            message="Managed knowledge asset detail loaded.",
            state=self.get_capability_state(definition.name),
            details=detail,
        )

    def import_rag_text_asset(self, name: str, payload: Dict[str, Any]) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "import-asset", "Unknown capability.")

        config = self._get_or_create_config(definition)
        provider = self._get_rag_provider(definition, config)
        if provider is None or not hasattr(provider, "import_text_asset"):
            return self._result(definition.name, "import-asset", False, "Capability does not support managed knowledge asset import.")

        auto_reindex = self._should_auto_reindex_rag_assets(definition, config)
        try:
            details = provider.import_text_asset(
                title=payload.get("title") or "",
                asset_type=payload.get("asset_type") or "reference_document",
                content=payload.get("content") or "",
                source_label=payload.get("source_label") or "",
                description=payload.get("description") or "",
                tags=payload.get("tags") or [],
                attributes=payload.get("attributes") or {},
                auto_reindex=auto_reindex,
            )
        except Exception as exc:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="import-asset",
                message="Knowledge asset import failed.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        if auto_reindex and config.installed:
            self._sync_health_state(definition, config)

        import_action = str(details.get("asset_import_action") or "created").strip().lower()
        is_refresh = import_action == "updated"
        message = "Knowledge asset refreshed." if is_refresh else "Knowledge asset imported."
        if details.get("auto_reindexed"):
            message = "Knowledge asset refreshed and indexed." if is_refresh else "Knowledge asset imported and indexed."
        elif not config.enabled:
            message = (
                "Knowledge asset refreshed. Enable indexed retrieval to use it in context previews and chat."
                if is_refresh
                else "Knowledge asset imported. Enable indexed retrieval to use it in context previews and chat."
            )

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="import-asset",
            message=message,
            state=self.get_capability_state(definition.name),
            details=details,
        )

    def import_rag_file_asset(
        self,
        name: str,
        filename: str,
        content_bytes: bytes,
        payload: Dict[str, Any],
    ) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "import-asset", "Unknown capability.")

        config = self._get_or_create_config(definition)
        provider = self._get_rag_provider(definition, config)
        if provider is None or not hasattr(provider, "import_file_asset"):
            return self._result(definition.name, "import-asset", False, "Capability does not support managed knowledge asset import.")

        auto_reindex = self._should_auto_reindex_rag_assets(definition, config)
        try:
            details = provider.import_file_asset(
                filename=filename,
                content_bytes=content_bytes,
                title=payload.get("title") or None,
                asset_type=payload.get("asset_type") or "reference_document",
                source_label=payload.get("source_label") or "",
                description=payload.get("description") or "",
                tags=payload.get("tags") or [],
                attributes=payload.get("attributes") or {},
                auto_reindex=auto_reindex,
            )
        except Exception as exc:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="import-asset",
                message="Knowledge asset import failed.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        if auto_reindex and config.installed:
            self._sync_health_state(definition, config)

        import_action = str(details.get("asset_import_action") or "created").strip().lower()
        is_refresh = import_action == "updated"
        message = "Knowledge asset refreshed." if is_refresh else "Knowledge asset uploaded."
        if details.get("auto_reindexed"):
            message = "Knowledge asset refreshed and indexed." if is_refresh else "Knowledge asset uploaded and indexed."
        elif not config.enabled:
            message = (
                "Knowledge asset refreshed. Enable indexed retrieval to use it in context previews and chat."
                if is_refresh
                else "Knowledge asset uploaded. Enable indexed retrieval to use it in context previews and chat."
            )

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="import-asset",
            message=message,
            state=self.get_capability_state(definition.name),
            details=details,
        )

    def delete_rag_asset(self, name: str, asset_id: str) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "delete-asset", "Unknown capability.")

        config = self._get_or_create_config(definition)
        provider = self._get_rag_provider(definition, config)
        if provider is None or not hasattr(provider, "delete_managed_asset"):
            return self._result(definition.name, "delete-asset", False, "Capability does not expose managed knowledge assets.")

        auto_reindex = self._should_auto_reindex_rag_assets(definition, config)
        try:
            details = provider.delete_managed_asset(asset_id=asset_id, auto_reindex=auto_reindex)
        except Exception as exc:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="delete-asset",
                message="Knowledge asset deletion failed.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        if not details.get("deleted"):
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="delete-asset",
                message="Knowledge asset was not found.",
                state=self.get_capability_state(definition.name),
                details=details,
            )

        if auto_reindex and config.installed:
            self._sync_health_state(definition, config)

        message = "Knowledge asset deleted."
        if details.get("auto_reindexed"):
            message = "Knowledge asset deleted and index refreshed."

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="delete-asset",
            message=message,
            state=self.get_capability_state(definition.name),
            details=details,
        )

    def check_in_rag_asset(self, name: str, asset_id: str) -> CapabilityActionResult:
        return self._set_rag_asset_library_status(name, asset_id, "checked_in")

    def check_out_rag_asset(self, name: str, asset_id: str) -> CapabilityActionResult:
        return self._set_rag_asset_library_status(name, asset_id, "checked_out")

    def _set_rag_asset_library_status(
        self,
        name: str,
        asset_id: str,
        library_status: str,
    ) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            action = "check-in-asset" if library_status == "checked_in" else "check-out-asset"
            return CapabilityActionResult(False, name, action, "Unknown capability.")

        config = self._get_or_create_config(definition)
        provider = self._get_rag_provider(definition, config)
        provider_method_name = "check_in_managed_asset" if library_status == "checked_in" else "check_out_managed_asset"
        action = "check-in-asset" if library_status == "checked_in" else "check-out-asset"
        if provider is None or not hasattr(provider, provider_method_name):
            return self._result(definition.name, action, False, "Capability does not expose managed knowledge asset library controls.")

        auto_reindex = self._should_auto_reindex_rag_assets(definition, config)
        try:
            details = getattr(provider, provider_method_name)(asset_id=asset_id, auto_reindex=auto_reindex)
        except Exception as exc:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action=action,
                message="Knowledge asset library action failed.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        if not details.get("found"):
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action=action,
                message="Knowledge asset was not found.",
                state=self.get_capability_state(definition.name),
                details=details,
            )

        if auto_reindex and config.installed and details.get("changed"):
            self._sync_health_state(definition, config)

        state_label = "checked in" if library_status == "checked_in" else "checked out"
        if not details.get("changed"):
            message = f"Knowledge asset already {state_label}."
        elif details.get("auto_reindexed"):
            message = f"Knowledge asset {state_label} and index refreshed."
        else:
            message = f"Knowledge asset {state_label}."

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action=action,
            message=message,
            state=self.get_capability_state(definition.name),
            details=details,
        )

    def build_rag_context_preview(self, name: str, query: str, max_chunks: int = 4) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "build-context", "Unknown capability.")

        config = self._get_or_create_config(definition)
        if not config.installed:
            return self._result(definition.name, "build-context", False, "Install the capability before building RAG context previews.")
        if config.restart_required:
            return self._result(definition.name, "build-context", False, "Restart the application before using this capability.")
        if not config.enabled:
            return self._result(definition.name, "build-context", False, "Enable the capability before building RAG context previews.")

        provider = self._get_rag_provider(definition, config)
        if provider is None or not hasattr(provider, "build_context_preview"):
            return self._result(definition.name, "build-context", False, "Capability does not expose context preview generation.")

        try:
            details = provider.build_context_preview(query=query, max_chunks=max_chunks)
        except Exception as exc:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="build-context",
                message="RAG context preview generation failed.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="build-context",
            message=details.get("message") or "RAG context preview generated.",
            state=self.get_capability_state(definition.name),
            details=details,
        )

    def record_rag_spl_query_feedback(
        self,
        name: str,
        query: str,
        status: str,
        feedback: Optional[Dict[str, Any]] = None,
    ) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "record-feedback", "Unknown capability.")

        config = self._get_or_create_config(definition)
        provider = self._get_rag_provider(definition, config)
        if provider is None or not hasattr(provider, "record_spl_query_feedback"):
            return self._result(definition.name, "record-feedback", False, "Capability does not expose SPL query feedback updates.")

        try:
            details = provider.record_spl_query_feedback(query=query, status=status, feedback=feedback or {})
        except Exception as exc:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="record-feedback",
                message="SPL query feedback update failed.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        if not details.get("found"):
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="record-feedback",
                message="No matching SPL library asset was found for feedback.",
                state=self.get_capability_state(definition.name),
                details=details,
            )

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="record-feedback",
            message="SPL query feedback recorded.",
            state=self.get_capability_state(definition.name),
            details=details,
        )

    def build_deeplink(self, name: str, link_type: str, payload: Dict[str, Any]) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "build", "Unknown capability.")

        config = self._get_or_create_config(definition)
        if not config.installed:
            return self._result(definition.name, "build", False, "Install the capability before building deeplinks.")
        if config.restart_required:
            return self._result(definition.name, "build", False, "Restart the application before using this capability.")
        if not config.enabled:
            return self._result(definition.name, "build", False, "Enable the capability before building deeplinks.")

        provider = self._get_deeplink_provider(definition, config)
        if provider is None:
            return self._result(definition.name, "build", False, "Capability does not expose deeplink generation.")

        try:
            if str(link_type or "search").strip().lower() != "search":
                raise ValueError("Only search deeplinks are implemented in this phase.")
            deeplink = provider.build_search_link(
                spl_query=payload.get("query") or payload.get("spl_query") or "",
                earliest=payload.get("earliest"),
                latest=payload.get("latest"),
                app=payload.get("app"),
            )
        except Exception as exc:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="build",
                message="Splunk deeplink generation failed.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="build",
            message="Splunk deeplink generated.",
            state=self.get_capability_state(definition.name),
            details={"deeplink": deeplink},
        )

    def build_visualization(self, name: str, payload: Dict[str, Any]) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "build", "Unknown capability.")

        config = self._get_or_create_config(definition)
        if not config.installed:
            return self._result(definition.name, "build", False, "Install the capability before generating visualization previews.")
        if config.restart_required:
            return self._result(definition.name, "build", False, "Restart the application before using this capability.")
        if not config.enabled:
            return self._result(definition.name, "build", False, "Enable the capability before generating visualization previews.")

        provider = self._get_visualization_provider(definition, config)
        if provider is None:
            return self._result(definition.name, "build", False, "Capability does not expose visualization generation.")

        try:
            visualization = provider.build_preview(
                rows=payload.get("rows") or payload.get("results") or [],
                payload=payload,
            )
        except Exception as exc:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="build",
                message="Visualization preview generation failed.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="build",
            message="Visualization preview generated.",
            state=self.get_capability_state(definition.name),
            details={"visualization": visualization},
        )

    def build_export(self, name: str, payload: Dict[str, Any]) -> CapabilityActionResult:
        definition = self.registry.get_definition(name)
        if definition is None:
            return CapabilityActionResult(False, name, "build", "Unknown capability.")

        config = self._get_or_create_config(definition)
        if not config.installed:
            return self._result(definition.name, "build", False, "Install the capability before generating report packages.")
        if config.restart_required:
            return self._result(definition.name, "build", False, "Restart the application before using this capability.")
        if not config.enabled:
            return self._result(definition.name, "build", False, "Enable the capability before generating report packages.")

        provider = self._get_export_provider(definition, config)
        if provider is None:
            return self._result(definition.name, "build", False, "Capability does not support report package generation.")

        try:
            export_payload = provider.build_export(payload=payload)
        except Exception as exc:
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="build",
                message="Report package generation failed.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="build",
            message="Report package generated.",
            state=self.get_capability_state(definition.name),
            details={"export": export_payload},
        )

    def get_rag_context(self, user_message: str, max_chunks: int = 3) -> Dict[str, Any]:
        preferred_order = {"rag_chromadb": 0, "rag_local": 1}
        definitions = sorted(
            self.registry.rag_definitions(),
            key=lambda definition: preferred_order.get(definition.name, 99),
        )
        for definition in definitions:
            config = self._get_or_create_config(definition)
            if not definition.runtime_available or not config.installed or not config.enabled or config.restart_required:
                continue
            provider = self._get_rag_provider(definition, config)
            if provider is None:
                continue
            result = provider.get_context(user_message=user_message, max_chunks=max_chunks)
            if result.get("context_text"):
                return result
        return {
            "capability": None,
            "provider": None,
            "context_text": "",
            "chunks": [],
        }

    def _install_python_capability(self, definition: CapabilityDefinition, config: CapabilityConfig) -> CapabilityActionResult:
        if self._dependencies_available(definition):
            config.installed = True
            config.version = self._resolve_version(definition)
            config.installed_at = config.installed_at or _utc_now_iso()
            config.restart_required = False
            config.last_error = None
            self.config_manager.save_capability(config)
            return self._result(definition.name, "install", True, "Capability dependencies already available.")

        try:
            command = [sys.executable, "-m", "pip", "install", *definition.dependency_packages]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=600, check=False)
        except Exception as exc:
            config.last_error = str(exc)
            self.config_manager.save_capability(config)
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="install",
                message="Capability installation failed.",
                state=self.get_capability_state(definition.name),
                details={"error": str(exc)},
            )

        if completed.returncode != 0:
            config.last_error = (completed.stderr or completed.stdout or "pip install failed").strip()[-4000:]
            self.config_manager.save_capability(config)
            return CapabilityActionResult(
                ok=False,
                capability=definition.name,
                action="install",
                message="Capability installation failed.",
                state=self.get_capability_state(definition.name),
                details={
                    "return_code": completed.returncode,
                    "stderr": completed.stderr[-4000:],
                    "stdout": completed.stdout[-4000:],
                },
            )

        config.installed = True
        config.version = self._resolve_version(definition)
        config.installed_at = config.installed_at or _utc_now_iso()
        config.restart_required = bool(definition.requires_restart_on_install)
        config.last_error = None
        self.config_manager.save_capability(config)
        return CapabilityActionResult(
            ok=True,
            capability=definition.name,
            action="install",
            message="Capability installed successfully.",
            state=self.get_capability_state(definition.name),
            details={
                "restart_required": config.restart_required,
                "stdout": completed.stdout[-4000:],
            },
        )

    def _extra_capability_state(self, definition: CapabilityDefinition, config: CapabilityConfig) -> Dict[str, Any]:
        if definition.name == "rag_chromadb":
            provider = ChromaRAGProvider(config=config, definition=definition)
            asset_summary = provider.get_knowledge_asset_summary()
            return {
                "index_summary": provider.get_index_summary(),
                "knowledge_asset_summary": {
                    key: value
                    for key, value in asset_summary.items()
                    if key != "assets"
                },
            }
        if definition.name == "splunk_deeplink_tools":
            provider = self._get_deeplink_provider(definition, config)
            return provider.get_runtime_summary() if provider is not None else {}
        if definition.name == "visualization_tools":
            provider = self._get_visualization_provider(definition, config)
            return provider.get_runtime_summary() if provider is not None else {}
        if definition.name == "export_tools":
            provider = self._get_export_provider(definition, config)
            return provider.get_runtime_summary() if provider is not None else {}
        return {}

    def _get_rag_provider(self, definition: CapabilityDefinition, config: CapabilityConfig):
        if definition.name == "rag_local":
            return LightweightRAGProvider(config=config, definition=definition)
        if definition.name == "rag_chromadb":
            return ChromaRAGProvider(config=config, definition=definition)
        return None

    def _get_deeplink_provider(self, definition: CapabilityDefinition, config: CapabilityConfig):
        if definition.name != "splunk_deeplink_tools":
            return None
        mcp_url = str(self.config_manager.get().mcp.url or "").strip()
        return SplunkDeepLinkProvider(config=config, definition=definition, mcp_url=mcp_url)

    def _get_visualization_provider(self, definition: CapabilityDefinition, config: CapabilityConfig):
        if definition.name != "visualization_tools":
            return None
        return VisualizationPreviewProvider(config=config, definition=definition)

    def _get_export_provider(self, definition: CapabilityDefinition, config: CapabilityConfig):
        if definition.name != "export_tools":
            return None
        return DeterministicExportProvider(config=config, definition=definition)

    def _sync_health_state(self, definition: CapabilityDefinition, config: CapabilityConfig):
        report = self.health_service.check(definition, config)
        config.last_tested_at = report.checked_at
        config.health_status = report.status
        config.health_message = report.message
        config.last_error = report.message if report.status in {"degraded", "unavailable"} else None
        self.config_manager.save_capability(config)
        return report

    def _result(self, name: str, action: str, ok: bool, message: str) -> CapabilityActionResult:
        return CapabilityActionResult(
            ok=ok,
            capability=name,
            action=action,
            message=message,
            state=self.get_capability_state(name),
        )

    def _get_or_create_config(self, definition: CapabilityDefinition) -> CapabilityConfig:
        config = self.config_manager.get_capability(definition.name)
        if config is not None:
            config.config = self._normalize_capability_config(definition, dict(config.config or {}))
            return config

        config = CapabilityConfig(
            name=definition.name,
            install_method=definition.install_method,
            config=self._normalize_capability_config(definition, dict(definition.default_config)),
        )
        self.config_manager.save_capability(config)
        return config

    def _normalize_capability_config(self, definition: CapabilityDefinition, config: Dict[str, Any]) -> Dict[str, Any]:
        normalized = dict(config or {})
        if definition.name == "rag_chromadb":
            configured_extensions = normalized.get("allowed_extensions")
            if isinstance(configured_extensions, list):
                filtered_extensions = []
                for item in configured_extensions:
                    cleaned = str(item or "").strip().lower()
                    if cleaned and not cleaned.startswith("."):
                        cleaned = f".{cleaned}"
                    if cleaned and cleaned not in filtered_extensions:
                        filtered_extensions.append(cleaned)
            else:
                filtered_extensions = []
            normalized["allowed_extensions"] = filtered_extensions or list(definition.default_config.get("allowed_extensions", []))

            normalized["asset_dir"] = str(normalized.get("asset_dir") or "").strip()
            normalized["auto_reindex_on_asset_change"] = _coerce_bool(
                normalized.get("auto_reindex_on_asset_change"),
                bool(definition.default_config.get("auto_reindex_on_asset_change", True)),
            )

            for key in ("max_files", "max_scan_chars", "max_document_chars", "max_documents", "max_sections_per_file", "context_preview_limit"):
                value = normalized.get(key)
                try:
                    parsed = int(value)
                    normalized[key] = parsed if parsed > 0 else int(definition.default_config.get(key, 1))
                except (TypeError, ValueError):
                    normalized[key] = int(definition.default_config.get(key, 1))

        if definition.name == "export_tools":
            supported_outputs = {"bundle_zip", "manifest_json", "summary_markdown"}
            configured_formats = normalized.get("formats")
            if isinstance(configured_formats, list):
                filtered_formats = [item for item in configured_formats if item in supported_outputs]
            else:
                filtered_formats = []
            normalized["formats"] = filtered_formats or list(definition.default_config.get("formats", []))
        return normalized

    def _should_auto_reindex_rag_assets(self, definition: CapabilityDefinition, config: CapabilityConfig) -> bool:
        auto_reindex = _coerce_bool(
            config.config.get("auto_reindex_on_asset_change"),
            bool(definition.default_config.get("auto_reindex_on_asset_change", True)),
        )
        return bool(auto_reindex and config.installed and config.enabled and not config.restart_required and definition.runtime_available)

    def _dependencies_available(self, definition: CapabilityDefinition) -> bool:
        if not definition.module_probes:
            return True
        for module_name in definition.module_probes:
            try:
                __import__(module_name)
            except Exception:
                return False
        return True

    def _resolve_version(self, definition: CapabilityDefinition) -> Optional[str]:
        for requirement in definition.dependency_packages:
            distribution = re.split(r"[<>=!~]", requirement, maxsplit=1)[0].strip()
            if not distribution:
                continue
            try:
                return metadata.version(distribution)
            except metadata.PackageNotFoundError:
                continue
        return "bundled" if definition.install_method == "internal" else None
