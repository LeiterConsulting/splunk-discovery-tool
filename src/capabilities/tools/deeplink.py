"""Splunk Web deeplink generation for operator-facing investigation pivots."""

import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from capabilities.models import CapabilityConfig, CapabilityDefinition


class SplunkDeepLinkProvider:
    """Build Splunk Web links from capability config and MCP connection context."""

    def __init__(self, config: CapabilityConfig, definition: CapabilityDefinition, mcp_url: Optional[str] = None):
        self.config = config
        self.definition = definition
        self.mcp_url = str(mcp_url or "").strip()

    def resolve_web_base_url(self) -> Optional[str]:
        override = self._normalize_override_base_url(self.config.config.get("web_base_url"))
        if override:
            return override
        return self._derive_web_base_url_from_mcp(self.mcp_url)

    def resolve_base_url_source(self) -> str:
        if self._normalize_override_base_url(self.config.config.get("web_base_url")):
            return "capability_config.web_base_url"
        if self._derive_web_base_url_from_mcp(self.mcp_url):
            return "mcp.url"
        return "unresolved"

    def resolve_default_app(self, app: Optional[str] = None) -> str:
        candidate = str(
            app
            or self.config.config.get("default_app")
            or self.definition.default_config.get("default_app")
            or "search"
        ).strip()
        candidate = candidate.strip("/")
        return candidate or "search"

    def resolve_default_time_range(
        self,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
    ) -> Tuple[str, str]:
        resolved_earliest = str(
            earliest
            or self.config.config.get("default_earliest")
            or self.definition.default_config.get("default_earliest")
            or "-24h"
        ).strip() or "-24h"
        resolved_latest = str(
            latest
            or self.config.config.get("default_latest")
            or self.definition.default_config.get("default_latest")
            or "now"
        ).strip() or "now"
        return resolved_earliest, resolved_latest

    def build_search_link(
        self,
        spl_query: str,
        earliest: Optional[str] = None,
        latest: Optional[str] = None,
        app: Optional[str] = None,
    ) -> Dict[str, Any]:
        normalized_query = self.normalize_search_query(spl_query)
        if not normalized_query:
            raise ValueError("SPL query is required to build a Splunk deeplink.")

        base_url = self.resolve_web_base_url()
        if not base_url:
            raise ValueError(
                "Splunk Web base URL could not be resolved. Configure web_base_url or set a valid MCP URL."
            )

        app_name = self.resolve_default_app(app)
        earliest_value, latest_value = self.resolve_default_time_range(earliest=earliest, latest=latest)
        query_string = urlencode(
            {
                "q": normalized_query,
                "earliest": earliest_value,
                "latest": latest_value,
            },
            quote_via=quote,
        )
        path = f"/en-US/app/{quote(app_name, safe='')}/search"
        url = f"{base_url}{path}?{query_string}"

        return {
            "type": "search",
            "url": url,
            "base_url": base_url,
            "base_url_source": self.resolve_base_url_source(),
            "app": app_name,
            "query": normalized_query,
            "earliest": earliest_value,
            "latest": latest_value,
        }

    def build_sample_search_link(self) -> Dict[str, Any]:
        return self.build_search_link("search index=_internal | head 20", earliest="-15m", latest="now")

    def get_runtime_summary(self) -> Dict[str, Any]:
        summary = {
            "resolved_web_base_url": self.resolve_web_base_url(),
            "base_url_source": self.resolve_base_url_source(),
            "default_app": self.resolve_default_app(),
        }
        try:
            summary["sample_search_url"] = self.build_sample_search_link()["url"]
        except Exception:
            summary["sample_search_url"] = None
        return summary

    @staticmethod
    def normalize_search_query(spl_query: Any) -> str:
        query = re.sub(r"\s+", " ", str(spl_query or "")).strip()
        if not query:
            return ""
        lowered = query.lower()
        if lowered.startswith("search ") or query.startswith("|"):
            return query
        return f"search {query}"

    @staticmethod
    def _normalize_override_base_url(value: Any) -> Optional[str]:
        candidate = str(value or "").strip()
        if not candidate:
            return None
        parsed = urlsplit(candidate)
        if not parsed.scheme or not parsed.netloc:
            return None
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")).rstrip("/")

    @staticmethod
    def _derive_web_base_url_from_mcp(mcp_url: str) -> Optional[str]:
        candidate = str(mcp_url or "").strip()
        if not candidate:
            return None

        parsed = urlsplit(candidate)
        if not parsed.scheme or not parsed.hostname:
            return None

        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"

        port = parsed.port
        web_port = 8000 if port == 8089 else port
        if web_port and not ((parsed.scheme == "http" and web_port == 80) or (parsed.scheme == "https" and web_port == 443)):
            netloc = f"{host}:{web_port}"
        else:
            netloc = host

        return urlunsplit((parsed.scheme, netloc, "", "", "")).rstrip("/")