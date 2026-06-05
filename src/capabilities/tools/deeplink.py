"""Splunk Web deeplink generation for operator-facing investigation pivots."""

import re
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from capabilities.models import CapabilityConfig, CapabilityDefinition


class SplunkDeepLinkProvider:
    """Build Splunk Web links from capability config and MCP connection context."""

    _probe_path = "/en-US/account/login"
    _probe_user_agent = "DT4SMS Deeplink Probe/1.0"

    def __init__(self, config: CapabilityConfig, definition: CapabilityDefinition, mcp_url: Optional[str] = None):
        self.config = config
        self.definition = definition
        self.mcp_url = str(mcp_url or "").strip()

    def resolve_web_base_url(self) -> Optional[str]:
        override = self._normalize_override_base_url(self.config.config.get("web_base_url"))
        if override:
            return override
        verified = self._get_verified_runtime_base_url()
        if verified:
            return verified
        return self._derive_web_base_url_from_mcp(self.mcp_url)

    def resolve_base_url_source(self) -> str:
        if self._normalize_override_base_url(self.config.config.get("web_base_url")):
            return "capability_config.web_base_url"
        if self._get_verified_runtime_base_url():
            return "runtime_state.verified_web_base_url"
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
        base_url_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        normalized_query = self.normalize_search_query(spl_query)
        if not normalized_query:
            raise ValueError("SPL query is required to build a Splunk deeplink.")

        base_url = self._normalize_override_base_url(base_url_override) or self.resolve_web_base_url()
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

    def build_sample_search_link(self, base_url_override: Optional[str] = None) -> Dict[str, Any]:
        return self.build_search_link(
            "search index=_internal | head 20",
            earliest="-15m",
            latest="now",
            base_url_override=base_url_override,
        )

    def get_runtime_summary(self) -> Dict[str, Any]:
        runtime_state = self._get_runtime_state()
        summary = {
            "resolved_web_base_url": self.resolve_web_base_url(),
            "base_url_source": self.resolve_base_url_source(),
            "default_app": self.resolve_default_app(),
            "candidate_web_base_urls": self.get_candidate_web_base_urls(),
        }
        if runtime_state.get("verified_web_base_url"):
            summary["verified_web_base_url"] = runtime_state.get("verified_web_base_url")
        if runtime_state.get("last_probe"):
            summary["last_web_probe"] = dict(runtime_state.get("last_probe") or {})
        try:
            summary["sample_search_url"] = self.build_sample_search_link()["url"]
        except Exception:
            summary["sample_search_url"] = None
        return summary

    def get_candidate_web_base_urls(self) -> List[str]:
        override = self._normalize_override_base_url(self.config.config.get("web_base_url"))
        if override:
            return [override]

        candidates: List[str] = []
        verified = self._get_verified_runtime_base_url()
        if verified:
            candidates.append(verified)

        for candidate in self._derive_web_base_url_candidates_from_mcp(self.mcp_url):
            if candidate and candidate not in candidates:
                candidates.append(candidate)

        return candidates

    def probe_web_base_url(self, verify_ssl: bool = True, timeout_seconds: float = 1.5) -> Dict[str, Any]:
        candidates = self.get_candidate_web_base_urls()
        if not candidates:
            return {
                "reachable": False,
                "message": "No Splunk Web base URL candidates could be resolved.",
                "attempts": [],
                "verify_ssl": verify_ssl,
            }

        attempts = []
        for index, candidate in enumerate(candidates):
            probe_url = f"{candidate}{self._probe_path}"
            attempt = {
                "base_url": candidate,
                "probe_url": probe_url,
                "candidate_index": index,
            }
            attempt.update(self._probe_url(probe_url, timeout_seconds=timeout_seconds, verify_ssl=verify_ssl))
            attempts.append(attempt)

            if attempt.get("reachable"):
                resolved_base_url = self._resolve_probe_base_url(candidate, attempt.get("final_url"))
                return {
                    "reachable": True,
                    "resolved_web_base_url": resolved_base_url,
                    "resolved_web_base_url_source": self._resolve_candidate_source(candidate),
                    "probe_url": probe_url,
                    "final_url": attempt.get("final_url"),
                    "status_code": attempt.get("status_code"),
                    "used_candidate_index": index,
                    "used_alternate_scheme": index > 0,
                    "attempts": attempts,
                    "verify_ssl": verify_ssl,
                }

        return {
            "reachable": False,
            "message": "Resolved Splunk Web URL candidates were not reachable.",
            "attempts": attempts,
            "verify_ssl": verify_ssl,
        }

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
        candidates = SplunkDeepLinkProvider._derive_web_base_url_candidates_from_mcp(mcp_url)
        return candidates[0] if candidates else None

    @staticmethod
    def _derive_web_base_url_candidates_from_mcp(mcp_url: str) -> List[str]:
        candidate = str(mcp_url or "").strip()
        if not candidate:
            return []

        parsed = urlsplit(candidate)
        if not parsed.scheme or not parsed.hostname:
            return []

        candidates: List[str] = []
        primary = SplunkDeepLinkProvider._build_base_url(
            scheme=parsed.scheme,
            hostname=parsed.hostname,
            port=parsed.port,
        )
        if primary:
            candidates.append(primary)

        web_port = 8000 if parsed.port == 8089 else parsed.port
        if web_port == 8000:
            alternate_scheme = "http" if parsed.scheme == "https" else "https"
            alternate = SplunkDeepLinkProvider._build_base_url(
                scheme=alternate_scheme,
                hostname=parsed.hostname,
                port=parsed.port,
            )
            if alternate and alternate not in candidates:
                candidates.append(alternate)

        return candidates

    @staticmethod
    def _build_base_url(scheme: str, hostname: Optional[str], port: Optional[int]) -> Optional[str]:
        if not scheme or not hostname:
            return None

        host = hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"

        web_port = 8000 if port == 8089 else port
        if web_port and not ((scheme == "http" and web_port == 80) or (scheme == "https" and web_port == 443)):
            netloc = f"{host}:{web_port}"
        else:
            netloc = host

        return urlunsplit((scheme, netloc, "", "", "")).rstrip("/")

    def _get_runtime_state(self) -> Dict[str, Any]:
        runtime_state = getattr(self.config, "runtime_state", None)
        return dict(runtime_state) if isinstance(runtime_state, dict) else {}

    def _get_verified_runtime_base_url(self) -> Optional[str]:
        runtime_state = self._get_runtime_state()
        candidate = self._normalize_override_base_url(runtime_state.get("verified_web_base_url"))
        if not candidate:
            return None

        verified_source = str(runtime_state.get("verified_from_source") or "").strip()
        if not verified_source.startswith("mcp.url"):
            return None

        verified_mcp_url = str(runtime_state.get("verified_from_mcp_url") or "").strip()
        if verified_mcp_url != self.mcp_url:
            return None

        return candidate

    def _resolve_candidate_source(self, candidate: str) -> str:
        override = self._normalize_override_base_url(self.config.config.get("web_base_url"))
        if override and candidate == override:
            return "capability_config.web_base_url"

        verified = self._get_verified_runtime_base_url()
        if verified and candidate == verified:
            return "runtime_state.verified_web_base_url"

        derived_candidates = self._derive_web_base_url_candidates_from_mcp(self.mcp_url)
        if candidate == (derived_candidates[0] if derived_candidates else None):
            return "mcp.url"
        if candidate in derived_candidates[1:]:
            return "mcp.url.alternate_scheme"
        return "unresolved"

    @classmethod
    def _resolve_probe_base_url(cls, requested_base_url: str, final_url: Optional[str]) -> str:
        requested = cls._normalize_override_base_url(requested_base_url) or str(requested_base_url or "").rstrip("/")
        final_candidate = str(final_url or "").strip()
        if not final_candidate:
            return requested

        requested_parsed = urlsplit(requested)
        final_parsed = urlsplit(final_candidate)
        requested_path = requested_parsed.path.rstrip("/")
        if requested_path:
            return urlunsplit((final_parsed.scheme, final_parsed.netloc, requested_path, "", "")).rstrip("/")

        final_path = final_parsed.path.rstrip("/")
        marker_index = final_path.lower().find(cls._probe_path.lower())
        base_path = final_path[:marker_index] if marker_index >= 0 else ""
        return urlunsplit((final_parsed.scheme, final_parsed.netloc, base_path.rstrip("/"), "", "")).rstrip("/")

    def _probe_url(self, probe_url: str, timeout_seconds: float = 1.5, verify_ssl: bool = True) -> Dict[str, Any]:
        context = None
        if probe_url.lower().startswith("https://") and not verify_ssl:
            context = ssl._create_unverified_context()

        request = Request(
            probe_url,
            headers={
                "User-Agent": self._probe_user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            method="GET",
        )

        try:
            with urlopen(request, timeout=timeout_seconds, context=context) as response:
                return {
                    "reachable": True,
                    "status_code": response.getcode(),
                    "final_url": response.geturl(),
                }
        except HTTPError as exc:
            if exc.code in {401, 403}:
                return {
                    "reachable": True,
                    "status_code": exc.code,
                    "final_url": exc.geturl(),
                    "http_error": f"HTTP {exc.code}: {exc.reason}",
                }
            return {
                "reachable": False,
                "status_code": exc.code,
                "final_url": exc.geturl(),
                "error": f"HTTP {exc.code}: {exc.reason}",
            }
        except URLError as exc:
            reason = getattr(exc, "reason", exc)
            return {
                "reachable": False,
                "error": str(reason or exc),
            }
        except Exception as exc:
            return {
                "reachable": False,
                "error": str(exc),
            }