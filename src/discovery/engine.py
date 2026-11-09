"""
Core discovery engine for recursive Splunk environment exploration.

This module provides the main DiscoveryEngine class that coordinates
the entire discovery process through MCP integration.
"""

import asyncio
import contextlib
import functools
import json
import os
import re
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

import aiohttp

from mcp_tool_args import adapt_tool_arguments
from discovery.local_analyzer import (
    KIND_ANALYTICS,
    KIND_HOST,
    KIND_INDEX,
    KIND_INDEX_DETAIL,
    KIND_KNOWLEDGE_OBJECT,
    KIND_KV_COLLECTION,
    KIND_SOURCE,
    KIND_SOURCETYPE,
    KIND_STEP_STATUS,
    KIND_USER,
    LocalDataAnalyzer,
    is_truthy_flag,
    metadata_recent_epoch,
    result_kind,
    safe_float,
    safe_int,
)


ROW_LIMITS: Dict[str, int] = {
    "indexes": 1000,
    "sourcetypes": 1000,
    "hosts": 1000,
    "sources": 1000,
    "knowledge_objects": 500,
    "kv_collections": 500,
}
# Names follow the GA splunk_get_knowledge_objects "type" enum; dashboards are "views".
KNOWLEDGE_OBJECT_TYPES: List[str] = ["saved_searches", "alerts", "views", "macros", "lookups", "data_models"]
# Alerts are saved searches with alert actions; counting both would double count.
KNOWLEDGE_OBJECT_TOTAL_EXCLUDES = {"alerts"}
DETAILED_INDEX_LIMIT = 10
DEFAULT_MCP_DEADLINE_SECONDS = 600.0
DEFAULT_MCP_CONCURRENCY = 4
DEFAULT_REQUEST_TIMEOUT_SECONDS = 60.0
TOOLS_LIST_TIMEOUT_SECONDS = 15.0
LLM_PROMPT_MAX_CHARS = 20000
MCP_DEADLINE_ENV_VAR = "DISCOVERY_MCP_DEADLINE_SECONDS"

LICENSE_USAGE_24H_QUERY = "index=_internal source=*license_usage.log* type=Usage earliest=-24h | stats sum(b) as bytes"
# The GA MCP metadata tool only lists hosts and sources, so sourcetypes come from
# the metadata search command when the tool rejects type=sourcetypes.
SOURCETYPE_METADATA_QUERY = "| metadata type=sourcetypes index=* | sort - totalCount"
RECENT_INDEX_ACTIVITY_QUERY = "| tstats count where index=* OR index=_* by index"
DAILY_EVENT_TREND_QUERY = "| tstats count where index=* by _time span=1d"

STEP_LABELS: Dict[str, str] = {
    "platform_info": "Platform information",
    "indexes": "Index inventory",
    "sourcetypes": "Sourcetype inventory",
    "hosts": "Host inventory",
    "sources": "Source inventory",
    "users": "Authenticated user context",
    "kv_collections": "KV store collections",
    "license_usage_24h": "24h license usage",
    "index_details": "Index configuration details",
}

SURFACE_STEPS: Dict[str, str] = {
    "indexes": "indexes",
    "sourcetypes": "sourcetypes",
    "hosts": "hosts",
    "sources": "sources",
    "knowledge_objects": "knowledge_objects:saved_searches",
    "kv_collections": "kv_collections",
}


class MCPToolError(Exception):
    """Raised when the MCP server or a tool reports an error."""


class DiscoveryStepUnavailable(Exception):
    """Raised by a discovery step whose data could not be collected."""

    def __init__(self, step: str, status: str, message: str):
        super().__init__(message)
        self.step = step
        self.status = status


@dataclass
class StepOutcome:
    name: str
    status: str
    rows: List[Dict[str, Any]] = field(default_factory=list)
    response: Any = None
    error: str = ""
    truncated: bool = False
    row_limit: Optional[int] = None


@dataclass
class EnvironmentOverview:
    """Summary of the Splunk environment for progress estimation."""
    total_indexes: int
    total_sourcetypes: int
    total_hosts: int = 0
    total_sources: int = 0
    total_knowledge_objects: int = 0
    total_users: int = 0
    total_kv_collections: int = 0
    # Real 24h ingest from license_usage.log only; None when it could not be measured.
    data_volume_24h: Optional[str] = None
    active_sources: int = 0
    estimated_discovery_steps: int = 0
    estimated_time: str = ""
    notable_patterns: List[Any] = None
    splunk_version: str = ""
    splunk_build: str = ""
    license_state: str = ""
    server_roles: List[str] = None
    data_volume_24h_mb: Optional[float] = None
    data_volume_24h_source: str = ""
    total_index_size_mb: float = 0.0
    truncated: Dict[str, bool] = None
    row_limits: Dict[str, int] = None
    count_display: Dict[str, str] = None
    knowledge_object_counts: Dict[str, int] = None
    user_scope: str = "authenticated_user_context"
    authenticated_user: str = ""
    authenticated_user_roles: List[str] = None

    def __post_init__(self):
        """Ensure collections are always initialized."""
        if self.notable_patterns is None:
            self.notable_patterns = []
        if self.server_roles is None:
            self.server_roles = []
        if self.truncated is None:
            self.truncated = {}
        if self.row_limits is None:
            self.row_limits = {}
        if self.count_display is None:
            self.count_display = {}
        if self.knowledge_object_counts is None:
            self.knowledge_object_counts = {}
        if self.authenticated_user_roles is None:
            self.authenticated_user_roles = []


@dataclass
class DiscoveryResult:
    """Result from a single discovery step."""
    step: int
    description: str
    data: Dict[str, Any]
    interesting_findings: List[str]
    timestamp: datetime
    kind: str = ""


_TOKEN_SPLIT = re.compile(r"[^a-z0-9]+")


def _name_tokens(name: Any) -> List[str]:
    """Split an entity name into lowercase word tokens; 'dc01' also yields 'dc'."""
    tokens: List[str] = []
    for raw in _TOKEN_SPLIT.split(str(name or "").lower()):
        if not raw:
            continue
        tokens.append(raw)
        stripped = raw.rstrip("0123456789")
        if stripped and stripped != raw:
            tokens.append(stripped)
    return tokens


def _format_mb(mb: float) -> str:
    if mb < 1024:
        return f"{mb:,.1f} MB"
    if mb < 1024 * 1024:
        return f"{mb / 1024:,.2f} GB"
    return f"{mb / 1024 / 1024:,.2f} TB"


def _shrink_for_prompt(value: Any, max_chars: int = LLM_PROMPT_MAX_CHARS) -> Any:
    """Bound the serialized size of an LLM payload by progressively truncating lists and strings."""

    def shrink(obj: Any, list_cap: int, str_cap: int) -> Any:
        if isinstance(obj, dict):
            return {str(k): shrink(v, list_cap, str_cap) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set)):
            items = list(obj)
            reduced = [shrink(item, list_cap, str_cap) for item in items[:list_cap]]
            if len(items) > list_cap:
                reduced.append(f"... {len(items) - list_cap} more")
            return reduced
        if isinstance(obj, str):
            return obj if len(obj) <= str_cap else obj[:str_cap] + "..."
        if obj is None or isinstance(obj, (bool, int, float)):
            return obj
        return shrink(str(obj), list_cap, str_cap)

    candidate: Any = value
    for list_cap, str_cap in ((50, 500), (25, 300), (10, 200), (5, 120), (2, 80)):
        candidate = shrink(value, list_cap, str_cap)
        if len(json.dumps(candidate, indent=2, default=str)) <= max_chars:
            return candidate
    return {"truncated_summary": json.dumps(candidate, default=str)[: max_chars // 2]}


def _is_unstructured_llm_result(result: Any) -> bool:
    """LLM clients wrap non-JSON replies as {"analysis": text, "insights": ["Analysis completed"]}."""
    return (
        isinstance(result, dict)
        and isinstance(result.get("analysis"), str)
        and set(result.keys()) <= {"analysis", "insights"}
    )


def _parse_time_value(value: Any) -> Optional[float]:
    """Parse epoch seconds or ISO timestamps returned by Splunk."""
    if value is None or value == "":
        return None
    numeric = safe_float(value, default=float("nan"))
    if numeric == numeric:
        return numeric
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _age_hours(value: Any) -> Optional[float]:
    """Hours since an ISO timestamp or epoch seconds; None when missing or unparseable."""
    timestamp = _parse_time_value(value)
    if timestamp is None or timestamp <= 0:
        return None
    return (time.time() - timestamp) / 3600


class DiscoveryEngine:
    """
    Main discovery engine that coordinates recursive Splunk environment exploration.

    This class handles:
    - Initial environment overview and estimation
    - Step-by-step detailed discovery
    - Data classification and analysis
    - Integration with LLM for intelligent insights
    """

    def __init__(
        self,
        mcp_url: str,
        mcp_token: str,
        llm_client,
        verify_ssl: bool = False,
        ca_bundle_path: Optional[str] = None,
        *,
        available_tools: Optional[Any] = None,
        tool_schemas: Optional[Dict[str, Any]] = None,
        mcp_deadline_seconds: Optional[float] = None,
        max_concurrency: int = DEFAULT_MCP_CONCURRENCY,
        request_timeout_seconds: float = DEFAULT_REQUEST_TIMEOUT_SECONDS,
    ):
        self.mcp_url = mcp_url
        self.mcp_token = mcp_token
        self.llm_client = llm_client
        self.verify_ssl = verify_ssl
        self.ca_bundle_path = ca_bundle_path
        self.discovery_results: List[DiscoveryResult] = []
        self.environment_overview: Optional[EnvironmentOverview] = None
        self.discovery_data: Dict[str, Any] = {}
        self.local_analyzer = LocalDataAnalyzer()
        self._available_tools: set = set()
        self._tool_schemas: Dict[str, Any] = {}
        self._tool_last_refresh: float = 0.0
        self._tool_list_attempted = False
        if isinstance(tool_schemas, dict):
            self._tool_schemas = {str(name): schema for name, schema in tool_schemas.items() if isinstance(schema, dict)}
        if available_tools:
            self._available_tools = {str(name) for name in available_tools}
            self._tool_list_attempted = True
            self._tool_last_refresh = time.time()
        self._tool_aliases: Dict[str, List[str]] = {
            "splunk_run_query": ["splunk_run_query", "run_splunk_query"],
            "splunk_get_info": ["splunk_get_info", "get_splunk_info"],
            "splunk_get_indexes": ["splunk_get_indexes", "get_indexes"],
            "splunk_get_index_info": ["splunk_get_index_info", "get_index_info"],
            "splunk_get_metadata": ["splunk_get_metadata", "get_metadata"],
            "splunk_get_user_info": ["splunk_get_user_info", "splunk_get_user_list", "get_user_list"],
            "splunk_get_kv_store_collections": ["splunk_get_kv_store_collections", "get_kv_store_collections"],
            "splunk_get_knowledge_objects": ["splunk_get_knowledge_objects", "get_knowledge_objects"],
            "saia_generate_spl": ["saia_generate_spl"],
            "saia_optimize_spl": ["saia_optimize_spl"],
            "saia_explain_spl": ["saia_explain_spl"],
            "saia_ask_splunk_question": ["saia_ask_splunk_question"]
        }

        self.mcp_deadline_seconds = self._resolve_deadline(mcp_deadline_seconds)
        self.max_concurrency = max(1, safe_int(max_concurrency, DEFAULT_MCP_CONCURRENCY))
        self.request_timeout_seconds = safe_float(request_timeout_seconds, DEFAULT_REQUEST_TIMEOUT_SECONDS) or DEFAULT_REQUEST_TIMEOUT_SECONDS
        self.retry_backoff_seconds = 0.5

        self._rpc_id = 0
        self._session: Optional[aiohttp.ClientSession] = None
        self._session_loop = None
        self._session_depth = 0
        self._ssl_context = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._semaphore_loop = None
        self._mcp_cache: Dict[str, Tuple[str, Any]] = {}
        self._step_status: Dict[str, Dict[str, Any]] = {}
        self._llm_status: Dict[str, Dict[str, Any]] = {}
        self._inventory: Dict[str, List[Dict[str, Any]]] = {}
        self._freshness: Dict[str, Any] = {}
        self._summary_cache: Optional[Tuple[int, Dict[str, Any]]] = None
        self._metrics: Dict[str, int] = {"mcp_requests": 0, "mcp_tool_calls": 0, "cache_hits": 0, "retries": 0}
        self._mcp_phase_started_at: Optional[float] = None

    # ------------------------------------------------------------------
    # Configuration helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_deadline(value: Optional[float]) -> float:
        if value is None:
            env_value = os.environ.get(MCP_DEADLINE_ENV_VAR)
            value = safe_float(env_value, DEFAULT_MCP_DEADLINE_SECONDS) if env_value else DEFAULT_MCP_DEADLINE_SECONDS
        resolved = safe_float(value, DEFAULT_MCP_DEADLINE_SECONDS)
        return resolved if resolved > 0 else 0.0

    def _ssl_param(self):
        if not self.verify_ssl:
            return False
        if self.ca_bundle_path:
            if self._ssl_context is None:
                self._ssl_context = ssl.create_default_context(cafile=self.ca_bundle_path)
            return self._ssl_context
        return None

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.mcp_token}"
        }

    def _next_rpc_id(self) -> int:
        self._rpc_id = getattr(self, "_rpc_id", 0) + 1
        return self._rpc_id

    def _build_rpc_payload(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": self._next_rpc_id(), "method": method, "params": params}

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    @contextlib.asynccontextmanager
    async def _mcp_session_scope(self):
        """Share one HTTP session for every MCP request issued inside the scope."""
        self._session_depth += 1
        try:
            yield
        finally:
            self._session_depth -= 1
            if self._session_depth <= 0:
                self._session_depth = 0
                await self._close_session()

    async def _close_session(self) -> None:
        session = self._session
        self._session = None
        self._session_loop = None
        if session is not None and not session.closed:
            try:
                await session.close()
            except Exception:
                pass

    async def aclose(self) -> None:
        """Release network resources held by the engine."""
        self._session_depth = 0
        await self._close_session()

    async def _acquire_session(self) -> Tuple[aiohttp.ClientSession, bool]:
        loop = asyncio.get_running_loop()
        if self._session_depth > 0:
            if self._session is None or self._session.closed or self._session_loop is not loop:
                self._session = aiohttp.ClientSession()
                self._session_loop = loop
            return self._session, False
        return aiohttp.ClientSession(), True

    async def _post_json(self, payload: Dict[str, Any], timeout_seconds: float) -> Tuple[int, str]:
        """POST one JSON-RPC payload and return (HTTP status, body text)."""
        session, owned = await self._acquire_session()
        try:
            async with session.post(
                self.mcp_url,
                headers=self._headers(),
                json=payload,
                timeout=aiohttp.ClientTimeout(total=timeout_seconds),
                ssl=self._ssl_param(),
            ) as response:
                return response.status, await response.text()
        finally:
            if owned:
                await session.close()

    @staticmethod
    def _decode_body(body_text: Any) -> Any:
        if not isinstance(body_text, str):
            return body_text
        stripped = body_text.strip()
        if not stripped:
            raise MCPToolError("MCP server returned an empty response body")
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
        # Streamable HTTP MCP servers may answer with an SSE stream.
        data_lines = [line[5:].strip() for line in stripped.splitlines() if line.startswith("data:")]
        for candidate in reversed(data_lines):
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue
        raise MCPToolError(f"MCP server returned a non-JSON response: {stripped[:300]}")

    async def _rpc_request(self, method: str, params: Dict[str, Any], timeout_seconds: float) -> Any:
        """Send a JSON-RPC request with one retry on timeouts, connection errors, and 5xx."""
        attempts = 2
        for attempt in range(attempts):
            payload = self._build_rpc_payload(method, params)
            self._metrics["mcp_requests"] = self._metrics.get("mcp_requests", 0) + 1
            try:
                status, body_text = await self._post_json(payload, timeout_seconds)
            except (asyncio.TimeoutError, aiohttp.ClientConnectionError, aiohttp.ClientPayloadError) as exc:
                if attempt + 1 < attempts:
                    self._metrics["retries"] = self._metrics.get("retries", 0) + 1
                    await asyncio.sleep(self.retry_backoff_seconds * (attempt + 1))
                    continue
                detail = str(exc) or type(exc).__name__
                raise MCPToolError(f"MCP request '{method}' failed after {attempts} attempts: {type(exc).__name__}: {detail}") from exc

            if status >= 500 and attempt + 1 < attempts:
                self._metrics["retries"] = self._metrics.get("retries", 0) + 1
                await asyncio.sleep(self.retry_backoff_seconds * (attempt + 1))
                continue
            if not 200 <= status < 300:
                raise MCPToolError(f"MCP server returned {status}: {str(body_text)[:500]}")
            return self._decode_body(body_text)
        raise MCPToolError(f"MCP request '{method}' failed")

    async def _refresh_available_tools(self, force: bool = False) -> set:
        """Refresh and cache available MCP tools from Splunk MCP server."""
        now = time.time()
        if not force and self._available_tools and (now - self._tool_last_refresh) < 60:
            return self._available_tools
        if not force and self._tool_list_attempted and not self._available_tools:
            return self._available_tools

        self._tool_list_attempted = True
        discovered = set()
        try:
            result = await self._rpc_request("tools/list", {}, TOOLS_LIST_TIMEOUT_SECONDS)
        except Exception:
            return self._available_tools

        result_obj = result.get("result", {}) if isinstance(result, dict) else {}
        if not isinstance(result_obj, dict):
            result_obj = {}

        if isinstance(result_obj.get("tools"), list):
            for tool in result_obj.get("tools", []):
                if isinstance(tool, dict) and tool.get("name"):
                    discovered.add(tool["name"])
                    if isinstance(tool.get("inputSchema"), dict):
                        self._tool_schemas[tool["name"]] = tool["inputSchema"]

        content = result_obj.get("content", [])
        if isinstance(content, list):
            for item in content:
                if not isinstance(item, dict):
                    continue
                text = item.get("text")
                if not isinstance(text, str) or not text.strip():
                    continue
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict) and isinstance(parsed.get("tools"), list):
                    for tool in parsed["tools"]:
                        if isinstance(tool, dict) and tool.get("name"):
                            discovered.add(tool["name"])

        if discovered:
            self._available_tools = discovered
            self._tool_last_refresh = now
        return self._available_tools

    async def _resolve_tool_name(self, requested_method: str, force_refresh: bool = False) -> str:
        """Resolve logical or legacy tool name to an available MCP tool name."""
        if force_refresh or (not self._available_tools and not self._tool_list_attempted):
            await self._refresh_available_tools(force=force_refresh)

        available = self._available_tools
        if requested_method in available:
            return requested_method

        for canonical, aliases in self._tool_aliases.items():
            if requested_method == canonical or requested_method in aliases:
                for candidate in aliases:
                    if candidate in available:
                        return candidate
                if canonical in available:
                    return canonical
                # Prefer first alias as fallback when tool list is unavailable
                return aliases[0]

        return requested_method

    async def _call_tool_raw(self, resolved_tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a tools/call request with a resolved tool name and normalize the response."""
        normalized_params = self._normalize_tool_arguments(resolved_tool_name, params)
        self._metrics["mcp_tool_calls"] = self._metrics.get("mcp_tool_calls", 0) + 1
        body = await self._rpc_request(
            "tools/call",
            {"name": resolved_tool_name, "arguments": normalized_params},
            self.request_timeout_seconds,
        )
        return self._parse_tool_response(body)

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _describe_error(error: Any) -> str:
        if isinstance(error, dict):
            message = error.get("message") or error.get("error") or error.get("detail") or error.get("msg")
            code = error.get("code") or error.get("status_code") or error.get("statusCode")
            if message:
                text = str(message) if not isinstance(message, (dict, list)) else json.dumps(message, default=str)
                return f"{text} (code {code})" if code not in (None, "") else text
            return json.dumps(error, default=str)[:500]
        return str(error)[:500]

    @staticmethod
    def _content_text(content: Any) -> str:
        if not isinstance(content, list):
            return ""
        parts = [str(item.get("text")) for item in content if isinstance(item, dict) and item.get("text")]
        return "\n".join(parts).strip()

    @staticmethod
    def _normalize_mapping(mapping: Dict[str, Any], merge_single: bool = True) -> Dict[str, Any]:
        results = mapping.get("results")
        if not isinstance(results, list):
            results = None
            for key in ("data", "items", "entries", "rows", "records", "result"):
                candidate = mapping.get(key)
                if isinstance(candidate, list) and all(isinstance(item, dict) for item in candidate):
                    results = candidate
                    break
            if results is None:
                for candidate in mapping.values():
                    if isinstance(candidate, list) and candidate and all(isinstance(item, dict) for item in candidate):
                        results = candidate
                        break
            if results is not None:
                mapping["results"] = results
        if merge_single and isinstance(results, list) and len(results) == 1 and isinstance(results[0], dict):
            for key, value in results[0].items():
                mapping.setdefault(key, value)
        return mapping

    def _parse_content_items(self, content: List[Any]) -> Dict[str, Any]:
        texts = [item.get("text") for item in content if isinstance(item, dict) and isinstance(item.get("text"), str)]
        non_empty = [text for text in texts if text.strip()]
        if not non_empty:
            return {"results": []}

        parsed: List[Any] = []
        unparsed: List[str] = []
        for text in non_empty:
            try:
                parsed.append(json.loads(text))
            except json.JSONDecodeError:
                unparsed.append(text)

        if not parsed:
            joined = "\n".join(unparsed)
            return {
                "results": [],
                "unparsed": True,
                "raw_text": joined[:4000],
                "parse_error": "MCP tool returned non-JSON text content",
            }

        if len(parsed) == 1:
            single = parsed[0]
            if isinstance(single, dict):
                normalized = self._normalize_mapping(single)
            elif isinstance(single, list):
                normalized = self._normalize_mapping({"results": single})
            else:
                normalized = {"results": [], "value": single}
        else:
            rows: List[Any] = []
            extra: Dict[str, Any] = {}
            for part in parsed:
                if isinstance(part, list):
                    rows.extend(part)
                elif isinstance(part, dict):
                    part_norm = self._normalize_mapping(dict(part), merge_single=False)
                    part_rows = part_norm.get("results")
                    if isinstance(part_rows, list):
                        rows.extend(part_rows)
                        for key, value in part_norm.items():
                            if key != "results" and not isinstance(value, list):
                                extra.setdefault(key, value)
                    else:
                        rows.append(part)
            normalized = self._normalize_mapping({**extra, "results": rows})

        if unparsed:
            normalized["unparsed_parts"] = len(unparsed)
        return normalized

    def _parse_tool_response(self, body: Any) -> Dict[str, Any]:
        """Normalize a JSON-RPC tools/call response into a dict with a 'results' list when rows exist."""
        if isinstance(body, list):
            return {"results": body}
        if not isinstance(body, dict):
            return {"results": [], "value": body}

        if body.get("error") is not None:
            raise MCPToolError(f"MCP tool error: {self._describe_error(body['error'])}")

        if "result" not in body:
            return body

        result_obj = body.get("result")
        if isinstance(result_obj, list):
            return self._normalize_mapping({"results": result_obj})
        if not isinstance(result_obj, dict):
            return {"results": []} if result_obj is None else {"results": [], "value": result_obj}

        content = result_obj.get("content")
        structured = result_obj.get("structuredContent")

        if is_truthy_flag(result_obj.get("isError")):
            message = self._content_text(content)
            if not message and isinstance(structured, dict):
                message = self._describe_error(structured)
            raise MCPToolError(f"MCP tool error: {(message or 'tool reported isError without details')[:500]}")

        if isinstance(structured, dict) and structured:
            status_code = safe_int(structured.get("status_code", structured.get("statusCode")), 0)
            if status_code >= 400:
                raise MCPToolError(f"MCP tool error (status {status_code}): {self._describe_error(structured)}")
            return self._normalize_mapping(dict(structured))

        if isinstance(result_obj.get("results"), list):
            return self._normalize_mapping({"results": result_obj["results"]})

        if isinstance(content, list) and content:
            return self._parse_content_items(content)

        if result_obj:
            return result_obj
        return {"results": []}

    def _normalize_tool_arguments(self, resolved_tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize argument shapes to the GA v1 Splunk MCP tool arguments.

        When tools/list advertised an input schema, names and values are adapted to
        it. Otherwise the GA spellings (index_name, type, count) are assumed.
        """
        normalized = dict(params or {})

        schema = getattr(self, "_tool_schemas", {}).get(resolved_tool_name)
        if isinstance(schema, dict):
            adapted, _dropped = adapt_tool_arguments(normalized, schema)
            return adapted

        if resolved_tool_name in {"splunk_get_info", "get_splunk_info", "splunk_get_user_info", "splunk_get_user_list", "get_user_list"}:
            return {}

        if resolved_tool_name in {"splunk_get_index_info", "get_index_info"}:
            if "index" in normalized and "index_name" not in normalized:
                normalized["index_name"] = normalized.pop("index")

        if resolved_tool_name in {"splunk_get_knowledge_objects", "get_knowledge_objects"}:
            if "object_type" in normalized and "type" not in normalized:
                normalized["type"] = normalized.pop("object_type")

        if resolved_tool_name in {"splunk_get_indexes", "get_indexes"}:
            if "row_limit" in normalized and "count" not in normalized:
                normalized["count"] = normalized.pop("row_limit")

        return normalized

    async def _mcp_call(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make MCP call with dynamic tool-name resolution and auto-refresh on unknown-tool errors."""
        try:
            resolved_name = await self._resolve_tool_name(method)
            try:
                return await self._call_tool_raw(resolved_name, params)
            except Exception as first_error:
                error_text = str(first_error).lower()
                unknown_tool_signals = [
                    "tool not found",
                    "unknown tool",
                    "invalid tool",
                    "no such tool",
                    "method not found"
                ]

                if any(signal in error_text for signal in unknown_tool_signals):
                    refreshed_name = await self._resolve_tool_name(method, force_refresh=True)
                    if refreshed_name != resolved_name:
                        return await self._call_tool_raw(refreshed_name, params)

                raise first_error
        except MCPToolError:
            raise
        except Exception as e:
            raise MCPToolError(f"MCP connection failed: {str(e)}") from e

    # ------------------------------------------------------------------
    # Step execution: caching, concurrency, deadline, status tracking
    # ------------------------------------------------------------------

    @staticmethod
    def _cache_key(method: str, params: Dict[str, Any]) -> str:
        return f"{method}|{json.dumps(params or {}, sort_keys=True, default=str)}"

    async def _cached_mcp_call(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Issue each distinct MCP call at most once per engine run (errors are cached too)."""
        key = self._cache_key(method, params)
        cached = self._mcp_cache.get(key)
        if cached is not None:
            self._metrics["cache_hits"] = self._metrics.get("cache_hits", 0) + 1
            status, value = cached
            if status == "ok":
                return value
            raise value
        try:
            value = await self._mcp_call(method, params)
        except Exception as exc:
            self._mcp_cache[key] = ("err", exc)
            raise
        self._mcp_cache[key] = ("ok", value)
        return value

    def _get_semaphore(self) -> asyncio.Semaphore:
        loop = asyncio.get_running_loop()
        if self._semaphore is None or self._semaphore_loop is not loop:
            self._semaphore = asyncio.Semaphore(self.max_concurrency)
            self._semaphore_loop = loop
        return self._semaphore

    def _start_mcp_phase(self) -> None:
        if self._mcp_phase_started_at is None:
            self._mcp_phase_started_at = time.monotonic()

    def _deadline_exceeded(self) -> bool:
        if not self.mcp_deadline_seconds or self._mcp_phase_started_at is None:
            return False
        return (time.monotonic() - self._mcp_phase_started_at) >= self.mcp_deadline_seconds

    @staticmethod
    def _extract_rows(response: Any, single_record: bool = False) -> List[Dict[str, Any]]:
        if isinstance(response, list):
            return [row for row in response if isinstance(row, dict)]
        if not isinstance(response, dict):
            return []
        rows = response.get("results")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
        if single_record:
            record = {k: v for k, v in response.items() if k not in {"results", "unparsed_parts"}}
            return [record] if record else []
        return []

    @staticmethod
    def _step_label(name: str) -> str:
        if name in STEP_LABELS:
            return STEP_LABELS[name]
        prefix, _, suffix = name.partition(":")
        if prefix == "knowledge_objects":
            return f"Knowledge objects ({suffix})"
        if prefix == "index_detail":
            return f"Index detail ({suffix})"
        if prefix == "analytics":
            return f"Analytics ({suffix.replace('_', ' ')})"
        return name.replace("_", " ").capitalize()

    def _record_step(self, outcome: StepOutcome, tool: str = "", duration: float = 0.0) -> None:
        existing = self._step_status.get(outcome.name)
        if existing and existing.get("status") == "ok" and outcome.status == "ok":
            return
        self._step_status[outcome.name] = {
            "status": outcome.status,
            "label": self._step_label(outcome.name),
            "tool": tool,
            "rows": len(outcome.rows),
            "row_limit": outcome.row_limit,
            "truncated": bool(outcome.truncated),
            "error": outcome.error,
            "duration_ms": int(duration * 1000),
        }

    def _schema_for(self, method: str) -> Optional[Dict[str, Any]]:
        schemas = getattr(self, "_tool_schemas", {}) or {}
        if method in schemas:
            return schemas[method]
        for canonical, aliases in (getattr(self, "_tool_aliases", {}) or {}).items():
            if method == canonical or method in aliases:
                for candidate in aliases:
                    if candidate in schemas:
                        return schemas[candidate]
        return None

    def _unsupported_argument(self, method: str, params: Dict[str, Any]) -> Optional[str]:
        """Explain why the advertised input schema rejects these arguments, or None when it accepts them."""
        schema = self._schema_for(method)
        properties = schema.get("properties") if isinstance(schema, dict) else None
        if not isinstance(properties, dict):
            return None
        adapted, _dropped = adapt_tool_arguments(params, schema)
        for key, value in adapted.items():
            spec = properties.get(key)
            allowed = spec.get("enum") if isinstance(spec, dict) else None
            if isinstance(allowed, list) and allowed and isinstance(value, str) and value not in allowed:
                return f"{method} does not offer {key}={value} on this MCP server (supported: {', '.join(str(item) for item in allowed)})"
        return None

    async def _fetch(
        self,
        name: str,
        method: str,
        params: Dict[str, Any],
        *,
        optional: bool = True,
        row_limit: Optional[int] = None,
        rows_mode: str = "results",
    ) -> StepOutcome:
        """Run one MCP-backed discovery step without raising; the outcome carries status and rows."""
        unsupported = self._unsupported_argument(method, params)
        if unsupported:
            outcome = StepOutcome(name=name, status="unsupported", error=unsupported[:500], row_limit=row_limit)
            self._record_step(outcome, method)
            return outcome
        key = self._cache_key(method, params)
        async with self._get_semaphore():
            if optional and key not in self._mcp_cache and self._deadline_exceeded():
                outcome = StepOutcome(
                    name=name,
                    status="skipped",
                    error=f"Skipped after the MCP phase soft deadline ({self.mcp_deadline_seconds:.0f}s) was reached",
                    row_limit=row_limit,
                )
                self._record_step(outcome, method)
                return outcome
            started = time.monotonic()
            try:
                response = await self._cached_mcp_call(method, params)
            except Exception as exc:
                outcome = StepOutcome(name=name, status="error", error=str(exc)[:500], row_limit=row_limit)
                self._record_step(outcome, method, time.monotonic() - started)
                return outcome
            duration = time.monotonic() - started

        if isinstance(response, dict) and response.get("unparsed"):
            excerpt = str(response.get("raw_text", ""))[:200]
            outcome = StepOutcome(
                name=name,
                status="error",
                response=response,
                error=f"MCP response could not be parsed as JSON: {excerpt}",
                row_limit=row_limit,
            )
        else:
            rows = self._extract_rows(response, single_record=(rows_mode == "record"))
            outcome = StepOutcome(
                name=name,
                status="ok",
                rows=rows,
                response=response,
                truncated=bool(row_limit) and len(rows) >= row_limit,
                row_limit=row_limit,
            )
        self._record_step(outcome, method, duration)
        return outcome

    @staticmethod
    def _rows_or_raise(outcome: StepOutcome) -> List[Dict[str, Any]]:
        if outcome.status != "ok":
            raise DiscoveryStepUnavailable(outcome.name, outcome.status, outcome.error)
        return outcome.rows

    @staticmethod
    def _metadata_params(metadata_type: str) -> Dict[str, Any]:
        return {
            "type": metadata_type,
            "index": "*",
            "earliest_time": "-24h",
            "latest_time": "now",
            "row_limit": ROW_LIMITS[metadata_type],
        }

    @staticmethod
    def _knowledge_object_params(ko_type: str) -> Dict[str, Any]:
        return {"type": ko_type, "row_limit": ROW_LIMITS["knowledge_objects"]}

    def _overview_call_specs(self) -> List[Tuple[str, str, Dict[str, Any], Optional[int], str]]:
        """(step name, tool, params, row_limit, rows_mode) for every overview call; discovery reuses them."""
        return [
            ("platform_info", "splunk_get_info", {}, None, "record"),
            ("indexes", "splunk_get_indexes", {"row_limit": ROW_LIMITS["indexes"]}, ROW_LIMITS["indexes"], "results"),
            ("sourcetypes", "splunk_get_metadata", self._metadata_params("sourcetypes"), ROW_LIMITS["sourcetypes"], "results"),
            ("hosts", "splunk_get_metadata", self._metadata_params("hosts"), ROW_LIMITS["hosts"], "results"),
            ("sources", "splunk_get_metadata", self._metadata_params("sources"), ROW_LIMITS["sources"], "results"),
            (
                "knowledge_objects:saved_searches",
                "splunk_get_knowledge_objects",
                self._knowledge_object_params("saved_searches"),
                ROW_LIMITS["knowledge_objects"],
                "results",
            ),
            ("users", "splunk_get_user_info", {}, None, "record"),
            (
                "kv_collections",
                "splunk_get_kv_store_collections",
                {"row_limit": ROW_LIMITS["kv_collections"]},
                ROW_LIMITS["kv_collections"],
                "results",
            ),
            (
                "license_usage_24h",
                "splunk_run_query",
                {"query": LICENSE_USAGE_24H_QUERY, "earliest_time": "-24h", "latest_time": "now", "row_limit": 10},
                None,
                "results",
            ),
        ]

    async def _fetch_spec(self, name: str) -> StepOutcome:
        for spec_name, tool, params, row_limit, rows_mode in self._overview_call_specs():
            if spec_name == name:
                return await self._fetch(
                    spec_name, tool, params,
                    optional=(spec_name != "indexes"),
                    row_limit=row_limit,
                    rows_mode=rows_mode,
                )
        raise KeyError(name)

    def get_step_status(self) -> Dict[str, Dict[str, Any]]:
        """Per-step MCP collection status (ok/error/skipped) recorded during this run."""
        return {name: dict(status) for name, status in getattr(self, "_step_status", {}).items()}

    def get_llm_status(self) -> Dict[str, Dict[str, Any]]:
        """Per-stage LLM enrichment status recorded during this run."""
        return {stage: dict(status) for stage, status in getattr(self, "_llm_status", {}).items()}

    def get_discovery_metrics(self) -> Dict[str, Any]:
        """Run metrics: MCP request counts, cache hits, freshness, and truncation."""
        started = getattr(self, "_mcp_phase_started_at", None)
        overview = getattr(self, "environment_overview", None)
        return {
            "mcp": dict(getattr(self, "_metrics", {})),
            "mcp_deadline_seconds": getattr(self, "mcp_deadline_seconds", DEFAULT_MCP_DEADLINE_SECONDS),
            "mcp_phase_elapsed_seconds": round(time.monotonic() - started, 2) if started is not None else None,
            "freshness": dict(getattr(self, "_freshness", {}) or {}),
            "truncated": dict(getattr(overview, "truncated", {}) or {}) if overview is not None else {},
            "row_limits": dict(ROW_LIMITS),
        }

    def _set_llm_status(self, stage: str, status: str, detail: Any = "", fallback_used: bool = False, **extra: Any) -> None:
        store = getattr(self, "_llm_status", None)
        if not isinstance(store, dict):
            store = {}
            self._llm_status = store
        store[stage] = {
            "status": status,
            "fallback_used": bool(fallback_used),
            "detail": str(detail or "")[:500],
            **extra,
        }

    # ------------------------------------------------------------------
    # Overview
    # ------------------------------------------------------------------

    @staticmethod
    def _license_volume(outcome: StepOutcome) -> Tuple[Optional[float], str]:
        if outcome.status == "skipped":
            return None, f"unavailable: license usage query skipped ({outcome.error})"
        if outcome.status != "ok":
            return None, f"unavailable: license usage query failed ({outcome.error[:200]})"
        total_bytes: Optional[float] = None
        for row in outcome.rows:
            raw = row.get("bytes")
            if raw in (None, ""):
                continue
            total_bytes = (total_bytes or 0.0) + safe_float(raw)
        if total_bytes is None:
            return None, (
                "unavailable: license_usage.log in index=_internal returned no usage rows "
                "(usually visible only to admins on the license manager)"
            )
        return round(total_bytes / 1024 / 1024, 2), "license_usage.log type=Usage, sum(b) over the last 24 hours"

    async def get_quick_overview(self) -> EnvironmentOverview:
        """
        Get a quick overview of the Splunk environment to estimate discovery scope.

        Returns:
            EnvironmentOverview with basic metrics and estimates

        Raises:
            Exception: If the index inventory cannot be retrieved from Splunk
        """
        self._start_mcp_phase()
        specs = self._overview_call_specs()
        async with self._mcp_session_scope():
            await self._refresh_available_tools()
            outcomes = await asyncio.gather(*(
                self._fetch(name, tool, params, optional=(name != "indexes"), row_limit=row_limit, rows_mode=rows_mode)
                for name, tool, params, row_limit, rows_mode in specs
            ))
            by_name: Dict[str, StepOutcome] = {spec[0]: outcome for spec, outcome in zip(specs, outcomes)}
            if by_name["sourcetypes"].status in {"error", "unsupported"}:
                by_name["sourcetypes"] = await self._fetch_sourcetypes()

        index_outcome = by_name["indexes"]
        if index_outcome.status != "ok":
            raise Exception(
                "Unable to retrieve environment information from Splunk. Please verify MCP server connection "
                f"and credentials. Error: {index_outcome.error}"
            )

        info_outcome = by_name["platform_info"]
        system_info = info_outcome.response if info_outcome.status == "ok" and isinstance(info_outcome.response, dict) else {}
        splunk_version = str(system_info.get("version") or "unknown")
        splunk_build = str(system_info.get("build") or "unknown")
        license_state = str(system_info.get("licenseState") or "unknown")
        server_roles = system_info.get("server_roles", [])
        if isinstance(server_roles, str):
            server_roles = [r.strip() for r in server_roles.split(",") if r.strip()]
        elif not isinstance(server_roles, list):
            server_roles = []

        indexes_list = index_outcome.rows
        sourcetypes_list = by_name["sourcetypes"].rows
        hosts_list = by_name["hosts"].rows
        sources_list = by_name["sources"].rows
        ko_list = by_name["knowledge_objects:saved_searches"].rows
        user_list = by_name["users"].rows
        kv_list = by_name["kv_collections"].rows
        self._inventory = {
            "indexes": indexes_list,
            "sourcetypes": sourcetypes_list,
            "hosts": hosts_list,
            "sources": sources_list,
            "saved_searches": ko_list,
            "users": user_list,
            "kv_collections": kv_list,
        }

        truncated = {surface: bool(by_name[step].truncated) for surface, step in SURFACE_STEPS.items()}
        counts = {
            "indexes": len(indexes_list),
            "sourcetypes": len(sourcetypes_list),
            "hosts": len(hosts_list),
            "sources": len(sources_list),
            "knowledge_objects": len(ko_list),
            "kv_collections": len(kv_list),
        }
        count_display = {
            surface: (f"≥{count}" if truncated.get(surface) else str(count))
            for surface, count in counts.items()
        }

        total_index_size_mb = round(sum(safe_float(idx.get("currentDBSizeMB")) for idx in indexes_list), 2)
        volume_mb, volume_source = self._license_volume(by_name["license_usage_24h"])

        authenticated_user = ""
        authenticated_roles: List[str] = []
        if user_list:
            first_user = user_list[0]
            authenticated_user = str(first_user.get("name") or first_user.get("username") or "")
            roles = first_user.get("roles", [])
            if isinstance(roles, str):
                roles = [r.strip() for r in roles.split(",") if r.strip()]
            authenticated_roles = [str(r) for r in roles] if isinstance(roles, list) else []

        estimated_steps = self._estimate_discovery_steps(
            counts["indexes"], counts["sourcetypes"], counts["hosts"], counts["sources"],
            counts["knowledge_objects"], len(user_list), counts["kv_collections"]
        )

        notable_patterns = await self._notable_patterns_with_fallback(indexes_list, sourcetypes_list)

        overview = EnvironmentOverview(
            total_indexes=counts["indexes"],
            total_sourcetypes=counts["sourcetypes"],
            total_hosts=counts["hosts"],
            total_sources=counts["sources"],
            total_knowledge_objects=counts["knowledge_objects"],
            total_users=len(user_list),
            total_kv_collections=counts["kv_collections"],
            data_volume_24h=_format_mb(volume_mb) if volume_mb is not None else None,
            active_sources=counts["sourcetypes"],
            estimated_discovery_steps=estimated_steps,
            estimated_time=self._estimate_time(estimated_steps),
            notable_patterns=notable_patterns,
            splunk_version=splunk_version,
            splunk_build=splunk_build,
            license_state=license_state,
            server_roles=[str(role) for role in server_roles],
            data_volume_24h_mb=volume_mb,
            data_volume_24h_source=volume_source,
            total_index_size_mb=total_index_size_mb,
            truncated=truncated,
            row_limits={surface: ROW_LIMITS[surface] for surface in counts},
            count_display=count_display,
            knowledge_object_counts={"saved_searches": counts["knowledge_objects"]},
            authenticated_user=authenticated_user,
            authenticated_user_roles=authenticated_roles,
        )

        self.environment_overview = overview
        return overview

    @staticmethod
    def _compact_index_rows(rows: List[Dict[str, Any]], limit: int = 50) -> List[Dict[str, Any]]:
        compact = [
            {
                "name": row.get("title") or row.get("name"),
                "events": safe_int(row.get("totalEventCount")),
                "size_mb": round(safe_float(row.get("currentDBSizeMB")), 2),
                "datatype": row.get("datatype", "event"),
                "disabled": is_truthy_flag(row.get("disabled")),
            }
            for row in rows if isinstance(row, dict)
        ]
        compact.sort(key=lambda item: item["events"], reverse=True)
        return compact[:limit]

    @staticmethod
    def _compact_metadata_rows(rows: List[Dict[str, Any]], key: str, limit: int = 50) -> List[Dict[str, Any]]:
        compact = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            timestamp = metadata_recent_epoch(row)
            age = _age_hours(timestamp)
            compact.append({
                "name": row.get(key) or row.get("name") or row.get("title"),
                "events": safe_int(row.get("totalCount")),
                "last_seen_utc": (
                    datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
                    if timestamp and timestamp > 0 else None
                ),
                "age_hours": round(age, 1) if age is not None else None,
            })
        compact.sort(key=lambda item: item["events"], reverse=True)
        return compact[:limit]

    @staticmethod
    def _deterministic_patterns(indexes_list: List[Dict[str, Any]], sourcetypes_list: List[Dict[str, Any]]) -> List[str]:
        patterns: List[str] = []
        top_indexes = [item for item in DiscoveryEngine._compact_index_rows(indexes_list, 3) if item["events"] > 0]
        if top_indexes:
            patterns.append(
                "Largest indexes by event count: "
                + ", ".join(f"{item['name']} ({item['events']:,} events, {item['size_mb']:,.1f} MB)" for item in top_indexes)
            )
        top_sourcetypes = [item for item in DiscoveryEngine._compact_metadata_rows(sourcetypes_list, "sourcetype", 3) if item["events"] > 0]
        if top_sourcetypes:
            patterns.append(
                "Highest event counts among sourcetypes seen in the last 24h: "
                + ", ".join(f"{item['name']} ({item['events']:,} events)" for item in top_sourcetypes)
            )
        empty = [
            idx for idx in indexes_list
            if isinstance(idx, dict) and safe_int(idx.get("totalEventCount")) == 0 and safe_float(idx.get("currentDBSizeMB")) == 0
        ]
        if indexes_list and empty:
            patterns.append(f"{len(empty)} of {len(indexes_list)} indexes contain no events")
        return patterns

    async def _notable_patterns_with_fallback(
        self, indexes_list: List[Dict[str, Any]], sourcetypes_list: List[Dict[str, Any]]
    ) -> List[Any]:
        try:
            patterns = await self._identify_notable_patterns({"results": indexes_list}, {"results": sourcetypes_list})
        except Exception as exc:
            self._set_llm_status("patterns", "failed", detail=str(exc), fallback_used=True)
            return self._deterministic_patterns(indexes_list, sourcetypes_list)
        if patterns:
            return patterns
        status = getattr(self, "_llm_status", {}).get("patterns", {}).get("status", "empty")
        self._set_llm_status("patterns", status, detail="LLM returned no patterns; using discovered facts", fallback_used=True)
        return self._deterministic_patterns(indexes_list, sourcetypes_list)

    async def discover_environment(self) -> AsyncGenerator[DiscoveryResult, None]:
        """
        Perform detailed recursive discovery of the Splunk environment.

        Independent MCP calls run concurrently (bounded by max_concurrency) while
        results are yielded in a fixed, deterministic order. A failed or skipped
        step yields a single step_status result instead of aborting the run.

        Yields:
            DiscoveryResult objects for each discovery step
        """
        if not self.environment_overview:
            raise ValueError("Must call get_quick_overview() first")

        self._start_mcp_phase()
        step = 0
        plan: List[Tuple[str, str, Any]] = [
            ("indexes", KIND_INDEX, self._discover_indexes),
            ("sourcetypes", KIND_SOURCETYPE, self._discover_sourcetypes),
            ("hosts", KIND_HOST, self._discover_hosts),
            ("sources", KIND_SOURCE, self._discover_sources),
            *[
                (f"knowledge_objects:{ko_type}", KIND_KNOWLEDGE_OBJECT, functools.partial(self._discover_knowledge_objects_by_type, ko_type))
                for ko_type in KNOWLEDGE_OBJECT_TYPES
            ],
            ("index_details", KIND_INDEX_DETAIL, self._discover_detailed_index_info),
            ("users", KIND_USER, self._discover_users),
            ("kv_collections", KIND_KV_COLLECTION, self._discover_kv_collections),
            ("analytics", KIND_ANALYTICS, self._run_advanced_analytics),
        ]

        async with self._mcp_session_scope():
            tasks = [asyncio.ensure_future(factory()) for _, _, factory in plan]
            try:
                for (name, kind, _), task in zip(plan, tasks):
                    try:
                        items = await task
                    except DiscoveryStepUnavailable as exc:
                        step += 1
                        result = self._step_status_result(step, exc.step or name, exc.status, str(exc))
                        self.discovery_results.append(result)
                        yield result
                        continue
                    except Exception as exc:
                        self._step_status[name] = {
                            "status": "error",
                            "label": self._step_label(name),
                            "tool": "",
                            "rows": 0,
                            "row_limit": None,
                            "truncated": False,
                            "error": str(exc)[:500],
                            "duration_ms": 0,
                        }
                        step += 1
                        result = self._step_status_result(step, name, "error", str(exc))
                        self.discovery_results.append(result)
                        yield result
                        continue

                    for item in items or []:
                        if not isinstance(item, dict):
                            continue
                        step += 1
                        result = await self._build_discovery_result(step, kind, item)
                        self.discovery_results.append(result)
                        yield result

                    if name == "analytics":
                        for step_name, status in list(self._step_status.items()):
                            if step_name.startswith("analytics:") and status.get("status") in {"error", "skipped"}:
                                step += 1
                                result = self._step_status_result(step, step_name, status["status"], status.get("error", ""))
                                self.discovery_results.append(result)
                                yield result
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        self._update_knowledge_object_counts()

    def _step_status_result(self, step: int, name: str, status: str, error: str) -> DiscoveryResult:
        label = self._step_label(name)
        if status == "skipped":
            finding = f"⏭️  {label} skipped: {error}"
            state = "skipped"
        elif status == "unsupported":
            finding = f"ℹ️  {label} not collected: {error}"
            state = "not supported"
        else:
            finding = f"⚠️  {label} could not be collected: {error}"
            state = "unavailable"
        return DiscoveryResult(
            step=step,
            description=f"Discovery step {state}: {label}",
            data={"discovery_step": name, "status": status, "error": str(error)[:500]},
            interesting_findings=[finding[:600]],
            timestamp=datetime.now(),
            kind=KIND_STEP_STATUS,
        )

    async def _build_discovery_result(self, step: int, kind: str, item: Dict[str, Any]) -> DiscoveryResult:
        if kind == KIND_INDEX:
            description = f"Analyzing index: {item.get('title', item.get('name', 'unknown'))}"
            findings = await self._analyze_index_findings(item)
        elif kind == KIND_SOURCETYPE:
            description = f"Analyzing sourcetype: {item.get('sourcetype', 'unknown')}"
            findings = await self._analyze_sourcetype_findings(item)
        elif kind == KIND_HOST:
            description = f"Analyzing host: {item.get('host', 'unknown')}"
            findings = await self._analyze_host_findings(item)
        elif kind == KIND_SOURCE:
            description = f"Analyzing source: {item.get('source', 'unknown')}"
            findings = await self._analyze_source_findings(item)
        elif kind == KIND_KNOWLEDGE_OBJECT:
            ko_type = item.get("ko_type", "saved_searches")
            description = f"Analyzing {ko_type}: {item.get('name', item.get('title', 'unknown'))}"
            findings = await self._analyze_knowledge_object_findings(item, ko_type)
        elif kind == KIND_INDEX_DETAIL:
            description = f"Deep-dive index analysis: {item.get('name', item.get('title', 'unknown'))}"
            findings = await self._analyze_detailed_index_findings(item)
        elif kind == KIND_USER:
            description = f"Analyzing user: {item.get('name', item.get('username', 'unknown'))}"
            findings = await self._analyze_user_findings(item)
        elif kind == KIND_KV_COLLECTION:
            description = f"Analyzing KV collection: {item.get('name', item.get('title', 'unknown'))}"
            findings = await self._analyze_kv_findings(item)
        else:
            description = item.get('description', 'Advanced analysis')
            findings = list(item.get('findings', []) or [])
        return DiscoveryResult(
            step=step,
            description=description,
            data=item,
            interesting_findings=findings,
            timestamp=datetime.now(),
            kind=kind,
        )

    def _update_knowledge_object_counts(self) -> None:
        overview = self.environment_overview
        if overview is None:
            return
        counts: Dict[str, int] = {}
        for ko_type in KNOWLEDGE_OBJECT_TYPES:
            status = self._step_status.get(f"knowledge_objects:{ko_type}", {})
            if status.get("status") == "ok":
                counts[ko_type] = safe_int(status.get("rows"))
                if status.get("truncated"):
                    overview.truncated[f"knowledge_objects:{ko_type}"] = True
        if not counts:
            return
        overview.knowledge_object_counts = counts
        total = sum(count for ko_type, count in counts.items() if ko_type not in KNOWLEDGE_OBJECT_TOTAL_EXCLUDES)
        overview.total_knowledge_objects = total
        any_truncated = any(
            overview.truncated.get(f"knowledge_objects:{ko_type}") for ko_type in counts
            if ko_type not in KNOWLEDGE_OBJECT_TOTAL_EXCLUDES
        )
        overview.truncated["knowledge_objects"] = bool(any_truncated or overview.truncated.get("knowledge_objects"))
        overview.count_display["knowledge_objects"] = f"≥{total}" if overview.truncated["knowledge_objects"] else str(total)

    # ------------------------------------------------------------------
    # Classification and LLM enrichment
    # ------------------------------------------------------------------

    def _discovery_summary(self) -> Dict[str, Any]:
        results = getattr(self, "discovery_results", []) or []
        cache = getattr(self, "_summary_cache", None)
        if cache is not None and cache[0] == len(results):
            return cache[1]
        summary = self.local_analyzer.summarize_discovery(results)
        if not isinstance(summary, dict):
            summary = {}
        self._summary_cache = (len(results), summary)
        return summary

    async def classify_data(self) -> Dict[str, Any]:
        """
        Classify discovered data into categories and patterns using local analysis.

        Returns:
            Classification results with categories and insights
        """
        discovery_summary = self._discovery_summary()

        self.discovery_data = {
            'detailed_discovery': {
                'sources': [
                    {
                        'sourcetype': result.data.get('sourcetype'),
                        'name': result.data.get('sourcetype') or result.data.get('title') or result.data.get('name'),
                        'source': result.data.get('sourcetype') or result.data.get('title'),
                        'count': safe_int(result.data.get('totalCount')),
                        'index': result.data.get('index', 'unknown')
                    }
                    for result in self.discovery_results
                    if isinstance(result.data, dict) and result_kind(result) == KIND_SOURCETYPE
                ]
            },
            'summary': discovery_summary
        }

        sourcetype_analysis = discovery_summary.get('sourcetype_analysis', {})
        index_analysis = discovery_summary.get('index_analysis', {})
        category_details = sourcetype_analysis.get('category_details', {})
        category_totals = sourcetype_analysis.get('category_totals', {})
        capability_gaps = discovery_summary.get('capability_gaps', {})
        data_quality = discovery_summary.get('data_quality', {})
        missing_categories = capability_gaps.get('missing_categories', [])

        def _source_count(category: str) -> int:
            totals = category_totals.get(category)
            if isinstance(totals, dict):
                return safe_int(totals.get("count"))
            return len(category_details.get(category, []))

        def _volume(category: str) -> str:
            totals = category_totals.get(category)
            if isinstance(totals, dict):
                return self._calculate_volume([], total_events=safe_int(totals.get("events")))
            return self._calculate_volume(category_details.get(category, []))

        classifications = {}

        security_sources = category_details.get('Security', [])
        security_patterns = []
        security_use_cases = []

        for src in security_sources[:5]:
            st_name = src.get('name', '')
            if 'wineventlog:security' in st_name.lower():
                security_patterns.append("Windows Security Event Logs - user authentication, logon/logoff, access control")
                security_use_cases.append("User behavior monitoring and threat detection")
            elif 'firewall' in st_name.lower():
                security_patterns.append("Network firewall logs - traffic monitoring and threat prevention")
                security_use_cases.append("Network intrusion detection and traffic analysis")
            elif 'auth' in st_name.lower():
                security_patterns.append(f"{st_name} - authentication and access control")
                security_use_cases.append("Authentication failure analysis and account security")

        if not security_patterns:
            if security_sources:
                security_patterns = [f"{src.get('name')} - security-related data" for src in security_sources[:5]]
                security_use_cases = ["Security event review and alerting on discovered security sources"]
            else:
                security_patterns = ["No security data sources identified"]
                security_use_cases = ["Add Windows Security logs, firewall logs, or authentication logs"]

        classifications['Security'] = {
            "source_count": _source_count('Security'),
            "volume": _volume('Security'),
            "quality_score": f"{data_quality.get('score', 0)}%",
            "key_patterns": list(dict.fromkeys(security_patterns)),
            "recommended_use_cases": list(dict.fromkeys(security_use_cases)),
            "sources": [s.get('name') for s in security_sources[:10]],
            "missing_capabilities": ['security'] if 'security' in missing_categories else [],
            "recommendations": [rec for rec in capability_gaps.get('recommendations', []) if 'security' in rec.lower() or 'firewall' in rec.lower()],
            "index_analysis": index_analysis
        }

        infra_sources = category_details.get('Infrastructure', [])
        infra_patterns = []
        infra_use_cases = []

        for src in infra_sources[:5]:
            st_name = src.get('name', '')
            if 'wineventlog:system' in st_name.lower():
                infra_patterns.append("Windows System Event Logs - OS health, services, hardware events")
                infra_use_cases.append("System health monitoring and failure prediction")
            elif 'wineventlog:application' in st_name.lower():
                infra_patterns.append("Windows Application Event Logs - application errors and warnings")
                infra_use_cases.append("Application performance monitoring and error tracking")
            elif 'cpu' in st_name.lower() or 'memory' in st_name.lower():
                infra_patterns.append(f"{st_name} - Performance metrics and resource utilization")
                infra_use_cases.append("Capacity planning and performance optimization")
            elif 'syslog' in st_name.lower() or 'unix' in st_name.lower():
                infra_patterns.append(f"{st_name} - Unix/Linux system logs")
                infra_use_cases.append("Linux system monitoring and troubleshooting")

        if not infra_patterns:
            if infra_sources:
                infra_patterns = [f"{src.get('name')} - operational data" for src in infra_sources[:5]]
                infra_use_cases = ["Operational health dashboards for discovered sources"]
            else:
                infra_patterns = ["No infrastructure data sources identified"]
                infra_use_cases = ["Add system logs, performance metrics, or application logs"]

        classifications['Infrastructure'] = {
            "source_count": _source_count('Infrastructure'),
            "volume": _volume('Infrastructure'),
            "quality_score": f"{data_quality.get('score', 0)}%",
            "key_patterns": list(dict.fromkeys(infra_patterns)),
            "recommended_use_cases": list(dict.fromkeys(infra_use_cases)),
            "sources": [s.get('name') for s in infra_sources[:10]],
            "missing_platforms": capability_gaps.get('missing_platforms', []),
            "recommendations": [rec for rec in capability_gaps.get('recommendations', []) if any(term in rec.lower() for term in ['cloud', 'database', 'network'])],
            "sourcetype_analysis": sourcetype_analysis
        }

        business_sources = category_details.get('Business', [])
        business_patterns = [f"{src.get('name', '')} - Business application data" for src in business_sources[:5]]
        business_use_cases = ["Business process monitoring and analytics"] if business_sources else []

        if not business_patterns:
            business_patterns = ["No business data sources identified"]
            business_use_cases = ["Add CRM, ERP, or business application logs for KPI tracking"]

        classifications['Business'] = {
            "source_count": _source_count('Business'),
            "volume": _volume('Business'),
            "quality_score": f"{data_quality.get('score', 0)}%",
            "key_patterns": list(dict.fromkeys(business_patterns)),
            "recommended_use_cases": list(dict.fromkeys(business_use_cases)),
            "sources": [s.get('name') for s in business_sources[:10]],
            "missing_capabilities": ['business'] if 'business' in missing_categories else [],
            "recommendations": [rec for rec in capability_gaps.get('recommendations', []) if 'business' in rec.lower()],
            "sourcetype_analysis": sourcetype_analysis
        }

        compliance_sources = category_details.get('Compliance', [])
        compliance_patterns = [f"{src.get('name', '')} - Audit and compliance data" for src in compliance_sources[:5]]
        compliance_use_cases = ["Regulatory compliance and audit reporting"] if compliance_sources else []

        if not compliance_patterns:
            compliance_patterns = ["No compliance-specific data sources identified"]
            compliance_use_cases = ["Add audit logs for PCI-DSS, HIPAA, or SOX compliance"]

        classifications['Compliance'] = {
            "source_count": _source_count('Compliance'),
            "volume": _volume('Compliance'),
            "quality_score": f"{data_quality.get('score', 0)}%",
            "key_patterns": list(dict.fromkeys(compliance_patterns)),
            "recommended_use_cases": list(dict.fromkeys(compliance_use_cases)),
            "sources": [s.get('name') for s in compliance_sources[:10]],
            "missing_capabilities": ['compliance'] if 'compliance' in missing_categories else [],
            "recommendations": data_quality.get('recommendations', []),
            "data_quality": data_quality
        }

        return classifications

    def _calculate_volume(self, sources: List[Dict], total_events: Optional[int] = None) -> str:
        """Describe event volume from sourcetype metadata (buckets active in the last 24 hours)."""
        if total_events is None:
            total_events = sum(safe_int(src.get('events')) for src in sources)

        if total_events == 0:
            return "No data"
        elif total_events < 10000:
            return f"~{total_events:,} events (Low volume)"
        elif total_events < 100000:
            return f"~{total_events:,} events (Medium volume)"
        elif total_events < 1000000:
            return f"~{total_events:,} events (High volume)"
        else:
            return f"~{total_events:,} events (Very high volume)"

    async def _fallback_classification(self) -> Dict[str, Any]:
        """Fallback classification; kept for backwards compatibility."""
        return await self.classify_data()

    def _compact_overview(self) -> Dict[str, Any]:
        overview = getattr(self, "environment_overview", None)
        if overview is None:
            return {}
        data = dict(overview.__dict__) if hasattr(overview, "__dict__") else dict(overview or {})
        patterns = data.get("notable_patterns") or []
        data["notable_patterns"] = [
            (json.dumps(item, default=str) if isinstance(item, (dict, list)) else str(item))[:300] for item in patterns[:5]
        ] if isinstance(patterns, list) else []
        return data

    def _step_issue_list(self) -> List[Dict[str, Any]]:
        return [
            {"step": name, "status": status.get("status"), "error": str(status.get("error", ""))[:200]}
            for name, status in getattr(self, "_step_status", {}).items()
            if status.get("status") in {"error", "skipped"}
        ]

    @staticmethod
    def _titled_items(values: Any) -> List[Dict[str, Any]]:
        """Keep mappings with a title, or a name plus a description (copied into ``title``)."""
        items: List[Dict[str, Any]] = []
        for item in values if isinstance(values, list) else []:
            if not isinstance(item, dict):
                continue
            if str(item.get("title") or "").strip():
                items.append(item)
                continue
            name = str(item.get("name") or item.get("use_case") or "").strip()
            described = any(
                str(item.get(key) or "").strip()
                for key in ("description", "summary", "details", "scenario", "business_value")
            )
            if name and described:
                items.append({**item, "title": name})
        return items

    @classmethod
    def _parse_llm_list(cls, result: Any, preferred_key: str) -> Tuple[List[Dict[str, Any]], str]:
        """Extract titled items from an LLM result and classify the response.

        Untitled entries are ignored, so a nested list such as one use case's
        ``data_sources`` is never mistaken for the requested list; a lone item
        (what a truncated array can parse down to) counts as a list of one.
        """
        if isinstance(result, list):
            items = cls._titled_items(result)
            return items, "ok" if items else "empty"
        if _is_unstructured_llm_result(result):
            return [], "unstructured"
        if isinstance(result, dict):
            preferred = result.get(preferred_key)
            if isinstance(preferred, list):
                items = cls._titled_items(preferred)
                return items, "ok" if items else "empty"
            for value in result.values():
                items = cls._titled_items(value)
                if items:
                    return items, "ok"
            single = cls._titled_items([result])
            if single:
                return single, "ok"
            return [], "empty"
        return [], "empty"

    async def generate_recommendations(self) -> List[Dict[str, Any]]:
        """
        Generate use case recommendations based on discovered data.

        LLM failures and unusable replies fall back to deterministic
        recommendations derived from discovered facts; the outcome is
        recorded in get_llm_status()["recommendations"].

        Returns:
            List of recommended use cases with priorities and details
        """
        discovery_summary = self._discovery_summary()
        results = getattr(self, "discovery_results", []) or []

        analysis_data = _shrink_for_prompt({
            "environment_overview": self._compact_overview(),
            "discovery_summary": discovery_summary,
            "discovery_step_issues": self._step_issue_list(),
            "total_steps": len(results),
            "total_interesting_findings": sum(len(getattr(r, "interesting_findings", []) or []) for r in results),
        })

        try:
            recommendations_result = await self.llm_client.analyze_data(analysis_data, "recommendations")
        except Exception as exc:
            fallback = self._build_fallback_recommendations(discovery_summary)
            self._set_llm_status("recommendations", "failed", detail=str(exc), fallback_used=True, items=len(fallback))
            return fallback

        recommendations, status = self._parse_llm_list(recommendations_result, "recommendations")
        if recommendations:
            self._set_llm_status("recommendations", "ok", items=len(recommendations))
            return recommendations

        fallback = self._build_fallback_recommendations(discovery_summary)
        detail = ""
        if status == "unstructured":
            detail = str(recommendations_result.get("analysis", ""))[:500]
        self._set_llm_status("recommendations", status, detail=detail, fallback_used=True, items=len(fallback))
        return fallback

    def _build_fallback_recommendations(self, discovery_summary: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Deterministic recommendations grounded only in discovered facts."""
        summary = discovery_summary if isinstance(discovery_summary, dict) else {}
        recommendations: List[Dict[str, Any]] = []

        def add(title: str, description: str, priority: str, category: str, actions: str, evidence: List[str]) -> None:
            recommendations.append({
                "title": title,
                "description": description,
                "priority": priority,
                "category": category,
                "suggested_actions": actions,
                "evidence": evidence[:10],
                "generated_by": "local_analysis",
            })

        freshness = getattr(self, "_freshness", {}) or {}
        stale = list(freshness.get("stale_indexes", []) or [])
        if stale:
            add(
                "Investigate indexes that stopped receiving data",
                f"{len(stale)} index(es) hold historical events but received none in the last 24 hours: "
                + ", ".join(stale[:10]) + (" ..." if len(stale) > 10 else ""),
                "high",
                "Data Quality",
                "Check forwarder connectivity, inputs, and HEC tokens feeding these indexes; confirm whether retirement was intentional.",
                [f"index={name}" for name in stale[:10]],
            )

        for result in getattr(self, "discovery_results", []) or []:
            if result_kind(result) != KIND_INDEX_DETAIL or not isinstance(result.data, dict):
                continue
            usage_pct = self._index_capacity_pct(result.data)
            if usage_pct is not None and usage_pct > 80:
                name = result.data.get("name") or result.data.get("title") or "unknown"
                add(
                    f"Index {name} is near its size cap",
                    f"Index {name} uses {usage_pct:.0f}% of maxTotalDataSizeMB; older buckets will be frozen early.",
                    "high",
                    "Performance",
                    "Increase maxTotalDataSizeMB or adjust retention for this index.",
                    [f"index={name} usage={usage_pct:.0f}%"],
                )

        for name, status in getattr(self, "_step_status", {}).items():
            if status.get("status") not in {"error", "skipped"} or name.startswith("index_detail:"):
                continue
            label = status.get("label") or self._step_label(name)
            add(
                f"Restore discovery visibility: {label}",
                f"{label} could not be collected ({status.get('error', 'unknown error')}); findings for this surface are incomplete.",
                "medium" if name in SURFACE_STEPS.values() or name == "platform_info" else "low",
                "Data Quality",
                "Verify the MCP tool is enabled and the service account has the required capabilities, then re-run discovery.",
                [f"step={name} status={status.get('status')}"],
            )

        data_quality = summary.get("data_quality", {}) if isinstance(summary.get("data_quality"), dict) else {}
        for issue, rec in zip(data_quality.get("issues", []) or [], data_quality.get("recommendations", []) or []):
            add(issue, rec, "medium", "Data Quality", rec, [issue])

        gaps = summary.get("capability_gaps", {}) if isinstance(summary.get("capability_gaps"), dict) else {}
        for rec in gaps.get("recommendations", []) or []:
            add(
                rec,
                f"No discovered sourcetype matched this monitoring area. {rec}.",
                "low",
                "Coverage",
                rec,
                [f"detected platforms: {', '.join(gaps.get('detected_platforms', []) or []) or 'none'}"],
            )

        overview = getattr(self, "environment_overview", None)
        truncated = [surface for surface, flag in (getattr(overview, "truncated", {}) or {}).items() if flag] if overview else []
        if truncated:
            add(
                "Discovery inventory reached row limits",
                "Counts for " + ", ".join(truncated) + " are lower bounds because the MCP row limit was reached.",
                "low",
                "Data Quality",
                "Scope discovery to specific indexes or raise row limits to capture the full inventory.",
                [f"{surface} truncated" for surface in truncated],
            )

        return recommendations[:12]

    async def generate_suggested_use_cases(self) -> List[Dict[str, Any]]:
        """
        Generate creative, cross-functional use cases based on data source combinations.

        Returns:
            List of sophisticated use cases that leverage multiple data sources
        """
        discovery_summary = self._discovery_summary()
        data_source_analysis = self._analyze_data_source_combinations()

        use_case_data = _shrink_for_prompt({
            "environment_overview": self._compact_overview(),
            "data_source_combinations": data_source_analysis,
            "discovery_summary": discovery_summary,
            "prompt_guidance": (
                "Generate cross-functional use cases that combine at least two of the discovered data sources listed above. "
                "Only reference sourcetypes, sources, and indexes that appear in this payload. For each use case provide: "
                "title, description, data_sources, business_value, implementation_complexity, success_metrics, scenario, category."
            ),
        })

        try:
            use_cases_result = await self.llm_client.analyze_data(use_case_data, "creative_use_cases")
        except Exception as exc:
            fallback = self._generate_creative_fallback_use_cases()
            self._set_llm_status("creative_use_cases", "failed", detail=str(exc), fallback_used=True, items=len(fallback))
            return fallback

        use_cases, status = self._parse_llm_list(use_cases_result, "use_cases")
        if use_cases:
            self._set_llm_status("creative_use_cases", "ok", items=len(use_cases))
            return use_cases

        fallback = self._generate_creative_fallback_use_cases()
        detail = str(use_cases_result.get("analysis", ""))[:500] if status == "unstructured" else ""
        self._set_llm_status("creative_use_cases", status, detail=detail, fallback_used=True, items=len(fallback))
        return fallback

    def get_all_results(self) -> List[DiscoveryResult]:
        """Get all discovery results."""
        return self.discovery_results

    def _get_source_count(self, sourcetype):
        """Helper method to get formatted event count for a specific source type."""
        if not self.discovery_data or 'detailed_discovery' not in self.discovery_data:
            return "events"

        detailed = self.discovery_data['detailed_discovery']
        if isinstance(detailed, dict) and 'sources' in detailed:
            for source in detailed['sources']:
                if isinstance(source, dict):
                    source_name = source.get('sourcetype') or source.get('name') or source.get('source')
                    if source_name == sourcetype:
                        count = safe_int(source.get('count'))
                        if count > 1000:
                            return f"{count / 1000:.0f}K+"
                        return str(count)

        return "events"

    def _get_actual_data_sources(self) -> Dict[str, Any]:
        """Get summary of actual discovered data sources."""
        if not self.discovery_data or 'detailed_discovery' not in self.discovery_data:
            return {}

        sources = {}
        detailed = self.discovery_data['detailed_discovery']

        if isinstance(detailed, dict) and 'sources' in detailed:
            for source in detailed['sources']:
                if isinstance(source, dict):
                    source_name = source.get('sourcetype') or source.get('name') or source.get('source')
                    if source_name:
                        sources[source_name] = {
                            'count': safe_int(source.get('count')),
                            'index': source.get('index', 'unknown')
                        }

        return sources

    _COMBINATION_TERMS: Dict[str, set] = {
        "security": {"security", "auth", "authentication", "login", "logon", "secure", "firewall", "vpn",
                     "certificate", "ssl", "ids", "ips", "malware", "antivirus", "edr", "sysmon", "threat"},
        "user_activity": {"user", "users", "session", "login", "logon", "logoff", "activity", "audit"},
        "infrastructure": {"system", "server", "cpu", "memory", "disk", "performance", "perfmon", "uptime",
                           "vmstat", "iostat", "syslog", "metrics", "df"},
        "application": {"application", "app", "web", "api", "service", "error", "exception", "access",
                        "iis", "nginx", "apache", "tomcat"},
        "network": {"network", "interface", "interfaces", "bandwidth", "connection", "dns", "dhcp",
                    "netflow", "firewall", "router", "switch", "traffic"},
        "location": {"geo", "gps", "location"},
        "communication": {"chat", "teams", "slack", "email", "mail", "smtp", "exchange", "meeting",
                          "webex", "collaboration"},
        "hr_business": {"hr", "workday", "sap", "crm", "erp", "salesforce", "transaction", "order", "billing"},
    }

    def _analyze_data_source_combinations(self) -> Dict[str, Any]:
        """Group discovered data sources into categories using word-boundary name matching."""
        data_sources: Dict[str, List[Dict[str, Any]]] = {category: [] for category in self._COMBINATION_TERMS}
        seen: Dict[str, set] = {category: set() for category in self._COMBINATION_TERMS}
        name_keys = {KIND_SOURCETYPE: "sourcetype", KIND_SOURCE: "source", KIND_INDEX: "title"}

        for result in getattr(self, "discovery_results", []) or []:
            kind = result_kind(result)
            if kind not in name_keys or not isinstance(result.data, dict):
                continue
            name = result.data.get(name_keys[kind]) or result.data.get("name")
            if not name:
                continue
            tokens = set(_name_tokens(name))
            events = safe_int(result.data.get("totalCount") if kind != KIND_INDEX else result.data.get("totalEventCount"))
            for category, terms in self._COMBINATION_TERMS.items():
                if tokens & terms and (kind, name) not in seen[category]:
                    seen[category].add((kind, name))
                    data_sources[category].append({"name": str(name), "kind": kind, "events": events})

        for entries in data_sources.values():
            entries.sort(key=lambda item: item["events"], reverse=True)

        return {
            "categories": {category: entries[:25] for category, entries in data_sources.items()},
            "category_counts": {category: len(entries) for category, entries in data_sources.items()},
            "total_sources": sum(len(entries) for entries in data_sources.values()),
            "combinations_possible": len([entries for entries in data_sources.values() if entries]),
        }

    def _extract_use_cases_from_analysis(self, analysis_text: str) -> List[Dict[str, Any]]:
        """Extract structured use cases from analysis text."""
        use_cases = []
        current_use_case = None

        for line in str(analysis_text or "").split('\n'):
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith('-') or line.startswith('*')):
                if current_use_case:
                    use_cases.append(current_use_case)
                current_use_case = {
                    "title": line.split('.', 1)[-1].strip() if '.' in line else line,
                    "description": "",
                    "data_sources": [],
                    "category": "Cross-functional",
                    "generated_by": "llm_unstructured",
                }
            elif current_use_case and line:
                current_use_case["description"] += line + " "

        if current_use_case:
            use_cases.append(current_use_case)

        return use_cases if use_cases else self._generate_creative_fallback_use_cases()

    def _discovered_sourcetype_events(self) -> Dict[str, int]:
        events: Dict[str, int] = {}
        for result in getattr(self, "discovery_results", []) or []:
            if result_kind(result) == KIND_SOURCETYPE and isinstance(result.data, dict):
                name = result.data.get("sourcetype")
                if name:
                    events[str(name)] = max(events.get(str(name), 0), safe_int(result.data.get("totalCount")))
        if not events:
            for row in (getattr(self, "_inventory", {}) or {}).get("sourcetypes", []) or []:
                name = row.get("sourcetype") if isinstance(row, dict) else None
                if name:
                    events[str(name)] = safe_int(row.get("totalCount"))
        return events

    def _discovered_index_events(self) -> Dict[str, int]:
        events: Dict[str, int] = {}
        for result in getattr(self, "discovery_results", []) or []:
            if result_kind(result) == KIND_INDEX and isinstance(result.data, dict):
                name = result.data.get("title") or result.data.get("name")
                if name:
                    events[str(name)] = safe_int(result.data.get("totalEventCount"))
        if not events:
            for row in (getattr(self, "_inventory", {}) or {}).get("indexes", []) or []:
                name = (row.get("title") or row.get("name")) if isinstance(row, dict) else None
                if name:
                    events[str(name)] = safe_int(row.get("totalEventCount"))
        return events

    _USE_CASE_CATALOG: List[Dict[str, Any]] = [
        {
            "id": "windows_security",
            "title": "Windows Authentication and Account Monitoring",
            "category": "Security & Risk Management",
            "prefixes": ("wineventlog:security", "xmlwineventlog:security"),
            "description": "Track failed and successful logons, account lockouts, and privilege use.",
            "scenario": "Alert when one account or source produces repeated failed logons (EventCode 4625) or lockouts (EventCode 4740) in a short window.",
            "success_metrics": ["Failed logon alerts triaged", "Mean time to detect brute-force activity", "Lockout volume trend"],
            "complexity": "Medium",
        },
        {
            "id": "linux_auth",
            "title": "Linux Authentication and Privilege Monitoring",
            "category": "Security & Risk Management",
            "exact": {"linux_secure", "linux:auth", "auth", "secure"},
            "prefixes": ("linux_secure", "linux:auth"),
            "description": "Monitor SSH logons, sudo usage, and authentication failures on Linux hosts.",
            "scenario": "Detect repeated SSH failures followed by a success from the same source address.",
            "success_metrics": ["SSH failure alerts", "Unexpected sudo usage reviewed"],
            "complexity": "Low-Medium",
        },
        {
            "id": "network_security",
            "title": "Firewall and Network Traffic Monitoring",
            "category": "Network Security",
            "prefixes": ("pan:", "cisco:asa", "cisco:ftd", "fgt_", "fortinet", "fortigate", "juniper", "checkpoint", "opnsense", "pfsense"),
            "tokens": {"firewall", "netflow", "traffic"},
            "description": "Analyze allowed and blocked connections, top talkers, and policy hits.",
            "scenario": "Flag sources with a sudden spike in denied connections or new destination ports.",
            "success_metrics": ["Blocked-connection anomalies investigated", "Firewall rule hit coverage"],
            "complexity": "Medium",
        },
        {
            "id": "web_activity",
            "title": "Web Traffic and Error Rate Monitoring",
            "category": "Application Performance",
            "prefixes": ("access_combined", "access_common", "iis", "ms:iis", "nginx", "apache", "tomcat"),
            "description": "Track request volume, HTTP status distribution, and latency for web services.",
            "scenario": "Alert when the share of HTTP 5xx responses exceeds its normal baseline.",
            "success_metrics": ["5xx error rate", "Requests per minute baseline", "Top failing URIs"],
            "complexity": "Low-Medium",
        },
        {
            "id": "cloud_audit",
            "title": "Cloud Control-Plane Audit Monitoring",
            "category": "Cloud Security",
            "prefixes": ("aws:cloudtrail", "aws:config", "azure:", "mscs:", "o365", "ms:o365", "gcp:", "google:"),
            "description": "Review administrative API activity, configuration changes, and console logons in cloud accounts.",
            "scenario": "Detect IAM policy changes or console logons without MFA.",
            "success_metrics": ["Privileged API calls reviewed", "Unauthorized configuration changes detected"],
            "complexity": "Medium",
        },
        {
            "id": "host_performance",
            "title": "Host Performance and Capacity Monitoring",
            "category": "Operational Excellence",
            "exact": {"cpu", "vmstat", "iostat", "df", "top", "ps", "interfaces"},
            "prefixes": ("perfmon", "linux:cpu", "linux:mem", "unix:", "collectd"),
            "description": "Trend CPU, memory, disk, and interface utilization to anticipate capacity issues.",
            "scenario": "Warn when a host's CPU or disk utilization stays above threshold for a sustained period.",
            "success_metrics": ["Hosts above capacity thresholds", "Capacity incidents avoided"],
            "complexity": "Low-Medium",
        },
        {
            "id": "windows_system",
            "title": "Windows System and Application Health",
            "category": "Operational Excellence",
            "prefixes": ("wineventlog:system", "wineventlog:application", "xmlwineventlog:system", "xmlwineventlog:application"),
            "description": "Monitor unexpected shutdowns, service failures, and application errors on Windows hosts.",
            "scenario": "Alert on unexpected shutdowns (EventCode 6008) and recurring application crashes.",
            "success_metrics": ["Unexpected shutdowns per week", "Recurring application errors resolved"],
            "complexity": "Low",
        },
        {
            "id": "syslog_ops",
            "title": "Syslog Error and Change Monitoring",
            "category": "Operational Excellence",
            "exact": {"syslog"},
            "prefixes": ("syslog", "linux_messages_syslog"),
            "description": "Surface error, critical, and configuration-change messages from syslog senders.",
            "scenario": "Alert when a device starts emitting critical-severity syslog messages.",
            "success_metrics": ["Critical syslog events triaged", "Devices with recurring errors"],
            "complexity": "Low",
        },
        {
            "id": "dns",
            "title": "DNS Query Monitoring",
            "category": "Network Security",
            "tokens": {"dns"},
            "description": "Profile DNS query volume, rare domains, and failed lookups.",
            "scenario": "Detect hosts querying newly seen or algorithmically generated domains.",
            "success_metrics": ["Suspicious domain lookups investigated", "NXDOMAIN rate baseline"],
            "complexity": "Medium",
        },
    ]

    @staticmethod
    def _catalog_matches(entry: Dict[str, Any], sourcetype: str) -> bool:
        lowered = sourcetype.lower()
        if lowered in entry.get("exact", set()):
            return True
        if any(lowered.startswith(prefix) for prefix in entry.get("prefixes", ())):
            return True
        tokens = entry.get("tokens")
        return bool(tokens and set(_name_tokens(lowered)) & tokens)

    def _generate_creative_fallback_use_cases(self) -> List[Dict[str, Any]]:
        """Use cases grounded only in sourcetypes and indexes that discovery actually observed."""
        sourcetype_events = self._discovered_sourcetype_events()
        index_events = self._discovered_index_events()
        use_cases: List[Dict[str, Any]] = []
        matched_by_category: Dict[str, List[str]] = {}

        def evidence_for(names: List[str]) -> List[str]:
            return [f"sourcetype={name}: {sourcetype_events.get(name, 0):,} events (active in the last 24h)" for name in names]

        for entry in self._USE_CASE_CATALOG:
            matched = sorted(
                (name for name in sourcetype_events if self._catalog_matches(entry, name)),
                key=lambda name: sourcetype_events.get(name, 0),
                reverse=True,
            )
            matched = [name for name in matched if sourcetype_events.get(name, 0) > 0] or matched
            if not matched:
                continue
            top = matched[:5]
            matched_by_category.setdefault(entry["category"], []).extend(top)
            use_cases.append({
                "title": entry["title"],
                "description": f"{entry['description']} Uses discovered data: {', '.join(top)}.",
                "data_sources": top,
                "business_value": "Builds on data already being collected, so it can be implemented without new onboarding.",
                "implementation_complexity": entry["complexity"],
                "success_metrics": list(entry["success_metrics"]),
                "scenario": entry["scenario"],
                "category": entry["category"],
                "type": "existing_data",
                "evidence": evidence_for(top),
                "generated_by": "local_analysis",
            })

        security_sources = matched_by_category.get("Security & Risk Management", []) + matched_by_category.get("Network Security", [])
        ops_sources = matched_by_category.get("Operational Excellence", []) + matched_by_category.get("Application Performance", [])
        if security_sources and ops_sources:
            combined = list(dict.fromkeys(security_sources[:3] + ops_sources[:3]))
            use_cases.append({
                "title": "Correlated Security and Operations Timeline",
                "description": "Correlate security events with operational health signals on the same hosts to separate attacks from outages.",
                "data_sources": combined,
                "business_value": "Shortens triage by showing security and health context together.",
                "implementation_complexity": "Medium-High",
                "success_metrics": ["Incidents triaged with combined context", "Time to root cause"],
                "scenario": "When authentication failures spike on a host, show its concurrent service errors and resource usage.",
                "category": "Cross-functional",
                "type": "existing_data",
                "evidence": evidence_for(combined),
                "generated_by": "local_analysis",
            })

        if "_internal" in index_events:
            use_cases.append({
                "title": "Splunk Platform Health Monitoring",
                "description": "Track indexing throughput, skipped searches, and forwarder connectivity from Splunk's own logs.",
                "data_sources": ["index=_internal"],
                "business_value": "Detects ingestion and search problems before they create blind spots.",
                "implementation_complexity": "Low",
                "success_metrics": ["Skipped search ratio", "Forwarders not reporting", "Indexing queue saturation events"],
                "scenario": "Alert when a forwarder that normally reports stops sending data for more than an hour.",
                "category": "Platform Operations",
                "type": "existing_data",
                "evidence": [f"index=_internal: {index_events['_internal']:,} events"],
                "generated_by": "local_analysis",
            })
        if "_audit" in index_events:
            use_cases.append({
                "title": "Splunk User and Search Audit",
                "description": "Review who runs which searches, failed Splunk logons, and configuration changes.",
                "data_sources": ["index=_audit"],
                "business_value": "Provides accountability for administrative activity on the Splunk platform itself.",
                "implementation_complexity": "Low",
                "success_metrics": ["Failed Splunk logons reviewed", "Expensive searches identified"],
                "scenario": "Report users whose searches consume the most runtime each week.",
                "category": "Platform Operations",
                "type": "existing_data",
                "evidence": [f"index=_audit: {index_events['_audit']:,} events"],
                "generated_by": "local_analysis",
            })

        if not use_cases:
            active = sorted(
                (name for name, count in sourcetype_events.items() if count > 0),
                key=lambda name: sourcetype_events[name],
                reverse=True,
            )[:5]
            if active:
                use_cases.append({
                    "title": "Data Source Baseline and Freshness Monitoring",
                    "description": "Baseline event volume for the most active discovered sourcetypes and alert when one goes silent.",
                    "data_sources": active,
                    "business_value": "Catches collection gaps before they hide incidents.",
                    "implementation_complexity": "Low",
                    "success_metrics": ["Silent sources detected", "Time to restore collection"],
                    "scenario": "Alert when a sourcetype that normally reports hourly sends no events for 24 hours.",
                    "category": "Data Quality",
                    "type": "existing_data",
                    "evidence": evidence_for(active),
                    "generated_by": "local_analysis",
                })

        return use_cases[:8]

    # ------------------------------------------------------------------
    # Estimation helpers
    # ------------------------------------------------------------------

    def _estimate_discovery_steps(self, indexes: int, sourcetypes: int, hosts: int = 0,
                                  sources: int = 0, knowledge_objects: int = 0,
                                  users: int = 0, kv_collections: int = 0) -> int:
        """Estimate the number of DiscoveryResult steps the evidence phase will yield."""
        index_detail_steps = min(indexes, DETAILED_INDEX_LIMIT)
        # Other knowledge-object types (alerts, views, macros, lookups, data models) are unknown until fetched.
        ko_steps = knowledge_objects * 2 + 10
        analytics_steps = 2
        return (
            indexes + index_detail_steps + sourcetypes + hosts + sources
            + ko_steps + users + kv_collections + analytics_steps
        )

    def _estimate_time(self, steps: int) -> str:
        """Estimate discovery time as a conservative range before runtime calibration kicks in."""
        lower_minutes = max(2, int(round(steps / 250.0)))
        upper_minutes = max(lower_minutes + 3, int(round(lower_minutes * 1.5)))

        def _format_minutes(value: int) -> str:
            if value < 60:
                return f"{value}m"
            hours = value // 60
            remaining_minutes = value % 60
            return f"{hours}h {remaining_minutes}m" if remaining_minutes else f"{hours}h"

        return f"~{_format_minutes(lower_minutes)} to {_format_minutes(upper_minutes)}"

    async def _identify_notable_patterns(self, indexes_data: Dict, sourcetypes_data: Dict) -> List[Any]:
        """Use LLM to identify notable patterns in a compact view of the initial inventory."""
        index_rows = self._extract_rows(indexes_data)
        sourcetype_rows = self._extract_rows(sourcetypes_data)
        pattern_data = _shrink_for_prompt({
            "indexes": {"total": len(index_rows), "top_by_events": self._compact_index_rows(index_rows)},
            "sourcetypes_seen_last_24h": {
                "total": len(sourcetype_rows),
                "note": (
                    "Splunk metadata counts cover whole index buckets, so events can predate the 24h window; "
                    "age_hours is the time since the latest event."
                ),
                "top_by_events": self._compact_metadata_rows(sourcetype_rows, "sourcetype"),
            },
        })
        try:
            result = await self.llm_client.analyze_data(pattern_data, "patterns")
        except Exception as e:
            raise Exception(f"LLM pattern analysis failed: {str(e)}")

        if _is_unstructured_llm_result(result):
            analysis = result.get("analysis", "").strip()
            if analysis:
                self._set_llm_status("patterns", "unstructured", detail=analysis[:500])
                return [analysis[:1500]]
            self._set_llm_status("patterns", "empty")
            return []
        patterns = self._normalize_llm_patterns(result)
        if patterns:
            self._set_llm_status("patterns", "ok", items=len(patterns))
            return patterns
        self._set_llm_status("patterns", "empty")
        return []

    @staticmethod
    def _normalize_llm_patterns(result: Any, limit: int = 8) -> List[Any]:
        """Normalize an LLM patterns reply into strings or {category, insight, evidence} mappings."""
        if isinstance(result, list):
            raw_items = result
        elif isinstance(result, dict):
            raw_items = next(
                (result[key] for key in ("patterns", "notable_patterns") if isinstance(result.get(key), list)),
                None,
            )
            if raw_items is None:
                if any(key in result for key in ("category", "insight", "description", "pattern")):
                    raw_items = [result]
                elif isinstance(result.get("insights"), list):
                    raw_items = result["insights"]
                else:
                    raw_items = []
        else:
            raw_items = []

        def text_of(value: Any) -> str:
            if isinstance(value, list):
                return " ".join(str(part).strip() for part in value[:3] if str(part).strip())
            return str(value or "").strip()

        normalized: List[Any] = []
        for item in raw_items:
            if isinstance(item, str):
                if item.strip():
                    normalized.append(item.strip()[:600])
                continue
            if not isinstance(item, dict):
                continue
            category = text_of(item.get("category") or item.get("title") or item.get("name"))
            insight = text_of(
                item.get("insight") or item.get("insights") or item.get("description")
                or item.get("summary") or item.get("pattern")
            )
            if not (category or insight):
                continue
            raw_evidence = item.get("evidence")
            if isinstance(raw_evidence, list):
                evidence = [str(entry).strip()[:200] for entry in raw_evidence if str(entry).strip()][:3]
            elif isinstance(raw_evidence, str) and raw_evidence.strip():
                evidence = [raw_evidence.strip()[:200]]
            else:
                evidence = []
            normalized.append({"category": category[:120], "insight": insight[:600], "evidence": evidence})
        return normalized[:limit]

    # ------------------------------------------------------------------
    # Discovery steps
    # ------------------------------------------------------------------

    async def _discover_indexes(self) -> List[Dict[str, Any]]:
        """Discover detailed information about all indexes."""
        return self._rows_or_raise(await self._fetch_spec("indexes"))

    async def _fetch_sourcetypes(self) -> StepOutcome:
        """Sourcetype inventory from the metadata tool, or the metadata search command as a fallback."""
        outcome = await self._fetch_spec("sourcetypes")
        if outcome.status not in {"error", "unsupported"}:
            return outcome
        fallback = await self._fetch(
            "sourcetypes",
            "splunk_run_query",
            {
                "query": SOURCETYPE_METADATA_QUERY,
                "earliest_time": "-24h",
                "latest_time": "now",
                "row_limit": ROW_LIMITS["sourcetypes"],
            },
            row_limit=ROW_LIMITS["sourcetypes"],
        )
        if fallback.status == "ok":
            status = getattr(self, "_step_status", {}).get("sourcetypes")
            if isinstance(status, dict):
                status["fallback"] = "metadata search command"
                status["primary_error"] = outcome.error[:200]
            return fallback
        return outcome

    async def _discover_sourcetypes(self) -> List[Dict[str, Any]]:
        """Discover detailed information about all sourcetypes (last 24h)."""
        return self._rows_or_raise(await self._fetch_sourcetypes())

    async def _discover_knowledge_objects(self) -> List[Dict[str, Any]]:
        """Discover saved searches."""
        return self._rows_or_raise(await self._fetch_spec("knowledge_objects:saved_searches"))

    async def _discover_hosts(self) -> List[Dict[str, Any]]:
        """Discover detailed information about all hosts sending data (last 24h)."""
        return self._rows_or_raise(await self._fetch_spec("hosts"))

    async def _discover_sources(self) -> List[Dict[str, Any]]:
        """Discover detailed information about all data sources (last 24h)."""
        return self._rows_or_raise(await self._fetch_spec("sources"))

    async def _discover_knowledge_objects_by_type(self, ko_type: str) -> List[Dict[str, Any]]:
        """Discover knowledge objects of a specific type."""
        outcome = await self._fetch(
            f"knowledge_objects:{ko_type}",
            "splunk_get_knowledge_objects",
            self._knowledge_object_params(ko_type),
            row_limit=ROW_LIMITS["knowledge_objects"],
        )
        results = self._rows_or_raise(outcome)
        for row in results:
            row['ko_type'] = ko_type
        return results

    async def _discover_detailed_index_info(self) -> List[Dict[str, Any]]:
        """Get detailed configuration for the largest indexes by event count."""
        indexes = (getattr(self, "_inventory", {}) or {}).get("indexes")
        if not indexes:
            indexes = await self._discover_indexes()

        candidates = sorted(
            (idx for idx in indexes if isinstance(idx, dict)),
            key=lambda x: safe_int(x.get('totalEventCount')),
            reverse=True,
        )[:DETAILED_INDEX_LIMIT]
        names = [str(idx.get('title') or idx.get('name') or '').strip() for idx in candidates]
        names = [name for name in names if name]
        if not names:
            return []

        outcomes = await asyncio.gather(*(
            self._fetch(f"index_detail:{name}", "splunk_get_index_info", {"index_name": name}, rows_mode="record")
            for name in names
        ))

        detailed_info = []
        for name, outcome in zip(names, outcomes):
            if outcome.status != "ok" or not outcome.rows:
                continue
            record = outcome.rows[0]
            if isinstance(record, dict) and record:
                record.setdefault("name", name)
                detailed_info.append(record)

        if not detailed_info:
            failed = [outcome for outcome in outcomes if outcome.status != "ok"]
            if failed:
                raise DiscoveryStepUnavailable("index_details", failed[0].status, failed[0].error)
        return detailed_info

    async def _discover_users(self) -> List[Dict[str, Any]]:
        """Discover the authenticated user context (splunk_get_user_info returns the calling user)."""
        return self._rows_or_raise(await self._fetch_spec("users"))

    async def _discover_kv_collections(self) -> List[Dict[str, Any]]:
        """Discover KV store collections."""
        rows = self._rows_or_raise(await self._fetch_spec("kv_collections"))
        for row in rows:
            row.setdefault("ko_type", "kv_store_collections")
        return rows

    async def _run_advanced_analytics(self) -> List[Dict[str, Any]]:
        """Run evidence-based analytical queries (freshness and complete-day volume trend)."""
        indexes = (getattr(self, "_inventory", {}) or {}).get("indexes") or []
        recent_outcome, trend_outcome = await asyncio.gather(
            self._fetch(
                "analytics:recent_index_activity",
                "splunk_run_query",
                {"query": RECENT_INDEX_ACTIVITY_QUERY, "earliest_time": "-24h", "latest_time": "now", "row_limit": 1000},
                row_limit=1000,
            ),
            self._fetch(
                "analytics:daily_event_trend",
                "splunk_run_query",
                {"query": DAILY_EVENT_TREND_QUERY, "earliest_time": "-7d@d", "latest_time": "@d", "row_limit": 10},
            ),
        )

        analytics_results: List[Dict[str, Any]] = []
        freshness = self._analyze_recent_index_activity(indexes, recent_outcome)
        if freshness is not None:
            analytics_results.append(freshness)
        trend = self._analyze_daily_trend(trend_outcome)
        if trend is not None:
            analytics_results.append(trend)
        return analytics_results

    def _analyze_recent_index_activity(self, indexes: List[Dict[str, Any]], outcome: StepOutcome) -> Optional[Dict[str, Any]]:
        if outcome.status != "ok":
            return None
        recent_counts: Dict[str, int] = {}
        for row in outcome.rows:
            name = row.get("index")
            if name:
                recent_counts[str(name)] = recent_counts.get(str(name), 0) + safe_int(row.get("count"))

        if outcome.truncated:
            self._freshness = {"status": "unknown", "reason": "tstats result reached its row limit"}
            return {
                "description": "Data Freshness: Index Activity in Last 24h",
                "analytics_id": "recent_index_activity",
                "data": {"recent_event_counts": dict(list(recent_counts.items())[:200]), "truncated": True},
                "findings": ["ℹ️  Index activity check reached its row limit; freshness could not be evaluated for every index"],
            }

        checked: List[str] = []
        stale: List[str] = []
        empty: List[str] = []
        for idx in indexes:
            if not isinstance(idx, dict):
                continue
            name = str(idx.get("title") or idx.get("name") or "").strip()
            if not name or is_truthy_flag(idx.get("disabled")):
                continue
            if str(idx.get("datatype", "event")).lower() == "metric":
                continue
            checked.append(name)
            if recent_counts.get(name, 0) > 0:
                continue
            if safe_int(idx.get("totalEventCount")) > 0:
                stale.append(name)
            else:
                empty.append(name)

        silent = stale + empty
        self._freshness = {
            "status": "measured",
            "checked_indexes": len(checked),
            "active_indexes": len(checked) - len(silent),
            "stale_indexes": sorted(stale),
            "empty_indexes": sorted(empty),
        }

        findings: List[str] = []
        if stale:
            preview = ", ".join(sorted(stale)[:10]) + (f" (+{len(stale) - 10} more)" if len(stale) > 10 else "")
            findings.append(f"⚠️  {len(stale)} index(es) with historical data received no events in the last 24h: {preview}")
        if empty:
            preview = ", ".join(sorted(empty)[:10]) + (f" (+{len(empty) - 10} more)" if len(empty) > 10 else "")
            findings.append(f"💭 {len(empty)} enabled index(es) contain no events at all: {preview}")
        if checked and not silent:
            findings.append(f"✅ All {len(checked)} enabled event indexes received events in the last 24h")

        return {
            "description": "Data Freshness: Indexes Without Events in Last 24h",
            "analytics_id": "recent_index_activity",
            "data": {
                "indexes_without_recent_events": sorted(silent)[:200],
                "stale_indexes": sorted(stale)[:200],
                "empty_indexes": sorted(empty)[:200],
                "checked_indexes": len(checked),
                "recent_event_counts": dict(sorted(recent_counts.items(), key=lambda kv: kv[1], reverse=True)[:200]),
            },
            "findings": findings,
        }

    @staticmethod
    def _analyze_daily_trend(outcome: StepOutcome) -> Optional[Dict[str, Any]]:
        if outcome.status != "ok" or not outcome.rows:
            return None
        rows = sorted(outcome.rows, key=lambda row: _parse_time_value(row.get("_time")) or 0.0)
        counts = [safe_int(row.get("count")) for row in rows]
        if not counts:
            return None
        days = len(counts)
        avg_daily = sum(counts) / days
        findings = [f"📊 Average daily events over {days} complete day(s): {avg_daily:,.0f}"]
        trend = "insufficient data"
        change_pct: Optional[float] = None
        if days >= 2:
            window = 3 if days >= 6 else 1
            first_avg = sum(counts[:window]) / window
            last_avg = sum(counts[-window:]) / window
            if first_avg > 0:
                change_pct = (last_avg - first_avg) / first_avg * 100
                if change_pct > 10:
                    trend = "increasing"
                elif change_pct < -10:
                    trend = "decreasing"
                else:
                    trend = "stable"
                findings.append(
                    f"📈 7-day trend: {trend} ({change_pct:+.0f}% comparing the first {window} vs last {window} complete day(s))"
                )
            elif last_avg > 0:
                trend = "increasing"
                findings.append("📈 7-day trend: increasing (no events on the earliest complete day)")
        return {
            "description": "Temporal Analysis: 7-Day Data Volume Trend",
            "analytics_id": "daily_event_trend",
            "data": {
                "daily_volumes": rows,
                "complete_days": days,
                "trend": trend,
                "change_pct": round(change_pct, 1) if change_pct is not None else None,
            },
            "findings": findings,
        }

    # ------------------------------------------------------------------
    # Per-entity finding analysis
    # ------------------------------------------------------------------

    async def _analyze_index_findings(self, index_info: Dict[str, Any]) -> List[str]:
        """Analyze index for interesting findings with actionable insights."""
        findings: List[str] = []

        if not isinstance(index_info, dict):
            return findings

        title = str(index_info.get("title", index_info.get("name", "unknown")))
        size_mb = safe_float(index_info.get("currentDBSizeMB"))
        event_count = safe_int(index_info.get("totalEventCount"))
        disabled = is_truthy_flag(index_info.get("disabled"))

        if size_mb > 1000:
            findings.append(f"⚠️  Large index: {title} ({size_mb:,.0f}MB on disk, {event_count:,} events) - Review retention policy and consider archiving")
        elif size_mb > 100:
            findings.append(f"📊 Moderate index: {title} ({size_mb:,.0f}MB on disk, {event_count:,} events) - Good data volume for analysis")

        if event_count > 1000000:
            findings.append(f"🔥 High-volume index: {title} ({event_count:,} events) - Prime candidate for analytics and dashboards")
        elif event_count > 100000:
            findings.append(f"📈 Active index: {title} ({event_count:,} events) - Sufficient data for meaningful insights")

        if disabled and (size_mb > 0 or event_count > 0):
            findings.append(f"⚠️  Disabled index contains data: {title} ({size_mb:,.0f}MB, {event_count:,} events) - Consider re-enabling or archiving")

        title_lower = title.lower()
        if 'wineventlog' in title_lower:
            if event_count > 0:
                findings.append(f"🔒 Windows Event Log data found in {title} - Excellent for security monitoring and compliance")
        elif 'security' in title_lower:
            findings.append(f"🔐 Security-focused index: {title} - Review for threat hunting and compliance use cases")
        elif title.startswith('_') and not disabled and event_count == 0:
            findings.append(f"💡 Internal index {title} is enabled but empty - Consider disabling to save resources")

        if not disabled and size_mb == 0 and event_count == 0 and not title.startswith('_'):
            findings.append(f"💭 Empty index: {title} - No data received yet. Verify data inputs or consider removing")

        return findings

    async def _analyze_sourcetype_findings(self, sourcetype_info: Dict[str, Any]) -> List[str]:
        """Analyze sourcetype for interesting findings with actionable insights."""
        findings: List[str] = []

        if not isinstance(sourcetype_info, dict):
            return findings

        sourcetype_name = str(sourcetype_info.get("sourcetype", sourcetype_info.get("type", "unknown")))
        total_count = safe_int(sourcetype_info.get("totalCount"))
        lowered = sourcetype_name.lower()
        tokens = set(_name_tokens(sourcetype_name))

        if total_count > 100000:
            findings.append(f"🔥 High-volume source: {sourcetype_name} ({total_count:,} events) - Key data source for analytics")
        elif total_count > 10000:
            findings.append(f"📊 Active source: {sourcetype_name} ({total_count:,} events) - Good for dashboards and alerting")
        elif total_count > 0:
            findings.append(f"📈 Data source: {sourcetype_name} ({total_count:,} events)")

        if 'wineventlog:security' in lowered:
            findings.append(f"🔒 Critical security data: {sourcetype_name} - Essential for threat detection, user monitoring, and compliance")
        elif 'security' in lowered or 'auth' in tokens or 'authentication' in tokens or lowered == 'linux_secure':
            findings.append(f"🔐 Security data: {sourcetype_name} - Use for authentication monitoring and security analytics")
        elif tokens & {'firewall', 'ids', 'ips', 'pan', 'asa'}:
            findings.append(f"🛡️  Network security data: {sourcetype_name} - Valuable for threat hunting and network monitoring")
        elif 'wineventlog:application' in lowered:
            findings.append(f"📱 Application logs: {sourcetype_name} - Monitor app health, errors, and performance")
        elif tokens & {'application', 'app'}:
            findings.append(f"💼 Application data: {sourcetype_name} - Track application behavior and errors")
        elif 'wineventlog:system' in lowered:
            findings.append(f"⚙️  System logs: {sourcetype_name} - Monitor OS health, services, and hardware")
        elif tokens & {'syslog', 'linux', 'unix'}:
            findings.append(f"🐧 Unix/Linux system data: {sourcetype_name} - Track system health and operations")
        elif tokens & {'cpu', 'memory', 'disk', 'vmstat', 'iostat', 'perfmon'}:
            findings.append(f"📊 Performance metrics: {sourcetype_name} - Monitor resource utilization and capacity planning")

        if tokens & {'json', 'xml'} or lowered.startswith('xmlwineventlog'):
            findings.append(f"✨ Structured data: {sourcetype_name} - Well-formatted for easy parsing and analytics")

        age_hours = _age_hours(metadata_recent_epoch(sourcetype_info))
        if age_hours is not None:
            if age_hours < 1:
                findings.append(f"✅ Fresh data: {sourcetype_name} - Recent events (< 1 hour old)")
            elif age_hours > 24:
                findings.append(f"⚠️  Stale data: {sourcetype_name} - Last event {age_hours:.0f} hours ago. Check data inputs")

        if 0 < total_count < 100:
            findings.append(f"💎 Low-volume source: {sourcetype_name} ({total_count} events) - May be rare events or new data source")

        return findings

    _HOST_ROLE_TOKENS: List[Tuple[set, str]] = [
        ({"web", "www", "apache", "nginx", "iis"}, "🌐 Possible role (from hostname): web server - Consider web analytics and performance monitoring"),
        ({"db", "database", "sql", "mysql", "postgres", "oracle", "mssql"}, "🗄️  Possible role (from hostname): database server - Monitor queries, performance, and security"),
        ({"dc", "ad", "ldap", "domain"}, "👥 Possible role (from hostname): directory/domain controller - Critical for authentication and access control"),
        ({"mail", "exchange", "smtp", "mx"}, "📧 Possible role (from hostname): mail server - Monitor email flow and security"),
        ({"fw", "firewall", "proxy"}, "🛡️  Possible role (from hostname): security appliance - Essential for threat detection"),
    ]

    async def _analyze_host_findings(self, host_info: Dict[str, Any]) -> List[str]:
        """Analyze host for interesting findings with actionable insights."""
        findings: List[str] = []

        if not isinstance(host_info, dict):
            return findings

        host_name = str(host_info.get("host", "unknown"))
        total_count = safe_int(host_info.get("totalCount"))

        if total_count > 50000:
            findings.append(f"🔥 High-activity host: {host_name} ({total_count:,} events) - Major infrastructure component")
        elif total_count > 10000:
            findings.append(f"📊 Active host: {host_name} ({total_count:,} events) - Important monitoring target")
        elif total_count > 1000:
            findings.append(f"📈 Moderate host: {host_name} ({total_count:,} events)")
        elif total_count > 0:
            findings.append(f"📌 Light host: {host_name} ({total_count} events)")

        if 0 < total_count < 10:
            findings.append(f"⚠️  Very low activity: {host_name} - May indicate monitoring gaps or intermittent data collection")

        tokens = set(_name_tokens(host_name))
        if tokens & {'prod', 'production', 'prd'}:
            findings.append(f"🏭 Possible production host (from hostname): {host_name}")
        elif tokens & {'dev', 'development', 'test', 'staging', 'stg', 'qa', 'uat'}:
            findings.append(f"🔧 Possible non-production host (from hostname): {host_name}")

        for role_tokens, message in self._HOST_ROLE_TOKENS:
            if tokens & role_tokens:
                findings.append(f"{message} [{host_name}]")
                break

        age_hours = _age_hours(metadata_recent_epoch(host_info))
        if age_hours is not None:
            if age_hours < 1:
                findings.append(f"✅ Fresh data: {host_name} - Recent events (< 1 hour old)")
            elif age_hours > 24:
                findings.append(f"⚠️  Stale data: {host_name} - No recent events ({age_hours / 24:.1f} days old). Check forwarder")

        return findings

    async def _analyze_source_findings(self, source_info: Dict[str, Any]) -> List[str]:
        """Analyze source for interesting findings with actionable insights."""
        findings: List[str] = []

        if not isinstance(source_info, dict):
            return findings

        source_path = str(source_info.get("source", "unknown"))
        total_count = safe_int(source_info.get("totalCount"))

        if total_count > 50000:
            findings.append(f"🔥 High-volume source: {source_path} ({total_count:,} events) - Major data input")
        elif total_count > 10000:
            findings.append(f"📊 Active source: {source_path} ({total_count:,} events)")
        elif total_count > 1000:
            findings.append(f"📈 Moderate source: {source_path} ({total_count:,} events)")
        elif total_count > 0:
            findings.append(f"📌 Light source: {source_path} ({total_count} events)")

        if 0 < total_count < 10:
            findings.append(f"⚠️  Very low activity: {source_path} - May indicate new source or collection issues")

        source_lower = source_path.lower()
        tokens = set(_name_tokens(source_path))

        if 'wineventlog' in source_lower or 'eventlog' in source_lower:
            findings.append(f"🪟 Windows Event Log: {source_path} - System event monitoring")
        elif '.log' in source_lower or '/var/log' in source_lower or 'c:\\logs' in source_lower:
            findings.append(f"📄 Log file: {source_path} - File-based monitoring")
            if tokens & {'access', 'access_log'}:
                findings.append(f"🌐 Web access log: {source_path} - Track web traffic and user behavior")
            elif tokens & {'error', 'errors'}:
                findings.append(f"⚠️  Error log: {source_path} - Application error tracking")
            elif tokens & {'security', 'audit', 'secure', 'auth'}:
                findings.append(f"🔒 Security/audit log: {source_path} - Compliance and security monitoring")
            elif tokens & {'application', 'app'}:
                findings.append(f"📱 Application log: {source_path} - App behavior and performance")
        elif 'syslog' in source_lower or source_lower.startswith(('udp:', 'tcp:')):
            findings.append(f"📡 Network input: {source_path} - Syslog or network data collection")
        elif source_lower.startswith('script:') or 'powershell' in source_lower or source_lower.endswith(('.ps1', '.sh', '.py')):
            findings.append(f"⚙️  Scripted input: {source_path} - Custom data collection script")
        elif tokens & {'jdbc', 'odbc', 'sql', 'dbx'}:
            findings.append(f"🗄️  Database input: {source_path} - Database query monitoring")
        elif tokens & {'http', 'https', 'api', 'rest', 'hec'}:
            findings.append(f"🔌 API/HTTP input: {source_path} - REST API or HTTP event collector")

        age_hours = _age_hours(metadata_recent_epoch(source_info))
        if age_hours is not None:
            if age_hours < 1:
                findings.append("✅ Fresh data: Recent events (< 1 hour old)")
            elif age_hours > 24:
                findings.append(f"⚠️  Stale data: No recent events ({age_hours / 24:.1f} days old). Check input configuration")

        return findings

    async def _analyze_knowledge_object_findings(self, ko_info: Dict[str, Any], ko_type: str = "saved_searches") -> List[str]:
        """Analyze knowledge objects for interesting findings with actionable insights."""
        findings: List[str] = []

        if not isinstance(ko_info, dict):
            return findings

        ko_name = ko_info.get("name", ko_info.get("title", "unknown"))
        is_disabled = is_truthy_flag(ko_info.get("disabled"))

        if ko_type == "alerts":
            if not is_disabled:
                severity = ko_info.get("alert.severity", "unspecified")
                cron = ko_info.get("cron_schedule", "")
                findings.append(f"🚨 Alert active: '{ko_name}' - Severity: {severity}")
                if cron:
                    findings.append(f"⏰ Alert schedule: {cron}")
            else:
                findings.append(f"💤 Disabled alert: '{ko_name}' - Review and consider re-enabling")

        elif ko_type in {"views", "dashboards"}:
            dashboard_flag = ko_info.get("is_dashboard")
            if dashboard_flag is None or is_truthy_flag(dashboard_flag):
                findings.append(f"📊 Dashboard available: '{ko_info.get('label') or ko_name}'")

        elif ko_type == "macros":
            if ko_info.get("definition"):
                findings.append(f"🔧 Macro: '{ko_name}' - Reusable SPL component")

        elif ko_type == "lookups":
            findings.append(f"📇 Lookup available: '{ko_name}' - Enrichment data for searches")

        elif ko_type == "data_models":
            if self._data_model_accelerated(ko_info):
                findings.append(f"⚡ Accelerated data model: '{ko_name}' - Supports fast tstats searches")
            else:
                findings.append(f"🧩 Data model: '{ko_name}' - Not reported as accelerated")

        else:
            ko_search = str(ko_info.get("search", "") or "")
            cron = ko_info.get("cron_schedule", "")
            search_lower = ko_search.lower()

            if not is_disabled:
                if any(term in search_lower for term in ['security', 'threat', 'malware', 'intrusion', 'authentication', 'failed login']):
                    findings.append(f"🔒 Security search active: '{ko_name}' - Shows existing security monitoring")
                elif any(term in search_lower for term in ['cpu', 'memory', 'disk', 'performance', 'capacity']):
                    findings.append(f"📊 Performance monitoring: '{ko_name}' - Active infrastructure monitoring")
                elif any(term in search_lower for term in ['error', 'failed', 'exception', '404', '500', '503']):
                    findings.append(f"⚠️  Error tracking: '{ko_name}' - Proactive error monitoring in place")
                elif any(term in search_lower for term in ['compliance', 'audit', 'license', 'policy']):
                    findings.append(f"📋 Compliance monitoring: '{ko_name}' - Audit and compliance tracking active")
                elif cron:
                    findings.append(f"⏰ Scheduled search: '{ko_name}' - Running on schedule: {cron}")
                else:
                    findings.append(f"🔍 Saved search available: '{ko_name}' - Shows existing use case implementation")
            else:
                findings.append(f"💤 Disabled search: '{ko_name}' - Consider re-enabling or removing")

        return findings

    @staticmethod
    def _data_model_accelerated(ko_info: Dict[str, Any]) -> bool:
        # The GA tool returns acceleration as a JSON string such as '{"enabled":false,...}'.
        acceleration = ko_info.get("acceleration", ko_info.get("accelerated"))
        if isinstance(acceleration, str) and acceleration.strip().startswith("{"):
            try:
                acceleration = json.loads(acceleration)
            except json.JSONDecodeError:
                return False
        if isinstance(acceleration, dict):
            return is_truthy_flag(acceleration.get("enabled"))
        return is_truthy_flag(acceleration)

    @staticmethod
    def _index_capacity_pct(index_info: Dict[str, Any]) -> Optional[float]:
        max_data_size = safe_float(index_info.get("maxTotalDataSizeMB"))
        total_size = safe_float(index_info.get("currentDBSizeMB"))
        if max_data_size <= 0 or total_size <= 0:
            return None
        return (total_size / max_data_size) * 100

    async def _analyze_detailed_index_findings(self, index_info: Dict[str, Any]) -> List[str]:
        """Analyze detailed index configuration for optimization opportunities."""
        findings: List[str] = []

        if not isinstance(index_info, dict):
            return findings

        index_name = index_info.get("name", index_info.get("title", "unknown"))

        frozen_seconds = safe_float(index_info.get("frozenTimePeriodInSecs"))
        if frozen_seconds > 0:
            days = frozen_seconds / 86400
            if days > 365:
                findings.append(f"📅 Long retention: {index_name} retains data for {days:.0f} days - Validate against usage patterns")
            elif days < 30:
                findings.append(f"⚠️  Short retention: {index_name} only retains {days:.0f} days - May need extension for compliance")

        # repFactor "auto" means the index is replicated by an indexer cluster; "0" means it is not.
        replication_factor = str(index_info.get("repFactor", "") or "").strip().lower()
        if replication_factor == "0":
            findings.append(f"ℹ️  repFactor=0: {index_name} is not replicated by an indexer cluster (expected on standalone indexers)")

        usage_pct = self._index_capacity_pct(index_info)
        if usage_pct is not None and usage_pct > 80:
            findings.append(f"💾 Storage warning: {index_name} at {usage_pct:.0f}% of maxTotalDataSizeMB - Increase the cap or adjust retention")

        return findings

    async def _analyze_user_findings(self, user_info: Dict[str, Any]) -> List[str]:
        """Analyze the authenticated user context returned by splunk_get_user_info."""
        findings: List[str] = []

        if not isinstance(user_info, dict):
            return findings

        username = user_info.get("name", user_info.get("username", "unknown"))
        roles = user_info.get("roles", [])
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",") if r.strip()]
        if not isinstance(roles, list):
            roles = []

        findings.append(f"ℹ️  Authenticated user context: {username} (roles: {', '.join(str(r) for r in roles) or 'none reported'})")

        if "admin" in roles or "sc_admin" in roles:
            findings.append(f"🔑 Discovery is running with an admin role ({username}) - Consider a least-privilege service account")

        if len(roles) > 5:
            findings.append(f"⚠️  {username} has {len(roles)} roles - Review for least privilege")

        return findings

    async def _analyze_kv_findings(self, kv_info: Dict[str, Any]) -> List[str]:
        """Analyze KV store collections for integration opportunities."""
        findings: List[str] = []

        if not isinstance(kv_info, dict):
            return findings

        kv_name = str(kv_info.get("name", kv_info.get("title", "unknown")))
        size = safe_int(kv_info.get("record_count"))
        kv_lower = kv_name.lower()

        if any(term in kv_lower for term in ['threat', 'intel', 'ioc', 'indicator', 'malware', 'blacklist', 'blocklist']):
            findings.append(f"🛡️  Threat Intel: {kv_name} ({size} records) - Valuable for correlation searches")
        elif any(term in kv_lower for term in ['asset', 'inventory', 'cmdb', 'device']):
            findings.append(f"📋 Asset Inventory: {kv_name} ({size} records) - Enable asset-based monitoring")
        elif 'lookup' in kv_lower:
            findings.append(f"🔍 Lookup Table: {kv_name} ({size} records) - Data enrichment available")

        if size > 100000:
            findings.append(f"💾 Large collection: {kv_name} has {size:,} records - Consider optimization")

        return findings

    def _build_classification_prompt(self) -> str:
        """Build prompt for LLM classification of discovered data."""
        return "Classify the discovered Splunk data into security, infrastructure, business, and compliance categories..."

    def _build_recommendations_prompt(self) -> str:
        """Build prompt for LLM use case recommendations."""
        return "Based on the discovered Splunk environment, recommend optimal use cases with priorities and ROI estimates..."
