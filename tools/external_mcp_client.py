#!/usr/bin/env python3
"""Small CLI for DT4SMS inbound MCP bootstrapping and usage."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import httpx


DEFAULT_BASE_URL = str(os.getenv("DT4SMS_BASE_URL") or "http://127.0.0.1:8003").rstrip("/")
DEFAULT_TIMEOUT = float(os.getenv("DT4SMS_HTTP_TIMEOUT") or "20")
DEFAULT_PROTOCOL_VERSION = "2025-03-26"


def _pretty_print(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


class Dt4smsMcpClient:
    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT):
        self.base_url = str(base_url or DEFAULT_BASE_URL).rstrip("/")
        self.client = httpx.Client(base_url=self.base_url, timeout=timeout, follow_redirects=True)

    def close(self) -> None:
        self.client.close()

    def _request_json(self, method: str, path: str, **kwargs: Any) -> Dict[str, Any]:
        response = self.client.request(method.upper(), path, **kwargs)
        try:
            payload = response.json()
        except Exception:
            payload = {"raw": response.text}

        if response.is_error:
            raise RuntimeError(f"{response.request.method} {path} failed with {response.status_code}: {json.dumps(payload, ensure_ascii=False)}")
        return payload if isinstance(payload, dict) else {"data": payload}

    def _request_mcp(self, token: str, method: str, params: Optional[Dict[str, Any]] = None, request_id: int = 1) -> Dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        response = self.client.post(
            "/api/external/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        try:
            body = response.json()
        except Exception:
            body = {"raw": response.text}

        if response.is_error:
            raise RuntimeError(f"POST /api/external/mcp failed with {response.status_code}: {json.dumps(body, ensure_ascii=False)}")

        if isinstance(body, dict) and body.get("error"):
            raise RuntimeError(json.dumps(body["error"], ensure_ascii=False))

        return body if isinstance(body, dict) else {"data": body}

    def maybe_login(self, username: Optional[str], password: Optional[str]) -> None:
        if not username or not password:
            return
        try:
            self._request_json(
                "POST",
                "/api/auth/login",
                json={"username": username, "password": password},
            )
        except RuntimeError as exc:
            message = str(exc).lower()
            if "authentication is not enabled" in message:
                return
            raise

    def enable_external_mcp(self) -> Dict[str, Any]:
        return self._request_json(
            "POST",
            "/api/config",
            json={"security": {"external_mcp_enabled": True}},
        )

    def issue_token(self, name: str, owner_user_id: Optional[int] = None, expires_days: Optional[int] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "name": name,
            "token_type": "inbound_mcp",
            "scopes": ["mcp:tools:read"],
        }
        if owner_user_id is not None:
            payload["owner_user_id"] = int(owner_user_id)
        if expires_days is not None:
            payload["expires_in_days"] = int(expires_days)
        return self._request_json("POST", "/api/security/tokens", json=payload)

    def get_info(self) -> Dict[str, Any]:
        return self._request_json("GET", "/api/external/mcp/info")

    def initialize(self, token: str, client_name: str, client_version: str, request_id: int = 1) -> Dict[str, Any]:
        return self._request_mcp(
            token,
            "initialize",
            params={
                "protocolVersion": DEFAULT_PROTOCOL_VERSION,
                "clientInfo": {"name": client_name, "version": client_version},
            },
            request_id=request_id,
        )

    def list_tools(self, token: str, request_id: int = 2) -> Dict[str, Any]:
        return self._request_mcp(token, "tools/list", request_id=request_id)

    def call_tool(self, token: str, tool_name: str, arguments: Optional[Dict[str, Any]] = None, request_id: int = 3) -> Dict[str, Any]:
        return self._request_mcp(
            token,
            "tools/call",
            params={
                "name": tool_name,
                "arguments": dict(arguments or {}),
            },
            request_id=request_id,
        )

    def get_runtime_summary(self, token: str, request_id: int = 3) -> Dict[str, Any]:
        return self.call_tool(token, "system_get_runtime_summary", {}, request_id=request_id)

    def list_capabilities(self, token: str, refresh_health: bool = False, request_id: int = 3) -> Dict[str, Any]:
        return self.call_tool(
            token,
            "capabilities_list",
            {"refresh_health": bool(refresh_health)},
            request_id=request_id,
        )

    def get_capability_detail(
        self,
        token: str,
        capability_name: str,
        refresh_health: bool = False,
        request_id: int = 3,
    ) -> Dict[str, Any]:
        return self.call_tool(
            token,
            "capabilities_get_detail",
            {"capability_name": capability_name, "refresh_health": bool(refresh_health)},
            request_id=request_id,
        )

    def list_artifacts(
        self,
        token: str,
        limit: int = 20,
        session_timestamp: Optional[str] = None,
        artifact_kind: Optional[str] = None,
        request_id: int = 3,
    ) -> Dict[str, Any]:
        arguments: Dict[str, Any] = {"limit": int(limit)}
        if session_timestamp:
            arguments["session_timestamp"] = session_timestamp
        if artifact_kind:
            arguments["artifact_kind"] = artifact_kind
        return self.call_tool(token, "artifacts_list", arguments, request_id=request_id)

    def get_artifact_detail(
        self,
        token: str,
        artifact_name: str,
        max_chars: int = 12000,
        request_id: int = 3,
    ) -> Dict[str, Any]:
        return self.call_tool(
            token,
            "artifacts_get_detail",
            {"artifact_name": artifact_name, "max_chars": int(max_chars)},
            request_id=request_id,
        )

    def get_discovery_dashboard(self, token: str, request_id: int = 3) -> Dict[str, Any]:
        return self.call_tool(token, "discovery_get_dashboard", {}, request_id=request_id)

    def get_latest_intelligence(self, token: str, request_id: int = 3) -> Dict[str, Any]:
        return self.call_tool(token, "discovery_get_latest_intelligence", {}, request_id=request_id)

    def get_discovery_runbook(
        self,
        token: str,
        timestamp: Optional[str] = None,
        persona: str = "admin",
        voice: str = "direct",
        request_id: int = 3,
    ) -> Dict[str, Any]:
        arguments: Dict[str, Any] = {
            "persona": str(persona or "admin"),
            "voice": str(voice or "direct"),
        }
        if timestamp:
            arguments["timestamp"] = timestamp
        return self.call_tool(token, "discovery_get_runbook", arguments, request_id=request_id)

    def compare_discovery_sessions(
        self,
        token: str,
        current_selection: Optional[str] = None,
        baseline_selection: Optional[str] = None,
        request_id: int = 3,
    ) -> Dict[str, Any]:
        arguments: Dict[str, Any] = {}
        if current_selection:
            arguments["current_selection"] = current_selection
        if baseline_selection:
            arguments["baseline_selection"] = baseline_selection
        return self.call_tool(token, "discovery_compare_sessions", arguments, request_id=request_id)


def _resolve_admin_user(args: argparse.Namespace) -> Optional[str]:
    return args.admin_user or os.getenv("DT4SMS_ADMIN_USER") or None


def _resolve_admin_password(args: argparse.Namespace) -> Optional[str]:
    return args.admin_password or os.getenv("DT4SMS_ADMIN_PASSWORD") or None


def _resolve_mcp_token(args: argparse.Namespace) -> str:
    token = args.token or os.getenv("DT4SMS_MCP_TOKEN") or ""
    token = str(token).strip()
    if not token:
        raise RuntimeError("An inbound MCP token is required. Use --token or set DT4SMS_MCP_TOKEN.")
    return token


def _write_token_file(path: Optional[str], token: str) -> None:
    if not path:
        return
    token_path = Path(path)
    token_path.write_text(token, encoding="utf-8")
    print(f"Saved token to {token_path}")


def _parse_arguments_json(value: str) -> Dict[str, Any]:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON for --arguments-json: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("--arguments-json must decode to a JSON object")
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DT4SMS external MCP helper")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="DT4SMS base URL")
    parser.add_argument("--admin-user", default=None, help="Admin username for auth-enabled installs")
    parser.add_argument("--admin-password", default=None, help="Admin password for auth-enabled installs")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("info", help="Call the unauthenticated MCP setup endpoint")
    subparsers.add_parser("enable-mcp", help="Enable the external MCP surface through the admin config endpoint")

    issue_token_parser = subparsers.add_parser("issue-token", help="Create an inbound MCP token")
    issue_token_parser.add_argument("--name", required=True, help="Token display name")
    issue_token_parser.add_argument("--owner-user-id", type=int, default=None, help="Optional owning user id")
    issue_token_parser.add_argument("--expires-days", type=int, default=30, help="Token expiry in days")
    issue_token_parser.add_argument("--enable-mcp", action="store_true", help="Enable the MCP surface before creating the token")
    issue_token_parser.add_argument("--save-token", default=None, help="Optional file path to store the plaintext token")

    initialize_parser = subparsers.add_parser("initialize", help="Run MCP initialize against the external MCP endpoint")
    initialize_parser.add_argument("--token", default=None, help="Inbound MCP token")
    initialize_parser.add_argument("--client-name", default="dt4sms-external-mcp-client", help="Client name for initialize")
    initialize_parser.add_argument("--client-version", default="1.0", help="Client version for initialize")

    list_tools_parser = subparsers.add_parser("list-tools", help="Run MCP tools/list")
    list_tools_parser.add_argument("--token", default=None, help="Inbound MCP token")

    call_tool_parser = subparsers.add_parser("call-tool", help="Run MCP tools/call with explicit JSON arguments")
    call_tool_parser.add_argument("--token", default=None, help="Inbound MCP token")
    call_tool_parser.add_argument("--tool-name", required=True, help="MCP tool name")
    call_tool_parser.add_argument("--arguments-json", default="{}", help="JSON object passed as the tool arguments")

    search_parser = subparsers.add_parser("search", help="Call the rag_search MCP tool")
    search_parser.add_argument("--token", default=None, help="Inbound MCP token")
    search_parser.add_argument("--query", required=True, help="Search query")
    search_parser.add_argument("--limit", type=int, default=4, help="Maximum chunks to request")

    build_context_parser = subparsers.add_parser("build-context", help="Call the rag_build_context MCP tool")
    build_context_parser.add_argument("--token", default=None, help="Inbound MCP token")
    build_context_parser.add_argument("--query", required=True, help="Context query")
    build_context_parser.add_argument("--limit", type=int, default=4, help="Maximum chunks to request")

    list_assets_parser = subparsers.add_parser("list-assets", help="Call the rag_list_assets MCP tool")
    list_assets_parser.add_argument("--token", default=None, help="Inbound MCP token")

    get_asset_parser = subparsers.add_parser("get-asset", help="Call the rag_get_asset_detail MCP tool")
    get_asset_parser.add_argument("--token", default=None, help="Inbound MCP token")
    get_asset_parser.add_argument("--asset-id", required=True, help="Managed knowledge asset id")

    runtime_summary_parser = subparsers.add_parser("runtime-summary", help="Call the system_get_runtime_summary MCP tool")
    runtime_summary_parser.add_argument("--token", default=None, help="Inbound MCP token")

    list_capabilities_parser = subparsers.add_parser("list-capabilities", help="Call the capabilities_list MCP tool")
    list_capabilities_parser.add_argument("--token", default=None, help="Inbound MCP token")
    list_capabilities_parser.add_argument("--refresh-health", action="store_true", help="Refresh capability health before returning results")

    get_capability_parser = subparsers.add_parser("get-capability", help="Call the capabilities_get_detail MCP tool")
    get_capability_parser.add_argument("--token", default=None, help="Inbound MCP token")
    get_capability_parser.add_argument("--capability-name", required=True, help="Registered capability name")
    get_capability_parser.add_argument("--refresh-health", action="store_true", help="Refresh capability health before returning results")

    list_artifacts_parser = subparsers.add_parser("list-artifacts", help="Call the artifacts_list MCP tool")
    list_artifacts_parser.add_argument("--token", default=None, help="Inbound MCP token")
    list_artifacts_parser.add_argument("--limit", type=int, default=20, help="Maximum artifact records to return")
    list_artifacts_parser.add_argument("--session-timestamp", default=None, help="Optional session timestamp filter")
    list_artifacts_parser.add_argument("--artifact-kind", default=None, help="Optional artifact kind filter: report or infographic")

    get_artifact_parser = subparsers.add_parser("get-artifact", help="Call the artifacts_get_detail MCP tool")
    get_artifact_parser.add_argument("--token", default=None, help="Inbound MCP token")
    get_artifact_parser.add_argument("--artifact-name", required=True, help="Artifact filename from the output catalog")
    get_artifact_parser.add_argument("--max-chars", type=int, default=12000, help="Maximum preview characters to inline")

    discovery_dashboard_parser = subparsers.add_parser("discovery-dashboard", help="Call the discovery_get_dashboard MCP tool")
    discovery_dashboard_parser.add_argument("--token", default=None, help="Inbound MCP token")

    discovery_intelligence_parser = subparsers.add_parser("discovery-intelligence", help="Call the discovery_get_latest_intelligence MCP tool")
    discovery_intelligence_parser.add_argument("--token", default=None, help="Inbound MCP token")

    discovery_runbook_parser = subparsers.add_parser("discovery-runbook", help="Call the discovery_get_runbook MCP tool")
    discovery_runbook_parser.add_argument("--token", default=None, help="Inbound MCP token")
    discovery_runbook_parser.add_argument("--timestamp", default=None, help="Optional session timestamp selector")
    discovery_runbook_parser.add_argument("--persona", default="admin", help="Runbook persona: admin, analyst, or executive")
    discovery_runbook_parser.add_argument("--voice", default="direct", help="Operator voice: direct, evidence, or executive")

    discovery_compare_parser = subparsers.add_parser("discovery-compare", help="Call the discovery_compare_sessions MCP tool")
    discovery_compare_parser.add_argument("--token", default=None, help="Inbound MCP token")
    discovery_compare_parser.add_argument("--current-selection", default=None, help="Current session selector")
    discovery_compare_parser.add_argument("--baseline-selection", default=None, help="Baseline session selector")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    client = Dt4smsMcpClient(base_url=args.base_url)
    try:
        if args.command == "info":
            _pretty_print(client.get_info())
            return 0

        if args.command == "enable-mcp":
            client.maybe_login(_resolve_admin_user(args), _resolve_admin_password(args))
            _pretty_print(client.enable_external_mcp())
            return 0

        if args.command == "issue-token":
            client.maybe_login(_resolve_admin_user(args), _resolve_admin_password(args))
            if args.enable_mcp:
                client.enable_external_mcp()
            payload = client.issue_token(
                name=args.name,
                owner_user_id=args.owner_user_id,
                expires_days=args.expires_days,
            )
            _write_token_file(args.save_token, str(payload.get("access_token") or ""))
            _pretty_print(payload)
            return 0

        if args.command == "initialize":
            _pretty_print(client.initialize(_resolve_mcp_token(args), args.client_name, args.client_version))
            return 0

        if args.command == "list-tools":
            _pretty_print(client.list_tools(_resolve_mcp_token(args)))
            return 0

        if args.command == "call-tool":
            _pretty_print(
                client.call_tool(
                    _resolve_mcp_token(args),
                    args.tool_name,
                    _parse_arguments_json(args.arguments_json),
                )
            )
            return 0

        if args.command == "search":
            _pretty_print(
                client.call_tool(
                    _resolve_mcp_token(args),
                    "rag_search",
                    {"query": args.query, "limit": int(args.limit)},
                )
            )
            return 0

        if args.command == "build-context":
            _pretty_print(
                client.call_tool(
                    _resolve_mcp_token(args),
                    "rag_build_context",
                    {"query": args.query, "limit": int(args.limit)},
                )
            )
            return 0

        if args.command == "list-assets":
            _pretty_print(client.call_tool(_resolve_mcp_token(args), "rag_list_assets", {}))
            return 0

        if args.command == "get-asset":
            _pretty_print(
                client.call_tool(
                    _resolve_mcp_token(args),
                    "rag_get_asset_detail",
                    {"asset_id": args.asset_id},
                )
            )
            return 0

        if args.command == "runtime-summary":
            _pretty_print(client.get_runtime_summary(_resolve_mcp_token(args)))
            return 0

        if args.command == "list-capabilities":
            _pretty_print(
                client.list_capabilities(
                    _resolve_mcp_token(args),
                    refresh_health=bool(args.refresh_health),
                )
            )
            return 0

        if args.command == "get-capability":
            _pretty_print(
                client.get_capability_detail(
                    _resolve_mcp_token(args),
                    args.capability_name,
                    refresh_health=bool(args.refresh_health),
                )
            )
            return 0

        if args.command == "list-artifacts":
            _pretty_print(
                client.list_artifacts(
                    _resolve_mcp_token(args),
                    limit=int(args.limit),
                    session_timestamp=args.session_timestamp,
                    artifact_kind=args.artifact_kind,
                )
            )
            return 0

        if args.command == "get-artifact":
            _pretty_print(
                client.get_artifact_detail(
                    _resolve_mcp_token(args),
                    args.artifact_name,
                    max_chars=int(args.max_chars),
                )
            )
            return 0

        if args.command == "discovery-dashboard":
            _pretty_print(client.get_discovery_dashboard(_resolve_mcp_token(args)))
            return 0

        if args.command == "discovery-intelligence":
            _pretty_print(client.get_latest_intelligence(_resolve_mcp_token(args)))
            return 0

        if args.command == "discovery-runbook":
            _pretty_print(
                client.get_discovery_runbook(
                    _resolve_mcp_token(args),
                    timestamp=args.timestamp,
                    persona=args.persona,
                    voice=args.voice,
                )
            )
            return 0

        if args.command == "discovery-compare":
            _pretty_print(
                client.compare_discovery_sessions(
                    _resolve_mcp_token(args),
                    current_selection=args.current_selection,
                    baseline_selection=args.baseline_selection,
                )
            )
            return 0

        raise RuntimeError(f"Unsupported command: {args.command}")
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())