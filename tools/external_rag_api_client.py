#!/usr/bin/env python3
"""Small CLI for DT4SMS external RAG API bootstrapping and usage."""

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


def _pretty_print(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


class Dt4smsClient:
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

    def enable_external_api(self) -> Dict[str, Any]:
        return self._request_json(
            "POST",
            "/api/config",
            json={"security": {"external_api_enabled": True}},
        )

    def issue_token(
        self,
        name: str,
        scopes: list[str],
        token_type: str = "external_api",
        owner_user_id: Optional[int] = None,
        expires_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "name": name,
            "token_type": token_type,
            "scopes": scopes,
        }
        if owner_user_id is not None:
            payload["owner_user_id"] = int(owner_user_id)
        if expires_days is not None:
            payload["expires_in_days"] = int(expires_days)
        return self._request_json("POST", "/api/security/tokens", json=payload)

    def get_info(self) -> Dict[str, Any]:
        return self._request_json("GET", "/api/external/info")

    def get_index_summary(self, token: str) -> Dict[str, Any]:
        return self._request_json(
            "GET",
            "/api/external/rag/index-summary",
            headers={"Authorization": f"Bearer {token}"},
        )

    def search(self, token: str, query: str, limit: int = 4) -> Dict[str, Any]:
        return self._request_json(
            "POST",
            "/api/external/rag/search",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": query, "limit": int(limit)},
        )

    def list_assets(self, token: str) -> Dict[str, Any]:
        return self._request_json(
            "GET",
            "/api/external/rag/assets",
            headers={"Authorization": f"Bearer {token}"},
        )

    def get_asset(self, token: str, asset_id: str) -> Dict[str, Any]:
        return self._request_json(
            "GET",
            f"/api/external/rag/assets/{asset_id}",
            headers={"Authorization": f"Bearer {token}"},
        )


def _resolve_admin_user(args: argparse.Namespace) -> Optional[str]:
    return args.admin_user or os.getenv("DT4SMS_ADMIN_USER") or None


def _resolve_admin_password(args: argparse.Namespace) -> Optional[str]:
    return args.admin_password or os.getenv("DT4SMS_ADMIN_PASSWORD") or None


def _resolve_external_token(args: argparse.Namespace) -> str:
    token = args.token or os.getenv("DT4SMS_EXTERNAL_TOKEN") or ""
    token = str(token).strip()
    if not token:
        raise RuntimeError("An external API token is required. Use --token or set DT4SMS_EXTERNAL_TOKEN.")
    return token


def _write_token_file(path: Optional[str], token: str) -> None:
    if not path:
        return
    token_path = Path(path)
    token_path.write_text(token, encoding="utf-8")
    print(f"Saved token to {token_path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DT4SMS external RAG API helper")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="DT4SMS base URL")
    parser.add_argument("--admin-user", default=None, help="Admin username for auth-enabled installs")
    parser.add_argument("--admin-password", default=None, help="Admin password for auth-enabled installs")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("info", help="Call the unauthenticated discovery endpoint")

    subparsers.add_parser("enable-api", help="Enable the external API through the admin config endpoint")

    issue_token_parser = subparsers.add_parser("issue-token", help="Create an external API token")
    issue_token_parser.add_argument("--name", required=True, help="Token display name")
    issue_token_parser.add_argument("--token-type", default="external_api", help="Token type to issue")
    issue_token_parser.add_argument("--scopes", nargs="+", required=True, help="One or more token scopes")
    issue_token_parser.add_argument("--owner-user-id", type=int, default=None, help="Optional owning user id")
    issue_token_parser.add_argument("--expires-days", type=int, default=30, help="Token expiry in days")
    issue_token_parser.add_argument("--enable-api", action="store_true", help="Enable the external API before creating the token")
    issue_token_parser.add_argument("--save-token", default=None, help="Optional file path to store the plaintext token")

    index_summary_parser = subparsers.add_parser("index-summary", help="Fetch external RAG index summary")
    index_summary_parser.add_argument("--token", default=None, help="External API token")

    search_parser = subparsers.add_parser("search", help="Run an external RAG search")
    search_parser.add_argument("--token", default=None, help="External API token")
    search_parser.add_argument("--query", required=True, help="Search query")
    search_parser.add_argument("--limit", type=int, default=4, help="Maximum chunks to request")

    list_assets_parser = subparsers.add_parser("list-assets", help="List external RAG assets")
    list_assets_parser.add_argument("--token", default=None, help="External API token")

    get_asset_parser = subparsers.add_parser("get-asset", help="Load one external RAG asset")
    get_asset_parser.add_argument("--token", default=None, help="External API token")
    get_asset_parser.add_argument("--asset-id", required=True, help="Managed knowledge asset id")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    client = Dt4smsClient(base_url=args.base_url)
    try:
        if args.command == "info":
            _pretty_print(client.get_info())
            return 0

        if args.command == "enable-api":
            client.maybe_login(_resolve_admin_user(args), _resolve_admin_password(args))
            _pretty_print(client.enable_external_api())
            return 0

        if args.command == "issue-token":
            client.maybe_login(_resolve_admin_user(args), _resolve_admin_password(args))
            if args.enable_api:
                client.enable_external_api()
            payload = client.issue_token(
                name=args.name,
                scopes=list(args.scopes or []),
                token_type=args.token_type,
                owner_user_id=args.owner_user_id,
                expires_days=args.expires_days,
            )
            _write_token_file(args.save_token, str(payload.get("access_token") or ""))
            _pretty_print(payload)
            return 0

        if args.command == "index-summary":
            _pretty_print(client.get_index_summary(_resolve_external_token(args)))
            return 0

        if args.command == "search":
            _pretty_print(client.search(_resolve_external_token(args), args.query, limit=args.limit))
            return 0

        if args.command == "list-assets":
            _pretty_print(client.list_assets(_resolve_external_token(args)))
            return 0

        if args.command == "get-asset":
            _pretty_print(client.get_asset(_resolve_external_token(args), args.asset_id))
            return 0

        raise RuntimeError(f"Unsupported command: {args.command}")
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())