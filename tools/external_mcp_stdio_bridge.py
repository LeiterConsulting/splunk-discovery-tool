#!/usr/bin/env python3
"""Expose the DT4SMS external HTTP MCP surface over stdio framing."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, BinaryIO, Dict, Optional

import httpx


DEFAULT_BASE_URL = str(os.getenv("DT4SMS_BASE_URL") or "http://127.0.0.1:8003").rstrip("/")
DEFAULT_TIMEOUT = float(os.getenv("DT4SMS_HTTP_TIMEOUT") or "20")
DEFAULT_TOKEN = str(os.getenv("DT4SMS_MCP_TOKEN") or "").strip()


def read_framed_message(input_stream: BinaryIO) -> Optional[Dict[str, Any]]:
    headers: Dict[str, str] = {}
    line = input_stream.readline()
    while line in {b"\r\n", b"\n"}:
        line = input_stream.readline()
    if not line:
        return None

    while line and line not in {b"\r\n", b"\n"}:
        decoded = line.decode("ascii", errors="ignore")
        if ":" not in decoded:
            raise RuntimeError("Invalid stdio MCP header")
        key, value = decoded.split(":", 1)
        headers[key.strip().lower()] = value.strip()
        line = input_stream.readline()

    raw_content_length = headers.get("content-length")
    if raw_content_length is None:
        raise RuntimeError("Missing Content-Length header")

    try:
        content_length = int(raw_content_length)
    except ValueError as exc:
        raise RuntimeError("Invalid Content-Length header") from exc

    body = input_stream.read(content_length)
    if len(body) != content_length:
        raise RuntimeError("Incomplete stdio MCP message body")

    payload = json.loads(body.decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("Expected JSON-RPC object payload")
    return payload


def write_framed_message(output_stream: BinaryIO, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    output_stream.write(header)
    output_stream.write(body)
    if hasattr(output_stream, "flush"):
        output_stream.flush()


def _build_bridge_error_response(request_id: Any, message: str, code: int = -32001) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


class HttpJsonRpcBridgeTransport:
    def __init__(self, base_url: str, token: str, timeout: float = DEFAULT_TIMEOUT):
        cleaned_token = str(token or "").strip()
        if not cleaned_token:
            raise RuntimeError("An inbound MCP token is required. Use --token or set DT4SMS_MCP_TOKEN.")
        self.base_url = str(base_url or DEFAULT_BASE_URL).rstrip("/")
        self.client = httpx.Client(base_url=self.base_url, timeout=timeout, follow_redirects=True)
        self.token = cleaned_token

    def close(self) -> None:
        self.client.close()

    def forward_jsonrpc(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        response = self.client.post(
            "/api/external/mcp",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
            json=payload,
        )
        try:
            body = response.json()
        except Exception as exc:
            raise RuntimeError(f"Bridge upstream returned a non-JSON response with status {response.status_code}") from exc

        if isinstance(body, dict) and body.get("jsonrpc") == "2.0":
            return body
        raise RuntimeError(f"Bridge upstream returned an unexpected payload shape with status {response.status_code}")


def run_stdio_bridge_session(input_stream: BinaryIO, output_stream: BinaryIO, transport: Any) -> None:
    while True:
        payload = read_framed_message(input_stream)
        if payload is None:
            return

        request_id = payload.get("id") if isinstance(payload, dict) else None
        expects_response = request_id is not None

        try:
            response = transport.forward_jsonrpc(payload)
        except Exception as exc:
            if expects_response:
                write_framed_message(output_stream, _build_bridge_error_response(request_id, str(exc)))
            continue

        if expects_response and isinstance(response, dict):
            write_framed_message(output_stream, response)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DT4SMS external MCP stdio bridge")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="DT4SMS base URL")
    parser.add_argument("--token", default=DEFAULT_TOKEN, help="Inbound MCP token")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP request timeout in seconds")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        transport = HttpJsonRpcBridgeTransport(args.base_url, args.token, timeout=float(args.timeout))
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    try:
        run_stdio_bridge_session(sys.stdin.buffer, sys.stdout.buffer, transport)
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        transport.close()


if __name__ == "__main__":
    raise SystemExit(main())
