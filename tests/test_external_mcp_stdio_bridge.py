import io
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


import external_mcp_stdio_bridge as bridge


def _frame_message(payload):
    body = json.dumps(payload).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body


class FakeBridgeTransport:
    def __init__(self, response_payload=None, error=None):
        self.response_payload = response_payload or {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        self.error = error
        self.requests = []

    def forward_jsonrpc(self, payload):
        self.requests.append(payload)
        if self.error is not None:
            raise self.error
        response = json.loads(json.dumps(self.response_payload))
        if isinstance(payload, dict) and "id" in payload:
            response["id"] = payload["id"]
        return response

    def close(self):
        return None


class ExternalMcpStdioBridgeTests(unittest.TestCase):
    def test_run_bridge_session_forwards_request_and_writes_framed_response(self):
        transport = FakeBridgeTransport(
            response_payload={
                "jsonrpc": "2.0",
                "id": 1,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "serverInfo": {"name": "dt4sms-external-mcp", "version": "1.0.0"},
                },
            }
        )
        input_stream = io.BytesIO(
            _frame_message(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-03-26", "clientInfo": {"name": "test", "version": "1.0"}},
                }
            )
        )
        output_stream = io.BytesIO()

        bridge.run_stdio_bridge_session(input_stream, output_stream, transport)

        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(transport.requests[0]["method"], "initialize")
        output_stream.seek(0)
        response = bridge.read_framed_message(output_stream)
        self.assertEqual(response["id"], 1)
        self.assertEqual(response["result"]["protocolVersion"], "2025-03-26")

    def test_run_bridge_session_ignores_notification_response_body(self):
        transport = FakeBridgeTransport(response_payload={"jsonrpc": "2.0", "result": {"acknowledged": True}})
        input_stream = io.BytesIO(
            _frame_message(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                }
            )
        )
        output_stream = io.BytesIO()

        bridge.run_stdio_bridge_session(input_stream, output_stream, transport)

        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(output_stream.getvalue(), b"")

    def test_run_bridge_session_returns_jsonrpc_error_when_transport_fails(self):
        transport = FakeBridgeTransport(error=RuntimeError("bridge transport unavailable"))
        input_stream = io.BytesIO(
            _frame_message(
                {
                    "jsonrpc": "2.0",
                    "id": 9,
                    "method": "tools/list",
                }
            )
        )
        output_stream = io.BytesIO()

        bridge.run_stdio_bridge_session(input_stream, output_stream, transport)

        output_stream.seek(0)
        response = bridge.read_framed_message(output_stream)
        self.assertEqual(response["id"], 9)
        self.assertEqual(response["error"]["code"], -32001)
        self.assertIn("bridge transport unavailable", response["error"]["message"])


if __name__ == "__main__":
    unittest.main()
