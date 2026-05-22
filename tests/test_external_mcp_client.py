import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


import external_mcp_client as client_module


class RecordingClient(client_module.Dt4smsMcpClient):
    def __init__(self):
        self.calls = []

    def call_tool(self, token, tool_name, arguments=None, request_id=3):
        payload = {
            "token": token,
            "tool_name": tool_name,
            "arguments": dict(arguments or {}),
            "request_id": request_id,
        }
        self.calls.append(payload)
        return payload


class ExternalMcpClientContractTests(unittest.TestCase):
    def test_discovery_helper_methods_map_to_expected_tools(self):
        client = RecordingClient()

        dashboard = client.get_discovery_dashboard("token-a")
        intelligence = client.get_latest_intelligence("token-b")
        runbook = client.get_discovery_runbook(
            "token-c",
            timestamp="20260517_101010",
            persona="analyst",
            voice="evidence",
        )
        compare = client.compare_discovery_sessions(
            "token-d",
            current_selection="latest",
            baseline_selection="previous",
        )

        self.assertEqual(dashboard["tool_name"], "discovery_get_dashboard")
        self.assertEqual(dashboard["arguments"], {})

        self.assertEqual(intelligence["tool_name"], "discovery_get_latest_intelligence")
        self.assertEqual(intelligence["arguments"], {})

        self.assertEqual(runbook["tool_name"], "discovery_get_runbook")
        self.assertEqual(
            runbook["arguments"],
            {"timestamp": "20260517_101010", "persona": "analyst", "voice": "evidence"},
        )

        self.assertEqual(compare["tool_name"], "discovery_compare_sessions")
        self.assertEqual(
            compare["arguments"],
            {"current_selection": "latest", "baseline_selection": "previous"},
        )


if __name__ == "__main__":
    unittest.main()
