import asyncio
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

import web_app  # noqa: E402
from capabilities import CapabilityManager  # noqa: E402
from capabilities.tools.dashboard_service import DashboardService  # noqa: E402
from capabilities.tools.dashboard_store import DashboardOperationStore  # noqa: E402
from capabilities.tools.dashboards import CREATE_TOOL, STATUS_TOOL, USER_INFO_TOOL  # noqa: E402
from config_manager import ConfigManager  # noqa: E402
from incognito import IncognitoStore  # noqa: E402
from incognito.store import IncognitoPolicy  # noqa: E402
from security_manager import SecurityManager  # noqa: E402

MCP_URL = "https://splunk.example.com:8089/services/mcp"
WEB = "https://splunk.example.com:8000"
SPLUNK_USER = "analyst.contoso"
REPORT_NAME = "v2_operator_runbook_20260522_010203.md"
CONSTELLATION_RELEASES = "https://github.com/LeiterConsulting/constellation/releases"
SPLUNK_MCP_SERVER = "https://splunkbase.splunk.com/app/7931"


def tool_schema(names):
    properties = {name: {"type": "string"} for name in names}
    properties["schema_version"]["enum"] = ["1"]
    return {"type": "object", "properties": properties, "required": list(names)}


STANDARD_CATALOG = {"ok": True, "tools": ["splunk_run_query", "splunk_get_info", USER_INFO_TOOL], "schemas": {}, "checked_at": "2026-05-22T12:00:00+00:00"}
DASHBOARD_CATALOG = {
    "ok": True,
    "tools": STANDARD_CATALOG["tools"] + [CREATE_TOOL, STATUS_TOOL],
    "schemas": {
        CREATE_TOOL: tool_schema(["schema_version", "request_id", "expected_user", "brief_json"]),
        STATUS_TOOL: tool_schema(["schema_version", "request_id", "expected_user"]),
    },
    "checked_at": "2026-05-22T12:00:00+00:00",
}


def wrapped_reply(payload):
    return {
        "http_status": 200,
        "body": {"jsonrpc": "2.0", "id": "1", "result": {"content": [{"type": "text", "text": json.dumps({"results": [payload]})}]}},
        "timed_out": False,
        "error": "",
    }


class FakeSplunk:
    """Splunk MCP Server with Constellation: create starts the request, status reports it created."""

    def __init__(self):
        self.calls = []

    async def __call__(self, mcp, tool_name, arguments, timeout_seconds):
        self.calls.append((tool_name, dict(arguments), str(getattr(mcp, "url", ""))))
        if tool_name == USER_INFO_TOOL:
            return wrapped_reply({"username": SPLUNK_USER})
        base = {"schema_version": "1", "request_id": arguments["request_id"], "warnings": []}
        if tool_name == CREATE_TOOL:
            return wrapped_reply(dict(base, status="running", stage="authoring", poll_after_ms=500))
        return wrapped_reply(dict(
            base,
            status="created",
            title="Web errors",
            dashboard_id="contoso_web_errors",
            draft_id="draft_contoso_1",
            view_url=f"{WEB}/en-US/app/constellation/contoso_web_errors",
            edit_url=f"{WEB}/en-US/app/constellation/workspace?draft=draft_contoso_1",
        ))

    def named(self, tool_name):
        return [arguments for name, arguments, _url in self.calls if name == tool_name]

    def dashboard_calls(self):
        return [name for name, _arguments, _url in self.calls if name.startswith("constellation_")]


class DashboardRouteCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.temp_path = Path(self.temp.name)
        original_cwd = Path.cwd()
        os.chdir(self.temp_path)
        self.addCleanup(os.chdir, original_cwd)
        output = Path("output")
        output.mkdir()
        (output / REPORT_NAME).write_text("# Operator Runbook\n\n1. Track failed logins on the contoso web tier.\n", encoding="utf-8")

        self.config_manager = ConfigManager(str(self.temp_path / "config.encrypted"))
        self.config_manager.update_mcp(url=MCP_URL, token="contoso-fixture-token", verify_ssl=False)
        self.incognito = IncognitoStore(self.temp_path / "incognito", Fernet(Fernet.generate_key()))
        self.fake = FakeSplunk()
        self.logs = []
        self.catalog = STANDARD_CATALOG

        async def quick_sleep(_seconds):
            await asyncio.sleep(0)

        async def catalog_for(_config, force_refresh=False, wait_seconds=None):
            return dict(self.catalog)

        service = DashboardService(
            DashboardOperationStore(self.temp_path / "dashboards"),
            settings=web_app._dashboard_settings,
            binding_is_current=web_app._dashboard_binding_is_current,
            log=self.logs.append,
            call=self.fake,
            sleep=quick_sleep,
        )
        service.recover_delay_seconds = 0
        patches = {
            "config_manager": self.config_manager,
            "capability_manager": CapabilityManager(self.config_manager, registry=web_app.capability_registry),
            "security_manager": SecurityManager(str(self.temp_path / "security.db")),
            "external_surface_rate_limiter": web_app.ExternalSurfaceRateLimiter(),
            "incognito_store": self.incognito,
            "dashboard_service": service,
            "get_connection_tool_catalog": catalog_for,
            "run_due_environment_checks": mock.AsyncMock(),
        }
        for name, value in patches.items():
            patcher = mock.patch.object(web_app, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

        # One event loop for the whole test, so requests followed in the background keep running.
        self.client = TestClient(web_app.app)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def turn_on(self, client=None):
        client = client or self.client
        self.assertEqual(client.post("/api/capabilities/splunk_dashboards/install").status_code, 200)
        self.assertEqual(client.post("/api/capabilities/splunk_dashboards/enable").status_code, 200)

    def wait_for_status(self, request_id, expected, client=None):
        client = client or self.client
        deadline = time.monotonic() + 10
        operation = {}
        while time.monotonic() < deadline:
            operation = client.get(f"/api/dashboards/operations/{request_id}").json().get("operation") or {}
            if operation.get("status") == expected and not operation.get("polling"):
                return operation
            time.sleep(0.05)
        self.fail(f"Expected {expected}, got {operation.get('status')}")


class DashboardRouteTests(DashboardRouteCase):
    def test_status_and_propose_say_what_is_missing(self):
        status = self.client.get("/api/dashboards/status").json()
        self.assertFalse(status["installed"])
        self.assertFalse(status["can_create"])
        self.assertIn("not installed", status["blocked_reason"])
        self.assertEqual(
            [(item["name"], item["url"]) for item in status["requirements"]],
            [("Constellation", CONSTELLATION_RELEASES), ("Splunk MCP Server", SPLUNK_MCP_SERVER)],
        )

        refused = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME})
        self.assertEqual(refused.status_code, 409)
        self.assertEqual(set(refused.json()), {"detail", "support", "requirements"})

        self.turn_on()
        status = self.client.get("/api/dashboards/status?refresh=true").json()
        self.assertEqual(status["support"]["state"], "potential")
        self.assertEqual(status["support"]["missing_tools"], [CREATE_TOOL, STATUS_TOOL])
        self.assertIn("install Constellation in that Splunk environment", status["blocked_reason"])

        refused = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME})
        self.assertEqual(refused.status_code, 409)
        payload = refused.json()
        self.assertEqual(payload["support"]["state"], "potential")
        self.assertEqual({item["url"] for item in payload["requirements"]}, {CONSTELLATION_RELEASES, SPLUNK_MCP_SERVER})
        self.assertEqual(self.fake.calls, [])

    def test_report_plan_then_create_through_the_connection(self):
        self.turn_on()
        self.catalog = DASHBOARD_CATALOG
        proposed = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME})
        self.assertEqual(proposed.status_code, 200, proposed.text)
        proposal = proposed.json()["proposal"]
        self.assertEqual(proposal["splunk_user"], SPLUNK_USER)
        self.assertEqual(proposal["splunk_web_url"], WEB)
        self.assertEqual(proposal["splunk_web_url_source"], "derived")
        self.assertEqual(proposal["brief"]["title"], "Findings from the Operator Runbook report")
        self.assertEqual(proposal["brief"]["provenance"], {"kind": "discovery_report", "label": REPORT_NAME})
        self.assertEqual([item["field"] for item in proposal["problems"]], ["source.index"])
        self.assertEqual(self.fake.dashboard_calls(), [], "Drafting a plan must not call Constellation.")

        brief = dict(proposal["brief"], source={"kind": "index", "index": "contoso_web"})
        changed = self.client.post("/api/dashboards/create", json={"proposal_id": proposal["proposal_id"], "binding_key": "0" * 32, "brief": brief})
        self.assertEqual(changed.status_code, 409)
        self.assertIn("changed after this plan was made", changed.json()["detail"])

        invalid = self.client.post("/api/dashboards/create", json={"proposal_id": proposal["proposal_id"], "binding_key": proposal["binding_key"], "brief": proposal["brief"]})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual([item["field"] for item in invalid.json()["problems"]], ["source.index"])
        self.assertEqual(self.fake.dashboard_calls(), [])

        created = self.client.post("/api/dashboards/create", json={"proposal_id": proposal["proposal_id"], "binding_key": proposal["binding_key"], "brief": brief})
        self.assertEqual(created.status_code, 200, created.text)
        request_id = created.json()["operation"]["request_id"]
        operation = self.wait_for_status(request_id, "created")
        self.assertEqual(operation["receipt"]["view_url"], f"{WEB}/en-US/app/constellation/contoso_web_errors")
        self.assertEqual(operation["splunk_user"], SPLUNK_USER)

        create_args = self.fake.named(CREATE_TOOL)
        self.assertEqual(len(create_args), 1)
        self.assertEqual(create_args[0]["expected_user"], SPLUNK_USER)
        self.assertEqual(json.loads(create_args[0]["brief_json"])["source"], {"kind": "index", "index": "contoso_web"})
        self.assertTrue(all(url == MCP_URL for _name, _args, url in self.fake.calls))

        listed = self.client.get("/api/dashboards/operations").json()["operations"]
        self.assertEqual([item["request_id"] for item in listed], [request_id])
        checked = self.client.post(f"/api/dashboards/operations/{request_id}/check")
        self.assertEqual(checked.status_code, 200)
        self.assertEqual(checked.json()["operation"]["status"], "created")
        self.assertEqual(self.client.get("/api/dashboards/operations/20260522T120000Z-" + "0" * 32).status_code, 404)

        joined = "\n".join(self.logs)
        self.assertNotIn("contoso", joined)
        self.assertNotIn("https://", joined)

    def test_saved_splunk_web_address_is_used_for_links(self):
        self.turn_on()
        self.catalog = DASHBOARD_CATALOG
        refused = self.client.post("/api/capabilities/splunk_dashboards/config", json={"config": {"splunk_web_urls": {"": "http://splunk.example.com:8000"}}})
        self.assertEqual(refused.status_code, 400)
        self.assertIn("Enter an HTTPS Splunk Web address", refused.text)
        saved = self.client.post("/api/capabilities/splunk_dashboards/config", json={"config": {"splunk_web_urls": {"": "https://web.example.com/"}}})
        self.assertEqual(saved.status_code, 200)
        connections = self.client.get("/api/capabilities/splunk_dashboards/connections").json()["connections"]
        self.assertEqual(connections[0]["splunk_web_url"], "https://web.example.com")
        self.assertEqual(connections[0]["derived_splunk_web_url"], WEB)
        self.assertEqual(connections[0]["support"]["state"], "available")
        proposal = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME}).json()["proposal"]
        self.assertEqual((proposal["splunk_web_url"], proposal["splunk_web_url_source"]), ("https://web.example.com", "configured"))

    def test_incognito_blocks_creation_but_status_stays_readable(self):
        self.turn_on()
        self.catalog = DASHBOARD_CATALOG
        self.incognito.set_preference("local", True)
        status = self.client.get("/api/dashboards/status")
        self.assertEqual(status.status_code, 200)
        self.assertFalse(status.json()["can_create"])
        self.assertIn("incognito mode is on", status.json()["blocked_reason"])
        self.assertEqual(self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME}).status_code, 409)
        blocked = self.client.post("/api/dashboards/create", json={"proposal_id": "a" * 32, "binding_key": "b" * 32, "brief": {"title": "x"}})
        self.assertEqual(blocked.status_code, 409)
        self.assertIn("incognito mode is on", blocked.json()["detail"])

        self.incognito.set_preference("local", False)
        self.incognito.save_policy(IncognitoPolicy(force_for_cloud=True))
        with mock.patch.object(web_app, "llm_provider_kind", return_value="local"):
            required = self.client.get("/api/dashboards/status").json()
        self.assertFalse(required["can_create"])
        self.assertIn("requires incognito mode for cloud AI models", required["blocked_reason"])
        self.assertEqual(self.fake.calls, [])

    def test_chat_answers_with_a_plan_or_with_what_to_install(self):
        config = self.config_manager.get()

        def ask(message):
            return asyncio.run(web_app.handle_dashboard_chat_request(message, [], None, {}, config, None))

        self.assertIsNone(ask("Create a dashboard of web errors"), "Chat answers as usual while the capability is off.")
        self.turn_on()
        self.assertIsNone(ask("How do I create a dashboard?"))

        text, proposal = ask("Create a dashboard of web errors")
        self.assertIsNone(proposal)
        self.assertIn("does not offer the dashboard tools yet", text)
        self.assertIn(f"[Constellation releases]({CONSTELLATION_RELEASES})", text)
        self.assertIn(f"[Splunk MCP Server on Splunkbase]({SPLUNK_MCP_SERVER})", text)

        self.catalog = DASHBOARD_CATALOG
        text, proposal = ask("Create a dashboard of web errors")
        self.assertIn("Nothing goes to Splunk until you click Create.", text)
        self.assertEqual(proposal["brief"]["title"], "Web errors")
        self.assertEqual(proposal["brief"]["provenance"]["kind"], "conversation")
        self.assertEqual(proposal["splunk_user"], SPLUNK_USER)
        self.assertEqual(self.fake.dashboard_calls(), [])

    def test_report_label(self):
        self.assertEqual(web_app._dashboard_report_label(REPORT_NAME), "Operator Runbook")
        self.assertEqual(web_app._dashboard_report_label("v2_ai_summary_20260522_010203.md"), "AI Summary")
        self.assertEqual(web_app._dashboard_report_label("notes.txt"), "Notes")


class DashboardSignInTests(DashboardRouteCase):
    def sign_in_admin(self):
        self.assertTrue(self.config_manager.update_security(auth_enabled=True, session_timeout_minutes=60, password_min_length=14))
        password = "".join(["Dash", "Admin", "Pass", "123!"])
        self.assertEqual(self.client.post("/api/auth/login", json={"username": "admin", "password": "password"}).status_code, 200)
        reset = self.client.post("/api/auth/reset-password", json={"current_password": "password", "new_password": password, "confirm_password": password})
        self.assertEqual(reset.status_code, 200)

    def add_analyst(self, username, connection_name=None):
        password = "".join(["Dash", "Analyst", "Pass", "123!"])
        created = self.client.post("/api/security/users", json={
            "username": username, "password": password, "role": "analyst", "require_password_reset": False, "mcp_config_name": connection_name,
        })
        self.assertEqual(created.status_code, 200, created.text)
        return password

    def add_scoped_report(self, connection_name, timestamp):
        scope_key = f"mcp:{connection_name}"
        report_name = f"v2_operator_runbook_{timestamp}.md"
        (web_app._discovery_scope_output_dir(scope_key) / report_name).write_text("# Operator Runbook\n", encoding="utf-8")
        overview = SimpleNamespace(total_indexes=0, total_sourcetypes=0, total_hosts=0, total_users=0, data_volume_24h="unknown", splunk_version="unknown")
        web_app.register_discovery_session(
            timestamp=timestamp,
            overview=overview,
            report_paths=[report_name],
            mcp_capabilities={},
            classifications={},
            recommendations=[],
            suggested_use_cases=[],
            discovery_step_count=0,
            discovery_scope={"scope_key": scope_key, "scope_label": connection_name, "active_mcp_config_name": connection_name},
        )
        return report_name

    def signed_in(self, username, password):
        # A plain client: entering a second TestClient would share the app's startup tasks with the main one.
        client = TestClient(web_app.app)
        self.addCleanup(client.close)
        self.assertEqual(client.post("/api/auth/login", json={"username": username, "password": password}).status_code, 200)
        return client

    def test_admins_change_the_capability_and_each_user_creates_only_through_their_own_connection(self):
        self.sign_in_admin()
        self.turn_on()
        self.catalog = DASHBOARD_CATALOG
        self.assertTrue(self.config_manager.save_mcp_config("contoso-analyst", url=MCP_URL, token="contoso-analyst-token", verify_ssl=False))
        assigned_password = self.add_analyst("analyst1", "contoso-analyst")
        unassigned_password = self.add_analyst("analyst2")

        admin_status = self.client.get("/api/dashboards/status").json()
        self.assertFalse(admin_status["can_create"])
        self.assertIn("none is assigned to you", admin_status["blocked_reason"])

        analyst = self.signed_in("analyst1", assigned_password)
        for action in ("install", "enable", "disable", "uninstall", "test", "reindex"):
            self.assertEqual(analyst.post(f"/api/capabilities/splunk_dashboards/{action}").status_code, 403, action)
        self.assertEqual(analyst.post("/api/capabilities/splunk_dashboards/config", json={"config": {}}).status_code, 403)
        self.assertEqual(analyst.get("/api/capabilities/splunk_dashboards/connections").status_code, 403)
        self.assertEqual(analyst.get("/api/capabilities").status_code, 200)

        status = analyst.get("/api/dashboards/status").json()
        self.assertTrue(status["can_create"], status["blocked_reason"])
        self.assertEqual(status["connection"]["connection_label"], "contoso-analyst")
        # Reports belong to the scope that ran them, so the shared report is not this user's to plan from.
        self.assertEqual(analyst.post("/api/dashboards/propose", json={"report_name": REPORT_NAME}).status_code, 404)
        scoped_report = self.add_scoped_report("contoso-analyst", "20260523_010203")
        proposal = analyst.post("/api/dashboards/propose", json={"report_name": scoped_report, "focus": "Create a dashboard of failed logins"})
        self.assertEqual(proposal.status_code, 200, proposal.text)
        self.assertEqual(proposal.json()["proposal"]["brief"]["title"], "Failed logins")

        self.assertEqual(self.client.post("/api/capabilities/splunk_dashboards/disable").status_code, 200)
        other = self.signed_in("analyst2", unassigned_password)
        status = other.get("/api/dashboards/status").json()
        self.assertEqual(status["blocked_reason"], "Splunk Dashboards is turned off. Ask an administrator to enable it on the Capabilities tab.")
        self.assertEqual(self.client.post("/api/capabilities/splunk_dashboards/enable").status_code, 200)
        status = other.get("/api/dashboards/status").json()
        self.assertFalse(status["can_create"])
        self.assertIn("none is assigned to you", status["blocked_reason"])
        self.assertEqual(other.get("/api/dashboards/operations").json()["operations"], [])


if __name__ == "__main__":
    unittest.main()
