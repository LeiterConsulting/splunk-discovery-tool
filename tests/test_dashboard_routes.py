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
from capabilities.tools.dashboards import CREATE_TOOL, INSPECT_TOOL, STATUS_TOOL, USER_INFO_TOOL  # noqa: E402
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
INSPECTION_CATALOG = {
    **DASHBOARD_CATALOG,
    "tools": DASHBOARD_CATALOG["tools"] + [INSPECT_TOOL],
    "schemas": {
        **DASHBOARD_CATALOG["schemas"],
        INSPECT_TOOL: tool_schema(["schema_version", "expected_user", "scope_json"]),
    },
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
        self.created_ids = set()
        self.authoring_mode = "authoring"
        self.before_inspection_reply = None
        self.create_problem = None
        self.failed_requests = {}

    async def __call__(self, mcp, tool_name, arguments, timeout_seconds):
        self.calls.append((tool_name, dict(arguments), str(getattr(mcp, "url", ""))))
        if tool_name == USER_INFO_TOOL:
            return wrapped_reply({"username": SPLUNK_USER})
        if tool_name == INSPECT_TOOL:
            scope = json.loads(arguments["scope_json"])
            if self.before_inspection_reply:
                self.before_inspection_reply()
            return wrapped_reply({
                "schema_version": "1", "status": "observed",
                "source": {key: value for key, value in dict(scope["source"], language="spl").items() if key != "query"},
                "time_range": scope["time_range"],
                "sample": {
                    "rows": 3, "row_limit": 200,
                    "grain": "indexed_observations" if scope["source"]["kind"] == "index" else "existing_search_output",
                    "completion": "partial", "reasons": ["resource_limit"],
                },
                "fields": [{"name": "latency_ms", "present": 2, "missing": 1, "numeric": 2, "multivalue": 0,
                            "unit": "ms", "basis": "field_name", "value": "discard synthetic value"}],
                "results": [{"_raw": "discard synthetic event"}],
            })
        base = {"schema_version": "1", "request_id": arguments["request_id"], "warnings": []}
        if tool_name == CREATE_TOOL:
            self.created_ids.add(arguments["request_id"])
            if self.create_problem:
                self.failed_requests[arguments["request_id"]] = dict(base, **self.create_problem)
            return wrapped_reply(dict(base, status="running", stage="authoring", poll_after_ms=500))
        if arguments["request_id"] in self.failed_requests:
            return wrapped_reply(self.failed_requests[arguments["request_id"]])
        if arguments["request_id"] not in self.created_ids:
            if self.authoring_mode in {"feature_disabled", "identity_unavailable"}:
                return wrapped_reply({"error": "Fixture refusal", "code": self.authoring_mode})
            if self.authoring_mode == "timeout":
                return {"http_status": None, "timed_out": True}
            status = dict(base, status="not_found")
            if self.authoring_mode != "legacy":
                status["pilot"] = {"mode": self.authoring_mode, "identity_verified": True}
            return wrapped_reply(status)
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

        self.config_manager = ConfigManager(str(self.temp_path / "config.encrypted"))
        self.config_manager.update_mcp(url=MCP_URL, token="contoso-fixture-token", verify_ssl=False)
        scope_key = web_app._mcp_workspace(self.config_manager.get())["scope_key"]
        report_dir = web_app._discovery_scope_output_dir(scope_key)
        (report_dir / REPORT_NAME).write_text("# Operator Runbook\n\n1. Track failed logins on the contoso web tier.\n", encoding="utf-8")
        web_app.register_discovery_session(
            timestamp="20260522_010203",
            overview=SimpleNamespace(total_indexes=0, total_sourcetypes=0, total_hosts=0, total_users=0,
                                     data_volume_24h="unknown", splunk_version="unknown"),
            report_paths=[REPORT_NAME],
            mcp_capabilities={},
            classifications={},
            recommendations=[],
            suggested_use_cases=[],
            discovery_step_count=0,
            discovery_scope=web_app._mcp_workspace(self.config_manager.get()),
        )
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
        self.assertIn("MCP-enabled Constellation build", status["blocked_reason"])
        self.assertEqual(status["support"]["message"], status["blocked_reason"])

        refused = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME})
        self.assertEqual(refused.status_code, 409)
        payload = refused.json()
        self.assertEqual(payload["support"]["state"], "potential")
        self.assertEqual({item["url"] for item in payload["requirements"]}, {CONSTELLATION_RELEASES, SPLUNK_MCP_SERVER})
        self.assertEqual(self.fake.calls, [])

    def test_authoring_check_distinguishes_modes_and_keeps_the_status_call_read_only(self):
        self.turn_on()
        self.catalog = DASHBOARD_CATALOG
        for mode, expected, allowed in (
            ("probe", "pilot_probe_only", False),
            ("fixture", "fixture", False),
            ("feature_disabled", "feature_disabled", False),
            ("identity_unavailable", "identity_unavailable", False),
            ("timeout", "unconfirmed", False),
            ("legacy", "legacy", True),
            ("authoring", "authoring", True),
        ):
            with self.subTest(mode=mode):
                self.fake.authoring_mode = mode
                status = self.client.get("/api/dashboards/status").json()
                self.assertEqual(status["support"]["state"], "available")
                self.assertEqual(status["authoring"]["state"], expected)
                self.assertEqual(status["can_create"], allowed)
                self.assertEqual(status["connection"]["splunk_user"], SPLUNK_USER)
        checked = self.fake.named(STATUS_TOOL)
        self.assertEqual(len(checked), 7)
        self.assertEqual(len({item["request_id"] for item in checked}), 7)
        for arguments in checked:
            self.assertEqual(set(arguments), {"schema_version", "request_id", "expected_user"})
            self.assertEqual(arguments["expected_user"], SPLUNK_USER)
        self.assertFalse(self.fake.named(CREATE_TOOL))
        self.assertEqual(self.client.get("/api/dashboards/operations").json()["operations"], [])

    def test_probe_blocks_chat_and_report_planning_and_is_rechecked_on_create(self):
        self.turn_on()
        self.catalog = DASHBOARD_CATALOG
        proposal = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME}).json()["proposal"]
        self.fake.authoring_mode = "probe"
        with mock.patch.object(web_app, "draft_dashboard_plan", new_callable=mock.AsyncMock) as draft:
            refused = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME})
            self.assertEqual(refused.status_code, 409)
            self.assertIn("probe mode", refused.json()["detail"])
            reply, chat_proposal = asyncio.run(web_app.handle_dashboard_chat_request(
                "Create a dashboard of web errors", [], None, {}, self.config_manager.get(), None
            ))
            self.assertIn("probe mode", reply)
            self.assertIsNone(chat_proposal)
            draft.assert_not_awaited()
        blocked = self.client.post("/api/dashboards/create", json={
            "proposal_id": proposal["proposal_id"], "binding_key": proposal["binding_key"],
            "brief": dict(proposal["brief"], source={"kind": "index", "index": "contoso_web"}),
        })
        self.assertEqual(blocked.status_code, 409)
        self.assertIn("probe mode", blocked.json()["detail"])
        self.assertFalse(self.fake.named(CREATE_TOOL))

    def test_dashboard_source_options_are_bound_to_the_plan_and_return_only_names(self):
        self.turn_on()
        self.catalog = dict(DASHBOARD_CATALOG, tools=DASHBOARD_CATALOG["tools"] + ["splunk_get_indexes"])
        proposal = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME}).json()["proposal"]
        request = {"binding_key": proposal["binding_key"]}
        with mock.patch.object(web_app, "call_dashboard_mcp_tool", new_callable=mock.AsyncMock) as call:
            call.return_value = {"http_status": 200, "body": {"result": {"results": [
                {"title": "contoso_web", "private": "omitted"},
                {"name": "contoso_app"},
                {"title": "contoso_web"},
                {"name": "invalid index name"},
            ]}}}
            indexes = self.client.post("/api/dashboards/source-options", json=request)
            self.assertEqual(indexes.json(), {"options": ["contoso_app", "contoso_web"]})
            self.assertIn("no-store", indexes.headers["Cache-Control"])
            connection, tool, arguments, _timeout = call.await_args.args
            self.assertEqual((connection.url, connection.token), (MCP_URL, "contoso-fixture-token"))
            self.assertEqual((tool, arguments), ("splunk_get_indexes", {"count": 100}))

            call.return_value = {"http_status": 200, "body": {"result": {"results": [
                {"sourcetype": "access:combined", "count": "17", "_raw": "omitted"},
            ]}}}
            types = self.client.post("/api/dashboards/source-options", json=dict(request, index="contoso_web", earliest="-1h"))
            self.assertEqual(types.json(), {"options": ["access:combined"]})
            _connection, tool, arguments, _timeout = call.await_args.args
            self.assertEqual(tool, "splunk_run_query")
            self.assertEqual(arguments["earliest_time"], "-1h")
            self.assertEqual(arguments["latest_time"], "now")
            self.assertIn('index="contoso_web" by sourcetype', arguments["query"])

            invalid = self.client.post("/api/dashboards/source-options", json=dict(request, index="*", earliest="-1h"))
            self.assertEqual(invalid.status_code, 400)
            self.incognito.set_preference("local", True)
            self.assertEqual(self.client.post("/api/dashboards/source-options", json=request).status_code, 409)
            self.incognito.set_preference("local", False)
            self.config_manager.update_mcp(url=MCP_URL, token="replacement-fixture-token", verify_ssl=False)
            stale = self.client.post("/api/dashboards/source-options", json=request)
            self.assertEqual(stale.status_code, 409)
            self.assertIn("connection or user changed", stale.json()["detail"])
            self.assertEqual(call.await_count, 2)
        self.assertFalse(self.fake.named(CREATE_TOOL))

    def test_report_plan_then_create_through_the_connection(self):
        self.turn_on()
        self.catalog = DASHBOARD_CATALOG
        proposed = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME})
        self.assertEqual(proposed.status_code, 200, proposed.text)
        proposal = proposed.json()["proposal"]
        self.assertFalse(proposal["source_inspection_available"])
        absent = self.client.post("/api/dashboards/inspect-source", json={
            "binding_key": proposal["binding_key"], "scope": {
                "source": {"kind": "index", "index": "contoso_web"}, "time_range": proposal["brief"]["time_range"],
            },
        })
        self.assertEqual(absent.json()["profile"]["status"], "unavailable")
        self.assertFalse(self.fake.named(INSPECT_TOOL))
        self.assertEqual(proposal["splunk_user"], SPLUNK_USER)
        self.assertEqual(proposal["splunk_web_url"], WEB)
        self.assertEqual(proposal["splunk_web_url_source"], "derived")
        self.assertEqual(proposal["brief"]["title"], "Findings from the Operator Runbook report")
        self.assertEqual(proposal["brief"]["provenance"], {"kind": "discovery_report", "label": REPORT_NAME})
        self.assertEqual([item["field"] for item in proposal["problems"]], ["source.index"])
        self.assertFalse(self.fake.named(CREATE_TOOL), "Drafting a plan may only check Constellation status.")

        brief = dict(proposal["brief"], source={"kind": "index", "index": "contoso_web"})
        changed = self.client.post("/api/dashboards/create", json={"proposal_id": proposal["proposal_id"], "binding_key": "0" * 32, "brief": brief})
        self.assertEqual(changed.status_code, 409)
        self.assertIn("changed after this plan was made", changed.json()["detail"])

        invalid = self.client.post("/api/dashboards/create", json={"proposal_id": proposal["proposal_id"], "binding_key": proposal["binding_key"], "brief": proposal["brief"]})
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual([item["field"] for item in invalid.json()["problems"]], ["source.index"])
        self.assertFalse(self.fake.named(CREATE_TOOL))

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

    def test_inspection_guides_panel_suggestions_for_the_exact_reviewed_scope(self):
        self.turn_on()
        self.catalog = INSPECTION_CATALOG
        proposal = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME}).json()["proposal"]
        self.assertTrue(proposal["source_inspection_available"])
        key = proposal["binding_key"]
        search = "search index=contoso_web  | stats avg(duration) AS latency_ms"
        scope = {
            "source": {"kind": "spl", "query": search},
            "time_range": {"earliest": "-1h", "latest": "now"},
        }
        request = {"binding_key": key, "scope": scope}
        not_reviewed = self.client.post("/api/dashboards/inspect-source", json=request)
        self.assertEqual(not_reviewed.status_code, 400)
        self.assertFalse(self.fake.named(INSPECT_TOOL))
        self.incognito.set_preference("local", True)
        blocked = self.client.post("/api/dashboards/inspect-source", json=dict(request, reviewed_search=True))
        self.assertEqual(blocked.status_code, 409)
        self.assertFalse(self.fake.named(INSPECT_TOOL))
        self.incognito.set_preference("local", False)

        response = self.client.post("/api/dashboards/inspect-source", json=dict(request, reviewed_search=True))
        self.assertEqual(response.status_code, 200, response.text)
        profile = response.json()["profile"]
        self.assertEqual(profile["sample"]["completion"], "partial")
        self.assertEqual(profile["sample"]["grain"], "existing_search_output")
        self.assertEqual(profile["fields"][0]["name"], "latency_ms")
        self.assertNotIn("discard", response.text)
        self.assertNotIn(search, json.dumps(profile))
        self.assertEqual(response.json()["scope"], scope)
        self.assertEqual(self.fake.named(INSPECT_TOOL), [{
            "schema_version": "1", "expected_user": SPLUNK_USER,
            "scope_json": json.dumps(scope, separators=(",", ":")),
        }])

        brief = dict(proposal["brief"], **scope)
        stale = dict(brief, time_range={"earliest": "-7d", "latest": "now"})
        pages = [{"name": "Latency", "panels": ["Latency from the selected search"]}]
        with mock.patch.object(web_app, "draft_dashboard_plan", new_callable=mock.AsyncMock) as draft:
            draft.return_value = (dict(brief, pages=pages, source={"kind": "index", "index": "other"}), "ai")
            wrong_scope = self.client.post("/api/dashboards/suggest-panels", json={"binding_key": key, "brief": stale})
            self.assertEqual(wrong_scope.status_code, 409)
            draft.assert_not_awaited()
            suggestion = self.client.post("/api/dashboards/suggest-panels", json={"binding_key": key, "brief": brief})
            self.assertEqual(suggestion.json(), {"pages": pages})
            context = dict(draft.await_args.args[1])
            self.assertEqual(json.loads(context["Advisory Splunk sample metadata"]), profile)
            self.assertNotIn(search, json.dumps(context))
        self.assertFalse(self.fake.named(CREATE_TOOL))

        submission = {"proposal_id": proposal["proposal_id"], "binding_key": key, "inspected_scope": scope}
        mismatch = self.client.post("/api/dashboards/create", json={**submission, "brief": stale})
        self.assertEqual(mismatch.status_code, 409, mismatch.text)
        self.assertFalse(self.fake.named(CREATE_TOOL))
        updated_plan = {**brief, "pages": pages}
        started = self.client.post("/api/dashboards/create", json={**submission, "brief": updated_plan})
        self.assertEqual(started.status_code, 200, started.text)
        self.wait_for_status(started.json()["operation"]["request_id"], "created")
        sent = json.loads(self.fake.named(CREATE_TOOL)[0]["brief_json"])
        self.assertEqual({key: sent[key] for key in scope}, scope)
        self.assertEqual(sent["pages"], pages)

    def test_dashboard_planner_keeps_an_explicit_selected_search(self):
        self.turn_on()
        self.catalog = DASHBOARD_CATALOG
        search = '| makeresults count=4  | eval label="a  b" | stats count BY label'
        block = f"```spl\n{search}\n```"
        scope_key = web_app._build_discovery_scope_metadata()["scope_key"]
        report = web_app._discovery_scope_output_dir(scope_key) / REPORT_NAME
        report.write_text(f"# Synthetic report\n\n{block}\n", encoding="utf-8")
        model_plan = web_app.fallback_brief_draft("Create a dashboard of tests", "contoso_web")
        with mock.patch.object(web_app, "draft_dashboard_plan", return_value=(model_plan, "ai")):
            chat = self.client.post("/chat", json={"message": "Create a dashboard from this search\n\n" + block})
            report_plan = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME})
        self.assertEqual(chat.status_code, 200, chat.text)
        self.assertEqual(report_plan.status_code, 200, report_plan.text)
        for proposal in (chat.json()["dashboard_proposal"], report_plan.json()["proposal"]):
            self.assertEqual(proposal["brief"]["source"], {"kind": "spl", "query": search})
        self.assertEqual(model_plan["source"]["kind"], "index")
        self.assertIsNone(web_app._dashboard_selected_source([search, "index=other"]))

    def test_inspection_discards_result_if_connection_changes_in_flight(self):
        self.turn_on()
        self.catalog = INSPECTION_CATALOG
        proposal = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME}).json()["proposal"]
        self.fake.before_inspection_reply = lambda: self.config_manager.update_mcp(
            url=MCP_URL, token="replacement-fixture-token", verify_ssl=False,
        )
        response = self.client.post("/api/dashboards/inspect-source", json={
            "binding_key": proposal["binding_key"],
            "scope": {"source": {"kind": "index", "index": "contoso_web"}, "time_range": proposal["brief"]["time_range"]},
        })
        self.assertEqual(response.status_code, 409)
        self.assertNotIn("latency_ms", response.text)
        self.assertEqual(len(self.fake.named(INSPECT_TOOL)), 1)

    def test_dashboard_repair_keeps_scope_and_requires_review_after_a_failed_request(self):
        self.turn_on()
        self.catalog = DASHBOARD_CATALOG
        proposal = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME}).json()["proposal"]
        brief = {**proposal["brief"], "source": {"kind": "index", "index": "contoso_web"}}
        request = {"proposal_id": proposal["proposal_id"], "binding_key": proposal["binding_key"], "brief": brief}
        self.fake.create_problem = {"status": "needs_input", "code": "panel_coverage", "question": "Review your panel list."}
        started = self.client.post("/api/dashboards/create", json=request).json()["operation"]
        failed = self.wait_for_status(started["request_id"], "needs_input")
        self.assertEqual(failed["receipt"]["code"], "panel_coverage")
        self.assertEqual(failed["recovery"]["heading"], "Revise the dashboard panels")
        self.assertEqual(failed["brief"]["source"], brief["source"])
        suggested = [{"name": "Overview", "panels": ["Event count"]}]
        body = {"binding_key": proposal["binding_key"], "brief": brief, "repair_request_id": started["request_id"]}
        with mock.patch.object(web_app, "draft_dashboard_plan", new_callable=mock.AsyncMock) as draft:
            draft.return_value = (dict(brief, pages=suggested), "ai")
            missing = self.client.post("/api/dashboards/suggest-panels", json={**body, "repair_request_id": "missing"})
            self.assertEqual(missing.status_code, 409)
            draft.assert_not_awaited()
            fix = self.client.post("/api/dashboards/suggest-panels", json=body)
            self.assertEqual(fix.json(), {"pages": suggested})
            prompt, context, _ = draft.await_args.args
            self.assertIn("introduce no new fields", prompt)
            self.assertIn("could not verify every requested panel", dict(context)["Constellation recovery guidance"])
            self.assertNotIn("Advisory Splunk sample metadata", dict(context))
        self.assertEqual(len(self.fake.named(CREATE_TOOL)), 1)
        self.fake.create_problem = None
        retried = self.client.post("/api/dashboards/create", json=dict(request, brief=dict(brief, pages=suggested))).json()["operation"]
        self.assertNotEqual(retried["request_id"], started["request_id"])
        self.wait_for_status(retried["request_id"], "created")
        self.assertEqual(len(self.fake.named(CREATE_TOOL)), 2)

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
        self.assertIn("sends the plan to Splunk only when you click Create", text)
        self.assertEqual(proposal["brief"]["title"], "Web errors")
        self.assertEqual(proposal["brief"]["provenance"]["kind"], "conversation")
        self.assertEqual(proposal["splunk_user"], SPLUNK_USER)
        self.assertFalse(self.fake.named(CREATE_TOOL))

    def test_report_label(self):
        self.assertEqual(web_app._dashboard_report_label(REPORT_NAME), "Operator Runbook")
        self.assertEqual(web_app._dashboard_report_label("v2_ai_summary_20260522_010203.md"), "AI Summary")
        self.assertEqual(web_app._dashboard_report_label("notes.txt"), "Notes")

    def test_chat_and_report_plans_retrieve_from_their_splunk_workspace(self):
        self.turn_on()
        self.catalog = DASHBOARD_CATALOG
        expected_dir = web_app._discovery_scope_output_dir(
            web_app._mcp_workspace(self.config_manager.get())["scope_key"], create=False
        )

        async def draft(text, sections, config, **options):
            self.assertIn(("Knowledge Base for this Splunk workspace", "Lab fixture passage"), sections)
            return web_app.fallback_brief_draft(text, "contoso_web", options.get("provenance")), "ai"

        with mock.patch.object(web_app, "sync_chat_settings_for_request", return_value=dict(web_app.chat_session_settings, enable_rag_context=True)), \
                mock.patch.object(web_app, "draft_dashboard_plan", side_effect=draft), \
                mock.patch.object(web_app, "get_optional_rag_context", return_value=(
                    "Lab fixture passage", [{"chunks": [{"source": "Lab evidence"}]}],
                )) as retrieve:
            chat = self.client.post("/chat", json={"message": "Create a dashboard of failed logins"})
            report = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME})
        self.assertEqual(chat.status_code, 200, chat.text)
        self.assertEqual(report.status_code, 200, report.text)
        self.assertEqual([call.kwargs["discovery_dir"] for call in retrieve.call_args_list], [expected_dir, expected_dir])
        self.assertIn("Track failed logins", retrieve.call_args_list[1].args[0])
        for proposal in (chat.json()["dashboard_proposal"], report.json()["proposal"]):
            self.assertIn("The plan used Knowledge Base evidence from this Splunk workspace.", proposal["notes"])

    def test_dashboard_plan_keeps_visible_chat_history_before_server_history_exists(self):
        history = [
            {"role": "system", "content": "Internal guidance"},
            {"type": "user", "content": "Show the deployment signal count."},
            {"type": "error", "content": "An internal error"},
            {"role": "assistant", "content": "There are six synthetic events."},
        ]
        self.assertEqual(
            web_app._dashboard_history_excerpt(history),
            "User: Show the deployment signal count.\nAssistant: There are six synthetic events.",
        )

    def test_dashboard_plan_retries_an_incomplete_model_reply_with_the_same_context(self):
        model = mock.Mock()
        model.generate_response = mock.AsyncMock(side_effect=[
            '{"title":"Dashboard Creation","purpose":"Track deployment events","pages":[{"name":"Overview","panels":[]}]}',
            '{"title":"Deployment signals","purpose":"Count deployment events",'
            '"pages":[{"name":"Overview","panels":[{"name":"Overall event count","description":"Single value"}]}]}',
        ])
        with mock.patch.object(web_app, "_is_llm_available_for_m26_14_advisory", return_value=(True, "")), \
                mock.patch.object(web_app, "get_or_create_llm_client", return_value=model):
            draft, author = asyncio.run(web_app.draft_dashboard_plan(
                "Turn this into a dashboard",
                [("Conversation so far", "User: Count deployment events")],
                self.config_manager.get(),
            ))
        self.assertEqual((draft["title"], author), ("Deployment signals", "ai"))
        self.assertEqual(draft["pages"][0]["panels"], ["Overall event count. Single value"])
        first, second = [call.kwargs["messages"] for call in model.generate_response.call_args_list]
        self.assertEqual(second[:len(first)], first)
        self.assertIn("Count deployment events", second[1]["content"])

    def test_chat_and_report_retry_a_valid_but_incomplete_requested_outline(self):
        self.turn_on()
        self.catalog = DASHBOARD_CATALOG
        scope_key = web_app._build_discovery_scope_metadata()["scope_key"]
        report = web_app._discovery_scope_output_dir(scope_key) / REPORT_NAME
        report.write_text("# Deployment report\n\nUse one page with exactly 4 visualizations: volume, failures, trend, and region.\n", encoding="utf-8")
        panels = ["Total deployments", "Failed deployments", "Failures over time", "Deployments by region"]

        def answer(outline):
            return json.dumps({
                "title": "Deployment signals", "purpose": "Count deployments and failed deployments",
                "source": {"kind": "index", "index": "contoso_web"},
                "pages": [{"name": "Overview" if i == 0 else "Details", "panels": page} for i, page in enumerate(outline)],
            })

        model = mock.Mock()
        model.generate_response = mock.AsyncMock(side_effect=[answer([panels[:2]]), answer([panels[:2], panels[2:]])] * 2)
        with mock.patch.object(web_app, "_is_llm_available_for_m26_14_advisory", return_value=(True, "")), \
                mock.patch.object(web_app, "get_or_create_llm_client", return_value=model):
            chat = self.client.post("/chat", json={"message": "Create a four-panel dashboard for deployments on one Overview page"})
            report_plan = self.client.post("/api/dashboards/propose", json={"report_name": REPORT_NAME})

        self.assertEqual(chat.status_code, 200, chat.text)
        self.assertEqual(report_plan.status_code, 200, report_plan.text)
        for proposal in (chat.json()["dashboard_proposal"], report_plan.json()["proposal"]):
            self.assertEqual(proposal["brief"]["pages"], [{"name": "Overview", "panels": panels}])
        self.assertEqual(model.generate_response.await_count, 4)
        for call in model.generate_response.call_args_list[1::2]:
            self.assertIn("exactly 4 panels", call.kwargs["messages"][-1]["content"])
        self.assertFalse(self.fake.named(CREATE_TOOL))

    def test_explicit_panel_count_does_not_get_padded_with_generic_panels(self):
        with mock.patch.object(web_app, "_is_llm_available_for_m26_14_advisory", return_value=(False, "")):
            draft, author = asyncio.run(web_app.draft_dashboard_plan(
                "Create a dashboard with four charts", [], self.config_manager.get(), panel_count=4,
            ))
        self.assertEqual((draft["pages"], author), ([], "starter"))
        self.assertIsNone(web_app.requested_dashboard_panel_count("Use two to four panels. `exactly six panels`"))
        self.assertIsNone(web_app.requested_dashboard_panel_count("Build two pages with two panels per page."))


class DashboardSignInTests(DashboardRouteCase):
    def sign_in_admin(self):
        self.assertTrue(self.config_manager.update_security(auth_enabled=True, session_timeout_minutes=60, password_min_length=14))
        password = "".join(["Dash", "Admin", "Pass", "123!"])
        self.assertEqual(self.client.post("/api/auth/login", json={"username": "admin", "password": "password"}).status_code, 200)
        reset = self.client.post("/api/auth/reset-password", json={"current_password": "password", "new_password": password, "confirm_password": password})
        self.assertEqual(reset.status_code, 200)

    def add_analyst(self, username, connection_name=None, role="analyst"):
        password = "".join(["Dash", "Analyst", "Pass", "123!"])
        created = self.client.post("/api/security/users", json={
            "username": username, "password": password, "role": role, "require_password_reset": False, "mcp_config_name": connection_name,
        })
        self.assertEqual(created.status_code, 200, created.text)
        return password

    def add_scoped_report(self, connection_name, timestamp):
        scope_key = web_app._build_discovery_scope_metadata(
            auth_user={"role": "analyst", "mcp_config_name": connection_name}
        )["scope_key"]
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

        viewer_password = self.add_analyst("viewer1", "contoso-analyst", role="viewer")

        admin_status = self.client.get("/api/dashboards/status").json()
        self.assertFalse(admin_status["can_create"])
        self.assertIn("none is assigned to you", admin_status["blocked_reason"])
        self.assertIn("Assign one to your user in Settings > Users.", admin_status["blocked_reason"])

        viewer_status = self.signed_in("viewer1", viewer_password).get("/api/dashboards/status").json()
        self.assertFalse(viewer_status["can_create"])
        self.assertIn("Your role cannot create dashboards", viewer_status["blocked_reason"])

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
        self.assertIn("Ask an administrator to assign one", status["blocked_reason"])
        self.assertEqual(status["support"]["reason"], "no_connection")
        self.assertEqual(other.get("/api/dashboards/operations").json()["operations"], [])


if __name__ == "__main__":
    unittest.main()
