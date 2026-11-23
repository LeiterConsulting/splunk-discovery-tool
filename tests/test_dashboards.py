import asyncio
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from capabilities.connection_support import evaluate_connection_support  # noqa: E402
from capabilities.tools.dashboard_service import (  # noqa: E402
    DashboardBinding,
    DashboardBindingChanged,
    DashboardConflict,
    DashboardService,
    build_plan_messages,
    coerce_brief_draft,
    detect_dashboard_create_intent,
    fallback_brief_draft,
    plan_problems,
)
from capabilities.tools.dashboard_store import DashboardOperationStore  # noqa: E402
from capabilities.tools.dashboards import (  # noqa: E402
    CREATE_TOOL,
    ERROR_MESSAGES,
    INSPECT_TOOL,
    STATUS_TOOL,
    USER_INFO_TOOL,
    BriefError,
    ReceiptError,
    brief_digest,
    build_tool_arguments,
    check_tool_schema,
    derive_web_base,
    error_message,
    new_request_id,
    normalize_brief,
    normalize_receipt,
    normalize_web_base,
    parse_splunk_username,
    parse_tool_response,
    request_id_is_fresh,
    serialize_brief,
    validate_dashboard_link,
)

WEB = "https://splunk.example.com:8000"
SPLUNK_USER = "analyst.contoso"
VALID_BRIEF = {
    "title": "Web errors",
    "purpose": "Track server errors on the contoso web tier for the operations team.",
    "source": {"kind": "index", "index": "contoso_web", "sourcetype": "access_combined"},
    "time_range": {"earliest": "-24h", "latest": "now"},
    "pages": [{"name": "Overview", "panels": ["Server errors over time", "Top error paths"]}],
    "findings": ["Errors doubled after the last release."],
    "provenance": {"kind": "conversation", "label": "Chat conversation"},
}


def brief(**changes):
    data = json.loads(json.dumps(VALID_BRIEF))
    data.update(changes)
    return data


def problem_fields(raw):
    try:
        normalize_brief(raw)
    except BriefError as exc:
        return [item["field"] for item in exc.problems]
    return []


def wrapped_reply(payload):
    """A Splunk MCP Server reply: the REST answer wrapped as {"results": [payload]} in a text item."""
    return {
        "http_status": 200,
        "body": {"jsonrpc": "2.0", "id": "1", "result": {"content": [{"type": "text", "text": json.dumps({"results": [payload]})}]}},
        "timed_out": False,
        "error": "",
    }


def domain_error_reply(code):
    return {
        "http_status": 200,
        "body": {"jsonrpc": "2.0", "id": "1", "result": {"isError": True, "content": [{"type": "text", "text": json.dumps({"code": code, "error": "x"})}]}},
        "timed_out": False,
        "error": "",
    }


TIMEOUT_REPLY = {"http_status": None, "body": None, "timed_out": True, "error": "timeout"}


def receipt(request_id, status, **fields):
    payload = {"schema_version": "1", "request_id": request_id, "status": status, "warnings": []}
    payload.update(fields)
    return payload


def running(args):
    return wrapped_reply(receipt(args["request_id"], "running", stage="authoring", poll_after_ms=500))


def created(args, view_host=WEB):
    return wrapped_reply(receipt(
        args["request_id"],
        "created",
        title="Web errors",
        message="Saved as a private dashboard.",
        dashboard_id="contoso_web_errors",
        draft_id="draft_contoso_1",
        view_url=f"{view_host}/en-US/app/constellation/contoso_web_errors",
        edit_url=f"{WEB}/en-US/app/constellation/workspace?draft=draft_contoso_1",
    ))


def not_found(args):
    return wrapped_reply(receipt(args["request_id"], "not_found"))


def probe_status(args):
    return wrapped_reply(receipt(args["request_id"], "not_found", pilot={"mode": "probe", "identity_verified": True}))


class DashboardContractTests(unittest.TestCase):
    def test_dashboard_design_guidance_matches_the_planning_context(self):
        messages = build_plan_messages("Build a dashboard for latency over time", [])
        self.assertIn("Dashboard design guidance v1", messages[0]["content"])
        self.assertIn("audience's decision", messages[0]["content"])
        self.assertIn("Do not take percentiles of pre-aggregated averages", messages[0]["content"])
        self.assertNotIn("Carry deliberate filters into detail views", messages[0]["content"])

    def test_valid_plan_keeps_its_fields_and_serializes_compactly(self):
        normalized = normalize_brief(VALID_BRIEF)
        self.assertEqual(normalized, VALID_BRIEF)
        self.assertEqual(serialize_brief(normalized), json.dumps(VALID_BRIEF, ensure_ascii=False, separators=(",", ":")))
        reordered = dict(reversed(list(VALID_BRIEF.items())))
        self.assertEqual(brief_digest(normalize_brief(reordered)), brief_digest(normalized))

    def test_plan_problems_name_each_field(self):
        self.assertEqual(problem_fields(brief(title="", purpose="")), ["title", "purpose"])
        self.assertEqual(problem_fields(brief(source={"kind": "index", "index": ""})), ["source.index"])
        self.assertEqual(problem_fields(brief(source={"kind": "index", "index": "contoso_web", "sourcetype": "bad sourcetype"})), ["source.sourcetype"])
        self.assertEqual(problem_fields(brief(source={"kind": "saved_report", "name": "x"})), ["source.kind"])
        self.assertEqual(problem_fields(brief(time_range={"earliest": "-30d", "latest": "now"})), ["time_range"])
        self.assertEqual(problem_fields(brief(extra="x")), [""])
        self.assertEqual(problem_fields(brief(provenance={"kind": "email", "label": "x"})), ["provenance"])
        self.assertEqual(problem_fields(brief(findings=["a", "b", "c", "d", "e"])), ["findings"])
        self.assertEqual(problem_fields(brief(title="t" * 121)), ["title"])

    def test_page_and_panel_limits(self):
        three_pages = [{"name": f"Page {n}", "panels": ["Count"]} for n in range(3)]
        self.assertIn("pages", problem_fields(brief(pages=three_pages)))
        self.assertEqual(problem_fields(brief(pages=[{"name": "A", "panels": ["1", "2", "3", "4", "5"]}])), ["pages.0.panels"])
        seven = [{"name": "A", "panels": ["1", "2", "3", "4"]}, {"name": "B", "panels": ["5", "6", "7"]}]
        self.assertEqual(problem_fields(brief(pages=seven)), ["pages"])
        self.assertEqual(problem_fields(brief(pages=[{"name": "A", "panels": ["1"]}, {"name": "a", "panels": ["2"]}])), ["pages.1.name"])
        self.assertEqual(problem_fields(brief(pages=[])), ["pages"])

    def test_search_source_keeps_spacing_and_drops_control_characters(self):
        normalized = normalize_brief(brief(source={"kind": "spl", "query": "index=contoso_web  status>=500\n| stats count by uri"}))
        self.assertEqual(normalized["source"], {"kind": "spl", "query": "index=contoso_web  status>=500 | stats count by uri"})

    def test_oversized_plan_is_refused(self):
        big = brief(
            requirements="r" * 1200,
            purpose="p" * 500,
            # Each character is three bytes in UTF-8, so every field fits its limit but the plan passes 16 KB.
            source={"kind": "spl", "query": "\u20ac" * 8000},
            findings=["f" * 300] * 4,
            pages=[{"name": "A" * 60, "panels": ["x" * 240] * 3}, {"name": "B" * 60, "panels": ["y" * 240] * 3}],
        )
        self.assertEqual(problem_fields(big), [""])

    def test_request_ids_follow_the_contract_and_expire_after_a_day(self):
        now = datetime(2026, 5, 22, 12, 0, tzinfo=timezone.utc)
        request_id = new_request_id(now)
        self.assertRegex(request_id, r"^20260522T120000Z-[a-f0-9]{32}$")
        self.assertTrue(request_id_is_fresh(request_id, now + timedelta(hours=23)))
        self.assertFalse(request_id_is_fresh(request_id, now + timedelta(hours=24)))
        self.assertFalse(request_id_is_fresh(request_id, now - timedelta(minutes=6)))
        self.assertFalse(request_id_is_fresh("not-an-id", now))

    def test_tool_arguments_are_exact(self):
        create = build_tool_arguments(CREATE_TOOL, "rid", SPLUNK_USER, "{}")
        self.assertEqual(create, {"schema_version": "1", "request_id": "rid", "expected_user": SPLUNK_USER, "brief_json": "{}"})
        status = build_tool_arguments(STATUS_TOOL, "rid", SPLUNK_USER)
        self.assertEqual(status, {"schema_version": "1", "request_id": "rid", "expected_user": SPLUNK_USER})
        with self.assertRaises(ValueError):
            build_tool_arguments(CREATE_TOOL, "rid", SPLUNK_USER)

    def test_tool_schema_check(self):
        def schema(names, required=None, versions=("1",)):
            properties = {name: {"type": "string"} for name in names}
            if "schema_version" in properties:
                properties["schema_version"]["enum"] = list(versions)
            return {"type": "object", "properties": properties, "required": list(required if required is not None else names)}

        create_args = ["schema_version", "request_id", "expected_user", "brief_json"]
        self.assertIsNone(check_tool_schema(CREATE_TOOL, schema(create_args)))
        self.assertIn("missing the arguments brief_json", check_tool_schema(CREATE_TOOL, schema(create_args[:3])))
        self.assertIn("does not send: owner", check_tool_schema(STATUS_TOOL, schema(create_args[:3] + ["owner"])))
        self.assertIn("contract version 1", check_tool_schema(STATUS_TOOL, schema(create_args[:3], versions=("2",))))
        self.assertEqual(check_tool_schema(CREATE_TOOL, None), "does not describe its arguments")
        self.assertIsNone(check_tool_schema("splunk_run_query", None))

    def test_tool_replies_are_classified_before_any_receipt_is_read(self):
        self.assertEqual(parse_tool_response(None, None, "timeout")["kind"], "transport_error")
        self.assertTrue(parse_tool_response(None, None)["ambiguous"])
        wrapped = wrapped_reply(receipt("rid", "running"))
        self.assertEqual(parse_tool_response(200, wrapped["body"])["payload"]["status"], "running")
        structured = {"result": {"structuredContent": receipt("rid", "created")}}
        self.assertEqual(parse_tool_response(200, structured)["payload"]["status"], "created")
        busy = parse_tool_response(200, domain_error_reply("pilot_busy")["body"])
        self.assertEqual((busy["kind"], busy["code"], busy["ambiguous"]), ("domain_error", "pilot_busy", False))
        self.assertTrue(parse_tool_response(200, domain_error_reply("write_unconfirmed")["body"])["ambiguous"])
        jsonrpc = {"error": {"code": -32000, "message": "failed", "data": {"code": "identity_unavailable", "error": "no"}}}
        self.assertEqual(parse_tool_response(200, jsonrpc)["code"], "identity_unavailable")
        unknown = {"result": {"isError": True, "content": [{"type": "text", "text": json.dumps({"code": "Bad Code!", "error": "x"})}]}}
        self.assertEqual(parse_tool_response(200, unknown)["kind"], "transport_error")
        self.assertEqual(parse_tool_response(200, {"result": {"content": [{"type": "text", "text": "hello"}]}})["kind"], "transport_error")

    def test_splunk_username_comes_from_the_user_info_reply(self):
        self.assertEqual(parse_splunk_username(wrapped_reply({"username": SPLUNK_USER})["body"]), SPLUNK_USER)
        listed = {"result": {"content": [{"type": "text", "text": json.dumps([{"name": SPLUNK_USER}])}]}}
        self.assertEqual(parse_splunk_username(listed), SPLUNK_USER)
        self.assertIsNone(parse_splunk_username({"result": {"isError": True, "content": []}}))
        self.assertIsNone(parse_splunk_username({"error": {"message": "x"}}))

    def test_web_addresses(self):
        self.assertEqual(normalize_web_base("https://Splunk.Example.com:8000/"), WEB)
        self.assertEqual(normalize_web_base("https://splunk.example.com/splunk"), "https://splunk.example.com/splunk")
        for bad in ("http://splunk.example.com:8000", "https://user:pw@splunk.example.com", "https://splunk.example.com/?a=1", "https://splunk.example.com/#x", "", "splunk.example.com"):
            self.assertIsNone(normalize_web_base(bad), bad)
        self.assertEqual(derive_web_base("https://splunk.example.com:8089/services/mcp"), WEB)
        self.assertEqual(derive_web_base("https://splunk.example.com/services/mcp"), WEB)
        self.assertEqual(derive_web_base("https://splunk.example.com:9443/services/mcp"), "https://splunk.example.com:9443")
        self.assertEqual(derive_web_base("http://[2001:db8::1]:8089/services/mcp"), "https://[2001:db8::1]:8000")
        self.assertIsNone(derive_web_base(""))

    def test_dashboard_links_must_match_the_exact_route(self):
        view = f"{WEB}/en-US/app/constellation/contoso_web_errors"
        edit = f"{WEB}/en-US/app/constellation/workspace?draft=draft_1"
        self.assertTrue(validate_dashboard_link(view, WEB, "view", "contoso_web_errors"))
        self.assertTrue(validate_dashboard_link(edit, WEB, "edit", "draft_1"))
        self.assertFalse(validate_dashboard_link(view, WEB, "view", "other_dashboard"))
        self.assertFalse(validate_dashboard_link(view.replace("splunk.example.com", "evil.example.com"), WEB, "view", "contoso_web_errors"))
        self.assertFalse(validate_dashboard_link(view.replace("https", "http"), WEB, "view", "contoso_web_errors"))
        self.assertFalse(validate_dashboard_link(f"{view}?x=1", WEB, "view", "contoso_web_errors"))
        self.assertFalse(validate_dashboard_link(f"{view}#top", WEB, "view", "contoso_web_errors"))
        self.assertFalse(validate_dashboard_link(f"{edit}&next=https://evil.example.com", WEB, "edit", "draft_1"))
        self.assertFalse(validate_dashboard_link(f"{WEB}/app/constellation/contoso_web_errors", WEB, "view", "contoso_web_errors"))
        localized = "https://splunk.example.com/splunk/en-GB"
        self.assertTrue(validate_dashboard_link(f"{localized}/app/constellation/contoso_web_errors", localized, "view", "contoso_web_errors"))

    def test_receipts_are_checked_against_the_request(self):
        with self.assertRaises(ReceiptError) as mismatch:
            normalize_receipt(receipt("other", "running"), "rid", WEB)
        self.assertEqual(mismatch.exception.code, "request_mismatch")
        with self.assertRaises(ReceiptError):
            normalize_receipt(dict(receipt("rid", "running"), schema_version="2"), "rid", WEB)
        with self.assertRaises(ReceiptError):
            normalize_receipt(receipt("rid", "exploded"), "rid", WEB)
        with self.assertRaises(ReceiptError):
            normalize_receipt(receipt("rid", "needs_input"), "rid", WEB)
        self.assertEqual(normalize_receipt(receipt("rid", "running", poll_after_ms=10), "rid", WEB)["poll_after_ms"], 500)
        self.assertEqual(normalize_receipt(receipt("rid", "running", poll_after_ms=99999), "rid", WEB)["poll_after_ms"], 30000)
        self.assertEqual(normalize_receipt(receipt("rid", "failed", code="<script>"), "rid", WEB)["code"], "unknown")
        many = [{"code": f"warning_{n}", "message": "m"} for n in range(12)]
        self.assertEqual(len(normalize_receipt(receipt("rid", "draft_only", warnings=many), "rid", WEB)["warnings"]), 8)

    def test_created_receipt_keeps_only_verified_links(self):
        def payload_of(reply):
            return parse_tool_response(reply["http_status"], reply["body"])["payload"]

        good = normalize_receipt(payload_of(created({"request_id": "rid"})), "rid", WEB)
        self.assertEqual(good["view_url"], f"{WEB}/en-US/app/constellation/contoso_web_errors")
        self.assertEqual(good["edit_url"], f"{WEB}/en-US/app/constellation/workspace?draft=draft_contoso_1")
        self.assertEqual(good["warnings"], [])
        hidden = normalize_receipt(payload_of(created({"request_id": "rid"}, view_host="https://evil.example.com:8000")), "rid", WEB)
        self.assertNotIn("view_url", hidden)
        self.assertIn("edit_url", hidden)
        self.assertEqual([warning["code"] for warning in hidden["warnings"]], ["link_rejected"])

    def test_error_messages(self):
        self.assertEqual(error_message("pilot_busy"), ERROR_MESSAGES["pilot_busy"])
        self.assertEqual(error_message("brand_new_code"), "Dashboard creation did not finish (code brand_new_code).")
        self.assertEqual(error_message("<b>bad</b>"), "Dashboard creation did not finish.")


class ConnectionSupportTests(unittest.TestCase):
    REQUIRED = [CREATE_TOOL, STATUS_TOOL]

    def test_states(self):
        self.assertEqual(evaluate_connection_support([], None)["state"], "not_required")
        self.assertEqual(evaluate_connection_support(self.REQUIRED, None)["reason"], "no_connection")
        self.assertEqual(evaluate_connection_support(self.REQUIRED, {"ok": False})["reason"], "catalog_unavailable")
        potential = evaluate_connection_support(self.REQUIRED, {"ok": True, "tools": ["splunk_run_query", CREATE_TOOL]})
        self.assertEqual((potential["state"], potential["missing_tools"]), ("potential", [STATUS_TOOL]))
        catalog = {"ok": True, "tools": self.REQUIRED, "schemas": {CREATE_TOOL: {"properties": {"x": {}}}, STATUS_TOOL: None}}
        incompatible = evaluate_connection_support(self.REQUIRED, catalog, check_tool_schema)
        self.assertEqual(incompatible["state"], "incompatible")
        self.assertEqual(len(incompatible["problems"]), 2)
        self.assertEqual(evaluate_connection_support(self.REQUIRED, {"ok": True, "tools": self.REQUIRED})["state"], "available")


class DashboardIntentTests(unittest.TestCase):
    def test_requests_to_create_a_dashboard_now(self):
        for message in (
            "Create a dashboard of web errors",
            "Can you build me a Splunk dashboard for failed logins?",
            "ok, please make a dashboard showing firewall denies",
            "I want a dashboard of license usage",
            "Turn this into a dashboard",
            "Thanks. Let's build a new dashboard for the contoso web tier.",
        ):
            self.assertTrue(detect_dashboard_create_intent(message), message)

    def test_questions_ideas_and_pasted_text_do_not_count(self):
        for message in (
            "How do I create a dashboard?",
            "What dashboards should I build?",
            "Create dashboards for each index",
            "Show me the dashboard list",
            "The report says: create a dashboard of web errors",
            "Create a dashboard tutorial for new analysts",
            "",
            None,
        ):
            self.assertFalse(detect_dashboard_create_intent(message), message)


class DashboardPlanDraftTests(unittest.TestCase):
    def test_starter_plan_title_comes_from_the_request(self):
        self.assertEqual(fallback_brief_draft("Create a dashboard that tracks failed logins")["title"], "Failed logins")
        self.assertEqual(fallback_brief_draft("Please build a dashboard of web errors.")["title"], "Web errors")
        topic = fallback_brief_draft("Create a dashboard that tracks the main findings", topic="findings from the Operator Runbook report")
        self.assertEqual(topic["title"], "Findings from the Operator Runbook report")
        self.assertEqual(topic["purpose"], "Track findings from the Operator Runbook report for the team reviewing this Splunk environment.")

    def test_starter_plan_needs_only_an_index(self):
        draft = fallback_brief_draft("Create a dashboard of web errors", provenance={"kind": "conversation", "label": "Chat conversation"})
        self.assertEqual([item["field"] for item in plan_problems(draft)], ["source.index"])
        self.assertEqual(plan_problems(fallback_brief_draft("Create a dashboard of web errors", known_index="contoso_web")), [])

    def test_model_answer_is_trimmed_to_the_limits(self):
        raw = {
            "title": "t" * 300,
            "purpose": "Track errors for the operations team.",
            "source": {"kind": "spl", "query": "index=contoso_web | stats count"},
            "time_range": {"earliest": "-90d"},
            "pages": [{"name": "Same", "panels": ["a", "b", "c", "d", "e"]}, {"name": "same", "panels": ["f", "g", "h"]}, {"name": "Third", "panels": ["i"]}],
            "findings": ["one", "two", "three", "four", "five"],
        }
        draft = coerce_brief_draft(raw, {"kind": "discovery_report", "label": "report.md"})
        self.assertEqual(len(draft["title"]), 120)
        self.assertEqual(draft["time_range"], {"earliest": "-24h", "latest": "now"})
        self.assertEqual([len(page["panels"]) for page in draft["pages"]], [4, 2])
        self.assertNotEqual(draft["pages"][0]["name"].casefold(), draft["pages"][1]["name"].casefold())
        self.assertEqual(len(draft["findings"]), 4)
        self.assertEqual(draft["source"]["kind"], "spl")
        self.assertEqual(draft["provenance"], {"kind": "discovery_report", "label": "report.md"})
        self.assertEqual(plan_problems(draft), [])


class DashboardStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.now = datetime(2026, 5, 22, 12, 0, tzinfo=timezone.utc)
        self.store = DashboardOperationStore(Path(self.temp.name), clock=lambda: self.now)

    def test_plans_are_dropped_after_a_day_and_records_after_a_week(self):
        recent = new_request_id(self.now - timedelta(hours=25))
        old = new_request_id(self.now - timedelta(days=8))
        for request_id in (recent, old):
            self.store.add("local", {"request_id": request_id, "status": "created", "brief": VALID_BRIEF, "brief_json": "{}"})
        kept = self.store.get("local", recent)
        self.assertIsNotNone(kept)
        self.assertNotIn("brief", kept)
        self.assertNotIn("brief_json", kept)
        self.assertIsNone(self.store.get("local", old))

    def test_owners_see_only_their_own_requests(self):
        request_id = new_request_id(self.now)
        self.store.add("user_a", {"request_id": request_id, "status": "running"})
        self.assertEqual(len(self.store.list("user_a")), 1)
        self.assertEqual(self.store.list("user_b"), [])
        self.assertIsNone(self.store.get("user_b", request_id))

    def test_claim_reuses_the_plans_request(self):
        first = self.store.claim_for_proposal("local", "p1", lambda latest: {"request_id": new_request_id(self.now), "proposal_id": "p1", "status": "sending"})
        again = self.store.claim_for_proposal("local", "p1", lambda latest: None)
        self.assertFalse(first["reused"])
        self.assertTrue(again["reused"])
        self.assertEqual(first["request_id"], again["request_id"])

    @unittest.skipIf(os.name == "nt", "POSIX file modes")
    def test_record_file_is_private(self):
        self.store.add("local", {"request_id": new_request_id(self.now), "status": "running"})
        self.assertEqual(os.stat(self.store.path).st_mode & 0o077, 0)


class FakeSplunk:
    """Answers each tool call from a per-tool script of reply factories, recording every call."""

    def __init__(self, script=None):
        self.script = {name: list(replies) for name, replies in (script or {}).items()}
        self.calls = []

    async def __call__(self, mcp, tool_name, arguments, timeout_seconds):
        self.calls.append((tool_name, dict(arguments)))
        if tool_name == USER_INFO_TOOL:
            return wrapped_reply({"username": SPLUNK_USER})
        replies = self.script.get(tool_name) or []
        if not replies:
            raise AssertionError(f"Unexpected {tool_name} call")
        factory = replies[0] if len(replies) == 1 and getattr(replies[0], "repeat", False) else replies.pop(0)
        return factory(arguments)

    def named(self, tool_name):
        return [arguments for name, arguments in self.calls if name == tool_name]


def repeat(factory):
    factory.repeat = True
    return factory


class DashboardServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.temp.cleanup)
        self.store = DashboardOperationStore(Path(self.temp.name))
        self.logs = []
        self.now = 0.0
        self.current = True
        self.settings = {"max_wait_seconds": 600}

    def service(self, fake):
        async def sleep(seconds):
            self.now += seconds

        service = DashboardService(
            self.store,
            settings=lambda: self.settings,
            binding_is_current=lambda _binding: self.current,
            log=self.logs.append,
            call=fake,
            sleep=sleep,
            clock=lambda: self.now,
        )
        service.recover_delay_seconds = 0
        return service

    @staticmethod
    def binding(**changes):
        values = dict(
            connection_name="",
            connection_label="Active connection",
            mcp=SimpleNamespace(url="https://splunk.example.com:8089/services/mcp"),
            identity="identity-1",
            web_base=WEB,
            web_base_source="derived",
            splunk_user=SPLUNK_USER,
        )
        values.update(changes)
        return DashboardBinding(**values)

    @staticmethod
    async def settle(service):
        while service._tasks:
            await asyncio.gather(*list(service._tasks.values()))

    async def test_source_inspection_distinguishes_empty_partial_and_transport_timeout(self):
        scope = {key: VALID_BRIEF[key] for key in ("source", "time_range")}

        def source_reply(rows, completion, status):
            return lambda _args: wrapped_reply({
                "schema_version": "1", "status": status,
                "source": dict(scope["source"], language="spl"), "time_range": scope["time_range"],
                "sample": {"rows": rows, "row_limit": 200, "grain": "indexed_observations", "completion": completion},
                "fields": [],
            })

        fake = FakeSplunk({INSPECT_TOOL: [
            source_reply(0, "complete", "empty"),
            source_reply(0, "partial", "inconclusive"),
            source_reply(3, "partial", "observed"),
            lambda _args: TIMEOUT_REPLY,
        ]})
        service = self.service(fake)
        binding = self.binding()
        empty = await service.inspect_source("local", binding, scope)
        self.assertEqual(empty["status"], "empty")
        self.assertEqual(await service.inspect_source("local", binding, scope), empty)
        self.assertEqual(len(fake.named(INSPECT_TOOL)), 1)
        self.assertIsNone(service.cached_source_profile("other", binding, scope))
        self.assertIsNone(service.cached_source_profile("local", self.binding(identity="other"), scope))
        self.assertIsNone(service.cached_source_profile("local", self.binding(splunk_user="other"), scope))

        self.now += 61
        partial_empty = await service.inspect_source("local", binding, scope)
        self.assertEqual(partial_empty["status"], "inconclusive")
        self.assertEqual(partial_empty["sample"]["rows"], 0)
        partial = await service.inspect_source("local", binding, scope, refresh=True)
        self.assertEqual(partial["status"], "observed")
        self.assertEqual(partial["sample"]["completion"], "partial")
        timed_out = await service.inspect_source("local", binding, scope, refresh=True)
        self.assertEqual(timed_out, {"status": "inconclusive", "sample": None, "fields": []})
        self.assertIsNone(service.cached_source_profile("local", binding, scope))
        self.assertEqual(service.list_operations("local"), [])

    async def test_create_then_status_until_created(self):
        fake = FakeSplunk({CREATE_TOOL: [running], STATUS_TOOL: [running, created]})
        service = self.service(fake)
        started = service.start_create("local", "a" * 32, VALID_BRIEF, self.binding())
        self.assertEqual(started["status"], "sending")
        await self.settle(service)
        operation = service.get_operation("local", started["request_id"])
        self.assertEqual(operation["status"], "created")
        self.assertEqual(operation["receipt"]["view_url"], f"{WEB}/en-US/app/constellation/contoso_web_errors")
        creates = fake.named(CREATE_TOOL)
        self.assertEqual(len(creates), 1)
        self.assertEqual(creates[0], {
            "schema_version": "1",
            "request_id": started["request_id"],
            "expected_user": SPLUNK_USER,
            "brief_json": serialize_brief(normalize_brief(VALID_BRIEF)),
        })
        statuses = fake.named(STATUS_TOOL)
        self.assertEqual(statuses, [{"schema_version": "1", "request_id": started["request_id"], "expected_user": SPLUNK_USER}] * 2)
        joined = "\n".join(self.logs)
        for private in ("Web errors", "contoso", "https://", started["request_id"]):
            self.assertNotIn(private, joined)

    async def test_lost_reply_then_not_found_resends_the_identical_request_once(self):
        fake = FakeSplunk({CREATE_TOOL: [lambda _args: TIMEOUT_REPLY, running], STATUS_TOOL: [not_found, created]})
        service = self.service(fake)
        started = service.start_create("local", "b" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        creates = fake.named(CREATE_TOOL)
        self.assertEqual(len(creates), 2)
        self.assertEqual(creates[0], creates[1])
        operation = service.get_operation("local", started["request_id"])
        self.assertEqual(operation["status"], "created")
        self.assertTrue(operation["resent"])

    async def test_second_not_found_ends_the_request_without_another_resend(self):
        fake = FakeSplunk({CREATE_TOOL: [lambda _args: TIMEOUT_REPLY, lambda _args: TIMEOUT_REPLY], STATUS_TOOL: [not_found, not_found]})
        service = self.service(fake)
        started = service.start_create("local", "c" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        self.assertEqual(len(fake.named(CREATE_TOOL)), 2)
        operation = service.get_operation("local", started["request_id"])
        self.assertEqual(operation["status"], "not_found")
        self.assertTrue(operation["can_retry"])

    async def test_probe_status_preserves_an_uncertain_create_until_authoring_recovers(self):
        fake = FakeSplunk({CREATE_TOOL: [lambda _args: TIMEOUT_REPLY], STATUS_TOOL: [probe_status, created]})
        service = self.service(fake)
        started = service.start_create("local", "b" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        uncertain = service.get_operation("local", started["request_id"])
        self.assertEqual(uncertain["status"], "unconfirmed")
        self.assertIn("probe mode", uncertain["check_note"])
        self.assertTrue(uncertain["can_check"])
        self.assertFalse(uncertain["can_retry"])
        self.assertFalse(uncertain["resent"])
        recovered = await service.check_status("local", started["request_id"], self.binding())
        self.assertEqual(recovered["status"], "created")
        self.assertEqual(recovered["check_note"], "")
        self.assertEqual(len(fake.named(CREATE_TOOL)), 1)
        self.assertEqual({args["request_id"] for args in fake.named(STATUS_TOOL)}, {started["request_id"]})

    async def test_check_status_never_resends_an_unconfirmed_create(self):
        fake = FakeSplunk({
            CREATE_TOOL: [lambda _args: TIMEOUT_REPLY],
            STATUS_TOOL: [lambda _args: TIMEOUT_REPLY, not_found],
        })
        service = self.service(fake)
        started = service.start_create("local", "c" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        checked = await service.check_status("local", started["request_id"], self.binding())
        self.assertEqual(checked["status"], "not_found")
        self.assertTrue(checked["can_retry"])
        self.assertFalse(checked["resent"])
        self.assertEqual(len(fake.named(CREATE_TOOL)), 1)

    async def test_missing_receipt_after_acceptance_does_not_authorize_retry(self):
        fake = FakeSplunk({CREATE_TOOL: [running], STATUS_TOOL: [not_found, created]})
        service = self.service(fake)
        started = service.start_create("local", "a" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        waiting = service.get_operation("local", started["request_id"])
        self.assertEqual(waiting["status"], "unconfirmed")
        self.assertIn("previously accepted", waiting["check_note"])
        self.assertTrue(waiting["can_check"])
        self.assertFalse(waiting["can_retry"])
        recovered = await service.check_status("local", started["request_id"], self.binding())
        self.assertEqual(recovered["status"], "created")
        self.assertEqual(len(fake.named(CREATE_TOOL)), 1)

    async def test_clear_refusal_fails_without_a_status_check(self):
        fake = FakeSplunk({CREATE_TOOL: [lambda _args: domain_error_reply("pilot_busy")]})
        service = self.service(fake)
        started = service.start_create("local", "d" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        operation = service.get_operation("local", started["request_id"])
        self.assertEqual(operation["status"], "failed")
        self.assertEqual(operation["error"], {"code": "pilot_busy", "message": ERROR_MESSAGES["pilot_busy"]})
        self.assertEqual(fake.named(STATUS_TOOL), [])

    async def test_unclear_refusal_checks_status_first(self):
        fake = FakeSplunk({CREATE_TOOL: [lambda _args: domain_error_reply("write_unconfirmed")], STATUS_TOOL: [created]})
        service = self.service(fake)
        started = service.start_create("local", "e" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        self.assertEqual(service.get_operation("local", started["request_id"])["status"], "created")

    async def test_same_plan_reuses_its_request_and_a_changed_plan_conflicts(self):
        fake = FakeSplunk({CREATE_TOOL: [running], STATUS_TOOL: [created]})
        service = self.service(fake)
        first = service.start_create("local", "f" * 32, VALID_BRIEF, self.binding())
        second = service.start_create("local", "f" * 32, VALID_BRIEF, self.binding())
        self.assertEqual(first["request_id"], second["request_id"])
        with self.assertRaises(DashboardConflict):
            service.start_create("local", "f" * 32, brief(title="Other title"), self.binding())
        await self.settle(service)
        self.assertEqual(len(fake.named(CREATE_TOOL)), 1)

    async def test_a_failed_request_can_be_tried_again_with_a_new_id(self):
        fake = FakeSplunk({CREATE_TOOL: [lambda _args: domain_error_reply("no_data"), running], STATUS_TOOL: [created]})
        service = self.service(fake)
        failed = service.start_create("local", "1" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        retried = service.start_create("local", "1" * 32, brief(time_range={"earliest": "-7d", "latest": "now"}), self.binding())
        await self.settle(service)
        self.assertNotEqual(failed["request_id"], retried["request_id"])
        self.assertEqual(service.get_operation("local", retried["request_id"])["status"], "created")

    async def test_status_problems_never_turn_a_created_dashboard_into_a_failure(self):
        fake = FakeSplunk({CREATE_TOOL: [created], STATUS_TOOL: [lambda _args: TIMEOUT_REPLY]})
        service = self.service(fake)
        started = service.start_create("local", "2" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        checked = await service.check_status("local", started["request_id"], self.binding())
        self.assertEqual(checked["status"], "created")
        self.assertIn("did not answer in time", checked["check_note"])
        self.assertEqual(checked["receipt"]["dashboard_id"], "contoso_web_errors")

    async def test_probe_status_preserves_a_created_dashboard_and_its_links(self):
        fake = FakeSplunk({CREATE_TOOL: [created], STATUS_TOOL: [probe_status]})
        service = self.service(fake)
        started = service.start_create("local", "2" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        original = service.get_operation("local", started["request_id"])
        checked = await service.check_status("local", started["request_id"], self.binding())
        self.assertEqual(checked["status"], "created")
        self.assertEqual(checked["receipt"], original["receipt"])
        self.assertIn("probe mode", checked["check_note"])
        self.assertEqual(len(fake.named(CREATE_TOOL)), 1)

    async def test_check_status_refuses_another_connection_or_user(self):
        fake = FakeSplunk({CREATE_TOOL: [created]})
        service = self.service(fake)
        started = service.start_create("local", "3" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        with self.assertRaises(DashboardBindingChanged):
            await service.check_status("local", started["request_id"], self.binding(splunk_user="someone.else"))
        with self.assertRaises(DashboardBindingChanged):
            await service.check_status("local", started["request_id"], self.binding(identity="identity-2"))
        self.assertIsNone(await service.check_status("user_other", started["request_id"], self.binding()))

    async def test_polling_stops_when_the_connection_changes(self):
        fake = FakeSplunk({CREATE_TOOL: [running]})
        service = self.service(fake)
        self.current = False
        started = service.start_create("local", "4" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        operation = service.get_operation("local", started["request_id"])
        self.assertEqual(operation["status"], "running")
        self.assertTrue(operation["wait_stopped"])
        self.assertIn("connection changed", operation["check_note"])
        self.assertEqual(fake.named(STATUS_TOOL), [])

    async def test_polling_stops_at_the_wait_limit_and_stays_checkable(self):
        self.settings = {"max_wait_seconds": 5}
        fake = FakeSplunk({CREATE_TOOL: [running], STATUS_TOOL: [repeat(running)]})
        service = self.service(fake)
        started = service.start_create("local", "5" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        operation = service.get_operation("local", started["request_id"])
        self.assertTrue(operation["wait_stopped"])
        self.assertTrue(operation["can_check"])
        self.assertLessEqual(self.now, 5)

    async def test_failed_receipt_carries_a_readable_reason(self):
        fake = FakeSplunk({CREATE_TOOL: [running], STATUS_TOOL: [lambda args: wrapped_reply(receipt(args["request_id"], "failed", code="no_data"))]})
        service = self.service(fake)
        started = service.start_create("local", "6" * 32, VALID_BRIEF, self.binding())
        await self.settle(service)
        operation = service.get_operation("local", started["request_id"])
        self.assertEqual(operation["status"], "failed")
        self.assertEqual(operation["code_message"], ERROR_MESSAGES["no_data"])

    async def test_splunk_user_is_cached_and_a_missing_user_blocks_creation(self):
        fake = FakeSplunk()
        service = self.service(fake)
        self.assertEqual(await service.verify_splunk_user(self.binding()), (SPLUNK_USER, ""))
        self.assertEqual(await service.verify_splunk_user(self.binding()), (SPLUNK_USER, ""))
        self.assertEqual(len(fake.named(USER_INFO_TOOL)), 1)

        async def no_user(_mcp, _tool, _args, _timeout):
            return {"http_status": 200, "body": {"result": {"isError": True, "content": []}}, "timed_out": False, "error": ""}

        failing = self.service(no_user)
        username, problem = await failing.verify_splunk_user(self.binding(identity="identity-9"))
        self.assertIsNone(username)
        self.assertIn("Could not confirm which Splunk user", problem)

    async def test_invalid_plan_is_refused_before_anything_is_saved_or_sent(self):
        fake = FakeSplunk()
        service = self.service(fake)
        with self.assertRaises(BriefError):
            service.start_create("local", "7" * 32, brief(source={"kind": "index", "index": ""}), self.binding())
        self.assertEqual(fake.calls, [])
        self.assertEqual(self.store.list("local"), [])


if __name__ == "__main__":
    unittest.main()
