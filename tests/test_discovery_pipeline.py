import asyncio
import json
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from discovery import engine as engine_module  # noqa: E402
from discovery.engine import DiscoveryEngine, MCPToolError  # noqa: E402
from discovery.local_analyzer import KIND_INDEX_DETAIL, KIND_STEP_STATUS, metadata_recent_time_utc  # noqa: E402
from discovery.v2_pipeline import DiscoveryV2Pipeline  # noqa: E402
from llm.factory import parse_json_from_llm_text  # noqa: E402
from spl.generator import SPLGenerator  # noqa: E402


LAB_STRINGS = ["wmata", "375k", "chatllm", "homebridge", "esp32", "netops"]

INDEXES = [
    {"title": "main", "totalEventCount": "5000", "currentDBSizeMB": "120", "datatype": "event"},
    {"title": "firewall", "totalEventCount": "20000", "currentDBSizeMB": "300", "datatype": "event"},
    {"title": "legacy_app", "totalEventCount": "800", "currentDBSizeMB": "10", "datatype": "event"},
    {"title": "empty_idx", "totalEventCount": "0", "currentDBSizeMB": "0", "datatype": "event"},
    {"title": "_internal", "totalEventCount": "100000", "currentDBSizeMB": "500", "datatype": "event"},
    {"title": "_audit", "totalEventCount": "3000", "currentDBSizeMB": "20", "datatype": "event"},
]

SOURCETYPES = [
    {"sourcetype": "WinEventLog:Security", "totalCount": "1500"},
    {"sourcetype": "pan:traffic", "totalCount": "2000"},
    {"sourcetype": "access_combined", "totalCount": "300"},
    {"sourcetype": "splunkd", "totalCount": "9000"},
]

HOST_PARTS = [
    [{"host": "web-01", "totalCount": "100"}],
    [{"host": "dc-01", "totalCount": "200"}, {"host": "fw-edge", "totalCount": "2000"}],
]

SOURCES = [
    {"source": "/var/log/httpd/access_log", "totalCount": "300"},
    {"source": "WinEventLog:Security", "totalCount": "1500"},
]

RECENT_ACTIVITY = [
    {"index": "main", "count": "400"},
    {"index": "firewall", "count": "2000"},
    {"index": "_internal", "count": "9000"},
    {"index": "_audit", "count": "100"},
]

TREND = [
    {"_time": f"2026-01-0{day}T00:00:00+00:00", "count": str(1000 + day * 10)}
    for day in range(1, 8)
]

TOOL_NAMES = [
    "splunk_get_info",
    "splunk_get_indexes",
    "splunk_get_index_info",
    "splunk_get_metadata",
    "splunk_get_user_info",
    "splunk_get_kv_store_collections",
    "splunk_get_knowledge_objects",
    "splunk_run_query",
]


def text_content(obj):
    return {"content": [{"type": "text", "text": json.dumps(obj)}]}


class FakeSplunkMCP:
    """In-memory JSON-RPC MCP server returning varied but realistic response shapes."""

    def __init__(self, license_bytes=2.5 * 1024 ** 3, hosts=None, failing_ko_types=("macros",)):
        self.license_bytes = license_bytes
        self.hosts = hosts
        self.failing_ko_types = set(failing_ko_types)
        self.calls = []
        self.tools_list_calls = 0
        self.rpc_ids = []

    async def post(self, payload, timeout_seconds):
        self.rpc_ids.append(payload.get("id"))
        assert payload.get("jsonrpc") == "2.0"
        method = payload.get("method")
        if method == "tools/list":
            self.tools_list_calls += 1
            result = {"tools": [{"name": name} for name in TOOL_NAMES]}
        elif method == "tools/call":
            name = payload["params"]["name"]
            args = payload["params"]["arguments"]
            self.calls.append((name, json.dumps(args, sort_keys=True)))
            result = self.tool_result(name, args)
        else:
            return 200, json.dumps({"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32601, "message": "Method not found"}})
        return 200, json.dumps({"jsonrpc": "2.0", "id": payload.get("id"), "result": result})

    def tool_result(self, name, args):
        if name == "splunk_get_info":
            return text_content({"version": "9.3.1", "build": "abc123", "licenseState": "OK", "server_roles": ["indexer", "search_head"]})
        if name == "splunk_get_indexes":
            return {"structuredContent": {"results": [dict(row) for row in INDEXES]}, "content": []}
        if name == "splunk_get_metadata":
            metadata_type = args.get("type")
            if metadata_type == "sourcetypes":
                return text_content({"results": [dict(row) for row in SOURCETYPES]})
            if metadata_type == "hosts":
                if self.hosts is not None:
                    return text_content({"results": [dict(row) for row in self.hosts]})
                return {"content": [{"type": "text", "text": json.dumps(part)} for part in HOST_PARTS]}
            if metadata_type == "sources":
                return text_content([dict(row) for row in SOURCES])
        if name == "splunk_get_knowledge_objects":
            ko_type = args.get("type")
            if ko_type in self.failing_ko_types:
                return {"isError": True, "content": [{"type": "text", "text": f"Insufficient permissions to list {ko_type}"}]}
            if ko_type == "saved_searches":
                return text_content({"results": [
                    {"name": "Errors by host", "search": "index=main error | stats count by host", "is_scheduled": "1"},
                ]})
            return text_content({"results": []})
        if name == "splunk_get_user_info":
            return text_content({"name": "svc_discovery", "roles": ["power", "user"]})
        if name == "splunk_get_kv_store_collections":
            return text_content({"results": [{"name": "asset_inventory", "app": "search"}]})
        if name == "splunk_get_index_info":
            index_name = args.get("index_name")
            source = next(row for row in INDEXES if row["title"] == index_name)
            return text_content({
                "name": index_name,
                "repFactor": "auto",
                "frozenTimePeriodInSecs": "7776000",
                "maxTotalDataSizeMB": "500000",
                "currentDBSizeMB": source["currentDBSizeMB"],
                "totalEventCount": source["totalEventCount"],
            })
        if name == "splunk_run_query":
            query = args.get("query", "")
            if "license_usage.log" in query:
                rows = [] if self.license_bytes is None else [{"bytes": str(self.license_bytes)}]
                return text_content({"results": rows})
            if query == engine_module.RECENT_INDEX_ACTIVITY_QUERY:
                return text_content({"results": [dict(row) for row in RECENT_ACTIVITY]})
            if query == engine_module.DAILY_EVENT_TREND_QUERY:
                return text_content({"results": [dict(row) for row in TREND]})
            return text_content({"results": []})
        return {"isError": True, "content": [{"type": "text", "text": f"Unknown tool {name}"}]}


GA_TOOL_SCHEMAS = {
    "splunk_get_metadata": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["hosts", "sources"]},
            "index": {"type": "string"},
            "earliest_time": {"type": "string"},
            "latest_time": {"type": "string"},
            "row_limit": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
        "required": ["type"],
    },
    "splunk_get_knowledge_objects": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["saved_searches", "alerts", "macros", "lookups", "data_models", "views", "tags"]},
            "row_limit": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
        "required": ["type"],
    },
}


class SchemaAwareFakeMCP(FakeSplunkMCP):
    """Advertises the GA input schemas: metadata lists only hosts/sources and dashboards are "views"."""

    def __init__(self, **kwargs):
        kwargs.setdefault("failing_ko_types", ())
        super().__init__(**kwargs)

    async def post(self, payload, timeout_seconds):
        if payload.get("method") == "tools/list":
            self.tools_list_calls += 1
            tools = [
                {"name": name, **({"inputSchema": GA_TOOL_SCHEMAS[name]} if name in GA_TOOL_SCHEMAS else {})}
                for name in TOOL_NAMES
            ]
            return 200, json.dumps({"jsonrpc": "2.0", "id": payload.get("id"), "result": {"tools": tools}})
        return await super().post(payload, timeout_seconds)

    def tool_result(self, name, args):
        if name == "splunk_get_metadata" and args.get("type") not in {"hosts", "sources"}:
            return {"isError": True, "content": [{"type": "text", "text": "Invalid metadata type"}]}
        if name == "splunk_get_knowledge_objects" and args.get("type") == "data_models":
            return text_content({"results": [
                {"name": "Authentication", "acceleration": '{"enabled":true}'},
                {"name": "Alerts", "acceleration": '{"enabled":false}'},
            ]})
        if name == "splunk_run_query" and args.get("query") == engine_module.SOURCETYPE_METADATA_QUERY:
            return text_content({"results": [dict(row) for row in SOURCETYPES]})
        return super().tool_result(name, args)


class JsonLLM:
    def __init__(self):
        self.calls = []

    async def analyze_data(self, data, analysis_type):
        self.calls.append((analysis_type, len(json.dumps(data, indent=2, default=str))))
        if analysis_type == "patterns":
            return {"patterns": ["The firewall index holds the most events"]}
        if analysis_type == "recommendations":
            return {"recommendations": [{
                "title": "Baseline firewall deny rates",
                "description": "pan:traffic is the busiest sourcetype; baseline deny rates per zone.",
                "priority": "high",
                "category": "Security",
                "suggested_actions": "Build a deny-rate baseline search.",
            }]}
        if analysis_type == "creative_use_cases":
            return {"use_cases": [{
                "title": "Correlate web access with firewall denies",
                "description": "Join access_combined and pan:traffic by client IP.",
                "data_sources": ["access_combined", "pan:traffic"],
            }]}
        return {}


class RaisingLLM:
    async def analyze_data(self, data, analysis_type):
        raise RuntimeError("LLM endpoint unavailable")


class TextLLM:
    async def analyze_data(self, data, analysis_type):
        return {"analysis": "Here are some thoughts without any JSON structure.", "insights": ["Analysis completed"]}


class StubDisplay:
    def __init__(self):
        self.messages = []
        self.overviews = []

    def phase(self, message):
        self.messages.append(("phase", message))

    def info(self, message):
        self.messages.append(("info", message))

    def success(self, message):
        self.messages.append(("success", message))

    def warning(self, message):
        self.messages.append(("warning", message))

    def error(self, message):
        self.messages.append(("error", message))

    def show_overview_summary(self, overview):
        self.overviews.append(overview)


class StubProgress:
    def __init__(self):
        self.updates = []
        self.total_steps = None

    def set_total_steps(self, total):
        self.total_steps = total

    async def update_progress(self, pct, message=""):
        self.updates.append((pct, message))


def make_engine(fake, llm=None, **kwargs):
    engine = DiscoveryEngine("https://splunk.example.test:8089/services/mcp", "test-token", llm or JsonLLM(), **kwargs)
    engine._post_json = fake.post
    engine.retry_backoff_seconds = 0
    return engine


def index_references(spl):
    return [match.group(2) for match in re.finditer(r'index\s*=\s*("?)([^\s"()|]+)\1', spl)]


class ToolResponseParsingTests(unittest.TestCase):
    def setUp(self):
        self.engine = DiscoveryEngine("https://splunk.example.test/mcp", "token", JsonLLM())

    def test_text_content_with_results(self):
        body = {"jsonrpc": "2.0", "id": 1, "result": text_content({"results": [{"a": 1}, {"a": 2}]})}
        parsed = self.engine._parse_tool_response(body)
        self.assertEqual(parsed["results"], [{"a": 1}, {"a": 2}])

    def test_multi_part_content_is_merged(self):
        body = {"jsonrpc": "2.0", "id": 1, "result": {"content": [
            {"type": "text", "text": json.dumps([{"host": "a"}])},
            {"type": "text", "text": json.dumps({"results": [{"host": "b"}, {"host": "c"}]})},
        ]}}
        parsed = self.engine._parse_tool_response(body)
        self.assertEqual([row["host"] for row in parsed["results"]], ["a", "b", "c"])

    def test_structured_content_is_preferred(self):
        body = {"jsonrpc": "2.0", "id": 1, "result": {
            "structuredContent": {"results": [{"title": "main"}]},
            "content": [{"type": "text", "text": "summary text"}],
        }}
        parsed = self.engine._parse_tool_response(body)
        self.assertEqual(parsed["results"], [{"title": "main"}])

    def test_structured_content_error_status_raises(self):
        body = {"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": {"status_code": 403, "message": "forbidden"}}}
        with self.assertRaises(MCPToolError) as ctx:
            self.engine._parse_tool_response(body)
        self.assertIn("forbidden", str(ctx.exception))

    def test_is_error_raises_with_message(self):
        body = {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": [{"type": "text", "text": "Search failed"}]}}
        with self.assertRaises(MCPToolError) as ctx:
            self.engine._parse_tool_response(body)
        self.assertIn("Search failed", str(ctx.exception))

    def test_jsonrpc_error_raises(self):
        body = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "Invalid params"}}
        with self.assertRaises(MCPToolError) as ctx:
            self.engine._parse_tool_response(body)
        self.assertIn("Invalid params", str(ctx.exception))

    def test_non_json_text_is_marked_unparsed(self):
        body = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "index main has 5 events"}]}}
        parsed = self.engine._parse_tool_response(body)
        self.assertTrue(parsed.get("unparsed"))
        self.assertEqual(parsed["results"], [])

    def test_decode_body_handles_sse_and_rejects_garbage(self):
        sse = 'event: message\ndata: {"jsonrpc": "2.0", "id": 3, "result": {"results": []}}\n\n'
        self.assertEqual(DiscoveryEngine._decode_body(sse)["id"], 3)
        with self.assertRaises(MCPToolError):
            DiscoveryEngine._decode_body("<html>Bad gateway</html>")
        with self.assertRaises(MCPToolError):
            DiscoveryEngine._decode_body("   ")


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_rpc_request_retries_once_on_timeout_and_5xx(self):
        engine = DiscoveryEngine("https://splunk.example.test/mcp", "token", JsonLLM())
        engine.retry_backoff_seconds = 0
        responses = [asyncio.TimeoutError(), (200, json.dumps({"jsonrpc": "2.0", "id": 2, "result": {"results": []}}))]

        async def flaky_post(payload, timeout_seconds):
            item = responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        engine._post_json = flaky_post
        body = await engine._rpc_request("tools/call", {"name": "x", "arguments": {}}, 1)
        self.assertEqual(body["id"], 2)
        self.assertEqual(engine.get_discovery_metrics()["mcp"]["retries"], 1)

        statuses = [(502, "bad gateway"), (503, "unavailable")]

        async def failing_post(payload, timeout_seconds):
            return statuses.pop(0)

        engine._post_json = failing_post
        with self.assertRaises(MCPToolError) as ctx:
            await engine._rpc_request("tools/call", {"name": "x", "arguments": {}}, 1)
        self.assertIn("503", str(ctx.exception))

    async def test_rpc_ids_increment(self):
        fake = FakeSplunkMCP()
        engine = make_engine(fake)
        await engine._mcp_call("splunk_get_info", {})
        await engine._mcp_call("splunk_get_indexes", {"row_limit": 5})
        ids = [rpc_id for rpc_id in fake.rpc_ids if rpc_id is not None]
        self.assertEqual(ids, sorted(set(ids)))

    async def test_unparsed_response_records_step_error(self):
        engine = DiscoveryEngine("https://splunk.example.test/mcp", "token", JsonLLM(), available_tools=TOOL_NAMES)

        async def prose_post(payload, timeout_seconds):
            return 200, json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": {"content": [{"type": "text", "text": "not json"}]}})

        engine._post_json = prose_post
        outcome = await engine._fetch("platform_info", "splunk_get_info", {})
        self.assertEqual(outcome.status, "error")
        self.assertEqual(engine.get_step_status()["platform_info"]["status"], "error")


class OverviewTests(unittest.IsolatedAsyncioTestCase):
    async def test_overview_counts_and_license_volume(self):
        fake = FakeSplunkMCP()
        engine = make_engine(fake)
        overview = await engine.get_quick_overview()
        await engine.aclose()

        self.assertEqual(overview.total_indexes, 6)
        self.assertEqual(overview.total_sourcetypes, 4)
        self.assertEqual(overview.total_hosts, 3)
        self.assertEqual(overview.total_sources, 2)
        self.assertEqual(overview.splunk_version, "9.3.1")
        self.assertEqual(overview.data_volume_24h, "2.50 GB")
        self.assertAlmostEqual(overview.data_volume_24h_mb, 2560.0)
        self.assertIn("license_usage.log", overview.data_volume_24h_source)
        self.assertAlmostEqual(overview.total_index_size_mb, 950.0)
        self.assertEqual(overview.authenticated_user, "svc_discovery")
        self.assertFalse(any(overview.truncated.values()))
        self.assertEqual(fake.tools_list_calls, 1)

    async def test_data_volume_is_unknown_without_license_usage(self):
        fake = FakeSplunkMCP(license_bytes=None)
        engine = make_engine(fake)
        overview = await engine.get_quick_overview()
        self.assertIsNone(overview.data_volume_24h)
        self.assertIsNone(overview.data_volume_24h_mb)
        self.assertTrue(overview.data_volume_24h_source.startswith("unavailable"))
        # On-disk size is reported separately and never substituted for ingest volume.
        self.assertGreater(overview.total_index_size_mb, 0)

    async def test_row_limit_marks_counts_as_lower_bounds(self):
        hosts = [{"host": f"host-{i}", "totalCount": "1"} for i in range(3)]
        fake = FakeSplunkMCP(hosts=hosts)
        with mock.patch.dict(engine_module.ROW_LIMITS, {"hosts": 3}):
            engine = make_engine(fake)
            overview = await engine.get_quick_overview()
        self.assertTrue(overview.truncated["hosts"])
        self.assertEqual(overview.count_display["hosts"], "≥3")
        self.assertFalse(overview.truncated["indexes"])
        self.assertTrue(engine.get_step_status()["hosts"]["truncated"])

    async def test_soft_deadline_skips_optional_steps(self):
        fake = FakeSplunkMCP()
        engine = make_engine(fake, mcp_deadline_seconds=1e-9)
        overview = await engine.get_quick_overview()
        status = engine.get_step_status()
        self.assertEqual(status["indexes"]["status"], "ok")
        self.assertEqual(status["license_usage_24h"]["status"], "skipped")
        self.assertIsNone(overview.data_volume_24h)
        self.assertEqual(overview.total_indexes, 6)

    async def test_index_failure_is_fatal(self):
        engine = DiscoveryEngine("https://splunk.example.test/mcp", "token", JsonLLM(), available_tools=TOOL_NAMES)
        engine.retry_backoff_seconds = 0

        async def down(payload, timeout_seconds):
            return 401, "Unauthorized"

        engine._post_json = down
        with self.assertRaises(Exception) as ctx:
            await engine.get_quick_overview()
        self.assertIn("Unable to retrieve environment information", str(ctx.exception))


class DiscoveryFindingsTests(unittest.IsolatedAsyncioTestCase):
    async def test_repfactor_auto_is_not_flagged(self):
        engine = DiscoveryEngine("https://splunk.example.test/mcp", "token", JsonLLM())
        findings = await engine._analyze_detailed_index_findings({"name": "main", "repFactor": "auto"})
        self.assertFalse(any("repfactor" in finding.lower() or "replicat" in finding.lower() for finding in findings))
        findings = await engine._analyze_detailed_index_findings({"name": "main", "repFactor": "0"})
        self.assertTrue(any("repFactor=0" in finding for finding in findings))

    async def test_epoch_recent_time_from_metadata_search_drives_freshness(self):
        engine = DiscoveryEngine("https://splunk.example.test/mcp", "token", JsonLLM())
        stale_epoch = time.time() - 72 * 3600
        row = {"sourcetype": "legacy:feed", "totalCount": "500", "recentTime": str(int(stale_epoch))}

        findings = await engine._analyze_sourcetype_findings(row)
        compact = DiscoveryEngine._compact_metadata_rows([row], "sourcetype")[0]

        self.assertTrue(any("Stale data: legacy:feed" in finding for finding in findings))
        self.assertFalse(any("last 24h" in finding for finding in findings))
        self.assertAlmostEqual(compact["age_hours"], 72.0, delta=0.2)
        self.assertTrue(compact["last_seen_utc"].endswith("Z"))
        self.assertIsNone(DiscoveryEngine._compact_metadata_rows([{"sourcetype": "x"}], "sourcetype")[0]["age_hours"])

    async def test_epoch_recent_time_wins_over_iso_in_server_local_time(self):
        engine = DiscoveryEngine("https://splunk.example.test/mcp", "token", JsonLLM())
        epoch = int(time.time() - 49 * 3600)
        # The MCP metadata tool has been seen labelling server-local time (UTC-5 here) with "Z".
        skewed_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch - 5 * 3600))
        row = {"source": "/opt/collector.py", "totalCount": "10", "recentTime": str(epoch), "recentTimeIso": skewed_iso}

        compact = DiscoveryEngine._compact_metadata_rows([row], "source")[0]
        self.assertAlmostEqual(compact["age_hours"], 49.0, delta=0.2)
        self.assertEqual(metadata_recent_time_utc(row), time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch)))
        self.assertEqual(metadata_recent_time_utc({"recentTimeIso": skewed_iso}), skewed_iso)
        self.assertEqual(metadata_recent_time_utc({"recentTime": "0"}), "")
        findings = await engine._analyze_source_findings(row)
        self.assertTrue(any("2.0 days old" in finding for finding in findings), findings)
    async def test_each_distinct_mcp_call_runs_once(self):
        fake = FakeSplunkMCP()
        engine = make_engine(fake)
        await engine.get_quick_overview()
        results = [result async for result in engine.discover_environment()]
        await engine.aclose()

        self.assertTrue(results)
        duplicates = {call for call in fake.calls if fake.calls.count(call) > 1}
        self.assertEqual(duplicates, set())
        self.assertGreater(engine.get_discovery_metrics()["mcp"]["cache_hits"], 0)

    async def test_failed_step_yields_status_result_and_continues(self):
        fake = FakeSplunkMCP(failing_ko_types=("macros",))
        engine = make_engine(fake)
        await engine.get_quick_overview()
        results = [result async for result in engine.discover_environment()]

        status_results = [r for r in results if r.kind == KIND_STEP_STATUS]
        self.assertEqual([r.data["discovery_step"] for r in status_results], ["knowledge_objects:macros"])
        self.assertEqual(engine.get_step_status()["knowledge_objects:macros"]["status"], "error")
        self.assertNotIn("macros", engine.environment_overview.knowledge_object_counts)
        self.assertTrue(any(r.kind == KIND_INDEX_DETAIL for r in results))

        freshness = engine.get_discovery_metrics()["freshness"]
        self.assertEqual(freshness["status"], "measured")
        self.assertEqual(freshness["stale_indexes"], ["legacy_app"])
        self.assertEqual(freshness["empty_indexes"], ["empty_idx"])

    async def test_discovery_order_is_deterministic(self):
        orders = []
        for _ in range(2):
            engine = make_engine(FakeSplunkMCP())
            await engine.get_quick_overview()
            orders.append([result.description async for result in engine.discover_environment()])
        self.assertEqual(orders[0], orders[1])


class SchemaAwareDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_metadata_type_the_schema_rejects_goes_straight_to_the_search_fallback(self):
        fake = SchemaAwareFakeMCP()
        engine = make_engine(fake)
        overview = await engine.get_quick_overview()
        await engine.aclose()

        self.assertEqual(overview.total_sourcetypes, len(SOURCETYPES))
        self.assertFalse(any(name == "splunk_get_metadata" and '"sourcetypes"' in args for name, args in fake.calls))
        status = engine.get_step_status()["sourcetypes"]
        self.assertEqual(status["status"], "ok")
        self.assertEqual(status["fallback"], "metadata search command")

    async def test_knowledge_object_types_use_ga_names_and_unsupported_types_are_not_called(self):
        fake = SchemaAwareFakeMCP()
        engine = make_engine(fake)
        with mock.patch.object(engine_module, "KNOWLEDGE_OBJECT_TYPES", engine_module.KNOWLEDGE_OBJECT_TYPES + ["eventtypes"]):
            await engine.get_quick_overview()
            results = [result async for result in engine.discover_environment()]
        await engine.aclose()

        requested = {json.loads(args)["type"] for name, args in fake.calls if name == "splunk_get_knowledge_objects"}
        self.assertIn("views", requested)
        self.assertIn("data_models", requested)
        self.assertNotIn("dashboards", requested)
        self.assertNotIn("eventtypes", requested)
        status = engine.get_step_status()["knowledge_objects:eventtypes"]
        self.assertEqual(status["status"], "unsupported")
        self.assertIn("supported:", status["error"])
        unsupported = [r for r in results if r.kind == KIND_STEP_STATUS and r.data["discovery_step"] == "knowledge_objects:eventtypes"]
        self.assertEqual(len(unsupported), 1)
        self.assertIn("not supported", unsupported[0].description)
        self.assertEqual(engine.environment_overview.knowledge_object_counts.get("data_models"), 2)

    async def test_schemas_passed_by_the_caller_skip_tools_list(self):
        fake = SchemaAwareFakeMCP()
        engine = make_engine(fake, available_tools=TOOL_NAMES, tool_schemas=GA_TOOL_SCHEMAS)
        overview = await engine.get_quick_overview()
        await engine.aclose()
        self.assertEqual(fake.tools_list_calls, 0)
        self.assertEqual(overview.total_sourcetypes, len(SOURCETYPES))

    async def test_data_model_acceleration_is_read_from_the_json_string(self):
        engine = DiscoveryEngine("https://splunk.example.test/mcp", "token", JsonLLM())
        accelerated = await engine._analyze_knowledge_object_findings(
            {"name": "Authentication", "acceleration": '{"enabled":true,"earliest_time":"-1mon"}'}, "data_models"
        )
        plain = await engine._analyze_knowledge_object_findings(
            {"name": "Alerts", "acceleration": '{"enabled":false}'}, "data_models"
        )
        self.assertTrue(any("Accelerated data model" in finding for finding in accelerated))
        self.assertTrue(any("Not reported as accelerated" in finding for finding in plain))
        view = await engine._analyze_knowledge_object_findings({"name": "admin_setup", "is_dashboard": "0"}, "views")
        dashboard = await engine._analyze_knowledge_object_findings({"name": "ops", "label": "Ops Overview", "is_dashboard": "1"}, "views")
        self.assertEqual(view, [])
        self.assertTrue(any("Ops Overview" in finding for finding in dashboard))

    async def test_unsupported_steps_do_not_lower_the_readiness_score(self):
        engine = make_engine(SchemaAwareFakeMCP())
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pipeline = DiscoveryV2Pipeline(engine, output_root=Path(tmp.name))
        overview = await engine.get_quick_overview()
        [result async for result in engine.discover_environment()]
        status = engine.get_step_status()
        status["knowledge_objects:eventtypes"] = {"status": "unsupported", "error": "not offered"}
        baseline = pipeline._compute_readiness(overview, {k: v for k, v in status.items() if k != "knowledge_objects:eventtypes"}, engine.get_discovery_metrics())
        with_unsupported = pipeline._compute_readiness(overview, status, engine.get_discovery_metrics())
        await engine.aclose()
        self.assertEqual(baseline["score"], with_unsupported["score"])


class TruncatedReplyLLM:
    """Returns what a real client parses from replies cut off by the output budget."""

    REPLIES = {
        "patterns": (
            '{"patterns": [{"category": "Volume concentration", "insights": ["firewall holds the most events.", "web is second."]}, '
            '{"category": "Freshness", "insight": "legacy stopped receiving data.", "evidence": ["index=legacy"]}, {"category": "Qual'
        ),
        "recommendations": (
            '```json\n{"recommendations": [{"title": "Baseline firewall deny rates", "description": "pan:traffic is the busiest sourcetype.",'
            ' "priority": "high"}, {"title": "Watch the legacy index", "descr'
        ),
        "creative_use_cases": (
            '[{"title": "Correlate web access with firewall denies", "description": "Join access_combined and pan:traffic by client IP.",'
            ' "data_sources": [{"type": "sourcetype", "name": "access_combined"}, {"type": "sourcetype", "name": "pan:traffic"}]},'
            ' {"title": "Second idea", "descr'
        ),
    }

    async def analyze_data(self, data, analysis_type):
        return parse_json_from_llm_text(self.REPLIES.get(analysis_type, "{}"))


class LLMReplyParsingTests(unittest.TestCase):
    def test_single_use_case_is_not_replaced_by_its_data_sources(self):
        reply = {
            "title": "Correlate web access with firewall denies",
            "description": "Join access_combined and pan:traffic.",
            "data_sources": [{"type": "sourcetype", "name": "access_combined"}],
        }

        items, status = DiscoveryEngine._parse_llm_list(reply, "use_cases")

        self.assertEqual(status, "ok")
        self.assertEqual([item["title"] for item in items], ["Correlate web access with firewall denies"])

    def test_wrapper_object_list_is_found_and_names_become_titles(self):
        reply = {"name": "Splunk ideas", "items": [{"name": "Baseline denies", "description": "Use pan:traffic."}]}

        items, status = DiscoveryEngine._parse_llm_list(reply, "recommendations")

        self.assertEqual(status, "ok")
        self.assertEqual(items[0]["title"], "Baseline denies")

    def test_untitled_lists_are_empty(self):
        items, status = DiscoveryEngine._parse_llm_list([{"type": "sourcetype", "name": "x"}], "use_cases")
        self.assertEqual((items, status), ([], "empty"))

    def test_patterns_are_normalized_to_category_insight_evidence(self):
        patterns = DiscoveryEngine._normalize_llm_patterns({"category": "Volume", "insights": ["a.", "b."], "evidence": "main: 5000"})
        self.assertEqual(patterns, [{"category": "Volume", "insight": "a. b.", "evidence": ["main: 5000"]}])
        self.assertEqual(DiscoveryEngine._normalize_llm_patterns({"patterns": ["firewall is busiest", ""]}), ["firewall is busiest"])
        self.assertEqual(DiscoveryEngine._normalize_llm_patterns({"unrelated": 1}), [])


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    async def run_pipeline(self, llm, fake=None):
        fake = fake or FakeSplunkMCP()
        engine = make_engine(fake, llm=llm)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        output_root = Path(tmp.name) / "nested" / "output"
        pipeline = DiscoveryV2Pipeline(engine, output_root=output_root)
        display = StubDisplay()
        progress = StubProgress()
        result = await pipeline.run(display, progress)
        artifacts = {name: (output_root / name).read_text(encoding="utf-8") for name in result["report_paths"]}
        blueprint_name = next(name for name in artifacts if name.startswith("v2_intelligence_blueprint_"))
        blueprint = json.loads(artifacts[blueprint_name])
        return result, blueprint, artifacts, display, fake

    def assert_common_artifacts(self, result, blueprint, artifacts):
        self.assertEqual(len(result["report_paths"]), 4)
        for prefix in ("v2_intelligence_blueprint_", "v2_insights_brief_", "v2_operator_runbook_", "v2_developer_handoff_"):
            self.assertTrue(any(name.startswith(prefix) for name in artifacts), prefix)
        for key in (
            "readiness_score", "score_basis", "overview", "capability_graph", "finding_ledger",
            "finding_ledger_summary", "discovered_inventory", "classification_map", "coverage_gaps",
            "risk_register", "trend_signals", "recommendations", "suggested_use_cases", "llm_status",
            "discovery_step_status", "discovery_metrics", "pipeline_errors",
        ):
            self.assertIn(key, blueprint)
        self.assertEqual(blueprint["pipeline_errors"], [])
        self.assertEqual(result["pipeline_errors"], [])
        self.assertTrue(0 <= blueprint["readiness_score"] <= 100)
        self.assertEqual(blueprint["score_basis"]["method"], "evidence_weighted_v1")
        self.assertEqual(sorted(blueprint["discovered_inventory"]["indexes"]), sorted(row["title"] for row in INDEXES))
        for name, content in artifacts.items():
            lowered = content.lower()
            for lab_string in LAB_STRINGS:
                self.assertNotIn(lab_string, lowered, f"{lab_string} leaked into {name}")
        handoff = next(content for name, content in artifacts.items() if name.startswith("v2_developer_handoff_"))
        for name in result["report_paths"]:
            if not name.startswith("v2_developer_handoff_"):
                self.assertIn(name, handoff)
        for entry in blueprint["finding_ledger"]:
            if entry["kind"] == KIND_INDEX_DETAIL:
                self.assertFalse(any("replicat" in finding.lower() for finding in entry["findings"]))

    async def test_pipeline_with_structured_llm(self):
        llm = JsonLLM()
        result, blueprint, artifacts, display, _ = await self.run_pipeline(llm)
        self.assert_common_artifacts(result, blueprint, artifacts)
        for stage in ("patterns", "recommendations", "creative_use_cases"):
            self.assertEqual(blueprint["llm_status"][stage]["status"], "ok", stage)
            self.assertFalse(blueprint["llm_status"][stage]["fallback_used"])
        self.assertEqual(blueprint["recommendations"][0]["title"], "Baseline firewall deny rates")
        self.assertEqual(blueprint["overview"]["data_volume_24h"], "2.50 GB")
        for _, prompt_chars in llm.calls:
            self.assertLessEqual(prompt_chars, engine_module.LLM_PROMPT_MAX_CHARS)
        self.assertEqual(len(display.overviews), 1)

    async def test_pipeline_keeps_complete_items_from_truncated_llm_replies(self):
        result, blueprint, artifacts, _, _ = await self.run_pipeline(TruncatedReplyLLM())
        self.assert_common_artifacts(result, blueprint, artifacts)
        for stage in ("patterns", "recommendations", "creative_use_cases"):
            self.assertEqual(blueprint["llm_status"][stage]["status"], "ok", stage)
        self.assertEqual(
            [item["category"] for item in blueprint["overview"]["notable_patterns"]],
            ["Volume concentration", "Freshness"],
        )
        self.assertEqual(blueprint["overview"]["notable_patterns"][0]["insight"], "firewall holds the most events. web is second.")
        self.assertEqual([rec["title"] for rec in blueprint["recommendations"]], ["Baseline firewall deny rates"])
        self.assertEqual(
            [use_case["title"] for use_case in blueprint["suggested_use_cases"]],
            ["Correlate web access with firewall denies"],
        )

    async def test_pipeline_survives_llm_failures(self):
        result, blueprint, artifacts, display, _ = await self.run_pipeline(RaisingLLM())
        self.assert_common_artifacts(result, blueprint, artifacts)
        for stage in ("patterns", "recommendations", "creative_use_cases"):
            self.assertEqual(blueprint["llm_status"][stage]["status"], "failed", stage)
            self.assertTrue(blueprint["llm_status"][stage]["fallback_used"])
        titles = [rec["title"] for rec in blueprint["recommendations"]]
        self.assertIn("Investigate indexes that stopped receiving data", titles)
        self.assertTrue(all(rec.get("generated_by") == "local_analysis" for rec in blueprint["recommendations"]))
        self.assertTrue(any(level == "warning" and "The AI step did not finish" in message for level, message in display.messages))
        self.assertEqual(result["llm_status"], blueprint["llm_status"])

    async def test_pipeline_with_unstructured_llm_replies(self):
        result, blueprint, artifacts, _, _ = await self.run_pipeline(TextLLM())
        self.assert_common_artifacts(result, blueprint, artifacts)
        self.assertEqual(blueprint["llm_status"]["recommendations"]["status"], "unstructured")
        self.assertTrue(blueprint["llm_status"]["recommendations"]["fallback_used"])
        self.assertTrue(blueprint["recommendations"])
        for use_case in blueprint["suggested_use_cases"]:
            self.assertNotIn("Analysis completed", json.dumps(use_case))

    async def test_pipeline_reports_unknown_ingest_volume_honestly(self):
        result, blueprint, artifacts, _, _ = await self.run_pipeline(JsonLLM(), FakeSplunkMCP(license_bytes=None))
        self.assert_common_artifacts(result, blueprint, artifacts)
        self.assertIsNone(blueprint["overview"]["data_volume_24h"])
        self.assertAlmostEqual(blueprint["overview"]["total_index_size_mb"], 950.0)

    async def test_generator_uses_only_discovered_indexes(self):
        _, blueprint, _, _, _ = await self.run_pipeline(JsonLLM())
        generator = SPLGenerator(blueprint["finding_ledger"])
        queries = await generator.generate_all_queries()
        self.assertTrue(queries)
        allowed = {row["title"] for row in INDEXES} | {"*", "_*"}
        for query in queries:
            spl = query.get("spl") or query.get("query") or ""
            for reference in index_references(spl):
                self.assertIn(reference, allowed, f"{query.get('title')}: {spl}")

    def test_generator_without_context_uses_wildcard(self):
        generator = SPLGenerator([])
        queries = asyncio.run(generator.generate_all_queries())
        for query in queries:
            spl = query.get("spl") or query.get("query") or ""
            for reference in index_references(spl):
                self.assertIn(reference, {"*", "_*", "_internal"}, spl)


if __name__ == "__main__":
    unittest.main()
