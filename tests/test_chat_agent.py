import asyncio
import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


import chat_agent  # noqa: E402
import web_app  # noqa: E402
from mcp_tool_args import adapt_tool_arguments, parse_jsonrpc_error  # noqa: E402


def _rows_result(rows, **extra):
    structured = {"results": rows}
    structured.update(extra)
    return {"jsonrpc": "2.0", "id": 1, "result": {"content": [], "structuredContent": structured}}


def _tool_error_result(message):
    return {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": [{"type": "text", "text": message}]}}


def _tool_call(query, earliest="-24h", latest="now"):
    payload = {"tool": "splunk_run_query", "args": {"query": query, "earliest_time": earliest, "latest_time": latest}}
    return f"<TOOL_CALL>{json.dumps(payload)}</TOOL_CALL>"


class ScriptedLLM:
    """Returns canned replies in order and records every message list it was sent."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def generate_response(self, messages=None, max_tokens=None, temperature=None, prompt=None):
        # Copy: the chat loop keeps appending to the same history list after each call.
        self.calls.append(list(messages) if messages is not None else prompt)
        if not self.responses:
            raise AssertionError("Unexpected extra LLM call")
        return self.responses.pop(0)


class RecordingMCP:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    async def __call__(self, tool_call, _config):
        self.calls.append(tool_call)
        return self.handler(tool_call)


@contextmanager
def chat_harness(llm, mcp, tools=("splunk_run_query", "splunk_get_indexes")):
    async def discover(_config):
        return set(tools)

    with tempfile.TemporaryDirectory() as temp_dir, \
            patch.object(web_app, "get_or_create_llm_client", lambda _config: llm), \
            patch.object(web_app, "load_latest_report_knowledge", lambda *_: None), \
            patch.object(web_app, "discover_mcp_tools", discover), \
            patch.object(web_app, "execute_mcp_tool_call", mcp), \
            patch.object(web_app, "_get_memory_store_path", lambda session_id: Path(temp_dir) / f"{session_id}.json"), \
            patch.dict(web_app.chat_session_settings, {"enable_splunk_augmentation": True}), \
            patch.dict(web_app.chat_agent_memory, {}, clear=True):
        yield lambda request: asyncio.run(web_app.chat_with_splunk_logic(request))


def _system_text(messages):
    return "\n".join(m.get("content", "") for m in messages if isinstance(m, dict) and m.get("role") == "system")


class ChatAgentHelperTests(unittest.TestCase):
    def test_small_talk_requires_the_whole_message_to_be_a_greeting(self):
        for message in ["hi", "Thanks!", "hello there", "good morning team", "how are you?"]:
            self.assertTrue(chat_agent.is_small_talk(message), message)
        for message in ["this index is empty", "hi, show me errors in index=main", "thanks, now count events in index=web", ""]:
            self.assertFalse(chat_agent.is_small_talk(message), message)

    def test_announces_unexecuted_search_only_for_short_promises(self):
        self.assertTrue(chat_agent.announces_unexecuted_search("Let me run a search for that."))
        self.assertTrue(chat_agent.announces_unexecuted_search("I'll query Splunk for the latest events."))
        self.assertFalse(chat_agent.announces_unexecuted_search("Here are the results: 42 events."))
        self.assertFalse(chat_agent.announces_unexecuted_search("Answer. " * 120 + "Let me run a search next."))

    def test_normalize_mission_cleans_and_bounds_text(self):
        self.assertEqual(chat_agent.normalize_mission("  Find\tsensor\n gaps \x00 "), "Find sensor gaps")
        self.assertEqual(chat_agent.normalize_mission(None), "")
        long_mission = chat_agent.normalize_mission("x" * 2000)
        self.assertLessEqual(len(long_mission), chat_agent.MAX_MISSION_CHARS)
        self.assertTrue(long_mission.endswith("..."))
        self.assertIn("Find sensor gaps", chat_agent.format_mission_context("Find sensor gaps"))
        self.assertEqual(chat_agent.format_mission_context("   "), "")

    def test_classify_tool_result_reads_in_band_tool_errors(self):
        outcome = chat_agent.classify_tool_result(_tool_error_result("Search failed: unknown index"))
        self.assertEqual(outcome["status"], "error")
        self.assertIn("unknown index", outcome["error"])

    def test_classify_tool_result_reads_jsonrpc_and_transport_errors(self):
        rpc = chat_agent.classify_tool_result({"jsonrpc": "2.0", "id": 1, "error": {"code": -32004, "message": "Tool not found"}})
        self.assertEqual(rpc["status"], "error")
        self.assertIn("Tool not found", rpc["error"])
        transport = chat_agent.classify_tool_result({"error": "Unauthorized", "detail": "bad token", "status_code": 401, "fatal": True})
        self.assertEqual(transport["status"], "error")
        self.assertTrue(transport["fatal"])
        self.assertEqual(transport["status_code"], 401)
        structured = chat_agent.classify_tool_result({"result": {"structuredContent": {"status_code": 403, "content": "forbidden"}}})
        self.assertEqual(structured["status"], "error")
        self.assertEqual(structured["status_code"], 403)

    def test_classify_tool_result_reports_rows_paging_and_zero_counts(self):
        outcome = chat_agent.classify_tool_result(_rows_result([{"index": "main", "count": "10"}], truncated=True, total_rows=50))
        self.assertEqual(outcome["status"], "data")
        self.assertEqual(outcome["row_count"], 1)
        self.assertTrue(outcome["truncated"])
        self.assertEqual(outcome["total_rows"], 50)
        self.assertFalse(outcome["zero_counts"])

        zero = chat_agent.classify_tool_result(_rows_result([{"event_count": "0"}]))
        self.assertEqual(zero["status"], "data")
        self.assertTrue(zero["zero_counts"])

        empty = chat_agent.classify_tool_result(_rows_result([]))
        self.assertEqual(empty["status"], "no_data")

        text_rows = chat_agent.classify_tool_result({"result": {"content": [{"type": "text", "text": json.dumps([{"a": 1}])}]}})
        self.assertEqual(text_rows["rows"], [{"a": 1}])

    def test_tool_call_signature_ignores_whitespace_but_keeps_case(self):
        first = chat_agent.tool_call_signature("splunk_run_query", {"query": "search  index=main | where status=\"Failed\""})
        same = chat_agent.tool_call_signature("splunk_run_query", {"query": "search index=main | where status=\"Failed\""})
        case_fix = chat_agent.tool_call_signature("splunk_run_query", {"query": "search index=main | where status=\"failed\""})
        self.assertEqual(first, same)
        self.assertNotEqual(first, case_fix)

    def test_tool_call_with_misspelled_closing_tag_is_recovered(self):
        text = 'Checking now.\n<TOOL_CALL>{"tool": "splunk_run_query", "args": {"query": "| tstats count where index=* by index"}}</TOO_CALL>'
        call = web_app.extract_recoverable_tool_call(text, "splunk_run_query", default_earliest="-4h")
        self.assertEqual(call["params"]["name"], "splunk_run_query")
        self.assertEqual(call["params"]["arguments"]["query"], "| tstats count where index=* by index")
        self.assertEqual(call["params"]["arguments"]["earliest_time"], "-4h")
        self.assertEqual(web_app.sanitize_llm_response_text(text), "Checking now.")
        self.assertIsNone(web_app.extract_recoverable_tool_call("<TOOL_CALL>not json</TOO_CALL>", "splunk_run_query"))

    def test_rows_beyond_the_evidence_cap_still_show_their_names(self):
        rows = [{"title": f"idx_{i:02d}", "totalEventCount": str(i)} for i in range(30)] + [{"title": "ping", "totalEventCount": "5"}]
        outcome = chat_agent.classify_tool_result(_rows_result(rows))
        feedback = chat_agent.build_tool_feedback(
            step=1, tool_name="splunk_get_indexes", args={}, outcome=outcome, evidence_rows=5, evidence_chars=4000,
        )
        self.assertIn("Showing 5", feedback)
        self.assertIn("title of the 26 rows not shown", feedback)
        self.assertIn("ping", feedback)
        self.assertEqual(chat_agent.summarize_remaining_rows(rows, len(rows)), "")
        self.assertEqual(chat_agent.summarize_remaining_rows([{"count": "1"}, {"count": "2"}], 1), "")

    def test_index_agnostic_signature_spots_index_sweeps(self):
        sig = chat_agent.index_agnostic_signature
        netops = sig("splunk_run_query", {"query": 'index=netops sourcetype=homebridge:collector | stats count', "earliest_time": "-24h"})
        other = sig("splunk_run_query", {"query": 'index="brickeconomy" sourcetype=homebridge:collector | stats count', "earliest_time": "-24h"})
        wider = sig("splunk_run_query", {"query": 'index=netops sourcetype=homebridge:collector | stats count', "earliest_time": "-7d"})
        refined = sig("splunk_run_query", {"query": 'index=netops sourcetype=homebridge:collector ERROR | stats count', "earliest_time": "-24h"})
        self.assertEqual(netops, other)
        self.assertNotEqual(netops, wider)
        self.assertNotEqual(netops, refined)
        self.assertEqual(sig("splunk_get_index_info", {"index": "a"}), sig("splunk_get_index_info", {"index": "b"}))

    def test_sanitize_strips_leaked_role_labels_and_template_tokens(self):
        self.assertEqual(web_app.sanitize_llm_response_text("assistant\n\nNo matches were found."), "No matches were found.")
        self.assertEqual(web_app.sanitize_llm_response_text("Assistant: Here is the count."), "Here is the count.")
        self.assertEqual(web_app.sanitize_llm_response_text("Done.<|eot_id|>"), "Done.")
        self.assertEqual(web_app.sanitize_llm_response_text("assistants can help."), "assistants can help.")
        self.assertEqual(web_app.sanitize_llm_response_text("Ask the assistant: it helps."), "Ask the assistant: it helps.")

    def test_final_answer_prompt_rejects_overclaiming_from_empty_results(self):
        prompt = web_app.build_final_user_answer_prompt("Why did the collector stop?", "  • [Step 1] 0 rows")
        self.assertIn("zero results only shows that nothing matched", prompt)
        self.assertIn("Do not say you will run more searches", prompt)
        self.assertNotIn("successfully investigated", prompt)

    def test_tool_call_json_that_ends_the_reply_is_recovered(self):
        backticked = '`{"tool": "splunk_run_query", "args": {"query": "| tstats count where index=_internal by sourcetype", "earliest_time": "-1h"}}`'
        call = web_app.extract_recoverable_tool_call(backticked, "splunk_run_query", default_latest="now")
        self.assertEqual(call["params"]["arguments"]["query"], "| tstats count where index=_internal by sourcetype")
        self.assertEqual(call["params"]["arguments"]["earliest_time"], "-1h")
        self.assertEqual(call["params"]["arguments"]["latest_time"], "now")
        self.assertEqual(web_app.sanitize_llm_response_text(backticked), "")

        fenced = 'Checking the busiest sourcetypes.\n```json\n{"tool": "splunk_run_query", "args": {"query": "index=main | head 1"}}\n```'
        self.assertEqual(web_app.extract_recoverable_tool_call(fenced, "splunk_run_query")["params"]["arguments"]["query"], "index=main | head 1")
        self.assertEqual(web_app.sanitize_llm_response_text(fenced), "Checking the busiest sourcetypes.")

        example = 'You could later run `{"tool": "splunk_run_query", "args": {"query": "index=main"}}` to check this.'
        self.assertIsNone(web_app.extract_recoverable_tool_call(example, "splunk_run_query"))
        self.assertEqual(web_app.sanitize_llm_response_text(example), example)

    def test_unscoped_event_search_is_scoped_to_index_star(self):
        cases = {
            "sourcetype=homebridge:collector | stats count": "index=* sourcetype=homebridge:collector | stats count",
            "search sourcetype=x": "search index=* sourcetype=x",
            "NOT index=main sourcetype=x": "index=* NOT index=main sourcetype=x",
        }
        for query, expected in cases.items():
            args = {"query": query}
            self.assertTrue(web_app.scope_unscoped_chat_search(args), query)
            self.assertEqual(args["query"], expected)
        for query in ("index=main error", "| tstats count where index=* by index", ""):
            args = {"query": query}
            self.assertFalse(web_app.scope_unscoped_chat_search(args), query)
            self.assertEqual(args["query"], query)

    def test_index_metadata_totals_are_not_read_as_freshness(self):
        rows = [{"title": "homebridge_for_splunk", "totalEventCount": "92850", "currentDBSizeMB": "129"}]
        summary = web_app.summarize_tool_outcome("splunk_get_index_info", {"status": "data", "rows": rows})
        brief = web_app.format_result_summary_for_llm(summary)
        self.assertIn("does not show whether data is recent", brief)
        self.assertIn("latest(_time) as latest where index=homebridge_for_splunk", brief)

        dated = [{"title": "main", "totalEventCount": "10", "maxTime": "2026-11-09T13:00:00-05:00"}]
        dated_summary = web_app.summarize_tool_outcome("splunk_get_index_info", {"status": "data", "rows": dated})
        self.assertFalse(any("recent" in finding for finding in dated_summary["findings"]))

    def test_tool_feedback_lists_notes_after_the_spl(self):
        feedback = chat_agent.build_tool_feedback(
            step=1, tool_name="splunk_run_query", args={"query": "index=* sourcetype=x", "earliest_time": "-24h"},
            outcome={"status": "no_data"}, evidence_rows=5, evidence_chars=2000, notes=[web_app.UNSCOPED_SEARCH_NOTE],
        )
        lines = feedback.splitlines()
        self.assertTrue(lines[3].startswith("Note: the search named no index"))
        self.assertIn("0 rows returned", lines[4])
    def test_tool_catalog_lists_primary_tools_first(self):
        text = chat_agent.build_tool_catalog_text(
            ["splunk_get_indexes", "splunk_run_query"],
            descriptions={"splunk_run_query": "Run a search. Extra detail."},
            primary_order=("splunk_run_query",),
        )
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("- splunk_run_query: Run a search."))
        self.assertIn("splunk_get_indexes", lines[1])


class McpToolArgumentTests(unittest.TestCase):
    def test_aliases_are_renamed_to_schema_names(self):
        schema = {"type": "object", "properties": {"index_name": {"type": "string"}}, "required": ["index_name"]}
        args, dropped = adapt_tool_arguments({"index": "main"}, schema)
        self.assertEqual(args, {"index_name": "main"})
        self.assertEqual(dropped, [])

    def test_row_limit_maps_to_count_and_is_clamped(self):
        schema = {"type": "object", "properties": {"offset": {"type": "integer"}, "count": {"type": "integer", "maximum": 100}}}
        args, _ = adapt_tool_arguments({"row_limit": "200"}, schema)
        self.assertEqual(args, {"count": 100})

    def test_enum_synonyms_and_unknown_keys(self):
        schema = {"type": "object", "properties": {"type": {"type": "string", "enum": ["saved_searches", "views", "macros"]}}}
        args, dropped = adapt_tool_arguments({"object_type": "Dashboards", "verbose": True}, schema)
        self.assertEqual(args, {"type": "views"})
        self.assertEqual(dropped, ["verbose"])

    def test_without_schema_arguments_are_unchanged(self):
        self.assertEqual(adapt_tool_arguments({"query": "x"}, None), ({"query": "x"}, []))

    def test_parse_jsonrpc_error(self):
        self.assertEqual(
            parse_jsonrpc_error({"jsonrpc": "2.0", "error": {"code": -32004, "message": "Tool not found"}}),
            {"code": -32004, "message": "Tool not found"},
        )
        self.assertIsNone(parse_jsonrpc_error({"jsonrpc": "2.0", "result": {}}))


class ChatToolLoopTests(unittest.TestCase):
    def test_tool_error_is_reported_and_follow_ons_offer_a_repair(self):
        llm = ScriptedLLM([
            _tool_call("search index=web status=500 | stats count by sourcetype"),
            "The search failed because Splunk could not find index=web, so I have no counts yet.",
        ])
        mcp = RecordingMCP(lambda _call: _tool_error_result("Search failed: index 'web' not found"))
        with chat_harness(llm, mcp) as run:
            result = run({"message": "Which sourcetypes in index=web returned HTTP 500 errors today?", "history": [], "chat_session_id": "loop_error"})

        self.assertEqual(len(mcp.calls), 1)
        self.assertEqual(result["tool_calls"][0]["summary"]["status"], "error")
        self.assertEqual(result["reasoning_chain"][0]["status"], "error")
        feedback = llm.calls[1][-1]
        self.assertEqual(feedback["role"], "user")
        self.assertIn("index 'web' not found", feedback["content"])
        self.assertIn("search index=web status=500", feedback["content"])
        kinds = [action["kind"] for action in result["follow_on_actions"]]
        self.assertIn("repair_failed_search", kinds)
        self.assertNotIn("broaden_time", kinds)

    def test_repeated_tool_call_is_not_executed_twice(self):
        repeated = _tool_call("| tstats count where index=main by sourcetype")
        llm = ScriptedLLM([repeated, repeated, "index=main has 12 events from syslog in the last 24 hours."])
        mcp = RecordingMCP(lambda _call: _rows_result([{"sourcetype": "syslog", "count": "12"}]))
        with chat_harness(llm, mcp) as run:
            result = run({"message": "Which sourcetypes are in index=main and how many events does each have?", "history": [], "chat_session_id": "loop_dedupe"})

        self.assertEqual(len(mcp.calls), 1)
        self.assertEqual(len(result["tool_calls"]), 1)
        self.assertIn("repeats the tool call", llm.calls[2][-1]["content"])
        self.assertIn("12 events", result["response"])

    def test_index_sweep_after_an_empty_result_is_redirected_to_one_search(self):
        llm = ScriptedLLM([
            _tool_call("index=netops sourcetype=homebridge:collector | stats count"),
            _tool_call("index=brickeconomy sourcetype=homebridge:collector | stats count"),
            _tool_call("| tstats count where (index=* OR index=_*) sourcetype=homebridge:collector by index"),
            "No homebridge:collector events arrived in any index in the last 24 hours.",
        ])

        def handler(call):
            query = call["params"]["arguments"]["query"]
            return _rows_result([{"index": "homebridge_for_splunk", "count": "0"}] if "tstats" in query else [])

        mcp = RecordingMCP(handler)
        with chat_harness(llm, mcp) as run:
            result = run({"message": "Is homebridge:collector still sending data?", "history": [], "chat_session_id": "loop_sweep"})

        queries = [call["params"]["arguments"]["query"] for call in mcp.calls]
        self.assertEqual(len(queries), 2)
        self.assertTrue(queries[1].startswith("| tstats"))
        self.assertIn("only the index changed", llm.calls[2][-1]["content"])
        self.assertIn("No homebridge:collector events", result["response"])

    def test_unscoped_search_runs_against_index_star_and_says_so(self):
        llm = ScriptedLLM([
            _tool_call("sourcetype=homebridge:collector | stats count"),
            "homebridge:collector sent 7 events in the last 24 hours.",
        ])
        mcp = RecordingMCP(lambda _call: _rows_result([{"count": "7"}]))
        with chat_harness(llm, mcp) as run:
            result = run({"message": "How many homebridge:collector events arrived today?", "history": [], "chat_session_id": "loop_scope"})

        self.assertEqual(mcp.calls[0]["params"]["arguments"]["query"], "index=* sourcetype=homebridge:collector | stats count")
        self.assertEqual(result["tool_calls"][0]["args"]["query"], "index=* sourcetype=homebridge:collector | stats count")
        self.assertIn("index=* was added", llm.calls[1][-1]["content"])

    def test_backticked_tool_call_json_is_executed(self):
        llm = ScriptedLLM([
            '`{"tool": "splunk_run_query", "args": {"query": "| tstats count where index=_internal by sourcetype", "earliest_time": "-1h", "latest_time": "now"}}`',
            "splunkd sent the most _internal events in the last hour (25,537).",
        ])
        mcp = RecordingMCP(lambda _call: _rows_result([{"sourcetype": "splunkd", "count": "25537"}]))
        with chat_harness(llm, mcp) as run:
            result = run({"message": "Which sourcetypes sent the most events to index=_internal in the last hour?", "history": [], "chat_session_id": "loop_backticks"})

        self.assertEqual(len(mcp.calls), 1)
        self.assertEqual(mcp.calls[0]["params"]["arguments"]["earliest_time"], "-1h")
        self.assertIn("25,537", result["response"])
        self.assertNotIn('"tool"', result["response"])
    def test_index_by_index_search_is_allowed_after_a_productive_result(self):
        llm = ScriptedLLM([
            _tool_call("index=main | stats count by sourcetype"),
            _tool_call("index=web | stats count by sourcetype"),
            "index=main has 12 syslog events and index=web has 12 syslog events.",
        ])
        mcp = RecordingMCP(lambda _call: _rows_result([{"sourcetype": "syslog", "count": "12"}]))
        with chat_harness(llm, mcp) as run:
            run({"message": "Compare sourcetype counts in index=main and index=web", "history": [], "chat_session_id": "loop_compare"})

        self.assertEqual(len(mcp.calls), 2)

    def test_fatal_mcp_error_stops_without_more_model_calls(self):
        llm = ScriptedLLM([_tool_call("search index=main | head 5")])
        mcp = RecordingMCP(lambda _call: {"error": "Unauthorized", "detail": "invalid token", "status_code": 401, "fatal": True})
        with chat_harness(llm, mcp) as run:
            result = run({"message": "Show me the five newest events in index=main with their hosts", "history": [], "chat_session_id": "loop_fatal"})

        self.assertEqual(len(llm.calls), 1)
        self.assertIn("Authentication failed", result["response"])
        self.assertEqual(result["stop_reason"], "fatal_error")

    def test_announced_search_without_tool_call_gets_one_nudge(self):
        llm = ScriptedLLM([
            "Let me run a search for that.",
            _tool_call("| tstats count as event_count where index=main"),
            "index=main received 42 events in the last 24 hours.",
        ])
        mcp = RecordingMCP(lambda _call: _rows_result([{"event_count": "42"}]))
        with chat_harness(llm, mcp) as run:
            result = run({"message": "Did index=main receive data in the last day, and roughly how much?", "history": [], "chat_session_id": "loop_nudge"})

        self.assertEqual(len(mcp.calls), 1)
        self.assertIn("did not include a TOOL_CALL", llm.calls[1][-1]["content"])
        self.assertIn("42 events", result["response"])

    def test_promise_after_a_tool_result_gets_one_nudge_inside_the_loop(self):
        llm = ScriptedLLM([
            _tool_call("| tstats count where index=* by index"),
            "Let me check the ping index next.",
            _tool_call("| tstats count where index=ping by host"),
            "index=ping has events from 3 hosts in the last 24 hours.",
        ])
        mcp = RecordingMCP(lambda _call: _rows_result([{"index": "ping", "count": "30"}]))
        with chat_harness(llm, mcp) as run:
            result = run({"message": "Is index=ping receiving data from its hosts today?", "history": [], "chat_session_id": "loop_inner_nudge"})

        self.assertEqual(len(mcp.calls), 2)
        self.assertIn("did not include a TOOL_CALL", llm.calls[2][-1]["content"])
        self.assertIn("3 hosts", result["response"])

    def test_repeated_promise_falls_back_to_a_final_answer_pass(self):
        llm = ScriptedLLM([
            _tool_call("| tstats count where index=main"),
            "Let me check that again.",
            "I will check the hosts too.",
            "index=main received 42 events in the last 24 hours.",
        ])
        mcp = RecordingMCP(lambda _call: _rows_result([{"count": "42"}]))
        with chat_harness(llm, mcp) as run:
            result = run({"message": "How many events reached index=main in the last day?", "history": [], "chat_session_id": "loop_final_pass"})

        self.assertEqual(len(mcp.calls), 1)
        self.assertEqual(len(llm.calls), 4)
        self.assertIn("42 events", result["response"])
        self.assertNotIn("Let me check", result["response"])

    def test_mission_is_saved_used_in_the_prompt_and_cleared_on_request(self):
        mission = "Find out why freezer sensor data stopped arriving"
        llm = ScriptedLLM([
            "tstats reads indexed fields from tsidx files, so it is much faster than a raw search.",
            "Use | tstats count where index=<name> by sourcetype to profile an index quickly.",
            "tstats supports prestats=t for chaining into timechart.",
        ])
        mcp = RecordingMCP(lambda _call: _rows_result([]))
        missions = []
        with chat_harness(llm, mcp) as run:
            # chat_memory is the live session object, so read the mission after each turn.
            first = run({"message": "Explain what the tstats command does in SPL.", "history": [], "chat_session_id": "mission_test", "mission": mission})
            missions.append(first["chat_memory"]["mission"])
            second = run({"message": "How would I use tstats to profile an index in SPL?", "history": [], "chat_session_id": "mission_test"})
            missions.append(second["chat_memory"]["mission"])
            third = run({"message": "What does prestats do for tstats in SPL?", "history": [], "chat_session_id": "mission_test", "mission": ""})
            missions.append(third["chat_memory"]["mission"])

        self.assertEqual(missions, [mission, mission, ""])
        self.assertIn(mission, _system_text(llm.calls[0]))
        self.assertIn(mission, _system_text(llm.calls[1]))
        self.assertIn("advance_mission", [action["kind"] for action in first["follow_on_actions"]])
        self.assertNotIn(mission, _system_text(llm.calls[2]))
        self.assertEqual(mcp.calls, [])


class FollowOnActionTests(unittest.TestCase):
    def _memory(self, **last_result):
        base = {"index": "main", "row_count": 0, "earliest_time": "-24h", "latest_time": "now"}
        base.update(last_result)
        return {"entities": {"indexes": ["main"], "hosts": [], "sourcetypes": [], "sources": []}, "last_result": base}

    def test_failed_search_suggests_repair_not_broadening(self):
        calls = [{
            "tool": "splunk_run_query",
            "args": {"query": "search index=main | stats count by user"},
            "summary": {"status": "error", "message": "Error in 'stats' command", "row_count": 0},
        }]
        actions = web_app.build_follow_on_actions("count by user", self._memory(), calls)
        kinds = [action["kind"] for action in actions]
        self.assertEqual(kinds[0], "repair_failed_search")
        self.assertIn("Error in 'stats' command", actions[0]["prompt"])
        self.assertIn("search index=main | stats count by user", actions[0]["prompt"])
        self.assertIn("list_indexes", kinds)
        self.assertNotIn("broaden_time", kinds)
        self.assertEqual(web_app.detect_basic_inventory_intent(actions[kinds.index("list_indexes")]["prompt"]), "list_indexes")

    def test_zero_counts_broaden_to_a_wider_window_than_the_last_search(self):
        calls = [{
            "tool": "splunk_run_query",
            "args": {"query": "| tstats count as event_count where index=main", "earliest_time": "-7d"},
            "summary": {"status": "data", "row_count": 1, "zero_counts": True, "actual_results": [{"event_count": "0"}]},
        }]
        actions = web_app.build_follow_on_actions("any data?", self._memory(earliest_time="-7d", row_count=1), calls)
        broaden = next(action for action in actions if action["kind"] == "broaden_time")
        self.assertIn("last 30 days", broaden["prompt"])

    def test_mission_adds_a_next_step_action(self):
        memory = self._memory(row_count=5)
        memory["mission"] = "Reduce noisy firewall alerts"
        calls = [{
            "tool": "splunk_run_query",
            "args": {"query": "search index=main | stats count by host"},
            "summary": {"status": "data", "row_count": 5, "query_shape": "aggregation", "top_dimensions": [{"field": "host", "values": ["fw1 (10)"]}]},
        }]
        actions = web_app.build_follow_on_actions("count by host", memory, calls)
        mission_action = next(action for action in actions if action["kind"] == "advance_mission")
        self.assertIn("Reduce noisy firewall alerts", mission_action["prompt"])

    def test_last_result_context_does_not_treat_src_as_host(self):
        context = web_app._extract_last_result_context([{
            "tool": "splunk_run_query",
            "args": {"query": "search index=fw | stats count by src"},
            "summary": {"row_count": 1, "actual_results": [{"src": "10.0.0.5", "count": "3"}]},
        }])
        self.assertEqual(context["index"], "fw")
        self.assertEqual(context["host"], "")

    def test_memory_signals_skip_bare_wildcards_and_read_quoted_values(self):
        self.assertEqual(web_app._extract_memory_signals("search index=* | stats count")["indexes"], [])
        signals = web_app._extract_memory_signals('search index="web" host="app-01" | head 5')
        self.assertEqual(signals["indexes"], ["web"])
        self.assertIn("app-01", signals["hosts"])


class DeterministicRoutingTests(unittest.TestCase):
    memory = {"entities": {"indexes": ["main"], "hosts": [], "sourcetypes": [], "sources": []}, "last_result": {"index": "main"}}

    def test_plain_route_requests_still_route(self):
        cases = {
            "Break down index=main by sourcetype and host for the last 24 hours.": "breakdown_index",
            "Show a timechart of event volume over the last 24 hours": "timechart_index_trend",
            "Give me a reusable SPL for top indexes by event count.": "top_indexes",
            "What indexes do I have?": "list_indexes",
            "how many events in index=main": "count_index_events",
            "When was host=router-01 last seen in Splunk?": "latest_host_heartbeat",
        }
        for message, expected in cases.items():
            self.assertEqual(web_app.detect_basic_inventory_intent(message, self.memory), expected, message)

    def test_requests_with_extra_qualifiers_go_to_the_model(self):
        for message in [
            "Break down errors in index=main by host",
            "Show a timechart for the top sourcetype in index=main over the last 24 hours.",
            "What indexes have firewall data?",
            "Explain the biggest spikes in index=main by sourcetype and host over the last 24 hours.",
        ]:
            self.assertIsNone(web_app.detect_basic_inventory_intent(message, self.memory), message)

    def test_failed_logins_by_host_uses_the_auth_route_not_an_index_breakdown(self):
        self.assertEqual(web_app.detect_basic_inventory_intent("Show failed logins by host", self.memory), "latest_auth_failures")

    def test_offline_detection_ignores_breakdown_and_download(self):
        self.assertIsNone(web_app.detect_last_offline_target("Give me a breakdown of 10.1.2.3 traffic"))
        self.assertIsNone(web_app.detect_last_offline_target("Did 10.1.2.3 download the update?"))
        self.assertEqual(web_app.detect_last_offline_target("When was 10.1.2.3 last down?"), "10.1.2.3")

    def test_host_extraction_needs_an_assignment_or_host_like_name(self):
        self.assertIsNone(web_app.extract_host_or_ip_from_message("list hosts"))
        self.assertIsNone(web_app.extract_host_or_ip_from_message("investigate host anomalies"))
        self.assertEqual(web_app.extract_host_or_ip_from_message("pivot on host=router-01."), "router-01")
        self.assertEqual(web_app.extract_host_or_ip_from_message("check host web-01 now"), "web-01")
        self.assertEqual(web_app.extract_host_or_ip_from_message("ping 192.168.1.20"), "192.168.1.20")

    def test_report_follow_on_validation_prompts_run_live(self):
        knowledge = {"viability": {"usable": True}, "recommendations": [{"title": "Platform Health Monitoring"}]}
        self.assertIsNone(web_app.detect_report_intent(
            "Validate this discovery recommendation with live Splunk data and summarize drift from the report snapshot: Platform Health Monitoring.",
            knowledge,
        ))
        self.assertEqual(web_app.detect_report_intent("What should I improve next?", knowledge), "recommendations")

    def test_query_plan_lists_discovery_facts_for_names_in_the_request_and_mission(self):
        ledger = [
            {"kind": "index", "title": "Analyzing index: homebridge", "findings": [], "data": {"name": "homebridge", "totalEventCount": "0", "currentDBSizeMB": "1"}},
            {"kind": "index", "title": "Analyzing index: homebridge_for_splunk", "findings": ["📊 Moderate index"],
             "data": {"name": "homebridge_for_splunk", "totalEventCount": "92850", "currentDBSizeMB": "129"}},
            {"kind": "sourcetype", "title": "Analyzing sourcetype: homebridge:collector",
             "findings": ["📊 Active source", "⚠️  Stale data: homebridge:collector - Last event 49 hours ago. Check data inputs"],
             "data": {"sourcetype": "homebridge:collector", "totalCount": "92850", "recentTime": "1794071424", "type": "sourcetypes"}},
            {"kind": "sourcetype", "title": "Analyzing sourcetype: brickeconomy:collector:log", "findings": [],
             "data": {"sourcetype": "brickeconomy:collector:log", "totalCount": "13023", "recentTime": "1794247020"}},
            {"kind": "host", "title": "Analyzing host: splunk.localdomain", "findings": [], "data": {"host": "splunk.localdomain", "totalCount": "5"}},
        ]
        bundle = {"blueprint": {"finding_ledger": ledger, "discovery_metrics": {"freshness": {
            "stale_indexes": ["homebridge_for_splunk"], "empty_indexes": ["homebridge"]}}}, "ai_summary": {}}
        knowledge = web_app._build_report_knowledge(bundle, {"timestamp": "20261109_131858", "status": "fresh"})
        memory = {"mission": "Keep the homebridge:collector feed healthy"}

        brief = web_app.build_query_plan_brief("Why is the data stale? Tell me what to fix.", knowledge, memory)
        self.assertIn("from the discovery run at 2026-11-09 13:18", brief)
        self.assertIn("sourcetype homebridge:collector: 92,850 events; last event 2026-11-07T17:10:24Z; Stale data", brief)
        self.assertIn("index homebridge_for_splunk: 92,850 events in total, 129 MB; no events in the 24h before discovery", brief)
        self.assertRegex(brief, r"Candidate indexes: .*homebridge_for_splunk")
        self.assertNotIn("brickeconomy", brief)

        bare = web_app.build_query_plan_brief("Why is homebridge data stale?", knowledge, {})
        self.assertIn("index homebridge: 0 events in total, 1 MB; no events at all", bare)
        self.assertIn("index homebridge_for_splunk", bare)
        self.assertNotIn("Discovery facts", web_app.build_query_plan_brief("Is Splunk health ok?", knowledge, {}))
    def test_query_plan_anchor_comes_from_the_report(self):
        knowledge = {
            "known_entities": {"indexes": ["_internal", "web"], "sourcetypes": [], "hosts": [], "sources": []},
            "recommendations": [{"title": "Platform Health Monitoring"}],
        }
        brief = web_app.build_query_plan_brief("Check Splunk health and ingestion issues", knowledge, memory={})
        self.assertIn("Likely domain: platform operations", brief)
        self.assertIn("related recommendation: Platform Health Monitoring", brief)
        self.assertIn("_internal", brief)

        network = web_app.build_query_plan_brief("Any network latency problems?", knowledge, memory={})
        self.assertIn("Likely domain: network operations", network)
        self.assertIn("No discovery report item matches", network)


class VerifyTaskTests(unittest.TestCase):
    def _run(self, mcp_result, llm):
        async def execute(_call, _config):
            return mcp_result

        config_stub = SimpleNamespace(get=lambda: SimpleNamespace(llm=SimpleNamespace(max_tokens=4000)))
        request = {
            "session_id": "20260101_120000",
            "task_index": 0,
            "verification_spl": "| tstats count where index=main",
            "expected_outcome": "index=main receives data",
        }
        previous_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(web_app, "execute_mcp_tool_call", execute), \
                patch.object(web_app, "get_or_create_llm_client", lambda _config: llm), \
                patch.object(web_app, "config_manager", config_stub):
            os.chdir(temp_dir)
            try:
                return asyncio.run(web_app.verify_task(request))
            finally:
                os.chdir(previous_cwd)

    def test_in_band_tool_error_is_not_graded(self):
        llm = ScriptedLLM([])
        result = self._run(_tool_error_result("Search failed: permission denied"), llm)
        self.assertEqual(result["status"], "error")
        self.assertIn("permission denied", result["message"])
        self.assertEqual(llm.calls, [])

    def test_verdict_uses_rows_and_is_normalized(self):
        llm = ScriptedLLM(['<think>checking</think>```json\n{"status": "SUCCESS", "message": "count is 42", "metrics": {}}\n```'])
        result = self._run(_rows_result([{"count": "42"}]), llm)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["row_count"], 1)
        self.assertIn('"count": "42"', llm.calls[0])


class DiscoveryReportingTests(unittest.TestCase):
    def test_data_volume_formatting_keeps_missing_values_explicit(self):
        self.assertEqual(web_app._format_data_volume(None), "Unavailable")
        self.assertEqual(web_app._format_data_volume("unknown"), "Unavailable")
        self.assertEqual(web_app._format_data_volume("2.50 GB"), "2.50 GB")
        self.assertEqual(web_app._format_data_volume(512), "512.0 MB")
        self.assertEqual(web_app._format_data_volume(2560.0), "2.50 GB")

    def test_discovery_quality_separates_failures_from_unsupported_steps(self):
        payload = {
            "readiness_score": 71,
            "score_basis": {"method": "evidence_weighted_v1", "explanation": "Surface coverage 50/60"},
            "discovery_step_status": {
                "indexes": {"status": "ok"},
                "knowledge_objects:macros": {"status": "error"},
                "knowledge_objects:eventtypes": {"status": "unsupported"},
            },
        }
        quality = web_app.build_discovery_quality(
            {"patterns": {"status": "ok"}, "recommendations": {"status": "failed"}},
            [{"stage": "Classification", "error": "boom"}],
            payload,
        )
        self.assertEqual(quality["status"], "partial")
        self.assertEqual(quality["failed_steps"], ["knowledge_objects:macros"])
        self.assertEqual(quality["unsupported_steps"], ["knowledge_objects:eventtypes"])
        self.assertEqual(quality["llm_degraded_stages"], ["recommendations"])
        self.assertEqual(quality["score_method"], "evidence_weighted_v1")

        clean = web_app.build_discovery_quality({"patterns": {"status": "failed"}}, [], {"discovery_step_status": {}})
        self.assertEqual(clean["status"], "deterministic_fallback")

    def test_persona_brief_uses_the_pipeline_score(self):
        overview = SimpleNamespace(total_indexes=40, total_sourcetypes=80, total_hosts=40)
        playbooks = web_app.build_persona_playbooks(overview, [], [], {"tool_count": 9}, readiness_score=42)
        self.assertEqual(playbooks["executive"]["platform_readiness_score"], 42)
        self.assertIn("significant gaps", playbooks["executive"]["headline"])

    def test_chat_memory_writes_are_atomic(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(web_app, "_get_memory_store_path", lambda session_id: Path(temp_dir) / f"{session_id}.json"), \
                patch.dict(web_app.chat_agent_memory, {}, clear=True):
            memory = web_app.load_chat_memory("atomic-test")
            memory["mission"] = "Track failed logins"
            web_app.save_chat_memory("atomic-test", memory)
            files = sorted(os.listdir(temp_dir))
            self.assertEqual(files, ["atomic-test.json"])
            with open(Path(temp_dir) / "atomic-test.json", encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["mission"], "Track failed logins")

    def test_report_knowledge_is_reused_until_a_report_changes(self):
        calls = []

        def fake_uncached(output_dir, staleness_days, report_files):
            calls.append(len(report_files))
            return {"files": len(report_files)}

        previous_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir, \
                patch.object(web_app, "_load_latest_report_knowledge_uncached", fake_uncached), \
                patch.dict(web_app._report_knowledge_cache, {"key": None, "expires_at": 0.0, "value": None}):
            os.chdir(temp_dir)
            try:
                output = Path("output")
                output.mkdir()
                (output / "v2_insights_brief_20260101_000000.md").write_text("one", encoding="utf-8")
                first = web_app.load_latest_report_knowledge(7)
                first["files"] = 99
                second = web_app.load_latest_report_knowledge(7)
                (output / "v2_insights_brief_20260102_000000.md").write_text("two", encoding="utf-8")
                third = web_app.load_latest_report_knowledge(7)
            finally:
                os.chdir(previous_cwd)
        self.assertEqual(calls, [1, 2])
        self.assertEqual(second, {"files": 1})
        self.assertEqual(third, {"files": 2})


if __name__ == "__main__":
    unittest.main()
