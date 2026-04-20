import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


from llm.factory import filter_openai_generation_models, get_openai_model_capabilities
from capabilities.models import CapabilityActionResult
from discovery.context_manager import DiscoveryContextManager
import web_app


class OpenAIModelHelperTests(unittest.TestCase):
    def test_filter_openai_generation_models_excludes_non_chat_models(self):
        models = [
            "gpt-4o-mini",
            "o4-mini",
            "gpt-5-mini",
            "text-embedding-3-large",
            "whisper-1",
            "gpt-4o-realtime-preview",
            "dall-e-3",
        ]

        filtered = filter_openai_generation_models(models)

        self.assertIn("gpt-4o-mini", filtered)
        self.assertIn("o4-mini", filtered)
        self.assertIn("gpt-5-mini", filtered)
        self.assertNotIn("text-embedding-3-large", filtered)
        self.assertNotIn("whisper-1", filtered)
        self.assertNotIn("gpt-4o-realtime-preview", filtered)
        self.assertNotIn("dall-e-3", filtered)

    def test_reasoning_model_capabilities_prefer_responses(self):
        capabilities = get_openai_model_capabilities("o4-mini")

        self.assertTrue(capabilities["supports_generation"])
        self.assertTrue(capabilities["prefers_responses_api"])
        self.assertFalse(capabilities["supports_temperature"])
        self.assertIn("max_completion_tokens", capabilities["chat_token_keys"])


class ChatHelperTests(unittest.TestCase):
    def test_extract_primary_spl_query_prefers_last_non_empty_query(self):
        tool_calls = [
            {
                "tool": "splunk_get_indexes",
                "spl_query": None,
            },
            {
                "tool": "splunk_run_query",
                "args": {"query": "search index=main | stats count"},
            },
            {
                "tool": "splunk_run_query",
                "spl_query": "search index=_internal | head 5",
            },
        ]

        self.assertEqual(
            web_app.extract_primary_spl_query(tool_calls),
            "search index=_internal | head 5",
        )

    def test_build_follow_on_actions_returns_clickable_prompts(self):
        memory = {
            "entities": {
                "indexes": ["main"],
                "hosts": ["router-01"],
                "sourcetypes": [],
                "sources": [],
            },
            "last_result": {
                "index": "main",
                "host": "router-01",
                "row_count": 12,
                "earliest_time": "-24h",
                "latest_time": "now",
            },
        }
        tool_calls = [
            {
                "tool": "splunk_run_query",
                "args": {"query": "search index=main host=router-01 | head 10"},
                "summary": {"row_count": 12},
            }
        ]

        actions = web_app.build_follow_on_actions("Show me recent events", memory, tool_calls)

        self.assertGreaterEqual(len(actions), 2)
        self.assertTrue(all(isinstance(action, dict) for action in actions))
        self.assertTrue(any(action.get("kind") == "surrounding_events_host" for action in actions))
        self.assertTrue(any("index=main" in action.get("prompt", "") for action in actions))

    def test_detect_basic_inventory_intent_uses_memory_anchor_for_follow_ons(self):
        memory = {
            "entities": {
                "indexes": ["main"],
                "hosts": ["router-01"],
                "sourcetypes": [],
                "sources": [],
            },
            "last_result": {
                "index": "main",
                "host": "router-01",
                "row_count": 7,
                "earliest_time": "-24h",
                "latest_time": "now",
            },
        }

        intent = web_app.detect_basic_inventory_intent(
            "Show a timechart of event volume over the last 24 hours",
            memory,
        )

        self.assertEqual(intent, "timechart_index_trend")

    def test_extract_recoverable_tool_call_recovers_malformed_tagged_payload(self):
        response_text = (
            '<TOOL_CALL>{"tool": "splunk_run_query", "args": {"query": '
            '"search index=main user="admin" | stats count", '
            '"earliest_time": "-24h", "latest_time": "now"}}</TOOL_CALL>'
        )

        recovered = web_app.extract_recoverable_tool_call(response_text, "splunk_run_query")

        self.assertIsNotNone(recovered)
        self.assertEqual(recovered["params"]["name"], "splunk_run_query")
        self.assertIn('user="admin"', recovered["params"]["arguments"]["query"])
        self.assertEqual(recovered["params"]["arguments"]["earliest_time"], "-24h")
        self.assertEqual(recovered["params"]["arguments"]["latest_time"], "now")

    def test_detect_report_intent_handles_strategic_questions_only(self):
        report_knowledge = {
            "viability": {"usable": True},
            "known_entities": {
                "indexes": ["_internal", "_audit", "wmata"],
                "sourcetypes": ["WinEventLog:Security"],
                "hosts": [],
                "sources": [],
            },
            "recommendations": [
                {"title": "Platform Health and Splunk Operational Monitoring", "priority": "high"}
            ],
            "coverage_gaps": [
                {"gap": "Platform Health and Splunk Operational Monitoring", "priority": "high"}
            ],
            "risk_register": [],
            "suggested_use_cases": [],
        }

        strategic_intent = web_app.detect_report_intent(
            "What should I improve in this Splunk environment next?",
            report_knowledge,
        )
        live_intent = web_app.detect_report_intent(
            "Show a timechart for index=main over the last 24 hours",
            report_knowledge,
        )

        self.assertEqual(strategic_intent, "recommendations")
        self.assertIsNone(live_intent)

    def test_build_query_plan_brief_uses_report_domain_anchors(self):
        report_knowledge = {
            "known_entities": {
                "indexes": ["_internal", "_audit", "_introspection", "wmata"],
                "sourcetypes": ["WinEventLog:Security", "wmata:api"],
                "hosts": [],
                "sources": [],
            }
        }

        brief = web_app.build_query_plan_brief(
            "Check Splunk health and ingestion issues",
            report_knowledge,
            memory={},
        )

        self.assertIn("Likely domain: platform operations", brief)
        self.assertIn("_internal", brief)
        self.assertIn("_audit", brief)

    def test_build_follow_on_actions_prefers_platform_focus_actions(self):
        memory = {
            "primary_intent": "platform operations",
            "current_focus": "platform_health",
            "entities": {
                "indexes": ["_internal", "_audit"],
                "hosts": [],
                "sourcetypes": [],
                "sources": [],
            },
            "last_result": {
                "index": "_internal",
                "row_count": 14,
                "earliest_time": "-24h",
                "latest_time": "now",
            },
        }

        actions = web_app.build_follow_on_actions("What should I check next for platform health?", memory, tool_calls=[])

        self.assertTrue(any(action.get("kind") == "validate_platform_health" for action in actions))
        self.assertTrue(any("_internal" in action.get("prompt", "") or "platform health" in action.get("prompt", "").lower() for action in actions))

    def test_build_follow_on_actions_uses_immediate_time_series_output(self):
        memory = {
            "entities": {
                "indexes": ["main"],
                "hosts": ["router-01"],
                "sourcetypes": [],
                "sources": [],
            },
            "last_result": {
                "index": "main",
                "host": "router-01",
                "row_count": 24,
                "earliest_time": "-24h",
                "latest_time": "now",
            },
        }
        tool_calls = [
            {
                "tool": "splunk_run_query",
                "args": {"query": "search index=main host=router-01 | timechart span=1h count"},
                "summary": {
                    "row_count": 24,
                    "query_shape": "time_series",
                    "sample_fields": ["_time", "count"],
                    "time_bounds": {
                        "field": "_time",
                        "first": "2026-04-19 00:00:00",
                        "last": "2026-04-19 23:00:00",
                    },
                    "findings": ["24 results returned", "Result shape: time_series"],
                    "next_pivots": ["Compare adjacent time buckets for spikes or drops"],
                },
            }
        ]

        actions = web_app.build_follow_on_actions("What should I look at next?", memory, tool_calls)
        action_kinds = {action.get("kind") for action in actions}

        self.assertIn("explain_trend_change", action_kinds)
        self.assertIn("compare_previous_window", action_kinds)
        self.assertNotIn("timechart_index", action_kinds)

    def test_build_follow_on_actions_uses_top_dimension_from_latest_output(self):
        memory = {
            "entities": {
                "indexes": ["main"],
                "hosts": [],
                "sourcetypes": [],
                "sources": [],
            },
            "last_result": {
                "index": "main",
                "row_count": 18,
                "earliest_time": "-24h",
                "latest_time": "now",
            },
        }
        tool_calls = [
            {
                "tool": "splunk_run_query",
                "args": {"query": "search index=main | stats count by sourcetype"},
                "summary": {
                    "row_count": 18,
                    "query_shape": "aggregation",
                    "sample_fields": ["sourcetype", "count"],
                    "top_dimensions": [
                        {
                            "field": "sourcetype",
                            "distinct_count": 3,
                            "values": ["WinEventLog:Security (9)", "syslog (6)", "metrics (3)"],
                        }
                    ],
                    "findings": ["18 results returned", "Top sourcetype: WinEventLog:Security (9)"],
                },
            }
        ]

        actions = web_app.build_follow_on_actions("What should I check next?", memory, tool_calls)

        self.assertTrue(any(action.get("kind") == "filter_dimension_value" for action in actions))
        self.assertTrue(any("sourcetype=WinEventLog:Security" in action.get("prompt", "") for action in actions))

    def test_update_chat_memory_tracks_focus_and_recent_turns(self):
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"

            try:
                memory = web_app.update_chat_memory(
                    "focus_test_session",
                    "Check platform health in _internal for ingestion issues",
                )
                memory = web_app.update_chat_memory(
                    "focus_test_session",
                    "Check platform health in _internal for ingestion issues",
                    assistant_response="Platform health in _internal shows ingestion failures and queue pressure.",
                    record_user_turn=False,
                )
            finally:
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertEqual(memory.get("current_focus"), "platform_health")
        self.assertEqual([turn.get("role") for turn in memory.get("recent_turns", [])], ["user", "assistant"])
        self.assertIn("ingestion failures", memory.get("last_assistant_response", ""))

    def test_chat_with_splunk_logic_returns_capability_usage_for_optional_rag(self):
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_get_rag_context = web_app.capability_manager.get_rag_context
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        class StubLLMClient:
            async def generate_response(self, messages, max_tokens, temperature):
                return "Capability-backed context was used to answer this question."

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: StubLLMClient()
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.capability_manager.get_rag_context = lambda user_message, max_chunks=3: {
                "capability": "rag_local",
                "provider": "lightweight",
                "context_text": "Recovered queue pressure evidence from exported artifacts.",
                "chunks": [
                    {
                        "source": "output/v2_operator_runbook_20260417_144141.md",
                        "score": 5,
                        "snippet": "Queue pressure and ingestion delays were called out in the latest operator runbook.",
                    }
                ],
            }
            web_app.chat_session_settings["enable_rag_context"] = True
            web_app.chat_session_settings["enable_splunk_augmentation"] = False

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "What do the exported artifacts say about queue pressure?",
                            "history": [],
                            "chat_session_id": "capability_usage_test",
                        }
                    )
                )
            finally:
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.capability_manager.get_rag_context = original_get_rag_context
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertEqual(result.get("response"), "Capability-backed context was used to answer this question.")
        self.assertIn("capability_usage", result)
        self.assertEqual(len(result["capability_usage"]), 1)
        self.assertEqual(result["capability_usage"][0]["name"], "rag_local")
        self.assertEqual(result["capability_usage"][0]["used_in"], "llm_prompt")
        self.assertEqual(result["capability_usage"][0]["chunks"][0]["source"], "output/v2_operator_runbook_20260417_144141.md")

    def test_chat_with_splunk_logic_returns_top_level_spl_query_for_deterministic_route(self):
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_discover_mcp_tools = web_app.discover_mcp_tools
        original_execute_mcp_tool_call = web_app.execute_mcp_tool_call
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        async def stub_discover_mcp_tools(_config):
            return {"splunk_run_query"}

        async def stub_execute_mcp_tool_call(tool_call, _config):
            self.assertEqual(
                tool_call["params"]["arguments"]["query"],
                "search index=main | timechart span=1h count",
            )
            return {
                "result": {
                    "structuredContent": {
                        "results": [
                            {"_time": "2026-04-19 14:00:00.000 EDT", "count": "42"},
                        ]
                    }
                }
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.discover_mcp_tools = stub_discover_mcp_tools
            web_app.execute_mcp_tool_call = stub_execute_mcp_tool_call
            web_app.chat_session_settings["enable_splunk_augmentation"] = True

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "Show a timechart of event volume for index=main over the last 24 hours.",
                            "history": [],
                            "chat_session_id": "deterministic_spl_query_test",
                        }
                    )
                )
            finally:
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app.discover_mcp_tools = original_discover_mcp_tools
                web_app.execute_mcp_tool_call = original_execute_mcp_tool_call
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertEqual(result.get("spl_query"), "search index=main | timechart span=1h count")
        self.assertEqual(result.get("tool_calls", [])[0].get("spl_query"), "search index=main | timechart span=1h count")

    def test_chat_with_splunk_logic_returns_visualization_preview_for_deterministic_route(self):
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_discover_mcp_tools = web_app.discover_mcp_tools
        original_execute_mcp_tool_call = web_app.execute_mcp_tool_call
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        async def stub_discover_mcp_tools(_config):
            return {"splunk_run_query"}

        async def stub_execute_mcp_tool_call(_tool_call, _config):
            return {
                "result": {
                    "structuredContent": {
                        "results": [
                            {"_time": "2026-04-19 14:00:00.000 EDT", "count": "42"},
                            {"_time": "2026-04-19 15:00:00.000 EDT", "count": "57"},
                            {"_time": "2026-04-19 16:00:00.000 EDT", "count": "39"},
                        ]
                    }
                }
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.discover_mcp_tools = stub_discover_mcp_tools
            web_app.execute_mcp_tool_call = stub_execute_mcp_tool_call
            web_app.chat_session_settings["enable_splunk_augmentation"] = True

            with patch.object(web_app.capability_manager, "get_capability_state", return_value={
                "installed": True,
                "enabled": True,
                "restart_required": False,
                "health_status": "ready",
            }), patch.object(
                web_app.capability_manager,
                "build_visualization",
                return_value=CapabilityActionResult(
                    ok=True,
                    capability="visualization_tools",
                    action="build",
                    message="Visualization preview generated.",
                    details={
                        "visualization": {
                            "title": "Trend Preview",
                            "chart_type": "line",
                            "x_field": "_time",
                            "y_field": "count",
                            "point_count": 3,
                            "summary_text": "Generated a line preview from 3 points using _time and count.",
                            "points": [
                                {"label": "2026-04-19 14:00", "value": 42.0},
                                {"label": "2026-04-19 15:00", "value": 57.0},
                                {"label": "2026-04-19 16:00", "value": 39.0},
                            ],
                        }
                    },
                ),
            ):
                try:
                    result = asyncio.run(
                        web_app.chat_with_splunk_logic(
                            {
                                "message": "Show a timechart of event volume for index=main over the last 24 hours.",
                                "history": [],
                                "chat_session_id": "deterministic_visualization_test",
                            }
                        )
                    )
                finally:
                    web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                    web_app.discover_mcp_tools = original_discover_mcp_tools
                    web_app.execute_mcp_tool_call = original_execute_mcp_tool_call
                    web_app._get_memory_store_path = original_get_memory_store_path
                    web_app.chat_session_settings.clear()
                    web_app.chat_session_settings.update(original_chat_settings)
                    web_app.chat_agent_memory.clear()
                    web_app.chat_agent_memory.update(original_cache)

        self.assertIsInstance(result.get("visualization_spec"), dict)
        self.assertEqual(result["visualization_spec"].get("chart_type"), "line")
        self.assertTrue(any(
            isinstance(item, dict) and item.get("name") == "visualization_tools"
            for item in result.get("capability_usage", [])
        ))


class DiscoveryContextManagerTests(unittest.TestCase):
    def test_context_manager_reads_v2_blueprint_and_strategic_context(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            payload = {
                "overview": {
                    "total_indexes": 2,
                    "total_sourcetypes": 1,
                    "total_hosts": 1,
                    "total_sources": 1,
                    "total_users": 1,
                    "data_volume_24h": "~1GB",
                    "splunk_version": "10.0.1",
                    "license_state": "OK",
                },
                "readiness_score": 77,
                "finding_ledger": [
                    {
                        "title": "Analyzing index: _internal",
                        "data": {
                            "title": "_internal",
                            "totalEventCount": "123",
                            "currentDBSizeMB": "12",
                            "disabled": "0",
                        },
                    },
                    {
                        "title": "Analyzing sourcetype: WinEventLog:Security",
                        "data": {
                            "sourcetype": "WinEventLog:Security",
                            "totalCount": "55",
                        },
                    },
                    {
                        "title": "Analyzing host: splunk.localdomain",
                        "data": {
                            "host": "splunk.localdomain",
                            "totalCount": "44",
                        },
                    },
                ],
                "recommendations": [
                    {
                        "title": "Platform Health and Splunk Operational Monitoring",
                        "priority": "high",
                    }
                ],
                "risk_register": [
                    {
                        "risk": "Platform Health and Splunk Operational Monitoring",
                        "severity": "high",
                    }
                ],
                "coverage_gaps": [
                    {
                        "gap": "Platform Health and Splunk Operational Monitoring",
                        "priority": "high",
                    }
                ],
                "suggested_use_cases": [
                    {
                        "title": "Platform Health Dashboard",
                    }
                ],
            }
            blueprint_path = output_dir / "v2_intelligence_blueprint_20260419_101515.json"
            blueprint_path.write_text(json.dumps(payload), encoding="utf-8")

            manager = DiscoveryContextManager(output_dir=output_dir)
            metadata = manager.get_metadata()
            indexes = manager.get_specific_context("indexes")
            recommendations = manager.get_specific_context("recommendations")
            post_tool_context = manager.get_context_after_tool_call(
                tool_name="splunk_run_query",
                tool_args={"query": "search index=_internal | head 1"},
                tool_result={},
            )

            self.assertTrue(metadata["available"])
            self.assertEqual(metadata["format"], "v2")
            self.assertEqual(indexes[0]["name"], "_internal")
            self.assertEqual(recommendations[0]["title"], "Platform Health and Splunk Operational Monitoring")
            self.assertIn("Platform Health and Splunk Operational Monitoring", post_tool_context)


if __name__ == "__main__":
    unittest.main()