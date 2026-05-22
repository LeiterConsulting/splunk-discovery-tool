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


from llm.factory import CustomLLMClient, filter_openai_generation_models, get_openai_model_capabilities, is_openai_image_generation_model
from capabilities.models import CapabilityActionResult, CapabilityConfig
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

    def test_image_model_capabilities_report_image_generation(self):
        capabilities = get_openai_model_capabilities("gpt-image-2")

        self.assertFalse(capabilities["supports_generation"])
        self.assertTrue(capabilities["supports_image_generation"])
        self.assertTrue(is_openai_image_generation_model("gpt-image-2"))

    def test_build_openai_api_url_handles_full_chat_completion_endpoint(self):
        models_url = web_app.build_openai_api_url("https://api.openai.com/v1/chat/completions", "/models")
        images_url = web_app.build_openai_api_url("https://api.openai.com/v1/chat/completions", "/images/generations")

        self.assertEqual(models_url, "https://api.openai.com/v1/models")
        self.assertEqual(images_url, "https://api.openai.com/v1/images/generations")

    def test_openai_model_ids_include_detects_gpt_image_2_exactly(self):
        self.assertTrue(web_app.openai_model_ids_include(["gpt-4.1", "gpt-image-2"], "gpt-image-2"))
        self.assertFalse(web_app.openai_model_ids_include(["gpt-4.1", "gpt-image-2-preview"], "gpt-image-2"))

    def test_build_summary_infographic_prompt_includes_key_summary_content(self):
        summary_data = {
            "ai_summary": "Executive Summary\nThe environment is moderately ready.\n\nPriority Actions\n- Stabilize ingestion.\n\nQuick Wins\n- Monitor _audit.",
            "readiness_score": 72,
            "risk_register": [
                {"severity": "high", "domain": "security", "risk": "Authentication gaps", "impact": "Reduced visibility"}
            ],
            "admin_tasks": [
                {"priority": "HIGH", "category": "Security", "title": "Create authentication dashboard", "impact": "Faster investigations"}
            ],
        }

        prompt = web_app.build_summary_infographic_prompt("20260422_075552", summary_data)

        self.assertIn("Session ID: 20260422_075552", prompt)
        self.assertIn("Authentication gaps", prompt)
        self.assertIn("Create authentication dashboard", prompt)
        self.assertIn("The environment is moderately ready.", prompt)

    def test_build_summary_infographic_prompt_caps_total_length(self):
        summary_data = {
            "ai_summary": "Executive Summary\n" + ("Large summary section. " * 5000),
            "readiness_score": 80,
            "risk_register": [
                {"severity": "high", "domain": "ops", "risk": "Telemetry gaps", "impact": "Reduced response quality"}
                for _ in range(20)
            ],
            "admin_tasks": [
                {"priority": "HIGH", "category": "Operations", "title": f"Task {idx}", "impact": "Improve visibility"}
                for idx in range(20)
            ],
            "coverage_gaps": [
                {"priority": "medium", "domain": "ops", "gap": f"Gap {idx}", "impact": "Coverage reduction"}
                for idx in range(20)
            ],
            "spl_queries": [
                {"title": f"Query {idx}", "category": "ops", "spl": "index=_internal | head 10"}
                for idx in range(20)
            ],
        }

        prompt = web_app.build_summary_infographic_prompt("20260422_075552", summary_data)

        self.assertLessEqual(len(prompt), web_app.MAX_INFOGRAPHIC_SUMMARY_CHARS)

    def test_extract_session_timestamp_from_artifact_name_rejects_debug_probe_infographics(self):
        self.assertEqual(
            web_app._extract_session_timestamp_from_artifact_name(
                "summary_infographic_20260422_075552_20260422_141453.png"
            ),
            "20260422_075552",
        )
        self.assertIsNone(
            web_app._extract_session_timestamp_from_artifact_name(
                "summary_infographic_debug_probe_20260422_140526.png"
            )
        )

    def test_build_context_explorer_payload_includes_formalized_actions(self):
        discovery_data = {
            "overview": {
                "total_indexes": 1,
                "total_sourcetypes": 1,
                "total_hosts": 1,
                "data_volume_24h": "14.2 GB",
                "license_state": "healthy",
                "notable_patterns": [
                    {
                        "patterns": [
                            {
                                "title": "Authentication activity concentration",
                                "description": "Security events are concentrated into one index.",
                                "signal": "index coverage",
                            }
                        ]
                    }
                ],
            },
            "finding_ledger": [
                {
                    "title": "Index inventory",
                    "data": {
                        "title": "main",
                        "totalEventCount": 1240,
                        "currentDBSizeMB": 84.2,
                        "datatype": "event",
                        "maxTime": "2026-05-01T12:30:00Z",
                    },
                },
                {
                    "title": "Sourcetype inventory",
                    "data": {
                        "type": "sourcetypes",
                        "title": "WinEventLog:Security",
                        "totalCount": 880,
                    },
                },
                {
                    "title": "Analyzing host: splunk-sh-1",
                    "data": {
                        "title": "splunk-sh-1",
                        "eventCount": 610,
                    },
                }
            ],
        }
        unknown_questions = [
            {
                "type": "index",
                "name": "mystery_index",
                "question": "What kind of data lands in this index?",
                "context": {
                    "volume_category": "high",
                    "has_significant_data": True,
                },
                "suggestions": [
                    {"label": "Security"},
                    {"label": "Authentication"},
                ],
            }
        ]
        coverage_gaps = [
            {
                "priority": "HIGH",
                "domain": "Security",
                "gap": "Authentication dashboards are missing",
                "why_it_matters": "Operators cannot validate authentication trends quickly.",
                "recommended_next_step": "Build an authentication validation dashboard.",
            }
        ]
        risk_register = [
            {
                "severity": "high",
                "domain": "Security",
                "risk": "Authentication gaps",
                "impact": "Reduced visibility into privileged activity.",
                "mitigation": "Create validation dashboards and review saved searches.",
            }
        ]
        admin_tasks = [
            {
                "title": "Create authentication validation dashboard",
                "priority": "HIGH",
                "category": "Security",
                "finding_reference": "Authentication gaps",
                "environment_evidence": ["index=main", "sourcetype=WinEventLog:Security"],
            }
        ]

        payload = web_app.build_context_explorer_payload(
            discovery_data,
            unknown_questions=unknown_questions,
            admin_tasks=admin_tasks,
            coverage_gaps=coverage_gaps,
            risk_register=risk_register,
            readiness_score=87,
            session_id="20260501_123456",
        )

        index_actions = payload["anchors"]["indexes"][0]["actions"]
        self.assertEqual([action["kind"] for action in index_actions], ["launch_chat", "focus_queries", "save_context_asset"])
        self.assertEqual(index_actions[0]["launchOptions"]["investigationMode"], "context_explorer")
        self.assertEqual(index_actions[1]["queryFocus"]["generatedQueries"][0]["query_source"], "context_engine")
        self.assertEqual(index_actions[2]["assetImport"]["source_label"], "Discovery Summary Context Explorer")
        self.assertIn("Session: 20260501_123456", index_actions[2]["assetImport"]["content"])

        unknown_actions = payload["lanes"]["unknown_entities"][0]["actions"]
        self.assertEqual(unknown_actions[0]["launchOptions"]["investigationMode"], "unknown_entity_context_builder")
        self.assertEqual(unknown_actions[1]["queryFocus"]["title"], "mystery_index Context Builder")
        self.assertEqual(unknown_actions[2]["assetImport"]["asset_type"], "reference_document")

        risk_actions = payload["lanes"]["risks"][0]["actions"]
        self.assertEqual(risk_actions[0]["taskFocus"]["taskFilter"], "category:Security")
        self.assertEqual(risk_actions[2]["assetImport"]["asset_type"], "runbook_context")

        task_actions = payload["lanes"]["priority_tasks"][0]["actions"]
        self.assertEqual(task_actions[0]["kind"], "focus_tasks")
        self.assertEqual(task_actions[1]["queryFocus"]["categories"], ["Security & Compliance"])
        self.assertEqual(task_actions[2]["kind"], "save_context_asset")

    def test_build_context_explorer_payload_recovers_truncated_notable_pattern_blob(self):
        discovery_data = {
            "overview": {
                "notable_patterns": [
                    '{"patterns": [{"category": "Data volume and distribution", "insight": "Large indexes dominate the environment.", "evidence": ["netops: 88M", "_internal: 84M"]}, {"category": "Temporal patterns", "insight": "Most active sources are near-real-time.", "evidence": ["recent data"]}'
                ],
            },
            "finding_ledger": [],
        }

        payload = web_app.build_context_explorer_payload(discovery_data)

        self.assertGreaterEqual(len(payload["patterns"]), 2)
        self.assertEqual(payload["patterns"][0]["title"], "Data volume and distribution")
        self.assertIn("Large indexes dominate the environment.", payload["patterns"][0]["description"])
        self.assertEqual(payload["patterns"][0]["signal"], "netops: 88M, _internal: 84M")

    def test_normalize_v2_notable_patterns_for_ui_recovers_truncated_blob(self):
        raw_patterns = [
            '{"patterns": [{"category": "Data volume and distribution", "insight": "Large indexes dominate the environment.", "evidence": ["netops: 88M", "_internal: 84M"]}, {"category": "Temporal patterns", "insight": "Most active sources are near-real-time.", "evidence": ["recent data"]}'
        ]

        normalized = web_app._normalize_v2_notable_patterns_for_ui(raw_patterns)

        self.assertGreaterEqual(len(normalized), 2)
        self.assertEqual(normalized[0]["title"], "Data volume and distribution")
        self.assertIn("Large indexes dominate the environment.", normalized[0]["description"])
        self.assertEqual(normalized[0]["signal"], "netops: 88M, _internal: 84M")
        self.assertEqual(normalized[0]["evidence"], ["netops: 88M", "_internal: 84M"])

    def test_normalize_v2_notable_patterns_for_ui_merges_duplicate_headlines(self):
        raw_patterns = [
            {
                "patterns": [
                    {
                        "category": "data_volume_and_distribution",
                        "insight": "Event volume is highly concentrated in a few large indexes.",
                        "evidence": ["_internal: 110M", "netops: 88M"],
                    },
                    {
                        "category": "data-volume-and-distribution",
                        "insight": "Storage usage is not perfectly proportional to event count.",
                        "evidence": ["wmata: 8175 MB / 45.4M events", "netops: 4099 MB / 88.5M events"],
                    },
                ]
            }
        ]

        normalized = web_app._normalize_v2_notable_patterns_for_ui(raw_patterns)

        self.assertEqual(len(normalized), 1)
        self.assertEqual(normalized[0]["title"], "data_volume_and_distribution")
        self.assertIn("_internal: 110M", normalized[0]["evidence"])
        self.assertIn("wmata: 8175 MB / 45.4M events", normalized[0]["evidence"])


class CustomLLMClientCompatibilityTests(unittest.TestCase):
    class _StubMetrics:
        def to_dict(self):
            return {}

    class _StubHealthMonitor:
        def should_attempt_request(self):
            return True

        def record_request(self, success, response_time, is_timeout):
            return None

        def get_metrics(self):
            return CustomLLMClientCompatibilityTests._StubMetrics()

    class _StubTimeoutManager:
        def calculate_timeout(self, estimated_tokens):
            return 30

    class _StubPayloadAdapter:
        def adapt_request(self, messages, max_tokens):
            return messages, max_tokens

    class _StubResponse:
        def __init__(self, payload, status_code=200):
            self._payload = payload
            self.status_code = status_code
            self.text = json.dumps(payload)

        def json(self):
            return self._payload

    class _StubSession:
        def __init__(self, response):
            self.response = response
            self.calls = []

        def post(self, url, headers=None, json=None, timeout=None):
            self.calls.append({
                "url": url,
                "headers": headers,
                "json": json,
                "timeout": timeout,
            })
            return self.response

    class _SequenceStubSession:
        def __init__(self, responses):
            self.responses = list(responses)
            self.calls = []

        def post(self, url, headers=None, json=None, timeout=None):
            self.calls.append({
                "url": url,
                "headers": headers,
                "json": json,
                "timeout": timeout,
            })
            index = min(len(self.calls) - 1, len(self.responses) - 1)
            return self.responses[index]

    def _build_client(self, endpoint_url, response_payload):
        client = CustomLLMClient(endpoint_url, model="llama3", provider="custom")
        client.health_monitor = self._StubHealthMonitor()
        client.timeout_manager = self._StubTimeoutManager()
        client.payload_adapter = self._StubPayloadAdapter()
        client.session = self._StubSession(self._StubResponse(response_payload))
        client.use_session = True
        return client

    def test_ollama_base_url_includes_native_api_candidates(self):
        client = CustomLLMClient("http://localhost:11434", model="llama3", provider="custom")

        candidates = client._build_candidate_urls()

        self.assertEqual(candidates[0], "http://localhost:11434/v1/chat/completions")
        self.assertEqual(candidates[1], "http://localhost:11434/chat/completions")
        self.assertIn("http://localhost:11434/api/chat", candidates)
        self.assertIn("http://localhost:11434/api/generate", candidates)

    def test_generate_response_sync_extracts_ollama_chat_content(self):
        client = self._build_client(
            "http://localhost:11434/api/chat",
            {"message": {"content": "Ollama says hello."}},
        )

        response = client.generate_response_sync(
            [{"role": "user", "content": "Say hello."}],
            max_tokens=128,
            temperature=0.2,
        )

        self.assertEqual(response, "Ollama says hello.")
        self.assertEqual(client.session.calls[0]["url"], "http://localhost:11434/api/chat")
        self.assertEqual(client.session.calls[0]["json"]["messages"][0]["content"], "Say hello.")
        self.assertNotIn("prompt", client.session.calls[0]["json"])

    def test_generate_response_sync_normalizes_ollama_native_tool_calls(self):
        client = self._build_client(
            "http://localhost:11434/api/chat",
            {
                "message": {
                    "content": "",
                    "tool_calls": [
                        {
                            "function": {
                                "name": "tool:splunk_run_query",
                                "arguments": {
                                    "tool": "splunk_run_query",
                                    "args": {
                                        "query": "search index=_internal | head 5",
                                        "earliest_time": "-24h",
                                        "latest_time": "now",
                                    },
                                },
                            }
                        }
                    ],
                }
            },
        )

        response = client.generate_response_sync(
            [{"role": "user", "content": "Inspect _internal."}],
            max_tokens=128,
            temperature=0.2,
        )

        self.assertTrue(response.startswith("<TOOL_CALL>"))
        self.assertTrue(response.endswith("</TOOL_CALL>"))
        payload = json.loads(response[len("<TOOL_CALL>"):-len("</TOOL_CALL>")])
        self.assertEqual(payload["tool"], "splunk_run_query")
        self.assertEqual(payload["args"]["query"], "search index=_internal | head 5")
        self.assertEqual(payload["args"]["earliest_time"], "-24h")
        self.assertEqual(payload["args"]["latest_time"], "now")

    def test_generate_response_sync_normalizes_openai_style_tool_calls(self):
        client = self._build_client(
            "http://localhost:11434/v1/chat/completions",
            {
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "type": "function",
                                    "function": {
                                        "name": "tool.splunk_run_query",
                                        "arguments": json.dumps(
                                            {
                                                "tool": "splunk_run_query",
                                                "args": {
                                                    "query": "search index=_audit | head 3",
                                                    "earliest_time": "-24h",
                                                    "latest_time": "now",
                                                },
                                            }
                                        ),
                                    },
                                }
                            ],
                        }
                    }
                ]
            },
        )

        response = client.generate_response_sync(
            [{"role": "user", "content": "Inspect _audit."}],
            max_tokens=128,
            temperature=0.2,
        )

        self.assertTrue(response.startswith("<TOOL_CALL>"))
        self.assertTrue(response.endswith("</TOOL_CALL>"))
        payload = json.loads(response[len("<TOOL_CALL>"):-len("</TOOL_CALL>")])
        self.assertEqual(payload["tool"], "splunk_run_query")
        self.assertEqual(payload["args"]["query"], "search index=_audit | head 3")
        self.assertEqual(payload["args"]["earliest_time"], "-24h")
        self.assertEqual(payload["args"]["latest_time"], "now")

    def test_generate_response_sync_falls_back_after_recoverable_ollama_parse_error(self):
        client = CustomLLMClient("http://localhost:11434", model="llama3", provider="custom")
        client.health_monitor = self._StubHealthMonitor()
        client.timeout_manager = self._StubTimeoutManager()
        client.payload_adapter = self._StubPayloadAdapter()
        client.session = self._SequenceStubSession([
            self._StubResponse(
                {"error": {"message": "error parsing tool call: raw='{"}},
                status_code=500,
            ),
            self._StubResponse({"error": "not found"}, status_code=404),
            self._StubResponse({"error": "not found"}, status_code=404),
            self._StubResponse({"response": "Recovered via generate fallback."}),
        ])
        client.use_session = True

        response = client.generate_response_sync(
            [{"role": "user", "content": "Inspect platform health."}],
            max_tokens=128,
            temperature=0.2,
        )

        self.assertEqual(response, "Recovered via generate fallback.")
        self.assertEqual(client.session.calls[0]["url"], "http://localhost:11434/v1/chat/completions")
        self.assertEqual(client.session.calls[3]["url"], "http://localhost:11434/api/generate")
        self.assertEqual(client.endpoint_url, "http://localhost:11434/api/generate")

    def test_generate_response_sync_builds_ollama_generate_payload(self):
        client = self._build_client(
            "http://localhost:11434/api/generate",
            {"response": "Generated from Ollama."},
        )

        response = client.generate_response_sync(
            [{"role": "user", "content": "Summarize this."}],
            max_tokens=128,
            temperature=0.2,
        )

        self.assertEqual(response, "Generated from Ollama.")
        self.assertEqual(client.session.calls[0]["url"], "http://localhost:11434/api/generate")
        self.assertEqual(client.session.calls[0]["json"]["prompt"], "Summarize this.")
        self.assertNotIn("messages", client.session.calls[0]["json"])


class LLMSettingsTests(unittest.TestCase):
    def test_assess_max_tokens_skips_openai_image_models(self):
        stub_config = type(
            "StubConfig",
            (),
            {
                "llm": type(
                    "StubLLM",
                    (),
                    {
                        "provider": "openai",
                        "api_key": "sk-test",
                        "model": "gpt-4o-mini",
                        "endpoint_url": None,
                        "max_tokens": 16000,
                        "temperature": 0.7,
                    },
                )()
            },
        )()

        request_payload = {
            "llm": {
                "provider": "openai",
                "api_key": "sk-test",
                "model": "gpt-image-2",
            }
        }

        class StubRequest:
            def __init__(self, payload):
                self._payload = payload

            async def json(self):
                return self._payload

        with patch.object(web_app.config_manager, "get", return_value=stub_config), patch.object(
            web_app.LLMClientFactory,
            "create_client",
            side_effect=AssertionError("image models should not run text token assessment"),
        ):
            result = asyncio.run(web_app.assess_max_tokens(StubRequest(request_payload)))

        self.assertEqual(result["status"], "info")
        self.assertFalse(result["applicable"])
        self.assertIsNone(result["recommended_max_tokens"])
        self.assertIn("not required", result["message"])

    def test_test_llm_connection_skips_text_probe_for_openai_image_models(self):
        stub_config = type(
            "StubConfig",
            (),
            {
                "llm": type(
                    "StubLLM",
                    (),
                    {
                        "provider": "openai",
                        "api_key": "sk-test",
                        "model": "gpt-4o-mini",
                        "endpoint_url": None,
                        "max_tokens": 16000,
                        "temperature": 0.7,
                    },
                )()
            },
        )()

        request_payload = {
            "llm": {
                "provider": "openai",
                "api_key": "sk-test",
                "model": "gpt-image-2",
                "max_tokens": 16000,
                "temperature": 0.7,
            }
        }

        class StubRequest:
            def __init__(self, payload):
                self._payload = payload

            async def json(self):
                return self._payload

        class StubResponse:
            def __init__(self, payload):
                self._payload = payload

            def raise_for_status(self):
                return None

            def json(self):
                return self._payload

        class StubAsyncClient:
            def __init__(self, *args, **kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def get(self, url, headers=None):
                return StubResponse({"data": [{"id": "gpt-image-2"}, {"id": "gpt-4o-mini"}]})

        with patch.object(web_app.config_manager, "get", return_value=stub_config), patch.object(
            web_app.httpx,
            "AsyncClient",
            StubAsyncClient,
        ), patch.object(
            web_app.LLMClientFactory,
            "create_client",
            side_effect=AssertionError("image models should not run text connection probes"),
        ):
            result = asyncio.run(web_app.test_llm_connection(StubRequest(request_payload)))

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["tests"]["model"]["status"], "info")
        self.assertIn("Skipped text completion probe", result["tests"]["model"]["message"])
        self.assertEqual(result["tests"]["max_tokens"]["status"], "info")
        self.assertNotIn("max_tokens", result.get("recommended_config", {}))


class ChatSettingsTests(unittest.TestCase):
    def test_get_chat_settings_defaults_rag_context_when_optional_rag_is_enabled(self):
        original_chat_settings = dict(web_app.chat_session_settings)
        original_overrides = dict(web_app.chat_settings_explicit_overrides)

        web_app.chat_session_settings.clear()
        web_app.chat_session_settings.update(web_app.build_default_chat_settings())
        web_app.chat_session_settings["enable_rag_context"] = False
        web_app.chat_settings_explicit_overrides["enable_rag_context"] = False

        enabled_rag_capabilities = {
            "rag_chromadb": CapabilityConfig(name="rag_chromadb", installed=True, enabled=True),
        }
        actual_runtime_value = None

        try:
            with patch.object(web_app.config_manager, "list_capabilities", return_value=enabled_rag_capabilities):
                result = asyncio.run(web_app.get_chat_settings())
                actual_runtime_value = web_app.chat_session_settings["enable_rag_context"]
        finally:
            web_app.chat_session_settings.clear()
            web_app.chat_session_settings.update(original_chat_settings)
            web_app.chat_settings_explicit_overrides.clear()
            web_app.chat_settings_explicit_overrides.update(original_overrides)

        self.assertTrue(result["enable_rag_context"])
        self.assertTrue(actual_runtime_value)

    def test_get_chat_settings_preserves_manual_disable_for_current_session(self):
        original_chat_settings = dict(web_app.chat_session_settings)
        original_overrides = dict(web_app.chat_settings_explicit_overrides)

        web_app.chat_session_settings.clear()
        web_app.chat_session_settings.update(web_app.build_default_chat_settings())
        web_app.chat_session_settings["enable_rag_context"] = True
        web_app.chat_settings_explicit_overrides["enable_rag_context"] = False

        enabled_rag_capabilities = {
            "rag_chromadb": CapabilityConfig(name="rag_chromadb", installed=True, enabled=True),
        }
        override_after_update = None

        try:
            with patch.object(web_app.config_manager, "list_capabilities", return_value=enabled_rag_capabilities):
                asyncio.run(web_app.update_chat_settings({"enable_rag_context": False}))
                result = asyncio.run(web_app.get_chat_settings())
                override_after_update = web_app.chat_settings_explicit_overrides["enable_rag_context"]
        finally:
            web_app.chat_session_settings.clear()
            web_app.chat_session_settings.update(original_chat_settings)
            web_app.chat_settings_explicit_overrides.clear()
            web_app.chat_settings_explicit_overrides.update(original_overrides)

        self.assertFalse(result["enable_rag_context"])
        self.assertTrue(override_after_update)

    def test_reset_chat_settings_reapplies_optional_rag_default(self):
        original_chat_settings = dict(web_app.chat_session_settings)
        original_overrides = dict(web_app.chat_settings_explicit_overrides)

        web_app.chat_session_settings.clear()
        web_app.chat_session_settings.update(web_app.build_default_chat_settings())
        web_app.chat_session_settings["enable_rag_context"] = False
        web_app.chat_settings_explicit_overrides["enable_rag_context"] = True

        enabled_rag_capabilities = {
            "rag_chromadb": CapabilityConfig(name="rag_chromadb", installed=True, enabled=True),
        }
        override_after_reset = None

        try:
            with patch.object(web_app.config_manager, "list_capabilities", return_value=enabled_rag_capabilities):
                result = asyncio.run(web_app.reset_chat_settings())
                override_after_reset = web_app.chat_settings_explicit_overrides["enable_rag_context"]
        finally:
            web_app.chat_session_settings.clear()
            web_app.chat_session_settings.update(original_chat_settings)
            web_app.chat_settings_explicit_overrides.clear()
            web_app.chat_settings_explicit_overrides.update(original_overrides)

        self.assertTrue(result["settings"]["enable_rag_context"])
        self.assertFalse(override_after_reset)


class ChatHelperTests(unittest.TestCase):
    def test_finalize_user_facing_response_text_uses_fallback_after_sanitization(self):
        self.assertEqual(
            web_app.finalize_user_facing_response_text(
                "<CONTEXT_REQUEST>inventory</CONTEXT_REQUEST>",
                web_app.DEFAULT_DIRECT_CHAT_RESPONSE,
            ),
            web_app.DEFAULT_DIRECT_CHAT_RESPONSE,
        )

    def test_sanitize_llm_response_text_strips_reasoning_markup(self):
        self.assertEqual(
            web_app.sanitize_llm_response_text(
                "<think>internal reasoning</think>Visible answer<thinking>more hidden reasoning</thinking>"
            ),
            "Visible answer",
        )

    def test_build_chat_runtime_profile_detects_ollama_runtime(self):
        stub_config = type(
            "Config",
            (),
            {
                "llm": type(
                    "LLMSettingsStub",
                    (),
                    {
                        "provider": "custom",
                        "endpoint_url": "http://localhost:11434",
                        "model": "gpt-oss:20b",
                    },
                )(),
            },
        )()
        stub_client = type("LLMClientStub", (), {"provider_type": "ollama"})()
        original_chat_settings = dict(web_app.chat_session_settings)

        try:
            web_app.chat_session_settings["max_tokens"] = 16000
            web_app.chat_session_settings["context_history"] = 6

            profile = web_app.build_chat_runtime_profile(stub_config, stub_client)
        finally:
            web_app.chat_session_settings.clear()
            web_app.chat_session_settings.update(original_chat_settings)

        self.assertEqual(profile["provider"], "ollama")
        self.assertEqual(profile["context_history_limit"], 4)
        self.assertEqual(profile["initial_max_tokens"], 1200)
        self.assertEqual(profile["followup_max_tokens"], 1400)
        self.assertEqual(profile["final_max_tokens"], 1800)
        self.assertEqual(profile["retry_max_tokens"], 1200)
        self.assertAlmostEqual(profile["temperature_multiplier"], 0.9)
        self.assertIn("Do not emit <think>", profile["reasoning_guard"])

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

    def test_extract_spl_queries_from_text_returns_fenced_and_inline_queries(self):
        response_text = """
Here are two searches to keep handy.

```spl
search index=main sourcetype=syslog | stats count by host
```

Verification SPL: | tstats count where index=_internal by sourcetype
"""

        queries = web_app.extract_spl_queries_from_text(response_text)

        self.assertEqual(queries[0], "search index=main sourcetype=syslog | stats count by host")
        self.assertIn("| tstats count where index=_internal by sourcetype", queries)

    def test_extract_spl_queries_from_payload_walks_nested_report_shapes(self):
        payload = {
            "summary": "No query here.",
            "tasks": [
                {
                    "action": "Validate ingestion",
                    "verification_spl": "search index=_internal | stats count by component",
                },
                {
                    "steps": [
                        {
                            "spl": "| tstats count where index=main by host",
                        }
                    ]
                },
            ],
        }

        queries = web_app.extract_spl_queries_from_payload(payload)

        self.assertIn("search index=_internal | stats count by component", queries)
        self.assertIn("| tstats count where index=main by host", queries)

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

    def test_extract_index_from_message_ignores_trailing_punctuation_and_quoted_names(self):
        prompt = (
            "Build context for this unclear Splunk index and decide whether it is expected, important, and worth monitoring coverage. "
            "Use the exact entity anchor index=os. Do not substitute another index name. "
            "Name: os. Question: I'm not familiar with the 'os' index. Can you help me understand what data it contains? "
            "index=os | stats count by sourcetype host | sort - count"
        )

        self.assertEqual(web_app.extract_index_from_message(prompt), "os")

    def test_should_bypass_basic_inventory_intent_for_unknown_entity_context_builder(self):
        self.assertTrue(
            web_app.should_bypass_basic_inventory_intent({"investigation_mode": "unknown_entity_context_builder"})
        )
        self.assertFalse(web_app.should_bypass_basic_inventory_intent({"investigation_mode": "other"}))
        self.assertFalse(web_app.should_bypass_basic_inventory_intent({}))

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

    def test_execute_mcp_tool_call_remaps_unknown_query_tool_to_splunk_query(self):
        captured = {}

        async def stub_discover_mcp_tools(_config, force_refresh=False):
            return {"splunk_run_query"}

        class StubResponse:
            status_code = 200
            headers = {"content-type": "application/json"}
            text = '{"result":{"structuredContent":{"results":[{"count":"1"}]}}}'

            def json(self):
                return {"result": {"structuredContent": {"results": [{"count": "1"}]}}}

        class StubAsyncClient:
            def __init__(self, *args, **kwargs):
                return None

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def post(self, url, json=None, headers=None):
                captured["url"] = url
                captured["json"] = json
                captured["headers"] = headers
                return StubResponse()

        stub_config = type(
            "Config",
            (),
            {
                "mcp": type(
                    "MCPSettingsStub",
                    (),
                    {
                        "url": "https://splunk:8089/services/mcp",
                        "token": "test-token",
                        "verify_ssl": False,
                    },
                )(),
                "security": type("SecuritySettingsStub", (), {"ca_bundle_path": None})(),
            },
        )()

        tool_call = {
            "method": "tools/call",
            "params": {
                "name": "container.exec",
                "arguments": {
                    "query": "search index=_internal | head 5",
                    "earliest_time": "-24h",
                    "latest_time": "now",
                },
            },
        }

        with patch.object(web_app, "discover_mcp_tools", new=stub_discover_mcp_tools), patch.object(
            web_app.httpx,
            "AsyncClient",
            StubAsyncClient,
        ):
            result = asyncio.run(web_app.execute_mcp_tool_call(tool_call, stub_config))

        self.assertIn("result", result)
        self.assertEqual(captured["json"]["params"]["name"], "splunk_run_query")
        self.assertEqual(
            captured["json"]["params"]["arguments"]["query"],
            "search index=_internal | head 5",
        )

    def test_maybe_record_rag_spl_query_feedback_records_success(self):
        captured = {}

        def stub_record(name, query, status, feedback):
            captured["name"] = name
            captured["query"] = query
            captured["status"] = status
            captured["feedback"] = feedback
            return CapabilityActionResult(True, name, "record-feedback", "ok")

        with patch.object(web_app.capability_manager, "record_rag_spl_query_feedback", side_effect=stub_record):
            web_app.maybe_record_rag_spl_query_feedback(
                "splunk_run_query",
                {
                    "query": "search index=_internal | head 5",
                    "earliest_time": "-24h",
                    "latest_time": "now",
                },
                mcp_response={
                    "result": {
                        "structuredContent": {
                            "results": [
                                {"count": "1"},
                                {"count": "2"},
                            ]
                        }
                    }
                },
            )

        self.assertEqual(captured["name"], "rag_chromadb")
        self.assertEqual(captured["query"], "search index=_internal | head 5")
        self.assertEqual(captured["status"], "success")
        self.assertEqual(captured["feedback"]["row_count"], 2)
        self.assertEqual(captured["feedback"]["earliest_time"], "-24h")
        self.assertEqual(captured["feedback"]["latest_time"], "now")

    def test_build_capability_usage_from_rag_result_includes_reusable_queries(self):
        capability_usage = web_app.build_capability_usage_from_rag_result(
            {
                "capability": "rag_chromadb",
                "context_text": "context",
                "chunks": [
                    {
                        "source": "output/example.md",
                        "score": 88,
                        "snippet": "Matched queue guidance.",
                        "metadata": {"source_type": "knowledge_asset"},
                    }
                ],
                "reusable_spl_queries": [
                    {
                        "title": "Internal Sourcetype Counts",
                        "query": "search index=_internal | stats count by sourcetype",
                        "reuse_tier": "known_good",
                        "known_good": True,
                        "why_reuse": "Prefer adapting this known-good query before generating a new one.",
                        "environment_fit_status": "strong",
                        "validation_status": "known_good",
                        "success_count": 3,
                        "failure_count": 1,
                        "app": "search",
                        "earliest": "-24h",
                        "latest": "now",
                    }
                ],
            }
        )

        self.assertEqual(len(capability_usage), 1)
        self.assertEqual(capability_usage[0]["reusable_queries"][0]["reuse_tier"], "known_good")
        self.assertTrue(capability_usage[0]["reusable_queries"][0]["known_good"])
        self.assertEqual(capability_usage[0]["reusable_queries"][0]["environment_fit_status"], "strong")
        self.assertEqual(capability_usage[0]["reusable_queries"][0]["validation_status"], "known_good")
        self.assertEqual(capability_usage[0]["reusable_queries"][0]["success_count"], 3)
        self.assertEqual(capability_usage[0]["reusable_queries"][0]["failure_count"], 1)
        self.assertEqual(capability_usage[0]["reusable_queries"][0]["app"], "search")
        self.assertIn("reusable SPL candidate", capability_usage[0]["contribution"])

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

    def test_detect_report_intent_prefers_structured_risk_requests(self):
        report_knowledge = {
            "viability": {"usable": True},
            "known_entities": {
                "indexes": ["_internal", "_audit", "wmata"],
                "sourcetypes": ["WinEventLog:Security"],
                "hosts": [],
                "sources": [],
            },
            "recommendations": [],
            "coverage_gaps": [],
            "risk_register": [],
            "suggested_use_cases": [],
        }

        intent = web_app.detect_report_intent(
            "Help me investigate and mitigate this risk in Splunk:\n\nRisk: Splunk Platform Health and Capacity Monitoring\nImpact: Build dashboards and alerts for _internal, _introspection, _audit, license usage, indexing latency, queue backlogs, and search performance.\nMitigation: Investigate and remediate through targeted Splunk validation.",
            report_knowledge,
        )

        self.assertEqual(intent, "top_risks")

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

    def test_build_compact_chat_prompt_allows_broader_questions(self):
        prompt = web_app.build_compact_chat_prompt(
            query_tool_name="splunk_run_query",
            discovery_context="discovery",
            rag_context="",
            memory_context="memory",
            available_tools_text="- splunk_run_query",
            discovery_age_warning=None,
        )

        self.assertIn("You may answer broader questions directly", prompt)
        self.assertNotIn("do not act like a general-purpose AI assistant", prompt)

    def test_build_report_follow_on_actions_uses_top_risk_context(self):
        report_knowledge = {
            "recommendations": [
                {"title": "Platform Health and Splunk Operational Monitoring", "priority": "high"}
            ],
            "risk_register": [
                {
                    "risk": "Unmonitored ingestion failures in core platform telemetry",
                    "severity": "high",
                    "impact": "Critical ingestion failures can go undetected.",
                    "mitigation": "Validate _internal and _introspection coverage.",
                }
            ],
            "coverage_gaps": [],
            "suggested_use_cases": [],
        }

        actions = web_app.build_report_follow_on_actions("top_risks", report_knowledge)

        self.assertTrue(any(action.get("kind") == "investigate_top_risk" for action in actions))
        self.assertTrue(any(
            "Unmonitored ingestion failures" in action.get("prompt", "")
            for action in actions
        ))

    def test_build_report_follow_on_actions_matches_focused_risk(self):
        report_knowledge = {
            "recommendations": [],
            "risk_register": [
                {
                    "risk": "WMATA API Ingestion Health and Throughput Monitoring",
                    "severity": "high",
                    "impact": "Protect the data pipeline.",
                    "mitigation": "Validate wmata telemetry.",
                },
                {
                    "risk": "Splunk Platform Health and Capacity Monitoring",
                    "severity": "high",
                    "impact": "Protect platform telemetry and queue health.",
                    "mitigation": "Validate _internal and _introspection.",
                },
            ],
            "coverage_gaps": [],
            "suggested_use_cases": [],
        }

        actions = web_app.build_report_follow_on_actions(
            "top_risks",
            report_knowledge,
            focus_text="Risk: Splunk Platform Health and Capacity Monitoring",
        )

        self.assertTrue(any(
            "Splunk Platform Health and Capacity Monitoring" in action.get("prompt", "")
            for action in actions
        ))

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

    def test_chat_with_splunk_logic_cites_adapted_reusable_query_in_direct_response(self):
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_get_rag_context = web_app.capability_manager.get_rag_context
        original_list_rag_assets = web_app.capability_manager.list_rag_assets
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_extract_recoverable_tool_call = web_app.extract_recoverable_tool_call
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        class StubLLMClient:
            async def generate_response(self, messages, max_tokens, temperature):
                return (
                    "Use this adapted query to inspect internal sourcetype counts:\n\n"
                    "```spl\n"
                    "search index=_internal | stats count by sourcetype | head 20\n"
                    "```"
                )

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: StubLLMClient()
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.extract_recoverable_tool_call = lambda *args, **kwargs: None
            web_app.capability_manager.list_rag_assets = lambda name="rag_chromadb": type(
                "StubAssetListResult",
                (),
                {
                    "ok": True,
                    "details": {
                        "assets": [
                            {
                                "title": "Internal Sourcetype Counts",
                                "description": "Prefer adapting this baseline query before generating a new one.",
                                "attributes": {
                                    "spl_query": "search index=_internal | stats count by sourcetype",
                                    "spl_intelligence": {
                                        "environment_fit": {"status": "strong", "score": 88},
                                        "validation": {"status": "known_good", "success_count": 3, "failure_count": 1},
                                        "reuse": {"tier": "known_good", "known_good": True, "guidance": "Prefer adapting this baseline query before generating a new one."},
                                    },
                                },
                            }
                        ]
                    },
                },
            )()
            web_app.capability_manager.get_rag_context = lambda user_message, max_chunks=3: {
                "capability": "rag_local",
                "provider": "lightweight",
                "context_text": "Recovered known-good SPL guidance for internal sourcetype analysis.",
                "chunks": [
                    {
                        "source": "output/v2_operator_runbook_20260417_144141.md",
                        "score": 5,
                        "snippet": "Known-good internal sourcetype rollup query is available for reuse.",
                    }
                ],
                "reusable_spl_queries": [
                    {
                        "title": "Internal Sourcetype Counts",
                        "query": "search index=_internal | stats count by sourcetype",
                        "reuse_tier": "known_good",
                        "known_good": True,
                        "why_reuse": "Prefer adapting this baseline query before generating a new one.",
                        "environment_fit_status": "strong",
                        "validation_status": "known_good",
                        "success_count": 3,
                        "failure_count": 1,
                    }
                ],
            }
            web_app.chat_session_settings["enable_rag_context"] = True
            web_app.chat_session_settings["enable_splunk_augmentation"] = False

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "Give me a reusable SPL to inspect internal sourcetype counts.",
                            "history": [],
                            "chat_session_id": "reusable_query_citation_test",
                        }
                    )
                )
            finally:
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.capability_manager.get_rag_context = original_get_rag_context
                web_app.capability_manager.list_rag_assets = original_list_rag_assets
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.extract_recoverable_tool_call = original_extract_recoverable_tool_call
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertIn('Reusable SPL reference: adapted from "Internal Sourcetype Counts"', result.get("response", ""))
        self.assertIn("Use this adapted query to inspect internal sourcetype counts", result.get("response", ""))
        self.assertIn("known good", result.get("response", "").lower())
        self.assertEqual(result.get("iterations"), 0)

    def test_chat_with_splunk_logic_cites_saved_query_in_deterministic_basic_route(self):
        original_execute_mcp_tool_call = web_app.execute_mcp_tool_call
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_list_rag_assets = web_app.capability_manager.list_rag_assets
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        class StubAssetListResult:
            ok = True
            details = {
                "assets": [
                    {
                        "title": "Top Index Counts",
                        "description": "Saved reusable SPL query for direct Splunk launch and chat reuse.",
                        "attributes": {
                            "spl_query": "| tstats count where index=* by index | sort - count | head 25",
                            "spl_intelligence": {
                                "environment_fit": {"status": "unknown", "score": 50},
                                "validation": {"status": "unvalidated", "success_count": 0, "failure_count": 0},
                                "reuse": {"tier": "candidate", "score": 50, "guidance": "Reasonable starting point, but validate the fit before relying on it."},
                            },
                        },
                    }
                ]
            }

        class StubLLMClient:
            async def generate_response(self, messages, max_tokens, temperature):
                raise AssertionError("Deterministic basic route should not call the LLM")

        async def stub_execute_mcp_tool_call(tool_call, config):
            query = tool_call.get("params", {}).get("arguments", {}).get("query")
            return {
                "jsonrpc": "2.0",
                "id": None,
                "result": {
                    "content": [],
                    "structuredContent": {
                        "results": [
                            {"index": "main", "count": "10"},
                            {"index": "netops", "count": "5"},
                        ],
                        "truncated": False,
                        "total_rows": 2,
                    },
                },
                "_debug_query": query,
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: StubLLMClient()
            web_app.execute_mcp_tool_call = stub_execute_mcp_tool_call
            web_app.capability_manager.list_rag_assets = lambda name="rag_chromadb": StubAssetListResult()
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.chat_session_settings["enable_splunk_augmentation"] = True

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "Give me a reusable SPL for top indexes by event count.",
                            "history": [],
                            "chat_session_id": "deterministic_reusable_citation_test",
                        }
                    )
                )
            finally:
                web_app.execute_mcp_tool_call = original_execute_mcp_tool_call
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.capability_manager.list_rag_assets = original_list_rag_assets
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertIn('Reusable SPL reference: "Top Index Counts"', result.get("response", ""))
        self.assertIn("Top indexes by event count", result.get("response", ""))
        self.assertEqual(result.get("iterations"), 1)

    def test_chat_with_splunk_logic_falls_back_when_sanitized_direct_answer_is_empty(self):
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_get_context_manager = web_app.get_context_manager
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        class StubLLMClient:
            async def generate_response(self, messages, max_tokens, temperature):
                return "<CONTEXT_REQUEST>inventory</CONTEXT_REQUEST>"

        class StubContextManager:
            def get_specific_context(self, _context_type):
                return None

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: StubLLMClient()
            web_app.get_context_manager = lambda: StubContextManager()
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.chat_session_settings["enable_splunk_augmentation"] = False

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "Summarize the current state.",
                            "history": [],
                            "chat_session_id": "empty_direct_answer_fallback_test",
                        }
                    )
                )
            finally:
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.get_context_manager = original_get_context_manager
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertEqual(result.get("response"), web_app.DEFAULT_DIRECT_CHAT_RESPONSE)
        self.assertEqual(result.get("chat_memory", {}).get("last_assistant_response"), web_app.DEFAULT_DIRECT_CHAT_RESPONSE)
        self.assertEqual(result.get("conversation_history", [])[-1].get("content"), web_app.DEFAULT_DIRECT_CHAT_RESPONSE)

    def test_chat_stream_returns_fallback_when_sanitized_direct_answer_is_empty(self):
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_get_context_manager = web_app.get_context_manager
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        class StubLLMClient:
            async def generate_response(self, messages, max_tokens, temperature):
                return "<CONTEXT_REQUEST>inventory</CONTEXT_REQUEST>"

        class StubContextManager:
            def get_specific_context(self, _context_type):
                return None

        class StubHttpRequest:
            def __init__(self):
                self.state = type("State", (), {"auth_user": None})()

        async def collect_stream_body():
            response = await web_app.chat_with_splunk_stream(
                StubHttpRequest(),
                {
                    "message": "Summarize the current state.",
                    "history": [],
                    "chat_session_id": "empty_direct_answer_stream_fallback_test",
                }
            )
            chunks = []
            async for chunk in response.body_iterator:
                chunks.append(chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk)
            return "".join(chunks)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: StubLLMClient()
            web_app.get_context_manager = lambda: StubContextManager()
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.chat_session_settings["enable_splunk_augmentation"] = False

            try:
                sse_body = asyncio.run(collect_stream_body())
            finally:
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.get_context_manager = original_get_context_manager
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        payloads = [
            json.loads(line[6:])
            for line in sse_body.splitlines()
            if line.startswith("data: ")
        ]
        final_payload = next(payload for payload in payloads if payload.get("type") == "response")

        self.assertEqual(final_payload["data"].get("response"), web_app.DEFAULT_DIRECT_CHAT_RESPONSE)
        self.assertEqual(
            final_payload["data"].get("chat_memory", {}).get("last_assistant_response"),
            web_app.DEFAULT_DIRECT_CHAT_RESPONSE,
        )

    def test_chat_with_splunk_logic_allows_unrelated_general_requests(self):
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        class StubLLMClient:
            async def generate_response(self, messages, max_tokens, temperature):
                return "Here is a short poem about the ocean."

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: StubLLMClient()
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.chat_session_settings["enable_splunk_augmentation"] = False

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "Write me a short poem about the ocean.",
                            "history": [],
                            "chat_session_id": "off_topic_scope_test",
                        }
                    )
                )
            finally:
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

            self.assertEqual(result.get("response"), "Here is a short poem about the ocean.")

    def test_chat_with_splunk_logic_allows_basic_utility_requests(self):
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        class StubLLMClient:
            async def generate_response(self, messages, max_tokens, temperature):
                return "2 + 2 = 4."

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: StubLLMClient()
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.chat_session_settings["enable_splunk_augmentation"] = False

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "What is 2 + 2?",
                            "history": [],
                            "chat_session_id": "basic_utility_scope_test",
                        }
                    )
                )
            finally:
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertEqual(result.get("response"), "2 + 2 = 4.")
        self.assertNotIn("general-purpose AI resource", result.get("response", ""))

    def test_chat_with_splunk_logic_treats_natural_language_index_mentions_as_in_scope(self):
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        class StubLLMClient:
            async def generate_response(self, messages, max_tokens, temperature):
                return "I can help investigate that device in the esp32 index."

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: StubLLMClient()
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.chat_session_settings["enable_splunk_augmentation"] = False

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "the freezer is a device in the esp32 index",
                            "history": [],
                            "chat_session_id": "natural_language_index_scope_test",
                        }
                    )
                )
            finally:
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertEqual(result.get("response"), "I can help investigate that device in the esp32 index.")
        self.assertNotIn("general-purpose AI resource", result.get("response", ""))

    def test_chat_with_splunk_logic_injects_continuity_gate_for_contextual_follow_ups(self):
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)
        captured = {}

        class CapturingStubLLMClient:
            async def generate_response(self, messages, max_tokens, temperature):
                captured["messages"] = messages
                return "Use 30-day retention for the wmata sizing estimate."

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: CapturingStubLLMClient()
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.chat_session_settings["enable_splunk_augmentation"] = False
            web_app.chat_session_settings["context_history"] = 4

            session_id = "continuity_gate_follow_up_test"
            web_app.update_chat_memory(session_id, "What is the total disk size of index=wmata?")
            web_app.update_chat_memory(
                session_id,
                "What is the total disk size of index=wmata?",
                assistant_response="wmata is about 6.6 GB per day. I can estimate 30 day retention next.",
                record_user_turn=False,
            )

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "what about 30 day retention on that index?",
                            "history": [
                                {"role": "system", "content": "stale system prompt"},
                                {"role": "user", "content": "What is the total disk size of index=wmata?"},
                                {"role": "assistant", "content": "wmata is about 6.6 GB per day. I can estimate 30 day retention next."},
                            ],
                            "chat_session_id": session_id,
                        }
                    )
                )
            finally:
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertEqual(result.get("response"), "Use 30-day retention for the wmata sizing estimate.")
        self.assertIn("messages", captured)
        system_messages = [msg.get("content", "") for msg in captured["messages"] if msg.get("role") == "system"]
        self.assertTrue(any("SESSION CONTINUITY GATE:" in content for content in system_messages))
        self.assertTrue(any("Remembered indexes: wmata" in content for content in system_messages))
        self.assertTrue(any("Recent conversation:" in content for content in system_messages))
        self.assertFalse(any(content == "stale system prompt" for content in system_messages))
        self.assertEqual(captured["messages"][-1]["role"], "user")
        self.assertEqual(captured["messages"][-1]["content"], "what about 30 day retention on that index?")

    def test_chat_with_splunk_logic_allows_colloquial_entity_follow_up_from_memory(self):
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)
        captured = {}

        class CapturingStubLLMClient:
            async def generate_response(self, messages, max_tokens, temperature):
                captured["messages"] = messages
                return "The freezer is currently at -17.5 C in index=esp32."

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: CapturingStubLLMClient()
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.chat_session_settings["enable_splunk_augmentation"] = False
            web_app.chat_session_settings["context_history"] = 4

            session_id = "colloquial_follow_up_memory_test"
            web_app.update_chat_memory(session_id, "my freezer is a device in the esp32 index, what is the current status")
            web_app.update_chat_memory(
                session_id,
                "Show surrounding events for host=Freezer Temp Monitor in index=esp32 over the last 24 hours and highlight the most relevant patterns.",
                assistant_response="Current status for Freezer Temp Monitor in esp32 shows temperature -17.5 C and healthy sensor status.",
                record_user_turn=False,
            )

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "what's my freezer temp right now",
                            "history": [
                                {"type": "user", "content": "my freezer is a device in the esp32 index, what is the current status"},
                                {"type": "assistant", "content": "Current status for Freezer Temp Monitor in esp32 shows temperature -17.5 C and healthy sensor status."},
                            ],
                            "chat_session_id": session_id,
                        }
                    )
                )
            finally:
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertEqual(result.get("response"), "The freezer is currently at -17.5 C in index=esp32.")
        self.assertNotIn("general-purpose AI resource", result.get("response", ""))
        system_messages = [msg.get("content", "") for msg in captured.get("messages", []) if msg.get("role") == "system"]
        self.assertTrue(any("Remembered indexes: esp32" in content for content in system_messages))
        self.assertTrue(any("Current request to interpret in-session: what's my freezer temp right now" in content for content in system_messages))

    def test_chat_with_splunk_logic_uses_ollama_runtime_profile(self):
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_discover_mcp_tools = web_app.discover_mcp_tools
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)
        original_config_get = web_app.config_manager.get
        captured = {}

        class CapturingStubLLMClient:
            provider_type = "ollama"

            async def generate_response(self, messages, max_tokens, temperature):
                captured["messages"] = messages
                captured["max_tokens"] = max_tokens
                captured["temperature"] = temperature
                return "Ollama runtime profile applied."

        async def stub_discover_mcp_tools(_config):
            return {"splunk_run_query"}

        stub_config = type(
            "Config",
            (),
            {
                "llm": type(
                    "LLMSettingsStub",
                    (),
                    {
                        "provider": "custom",
                        "endpoint_url": "http://localhost:11434",
                        "model": "gpt-oss:20b",
                        "api_key": "",
                        "temperature": 0.7,
                    },
                )(),
            },
        )()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: CapturingStubLLMClient()
            web_app.config_manager.get = lambda: stub_config
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.discover_mcp_tools = stub_discover_mcp_tools
            web_app.chat_session_settings["enable_splunk_augmentation"] = False
            web_app.chat_session_settings["enable_rag_context"] = False
            web_app.chat_session_settings["context_history"] = 6
            web_app.chat_session_settings["max_tokens"] = 16000

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "Summarize the current platform state.",
                            "history": [
                                {"role": "system", "content": "stale system prompt"},
                                {"role": "user", "content": "Turn 1"},
                                {"role": "assistant", "content": "Turn 2"},
                                {"role": "user", "content": "Turn 3"},
                                {"role": "assistant", "content": "Turn 4"},
                                {"role": "user", "content": "Turn 5"},
                                {"role": "assistant", "content": "Turn 6"},
                            ],
                            "chat_session_id": "ollama_runtime_profile_test",
                        }
                    )
                )
            finally:
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.config_manager.get = original_config_get
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app.discover_mcp_tools = original_discover_mcp_tools
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertEqual(result.get("response"), "Ollama runtime profile applied.")
        self.assertEqual(captured.get("max_tokens"), 1200)
        self.assertAlmostEqual(captured.get("temperature"), 0.63)
        self.assertEqual(
            [msg.get("content") for msg in captured.get("messages", []) if msg.get("role") in {"user", "assistant"}],
            ["Turn 3", "Turn 4", "Turn 5", "Turn 6", "Summarize the current platform state."],
        )
        system_messages = [msg.get("content", "") for msg in captured.get("messages", []) if msg.get("role") == "system"]
        self.assertTrue(any("Do not emit <think>" in content for content in system_messages))

    def test_chat_with_splunk_logic_report_intent_returns_normalized_history_and_rag_usage(self):
        original_get_rag_context = web_app.capability_manager.get_rag_context
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        report_knowledge = {
            "viability": {"status": "usable", "score": 84, "age_days": 1, "usable": True},
            "overview": {"readiness_score": 84},
            "known_entities": {
                "indexes": ["_internal", "_audit"],
                "sourcetypes": [],
                "hosts": [],
                "sources": [],
            },
            "recommendations": [
                {
                    "title": "Platform Health and Splunk Operational Monitoring",
                    "priority": "high",
                    "description": "Improve platform telemetry coverage.",
                }
            ],
            "risk_register": [
                {
                    "risk": "Unmonitored ingestion failures in core platform telemetry",
                    "severity": "high",
                    "impact": "Critical ingestion failures can go undetected.",
                    "mitigation": "Validate _internal and _introspection coverage.",
                }
            ],
            "coverage_gaps": [
                {
                    "gap": "Platform Health and Splunk Operational Monitoring",
                    "priority": "high",
                    "why_it_matters": "Platform drift is hard to see without operational telemetry.",
                }
            ],
            "suggested_use_cases": [],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.load_latest_report_knowledge = lambda *_: report_knowledge
            web_app.capability_manager.get_rag_context = lambda user_message, max_chunks=3: {
                "capability": "rag_local",
                "provider": "lightweight",
                "context_text": "Recovered platform telemetry guidance from uploaded runbooks.",
                "chunks": [
                    {
                        "source": "output/v2_operator_runbook_20260417_144141.md",
                        "score": 9,
                        "snippet": "Validate _internal ingestion queues and scheduler failures first.",
                    }
                ],
            }
            web_app.chat_session_settings["enable_rag_context"] = True
            web_app.chat_session_settings["enable_splunk_augmentation"] = True

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "What are the biggest risks in this Splunk environment?",
                            "history": [
                                {"role": "system", "content": "stale system prompt"},
                                {"role": "user", "content": "Old unrelated question"},
                                {"role": "assistant", "content": "Old unrelated answer"},
                            ],
                            "chat_session_id": "report_intent_rag_test",
                        }
                    )
                )
            finally:
                web_app.capability_manager.get_rag_context = original_get_rag_context
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertIn("Indexed context signals:", result.get("response", ""))
        self.assertEqual(result.get("capability_usage", [])[0].get("name"), "rag_local")
        self.assertTrue(all(item.get("role") in {"user", "assistant"} for item in result.get("conversation_history", [])))
        self.assertEqual(result.get("conversation_history", [])[-2].get("content"), "What are the biggest risks in this Splunk environment?")
        self.assertTrue(any(
            action.get("kind") == "investigate_top_risk"
            for action in result.get("follow_on_actions", [])
        ))

    def test_chat_with_splunk_logic_structured_risk_prompt_stays_focused(self):
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)

        report_knowledge = {
            "viability": {"status": "viable", "score": 100, "age_days": 0, "usable": True},
            "overview": {"readiness_score": 74},
            "known_entities": {
                "indexes": ["_internal", "_audit", "wmata"],
                "sourcetypes": ["WinEventLog:Security", "wmata:api"],
                "hosts": [],
                "sources": [],
            },
            "recommendations": [
                {
                    "title": "Splunk Platform Health and Capacity Monitoring",
                    "priority": "high",
                    "description": "Build dashboards and alerts for _internal, _introspection, _audit, license usage, indexing latency, queue backlogs, and search performance.",
                }
            ],
            "risk_register": [
                {
                    "risk": "WMATA API Ingestion Health and Throughput Monitoring",
                    "severity": "high",
                    "domain": "Infrastructure / Data Pipeline",
                    "impact": "Protect the data pipeline.",
                    "mitigation": "Validate wmata telemetry.",
                },
                {
                    "risk": "Splunk Platform Health and Capacity Monitoring",
                    "severity": "high",
                    "domain": "Platform Operations",
                    "impact": "Build dashboards and alerts for _internal, _introspection, _audit, license usage, indexing latency, queue backlogs, and search performance.",
                    "mitigation": "Investigate and remediate through targeted Splunk validation.",
                },
            ],
            "coverage_gaps": [
                {
                    "gap": "Splunk Platform Health and Capacity Monitoring",
                    "priority": "high",
                    "why_it_matters": "Platform drift is hard to see without internal telemetry.",
                }
            ],
            "suggested_use_cases": [
                {
                    "title": "Windows Security Event Correlation & Threat Detection",
                    "scenario": "Detect brute force attacks and suspicious authentication patterns.",
                }
            ],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.load_latest_report_knowledge = lambda *_: report_knowledge
            web_app.chat_session_settings["enable_rag_context"] = False
            web_app.chat_session_settings["enable_splunk_augmentation"] = True

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "Help me investigate and mitigate this risk in Splunk:\n\nRisk: Splunk Platform Health and Capacity Monitoring\nImpact: Build dashboards and alerts for _internal, _introspection, _audit, license usage, indexing latency, queue backlogs, and search performance.\nMitigation: Investigate and remediate through targeted Splunk validation.",
                            "history": [],
                            "chat_session_id": "structured_risk_prompt_test",
                        }
                    )
                )
            finally:
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertIn("Focused risk investigation: Splunk Platform Health and Capacity Monitoring", result.get("response", ""))
        self.assertTrue(any(
            "Splunk Platform Health and Capacity Monitoring" in action.get("prompt", "")
            for action in result.get("follow_on_actions", [])
        ))

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
                            "history": [
                                {"role": "system", "content": "legacy prompt"},
                                {"role": "user", "content": "Old unrelated question"},
                                {"role": "assistant", "content": "Old unrelated answer"},
                            ],
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
        self.assertTrue(all(item.get("role") in {"user", "assistant"} for item in result.get("conversation_history", [])))
        self.assertEqual(result.get("conversation_history", [])[-2].get("content"), "Show a timechart of event volume for index=main over the last 24 hours.")

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

    def test_chat_with_splunk_logic_explains_spl_for_explain_and_run_requests(self):
        original_get_or_create_llm_client = web_app.get_or_create_llm_client
        original_load_latest_report_knowledge = web_app.load_latest_report_knowledge
        original_discover_mcp_tools = web_app.discover_mcp_tools
        original_execute_mcp_tool_call = web_app.execute_mcp_tool_call
        original_get_memory_store_path = web_app._get_memory_store_path
        original_cache = dict(web_app.chat_agent_memory)
        original_chat_settings = dict(web_app.chat_session_settings)
        captured = {"message_sets": []}

        class SequencedStubLLMClient:
            def __init__(self):
                self.responses = [
                    '<TOOL_CALL>{"tool": "splunk_run_query", "args": {"query": "search index=main | stats count", "earliest_time": "-24h", "latest_time": "now"}}</TOOL_CALL>',
                    (
                        "The results came back with a single row showing count 42 for index=main in the last 24 hours. "
                        "That confirms the run succeeded and there was measurable activity in the requested period."
                    ),
                    (
                        "This SPL searches index=main over the last 24 hours and then uses stats count to collapse the matching events into a single total. "
                        "In plain English, it is asking how many events are in index=main during that window. When it ran, it returned one row with a count of 42, so there were 42 matching events in that period."
                    ),
                ]
                self.call_index = 0

            async def generate_response(self, messages, max_tokens, temperature):
                captured["message_sets"].append(messages)
                response = self.responses[self.call_index]
                self.call_index += 1
                return response

        async def stub_discover_mcp_tools(_config):
            return {"splunk_run_query"}

        async def stub_execute_mcp_tool_call(tool_call, _config):
            self.assertEqual(
                tool_call["params"]["arguments"]["query"],
                "search index=main | stats count",
            )
            return {
                "result": {
                    "structuredContent": {
                        "results": [
                            {"count": "42", "index": "main"},
                        ]
                    }
                }
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            web_app.chat_agent_memory.clear()
            web_app._get_memory_store_path = lambda session_id: temp_path / f"{session_id}.json"
            web_app.get_or_create_llm_client = lambda config: SequencedStubLLMClient()
            web_app.load_latest_report_knowledge = lambda *_: None
            web_app.discover_mcp_tools = stub_discover_mcp_tools
            web_app.execute_mcp_tool_call = stub_execute_mcp_tool_call
            web_app.chat_session_settings["enable_splunk_augmentation"] = True

            try:
                result = asyncio.run(
                    web_app.chat_with_splunk_logic(
                        {
                            "message": "Can you help me understand this query and run it?\n\nsearch index=main | stats count",
                            "history": [],
                            "chat_session_id": "explain_and_run_query_test",
                        }
                    )
                )
            finally:
                web_app.get_or_create_llm_client = original_get_or_create_llm_client
                web_app.load_latest_report_knowledge = original_load_latest_report_knowledge
                web_app.discover_mcp_tools = original_discover_mcp_tools
                web_app.execute_mcp_tool_call = original_execute_mcp_tool_call
                web_app._get_memory_store_path = original_get_memory_store_path
                web_app.chat_session_settings.clear()
                web_app.chat_session_settings.update(original_chat_settings)
                web_app.chat_agent_memory.clear()
                web_app.chat_agent_memory.update(original_cache)

        self.assertIn("This SPL searches index=main", result.get("response", ""))
        self.assertIn("count of 42", result.get("response", ""))
        self.assertEqual(len(captured["message_sets"]), 3)
        final_system_messages = [
            msg.get("content", "")
            for msg in captured["message_sets"][-1]
            if msg.get("role") == "system"
        ]
        self.assertTrue(any(
            "Start by explaining in plain English what the SPL is doing step by step." in content
            for content in final_system_messages
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