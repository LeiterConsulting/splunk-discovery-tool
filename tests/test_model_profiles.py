import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from llm import runtime_tuning  # noqa: E402
from llm.model_profiles import (  # noqa: E402
    HOSTED_CONTEXT_CAP,
    LOCAL_CONTEXT_CAP,
    budget_tokens,
    build_model_profile,
    chat_budgets,
    clear_model_metadata_cache,
    is_local_endpoint,
    parse_ollama_model_entry,
    parse_ollama_show_payload,
    parse_openai_compatible_model_entry,
    parse_parameter_sizes,
    rank_models,
    recommend_model,
    recommend_settings,
)


class ParameterParsingTests(unittest.TestCase):
    def test_dense_moe_and_small_sizes(self):
        self.assertEqual(parse_parameter_sizes("llama3.1:8b"), (8.0, None))
        self.assertEqual(parse_parameter_sizes("qwen3:30b-a3b"), (30.0, 3.0))
        self.assertAlmostEqual(parse_parameter_sizes("gemma3:270m")[0], 0.27)
        total, active = parse_parameter_sizes("mixtral:8x7b")
        self.assertTrue(40 < total < 56)
        self.assertTrue(10 < active < 15)
        self.assertEqual(parse_parameter_sizes("gpt-4o-mini"), (None, None))

    def test_local_endpoint_detection(self):
        self.assertTrue(is_local_endpoint("http://localhost:11434"))
        self.assertTrue(is_local_endpoint("192.168.1.20:8000/v1"))
        self.assertTrue(is_local_endpoint("http://gpu-box.local:8000"))
        self.assertFalse(is_local_endpoint("https://api.openai.com/v1"))
        self.assertFalse(is_local_endpoint(""))


class MetadataParsingTests(unittest.TestCase):
    def test_ollama_tags_entry(self):
        meta = parse_ollama_model_entry({
            "name": "qwen3-coder:latest",
            "capabilities": ["completion", "tools"],
            "details": {"parameter_size": "30.5B", "family": "qwen3moe", "context_length": 262144},
        })
        self.assertEqual(meta["context_window"], 262144)
        self.assertEqual(meta["params_b"], 30.5)
        self.assertTrue(meta["supports_tools"])
        self.assertTrue(meta["generation"])
        self.assertFalse(meta["reasoning"])

    def test_ollama_embedding_entry_is_not_generation(self):
        meta = parse_ollama_model_entry({"name": "nomic-embed-text", "capabilities": ["embedding"]})
        self.assertFalse(meta["generation"])

    def test_ollama_show_payload_reads_context_and_experts(self):
        meta = parse_ollama_show_payload({
            "capabilities": ["completion", "tools", "thinking"],
            "model_info": {
                "general.architecture": "qwen3moe",
                "general.parameter_count": 30_532_122_624,
                "qwen3moe.context_length": 40960,
                "qwen3moe.expert_count": 128,
                "qwen3moe.expert_used_count": 8,
            },
        })
        self.assertEqual(meta["context_window"], 40960)
        self.assertAlmostEqual(meta["params_b"], 30.53, places=2)
        self.assertTrue(meta["reasoning"])
        self.assertLess(meta["active_params_b"], 6)

    def test_openai_compatible_entries(self):
        vllm = parse_openai_compatible_model_entry({"id": "Qwen/Qwen2.5-32B-Instruct", "max_model_len": 32768})
        self.assertEqual(vllm["context_window"], 32768)

        openrouter = parse_openai_compatible_model_entry({
            "id": "openai/gpt-4.1-mini",
            "context_length": 1047576,
            "pricing": {"prompt": "0.0000004", "completion": "0.0000016"},
            "supported_parameters": ["tools", "temperature"],
            "top_provider": {"max_completion_tokens": 32768},
        })
        self.assertAlmostEqual(openrouter["input_cost_per_mtok"], 0.4)
        self.assertAlmostEqual(openrouter["output_cost_per_mtok"], 1.6)
        self.assertTrue(openrouter["supports_tools"])
        self.assertEqual(openrouter["max_output_tokens"], 32768)

        gemini = parse_openai_compatible_model_entry({
            "name": "models/text-embedding-004",
            "inputTokenLimit": 2048,
            "supportedGenerationMethods": ["embedContent"],
        })
        self.assertFalse(gemini["generation"])


class ProfileAndRankingTests(unittest.TestCase):
    def test_hosted_reasoning_profile(self):
        profile = build_model_profile("openai", "gpt-5-mini")
        self.assertTrue(profile.hosted)
        self.assertTrue(profile.reasoning)
        self.assertFalse(profile.supports_temperature)
        self.assertIn("catalog", profile.sources)

    def test_unknown_local_model_uses_heuristics(self):
        profile = build_model_profile("ollama", "my-private-model")
        self.assertFalse(profile.hosted)
        self.assertIn("heuristic", profile.sources)
        self.assertEqual(profile.cost, 1.0)
        self.assertTrue(any("size unknown" in note for note in profile.notes))

    def test_endpoint_metadata_overrides_catalog_context(self):
        profile = build_model_profile("custom", "llama3.1:8b", {"context_window": 16384}, "http://10.0.0.5:8000/v1")
        self.assertEqual(profile.context_window, 16384)
        self.assertFalse(profile.hosted)
        self.assertIn("endpoint", profile.sources)

    def test_openai_balanced_pick_avoids_premium_and_embedding_models(self):
        models = ["o3-pro", "gpt-5", "gpt-4.1-mini", "gpt-4o-mini", "text-embedding-3-small"]
        ranked = rank_models("openai", models)
        self.assertEqual(ranked[-1]["model"], "text-embedding-3-small")
        self.assertFalse(ranked[-1]["eligible"])
        top = recommend_model("openai", models)
        self.assertNotIn(top["model"], {"o3-pro", "text-embedding-3-small"})
        self.assertEqual([item["rank"] for item in ranked], list(range(1, len(models) + 1)))
        self.assertEqual(sum(1 for item in ranked if item["recommended"]), 1)

    def test_newer_gpt_generation_inherits_gpt5_limits(self):
        profile = build_model_profile("openai", "gpt-6.1-terra")
        self.assertEqual(profile.family, "gpt-5")
        self.assertEqual(profile.context_window, 400000)
        self.assertIn("catalog", profile.sources)
        self.assertTrue(any("Newer GPT generation" in note for note in profile.notes))
        self.assertEqual(recommend_settings(profile)["context_window"], HOSTED_CONTEXT_CAP)

        self.assertEqual(build_model_profile("openai", "gpt-7-mini").family, "gpt-5-mini")
        self.assertFalse(any("Newer GPT generation" in note for note in build_model_profile("openai", "gpt-5.1").notes))
        self.assertIn("heuristic", build_model_profile("openai", "gpt-60x").sources)

    def test_ollama_pick_prefers_tool_capable_moe_over_completion_only(self):
        metadata = {
            "llama3.1:8b": {"context_window": 131072, "params_b": 8.0, "supports_tools": True, "generation": True},
            "qwen3-coder:latest": {"context_window": 262144, "params_b": 30.5, "supports_tools": True, "generation": True},
            "hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF:Q4_K_M": {
                "context_window": 65536, "params_b": 8.0, "supports_tools": False, "generation": True,
            },
            "nomic-embed-text:latest": {"generation": False},
        }
        ranked = rank_models("ollama", list(metadata), metadata, "http://localhost:11434")
        order = [item["model"] for item in ranked]
        self.assertEqual(order[0], "qwen3-coder:latest")
        self.assertLess(order.index("llama3.1:8b"), order.index("hf.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF:Q4_K_M"))
        self.assertEqual(order[-1], "nomic-embed-text:latest")


class SettingsTests(unittest.TestCase):
    def test_local_context_is_capped_and_budget_fits(self):
        settings = recommend_settings(build_model_profile("ollama", "qwen3-coder:latest", {"context_window": 262144}))
        self.assertEqual(settings["context_window"], LOCAL_CONTEXT_CAP)
        self.assertEqual(settings["num_ctx"], LOCAL_CONTEXT_CAP)
        self.assertLessEqual(settings["max_tokens"], settings["context_window"] // 2)
        self.assertEqual(settings["temperature"], 0.2)
        self.assertGreaterEqual(settings["request_timeout"], 300)
        self.assertIsNone(settings["reasoning_effort"])

    def test_hosted_reasoning_settings(self):
        settings = recommend_settings(build_model_profile("openai", "gpt-5"))
        self.assertEqual(settings["context_window"], HOSTED_CONTEXT_CAP)
        self.assertIsNone(settings["temperature"])
        self.assertEqual(settings["reasoning_effort"], "low")
        self.assertIsNone(settings["num_ctx"])
        self.assertGreaterEqual(settings["chat"]["initial_max_tokens"], 2048)

    def test_ollama_thinking_controls(self):
        gpt_oss = recommend_settings(build_model_profile("ollama", "gpt-oss:20b"))
        self.assertEqual(gpt_oss["ollama_think"], "low")
        qwen3 = recommend_settings(build_model_profile("ollama", "qwen3:8b"))
        self.assertIs(qwen3["ollama_think"], False)
        llama = recommend_settings(build_model_profile("ollama", "llama3.1:8b"))
        self.assertIsNone(llama["ollama_think"])

    def test_context_override_is_respected(self):
        settings = recommend_settings(build_model_profile("ollama", "llama3.1:8b"), context_window_override=8192)
        self.assertEqual(settings["context_window"], 8192)
        self.assertLessEqual(settings["max_tokens"], 4096)
        self.assertEqual(settings["chat"]["history_turns"], 2)

    def test_chat_budgets_and_budget_tokens(self):
        budgets = chat_budgets(4096, 32768, reasoning=False)
        self.assertLessEqual(budgets["initial_max_tokens"], budgets["final_max_tokens"])
        self.assertEqual(budgets["final_max_tokens"], 4096)
        self.assertGreater(budgets["evidence_chars"], 1500)
        reasoning = chat_budgets(8192, 32768, reasoning=True)
        self.assertGreaterEqual(reasoning["initial_max_tokens"], 2048)
        self.assertEqual(budget_tokens(4096, 0.25, floor=1536, ceiling=4000), 1536)
        self.assertEqual(budget_tokens(16000, 0.5, floor=1024, ceiling=4000), 4000)
        self.assertEqual(budget_tokens("bad", 0.5, floor=512), 2048)
        self.assertLessEqual(budget_tokens(1000, 0.5, floor=2048), 2048)


class RuntimeTuningTests(unittest.TestCase):
    def setUp(self):
        clear_model_metadata_cache()

    def tearDown(self):
        clear_model_metadata_cache()

    def _llm(self, **overrides):
        values = {
            "provider": "ollama",
            "endpoint_url": "http://localhost:11434",
            "model": "llama3.1:8b",
            "api_key": "",
            "max_tokens": 16000,
            "temperature": 0.7,
            "auto_tune": True,
            "context_window": 0,
            "request_timeout": 0,
            "reasoning_effort": "",
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_auto_tune_ignores_saved_budget(self):
        tuning = runtime_tuning.resolve_llm_tuning(self._llm())
        self.assertTrue(tuning["auto_tune"])
        self.assertLessEqual(tuning["max_tokens"], 4096)
        self.assertEqual(tuning["temperature"], 0.2)

    def test_manual_mode_uses_saved_values_and_overrides(self):
        tuning = runtime_tuning.resolve_llm_tuning(self._llm(
            auto_tune=False, max_tokens=3000, temperature=0.4, context_window=16384, request_timeout=90,
        ))
        self.assertFalse(tuning["auto_tune"])
        self.assertEqual(tuning["max_tokens"], 3000)
        self.assertEqual(tuning["temperature"], 0.4)
        self.assertEqual(tuning["context_window"], 16384)
        self.assertEqual(tuning["num_ctx"], 16384)
        self.assertEqual(tuning["request_timeout"], 90)
        self.assertEqual(tuning["chat"]["final_max_tokens"], 3000)

    def test_manual_budget_is_clamped_to_known_output_limit(self):
        tuning = runtime_tuning.resolve_llm_tuning(self._llm(
            provider="openai", endpoint_url=None, model="gpt-4o-mini", auto_tune=False, max_tokens=100000,
        ))
        self.assertEqual(tuning["max_tokens"], 16384)

    def test_reasoning_effort_override_only_for_reasoning_models(self):
        gpt5 = runtime_tuning.resolve_llm_tuning(self._llm(provider="openai", endpoint_url=None, model="gpt-5-mini", reasoning_effort="medium"))
        self.assertEqual(gpt5["reasoning_effort"], "medium")
        mini = runtime_tuning.resolve_llm_tuning(self._llm(provider="openai", endpoint_url=None, model="gpt-4.1-mini", reasoning_effort="high"))
        self.assertIsNone(mini["reasoning_effort"])

    def test_custom_endpoint_on_ollama_port_is_treated_as_ollama(self):
        self.assertEqual(runtime_tuning.runtime_provider_for("custom", "http://127.0.0.1:11434/v1"), "ollama")
        self.assertEqual(runtime_tuning.runtime_provider_for("custom", "http://10.0.0.5:8000/v1"), "custom")
        tuning = runtime_tuning.resolve_llm_tuning(self._llm(provider="custom"))
        self.assertEqual(tuning["provider"], "ollama")
        self.assertIsNotNone(tuning["num_ctx"])

    def test_metadata_fetch_happens_once_and_only_when_allowed(self):
        with patch.object(runtime_tuning, "fetch_ollama_model_metadata", return_value={"context_window": 8192}) as fetch:
            no_fetch = runtime_tuning.resolve_llm_tuning(self._llm(), allow_fetch=False)
            fetch.assert_not_called()
            first = runtime_tuning.resolve_llm_tuning(self._llm(), allow_fetch=True)
            second = runtime_tuning.resolve_llm_tuning(self._llm(), allow_fetch=True)
        self.assertEqual(fetch.call_count, 1)
        self.assertGreater(no_fetch["context_window"], 8192)
        self.assertEqual(first["context_window"], 8192)
        self.assertEqual(second["context_window"], 8192)

    def test_client_tuning_contains_only_client_fields(self):
        tuning = runtime_tuning.resolve_llm_tuning(self._llm(model="gpt-oss:20b"))
        client = runtime_tuning.client_tuning(tuning)
        self.assertEqual(set(client) - set(runtime_tuning.CLIENT_TUNING_KEYS), set())
        self.assertEqual(client["ollama_think"], "low")
        public = runtime_tuning.public_tuning(tuning)
        self.assertIsInstance(public["profile"], dict)


if __name__ == "__main__":
    unittest.main()
