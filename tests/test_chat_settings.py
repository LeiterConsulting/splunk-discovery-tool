import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from chat_settings import (  # noqa: E402
    ChatSettingsStore,
    apply_custom_values,
    coerce_setting,
    model_defaults,
    model_identity,
    reset_custom_values,
    resolve_chat_settings,
)


def _identity(model: str) -> dict:
    return model_identity(SimpleNamespace(model=model, provider="openai", endpoint_url="https://api.example.test/v1/"))


class ModelDefaultsTests(unittest.TestCase):
    def test_large_context_model_gets_full_search_rounds_and_passages(self):
        auto = model_defaults(
            {"max_tokens": 8000, "temperature": 0.3, "context_window": 128000, "request_timeout": 300, "chat": {"history_turns": 10}},
            rag_available=True,
        )
        self.assertEqual(auto["max_tokens"], 8000)
        self.assertEqual(auto["temperature"], 0.3)
        self.assertEqual(auto["max_execution_time"], 300)
        self.assertEqual(auto["max_iterations"], 5)
        self.assertEqual(auto["convergence_detection"], 3)
        self.assertEqual(auto["context_history"], 10)
        self.assertEqual(auto["rag_max_chunks"], 3)
        self.assertTrue(auto["enable_rag_context"])

    def test_small_and_tiny_context_models_search_less(self):
        small = model_defaults({"max_tokens": 2048, "context_window": 16384}, rag_available=False)
        tiny = model_defaults({"max_tokens": 1024, "context_window": 8192}, rag_available=False)
        self.assertEqual(small["max_iterations"], 3)
        self.assertEqual(small["convergence_detection"], 2)
        self.assertEqual(small["rag_max_chunks"], 2)
        self.assertEqual(tiny["rag_max_chunks"], 1)
        self.assertFalse(small["enable_rag_context"])

    def test_time_limit_stays_between_two_and_fifteen_minutes(self):
        self.assertEqual(model_defaults({"max_tokens": 1, "request_timeout": 30}, False)["max_execution_time"], 120)
        self.assertEqual(model_defaults({"max_tokens": 1, "request_timeout": 5000}, False)["max_execution_time"], 900)

    def test_fixed_temperature_model_has_no_temperature_and_untuned_model_uses_app_defaults(self):
        self.assertIsNone(model_defaults({"max_tokens": 4000, "temperature": None}, False)["temperature"])
        untuned = model_defaults(None, False)
        self.assertEqual(untuned["temperature"], 0.2)
        self.assertEqual(untuned["max_tokens"], 4096)
        self.assertEqual(untuned["context_history"], 6)


class CoerceSettingTests(unittest.TestCase):
    def test_numbers_are_kept_in_range_and_rounded(self):
        self.assertEqual(coerce_setting("context_history", 50), 20)
        self.assertEqual(coerce_setting("context_history", 0), 1)
        self.assertEqual(coerce_setting("max_tokens", "1500.6"), 1501)
        self.assertEqual(coerce_setting("temperature", 0.456), 0.46)

    def test_wrong_kinds_are_rejected(self):
        for key, value in (
            ("enable_rag_context", "yes"),
            ("max_tokens", True),
            ("max_tokens", "lots"),
            ("temperature", float("nan")),
        ):
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    coerce_setting(key, value)


class ChatSettingsStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.store = ChatSettingsStore(Path(self._tmp.name))
        self.identity = _identity("model-a")

    def tearDown(self):
        self._tmp.cleanup()

    def test_model_identity_ignores_case_and_trailing_slash(self):
        other = model_identity(SimpleNamespace(model="MODEL-A", provider="OpenAI", endpoint_url="https://api.example.test/v1"))
        self.assertEqual(other["key"], self.identity["key"])
        self.assertEqual(other["label"], "MODEL-A")

    def test_unreadable_file_falls_back_to_auto(self):
        self.store.path.parent.mkdir(parents=True, exist_ok=True)
        self.store.path.write_text("{not json", encoding="utf-8")
        view = resolve_chat_settings(self.store, {"max_tokens": 3000}, self.identity, rag_available=False)
        self.assertEqual(view.custom, {})
        self.assertEqual(view.effective["max_tokens"], 3000)

    def test_saved_values_out_of_range_are_cleaned_on_load(self):
        self.store.path.parent.mkdir(parents=True, exist_ok=True)
        self.store.path.write_text(
            '{"model_key": "%s", "custom": {"context_history": 99, "temperature": "hot", "unknown": 1}}' % self.identity["key"],
            encoding="utf-8",
        )
        view = resolve_chat_settings(self.store, {"max_tokens": 3000}, self.identity, rag_available=False)
        self.assertEqual(view.custom, {"context_history": 20})

    def test_unknown_keys_are_ignored_and_bad_values_change_nothing(self):
        apply_custom_values(self.store, {"max_tokens": 2000, "max_retries": 9}, self.identity)
        with self.assertRaises(ValueError):
            apply_custom_values(self.store, {"max_tokens": "lots"}, self.identity)
        self.assertEqual(self.store.load()["custom"], {"max_tokens": 2000})

    def test_model_change_notice_lists_cleared_settings_and_clears_on_next_change(self):
        apply_custom_values(self.store, {"max_tokens": 2000, "temperature": 0.9}, self.identity)
        view = resolve_chat_settings(self.store, {"max_tokens": 3000}, _identity("model-b"), rag_available=False)
        self.assertEqual(view.custom, {})
        self.assertEqual(view.notice["previous_model"], "model-a")
        self.assertEqual(view.notice["model"], "model-b")
        self.assertEqual(view.notice["cleared"], ["max_tokens", "temperature"])
        apply_custom_values(self.store, {}, _identity("model-b"))
        self.assertIsNone(self.store.load()["notice"])

    def test_reset_keeps_the_model_so_later_values_are_not_cleared(self):
        apply_custom_values(self.store, {"max_tokens": 2000}, self.identity)
        reset_custom_values(self.store, self.identity)
        apply_custom_values(self.store, {"context_history": 4}, self.identity)
        view = resolve_chat_settings(self.store, {"max_tokens": 3000}, self.identity, rag_available=False)
        self.assertEqual(view.custom, {"context_history": 4})
        self.assertIsNone(view.notice)

    def test_payload_keeps_effective_values_at_the_top_level(self):
        apply_custom_values(self.store, {"max_tokens": 2000}, self.identity)
        payload = resolve_chat_settings(
            self.store, {"max_tokens": 3000}, self.identity, rag_available=False, model_info={"label": "model-a"}
        ).payload()
        self.assertEqual(payload["max_tokens"], 2000)
        self.assertEqual(payload["auto"]["max_tokens"], 3000)
        self.assertEqual(payload["custom"], ["max_tokens"])
        self.assertEqual(payload["limits"]["context_history"], {"min": 1, "max": 20})
        self.assertNotIn("enable_rag_context", payload["limits"])
        self.assertEqual(payload["model"], {"label": "model-a"})


if __name__ == "__main__":
    unittest.main()
