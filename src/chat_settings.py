"""Chat settings that start from the active AI model's tuning.

Every chat setting has an Auto value. Output length, temperature, messages
remembered, the time limit, search rounds, and Knowledge Base passages come
from the model's tuning; the rest are app defaults. Changing a setting makes it
Custom. Custom values are saved with the model they were chosen for and are
cleared when the AI model changes, because a value picked for one model rarely
fits another.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

CHAT_DATA_DIR_NAME = "chat_data"
CHAT_SETTINGS_FILENAME = "chat_settings.json"

# key -> (kind, minimum, maximum)
SETTING_LIMITS: Dict[str, tuple] = {
    "max_execution_time": ("int", 30, 1800),
    "max_iterations": ("int", 1, 10),
    "convergence_detection": ("int", 2, 10),
    "discovery_freshness_days": ("int", 1, 30),
    "max_tokens": ("int", 256, 128000),
    "temperature": ("float", 0.0, 2.0),
    "context_history": ("int", 1, 20),
    "enable_splunk_augmentation": ("bool", None, None),
    "enable_rag_context": ("bool", None, None),
    "rag_max_chunks": ("int", 1, 6),
}
SETTING_KEYS = tuple(SETTING_LIMITS)

# Where each Auto value comes from: the model's tuning, the app, or whether the Knowledge Base is on.
SETTING_SOURCES: Dict[str, str] = {
    "max_execution_time": "model",
    "max_iterations": "model",
    "convergence_detection": "model",
    "discovery_freshness_days": "app",
    "max_tokens": "model",
    "temperature": "model",
    "context_history": "model",
    "enable_splunk_augmentation": "app",
    "enable_rag_context": "knowledge_base",
    "rag_max_chunks": "model",
}

SMALL_CONTEXT_TOKENS = 16384
TINY_CONTEXT_TOKENS = 8192


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _as_int(value: Any, default: int) -> int:
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def model_identity(llm_config: Any, runtime_provider: str = "") -> Dict[str, str]:
    """The key custom values are saved against, and a label for the model."""
    model = str(getattr(llm_config, "model", "") or "").strip()
    provider = str(runtime_provider or getattr(llm_config, "provider", "") or "").strip().lower()
    endpoint = str(getattr(llm_config, "endpoint_url", "") or "").strip().rstrip("/").lower()
    return {"key": f"{provider}|{endpoint}|{model.lower()}", "label": model or "the AI model"}


def model_defaults(tuning: Optional[Mapping[str, Any]], rag_available: bool) -> Dict[str, Any]:
    """Auto values for one model's tuning."""
    tuning = tuning if isinstance(tuning, Mapping) else {}
    has_tuning = "max_tokens" in tuning
    chat_budgets = tuning.get("chat") if isinstance(tuning.get("chat"), Mapping) else {}
    context_window = _as_int(tuning.get("context_window"), 0)
    small_context = 0 < context_window <= SMALL_CONTEXT_TOKENS
    max_iterations = 3 if small_context else 5
    temperature = tuning.get("temperature") if has_tuning else 0.2
    return {
        # One answer may need several model requests, but should never stop before the first can finish.
        "max_execution_time": int(_clamp(_as_int(tuning.get("request_timeout"), 120), 120, 900)),
        "max_iterations": max_iterations,
        # The stall limit only matters when it is lower than the number of rounds.
        "convergence_detection": max(2, min(3, max_iterations - 1)),
        "discovery_freshness_days": 7,
        "max_tokens": _as_int(tuning.get("max_tokens"), 4096),
        "temperature": None if temperature is None else round(float(temperature), 2),
        "context_history": _as_int(chat_budgets.get("history_turns"), 6),
        "enable_splunk_augmentation": True,
        "enable_rag_context": bool(rag_available),
        "rag_max_chunks": 1 if 0 < context_window <= TINY_CONTEXT_TOKENS else (2 if small_context else 3),
    }


def coerce_setting(key: str, value: Any) -> Any:
    """Validate one custom value; raises ValueError for a value of the wrong kind."""
    kind, low, high = SETTING_LIMITS[key]
    if kind == "bool":
        if isinstance(value, bool):
            return value
        raise ValueError(f"{key} must be true or false")
    if isinstance(value, bool):
        raise ValueError(f"{key} must be a number")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a number") from None
    if number != number:  # NaN
        raise ValueError(f"{key} must be a number")
    number = _clamp(number, low, high)
    return round(number, 2) if kind == "float" else int(round(number))


def sanitize_custom(values: Any) -> Dict[str, Any]:
    if not isinstance(values, Mapping):
        return {}
    cleaned: Dict[str, Any] = {}
    for key, value in values.items():
        if key not in SETTING_LIMITS or value is None:
            continue
        try:
            cleaned[key] = coerce_setting(key, value)
        except ValueError:
            continue
    return cleaned


class ChatSettingsStore:
    """Saves custom chat values, with the model they were chosen for, in one JSON file."""

    def __init__(self, root: Optional[Path] = None):
        self._root = Path(root) if root is not None else None
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        root = self._root if self._root is not None else Path("output") / CHAT_DATA_DIR_NAME
        return root / CHAT_SETTINGS_FILENAME

    def load(self) -> Dict[str, Any]:
        state = {"model_key": "", "model_label": "", "custom": {}, "notice": None}
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        except (OSError, ValueError):
            return state
        if isinstance(loaded, dict):
            state["model_key"] = str(loaded.get("model_key") or "")
            state["model_label"] = str(loaded.get("model_label") or "")
            state["custom"] = sanitize_custom(loaded.get("custom"))
            state["notice"] = loaded.get("notice") if isinstance(loaded.get("notice"), dict) else None
        return state

    def save(self, state: Mapping[str, Any]) -> None:
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "model_key": str(state.get("model_key") or ""),
            "model_label": str(state.get("model_label") or ""),
            "custom": sanitize_custom(state.get("custom")),
            "notice": state.get("notice") if isinstance(state.get("notice"), dict) else None,
            "saved_at": _utc_now_iso(),
        }
        temp_path = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        with self._lock:
            try:
                with open(temp_path, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2)
                os.replace(temp_path, path)
            finally:
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except OSError:
                        pass


@dataclass
class ChatSettingsView:
    auto: Dict[str, Any]
    custom: Dict[str, Any]
    effective: Dict[str, Any]
    model: Dict[str, Any] = field(default_factory=dict)
    notice: Optional[Dict[str, Any]] = None

    def payload(self) -> Dict[str, Any]:
        """Effective values at the top level (as before), plus what the Chat Settings dialog needs."""
        result = dict(self.effective)
        result.update({
            "auto": dict(self.auto),
            "custom": sorted(self.custom),
            "sources": dict(SETTING_SOURCES),
            "limits": {
                key: {"min": low, "max": high}
                for key, (kind, low, high) in SETTING_LIMITS.items()
                if kind != "bool"
            },
            "model": dict(self.model),
            "notice": self.notice,
        })
        return result


def _load_for_model(store: ChatSettingsStore, identity: Mapping[str, str]) -> Dict[str, Any]:
    """Saved state, with custom values cleared (and a notice kept) when the AI model changed."""
    state = store.load()
    if state["custom"] and state["model_key"] and state["model_key"] != identity["key"]:
        state = {
            "model_key": identity["key"],
            "model_label": identity["label"],
            "custom": {},
            "notice": {
                "previous_model": state["model_label"] or "the previous AI model",
                "model": identity["label"],
                "cleared": sorted(state["custom"]),
                "at": _utc_now_iso(),
            },
        }
        try:
            store.save(state)
        except OSError:
            pass
    return state


def resolve_chat_settings(
    store: ChatSettingsStore,
    tuning: Optional[Mapping[str, Any]],
    identity: Mapping[str, str],
    rag_available: bool,
    model_info: Optional[Mapping[str, Any]] = None,
) -> ChatSettingsView:
    state = _load_for_model(store, identity)
    auto = model_defaults(tuning, rag_available)
    custom = dict(state["custom"])
    effective = {**auto, **custom}
    return ChatSettingsView(auto=auto, custom=custom, effective=effective, model=dict(model_info or {}), notice=state["notice"])


def apply_custom_values(store: ChatSettingsStore, updates: Mapping[str, Any], identity: Mapping[str, str]) -> None:
    """Make settings Custom, or Auto again with None. Unknown keys are ignored; bad values raise ValueError."""
    if not isinstance(updates, Mapping):
        raise ValueError("Settings must be a JSON object")
    state = _load_for_model(store, identity)
    custom = dict(state["custom"]) if state["model_key"] in {"", identity["key"]} else {}
    for key, value in updates.items():
        if key not in SETTING_LIMITS:
            continue
        if value is None:
            custom.pop(key, None)
        else:
            custom[key] = coerce_setting(key, value)
    store.save({"model_key": identity["key"], "model_label": identity["label"], "custom": custom, "notice": None})


def reset_custom_values(store: ChatSettingsStore, identity: Mapping[str, str]) -> None:
    store.save({"model_key": identity["key"], "model_label": identity["label"], "custom": {}, "notice": None})
