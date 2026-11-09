"""Resolve the effective model profile and runtime settings for a saved LLM configuration."""

from __future__ import annotations

from typing import Any, Dict, Optional

from llm.factory import normalize_ollama_endpoint_url, normalize_provider_name
from llm.model_profiles import (
    ModelProfile,
    build_model_profile,
    chat_budgets,
    fetch_ollama_model_metadata,
    fetch_openai_compatible_model_metadata,
    get_cached_model_metadata,
    recommend_settings,
    remember_model_metadata,
)

VALID_REASONING_EFFORTS = {"minimal", "low", "medium", "high"}
CLIENT_TUNING_KEYS = ("request_timeout", "reasoning_effort", "num_ctx", "ollama_think", "supports_temperature")


def _positive_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def looks_like_ollama_endpoint(endpoint_url: Optional[str]) -> bool:
    lowered = str(endpoint_url or "").lower()
    return "ollama" in lowered or ":11434" in lowered


def runtime_provider_for(provider: Optional[str], endpoint_url: Optional[str]) -> str:
    """Return the provider that actually serves requests (custom endpoints on Ollama count as Ollama)."""
    normalized = normalize_provider_name(provider)
    if normalized in {"custom", ""} and looks_like_ollama_endpoint(endpoint_url):
        return "ollama"
    return normalized or "custom"


def lookup_model_metadata(
    provider: Optional[str],
    endpoint_url: Optional[str],
    model: Optional[str],
    api_key: Optional[str] = None,
    allow_fetch: bool = False,
) -> Dict[str, Any]:
    """Return cached endpoint metadata for a model, fetching it once when allowed.

    Hosted providers rely on the curated catalog, so only Ollama and custom
    OpenAI-compatible endpoints are queried. Failed lookups are cached as empty
    so a slow endpoint is not probed on every request.
    """
    runtime_provider = runtime_provider_for(provider, endpoint_url)
    cached = get_cached_model_metadata(runtime_provider, endpoint_url, model)
    if cached is not None:
        return cached
    if not allow_fetch or not model:
        return {}

    metadata: Dict[str, Any] = {}
    if runtime_provider == "ollama":
        metadata = fetch_ollama_model_metadata(normalize_ollama_endpoint_url(endpoint_url), str(model))
    elif runtime_provider == "custom" and endpoint_url:
        metadata = fetch_openai_compatible_model_metadata(str(endpoint_url), str(model), api_key=api_key)
    remember_model_metadata(runtime_provider, endpoint_url, model, metadata or {})
    return metadata or {}


def _manual_value(llm_config: Any, name: str) -> Any:
    return getattr(llm_config, name, None) if llm_config is not None else None


def resolve_llm_tuning(
    llm_config: Any,
    allow_fetch: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return effective runtime settings for an LLM config.

    With ``auto_tune`` on (the default) the output budget and temperature come
    from the model profile. With it off, the saved ``max_tokens`` and
    ``temperature`` are used as-is, clamped only to known model output limits.
    Explicit ``context_window``, ``request_timeout``, and ``reasoning_effort``
    values override the profile in both modes.
    """
    provider_name = _manual_value(llm_config, "provider")
    endpoint_url = _manual_value(llm_config, "endpoint_url")
    model = str(_manual_value(llm_config, "model") or "").strip()
    runtime_provider = runtime_provider_for(provider_name, endpoint_url)

    if metadata is None:
        metadata = lookup_model_metadata(
            runtime_provider,
            endpoint_url,
            model,
            api_key=_manual_value(llm_config, "api_key"),
            allow_fetch=allow_fetch,
        )
    else:
        remember_model_metadata(runtime_provider, endpoint_url, model, metadata)

    profile = build_model_profile(runtime_provider, model, metadata, endpoint_url)
    settings = recommend_settings(profile, context_window_override=_positive_int(_manual_value(llm_config, "context_window")))
    auto_tune = _manual_value(llm_config, "auto_tune") is not False

    if not auto_tune:
        manual_max = _positive_int(_manual_value(llm_config, "max_tokens")) or settings["max_tokens"]
        if "catalog" in profile.sources or (metadata or {}).get("max_output_tokens"):
            manual_max = min(manual_max, profile.max_output_tokens)
        settings["max_tokens"] = int(manual_max)
        manual_temperature = _manual_value(llm_config, "temperature")
        if profile.supports_temperature and manual_temperature is not None:
            try:
                settings["temperature"] = max(0.0, min(2.0, float(manual_temperature)))
            except (TypeError, ValueError):
                pass
        settings["chat"] = chat_budgets(settings["max_tokens"], settings["context_window"], profile.reasoning)

    timeout_override = _positive_int(_manual_value(llm_config, "request_timeout"))
    if timeout_override:
        settings["request_timeout"] = timeout_override

    effort_override = str(_manual_value(llm_config, "reasoning_effort") or "").strip().lower()
    if effort_override in VALID_REASONING_EFFORTS and profile.reasoning:
        settings["reasoning_effort"] = effort_override
        if runtime_provider == "ollama" and profile.family.startswith("gpt-oss"):
            settings["ollama_think"] = "low" if effort_override == "minimal" else effort_override

    settings.update({
        "auto_tune": auto_tune,
        "provider": runtime_provider,
        "configured_provider": normalize_provider_name(provider_name),
        "model": model,
        "profile": profile,
    })
    return settings


def client_tuning(settings: Dict[str, Any]) -> Dict[str, Any]:
    """Pick the settings that LLM clients accept from a resolved tuning dict."""
    return {key: settings.get(key) for key in CLIENT_TUNING_KEYS if settings.get(key) is not None}


def public_tuning(settings: Dict[str, Any]) -> Dict[str, Any]:
    """Return a JSON-safe view of resolved tuning for API responses."""
    profile = settings.get("profile")
    payload = {key: value for key, value in settings.items() if key != "profile"}
    if isinstance(profile, ModelProfile):
        payload["profile"] = profile.to_dict()
    return payload
