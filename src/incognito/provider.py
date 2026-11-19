"""Decide whether the configured AI model runs on this network or with an outside provider."""

from __future__ import annotations

from typing import Optional

from llm.model_profiles import is_local_endpoint

_ALIASES = {
    "azure openai": "azure",
    "claude": "anthropic",
    "google": "gemini",
    "google ai": "gemini",
    "local ollama": "ollama",
    "ollama endpoint": "ollama",
    "custom endpoint": "custom",
}

# Hosted services that are outside the network even when reached through a private link.
_ALWAYS_CLOUD = frozenset({"azure", "anthropic", "gemini", "cohere", "bedrock", "vertex"})


def provider_kind(provider: Optional[str], endpoint_url: Optional[str]) -> str:
    """Return ``"local"`` for models on this machine or private network, otherwise ``"cloud"``.

    Anything that cannot be confirmed as local counts as cloud, so a forced incognito policy
    errs toward masking.
    """
    name = " ".join(str(provider or "").strip().lower().replace("_", " ").split())
    name = _ALIASES.get(name, name)
    endpoint = str(endpoint_url or "").strip()
    if name in _ALWAYS_CLOUD:
        return "cloud"
    if endpoint:
        return "local" if is_local_endpoint(endpoint) else "cloud"
    if name == "ollama":
        return "local"
    return "cloud"
