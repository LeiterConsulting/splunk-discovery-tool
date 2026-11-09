"""Model capability profiles, balanced ranking, and automatic tuning.

A profile combines three sources, highest priority first:

1. Metadata reported by the endpoint: Ollama ``/api/tags`` and ``/api/show``, and
   the OpenAI-compatible ``/v1/models`` extensions used by vLLM, LM Studio,
   llama.cpp, OpenRouter, Groq, Mistral, Together, and the Gemini model list.
2. A curated catalog of hosted model families.
3. Size and family heuristics for open-weight models.

Catalog prices are reference list prices in USD per million tokens. They are only
used to compare models with each other, never to bill or to block a choice.
"""

from __future__ import annotations

import ipaddress
import math
import re
import threading
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

BALANCED_WEIGHTS: Dict[str, float] = {"quality": 0.45, "speed": 0.30, "cost": 0.25}

HOSTED_PROVIDERS = {"openai", "azure", "anthropic", "gemini"}

# Budgets the app plans against even when a model supports more. Larger prompts
# cost more on hosted APIs and are slow and memory-hungry on local runtimes.
LOCAL_CONTEXT_CAP = 32768
HOSTED_CONTEXT_CAP = 128000
DEFAULT_UNKNOWN_CONTEXT = 8192
DEFAULT_UNKNOWN_PARAMS_B = 7.0

NON_GENERATION_NAME_TOKENS = (
    "embed",
    "embedding",
    "rerank",
    "bge-",
    "minilm",
    "whisper",
    "tts",
    "transcribe",
    "moderation",
    "dall-e",
    "gpt-image",
    "imagen",
    "clip",
)


@dataclass(frozen=True)
class CatalogEntry:
    pattern: str
    family: str
    context_window: int
    max_output_tokens: int
    quality: float
    speed: float
    input_cost: Optional[float] = None
    output_cost: Optional[float] = None
    reasoning: bool = False
    supports_tools: bool = True
    supports_temperature: bool = True
    vision: bool = False


@dataclass(frozen=True)
class OpenWeightFamily:
    pattern: str
    family: str
    quality_bonus: float
    supports_tools: bool
    context_window: int
    reasoning: bool = False


_C = CatalogEntry
_F = OpenWeightFamily

# Order matters: the first matching pattern wins, so specific tiers come first.
HOSTED_CATALOG: Tuple[CatalogEntry, ...] = (
    _C(r"^gpt-5(\.\d+)?-pro", "gpt-5-pro", 400000, 128000, 0.97, 0.15, 15.0, 120.0, reasoning=True, supports_temperature=False, vision=True),
    _C(r"^gpt-5(\.\d+)?-nano", "gpt-5-nano", 400000, 128000, 0.70, 0.80, 0.05, 0.40, reasoning=True, supports_temperature=False, vision=True),
    _C(r"^gpt-5(\.\d+)?-mini", "gpt-5-mini", 400000, 128000, 0.85, 0.66, 0.25, 2.00, reasoning=True, supports_temperature=False, vision=True),
    _C(r"^gpt-5(\.\d+)?-chat", "gpt-5-chat", 128000, 16384, 0.86, 0.78, 1.25, 10.0, vision=True),
    _C(r"^gpt-5(\.\d+)?-codex", "gpt-5-codex", 400000, 128000, 0.93, 0.45, 1.25, 10.0, reasoning=True, supports_temperature=False),
    _C(r"^gpt-5", "gpt-5", 400000, 128000, 0.95, 0.42, 1.25, 10.0, reasoning=True, supports_temperature=False, vision=True),
    _C(r"^gpt-4\.1-nano", "gpt-4.1-nano", 1047576, 32768, 0.62, 0.95, 0.10, 0.40, vision=True),
    _C(r"^gpt-4\.1-mini", "gpt-4.1-mini", 1047576, 32768, 0.78, 0.88, 0.40, 1.60, vision=True),
    _C(r"^gpt-4\.1", "gpt-4.1", 1047576, 32768, 0.86, 0.76, 2.00, 8.00, vision=True),
    _C(r"^(chatgpt-)?gpt-4o-mini", "gpt-4o-mini", 128000, 16384, 0.68, 0.90, 0.15, 0.60, vision=True),
    _C(r"^(chatgpt-4o|gpt-4o)", "gpt-4o", 128000, 16384, 0.82, 0.80, 2.50, 10.0, vision=True),
    _C(r"^o4-mini", "o4-mini", 200000, 100000, 0.86, 0.52, 1.10, 4.40, reasoning=True, supports_temperature=False, vision=True),
    _C(r"^o3-pro", "o3-pro", 200000, 100000, 0.96, 0.10, 20.0, 80.0, reasoning=True, supports_temperature=False),
    _C(r"^o3-mini", "o3-mini", 200000, 100000, 0.80, 0.52, 1.10, 4.40, reasoning=True, supports_temperature=False),
    _C(r"^o3", "o3", 200000, 100000, 0.93, 0.36, 2.00, 8.00, reasoning=True, supports_temperature=False, vision=True),
    _C(r"^o1-mini", "o1-mini", 128000, 65536, 0.74, 0.45, 1.10, 4.40, reasoning=True, supports_tools=False, supports_temperature=False),
    _C(r"^o1", "o1", 200000, 100000, 0.88, 0.25, 15.0, 60.0, reasoning=True, supports_temperature=False),
    _C(r"^gpt-4-turbo", "gpt-4-turbo", 128000, 4096, 0.76, 0.60, 10.0, 30.0),
    _C(r"^gpt-4(-\d{4})?$|^gpt-4-0", "gpt-4", 8192, 8192, 0.66, 0.50, 30.0, 60.0),
    _C(r"^gpt-3\.5", "gpt-3.5-turbo", 16385, 4096, 0.45, 0.90, 0.50, 1.50),
    _C(r"^gpt-oss[-:_]?120b", "gpt-oss-120b", 131072, 32768, 0.86, 0.55, 0.15, 0.60, reasoning=True),
    _C(r"^gpt-oss", "gpt-oss-20b", 131072, 32768, 0.76, 0.72, 0.05, 0.20, reasoning=True),
    _C(r"^claude-opus-4[-.]5", "claude-opus-4.5", 200000, 64000, 0.98, 0.42, 5.0, 25.0, vision=True),
    _C(r"^claude-(opus-4|4-opus)", "claude-opus-4", 200000, 32000, 0.97, 0.35, 15.0, 75.0, vision=True),
    _C(r"^claude-(sonnet-4|4-sonnet)", "claude-sonnet-4", 200000, 64000, 0.93, 0.62, 3.0, 15.0, vision=True),
    _C(r"^claude-3-7-sonnet", "claude-3.7-sonnet", 200000, 64000, 0.90, 0.60, 3.0, 15.0, vision=True),
    _C(r"^claude-3-5-sonnet", "claude-3.5-sonnet", 200000, 8192, 0.87, 0.65, 3.0, 15.0, vision=True),
    _C(r"^claude-(haiku-4|4-haiku)", "claude-haiku-4", 200000, 64000, 0.82, 0.90, 1.0, 5.0, vision=True),
    _C(r"^claude-3-5-haiku", "claude-3.5-haiku", 200000, 8192, 0.72, 0.88, 0.80, 4.0),
    _C(r"^claude-3-opus", "claude-3-opus", 200000, 4096, 0.85, 0.30, 15.0, 75.0, vision=True),
    _C(r"^claude-3-haiku", "claude-3-haiku", 200000, 4096, 0.60, 0.95, 0.25, 1.25, vision=True),
    _C(r"^claude", "claude", 200000, 8192, 0.85, 0.60, 3.0, 15.0, vision=True),
    _C(r"^gemini-1\.5-pro", "gemini-1.5-pro", 2097152, 8192, 0.80, 0.55, 1.25, 5.0, vision=True),
    _C(r"^gemini-1\.5-flash", "gemini-1.5-flash", 1048576, 8192, 0.66, 0.90, 0.075, 0.30, vision=True),
    _C(r"^gemini-2\.0-flash-lite", "gemini-2.0-flash-lite", 1048576, 8192, 0.64, 0.95, 0.075, 0.30, vision=True),
    _C(r"^gemini-2\.0-flash", "gemini-2.0-flash", 1048576, 8192, 0.74, 0.90, 0.10, 0.40, vision=True),
    _C(r"^gemini-[\d.]+-pro", "gemini-pro", 1048576, 65536, 0.93, 0.50, 1.25, 10.0, reasoning=True, vision=True),
    _C(r"^gemini-[\d.]+-flash-lite", "gemini-flash-lite", 1048576, 65536, 0.68, 0.95, 0.10, 0.40, vision=True),
    _C(r"^gemini-[\d.]+-flash", "gemini-flash", 1048576, 65536, 0.82, 0.85, 0.30, 2.50, reasoning=True, vision=True),
    _C(r"^gemini", "gemini", 1048576, 8192, 0.75, 0.80, 0.30, 2.50, vision=True),
)

OPEN_WEIGHT_FAMILIES: Tuple[OpenWeightFamily, ...] = (
    _F(r"qwen3[-_.]?coder", "qwen3-coder", 0.03, True, 262144),
    _F(r"qwen3", "qwen3", 0.05, True, 40960, reasoning=True),
    _F(r"qwq", "qwq", 0.03, True, 40960, reasoning=True),
    _F(r"qwen2\.5[-_.]?coder", "qwen2.5-coder", 0.0, True, 32768),
    _F(r"qwen2\.5", "qwen2.5", 0.01, True, 32768),
    _F(r"qwen", "qwen", -0.04, False, 32768),
    _F(r"llama[-_.]?4", "llama4", 0.05, True, 131072),
    _F(r"llama[-_.]?3\.3", "llama3.3", 0.04, True, 131072),
    _F(r"llama[-_.]?3\.[12]", "llama3.1", 0.0, True, 131072),
    _F(r"llama[-_.]?3", "llama3", -0.03, False, 8192),
    _F(r"llama[-_.]?2", "llama2", -0.12, False, 4096),
    _F(r"foundation[-_.]?sec", "foundation-sec", 0.0, False, 65536),
    _F(r"devstral", "devstral", 0.02, True, 131072),
    _F(r"magistral", "magistral", 0.02, True, 40960, reasoning=True),
    _F(r"mistral[-_.]?small", "mistral-small", 0.03, True, 131072),
    _F(r"mistral[-_.]?large", "mistral-large", 0.04, True, 131072),
    _F(r"mistral[-_.]?nemo", "mistral-nemo", 0.0, True, 131072),
    _F(r"ministral", "ministral", 0.0, True, 131072),
    _F(r"mixtral", "mixtral", -0.02, True, 32768),
    _F(r"mistral", "mistral", -0.05, True, 32768),
    _F(r"gemma[-_.]?4", "gemma4", 0.04, True, 131072),
    _F(r"gemma[-_.]?3n", "gemma3n", -0.02, False, 32768),
    _F(r"gemma[-_.]?3", "gemma3", 0.03, False, 131072),
    _F(r"gemma", "gemma", -0.06, False, 8192),
    _F(r"phi[-_.]?4[-_.]?mini", "phi4-mini", 0.0, True, 131072),
    _F(r"phi[-_.]?4", "phi4", 0.03, False, 16384),
    _F(r"phi", "phi", -0.05, False, 4096),
    _F(r"deepseek[-_.]?r1", "deepseek-r1", 0.04, False, 131072, reasoning=True),
    _F(r"deepseek[-_.]?(v3|chat)", "deepseek-v3", 0.06, True, 131072),
    _F(r"deepseek[-_.]?coder", "deepseek-coder", -0.02, False, 16384),
    _F(r"command[-_.]?r", "command-r", 0.0, True, 131072),
    _F(r"granite", "granite", -0.02, True, 131072),
    _F(r"hermes", "hermes", 0.0, True, 131072),
    _F(r"glm[-_.]?4", "glm4", 0.03, True, 131072),
    _F(r"kimi", "kimi", 0.06, True, 131072),
    _F(r"smollm|tinyllama", "small", -0.10, False, 8192),
)


@dataclass
class ModelProfile:
    model: str
    provider: str
    family: str
    hosted: bool
    context_window: int
    max_output_tokens: int
    supports_tools: bool
    supports_temperature: bool
    reasoning: bool
    vision: bool
    generation: bool
    quality: float
    speed: float
    cost: float
    params_b: Optional[float] = None
    active_params_b: Optional[float] = None
    input_cost_per_mtok: Optional[float] = None
    output_cost_per_mtok: Optional[float] = None
    sources: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def score(self, weights: Optional[Dict[str, float]] = None) -> float:
        if not self.generation:
            return 0.0
        active = weights or BALANCED_WEIGHTS
        total = sum(active.values()) or 1.0
        value = (
            active.get("quality", 0.0) * self.quality
            + active.get("speed", 0.0) * self.speed
            + active.get("cost", 0.0) * self.cost
        ) / total
        return round(value, 4)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["score"] = self.score()
        return payload


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def normalize_model_id(model: Optional[str]) -> str:
    """Lowercase a model id and drop routing prefixes such as ``openai/`` or ``models/``."""
    value = str(model or "").strip().lower()
    if value.startswith("ft:"):
        value = value[3:]
    if value.startswith("models/"):
        value = value[len("models/"):]
    if "/" in value:
        value = value.rsplit("/", 1)[-1]
    return value


def is_local_endpoint(endpoint_url: Optional[str]) -> bool:
    """Return True for loopback, private-network, and ``.local`` hosts."""
    raw = str(endpoint_url or "").strip()
    if not raw:
        return False
    if "://" not in raw:
        raw = f"http://{raw}"
    try:
        host = (urlparse(raw).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    if host in {"localhost", "host.docker.internal"} or host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def _normalize_provider(provider: Optional[str]) -> str:
    value = str(provider or "").strip().lower().replace("_", " ")
    aliases = {
        "azure openai": "azure",
        "claude": "anthropic",
        "google": "gemini",
        "google ai": "gemini",
        "local ollama": "ollama",
        "ollama endpoint": "ollama",
        "custom endpoint": "custom",
        "vllm": "custom",
        "local-vllm": "custom",
        "generic": "custom",
    }
    return aliases.get(value, value or "custom")


def match_catalog_entry(normalized_model: str) -> Optional[CatalogEntry]:
    for entry in HOSTED_CATALOG:
        if re.search(entry.pattern, normalized_model):
            return entry
    return None


def newer_gpt_generation_alias(normalized_model: str) -> Optional[str]:
    """Map ids from GPT generations newer than the catalog (gpt-6, gpt-7.1-mini) onto gpt-5 ids."""
    match = re.match(r"^gpt-(\d+)(?=$|[.\-])", normalized_model)
    if not match or int(match.group(1)) <= 5:
        return None
    return "gpt-5" + normalized_model[match.end():]


def match_open_weight_family(normalized_model: str) -> Optional[OpenWeightFamily]:
    for family in OPEN_WEIGHT_FAMILIES:
        if re.search(family.pattern, normalized_model):
            return family
    return None


def _parse_size_token(value: str) -> Optional[float]:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([bmk])\s*", str(value or "").lower())
    if not match:
        return None
    number = float(match.group(1))
    unit = match.group(2)
    if unit == "m":
        return number / 1000.0
    if unit == "k":
        return number / 1_000_000.0
    return number


def parse_parameter_sizes(text: Optional[str]) -> Tuple[Optional[float], Optional[float]]:
    """Parse total and active parameter counts (billions) from names like ``30b-a3b`` or ``8x7b``."""
    lowered = str(text or "").lower()
    if not lowered:
        return None, None

    experts = re.search(r"(?<![a-z0-9.])(\d+)x(\d+(?:\.\d+)?)b(?![a-z])", lowered)
    if experts:
        count = int(experts.group(1))
        size = float(experts.group(2))
        # Experts share attention and embedding weights, so totals run below count * size.
        return round(count * size * 0.83, 2), round(2 * size * 0.92, 2)

    total_match = re.search(r"(?<![a-z0-9.])(\d+(?:\.\d+)?)([bm])(?![a-z])", lowered)
    total = _parse_size_token(total_match.group(1) + total_match.group(2)) if total_match else None
    active_match = re.search(r"(?<![a-z0-9])a(\d+(?:\.\d+)?)b(?![a-z])", lowered)
    active = float(active_match.group(1)) if active_match else None
    return total, active


def _size_quality(total_b: float, active_b: Optional[float]) -> float:
    effective = total_b
    if active_b and active_b < total_b:
        # Mixture-of-experts models land between their active and total size in quality.
        effective = (total_b ** 0.7) * (active_b ** 0.3)
    return _clamp(0.30 + 0.13 * math.log2(max(effective, 0.5)), 0.20, 0.90)


def _size_speed(active_b: float) -> float:
    return _clamp(1.05 - 0.15 * math.log2(max(active_b, 0.5)), 0.08, 1.0)


def _price_score(input_cost: Optional[float], output_cost: Optional[float]) -> Optional[float]:
    if input_cost is None and output_cost is None:
        return None
    blended = 0.75 * float(input_cost or 0.0) + 0.25 * float(output_cost or 0.0)
    return round(_clamp(1.0 - math.log10(1.0 + blended) / math.log10(61.0), 0.05, 1.0), 4)


def _version_bonus(normalized_model: str) -> float:
    match = re.match(r"^gpt-5\.(\d+)", normalized_model)
    if not match:
        return 0.0
    return min(0.04, 0.01 * int(match.group(1)))


def _first_int(*values: Any) -> Optional[int]:
    for value in values:
        if value is None or isinstance(value, bool):
            continue
        try:
            number = int(float(value))
        except (TypeError, ValueError):
            continue
        if number > 0:
            return number
    return None


def _capability_flags(capabilities: Any) -> Dict[str, Optional[bool]]:
    flags: Dict[str, Optional[bool]] = {}
    if isinstance(capabilities, dict):
        lowered = {str(key).lower(): bool(value) for key, value in capabilities.items()}
        if "function_calling" in lowered or "tools" in lowered or "tool_use" in lowered:
            flags["supports_tools"] = lowered.get("function_calling") or lowered.get("tools") or lowered.get("tool_use")
        if "vision" in lowered:
            flags["vision"] = lowered["vision"]
        if "reasoning" in lowered or "thinking" in lowered:
            flags["reasoning"] = lowered.get("reasoning") or lowered.get("thinking")
        if "completion_chat" in lowered or "chat" in lowered:
            flags["generation"] = lowered.get("completion_chat") or lowered.get("chat")
        return flags
    if isinstance(capabilities, (list, tuple, set)):
        lowered_items = {str(item).strip().lower() for item in capabilities}
        flags["supports_tools"] = "tools" in lowered_items or "function_calling" in lowered_items
        flags["reasoning"] = "thinking" in lowered_items or "reasoning" in lowered_items
        flags["vision"] = "vision" in lowered_items
        has_completion = bool(lowered_items & {"completion", "chat", "generate", "insert"})
        if has_completion:
            flags["generation"] = True
        elif "embedding" in lowered_items or "embeddings" in lowered_items:
            flags["generation"] = False
    return flags


def parse_ollama_model_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize one ``/api/tags`` model record (Ollama 0.6+ includes capabilities and context)."""
    if not isinstance(entry, dict):
        return {}
    details = entry.get("details") if isinstance(entry.get("details"), dict) else {}
    metadata: Dict[str, Any] = {}
    context = _first_int(entry.get("context_length"), details.get("context_length"))
    if context:
        metadata["context_window"] = context
    total_b = _parse_size_token(str(details.get("parameter_size") or ""))
    if total_b:
        metadata["params_b"] = round(total_b, 2)
    family = str(details.get("family") or "").strip().lower()
    if family:
        metadata["runtime_family"] = family
    metadata.update({key: value for key, value in _capability_flags(entry.get("capabilities")).items() if value is not None})
    return metadata


def parse_ollama_show_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize an Ollama ``/api/show`` response."""
    if not isinstance(payload, dict):
        return {}
    metadata = parse_ollama_model_entry(payload)
    model_info = payload.get("model_info") if isinstance(payload.get("model_info"), dict) else {}
    architecture = str(model_info.get("general.architecture") or "").strip()

    context = _first_int(model_info.get(f"{architecture}.context_length")) if architecture else None
    if not context:
        context = _first_int(*[value for key, value in model_info.items() if str(key).endswith(".context_length")])
    if context:
        metadata["context_window"] = context

    parameter_count = _first_int(model_info.get("general.parameter_count"))
    if parameter_count:
        metadata["params_b"] = round(parameter_count / 1e9, 2)

    size_total, size_active = parse_parameter_sizes(str(model_info.get("general.size_label") or ""))
    if size_total and "params_b" not in metadata:
        metadata["params_b"] = size_total
    if size_active:
        metadata["active_params_b"] = size_active
    elif architecture:
        expert_count = _first_int(model_info.get(f"{architecture}.expert_count"))
        experts_used = _first_int(model_info.get(f"{architecture}.expert_used_count"))
        total_b = metadata.get("params_b")
        if expert_count and experts_used and total_b and experts_used < expert_count:
            metadata["active_params_b"] = round(total_b * (0.1 + 0.9 * experts_used / expert_count), 2)
    if architecture:
        metadata.setdefault("runtime_family", architecture.lower())
    return metadata


def parse_openai_compatible_model_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize the optional metadata that OpenAI-compatible servers add to ``/models`` entries."""
    if not isinstance(entry, dict):
        return {}
    metadata: Dict[str, Any] = {}
    top_provider = entry.get("top_provider") if isinstance(entry.get("top_provider"), dict) else {}
    meta_block = entry.get("meta") if isinstance(entry.get("meta"), dict) else {}
    context = _first_int(
        entry.get("context_length"),
        entry.get("context_window"),
        entry.get("max_model_len"),
        entry.get("max_context_length"),
        entry.get("loaded_context_length"),
        entry.get("max_input_tokens"),
        entry.get("inputTokenLimit"),
        entry.get("n_ctx"),
        top_provider.get("context_length"),
        meta_block.get("n_ctx"),
        meta_block.get("n_ctx_train"),
    )
    if context:
        metadata["context_window"] = context
    output = _first_int(
        entry.get("max_completion_tokens"),
        entry.get("max_output_tokens"),
        entry.get("outputTokenLimit"),
        top_provider.get("max_completion_tokens"),
    )
    if output:
        metadata["max_output_tokens"] = output

    metadata.update({key: value for key, value in _capability_flags(entry.get("capabilities")).items() if value is not None})

    supported_parameters = entry.get("supported_parameters")
    if isinstance(supported_parameters, list):
        lowered = {str(item).lower() for item in supported_parameters}
        metadata["supports_tools"] = "tools" in lowered or "tool_choice" in lowered
        if "reasoning" in lowered or "include_reasoning" in lowered:
            metadata["reasoning"] = True
        if "temperature" in lowered:
            metadata["supports_temperature"] = True

    generation_methods = entry.get("supportedGenerationMethods")
    if isinstance(generation_methods, list):
        metadata["generation"] = "generateContent" in generation_methods
    if isinstance(entry.get("thinking"), bool):
        metadata["reasoning"] = entry["thinking"]

    model_type = str(entry.get("type") or "").strip().lower()
    if model_type in {"embedding", "embeddings"}:
        metadata["generation"] = False
    elif model_type == "vlm":
        metadata["vision"] = True

    pricing = entry.get("pricing") if isinstance(entry.get("pricing"), dict) else {}
    for source_key, target_key in (("prompt", "input_cost_per_mtok"), ("completion", "output_cost_per_mtok"), ("input", "input_cost_per_mtok"), ("output", "output_cost_per_mtok")):
        raw_price = pricing.get(source_key)
        if raw_price is None:
            continue
        try:
            per_token = float(raw_price)
        except (TypeError, ValueError):
            continue
        # OpenRouter-style prices are per token; Together-style prices are already per million.
        metadata[target_key] = round(per_token * 1e6, 4) if per_token < 0.01 else round(per_token, 4)

    created = _first_int(entry.get("created"))
    if created:
        metadata["created"] = created
    return metadata


def build_model_profile(
    provider: Optional[str],
    model: Optional[str],
    metadata: Optional[Dict[str, Any]] = None,
    endpoint_url: Optional[str] = None,
) -> ModelProfile:
    """Build a capability profile for one model from endpoint metadata, the catalog, and heuristics."""
    provider_key = _normalize_provider(provider)
    meta = dict(metadata or {})
    normalized = normalize_model_id(model)
    entry = match_catalog_entry(normalized)
    successor_alias = None
    if entry is None:
        successor_alias = newer_gpt_generation_alias(normalized)
        entry = match_catalog_entry(successor_alias) if successor_alias else None
        if entry is None:
            successor_alias = None
    family_rule = None if entry else match_open_weight_family(normalized)

    if provider_key in HOSTED_PROVIDERS:
        hosted = True
    elif provider_key == "ollama":
        hosted = normalized.endswith("-cloud") or normalized.endswith(":cloud")
    else:
        hosted = bool(endpoint_url) and not is_local_endpoint(endpoint_url)

    name_total, name_active = parse_parameter_sizes(normalized)
    params_b = meta.get("params_b") or name_total
    active_b = meta.get("active_params_b") or name_active
    notes: List[str] = []
    sources: List[str] = []

    input_cost = output_cost = None
    if entry is not None:
        family = entry.family
        context_window = entry.context_window
        max_output = entry.max_output_tokens
        quality = entry.quality + _version_bonus(successor_alias or normalized)
        speed = entry.speed
        supports_tools = entry.supports_tools
        supports_temperature = entry.supports_temperature
        reasoning = entry.reasoning
        vision = entry.vision
        input_cost, output_cost = entry.input_cost, entry.output_cost
        sources.append("catalog")
        if successor_alias:
            notes.append(f"Newer GPT generation than the built-in catalog; planning with {entry.family} limits.")
        if not hosted and params_b:
            speed = _size_speed(active_b or params_b)
    else:
        size_for_quality = params_b or DEFAULT_UNKNOWN_PARAMS_B
        family = family_rule.family if family_rule else (normalized.split(":", 1)[0] or "unknown")
        context_window = family_rule.context_window if family_rule else DEFAULT_UNKNOWN_CONTEXT
        max_output = 0
        quality = _size_quality(size_for_quality, active_b) + (family_rule.quality_bonus if family_rule else -0.03)
        speed = _size_speed(active_b or size_for_quality)
        supports_tools = family_rule.supports_tools if family_rule else False
        supports_temperature = True
        reasoning = family_rule.reasoning if family_rule else False
        vision = False
        sources.append("heuristic")
        if not params_b:
            notes.append("Model size unknown; estimated as a 7B model.")

    generation = not any(token in normalized for token in NON_GENERATION_NAME_TOKENS)

    endpoint_keys = {"context_window", "max_output_tokens", "supports_tools", "reasoning", "vision", "generation", "supports_temperature", "input_cost_per_mtok", "output_cost_per_mtok"}
    if any(key in meta for key in endpoint_keys) or meta.get("params_b"):
        sources.append("endpoint")
    context_window = _first_int(meta.get("context_window")) or context_window
    max_output = _first_int(meta.get("max_output_tokens")) or max_output
    if isinstance(meta.get("supports_tools"), bool):
        supports_tools = meta["supports_tools"]
    if isinstance(meta.get("reasoning"), bool):
        reasoning = meta["reasoning"] or (entry is not None and entry.reasoning and provider_key in HOSTED_PROVIDERS)
    if isinstance(meta.get("vision"), bool):
        vision = meta["vision"]
    if isinstance(meta.get("generation"), bool):
        generation = meta["generation"] and generation
    if isinstance(meta.get("supports_temperature"), bool):
        supports_temperature = meta["supports_temperature"]
    if meta.get("input_cost_per_mtok") is not None or meta.get("output_cost_per_mtok") is not None:
        input_cost = meta.get("input_cost_per_mtok")
        output_cost = meta.get("output_cost_per_mtok")

    if not max_output:
        max_output = 4096 if hosted else max(1024, min(context_window // 4, 8192))

    if entry is None and reasoning:
        speed *= 0.85
        notes.append("Thinking-capable model; the app turns thinking off for quick chat turns.")

    if not supports_tools:
        quality -= 0.08
        notes.append("No native tool calling; the agent uses text tool tags instead.")
    if context_window < 8192:
        quality -= 0.20
        notes.append(f"Small context window ({context_window} tokens) limits evidence per answer.")
    elif context_window < 16384:
        quality -= 0.10
        notes.append(f"Context window of {context_window} tokens limits evidence per answer.")

    if hosted:
        cost = _price_score(input_cost, output_cost)
        if cost is None:
            cost = 0.6
            notes.append("Hosted model with unknown pricing.")
    else:
        cost = 1.0

    if not generation:
        notes.append("Not a text-generation model.")

    return ModelProfile(
        model=str(model or ""),
        provider=provider_key,
        family=family,
        hosted=hosted,
        context_window=int(context_window),
        max_output_tokens=int(max_output),
        supports_tools=bool(supports_tools),
        supports_temperature=bool(supports_temperature),
        reasoning=bool(reasoning),
        vision=bool(vision),
        generation=bool(generation),
        quality=round(_clamp(quality, 0.0, 1.0), 4),
        speed=round(_clamp(speed, 0.0, 1.0), 4),
        cost=round(_clamp(cost, 0.0, 1.0), 4),
        params_b=round(params_b, 2) if params_b else None,
        active_params_b=round(active_b, 2) if active_b else None,
        input_cost_per_mtok=input_cost,
        output_cost_per_mtok=output_cost,
        sources=sources,
        notes=notes,
    )


def _format_tokens(value: int) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M".replace(".0M", "M")
    if value >= 1000:
        return f"{round(value / 1024)}K" if value % 1024 == 0 else f"{round(value / 1000)}K"
    return str(value)


def describe_profile(profile: ModelProfile) -> List[str]:
    reasons: List[str] = []
    if not profile.generation:
        return ["Not a text-generation model"]
    reasons.append("Native tool calling" if profile.supports_tools else "No native tool calling")
    reasons.append(f"{_format_tokens(profile.context_window)} context")
    if profile.hosted:
        if profile.input_cost_per_mtok is not None:
            reasons.append(
                f"About ${profile.input_cost_per_mtok:g} in / ${profile.output_cost_per_mtok or 0:g} out per 1M tokens"
            )
    else:
        reasons.append("Runs on your hardware (no per-token cost)")
    if profile.active_params_b and profile.params_b and profile.active_params_b < profile.params_b:
        reasons.append(f"Mixture of experts: about {profile.active_params_b:g}B of {profile.params_b:g}B parameters active per token")
    elif profile.params_b and not profile.hosted:
        reasons.append(f"{profile.params_b:g}B parameters")
    if profile.reasoning:
        if profile.hosted or profile.family.startswith("gpt-oss"):
            reasons.append("Reasoning model: stronger analysis, uses extra output tokens")
        else:
            reasons.append("Thinking-capable model (thinking is turned off for quick chat turns)")
    return reasons


def rank_models(
    provider: Optional[str],
    models: Iterable[str],
    metadata_by_model: Optional[Dict[str, Dict[str, Any]]] = None,
    endpoint_url: Optional[str] = None,
    weights: Optional[Dict[str, float]] = None,
) -> List[Dict[str, Any]]:
    """Rank models by balanced quality, speed, and cost. Non-generation models sort last."""
    metadata_by_model = metadata_by_model or {}
    ranked: List[Tuple[float, int, str, Dict[str, Any]]] = []
    for model in models:
        if not isinstance(model, str) or not model.strip():
            continue
        metadata = metadata_by_model.get(model) or {}
        profile = build_model_profile(provider, model, metadata, endpoint_url)
        score = profile.score(weights)
        ranked.append((
            score,
            int(metadata.get("created") or 0),
            model,
            {
                "model": model,
                "score": score,
                "quality": profile.quality,
                "speed": profile.speed,
                "cost": profile.cost,
                "family": profile.family,
                "context_window": profile.context_window,
                "supports_tools": profile.supports_tools,
                "reasoning": profile.reasoning,
                "hosted": profile.hosted,
                "eligible": profile.generation,
                "reasons": describe_profile(profile),
                "notes": list(profile.notes),
            },
        ))
    ranked.sort(key=lambda item: (-item[0], -item[1], item[2]))
    results = [item[3] for item in ranked]
    for index, item in enumerate(results):
        item["rank"] = index + 1
        item["recommended"] = index == 0 and item["eligible"]
    return results


def recommend_model(
    provider: Optional[str],
    models: Iterable[str],
    metadata_by_model: Optional[Dict[str, Dict[str, Any]]] = None,
    endpoint_url: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    for item in rank_models(provider, models, metadata_by_model, endpoint_url):
        if item["eligible"]:
            return item
    return None


def _history_turns(context: int) -> int:
    if context <= 8192:
        return 2
    if context <= 16384:
        return 4
    if context <= 32768:
        return 6
    return 8


def _evidence_rows(context: int) -> int:
    if context <= 8192:
        return 5
    if context <= 16384:
        return 10
    if context <= 32768:
        return 20
    return 30


def recommend_settings(profile: ModelProfile, context_window_override: Optional[int] = None) -> Dict[str, Any]:
    """Return tuned runtime settings for one model profile."""
    model_context = profile.context_window or DEFAULT_UNKNOWN_CONTEXT
    cap = HOSTED_CONTEXT_CAP if profile.hosted else LOCAL_CONTEXT_CAP
    effective_context = min(model_context, cap)
    override = _first_int(context_window_override)
    if override:
        effective_context = min(model_context, override)
    effective_context = max(2048, effective_context)

    output_cap = profile.max_output_tokens or 4096
    if profile.reasoning:
        max_tokens = min(output_cap, 16000 if profile.hosted else 8192)
    else:
        max_tokens = min(output_cap, 8192 if profile.hosted else 4096)
    max_tokens = int(max(512, min(max_tokens, effective_context // 2)))

    temperature = 0.2 if profile.supports_temperature else None

    if profile.hosted:
        request_timeout = 300 if profile.reasoning else 120
    else:
        request_timeout = 900 if profile.reasoning else 600

    reasoning_effort = None
    if profile.reasoning and (profile.provider in {"openai", "azure"} or profile.family.startswith("gpt-oss")):
        reasoning_effort = "low"

    # Ollama: gpt-oss always reasons and accepts an effort level; other thinking
    # models can switch thinking off, which keeps short chat turns fast.
    ollama_think: Any = None
    if profile.provider == "ollama" and profile.reasoning:
        ollama_think = "low" if profile.family.startswith("gpt-oss") else False

    chat = chat_budgets(max_tokens, effective_context, profile.reasoning)

    rationale = [
        f"Plans prompts against {_format_tokens(effective_context)} of the model's {_format_tokens(model_context)} context"
        + (" (local runtimes are capped to keep responses fast)." if not profile.hosted and model_context > effective_context else "."),
        f"Caps each response at {max_tokens} output tokens"
        + (" with headroom for hidden reasoning tokens." if profile.reasoning else "."),
    ]
    if temperature is None:
        rationale.append("This model uses a fixed temperature, so the app does not send one.")
    else:
        rationale.append("Temperature 0.2 keeps answers grounded in the returned Splunk data.")
    if reasoning_effort:
        rationale.append("Reasoning effort 'low' balances answer quality with latency and cost.")
    rationale.append(f"Allows up to {request_timeout}s per request.")

    return {
        "max_tokens": max_tokens,
        "temperature": temperature,
        "context_window": effective_context,
        "model_context_window": model_context,
        "request_timeout": request_timeout,
        "reasoning_effort": reasoning_effort,
        "num_ctx": effective_context if profile.provider == "ollama" else None,
        "ollama_think": ollama_think,
        "supports_temperature": profile.supports_temperature,
        "supports_tools": profile.supports_tools,
        "reasoning": profile.reasoning,
        "chat": chat,
        "rationale": rationale,
    }


def chat_budgets(max_tokens: int, context_window: int, reasoning: bool) -> Dict[str, int]:
    """Split one output budget into per-step chat budgets sized to the context window."""
    effective_context = max(2048, int(context_window or DEFAULT_UNKNOWN_CONTEXT))
    final_max = max(256, int(max_tokens or 1024))
    # Reasoning models spend hidden tokens before the visible answer, so small
    # budgets return empty text; keep a floor for every step.
    floor = min(final_max, 2048) if reasoning else min(final_max, 512)
    initial_max = max(floor, min(final_max, int(final_max * 0.5)))
    followup_max = max(floor, min(final_max, int(final_max * 0.6)))
    prompt_budget = max(1024, effective_context - final_max - 512)
    return {
        "initial_max_tokens": initial_max,
        "followup_max_tokens": followup_max,
        "final_max_tokens": final_max,
        "retry_max_tokens": initial_max,
        "history_turns": _history_turns(effective_context),
        "evidence_rows": _evidence_rows(effective_context),
        "evidence_chars": int(_clamp(prompt_budget * 3.5 * 0.35, 1500, 24000)),
        "prompt_budget_tokens": prompt_budget,
    }


def budget_tokens(max_tokens: Any, fraction: float, floor: int, ceiling: Optional[int] = None) -> int:
    """Scale an output budget, never below ``floor`` and never above the configured maximum."""
    try:
        base = int(max_tokens)
    except (TypeError, ValueError):
        base = 4096
    base = max(256, base)
    value = max(floor, int(base * fraction))
    if ceiling:
        value = min(value, ceiling)
    return min(value, max(base, floor))


_METADATA_CACHE: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
_METADATA_LOCK = threading.Lock()


def _cache_key(provider: Optional[str], endpoint_url: Optional[str], model: Optional[str]) -> Tuple[str, str, str]:
    base = str(endpoint_url or "").strip().rstrip("/").lower()
    for suffix in ("/v1/chat/completions", "/chat/completions", "/api/chat", "/api/generate", "/v1"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    return (_normalize_provider(provider), base, str(model or "").strip())


def remember_model_metadata(provider: Optional[str], endpoint_url: Optional[str], model: Optional[str], metadata: Dict[str, Any]) -> None:
    if not model or not isinstance(metadata, dict):
        return
    with _METADATA_LOCK:
        _METADATA_CACHE[_cache_key(provider, endpoint_url, model)] = dict(metadata)


def get_cached_model_metadata(provider: Optional[str], endpoint_url: Optional[str], model: Optional[str]) -> Optional[Dict[str, Any]]:
    with _METADATA_LOCK:
        cached = _METADATA_CACHE.get(_cache_key(provider, endpoint_url, model))
    return dict(cached) if cached is not None else None


def clear_model_metadata_cache() -> None:
    with _METADATA_LOCK:
        _METADATA_CACHE.clear()


def fetch_ollama_model_metadata(base_url: str, model: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Read model metadata from Ollama ``/api/show``. Returns an empty dict when unavailable."""
    import requests

    base = str(base_url or "").rstrip("/")
    if not base or not model:
        return {}
    try:
        response = requests.post(f"{base}/api/show", json={"model": model}, timeout=timeout)
        if response.status_code != 200:
            return {}
        return parse_ollama_show_payload(response.json())
    except Exception:
        return {}


def fetch_openai_compatible_model_metadata(base_url: str, model: str, api_key: Optional[str] = None, timeout: float = 4.0) -> Dict[str, Any]:
    """Look up one model in an OpenAI-compatible ``/models`` listing. Returns an empty dict when unavailable."""
    import requests

    base = str(base_url or "").rstrip("/")
    for suffix in ("/chat/completions", "/completions", "/responses"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    if not base or not model:
        return {}
    candidates = [f"{base}/models"] if base.endswith("/v1") else [f"{base}/v1/models", f"{base}/models"]
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    for url in candidates:
        try:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code != 200:
                continue
            payload = response.json()
        except Exception:
            continue
        entries = payload.get("data") if isinstance(payload, dict) else payload
        if not isinstance(entries, list):
            continue
        for item in entries:
            if isinstance(item, dict) and str(item.get("id") or item.get("name") or "") == model:
                return parse_openai_compatible_model_entry(item)
        return {}
    return {}
