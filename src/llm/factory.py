"""
LLM client factory for creating different types of LLM integrations.

Supports OpenAI API and custom LLM endpoints with a unified interface.
"""

import os
import json
import asyncio
import aiohttp
import time
import re
import random
import logging
from typing import Optional, Protocol, Dict, Any, Callable
from datetime import datetime
from urllib.parse import quote

from spl.spl_utils import extract_json_payload

logger = logging.getLogger(__name__)


OPENAI_GENERATION_PREFIXES = (
    "gpt-",
    "chatgpt-",
    "o1",
    "o3",
    "o4",
    "codex-",
)

OPENAI_NON_GENERATION_TOKENS = (
    "embedding",
    "whisper",
    "tts",
    "audio",
    "speech",
    "transcribe",
    "transcription",
    "moderation",
    "dall-e",
    "image",
    "realtime",
    "search-preview",
    "computer-use-preview",
)

OPENAI_IMAGE_GENERATION_PREFIXES = (
    "gpt-image-",
    "dall-e-",
)

OPENAI_RESPONSES_MODEL_PREFIXES = (
    "o1",
    "o3",
    "o4",
    "gpt-5",
)

OPENAI_CHAT_COMPLETION_NEW_TOKEN_HINTS = (
    "gpt-4o",
    "gpt-4.1",
    "gpt-4-turbo",
    "chatgpt-4o",
    "o1",
    "o3",
    "o4",
    "gpt-5",
)


REASONING_MARKUP_PATTERN = re.compile(r"<(think|thinking|reasoning)>.*?</\1>", re.IGNORECASE | re.DOTALL)
DANGLING_REASONING_CLOSE_PATTERN = re.compile(r"^.*?</(think|thinking|reasoning)>", re.IGNORECASE | re.DOTALL)
UNCLOSED_REASONING_OPEN_PATTERN = re.compile(r"<(think|thinking|reasoning)>.*$", re.IGNORECASE | re.DOTALL)


def strip_reasoning_markup(text: Any) -> str:
    """Remove inline chain-of-thought blocks that some local models emit in the answer text."""
    if not isinstance(text, str):
        return "" if text is None else str(text)
    cleaned = REASONING_MARKUP_PATTERN.sub("", text)
    if DANGLING_REASONING_CLOSE_PATTERN.search(cleaned) and not re.search(r"<(think|thinking|reasoning)>", cleaned, re.IGNORECASE):
        cleaned = DANGLING_REASONING_CLOSE_PATTERN.sub("", cleaned, count=1)
    stripped_open = UNCLOSED_REASONING_OPEN_PATTERN.sub("", cleaned)
    if stripped_open.strip():
        cleaned = stripped_open
    return cleaned.strip()


def parse_json_from_llm_text(text: Any) -> Optional[Any]:
    """Parse JSON from model output, tolerating code fences, prose, and truncation.

    A complete fenced block or whole reply is used as-is. Otherwise the largest
    JSON value in the text wins, so a reply cut off by the output budget keeps
    the complete elements of its main array instead of collapsing to the first
    nested object.
    """
    if isinstance(text, (dict, list)):
        return text
    cleaned = strip_reasoning_markup(text)
    if not cleaned:
        return None
    fenced = re.findall(r"```(?:json)?\s*(.*?)```", cleaned, flags=re.IGNORECASE | re.DOTALL)
    for candidate in fenced + [cleaned]:
        try:
            return json.loads(candidate.strip())
        except (json.JSONDecodeError, ValueError):
            continue
    return extract_json_payload(cleaned, expect="any")


# Discovery analysis replies are lists of short items; these budgets leave room
# for the capped item counts in build_analysis_prompt without truncation.
ANALYSIS_MAX_TOKENS = 4096
ANALYSIS_REASONING_MAX_TOKENS = 8192

_ANALYSIS_GROUNDING = (
    "Use only facts present in the data. Name indexes, sourcetypes, sources, and hosts exactly as they "
    "appear and never invent ones that are not listed."
)
_ANALYSIS_JSON_RULE = "Reply with only the JSON object, with no prose before or after it."


def build_analysis_prompt(data: dict, analysis_type: str) -> str:
    """Build the discovery analysis prompt shared by every provider.

    Each list-style analysis asks for one JSON object with a named list, a capped
    item count, and short fields so replies fit small output budgets.
    """
    now = datetime.now()
    time_context = (
        f"Current date and time: {now.strftime('%Y-%m-%d %H:%M:%S')}. "
        f"Timestamps from {now.year} are current or recent, not future events.\n\n"
    )
    payload = json.dumps(data, indent=1, default=str)

    if analysis_type == "classification":
        return time_context + (
            "Classify the following Splunk data into categories such as Security (authentication, firewall, "
            "intrusion detection), Infrastructure (system logs, performance metrics), Business (application "
            "logs, user activity), and Compliance (audit logs, regulatory data).\n\n"
            f"Data: {payload}\n\n"
            f"{_ANALYSIS_GROUNDING}\nReturn a JSON object with the classification results. {_ANALYSIS_JSON_RULE}"
        )
    if analysis_type == "recommendations":
        return time_context + (
            "Based on the following Splunk environment analysis, recommend the most valuable next steps.\n\n"
            f"Analysis: {payload}\n\n"
            f"{_ANALYSIS_GROUNDING}\n"
            'Return {"recommendations": [...]} with at most 8 items, most valuable first. Each item has '
            '"title" (short), "description" (under 60 words, naming the discovered data it relies on), '
            '"priority" ("high", "medium", or "low"), "category", "roi_estimate" (one sentence), and '
            '"implementation_complexity" ("Low", "Medium", or "High").\n'
            f"{_ANALYSIS_JSON_RULE}"
        )
    if analysis_type == "creative_use_cases":
        guidance = str(data.get("prompt_guidance") or "").strip() if isinstance(data, dict) else ""
        return time_context + (
            "Based on the following Splunk environment data, propose cross-functional use cases that combine "
            "at least two discovered data sources, address a real operational or business problem, and "
            "provide measurable value.\n\n"
            f"Environment analysis: {payload}\n\n"
            + (f"{guidance}\n" if guidance else "")
            + f"{_ANALYSIS_GROUNDING}\n"
            'Return {"use_cases": [...]} with at most 5 items. Each item has "title", "description" (under '
            '50 words), "data_sources" (list of discovered sourcetype or index names), "business_value" (one '
            'sentence), "implementation_complexity" ("Low", "Medium", or "High" with a short reason), '
            '"success_metrics" (list of up to 3 short metrics), "scenario" (one or two sentences), and '
            '"category".\n'
            f"{_ANALYSIS_JSON_RULE}"
        )
    if analysis_type == "patterns":
        return time_context + (
            "Identify notable patterns in this Splunk inventory: data volume and distribution, sourcetype "
            "characteristics, index usage, data freshness, and data quality signals.\n\n"
            f"Data: {payload}\n\n"
            f"{_ANALYSIS_GROUNDING} Do not report fields as missing just because this summary omits them.\n"
            'Return {"patterns": [...]} with at most 6 items. Each item has "category" (short label), '
            '"insight" (one or two sentences), and "evidence" (list of up to 3 short facts taken from the '
            "data, such as names and counts).\n"
            f"{_ANALYSIS_JSON_RULE}"
        )
    return time_context + f"Analyze this Splunk data for {analysis_type} and return JSON.\n\nData: {payload}"


def _positive_int(value: Any, default: int) -> int:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default

def normalize_provider_name(provider: Optional[str]) -> str:
    """Normalize provider labels from UI/config into stable internal identifiers."""
    value = (provider or "openai").strip().lower().replace("_", " ")
    aliases = {
        "openai": "openai",
        "azure": "azure",
        "azure openai": "azure",
        "anthropic": "anthropic",
        "claude": "anthropic",
        "gemini": "gemini",
        "google": "gemini",
        "google ai": "gemini",
        "ollama": "ollama",
        "local ollama": "ollama",
        "ollama endpoint": "ollama",
        "custom": "custom",
        "custom endpoint": "custom",
    }
    return aliases.get(value, value)


DEFAULT_OLLAMA_ENDPOINT_URL = "http://localhost:11434"


def normalize_ollama_endpoint_url(endpoint_url: Optional[str]) -> str:
    """Normalize Ollama endpoints to a base URL so native paths can be derived safely."""
    base = str(endpoint_url or "").strip() or DEFAULT_OLLAMA_ENDPOINT_URL
    base = base.rstrip("/")

    known_suffixes = [
        "/api/tags",
        "/api/chat",
        "/api/generate",
        "/v1/models",
        "/v1/chat/completions",
        "/chat/completions",
        "/v1/completions",
        "/completions",
        "/v1",
    ]

    lower_base = base.lower()
    for suffix in known_suffixes:
        if lower_base.endswith(suffix):
            base = base[:-len(suffix)]
            break

    return base.rstrip("/") or DEFAULT_OLLAMA_ENDPOINT_URL


def messages_to_plain_text(messages: list) -> str:
    """Flatten chat messages to plain text (best-effort for providers without chat schema)."""
    if not isinstance(messages, list):
        return ""

    lines = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role", "user")).strip().lower()
        content = str(message.get("content", "")).strip()
        if not content:
            continue
        if role == "system":
            lines.append(f"System: {content}")
        elif role == "assistant":
            lines.append(f"Assistant: {content}")
        else:
            lines.append(f"User: {content}")
    return "\n\n".join(lines)


def _normalize_openai_model_name(model: Optional[str]) -> str:
    return (model or "").strip().lower()


def is_openai_generation_model(model_id: str) -> bool:
    """Return True when a model ID is a likely text-generation/chat model."""
    model_lower = _normalize_openai_model_name(model_id)
    if not model_lower:
        return False

    if model_lower.startswith("ft:"):
        model_lower = model_lower[3:]

    if any(token in model_lower for token in OPENAI_NON_GENERATION_TOKENS):
        return False

    return model_lower.startswith(OPENAI_GENERATION_PREFIXES)


def is_openai_image_generation_model(model_id: str) -> bool:
    """Return True when a model ID targets OpenAI image generation."""
    model_lower = _normalize_openai_model_name(model_id)
    if not model_lower:
        return False

    if model_lower.startswith("ft:"):
        model_lower = model_lower[3:]

    return model_lower.startswith(OPENAI_IMAGE_GENERATION_PREFIXES)


def filter_openai_generation_models(model_ids: list[str]) -> list[str]:
    """Filter /v1/models output down to likely chat-capable generation models."""
    filtered = []
    seen = set()
    for model_id in sorted(model_ids or []):
        if not isinstance(model_id, str):
            continue
        cleaned = model_id.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        if is_openai_generation_model(cleaned):
            filtered.append(cleaned)
    return filtered


def get_openai_model_capabilities(model: str) -> Dict[str, Any]:
    """Infer compatibility hints for OpenAI model families used by the app."""
    model_lower = _normalize_openai_model_name(model)
    prefers_responses_api = model_lower.startswith(OPENAI_RESPONSES_MODEL_PREFIXES)
    is_gpt5_chat = bool(re.match(r"^gpt-5(\.\d+)?-chat", model_lower))
    reasoning = model_lower.startswith(("o1", "o3", "o4")) or (model_lower.startswith("gpt-5") and not is_gpt5_chat)
    supports_temperature = not reasoning

    chat_token_keys = ["max_tokens"]
    if any(hint in model_lower for hint in OPENAI_CHAT_COMPLETION_NEW_TOKEN_HINTS):
        chat_token_keys = ["max_completion_tokens", "max_tokens"]

    return {
        "model": model,
        "supports_generation": is_openai_generation_model(model),
        "supports_image_generation": is_openai_image_generation_model(model),
        "prefers_responses_api": prefers_responses_api,
        "supports_temperature": supports_temperature,
        "reasoning": reasoning,
        "chat_token_keys": chat_token_keys,
        "supports_chat_completions": not prefers_responses_api or model_lower.startswith(("gpt-4", "gpt-3.5", "chatgpt-4o")),
    }


def extract_text_from_openai_response(response_data: Dict[str, Any]) -> str:
    """Extract assistant text from either chat-completions or responses payloads."""
    if not isinstance(response_data, dict):
        return ""

    output_text = response_data.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    choices = response_data.get("choices", [])
    if isinstance(choices, list) and choices:
        first_choice = choices[0] if isinstance(choices[0], dict) else {}
        message = first_choice.get("message", {}) if isinstance(first_choice, dict) else {}
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str) and content.strip():
                return content.strip()
            if isinstance(message.get("refusal"), str) and message.get("refusal", "").strip():
                return message.get("refusal", "").strip()
            if isinstance(content, list):
                parts = []
                for item in content:
                    if not isinstance(item, dict):
                        continue
                    text_value = item.get("text") or item.get("content") or item.get("value")
                    if isinstance(text_value, str) and text_value.strip():
                        parts.append(text_value.strip())
                if parts:
                    return "\n".join(parts).strip()

    output_items = response_data.get("output", [])
    if isinstance(output_items, list):
        parts = []
        for item in output_items:
            if not isinstance(item, dict):
                continue
            if item.get("type") in {"output_text", "text"}:
                text_value = item.get("text") or item.get("content") or item.get("value")
                if isinstance(text_value, str) and text_value.strip():
                    parts.append(text_value.strip())
                continue
            if item.get("type") == "message":
                for content_item in item.get("content", []) if isinstance(item.get("content", []), list) else []:
                    if not isinstance(content_item, dict):
                        continue
                    text_value = (
                        content_item.get("text")
                        or content_item.get("content")
                        or content_item.get("value")
                        or content_item.get("refusal")
                    )
                    if isinstance(text_value, str) and text_value.strip():
                        parts.append(text_value.strip())
        if parts:
            return "\n".join(parts).strip()

    return ""


class RateLimitManager:
    """Intelligent rate limit manager for API requests."""
    
    def __init__(self, display_callback=None):
        self.display_callback = display_callback
        self.request_history = []
        self.current_limits = {}
        self.base_delay = 1.0
        self.max_delay = 300.0  # 5 minutes max
        self.retry_count = 0
        self.max_retries = 5
        
    def parse_rate_limit_error(self, error_message: str) -> Dict[str, Any]:
        """Parse rate limit error to extract timing information."""
        # Parse OpenAI rate limit error format
        patterns = {
            'limit': r'Limit (\d+)',
            'used': r'Used (\d+)',  
            'requested': r'Requested (\d+)',
            'retry_after': r'try again in ([\d.]+)s'
        }
        
        parsed = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, error_message)
            if match:
                if key == 'retry_after':
                    parsed[key] = float(match.group(1))
                else:
                    parsed[key] = int(match.group(1))
        
        return parsed
    
    def calculate_optimal_delay(self, rate_limit_info: Dict[str, Any]) -> float:
        """Calculate optimal delay based on rate limit information."""
        if 'retry_after' in rate_limit_info:
            # Use the suggested retry time plus a small buffer
            base_delay = rate_limit_info['retry_after'] + 2.0
        else:
            # Fallback to exponential backoff
            base_delay = self.base_delay * (2 ** self.retry_count)
        
        # Add jitter to avoid thundering herd
        jitter = random.uniform(0.1, 0.3) * base_delay
        total_delay = min(base_delay + jitter, self.max_delay)
        
        return total_delay
    
    def update_request_budget(self, rate_limit_info: Dict[str, Any]) -> Dict[str, Any]:
        """Update request budget based on current limits."""
        if 'limit' in rate_limit_info and 'used' in rate_limit_info:
            remaining = rate_limit_info['limit'] - rate_limit_info['used']
            self.current_limits = {
                'tokens_per_minute': rate_limit_info['limit'],
                'tokens_used': rate_limit_info['used'],
                'tokens_remaining': remaining,
                'updated_at': time.time()
            }
            
            # Calculate recommended request size
            if remaining > 0:
                recommended_tokens = min(remaining * 0.8, 4000)  # Use 80% of remaining, max 4k
            else:
                recommended_tokens = 500  # Conservative fallback
                
            return {
                'recommended_max_tokens': int(recommended_tokens),
                'should_split_request': remaining < 2000,
                'estimated_requests_remaining': remaining // 1000 if remaining > 1000 else 0
            }
        
        return {'recommended_max_tokens': 1000, 'should_split_request': False}
    
    def handle_context_length_error(self, error_message: str) -> Dict[str, Any]:
        """Handle context length exceeded errors with intelligent truncation suggestions."""
        # Parse context length information
        token_match = re.search(r'requested (\d+) tokens.*maximum.*?(\d+) tokens', error_message)
        if token_match:
            requested = int(token_match.group(1))
            maximum = int(token_match.group(2))
            
            # Calculate safe token limits
            safe_completion_tokens = min(500, maximum // 4)  # Use at most 25% for completion
            safe_prompt_tokens = maximum - safe_completion_tokens - 100  # Leave buffer
            
            return {
                'max_context_tokens': maximum,
                'requested_tokens': requested,
                'safe_max_tokens': safe_completion_tokens,
                'should_truncate_prompt': True,
                'recommended_prompt_length': safe_prompt_tokens,
                'truncation_ratio': safe_prompt_tokens / (requested - safe_completion_tokens) if requested > safe_completion_tokens else 0.5
            }
        
        # Fallback for unparseable errors
        return {
            'should_truncate_prompt': True,
            'truncation_ratio': 0.6,  # Reduce to 60% of original
            'safe_max_tokens': 500
        }
    
    def truncate_prompt_intelligently(self, prompt: str, truncation_info: Dict[str, Any]) -> str:
        """Intelligently truncate prompt while preserving important information."""
        if not truncation_info.get('should_truncate_prompt'):
            return prompt
        
        ratio = truncation_info.get('truncation_ratio', 0.6)
        
        # Split prompt into sections
        lines = prompt.split('\n')
        
        # Preserve instruction lines (usually at the beginning)
        instruction_lines = []
        data_lines = []
        
        in_data_section = False
        for line in lines:
            if 'Data:' in line or 'Environment Analysis:' in line or 'Analysis:' in line:
                in_data_section = True
            
            if in_data_section:
                data_lines.append(line)
            else:
                instruction_lines.append(line)
        
        # Keep all instructions, truncate data proportionally
        target_data_chars = int(len('\n'.join(data_lines)) * ratio)
        
        if len('\n'.join(data_lines)) > target_data_chars:
            # Truncate data section while preserving structure
            truncated_data = '\n'.join(data_lines)[:target_data_chars]
            # Ensure we don't break in the middle of a JSON structure
            if '{' in truncated_data and truncated_data.count('{') > truncated_data.count('}'):
                truncated_data = truncated_data.rsplit('{', 1)[0] + '\n... [data truncated for context limits]'
        else:
            truncated_data = '\n'.join(data_lines)
        
        return '\n'.join(instruction_lines) + '\n' + truncated_data
    
    async def wait_for_rate_limit(self, delay_seconds: float, reason: str = "Rate limit"):
        """Wait for rate limit with user-visible countdown."""
        self.retry_count += 1
        
        if self.display_callback:
            # Show initial rate limit message
            await self.display_callback(
                'rate_limit_start', 
                {
                    'delay': delay_seconds,
                    'reason': reason,
                    'retry_count': self.retry_count,
                    'max_retries': self.max_retries
                }
            )
        
        # Countdown timer
        end_time = time.time() + delay_seconds
        while time.time() < end_time:
            remaining = end_time - time.time()
            
            if self.display_callback and remaining > 0:
                await self.display_callback(
                    'rate_limit_countdown',
                    {
                        'remaining_seconds': remaining,
                        'total_seconds': delay_seconds,
                        'percentage': ((delay_seconds - remaining) / delay_seconds) * 100
                    }
                )
            
            await asyncio.sleep(min(1.0, remaining))
        
        if self.display_callback:
            await self.display_callback('rate_limit_complete', {'retry_count': self.retry_count})
    
    def should_retry(self, attempt: int) -> bool:
        """Determine if we should retry the request."""
        return attempt < self.max_retries
    
    def reset_retry_count(self):
        """Reset retry count after successful request."""
        self.retry_count = 0


class LLMClient(Protocol):
    """Protocol defining the interface for LLM clients."""
    
    async def generate_response(self, prompt: str, max_tokens: int = 1000) -> str:
        """Generate a response from the LLM."""
        ...
        
    async def analyze_data(self, data: dict, analysis_type: str) -> dict:
        """Analyze data using the LLM."""
        ...


class OpenAIClient:
    """OpenAI API client implementation with intelligent rate limiting."""

    # (base_url, model) -> signature of the request strategy that last succeeded,
    # so later calls skip known-incompatible parameter combinations.
    _preferred_strategies: Dict[tuple, tuple] = {}

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4",
                 endpoint_url: Optional[str] = None, rate_limit_display_callback=None,
                 tuning: Optional[Dict[str, Any]] = None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key required")
        self.model = model
        normalized_base_url = (endpoint_url or "https://api.openai.com/v1").rstrip("/")
        for suffix in ["/chat/completions", "/responses"]:
            if normalized_base_url.endswith(suffix):
                normalized_base_url = normalized_base_url[:-len(suffix)]
        if re.match(r"^https?://api\.openai\.com$", normalized_base_url, flags=re.IGNORECASE):
            normalized_base_url = f"{normalized_base_url}/v1"
        self.base_url = normalized_base_url
        self.rate_limit_manager = RateLimitManager(rate_limit_display_callback)
        self.model_capabilities = get_openai_model_capabilities(model)
        tuning = tuning if isinstance(tuning, dict) else {}
        default_timeout = 300 if self.model_capabilities.get("reasoning") else 120
        self.request_timeout = _positive_int(tuning.get("request_timeout"), default_timeout)
        effort = str(tuning.get("reasoning_effort") or "").strip().lower()
        self.reasoning_effort = (
            effort
            if effort in {"minimal", "low", "medium", "high"} and self.model_capabilities.get("reasoning")
            else None
        )

    def _normalize_messages(self, messages: list) -> list:
        normalized = []
        for message in messages or []:
            if not isinstance(message, dict):
                continue
            role = str(message.get("role", "user")).strip().lower()
            if role not in {"system", "user", "assistant"}:
                role = "user"

            content = message.get("content", "")
            if isinstance(content, list):
                content_parts = []
                for item in content:
                    if isinstance(item, dict):
                        text_value = item.get("text") or item.get("content") or item.get("value")
                        if isinstance(text_value, str) and text_value.strip():
                            content_parts.append(text_value.strip())
                    elif isinstance(item, str) and item.strip():
                        content_parts.append(item.strip())
                content = "\n".join(content_parts)

            content = str(content).strip()
            if not content:
                continue
            normalized.append({"role": role, "content": content})

        if not normalized:
            normalized = [{"role": "user", "content": "Hello"}]
        return normalized

    def _build_chat_payload(self, messages: list, max_tokens: int, temperature: float,
                            token_key: str, include_temperature: bool,
                            include_reasoning: bool = False) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": messages,
            token_key: max_tokens,
        }
        if include_temperature:
            payload["temperature"] = temperature
        if include_reasoning and self.reasoning_effort:
            payload["reasoning_effort"] = self.reasoning_effort
        return payload

    def _build_responses_payload(self, messages: list, max_tokens: int,
                                 temperature: float, include_temperature: bool,
                                 include_reasoning: bool = False) -> Dict[str, Any]:
        instructions = []
        dialogue = []
        for message in messages:
            role = str(message.get("role", "user")).strip().lower()
            content = str(message.get("content", "")).strip()
            if not content:
                continue
            if role == "system":
                instructions.append(content)
            else:
                dialogue.append({"role": "assistant" if role == "assistant" else "user", "content": content})

        if not dialogue:
            dialogue = [{"role": "user", "content": "Hello"}]

        payload = {
            "model": self.model,
            "input": dialogue,
            "max_output_tokens": max_tokens,
        }
        if instructions:
            payload["instructions"] = "\n\n".join(instructions)
        if include_temperature:
            payload["temperature"] = temperature
        if include_reasoning and self.reasoning_effort:
            payload["reasoning"] = {"effort": self.reasoning_effort}
        return payload

    def _build_openai_request_strategies(self, messages: list, max_tokens: int,
                                         temperature: float) -> list[Dict[str, Any]]:
        strategies = []
        seen = set()

        def add_strategy(mode: str, token_key: str, include_temperature: bool, include_reasoning: bool):
            signature = (mode, token_key, include_temperature, include_reasoning)
            if signature in seen:
                return
            seen.add(signature)

            if mode == "responses":
                payload = self._build_responses_payload(messages, max_tokens, temperature, include_temperature, include_reasoning)
                endpoint = f"{self.base_url}/responses"
            else:
                payload = self._build_chat_payload(messages, max_tokens, temperature, token_key, include_temperature, include_reasoning)
                endpoint = f"{self.base_url}/chat/completions"

            strategies.append({
                "mode": mode,
                "token_key": token_key,
                "include_temperature": include_temperature,
                "include_reasoning": include_reasoning,
                "signature": signature,
                "endpoint": endpoint,
                "payload": payload,
            })

        chat_token_keys = self.model_capabilities.get("chat_token_keys", ["max_tokens"])
        supports_temperature = bool(self.model_capabilities.get("supports_temperature", True)) and temperature is not None
        reasoning_options = [True, False] if self.reasoning_effort else [False]
        modes = ["responses", "chat"] if self.model_capabilities.get("prefers_responses_api") else ["chat", "responses"]

        for mode in modes:
            token_keys = ["max_output_tokens"] if mode == "responses" else chat_token_keys
            for token_key in token_keys:
                for include_reasoning in reasoning_options:
                    if supports_temperature:
                        add_strategy(mode, token_key, True, include_reasoning)
                    add_strategy(mode, token_key, False, include_reasoning)

        preferred = self._preferred_strategies.get((self.base_url, self.model))
        if preferred:
            strategies.sort(key=lambda item: 0 if item["signature"] == preferred else 1)
        return strategies

    def _should_try_next_strategy(self, status_code: int, error_text: str) -> bool:
        if status_code == 404:
            return True
        if status_code not in {400, 422}:
            return False

        lowered = (error_text or "").lower()
        compatibility_hints = [
            "unsupported parameter",
            "unknown parameter",
            "unrecognized request argument",
            "does not support",
            "not supported",
            "unsupported value",
            "use the responses api",
            "responses api",
            "chat.completions",
            "temperature",
            "max_tokens",
            "max_completion_tokens",
            "max_output_tokens",
            "reasoning",
            "instructions",
            "input",
            "messages",
        ]
        return any(hint in lowered for hint in compatibility_hints)

    @staticmethod
    def _output_budget_exhausted(response_data: Dict[str, Any]) -> bool:
        if not isinstance(response_data, dict):
            return False
        details = response_data.get("incomplete_details") if isinstance(response_data.get("incomplete_details"), dict) else {}
        if str(response_data.get("status") or "") == "incomplete" and "max_output" in str(details.get("reason") or ""):
            return True
        choices = response_data.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            return str(choices[0].get("finish_reason") or "") == "length"
        return False

    async def generate_response(self, prompt: str = None, messages: list = None, max_tokens: int = 1000, temperature: float = 0.7) -> str:
        """Generate response using OpenAI API with intelligent rate limiting.

        Args:
            prompt: Simple text prompt (legacy support)
            messages: List of message objects for chat format
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature; ``None`` omits it
        """
        if messages is None and prompt is not None:
            messages = [{"role": "user", "content": prompt}]
        elif messages is None and prompt is None:
            raise ValueError("Either 'prompt' or 'messages' must be provided")

        messages = self._normalize_messages(messages)
        max_tokens = _positive_int(max_tokens, 1000)
        budget_retry_used = False

        attempt = 0

        while attempt < self.rate_limit_manager.max_retries:
            try:
                adjusted_max_tokens = max_tokens
                if self.rate_limit_manager.current_limits:
                    budget_info = self.rate_limit_manager.update_request_budget(
                        self.rate_limit_manager.current_limits
                    )
                    adjusted_max_tokens = min(max_tokens, budget_info.get('recommended_max_tokens', max_tokens))

                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }

                request_strategies = self._build_openai_request_strategies(messages, adjusted_max_tokens, temperature)
                retry_loop = False
                last_error = None

                async with aiohttp.ClientSession() as session:
                    for strategy in request_strategies:
                        async with session.post(
                            strategy["endpoint"],
                            headers=headers,
                            json=strategy["payload"],
                            timeout=aiohttp.ClientTimeout(total=self.request_timeout)
                        ) as response:
                            if response.status == 200:
                                result = await response.json()
                                response_text = strip_reasoning_markup(extract_text_from_openai_response(result))
                                self._preferred_strategies[(self.base_url, self.model)] = strategy["signature"]
                                if response_text:
                                    self.rate_limit_manager.reset_retry_count()
                                    return response_text
                                if self._output_budget_exhausted(result) and not budget_retry_used and adjusted_max_tokens < 32000:
                                    # Reasoning tokens consumed the whole budget before any visible text.
                                    budget_retry_used = True
                                    max_tokens = min(32000, max(adjusted_max_tokens * 2, 4096))
                                    logger.info("OpenAI output budget exhausted for %s; retrying with max_tokens=%s", self.model, max_tokens)
                                    retry_loop = True
                                    break
                                raise Exception(f"OpenAI API returned an empty response payload for model {self.model}")

                            error_text = await response.text()

                            if response.status == 429:
                                rate_limit_info = self.rate_limit_manager.parse_rate_limit_error(error_text)

                                if not self.rate_limit_manager.should_retry(attempt):
                                    raise Exception(f"Max retries exceeded. Last error: {error_text}")

                                delay = self.rate_limit_manager.calculate_optimal_delay(rate_limit_info)
                                await self.rate_limit_manager.wait_for_rate_limit(
                                    delay,
                                    f"OpenAI rate limit (attempt {attempt + 1}/{self.rate_limit_manager.max_retries})"
                                )
                                attempt += 1
                                retry_loop = True
                                break

                            if response.status in {400, 422} and (
                                "context length" in error_text.lower()
                                or "maximum context" in error_text.lower()
                                or "too many tokens" in error_text.lower()
                                or "context_length_exceeded" in error_text.lower()
                            ):
                                truncation_info = self.rate_limit_manager.handle_context_length_error(error_text)

                                if not self.rate_limit_manager.should_retry(attempt):
                                    raise Exception(f"Max retries exceeded. Context length error: {error_text}")

                                messages = self._truncate_messages(messages, truncation_info)

                                if self.rate_limit_manager.display_callback:
                                    await self.rate_limit_manager.display_callback(
                                        'context_truncation',
                                        {
                                            'original_tokens': truncation_info.get('requested_tokens', 'unknown'),
                                            'max_tokens': truncation_info.get('max_context_tokens', 'unknown'),
                                            'attempt': attempt + 1
                                        }
                                    )

                                attempt += 1
                                retry_loop = True
                                break

                            if response.status in {401, 403}:
                                raise Exception(f"OpenAI API error {response.status}: {error_text}")

                            last_error = (
                                f"OpenAI {strategy['mode']} request failed for model {self.model} "
                                f"(status {response.status}, token_key={strategy['token_key']}, "
                                f"temperature={'on' if strategy['include_temperature'] else 'off'}, "
                                f"reasoning={'on' if strategy['include_reasoning'] else 'off'}): {error_text}"
                            )

                            if self._should_try_next_strategy(response.status, error_text):
                                logger.info("Retrying OpenAI request with alternate strategy after compatibility error: %s", last_error)
                                continue

                            raise Exception(last_error)

                if retry_loop:
                    continue

                if last_error:
                    raise Exception(last_error)

                raise Exception(f"OpenAI request failed without a usable strategy for model {self.model}")

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt >= self.rate_limit_manager.max_retries - 1:
                    raise Exception(f"Failed to generate OpenAI response after {attempt + 1} attempts: {e or 'request timed out'}")

                delay = self.rate_limit_manager.base_delay * (2 ** attempt)
                await self.rate_limit_manager.wait_for_rate_limit(
                    delay,
                    f"Network error retry (attempt {attempt + 1}/{self.rate_limit_manager.max_retries})"
                )
                attempt += 1
                continue
            except Exception as e:
                raise Exception(f"Failed to generate OpenAI response: {e}")

        raise Exception("Max retry attempts exceeded")

    def _truncate_messages(self, messages: list, truncation_info: Dict[str, Any]) -> list:
        """Truncate messages to fit within context limits, keeping system messages and the latest turn."""
        if not truncation_info.get('should_truncate_prompt'):
            return messages

        ratio = float(truncation_info.get('truncation_ratio', 0.6) or 0.6)
        ratio = max(0.1, min(ratio, 0.95))
        system_messages = [msg for msg in messages if msg.get('role') == 'system']
        other_messages = [msg for msg in messages if msg.get('role') != 'system']

        if len(other_messages) > 1:
            target_count = max(1, int(len(other_messages) * ratio))
            if target_count < len(other_messages):
                return system_messages + other_messages[-target_count:]

        # Too few turns to drop: shorten the longest message instead, keeping its start and end.
        shortened = [dict(msg) for msg in messages]
        longest_index = max(range(len(shortened)), key=lambda idx: len(str(shortened[idx].get('content', ''))))
        content = str(shortened[longest_index].get('content', ''))
        keep = max(200, int(len(content) * ratio))
        if keep < len(content):
            head = int(keep * 0.7)
            tail = keep - head
            shortened[longest_index]['content'] = (
                content[:head] + "\n...[content truncated to fit the model context]...\n" + content[-tail:]
            )
        return shortened

    async def analyze_data(self, data: dict, analysis_type: str) -> dict:
        """Analyze data using OpenAI."""
        prompt = self._build_analysis_prompt(data, analysis_type)
        max_tokens = ANALYSIS_REASONING_MAX_TOKENS if self.model_capabilities.get("reasoning") else ANALYSIS_MAX_TOKENS
        response = await self.generate_response(prompt, max_tokens=max_tokens, temperature=0.2)
        parsed = parse_json_from_llm_text(response)
        if parsed is not None:
            return parsed
        return {"analysis": response, "insights": ["Analysis completed"]}
    def _build_analysis_prompt(self, data: dict, analysis_type: str) -> str:
        return build_analysis_prompt(data, analysis_type)


class CustomLLMClient:
    """Custom LLM endpoint client using requests library for better Windows/vLLM compatibility."""
    
    # Class-level cache shared across all instances {endpoint_url: config_dict}
    _endpoint_cache = {}
    
    def __init__(self, endpoint_url: str, api_key: Optional[str] = None, model: str = "llama2",
                 rate_limit_display_callback: Optional[Callable] = None, provider: str = "custom",
                 tuning: Optional[Dict[str, Any]] = None):
        # Use the endpoint URL EXACTLY as configured by admin - no modifications
        self.endpoint_url = endpoint_url.rstrip('/')  # Only remove trailing slash
        self.api_key = api_key
        self.model = model
        self.rate_limit_display_callback = rate_limit_display_callback
        self.provider = normalize_provider_name(provider)
        tuning = tuning if isinstance(tuning, dict) else {}
        self.request_timeout = _positive_int(tuning.get("request_timeout"), 600)
        self.num_ctx = _positive_int(tuning.get("num_ctx"), 0) or None
        self.supports_temperature = tuning.get("supports_temperature", True) is not False
        think_setting = tuning.get("ollama_think")
        self.ollama_think = think_setting if isinstance(think_setting, (bool, str)) else None
        
        # Detect LLM provider type for connection strategy
        detected_provider_type = self._detect_provider(endpoint_url)
        self.provider_type = "ollama" if self.provider == "ollama" else detected_provider_type
        
        # Connection strategy: Some providers (vLLM) need fresh connections, others benefit from session reuse
        import requests
        if self.provider_type in ["vllm", "local-vllm"]:
            # vLLM has issues with persistent connections - use fresh connections
            self.session = None
            self.use_session = False
            logger.info(f"[CustomLLM] 🔧 Connection Strategy: FRESH (detected {self.provider_type})")
        else:
            # OpenAI, Anthropic, Ollama, etc. work well with persistent sessions
            self.session = requests.Session()
            self.use_session = True
            logger.info(f"[CustomLLM] 🔧 Connection Strategy: PERSISTENT (detected {self.provider_type})")
        
        # Health monitoring
        from llm.health_monitor import (
            get_health_monitor, 
            AdaptiveTimeoutManager, 
            HungRequestDetector,
            PayloadAdapter
        )
        self.health_monitor = get_health_monitor(endpoint_url)
        # Local runtimes are routinely slower than hosted APIs; slowness alone is not a failure.
        self.health_monitor.configure_thresholds(
            healthy_response_time=max(30.0, self.request_timeout * 0.5),
            degraded_response_time=max(120.0, float(self.request_timeout)),
        )
        self.timeout_manager = AdaptiveTimeoutManager(self.health_monitor, base_timeout=self.request_timeout)
        self.hung_detector = HungRequestDetector(no_progress_timeout=30)
        self.payload_adapter = PayloadAdapter(self.health_monitor)
        
        # Detect if this looks like a full API path or base URL (for format detection only)
        full_path_indicators = [
            '/v1/chat/completions',
            '/chat/completions',
            '/v1/completions',
            '/completions',
            '/api/chat',
            '/api/generate'
        ]
        self.is_full_path = any(self.endpoint_url.endswith(path) for path in full_path_indicators)
    
    def _detect_provider(self, endpoint_url: str) -> str:
        """
        Detect LLM provider type from endpoint URL.
        This determines the connection strategy and compatibility features.
        
        Returns:
            str: Provider type (vllm, ollama, openai, anthropic, cohere, local-vllm, generic)
        """
        url_lower = endpoint_url.lower()
        
        # vLLM detection (both cloud and local)
        if any(indicator in url_lower for indicator in ["vllm", "localhost:8000", "127.0.0.1:8000"]):
            if "localhost" in url_lower or "127.0.0.1" in url_lower:
                return "local-vllm"
            return "vllm"
        
        # Ollama detection
        if "ollama" in url_lower or ":11434" in url_lower:
            return "ollama"
        
        # OpenAI (official and compatible endpoints)
        if any(indicator in url_lower for indicator in ["openai.com", "api.openai", "openai-compatible"]):
            return "openai"
        
        # Anthropic
        if "anthropic" in url_lower or "claude" in url_lower:
            return "anthropic"
        
        # Cohere
        if "cohere" in url_lower:
            return "cohere"
        
        # HuggingFace Inference API
        if "huggingface" in url_lower or "hf.space" in url_lower:
            return "huggingface"
        
        # Replicate
        if "replicate" in url_lower:
            return "replicate"
        
        # Generic/Unknown
        return "generic"

    def _build_candidate_urls(self) -> list[str]:
        """Build candidate completion URLs from configured endpoint."""
        base = (self.endpoint_url or "").rstrip('/')
        if not base:
            return []

        full_path_indicators = [
            '/v1/chat/completions',
            '/chat/completions',
            '/v1/completions',
            '/completions',
            '/api/chat',
            '/api/generate'
        ]
        if any(base.endswith(path) for path in full_path_indicators):
            return [base]

        candidates = []

        if base.endswith('/v1'):
            candidates.extend([
                f"{base}/chat/completions",
                f"{base}/completions",
                base,
            ])
        elif self.provider_type == "ollama":
            # Native /api/chat honors num_ctx and num_predict; the OpenAI-compatible
            # route ignores them, which silently truncates long prompts on small defaults.
            candidates.extend([
                f"{base}/api/chat",
                f"{base}/v1/chat/completions",
                f"{base}/api/generate",
            ])
        else:
            candidates.extend([
                f"{base}/v1/chat/completions",
                f"{base}/chat/completions",
                f"{base}/v1/completions",
                f"{base}/completions",
                base,
            ])

        deduped = []
        seen = set()
        for url in candidates:
            if url not in seen:
                seen.add(url)
                deduped.append(url)
        return deduped

    def _infer_endpoint_format(self, candidate_url: str) -> str:
        """Infer request/response format from the resolved endpoint URL."""
        url = (candidate_url or "").rstrip('/').lower()

        if url.endswith('/api/chat'):
            return "Ollama Chat"
        if url.endswith('/api/generate'):
            return "Ollama Generate"
        if url.endswith('/v1/chat/completions') or url.endswith('/chat/completions'):
            return "OpenAI v1"
        if url.endswith('/v1/completions') or url.endswith('/completions'):
            if self.provider_type in ["vllm", "local-vllm"]:
                return "vLLM Completions"
            return "Generic Completions"

        if self.provider_type == "ollama":
            return "Ollama Chat"
        return "Generic Chat"

    def _is_recoverable_ollama_candidate_error(self, status_code: int, response_text: str) -> bool:
        """Return True when Ollama returned an endpoint-specific parse failure worth retrying elsewhere."""
        if self.provider_type != "ollama":
            return False
        if status_code < 500:
            return False

        response_preview = str(response_text or "").lower()
        return "error parsing tool call" in response_preview or "unexpected end of json input" in response_preview
    
    def generate_response_sync(self, messages: list, max_tokens: int = 1000, temperature: float = 0.7) -> str:
        """SYNCHRONOUS response generation with health monitoring."""
        import requests
        import time
        
        start_time = time.time()
        request_id = f"req_{int(start_time * 1000)}"
        
        # Check if we should attempt request
        if not self.health_monitor.should_attempt_request():
            logger.error(f"[CustomLLM-SYNC] ❌ Endpoint unhealthy (10+ consecutive failures), refusing request")
            raise Exception("LLM endpoint is unhealthy - too many consecutive failures")
        
        # Adapt payload based on endpoint health
        # Provider-specific timeout and payload strategy
        if self.provider_type in ["vllm", "local-vllm"]:
            # vLLM/Local LLM: Users are warned about long wait times via UI
            # Give generous 20-minute timeout - let LLM complete or fail naturally
            # No payload adaptation - send full context for best quality results
            
            # Always use full payload (users warned about wait times)
            adapted_messages = messages
            adapted_max_tokens = max_tokens
            
            # At least 20 minutes for local vLLM requests; the UI warns about long waits.
            request_timeout = max(1200, self.request_timeout)
            
            total_chars = sum(len(str(m.get('content', ''))) for m in adapted_messages)
            estimated_input_tokens = total_chars // 4
            estimated_total_tokens = estimated_input_tokens + adapted_max_tokens
            
            logger.info(f"[CustomLLM-SYNC] 🔧 vLLM/Local LLM Mode: Full payload, 20-minute timeout")
            logger.info(f"[CustomLLM-SYNC] � Sending ~{estimated_total_tokens} tokens ({len(adapted_messages)} messages)")
            logger.info(f"[CustomLLM-SYNC] ⏰ Timeout: {request_timeout}s (user warned via UI, can abort)")
        else:
            # Other providers use adaptive timeout and payload adaptation
            adapted_messages, adapted_max_tokens = self.payload_adapter.adapt_request(messages, max_tokens)
            estimated_tokens = sum(len(str(m.get('content', ''))) for m in adapted_messages) // 4
            request_timeout = self.timeout_manager.calculate_timeout(estimated_tokens)
            logger.info(f"[CustomLLM-SYNC] 🔧 Adaptive Mode: {request_timeout}s timeout")
        
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        prompt_text = self._messages_to_prompt(adapted_messages)
        
        logger.info(f"[CustomLLM-SYNC] 📊 Messages: {len(messages)} → {len(adapted_messages)}")
        logger.info(f"[CustomLLM-SYNC] � Max Tokens: {max_tokens} → {adapted_max_tokens}")
        
        try:
            logger.info(f"[CustomLLM-SYNC] ⏱️  {time.time()-start_time:.3f}s - Starting request {request_id}")
            candidate_urls = self._build_candidate_urls()
            logger.info(f"[CustomLLM-SYNC] 🌐 Candidate endpoints: {candidate_urls}")
            logger.info(f"[CustomLLM-SYNC] 📝 {len(adapted_messages)} messages, {sum(len(str(m.get('content',''))) for m in adapted_messages)} total chars")
            
            request_time = 0.0
            response = None
            last_error = None
            resolved_endpoint_format = None
            
            for candidate_url in candidate_urls:
                request_start = time.time()
                endpoint_format = self._infer_endpoint_format(candidate_url)
                payload = self._build_payload(
                    endpoint_format,
                    adapted_messages,
                    prompt_text,
                    adapted_max_tokens,
                    temperature,
                )
                logger.info(f"[CustomLLM-SYNC] ⏱️  {time.time()-start_time:.3f}s - Sending HTTP POST to {candidate_url}...")
                logger.info(f"[CustomLLM-SYNC] 🔧 Using {'PERSISTENT session' if self.use_session else 'FRESH connection'}")
                logger.info(f"[CustomLLM-SYNC] 🧭 Endpoint format: {endpoint_format}")

                try:
                    if self.use_session and self.session:
                        candidate_response = self.session.post(
                            candidate_url,
                            headers=headers,
                            json=payload,
                            timeout=request_timeout
                        )
                    else:
                        candidate_response = requests.post(
                            candidate_url,
                            headers=headers,
                            json=payload,
                            timeout=request_timeout
                        )
                    elapsed = time.time() - request_start
                    request_time += elapsed

                    if candidate_response.status_code in (404, 405):
                        logger.warning(f"[CustomLLM-SYNC] Endpoint not available ({candidate_response.status_code}): {candidate_url}")
                        last_error = Exception(f"HTTP {candidate_response.status_code} at {candidate_url}")
                        continue
                    if self._is_recoverable_ollama_candidate_error(candidate_response.status_code, candidate_response.text):
                        logger.warning(
                            f"[CustomLLM-SYNC] Recoverable Ollama endpoint error at {candidate_url}; trying next candidate"
                        )
                        last_error = Exception(
                            f"HTTP {candidate_response.status_code} recoverable Ollama error at {candidate_url}: {candidate_response.text[:200]}"
                        )
                        continue

                    response = candidate_response
                    resolved_endpoint_format = endpoint_format
                    if candidate_url != self.endpoint_url:
                        logger.info(f"[CustomLLM-SYNC] ✅ Resolved custom LLM endpoint to {candidate_url}")
                        self.endpoint_url = candidate_url
                    break
                except Exception as candidate_error:
                    elapsed = time.time() - request_start
                    request_time += elapsed
                    last_error = candidate_error
                    logger.warning(f"[CustomLLM-SYNC] Candidate failed ({candidate_url}): {candidate_error}")
                    continue

            if response is None:
                raise Exception(f"All endpoint candidates failed. Last error: {last_error}")
            
            logger.info(f"[CustomLLM-SYNC] ⏱️  {time.time()-start_time:.3f}s - HTTP response received (took {request_time:.3f}s)")
            logger.info(f"[CustomLLM-SYNC] 📥 Status: {response.status_code}")
            
            if response.status_code == 200:
                parse_start = time.time()
                data = response.json()
                parse_time = time.time() - parse_start
                logger.info(f"[CustomLLM-SYNC] ⏱️  JSON parsed in {parse_time:.3f}s")
                
                content = self._extract_response_content(data, resolved_endpoint_format or "OpenAI v1")
                total_time = time.time() - start_time
                
                # Record success in health monitor
                self.health_monitor.record_request(success=True, response_time=total_time, is_timeout=False)
                
                logger.info(f"[CustomLLM-SYNC] ✅ TOTAL TIME: {total_time:.3f}s (HTTP: {request_time:.3f}s, Parse: {parse_time:.3f}s)")
                logger.info(f"[CustomLLM-SYNC] ✅ Response: {len(content)} chars")
                logger.info(f"[CustomLLM-SYNC] 🏥 Health updated: {self.health_monitor.get_metrics().to_dict()}")
                return content
            else:
                error = f"HTTP {response.status_code}: {response.text[:200]}"
                elapsed = time.time() - start_time
                
                # Record failure
                is_timeout = response.status_code in [408, 504]
                self.health_monitor.record_request(success=False, response_time=elapsed, is_timeout=is_timeout)
                
                logger.error(f"[CustomLLM-SYNC] ❌ {error}")
                logger.error(f"[CustomLLM-SYNC] 🏥 Health degraded: {self.health_monitor.get_metrics().to_dict()}")
                raise Exception(error)
                
        except requests.exceptions.Timeout as e:
            elapsed = time.time() - start_time
            
            # Record timeout failure
            self.health_monitor.record_request(success=False, response_time=elapsed, is_timeout=True)
            
            logger.error(f"[CustomLLM-SYNC] ⏰ TIMEOUT after {elapsed:.3f}s (limit: {request_timeout}s)")
            logger.error(f"[CustomLLM-SYNC] 🏥 Health degraded: {self.health_monitor.get_metrics().to_dict()}")
            raise Exception(f"Request timeout after {elapsed:.1f}s (limit: {request_timeout}s)")
            
        except Exception as e:
            elapsed = time.time() - start_time
            
            # Record failure
            self.health_monitor.record_request(success=False, response_time=elapsed, is_timeout=False)
            
            logger.error(f"[CustomLLM-SYNC] ❌ Exception after {elapsed:.3f}s: {e}")
            logger.error(f"[CustomLLM-SYNC] 🏥 Health degraded: {self.health_monitor.get_metrics().to_dict()}")
            raise
    
    async def generate_response(self, prompt: str = None, messages: list = None, max_tokens: int = 1000, temperature: float = 0.7) -> str:
        """Generate response using custom LLM endpoint.
        
        Args:
            prompt: Simple text prompt (legacy support)
            messages: List of message objects for chat format
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
        """
        # Convert prompt to messages format if needed
        if messages is None and prompt is not None:
            messages = [{"role": "user", "content": prompt}]
        elif messages is None and prompt is None:
            raise ValueError("Either 'prompt' or 'messages' must be provided")
        
        # Run in thread pool to allow cancellation via asyncio
        # This allows the async task to be cancelled even though requests.post() is blocking
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.generate_response_sync, messages, max_tokens, temperature)
    
    def _messages_to_prompt(self, messages: list) -> str:
        """Convert messages to prompt text for completion-style endpoints, keeping speaker roles."""
        if not messages:
            return ""
        usable = [msg for msg in messages if isinstance(msg, dict) and str(msg.get("content", "")).strip()]
        if len(usable) == 1:
            return str(usable[0].get("content", "")).strip()
        prompt = messages_to_plain_text(usable)
        return f"{prompt}\n\nAssistant:" if prompt else ""

    def _ollama_options(self, max_tokens: int, temperature: Optional[float]) -> Dict[str, Any]:
        options: Dict[str, Any] = {"num_predict": max_tokens}
        if temperature is not None and self.supports_temperature:
            options["temperature"] = temperature
        if self.num_ctx:
            options["num_ctx"] = self.num_ctx
        return options
    
    def _build_payload(self, endpoint_format: str, messages: list, prompt_text: str, max_tokens: int, temperature: float) -> dict:
        """Build request payload for specific endpoint format."""
        # Clean and format messages to ensure they're valid
        formatted_messages = []
        for msg in messages:
            if isinstance(msg, dict) and "role" in msg and "content" in msg:
                # Ensure content is a string and clean it up
                content = str(msg["content"]).strip()
                formatted_messages.append({
                    "role": msg["role"],
                    "content": content
                })
        
        include_temperature = temperature is not None and self.supports_temperature

        if endpoint_format == "Ollama Chat":
            payload = {
                "model": self.model,
                "messages": formatted_messages,
                "stream": False,
                "options": self._ollama_options(max_tokens, temperature),
            }
            if self.ollama_think is not None:
                payload["think"] = self.ollama_think
            return payload
        if endpoint_format == "Ollama Generate":
            payload = {
                "model": self.model,
                "prompt": prompt_text,
                "stream": False,
                "options": self._ollama_options(max_tokens, temperature),
            }
            if self.ollama_think is not None:
                payload["think"] = self.ollama_think
            return payload
        if endpoint_format in ["vLLM Completions", "Generic Completions"]:
            payload = {"model": self.model, "prompt": prompt_text, "max_tokens": max_tokens, "stream": False}
        else:
            # OpenAI v1, LM Studio, Generic Chat, and unknown formats share the chat schema.
            payload = {"model": self.model, "messages": formatted_messages, "max_tokens": max_tokens, "stream": False}
        if include_temperature:
            payload["temperature"] = temperature
        return payload

    def _normalize_native_tool_call(self, tool_call: dict) -> Optional[dict]:
        """Convert native tool call payloads into the tagged chat-agent format."""
        if not isinstance(tool_call, dict):
            return None

        function = tool_call.get("function") if isinstance(tool_call.get("function"), dict) else {}
        raw_name = str(function.get("name") or tool_call.get("name") or "").strip()
        if raw_name.startswith("tool:"):
            raw_name = raw_name.split(":", 1)[1].strip()
        elif raw_name.startswith("tool."):
            raw_name = raw_name.split(".", 1)[1].strip()

        raw_arguments = function.get("arguments", tool_call.get("arguments"))
        if isinstance(raw_arguments, str):
            try:
                raw_arguments = json.loads(raw_arguments)
            except json.JSONDecodeError:
                raw_arguments = {"query": raw_arguments}

        if isinstance(raw_arguments, dict) and raw_arguments.get("tool") and isinstance(raw_arguments.get("args"), dict):
            return {
                "tool": str(raw_arguments.get("tool") or raw_name).strip(),
                "args": raw_arguments.get("args", {}),
            }

        if not raw_name:
            return None

        return {
            "tool": raw_name,
            "args": raw_arguments if isinstance(raw_arguments, dict) else {},
        }

    def _render_native_tool_calls(self, tool_calls: Any) -> str:
        """Render native tool calls as tagged text for the existing chat agent parser."""
        if not isinstance(tool_calls, list):
            return ""

        rendered_calls = []
        for tool_call in tool_calls:
            normalized = self._normalize_native_tool_call(tool_call)
            if not normalized:
                continue
            rendered_calls.append(f"<TOOL_CALL>{json.dumps(normalized, ensure_ascii=False)}</TOOL_CALL>")

        return "\n".join(rendered_calls)
    
    def _extract_response_content(self, response_data: dict, endpoint_format: str) -> str:
        """Extract the visible answer, dropping chain-of-thought blocks some models inline."""
        content = self._extract_raw_response_content(response_data, endpoint_format)
        cleaned = strip_reasoning_markup(content)
        if not cleaned and isinstance(response_data, dict):
            message = response_data.get("message")
            if not isinstance(message, dict):
                choices = response_data.get("choices") if isinstance(response_data.get("choices"), list) else []
                message = choices[0].get("message", {}) if choices and isinstance(choices[0], dict) else {}
            if isinstance(message, dict) and any(message.get(key) for key in ("thinking", "reasoning", "reasoning_content")):
                logger.warning(
                    "[CustomLLM] Model %s returned reasoning without a final answer; the output budget may be too small",
                    self.model,
                )
        return cleaned

    def _extract_raw_response_content(self, response_data: dict, endpoint_format: str) -> str:
        """Extract response content based on endpoint format."""
        try:
            if endpoint_format in ["OpenAI v1", "OpenAI", "LM Studio"]:
                message = response_data["choices"][0]["message"]
                content = message.get("content") or response_data.get("response", "")
                native_tool_calls = self._render_native_tool_calls(message.get("tool_calls"))
                if native_tool_calls and content:
                    return f"{native_tool_calls}\n\n{content}".strip()
                if native_tool_calls:
                    return native_tool_calls
                return content
            elif endpoint_format == "Ollama Chat":
                message = response_data.get("message", {}) if isinstance(response_data, dict) else {}
                content = message.get("content") or response_data.get("response", "")
                native_tool_calls = self._render_native_tool_calls(message.get("tool_calls"))
                if native_tool_calls and content:
                    return f"{native_tool_calls}\n\n{content}".strip()
                if native_tool_calls:
                    return native_tool_calls
                return content
            elif endpoint_format == "Ollama Generate":
                return response_data.get("response", "")
            elif endpoint_format == "vLLM Completions":
                return response_data["choices"][0]["text"]
            elif endpoint_format == "Generic Chat":
                return response_data.get("response") or response_data.get("content") or response_data.get("message", {}).get("content", "")
            elif endpoint_format == "Generic Completions":
                return response_data.get("text") or response_data.get("content") or response_data.get("response", "")
            else:
                # Default to OpenAI format
                return response_data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise ValueError(f"Failed to extract content from {endpoint_format} response: {str(e)}")
    
    async def _try_alternative_format(self, prompt: str, max_tokens: int) -> str:
        """Try alternative API formats for custom LLMs."""
        # Try Ollama format
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        
        headers = {"Content-Type": "application/json"}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.endpoint_url}/api/generate",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get("response", "No response from custom LLM")
                    else:
                        error_text = await response.text()
                        raise Exception(f"Custom LLM API error {response.status}: {error_text}")
        except Exception as e:
            raise Exception(f"Failed to connect to custom LLM: {e}")
        
    async def analyze_data(self, data: dict, analysis_type: str) -> dict:
        """Analyze data using custom LLM."""
        prompt = self._build_analysis_prompt(data, analysis_type)
        max_tokens = ANALYSIS_MAX_TOKENS
        num_ctx = getattr(self, "num_ctx", None)
        if num_ctx:
            # Leave most of a small local context window for the prompt itself.
            max_tokens = max(1024, min(max_tokens, num_ctx // 3))
        response = await self.generate_response(prompt, max_tokens=max_tokens, temperature=0.2)
        parsed = parse_json_from_llm_text(response)
        if parsed is not None:
            return parsed
        return {"analysis": response, "insights": ["Analysis completed"]}
    
    def _build_analysis_prompt(self, data: dict, analysis_type: str) -> str:
        return build_analysis_prompt(data, analysis_type)


class LLMClientFactory:
    """Factory for creating LLM clients with rate limit support."""

    @staticmethod
    def _normalize_azure_chat_url(endpoint_url: Optional[str], deployment_or_model: str) -> str:
        """Build an Azure OpenAI chat completions URL from base or full endpoint."""
        if not endpoint_url:
            raise ValueError("Azure provider requires endpoint_url")

        cleaned = endpoint_url.rstrip('/')
        if cleaned.endswith('/openai'):
            cleaned = cleaned[:-len('/openai')]
        if cleaned.endswith("/chat/completions"):
            return cleaned

        if "/openai/deployments/" in cleaned:
            return f"{cleaned}/chat/completions"

        deployment = deployment_or_model.strip()
        if not deployment:
            raise ValueError("Azure provider requires model/deployment name")
        return f"{cleaned}/openai/deployments/{deployment}/chat/completions"

    @staticmethod
    def _append_api_version(url: str, api_version: str = "2024-02-15-preview") -> str:
        if "api-version=" in url:
            return url
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}api-version={api_version}"

    @staticmethod
    def _normalize_anthropic_url(endpoint_url: Optional[str]) -> str:
        base = (endpoint_url or "https://api.anthropic.com").rstrip('/')
        if base.endswith("/v1/messages"):
            return base
        return f"{base}/v1/messages"

    @staticmethod
    def _normalize_gemini_url(endpoint_url: Optional[str], model: str) -> str:
        if endpoint_url and endpoint_url.strip():
            base = endpoint_url.rstrip('/')
            if ":generateContent" in base:
                return base
            if "/models/" in base:
                return f"{base}:generateContent"
            return f"{base}/v1beta/models/{quote(model)}:generateContent"
        return f"https://generativelanguage.googleapis.com/v1beta/models/{quote(model)}:generateContent"

    @staticmethod
    def _build_anthropic_messages(messages: list) -> tuple[str, list]:
        system_lines = []
        converted = []
        for msg in messages or []:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "user")).strip().lower()
            content = str(msg.get("content", "")).strip()
            if not content:
                continue
            if role == "system":
                system_lines.append(content)
                continue
            anthropic_role = "assistant" if role == "assistant" else "user"
            converted.append({"role": anthropic_role, "content": content})

        if not converted:
            converted = [{"role": "user", "content": "Hello"}]
        return ("\n\n".join(system_lines), converted)

    @staticmethod
    def _build_gemini_contents(messages: list) -> list:
        contents = []
        for msg in messages or []:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "user")).strip().lower()
            if role == "system":
                role = "user"
            gemini_role = "model" if role == "assistant" else "user"
            content = str(msg.get("content", "")).strip()
            if not content:
                continue
            contents.append({"role": gemini_role, "parts": [{"text": content}]})

        if not contents:
            contents = [{"role": "user", "parts": [{"text": "Hello"}]}]
        return contents

    @staticmethod
    def _extract_gemini_text(response_data: dict) -> str:
        candidates = response_data.get("candidates", []) if isinstance(response_data, dict) else []
        if not candidates:
            return ""
        first = candidates[0] if isinstance(candidates[0], dict) else {}
        content = first.get("content", {}) if isinstance(first, dict) else {}
        parts = content.get("parts", []) if isinstance(content, dict) else []
        texts = []
        for part in parts:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                texts.append(part.get("text"))
        return "\n".join([t for t in texts if t]).strip()

    @staticmethod
    def _normalize_chat_messages(messages: list) -> list:
        normalized = []
        for msg in messages or []:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "user")).strip().lower()
            if role not in {"system", "user", "assistant"}:
                role = "user"
            content = str(msg.get("content", "")).strip()
            if content:
                normalized.append({"role": role, "content": content})
        return normalized or [{"role": "user", "content": "Hello"}]

    @staticmethod
    async def _generate_azure_response(endpoint_url: str, api_key: str, model: str, messages: list,
                                       max_tokens: int, temperature: Optional[float],
                                       timeout: int = 120, reasoning_effort: Optional[str] = None) -> str:
        if not api_key:
            raise ValueError("Azure provider requires api_key")
        chat_url = LLMClientFactory._normalize_azure_chat_url(endpoint_url, model)
        reasoning_deployment = bool(get_openai_model_capabilities(model).get("reasoning"))
        # Reasoning deployments need max_completion_tokens, which older API versions reject.
        url = LLMClientFactory._append_api_version(
            chat_url, "2024-12-01-preview" if reasoning_deployment else "2024-02-15-preview"
        )
        headers = {
            "Content-Type": "application/json",
            "api-key": api_key,
        }

        attempts: list = []
        if reasoning_deployment:
            if reasoning_effort:
                attempts.append({"max_completion_tokens": max_tokens, "reasoning_effort": reasoning_effort})
            attempts.append({"max_completion_tokens": max_tokens})
        if temperature is not None and not reasoning_deployment:
            attempts.append({"max_tokens": max_tokens, "temperature": temperature})
        attempts.append({"max_tokens": max_tokens})
        attempts.append({"max_completion_tokens": max_tokens})
        unique_attempts = []
        for options in attempts:
            if options not in unique_attempts:
                unique_attempts.append(options)

        chat_messages = LLMClientFactory._normalize_chat_messages(messages)
        last_error = ""
        async with aiohttp.ClientSession() as session:
            for options in unique_attempts:
                payload = {"messages": chat_messages, **options}
                async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    if response.status == 200:
                        data = await response.json()
                        return strip_reasoning_markup(extract_text_from_openai_response(data))
                    body = await response.text()
                    last_error = f"Azure OpenAI error {response.status}: {body[:300]}"
                    lowered = body.lower()
                    if response.status in {400, 422} and any(
                        hint in lowered
                        for hint in ("max_tokens", "max_completion_tokens", "temperature", "reasoning_effort", "unsupported", "not supported")
                    ):
                        continue
                    raise Exception(last_error)
        raise Exception(last_error or "Azure OpenAI request failed")

    @staticmethod
    async def _generate_anthropic_response(endpoint_url: Optional[str], api_key: str, model: str, messages: list,
                                           max_tokens: int, temperature: Optional[float], timeout: int = 120) -> str:
        if not api_key:
            raise ValueError("Anthropic provider requires api_key")
        url = LLMClientFactory._normalize_anthropic_url(endpoint_url)
        system_prompt, anthropic_messages = LLMClientFactory._build_anthropic_messages(messages)
        if anthropic_messages and anthropic_messages[0]["role"] != "user":
            anthropic_messages.insert(0, {"role": "user", "content": "Continue the conversation."})
        payload = {
            "model": model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens,
        }
        if temperature is not None:
            payload["temperature"] = max(0.0, min(1.0, float(temperature)))
        if system_prompt:
            payload["system"] = system_prompt

        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                if response.status != 200:
                    body = await response.text()
                    raise Exception(f"Anthropic error {response.status}: {body[:300]}")
                data = await response.json()
                content_items = data.get("content", []) if isinstance(data, dict) else []
                text_parts = []
                for item in content_items:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text = item.get("text", "")
                        if isinstance(text, str) and text.strip():
                            text_parts.append(text)
                return strip_reasoning_markup("\n".join(text_parts))

    @staticmethod
    def _build_gemini_request(messages: list) -> tuple[str, list]:
        system_lines = []
        contents = []
        for msg in messages or []:
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "user")).strip().lower()
            content = str(msg.get("content", "")).strip()
            if not content:
                continue
            if role == "system":
                system_lines.append(content)
                continue
            contents.append({"role": "model" if role == "assistant" else "user", "parts": [{"text": content}]})
        if not contents:
            contents = [{"role": "user", "parts": [{"text": "Hello"}]}]
        return "\n\n".join(system_lines), contents

    @staticmethod
    async def _generate_gemini_response(endpoint_url: Optional[str], api_key: str, model: str, messages: list,
                                        max_tokens: int, temperature: Optional[float], timeout: int = 120) -> str:
        if not api_key:
            raise ValueError("Gemini provider requires api_key")
        base_url = LLMClientFactory._normalize_gemini_url(endpoint_url, model)
        url = base_url if "?key=" in base_url else f"{base_url}?key={quote(api_key)}"
        system_text, contents = LLMClientFactory._build_gemini_request(messages)

        model_lower = str(model or "").lower()
        thinking_model = bool(re.search(r"gemini-(2\.5|[3-9])", model_lower))
        generation_config: Dict[str, Any] = {"maxOutputTokens": max_tokens}
        if temperature is not None:
            generation_config["temperature"] = temperature
        if thinking_model:
            # Thinking tokens count against maxOutputTokens; reserve room for the visible answer.
            generation_config["maxOutputTokens"] = max(max_tokens, 2048)
            generation_config["thinkingConfig"] = {"thinkingBudget": max(128, min(2048, max_tokens // 4))}

        payload: Dict[str, Any] = {"contents": contents, "generationConfig": generation_config}
        if system_text:
            payload["systemInstruction"] = {"parts": [{"text": system_text}]}

        async with aiohttp.ClientSession() as session:
            for _ in range(2):
                async with session.post(url, headers={"Content-Type": "application/json"}, json=payload,
                                        timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    if response.status == 200:
                        data = await response.json()
                        return strip_reasoning_markup(LLMClientFactory._extract_gemini_text(data))
                    body = await response.text()
                    if response.status == 400 and "thinking" in body.lower() and "thinkingConfig" in generation_config:
                        generation_config.pop("thinkingConfig", None)
                        continue
                    raise Exception(f"Gemini error {response.status}: {body[:300]}")
        raise Exception("Gemini request failed")

    @staticmethod
    def create_client(provider: str = "openai", custom_endpoint: Optional[str] = None,
                     api_key: Optional[str] = None, model: str = "gpt-4",
                     rate_limit_display_callback=None,
                     tuning: Optional[Dict[str, Any]] = None) -> LLMClient:
        """
        Create an LLM client based on the specified provider.

        Args:
            provider: openai, azure, anthropic, gemini, ollama, or custom
            custom_endpoint: Required for azure and custom providers
            api_key: API key (OpenAI falls back to OPENAI_API_KEY)
            model: Model or deployment name
            rate_limit_display_callback: Optional callback for rate limit display
            tuning: Optional runtime settings from ``llm.model_profiles.recommend_settings``
                (request_timeout, reasoning_effort, num_ctx, ollama_think, supports_temperature)

        Returns:
            LLMClient instance

        Raises:
            ValueError: If invalid provider or missing requirements
        """
        normalized_provider = normalize_provider_name(provider)
        tuning = tuning if isinstance(tuning, dict) else {}

        if normalized_provider == "openai":
            return OpenAIClient(
                api_key=api_key,
                model=model,
                endpoint_url=custom_endpoint,
                rate_limit_display_callback=rate_limit_display_callback,
                tuning=tuning,
            )

        if normalized_provider == "custom":
            if not custom_endpoint:
                raise ValueError("Custom endpoint URL required for custom LLM provider")
            return CustomLLMClient(
                custom_endpoint,
                api_key=api_key,
                model=model,
                rate_limit_display_callback=rate_limit_display_callback,
                provider="custom",
                tuning=tuning,
            )

        if normalized_provider == "ollama":
            return CustomLLMClient(
                normalize_ollama_endpoint_url(custom_endpoint),
                api_key=api_key,
                model=model,
                rate_limit_display_callback=rate_limit_display_callback,
                provider="ollama",
                tuning=tuning,
            )

        if normalized_provider in {"azure", "anthropic", "gemini"}:
            class _ProviderAdapter:
                def __init__(self, provider_name: str, endpoint: Optional[str], key: Optional[str], model_name: str,
                             adapter_tuning: Dict[str, Any]):
                    self.provider_name = provider_name
                    self.provider_type = provider_name
                    self.endpoint = endpoint
                    self.key = key
                    self.model_name = model_name
                    self.model = model_name
                    self.request_timeout = _positive_int(adapter_tuning.get("request_timeout"), 120)
                    self.reasoning_effort = adapter_tuning.get("reasoning_effort")
                    self.supports_temperature = adapter_tuning.get("supports_temperature", True) is not False

                async def generate_response(self, prompt: str = None, messages: list = None,
                                            max_tokens: int = 1000, temperature: float = 0.7) -> str:
                    if messages is None:
                        if prompt is None:
                            raise ValueError("Either 'prompt' or 'messages' must be provided")
                        messages = [{"role": "user", "content": prompt}]
                    effective_temperature = temperature if self.supports_temperature else None

                    if self.provider_name == "azure":
                        return await LLMClientFactory._generate_azure_response(
                            endpoint_url=self.endpoint or "",
                            api_key=self.key or "",
                            model=self.model_name,
                            messages=messages,
                            max_tokens=max_tokens,
                            temperature=effective_temperature,
                            timeout=self.request_timeout,
                            reasoning_effort=self.reasoning_effort,
                        )

                    if self.provider_name == "anthropic":
                        return await LLMClientFactory._generate_anthropic_response(
                            endpoint_url=self.endpoint,
                            api_key=self.key or "",
                            model=self.model_name,
                            messages=messages,
                            max_tokens=max_tokens,
                            temperature=effective_temperature,
                            timeout=self.request_timeout,
                        )

                    return await LLMClientFactory._generate_gemini_response(
                        endpoint_url=self.endpoint,
                        api_key=self.key or "",
                        model=self.model_name,
                        messages=messages,
                        max_tokens=max_tokens,
                        temperature=effective_temperature,
                        timeout=self.request_timeout,
                    )

                async def analyze_data(self, data: dict, analysis_type: str) -> dict:
                    prompt = build_analysis_prompt(data, analysis_type)
                    response = await self.generate_response(prompt=prompt, max_tokens=ANALYSIS_MAX_TOKENS, temperature=0.2)
                    parsed = parse_json_from_llm_text(response)
                    if parsed is not None:
                        return parsed
                    return {"analysis": response, "insights": ["Analysis completed"]}

            return _ProviderAdapter(
                provider_name=normalized_provider,
                endpoint=custom_endpoint,
                key=api_key,
                model_name=model,
                adapter_tuning=tuning,
            )

        raise ValueError(f"Unsupported LLM provider: {provider}")
    @staticmethod
    def get_available_providers() -> list[str]:
        """Get list of available LLM providers."""
        return ["openai", "azure", "anthropic", "gemini", "ollama", "custom"]
