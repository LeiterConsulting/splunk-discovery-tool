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
        "custom": "custom",
        "custom endpoint": "custom",
    }
    return aliases.get(value, value)


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
    supports_temperature = not model_lower.startswith(("o1", "o3", "o4"))

    chat_token_keys = ["max_tokens"]
    if any(hint in model_lower for hint in OPENAI_CHAT_COMPLETION_NEW_TOKEN_HINTS):
        chat_token_keys = ["max_completion_tokens", "max_tokens"]

    return {
        "model": model,
        "supports_generation": is_openai_generation_model(model),
        "supports_image_generation": is_openai_image_generation_model(model),
        "prefers_responses_api": prefers_responses_api,
        "supports_temperature": supports_temperature,
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
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4",
                 endpoint_url: Optional[str] = None, rate_limit_display_callback=None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key required")
        self.model = model
        normalized_base_url = (endpoint_url or "https://api.openai.com/v1").rstrip("/")
        for suffix in ["/chat/completions", "/responses"]:
            if normalized_base_url.endswith(suffix):
                normalized_base_url = normalized_base_url[:-len(suffix)]
        self.base_url = normalized_base_url
        self.rate_limit_manager = RateLimitManager(rate_limit_display_callback)
        self.model_capabilities = get_openai_model_capabilities(model)

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
                            token_key: str, include_temperature: bool) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": messages,
            token_key: max_tokens,
        }
        if include_temperature:
            payload["temperature"] = temperature
        return payload

    def _build_responses_payload(self, messages: list, max_tokens: int,
                                 temperature: float, include_temperature: bool) -> Dict[str, Any]:
        instructions = []
        dialogue_lines = []
        for message in messages:
            role = str(message.get("role", "user")).strip().lower()
            content = str(message.get("content", "")).strip()
            if not content:
                continue
            if role == "system":
                instructions.append(content)
            elif role == "assistant":
                dialogue_lines.append(f"Assistant: {content}")
            else:
                dialogue_lines.append(f"User: {content}")

        if not dialogue_lines:
            dialogue_lines = ["User: Hello"]

        payload = {
            "model": self.model,
            "input": "\n\n".join(dialogue_lines),
            "max_output_tokens": max_tokens,
        }
        if instructions:
            payload["instructions"] = "\n\n".join(instructions)
        if include_temperature:
            payload["temperature"] = temperature
        return payload

    def _build_openai_request_strategies(self, messages: list, max_tokens: int,
                                         temperature: float) -> list[Dict[str, Any]]:
        strategies = []
        seen = set()

        def add_strategy(mode: str, token_key: str, include_temperature: bool):
            signature = (mode, token_key, include_temperature)
            if signature in seen:
                return
            seen.add(signature)

            if mode == "responses":
                payload = self._build_responses_payload(messages, max_tokens, temperature, include_temperature)
                endpoint = f"{self.base_url}/responses"
            else:
                payload = self._build_chat_payload(messages, max_tokens, temperature, token_key, include_temperature)
                endpoint = f"{self.base_url}/chat/completions"

            strategies.append({
                "mode": mode,
                "token_key": token_key,
                "include_temperature": include_temperature,
                "endpoint": endpoint,
                "payload": payload,
            })

        chat_token_keys = self.model_capabilities.get("chat_token_keys", ["max_tokens"])
        supports_temperature = bool(self.model_capabilities.get("supports_temperature", True))

        if self.model_capabilities.get("prefers_responses_api"):
            if supports_temperature:
                add_strategy("responses", "max_output_tokens", True)
            add_strategy("responses", "max_output_tokens", False)

            for token_key in chat_token_keys:
                if supports_temperature:
                    add_strategy("chat", token_key, True)
                add_strategy("chat", token_key, False)
        else:
            for token_key in chat_token_keys:
                if supports_temperature:
                    add_strategy("chat", token_key, True)
                add_strategy("chat", token_key, False)

            if supports_temperature:
                add_strategy("responses", "max_output_tokens", True)
            add_strategy("responses", "max_output_tokens", False)

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
            "does not support",
            "not supported",
            "use the responses api",
            "responses api",
            "chat.completions",
            "temperature",
            "max_tokens",
            "max_completion_tokens",
            "max_output_tokens",
            "instructions",
            "input",
            "messages",
        ]
        return any(hint in lowered for hint in compatibility_hints)
            
    async def generate_response(self, prompt: str = None, messages: list = None, max_tokens: int = 1000, temperature: float = 0.7) -> str:
        """Generate response using OpenAI API with intelligent rate limiting.
        
        Args:
            prompt: Simple text prompt (legacy support)
            messages: List of message objects for chat format
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
        """
        if messages is None and prompt is not None:
            # Legacy format: convert prompt to messages
            messages = [{"role": "user", "content": prompt}]
        elif messages is None and prompt is None:
            raise ValueError("Either 'prompt' or 'messages' must be provided")

        messages = self._normalize_messages(messages)
        
        attempt = 0
        
        while attempt < self.rate_limit_manager.max_retries:
            try:
                # Only adjust max_tokens if we have actual rate limit data
                # Skip budget calculation for normal requests (performance optimization)
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
                rate_limited = False
                last_error = None

                async with aiohttp.ClientSession() as session:
                    for strategy in request_strategies:
                        async with session.post(
                            strategy["endpoint"],
                            headers=headers,
                            json=strategy["payload"],
                            timeout=aiohttp.ClientTimeout(total=60)
                        ) as response:
                            if response.status == 200:
                                result = await response.json()
                                response_text = extract_text_from_openai_response(result)
                                if response_text:
                                    self.rate_limit_manager.reset_retry_count()
                                    return response_text
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
                                rate_limited = True
                                break

                            if response.status in {400, 422} and (
                                "context length" in error_text.lower()
                                or "maximum context" in error_text.lower()
                                or "too many tokens" in error_text.lower()
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
                                rate_limited = True
                                break

                            if response.status in {401, 403}:
                                raise Exception(f"OpenAI API error {response.status}: {error_text}")

                            last_error = (
                                f"OpenAI {strategy['mode']} request failed for model {self.model} "
                                f"(status {response.status}, token_key={strategy['token_key']}, "
                                f"temperature={'on' if strategy['include_temperature'] else 'off'}): {error_text}"
                            )

                            if self._should_try_next_strategy(response.status, error_text):
                                logger.info("Retrying OpenAI request with alternate strategy after compatibility error: %s", last_error)
                                continue

                            raise Exception(last_error)

                if rate_limited:
                    continue

                if last_error:
                    raise Exception(last_error)

                raise Exception(f"OpenAI request failed without a usable strategy for model {self.model}")
                            
            except aiohttp.ClientError as e:
                if attempt >= self.rate_limit_manager.max_retries - 1:
                    raise Exception(f"Failed to generate OpenAI response after {attempt + 1} attempts: {e}")
                
                # Network error - use exponential backoff
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
        """Truncate messages to fit within context limits."""
        if not truncation_info.get('should_truncate_prompt'):
            return messages
            
        # Always keep the system message if present
        system_messages = [msg for msg in messages if msg.get('role') == 'system']
        other_messages = [msg for msg in messages if msg.get('role') != 'system']
        
        # Calculate target length for other messages
        ratio = truncation_info.get('truncation_ratio', 0.6)
        target_count = max(1, int(len(other_messages) * ratio))
        
        # Keep the most recent messages (preserve conversation flow)
        truncated_messages = other_messages[-target_count:] if target_count < len(other_messages) else other_messages
        
        return system_messages + truncated_messages
        
    async def analyze_data(self, data: dict, analysis_type: str) -> dict:
        """Analyze data using OpenAI."""
        prompt = self._build_analysis_prompt(data, analysis_type)
        response = await self.generate_response(prompt, max_tokens=2000)
        
        # Try to parse JSON response, handling markdown code blocks
        try:
            # Clean up response - remove markdown code blocks if present
            cleaned_response = response.strip()
            if cleaned_response.startswith('```'):
                # Remove opening ```json or ```
                lines = cleaned_response.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                # Remove closing ```
                if lines and lines[-1].strip() == '```':
                    lines = lines[:-1]
                cleaned_response = '\n'.join(lines)
            
            return json.loads(cleaned_response)
        except json.JSONDecodeError:
            # If still can't parse, return as text analysis
            return {"analysis": response, "insights": ["Analysis completed"]}
    
    def _build_analysis_prompt(self, data: dict, analysis_type: str) -> str:
        """Build analysis prompt for different types of analysis."""
        # Add current context information
        current_time = datetime.now()
        current_year = current_time.year
        time_context = f"""
IMPORTANT CONTEXT: The current date and time is {current_time.strftime('%Y-%m-%d %H:%M:%S')} UTC. 
We are currently in the year {current_year}. Any timestamps showing {current_year} are NOT future events - they are current or recent events.
When analyzing temporal patterns, consider that {current_year} events are happening now or in the recent past.

"""
        
        if analysis_type == "classification":
            return time_context + f"""
Analyze the following Splunk data and classify it into categories:

Data: {json.dumps(data, indent=2)}

Please classify this data into categories like:
- Security (authentication, firewall, intrusion detection)
- Infrastructure (system logs, performance metrics)
- Business (application logs, user activity)
- Compliance (audit logs, regulatory data)

Return a JSON response with the classification results.
"""
        elif analysis_type == "recommendations":
            return time_context + f"""
Based on the following Splunk environment analysis, generate use case recommendations:

Analysis: {json.dumps(data, indent=2)}

Generate specific use case recommendations with:
- Title and description
- Priority (high/medium/low)
- Category
- ROI estimate
- Implementation complexity

Return a JSON array of recommendations.
"""
        elif analysis_type == "creative_use_cases":
            return time_context + f"""
Based on the following Splunk environment data, generate creative, cross-functional use cases that combine multiple data sources:

Environment Analysis: {json.dumps(data, indent=2)}

{data.get('prompt_guidance', '')}

Generate innovative use cases that:
1. Combine at least 2 different data source types
2. Address real business challenges
3. Provide measurable value
4. Consider implementation complexity

For each use case, provide:
- Title: Clear, business-focused name
- Description: Detailed explanation of the use case
- Data Sources: List of required data sources
- Business Value: Expected outcomes and benefits  
- Implementation Complexity: Low/Medium/High with reasoning
- Success Metrics: How to measure success
- Scenario: Real-world example of how it works
- Category: Business area (Security, Operations, Analytics, etc.)

Think creatively about scenarios like:
- User behavior correlation across systems
- Anomaly detection using multiple data streams
- Business intelligence from operational data
- Risk assessment from behavioral patterns
- Compliance automation across departments

Return a JSON array with structured use case objects.
"""
        elif analysis_type == "patterns":
            return time_context + f"""
Analyze the following Splunk data to identify notable patterns and insights:

Data: {json.dumps(data, indent=2)}

Identify patterns in:
- Data volume and distribution
- Source types and their characteristics  
- Index usage patterns
- Temporal patterns (remember: we are in {current_year}, so {current_year} timestamps are current!)
- Data quality indicators

Return insights as a JSON object with a 'patterns' array.
"""
        else:
            return time_context + f"Analyze this Splunk data for {analysis_type}: {json.dumps(data, indent=2)}"


class CustomLLMClient:
    """Custom LLM endpoint client using requests library for better Windows/vLLM compatibility."""
    
    # Class-level cache shared across all instances {endpoint_url: config_dict}
    _endpoint_cache = {}
    
    def __init__(self, endpoint_url: str, api_key: Optional[str] = None, model: str = "llama2",
                 rate_limit_display_callback: Optional[Callable] = None, provider: str = "custom"):
        # Use the endpoint URL EXACTLY as configured by admin - no modifications
        self.endpoint_url = endpoint_url.rstrip('/')  # Only remove trailing slash
        self.api_key = api_key
        self.model = model
        self.rate_limit_display_callback = rate_limit_display_callback
        self.provider = normalize_provider_name(provider)
        
        # Detect LLM provider type for connection strategy
        self.provider_type = self._detect_provider(endpoint_url)
        
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
        
        # Health monitoring (v1.1.0)
        from llm.health_monitor import (
            get_health_monitor, 
            AdaptiveTimeoutManager, 
            HungRequestDetector,
            PayloadAdapter
        )
        self.health_monitor = get_health_monitor(endpoint_url)
        self.timeout_manager = AdaptiveTimeoutManager(self.health_monitor)
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
    
    def generate_response_sync(self, messages: list, max_tokens: int = 1000, temperature: float = 0.7) -> str:
        """SYNCHRONOUS response generation with health monitoring (v1.1.0)."""
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
            
            # Fixed 20-minute timeout for all local LLM requests
            # User has been warned via UI and can abort if needed
            request_timeout = 1200  # 20 minutes
            
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
        
        payload = {
            "model": self.model,
            "messages": adapted_messages,
            "max_tokens": adapted_max_tokens,
            "temperature": temperature,
            "stream": False
        }
        
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
            
            for candidate_url in candidate_urls:
                request_start = time.time()
                logger.info(f"[CustomLLM-SYNC] ⏱️  {time.time()-start_time:.3f}s - Sending HTTP POST to {candidate_url}...")
                logger.info(f"[CustomLLM-SYNC] 🔧 Using {'PERSISTENT session' if self.use_session else 'FRESH connection'}")

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

                    if candidate_response.status_code == 404:
                        logger.warning(f"[CustomLLM-SYNC] Endpoint not found: {candidate_url}")
                        last_error = Exception(f"HTTP 404 at {candidate_url}")
                        continue

                    response = candidate_response
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
                
                content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
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
        """Convert messages format to simple prompt text."""
        if not messages:
            return ""
        # Join all user messages
        return "\n\n".join([msg.get("content", "") for msg in messages if msg.get("role") in ["user", "system"]])
    
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
        
        if endpoint_format in ["OpenAI v1", "OpenAI"]:
            # Always explicitly disable streaming for compatibility
            return {
                "model": self.model,
                "messages": formatted_messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "stream": False
            }
        elif endpoint_format == "LM Studio":
            return {
                "model": self.model,
                "messages": formatted_messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "stream": False
            }
        elif endpoint_format == "Ollama Chat":
            return {"model": self.model, "messages": formatted_messages, "stream": False}
        elif endpoint_format == "Ollama Generate":
            return {"model": self.model, "prompt": prompt_text, "stream": False}
        elif endpoint_format in ["vLLM Completions", "Generic Completions"]:
            return {"model": self.model, "prompt": prompt_text, "max_tokens": max_tokens, "temperature": temperature, "stream": False}
        elif endpoint_format == "Generic Chat":
            return {"model": self.model, "messages": formatted_messages, "max_tokens": max_tokens, "temperature": temperature, "stream": False}
        else:
            # Default to OpenAI format with stream disabled
            return {
                "model": self.model,
                "messages": formatted_messages,
                "max_tokens": max_tokens,
                "temperature": temperature,
                "stream": False
            }
    
    def _extract_response_content(self, response_data: dict, endpoint_format: str) -> str:
        """Extract response content based on endpoint format."""
        try:
            if endpoint_format in ["OpenAI v1", "OpenAI", "LM Studio"]:
                return response_data["choices"][0]["message"]["content"]
            elif endpoint_format == "Ollama Chat":
                return response_data["message"]["content"]
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
        response = await self.generate_response(prompt, max_tokens=2000)
        
        # Try to parse JSON response, handling markdown code blocks
        try:
            # Clean up response - remove markdown code blocks if present
            cleaned_response = response.strip()
            if cleaned_response.startswith('```'):
                # Remove opening ```json or ```
                lines = cleaned_response.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                # Remove closing ```
                if lines and lines[-1].strip() == '```':
                    lines = lines[:-1]
                cleaned_response = '\n'.join(lines)
            
            return json.loads(cleaned_response)
        except json.JSONDecodeError:
            # If still can't parse, return as text analysis
            return {"analysis": response, "insights": ["Analysis completed"]}
    
    def _build_analysis_prompt(self, data: dict, analysis_type: str) -> str:
        """Build analysis prompt for different types of analysis."""
        # Add current context information
        current_time = datetime.now()
        current_year = current_time.year
        time_context = f"""
IMPORTANT CONTEXT: The current date and time is {current_time.strftime('%Y-%m-%d %H:%M:%S')} UTC. 
We are currently in the year {current_year}. Any timestamps showing {current_year} are NOT future events - they are current or recent events.
When analyzing temporal patterns, consider that {current_year} events are happening now or in the recent past.

"""
        
        if analysis_type == "classification":
            return time_context + f"""
Analyze the following Splunk data and classify it into categories:

Data: {json.dumps(data, indent=2)}

Please classify this data into categories like:
- Security (authentication, firewall, intrusion detection)
- Infrastructure (system logs, performance metrics)
- Business (application logs, user activity)
- Compliance (audit logs, regulatory data)

Return a JSON response with the classification results.
"""
        elif analysis_type == "recommendations":
            return time_context + f"""
Based on the following Splunk environment analysis, generate use case recommendations:

Analysis: {json.dumps(data, indent=2)}

Generate specific use case recommendations with:
- Title and description
- Priority (high/medium/low)
- Category
- ROI estimate
- Implementation complexity

Return a JSON array of recommendations.
"""
        elif analysis_type == "creative_use_cases":
            return time_context + f"""
Based on the following Splunk environment data, generate creative, cross-functional use cases that combine multiple data sources:

Environment Analysis: {json.dumps(data, indent=2)}

{data.get('prompt_guidance', '')}

Generate innovative use cases that:
1. Combine at least 2 different data source types
2. Address real business challenges
3. Provide measurable value
4. Consider implementation complexity

For each use case, provide:
- Title: Clear, business-focused name
- Description: Detailed explanation of the use case
- Data Sources: List of required data sources
- Business Value: Expected outcomes and benefits  
- Implementation Complexity: Low/Medium/High with reasoning
- Success Metrics: How to measure success
- Scenario: Real-world example of how it works
- Category: Business area (Security, Operations, Analytics, etc.)

Think creatively about scenarios like:
- User behavior correlation across systems
- Anomaly detection using multiple data streams
- Business intelligence from operational data
- Risk assessment from behavioral patterns
- Compliance automation across departments

Return a JSON array with structured use case objects.
"""
        elif analysis_type == "patterns":
            return time_context + f"""
Analyze the following Splunk data to identify notable patterns and insights:

Data: {json.dumps(data, indent=2)}

Identify patterns in:
- Data volume and distribution
- Source types and their characteristics  
- Index usage patterns
- Temporal patterns (remember: we are in {current_year}, so {current_year} timestamps are current!)
- Data quality indicators

Return insights as a JSON object with a 'patterns' array.
"""
        else:
            return time_context + f"Analyze this Splunk data for {analysis_type}: {json.dumps(data, indent=2)}"


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
    async def _generate_azure_response(endpoint_url: str, api_key: str, model: str, messages: list,
                                       max_tokens: int, temperature: float) -> str:
        if not api_key:
            raise ValueError("Azure provider requires api_key")
        url = LLMClientFactory._append_api_version(
            LLMClientFactory._normalize_azure_chat_url(endpoint_url, model)
        )
        headers = {
            "Content-Type": "application/json",
            "api-key": api_key,
        }
        payload = {
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=60)) as response:
                if response.status != 200:
                    body = await response.text()
                    raise Exception(f"Azure OpenAI error {response.status}: {body[:300]}")
                data = await response.json()
                return data.get("choices", [{}])[0].get("message", {}).get("content", "")

    @staticmethod
    async def _generate_anthropic_response(endpoint_url: Optional[str], api_key: str, model: str, messages: list,
                                           max_tokens: int, temperature: float) -> str:
        if not api_key:
            raise ValueError("Anthropic provider requires api_key")
        url = LLMClientFactory._normalize_anthropic_url(endpoint_url)
        system_prompt, anthropic_messages = LLMClientFactory._build_anthropic_messages(messages)
        payload = {
            "model": model,
            "messages": anthropic_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system_prompt:
            payload["system"] = system_prompt

        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload, timeout=aiohttp.ClientTimeout(total=60)) as response:
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
                return "\n".join(text_parts).strip()

    @staticmethod
    async def _generate_gemini_response(endpoint_url: Optional[str], api_key: str, model: str, messages: list,
                                        max_tokens: int, temperature: float) -> str:
        if not api_key:
            raise ValueError("Gemini provider requires api_key")
        base_url = LLMClientFactory._normalize_gemini_url(endpoint_url, model)
        url = base_url if "?key=" in base_url else f"{base_url}?key={quote(api_key)}"
        payload = {
            "contents": LLMClientFactory._build_gemini_contents(messages),
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            }
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers={"Content-Type": "application/json"}, json=payload,
                                    timeout=aiohttp.ClientTimeout(total=60)) as response:
                if response.status != 200:
                    body = await response.text()
                    raise Exception(f"Gemini error {response.status}: {body[:300]}")
                data = await response.json()
                return LLMClientFactory._extract_gemini_text(data)
    
    @staticmethod
    def create_client(provider: str = "openai", custom_endpoint: Optional[str] = None, 
                     api_key: Optional[str] = None, model: str = "gpt-4",
                     rate_limit_display_callback=None) -> LLMClient:
        """
        Create an LLM client based on the specified provider.
        
        Args:
            provider: Either "openai" or "custom"
            custom_endpoint: Required if provider is "custom"
            api_key: API key for OpenAI (optional, will use env var if not provided)
            model: Model name for OpenAI (default: gpt-4)
            rate_limit_display_callback: Optional callback for rate limit display
            
        Returns:
            LLMClient instance
            
        Raises:
            ValueError: If invalid provider or missing requirements
        """
        normalized_provider = normalize_provider_name(provider)

        if normalized_provider == "openai":
            return OpenAIClient(
                api_key=api_key,
                model=model,
                endpoint_url=custom_endpoint,
                rate_limit_display_callback=rate_limit_display_callback,
            )

        if normalized_provider == "custom":
            if not custom_endpoint:
                raise ValueError("Custom endpoint URL required for custom LLM provider")
            return CustomLLMClient(
                custom_endpoint,
                api_key=api_key,
                model=model,
                rate_limit_display_callback=rate_limit_display_callback,
                provider="custom"
            )

        if normalized_provider in {"azure", "anthropic", "gemini"}:
            class _ProviderAdapter:
                def __init__(self, provider_name: str, endpoint: Optional[str], key: Optional[str], model_name: str):
                    self.provider_name = provider_name
                    self.endpoint = endpoint
                    self.key = key
                    self.model_name = model_name

                async def generate_response(self, prompt: str = None, messages: list = None,
                                            max_tokens: int = 1000, temperature: float = 0.7) -> str:
                    if messages is None:
                        if prompt is None:
                            raise ValueError("Either 'prompt' or 'messages' must be provided")
                        messages = [{"role": "user", "content": prompt}]

                    if self.provider_name == "azure":
                        return await LLMClientFactory._generate_azure_response(
                            endpoint_url=self.endpoint or "",
                            api_key=self.key or "",
                            model=self.model_name,
                            messages=messages,
                            max_tokens=max_tokens,
                            temperature=temperature,
                        )

                    if self.provider_name == "anthropic":
                        return await LLMClientFactory._generate_anthropic_response(
                            endpoint_url=self.endpoint,
                            api_key=self.key or "",
                            model=self.model_name,
                            messages=messages,
                            max_tokens=max_tokens,
                            temperature=temperature,
                        )

                    return await LLMClientFactory._generate_gemini_response(
                        endpoint_url=self.endpoint,
                        api_key=self.key or "",
                        model=self.model_name,
                        messages=messages,
                        max_tokens=max_tokens,
                        temperature=temperature,
                    )

                async def analyze_data(self, data: dict, analysis_type: str) -> dict:
                    prompt = f"Analyze this Splunk data for {analysis_type}: {json.dumps(data, indent=2)}"
                    response = await self.generate_response(prompt=prompt, max_tokens=2000)
                    try:
                        return json.loads(response)
                    except json.JSONDecodeError:
                        return {"analysis": response, "insights": ["Analysis completed"]}

            return _ProviderAdapter(
                provider_name=normalized_provider,
                endpoint=custom_endpoint,
                key=api_key,
                model_name=model,
            )

        raise ValueError(f"Unsupported LLM provider: {provider}")
            
    @staticmethod
    def get_available_providers() -> list[str]:
        """Get list of available LLM providers."""
        return ["openai", "azure", "anthropic", "gemini", "custom"]
