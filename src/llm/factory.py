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
from typing import Optional, Protocol, Dict, Any
from datetime import datetime, timedelta


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
    
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4", rate_limit_display_callback=None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key required")
        self.model = model
        self.base_url = "https://api.openai.com/v1"
        self.rate_limit_manager = RateLimitManager(rate_limit_display_callback)
            
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
        
        attempt = 0
        
        while attempt < self.rate_limit_manager.max_retries:
            try:
                # Adjust max_tokens based on current rate limit budget
                budget_info = self.rate_limit_manager.update_request_budget(
                    self.rate_limit_manager.current_limits
                )
                adjusted_max_tokens = min(max_tokens, budget_info.get('recommended_max_tokens', max_tokens))
                
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                
                payload = {
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": adjusted_max_tokens,
                    "temperature": temperature
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.base_url}/chat/completions",
                        headers=headers,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=60)  # Increased timeout
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            self.rate_limit_manager.reset_retry_count()
                            return result["choices"][0]["message"]["content"]
                        elif response.status == 429:  # Rate limit error
                            error_text = await response.text()
                            rate_limit_info = self.rate_limit_manager.parse_rate_limit_error(error_text)
                            
                            if not self.rate_limit_manager.should_retry(attempt):
                                raise Exception(f"Max retries exceeded. Last error: {error_text}")
                            
                            delay = self.rate_limit_manager.calculate_optimal_delay(rate_limit_info)
                            await self.rate_limit_manager.wait_for_rate_limit(
                                delay, 
                                f"OpenAI rate limit (attempt {attempt + 1}/{self.rate_limit_manager.max_retries})"
                            )
                            
                            attempt += 1
                            continue
                        elif response.status == 400:  # Bad request - might be context length
                            error_text = await response.text()
                            if "context length" in error_text.lower() or "maximum context" in error_text.lower():
                                # Context length exceeded
                                truncation_info = self.rate_limit_manager.handle_context_length_error(error_text)
                                
                                if not self.rate_limit_manager.should_retry(attempt):
                                    raise Exception(f"Max retries exceeded. Context length error: {error_text}")
                                
                                # Truncate messages and retry
                                messages = self._truncate_messages(messages, truncation_info)
                                adjusted_max_tokens = truncation_info.get('safe_max_tokens', 500)
                                
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
                                continue
                            else:
                                raise Exception(f"OpenAI API error {response.status}: {error_text}")
                        else:
                            error_text = await response.text()
                            raise Exception(f"OpenAI API error {response.status}: {error_text}")
                            
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
    """Custom LLM endpoint client implementation."""
    
    def __init__(self, endpoint_url: str, api_key: Optional[str] = None, model: str = "llama2", 
                 rate_limit_display_callback=None):
        self.endpoint_url = endpoint_url.rstrip('/')
        self.api_key = api_key
        self.model = model
        self.rate_limit_display_callback = rate_limit_display_callback
        
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
        
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        # Try OpenAI-compatible format first
        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.endpoint_url}/chat/completions",
                    headers=headers,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result["choices"][0]["message"]["content"]
                    else:
                        # Try alternative formats (Ollama, etc.)
                        # Extract text from messages for simple prompt format
                        prompt_text = self._messages_to_prompt(messages)
                        return await self._try_alternative_format(prompt_text, max_tokens)
        except Exception as e:
            raise Exception(f"Failed to generate custom LLM response: {e}")
    
    def _messages_to_prompt(self, messages: list) -> str:
        """Convert messages format to simple prompt text."""
        if not messages:
            return ""
        # Join all user messages
        return "\n\n".join([msg.get("content", "") for msg in messages if msg.get("role") in ["user", "system"]])
    
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
        if provider == "openai":
            return OpenAIClient(api_key=api_key, model=model, rate_limit_display_callback=rate_limit_display_callback)
        elif provider == "custom":
            if not custom_endpoint:
                raise ValueError("Custom endpoint URL required for custom LLM provider")
            return CustomLLMClient(custom_endpoint, rate_limit_display_callback=rate_limit_display_callback)
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")
            
    @staticmethod
    def get_available_providers() -> list[str]:
        """Get list of available LLM providers."""
        return ["openai", "custom"]