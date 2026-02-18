# Configuration Variables & Tolerances

Comprehensive enumeration of all configurable parameters, thresholds, and constants in the Discovery Tool for Splunk MCP Server.

---

## 1. LLM Configuration

### 1.1 Default Values (src/config_manager.py)
```python
class LLMConfig:
    provider: str = "openai"           # Supported: openai, azure, anthropic, gemini, custom
    model: str = "gpt-4o-mini"         # Default model
    max_tokens: int = 16000            # Default max tokens per request
    temperature: float = 0.7           # Default temperature for responses
```

Provider endpoint requirements:
- `openai`: endpoint optional (defaults to OpenAI public API)
- `azure`: endpoint required (Azure OpenAI resource/deployment URL)
- `anthropic`: endpoint optional (defaults to `https://api.anthropic.com`)
- `gemini`: endpoint optional (defaults to `https://generativelanguage.googleapis.com`)
- `custom`: endpoint required

### 1.2 Rate Limiting (src/llm/factory.py)
```python
class RateLimitManager:
    base_delay: float = 1.0            # Initial delay between retries (seconds)
    max_delay: float = 300.0           # Maximum delay (5 minutes)
    max_retries: int = 5               # Maximum retry attempts
    
    # Token Budget Management
    recommended_max_usage: float = 0.8 # Use 80% of remaining tokens
    max_recommended_tokens: int = 4000 # Maximum tokens per request
    conservative_fallback: int = 500   # Conservative token count when limits unknown
    context_buffer: int = 100          # Buffer to leave for safety
```

---

## 2. MCP Server Configuration

### 2.1 Default Values (src/config_manager.py)
```python
class MCPConfig:
    url: str = "https://splunk:8089/services/mcp"  # Default MCP endpoint
    token: str = ""                                 # MCP authentication token
    verify_ssl: bool = False                        # SSL verification (default disabled)
    ca_bundle_path: Optional[str] = None           # Custom CA bundle path
```

### 2.2 Fatal Error Codes (src/web_app.py)
```python
fatal_statuses = {401, 403, 404}  # HTTP status codes that stop discovery immediately
# 401: Authentication failed
# 403: Access forbidden
# 404: MCP endpoint not found
```

---

## 3. Discovery Agent & Chat

### 3.1 Execution Limits (src/web_app.py)
```python
max_execution_time: int = 90           # Discovery timeout (90 seconds)
max_iterations: int = 5                # Maximum query iterations before stopping
convergence_check_threshold: int = 5   # Minimum iterations before checking for convergence
```

### 3.2 Context & Data Handling
```python
# Result Sampling
metadata_full_data: bool = True        # Send all metadata (indexes, sourcetypes)
query_sample_size: int = 2             # Sample size for large query results (first N rows)
summary_sample_size: int = 5           # Summary context size (first N rows)

# Context Windows
metadata_context_chars: int = 2000     # Max characters for metadata context
query_context_chars: int = 800         # Max characters for query result context

# Message History
max_history_messages: int = 6          # Recent messages to include in context
```

### 3.3 Quality Assessment Thresholds (src/web_app.py)
```python
# Answer Quality Scoring
actionable_data_score: int = 40        # Points for retrieving data
detailed_explanation_score: int = 15   # Points for substantive response
conclusive_analysis_score: int = 25    # Points for conclusive findings
error_penalty: int = -15               # Penalty for errors/uncertainty
progress_score: int = 10               # Points for showing progress

# Quality Thresholds
low_quality_threshold: int = 40        # Below this = low quality
moderate_quality_threshold: int = 70   # 40-70 = moderate quality
high_quality_threshold: int = 70       # Above 70 = high quality
```

### 3.4 Convergence Detection
```python
# Pattern repetition detection
no_data_repetitions: int = 5           # Stop after 5 iterations with no data
```

---

## 4. Discovery Data Management

### 4.1 Discovery Freshness (src/web_app.py)
```python
staleness_threshold: int = 604800      # 7 days in seconds (when to recommend re-discovery)
discovery_summary_preview: int = 2000  # Characters to read from V2 insights brief
max_key_findings: int = 5              # Maximum findings to inject into context
max_recommendations: int = 5           # Maximum recommendations to inject
```

### 4.2 Discovery Insights Keywords
```python
insight_keywords = [
    'summary', 'overview', 'recommend', 'best practice', 'optimization',
    'use case', 'compliance', 'security', 'improve', 'assess'
]
```

---

## 5. WebSocket & Streaming

### 5.1 WebSocket Timeouts (src/web_app.py)
```python
websocket_receive_timeout: float = 0.1 # Timeout for checking new messages (100ms)
keepalive_interval: float = 0.1        # SSE keepalive interval (100ms)
```

### 5.2 Debug Log Queue
```python
debug_log_queue_maxsize: int = 1000    # Maximum debug messages in queue
```

---

## 6. User Input Validation

### 6.1 Message Limits (src/web_app.py)
```python
max_message_length: int = 10000        # Maximum characters in user message
```

---

## 7. API Endpoints

### 7.1 Base URLs
```python
# Default MCP Endpoint
mcp_default_url = "https://splunk:8089/services/mcp"

# Web Application
web_app_host = "0.0.0.0"
web_app_port = 8003

# API Routes
api_prefix = "/api"
websocket_endpoint = "/ws"
debug_websocket_endpoint = "/ws/debug"

# V2 Workspace Routes
v2_intelligence_endpoint = "/api/v2/intelligence"
v2_artifacts_endpoint = "/api/v2/artifacts"
discovery_dashboard_endpoint = "/api/discovery/dashboard"
discovery_compare_endpoint = "/api/discovery/compare"
discovery_runbook_endpoint = "/api/discovery/runbook"
summarize_session_endpoint = "/summarize-session"
summarize_progress_endpoint = "/summarize-progress/{session_id}"
```

---

## 8. File System Paths

### 8.1 Configuration Files
```python
config_file = "config.encrypted"       # Encrypted configuration
config_key_file = ".config.key"        # Encryption key
```

### 8.2 Output Directories
```python
output_directory = "output/"           # Discovery reports output
log_directory = "logs/"                # Application logs (if enabled)

# V2 Artifact Naming
v2_blueprint_pattern = "v2_intelligence_blueprint_<timestamp>.json"
v2_insights_pattern = "v2_insights_brief_<timestamp>.md"
v2_runbook_pattern = "v2_operator_runbook_<timestamp>.md"
v2_handoff_pattern = "v2_developer_handoff_<timestamp>.md"
v2_summary_pattern = "v2_ai_summary_<timestamp>.json"
```

### 8.3 Ignored Patterns (.gitignore)
```
# Secrets
.config.key
config.encrypted
*.pem
*.key
*.cert
*.env

# Output
output/

# Development
DO NOT SEND TO GIT/
*.backup*
*.corrupted*
test_*.py
test_*.sh
```

---

## 9. LLM Provider-Specific Settings

### 9.1 OpenAI
```python
default_model = "gpt-4o-mini"
max_context_window = 128000            # Model-specific (varies by model)
```

### 9.2 Azure OpenAI
```python
endpoint_pattern = "https://<resource>.openai.azure.com"
api_version = "2024-02-15-preview"   # Used for deployment/model probes
```

### 9.3 Anthropic
```python
default_endpoint = "https://api.anthropic.com"
header_anthropic_version = "2023-06-01"
```

### 9.4 Gemini
```python
default_endpoint = "https://generativelanguage.googleapis.com"
request_shape = "models/{model}:generateContent"
```

### 9.5 Custom Endpoints
```python
endpoint_base_example = "http://<host>:<port>/v1"
auto_candidate_paths = ["/v1/chat/completions", "/chat/completions", "/v1/completions", "/completions"]

# Simple prompt for greetings (no heavy context)
greeting_keywords = ['hi', 'hello', 'hey', 'how are you', 'thanks', 'thank you', 'bye', 'goodbye']
```

Notes:
- Custom provider accepts either a full completion URL or a base endpoint.
- When a base endpoint is provided, the client automatically tries common OpenAI-compatible completion paths.

### 9.6 LLM Utility API Endpoints
```python
llm_list_models_endpoint = "/api/llm/list-models"          # Provider-aware model/deployment fetch
llm_test_connection_endpoint = "/api/llm/test-connection"  # Provider-aware connectivity + generation test
llm_assess_max_tokens_endpoint = "/api/llm/assess-max-tokens"
```

---

## 10. Error Handling

### 10.1 Token Limit Errors
```python
safe_completion_ratio: float = 0.25    # Use 25% of max context for completion
safe_prompt_buffer: int = 100          # Buffer tokens for safety
```

### 10.2 Retry Strategy
```python
retry_with_jitter_min: float = 0.1     # Minimum jitter (10% of delay)
retry_with_jitter_max: float = 0.3     # Maximum jitter (30% of delay)
```

---

## 11. Data Classification & Analysis

### 11.1 Sample Sizes
```python
sample_field_count: int = 5            # Number of fields to show in summaries
large_result_threshold: int = 100      # Threshold for "large result set" warning
```

---

## 12. Security & Encryption

### 12.1 Encryption
```python
encryption_algorithm = "Fernet"        # Symmetric encryption (cryptography.fernet)
```

### 12.2 Masked Values
```python
masked_placeholder = "***"             # Placeholder for masked secrets in UI
```

---

## 13. Performance Optimization

### 13.1 Thread Pools
```python
# LLM Factory uses ThreadPoolExecutor for blocking operations
# Size not explicitly configured (uses Python defaults)
```

---

## Summary of Key Thresholds

| Category | Parameter | Value | Unit | Notes |
|----------|-----------|-------|------|-------|
| **Discovery** | Max Execution Time | 90 | seconds | Safety timeout |
| **Discovery** | Max Iterations | 5 | count | Before stopping |
| **Discovery** | Staleness Threshold | 7 | days | When to recommend re-discovery |
| **Rate Limiting** | Max Delay | 300 | seconds | 5 minutes max wait |
| **Rate Limiting** | Max Retries | 5 | count | Retry attempts |
| **Context** | Max Message Length | 10000 | characters | User input limit |
| **Context** | History Messages | 6 | count | Recent messages in context |
| **Context** | Metadata Context | 2000 | characters | For metadata queries |
| **Context** | Query Context | 800 | characters | For query results |
| **Quality** | Low Quality | <40 | score | Needs improvement |
| **Quality** | Moderate Quality | 40-70 | score | Acceptable |
| **Quality** | High Quality | >70 | score | Good answer |
| **WebSocket** | Receive Timeout | 0.1 | seconds | 100ms polling |
| **Tokens** | Default Max | 16000 | tokens | Per request |
| **Tokens** | Conservative | 500 | tokens | Fallback when limits unknown |

---

## Configuration Priority

1. **User Settings** (via web UI) - Highest priority
2. **Saved Credentials** (encrypted vault)
3. **Active Configuration** (config.encrypted)
4. **Code Defaults** (dataclass defaults)

---

*Last Updated: 2026-02-18*
*Version: 1.1.0-dev*
