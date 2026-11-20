# Configuration Variables & Tolerances

Reference of the configurable parameters, thresholds, and constants in Splunk Discovery Tool. Each entry names the file where the value lives.

---

## 1. LLM Configuration

### 1.1 Default Values (src/config_manager.py)
```python
class LLMConfig:
    provider: str = "openai"           # Supported: openai, azure, anthropic, gemini, ollama, custom
    model: str = "gpt-4o-mini"         # Default model
    max_tokens: int = 16000            # Max tokens per request (used when auto_tune is off)
    temperature: float = 0.7           # Temperature (used when auto_tune is off)
    auto_tune: bool = True             # Derive runtime settings from the model profile
    context_window: int = 0            # 0 = derive from the model profile
    request_timeout: int = 0           # Seconds; 0 = derive from the model profile
    reasoning_effort: str = ""         # "", "low", "medium", or "high"
```

Saved LLM credentials (`LLMCredential`) carry the same `max_tokens`, `temperature`, `auto_tune`, `context_window`, `request_timeout`, and `reasoning_effort` fields. Config files written by other versions still load; unknown keys are ignored.

Provider endpoint requirements:
- `openai`: endpoint optional (defaults to OpenAI public API)
- `azure`: endpoint required (Azure OpenAI resource/deployment URL)
- `anthropic`: endpoint optional (defaults to `https://api.anthropic.com`)
- `gemini`: endpoint optional (defaults to `https://generativelanguage.googleapis.com`)
- `ollama`: local Ollama runtime; the endpoint is normalized by `normalize_ollama_endpoint_url()` in `src/llm/factory.py`
- `custom`: endpoint required

### 1.2 Auto-Tuning (src/llm/model_profiles.py)
```python
BALANCED_WEIGHTS = {"quality": 0.45, "speed": 0.30, "cost": 0.25}  # Model ranking weights
HOSTED_CONTEXT_CAP = 128000        # Prompt planning cap for hosted models
LOCAL_CONTEXT_CAP = 32768          # Prompt planning cap for local runtimes (keeps responses fast)
DEFAULT_UNKNOWN_CONTEXT = 8192     # Context assumed when nothing reports one

# recommend_settings(profile) when auto_tune is on
max_tokens: hosted 8192 (16000 for reasoning models), local 4096 (8192 for reasoning),
            capped by the model's output limit and half of the effective context
temperature: 0.2                   # Omitted for models with a fixed temperature
request_timeout: hosted 120s (300s reasoning), local 600s (900s reasoning)
reasoning_effort: "low"            # OpenAI/Azure reasoning models and gpt-oss

# Built-in catalog (HOSTED_CATALOG, first matching pattern wins)
# gpt-6-astra, gpt-6-sol, gpt-6-terra, gpt-6-luna, gpt-6 (any other gpt-6 id)
# gpt-5-sol, gpt-5-terra, gpt-5-luna (the GPT-5.6 tiers)
#   1,050,000-token context window, 128,000 output tokens, reasoning, no temperature
NEWEST_CATALOG_GPT_GENERATION = 6  # gpt-7 and later use the closest gpt-6 tier, then the closest gpt-5 tier
```

Chat budgets come from `chat_budgets()`: the first step gets about 50% and follow-up steps about 60% of `max_tokens` (at least 2048 tokens for reasoning models and 512 otherwise). History turns (`_history_turns()`: 2 up to 8192 tokens of context, 4 up to 16384, 6 up to 32768, otherwise 8) and evidence rows scale with the context window.

### 1.3 Rate Limiting (src/llm/factory.py)
```python
class RateLimitManager:
    base_delay = 1.0                   # Initial delay between retries (seconds)
    max_delay = 300.0                  # Maximum delay (5 minutes)
    max_retries = 5                    # Maximum retry attempts

    # Token budget management (literals inside RateLimitManager methods)
    recommended_max_usage = 0.8        # Use 80% of remaining tokens
    max_recommended_tokens = 4000      # Maximum recommended tokens per request
    conservative_fallback = 500        # Token count used when limits are unknown
    context_buffer = 100               # Tokens left free when a request exceeds the context
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
# An MCP call that fails with one of these HTTP status codes is marked fatal and stops the chat answer
fatal_statuses = {401, 403, 404}
# 401: Authentication failed
# 403: Access forbidden
# 404: MCP endpoint not found
# A JSON-RPC error in the response body is fatal only with HTTP 401 or 403.
```

### 2.3 External Surface Rate Limits (src/config_manager.py, src/web_app.py)
```python
class SecurityConfig:
    external_api_rate_limit_requests: int = 30          # Requests allowed per window for external REST
    external_api_rate_limit_window_seconds: int = 60    # Fixed-window size for external REST
    external_mcp_rate_limit_requests: int = 30          # Requests allowed per window for inbound MCP
    external_mcp_rate_limit_window_seconds: int = 60    # Fixed-window size for inbound MCP
```

Behavior notes:
- limits are enforced per issued token in the current single-process runtime
- the settings API accepts request counts from 1 to 10000
- over-budget requests return `429 Too Many Requests`
- clients should wait for the `Retry-After` header before retrying

### 2.4 Security Feature Defaults (src/config_manager.py)
```python
class SecurityConfig:
    auth_enabled: bool = False
    auth_provider: str = "local_password"
    external_api_enabled: bool = False
    external_mcp_enabled: bool = False
    session_timeout_minutes: int = 480
    password_min_length: int = 12
    require_password_reset_on_first_login: bool = True
```

Behavior notes:
- sign-in is off after install, and while it is off anyone who can reach the app can use it
- sign-in stays off until an admin turns on authentication in Settings and saves
- the external REST and inbound MCP surfaces have separate toggles

### 2.5 OIDC Provider Defaults (src/config_manager.py)
```python
class OIDCConfig:
    issuer_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    audience: Optional[str] = None
    scopes: list = ["openid", "profile", "email"]
    username_claim: str = "preferred_username"
    email_claim: str = "email"
    role_claim: str = "roles"
    default_role: str = "viewer"
    mcp_assignment_claim: Optional[str] = None
```

Behavior notes:
- the default auth provider is still local-password unless OIDC is configured and enabled
- role and MCP assignment claim names are configurable so providers do not need identical schemas
- OIDC claim mapping is install-wide and feeds the same user/session model as local auth

### 2.6 Web Server (src/config_manager.py, src/main.py)
```python
class ServerConfig:
    port: int = 8003
    host: str = "0.0.0.0"
    cors_origins: list = ["*"]         # Set in __post_init__ when not configured
    trusted_hosts: list = ["*"]        # Set in __post_init__ when not configured
    debug_mode: bool = False           # Debug logging to the popup window

# src/main.py
_resolve_startup_port(preferred_port, max_scan_ports=20)
```

If the configured port is in use, the app tries the next 20 ports (for example 8004 through 8023) and prints the port it chose. On Windows it first tries to reclaim the preferred port from an earlier instance of this app.

---

## 3. Discovery Agent & Chat

### 3.1 Chat Settings (src/chat_settings.py)
Chat settings start from the active AI model's tuning (`model_defaults()`). A value changed in Chat Settings becomes Custom, is saved in `output/chat_data/chat_settings.json`, and is cleared when the AI model (provider, endpoint, or model) changes. Custom values are clamped to the ranges in `SETTING_LIMITS`. `SETTING_SOURCES` records where each Auto value comes from.

```python
# key: Auto value                                                          Custom range (SETTING_LIMITS)
max_execution_time         # Model request_timeout, kept between 120 and 900 seconds        30-1800
max_iterations             # Search rounds per answer: 3 when the context window is
                           # 16384 tokens or less (SMALL_CONTEXT_TOKENS), otherwise 5         1-10
convergence_detection      # Stop after this many rounds without new data:
                           # max(2, min(3, max_iterations - 1))                               2-10
discovery_freshness_days   # 7 (app default)                                                  1-30
max_tokens                 # From the model tuning                                            256-128000
temperature                # From the model tuning (0.2 when there is no tuning)              0.0-2.0
context_history            # Chat budget history_turns from the model tuning                  1-20
enable_splunk_augmentation # True (app default)                                               true/false
enable_rag_context         # True when the Knowledge Base is installed                        true/false
rag_max_chunks             # 1 when the context window is 8192 tokens or less
                           # (TINY_CONTEXT_TOKENS), 2 when 16384 or less, otherwise 3         1-6
```

Removed in 2.0.0: max retry delay, max retries, answer quality threshold, query sample size, and the fixed 90-second time limit. The earlier `convergence_check_threshold`, the "Context & Data Handling" values (`summary_sample_size`, `metadata_context_chars`, `query_context_chars`, `max_history_messages`), the answer quality scores and thresholds, and `no_data_repetitions` no longer exist in the code. Messages remembered now come from `context_history`, and the stall limit comes from `convergence_detection`.

Chat searches that name no index run with `index=*` added. A search that repeats an earlier empty search with only the index changed is skipped, and the model is told to search all indexes in one step instead.

### 3.2 Chat Goals (src/chat_goals.py)
```python
MAX_GOALS = 100                # Goals per library
MAX_ITEMS = 10                 # Tracked questions per goal
MAX_QUESTIONS = 3              # Suggested next questions per goal
MAX_NEW_ITEMS_PER_ANSWER = 2   # Tracked questions one answer can add
MAX_TURNS = 30                 # Recent question-and-answer turns kept for judging progress
MAX_CHATS = 50                 # Saved chats per goal
MAX_CHAT_MESSAGES = 200        # Messages kept per saved chat (newest kept)
MAX_CHAT_BYTES = 1_000_000     # Size cap for one saved chat; oldest messages are dropped first
MAX_GOAL_CHARS = 600           # Goal text length
MAX_TITLE_CHARS = 80           # Goal and chat title length
```

Goals are stored as one JSON file per library owner under `output/chat_data/goals/`. When sign-in is on, each user has their own library (`user_<id>.json`). When sign-in is off, everyone shares one library (`local.json`).

Each chat's scratchpad is stored the same way, under `output/chat_data/memory/<owner>/chat_memory_<chat session>.json` (`CHAT_MEMORY_DIR_NAME = "memory"` in `src/web_app.py`).

### 3.3 Environment Memory (src/environment_memory/, src/web_app.py)
```python
# src/environment_memory/settings.py: install-wide, saved in output/environment_memory/settings.json (admin)
class EnvironmentMemorySettings:
    learn_from_chat: bool = True       # Keep names that chat search results return
    scheduled_check: bool = False      # Light tstats check for each scope with a record or discovery runs
    check_interval_hours: int = 6      # CHECK_INTERVAL_RANGE = (1, 168)
    quiet_hours: int = 24              # QUIET_HOURS_RANGE = (1, 720); no events for this long is Went quiet

# src/environment_memory/record.py: one record per scope, <scope folder>/environment_memory/record.json
CHANGE_KINDS = ("index", "sourcetype", "host")           # Sources are kept but report no changes
CHANGE_TYPES = ("new", "went_quiet", "back", "volume_shift", "gone")
ENTITY_CAPS = {"index": 2000, "sourcetype": 5000, "host": 5000, "source": 2000}  # Least recently seen dropped first
MAX_CHANGES = 500                  # Newest changes kept
MAX_OBSERVATIONS = 50              # Newest observation summaries kept
MIN_SHIFT_EVENTS = 100             # Volume shift: tstats counts, more than 50% up or down, either count at least this
BACKFILL_RUNS = 2                  # A new record starts from the last 2 discovery runs
UNREADABLE_REPORT_GRACE_SECONDS = 120   # A report this young that cannot be read is tried again later

# src/environment_memory/observations.py
CHECK_WINDOW = "-24h"
CHECK_ROW_LIMIT = 5000             # A result at this size or a round cap (100, 1000, ...) counts as cut short
CHAT_ROW_LIMIT = 5000              # Rows read from one chat answer's searches

# src/environment_memory/context.py
RECENT_CHANGE_DAYS = 7             # Changes listed in the chat Known environment section
# Known environment lists up to 12 names per kind (6 in compact mode), 6 quiet items (3), and 6 changes (3)

# src/web_app.py
ENVIRONMENT_CHECK_LOOP_SECONDS = 60             # How often the schedule looks for a check that is due
ENVIRONMENT_CHECK_SEARCH_TIMEOUT_SECONDS = 300  # Per check search
ENVIRONMENT_VIEW_LIMIT_MAX = 500                # Largest limit or change_limit the API returns
```

The record keeps only names that Splunk returned. Each scope shares one record for everyone who searches it, and the Knowledge Base indexer skips `environment_memory/` folders.
---

## 4. Discovery Data Management

### 4.1 Discovery Freshness (src/web_app.py)
```python
load_latest_report_knowledge(staleness_days=7, output_dir=None)  # Chat passes discovery_freshness_days (default 7) and the asker's scope folder
# Fresh: bundle age <= discovery_freshness_days
# Warning: older than the window but no more than twice the window
# Stale: older than twice the window
insights_brief_read_limit = 5000       # Characters read from the latest insights brief
runbook_and_handoff_read_limit = 3000  # Characters read from the runbook and developer handoff
max_key_findings = 5                   # Headline findings injected into chat context
max_recommendations = 5                # Recommendations injected into chat context
```

### 4.2 Discovery Insights Keywords (src/web_app.py)
Messages that contain one of these words also get the strategic discovery context:
```python
insight_keywords = [
    'summary', 'overview', 'recommend', 'best practice', 'optimization',
    'use case', 'compliance', 'security', 'improve', 'assess', 'risk', 'gap', 'priority'
]
```

---

## 5. WebSocket & Streaming

### 5.1 WebSocket Timeouts (src/web_app.py)
```python
websocket_receive_timeout: float = 0.1 # Timeout for checking new messages (100ms)
status_queue_poll_timeout: float = 0.1 # Progress stream polling interval (100ms)
```

### 5.2 Debug Log Queue (src/web_app.py)
```python
debug_log_queue = asyncio.Queue()      # No size limit is set
```

---

## 6. User Input Validation

### 6.1 Message Limits (src/web_app.py)
```python
max_message_length: int = 10000        # Maximum characters in user message
```

---

## 7. API Endpoints

### 7.1 Base URLs and Routes (src/web_app.py)
```python
# Default MCP Endpoint
mcp_default_url = "https://splunk:8089/services/mcp"

# Web Application (ServerConfig defaults)
web_app_host = "0.0.0.0"
web_app_port = 8003

# API Routes
api_prefix = "/api"
websocket_endpoint = "/ws"
debug_websocket_endpoint = "/ws/debug"

# Workspace Data Routes
v2_intelligence_endpoint = "/api/v2/intelligence"
v2_artifacts_endpoint = "/api/v2/artifacts"
discovery_dashboard_endpoint = "/api/discovery/dashboard"
discovery_compare_endpoint = "/api/discovery/compare"
discovery_runbook_endpoint = "/api/discovery/runbook"
summarize_session_endpoint = "/summarize-session"
summarize_progress_endpoint = "/summarize-progress/{session_id}"

# Chat Settings
chat_settings_endpoint = "/api/chat/settings"              # GET current values, POST custom values
chat_settings_reset_endpoint = "/api/chat/settings/reset"  # POST: all settings back to Auto

# Chat Goals
chat_goals_endpoint = "/api/chat/goals"                    # GET list, POST create
chat_goal_endpoint = "/api/chat/goals/{goal_id}"           # GET, PATCH, DELETE
chat_goal_plan_endpoint = "/api/chat/goals/{goal_id}/plan"
chat_goal_items_endpoint = "/api/chat/goals/{goal_id}/items"            # POST
chat_goal_item_endpoint = "/api/chat/goals/{goal_id}/items/{item_id}"   # PATCH, DELETE
chat_goal_progress_endpoint = "/api/chat/goals/{goal_id}/progress"
chat_goal_chat_endpoint = "/api/chat/goals/{goal_id}/chats/{chat_id}"   # GET, PUT, PATCH, DELETE

# Incognito Mode
incognito_status_endpoint = "/api/incognito/status"                    # GET
incognito_preference_endpoint = "/api/incognito/preference"            # POST {"enabled": true|false|null}
incognito_policy_endpoint = "/api/incognito/policy"                    # GET, POST (admin)
incognito_rotate_endpoint = "/api/incognito/rotate"                    # POST (admin)
incognito_preview_endpoint = "/api/incognito/preview"                  # POST (admin)
incognito_ledger_endpoint = "/api/incognito/ledger/{ledger_id}"        # GET (the person who asked)
incognito_export_endpoint = "/api/incognito/export"                    # POST {"text", "filename"}
incognito_report_export_endpoint = "/api/incognito/export/report/{filename}"  # GET

# Environment Memory
environment_memory_endpoint = "/api/environment-memory"                  # GET ?limit=50&change_limit=100
environment_changes_endpoint = "/api/environment-memory/changes"         # GET ?limit=100&change=&kind=
environment_check_endpoint = "/api/environment-memory/check"             # POST (admin)
environment_clear_endpoint = "/api/environment-memory/clear"             # POST (admin)
environment_settings_endpoint = "/api/environment-memory/settings"       # GET, POST (admin)

# Knowledge Library
knowledge_library_status_endpoint = "/api/knowledge-library/status"
knowledge_library_settings_endpoint = "/api/knowledge-library/settings"
knowledge_library_refresh_endpoint = "/api/knowledge-library/refresh"
knowledge_library_search_endpoint = "/api/knowledge-library/search"
knowledge_library_pack_import_endpoint = "/api/knowledge-library/pack/import"
knowledge_library_pack_export_endpoint = "/api/knowledge-library/pack/export"

# Troubleshooting
troubleshoot_server_status_endpoint = "/api/troubleshoot/server-status"  # GET
troubleshoot_mcp_endpoint = "/api/troubleshoot/mcp"                      # POST
troubleshoot_llm_endpoint = "/api/troubleshoot/llm"                      # POST

# Capabilities
capabilities_endpoint = "/api/capabilities"
capabilities_health_endpoint = "/api/capabilities/health"
capability_action_endpoints = "/api/capabilities/{name}/{install|enable|disable|uninstall|test|reindex|config}"  # POST (admin)
capability_connections_endpoint = "/api/capabilities/{name}/connections"  # GET ?refresh=false (admin)
rag_assets_endpoints = "/api/capabilities/rag/assets..."   # List, read, import, delete, check in, check out
rag_context_build_endpoint = "/api/capabilities/rag/context/build"
deeplinks_build_endpoint = "/api/capabilities/deeplinks/build"
exports_build_endpoint = "/api/capabilities/exports/build"
exports_download_endpoint = "/api/capabilities/exports/download/{filename}"

# Splunk Dashboards
dashboards_status_endpoint = "/api/dashboards/status"                  # GET ?refresh=false
dashboards_propose_endpoint = "/api/dashboards/propose"                # POST report_name, focus
dashboards_create_endpoint = "/api/dashboards/create"                  # POST proposal_id, brief, binding_key
dashboards_operations_endpoint = "/api/dashboards/operations"          # GET ?limit=20 (1-50); /{request_id}
dashboards_check_endpoint = "/api/dashboards/operations/{request_id}/check"  # POST
```

---

## 8. File System Paths

### 8.1 Configuration Files (src/config_manager.py, src/web_app.py)
```python
config_file = "config.encrypted"       # Encrypted configuration
config_key_file = ".config.key"        # Encryption key
```

### 8.2 Output Directories
```python
output_directory = "output/"                                       # Discovery reports output
chat_settings_file = "output/chat_data/chat_settings.json"         # src/chat_settings.py
chat_goals_directory = "output/chat_data/goals/"                   # src/chat_goals.py
knowledge_library_directory = "output/knowledge_library/"          # src/knowledge_library/
library_docs_database = "output/knowledge_library/docs/library_docs.sqlite3"
incognito_directory = "output/incognito/"                          # src/incognito/store.py (encrypted)
environment_record = "output/environment_memory/record.json"       # Global scope; output/scopes/<scope>/environment_memory/ otherwise
environment_settings_file = "output/environment_memory/settings.json"  # src/environment_memory/settings.py
dashboard_requests_file = "output/chat_data/dashboards/operations.json"  # src/capabilities/tools/dashboard_store.py

# Current Artifact Naming
v2_blueprint_pattern = "v2_intelligence_blueprint_<timestamp>.json"
v2_insights_pattern = "v2_insights_brief_<timestamp>.md"
v2_runbook_pattern = "v2_operator_runbook_<timestamp>.md"
v2_handoff_pattern = "v2_developer_handoff_<timestamp>.md"
v2_summary_pattern = "v2_ai_summary_<timestamp>.json"
```

### 8.3 Ignored Patterns (.gitignore)
Relevant entries from the repository `.gitignore`:
```
# Secrets and Configuration
.config.key
config.encrypted
*.pem
*.key
*.cert
*.env
.env
.env.local

# Installation
.install_manifest.json
.dt4sms.pid
dt4sms.log

# Output
output/

# Logs
*.log
logs/

# Testing
test_*.py
test_*.sh
!tests/test_*.py
!tests/**/test_*.py

# Development/Debugging
DO NOT SEND TO GIT/
*.backup*
*.corrupted*

# Local scratch artifacts
external_mcp.token
external_rag.token
security.db
```

---

## 9. LLM Provider-Specific Settings

### 9.1 OpenAI (src/llm/factory.py)
```python
default_model = "gpt-4o-mini"
max_context_window = 128000            # gpt-4o-mini profile (varies by model)

# get_openai_model_capabilities(): o1, o3, o4, and every gpt-5 or newer model (gpt-5.6, gpt-6.1, gpt-7)
#   try the Responses API first, run as reasoning models (except -chat models), omit temperature,
#   and send max_completion_tokens to Chat Completions
# openai_reasoning_effort_for_model(): "minimal" is sent as "low" for gpt-5.6 and newer
```

### 9.2 Azure OpenAI (src/llm/factory.py)
```python
endpoint_pattern = "https://<resource>.openai.azure.com"
api_version = "2024-02-15-preview"   # Default for _append_api_version()
```

### 9.3 Anthropic (src/llm/factory.py)
```python
default_endpoint = "https://api.anthropic.com"
header_anthropic_version = "2023-06-01"
```

### 9.4 Gemini (src/llm/factory.py)
```python
default_endpoint = "https://generativelanguage.googleapis.com"
request_shape = "v1beta/models/{model}:generateContent"
```

### 9.5 Custom Endpoints (src/llm/factory.py, src/chat_agent.py)
```python
endpoint_base_example = "http://<host>:<port>/v1"
auto_candidate_paths = ["/v1/chat/completions", "/chat/completions", "/v1/completions", "/completions"]

# Small talk (src/chat_agent.py, _SMALL_TALK_PHRASES): greetings, thanks, and farewells
# such as 'hi', 'hello', 'hey', 'good morning', 'thanks', 'thank you', 'bye', 'goodbye', 'how are you'
```

Notes:
- Custom provider accepts either a full completion URL or a base endpoint.
- When a base endpoint is provided, the client automatically tries common OpenAI-compatible completion paths.
- A message counts as small talk only when it starts with a known phrase, has at most 6 words, and contains only filler words after the phrase. Local runtimes answer small talk with a short prompt instead of the full tool prompt.

### 9.6 LLM Utility API Endpoints (src/web_app.py)
```python
llm_list_models_endpoint = "/api/llm/list-models"          # Provider-aware model/deployment fetch
llm_test_connection_endpoint = "/api/llm/test-connection"  # Provider-aware connectivity + generation test
llm_assess_max_tokens_endpoint = "/api/llm/assess-max-tokens"
llm_health_endpoint = "/api/llm/health"
```

`/api/llm/list-models` also returns `ranked` (per-model profile and balanced score), `recommended`, `recommended_model`, and `ranking_basis`. With a blank or masked `api_key`, it uses the active model's saved key when the provider matches and the endpoint is the same; when the request gives no endpoint, it uses the active model's endpoint for the same provider. `/api/llm/test-connection` returns the tuned settings it used and the recommended settings for the model.

### 9.7 Certificate Trust for AI Requests (src/llm/factory.py)
```python
# create_llm_ssl_context()
# SSL_CERT_FILE or SSL_CERT_DIR set (nonempty): trust only that CA file or folder
# Otherwise: Python's system CA store plus certifi's public CA bundle
# Certificate chain and host name verification stay on; there is no unverified retry
# A missing or unreadable SSL_CERT_FILE is an error, not a fallback
```

Used by:
- `/api/llm/list-models` and `/api/llm/test-connection` (HTTPX)
- Generation for OpenAI, Azure OpenAI, Anthropic, and Gemini, and the custom-provider fallback request (aiohttp)
- OpenAI infographic capability checks, image generation, and image download
- The TLS check in **Settings > Troubleshoot > AI Provider**

Not used by:
- MCP connections, which use **Verify SSL Certificate** and **CA Bundle File**
- Custom-provider requests sent through the Requests client, and the Ollama and custom model metadata lookups

`SSL_CERT_FILE` and `SSL_CERT_DIR` are read when each request starts, so set them in the environment that starts the app (the installers pass the environment through). HTTPX also honors them for other outbound HTTPS that uses its default trust, such as knowledge library downloads.

---

## 10. Error Handling

### 10.1 Token Limit Errors (src/llm/factory.py)
```python
safe_completion_tokens = min(500, maximum // 4)                    # At most 25% of the context for completion
safe_prompt_tokens = maximum - safe_completion_tokens - 100        # 100-token safety buffer
```

### 10.2 Retry Strategy (src/llm/factory.py)
```python
retry_with_jitter_min: float = 0.1     # Minimum jitter (10% of delay)
retry_with_jitter_max: float = 0.3     # Maximum jitter (30% of delay)
```

---

## 11. Data Classification & Analysis

### 11.1 Sample Sizes (src/web_app.py)
```python
sample_rows_scanned: int = 60          # Rows read when extracting result structure
sample_field_count: int = 12           # Maximum sample fields listed per result
large_result_threshold: int = 100      # Rows above this suggest tightening or aggregating the query
```

---

## 12. Security & Encryption

### 12.1 Encryption (src/config_manager.py)
```python
encryption_algorithm = "Fernet"        # Symmetric encryption (cryptography.fernet)
```

### 12.2 Masked Values (src/config_manager.py)
```python
MASKED_SECRET = "***"                  # Placeholder for masked secrets in the UI; saving it keeps the stored secret
```

---

## 13. Performance Optimization

### 13.1 Thread Pools
```python
# src/llm/factory.py runs blocking LLM calls with loop.run_in_executor(None, ...),
# which uses asyncio's default executor (size not configured).
# src/web_app.py and src/knowledge_library/ use asyncio.to_thread for blocking work.
```

---

## 14. Knowledge Library (src/knowledge_library/, src/config_manager.py)

### 14.1 Online Sources
```python
class LibraryConfig:
    allow_online_sources: bool = False # Online downloads stay off until an admin turns them on

# src/knowledge_library/sources.py
ALLOWED_HOSTS = {"api.github.com", "raw.githubusercontent.com", "splunkbase.splunk.com", "help.splunk.com"}
MAX_RESPONSE_BYTES = 32 * 1024 * 1024  # 32 MB per downloaded response
MAX_SPLUNKBASE_LOOKUPS = 400
```

Only HTTPS requests to the allowed hosts are made.

### 14.2 Background Refresh (src/knowledge_library/service.py)
```python
AUTO_REFRESH_DAYS = 7                  # Refresh sources that are missing or older than a week
AUTO_RETRY_MINUTES = 60                # Wait between automatic refresh attempts
```

Automatic refresh runs only when `allow_online_sources` is on.

### 14.3 Documentation Download (src/knowledge_library/docs.py)
```python
DOC_FETCH_CONCURRENCY = 2              # Pages downloaded at the same time
DOC_REQUEST_INTERVAL = 0.25            # Seconds between page requests
DOC_REFUSAL_LIMIT = 3                  # Refused requests before the download stops
MAX_DOC_PAGES = 8000                   # Total documentation pages kept
MAX_PAGES_PER_MANUAL = 1500            # Pages kept per manual
MAX_STATUS_MANUALS = 400               # Manuals listed in the status response
```

### 14.4 Library Packs (src/knowledge_library/sources.py)
```python
MAX_PACK_BYTES = 100 * 1024 * 1024         # 100 MB limit for an imported pack
MAX_PACK_MEMBER_BYTES = 128 * 1024 * 1024  # 128 MB limit for one file inside a pack
```

### 14.5 Storage
```python
LIBRARY_DIR_NAME = "knowledge_library"     # output/knowledge_library/
DOCS_DIR_NAME = "docs"
DOCS_DB_NAME = "library_docs.sqlite3"      # output/knowledge_library/docs/library_docs.sqlite3
```

---

## 15. Knowledge Base Index Freshness (src/capabilities/rag/indexer.py)
```python
FRESHNESS_EXEMPT_SOURCE_TYPES = {"knowledge_asset"}
FRESHNESS_EXEMPT_FILENAMES = {"runtime_state.json"}
FRESHNESS_EXEMPT_DIRS = {"runtime_jobs"}
RETIRED_SOURCE_TYPES = {"chat_memory_derived"}    # An index that still holds these is rebuilt before the next search
LEGACY_CHAT_MEMORY_DIR_NAME = "chat_memory"       # Old scratchpad folder; never indexed
SCOPES_DIR_NAME = "scopes"                        # output/scopes/<scope>/ holds each sign-in scope's reports
ENVIRONMENT_MEMORY_DIR_NAME = "environment_memory"  # Environment records and settings; never indexed
DISCOVERY_SOURCE_TYPES = {"discovery_artifact", "generated_summary", "handoff", "runbook", "tool_result_snapshot"}
```

`get_index_freshness()` reports the index as `not_indexed`, `nothing_to_index`, `outdated` (older index format, or source files changed after the last index), or `current`. Files matching the exempt names, folders, and source types do not make the index outdated. The result appears as `index_freshness` in the capability health and install status.

Chat searches the Knowledge Base with the asker's scope folder. Passages of the `DISCOVERY_SOURCE_TYPES` come only from that scope; imports and other documents are shared by every scope.

---

## 16. Incognito Mode (src/incognito/, src/web_app.py)
```python
# src/web_app.py
INCOGNITO_ROOT = "output/incognito"            # policy.enc, preferences.enc, vaults/, ledger/
INCOGNITO_VAULT_SCOPE = "installation"         # One stand-in mapping for the whole installation
INCOGNITO_EXPORT_MAX_CHARS = 5_000_000         # Largest chat or report exported with stand-ins
# Preview text limit: 20,000 characters (POST /api/incognito/preview)
# Files are encrypted with config_manager.derived_fernet("incognito"):
#   Fernet key = HKDF-SHA256(.config.key, info="dt4sms:incognito")

# src/incognito/store.py
class IncognitoPolicy:
    force_for_cloud: bool = False              # Require incognito mode while a cloud AI model is in use
    default_on: bool = False                   # On for anyone who has not chosen
    always_mask_terms: list = []               # Admin terms replaced with term_NNNN
    keep_visible_terms: list = []              # Admin terms never replaced
MAX_TERMS = 500                                # Per term list
MAX_TERM_LENGTH = 200                          # Characters per term (shorter than 2 is dropped)
LEDGER_LIMIT = 300                             # Newest records of what the AI saw that are kept

# State, first match wins (resolve_state):
# 1. force_for_cloud and a cloud AI model: on, locked ("required_for_cloud")
# 2. The person's own choice ("user_choice")
# 3. default_on ("default")
# 4. Off
# An unreadable policy acts as force_for_cloud=True, default_on=True until an admin saves it again.
# A background job that started in incognito mode stays on ("job_started_incognito").

# src/incognito/session.py
MAX_LEDGER_CALLS = 24                          # Requests kept per record
MAX_LEDGER_TEXT = 60000                        # Characters kept per text in a record, cut in the middle

# src/incognito/provider.py: provider_kind()
# "local": endpoint on this machine or a private network, or Ollama without an endpoint
# "cloud": Azure OpenAI, Anthropic, Gemini, Cohere, Bedrock, Vertex, and anything not confirmed local
```

---

## 17. Splunk Dashboards (src/capabilities/tools/, src/web_app.py)
```python
# src/capabilities/registry.py: splunk_dashboards default_config (admin, POST /api/capabilities/splunk_dashboards/config)
create_timeout_seconds = 180                   # 30-900: wait for the create reply
status_timeout_seconds = 20                    # 5-60: wait for each status or user reply
max_wait_seconds = 600                         # 60-3600: keep checking a running request
splunk_web_urls = {}                           # Connection name -> Splunk Web address; empty uses the MCP host on port 8000

# src/capabilities/tools/dashboards.py (contract with Constellation, schema_version "1")
CREATE_TOOL = "constellation_create_dashboard"   # schema_version, request_id, expected_user, brief_json
STATUS_TOOL = "constellation_get_creation_status" # schema_version, request_id, expected_user
USER_INFO_TOOL = "splunk_get_user_info"          # Standard Splunk MCP tool that names the Splunk user
REQUEST_ADMISSION = 24 hours                   # Constellation accepts a resend of the same request ID
RECEIPT_RETENTION = 7 days                     # Requests kept in the app
MAX_BRIEF_BYTES = 16384                        # Serialized plan
TIME_RANGES = ("-15m", "-1h", "-24h", "-7d")   # latest is always "now"
# Plan limits: title 120, purpose 500, requirements 1200, search 8000, page name 60, panel 240,
# finding 300 characters; 1-2 pages, 1-4 panels per page, 6 panels, 4 findings

# src/capabilities/tools/dashboard_service.py
USER_CACHE_SECONDS = 600                       # How long a confirmed Splunk user is reused
MAX_POLL_DELAY_SECONDS = 15.0                  # Longest wait between status checks
MAX_STATUS_ERRORS = 3                          # Status errors in a row before the request shows as unconfirmed

# src/capabilities/tools/dashboard_store.py
MAX_OPERATIONS_PER_OWNER = 50                  # output/chat_data/dashboards/operations.json (owner-only file)

# src/web_app.py
MCP_TOOL_CATALOG_TTL_SECONDS = 60.0            # Cached MCP tool list per connection (30 after a failure)
DASHBOARD_CATALOG_WAIT_SECONDS = 8.0           # Wait for a tool list before showing Checking
DASHBOARD_REPORT_EXCERPT_CHARS = 6000          # Report text given to the AI model for a plan
DASHBOARD_HISTORY_CHARS = 4000                 # Conversation text given to the AI model for a plan
```
---
## Summary of Key Thresholds

| Category | Parameter | Value | Unit | Notes |
|----------|-----------|-------|------|-------|
| **Chat** | Time Limit (Auto) | Model request timeout, 120-900 | seconds | Custom 30-1800 |
| **Chat** | Search Rounds (Auto) | 3 or 5 | count | 3 when context is 16384 tokens or less; Custom 1-10 |
| **Chat** | Stall Limit (Auto) | max(2, min(3, rounds - 1)) | count | Custom 2-10 |
| **Chat** | Discovery Freshness | 7 | days | Custom 1-30 |
| **Chat** | Knowledge Base Passages (Auto) | 1, 2, or 3 | count | By context window; Custom 1-6 |
| **Chat** | Max Message Length | 10000 | characters | User input limit |
| **Chat Goals** | Goals per Library | 100 | count | Per user when sign-in is on |
| **Chat Goals** | Tracked Questions | 10 | count | Per goal |
| **Chat Goals** | Saved Chats | 50 | count | Per goal |
| **Chat Goals** | Messages per Saved Chat | 200 | count | Newest kept |
| **Environment Memory** | Quiet After | 24 | hours | Admin setting, 1-720 |
| **Environment Memory** | Scheduled Check | Off, every 6 | hours | Admin setting, 1-168 |
| **Environment Memory** | Volume Shift | 50 | percent | Up or down, tstats counts, at least 100 events |
| **Environment Memory** | Changes Kept | 500 | changes | Per scope, newest kept |
| **External REST** | Rate Limit Requests | 30 | requests | Per-token fixed-window budget |
| **External REST** | Rate Limit Window | 60 | seconds | Per-token window size |
| **Inbound MCP** | Rate Limit Requests | 30 | requests | Per-token fixed-window budget |
| **Inbound MCP** | Rate Limit Window | 60 | seconds | Per-token window size |
| **Rate Limiting** | Max Delay | 300 | seconds | 5 minutes max wait |
| **Rate Limiting** | Max Retries | 5 | count | LLM retry attempts |
| **Knowledge Library** | Auto Refresh | 7 | days | Only when online sources are allowed |
| **Knowledge Library** | Documentation Pages | 8000 | pages | Total cap |
| **Knowledge Library** | Pack Import Size | 100 | MB | Per pack |
| **Incognito** | Records Kept | 300 | records | Newest kept |
| **Incognito** | Requests per Record | 24 | count | Newest kept |
| **Incognito** | Term Lists | 500 | terms | Per list, 200 characters per term |
| **Incognito** | Preview | 20000 | characters | Admin preview text |
| **Incognito** | Export with Stand-ins | 5000000 | characters | Chat or report |
| **WebSocket** | Receive Timeout | 0.1 | seconds | 100ms polling |
| **Server** | Port | 8003 | port | Next 20 ports tried when busy |
| **Tokens** | Default Max (auto_tune off) | 16000 | tokens | Per request |
| **Tokens** | Conservative | 500 | tokens | Fallback when limits unknown |

---

## Configuration Priority

1. **User Settings** (via web UI) - Highest priority
2. **Saved Credentials** (encrypted vault)
3. **Active Configuration** (config.encrypted)
4. **Code Defaults** (dataclass defaults)

---

*Last Updated: 2026-11-20*
*Version: 2.3.0*
