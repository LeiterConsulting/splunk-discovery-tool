# External MCP Quickstart

Splunk Discovery Tool includes a read-only inbound MCP surface under `/api/external/mcp`.

It is meant for agent clients or lightweight automation that want MCP-style tool access to Splunk Discovery Tool retrieval, artifact, capability, and runtime summary context without a custom REST integration. The server identifies itself as `dt4sms-external-mcp`.

## What Ships

- unauthenticated setup endpoint: `GET /api/external/mcp/info`
- token-authenticated JSON-RPC endpoint: `POST /api/external/mcp`
- read-only MCP tools:
  - `rag_search`
  - `rag_list_assets`
  - `rag_get_asset_detail`
  - `rag_build_context`
  - `system_get_runtime_summary`
  - `capabilities_list`
  - `capabilities_get_detail`
  - `artifacts_list`
  - `artifacts_get_detail`
  - `discovery_get_dashboard`
  - `discovery_get_latest_intelligence`
  - `discovery_get_runbook`
  - `discovery_compare_sessions`
- helper client: `tools/external_mcp_client.py`
- stdio bridge: `tools/external_mcp_stdio_bridge.py`

## Required Setup

1. Start Splunk Discovery Tool.
2. Enable the external MCP surface. In the app, open Settings, then the Security tab, turn on Enable External MCP under Sign-in and API Settings, and click Save Settings.
3. Issue an `inbound_mcp` token with the `mcp:tools:read` scope. In the app, use Create Token under Access Tokens on the Security tab and choose the Inbound MCP token type. Only admins can issue tokens when sign-in is on.
4. If you want useful search and context results, make sure the Knowledge Base capability (`rag_chromadb`) is installed, turned on, and indexed. If the Knowledge Base shows a Reindex needed notice, reindex it first; report changes are never indexed on their own.
5. If you want artifact and discovery coverage, make sure Splunk Discovery Tool has generated output under `output/`.

## Transport Notes

The surface exposes MCP-style tool access as JSON-RPC 2.0 over a single HTTP POST endpoint.

- info route: `GET /api/external/mcp/info`
- MCP request route: `POST /api/external/mcp`
- auth header: `Authorization: Bearer <token>`
- token type: `inbound_mcp`
- required scope: `mcp:tools:read`
- MCP protocol version: `2025-03-26`
- supported methods: `initialize`, `notifications/initialized` (or `initialized`), `ping`, `tools/list`, and `tools/call`
- default rate limit: 30 requests per 60-second window per `inbound_mcp` token. Admins can change it with the `security.external_mcp_rate_limit_requests` (1 to 10000) and `security.external_mcp_rate_limit_window_seconds` (1 to 3600) settings through `POST /api/config`.

This is a practical read-only inbound MCP surface for scripted clients and HTTP-capable agent adapters.

If an MCP client only supports a command-launched stdio server, use the stdio bridge. It reads JSON-RPC messages from stdin, forwards each one to `POST /api/external/mcp`, and writes the responses to stdout. The bridge uses `Content-Length` header framing for each message, so the client must use that framing as well. Messages without an `id` (notifications) are forwarded but get no response.

Example bridge launch:

```powershell
$env:DT4SMS_MCP_TOKEN = Get-Content .\external_mcp.token -Raw
python .\tools\external_mcp_stdio_bridge.py --base-url http://127.0.0.1:8003
```

The bridge also accepts `--token` (defaults to `DT4SMS_MCP_TOKEN`) and `--timeout` in seconds (defaults to `DT4SMS_HTTP_TIMEOUT`, or 20). It exits with an error if no token is set.

Typical MCP client launcher shape:

```json
{
    "command": "python",
    "args": ["tools/external_mcp_stdio_bridge.py", "--base-url", "http://127.0.0.1:8003"],
    "env": {
        "DT4SMS_MCP_TOKEN": "YOUR_TOKEN"
    }
}
```

## Fast Path With The Helper Script

Default base URL:

```text
http://127.0.0.1:8003
```

You can override it with `--base-url` or `DT4SMS_BASE_URL`. The `--base-url`, `--admin-user`, and `--admin-password` flags go before the command name.

### 1. Enable The External MCP Surface

If sign-in is on, provide admin credentials. If sign-in is off, the script calls the admin endpoint (`POST /api/config`) directly.

```powershell
python .\tools\external_mcp_client.py --admin-user admin --admin-password "YOUR_ADMIN_PASSWORD" enable-mcp
```

### 2. Issue A Token

The helper always issues an `inbound_mcp` token with the `mcp:tools:read` scope. `--expires-days` defaults to 30.

```powershell
python .\tools\external_mcp_client.py --admin-user admin --admin-password "YOUR_ADMIN_PASSWORD" issue-token --enable-mcp --name "Local Inbound MCP" --save-token .\external_mcp.token
```

If you want the token attributed to a specific local user:

```powershell
python .\tools\external_mcp_client.py --admin-user admin --admin-password "YOUR_ADMIN_PASSWORD" issue-token --name "Analyst MCP Token" --owner-user-id 2
```

### 3. Discover Setup Metadata

```powershell
python .\tools\external_mcp_client.py info
```

### 4. Initialize And Inspect Tools

If you saved the token to a file:

```powershell
$env:DT4SMS_MCP_TOKEN = Get-Content .\external_mcp.token -Raw
python .\tools\external_mcp_client.py initialize
python .\tools\external_mcp_client.py list-tools
```

### 5. Call Read-Only MCP Tools

Convenience wrappers:

```powershell
python .\tools\external_mcp_client.py search --query "How should I investigate platform health issues?" --limit 4
python .\tools\external_mcp_client.py list-assets
python .\tools\external_mcp_client.py get-asset --asset-id asset-123
python .\tools\external_mcp_client.py build-context --query "Show me queue pressure guidance" --limit 4
python .\tools\external_mcp_client.py runtime-summary
python .\tools\external_mcp_client.py list-capabilities
python .\tools\external_mcp_client.py get-capability --capability-name rag_chromadb
python .\tools\external_mcp_client.py list-artifacts --limit 10
python .\tools\external_mcp_client.py get-artifact --artifact-name v2_intelligence_blueprint_20260429_125745.json --max-chars 4000
python .\tools\external_mcp_client.py discovery-dashboard
python .\tools\external_mcp_client.py discovery-intelligence
python .\tools\external_mcp_client.py discovery-runbook --persona analyst
python .\tools\external_mcp_client.py discovery-compare --current-selection latest --baseline-selection previous
```

Other wrapper flags: `list-capabilities` and `get-capability` accept `--refresh-health`; `list-artifacts` accepts `--session-timestamp` and `--artifact-kind` (`report` or `infographic`); `discovery-runbook` accepts `--timestamp`, `--persona` (`admin`, `analyst`, or `executive`), and `--voice` (`direct`, `evidence`, or `executive`). Every wrapper accepts `--token`.

Generic tool invocation:

```powershell
python .\tools\external_mcp_client.py call-tool --tool-name rag_search --arguments-json '{"query":"platform health","limit":4}'
python .\tools\external_mcp_client.py call-tool --tool-name artifacts_list --arguments-json '{"limit":10}'
```

## Manual HTTP Examples

### PowerShell

```powershell
$base = "http://127.0.0.1:8003"
$token = (Get-Content .\external_mcp.token -Raw).Trim()
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

Invoke-RestMethod "$base/api/external/mcp/info"

$initialize = @{
    jsonrpc = "2.0"
    id = 1
    method = "initialize"
    params = @{
        protocolVersion = "2025-03-26"
        clientInfo = @{ name = "local-smoke"; version = "1.0" }
    }
} | ConvertTo-Json -Depth 8
Invoke-RestMethod "$base/api/external/mcp" -Method Post -Headers $headers -Body $initialize

$listTools = @{ jsonrpc = "2.0"; id = 2; method = "tools/list" } | ConvertTo-Json -Depth 8
Invoke-RestMethod "$base/api/external/mcp" -Method Post -Headers $headers -Body $listTools

$search = @{
    jsonrpc = "2.0"
    id = 3
    method = "tools/call"
    params = @{
        name = "rag_search"
        arguments = @{ query = "How do I investigate ingestion delay?"; limit = 4 }
    }
} | ConvertTo-Json -Depth 8
Invoke-RestMethod "$base/api/external/mcp" -Method Post -Headers $headers -Body $search

$runtimeSummary = @{
    jsonrpc = "2.0"
    id = 4
    method = "tools/call"
    params = @{
        name = "system_get_runtime_summary"
        arguments = @{}
    }
} | ConvertTo-Json -Depth 8
Invoke-RestMethod "$base/api/external/mcp" -Method Post -Headers $headers -Body $runtimeSummary

$artifacts = @{
    jsonrpc = "2.0"
    id = 5
    method = "tools/call"
    params = @{
        name = "artifacts_list"
        arguments = @{ limit = 10 }
    }
} | ConvertTo-Json -Depth 8
Invoke-RestMethod "$base/api/external/mcp" -Method Post -Headers $headers -Body $artifacts
```

### curl

```bash
BASE_URL="http://127.0.0.1:8003"
TOKEN="YOUR_TOKEN"

curl "$BASE_URL/api/external/mcp/info"

curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$BASE_URL/api/external/mcp" -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"curl-smoke","version":"1.0"}}}'

curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$BASE_URL/api/external/mcp" -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$BASE_URL/api/external/mcp" -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rag_search","arguments":{"query":"platform health","limit":4}}}'

curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$BASE_URL/api/external/mcp" -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"system_get_runtime_summary","arguments":{}}}'

curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$BASE_URL/api/external/mcp" -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"artifacts_list","arguments":{"limit":10}}}'
```

## Tool Summary

- `rag_search`: returns sanitized search and context results for a query. Arguments: `query` (required), `limit` (1 to 10, default 4).
- `rag_list_assets`: returns sanitized managed asset metadata. No arguments.
- `rag_get_asset_detail`: returns sanitized detail for one managed asset. Arguments: `asset_id` (required).
- `rag_build_context`: returns the same read-only context pack shape used by the external RAG search route. Arguments: `query` (required), `limit` (1 to 10, default 4).
- `system_get_runtime_summary`: returns a sanitized install and runtime posture and coverage summary without secrets. No arguments.
- `capabilities_list`: returns sanitized capability inventory and health state. Arguments: `refresh_health` (default false).
- `capabilities_get_detail`: returns sanitized detail for one capability, including safe capability-specific readiness fields. Arguments: `capability_name` (required), `refresh_health` (default false).
- `artifacts_list`: returns sanitized generated artifact metadata from the Splunk Discovery Tool output catalog. Arguments: `limit` (1 to 50, default 20), `session_timestamp` (`YYYYMMDD_HHMMSS`), `artifact_kind` (`report` or `infographic`).
- `artifacts_get_detail`: returns sanitized metadata plus a bounded preview for one artifact. Arguments: `artifact_name` (required), `max_chars` (256 to 50000, default 12000).
- `discovery_get_dashboard`: returns a compact discovery dashboard with KPIs, trends, and recent session summaries. No arguments.
- `discovery_get_latest_intelligence`: returns the latest intelligence blueprint with sanitized artifact metadata. No arguments.
- `discovery_get_runbook`: returns a persona-scoped runbook plus a compact selected-session summary. Arguments: `timestamp`, `persona` (`admin`, `analyst`, or `executive`, default `admin`), `voice` (`direct`, `evidence`, or `executive`, default `direct`).
- `discovery_compare_sessions`: returns a compact compare payload with metrics, deltas, and session summaries. Arguments: `current_selection` and `baseline_selection` (for example `latest`, `previous`, or a session timestamp).

The RAG tools read the Knowledge Base (`rag_chromadb`) only. The Splunk documentation downloaded by the knowledge library is not exposed through this surface.

## Response And Security Notes

- All MCP tools are read-only.
- Tool responses are sanitized to avoid leaking local storage and manifest paths.
- Runtime summary responses expose configuration state, not raw secrets or external endpoint values.
- Artifact detail previews are bounded and may be truncated for context safety.
- Discovery tools expose compact session summaries rather than full session payloads.
- Tokens are shown only once, when they are created. Tokens start with `dt4sms_`.
- A disabled MCP surface returns `404` on both `/api/external/mcp/info` and `/api/external/mcp`.
- A missing token returns `401`.
- An invalid, expired, revoked, or wrong-type token (for example an `external_api` token) returns `401`.
- A token without the required scope returns `403`.
- Exceeding the per-token request budget returns `429` with a `Retry-After` header.
- Unsupported methods and unknown tool names return JSON-RPC error `-32601`. Missing or invalid tool arguments return JSON-RPC error `-32602`. Other tool failures return a JSON-RPC error object as well.
- The helper client treats either HTTP errors or JSON-RPC error objects as failures.
- The stdio bridge turns HTTP errors that do not carry a JSON-RPC body (such as `401`, `403`, `404`, or `429`) into a JSON-RPC error with code `-32001`.

## Useful Environment Variables

```text
DT4SMS_BASE_URL=http://127.0.0.1:8003
DT4SMS_MCP_TOKEN=YOUR_TOKEN
DT4SMS_ADMIN_USER=admin
DT4SMS_ADMIN_PASSWORD=YOUR_ADMIN_PASSWORD
DT4SMS_HTTP_TIMEOUT=20
```

## See Also

The external REST quickstart is in `docs/EXTERNAL_RAG_API_QUICKSTART.md`.
