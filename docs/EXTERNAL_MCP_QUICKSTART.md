# External MCP Quickstart

This phase adds a read-only inbound MCP surface for DT4SMS under `/api/external/mcp`.

It is intended for agent clients or lightweight automation that want MCP-style tool access to DT4SMS retrieval, artifact, capability, and runtime-summary context without needing bespoke REST integration.

## What Ships In This Slice

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

1. Start DT4SMS.
2. Enable the external MCP surface.
3. Issue an `inbound_mcp` token with the `mcp:tools:read` scope.
4. If you want useful search/context results, make sure `rag_chromadb` is installed, enabled, and indexed.
5. If you want artifact and discovery coverage, make sure DT4SMS has generated output under `output/`.

## Transport Notes

The current slice exposes MCP-style tool access as JSON-RPC 2.0 over a single HTTP POST endpoint.

- info route: `GET /api/external/mcp/info`
- MCP request route: `POST /api/external/mcp`
- auth header: `Authorization: Bearer <token>`
- token type: `inbound_mcp`
- required scope: `mcp:tools:read`
- default rate limit: 30 requests per 60-second window per `inbound_mcp` token

This is a practical read-only inbound MCP surface for scripted clients and HTTP-capable agent adapters.

If a third-party MCP client only supports stdio or a different transport launcher shape, use the helper client or a thin bridge until a richer transport layer is added later.

The repo now ships a thin stdio bridge that forwards framed MCP requests to the same HTTP endpoint. This lets command-launch MCP clients point at DT4SMS without writing their own adapter layer.

Example bridge launch:

```powershell
$env:DT4SMS_MCP_TOKEN = Get-Content .\external_mcp.token -Raw
python .\tools\external_mcp_stdio_bridge.py --base-url http://127.0.0.1:8003
```

Typical MCP client launcher shape:

```json
{
    "command": "python",
    "args": ["tools/external_mcp_stdio_bridge.py", "--base-url", "http://127.0.0.1:8003"],
    "env": {
        "DT4SMS_MCP_TOKEN": "dt4sms_..."
    }
}
```

## Fast Path With The Helper Script

Default base URL:

```text
http://127.0.0.1:8003
```

You can override it with `--base-url` or `DT4SMS_BASE_URL`.

### 1. Enable The External MCP Surface

If auth is enabled, provide admin credentials. If auth is disabled, the script can call the admin endpoint directly.

```powershell
python .\tools\external_mcp_client.py enable-mcp --admin-user admin --admin-password BetterPassword123!
```

### 2. Issue A Token

```powershell
python .\tools\external_mcp_client.py issue-token --enable-mcp --admin-user admin --admin-password BetterPassword123! --name "Local Inbound MCP" --save-token .\external_mcp.token
```

If you want the token attributed to a specific local user:

```powershell
python .\tools\external_mcp_client.py issue-token --admin-user admin --admin-password BetterPassword123! --name "Analyst MCP Token" --owner-user-id 2
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

Generic tool invocation:

```powershell
python .\tools\external_mcp_client.py call-tool --tool-name rag_search --arguments-json '{"query":"platform health","limit":4}'
python .\tools\external_mcp_client.py call-tool --tool-name artifacts_list --arguments-json '{"limit":10}'
```

## Manual HTTP Examples

### PowerShell

```powershell
$base = "http://127.0.0.1:8003"
$token = Get-Content .\external_mcp.token -Raw
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

- `rag_search`: returns sanitized search/context results for a query
- `rag_list_assets`: returns sanitized managed asset metadata
- `rag_get_asset_detail`: returns sanitized detail for one managed asset
- `rag_build_context`: returns the same read-only context pack shape used by the external RAG search surface
- `system_get_runtime_summary`: returns sanitized install/runtime posture and coverage summary without secrets
- `capabilities_list`: returns sanitized capability inventory and health state
- `capabilities_get_detail`: returns sanitized detail for one capability, including safe capability-specific readiness fields
- `artifacts_list`: returns sanitized generated-artifact metadata from the DT4SMS output catalog
- `artifacts_get_detail`: returns sanitized metadata plus a bounded preview for one artifact
- `discovery_get_dashboard`: returns a compact discovery dashboard with KPIs, trends, and recent session summaries
- `discovery_get_latest_intelligence`: returns the latest intelligence blueprint with sanitized artifact metadata
- `discovery_get_runbook`: returns a persona-scoped runbook plus a compact selected-session summary
- `discovery_compare_sessions`: returns a compact compare payload with metrics, deltas, and session summaries

## Response And Security Notes

- All MCP tools are read-only in this slice.
- Tool responses are sanitized to avoid leaking local storage and manifest paths.
- Runtime summary responses expose configuration state, not raw secrets or external endpoint values.
- Artifact detail previews are bounded and may be truncated for context safety.
- Discovery tools expose compact session summaries rather than full hydrated session payloads.
- Missing token returns `401`.
- Wrong token type or expired token returns `401`.
- Missing required scope returns `403`.
- Exceeding the per-token request budget returns `429` with a `Retry-After` header.
- Unsupported methods or invalid tool arguments return JSON-RPC errors.
- The helper client treats either HTTP errors or JSON-RPC error objects as failures.

## Useful Environment Variables

```text
DT4SMS_BASE_URL=http://127.0.0.1:8003
DT4SMS_MCP_TOKEN=dt4sms_...
DT4SMS_ADMIN_USER=admin
DT4SMS_ADMIN_PASSWORD=BetterPassword123!
```

## See Also

The external REST quickstart lives in `docs/EXTERNAL_RAG_API_QUICKSTART.md`.