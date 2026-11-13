# External RAG API Quickstart

Splunk Discovery Tool includes a read-only external RAG API under `/api/external/*`.

It lets another tool, script, analyst workflow, or agent client query the Knowledge Base (`rag_chromadb`) assets without using the web interface. It does not search the Splunk documentation that the knowledge library downloads; that documentation has its own index and is used only inside the app.

## What Ships

- unauthenticated discovery endpoint: `GET /api/external/info`
- token-authenticated RAG index summary: `GET /api/external/rag/index-summary`
- token-authenticated RAG search: `POST /api/external/rag/search`
- token-authenticated RAG asset catalog: `GET /api/external/rag/assets`
- token-authenticated RAG asset detail: `GET /api/external/rag/assets/{asset_id}`
- helper client: `tools/external_rag_api_client.py`

## Required Setup

1. Start Splunk Discovery Tool.
2. Enable the external API. In the app, open Settings, then the Security tab, turn on Enable External REST API under Sign-in and API Settings, and click Save Settings.
3. Issue an `external_api` token with the scopes your client needs. In the app, use Create Token under Access Tokens on the Security tab and choose the External REST API token type. Only admins can issue tokens when sign-in is on.
4. If you want useful search results, make sure the Knowledge Base capability (`rag_chromadb`) is installed, turned on, and indexed. If the Knowledge Base shows a Reindex needed notice, reindex it first; report changes are never indexed on their own.

Supported scopes:

- `rag:search`: required for `POST /api/external/rag/search`
- `rag:assets:read`: required for `GET /api/external/rag/index-summary`, `GET /api/external/rag/assets`, and `GET /api/external/rag/assets/{asset_id}`

Default rate limit:

- 30 requests per 60-second window per `external_api` token
- exceeded limits return `429` with a `Retry-After` header
- admins can change the limit with the `security.external_api_rate_limit_requests` (1 to 10000) and `security.external_api_rate_limit_window_seconds` (1 to 3600) settings through `POST /api/config`

## Fast Path With The Helper Script

Default base URL:

```text
http://127.0.0.1:8003
```

You can override it with `--base-url` or `DT4SMS_BASE_URL`. The `--base-url`, `--admin-user`, and `--admin-password` flags go before the command name.

### 1. Enable The External API

If sign-in is on, provide admin credentials. If sign-in is off, the script calls the admin endpoint (`POST /api/config`) directly.

```powershell
python .\tools\external_rag_api_client.py --admin-user admin --admin-password "YOUR_ADMIN_PASSWORD" enable-api
```

### 2. Issue A Token

This example creates one token that can both search and read asset metadata. `--expires-days` defaults to 30.

```powershell
python .\tools\external_rag_api_client.py --admin-user admin --admin-password "YOUR_ADMIN_PASSWORD" issue-token --enable-api --name "Local External RAG" --scopes rag:search rag:assets:read --expires-days 30 --save-token .\external_rag.token
```

You can also set a user owner if you want tokens attributed to a user:

```powershell
python .\tools\external_rag_api_client.py --admin-user admin --admin-password "YOUR_ADMIN_PASSWORD" issue-token --name "Analyst RAG Token" --owner-user-id 2 --scopes rag:search rag:assets:read
```

### 3. Call The Discovery Endpoint

```powershell
python .\tools\external_rag_api_client.py info
```

### 4. Query The External RAG API

If you saved the token to a file:

```powershell
$env:DT4SMS_EXTERNAL_TOKEN = Get-Content .\external_rag.token -Raw
python .\tools\external_rag_api_client.py index-summary
python .\tools\external_rag_api_client.py search --query "How should I investigate platform health issues?" --limit 4
python .\tools\external_rag_api_client.py list-assets
python .\tools\external_rag_api_client.py get-asset --asset-id asset-123
```

If you prefer passing the token directly:

```powershell
python .\tools\external_rag_api_client.py search --token YOUR_TOKEN --query "Show me queue pressure guidance"
```

## Manual HTTP Examples

### PowerShell

```powershell
$base = "http://127.0.0.1:8003"
$token = (Get-Content .\external_rag.token -Raw).Trim()
$headers = @{ Authorization = "Bearer $token" }

Invoke-RestMethod "$base/api/external/info"
Invoke-RestMethod "$base/api/external/rag/index-summary" -Headers $headers
Invoke-RestMethod "$base/api/external/rag/assets" -Headers $headers
Invoke-RestMethod "$base/api/external/rag/assets/asset-123" -Headers $headers

$body = @{ query = "How do I investigate ingestion delay?"; limit = 4 } | ConvertTo-Json
Invoke-RestMethod "$base/api/external/rag/search" -Method Post -Headers ($headers + @{ "Content-Type" = "application/json" }) -Body $body
```

### curl

```bash
BASE_URL="http://127.0.0.1:8003"
TOKEN="YOUR_TOKEN"

curl "$BASE_URL/api/external/info"
curl -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/external/rag/index-summary"
curl -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/external/rag/assets"
curl -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/external/rag/assets/asset-123"
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$BASE_URL/api/external/rag/search" -d '{"query":"How do I investigate ingestion delay?","limit":4}'
```

## Request And Response Notes

- The search body takes `query` (required) and `limit` (default 4). The server clamps `limit` to the range 1 to 10.
- `GET /api/external/info` returns the API name (`dt4sms-external-rag`), the bearer token type, the supported scopes, each route with its required scope, and whether the inbound MCP surface is on.
- The external API strips local file-system paths such as storage directories, manifest paths, and asset content file names.
- Tokens are shown only once, when they are created. Tokens start with `dt4sms_`.
- Listing or loading token metadata later does not return the plaintext token.
- A disabled external API returns `404` on every `/api/external/*` route, including `/api/external/info`.
- A missing token returns `401`.
- An invalid, expired, revoked, or wrong-type token (for example an `inbound_mcp` token) returns `401`.
- A token without the required scope returns `403`.
- Exceeding the per-token request budget returns `429`; callers should wait for the `Retry-After` value before retrying.

## Useful Environment Variables

```text
DT4SMS_BASE_URL=http://127.0.0.1:8003
DT4SMS_EXTERNAL_TOKEN=YOUR_TOKEN
DT4SMS_ADMIN_USER=admin
DT4SMS_ADMIN_PASSWORD=YOUR_ADMIN_PASSWORD
DT4SMS_HTTP_TIMEOUT=20
```

## Current Scope Boundary

This guide covers the REST API only.

The inbound MCP surface ships separately under `/api/external/mcp`. It has the same read-only posture and uses its own `inbound_mcp` tokens issued by Splunk Discovery Tool. See `docs/EXTERNAL_MCP_QUICKSTART.md` for MCP setup, helper client usage, and the stdio bridge launcher.
