# External RAG API Quickstart

This phase adds a read-only external RAG API under `/api/external/*`.

The goal is to let another tool, script, analyst workflow, or future agent client query the DT4SMS RAG asset plane without using the operator UI.

## What Ships In This Slice

- unauthenticated discovery endpoint: `GET /api/external/info`
- token-authenticated RAG index summary: `GET /api/external/rag/index-summary`
- token-authenticated RAG search: `POST /api/external/rag/search`
- token-authenticated RAG asset catalog: `GET /api/external/rag/assets`
- token-authenticated RAG asset detail: `GET /api/external/rag/assets/{asset_id}`
- helper client: `tools/external_rag_api_client.py`

## Required Setup

1. Start DT4SMS.
2. Enable the external API.
3. Issue an `external_api` token with the scopes your client needs.
4. If you want useful RAG search results, make sure `rag_chromadb` is installed, enabled, and indexed.

Supported scopes in this slice:

- `rag:search`
- `rag:assets:read`

Default rate limit in this slice:

- 30 requests per 60-second window per `external_api` token
- exceeded limits return `429` with a `Retry-After` header

## Fast Path With The Helper Script

Default base URL:

```text
http://127.0.0.1:8003
```

You can override it with `--base-url` or `DT4SMS_BASE_URL`.

### 1. Enable The External API

If auth is enabled, provide admin credentials. If auth is disabled, the script can call the admin endpoint directly.

```powershell
python .\tools\external_rag_api_client.py enable-api --admin-user admin --admin-password BetterPassword123!
```

### 2. Issue A Token

This example creates one token that can both search and read asset metadata.

```powershell
python .\tools\external_rag_api_client.py issue-token --enable-api --admin-user admin --admin-password BetterPassword123! --name "Local External RAG" --scopes rag:search rag:assets:read --expires-days 30 --save-token .\external_rag.token
```

You can also supply a user owner if you want attributable user-owned tokens:

```powershell
python .\tools\external_rag_api_client.py issue-token --admin-user admin --admin-password BetterPassword123! --name "Analyst RAG Token" --owner-user-id 2 --scopes rag:search rag:assets:read
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
$token = Get-Content .\external_rag.token -Raw
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

## Response Notes

- The external API intentionally strips local file-system paths such as storage directories, manifest paths, and asset content file names.
- Tokens are only revealed at creation time.
- Listing or loading token metadata later will not return the plaintext token.
- Missing token returns `401`.
- Wrong scope returns `403`.
- Disabled external API returns `404`.
- Exceeding the per-token request budget returns `429`; callers should honor the `Retry-After` header before retrying.

## Useful Environment Variables

```text
DT4SMS_BASE_URL=http://127.0.0.1:8003
DT4SMS_EXTERNAL_TOKEN=dt4sms_...
DT4SMS_ADMIN_USER=admin
DT4SMS_ADMIN_PASSWORD=BetterPassword123!
```

## Current Scope Boundary

This guide is REST-only.

The inbound MCP surface now ships separately under `/api/external/mcp` and uses the same read-only posture plus DT4SMS-issued scoped tokens. See `docs/EXTERNAL_MCP_QUICKSTART.md` for MCP setup, helper-client usage, and the stdio bridge launcher shape.