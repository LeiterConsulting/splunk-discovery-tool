# Security, Access, and External API Roadmap

> Historical note: this document started as the implementation roadmap for Splunk Discovery Tool security and external access. As of release 2.0.0, local sign-in, OIDC sign-in, per-user MCP assignment, token issuance, the read-only external RAG API, the inbound MCP surface, and browser coverage of account functions all ship. An in-app audit view has not shipped yet; audit events are recorded in the security database only. The phase sections below remain useful as implementation history and extension notes.

## Goal

Document the optional security and access model in Splunk Discovery Tool without making the base install or first-run workflow more complex. The app installs and runs the same way when security features are off: sign-in is off and anyone who can reach the app can use it.

This roadmap covers:

- optional local user sign-in
- shipped OIDC sign-in behind a provider abstraction that can take more providers later
- per-user MCP connection assignment
- inbound API and MCP token management
- a read-only external RAG API and inbound MCP server surface
- data that is kept per user when sign-in is on

## Guardrails

1. Open access remains the default

Fresh installs run without users, sign-in prompts, or token setup. With sign-in off, the app says anyone can use it. Security features are opt-in from Settings.

2. Security state is separate from install config

`config.encrypted` stays focused on install-wide settings and secrets, including the saved MCP connection definitions and LLM credentials. Users, password hashes, sessions, token metadata, external identity links, and audit events live in a separate SQLite store, `security.db`, in the app directory.

3. Authentication is provider-based

Local username and password (`local_password`) and OIDC (`oidc`) are the current providers. Keep the provider abstraction so other SSO options can be added later without rewriting authorization, sessions, or user-to-MCP assignment logic.

4. External access is read-only first

The external RAG API and inbound MCP server are read-only. Write operations can be evaluated later, after the permission model and audit controls are proven.

5. User identity resolves runtime access

When sign-in is on, the active MCP connection is resolved from the signed-in user's assigned connection, not from the single install-wide active MCP configuration.

## Target Architecture

### 1. Install-wide configuration

`config.encrypted` holds:

- web server settings
- LLM configuration and saved LLM credentials
- saved MCP connection definitions (`saved_mcp_configs`) and the install-wide active MCP connection
- capability settings
- install-wide feature toggles
- knowledge library settings (`library.allow_online_sources`, off by default; only admins can turn it on)

Install-wide security settings live under `security` in the same file. These are the shipped names and defaults:

- `auth_enabled`: `false`
- `auth_provider`: `local_password` (or `oidc`)
- `external_api_enabled`: `false`
- `external_mcp_enabled`: `false`
- `external_api_rate_limit_requests`: `30` (1 to 10000)
- `external_api_rate_limit_window_seconds`: `60` (1 to 3600)
- `external_mcp_rate_limit_requests`: `30` (1 to 10000)
- `external_mcp_rate_limit_window_seconds`: `60` (1 to 3600)
- `session_timeout_minutes`: `480` (15 to 10080)
- `password_min_length`: `12` (8 to 256)
- `require_password_reset_on_first_login`: `true`
- `oidc`: provider settings (see Phase 6)

Admins change these through Settings or `POST /api/config`. A partial `security` object only changes the fields it includes.

### 2. Security data store

The shipped store is SQLite (`security.db`) with these tables:

- `users`: username, Argon2id password hash, role, enabled flag, password reset flag, assigned MCP connection name (`mcp_config_name`)
- `sessions`: SHA-256 hash of the session token, owner, last seen time, expiry, revocation
- `access_tokens`: SHA-256 hash of the token, a short display prefix, token type, scopes, owner, creator, expiry, revocation, last use
- `external_identities`: OIDC provider and subject linked to a local user, with the last claims received
- `audit_events`: sign-in, session, password, user, token, and identity events

No plaintext passwords, session tokens, or access tokens are stored. MCP connection secrets stay in `config.encrypted`, not in `security.db`.

### 3. Authentication providers

The provider interface has two implementations:

- `local_password`
- `oidc`

The provider boundary handles identity proof and profile claims. Authorization, session handling, role checks, and MCP assignment logic stay provider-agnostic. Both providers issue the same `dt4sms_session` cookie (HttpOnly, SameSite=Lax, Secure when served over HTTPS) whose lifetime follows `session_timeout_minutes`.

### 4. Authorization model

The shipped role model has three roles:

- `admin`: full settings, users, tokens, connections, and platform controls. Uses the assigned MCP connection, or the install-wide active connection when none is assigned.
- `analyst`: signed-in product use through the assigned MCP connection only, with no admin settings. An analyst with no assignment has no runtime MCP access.
- `viewer`: signed-in, read-oriented role with no runtime MCP access, even when a connection is assigned.

Admin-only endpoints when sign-in is on:

- `GET` and `POST /api/config`
- `/api/security/users` and `/api/security/users/{user_id}` (list, create, read, update, delete)
- `/api/security/tokens`, `/api/security/tokens/{token_id}`, and `POST /api/security/tokens/{token_id}/revoke`
- `/api/credentials` and `/api/mcp-configs` routes, including load and test
- knowledge library admin routes: `POST /api/knowledge-library/settings`, `POST /api/knowledge-library/refresh`, and `POST /api/knowledge-library/pack/import`

`POST /api/discovery/m26-14/validate` (run an M-26-14 check) requires the analyst or admin role. Other app routes, including the capability lifecycle routes under `/api/capabilities/{name}/...` and `POST /api/chat/settings`, require a signed-in user but do not check the role.

Keep authorization simple and explicit. Avoid adding fine-grained scopes inside the core app before the access patterns are real.

### 5. External access model

Two separate inbound surfaces ship:

- read-only REST API for Knowledge Base search and asset metadata (`/api/external/rag/*`, `external_api` tokens)
- read-only inbound MCP server for agent clients (`/api/external/mcp`, `inbound_mcp` tokens)

Both use inbound tokens issued by Splunk Discovery Tool. They are not the same as the outbound MCP credentials used to connect to Splunk-side services. The sign-in session check skips `/api/external/*`; those routes check bearer tokens instead.

### 6. User-scoped data

When sign-in is on, chat goals and the saved chats under each goal are stored per user under `output/chat_data/goals/`. When sign-in is off, everyone shares one goal library. Chat settings (`output/chat_data/chat_settings.json`) are one install-wide file in both modes.

## Settings Information Architecture

The roadmap proposed a dedicated Security or Access area with the pages below. The shipped Settings tabs are Connections, Users, Security, Appearance, and Troubleshoot. Each proposed page maps to them as follows.

### Authentication

Shipped on the Security tab under Sign-in and API Settings:

- turn sign-in on or off
- choose the sign-in method (local passwords or single sign-on with OIDC)
- session timeout, password policy, and Require Password Change on First Sign-in
- turn on Enable External REST API and Enable External MCP
- first-enable bootstrap flow (an `admin` account that must change its password at first sign-in when that setting is on)

### Users

Shipped on the Users tab (Users and Roles):

- create, update, disable, and delete users
- require a password change
- assign a role
- assign a default MCP connection

Linking an OIDC identity to an existing local user is available through `POST /api/security/users/{user_id}/external-identities`.

### MCP Connections

Shipped on the Connections tab:

- create shared outbound MCP connection definitions
- test connections
- load a connection as the install-wide active connection

Inspecting assignment usage per connection is not shipped.

### Access Tokens

Shipped on the Security tab under Access Tokens:

- create (Create Token, then Issue Token), revoke, and delete External REST API and Inbound MCP tokens
- choose scopes, expiry in days, and an optional owner
- show last used time and owner

### Audit

Not shipped as a page. The app records these events in the `audit_events` table:

- local and OIDC sign-in successes and failures, plus session creation and revocation
- password changes and the bootstrap admin creation
- token issuance, use, scope denials, revocation, and deletion
- user creation, updates, and deletion, and OIDC identity links

External API and MCP access summaries are limited to per-token last used time and source.

## Delivery Plan (Historical)

## Phase 0 - Foundation and Data Model (shipped)

Objective: prepare the application for security features without changing the open-access experience.

Deliverables:

- define the security configuration toggles in `config.encrypted`
- introduce a security data store and migration and bootstrap logic
- create service boundaries for auth, sessions, tokens, roles, and MCP assignment
- add request-context identity resolution hooks in the web layer
- document the security modes and migration story

Acceptance criteria:

- existing installs continue to run without sign-in when sign-in is off
- turning on sign-in initializes the data store safely
- no existing discovery, chat, or report flows regress with sign-in off

## Phase 1 - Local Authentication v1 (shipped)

Objective: ship optional local username and password sign-in with secure defaults.

Deliverables:

- sign-in, sign-out, and session management (`POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/status`)
- admin bootstrap on first enable
- forced password change on first sign-in (`POST /api/auth/reset-password`)
- admin route guards for settings and security pages
- password hashing with Argon2id
- HttpOnly, SameSite=Lax session cookies (there is no separate CSRF token)

Acceptance criteria:

- with sign-in off, the app behaves as before
- with sign-in on, the app requires sign-in for application use
- the bootstrap admin must change the password before normal access
- an admin can sign out and sign back in successfully

## Phase 2 - User Management and MCP Assignment (shipped)

Objective: turn the global MCP configuration into a multi-user access model.

Deliverables:

- user management in Settings
- MCP connection management in Settings
- per-user MCP assignment (`mcp_config_name` on each user)
- runtime resolution of the user's effective MCP connection
- safe fallback when a user has no valid assignment (no MCP access, except admins, who fall back to the install-wide active connection)

Acceptance criteria:

- multiple users can exist with different assigned MCP connections
- with sign-in on, the app does not depend on one global active MCP definition
- user actions route through the correct assigned connection

## Phase 3 - Token System (shipped)

Objective: add a proper token system for external surfaces.

Deliverables:

- token issuance and one-time reveal (tokens start with `dt4sms_`)
- hashed token storage
- scopes, expiry, revocation, deletion, and usage tracking
- user-owned and admin-managed tokens
- Settings section for the token lifecycle

Shipped scopes:

- `rag:search`
- `rag:assets:read`
- `mcp:tools:read`
- `admin:tokens` (accepted when issuing a token, but no route checks it yet)

Token types are `external_api` and `inbound_mcp`. A token only works on the surface that matches its type.

Acceptance criteria:

- admins can create, revoke, and review tokens
- plaintext tokens are not stored after the one-time reveal
- every inbound token action is attributable to a user or to the admin who created the token

## Phase 4 - External Read-Only RAG API (shipped)

Objective: expose a stable, authenticated external API without exposing internal operator endpoints.

Deliverables:

- route namespace `/api/external/rag/*`
- small unauthenticated discovery endpoint with no sensitive data
- authenticated read-only asset and search endpoints
- usage tracking and per-token rate limiting (default 30 requests per 60 seconds, `429` with `Retry-After`)
- documentation for external consumers (`docs/EXTERNAL_RAG_API_QUICKSTART.md`)

Shipped v1 endpoints:

- `GET /api/external/info`
- `GET /api/external/rag/index-summary`
- `POST /api/external/rag/search`
- `GET /api/external/rag/assets`
- `GET /api/external/rag/assets/{asset_id}`

Acceptance criteria:

- external consumers cannot reach internal operator endpoints with an external token
- only read-only routes are available in v1
- access requires a valid scoped token, except for the discovery endpoint

## Phase 5 - Inbound Read-Only MCP Server (shipped)

Objective: provide an agent-friendly tool surface over the same backend services.

Deliverables:

- inbound MCP endpoint (`POST /api/external/mcp`, JSON-RPC 2.0 over HTTP) and setup endpoint (`GET /api/external/mcp/info`)
- read-only tools backed by the same token checks as the external API
- token-based authentication for MCP clients (`inbound_mcp` tokens with `mcp:tools:read`)
- setup metadata for client configuration
- stdio bridge for command-launched clients (`tools/external_mcp_stdio_bridge.py`)

The roadmap proposed four v1 tools (`rag_search`, `rag_list_assets`, `rag_get_asset_detail`, `rag_build_context`). The shipped surface adds `system_get_runtime_summary`, `capabilities_list`, `capabilities_get_detail`, `artifacts_list`, `artifacts_get_detail`, `discovery_get_dashboard`, `discovery_get_latest_intelligence`, `discovery_get_runbook`, and `discovery_compare_sessions`. See `docs/EXTERNAL_MCP_QUICKSTART.md`.

Acceptance criteria:

- MCP tools are read-only
- permission checks, rate limiting, and usage tracking match the REST API surface
- unauthenticated clients can discover setup requirements but cannot retrieve protected content

## Phase 6 - OIDC and SSO Integration (shipped)

Objective: add enterprise identity without refactoring the rest of the platform.

Deliverables:

- OIDC provider implementation for the auth abstraction (`GET /api/auth/oidc/start` and `GET /api/auth/oidc/callback`, with state and nonce checks)
- provider settings in Settings, stored under `security.oidc`: `issuer_url`, `client_id`, `client_secret`, `audience`, `scopes` (default `openid`, `profile`, `email`), `username_claim` (default `preferred_username`), `email_claim` (default `email`), `role_claim` (default `roles`), `default_role` (default `viewer`), and `mcp_assignment_claim` (off by default)
- local-to-SSO user linking: a first OIDC sign-in creates a linked local user, and admins can link an identity to an existing user
- role mapping and MCP assignment from claims: the first `admin`, `analyst`, or `viewer` value in the role claim sets the role, otherwise `default_role` applies; when `mcp_assignment_claim` is set, a claim value that matches a saved MCP connection name becomes the user's assignment

Acceptance criteria:

- local sign-in and OIDC work behind the same app-level authorization model
- session and role handling do not depend on the provider type
- the app can be tested against a local or sandbox OIDC provider without production infrastructure

## Testing Strategy

### Immediate test coverage

- unit tests for auth services, password policy, token hashing, and assignment resolution
- API tests for sign-in, sign-out, forced password change, permission checks, and token-protected routes
- browser tests for open access, sign-in on, bootstrap admin, user management, token creation, and revocation (`tools/test_auth_browser.mjs` and `tools/run_account_function_tests.mjs`; see `docs/AUTH_TESTING.md`)

### Additional SSO testing

There is a practical path even without a production SSO system:

- keep provider contract tests so the app-side behavior stays stable
- validate with a local development identity provider such as Keycloak, Authentik, or Zitadel
- add a minimal test harness or container compose setup later for repeatable SSO validation

## Migration and Rollout Notes

- existing installs are not forced into secured mode
- turning on sign-in is an explicit admin action in Settings
- the first enable creates a bootstrap `admin` account that must change its password at first sign-in when Require Password Change on First Sign-in is on
- documentation and installer messaging continue to present open access as the default quick start

## Historical Build Order

1. Phase 0 and Phase 1 together
2. Phase 2 user-to-MCP assignment
3. Phase 3 token system
4. Phase 4 external RAG API
5. Phase 5 inbound MCP server
6. Phase 6 OIDC and SSO

This sequence kept the simple install intact, landed the security boundary before external exposure, and avoided building public surfaces on top of a single-user or globally shared trust model.
