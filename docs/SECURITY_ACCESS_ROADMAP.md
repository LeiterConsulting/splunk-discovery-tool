# Security, Access, and External API Roadmap

> Historical note: this document started as the implementation roadmap for DT4SMS security and external access. Local auth, OIDC, per-user MCP assignment, token issuance, the read-only external RAG API, the inbound MCP surface, and browser account-function coverage now ship in the current repo. The phase sections below remain useful as implementation history and extension notes.

## Goal

Document the optional security and access model in DT4SMS without making the base install or demo workflow more complex. The app should continue to install and run exactly as it does today when security features are not enabled.

This roadmap covers:

- optional local user authentication
- shipped OIDC integration and future-friendly provider abstraction
- per-user MCP connection assignment
- inbound API and MCP token management
- a read-only external RAG API and inbound MCP server surface

## Guardrails

1. Demo mode remains the default

Fresh installs continue to run without users, login prompts, or token setup. Security features are opt-in from Settings.

2. Security state is separate from install config

`config.encrypted` should remain focused on install-wide settings and secrets. Users, password hashes, sessions, token metadata, audit trails, and assignments should live in a dedicated application data store.

3. Authentication is provider-based

Local username/password and OIDC are the current providers. Keep the authentication provider abstraction so additional SSO options can be added later without rewriting authorization, sessions, or user-to-MCP assignment logic.

4. External access is read-only first

The initial external RAG API and inbound MCP server should be read-only. Write operations can be evaluated later after the permission model and audit controls are proven.

5. User identity resolves runtime access

Once authentication is enabled, the active MCP connection should be resolved from the signed-in user or that user's allowed assignments, not a single global MCP configuration.

## Target Architecture

### 1. Install-wide configuration

Continue using `config.encrypted` for:

- web server settings
- LLM configuration
- capability enablement
- install-wide feature toggles
- encryption/material references for protected local stores

Add install-wide security toggles such as:

- `auth_enabled`
- `auth_provider`
- `external_api_enabled`
- `external_mcp_enabled`
- session timeout defaults
- password policy defaults

### 2. Security data store

Introduce a dedicated local store, preferably SQLite, for:

- users
- password hashes
- password reset state
- roles and permissions
- sessions
- personal access tokens
- external service tokens
- audit events
- MCP connection definitions and user assignments

Sensitive secret fields stored in the database should be encrypted at rest using application-managed encryption material, rather than stored in plaintext.

### 3. Authentication providers

Define a small provider interface with implementations for:

- `local_password`
- `oidc`

That provider boundary should handle identity proof and profile claims. The app's authorization, session handling, role checks, and MCP assignment logic should remain provider-agnostic.

### 4. Authorization model

Start with a small role model:

- `admin`: full settings, users, tokens, connections, and platform controls
- `analyst`: authenticated product use, assigned MCP connections, no admin settings
- `viewer`: read-oriented authenticated role with restricted runtime MCP access

The first version should keep authorization simple and explicit. Avoid over-designing scopes inside the core app before the access patterns are real.

### 5. External access model

Add two separate inbound surfaces:

- read-only REST API for RAG and discovery metadata
- read-only inbound MCP server for agent clients

These must use inbound DT4SMS-issued tokens. They are not the same as outbound MCP credentials used to connect to Splunk-side services.

## Settings Information Architecture

Add a dedicated Security or Access area in Settings with these pages:

### Authentication

- enable or disable authentication
- choose provider type
- session timeout and password policy controls
- first-enable bootstrap flow

### Users

- create, update, disable, delete users
- force password reset
- assign role
- assign default MCP connection or allowed MCP connections

### MCP Connections

- create shared outbound MCP connection definitions
- test connections
- enable or disable connections
- inspect assignment usage

### Access Tokens

- create and revoke external API tokens
- create and revoke inbound MCP tokens
- assign scopes and expiry
- show last used time and owner

### Audit

- login attempts
- password reset events
- token creation and revocation
- admin changes
- external API and MCP access summaries

## Delivery Plan (Historical)

## Phase 0 - Foundation and Data Model (shipped)

Objective: prepare the application for security features without changing the current demo-mode experience.

Deliverables:

- define the security configuration toggles in `config.encrypted`
- introduce a security data store and migration/bootstrap logic
- create service boundaries for auth, sessions, tokens, roles, and MCP assignment
- add request-context identity resolution hooks in the web layer
- document the new security modes and migration story

Acceptance criteria:

- existing installs continue to run without login when auth is disabled
- enabling the security feature initializes the new data store safely
- no existing discovery/chat/report flows regress in demo mode

## Phase 1 - Local Authentication v1 (shipped)

Objective: ship optional local username/password auth with secure defaults.

Deliverables:

- login, logout, and session management
- admin bootstrap on first enable
- forced password reset on first login
- admin route guards for settings and security pages
- password hashing with a modern algorithm such as Argon2id
- session cookies and CSRF protections where appropriate

Acceptance criteria:

- auth-disabled mode behaves exactly like today
- auth-enabled mode requires login for application use
- first bootstrap admin must reset password before normal access
- admin can sign out and sign back in successfully

## Phase 2 - User Management and MCP Assignment (shipped)

Objective: turn global MCP configuration into a multi-user access model.

Deliverables:

- user CRUD in settings
- MCP connection CRUD in settings
- per-user MCP assignment model
- runtime resolution of the user's effective MCP connection
- safe fallback behavior if a user has no valid assignment

Acceptance criteria:

- multiple users can exist with different assigned MCP connections
- the app no longer depends on one global active MCP definition for secured mode
- user actions route through the correct assigned connection

## Phase 3 - Token System (shipped)

Objective: add a proper token system for external surfaces.

Deliverables:

- token issuance and one-time reveal flow
- hashed token storage
- scopes, expiry, revocation, and usage tracking
- user-owned and admin/service-managed token support
- settings page for token lifecycle management

Suggested initial scopes:

- `rag:search`
- `rag:assets:read`
- `mcp:tools:read`
- `admin:tokens`

Acceptance criteria:

- admins can create, revoke, and review tokens
- plaintext tokens are not stored after initial reveal
- every inbound token action is attributable to a user or service owner

## Phase 4 - External Read-Only RAG API (shipped)

Objective: expose a stable, authenticated external API without leaking internal operator endpoints.

Deliverables:

- new external route namespace such as `/api/external/rag/*`
- small unauthenticated discovery endpoint with no sensitive data
- authenticated read-only asset and search endpoints
- audit logging and rate limiting
- documentation for external consumers

Candidate v1 endpoints:

- `GET /api/external/info`
- `GET /api/external/rag/index-summary`
- `POST /api/external/rag/search`
- `GET /api/external/rag/assets`
- `GET /api/external/rag/assets/{asset_id}`

Acceptance criteria:

- external consumers cannot hit internal operator endpoints directly
- only read-only routes are available in v1
- access requires valid scoped tokens unless using the discovery endpoint

## Phase 5 - Inbound Read-Only MCP Server (shipped)

Objective: provide an agent-friendly tool surface over the same backend services.

Deliverables:

- inbound MCP server endpoint
- read-only tool registration backed by the same permission checks as the external API
- token-based authentication for MCP clients
- capability discovery metadata for client setup

Candidate v1 tools:

- `rag_search`
- `rag_list_assets`
- `rag_get_asset_detail`
- `rag_build_context`

Acceptance criteria:

- MCP tools are read-only
- permission checks and audit behavior match the REST API surface
- unauthenticated clients can discover setup requirements but cannot retrieve protected content

## Phase 6 - OIDC and SSO Integration (shipped)

Objective: add enterprise identity without refactoring the rest of the platform.

Deliverables:

- OIDC provider implementation for the auth abstraction
- provider config in Settings
- local-to-SSO user linking or migration strategy
- role mapping and default connection assignment rules from claims where useful

Acceptance criteria:

- local auth and OIDC can be supported behind the same app-level authorization model
- session and role handling do not depend on the provider type
- the app can be tested against a local or sandbox OIDC provider without production infrastructure

## Testing Strategy

### Immediate test coverage

- unit tests for auth services, password policy, token hashing, and assignment resolution
- API tests for login, logout, forced reset, permission checks, and token-protected routes
- browser tests for demo mode, auth-enabled mode, bootstrap admin, user CRUD, token creation, and revocation

### Additional SSO testing

There is a practical path even without a production SSO system today:

- keep OIDC behind a provider abstraction until implementation time
- add provider contract tests now so the app-side behavior is stable
- when ready, validate with a local development identity provider such as Keycloak, Authentik, or Zitadel
- add a minimal test harness or container-compose dev setup later for repeatable SSO validation

## Migration and Rollout Notes

- existing installs should not be forced into secured mode
- enabling auth should be an explicit admin action in Settings
- the initial enablement flow should create or reveal a bootstrap admin credential and require immediate reset
- documentation and installer messaging must continue to present the current demo path as the default quick start

## Historical Build Order

1. Phase 0 and Phase 1 together
2. Phase 2 user-to-MCP assignment
3. Phase 3 token system
4. Phase 4 external RAG API
5. Phase 5 inbound MCP server
6. Phase 6 OIDC and SSO

This sequence keeps the simple install intact, lands the security boundary before external exposure, and avoids building public surfaces on top of a single-user or globally shared trust model.