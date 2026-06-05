# M-26-14 Full V1 Implementation Plan

## Status

This document records the current implementation direction for the DT4SMS M-26-14 advisor workspace.

- Model: internal optional capability pack, enabled from Settings and surfaced through the capability framework
- Surface: hidden-until-enabled workspace tab
- Scope: discovery-backed posture plus day-one curated live validation and optional bespoke follow-up
- Trust model: explicitly non-authoritative, evidence-backed, and confidence-labeled

Current implementation snapshot:

- completed: capability registration, capability health wiring, curated validation catalog, discovery-backed profile engine, backend advisor APIs, initial capability auth hardening, targeted M-26-14 backend/frontend test coverage, repeated-validation cache coverage, grounded advisory enrichment using discovery plus retrieval plus optional LLM context, frontend delivery build/sync restoration, static-bundle browser regression coverage, auth-role browser regression coverage
- in progress: initial workspace UI, curated validation UX refinement, advisory-cache freshness strategy for repeated validation reuse
- historical ledger: [DEVELOPMENT_LEDGER.md](./DEVELOPMENT_LEDGER.md)

## Product Direction

Fuller v1 should not wait for a later phase to introduce live validation. It should ship with:

- a discovery-derived M-26-14 posture profile
- a curated validation SPL catalog for common M-26-14 control areas
- explicit operator-triggered live validation actions
- optional LLM or MCP-assisted follow-up only when curated validation leaves material uncertainty

The feature should remain safe and explainable:

- discovery artifacts remain the baseline evidence source
- curated SPL is preferred over generated SPL
- retrieval context should come from indexed or local artifacts before any LLM explanation step runs
- generated SPL must be provenance-labeled and operator-reviewable
- viewers can see posture once the feature is enabled, but live MCP-backed actions remain constrained by existing runtime role gates

## Implementation Phases

### 1. Policy Rubric

Translate [../../M-26-14_logging_network_visibility_vs_code.md](../../M-26-14_logging_network_visibility_vs_code.md) into a structured rubric that covers:

- CEM
- THIRF
- Inventory Visibility
- Collection Coverage
- Collection Operations
- Data Retention
- Log Management
- supporting requirements such as SOC access, timestamp accuracy, and sensitive log handling

Each element should return:

- status
- confidence
- evidence
- gaps
- unknowns
- remediation guidance
- estimated maturity floor where defensible

### 2. Capability Registration

Register `m26_14_advisor` as an internal capability in [../../src/capabilities/registry.py](../../src/capabilities/registry.py).

Use the capability framework, not `SecurityConfig`, as the persistence and runtime health source of truth. Settings remains the admin control plane for enablement.

### 3. Curated Validation Packs

Define day-one curated SPL packs for at least:

- retention and searchability
- audit and admin activity coverage
- network visibility coverage
- privileged change monitoring
- infrastructure change visibility
- alert and detection posture
- IOC and anomaly signals
- timestamp and freshness sanity

Each validation pack should include:

- control area
- objective
- SPL text
- expected evidence
- limitations
- execution mode
- required role

### 4. Live Validation Path

Expose operator-triggered live validation via backend routes in [../../src/web_app.py](../../src/web_app.py). The UI should show the exact SPL before execution and cache recent validation results by session and query signature.

The validation response should also carry grounded operator context assembled in this order:

- discovery-backed M-26-14 profile snapshot
- indexed-artifact or local-artifact context relevant to the selected validation pack
- optional configured-LLM explanation constrained to the grounded evidence already assembled

### 5. Discovery-Backed Profile Engine

Build the advisory profile on top of persisted V2 blueprints from [../../src/discovery/v2_pipeline.py](../../src/discovery/v2_pipeline.py) and [../../src/discovery/context_manager.py](../../src/discovery/context_manager.py) so core discovery latency stays stable.

### 6. Workspace UI

Add a new workspace tab in [../../src/static/app.js](../../src/static/app.js). Visibility should key off capability state from `/api/capabilities`, not the admin-only `/api/config` route.

The page should include:

- non-authoritative banner
- readiness estimate
- maturity breakdown
- CEM and THIRF alignment
- evidence cards
- unknowns and limitations
- remediation roadmap
- curated live validation actions
- discovery-grounding and environment-context panels attached to validation results
- reusable SPL candidates sourced from indexed or local artifacts
- grounded advisory notes that explain relevance and suggest bounded next steps
- compare and history views

### 7. Role Boundaries

Align with current runtime MCP rules in [../../src/web_app.py](../../src/web_app.py):

- admin: can enable and validate
- analyst: can validate when runtime MCP access is available
- viewer: read-only posture, no live MCP-backed validation

### 8. Delivery Integrity

Keep [../../src/frontend_legacy_template.html](../../src/frontend_legacy_template.html), [../../src/static/app.js](../../src/static/app.js), and [../../src/static/build-manifest.json](../../src/static/build-manifest.json) synchronized via [../../tools/build_frontend.mjs](../../tools/build_frontend.mjs).

Validate with:

- [../../tools/check_frontend_sync.py](../../tools/check_frontend_sync.py)
- [../../tests/test_capability_framework.py](../../tests/test_capability_framework.py)
- [../../tests/test_frontend_delivery.py](../../tests/test_frontend_delivery.py)
- [../../tests/test_security_access.py](../../tests/test_security_access.py)

## Key Decisions

- Use capability-backed persistence and health.
- Start with curated SPL and live validation in v1.
- Keep discovery as the baseline posture source.
- Apply a ground-first, explain-second model: discovery and retrieval context before LLM guidance.
- Keep the page non-authoritative and confidence-labeled.
- Separate discovery evidence, curated validation evidence, and bespoke follow-up evidence in the UI.

## Current Implementation Snapshot
