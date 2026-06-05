# M-26-14 Development Ledger

## Purpose

This ledger tracks the planned M-26-14 implementation phases, their current development status, and a dated log of what has been completed so far.

## Phase Status Ledger

| Phase | Scope | Status | Current State | Latest Logged Milestone |
| --- | --- | --- | --- | --- |
| 1. Policy Rubric | Translate the M-26-14 memo into concrete scoring elements and evidence categories | In progress | Discovery-backed heuristic rubric exists for inventory visibility, collection coverage, collection operations, data retention, and log management | 2026-05-26: rubric signals scaffolded in the advisor profile engine |
| 2. Capability Registration | Register `m26_14_advisor` in the capability framework | Completed | Capability is registered, normalized, health-checked, and surfaced through `/api/capabilities` | 2026-05-26: capability registry, install manager, and health integration landed |
| 3. Curated Validation Packs | Ship day-one curated SPL packs for major control areas | Completed | Eight curated validation packs are defined with evidence, limitations, role requirements, and execution mode | 2026-05-26: curated pack catalog added in `src/discovery/m26_14_advisor.py` |
| 4. Live Validation Path | Expose curated validation execution through backend APIs | In progress | Backend live-validation API is implemented, returns summarized results, reuses bounded cached responses for repeated identical validation requests, and now enriches validation responses with discovery grounding, retrieval context, reusable SPL candidates, and optional LLM guidance | 2026-05-26: grounded advisory payload landed for `/api/discovery/m26-14/validate` |
| 5. Discovery-Backed Profile Engine | Build posture from persisted V2 blueprint artifacts | Completed | Latest and selected session profiles can be derived from V2 blueprints and compared across sessions; compare-history coverage now verifies `latest` versus `previous` selection behavior | 2026-05-26: compare-history regression coverage landed for the advisor compare endpoint |
| 6. Workspace UI | Add a hidden-until-enabled workspace tab and operator workflow | In progress | Hidden tab is wired from capability state with posture, compare, validation, discovery-grounding, environment-context, reusable-SPL, and grounded-advisory panels; browser regression exercises the shipped static bundle for the M-26-14 workspace | 2026-05-26: grounded advisory UI landed in the shipped static bundle |
| 7. Role Boundaries | Align viewer, analyst, and admin behavior with existing auth and MCP rules | In progress | Backend role gates exist for live validation and capability mutation routes; targeted backend tests cover profile access, compare history, viewer denial, positive admin/analyst validation, and the browser auth matrix now verifies viewer versus analyst behavior on the M-26-14 workspace | 2026-05-26: analyst-versus-viewer browser regression landed in the auth suite |
| 8. Delivery Integrity | Keep generated frontend assets, tests, and build metadata in sync | Completed | Static assets were regenerated, the build manifest was refreshed, focused frontend sync validation passed, and the static bundle now has browser-level regression coverage | 2026-05-26: Playwright regression passed against `/static/index.html` after Chromium provisioning |

Status legend:

- Completed: implementation slice is present and connected in the app
- In progress: implementation has started, but adjacent wiring, UX depth, or validation is still outstanding
- Planned: phase has not started yet
- Blocked: work is waiting on environment, dependency, or design resolution

## Development Log

### 2026-05-26 1. Planning And Direction Lock

Stage: Architecture and product-direction decision

- Chosen delivery model: internal optional capability pack, not a top-level security config toggle
- Chosen surface: hidden-until-enabled workspace tab
- Chosen operating model: discovery-derived posture plus curated live validation from v1
- Chosen trust model: explicitly non-authoritative and evidence-labeled
- Archived the fuller v1 plan in [FULL_V1_IMPLEMENTATION_PLAN.md](./FULL_V1_IMPLEMENTATION_PLAN.md)

### 2026-05-26 2. Capability Foundation

Stage: Backend capability and health scaffolding

- Added `m26_14_advisor` to the capability registry
- Added M-26-14 config normalization in capability install management
- Added capability health checks and runtime summary support
- Established the capability framework as the source of truth for enablement and visibility

### 2026-05-26 3. Profile Engine And Curated Catalog

Stage: Discovery-backed advisor logic

- Added `src/discovery/m26_14_advisor.py`
- Implemented heuristic profile generation from persisted V2 blueprints
- Added curated validation packs for retention, audit, network visibility, privileged change monitoring, infrastructure visibility, detection posture, IOC/anomaly signals, and freshness sanity
- Added summarized validation-result interpretation for immediate UI consumption

### 2026-05-26 4. Backend API And Access Control

Stage: Advisor API exposure

- Added selected-session M-26-14 profile route
- Added M-26-14 compare route
- Added curated validation-pack catalog route
- Added live curated validation execution route
- Added analyst-or-admin gating for live validation
- Added admin gating for capability mutation routes

### 2026-05-26 5. Initial Workspace UI

Stage: First visible operator surface

- Added hidden M-26-14 workspace tab driven by capability state from `/api/capabilities`
- Added initial advisor workspace cards for readiness, confidence, maturity floor, and observed footprint
- Added initial priority-objective and maturity-element rendering
- Added initial compare controls using the shared discovery session selectors
- Added curated validation pack picker, SPL preview, and validation result display

### 2026-05-26 6. Validation And Environment Notes

Stage: Immediate post-edit validation

- Backend diagnostics reported no errors in touched files
- `python3 -m py_compile src/web_app.py src/discovery/m26_14_advisor.py` passed
- FastAPI request-model ordering was verified after the backend endpoint patch
- Frontend template diagnostics reported no errors
- Frontend rebuild initially failed because the local Node environment did not have `esbuild` installed
- `npm ci` was started to restore the frontend build toolchain from the committed lockfile

### 2026-05-26 7. Targeted Advisor Test Coverage

Stage: Focused regression coverage for the new slice

- Added targeted backend tests for M-26-14 profile/catalog access and viewer denial of live validation
- Added a targeted frontend template test for hidden-tab and validation wiring
- Added a Python-version-tolerant temporary-directory helper in `tests/test_security_access.py` so the touched tests run on the local interpreter
- Verified the three new M-26-14 tests pass via `.venv/bin/python -m unittest`
- Confirmed the application still serves the edited legacy template directly at runtime while static asset regeneration remains blocked by the local Node environment

### 2026-05-26 8. Node Toolchain Recovery And Positive Validation Path

Stage: Delivery restoration and role-path validation

- Identified the local npm registry override as `https://repo.splunkdev.net/artifactory/api/npm/npm/`
- Confirmed repeated `npm ci` failures were driven by registry `ECONNRESET` resets during tarball fetches
- Restored the frontend build environment by reinstalling the minimal build dependency set from `https://registry.npmjs.org/`
- Regenerated `src/static/app.js`, `src/static/index.html`, and `src/static/build-manifest.json` with `tools/build_frontend.mjs`
- Verified frontend delivery integrity with `tools/check_frontend_sync.py`
- Added a positive-path live validation test proving both admin and analyst roles can execute `/api/discovery/m26-14/validate` when runtime MCP access is available
- Verified the focused M-26-14 validation and frontend sync test slice passes under `.venv/bin/python -m unittest`

### 2026-05-26 9. Compare-History And Static-Bundle Browser Coverage

Stage: Broader regression coverage for the shipped M-26-14 surface

- Added compare-history API coverage for `/api/discovery/m26-14/compare`, including `latest` versus `previous` session selection and recommended-pack deduplication
- Added stable M-26-14 browser test selectors to the workspace compare and validation controls
- Regenerated the shipped static bundle after the selector additions
- Added a Playwright regression phase that opens `/static/index.html`, verifies the hidden M-26-14 tab appears when capability data enables it, flips compare direction, and renders a validation result
- Installed the local Playwright Chromium runtime and verified the full visualization browser regression suite passes with the new M-26-14 phase included

### 2026-05-26 10. Cached Validation Reuse And Auth-Role Browser Coverage

Stage: Repeated validation workflow hardening and real-role browser coverage

- Added a bounded in-memory cache for `/api/discovery/m26-14/validate`, keyed by validation pack, resolved session selection, time range, discovery scope, and runtime MCP identity
- Added response metadata for repeated validation reuse, including `from_cache`, `cache_key`, and `cached_at`
- Added focused backend coverage proving repeated identical validation requests reuse the cached result while changed time ranges force a fresh MCP execution
- Extended the auth browser suite with a local-password M-26-14 role scenario that seeds an enabled advisor capability plus viewer and analyst users
- Verified the browser suite exercises the real auth shell while checking that viewers see a disabled validation path and analysts can execute the workspace validation flow
- Hardened `tools/test_auth_browser.mjs` to resolve interpreter paths absolutely so temp-directory browser scenarios do not lose the selected virtualenv
