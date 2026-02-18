# DT4SMS V2 Rewrite Guide

This document describes the new architecture direction for the demo-first v2 project.

## Objectives

- Replace legacy UI shape with an insight-first workspace.
- Replace monolithic reporting with modular intelligence artifacts.
- Preserve the MCP/LLM settings behavior and API contract.
- Provide developer-first documentation so teams can repurpose the app.

## V2 Discovery + Reporting Model

V2 writes timestamped artifacts to `output/` using stable naming:

- `v2_intelligence_blueprint_<timestamp>.json` — canonical machine-readable discovery payload
- `v2_insights_brief_<timestamp>.md` — concise operator/executive summary
- `v2_operator_runbook_<timestamp>.md` — prioritized action queue
- `v2_developer_handoff_<timestamp>.md` — integration notes for app builders

Core schema blocks:

- `overview`
- `capability_graph`
- `finding_ledger`
- `classification_map`
- `coverage_gaps`
- `risk_register`
- `trend_signals`
- `vulnerability_hypotheses`
- `recursive_investigations`
- `recommendations`
- `suggested_use_cases`

## V2 Workspace Model

The web app consumes V2 data through dedicated endpoints:

- `GET /api/v2/intelligence` (latest blueprint)
- `GET /api/v2/artifacts` (artifact catalog)
- `GET /api/discovery/dashboard` (KPI + trends)
- `GET /api/discovery/compare` (session comparison)
- `GET /api/discovery/runbook` (persona runbook payload)

The UI is organized into three tabs:

1. **Mission** — discovery execution, live log, and generated session views
2. **Intelligence** — blueprint KPIs, coverage gaps, capability graph, finding ledger
3. **Artifacts** — V2 artifact browsing and export/access

## Chat with Splunk (Developer Notes)

The chat feature now combines:

1. Deterministic intent routes for high-value simple asks
2. Optional local-RAG snippet retrieval from output artifacts
3. Compact reliable prompt + tool-call fallback parsing

When adding new intents:

1. Add detector in `detect_basic_inventory_intent`
2. Add handler branch in `chat_with_splunk_logic`
3. Return structured tool call summaries for timeline + follow-ons

## MCP + LLM Settings (Preserved)

Settings behavior is intentionally preserved:

- Existing API endpoints remain unchanged.
- Existing credential/config persistence behavior remains unchanged.
- UI visuals can evolve, but implementation contract should remain stable.

## Migration Strategy

1. Route discovery execution through `DiscoveryV2Pipeline`.
2. Keep legacy paths only as temporary fallback.
3. Move UI progressively to consume `v2_intelligence_blueprint_<timestamp>.json` blocks.
4. Keep documentation updated for each new intent/artifact.

## Repurposing Checklist for Developers

- Replace recommendation logic with domain-specific rules.
- Swap runbook rendering templates with your own workflows.
- Add custom chat intents linked to your environment semantics.
- Build dashboards directly from `capability_graph` and `finding_ledger`.
