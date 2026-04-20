# Optional Capabilities Initiative exec-ctrl

## Control Summary

| Field | Value |
| --- | --- |
| Initiative | Optional Capabilities |
| Abbrev | `opt-cap` |
| Control system | `exec-ctrl` |
| Overall state | `completed` |
| Current phase | `Phase 6 Validate and Close completed` |
| Started | 2026-04-19 |
| Governs | Optional RAG and optional enhancement-pack implementation |
| Primary architecture input | `docs/OPTIONAL_CAPABILITIES_ARCHITECTURE.md` |

## Objective

Deliver an optional capability framework that allows DT4SMS to install, configure, operate, and visibly benefit from:

- a stronger RAG system, including a future Chroma-backed provider
- optional enhancement packs for visuals, export generation, and Splunk deep links

This work must preserve the base product behavior when optional capabilities are not installed.

## Scope In

- capability-pack registry and runtime model
- persistent capability configuration
- install, enable, disable, test, and health flows
- dedicated capability management surface in the UI
- migration of current lightweight RAG into the capability model
- optional Chroma-backed RAG provider
- optional enhancement packs for:
  - Splunk deep links
  - visuals from Splunk data
  - deterministic export bundles and staged downloadable outputs
- chat and discovery integration points for optional capability usage
- evidence visibility showing when optional capability output improved an answer or artifact

## Scope Out

- mandatory RAG on every deployment
- replacing core discovery evidence with RAG-only synthesis
- arbitrary package installation from the UI
- multi-MCP federation beyond the initial native-pack model unless explicitly reopened by decision log
- full productization of every enhancement pack in the first delivery slice

## Deliverables

1. Capability framework in backend code
2. Persistent capability configuration in encrypted config
3. Settings-driven install and control flow for optional packs
4. Dedicated `Capabilities` workspace tab or equivalent operational surface
5. `rag_local` capability replacing the current ad hoc lightweight RAG path
6. Visible evidence in chat when RAG or enhancement packs are used
7. `rag_chromadb` optional provider
8. Initial enhancement packs:
   - `splunk_deeplink_tools`
   - `visualization_tools`
   - `export_tools`
9. Validation and rollout documentation

## Must-Pass Success Criteria

1. All optional capabilities are off by default and the base app remains functional without them.
2. Capability installation and enablement state persists across restart.
3. The user can install, enable, disable, test, and inspect optional capabilities from the app’s control surface.
4. A dedicated operational surface exists for capability management beyond the Settings modal alone.
5. The current lightweight RAG path is refactored behind a capability/provider abstraction.
6. If RAG contributes to a chat answer or discovery output, the user can see what was retrieved and why it mattered.
7. Optional RAG can influence prompt context, follow-on actions, and post-result interpretation without replacing primary Splunk evidence.
8. A Chroma-backed provider can be installed optionally and managed without reinstalling the full app.
9. A Splunk deeplink capability pack is implemented and usable from relevant answers or actions.
10. Visualization and export packs are installable as optional capabilities, even if delivered in staged maturity.
11. Documentation and audit evidence exist for architecture, implementation, and validation.

## Should-Pass Success Criteria

1. Capability health is visible and normalized into states such as ready, degraded, and restart-required.
2. Capability usage is included in chat/discovery response metadata for future UX enhancements.
3. Chroma-backed indexing supports typed source categories instead of plain undifferentiated text chunks.
4. Export generation starts from deterministic artifact structures rather than free-form LLM formatting.
5. Visualization output can be reused for both on-screen preview and downloadable artifacts.

## Non-Goals

- making ChromaDB the required RAG backend
- adding arbitrary third-party MCP servers as part of the initial slice
- forcing users through capability setup before the base product works
- binding the architecture directly to a single dependency vendor

## Execution Process

This initiative follows the `exec-ctrl` lifecycle below.

### Phase 0. Activate

Outputs:

- control pack created
- baseline and architecture inputs identified

Status:

- `completed`

### Phase 1. Define

Outputs:

- explicit scope
- success criteria
- deliverables
- non-goals

Status:

- `completed`

### Phase 2. Design

Outputs:

- architecture document
- phase sequencing
- dependency strategy
- UI and persistence strategy

Status:

- `completed`

Primary evidence:

- `docs/OPTIONAL_CAPABILITIES_ARCHITECTURE.md`

### Phase 3. Build Foundation

Outputs:

- capability registry
- persistent config model
- install manager
- health and status model

Audit gate:

- framework works with at least `rag_local`

Status:

- `completed`

### Phase 4. Build RAG

Outputs:

- `rag_local` provider migration
- visible RAG evidence in UX
- `rag_chromadb` provider and indexing controls

Audit gate:

- RAG is optional, visible, and health-checked

Status:

- `completed`

### Phase 5. Build Enhancement Packs

Outputs:

- deeplink pack
- visualization pack
- export pack

Audit gate:

- packs are installable, optional, and integrated into relevant answer flows

Status:

- `completed`

### Phase 6. Validate and Close

Outputs:

- test evidence
- manual validation evidence
- completion audit
- follow-up list

Audit gate:

- all must-pass criteria satisfied

Status:

- `completed`

## Workstreams

| Workstream | Purpose | Status | Evidence |
| --- | --- | --- | --- |
| WS1 Capability framework | Registry, config, install, health | `completed` | `src/capabilities/`, `src/config_manager.py`, `src/web_app.py` capability APIs |
| WS2 RAG abstraction | Move local retrieval behind provider model | `completed` | `src/capabilities/rag/lightweight.py`, `src/web_app.py` capability-backed RAG context and usage metadata |
| WS3 RAG v2 provider | Chroma-backed provider and indexing | `completed` | `src/capabilities/rag/indexer.py`, `src/capabilities/rag/chromadb_provider.py`, `src/capabilities/install_manager.py`, `tests/test_capability_framework.py`, live browser install/enable/reindex/test validation |
| WS4 Control surfaces | Settings install cards and Capabilities workspace | `completed` | `src/web_app.py` Capabilities workspace, reindex control surface, chat settings bridge, live capability evidence validation |
| WS5 Enhancement packs | Deeplink, visualization, export | `completed` | `src/capabilities/tools/deeplink.py`, `src/capabilities/tools/visualization.py`, `src/capabilities/tools/exporter.py`, `src/capabilities/install_manager.py`, `src/capabilities/health.py`, `src/capabilities/registry.py`, `src/web_app.py`, `tests/test_capability_framework.py`, `tests/test_chat_and_llm_helpers.py`, live capability install/enable/build validation plus deterministic chat-card deeplink, visualization preview, and export bundle validation |
| WS6 Validation and docs | Tests, audits, rollout docs | `completed` | `tests/test_chat_and_llm_helpers.py`, `tests/test_capability_framework.py`, targeted suite pass, export bundle download validation, restart persistence validation, audit/docs refresh, completion audit |

## Baseline Evidence

- `docs/OPTIONAL_CAPABILITIES_ARCHITECTURE.md`
- `docs/DEVELOPER_REFERENCE.md`
- `src/web_app.py` current lightweight RAG and settings endpoints
- `src/config_manager.py` current encrypted persistence model

## Risks and Dependencies

1. `src/web_app.py` already carries significant UI and backend weight, so uncontrolled capability UI additions could make maintenance worse.
2. Optional dependency installation requires strong allowlisting and restart handling.
3. Chroma indexing and health behavior will introduce operational state the current app does not yet manage.
4. Export tooling can expand quickly if deterministic artifact templates are not enforced.
5. If capability contribution is not visible, the user will not trust the force-multiplier value.

## Current Status

What is complete now:

- architecture exploration is complete
- `exec-ctrl` is defined
- this initiative is now under control
- capability registry and state models exist under `src/capabilities/`
- encrypted config now persists capability state in `src/config_manager.py`
- FastAPI exposes capability management and health endpoints in `src/web_app.py`
- `rag_local` now runs through the capability framework
- live capability inventory was validated from the running app
- unit coverage exists for capability bootstrap, persistence, and `rag_local` lifecycle
- the app now exposes a dedicated `Capabilities` workspace with install, enable, disable, test, inspect, and save-config controls
- chat responses now expose normalized `capability_usage` metadata and the assistant UI renders retrieved RAG evidence with source snippets
- live browser validation confirmed `rag_local` install, enable, and test flows plus visible capability evidence in chat
- `rag_chromadb` now has a runtime provider, deterministic local embeddings, typed artifact indexing, persistent index summaries, and health-aware reindex support
- FastAPI now exposes `POST /api/capabilities/{name}/reindex` and the Capabilities workspace renders Chroma-specific index status plus reindex controls
- live browser validation confirmed `rag_chromadb` install, restart-required handling, enable, reindex, test, and in-chat capability evidence from the Chroma provider
- targeted validation now passes for both chat helpers and the capability suite, including the real Chroma-backed integration test path when `chromadb` is present
- `splunk_deeplink_tools` now has a native runtime, derives Splunk Web URLs from MCP settings or a capability override, exposes a dedicated deeplink build endpoint, and renders operator-facing build controls in the Capabilities workspace
- targeted validation now passes for the deeplink provider lifecycle and build path, and live browser validation confirmed install, enable, and build-url flows for the deeplink capability
- deterministic chat responses now surface executed SPL consistently, and the assistant UI renders `SPL Query Executed` cards with the `Open in Splunk` action for executed searches
- live browser validation confirmed the chat-side deeplink path after service restart, including the rendered assistant card and the button-driven deeplink URL assignment flow
- `visualization_tools` now has a native preview runtime, registry/install/health integration, Capabilities workspace status rendering, and assistant-side visualization preview cards with normalized capability evidence
- targeted validation now passes for the visualization provider lifecycle and deterministic chat preview contract in the chat helper suite
- live browser validation confirmed `visualization_tools` install, enable, configuration guidance, and in-chat line preview rendering with `Visualization Tools` capability evidence
- `export_tools` now has a native deterministic bundle runtime, registry/install/health integration, capability-config migration for legacy `pdf`/`pptx` settings, a dedicated bundle build/download API, Capabilities workspace status rendering, and mission-workspace bundle controls tied to the active persona runbook
- targeted validation now passes for the export provider lifecycle and capability-manager build path in the capability suite while preserving the existing chat/helper regressions
- live browser validation confirmed `export_tools` install, enable, test, mission-workspace `Build Export Bundle`, capability-card latest-bundle status, and successful download-route delivery of the generated zip bundle
- restart validation confirmed persisted capability state survives service restart, including `export_tools` remaining installed, enabled, ready, and associated with the generated bundle via `GET /api/capabilities`
- the completion audit is now recorded in `docs/exec_ctrl/OPTIONAL_CAPABILITIES_AUDIT_LOG.md`

Deferred follow-ups:

- richer `export_tools` formats beyond the deterministic bundle zip, manifest, and summary outputs
- mirrored capability lifecycle controls in Settings in addition to the Capabilities workspace
- broader capability-evidence propagation into future discovery and artifact surfaces beyond the implemented chat and mission flows

Phase 4 closeout status:

- the Phase 4 audit gate is now satisfied: optional RAG is installable, visible, and health-checked across both providers

What remains open before initiative completion:

- no must-pass items remain open
- only explicit should-pass deferrals recorded in the decision log remain

## Completion Conditions

This initiative may be marked `completed` only when:

- all must-pass criteria are satisfied
- completion audit is recorded in the audit log
- remaining gaps are only should-pass deferrals with explicit decision-log entries
- implementation and operational docs are updated

Completion status:

- all must-pass criteria are satisfied
- completion audit is recorded in the audit log with a `pass-with-gaps` verdict limited to should-pass deferrals
- deferred items are captured in `docs/exec_ctrl/OPTIONAL_CAPABILITIES_DECISION_LOG.md`
- this initiative is complete unless reopened by a new follow-on objective

## Next Build Order

The required build order for this initiative is:

1. capability framework
2. `rag_local` capability migration
3. visible RAG evidence in chat and discovery outputs
4. Capabilities workspace and settings install controls
5. `rag_chromadb`
6. `splunk_deeplink_tools`
7. `visualization_tools` completed
8. `export_tools` completed
9. final validation and closeout
