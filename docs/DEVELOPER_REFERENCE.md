# Splunk Discovery Tool Developer Reference

This reference is for developers who extend Splunk Discovery Tool or reuse it in their own projects. It describes release 2.0.0.

## 1) Runtime Topology

- Entry point: src/main.py (finds a free port, prints the release version from src/app_version.py, and starts uvicorn)
- Web app + API + frontend delivery: src/web_app.py (the browser app is built from src/frontend_legacy_template.html into src/static/)
- Discovery orchestration:
  - Engine (MCP calls and step-level findings): src/discovery/engine.py
  - Current primary pipeline: src/discovery/v2_pipeline.py
  - Environment profile (Splunk version, deployment type, installed apps): src/discovery/environment_profile.py
  - Durable discovery and summary jobs: src/runtime_job_worker.py
- LLM abstraction: src/llm/factory.py
  - Model profiles, ranking, and auto-tuning: src/llm/model_profiles.py, src/llm/runtime_tuning.py
  - Endpoint health tracking: src/llm/health_monitor.py
- Chat agent helpers (prompts, tool outcomes, evidence, loop guards): src/chat_agent.py
- Chat settings and chat goals: src/chat_settings.py, src/chat_goals.py
- MCP argument adaptation to advertised tool schemas: src/mcp_tool_args.py
- SPL safety, validation, and scoping helpers: src/spl/spl_utils.py
- Optional capabilities (registry, install manager, Knowledge Base indexer): src/capabilities/
- Knowledge library (reference sources, documentation index, ranking, scorecard): src/knowledge_library/
- Settings troubleshooting: src/troubleshooting.py
- Config and encrypted credentials: src/config_manager.py
- Local auth, OIDC, sessions, roles, and tokens: src/security_manager.py

## 2) Discovery Flow (Current)

The current discovery pipeline runs these stages (the labels match what the UI shows):

1. Survey the environment
   - get_quick_overview()
2. Collect details
   - discover_environment() yields step-level findings
3. Classify data, recommend actions, and suggest use cases
   - classify_data()
   - generate_recommendations()
   - generate_suggested_use_cases()
4. Assemble results and save reports
   - v2_intelligence_blueprint_<ts>.json
   - v2_insights_brief_<ts>.md
   - v2_operator_runbook_<ts>.md
   - v2_developer_handoff_<ts>.md
5. Session summarization (on demand)
   - POST /summarize-session
   - cached output: v2_ai_summary_<ts>.json

### Extension points

- Add a new synthesis stage in DiscoveryV2Pipeline.run()
- Add a new block to _build_v2_payload()
- Add a new artifact writer in _export_v2_bundle()

## 3) Chat with Splunk (Recursive)

Chat strategy combines deterministic and agentic logic:

1. Deterministic intent routes (preferred for common/demo asks)
   - detect_basic_inventory_intent()
   - route handlers in chat_with_splunk_logic()
2. Deterministic domain skills
   - edge processor templates
   - latest offline event lookup
   - latest index event lookup
3. Optional local RAG
   - build_lightweight_rag_context()
4. LLM agentic loop fallback
   - compact prompt (local/small-context models) or full grounded prompt (chat_agent.build_grounded_chat_prompt)
   - plan hints from discovery, including facts for entities named in the request or mission (build_query_plan_brief)
   - one tool call per step; repeats and empty index-by-index sweeps are skipped; unscoped searches get index=*
   - each result goes back through chat_agent.build_tool_feedback with the SPL, time range, and analysis brief

### Add a new deterministic intent

1. Update detect_basic_inventory_intent()
2. Add handler branch in chat_with_splunk_logic()
3. Return structured timeline/tool summaries for UI feedback
4. Add a Suggested Query in UI for demo discoverability

### Chat goals and settings

- `src/chat_settings.py` and `src/chat_goals.py` have no FastAPI dependency. Both store JSON under `output/chat_data/` (relative to the working directory, like the rest of `output/`), and the RAG indexer skips that folder
- `resolve_chat_settings()` merges Auto values (`model_defaults()` from the runtime tuning) with saved Custom values. Custom values are saved with `model_identity()` (provider, endpoint, and model) and cleared when it changes. To add a setting, add it to `SETTING_LIMITS`, `SETTING_SOURCES`, and `model_defaults()`, then to the Chat Settings dialog
- `ChatGoalStore` keeps one file per library owner (`owner_key()`: `local` when sign-in is off, `user_<id>` when it is on) and makes every change as a locked read-modify-write
- A chat request with `goal_id` uses the stored goal text as the mission. `record_chat_goal_turn()` keeps the question and answer and sets `goal_turn_recorded`. The frontend then saves the chat under the goal and calls `POST /api/chat/goals/{goal_id}/progress`, which judges the latest unevaluated turns with `build_progress_messages()` and `parse_progress()`

## 4) MCP Integration

Core contracts:

- Tool discovery: discover_mcp_tools()
- Tool alias resolution: resolve_tool_name()
- Argument normalization: normalize_tool_arguments(), then mcp_tool_args.adapt_tool_arguments() against the tool's input schema
- Execution: execute_mcp_tool_call()
- Outcome classification: chat_agent.classify_tool_result()

### Guidance

- Preserve alias maps for compatibility with tool naming differences
- Keep tool output normalization centralized (extract_results_from_mcp_response)
- Include status_code and error_message handling for robust UX

## 5) LLM Integration

LLM flow:

- get_or_create_llm_client() caches by config hash
- runtime_tuning.resolve_llm_tuning() resolves the model profile and tuned settings (auto_tune); build_chat_runtime_profile() turns them into per-step chat budgets
- Chat pipeline uses the compact reliability-first prompt for local and small-context models
- Tool-call extraction (extract_recoverable_tool_call) accepts tagged JSON, misspelled or missing closing tags, python-like dicts, and a tool-call JSON object that ends the reply (bare, backticked, or fenced)

### Guidance

- Keep deterministic paths for high-value queries
- Reserve free-form agentic behavior for exploratory questions
- Track and expose reasoning timeline to users for transparency

## 6) Settings Surface (Preserved)

Requirement: preserve MCP + LLM settings behavior.

- Existing settings API endpoints should remain stable
- Existing credential load/save/update semantics should remain stable
- Visual refresh is allowed; function contract should not change
- Troubleshooting (`src/troubleshooting.py`) has no FastAPI dependency; `web_app.py` passes in the config manager, the startup state, the account, and the save endpoint's validation errors
  - `POST /api/troubleshoot/mcp` and `POST /api/troubleshoot/llm` take the same fields as the save endpoints plus `check_save` and `check_connection`, never save, and return `status`, `summary`, `summary_fix`, `stages[].checks[]` (`pass`/`warn`/`fail`/`info`/`skip`), and a redacted plain-text `report`
  - `GET /api/troubleshoot/server-status` compares the code fingerprint captured at startup with the install folder and returns `port`, `pid`, and (for admins) `install_dir`; a 404 tells the browser the server predates the page
  - When the server is out of date, the browser probes `server-status` and `/api/auth/status` on the configured port and the next 20 (the fallback range in `src/main.py`) to find other copies; the server-side other-copies check does the same from `127.0.0.1` and adds each listener's PID and folder from `lsof`/`ss`/`ps` (or `netstat` and `Win32_Process` on Windows)
  - The saving stage uses `ConfigManager.probe_save`, which writes, reads back, and deletes a temporary copy next to the settings file
  - When a save path gains a new failure mode, add a check with a plain-language title and fix, plus a case in `tests/test_troubleshooting.py`

## 7) Frontend Feedback Principle

Every button should communicate purpose:

- Use title and icon hints
- Show immediate status/disabled state for long-running actions
- Return timeline + follow-on suggestions for investigation flows

## 8) Workspace Endpoint Map (Current)

- `POST /start-discovery` → Start a discovery run (progress streams over `/ws`)
- `GET /api/discovery/status` and `GET /api/discovery/sessions` → Discovery run state and saved runs
- `POST /chat` and `POST /chat/stream` → Chat answers (`goal_id` ties a request to a chat goal)
- `GET` and `POST /api/chat/settings`, `POST /api/chat/settings/reset` → Chat settings with Auto, Custom, and effective values
- `GET` and `POST /api/chat/goals`; `GET`, `PATCH`, and `DELETE /api/chat/goals/{goal_id}`; `POST /api/chat/goals/{goal_id}/plan` and `/progress`; `POST`, `PATCH`, and `DELETE` on `/items`; `GET`, `PUT`, `PATCH`, and `DELETE` on `/chats/{chat_id}` → Chat goals, tracked questions, and saved chats
- `POST /api/llm/list-models`, `POST /api/llm/test-connection`, `POST /api/llm/assess-max-tokens`, `GET /api/llm/health` → AI model listing, ranking, tuning, and health
- `GET /api/discovery/dashboard` → Overview and Findings data
- `GET /api/discovery/compare` → Session delta metrics
- `GET /api/discovery/runbook` → Persona runbook payload
- `GET /api/v2/intelligence` → Latest blueprint payload
- `GET /api/v2/artifacts` → Artifact catalog
- `GET /api/capabilities` → Capability registry with persisted state
- `GET /api/capabilities/health` → Capability health snapshot
- `GET /api/capabilities/rag/assets` → Managed RAG knowledge-asset catalog
- `GET /api/capabilities/rag/assets/{asset_id}` → Managed knowledge-asset detail with stored sections and chunk-browser output
- `POST /api/capabilities/rag/assets/import/text` → Import pasted text as a managed knowledge asset
- `POST /api/capabilities/rag/assets/import/file` → Import a supported text-based file as a managed knowledge asset
- `POST /api/capabilities/rag/assets/{asset_id}/delete` → Delete a managed knowledge asset
- `POST /api/capabilities/rag/context/build` → Build an operator-facing context preview from indexed managed knowledge assets, including traceable chunk references for matched assets, plus matching downloaded documentation in `details.library_matches` (documentation alone when the Knowledge Base is not ready)
- `POST /api/capabilities/{name}/install` → Install or prepare a capability
- `POST /api/capabilities/{name}/enable` → Enable an installed capability
- `POST /api/capabilities/{name}/disable` → Disable a capability
- `POST /api/capabilities/{name}/uninstall` → Turn a capability off and mark it not installed (Python packages, settings, and indexed knowledge stay)
- `POST /api/capabilities/{name}/test` → Run a capability health check
- `POST /api/capabilities/{name}/reindex` → Rebuild indexed retrieval content for capabilities that support it
- `POST /api/capabilities/{name}/config` → Persist capability-specific config
- `POST /api/capabilities/deeplinks/build` → Build a Splunk Web search deeplink through the optional deeplink capability
- `GET /api/knowledge-library/status` → Environment profile, loaded library sources, refresh job, coverage scorecard, gaps, and the matched catalog for the latest discovery
- `POST /api/knowledge-library/settings` → Turn online library sources on or off (admin)
- `POST /api/knowledge-library/refresh` → Download the library sources again in the background, or only those named in an optional `{"sources": [...]}` body (admin; 400 when no named source is valid, 409 while online sources are off)
- `POST /api/knowledge-library/pack/import` → Load sources and documentation text from a library pack zip (admin; 400 for an unusable pack, 409 during a refresh or another import)
- `GET /api/knowledge-library/pack/export` → Download the loaded sources and documentation text as a library pack zip (404 when none are loaded)
- `POST /api/knowledge-library/search` → Rank downloaded Splunk documentation passages for a question, as chat does (400 for an empty question)
- `GET /reports` → Report/session list

### Capability notes

- `rag_chromadb` persists an `index_summary` alongside the local Chroma storage and surfaces that summary through `GET /api/capabilities`
- `rag_chromadb` also reports `index_freshness` (`ArtifactSourceIndexer.get_index_freshness`): `not_indexed`, `nothing_to_index`, `current`, or `outdated` with reason `index_format` or `changed_files` and a count per source type. It compares source-file modification times with `last_indexed_at`. Files the app rewrites as bookkeeping (`FRESHNESS_EXEMPT_FILENAMES`, `FRESHNESS_EXEMPT_DIRS`), chat memory, and imports do not count. The UI shows a Reindex needed notice from it; nothing reindexes automatically
- `rag_chromadb` now also supports managed knowledge assets stored under a capability-controlled asset directory, with catalog/list/delete behavior exposed through dedicated RAG endpoints
- managed knowledge assets now persist deterministic focus terms, key points, and usage guidance so preview results can explain why an asset matched and how it should be used
- managed knowledge assets refresh stored derived sections on load, and preview/search requests auto-reindex before retrieval if managed-asset timestamps are newer than the last Chroma index build
- `GET /api/capabilities/rag/assets/{asset_id}` returns a single managed asset plus stored-section detail and a chunk-browser payload generated from the same sectioning logic used by the indexer
- `/api/capabilities/rag/context/build` returns raw matched chunks plus an operator brief, recommended uses, basic coverage-gap signals, and stable matched-chunk identifiers that map back to asset-detail chunk-browser sections
- managed knowledge assets currently support pasted text plus `.md`, `.txt`, `.json`, `.log`, `.csv`, `.pdf`, and `.docx` uploads; richer document ingestion is intentionally deferred beyond staged PDF and DOCX extraction
- Chroma indexing uses a deterministic local hash-based embedding function so optional retrieval works without downloading an external embedding model
- `splunk_deeplink_tools` derives a Splunk Web base URL from `config.mcp.url` by default, supports a `web_base_url` override in capability config, and currently ships search deeplinks first

### Knowledge library notes

- `src/knowledge_library/` has no FastAPI dependency: `sources.py` fetches, sanitizes, stores, and packs the sources; `profile.py` reads the blueprint's `environment_profile`; `catalog.py` matches sourcetypes, apps, and documentation; `docs.py` downloads, indexes, and ranks documentation text; `ranking.py` holds the shared ranking helpers; `scorecard.py` scores coverage and lists gaps; `service.py` runs one background refresh at a time and builds the status payload
- Sources live under `output/knowledge_library/` as one JSON file per source, and the RAG indexer skips that folder
- Online fetching is off by default (`config.library.allow_online_sources`). The HTTP client rejects any host outside `ALLOWED_HOSTS` and any non-HTTPS URL, including redirects
- Pack imports rebuild each source with `sanitize_source_payload`, which reuses the fetchers' normalizers, so a pack cannot store fields or links that a download would not produce
- When a scorecard dimension gains a new input, return `None` with a status (`needs_sources`, `needs_discovery`, `not_applicable`, `unavailable`) when the input is missing rather than a score of 0, and add a case in `tests/test_knowledge_library.py`
- `docs.py` plans which help.splunk.com manuals to download from the environment profile (`build_doc_plan`), downloads them (`sync_docs`), and stores sections in `output/knowledge_library/docs/library_docs.sqlite3` (`DocIndex`). The index uses FTS5 when SQLite has it and a LIKE scan plus in-memory BM25 otherwise; it rebuilds the FTS table when chunks were written without it
- Keep documentation downloads polite: `DOC_FETCH_CONCURRENCY`, `DOC_REQUEST_INTERVAL`, and `DOC_REFUSAL_LIMIT` bound the request rate, and `LibraryRefusedError` (HTTP 403 or 429) stops the run. help.splunk.com answers 403 to non-browser requests whose Accept header names `text/html`, so page requests send the HTTP client's default Accept header. Do not send a browser User-Agent
- `ranking.py` holds the shared BM25, reciprocal rank fusion, `coverage_weight`, and `EnvironmentTerms`. The documentation ranker (`docs.rank_doc_results`) and the Knowledge Base indexer (`ArtifactSourceIndexer._hybrid_scores`) both use it, so scores stay comparable in the preview
- Chat adds documentation through `get_optional_rag_context`, which runs only when the chat setting `enable_rag_context` is on
- Documentation has its own index, so it never needs a Knowledge Base reindex. `plan_coverage` lists each planned manual through `manual_status` (`missing`, `partial`, `changed`, `downloaded`), and `KnowledgeLibraryService.resolve_refresh_sources` validates the sources a refresh request names

## 9) Quality Gates

- `tests/test_ui_copy.py` fails when the template contains the old product name, "(s)" plurals, doubled words, listed jargon (such as "deterministic"), or dates not formatted with `formatMissionDateTime()`; the contrast browser check applies the same rules to the text each view shows
- `tests/test_version_consistency.py` fails when `src/app_version.py`, the installers, the README badge, and the latest CHANGELOG release name different versions

- lightweight repo linting now lives in `ruff.toml` with developer install support in `requirements-dev.txt`
- current lint baseline is intentionally narrow and correctness-focused: unused imports, undefined names, invalid local scope references, and syntax-level failures
- the public frontend now ships from checked-in local static assets under `src/static/`; rebuild them with `npm run build:frontend` whenever the source template in `src/frontend_legacy_template.html` changes
- `src/static/build-manifest.json` now records the expected source and artifact hashes for the shipped frontend bundle so drift can be detected without rebuilding during Python validation
- `.github/workflows/repo-validation.yml` now mirrors the documented local validation gates on GitHub-hosted Ubuntu and Windows runners for `push`, `pull_request`, and manual dispatch
- recommended validation commands for hardening work, from an activated `.venv` or equivalent, are:
   - `npm run build:frontend`
   - `python tools/check_frontend_sync.py`
   - `npm run test:browser`
   - `npm run test:settings-profiles-browser`
   - `npm run test:settings-troubleshoot-browser`
   - `npm run test:ui-contrast-browser`
   - `npm run test:auth-browser`
   - `npm run test:account-functions`
   - `python -m ruff check src tests`
   - `python -W error::SyntaxWarning -m compileall -q src tests`
   - `python -m unittest discover -v`
- because the frontend source is maintained in `src/frontend_legacy_template.html` and then transpiled into shipped static assets, CSS selectors and JavaScript regex literals must keep build-safe escaping or strict compile validation will fail
- `tools/render_frontend_template.py` renders the legacy inline template, and `tools/build_frontend.mjs` transpiles its JSX, builds `src/static/app.css` with Tailwind's JIT engine from `tailwind.config.cjs`, and vendors pinned local assets so runtime delivery no longer depends on CDN-hosted React, Tailwind, Font Awesome, or in-browser Babel
- every Tailwind color reads its RGB channels from a CSS variable (`--c-<color>-<shade>`) defined per theme (`:root` for Light, `[data-theme='dark']`, `[data-theme='neo']`) at the top of the template's `<style>` block; change colors there rather than adding hex values in markup, then run `npm run test:ui-contrast-browser` to confirm every theme still meets WCAG AA contrast
- `tools/check_frontend_sync.py` and `tests/test_frontend_delivery.py` now enforce that the shipped static bundle still matches the legacy inline frontend source before release

## 10) Build-Your-Own Checklist

- Replace discovery recommendation logic with domain controls
- Add custom deterministic intents for your data model
- Create role-specific runbooks from the intelligence blueprint
- Add org-specific KPI cards over capability_graph and finding_ledger
- Keep settings contract stable for operator familiarity

## 11) Optional Capabilities

For the optional capability model (the Knowledge Base, exports, charts, Splunk search links, and capability tabs), see:

- `docs/OPTIONAL_CAPABILITIES_ARCHITECTURE.md`

A capability can add its own workspace tab by setting `workspace` on its `CapabilityDefinition` to a `CapabilityWorkspace(id, label, description)`. `GET /api/capabilities` returns it as `workspace` (or `null`) on each capability, and the UI shows the tab after the core tabs while the capability is installed and enabled. The tab label comes from `label`; the frontend maps `id` to the view it opens in `MODULE_WORKSPACE_OPENERS`.

## 12) Releases and Versioning

The release version lives in `src/app_version.py` (`APP_VERSION`). The startup banner, the FastAPI app, and the inbound MCP server's `serverInfo` report it. The `version` field in the settings file records the version that created the file and is not the running version.

To cut a release:

1. Set `APP_VERSION`, `VERSION` in `install.sh`, `$VERSION` in `install.ps1`, and the README version badge to the new version. A new installer version makes existing installs update their Python packages on the next start
2. Move the changes into a `## [X.Y.Z] - <date>` section at the top of `CHANGELOG.md` (under `## [Unreleased]`) and add its link at the bottom
3. Run the quality gates above; `tests/test_version_consistency.py` checks that the numbers match
4. Tag the release commit `vX.Y.Z` and publish a GitHub release from the tag with the CHANGELOG section as its notes
