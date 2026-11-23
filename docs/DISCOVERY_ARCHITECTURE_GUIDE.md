# Splunk Discovery Tool: Discovery Architecture Guide

This document describes how discovery, reports, the workspace, and chat fit together in release 3.0.0.

## Design Goals

- An insight-first workspace instead of a single long report.
- Modular intelligence artifacts instead of monolithic reporting.
- A stable MCP and AI model settings contract, so the UI can change without breaking saved settings or API clients.
- Developer-first documentation so teams can reuse the app.

## Discovery + Reporting Model

`DiscoveryV2Pipeline` (`src/discovery/v2_pipeline.py`) orchestrates a run over `DiscoveryEngine` (`src/discovery/engine.py`), which makes the MCP calls and yields step-level findings. Runs execute in a detached worker (`src/runtime_job_worker.py`) whose progress is saved to disk, so a restart does not lose them. Progress reaches the browser over the `/ws` WebSocket.

The pipeline writes timestamped artifacts to `output/scopes/<scope>/` for an active MCP connection, or to `output/` for the standalone scope. The filenames remain compatible with earlier reports.

- `v2_intelligence_blueprint_<timestamp>.json`: canonical machine-readable discovery payload
- `v2_insights_brief_<timestamp>.md`: concise operator or executive summary
- `v2_operator_runbook_<timestamp>.md`: prioritized action queue
- `v2_developer_handoff_<timestamp>.md`: integration notes for app builders
- `v2_ai_summary_<timestamp>.json`: the AI summary, written on demand by `POST /summarize-session`

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
- `environment_profile`: Splunk version, matching documentation version, deployment type (Splunk Cloud Platform or Splunk Enterprise, with the reason), and installed apps with built-in apps marked (`src/discovery/environment_profile.py`)

## Workspace Model

The web app reads discovery data through dedicated endpoints:

- `GET /api/v2/intelligence` (latest blueprint)
- `GET /api/v2/artifacts` (artifact catalog)
- `GET /api/discovery/dashboard` (key numbers and trends)
- `GET /api/discovery/compare` (run comparison)
- `GET /api/discovery/runbook` (runbook for each audience)
- `GET /api/knowledge-library/status` (environment profile, library sources, coverage scorecard, and gaps)

The UI has five core tabs, followed by any tabs that enabled capabilities add:

1. **Overview**: discovery status, key numbers, top next steps, what changed (from environment memory), runbook, and report packages
2. **Findings**: next steps for each audience, the environment profile, key evidence, and patterns
3. **Discovery**: discovery runs, stage progress, saved reports, and summaries
4. **Knowledge Base**: library health and the coverage scorecard, downloaded Splunk documentation, managed knowledge assets, the SPL Library, and context previews
5. **Capabilities**: install, turn on or off, test, configure, and remove optional capabilities

A capability adds a tab by declaring a `CapabilityWorkspace` (the M-26-14 Readiness Advisor adds the M-26-14 tab).

## Chat with Splunk (Developer Notes)

Chat combines:

1. Fixed intent routes for common inventory questions (`detect_basic_inventory_intent`, `chat_with_splunk_logic`)
2. An agent loop grounded in the live MCP tool catalog (`src/chat_agent.py`): one tool call per step, repeated and empty index-by-index searches skipped, `index=*` added to searches that name no index, and every result fed back with the SPL, time range, and an analysis brief
3. Plan hints from discovery, including facts for the indexes, sourcetypes, sources, and hosts that the question or goal names
4. Optional context: Knowledge Base passages and downloaded Splunk documentation, ranked together, only when Search the Knowledge Base is on
5. Chat goals (`src/chat_goals.py`): a request with `goal_id` uses the goal as the mission; after each answer the browser asks `POST /api/chat/goals/{goal_id}/progress` which tracked questions the answer settled
6. Chat settings (`src/chat_settings.py`): Auto values from the AI model's tuning, with Custom values saved per model. Each answer keeps its own copy for the whole answer
7. A scratchpad per chat with the indexes, hosts, and recent turns it mentioned, saved privately for each user under `output/chat_data/memory/<owner>/` and never indexed
8. Known environment: the busiest indexes, sourcetypes, and hosts in the asker's scope, what is quiet now, and changes in the last 7 days, from environment memory (below)

Discovery resolves the active MCP connection from the user's assignment when one applies, or the selected shared connection in standalone operation. The endpoint and profile together identify the workspace. Chat, reports, environment memory, Knowledge Base passages from Discovery reports, and goal planning read its scope through `request_discovery_dir`. The browser reloads workspace data when the active connection switches. Requests that still carry the previous workspace are refused and the browser refreshes the connection information.

When adding new intents:

1. Add a detector in `detect_basic_inventory_intent`
2. Add a handler branch in `chat_with_splunk_logic`
3. Return structured tool call summaries for the step list and follow-on actions

## Environment Memory (Developer Notes)

`src/environment_memory/` keeps one record per discovery scope at `<scope folder>/environment_memory/record.json` (`output/` for the global scope, `output/scopes/<scope>/` otherwise). It lists the indexes, sourcetypes, hosts, and sources the app has seen, with first and last seen times, last event time, 24-hour counts, and status, plus a change log.

1. **Observations**: `observation_from_blueprint` reads each discovery run, `observation_from_rows` reads the rows of chat searches (`learn_environment_from_chat`, after each answer), and `observation_from_check` reads the scheduled check's two `tstats` searches (`CHECK_QUERIES`, last 24 hours)
2. **Merging**: `merge_observation` updates the entities and returns the changes: `new`, `went_quiet`, `back`, `volume_shift` (tstats counts only, more than 50 percent, at least 100 events), and `gone`. A kind reports changes only after an observation covered it in full (its baseline). Chat observations are never complete, so chat can add New items but never mark anything quiet
3. **Discovery sync**: `load_environment_record` merges discovery runs the record has not seen (a new record starts from the last 2). `register_discovery_session` calls it after each run, and Overview and chat call it before they read the record
4. **Chat**: `known_environment_block` adds a KNOWN ENVIRONMENT section to the chat instructions. Under incognito mode, `environment_prompt_context` registers the record's index and host names with the masker first, and drops the section if it cannot
5. **Scheduled check**: off by default. `_environment_check_loop` runs every minute and checks each scope with a record or discovery runs whose last check is older than the interval, when the scope has an MCP URL and token

Every update holds a file lock and writes the file atomically. The change log keeps the newest 500 changes.
## MCP + AI Model Settings (Preserved)

Settings behavior is intentionally stable:

- Existing API endpoints remain unchanged.
- Existing credential and config persistence behavior remains unchanged; config files written by other versions still load, and unknown keys are ignored.
- UI visuals can evolve, but the implementation contract should remain stable.

## Extending Discovery

1. Add a synthesis stage in `DiscoveryV2Pipeline.run()`.
2. Add a block to `_build_v2_payload()` and, when it should be exported, a writer in `_export_v2_bundle()`.
3. Read new blocks in the UI from `v2_intelligence_blueprint_<timestamp>.json` through the endpoints above.
4. Update this guide and `docs/DEVELOPER_REFERENCE.md` for each new intent or artifact.

## Repurposing Checklist for Developers

- Replace recommendation logic with domain-specific rules.
- Swap runbook rendering templates with your own workflows.
- Add custom chat intents linked to your environment semantics.
- Build dashboards directly from `capability_graph` and `finding_ledger`.
