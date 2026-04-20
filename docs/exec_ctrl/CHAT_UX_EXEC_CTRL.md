# Chat UX Refinement exec-ctrl

## Control Summary

| Field | Value |
| --- | --- |
| Initiative | Chat UX Refinement |
| Abbrev | `chat-ux` |
| Control system | `exec-ctrl` |
| Overall state | `completed` |
| Current phase | `Phase 5 Close completed` |
| Started | 2026-04-20 |
| Governs | Chat follow-on relevance, capability-evidence default visibility, and chat-open scroll behavior |
| Primary architecture input | `src/web_app.py` chat pipeline, result summarization, and inline React UI |

## Objective

Improve operator usability and trust in the chat surface by making Suggested Next Actions specific to the immediate conversation and output, reducing evidence-panel noise, and reliably landing the operator at the newest chat context whenever the modal opens.

## Requirement Definitions

| ID | Requirement | Definition | Success Signal |
| --- | --- | --- | --- |
| CUX-1 | Contextual Suggested Next Actions | Suggested next actions must prefer the latest tool output, result-analysis metadata, and remembered conversation anchors over generic one-size-fits-all prompts. | Different result shapes produce different follow-on actions, and drill-down prompts reference the actual index, host, dimension, or pivot exposed by the latest output. |
| CUX-2 | Collapsed Capability Evidence by Default | Capability Evidence should stay available, but it must not dominate the chat card unless the operator chooses to expand it. | Assistant messages render Capability Evidence closed by default while preserving the existing expandable evidence details. |
| CUX-3 | Auto-Scroll to Current Context on Chat Open | Opening chat should place the operator at the newest message instead of requiring manual scrolling through persisted history. | Reopening a populated chat lands at the bottom of the chat history and keeps the input focused for the next action. |

## Scope In

- server-side follow-on action generation in chat response helpers
- use of existing result-analysis metadata such as `query_shape`, `top_dimensions`, `findings`, and `next_pivots`
- chat-memory carry-forward needed to preserve immediate result context across turns
- inline React chat UX changes for evidence visibility and modal-open scroll behavior
- targeted regression tests and live browser verification for the affected chat behaviors

## Scope Out

- full chat UI redesign or layout overhaul
- ML-based ranking or personalization of suggested actions
- persistent per-user expand/collapse preferences for evidence panels
- virtualization or pagination of chat history
- broad prompt-routing changes outside the affected follow-on-action logic

## Deliverables

1. Result-aware follow-on action generation that uses the latest tool summary before generic focus fallbacks.
2. Expanded last-result memory context carrying forward query-shape and pivot signals.
3. Capability Evidence rendered collapsed by default in assistant chat cards.
4. Chat modal open behavior that scrolls to the newest message and focuses the input.
5. Regression coverage for the new follow-on-action routing.
6. `exec-ctrl` control, audit, and decision records for this initiative.

## Must-Pass Success Criteria

1. Suggested next actions change meaningfully based on immediate output shape rather than repeating the same generic actions across materially different responses.
2. Time-series results yield follow-on actions aimed at explaining spikes, changes, or window comparisons rather than just replaying the same trend query.
3. Aggregation and event-sample results yield follow-on actions grounded in top dimensions, hosts, or key entities when that information exists.
4. Capability Evidence is collapsed by default in assistant messages without removing access to the underlying evidence.
5. Opening a chat session with existing history lands at or near the bottom of the scroll container and focuses the chat input.
6. Targeted automated validation and live browser verification exist for the affected behaviors.

## Should-Pass Success Criteria

1. Follow-on fallbacks still remain useful when no result summary is available.
2. Last-result memory persists enough structured context to influence the next turn without storing excessive raw result payloads.
3. Existing capability-usage rendering and clickable follow-on actions do not regress.

## Non-Goals

- replace deterministic follow-on logic with LLM-only suggestion generation
- store raw result tables in chat memory for follow-on generation
- introduce a new frontend framework or split the inline React bundle in this slice
- redesign evidence cards beyond the default collapsed state

## Completion Conditions

- all must-pass criteria are satisfied
- targeted unit tests pass
- live browser validation confirms collapsed Capability Evidence and open-to-bottom chat behavior
- audit and decision logs capture the implementation and validation record

## Execution Process

This initiative follows the `exec-ctrl` lifecycle below.

### Phase 0. Activate

Outputs:

- control pack created
- baseline chat UX gaps identified

Status:

- `completed`

### Phase 1. Define

Outputs:

- requirement definitions for contextual actions, collapsed evidence, and open-to-bottom scroll
- explicit success criteria and non-goals

Status:

- `completed`

### Phase 2. Design

Outputs:

- decision to reuse existing result-analysis metadata rather than invent a parallel scoring system
- decision to centralize scroll-on-open in the chat modal effect

Status:

- `completed`

### Phase 3. Build

Outputs:

- server-side follow-on logic updated
- chat memory context enriched
- inline React evidence and scroll behavior updated

Audit gate:

- new chat behavior is implemented in `src/web_app.py`

Status:

- `completed`

### Phase 4. Validate

Outputs:

- targeted test evidence
- live browser DOM verification for evidence collapse and scroll state

Audit gate:

- all must-pass criteria have direct evidence

Status:

- `completed`

### Phase 5. Close

Outputs:

- completion audit
- decision log
- control pack handoff

Audit gate:

- no must-pass gaps remain open

Status:

- `completed`

## Workstreams

| Workstream | Purpose | Status | Evidence |
| --- | --- | --- | --- |
| WS1 Follow-on relevance | Make Suggested Next Actions depend on latest result shape and pivots | `completed` | `src/web_app.py`, `tests/test_chat_and_llm_helpers.py` |
| WS2 Chat modal UX | Collapse evidence by default and scroll to bottom on open | `completed` | `src/web_app.py`, live browser DOM validation |
| WS3 Validation and governance | Preserve regression coverage and record the initiative under `exec-ctrl` | `completed` | `tests/test_chat_and_llm_helpers.py`, `docs/exec_ctrl/CHAT_UX_AUDIT_LOG.md`, `docs/exec_ctrl/CHAT_UX_DECISION_LOG.md` |

## Baseline Evidence

- `docs/EXEC_CTRL.md`
- `src/web_app.py` existing chat follow-on helpers, result summarization, and inline React modal
- `tests/test_chat_and_llm_helpers.py`

## Risks and Dependencies

1. `src/web_app.py` remains a monolithic backend-plus-inline-React file, so even small chat UX changes require careful read-through and targeted validation to avoid collateral regressions.
2. Follow-on quality depends on the result-summary metadata already produced by the latest tool call; weak or missing summaries will still force the system onto broader focus-based fallbacks.
3. Live validation for chat UX changes depends on restarting the running DT4SMS service so the inline UI and backend behavior are not tested against stale code.
4. Chat-open scroll behavior depends on persisted chat history and the current modal scroll container structure; if either changes later, the reopen behavior should be revalidated.

## Current Status

What is complete now:

- contextual Suggested Next Actions are routed from immediate result shape, pivots, and remembered anchors before generic fallbacks
- last-result chat memory now carries forward query-shape, findings, top-dimension, and pivot context needed for better follow-ons
- Capability Evidence is collapsed by default in assistant chat cards
- reopening chat now scrolls to the newest message and restores input focus
- targeted regressions were added for time-series and aggregation-specific follow-on behavior
- live browser validation confirmed collapsed evidence and reopen-to-bottom behavior after service restart

What remains open before initiative completion:

- no must-pass items remain open
- no should-pass items are currently deferred for this slice

## Validation Evidence

- `c:/Temp/splunk-discovery-tool/.venv/Scripts/python.exe -m unittest tests.test_chat_and_llm_helpers -v`
- live browser validation after `./install.ps1 -Restart` confirming `Capability Evidence` details render with `open=false`
- live browser validation after `./install.ps1 -Restart` confirming chat scroll container reopens within 6px of the bottom of persisted history