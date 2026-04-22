# Chat Context Integrity exec-ctrl

## Control Summary

| Field | Value |
| --- | --- |
| Initiative | Chat Context Integrity |
| Abbrev | `chat-context-integrity` |
| Control system | `exec-ctrl` |
| Overall state | `completed` |
| Current phase | `Phase 5 Close completed` |
| Started | 2026-04-20 |
| Governs | Summary-to-chat context isolation, normalized chat history, focused report routing, and report-path optional RAG usage |
| Primary architecture input | `src/web_app.py` chat pipeline, report-backed routing, persisted chat state, and inline React summary/chat UI |

## Objective

Prevent stale chat context from contaminating new investigations, especially when an operator launches a risk investigation from the summary modal, while preserving contextual follow-on actions and allowing report-backed turns to use optional RAG evidence when enabled.

## Requirement Definitions

| ID | Requirement | Definition | Success Signal |
| --- | --- | --- | --- |
| CCI-1 | Route-consistent conversation history | Deterministic, report-backed, and direct-answer chat routes must return normalized follow-up conversation history instead of leaving stale server history authoritative. | After any non-agentic route, the frontend replaces `serverConversationHistory` with a compact user/assistant history for the current thread. |
| CCI-2 | Fresh summary investigations | Summary-surface investigate actions must launch as isolated contextual turns rather than inheriting prior `serverConversationHistory` or `chat_session_id` memory. | Clicking `Investigate`, `Investigate in Chat`, `Build Validation Query`, or summary `Ask AI` starts a fresh chat session and immediately sends the intended prompt. |
| CCI-3 | Focused report routing | Structured risk-investigation prompts from the summary modal must stay anchored to the clicked risk instead of being misclassified by generic strategic-intent keywords. | A clicked risk returns a focused risk answer and risk-specific follow-on actions rather than a generic use-case or environment summary. |
| CCI-4 | Report-path RAG leverage | Report-backed chat answers must be able to incorporate optional RAG evidence when the capability is enabled. | Strategic report responses can return `capability_usage` and an indexed-context addendum sourced from optional RAG chunks. |

## Scope In

- server-side chat response finalization and history normalization
- summary-modal chat launch behavior in the inline React frontend
- strategic report-intent detection and focused risk handling
- report-backed optional RAG evidence surfacing
- targeted regression coverage and live browser validation of the summary risk flow

## Scope Out

- full chat-agent prompt redesign
- new persistence model for chat transcripts beyond the current session primitives
- broad rewrite of the monolithic `src/web_app.py` frontend/backend bundle
- new RAG indexing capabilities beyond reusing the existing optional capability framework

## Deliverables

1. Compact follow-up conversation-history helpers used across non-agentic chat routes.
2. Summary chat launcher that starts a fresh chat session and immediately sends the chosen investigation prompt.
3. Structured risk-request parsing and focused report-backed response generation.
4. Focus-aware report follow-on actions that reference the clicked risk when applicable.
5. Report-path optional RAG evidence support and normalized `capability_usage` on report-backed turns.
6. Regression coverage and live browser validation for the reopened risk-investigation bug.
7. `exec-ctrl` control, audit, and decision records for this initiative.

## Must-Pass Success Criteria

1. A summary Risk Register `Investigate` action does not reuse stale prior chat history or session memory.
2. Deterministic and report-backed chat routes return conversation history that can safely be reused for the next turn.
3. Structured risk prompts remain in the risk lane and produce a focused answer tied to the clicked risk.
4. Report-backed responses can surface optional RAG evidence when enabled.
5. Automated regressions and live browser validation exist for the repaired path.

## Should-Pass Success Criteria

1. Reused follow-on actions remain contextual after the history-normalization change.
2. Other summary-launched chat actions reuse the same fresh-context launcher instead of bespoke input-prefill logic.
3. Existing agentic chat flows continue to work without losing their richer server-managed prompt state.

## Non-Goals

- replacing the existing chat memory system with a new store
- removing agentic conversation-history returns from the deep tool-calling loop
- redesigning summary cards or the broader generated-report UI
- enabling optional RAG by default for all sessions regardless of operator settings

## Completion Conditions

- all must-pass criteria are satisfied
- targeted unit tests pass
- live browser validation confirms the risk-register investigate path starts a clean thread and returns a focused answer
- audit and decision logs capture the implementation and validation record

## Execution Process

This initiative follows the `exec-ctrl` lifecycle below.

### Phase 0. Activate

Outputs:

- reopened chat reliability issue isolated as a dedicated initiative
- stale-history and summary-launch defect path identified

Status:

- `completed`

### Phase 1. Define

Outputs:

- explicit requirements for context isolation, route consistency, focused report routing, and report-path RAG usage
- bounded scope for frontend launch behavior plus backend response normalization

Status:

- `completed`

### Phase 2. Design

Outputs:

- decision to normalize non-agentic conversation history instead of preserving stale server prompt state
- decision to start summary investigations as fresh chat sessions rather than only clearing one state channel
- decision to parse structured risk prompts so clicked risks survive generic keyword-based report routing

Status:

- `completed`

### Phase 3. Build

Outputs:

- history-normalization helpers added
- summary launcher updated to start fresh chat sessions and auto-send prompts
- focused report response and follow-on routing implemented
- report-backed optional RAG evidence surfaced

Audit gate:

- new context-integrity behavior is implemented in `src/web_app.py`

Status:

- `completed`

### Phase 4. Validate

Outputs:

- targeted regression evidence
- live browser reproduction of the Risk Register `Investigate` path after restart

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
| WS1 Route consistency | Normalize follow-up conversation history across report-backed, deterministic, and direct-answer routes | `completed` | `src/web_app.py`, `tests/test_chat_and_llm_helpers.py` |
| WS2 Summary launch isolation | Start summary chat actions as fresh sessions and auto-send the selected investigation prompt | `completed` | `src/web_app.py`, live browser validation |
| WS3 Focused report routing | Keep structured risk investigations anchored to the clicked risk and align follow-on actions to that focus | `completed` | `src/web_app.py`, `tests/test_chat_and_llm_helpers.py` |
| WS4 Validation and governance | Preserve regression coverage and record the slice under `exec-ctrl` | `completed` | `tests/test_chat_and_llm_helpers.py`, `docs/exec_ctrl/CHAT_CONTEXT_INTEGRITY_AUDIT_LOG.md`, `docs/exec_ctrl/CHAT_CONTEXT_INTEGRITY_DECISION_LOG.md` |

## Baseline Evidence

- `docs/EXEC_CTRL.md`
- `src/web_app.py` chat pipeline, summary modal actions, and inline React chat state
- `tests/test_chat_and_llm_helpers.py`

## Risks and Dependencies

1. `src/web_app.py` remains monolithic, so context fixes still require backend and frontend edits in the same file and must be revalidated together.
2. Agentic chat flows still rely on full server-managed conversation history; the normalization change only applies to non-agentic routes by design.
3. Optional RAG evidence on report-backed answers depends on the capability being enabled and returning chunks for the prompt.
4. Summary-launch isolation intentionally starts a fresh chat session, so operators lose the previous visible thread when they choose a new summary-driven investigation.

## Current Status

What is complete now:

- report-backed, deterministic, and direct-answer routes now return compact user/assistant conversation history for safe follow-up reuse
- summary Risk Register, unknown-entity, validation-query, and summary `Ask AI` actions now launch fresh chat sessions and send immediately
- structured summary risk prompts now yield focused risk investigations instead of generic use-case summaries
- report-backed answers can surface optional RAG evidence through the existing capability-usage path when enabled
- targeted regressions cover focused risk routing, report-path RAG evidence, and normalized conversation history
- live browser validation confirmed the Risk Register `Investigate` flow opens a clean chat thread and returns an answer focused on the clicked platform-health risk

What remains open before initiative completion:

- no must-pass items remain open
- no should-pass items are currently deferred for this slice

## Validation Evidence

- `c:/Temp/splunk-discovery-tool/.venv/Scripts/python.exe -m unittest tests.test_chat_and_llm_helpers -v`
- live browser validation after `./install.ps1 -Restart` confirming a summary Risk Register `Investigate` action opens a fresh chat thread and renders `Focused risk investigation: Splunk Platform Health and Capacity Monitoring`
- live browser validation confirming the resulting follow-on actions stayed anchored to the clicked platform-health risk and did not reuse the prior chat thread