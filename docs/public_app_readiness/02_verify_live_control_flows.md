# Plan 02: Verify Live Control Flows

## Objective

Confirm that all visible controls, links, and workflow entry points behave correctly in the running app and do not present false affordances.

This plan is behavior-first. It is meant to catch dead controls, stale states, broken transitions, and misleading UI paths.

## Why This Matters

Public users judge quality by what the interface actually does, not by what the code intends to do.

Controls that appear valid but fail silently create more damage than controls that are clearly unavailable.

## Flow Categories

1. App shell and top navigation
2. Settings and connection details
3. Mission workspace actions
4. Intelligence workspace actions
5. Artifacts browsing and report selection
6. Capabilities workspace controls
7. Chat open, close, clear, settings, suggested queries, and follow-on actions
8. External link and download behaviors

## Test Principles

- prefer non-destructive checks first
- distinguish disabled-by-design from broken
- verify loading, error, empty, and success states
- verify that visible status text matches actual backend state
- treat stale UI data as a defect if it materially misrepresents the current system state

## Work Plan

### Phase A: Build the Flow Matrix

- list every user-visible control by workspace and modal
- record the expected action, backend dependency, and expected result state
- tag controls as safe, caution, or destructive for audit execution

### Phase B: Execute Normal Paths

- open every major workspace and modal from a clean browser state
- validate entry, action, response, and recovery behavior
- confirm that success feedback is specific and understandable

### Phase C: Execute Empty and Disabled Paths

- verify what the UI does when artifacts are absent, features are disabled, or required config is missing
- confirm disabled controls explain why they are unavailable
- check that loading states do not strand the user without context

### Phase D: Verify Linked and External Actions

- validate external links, deeplinks, downloads, and open-in-new-tab actions
- confirm that generated URLs are well-formed and connected to the visible action label
- confirm that copy-to-clipboard and export/download actions provide feedback

### Phase E: State Accuracy Review

- compare displayed UI status to API state where relevant
- flag stale cards, inaccurate counts, or misleading installed/enabled/ready messaging
- verify that modal overlays do not block unrelated controls after close or reload

## Deliverables

- control-flow matrix
- verified working-path list
- dead or misleading control list
- state-accuracy defects list

## Evidence to Capture

- browser snapshots for each major flow
- API payload comparison where UI state is disputed
- exact file references in `src/web_app.py`

## Exit Criteria

- each public-facing control has a verified behavior classification
- dead controls and false affordances are explicitly documented
- major flows have evidence for normal, loading, and disabled states
- external-link and export actions are classified as working, blocked, or misleading

## Risks and Dependencies

- some flows depend on live Splunk connectivity or persisted capability state
- browser pages with preserved modal state can create audit noise if not reset between checks
- backend readiness and UI readiness may drift, which requires API comparison before final classification