# Frontend Sync Guardrails exec-ctrl

## Control Summary

| Field | Value |
| --- | --- |
| Initiative | Frontend Sync Guardrails |
| Abbrev | `frontend-sync-guardrails` |
| Control system | `exec-ctrl` |
| Overall state | `completed` |
| Current phase | `Phase 5 Close completed` |
| Started | 2026-04-20 |
| Governs | Detection of drift between the legacy inline frontend source and the shipped static frontend bundle |
| Primary architecture input | `docs/exec_ctrl/FRONTEND_DELIVERY_HARDENING_EXEC_CTRL.md`, `src/web_app.py`, `src/static/`, and the release-path validation commands |

## Objective

Add deterministic guardrails that fail fast when the legacy inline frontend source in `src/web_app.py` diverges from the shipped static frontend bundle under `src/static/`.

## Requirement Definitions

| ID | Requirement | Definition | Success Signal |
| --- | --- | --- | --- |
| FSG-1 | Recorded build state | The shipped frontend bundle must record the source and artifact fingerprints it was built from. | `src/static/build-manifest.json` exists and captures source plus artifact hashes. |
| FSG-2 | Python-readable sync check | Drift detection must run from the existing Python-first validation path without requiring a rebuild during the check itself. | `tools/check_frontend_sync.py` returns success when the bundle is current and fails when it is stale. |
| FSG-3 | Release-path enforcement | The existing unittest quality gate must fail if the shipped bundle is stale. | `python -m unittest discover -v` includes frontend sync tests and fails on drift. |
| FSG-4 | Operator-visible warning | Normal installer-driven service start should warn when stale frontend assets are detected. | `install.ps1` and `install.sh` print a non-blocking warning before service start when the sync check fails. |

## Scope In

- build-manifest generation during frontend rebuilds
- Python helper logic for source and artifact fingerprint comparison
- dedicated sync checker CLI
- unittest coverage for frontend bundle drift
- installer warnings for stale frontend assets
- developer and repo documentation updates

## Scope Out

- automatic frontend rebuilds inside the installers
- CI workflow creation in this slice
- removing the legacy inline frontend source or fallback path
- changing UI behavior or styling unrelated to sync enforcement

## Deliverables

1. Frontend build manifest generation.
2. Python sync helper module and CLI.
3. Unittest coverage for bundle drift.
4. Installer warnings on stale assets.
5. Updated docs and control-pack records.

## Must-Pass Success Criteria

1. `npm run build:frontend` writes a manifest describing the built source and artifacts.
2. `tools/check_frontend_sync.py` passes when the shipped bundle is current.
3. `python -m unittest discover -v` fails if the bundle drifts.
4. Installer-driven service start still works after the warning hook is added.

## Should-Pass Success Criteria

1. The sync manifest is stable across Windows and Unix line-ending behavior.
2. The new guardrail does not add a Node runtime dependency to service startup.
3. The repo guidance makes the rebuild-and-check workflow explicit for future frontend edits.

## Non-Goals

- replacing the current frontend build pipeline
- removing the legacy inline template from `src/web_app.py`
- adding CI-only enforcement while leaving local validation unchanged

## Completion Conditions

- all must-pass criteria are satisfied
- the sync checker and unittest gate are validated
- installer start warnings work without blocking startup
- docs record the new release-path guardrail

## Execution Process

This initiative follows the `exec-ctrl` lifecycle below.

### Phase 0. Activate

Outputs:

- follow-up gap identified after frontend delivery hardening completed
- dedicated control pack created for drift detection guardrails

Status:

- `completed`

### Phase 1. Define

Outputs:

- explicit requirements for manifest generation, drift detection, unittest enforcement, and installer warning behavior

Status:

- `completed`

### Phase 2. Design

Outputs:

- decision to use a build manifest instead of re-running the frontend build inside the Python test suite
- decision to enforce drift through the existing Python unittest gate and installer warnings instead of waiting for future CI work

Status:

- `completed`

### Phase 3. Build

Outputs:

- manifest generation, sync helper, CLI, tests, and installer warnings

Status:

- `completed`

### Phase 4. Validate

Outputs:

- successful frontend rebuild
- successful sync-check execution
- successful unittest, lint, compile, and installer-start validation

Status:

- `completed`

### Phase 5. Close

Outputs:

- durable repo documentation and control-pack handoff

Status:

- `completed`

## Workstreams

| Workstream | Purpose | Status | Evidence |
| --- | --- | --- | --- |
| WS1 Manifest generation | Record the built frontend source and artifact fingerprints | `completed` | `tools/build_frontend.mjs`, `src/static/build-manifest.json` |
| WS2 Drift detection | Provide a Python helper and CLI that can validate the shipped bundle without rebuilding it | `completed` | `src/frontend_delivery.py`, `tools/check_frontend_sync.py` |
| WS3 Release-path enforcement | Fail the unittest gate and warn during installer start when frontend assets are stale | `completed` | `tests/test_frontend_delivery.py`, `install.ps1`, `install.sh` |

## Risks and Dependencies

1. The legacy inline frontend remains the canonical source for the build, so frontend edits still require an explicit rebuild.
2. Installer warnings depend on the Python environment being healthy enough to import the app code.
3. CI is still absent, so local and release-path discipline remains important even with the new guardrail.

## Current Status

What is complete now:

- the frontend build writes `src/static/build-manifest.json`
- a Python sync checker can validate the shipped bundle against `src/web_app.py`
- the unittest suite now includes frontend drift detection
- both installers warn before service start if the static bundle is stale

What remains open:

- no must-pass items remain open for this slice
- future CI automation could add another enforcement layer, but it is not required for completion here

## Validation Evidence

- `npm run build:frontend`
- `c:/Temp/splunk-discovery-tool/.venv/Scripts/python.exe tools/check_frontend_sync.py`
- `c:/Temp/splunk-discovery-tool/.venv/Scripts/python.exe -m ruff check src tests`
- `c:/Temp/splunk-discovery-tool/.venv/Scripts/python.exe -W error::SyntaxWarning -m compileall -q src tests`
- `c:/Temp/splunk-discovery-tool/.venv/Scripts/python.exe -m unittest discover -v`
- forced manifest-mismatch validation followed by `./install.ps1 -Restart`, which emitted the stale-frontend warning before successful service start
- post-warning restore through `npm run build:frontend` plus a clean `c:/Temp/splunk-discovery-tool/.venv/Scripts/python.exe tools/check_frontend_sync.py --quiet`