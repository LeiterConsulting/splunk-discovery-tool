# Repo Validation Automation exec-ctrl

## Control Summary

| Field | Value |
| --- | --- |
| Initiative | Repo Validation Automation |
| Abbrev | `repo-validation-automation` |
| Control system | `exec-ctrl` |
| Overall state | `completed` |
| Current phase | `Phase 5 Close completed` |
| Started | 2026-04-20 |
| Governs | Automated execution of the repo's documented validation gates on GitHub-hosted runners |
| Primary architecture input | `docs/DEVELOPER_REFERENCE.md`, `README.md`, `requirements.txt`, `requirements-dev.txt`, `package.json`, and the existing frontend delivery guardrails |

## Objective

Move the repo's existing manual validation path into a durable GitHub Actions workflow so push and pull-request changes are checked automatically for frontend build drift, Python lint failures, compile regressions, and unit-test failures.

## Requirement Definitions

| ID | Requirement | Definition | Success Signal |
| --- | --- | --- | --- |
| RVA-1 | GitHub-triggered validation | Repo validation must run automatically in GitHub Actions for normal change events and be manually dispatchable when needed. | `.github/workflows/repo-validation.yml` triggers on `push`, `pull_request`, and `workflow_dispatch`. |
| RVA-2 | Gate parity with local hardening path | The workflow must execute the same validation gates already documented for local hardening work. | The workflow installs Python and Node dependencies, then runs `npm run build:frontend`, `python tools/check_frontend_sync.py`, `python -m ruff check src tests`, `python -W error::SyntaxWarning -m compileall -q src tests`, and `python -m unittest discover -v`. |
| RVA-3 | Cross-platform runner coverage | Repo validation must cover both Linux and Windows because the repo has already seen OS-sensitive frontend delivery behavior. | The workflow runs the same gate sequence on `ubuntu-latest` and `windows-latest`. |
| RVA-4 | Durable repo guidance | Developer-facing docs must make the relationship between local validation and CI automation explicit. | `README.md`, `docs/DEVELOPER_REFERENCE.md`, and `docs/EXEC_CTRL.md` reference the new workflow and control pack. |

## Scope In

- GitHub Actions workflow creation under `.github/workflows/`
- Python and Node dependency bootstrap for hosted validation
- automation of the documented frontend build, sync, lint, compile, and unittest gates
- developer and governance documentation updates for the new validation path
- `exec-ctrl` control, audit, and decision records for this slice

## Scope Out

- deployment, packaging, or release publishing automation
- branch protection or repository settings changes that require GitHub admin configuration
- secret-backed integration tests against live Splunk or LLM endpoints
- replacing the existing local validation path with CI-only enforcement
- adding macOS runner coverage in this slice

## Deliverables

1. GitHub Actions workflow for repo validation.
2. Hosted-runner installation path for Python and frontend build dependencies.
3. Automated execution of frontend build, frontend sync, Ruff, strict compile, and unittest gates.
4. Updated README and developer reference guidance.
5. `exec-ctrl` control, audit, and decision logs for this initiative.

## Must-Pass Success Criteria

1. A workflow exists at `.github/workflows/repo-validation.yml` and triggers on `push`, `pull_request`, and `workflow_dispatch`.
2. The workflow uses the documented validation commands rather than introducing a separate CI-only correctness path.
3. The workflow runs on both Ubuntu and Windows runners.
4. Repo documentation records the automated validation path and its relationship to the local hardening workflow.
5. The existing local validation commands still pass after the workflow and docs changes are added.

## Should-Pass Success Criteria

1. The workflow caches Python and Node dependencies to keep routine validation runs practical.
2. The workflow uses stable major-pinned GitHub Actions maintained by GitHub.
3. The first hosted workflow run should be reviewed after the next push so any runner-specific issues are recorded.

## Non-Goals

- replacing the repo's local validation guidance with a single wrapper command
- adding environment-specific deployment jobs
- introducing secrets, service containers, or external system integration tests
- removing the existing installer and unittest-based guardrails added in earlier slices

## Completion Conditions

- all must-pass criteria are satisfied
- the repo contains a documented GitHub Actions validation path
- local validation commands still pass in the workspace after the changes
- any remaining hosted-runner follow-up is explicitly recorded as deferred

## Execution Process

This initiative follows the `exec-ctrl` lifecycle below.

### Phase 0. Activate

Outputs:

- repo-level enforcement gap identified after frontend sync guardrails landed
- dedicated control pack created for validation automation

Status:

- `completed`

### Phase 1. Define

Outputs:

- explicit requirements for GitHub triggers, gate parity, cross-platform coverage, and documentation updates

Status:

- `completed`

### Phase 2. Design

Outputs:

- decision to automate the existing documented gates rather than invent a CI-only test path
- decision to run on Ubuntu and Windows to catch path and line-ending regressions earlier

Status:

- `completed`

### Phase 3. Build

Outputs:

- `.github/workflows/repo-validation.yml`
- repo and developer documentation updates
- `exec-ctrl` control pack artifacts

Status:

- `completed`

### Phase 4. Validate

Outputs:

- local validation commands rerun successfully after the automation slice
- workflow file and command parity reviewed in-repo

Status:

- `completed`

### Phase 5. Close

Outputs:

- control-pack closeout
- residual hosted-runner follow-up explicitly recorded as deferred

Status:

- `completed`

## Workstreams

| Workstream | Purpose | Status | Evidence |
| --- | --- | --- | --- |
| WS1 Workflow automation | Add GitHub Actions automation for the documented repo validation gates | `completed` | `.github/workflows/repo-validation.yml` |
| WS2 Documentation and governance | Update repo references and record the slice under `exec-ctrl` | `completed` | `README.md`, `docs/DEVELOPER_REFERENCE.md`, `docs/EXEC_CTRL.md`, `docs/exec_ctrl/REPO_VALIDATION_AUTOMATION_*` |
| WS3 Local validation | Confirm the repo still passes its existing local validation path after the automation additions | `completed` | `npm run build:frontend`, `python tools/check_frontend_sync.py`, `python -m ruff check src tests`, `python -W error::SyntaxWarning -m compileall -q src tests`, `python -m unittest discover -v` |

## Risks and Dependencies

1. The workflow can be inspected locally, but the first hosted GitHub Actions run still depends on a future push or manual dispatch in the remote repository.
2. `src/web_app.py` imports still initialize `ConfigManager`, so hosted runners may emit default-config load noise unless a later slice isolates frontend rendering from config bootstrap.
3. macOS validation is still uncovered in this slice by design.

## Current Status

What is complete now:

- GitHub Actions automation now exists for the repo's documented validation gates
- the workflow runs the same build, sync, lint, compile, and unittest sequence already used locally
- the validation matrix covers Ubuntu and Windows runners
- README and developer reference docs now call out the workflow as part of the repo validation surface
- the new slice is documented under `exec-ctrl`

What remains open:

- the first hosted workflow run still needs to be observed after a push or manual dispatch outside this local workspace
- branch protection or required-check configuration is intentionally deferred because it requires GitHub repo settings access

## Validation Evidence

- `.github/workflows/repo-validation.yml`
- `npm run build:frontend`
- `python tools/check_frontend_sync.py`
- `python -m ruff check src tests`
- `python -W error::SyntaxWarning -m compileall -q src tests`
- `python -m unittest discover -v`
- source review of `README.md`, `docs/DEVELOPER_REFERENCE.md`, and `docs/EXEC_CTRL.md` confirming the automated validation path is documented