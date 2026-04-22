# Execution Control (exec-ctrl)

`exec-ctrl` is the engineering control system for non-trivial DT4SMS initiatives.

Its purpose is to ensure a piece of work is:

- defined before building starts
- documented as decisions and scope evolve
- audited against explicit evidence and success criteria
- progressed through visible phase gates
- completed only when exit criteria are satisfied

This is an internal development process. It is not a product feature.

## When exec-ctrl is required

Use `exec-ctrl` for work that introduces one or more of the following:

- new subsystems or cross-cutting architecture
- new dependencies or install-time behavior
- persistent configuration changes
- operator-facing workflows spanning backend and UI
- optional capability packs or plugin-like systems
- security, auditability, or release-readiness concerns

The optional RAG and enhancement-pack initiative qualifies.

## exec-ctrl outcomes

Every initiative under `exec-ctrl` must provide a durable answer to five questions:

1. What are we building and why?
2. How do we know it is done?
3. What evidence proves it works?
4. What changed while building it?
5. What remains open after completion?

## Required control artifacts

Each `exec-ctrl` initiative must maintain these artifacts under `docs/exec_ctrl/`:

1. Control record
2. Audit log
3. Decision log

Recommended naming:

- `<initiative>_EXEC_CTRL.md`
- `<initiative>_AUDIT_LOG.md`
- `<initiative>_DECISION_LOG.md`

The control record is the source of truth. The audit and decision logs are supporting evidence.

## Lifecycle

`exec-ctrl` uses six phases.

### 0. Activate

Purpose:

- create the control record
- establish scope, baseline, and working assumptions

Minimum outputs:

- initiative name and objective
- scope in and scope out
- baseline evidence
- initial risks and dependencies

### 1. Define

Purpose:

- convert the idea into explicit deliverables and measurable success criteria

Minimum outputs:

- problem statement
- deliverables
- must-pass success criteria
- should-pass quality criteria
- completion conditions

### 2. Design

Purpose:

- select the architecture, interfaces, rollout shape, and operational model

Minimum outputs:

- architecture summary
- interface and persistence approach
- UI/API touchpoints
- dependency and installation approach
- rollout sequencing

### 3. Build

Purpose:

- execute the work in controlled workstreams

Minimum outputs:

- phase or workstream plan
- progress status per workstream
- evidence links to implemented changes
- logged scope changes or decisions

### 4. Validate

Purpose:

- prove the implementation meets functional and non-functional criteria

Minimum outputs:

- tests and manual verification evidence
- failure mode review
- documentation updates
- unresolved issues list

### 5. Close

Purpose:

- certify that the initiative is complete, auditable, and ready for handoff or follow-on work

Minimum outputs:

- final audit verdict
- completion summary
- open follow-ups
- explicit statement of what is complete and what is deferred

## Status model

Each initiative and each workstream must use one of these states:

- `not-started`
- `defined`
- `designing`
- `in-progress`
- `blocked`
- `validating`
- `audit-ready`
- `completed`
- `deferred`

## Success criteria model

Every initiative must separate success criteria into these groups:

### Must-pass

These are mandatory. If one is open, the initiative is not complete.

### Should-pass

These are important quality targets. They may be deferred only with an explicit decision-log entry.

### Non-goals

These are intentionally excluded so the work does not drift.

## Audit model

Audits are evidence-based checkpoints. Each audit entry must include:

- date
- checkpoint name
- evidence reviewed
- verdict
- gaps found
- next action

Required audit points:

1. Baseline audit
2. Phase-exit audits for any major phase gate
3. Completion audit

Allowed verdicts:

- `pass`
- `pass-with-gaps`
- `fail`

`pass-with-gaps` requires an explicit next action and owner path, even if the owner is simply `future follow-up`.

## Decision model

All material scope, sequencing, dependency, or architecture changes must be logged.

Each decision entry should capture:

- ID
- date
- decision
- rationale
- consequence

If a decision changes success criteria, scope, or phase order, the control record must be updated in the same change set.

## Progress model

Progress is tracked in the control record using:

- current phase
- overall state
- workstream table
- evidence links
- risks and blockers

Progress is not just a checklist. It must show whether the work is still on the path defined by the success criteria.

## Completion rule

An initiative may be marked `completed` only when all of the following are true:

- all must-pass success criteria are satisfied
- completion audit is `pass` or `pass-with-gaps` with only deferred should-pass items
- required docs are updated
- unresolved items are explicitly recorded as follow-up work

## Repo implementation standard

For DT4SMS, the standard implementation of `exec-ctrl` is:

- `docs/EXEC_CTRL.md` for the process standard
- `docs/exec_ctrl/` for initiative-level control records and logs

Each initiative should link to the architecture or design docs it governs.

## Minimum template for a control record

Each control record should include these sections:

- control summary
- objective
- scope in
- scope out
- deliverables
- success criteria
- non-goals
- workstreams and phase gates
- baseline evidence
- risks and dependencies
- current status
- completion conditions

## Tracked initiatives

Current and recent initiative control records include:

- `docs/exec_ctrl/OPTIONAL_CAPABILITIES_EXEC_CTRL.md`
- `docs/exec_ctrl/CHAT_UX_EXEC_CTRL.md`
- `docs/exec_ctrl/PUBLIC_APP_READINESS_EXEC_CTRL.md`
- `docs/exec_ctrl/REPO_VALIDATION_AUTOMATION_EXEC_CTRL.md`
