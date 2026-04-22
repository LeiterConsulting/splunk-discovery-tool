# Public App Readiness Plans

This folder captures the proposed work plans for the public-facing UX, accessibility, clarity, and reliability audit effort.

The goal is to move from ad hoc chat findings to a repeatable review package that can be executed, tracked, and turned into implementation work.

## Scope

- accessibility semantics and control labeling
- live control-flow verification across public UI surfaces
- contrast and visual quality review against practical UI standards
- final findings consolidation for release readiness

## Plan Files

1. `01_audit_semantics_and_labels.md`
2. `02_verify_live_control_flows.md`
3. `03_check_contrast_and_visuals.md`
4. `04_consolidate_findings_report.md`

## Recommended Execution Order

1. Audit semantics and labels first so the UI control inventory is accurate.
2. Verify live control flows second so dead or misleading actions are identified with real behavior evidence.
3. Check contrast and visuals after the control map is stable.
4. Consolidate findings last into a release-readiness report with severity, evidence, and remediation guidance.

## Standards Baseline

- WCAG 2.2 AA for core text contrast, focus visibility, keyboard access, and semantic structure
- plain operator-facing language rather than internal engineering terminology
- no dead links, fake affordances, or controls that look actionable but are not
- consistent status language for installed, enabled, ready, degraded, and unavailable states
- predictable behavior in both normal and error states

## Expected Outputs

- a validated control inventory for the public app surface
- a prioritized issue register with release blockers clearly separated from polish items
- a remediation backlog that can be turned into implementation slices
- a final public-readiness findings report suitable for repo documentation or release review

## Execution Assets

- `FINDINGS_REGISTER.md` for the working issue ledger
- `REMEDIATION_ISSUE_TEMPLATE.md` for implementation-ready follow-up tickets
- `PUBLIC_APP_READINESS_FINDINGS_REPORT.md` for the current consolidated report

## Current Execution Status

- the audited semantics, control-integrity, contrast, and public-language issues have been remediated and revalidated against `http://localhost:8003`
- contrast review explicitly covered buttons, cards, badges, disclosures, expandable surfaces, and modal/tab shells during the live audit
- the current release gate recommendation is ready for controlled preview and public-facing use without an open medium-severity delivery-model finding in the runtime shell
- the repo now also has lightweight drift-detection gates through `ruff.toml`, strict compile validation for the embedded frontend string, and a local static-frontend build step through `npm run build:frontend`
- frontend delivery hardening is now implemented through checked-in local static assets served from `src/static/`, with the legacy inline frontend retained only as a build source and fallback