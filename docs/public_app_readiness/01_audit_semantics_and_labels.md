# Plan 01: Audit Semantics and Labels

## Objective

Establish whether every public-facing interactive element exposes the right semantic role, accessible name, state, and intent.

This plan focuses on the structure of the interface rather than its appearance.

## Why This Matters

For a downloadable public app, semantic correctness is not optional:

- keyboard users need stable navigation and focus behavior
- assistive technologies need reliable roles and labels
- all users benefit when the control label matches the actual action
- ambiguous naming erodes trust even when the feature technically works

## Priority Surfaces

1. Top bar workspace navigation
2. Connection status and connection details popover
3. Chat modal header controls and message actions
4. Suggested next actions and suggested query controls
5. Report/session accordion rows and report viewer actions
6. Capabilities workspace controls, status badges, and configuration areas
7. Settings and chat-settings modal controls

## Review Questions

1. Is each interactive element implemented with the correct HTML element for its job?
2. Does each control have a clear visible label or an explicit accessible label?
3. Are expanded, collapsed, selected, busy, disabled, and error states exposed consistently?
4. Do tabs, dialogs, accordions, and disclosure widgets expose the right semantics?
5. Are labels public-facing and operator-friendly rather than internal or developer-centric?

## Work Plan

### Phase A: Build the Control Inventory

- enumerate all buttons, links, clickable containers, disclosures, tabs, inputs, and modal entry points
- group them by surface and by interaction type
- record the current visible label, tooltip text, and implied action

### Phase B: Semantic Validation

- replace non-semantic clickable containers with buttons or links where appropriate
- identify missing `aria-label`, `aria-expanded`, `aria-selected`, `aria-controls`, and `role` usage
- verify that dialogs and tab groups expose recognizable structures

### Phase C: Language and Label Review

- flag labels that are vague, internal, overly technical, or misleading
- separate user-facing labels from developer-only metadata
- normalize control naming so similar actions use similar terms

### Phase D: Keyboard and Focus Review

- verify that each control is reachable with keyboard navigation
- verify that overlays trap focus appropriately and return focus on close
- confirm that expandable items are operable without a mouse

### Phase E: Remediation Proposal

- document exact changes needed per control class
- define a naming convention for user-facing actions, statuses, and helper text
- identify reusable patterns that should be applied across the app shell

## Deliverables

- interactive element inventory
- semantic defects list
- ambiguous or misleading labels list
- recommended naming and accessibility pattern guide for this app

## Evidence to Capture

- DOM snapshots of affected elements
- code references in `src/web_app.py`
- before/after examples for the highest-risk controls

## Exit Criteria

- all public-facing controls are inventoried
- all non-semantic high-value controls are identified
- missing accessible labels and state exposure are documented
- ambiguous labels have proposed replacements
- a remediation set exists for tabs, dialogs, disclosures, and icon-only controls

## Risks and Dependencies

- the app is rendered from a large inline frontend in `src/web_app.py`, so findings may cluster in one file
- modal state persistence and local UI state can obscure whether a behavior is a defect or an intentionally preserved session state
- some controls may expose valid behavior through poor semantics, which requires careful classification