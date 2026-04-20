# Plan 03: Check Contrast and Visuals

## Objective

Evaluate whether the public UI meets practical contrast, readability, focus visibility, and visual-consistency standards across its main surfaces.

This plan covers both accessibility and general product polish.

## Why This Matters

Even when the app is functionally correct, low-contrast text, weak visual hierarchy, and inconsistent styling make the interface feel unfinished and harder to use.

For a public app, appearance is part of trust.

## Standards Baseline

- WCAG 2.2 AA contrast targets for text and meaningful controls
- visible focus indicators for keyboard use
- readable body and helper text at common zoom levels
- consistent action-color meaning across the app
- restrained use of decorative gradients and status colors

## Priority Areas

1. Header and workspace navigation
2. Status cards and KPI tiles
3. Chat message cards, helper text, and disclosure headers
4. Button variants, especially green, amber, and muted controls
5. Modal shells in light and dark themes
6. Sidebar report/session rows and small metadata text
7. Capability tags, badges, and low-emphasis metadata

## Work Plan

### Phase A: Visual Token Inventory

- capture all primary colors used for text, backgrounds, badges, and buttons
- group recurring classes and hard-coded color values
- identify where color meaning is inconsistent across surfaces

### Phase B: Automated Contrast Sampling

- run targeted browser-side contrast checks for buttons, summary rows, helper text, and metadata text
- log values below AA thresholds
- separate body-text failures from non-text decoration

### Phase C: Manual Readability Review

- inspect dense panels and small helper text in both themes
- check whether microcopy remains readable without hover or zoom dependence
- verify that status colors still make sense for color-blind and low-vision users

### Phase D: Focus and Interaction Visibility

- verify that hover-only affordances are not doing too much work
- check focus visibility on major buttons, inputs, tabs, and disclosures
- confirm disabled states look intentionally unavailable rather than broken

### Phase E: Remediation Proposal

- define preferred replacements for low-contrast text and button styles
- identify components that should use shared color tokens instead of hard-coded values
- recommend a simplified visual language for public release quality

## Deliverables

- contrast findings register
- color and component consistency observations
- recommended palette and emphasis adjustments
- remediation priorities for AA compliance and public presentation quality

## Evidence to Capture

- contrast ratio outputs for failing elements
- screenshots or DOM references for weak readability cases
- code references in `src/web_app.py` for repeated problematic classes or values

## Exit Criteria

- contrast failures are documented with ratios and affected surfaces
- low-readability helper text and metadata are identified
- action-color inconsistencies are documented
- a practical visual remediation path exists for both themes

## Risks and Dependencies

- the UI currently mixes Tailwind utility classes with hard-coded color values, which increases drift risk
- some low-contrast items may appear acceptable in one theme and fail in another
- purely automated contrast checks need manual confirmation for inherited or transparent backgrounds