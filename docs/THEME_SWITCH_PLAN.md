# Theme Switch Plan (Light / Dark / System)

> Status: Implemented in current V2 UI baseline. This document now serves as implementation notes + validation checklist.

## Goal
Add a user-facing theme selector in Settings with three options:
- `light`
- `dark`
- `system` (follow OS preference)

The implementation must maintain readable contrast for all UI surfaces, text, controls, badges, tabs, status chips, modals, and chat/discovery panels.

## Current State (Observed)
- UI is heavily Tailwind class-based inside `src/web_app.py` inline React markup.
- Theme preference state is active (`light | dark | system`) and persisted via `dt4sms_theme_preference`.
- Resolved theme tracks OS changes when `system` is selected.
- Major contrast regressions were addressed across top bar, discovery log, summary modal, chat surfaces, and settings modals.

## Target Architecture

### 1) Theme State + Resolution
- Add state in app shell:
  - `themePreference`: `"light" | "dark" | "system"`
  - `resolvedTheme`: `"light" | "dark"`
- Resolution logic:
  - if `themePreference === "system"`, use `window.matchMedia('(prefers-color-scheme: dark)')`.
  - otherwise use explicit preference.
- Persist `themePreference` in `localStorage` (e.g., `dt4sms_theme_preference`).
- Apply mode on root container with class toggle (`dark`) to leverage Tailwind dark variants.

### 2) Settings Tab UX
- Add a **Theme** section in Settings modal:
  - segmented control or radio group for `Light | Dark | System`
  - helper text showing active resolved mode in system mode
- Keep behavior immediate: selecting option updates UI live.
- Keep this local-first; no backend dependency required for MVP.

### 3) Color Token Strategy (No hardcoded random colors)
Normalize UI classes to semantic role groups and provide light/dark pairs:
- App background: `bg-gray-50 dark:bg-gray-900`
- Primary card: `bg-white dark:bg-gray-800`
- Secondary card: `bg-gray-50 dark:bg-gray-850/gray-700 equivalent`
- Primary text: `text-gray-900 dark:text-gray-100`
- Secondary text: `text-gray-600 dark:text-gray-300`
- Muted text: `text-gray-500 dark:text-gray-400`
- Borders: `border-gray-200 dark:border-gray-700`
- Interactive primary button: keep dark enough shade for white text (e.g., `*-600`/`*-700`), avoid `*-400` with white text
- Warning/yellow chips: use dark text (`text-gray-900`) on yellow backgrounds

### 4) Component-by-Component Conversion Map
Convert these sections first (highest visibility):
1. V2 Mission header + command deck + workspace tabs
2. Discovery log panel + progress bar + report/artifact viewer
3. Intelligence tab cards (coverage, capability, ledger, use-cases)
4. Artifacts sidebar + list rows + selection states
5. Chat drawer, chat status pills, suggested query panel
6. Settings modal (all subpanels, buttons, list states)
7. Summary modal and task/verification badges

Each conversion step must replace fixed light-only classes with dual light/dark classes.

## Contrast Requirements
Use WCAG targets:
- Body text: at least 4.5:1
- Large text (>= 18px regular / 14px bold): at least 3:1
- UI components / focus indicators: at least 3:1 against adjacent colors

### Guardrails
- Never use white text on `*-400` backgrounds.
- For yellow/amber chips, default to dark text.
- Disabled state still needs visible contrast against background and neighboring controls.
- Focus ring must be visible in both light and dark themes.

## Verification Plan

### Automated checks
- Add a lightweight Playwright + axe pass for critical screens:
  - `/` with Mission tab
  - Intelligence tab
  - Artifacts tab
  - Settings modal open
  - Chat drawer open
- Validate in `light`, `dark`, and `system` (simulate both OS preferences).

### Manual checks
- Verify all badges/chips, hover states, disabled buttons, and tab states.
- Verify text readability in gradient headers and colored cards.
- Verify no white-on-white / dark-on-dark in any modal or drawer.

## Implementation Phases

### Phase A — Foundation
- Add theme preference state + persistence.
- Add Settings selector UI.
- Apply root dark-mode class wiring.

### Phase B — Core surfaces
- Convert app shell, Mission, Intelligence, Artifacts, and shared cards/buttons.

### Phase C — Modals and advanced views
- Convert Settings modal internals, summary modal, task/verification views, chat drawer.

### Phase D — Validation hardening
- Run automated + manual contrast checks.
- Fix all failing combinations before release.

## Acceptance Criteria
- Settings shows `Light | Dark | System` and updates UI immediately.
- Preference persists across reloads.
- System mode tracks OS preference changes without reload.
- No known contrast failures in audited views.
- No regressions in existing settings behavior (credentials/MCP/LLM workflows remain unchanged).

## Suggested Next Work Item
Run a full contrast audit pass (automated + manual) on all three workspace tabs and both settings modals, then capture any residual edge cases in this file.
