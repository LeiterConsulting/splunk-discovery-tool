# Frontend Delivery Hardening exec-ctrl

## Control Summary

| Field | Value |
| --- | --- |
| Initiative | Frontend Delivery Hardening |
| Abbrev | `frontend-delivery-hardening` |
| Control system | `exec-ctrl` |
| Overall state | `completed` |
| Current phase | `Phase 5 Close completed` |
| Started | 2026-04-20 |
| Governs | Removal of CDN-hosted runtime frontend assets and in-browser Babel from the DT4SMS public app shell |
| Primary architecture input | `src/web_app.py` inline frontend template, `src/static/` runtime assets, and `docs/public_app_readiness/` follow-up finding `PAR-F009` |

## Objective

Replace the public runtime path that depended on CDN-hosted React, ReactDOM, Tailwind, Font Awesome, and in-browser Babel with a checked-in local static delivery model that keeps runtime behavior stable without adding a Node runtime dependency to app startup.

## Requirement Definitions

| ID | Requirement | Definition | Success Signal |
| --- | --- | --- | --- |
| FDH-1 | Local runtime delivery | The app must serve local static frontend assets by default instead of loading runtime dependencies from CDNs. | `src/static/index.html` references only local `/static/...` assets for the public runtime shell. |
| FDH-2 | No in-browser JSX compilation | The app must stop depending on browser-side Babel for the shipped runtime path. | The served frontend uses a precompiled `src/static/app.js` bundle and no Babel warning appears on live reload. |
| FDH-3 | Rebuildable asset pipeline | The repo must include a repeatable build path that regenerates the local frontend assets from the existing frontend source. | `npm run build:frontend` regenerates `src/static/index.html`, `src/static/app.js`, and the vendored runtime assets. |
| FDH-4 | Safe transition path | The migration must avoid breaking the app if generated assets are temporarily missing in a development checkout. | FastAPI falls back to the legacy inline frontend only when `src/static/index.html` is absent. |

## Scope In

- build-time extraction and JSX transpilation for the existing inline frontend source
- checked-in runtime assets under `src/static/`
- FastAPI runtime delivery changes for `/` and `/static`
- developer-facing build documentation and release-path validation updates
- closeout of public-readiness follow-up `PAR-F009`

## Scope Out

- redesigning the DT4SMS UI or changing operator workflows
- splitting the frontend into a separate SPA project in this slice
- adding Node/NPM as a runtime prerequisite for normal app startup
- removing the legacy inline frontend source entirely if a lower-risk fallback remains useful

## Deliverables

1. `package.json` with pinned frontend build-time dependencies.
2. Build tooling that renders the legacy inline template and transpiles the JSX into local assets.
3. Checked-in runtime frontend assets under `src/static/`.
4. FastAPI runtime delivery changes that prefer local static assets and keep a safe fallback.
5. Updated developer and public-readiness documentation.
6. Control, audit, and decision logs for this hardening initiative.

## Must-Pass Success Criteria

1. The runtime shell no longer loads React, ReactDOM, Tailwind, Font Awesome, or Babel from CDNs.
2. The runtime shell no longer depends on `<script type="text/babel">`.
3. `npm run build:frontend` succeeds and regenerates the checked-in frontend assets.
4. The live app reloads successfully on the new delivery path.
5. Public-readiness documentation closes `PAR-F009` with evidence.

## Should-Pass Success Criteria

1. The migration keeps a low-risk fallback path for development checkouts that do not yet have generated assets.
2. The build path stays pinned to known-compatible versions rather than introducing broad version drift.
3. The validation path is simple enough to keep in normal hardening work.

## Non-Goals

- introducing a full modern frontend workspace with linting, tests, and dev server in this slice
- converting the inline source into many component files during the delivery hardening pass
- changing visual design or user-facing copy unrelated to delivery model hardening

## Completion Conditions

- all must-pass criteria are satisfied
- the app serves local static assets by default
- the build command is documented and validated
- public-readiness follow-up documentation reflects the closed `PAR-F009` finding

## Execution Process

This initiative follows the `exec-ctrl` lifecycle below.

### Phase 0. Activate

Outputs:

- dedicated control pack created for the deferred frontend delivery risk
- baseline delivery-model dependencies identified from `PAR-F009`

Status:

- `completed`

### Phase 1. Define

Outputs:

- explicit requirements for local runtime delivery, precompiled JSX, rebuildability, and safe fallback behavior

Status:

- `completed`

### Phase 2. Design

Outputs:

- decision to keep Node build-time only
- decision to preserve the legacy inline frontend as a build source and fallback for this slice
- decision to serve checked-in static assets from FastAPI rather than introducing a separate frontend host

Status:

- `completed`

### Phase 3. Build

Outputs:

- build tooling, checked-in static assets, and runtime delivery switch

Status:

- `completed`

### Phase 4. Validate

Outputs:

- successful frontend build, live reload evidence, and repo validation checks

Status:

- `completed`

### Phase 5. Close

Outputs:

- control-pack closeout
- public-readiness follow-up closure

Status:

- `completed`

## Workstreams

| Workstream | Purpose | Status | Evidence |
| --- | --- | --- | --- |
| WS1 Build pipeline | Render the legacy inline template and transpile JSX into local assets | `completed` | `package.json`, `tools/render_frontend_template.py`, `tools/build_frontend.mjs` |
| WS2 Runtime delivery | Serve `src/static/` assets by default while preserving a safe fallback | `completed` | `src/web_app.py`, `src/static/index.html`, `src/static/app.js`, `src/static/vendor/` |
| WS3 Validation and governance | Rebuild, live-reload, and close the deferred public-readiness finding with durable docs | `completed` | `npm run build:frontend`, live browser reload at `http://localhost:8003`, updated public-readiness docs, this control pack |

## Risks and Dependencies

1. The legacy inline frontend source still exists, so future UI changes must rebuild `src/static/` assets before release.
2. The build pipeline depends on Node for regeneration, but runtime startup does not.
3. Vendor asset versions are pinned intentionally; changing them should be treated as its own verification event.

## Current Status

What is complete now:

- the runtime frontend shell serves checked-in local static assets from `src/static/`
- the JSX app is precompiled into `src/static/app.js`
- the runtime shell no longer loads React, ReactDOM, Tailwind, Font Awesome, or Babel from CDNs
- FastAPI serves `/static` assets and falls back to the legacy inline template only if generated assets are missing
- `PAR-F009` is closed in the public-readiness artifacts

What remains open:

- the legacy inline template still exists as a build source and safe fallback; removing it is optional future cleanup, not an open must-pass gap for this initiative

## Validation Evidence

- `npm run build:frontend`
- live browser reload at `http://localhost:8003` showing the app still renders and the prior Babel warning path is no longer present
- source inspection of `src/static/index.html` confirming only local `/static/...` runtime dependencies
- `c:/Temp/splunk-discovery-tool/.venv/Scripts/python.exe -m ruff check src tests`
- `c:/Temp/splunk-discovery-tool/.venv/Scripts/python.exe -W error::SyntaxWarning -m compileall -q src tests`
- `c:/Temp/splunk-discovery-tool/.venv/Scripts/python.exe -m unittest discover -v`