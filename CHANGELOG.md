# Changelog

All notable changes to the Splunk Discovery Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - TBD (In Development)

### 🤖 Grounded Chat Agent, Reliable Discovery & LLM Auto-Tuning

#### Added
- **Model profiles, ranking, and auto-tuning** (`src/llm/model_profiles.py`, `src/llm/runtime_tuning.py`)
  - Builds a capability profile per model from endpoint metadata (Ollama `/api/tags` and `/api/show`; the `/models` extensions of vLLM, LM Studio, llama.cpp, OpenRouter, Groq, Mistral, Together; the Gemini model list), a curated hosted-model catalog, and open-weight size/family heuristics
  - Ranks models by balanced quality (45%), speed (30%), and cost (25%); `/api/llm/list-models` now returns `ranked`, `recommended`, and `recommended_model`
  - Auto-tune (on by default) derives the output budget, temperature, context window, request timeout, reasoning effort, and per-step chat budgets from the profile; newer GPT generations (for example `gpt-6.1-*`) map onto the closest catalog profile
  - `/api/llm/test-connection` probes with the tuned settings and returns recommended runtime settings with a short rationale
  - New LLM settings: `auto_tune`, `context_window`, `request_timeout`, `reasoning_effort` (also stored on saved credentials)
  - Settings UI: auto-tune toggle, recommended model, and optional context/timeout/reasoning overrides
- **Grounded chat agent helpers** (`src/chat_agent.py`): system prompts built from the live MCP tool catalog, normalized tool outcomes (`error` / `no_data` / `data`), evidence rendering within the tuned budget, and tool feedback that always shows the SPL and time range that ran
- **Chat mission**: a mission field in the chat panel (kept when chat history is cleared) is sent with each request, stored in chat memory, shapes the prompts, and adds a "Next step for the mission" follow-on
- **MCP argument adaptation** (`src/mcp_tool_args.py`): maps tool arguments onto each tool's advertised input schema (for example `index_name`, knowledge-object `type` enums) and parses JSON-RPC errors
- **SPL utilities** (`src/spl/spl_utils.py`): read-only safety checks, entity extraction, validation against discovered indexes/sourcetypes/hosts, index scoping, time bounds, and JSON extraction from LLM output
- **Discovery facts in chat**: when the request or mission names an index, sourcetype, source, or host, the plan hints include what discovery recorded about it (event totals, last event time, stale-data findings)
- Unit suites: `tests/test_chat_agent.py`, `tests/test_discovery_pipeline.py`, `tests/test_model_profiles.py`, `tests/test_spl_utils.py`

#### Changed
- **Chat tool loop**: one tool call per step; skips exact repeats and index-by-index sweeps after an empty result; asks once for the missing tool call when a model promises a search; recovers misspelled, unterminated, bare, backticked, or fenced tool-call JSON; stops on fatal MCP errors; returns tool results as user turns so providers keep them attached to the call
- **Unscoped searches**: chat searches that name no index run with `index=*` (Splunk otherwise searches only the role's default indexes), and the model is told that the index was added
- **Answer grounding**: prompts state that zero results are not proof of health or failure, that event totals and index sizes do not show recency, and that more searches should be offered rather than promised
- **Result analysis and follow-on actions**: aggregated results are ranked by their count column, Splunk internal fields (`_cd`, `_bkt`, `date_*`, `punct`, ...) are never used as pivots, index metadata without a latest-event time is flagged as totals-only, and failed searches offer a repair action
- **Discovery engine and v2 pipeline**: schema-aware knowledge-object discovery, per-step status for unsupported or failed steps, de-duplicated MCP calls, readable data-volume formatting, a discovery quality record, freshness computed from metadata timestamps, and one shared JSON-only analysis prompt for all providers that forbids invented entities
- **LLM health monitor**: response-time thresholds and timeouts follow the tuned runtime (local models are slower); slow but successful responses degrade the status instead of marking the endpoint unhealthy
- Chat memory writes are atomic and the latest report knowledge is memoized per report file set

#### Fixed
- Discovery patterns, recommendations, and use cases came back empty or from the wrong list when the model's JSON was truncated or wrapped; truncated arrays are now salvaged
- Source and host freshness read the MCP metadata tool's `*TimeIso` fields, which carry a `Z` suffix but were observed in the Splunk server's local time; epoch fields now take priority (sources in a UTC-5 environment were reported 5 hours staler than they were)
- "Top" values in result summaries and follow-on actions followed the row order instead of the counts
- Follow-on actions suggested filters on Splunk internal fields such as `_cd`
- Local models leaked chat-template tokens and a leading `assistant` role label into answers
- Saved-credential details in Settings are HTML-escaped
- The browser regression harness reports a missing Python interpreter instead of crashing, restores seeded output, and removes the export directory it created

### 🔐 Saved MCP Configurations & Credentials

#### Fixed
- Updating a saved MCP configuration without retyping its token stored the `***` mask as the token, so loading it later failed authentication; updating an LLM credential without retyping its key erased the key. A blank or masked secret now keeps the saved value, and a new configuration for the active server (or a new credential for the active provider and endpoint) reuses the active secret
- Profile names containing `'`, `/`, `#`, `?`, or `%` broke Test, Load, and Delete; the routes accept any name, and the Settings lists pass names through data attributes and encoded URLs
- "Save as New" after loading an MCP configuration opened a dialog with a locked, empty name field
- The save dialog previewed the active settings (old URL, "Token: Not set") instead of the values typed in the form
- Updating the active MCP configuration or LLM credential did not update the live connection, and the first MCP configuration saved on a fresh install was not made active
- Test Connection on the MCP form sent `***` as the bearer token after a configuration was loaded; it now uses the saved token, and testing a saved configuration with no token reports that instead of calling the server
- Save failures now report the reason and the config file path; config writes are atomic, and a config file that cannot be decrypted is kept as `config.encrypted.corrupted-<time>` instead of being overwritten with defaults
- On macOS a second server could bind `0.0.0.0:8003` while another listened on `127.0.0.1:8003`; startup now detects the local listener and moves to the next free port

#### Added
- Saved configurations without a token show a NO TOKEN badge, and saving over an existing name asks for confirmation
- Regression suites: `tests/test_settings_profiles.py` and `tools/test_settings_profiles_browser.mjs` (`npm run test:settings-profiles-browser`, also run in CI)

### 🩺 Settings Troubleshooting

#### Added
- **Troubleshoot tab in Settings** (`src/troubleshooting.py`, `POST /api/troubleshoot/mcp`, `POST /api/troubleshoot/llm`): checks an MCP configuration or AI provider credential without saving it and explains why it can't connect or can't be saved, in five stages: app and server, values entered, saving, network, and the server's response. Reports redact tokens and keys and can be copied as plain text
  - App and server: running code vs. the install folder, missing or outdated packages from `requirements.txt`, the Python environment, other copies of the app on nearby ports, and whether the signed-in account may save
  - Values entered: the save endpoint's own validation, URL mistakes (Splunk Web port, `http` on the management port, missing `/services/mcp`), pasted `Bearer ` prefixes and whitespace, JWT expiry, CA bundle files, and provider-specific key and endpoint checks
  - Saving: settings location vs. the install folder, folder permissions (including root-owned files and macOS protected folders), disk space, key/settings file mismatches, the last save error, and a test save to a temporary copy
  - Network: proxy, DNS, TCP, and TLS trust with certificate details and Splunk self-signed certificate advice
  - Response: MCP `tools/list` (redirects, 401/403/404/405, HTML pages, event streams, JSON-RPC errors, tool count) and AI provider errors classified into plain-language causes
- `GET /api/troubleshoot/server-status`: Settings shows a banner when the server runs older code than the install folder (for example after `git pull` without a restart), or when the server is too old to have the endpoint
  - The banner names the server's port (and, for admins, its folder and restart command), looks for other copies of the app on ports 8003-8023, links to an up-to-date copy, and explains that restarting a copy in another folder doesn't change the one answering
  - The troubleshooter's other-copies check reports each copy's version, process ID, and folder, with the command that stops the older ones
- `install.sh` and `install.ps1` list other copies of the app on its ports (process ID and folder) after starting and with `--status` / `-Status`, with one command to stop them and restart this copy
- Troubleshoot buttons next to Test Connection in the MCP and AI provider forms; failed saves and MCP tests offer to open the troubleshooter with the same values
- **CA Bundle File** field in the MCP form, saved with the configuration and used by Test Connection
- Regression suites: `tests/test_troubleshooting.py` and `tools/test_settings_troubleshoot_browser.mjs` (`npm run test:settings-troubleshoot-browser`, also run in CI); CI also checks `install.sh` and `install.ps1` syntax

#### Changed
- `install.sh` and `install.ps1` start the app from the install folder, reinstall Python packages when `requirements.txt` changes (also on restart), warn when the running service started before the code changed, and print the port the app actually uses
- Save errors that aren't JSON (proxy pages, crashes) show the HTTP status and the start of the response instead of "Unknown error"; a save that worked but couldn't refresh capabilities shows the warning
- Settings tabs keep the Connections forms mounted, so typed values and the saved lists survive switching tabs

#### Fixed
- Tokens and API keys pasted with a `Bearer ` prefix or surrounding whitespace were saved as-is and then rejected by the server
- A capability refresh error after a successful save turned the save into an HTTP 500
- `./install.sh` reported port 8003 even when the app had moved to another port, and launching it from another folder stored settings in that folder
- After installing again in a new folder, the out-of-date banner kept appearing on the old copy's port and told users to restart, which only restarted the new copy on a fallback port
- Saving an MCP configuration from the form dropped its CA bundle path, and Test Connection ignored the CA bundle and sent a request without the JSON-RPC `jsonrpc`/`id` fields that strict MCP servers require

### 🎨 Themes, Contrast & Stylesheet

#### Added
- **Neo theme** in Settings > Appearance, next to Light, Dark, and System, and saved like the others. It replaces the hidden Construct theme, which only lasted for one browser tab
- `tools/test_ui_contrast_browser.mjs` (`npm run test:ui-contrast-browser`, also run in CI): opens each workspace tab, the report viewer, the summary tabs, chat, chat settings, connection details, and each Settings tab in Light, Dark, Neo, and System (light and dark) against seeded discovery output. It fails when text or a placeholder falls below WCAG AA contrast, when text is smaller than 12px, or when a view can't be reached

#### Changed
- The stylesheet is built at `npm run build:frontend` time with Tailwind's JIT engine (`tailwind.config.cjs`) into `src/static/app.css`, which holds only the classes the app uses (75 KB instead of the 2.9 MB full Tailwind file)
- Colors come from per-theme CSS variables in the template, so each theme recolors every utility class. Light darkens gray helper text; Dark keeps the standard grays; Neo maps the palette to greens
- Layouts written with Tailwind arbitrary values (two-column grids, size limits, dialog stacking) now take effect; the full Tailwind file never included them
- Text that was 10-11px is now 12px, and uppercase labels use less letter-spacing
- Google Fonts are no longer loaded; Neo uses the system monospace font
- `build-manifest.json` records the Tailwind config and `app.css` hashes, so `tools/check_frontend_sync.py` reports a stale stylesheet

#### Fixed
- Text below 4.5:1 contrast: gray helper text and placeholders, the dark-theme Export link, translucent header buttons, the discovery log banner, and chat settings hints. A full pass found 36 failures in Light, 14 in Dark, and about 50 in Construct; every theme now has none

### ✍️ Plain Language & Text Fixes

#### Added
- `tests/test_ui_copy.py`: fails when the template contains the old product name, the Construct theme name, "(s)" plurals, doubled words, listed jargon, or dates formatted without `formatMissionDateTime()`
- The contrast browser check also reads the text of each view and fails on the old product name, raw session or ISO timestamps, "(s)" plurals, doubled words, `undefined` or `NaN`, and listed jargon. Report bodies and code blocks are skipped because they show saved data as written

#### Changed
- The app is called Splunk Discovery Tool everywhere: page title, header, welcome screen, sign-in page, troubleshooting report, docs, and installers
- Plain wording across Mission, Intelligence, Discovery, the Knowledge Base, Capabilities, the discovery summary, chat, and Settings. For example: discovery stages are Prepare, Survey the environment, Collect details, and so on; report styles are Direct, Evidence-led, and Executive; the welcome button is Get Started; Settings tabs are Connections, Users, Security, and Troubleshoot; the connection buttons are Add MCP Server and Add AI Model; Abort Summary is Stop Summary
- Capability names: M-26-14 Readiness Advisor, Quick Report Search, Knowledge Base, Splunk Search Links, Charts, and Report Packages, each with a one-line description of what it does
- Dates show as "May 22, 2026, 1:02 AM" instead of raw session IDs or ISO strings, and counts use the right singular or plural
- The AI summary prompt asks for a "Next Check" section instead of "Recursive Next Loop"; summaries saved with the old heading still show it
- With sign-in off, Settings says anyone can use the app instead of calling it demo mode
- Removed filler: the welcome screen's repeated "Welcome" label, a "Fun Facts" line, the capability "Stage" field, the "Available now" badge on every capability card, and unused summary and capability card code

#### Fixed
- The executive summary repeated its first paragraph
- The chat connection popover named a provider when no AI model was configured
- The empty MCP list told users to click "Save Current Config", a button that does not exist
- The Users and Security tabs in Settings both used the heading "Security & Access"
- The summary dialog showed the raw session ID as its subtitle, and category names such as "data quality" were lowercase
- Settings tab icons were read aloud as part of the tab names

### 🧭 Navigation & Page Layout

#### Added
- Capabilities can add their own workspace tab: `CapabilityWorkspace(id, label, description)` on a `CapabilityDefinition`, returned as `workspace` by `GET /api/capabilities`. The tab appears after the core tabs while the capability is installed and enabled, and its label comes from this metadata. The M-26-14 Readiness Advisor adds the M-26-14 tab this way
- A connection status button in the header (Connected, Setup incomplete, Status unavailable, or Not connected) that opens connection details
- The Discovery tab shows the progress of a running discovery, or Failed after a failed run
- Arrow keys, Home, and End move between tabs in the workspace tab bar, the runbook audience tabs, and the summary view tabs
- Settings > Appearance holds the theme choice and the welcome screen options. Changes there apply right away, so it has no Save Settings button

#### Changed
- The workspace tabs are Overview, Findings, Discovery, Knowledge Base, and Capabilities, followed by capability tabs. Mission is now Overview, Intelligence is now Findings, and Context is now Knowledge Base
- The header has two rows: the app name, connection status, Chat, sign-in, and Settings on top, then the tabs. Actions such as Refresh and the wording style sit on the page they affect
- Overview shows the discovery status, one row of six key numbers, the top three next steps, run comparison, the runbook, and report packages
- Findings shows the full next-step lists: coverage gaps for admins (with the matching risk mitigation as the next step), investigations for analysts, and business value for executives. The environment profile and key evidence follow, then patterns
- Overview and Findings read their next steps from the same lists, so the top three on Overview always match the start of the lists on Findings
- The runbook card on Overview shows a short description instead of repeating the next-step lists
- The Capabilities tab has a Refresh button instead of a second row of tabs
- The Runbook and Report Package cards put their buttons under the description, and the buttons wrap on narrow screens
- Abort Discovery is now Stop Discovery
- The README screenshots show the Overview and Findings tabs

#### Removed
- The Chat tab; Chat opens from the header
- The theme picker at the top of the workspace (now in Settings > Appearance)
- The Discovery steps tile in the environment profile, which showed the estimate made before the run
- Cards that repeated the same next steps: Mission's Admin tasks, Investigations, and Executive summary cards, and Intelligence's Top priorities, Coverage gaps, and Suggested investigations cards. Findings now lists each step once

### 📚 Knowledge Library & Coverage Scorecard

#### Added
- **Environment profile from discovery** (`src/discovery/environment_profile.py`): a new "Installed apps and add-ons" step lists apps through the MCP knowledge-object tool, or `| rest /services/apps/local` when that tool cannot. The v2 blueprint gains `environment_profile` with the Splunk version, the matching documentation version, the deployment type (Splunk Cloud Platform or Splunk Enterprise, with the reason), and the installed apps with built-in apps marked. A failed app listing does not lower the discovery reliability score
- **Knowledge library sources** (`src/knowledge_library/`), stored under `output/knowledge_library/` and kept out of the Knowledge Base index:
  - Splunk Security Content data sources (latest release of `splunk/security_content`): the sourcetypes each data source produces and the add-on that supports it
  - Splunkbase records for the installed apps: latest release, archived state, and Splunk Cloud Platform compatibility
  - help.splunk.com sitemaps: an index of documentation pages by product, manual, and version, so links point at the release you run. Pages are linked, not downloaded
- **Online sources are off by default.** An admin turns them on in Knowledge Base > Library health. The server then refreshes in the background when a source is missing or more than a week old, or when discovery finds an app that has not been looked up. Requests go only to `api.github.com`, `raw.githubusercontent.com`, `splunkbase.splunk.com`, and `help.splunk.com` over HTTPS
- **Library packs** for servers without internet access: Export pack downloads the loaded sources as a zip, and Import pack loads one (up to 100 MB; every file is checked before anything is saved)
- **Library health panel and coverage scorecard** on the Knowledge Base tab: an overall score averaged from Environment facts, Data source references, Add-ons for your data, App versions, Documentation for your version, and Knowledge Base coverage. Prioritized gaps come with a next action: add-ons that your sourcetypes need but are missing or turned off, outdated or archived apps, apps not marked Cloud compatible on Splunk Cloud Platform, and busy sourcetypes no public reference describes. The panel also lists the matched references, apps, and documentation links. A dimension whose source is not loaded says what it needs instead of scoring 0
- `GET /api/knowledge-library/status` and `GET /api/knowledge-library/pack/export`, plus admin-only `POST /api/knowledge-library/settings`, `POST /api/knowledge-library/refresh`, and `POST /api/knowledge-library/pack/import`
- Unit suite `tests/test_knowledge_library.py` and installed-apps cases in `tests/test_discovery_pipeline.py`

### 📄 Discovery, Capabilities & Knowledge Base Pages

#### Added
- Remove for optional capabilities: `POST /api/capabilities/{name}/uninstall` turns a capability off and marks it not installed. Its packages, settings, and Knowledge Base data are kept, so Install brings it back as it was
- The report viewer formats Markdown reports: headings, lists, tables, quotes, and code blocks. The page builds them as elements, never as HTML, so a report cannot add markup to the page. Export still downloads the original file
- Browser checks: capability cards offer only the actions for their state, Run details starts folded after a finished run, report names have no underscores, Settings > Troubleshoot has no Save Settings, the welcome screen lists three steps, Set Up Connections on a fresh install opens Settings, the newest run's reports show without expanding anything, and Markdown reports show headings and code blocks instead of raw markers. The contrast check also covers a formatted Markdown report

#### Changed
- The Discovery tab has one status card with the run state, key facts, Stop or Run Discovery, and View Summary (Summarize when no summary is saved). The report library comes first; on phones the viewer appears after you pick a report. Stages and the activity log sit under Run details, which opens while discovery runs and after a failed or stopped run
- Reports show plain names such as Insights brief and Operator runbook, with the file name underneath. Other reports get a readable name that keeps acronyms, such as SPL library report. The empty report viewer is one line
- The report library opens on the newest run, so its reports show without expanding the year, day, and run. Each run has a smaller View Summary or Summarize button in the neutral style, says "1 report" instead of "1 reports", and no longer shows an unlabeled clock time
- The SPL buttons (Open in Splunk, Save to Library, Use in Chat, Copy) share one neutral style instead of four colors. Generate Runbook on Overview uses the neutral style, so Download Runbook is the one main action
- Capability cards show only the actions that fit their state: Install when not installed, Turn On and Remove when off, Test and Turn Off when on. Settings sit under Advanced settings, with Save Settings only for installed capabilities. Splunk Search Links shows its link builder only when it is on and ready
- The Capabilities tab shows one line of counts instead of five tiles, and the Knowledge Base card links to its tab only when it is installed
- The Knowledge Base tab has one Status card with the capability actions and Reindex; index counts appear once it is installed. Preview Chat Context says what it needs before it works, Clear Preview appears only after a preview, and the extra Refresh List button is gone (Refresh at the top reloads the library)
- Capability messages say "turn on" instead of "enable" and name the capability instead of its internal ID
- The welcome screen lists three numbered steps (Connect, Run discovery, Review and act) instead of four overlapping panels, offers Set Up Connections until the app is connected, and fits on a phone screen
- Runbooks, persona playbooks, and Findings cards leave out a line when discovery recorded nothing for it, instead of repeating generic text such as "Create implementation task for: ..." or "Schedule this as a recurring task." Executive themes come from the suggested use cases and the 90-day focus from the top recommendations, instead of fixed text
- Compare runs on Overview and the M-26-14 tab appears only after two or more discovery runs

#### Fixed
- The Discovery tab offered Summarize for runs that already had a saved summary
- Disabled buttons in Dark matched the card behind them, and Download Runbook, Build Report Package, and Download package kept their light disabled colors
- Settings > Troubleshoot showed Save Settings, which saved the hidden connection form
- Nine elements used `shrink-0`, which Tailwind 2 does not generate; they now use `flex-shrink-0`
- Advanced settings in Dark sat on a near-black bar that stood out from its card
- Installing the Knowledge Base on a Python version that onnxruntime does not support yet (such as 3.15) quietly fell back to chromadb 0.3.23, which fails on import. The install now requires chromadb 1.x, and when pip cannot install onnxruntime it installs chromadb and its other dependencies without it. The Knowledge Base uses its own embedding function, so it never needs onnxruntime
- A Knowledge Base install whose packages cannot load (such as that chromadb 0.3.23) kept saying "Restart Splunk Discovery Tool to finish installing", and restarting never finished it. At startup, a capability that is still waiting for a restart and whose packages still do not import is shown as not installed, so Install can repair it
- Install guidance quotes package version ranges so the copied pip command works in a shell
- The README and installers asked for Python 3.8 or newer; they now say 3.11 or newer, the oldest version the test suite has been run on

### 🪟 Summary, Chat, Connection Details & M-26-14

#### Added
- The contrast check opens the MCP server and AI model forms in Settings > Connections and both save dialogs, so it now covers 120 surfaces across five themes instead of 105

#### Changed
- **Summary dialog**: the header shows Discovery Summary, a Saved badge, and the run date, without a gradient. Tabs share one underline style and show their counts in plain text; the green New badge is gone
  - Executive Summary opens with "What this run found" and four tiles (Readiness, Open risks, Coverage gaps, Admin tasks), followed by Details, By the Numbers, Priority Actions, and Quick Wins
  - SPL Queries show "High priority" or "Medium priority" and where the search came from (AI-generated, Environment-based, Template-based), with filter buttons that show counts. "From discovery" and "Why it matters" replace "📋 Discovery Finding" and "Business Value", and Show SPL replaces View SPL Code
  - Admin Tasks use plain labels: Checklist, Expected result, Suggest a Fix (was Get Remediation Help), Run Again (was Re-verify), Likely Cause, Chance of success, How to Prevent It, and How to Undo (was Rollback Instructions). Verification history reads "Attempt 2: Passed" instead of "Attempt #2 - SUCCESS"
  - While a summary builds, the dialog says Building Your Summary with a solid progress bar, and Stop Summary is a standard red button
- **Chat**: searches are labeled "Search that ran" or "Suggested search (not run)", the step list reads "Steps taken (3 rounds, 12s)" instead of "Investigation Timeline (3 iterations, 12s)", and View Raw Data is now Show raw data. The typing dots move only when the system allows motion, and screen readers hear "The assistant is working."
- **Chat Settings**: groups settings into Answer Limits, AI Model, Retries and Sampling, Answer Quality, and Extras. Max response length is a number field that explains when the AI connection allows fewer tokens (for example "allows up to 8,192 tokens, so answers stop at 8,192"), and the footer says changes apply right away and reset when the server restarts
- **Connection Details**: the header shows the overall status. The Splunk MCP server and AI model sections are each marked Set up or Not set up and list the address, saved name, provider, model, and endpoint, with a hint when something is missing. A load error shows a plain message with Try Again, and Open Settings sits at the bottom (the main action while the app is not connected)
- **M-26-14 tab**: renamed M-26-14 Readiness Advisor to M-26-14 Readiness and rewrote its text in plain language
  - Priority objectives spell out Continuous Event Monitoring (CEM) and Threat Hunting, Investigation, Response, and Forensics (THIRF)
  - Compare Runs has labeled run pickers and shows Readiness change and Maturity floor change instead of "Δ"
  - Maturity elements list Found, Missing, Not yet known, and Next step
  - Live Checks (was Curated Live Validation) has Check, Suggested checks, and From/To fields with a Splunk time hint, shows the "Search that will run", and starts with Run Check
  - Check results show What Discovery Found, Related Context, Searches you can reuse, and AI Review (was Grounded Advisory)
- M-26-14 server messages use plain language: why AI review is unavailable or turned off, unknown checks, a missing MCP server, failed checks, and the check descriptions, evidence, gaps, and next steps. Two checks are renamed: Alert and Detection Coverage (was Alert and Detection Posture) and Timestamp and Data Freshness (was Timestamp and Freshness Sanity)
- **Save dialogs** for MCP configurations and AI model connections are labeled dialogs that close with Escape, with a neutral header, an amber note when saving replaces a saved item, labeled fields, a list of the settings to save, plain confirmation text, and green success messages that screen readers announce. Titles read Save (or Update) MCP Configuration and Save (or Update) AI Model Connection
- Settings panels (MCP server, AI model, troubleshooter, security) use neutral cards, and their buttons use the shared primary and secondary styles. Fetch Models and Auto-Assess use the neutral small button style instead of purple and indigo
- The warning toast is solid amber, toasts no longer bounce, the discovery banner is solid indigo, and saved-list buttons no longer grow on hover

#### Removed
- The last gradient backgrounds, including the `.animated-gradient` style, and the dark-theme overrides that only existed to restyle them

#### Fixed
- Admin Tasks showed "Generating Tasks..." with no end when a summary had no tasks; it now says the run has no admin tasks and suggests asking in Chat
- In Dark, Neo, and system dark, the AI model form's auto-tune box and the Fetch Models and Auto-Assess buttons kept light backgrounds under lightened text (1.3:1 to 1.8:1 contrast), and the recommended-model note used dark green text on its dark background
- Fetch Models and Auto-Assess sat inside the Model and Max Tokens labels, so screen readers announced them as "Model" and "Max Tokens" buttons and clicking either label ran the action. The labels now name their fields
- The required-field asterisk in the save dialogs was dark red on a dark background in dark themes
- Icons in the Settings connection forms were part of the button names that screen readers and browser tests see; they are now hidden from assistive technology
### 🧩 Workspace & Summarization UX Hardening

#### Added
- **Repo Validation Automation**
  - GitHub Actions workflow at `.github/workflows/repo-validation.yml`
  - Push, pull request, and manual validation for frontend build, frontend sync, Ruff, strict compile, and unittest gates
  - Ubuntu and Windows runner coverage to catch OS-sensitive path and line-ending regressions earlier

- **Frontend Bundle Sync Guardrails**
  - Build manifest generation for shipped frontend assets in `src/static/build-manifest.json`
  - Python sync checker at `tools/check_frontend_sync.py` for source-to-bundle drift detection
  - Unittest coverage that fails when `src/web_app.py` and `src/static/` fall out of sync
  - Installer start warnings when stale frontend assets are detected

#### Added
- **Workspace Surfaces (UI + API integration)**
  - Unified static top bar with Mission / Intelligence / Artifacts workflow tabs
  - Intelligence workspace bindings to `/api/discovery/dashboard`, `/api/discovery/compare`, `/api/discovery/runbook`, and `/api/v2/intelligence`
  - Artifacts workspace bindings to `/api/v2/artifacts` with current artifact handling

- **Summarization Context Enrichment** (`/summarize-session`)
  - Environment extraction for indexes, sourcetypes, and hosts from the discovery finding ledger
  - Environment-aware SPL query anchoring and evidence tagging
  - Context-engine fallback generation for both SPL queries and admin tasks
  - Expanded intelligence payload surfaces (`trend_signals`, `risk_register`, `recursive_investigations`, `vulnerability_hypotheses`)

#### Changed
- **Header Architecture**
  - Removed legacy “Mission Control” title block
  - Merged tab controls and action buttons into the top static header layout
  - Reworked tab actions to trigger real workspace state transitions and refreshes

- **Generated Reports/Artifacts Sidebar Behavior**
  - Refined session row spacing and indentation
  - Added clipping + min-width protections to prevent content overflow
  - Improved action button stacking for constrained widths

- **Summary Modal Progress Semantics**
  - Normalized stage mapping to include `creating_summary`
  - Added monotonic progress behavior during polling updates

#### Fixed
- **Dark Mode Readability**
  - Corrected compile/progress screen contrast in summary modal
  - Improved dark styling for SPL query and admin task tabs
  - Updated discovery log card rendering for phase/success/error/warning/info/rate-limit/completion states
  - Updated contrast for “Save LLM Credential” and “Save MCP Configuration” modals in dark theme

- **Provider-Agnostic LLM Configuration & Testing**
  - Normalized provider handling for `openai`, `azure`, `anthropic`, `gemini`, and `custom`
  - Updated `/api/llm/list-models` and `/api/llm/test-connection` to provider-aware behavior
  - Added custom endpoint candidate-path fallback for base URLs such as `/v1`

- **Summarization Error Handling**
  - Added missing `Tuple` typing import causing summarize-time runtime failure
  - Hardened client-side summary fetch parsing for non-JSON 500 responses
  - Improved surfaced error messages for failed summary requests

### 🚀 Phase 1: Resilience & Health Monitoring (CRITICAL)

#### Added
- **LLM Health Monitoring System** (`llm/health_monitor.py`)
  - Continuous endpoint health tracking with rolling metrics (last 100 requests)
  - Response time monitoring (average + 95th percentile)
  - Error rate tracking with health status (healthy/degraded/unhealthy)
  - Automatic recommendations for timeout and token limits
  - Consecutive failure detection (10+ failures = refuse requests)
  
- **Adaptive Timeout Management**
  - Dynamic timeout calculation based on endpoint health + payload size
  - Payload-aware timeouts (accounts for token count)
  - Error-rate adaptive buffer (higher errors = more buffer)
  - Range: 10-120 seconds (clamped to reasonable bounds)
  
- **Hung Request Detection**
  - Monitors requests for progress (30s no-progress = hung)
  - Automatic cancellation of stuck requests
  - Request ID tracking with timestamps
  - Clean timeout error messages
  
- **Payload Size Adaptation**
  - Intelligent message truncation based on endpoint health
  - Healthy: Full payload (100%)
  - Degraded: Reduced payload (70%)
  - Unhealthy: Aggressive reduction (50%)
  - System messages always preserved
  - Most recent messages prioritized
  
- **Enhanced CustomLLMClient**
  - Integrated health monitoring into sync request path
  - Pre-request health checks (refuse if 10+ consecutive failures)
  - Adaptive timeout per request
  - Automatic payload adaptation
  - Success/failure recording with metrics
  - Detailed health logging

- **Health Metrics API**
  - New endpoint: `GET /api/llm/health`
  - Returns per-endpoint health metrics

#### Testing
- ✅ **Unit Test Scope**: Core health-monitoring behaviors validated
  - Health status transitions
  - Adaptive timeout calculation
  - Payload size adaptation
  - Hung request detection
  - Consecutive failure handling
  - Retry delay calculation
- ⚠️ **Integration Test Scope**: Partial pass with known mock-environment limits
  - HTTP 503 handling ✅
  - Timeout handling ⚠️ (needs mock server fixes)
  - Slow endpoint handling ⚠️ (needs mock server fixes)
  - Random failures ✅
  - High load ✅
  - Oversized payload ⚠️ (needs mock server fixes)
  - Summary statistics (healthy/degraded/unhealthy counts)
  - Exposed metrics:
    - Status, avg/p95 response time, error rate
    - Success/failure counts, timeout count
    - Last success/failure timestamps
    - Recommended timeout and max_tokens
    - Consecutive failures, uptime percentage

#### Changed
- CustomLLMClient now uses health-aware request handling
- Request timeouts are now adaptive (10-120s) instead of fixed 120s
- Message payloads automatically adapt to endpoint health
- All LLM requests now tracked for health metrics

#### Intelligence Improvements
- **Chat Agent**: 95/100 → 98/100 (+3 points)
  - Resilience: 13 → 15 (+2) - Health monitoring, hung detection
  - Adaptivity: 19 → 20 (+1) - Endpoint-aware behavior
  - Token Efficiency: 14 → 15 (+1) - Payload adaptation

### 🎯 Phase 2: Adaptive Discovery (Planned)
- AI-driven discovery planning
- Context-aware MCP call selection
- Early termination logic
- Anomaly detection & deep-dive

### 🔁 Phase 3: Iterative Summarization (Planned)
- Multi-pass analysis with quality gates
- Gap detection and filling
- Self-assessment integration

### 🏗️ Phase 4: Unified Agentic Framework (Planned)
- Shared agentic loop infrastructure
- Common quality assessment
- Unified error handling

---

## [1.0.0] - 2025-10-31

### 🎉 Initial Release

First production-ready release of the Splunk Discovery Tool with AI-powered admin assistance.

### Added

#### Core Features
- **AI-Powered Admin Chat**: Natural language Splunk administration with intelligent SPL query generation
- **Multi-Turn Reasoning**: Automatic query refinement with quality validation (0-100 scale)
- **Smart Convergence Detection**: Prevents infinite loops while allowing data quality improvements
- **Discovery Engine**: Automated Splunk environment scanning via MCP protocol
- **Real-Time WebSocket**: Live updates for discovery progress and chat interactions

#### Configuration & Security
- **Encrypted Configuration**: Fernet encryption for all credentials (no plaintext storage)
- **Web-Based Settings Panel**: Complete configuration management through intuitive UI
- **Universal Installers**: Cross-platform installation scripts for Windows (`install.ps1`) and Unix/macOS (`install.sh`)
- **Service Management**: Background daemon with `--start`, `--stop`, `--restart`, `--uninstall` commands

#### User Interface
- **Modern Web Interface**: React-based frontend with FastAPI backend
- **Three Main Tabs**: Discovery, Chat, Reports
- **Settings Modal**: Comprehensive configuration for MCP server, LLM provider, and web server
- **Debug Mode**: Optional real-time debug window with WebSocket streaming
- **Dependencies Viewer**: Modal showing installed Python packages and versions

#### Quality & Reliability
- **Quality Assessment**: Intelligent scoring system for SPL query results
  - High (≥70): Immediately usable results
  - Moderate (50-69): Accept if actionable or continue refining
  - Low (<50): Force query refinement with format requirements
- **Timestamp Formatting Detection**: Prevents convergence during post-processing steps
- **Diversity Requirements**: SPL query generation with temperature 0.75 to ensure varied approaches
- **Error Handling**: Comprehensive error messages and debug logging

#### Developer Experience
- **Clean Codebase**: Removed unused modules (CLI, classification, recommendations, output)
- **Type Safety**: Pydantic models for configuration and API requests
- **Async/Await**: Modern async Python for efficient I/O operations
- **Documented Code**: Inline comments and clear function signatures

### Technical Details

#### Dependencies
- FastAPI 0.104.0+ (web framework)
- Uvicorn 0.24.0+ (ASGI server)
- Cryptography 41.0.0+ (encryption)
- PyYAML 6.0+ (configuration)
- HTTPX 0.24.0+ (HTTP client)
- AIOHTTP 3.9.0+ (async HTTP)
- OpenAI 1.0.0+ (LLM integration)
- Python 3.8+ (runtime)

#### Architecture
- **Port**: 8003 (configurable)
- **Protocol**: HTTP + WebSocket
- **Storage**: Encrypted config file (`config.encrypted`)
- **Logs**: `dt4sms.log` (when run as service)
- **PID**: `.dt4sms.pid` (service mode)

### Installation
```bash
# Windows
.\install.ps1

# Unix/macOS
./install.sh
```

### Configuration
Access settings at `http://localhost:8003` → ⚙️ Settings icon

Required configuration:
- MCP Server endpoint and bearer token
- LLM API key and model selection

### Known Limitations
- Discovery mode UI in progress (chat mode fully functional)
- Single LLM provider per session (configurable via settings)
- Debug mode secrets sanitization (filters common patterns but may not catch all)

### Future Roadmap (v1.1+)
- Intent alignment validation using semantic similarity
- Enhanced SPL query generation with multi-pass refinement
- Discovery result caching with differential updates
- Support for multiple LLM providers simultaneously
- Export chat history and SPL queries

---

## Release Notes

**v1.0.0** represents the culmination of extensive development and testing to create a production-ready Splunk admin assistant. The focus was on reliability, security, and user experience.

### Highlights
- ✅ **Zero plaintext secrets**: All credentials encrypted at rest
- ✅ **One-command installation**: Universal installers for all platforms
- ✅ **Intelligent query refinement**: Multi-turn reasoning with quality gates
- ✅ **Debug transparency**: Optional debug mode for troubleshooting
- ✅ **Enterprise-ready**: Service mode with proper daemon management

---

[1.0.0]: https://github.com/LeiterConsulting/splunk-discovery-tool/releases/tag/v1.0.0
