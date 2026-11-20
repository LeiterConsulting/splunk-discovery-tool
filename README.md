# 🔍 Splunk Discovery Tool

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.2.2-green.svg)](https://github.com/LeiterConsulting/splunk-discovery-tool/releases/tag/v2.2.2)

> Finds what a Splunk environment contains, explains what to do next, and answers questions with live Splunk searches through the Splunk MCP server.

**Current release: [2.2.2](https://github.com/LeiterConsulting/splunk-discovery-tool/releases/tag/v2.2.2)** (November 20, 2026). Each user's chat scratchpad stays private and out of the Knowledge Base, and with sign-in on, chat answers from the discovery reports of the environment each user searches. See [CHANGELOG.md](CHANGELOG.md) for what changed and how to upgrade from 1.0.0.

## ✨ What's Included

- **Discovery**: a worker-backed pipeline that surveys the environment through MCP, keeps its progress across restarts, and saves an intelligence blueprint, an insights brief, an operator runbook, and a developer handoff (`v2_*` files in `output/`)
- **Workspace**: Overview, Findings, Discovery, Knowledge Base, and Capabilities tabs, plus tabs that enabled capabilities add (such as M-26-14)
- **AI summaries**: an on-demand summary of each discovery run with an executive summary, SPL queries, and admin tasks
- **Chat grounded in Splunk**: the chat agent runs one search at a time against the live MCP tool catalog, shows the SPL and time range that ran, and offers follow-on searches
- **Chat goals**: set a goal, and the AI model breaks it into questions, tracks which ones your answers settle, and suggests what to ask next. The Goal Library keeps goals, tracked questions, and saved chats
- **Settings tuned to the model**: model profiles, ranking, and auto-tuning for hosted and local models. Chat Settings start from the model's tuning and show each value as Auto or Custom
- **Knowledge library**: the environment profile from discovery, Splunk Security Content, Splunkbase records, and help.splunk.com documentation for your Splunk version and installed apps, downloaded for offline search, with a coverage scorecard and library packs for servers without internet access
- **Knowledge Base** (optional capability): managed knowledge assets, the SPL Library, and context previews. Discovery and AI summaries update its index after saving, and a Reindex needed notice shows when other sources change
- **Troubleshooting**: Settings > Troubleshoot explains why an MCP server or AI model connection or save fails, without saving anything
- **Incognito mode**: the AI model sees stand-ins such as `host_0012` instead of your host names, IP addresses, users, custom indexes, apps, and saved searches, while you still see the real names. Admins can require it for cloud AI models, and you can download chats and reports with stand-ins to share
- **Security**: optional local sign-in and OIDC, per-user MCP assignment, scoped tokens for a read-only external RAG API and an inbound MCP surface (HTTP plus a stdio bridge), and Fernet-encrypted settings with no plaintext secrets
- **Themes and accessibility**: Light, Dark, Neo, and System themes that meet WCAG AA contrast, checked by a browser test in CI
- **Installers** for Windows (`install.ps1`) and macOS or Linux (`install.sh`)

## 📋 Prerequisites

### Required

- Python 3.11+
- pip
- PowerShell 7+ (Windows only, if using `install.ps1`)

### External Services

- Splunk MCP server endpoint + bearer token
- An AI model: an API key for OpenAI, Azure OpenAI, Anthropic, or Gemini, or a local or custom OpenAI-compatible endpoint (such as Ollama, vLLM, or LM Studio)

## 🚀 Quick Start

### Windows

```powershell
.\install.ps1
```

### Unix/macOS

```bash
chmod +x install.sh
./install.sh
```

After startup, open the URL printed in the console (typically **http://localhost:8003**).

### Upgrading

Pull the new code in the install folder, then restart with the installer so the server runs the new code and updates its Python packages:

```bash
git pull
./install.sh --restart
```

```powershell
git pull
.\install.ps1 -Restart
```

Settings, keys, and `output/` stay in the install folder. Read the upgrade notes in [CHANGELOG.md](CHANGELOG.md) when moving between major versions.

## ⚙️ First-Time Configuration

1. Open the app at the startup URL shown in the console (default `http://localhost:8003`) and select **Set Up Connections** on the welcome screen, or open Settings (gear icon)
2. On **Settings > Connections**:
   - **Add MCP Server**: the MCP URL (for example `https://<splunk-host>:8089/services/mcp`), token, SSL verification, and an optional CA bundle file. Select **Test Connection**, then save
   - **Add AI Model**: provider, API key, endpoint URL (when required), and model. Select **Fetch Models** for a ranked list with a recommendation, then **Test Connection & Auto-Configure**, then save
3. Saved connections apply right away. You can keep several saved MCP configurations and AI model connections and switch between them
4. Optional: turn on sign-in, OIDC, and external access on **Settings > Users** and **Settings > Security**, and pick a theme on **Settings > Appearance**
5. Run discovery from the **Discovery** tab

If a test or save fails, open **Settings > Troubleshoot** (see [Troubleshooting](#-troubleshooting)).

### AI Model Notes

- Providers: `openai`, `azure`, `anthropic`, `gemini`, `ollama`, `custom` (any OpenAI-compatible endpoint, such as vLLM or LM Studio)
- Endpoint URL required for: `azure`, `custom`
- Endpoint URL optional override for: `anthropic`, `gemini`, `ollama` (defaults to the local Ollama port)
- For `custom`, you can use a base URL (for example `http://host:port/v1`); the app tries the common completion paths
- **Auto-tune** (on by default) sets the output length, temperature, context window, request timeout, and reasoning effort from the model's profile. You can override each value
- **Test Connection & Auto-Configure** runs a connectivity probe and a generation test with the tuned settings, and recommends settings for the model
- **Fetch Models** and **Test Connection** use the active model's saved API key when the key field is blank, so you don't need to paste the key again to refresh the list
- OpenAI GPT-6 (Astra, Sol, Terra, Luna) and GPT-5.6 models have built-in profiles with their real context and output limits. GPT-5 and newer models run as reasoning models through the Responses API, without a temperature setting. A newer GPT generation than the app knows about uses the closest GPT-6 profile, and the model profile says so
- AI model requests trust Python's system certificate store plus the bundled public CAs (certifi), and certificate verification is always on. If your network inspects HTTPS with a CA that neither list has, set `SSL_CERT_FILE` to an IT-provided PEM bundle before starting the app (see [AI provider certificate errors](#ai-provider-certificate-errors))

## 🧠 Workspace Overview

The header holds the connection status, Chat, sign-in, and Settings. Each tab keeps its own actions, and the theme choice lives in Settings > Appearance.

- **Overview**: Discovery status, key numbers, the top three next steps, run comparison, the runbook, and report packages
- **Findings**: The full next-step lists for admins, analysts, and executives, the environment profile, key evidence, and patterns
- **Discovery**: Run discovery, follow each stage, and open saved reports and summaries
- **Knowledge Base**: Library health (how well public Splunk references, Splunkbase, and versioned docs cover your environment, with gaps to fix), searchable Splunk documentation for your versions and installed apps, managed knowledge assets, the SPL Library, reusable query evidence, and context previews
- **Capabilities**: Optional add-ons for the knowledge base, exports, charts, and Splunk search links. Each can be installed, turned on or off, tested, and removed
- **Capability tabs**: An enabled capability can add its own tab after the core tabs. The M-26-14 Readiness Advisor adds an M-26-14 tab
- **Chat and Summary**: Investigation chat, which opens as a Chat tab or in a window, plus the runbook and summary views when you need more detail

## 💬 Chat, Goals, and Chat Settings

Chat answers questions about your Splunk environment with live searches through the MCP server, using what discovery found to pick indexes, sourcetypes, and hosts.

- **Layout**: chat opens as a Chat tab. On wide screens, a side column next to the conversation holds the goal and **In this chat**. The window button in the chat header shows chat in a window instead, and the app remembers your choice
- **Answers**: replies are formatted with headings, lists, tables, and code. The search that ran, the steps taken, charts, and evidence sit behind buttons under each reply, and a suggested next action runs as soon as you select it. Each reply has **Copy**, the download button in the chat header saves the whole chat as Markdown, and **Stop** ends an answer early
- **In this chat**: lists each question with the search it ran. Jump back to an answer, open its search or chart, copy the search, or open it in Splunk. **Data searched** shows the indexes, sourcetypes, and hosts the answers searched; select one to add it to your message
- **Goals**: type what you want to find out and select **Set goal**. The AI model breaks the goal into 3 to 6 questions that settle it and suggests the first questions to ask. **Start on this goal** sends a first message that runs the first search
- **Progress**: after each answer, the app checks which tracked questions the answer settled (only answers backed by search evidence count), may add up to 2 new open questions, and refreshes the suggestions. The goal bar shows progress such as "1 of 4 answered" and opens a checklist you can tick by hand, with **Plan again** and **Check progress now**
- **Goal Library**: add, rename, rewrite, finish, and delete goals; edit the tracked questions; and open, rename, and delete the chats saved under each goal. Each recorded answer saves the chat under its goal
- **Chat Settings** (gear icon in the chat header): each setting starts as Auto, from the AI model's tuning, and becomes Custom when you change it. Custom values stay across restarts and are cleared when the AI model changes. **Reset all to Auto** clears them
- **Search the Knowledge Base**: when it is on, chat adds matching Knowledge Base passages and downloaded Splunk documentation, with links, to its answers

Goals and saved chats are kept per user when sign-in is on and in one shared library when it is off, under `output/chat_data/`.

![Chat answer with its search and next action, and In this chat listing the question, the search it ran, and the data searched](docs/screenshots/chat-conversation-current.png)

![Chat with a goal, its progress checklist, and the next questions for the goal in the side column](docs/screenshots/chat-goal-current.png)

![Goal Library with a goal, its tracked questions, and a saved chat](docs/screenshots/chat-goal-library-current.png)

![Chat Settings showing Auto values that come from the AI model's tuning](docs/screenshots/chat-settings-current.png)

## 🕶️ Incognito Mode

Incognito mode keeps your own names away from the AI model. When it is on, host names, IP addresses, users, custom indexes, apps, saved searches, and similar values are replaced with stand-ins such as `host_0012` before anything is sent, and the real names are put back in the reply. Splunk's own indexes, sourcetypes, fields, and apps stay visible.

- **Turn it on** with **Incognito** in the top bar. Each user has their own choice when sign-in is on
- **Admins** can turn it on by default, require it while a cloud AI model is in use (the server enforces the lock), add terms to always or never replace, preview the result, and reset the stand-ins, on the Settings **Security** tab
- **What the AI saw** under each answer shows the exact masked text that was sent. Only the person who asked can open it
- **Nothing leaks silently**: if a known name would still be sent, the request stops and nothing goes to the AI model
- **Share with stand-ins**: download a chat or a text report with stand-ins in place of real names, even when incognito mode is off
- Chat, chat goals, discovery analysis, AI summaries, task verification, remediation, the M-26-14 AI Review, and infographics all use it. The stand-in mapping is encrypted and never leaves the server

See [docs/INCOGNITO_MODE.md](docs/INCOGNITO_MODE.md) for what is replaced, how requests are protected, and the limits.
## 📚 Knowledge Library and Splunk Documentation

Library health on the Knowledge Base tab scores how well reference sources cover the environment from your latest discovery and lists gaps with a next action (missing or turned-off add-ons, outdated or archived apps, apps not marked Cloud compatible, and busy sourcetypes no public reference describes).

- **Sources**: Splunk Security Content data sources, Splunkbase records for your installed apps, and the help.splunk.com documentation index
- **Documentation**: **Download documentation** saves the help.splunk.com manuals for your platform version and installed apps (up to 8,000 pages) into a local search index. Downloads are slow on purpose and stop when the site refuses requests. Chat uses the pages only when Search the Knowledge Base is on
- **Online sources are off by default**. An admin turns on **Download sources from the internet** under Sources. Requests go only to `api.github.com`, `raw.githubusercontent.com`, `splunkbase.splunk.com`, and `help.splunk.com` over HTTPS
- **Servers without internet access**: **Export library pack** on a connected server and **Import library pack** on the offline one (up to 100 MB, checked before anything is saved)
- The documentation has its own index, so it never needs a Knowledge Base reindex. When the Knowledge Base is installed and turned on, discovery updates its index after saving reports and the report catalog; AI summaries update it again after saving. Documents you import are indexed when you import them. **Reindex needed** can still appear before the first index, after other file changes, after an automatic update fails, or when the index uses an older format. Select **Reindex** to rebuild or retry. An indexing failure does not discard saved discovery results; the discovery log or summary progress explains that the update needs attention

## 📸 Current Workspace Snapshots

### First-run splash and workspace shell

![Current Splunk Discovery Tool welcome screen and workspace](docs/screenshots/welcome-splash-current.png)

### Overview tab

![Overview tab showing discovery status, key numbers, and the top next steps](docs/screenshots/workspace-overview-current.png)

### Findings tab

![Findings tab showing next steps for each audience, the environment profile, and key evidence](docs/screenshots/workspace-findings-current.png)

### Discovery tab

![Discovery tab showing the run status, a formatted Insights brief with its SPL, and the report library](docs/screenshots/workspace-discovery-current.png)

## 📸 SPL Library Workflow

The SPL Library keeps reusable SPL in the managed context workspace so operators can save good queries from chat, inspect stored context, and reuse saved SPL without leaving the tool.

### Save a Query From Chat

![Save a chat-generated SPL query to the SPL Library](docs/screenshots/spl-library-save-from-chat.png)

### Browse the SPL Library

![SPL Library listing in the Knowledge Base tab](docs/screenshots/spl-library-listing.png)

### Inspect Stored Asset Detail

![SPL Library asset detail view with stored sections and chunk browser](docs/screenshots/spl-library-detail.png)

### Reuse Library Context in Chat

![Chat response showing SPL Library context and reusable SPL evidence](docs/screenshots/spl-library-chat-context.png)

## 🔐 Security

- Sign-in is off after install, and anyone who can reach the app can use it until an admin turns it on
- Optional local username/password sign-in with a password reset on first login
- OIDC sign-in with provider metadata, claim mapping, and local-user linking support
- Per-user MCP assignment plus admin-managed connection, user, and token controls
- Read-only external RAG REST API and inbound MCP access with scoped tokens and rate limiting
- Chat goals and saved chats are kept per user when sign-in is on
- Credentials encrypted at rest (`config.encrypted`, `.config.key`); no plaintext secrets are stored, and troubleshooting reports hide tokens and keys
- Configurable SSL verification and CA bundle support
- Host/CORS protections available via server settings
- Knowledge library downloads are off until an admin turns them on, and reach only four allowed HTTPS hosts
- Incognito mode replaces your names with stand-ins before anything reaches the AI model; admins can require it while a cloud AI model is in use

## 📁 Key Paths

```text
install.ps1 / install.sh        Installer + service control
src/main.py                     Runtime entrypoint
src/app_version.py              Release version
src/web_app.py                  FastAPI API + frontend delivery/runtime orchestration
src/frontend_legacy_template.html Source-of-truth frontend template
src/frontend_legacy.py          Frontend template loader for runtime and build tooling
src/static/                     Shipped local frontend bundle (built, checked in)
src/discovery/                  Discovery engine, v2 pipeline, and environment profile
src/chat_agent.py               Grounded chat prompts, tool outcomes, and evidence
src/chat_settings.py            Chat settings with Auto values from the model's tuning
src/chat_goals.py               Chat goals, tracked questions, and saved chats
src/incognito/                  Incognito mode: stand-ins, masking, and records of what the AI saw
src/llm/                        AI provider clients, model profiles, and auto-tuning
src/knowledge_library/          Library sources, documentation index, ranking, and scorecard
src/capabilities/               Optional capabilities (Knowledge Base, exports, charts, links, M-26-14)
src/troubleshooting.py          Settings > Troubleshoot checks
src/config_manager.py           Encrypted config manager
src/security_manager.py         Local auth, OIDC, sessions, roles, and token management
src/runtime_job_worker.py       Detached worker entrypoint for durable discovery/summary jobs
tools/build_frontend.mjs        Rebuild shipped frontend assets from src/frontend_legacy_template.html
tools/check_frontend_sync.py    Validate frontend bundle sync before release
tools/test_*_browser.mjs        Browser regression suites (Playwright)
tools/run_account_function_tests.mjs Account/auth regression entrypoint
.github/workflows/repo-validation.yml  GitHub Actions validation workflow for repo quality gates
output/                         Discovery reports, summaries, chat data, the knowledge library, and incognito files
```

## 📚 Documentation

- [CHANGELOG.md](CHANGELOG.md): release history, highlights, and upgrade notes
- [CONFIGURATION_VARIABLES.md](CONFIGURATION_VARIABLES.md): settings, limits, defaults, and routes
- [docs/DEVELOPER_REFERENCE.md](docs/DEVELOPER_REFERENCE.md): code layout, extension points, and the endpoint map
- [docs/DISCOVERY_ARCHITECTURE_GUIDE.md](docs/DISCOVERY_ARCHITECTURE_GUIDE.md): discovery artifacts, the workspace model, and chat architecture
- [docs/OPTIONAL_CAPABILITIES_ARCHITECTURE.md](docs/OPTIONAL_CAPABILITIES_ARCHITECTURE.md): the optional capability model (Knowledge Base, exports, charts, links, capability tabs)
- [docs/SECURITY_ACCESS_ROADMAP.md](docs/SECURITY_ACCESS_ROADMAP.md): the shipped security model plus extension notes
- [docs/INCOGNITO_MODE.md](docs/INCOGNITO_MODE.md): incognito mode, what it replaces, admin settings, and shareable copies
- [docs/AUTH_TESTING.md](docs/AUTH_TESTING.md): local-password, OIDC, and account-function test guidance
- [docs/EXTERNAL_RAG_API_QUICKSTART.md](docs/EXTERNAL_RAG_API_QUICKSTART.md): read-only external RAG API setup and examples
- [docs/EXTERNAL_MCP_QUICKSTART.md](docs/EXTERNAL_MCP_QUICKSTART.md): inbound MCP setup, helper client, and stdio bridge usage
- [docs/M-26-14/](docs/M-26-14/): the M-26-14 Readiness Advisor plan and development ledger

## ✅ Validation

From an activated virtual environment with the dev requirements (`pip install -r requirements-dev.txt`) and the Node packages (`npm ci`, then `npx playwright install chromium` once), the release checks are:

```bash
npm run build:frontend
python tools/check_frontend_sync.py
npm run test:browser
npm run test:settings-profiles-browser
npm run test:settings-troubleshoot-browser
npm run test:ui-contrast-browser
npm run test:auth-browser
npm run test:account-functions
python -m ruff check src tests
python -W error::SyntaxWarning -m compileall -q src tests
python -m unittest discover -v
```

GitHub Actions runs the same checks on Ubuntu and Windows for every push and pull request (`.github/workflows/repo-validation.yml`).
## 🛠️ Installer Commands

| Command | Description |
|---------|-------------|
| `(no arguments)` | Install dependencies and start service |
| `--public_only` / `-PublicOnly` | Install using public PyPI only (skip private/local indexes) |
| `--start` / `-Start` | Start service |
| `--stop` / `-Stop` | Stop service |
| `--restart` / `-Restart` | Restart service |
| `--status` / `-Status` | Show status |
| `--uninstall` / `-Uninstall` | Uninstall |
| `--help` / `-Help` | Show help |

## 🐛 Troubleshooting

### Saving or connecting fails: use Settings > Troubleshoot

Open **Settings > Troubleshoot**, pick **MCP Server** or **AI Provider**, enter the values that fail, and click **Run Checks**. Nothing is saved. The checks run in stages and explain what to fix:

- **App and server**: whether the running server still uses the code in the install folder, missing Python packages, other copies of the app on ports 8003-8023, and whether your account may save settings
- **Values entered**: the same validation the save uses, URL mistakes (Splunk Web port 8000 instead of 8089, `http` on 8089, missing `/services/mcp`), pasted `Bearer ` prefixes or spaces, expired tokens, and CA bundle files
- **Saving**: where settings are stored, folder permissions and disk space, whether the settings file opens with its key, and a test save to a temporary copy
- **Network**: proxy, DNS, TCP, and TLS certificate trust (including Splunk's self-signed certificate)
- **Response**: what the MCP server or AI provider answered (401, 403, 404, web pages instead of MCP, tool count, model errors)

The **Troubleshoot** buttons next to **Test Connection** carry the values from the form, and a failed save or test offers to open the troubleshooter. **Copy Report** copies a plain-text report with tokens and keys hidden, which you can send with a support request.

### Saves still fail after `git pull`

The browser loads the new pages as soon as the files change, but the server keeps running the old code until it restarts, so fixes don't take effect and new pages can fail against the old server. Settings shows a banner when this happens. Restart from the install folder:

```bash
./install.sh --restart
```

```powershell
.\install.ps1 -Restart
```

The installers reinstall Python packages when `requirements.txt` changes, warn when the running service is older than the files, always start the app from the install folder (settings, keys, and output are stored there), and print the port the app actually uses.

### Port 8003 is already in use, or the banner stays after a restart

The app moves to the next free port automatically, and the installer prints the address it uses. A copy of the app installed earlier in another folder keeps answering on its port with its own code, so a bookmark for `http://<host>:8003` reaches that copy, and restarting the new install doesn't change it. When the server is out of date, the Settings banner names its port and links to an up-to-date copy if one is running on a nearby port. The installers list the other copies with their process IDs and folders after starting, and with `--status` / `-Status`:

```text
⚠ Other programs are using the app's ports on this computer:
    port 8003: another copy of the app (PID 21079), started from /home/me/old-folder
  To run only this copy: kill 21079 && ./install.sh --restart
```

Run the printed command in the folder of the copy you want to keep, so that copy moves back to port 8003. On Windows the command uses `Stop-Process -Id <PID>; .\install.ps1 -Restart`.

### Windows script execution blocked

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### MCP connection errors

- Run **Settings > Troubleshoot** with the URL and token
- For private certificate chains, turn on **Verify SSL Certificate** and enter the path of a `.pem` file on the app server in **CA Bundle File**, or turn verification off for a self-signed lab server

### AI provider certificate errors

**Fetch Models** or **Test Connection** fails with `CERTIFICATE_VERIFY_FAILED` (for example `unable to get local issuer certificate`):

- AI requests trust both Python's system certificate store and the bundled public CAs. In version 2.0.0 and earlier, **Fetch Models** and the **Test Connection** probe used only the bundled list, so update to version 2.0.1 or later and restart (`./install.sh --restart` or `.\install.ps1 -Restart`)
- Run **Settings > Troubleshoot** with **AI Provider**. Its TLS check uses the same certificate trust as the AI requests
- If the error remains, your network probably inspects HTTPS with a company CA. Ask IT for the CA bundle as a PEM file and start the app with it:

```bash
SSL_CERT_FILE=/path/to/company-ca.pem ./install.sh --restart
```

```powershell
$env:SSL_CERT_FILE = "C:\path\to\company-ca.pem"; .\install.ps1 -Restart
```

`SSL_CERT_FILE` (or `SSL_CERT_DIR` for a folder of certificates) replaces the default trust, so the file must include every CA the app needs. It also applies to other outbound HTTPS that uses the default trust, such as knowledge library downloads and MCP servers without a CA bundle. Don't turn off certificate verification for AI providers; there is no setting for it.

### pip install timeout / `repo.splunkdev.net` unreachable

- Some systems have a global/private pip index configured; if that index is unavailable, dependency install can time out.
- The installers now retry automatically against public PyPI (`https://pypi.org/simple`).
- To bypass private/local indexes immediately, use the installer public-only flag:

```bash
./install.sh --public_only
```

```powershell
.\install.ps1 -PublicOnly
```

- If needed, force PyPI for the current shell session before reinstall:

```bash
export PIP_INDEX_URL=https://pypi.org/simple
./install.sh
```

```powershell
$env:PIP_INDEX_URL = "https://pypi.org/simple"
.\install.ps1
```

### Frontend changes are not showing up or startup warns about stale assets

- The shipped UI is served from checked-in files under `src/static/`.
- After editing the frontend source template in `src/frontend_legacy_template.html`, rebuild and verify the shipped bundle:

```bash
npm run build:frontend
python tools/check_frontend_sync.py
```

- To run the deterministic browser regression for visualization previews, install the Chromium test browser once and run:

```bash
npx playwright install chromium
npm run test:browser
```

- To check saving, loading, testing, and deleting MCP configurations in Settings (including names with quotes, slashes, and `#`), and the Troubleshoot tab, run:

```bash
npm run test:settings-profiles-browser
npm run test:settings-troubleshoot-browser
```

- To validate auth-enabled flows and the account-function matrix, run:

```bash
npm run test:auth-browser
npm run test:account-functions
```

## 🤝 Contributing

Contributions are welcome via pull requests. Repo validation is also mirrored in `.github/workflows/repo-validation.yml`, which runs the documented frontend build, sync, browser regression, auth/account checks, lint, compile, and unittest gates on GitHub-hosted runners.

## 📄 License

MIT. See [LICENSE](LICENSE).
