# Splunk Discovery Tool: Assistant Instructions (v2.0.0)

## Project Overview
Splunk Discovery Tool finds what a Splunk environment contains through the Splunk MCP server, saves discovery reports, and answers questions in a chat grounded in live Splunk searches. It runs as a FastAPI app with a React browser UI, encrypted settings, and installers for Windows, macOS, and Linux.

## Architecture
- `src/main.py` starts the app (default port 8003, next free port if busy); `src/web_app.py` holds the API and serves the UI
- The UI source is `src/frontend_legacy_template.html` (over 1 MB). The shipped files in `src/static/` are built from it with `npm run build:frontend` and checked in; `python tools/check_frontend_sync.py` fails when they drift
- Discovery: `src/discovery/` (engine, v2 pipeline, environment profile) with durable jobs in `src/runtime_job_worker.py`
- Chat: `src/chat_agent.py` (grounded prompts and tool outcomes), `src/chat_settings.py` (Auto values from the model's tuning), `src/chat_goals.py` (goals, tracked questions, saved chats)
- AI models: `src/llm/` (provider clients, model profiles, auto-tuning, health)
- Optional capabilities: `src/capabilities/` (Knowledge Base, exports, charts, Splunk search links, M-26-14)
- Knowledge library: `src/knowledge_library/` (reference sources, documentation index, ranking, scorecard)
- Settings: `src/config_manager.py` (Fernet-encrypted, no plaintext secrets), `src/security_manager.py` (local sign-in, OIDC, roles, tokens), `src/troubleshooting.py`
- The release version is `APP_VERSION` in `src/app_version.py`

## Conventions
- Edit the UI only in the template, then rebuild `src/static/` and run the sync check
- UI text uses plain language: no "(s)" plurals, doubled words, listed jargon, or raw dates (`tests/test_ui_copy.py`), and every theme must meet WCAG AA contrast (`npm run test:ui-contrast-browser`)
- Never log, print, or commit tokens, keys, `config.encrypted`, `.config.key`, `security.db`, or `output/`
- Keep the settings API and saved-config format backward compatible; unknown config keys are ignored on load
- Record user-facing changes in `CHANGELOG.md` and keep the docs in `docs/` current

## Validation
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

## Quick Start
Run `./install.sh` (macOS/Linux) or `.\install.ps1` (Windows) to install and start the app, then open http://localhost:8003. Restart after code changes with `./install.sh --restart` or `.\install.ps1 -Restart`.
