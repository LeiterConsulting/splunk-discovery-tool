# DT4SMS Developer Reference (V2)

This reference is for developers repurposing the demo into production or custom projects.

## 1) Runtime Topology

- Entry point: src/main.py
- Web app + API + embedded frontend: src/web_app.py
- Discovery orchestration:
  - Legacy: src/discovery/engine.py
  - V2 primary pipeline: src/discovery/v2_pipeline.py
- LLM abstraction: src/llm/factory.py
- Config and encrypted credentials: src/config_manager.py

## 2) Discovery V2 Flow (Recursive)

The V2 pipeline executes in these phases:

1. Signal capture
   - get_quick_overview()
2. Evidence collection
   - discover_environment() yields step-level findings
3. Intelligence synthesis
   - classify_data()
   - generate_recommendations()
   - generate_suggested_use_cases()
4. Artifact packaging
   - v2_intelligence_blueprint_<ts>.json
   - v2_insights_brief_<ts>.md
   - v2_operator_runbook_<ts>.md
   - v2_developer_handoff_<ts>.md
5. Session summarization (on demand)
   - POST /summarize-session
   - cached output: v2_ai_summary_<ts>.json

### Extension points

- Add a new synthesis stage in DiscoveryV2Pipeline.run()
- Add a new block to _build_v2_payload()
- Add a new artifact writer in _export_v2_bundle()

## 3) Chat with Splunk (Recursive)

Chat strategy combines deterministic and agentic logic:

1. Deterministic intent routes (preferred for common/demo asks)
   - detect_basic_inventory_intent()
   - route handlers in chat_with_splunk_logic()
2. Deterministic domain skills
   - edge processor templates
   - latest offline event lookup
   - latest index event lookup
3. Optional local RAG
   - build_lightweight_rag_context()
4. LLM agentic loop fallback
   - compact prompt + tool-call parser + iterative execution

### Add a new deterministic intent

1. Update detect_basic_inventory_intent()
2. Add handler branch in chat_with_splunk_logic()
3. Return structured timeline/tool summaries for UI feedback
4. Add a Suggested Query in UI for demo discoverability

## 4) MCP Integration

Core contracts:

- Tool discovery: discover_mcp_tools()
- Tool alias resolution: resolve_tool_name()
- Argument normalization: normalize_tool_arguments()
- Execution: execute_mcp_tool_call()

### Guidance

- Preserve alias maps for compatibility with tool naming differences
- Keep tool output normalization centralized (extract_results_from_mcp_response)
- Include status_code and error_message handling for robust UX

## 5) LLM Integration

LLM flow:

- get_or_create_llm_client() caches by config hash
- Chat pipeline uses compact reliability-first prompt
- Tool-call extraction supports JSON and python-like dict fallback

### Guidance

- Keep deterministic paths for high-value queries
- Reserve free-form agentic behavior for exploratory questions
- Track and expose reasoning timeline to users for transparency

## 6) Settings Surface (Preserved)

Requirement: preserve MCP + LLM settings behavior.

- Existing settings API endpoints should remain stable
- Existing credential load/save/update semantics should remain stable
- Visual refresh is allowed; function contract should not change

## 7) Frontend Feedback Principle

Every button should communicate purpose:

- Use title and icon hints
- Show immediate status/disabled state for long-running actions
- Return timeline + follow-on suggestions for investigation flows

## 8) Workspace Endpoint Map (Current)

- `GET /api/discovery/dashboard` → Mission intelligence cards
- `GET /api/discovery/compare` → Session delta metrics
- `GET /api/discovery/runbook` → Persona runbook payload
- `GET /api/v2/intelligence` → Latest blueprint payload
- `GET /api/v2/artifacts` → V2 artifact catalog
- `GET /reports` → V2 report/session list

## 9) Build-Your-Own Checklist

- Replace discovery recommendation logic with domain controls
- Add custom deterministic intents for your data model
- Create role-specific runbooks from V2 blueprint
- Add org-specific KPI cards over capability_graph and finding_ledger
- Keep settings contract stable for operator familiarity
