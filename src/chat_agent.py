"""Pure helpers for the grounded Splunk chat agent.

Nothing in this module talks to Splunk or to an LLM. It turns user input,
discovered MCP tool metadata and MCP tool results into prompt text, compact
evidence and normalized outcomes so the chat loop in ``web_app`` stays small
and every rule here can be unit tested.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from mcp_tool_args import parse_jsonrpc_error

__all__ = [
    "MAX_MISSION_CHARS",
    "announces_unexecuted_search",
    "build_grounded_chat_prompt",
    "build_tool_catalog_text",
    "build_tool_feedback",
    "classify_tool_result",
    "format_mission_context",
    "index_agnostic_signature",
    "is_small_talk",
    "normalize_mission",
    "render_rows_for_llm",
    "summarize_remaining_rows",
    "tool_call_signature",
]

MAX_MISSION_CHARS = 600

_SMALL_TALK_PHRASES = tuple(
    sorted(
        (
            "hi",
            "hello",
            "hey",
            "hiya",
            "howdy",
            "yo",
            "good morning",
            "good afternoon",
            "good evening",
            "thanks",
            "thank you",
            "thx",
            "ty",
            "cheers",
            "bye",
            "goodbye",
            "see you",
            "how are you",
            "how are you doing",
            "whats up",
            "what's up",
        ),
        key=lambda phrase: len(phrase.split()),
        reverse=True,
    )
)
_SMALL_TALK_FILLERS = frozenset(
    {
        "there", "team", "all", "again", "so", "much", "a", "lot", "very", "you",
        "and", "ok", "okay", "great", "cool", "awesome", "nice", "today", "for", "that", "the", "help",
    }
)


def is_small_talk(message: Any) -> bool:
    """Return True only when the whole message is a greeting, thanks or farewell.

    Substring checks misfire on ordinary words ("this" contains "hi"), so the
    message must start with a known phrase and contain nothing else but filler.
    """

    text = re.sub(r"[^a-z0-9' ]+", " ", str(message or "").lower()).strip()
    if not text:
        return False
    words = text.split()
    if len(words) > 6:
        return False
    for phrase in _SMALL_TALK_PHRASES:
        phrase_words = phrase.split()
        if words[: len(phrase_words)] == phrase_words:
            return all(word in _SMALL_TALK_FILLERS for word in words[len(phrase_words):])
    return False


_ANNOUNCED_SEARCH_RE = re.compile(
    r"\b(?:let me|i(?:'ll| will| am going to|'m going to)|now i(?:'ll| will))\s+"
    r"(?:now\s+|quickly\s+|first\s+|go ahead and\s+)?"
    r"(?:run|execute|query|search|check|look up|pull|fetch|retrieve)\b",
    re.IGNORECASE,
)


def announces_unexecuted_search(text: Any, max_chars: int = 600) -> bool:
    """True when a short reply promises to run a search instead of answering.

    Long replies are treated as answers even when they mention a next search.
    """

    cleaned = str(text or "").strip()
    if not cleaned or len(cleaned) > max_chars:
        return False
    return bool(_ANNOUNCED_SEARCH_RE.search(cleaned))


def normalize_mission(value: Any) -> str:
    """Clean a user-supplied mission statement for prompt use."""

    if not isinstance(value, str):
        return ""
    cleaned = "".join(char if char.isprintable() else " " for char in value)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if len(cleaned) > MAX_MISSION_CHARS:
        cleaned = cleaned[: MAX_MISSION_CHARS - 3].rstrip() + "..."
    return cleaned


def format_mission_context(mission: Any, progress: Optional[Mapping[str, Any]] = None) -> str:
    """The user's goal for the chat prompt, with what is settled and still open when the goal is tracked."""
    mission_text = normalize_mission(mission)
    if not mission_text:
        return ""
    progress = progress if isinstance(progress, Mapping) else {}

    def _items(key: str) -> List[str]:
        values = progress.get(key) if isinstance(progress.get(key), (list, tuple)) else []
        cleaned = [normalize_mission(value)[:240] for value in values]
        return [value for value in cleaned if value][:5]

    settled = _items("answered")
    still_open = _items("open")
    lines = ["USER GOAL (the outcome the user is working toward in this chat):", mission_text]
    if settled:
        lines.append("Settled so far:")
        lines.extend(f"  * {value}" for value in settled)
    if still_open:
        lines.append("Still open:")
        lines.extend(f"  * {value}" for value in still_open)
    lines.append("- Keep searches, answers, and suggested next steps aligned with this goal.")
    if still_open:
        lines.append("- When the user asks to start or continue, work on the first open question; do not redo settled ones unless asked.")
    lines.append("- If a request is unrelated to the goal, still help with it; do not force the goal into the answer.")
    return "\n".join(lines)


def _first_sentence(text: str, limit: int = 180) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    if not cleaned:
        return ""
    match = re.match(r"(.+?[.!?])(?:\s|$)", cleaned)
    sentence = match.group(1) if match else cleaned
    if len(sentence) > limit:
        sentence = sentence[: limit - 3].rstrip() + "..."
    return sentence


def _schema_argument_hint(schema: Any) -> str:
    if not isinstance(schema, Mapping):
        return ""
    properties = schema.get("properties")
    if not isinstance(properties, Mapping) or not properties:
        return ""
    required = set(schema.get("required") or [])
    parts: List[str] = []
    for name, spec in list(properties.items())[:8]:
        label = f"{name}*" if name in required else str(name)
        if isinstance(spec, Mapping) and isinstance(spec.get("enum"), list) and len(spec["enum"]) <= 6:
            label += "=" + "|".join(str(item) for item in spec["enum"])
        parts.append(label)
    return f" Args: {', '.join(parts)}" if parts else ""


def build_tool_catalog_text(
    tool_names: Iterable[str],
    descriptions: Optional[Mapping[str, str]] = None,
    fallback_descriptions: Optional[Mapping[str, str]] = None,
    schemas: Optional[Mapping[str, Any]] = None,
    primary_order: Sequence[str] = (),
) -> str:
    """Render the live tool list (server descriptions first) for the system prompt."""

    names = [str(name) for name in tool_names if isinstance(name, str) and name.strip()]
    ordered = [name for name in primary_order if name in names]
    ordered.extend(sorted(name for name in names if name not in ordered))
    descriptions = descriptions or {}
    fallback_descriptions = fallback_descriptions or {}
    schemas = schemas or {}
    lines = []
    for name in ordered:
        description = _first_sentence(descriptions.get(name) or fallback_descriptions.get(name) or "MCP tool for Splunk operations.")
        lines.append(f"- {name}: {description}{_schema_argument_hint(schemas.get(name))}")
    return "\n".join(lines)


def build_grounded_chat_prompt(
    *,
    query_tool_name: str,
    available_tools_text: str,
    discovery_context: str = "",
    rag_context: str = "",
    memory_context: str = "",
    discovery_age_warning: Optional[str] = None,
    mission: Any = "",
    goal_progress: Optional[Mapping[str, Any]] = None,
    blocked_commands: Iterable[str] = (),
    max_tool_steps: int = 5,
) -> str:
    """Full system prompt for models with enough context for detailed guidance."""

    mission_block = format_mission_context(mission, goal_progress)
    blocked = ", ".join(sorted(blocked_commands)) or "write, export, alert, or script commands"
    context_sections = [
        section.strip()
        for section in (discovery_context, rag_context, discovery_age_warning or "", memory_context)
        if isinstance(section, str) and section.strip()
    ]
    environment_context = "\n\n".join(context_sections) or "No discovery context is loaded yet. Use tools to look things up, and suggest running a discovery for a full environment picture."

    return f"""You are the Splunk Discovery Tool assistant. You help the user understand and work with their own Splunk data through the Splunk MCP server. Be supportive and practical: explain clearly, show your evidence, and suggest the next useful step.
{chr(10) + mission_block + chr(10) if mission_block else ''}
HOW TO WORK
1. Decide whether the request needs live Splunk data. Concept questions, SPL help, and general questions can be answered directly without tools.
2. When live data is needed, make one tool call at a time and wait for its result. Never say you are about to run a search without including the TOOL_CALL in the same reply.
3. Ground every environment-specific statement (index names, counts, hosts, sourcetypes, timestamps, health) in tool results or the ENVIRONMENT CONTEXT below. If you have no evidence, say so and offer to check. Do not claim that all or every host, target, or source is covered unless the evidence includes the expected list; otherwise report what was observed and what would confirm completeness.
4. Use only index, sourcetype, and host names that appear in the context or in earlier results. If you need a name you do not know, look it up first.
5. Keep searches efficient and read-only:
   - Always set earliest_time and latest_time in the tool args. Start with the user's window, or -24h if none was given, and widen only when needed.
   - Prefer tstats, stats, and timechart aggregations. Cap raw-event searches with head.
   - Never use commands that write, export, alert, or run scripts ({blocked}). They are rejected before they reach Splunk.
6. If a search fails, read the error, fix the SPL, and retry once. If it returns no rows, tell the user exactly what was searched and over which window, and try at most one sensible broadening (for example index=* rather than repeating the search one index at a time). Zero matches only means nothing matched that search; never present it as proof that a system is healthy or broken. Event totals and index sizes do not show whether data is recent; judge freshness only from latest-event times or time-bounded searches.
7. If the request is ambiguous and a quick lookup cannot resolve it, ask one short clarifying question.
8. You have at most {max_tool_steps} tool steps for one request, so plan the shortest path to an answer.

TOOL CALL FORMAT (one per reply, valid JSON inside the tags, escape double quotes inside SPL as \\"):
<TOOL_CALL>{{"tool": "{query_tool_name}", "args": {{"query": "| tstats count where index=* by index", "earliest_time": "-24h", "latest_time": "now"}}}}</TOOL_CALL>
SPL that you show in ```spl code fences is a suggestion for the user and is never executed.

ANSWER STYLE
- Lead with the direct answer, using the actual numbers and values from the results.
- When you used data, say which SPL ran and over what time range.
- Be concise. Use a short list or a small table when it helps.
- When useful, end with one or two concrete next steps (a refinement, a pivot, or a check).

AVAILABLE TOOLS
{available_tools_text}

ENVIRONMENT CONTEXT
{environment_context}

If reusable SPL candidates appear in the context, adapt the best-matching known-good query before writing a new one."""


# ---------------------------------------------------------------------------
# MCP tool arguments and results
# ---------------------------------------------------------------------------

def _content_texts(result: Mapping[str, Any]) -> List[str]:
    content = result.get("content")
    texts: List[str] = []
    if isinstance(content, list):
        for item in content:
            if isinstance(item, Mapping) and isinstance(item.get("text"), str) and item["text"].strip():
                texts.append(item["text"].strip())
    return texts


_NUMERIC_RE = re.compile(r"\s*-?\d+(?:\.\d+)?\s*")


def _is_numeric_value(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    return isinstance(value, str) and bool(_NUMERIC_RE.fullmatch(value))


def _is_zero_value(value: Any) -> bool:
    try:
        return float(str(value).strip()) == 0.0
    except (TypeError, ValueError):
        return False


def classify_tool_result(mcp_result: Any) -> Dict[str, Any]:
    """Normalize any MCP tool response into one outcome record.

    ``status`` is ``error``, ``no_data`` or ``data``. ``rows`` holds result
    rows, ``text`` holds free-text output (for tools that return prose),
    ``total_rows``/``truncated`` reflect server-side paging, and
    ``zero_counts`` is True when every numeric value in the rows is zero.
    """

    outcome: Dict[str, Any] = {
        "status": "no_data",
        "rows": [],
        "row_count": 0,
        "total_rows": None,
        "truncated": False,
        "text": "",
        "error": "",
        "status_code": None,
        "fatal": False,
        "zero_counts": False,
    }
    if not isinstance(mcp_result, Mapping):
        outcome.update(status="error", error="The MCP server returned an unreadable response.")
        return outcome

    rpc_error = parse_jsonrpc_error(mcp_result)
    if rpc_error is not None or ("error" in mcp_result and "result" not in mcp_result):
        message = (rpc_error or {}).get("message") or str(mcp_result.get("error") or "MCP call failed")
        detail = mcp_result.get("detail")
        if isinstance(detail, str) and detail.strip() and detail.strip() not in message:
            message = f"{message}: {detail.strip()}"
        status_code = mcp_result.get("status_code")
        outcome.update(
            status="error",
            error=message[:1200],
            status_code=status_code if isinstance(status_code, int) else None,
            fatal=bool(mcp_result.get("fatal")),
        )
        return outcome

    result = mcp_result.get("result")
    if not isinstance(result, Mapping):
        outcome.update(status="error", error="The MCP response did not include a result.")
        return outcome

    texts = _content_texts(result)
    if result.get("isError"):
        outcome.update(status="error", error=("\n".join(texts) or "The tool reported an error without details.")[:1200])
        return outcome

    structured = result.get("structuredContent")
    payload: Any = None
    if isinstance(structured, Mapping):
        status_code = structured.get("status_code")
        if isinstance(status_code, int) and status_code >= 400:
            message = structured.get("content") if isinstance(structured.get("content"), str) else ""
            outcome.update(status="error", status_code=status_code, error=(message or "\n".join(texts) or f"Tool failed with status {status_code}")[:1200])
            return outcome
        payload = structured
    elif isinstance(result.get("results"), list):
        payload = result

    if payload is None and texts:
        try:
            parsed = json.loads(texts[0])
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, Mapping):
            payload = parsed
        elif isinstance(parsed, list):
            payload = {"results": parsed}

    rows: List[Any] = []
    if isinstance(payload, Mapping):
        if isinstance(payload.get("results"), list):
            rows = list(payload["results"])
        elif payload and not any(key in payload for key in ("content", "status_code")):
            rows = [dict(payload)]
        total = payload.get("total_rows")
        if isinstance(total, int):
            outcome["total_rows"] = total
        outcome["truncated"] = bool(payload.get("truncated"))
    elif texts:
        outcome["text"] = "\n".join(texts)[:4000]

    outcome["rows"] = rows
    outcome["row_count"] = len(rows)
    if rows:
        outcome["status"] = "data"
        all_numeric_rows = all(
            isinstance(row, Mapping) and row and all(_is_numeric_value(value) for value in row.values())
            for row in rows
        )
        outcome["zero_counts"] = all_numeric_rows and all(
            _is_zero_value(value) for row in rows for value in row.values()
        )
    elif outcome["text"]:
        outcome["status"] = "data"
    return outcome


_NOISY_FIELDS = frozenset(
    {
        "_bkt", "_cd", "_si", "_serial", "_indextime", "_sourcetype", "_eventtype_color",
        "_kv", "_subsecond", "linecount", "punct", "splunk_server", "splunk_server_group",
        "timestartpos", "timeendpos", "date_hour", "date_mday", "date_minute", "date_month",
        "date_second", "date_wday", "date_year", "date_zone", "timestamp",
    }
)


def _clip_value(value: Any, limit: int) -> Any:
    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 3] + "..."
    if isinstance(value, list):
        clipped = [_clip_value(item, limit) for item in value[:10]]
        if len(value) > 10:
            clipped.append(f"... {len(value) - 10} more")
        return clipped
    return value


def render_rows_for_llm(
    rows: Sequence[Any],
    max_rows: int = 10,
    max_chars: int = 6000,
    max_value_chars: int = 300,
) -> Tuple[str, int]:
    """Render result rows as compact JSON lines within a character budget.

    Returns ``(text, rows_shown)``. Splunk bookkeeping fields are dropped and
    long values are clipped so one wide event cannot crowd out the others.
    """

    lines: List[str] = []
    used = 0
    for row in list(rows or [])[: max(1, int(max_rows))]:
        if isinstance(row, Mapping):
            compact = {
                str(key): _clip_value(value, 600 if key == "_raw" else max_value_chars)
                for key, value in row.items()
                if str(key) not in _NOISY_FIELDS and value not in (None, "")
            }
            line = json.dumps(compact, default=str, ensure_ascii=False)
        else:
            line = json.dumps(_clip_value(row, max_value_chars), default=str, ensure_ascii=False)
        if lines and used + len(line) + 1 > max_chars:
            break
        if len(line) > max_chars:
            line = line[: max(0, max_chars - 3)] + "..."
        lines.append(line)
        used += len(line) + 1
    return "\n".join(lines), len(lines)


_ROW_KEY_FIELDS = ("title", "name", "index", "sourcetype", "host", "source", "label", "app", "user")


def summarize_remaining_rows(rows: Sequence[Any], shown: int, max_chars: int = 1500) -> str:
    """List the identifying value of each row that did not fit in the evidence.

    Inventory results (indexes, hosts, sourcetypes) often have more rows than the
    evidence budget allows; without their names the model concludes an item is missing.
    """

    remaining = [row for row in list(rows or [])[max(0, int(shown)):] if isinstance(row, Mapping)]
    if not remaining:
        return ""
    key = next((field for field in _ROW_KEY_FIELDS if any(row.get(field) not in (None, "") for row in remaining[:5])), None)
    if key is None:
        return ""
    values: List[str] = []
    used = 0
    for row in remaining:
        value = row.get(key)
        if value in (None, ""):
            continue
        rendered = str(value)[:80]
        if used + len(rendered) + 2 > max_chars:
            break
        values.append(rendered)
        used += len(rendered) + 2
    if not values:
        return ""
    omitted = len(remaining) - len(values)
    suffix = f" (+{omitted} more)" if omitted > 0 else ""
    return f"{key} of the {len(remaining)} rows not shown: {', '.join(values)}{suffix}"


def tool_call_signature(tool_name: str, args: Optional[Mapping[str, Any]]) -> str:
    """Stable identity for a tool call so the loop can skip exact repeats."""

    normalized: Dict[str, Any] = {}
    for key, value in sorted((args or {}).items()):
        # Case is kept: where/eval/regex comparisons are case-sensitive, so a
        # retry that only fixes case is a different search.
        if isinstance(value, str):
            value = " ".join(value.split())
        normalized[str(key)] = value
    return f"{tool_name}|{json.dumps(normalized, sort_keys=True, default=str)}"


_INDEX_TERM_PATTERN = re.compile(r"\bindex\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s|)\]]+)", re.IGNORECASE)


def index_agnostic_signature(tool_name: str, args: Optional[Mapping[str, Any]]) -> str:
    """Tool call identity that ignores which index is searched, to spot index-by-index sweeps."""

    normalized = dict(args or {})
    query = normalized.get("query")
    if isinstance(query, str):
        normalized["query"] = _INDEX_TERM_PATTERN.sub("index=?", query)
    if "index" in normalized:
        normalized["index"] = "?"
    return tool_call_signature(tool_name, normalized)


def build_tool_feedback(
    *,
    step: int,
    tool_name: str,
    args: Mapping[str, Any],
    outcome: Mapping[str, Any],
    evidence_rows: int,
    evidence_chars: int,
    analysis_brief: str = "",
    extra_context: str = "",
    explanation_requirement: str = "",
    remaining_steps: int = 0,
    notes: Sequence[str] = (),
) -> str:
    """Describe one tool result for the model, including the SPL that ran."""

    lines = [f"TOOL RESULT (step {step}) from {tool_name}"]
    query = args.get("query") if isinstance(args, Mapping) else None
    if isinstance(query, str) and query.strip():
        lines.append(f"SPL that ran: {query.strip()}")
        earliest = str(args.get("earliest_time") or "").strip()
        latest = str(args.get("latest_time") or "").strip()
        if earliest or latest:
            lines.append(f"Time range: {earliest or 'default'} to {latest or 'now'}")
    elif args:
        lines.append(f"Arguments: {json.dumps(dict(args), default=str)[:400]}")
    lines.extend(note.strip() for note in notes if isinstance(note, str) and note.strip())

    status = outcome.get("status")
    if status == "error":
        lines.append(f"Status: ERROR - {outcome.get('error') or 'unknown error'}")
        lines.append(
            "Fix the cause and retry once with a corrected TOOL_CALL. If it cannot be fixed (for example a missing "
            "index or a permission problem), explain the error to the user in plain language and suggest what to check."
        )
    elif status == "no_data":
        lines.append("Status: SUCCESS, 0 rows returned.")
        lines.append(
            "Either tell the user that nothing matched (state the SPL and time range), or try one sensible broadening "
            "(wider time range, fewer filters, or index=* instead of trying indexes one at a time) with a TOOL_CALL. "
            "Nothing matching is not evidence that the system is healthy or broken."
        )
    else:
        row_count = int(outcome.get("row_count") or 0)
        total_rows = outcome.get("total_rows")
        if row_count:
            count_text = f"{row_count} rows returned"
            if outcome.get("truncated") and isinstance(total_rows, int) and total_rows > row_count:
                count_text += f" (truncated; {total_rows} rows in total)"
            all_rows = outcome.get("rows") or []
            evidence_text, shown = render_rows_for_llm(all_rows, evidence_rows, evidence_chars)
            lines.append(f"Status: SUCCESS, {count_text}. Showing {shown}:")
            lines.append(evidence_text)
            remaining_text = summarize_remaining_rows(all_rows, shown, max(800, evidence_chars // 4))
            if remaining_text:
                lines.append(remaining_text)
            if outcome.get("zero_counts"):
                lines.append("Note: every numeric value is 0, so no matching events were counted.")
        else:
            text = str(outcome.get("text") or "")
            lines.append("Status: SUCCESS, text output:")
            lines.append(text[: max(200, evidence_chars)])

    if analysis_brief.strip():
        lines.append("Result analysis:")
        lines.append(analysis_brief.strip())
    if extra_context.strip():
        lines.append("Relevant context:")
        lines.append(extra_context.strip()[:1500])
    if explanation_requirement.strip():
        lines.append(explanation_requirement.strip())
    if remaining_steps > 0:
        lines.append(
            f"Next: if this answers the request, reply to the user now without a TOOL_CALL. Otherwise make exactly one "
            f"more TOOL_CALL ({remaining_steps} tool steps left)."
        )
    else:
        lines.append("No tool steps are left. Reply to the user now from the evidence above, without a TOOL_CALL.")
    return "\n".join(lines)
