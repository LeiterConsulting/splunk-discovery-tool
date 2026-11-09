"""Pure, dependency-free helpers for inspecting and repairing Splunk SPL.

These helpers are used before LLM-written SPL is handed to the Splunk MCP
``splunk_run_query`` tool. They never talk to Splunk; everything is a
deterministic string analysis so the functions can be unit tested in
isolation and imported from any layer of the application.

The parser is intentionally lightweight. It understands enough of SPL to
find top-level pipeline segments, subsearches (``[ ... ]``), quoted strings,
escapes and parenthesised boolean groups. Where SPL semantics are ambiguous
the safety checks err on the side of blocking.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

__all__ = [
    "BLOCKED_COMMANDS",
    "GENERATING_COMMANDS",
    "assess_spl_safety",
    "ensure_spl_time_bounds",
    "extract_json_payload",
    "extract_spl_entities",
    "normalize_query_tool_args",
    "scope_spl_to_index",
    "split_spl_pipeline",
    "validate_spl_against_environment",
]

# Commands that write data, send data elsewhere, or execute code. Any command
# whose name starts with "send" is blocked as well (see _is_blocked_command).
BLOCKED_COMMANDS = frozenset(
    {
        "collect",
        "crawl",
        "dbxoutput",
        "delete",
        "dump",
        "mcollect",
        "meventcollect",
        "outputcsv",
        "outputlookup",
        "outputtelemetry",
        "outputtext",
        "run",
        "runshellscript",
        "script",
        "sendalert",
        "sendemail",
        "sendresults",
        "summaryindex",
        "tscollect",
    }
)

# Commands that must be the first command of a pipeline (``| tstats ...``).
GENERATING_COMMANDS = frozenset(
    {
        "datamodel",
        "dbinspect",
        "dbxquery",
        "eventcount",
        "from",
        "gentimes",
        "inputcsv",
        "inputlookup",
        "loadjob",
        "makeresults",
        "mcatalog",
        "metadata",
        "metasearch",
        "mpreview",
        "msearch",
        "mstats",
        "pivot",
        "rest",
        "savedsearch",
        "tstats",
        "typeahead",
        "walklex",
    }
)

# Generating commands that are an error anywhere except the first position
# (unless they carry append=t). ``datamodel`` is excluded because it may also
# be used mid-pipeline.
_FIRST_ONLY_COMMANDS = GENERATING_COMMANDS - {"datamodel"}

# Commands that cannot start a pipeline because they need input events.
_NON_GENERATING_START_COMMANDS = frozenset(
    {
        "append",
        "appendcols",
        "bin",
        "bucket",
        "chart",
        "dedup",
        "eval",
        "eventstats",
        "fields",
        "fillnull",
        "head",
        "join",
        "lookup",
        "rare",
        "rename",
        "rex",
        "sort",
        "stats",
        "streamstats",
        "table",
        "tail",
        "timechart",
        "top",
        "transaction",
        "where",
    }
)

# Commands whose arguments use search-term syntax, so ``index=foo`` inside
# them is a real index reference rather than an eval assignment.
_SEARCH_LIKE_COMMANDS = frozenset(
    {
        "dbinspect",
        "eventcount",
        "mcatalog",
        "metadata",
        "metasearch",
        "mpreview",
        "msearch",
        "mstats",
        "search",
        "tstats",
        "walklex",
        "where",
    }
)

_ENTITY_KEYS = {
    "index": "indexes",
    "sourcetype": "sourcetypes",
    "host": "hosts",
    "source": "sources",
}
_ENTITY_CATEGORIES = ("indexes", "sourcetypes", "hosts", "sources")

_TIME_KEYS = frozenset({"earliest", "latest", "starttime", "endtime", "starttimeu", "endtimeu"})

# A single quote only opens a quoted string at a token boundary so that
# apostrophes in raw search terms (``don't``) are not treated as quotes.
_QUOTE_BOUNDARY_CHARS = frozenset(" \t\r\n=(,[|!<>+-*/%")
_WORD_STOP_CHARS = frozenset(' \t\r\n"=!<>(),[]|`')

_COMMAND_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)")
_IMPLICIT_FIRST_WORD_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?=\s|$)")
_SEARCH_TERM_START_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*(?:!=|==|=|<|>)")
_APPEND_TRUE_RE = re.compile(r"\bappend\s*=\s*[\"']?\s*(?:t|true|1)\b", re.IGNORECASE)
_REST_WRITE_RE = re.compile(r"\bmethod\s*=\s*[\"']?\s*(post|put|delete|patch)\b", re.IGNORECASE)
_MAXSPAN_RE = re.compile(r"\bmaxspan\s*=", re.IGNORECASE)
_MAP_SEARCH_RE = re.compile(r"\bsearch\s*=\s*\"((?:\\.|[^\"\\])*)\"", re.IGNORECASE | re.DOTALL)
_LEADING_SEARCH_KEYWORD_RE = re.compile(r"\s*(?:search(?=\s|$)\s*)?", re.IGNORECASE)
_SAFE_BARE_VALUE_RE = re.compile(r"[A-Za-z0-9_\-.*:/@+]+")

_MAX_SUBSEARCH_DEPTH = 32


# ---------------------------------------------------------------------------
# Low-level SPL scanning
# ---------------------------------------------------------------------------


def _code_mask(text: str, lenient_quotes: bool = True) -> Tuple[List[bool], bool]:
    """Return a per-character mask that is True for structural (unquoted) chars.

    With ``lenient_quotes`` the scanner treats single quotes (at token
    boundaries) and backticks as quote delimiters and honours backslash
    escapes outside of quotes. Without it only double quotes are quotes, which
    is the most pessimistic reading and is used by the safety checks.
    """

    n = len(text)
    mask = [True] * n
    quote: Optional[str] = None
    i = 0
    while i < n:
        char = text[i]
        if quote is not None:
            mask[i] = False
            if char == "\\" and i + 1 < n:
                mask[i + 1] = False
                i += 2
                continue
            if char == quote:
                quote = None
            i += 1
            continue
        if lenient_quotes and char == "\\" and i + 1 < n:
            mask[i] = False
            mask[i + 1] = False
            i += 2
            continue
        if char == '"' or (
            lenient_quotes
            and (char == "`" or (char == "'" and (i == 0 or text[i - 1] in _QUOTE_BOUNDARY_CHARS)))
        ):
            quote = char
            mask[i] = False
        i += 1
    return mask, quote is not None


class _Segment:
    __slots__ = ("raw", "outer", "command", "implicit", "first_word", "subsearches")

    def __init__(self, raw: str, outer: str, command: str, implicit: bool, first_word: str, subsearches: List["_Pipeline"]):
        self.raw = raw
        self.outer = outer
        self.command = command
        self.implicit = implicit
        self.first_word = first_word
        self.subsearches = subsearches


class _Pipeline:
    __slots__ = (
        "text",
        "leading_pipe",
        "segments",
        "unterminated_quote",
        "unclosed_brackets",
        "stray_brackets",
        "paren_error",
    )

    def __init__(self) -> None:
        self.text = ""
        self.leading_pipe = False
        self.segments: List[_Segment] = []
        self.unterminated_quote = False
        self.unclosed_brackets = 0
        self.stray_brackets = 0
        self.paren_error = False


def _parse(text: str, lenient_quotes: bool = True, depth: int = 0) -> _Pipeline:
    pipeline = _Pipeline()
    pipeline.text = text
    mask, unterminated = _code_mask(text, lenient_quotes)
    pipeline.unterminated_quote = unterminated
    n = len(text)

    bounds: List[Tuple[int, int]] = []
    spans: List[Tuple[int, int, bool]] = []  # (open bracket index, end index, closed)
    bracket_depth = 0
    open_at = -1
    seg_start = 0
    parens = 0
    for i, char in enumerate(text):
        if not mask[i]:
            continue
        if char == "[":
            if bracket_depth == 0:
                open_at = i
            bracket_depth += 1
        elif char == "]":
            if bracket_depth == 0:
                pipeline.stray_brackets += 1
            else:
                bracket_depth -= 1
                if bracket_depth == 0:
                    spans.append((open_at, i + 1, True))
        elif bracket_depth == 0:
            if char == "|":
                bounds.append((seg_start, i))
                seg_start = i + 1
            elif char == "(":
                parens += 1
            elif char == ")":
                parens -= 1
                if parens < 0:
                    pipeline.paren_error = True
    bounds.append((seg_start, n))
    if parens != 0:
        pipeline.paren_error = True
    if bracket_depth > 0:
        pipeline.unclosed_brackets = bracket_depth
        # Analyse an unclosed subsearch anyway so nothing can hide inside it.
        spans.append((open_at, n, False))

    first_index = next((i for i, char in enumerate(text) if not char.isspace()), None)
    pipeline.leading_pipe = first_index is not None and text[first_index] == "|" and mask[first_index]
    if pipeline.leading_pipe:
        bounds = bounds[1:]

    for index, (start, end) in enumerate(bounds):
        raw = text[start:end]
        outer_chars = list(raw)
        subsearches: List[_Pipeline] = []
        for open_idx, span_end, closed in spans:
            if not (start <= open_idx < end):
                continue
            for k in range(open_idx - start, min(span_end, end) - start):
                outer_chars[k] = " "
            inner = text[open_idx + 1 : span_end - 1] if closed else text[open_idx + 1 : span_end]
            if depth < _MAX_SUBSEARCH_DEPTH:
                subsearches.append(_parse(inner, lenient_quotes, depth + 1))
        outer = "".join(outer_chars).strip()
        stripped_raw = raw.strip()
        implicit = index == 0 and not pipeline.leading_pipe
        if implicit:
            match = _IMPLICIT_FIRST_WORD_RE.match(outer)
            first_word = match.group(1).lower() if match else ""
            command = "search"
        else:
            match = _COMMAND_RE.match(stripped_raw)
            command = match.group(1).lower() if match else ""
            first_word = command
        pipeline.segments.append(_Segment(stripped_raw, outer, command, implicit, first_word, subsearches))
    return pipeline


def _iter_pipelines(pipeline: _Pipeline, nested: bool = False) -> Iterator[Tuple[_Pipeline, bool]]:
    yield pipeline, nested
    for segment in pipeline.segments:
        for sub in segment.subsearches:
            yield from _iter_pipelines(sub, True)


def _lex(text: str) -> List[Tuple[str, str]]:
    """Tokenise search-term text into (kind, value) pairs."""

    tokens: List[Tuple[str, str]] = []
    i = 0
    n = len(text)
    while i < n:
        char = text[i]
        if char.isspace():
            i += 1
            continue
        if char == '"' or char == "`" or (char == "'" and (i == 0 or text[i - 1] in _QUOTE_BOUNDARY_CHARS)):
            j = i + 1
            buf: List[str] = []
            while j < n and text[j] != char:
                if text[j] == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            tokens.append(("macro" if char == "`" else "str", "".join(buf)))
            i = j + 1
            continue
        if char in "!=<>":
            if i + 1 < n and text[i + 1] == "=":
                tokens.append(("op", char + "="))
                i += 2
            elif char == "!":
                tokens.append(("other", "!"))
                i += 1
            else:
                tokens.append(("op", char))
                i += 1
            continue
        if char == "(":
            tokens.append(("lp", char))
            i += 1
            continue
        if char == ")":
            tokens.append(("rp", char))
            i += 1
            continue
        if char == ",":
            tokens.append(("comma", char))
            i += 1
            continue
        if char in "[]|":
            tokens.append(("other", char))
            i += 1
            continue
        j = i
        while j < n and text[j] not in _WORD_STOP_CHARS:
            j += 2 if text[j] == "\\" and j + 1 < n else 1
        tokens.append(("word", text[i:j]))
        i = j
    return tokens


def _empty_entities() -> Dict[str, List[str]]:
    return {category: [] for category in _ENTITY_CATEGORIES}


def _add_unique(values: List[str], value: str) -> None:
    value = value.strip()
    if not value:
        return
    lowered = value.lower()
    if all(existing.lower() != lowered for existing in values):
        values.append(value)


def _extract_terms(text: str, out: Dict[str, List[str]], strings_only: bool = False) -> None:
    tokens = _lex(text)
    negation_stack = [False]
    pending_not = False
    j = 0
    n = len(tokens)
    while j < n:
        kind, value = tokens[j]
        if kind == "word" and value.upper() == "NOT":
            pending_not = True
            j += 1
            continue
        if kind == "lp":
            negation_stack.append(negation_stack[-1] or pending_not)
            pending_not = False
            j += 1
            continue
        if kind == "rp":
            if len(negation_stack) > 1:
                negation_stack.pop()
            pending_not = False
            j += 1
            continue
        if kind == "word":
            category = _ENTITY_KEYS.get(value.lower())
            nxt = tokens[j + 1] if j + 1 < n else None
            if category and nxt is not None:
                if nxt[0] == "op" and nxt[1] in ("=", "==", "!=") and j + 2 < n and tokens[j + 2][0] in ("word", "str"):
                    value_kind, entity = tokens[j + 2]
                    negated = negation_stack[-1] or pending_not or nxt[1] == "!="
                    if not negated and (value_kind == "str" or not strings_only):
                        _add_unique(out[category], entity)
                    pending_not = False
                    j += 3
                    continue
                if nxt[0] == "word" and nxt[1].upper() == "IN" and j + 2 < n and tokens[j + 2][0] == "lp":
                    negated = negation_stack[-1] or pending_not
                    k = j + 3
                    while k < n and tokens[k][0] != "rp":
                        value_kind, entity = tokens[k]
                        if not negated and (value_kind == "str" or (value_kind == "word" and not strings_only)):
                            _add_unique(out[category], entity)
                        k += 1
                    pending_not = False
                    j = k + 1
                    continue
            if "::" in value:
                key, _, entity = value.partition("::")
                category = _ENTITY_KEYS.get(key.lower())
                if category and not (negation_stack[-1] or pending_not) and not strings_only:
                    _add_unique(out[category], entity)
        pending_not = False
        j += 1


def _has_time_terms(text: str) -> bool:
    tokens = _lex(text)
    for index, (kind, value) in enumerate(tokens[:-1]):
        if kind == "word" and value.lower() in _TIME_KEYS:
            nxt = tokens[index + 1]
            if nxt[0] == "op" and nxt[1] in ("=", "=="):
                return True
    return False


def _top_level_entities(pipeline: _Pipeline) -> Dict[str, List[str]]:
    out = _empty_entities()
    for segment in pipeline.segments:
        if segment.command in _SEARCH_LIKE_COMMANDS:
            _extract_terms(segment.outer, out, strings_only=segment.command == "where")
    return out


def _starts_with_generating(pipeline: _Pipeline) -> bool:
    if pipeline.leading_pipe:
        return True
    if not pipeline.segments:
        return False
    return pipeline.segments[0].first_word in GENERATING_COMMANDS


def _is_blocked_command(name: str) -> bool:
    name = (name or "").lower()
    return bool(name) and (name in BLOCKED_COMMANDS or name.startswith("send"))


def _quote_value(value: str) -> str:
    if _SAFE_BARE_VALUE_RE.fullmatch(value):
        return value
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _insert_base_terms(query: str, terms: List[str]) -> str:
    match = _LEADING_SEARCH_KEYWORD_RE.match(query)
    position = match.end() if match else 0
    prefix = query[:position]
    rest = query[position:]
    insertion = " ".join(terms)
    if prefix and not prefix[-1].isspace():
        prefix += " "
    if rest and not rest[0].isspace():
        insertion += " "
    return prefix + insertion + rest


def _unescape_quoted(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value, flags=re.DOTALL)


# ---------------------------------------------------------------------------
# Public SPL helpers
# ---------------------------------------------------------------------------


def split_spl_pipeline(query: str) -> List[str]:
    """Split ``query`` on top-level pipes and return the stripped segments.

    Pipes inside double quotes, single-quoted strings, backtick macros,
    subsearch brackets and backslash escapes are ignored. When the query
    starts with ``|`` the first returned segment is ``""``. An empty or
    whitespace-only query returns ``[]``.
    """

    if not isinstance(query, str) or not query.strip():
        return []
    pipeline = _parse(query)
    segments = [segment.raw for segment in pipeline.segments]
    if pipeline.leading_pipe:
        segments.insert(0, "")
    return segments


def _collect_safety(
    pipeline: _Pipeline,
    lenient_quotes: bool,
    blocked: List[str],
    warnings: Optional[List[str]],
    nested: bool,
    depth: int = 0,
) -> None:
    for current, is_sub in _iter_pipelines(pipeline, nested):
        for segment in current.segments:
            if segment.implicit:
                first_word = segment.first_word
                if _is_blocked_command(first_word):
                    if is_sub:
                        _add_unique(blocked, first_word)
                    elif warnings is not None:
                        _add_unique(
                            warnings,
                            f"First search term '{first_word}' matches a write command name; Splunk treats it as a "
                            "search term because it is not preceded by '|'.",
                        )
                continue
            command = segment.command
            if _is_blocked_command(command):
                _add_unique(blocked, command)
            if command == "rest" and _REST_WRITE_RE.search(segment.raw):
                _add_unique(blocked, "rest")
            if command == "map":
                if warnings is not None:
                    _add_unique(warnings, "map runs a separate search for every input row and can be very expensive.")
                if depth < _MAX_SUBSEARCH_DEPTH:
                    for match in _MAP_SEARCH_RE.finditer(segment.raw):
                        inner = _parse(_unescape_quoted(match.group(1)), lenient_quotes)
                        _collect_safety(inner, lenient_quotes, blocked, warnings, True, depth + 1)
            if warnings is None:
                continue
            if command == "transaction" and not _MAXSPAN_RE.search(segment.raw):
                _add_unique(warnings, "transaction without maxspan= can consume a lot of memory; add maxspan.")
            elif command == "join":
                _add_unique(warnings, "join is subject to subsearch limits and can be slow; prefer stats-based correlation.")
            elif command == "savedsearch":
                _add_unique(warnings, "savedsearch runs a stored search whose contents cannot be inspected here.")


def assess_spl_safety(query: str) -> Dict[str, Any]:
    """Decide whether ``query`` is read-only and therefore safe to run.

    Returns ``{"allowed", "blocked_commands", "warnings", "reason"}``. Every
    pipeline segment is inspected, including segments inside subsearches and
    ``map search="..."`` strings. Write, export, alerting and script commands
    are blocked (case-insensitive), as is ``| rest`` with a write method.
    Expensive patterns only produce warnings. ``reason`` is empty when the
    query is allowed.
    """

    result: Dict[str, Any] = {"allowed": False, "blocked_commands": [], "warnings": [], "reason": ""}
    if not isinstance(query, str) or not query.strip():
        result["reason"] = "Query is empty."
        return result

    blocked: List[str] = []
    warnings: List[str] = []
    lenient = _parse(query, lenient_quotes=True)
    _collect_safety(lenient, True, blocked, warnings, nested=False)
    # Re-check with only double quotes treated as quotes so that a pipe hidden
    # behind a single quote or backslash cannot smuggle a write command past
    # the scanner if Splunk reads the quoting differently.
    strict = _parse(query, lenient_quotes=False)
    _collect_safety(strict, False, blocked, None, nested=False)

    if "`" in query:
        _add_unique(warnings, "Query uses macros whose expansion cannot be inspected.")
    if any(p.unterminated_quote or p.unclosed_brackets or p.stray_brackets for p, _ in _iter_pipelines(lenient)):
        _add_unique(warnings, "Query has unbalanced quotes or brackets.")

    commands = {segment.command for p, _ in _iter_pipelines(lenient) for segment in p.segments}
    indexes = extract_spl_entities(query)["indexes"]
    if (
        any(value.strip("*") == "" for value in indexes)
        and "tstats" not in commands
        and not _query_has_time_terms(lenient)
    ):
        _add_unique(warnings, "index=* without an explicit earliest= bound can scan a lot of data.")

    result["blocked_commands"] = blocked
    result["warnings"] = warnings
    result["allowed"] = not blocked
    if blocked:
        result["reason"] = (
            "Query uses blocked command(s): " + ", ".join(blocked) + ". Only read-only searches are allowed."
        )
    return result


def _query_has_time_terms(pipeline: _Pipeline) -> bool:
    return any(
        _has_time_terms(segment.outer)
        for segment in pipeline.segments
        if segment.command in _SEARCH_LIKE_COMMANDS
    )


def _coerce_row_limit(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value == value and value not in (float("inf"), float("-inf")) else None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            pass
        try:
            number = float(text)
        except ValueError:
            return None
        return int(number) if number == number and number not in (float("inf"), float("-inf")) else None
    return None


def normalize_query_tool_args(
    args: Optional[Dict[str, Any]],
    *,
    default_earliest: Optional[str] = "-24h",
    default_latest: Optional[str] = "now",
    default_row_limit: int = 200,
    max_row_limit: int = 1000,
) -> Dict[str, Any]:
    """Return a new ``splunk_run_query`` argument dict with safe defaults.

    The query is stripped. ``earliest_time``/``latest_time`` keep caller
    values; blank or missing values get the defaults unless the SPL already
    contains an ``earliest=``/``latest=`` term, in which case they are left
    out. ``row_limit`` is coerced from int/str and clamped to
    ``[1, max_row_limit]``. Unrelated keys are preserved and the input is not
    modified.
    """

    source = dict(args) if isinstance(args, dict) else {}
    result = dict(source)
    raw_query = source.get("query")
    query = "" if raw_query is None else str(raw_query).strip()
    result["query"] = query
    spl_has_time = bool(query) and _query_has_time_terms(_parse(query))

    for key, default in (("earliest_time", default_earliest), ("latest_time", default_latest)):
        value = source.get(key)
        if value is not None and str(value).strip():
            result[key] = value.strip() if isinstance(value, str) else value
        elif spl_has_time or default is None or not str(default).strip():
            result.pop(key, None)
        else:
            result[key] = default

    upper = max(1, _coerce_row_limit(max_row_limit) or 1)
    fallback = _coerce_row_limit(default_row_limit)
    limit = _coerce_row_limit(source.get("row_limit"))
    if limit is None:
        limit = fallback if fallback is not None else 200
    result["row_limit"] = min(max(limit, 1), upper)
    return result


def extract_spl_entities(query: str) -> Dict[str, List[str]]:
    """Return positive ``index``/``sourcetype``/``host``/``source`` references.

    Handles ``key=value``, quoted values, ``key IN (...)`` lists, wildcards,
    ``key::value`` and case-insensitive keys in search-like commands (the
    base search, ``search``, ``where`` string literals, ``tstats``/``mstats``
    ``where`` clauses, ``metadata``, ``dbinspect``...) including subsearches.
    References negated with ``NOT`` or ``!=`` are excluded, as are field names
    that merely contain a key (``my_index``). Values are de-duplicated
    case-insensitively, preserving first-seen order.
    """

    out = _empty_entities()
    if not isinstance(query, str) or not query.strip():
        return out
    for pipeline, _ in _iter_pipelines(_parse(query)):
        for segment in pipeline.segments:
            if segment.command in _SEARCH_LIKE_COMMANDS:
                _extract_terms(segment.outer, out, strings_only=segment.command == "where")
    return out


def _wildcard_regex(pattern: str) -> "re.Pattern[str]":
    return re.compile("".join(".*" if char == "*" else re.escape(char) for char in pattern), re.IGNORECASE | re.DOTALL)


def _matches_known(value: str, known_values: List[str]) -> bool:
    lowered = value.strip().lower()
    if "*" in lowered:
        regex = _wildcard_regex(lowered)
        return any(regex.fullmatch(item) for item in known_values)
    for item in known_values:
        if item == lowered:
            return True
        if "*" in item and _wildcard_regex(item).fullmatch(lowered):
            return True
    return False


def _normalize_known(values: Any) -> List[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    try:
        items: Iterable[Any] = list(values)
    except TypeError:
        return []
    return [str(item).strip().lower() for item in items if item is not None and str(item).strip()]


def _structural_issues(pipeline: _Pipeline) -> List[str]:
    issues: List[str] = []
    if pipeline.unterminated_quote:
        _add_unique(issues, "Unbalanced quotes.")
    if pipeline.unclosed_brackets or pipeline.stray_brackets:
        _add_unique(issues, "Unbalanced subsearch brackets.")
    if pipeline.paren_error:
        _add_unique(issues, "Unbalanced parentheses.")

    top_segments = pipeline.segments
    if top_segments and top_segments[0].implicit:
        first_word = top_segments[0].first_word
        if first_word in GENERATING_COMMANDS:
            _add_unique(issues, f"Generating command '{first_word}' must start with a leading pipe ('| {first_word} ...').")

    for current, is_sub in _iter_pipelines(pipeline):
        if is_sub:
            if current.unterminated_quote:
                _add_unique(issues, "Unbalanced quotes.")
            if current.paren_error:
                _add_unique(issues, "Unbalanced parentheses.")
            if len(current.segments) == 1 and not current.segments[0].raw:
                _add_unique(issues, "Empty subsearch.")
                continue
        for position, segment in enumerate(current.segments):
            if not segment.raw:
                _add_unique(issues, "Empty pipeline segment (stray '|').")
                continue
            if segment.implicit:
                continue
            command = segment.command
            if position == 0 and command in _NON_GENERATING_START_COMMANDS:
                _add_unique(issues, f"Pipeline cannot start with '| {command}'; it needs a search or generating command first.")
            if position > 0 and command in _FIRST_ONLY_COMMANDS and not _APPEND_TRUE_RE.search(segment.raw):
                _add_unique(issues, f"Generating command '{command}' must be the first command in its pipeline.")
            if _SEARCH_TERM_START_RE.match(segment.raw):
                snippet = segment.raw[:40]
                _add_unique(issues, f"Pipeline segment '{snippet}' starts with a search term instead of a command.")
            elif not command and not segment.raw.startswith("`"):
                snippet = segment.raw[:40]
                _add_unique(issues, f"Pipeline segment '{snippet}' does not start with a command.")
    return issues


def validate_spl_against_environment(query: str, known: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate ``query`` for safety, structure and known environment entities.

    ``known`` may contain ``indexes``, ``sourcetypes``, ``hosts`` and
    ``sources`` iterables; only non-empty categories are checked. Matching is
    exact (case-insensitive) with ``*`` wildcards honoured on either side.
    ``status`` is the first applicable of ``blocked``, ``invalid``,
    ``unknown_entities``, ``unscoped`` (raw event search without a positive
    top-level index) and ``validated``.
    """

    safety = assess_spl_safety(query)
    result: Dict[str, Any] = {
        "status": "validated",
        "referenced": _empty_entities(),
        "unknown_entities": _empty_entities(),
        "issues": [],
        "safety": safety,
    }
    issues: List[str] = result["issues"]
    if not isinstance(query, str) or not query.strip():
        result["status"] = "invalid"
        issues.append("Query is empty.")
        return result

    pipeline = _parse(query)
    referenced = extract_spl_entities(query)
    result["referenced"] = referenced

    if not safety["allowed"]:
        issues.append(safety["reason"])
    structural = _structural_issues(pipeline)
    issues.extend(structural)

    known = known if isinstance(known, dict) else {}
    unknown = result["unknown_entities"]
    for category in _ENTITY_CATEGORIES:
        known_values = _normalize_known(known.get(category))
        if not known_values:
            continue
        for value in referenced[category]:
            if not _matches_known(value, known_values):
                _add_unique(unknown[category], value)
        if unknown[category]:
            issues.append(f"Unknown {category}: " + ", ".join(unknown[category]))

    raw_search = bool(pipeline.segments) and (
        (pipeline.leading_pipe and pipeline.segments[0].command == "search")
        or (not pipeline.leading_pipe and pipeline.segments[0].first_word not in GENERATING_COMMANDS)
    )
    unscoped = raw_search and not _top_level_entities(pipeline)["indexes"]
    if unscoped:
        issues.append("Query does not reference an index; Splunk will only search the role's default indexes.")

    if not safety["allowed"]:
        result["status"] = "blocked"
    elif structural:
        result["status"] = "invalid"
    elif any(unknown[category] for category in _ENTITY_CATEGORIES):
        result["status"] = "unknown_entities"
    elif unscoped:
        result["status"] = "unscoped"
    return result


def scope_spl_to_index(query: str, index: str) -> str:
    """Add ``index=<index>`` to the base search when it has no index yet.

    The query is returned unchanged when it is empty, starts with a pipe or a
    generating command, or already has a positive top-level index reference.
    The term is inserted at the start of the first segment (after a leading
    ``search`` keyword), never as a separate ``index=X |`` segment. Index
    names with spaces or special characters are quoted.
    """

    if not isinstance(query, str) or not query.strip():
        return query
    index_name = str(index or "").strip()
    if not index_name:
        return query
    pipeline = _parse(query)
    if _starts_with_generating(pipeline):
        return query
    if _top_level_entities(pipeline)["indexes"]:
        return query
    return _insert_base_terms(query, ["index=" + _quote_value(index_name)])


def ensure_spl_time_bounds(query: str, earliest: Optional[str] = "-24h", latest: Optional[str] = None) -> str:
    """Add ``earliest=``/``latest=`` terms to the base search when it has none.

    Queries that start with a pipe or a generating command (``| tstats``)
    are returned unchanged because their time range comes from the tool
    arguments. Queries whose first segment already contains a time term are
    also unchanged. Terms are only ever inserted into the first segment.
    """

    if not isinstance(query, str) or not query.strip():
        return query
    pipeline = _parse(query)
    if _starts_with_generating(pipeline) or not pipeline.segments:
        return query
    if _has_time_terms(pipeline.segments[0].outer):
        return query
    terms: List[str] = []
    if earliest is not None and str(earliest).strip():
        terms.append("earliest=" + _quote_value(str(earliest).strip()))
    if latest is not None and str(latest).strip():
        terms.append("latest=" + _quote_value(str(latest).strip()))
    if not terms:
        return query
    return _insert_base_terms(query, terms)


# ---------------------------------------------------------------------------
# JSON extraction from LLM output
# ---------------------------------------------------------------------------

_NOTHING = object()
_THINK_BLOCK_RE = re.compile(r"<(think|thinking|reasoning)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_THINK_CLOSE_RE = re.compile(r"</(?:think|thinking|reasoning)\s*>", re.IGNORECASE)
_THINK_OPEN_RE = re.compile(r"<(?:think|thinking|reasoning)\b[^>]*>", re.IGNORECASE)
_FENCE_RE = re.compile(r"```[ \t]*([A-Za-z]*)[ \t]*\r?\n?(.*?)```", re.DOTALL)
_MAX_SCAN_ATTEMPTS = 5000
_DEFAULT_LIST_KEYS = ("queries", "tasks", "items", "results", "recommendations", "findings", "use_cases", "patterns")


def _accept_json(obj: Any, expect: str, list_keys: Tuple[str, ...]) -> Any:
    if expect == "list":
        if isinstance(obj, list):
            return obj
        if isinstance(obj, dict):
            for key in list_keys:
                if isinstance(obj.get(key), list):
                    return obj[key]
            lowered = {str(k).lower(): v for k, v in obj.items()}
            for key in list_keys:
                if isinstance(lowered.get(str(key).lower()), list):
                    return lowered[str(key).lower()]
        return _NOTHING
    if expect == "dict":
        return obj if isinstance(obj, dict) else _NOTHING
    return obj if isinstance(obj, (list, dict)) else _NOTHING


def _lenient_json(text: str) -> str:
    """Drop ``//`` line comments and trailing commas outside JSON strings."""

    out: List[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        char = text[i]
        if in_string:
            out.append(char)
            if char == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if char == '"':
                in_string = False
            i += 1
            continue
        if char == '"':
            in_string = True
            out.append(char)
            i += 1
            continue
        if char == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if char == ",":
            k = i + 1
            while k < n and text[k] in " \t\r\n":
                k += 1
            if k < n and text[k] in "]}":
                i += 1
                continue
        out.append(char)
        i += 1
    return "".join(out)


def _salvage_array(decoder: json.JSONDecoder, text: str, start: int) -> Tuple[List[Any], List[Tuple[int, int]], int]:
    items: List[Any] = []
    spans: List[Tuple[int, int]] = []
    i = start + 1
    n = len(text)
    end = start + 1
    while i < n:
        while i < n and text[i] in " \t\r\n,":
            i += 1
        if i >= n or text[i] == "]":
            break
        try:
            obj, j = decoder.raw_decode(text, i)
        except ValueError:
            break
        if not isinstance(obj, (dict, list)):
            # A scalar at the very end may itself be truncated (e.g. "12" of "123").
            k = j
            while k < n and text[k] in " \t\r\n":
                k += 1
            if k >= n or text[k] not in ",]":
                break
        items.append(obj)
        spans.append((i, j))
        i = j
        end = j
    return items, spans, end


def _scan_json(text: str) -> List[Tuple[Any, int]]:
    decoder = json.JSONDecoder()
    candidates: List[Tuple[Any, int]] = []
    i = 0
    n = len(text)
    attempts = 0
    while i < n:
        char = text[i]
        if char not in "[{":
            i += 1
            continue
        attempts += 1
        if attempts > _MAX_SCAN_ATTEMPTS:
            break
        try:
            obj, end = decoder.raw_decode(text, i)
        except ValueError:
            pass
        else:
            candidates.append((obj, end - i))
            i = end
            continue
        if char == "[":
            items, spans, end = _salvage_array(decoder, text, i)
            if items:
                candidates.append((items, end - i))
                for item, (item_start, item_end) in zip(items, spans):
                    if isinstance(item, (dict, list)):
                        candidates.append((item, item_end - item_start))
                i = end
                continue
        i += 1
    return candidates


def _pick_largest(candidates: List[Tuple[Any, int]], expect: str, list_keys: Tuple[str, ...]) -> Any:
    best: Any = _NOTHING
    best_size = -1
    for obj, size in candidates:
        accepted = _accept_json(obj, expect, list_keys)
        if accepted is not _NOTHING and size > best_size:
            best = accepted
            best_size = size
    return best


def _loads_candidates(body: str) -> List[Tuple[Any, int]]:
    stripped = body.strip()
    if not stripped:
        return []
    for attempt in (stripped, _lenient_json(stripped)):
        try:
            return [(json.loads(attempt), len(stripped))]
        except ValueError:
            continue
    return []


def _extract_json_from(text: str, expect: str, list_keys: Tuple[str, ...]) -> Any:
    if not text or not text.strip():
        return _NOTHING
    fences = _FENCE_RE.findall(text)
    ordered = [body for lang, body in fences if lang.lower() == "json"] + [
        body for lang, body in fences if lang.lower() != "json"
    ]
    fenced: List[Tuple[Any, int]] = []
    for body in ordered:
        fenced.extend(_loads_candidates(body))
    picked = _pick_largest(fenced, expect, list_keys)
    if picked is not _NOTHING:
        return picked

    picked = _pick_largest(_loads_candidates(text), expect, list_keys)
    if picked is not _NOTHING:
        return picked

    picked = _pick_largest(_scan_json(text), expect, list_keys)
    if picked is not _NOTHING:
        return picked

    lenient = _lenient_json(text)
    if lenient != text:
        picked = _pick_largest(_scan_json(lenient), expect, list_keys)
    return picked


def extract_json_payload(
    text: Any,
    expect: str = "any",
    list_keys: Tuple[str, ...] = _DEFAULT_LIST_KEYS,
) -> Any:
    """Extract a JSON list or dict from free-form LLM output.

    ``<think>``/``<thinking>``/``<reasoning>`` blocks are removed first.
    Fenced code blocks (``json``-labelled first) are preferred, then the whole
    text, then every ``[``/``{`` position decoded with ``raw_decode``. A
    truncated top-level array is salvaged into the list of its complete
    elements. ``expect`` is ``"any"`` (largest list/dict), ``"list"`` (a list,
    or the list under one of ``list_keys`` in a dict) or ``"dict"``.
    Trailing commas and ``//`` comments are tolerated. Returns ``None`` when
    nothing usable is found.
    """

    if expect not in ("any", "list", "dict"):
        raise ValueError("expect must be 'any', 'list' or 'dict'")
    keys = tuple(list_keys or ())
    if isinstance(text, (list, dict)):
        accepted = _accept_json(text, expect, keys)
        return None if accepted is _NOTHING else accepted
    if isinstance(text, (bytes, bytearray)):
        text = bytes(text).decode("utf-8", errors="replace")
    if not isinstance(text, str):
        return None

    cleaned = _THINK_BLOCK_RE.sub("", text)
    variants: List[str] = []
    closes = list(_THINK_CLOSE_RE.finditer(cleaned))
    if closes:
        variants.append(cleaned[closes[-1].end():])
        variants.append(_THINK_CLOSE_RE.sub("", cleaned))
    else:
        opening = _THINK_OPEN_RE.search(cleaned)
        if opening:
            variants.append(cleaned[: opening.start()])
            variants.append(cleaned[opening.end():])
        else:
            variants.append(cleaned)

    seen = set()
    for variant in variants:
        if variant in seen:
            continue
        seen.add(variant)
        picked = _extract_json_from(variant, expect, keys)
        if picked is not _NOTHING:
            return picked
    return None
