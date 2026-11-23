"""Constellation dashboard contract v1: plan checks, request IDs, receipts, links, and the MCP call.

The contract lives in Constellation's docs/integrations/mcp-dashboard-contract.md. Application code,
not the AI model, builds every argument and decides whether a receipt shows a created dashboard.
"""

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import httpx

CREATE_TOOL = "constellation_create_dashboard"
STATUS_TOOL = "constellation_get_creation_status"
INSPECT_TOOL = "constellation_inspect_dashboard_source"
DASHBOARD_TOOLS = frozenset({CREATE_TOOL, STATUS_TOOL, INSPECT_TOOL})
USER_INFO_TOOL = "splunk_get_user_info"
SCHEMA_VERSION = "1"
TOOL_ARGUMENTS = {
    CREATE_TOOL: ("schema_version", "request_id", "expected_user", "brief_json"),
    STATUS_TOOL: ("schema_version", "request_id", "expected_user"),
    INSPECT_TOOL: ("schema_version", "expected_user", "scope_json"),
}

REQUEST_ID_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}$")
REQUEST_ADMISSION = timedelta(hours=24)
REQUEST_FUTURE_SKEW = timedelta(minutes=5)
RECEIPT_RETENTION = timedelta(days=7)
MAX_BRIEF_BYTES = 16384

TIME_RANGES = ("-15m", "-1h", "-24h", "-7d")
SOURCE_KINDS = ("index", "spl")
PROVENANCE_KINDS = ("conversation", "discovery_report")
BRIEF_FIELDS = ("title", "purpose", "requirements", "source", "time_range", "pages", "findings", "provenance")
LIMITS = {
    "title": 120,
    "purpose": 500,
    "requirements": 1200,
    "query": 8000,
    "page_name": 60,
    "panel": 240,
    "finding": 300,
    "provenance_label": 120,
    "pages": 2,
    "panels_per_page": 4,
    "panels_total": 6,
    "findings": 4,
}
INDEX_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,119}$")
SOURCETYPE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,199}$")

RUNNING_STATUS = "running"
TERMINAL_STATUSES = frozenset({"created", "draft_only", "needs_input", "failed", "indeterminate", "not_found"})
RECEIPT_STATUSES = frozenset({RUNNING_STATUS}) | TERMINAL_STATUSES
RUNNING_STAGES = ("accepted", "authoring", "validating", "saving_draft", "saving_native")
SAFE_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
LOCALE_RE = re.compile(r"^[a-z]{2}-[A-Z]{2}$")
DRAFT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
DASHBOARD_ID_RE = re.compile(r"^[A-Za-z0-9_]{1,100}$")
MAX_WARNINGS = 8

# Codes that leave open whether Splunk did the work, so the app checks status before showing an outcome.
AMBIGUOUS_ERROR_CODES = frozenset({"pilot_unconfirmed", "pilot_request_failed", "ledger_unavailable", "write_unconfirmed"})

ERROR_MESSAGES = {
    "identity_unavailable": "Splunk did not accept this request for your Splunk user. Ask an administrator to check that your user may create dashboards with Constellation.",
    "feature_disabled": "Dashboard creation is turned off in Constellation on this Splunk environment.",
    "request_conflict": "Splunk already holds a different plan under this request. Start a new request.",
    "unsupported_contract": "Constellation on this Splunk environment does not support this app's dashboard format. Update Constellation or this app.",
    "invalid_request": "Constellation did not accept the plan. Check the fields and try again.",
    "request_expired": "This request is more than a day old, so it cannot start. Create a new request.",
    "pilot_capacity": "Constellation has reached its limit of saved requests for your Splunk user. Try again later.",
    "pilot_busy": "Constellation is already creating another dashboard for you. Wait for it to finish, then try again.",
    "pilot_configuration": "Constellation is not fully set up on this Splunk environment. Ask an administrator to check its settings.",
    "pilot_probe_only": "Constellation is in read-only probe mode. Ask the Splunk administrator to enable authoring before trying again.",
    "pilot_request_failed": "The Splunk request failed. Check status, or try again later.",
    "pilot_unconfirmed": "Splunk could not confirm the result yet. Check status.",
    "ledger_unavailable": "Constellation could not read its request records. Check status later.",
    "no_data": "The chosen data returned no events for this time range. Pick a range or source with data.",
    "validation_failed": "Constellation could not build a dashboard that passed its checks.",
    "operation_interrupted": "Creation stopped before it finished. Start a new request.",
    "write_unconfirmed": "Splunk could not confirm that the dashboard was saved. Check status later.",
    "method_not_allowed": "The Splunk MCP server called the dashboard tool the wrong way. Ask an administrator to check the Constellation tool registration.",
}

# Contract v1 can include a safe reason for a failed request or one that needs input.
_DASHBOARD_RECOVERY = {
    "source_unavailable": ("source", "Review the dashboard source", "Constellation could not use the selected source. Choose an accessible index or review the search and time range."),
    "no_data": ("source", "Review the dashboard source", "The selected source and time range returned no usable rows for a requested panel. Choose a source or range with data."),
    "panel_coverage": ("panels", "Revise the dashboard panels", "Constellation could not verify every requested panel. Start with the key measure and a breakdown supported by the selected data."),
    "validation_failed": ("panels", "Review the dashboard plan", "Constellation stopped during validation and gave no specific reason. Verify the source and try a smaller set of panels focused on the main question."),
    "recovery_budget": ("panels", "Simplify the dashboard plan", "Constellation could not finish validating all the requested panels in one run. Start with a smaller overview."),
    "model_token_limit": ("panels", "Shorten the dashboard plan", "The Constellation model reached its context limit. Shorten the brief or choose a model with more room in Constellation Settings."),
    "model_output_limit": ("panels", "Simplify the dashboard plan", "The Constellation model ran out of room to finish its response. Start with fewer panels or adjust the model in Constellation Settings."),
    "authoring_settings": ("settings", "Check Constellation settings", "Select the approved authoring connection and model in Constellation Settings. You can then return to your plan."),
    "provider_timeout": ("retry", "The Constellation model timed out", "Check the model connection in Constellation Settings, then review and resubmit your plan."),
    "provider_connection": ("settings", "Check the Constellation model connection", "Constellation could not reach its model. Check the configured connection in Constellation Settings, then return to your plan."),
}


def dashboard_recovery(status: str, code: str) -> Optional[Dict[str, str]]:
    if status not in {"needs_input", "failed"} or code not in _DASHBOARD_RECOVERY:
        return None
    focus, heading, message = _DASHBOARD_RECOVERY[code]
    return {"focus": focus, "heading": heading, "message": message}


class BriefError(ValueError):
    """The plan breaks the contract. ``problems`` lists each field and what to fix."""

    def __init__(self, problems: List[Dict[str, str]]):
        self.problems = problems
        super().__init__(" ".join(problem["message"] for problem in problems) or "The dashboard plan is not valid.")


class ReceiptError(ValueError):
    """A reply this app cannot read as a v1 receipt for the request it sent."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def error_message(code: Any) -> str:
    cleaned = str(code or "").strip()
    if cleaned in ERROR_MESSAGES:
        return ERROR_MESSAGES[cleaned]
    if SAFE_CODE_RE.match(cleaned):
        return f"Dashboard creation did not finish (code {cleaned})."
    return "Dashboard creation did not finish."


# ---------------------------------------------------------------- plans


def _clean_text(value: Any) -> str:
    """Single-line text: control characters and runs of white space become one space."""
    if not isinstance(value, str):
        return ""
    cleaned = "".join(char if char.isprintable() else " " for char in value)
    return re.sub(r"\s+", " ", cleaned).strip()


def _clean_query(value: Any) -> str:
    """SPL keeps its spacing; only control characters such as line breaks become spaces."""
    if not isinstance(value, str):
        return ""
    return "".join(char if char.isprintable() else " " for char in value).strip()


def normalize_brief(raw: Any) -> Dict[str, Any]:
    """Return the plan in contract form, or raise BriefError listing every problem."""
    if not isinstance(raw, dict):
        raise BriefError([{"field": "", "message": "The dashboard plan is missing."}])
    problems: List[Dict[str, str]] = []

    def problem(field_name: str, message: str) -> None:
        problems.append({"field": field_name, "message": message})

    unknown = sorted(str(key) for key in raw if key not in BRIEF_FIELDS)
    if unknown:
        problem("", f"Remove fields the dashboard format does not define: {', '.join(unknown)}.")

    brief: Dict[str, Any] = {}
    title = _clean_text(raw.get("title"))
    if not title:
        problem("title", "Add a title.")
    elif len(title) > LIMITS["title"]:
        problem("title", f"Shorten the title to {LIMITS['title']} characters or fewer.")
    brief["title"] = title

    purpose = _clean_text(raw.get("purpose"))
    if not purpose:
        problem("purpose", "Describe the question the dashboard answers and who it is for.")
    elif len(purpose) > LIMITS["purpose"]:
        problem("purpose", f"Shorten the purpose to {LIMITS['purpose']} characters or fewer.")
    brief["purpose"] = purpose

    requirements = _clean_text(raw.get("requirements"))
    if len(requirements) > LIMITS["requirements"]:
        problem("requirements", f"Shorten the requirements to {LIMITS['requirements']} characters or fewer.")
    if requirements:
        brief["requirements"] = requirements

    brief["source"] = _normalize_source(raw.get("source"), problem)

    brief["time_range"] = _normalize_time_range(raw.get("time_range"), problem)

    brief["pages"] = _normalize_pages(raw.get("pages"), problem)

    findings_raw = raw.get("findings")
    if findings_raw is not None and not isinstance(findings_raw, list):
        problem("findings", "Findings must be a list.")
        findings_raw = []
    findings = [_clean_text(item) for item in (findings_raw or [])]
    findings = [item for item in findings if item]
    if len(findings) > LIMITS["findings"]:
        problem("findings", f"Keep {LIMITS['findings']} findings or fewer.")
    for position, finding in enumerate(findings):
        if len(finding) > LIMITS["finding"]:
            problem(f"findings.{position}", f"Shorten finding {position + 1} to {LIMITS['finding']} characters or fewer.")
    if findings:
        brief["findings"] = findings

    provenance = raw.get("provenance")
    if provenance is not None:
        if not isinstance(provenance, dict) or set(provenance) - {"kind", "label"}:
            problem("provenance", "The plan source label takes only kind and label.")
        else:
            kind = provenance.get("kind")
            label = _clean_text(provenance.get("label"))
            if kind not in PROVENANCE_KINDS:
                problem("provenance", "The plan source must be a conversation or a discovery report.")
            elif len(label) > LIMITS["provenance_label"]:
                problem("provenance", f"Shorten the source label to {LIMITS['provenance_label']} characters or fewer.")
            elif label:
                brief["provenance"] = {"kind": kind, "label": label}

    if not problems and len(serialize_brief(brief).encode("utf-8")) > MAX_BRIEF_BYTES:
        problem("", "The plan is too large. Shorten the text fields.")
    if problems:
        raise BriefError(problems)
    return brief


def _normalize_time_range(time_range: Any, problem) -> Dict[str, str]:
    earliest = time_range.get("earliest") if isinstance(time_range, dict) else None
    latest = time_range.get("latest", "now") if isinstance(time_range, dict) else None
    if isinstance(time_range, dict) and set(time_range) - {"earliest", "latest"}:
        problem("time_range", "The time range takes only earliest and latest.")
    if earliest not in TIME_RANGES or latest != "now":
        problem("time_range", "Pick a time range: last 15 minutes, last hour, last 24 hours, or last 7 days.")
    return {"earliest": earliest if earliest in TIME_RANGES else "", "latest": "now"}


def normalize_inspection_scope(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Reuse Create's source and time contract without accepting any plan details."""
    problems: List[Dict[str, str]] = []

    def problem(field_name: str, message: str) -> None:
        problems.append({"field": field_name, "message": message})

    if set(raw) != {"source", "time_range"}:
        problem("", "Provide a source and time range for inspection.")
    source = _normalize_source(raw.get("source"), problem)
    time_range = _normalize_time_range(raw.get("time_range"), problem)
    if problems:
        raise BriefError(problems)
    return {"source": source, "time_range": time_range}


def _normalize_source(source: Any, problem) -> Dict[str, Any]:
    if not isinstance(source, dict):
        problem("source", "Choose an index or a search for the dashboard data.")
        return {"kind": "index", "index": ""}
    kind = source.get("kind")
    if kind == "saved_report":
        problem("source.kind", "Saved reports are not supported yet. Use an index or a search.")
        return {"kind": "index", "index": ""}
    if kind == "spl":
        if set(source) - {"kind", "query"}:
            problem("source", "A search source takes only the search text.")
        query = _clean_query(source.get("query"))
        if not query:
            problem("source.query", "Enter the search the dashboard should use.")
        elif len(query) > LIMITS["query"]:
            problem("source.query", f"Shorten the search to {LIMITS['query']} characters or fewer.")
        return {"kind": "spl", "query": query}
    if kind != "index":
        problem("source.kind", "Choose an index or a search for the dashboard data.")
        return {"kind": "index", "index": ""}
    if set(source) - {"kind", "index", "sourcetype"}:
        problem("source", "An index source takes only an index and an optional sourcetype.")
    index = _clean_text(source.get("index"))
    normalized: Dict[str, Any] = {"kind": "index", "index": index}
    if not index:
        problem("source.index", "Enter the index the dashboard should use.")
    elif not INDEX_RE.match(index):
        problem("source.index", "Enter a single index name using letters, numbers, dots, dashes, or underscores.")
    sourcetype = _clean_text(source.get("sourcetype"))
    if sourcetype:
        if not SOURCETYPE_RE.match(sourcetype):
            problem("source.sourcetype", "Enter a single sourcetype using letters, numbers, dots, colons, dashes, or underscores.")
        normalized["sourcetype"] = sourcetype
    return normalized


def _normalize_pages(pages: Any, problem) -> List[Dict[str, Any]]:
    if not isinstance(pages, list) or not pages:
        problem("pages", "Add at least one page with one panel.")
        return []
    if len(pages) > LIMITS["pages"]:
        problem("pages", f"Use {LIMITS['pages']} pages or fewer.")
    normalized: List[Dict[str, Any]] = []
    seen_names = set()
    total_panels = 0
    for position, page in enumerate(pages):
        label = f"page {position + 1}"
        if not isinstance(page, dict):
            problem(f"pages.{position}", f"Describe {label} with a name and panels.")
            continue
        if set(page) - {"name", "panels"}:
            problem(f"pages.{position}", f"A page takes only a name and panels ({label}).")
        name = _clean_text(page.get("name"))
        if not name:
            problem(f"pages.{position}.name", f"Name {label}.")
        elif len(name) > LIMITS["page_name"]:
            problem(f"pages.{position}.name", f"Shorten the name of {label} to {LIMITS['page_name']} characters or fewer.")
        elif name.casefold() in seen_names:
            problem(f"pages.{position}.name", "Give each page a different name.")
        seen_names.add(name.casefold())
        panels_raw = page.get("panels")
        panels = [_clean_text(item) for item in panels_raw] if isinstance(panels_raw, list) else []
        panels = [item for item in panels if item]
        if not panels:
            problem(f"pages.{position}.panels", f"Describe at least one panel on {label}.")
        elif len(panels) > LIMITS["panels_per_page"]:
            problem(f"pages.{position}.panels", f"Use {LIMITS['panels_per_page']} panels or fewer on {label}.")
        for panel_position, panel in enumerate(panels):
            if len(panel) > LIMITS["panel"]:
                problem(
                    f"pages.{position}.panels.{panel_position}",
                    f"Shorten panel {panel_position + 1} on {label} to {LIMITS['panel']} characters or fewer.",
                )
        total_panels += len(panels)
        normalized.append({"name": name, "panels": panels})
    if total_panels > LIMITS["panels_total"]:
        problem("pages", f"Use {LIMITS['panels_total']} panels or fewer across all pages.")
    return normalized


def serialize_brief(brief: Dict[str, Any]) -> str:
    """The exact brief_json string. It is built once and reused for an identical resend."""
    return json.dumps(brief, ensure_ascii=False, separators=(",", ":"))


def brief_digest(brief: Dict[str, Any]) -> str:
    canonical = json.dumps(brief, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- request IDs and arguments


def new_request_id(now: Optional[datetime] = None) -> str:
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return f"{moment:%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex}"


def request_id_issued_at(request_id: Any) -> Optional[datetime]:
    if not isinstance(request_id, str) or not REQUEST_ID_RE.match(request_id):
        return None
    try:
        return datetime.strptime(request_id[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def request_id_is_fresh(request_id: Any, now: Optional[datetime] = None) -> bool:
    """True while Constellation still admits the ID for a new creation."""
    issued = request_id_issued_at(request_id)
    if issued is None:
        return False
    moment = now or datetime.now(timezone.utc)
    return issued - REQUEST_FUTURE_SKEW <= moment < issued + REQUEST_ADMISSION


def build_tool_arguments(tool_name: str, request_id: str, expected_user: str, brief_json: Optional[str] = None) -> Dict[str, str]:
    arguments = {"schema_version": SCHEMA_VERSION, "request_id": request_id, "expected_user": expected_user}
    if tool_name == CREATE_TOOL:
        if not isinstance(brief_json, str):
            raise ValueError("Creation needs the serialized brief.")
        arguments["brief_json"] = brief_json
    return arguments


def check_tool_schema(tool_name: str, schema: Any) -> Optional[str]:
    """Why a listed dashboard tool does not match contract v1, or None when it does."""
    expected = TOOL_ARGUMENTS.get(tool_name)
    if expected is None:
        return None
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict) or not properties:
        return "does not describe its arguments"
    missing = [name for name in expected if name not in properties]
    if missing:
        return f"is missing the arguments {', '.join(missing)}"
    required = schema.get("required")
    if isinstance(required, list):
        extra = [name for name in required if isinstance(name, str) and name not in expected]
        if extra:
            return f"requires arguments this app does not send: {', '.join(extra)}"
    version = properties.get("schema_version")
    if isinstance(version, dict) and isinstance(version.get("enum"), list) and SCHEMA_VERSION not in version["enum"]:
        return f"does not accept contract version {SCHEMA_VERSION}"
    return None


def supports_source_inspection(catalog: Any) -> bool:
    if not isinstance(catalog, dict) or not catalog.get("ok") or INSPECT_TOOL not in (catalog.get("tools") or []):
        return False
    schema = (catalog.get("schemas") or {}).get(INSPECT_TOOL)
    if check_tool_schema(INSPECT_TOOL, schema) is not None:
        return False
    return all(
        isinstance(schema["properties"][name], dict) and schema["properties"][name].get("type") == "string"
        for name in TOOL_ARGUMENTS[INSPECT_TOOL]
    )


_INSPECTION_REASONS = {
    "resource_limit", "row_limit", "unverified_completion", "search_warning", "byte_limit",
    "preview_timeout", "dynamic_field_names",
}
_FIELD_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.: -]{0,79}")
_FIELD_HINT_RE = re.compile(r"[A-Za-z0-9_%./-]{1,24}")


def normalize_source_profile(payload: Any, scope: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Keep bounded sample metadata for the requested scope. Drop all other tool output."""
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        return None
    source = payload.get("source")
    expected = scope["source"]
    if (
        not isinstance(source, dict)
        or source.get("kind") != expected["kind"]
        or source.get("language") != "spl"
        or (expected["kind"] == "index" and any(source.get(key) != expected.get(key) for key in ("index", "sourcetype")))
        or payload.get("time_range") != scope["time_range"]
    ):
        return None
    sample = payload.get("sample")
    if not isinstance(sample, dict):
        return None
    rows, row_limit = sample.get("rows"), sample.get("row_limit")
    if type(rows) is not int or type(row_limit) is not int or not 0 <= rows <= row_limit <= 200 or not row_limit:
        return None
    grain = "indexed_observations" if expected["kind"] == "index" else "existing_search_output"
    completion = sample.get("completion")
    status = "observed" if rows else ("empty" if completion == "complete" else "inconclusive")
    if completion not in ("complete", "partial", "unknown") or sample.get("grain") != grain or payload.get("status") != status:
        return None
    raw_reasons = sample.get("reasons")
    reasons = list(dict.fromkeys(
        reason for reason in raw_reasons[:12] if isinstance(reason, str) and reason in _INSPECTION_REASONS
    )) if isinstance(raw_reasons, list) else []
    fields = []
    names = set()
    raw_fields = payload.get("fields")
    if rows and isinstance(raw_fields, list) and "dynamic_field_names" not in reasons:
        for field in raw_fields[:12]:
            if not isinstance(field, dict):
                continue
            name = field.get("name")
            if not isinstance(name, str) or not _FIELD_NAME_RE.fullmatch(name) or name in names:
                continue
            counts = {key: field.get(key) for key in ("present", "missing", "numeric", "multivalue")}
            if any(type(count) is not int or not 0 <= count <= rows for count in counts.values()):
                continue
            if counts["present"] + counts["missing"] != rows or max(counts["numeric"], counts["multivalue"]) > counts["present"]:
                continue
            names.add(name)
            hints = {
                key: field[key] for key in ("role", "unit", "basis")
                if isinstance(field.get(key), str) and _FIELD_HINT_RE.fullmatch(field[key])
            }
            if "basis" not in hints:
                hints.pop("unit", None)
            fields.append({"name": name, **counts, **hints})
    return {
        "status": status,
        "sample": {"rows": rows, "row_limit": row_limit, "grain": grain, "completion": completion, "reasons": reasons},
        "fields": fields,
    }


# ---------------------------------------------------------------- replies


def _payload_candidates(result: Dict[str, Any]) -> List[Any]:
    candidates: List[Any] = []
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        candidates.append(structured)
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict) or item.get("type", "text") != "text":
                continue
            text = item.get("text")
            if not isinstance(text, str) or not text.strip():
                continue
            try:
                candidates.append(json.loads(text))
            except ValueError:
                continue
    return candidates


def _unwrap_payload(candidate: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(candidate, dict):
        return None
    if "schema_version" in candidate or ("code" in candidate and "error" in candidate):
        return candidate
    # Splunk MCP Server wraps REST replies as {"results": [reply]}.
    wrapped = candidate.get("results")
    if isinstance(wrapped, list) and len(wrapped) == 1 and isinstance(wrapped[0], dict):
        inner = wrapped[0]
        if "schema_version" in inner or ("code" in inner and "error" in inner):
            return inner
    return None


def _jsonrpc_error_code(error: Any) -> str:
    """A Constellation code the MCP server passed through inside a JSON-RPC error, if any."""
    if not isinstance(error, dict):
        return ""
    for value in (error.get("data"), error.get("message")):
        candidate = value
        if isinstance(value, str):
            start, end = value.find("{"), value.rfind("}")
            if start < 0 or end <= start:
                continue
            try:
                candidate = json.loads(value[start:end + 1])
            except ValueError:
                continue
        if isinstance(candidate, dict) and "error" in candidate:
            code = str(candidate.get("code") or "")
            if SAFE_CODE_RE.match(code):
                return code
    return ""


def parse_tool_response(http_status: Optional[int], body: Any, error: str = "") -> Dict[str, Any]:
    """Classify one tools/call reply before any receipt is read.

    Kinds: ``receipt`` (payload to validate), ``domain_error`` (a safe Constellation code), and
    ``transport_error``. ``ambiguous`` is True when Splunk may have done the work anyway.
    """
    if http_status is None:
        return {"kind": "transport_error", "ambiguous": True, "message": "The Splunk MCP server did not answer.", "detail": error}
    if not isinstance(body, dict):
        return {
            "kind": "transport_error",
            "ambiguous": True,
            "message": f"The Splunk MCP server answered with HTTP {http_status} and no readable reply.",
        }
    if body.get("error") is not None:
        code = _jsonrpc_error_code(body.get("error"))
        if code:
            return {"kind": "domain_error", "code": code, "ambiguous": code in AMBIGUOUS_ERROR_CODES, "message": error_message(code)}
        return {"kind": "transport_error", "ambiguous": True, "message": "The Splunk MCP server returned an error."}
    result = body.get("result")
    if not isinstance(result, dict):
        return {"kind": "transport_error", "ambiguous": True, "message": "The Splunk MCP server reply had no result."}
    payload = None
    for candidate in _payload_candidates(result):
        payload = _unwrap_payload(candidate)
        if payload is not None:
            break
    is_domain_error = isinstance(payload, dict) and "schema_version" not in payload and isinstance(payload.get("code"), str)
    if result.get("isError") or is_domain_error:
        code = str(payload.get("code") or "") if isinstance(payload, dict) else ""
        if SAFE_CODE_RE.match(code):
            return {
                "kind": "domain_error",
                "code": code,
                "ambiguous": code in AMBIGUOUS_ERROR_CODES,
                "message": error_message(code),
            }
        return {"kind": "transport_error", "ambiguous": True, "message": "The dashboard tool reported an error without a known code."}
    if payload is None:
        return {"kind": "transport_error", "ambiguous": True, "message": "The dashboard tool reply was not a readable receipt."}
    return {"kind": "receipt", "payload": payload}


def parse_splunk_username(body: Any) -> Optional[str]:
    """The authenticated Splunk user from a splunk_get_user_info reply."""
    result = body.get("result") if isinstance(body, dict) else None
    if not isinstance(result, dict) or result.get("isError") or body.get("error") is not None:
        return None
    for candidate in _payload_candidates(result):
        records: Iterable[Any] = []
        if isinstance(candidate, dict):
            results = candidate.get("results")
            records = results if isinstance(results, list) else [candidate]
        elif isinstance(candidate, list):
            records = candidate
        for record in records:
            if isinstance(record, dict):
                name = record.get("username") or record.get("name")
                if isinstance(name, str) and name.strip() and len(name) <= 200:
                    return name.strip()
    return None


# ---------------------------------------------------------------- links


def normalize_web_base(value: Any) -> Optional[str]:
    """An HTTPS Splunk Web address with no credentials, query, or fragment, without a trailing slash."""
    candidate = str(value or "").strip()
    if not candidate or len(candidate) > 500:
        return None
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    if parsed.query or parsed.fragment or port == 0:
        return None
    path = parsed.path.rstrip("/")
    if path and not re.fullmatch(r"(?:/[A-Za-z0-9_.-]+)+", path):
        return None
    return urlunsplit(("https", parsed.netloc.lower(), path, "", ""))


def derive_web_base(mcp_url: Any) -> Optional[str]:
    """Splunk Web on the MCP host: the management port 8089 becomes 8000, and the scheme is always HTTPS."""
    try:
        parsed = urlsplit(str(mcp_url or "").strip())
        port = parsed.port
    except ValueError:
        return None
    if not parsed.hostname:
        return None
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    web_port = 8000 if port in (None, 8089) else port
    netloc = host if web_port == 443 else f"{host}:{web_port}"
    return normalize_web_base(f"https://{netloc}")


def validate_dashboard_link(url: Any, web_base: Any, kind: str, resource_id: Any) -> bool:
    """True only for the exact view or edit route of ``resource_id`` under the connection's Splunk Web address."""
    base = normalize_web_base(web_base)
    if not base or not isinstance(url, str) or len(url) > 2048 or not isinstance(resource_id, str):
        return False
    try:
        parsed = urlsplit(url)
        parsed.port
    except ValueError:
        return False
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
        return False
    base_parts = urlsplit(base)
    if parsed.netloc.lower() != base_parts.netloc:
        return False
    base_path = base_parts.path
    if not parsed.path.startswith(f"{base_path}/"):
        return False
    segments = parsed.path[len(base_path) + 1:].split("/")
    base_has_locale = bool(base_path) and bool(LOCALE_RE.match(base_path.rsplit("/", 1)[-1]))
    if not base_has_locale:
        if not segments or not LOCALE_RE.match(segments[0]):
            return False
        segments = segments[1:]
    if kind == "view":
        return bool(DASHBOARD_ID_RE.match(resource_id)) and segments == ["app", "constellation", resource_id] and not parsed.query
    if kind == "edit":
        if not DRAFT_ID_RE.match(resource_id) or segments != ["app", "constellation", "workspace"]:
            return False
        try:
            query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            return False
        return query == [("draft", resource_id)]
    return False


# ---------------------------------------------------------------- receipts


def _bounded_text(value: Any, limit: int) -> str:
    text = _clean_text(value)
    return text[:limit]


def _normalize_warnings(value: Any) -> List[Dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ReceiptError("malformed_receipt", "The receipt warnings were not a list.")
    warnings: List[Dict[str, str]] = []
    for item in value[:MAX_WARNINGS]:
        if not isinstance(item, dict):
            continue
        code = str(item.get("code") or "")
        if not SAFE_CODE_RE.match(code):
            continue
        warning = {"code": code}
        message = _bounded_text(item.get("message"), 300)
        if message:
            warning["message"] = message
        warnings.append(warning)
    return warnings


LINK_REJECTED_WARNING = {
    "code": "link_rejected",
    "message": "A returned link did not match this connection's Splunk Web address, so it is hidden.",
}


def normalize_receipt(payload: Any, request_id: str, web_base: Any) -> Dict[str, Any]:
    """Check a receipt against the request and the connection, keeping only verified links."""
    if not isinstance(payload, dict):
        raise ReceiptError("malformed_receipt", "The reply was not a receipt.")
    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ReceiptError("unsupported_contract", "The receipt uses a dashboard format version this app does not support.")
    if payload.get("request_id") != request_id:
        raise ReceiptError("request_mismatch", "The receipt was for a different request.")
    status = payload.get("status")
    if status not in RECEIPT_STATUSES:
        raise ReceiptError("unknown_status", "The receipt reported a status this app does not know.")
    receipt: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "status": status,
        "warnings": _normalize_warnings(payload.get("warnings")),
    }
    message = _bounded_text(payload.get("message"), 500)
    if message:
        receipt["message"] = message
    title = _bounded_text(payload.get("title"), LIMITS["title"])
    if title:
        receipt["title"] = title

    if status == RUNNING_STATUS:
        stage = payload.get("stage")
        receipt["stage"] = stage if stage in RUNNING_STAGES else ""
        try:
            poll_after = int(payload.get("poll_after_ms"))
        except (TypeError, ValueError):
            poll_after = 2000
        receipt["poll_after_ms"] = max(500, min(poll_after, 30000))
    elif status == "needs_input":
        question = _bounded_text(payload.get("question"), 1000)
        if not question:
            raise ReceiptError("malformed_receipt", "The receipt asked for input without a question.")
        receipt["question"] = question
        code = payload.get("code")
        if isinstance(code, str) and code in _DASHBOARD_RECOVERY:
            receipt["code"] = code
    elif status in {"failed", "indeterminate"}:
        code = str(payload.get("code") or "")
        receipt["code"] = code if SAFE_CODE_RE.match(code) else "unknown"

    if status in {"created", "draft_only", "indeterminate"}:
        rejected = False
        draft_id = payload.get("draft_id")
        edit_url = payload.get("edit_url")
        if isinstance(draft_id, str) and DRAFT_ID_RE.match(draft_id):
            receipt["draft_id"] = draft_id
            if edit_url is not None:
                if validate_dashboard_link(edit_url, web_base, "edit", draft_id):
                    receipt["edit_url"] = edit_url
                else:
                    rejected = True
        elif edit_url is not None:
            rejected = True
        if status == "created":
            dashboard_id = payload.get("dashboard_id")
            view_url = payload.get("view_url")
            if isinstance(dashboard_id, str) and DASHBOARD_ID_RE.match(dashboard_id):
                receipt["dashboard_id"] = dashboard_id
                if view_url is not None:
                    if validate_dashboard_link(view_url, web_base, "view", dashboard_id):
                        receipt["view_url"] = view_url
                    else:
                        rejected = True
            elif view_url is not None:
                rejected = True
        if rejected:
            receipt["warnings"] = (receipt["warnings"] + [dict(LINK_REJECTED_WARNING)])[: MAX_WARNINGS + 1]
        validation = payload.get("validation")
        if isinstance(validation, dict):
            receipt["validation"] = {
                str(key)[:40]: str(value)[:40]
                for key, value in list(validation.items())[:8]
                if isinstance(key, str) and isinstance(value, str) and SAFE_CODE_RE.match(key)
            }
    return receipt


# ---------------------------------------------------------------- MCP transport


async def call_tool(mcp: Any, tool_name: str, arguments: Dict[str, Any], timeout_seconds: float) -> Dict[str, Any]:
    """One tools/call with no tool remapping, argument rewriting, retry, or argument logging."""
    url = str(getattr(mcp, "url", "") or "").strip()
    if not url:
        return {"http_status": None, "body": None, "timed_out": False, "error": "no_connection"}
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    token = str(getattr(mcp, "token", "") or "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    verify_ssl = bool(getattr(mcp, "verify_ssl", False))
    ca_bundle = getattr(mcp, "ca_bundle_path", None)
    ssl_verify: Any = ca_bundle if (ca_bundle and verify_ssl) else verify_ssl
    payload = {
        "jsonrpc": "2.0",
        "id": uuid.uuid4().hex,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    try:
        async with httpx.AsyncClient(verify=ssl_verify, timeout=timeout_seconds) as client:
            response = await client.post(url, json=payload, headers=headers)
    except httpx.TimeoutException:
        return {"http_status": None, "body": None, "timed_out": True, "error": "timeout"}
    except httpx.HTTPError as exc:
        return {"http_status": None, "body": None, "timed_out": False, "error": type(exc).__name__}
    try:
        body = response.json()
    except ValueError:
        body = None
    return {"http_status": response.status_code, "body": body, "timed_out": False, "error": ""}
