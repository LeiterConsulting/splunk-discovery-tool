"""Dashboard requests from plan to receipt: intent check, plan drafting, create, status, and one resend."""

import asyncio
import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from capabilities.tools.dashboard_store import ACTIVE_STATES, DashboardOperationStore
from capabilities.tools.dashboards import (
    CREATE_TOOL,
    INSPECT_TOOL,
    LIMITS,
    SCHEMA_VERSION,
    STATUS_TOOL,
    TERMINAL_STATUSES,
    TIME_RANGES,
    USER_INFO_TOOL,
    BriefError,
    ReceiptError,
    brief_digest,
    build_tool_arguments,
    call_tool,
    dashboard_recovery,
    error_message,
    new_request_id,
    normalize_brief,
    normalize_receipt,
    normalize_source_profile,
    parse_splunk_username,
    parse_tool_response,
    request_id_is_fresh,
    serialize_brief,
)

# States after which a new click on Create is a new request with a new ID.
RETRYABLE_STATES = frozenset({"needs_input", "failed", "not_found", "error"})
USER_CACHE_SECONDS = 600
MAX_STATUS_ERRORS = 3
MAX_POLL_DELAY_SECONDS = 15.0
SOURCE_PROFILE_TTL_SECONDS = 60.0
SOURCE_PROFILE_CACHE_LIMIT = 64
SourceProfileKey = Tuple[str, str, str, str, str]


class DashboardConflict(ValueError):
    """The plan already has a request that a different plan cannot reuse."""


class DashboardBindingChanged(ValueError):
    """The request was made on a different connection or Splunk user than the current one."""


@dataclass
class DashboardBinding:
    """The connection and verified Splunk user a request is sent with."""

    connection_name: str
    connection_label: str
    mcp: Any
    identity: str
    web_base: Optional[str]
    web_base_source: str
    splunk_user: str = ""

    def describe(self) -> Dict[str, Any]:
        return {
            "connection_label": self.connection_label,
            "splunk_user": self.splunk_user,
            "splunk_web_url": self.web_base or "",
            "splunk_web_url_source": self.web_base_source,
        }

    def matches(self, stored: Dict[str, Any]) -> bool:
        return all(stored.get(key) == getattr(self, key) for key in ("identity", "connection_name", "splunk_user"))


def identity_digest(runtime_identity: Optional[str]) -> str:
    return hashlib.sha256(str(runtime_identity or "").encode("utf-8")).hexdigest() if runtime_identity else ""


# ---------------------------------------------------------------- intent

_CREATE_VERBS = r"(?:create|build|make|generate|set\s+up|put\s+together|spin\s+up|draft|produce)"
_PANEL_QUANTITY = r"[1-6]|one|two|three|four|five|six"
_DASHBOARD = rf"(?:(?:splunk|dashboard\s+studio|studio|constellation)\s+)?(?:(?:{_PANEL_QUANTITY})-panel\s+)?dashboard\b(?!s)"
_LEAD_INS = r"(?:(?:ok(?:ay)?|yes|great|thanks|perfect|please|now|so|then|and|alright)[,!.]?\s+)*"
_ASKS = (
    r"(?:(?:can|could|would|will)\s+you\s+(?:please\s+)?|please\s+|go\s+ahead\s+and\s+"
    r"|i\s+(?:want|need|would\s+like|'d\s+like)\s+you\s+to\s+|let'?s\s+)?"
)
_CREATE_REQUEST_RE = re.compile(
    rf"^{_LEAD_INS}{_ASKS}{_CREATE_VERBS}\s+(?:me\s+|us\s+)?(?:a|an|the|one|this|that)?\s*"
    rf"(?:new\s+|quick\s+|simple\s+|small\s+|private\s+)?{_DASHBOARD}",
    re.IGNORECASE,
)
_WANT_RE = re.compile(
    rf"^{_LEAD_INS}i\s+(?:want|need|would\s+like|'d\s+like)\s+(?:a|an|one)\s+(?:new\s+)?{_DASHBOARD}",
    re.IGNORECASE,
)
_TURN_INTO_RE = re.compile(
    rf"^{_LEAD_INS}(?:(?:can|could|would)\s+you\s+(?:please\s+)?|please\s+)?(?:turn|convert|make)\s+"
    rf"(?:this|that|it|these|those|the\s+[\w-]+(?:\s+[\w-]+)?)\s+into\s+(?:a|an)\s+(?:new\s+)?{_DASHBOARD}",
    re.IGNORECASE,
)
_ADVICE_RE = re.compile(r"\b(?:how\s+(?:to|do|would|should|can)|steps\s+to|instructions|tutorial|explain)\b", re.IGNORECASE)
_PANEL_COUNT_WORDS = {word: count for count, word in enumerate(("one", "two", "three", "four", "five", "six"), 1)}
_PANEL_COUNT = re.compile(
    rf"\b(?:exactly|with)\s+(?P<total>{_PANEL_QUANTITY})\s+(?:panels?|charts?|visualizations?)\b"
    r"(?!\s+(?:per\s+page|(?:on|for)\s+each|each\b))"
    rf"|\b(?P<compound>{_PANEL_QUANTITY})-panel\s+dashboard\b",
    re.IGNORECASE,
)
_SINGLE_PAGE = re.compile(r"\b(?i:one|1|single)\s+(?:[A-Z][\w-]*[ \t]+){0,4}(?i:page)\b")
_DASHBOARD_CODE = re.compile(r"```.*?```|`[^`\n]+`", re.S)


def detect_dashboard_create_intent(message: Any) -> bool:
    """True only when the user's own words ask the app to create a dashboard now.

    Questions about how to build one, requests for ideas, and text pasted from reports do not count.
    """
    if not isinstance(message, str) or not message.strip():
        return False
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", message.strip()):
        cleaned = sentence.strip().strip("\"'`*").strip()
        if not cleaned:
            continue
        match = _CREATE_REQUEST_RE.match(cleaned) or _WANT_RE.match(cleaned) or _TURN_INTO_RE.match(cleaned)
        if match and not _ADVICE_RE.search(cleaned[: match.end() + 40]):
            return True
    return False


# ---------------------------------------------------------------- plan drafting


def requested_dashboard_panel_count(text: str) -> Optional[int]:
    """Return the unambiguous requested count, excluding quoted code and size ranges."""
    prose = _DASHBOARD_CODE.sub(" ", text)
    counts = set()
    for match in _PANEL_COUNT.finditer(prose):
        value = (match["total"] or match["compound"]).lower()
        counts.add(int(value) if value.isdecimal() else _PANEL_COUNT_WORDS[value])
    return next(iter(counts)) if len(counts) == 1 else None


def dashboard_requests_one_page(text: str) -> bool:
    return bool(_SINGLE_PAGE.search(_DASHBOARD_CODE.sub(" ", text)))


DASHBOARD_DESIGN = json.loads(Path(__file__).with_name("dashboard_design.json").read_text(encoding="utf-8"))

PLAN_SYSTEM_PROMPT = """You draft a dashboard plan for Constellation, which builds Splunk Dashboard Studio dashboards.
Use the latest request to decide what to draft. Resolve references such as "this" from the preceding conversation.
Keep any explicit title, source, measurements, and panels the user has already chosen unless the latest request changes them.
Use the discovery summary as supporting evidence only. Earlier requests in the context describe prior turns.
Reply with one JSON object and nothing else, in this form:
{"title": "...", "purpose": "...", "requirements": "...", "source": {"kind": "index", "index": "...", "sourcetype": "..."}, "time_range": {"earliest": "-24h", "latest": "now"}, "pages": [{"name": "Overview", "panels": ["...", "..."]}], "findings": ["..."]}
Rules:
- title: up to 120 characters. purpose: up to 500 characters, naming the question the dashboard answers and who it is for.
- requirements: optional, up to 1200 characters: units, metric definitions, exclusions, and how to treat missing data.
- source: either {"kind": "index", "index": "<one index>", "sourcetype": "<optional sourcetype>"} or {"kind": "spl", "query": "<one read-only search>"}. Use only indexes, sourcetypes, and searches named in the context. When "Selected SPL source" is supplied, omit source and use the search's output to plan panels. If no source fits, use an index source with an empty index.
- time_range earliest is one of -15m, -1h, -24h, -7d, and latest is always now.
- pages: one or two pages with different names (up to 60 characters). Each page has a "panels" array of one to four strings, six panels at most in total. Keep every explicitly requested panel in its requested order. Include its chart type and field bindings, and quote any supplied panel aggregation in the string (up to 240 characters).
- findings: optional, up to four short statements (up to 300 characters each) taken from the conversation or report. Use only facts stated there.
- Leave out raw events, user names, passwords, tokens, and web addresses."""


def build_plan_messages(request_text: str, context_sections: List[Tuple[str, str]]) -> List[Dict[str, str]]:
    parts = [f"Request: {request_text.strip()[:2000]}"]
    for heading, body in context_sections:
        cleaned = str(body or "").strip()
        if cleaned:
            parts.append(f"{heading}:\n{cleaned}")
    intent = "\n".join(parts).casefold()
    guidance = list(DASHBOARD_DESIGN["baseline"])
    guidance.extend(
        pattern["guidance"]
        for pattern in DASHBOARD_DESIGN["patterns"]
        if any(re.search(r"(?<!\w)" + re.escape(term) + r"(?!\w)", intent) for term in pattern["terms"])
    )
    design = "\n".join(f"- {rule}" for rule in guidance)
    return [
        {"role": "system", "content": f"{PLAN_SYSTEM_PROMPT}\n\nDashboard design guidance v{DASHBOARD_DESIGN['version']}\n{design}"},
        {"role": "user", "content": "\n\n".join(parts)},
    ]


def _short(value: Any, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip() if isinstance(value, (str, int, float)) else ""
    return text[:limit].rstrip()


def coerce_brief_draft(raw: Any, provenance: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Shape a model's answer into an editable plan, trimming to the limits. It may still need fixes."""
    data = raw if isinstance(raw, dict) else {}
    source = data.get("source") if isinstance(data.get("source"), dict) else {}
    if source.get("kind") == "spl" and _short(source.get("query"), LIMITS["query"]):
        draft_source: Dict[str, Any] = {"kind": "spl", "query": str(source.get("query")).strip()[: LIMITS["query"]]}
    else:
        draft_source = {"kind": "index", "index": _short(source.get("index"), 120)}
        sourcetype = _short(source.get("sourcetype"), 200)
        if sourcetype:
            draft_source["sourcetype"] = sourcetype
    time_range = data.get("time_range") if isinstance(data.get("time_range"), dict) else {}
    earliest = time_range.get("earliest") if time_range.get("earliest") in TIME_RANGES else "-24h"
    pages: List[Dict[str, Any]] = []
    total = 0
    seen = set()
    for page in data.get("pages") if isinstance(data.get("pages"), list) else []:
        if not isinstance(page, dict) or len(pages) >= LIMITS["pages"]:
            continue
        name = _short(page.get("name"), LIMITS["page_name"]) or f"Page {len(pages) + 1}"
        if name.casefold() in seen:
            name = f"{name[: LIMITS['page_name'] - 3]} {len(pages) + 1}"
        panels = []
        for panel in page.get("panels") if isinstance(page.get("panels"), list) else []:
            if isinstance(panel, dict):
                title = _short(panel.get("title") or panel.get("name"), LIMITS["panel"])
                description = _short(panel.get("description"), LIMITS["panel"])
                panel = ". ".join(part for part in (title, description) if part)
            text = _short(panel, LIMITS["panel"])
            if text and len(panels) < LIMITS["panels_per_page"] and total < LIMITS["panels_total"]:
                panels.append(text)
                total += 1
        if panels:
            seen.add(name.casefold())
            pages.append({"name": name, "panels": panels})
    draft: Dict[str, Any] = {
        "title": _short(data.get("title"), LIMITS["title"]) or "New dashboard",
        "purpose": _short(data.get("purpose"), LIMITS["purpose"]),
        "requirements": _short(data.get("requirements"), LIMITS["requirements"]),
        "source": draft_source,
        "time_range": {"earliest": earliest, "latest": "now"},
        "pages": pages,
        "findings": [
            text
            for text in (_short(item, LIMITS["finding"]) for item in (data.get("findings") or [])[: LIMITS["findings"]])
            if text
        ] if isinstance(data.get("findings"), list) else [],
    }
    if provenance:
        draft["provenance"] = {"kind": provenance["kind"], "label": _short(provenance.get("label"), LIMITS["provenance_label"])}
    return draft


_REQUEST_PREFIX_RE = re.compile(
    rf"^{_LEAD_INS}{_ASKS}(?:{_CREATE_VERBS}\s+(?:me\s+|us\s+)?(?:a|an|the|one)?\s*(?:new\s+)?{_DASHBOARD}"
    r"|i\s+(?:want|need|would\s+like|'d\s+like)\s+(?:a|an|one)\s+(?:new\s+)?(?:splunk\s+)?dashboard)"
    r"\s*(?:of|for|about|on|showing|tracking|monitoring|with"
    r"|that\s+(?:shows|tracks|lists|monitors|covers)|to\s+(?:show|track|monitor|cover))?\s*",
    re.IGNORECASE,
)


def fallback_brief_draft(
    request_text: str,
    known_index: str = "",
    provenance: Optional[Dict[str, str]] = None,
    topic: str = "",
) -> Dict[str, Any]:
    """A starter plan when the AI model cannot draft one. The user edits it before creating.

    ``topic`` names what the dashboard covers when the request text is not the user's own words.
    """
    topic = _short(topic, LIMITS["title"]) or _REQUEST_PREFIX_RE.sub("", str(request_text or "").strip()).strip(" .!?") or "Splunk activity"
    title = topic[:1].upper() + topic[1:]
    return coerce_brief_draft(
        {
            "title": title,
            "purpose": f"Track {topic} for the team reviewing this Splunk environment.",
            "source": {"kind": "index", "index": known_index},
            "time_range": {"earliest": "-24h", "latest": "now"},
            "pages": [{"name": "Overview", "panels": ["Event count", "Event arrivals over time", "Event counts by sourcetype"]}],
        },
        provenance,
    )


def plan_problems(draft: Dict[str, Any]) -> List[Dict[str, str]]:
    try:
        normalize_brief(draft)
    except BriefError as exc:
        return exc.problems
    return []


def new_proposal_id() -> str:
    return uuid.uuid4().hex


# ---------------------------------------------------------------- service

CallTool = Callable[[Any, str, Dict[str, Any], float], Awaitable[Dict[str, Any]]]


@dataclass
class _Outcome:
    status: str
    ambiguous: bool = False
    receipt: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, str]] = None


class DashboardService:
    def __init__(
        self,
        store: DashboardOperationStore,
        settings: Callable[[], Dict[str, Any]],
        binding_is_current: Callable[[DashboardBinding], bool],
        log: Callable[[str], None] = print,
        call: CallTool = call_tool,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.store = store
        self._settings = settings
        self._binding_is_current = binding_is_current
        self._log = log
        self._call = call
        self._sleep = sleep
        self._clock = clock
        self._tasks: Dict[str, asyncio.Task] = {}
        self._user_cache: Dict[str, Tuple[str, float]] = {}
        self._source_profiles: Dict[SourceProfileKey, Tuple[float, Dict[str, Any]]] = {}
        self._source_profile_tasks: Dict[SourceProfileKey, asyncio.Task] = {}
        self.recover_delay_seconds = 2.0

    # -- settings and identity

    def _timing(self, key: str, default: float) -> float:
        try:
            return float((self._settings() or {}).get(key, default))
        except (TypeError, ValueError):
            return default

    async def verify_splunk_user(self, binding: DashboardBinding) -> Tuple[Optional[str], str]:
        """The Splunk user the connection signs in as, from splunk_get_user_info."""
        cached = self._user_cache.get(binding.identity)
        if cached and self._clock() - cached[1] < USER_CACHE_SECONDS:
            return cached[0], ""
        reply = await self._call(binding.mcp, USER_INFO_TOOL, {}, self._timing("status_timeout_seconds", 20))
        username = parse_splunk_username(reply.get("body")) if reply.get("http_status") == 200 else None
        if not username:
            return None, (
                "Could not confirm which Splunk user this connection signs in as, so no dashboard can be created safely. "
                "Check the connection in Settings."
            )
        self._user_cache[binding.identity] = (username, self._clock())
        return username, ""

    async def check_authoring(self, binding: DashboardBinding) -> Dict[str, str]:
        """Check Constellation under the caller's token without sending a plan or recording a request."""
        username, problem = await self.verify_splunk_user(binding)
        if not username:
            return {"state": "identity_unavailable", "message": problem}
        binding.splunk_user = username
        request_id = new_request_id()
        arguments = build_tool_arguments(STATUS_TOOL, request_id, username)
        reply = await self._call(binding.mcp, STATUS_TOOL, arguments, self._timing("status_timeout_seconds", 20))
        parsed = parse_tool_response(reply.get("http_status"), reply.get("body"), str(reply.get("error") or ""))
        if parsed["kind"] == "domain_error" and parsed["code"] in {
            "feature_disabled", "identity_unavailable", "method_not_allowed", "pilot_configuration", "pilot_probe_only",
        }:
            return {"state": parsed["code"], "message": parsed["message"]}

        unconfirmed = {
            "state": "unconfirmed",
            "message": "Discovery could not confirm Constellation authoring. Check the connection and try again.",
        }
        if parsed["kind"] != "receipt" or reply.get("http_status") != 200:
            return unconfirmed
        payload = parsed["payload"]
        try:
            receipt = normalize_receipt(payload, request_id, binding.web_base)
        except ReceiptError:
            return unconfirmed
        if receipt["status"] != "not_found":
            return unconfirmed
        if "pilot" not in payload:
            return {
                "state": "legacy",
                "message": "This Constellation build accepted your Splunk identity but does not report whether authoring is enabled.",
            }
        pilot = payload["pilot"]
        if not isinstance(pilot, dict) or pilot.get("identity_verified") is not True:
            return unconfirmed
        mode = pilot.get("mode")
        if mode == "authoring":
            return {"state": "authoring", "message": f"Constellation authoring is enabled for Splunk user {username}."}
        if mode == "probe":
            return {"state": "pilot_probe_only", "message": error_message("pilot_probe_only")}
        if mode == "fixture":
            return {
                "state": "fixture",
                "message": (
                    "Constellation is in fixture mode, which only creates preset test dashboards. "
                    "Ask the Splunk administrator to enable authoring."
                ),
            }
        return unconfirmed

    # -- source inspection

    @staticmethod
    def _source_profile_key(owner: str, binding: DashboardBinding, scope: Dict[str, Any]) -> SourceProfileKey:
        digest = hashlib.sha256(serialize_brief(scope).encode("utf-8")).hexdigest()
        return owner, binding.identity, binding.connection_name, binding.splunk_user, digest

    def cached_source_profile(self, owner: str, binding: DashboardBinding, scope: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        key = self._source_profile_key(owner, binding, scope)
        entry = self._source_profiles.get(key)
        if entry is not None and entry[0] > self._clock():
            return entry[1]
        self._source_profiles.pop(key, None)
        return None

    async def inspect_source(
        self, owner: str, binding: DashboardBinding, scope: Dict[str, Any], *, refresh: bool = False
    ) -> Dict[str, Any]:
        """Join any inspection for this exact caller and scope, or make one read-only call."""
        cached = None if refresh else self.cached_source_profile(owner, binding, scope)
        if cached is not None:
            return cached
        key = self._source_profile_key(owner, binding, scope)
        task = self._source_profile_tasks.get(key)
        if task is None:
            if refresh:
                self._source_profiles.pop(key, None)
            task = asyncio.create_task(self._read_source_profile(key, binding, scope))
            self._source_profile_tasks[key] = task
        return await asyncio.shield(task)

    async def _read_source_profile(self, key: SourceProfileKey, binding: DashboardBinding, scope: Dict[str, Any]) -> Dict[str, Any]:
        try:
            reply = await self._call(binding.mcp, INSPECT_TOOL, {
                "schema_version": SCHEMA_VERSION,
                "expected_user": binding.splunk_user,
                "scope_json": serialize_brief(scope),
            }, 15.0)
            if reply.get("timed_out"):
                return {"status": "inconclusive", "sample": None, "fields": []}
            parsed = parse_tool_response(reply.get("http_status"), reply.get("body"), str(reply.get("error") or ""))
            profile = None
            if parsed["kind"] == "receipt" and reply.get("http_status") == 200:
                profile = normalize_source_profile(parsed["payload"], scope)
            if profile is None:
                return {"status": "unavailable", "sample": None, "fields": []}
            if len(self._source_profiles) >= SOURCE_PROFILE_CACHE_LIMIT:
                oldest = min(self._source_profiles, key=lambda entry: self._source_profiles[entry][0])
                self._source_profiles.pop(oldest)
            self._source_profiles[key] = (self._clock() + SOURCE_PROFILE_TTL_SECONDS, profile)
            return profile
        finally:
            self._source_profile_tasks.pop(key, None)

    # -- public view

    def is_polling(self, owner: str, request_id: str) -> bool:
        task = self._tasks.get(f"{owner}:{request_id}")
        return task is not None and not task.done()

    def public_operation(self, owner: str, record: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not record:
            return None
        receipt = record.get("receipt") if isinstance(record.get("receipt"), dict) else None
        binding = record.get("binding") if isinstance(record.get("binding"), dict) else {}
        brief = record.get("brief") if isinstance(record.get("brief"), dict) else None
        status = str(record.get("status") or "")
        request_id = str(record.get("request_id") or "")
        polling = self.is_polling(owner, request_id)
        error = record.get("error") if isinstance(record.get("error"), dict) else None
        code = (receipt or {}).get("code") or (error or {}).get("code") or ""
        return {
            "request_id": request_id,
            "proposal_id": record.get("proposal_id") or "",
            "status": status,
            "title": (receipt or {}).get("title") or record.get("title") or "",
            "receipt": dict(receipt) if receipt else None,
            "code_message": error_message(receipt["code"]) if receipt and receipt.get("code") else "",
            "error": error,
            "recovery": dashboard_recovery(status, code),
            "check_note": record.get("check_note") or "",
            "brief": dict(brief) if brief else None,
            "provenance": record.get("provenance") if isinstance(record.get("provenance"), dict) else None,
            "connection_label": binding.get("connection_label") or "",
            "splunk_user": binding.get("splunk_user") or "",
            "created_at": record.get("created_at"),
            "updated_at": record.get("updated_at"),
            "resent": bool(record.get("resent")),
            "polling": polling,
            "wait_stopped": bool(record.get("wait_stopped")) and not polling,
            "can_check": status not in {"error"} and not polling,
            "can_retry": status in RETRYABLE_STATES,
        }

    def list_operations(self, owner: str, limit: int = 20) -> List[Dict[str, Any]]:
        return [self.public_operation(owner, record) for record in self.store.list(owner, limit)]

    def get_operation(self, owner: str, request_id: str) -> Optional[Dict[str, Any]]:
        return self.public_operation(owner, self.store.get(owner, request_id))

    def repair_feedback(self, owner: str, request_id: str, binding: DashboardBinding) -> Optional[str]:
        record = self.store.get(owner, request_id)
        if record is None or not binding.matches(record.get("binding") or {}):
            return None
        recovery = (self.public_operation(owner, record) or {}).get("recovery") or {}
        return recovery.get("message") if recovery.get("focus") == "panels" else None

    # -- create

    def start_create(
        self,
        owner: str,
        proposal_id: str,
        brief_raw: Any,
        binding: DashboardBinding,
    ) -> Dict[str, Any]:
        """Save the request, then send it in the background. Raises BriefError or DashboardConflict."""
        brief = normalize_brief(brief_raw)
        brief_json = serialize_brief(brief)
        digest = brief_digest(brief)
        proposal_id = re.sub(r"[^a-f0-9]", "", str(proposal_id or "").lower())[:32] or new_proposal_id()

        def build(latest: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
            if latest is not None and latest.get("status") not in RETRYABLE_STATES:
                if latest.get("brief_digest") == digest:
                    return None
                raise DashboardConflict(
                    "This plan already has a dashboard request. Ask for a new dashboard in chat to start another one."
                )
            return {
                "request_id": new_request_id(),
                "proposal_id": proposal_id,
                "status": "sending",
                "title": brief["title"],
                "brief": brief,
                "brief_json": brief_json,
                "brief_digest": digest,
                "provenance": brief.get("provenance"),
                "binding": {
                    "connection_name": binding.connection_name,
                    "connection_label": binding.connection_label,
                    "identity": binding.identity,
                    "splunk_user": binding.splunk_user,
                    "web_base": binding.web_base or "",
                },
                "resent": False,
                "attempts": 0,
                "receipt": None,
                "error": None,
            }

        record = self.store.claim_for_proposal(owner, proposal_id, build)
        if not record.get("reused"):
            self._launch(owner, record["request_id"], self._run_create(owner, record["request_id"], binding))
        return self.public_operation(owner, self.store.get(owner, record["request_id"]))

    def _launch(self, owner: str, request_id: str, work: Awaitable[None]) -> None:
        key = f"{owner}:{request_id}"

        async def guarded() -> None:
            try:
                await work
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - a crash must leave the request checkable, not lost
                self._log(f"[DASHBOARDS] request worker stopped: {type(exc).__name__}")
                self.store.update(
                    owner,
                    request_id,
                    status="unconfirmed",
                    error={"code": "worker_stopped", "message": "The app stopped following this request. Check status."},
                )

        task = asyncio.create_task(guarded())
        self._tasks[key] = task
        task.add_done_callback(lambda _task: self._tasks.pop(key, None) if self._tasks.get(key) is _task else None)

    async def _send_create(self, owner: str, request_id: str, binding: DashboardBinding, record: Dict[str, Any]) -> _Outcome:
        arguments = build_tool_arguments(CREATE_TOOL, request_id, binding.splunk_user, record["brief_json"])
        self.store.update(
            owner,
            request_id,
            status="sending",
            attempts=int(record.get("attempts") or 0) + 1,
            sent_at=datetime.now(timezone.utc).isoformat(),
        )
        started = self._clock()
        reply = await self._call(binding.mcp, CREATE_TOOL, arguments, self._timing("create_timeout_seconds", 180))
        outcome = self._apply(owner, request_id, binding, reply, "create")
        self._log(
            f"[DASHBOARDS] create reply: {outcome.status}"
            f"{' code=' + outcome.error['code'] if outcome.error else ''} after {self._clock() - started:.1f}s"
        )
        return outcome

    async def _run_create(self, owner: str, request_id: str, binding: DashboardBinding) -> None:
        record = self.store.get(owner, request_id)
        if not record or not record.get("brief_json"):
            return
        outcome = await self._send_create(owner, request_id, binding, record)
        await self._follow(owner, request_id, binding, outcome)

    async def _follow(self, owner: str, request_id: str, binding: DashboardBinding, outcome: _Outcome) -> None:
        if outcome.ambiguous:
            await self._sleep(self.recover_delay_seconds)
            outcome = await self._status(owner, request_id, binding)
            if outcome.status == "not_found":
                outcome = await self._handle_not_found(owner, request_id, binding, allow_resend=True)
                if outcome.ambiguous:
                    await self._sleep(self.recover_delay_seconds)
                    outcome = await self._status(owner, request_id, binding)
                    if outcome.status == "not_found":
                        outcome = await self._handle_not_found(owner, request_id, binding, False)
        if outcome.status == "running":
            await self._poll(owner, request_id, binding, outcome)

    async def _handle_not_found(self, owner: str, request_id: str, binding: DashboardBinding, allow_resend: bool) -> _Outcome:
        """Resolve an authoritative miss. Only the initial Create flow can resend."""
        record = self.store.get(owner, request_id) or {}
        if record.get("status") in TERMINAL_STATUSES - {"not_found"}:
            self.store.update(owner, request_id, check_note="Splunk returned no receipt for this request on this connection.")
            return _Outcome(status=str(record.get("status")))
        previous_receipt = record.get("receipt")
        if isinstance(previous_receipt, dict) and previous_receipt.get("status") == "running":
            self.store.update(
                owner, request_id, status="unconfirmed", wait_stopped=True,
                check_note="Splunk previously accepted this request. Check Status again to recover its receipt.",
            )
            return _Outcome(status="unconfirmed")
        if (
            allow_resend
            and not record.get("resent")
            and record.get("status") in {"sending", "unconfirmed"}
            and record.get("brief_json")
            and request_id_is_fresh(request_id)
            and self._binding_is_current(binding)
        ):
            self.store.update(owner, request_id, resent=True)
            return await self._send_create(owner, request_id, binding, self.store.get(owner, request_id) or record)
        receipt = {"schema_version": "1", "request_id": request_id, "status": "not_found", "warnings": []}
        self.store.update(
            owner, request_id, status="not_found", receipt=receipt, error=None, check_note="", wait_stopped=False,
        )
        return _Outcome(status="not_found", receipt=receipt)

    async def _status(self, owner: str, request_id: str, binding: DashboardBinding) -> _Outcome:
        arguments = build_tool_arguments(STATUS_TOOL, request_id, binding.splunk_user)
        reply = await self._call(binding.mcp, STATUS_TOOL, arguments, self._timing("status_timeout_seconds", 20))
        return self._apply(owner, request_id, binding, reply, "status")

    async def _poll(self, owner: str, request_id: str, binding: DashboardBinding, outcome: _Outcome) -> None:
        deadline = self._clock() + self._timing("max_wait_seconds", 600)
        delay = max(1.0, float((outcome.receipt or {}).get("poll_after_ms", 2000)) / 1000.0)
        errors = 0
        while True:
            if self._clock() + delay > deadline:
                self.store.update(owner, request_id, wait_stopped=True)
                self._log("[DASHBOARDS] stopped waiting for a running request")
                return
            await self._sleep(delay)
            if not self._binding_is_current(binding):
                self.store.update(
                    owner,
                    request_id,
                    wait_stopped=True,
                    check_note="The Splunk connection changed, so the app stopped checking. Switch back to check status.",
                )
                return
            outcome = await self._status(owner, request_id, binding)
            if outcome.status == "running":
                errors = 0
                hint = float((outcome.receipt or {}).get("poll_after_ms", 2000)) / 1000.0
                delay = min(max(hint, delay * 1.5), MAX_POLL_DELAY_SECONDS)
                continue
            if outcome.status == "not_found":
                await self._handle_not_found(owner, request_id, binding, False)
                return
            if outcome.ambiguous:
                errors += 1
                if errors >= MAX_STATUS_ERRORS:
                    self.store.update(owner, request_id, wait_stopped=True)
                    return
                delay = min(delay * 2, MAX_POLL_DELAY_SECONDS)
                continue
            return

    def _apply(self, owner: str, request_id: str, binding: DashboardBinding, reply: Dict[str, Any], kind: str) -> _Outcome:
        """Record one reply. Status replies never turn a finished request into a failure."""
        parsed = parse_tool_response(reply.get("http_status"), reply.get("body"), str(reply.get("error") or ""))
        record = self.store.get(owner, request_id) or {}
        current = str(record.get("status") or "")
        finished = current in TERMINAL_STATUSES - {"not_found"}
        if parsed["kind"] == "receipt":
            try:
                receipt = normalize_receipt(parsed["payload"], request_id, binding.web_base)
            except ReceiptError as exc:
                error = {"code": exc.code, "message": f"This app could not read Splunk's reply: {exc}"}
                if kind == "create" or not finished:
                    self.store.update(owner, request_id, status="unconfirmed", error=error)
                else:
                    self.store.update(owner, request_id, check_note=error["message"])
                return _Outcome(status="unconfirmed", ambiguous=True, error=error)
            if receipt["status"] == "not_found":
                pilot = parsed["payload"].get("pilot")
                # Build 65 answers status probes without consulting the ledger.
                if kind == "status" and isinstance(pilot, dict) and pilot.get("mode") == "probe":
                    self.store.update(
                        owner, request_id,
                        status="unconfirmed" if current in ACTIVE_STATES else current,
                        wait_stopped=True,
                        check_note="Constellation is in probe mode. Check Status again when authoring is available.",
                    )
                    return _Outcome(status="unconfirmed")
                return _Outcome(status="not_found", receipt=receipt)
            self.store.update(
                owner,
                request_id,
                status=receipt["status"],
                receipt=receipt,
                error=None,
                check_note="",
                wait_stopped=False,
            )
            return _Outcome(status=receipt["status"], receipt=receipt)
        if parsed["kind"] == "domain_error":
            error = {"code": parsed["code"], "message": parsed["message"]}
            if kind == "create" and not parsed["ambiguous"]:
                self.store.update(owner, request_id, status="failed", error=error, receipt=None)
                return _Outcome(status="failed", error=error)
            if kind == "create" or current in ACTIVE_STATES:
                self.store.update(owner, request_id, status="unconfirmed" if kind == "create" else current, error=error)
            else:
                self.store.update(owner, request_id, check_note=error["message"])
            return _Outcome(status="unconfirmed", ambiguous=True, error=error)
        timed_out = bool(reply.get("timed_out"))
        error = {
            "code": "timeout" if timed_out else "transport",
            "message": (
                "Splunk did not answer in time. The dashboard may still be in progress. Check status."
                if timed_out
                else f"{parsed.get('message') or 'The Splunk MCP server did not answer.'} Check status."
            ),
        }
        if kind == "create" or current in ACTIVE_STATES:
            self.store.update(owner, request_id, status="unconfirmed" if kind == "create" else current, error=error)
        else:
            self.store.update(owner, request_id, check_note=error["message"])
        return _Outcome(status="unconfirmed", ambiguous=True, error=error)

    # -- check status

    async def check_status(self, owner: str, request_id: str, binding: DashboardBinding) -> Optional[Dict[str, Any]]:
        """Read the receipt. Raises DashboardBindingChanged on a different connection or user."""
        record = self.store.get(owner, request_id)
        if record is None:
            return None
        bound = record.get("binding") if isinstance(record.get("binding"), dict) else {}
        if not binding.matches(bound):
            label = bound.get("connection_label") or "another connection"
            raise DashboardBindingChanged(
                f"This request was made on {label} as a different Splunk connection or user. Switch back to that connection to check it."
            )
        if self.is_polling(owner, request_id):
            return self.public_operation(owner, record)
        stored_binding = DashboardBinding(
            connection_name=binding.connection_name,
            connection_label=binding.connection_label,
            mcp=binding.mcp,
            identity=binding.identity,
            web_base=bound.get("web_base") or binding.web_base,
            web_base_source=binding.web_base_source,
            splunk_user=binding.splunk_user,
        )
        outcome = await self._status(owner, request_id, stored_binding)
        if outcome.status == "not_found":
            await self._handle_not_found(owner, request_id, stored_binding, False)
        elif outcome.status == "running":
            self.store.update(owner, request_id, wait_stopped=False)
            self._launch(owner, request_id, self._poll(owner, request_id, stored_binding, outcome))
        return self.get_operation(owner, request_id)
