"""Per-request incognito state, the record of what the AI saw, and the note that explains stand-ins.

Incognito state travels with a request through a context variable, so the shared model client
can apply it without every caller passing it along. Worker processes set it from their job.
"""

from __future__ import annotations

import contextvars
import json
import threading
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

from .masker import Masker
from .vault import VaultError

# The examples use NNNN rather than real numbers so the note never matches a stand-in in use.
INCOGNITO_NOTICE = (
    "Privacy note: names in this conversation are stand-ins, not real values. Each stand-in is a prefix and a "
    "number, written here as NNNN: hosts are host_NNNN, custom indexes idx_NNNN, users user_NNNN, apps app_NNNN, "
    "saved searches search_NNNN, knowledge objects object_NNNN, KV store collections kv_NNNN, roles role_NNNN, "
    "secrets secret_NNNN, other masked names term_NNNN, emails email_NNNN@example.com, and domains "
    "domain_NNNN.example. IP addresses are replaced with addresses that keep subnet grouping: 198.18.x.x and "
    "240-247.x.x.x stand for internal addresses, while 192.0.2.x, 198.51.100.x, 203.0.113.x, and 248-254.x.x.x "
    "stand for public ones; IPv6 addresses use 2001:db8::. Splunk's own indexes, sourcetypes, fields, and apps "
    "keep their real names. Use stand-ins exactly as written, including inside SPL. Never invent new stand-ins or "
    "guess the real names behind them; the user sees the real names."
)

MAX_LEDGER_CALLS = 24
MAX_LEDGER_TEXT = 60000

REASON_LABELS = {
    "off": "Incognito mode is off.",
    "job_started_incognito": "Incognito mode stays on because this job started in incognito mode.",
    "user_choice": "Incognito mode is on because you turned it on.",
    "default": "Incognito mode is on by default for this server.",
    "required_for_cloud": "Incognito mode is required by your administrator while a cloud AI model is in use.",
}


class IncognitoBlocked(RuntimeError):
    """Raised instead of sending anything when masking cannot be completed safely."""

    def __init__(self, message: str, *, reason: str = "leak", namespaces: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.reason = reason
        self.namespaces = list(namespaces)


@dataclass(frozen=True)
class IncognitoState:
    active: bool = False
    locked: bool = False
    reason: str = "off"
    provider_kind: str = "local"
    owner: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("owner", None)
        data["explanation"] = REASON_LABELS.get(self.reason, "")
        return data


def _clip(text: Any) -> Any:
    if isinstance(text, str) and len(text) > MAX_LEDGER_TEXT:
        head = int(MAX_LEDGER_TEXT * 0.7)
        tail = MAX_LEDGER_TEXT - head
        return text[:head] + f"\n...[{len(text) - MAX_LEDGER_TEXT} characters not shown]...\n" + text[-tail:]
    return text


def _with_notice(messages: List[Any]) -> List[Any]:
    for index, message in enumerate(messages):
        if isinstance(message, dict) and message.get("role") == "system" and isinstance(message.get("content"), str):
            updated = dict(message)
            updated["content"] = f"{message['content']}\n\n{INCOGNITO_NOTICE}"
            return messages[:index] + [updated] + messages[index + 1:]
    return [{"role": "system", "content": INCOGNITO_NOTICE}] + messages


class IncognitoSession:
    """Incognito state for one request or job, plus the record of what was sent."""

    def __init__(self, state: IncognitoState, masker: Optional[Masker] = None, *, feature: str = "chat",
                 error: Optional[str] = None) -> None:
        self.state = state
        self.masker = masker
        self.feature = feature
        self.error = error
        self._lock = threading.Lock()
        self.calls: List[Dict[str, Any]] = []
        self.trimmed_calls = 0
        self.used: Dict[str, set] = {}
        self._shown: set = set()
        self.unknown: List[str] = []
        self.blocked: Optional[str] = None
        self.ledger_id: Optional[str] = None
        self._last_sent: List[Tuple[str, str]] = []

    @property
    def active(self) -> bool:
        return self.state.active

    # ----- masking -------------------------------------------------------------------------

    @contextmanager
    def _vault_guard(self) -> Iterator[None]:
        try:
            yield
        except VaultError as exc:
            message = f"{exc} Nothing was sent to the AI model."
            self.blocked = message
            raise IncognitoBlocked(message, reason="unavailable") from exc

    def _require_masker(self) -> Masker:
        if self.error or self.masker is None:
            message = self.error or "Incognito mode could not start, so nothing was sent to the AI model."
            self.blocked = message
            raise IncognitoBlocked(message, reason="unavailable")
        return self.masker

    def _block_for(self, leaks: Sequence[Tuple[str, str]]) -> None:
        kinds = sorted({namespace for namespace, _value in leaks})
        message = (
            "Incognito mode stopped this request because some values could not be replaced "
            f"({', '.join(kinds)}). Nothing was sent to the AI model."
        )
        self.blocked = message
        raise IncognitoBlocked(message, reason="leak", namespaces=kinds)

    def _note_used(self, masked: str) -> None:
        if self.masker is None:
            return
        found = self.masker.stand_ins_in(masked)
        with self._lock:
            for namespace, stand_ins in found.items():
                self.used.setdefault(namespace, set()).update(stand_ins)
                self._shown.update(stand_ins)

    def _was_shown(self, key: str) -> bool:
        with self._lock:
            return key in self._shown

    def mask_text(self, text: Any) -> Any:
        """Mask text and confirm nothing identifying is left, or raise IncognitoBlocked."""
        if not isinstance(text, str) or not text:
            return text
        masker = self._require_masker()
        with self._vault_guard():
            masked = masker.mask_text(text)
            leaks = masker.find_leaks(masked)
            if leaks:
                masked = masker.mask_text(masked)
                leaks = masker.find_leaks(masked)
        if leaks:
            self._block_for(leaks)
        self._note_used(masked)
        return masked

    def mask_messages(self, messages: Sequence[Any]) -> List[Any]:
        masker = self._require_masker()
        terms_version = masker.vault.terms_version
        masked = self._mask_messages_once(messages)
        if masker.vault.terms_version != terms_version:
            # A later message (such as tool rows) can name something an earlier message mentions in passing.
            masked = self._mask_messages_once(messages)
        return masked

    def _mask_messages_once(self, messages: Sequence[Any]) -> List[Any]:
        masked: List[Any] = []
        for message in messages:
            if not isinstance(message, dict):
                masked.append(self.mask_text(message) if isinstance(message, str) else message)
                continue
            copy = dict(message)
            content = copy.get("content")
            if isinstance(content, str):
                copy["content"] = self.mask_text(content)
            elif isinstance(content, list):
                parts = []
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        part = dict(part)
                        part["text"] = self.mask_text(part["text"])
                    elif isinstance(part, str):
                        part = self.mask_text(part)
                    parts.append(part)
                copy["content"] = parts
            masked.append(copy)
        return masked

    def mask_request(self, *, prompt: Optional[str] = None, messages: Optional[Sequence[Any]] = None
                     ) -> Tuple[Optional[str], Optional[List[Any]]]:
        """Mask a model request and add the stand-in note. Returns ``(prompt, messages)``."""
        masked_messages = None
        masked_prompt = None
        if messages is not None:
            masked_messages = _with_notice(self.mask_messages(messages))
        if prompt is not None:
            masked_prompt = self.mask_text(prompt)
            if messages is None:
                masked_prompt = f"{INCOGNITO_NOTICE}\n\n{masked_prompt}"
        return masked_prompt, masked_messages

    def _mask_structure_checked(self, data: Any, hint: Optional[str] = None) -> Any:
        masker = self._require_masker()
        with self._vault_guard():
            masked = masker.mask_structure(data, hint=hint)
            leaks = masker.find_leaks(json.dumps(masked, default=str))
            if leaks:
                masked = masker.mask_structure(masked, hint=hint)
                leaks = masker.find_leaks(json.dumps(masked, default=str))
        if leaks:
            self._block_for(leaks)
        self._note_used(json.dumps(masked, default=str))
        return masked

    def mask_data(self, data: Any, *, hint: Optional[str] = None) -> Any:
        """Mask structured data sent for analysis, adding the stand-in note when it is a mapping."""
        masked = self._mask_structure_checked(data, hint)
        if isinstance(masked, dict):
            masked = {"incognito_note": INCOGNITO_NOTICE, **masked}
        return masked

    def mask_export(self, value: Any) -> Any:
        """Mask text or data for a copy people can share. Unlike model requests, no note is added."""
        if isinstance(value, str):
            return self.mask_text(value)
        return self._mask_structure_checked(value)

    def learn_names(self, inventory: Mapping[str, Iterable[Any]]) -> int:
        """Register names found during this request (such as by discovery) so they are masked from now on.

        If they cannot be recorded, later model calls in this session are stopped rather than sent
        without them.
        """
        masker = self._require_masker()
        try:
            return masker.seed(inventory)
        except Exception as exc:  # noqa: BLE001 - any failure here must stop later calls
            self.error = f"Incognito mode could not record the names discovery found ({exc}), so nothing more was sent to the AI model."
            self.blocked = self.error
            raise IncognitoBlocked(self.error, reason="unavailable") from exc

    def mask_rows(self, rows: Sequence[Any], *, hint: Optional[str] = None, splunk_apps: bool = False) -> List[Any]:
        masker = self._require_masker()
        with self._vault_guard():
            return masker.mask_rows(rows, hint=hint, splunk_apps=splunk_apps)

    # ----- restoring -----------------------------------------------------------------------

    def _note_unknown(self, unknown: Sequence[str]) -> None:
        with self._lock:
            for item in unknown:
                if item not in self.unknown:
                    self.unknown.append(item)

    def restore_text(self, text: Any) -> Any:
        if self.masker is None or not isinstance(text, str):
            return text
        restored, unknown = self.masker.restore_reply(text, self._was_shown)
        self._note_unknown(unknown)
        return restored

    def restore_data(self, data: Any) -> Any:
        if self.masker is None:
            return data
        restored, unknown = self.masker.restore_structure(data, self._was_shown)
        self._note_unknown(unknown)
        return restored

    def unknown_in(self, value: Any) -> List[str]:
        """Stand-ins in ``value`` (text or data) the model was never shown, such as ones it invented."""
        if self.masker is None:
            return []
        return self.masker.unknown_stand_ins(value, self._was_shown)

    # ----- record of what the AI saw -------------------------------------------------------

    def record(self, *, feature: Optional[str] = None, prompt: Optional[str] = None,
               messages: Optional[Sequence[Any]] = None, data: Any = None, reply: Any = None) -> None:
        entry: Dict[str, Any] = {
            "feature": feature or self.feature,
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        if messages is not None:
            flattened = [
                (str(message.get("role") or "user"), message.get("content") if isinstance(message.get("content"), str)
                 else json.dumps(message.get("content"), default=str))
                for message in messages if isinstance(message, dict)
            ]
            with self._lock:
                previous = self._last_sent
                self._last_sent = flattened
            shared = 0
            while shared < len(previous) and shared < len(flattened) and previous[shared] == flattened[shared]:
                shared += 1
            entry["earlier_messages"] = shared
            entry["messages"] = [{"role": role, "content": _clip(content)} for role, content in flattened[shared:]]
        if prompt is not None:
            entry["prompt"] = _clip(prompt)
        if data is not None:
            entry["data"] = _clip(json.dumps(data, indent=1, default=str))
        if reply is not None:
            entry["reply"] = _clip(reply if isinstance(reply, str) else json.dumps(reply, indent=1, default=str))
        with self._lock:
            self.calls.append(entry)
            if len(self.calls) > MAX_LEDGER_CALLS:
                self.calls.pop(0)
                self.trimmed_calls += 1

    def masked_counts(self) -> Dict[str, int]:
        with self._lock:
            return {namespace: len(values) for namespace, values in sorted(self.used.items()) if values}

    def describe(self) -> Dict[str, Any]:
        """Summary for API responses. Contains no real names."""
        summary = self.state.to_dict()
        summary.update(
            {
                "masked": self.masked_counts(),
                "calls": len(self.calls) + self.trimmed_calls,
                "unknown_stand_ins": list(self.unknown[:20]),
                "blocked": self.blocked,
                "ledger_id": self.ledger_id,
            }
        )
        return summary

    def ledger_payload(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "state": self.state.to_dict(),
            "masked": self.masked_counts(),
            "unknown_stand_ins": list(self.unknown[:50]),
            "blocked": self.blocked,
            "trimmed_calls": self.trimmed_calls,
            "calls": list(self.calls),
        }


_CURRENT: contextvars.ContextVar[Optional[IncognitoSession]] = contextvars.ContextVar("incognito_session", default=None)


def current_session() -> Optional[IncognitoSession]:
    return _CURRENT.get()


@contextmanager
def session_scope(session: Optional[IncognitoSession]) -> Iterator[Optional[IncognitoSession]]:
    token = _CURRENT.set(session)
    try:
        yield session
    finally:
        _CURRENT.reset(token)
