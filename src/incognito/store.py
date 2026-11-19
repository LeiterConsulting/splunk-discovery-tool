"""Encrypted storage for the incognito policy, each person's choice, stand-in vaults, and AI-view records."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .masker import Masker, MaskSettings
from .session import IncognitoSession, IncognitoState
from .vault import StandInVault, VaultError, file_lock, write_private_file

MAX_TERMS = 500
MAX_TERM_LENGTH = 200
LEDGER_LIMIT = 300
_LEDGER_ID = re.compile(r"^[A-Za-z0-9_-]{8,48}$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_terms(values: Iterable[Any]) -> List[str]:
    """Trim, de-duplicate (ignoring case), and cap a list of admin-entered terms."""
    cleaned: List[str] = []
    seen = set()
    for value in values or ():
        text = " ".join(str(value or "").split())
        if len(text) < 2 or len(text) > MAX_TERM_LENGTH:
            continue
        lowered = text.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        cleaned.append(text)
        if len(cleaned) >= MAX_TERMS:
            break
    return cleaned


@dataclass
class IncognitoPolicy:
    force_for_cloud: bool = False
    default_on: bool = False
    always_mask_terms: List[str] = field(default_factory=list)
    keep_visible_terms: List[str] = field(default_factory=list)
    updated_at: str = ""
    updated_by: str = ""
    unreadable: bool = False

    @classmethod
    def from_dict(cls, data: Any) -> "IncognitoPolicy":
        if not isinstance(data, dict):
            return cls()
        return cls(
            force_for_cloud=bool(data.get("force_for_cloud", False)),
            default_on=bool(data.get("default_on", False)),
            always_mask_terms=clean_terms(data.get("always_mask_terms") or []),
            keep_visible_terms=clean_terms(data.get("keep_visible_terms") or []),
            updated_at=str(data.get("updated_at") or ""),
            updated_by=str(data.get("updated_by") or ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if not self.unreadable:
            data.pop("unreadable", None)
        return data

    def mask_settings(self) -> MaskSettings:
        return MaskSettings.from_terms(self.always_mask_terms, self.keep_visible_terms)


def resolve_state(policy: IncognitoPolicy, preference: Optional[bool], provider_kind: str, owner: str = "") -> IncognitoState:
    if policy.force_for_cloud and provider_kind == "cloud":
        return IncognitoState(True, True, "required_for_cloud", provider_kind, owner)
    if preference is not None:
        return IncognitoState(bool(preference), False, "user_choice", provider_kind, owner)
    if policy.default_on:
        return IncognitoState(True, False, "default", provider_kind, owner)
    return IncognitoState(False, False, "off", provider_kind, owner)


class IncognitoStore:
    """Files under one folder, all encrypted with the application's key."""

    def __init__(self, root: Path, fernet) -> None:
        self.root = Path(root)
        self._fernet = fernet
        self._lock = threading.RLock()
        self._vaults: Dict[str, StandInVault] = {}
        self._maskers: Dict[Tuple[str, MaskSettings], Masker] = {}

    # ----- encrypted files -------------------------------------------------------------------

    def _read(self, path: Path) -> Any:
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return None
        return json.loads(self._fernet.decrypt(raw).decode("utf-8"))

    def _write(self, path: Path, data: Any) -> None:
        payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        write_private_file(path, self._fernet.encrypt(payload))

    @property
    def _policy_path(self) -> Path:
        return self.root / "policy.enc"

    @property
    def _preferences_path(self) -> Path:
        return self.root / "preferences.enc"

    # ----- policy ----------------------------------------------------------------------------

    def load_policy(self) -> IncognitoPolicy:
        try:
            data = self._read(self._policy_path)
        except Exception:  # noqa: BLE001 - an unreadable policy must not silently turn masking off
            return IncognitoPolicy(force_for_cloud=True, default_on=True, unreadable=True)
        return IncognitoPolicy.from_dict(data) if data is not None else IncognitoPolicy()

    def save_policy(self, policy: IncognitoPolicy, *, updated_by: str = "") -> IncognitoPolicy:
        cleaned = IncognitoPolicy.from_dict(policy.to_dict())
        cleaned.updated_at = _now()
        cleaned.updated_by = str(updated_by or "")
        with self._lock, file_lock(self.root / "policy.lock"):
            self._write(self._policy_path, cleaned.to_dict())
        return cleaned

    # ----- per-person choice -----------------------------------------------------------------

    def _load_preferences(self) -> Dict[str, Any]:
        try:
            data = self._read(self._preferences_path)
        except Exception:  # noqa: BLE001 - lost choices fall back to the policy default
            return {}
        owners = data.get("owners") if isinstance(data, dict) else None
        return owners if isinstance(owners, dict) else {}

    def get_preference(self, owner: str) -> Optional[bool]:
        entry = self._load_preferences().get(str(owner))
        if isinstance(entry, dict) and isinstance(entry.get("enabled"), bool):
            return entry["enabled"]
        return None

    def set_preference(self, owner: str, enabled: Optional[bool]) -> None:
        with self._lock, file_lock(self.root / "preferences.lock"):
            owners = self._load_preferences()
            if enabled is None:
                owners.pop(str(owner), None)
            else:
                owners[str(owner)] = {"enabled": bool(enabled), "updated_at": _now()}
            self._write(self._preferences_path, {"owners": owners})

    def resolve_state(self, owner: str, provider_kind: str, policy: Optional[IncognitoPolicy] = None) -> IncognitoState:
        policy = policy or self.load_policy()
        return resolve_state(policy, self.get_preference(owner), provider_kind, owner)

    # ----- vaults ----------------------------------------------------------------------------

    @staticmethod
    def scope_id(scope: str) -> str:
        return hashlib.sha256(str(scope or "global").encode("utf-8")).hexdigest()[:24]

    def vault(self, scope: str) -> StandInVault:
        key = self.scope_id(scope)
        with self._lock:
            vault = self._vaults.get(key)
            if vault is None:
                vault = StandInVault(self.root / "vaults" / f"{key}.vault", self._fernet)
                self._vaults[key] = vault
            return vault

    def masker(self, scope: str, policy: Optional[IncognitoPolicy] = None) -> Masker:
        policy = policy or self.load_policy()
        settings = policy.mask_settings()
        key = (self.scope_id(scope), settings)
        with self._lock:
            masker = self._maskers.get(key)
            if masker is None:
                masker = Masker(self.vault(scope), settings)
                self._maskers = {k: v for k, v in self._maskers.items() if k[0] != key[0]}
                self._maskers[key] = masker
            return masker

    def rotate(self, scope: str) -> None:
        key = self.scope_id(scope)
        with self._lock:
            vault = self._vaults.get(key)
            if vault is None:
                path = self.root / "vaults" / f"{key}.vault"
                with file_lock(path.with_name(path.name + ".lock")):
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
            else:
                vault.rotate()
            self._maskers = {k: v for k, v in self._maskers.items() if k[0] != key}

    def open_session(self, *, owner: str, provider_kind: str, scope: str, feature: str = "chat",
                     state: Optional[IncognitoState] = None) -> IncognitoSession:
        policy = self.load_policy()
        if state is None:
            state = resolve_state(policy, self.get_preference(owner), provider_kind, owner)
        elif not state.owner:
            state = replace(state, owner=str(owner))
        if not state.active:
            return IncognitoSession(state, None, feature=feature)
        try:
            masker = self.masker(scope, policy)
        except VaultError as exc:
            return IncognitoSession(state, None, feature=feature, error=f"{exc} Nothing was sent to the AI model.")
        return IncognitoSession(state, masker, feature=feature)

    # ----- records of what the AI saw --------------------------------------------------------

    def save_ledger(self, session: IncognitoSession) -> Optional[str]:
        if not session.calls and not session.blocked:
            return None
        ledger_id = secrets.token_urlsafe(12)
        session.ledger_id = ledger_id
        payload = session.ledger_payload()
        payload["owner"] = session.state.owner
        payload["ledger_id"] = ledger_id
        folder = self.root / "ledger"
        self._write(folder / f"{ledger_id}.rec", payload)
        self._prune_ledger(folder)
        return ledger_id

    @staticmethod
    def _prune_ledger(folder: Path) -> None:
        try:
            records = sorted(folder.glob("*.rec"), key=lambda path: path.stat().st_mtime)
        except OSError:
            return
        for path in records[:-LEDGER_LIMIT] if len(records) > LEDGER_LIMIT else []:
            try:
                path.unlink()
            except OSError:
                pass

    def load_ledger(self, owner: str, ledger_id: str) -> Optional[Dict[str, Any]]:
        if not _LEDGER_ID.match(str(ledger_id or "")):
            return None
        try:
            payload = self._read(self.root / "ledger" / f"{ledger_id}.rec")
        except Exception:  # noqa: BLE001 - an unreadable record is treated as missing
            return None
        if not isinstance(payload, dict) or payload.get("owner") != str(owner):
            return None
        payload.pop("owner", None)
        return payload
