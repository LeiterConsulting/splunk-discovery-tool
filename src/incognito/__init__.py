"""Incognito mode: replace a deployment's own names with stand-ins before anything reaches an AI model."""

from .client import IncognitoLLMClient
from .masker import Masker, MaskSettings, RAW_EVENT_FIELDS, row_hint_for_tool
from .provider import provider_kind
from .session import (
    INCOGNITO_NOTICE,
    IncognitoBlocked,
    IncognitoSession,
    IncognitoState,
    current_session,
    session_scope,
)
from .store import IncognitoPolicy, IncognitoStore, clean_terms, resolve_state
from .vault import StandInVault, VaultError

__all__ = [
    "INCOGNITO_NOTICE",
    "IncognitoBlocked",
    "IncognitoLLMClient",
    "IncognitoPolicy",
    "IncognitoSession",
    "IncognitoState",
    "IncognitoStore",
    "MaskSettings",
    "Masker",
    "RAW_EVENT_FIELDS",
    "StandInVault",
    "VaultError",
    "clean_terms",
    "current_session",
    "provider_kind",
    "resolve_state",
    "row_hint_for_tool",
    "session_scope",
]
