"""
FastAPI Web Application for Splunk Discovery Tool

A modern web-based interface providing real-time progress tracking,
animated progress indicators, and comprehensive report management.
"""

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import asyncio
import base64
import copy
import ctypes
from contextlib import suppress
from collections import deque
import hashlib
import html
import json
import os
import re
import secrets
import signal
import time
import sys
import socket
import ssl
import subprocess
import threading
from urllib.parse import quote, urlencode
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import List, Dict, Any, Optional, Tuple
import uvicorn
import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa, utils
from pydantic import BaseModel, Field, ValidationError

# DT4SMS: Use encrypted config manager instead of YAML
from app_version import APP_VERSION
from config_manager import MASKED_SECRET, ConfigManager, is_unset_secret
from troubleshooting import capture_startup_state, run_llm_diagnostics, run_mcp_diagnostics, server_code_status
from capabilities import CapabilityManager, CapabilityRegistry
from discovery.engine import DiscoveryEngine
from discovery.m26_14_advisor import (
    build_profile_from_blueprint as build_m26_14_profile_from_blueprint,
    get_validation_pack as get_m26_14_validation_pack,
    list_validation_packs as list_m26_14_validation_packs,
    summarize_validation_results as summarize_m26_14_validation_results,
)
from discovery.v2_pipeline import DiscoveryV2Pipeline
from knowledge_library import LIBRARY_DIR_NAME
from knowledge_library.profile import build_environment_profile
from knowledge_library.ranking import query_terms as library_query_terms
from knowledge_library.service import KnowledgeLibraryService, LibraryBusyError
from knowledge_library.sources import MAX_PACK_BYTES, LibraryPackError
from llm.factory import (
    DEFAULT_OLLAMA_ENDPOINT_URL,
    LLMClientFactory,
    filter_openai_generation_models,
    get_openai_model_capabilities,
    is_openai_image_generation_model,
    normalize_ollama_endpoint_url,
    normalize_provider_name,
)
from llm.model_profiles import (
    budget_tokens,
    chat_budgets,
    describe_profile,
    parse_ollama_model_entry,
    parse_openai_compatible_model_entry,
    rank_models,
    remember_model_metadata,
)
from llm.runtime_tuning import (
    client_tuning,
    lookup_model_metadata,
    resolve_llm_tuning,
    runtime_provider_for,
)
from discovery.context_manager import get_context_manager
from discovery.local_analyzer import metadata_recent_time_utc
from chat_settings import (
    CHAT_DATA_DIR_NAME,
    ChatSettingsStore,
    ChatSettingsView,
    apply_custom_values,
    model_defaults,
    model_identity,
    reset_custom_values,
    resolve_chat_settings,
)
from chat_goals import (
    MAX_GOAL_CHARS,
    ChatGoalStore,
    GoalLimitError,
    GoalNotFoundError,
    build_plan_messages,
    build_progress_messages,
    fallback_plan,
    goal_detail,
    owner_key,
    parse_plan,
    parse_progress,
    progress_brief,
)
from chat_goals import clean_id as clean_goal_id
from chat_goals import clean_text as clean_goal_text
from chat_goals import pending_turns as pending_goal_turns
from chat_agent import (
    announces_unexecuted_search,
    build_grounded_chat_prompt,
    build_tool_catalog_text,
    build_tool_feedback,
    classify_tool_result,
    format_mission_context,
    index_agnostic_signature,
    is_small_talk,
    normalize_mission,
    render_rows_for_llm,
    tool_call_signature,
)
from mcp_tool_args import adapt_tool_arguments, parse_jsonrpc_error
from spl.spl_utils import (
    BLOCKED_COMMANDS as SPL_BLOCKED_COMMANDS,
    assess_spl_safety,
    ensure_spl_time_bounds,
    extract_json_payload,
    extract_spl_entities,
    scope_spl_to_index,
)
from frontend_legacy import get_frontend_html
from security_manager import SecurityManager

# Ensure console/log prints do not crash on Windows code pages (cp1252, etc.)
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Initialize encrypted config manager
config_manager = ConfigManager("config.encrypted")
capability_registry = CapabilityRegistry()
capability_manager = CapabilityManager(config_manager, registry=capability_registry)
security_manager = SecurityManager("security.db")

AUTH_SESSION_COOKIE_NAME = "dt4sms_session"
SUPPORTED_AUTH_PROVIDERS = {"local_password", "oidc"}
OIDC_STATE_TTL_SECONDS = 600
OIDC_JWKS_CACHE_TTL_SECONDS = 300
DEFAULT_EXTERNAL_API_RATE_LIMIT_REQUESTS = 30
DEFAULT_EXTERNAL_API_RATE_LIMIT_WINDOW_SECONDS = 60
DEFAULT_EXTERNAL_MCP_RATE_LIMIT_REQUESTS = 30
DEFAULT_EXTERNAL_MCP_RATE_LIMIT_WINDOW_SECONDS = 60

# Module-level LLM client cache for performance
_cached_llm_client = None
_cached_config_hash = None
_cached_oidc_provider_jwks: Dict[str, Dict[str, Any]] = {}
M2614_VALIDATION_CACHE_LIMIT = 64
_cached_m2614_validation_results: Dict[str, Dict[str, Any]] = {}


class ExternalSurfaceRateLimiter:
    """Simple fixed-window limiter for external DT4SMS surfaces."""

    def __init__(self, time_source=None):
        self._time_source = time_source or time.monotonic
        self._lock = threading.Lock()
        self._request_windows: Dict[str, deque] = {}

    def check_request(self, bucket_key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int, int]:
        max_requests = int(max_requests or 0)
        window_seconds = int(window_seconds or 0)
        if max_requests <= 0 or window_seconds <= 0:
            return True, 0, max_requests

        now = float(self._time_source())
        cutoff = now - float(window_seconds)

        with self._lock:
            request_window = self._request_windows.get(bucket_key)
            if request_window is None:
                request_window = deque()
                self._request_windows[bucket_key] = request_window

            while request_window and request_window[0] <= cutoff:
                request_window.popleft()

            if len(request_window) >= max_requests:
                retry_after = max(1, int((request_window[0] + float(window_seconds)) - now + 0.999))
                return False, retry_after, 0

            request_window.append(now)
            remaining = max(0, max_requests - len(request_window))
            return True, 0, remaining


class OIDCLoginStateStore:
    """Track in-flight OIDC authorization attempts for the single-process app runtime."""

    def __init__(self, time_source=None):
        self._time_source = time_source or time.monotonic
        self._lock = threading.Lock()
        self._states: Dict[str, Dict[str, Any]] = {}

    def _purge_expired_locked(self) -> None:
        now = float(self._time_source())
        expired_states = [
            state
            for state, payload in self._states.items()
            if (now - float(payload.get("issued_at", 0.0))) > OIDC_STATE_TTL_SECONDS
        ]
        for state in expired_states:
            self._states.pop(state, None)

    def issue(self, payload: Dict[str, Any]) -> str:
        state = secrets.token_urlsafe(32)
        record = dict(payload or {})
        record["issued_at"] = float(self._time_source())
        with self._lock:
            self._purge_expired_locked()
            self._states[state] = record
        return state

    def consume(self, state: str) -> Optional[Dict[str, Any]]:
        normalized_state = str(state or "").strip()
        if not normalized_state:
            return None
        with self._lock:
            self._purge_expired_locked()
            payload = self._states.pop(normalized_state, None)
        return dict(payload) if isinstance(payload, dict) else None


external_surface_rate_limiter = ExternalSurfaceRateLimiter()
oidc_login_state_store = OIDCLoginStateStore()


def get_security_config() -> Any:
    return getattr(config_manager.get(), "security", None)


def is_auth_enabled() -> bool:
    security_config = get_security_config()
    return bool(security_config and getattr(security_config, "auth_enabled", False))


def get_auth_provider() -> str:
    security_config = get_security_config()
    provider = str(getattr(security_config, "auth_provider", "local_password") or "local_password").strip().lower()
    return provider if provider in SUPPORTED_AUTH_PROVIDERS else "local_password"


def get_oidc_config() -> Any:
    security_config = get_security_config()
    return getattr(security_config, "oidc", None) if security_config else None


def _snapshot_oidc_settings(oidc_config: Any = None) -> Dict[str, Any]:
    config_ref = oidc_config if oidc_config is not None else get_oidc_config()
    return {
        "issuer_url": str(getattr(config_ref, "issuer_url", "") or "").strip() if config_ref else "",
        "client_id": str(getattr(config_ref, "client_id", "") or "").strip() if config_ref else "",
        "client_secret": str(getattr(config_ref, "client_secret", "") or "").strip() if config_ref else "",
        "audience": str(getattr(config_ref, "audience", "") or "").strip() if config_ref else "",
        "scopes": list(getattr(config_ref, "scopes", []) or ["openid", "profile", "email"]) if config_ref else ["openid", "profile", "email"],
        "username_claim": str(getattr(config_ref, "username_claim", "preferred_username") or "preferred_username") if config_ref else "preferred_username",
        "email_claim": str(getattr(config_ref, "email_claim", "email") or "email") if config_ref else "email",
        "role_claim": str(getattr(config_ref, "role_claim", "roles") or "roles") if config_ref else "roles",
        "default_role": str(getattr(config_ref, "default_role", "viewer") or "viewer") if config_ref else "viewer",
        "mcp_assignment_claim": str(getattr(config_ref, "mcp_assignment_claim", "") or "") if config_ref else "",
    }


def _get_oidc_well_known_url(issuer_url: str) -> str:
    normalized_issuer = str(issuer_url or "").strip()
    if not normalized_issuer:
        raise ValueError("OIDC issuer URL is required")
    if normalized_issuer.endswith("/.well-known/openid-configuration"):
        return normalized_issuer
    return f"{normalized_issuer.rstrip('/')}/.well-known/openid-configuration"


def _coerce_oidc_claim_values(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item or "").strip() for item in value if str(item or "").strip()]
    if isinstance(value, tuple):
        return [str(item or "").strip() for item in value if str(item or "").strip()]
    if isinstance(value, str):
        return [item for item in re.split(r"[,\s]+", value) if item]
    if value in (None, ""):
        return []
    return [str(value).strip()]


def _resolve_oidc_role(claims: Dict[str, Any], oidc_settings: Dict[str, Any]) -> str:
    default_role = str(oidc_settings.get("default_role") or "viewer").strip().lower()
    candidate_roles = _coerce_oidc_claim_values(claims.get(oidc_settings.get("role_claim") or "roles"))
    for candidate in candidate_roles:
        normalized_candidate = str(candidate or "").strip().lower()
        if normalized_candidate in {"admin", "analyst", "viewer"}:
            return normalized_candidate
    return default_role if default_role in {"admin", "analyst", "viewer"} else "viewer"


def _resolve_oidc_role_sync_behavior(claims: Dict[str, Any], oidc_settings: Dict[str, Any]) -> Tuple[str, bool]:
    role_claim_name = str(oidc_settings.get("role_claim") or "roles").strip() or "roles"
    candidate_roles = _coerce_oidc_claim_values(claims.get(role_claim_name))
    for candidate in candidate_roles:
        normalized_candidate = str(candidate or "").strip().lower()
        if normalized_candidate in {"admin", "analyst", "viewer"}:
            return normalized_candidate, True
    return _resolve_oidc_role(claims, oidc_settings), False


def _resolve_oidc_mcp_assignment(claims: Dict[str, Any], oidc_settings: Dict[str, Any]) -> Optional[str]:
    claim_name = str(oidc_settings.get("mcp_assignment_claim") or "").strip()
    if not claim_name:
        return None

    raw_value = claims.get(claim_name)
    candidates = _coerce_oidc_claim_values(raw_value)
    saved_configs = getattr(config_manager.get(), "saved_mcp_configs", {}) or {}
    available_names = {str(name): str(name) for name in saved_configs.keys()}
    for candidate in candidates:
        if candidate in available_names:
            return available_names[candidate]
    return None


def _resolve_oidc_mcp_assignment_sync_behavior(claims: Dict[str, Any], oidc_settings: Dict[str, Any]) -> Tuple[Optional[str], bool]:
    claim_name = str(oidc_settings.get("mcp_assignment_claim") or "").strip()
    if not claim_name or claim_name not in claims:
        return None, False

    resolved_assignment = _resolve_oidc_mcp_assignment(claims, oidc_settings)
    return resolved_assignment, resolved_assignment is not None


def _resolve_oidc_identity_fields(claims: Dict[str, Any], oidc_settings: Dict[str, Any]) -> Dict[str, Any]:
    subject = str(claims.get("sub") or "").strip()
    if not subject:
        raise ValueError("OIDC userinfo response did not include a subject")

    username_claim = str(oidc_settings.get("username_claim") or "preferred_username").strip() or "preferred_username"
    email_claim = str(oidc_settings.get("email_claim") or "email").strip() or "email"

    username = str(claims.get(username_claim) or "").strip()
    email = str(claims.get(email_claim) or "").strip().lower()
    if not username and email:
        username = email.split("@", 1)[0]
    if not username:
        username = subject

    resolved_role, sync_role = _resolve_oidc_role_sync_behavior(claims, oidc_settings)
    resolved_assignment, sync_assignment = _resolve_oidc_mcp_assignment_sync_behavior(claims, oidc_settings)

    return {
        "subject": subject,
        "username": username,
        "email": email or None,
        "role": resolved_role,
        "sync_role": sync_role,
        "mcp_config_name": resolved_assignment,
        "sync_mcp_config_name": sync_assignment,
    }


async def load_oidc_provider_metadata(oidc_settings: Dict[str, Any]) -> Dict[str, Any]:
    discovery_url = _get_oidc_well_known_url(str(oidc_settings.get("issuer_url") or ""))
    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        response = await client.get(discovery_url)
        response.raise_for_status()
        metadata = response.json()

    for field_name in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint"):
        if not str(metadata.get(field_name) or "").strip():
            raise ValueError(f"OIDC discovery document is missing {field_name}")
    return metadata


async def load_oidc_provider_jwks(provider_metadata: Dict[str, Any]) -> Dict[str, Any]:
    jwks_uri = str(provider_metadata.get("jwks_uri") or "").strip()
    if not jwks_uri:
        raise ValueError("OIDC discovery document is missing jwks_uri")

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        response = await client.get(jwks_uri)
        response.raise_for_status()
        jwks_payload = response.json()

    if not isinstance(jwks_payload, dict):
        raise ValueError("OIDC JWKS endpoint did not return a JSON object")
    if not isinstance(jwks_payload.get("keys"), list):
        raise ValueError("OIDC JWKS response did not include signing keys")
    return jwks_payload


def clear_oidc_provider_jwks_cache() -> None:
    _cached_oidc_provider_jwks.clear()


async def _load_cached_oidc_provider_jwks(provider_metadata: Dict[str, Any], force_refresh: bool = False) -> Tuple[Dict[str, Any], bool]:
    jwks_uri = str(provider_metadata.get("jwks_uri") or "").strip()
    if not jwks_uri:
        raise ValueError("OIDC discovery document is missing jwks_uri")

    cached_entry = _cached_oidc_provider_jwks.get(jwks_uri)
    now = time.time()
    if (
        not force_refresh
        and isinstance(cached_entry, dict)
        and isinstance(cached_entry.get("payload"), dict)
        and isinstance(cached_entry.get("payload", {}).get("keys"), list)
        and (now - float(cached_entry.get("timestamp") or 0.0)) < OIDC_JWKS_CACHE_TTL_SECONDS
    ):
        return cached_entry["payload"], True

    jwks_payload = await load_oidc_provider_jwks(provider_metadata)
    _cached_oidc_provider_jwks[jwks_uri] = {
        "payload": jwks_payload,
        "timestamp": time.time(),
    }
    return jwks_payload, False


async def exchange_oidc_authorization_code(
    oidc_settings: Dict[str, Any],
    provider_metadata: Dict[str, Any],
    code: str,
    redirect_uri: str,
) -> Dict[str, Any]:
    form_data = {
        "grant_type": "authorization_code",
        "code": str(code or "").strip(),
        "redirect_uri": redirect_uri,
        "client_id": str(oidc_settings.get("client_id") or "").strip(),
        "client_secret": str(oidc_settings.get("client_secret") or "").strip(),
    }
    audience = str(oidc_settings.get("audience") or "").strip()
    if audience:
        form_data["audience"] = audience

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        response = await client.post(
            str(provider_metadata.get("token_endpoint") or "").strip(),
            data=form_data,
            headers={"Accept": "application/json"},
        )
        response.raise_for_status()
        token_payload = response.json()

    return _validate_oidc_token_payload(token_payload)


def _validate_oidc_token_payload(token_payload: Any) -> Dict[str, Any]:
    if not isinstance(token_payload, dict):
        raise ValueError("OIDC token exchange did not return a JSON object")

    access_token = str(token_payload.get("access_token") or "").strip()
    if not access_token:
        raise ValueError("OIDC token exchange did not return an access token")

    token_type = str(token_payload.get("token_type") or "").strip()
    if token_type and token_type.lower() != "bearer":
        raise ValueError(f"OIDC token exchange returned unsupported token type '{token_type}'")
    return token_payload


def _normalize_oidc_issuer_for_comparison(issuer: Any) -> str:
    return str(issuer or "").strip().rstrip("/")


def _decode_oidc_base64url_bytes(value: Any, error_message: str) -> bytes:
    segment = str(value or "").strip()
    if not segment:
        raise ValueError(error_message)

    padding_value = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(f"{segment}{padding_value}")
    except (ValueError, TypeError):
        raise ValueError(error_message)


def _decode_oidc_jwt_json_segment(segment: Any, error_message: str) -> Dict[str, Any]:
    try:
        decoded_bytes = _decode_oidc_base64url_bytes(segment, error_message)
        decoded_value = json.loads(decoded_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(error_message)

    if not isinstance(decoded_value, dict):
        raise ValueError(error_message)
    return decoded_value


def _decode_oidc_id_token(id_token: Any) -> Dict[str, Any]:
    token_value = str(id_token or "").strip()
    token_segments = token_value.split(".")
    if len(token_segments) == 5:
        raise ValueError("OIDC token exchange returned an encrypted id_token, which Splunk Discovery Tool does not support")
    if len(token_segments) != 3:
        raise ValueError("OIDC token exchange returned a malformed id_token")

    header_segment, payload_segment, signature_segment = token_segments
    return {
        "header": _decode_oidc_jwt_json_segment(header_segment, "OIDC token exchange returned a malformed id_token"),
        "claims": _decode_oidc_jwt_json_segment(payload_segment, "OIDC token exchange returned a malformed id_token"),
        "signature": _decode_oidc_base64url_bytes(signature_segment, "OIDC token exchange returned a malformed id_token")
        if signature_segment
        else b"",
        "signing_input": f"{header_segment}.{payload_segment}".encode("ascii"),
    }


def _get_oidc_signature_hash_algorithm(algorithm: str):
    normalized_algorithm = str(algorithm or "").strip().upper()
    if normalized_algorithm.startswith("HS"):
        raise ValueError(
            f"OIDC id_token used unsupported symmetric signing algorithm '{str(algorithm or '').strip() or 'unknown'}'"
        )
    hash_algorithms = {
        "RS256": hashes.SHA256,
        "RS384": hashes.SHA384,
        "RS512": hashes.SHA512,
        "PS256": hashes.SHA256,
        "PS384": hashes.SHA384,
        "PS512": hashes.SHA512,
        "ES256": hashes.SHA256,
        "ES384": hashes.SHA384,
        "ES512": hashes.SHA512,
        "EDDSA": None,
    }
    hash_algorithm_factory = hash_algorithms.get(normalized_algorithm)
    if hash_algorithm_factory is None:
        if normalized_algorithm == "EDDSA":
            return None
        raise ValueError(f"OIDC id_token used unsupported signing algorithm '{str(algorithm or '').strip() or 'unknown'}'")
    return hash_algorithm_factory()


def _get_oidc_signature_padding(algorithm: str, hash_algorithm: hashes.HashAlgorithm):
    normalized_algorithm = str(algorithm or "").strip().upper()
    if normalized_algorithm.startswith("PS"):
        return padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.DIGEST_LENGTH)
    return padding.PKCS1v15()


def _get_oidc_expected_jwk_key_types(algorithm: str) -> Tuple[str, ...]:
    normalized_algorithm = str(algorithm or "").strip().upper()
    if normalized_algorithm.startswith(("RS", "PS")):
        return ("RSA",)
    if normalized_algorithm.startswith("ES"):
        return ("EC",)
    if normalized_algorithm == "EDDSA":
        return ("OKP",)
    return ()


def _oidc_jwk_allows_signature_verification(jwk: Dict[str, Any]) -> bool:
    key_use = str(jwk.get("use") or "").strip().lower()
    if key_use and key_use != "sig":
        return False

    key_operations = {
        str(operation or "").strip().lower()
        for operation in _coerce_oidc_claim_values(jwk.get("key_ops"))
        if str(operation or "").strip()
    }
    if key_operations and "verify" not in key_operations:
        return False
    return True


def _decode_oidc_base64url_int(value: Any, error_message: str) -> int:
    decoded_bytes = _decode_oidc_base64url_bytes(value, error_message)
    if not decoded_bytes:
        raise ValueError(error_message)
    return int.from_bytes(decoded_bytes, "big")


def _select_oidc_signing_jwk(header: Dict[str, Any], jwks_payload: Dict[str, Any]) -> Dict[str, Any]:
    token_algorithm = str(header.get("alg") or "").strip().upper()
    expected_key_types = set(_get_oidc_expected_jwk_key_types(token_algorithm))
    key_candidates = [
        key
        for key in jwks_payload.get("keys") or []
        if isinstance(key, dict)
        and str(key.get("kty") or "").strip().upper() in expected_key_types
        and _oidc_jwk_allows_signature_verification(key)
    ]

    token_kid = str(header.get("kid") or "").strip()
    if token_kid:
        key_candidates = [key for key in key_candidates if str(key.get("kid") or "").strip() == token_kid]
        if not key_candidates:
            raise ValueError("OIDC JWKS did not contain the signing key referenced by the id_token")

    matching_algorithm_candidates = [
        key for key in key_candidates if not str(key.get("alg") or "").strip() or str(key.get("alg") or "").strip().upper() == token_algorithm
    ]
    if matching_algorithm_candidates:
        key_candidates = matching_algorithm_candidates

    if len(key_candidates) != 1:
        raise ValueError("OIDC JWKS did not identify a unique signing key for the id_token")
    return key_candidates[0]


def _build_oidc_rsa_public_key(jwk: Dict[str, Any]):
    modulus = _decode_oidc_base64url_int(jwk.get("n"), "OIDC JWKS signing key was missing RSA modulus data")
    exponent = _decode_oidc_base64url_int(jwk.get("e"), "OIDC JWKS signing key was missing RSA exponent data")
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


def _get_oidc_ec_curve(curve_name: Any):
    normalized_curve_name = str(curve_name or "").strip()
    curves = {
        "P-256": ec.SECP256R1,
        "P-384": ec.SECP384R1,
        "P-521": ec.SECP521R1,
    }
    curve_factory = curves.get(normalized_curve_name)
    if curve_factory is None:
        raise ValueError(f"OIDC JWKS signing key used unsupported EC curve '{normalized_curve_name or 'unknown'}'")
    return curve_factory()


def _build_oidc_ec_public_key(jwk: Dict[str, Any]):
    curve = _get_oidc_ec_curve(jwk.get("crv"))
    x_coordinate = _decode_oidc_base64url_int(jwk.get("x"), "OIDC JWKS signing key was missing EC x-coordinate data")
    y_coordinate = _decode_oidc_base64url_int(jwk.get("y"), "OIDC JWKS signing key was missing EC y-coordinate data")
    try:
        return ec.EllipticCurvePublicNumbers(x_coordinate, y_coordinate, curve).public_key()
    except ValueError:
        raise ValueError("OIDC JWKS signing key contained invalid EC coordinates")


def _build_oidc_okp_public_key(jwk: Dict[str, Any]):
    curve_name = str(jwk.get("crv") or "").strip()
    public_key_bytes = _decode_oidc_base64url_bytes(jwk.get("x"), "OIDC JWKS signing key was missing OKP public key data")
    key_factories = {
        "Ed25519": ed25519.Ed25519PublicKey.from_public_bytes,
        "Ed448": ed448.Ed448PublicKey.from_public_bytes,
    }
    key_factory = key_factories.get(curve_name)
    if key_factory is None:
        raise ValueError(f"OIDC JWKS signing key used unsupported OKP curve '{curve_name or 'unknown'}'")
    try:
        return key_factory(public_key_bytes)
    except ValueError:
        raise ValueError("OIDC JWKS signing key contained invalid OKP public key data")


def _build_oidc_signing_public_key(jwk: Dict[str, Any]):
    key_type = str(jwk.get("kty") or "").strip().upper()
    if key_type == "RSA":
        return _build_oidc_rsa_public_key(jwk)
    if key_type == "EC":
        return _build_oidc_ec_public_key(jwk)
    if key_type == "OKP":
        return _build_oidc_okp_public_key(jwk)
    raise ValueError(f"OIDC JWKS signing key used unsupported key type '{key_type or 'unknown'}'")


def _normalize_oidc_ecdsa_signature_for_verification(signature: bytes, jwk: Dict[str, Any]) -> bytes:
    curve = _get_oidc_ec_curve(jwk.get("crv"))
    coordinate_length = (curve.key_size + 7) // 8
    if len(signature) != coordinate_length * 2:
        raise ValueError("OIDC id_token signature did not match the advertised EC curve")

    r_value = int.from_bytes(signature[:coordinate_length], "big")
    s_value = int.from_bytes(signature[coordinate_length:], "big")
    return utils.encode_dss_signature(r_value, s_value)


def _validate_oidc_id_token_signature(
    decoded_token: Dict[str, Any],
    token_header: Dict[str, Any],
    jwks_payload: Dict[str, Any],
    signing_hash_algorithm: Optional[hashes.HashAlgorithm],
) -> None:
    signing_jwk = _select_oidc_signing_jwk(token_header, jwks_payload)
    public_key = _build_oidc_signing_public_key(signing_jwk)
    token_algorithm = str(token_header.get("alg") or "").strip().upper()

    try:
        if token_algorithm == "EDDSA":
            public_key.verify(decoded_token["signature"], decoded_token["signing_input"])
        elif token_algorithm.startswith("ES"):
            normalized_signature = _normalize_oidc_ecdsa_signature_for_verification(decoded_token["signature"], signing_jwk)
            public_key.verify(normalized_signature, decoded_token["signing_input"], ec.ECDSA(signing_hash_algorithm))
        else:
            signature_padding = _get_oidc_signature_padding(token_algorithm, signing_hash_algorithm)
            public_key.verify(decoded_token["signature"], decoded_token["signing_input"], signature_padding, signing_hash_algorithm)
    except InvalidSignature:
        raise ValueError("OIDC id_token signature validation failed")


def _should_refresh_cached_oidc_jwks(validation_error: ValueError) -> bool:
    return str(validation_error) in {
        "OIDC JWKS did not contain the signing key referenced by the id_token",
        "OIDC JWKS did not identify a unique signing key for the id_token",
        "OIDC id_token signature validation failed",
    }


async def _validate_oidc_id_token_claims(
    token_payload: Dict[str, Any],
    provider_metadata: Dict[str, Any],
    oidc_settings: Dict[str, Any],
    state_record: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    id_token = str(token_payload.get("id_token") or "").strip()
    if not id_token:
        return None

    decoded_token = _decode_oidc_id_token(id_token)
    token_header = decoded_token["header"]
    token_algorithm = str(token_header.get("alg") or "").strip()
    if not token_algorithm or token_algorithm.lower() == "none":
        raise ValueError("OIDC id_token used unsupported signing algorithm 'none'")

    signing_hash_algorithm = _get_oidc_signature_hash_algorithm(token_algorithm)
    jwks_payload, jwks_from_cache = await _load_cached_oidc_provider_jwks(provider_metadata)
    try:
        _validate_oidc_id_token_signature(decoded_token, token_header, jwks_payload, signing_hash_algorithm)
    except ValueError as exc:
        if not jwks_from_cache or not _should_refresh_cached_oidc_jwks(exc):
            raise
        refreshed_jwks_payload, _ = await _load_cached_oidc_provider_jwks(provider_metadata, force_refresh=True)
        _validate_oidc_id_token_signature(decoded_token, token_header, refreshed_jwks_payload, signing_hash_algorithm)

    claims = decoded_token["claims"]

    expected_issuer = _normalize_oidc_issuer_for_comparison(oidc_settings.get("issuer_url"))
    token_issuer = _normalize_oidc_issuer_for_comparison(claims.get("iss"))
    if not token_issuer or token_issuer != expected_issuer:
        raise ValueError("OIDC id_token issuer did not match the configured issuer")

    token_subject = str(claims.get("sub") or "").strip()
    if not token_subject:
        raise ValueError("OIDC id_token did not include a subject")

    expected_client_id = str(oidc_settings.get("client_id") or "").strip()
    token_audiences = _coerce_oidc_claim_values(claims.get("aud"))
    if not expected_client_id or expected_client_id not in token_audiences:
        raise ValueError("OIDC id_token audience did not include the configured client_id")

    try:
        expires_at = int(float(claims.get("exp")))
    except (TypeError, ValueError):
        raise ValueError("OIDC id_token did not include a valid expiration")
    if expires_at <= int(time.time()):
        raise ValueError("OIDC id_token is expired")

    expected_nonce = str(state_record.get("nonce") or "").strip()
    if expected_nonce:
        token_nonce = str(claims.get("nonce") or "").strip()
        if not token_nonce:
            raise ValueError("OIDC id_token did not include the expected nonce")
        if token_nonce != expected_nonce:
            raise ValueError("OIDC id_token nonce did not match the authorization request")

    return claims


def _validate_oidc_subject_coherence(
    id_token_claims: Optional[Dict[str, Any]],
    userinfo_claims: Dict[str, Any],
) -> None:
    if not isinstance(id_token_claims, dict):
        return

    id_token_subject = str(id_token_claims.get("sub") or "").strip()
    userinfo_subject = str(userinfo_claims.get("sub") or "").strip()
    if id_token_subject and userinfo_subject and id_token_subject != userinfo_subject:
        raise ValueError("OIDC userinfo subject did not match the id_token subject")


async def fetch_oidc_userinfo(provider_metadata: Dict[str, Any], access_token: str) -> Dict[str, Any]:
    userinfo_endpoint = str(provider_metadata.get("userinfo_endpoint") or "").strip()
    if not userinfo_endpoint:
        raise ValueError("OIDC discovery document is missing userinfo_endpoint")

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
        response = await client.get(
            userinfo_endpoint,
            headers={
                "Authorization": f"Bearer {str(access_token or '').strip()}",
                "Accept": "application/json",
            },
        )
        response.raise_for_status()
        claims = response.json()

    if not isinstance(claims, dict):
        raise ValueError("OIDC userinfo response was not a JSON object")
    return claims


def is_external_api_enabled() -> bool:
    security_config = get_security_config()
    return bool(security_config and getattr(security_config, "external_api_enabled", False))


def is_external_mcp_enabled() -> bool:
    security_config = get_security_config()
    return bool(security_config and getattr(security_config, "external_mcp_enabled", False))


def _build_oidc_provider_status() -> Dict[str, Any]:
    oidc_settings = _snapshot_oidc_settings()
    configured = any(
        [
            oidc_settings["issuer_url"],
            oidc_settings["client_id"],
            oidc_settings["client_secret"],
            oidc_settings["audience"],
            oidc_settings["mcp_assignment_claim"],
        ]
    )
    ready = bool(oidc_settings["issuer_url"] and oidc_settings["client_id"] and oidc_settings["client_secret"])
    return {
        "implemented": True,
        "configured": configured,
        "ready": ready,
        "can_enable_auth": ready,
        "issuer_url": oidc_settings["issuer_url"],
        "client_id": oidc_settings["client_id"],
        "client_secret_configured": bool(oidc_settings["client_secret"]),
        "audience": oidc_settings["audience"],
        "scopes": oidc_settings["scopes"],
        "username_claim": oidc_settings["username_claim"],
        "email_claim": oidc_settings["email_claim"],
        "role_claim": oidc_settings["role_claim"],
        "default_role": oidc_settings["default_role"],
        "mcp_assignment_claim": oidc_settings["mcp_assignment_claim"],
    }


async def _build_oidc_logout_plan(request: Request) -> Dict[str, Any]:
    redirect_uri = str(request.url_for("serve_frontend"))
    logout_plan = {
        "provider": "oidc",
        "supported": False,
        "mode": "local_session_only",
        "url": None,
        "post_logout_redirect_uri": redirect_uri,
        "reason": "provider_end_session_endpoint_unavailable",
    }

    if not _build_oidc_provider_status().get("ready"):
        logout_plan["reason"] = "provider_not_ready"
        return logout_plan

    try:
        provider_metadata = await load_oidc_provider_metadata(_snapshot_oidc_settings())
    except (ValueError, httpx.HTTPError):
        logout_plan["reason"] = "provider_metadata_unavailable"
        return logout_plan

    end_session_endpoint = str(provider_metadata.get("end_session_endpoint") or "").strip()
    if not end_session_endpoint:
        return logout_plan

    query_params = {"post_logout_redirect_uri": redirect_uri}
    client_id = str(_snapshot_oidc_settings().get("client_id") or "").strip()
    if client_id:
        query_params["client_id"] = client_id

    separator = "&" if "?" in end_session_endpoint else "?"
    logout_plan.update(
        {
            "supported": True,
            "mode": "front_channel_redirect",
            "url": f"{end_session_endpoint}{separator}{urlencode(query_params)}",
            "reason": None,
        }
    )
    return logout_plan


def ensure_local_auth_bootstrap_state() -> Dict[str, Any]:
    security_config = get_security_config()
    if not security_config or not getattr(security_config, "auth_enabled", False):
        return {"created": False}
    if get_auth_provider() != "local_password":
        return {"created": False}
    return security_manager.ensure_bootstrap_admin(
        require_password_reset=bool(getattr(security_config, "require_password_reset_on_first_login", True))
    )


def _is_public_auth_path(path: str) -> bool:
    return path in {
        "/",
        "/api/auth/status",
        "/api/auth/login",
        "/api/auth/logout",
        "/api/auth/oidc/start",
        "/api/auth/oidc/callback",
        "/api/auth/reset-password",
    }


def _is_password_reset_allowed_path(path: str) -> bool:
    return path in {
        "/",
        "/api/auth/status",
        "/api/auth/logout",
        "/api/auth/reset-password",
    }


def _is_external_api_path(path: str) -> bool:
    return str(path or "").startswith("/api/external/")


def _serialize_authenticated_user(user: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(user, dict):
        return None
    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "role": user.get("role"),
        "mcp_config_name": user.get("mcp_config_name"),
        "require_password_reset": bool(user.get("require_password_reset")),
        "last_login_at": user.get("last_login_at"),
        "session_expires_at": user.get("session_expires_at"),
    }


def _serialize_security_user_record(user: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(user, dict):
        return None
    return {
        "id": user.get("id"),
        "username": user.get("username"),
        "role": user.get("role"),
        "is_enabled": bool(user.get("is_enabled")),
        "require_password_reset": bool(user.get("require_password_reset")),
        "mcp_config_name": user.get("mcp_config_name"),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
        "last_login_at": user.get("last_login_at"),
    }


def _serialize_external_identity_record(identity: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(identity, dict):
        return None
    return {
        "id": identity.get("id"),
        "auth_provider": identity.get("auth_provider"),
        "subject": identity.get("subject"),
        "user_id": identity.get("user_id"),
        "email": identity.get("email"),
        "claims": identity.get("claims", {}),
        "created_at": identity.get("created_at"),
        "updated_at": identity.get("updated_at"),
        "last_login_at": identity.get("last_login_at"),
        "user": _serialize_security_user_record(identity.get("user")),
    }


def _serialize_security_token_record(token: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(token, dict):
        return None
    return {
        "id": token.get("id"),
        "name": token.get("name"),
        "token_type": token.get("token_type"),
        "token_prefix": token.get("token_prefix"),
        "owner_user_id": token.get("owner_user_id"),
        "owner_username": token.get("owner_username"),
        "created_by_user_id": token.get("created_by_user_id"),
        "created_by_username": token.get("created_by_username"),
        "scopes": token.get("scopes", []),
        "created_at": token.get("created_at"),
        "updated_at": token.get("updated_at"),
        "expires_at": token.get("expires_at"),
        "revoked_at": token.get("revoked_at"),
        "last_used_at": token.get("last_used_at"),
        "last_used_from": token.get("last_used_from"),
        "use_count": token.get("use_count", 0),
    }


def require_authenticated_user(request: Request) -> Optional[Dict[str, Any]]:
    if not is_auth_enabled():
        return None
    current_user = getattr(request.state, "auth_user", None)
    if not isinstance(current_user, dict):
        raise HTTPException(status_code=401, detail="Authentication required")
    return current_user


def require_admin_user(request: Request) -> Optional[Dict[str, Any]]:
    current_user = require_authenticated_user(request)
    if current_user is None:
        return None
    if str(current_user.get("role") or "").strip().lower() != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


def require_analyst_or_admin_user(request: Request) -> Optional[Dict[str, Any]]:
    current_user = require_authenticated_user(request)
    if current_user is None:
        return None
    normalized_role = str(current_user.get("role") or "").strip().lower()
    if normalized_role not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Analyst or admin access required")
    return current_user


def validate_assigned_mcp_config_name(mcp_config_name: Optional[str]) -> Optional[str]:
    cleaned = str(mcp_config_name or "").strip()
    if not cleaned:
        return None
    if cleaned not in config_manager.list_mcp_configs():
        raise HTTPException(status_code=400, detail=f"Assigned MCP configuration '{cleaned}' does not exist")
    return cleaned


def require_external_api_enabled() -> None:
    if not is_external_api_enabled():
        raise HTTPException(status_code=404, detail="External API is not enabled")


def require_external_mcp_enabled() -> None:
    if not is_external_mcp_enabled():
        raise HTTPException(status_code=404, detail="External MCP server is not enabled")


def _get_external_surface_rate_limit(surface_name: str) -> Tuple[int, int]:
    security_config = get_security_config()
    if surface_name == "external_mcp":
        default_requests = DEFAULT_EXTERNAL_MCP_RATE_LIMIT_REQUESTS
        default_window_seconds = DEFAULT_EXTERNAL_MCP_RATE_LIMIT_WINDOW_SECONDS
        request_attr = "external_mcp_rate_limit_requests"
        window_attr = "external_mcp_rate_limit_window_seconds"
    else:
        default_requests = DEFAULT_EXTERNAL_API_RATE_LIMIT_REQUESTS
        default_window_seconds = DEFAULT_EXTERNAL_API_RATE_LIMIT_WINDOW_SECONDS
        request_attr = "external_api_rate_limit_requests"
        window_attr = "external_api_rate_limit_window_seconds"

    max_requests = default_requests
    window_seconds = default_window_seconds
    if security_config is not None:
        max_requests = int(getattr(security_config, request_attr, default_requests) or default_requests)
        window_seconds = int(getattr(security_config, window_attr, default_window_seconds) or default_window_seconds)
    return max_requests, window_seconds


def _enforce_external_surface_rate_limit(surface_name: str, token_record: Dict[str, Any]) -> None:
    max_requests, window_seconds = _get_external_surface_rate_limit(surface_name)
    token_key = token_record.get("id") or token_record.get("token_prefix") or "anonymous"
    bucket_key = f"{surface_name}:{token_key}"
    allowed, retry_after, _remaining = external_surface_rate_limiter.check_request(
        bucket_key,
        max_requests=max_requests,
        window_seconds=window_seconds,
    )
    if allowed:
        return

    surface_label = "External MCP" if surface_name == "external_mcp" else "External API"
    raise HTTPException(
        status_code=429,
        detail=f"{surface_label} rate limit exceeded. Retry in {retry_after} seconds.",
        headers={"Retry-After": str(retry_after)},
    )


def _extract_bearer_token(request: Request) -> Optional[str]:
    authorization_header = str(request.headers.get("Authorization") or "").strip()
    if not authorization_header.lower().startswith("bearer "):
        return None
    token = authorization_header[7:].strip()
    return token or None


def require_external_api_token(request: Request, required_scopes: Optional[List[str]] = None) -> Dict[str, Any]:
    require_external_api_enabled()
    access_token = _extract_bearer_token(request)
    if not access_token:
        raise HTTPException(status_code=401, detail="Bearer token required for external API access")

    token_record = security_manager.resolve_access_token(
        access_token,
        token_type="external_api",
        record_usage=False,
    )
    if token_record is None:
        raise HTTPException(status_code=401, detail="Invalid or expired external API token")

    scoped_record = security_manager.resolve_access_token(
        access_token,
        required_scopes=list(required_scopes or []),
        token_type="external_api",
        record_usage=False,
    )
    if scoped_record is None:
        raise HTTPException(status_code=403, detail="External API token does not include the required scope")

    _enforce_external_surface_rate_limit("external_api", scoped_record)

    used_from = str(request.headers.get("X-Forwarded-For") or "").strip() or (request.client.host if request.client else None)
    recorded_record = security_manager.resolve_access_token(
        access_token,
        required_scopes=list(required_scopes or []),
        token_type="external_api",
        used_from=used_from,
        record_usage=True,
    )
    if recorded_record is None:
        raise HTTPException(status_code=401, detail="Invalid or expired external API token")
    return recorded_record


def require_external_mcp_token(request: Request, required_scopes: Optional[List[str]] = None) -> Dict[str, Any]:
    require_external_mcp_enabled()
    access_token = _extract_bearer_token(request)
    if not access_token:
        raise HTTPException(status_code=401, detail="Bearer token required for external MCP access")

    token_record = security_manager.resolve_access_token(
        access_token,
        token_type="inbound_mcp",
        record_usage=False,
    )
    if token_record is None:
        raise HTTPException(status_code=401, detail="Invalid or expired external MCP token")

    scoped_record = security_manager.resolve_access_token(
        access_token,
        required_scopes=list(required_scopes or []),
        token_type="inbound_mcp",
        record_usage=False,
    )
    if scoped_record is None:
        raise HTTPException(status_code=403, detail="External MCP token does not include the required scope")

    _enforce_external_surface_rate_limit("external_mcp", scoped_record)

    used_from = str(request.headers.get("X-Forwarded-For") or "").strip() or (request.client.host if request.client else None)
    recorded_record = security_manager.resolve_access_token(
        access_token,
        required_scopes=list(required_scopes or []),
        token_type="inbound_mcp",
        used_from=used_from,
        record_usage=True,
    )
    if recorded_record is None:
        raise HTTPException(status_code=401, detail="Invalid or expired external MCP token")
    return recorded_record


def _sanitize_external_rag_index_summary(summary: Any) -> Dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    sanitized: Dict[str, Any] = {}
    for key in (
        "collection_name",
        "index_schema_version",
        "document_count",
        "source_file_count",
        "source_type_counts",
        "sample_sources",
        "last_indexed_at",
        "error",
    ):
        if key in summary:
            sanitized[key] = summary.get(key)
    return sanitized


def _sanitize_external_rag_asset(asset: Any) -> Dict[str, Any]:
    if not isinstance(asset, dict):
        return {}
    sanitized: Dict[str, Any] = {}
    for key in (
        "asset_id",
        "title",
        "asset_type",
        "source_label",
        "description",
        "summary",
        "preview",
        "headings",
        "key_points",
        "focus_terms",
        "usage_guidance",
        "tags",
        "attributes",
        "library_status",
        "checked_out_at",
        "last_checked_in_at",
        "import_method",
        "original_filename",
        "created_at",
        "updated_at",
        "text_char_count",
        "word_count",
    ):
        if key in asset:
            sanitized[key] = asset.get(key)
    return sanitized


def _sanitize_external_rag_asset_summary(summary: Any) -> Dict[str, Any]:
    if not isinstance(summary, dict):
        return {}
    return {
        "asset_count": int(summary.get("asset_count") or 0),
        "checked_in_asset_count": int(summary.get("checked_in_asset_count") or 0),
        "checked_out_asset_count": int(summary.get("checked_out_asset_count") or 0),
        "library_status_counts": dict(summary.get("library_status_counts") or {}),
        "asset_type_counts": dict(summary.get("asset_type_counts") or {}),
        "assets": [
            _sanitize_external_rag_asset(asset)
            for asset in (summary.get("assets") or [])
            if isinstance(asset, dict)
        ],
    }


def _sanitize_external_rag_chunk(chunk: Any) -> Dict[str, Any]:
    if not isinstance(chunk, dict):
        return {}
    metadata = chunk.get("metadata") if isinstance(chunk.get("metadata"), dict) else {}
    sanitized: Dict[str, Any] = {
        "source": chunk.get("source"),
        "score": chunk.get("score"),
        "snippet": chunk.get("snippet"),
        "document_id": chunk.get("document_id") or metadata.get("document_id"),
        "section": chunk.get("section") or metadata.get("section"),
        "asset_id": chunk.get("asset_id") or metadata.get("asset_id"),
        "asset_title": chunk.get("asset_title") or metadata.get("asset_title"),
    }
    if metadata.get("source_type"):
        sanitized["source_type"] = metadata.get("source_type")
    if metadata.get("asset_type"):
        sanitized["asset_type"] = metadata.get("asset_type")
    if metadata.get("asset_source_label"):
        sanitized["asset_source_label"] = metadata.get("asset_source_label")
    return sanitized


def _sanitize_external_rag_match_chunk(chunk: Any) -> Dict[str, Any]:
    if not isinstance(chunk, dict):
        return {}
    return {
        "document_id": chunk.get("document_id"),
        "section": chunk.get("section"),
        "score": chunk.get("score"),
        "snippet": chunk.get("snippet"),
        "source": chunk.get("source"),
    }


def _sanitize_external_rag_matched_asset(asset: Any) -> Dict[str, Any]:
    sanitized = _sanitize_external_rag_asset(asset)
    if not isinstance(asset, dict):
        return sanitized
    for key in (
        "spl_query",
        "reuse_tier",
        "reuse_score",
        "known_good",
        "validation_status",
        "environment_fit_status",
        "environment_fit_score",
        "environment_fit_reason",
        "matched_sections",
        "matched_chunk_ids",
        "best_excerpt",
        "best_chunk_document_id",
        "match_score",
        "why_matched",
    ):
        if key in asset:
            sanitized[key] = asset.get(key)
    sanitized["matched_chunks"] = [
        _sanitize_external_rag_match_chunk(chunk)
        for chunk in (asset.get("matched_chunks") or [])
        if isinstance(chunk, dict)
    ]
    return sanitized


def _sanitize_external_rag_chunk_section(section: Any) -> Dict[str, Any]:
    if not isinstance(section, dict):
        return {}
    metadata = section.get("metadata") if isinstance(section.get("metadata"), dict) else {}
    sanitized_metadata: Dict[str, Any] = {}
    for key in ("source_type", "asset_type", "asset_source_label"):
        if key in metadata:
            sanitized_metadata[key] = metadata.get(key)
    return {
        "document_id": section.get("document_id"),
        "section": section.get("section"),
        "content": section.get("content"),
        "character_count": section.get("character_count"),
        "source_name": section.get("source_name"),
        "metadata": sanitized_metadata,
    }


def _sanitize_external_reusable_spl_query(candidate: Any) -> Dict[str, Any]:
    if not isinstance(candidate, dict):
        return {}
    sanitized: Dict[str, Any] = {}
    for key in (
        "asset_id",
        "title",
        "query",
        "source_label",
        "intent",
        "environment_fit_status",
        "environment_fit_score",
        "validation_status",
        "success_count",
        "failure_count",
        "reuse_tier",
        "reuse_score",
        "known_good",
        "why_reuse",
        "app",
        "earliest",
        "latest",
    ):
        if key in candidate:
            sanitized[key] = candidate.get(key)
    return sanitized


def _sanitize_external_rag_search_result(details: Any) -> Dict[str, Any]:
    if not isinstance(details, dict):
        return {}
    return {
        "provider": "rag_chromadb",
        "query": str(details.get("query") or "").strip(),
        "message": str(details.get("message") or "").strip(),
        "context_text": str(details.get("context_text") or "").strip(),
        "operator_brief": str(details.get("operator_brief") or "").strip(),
        "chunks": [
            _sanitize_external_rag_chunk(chunk)
            for chunk in (details.get("chunks") or [])
            if isinstance(chunk, dict)
        ],
        "matched_assets": [
            _sanitize_external_rag_matched_asset(asset)
            for asset in (details.get("matched_assets") or [])
            if isinstance(asset, dict)
        ],
        "reusable_spl_queries": [
            _sanitize_external_reusable_spl_query(candidate)
            for candidate in (details.get("reusable_spl_queries") or [])
            if isinstance(candidate, dict)
        ],
        "retrieved_key_points": list(details.get("retrieved_key_points") or []),
        "recommended_uses": list(details.get("recommended_uses") or []),
        "coverage_gaps": list(details.get("coverage_gaps") or []),
        "coverage_summary": dict(details.get("coverage_summary") or {}),
        "index_summary": _sanitize_external_rag_index_summary(details.get("index_summary") or {}),
        "asset_summary": _sanitize_external_rag_asset_summary(details.get("asset_summary") or {}),
    }


def _sanitize_external_rag_asset_detail(detail: Any) -> Dict[str, Any]:
    if not isinstance(detail, dict):
        return {}
    return {
        "asset": _sanitize_external_rag_asset(detail.get("asset") or {}),
        "stored_sections": list(detail.get("stored_sections") or []),
        "context_body": detail.get("context_body"),
        "context_character_count": detail.get("context_character_count"),
        "chunk_sections": [
            _sanitize_external_rag_chunk_section(section)
            for section in (detail.get("chunk_sections") or [])
            if isinstance(section, dict)
        ],
        "chunk_count": int(detail.get("chunk_count") or 0),
        "index_summary": _sanitize_external_rag_index_summary(detail.get("index_summary") or {}),
    }


def _sanitize_external_artifact_metadata(metadata: Any) -> Dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    sanitized: Dict[str, Any] = {}
    for key in (
        "name",
        "size",
        "size_bytes",
        "modified",
        "modified_at",
        "type",
        "artifact_kind",
        "session_timestamp",
    ):
        if key in metadata:
            sanitized[key] = metadata.get(key)
    return sanitized


def _sanitize_external_capability_state(state: Any) -> Dict[str, Any]:
    if not isinstance(state, dict):
        return {}

    sanitized: Dict[str, Any] = {}
    for key in (
        "name",
        "title",
        "category",
        "description",
        "purpose",
        "intent",
        "capability_set",
        "dependency_packages",
        "runtime_available",
        "requires_restart_on_install",
        "maturity",
        "installed",
        "enabled",
        "version",
        "health_status",
        "health_message",
        "last_tested_at",
        "restart_required",
        "installed_at",
    ):
        if key in state:
            sanitized[key] = copy.deepcopy(state.get(key))

    if isinstance(state.get("index_summary"), dict):
        sanitized["index_summary"] = _sanitize_external_rag_index_summary(state.get("index_summary") or {})
    if isinstance(state.get("knowledge_asset_summary"), dict):
        sanitized["knowledge_asset_summary"] = _sanitize_external_rag_asset_summary(
            state.get("knowledge_asset_summary") or {}
        )

    export_summary: Dict[str, Any] = {}
    for key in (
        "supported_outputs",
        "max_bundle_files",
        "available_session_count",
        "latest_session_timestamp",
        "bundle_count",
    ):
        if key in state:
            export_summary[key] = copy.deepcopy(state.get(key))

    latest_bundle = state.get("latest_bundle") if isinstance(state.get("latest_bundle"), dict) else None
    if latest_bundle is not None:
        export_summary["latest_bundle"] = {
            key: latest_bundle.get(key)
            for key in ("name", "size_bytes", "modified_at")
            if key in latest_bundle
        }

    if export_summary:
        sanitized.update(export_summary)

    if "preview_enabled" in state:
        sanitized["preview_enabled"] = bool(state.get("preview_enabled"))

    if any(key in state for key in ("web_base_url", "base_url", "mcp_url")):
        sanitized["web_base_url_configured"] = bool(
            state.get("web_base_url") or state.get("base_url") or state.get("mcp_url")
        )

    return sanitized


def _sanitize_external_discovery_session_summary(session: Any) -> Dict[str, Any]:
    if not isinstance(session, dict):
        return {}
    overview = session.get("overview") if isinstance(session.get("overview"), dict) else {}
    stats = session.get("stats") if isinstance(session.get("stats"), dict) else {}
    mcp_capabilities = session.get("mcp_capabilities") if isinstance(session.get("mcp_capabilities"), dict) else {}
    return {
        "timestamp": session.get("timestamp"),
        "readiness_score": _safe_int(session.get("readiness_score")),
        "overview": {
            "total_indexes": _safe_int(overview.get("total_indexes")),
            "total_sourcetypes": _safe_int(overview.get("total_sourcetypes")),
            "total_hosts": _safe_int(overview.get("total_hosts")),
            "license_state": str(overview.get("license_state", "unknown") or "unknown"),
        },
        "stats": {
            "recommendation_count": _safe_int(stats.get("recommendation_count")),
        },
        "mcp_capabilities": {
            "tool_count": _safe_int(mcp_capabilities.get("tool_count")),
        },
    }


def _sanitize_external_discovery_value(value: Any) -> Any:
    blocked_keys = {
        "path",
        "content_path",
        "stored_path",
        "storage_dir",
        "source_dir",
        "asset_dir",
        "export_dir",
        "output_dir",
        "manifest_path",
        "sensitive_local_path",
        "local_path",
    }
    if isinstance(value, dict):
        sanitized: Dict[str, Any] = {}
        for key, nested_value in value.items():
            normalized_key = str(key).strip().lower()
            if normalized_key in blocked_keys:
                continue
            sanitized[str(key)] = _sanitize_external_discovery_value(nested_value)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_external_discovery_value(item) for item in value]
    return copy.deepcopy(value)


EXTERNAL_MCP_PROTOCOL_VERSION = "2025-03-26"
EXTERNAL_MCP_SERVER_NAME = "dt4sms-external-mcp"
EXTERNAL_MCP_TOOL_DEFINITIONS = [
    {
        "name": "rag_search",
        "description": "Search the Splunk Discovery Tool RAG knowledge assets and return sanitized read-only results.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search prompt or problem statement."},
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of indexed chunks to retrieve.",
                    "minimum": 1,
                    "maximum": 10,
                    "default": 4,
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "rag_list_assets",
        "description": "List sanitized metadata for managed RAG knowledge assets.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "rag_get_asset_detail",
        "description": "Load sanitized detail for one managed RAG knowledge asset.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset_id": {"type": "string", "description": "Managed knowledge asset identifier."},
            },
            "required": ["asset_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "rag_build_context",
        "description": "Build a sanitized RAG context pack for a query, including matched assets and retrieved chunks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search prompt or problem statement."},
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of indexed chunks to retrieve.",
                    "minimum": 1,
                    "maximum": 10,
                    "default": 4,
                },
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
    {
        "name": "system_get_runtime_summary",
        "description": "Return a sanitized read-only Splunk Discovery Tool runtime summary, including auth posture, configured integrations, discovery coverage, and artifact availability.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "capabilities_list",
        "description": "List sanitized capability state and health summaries for the Splunk Discovery Tool optional capabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "refresh_health": {
                    "type": "boolean",
                    "description": "When true, refresh capability health before returning the summary.",
                    "default": False,
                }
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "capabilities_get_detail",
        "description": "Load sanitized detail for one Splunk Discovery Tool capability, including capability-specific readiness summaries when available.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "capability_name": {"type": "string", "description": "Registered Splunk Discovery Tool capability name."},
                "refresh_health": {
                    "type": "boolean",
                    "description": "When true, refresh capability health before returning the detail.",
                    "default": False,
                },
            },
            "required": ["capability_name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "artifacts_list",
        "description": "List sanitized generated Splunk Discovery Tool artifacts from the local output catalog.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of artifacts to return.",
                    "minimum": 1,
                    "maximum": 50,
                    "default": 20,
                },
                "session_timestamp": {
                    "type": "string",
                    "description": "Optional session timestamp filter in YYYYMMDD_HHMMSS format.",
                },
                "artifact_kind": {
                    "type": "string",
                    "description": "Optional artifact kind filter.",
                    "enum": ["report", "infographic"],
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "artifacts_get_detail",
        "description": "Load sanitized metadata and a bounded preview for one generated Splunk Discovery Tool artifact.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "artifact_name": {"type": "string", "description": "Artifact filename from the Splunk Discovery Tool output catalog."},
                "max_chars": {
                    "type": "integer",
                    "description": "Maximum preview characters to inline for textual artifacts.",
                    "minimum": 256,
                    "maximum": 50000,
                    "default": 12000,
                },
            },
            "required": ["artifact_name"],
            "additionalProperties": False,
        },
    },
    {
        "name": "discovery_get_dashboard",
        "description": "Return a compact read-only discovery dashboard summary with current KPIs, trends, and recent session summaries.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "discovery_get_latest_intelligence",
        "description": "Return the latest discovery intelligence blueprint with sanitized artifact metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "discovery_get_runbook",
        "description": "Build a persona-scoped discovery runbook for a selected session and return a compact read-only payload.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "timestamp": {
                    "type": "string",
                    "description": "Optional session timestamp selection in YYYYMMDD_HHMMSS format.",
                },
                "persona": {
                    "type": "string",
                    "description": "Runbook persona selection.",
                    "enum": ["admin", "analyst", "executive"],
                    "default": "admin",
                },
                "voice": {
                    "type": "string",
                    "description": "Operator voice used to frame the returned runbook.",
                    "enum": ["direct", "evidence", "executive"],
                    "default": "direct",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "discovery_compare_sessions",
        "description": "Compare two discovery sessions and return compact metrics, deltas, and selected session summaries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "current_selection": {
                    "type": "string",
                    "description": "Optional current session selector such as latest, previous, or a concrete timestamp.",
                },
                "baseline_selection": {
                    "type": "string",
                    "description": "Optional baseline session selector such as previous or a concrete timestamp.",
                },
            },
            "additionalProperties": False,
        },
    },
]


def _build_external_rag_index_summary_payload() -> Dict[str, Any]:
    rag_state = capability_manager.get_capability_state("rag_chromadb", refresh_health=False)
    return {
        "provider": "rag_chromadb",
        "installed": bool(rag_state.get("installed")),
        "enabled": bool(rag_state.get("enabled")),
        "health_status": rag_state.get("health_status"),
        "index_summary": _sanitize_external_rag_index_summary(rag_state.get("index_summary") or {}),
        "asset_summary": _sanitize_external_rag_asset_summary(rag_state.get("knowledge_asset_summary") or {}),
    }


def _normalize_external_rag_limit(value: Any, default: int = 4, maximum: int = 10) -> int:
    try:
        limit = int(value if value is not None else default)
    except (TypeError, ValueError) as exc:
        raise ValueError("Tool argument 'limit' must be an integer") from exc
    return max(1, min(limit, maximum))


def _build_external_rag_search_payload(query: str, limit: int = 4) -> Dict[str, Any]:
    result = capability_manager.build_rag_context_preview(
        "rag_chromadb",
        query,
        max_chunks=_normalize_external_rag_limit(limit),
    ).to_dict()
    _raise_for_capability_result(result)
    return _sanitize_external_rag_search_result(result.get("details") or {})


def _list_external_rag_assets_payload() -> Dict[str, Any]:
    result = capability_manager.list_rag_assets("rag_chromadb").to_dict()
    _raise_for_capability_result(result)
    return _sanitize_external_rag_asset_summary(result.get("details") or {})


def _get_external_rag_asset_detail_payload(asset_id: str) -> Dict[str, Any]:
    result = capability_manager.get_rag_asset_detail("rag_chromadb", asset_id).to_dict()
    _raise_for_capability_result(result)
    return _sanitize_external_rag_asset_detail(result.get("details") or {})


def _normalize_external_boolean(value: Any, field_name: str, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes", "on"}:
        return True
    if normalized in {"false", "0", "no", "off"}:
        return False
    raise ValueError(f"Tool argument '{field_name}' must be a boolean")


def _normalize_external_artifact_list_limit(value: Any, default: int = 20, maximum: int = 50) -> int:
    try:
        limit = int(value if value is not None else default)
    except (TypeError, ValueError) as exc:
        raise ValueError("Tool argument 'limit' must be an integer") from exc
    return max(1, min(limit, maximum))


def _normalize_external_artifact_preview_limit(value: Any, default: int = 12000, maximum: int = 50000) -> int:
    try:
        limit = int(value if value is not None else default)
    except (TypeError, ValueError) as exc:
        raise ValueError("Tool argument 'max_chars' must be an integer") from exc
    return max(256, min(limit, maximum))


def _normalize_external_persona(value: Any, default: str = "admin") -> str:
    persona = str(value or default).strip().lower()
    return persona if persona in {"admin", "analyst", "executive"} else default


def _normalize_operator_voice(value: Any, default: str = "direct") -> str:
    voice = str(value or default).strip().lower()
    return voice if voice in {"direct", "evidence", "executive"} else default


def _operator_voice_label(value: Any) -> str:
    voice = _normalize_operator_voice(value)
    if voice == "evidence":
        return "Evidence-led"
    if voice == "executive":
        return "Executive"
    return "Direct"


def _first_text_line(value: Any) -> str:
    entries = value if isinstance(value, list) else [value]
    for entry in entries:
        if isinstance(entry, dict):
            entry = entry.get("action") or entry.get("step") or entry.get("title") or entry.get("description")
        text = " ".join(str(entry or "").split())
        if text:
            return text
    return ""


# Voice items leave a field empty when discovery recorded nothing for it, so
# runbooks never pad every step with the same generic advice.
def _build_operator_voice_admin_item(action: Dict[str, Any], voice: str) -> Dict[str, str]:
    title = str(action.get("title") or "Admin follow-up").strip() or "Admin follow-up"
    why = str(action.get("why") or "").strip()
    next_step = str(action.get("next_step") or "").strip()
    effort = str(action.get("effort") or "").strip()
    if effort.lower() == "unknown":
        effort = ""

    if voice == "evidence":
        summary_prefix, meta_prefix = "", "How to verify: "
    elif voice == "executive":
        summary_prefix, meta_prefix = "Risk if ignored: ", "Decision needed: "
    else:
        summary_prefix, meta_prefix = "", "Next step: "
    return {
        "title": title,
        "summary": f"{summary_prefix}{why}" if why else "",
        "meta": f"{meta_prefix}{next_step}" if next_step else "",
        "badge": f"Effort: {effort}" if effort else "",
    }


def _build_operator_voice_analyst_item(track: Dict[str, Any], voice: str) -> Dict[str, str]:
    title = str(track.get("title") or "Investigation track").strip() or "Investigation track"
    question = str(track.get("question") or "").strip()
    success_metric = str(track.get("success_metric") or "").strip()

    if voice == "evidence":
        summary_prefix, meta_prefix = "", "Proof: "
    elif voice == "executive":
        summary_prefix, meta_prefix = "If confirmed: ", "Why it matters: "
    else:
        summary_prefix, meta_prefix = "Check: ", "Done when: "
    return {
        "title": title,
        "summary": f"{summary_prefix}{question}" if question else "",
        "meta": f"{meta_prefix}{success_metric}" if success_metric else "",
    }


def _build_operator_voice_executive_item(item: Any, voice: str, index: int, item_type: str = "theme") -> Dict[str, str]:
    summary = str(item or "").strip()

    if voice == "evidence":
        title = f"{'Evidence theme' if item_type == 'theme' else '90-day check'} {index}"
    elif voice == "executive":
        title = f"{'Board theme' if item_type == 'theme' else 'Quarter priority'} {index}"
    else:
        title = f"{'Theme' if item_type == 'theme' else '90-day action'} {index}"
    return {"title": title, "summary": summary, "meta": ""}


def _build_external_runtime_summary_payload() -> Dict[str, Any]:
    config = config_manager.get()
    artifact_catalog = build_v2_artifact_catalog()
    artifact_items = [
        _sanitize_external_artifact_metadata(artifact)
        for artifact in (artifact_catalog.get("artifacts") or [])
        if isinstance(artifact, dict)
    ]
    discovery_sessions = load_discovery_sessions()
    latest_session = discovery_sessions[0] if discovery_sessions else None
    latest_blueprint = load_latest_v2_blueprint()
    latest_blueprint_artifact = None
    if isinstance(latest_blueprint, dict):
        latest_blueprint_artifact = _sanitize_external_artifact_metadata(latest_blueprint.get("_artifact") or {})

    return {
        "version": str(getattr(config, "version", "1.0.0") or "1.0.0"),
        "security": {
            "auth_enabled": bool(config.security.auth_enabled),
            "auth_provider": str(config.security.auth_provider or "local_password"),
            "external_api_enabled": bool(config.security.external_api_enabled),
            "external_mcp_enabled": bool(config.security.external_mcp_enabled),
            "session_timeout_minutes": int(config.security.session_timeout_minutes or 0),
            "password_min_length": int(config.security.password_min_length or 0),
            "oidc": {
                "issuer_configured": bool(config.security.oidc.issuer_url),
                "client_id_configured": bool(config.security.oidc.client_id),
                "client_secret_configured": bool(config.security.oidc.client_secret),
                "audience_configured": bool(config.security.oidc.audience),
                "scopes": list(config.security.oidc.scopes or []),
            },
        },
        "llm": {
            "provider": str(config.llm.provider or ""),
            "model": str(config.llm.model or ""),
            "endpoint_configured": bool(config.llm.endpoint_url),
            "api_key_configured": bool(config.llm.api_key),
            "active_credential_name": config.active_credential_name,
        },
        "mcp": {
            "url_configured": bool(config.mcp.url),
            "verify_ssl": bool(config.mcp.verify_ssl),
            "ca_bundle_configured": bool(config.mcp.ca_bundle_path),
            "active_config_name": config.active_mcp_config_name,
        },
        "server": {
            "port": int(config.server.port or 0),
            "debug_mode": bool(config.server.debug_mode),
        },
        "capabilities": capability_manager.get_summary(),
        "discovery": {
            "session_count": len(discovery_sessions),
            "latest_session_timestamp": latest_session.get("timestamp") if isinstance(latest_session, dict) else None,
            "latest_readiness_score": _safe_int(latest_session.get("readiness_score")) if isinstance(latest_session, dict) else 0,
        },
        "artifacts": {
            "count": int(artifact_catalog.get("count") or 0),
            "latest": artifact_items[0] if artifact_items else None,
            "latest_blueprint": latest_blueprint_artifact,
        },
    }


def _build_external_capabilities_list_payload(refresh_health: bool = False) -> Dict[str, Any]:
    capability_states = capability_manager.list_capabilities(refresh_health=bool(refresh_health))
    sanitized_capabilities = [
        _sanitize_external_capability_state(state)
        for _, state in sorted(capability_states.items(), key=lambda item: item[0])
    ]
    return {
        "summary": capability_manager.get_summary(),
        "capabilities": sanitized_capabilities,
    }


def _build_external_capability_detail_payload(capability_name: str, refresh_health: bool = False) -> Dict[str, Any]:
    try:
        state = capability_manager.get_capability_state(capability_name, refresh_health=bool(refresh_health))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown capability '{capability_name}'") from exc
    return {
        "capability": _sanitize_external_capability_state(state),
    }


def _build_external_artifacts_list_payload(
    *,
    limit: int = 20,
    session_timestamp: Optional[str] = None,
    artifact_kind: Optional[str] = None,
) -> Dict[str, Any]:
    catalog = build_v2_artifact_catalog()
    artifacts = [artifact for artifact in (catalog.get("artifacts") or []) if isinstance(artifact, dict)]

    selected_session_timestamp = str(session_timestamp or "").strip()
    if selected_session_timestamp:
        selected_session_timestamp = validate_session_id(selected_session_timestamp)
        artifacts = [
            artifact
            for artifact in artifacts
            if str(artifact.get("session_timestamp") or "") == selected_session_timestamp
        ]

    selected_artifact_kind = str(artifact_kind or "").strip().lower()
    if selected_artifact_kind:
        if selected_artifact_kind not in {"report", "infographic"}:
            raise ValueError("Tool argument 'artifact_kind' must be 'report' or 'infographic'")
        artifacts = [
            artifact
            for artifact in artifacts
            if str(artifact.get("artifact_kind") or "").strip().lower() == selected_artifact_kind
        ]

    limited_artifacts = artifacts[: _normalize_external_artifact_list_limit(limit)]
    return {
        "has_data": len(artifacts) > 0,
        "count": len(artifacts),
        "returned": len(limited_artifacts),
        "artifacts": [_sanitize_external_artifact_metadata(artifact) for artifact in limited_artifacts],
    }


def _build_external_artifact_detail_payload(artifact_name: str, max_chars: int = 12000) -> Dict[str, Any]:
    artifact_path = _resolve_external_catalog_artifact_path(artifact_name)
    artifact_metadata = _sanitize_external_artifact_metadata(_build_artifact_metadata(artifact_path))
    suffix = artifact_path.suffix.lower()

    if suffix in IMAGE_ARTIFACT_EXTENSIONS:
        return {
            "artifact": artifact_metadata,
            "content_kind": "binary",
            "top_level_kind": None,
            "top_level_keys": [],
            "preview": None,
            "truncated": False,
            "total_chars": 0,
            "preview_unavailable_reason": "Binary artifacts are not inlined over the external MCP surface.",
        }

    raw_text = artifact_path.read_text(encoding="utf-8", errors="replace")
    preview_source = raw_text
    content_kind = "text"
    top_level_kind: Optional[str] = None
    top_level_keys: List[str] = []

    if suffix == ".json":
        try:
            parsed_payload = json.loads(raw_text)
        except json.JSONDecodeError:
            parsed_payload = None
        else:
            content_kind = "json"
            if isinstance(parsed_payload, dict):
                top_level_kind = "object"
                top_level_keys = sorted(str(key) for key in parsed_payload.keys())[:50]
            elif isinstance(parsed_payload, list):
                top_level_kind = "array"
            else:
                top_level_kind = type(parsed_payload).__name__
            preview_source = json.dumps(parsed_payload, indent=2, ensure_ascii=False)

    preview_limit = _normalize_external_artifact_preview_limit(max_chars)
    return {
        "artifact": artifact_metadata,
        "content_kind": content_kind,
        "top_level_kind": top_level_kind,
        "top_level_keys": top_level_keys,
        "preview": truncate_prompt_text(preview_source, preview_limit, "\n... [artifact preview truncated]"),
        "truncated": len(preview_source) > preview_limit,
        "total_chars": len(preview_source),
    }


def _build_external_discovery_dashboard_payload() -> Dict[str, Any]:
    payload = build_discovery_dashboard_payload()
    sessions = [
        _sanitize_external_discovery_session_summary(session)
        for session in (payload.get("sessions") or [])
        if isinstance(session, dict)
    ]
    if not payload.get("has_data"):
        return {
            "has_data": False,
            "message": str(payload.get("message") or "No discovery runs yet."),
            "sessions": sessions,
        }
    return {
        "has_data": True,
        "kpis": dict(payload.get("kpis") or {}),
        "trends": dict(payload.get("trends") or {}),
        "latest_session": _sanitize_external_discovery_session_summary(payload.get("latest") or {}),
        "previous_session": _sanitize_external_discovery_session_summary(payload.get("previous") or {}),
        "sessions": sessions,
    }


def _build_external_latest_intelligence_payload() -> Dict[str, Any]:
    payload = load_latest_v2_blueprint()
    if not isinstance(payload, dict):
        return {
            "has_data": False,
            "message": "No intelligence blueprint found.",
        }
    blueprint = _sanitize_external_discovery_value(
        {
            key: value
            for key, value in payload.items()
            if key != "_artifact"
        }
    )
    return {
        "has_data": True,
        "artifact": _sanitize_external_artifact_metadata(payload.get("_artifact") or {}),
        "top_level_keys": sorted(str(key) for key in blueprint.keys())[:50],
        "blueprint": blueprint,
    }
def _build_external_discovery_runbook_payload(
    timestamp: Optional[str] = None,
    persona: str = "admin",
    voice: str = "direct",
) -> Dict[str, Any]:
    payload = build_session_runbook_payload(
        timestamp,
        _normalize_external_persona(persona),
        _normalize_operator_voice(voice),
    )
    sessions = [
        _sanitize_external_discovery_session_summary(session)
        for session in (payload.get("sessions") or [])
        if isinstance(session, dict)
    ]
    if not payload.get("has_data"):
        return {
            "has_data": False,
            "message": str(payload.get("message") or "No discovery runs yet."),
            "sessions": sessions,
        }
    return {
        "has_data": True,
        "persona": str(payload.get("persona") or _normalize_external_persona(persona)),
        "voice": str(payload.get("voice") or _normalize_operator_voice(voice)),
        "voice_label": str(payload.get("voice_label") or _operator_voice_label(voice)),
        "title": str(payload.get("title") or "Discovery Runbook"),
        "filename": str(payload.get("filename") or "runbook.md"),
        "markdown": str(payload.get("markdown") or ""),
        "steps": list(payload.get("steps") or []),
        "session": _sanitize_external_discovery_session_summary(payload.get("session") or {}),
        "sessions": sessions,
    }


def _build_external_discovery_compare_payload(
    current_selection: Optional[str] = None,
    baseline_selection: Optional[str] = None,
) -> Dict[str, Any]:
    payload = build_discovery_compare_payload(current_selection, baseline_selection)
    sessions = [
        _sanitize_external_discovery_session_summary(session)
        for session in (payload.get("sessions") or [])
        if isinstance(session, dict)
    ]
    if not payload.get("has_data"):
        return {
            "has_data": False,
            "message": str(payload.get("message") or "Could not compare discovery runs."),
            "sessions": sessions,
            "current_session": _sanitize_external_discovery_session_summary(payload.get("current") or {}),
            "baseline_session": _sanitize_external_discovery_session_summary(payload.get("baseline") or {}),
        }
    return {
        "has_data": True,
        "metrics": copy.deepcopy(payload.get("metrics") or {}),
        "persona_deltas": copy.deepcopy(payload.get("persona_deltas") or {}),
        "current_session": _sanitize_external_discovery_session_summary(payload.get("current") or {}),
        "baseline_session": _sanitize_external_discovery_session_summary(payload.get("baseline") or {}),
        "sessions": sessions,
    }


def _build_external_mcp_info_payload() -> Dict[str, Any]:
    return {
        "server_name": EXTERNAL_MCP_SERVER_NAME,
        "status": "available",
        "version": "v1",
        "transport": "jsonrpc-http",
        "endpoint": "/api/external/mcp",
        "authentication": {
            "scheme": "bearer",
            "header": "Authorization: Bearer <token>",
            "token_type": "inbound_mcp",
            "required_scopes": ["mcp:tools:read"],
        },
        "protocol": {
            "jsonrpc": "2.0",
            "mcp_protocol_version": EXTERNAL_MCP_PROTOCOL_VERSION,
        },
        "tools": [
            {
                "name": tool.get("name"),
                "description": tool.get("description"),
                "required_scope": "mcp:tools:read",
            }
            for tool in EXTERNAL_MCP_TOOL_DEFINITIONS
        ],
    }


def _build_external_mcp_initialize_result() -> Dict[str, Any]:
    return {
        "protocolVersion": EXTERNAL_MCP_PROTOCOL_VERSION,
        "serverInfo": {
            "name": EXTERNAL_MCP_SERVER_NAME,
            "version": APP_VERSION,
        },
        "capabilities": {
            "tools": {
                "listChanged": False,
            }
        },
        "instructions": "Use bearer auth with an inbound_mcp token scoped for mcp:tools:read. All tools are read-only wrappers over Splunk Discovery Tool RAG, artifact, capability, and runtime summary surfaces.",
    }


def _build_jsonrpc_success_response(request_id: Any, result: Dict[str, Any], status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result,
        },
    )


def _build_jsonrpc_error_response(
    request_id: Any,
    code: int,
    message: str,
    *,
    data: Optional[Any] = None,
    status_code: int = 400,
) -> JSONResponse:
    error: Dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if data is not None:
        error["data"] = data
    return JSONResponse(
        status_code=status_code,
        content={
            "jsonrpc": "2.0",
            "id": request_id,
            "error": error,
        },
    )


def _handle_external_mcp_tool_call(request_id: Any, params: Any) -> JSONResponse:
    if not isinstance(params, dict):
        return _build_jsonrpc_error_response(request_id, -32602, "MCP tools/call requires an object params payload")

    tool_name = str(params.get("name") or "").strip()
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    if not tool_name:
        return _build_jsonrpc_error_response(request_id, -32602, "Tool name is required")

    try:
        if tool_name == "rag_search":
            query = str(arguments.get("query") or "").strip()
            if not query:
                return _build_jsonrpc_error_response(request_id, -32602, "Tool argument 'query' is required")
            payload = _build_external_rag_search_payload(query, arguments.get("limit", 4))
            message = f"Retrieved read-only RAG search results for '{query}'."
        elif tool_name == "rag_build_context":
            query = str(arguments.get("query") or "").strip()
            if not query:
                return _build_jsonrpc_error_response(request_id, -32602, "Tool argument 'query' is required")
            payload = _build_external_rag_search_payload(query, arguments.get("limit", 4))
            message = f"Built a read-only RAG context pack for '{query}'."
        elif tool_name == "rag_list_assets":
            payload = _list_external_rag_assets_payload()
            message = f"Retrieved {int(payload.get('asset_count') or 0)} managed RAG asset(s)."
        elif tool_name == "rag_get_asset_detail":
            asset_id = str(arguments.get("asset_id") or "").strip()
            if not asset_id:
                return _build_jsonrpc_error_response(request_id, -32602, "Tool argument 'asset_id' is required")
            payload = _get_external_rag_asset_detail_payload(asset_id)
            message = f"Retrieved managed RAG asset detail for '{asset_id}'."
        elif tool_name == "system_get_runtime_summary":
            payload = _build_external_runtime_summary_payload()
            message = "Retrieved a sanitized Splunk Discovery Tool runtime summary."
        elif tool_name == "capabilities_list":
            payload = _build_external_capabilities_list_payload(
                refresh_health=_normalize_external_boolean(arguments.get("refresh_health"), "refresh_health", False)
            )
            message = f"Retrieved {len(payload.get('capabilities') or [])} sanitized capability summary record(s)."
        elif tool_name == "capabilities_get_detail":
            capability_name = str(arguments.get("capability_name") or "").strip()
            if not capability_name:
                return _build_jsonrpc_error_response(request_id, -32602, "Tool argument 'capability_name' is required")
            payload = _build_external_capability_detail_payload(
                capability_name,
                refresh_health=_normalize_external_boolean(arguments.get("refresh_health"), "refresh_health", False),
            )
            message = f"Retrieved sanitized capability detail for '{capability_name}'."
        elif tool_name == "artifacts_list":
            payload = _build_external_artifacts_list_payload(
                limit=arguments.get("limit", 20),
                session_timestamp=arguments.get("session_timestamp"),
                artifact_kind=arguments.get("artifact_kind"),
            )
            message = f"Retrieved {int(payload.get('returned') or 0)} sanitized artifact record(s)."
        elif tool_name == "artifacts_get_detail":
            artifact_name = str(arguments.get("artifact_name") or "").strip()
            if not artifact_name:
                return _build_jsonrpc_error_response(request_id, -32602, "Tool argument 'artifact_name' is required")
            payload = _build_external_artifact_detail_payload(
                artifact_name,
                max_chars=arguments.get("max_chars", 12000),
            )
            message = f"Retrieved sanitized artifact detail for '{artifact_name}'."
        elif tool_name == "discovery_get_dashboard":
            payload = _build_external_discovery_dashboard_payload()
            message = "Retrieved the sanitized discovery dashboard summary."
        elif tool_name == "discovery_get_latest_intelligence":
            payload = _build_external_latest_intelligence_payload()
            message = "Retrieved the latest sanitized discovery intelligence blueprint."
        elif tool_name == "discovery_get_runbook":
            payload = _build_external_discovery_runbook_payload(
                timestamp=str(arguments.get("timestamp") or "").strip() or None,
                persona=_normalize_external_persona(arguments.get("persona"), "admin"),
                voice=_normalize_operator_voice(arguments.get("voice"), "direct"),
            )
            message = f"Retrieved the sanitized discovery runbook for persona '{payload.get('persona', 'admin')}'."
        elif tool_name == "discovery_compare_sessions":
            payload = _build_external_discovery_compare_payload(
                current_selection=str(arguments.get("current_selection") or "").strip() or None,
                baseline_selection=str(arguments.get("baseline_selection") or "").strip() or None,
            )
            message = "Retrieved the sanitized discovery session comparison payload."
        else:
            return _build_jsonrpc_error_response(request_id, -32601, f"Unknown MCP tool '{tool_name}'")
    except ValueError as exc:
        return _build_jsonrpc_error_response(request_id, -32602, str(exc))
    except HTTPException as exc:
        return _build_jsonrpc_error_response(
            request_id,
            -32000,
            str(exc.detail),
            status_code=exc.status_code,
        )
    except Exception as exc:
        return _build_jsonrpc_error_response(request_id, -32000, f"Tool execution failed: {str(exc)}", status_code=500)

    return _build_jsonrpc_success_response(
        request_id,
        {
            "content": [{"type": "text", "text": message}],
            "structuredContent": payload,
        },
    )


def build_login_page() -> str:
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Sign in to Splunk Discovery Tool</title>
    <style>
        body { margin: 0; font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #0f172a, #1e293b 55%, #334155); color: #e2e8f0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .panel { width: min(420px, calc(100vw - 32px)); background: rgba(15, 23, 42, 0.92); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 18px; box-shadow: 0 24px 80px rgba(15, 23, 42, 0.45); padding: 32px; }
        .eyebrow { text-transform: uppercase; letter-spacing: 0.18em; font-size: 11px; color: #93c5fd; }
        h1 { margin: 10px 0 8px; font-size: 28px; }
        p { color: #cbd5e1; line-height: 1.5; }
        label { display: block; font-size: 13px; font-weight: 600; margin: 18px 0 8px; color: #e2e8f0; }
        input { width: 100%; box-sizing: border-box; border: 1px solid #475569; border-radius: 10px; padding: 12px 14px; background: #0f172a; color: #f8fafc; }
        button { margin-top: 20px; width: 100%; border: 0; border-radius: 10px; padding: 12px 14px; background: #2563eb; color: white; font-weight: 700; cursor: pointer; }
        button:hover { background: #1d4ed8; }
        .hint { margin-top: 18px; font-size: 12px; color: #94a3b8; }
        .error { margin-top: 14px; min-height: 20px; color: #fda4af; font-size: 13px; }
    </style>
</head>
<body>
    <div class="panel">
        <div class="eyebrow">Security Enabled</div>
        <h1>Sign in to Splunk Discovery Tool</h1>
        <p>Authentication is enabled for this installation. Sign in to continue.</p>
        <form id="login-form">
            <label for="username">Username</label>
            <input id="username" name="username" autocomplete="username" required />
            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required />
            <button type="submit">Sign In</button>
            <div id="login-error" class="error" aria-live="polite"></div>
        </form>
        <div class="hint">A password reset may be required before normal access is granted.</div>
    </div>
    <script>
        const form = document.getElementById('login-form');
        const errorNode = document.getElementById('login-error');
        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            errorNode.textContent = '';
            const payload = {
                username: document.getElementById('username').value,
                password: document.getElementById('password').value,
            };
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await response.json().catch(() => ({}));
            if (!response.ok) {
                errorNode.textContent = data.detail || 'Sign in failed.';
                return;
            }
            window.location.href = '/';
        });
    </script>
</body>
</html>
"""


def build_oidc_login_page(provider_status: Dict[str, Any]) -> str:
    issuer_url = html.escape(str(provider_status.get("issuer_url") or "Not configured"))
    button_disabled = "disabled" if not provider_status.get("ready") else ""
    button_label = "Sign In With OpenID Connect" if provider_status.get("ready") else "OIDC Provider Not Ready"
    helper_text = (
        "Sign in with your organization's identity provider."
        if provider_status.get("ready")
        else "OIDC authentication is enabled, but issuer URL, client ID, or client secret is still incomplete."
    )
    button_opacity = "opacity:0.55; cursor:not-allowed;" if button_disabled else ""
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Sign in to Splunk Discovery Tool</title>
    <style>
        body {{ margin: 0; font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #0f172a, #1e293b 55%, #1d4ed8); color: #e2e8f0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .panel {{ width: min(460px, calc(100vw - 32px)); background: rgba(15, 23, 42, 0.92); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 18px; box-shadow: 0 24px 80px rgba(15, 23, 42, 0.45); padding: 32px; }}
        .eyebrow {{ text-transform: uppercase; letter-spacing: 0.18em; font-size: 11px; color: #93c5fd; }}
        h1 {{ margin: 10px 0 8px; font-size: 28px; }}
        p {{ color: #cbd5e1; line-height: 1.5; }}
        .issuer {{ margin-top: 18px; padding: 12px 14px; border-radius: 12px; background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(148, 163, 184, 0.25); font-size: 12px; color: #cbd5e1; word-break: break-word; }}
        .button {{ margin-top: 22px; display: inline-flex; width: 100%; align-items: center; justify-content: center; gap: 10px; box-sizing: border-box; border-radius: 12px; padding: 13px 16px; background: #2563eb; color: #fff; font-weight: 700; text-decoration: none; {button_opacity} }}
        .button:hover {{ background: #1d4ed8; }}
        .hint {{ margin-top: 18px; font-size: 12px; color: #94a3b8; }}
    </style>
</head>
<body>
    <div class="panel">
        <div class="eyebrow">Security Enabled</div>
        <h1>Sign in to Splunk Discovery Tool</h1>
        <p>{html.escape(helper_text)}</p>
        <div class="issuer"><strong>Issuer:</strong> {issuer_url}</div>
        <a class="button" href="/api/auth/oidc/start" {button_disabled}>
            <span>OpenID Connect</span>
            <span>{html.escape(button_label)}</span>
        </a>
        <div class="hint">After the identity provider confirms who you are, you return to Splunk Discovery Tool.</div>
    </div>
</body>
</html>
"""


def build_auth_error_page(title: str, message: str) -> str:
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{html.escape(title)}</title>
    <style>
        body {{ margin: 0; font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #111827, #1f2937); color: #e5e7eb; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .panel {{ width: min(460px, calc(100vw - 32px)); background: rgba(17, 24, 39, 0.95); border: 1px solid rgba(248, 113, 113, 0.25); border-radius: 18px; padding: 32px; box-shadow: 0 24px 80px rgba(15, 23, 42, 0.45); }}
        h1 {{ margin: 0 0 12px; font-size: 26px; }}
        p {{ color: #d1d5db; line-height: 1.6; }}
        a {{ color: #93c5fd; }}
    </style>
</head>
<body>
    <div class="panel">
        <h1>{html.escape(title)}</h1>
        <p>{html.escape(message)}</p>
        <p><a href="/">Return to sign-in</a></p>
    </div>
</body>
</html>
"""


def build_password_reset_page(username: str) -> str:
    safe_username = html.escape(str(username or ""))
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Reset password for Splunk Discovery Tool</title>
    <style>
        body {{ margin: 0; font-family: 'Segoe UI', sans-serif; background: linear-gradient(135deg, #111827, #1f2937 55%, #374151); color: #e5e7eb; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
        .panel {{ width: min(460px, calc(100vw - 32px)); background: rgba(17, 24, 39, 0.95); border: 1px solid rgba(148, 163, 184, 0.25); border-radius: 18px; box-shadow: 0 24px 80px rgba(15, 23, 42, 0.45); padding: 32px; }}
        .eyebrow {{ text-transform: uppercase; letter-spacing: 0.18em; font-size: 11px; color: #fbbf24; }}
        h1 {{ margin: 10px 0 8px; font-size: 28px; }}
        p {{ color: #d1d5db; line-height: 1.5; }}
        label {{ display: block; font-size: 13px; font-weight: 600; margin: 18px 0 8px; color: #f3f4f6; }}
        input {{ width: 100%; box-sizing: border-box; border: 1px solid #4b5563; border-radius: 10px; padding: 12px 14px; background: #111827; color: #f9fafb; }}
        button {{ margin-top: 20px; width: 100%; border: 0; border-radius: 10px; padding: 12px 14px; background: #d97706; color: white; font-weight: 700; cursor: pointer; }}
        button:hover {{ background: #b45309; }}
        .error {{ margin-top: 14px; min-height: 20px; color: #fda4af; font-size: 13px; }}
    </style>
</head>
<body>
    <div class="panel">
        <div class="eyebrow">Action Required</div>
        <h1>Reset Password</h1>
        <p>Signed in as <strong>{safe_username}</strong>. A password reset is required before normal access is granted.</p>
        <form id="reset-form">
            <label for="current_password">Current Password</label>
            <input id="current_password" name="current_password" type="password" autocomplete="current-password" required />
            <label for="new_password">New Password</label>
            <input id="new_password" name="new_password" type="password" autocomplete="new-password" required />
            <label for="confirm_password">Confirm New Password</label>
            <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required />
            <button type="submit">Update Password</button>
            <div id="reset-error" class="error" aria-live="polite"></div>
        </form>
    </div>
    <script>
        const form = document.getElementById('reset-form');
        const errorNode = document.getElementById('reset-error');
        form.addEventListener('submit', async (event) => {{
            event.preventDefault();
            errorNode.textContent = '';
            const payload = {{
                current_password: document.getElementById('current_password').value,
                new_password: document.getElementById('new_password').value,
                confirm_password: document.getElementById('confirm_password').value,
            }};
            const response = await fetch('/api/auth/reset-password', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify(payload),
            }});
            const data = await response.json().catch(() => ({{}}));
            if (!response.ok) {{
                errorNode.textContent = data.detail || 'Password reset failed.';
                return;
            }}
            window.location.href = '/';
        }});
    </script>
</body>
</html>
"""


def should_enable_rag_context_by_default() -> bool:
    """Return True when any persisted optional RAG capability is installed and enabled."""
    capability_configs = config_manager.list_capabilities()
    for definition in capability_registry.rag_definitions():
        config = capability_configs.get(definition.name)
        if config and config.installed and config.enabled:
            return True
    return False


def detect_chat_runtime_provider(config: Any, llm_client: Any = None) -> str:
    """Resolve the effective provider used by the active chat runtime."""
    configured_provider = normalize_provider_name(getattr(getattr(config, "llm", None), "provider", ""))
    if configured_provider and configured_provider not in {"custom", "custom endpoint"}:
        return configured_provider

    runtime_provider = normalize_provider_name(str(getattr(llm_client, "provider_type", "") or ""))
    if runtime_provider and runtime_provider != "custom":
        return runtime_provider

    endpoint_url = str(getattr(getattr(config, "llm", None), "endpoint_url", "") or "").lower()
    if "ollama" in endpoint_url or ":11434" in endpoint_url:
        return "ollama"

    return configured_provider or runtime_provider or "generic"


LOCAL_RUNTIME_PROVIDERS = {"custom", "generic", "ollama", "vllm", "local-vllm"}
REASONING_MARKUP_GUARD = (
    "Do not emit <think>, </think>, <thinking>, or chain-of-thought markup. "
    "Return either a direct answer or a single <TOOL_CALL> block plus one short sentence."
)


def resolve_active_llm_tuning(config: Any, allow_fetch: bool = False) -> Dict[str, Any]:
    """Return the effective tuning for the configured model (profile, budgets, timeouts)."""
    return resolve_llm_tuning(getattr(config, "llm", None), allow_fetch=allow_fetch)


def get_effective_llm_max_tokens(config: Any) -> int:
    """Return the output budget the app plans against for the configured model."""
    try:
        return int(resolve_active_llm_tuning(config)["max_tokens"])
    except Exception:
        try:
            return max(512, int(getattr(getattr(config, "llm", None), "max_tokens", 4096) or 4096))
        except (TypeError, ValueError):
            return 4096


def llm_call_budget(config: Any, fraction: float, floor: int = 768, ceiling: Optional[int] = None) -> int:
    """Size one LLM call from the effective output budget, with a reasoning-aware floor."""
    try:
        tuning = resolve_active_llm_tuning(config)
        effective_max = int(tuning["max_tokens"])
        reasoning = bool(tuning.get("reasoning"))
    except Exception:
        effective_max = get_effective_llm_max_tokens(config)
        reasoning = False
    if reasoning:
        # Hidden reasoning tokens count against the budget, so small caps return empty text.
        floor = max(floor, 2048)
        if ceiling:
            ceiling = max(ceiling, floor)
    return budget_tokens(effective_max, fraction, floor, ceiling)


def build_chat_runtime_profile(config: Any, llm_client: Any = None) -> Dict[str, Any]:
    """Return chat budgets and prompt behavior tuned to the active model, with custom chat values applied."""
    effective_provider = detect_chat_runtime_provider(config, llm_client)
    model_name = str(getattr(getattr(config, "llm", None), "model", "") or "").strip().lower()
    tuning = resolve_active_llm_tuning(config)
    custom = chat_custom_settings()
    context_window = int(tuning.get("context_window") or 0)
    reasoning = bool(tuning.get("reasoning"))
    budgets = dict(tuning.get("chat") or {})
    output_cap = max(256, int(tuning.get("max_tokens") or 4096))
    if "max_tokens" in custom:
        output_cap = max(256, int(custom["max_tokens"]))
        model_output_limit = int(getattr(tuning.get("profile"), "max_output_tokens", 0) or 0)
        if model_output_limit > 0:
            output_cap = min(output_cap, model_output_limit)
        budgets = chat_budgets(output_cap, context_window, reasoning)

    def _cap(value: Any) -> int:
        return int(max(256, min(int(value or 1024), output_cap)))

    local_runtime = effective_provider in LOCAL_RUNTIME_PROVIDERS
    small_context = context_window <= 16384
    history_limit = int(custom.get("context_history") or budgets.get("history_turns") or 6)
    temperature = tuning.get("temperature")
    if "temperature" in custom and tuning.get("supports_temperature", True) is not False:
        temperature = float(custom["temperature"])

    return {
        "provider": effective_provider,
        "model": model_name,
        "auto_tune": bool(tuning.get("auto_tune", True)),
        "use_compact_prompt": local_runtime or small_context,
        "short_circuit_greetings": local_runtime,
        "context_history_limit": max(1, history_limit),
        "initial_max_tokens": _cap(budgets.get("initial_max_tokens")),
        "followup_max_tokens": _cap(budgets.get("followup_max_tokens")),
        "final_max_tokens": _cap(budgets.get("final_max_tokens")),
        "retry_max_tokens": _cap(budgets.get("retry_max_tokens")),
        "evidence_rows": int(budgets.get("evidence_rows") or 10),
        "evidence_chars": int(budgets.get("evidence_chars") or 6000),
        "prompt_budget_tokens": int(budgets.get("prompt_budget_tokens") or 6000),
        "context_window": context_window,
        "supports_tools": bool(tuning.get("supports_tools")),
        "reasoning": reasoning,
        "temperature": 0.2 if temperature is None else float(temperature),
        "temperature_multiplier": 1.0,
        "reasoning_guard": REASONING_MARKUP_GUARD if (local_runtime or tuning.get("reasoning")) else "",
    }


CHAT_DATA_ROOT = Path("output") / CHAT_DATA_DIR_NAME
chat_settings_store = ChatSettingsStore(CHAT_DATA_ROOT)
chat_settings_view: Optional[ChatSettingsView] = None


def _chat_settings_inputs(config: Any = None) -> Tuple[Dict[str, Any], Dict[str, str]]:
    config = config if config is not None else config_manager.get()
    try:
        tuning = resolve_active_llm_tuning(config)
    except Exception:
        tuning = {}
    identity = model_identity(getattr(config, "llm", None), str(tuning.get("provider") or ""))
    return tuning, identity


def _chat_settings_model_info(tuning: Dict[str, Any], identity: Dict[str, str]) -> Dict[str, Any]:
    """What the Chat Settings dialog shows about the model the Auto values come from."""
    return {
        "label": identity["label"],
        "provider": str(tuning.get("provider") or ""),
        "auto_tune": bool(tuning.get("auto_tune", True)),
        "supports_temperature": tuning.get("supports_temperature", True) is not False,
        "reasoning": bool(tuning.get("reasoning")),
        "context_window": int(tuning.get("context_window") or 0),
        "request_timeout": int(tuning.get("request_timeout") or 0),
        "max_output_tokens": int(getattr(tuning.get("profile"), "max_output_tokens", 0) or 0),
    }


def refresh_chat_session_settings(config: Any = None) -> ChatSettingsView:
    """Recompute Auto values from the model's tuning and apply the saved custom values."""
    global chat_settings_view
    tuning, identity = _chat_settings_inputs(config)
    view = resolve_chat_settings(
        chat_settings_store,
        tuning,
        identity,
        should_enable_rag_context_by_default(),
        model_info=_chat_settings_model_info(tuning, identity),
    )
    chat_session_settings.clear()
    chat_session_settings.update(view.effective)
    chat_settings_view = view
    return view


def sync_chat_settings_for_request(config: Any = None) -> None:
    """Pick up model, tuning, and Knowledge Base changes before a chat answer."""
    try:
        refresh_chat_session_settings(config)
    except Exception as exc:
        print(f"⚠️ [CHAT] Could not refresh chat settings: {exc}")


def chat_custom_settings() -> Dict[str, Any]:
    """Custom chat values for the current model; values left on Auto are absent."""
    return dict(chat_settings_view.custom) if chat_settings_view is not None else {}

def _llm_client_cache_key(llm_config: Any) -> int:
    fields = (
        "provider", "endpoint_url", "model", "api_key", "auto_tune", "context_window",
        "request_timeout", "reasoning_effort", "max_tokens", "temperature",
    )
    return hash(tuple(str(getattr(llm_config, name, "")) for name in fields))


def get_or_create_llm_client(config):
    """Get cached LLM client or create new one if config changed."""
    global _cached_llm_client, _cached_config_hash

    config_hash = _llm_client_cache_key(config.llm)
    if _cached_llm_client is not None and _cached_config_hash == config_hash:
        return _cached_llm_client

    provider_name = normalize_provider_name(config.llm.provider)
    endpoint_url = config.llm.endpoint_url

    if provider_name in {"azure", "custom"} and not endpoint_url:
        raise ValueError(f"Provider '{config.llm.provider}' requires endpoint_url")

    tuning = resolve_active_llm_tuning(config, allow_fetch=True)
    _cached_llm_client = LLMClientFactory.create_client(
        provider=provider_name,
        custom_endpoint=endpoint_url,
        api_key=config.llm.api_key,
        model=config.llm.model,
        tuning=client_tuning(tuning),
    )
    print(
        f"[LLM Cache] Created {provider_name} client ({config.llm.model}): "
        f"max_tokens={tuning.get('max_tokens')} context={tuning.get('context_window')} "
        f"timeout={tuning.get('request_timeout')}s auto_tune={tuning.get('auto_tune')}"
    )

    _cached_config_hash = config_hash
    return _cached_llm_client


app = FastAPI(
    title="Splunk Discovery Tool",
    description="Finds what a Splunk environment contains and suggests next steps. Includes encrypted settings, AI summaries, and SPL generation.",
    version=APP_VERSION
)

FRONTEND_STATIC_DIR = Path(__file__).with_name("static")
FRONTEND_INDEX_PATH = FRONTEND_STATIC_DIR / "index.html"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Compared against the files on disk to spot a server that kept running through an update.
SERVER_STARTUP_STATE = capture_startup_state(PROJECT_ROOT)

app.mount("/static", StaticFiles(directory=str(FRONTEND_STATIC_DIR), check_dir=False), name="static")

# Security: Allow external access for development/testing
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Allow any host - use specific IPs/domains in production
)

# Enable CORS with configurable access policy
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8003",
        "http://127.0.0.1:8003",
        "*"  # Allow external access - remove this line for production security
    ],  # Note: "*" allows any origin for development/testing
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Only allow needed methods
    allow_headers=["Content-Type", "Authorization"],  # Only allow needed headers
)

# Global state management
active_connections: List[WebSocket] = []
scoped_active_connections: Dict[str, List[WebSocket]] = {}
current_discovery_session = None
summarization_progress: Dict[str, Dict[str, Any]] = {}  # Track progress by session_id
discovery_runtime_states: Dict[str, Dict[str, Any]] = {}
DISCOVERY_SCOPE_GLOBAL = "__global__"
DISCOVERY_SCOPE_NO_MCP = "__no_mcp__"
DISCOVERY_ACTIVE_STATUSES = {"starting", "running"}
DISCOVERY_ACTIVITY_LOG_LIMIT = 160
SUMMARIZATION_TERMINAL_STAGES = {"idle", "complete", "error", "interrupted", "aborted"}
RUNTIME_STATE_FILENAME = "runtime_state.json"
RUNTIME_STATE_SCHEMA_VERSION = 2
RUNTIME_JOB_DIRNAME = "runtime_jobs"
RUNTIME_JOB_WORKER_ENV = "DT4SMS_RUNTIME_WORKER"
RUNTIME_STATE_BRIDGE_POLL_INTERVAL_SECONDS = 0.5
runtime_state_bridge_task: Optional[asyncio.Task] = None
runtime_state_bridge_last_file_marker: Optional[Tuple[int, int]] = None
runtime_state_bridge_last_discovery_signature: Optional[str] = None


def _utcnow_iso() -> str:
    return datetime.now().isoformat()


def _is_runtime_worker_process() -> bool:
    return str(os.getenv(RUNTIME_JOB_WORKER_ENV, "")).strip() == "1"


def _coerce_process_id(value: Any) -> Optional[int]:
    try:
        pid = int(value or 0)
    except (TypeError, ValueError):
        return None
    return pid if pid > 0 else None


def _is_process_running_windows(pid: int) -> Optional[bool]:
    if os.name != "nt":
        return None

    kernel32 = getattr(ctypes, "windll", None)
    if kernel32 is None:
        return None

    process_query_limited_information = 0x1000
    still_active = 259

    handle = kernel32.kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        error_code = ctypes.GetLastError()
        if error_code == 5:
            return True
        if error_code == 87:
            return False
        return None

    exit_code = ctypes.c_ulong()
    try:
        if not kernel32.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            error_code = ctypes.GetLastError()
            if error_code == 5:
                return True
            return None
        return int(exit_code.value) == still_active
    finally:
        kernel32.kernel32.CloseHandle(handle)


def _is_process_running(value: Any) -> bool:
    pid = _coerce_process_id(value)
    if pid is None:
        return False

    windows_status = _is_process_running_windows(pid)
    if windows_status is not None:
        return windows_status

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _normalize_discovery_activity_entry(entry: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(entry, dict):
        return None

    message_type = str(entry.get("type") or "").strip().lower()
    if not message_type:
        return None

    timestamp = str(entry.get("timestamp") or _utcnow_iso()).strip() or _utcnow_iso()
    payload = copy.deepcopy(entry.get("data"))
    identifier = str(entry.get("id") or f"{timestamp}:{message_type}:{secrets.token_hex(4)}").strip()

    return {
        "id": identifier,
        "type": message_type,
        "data": payload,
        "timestamp": timestamp,
    }


def _normalize_discovery_activity_log(entries: Any) -> List[Dict[str, Any]]:
    if not isinstance(entries, list):
        return []

    normalized_entries: List[Dict[str, Any]] = []
    for entry in entries:
        normalized_entry = _normalize_discovery_activity_entry(entry)
        if normalized_entry is not None:
            normalized_entries.append(normalized_entry)

    return normalized_entries[-DISCOVERY_ACTIVITY_LOG_LIMIT:]


def _default_summarization_progress_payload() -> Dict[str, Any]:
    return {
        "stage": "idle",
        "progress": 0,
        "message": "Not started",
    }


def _normalize_discovery_progress_payload(payload: Any = None) -> Dict[str, Any]:
    progress_payload = payload if isinstance(payload, dict) else {}

    try:
        percentage = float(progress_payload.get("percentage", 0) or 0)
    except (TypeError, ValueError):
        percentage = 0.0
    percentage = max(0.0, min(100.0, percentage))

    try:
        current_step = int(progress_payload.get("current_step", 0) or 0)
    except (TypeError, ValueError):
        current_step = 0

    try:
        total_steps = int(progress_payload.get("total_steps", 0) or 0)
    except (TypeError, ValueError):
        total_steps = 0

    eta_seconds_raw = progress_payload.get("eta_seconds")
    try:
        eta_seconds = float(eta_seconds_raw) if eta_seconds_raw not in (None, "") else None
    except (TypeError, ValueError):
        eta_seconds = None

    eta_method = str(progress_payload.get("eta_method") or "").strip() or None

    return {
        "percentage": percentage,
        "current_step": max(0, current_step),
        "total_steps": max(0, total_steps),
        "description": str(progress_payload.get("description") or "").strip(),
        "eta_seconds": eta_seconds,
        "eta_method": eta_method,
    }


def _build_discovery_runtime_state() -> Dict[str, Any]:
    return {
        "scope_key": DISCOVERY_SCOPE_GLOBAL,
        "scope_label": "Global",
        "active_mcp_config_name": None,
        "status": "idle",
        "session_id": None,
        "worker_pid": None,
        "execution_mode": None,
        "pipeline_version": None,
        "started_at": None,
        "updated_at": None,
        "completed_at": None,
        "result_timestamp": None,
        "report_count": 0,
        "error": None,
        "current_phase_key": None,
        "current_phase_title": None,
        "phase_plan": [],
        "activity_log": [],
        "last_run_outcome": None,
        "progress": _normalize_discovery_progress_payload(),
    }


def _normalize_discovery_scope_key(value: Any) -> str:
    cleaned = str(value or "").strip()
    if not cleaned:
        return DISCOVERY_SCOPE_GLOBAL
    return cleaned[:128]


def _build_discovery_scope_metadata(
    request: Optional[Request] = None,
    auth_user: Optional[Dict[str, Any]] = None,
    runtime_binding: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resolved_user = auth_user
    if resolved_user is None and request is not None:
        resolved_user = getattr(getattr(request, "state", None), "auth_user", None)

    binding = runtime_binding if isinstance(runtime_binding, dict) else _build_discovery_runtime_binding(
        request=request,
        auth_user=resolved_user,
    )
    active_mcp_config_name = str(binding.get("active_mcp_config_name") or "").strip() or None
    clear_runtime_mcp = bool(binding.get("clear_runtime_mcp"))

    if not is_auth_enabled() or not isinstance(resolved_user, dict):
        return {
            "scope_key": DISCOVERY_SCOPE_GLOBAL,
            "scope_label": "Global",
            "active_mcp_config_name": active_mcp_config_name,
            "clear_runtime_mcp": clear_runtime_mcp,
        }

    if active_mcp_config_name:
        return {
            "scope_key": f"mcp:{active_mcp_config_name}",
            "scope_label": active_mcp_config_name,
            "active_mcp_config_name": active_mcp_config_name,
            "clear_runtime_mcp": clear_runtime_mcp,
        }

    if clear_runtime_mcp:
        return {
            "scope_key": DISCOVERY_SCOPE_NO_MCP,
            "scope_label": "No MCP",
            "active_mcp_config_name": None,
            "clear_runtime_mcp": True,
        }

    return {
        "scope_key": DISCOVERY_SCOPE_GLOBAL,
        "scope_label": "Global",
        "active_mcp_config_name": None,
        "clear_runtime_mcp": False,
    }


def _get_discovery_scope_connections(scope_key: Optional[str] = None) -> List[WebSocket]:
    normalized_scope_key = _normalize_discovery_scope_key(scope_key)
    if normalized_scope_key == DISCOVERY_SCOPE_GLOBAL:
        scoped_active_connections[DISCOVERY_SCOPE_GLOBAL] = active_connections
        return active_connections
    if normalized_scope_key not in scoped_active_connections:
        scoped_active_connections[normalized_scope_key] = []
    return scoped_active_connections[normalized_scope_key]


def _has_any_discovery_connections() -> bool:
    if active_connections:
        return True
    return any(
        connections
        for scope_key, connections in scoped_active_connections.items()
        if scope_key != DISCOVERY_SCOPE_GLOBAL
    )


def _iter_active_discovery_scopes() -> List[str]:
    scopes = set()
    if active_connections:
        scopes.add(DISCOVERY_SCOPE_GLOBAL)
    for scope_key, connections in scoped_active_connections.items():
        if connections:
            scopes.add(_normalize_discovery_scope_key(scope_key))
    return sorted(scopes)


def _remove_discovery_scope_connection(websocket: WebSocket, scope_key: Optional[str] = None) -> None:
    connections = _get_discovery_scope_connections(scope_key)
    if websocket in connections:
        connections.remove(websocket)


def _get_discovery_runtime_state_for_scope(scope_key: Optional[str] = None) -> Dict[str, Any]:
    global discovery_runtime_state

    normalized_scope_key = _normalize_discovery_scope_key(scope_key)
    if normalized_scope_key == DISCOVERY_SCOPE_GLOBAL:
        if not isinstance(discovery_runtime_state, dict):
            discovery_runtime_state = _build_discovery_runtime_state()
        discovery_runtime_state.setdefault("scope_key", DISCOVERY_SCOPE_GLOBAL)
        discovery_runtime_state.setdefault("scope_label", "Global")
        discovery_runtime_states[DISCOVERY_SCOPE_GLOBAL] = discovery_runtime_state
        return discovery_runtime_state

    snapshot = discovery_runtime_states.get(normalized_scope_key)
    if not isinstance(snapshot, dict):
        snapshot = _build_discovery_runtime_state()
        snapshot["scope_key"] = normalized_scope_key
        snapshot["scope_label"] = normalized_scope_key
        discovery_runtime_states[normalized_scope_key] = snapshot
    return snapshot


discovery_runtime_state: Dict[str, Any] = _build_discovery_runtime_state()


def _snapshot_discovery_runtime_state(scope_key: Optional[str] = None) -> Dict[str, Any]:
    snapshot = copy.deepcopy(_get_discovery_runtime_state_for_scope(scope_key))
    snapshot["is_active"] = snapshot.get("status") in DISCOVERY_ACTIVE_STATUSES
    return snapshot


def _update_discovery_runtime_state(
    *,
    scope_key: Optional[str] = None,
    reset: bool = False,
    status: Optional[str] = None,
    progress: Any = None,
    **fields: Any,
) -> Dict[str, Any]:
    global discovery_runtime_state

    normalized_scope_key = _normalize_discovery_scope_key(scope_key)
    current_snapshot = _get_discovery_runtime_state_for_scope(normalized_scope_key)
    snapshot = _build_discovery_runtime_state() if reset else copy.deepcopy(current_snapshot)
    snapshot["scope_key"] = normalized_scope_key
    if normalized_scope_key == DISCOVERY_SCOPE_GLOBAL:
        snapshot.setdefault("scope_label", "Global")

    if status is not None:
        normalized_status = str(status or "idle").strip().lower() or "idle"
        snapshot["status"] = normalized_status

    if progress is not None:
        snapshot["progress"] = _normalize_discovery_progress_payload(progress)

    append_activity = fields.pop("append_activity", None)

    if "worker_pid" in fields:
        fields["worker_pid"] = _coerce_process_id(fields.get("worker_pid"))
    if "execution_mode" in fields:
        fields["execution_mode"] = str(fields.get("execution_mode") or "").strip().lower() or None
    if "activity_log" in fields:
        fields["activity_log"] = _normalize_discovery_activity_log(fields.get("activity_log"))

    for field_name, field_value in fields.items():
        snapshot[field_name] = field_value

    if append_activity is not None:
        appended_entries = append_activity if isinstance(append_activity, list) else [append_activity]
        snapshot["activity_log"] = _normalize_discovery_activity_log(
            list(snapshot.get("activity_log") or []) + appended_entries
        )

    phase_plan = snapshot.get("phase_plan")
    if isinstance(phase_plan, list) and phase_plan:
        active_phase = next((item for item in phase_plan if item.get("status") == "active"), None)
        if active_phase is not None:
            snapshot["current_phase_key"] = active_phase.get("key")
            snapshot["current_phase_title"] = active_phase.get("title") or active_phase.get("label")

            description = str((snapshot.get("progress") or {}).get("description") or "").strip()
            if description:
                active_phase["last_detail"] = description

            try:
                percentage = float((snapshot.get("progress") or {}).get("percentage") or 0.0)
            except (TypeError, ValueError):
                percentage = 0.0
            active_phase["progress_percent"] = max(
                float(active_phase.get("progress_percent") or 0.0),
                percentage,
            )

    if snapshot.get("progress"):
        calibrated_eta_seconds = _calculate_stage_calibrated_eta_seconds(snapshot)
        if calibrated_eta_seconds is not None:
            snapshot["progress"]["eta_seconds"] = calibrated_eta_seconds
            snapshot["progress"]["eta_method"] = "stage_calibrated"

    snapshot["updated_at"] = _utcnow_iso()
    if normalized_scope_key == DISCOVERY_SCOPE_GLOBAL:
        discovery_runtime_state = snapshot
        discovery_runtime_states[DISCOVERY_SCOPE_GLOBAL] = discovery_runtime_state
    else:
        discovery_runtime_states[normalized_scope_key] = snapshot
    _persist_runtime_state()
    return _snapshot_discovery_runtime_state(normalized_scope_key)


def _append_discovery_runtime_activity(
    message_type: str,
    data: Any,
    *,
    scope_key: Optional[str] = None,
) -> Dict[str, Any]:
    return _update_discovery_runtime_state(
        scope_key=scope_key,
        append_activity={
            "type": message_type,
            "data": data,
            "timestamp": _utcnow_iso(),
        }
    )


def _build_websocket_message(message_type: str, data: Any) -> Dict[str, Any]:
    return {
        "type": message_type,
        "data": data,
        "timestamp": _utcnow_iso(),
    }


async def _broadcast_websocket_message(
    message_type: str,
    data: Any,
    scope_key: Optional[str] = None,
):
    message = _build_websocket_message(message_type, data)

    disconnected = []
    for connection in _get_discovery_scope_connections(scope_key):
        try:
            await connection.send_text(json.dumps(message))
        except Exception:
            disconnected.append(connection)

    for conn in disconnected:
        _remove_discovery_scope_connection(conn, scope_key)


async def _broadcast_discovery_runtime_state(
    snapshot: Optional[Dict[str, Any]] = None,
    *,
    scope_key: Optional[str] = None,
):
    normalized_scope_key = _normalize_discovery_scope_key(scope_key or (snapshot or {}).get("scope_key"))
    discovery_snapshot = snapshot or _snapshot_discovery_runtime_state(normalized_scope_key)
    _remember_runtime_state_bridge_snapshot(discovery_snapshot)
    await _broadcast_websocket_message("discovery_status", discovery_snapshot, normalized_scope_key)


@app.on_event("startup")
async def start_runtime_state_bridge() -> None:
    global runtime_state_bridge_task

    if _is_runtime_worker_process():
        return

    _sync_runtime_state_from_disk()
    _remember_runtime_state_bridge_snapshot()
    if runtime_state_bridge_task is None or runtime_state_bridge_task.done():
        runtime_state_bridge_task = asyncio.create_task(_runtime_state_bridge_loop())


@app.on_event("shutdown")
async def stop_runtime_state_bridge() -> None:
    global runtime_state_bridge_task

    task = runtime_state_bridge_task
    runtime_state_bridge_task = None
    if task is None:
        return

    task.cancel()
    with suppress(asyncio.CancelledError):
        await task

# Debug mode support
debug_connections: List[WebSocket] = []  # WebSocket connections for debug log streaming
debug_log_queue = asyncio.Queue()  # Queue for debug messages

# Effective chat settings: Auto values from the model's tuning plus saved custom values.
# refresh_chat_session_settings() fills this in; these defaults only cover the time before that.
chat_session_settings: Dict[str, Any] = model_defaults(None, False)

MCP_TOOL_ALIASES = {
    "splunk_run_query": ["splunk_run_query", "run_splunk_query"],
    "splunk_get_info": ["splunk_get_info", "get_splunk_info"],
    "splunk_get_indexes": ["splunk_get_indexes", "get_indexes"],
    "splunk_get_index_info": ["splunk_get_index_info", "get_index_info"],
    "splunk_get_metadata": ["splunk_get_metadata", "get_metadata"],
    "splunk_get_user_info": ["splunk_get_user_info", "splunk_get_user_list", "get_user_list"],
    "splunk_get_kv_store_collections": ["splunk_get_kv_store_collections", "get_kv_store_collections"],
    "splunk_get_knowledge_objects": ["splunk_get_knowledge_objects", "get_knowledge_objects"],
    "saia_generate_spl": ["saia_generate_spl"],
    "saia_optimize_spl": ["saia_optimize_spl"],
    "saia_explain_spl": ["saia_explain_spl"],
    "saia_ask_splunk_question": ["saia_ask_splunk_question"]
}

MCP_TOOL_DESCRIPTIONS = {
    "splunk_run_query": "Run a query and return results.",
    "splunk_get_info": "Get Splunk instance version and server information.",
    "splunk_get_indexes": "List Splunk indexes you can access.",
    "splunk_get_index_info": "Get detailed information about a specific index.",
    "splunk_get_metadata": "Get hosts, sources, or sourcetypes for query building.",
    "splunk_get_user_info": "Get information about the authenticated user.",
    "splunk_get_kv_store_collections": "List KV store collections.",
    "splunk_get_knowledge_objects": "List knowledge objects (saved searches, data models, macros, etc.).",
    "saia_generate_spl": "Generate SPL from natural language.",
    "saia_optimize_spl": "Optimize existing SPL.",
    "saia_explain_spl": "Explain SPL in natural language.",
    "saia_ask_splunk_question": "Ask Splunk AI Assistant a natural language question."
}

_cached_mcp_tools = {
    "identity": None,
    "tools": set(),
    "descriptions": {},
    "schemas": {},
    "timestamp": 0.0
}

MCP_QUERY_TIMEOUT_SECONDS = 120.0
MCP_METADATA_TIMEOUT_SECONDS = 45.0
_mcp_request_counter = {"value": 0}


def _next_mcp_request_id() -> int:
    _mcp_request_counter["value"] += 1
    return _mcp_request_counter["value"]


def _mcp_call_timeout(tool_name: str) -> float:
    override = os.environ.get("DT4SMS_MCP_TIMEOUT_SECONDS", "").strip()
    if override:
        try:
            return max(5.0, float(override))
        except ValueError:
            pass
    if tool_name in {"splunk_run_query", "run_splunk_query"}:
        return MCP_QUERY_TIMEOUT_SECONDS
    return MCP_METADATA_TIMEOUT_SECONDS


def get_cached_mcp_tool_metadata(config: Any = None) -> Dict[str, Dict[str, Any]]:
    """Return descriptions and input schemas from the last tools/list call."""
    identity = _build_mcp_runtime_identity(config) if config is not None else _cached_mcp_tools.get("identity")
    if identity is None or _cached_mcp_tools.get("identity") != identity:
        return {"descriptions": {}, "schemas": {}}
    return {
        "descriptions": dict(_cached_mcp_tools.get("descriptions") or {}),
        "schemas": dict(_cached_mcp_tools.get("schemas") or {}),
    }

DISCOVERY_PIPELINE_VERSION = "v2"
OPENAI_IMAGE_MODEL = "gpt-image-2"
MAX_INFOGRAPHIC_SUMMARY_CHARS = 32000
MAX_INFOGRAPHIC_BRIEF_CHARS = 12000
SUMMARY_INFOGRAPHIC_DIRNAME = "summary_infographics"
SUMMARY_INFOGRAPHIC_PREFIX = "summary_infographic_"
IMAGE_ARTIFACT_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}

DISCOVERY_PHASE_MODELS = {
    "v2": [
        {
            "key": "pipeline_boot",
            "label": "Prepare",
            "description": "Check the settings and start discovery.",
            "progress_start": 0.0,
            "progress_end": 8.0,
            "baseline_seconds": 45.0,
            "match_tokens": ["preparing discovery", "v2 discovery pipeline"],
        },
        {
            "key": "signal_capture",
            "label": "Survey the environment",
            "description": "Find what the environment contains and set the scope.",
            "progress_start": 2.0,
            "progress_end": 12.0,
            "baseline_seconds": 75.0,
            "match_tokens": ["surveying the environment", "environment signal capture"],
        },
        {
            "key": "evidence_collection",
            "label": "Collect details",
            "description": "Gather details about indexes, sourcetypes, hosts, and settings.",
            "progress_start": 10.0,
            "progress_end": 78.0,
            "baseline_seconds": 300.0,
            "match_tokens": ["collecting details", "evidence collection"],
        },
        {
            "key": "classification_map",
            "label": "Classify data",
            "description": "Group the collected data by what it is used for.",
            "progress_start": 78.0,
            "progress_end": 84.0,
            "baseline_seconds": 70.0,
            "match_tokens": ["classifying data", "classification map"],
        },
        {
            "key": "recommendation_queue",
            "label": "Recommend actions",
            "description": "Turn the findings into prioritized recommendations.",
            "progress_start": 84.0,
            "progress_end": 90.0,
            "baseline_seconds": 70.0,
            "match_tokens": ["recommending actions", "recommendation queue"],
        },
        {
            "key": "use_case_generation",
            "label": "Suggest use cases",
            "description": "Suggest detection and monitoring use cases.",
            "progress_start": 90.0,
            "progress_end": 94.0,
            "baseline_seconds": 80.0,
            "match_tokens": ["suggesting use cases", "use case generation"],
        },
        {
            "key": "blueprint_assembly",
            "label": "Assemble results",
            "description": "Combine the findings into the results file and runbooks.",
            "progress_start": 94.0,
            "progress_end": 97.0,
            "baseline_seconds": 45.0,
            "match_tokens": ["assembling results", "blueprint assembly"],
        },
        {
            "key": "artifact_packaging",
            "label": "Save reports",
            "description": "Write the reports and add this run to the report library.",
            "progress_start": 97.0,
            "progress_end": 100.0,
            "baseline_seconds": 50.0,
            "match_tokens": ["saving reports", "artifact packaging"],
        },
    ],
    "legacy": [
        {
            "key": "quick_overview",
            "label": "Quick overview",
            "description": "Collect a baseline overview and size the environment.",
            "progress_start": 0.0,
            "progress_end": 12.0,
            "baseline_seconds": 75.0,
            "match_tokens": ["quick overview"],
        },
        {
            "key": "environment_discovery",
            "label": "Explore the environment",
            "description": "Walk the environment and collect details.",
            "progress_start": 12.0,
            "progress_end": 58.0,
            "baseline_seconds": 300.0,
            "match_tokens": ["detailed environment discovery"],
        },
        {
            "key": "classification_analysis",
            "label": "Classify data",
            "description": "Classify and score the collected findings.",
            "progress_start": 58.0,
            "progress_end": 72.0,
            "baseline_seconds": 95.0,
            "match_tokens": ["data classification analysis"],
        },
        {
            "key": "recommendation_generation",
            "label": "Recommend actions",
            "description": "Generate prioritized recommendations from the discovery output.",
            "progress_start": 72.0,
            "progress_end": 82.0,
            "baseline_seconds": 90.0,
            "match_tokens": ["recommendation generation"],
        },
        {
            "key": "legacy_use_case_generation",
            "label": "Suggest use cases",
            "description": "Draft suggested use cases from the environment findings.",
            "progress_start": 82.0,
            "progress_end": 90.0,
            "baseline_seconds": 85.0,
            "match_tokens": ["suggested use case generation"],
        },
        {
            "key": "report_export",
            "label": "Save reports",
            "description": "Write the final reports and save the discovery results.",
            "progress_start": 90.0,
            "progress_end": 100.0,
            "baseline_seconds": 75.0,
            "match_tokens": ["report export"],
        },
    ],
}

DISCOVERY_HEAVY_PHASE_KEYS = {"evidence_collection", "environment_discovery"}


def _normalize_discovery_phase_token(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(value or "").strip().lower()).strip()


def _build_discovery_phase_plan(pipeline_version: Optional[str] = None) -> List[Dict[str, Any]]:
    models = DISCOVERY_PHASE_MODELS.get((pipeline_version or DISCOVERY_PIPELINE_VERSION).strip().lower())
    if not models:
        models = DISCOVERY_PHASE_MODELS["v2"]

    return [
        {
            "key": item["key"],
            "label": item["label"],
            "title": item["label"],
            "description": item["description"],
            "progress_start": float(item["progress_start"]),
            "progress_end": float(item["progress_end"]),
            "baseline_seconds": float(item["baseline_seconds"]),
            "progress_percent": float(item["progress_start"]),
            "status": "pending",
            "started_at": None,
            "completed_at": None,
            "last_detail": "",
        }
        for item in models
    ]


def _prime_discovery_phase_plan_for_start(
    pipeline_version: Optional[str] = None,
    *,
    started_at: Optional[str] = None,
) -> List[Dict[str, Any]]:
    phase_plan = _build_discovery_phase_plan(pipeline_version)
    if not phase_plan:
        return phase_plan

    bootstrap_phase = phase_plan[0]
    bootstrap_started_at = started_at or _utcnow_iso()
    bootstrap_phase["status"] = "active"
    bootstrap_phase["started_at"] = bootstrap_phase.get("started_at") or bootstrap_started_at
    bootstrap_phase["completed_at"] = None
    bootstrap_phase["progress_percent"] = max(
        float(bootstrap_phase.get("progress_percent") or 0.0),
        float(bootstrap_phase.get("progress_start") or 0.0),
    )
    return phase_plan


def _resolve_discovery_phase_definition(title: str, pipeline_version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    normalized_title = _normalize_discovery_phase_token(title)
    if not normalized_title:
        return None

    models = DISCOVERY_PHASE_MODELS.get((pipeline_version or DISCOVERY_PIPELINE_VERSION).strip().lower())
    if not models:
        models = DISCOVERY_PHASE_MODELS["v2"]

    for item in models:
        if any(token in normalized_title for token in item.get("match_tokens", [])):
            return item
    return None


def _parse_runtime_datetime(value: Any) -> Optional[datetime]:
    if not value:
        return None

    if isinstance(value, datetime):
        return value

    text = str(value).strip()
    if not text:
        return None

    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _calculate_stage_calibrated_eta_seconds(snapshot: Dict[str, Any]) -> Optional[float]:
    progress = snapshot.get("progress") or {}
    try:
        percentage = float(progress.get("percentage") or 0.0)
    except (TypeError, ValueError):
        percentage = 0.0

    phase_plan = snapshot.get("phase_plan") or []
    started_at = _parse_runtime_datetime(snapshot.get("started_at"))
    if not phase_plan or started_at is None:
        return None

    active_index = next((index for index, item in enumerate(phase_plan) if item.get("status") == "active"), None)
    if active_index is None:
        return None

    active_phase = phase_plan[active_index]
    phase_started_at = _parse_runtime_datetime(active_phase.get("started_at")) or started_at
    elapsed_current_phase = max(0.0, (datetime.now(phase_started_at.tzinfo) - phase_started_at).total_seconds())

    phase_start = float(active_phase.get("progress_start") or 0.0)
    phase_end = float(active_phase.get("progress_end") or 100.0)
    phase_span = max(1.0, phase_end - phase_start)
    phase_progress = max(0.0, min(1.0, (percentage - phase_start) / phase_span))

    if phase_progress <= 0.02:
        current_phase_remaining = float(active_phase.get("baseline_seconds") or 0.0)
    else:
        measured_total = elapsed_current_phase / min(max(phase_progress, 0.05), 0.98)
        baseline_total = float(active_phase.get("baseline_seconds") or 0.0)
        multiplier = 1.25 if active_phase.get("key") in DISCOVERY_HEAVY_PHASE_KEYS else 1.12
        calibrated_total = max(baseline_total, measured_total * multiplier)
        current_phase_remaining = max(0.0, calibrated_total - elapsed_current_phase)

    remaining_after_current = sum(
        float(item.get("baseline_seconds") or 0.0)
        for item in phase_plan[active_index + 1:]
        if item.get("status") == "pending"
    )

    eta_seconds = current_phase_remaining + remaining_after_current
    if percentage >= 99.0:
        eta_seconds = min(eta_seconds, 45.0)

    return round(max(0.0, eta_seconds), 1)


def _build_discovery_last_run_outcome(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    status = str(snapshot.get("status") or "idle").strip().lower() or "idle"
    completed_at = snapshot.get("completed_at")
    result_timestamp = snapshot.get("result_timestamp")
    report_count = int(snapshot.get("report_count") or 0)
    phase_title = snapshot.get("current_phase_title") or "Discovery pipeline"
    error_message = str(snapshot.get("error") or "").strip()

    if status == "completed":
        title = "Discovery run completed"
        summary = f"Finished at {completed_at or 'the latest checkpoint'} and produced {report_count} report{'s' if report_count != 1 else ''}."
    elif status == "interrupted":
        title = "Discovery run interrupted"
        summary = f"The app restarted during {phase_title.lower()}. Review the latest checkpoint and rerun when ready."
    elif status == "aborted":
        title = "Discovery run stopped"
        summary = f"Stopped during {phase_title.lower()}. Review the activity log before starting a new run."
    elif status == "error":
        title = "Discovery run failed"
        summary = error_message or f"Failed during {phase_title.lower()}. Check the latest log output to see what stopped it."
    else:
        title = "Discovery monitor"
        summary = "No completed discovery outcome is available yet."

    return {
        "status": status,
        "title": title,
        "summary": summary,
        "completed_at": completed_at,
        "result_timestamp": result_timestamp,
        "report_count": report_count,
        "phase_title": phase_title,
        "error": error_message or None,
    }


def _advance_discovery_runtime_phase(title: str, *, scope_key: Optional[str] = None) -> Dict[str, Any]:
    snapshot = _snapshot_discovery_runtime_state(scope_key)
    pipeline_version = snapshot.get("pipeline_version") or DISCOVERY_PIPELINE_VERSION
    phase_plan = snapshot.get("phase_plan") or _build_discovery_phase_plan(pipeline_version)
    definition = _resolve_discovery_phase_definition(title, pipeline_version)
    if definition is None:
        return _update_discovery_runtime_state(
            scope_key=scope_key,
            status="running",
            current_phase_title=title,
            phase_plan=phase_plan,
        )

    now_iso = _utcnow_iso()
    for phase_entry in phase_plan:
        if phase_entry.get("status") == "active" and phase_entry.get("key") != definition["key"]:
            phase_entry["status"] = "completed"
            phase_entry["completed_at"] = phase_entry.get("completed_at") or now_iso
            phase_entry["progress_percent"] = max(
                float(phase_entry.get("progress_percent") or 0.0),
                float(phase_entry.get("progress_end") or 0.0),
            )

    target_phase = next((item for item in phase_plan if item.get("key") == definition["key"]), None)
    if target_phase is None:
        target_phase = {
            "key": definition["key"],
            "label": definition["label"],
            "title": title,
            "description": definition["description"],
            "progress_start": float(definition["progress_start"]),
            "progress_end": float(definition["progress_end"]),
            "baseline_seconds": float(definition["baseline_seconds"]),
            "progress_percent": float(definition["progress_start"]),
            "status": "pending",
            "started_at": None,
            "completed_at": None,
            "last_detail": "",
        }
        phase_plan.append(target_phase)

    target_phase["title"] = title
    target_phase["status"] = "active"
    target_phase["started_at"] = target_phase.get("started_at") or now_iso
    target_phase["completed_at"] = None
    target_phase["progress_percent"] = max(
        float(target_phase.get("progress_percent") or 0.0),
        float(target_phase.get("progress_start") or 0.0),
    )

    return _update_discovery_runtime_state(
        scope_key=scope_key,
        status="running",
        phase_plan=phase_plan,
        current_phase_key=target_phase.get("key"),
        current_phase_title=title,
    )


def _finalize_discovery_runtime(
    status: str,
    *,
    scope_key: Optional[str] = None,
    error: Optional[str] = None,
    report_count: Optional[int] = None,
    result_timestamp: Optional[str] = None,
    completed_at: Optional[str] = None,
    **fields: Any,
) -> Dict[str, Any]:
    snapshot = _snapshot_discovery_runtime_state(scope_key)
    phase_plan = snapshot.get("phase_plan") or _build_discovery_phase_plan(snapshot.get("pipeline_version") or DISCOVERY_PIPELINE_VERSION)
    now_iso = completed_at or _utcnow_iso()
    normalized_status = str(status or "idle").strip().lower() or "idle"

    for phase_entry in phase_plan:
        if phase_entry.get("status") == "active":
            phase_entry["status"] = "completed" if normalized_status == "completed" else normalized_status
            phase_entry["completed_at"] = phase_entry.get("completed_at") or now_iso
            if normalized_status == "completed":
                phase_entry["progress_percent"] = max(
                    float(phase_entry.get("progress_percent") or 0.0),
                    float(phase_entry.get("progress_end") or 0.0),
                )
            elif error:
                phase_entry["last_detail"] = error

    completed_snapshot = _update_discovery_runtime_state(
        scope_key=scope_key,
        status=normalized_status,
        phase_plan=phase_plan,
        completed_at=now_iso,
        error=error,
        report_count=report_count if report_count is not None else snapshot.get("report_count") or 0,
        result_timestamp=result_timestamp if result_timestamp is not None else snapshot.get("result_timestamp"),
        **fields,
    )
    outcome = _build_discovery_last_run_outcome(completed_snapshot)
    return _update_discovery_runtime_state(scope_key=scope_key, last_run_outcome=outcome)


def _runtime_state_store_path() -> Path:
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    return output_dir / RUNTIME_STATE_FILENAME


def _normalize_summarization_progress_entry(
    session_id: str,
    payload: Any = None,
    *,
    scope_key: Optional[str] = None,
    existing: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    source_payload = payload if isinstance(payload, dict) else {}
    current = existing if isinstance(existing, dict) else {}

    stage = str(source_payload.get("stage") or current.get("stage") or "idle").strip().lower() or "idle"
    try:
        progress = int(source_payload.get("progress", current.get("progress", 0)) or 0)
    except (TypeError, ValueError):
        progress = 0

    message = str(
        source_payload.get("message")
        or current.get("message")
        or _default_summarization_progress_payload()["message"]
    ).strip() or _default_summarization_progress_payload()["message"]
    worker_pid = _coerce_process_id(source_payload.get("worker_pid", current.get("worker_pid")))
    execution_mode = str(
        source_payload.get("execution_mode")
        or current.get("execution_mode")
        or ("worker" if worker_pid else "inline")
    ).strip().lower() or ("worker" if worker_pid else "inline")

    now_iso = _utcnow_iso()
    normalized = {
        **current,
        **source_payload,
        "session_id": session_id,
        "scope_key": _normalize_discovery_scope_key(scope_key or current.get("scope_key")),
        "stage": stage,
        "progress": max(0, min(100, progress)),
        "message": message,
        "worker_pid": worker_pid,
        "execution_mode": execution_mode,
        "updated_at": now_iso,
        "started_at": str(current.get("started_at") or source_payload.get("started_at") or now_iso),
    }

    if stage in SUMMARIZATION_TERMINAL_STAGES:
        normalized["completed_at"] = str(current.get("completed_at") or source_payload.get("completed_at") or now_iso)
    else:
        normalized["completed_at"] = None

    return normalized


def _summary_progress_storage_key(session_id: str, scope_key: Optional[str] = None) -> str:
    normalized_scope_key = _normalize_discovery_scope_key(scope_key)
    if normalized_scope_key == DISCOVERY_SCOPE_GLOBAL:
        return session_id
    return f"{normalized_scope_key}::{session_id}"


def _parse_summary_progress_storage_key(value: Any) -> Tuple[str, str]:
    text = str(value or "").strip()
    if "::" not in text:
        return DISCOVERY_SCOPE_GLOBAL, text
    scope_key, session_id = text.split("::", 1)
    return _normalize_discovery_scope_key(scope_key), session_id


def _get_summarization_progress(session_id: str, scope_key: Optional[str] = None) -> Dict[str, Any]:
    return copy.deepcopy(
        summarization_progress.get(
            _summary_progress_storage_key(session_id, scope_key),
            _default_summarization_progress_payload(),
        )
    )


def _set_summarization_progress(session_id: str, *, scope_key: Optional[str] = None, **fields: Any) -> Dict[str, Any]:
    storage_key = _summary_progress_storage_key(session_id, scope_key)
    entry = _normalize_summarization_progress_entry(
        session_id,
        fields,
        scope_key=scope_key,
        existing=summarization_progress.get(storage_key),
    )
    summarization_progress[storage_key] = entry
    _persist_runtime_state()
    return copy.deepcopy(entry)


def _clear_summarization_progress(session_id: str, *, scope_key: Optional[str] = None) -> None:
    storage_key = _summary_progress_storage_key(session_id, scope_key)
    if storage_key in summarization_progress:
        del summarization_progress[storage_key]
        _persist_runtime_state()


def _resolve_discovery_scope_output_dir(scope_key: Optional[str] = None, *, create: bool = True) -> Path:
    output_dir = Path("output")
    if create:
        output_dir.mkdir(exist_ok=True)

    normalized_scope_key = _normalize_discovery_scope_key(scope_key)
    if normalized_scope_key == DISCOVERY_SCOPE_GLOBAL:
        return output_dir

    scopes_dir = output_dir / "scopes"
    if create:
        scopes_dir.mkdir(parents=True, exist_ok=True)

    encoded_scope = base64.urlsafe_b64encode(normalized_scope_key.encode("utf-8")).decode("ascii").rstrip("=")
    scope_dir = scopes_dir / encoded_scope
    if create:
        scope_dir.mkdir(parents=True, exist_ok=True)
    return scope_dir


def _summary_artifact_path(session_id: str, scope_key: Optional[str] = None) -> Path:
    return _resolve_discovery_scope_output_dir(scope_key, create=False) / f"v2_ai_summary_{session_id}.json"


def _restore_discovery_runtime_state(snapshot: Any) -> Dict[str, Any]:
    restored = _build_discovery_runtime_state()
    if not isinstance(snapshot, dict):
        return restored

    restored.update({
        "status": str(snapshot.get("status") or restored["status"]).strip().lower() or restored["status"],
        "session_id": snapshot.get("session_id"),
        "worker_pid": _coerce_process_id(snapshot.get("worker_pid")),
        "execution_mode": str(snapshot.get("execution_mode") or "").strip().lower() or None,
        "pipeline_version": snapshot.get("pipeline_version"),
        "started_at": snapshot.get("started_at"),
        "updated_at": snapshot.get("updated_at"),
        "completed_at": snapshot.get("completed_at"),
        "result_timestamp": snapshot.get("result_timestamp"),
        "report_count": int(snapshot.get("report_count") or 0),
        "error": snapshot.get("error"),
        "current_phase_key": snapshot.get("current_phase_key"),
        "current_phase_title": snapshot.get("current_phase_title"),
        "last_run_outcome": copy.deepcopy(snapshot.get("last_run_outcome")),
        "progress": _normalize_discovery_progress_payload(snapshot.get("progress")),
    })

    raw_phase_plan = snapshot.get("phase_plan")
    restored["phase_plan"] = copy.deepcopy(raw_phase_plan) if isinstance(raw_phase_plan, list) else []
    restored["activity_log"] = _normalize_discovery_activity_log(snapshot.get("activity_log"))

    if restored["status"] in DISCOVERY_ACTIVE_STATUSES:
        if _is_runtime_worker_process() or _is_process_running(restored.get("worker_pid")):
            return restored

        interruption_message = "The app restarted during an active discovery run. Start a new run to continue."
        restored["status"] = "interrupted"
        restored["error"] = interruption_message
        restored["worker_pid"] = None
        restored["completed_at"] = restored.get("completed_at") or _utcnow_iso()
        for phase_entry in restored["phase_plan"]:
            if not isinstance(phase_entry, dict):
                continue
            if phase_entry.get("status") == "active":
                phase_entry["status"] = "interrupted"
                phase_entry["completed_at"] = phase_entry.get("completed_at") or restored["completed_at"]
                phase_entry["last_detail"] = str(phase_entry.get("last_detail") or interruption_message)
        restored["last_run_outcome"] = _build_discovery_last_run_outcome(restored)

    return restored


def _restore_summarization_progress(snapshot: Any) -> Dict[str, Dict[str, Any]]:
    restored: Dict[str, Dict[str, Any]] = {}
    if not isinstance(snapshot, dict):
        return restored

    for progress_key, payload in snapshot.items():
        scope_key, session_id = _parse_summary_progress_storage_key(progress_key)
        if not isinstance(session_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session_id):
            continue

        storage_key = _summary_progress_storage_key(session_id, scope_key)
        entry = _normalize_summarization_progress_entry(session_id, payload, scope_key=scope_key)
        if _summary_artifact_path(session_id, scope_key).exists():
            entry = _normalize_summarization_progress_entry(
                session_id,
                {
                    "stage": "complete",
                    "progress": 100,
                    "message": "Summary available from saved artifacts after restart.",
                    "worker_pid": None,
                },
                scope_key=scope_key,
                existing=entry,
            )
        elif entry["stage"] not in SUMMARIZATION_TERMINAL_STAGES:
            if _is_runtime_worker_process() or _is_process_running(entry.get("worker_pid")):
                restored[storage_key] = entry
                continue

            entry = _normalize_summarization_progress_entry(
                session_id,
                {
                    "stage": "interrupted",
                    "progress": entry.get("progress", 0),
                    "message": "The app restarted during summary generation. Re-run summarization for this session.",
                    "worker_pid": None,
                },
                scope_key=scope_key,
                existing=entry,
            )

        restored[storage_key] = entry

    return restored


def _load_persisted_runtime_state() -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]]]:
    state_path = _runtime_state_store_path()
    if not state_path.exists():
        return {DISCOVERY_SCOPE_GLOBAL: _build_discovery_runtime_state()}, {}

    try:
        with open(state_path, "r", encoding="utf-8") as runtime_state_file:
            payload = json.load(runtime_state_file)
    except Exception as exc:
        print(f"Error loading runtime state from disk: {exc}")
        return {DISCOVERY_SCOPE_GLOBAL: _build_discovery_runtime_state()}, {}

    raw_discovery_payload = payload.get("discovery_runtime_states")
    if not isinstance(raw_discovery_payload, dict):
        raw_discovery_payload = {
            DISCOVERY_SCOPE_GLOBAL: payload.get("discovery_runtime_state")
        }

    restored_discovery: Dict[str, Dict[str, Any]] = {}
    for scope_key, discovery_payload in raw_discovery_payload.items():
        normalized_scope_key = _normalize_discovery_scope_key(scope_key)
        restored_snapshot = _restore_discovery_runtime_state(discovery_payload)
        restored_snapshot["scope_key"] = normalized_scope_key
        restored_snapshot.setdefault(
            "scope_label",
            "Global" if normalized_scope_key == DISCOVERY_SCOPE_GLOBAL else normalized_scope_key,
        )
        restored_discovery[normalized_scope_key] = restored_snapshot

    if DISCOVERY_SCOPE_GLOBAL not in restored_discovery:
        restored_discovery[DISCOVERY_SCOPE_GLOBAL] = _build_discovery_runtime_state()

    return (
        restored_discovery,
        _restore_summarization_progress(payload.get("summarization_progress")),
    )


def _persist_runtime_state() -> None:
    state_path = _runtime_state_store_path()
    discovery_runtime_states[DISCOVERY_SCOPE_GLOBAL] = copy.deepcopy(_get_discovery_runtime_state_for_scope())
    payload = {
        "schema_version": RUNTIME_STATE_SCHEMA_VERSION,
        "saved_at": _utcnow_iso(),
        "discovery_runtime_state": copy.deepcopy(discovery_runtime_states[DISCOVERY_SCOPE_GLOBAL]),
        "discovery_runtime_states": copy.deepcopy(discovery_runtime_states),
        "summarization_progress": copy.deepcopy(summarization_progress),
    }
    temp_path = state_path.with_suffix(state_path.suffix + ".tmp")

    try:
        with open(temp_path, "w", encoding="utf-8") as runtime_state_file:
            json.dump(payload, runtime_state_file, indent=2)
        os.replace(temp_path, state_path)
    except Exception as exc:
        print(f"Error persisting runtime state to disk: {exc}")
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass


def _capture_runtime_state_file_marker() -> Optional[Tuple[int, int]]:
    state_path = _runtime_state_store_path()
    try:
        stat_result = state_path.stat()
    except OSError:
        return None
    return (int(stat_result.st_mtime_ns), int(stat_result.st_size))


def _build_discovery_runtime_signature(snapshot: Optional[Dict[str, Any]] = None) -> str:
    safe_snapshot = snapshot if isinstance(snapshot, dict) else copy.deepcopy(discovery_runtime_states)
    return json.dumps(safe_snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _remember_runtime_state_bridge_snapshot(snapshot: Optional[Dict[str, Any]] = None) -> None:
    global runtime_state_bridge_last_file_marker, runtime_state_bridge_last_discovery_signature

    runtime_state_bridge_last_file_marker = _capture_runtime_state_file_marker()
    runtime_state_bridge_last_discovery_signature = _build_discovery_runtime_signature(snapshot)


async def _check_for_persisted_runtime_state_rebroadcast(*, force: bool = False) -> bool:
    global runtime_state_bridge_last_file_marker

    if _is_runtime_worker_process():
        return False

    if not _has_any_discovery_connections() and not force:
        return False

    current_marker = _capture_runtime_state_file_marker()
    if not force and current_marker == runtime_state_bridge_last_file_marker:
        return False

    runtime_state_bridge_last_file_marker = current_marker
    _sync_runtime_state_from_disk()
    snapshot_signature = _build_discovery_runtime_signature()
    if not force and snapshot_signature == runtime_state_bridge_last_discovery_signature:
        return False

    for active_scope_key in _iter_active_discovery_scopes():
        await _broadcast_discovery_runtime_state(scope_key=active_scope_key)
    return True


async def _runtime_state_bridge_loop() -> None:
    while True:
        try:
            await _check_for_persisted_runtime_state_rebroadcast()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print(f"Runtime state bridge error: {exc}")

        await asyncio.sleep(RUNTIME_STATE_BRIDGE_POLL_INTERVAL_SECONDS)


def _sync_runtime_state_from_disk() -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    global discovery_runtime_state, discovery_runtime_states, summarization_progress

    persisted_discovery, persisted_summarization = _load_persisted_runtime_state()
    discovery_runtime_states = persisted_discovery
    discovery_runtime_state = discovery_runtime_states.get(DISCOVERY_SCOPE_GLOBAL, _build_discovery_runtime_state())
    discovery_runtime_states[DISCOVERY_SCOPE_GLOBAL] = discovery_runtime_state
    summarization_progress = persisted_summarization
    return copy.deepcopy(discovery_runtime_states), copy.deepcopy(summarization_progress)


def _runtime_job_dir() -> Path:
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    job_dir = output_dir / RUNTIME_JOB_DIRNAME
    job_dir.mkdir(parents=True, exist_ok=True)
    return job_dir


def _runtime_job_worker_path() -> Path:
    return Path(__file__).resolve().with_name("runtime_job_worker.py")


def _write_runtime_job_request(job_type: str, payload: Dict[str, Any]) -> Path:
    request_id = f"{job_type}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{secrets.token_hex(4)}"
    request_path = _runtime_job_dir() / f"{request_id}.json"
    with open(request_path, "w", encoding="utf-8") as request_file:
        json.dump(payload, request_file, indent=2)
    return request_path


def _launch_runtime_job_worker(job_type: str, payload: Dict[str, Any]) -> subprocess.Popen:
    worker_path = _runtime_job_worker_path()
    if not worker_path.exists():
        raise FileNotFoundError(f"Runtime job worker not found: {worker_path}")

    request_path = _write_runtime_job_request(job_type, payload)
    python_executable = sys.executable or "python"
    popen_kwargs: Dict[str, Any] = {
        "cwd": str(Path(__file__).resolve().parent.parent),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }

    if os.name == "nt":
        popen_kwargs["creationflags"] = (
            getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        )
    else:
        popen_kwargs["start_new_session"] = True

    return subprocess.Popen(
        [python_executable, str(worker_path), job_type, str(request_path)],
        **popen_kwargs,
    )


def _terminate_runtime_worker_process(value: Any) -> bool:
    pid = _coerce_process_id(value)
    if pid is None:
        return False

    if not _is_process_running(pid):
        return True

    try:
        if os.name == "nt":
            result = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode == 0 or not _is_process_running(pid)

        if hasattr(os, "getpgid"):
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGTERM)
        return True
    except ProcessLookupError:
        return True
    except Exception:
        return False


discovery_runtime_states, summarization_progress = _load_persisted_runtime_state()
discovery_runtime_state = discovery_runtime_states.get(DISCOVERY_SCOPE_GLOBAL, _build_discovery_runtime_state())
discovery_runtime_states[DISCOVERY_SCOPE_GLOBAL] = discovery_runtime_state
_persist_runtime_state()

chat_agent_memory: Dict[str, Dict[str, Any]] = {}
_chat_memory_write_lock = threading.Lock()


def sanitize_chat_session_id(chat_session_id: str) -> str:
    """Sanitize chat session ID for safe in-memory and file usage."""
    if not isinstance(chat_session_id, str) or not chat_session_id.strip():
        return "default"
    cleaned = re.sub(r'[^a-zA-Z0-9_\-]', '_', chat_session_id.strip())
    return cleaned[:64] if cleaned else "default"


def _get_memory_store_path(chat_session_id: str) -> Path:
    """Get per-chat memory persistence path."""
    project_root = Path(__file__).resolve().parent.parent
    memory_dir = project_root / "output" / "chat_memory"
    memory_dir.mkdir(parents=True, exist_ok=True)
    return memory_dir / f"chat_memory_{sanitize_chat_session_id(chat_session_id)}.json"


def _default_chat_memory(chat_session_id: str) -> Dict[str, Any]:
    """Default chat memory payload."""
    now = datetime.now().isoformat()
    return {
        "chat_session_id": sanitize_chat_session_id(chat_session_id),
        "created_at": now,
        "updated_at": now,
        "primary_intent": "",
        "recent_intents": [],
        "current_focus": "",
        "last_user_message": "",
        "last_assistant_response": "",
        "recent_turns": [],
        "tracked_terms": [],
        "locations": [],
        "entities": {
            "indexes": [],
            "sourcetypes": [],
            "hosts": [],
            "sources": []
        },
        "time_preferences": [],
        "last_tools_used": [],
        "last_result": {},
        "mission": "",
    }


def load_chat_memory(chat_session_id: str) -> Dict[str, Any]:
    """Load chat memory from cache or disk."""
    session_key = sanitize_chat_session_id(chat_session_id)
    if session_key in chat_agent_memory:
        return chat_agent_memory[session_key]

    memory = _default_chat_memory(session_key)
    path = _get_memory_store_path(session_key)
    if path.exists():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    memory.update(loaded)
        except Exception:
            pass

    chat_agent_memory[session_key] = memory
    return memory


def save_chat_memory(chat_session_id: str, memory: Dict[str, Any]) -> None:
    """Persist chat memory in cache and on disk."""
    session_key = sanitize_chat_session_id(chat_session_id)
    memory["chat_session_id"] = session_key
    memory["updated_at"] = datetime.now().isoformat()
    chat_agent_memory[session_key] = memory

    path = _get_memory_store_path(session_key)
    # Concurrent chat requests for one session must never leave a half-written memory file behind.
    temp_path = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with _chat_memory_write_lock:
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(memory, f, indent=2, default=str)
            os.replace(temp_path, path)
    except Exception:
        try:
            if temp_path.exists():
                temp_path.unlink()
        except OSError:
            pass


def _append_unique(target_list: List[str], values: List[str], limit: int = 25) -> List[str]:
    """Append unique non-empty string values with max length enforcement."""
    for value in values:
        if not isinstance(value, str):
            continue
        cleaned = value.strip()
        if cleaned and cleaned not in target_list:
            target_list.append(cleaned)
    if len(target_list) > limit:
        del target_list[:-limit]
    return target_list


def _extract_memory_signals(text: str) -> Dict[str, List[str]]:
    """Extract intent and entity candidates from natural language or SPL text."""
    if not text:
        return {
            "terms": [],
            "indexes": [],
            "sourcetypes": [],
            "hosts": [],
            "sources": [],
            "time_preferences": [],
            "intent": ""
        }

    lower_text = text.lower()
    terms = []
    terms.extend(re.findall(r'"([^"\n]{2,80})"', text))
    terms.extend(re.findall(r"'([^'\n]{2,80})'", text))

    # A bare "*" is not a usable anchor for follow-on searches, so it is dropped.
    indexes = [value for value in re.findall(r'\bindex\s*=\s*"?([\w\*\-\.]+)', text, flags=re.IGNORECASE) if value.strip("*")]
    sourcetypes = [value for value in re.findall(r'\bsourcetype\s*=\s*"?([\w\*\-:\.]+)', text, flags=re.IGNORECASE) if value.strip("*")]
    hosts = [value for value in re.findall(r'\bhost\s*=\s*"?([\w\*\-\.]+)', text, flags=re.IGNORECASE) if value.strip("*")]
    sources = [value for value in re.findall(r'\bsource\s*=\s*"?([^\s\|"]+)', text, flags=re.IGNORECASE) if value.strip("*")]

    natural_language_index = extract_index_from_message(text)
    if natural_language_index:
        indexes.append(natural_language_index)

    natural_language_host = extract_host_or_ip_from_message(text)
    if natural_language_host:
        hosts.append(natural_language_host)

    time_preferences = []
    for token in [
        "-24h",
        "-7d",
        "-30d",
        "today",
        "yesterday",
        "last week",
        "last month",
        "last 24 hours",
        "last 7 days",
        "last 30 days",
        "now",
    ]:
        if token in lower_text:
            time_preferences.append(token)

    intent = ""
    intent_patterns = [
        ("security investigation", ["security", "threat", "incident", "attack"]),
        ("performance monitoring", ["performance", "latency", "cpu", "memory", "slow"]),
        ("index discovery", ["index", "indexes", "sourcetype", "metadata"]),
        ("compliance reporting", ["compliance", "audit", "pci", "hipaa", "sox"]),
        ("spl optimization", ["optimize", "improve query", "explain spl", "generate spl"])
    ]
    for label, keywords in intent_patterns:
        if any(keyword in lower_text for keyword in keywords):
            intent = label
            break

    return {
        "terms": terms,
        "indexes": list(dict.fromkeys(indexes)),
        "sourcetypes": list(dict.fromkeys(sourcetypes)),
        "hosts": list(dict.fromkeys(hosts)),
        "sources": list(dict.fromkeys(sources)),
        "time_preferences": time_preferences,
        "intent": intent
    }


def _extract_last_result_context(tool_calls: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
    """Capture compact state from the latest tool activity for follow-on routing."""
    if not isinstance(tool_calls, list) or not tool_calls:
        return {}

    last_call = next((call for call in reversed(tool_calls) if isinstance(call, dict)), None)
    if not isinstance(last_call, dict):
        return {}

    args = last_call.get("args", {}) if isinstance(last_call.get("args", {}), dict) else {}
    summary = last_call.get("summary", {}) if isinstance(last_call.get("summary", {}), dict) else {}
    query = args.get("query", "") if isinstance(args.get("query", ""), str) else ""
    query_signals = _extract_memory_signals(query)

    actual_results = summary.get("actual_results", []) if isinstance(summary.get("actual_results", []), list) else []
    first_row = actual_results[0] if actual_results and isinstance(actual_results[0], dict) else {}

    def _pick_from_row(keys: List[str]) -> str:
        for key in keys:
            value = first_row.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    index_value = query_signals.get("indexes", [])[-1] if query_signals.get("indexes") else _pick_from_row(["index", "INDEX"])
    # Only real host fields: src/dest values are not Splunk hosts, so host=<src> pivots would miss.
    host_value = query_signals.get("hosts", [])[-1] if query_signals.get("hosts") else _pick_from_row(["host", "HOST"])
    sourcetype_value = query_signals.get("sourcetypes", [])[-1] if query_signals.get("sourcetypes") else _pick_from_row(["sourcetype", "SOURCETYPE"])

    result_fields = summary.get("sample_fields", []) if isinstance(summary.get("sample_fields", []), list) else []
    top_dimensions = summary.get("top_dimensions", []) if isinstance(summary.get("top_dimensions", []), list) else []
    next_pivots = summary.get("next_pivots", []) if isinstance(summary.get("next_pivots", []), list) else []
    findings = summary.get("findings", []) if isinstance(summary.get("findings", []), list) else []
    time_bounds = summary.get("time_bounds", {}) if isinstance(summary.get("time_bounds", {}), dict) else {}

    context = {
        "tool": str(last_call.get("tool", "")).strip(),
        "query": query[:600],
        "row_count": _safe_int(summary.get("row_count")),
        "earliest_time": str(args.get("earliest_time", "") or ""),
        "latest_time": str(args.get("latest_time", "") or ""),
        "index": index_value,
        "host": host_value,
        "sourcetype": sourcetype_value,
        "result_fields": result_fields[:10],
        "query_shape": str(summary.get("query_shape", "") or "").strip(),
        "top_dimensions": [item for item in top_dimensions[:2] if isinstance(item, dict)],
        "next_pivots": [str(item).strip() for item in next_pivots[:3] if isinstance(item, str) and str(item).strip()],
        "findings": [str(item).strip() for item in findings[:4] if isinstance(item, str) and str(item).strip()],
        "time_bounds": time_bounds,
    }

    if not any([
        context.get("query"),
        context.get("index"),
        context.get("host"),
        context.get("sourcetype"),
        context.get("row_count"),
    ]):
        return {}

    return context


def _remembered_entity(memory: Dict[str, Any], entity_key: str) -> Optional[str]:
    """Resolve the most recent entity anchor from memory or latest result context."""
    if not isinstance(memory, dict):
        return None

    last_result = memory.get("last_result", {}) if isinstance(memory.get("last_result", {}), dict) else {}
    candidate = last_result.get(entity_key)
    if isinstance(candidate, str) and candidate.strip():
        return candidate.strip()

    plural_map = {
        "index": "indexes",
        "host": "hosts",
        "sourcetype": "sourcetypes",
        "source": "sources",
    }
    entity_values = memory.get("entities", {}).get(plural_map.get(entity_key, ""), [])
    if isinstance(entity_values, list) and entity_values:
        last_value = entity_values[-1]
        if isinstance(last_value, str) and last_value.strip():
            return last_value.strip()
    return None


def _describe_time_window(earliest_time: str, latest_time: str) -> str:
    earliest = str(earliest_time or "").strip().lower()
    latest = str(latest_time or "").strip().lower()
    known_windows = {
        ("-24h", "now"): "the last 24 hours",
        ("-7d", "now"): "the last 7 days",
        ("-30d", "now"): "the last 30 days",
    }
    if (earliest, latest) in known_windows:
        return known_windows[(earliest, latest)]
    if earliest:
        return f"the window {earliest} to {latest or 'now'}"
    return "the recent time window"


def _make_follow_on_action(label: str, prompt: str, kind: str) -> Dict[str, str]:
    return {
        "label": label,
        "prompt": prompt,
        "kind": kind,
    }


def _normalize_response_follow_on_text(action_text: str) -> str:
    cleaned = re.sub(r'\s+', ' ', str(action_text or '')).strip(" \t\r\n:-*•")
    cleaned = cleaned.strip("`'\"")
    cleaned = re.sub(r'^to\s+', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'^also\s+', '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'\s+(?:for you|if helpful|if that helps|if you want)$', '', cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.rstrip(' .;:')
    if not cleaned:
        return ""
    return cleaned[0].upper() + cleaned[1:]


def _build_response_follow_on_label(prompt: str, limit: int = 72) -> str:
    label = str(prompt or '').strip().rstrip('.')
    if len(label) <= limit:
        return label
    shortened = label[:limit].rsplit(' ', 1)[0].strip()
    return f"{shortened or label[:limit].strip()}..."


_RESPONSE_FOLLOW_ON_LIST_ITEM_PATTERN = re.compile(r"^\s*(?:[-*•]+|\d+[.)])\s+(?P<action>.+?)\s*$")
_RESPONSE_FOLLOW_ON_INLINE_MARKER_PATTERN = re.compile(r"(?:(?<=^)|(?<=[\s,;]))(?P<marker>\d+[.)]|[-*•])\s+")
_RESPONSE_FOLLOW_ON_TRUNCATED_INLINE_PATTERN = re.compile(r":\s*(?:\d+[.)]?|[-*•])$")


def _is_response_follow_on_list_lead_in(line: str) -> bool:
    normalized = re.sub(r'\s+', ' ', str(line or '')).strip().lower().rstrip(' :;,.')
    if not normalized:
        return False

    trigger_match = (
        normalized.startswith("if you'd like")
        or normalized.startswith("if you’d like")
        or normalized.startswith("if you would like")
        or normalized.startswith("if you want")
        or normalized.startswith("if helpful")
        or normalized.startswith("things i can do next")
        or normalized.startswith("next steps i can")
        or normalized.startswith("here are")
        or normalized.startswith("here's")
    )
    if not trigger_match:
        return False

    return (
        normalized.endswith("i can")
        or normalized.endswith("following")
        or normalized.endswith("make this")
        or normalized.endswith("turn this into")
        or "next steps" in normalized
        or "options" in normalized
        or "things i can do next" in normalized
        or "things i can" in normalized
    )


def _is_response_follow_on_wrapper_prompt(prompt: str) -> bool:
    normalized = re.sub(r'\s+', ' ', str(prompt or '')).strip().lower().rstrip(' :;,.')
    if not normalized:
        return False
    if normalized in {"following", "the following", "next steps", "options", "things i can do next"}:
        return True
    return bool(re.fullmatch(
        r"(?:do|help with|take|offer)(?:\s+(?:any|one|some))?\s*(?:of\s+)?(?:the|these)?\s*(?:following|next steps|options)",
        normalized,
    ))


def _expand_response_follow_on_inline_actions(action_text: str) -> List[str]:
    raw_action = re.sub(r'\s+', ' ', str(action_text or '')).strip()
    if not raw_action:
        return []

    prefix, separator, suffix = raw_action.partition(':')
    if not separator:
        normalized_action = _normalize_response_follow_on_text(raw_action)
        return [normalized_action] if normalized_action else []

    matches = list(_RESPONSE_FOLLOW_ON_INLINE_MARKER_PATTERN.finditer(suffix))
    if not matches:
        normalized_action = _normalize_response_follow_on_text(raw_action)
        return [normalized_action] if normalized_action else []

    cleaned_prefix = _normalize_response_follow_on_text(prefix)
    prompts: List[str] = []
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(suffix)
        item_text = suffix[start:end].strip(" \t\r\n,;")
        item_text = re.sub(r'^(?:and|or)\s+', '', item_text, flags=re.IGNORECASE)
        item_text = re.sub(r'(?:,|;)\s*(?:and|or)\s*$', '', item_text, flags=re.IGNORECASE)
        if not item_text:
            continue

        if cleaned_prefix and not _is_response_follow_on_wrapper_prompt(cleaned_prefix):
            combined_prompt = _normalize_response_follow_on_text(f"{prefix.strip()} {item_text}")
            if combined_prompt:
                prompts.append(combined_prompt)
            continue

        normalized_item = _normalize_response_follow_on_text(item_text)
        if normalized_item:
            prompts.append(normalized_item)

    if prompts:
        return prompts

    normalized_action = _normalize_response_follow_on_text(raw_action)
    return [normalized_action] if normalized_action else []


def _extract_response_follow_on_list_actions(
    cleaned_response: str,
    seen_prompts: set[str],
    ignored_prefixes: Tuple[str, ...],
) -> List[Dict[str, str]]:
    actions: List[Dict[str, str]] = []
    lines = str(cleaned_response or '').splitlines()
    line_index = 0

    while line_index < len(lines):
        if not _is_response_follow_on_list_lead_in(lines[line_index]):
            line_index += 1
            continue

        candidate_index = line_index + 1
        found_list_item = False

        while candidate_index < len(lines):
            raw_line = lines[candidate_index]
            stripped_line = raw_line.strip()
            if not stripped_line:
                if found_list_item:
                    break
                candidate_index += 1
                continue

            match = _RESPONSE_FOLLOW_ON_LIST_ITEM_PATTERN.match(raw_line)
            if not match:
                break

            found_list_item = True
            prompt = _normalize_response_follow_on_text(match.group('action'))
            lowered_prompt = prompt.lower()
            if (
                len(prompt.split()) >= 3
                and not lowered_prompt.startswith(ignored_prefixes)
                and not _is_response_follow_on_wrapper_prompt(prompt)
                and lowered_prompt not in seen_prompts
            ):
                seen_prompts.add(lowered_prompt)
                actions.append(_make_follow_on_action(
                    _build_response_follow_on_label(prompt),
                    prompt,
                    'assistant_response_follow_up',
                ))

            candidate_index += 1

        line_index = candidate_index if candidate_index > line_index else line_index + 1

    return actions


def _extract_response_follow_on_actions(assistant_response: str) -> List[Dict[str, str]]:
    cleaned_response = sanitize_llm_response_text(str(assistant_response or ''))
    if not cleaned_response:
        return []

    inline_list_patterns = [
        r"\bif you(?:'d|’d|\swould)? like,?\s+i can\s+(?P<action>[^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)",
        r"\bif you want(?:\s+[^,.!?\n]+)?[,;]?\s+i can\s+(?P<action>[^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)",
        r"\bif helpful,?\s+i can\s+(?P<action>[^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)",
        r"\bor i can\s+(?P<action>[^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)",
        r"\bi can also\s+(?P<action>[^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)",
        r"\bi can\s+(?P<action>[^\n]+?:\s*(?:\d+[.)]|[-*•])[^\n]*)",
    ]
    patterns = [
        r"\ba good follow[ -]?up(?: question| step| action)?\s+(?:would be(?: to)?|is|might be|could be)\s+(?P<action>[^.!?\n]+)",
        r"\bif you(?:'d|’d|\swould)? like,?\s+i can\s+(?P<action>[^.!?\n]+)",
        r"\bif you want(?:\s+[^,.!?\n]+)?[,;]?\s+i can\s+(?P<action>[^.!?\n]+)",
        r"\bif helpful,?\s+i can\s+(?P<action>[^.!?\n]+)",
        r"\bor i can\s+(?P<action>[^.!?\n]+)",
        r"\bi can also\s+(?P<action>[^.!?\n]+)",
        r"\bi can\s+(?P<action>(?:list|show|compare|check|validate|investigate|review|summarize|break down|trend|prototype|measure|explain|help you find)[^.!?\n]+)",
    ]
    ignored_prefixes = (
        'do that',
        'help with that',
        'continue',
        'keep going',
        'take it further',
        'go deeper',
    )

    actions: List[Dict[str, str]] = []
    seen_prompts = set()
    actions.extend(_extract_response_follow_on_list_actions(cleaned_response, seen_prompts, ignored_prefixes))

    for pattern in inline_list_patterns:
        for match in re.finditer(pattern, cleaned_response, flags=re.IGNORECASE):
            for prompt in _expand_response_follow_on_inline_actions(match.group('action')):
                lowered_prompt = prompt.lower()
                if (
                    len(prompt.split()) < 3
                    or lowered_prompt.startswith(ignored_prefixes)
                    or _is_response_follow_on_wrapper_prompt(prompt)
                    or _RESPONSE_FOLLOW_ON_TRUNCATED_INLINE_PATTERN.search(prompt)
                ):
                    continue
                if lowered_prompt in seen_prompts:
                    continue
                seen_prompts.add(lowered_prompt)
                actions.append(_make_follow_on_action(
                    _build_response_follow_on_label(prompt),
                    prompt,
                    'assistant_response_follow_up',
                ))

    for pattern in patterns:
        for match in re.finditer(pattern, cleaned_response, flags=re.IGNORECASE):
            for prompt in _expand_response_follow_on_inline_actions(match.group('action')):
                lowered_prompt = prompt.lower()
                if (
                    len(prompt.split()) < 3
                    or lowered_prompt.startswith(ignored_prefixes)
                    or _is_response_follow_on_wrapper_prompt(prompt)
                    or _RESPONSE_FOLLOW_ON_TRUNCATED_INLINE_PATTERN.search(prompt)
                ):
                    continue
                if lowered_prompt in seen_prompts:
                    continue
                seen_prompts.add(lowered_prompt)
                actions.append(_make_follow_on_action(
                    _build_response_follow_on_label(prompt),
                    prompt,
                    'assistant_response_follow_up',
                ))

    return _dedupe_follow_on_actions(actions, limit=3)


def _extract_top_dimension_context(summary: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(summary, dict):
        return {}

    top_dimensions = summary.get("top_dimensions", []) if isinstance(summary.get("top_dimensions", []), list) else []
    for dimension in top_dimensions:
        if not isinstance(dimension, dict):
            continue
        field = str(dimension.get("field", "")).strip()
        values = [
            str(value).strip()
            for value in (dimension.get("values", []) if isinstance(dimension.get("values", []), list) else [])
            if str(value).strip()
        ]
        if not field or not values:
            continue
        top_value = values[0].rsplit(" (", 1)[0].strip()
        return {
            "field": field,
            "values": values[:3],
            "top_value": top_value,
        }
    return {}


def _build_output_follow_on_actions(
    summary: Dict[str, Any],
    remembered_index: Optional[str],
    remembered_host: Optional[str],
    time_window_label: str,
) -> List[Dict[str, Any]]:
    if not isinstance(summary, dict):
        return []

    actions: List[Dict[str, Any]] = []
    row_count = _safe_int(summary.get("row_count"))
    if row_count <= 0:
        return actions

    query_shape = str(summary.get("query_shape", "") or "").strip().lower()
    findings_text = " ".join(
        item.strip().lower()
        for item in summary.get("findings", [])
        if isinstance(item, str) and item.strip()
    )
    next_pivots = [
        str(item).strip()
        for item in summary.get("next_pivots", [])
        if isinstance(item, str) and str(item).strip()
    ]
    sample_fields = [
        str(field).strip().lower()
        for field in summary.get("sample_fields", [])
        if isinstance(field, str) and str(field).strip()
    ]
    top_dimension = _extract_top_dimension_context(summary)
    dimension_field = str(top_dimension.get("field", "")).strip()
    top_value = str(top_dimension.get("top_value", "")).strip()
    top_values = top_dimension.get("values", []) if isinstance(top_dimension.get("values", []), list) else []
    index_clause = f" in index={remembered_index}" if remembered_index else ""

    if query_shape == "time_series":
        if remembered_index:
            actions.append(_make_follow_on_action(
                f"Explain changes in index={remembered_index}",
                f"Explain the biggest spikes or drops in index={remembered_index} over {time_window_label} by breaking the trend down by sourcetype and host.",
                "explain_trend_change",
            ))
            actions.append(_make_follow_on_action(
                "Compare with the previous window",
                f"Compare event volume for index={remembered_index} in {time_window_label} versus the previous equivalent window and summarize what changed.",
                "compare_previous_window",
            ))
        if remembered_host:
            actions.append(_make_follow_on_action(
                f"Inspect host={remembered_host} around the change",
                f"Show surrounding events for host={remembered_host}{index_clause} over {time_window_label} and highlight what lines up with the biggest spike or drop.",
                "host_spike_pivot",
            ))
    elif query_shape == "aggregation":
        if dimension_field and top_value:
            actions.append(_make_follow_on_action(
                f"Filter on {dimension_field}={top_value}",
                f"Filter the last query on {dimension_field}={top_value}{index_clause} over {time_window_label} and explain why it stands out.",
                "filter_dimension_value",
            ))
            if remembered_index:
                actions.append(_make_follow_on_action(
                    f"Trend {top_value} over time",
                    f"Show a timechart for {dimension_field}={top_value} in index={remembered_index} over {time_window_label}.",
                    "trend_dimension_value",
                ))
        if dimension_field and len(top_values) > 1:
            actions.append(_make_follow_on_action(
                f"Compare the top {dimension_field} values",
                f"Compare the top {dimension_field} values from the last result ({', '.join(top_values[:3])}){index_clause} and summarize what separates them.",
                "compare_dimension_values",
            ))
    elif query_shape == "event_sample":
        if remembered_host:
            actions.append(_make_follow_on_action(
                f"Show surrounding events for host={remembered_host}",
                f"Show surrounding events for host={remembered_host}{index_clause} over {time_window_label} and highlight the most relevant patterns.",
                "surrounding_events_host",
            ))
        if "sourcetype" in sample_fields or "host" in sample_fields:
            actions.append(_make_follow_on_action(
                "Summarize the event pattern",
                f"Group the last result by sourcetype and host{index_clause} over {time_window_label} so the main event pattern is easier to interpret.",
                "summarize_event_pattern",
            ))
        if any(field in sample_fields for field in ["user", "src", "src_ip", "dest", "dest_ip", "action", "status", "signature"]):
            actions.append(_make_follow_on_action(
                "Pivot on the key entities",
                f"Pivot on the most important entities from the last result{index_clause} over {time_window_label} and show the strongest outliers.",
                "pivot_key_entities",
            ))
    elif dimension_field and top_value:
        actions.append(_make_follow_on_action(
            f"Filter on {dimension_field}={top_value}",
            f"Filter the last query on {dimension_field}={top_value}{index_clause} over {time_window_label} and explain what changes.",
            "filter_dimension_value",
        ))

    for pivot in next_pivots[:2]:
        lowered_pivot = pivot.lower()
        if lowered_pivot.startswith("filter on ") and "=" in pivot:
            filter_target = pivot[len("Filter on "):].strip()
            actions.append(_make_follow_on_action(
                f"Filter on {filter_target}",
                f"Filter the last query on {filter_target}{index_clause} over {time_window_label} and explain what changes.",
                "filter_dimension_value",
            ))
        elif "compare adjacent time buckets" in lowered_pivot and remembered_index:
            actions.append(_make_follow_on_action(
                "Compare adjacent time buckets",
                f"Compare adjacent time buckets for index={remembered_index} over {time_window_label} and explain the biggest changes.",
                "compare_time_buckets",
            ))
        elif "aggregate by one dimension" in lowered_pivot:
            actions.append(_make_follow_on_action(
                "Aggregate by one dimension",
                f"Aggregate the last query{index_clause} by one dimension over {time_window_label} so the result is easier to explain.",
                "aggregate_one_dimension",
            ))

    if "large result set" in findings_text or row_count > 100:
        actions.append(_make_follow_on_action(
            "Tighten the result set",
            f"Tighten the last query{index_clause} by one dimension or a narrower time window so the result is easier to explain.",
            "tighten_result_set",
        ))

    return _dedupe_follow_on_actions(actions, limit=3)


def _compact_memory_text(text: Any, limit: int = 280) -> str:
    if not isinstance(text, str):
        return ""
    cleaned = re.sub(r'\s+', ' ', text).strip()
    return cleaned[:limit]


def _append_recent_turn(memory: Dict[str, Any], role: str, content: str, limit: int = 8) -> None:
    if not isinstance(memory, dict):
        return

    cleaned = _compact_memory_text(content, limit=320)
    if not cleaned:
        return

    turns = memory.get("recent_turns", []) if isinstance(memory.get("recent_turns", []), list) else []
    candidate = {
        "role": str(role or "user").strip().lower(),
        "content": cleaned,
    }
    if turns and isinstance(turns[-1], dict):
        if turns[-1].get("role") == candidate["role"] and turns[-1].get("content") == candidate["content"]:
            memory["recent_turns"] = turns[-limit:]
            return

    turns.append(candidate)
    memory["recent_turns"] = turns[-limit:]


def _build_conversation_focus_text(
    user_message: str,
    memory: Dict[str, Any],
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    assistant_response: str = "",
) -> str:
    parts = [
        str(user_message or ""),
        str(assistant_response or ""),
        str(memory.get("primary_intent", "") if isinstance(memory, dict) else ""),
        str(memory.get("current_focus", "") if isinstance(memory, dict) else ""),
        str(memory.get("last_user_message", "") if isinstance(memory, dict) else ""),
        str(memory.get("last_assistant_response", "") if isinstance(memory, dict) else ""),
    ]

    if isinstance(memory, dict):
        last_result = memory.get("last_result", {}) if isinstance(memory.get("last_result", {}), dict) else {}
        for key in ["query", "index", "host", "sourcetype"]:
            value = last_result.get(key)
            if isinstance(value, str):
                parts.append(value)
        for finding in last_result.get("findings", []) if isinstance(last_result.get("findings", []), list) else []:
            if isinstance(finding, str):
                parts.append(finding)
        for pivot in last_result.get("next_pivots", []) if isinstance(last_result.get("next_pivots", []), list) else []:
            if isinstance(pivot, str):
                parts.append(pivot)

        for turn in memory.get("recent_turns", [])[-4:] if isinstance(memory.get("recent_turns", []), list) else []:
            if isinstance(turn, dict) and isinstance(turn.get("content"), str):
                parts.append(turn.get("content", ""))

    if tool_calls:
        last_call = next((call for call in reversed(tool_calls) if isinstance(call, dict)), None)
        if isinstance(last_call, dict):
            args = last_call.get("args", {}) if isinstance(last_call.get("args", {}), dict) else {}
            summary = last_call.get("summary", {}) if isinstance(last_call.get("summary", {}), dict) else {}
            if isinstance(args.get("query"), str):
                parts.append(args.get("query", ""))
            for finding in summary.get("findings", [])[:4] if isinstance(summary.get("findings", []), list) else []:
                if isinstance(finding, str):
                    parts.append(finding)

    return " ".join(part for part in parts if isinstance(part, str) and part.strip()).lower()


def _detect_conversation_focus(
    user_message: str,
    memory: Dict[str, Any],
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    assistant_response: str = "",
    report_intent: Optional[str] = None,
) -> str:
    if report_intent:
        return str(report_intent).strip().lower()

    focus_text = _build_conversation_focus_text(user_message, memory, tool_calls, assistant_response)
    last_result = memory.get("last_result", {}) if isinstance(memory, dict) and isinstance(memory.get("last_result", {}), dict) else {}
    query_text = str(last_result.get("query", "") or "").lower()

    if any(token in focus_text for token in ["windows security", "failed logon", "failed login", "authentication", "lockout", "privilege", "wineventlog:security"]):
        return "security"
    if any(token in focus_text for token in ["platform health", "_internal", "_audit", "_introspection", "ingestion", "license", "scheduler", "search failure", "splunk health"]):
        return "platform_health"
    if any(token in focus_text for token in ["api availability", "collector", "latency spike", "feed health", "error rate", "response time", "uptime"]):
        return "service_health"
    if any(token in focus_text for token in ["network", "latency", "packet loss", "connectivity", "ping"]):
        return "network"
    if any(token in focus_text for token in ["compliance", "audit", "governance", "admin action", "privileged action"]):
        return "compliance"
    if any(token in focus_text for token in ["recommendation", "recommend", "improve", "next step", "priority action"]):
        return "recommendations"
    if any(token in focus_text for token in ["risk", "exposure", "blind spot", "weak spot"]):
        return "top_risks"
    if any(token in focus_text for token in ["coverage gap", "coverage gaps", "missing coverage", "what is missing"]):
        return "coverage_gaps"
    if any(token in focus_text for token in ["use case", "use cases", "what should we build", "monitoring opportunity"]):
        return "use_cases"
    if any(token in focus_text for token in ["readiness", "maturity", "posture", "how ready"]):
        return "readiness"
    if "timechart" in focus_text or "timechart" in query_text:
        return "trend_analysis"
    if any(token in focus_text for token in ["break down", "breakdown", "by sourcetype", "by host"]) or any(token in query_text for token in [" by sourcetype", " by host"]):
        return "breakdown_analysis"
    if any(token in focus_text for token in ["last seen", "latest event", "surrounding events", "host investigation", "pivot on host"]) or memory.get("last_result", {}).get("host"):
        if memory.get("last_result", {}).get("host"):
            return "host_analysis"
    if memory.get("last_result", {}).get("index"):
        return "index_analysis"
    return str(memory.get("primary_intent", "") or "general").strip().lower() or "general"


def _dedupe_follow_on_actions(actions: List[Dict[str, Any]], limit: int = 3) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        key = (str(action.get("kind", "")).strip().lower(), str(action.get("prompt", "")).strip().lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(action)
        if len(deduped) >= limit:
            break
    return deduped


def _build_focus_follow_on_actions(
    focus: str,
    remembered_index: Optional[str],
    remembered_host: Optional[str],
    time_window_label: str,
) -> List[Dict[str, Any]]:
    actions: List[Dict[str, Any]] = []
    index_clause = f" in index={remembered_index}" if remembered_index else ""

    if focus == "security":
        actions.extend([
            _make_follow_on_action(
                "Validate failed logons",
                f"Validate failed logons{index_clause} over {time_window_label} and show the top users, hosts, and source IPs.",
                "validate_failed_logons",
            ),
            _make_follow_on_action(
                "Check privilege changes",
                f"Check privilege changes, account lockouts, and group membership changes{index_clause} over {time_window_label}.",
                "validate_privilege_changes",
            ),
        ])
    elif focus == "platform_health":
        actions.extend([
            _make_follow_on_action(
                "Check Splunk platform health",
                "Check platform health in _internal, _audit, and _introspection over the last 24 hours and summarize ingestion issues, search failures, and license signals.",
                "validate_platform_health",
            ),
            _make_follow_on_action(
                "Inspect ingestion failures",
                "Show ingestion errors, queue pressure, and blocked pipelines from _internal over the last 24 hours.",
                "inspect_ingestion_failures",
            ),
        ])
    elif focus == "service_health":
        actions.extend([
            _make_follow_on_action(
                "Review service feed health",
                f"Check the API or collector data{index_clause} over {time_window_label} for outages, elevated errors, and latency spikes.",
                "validate_service_health",
            ),
            _make_follow_on_action(
                "Compare sources by error rate",
                f"Compare sources or collectors{index_clause} by error rate and response time over {time_window_label}.",
                "compare_service_sources",
            ),
        ])
    elif focus == "network":
        actions.extend([
            _make_follow_on_action(
                "Inspect network connectivity",
                "Show connectivity, latency, and packet-loss trends from ping or network telemetry over the last 24 hours.",
                "validate_network_health",
            ),
            _make_follow_on_action(
                "Compare noisy hosts",
                "Compare the noisiest network hosts over the last 24 hours and highlight packet-loss or latency outliers.",
                "compare_network_hosts",
            ),
        ])
    elif focus == "compliance":
        actions.extend([
            _make_follow_on_action(
                "Review audit activity",
                "Show privileged actions, configuration changes, and audit failures over the last 7 days.",
                "review_audit_activity",
            ),
            _make_follow_on_action(
                "Check admin changes",
                "Summarize admin changes and notable governance events over the last 7 days.",
                "review_admin_changes",
            ),
        ])
    elif focus == "trend_analysis" and remembered_index:
        actions.extend([
            _make_follow_on_action(
                f"Explain spikes in index={remembered_index}",
                f"Break down the biggest spikes in index={remembered_index} by sourcetype and host over {time_window_label}.",
                "explain_trend_spikes",
            ),
            _make_follow_on_action(
                f"Compare trend windows for index={remembered_index}",
                f"Compare event volume for index={remembered_index} in {time_window_label} versus the previous equivalent window.",
                "compare_trend_windows",
            ),
        ])
    elif focus == "breakdown_analysis" and remembered_index:
        actions.extend([
            _make_follow_on_action(
                f"Trend the top sourcetype in index={remembered_index}",
                f"Show a timechart for the top sourcetype in index={remembered_index} over {time_window_label}.",
                "trend_top_sourcetype",
            ),
            _make_follow_on_action(
                f"Inspect top host in index={remembered_index}",
                f"Inspect the busiest host in index={remembered_index} and show representative events over {time_window_label}.",
                "inspect_top_host",
            ),
        ])
    elif focus == "host_analysis" and remembered_host:
        actions.extend([
            _make_follow_on_action(
                f"Show surrounding events for host={remembered_host}",
                f"Show surrounding events for host={remembered_host}{index_clause} over {time_window_label} with sourcetype breakdown.",
                "surrounding_events_host",
            ),
            _make_follow_on_action(
                f"Check last seen for host={remembered_host}",
                f"When was host={remembered_host} last seen in Splunk, and what sourcetypes did it report most recently?",
                "last_seen_host",
            ),
        ])
    elif focus in {"recommendations", "top_risks", "coverage_gaps", "use_cases", "readiness"}:
        actions.append(_make_follow_on_action(
            "Validate the top issue live",
            "Validate the top recommendation, risk, or coverage gap with a live query and summarize current drift from the report snapshot.",
            "validate_top_gap",
        ))

    return actions


def update_chat_memory(
    chat_session_id: str,
    user_message: str,
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    assistant_response: Optional[str] = None,
    report_intent: Optional[str] = None,
    record_user_turn: bool = True,
    update_focus: bool = True,
) -> Dict[str, Any]:
    """Update chat memory with latest user message, optional tool activity, and optional assistant response."""
    memory = load_chat_memory(chat_session_id)
    signals = _extract_memory_signals(user_message)

    if isinstance(user_message, str) and user_message.strip():
        memory["last_user_message"] = _compact_memory_text(user_message, limit=320)
        if record_user_turn:
            _append_recent_turn(memory, "user", user_message)

    if signals.get("intent"):
        memory["primary_intent"] = signals["intent"]
        _append_unique(memory["recent_intents"], [signals["intent"]], limit=8)
    if report_intent:
        _append_unique(memory["recent_intents"], [str(report_intent).strip().lower()], limit=8)

    _append_unique(memory["tracked_terms"], signals.get("terms", []), limit=30)
    _append_unique(memory["time_preferences"], signals.get("time_preferences", []), limit=10)

    entities = memory.get("entities", {})
    _append_unique(entities.setdefault("indexes", []), signals.get("indexes", []), limit=25)
    _append_unique(entities.setdefault("sourcetypes", []), signals.get("sourcetypes", []), limit=25)
    _append_unique(entities.setdefault("hosts", []), signals.get("hosts", []), limit=25)
    _append_unique(entities.setdefault("sources", []), signals.get("sources", []), limit=25)

    _append_unique(memory["locations"], signals.get("indexes", []) + signals.get("hosts", []) + signals.get("sources", []), limit=25)

    if tool_calls:
        recent_tools = [tc.get("tool", "") for tc in tool_calls if isinstance(tc, dict) and tc.get("tool")]
        _append_unique(memory["last_tools_used"], recent_tools, limit=15)

        for tc in tool_calls:
            if not isinstance(tc, dict):
                continue
            args = tc.get("args", {}) or {}
            if isinstance(args, dict) and args.get("query"):
                query_signals = _extract_memory_signals(args.get("query", ""))
                _append_unique(entities.setdefault("indexes", []), query_signals.get("indexes", []), limit=25)
                _append_unique(entities.setdefault("sourcetypes", []), query_signals.get("sourcetypes", []), limit=25)
                _append_unique(entities.setdefault("hosts", []), query_signals.get("hosts", []), limit=25)
                _append_unique(entities.setdefault("sources", []), query_signals.get("sources", []), limit=25)

        last_result_context = _extract_last_result_context(tool_calls)
        if last_result_context:
            memory["last_result"] = last_result_context

    if isinstance(assistant_response, str) and assistant_response.strip():
        memory["last_assistant_response"] = _compact_memory_text(assistant_response, limit=400)
        _append_recent_turn(memory, "assistant", assistant_response)

    if update_focus:
        focus = _detect_conversation_focus(
            user_message,
            memory,
            tool_calls=tool_calls,
            assistant_response=assistant_response or "",
            report_intent=report_intent,
        )
        if focus:
            memory["current_focus"] = focus

    memory["entities"] = entities
    save_chat_memory(chat_session_id, memory)
    return memory


def build_chat_memory_context(memory: Dict[str, Any]) -> str:
    """Render concise memory context for system prompt injection."""
    if not memory:
        return ""

    entities = memory.get("entities", {})
    lines = ["🧠 SESSION MEMORY:"]
    if memory.get("primary_intent"):
        lines.append(f"- Primary intent: {memory['primary_intent']}")
    if memory.get("current_focus"):
        lines.append(f"- Current focus: {memory['current_focus']}")
    if memory.get("recent_intents"):
        lines.append(f"- Recent intents: {', '.join(memory['recent_intents'][-3:])}")
    if memory.get("tracked_terms"):
        lines.append(f"- Tracked terms: {', '.join(memory['tracked_terms'][-6:])}")
    if entities.get("indexes"):
        lines.append(f"- Remembered indexes: {', '.join(entities['indexes'][-6:])}")
    if entities.get("hosts"):
        lines.append(f"- Remembered hosts: {', '.join(entities['hosts'][-4:])}")
    if entities.get("sourcetypes"):
        lines.append(f"- Remembered sourcetypes: {', '.join(entities['sourcetypes'][-4:])}")
    if memory.get("time_preferences"):
        lines.append(f"- Preferred time ranges: {', '.join(memory['time_preferences'][-4:])}")
    if memory.get("last_tools_used"):
        lines.append(f"- Last tools used: {', '.join(memory['last_tools_used'][-5:])}")
    last_result = memory.get("last_result", {}) if isinstance(memory.get("last_result", {}), dict) else {}
    if last_result:
        last_context_parts = []
        if last_result.get("index"):
            last_context_parts.append(f"index={last_result['index']}")
        if last_result.get("host"):
            last_context_parts.append(f"host={last_result['host']}")
        if last_result.get("row_count") is not None:
            last_context_parts.append(f"row_count={last_result.get('row_count', 0)}")
        if last_result.get("earliest_time"):
            last_context_parts.append(
                f"window={last_result.get('earliest_time', '')} to {last_result.get('latest_time', 'now') or 'now'}"
            )
        if last_context_parts:
            lines.append(f"- Last result context: {', '.join(last_context_parts)}")
    if memory.get("recent_turns"):
        turn_snapshot = []
        for turn in memory.get("recent_turns", [])[-3:]:
            if not isinstance(turn, dict):
                continue
            role = str(turn.get("role", "user")).strip().capitalize()
            content = _compact_memory_text(turn.get("content", ""), limit=80)
            if content:
                turn_snapshot.append(f"{role}: {content}")
        if turn_snapshot:
            lines.append(f"- Recent turns: {' | '.join(turn_snapshot)}")

    return "\n".join(lines)


def _format_last_result_context_for_prompt(memory: Dict[str, Any]) -> str:
    """Render the last result context in a compact single-line form for prompt continuity."""
    if not isinstance(memory, dict):
        return ""

    last_result = memory.get("last_result", {}) if isinstance(memory.get("last_result", {}), dict) else {}
    if not last_result:
        return ""

    parts: List[str] = []
    for key in ("index", "host", "sourcetype", "source"):
        value = str(last_result.get(key) or "").strip()
        if value:
            parts.append(f"{key}={value}")

    if last_result.get("row_count") is not None:
        parts.append(f"row_count={_safe_int(last_result.get('row_count'))}")

    earliest_time = str(last_result.get("earliest_time") or "").strip()
    latest_time = str(last_result.get("latest_time") or "now").strip() or "now"
    if earliest_time:
        parts.append(f"window={earliest_time} to {latest_time}")

    query = _compact_memory_text(last_result.get("query", ""), limit=140)
    if query:
        parts.append(f"query={query}")

    findings = [
        _compact_memory_text(finding, limit=90)
        for finding in (last_result.get("findings", []) if isinstance(last_result.get("findings", []), list) else [])[:3]
        if isinstance(finding, str) and finding.strip()
    ]
    if findings:
        parts.append(f"findings={'; '.join(findings)}")

    return ", ".join(parts)


def _build_llm_recent_context_turns(
    history: Any,
    memory: Dict[str, Any],
    limit: int = 6,
) -> List[Dict[str, str]]:
    """Return recent turns for LLM continuity, preferring normalized live history over persisted memory."""
    recent_history = _compact_chat_role_history(history, limit=limit, include_system=False)
    if recent_history:
        return [
            {
                "role": entry.get("role", "user"),
                "content": _compact_memory_text(entry.get("content", ""), limit=180),
            }
            for entry in recent_history
            if isinstance(entry, dict) and _compact_memory_text(entry.get("content", ""), limit=180)
        ]

    turns = memory.get("recent_turns", []) if isinstance(memory, dict) and isinstance(memory.get("recent_turns", []), list) else []
    normalized: List[Dict[str, str]] = []
    for turn in turns[-limit:]:
        if not isinstance(turn, dict):
            continue
        role = str(turn.get("role") or "").strip().lower()
        if role not in {"user", "assistant"}:
            continue
        content = _compact_memory_text(turn.get("content", ""), limit=180)
        if not content:
            continue
        normalized.append({"role": role, "content": content})
    return normalized


def build_llm_continuity_context(
    user_message: str,
    history: Any,
    memory: Dict[str, Any],
    limit: int = 6,
) -> str:
    """Build a provider-agnostic continuity gate so the LLM sees the live session state on every turn."""
    memory = memory if isinstance(memory, dict) else {}
    recent_turns = _build_llm_recent_context_turns(history, memory, limit=limit)
    user_text = _compact_memory_text(user_message, limit=320)
    last_result_context = _format_last_result_context_for_prompt(memory)
    entities = memory.get("entities", {}) if isinstance(memory.get("entities", {}), dict) else {}

    state_lines: List[str] = []
    primary_intent = str(memory.get("primary_intent") or "").strip()
    if primary_intent:
        state_lines.append(f"- Primary intent: {primary_intent}")

    current_focus = str(memory.get("current_focus") or "").strip()
    if current_focus:
        state_lines.append(f"- Active focus: {current_focus}")

    remembered_indexes = [str(item).strip() for item in entities.get("indexes", [])[-6:] if isinstance(item, str) and item.strip()]
    if remembered_indexes:
        state_lines.append(f"- Remembered indexes: {', '.join(remembered_indexes)}")

    remembered_hosts = [str(item).strip() for item in entities.get("hosts", [])[-4:] if isinstance(item, str) and item.strip()]
    if remembered_hosts:
        state_lines.append(f"- Remembered hosts: {', '.join(remembered_hosts)}")

    remembered_sourcetypes = [str(item).strip() for item in entities.get("sourcetypes", [])[-4:] if isinstance(item, str) and item.strip()]
    if remembered_sourcetypes:
        state_lines.append(f"- Remembered sourcetypes: {', '.join(remembered_sourcetypes)}")

    if last_result_context:
        state_lines.append(f"- Last result context: {last_result_context}")

    last_assistant_response = _compact_memory_text(memory.get("last_assistant_response", ""), limit=200)
    if last_assistant_response:
        state_lines.append(f"- Last assistant response: {last_assistant_response}")

    if not state_lines and not recent_turns and not user_text:
        return ""

    lines = [
        "SESSION CONTINUITY GATE:",
        "- Treat the current user message as a continuation of the active investigation unless the user clearly changes topic.",
        "- Resolve pronouns, shorthand, omitted nouns, and aliases using the active focus, remembered entities, last result, and recent turns before answering.",
        "- Prefer the current Splunk and Splunk Discovery Tool session context over generic interpretations when the request is ambiguous.",
    ]

    if state_lines:
        lines.append("Active session state:")
        lines.extend(state_lines)

    if recent_turns:
        lines.append("Recent conversation:")
        for turn in recent_turns[-4:]:
            role = str(turn.get("role") or "user").strip().capitalize()
            content = _compact_memory_text(turn.get("content", ""), limit=180)
            if content:
                lines.append(f"- {role}: {content}")

    if user_text:
        lines.append(f"Current request to interpret in-session: {user_text}")

    return "\n".join(lines)


def _compact_chat_role_history(
    history: Any,
    limit: int = 12,
    include_system: bool = False,
) -> List[Dict[str, str]]:
    """Normalize chat history into compact role/content pairs for safe follow-up reuse."""
    if not isinstance(history, list):
        return []

    normalized: List[Dict[str, str]] = []
    for entry in history:
        if not isinstance(entry, dict):
            continue
        role = str(entry.get("role") or "").strip().lower()
        if role not in {"user", "assistant", "system"}:
            continue
        if role == "system" and not include_system:
            continue
        content = str(entry.get("content") or "").strip()
        if not content:
            continue
        normalized.append({"role": role, "content": content})

    if include_system:
        system_entries = [item for item in normalized if item.get("role") == "system"][:1]
        non_system_entries = [item for item in normalized if item.get("role") != "system"]
        return system_entries + (non_system_entries[-limit:] if limit > 0 else non_system_entries)

    return normalized[-limit:] if limit > 0 else normalized


def _build_follow_up_conversation_history(
    history: Any,
    user_message: str,
    assistant_response: str,
    limit: int = 12,
) -> List[Dict[str, str]]:
    """Return compact user/assistant history for deterministic and report-backed chat turns."""
    compact_history = _compact_chat_role_history(history, limit=limit, include_system=False)

    cleaned_user_message = str(user_message or "").strip()
    if cleaned_user_message:
        compact_history.append({"role": "user", "content": cleaned_user_message})

    cleaned_response = sanitize_llm_response_text(str(assistant_response or ""))
    if cleaned_response:
        compact_history.append({"role": "assistant", "content": cleaned_response})

    return _compact_chat_role_history(compact_history, limit=limit, include_system=False)


def build_follow_on_actions(
    user_message: str,
    memory: Dict[str, Any],
    tool_calls: Optional[List[Dict[str, Any]]] = None,
    assistant_response: str = "",
) -> List[Dict[str, Any]]:
    """Generate executable, context-aware follow-on action suggestions."""
    actions: List[Dict[str, Any]] = []
    remembered_index = _remembered_entity(memory, "index")
    remembered_host = _remembered_entity(memory, "host")
    last_result = memory.get("last_result", {}) if isinstance(memory, dict) and isinstance(memory.get("last_result", {}), dict) else {}
    earliest_time = str(last_result.get("earliest_time") or "").strip() or "-24h"
    latest_time = str(last_result.get("latest_time") or "").strip() or "now"
    time_window_label = _describe_time_window(earliest_time, latest_time)
    row_count = _safe_int(last_result.get("row_count"))
    effective_assistant_response = str(assistant_response or memory.get("last_assistant_response", ""))
    focus = _detect_conversation_focus(user_message, memory, tool_calls=tool_calls, assistant_response=effective_assistant_response)
    latest_summary = {}
    if tool_calls:
        last_call = next((call for call in reversed(tool_calls) if isinstance(call, dict)), {})
        latest_summary = last_call.get("summary", {}) if isinstance(last_call.get("summary", {}), dict) else {}

    latest_status = str(latest_summary.get("status") or "").strip().lower()
    mission = normalize_mission(memory.get("mission")) if isinstance(memory, dict) else ""
    response_actions = _extract_response_follow_on_actions(effective_assistant_response)

    if tool_calls and latest_status == "error":
        # Re-running a failed search with a wider window or a pivot fails the same way;
        # the useful next step is to repair it or confirm the names it relies on.
        actions.extend(response_actions)
        actions.append(_build_failed_search_follow_on_action(tool_calls, latest_summary))
        if remembered_index:
            actions.append(_make_follow_on_action(
                "List available indexes",
                "List indexes",
                "list_indexes",
            ))
        return _dedupe_follow_on_actions(actions, limit=3)

    latest_has_no_data = bool(tool_calls) and (
        _safe_int(latest_summary.get("row_count")) == 0 or bool(latest_summary.get("zero_counts"))
    )
    output_actions = [] if latest_has_no_data else _build_output_follow_on_actions(
        latest_summary, remembered_index, remembered_host, time_window_label
    )
    focus_actions = _build_focus_follow_on_actions(focus, remembered_index, remembered_host, time_window_label)

    actions.extend(response_actions)

    if output_actions:
        actions.extend(output_actions)
        if focus in {"security", "platform_health", "service_health", "network", "compliance", "recommendations", "top_risks", "coverage_gaps", "use_cases", "readiness"}:
            actions.extend(focus_actions[:1])
    elif not latest_has_no_data:
        actions.extend(focus_actions)

    if tool_calls:
        last_call = tool_calls[-1] if tool_calls else {}
        summary = last_call.get("summary", {}) if isinstance(last_call, dict) else {}
        row_count = _safe_int(summary.get("row_count"))

        if latest_has_no_data:
            wider_window = _wider_time_window_label(earliest_time)
            broaden_prompt = f"Retry the last search over the {wider_window} and tell me whether any relevant data exists."
            if remembered_index:
                broaden_prompt = f"Retry the last search for index={remembered_index} over the {wider_window} and tell me whether any relevant data exists."
            actions.append(_make_follow_on_action("Broaden the time range", broaden_prompt, "broaden_time"))
            if remembered_index:
                actions.append(_make_follow_on_action(
                    f"Baseline index={remembered_index}",
                    f"Run a baseline count check for index={remembered_index} and confirm whether data is available over the last 7 days.",
                    "baseline_index",
                ))
            if remembered_host:
                actions.append(_make_follow_on_action(
                    f"Check last seen for host={remembered_host}",
                    f"When was host={remembered_host} last seen in Splunk?",
                    "last_seen_host",
                ))
        elif row_count > 0 and not actions:
            if remembered_index:
                actions.append(_make_follow_on_action(
                    f"Trend index={remembered_index}",
                    f"Show a timechart of event volume for index={remembered_index} over {time_window_label}.",
                    "timechart_index",
                ))
                actions.append(_make_follow_on_action(
                    f"Break down index={remembered_index}",
                    f"Break down index={remembered_index} by sourcetype and host for {time_window_label}.",
                    "breakdown_index",
                ))
            if remembered_host:
                host_scope = f" within index={remembered_index}" if remembered_index else ""
                actions.append(_make_follow_on_action(
                    f"Investigate host={remembered_host}",
                    f"Pivot on host={remembered_host}{host_scope} and identify related anomalies for {time_window_label}.",
                    "host_pivot",
                ))

    if mission:
        open_goal_items = [
            normalize_mission(item) for item in (memory.get("goal_open_items") or [])
            if isinstance(item, str) and normalize_mission(item)
        ] if isinstance(memory, dict) else []
        if open_goal_items:
            # Progress is judged after this answer, so the question to work on is picked when the prompt is sent,
            # from the goal's open list at that time, rather than named here.
            next_step_prompt = (
                "Based on what we found so far, work on the most important question still open for my goal. "
                "Run the most useful search, then say what it settles and what is still open."
            )
        else:
            next_step_prompt = (
                f"Based on what we found so far, run the next most useful search for my goal: {mission[:200]}. "
                "Then summarize progress and what is still unknown."
            )
        actions.insert(min(2, len(actions)), _make_follow_on_action(
            "Next step for the goal",
            next_step_prompt,
            "advance_mission",
        ))

    if not actions:
        if remembered_index:
            actions.append(_make_follow_on_action(
                "Investigate unusual events",
                f"Show me unusual events in index={remembered_index} over the last 24 hours.",
                "unusual_events",
            ))
        else:
            actions.append(_make_follow_on_action(
                "Ask a focused follow-up",
                "Ask a focused plain-language question about one index, host, or sourcetype for deeper analysis.",
                "generic_follow_up",
            ))

    return _dedupe_follow_on_actions(actions, limit=3)


def _wider_time_window_label(earliest_time: str) -> str:
    earliest = str(earliest_time or "").strip().lower()
    if earliest in {"-30d", "-30d@d", "-1mon", "-1mon@mon"}:
        return "last 90 days"
    if earliest in {"-7d", "-7d@d", "-1w", "-1w@w", "-14d"}:
        return "last 30 days"
    return "last 7 days"


def _build_failed_search_follow_on_action(
    tool_calls: List[Dict[str, Any]],
    latest_summary: Dict[str, Any],
) -> Dict[str, str]:
    last_call = next((call for call in reversed(tool_calls) if isinstance(call, dict)), {})
    args = last_call.get("args", {}) if isinstance(last_call.get("args", {}), dict) else {}
    failed_query = str(args.get("query") or "").strip()
    error_text = re.sub(r"\s+", " ", str(latest_summary.get("message") or "")).strip()
    prompt = "The last Splunk request failed"
    if error_text:
        prompt += f" with this error: {error_text[:240]}"
    prompt += ". Explain the likely cause, correct the request, and run it again."
    if failed_query:
        prompt += f"\n\nFailed search: {failed_query[:400]}"
    return _make_follow_on_action("Fix the failed search", prompt, "repair_failed_search")


def resolve_tool_name(tool_name: str, available_tools: Optional[set] = None) -> str:
    """Resolve a logical/legacy tool name to the best available MCP tool name."""
    available = available_tools or set()
    if tool_name in available:
        return tool_name

    for canonical_name, aliases in MCP_TOOL_ALIASES.items():
        if tool_name == canonical_name or tool_name in aliases:
            for candidate in aliases:
                if candidate in available:
                    return candidate
            return aliases[0]

    return tool_name


def normalize_tool_arguments(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize tool arguments for GA tool signatures while preserving compatibility."""
    normalized = dict(args or {})

    if tool_name in {"splunk_get_info", "get_splunk_info", "splunk_get_user_info", "splunk_get_user_list", "get_user_list"}:
        return {}

    # The GA Splunk MCP server names these arguments index_name and type. When a
    # live input schema is cached, execute_mcp_tool_call adapts names to it.
    if tool_name in {"splunk_get_index_info", "get_index_info"}:
        if "index" in normalized and "index_name" not in normalized:
            normalized["index_name"] = normalized.pop("index")

    if tool_name in {"splunk_get_knowledge_objects", "get_knowledge_objects"}:
        if "object_type" in normalized and "type" not in normalized:
            normalized["type"] = normalized.pop("object_type")

    return normalized


def extract_results_from_mcp_response(tool_response: Dict[str, Any]) -> Dict[str, Any]:
    """Extract normalized result payload from MCP response across GA and legacy shapes."""
    normalized = {
        "results": [],
        "status_code": None,
        "error_message": ""
    }

    if not isinstance(tool_response, dict):
        return normalized

    result_obj = tool_response.get("result", {})
    if not isinstance(result_obj, dict):
        return normalized

    structured = result_obj.get("structuredContent", {})
    if isinstance(structured, dict):
        status_code = structured.get("status_code")
        if isinstance(status_code, int):
            normalized["status_code"] = status_code
        if isinstance(structured.get("content"), str):
            normalized["error_message"] = structured.get("content", "")
        if isinstance(structured.get("results"), list):
            normalized["results"] = structured.get("results", [])
            return normalized

    if isinstance(result_obj.get("results"), list):
        normalized["results"] = result_obj.get("results", [])
        return normalized

    content_items = result_obj.get("content", []) if isinstance(result_obj.get("content", []), list) else []
    if content_items:
        first_item = content_items[0]
        if isinstance(first_item, dict) and isinstance(first_item.get("text"), str):
            text = first_item.get("text", "")
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict) and isinstance(parsed.get("results"), list):
                    normalized["results"] = parsed.get("results", [])
                elif isinstance(parsed, list):
                    normalized["results"] = parsed
            except json.JSONDecodeError:
                pass

    return normalized


def extract_primary_spl_query(tool_calls: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    """Return the most relevant executed SPL query from a tool-call history."""
    if not isinstance(tool_calls, list):
        return None

    for tool_call in reversed(tool_calls):
        if not isinstance(tool_call, dict):
            continue

        spl_query = tool_call.get("spl_query")
        if isinstance(spl_query, str) and spl_query.strip():
            return spl_query.strip()

        args = tool_call.get("args", {})
        if isinstance(args, dict):
            query = args.get("query")
            if isinstance(query, str) and query.strip():
                return query.strip()

    return None


def _capability_is_ready(capability_name: str) -> bool:
    """Return True when an optional capability is installed, enabled, and healthy."""
    try:
        capability_state = capability_manager.get_capability_state(capability_name)
    except Exception:
        return False

    return (
        bool(capability_state.get("installed"))
        and bool(capability_state.get("enabled"))
        and not bool(capability_state.get("restart_required"))
        and str(capability_state.get("health_status") or "").lower() == "ready"
    )


def build_visualization_capability_usage(visualization_spec: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Describe visualization-preview contribution in the normalized capability-usage format."""
    if not isinstance(visualization_spec, dict) or not visualization_spec.get("chart_type"):
        return []

    definition = capability_registry.get_definition("visualization_tools")
    point_count = _safe_int(visualization_spec.get("point_count"))
    chart_type = str(visualization_spec.get("chart_type") or "chart").strip()
    summary_text = str(visualization_spec.get("summary_text") or "").strip()
    if not summary_text:
        summary_text = f"Generated a {chart_type} preview from {point_count or 'several'} plotted values."

    return [
        {
            "name": "visualization_tools",
            "title": definition.title if definition else "Charts",
            "category": definition.category if definition else "tool_pack",
            "used_in": "chat_preview",
            "contribution": summary_text,
            "chunks": [
                {
                    "source": "Splunk query results",
                    "score": 100,
                    "snippet": summary_text,
                    "source_type": "query_result_preview",
                }
            ],
        }
    ]


def extract_primary_visualization(tool_calls: Optional[List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
    """Build or recover the most relevant visualization preview from recent tool calls."""
    if not isinstance(tool_calls, list) or not _capability_is_ready("visualization_tools"):
        return None

    for tool_call in reversed(tool_calls):
        if not isinstance(tool_call, dict):
            continue

        summary = tool_call.get("summary", {}) if isinstance(tool_call.get("summary", {}), dict) else {}
        existing_preview = summary.get("visualization_spec")
        if isinstance(existing_preview, dict) and existing_preview.get("chart_type"):
            return existing_preview

        rows = summary.get("actual_results", []) if isinstance(summary.get("actual_results", []), list) else []
        if not rows:
            continue

        visualization_result = capability_manager.build_visualization(
            "visualization_tools",
            {
                "rows": rows,
                "spl_query": tool_call.get("spl_query") or (tool_call.get("args", {}) if isinstance(tool_call.get("args", {}), dict) else {}).get("query"),
                "query_shape": summary.get("query_shape"),
                "sample_fields": summary.get("sample_fields"),
                "time_bounds": summary.get("time_bounds"),
                "top_dimensions": summary.get("top_dimensions"),
                "numeric_fields": summary.get("numeric_fields"),
                "row_count": summary.get("row_count"),
                "findings": summary.get("findings"),
            },
        )

        if visualization_result.ok:
            visualization_spec = visualization_result.details.get("visualization")
            if isinstance(visualization_spec, dict) and visualization_spec.get("chart_type"):
                summary["visualization_spec"] = visualization_spec
                return visualization_spec

    return None


def augment_capability_usage_with_visualization(
    tool_calls: Optional[List[Dict[str, Any]]],
    capability_usage: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    """Attach visualization contribution metadata when the preview capability contributes."""
    visualization_spec = extract_primary_visualization(tool_calls)
    enriched_usage = list(capability_usage or [])
    if not visualization_spec:
        return None, enriched_usage

    existing_names = {
        str(item.get("name") or "").strip().lower()
        for item in enriched_usage
        if isinstance(item, dict)
    }
    if "visualization_tools" not in existing_names:
        enriched_usage.extend(build_visualization_capability_usage(visualization_spec))

    return visualization_spec, enriched_usage


def detect_latest_entry_index_request(user_message: str) -> Optional[str]:
    """Detect user intent asking for latest/newest entry in a specific index."""
    if not isinstance(user_message, str):
        return None

    message = user_message.strip().lower()
    patterns = [
        r"latest\s+(?:entry|event|record|log\s*entry)\s+(?:in|from)\s+the\s+([a-zA-Z0-9_\-\.]+)\s+index",
        r"latest\s+(?:entry|event|record|log\s*entry)\s+(?:in|from)\s+([a-zA-Z0-9_\-\.]+)\s+index",
        r"newest\s+(?:entry|event|record)\s+(?:in|from)\s+the\s+([a-zA-Z0-9_\-\.]+)\s+index",
        r"what\s+is\s+the\s+latest\s+(?:entry|event|record)\s+(?:in|from)\s+([a-zA-Z0-9_\-\.]+)\s+index"
    ]

    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return None


def detect_edge_processor_template_request(user_message: str) -> bool:
    """Detect user intent asking for edge processor templates."""
    if not isinstance(user_message, str):
        return False
    message = user_message.lower()
    has_template_intent = any(token in message for token in ["template", "templates"])
    has_edge_processor_intent = (
        "edge processor" in message
        or "edge_processor" in message
        or ("edge" in message and "processor" in message)
    )
    return has_template_intent and has_edge_processor_intent


def detect_last_offline_target(user_message: str) -> Optional[str]:
    """Detect user intent asking when an entity (IP/host) was last offline."""
    if not isinstance(user_message, str):
        return None

    message = user_message.strip().lower()
    # Word boundaries keep "breakdown", "download" and "slowdown" from reading as "down".
    offline_wording = re.compile(r"\b(?:offline|down|unreachable)\b")
    if not offline_wording.search(message):
        return None

    patterns = [
        r"last\s+time\s+that\s+([a-zA-Z0-9_\-\.]+)\s+was\s+reported\s+offline",
        r"when\s+was\s+the\s+last\s+time\s+([a-zA-Z0-9_\-\.]+)\s+was\s+offline",
        r"when\s+was\s+([a-zA-Z0-9_\-\.]+)\s+last\s+(?:reported\s+)?offline",
        r"last\s+offline\s+(?:event|time)\s+for\s+([a-zA-Z0-9_\-\.]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()

    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", message)
    if ip_match:
        return ip_match.group(1)

    return None


def _extract_query_terms_for_rag(user_message: str) -> List[str]:
    tokens = re.findall(r"[a-zA-Z0-9_\-\.]{3,}", user_message.lower())
    stopwords = {
        "what", "when", "where", "which", "that", "this", "with", "from", "have", "used",
        "show", "list", "last", "time", "were", "been", "into", "does", "about", "splunk"
    }
    unique = []
    seen = set()
    for token in tokens:
        if token in stopwords:
            continue
        if token not in seen:
            seen.add(token)
            unique.append(token)
    return unique[:10]


def build_lightweight_rag_context(user_message: str, max_chunks: int = 3) -> str:
    """Return optional RAG context through the capability framework."""
    rag_context, _ = get_optional_rag_context(user_message=user_message, max_chunks=max_chunks)
    return rag_context


def build_capability_usage_from_rag_result(rag_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize capability contribution details for UI and persistence."""
    if not isinstance(rag_result, dict):
        return []

    capability_name = str(rag_result.get("capability") or rag_result.get("provider") or "").strip()
    context_text = str(rag_result.get("context_text") or "")
    if not capability_name or not context_text:
        return []

    definition = capability_registry.get_definition(capability_name)
    chunks = rag_result.get("chunks", []) if isinstance(rag_result.get("chunks", []), list) else []
    normalized_chunks = []
    for chunk in chunks[:6]:
        if not isinstance(chunk, dict):
            continue
        source_name = str(chunk.get("source") or chunk.get("file") or "artifact").strip() or "artifact"
        snippet = str(chunk.get("snippet") or "").strip()
        metadata = chunk.get("metadata", {}) if isinstance(chunk.get("metadata", {}), dict) else {}
        normalized_chunks.append(
            {
                "source": source_name,
                "score": _safe_int(chunk.get("score", 0)),
                "snippet": snippet,
                "source_type": str(metadata.get("source_type") or "").strip() or None,
            }
        )

    reusable_queries = rag_result.get("reusable_spl_queries", []) if isinstance(rag_result.get("reusable_spl_queries"), list) else []
    normalized_reusable_queries = []
    for candidate in reusable_queries[:3]:
        if not isinstance(candidate, dict):
            continue
        query = str(candidate.get("query") or "").strip()
        if not query:
            continue
        normalized_reusable_queries.append(
            {
                "title": str(candidate.get("title") or "Saved SPL Query").strip() or "Saved SPL Query",
                "query": query,
                "reuse_tier": str(candidate.get("reuse_tier") or "candidate").strip(),
                "known_good": bool(candidate.get("known_good")),
                "why_reuse": str(candidate.get("why_reuse") or "").strip(),
                "environment_fit_status": str(candidate.get("environment_fit_status") or "").strip() or None,
                "validation_status": str(candidate.get("validation_status") or "").strip() or None,
                "success_count": _safe_int(candidate.get("success_count", 0)),
                "failure_count": _safe_int(candidate.get("failure_count", 0)),
                "app": str(candidate.get("app") or "").strip() or None,
                "earliest": str(candidate.get("earliest") or "").strip() or None,
                "latest": str(candidate.get("latest") or "").strip() or None,
            }
        )

    chunk_count = len(normalized_chunks)
    contribution = (
        f"Added {chunk_count} matching artifact snippet{'s' if chunk_count != 1 else ''} to the LLM prompt context."
        if chunk_count > 0
        else "Added optional capability context to the LLM prompt."
    )
    if normalized_reusable_queries:
        contribution = f"{contribution} Surfaced {len(normalized_reusable_queries)} reusable SPL candidate{'s' if len(normalized_reusable_queries) != 1 else ''}."

    return [
        {
            "name": capability_name,
            "title": definition.title if definition else capability_name,
            "category": definition.category if definition else "capability",
            "used_in": "llm_prompt",
            "contribution": contribution,
            "chunks": normalized_chunks,
            "reusable_queries": normalized_reusable_queries,
        }
    ]


def build_capability_usage_brief(capability_usage: Optional[List[Dict[str, Any]]], limit: int = 2) -> str:
    """Render a brief retrieved-context section for report-backed responses."""
    if not isinstance(capability_usage, list):
        return ""

    lines: List[str] = []
    for usage in capability_usage:
        if not isinstance(usage, dict):
            continue
        reusable_queries = usage.get("reusable_queries", []) if isinstance(usage.get("reusable_queries"), list) else []
        for candidate in reusable_queries[:1]:
            if not isinstance(candidate, dict):
                continue
            query = _compact_memory_text(candidate.get("query"), limit=180)
            if query:
                tier = str(candidate.get("reuse_tier") or "candidate").replace("_", " ")
                lines.append(f"- Reusable SPL ({tier}): {query}")
        if lines:
            break
        chunks = usage.get("chunks", []) if isinstance(usage.get("chunks", []), list) else []
        for chunk in chunks[:limit]:
            if not isinstance(chunk, dict):
                continue
            raw_source = str(chunk.get("source") or "artifact")
            source = raw_source if chunk.get("url") else (Path(raw_source).name or "artifact")
            snippet = _compact_memory_text(chunk.get("snippet"), limit=180)
            if snippet:
                lines.append(f"- {source}: {snippet}")
        if lines:
            break

    if not lines:
        return ""

    return "Indexed context signals:\n" + "\n".join(lines)


LIBRARY_DOCS_USAGE_NAME = "knowledge_library_docs"
MAX_LIBRARY_DOCS_CHAT_PASSAGES = 3


def search_library_docs(query: str, limit: int = 5, min_coverage: float = 0.0) -> List[Dict[str, Any]]:
    """Rank downloaded Splunk documentation passages for a question, favoring the latest discovery's names."""
    try:
        environment = knowledge_library_service.environment_terms(load_latest_v2_blueprint)
        return knowledge_library_service.search_docs(query, limit=limit, environment=environment, min_coverage=min_coverage)
    except Exception as exc:
        print(f"⚠️ [LIBRARY] Documentation search failed: {type(exc).__name__}: {exc}")
        return []


def public_library_doc_result(result: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in result.items() if key not in {"text", "context"}}


def get_library_docs_context(user_message: str, max_chunks: int = 3) -> Tuple[str, List[Dict[str, Any]]]:
    """Return documentation passages for the prompt and their capability usage entry."""
    terms = library_query_terms(user_message)
    if not terms:
        return "", []
    # Questions about the user's own data rarely need documentation, so most of the question must match.
    results = search_library_docs(
        user_message,
        limit=max(1, min(_safe_int(max_chunks) or 3, MAX_LIBRARY_DOCS_CHAT_PASSAGES)),
        min_coverage=0.5 if len(terms) > 1 else 1.0,
    )
    if not results:
        return "", []
    lines = ["📘 SPLUNK DOCUMENTATION (help.splunk.com pages for this environment's versions; cite the link when an answer relies on one):"]
    for index, result in enumerate(results, 1):
        source = " > ".join(part for part in [result.get("group") or result.get("manual"), result.get("label")] if part)
        lines.append(f"{index}. [{source}] {result.get('url')}")
        lines.append(f"   {result.get('context') or result.get('snippet')}")
    count = len(results)
    usage = {
        "name": LIBRARY_DOCS_USAGE_NAME,
        "title": "Splunk documentation",
        "category": "knowledge_library",
        "used_in": "llm_prompt",
        "contribution": f"Added {count} passage{'s' if count != 1 else ''} from the downloaded Splunk documentation to the LLM prompt context.",
        "chunks": [
            {
                "source": " > ".join(part for part in [result.get("group"), result.get("label")] if part) or "Splunk documentation",
                "score": _safe_int(result.get("score")),
                "snippet": str(result.get("snippet") or ""),
                "source_type": "splunk_docs",
                "url": str(result.get("url") or ""),
                "why": [str(item) for item in (result.get("why") or [])[:3]],
            }
            for result in results
        ],
        "reusable_queries": [],
    }
    return "\n".join(lines), [usage]


def get_optional_rag_context(user_message: str, max_chunks: int = 3) -> Tuple[str, List[Dict[str, Any]]]:
    """Return optional RAG context and normalized capability usage details, including downloaded documentation."""
    rag_result = capability_manager.get_rag_context(user_message=user_message, max_chunks=max_chunks)
    context_text = str(rag_result.get("context_text") or "") if isinstance(rag_result, dict) else ""
    capability_usage = build_capability_usage_from_rag_result(rag_result)
    docs_text, docs_usage = get_library_docs_context(user_message, max_chunks=max_chunks)
    if docs_text:
        context_text = f"{context_text}\n\n{docs_text}" if context_text else docs_text
        capability_usage.extend(docs_usage)
    return context_text, capability_usage


def _extract_mcp_result_rows(mcp_response: Any) -> List[Dict[str, Any]]:
    if not isinstance(mcp_response, dict):
        return []
    result = mcp_response.get("result") if isinstance(mcp_response.get("result"), dict) else {}
    structured_content = result.get("structuredContent") if isinstance(result.get("structuredContent"), dict) else {}
    structured_results = structured_content.get("results") if isinstance(structured_content.get("results"), list) else []
    if structured_results:
        return [row for row in structured_results if isinstance(row, dict)]
    direct_results = result.get("results") if isinstance(result.get("results"), list) else []
    return [row for row in direct_results if isinstance(row, dict)]


def maybe_record_rag_spl_query_feedback(
    tool_name: str,
    tool_arguments: Optional[Dict[str, Any]],
    mcp_response: Optional[Dict[str, Any]] = None,
    error_payload: Optional[Dict[str, Any]] = None,
) -> None:
    normalized_tool_name = str(tool_name or "").strip().lower()
    arguments = tool_arguments if isinstance(tool_arguments, dict) else {}
    query = str(arguments.get("query") or "").strip()
    if normalized_tool_name != "splunk_run_query" or not query:
        return

    feedback = {
        "row_count": len(_extract_mcp_result_rows(mcp_response)),
        "earliest_time": str(arguments.get("earliest_time") or "").strip(),
        "latest_time": str(arguments.get("latest_time") or "").strip(),
    }
    status = "success"

    if isinstance(error_payload, dict) and (error_payload.get("error") or error_payload.get("detail")):
        status = "failure"
        feedback["error"] = str(error_payload.get("detail") or error_payload.get("error") or "").strip()
    elif isinstance(mcp_response, dict) and mcp_response.get("error"):
        status = "failure"
        feedback["error"] = str(mcp_response.get("error") or "").strip()

    try:
        capability_manager.record_rag_spl_query_feedback("rag_chromadb", query, status, feedback)
    except Exception as exc:
        debug_log(f"Failed to record SPL query feedback: {exc}", "warning")


def detect_basic_inventory_intent(user_message: str, memory: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Detect common simple or memory-anchored intents that should not rely on LLM tool formatting."""
    if not isinstance(user_message, str):
        return None
    message = user_message.lower()
    explicit_index = extract_index_from_message(user_message)
    explicit_host = extract_host_or_ip_from_message(user_message)
    remembered_index = explicit_index or _remembered_entity(memory or {}, "index")
    remembered_host = explicit_host or _remembered_entity(memory or {}, "host")

    def _mentions(tokens: List[str]) -> bool:
        return any(token in message for token in tokens)

    candidates: List[Tuple[str, bool, List[Optional[str]]]] = [
        ("timechart_index_trend", bool(remembered_index) and _mentions(["timechart", "trend over time", "volume over time", "show trend"]), [remembered_index]),
        ("breakdown_index", bool(remembered_index) and _mentions(["break it down", "breakdown", "break down", "by sourcetype", "by host"]), [remembered_index]),
        ("baseline_index_check", bool(remembered_index) and _mentions(["baseline count", "baseline check", "confirm data availability", "data availability"]), [remembered_index]),
        ("host_pivot", bool(remembered_host) and _mentions(["pivot on host", "investigate host", "related anomalies", "host anomalies"]), [remembered_host, remembered_index]),
        ("list_indexes", _mentions(["list indexes", "show indexes", "what indexes", "available indexes"]), []),
        ("top_indexes", _mentions(["top indexes", "largest indexes", "most active indexes", "indexes by volume", "events by index", "event count by index", "count by index"]), []),
        ("top_errors", _mentions(["top errors", "most errors", "error summary", "error breakdown"]), []),
        ("latest_auth_failures", _mentions(["auth failures", "authentication failures", "failed logins", "login failures"]), []),
        ("count_index_events", bool(explicit_index) and _mentions(["how many events in index", "event count for index", "count events in index", "events in index"]), [explicit_index]),
        ("list_sourcetypes", _mentions(["list sourcetypes", "show sourcetypes", "what sourcetypes"]), []),
        ("list_hosts", _mentions(["list hosts", "show hosts", "what hosts", "active hosts"]), []),
        ("latest_host_heartbeat", bool(explicit_host) and _mentions(["last seen", "latest heartbeat", "last heartbeat", "last event for host", "latest event for host"]), [explicit_host]),
        ("list_templates", "template" in message and "splunk" in message and "edge processor" not in message, []),
    ]
    for route, triggered, anchors in candidates:
        if triggered and _is_plain_route_request(message, route, anchors):
            return route
    return None


_ROUTE_COMMON_WORDS = frozenset(
    (
        "a an the of for in on over to from by and or with within at me my our we us i you please can could would will "
        "show give get tell run do does did is are was were be been what which what's whats there have has got it its "
        "this that these those them same again also just only any all every each data event events index indexes "
        "sourcetype sourcetypes host hosts source sources splunk environment last past previous recent recently during "
        "hour hours day days week weeks month months minute minutes now today yesterday window time range spl "
        "reusable query search"
    ).split()
)
_ROUTE_WORDS: Dict[str, frozenset] = {
    "timechart_index_trend": frozenset("timechart trend trends volume chart graph plot".split()),
    "breakdown_index": frozenset("break breakdown down split group grouped".split()),
    "baseline_index_check": frozenset("baseline check confirm availability available whether exists exist count counts".split()),
    "host_pivot": frozenset("pivot investigate related anomalies anomaly identify unusual".split()),
    "list_indexes": frozenset("list available".split()),
    "top_indexes": frozenset("top largest biggest most active busiest volume count counts".split()),
    "top_errors": frozenset("top most errors error summary breakdown".split()),
    "latest_auth_failures": frozenset("auth authentication failures failure failed logins login latest".split()),
    "count_index_events": frozenset("how many count number total".split()),
    "list_sourcetypes": frozenset("list available".split()),
    "list_hosts": frozenset("list available active sending reporting".split()),
    "latest_host_heartbeat": frozenset("last seen latest heartbeat when".split()),
    "list_templates": frozenset("template templates list available knowledge objects saved searches".split()),
}
_ROUTE_TIME_TOKEN = re.compile(r"^-?\d+[smhdwy]?$")


def _is_plain_route_request(message: str, route: str, anchors: List[Optional[str]]) -> bool:
    """True when the message asks only for what the deterministic ``route`` computes.

    Routes run a fixed search, so a request with extra qualifiers ("break down
    errors by host") must go to the model rather than get an unfiltered answer.
    """
    allowed = _ROUTE_COMMON_WORDS | _ROUTE_WORDS.get(route, frozenset())
    anchor_values = {str(anchor).strip().lower() for anchor in anchors if anchor}
    for raw_token in re.findall(r"[^\s,;?!()]+", message.lower()):
        token = raw_token.strip(".'\"`:")
        if not token or token in allowed or token in anchor_values or _ROUTE_TIME_TOKEN.match(token):
            continue
        key, separator, value = token.partition("=")
        if separator:
            value = value.strip("'\"")
            if key in {"earliest", "latest"}:
                continue
            if key in {"index", "host"} and value in anchor_values:
                continue
        return False
    return True


def should_bypass_basic_inventory_intent(request: Optional[Dict[str, Any]]) -> bool:
    """Allow specialized chat launches to bypass short deterministic inventory routes."""
    if not isinstance(request, dict):
        return False

    investigation_mode = str(request.get("investigation_mode") or "").strip().lower()
    return investigation_mode in {"unknown_entity_context_builder", "context_explorer"}


def extract_index_from_message(user_message: str) -> Optional[str]:
    """Extract index target from natural language."""
    if not isinstance(user_message, str):
        return None
    quoted_name = r"['\"]?([a-zA-Z0-9_][a-zA-Z0-9_.-]*)['\"]?"
    patterns = [
        rf"\bindex\s*[=:]\s*{quoted_name}\b",
        rf"\bindex\s+{quoted_name}(?=\s*(?:\||earliest\s*=|latest\s*=|$))",
        rf"\bin\s+index\s+{quoted_name}\b",
        rf"\bfor\s+index\s+{quoted_name}\b",
        rf"\bin(?:\s+the)?\s+{quoted_name}\s+index\b",
        rf"\bfor(?:\s+the)?\s+{quoted_name}\s+index\b",
        rf"\bfrom(?:\s+the)?\s+{quoted_name}\s+index\b",
        rf"\bthe\s+{quoted_name}\s+index\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, user_message, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def extract_host_or_ip_from_message(user_message: str) -> Optional[str]:
    """Extract host or IPv4 target from natural language."""
    if not isinstance(user_message, str):
        return None
    ip_match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", user_message)
    if ip_match:
        return ip_match.group(0)
    host_match = re.search(r"\bhost\s*[=:]\s*[\"']?([a-zA-Z0-9_][a-zA-Z0-9_\-.]*)", user_message, flags=re.IGNORECASE)
    if host_match:
        return host_match.group(1).strip().rstrip(".") or None
    # Without "=" only accept names that look like hosts (router-01, web1.example.com),
    # so phrases such as "host anomalies" or "hosts" are not read as host names.
    host_match = re.search(r"\bhost\s+[\"']?([a-zA-Z0-9_]*[\d\-.][a-zA-Z0-9_\-.]*)", user_message, flags=re.IGNORECASE)
    if host_match:
        candidate = host_match.group(1).strip().rstrip(".")
        if re.search(r"[a-zA-Z0-9]", candidate):
            return candidate
    return None


def extract_time_range_from_message(user_message: str) -> Tuple[str, str]:
    """Extract a simple relative time range from plain language follow-on prompts."""
    if not isinstance(user_message, str):
        return "", ""

    message = user_message.lower()
    if any(token in message for token in ["last 24 hours", "past 24 hours", "-24h"]):
        return "-24h", "now"
    if any(token in message for token in ["last 7 days", "past 7 days", "last week", "-7d"]):
        return "-7d", "now"
    if any(token in message for token in ["last 30 days", "past 30 days", "last month", "-30d"]):
        return "-30d", "now"
    return "", ""


def parse_tool_call_payload(raw_json: str) -> Optional[Dict[str, Any]]:
    """Parse tool-call payload robustly across JSON and python-like dict styles."""
    if not isinstance(raw_json, str) or not raw_json.strip():
        return None

    payload = raw_json.strip()
    try:
        parsed = json.loads(payload)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    try:
        import ast
        parsed = ast.literal_eval(payload)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    cleaned = re.sub(r",\s*([}\]])", r"\1", payload)
    try:
        parsed = json.loads(cleaned)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return None

    return None


# Local models (notably Llama 3 through Ollama) sometimes leak chat-template tokens
# or open their reply with a bare "assistant" role line.
_CHAT_TEMPLATE_TOKEN_PATTERN = re.compile(
    r'<\|(?:start_header_id|end_header_id|eot_id|im_start|im_end|begin_of_text|end_of_text)\|>'
)
_LEADING_ROLE_LABEL_PATTERN = re.compile(r'\A\s*assistant\s*(?::\s*|\n+)', re.IGNORECASE)


_TOOL_JSON_START_RE = re.compile(r'\{\s*"tool"\s*:')
_TRAILING_CODE_OPENER_RE = re.compile(r'(?:```[A-Za-z]*|`)\s*\Z')


def _find_trailing_tool_call_json(response_text: str) -> Optional[Tuple[int, Dict[str, Any]]]:
    """Find a {"tool": ..., "args": {...}} object that ends the reply, bare or in backticks/a fence.

    Only a call at the very end counts; JSON followed by more prose reads as an example.
    Returns the start offset of the object and the parsed payload.
    """
    if not isinstance(response_text, str) or '"tool"' not in response_text:
        return None
    decoder = json.JSONDecoder()
    for match in _TOOL_JSON_START_RE.finditer(response_text):
        try:
            payload, end = decoder.raw_decode(response_text, match.start())
        except json.JSONDecodeError:
            continue
        if response_text[end:].strip().strip('`').strip():
            continue
        tool = payload.get("tool") if isinstance(payload, dict) else None
        if isinstance(tool, str) and tool.strip() and isinstance(payload.get("args", {}), dict):
            return match.start(), payload
    return None


def sanitize_llm_response_text(text: str) -> str:
    """Remove control markup like TOOL_CALL/CONTEXT_REQUEST from user-facing text."""
    if not isinstance(text, str):
        return ""

    cleaned = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<thinking>.*?</thinking>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<CONTEXT_REQUEST>.*?</CONTEXT_REQUEST>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<TOOL_CALL>.*?</TOOL_CALL>', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r'<TOOL_CALL>.*$', '', cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = cleaned.replace('</TOOL_CALL>', '')
    trailing_call = _find_trailing_tool_call_json(cleaned)
    if trailing_call:
        cleaned = _TRAILING_CODE_OPENER_RE.sub('', cleaned[:trailing_call[0]])
    cleaned = _CHAT_TEMPLATE_TOKEN_PATTERN.sub('', cleaned)
    cleaned = _LEADING_ROLE_LABEL_PATTERN.sub('', cleaned, count=1)
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    return cleaned.strip()


UNSCOPED_SEARCH_NOTE = (
    "Note: the search named no index, so index=* was added; without it Splunk only searches the role's default "
    "indexes. index=* does not include internal indexes such as _internal or _audit, so name those explicitly."
)


def scope_unscoped_chat_search(tool_args: Dict[str, Any]) -> bool:
    """Add index=* to an event search that names no index; True when the query changed."""
    query = tool_args.get("query")
    if not isinstance(query, str) or not query.strip():
        return False
    scoped = scope_spl_to_index(query, "*")
    if scoped == query:
        return False
    tool_args["query"] = scoped
    return True


DEFAULT_DIRECT_CHAT_RESPONSE = "I couldn't generate a complete answer for that request. Please try again."
UNEXECUTED_SEARCH_NUDGE = (
    "You said you would run a search but did not include a TOOL_CALL. If live Splunk data is needed, "
    "reply with only the TOOL_CALL now. Otherwise reply with your final answer."
)
DEFAULT_TOOL_INVESTIGATION_RESPONSE = "Investigation complete. See findings above."


def finalize_user_facing_response_text(text: Any, fallback: str) -> str:
    """Return sanitized assistant text, or a sanitized fallback if nothing user-visible remains."""
    cleaned = sanitize_llm_response_text(str(text or ""))
    if cleaned:
        return cleaned
    return sanitize_llm_response_text(str(fallback or ""))




def resolve_effective_runtime_config(
    request: Optional[Request] = None,
    auth_user: Optional[Dict[str, Any]] = None,
    base_config: Any = None,
) -> Any:
    runtime_config = copy.deepcopy(base_config or config_manager.get())
    resolved_user = auth_user
    if resolved_user is None and request is not None:
        resolved_user = getattr(getattr(request, "state", None), "auth_user", None)

    if not is_auth_enabled() or not isinstance(resolved_user, dict):
        return runtime_config

    assigned_name = str(resolved_user.get("mcp_config_name") or "").strip()
    user_role = str(resolved_user.get("role") or "").strip().lower()
    runtime_role_allows_mcp = user_role in {"admin", "analyst"}
    if assigned_name and runtime_role_allows_mcp:
        assigned_config = config_manager.get_mcp_config(assigned_name)
        if assigned_config is not None:
            runtime_config.mcp.url = assigned_config.url
            runtime_config.mcp.token = assigned_config.token
            runtime_config.mcp.verify_ssl = assigned_config.verify_ssl
            runtime_config.mcp.ca_bundle_path = assigned_config.ca_bundle_path
            runtime_config.active_mcp_config_name = assigned_name
            return runtime_config

        debug_log(
            f"Assigned MCP configuration '{assigned_name}' for user '{resolved_user.get('username')}' was not found; clearing runtime MCP access.",
            "warning",
        )
    elif assigned_name and not runtime_role_allows_mcp:
        debug_log(
            f"Ignoring assigned MCP configuration '{assigned_name}' for user '{resolved_user.get('username')}' because role '{user_role or 'unknown'}' does not allow runtime MCP access.",
            "info",
        )

    if user_role != "admin":
        runtime_config.mcp.url = ""
        runtime_config.mcp.token = ""
        runtime_config.mcp.verify_ssl = False
        runtime_config.mcp.ca_bundle_path = None
        runtime_config.active_mcp_config_name = None
    return runtime_config


def _build_discovery_runtime_binding(
    request: Optional[Request] = None,
    auth_user: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    resolved_user = auth_user
    if resolved_user is None and request is not None:
        resolved_user = getattr(getattr(request, "state", None), "auth_user", None)

    binding = {
        "active_mcp_config_name": None,
        "clear_runtime_mcp": False,
    }

    if not is_auth_enabled() or not isinstance(resolved_user, dict):
        active_name = str(getattr(config_manager.get(), "active_mcp_config_name", "") or "").strip()
        if active_name:
            binding["active_mcp_config_name"] = active_name
        return binding

    assigned_name = str(resolved_user.get("mcp_config_name") or "").strip()
    user_role = str(resolved_user.get("role") or "").strip().lower()
    if assigned_name and user_role in {"admin", "analyst"}:
        binding["active_mcp_config_name"] = assigned_name
        return binding

    if user_role != "admin":
        binding["clear_runtime_mcp"] = True
        return binding

    active_name = str(getattr(config_manager.get(), "active_mcp_config_name", "") or "").strip()
    if active_name:
        binding["active_mcp_config_name"] = active_name
    return binding


def _build_mcp_runtime_identity(config: Any) -> Optional[str]:
    mcp_config = getattr(config, "mcp", None)
    if mcp_config is None:
        return None

    current_url = str(getattr(mcp_config, "url", "") or "").strip()
    if not current_url:
        return None

    token = str(getattr(mcp_config, "token", "") or "")
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest() if token else ""
    verify_ssl = bool(getattr(mcp_config, "verify_ssl", False))
    ca_bundle = str(getattr(mcp_config, "ca_bundle_path", "") or "")
    return f"{current_url}|{token_hash}|{int(verify_ssl)}|{ca_bundle}"


def extract_tool_call_from_text(response_text: str) -> Optional[Dict[str, Any]]:
    """Extract and normalize tool call payload from tagged response text."""
    if not isinstance(response_text, str):
        return None
    if '<TOOL_CALL>' not in response_text or '</TOOL_CALL>' not in response_text:
        return None

    start = response_text.find('<TOOL_CALL>') + len('<TOOL_CALL>')
    end = response_text.find('</TOOL_CALL>', start)
    if end <= start:
        return None

    raw_json = response_text[start:end].strip()
    tool_data = parse_tool_call_payload(raw_json)
    if not isinstance(tool_data, dict):
        return None

    tool_name = tool_data.get('tool')
    if not isinstance(tool_name, str) or not tool_name.strip():
        return None

    tool_args = tool_data.get('args', {})
    if not isinstance(tool_args, dict):
        tool_args = {}

    return {
        "method": "tools/call",
        "params": {
            "name": tool_name.strip(),
            "arguments": tool_args
        }
    }


def _decode_inline_json_string(value: str) -> str:
    """Best-effort decode for partially escaped JSON fragments."""
    if not isinstance(value, str):
        return ""
    try:
        return bytes(value, "utf-8").decode("unicode_escape")
    except Exception:
        return value


def extract_spl_from_response_text(response_text: str) -> Optional[str]:
    """Recover an SPL query from fenced code or simple inline query text."""
    if not isinstance(response_text, str) or not response_text.strip():
        return None

    patterns = [
        r'```spl\s*\n(.*?)```',
        r'```splunk\s*\n(.*?)```',
        r'```(?:\w+)?\s*\n((?:search\s+)?index=.*?)```',
        r'(?mi)^\s*(\|\s*tstats[^\n`]+)\s*$',
        r'(?mi)^\s*((?:search\s+)?index=[^\n`]+(?:\|\s*[^\n`]+)*)\s*$',
        r'(?mi)^\s*(search\s+[^\n`]+(?:\|\s*[^\n`]+)*)\s*$',
        r'(?is)\b(?:spl|query)\s*:\s*((?:search\s+)?index=.*?)(?:\n|$)',
    ]

    for pattern in patterns:
        match = re.search(pattern, response_text, re.DOTALL | re.IGNORECASE)
        if not match:
            continue
        candidate = match.group(1).strip().strip('"').strip("'")
        if candidate:
            return candidate

    return None


def _normalize_extracted_spl_query(candidate: Any) -> str:
    if not isinstance(candidate, str):
        return ""

    normalized_text = str(candidate).replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized_text:
        return ""

    normalized_lines: List[str] = []
    for index, raw_line in enumerate(normalized_text.split("\n")):
        line = raw_line.strip()
        if not line:
            continue
        if index == 0:
            line = re.sub(r"^(?:[-*+]\s+|\d+[.)]\s+)", "", line)
            prefix_match = re.match(r"(?i)^(?:spl(?:[_\s]+query)?|verification[_\s]+spl|query)\s*:\s*(.+)$", line)
            if prefix_match:
                line = prefix_match.group(1).strip()
        normalized_lines.append(line)

    return "\n".join(normalized_lines).strip()


def _looks_like_spl_query_start(candidate: str) -> bool:
    line = _normalize_extracted_spl_query(candidate)
    if not line:
        return False

    return bool(
        re.match(
            r"(?is)^(?:search\s+|index=|\|\s*(?:tstats|mstats|from|inputlookup|metadata|rest|makeresults|dbinspect|walklex|pivot|savedsearch|multisearch|union|set))",
            line,
        )
    )


def _append_extracted_spl_query(results: List[str], seen: set, candidate: Any, max_queries: int = 8) -> None:
    if len(results) >= max_queries:
        return

    normalized_query = _normalize_extracted_spl_query(candidate)
    if not _looks_like_spl_query_start(normalized_query):
        return

    dedupe_key = re.sub(r"\s+", " ", normalized_query).strip().lower()
    if not dedupe_key or dedupe_key in seen:
        return

    seen.add(dedupe_key)
    results.append(normalized_query)


def extract_spl_queries_from_text(text: Any, max_queries: int = 8) -> List[str]:
    """Return distinct SPL queries that are visibly present in a text blob."""
    if not isinstance(text, str) or not text.strip():
        return []

    results: List[str] = []
    seen = set()

    for block_match in re.finditer(r"```(?:\w+)?\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE):
        block_content = block_match.group(1).strip()
        first_line = next((line.strip() for line in block_content.splitlines() if line.strip()), "")
        if _looks_like_spl_query_start(first_line):
            _append_extracted_spl_query(results, seen, block_content, max_queries=max_queries)
        if len(results) >= max_queries:
            return results

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    line_index = 0
    while line_index < len(lines) and len(results) < max_queries:
        stripped_line = lines[line_index].strip()
        candidate_start = _normalize_extracted_spl_query(stripped_line)
        if _looks_like_spl_query_start(candidate_start):
            block_lines = [candidate_start]
            next_index = line_index + 1
            while next_index < len(lines):
                next_line = lines[next_index].strip()
                if not next_line:
                    break
                if next_line.startswith("|"):
                    block_lines.append(next_line)
                    next_index += 1
                    continue
                break
            _append_extracted_spl_query(results, seen, "\n".join(block_lines), max_queries=max_queries)
            line_index = next_index
            continue
        line_index += 1

    return results


def _normalized_spl_query_signature(candidate: Any) -> str:
    normalized_query = _normalize_extracted_spl_query(candidate)
    if not normalized_query:
        return ""
    return re.sub(r"\s+", " ", normalized_query).strip().lower()


def _iter_capability_reusable_queries(capability_usage: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    reusable_queries: List[Dict[str, Any]] = []
    if not isinstance(capability_usage, list):
        return reusable_queries

    for usage in capability_usage:
        if not isinstance(usage, dict):
            continue
        for candidate in usage.get("reusable_queries", []):
            if not isinstance(candidate, dict):
                continue
            query = str(candidate.get("query") or "").strip()
            if query:
                reusable_queries.append(candidate)

    return reusable_queries


def _select_reusable_query_reference(
    capability_usage: Optional[List[Dict[str, Any]]],
    response_text: Any,
    preferred_query: Any = None,
) -> Any:
    reusable_queries = _iter_capability_reusable_queries(capability_usage)
    if not reusable_queries:
        return None, False

    target_signatures: List[str] = []
    preferred_signature = _normalized_spl_query_signature(preferred_query)
    if preferred_signature:
        target_signatures.append(preferred_signature)

    for extracted_query in extract_spl_queries_from_text(response_text, max_queries=3):
        extracted_signature = _normalized_spl_query_signature(extracted_query)
        if extracted_signature and extracted_signature not in target_signatures:
            target_signatures.append(extracted_signature)

    if not target_signatures:
        return None, False

    for target_signature in target_signatures:
        for candidate in reusable_queries:
            candidate_signature = _normalized_spl_query_signature(candidate.get("query"))
            if not candidate_signature:
                continue
            if target_signature == candidate_signature:
                return candidate, False
            if candidate_signature in target_signature or target_signature in candidate_signature:
                return candidate, True

    return None, False


def _build_reusable_query_reference_text(candidate: Dict[str, Any], adapted: bool = False) -> str:
    title = str(candidate.get("title") or "").strip()
    query = str(candidate.get("query") or "").strip()
    if not title:
        compact_query = re.sub(r"\s+", " ", _normalize_extracted_spl_query(query)).strip()
        title = compact_query[:72].rstrip() + "..." if len(compact_query) > 72 else compact_query or "Saved SPL Query"

    qualifiers: List[str] = []
    validation_status = str(candidate.get("validation_status") or "").strip().lower()
    environment_fit_status = str(candidate.get("environment_fit_status") or "").strip().lower()
    success_count = _safe_int(candidate.get("success_count", 0))
    failure_count = _safe_int(candidate.get("failure_count", 0))

    if bool(candidate.get("known_good")) or validation_status == "known_good":
        qualifiers.append("known good")
    elif validation_status:
        qualifiers.append(validation_status.replace("_", " "))

    if environment_fit_status:
        qualifiers.append(f"{environment_fit_status.replace('_', ' ')} fit")

    if success_count or failure_count:
        qualifiers.append(f"{success_count} success / {failure_count} failure")

    qualifier_text = f" ({', '.join(qualifiers)})" if qualifiers else ""
    prefix = "Reusable SPL reference: adapted from" if adapted else "Reusable SPL reference:"
    return f"{prefix} \"{title}\"{qualifier_text}."


def apply_reusable_query_reference_to_response(
    response_text: Any,
    capability_usage: Optional[List[Dict[str, Any]]],
    preferred_query: Any = None,
) -> str:
    cleaned_response = str(response_text or "").strip()
    if not cleaned_response or not isinstance(capability_usage, list):
        return cleaned_response
    if "Reusable SPL reference:" in cleaned_response:
        return cleaned_response

    candidate, adapted = _select_reusable_query_reference(
        capability_usage,
        cleaned_response,
        preferred_query=preferred_query,
    )
    if not isinstance(candidate, dict):
        return cleaned_response

    citation = _build_reusable_query_reference_text(candidate, adapted=adapted)
    if citation.lower() in cleaned_response.lower():
        return cleaned_response
    return f"{citation}\n\n{cleaned_response}"


def _build_reusable_query_candidate_from_asset(asset: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(asset, dict):
        return None

    attributes = asset.get("attributes") if isinstance(asset.get("attributes"), dict) else {}
    query = str(attributes.get("spl_query") or "").strip()
    if not query:
        return None

    intelligence = attributes.get("spl_intelligence") if isinstance(attributes.get("spl_intelligence"), dict) else {}
    environment_fit = intelligence.get("environment_fit") if isinstance(intelligence.get("environment_fit"), dict) else {}
    validation = intelligence.get("validation") if isinstance(intelligence.get("validation"), dict) else {}
    reuse = intelligence.get("reuse") if isinstance(intelligence.get("reuse"), dict) else {}

    validation_status = str(validation.get("status") or "").strip()
    return {
        "title": str(asset.get("title") or "Saved SPL Query").strip() or "Saved SPL Query",
        "query": query,
        "reuse_tier": str(reuse.get("tier") or "candidate").strip() or "candidate",
        "known_good": bool(reuse.get("known_good")) or validation_status == "known_good",
        "why_reuse": str(reuse.get("guidance") or asset.get("description") or "").strip(),
        "environment_fit_status": str(environment_fit.get("status") or "").strip() or None,
        "environment_fit_score": _safe_int(environment_fit.get("score", 0)),
        "validation_status": validation_status or None,
        "success_count": _safe_int(validation.get("success_count", 0)),
        "failure_count": _safe_int(validation.get("failure_count", 0)),
        "app": str(attributes.get("app") or "").strip() or None,
        "earliest": str(attributes.get("earliest") or "").strip() or None,
        "latest": str(attributes.get("latest") or "").strip() or None,
    }


def _find_live_reusable_query_candidate(preferred_query: Any) -> Optional[Dict[str, Any]]:
    preferred_signature = _normalized_spl_query_signature(preferred_query)
    if not preferred_signature:
        return None

    try:
        result = capability_manager.list_rag_assets("rag_chromadb")
    except Exception:
        return None

    if not bool(getattr(result, "ok", False)):
        return None

    assets = result.details.get("assets", []) if isinstance(getattr(result, "details", {}), dict) else []
    exact_matches: List[Dict[str, Any]] = []
    partial_matches: List[Dict[str, Any]] = []

    for asset in assets:
        candidate = _build_reusable_query_candidate_from_asset(asset)
        if not isinstance(candidate, dict):
            continue
        candidate_signature = _normalized_spl_query_signature(candidate.get("query"))
        if not candidate_signature:
            continue
        if candidate_signature == preferred_signature:
            exact_matches.append(candidate)
            continue
        if candidate_signature in preferred_signature or preferred_signature in candidate_signature:
            partial_matches.append(candidate)

    def candidate_rank(candidate: Dict[str, Any]) -> Any:
        return (
            int(bool(candidate.get("known_good"))),
            _safe_int(candidate.get("success_count", 0)) - _safe_int(candidate.get("failure_count", 0)),
            _safe_int(candidate.get("environment_fit_score", 0)),
        )

    if exact_matches:
        return sorted(exact_matches, key=candidate_rank, reverse=True)[0]
    if partial_matches:
        return sorted(partial_matches, key=candidate_rank, reverse=True)[0]
    return None


def _capability_usage_contains_reusable_query(capability_usage: Optional[List[Dict[str, Any]]], query: Any) -> bool:
    query_signature = _normalized_spl_query_signature(query)
    if not query_signature or not isinstance(capability_usage, list):
        return False

    for usage in capability_usage:
        if not isinstance(usage, dict):
            continue
        for candidate in usage.get("reusable_queries", []):
            if not isinstance(candidate, dict):
                continue
            if _normalized_spl_query_signature(candidate.get("query")) == query_signature:
                return True
    return False


def enrich_response_with_live_reusable_query_reference(
    response_text: Any,
    capability_usage: Optional[List[Dict[str, Any]]],
    tool_calls: Optional[List[Dict[str, Any]]],
) -> Any:
    merged_usage = list(capability_usage or []) if isinstance(capability_usage, list) else []
    primary_spl_query = extract_primary_spl_query(tool_calls)
    if primary_spl_query and not _capability_usage_contains_reusable_query(merged_usage, primary_spl_query):
        live_candidate = _find_live_reusable_query_candidate(primary_spl_query)
        if isinstance(live_candidate, dict):
            definition = capability_registry.get_definition("rag_chromadb")
            merged_usage.append(
                {
                    "name": "rag_chromadb",
                    "title": definition.title if definition else "RAG ChromaDB",
                    "category": definition.category if definition else "capability",
                    "used_in": "query_library_match",
                    "contribution": "Matched the executed SPL against the saved SPL library.",
                    "chunks": [],
                    "reusable_queries": [live_candidate],
                }
            )

    return (
        apply_reusable_query_reference_to_response(
            response_text,
            merged_usage,
            preferred_query=primary_spl_query,
        ),
        merged_usage,
    )


def extract_spl_queries_from_payload(payload: Any, max_queries: int = 8) -> List[str]:
    """Return distinct SPL queries from nested report payloads or other structured content."""
    results: List[str] = []
    seen = set()

    def visit(value: Any) -> None:
        if len(results) >= max_queries:
            return
        if isinstance(value, str):
            for query in extract_spl_queries_from_text(value, max_queries=max_queries - len(results)):
                _append_extracted_spl_query(results, seen, query, max_queries=max_queries)
            return
        if isinstance(value, dict):
            for key, nested_value in value.items():
                if len(results) >= max_queries:
                    return
                key_name = str(key or "").strip().lower()
                if key_name in {"spl", "spl_query", "verification_spl", "query"}:
                    _append_extracted_spl_query(results, seen, nested_value, max_queries=max_queries)
                    continue
                visit(nested_value)
            return
        if isinstance(value, list):
            for item in value:
                if len(results) >= max_queries:
                    return
                visit(item)

    visit(payload)
    return results


def user_requested_spl_explanation(user_message: str) -> bool:
    """Return True when the user explicitly asks to explain or understand a query before/while running it."""
    if not isinstance(user_message, str) or not user_message.strip():
        return False

    message = user_message.lower()
    explicit_phrases = [
        "explain this query",
        "explain this spl",
        "understand this query",
        "understand this spl",
        "help me understand this query",
        "help me understand this spl",
        "walk me through this query",
        "walk me through this spl",
        "break down this query",
        "break down this spl",
        "what does this query do",
        "what does this spl do",
    ]
    if any(phrase in message for phrase in explicit_phrases):
        return True

    asks_for_explanation = any(
        phrase in message
        for phrase in ["explain", "understand", "walk me through", "break down", "what does"]
    )
    references_query = any(token in message for token in [" query", " spl", "search ", "|"])
    return asks_for_explanation and references_query


def response_addresses_spl_explanation(response_text: str) -> bool:
    """Heuristic check for whether a response actually explains what the SPL is doing."""
    if not isinstance(response_text, str) or not response_text.strip():
        return False

    text = response_text.lower()
    explanation_anchors = [
        "this query",
        "this spl",
        "the query",
        "the spl",
    ]
    explanation_actions = [
        "searches",
        "filters",
        "limits",
        "groups",
        "counts",
        "calculates",
        "uses",
        "looks for",
        "narrows",
        "aggregates",
        "then it",
        "the first part",
        "the next part",
        "the final part",
        "in plain english",
    ]

    return (
        any(phrase in text for phrase in explanation_anchors)
        and any(phrase in text for phrase in explanation_actions)
    )


def build_spl_explanation_requirement(require_spl_explanation: bool) -> str:
    """Return extra guidance for chat turns that must explain an SPL query."""
    if not require_spl_explanation:
        return ""

    return """\nEXPLANATION REQUIREMENT:
- The user explicitly asked you to explain or help them understand the SPL.
- Your final answer must start with a plain-English explanation of what the SPL is doing.
- Call out the major search terms, filters, pipes, and transforming commands.
- Then summarize what happened when it ran, even if it returned no data or hit an error.
"""


def build_final_user_answer_prompt(
    user_message: str,
    insights_summary: str,
    require_spl_explanation: bool = False,
) -> str:
    """Build the final user-facing answer prompt for post-tool chat responses."""
    if require_spl_explanation:
        instructions = """1. Start by explaining in plain English what the SPL is doing step by step.
2. Call out the major search terms, filters, pipes, and transforming commands.
3. Then summarize what happened when it ran, including specific data/numbers if available.
4. End with any relevant context, caveats, or recommendations."""
    else:
        instructions = """1. Direct answer to their question with the specific numbers and values from the findings
2. What was searched (SPL and time range) and what is still unchecked
3. One or two concrete next steps"""

    return f"""Write the final answer to the user's question: \"{user_message}\"

FINDINGS FROM THE SEARCHES THAT RAN:
{insights_summary}

Provide a COMPLETE, USER-FACING answer that includes:
{instructions}

Use only the findings above and the earlier tool results. A search with zero results only shows that nothing matched that search; do not treat it as proof that a system is healthy or broken. Event totals and index sizes do not show whether data is recent. Do not say you will run more searches; offer them as next steps.
Write as if speaking directly to the user (avoid phrases like \"I investigated\", \"I found\", \"I will\", etc.)."""


def _recover_tool_call_from_tagged_payload(
    response_text: str,
    query_tool_name: str,
    default_earliest: str = "-24h",
    default_latest: str = "now",
) -> Optional[Dict[str, Any]]:
    """Recover a tool call when the tagged JSON payload is malformed but structurally recognizable."""
    if not isinstance(response_text, str) or '<TOOL_CALL>' not in response_text or '</TOOL_CALL>' not in response_text:
        return None

    start = response_text.find('<TOOL_CALL>') + len('<TOOL_CALL>')
    end = response_text.find('</TOOL_CALL>', start)
    if end <= start:
        return None

    raw_payload = response_text[start:end].strip()
    if not raw_payload:
        return None

    tool_match = re.search(r'"tool"\s*:\s*"([^"]+)"', raw_payload)
    tool_name = tool_match.group(1).strip() if tool_match else query_tool_name

    query = None
    query_patterns = [
        r'"query"\s*:\s*"(?P<query>.*?)(?="\s*,\s*"(?:earliest_time|latest_time|row_limit|limit|count)|"\s*\}\s*\}|"\s*\})',
        r"'query'\s*:\s*'(?P<query>.*?)(?='\s*,\s*'(?:earliest_time|latest_time|row_limit|limit|count)|'\s*\}\s*\}|'\s*\})",
    ]
    for pattern in query_patterns:
        query_match = re.search(pattern, raw_payload, re.DOTALL)
        if query_match:
            query = _decode_inline_json_string(query_match.group('query').strip())
            break

    if not query:
        query = extract_spl_from_response_text(raw_payload)

    if not query:
        return None

    earliest_match = re.search(r'"earliest_time"\s*:\s*"([^"]+)"', raw_payload)
    latest_match = re.search(r'"latest_time"\s*:\s*"([^"]+)"', raw_payload)
    row_limit_match = re.search(r'"row_limit"\s*:\s*(\d+)', raw_payload)

    arguments: Dict[str, Any] = {
        "query": query,
        "earliest_time": earliest_match.group(1).strip() if earliest_match else default_earliest,
        "latest_time": latest_match.group(1).strip() if latest_match else default_latest,
    }
    if row_limit_match:
        arguments["row_limit"] = int(row_limit_match.group(1))

    return {
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        }
    }


_TOOL_CALL_OPEN_RE = re.compile(r"<\s*TOOL_CALL\s*>", re.IGNORECASE)


def _extract_unterminated_tool_call(
    response_text: str,
    default_earliest: str = "-24h",
    default_latest: str = "now",
) -> Optional[Dict[str, Any]]:
    """Read a valid JSON payload after <TOOL_CALL> when the closing tag is missing or misspelled."""
    match = _TOOL_CALL_OPEN_RE.search(response_text)
    if not match:
        return None
    remainder = response_text[match.end():].lstrip()
    if not remainder.startswith("{"):
        return None
    try:
        payload, _end = json.JSONDecoder().raw_decode(remainder)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("tool"), str) or not payload["tool"].strip():
        return None
    args = dict(payload.get("args")) if isinstance(payload.get("args"), dict) else {}
    if "query" in args:
        args.setdefault("earliest_time", default_earliest)
        args.setdefault("latest_time", default_latest)
    return {"method": "tools/call", "params": {"name": payload["tool"].strip(), "arguments": args}}


def extract_recoverable_tool_call(
    response_text: str,
    query_tool_name: str,
    default_earliest: str = "-24h",
    default_latest: str = "now",
) -> Optional[Dict[str, Any]]:
    """Recover the next tool call from tagged JSON, malformed tags, or a bare JSON payload.

    A tool-call JSON object that ends the reply also counts, even inside
    backticks or a code fence. SPL that only appears in prose or code fences is
    never turned into a tool call: models routinely show example searches, and
    running those would hit Splunk with queries nobody asked for.
    """
    if not isinstance(response_text, str) or not response_text.strip():
        return None

    extracted = extract_tool_call_from_text(response_text)
    if extracted:
        return extracted

    recovered = _recover_tool_call_from_tagged_payload(
        response_text,
        query_tool_name,
        default_earliest=default_earliest,
        default_latest=default_latest,
    )
    if recovered:
        return recovered

    unterminated = _extract_unterminated_tool_call(response_text, default_earliest, default_latest)
    if unterminated:
        return unterminated

    stripped = response_text.strip()
    if stripped.startswith("{") and 'tool' in stripped:
        payload = parse_tool_call_payload(stripped)
        if isinstance(payload, dict) and isinstance(payload.get('tool'), str):
            args = payload.get('args', {}) if isinstance(payload.get('args', {}), dict) else {}
            if 'query' in args and 'earliest_time' not in args:
                args['earliest_time'] = default_earliest
            if 'query' in args and 'latest_time' not in args:
                args['latest_time'] = default_latest
            return {
                "method": "tools/call",
                "params": {
                    "name": str(payload.get('tool')).strip(),
                    "arguments": args,
                }
            }

    trailing_call = _find_trailing_tool_call_json(response_text)
    if trailing_call:
        payload = trailing_call[1]
        args = dict(payload.get("args") or {})
        if "query" in args:
            args.setdefault("earliest_time", default_earliest)
            args.setdefault("latest_time", default_latest)
        return {"method": "tools/call", "params": {"name": payload["tool"].strip(), "arguments": args}}

    return None


def has_continuation_intent(response_text: str) -> bool:
    """Detect when the model says it will run another step/query but omitted tool-call markup."""
    if not isinstance(response_text, str):
        return False

    lowered = response_text.lower()
    keyword_hits = [
        "let me run a query",
        "let me run",
        "let me query",
        "let me calculate",
        "let me check",
        "i will run",
        "i'll run",
        "i will query",
        "i'll query",
        "i will execute",
        "i'll execute",
        "i will calculate",
        "i'll calculate",
        "i need to calculate",
        "i will first",
        "i'll first",
        "next step"
    ]
    if any(token in lowered for token in keyword_hits):
        return True

    patterns = [
        r"\blet me\s+(run|execute|query|check|calculate|retrieve|search|analyze)\b",
        r"\bi\s+(will|need to)\s+(run|execute|query|check|calculate|retrieve|search|analyze)\b",
        r"\bi(?:'ll)\s+(run|execute|query|check|calculate|retrieve|search|analyze)\b"
    ]
    return any(re.search(pattern, lowered) for pattern in patterns)


def build_compact_chat_prompt(
    query_tool_name: str,
    discovery_context: str,
    rag_context: str,
    memory_context: str,
    available_tools_text: str,
    discovery_age_warning: Optional[str],
    mission: str = "",
    goal_progress: Optional[Dict[str, Any]] = None,
) -> str:
    """Compact, deterministic-first prompt for local and small-context models."""
    mission_block = format_mission_context(mission, goal_progress)
    mission_section = f"\n{mission_block}\n" if mission_block else ""
    return f"""You are a helpful, precise Splunk assistant. You help the user work with their own Splunk data through MCP tools. Prioritize correctness over creativity.
{mission_section}
Context:
{discovery_context}
{rag_context}
{discovery_age_warning or ''}
{memory_context}

Available tools:
{available_tools_text}

Rules:
1) Your primary expertise is Splunk Discovery Tool, Splunk, discovery outputs, optional capabilities, and RAG context.
2) You may answer broader questions directly, but do not claim tool-backed or environment-specific evidence unless it comes from the provided context or executed tools.
3) When a session continuity gate is present, treat the current request as a follow-up unless the user clearly changes topic.
4) For live data requests, make a tool call instead of guessing. Use one tool call per reply and wait for the result.
5) Only use index, sourcetype, and host names from the context or earlier results. Searches must be read-only.
6) If a query returns no data, broaden once (wider time range, fewer filters, or index=* instead of one index at a time). If there is still no data, say so and show what was tried. Zero matches only means nothing matched that search; it does not show that a system is healthy or broken.
7) Answer with the actual numbers from the results, name the SPL and time range you used, and keep it concise.
8) Do not claim all or every host, target, or source is covered unless the results include the expected list; say what was observed instead.
9) Event totals and index sizes do not show whether data is recent. Judge freshness only from latest-event times or time-bounded searches.

Tool call format (required when querying; SPL in code fences is never executed):
<TOOL_CALL>{{"tool": "{query_tool_name}", "args": {{"query": "| tstats count where index=* by index", "earliest_time": "-24h", "latest_time": "now"}}}}</TOOL_CALL>
"""


BASIC_UTILITY_UNIT_TOKENS = (
    "kb",
    "mb",
    "gb",
    "tb",
    "kib",
    "mib",
    "gib",
    "tib",
    "byte",
    "bytes",
    "second",
    "seconds",
    "sec",
    "secs",
    "minute",
    "minutes",
    "min",
    "mins",
    "hour",
    "hours",
    "hr",
    "hrs",
    "day",
    "days",
    "week",
    "weeks",
    "month",
    "months",
    "year",
    "years",
    "percent",
    "percentage",
)

CHAT_SCOPE_PATTERNS = (
    r"\bsplunk\b",
    r"\bdt4sms\b",
    r"\bmcp\b",
    r"\brag\b",
    r"\bartifact(?:s)?\b",
    r"\bknowledge asset(?:s)?\b",
    r"\bcontext preview\b",
    r"\bcapabilit(?:y|ies)\b",
    r"\bdeeplink(?:s)?\b",
    r"\bvisualization(?: tools)?\b",
    r"\bexport(?: tools| bundle| package)?\b",
    r"\bdiscovery(?: artifact| artifacts| report| reports| finding| findings| summary| session| sessions)?\b",
    r"\brunbook(?:s)?\b",
    r"\boperator runbook\b",
    r"\bsearch head\b",
    r"\bforwarder(?:s)?\b",
    r"\bindexer(?:s)?\b",
    r"\bkv store\b",
    r"\bsaved search(?:es)?\b",
    r"\bdata model(?:s)?\b",
    r"\bsourcetype(?:s)?\b",
    r"\blookups?\b",
    r"\bmacros?\b",
    r"\bingestion\b",
    r"\bscheduler\b",
    r"\blicense\b",
    r"\b_internal\b",
    r"\b_audit\b",
    r"\b_introspection\b",
    r"\bwhat can (?:this tool|you) do\b",
    r"\bwhat is (?:this tool|dt4sms) for\b",
    r"\bwhat are you for\b",
    r"\byour purpose\b",
)

CONTEXTUAL_ANALYSIS_TOKENS = (
    "retention",
    "disk",
    "size",
    "status",
    "temperature",
    "temp",
    "alert",
    "alerts",
    "drift",
    "sensor",
    "healthy",
    "online",
    "offline",
    "device",
    "current",
    "right now",
    "volume",
    "count",
    "trend",
    "breakdown",
    "compare",
    "query",
    "search",
    "event",
    "events",
    "host",
    "index",
    "sourcetype",
    "latency",
    "queue",
    "queues",
    "error",
    "errors",
    "failure",
    "failures",
    "exact",
    "estimate",
    "estimated",
    "last seen",
    "spike",
    "spikes",
)

CONTEXTUAL_FOLLOW_UP_PATTERNS = (
    r"\bwhat about\b",
    r"\bhow about\b",
    r"\btell me more\b",
    r"\bgo deeper\b",
    r"\bexpand that\b",
    r"\bdrill into\b",
    r"\bbreak that down\b",
    r"\b(?:that|this|same)\s+(?:index|host|sourcetype|query|search|retention|disk|size|volume|count|trend|breakdown|window)\b",
    r"\b(?:its|their|that|this)\s+(?:retention|disk|size|volume|count|trend|breakdown|last seen|latency|errors|failures)\b",
    r"\b(?:7|14|30|60|90)-?day\b",
)


def is_basic_utility_chat_request(user_message: str) -> bool:
    """Allow simple utility requests without turning chat into a general-purpose assistant."""
    if not isinstance(user_message, str):
        return False

    lowered = re.sub(r"\s+", " ", user_message.lower()).strip()
    if not lowered:
        return False

    if any(token in lowered for token in (
        "splunk",
        "dt4sms",
        "rag",
        "_internal",
        "_audit",
        "_introspection",
        "index=",
        "sourcetype",
        "host=",
        "knowledge asset",
        "capability",
        "ingestion",
    )):
        return False

    expression_candidate = lowered.rstrip(" ?")
    if re.fullmatch(r"(?:what(?:'s| is)\s+)?[-+/*().,%x=0-9\s]+", expression_candidate) and re.search(r"\d", expression_candidate):
        return True

    numeric_count = len(re.findall(r"\b\d+(?:\.\d+)?\b", lowered))
    has_unit_token = any(token in lowered for token in BASIC_UTILITY_UNIT_TOKENS)
    has_utility_keyword = any(re.search(pattern, lowered) for pattern in (
        r"^what(?:'s| is)\b",
        r"\bconvert\b",
        r"\bconversion\b",
        r"\bcalculate\b",
        r"\bmath\b",
        r"\bpercentage\b",
        r"\bpercent\b",
        r"\bdifference\b",
        r"\bsum\b",
        r"\baverage\b",
        r"\bmean\b",
        r"\bmedian\b",
        r"\bmultiply\b",
        r"\bdivide\b",
        r"\bplus\b",
        r"\bminus\b",
        r"\btimes\b",
        r"\bhow many\b",
    ))

    if numeric_count >= 2 and has_utility_keyword:
        return True
    if numeric_count >= 1 and has_unit_token and has_utility_keyword:
        return True
    if has_unit_token and re.match(r"^(what(?:'s| is)?|how many)\b", lowered):
        return True
    return False


def is_contextual_follow_up_for_active_scope(user_message: str, memory: Optional[Dict[str, Any]] = None) -> bool:
    """Allow ambiguous follow-ups to reach the LLM when an active Splunk investigation is already in progress."""
    if not isinstance(user_message, str) or not isinstance(memory, dict):
        return False

    lowered = re.sub(r"\s+", " ", user_message.lower()).strip()
    if not lowered:
        return False

    active_focus = str(memory.get("current_focus") or memory.get("primary_intent") or "").strip().lower()
    entities = memory.get("entities", {}) if isinstance(memory.get("entities", {}), dict) else {}
    has_scope_anchor = (
        active_focus not in {"", "general"}
        or any(entities.get(key) for key in ("indexes", "hosts", "sourcetypes", "sources"))
        or bool(memory.get("last_result"))
    )
    if not has_scope_anchor:
        return False

    has_follow_up_shape = any(re.search(pattern, lowered) for pattern in CONTEXTUAL_FOLLOW_UP_PATTERNS)
    has_analysis_token = any(token in lowered for token in CONTEXTUAL_ANALYSIS_TOKENS)
    memory_anchor_candidates: List[str] = []
    memory_anchor_candidates.extend(
        item for item in memory.get("locations", [])[-6:]
        if isinstance(item, str) and item.strip()
    )
    entities = memory.get("entities", {}) if isinstance(memory.get("entities", {}), dict) else {}
    for key in ("indexes", "hosts", "sourcetypes", "sources"):
        memory_anchor_candidates.extend(
            item for item in entities.get(key, [])[-6:]
            if isinstance(item, str) and item.strip()
        )
    memory_anchor_match = any(
        candidate.lower() in lowered
        for candidate in memory_anchor_candidates
        if isinstance(candidate, str) and len(candidate.strip()) >= 3
    )

    if has_follow_up_shape and has_analysis_token:
        return True

    if memory_anchor_match and (has_analysis_token or len(lowered.split()) <= 10):
        return True

    # Very short analytic follow-ups often omit the noun entirely after a scoped turn.
    if len(lowered.split()) <= 8 and active_focus not in {"", "general"} and has_analysis_token:
        return True

    return False


def is_scope_relevant_chat_request(
    user_message: str,
    report_knowledge: Optional[Dict[str, Any]] = None,
    memory: Optional[Dict[str, Any]] = None,
    report_intent: Optional[str] = None,
) -> bool:
    """Return True when a chat request is within Splunk Discovery Tool or Splunk scope."""
    if not isinstance(user_message, str):
        return False

    if report_intent:
        return True
    if detect_basic_inventory_intent(user_message, memory):
        return True
    if is_contextual_follow_up_for_active_scope(user_message, memory):
        return True
    if detect_latest_entry_index_request(user_message) or detect_last_offline_target(user_message) or detect_edge_processor_template_request(user_message):
        return True
    if extract_index_from_message(user_message) or extract_host_or_ip_from_message(user_message):
        return True

    lowered = user_message.lower()
    if any(re.search(pattern, lowered) for pattern in CHAT_SCOPE_PATTERNS):
        return True

    if isinstance(report_knowledge, dict):
        known_entities = report_knowledge.get("known_entities", {}) if isinstance(report_knowledge.get("known_entities", {}), dict) else {}
        for key in ("indexes", "sourcetypes", "hosts", "sources"):
            if _known_entity_matches(user_message, known_entities.get(key, []), limit=1):
                return True

    return False


def build_scope_redirect_response() -> str:
    """Return a concise reminder that chat is scoped to Splunk Discovery Tool and Splunk work."""
    return (
        "I'm here to help with Splunk Discovery Tool, Splunk investigations, discovery findings, optional capabilities, RAG context, and related operational questions. "
        "Small utility asks like basic math or unit conversions are fine, but this chat is not meant to be a general-purpose AI resource. "
        "Ask me about searches, indexes, sourcetypes, platform health, discovery recommendations, RAG assets, or capability configuration."
    )


def build_scope_redirect_follow_on_actions() -> List[Dict[str, str]]:
    """Provide a few in-scope prompts when chat redirects an unrelated request."""
    return [
        _make_follow_on_action(
            "Explain what this tool covers",
            "What can this tool help me do across Splunk, discovery outputs, capabilities, and the RAG workspace?",
            "scope_redirect",
        ),
        _make_follow_on_action(
            "Check platform health",
            "Check Splunk platform health in _internal, _audit, and _introspection over the last 24 hours and summarize ingestion issues, search failures, and license signals.",
            "scope_redirect",
        ),
        _make_follow_on_action(
            "List available indexes",
            "List the Splunk indexes available in this environment.",
            "scope_redirect",
        ),
    ]


def _discovery_session_manifest_path() -> Path:
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    return output_dir / "discovery_sessions.json"


def _discovery_scope_output_dir(scope_key: Optional[str] = None, *, create: bool = True) -> Path:
    output_dir = Path("output")
    if create:
        output_dir.mkdir(exist_ok=True)

    normalized_scope_key = _normalize_discovery_scope_key(scope_key)
    if normalized_scope_key == DISCOVERY_SCOPE_GLOBAL:
        return output_dir

    scopes_dir = output_dir / "scopes"
    if create:
        scopes_dir.mkdir(parents=True, exist_ok=True)

    encoded_scope = base64.urlsafe_b64encode(normalized_scope_key.encode("utf-8")).decode("ascii").rstrip("=")
    scope_dir = scopes_dir / encoded_scope
    if create:
        scope_dir.mkdir(parents=True, exist_ok=True)
    return scope_dir


def _summary_infographic_dir(scope_key: Optional[str] = None) -> Path:
    return _discovery_scope_output_dir(scope_key) / SUMMARY_INFOGRAPHIC_DIRNAME


def _get_discovery_session_scope_key(session: Optional[Dict[str, Any]]) -> str:
    if not isinstance(session, dict):
        return DISCOVERY_SCOPE_GLOBAL
    return _normalize_discovery_scope_key(session.get("scope_key"))


def _filter_discovery_sessions_by_scope(
    sessions: List[Dict[str, Any]],
    scope_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
    if scope_key is None:
        return list(sessions)

    normalized_scope_key = _normalize_discovery_scope_key(scope_key)
    return [
        session
        for session in sessions
        if _get_discovery_session_scope_key(session) == normalized_scope_key
    ]


def _find_discovery_session_record(
    timestamp: str,
    *,
    scope_key: Optional[str] = None,
    sessions: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    session_list = sessions if isinstance(sessions, list) else load_discovery_sessions(scope_key=scope_key)
    for session in session_list:
        if str(session.get("timestamp") or "") == str(timestamp or ""):
            return session
    return None


def _extract_session_timestamp_from_artifact_name(filename: str) -> Optional[str]:
    safe_name = Path(str(filename or "")).name
    infographic_match = re.match(
        rf"^{SUMMARY_INFOGRAPHIC_PREFIX}(\d{{8}}_\d{{6}})(?:_\d{{8}}_\d{{6}})?\.[A-Za-z0-9]+$",
        safe_name,
    )
    if infographic_match:
        return infographic_match.group(1)

    if safe_name.startswith(SUMMARY_INFOGRAPHIC_PREFIX):
        return None

    generic_matches = re.findall(r"(\d{8}_\d{6})", safe_name)
    if generic_matches:
        return generic_matches[0]
    return None


def _build_artifact_metadata(file_path: Path) -> Dict[str, Any]:
    modified_iso = datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
    size_bytes = file_path.stat().st_size
    artifact_name = file_path.name
    artifact_suffix = file_path.suffix[1:].lower() if file_path.suffix else "unknown"
    artifact_kind = "infographic" if artifact_name.startswith(SUMMARY_INFOGRAPHIC_PREFIX) else "report"
    return {
        "name": artifact_name,
        "path": str(file_path),
        "size": size_bytes,
        "size_bytes": size_bytes,
        "modified": modified_iso,
        "modified_at": modified_iso,
        "type": artifact_suffix,
        "artifact_kind": artifact_kind,
        "session_timestamp": _extract_session_timestamp_from_artifact_name(artifact_name),
    }


def _iter_catalog_artifact_paths(scope_key: Optional[str] = None) -> List[Path]:
    output_dir = _discovery_scope_output_dir(scope_key, create=False)
    artifact_paths: List[Path] = []
    if output_dir.exists():
        artifact_paths.extend(path for path in output_dir.glob("v2_*") if path.is_file())

    infographic_dir = _summary_infographic_dir(scope_key)
    if infographic_dir.exists():
        artifact_paths.extend(
            path
            for path in infographic_dir.glob(f"{SUMMARY_INFOGRAPHIC_PREFIX}*")
            if path.is_file()
            and path.suffix.lower() in IMAGE_ARTIFACT_EXTENSIONS
            and _extract_session_timestamp_from_artifact_name(path.name)
        )

    return sorted(artifact_paths, key=lambda path: path.stat().st_mtime, reverse=True)


def _resolve_output_artifact_path(filename: str, scope_key: Optional[str] = None) -> Path:
    safe_filename = sanitize_filename(filename)
    output_dir = Path("output").resolve()
    scoped_output_dir = _discovery_scope_output_dir(scope_key, create=False)
    candidate_paths = [
        (scoped_output_dir / safe_filename).resolve(),
        (_summary_infographic_dir(scope_key) / safe_filename).resolve(),
    ]
    for candidate in candidate_paths:
        if not candidate.is_relative_to(output_dir):
            continue
        if candidate.exists() and candidate.is_file():
            return candidate
    raise HTTPException(status_code=404, detail="Report not found")


def _resolve_external_catalog_artifact_path(filename: str) -> Path:
    safe_filename = sanitize_filename(filename)
    for candidate in _iter_catalog_artifact_paths():
        if candidate.name == safe_filename:
            return candidate.resolve()
    raise HTTPException(status_code=404, detail="Report not found")


def _find_existing_summary_infographic(timestamp: str, scope_key: Optional[str] = None) -> Optional[Path]:
    safe_timestamp = str(timestamp or "").strip()
    if not safe_timestamp:
        return None

    infographic_dir = _summary_infographic_dir(scope_key)
    if not infographic_dir.exists():
        return None

    matches = sorted(
        infographic_dir.glob(f"{SUMMARY_INFOGRAPHIC_PREFIX}{safe_timestamp}_*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for match in matches:
        if match.is_file() and match.suffix.lower() in IMAGE_ARTIFACT_EXTENSIONS:
            return match
    return None


def _ensure_session_artifact_registered(
    timestamp: str,
    artifact_name: str,
    *,
    scope_key: Optional[str] = None,
) -> None:
    safe_timestamp = str(timestamp or "").strip()
    safe_artifact_name = Path(str(artifact_name or "")).name
    if not safe_timestamp or not safe_artifact_name:
        return
    if _extract_session_timestamp_from_artifact_name(safe_artifact_name) != safe_timestamp:
        return

    normalized_scope_key = _normalize_discovery_scope_key(scope_key)
    sessions = load_discovery_sessions()
    changed = False
    session_record = next(
        (
            session
            for session in sessions
            if str(session.get("timestamp") or "") == safe_timestamp
            and _get_discovery_session_scope_key(session) == normalized_scope_key
        ),
        None,
    )
    if session_record is None:
        session_record = {
            "timestamp": safe_timestamp,
            "scope_key": normalized_scope_key,
            "scope_label": "Global" if normalized_scope_key == DISCOVERY_SCOPE_GLOBAL else normalized_scope_key,
            "active_mcp_config_name": None,
            "created_at": datetime.now().isoformat(),
            "overview": {},
            "report_paths": [],
            "mcp_capabilities": {},
            "stats": {
                "discovery_steps": 0,
                "classification_groups": 0,
                "recommendation_count": 0,
                "suggested_use_case_count": 0,
            },
        }
        sessions.append(session_record)
        changed = True

    report_paths = session_record.setdefault("report_paths", [])
    if safe_artifact_name not in report_paths:
        report_paths.append(safe_artifact_name)
        changed = True

    if changed:
        sessions = sorted(sessions, key=lambda item: str(item.get("timestamp") or ""), reverse=True)
        save_discovery_sessions(sessions[:100])


def _session_has_meaningful_discovery_data(session: Dict[str, Any]) -> bool:
    if not isinstance(session, dict):
        return False

    overview = session.get("overview", {})
    if isinstance(overview, dict) and any(value not in (None, "", [], {}, 0) for value in overview.values()):
        return True

    personas = session.get("personas", {})
    if isinstance(personas, dict) and any(personas.values()):
        return True

    mcp_capabilities = session.get("mcp_capabilities", {})
    if isinstance(mcp_capabilities, dict) and any(mcp_capabilities.values()):
        return True

    readiness_score = session.get("readiness_score")
    if readiness_score not in (None, "", 0):
        return True

    stats = session.get("stats", {})
    if isinstance(stats, dict):
        for value in stats.values():
            try:
                if int(value) > 0:
                    return True
            except (TypeError, ValueError):
                continue

    return False


def _normalize_discovery_sessions(sessions: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], bool]:
    normalized_sessions: List[Dict[str, Any]] = []
    changed = False

    for session in sessions:
        if not isinstance(session, dict):
            changed = True
            continue

        timestamp = str(session.get("timestamp") or "").strip()
        if not timestamp:
            changed = True
            continue

        scope_key = _get_discovery_session_scope_key(session)

        raw_report_paths = session.get("report_paths", [])
        report_paths = raw_report_paths if isinstance(raw_report_paths, list) else []
        clean_report_paths: List[str] = []

        for report_name in report_paths:
            safe_report_name = Path(str(report_name or "")).name
            if not safe_report_name:
                changed = True
                continue
            if _extract_session_timestamp_from_artifact_name(safe_report_name) != timestamp:
                changed = True
                continue
            try:
                _resolve_output_artifact_path(safe_report_name, scope_key=scope_key)
            except HTTPException:
                changed = True
                continue
            if safe_report_name not in clean_report_paths:
                clean_report_paths.append(safe_report_name)
            else:
                changed = True

        normalized_session = dict(session)
        if normalized_session.get("scope_key") != scope_key:
            normalized_session["scope_key"] = scope_key
            changed = True
        normalized_session.setdefault(
            "scope_label",
            "Global" if scope_key == DISCOVERY_SCOPE_GLOBAL else scope_key,
        )
        normalized_session.setdefault("active_mcp_config_name", None)
        if clean_report_paths != report_paths:
            normalized_session["report_paths"] = clean_report_paths
            changed = True

        if not clean_report_paths and not _session_has_meaningful_discovery_data(normalized_session):
            changed = True
            continue

        normalized_sessions.append(normalized_session)

    normalized_sessions.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    if len(normalized_sessions) > 100:
        changed = True
    return normalized_sessions[:100], changed


def _augment_sessions_with_catalog_artifacts(sessions: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], bool]:
    sessions, changed = _normalize_discovery_sessions(sessions)
    sessions_by_identity: Dict[Tuple[str, str], Dict[str, Any]] = {
        (_get_discovery_session_scope_key(session), str(session.get("timestamp") or "")): session
        for session in sessions
        if isinstance(session, dict) and str(session.get("timestamp") or "").strip()
    }

    scopes_to_scan = {
        _get_discovery_session_scope_key(session)
        for session in sessions
        if isinstance(session, dict)
    }
    scopes_to_scan.add(DISCOVERY_SCOPE_GLOBAL)

    for current_scope_key in scopes_to_scan:
        for artifact_path in _iter_catalog_artifact_paths(current_scope_key):
            timestamp = _extract_session_timestamp_from_artifact_name(artifact_path.name)
            if not timestamp:
                continue

            session_identity = (current_scope_key, timestamp)
            session_entry = sessions_by_identity.get(session_identity)
            if session_entry is None:
                if current_scope_key != DISCOVERY_SCOPE_GLOBAL:
                    continue
                session_entry = {
                    "timestamp": timestamp,
                    "scope_key": current_scope_key,
                    "scope_label": "Global",
                    "active_mcp_config_name": None,
                    "created_at": datetime.fromtimestamp(artifact_path.stat().st_mtime).isoformat(),
                    "overview": {},
                    "report_paths": [],
                    "mcp_capabilities": {},
                    "stats": {
                        "discovery_steps": 0,
                        "classification_groups": 0,
                        "recommendation_count": 0,
                        "suggested_use_case_count": 0,
                    },
                }
                sessions.append(session_entry)
                sessions_by_identity[session_identity] = session_entry
                changed = True

            report_paths = session_entry.setdefault("report_paths", [])
            if artifact_path.name not in report_paths:
                report_paths.append(artifact_path.name)
                changed = True

    sessions.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return sessions[:100], changed


def load_discovery_sessions(scope_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load persisted discovery session catalog."""
    manifest_path = _discovery_session_manifest_path()
    if not manifest_path.exists():
        # Backfill from existing report files for legacy runs
        if not Path("output").exists():
            return []

        sessions_by_timestamp: Dict[str, Dict[str, Any]] = {}
        for file_path in _iter_catalog_artifact_paths():
            timestamp = _extract_session_timestamp_from_artifact_name(file_path.name)
            if not timestamp:
                continue
            entry = sessions_by_timestamp.setdefault(timestamp, {
                "timestamp": timestamp,
                "created_at": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                "overview": {},
                "report_paths": [],
                "mcp_capabilities": {},
                "stats": {
                    "discovery_steps": 0,
                    "classification_groups": 0,
                    "recommendation_count": 0,
                    "suggested_use_case_count": 0
                }
            })
            entry["report_paths"].append(file_path.name)

        reconstructed, changed = _augment_sessions_with_catalog_artifacts(
            sorted(sessions_by_timestamp.values(), key=lambda x: x.get("timestamp", ""), reverse=True)
        )
        if reconstructed:
            save_discovery_sessions(reconstructed)
        return _filter_discovery_sessions_by_scope(reconstructed, scope_key)

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            augmented_sessions, changed = _augment_sessions_with_catalog_artifacts(data)
            if changed:
                save_discovery_sessions(augmented_sessions)
            return _filter_discovery_sessions_by_scope(augmented_sessions, scope_key)
    except Exception:
        pass

    return []


def save_discovery_sessions(sessions: List[Dict[str, Any]]) -> None:
    """Persist discovery session catalog."""
    manifest_path = _discovery_session_manifest_path()
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(sessions, f, indent=2)
    except Exception:
        pass


def register_discovery_session(
    timestamp: str,
    overview: Any,
    report_paths: List[str],
    mcp_capabilities: Dict[str, Any],
    classifications: Dict[str, Any],
    recommendations: List[Dict[str, Any]],
    suggested_use_cases: List[Dict[str, Any]],
    discovery_step_count: int,
    personas: Optional[Dict[str, Any]] = None,
    readiness_score: Optional[int] = None,
    discovery_scope: Optional[Dict[str, Any]] = None,
    discovery_quality: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Register a discovery session in manifest for retrieval and UI history."""
    sessions = load_discovery_sessions()
    normalized_scope = copy.deepcopy(discovery_scope) if isinstance(discovery_scope, dict) else {}
    if not normalized_scope:
        normalized_scope = {
            "scope_key": DISCOVERY_SCOPE_GLOBAL,
            "scope_label": "Global",
            "active_mcp_config_name": None,
        }
    scope_key = _normalize_discovery_scope_key(normalized_scope.get("scope_key"))

    session_record = {
        "timestamp": timestamp,
        "scope_key": scope_key,
        "scope_label": normalized_scope.get("scope_label") or ("Global" if scope_key == DISCOVERY_SCOPE_GLOBAL else scope_key),
        "active_mcp_config_name": normalized_scope.get("active_mcp_config_name"),
        "created_at": datetime.now().isoformat(),
        "overview": {
            "total_indexes": getattr(overview, "total_indexes", 0),
            "total_sourcetypes": getattr(overview, "total_sourcetypes", 0),
            "total_hosts": getattr(overview, "total_hosts", 0),
            "total_users": getattr(overview, "total_users", 0),
            "data_volume_24h": _format_data_volume(getattr(overview, "data_volume_24h", None)),
            "splunk_version": getattr(overview, "splunk_version", "unknown")
        },
        "report_paths": report_paths,
        "mcp_capabilities": mcp_capabilities,
        "personas": personas or {},
        "readiness_score": readiness_score if isinstance(readiness_score, int) else 0,
        "discovery_quality": discovery_quality if isinstance(discovery_quality, dict) else {},
        "stats": {
            "discovery_steps": discovery_step_count,
            "classification_groups": len(classifications) if isinstance(classifications, dict) else 0,
            "recommendation_count": len(recommendations) if isinstance(recommendations, list) else 0,
            "suggested_use_case_count": len(suggested_use_cases) if isinstance(suggested_use_cases, list) else 0
        }
    }

    # Replace if same timestamp exists
    sessions = [
        s for s in sessions
        if not (
            s.get("timestamp") == timestamp
            and _get_discovery_session_scope_key(s) == scope_key
        )
    ]
    sessions.insert(0, session_record)
    sessions = sorted(sessions, key=lambda x: x.get("timestamp", ""), reverse=True)
    save_discovery_sessions(sessions[:100])
    return session_record


def _require_accessible_discovery_session(
    timestamp: str,
    *,
    scope_key: Optional[str] = None,
    sessions: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    session = _find_discovery_session_record(timestamp, scope_key=scope_key, sessions=sessions)
    if not isinstance(session, dict):
        raise HTTPException(status_code=404, detail="Discovery session not found")
    return session


def _build_accessible_report_metadata(scope_key: Optional[str] = None) -> List[Dict[str, Any]]:
    sessions = load_discovery_sessions(scope_key=scope_key)
    reports: List[Dict[str, Any]] = []
    seen_names = set()

    for session in sessions:
        session_scope_key = _get_discovery_session_scope_key(session)
        for report_name in session.get("report_paths", []):
            safe_report_name = Path(str(report_name or "")).name
            if not safe_report_name or safe_report_name in seen_names:
                continue
            try:
                report_path = _resolve_output_artifact_path(safe_report_name, session_scope_key)
            except HTTPException:
                continue
            reports.append(_build_artifact_metadata(report_path))
            seen_names.add(safe_report_name)

    reports.sort(key=lambda item: str(item.get("modified") or ""), reverse=True)
    return reports


def _resolve_accessible_output_artifact_path(filename: str, scope_key: Optional[str] = None) -> Path:
    safe_filename = sanitize_filename(filename)
    sessions = load_discovery_sessions(scope_key=scope_key)
    for session in sessions:
        report_paths = session.get("report_paths", []) if isinstance(session.get("report_paths", []), list) else []
        if safe_filename not in report_paths:
            continue
        return _resolve_output_artifact_path(safe_filename, _get_discovery_session_scope_key(session))
    raise HTTPException(status_code=404, detail="Report not found")


def _safe_int(value: Any) -> int:
    """Convert scalar-like values to int without raising."""
    try:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            cleaned = value.replace(",", "").strip()
            return int(float(cleaned))
    except Exception:
        pass
    return 0


def _normalize_context_anchor_type(anchor_type: Any) -> str:
    normalized = str(anchor_type or "").strip().lower()
    if normalized in {"sourcetype", "host"}:
        return normalized
    return "index"


def _format_context_volume_label(value: Any) -> str:
    cleaned = str(value or "unknown").replace("_", " ").strip()
    if not cleaned:
        cleaned = "unknown"
    return cleaned[:1].upper() + cleaned[1:]


def _dedupe_context_tags(*tag_groups: Any, limit: int = 12) -> List[str]:
    tags: List[str] = []
    seen = set()
    for group in tag_groups:
        if isinstance(group, list):
            raw_items = group
        else:
            raw_items = [group]
        for item in raw_items:
            cleaned = re.sub(r"\s+", " ", str(item or "").strip())
            if not cleaned:
                continue
            normalized = cleaned.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            tags.append(cleaned)
            if len(tags) >= limit:
                return tags
    return tags


def _build_context_query_focus_payload(
    title: str,
    category: str,
    categories: List[str],
    finding_reference: str,
    environment_evidence: List[str],
    source_label: str,
    description: str,
    generated_queries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "title": title,
        "category": category,
        "categories": categories,
        "findingReference": finding_reference,
        "environmentEvidence": environment_evidence,
        "sourceLabel": source_label,
        "description": description,
        "generatedQueries": generated_queries,
    }


def _build_context_task_focus_payload(title: str, task_filter: str, risk_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "title": title,
        "taskFilter": str(task_filter or "all"),
    }
    if isinstance(risk_data, dict) and risk_data:
        payload["domain"] = str(risk_data.get("domain") or "general")
        payload["riskData"] = risk_data
    return payload


def _build_context_asset_import_payload(
    *,
    title: str,
    asset_type: str,
    description: str,
    tags: List[str],
    session_id: Optional[str],
    content_sections: List[Tuple[str, str]],
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    content_lines = [
        "Saved discovery-summary context for reuse in the managed context library and follow-on chat workflows.",
    ]
    if session_id:
        content_lines.append(f"Session: {session_id}")

    for heading, body in content_sections:
        normalized_heading = str(heading or "").strip()
        normalized_body = str(body or "").strip()
        if not normalized_heading or not normalized_body:
            continue
        content_lines.extend(["", f"## {normalized_heading}", normalized_body])

    return {
        "title": str(title or "Discovery Context").strip() or "Discovery Context",
        "content": "\n".join(content_lines),
        "asset_type": str(asset_type or "reference_document").strip() or "reference_document",
        "source_label": "Discovery Summary Context Explorer",
        "description": str(description or "Saved discovery summary context for follow-on chat and library reuse.").strip(),
        "tags": _dedupe_context_tags(tags, ["summary-context", "context-explorer"]),
        "attributes": dict(attributes or {}),
    }


def _build_context_explorer_queries(anchor_type: str, item: Dict[str, Any]) -> List[Dict[str, Any]]:
    resolved_anchor_type = _normalize_context_anchor_type(anchor_type)
    anchor_name = str(item.get("name") or "").strip()
    if not anchor_name:
        return []

    search_anchor = f"{resolved_anchor_type}={anchor_name}"
    evidence = [f"{resolved_anchor_type}:{anchor_name}"]
    priority = "🔴 HIGH" if resolved_anchor_type == "index" else "🟠 MEDIUM"
    breakdown_fields = "sourcetype host" if resolved_anchor_type == "index" else "index host" if resolved_anchor_type == "sourcetype" else "index sourcetype"
    trend_field = "sourcetype" if resolved_anchor_type == "index" else "index" if resolved_anchor_type == "sourcetype" else "sourcetype"

    return [
        {
            "title": f"🔎 {anchor_name} Context Snapshot",
            "description": f"Profile {search_anchor} so an operator can quickly see where it shows up and how much signal it carries.",
            "use_case": "Data Quality",
            "category": "Data Quality",
            "spl": f"{search_anchor} earliest=-24h | stats count by {breakdown_fields} | sort - count | head 20",
            "finding_reference": f"Context explorer anchor for {search_anchor}",
            "execution_time": "< 30s",
            "business_value": "Shows the immediate shape and spread of this anchor before you decide on monitoring or ownership.",
            "priority": priority,
            "difficulty": "Beginner",
            "environment_evidence": evidence,
            "query_source": "context_engine",
        },
        {
            "title": f"📈 {anchor_name} Activity Trend",
            "description": f"Trend {search_anchor} over time to identify whether it is stable, bursty, or drifting.",
            "use_case": "Performance Monitoring",
            "category": "Infrastructure & Performance",
            "spl": f"{search_anchor} earliest=-7d | timechart span=1h count by {trend_field} limit=10 useother=true",
            "finding_reference": f"Trend exploration for {search_anchor}",
            "execution_time": "< 45s",
            "business_value": "Helps determine whether this anchor deserves coverage or more targeted alerting.",
            "priority": priority,
            "difficulty": "Intermediate",
            "environment_evidence": evidence,
            "query_source": "context_engine",
        },
        {
            "title": f"🧪 {anchor_name} Sample Events",
            "description": f"Pull a small sample from {search_anchor} so the operator can inspect representative events directly.",
            "use_case": "Data Exploration",
            "category": "Data Quality",
            "spl": f"{search_anchor} earliest=-24h | head 20 | table _time index sourcetype host source",
            "finding_reference": f"Sample event triage for {search_anchor}",
            "execution_time": "< 15s",
            "business_value": "Speeds up fast human classification before creating tasks or controls.",
            "priority": priority,
            "difficulty": "Beginner",
            "environment_evidence": evidence,
            "query_source": "context_engine",
        },
    ]


def _build_context_explorer_chat_prompt(anchor_type: str, item: Dict[str, Any]) -> str:
    resolved_anchor_type = _normalize_context_anchor_type(anchor_type)
    anchor_name = str(item.get("name") or "").strip()
    generated_queries = _build_context_explorer_queries(resolved_anchor_type, item)
    if not anchor_name or not generated_queries:
        return ""

    search_anchor = f"{resolved_anchor_type}={anchor_name}"
    starter_queries = "\n".join([f"{idx + 1}. {query['spl']}" for idx, query in enumerate(generated_queries)])
    volume_signal = (
        f"{_safe_int(item.get('events')).__format__(',')} observed events in discovery."
        if item.get("events") is not None
        else "Use the first query to determine current volume and spread."
    )
    size_mb = item.get("size_mb")
    size_signal = ""
    try:
        if size_mb not in (None, ""):
            size_signal = f"Approximate indexed size: {float(size_mb):.1f} MB."
    except Exception:
        size_signal = ""

    return "\n".join([
        f"Build operational context for {search_anchor} within this discovery session.",
        "",
        f"Use the exact entity anchor {search_anchor}. Do not substitute another {resolved_anchor_type} name.",
        f"Anchor type: {resolved_anchor_type}",
        f"Name: {anchor_name}",
        volume_signal,
        size_signal,
        "",
        "Start by executing one or more of these exact SPL queries before broadening the investigation:",
        starter_queries,
        "",
        "Return:",
        "1. What this anchor most likely represents in the environment",
        "2. Which related indexes, sourcetypes, or hosts stand out",
        "3. What monitoring, ownership, or validation should happen next",
    ]).strip()


def _build_unknown_entity_validation_queries(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    entity_type = "sourcetype" if str(item.get("type") or "").lower() == "sourcetype" else "index"
    entity_name = str(item.get("name") or "").strip()
    if not entity_name:
        return []

    search_anchor = f"index={entity_name}" if entity_type == "index" else f"index=* sourcetype={entity_name}"
    breakout_fields = "sourcetype host" if entity_type == "index" else "index host"
    trend_field = "sourcetype" if entity_type == "index" else "index"
    entity_label = f"index={entity_name}" if entity_type == "index" else f"sourcetype={entity_name}"
    priority = "🔴 HIGH" if bool((item.get("context") or {}).get("has_significant_data")) else "🟠 MEDIUM"
    finding_reference = str(item.get("question") or f"Classify and validate {entity_name} before it becomes an unmanaged blind spot.").strip()
    business_value = (
        f"Shows whether {entity_name} is an active data set, what sources feed it, and which hosts are contributing telemetry."
        if entity_type == "index"
        else f"Shows where sourcetype {entity_name} is present and whether it represents a meaningful operational or security signal."
    )

    return [
        {
            "title": f"🧭 {entity_name} Footprint by {'Sourcetype and Host' if entity_type == 'index' else 'Index and Host'}",
            "description": f"Establish the basic coverage and volume profile for {entity_label} before deciding how it should be classified.",
            "use_case": "Data Quality",
            "category": "Data Quality",
            "spl": f"{search_anchor} earliest=-24h | stats count by {breakout_fields} | sort - count",
            "finding_reference": finding_reference,
            "execution_time": "< 30s",
            "business_value": business_value,
            "priority": priority,
            "difficulty": "Beginner",
            "environment_evidence": [entity_label],
            "query_source": "context_engine",
        },
        {
            "title": f"📈 {entity_name} Activity Trend",
            "description": f"Trend {entity_label} over time so you can tell whether it is steady, bursty, or mostly dormant.",
            "use_case": "Data Quality",
            "category": "Data Quality",
            "spl": f"{search_anchor} earliest=-7d | timechart span=1h count by {trend_field} limit=10 useother=true",
            "finding_reference": finding_reference,
            "execution_time": "< 30s",
            "business_value": "Shows whether the entity is stable enough to warrant monitoring coverage or onboarding work.",
            "priority": priority,
            "difficulty": "Intermediate",
            "environment_evidence": [entity_label],
            "query_source": "context_engine",
        },
        {
            "title": f"🔎 {entity_name} Sample Event Triage",
            "description": f"Pull a small sample so an operator can quickly inspect what this entity actually contains.",
            "use_case": "Data Quality",
            "category": "Data Quality",
            "spl": f"{search_anchor} earliest=-24h | head 20 | table _time index sourcetype host source",
            "finding_reference": finding_reference,
            "execution_time": "< 15s",
            "business_value": "Provides fast human inspection of representative events before creating dashboards or detections.",
            "priority": priority,
            "difficulty": "Beginner",
            "environment_evidence": [entity_label],
            "query_source": "context_engine",
        },
    ]


def _build_unknown_entity_validation_chat_prompt(item: Dict[str, Any]) -> str:
    entity_type = "sourcetype" if str(item.get("type") or "").lower() == "sourcetype" else "index"
    entity_name = str(item.get("name") or "").strip()
    generated_queries = _build_unknown_entity_validation_queries(item)
    if not entity_name or not generated_queries:
        return ""

    entity_label = f"index={entity_name}" if entity_type == "index" else f"sourcetype={entity_name}"
    suggestions = item.get("suggestions") if isinstance(item.get("suggestions"), list) else []
    likely_categories = ", ".join([str(suggestion.get("label") or "").strip() for suggestion in suggestions[:3] if isinstance(suggestion, dict) and str(suggestion.get("label") or "").strip()]) or "unknown"
    starter_queries = "\n".join([f"{idx + 1}. {query['spl']}" for idx, query in enumerate(generated_queries)])
    question = str(item.get("question") or "Classify this entity and determine what it contains.").strip()
    context = item.get("context") if isinstance(item.get("context"), dict) else {}
    volume_signal = _format_context_volume_label(context.get("volume_category"))
    significance_note = "This entity already appears to have significant data." if bool(context.get("has_significant_data")) else "This entity may still be low-signal or poorly understood."

    return "\n".join([
        f"Build context for this unclear Splunk {entity_type} and decide whether it is expected, important, and worth monitoring coverage.",
        "",
        f"Use the exact entity anchor {entity_label}. Do not substitute another {entity_type} name.",
        f"Name: {entity_name}",
        f"Question: {question}",
        f"Likely categories: {likely_categories}",
        f"Volume signal: {volume_signal}",
        significance_note,
        "",
        "Start by executing one or more of these exact SPL queries, then improve or branch from them only if the results justify it:",
        starter_queries,
        "",
        "Return:",
        "1. What this entity most likely contains",
        "2. Whether it looks expected or risky",
        "3. What monitoring, ownership, or validation should happen next",
    ]).strip()


def _get_risk_task_filter_key(risk: Dict[str, Any]) -> str:
    risk_text = " ".join([
        str(risk.get("domain") or ""),
        str(risk.get("risk") or ""),
        str(risk.get("impact") or ""),
        str(risk.get("mitigation") or ""),
    ]).lower()

    if any(token in risk_text for token in ("security", "authentication", "privilege")):
        return "category:Security"
    if any(token in risk_text for token in ("data quality", "freshness", "clock skew", "timestamp")):
        return "category:Data Quality"
    if any(token in risk_text for token in ("ingestion", "collector", "pipeline", "configuration")):
        return "category:Configuration"
    if any(token in risk_text for token in ("performance", "platform", "health", "availability", "latency", "throughput", "infrastructure", "application")):
        return "category:Performance"
    domain = str(risk.get("domain") or "").strip()
    if domain:
        return f"category:{domain}"
    return "open"


def _get_task_query_categories(task: Dict[str, Any]) -> List[str]:
    category = str(task.get("category") or "").strip()
    if category in {"Security", "Compliance"}:
        return ["Security & Compliance"]
    if category == "Performance":
        return ["Infrastructure & Performance", "Capacity Planning"]
    if category == "Data Quality":
        return ["Data Quality", "Data Exploration"]
    if category == "Configuration":
        return ["Infrastructure & Performance", "Data Quality"]
    return []


def _build_context_launch_action(label: str, prompt: str, tone: str = "slate", investigation_mode: str = "context_explorer") -> Dict[str, Any]:
    return {
        "kind": "launch_chat",
        "label": label,
        "icon": "fa-comments",
        "tone": tone,
        "prompt": prompt,
        "launchOptions": {
            "freshContext": True,
            "investigationMode": investigation_mode,
        },
    }


def _build_context_query_action(label: str, query_focus: Dict[str, Any], tone: str = "indigo") -> Dict[str, Any]:
    return {
        "kind": "focus_queries",
        "label": label,
        "icon": "fa-code",
        "tone": tone,
        "queryFocus": query_focus,
    }


def _build_context_task_action(label: str, task_focus: Dict[str, Any], tone: str = "emerald") -> Dict[str, Any]:
    return {
        "kind": "focus_tasks",
        "label": label,
        "icon": "fa-list-check",
        "tone": tone,
        "taskFocus": task_focus,
    }


def _build_context_save_action(label: str, asset_import: Dict[str, Any], tone: str = "slate") -> Dict[str, Any]:
    asset_title = str(asset_import.get("title") or "context asset").strip()
    return {
        "kind": "save_context_asset",
        "label": label,
        "icon": "fa-book-open",
        "tone": tone,
        "assetImport": asset_import,
        "successMessage": f"Saved {asset_title} to the context library.",
        "errorMessage": f"Failed to save {asset_title} to the context library.",
    }


def _build_context_anchor_actions(anchor_type: str, item: Dict[str, Any], session_id: Optional[str], readiness_score: int) -> List[Dict[str, Any]]:
    resolved_anchor_type = _normalize_context_anchor_type(anchor_type)
    anchor_name = str(item.get("name") or "").strip()
    if not anchor_name:
        return []

    search_anchor = f"{resolved_anchor_type}={anchor_name}"
    generated_queries = _build_context_explorer_queries(resolved_anchor_type, item)
    chat_prompt = _build_context_explorer_chat_prompt(resolved_anchor_type, item)
    focus_payload = _build_context_query_focus_payload(
        title=f"{anchor_name} Context Explorer",
        category="Data Quality",
        categories=["Data Quality", "Infrastructure & Performance"],
        finding_reference=f"Context explorer for {search_anchor}",
        environment_evidence=[f"{resolved_anchor_type}:{anchor_name}"],
        source_label="Focused From Context Explorer",
        description=f"Showing discovery-aligned context queries for {search_anchor} so you can classify, validate, and route follow-up work without leaving exec-control.",
        generated_queries=generated_queries,
    )
    events = _safe_int(item.get("events"))
    size_mb = item.get("size_mb")
    signal_lines = [
        f"Anchor type: {resolved_anchor_type}",
        f"Name: {anchor_name}",
        f"Observed events: {events:,}" if events else "Observed events: unknown",
        f"Session readiness score: {readiness_score}" if readiness_score else "Session readiness score: unknown",
    ]
    try:
        if size_mb not in (None, ""):
            signal_lines.append(f"Approximate indexed size: {float(size_mb):.1f} MB")
    except Exception:
        pass
    if str(item.get("max_time") or "").strip():
        signal_lines.append(f"Latest observed time: {str(item.get('max_time') or '').strip()}")
    query_blocks = []
    for query in generated_queries:
        query_blocks.extend([f"### {query.get('title')}", f"```spl\n{query.get('spl')}\n```"])
    asset_import = _build_context_asset_import_payload(
        title=f"Discovery Context: {search_anchor}",
        asset_type="monitored_system_context" if resolved_anchor_type == "host" else "reference_document",
        description=f"Saved summary context for {search_anchor} with discovery-aligned investigation prompts and starter SPL.",
        tags=[resolved_anchor_type, anchor_name, search_anchor, "discovery-summary"],
        session_id=session_id,
        content_sections=[
            ("Signal", "\n".join(signal_lines)),
            ("Investigation Prompt", chat_prompt),
            ("Suggested Queries", "\n\n".join(query_blocks)),
        ],
        attributes={
            "origin_kind": "summary_context_anchor",
            "origin_label": "Summary Context Explorer",
            "session_id": session_id or "",
            "anchor_type": resolved_anchor_type,
            "anchor_name": anchor_name,
        },
    )
    return [
        _build_context_launch_action("Explore in Chat", chat_prompt, tone="cyan"),
        _build_context_query_action("Open Queries", focus_payload, tone="indigo"),
        _build_context_save_action("Save to Context Library", asset_import, tone="slate"),
    ]


def _build_unknown_entity_actions(item: Dict[str, Any], session_id: Optional[str], readiness_score: int) -> List[Dict[str, Any]]:
    entity_type = "sourcetype" if str(item.get("type") or "").lower() == "sourcetype" else "index"
    entity_name = str(item.get("name") or "").strip()
    if not entity_name:
        return []

    generated_queries = _build_unknown_entity_validation_queries(item)
    chat_prompt = _build_unknown_entity_validation_chat_prompt(item)
    entity_label = f"index={entity_name}" if entity_type == "index" else f"sourcetype={entity_name}"
    focus_payload = _build_context_query_focus_payload(
        title=f"{entity_name} Context Builder",
        category="Data Quality",
        categories=["Data Quality"],
        finding_reference=str(item.get("question") or f"Build context for {entity_label}").strip(),
        environment_evidence=[entity_label],
        source_label="Focused From Context Explorer",
        description=f"Showing discovery-aligned validation queries for {entity_label} so you can classify it before it becomes an unmanaged blind spot.",
        generated_queries=generated_queries,
    )
    suggestions = item.get("suggestions") if isinstance(item.get("suggestions"), list) else []
    suggestion_labels = [str(suggestion.get("label") or "").strip() for suggestion in suggestions[:4] if isinstance(suggestion, dict) and str(suggestion.get("label") or "").strip()]
    context = item.get("context") if isinstance(item.get("context"), dict) else {}
    asset_import = _build_context_asset_import_payload(
        title=f"Discovery Context: {entity_label}",
        asset_type="reference_document",
        description=f"Saved summary context for {entity_label} with validation prompts and starter SPL.",
        tags=[entity_type, entity_name, entity_label, "unknown-entity", "discovery-summary"],
        session_id=session_id,
        content_sections=[
            ("Signal", "\n".join([
                f"Entity type: {entity_type}",
                f"Name: {entity_name}",
                f"Question: {str(item.get('question') or 'Needs classification.').strip()}",
                f"Volume signal: {_format_context_volume_label(context.get('volume_category'))}",
                "Significant data observed: yes" if bool(context.get("has_significant_data")) else "Significant data observed: no",
                f"Session readiness score: {readiness_score}" if readiness_score else "Session readiness score: unknown",
                f"Likely categories: {', '.join(suggestion_labels)}" if suggestion_labels else "Likely categories: unknown",
            ])),
            ("Investigation Prompt", chat_prompt),
            ("Suggested Queries", "\n\n".join([f"### {query.get('title')}\n```spl\n{query.get('spl')}\n```" for query in generated_queries])),
        ],
        attributes={
            "origin_kind": "summary_context_unknown_entity",
            "origin_label": "Summary Context Explorer",
            "session_id": session_id or "",
            "anchor_type": entity_type,
            "anchor_name": entity_name,
        },
    )
    return [
        _build_context_launch_action("Build Context in Chat", chat_prompt, tone="indigo", investigation_mode="unknown_entity_context_builder"),
        _build_context_query_action("Open Queries", focus_payload, tone="slate"),
        _build_context_save_action("Save to Context Library", asset_import, tone="slate"),
    ]


def _build_risk_actions(risk: Dict[str, Any], session_id: Optional[str], readiness_score: int) -> List[Dict[str, Any]]:
    risk_title = str(risk.get("risk") or "Operational risk").strip() or "Operational risk"
    chat_prompt = "\n".join([
        "Help me build context around this risk and decide what evidence to collect next.",
        "",
        f"Risk: {risk_title}",
        f"Impact: {str(risk.get('impact') or '').strip()}",
        f"Mitigation: {str(risk.get('mitigation') or '').strip()}",
    ]).strip()
    asset_import = _build_context_asset_import_payload(
        title=f"Discovery Risk Context: {risk_title}",
        asset_type="runbook_context",
        description=f"Saved summary context for the risk '{risk_title}' with recommended follow-up evidence collection.",
        tags=[str(risk.get("domain") or "general").strip() or "general", "risk", "discovery-summary"],
        session_id=session_id,
        content_sections=[
            ("Risk", "\n".join([
                f"Severity: {str(risk.get('severity') or 'medium').strip()}",
                f"Domain: {str(risk.get('domain') or 'general').strip()}",
                f"Risk: {risk_title}",
                f"Impact: {str(risk.get('impact') or '').strip()}",
                f"Mitigation: {str(risk.get('mitigation') or '').strip()}",
                f"Session readiness score: {readiness_score}" if readiness_score else "Session readiness score: unknown",
            ])),
            ("Investigation Prompt", chat_prompt),
        ],
        attributes={
            "origin_kind": "summary_context_risk",
            "origin_label": "Summary Context Explorer",
            "session_id": session_id or "",
            "risk_domain": str(risk.get("domain") or "").strip(),
            "risk_title": risk_title,
        },
    )
    return [
        _build_context_task_action(
            "Open Control Path",
            _build_context_task_focus_payload(risk_title, _get_risk_task_filter_key(risk), risk_data=risk),
            tone="red",
        ),
        _build_context_launch_action("Investigate in Chat", chat_prompt, tone="slate"),
        _build_context_save_action("Save to Context Library", asset_import, tone="slate"),
    ]


def _build_coverage_gap_actions(gap: Dict[str, Any], session_id: Optional[str], readiness_score: int) -> List[Dict[str, Any]]:
    gap_title = str(gap.get("gap") or "Coverage gap").strip() or "Coverage gap"
    chat_prompt = "\n".join([
        "Help me build context around this coverage gap and decide what control work should follow.",
        "",
        f"Gap: {gap_title}",
        f"Why it matters: {str(gap.get('why_it_matters') or '').strip()}",
        f"Suggested next step: {str(gap.get('recommended_next_step') or gap.get('recommended_action') or '').strip()}",
    ]).strip()
    gap_domain = str(gap.get("domain") or "").strip()
    task_filter = f"category:{gap_domain}" if gap_domain else "open"
    asset_import = _build_context_asset_import_payload(
        title=f"Discovery Coverage Gap: {gap_title}",
        asset_type="runbook_context",
        description=f"Saved summary context for the coverage gap '{gap_title}' with recommended control follow-up.",
        tags=[gap_domain or "coverage", "coverage-gap", "discovery-summary"],
        session_id=session_id,
        content_sections=[
            ("Coverage Gap", "\n".join([
                f"Priority: {str(gap.get('priority') or 'unspecified').strip()}",
                f"Domain: {gap_domain or 'general'}",
                f"Gap: {gap_title}",
                f"Why it matters: {str(gap.get('why_it_matters') or '').strip()}",
                f"Recommended next step: {str(gap.get('recommended_next_step') or gap.get('recommended_action') or '').strip()}",
                f"Session readiness score: {readiness_score}" if readiness_score else "Session readiness score: unknown",
            ])),
            ("Investigation Prompt", chat_prompt),
        ],
        attributes={
            "origin_kind": "summary_context_coverage_gap",
            "origin_label": "Summary Context Explorer",
            "session_id": session_id or "",
            "gap_domain": gap_domain,
            "gap_title": gap_title,
        },
    )
    return [
        _build_context_task_action("Open Task Queue", _build_context_task_focus_payload(gap_title, task_filter), tone="amber"),
        _build_context_launch_action("Explore in Chat", chat_prompt, tone="slate"),
        _build_context_save_action("Save to Context Library", asset_import, tone="slate"),
    ]


def _build_priority_task_actions(task: Dict[str, Any], session_id: Optional[str], readiness_score: int) -> List[Dict[str, Any]]:
    task_title = str(task.get("title") or "Untitled task").strip() or "Untitled task"
    task_category = str(task.get("category") or "General").strip() or "General"
    query_focus = _build_context_query_focus_payload(
        title=task_title,
        category=task_category,
        categories=_get_task_query_categories(task),
        finding_reference=str(task.get("finding_reference") or "").strip(),
        environment_evidence=list(task.get("environment_evidence") or []) if isinstance(task.get("environment_evidence"), list) else [],
        source_label="Focused From Task Queue",
        description=f"Showing validation queries aligned to the {task_category} workstream using matching finding and telemetry evidence.",
        generated_queries=[],
    )
    asset_import = _build_context_asset_import_payload(
        title=f"Discovery Task Context: {task_title}",
        asset_type="runbook_context",
        description=f"Saved summary context for the priority task '{task_title}'.",
        tags=[task_category, str(task.get("priority") or "MEDIUM").strip() or "MEDIUM", "priority-task", "discovery-summary"],
        session_id=session_id,
        content_sections=[
            ("Task", "\n".join([
                f"Priority: {str(task.get('priority') or 'MEDIUM').strip()}",
                f"Category: {task_category}",
                f"Title: {task_title}",
                f"Finding reference: {str(task.get('finding_reference') or '').strip()}",
                f"Session readiness score: {readiness_score}" if readiness_score else "Session readiness score: unknown",
            ])),
        ],
        attributes={
            "origin_kind": "summary_context_priority_task",
            "origin_label": "Summary Context Explorer",
            "session_id": session_id or "",
            "task_category": task_category,
            "task_title": task_title,
        },
    )
    return [
        _build_context_task_action("Open Task Queue", _build_context_task_focus_payload(task_title, "all"), tone="emerald"),
        _build_context_query_action("Open Related Queries", query_focus, tone="slate"),
        _build_context_save_action("Save to Context Library", asset_import, tone="slate"),
    ]


def _context_explorer_has_formal_actions(context_explorer: Any) -> bool:
    if not isinstance(context_explorer, dict):
        return False
    anchors = context_explorer.get("anchors") if isinstance(context_explorer.get("anchors"), dict) else {}
    lanes = context_explorer.get("lanes") if isinstance(context_explorer.get("lanes"), dict) else {}
    collections = [
        anchors.get("indexes"),
        anchors.get("sourcetypes"),
        anchors.get("hosts"),
        lanes.get("unknown_entities"),
        lanes.get("coverage_gaps"),
        lanes.get("risks"),
        lanes.get("priority_tasks"),
    ]
    for collection in collections:
        if not isinstance(collection, list):
            continue
        for item in collection:
            if isinstance(item, dict) and isinstance(item.get("actions"), list) and item.get("actions"):
                return True
    return False


def _context_explorer_has_structured_patterns(context_explorer: Any) -> bool:
    if not isinstance(context_explorer, dict):
        return False

    patterns = context_explorer.get("patterns")
    if not isinstance(patterns, list):
        return True

    for pattern in patterns:
        if not isinstance(pattern, dict):
            return False

        title = str(pattern.get("title") or "").strip()
        description = str(pattern.get("description") or "").strip()
        signal = str(pattern.get("signal") or "").strip()
        if title.lstrip().startswith("{") and '"patterns"' in title:
            return False
        if not (title or description or signal):
            return False

    return True


def _format_data_volume(value: Any) -> str:
    """Render the 24h ingest volume (megabytes from license usage) for people; missing data stays explicit."""
    if value is None or isinstance(value, bool):
        return "Unavailable"
    if isinstance(value, (int, float)):
        megabytes = float(value)
        if megabytes >= 1024 * 1024:
            return f"{megabytes / 1024 / 1024:,.2f} TB"
        if megabytes >= 1024:
            return f"{megabytes / 1024:,.2f} GB"
        return f"{megabytes:,.1f} MB"
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "unknown", "n/a", "unavailable"}:
        return "Unavailable"
    return text


def build_discovery_quality(
    llm_status: Any,
    pipeline_errors: Any,
    artifact_payload: Any,
) -> Dict[str, Any]:
    """Summarize how complete a discovery run was so the UI and chat do not overstate its results."""
    payload = artifact_payload if isinstance(artifact_payload, dict) else {}
    stages = llm_status if isinstance(llm_status, dict) else {}
    degraded_stages = sorted(
        stage for stage, status in stages.items()
        if isinstance(status, dict) and status.get("status") != "ok"
    )
    step_status = payload.get("discovery_step_status") if isinstance(payload.get("discovery_step_status"), dict) else {}
    failed_steps = sorted(
        name for name, status in step_status.items()
        if isinstance(status, dict) and status.get("status") in {"error", "skipped"}
    )
    unsupported_steps = sorted(
        name for name, status in step_status.items()
        if isinstance(status, dict) and status.get("status") == "unsupported"
    )
    errors = [item for item in (pipeline_errors or []) if isinstance(item, (dict, str))] if isinstance(pipeline_errors, list) else []
    score_basis = payload.get("score_basis") if isinstance(payload.get("score_basis"), dict) else {}
    if errors or failed_steps:
        status = "partial"
    elif degraded_stages:
        status = "deterministic_fallback"
    else:
        status = "complete"
    return {
        "status": status,
        "llm_degraded_stages": degraded_stages,
        "failed_steps": failed_steps,
        "unsupported_steps": unsupported_steps,
        "pipeline_errors": errors[:10],
        "score_method": score_basis.get("method") or ("evidence_weighted_v1" if payload.get("readiness_score") is not None else "legacy_heuristic"),
        "score_explanation": str(score_basis.get("explanation") or ""),
    }


def _readiness_headline(readiness_score: int) -> str:
    if readiness_score >= 80:
        return "Discovery collected strong evidence across the core surfaces; focus on the prioritized recommendations."
    if readiness_score >= 55:
        return "Discovery shows a workable baseline with evidence gaps to close before relying on it for decisions."
    return "Discovery found significant gaps in collected evidence or data freshness; resolve them before acting on recommendations."


def compute_discovery_readiness_score(
    overview: Any,
    recommendations: List[Dict[str, Any]],
    suggested_use_cases: List[Dict[str, Any]],
    mcp_capabilities: Dict[str, Any]
) -> int:
    """Compute a practical readiness score for platform maturity (0-100)."""
    score = 0
    total_indexes = _safe_int(getattr(overview, "total_indexes", 0))
    total_sourcetypes = _safe_int(getattr(overview, "total_sourcetypes", 0))
    total_hosts = _safe_int(getattr(overview, "total_hosts", 0))
    tool_count = _safe_int((mcp_capabilities or {}).get("tool_count", 0))
    recommendation_count = len(recommendations) if isinstance(recommendations, list) else 0
    use_case_count = len(suggested_use_cases) if isinstance(suggested_use_cases, list) else 0

    score += min(25, total_indexes)
    score += min(20, total_sourcetypes // 2)
    score += min(10, total_hosts // 2)
    score += min(20, tool_count * 2)
    score += min(15, recommendation_count * 2)
    score += min(10, use_case_count * 2)
    return max(0, min(100, score))


def build_context_explorer_payload(
    discovery_data: Optional[Dict[str, Any]],
    unknown_questions: Optional[List[Dict[str, Any]]] = None,
    admin_tasks: Optional[List[Dict[str, Any]]] = None,
    coverage_gaps: Optional[List[Dict[str, Any]]] = None,
    risk_register: Optional[List[Dict[str, Any]]] = None,
    readiness_score: Optional[int] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a session-scoped context explorer payload from discovery artifacts."""
    if not isinstance(discovery_data, dict):
        return {
            "overview": {},
            "anchors": {"indexes": [], "sourcetypes": [], "hosts": []},
            "patterns": [],
            "lanes": {
                "unknown_entities": [],
                "coverage_gaps": [],
                "risks": [],
                "priority_tasks": [],
            },
        }

    overview = discovery_data.get("overview", {}) if isinstance(discovery_data.get("overview", {}), dict) else {}
    finding_ledger = discovery_data.get("finding_ledger", []) if isinstance(discovery_data.get("finding_ledger", []), list) else []

    indexes: List[Dict[str, Any]] = []
    sourcetypes: List[Dict[str, Any]] = []
    hosts: List[Dict[str, Any]] = []
    seen_index_names: set[str] = set()
    seen_sourcetype_names: set[str] = set()
    seen_host_names: set[str] = set()

    for entry in finding_ledger:
        if not isinstance(entry, dict):
            continue

        data = entry.get("data", {}) if isinstance(entry.get("data", {}), dict) else {}
        if not data:
            continue

        index_name = str(data.get("title", "")).strip()
        if index_name and "totalEventCount" in data and str(data.get("disabled", "0")) != "1":
            lowered_index = index_name.lower()
            if lowered_index not in seen_index_names:
                seen_index_names.add(lowered_index)
                indexes.append({
                    "name": index_name,
                    "events": _safe_int(data.get("totalEventCount", 0)),
                    "size_mb": float(data.get("currentDBSizeMB", 0) or 0),
                    "datatype": str(data.get("datatype", "event") or "event"),
                    "max_time": data.get("maxTime") or data.get("lastTimeIso") or "",
                })

        sourcetype_name = data.get("sourcetype")
        if not sourcetype_name and str(data.get("type", "")).lower() in {"sourcetypes", "source_types"}:
            sourcetype_name = data.get("title")
        if isinstance(sourcetype_name, str) and sourcetype_name.strip():
            normalized_sourcetype = sourcetype_name.strip()
            lowered_sourcetype = normalized_sourcetype.lower()
            if lowered_sourcetype not in seen_sourcetype_names:
                seen_sourcetype_names.add(lowered_sourcetype)
                sourcetypes.append({
                    "name": normalized_sourcetype,
                    "events": _safe_int(data.get("totalCount") or data.get("count") or data.get("eventCount")),
                    "recent_time": metadata_recent_time_utc(data),
                })

        host_name = data.get("host") or data.get("hostname")
        descriptor = str(entry.get("title") or entry.get("description") or "")
        if not host_name and "Analyzing host:" in descriptor:
            host_name = data.get("title")
        if isinstance(host_name, str) and host_name.strip():
            normalized_host = host_name.strip()
            lowered_host = normalized_host.lower()
            if lowered_host not in seen_host_names:
                seen_host_names.add(lowered_host)
                hosts.append({
                    "name": normalized_host,
                    "events": _safe_int(data.get("totalCount") or data.get("count") or data.get("eventCount")),
                })

    indexes.sort(key=lambda item: item.get("events", 0), reverse=True)
    sourcetypes.sort(key=lambda item: item.get("events", 0), reverse=True)
    hosts.sort(key=lambda item: item.get("events", 0), reverse=True)

    normalized_patterns = _normalize_v2_notable_patterns_for_ui(overview.get("notable_patterns", []), limit=6)

    safe_unknowns = [item for item in (unknown_questions or []) if isinstance(item, dict)]
    safe_gaps = [item for item in (coverage_gaps or discovery_data.get("coverage_gaps", []) or []) if isinstance(item, dict)]
    safe_risks = [item for item in (risk_register or discovery_data.get("risk_register", []) or []) if isinstance(item, dict)]
    safe_tasks = [item for item in (admin_tasks or []) if isinstance(item, dict)]
    resolved_readiness_score = _safe_int(readiness_score if readiness_score is not None else discovery_data.get("readiness_score"))

    return {
        "overview": {
            "readiness_score": resolved_readiness_score,
            "total_indexes": _safe_int(overview.get("total_indexes", len(indexes))),
            "total_sourcetypes": _safe_int(overview.get("total_sourcetypes", len(sourcetypes))),
            "total_hosts": _safe_int(overview.get("total_hosts", len(hosts))),
            "data_volume_24h": _format_data_volume(overview.get("data_volume_24h")),
            "license_state": str(overview.get("license_state", "unknown") or "unknown"),
        },
        "anchors": {
            "indexes": [
                {
                    **item,
                    "actions": _build_context_anchor_actions("index", item, session_id, resolved_readiness_score),
                }
                for item in indexes[:8]
            ],
            "sourcetypes": [
                {
                    **item,
                    "actions": _build_context_anchor_actions("sourcetype", item, session_id, resolved_readiness_score),
                }
                for item in sourcetypes[:8]
            ],
            "hosts": [
                {
                    **item,
                    "actions": _build_context_anchor_actions("host", item, session_id, resolved_readiness_score),
                }
                for item in hosts[:8]
            ],
        },
        "patterns": normalized_patterns[:6],
        "lanes": {
            "unknown_entities": [
                {
                    **item,
                    "actions": _build_unknown_entity_actions(item, session_id, resolved_readiness_score),
                }
                for item in safe_unknowns[:6]
            ],
            "coverage_gaps": [
                {
                    **item,
                    "actions": _build_coverage_gap_actions(item, session_id, resolved_readiness_score),
                }
                for item in safe_gaps[:6]
            ],
            "risks": [
                {
                    **item,
                    "actions": _build_risk_actions(item, session_id, resolved_readiness_score),
                }
                for item in safe_risks[:6]
            ],
            "priority_tasks": [
                {
                    "title": str(task.get("title") or "Untitled task"),
                    "priority": str(task.get("priority") or "MEDIUM"),
                    "category": str(task.get("category") or "General"),
                    "finding_reference": str(task.get("finding_reference") or ""),
                    "actions": _build_priority_task_actions(task, session_id, resolved_readiness_score),
                }
                for task in safe_tasks[:6]
            ],
        },
    }


def build_persona_playbooks(
    overview: Any,
    recommendations: List[Dict[str, Any]],
    suggested_use_cases: List[Dict[str, Any]],
    mcp_capabilities: Dict[str, Any],
    readiness_score: Optional[int] = None,
) -> Dict[str, Any]:
    """Build persona-specific outputs for admins, analysts, and executives."""
    # LLM analysis is an untrusted schema boundary. A text fallback must not
    # crash a completed discovery run during persona assembly.
    recs = [item for item in recommendations if isinstance(item, dict)] if isinstance(recommendations, list) else []
    use_cases = [item for item in suggested_use_cases if isinstance(item, dict)] if isinstance(suggested_use_cases, list) else []

    high_priority = [r for r in recs if isinstance(r, dict) and str(r.get("priority", "")).lower() == "high"]
    top_recs = (high_priority or recs)[:5]
    top_use_cases = use_cases[:4]

    admin_actions = []
    for rec in top_recs:
        title = rec.get("title", "Recommendation")
        admin_actions.append({
            "title": title,
            "why": _first_text_line(rec.get("description")),
            "effort": _first_text_line(rec.get("complexity")),
            "owner": "Splunk Admin",
            "next_step": _first_text_line(rec.get("suggested_actions") or rec.get("next_steps")),
        })

    analyst_hypotheses = []
    for use_case in top_use_cases:
        analyst_hypotheses.append({
            "title": use_case.get("title", "Use Case"),
            "question": use_case.get("description", ""),
            "data_sources": use_case.get("data_sources", []),
            "success_metric": _first_text_line(use_case.get("success_metrics")),
        })

    if not isinstance(readiness_score, int) or isinstance(readiness_score, bool):
        readiness_score = compute_discovery_readiness_score(overview, recs, use_cases, mcp_capabilities)
    business_value_themes = [_first_text_line(use_case.get("business_value")) for use_case in use_cases]
    next_90_day_focus = [_first_text_line(rec.get("title")) for rec in top_recs]
    exec_brief = {
        "platform_readiness_score": readiness_score,
        "headline": _readiness_headline(readiness_score),
        "business_value_themes": [theme for theme in business_value_themes if theme][:3],
        "next_90_day_focus": [item for item in next_90_day_focus if item][:3],
        "environment_snapshot": {
            "indexes": _safe_int(getattr(overview, "total_indexes", 0)),
            "sourcetypes": _safe_int(getattr(overview, "total_sourcetypes", 0)),
            "hosts": _safe_int(getattr(overview, "total_hosts", 0)),
            "tooling_capability_count": _safe_int((mcp_capabilities or {}).get("tool_count", 0))
        }
    }

    return {
        "admin": {
            "title": "Admin Action Queue",
            "actions": admin_actions[:6]
        },
        "analyst": {
            "title": "Analyst Investigation Tracks",
            "hypotheses": analyst_hypotheses[:6]
        },
        "executive": exec_brief
    }


def hydrate_discovery_session(session: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Hydrate a session with readiness/personas when legacy records are missing those fields."""
    if not isinstance(session, dict):
        return session

    hydrated = dict(session)
    if hydrated.get("readiness_score") and hydrated.get("personas"):
        return hydrated

    timestamp = hydrated.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        return hydrated

    export_path = _discovery_scope_output_dir(_get_discovery_session_scope_key(hydrated), create=False) / f"discovery_export_{timestamp}.json"
    if not export_path.exists():
        return hydrated

    try:
        with open(export_path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        overview_data = payload.get("overview", {}) if isinstance(payload, dict) else {}
        recommendations_data = payload.get("recommendations", []) if isinstance(payload, dict) else []
        use_cases_data = payload.get("suggested_use_cases", []) if isinstance(payload, dict) else []
        mcp_data = payload.get("mcp_capabilities", {}) if isinstance(payload, dict) else {}

        class _OverviewProxy:
            def __init__(self, values: Dict[str, Any]):
                for k, v in values.items():
                    setattr(self, k, v)

        overview_proxy = _OverviewProxy(overview_data if isinstance(overview_data, dict) else {})
        hydrated["readiness_score"] = compute_discovery_readiness_score(
            overview_proxy,
            recommendations_data if isinstance(recommendations_data, list) else [],
            use_cases_data if isinstance(use_cases_data, list) else [],
            mcp_data if isinstance(mcp_data, dict) else {}
        )
        hydrated["personas"] = build_persona_playbooks(
            overview_proxy,
            recommendations_data if isinstance(recommendations_data, list) else [],
            use_cases_data if isinstance(use_cases_data, list) else [],
            mcp_data if isinstance(mcp_data, dict) else {},
            readiness_score=hydrated["readiness_score"],
        )
    except Exception:
        return hydrated

    return hydrated


def _resolve_session_selection(
    sessions: List[Dict[str, Any]],
    selection: Optional[str],
    default_index: int
) -> Optional[Dict[str, Any]]:
    """Resolve a session selector (latest/previous/timestamp) to a concrete session."""
    if not sessions:
        return None

    token = (selection or "").strip().lower()
    if token in {"", "latest"}:
        return sessions[0]
    if token == "previous":
        return sessions[1] if len(sessions) > 1 else None

    matched = next((s for s in sessions if s.get("timestamp") == selection), None)
    if matched:
        return matched

    return sessions[default_index] if len(sessions) > default_index else sessions[0]


def build_discovery_compare_payload(
    current_selection: Optional[str] = None,
    baseline_selection: Optional[str] = None,
    scope_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Build compare payload across two discovery sessions."""
    sessions = load_discovery_sessions(scope_key=scope_key)
    if len(sessions) < 2:
        return {
            "has_data": False,
            "message": "Run discovery at least twice to compare runs.",
            "sessions": sessions[:20]
        }

    current = hydrate_discovery_session(_resolve_session_selection(sessions, current_selection, 0))
    baseline = hydrate_discovery_session(_resolve_session_selection(sessions, baseline_selection, 1))

    if not current or not baseline:
        return {
            "has_data": False,
            "message": "Unable to resolve selected sessions for compare.",
            "sessions": sessions[:20]
        }

    if current.get("timestamp") == baseline.get("timestamp"):
        return {
            "has_data": False,
            "message": "Choose two different sessions to compare.",
            "sessions": sessions[:20],
            "current": current,
            "baseline": baseline
        }

    def _metric(session: Dict[str, Any], path: List[str]) -> int:
        value: Any = session
        for key in path:
            value = value.get(key, {}) if isinstance(value, dict) else {}
        return _safe_int(value)

    metrics = {
        "readiness": {
            "current": _metric(current, ["readiness_score"]),
            "baseline": _metric(baseline, ["readiness_score"])
        },
        "indexes": {
            "current": _metric(current, ["overview", "total_indexes"]),
            "baseline": _metric(baseline, ["overview", "total_indexes"])
        },
        "sourcetypes": {
            "current": _metric(current, ["overview", "total_sourcetypes"]),
            "baseline": _metric(baseline, ["overview", "total_sourcetypes"])
        },
        "recommendations": {
            "current": _metric(current, ["stats", "recommendation_count"]),
            "baseline": _metric(baseline, ["stats", "recommendation_count"])
        },
        "tools": {
            "current": _metric(current, ["mcp_capabilities", "tool_count"]),
            "baseline": _metric(baseline, ["mcp_capabilities", "tool_count"])
        }
    }

    for metric in metrics.values():
        metric["delta"] = metric["current"] - metric["baseline"]

    admin_current = (current.get("personas", {}).get("admin", {}).get("actions", [])
                     if isinstance(current.get("personas", {}), dict) else [])
    admin_baseline = (baseline.get("personas", {}).get("admin", {}).get("actions", [])
                      if isinstance(baseline.get("personas", {}), dict) else [])

    analyst_current = (current.get("personas", {}).get("analyst", {}).get("hypotheses", [])
                       if isinstance(current.get("personas", {}), dict) else [])
    analyst_baseline = (baseline.get("personas", {}).get("analyst", {}).get("hypotheses", [])
                        if isinstance(baseline.get("personas", {}), dict) else [])

    return {
        "has_data": True,
        "current": current,
        "baseline": baseline,
        "metrics": metrics,
        "persona_deltas": {
            "admin_actions_delta": len(admin_current) - len(admin_baseline),
            "analyst_tracks_delta": len(analyst_current) - len(analyst_baseline)
        },
        "sessions": sessions[:20]
    }


def _get_m26_14_capability_state(refresh_health: bool = False) -> Dict[str, Any]:
    try:
        return capability_manager.get_capability_state("m26_14_advisor", refresh_health=refresh_health)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="M-26-14 advisor capability is not registered") from exc


def _require_m26_14_enabled(refresh_health: bool = False) -> Dict[str, Any]:
    capability_state = _get_m26_14_capability_state(refresh_health=refresh_health)
    if not capability_state.get("installed") or not capability_state.get("enabled"):
        raise HTTPException(status_code=404, detail="M-26-14 advisor is not enabled")
    return capability_state


def _resolve_m26_14_validation_cache_session_timestamp(selection: Optional[str], scope_key: Optional[str] = None) -> str:
    sessions = load_discovery_sessions(scope_key=scope_key)
    selected_session = _resolve_session_selection(sessions, selection, 0)
    if isinstance(selected_session, dict) and str(selected_session.get("timestamp") or "").strip():
        return str(selected_session.get("timestamp") or "").strip()
    return str(selection or "latest").strip() or "latest"


def _build_m26_14_validation_cache_key(
    validation_pack: Dict[str, Any],
    validation_request: "M2614ValidationRequest",
    runtime_config: Any,
    *,
    scope_key: Optional[str] = None,
) -> str:
    resolved_timestamp = _resolve_m26_14_validation_cache_session_timestamp(validation_request.timestamp, scope_key=scope_key)
    runtime_url = str(getattr(getattr(runtime_config, "mcp", None), "url", "") or "").strip()
    runtime_name = str(getattr(runtime_config, "active_mcp_config_name", "") or "").strip()
    cache_payload = {
        "pack_id": str(validation_pack.get("id") or "").strip(),
        "query": str(validation_pack.get("query") or "").strip(),
        "timestamp": resolved_timestamp,
        "earliest": str(validation_request.earliest or "").strip() or "-30d",
        "latest": str(validation_request.latest or "").strip() or "now",
        "scope_key": str(scope_key or "").strip(),
        "runtime_url": runtime_url,
        "runtime_name": runtime_name,
    }
    return hashlib.sha256(json.dumps(cache_payload, sort_keys=True).encode("utf-8")).hexdigest()


def _get_cached_m26_14_validation_result(cache_key: str) -> Optional[Dict[str, Any]]:
    cached_payload = _cached_m2614_validation_results.get(str(cache_key or "").strip())
    if not isinstance(cached_payload, dict):
        return None
    return copy.deepcopy(cached_payload)


def _store_cached_m26_14_validation_result(cache_key: str, payload: Dict[str, Any]) -> None:
    normalized_key = str(cache_key or "").strip()
    if not normalized_key or not isinstance(payload, dict):
        return

    if normalized_key in _cached_m2614_validation_results:
        _cached_m2614_validation_results.pop(normalized_key, None)

    _cached_m2614_validation_results[normalized_key] = copy.deepcopy(payload)
    while len(_cached_m2614_validation_results) > M2614_VALIDATION_CACHE_LIMIT:
        oldest_key = next(iter(_cached_m2614_validation_results), None)
        if oldest_key is None:
            break
        _cached_m2614_validation_results.pop(oldest_key, None)


def clear_m26_14_validation_cache() -> None:
    _cached_m2614_validation_results.clear()


def _normalize_m26_14_advisory_list(value: Any, limit: int = 5) -> List[str]:
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, list):
        candidates = value
    else:
        candidates = []

    normalized: List[str] = []
    for item in candidates:
        cleaned = str(item or "").strip()
        if cleaned and cleaned not in normalized:
            normalized.append(cleaned)
        if len(normalized) >= limit:
            break
    return normalized


def _sample_m26_14_validation_rows(rows: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
    if not isinstance(rows, list):
        return []
    sampled_rows: List[Dict[str, Any]] = []
    for row in rows[:max(1, limit)]:
        if isinstance(row, dict):
            sampled_rows.append(copy.deepcopy(row))
    return sampled_rows


def _build_m26_14_profile_advisory_snapshot(profile_payload: Dict[str, Any], validation_pack: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(profile_payload, dict) or not profile_payload.get("has_data"):
        return {
            "has_data": False,
            "message": str((profile_payload or {}).get("message") or "No M-26-14 discovery-backed profile is available for grounding.").strip(),
        }

    priority_key = str(validation_pack.get("priority_objective") or "").strip().lower()
    control_area = str(validation_pack.get("control_area") or "").strip().lower()
    priority_signal = None
    if isinstance(profile_payload.get("priority_objectives"), dict):
        priority_signal = profile_payload.get("priority_objectives", {}).get(priority_key)
    maturity_element = None
    if isinstance(profile_payload.get("maturity_elements"), list):
        maturity_element = next(
            (
                element
                for element in profile_payload.get("maturity_elements", [])
                if isinstance(element, dict) and str(element.get("id") or "").strip().lower() == control_area
            ),
            None,
        )

    return {
        "has_data": True,
        "timestamp": profile_payload.get("timestamp"),
        "readiness_estimate": profile_payload.get("readiness_estimate"),
        "confidence": profile_payload.get("confidence"),
        "maturity_floor": copy.deepcopy(profile_payload.get("maturity_floor") or {}),
        "priority_objective": copy.deepcopy(priority_signal or {}),
        "maturity_element": copy.deepcopy(maturity_element or {}),
        "source_summary": copy.deepcopy(profile_payload.get("source_summary") or {}),
        "recommended_pack_ids": list((profile_payload.get("live_validation") or {}).get("recommended_pack_ids") or []),
    }


def _build_m26_14_rag_context_query(
    validation_pack: Dict[str, Any],
    validation_summary: Dict[str, Any],
    profile_snapshot: Dict[str, Any],
) -> str:
    query_parts: List[str] = [
        "M-26-14 advisory",
        str(validation_pack.get("title") or "").strip(),
        str(validation_pack.get("control_area") or "").replace("_", " ").strip(),
        str(validation_pack.get("priority_objective") or "").upper().strip(),
        str(validation_pack.get("description") or "").strip(),
        str(validation_summary.get("headline") or "").strip(),
    ]

    if isinstance(profile_snapshot.get("priority_objective"), dict):
        query_parts.append(str(profile_snapshot.get("priority_objective", {}).get("objective") or "").strip())
        query_parts.extend(_normalize_m26_14_advisory_list(profile_snapshot.get("priority_objective", {}).get("notes"), limit=2))

    if isinstance(profile_snapshot.get("maturity_element"), dict):
        query_parts.append(str(profile_snapshot.get("maturity_element", {}).get("label") or "").strip())
        query_parts.extend(_normalize_m26_14_advisory_list(profile_snapshot.get("maturity_element", {}).get("gaps"), limit=2))
        query_parts.extend(_normalize_m26_14_advisory_list(profile_snapshot.get("maturity_element", {}).get("remediation"), limit=1))

    query_parts.extend(_normalize_m26_14_advisory_list(validation_summary.get("findings"), limit=2))
    return " ".join(part for part in query_parts if part)


def _build_m26_14_lightweight_rag_context_payload(query: str, details: Dict[str, Any]) -> Dict[str, Any]:
    chunks = [
        _sanitize_external_rag_chunk(chunk)
        for chunk in (details.get("chunks") or [])
        if isinstance(chunk, dict)
    ]
    context_text = str(details.get("context_text") or "").strip()
    message = str(details.get("message") or "").strip()
    if not message:
        message = "Built context from recent local artifacts." if context_text else "No local artifact context matched this advisory query."
    return {
        "status": "ready" if context_text else "unavailable",
        "provider": str(details.get("provider") or details.get("capability") or "rag_local").strip() or "rag_local",
        "query": str(query or "").strip(),
        "message": message,
        "context_text": context_text,
        "operator_brief": context_text,
        "chunks": chunks,
        "matched_assets": [],
        "reusable_spl_queries": [],
        "retrieved_key_points": [],
        "recommended_uses": [],
        "coverage_gaps": [],
        "coverage_summary": {
            "asset_count": 0,
            "asset_types": [],
            "source_labels": [],
            "focus_terms": [],
        },
        "index_summary": {},
        "asset_summary": {},
    }


def _build_m26_14_rag_context_payload(query: str) -> Dict[str, Any]:
    normalized_query = str(query or "").strip()
    for capability_name in ("rag_chromadb", "rag_local"):
        try:
            capability_state = capability_manager.get_capability_state(capability_name, refresh_health=False)
        except KeyError:
            continue

        if not capability_state.get("installed") or not capability_state.get("enabled"):
            continue

        if capability_name == "rag_chromadb":
            preview_result = capability_manager.build_rag_context_preview(capability_name, normalized_query, max_chunks=4).to_dict()
            if preview_result.get("ok"):
                sanitized = _sanitize_external_rag_search_result(preview_result.get("details") or {})
                sanitized["status"] = "ready" if sanitized.get("context_text") else "unavailable"
                sanitized["provider"] = capability_name
                if not sanitized.get("message"):
                    sanitized["message"] = str(preview_result.get("message") or "").strip()
                return sanitized
            return {
                "status": "error",
                "provider": capability_name,
                "query": normalized_query,
                "message": str(preview_result.get("message") or "Failed to build indexed artifact context preview.").strip(),
                "context_text": "",
                "operator_brief": "",
                "chunks": [],
                "matched_assets": [],
                "reusable_spl_queries": [],
                "retrieved_key_points": [],
                "recommended_uses": [],
                "coverage_gaps": [],
                "coverage_summary": {},
                "index_summary": {},
                "asset_summary": {},
            }

        definition = capability_manager.registry.get_definition(capability_name)
        if definition is None:
            continue
        config = capability_manager._get_or_create_config(definition)
        provider = capability_manager._get_rag_provider(definition, config)
        if provider is None or not hasattr(provider, "get_context"):
            continue

        try:
            details = provider.get_context(normalized_query, max_chunks=4)
        except Exception as exc:
            return {
                "status": "error",
                "provider": capability_name,
                "query": normalized_query,
                "message": f"Local artifact context lookup failed: {exc}",
                "context_text": "",
                "operator_brief": "",
                "chunks": [],
                "matched_assets": [],
                "reusable_spl_queries": [],
                "retrieved_key_points": [],
                "recommended_uses": [],
                "coverage_gaps": [],
                "coverage_summary": {},
                "index_summary": {},
                "asset_summary": {},
            }

        return _build_m26_14_lightweight_rag_context_payload(normalized_query, details if isinstance(details, dict) else {})

    return {
        "status": "unavailable",
        "provider": None,
        "query": normalized_query,
        "message": "Indexed artifact or local artifact context is not enabled.",
        "context_text": "",
        "operator_brief": "",
        "chunks": [],
        "matched_assets": [],
        "reusable_spl_queries": [],
        "retrieved_key_points": [],
        "recommended_uses": [],
        "coverage_gaps": [],
        "coverage_summary": {},
        "index_summary": {},
        "asset_summary": {},
    }


def _extract_json_object_from_llm_text(text: Any) -> Optional[Dict[str, Any]]:
    cleaned = sanitize_llm_response_text(str(text or ""))
    if not cleaned:
        return None

    candidates = [cleaned]
    fenced_match = re.search(r"```(?:json)?\s*(\{.*\})\s*```", cleaned, re.DOTALL | re.IGNORECASE)
    if fenced_match:
        candidates.insert(0, fenced_match.group(1).strip())
    object_match = re.search(r"(\{.*\})", cleaned, re.DOTALL)
    if object_match:
        candidates.append(object_match.group(1).strip())

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except Exception:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _is_llm_available_for_m26_14_advisory(config: Any) -> Tuple[bool, str]:
    provider = normalize_provider_name(getattr(getattr(config, "llm", None), "provider", "") or "")
    model = str(getattr(getattr(config, "llm", None), "model", "") or "").strip()
    endpoint_url = str(getattr(getattr(config, "llm", None), "endpoint_url", "") or "").strip()
    api_key = str(getattr(getattr(config, "llm", None), "api_key", "") or "").strip()

    if not provider or not model:
        return False, "No AI model is set up. Add one in Settings to get an AI review."
    if provider in {"azure", "custom"} and not endpoint_url:
        return False, f"The {provider} AI provider needs an endpoint URL. Add it in Settings."
    if provider in {"openai", "azure", "anthropic", "gemini"} and not api_key:
        return False, f"The {provider} AI provider needs an API key. Add it in Settings."
    return True, ""


async def _build_m26_14_llm_analysis_payload(
    validation_pack: Dict[str, Any],
    validation_summary: Dict[str, Any],
    rows: List[Dict[str, Any]],
    profile_snapshot: Dict[str, Any],
    rag_context: Dict[str, Any],
    capability_state: Dict[str, Any],
) -> Dict[str, Any]:
    capability_config = capability_state.get("config") if isinstance(capability_state.get("config"), dict) else {}
    if not bool(capability_config.get("allow_bespoke_follow_up", True)):
        return {
            "status": "disabled",
            "message": "AI review is turned off in the M-26-14 capability settings.",
        }

    config = config_manager.get()
    llm_available, reason = _is_llm_available_for_m26_14_advisory(config)
    if not llm_available:
        return {
            "status": "unavailable",
            "message": reason,
        }

    try:
        llm_client = get_or_create_llm_client(config)
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Could not start the AI model: {exc}",
        }

    pack_payload = {
        "id": validation_pack.get("id"),
        "title": validation_pack.get("title"),
        "control_area": validation_pack.get("control_area"),
        "priority_objective": validation_pack.get("priority_objective"),
        "description": validation_pack.get("description"),
        "expected_evidence": _normalize_m26_14_advisory_list(validation_pack.get("expected_evidence"), limit=4),
        "limitations": _normalize_m26_14_advisory_list(validation_pack.get("limitations"), limit=4),
    }
    rag_payload = {
        "provider": rag_context.get("provider"),
        "status": rag_context.get("status"),
        "operator_brief": str(rag_context.get("operator_brief") or "").strip(),
        "recommended_uses": _normalize_m26_14_advisory_list(rag_context.get("recommended_uses"), limit=4),
        "coverage_gaps": _normalize_m26_14_advisory_list(rag_context.get("coverage_gaps"), limit=4),
        "reusable_spl_queries": [
            {
                "title": item.get("title"),
                "why_reuse": item.get("why_reuse"),
                "environment_fit_status": item.get("environment_fit_status"),
                "validation_status": item.get("validation_status"),
                "reuse_tier": item.get("reuse_tier"),
                "known_good": bool(item.get("known_good")),
            }
            for item in (rag_context.get("reusable_spl_queries") or [])[:3]
            if isinstance(item, dict)
        ],
    }
    validation_payload = {
        "status": validation_summary.get("status"),
        "headline": validation_summary.get("headline"),
        "findings": _normalize_m26_14_advisory_list(validation_summary.get("findings"), limit=5),
        "row_count": validation_summary.get("row_count"),
        "sample_fields": validation_summary.get("sample_fields") or [],
        "sample_rows": _sample_m26_14_validation_rows(rows, limit=5),
    }

    prompt_payload = {
        "pack": pack_payload,
        "profile_snapshot": profile_snapshot,
        "validation": validation_payload,
        "rag_context": rag_payload,
    }
    messages = [
        {
            "role": "system",
            "content": (
                "You are producing grounded M-26-14 advisor guidance for Splunk Discovery Tool. "
                "Use only the provided evidence. Do not claim formal compliance. Do not invent SPL, logs, hosts, sourcetypes, or policies. "
                "Return strict JSON with keys: summary, environment_relevance, recommended_adjustments, suggested_follow_ups, evidence_gaps, confidence_notes. "
                "Each list should contain short strings."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(prompt_payload, indent=2),
        },
    ]

    try:
        raw_response = await llm_client.generate_response(
            messages=messages,
            max_tokens=llm_call_budget(config, 0.3, floor=400, ceiling=1200),
            temperature=0.2,
        )
    except Exception as exc:
        return {
            "status": "error",
            "message": f"Configured LLM follow-up failed: {exc}",
        }

    parsed = _extract_json_object_from_llm_text(raw_response)
    if parsed is None:
        fallback_summary = finalize_user_facing_response_text(raw_response, "")
        return {
            "status": "partial",
            "message": "Configured LLM returned unstructured output; using a plain-text advisory summary.",
            "summary": fallback_summary,
            "environment_relevance": "",
            "recommended_adjustments": [],
            "suggested_follow_ups": [],
            "evidence_gaps": [],
            "confidence_notes": [],
        }

    return {
        "status": "ready",
        "summary": str(parsed.get("summary") or "").strip(),
        "environment_relevance": str(parsed.get("environment_relevance") or "").strip(),
        "recommended_adjustments": _normalize_m26_14_advisory_list(parsed.get("recommended_adjustments"), limit=5),
        "suggested_follow_ups": _normalize_m26_14_advisory_list(parsed.get("suggested_follow_ups"), limit=5),
        "evidence_gaps": _normalize_m26_14_advisory_list(parsed.get("evidence_gaps"), limit=5),
        "confidence_notes": _normalize_m26_14_advisory_list(parsed.get("confidence_notes"), limit=4),
    }


async def _build_m26_14_validation_advisory_payload(
    validation_pack: Dict[str, Any],
    validation_request: "M2614ValidationRequest",
    validation_summary: Dict[str, Any],
    rows: List[Dict[str, Any]],
    capability_state: Dict[str, Any],
    *,
    scope_key: Optional[str] = None,
) -> Dict[str, Any]:
    profile_payload = build_m26_14_profile_payload(timestamp=validation_request.timestamp, scope_key=scope_key)
    profile_snapshot = _build_m26_14_profile_advisory_snapshot(profile_payload, validation_pack)
    rag_query = _build_m26_14_rag_context_query(validation_pack, validation_summary, profile_snapshot)
    rag_context = _build_m26_14_rag_context_payload(rag_query)
    llm_analysis = await _build_m26_14_llm_analysis_payload(
        validation_pack,
        validation_summary,
        rows,
        profile_snapshot,
        rag_context,
        capability_state,
    )

    status_parts = [profile_snapshot.get("has_data"), rag_context.get("status") == "ready", llm_analysis.get("status") in {"ready", "partial"}]
    overall_status = "ready" if any(status_parts) else "unavailable"
    if rag_context.get("status") == "error" or llm_analysis.get("status") == "error":
        overall_status = "partial"

    return {
        "status": overall_status,
        "profile_snapshot": profile_snapshot,
        "rag_context": rag_context,
        "llm_analysis": llm_analysis,
    }


def build_m26_14_profile_payload(
    timestamp: Optional[str] = None,
    scope_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an M-26-14 profile payload from a selected discovery session."""
    sessions = load_discovery_sessions(scope_key=scope_key)
    if not sessions:
        return {
            "has_data": False,
            "message": "No discovery runs yet.",
            "validation_packs": list_m26_14_validation_packs(),
            "sessions": [],
        }

    blueprint = load_selected_v2_blueprint(timestamp, scope_key=scope_key)
    if not blueprint:
        return {
            "has_data": False,
            "message": "Could not build a readiness estimate because the selected discovery results are missing.",
            "validation_packs": list_m26_14_validation_packs(),
            "sessions": sessions[:20],
        }

    profile = build_m26_14_profile_from_blueprint(blueprint)
    profile["timestamp"] = blueprint.get("_session", {}).get("timestamp")
    profile["artifact"] = blueprint.get("_artifact", {})
    profile["validation_packs"] = list_m26_14_validation_packs()
    profile["sessions"] = sessions[:20]
    return profile


def build_m26_14_compare_payload(
    current_selection: Optional[str] = None,
    baseline_selection: Optional[str] = None,
    scope_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Build compare payload across two M-26-14 profiles."""
    sessions = load_discovery_sessions(scope_key=scope_key)
    if len(sessions) < 2:
        return {
            "has_data": False,
            "message": "Run discovery at least twice to compare M-26-14 readiness.",
            "sessions": sessions[:20],
        }

    current = build_m26_14_profile_payload(current_selection, scope_key=scope_key)
    baseline = build_m26_14_profile_payload(baseline_selection or "previous", scope_key=scope_key)
    if not current.get("has_data") or not baseline.get("has_data"):
        return {
            "has_data": False,
            "message": "Could not build readiness estimates for both runs.",
            "current": current,
            "baseline": baseline,
            "sessions": sessions[:20],
        }

    current_level = current.get("maturity_floor", {}).get("level")
    baseline_level = baseline.get("maturity_floor", {}).get("level")
    recommended_pack_ids: List[str] = []
    for pack_id in list(current.get("live_validation", {}).get("recommended_pack_ids", []) or []) + list(
        baseline.get("live_validation", {}).get("recommended_pack_ids", []) or []
    ):
        if pack_id not in recommended_pack_ids:
            recommended_pack_ids.append(pack_id)

    return {
        "has_data": True,
        "current": current,
        "baseline": baseline,
        "comparison": {
            "readiness_delta": int(current.get("readiness_estimate", 0) or 0) - int(baseline.get("readiness_estimate", 0) or 0),
            "maturity_floor_delta": (current_level - baseline_level) if current_level is not None and baseline_level is not None else None,
            "recommended_pack_ids": recommended_pack_ids[:8],
        },
        "sessions": sessions[:20],
    }


def build_session_runbook_payload(
    timestamp: Optional[str] = None,
    persona: str = "admin",
    voice: str = "direct",
    scope_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Build one-click operational runbook payload for a selected persona and session."""
    sessions = load_discovery_sessions(scope_key=scope_key)
    if not sessions:
        return {
            "has_data": False,
            "message": "No discovery runs yet.",
            "sessions": []
        }

    selected = hydrate_discovery_session(_resolve_session_selection(sessions, timestamp, 0))
    if not selected:
        return {
            "has_data": False,
            "message": "Discovery session not found.",
            "sessions": sessions[:20]
        }

    persona_key = str(persona or "admin").strip().lower()
    if persona_key not in {"admin", "analyst", "executive"}:
        persona_key = "admin"
    voice_key = _normalize_operator_voice(voice)
    voice_label = _operator_voice_label(voice_key)

    ts = selected.get("timestamp", "unknown")
    personas = selected.get("personas", {}) if isinstance(selected.get("personas", {}), dict) else {}
    steps: List[Dict[str, Any]] = []
    markdown_lines = [
        "# Discovery Runbook",
        "",
        f"**Session:** {ts}",
        f"**Audience:** {persona_key.title()}",
        f"**Style:** {voice_label}",
        f"**Readiness Score:** {_safe_int(selected.get('readiness_score', 0))}/100",
        ""
    ]

    if persona_key == "admin":
        actions = personas.get("admin", {}).get("actions", []) if isinstance(personas.get("admin", {}), dict) else []
        for idx, action in enumerate(actions[:8], 1):
            action_payload = action if isinstance(action, dict) else {}
            voice_item = _build_operator_voice_admin_item(action_payload, voice_key)
            steps.append({
                "step": idx,
                "title": voice_item["title"],
                "owner": "Splunk Admin",
                "effort": voice_item["badge"],
                "details": voice_item["summary"],
                "next_step": voice_item["meta"],
            })
            markdown_lines.extend([
                f"## {idx}. {voice_item['title']}",
                "- Owner: Splunk Admin",
                *([f"- {voice_item['badge']}"] if voice_item["badge"] else []),
                *([f"- Summary: {voice_item['summary']}"] if voice_item["summary"] else []),
                *([f"- {voice_item['meta']}"] if voice_item["meta"] else []),
                ""
            ])

    elif persona_key == "analyst":
        tracks = personas.get("analyst", {}).get("hypotheses", []) if isinstance(personas.get("analyst", {}), dict) else []
        for idx, track in enumerate(tracks[:8], 1):
            track_payload = track if isinstance(track, dict) else {}
            title = track_payload.get("title", f"Investigation Track {idx}")
            sources = track_payload.get("data_sources", []) if isinstance(track_payload.get("data_sources", []), list) else []
            source_text = ", ".join([str(s) for s in sources[:6]]) if isinstance(sources, list) else ""
            voice_item = _build_operator_voice_analyst_item(track_payload, voice_key)
            steps.append({
                "step": idx,
                "title": voice_item["title"],
                "owner": "Security Analyst",
                "effort": "medium",
                "details": voice_item["summary"],
                "next_step": voice_item["meta"],
            })
            markdown_lines.extend([
                f"## {idx}. {voice_item['title']}",
                "- Owner: Security Analyst",
                *([f"- Summary: {voice_item['summary']}"] if voice_item["summary"] else []),
                *([f"- {voice_item['meta']}"] if voice_item["meta"] else []),
                *([f"- Data Sources: {source_text}"] if source_text else []),
                ""
            ])

    else:
        executive = personas.get("executive", {}) if isinstance(personas.get("executive", {}), dict) else {}
        headline = executive.get("headline", "")
        themes = executive.get("business_value_themes", []) if isinstance(executive.get("business_value_themes", []), list) else []
        themes = [theme for theme in themes if str(theme or "").strip()]
        focus_items = executive.get("next_90_day_focus", []) if isinstance(executive.get("next_90_day_focus", []), list) else []
        focus_items = [item for item in focus_items if str(item or "").strip()]

        for idx, item in enumerate(focus_items[:8], 1):
            voice_item = _build_operator_voice_executive_item(item, voice_key, idx, "focus")
            steps.append({
                "step": idx,
                "title": voice_item["title"],
                "owner": "Leadership",
                "effort": "strategic",
                "details": voice_item["summary"],
                "next_step": voice_item["meta"],
            })

        markdown_lines.extend([
            "## Executive Headline",
            f"{headline}",
            "",
        ])
        if themes:
            markdown_lines.append("## Business Value Themes")
        for idx, theme in enumerate(themes[:6], 1):
            theme_item = _build_operator_voice_executive_item(theme, voice_key, idx, "theme")
            markdown_lines.extend([
                f"### {theme_item['title']}",
                f"- Summary: {theme_item['summary']}",
                "",
            ])
        if focus_items:
            markdown_lines.extend(["", "## Next 90 Days"])
        for idx, item in enumerate(focus_items[:8], 1):
            focus_item = _build_operator_voice_executive_item(item, voice_key, idx, "focus")
            markdown_lines.extend([
                f"### {focus_item['title']}",
                f"- Summary: {focus_item['summary']}",
                "",
            ])
        markdown_lines.append("")

    filename = f"runbook_{persona_key}_{voice_key}_{ts}.md"
    return {
        "has_data": True,
        "session": selected,
        "persona": persona_key,
        "voice": voice_key,
        "voice_label": voice_label,
        "title": f"{persona_key.title()} runbook ({voice_label} style)",
        "filename": filename,
        "markdown": "\n".join(markdown_lines),
        "steps": steps,
        "sessions": sessions[:20]
    }


def build_discovery_dashboard_payload(scope_key: Optional[str] = None) -> Dict[str, Any]:
    """Build dashboard payload from persisted discovery sessions with simple trend analysis."""
    sessions = load_discovery_sessions(scope_key=scope_key)
    latest = sessions[0] if sessions else None
    previous = sessions[1] if len(sessions) > 1 else None

    latest = hydrate_discovery_session(latest)
    previous = hydrate_discovery_session(previous)

    if not latest:
        return {
            "has_data": False,
            "message": "No discovery runs yet.",
            "sessions": []
        }

    def _delta(path: List[str]) -> int:
        if not previous:
            return 0
        current = latest
        prior = previous
        for key in path:
            current = current.get(key, {}) if isinstance(current, dict) else {}
            prior = prior.get(key, {}) if isinstance(prior, dict) else {}
        return _safe_int(current) - _safe_int(prior)

    kpis = {
        "readiness_score": latest.get("readiness_score", 0),
        "total_indexes": _safe_int(latest.get("overview", {}).get("total_indexes", 0)),
        "total_sourcetypes": _safe_int(latest.get("overview", {}).get("total_sourcetypes", 0)),
        "recommendation_count": _safe_int(latest.get("stats", {}).get("recommendation_count", 0)),
        "tool_count": _safe_int(latest.get("mcp_capabilities", {}).get("tool_count", 0))
    }

    trends = {
        "indexes_delta": _delta(["overview", "total_indexes"]),
        "sourcetypes_delta": _delta(["overview", "total_sourcetypes"]),
        "recommendations_delta": _delta(["stats", "recommendation_count"]),
        "readiness_delta": _delta(["readiness_score"])
    }

    return {
        "has_data": True,
        "latest": latest,
        "previous": previous,
        "kpis": kpis,
        "trends": trends,
        "sessions": sessions[:20]
    }


def load_latest_v2_blueprint(scope_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Load the latest intelligence blueprint artifact if available."""
    sessions = load_discovery_sessions(scope_key=scope_key)
    for session in sessions:
        session_scope_key = _get_discovery_session_scope_key(session)
        report_names = session.get("report_paths", []) if isinstance(session.get("report_paths", []), list) else []
        blueprint_name = next(
            (
                report_name
                for report_name in report_names
                if str(report_name).startswith("v2_intelligence_blueprint_") and str(report_name).endswith(".json")
            ),
            None,
        )
        if blueprint_name is None:
            blueprint_name = f"v2_intelligence_blueprint_{session.get('timestamp')}.json"
        try:
            latest = _resolve_output_artifact_path(blueprint_name, session_scope_key)
        except HTTPException:
            continue
        try:
            payload = json.loads(latest.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                payload["_artifact"] = {
                    "name": latest.name,
                    "modified": datetime.fromtimestamp(latest.stat().st_mtime).isoformat(),
                    "size": latest.stat().st_size
                }
                return payload
        except Exception:
            return None
    return None


def load_selected_v2_blueprint(
    timestamp: Optional[str] = None,
    scope_key: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Load a selected intelligence blueprint artifact by discovery session timestamp."""
    sessions = load_discovery_sessions(scope_key=scope_key)
    if not sessions:
        return None

    selected_session = hydrate_discovery_session(_resolve_session_selection(sessions, timestamp, 0))
    if not selected_session:
        return None

    session_scope_key = _get_discovery_session_scope_key(selected_session)
    report_names = selected_session.get("report_paths", []) if isinstance(selected_session.get("report_paths", []), list) else []
    blueprint_name = next(
        (
            report_name
            for report_name in report_names
            if str(report_name).startswith("v2_intelligence_blueprint_") and str(report_name).endswith(".json")
        ),
        None,
    )
    if blueprint_name is None:
        blueprint_name = f"v2_intelligence_blueprint_{selected_session.get('timestamp')}.json"

    try:
        blueprint_path = _resolve_output_artifact_path(blueprint_name, session_scope_key)
    except HTTPException:
        return None

    try:
        payload = json.loads(blueprint_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None

    payload["_artifact"] = {
        "name": blueprint_path.name,
        "modified": datetime.fromtimestamp(blueprint_path.stat().st_mtime).isoformat(),
        "size": blueprint_path.stat().st_size,
    }
    payload["_session"] = {
        "timestamp": selected_session.get("timestamp"),
        "scope_key": session_scope_key,
    }
    return payload


def build_v2_artifact_catalog(scope_key: Optional[str] = None) -> Dict[str, Any]:
    """Build the artifact catalog for the Artifacts workspace tab."""
    artifacts = _build_accessible_report_metadata(scope_key)

    return {
        "has_data": len(artifacts) > 0,
        "artifacts": artifacts,
        "count": len(artifacts)
    }


async def discover_mcp_tools(config, force_refresh: bool = False) -> set:
    """Discover and cache available MCP tools from the connected Splunk MCP server."""
    cache_ttl_seconds = 60
    now = time.time()
    cache_identity = _build_mcp_runtime_identity(config)
    cached_tools = _cached_mcp_tools["tools"] if _cached_mcp_tools.get("identity") == cache_identity else set()

    if (
        not force_refresh
        and cached_tools
        and _cached_mcp_tools.get("identity") == cache_identity
        and (now - _cached_mcp_tools["timestamp"]) < cache_ttl_seconds
    ):
        return cached_tools

    current_url = getattr(config.mcp, "url", None)
    if not current_url or not cache_identity:
        return set()

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    if config.mcp.token:
        headers["Authorization"] = f"Bearer {config.mcp.token}"

    verify_ssl = config.mcp.verify_ssl
    ca_bundle = getattr(config.mcp, 'ca_bundle_path', None)
    if ca_bundle and verify_ssl:
        ssl_verify = ca_bundle
    elif verify_ssl:
        ssl_verify = True
    else:
        ssl_verify = False

    payload = {
        "jsonrpc": "2.0",
        "id": _next_mcp_request_id(),
        "method": "tools/list",
        "params": {}
    }

    discovered = set()
    descriptions: Dict[str, str] = {}
    schemas: Dict[str, Any] = {}

    def _collect(tool_entries: Any) -> None:
        if not isinstance(tool_entries, list):
            return
        for tool in tool_entries:
            if not isinstance(tool, dict) or not tool.get("name"):
                continue
            name = str(tool["name"])
            discovered.add(name)
            if isinstance(tool.get("description"), str) and tool["description"].strip():
                descriptions[name] = tool["description"].strip()
            if isinstance(tool.get("inputSchema"), dict):
                schemas[name] = tool["inputSchema"]

    try:
        async with httpx.AsyncClient(verify=ssl_verify, timeout=15.0) as client:
            response = await client.post(current_url, json=payload, headers=headers)
            if response.status_code != 200:
                return cached_tools

            data = response.json()
            result_obj = data.get("result", {}) if isinstance(data, dict) else {}
            if not isinstance(result_obj, dict):
                result_obj = {}

            _collect(result_obj.get("tools"))

            content = result_obj.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if not isinstance(item, dict):
                        continue
                    text = item.get("text")
                    if not isinstance(text, str) or not text.strip():
                        continue
                    try:
                        parsed = json.loads(text)
                    except json.JSONDecodeError:
                        continue

                    if isinstance(parsed, dict):
                        _collect(parsed.get("tools"))

        if discovered:
            _cached_mcp_tools["identity"] = cache_identity
            _cached_mcp_tools["tools"] = discovered
            _cached_mcp_tools["descriptions"] = descriptions
            _cached_mcp_tools["schemas"] = schemas
            _cached_mcp_tools["timestamp"] = now

        return discovered or cached_tools
    except Exception as e:
        debug_log(f"MCP tool discovery failed: {str(e)}", "warning")
        return cached_tools

def debug_log(message: str, category: str = "info", data: Any = None):
    """
    Log debug message to terminal and optionally to debug WebSocket clients.
    Automatically sanitizes secrets before sending to clients.
    """
    config = config_manager.get()
    
    # Always print to terminal
    print(message)
    
    # If debug mode enabled, also send to WebSocket clients
    if config.server.debug_mode and debug_connections:
        # Sanitize sensitive data
        sanitized_data = None
        if data:
            sanitized_data = _sanitize_debug_data(data)
        
        debug_msg = {
            "type": "debug",
            "category": category,  # info, warning, error, query, response
            "message": _sanitize_secrets(message),
            "data": sanitized_data,
            "timestamp": datetime.now().isoformat()
        }
        
        # Queue for WebSocket send
        try:
            debug_log_queue.put_nowait(debug_msg)
        except:
            pass  # Queue full, skip this message


def _sanitize_secrets(text: str) -> str:
    """Remove or mask sensitive information from text."""
    import re
    
    # Mask API keys (keep first/last 4 chars)
    text = re.sub(r'(api[_-]?key["\s:=]+)([a-zA-Z0-9\-_]{8,})', 
                  lambda m: f"{m.group(1)}{m.group(2)[:4]}***{m.group(2)[-4:]}", 
                  text, flags=re.IGNORECASE)
    
    # Mask tokens
    text = re.sub(r'(token["\s:=]+)([a-zA-Z0-9\-_]{16,})', 
                  lambda m: f"{m.group(1)}{m.group(2)[:4]}***{m.group(2)[-4:]}", 
                  text, flags=re.IGNORECASE)
    
    # Mask passwords
    text = re.sub(r'(password["\s:=]+)([^\s\'"]+)', 
                  lambda m: f"{m.group(1)}***REDACTED***", 
                  text, flags=re.IGNORECASE)
    
    return text


def _sanitize_debug_data(data: Any) -> Any:
    """Recursively sanitize sensitive data from objects."""
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            # Skip or mask sensitive keys
            if any(secret in key.lower() for secret in ['api_key', 'apikey', 'token', 'password', 'secret', 'credential']):
                if isinstance(value, str) and len(value) > 8:
                    sanitized[key] = f"{value[:4]}***{value[-4:]}"
                else:
                    sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = _sanitize_debug_data(value)
        return sanitized
    elif isinstance(data, list):
        return [_sanitize_debug_data(item) for item in data]
    elif isinstance(data, str):
        return _sanitize_secrets(data)
    else:
        return data


@app.middleware("http")
async def enforce_optional_authentication(request: Request, call_next):
    """Apply optional auth guards when security mode is enabled."""
    request.state.auth_user = None
    request.state.requires_password_reset = False
    path = request.url.path or "/"

    if _is_external_api_path(path):
        return await call_next(request)

    if not is_auth_enabled():
        return await call_next(request)

    auth_provider = get_auth_provider()
    if auth_provider not in {"local_password", "oidc"}:
        if _is_public_auth_path(path):
            return await call_next(request)
        return JSONResponse(status_code=503, content={"detail": "Configured auth provider is not implemented yet"})

    if auth_provider == "local_password":
        ensure_local_auth_bootstrap_state()

    session_token = request.cookies.get(AUTH_SESSION_COOKIE_NAME, "")
    if session_token:
        session_user = security_manager.resolve_session(session_token)
        if session_user:
            request.state.auth_user = session_user
            request.state.requires_password_reset = bool(session_user.get("require_password_reset")) if auth_provider == "local_password" else False

    if path.startswith("/static/") or _is_public_auth_path(path):
        return await call_next(request)

    if request.state.auth_user is None:
        if request.method.upper() == "GET" and not path.startswith("/api/"):
            return RedirectResponse(url="/", status_code=303)
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    if auth_provider == "local_password" and request.state.requires_password_reset and not _is_password_reset_allowed_path(path):
        if request.method.upper() == "GET" and not path.startswith("/api/"):
            return RedirectResponse(url="/", status_code=303)
        return JSONResponse(status_code=403, content={"detail": "Password reset required", "requires_password_reset": True})

    return await call_next(request)


# Security: Add security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response


# Security: Input validation helpers
def sanitize_filename(filename: str) -> str:
    """Validate and sanitize filename to prevent path traversal."""
    # Get just the filename, removing any directory components
    filename = Path(filename).name
    
    # Whitelist alphanumeric, dash, underscore, dot
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        raise HTTPException(status_code=400, detail="Invalid filename format")
    
    # Validate file extension
    allowed_extensions = ['.md', '.json', '.txt', '.png', '.jpg', '.jpeg', '.webp', '.gif']
    if not any(filename.endswith(ext) for ext in allowed_extensions):
        raise HTTPException(status_code=400, detail="Invalid file extension")
    
    return filename


def validate_session_id(session_id: str) -> str:
    """Validate session ID format to prevent injection."""
    # Format: YYYYMMDD_HHMMSS (e.g., 20251027_120653)
    if not re.match(r'^\d{8}_\d{6}$', session_id):
        raise HTTPException(status_code=400, detail="Invalid session ID format")
    return session_id


def _resolve_websocket_authenticated_user(websocket: WebSocket) -> Optional[Dict[str, Any]]:
    if not is_auth_enabled():
        return None
    session_token = websocket.cookies.get(AUTH_SESSION_COOKIE_NAME, "")
    if not session_token:
        return None
    return security_manager.resolve_session(session_token)


class WebSocketDisplayManager:
    """Display manager that sends updates via WebSocket."""
    
    def __init__(self, scope_key: Optional[str] = None):
        self.verbose = True
        self.start_time = datetime.now()
        self.scope_key = _normalize_discovery_scope_key(scope_key)
    
    async def send_to_clients(self, message_type: str, data: Dict[str, Any]):
        """Send message to all connected WebSocket clients."""
        await _broadcast_websocket_message(message_type, data, self.scope_key)
    
    async def show_banner(self):
        banner_payload = {
            "title": "Splunk Discovery Tool",
            "subtitle": "Discovery run",
            "start_time": self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            "start_time_iso": self.start_time.isoformat(),
        }
        _append_discovery_runtime_activity("banner", banner_payload, scope_key=self.scope_key)
        await self.send_to_clients("banner", banner_payload)
    
    def phase(self, title: str):
        _advance_discovery_runtime_phase(title, scope_key=self.scope_key)
        snapshot = _append_discovery_runtime_activity("phase", {"title": title}, scope_key=self.scope_key)
        asyncio.create_task(_broadcast_discovery_runtime_state(snapshot, scope_key=self.scope_key))
        asyncio.create_task(self.send_to_clients("phase", {"title": title}))
    
    def success(self, message: str):
        _append_discovery_runtime_activity("success", {"message": message}, scope_key=self.scope_key)
        asyncio.create_task(self.send_to_clients("success", {"message": message}))
    
    def error(self, message: str):
        _append_discovery_runtime_activity("error", {"message": message}, scope_key=self.scope_key)
        asyncio.create_task(self.send_to_clients("error", {"message": message}))
    
    def warning(self, message: str):
        _append_discovery_runtime_activity("warning", {"message": message}, scope_key=self.scope_key)
        asyncio.create_task(self.send_to_clients("warning", {"message": message}))
    
    def info(self, message: str):
        _append_discovery_runtime_activity("info", {"message": message}, scope_key=self.scope_key)
        asyncio.create_task(self.send_to_clients("info", {"message": message}))
    
    def show_overview_summary(self, overview):
        overview_payload = {
            "total_indexes": overview.total_indexes,
            "total_sourcetypes": overview.total_sourcetypes,
            "data_volume_24h": _format_data_volume(overview.data_volume_24h),
            "active_sources": overview.active_sources,
            "estimated_time": overview.estimated_time,
            "notable_patterns": overview.notable_patterns
        }
        _append_discovery_runtime_activity("overview", overview_payload, scope_key=self.scope_key)
        asyncio.create_task(self.send_to_clients("overview", overview_payload))
    
    def show_classification_summary(self, classifications: Dict[str, Any]):
        _append_discovery_runtime_activity("classification", classifications, scope_key=self.scope_key)
        asyncio.create_task(self.send_to_clients("classification", classifications))
    
    def show_recommendations_preview(self, recommendations: List):
        recommendation_payload = {
            "count": len(recommendations),
            "top_recommendations": recommendations[:5]  # Show top 5
        }
        _append_discovery_runtime_activity("recommendations", recommendation_payload, scope_key=self.scope_key)
        asyncio.create_task(self.send_to_clients("recommendations", recommendation_payload))
    
    def show_suggested_use_cases_preview(self, use_cases: List):
        use_case_payload = {
            "count": len(use_cases),
            "preview": use_cases[:3]  # Show top 3
        }
        _append_discovery_runtime_activity("use_cases", use_case_payload, scope_key=self.scope_key)
        asyncio.create_task(self.send_to_clients("use_cases", use_case_payload))
    
    def show_final_summary(self, report_paths: List[str]):
        elapsed = datetime.now() - self.start_time
        completion_payload = {
            "duration": str(elapsed),
            "duration_seconds": round(elapsed.total_seconds()),
            "report_paths": report_paths,
            "report_count": len(report_paths),
        }
        _append_discovery_runtime_activity("completion", completion_payload, scope_key=self.scope_key)
        asyncio.create_task(self.send_to_clients("completion", completion_payload))
    
    async def handle_rate_limit_callback(self, event_type: str, data: Dict[str, Any]):
        await self.send_to_clients("rate_limit", {
            "event": event_type,
            "details": data
        })


class ProgressTracker:
    """Enhanced progress tracking with WebSocket updates."""
    
    def __init__(self, scope_key: Optional[str] = None):
        self.total_steps = 0
        self.current_step = 0
        self.current_phase = ""
        self.current_description = ""
        self.start_time = None
        self.scope_key = _normalize_discovery_scope_key(scope_key)
    
    def set_total_steps(self, total: int):
        self.total_steps = total
        self.start_time = datetime.now()
    
    async def update_progress(self, step: int, description: str = ""):
        self.current_step = step
        self.current_description = description
        
        if self.total_steps > 0:
            percentage = (step / self.total_steps) * 100

            progress_payload = {
                "percentage": percentage,
                "current_step": step,
                "total_steps": self.total_steps,
                "description": description,
                "eta_seconds": None,
                "eta_method": "stage_calibrated",
            }
            snapshot = _update_discovery_runtime_state(
                scope_key=self.scope_key,
                status="running",
                progress=progress_payload,
            )
            await _broadcast_websocket_message(
                "progress",
                snapshot.get("progress") or progress_payload,
                self.scope_key,
            )


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    auth_user = _resolve_websocket_authenticated_user(websocket)
    if is_auth_enabled() and not isinstance(auth_user, dict):
        await websocket.close(code=4401, reason="Authentication required")
        return

    scope_info = _build_discovery_scope_metadata(auth_user=auth_user)
    scope_key = scope_info.get("scope_key")

    await websocket.accept()
    _get_discovery_scope_connections(scope_key).append(websocket)

    _sync_runtime_state_from_disk()
    await websocket.send_text(
        json.dumps(
            _build_websocket_message(
                "discovery_status",
                _snapshot_discovery_runtime_state(scope_key),
            )
        )
    )
    
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        _remove_discovery_scope_connection(websocket, scope_key)


@app.websocket("/ws/debug")
async def debug_websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for debug log streaming (only if debug_mode enabled)."""
    config = config_manager.get()
    
    if not config.server.debug_mode:
        await websocket.close(code=1008, reason="Debug mode not enabled")
        return
    
    await websocket.accept()
    debug_connections.append(websocket)
    
    # Send initial connection message
    await websocket.send_json({
        "type": "connected",
        "message": "🐛 Debug mode active - streaming logs in real-time",
        "timestamp": datetime.now().isoformat()
    })
    
    try:
        while True:
            # Keep connection alive and handle incoming pings
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=0.1)
            except asyncio.TimeoutError:
                # Check for queued debug messages
                try:
                    debug_msg = debug_log_queue.get_nowait()
                    await websocket.send_json(debug_msg)
                except asyncio.QueueEmpty:
                    pass
    except WebSocketDisconnect:
        if websocket in debug_connections:
            debug_connections.remove(websocket)


@app.post("/start-discovery")
async def start_discovery(request: Request, background_tasks: BackgroundTasks):
    """Start the discovery process in the background."""
    global current_discovery_session

    _sync_runtime_state_from_disk()
    worker_binding = _build_discovery_runtime_binding(request=request)
    scope_info = _build_discovery_scope_metadata(request=request, runtime_binding=worker_binding)
    scope_key = scope_info.get("scope_key")
    active_snapshot = _snapshot_discovery_runtime_state(scope_key)
    if active_snapshot.get("status") in DISCOVERY_ACTIVE_STATUSES:
        return {"error": "Discovery already in progress", "discovery": active_snapshot}

    if current_discovery_session and not current_discovery_session.done():
        return {"error": "Discovery already in progress", "discovery": active_snapshot}

    try:
        worker_process = _launch_runtime_job_worker(
            "discovery",
            {
                "scope": scope_info,
                "runtime_binding": worker_binding,
                "requested_at": _utcnow_iso(),
                "pipeline_version": DISCOVERY_PIPELINE_VERSION,
            },
        )
    except Exception as exc:
        error_message = f"Failed to launch discovery worker: {exc}"
        discovery_snapshot = _finalize_discovery_runtime(
            "error",
            scope_key=scope_key,
            error=error_message,
            worker_pid=None,
            execution_mode="worker",
        )
        await _broadcast_discovery_runtime_state(discovery_snapshot, scope_key=scope_key)
        raise HTTPException(status_code=500, detail=error_message)

    current_discovery_session = None
    discovery_started_at = _utcnow_iso()
    phase_plan = _prime_discovery_phase_plan_for_start(
        DISCOVERY_PIPELINE_VERSION,
        started_at=discovery_started_at,
    )
    bootstrap_phase = phase_plan[0] if phase_plan else None
    discovery_snapshot = _update_discovery_runtime_state(
        scope_key=scope_key,
        reset=True,
        scope_label=scope_info.get("scope_label"),
        active_mcp_config_name=scope_info.get("active_mcp_config_name"),
        status="starting",
        session_id=worker_process.pid,
        worker_pid=worker_process.pid,
        execution_mode="worker",
        pipeline_version=DISCOVERY_PIPELINE_VERSION,
        started_at=discovery_started_at,
        completed_at=None,
        result_timestamp=None,
        report_count=0,
        error=None,
        current_phase_key=bootstrap_phase.get("key") if bootstrap_phase else None,
        current_phase_title=(bootstrap_phase.get("title") or bootstrap_phase.get("label")) if bootstrap_phase else None,
        phase_plan=phase_plan,
        activity_log=[],
        last_run_outcome=None,
        progress={
            "percentage": 0,
            "current_step": 0,
            "total_steps": 0,
            "description": "Preparing discovery...",
            "eta_seconds": None,
            "eta_method": "stage_calibrated",
        },
    )
    discovery_snapshot = _append_discovery_runtime_activity(
        "info",
        {
            "message": "Discovery started in a background process. Progress is saved as it runs.",
            "worker_pid": worker_process.pid,
        },
        scope_key=scope_key,
    )
    await _broadcast_discovery_runtime_state(discovery_snapshot, scope_key=scope_key)

    return {
        "status": "Discovery started",
        "session_id": worker_process.pid,
        "worker_pid": worker_process.pid,
        "discovery": discovery_snapshot,
        "runtime_binding": {
            "active_mcp_config_name": worker_binding.get("active_mcp_config_name"),
            "clear_runtime_mcp": bool(worker_binding.get("clear_runtime_mcp")),
        },
        "scope": scope_info,
    }


@app.post("/abort-discovery")
async def abort_discovery(request: Request):
    """Abort the current discovery process."""
    global current_discovery_session

    _sync_runtime_state_from_disk()
    scope_info = _build_discovery_scope_metadata(request=request)
    scope_key = scope_info.get("scope_key")
    snapshot = _snapshot_discovery_runtime_state(scope_key)
    has_in_process_task = bool(current_discovery_session and not current_discovery_session.done())
    has_worker_process = snapshot.get("status") in DISCOVERY_ACTIVE_STATUSES and _is_process_running(snapshot.get("worker_pid"))
    if not has_in_process_task and not has_worker_process:
        return {"error": "No discovery in progress"}

    if has_in_process_task:
        current_discovery_session.cancel()

    worker_pid = _coerce_process_id(snapshot.get("worker_pid"))
    if worker_pid is not None and not _terminate_runtime_worker_process(worker_pid):
        raise HTTPException(status_code=500, detail="Failed to stop discovery worker")

    _update_discovery_runtime_state(
        scope_key=scope_key,
        progress={
            **(snapshot.get("progress") or {}),
            "description": "Discovery stopped by operator.",
        },
    )
    discovery_snapshot = _finalize_discovery_runtime(
        "aborted",
        scope_key=scope_key,
        error="Discovery aborted by user",
        worker_pid=None,
    )
    await _broadcast_websocket_message("warning", {"message": "⚠️ Discovery aborted by user"}, scope_key)
    await _broadcast_discovery_runtime_state(discovery_snapshot, scope_key=scope_key)

    return {"status": "Discovery aborted", "discovery": discovery_snapshot}


async def run_discovery(
    runtime_config: Any = None,
    *,
    scope_key: Optional[str] = None,
    scope_info: Optional[Dict[str, Any]] = None,
):
    """Run the complete discovery process with WebSocket updates."""
    display = None
    normalized_scope_key = _normalize_discovery_scope_key(scope_key)
    resolved_scope_info = copy.deepcopy(scope_info or {})
    try:
        if _is_runtime_worker_process():
            _sync_runtime_state_from_disk()
            _update_discovery_runtime_state(
                scope_key=normalized_scope_key,
                status="starting",
                worker_pid=os.getpid(),
                execution_mode="worker",
            )
        else:
            _update_discovery_runtime_state(scope_key=normalized_scope_key, execution_mode="inline")

        # Load configuration
        config = runtime_config or config_manager.get()
        if not resolved_scope_info:
            resolved_scope_info = {
                "scope_key": normalized_scope_key,
                "scope_label": "Global" if normalized_scope_key == DISCOVERY_SCOPE_GLOBAL else normalized_scope_key,
                "active_mcp_config_name": getattr(config, "active_mcp_config_name", None),
            }
        
        # Initialize display manager with WebSocket support
        display = WebSocketDisplayManager(normalized_scope_key)
        await display.show_banner()
        
        # Validate MCP configuration
        if not config.mcp.url:
            display.error("❌ MCP Server URL not configured. Please configure your Splunk MCP server in Settings.")
            raise Exception("MCP Server URL not configured")
        
        if not config.mcp.token:
            display.error("❌ MCP Server token not configured. Please configure your Splunk authentication token in Settings.")
            raise Exception("MCP Server token not configured")
        
        # Debug: Check if API key is loaded
        debug_log(f"Config loaded - provider: {config.llm.provider}, model: {config.llm.model}", "info")
        debug_log(f"API key present: {bool(config.llm.api_key)}, length: {len(config.llm.api_key) if config.llm.api_key else 0}", "info")

        discovered_mcp_tools = await discover_mcp_tools(config)
        available_mcp_tools = set(discovered_mcp_tools or ()) or {
            "splunk_run_query",
            "splunk_get_info",
            "splunk_get_indexes",
            "splunk_get_index_info",
            "splunk_get_metadata",
            "splunk_get_user_info",
            "splunk_get_knowledge_objects"
        }
        available_mcp_tools_sorted = sorted(list(available_mcp_tools))
        
        # Initialize LLM client (cached for performance)
        llm_client = get_or_create_llm_client(config)
        display.success("✅ LLM client initialized")
        
        # Only a real tools/list result is shared with the engine; with the fallback set it lists tools itself.
        discovery_engine = DiscoveryEngine(
            mcp_url=config.mcp.url,
            mcp_token=config.mcp.token,
            llm_client=llm_client,
            verify_ssl=config.mcp.verify_ssl,
            ca_bundle_path=config.mcp.ca_bundle_path,
            available_tools=discovered_mcp_tools or None,
            tool_schemas=get_cached_mcp_tool_metadata(config).get("schemas") if discovered_mcp_tools else None,
        )
        display.success("✅ Discovery engine initialized")
        
        # Initialize progress tracker
        progress = ProgressTracker(normalized_scope_key)

        if DISCOVERY_PIPELINE_VERSION == "v2":
            display.phase("🚀 Preparing discovery")
            v2_pipeline = DiscoveryV2Pipeline(
                discovery_engine,
                output_root=_discovery_scope_output_dir(normalized_scope_key),
            )
            v2_result = await v2_pipeline.run(display, progress)

            overview = v2_result.get("overview")
            classifications = v2_result.get("classifications", {})
            recommendations = v2_result.get("recommendations", [])
            suggested_use_cases = v2_result.get("suggested_use_cases", [])
            report_paths = v2_result.get("report_paths", [])
            timestamp = v2_result.get("timestamp") or datetime.now().strftime("%Y%m%d_%H%M%S")
            discovery_step_count = _safe_int(v2_result.get("discovery_step_count", 0))
            artifact_payload = v2_result.get("artifact_payload") if isinstance(v2_result.get("artifact_payload"), dict) else {}
            llm_status = v2_result.get("llm_status") if isinstance(v2_result.get("llm_status"), dict) else {}
            pipeline_errors = v2_result.get("pipeline_errors") if isinstance(v2_result.get("pipeline_errors"), list) else []
            discovery_quality = build_discovery_quality(llm_status, pipeline_errors, artifact_payload)

            # The pipeline's evidence-weighted score is the one written to the blueprint; keep the UI consistent with it.
            readiness_score = artifact_payload.get("readiness_score")
            if not isinstance(readiness_score, int) or isinstance(readiness_score, bool):
                readiness_score = compute_discovery_readiness_score(
                    overview,
                    recommendations if isinstance(recommendations, list) else [],
                    suggested_use_cases if isinstance(suggested_use_cases, list) else [],
                    {
                        "tool_count": len(available_mcp_tools_sorted),
                        "tools": available_mcp_tools_sorted
                    }
                )
            persona_playbooks = build_persona_playbooks(
                overview,
                recommendations if isinstance(recommendations, list) else [],
                suggested_use_cases if isinstance(suggested_use_cases, list) else [],
                {
                    "tool_count": len(available_mcp_tools_sorted),
                    "tools": available_mcp_tools_sorted
                },
                readiness_score=readiness_score,
            )

            session_record = register_discovery_session(
                timestamp=timestamp,
                overview=overview,
                report_paths=report_paths,
                mcp_capabilities={
                    "tool_count": len(available_mcp_tools_sorted),
                    "tools": available_mcp_tools_sorted
                },
                classifications=classifications if isinstance(classifications, dict) else {},
                recommendations=recommendations if isinstance(recommendations, list) else [],
                suggested_use_cases=suggested_use_cases if isinstance(suggested_use_cases, list) else [],
                discovery_step_count=discovery_step_count,
                personas=persona_playbooks,
                readiness_score=readiness_score,
                discovery_scope=resolved_scope_info,
                discovery_quality=discovery_quality,
            )

            if discovery_quality["status"] == "partial":
                display.warning(
                    "⚠️ Discovery finished with gaps: "
                    + ", ".join((discovery_quality["failed_steps"] + [str(item.get("stage", item)) if isinstance(item, dict) else str(item) for item in discovery_quality["pipeline_errors"]])[:8])
                    + ". The readiness score reflects the missing evidence."
                )
            display.success("✅ Discovery reports saved")
            display.show_final_summary(report_paths)

            _update_discovery_runtime_state(
                scope_key=normalized_scope_key,
                progress={
                    "percentage": 100,
                    "current_step": 100,
                    "total_steps": 100,
                    "description": "Discovery complete. Outputs are ready for review.",
                    "eta_seconds": 0,
                    "eta_method": "stage_calibrated",
                },
            )
            discovery_snapshot = _finalize_discovery_runtime(
                "completed",
                scope_key=normalized_scope_key,
                report_count=len(report_paths),
                result_timestamp=timestamp,
            )
            await _broadcast_discovery_runtime_state(discovery_snapshot, scope_key=normalized_scope_key)

            return {
                "status": "success",
                "overview": overview.__dict__ if hasattr(overview, '__dict__') else overview,
                "classifications": classifications,
                "recommendations": recommendations,
                "suggested_use_cases": suggested_use_cases,
                "session": session_record,
                "readiness_score": readiness_score,
                "score_basis": artifact_payload.get("score_basis", {}),
                "llm_status": llm_status,
                "pipeline_errors": pipeline_errors,
                "discovery_quality": discovery_quality,
                "persona_playbooks": persona_playbooks,
                "mcp_capabilities": {
                    "tool_count": len(available_mcp_tools_sorted),
                    "tools": available_mcp_tools_sorted
                },
                "report_paths": report_paths,
                "timestamp": timestamp
            }
        
        # Phase 1: Quick Overview
        display.phase("🔍 Phase 1: Quick Architecture Overview")
        display.info("🔄 Getting initial environment overview...")
        
        overview = await discovery_engine.get_quick_overview()
        progress.set_total_steps(overview.estimated_discovery_steps)
        
        display.success("✅ Getting initial environment overview... - completed")
        display.show_overview_summary(overview)
        
        # Phase 2: Detailed Discovery
        display.phase("🕵️ Phase 2: Detailed Environment Discovery")
        
        step = 0
        async for result in discovery_engine.discover_environment():
            step += 1
            await progress.update_progress(step, result.description)
        
        # Phase 3: Classification
        display.phase("🏷️ Phase 3: Data Classification and Analysis")
        display.info("🔄 Classifying discovered data...")
        
        classifications = await discovery_engine.classify_data()
        display.success("✅ Classifying discovered data... - completed")
        display.show_classification_summary(classifications)
        
        # Phase 4: Recommendations
        display.phase("💡 Phase 4: Generating Use Case Recommendations")
        display.info("🔄 Generating intelligent recommendations...")
        
        recommendations = await discovery_engine.generate_recommendations()
        display.success("✅ Generating intelligent recommendations... - completed")
        display.show_recommendations_preview(recommendations)
        
        # Phase 5: Cross-functional Use Cases
        display.phase("💡 Phase 5: Generating Cross-Functional Use Case Suggestions")
        display.info("🔄 Analyzing data source combinations for creative use cases...")
        
        try:
            suggested_use_cases = await discovery_engine.generate_suggested_use_cases()
            display.success("✅ Analyzing data source combinations for creative use cases... - completed")
            display.show_suggested_use_cases_preview(suggested_use_cases)
        except Exception as e:
            display.error(f"❌ Suggested use case generation failed: {str(e)}")
            display.info("🔄 Continuing with available analysis...")
            suggested_use_cases = []
        
        # Phase 6: Export Reports
        display.phase("📝 Phase 6: Exporting Discovery Reports")
        display.info("🔄 Generating report files...")
        
        # Generate timestamp for this session
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create output directory if it doesn't exist
        output_dir = _discovery_scope_output_dir(normalized_scope_key)
        output_dir.mkdir(exist_ok=True)
        
        report_paths = []
        readiness_score = compute_discovery_readiness_score(
            overview,
            recommendations if isinstance(recommendations, list) else [],
            suggested_use_cases if isinstance(suggested_use_cases, list) else [],
            {
                "tool_count": len(available_mcp_tools_sorted),
                "tools": available_mcp_tools_sorted
            }
        )
        persona_playbooks = build_persona_playbooks(
            overview,
            recommendations if isinstance(recommendations, list) else [],
            suggested_use_cases if isinstance(suggested_use_cases, list) else [],
            {
                "tool_count": len(available_mcp_tools_sorted),
                "tools": available_mcp_tools_sorted
            }
        )
        
        # Export JSON data
        try:
            # Get raw discovery results for SPL generation
            discovery_results = discovery_engine.get_all_results()
            discovery_results_dict = [
                {
                    "step": r.step,
                    "description": r.description,
                    "data": r.data,
                    "interesting_findings": r.interesting_findings,
                    "timestamp": r.timestamp.isoformat() if hasattr(r.timestamp, 'isoformat') else str(r.timestamp)
                }
                for r in discovery_results
            ]
            
            json_export_path = output_dir / f"discovery_export_{timestamp}.json"
            with open(json_export_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "overview": overview.__dict__ if hasattr(overview, '__dict__') else overview,
                    "classifications": classifications,
                    "recommendations": recommendations,
                    "suggested_use_cases": suggested_use_cases,
                    "readiness_score": readiness_score,
                    "persona_playbooks": persona_playbooks,
                    "mcp_capabilities": {
                        "tool_count": len(available_mcp_tools_sorted),
                        "tools": available_mcp_tools_sorted
                    },
                    "discovery_results": discovery_results_dict,
                    "timestamp": timestamp
                }, f, indent=2, default=str)
            report_paths.append(str(json_export_path.name))
            display.info(f"   ✓ {json_export_path.name} (includes {len(discovery_results_dict)} discovery items)")
        except Exception as e:
            display.error(f"   ✗ Failed to export JSON: {str(e)}")
        
        # Export Executive Summary
        try:
            mcp_capability_path = output_dir / f"mcp_capabilities_{timestamp}.md"
            with open(mcp_capability_path, 'w', encoding='utf-8') as f:
                f.write(f"# MCP Capability Snapshot\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Discovered Tool Count:** {len(available_mcp_tools_sorted)}\n\n")
                f.write("## Available Tools\n\n")
                for tool_name in available_mcp_tools_sorted:
                    description = MCP_TOOL_DESCRIPTIONS.get(tool_name, "MCP tool available for Splunk operations.")
                    f.write(f"- **{tool_name}**: {description}\n")
            report_paths.append(str(mcp_capability_path.name))
            display.info(f"   ✓ {mcp_capability_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export MCP capabilities snapshot: {str(e)}")

        # Export persona playbooks for admins/analysts/executives
        try:
            persona_json_path = output_dir / f"persona_playbooks_{timestamp}.json"
            with open(persona_json_path, 'w', encoding='utf-8') as f:
                json.dump(persona_playbooks, f, indent=2, default=str)
            report_paths.append(str(persona_json_path.name))
            display.info(f"   ✓ {persona_json_path.name}")

            persona_md_path = output_dir / f"persona_playbooks_{timestamp}.md"
            with open(persona_md_path, 'w', encoding='utf-8') as f:
                f.write("# Persona Playbooks\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Readiness Score:** {readiness_score}/100\n\n")

                admin_actions = persona_playbooks.get("admin", {}).get("actions", [])
                analyst_hypotheses = persona_playbooks.get("analyst", {}).get("hypotheses", [])
                executive = persona_playbooks.get("executive", {})

                f.write("## Admin Action Queue\n\n")
                for idx, action in enumerate(admin_actions[:6], 1):
                    f.write(f"{idx}. **{action.get('title', 'Action')}**\n")
                    for label, key in (("Why", "why"), ("Effort", "effort"), ("Next Step", "next_step")):
                        if action.get(key):
                            f.write(f"   - {label}: {action[key]}\n")
                    f.write("\n")

                f.write("## Analyst Investigation Tracks\n\n")
                for idx, hypothesis in enumerate(analyst_hypotheses[:6], 1):
                    f.write(f"{idx}. **{hypothesis.get('title', 'Track')}**\n")
                    for label, key in (("Question", "question"), ("Metric", "success_metric")):
                        if hypothesis.get(key):
                            f.write(f"   - {label}: {hypothesis[key]}\n")
                    data_sources = hypothesis.get('data_sources', [])
                    if isinstance(data_sources, list) and data_sources:
                        f.write(f"   - Data Sources: {', '.join(str(s) for s in data_sources[:6])}\n")
                    f.write("\n")

                f.write("## Executive Brief\n\n")
                f.write(f"- **Readiness Score:** {executive.get('platform_readiness_score', readiness_score)}/100\n")
                f.write(f"- **Headline:** {executive.get('headline', '')}\n")
                for theme in executive.get('business_value_themes', []):
                    f.write(f"  - Value Theme: {theme}\n")
                f.write("\n")
                if executive.get('next_90_day_focus'):
                    f.write("### Next 90 Days\n\n")
                for item in executive.get('next_90_day_focus', []):
                    f.write(f"- {item}\n")
            report_paths.append(str(persona_md_path.name))
            display.info(f"   ✓ {persona_md_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export persona playbooks: {str(e)}")

        # Export Executive Summary
        try:
            exec_summary_path = output_dir / f"executive_summary_{timestamp}.md"
            with open(exec_summary_path, 'w', encoding='utf-8') as f:
                f.write(f"# Splunk Environment Discovery - Executive Summary\n\n")
                f.write(f"**Discovery Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

                f.write(f"## MCP Capability Snapshot\n\n")
                f.write(f"- **Discovered Tools:** {len(available_mcp_tools_sorted)}\n")
                for tool_name in available_mcp_tools_sorted:
                    f.write(f"  - `{tool_name}`\n")
                f.write(f"\n")
                
                # Environment Overview
                f.write(f"## Environment Overview\n\n")
                if hasattr(overview, 'total_indexes'):
                    f.write(f"- **Total Indexes:** {overview.total_indexes}\n")
                    f.write(f"- **Total Source Types:** {overview.total_sourcetypes}\n")
                    f.write(f"- **Total Hosts:** {overview.total_hosts}\n")
                    f.write(f"- **Total Sources:** {overview.total_sources}\n")
                    f.write(f"- **24h Data Volume:** {_format_data_volume(overview.data_volume_24h)}\n")
                    if overview.splunk_version:
                        f.write(f"- **Splunk Version:** {overview.splunk_version} (Build: {overview.splunk_build})\n")
                    if overview.license_state:
                        f.write(f"- **License State:** {overview.license_state}\n")
                    if overview.server_roles:
                        f.write(f"- **Server Roles:** {', '.join(overview.server_roles)}\n")
                    f.write(f"\n")
                
                # Top Priority Recommendations
                f.write(f"## Top Priority Recommendations\n\n")
                high_priority = [r for r in recommendations if isinstance(r, dict) and r.get('priority') == 'high'][:5]
                if high_priority:
                    for idx, rec in enumerate(high_priority, 1):
                        f.write(f"### {idx}. {rec.get('title', 'Recommendation')}\n\n")
                        f.write(f"**Priority:** {rec.get('priority', 'N/A')} | ")
                        f.write(f"**Category:** {rec.get('category', 'N/A')} | ")
                        f.write(f"**Complexity:** {rec.get('complexity', 'N/A')}\n\n")
                        f.write(f"{rec.get('description', '')}\n\n")
                else:
                    f.write("_No high-priority recommendations identified._\n\n")
                
                # Data Classification Summary
                f.write(f"## Data Classification Summary\n\n")
                if isinstance(classifications, dict):
                    for category, items in classifications.items():
                        if items and len(items) > 0:
                            f.write(f"**{category.replace('_', ' ').title()}:** {len(items)} items\n")
                    f.write(f"\n")
                
                # Cross-Functional Use Cases
                if suggested_use_cases:
                    f.write(f"## Recommended Cross-Functional Use Cases\n\n")
                    for idx, use_case in enumerate(suggested_use_cases[:3], 1):
                        if isinstance(use_case, dict):
                            f.write(f"### {idx}. {use_case.get('title', 'Use Case')}\n\n")
                            f.write(f"**Category:** {use_case.get('category', 'N/A')} | ")
                            f.write(f"**Complexity:** {use_case.get('complexity', 'N/A')}\n\n")
                            f.write(f"{use_case.get('description', '')}\n\n")
                            if use_case.get('data_sources'):
                                f.write(f"**Data Sources:** {', '.join(use_case['data_sources'])}\n\n")
                
                # Discovery Statistics
                discovery_results = discovery_engine.get_all_results()
                f.write(f"## Discovery Statistics\n\n")
                f.write(f"- **Total Discovery Steps:** {len(discovery_results)}\n")
                f.write(f"- **Analysis Time:** {overview.estimated_time if hasattr(overview, 'estimated_time') else 'N/A'}\n")
                f.write(f"- **Notable Patterns:** {len(overview.notable_patterns) if hasattr(overview, 'notable_patterns') else 0}\n\n")
                
            report_paths.append(str(exec_summary_path.name))
            display.info(f"   ✓ {exec_summary_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export executive summary: {str(e)}")
        
        # Export Detailed Discovery
        try:
            detailed_path = output_dir / f"detailed_discovery_{timestamp}.md"
            with open(detailed_path, 'w', encoding='utf-8') as f:
                f.write(f"# Detailed Discovery Report\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Get discovery results
                discovery_results = discovery_engine.get_all_results()
                
                f.write(f"## Discovery Overview\n\n")
                f.write(f"Total discovery steps completed: {len(discovery_results)}\n\n")
                
                # Write each discovery step
                for result in discovery_results:
                    f.write(f"### Step {result.step}: {result.description}\n\n")
                    f.write(f"**Timestamp:** {result.timestamp}\n\n")
                    
                    # Interesting findings
                    if result.interesting_findings:
                        f.write(f"**Key Findings:**\n")
                        for finding in result.interesting_findings:
                            f.write(f"- {finding}\n")
                        f.write(f"\n")
                    
                    # Data details (formatted)
                    if result.data:
                        f.write(f"**Data Details:**\n\n")
                        if isinstance(result.data, dict):
                            for key, value in result.data.items():
                                if isinstance(value, (list, dict)):
                                    f.write(f"- **{key}:** {len(value)} items\n")
                                else:
                                    f.write(f"- **{key}:** {value}\n")
                        f.write(f"\n")
                    
                    f.write(f"---\n\n")
                
            report_paths.append(str(detailed_path.name))
            display.info(f"   ✓ {detailed_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export detailed discovery: {str(e)}")
        
        # Export Data Classification
        try:
            classification_path = output_dir / f"data_classification_{timestamp}.md"
            with open(classification_path, 'w', encoding='utf-8') as f:
                f.write(f"# Data Classification Report\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                if isinstance(classifications, dict):
                    for category, items in classifications.items():
                        f.write(f"## {category.replace('_', ' ').title()}\n\n")
                        if items and len(items) > 0:
                            f.write(f"**Total Items:** {len(items)}\n\n")
                            for item in items:
                                if isinstance(item, dict):
                                    f.write(f"### {item.get('name', item.get('title', 'Item'))}\n\n")
                                    for key, value in item.items():
                                        if key not in ['name', 'title'] and value:
                                            f.write(f"- **{key.replace('_', ' ').title()}:** {value}\n")
                                    f.write(f"\n")
                                elif isinstance(item, str):
                                    f.write(f"- {item}\n")
                            f.write(f"\n")
                        else:
                            f.write("_No items classified in this category._\n\n")
                else:
                    f.write("_Classification data not available._\n\n")
                    
            report_paths.append(str(classification_path.name))
            display.info(f"   ✓ {classification_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export classifications: {str(e)}")
        
        # Export Recommendations
        try:
            recommendations_path = output_dir / f"recommendations_{timestamp}.md"
            with open(recommendations_path, 'w', encoding='utf-8') as f:
                f.write(f"# Recommendations Report\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for idx, rec in enumerate(recommendations[:10], 1):
                    if isinstance(rec, dict):
                        f.write(f"## {idx}. {rec.get('title', 'Recommendation')}\n\n")
                        f.write(f"**Priority:** {rec.get('priority', 'N/A')}\n\n")
                        f.write(f"{rec.get('description', '')}\n\n")
            report_paths.append(str(recommendations_path.name))
            display.info(f"   ✓ {recommendations_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export recommendations: {str(e)}")
        
        # Export Suggested Use Cases
        try:
            use_cases_path = output_dir / f"suggested_use_cases_{timestamp}.md"
            with open(use_cases_path, 'w', encoding='utf-8') as f:
                f.write(f"# Suggested Use Cases\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for idx, uc in enumerate(suggested_use_cases[:10], 1):
                    if isinstance(uc, dict):
                        f.write(f"## {idx}. {uc.get('title', 'Use Case')}\n\n")
                        f.write(f"{uc.get('description', '')}\n\n")
            report_paths.append(str(use_cases_path.name))
            display.info(f"   ✓ {use_cases_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export use cases: {str(e)}")
        
        # Export Implementation Guide
        try:
            impl_guide_path = output_dir / f"implementation_guide_{timestamp}.md"
            with open(impl_guide_path, 'w', encoding='utf-8') as f:
                f.write(f"# Implementation Guide\n\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"## Quick Start\n\n")
                f.write(f"This guide provides implementation steps for the recommended use cases.\n\n")
                f.write(f"## Priority Recommendations\n\n")
                for idx, rec in enumerate([r for r in recommendations if isinstance(r, dict) and r.get('priority') == 'high'][:5], 1):
                    f.write(f"### {idx}. {rec.get('title', 'Recommendation')}\n\n")
                    f.write(f"{rec.get('description', '')}\n\n")
            report_paths.append(str(impl_guide_path.name))
            display.info(f"   ✓ {impl_guide_path.name}")
        except Exception as e:
            display.error(f"   ✗ Failed to export implementation guide: {str(e)}")
        
        display.success(f"✅ Generated {len(report_paths)} report files")

        discovery_results = discovery_engine.get_all_results()
        session_record = register_discovery_session(
            timestamp=timestamp,
            overview=overview,
            report_paths=report_paths,
            mcp_capabilities={
                "tool_count": len(available_mcp_tools_sorted),
                "tools": available_mcp_tools_sorted
            },
            classifications=classifications if isinstance(classifications, dict) else {},
            recommendations=recommendations if isinstance(recommendations, list) else [],
            suggested_use_cases=suggested_use_cases if isinstance(suggested_use_cases, list) else [],
            discovery_step_count=len(discovery_results),
            personas=persona_playbooks,
            readiness_score=readiness_score,
            discovery_scope=resolved_scope_info,
        )
        
        # Phase 7: Complete Discovery
        display.phase("✅ Discovery Complete")
        display.success("✅ All discovery phases completed successfully")
        
        # Send completion message to frontend
        await display.send_to_clients("completion", {
            "message": "Discovery completed successfully",
            "report_count": len(report_paths),
            "timestamp": timestamp
        })

        _update_discovery_runtime_state(
            scope_key=normalized_scope_key,
            progress={
                "percentage": 100,
                "current_step": 100,
                "total_steps": 100,
                "description": "Discovery complete. Outputs are ready for review.",
                "eta_seconds": 0,
                "eta_method": "stage_calibrated",
            },
        )
        discovery_snapshot = _finalize_discovery_runtime(
            "completed",
            scope_key=normalized_scope_key,
            report_count=len(report_paths),
            result_timestamp=timestamp,
        )
        await _broadcast_discovery_runtime_state(discovery_snapshot, scope_key=normalized_scope_key)
        
        # Return completion status
        return {
            "status": "completed",
            "overview": overview,
            "classifications": classifications,
            "recommendations": recommendations,
            "suggested_use_cases": suggested_use_cases,
            "session": session_record,
            "readiness_score": readiness_score,
            "persona_playbooks": persona_playbooks,
            "mcp_capabilities": {
                "tool_count": len(available_mcp_tools_sorted),
                "tools": available_mcp_tools_sorted
            },
            "report_paths": report_paths,
            "timestamp": timestamp
        }
        
    except asyncio.CancelledError:
        # User aborted the discovery
        print("Discovery cancelled by user")
        current_snapshot = _snapshot_discovery_runtime_state(normalized_scope_key)
        _update_discovery_runtime_state(
            scope_key=normalized_scope_key,
            progress={
                **(current_snapshot.get("progress") or {}),
                "description": "Discovery stopped by operator.",
            },
        )
        discovery_snapshot = _finalize_discovery_runtime(
            "aborted",
            scope_key=normalized_scope_key,
            error="Discovery aborted by user",
        )
        if display:
            await display.send_to_clients("warning", {
                "message": "⚠️ Discovery aborted by user",
                "type": "user_abort"
            })
        await _broadcast_discovery_runtime_state(discovery_snapshot, scope_key=normalized_scope_key)
        raise  # Re-raise to properly cancel the task
    
    except Exception as e:
        import traceback
        error_message = f"Discovery failed: {str(e)}"
        traceback_str = traceback.format_exc()
        print(f"ERROR in run_discovery: {error_message}")
        print(f"Traceback: {traceback_str}")

        current_snapshot = _snapshot_discovery_runtime_state(normalized_scope_key)

        _update_discovery_runtime_state(
            scope_key=normalized_scope_key,
            progress={
                **(current_snapshot.get("progress") or {}),
                "description": error_message,
            },
        )
        discovery_snapshot = _finalize_discovery_runtime(
            "error",
            scope_key=normalized_scope_key,
            error=str(e),
        )
        
        if display:
            await display.send_to_clients("error", {
                "message": error_message,
                "type": "fatal_error"
            })
        else:
            # Fallback if display is not initialized
            for connection in _get_discovery_scope_connections(normalized_scope_key):
                try:
                    await connection.send_json({
                        "type": "error",
                        "data": {"message": error_message}
                    })
                except:
                    pass
        await _broadcast_discovery_runtime_state(discovery_snapshot, scope_key=normalized_scope_key)
        return {"status": "error", "message": str(e)}


@app.get("/reports")
async def list_reports(request: Request):
    """Get the list of available discovery reports."""
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    sessions = load_discovery_sessions(scope_key=scope_key)
    reports = _build_accessible_report_metadata(scope_key)
    return {
        "reports": reports,
        "sessions": sessions
    }


@app.get("/api/discovery/sessions")
async def get_discovery_sessions(request: Request):
    """Return persisted discovery sessions for history UI and retrieval."""
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    sessions = load_discovery_sessions(scope_key=scope_key)
    return {
        "sessions": sessions,
        "count": len(sessions)
    }


@app.get("/api/discovery/sessions/{timestamp}")
async def get_discovery_session(timestamp: str, request: Request):
    """Return a specific discovery session and resolved report metadata."""
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    sessions = load_discovery_sessions(scope_key=scope_key)
    session = _require_accessible_discovery_session(timestamp, scope_key=scope_key, sessions=sessions)
    session_scope_key = _get_discovery_session_scope_key(session)

    files = []
    for report_name in session.get("report_paths", []):
        try:
            report_path = _resolve_output_artifact_path(report_name, session_scope_key)
        except HTTPException:
            report_path = None
        files.append({
            "name": report_name,
            "exists": report_path.exists() if report_path else False,
            "size": report_path.stat().st_size if report_path and report_path.exists() else 0,
            "modified": datetime.fromtimestamp(report_path.stat().st_mtime).isoformat() if report_path and report_path.exists() else None,
            "type": report_path.suffix[1:].lower() if report_path and report_path.suffix else "unknown",
            "artifact_kind": "infographic" if report_name.startswith(SUMMARY_INFOGRAPHIC_PREFIX) else "report",
        })

    return {
        "session": session,
        "files": files
    }


@app.get("/api/discovery/dashboard")
async def get_discovery_dashboard(request: Request):
    """Return latest discovery intelligence dashboard payload for UI hub."""
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    return build_discovery_dashboard_payload(scope_key=scope_key)


@app.get("/api/discovery/status")
async def get_discovery_runtime_status(request: Request):
    """Return current discovery runtime status for header and workspace hydration."""
    _sync_runtime_state_from_disk()
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    return _snapshot_discovery_runtime_state(scope_key)


@app.get("/api/v2/intelligence")
async def get_v2_intelligence(request: Request):
    """Return the latest intelligence blueprint for the workspace UI."""
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    payload = load_latest_v2_blueprint(scope_key=scope_key)
    if not payload:
        return {"has_data": False, "message": "No intelligence blueprint found."}
    overview = payload.get("overview", {}) if isinstance(payload.get("overview", {}), dict) else {}
    return {
        "has_data": True,
        "blueprint": payload,
        "artifact": payload.get("_artifact", {}),
        "notable_patterns": _normalize_v2_notable_patterns_for_ui(overview.get("notable_patterns", []), limit=6),
    }


class M2614ValidationRequest(BaseModel):
    pack_id: str
    timestamp: Optional[str] = None
    earliest: str = "-30d"
    latest: str = "now"


@app.get("/api/v2/artifacts")
async def get_v2_artifacts(request: Request):
    """Return the artifact catalog for the workspace view."""
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    return build_v2_artifact_catalog(scope_key=scope_key)


@app.get("/api/discovery/compare")
async def get_discovery_compare(request: Request, current: Optional[str] = None, baseline: Optional[str] = None):
    """Return comparative metrics between two discovery sessions."""
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    return build_discovery_compare_payload(current, baseline, scope_key=scope_key)


@app.get("/api/discovery/m26-14/profile")
async def get_m26_14_profile(request: Request, timestamp: Optional[str] = None):
    """Return the latest or selected M-26-14 advisor profile."""
    require_authenticated_user(request)
    _require_m26_14_enabled(refresh_health=True)
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    return build_m26_14_profile_payload(timestamp=timestamp, scope_key=scope_key)


@app.get("/api/discovery/m26-14/compare")
async def get_m26_14_compare(request: Request, current: Optional[str] = None, baseline: Optional[str] = None):
    """Return comparative metrics between two M-26-14 advisor profiles."""
    require_authenticated_user(request)
    _require_m26_14_enabled(refresh_health=False)
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    return build_m26_14_compare_payload(current_selection=current, baseline_selection=baseline, scope_key=scope_key)


@app.get("/api/discovery/m26-14/validation-packs")
async def get_m26_14_validation_packs(request: Request):
    """Return the curated live-validation pack catalog for the M-26-14 advisor."""
    require_authenticated_user(request)
    capability_state = _require_m26_14_enabled(refresh_health=False)
    return {
        "status": "success",
        "capability": {
            "health_status": capability_state.get("health_status"),
            "health_message": capability_state.get("health_message"),
        },
        "packs": list_m26_14_validation_packs(),
    }


@app.post("/api/discovery/m26-14/validate")
async def run_m26_14_validation(request: Request, validation_request: M2614ValidationRequest):
    """Execute one curated M-26-14 validation SPL pack against the active runtime MCP connection."""
    require_analyst_or_admin_user(request)
    capability_state = _require_m26_14_enabled(refresh_health=False)

    validation_pack = get_m26_14_validation_pack(validation_request.pack_id)
    if validation_pack is None:
        raise HTTPException(status_code=404, detail=f"There is no M-26-14 check named '{validation_request.pack_id}'.")

    runtime_config = resolve_effective_runtime_config(request=request)
    if not str(getattr(runtime_config.mcp, "url", "") or "").strip():
        raise HTTPException(status_code=503, detail="Live checks need a Splunk MCP server. Add one in Settings, then try again.")

    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    cache_key = _build_m26_14_validation_cache_key(
        validation_pack,
        validation_request,
        runtime_config,
        scope_key=scope_key,
    )
    cached_response = _get_cached_m26_14_validation_result(cache_key)
    if cached_response is not None:
        cached_response["from_cache"] = True
        cached_response["cache_key"] = cache_key
        return cached_response

    tool_result = await execute_mcp_tool_call(
        {
            "method": "tools/call",
            "params": {
                "name": "splunk_run_query",
                "arguments": {
                    "query": validation_pack.get("query"),
                    "earliest_time": validation_request.earliest,
                    "latest_time": validation_request.latest,
                },
            },
        },
        runtime_config,
    )

    if isinstance(tool_result, dict) and tool_result.get("error"):
        return JSONResponse(
            status_code=int(tool_result.get("status_code") or 502),
            content={
                "status": "error",
                "pack": validation_pack,
                "message": str(tool_result.get("error") or "The M-26-14 check could not run."),
                "detail": tool_result.get("detail"),
            },
        )

    normalized_result = extract_results_from_mcp_response(tool_result)
    rows = normalized_result.get("results", []) if isinstance(normalized_result.get("results", []), list) else []
    validation_summary = summarize_m26_14_validation_results(validation_pack, rows)
    advisory_payload = await _build_m26_14_validation_advisory_payload(
        validation_pack,
        validation_request,
        validation_summary,
        rows,
        capability_state,
        scope_key=scope_key,
    )
    response_payload = {
        "status": "success",
        "pack": validation_pack,
        "query": validation_pack.get("query"),
        "time_range": {
            "earliest": validation_request.earliest,
            "latest": validation_request.latest,
        },
        "cache_key": cache_key,
        "cached_at": datetime.now().isoformat(),
        "from_cache": False,
        "result": {
            "status_code": normalized_result.get("status_code"),
            "error_message": normalized_result.get("error_message"),
            "rows": rows,
            "summary": validation_summary,
        },
        "advisory": advisory_payload,
    }
    _store_cached_m26_14_validation_result(cache_key, response_payload)
    return response_payload


@app.get("/api/discovery/runbook")
async def get_discovery_runbook(request: Request, timestamp: Optional[str] = None, persona: str = "admin", voice: str = "direct"):
    """Return persona-scoped operational runbook for a selected discovery session."""
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    return build_session_runbook_payload(timestamp, persona, _normalize_operator_voice(voice), scope_key=scope_key)


@app.get("/api/discovery/results")
async def get_discovery_results(request: Request):
    """
    Discovery results summary endpoint for latest session.
    """
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    sessions = load_discovery_sessions(scope_key=scope_key)
    latest = sessions[0] if sessions else None
    return {
        "message": "Discovery sessions are persisted and available via /api/discovery/sessions.",
        "reports_endpoint": "/reports",
        "sessions_endpoint": "/api/discovery/sessions",
        "latest_session": latest
    }


@app.get("/reports/{filename}")
async def get_report(filename: str, request: Request):
    """Get a specific report file with security validation."""
    try:
        scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
        file_path = _resolve_accessible_output_artifact_path(filename, scope_key)
        
        if file_path.suffix.lower() == ".json":
            with open(file_path, 'r', encoding='utf-8') as f:
                content = json.load(f)
            return {
                "content": content,
                "type": "json",
                "spl_queries": extract_spl_queries_from_payload(content),
            }
        if file_path.suffix.lower() in IMAGE_ARTIFACT_EXTENSIONS:
            image_format = 'jpeg' if file_path.suffix.lower() == '.jpg' else file_path.suffix[1:].lower()
            return {
                "type": "image",
                "mime_type": f"image/{image_format}",
                "content_base64": base64.b64encode(file_path.read_bytes()).decode('ascii'),
            }
        else:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return {
                "content": content,
                "type": "text",
                "spl_queries": extract_spl_queries_from_text(content),
            }
    except HTTPException:
        raise
    except Exception as e:
        # Security: Don't leak file system details
        raise HTTPException(status_code=500, detail="Failed to read report")


@app.get("/connection-info")
async def get_connection_info(request: Request):
    """Get current LLM and MCP server connection information (DT4SMS version)."""
    try:
        config = resolve_effective_runtime_config(request=request)
        llm_configured, _ = _is_llm_available_for_m26_14_advisory(config)
        active_credential_name = str(getattr(config, "active_credential_name", "") or "").strip()
        llm_display_label = active_credential_name or (str(config.llm.model or "").strip() if llm_configured else "")
        mcp_endpoint = str(config.mcp.url or "").strip()
        mcp_configured = bool(mcp_endpoint and str(config.mcp.token or "").strip())
        
        # Get LLM info (no sensitive data)
        llm_provider = normalize_provider_name(config.llm.provider)
        
        # Determine endpoint display based on provider
        if not llm_configured:
            llm_endpoint = ""
        elif llm_provider == "openai":
            llm_endpoint = "OpenAI API (api.openai.com)"
        elif llm_provider == "anthropic":
            llm_endpoint = config.llm.endpoint_url or "Anthropic API (api.anthropic.com)"
        elif llm_provider == "gemini":
            llm_endpoint = config.llm.endpoint_url or "Gemini API (generativelanguage.googleapis.com)"
        elif llm_provider == "azure":
            llm_endpoint = config.llm.endpoint_url or "Azure OpenAI endpoint"
        elif config.llm.endpoint_url:
            llm_endpoint = config.llm.endpoint_url
        else:
            llm_endpoint = f"{llm_provider} API"
        
        llm_info = {
            "provider": llm_provider.upper(),
            "model": str(config.llm.model or "").strip() if llm_configured else "",
            "endpoint": llm_endpoint,
            "display_label": llm_display_label,
            "configured": llm_configured,
        }
        
        # Get MCP server info (no sensitive data)
        mcp_info = {
            "endpoint": mcp_endpoint if mcp_configured else "",
            "configured": mcp_configured,
        }

        status = "connected" if llm_configured and mcp_configured else "partial" if llm_configured or mcp_configured else "disconnected"
        
        return {
            "llm": llm_info,
            "mcp": mcp_info,
            "status": status,
        }
    except Exception as e:
        print(f"Error loading connection info: {e}")
        import traceback
        traceback.print_exc()
        return {
            "llm": {"provider": "ERROR", "model": "Check logs", "endpoint": str(e)},
            "mcp": {"endpoint": "Error loading config"},
            "status": "error"
        }

# DT4SMS: Configuration API Endpoints and Models
class MCPSettings(BaseModel):
    url: str
    token: Optional[str] = None
    verify_ssl: bool = False
    ca_bundle_path: Optional[str] = None

class LLMSettings(BaseModel):
    provider: str
    api_key: Optional[str] = None
    model: str
    endpoint_url: Optional[str] = None
    max_tokens: int = 16000
    temperature: float = 0.7
    auto_tune: bool = True
    context_window: int = Field(default=0, ge=0, le=10_000_000)
    request_timeout: int = Field(default=0, ge=0, le=3600)
    reasoning_effort: str = Field(default="", pattern="^(|minimal|low|medium|high)$")

class ServerSettings(BaseModel):
    port: int
    host: str
    cors_origins: List[str]
    trusted_hosts: List[str]
    debug_mode: Optional[bool] = False

class OIDCSettings(BaseModel):
    issuer_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    audience: Optional[str] = None
    scopes: List[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    username_claim: str = "preferred_username"
    email_claim: str = "email"
    role_claim: str = "roles"
    default_role: str = Field(default="viewer", pattern="^(admin|analyst|viewer)$")
    mcp_assignment_claim: Optional[str] = None

class SecuritySettings(BaseModel):
    auth_enabled: bool = False
    auth_provider: str = Field(default="local_password", pattern="^(local_password|oidc)$")
    external_api_enabled: bool = False
    external_mcp_enabled: bool = False
    external_api_rate_limit_requests: int = Field(default=DEFAULT_EXTERNAL_API_RATE_LIMIT_REQUESTS, ge=1, le=10000)
    external_api_rate_limit_window_seconds: int = Field(default=DEFAULT_EXTERNAL_API_RATE_LIMIT_WINDOW_SECONDS, ge=1, le=3600)
    external_mcp_rate_limit_requests: int = Field(default=DEFAULT_EXTERNAL_MCP_RATE_LIMIT_REQUESTS, ge=1, le=10000)
    external_mcp_rate_limit_window_seconds: int = Field(default=DEFAULT_EXTERNAL_MCP_RATE_LIMIT_WINDOW_SECONDS, ge=1, le=3600)
    session_timeout_minutes: int = Field(default=480, ge=15, le=10080)
    password_min_length: int = Field(default=12, ge=8, le=256)
    require_password_reset_on_first_login: bool = True
    oidc: OIDCSettings = Field(default_factory=OIDCSettings)

class ConfigUpdate(BaseModel):
    mcp: Optional[MCPSettings] = None
    llm: Optional[LLMSettings] = None
    server: Optional[ServerSettings] = None
    security: Optional[SecuritySettings] = None


class AuthLoginRequest(BaseModel):
    username: str
    password: str


class PasswordResetRequest(BaseModel):
    current_password: str
    new_password: str
    confirm_password: str


class SecurityUserCreateRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"
    is_enabled: bool = True
    require_password_reset: bool = True
    mcp_config_name: Optional[str] = None


class SecurityUserUpdateRequest(BaseModel):
    username: Optional[str] = None
    new_password: Optional[str] = None
    role: Optional[str] = None
    is_enabled: Optional[bool] = None
    require_password_reset: Optional[bool] = None
    mcp_config_name: Optional[str] = None


class SecurityExternalIdentityLinkRequest(BaseModel):
    auth_provider: str = "oidc"
    subject: str
    email: Optional[str] = None
    claims: Optional[Dict[str, Any]] = None


class SecurityTokenCreateRequest(BaseModel):
    name: str
    token_type: str = "external_api"
    scopes: List[str]
    owner_user_id: Optional[int] = None
    expires_at: Optional[str] = None
    expires_in_days: Optional[int] = None


class CapabilityConfigUpdate(BaseModel):
    config: Dict[str, Any]


class CapabilityInstallRequest(BaseModel):
    strategy: Optional[str] = None


class CapabilityDeeplinkBuildRequest(BaseModel):
    query: str
    earliest: Optional[str] = None
    latest: Optional[str] = None
    app: Optional[str] = None
    link_type: str = "search"


class CapabilityExportBuildRequest(BaseModel):
    timestamp: Optional[str] = None
    persona: str = "admin"
    voice: str = "direct"
    artifact_names: List[str] = []
    title: Optional[str] = None
    runbook_markdown: Optional[str] = None
    runbook_filename: Optional[str] = None


class RAGKnowledgeAssetImportRequest(BaseModel):
    title: str
    content: str
    asset_type: str = "reference_document"
    source_label: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = []
    attributes: Dict[str, Any] = Field(default_factory=dict)


class RAGContextPreviewRequest(BaseModel):
    query: str
    limit: int = 4


class ExternalRAGSearchRequest(BaseModel):
    query: str
    limit: int = 4


class SummaryInfographicRequest(BaseModel):
    timestamp: str
    summary_data: Dict[str, Any] = {}


def _parse_knowledge_asset_tags(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in re.split(r"[,\n]", str(value or "")) if item.strip()]


def normalize_openai_api_base_url(endpoint_url: Optional[str]) -> str:
    """Normalize an OpenAI endpoint to a reusable API base path."""
    normalized_base = (endpoint_url or "https://api.openai.com/v1").rstrip("/")
    for suffix in ["/chat/completions", "/responses", "/models", "/images/generations"]:
        if normalized_base.endswith(suffix):
            normalized_base = normalized_base[:-len(suffix)]
    return normalized_base


def build_openai_api_url(endpoint_url: Optional[str], path: str) -> str:
    """Build a full OpenAI REST URL while tolerating base or full-path config values."""
    normalized_path = "/" + str(path or "").lstrip("/")
    base_url = normalize_openai_api_base_url(endpoint_url)
    if base_url.endswith("/v1"):
        return f"{base_url}{normalized_path}"
    return f"{base_url}/v1{normalized_path}"


def openai_model_ids_include(model_ids: Any, target_model: str) -> bool:
    """Return True when the target model ID exists in an OpenAI models payload."""
    target = str(target_model or "").strip().lower()
    if not target:
        return False

    for model_id in model_ids or []:
        if isinstance(model_id, str) and model_id.strip().lower() == target:
            return True
    return False


def _compact_summary_entries(items: Any, limit: int, keys: Tuple[str, ...]) -> List[Dict[str, Any]]:
    compact_items: List[Dict[str, Any]] = []
    if not isinstance(items, list):
        return compact_items

    for item in items:
        if not isinstance(item, dict):
            continue
        compact_item: Dict[str, Any] = {}
        for key in keys:
            value = item.get(key)
            if value in (None, "", [], {}):
                continue
            compact_item[key] = value
        if compact_item:
            compact_items.append(compact_item)
        if len(compact_items) >= limit:
            break
    return compact_items


def truncate_prompt_text(value: str, max_chars: int, suffix: str = "\n... [truncated for API safety]") -> str:
    """Trim prompt fragments to a safe size while leaving a visible truncation marker."""
    text = str(value or "")
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    if max_chars <= len(suffix):
        return text[:max_chars]
    return text[: max_chars - len(suffix)].rstrip() + suffix


def build_summary_infographic_brief(timestamp: str, summary_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Create a compact, image-oriented brief from the full summary payload."""
    payload = summary_data if isinstance(summary_data, dict) else {}
    v2_context = payload.get("v2_context") if isinstance(payload.get("v2_context"), dict) else {}
    context_explorer = payload.get("context_explorer") if isinstance(payload.get("context_explorer"), dict) else {}
    context_anchors = context_explorer.get("anchors") if isinstance(context_explorer.get("anchors"), dict) else {}
    context_lanes = context_explorer.get("lanes") if isinstance(context_explorer.get("lanes"), dict) else {}

    return {
        "session_id": timestamp,
        "report_title": "Splunk Discovery Tool Executive Summary",
        "readiness_score": payload.get("readiness_score", v2_context.get("readiness_score")),
        "executive_summary": str(payload.get("ai_summary") or "").strip(),
        "stats": payload.get("stats") if isinstance(payload.get("stats"), dict) else {},
        "trend_signals": payload.get("trend_signals") if isinstance(payload.get("trend_signals"), dict) else {},
        "risk_register": _compact_summary_entries(payload.get("risk_register"), 6, ("severity", "domain", "risk", "impact", "mitigation")),
        "coverage_gaps": _compact_summary_entries(payload.get("coverage_gaps"), 6, ("priority", "domain", "gap", "recommended_action", "impact")),
        "priority_tasks": _compact_summary_entries(payload.get("admin_tasks"), 6, ("priority", "category", "title", "description", "impact")),
        "unknown_data": _compact_summary_entries(payload.get("unknown_data"), 8, ("type", "name", "question")),
        "spl_queries": _compact_summary_entries(payload.get("spl_queries"), 8, ("title", "category", "finding_reference", "query_source", "spl")),
        "context_explorer": {
            "overview": context_explorer.get("overview") if isinstance(context_explorer.get("overview"), dict) else {},
            "patterns": context_explorer.get("patterns", [])[:6] if isinstance(context_explorer.get("patterns"), list) else [],
            "anchors": {
                "indexes": _compact_summary_entries(context_anchors.get("indexes"), 8, ("name", "volume_category", "count", "reason")),
                "sourcetypes": _compact_summary_entries(context_anchors.get("sourcetypes"), 8, ("name", "volume_category", "count", "reason")),
                "hosts": _compact_summary_entries(context_anchors.get("hosts"), 8, ("name", "count", "reason")),
            },
            "lanes": {
                "unknown_entities": _compact_summary_entries(context_lanes.get("unknown_entities"), 6, ("type", "name", "question")),
                "coverage_gaps": _compact_summary_entries(context_lanes.get("coverage_gaps"), 6, ("priority", "gap", "recommended_action")),
                "risks": _compact_summary_entries(context_lanes.get("risks"), 6, ("severity", "risk", "impact")),
                "priority_tasks": _compact_summary_entries(context_lanes.get("priority_tasks"), 6, ("priority", "title", "category", "impact")),
            },
        },
    }

def build_summary_infographic_prompt(timestamp: str, summary_data: Optional[Dict[str, Any]]) -> str:
    """Build a rich prompt for turning the summary into a single infographic."""
    payload = summary_data if isinstance(summary_data, dict) else {}
    brief = build_summary_infographic_brief(timestamp, payload)
    brief_json = truncate_prompt_text(
        json.dumps(brief, indent=2, ensure_ascii=False),
        MAX_INFOGRAPHIC_BRIEF_CHARS,
    )
    prompt_prefix = f"""Create a polished single-page infographic poster for a Splunk discovery executive report.

Goal:
- Turn the supplied Splunk Discovery Tool summary into an executive-ready infographic.
- Keep every fact anchored to the provided summary.
- Prefer clear sectioning, concise labels, and high information density.
- Do not invent vendors, data sources, metrics, logos, incident claims, or counts that are not in the source material.

Design direction:
- Modern enterprise operations and security briefing board
- One-page landscape infographic
- Strong title hierarchy, summary KPI band, risks, coverage gaps, action queue, and next review loop
- Mix cards, labeled callouts, a simple process band, and tasteful analytical visuals where useful
- Use a restrained palette with indigo, slate, amber, red, and emerald accents
- Make it visually impressive but operational, not playful
- Render all text cleanly and legibly in English

Must include when available:
- Session identifier
- Readiness score and top operating signals
- Priority actions and quick wins
- Risk register highlights
- Coverage gaps
- Priority tasks and action queue
- Context explorer anchors or patterns
- Recursive or next-loop guidance

Output constraints:
- Single image only
- No screenshots, browser chrome, or fake application UI
- No fabricated percentages or extra counts
- If an item is unclear, omit it rather than hallucinating
- Keep names of indexes, sourcetypes, tasks, and control areas exact

Session ID: {timestamp}

Curated brief:
{brief_json}

Full summary payload (truncated only if needed for API safety):
"""
    full_payload_budget = max(0, MAX_INFOGRAPHIC_SUMMARY_CHARS - len(prompt_prefix))
    full_payload = truncate_prompt_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        full_payload_budget,
        "\n... [summary payload truncated for API safety]",
    )
    return f"{prompt_prefix}{full_payload}"

@app.get("/api/config")
async def get_config(request: Request):
    """Get current configuration (safe export with masked secrets)"""
    require_admin_user(request)
    payload = config_manager.export_safe()
    try:
        payload["llm_effective_tuning"] = _tuning_summary(resolve_active_llm_tuning(config_manager.get()))
    except Exception as tuning_error:
        print(f"[Config] Could not resolve effective LLM tuning: {tuning_error}")
    return payload

@app.post("/api/config")
async def update_config(request: Request, config_update: ConfigUpdate):
    """Update configuration"""
    require_admin_user(request)
    try:
        # Update MCP settings
        if config_update.mcp:
            try:
                update_data = config_update.mcp.dict(exclude_unset=True)
                if 'token' in update_data and is_unset_secret(update_data['token']):
                    update_data.pop('token')
                if update_data:
                    success = config_manager.update_mcp(**update_data)
                    if not success:
                        raise HTTPException(status_code=500, detail="Failed to save MCP configuration")
            except HTTPException:
                raise
            except Exception as e:
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=f"MCP config error: {str(e)}")

        # Update LLM settings
        if config_update.llm:
            try:
                update_data = config_update.llm.dict(exclude_unset=True)
                if 'api_key' in update_data and is_unset_secret(update_data['api_key']):
                    update_data.pop('api_key')
                if update_data:
                    success = config_manager.update_llm(**update_data)
                    if not success:
                        raise HTTPException(status_code=500, detail="Failed to save LLM configuration")
            except HTTPException:
                raise
            except Exception as e:
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=f"LLM config error: {str(e)}")

        # Update server settings
        if config_update.server:
            try:
                success = config_manager.update_server(**config_update.server.dict(exclude_unset=True))
                if not success:
                    raise HTTPException(status_code=500, detail="Failed to save server configuration")
            except HTTPException:
                raise
            except Exception as e:
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=f"Server config error: {str(e)}")

        # Update security settings
        if config_update.security:
            try:
                security_update_data = (
                    config_update.security.model_dump(exclude_unset=True)
                    if hasattr(config_update.security, "model_dump")
                    else config_update.security.dict(exclude_unset=True)
                )
                current_security = get_security_config()
                next_auth_enabled = bool(
                    security_update_data.get(
                        "auth_enabled",
                        getattr(current_security, "auth_enabled", False) if current_security else False,
                    )
                )
                next_auth_provider = str(
                    security_update_data.get(
                        "auth_provider",
                        getattr(current_security, "auth_provider", "local_password") if current_security else "local_password",
                    )
                    or "local_password"
                ).strip().lower()

                next_oidc_settings = _snapshot_oidc_settings(getattr(current_security, "oidc", None) if current_security else None)
                incoming_oidc_settings = security_update_data.get("oidc") if isinstance(security_update_data.get("oidc"), dict) else {}
                for field_name, field_value in incoming_oidc_settings.items():
                    if field_name == "client_secret" and str(field_value or "").strip() in {"", "***"}:
                        continue
                    next_oidc_settings[field_name] = field_value

                if next_auth_enabled and next_auth_provider == "oidc":
                    if not all(
                        [
                            str(next_oidc_settings.get("issuer_url") or "").strip(),
                            str(next_oidc_settings.get("client_id") or "").strip(),
                            str(next_oidc_settings.get("client_secret") or "").strip(),
                        ]
                    ):
                        raise HTTPException(
                            status_code=400,
                            detail="OIDC authentication requires issuer_url, client_id, and client_secret before it can be enabled",
                        )
                success = config_manager.update_security(**security_update_data)
                if not success:
                    raise HTTPException(status_code=500, detail="Failed to save security configuration")
            except HTTPException:
                raise
            except Exception as e:
                import traceback
                traceback.print_exc()
                raise HTTPException(status_code=500, detail=f"Security config error: {str(e)}")

        # Reload config
        config_manager._config = config_manager.load()
        if config_update.security:
            ensure_local_auth_bootstrap_state()
        capability_manager.refresh()

        return {"status": "success", "message": "Configuration updated successfully"}

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to update configuration: {str(e)}")


@app.get("/api/auth/status")
async def get_auth_status(request: Request):
    """Return auth mode and current session state for the active request."""
    security_config = get_security_config()
    if is_auth_enabled() and get_auth_provider() == "local_password":
        ensure_local_auth_bootstrap_state()

    current_user = _serialize_authenticated_user(getattr(request.state, "auth_user", None))
    auth_provider_status = {
        "local_password": {
            "implemented": True,
            "configured": True,
            "ready": True,
            "can_enable_auth": True,
        },
        "oidc": _build_oidc_provider_status(),
    }
    return {
        "auth_enabled": is_auth_enabled(),
        "auth_provider": get_auth_provider(),
        "authenticated": current_user is not None,
        "password_reset_required": bool(getattr(request.state, "requires_password_reset", False)),
        "demo_mode": not is_auth_enabled(),
        "user": current_user,
        "session_timeout_minutes": getattr(security_config, "session_timeout_minutes", None) if security_config else None,
        "auth_provider_status": auth_provider_status,
    }


def _issue_auth_session_response(
    request: Request,
    payload: Dict[str, Any],
    user_id: int,
    timeout_minutes: int,
    redirect_to: Optional[str] = None,
):
    session = security_manager.create_session(user_id=user_id, timeout_minutes=timeout_minutes)
    if redirect_to:
        response = RedirectResponse(url=redirect_to, status_code=303)
    else:
        response = JSONResponse(payload)

    response.set_cookie(
        key=AUTH_SESSION_COOKIE_NAME,
        value=session["session_token"],
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        max_age=max(60, timeout_minutes * 60),
        path="/",
    )
    return response


@app.post("/api/auth/login")
async def login(request: Request, login_request: AuthLoginRequest):
    """Authenticate a local user and issue a session cookie."""
    if not is_auth_enabled():
        raise HTTPException(status_code=400, detail="Authentication is not enabled")
    if get_auth_provider() != "local_password":
        raise HTTPException(status_code=400, detail="Use the configured OIDC sign-in flow instead of local username/password login")

    security_config = get_security_config()
    ensure_local_auth_bootstrap_state()
    user = security_manager.authenticate_local_user(login_request.username, login_request.password)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    timeout_minutes = int(getattr(security_config, "session_timeout_minutes", 480) or 480)
    response = _issue_auth_session_response(
        request=request,
        payload={
            "status": "success",
            "message": "Signed in successfully",
            "password_reset_required": bool(user.get("require_password_reset")),
            "user": _serialize_authenticated_user(user),
        },
        user_id=int(user["id"]),
        timeout_minutes=timeout_minutes,
    )
    return response


@app.get("/api/auth/oidc/start")
async def start_oidc_login(request: Request):
    """Start the OIDC authorization-code flow for the configured provider."""
    if not is_auth_enabled() or get_auth_provider() != "oidc":
        raise HTTPException(status_code=404, detail="OIDC authentication is not enabled")

    provider_status = _build_oidc_provider_status()
    if not provider_status.get("ready"):
        raise HTTPException(status_code=503, detail="OIDC configuration is incomplete")

    oidc_settings = _snapshot_oidc_settings()
    provider_metadata = await load_oidc_provider_metadata(oidc_settings)
    redirect_uri = str(request.url_for("complete_oidc_login"))
    nonce = secrets.token_urlsafe(24)
    state = oidc_login_state_store.issue({"redirect_uri": redirect_uri, "nonce": nonce})

    query = {
        "client_id": oidc_settings["client_id"],
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": " ".join(oidc_settings["scopes"] or ["openid", "profile", "email"]),
        "state": state,
        "nonce": nonce,
    }
    if oidc_settings["audience"]:
        query["audience"] = oidc_settings["audience"]

    authorization_url = f"{str(provider_metadata.get('authorization_endpoint') or '').strip()}?{urlencode(query)}"
    return RedirectResponse(url=authorization_url, status_code=303)


@app.get("/api/auth/oidc/callback")
async def complete_oidc_login(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None):
    """Complete the OIDC authorization-code flow and issue a normal app session."""
    if not is_auth_enabled() or get_auth_provider() != "oidc":
        raise HTTPException(status_code=404, detail="OIDC authentication is not enabled")

    if str(error or "").strip():
        return HTMLResponse(
            content=build_auth_error_page("OIDC sign-in failed", f"Identity provider returned an error: {str(error).strip()}"),
            status_code=400,
        )

    state_record = oidc_login_state_store.consume(str(state or ""))
    if state_record is None:
        return HTMLResponse(
            content=build_auth_error_page("OIDC sign-in failed", "The sign-in attempt is missing state or has expired. Start the flow again."),
            status_code=400,
        )

    if not str(code or "").strip():
        return HTMLResponse(
            content=build_auth_error_page("OIDC sign-in failed", "The identity provider did not return an authorization code."),
            status_code=400,
        )

    oidc_settings = _snapshot_oidc_settings()
    try:
        provider_metadata = await load_oidc_provider_metadata(oidc_settings)
        redirect_uri = str(state_record.get("redirect_uri") or request.url_for("complete_oidc_login"))
        token_payload = _validate_oidc_token_payload(
            await exchange_oidc_authorization_code(oidc_settings, provider_metadata, str(code or "").strip(), redirect_uri)
        )
        id_token_claims = await _validate_oidc_id_token_claims(token_payload, provider_metadata, oidc_settings, state_record)
        claims = await fetch_oidc_userinfo(provider_metadata, str(token_payload.get("access_token") or "").strip())
        _validate_oidc_subject_coherence(id_token_claims, claims)
        identity = _resolve_oidc_identity_fields(claims, oidc_settings)
        user = security_manager.resolve_or_provision_external_user(
            auth_provider="oidc",
            subject=identity["subject"],
            preferred_username=identity["username"],
            email=identity["email"],
            role=identity["role"],
            mcp_config_name=validate_assigned_mcp_config_name(identity["mcp_config_name"]),
            claims=claims,
            sync_role=bool(identity.get("sync_role")),
            sync_mcp_config_name=bool(identity.get("sync_mcp_config_name")),
        )
    except ValueError as exc:
        security_manager.record_audit_event("oidc_login_failed", details={"reason": str(exc)})
        return HTMLResponse(content=build_auth_error_page("OIDC sign-in failed", str(exc)), status_code=400)
    except httpx.HTTPError as exc:
        security_manager.record_audit_event("oidc_login_failed", details={"reason": str(exc)})
        return HTMLResponse(content=build_auth_error_page("OIDC sign-in failed", "Failed to contact the configured identity provider."), status_code=502)

    if not isinstance(user, dict) or not bool(user.get("is_enabled")):
        security_manager.record_audit_event(
            "oidc_login_failed",
            username=user.get("username") if isinstance(user, dict) else None,
            user_id=int(user["id"]) if isinstance(user, dict) and user.get("id") is not None else None,
            details={"reason": "user_disabled_or_missing"},
        )
        return HTMLResponse(
            content=build_auth_error_page("OIDC sign-in denied", "The linked Splunk Discovery Tool user is disabled or no longer exists."),
            status_code=403,
        )

    security_config = get_security_config()
    timeout_minutes = int(getattr(security_config, "session_timeout_minutes", 480) or 480)
    return _issue_auth_session_response(
        request=request,
        payload={
            "status": "success",
            "message": "OIDC sign-in completed",
            "password_reset_required": False,
            "user": _serialize_authenticated_user(user),
        },
        user_id=int(user["id"]),
        timeout_minutes=timeout_minutes,
        redirect_to="/",
    )


@app.post("/api/auth/logout")
async def logout(request: Request):
    """Revoke the current session and clear the auth cookie."""
    auth_provider = get_auth_provider() if is_auth_enabled() else "local_password"
    session_token = request.cookies.get(AUTH_SESSION_COOKIE_NAME, "")
    if session_token:
        security_manager.revoke_session(session_token)

    provider_logout = {
        "provider": auth_provider,
        "supported": False,
        "mode": "local_session_only",
        "url": None,
        "post_logout_redirect_uri": None,
        "reason": "local_session_only",
    }
    if is_auth_enabled() and auth_provider == "oidc":
        provider_logout = await _build_oidc_logout_plan(request)

    response = JSONResponse({"status": "success", "message": "Signed out", "provider_logout": provider_logout})
    response.delete_cookie(AUTH_SESSION_COOKIE_NAME, path="/")
    return response


@app.post("/api/auth/reset-password")
async def reset_password(request: Request, reset_request: PasswordResetRequest):
    """Allow an authenticated local user to reset their password."""
    if not is_auth_enabled():
        raise HTTPException(status_code=400, detail="Authentication is not enabled")
    if get_auth_provider() != "local_password":
        raise HTTPException(status_code=400, detail="Password resets are only available for local-password authentication")
    current_user = getattr(request.state, "auth_user", None)
    if not isinstance(current_user, dict):
        raise HTTPException(status_code=401, detail="Authentication required")

    security_config = get_security_config()
    minimum_length = int(getattr(security_config, "password_min_length", 12) or 12)
    new_password = str(reset_request.new_password or "")
    if new_password != str(reset_request.confirm_password or ""):
        raise HTTPException(status_code=400, detail="New password confirmation does not match")
    if len(new_password) < minimum_length:
        raise HTTPException(status_code=400, detail=f"New password must be at least {minimum_length} characters long")
    if not security_manager.verify_user_password(int(current_user["id"]), reset_request.current_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if not security_manager.update_password(int(current_user["id"]), new_password, require_password_reset=False):
        raise HTTPException(status_code=500, detail="Failed to update password")

    updated_user = security_manager.get_user_by_id(int(current_user["id"]))
    request.state.auth_user = updated_user
    request.state.requires_password_reset = False
    return {
        "status": "success",
        "message": "Password updated successfully",
        "password_reset_required": False,
        "user": _serialize_authenticated_user(updated_user),
    }


@app.get("/api/security/users")
async def list_security_users(request: Request):
    """List local security users for admin management."""
    require_admin_user(request)
    users = [_serialize_security_user_record(user) for user in security_manager.list_users()]
    return {"users": users, "count": len(users)}


@app.post("/api/security/users")
async def create_security_user(request: Request, user_request: SecurityUserCreateRequest):
    """Create a local user and optionally assign an MCP connection definition."""
    require_admin_user(request)
    security_config = get_security_config()
    minimum_length = int(getattr(security_config, "password_min_length", 12) or 12)
    if len(str(user_request.password or "")) < minimum_length:
        raise HTTPException(status_code=400, detail=f"Password must be at least {minimum_length} characters long")

    try:
        user = security_manager.create_user(
            username=user_request.username,
            password=user_request.password,
            role=user_request.role,
            is_enabled=user_request.is_enabled,
            require_password_reset=user_request.require_password_reset,
            mcp_config_name=validate_assigned_mcp_config_name(user_request.mcp_config_name),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "status": "success",
        "message": f"User '{user['username']}' created",
        "user": _serialize_security_user_record(user),
    }


@app.get("/api/security/users/{user_id}")
async def get_security_user(request: Request, user_id: int):
    """Load one local security user for admin management."""
    require_admin_user(request)
    user = security_manager.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return _serialize_security_user_record(user)


@app.patch("/api/security/users/{user_id}")
async def update_security_user(request: Request, user_id: int, user_update: SecurityUserUpdateRequest):
    """Update a local user, including role, enablement, password reset, and MCP assignment."""
    require_admin_user(request)
    update_data = user_update.model_dump(exclude_unset=True) if hasattr(user_update, "model_dump") else user_update.dict(exclude_unset=True)

    if "new_password" in update_data:
        new_password = str(update_data.get("new_password") or "")
        security_config = get_security_config()
        minimum_length = int(getattr(security_config, "password_min_length", 12) or 12)
        if len(new_password) < minimum_length:
            raise HTTPException(status_code=400, detail=f"Password must be at least {minimum_length} characters long")
        if "require_password_reset" not in update_data:
            update_data["require_password_reset"] = True

    if "mcp_config_name" in update_data:
        update_data["mcp_config_name"] = validate_assigned_mcp_config_name(update_data.get("mcp_config_name"))

    try:
        user = security_manager.update_user(user_id, **update_data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "status": "success",
        "message": f"User '{user['username']}' updated",
        "user": _serialize_security_user_record(user),
    }


@app.post("/api/security/users/{user_id}/external-identities")
async def link_security_user_external_identity(
    request: Request,
    user_id: int,
    identity_request: SecurityExternalIdentityLinkRequest,
):
    """Explicitly link an external identity to an existing local user for admin-driven migration flows."""
    require_admin_user(request)
    target_user = security_manager.get_user_by_id(user_id)
    if target_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        user = security_manager.link_external_identity(
            user_id=user_id,
            auth_provider=identity_request.auth_provider,
            subject=identity_request.subject,
            email=identity_request.email,
            claims=identity_request.claims,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    identity = security_manager.get_external_identity(identity_request.auth_provider, identity_request.subject)
    return {
        "status": "success",
        "message": f"External identity linked to user '{user['username']}'",
        "user": _serialize_security_user_record(user),
        "external_identity": _serialize_external_identity_record(identity),
    }


@app.delete("/api/security/users/{user_id}")
async def delete_security_user(request: Request, user_id: int):
    """Delete a local user while preserving at least one enabled admin."""
    require_admin_user(request)
    try:
        deleted = security_manager.delete_user(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not deleted:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "success", "message": "User deleted"}


@app.get("/api/security/tokens")
async def list_security_tokens(request: Request):
    """List inbound access tokens for admin review without re-exposing plaintext secrets."""
    require_admin_user(request)
    tokens = [_serialize_security_token_record(token) for token in security_manager.list_access_tokens()]
    return {"tokens": tokens, "count": len(tokens)}


@app.post("/api/security/tokens")
async def create_security_token(request: Request, token_request: SecurityTokenCreateRequest):
    """Issue a new inbound access token and reveal the plaintext value exactly once."""
    current_admin = require_admin_user(request)
    try:
        issued = security_manager.issue_access_token(
            name=token_request.name,
            token_type=token_request.token_type,
            scopes=token_request.scopes,
            owner_user_id=token_request.owner_user_id,
            created_by_user_id=int(current_admin["id"]) if isinstance(current_admin, dict) else None,
            expires_at=token_request.expires_at,
            expires_in_days=token_request.expires_in_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "status": "success",
        "message": f"Token '{issued['token']['name']}' created",
        "access_token": issued["access_token"],
        "token": _serialize_security_token_record(issued["token"]),
    }


@app.get("/api/security/tokens/{token_id}")
async def get_security_token(request: Request, token_id: int):
    """Load one token record for admin inspection without exposing the plaintext token."""
    require_admin_user(request)
    token = security_manager.get_access_token(token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Token not found")
    return _serialize_security_token_record(token)


@app.post("/api/security/tokens/{token_id}/revoke")
async def revoke_security_token(request: Request, token_id: int):
    """Revoke an inbound access token."""
    current_admin = require_admin_user(request)
    try:
        revoked = security_manager.revoke_access_token(
            token_id,
            revoked_by_user_id=int(current_admin["id"]) if isinstance(current_admin, dict) else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not revoked:
        raise HTTPException(status_code=404, detail="Token not found")
    token = security_manager.get_access_token(token_id)
    return {
        "status": "success",
        "message": "Token revoked",
        "token": _serialize_security_token_record(token),
    }


@app.delete("/api/security/tokens/{token_id}")
async def delete_security_token(request: Request, token_id: int):
    """Remove an inbound access token record permanently."""
    current_admin = require_admin_user(request)
    try:
        deleted = security_manager.delete_access_token(
            token_id,
            deleted_by_user_id=int(current_admin["id"]) if isinstance(current_admin, dict) else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not deleted:
        raise HTTPException(status_code=404, detail="Token not found")
    return {
        "status": "success",
        "message": "Token deleted",
    }


@app.get("/api/external/info")
async def get_external_api_info():
    """Return a minimal discovery document for the token-authenticated external API."""
    require_external_api_enabled()
    security_config = get_security_config()
    return {
        "api_name": "dt4sms-external-rag",
        "status": "available",
        "version": "v1",
        "authentication": {
            "scheme": "bearer",
            "header": "Authorization: Bearer <token>",
            "token_type": "external_api",
        },
        "supported_scopes": ["rag:search", "rag:assets:read"],
        "external_mcp_enabled": bool(getattr(security_config, "external_mcp_enabled", False) if security_config else False),
        "mcp_info_path": "/api/external/mcp/info",
        "routes": [
            {"method": "GET", "path": "/api/external/rag/index-summary", "scope": "rag:assets:read"},
            {"method": "POST", "path": "/api/external/rag/search", "scope": "rag:search"},
            {"method": "GET", "path": "/api/external/rag/assets", "scope": "rag:assets:read"},
            {"method": "GET", "path": "/api/external/rag/assets/{asset_id}", "scope": "rag:assets:read"},
        ],
    }


@app.get("/api/external/mcp/info")
async def get_external_mcp_info():
    """Return unauthenticated setup metadata for the inbound read-only MCP surface."""
    require_external_mcp_enabled()
    return _build_external_mcp_info_payload()


@app.post("/api/external/mcp")
async def handle_external_mcp(request: Request, payload: Dict[str, Any]):
    """Serve a minimal inbound read-only MCP surface over JSON-RPC HTTP."""
    require_external_mcp_token(request, ["mcp:tools:read"])

    if not isinstance(payload, dict):
        return _build_jsonrpc_error_response(None, -32600, "Invalid JSON-RPC request body")

    request_id = payload.get("id")
    method = str(payload.get("method") or "").strip()
    params = payload.get("params")
    if not method:
        return _build_jsonrpc_error_response(request_id, -32600, "JSON-RPC method is required")

    if method == "initialize":
        return _build_jsonrpc_success_response(request_id, _build_external_mcp_initialize_result())
    if method in {"notifications/initialized", "initialized"}:
        return _build_jsonrpc_success_response(request_id, {"acknowledged": True})
    if method == "ping":
        return _build_jsonrpc_success_response(request_id, {})
    if method == "tools/list":
        return _build_jsonrpc_success_response(
            request_id,
            {"tools": copy.deepcopy(EXTERNAL_MCP_TOOL_DEFINITIONS)},
        )
    if method == "tools/call":
        return _handle_external_mcp_tool_call(request_id, params)

    return _build_jsonrpc_error_response(request_id, -32601, f"Unsupported MCP method '{method}'")


@app.get("/api/external/rag/index-summary")
async def get_external_rag_index_summary(request: Request):
    """Return a sanitized RAG index summary for external consumers."""
    require_external_api_token(request, ["rag:assets:read"])
    return _build_external_rag_index_summary_payload()


@app.post("/api/external/rag/search")
async def search_external_rag(request: Request, search_request: ExternalRAGSearchRequest):
    """Search managed RAG assets through the external read-only API."""
    require_external_api_token(request, ["rag:search"])
    return _build_external_rag_search_payload(search_request.query, search_request.limit)


@app.get("/api/external/rag/assets")
async def list_external_rag_assets(request: Request):
    """List sanitized managed RAG assets for external consumers."""
    require_external_api_token(request, ["rag:assets:read"])
    return _list_external_rag_assets_payload()


@app.get("/api/external/rag/assets/{asset_id}")
async def get_external_rag_asset_detail(request: Request, asset_id: str):
    """Return sanitized detail for one managed RAG knowledge asset."""
    require_external_api_token(request, ["rag:assets:read"])
    return _get_external_rag_asset_detail_payload(asset_id)


def _raise_for_capability_result(result: Dict[str, Any]):
    if result.get("ok"):
        return
    detail = result.get("message") or "Capability operation failed"
    status_code = 404 if "unknown capability" in detail.lower() else 400
    raise HTTPException(status_code=status_code, detail=detail)


@app.get("/api/capabilities")
async def get_capabilities():
    """Get current capability registry state and persisted config."""
    return {
        "status": "success",
        "summary": capability_manager.get_summary(),
        "capabilities": capability_manager.list_capabilities(),
    }


@app.get("/api/capabilities/health")
async def get_capability_health():
    """Return current capability health snapshots."""
    capabilities = capability_manager.list_capabilities()
    return {
        "status": "success",
        "capabilities": {
            name: {
                "health_status": state.get("health_status"),
                "health_message": state.get("health_message"),
                "last_tested_at": state.get("last_tested_at"),
                "restart_required": state.get("restart_required"),
            }
            for name, state in capabilities.items()
        },
    }


@app.get("/api/capabilities/rag/assets")
async def list_rag_assets():
    """List user-managed knowledge assets for indexed retrieval."""
    result = capability_manager.list_rag_assets("rag_chromadb").to_dict()
    _raise_for_capability_result(result)
    return result


@app.get("/api/capabilities/rag/assets/{asset_id}")
async def get_rag_asset_detail(asset_id: str):
    """Load stored-section and chunk-browser detail for one managed knowledge asset."""
    result = capability_manager.get_rag_asset_detail("rag_chromadb", asset_id).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/assets/import/text")
async def import_rag_text_asset(import_request: RAGKnowledgeAssetImportRequest):
    """Import a pasted text asset into the managed RAG asset plane."""
    result = capability_manager.import_rag_text_asset(
        "rag_chromadb",
        {
            "title": import_request.title,
            "content": import_request.content,
            "asset_type": import_request.asset_type,
            "source_label": import_request.source_label,
            "description": import_request.description,
            "tags": list(import_request.tags or []),
            "attributes": dict(import_request.attributes or {}),
        },
    ).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/assets/import/file")
async def import_rag_file_asset(
    file: UploadFile = File(...),
    title: Optional[str] = Form(default=None),
    asset_type: str = Form(default="reference_document"),
    source_label: Optional[str] = Form(default=None),
    description: Optional[str] = Form(default=None),
    tags: str = Form(default=""),
):
    """Import a supported file as a managed RAG knowledge asset."""
    payload = await file.read()
    result = capability_manager.import_rag_file_asset(
        "rag_chromadb",
        filename=file.filename or "knowledge_asset.txt",
        content_bytes=payload,
        payload={
            "title": title,
            "asset_type": asset_type,
            "source_label": source_label,
            "description": description,
            "tags": _parse_knowledge_asset_tags(tags),
        },
    ).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/assets/{asset_id}/delete")
async def delete_rag_asset(asset_id: str):
    """Delete a managed RAG knowledge asset and refresh the index when configured."""
    result = capability_manager.delete_rag_asset("rag_chromadb", asset_id).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/assets/{asset_id}/check-in")
async def check_in_rag_asset(asset_id: str):
    """Check a managed RAG knowledge asset into indexed library circulation."""
    result = capability_manager.check_in_rag_asset("rag_chromadb", asset_id).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/assets/{asset_id}/check-out")
async def check_out_rag_asset(asset_id: str):
    """Check a managed RAG knowledge asset out of indexed library circulation."""
    result = capability_manager.check_out_rag_asset("rag_chromadb", asset_id).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/rag/context/build")
async def build_rag_context_preview(build_request: RAGContextPreviewRequest):
    """Build a retrieval context preview from managed RAG knowledge assets and the downloaded documentation."""
    result = capability_manager.build_rag_context_preview(
        "rag_chromadb",
        build_request.query,
        max_chunks=build_request.limit,
    ).to_dict()
    doc_matches = await asyncio.to_thread(search_library_docs, build_request.query, max(1, min(_safe_int(build_request.limit) or 4, 6)))
    library_matches = [public_library_doc_result(match) for match in doc_matches]
    if not result.get("ok") and library_matches:
        count = len(library_matches)
        return {
            "ok": True,
            "capability": "rag_chromadb",
            "action": "build-context",
            "message": f"Found {count} documentation passage{'s' if count != 1 else ''}. The Knowledge Base is not ready, so its passages are not included.",
            "details": {
                "query": build_request.query,
                "message": "The Knowledge Base is not installed or not ready, so this preview shows only Splunk documentation.",
                "library_matches": library_matches,
            },
        }
    _raise_for_capability_result(result)
    if isinstance(result.get("details"), dict):
        result["details"]["library_matches"] = library_matches
    return result


knowledge_library_service = KnowledgeLibraryService(Path("output") / LIBRARY_DIR_NAME)


class KnowledgeLibrarySettingsUpdate(BaseModel):
    allow_online_sources: bool


def _knowledge_library_can_manage(request: Request) -> bool:
    if not is_auth_enabled():
        return True
    current_user = getattr(request.state, "auth_user", None)
    return isinstance(current_user, dict) and str(current_user.get("role") or "").strip().lower() == "admin"


def _knowledge_library_kb_assets() -> Optional[List[Dict[str, Any]]]:
    try:
        result = capability_manager.list_rag_assets("rag_chromadb").to_dict()
    except Exception:
        return None
    if not result.get("ok"):
        return None
    assets = (result.get("details") or {}).get("assets")
    return assets if isinstance(assets, list) else []


def _knowledge_library_blueprint(request: Request) -> Optional[Dict[str, Any]]:
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    return load_latest_v2_blueprint(scope_key=scope_key)


def _knowledge_library_status_payload(request: Request, auto_refresh: bool = True) -> Dict[str, Any]:
    return knowledge_library_service.build_status(
        _knowledge_library_blueprint(request),
        _knowledge_library_kb_assets(),
        allow_online=bool(config_manager.get().library.allow_online_sources),
        can_manage=_knowledge_library_can_manage(request),
        auto_refresh=auto_refresh,
    )


@app.get("/api/knowledge-library/status")
async def get_knowledge_library_status(request: Request):
    """Score how well the library covers the latest discovery and list the gaps."""
    return _knowledge_library_status_payload(request)


@app.post("/api/knowledge-library/settings")
async def update_knowledge_library_settings(request: Request, update: KnowledgeLibrarySettingsUpdate):
    """Turn online library sources on or off."""
    require_admin_user(request)
    if not config_manager.update_library(allow_online_sources=bool(update.allow_online_sources)):
        raise HTTPException(status_code=500, detail=config_manager.last_save_error or "Could not save the library settings.")
    return _knowledge_library_status_payload(request)


class KnowledgeLibraryRefreshRequest(BaseModel):
    sources: Optional[List[str]] = None


@app.post("/api/knowledge-library/refresh")
async def refresh_knowledge_library(request: Request, refresh_request: Optional[KnowledgeLibraryRefreshRequest] = None):
    """Download the library sources again in the background, or only the sources the request names."""
    require_admin_user(request)
    if not config_manager.get().library.allow_online_sources:
        raise HTTPException(status_code=409, detail="Online library sources are turned off. Turn them on first, or import a library pack.")
    try:
        sources = knowledge_library_service.resolve_refresh_sources(refresh_request.sources if refresh_request else None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    profile = build_environment_profile(_knowledge_library_blueprint(request))
    knowledge_library_service.start_refresh(profile, sources=sources, reason="manual")
    return _knowledge_library_status_payload(request, auto_refresh=False)


class KnowledgeLibrarySearchRequest(BaseModel):
    query: str
    limit: int = 5


@app.post("/api/knowledge-library/search")
async def search_knowledge_library(search_request: KnowledgeLibrarySearchRequest):
    """Search the downloaded Splunk documentation the way chat does."""
    query = str(search_request.query or "").strip()[:500]
    if not query:
        raise HTTPException(status_code=400, detail="Enter a question to search for.")
    results = await asyncio.to_thread(search_library_docs, query, max(1, min(_safe_int(search_request.limit) or 5, 10)))
    return {
        "status": "success",
        "query": query,
        "results": [public_library_doc_result(result) for result in results],
        "docs_available": knowledge_library_service.docs_available(),
    }


@app.post("/api/knowledge-library/pack/import")
async def import_knowledge_library_pack(request: Request, file: UploadFile = File(...)):
    """Load library sources from a pack exported on another installation."""
    require_admin_user(request)
    data = await file.read(MAX_PACK_BYTES + 1)
    try:
        result = await asyncio.to_thread(knowledge_library_service.import_pack, data)
    except LibraryBusyError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except LibraryPackError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    payload = _knowledge_library_status_payload(request, auto_refresh=False)
    payload["import_result"] = result
    return payload


@app.get("/api/knowledge-library/pack/export")
async def export_knowledge_library_pack():
    """Download the loaded library sources and documentation text as a pack for installations without internet access."""
    try:
        data = await asyncio.to_thread(knowledge_library_service.export_pack)
    except LibraryPackError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    filename = f"dt4sms_library_pack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    return Response(content=data, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.post("/api/capabilities/{name}/install")
async def install_capability(name: str, install_request: Optional[CapabilityInstallRequest] = None):
    """Install or prepare an optional capability."""
    result = capability_manager.install_capability(name, strategy=install_request.strategy if install_request else None).to_dict()
    if not result.get("ok"):
        return JSONResponse(status_code=400, content=result)
    return result


@app.post("/api/capabilities/{name}/enable")
async def enable_capability(name: str):
    """Enable an installed optional capability."""
    result = capability_manager.enable_capability(name).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/{name}/disable")
async def disable_capability(name: str):
    """Disable an optional capability without uninstalling it."""
    result = capability_manager.disable_capability(name).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/{name}/uninstall")
async def uninstall_capability(name: str):
    """Turn off an optional capability and mark it not installed, keeping its settings and data."""
    result = capability_manager.uninstall_capability(name).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/{name}/test")
async def test_capability(name: str):
    """Run a health check for an optional capability."""
    result = capability_manager.test_capability(name).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/{name}/reindex")
async def reindex_capability(name: str):
    """Run an index rebuild for capabilities that manage retrieval content."""
    result = capability_manager.reindex_capability(name).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/{name}/config")
async def update_capability_config(name: str, config_update: CapabilityConfigUpdate):
    """Persist capability-specific configuration updates."""
    result = capability_manager.update_capability_config(name, config_update.config).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/deeplinks/build")
async def build_splunk_deeplink(request: Request, build_request: CapabilityDeeplinkBuildRequest):
    """Build a Splunk deeplink using the optional deeplink capability pack."""
    runtime_config = resolve_effective_runtime_config(request=request)
    result = capability_manager.build_deeplink(
        "splunk_deeplink_tools",
        build_request.link_type,
        {
            "query": build_request.query,
            "earliest": build_request.earliest,
            "latest": build_request.latest,
            "app": build_request.app,
            "mcp_url_override": runtime_config.mcp.url,
        },
    ).to_dict()
    _raise_for_capability_result(result)
    return result


@app.post("/api/capabilities/exports/build")
async def build_capability_export(build_request: CapabilityExportBuildRequest):
    """Build a deterministic export bundle using the optional export capability pack."""
    result = capability_manager.build_export(
        "export_tools",
        {
            "timestamp": build_request.timestamp,
            "persona": build_request.persona,
            "voice": _normalize_operator_voice(build_request.voice),
            "artifact_names": list(build_request.artifact_names or []),
            "title": build_request.title,
            "runbook_markdown": build_request.runbook_markdown,
            "runbook_filename": build_request.runbook_filename,
        },
    ).to_dict()
    _raise_for_capability_result(result)
    return result


@app.get("/api/capabilities/exports/download/{filename}")
async def download_capability_export(filename: str):
    """Download a generated deterministic export bundle from output/exports."""
    safe_filename = Path(filename).name
    if not re.match(r"^[a-zA-Z0-9_\-.]+$", safe_filename) or not safe_filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Invalid report package filename")

    export_state = capability_manager.get_capability_state("export_tools")
    export_dir = Path(str(export_state.get("export_dir") or Path("output") / "exports"))
    file_path = export_dir / safe_filename
    if not file_path.resolve().is_relative_to(export_dir.resolve()):
        raise HTTPException(status_code=403, detail="Access denied")
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Report package not found")

    return FileResponse(path=file_path, filename=file_path.name, media_type="application/zip")

# ==================== Credential Vault API ====================

PROFILE_NAME_MAX_LENGTH = 128


def _normalize_profile_name(raw_name: Any, kind: str) -> str:
    name = str(raw_name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail=f"{kind} name is required")
    if len(name) > PROFILE_NAME_MAX_LENGTH or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise HTTPException(
            status_code=400,
            detail=f"{kind} name must be 1-{PROFILE_NAME_MAX_LENGTH} printable characters",
        )
    return name


def _config_save_failure_detail(kind: str) -> str:
    reason = str(getattr(config_manager, "last_save_error", "") or "").strip()
    return f"Failed to save {kind}: {reason}" if reason else f"Failed to save {kind}"


def _credential_activates(name: str, requested: Optional[bool]) -> bool:
    if requested is not None:
        return bool(requested)
    return config_manager.get().active_credential_name == name


def _mcp_profile_activates(name: str, requested: Optional[bool]) -> bool:
    if requested is not None:
        return bool(requested)
    current = config_manager.get()
    return current.active_mcp_config_name == name or (
        not current.active_mcp_config_name and is_unset_secret(current.mcp.token)
    )


def _refresh_after_activation(payload: Dict[str, Any]) -> None:
    # The settings are already saved; a refresh failure must not turn the save into an error.
    try:
        capability_manager.refresh()
    except Exception as exc:
        print(f"Warning: capability refresh after save failed: {exc}")
        payload["warning"] = f"Saved, but refreshing capabilities failed: {exc}"
    payload["config"] = config_manager.export_safe()


class CredentialCreate(BaseModel):
    """Request model for creating/updating a credential"""
    name: str
    provider: str
    # Blank or "***" keeps the key already stored for this credential.
    api_key: str = ""
    model: str
    endpoint_url: Optional[str] = None
    max_tokens: int = 16000
    temperature: float = 0.7
    auto_tune: bool = True
    context_window: int = Field(default=0, ge=0, le=10_000_000)
    request_timeout: int = Field(default=0, ge=0, le=3600)
    reasoning_effort: str = Field(default="", pattern="^(|minimal|low|medium|high)$")
    # None: update the active LLM settings only when this is the active credential.
    activate: Optional[bool] = None


def _credential_public_view(cred: Any) -> Dict[str, Any]:
    return {
        'name': cred.name,
        'provider': cred.provider,
        'api_key': '' if is_unset_secret(cred.api_key) else MASKED_SECRET,
        'model': cred.model,
        'endpoint_url': cred.endpoint_url,
        'max_tokens': cred.max_tokens,
        'temperature': cred.temperature,
        'auto_tune': getattr(cred, 'auto_tune', True),
        'context_window': getattr(cred, 'context_window', 0),
        'request_timeout': getattr(cred, 'request_timeout', 0),
        'reasoning_effort': getattr(cred, 'reasoning_effort', ''),
    }

@app.get("/api/credentials")
async def list_credentials(request: Request):
    """Get all saved credentials (with masked API keys)"""
    require_admin_user(request)
    credentials = config_manager.list_credentials()
    return {name: _credential_public_view(cred) for name, cred in credentials.items()}

@app.post("/api/credentials")
async def save_credential(request: Request, credential: CredentialCreate):
    """Save a new credential"""
    require_admin_user(request)
    name = _normalize_profile_name(credential.name, "Credential")
    activate = _credential_activates(name, credential.activate)
    try:
        success = config_manager.save_credential(
            name=name,
            provider=credential.provider,
            api_key=credential.api_key,
            model=credential.model,
            endpoint_url=credential.endpoint_url,
            max_tokens=credential.max_tokens,
            temperature=credential.temperature,
            auto_tune=credential.auto_tune,
            context_window=credential.context_window,
            request_timeout=credential.request_timeout,
            reasoning_effort=credential.reasoning_effort,
            activate=bool(activate),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save credential: {e}")
    if not success:
        raise HTTPException(status_code=500, detail=_config_save_failure_detail("credential"))
    payload: Dict[str, Any] = {
        "status": "success",
        "message": f"Credential '{name}' saved",
        "name": name,
        "activated": bool(activate),
    }
    if activate:
        _refresh_after_activation(payload)
    return payload

# Profile names may contain "/", so the name segment uses the path convertor.
@app.get("/api/credentials/{name:path}")
async def get_credential(request: Request, name: str):
    """Get a specific credential (with masked API key)"""
    require_admin_user(request)
    cred = config_manager.get_credential(name)
    if not cred:
        raise HTTPException(status_code=404, detail=f"Credential '{name}' not found")

    return _credential_public_view(cred)

@app.delete("/api/credentials/{name:path}")
async def delete_credential(request: Request, name: str):
    """Delete a saved credential"""
    require_admin_user(request)
    success = config_manager.delete_credential(name)
    if success:
        return {"status": "success", "message": f"Credential '{name}' deleted"}
    else:
        raise HTTPException(status_code=404, detail=f"Credential '{name}' not found")

@app.post("/api/credentials/{name:path}/load")
async def load_credential(request: Request, name: str):
    """Load a saved credential into active configuration"""
    require_admin_user(request)
    success = config_manager.load_credential(name)
    if success:
        # Reload config
        config_manager._config = config_manager.load()
        capability_manager.refresh()
        return {
            "status": "success", 
            "message": f"Credential '{name}' loaded",
            "config": config_manager.export_safe()
        }
    else:
        raise HTTPException(status_code=404, detail=f"Credential '{name}' not found")

# ==================== MCP Configuration Vault API ====================

class MCPConfigCreate(BaseModel):
    """Request model for creating/updating an MCP configuration"""
    name: str
    url: str
    # Blank or "***" keeps the token already stored for this profile (or the active
    # token when the URL matches the active server).
    token: str = ""
    verify_ssl: bool = False
    ca_bundle_path: Optional[str] = None
    description: Optional[str] = None
    # None: activate when updating the active profile, or when no MCP connection is set up yet.
    activate: Optional[bool] = None

@app.get("/api/mcp-configs")
async def list_mcp_configs(request: Request):
    """Get all saved MCP configurations (with masked tokens)"""
    require_admin_user(request)
    mcp_configs = config_manager.list_mcp_configs()
    return {
        name: {
            'name': mcp_config.name,
            'url': mcp_config.url,
            'token': '' if is_unset_secret(mcp_config.token) else MASKED_SECRET,
            'verify_ssl': mcp_config.verify_ssl,
            'ca_bundle_path': mcp_config.ca_bundle_path,
            'description': mcp_config.description
        }
        for name, mcp_config in mcp_configs.items()
    }

@app.post("/api/mcp-configs")
async def save_mcp_config(request: Request, mcp_config: MCPConfigCreate):
    """Save a new MCP configuration"""
    require_admin_user(request)
    name = _normalize_profile_name(mcp_config.name, "MCP configuration")
    url = str(mcp_config.url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="MCP URL is required")
    activate = _mcp_profile_activates(name, mcp_config.activate)
    description = str(mcp_config.description or "").strip() or None
    try:
        success = config_manager.save_mcp_config(
            name=name,
            url=url,
            token=mcp_config.token,
            verify_ssl=mcp_config.verify_ssl,
            ca_bundle_path=mcp_config.ca_bundle_path,
            description=description,
            activate=bool(activate),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save MCP configuration: {e}")
    if not success:
        raise HTTPException(status_code=500, detail=_config_save_failure_detail("MCP configuration"))
    saved = config_manager.get_mcp_config(name)
    payload: Dict[str, Any] = {
        "status": "success",
        "message": f"MCP configuration '{name}' saved",
        "name": name,
        "activated": bool(activate),
        "token_configured": bool(saved and not is_unset_secret(saved.token)),
    }
    if activate:
        _refresh_after_activation(payload)
    return payload

@app.get("/api/mcp-configs/{name:path}")
async def get_mcp_config(request: Request, name: str):
    """Get a specific MCP configuration (with masked token)"""
    require_admin_user(request)
    mcp_config = config_manager.get_mcp_config(name)
    if not mcp_config:
        raise HTTPException(status_code=404, detail=f"MCP configuration '{name}' not found")
    
    return {
        'name': mcp_config.name,
        'url': mcp_config.url,
        'token': '' if is_unset_secret(mcp_config.token) else MASKED_SECRET,
        'verify_ssl': mcp_config.verify_ssl,
        'ca_bundle_path': mcp_config.ca_bundle_path,
        'description': mcp_config.description
    }

@app.delete("/api/mcp-configs/{name:path}")
async def delete_mcp_config(request: Request, name: str):
    """Delete a saved MCP configuration"""
    require_admin_user(request)
    success = config_manager.delete_mcp_config(name)
    if success:
        return {"status": "success", "message": f"MCP configuration '{name}' deleted"}
    else:
        raise HTTPException(status_code=404, detail=f"MCP configuration '{name}' not found")

@app.post("/api/mcp-configs/{name:path}/load")
async def load_mcp_config(request: Request, name: str):
    """Load a saved MCP configuration into active configuration"""
    require_admin_user(request)
    success = config_manager.load_mcp_config(name)
    if success:
        # Reload config
        config_manager._config = config_manager.load()
        capability_manager.refresh()
        return {
            "status": "success", 
            "message": f"MCP configuration '{name}' loaded",
            "config": config_manager.export_safe()
        }
    else:
        raise HTTPException(status_code=404, detail=f"MCP configuration '{name}' not found")

@app.post("/api/mcp-configs/test")
async def test_mcp_connection(request: Request, request_payload: dict):
    """Test MCP connection with provided credentials"""
    require_admin_user(request)
    try:
        import httpx
        
        url = str(request_payload.get('url') or '').strip()
        token = request_payload.get('token')
        verify_ssl = bool(request_payload.get('verify_ssl', False))
        ca_bundle = str(request_payload.get('ca_bundle_path') or '').strip()
        
        if not url:
            raise HTTPException(status_code=400, detail="URL is required")
        if is_unset_secret(token):
            token = config_manager.resolve_mcp_token(request_payload.get('name'), url)
        
        # Prepare headers
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        
        # Same JSON-RPC request the discovery engine and chat send; strict servers reject bare method calls
        test_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        
        ssl_verify: Any = False
        if verify_ssl and ca_bundle:
            bundle_path = Path(ca_bundle).expanduser()
            try:
                ssl_verify = ssl.create_default_context(cafile=str(bundle_path))
            except (OSError, ssl.SSLError) as bundle_error:
                return {
                    "status": "error",
                    "message": (
                        f"The CA bundle file {bundle_path} could not be used ({bundle_error}). "
                        "Check the path on the app server, or clear the CA Bundle field to use the system certificates."
                    ),
                }
        elif verify_ssl:
            ssl_verify = True
        
        # Make the test request
        async with httpx.AsyncClient(verify=ssl_verify, timeout=10.0) as client:
            response = await client.post(
                url,
                json=test_payload,
                headers=headers
            )
            
            if response.status_code == 200:
                return {
                    "status": "success",
                    "message": "Connection successful! MCP server is responding.",
                    "server_response": response.status_code
                }
            elif response.status_code == 401:
                return {
                    "status": "error",
                    "message": "Authentication failed. Please check your token.",
                    "server_response": response.status_code
                }
            elif response.status_code == 403:
                return {
                    "status": "error",
                    "message": "Access forbidden. Token may lack permissions.",
                    "server_response": response.status_code
                }
            else:
                return {
                    "status": "warning",
                    "message": f"Server responded with status {response.status_code}. Connection works but there may be issues.",
                    "server_response": response.status_code
                }
                
    except httpx.ConnectError as connect_error:
        if "CERTIFICATE_VERIFY_FAILED" in str(connect_error):
            return {
                "status": "error",
                "message": (
                    "The server's SSL certificate isn't trusted. Add its CA bundle file, or turn off Verify SSL "
                    "for a self-signed lab server. Use Troubleshoot for details."
                ),
            }
        return {
            "status": "error",
            "message": "Cannot connect to server. Check URL and network connectivity."
        }
    except httpx.TimeoutException:
        return {
            "status": "error",
            "message": "Connection timeout. Server may be slow or unreachable."
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Connection test failed: {str(e)}"
        }

@app.post("/api/mcp-configs/{name:path}/test")
async def test_saved_mcp_connection(request: Request, name: str):
    """Test a saved MCP configuration"""
    require_admin_user(request)
    mcp_config = config_manager.get_mcp_config(name)
    if not mcp_config:
        raise HTTPException(status_code=404, detail=f"MCP configuration '{name}' not found")
    if is_unset_secret(mcp_config.token):
        return {
            "status": "error",
            "message": f"'{name}' has no saved token. Load it, enter the token, and update the configuration.",
        }
    
    # Use the test endpoint with saved credentials
    return await test_mcp_connection(request, {
        'url': mcp_config.url,
        'token': mcp_config.token,
        'verify_ssl': mcp_config.verify_ssl,
        'ca_bundle_path': mcp_config.ca_bundle_path,
    })

# ==================== Chat Settings API ====================

def _chat_settings_response(view: ChatSettingsView) -> Dict[str, Any]:
    return {"status": "success", "settings": view.payload()}


@app.get("/api/chat/settings")
async def get_chat_settings():
    """Chat settings: Auto values from the AI model's tuning, with saved custom values applied."""
    return refresh_chat_session_settings().payload()


@app.post("/api/chat/settings")
async def update_chat_settings(settings: Dict[str, Any]):
    """Save custom chat values; null puts a setting back on Auto. Kept until the AI model changes."""
    tuning, identity = _chat_settings_inputs()
    if settings.get("temperature") is not None and tuning.get("supports_temperature", True) is False:
        raise HTTPException(status_code=400, detail=f"{identity['label']} uses a fixed temperature, so it cannot be changed.")
    try:
        apply_custom_values(chat_settings_store, settings, identity)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not save chat settings: {exc}") from None
    return _chat_settings_response(refresh_chat_session_settings())


@app.post("/api/chat/settings/reset")
async def reset_chat_settings():
    """Put every chat setting back on Auto."""
    _, identity = _chat_settings_inputs()
    try:
        reset_custom_values(chat_settings_store, identity)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Could not save chat settings: {exc}") from None
    return _chat_settings_response(refresh_chat_session_settings())

# ==================== Chat Goals API ====================

chat_goal_store = ChatGoalStore(CHAT_DATA_ROOT)


def chat_goal_owner(request: Request) -> str:
    """The signed-in user's goal library, or the shared one when sign-in is off."""
    if not is_auth_enabled():
        return owner_key(None)
    return owner_key(require_authenticated_user(request))


def load_active_chat_goal(goal_owner: Optional[str], goal_id: Any) -> Optional[Dict[str, Any]]:
    key = clean_goal_id(goal_id) if isinstance(goal_id, str) else ""
    if not key:
        return None
    try:
        return chat_goal_store.get_raw_goal(goal_owner or owner_key(None), key)
    except (GoalNotFoundError, OSError):
        return None


def record_chat_goal_turn(goal_owner: Optional[str], request: Any, result: Any) -> None:
    """Keep the question and answer with the goal so its progress can be checked next."""
    if not isinstance(request, dict) or not isinstance(result, dict) or result.get("error"):
        return
    goal_id = clean_goal_id(request.get("goal_id")) if isinstance(request.get("goal_id"), str) else ""
    answer = result.get("response")
    if not goal_id or not isinstance(answer, str) or not answer.strip():
        return
    try:
        recorded = chat_goal_store.record_turn(
            goal_owner or owner_key(None), goal_id, request.get("message"), answer, request.get("chat_session_id")
        )
    except OSError as exc:
        print(f"⚠️ [CHAT] Could not record the goal turn: {exc}")
        return
    if recorded:
        result["goal_turn_recorded"] = True


def _goal_http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, GoalNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, GoalLimitError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=f"Could not save the goal library: {exc}")


async def _goal_payload(request: Request) -> Dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


async def _ask_llm_for_goal_json(messages: List[Dict[str, str]], fraction: float, ceiling: int) -> Tuple[Optional[Dict[str, Any]], str]:
    """One JSON answer from the AI model for goal planning or progress, with a reason when there is none."""
    config = config_manager.get()
    available, reason = _is_llm_available_for_m26_14_advisory(config)
    if not available:
        return None, reason
    try:
        llm_client = get_or_create_llm_client(config)
        raw_response = await llm_client.generate_response(
            messages=messages,
            max_tokens=llm_call_budget(config, fraction, floor=400, ceiling=ceiling),
            temperature=0.2,
        )
    except Exception as exc:
        return None, f"The AI model could not answer: {exc}"
    parsed = _extract_json_object_from_llm_text(raw_response)
    if parsed is None:
        return None, "The AI model did not return a usable answer."
    return parsed, ""


def _goal_environment_brief() -> str:
    try:
        knowledge = load_latest_report_knowledge(chat_session_settings.get("discovery_freshness_days", 7))
    except Exception:
        return ""
    if not isinstance(knowledge, dict):
        return ""
    return str(knowledge.get("prompt_context_compact") or knowledge.get("greeting_context") or "")


async def _plan_chat_goal(goal_text: str) -> Tuple[Dict[str, Any], str, str]:
    """Plan from the AI model, or the starter plan when it is unavailable. Returns (plan, planned_by, message)."""
    data, reason = await _ask_llm_for_goal_json(
        build_plan_messages(goal_text, _goal_environment_brief()), fraction=0.25, ceiling=1200
    )
    plan = parse_plan(data, goal_text) if data else None
    if plan is not None:
        return plan, "model", ""
    message = reason or "The AI model did not return a usable plan."
    return fallback_plan(goal_text), "starter", f"{message} Starter questions are shown instead."


@app.get("/api/chat/goals")
async def list_chat_goals(request: Request):
    owner = chat_goal_owner(request)
    return {"goals": chat_goal_store.list_goals(owner)}


@app.post("/api/chat/goals")
async def create_chat_goal(request: Request):
    """Add a goal to the library, with questions to track and first questions to ask."""
    owner = chat_goal_owner(request)
    payload = await _goal_payload(request)
    goal_text = clean_goal_text(payload.get("goal"), MAX_GOAL_CHARS)
    if not goal_text:
        raise HTTPException(status_code=400, detail="Describe the goal first.")
    plan, planned_by, message = await _plan_chat_goal(goal_text)
    try:
        goal = chat_goal_store.create_goal(
            owner,
            goal_text,
            title=payload.get("title") or plan["title"],
            items=plan["items"],
            questions=plan["questions"],
            planned_by=planned_by,
        )
    except (GoalLimitError, OSError) as exc:
        raise _goal_http_error(exc) from None
    return {"goal": goal, "message": message}


@app.get("/api/chat/goals/{goal_id}")
async def get_chat_goal(goal_id: str, request: Request):
    try:
        return {"goal": chat_goal_store.get_goal(chat_goal_owner(request), goal_id)}
    except (GoalNotFoundError, OSError) as exc:
        raise _goal_http_error(exc) from None


@app.patch("/api/chat/goals/{goal_id}")
async def update_chat_goal(goal_id: str, request: Request):
    """Rename a goal, change its text, or mark it done or active again."""
    owner = chat_goal_owner(request)
    payload = await _goal_payload(request)
    try:
        goal = chat_goal_store.update_goal(
            owner, goal_id, title=payload.get("title"), goal=payload.get("goal"), status=payload.get("status")
        )
    except (GoalNotFoundError, GoalLimitError, OSError) as exc:
        raise _goal_http_error(exc) from None
    return {"goal": goal}


@app.delete("/api/chat/goals/{goal_id}")
async def delete_chat_goal(goal_id: str, request: Request):
    try:
        chat_goal_store.delete_goal(chat_goal_owner(request), goal_id)
    except (GoalNotFoundError, OSError) as exc:
        raise _goal_http_error(exc) from None
    return {"status": "deleted"}


@app.post("/api/chat/goals/{goal_id}/plan")
async def replan_chat_goal(goal_id: str, request: Request):
    """Plan the goal again; answered questions are kept and open ones are replaced."""
    owner = chat_goal_owner(request)
    try:
        goal = chat_goal_store.get_raw_goal(owner, goal_id)
    except (GoalNotFoundError, OSError) as exc:
        raise _goal_http_error(exc) from None
    plan, planned_by, message = await _plan_chat_goal(str(goal.get("goal") or ""))
    try:
        detail = chat_goal_store.replace_plan(owner, goal_id, plan["items"], plan["questions"], planned_by)
    except (GoalNotFoundError, OSError) as exc:
        raise _goal_http_error(exc) from None
    return {"goal": detail, "message": message}


@app.post("/api/chat/goals/{goal_id}/items")
async def add_chat_goal_item(goal_id: str, request: Request):
    payload = await _goal_payload(request)
    try:
        return {"goal": chat_goal_store.add_item(chat_goal_owner(request), goal_id, payload.get("text"))}
    except (GoalNotFoundError, GoalLimitError, OSError) as exc:
        raise _goal_http_error(exc) from None


@app.patch("/api/chat/goals/{goal_id}/items/{item_id}")
async def update_chat_goal_item(goal_id: str, item_id: str, request: Request):
    payload = await _goal_payload(request)
    try:
        goal = chat_goal_store.update_item(
            chat_goal_owner(request), goal_id, item_id,
            text=payload.get("text"), status=payload.get("status"), note=payload.get("note"),
        )
    except (GoalNotFoundError, GoalLimitError, OSError) as exc:
        raise _goal_http_error(exc) from None
    return {"goal": goal}


@app.delete("/api/chat/goals/{goal_id}/items/{item_id}")
async def delete_chat_goal_item(goal_id: str, item_id: str, request: Request):
    try:
        return {"goal": chat_goal_store.delete_item(chat_goal_owner(request), goal_id, item_id)}
    except (GoalNotFoundError, OSError) as exc:
        raise _goal_http_error(exc) from None


@app.post("/api/chat/goals/{goal_id}/progress")
async def check_chat_goal_progress(goal_id: str, request: Request):
    """Judge the answers recorded since the last check against the goal's open questions."""
    owner = chat_goal_owner(request)
    try:
        goal = chat_goal_store.get_raw_goal(owner, goal_id)
    except (GoalNotFoundError, OSError) as exc:
        raise _goal_http_error(exc) from None
    turns = pending_goal_turns(goal)
    if not turns:
        return {"goal": goal_detail(goal), "updated": False, "message": ""}
    data, reason = await _ask_llm_for_goal_json(build_progress_messages(goal, turns), fraction=0.25, ceiling=1500)
    evaluation = parse_progress(data, goal) if data else None
    if evaluation is None:
        return {
            "goal": goal_detail(goal),
            "updated": False,
            "message": reason or "The AI model did not return a usable progress check.",
        }
    turn_ids = [turn.get("id") for turn in goal.get("turns") or [] if isinstance(turn, dict) and not turn.get("evaluated")]
    try:
        detail = chat_goal_store.apply_progress(owner, goal_id, evaluation, turn_ids)
    except (GoalNotFoundError, OSError) as exc:
        raise _goal_http_error(exc) from None
    return {"goal": detail, "updated": True, "message": ""}


@app.get("/api/chat/goals/{goal_id}/chats/{chat_id}")
async def get_chat_goal_chat(goal_id: str, chat_id: str, request: Request):
    try:
        return {"chat": chat_goal_store.get_chat(chat_goal_owner(request), goal_id, chat_id)}
    except (GoalNotFoundError, OSError) as exc:
        raise _goal_http_error(exc) from None


@app.put("/api/chat/goals/{goal_id}/chats/{chat_id}")
async def save_chat_goal_chat(goal_id: str, chat_id: str, request: Request):
    """Save (or update) one conversation under a goal."""
    payload = await _goal_payload(request)
    try:
        chat = chat_goal_store.save_chat(
            chat_goal_owner(request), goal_id, chat_id, payload.get("messages"), title=payload.get("title")
        )
    except (GoalNotFoundError, GoalLimitError, OSError) as exc:
        raise _goal_http_error(exc) from None
    return {"chat": chat}


@app.patch("/api/chat/goals/{goal_id}/chats/{chat_id}")
async def rename_chat_goal_chat(goal_id: str, chat_id: str, request: Request):
    payload = await _goal_payload(request)
    try:
        chat = chat_goal_store.rename_chat(chat_goal_owner(request), goal_id, chat_id, payload.get("title"))
    except (GoalNotFoundError, GoalLimitError, OSError) as exc:
        raise _goal_http_error(exc) from None
    return {"chat": chat}


@app.delete("/api/chat/goals/{goal_id}/chats/{chat_id}")
async def delete_chat_goal_chat(goal_id: str, chat_id: str, request: Request):
    try:
        chat_goal_store.delete_chat(chat_goal_owner(request), goal_id, chat_id)
    except (GoalNotFoundError, OSError) as exc:
        raise _goal_http_error(exc) from None
    return {"status": "deleted"}

def _model_listing_response(
    provider: str,
    names: List[Any],
    metadata_by_model: Optional[Dict[str, Dict[str, Any]]] = None,
    endpoint_url: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return model names plus a balanced quality/speed/cost ranking and the recommended pick."""
    unique_names = sorted({name for name in names if isinstance(name, str) and name.strip()})
    metadata_by_model = {name: meta for name, meta in (metadata_by_model or {}).items() if isinstance(meta, dict)}
    runtime_provider = runtime_provider_for(provider, endpoint_url)
    for name, meta in metadata_by_model.items():
        if meta:
            remember_model_metadata(runtime_provider, endpoint_url, name, meta)
    ranked = rank_models(runtime_provider, unique_names, metadata_by_model, endpoint_url)
    recommended = next((item for item in ranked if item.get("recommended")), None)
    payload: Dict[str, Any] = {
        "models": unique_names,
        "ranked": ranked,
        "recommended": recommended,
        "recommended_model": recommended["model"] if recommended else None,
        "ranking_basis": "balanced quality, speed, and cost",
    }
    if extra:
        payload.update(extra)
    return payload


@app.post("/api/llm/list-models")
async def list_models(request: Request):
    """Fetch available models from OpenAI/Azure/Anthropic/Gemini/Custom endpoints."""
    try:
        data = await request.json()
        provider = normalize_provider_name(data.get('provider', 'openai'))
        api_key = data.get('api_key')
        endpoint_url = (data.get('endpoint_url') or '').strip() or None

        async with httpx.AsyncClient(timeout=12.0) as client:
            if provider == 'openai':
                if not api_key:
                    raise HTTPException(status_code=400, detail="API key required for OpenAI")
                base = (endpoint_url or 'https://api.openai.com').rstrip('/')
                if base.endswith('/v1'):
                    models_url = f'{base}/models'
                elif base.endswith('/models'):
                    models_url = base
                else:
                    models_url = f'{base}/v1/models'
                response = await client.get(
                    models_url,
                    headers={'Authorization': f'Bearer {api_key}'},
                )
                response.raise_for_status()
                models_data = response.json()
                entries = [m for m in models_data.get('data', []) if isinstance(m, dict) and isinstance(m.get('id'), str)]
                raw_models = sorted({m['id'] for m in entries})
                filtered_models = filter_openai_generation_models(raw_models)
                metadata = {m['id']: parse_openai_compatible_model_entry(m) for m in entries if m['id'] in filtered_models}
                return _model_listing_response(
                    provider,
                    filtered_models,
                    metadata,
                    endpoint_url,
                    extra={'filtered_out': max(0, len(raw_models) - len(filtered_models))},
                )

            if provider == 'azure':
                if not endpoint_url:
                    raise HTTPException(status_code=400, detail="Endpoint URL required for Azure provider")
                if not api_key:
                    raise HTTPException(status_code=400, detail="API key required for Azure provider")

                base = endpoint_url.rstrip('/')
                if '/openai/deployments/' in base:
                    base = base.split('/openai/deployments/')[0]
                if base.endswith('/openai'):
                    base = base[:-len('/openai')]

                deployment_url = f"{base}/openai/deployments?api-version=2024-02-15-preview"
                models_url = f"{base}/openai/models?api-version=2024-02-15-preview"
                headers = {'api-key': api_key}

                deployments = []
                try:
                    response = await client.get(deployment_url, headers=headers)
                    if response.status_code == 200:
                        payload = response.json()
                        deployments = [
                            item.get('id')
                            for item in payload.get('data', [])
                            if isinstance(item, dict) and item.get('id')
                        ]
                except Exception:
                    deployments = []

                model_ids = []
                try:
                    response = await client.get(models_url, headers=headers)
                    if response.status_code == 200:
                        payload = response.json()
                        model_ids = [
                            item.get('id')
                            for item in payload.get('data', [])
                            if isinstance(item, dict) and item.get('id')
                        ]
                except Exception:
                    model_ids = []

                merged = sorted({m for m in deployments + model_ids if isinstance(m, str) and m.strip()})
                if not merged:
                    raise HTTPException(status_code=400, detail="Could not fetch Azure deployments/models from endpoint")
                return _model_listing_response(provider, merged, None, endpoint_url)

            if provider == 'anthropic':
                if not api_key:
                    raise HTTPException(status_code=400, detail="API key required for Anthropic")
                base = (endpoint_url or 'https://api.anthropic.com').rstrip('/')
                response = await client.get(
                    f"{base}/v1/models",
                    headers={
                        'x-api-key': api_key,
                        'anthropic-version': '2023-06-01'
                    },
                )
                response.raise_for_status()
                payload = response.json()
                models = [item.get('id') for item in payload.get('data', []) if isinstance(item, dict)]
                return _model_listing_response(provider, models, None, endpoint_url)

            if provider == 'gemini':
                if not api_key:
                    raise HTTPException(status_code=400, detail="API key required for Gemini")
                base = (endpoint_url or 'https://generativelanguage.googleapis.com').rstrip('/')
                response = await client.get(f"{base}/v1beta/models?key={quote(api_key)}")
                response.raise_for_status()
                payload = response.json()
                models = []
                metadata = {}
                for item in payload.get('models', []):
                    if not isinstance(item, dict):
                        continue
                    name = item.get('name')
                    if isinstance(name, str) and name.startswith('models/'):
                        name = name.split('/', 1)[1]
                    if isinstance(name, str) and name.strip():
                        models.append(name)
                        metadata[name] = parse_openai_compatible_model_entry(item)
                return _model_listing_response(provider, models, metadata, endpoint_url)

            if provider == 'ollama':
                base = normalize_ollama_endpoint_url(endpoint_url)
                models = []
                metadata = {}

                response = await client.get(f"{base}/api/tags")
                response.raise_for_status()
                payload = response.json()

                for item in payload.get('models', []):
                    if not isinstance(item, dict):
                        continue
                    model_name = item.get('name') or item.get('model') or item.get('id')
                    if isinstance(model_name, str) and model_name.strip():
                        models.append(model_name)
                        metadata[model_name] = parse_ollama_model_entry(item)

                if not models:
                    try:
                        fallback_response = await client.get(f"{base}/v1/models")
                        fallback_response.raise_for_status()
                        fallback_payload = fallback_response.json()
                        models.extend([
                            item.get('id')
                            for item in fallback_payload.get('data', [])
                            if isinstance(item, dict) and item.get('id')
                        ])
                    except Exception:
                        pass

                if not models:
                    raise HTTPException(status_code=400, detail="Could not fetch models from Ollama endpoint")

                return _model_listing_response(provider, models, metadata, endpoint_url)

            if provider == 'custom':
                if not endpoint_url:
                    raise HTTPException(status_code=400, detail="Endpoint URL required for custom provider")

                base = endpoint_url.rstrip('/')
                endpoints_to_try = [
                    base if base.endswith('/v1/models') else f"{base}/v1/models",
                    base if base.endswith('/models') else f"{base}/models",
                    base if base.endswith('/api/tags') else f"{base}/api/tags",
                ]

                for url in endpoints_to_try:
                    try:
                        headers = {}
                        if api_key:
                            headers['Authorization'] = f'Bearer {api_key}'
                        response = await client.get(url, headers=headers)
                        response.raise_for_status()
                        payload = response.json()

                        if isinstance(payload, dict) and isinstance(payload.get('data'), list):
                            entries = [m for m in payload.get('data', []) if isinstance(m, dict) and isinstance(m.get('id'), str)]
                            metadata = {m['id']: parse_openai_compatible_model_entry(m) for m in entries}
                            return _model_listing_response(provider, [m['id'] for m in entries], metadata, endpoint_url)

                        if isinstance(payload, dict) and isinstance(payload.get('models'), list):
                            models = []
                            metadata = {}
                            for item in payload.get('models', []):
                                model_name = (item.get('name') or item.get('id')) if isinstance(item, dict) else item
                                if isinstance(model_name, str) and model_name.strip():
                                    models.append(model_name)
                                    if isinstance(item, dict):
                                        metadata[model_name] = parse_ollama_model_entry(item)
                            return _model_listing_response(provider, models, metadata, endpoint_url)

                        if isinstance(payload, list):
                            models = []
                            metadata = {}
                            for item in payload:
                                model_name = (item.get('id') or item.get('name')) if isinstance(item, dict) else item
                                if isinstance(model_name, str) and model_name.strip():
                                    models.append(model_name)
                                    if isinstance(item, dict):
                                        metadata[model_name] = parse_openai_compatible_model_entry(item)
                            return _model_listing_response(provider, models, metadata, endpoint_url)
                    except Exception:
                        continue

                raise HTTPException(status_code=400, detail="Could not fetch models from custom endpoint")

            raise HTTPException(status_code=400, detail=f"Unsupported provider: {provider}")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch models: {str(e)}")


@app.get("/api/summary/infographic-capability")
async def get_summary_infographic_capability(request: Request, timestamp: Optional[str] = None):
    """Return whether the active OpenAI credential can access gpt-image-2."""
    request_scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    session_scope_key = request_scope_key
    if timestamp:
        session = _require_accessible_discovery_session(timestamp, scope_key=request_scope_key)
        session_scope_key = _get_discovery_session_scope_key(session)
    existing_artifact = _find_existing_summary_infographic(timestamp, session_scope_key) if timestamp else None
    config = config_manager.get()
    provider = normalize_provider_name(config.llm.provider)

    if provider != "openai":
        return {
            "available": existing_artifact is not None,
            "can_generate": False,
            "has_existing": existing_artifact is not None,
            "existing_artifact": _build_artifact_metadata(existing_artifact) if existing_artifact else None,
            "checked": False,
            "provider": provider,
            "model": OPENAI_IMAGE_MODEL,
            "reason": "Active provider is not OpenAI",
        }

    if not config.llm.api_key:
        return {
            "available": existing_artifact is not None,
            "can_generate": False,
            "has_existing": existing_artifact is not None,
            "existing_artifact": _build_artifact_metadata(existing_artifact) if existing_artifact else None,
            "checked": False,
            "provider": provider,
            "model": OPENAI_IMAGE_MODEL,
            "reason": "OpenAI API key is not configured",
        }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                build_openai_api_url(config.llm.endpoint_url, "/models"),
                headers={"Authorization": f"Bearer {config.llm.api_key}"},
            )
            response.raise_for_status()
            payload = response.json()

        model_ids = [
            item.get("id")
            for item in payload.get("data", [])
            if isinstance(item, dict) and item.get("id")
        ]
        can_generate = openai_model_ids_include(model_ids, OPENAI_IMAGE_MODEL)
        return {
            "available": can_generate or existing_artifact is not None,
            "can_generate": can_generate,
            "has_existing": existing_artifact is not None,
            "existing_artifact": _build_artifact_metadata(existing_artifact) if existing_artifact else None,
            "checked": True,
            "provider": provider,
            "model": OPENAI_IMAGE_MODEL,
        }
    except Exception as exc:
        return {
            "available": existing_artifact is not None,
            "can_generate": False,
            "has_existing": existing_artifact is not None,
            "existing_artifact": _build_artifact_metadata(existing_artifact) if existing_artifact else None,
            "checked": False,
            "provider": provider,
            "model": OPENAI_IMAGE_MODEL,
            "reason": f"Capability probe failed: {exc}",
        }


@app.post("/api/summary/generate-infographic")
async def generate_summary_infographic(request: SummaryInfographicRequest, http_request: Request):
    """Generate an infographic image from the current summary using gpt-image-2."""
    config = config_manager.get()
    provider = normalize_provider_name(config.llm.provider)

    if provider != "openai":
        raise HTTPException(status_code=400, detail="Summary infographic generation requires the OpenAI provider")
    if not config.llm.api_key:
        raise HTTPException(status_code=400, detail="OpenAI API key is not configured")

    timestamp = str(request.timestamp or "").strip()
    if not timestamp:
        raise HTTPException(status_code=400, detail="timestamp is required")

    request_scope_key = _build_discovery_scope_metadata(request=http_request).get("scope_key")
    session = _require_accessible_discovery_session(timestamp, scope_key=request_scope_key)
    session_scope_key = _get_discovery_session_scope_key(session)

    existing_infographic = _find_existing_summary_infographic(timestamp, session_scope_key)
    if existing_infographic is not None:
        _ensure_session_artifact_registered(timestamp, existing_infographic.name, scope_key=session_scope_key)
        image_format = 'jpeg' if existing_infographic.suffix.lower() == '.jpg' else existing_infographic.suffix[1:].lower()
        return {
            "status": "success",
            "model": OPENAI_IMAGE_MODEL,
            "mime_type": f"image/{image_format}",
            "image_base64": base64.b64encode(existing_infographic.read_bytes()).decode("ascii"),
            "filename": existing_infographic.name,
            "artifact_path": str(existing_infographic),
            "reused_existing": True,
        }

    prompt = build_summary_infographic_prompt(timestamp, request.summary_data)
    payload = {
        "model": OPENAI_IMAGE_MODEL,
        "prompt": prompt,
        "size": "1536x1024",
    }

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(420.0, connect=30.0)) as client:
            response = await client.post(
                build_openai_api_url(config.llm.endpoint_url, "/images/generations"),
                headers={
                    "Authorization": f"Bearer {config.llm.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
            response.raise_for_status()
            response_payload = response.json()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="OpenAI image generation timed out while waiting for gpt-image-2 to finish")
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text[:500] if exc.response is not None else str(exc)
        raise HTTPException(status_code=exc.response.status_code if exc.response is not None else 502, detail=f"OpenAI image generation failed: {detail}")
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"OpenAI image generation failed: {exc}")

    image_items = response_payload.get("data", []) if isinstance(response_payload, dict) else []
    first_image = image_items[0] if image_items and isinstance(image_items[0], dict) else {}
    image_base64 = first_image.get("b64_json") if isinstance(first_image.get("b64_json"), str) else ""
    image_url = first_image.get("url") if isinstance(first_image.get("url"), str) else ""

    if image_base64:
        output_dir = _summary_infographic_dir(session_scope_key)
        output_dir.mkdir(parents=True, exist_ok=True)
        safe_timestamp = re.sub(r"[^0-9A-Za-z_-]", "_", timestamp)
        filename = f"summary_infographic_{safe_timestamp}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        artifact_path = output_dir / filename
        artifact_path.write_bytes(base64.b64decode(image_base64))
        _ensure_session_artifact_registered(timestamp, filename, scope_key=session_scope_key)
        return {
            "status": "success",
            "model": OPENAI_IMAGE_MODEL,
            "mime_type": "image/png",
            "image_base64": image_base64,
            "filename": filename,
            "artifact_path": str(artifact_path),
            "reused_existing": False,
        }

    if image_url:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=15.0)) as client:
                image_response = await client.get(image_url)
                image_response.raise_for_status()
            content_type = str(image_response.headers.get("content-type") or "image/png").split(";", 1)[0].strip().lower() or "image/png"
            extension = {
                "image/jpeg": ".jpg",
                "image/webp": ".webp",
                "image/gif": ".gif",
            }.get(content_type, ".png")
            output_dir = _summary_infographic_dir(session_scope_key)
            output_dir.mkdir(parents=True, exist_ok=True)
            safe_timestamp = re.sub(r"[^0-9A-Za-z_-]", "_", timestamp)
            filename = f"summary_infographic_{safe_timestamp}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{extension}"
            artifact_path = output_dir / filename
            artifact_bytes = image_response.content
            artifact_path.write_bytes(artifact_bytes)
            _ensure_session_artifact_registered(timestamp, filename, scope_key=session_scope_key)
            return {
                "status": "success",
                "model": OPENAI_IMAGE_MODEL,
                "mime_type": content_type,
                "image_base64": base64.b64encode(artifact_bytes).decode("ascii"),
                "filename": filename,
                "artifact_path": str(artifact_path),
                "reused_existing": False,
            }
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"OpenAI image download failed: {exc}")
        return {
            "status": "success",
            "model": OPENAI_IMAGE_MODEL,
            "image_url": image_url,
        }

    raise HTTPException(status_code=502, detail="OpenAI image generation returned no image payload")

@app.get("/api/dependencies")
async def get_dependencies():
    """Get installed Python packages and their versions"""
    try:
        import subprocess
        import json as json_module
        
        # Run pip list --format=json
        result = subprocess.run(
            ["pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            check=True
        )
        
        packages = json_module.loads(result.stdout)
        
        # Sort by name
        packages.sort(key=lambda x: x['name'].lower())

        return {
            "status": "success",
            "packages": packages,
            "total": len(packages)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get dependencies: {str(e)}")

def _llm_settings_view(llm_payload: Dict[str, Any], current_llm: Any, **overrides: Any) -> SimpleNamespace:
    """Merge request-supplied LLM settings over the saved config for one-off tuning checks."""
    fields = (
        "provider", "api_key", "model", "endpoint_url", "max_tokens", "temperature",
        "auto_tune", "context_window", "request_timeout", "reasoning_effort",
    )
    values = {name: llm_payload.get(name, getattr(current_llm, name, None)) for name in fields}
    values.update(overrides)
    return SimpleNamespace(**values)


def _tuning_source_label(profile: Any) -> str:
    sources = list(getattr(profile, "sources", []) or [])
    if "endpoint" in sources:
        return "endpoint metadata"
    if "catalog" in sources:
        return "model catalog"
    return "model size and family heuristics"


def _tuning_summary(tuning: Dict[str, Any]) -> Dict[str, Any]:
    profile = tuning["profile"]
    return {
        "auto_tune": bool(tuning.get("auto_tune", True)),
        "max_tokens": tuning["max_tokens"],
        "temperature": tuning.get("temperature"),
        "context_window": tuning["context_window"],
        "model_context_window": tuning.get("model_context_window"),
        "request_timeout": tuning["request_timeout"],
        "reasoning_effort": tuning.get("reasoning_effort") or "",
        "supports_tools": bool(tuning.get("supports_tools")),
        "reasoning": bool(tuning.get("reasoning")),
        "hosted": bool(getattr(profile, "hosted", False)),
        "score": profile.score(),
        "source": _tuning_source_label(profile),
        "reasons": describe_profile(profile),
        "notes": list(getattr(profile, "notes", []) or []),
        "rationale": list(tuning.get("rationale") or []),
    }


def _recommended_llm_config(tuning: Dict[str, Any]) -> Dict[str, Any]:
    """Fields the settings form can apply; context and timeout stay automatic unless overridden."""
    config_values: Dict[str, Any] = {"max_tokens": tuning["max_tokens"], "auto_tune": True}
    if tuning.get("temperature") is not None:
        config_values["temperature"] = tuning["temperature"]
    return config_values


def _custom_endpoint_base(endpoint_url: str) -> str:
    base = str(endpoint_url or "").strip().rstrip("/")
    for suffix in ("/v1/chat/completions", "/chat/completions", "/v1/completions", "/completions", "/api/chat", "/api/generate", "/v1/models", "/models", "/v1"):
        if base.lower().endswith(suffix):
            return base[: -len(suffix)].rstrip("/")
    return base


@app.post("/api/llm/assess-max-tokens")
async def assess_max_tokens(request: Request):
    """Recommend max_tokens and related runtime settings from the model profile."""
    try:
        payload = {}
        try:
            payload = await request.json()
            if not isinstance(payload, dict):
                payload = {}
        except Exception:
            payload = {}

        config = config_manager.get()
        llm_payload = payload.get("llm", {}) if isinstance(payload.get("llm"), dict) else payload

        provider = normalize_provider_name(llm_payload.get("provider", config.llm.provider))
        api_key = llm_payload.get("api_key", config.llm.api_key)
        model = llm_payload.get("model", config.llm.model)
        endpoint_url = llm_payload.get("endpoint_url", config.llm.endpoint_url)

        if provider == "ollama":
            endpoint_url = normalize_ollama_endpoint_url(endpoint_url)

        if provider in {"openai", "azure", "anthropic", "gemini"} and not api_key:
            raise HTTPException(status_code=400, detail="LLM API key not configured")

        if provider == "openai" and is_openai_image_generation_model(model):
            return {
                "recommended_max_tokens": None,
                "applicable": False,
                "status": "info",
                "message": f"{model} uses the OpenAI images API. max_tokens is not required for summary infographic execution; output is limited by image size instead.",
            }

        llm_view = _llm_settings_view(
            llm_payload,
            config.llm,
            provider=provider,
            api_key=api_key,
            model=model,
            endpoint_url=endpoint_url,
            auto_tune=True,
            request_timeout=0,
            reasoning_effort="",
        )
        tuning = await asyncio.to_thread(resolve_llm_tuning, llm_view, True)
        summary = _tuning_summary(tuning)
        estimated = summary["source"] == "model size and family heuristics"
        message = (
            f"Recommended {tuning['max_tokens']} output tokens for {model} "
            f"(planning context {tuning['context_window']} tokens) from {summary['source']}."
        )
        if estimated:
            message += " The model is not in the catalog, so limits are estimated; run Test Connection to confirm."
        return {
            "recommended_max_tokens": tuning["max_tokens"],
            "applicable": True,
            "status": "info" if estimated else "success",
            "message": message,
            "recommended_config": _recommended_llm_config(tuning),
            "tuning": summary,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Assessment error: {str(e)}")


@app.post("/api/llm/test-connection")
async def test_llm_connection(request: Request):
    """Test provider-specific LLM connectivity and generation, then report auto-tuned settings."""
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    return await _run_llm_connection_test(payload if isinstance(payload, dict) else {})


async def _run_llm_connection_test(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        current_config = config_manager.get()
        llm_payload = payload.get("llm", {}) if isinstance(payload.get("llm"), dict) else payload

        provider = normalize_provider_name(llm_payload.get("provider", current_config.llm.provider))
        api_key = llm_payload.get("api_key", current_config.llm.api_key)
        model = llm_payload.get("model", current_config.llm.model)
        endpoint_url = llm_payload.get("endpoint_url", current_config.llm.endpoint_url)
        try:
            temperature = float(llm_payload.get("temperature", current_config.llm.temperature or 0.7))
        except (TypeError, ValueError):
            temperature = 0.7

        if provider == "ollama":
            endpoint_url = normalize_ollama_endpoint_url(endpoint_url)

        if provider in {"azure", "custom"} and not endpoint_url:
            return {
                "status": "error",
                "message": f"Provider '{provider}' requires endpoint_url",
                "tests": {
                    "connection": {
                        "status": "error",
                        "message": "Missing endpoint_url"
                    }
                }
            }

        if provider in {"openai", "azure", "anthropic", "gemini"} and not api_key:
            return {
                "status": "error",
                "message": f"Provider '{provider}' requires api_key",
                "tests": {
                    "connection": {
                        "status": "error",
                        "message": "Missing api_key"
                    }
                }
            }

        results = {
            "status": "testing",
            "provider": provider,
            "model": model,
            "endpoint": endpoint_url or {
                "openai": "https://api.openai.com",
                "anthropic": "https://api.anthropic.com",
                "gemini": "https://generativelanguage.googleapis.com",
                "ollama": DEFAULT_OLLAMA_ENDPOINT_URL,
            }.get(provider, "n/a"),
            "tests": {}
        }

        openai_model_capabilities = {}
        openai_model_ids = []
        if provider == "openai":
            openai_model_capabilities = get_openai_model_capabilities(model)
            results["model_capabilities"] = openai_model_capabilities

        uses_openai_image_generation = provider == "openai" and openai_model_capabilities.get("supports_image_generation", False)
        model_metadata: Optional[Dict[str, Any]] = None

        # Test 1: Connectivity probe
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                if provider == "openai":
                    base = (endpoint_url or "https://api.openai.com").rstrip('/')
                    if base.endswith('/v1'):
                        probe_url = f"{base}/models"
                    elif base.endswith('/models'):
                        probe_url = base
                    else:
                        probe_url = f"{base}/v1/models"
                    probe = await client.get(
                        probe_url,
                        headers={"Authorization": f"Bearer {api_key}"}
                    )
                    probe.raise_for_status()
                    probe_payload = probe.json() if hasattr(probe, "json") else {}
                    openai_model_ids = [
                        item.get("id")
                        for item in probe_payload.get("data", [])
                        if isinstance(item, dict) and item.get("id")
                    ]
                    results["tests"]["connection"] = {"status": "success", "message": "OpenAI models endpoint reachable"}

                elif provider == "azure":
                    base = endpoint_url.rstrip('/')
                    if '/openai/deployments/' in base:
                        base = base.split('/openai/deployments/')[0]
                    if base.endswith('/openai'):
                        base = base[:-len('/openai')]
                    probe = await client.get(
                        f"{base}/openai/deployments?api-version=2024-02-15-preview",
                        headers={"api-key": api_key}
                    )
                    if probe.status_code not in {200, 401, 403}:
                        probe.raise_for_status()
                    if probe.status_code in {401, 403}:
                        raise Exception("Azure endpoint reachable but API key/auth failed")
                    results["tests"]["connection"] = {"status": "success", "message": "Azure OpenAI endpoint reachable"}

                elif provider == "anthropic":
                    base = (endpoint_url or "https://api.anthropic.com").rstrip('/')
                    probe = await client.get(
                        f"{base}/v1/models",
                        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"}
                    )
                    probe.raise_for_status()
                    results["tests"]["connection"] = {"status": "success", "message": "Anthropic models endpoint reachable"}

                elif provider == "gemini":
                    base = (endpoint_url or "https://generativelanguage.googleapis.com").rstrip('/')
                    probe = await client.get(f"{base}/v1beta/models?key={quote(api_key)}")
                    probe.raise_for_status()
                    probe_payload = probe.json() if hasattr(probe, "json") else {}
                    for item in probe_payload.get("models", []) if isinstance(probe_payload, dict) else []:
                        if isinstance(item, dict) and str(item.get("name") or "").split("/", 1)[-1] == model:
                            model_metadata = parse_openai_compatible_model_entry(item)
                            break
                    results["tests"]["connection"] = {"status": "success", "message": "Gemini models endpoint reachable"}

                elif provider == "ollama":
                    base = normalize_ollama_endpoint_url(endpoint_url)
                    probe = await client.get(f"{base}/api/tags")
                    probe.raise_for_status()
                    probe_payload = probe.json() if hasattr(probe, "json") else {}
                    ollama_models = []
                    for item in probe_payload.get("models", []):
                        if not isinstance(item, dict):
                            continue
                        model_name = item.get("name") or item.get("model") or item.get("id")
                        if isinstance(model_name, str) and model_name.strip():
                            ollama_models.append(model_name)
                            if model_name == model:
                                model_metadata = parse_ollama_model_entry(item)
                    if ollama_models:
                        results["available_models"] = sorted({name for name in ollama_models})
                        if model and model not in ollama_models:
                            raise Exception(f"Model '{model}' is not installed on this Ollama server. Run: ollama pull {model}")
                    results["tests"]["connection"] = {"status": "success", "message": "Ollama model inventory reachable"}

                else:  # custom
                    base = _custom_endpoint_base(endpoint_url)
                    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
                    listing_urls = [f"{base}/v1/models", f"{base}/models", f"{base}/api/tags"]
                    answered = False
                    auth_failed = False
                    listed = False
                    for url in listing_urls + [f"{base}/health", base]:
                        try:
                            resp = await client.get(url, headers=headers)
                        except Exception:
                            continue
                        answered = True
                        if resp.status_code in {401, 403}:
                            auth_failed = True
                            continue
                        if not 200 <= resp.status_code < 300:
                            continue
                        if url in listing_urls:
                            try:
                                listing = resp.json()
                            except Exception:
                                listing = None
                            entries = []
                            if isinstance(listing, dict):
                                entries = listing.get("data") or listing.get("models") or []
                            elif isinstance(listing, list):
                                entries = listing
                            for item in entries if isinstance(entries, list) else []:
                                if not isinstance(item, dict):
                                    continue
                                item_name = str(item.get("id") or item.get("name") or item.get("model") or "")
                                if item_name == model:
                                    model_metadata = (
                                        parse_ollama_model_entry(item) if "details" in item else parse_openai_compatible_model_entry(item)
                                    )
                                    break
                            listed = isinstance(listing, (dict, list))
                        break
                    if auth_failed and not listed:
                        raise Exception("Custom endpoint rejected the API key (HTTP 401/403)")
                    if not answered:
                        raise Exception("Custom endpoint not reachable")
                    if listed:
                        results["tests"]["connection"] = {"status": "success", "message": "Custom endpoint model list reachable"}
                    else:
                        results["tests"]["connection"] = {
                            "status": "warning",
                            "message": "Endpoint answered but does not expose a model list; checking generation directly",
                        }

        except Exception as connection_error:
            results["tests"]["connection"] = {
                "status": "error",
                "message": f"Connection probe failed: {connection_error}",
                "error": str(connection_error)
            }
            results["status"] = "error"
            return results

        if uses_openai_image_generation:
            if openai_model_ids and not openai_model_ids_include(openai_model_ids, model):
                results["tests"]["model"] = {
                    "status": "error",
                    "message": f"Image model '{model}' is not listed for this OpenAI credential"
                }
                results["status"] = "error"
                return results

            results["tests"]["model"] = {
                "status": "info",
                "message": f"{model} uses the OpenAI images API. Skipped text completion probe; summary infographic generation should use the dedicated image endpoint.",
            }
            results["tests"]["max_tokens"] = {
                "status": "info",
                "detected_max": None,
                "message": f"max_tokens is not used for {model}. Summary infographic generation is constrained by image output size instead.",
            }
            results["status"] = "success"
            results["message"] = "All provider tests passed"
            results["recommended_config"] = {"temperature": temperature}
            return results

        llm_view = _llm_settings_view(
            llm_payload,
            current_config.llm,
            provider=provider,
            api_key=api_key,
            model=model,
            endpoint_url=endpoint_url,
        )
        needs_fetch = model_metadata is None or "context_window" not in (model_metadata or {})
        if needs_fetch and provider in {"ollama", "custom"}:
            fetched = await asyncio.to_thread(
                lookup_model_metadata, provider, endpoint_url, model, api_key, True
            )
            model_metadata = {**(fetched or {}), **(model_metadata or {})}
        tuning = resolve_llm_tuning(llm_view, metadata=model_metadata if model_metadata is not None else None)
        recommended = resolve_llm_tuning(
            _llm_settings_view(
                llm_payload,
                current_config.llm,
                provider=provider,
                api_key=api_key,
                model=model,
                endpoint_url=endpoint_url,
                auto_tune=True,
                request_timeout=0,
                reasoning_effort="",
            ),
            metadata=model_metadata if model_metadata is not None else None,
        )

        # Test 2: Model generation with the tuned client settings
        try:
            llm_client = LLMClientFactory.create_client(
                provider=provider,
                custom_endpoint=endpoint_url,
                api_key=api_key,
                model=model,
                tuning=client_tuning(tuning),
            )
            probe_tokens = 1024 if tuning.get("reasoning") else 64
            started = time.monotonic()
            model_response = await llm_client.generate_response(
                messages=[{"role": "user", "content": "Reply with exactly: test successful"}],
                max_tokens=probe_tokens,
                temperature=0.0,
            )
            latency_ms = int((time.monotonic() - started) * 1000)
            preview = str(model_response or "").strip()
            if not preview:
                raise Exception("Model returned an empty response")
            results["tests"]["model"] = {
                "status": "success",
                "message": f"Model responded in {latency_ms} ms",
                "latency_ms": latency_ms,
                "response_preview": preview[:120],
            }
        except Exception as model_error:
            results["tests"]["model"] = {
                "status": "error",
                "message": f"Model test failed: {model_error}",
                "error": str(model_error)
            }
            results["status"] = "error"
            return results

        # Test 3: Auto-tuned runtime configuration
        summary = _tuning_summary(recommended)
        results["tests"]["max_tokens"] = {
            "status": "success" if summary["source"] != "model size and family heuristics" else "info",
            "detected_max": recommended["max_tokens"],
            "message": (
                f"Auto-tuned max_tokens={recommended['max_tokens']}, context={recommended['context_window']}, "
                f"timeout={recommended['request_timeout']}s from {summary['source']}"
            ),
        }
        results["status"] = "success"
        results["message"] = "All provider tests passed"
        results["recommended_config"] = _recommended_llm_config(recommended)
        results["tuning"] = summary
        results["active_tuning"] = _tuning_summary(tuning)
        return results

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "error": str(e),
            "message": f"Test failed: {str(e)}"
        }

# ==================== Settings Troubleshooting API ====================

_LLM_DEFAULT_ENDPOINTS = {
    "openai": "https://api.openai.com",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com",
}


def _llm_effective_endpoint(provider: str, endpoint_url: Optional[str]) -> str:
    if provider == "ollama":
        return normalize_ollama_endpoint_url(endpoint_url)
    if endpoint_url:
        return str(endpoint_url).strip()
    return _LLM_DEFAULT_ENDPOINTS.get(provider, "")


def _validation_messages(model_cls: Any, data: Dict[str, Any]) -> List[str]:
    """Run the save endpoint's request model so troubleshooting reports the same rejections."""
    try:
        model_cls(**data)
    except ValidationError as exc:
        return [
            f"{'.'.join(str(part) for part in error.get('loc', ())) or 'request'}: {error.get('msg')}"
            for error in exc.errors()
        ]
    return []


def _troubleshoot_account(request: Request) -> Dict[str, Any]:
    if not is_auth_enabled():
        return {"auth_enabled": False, "username": None, "role": None, "can_manage": True}
    user = require_authenticated_user(request) or {}
    role = str(user.get("role") or "").strip().lower()
    return {"auth_enabled": True, "username": user.get("username"), "role": role or None, "can_manage": role == "admin"}


def _request_port(request: Request) -> Optional[int]:
    return request.url.port or (443 if request.url.scheme == "https" else 80)


def _profile_name_errors(name: str, kind: str) -> List[str]:
    if not name:
        return []
    try:
        _normalize_profile_name(name, kind)
    except HTTPException as exc:
        return [f"name: {exc.detail}"]
    return []


@app.get("/api/troubleshoot/server-status")
async def troubleshoot_server_status(request: Request):
    """Tell the browser whether the server still runs the code it started with (a git pull without a restart)."""
    status = server_code_status(PROJECT_ROOT, SERVER_STARTUP_STATE)
    status["started_at"] = datetime.fromtimestamp(status["started_at"], timezone.utc).isoformat()
    status["port"] = _request_port(request)
    try:
        can_manage = bool(_troubleshoot_account(request).get("can_manage"))
    except HTTPException:
        can_manage = False
    if can_manage:
        status["install_dir"] = str(PROJECT_ROOT)
    return status


@app.post("/api/troubleshoot/mcp")
async def troubleshoot_mcp_settings(request: Request, request_payload: dict):
    """Explain why an MCP configuration can't connect or can't be saved. Nothing is saved."""
    account = _troubleshoot_account(request)
    name = str(request_payload.get("name") or "").strip()
    fields = {key: request_payload[key] for key in ("url", "token", "verify_ssl", "ca_bundle_path", "description") if key in request_payload}
    errors = _validation_messages(MCPConfigCreate, {"name": name, "url": "", **fields})
    errors += _profile_name_errors(name, "MCP configuration")
    activate = _mcp_profile_activates(name, request_payload.get("activate")) if name else False
    return await run_mcp_diagnostics(
        request_payload,
        config_manager=config_manager,
        project_root=PROJECT_ROOT,
        startup=SERVER_STARTUP_STATE,
        own_port=_request_port(request),
        account=account,
        activate=activate,
        validation_errors=errors,
    )


@app.post("/api/troubleshoot/llm")
async def troubleshoot_llm_settings(request: Request, request_payload: dict):
    """Explain why an AI provider credential can't connect or can't be saved. Nothing is saved."""
    account = _troubleshoot_account(request)
    name = str(request_payload.get("name") or "").strip()
    credential_fields = (
        "provider", "api_key", "model", "endpoint_url", "max_tokens", "temperature",
        "auto_tune", "context_window", "request_timeout", "reasoning_effort",
    )
    fields = {key: request_payload[key] for key in credential_fields if key in request_payload}
    errors = _validation_messages(CredentialCreate, {"name": name, "provider": "openai", "model": "", **fields})
    errors += _profile_name_errors(name, "Credential")
    activate = _credential_activates(name, request_payload.get("activate")) if name else False
    return await run_llm_diagnostics(
        request_payload,
        config_manager=config_manager,
        project_root=PROJECT_ROOT,
        startup=SERVER_STARTUP_STATE,
        own_port=_request_port(request),
        account=account,
        activate=activate,
        validation_errors=errors,
        normalize_provider=normalize_provider_name,
        effective_endpoint=_llm_effective_endpoint,
        runner=_run_llm_connection_test,
    )


@app.get("/summarize-progress/{session_id}")
async def get_summarize_progress(session_id: str, request: Request):
    """Get current progress of summarization with input validation."""
    try:
        # Security: Validate session ID format
        safe_session_id = validate_session_id(session_id)
        _sync_runtime_state_from_disk()
        scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
        session = _require_accessible_discovery_session(safe_session_id, scope_key=scope_key)
        return _get_summarization_progress(safe_session_id, _get_discovery_session_scope_key(session))
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid session ID")


@app.post("/abort-summary")
async def abort_summary(request: Dict[str, Any], http_request: Request):
    """Abort an active summary worker for a specific session."""
    timestamp = request.get("timestamp")
    if not timestamp:
        raise HTTPException(status_code=400, detail="timestamp required")

    try:
        safe_timestamp = validate_session_id(timestamp)
    except HTTPException:
        raise HTTPException(status_code=400, detail="Invalid timestamp format")

    _sync_runtime_state_from_disk()
    scope_key = _build_discovery_scope_metadata(request=http_request).get("scope_key")
    session = _require_accessible_discovery_session(safe_timestamp, scope_key=scope_key)
    session_scope_key = _get_discovery_session_scope_key(session)
    progress_entry = _get_summarization_progress(safe_timestamp, session_scope_key)
    stage = str(progress_entry.get("stage") or "idle").strip().lower() or "idle"
    worker_pid = _coerce_process_id(progress_entry.get("worker_pid"))

    if stage in SUMMARIZATION_TERMINAL_STAGES or worker_pid is None:
        return {
            "error": "No summary in progress",
            "progress": copy.deepcopy(progress_entry or _default_summarization_progress_payload()),
        }

    if not _terminate_runtime_worker_process(worker_pid):
        raise HTTPException(status_code=500, detail="Failed to stop summary worker")

    updated_progress = _set_summarization_progress(
        safe_timestamp,
        scope_key=session_scope_key,
        stage="aborted",
        progress=_safe_int(progress_entry.get("progress", 0)),
        message="Summary aborted by operator.",
        worker_pid=None,
        execution_mode="worker",
    )
    return {
        "status": "aborted",
        "progress": copy.deepcopy(updated_progress),
    }


def _load_cached_summary_if_available(
    session_id: str,
    json_file: Optional[Path] = None,
    *,
    scope_key: Optional[str] = None,
    mark_from_cache: bool,
    completion_message: str,
) -> Optional[Dict[str, Any]]:
    summary_file = _summary_artifact_path(session_id, scope_key)
    if not summary_file.exists():
        return None

    try:
        with open(summary_file, 'r', encoding='utf-8') as summary_handle:
            existing_summary = json.load(summary_handle)
        has_v2_panels = all(
            key in existing_summary
            for key in ["schema_version", "trend_signals", "risk_register", "recursive_investigations"]
        )
        if not has_v2_panels:
            print(f"Cached summary {summary_file.name} missing expected fields; regenerating...")
            return None

        if (
            (
                "context_explorer" not in existing_summary
                or not _context_explorer_has_formal_actions(existing_summary.get("context_explorer"))
                or not _context_explorer_has_structured_patterns(existing_summary.get("context_explorer"))
            )
            and json_file is not None
            and json_file.exists()
        ):
            try:
                with open(json_file, 'r', encoding='utf-8') as cached_discovery_file:
                    cached_discovery_data = json.load(cached_discovery_file)
                existing_summary["context_explorer"] = build_context_explorer_payload(
                    cached_discovery_data,
                    unknown_questions=existing_summary.get("unknown_data"),
                    admin_tasks=existing_summary.get("admin_tasks"),
                    coverage_gaps=existing_summary.get("coverage_gaps"),
                    risk_register=existing_summary.get("risk_register"),
                    readiness_score=existing_summary.get("readiness_score"),
                    session_id=session_id,
                )
                with open(summary_file, 'w', encoding='utf-8') as summary_out:
                    json.dump(existing_summary, summary_out, indent=2)
            except Exception as cache_patch_error:
                print(f"Error backfilling context explorer for cached summary: {cache_patch_error}")

        _set_summarization_progress(
            session_id,
            scope_key=scope_key,
            stage="complete",
            progress=100,
            message=completion_message,
            worker_pid=None,
        )
        if mark_from_cache:
            existing_summary['from_cache'] = True
        return existing_summary
    except Exception as exc:
        print(f"Error loading cached summary: {exc}")
        return None


async def _wait_for_summary_result(
    session_id: str,
    *,
    scope_key: Optional[str] = None,
    timeout_seconds: float = 900.0,
    poll_interval_seconds: float = 0.5,
) -> Dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    json_file = _discovery_scope_output_dir(scope_key, create=False) / f"v2_intelligence_blueprint_{session_id}.json"

    while True:
        _sync_runtime_state_from_disk()
        cached_summary = _load_cached_summary_if_available(
            session_id,
            json_file,
            scope_key=scope_key,
            mark_from_cache=False,
            completion_message="Analysis complete!",
        )
        if cached_summary is not None:
            return cached_summary

        progress_entry = _get_summarization_progress(session_id, scope_key)
        stage = str(progress_entry.get("stage") or "idle").strip().lower() or "idle"
        if stage == "aborted":
            raise HTTPException(
                status_code=409,
                detail=str(progress_entry.get("message") or "Summary generation was aborted."),
            )
        if stage in {"error", "interrupted"}:
            raise HTTPException(
                status_code=500,
                detail=str(progress_entry.get("message") or "Summary generation failed."),
            )

        worker_pid = _coerce_process_id(progress_entry.get("worker_pid"))
        if worker_pid is not None and not _is_process_running(worker_pid):
            failure_message = "Summary worker exited before completing the session."
            _set_summarization_progress(
                session_id,
                scope_key=scope_key,
                stage="error",
                progress=progress_entry.get("progress", 0),
                message=failure_message,
                worker_pid=None,
            )
            raise HTTPException(status_code=500, detail=failure_message)

        if time.monotonic() >= deadline:
            raise HTTPException(
                status_code=504,
                detail="Summary generation is still running. Reopen the summary to continue monitoring progress.",
            )

        await asyncio.sleep(poll_interval_seconds)


async def _handle_summary_background_request(
    request: Dict[str, Any],
    *,
    scope_key: Optional[str] = None,
) -> Dict[str, Any]:
    timestamp = request.get("timestamp")
    if not timestamp:
        raise HTTPException(status_code=400, detail="timestamp required")

    try:
        safe_timestamp = validate_session_id(timestamp)
    except HTTPException:
        raise HTTPException(status_code=400, detail="Invalid timestamp format")

    session = _require_accessible_discovery_session(safe_timestamp, scope_key=scope_key)
    session_scope_key = _get_discovery_session_scope_key(session)
    json_file = _discovery_scope_output_dir(session_scope_key, create=False) / f"v2_intelligence_blueprint_{safe_timestamp}.json"
    cached_summary = _load_cached_summary_if_available(
        safe_timestamp,
        json_file,
        scope_key=session_scope_key,
        mark_from_cache=True,
        completion_message="Summary available from cache.",
    )
    if cached_summary is not None:
        return cached_summary

    _sync_runtime_state_from_disk()
    existing_progress = _get_summarization_progress(safe_timestamp, session_scope_key)
    existing_stage = str(existing_progress.get("stage") or "idle").strip().lower() or "idle"
    existing_worker_pid = _coerce_process_id(existing_progress.get("worker_pid"))
    if existing_stage not in SUMMARIZATION_TERMINAL_STAGES and existing_worker_pid is not None and _is_process_running(existing_worker_pid):
        return await _wait_for_summary_result(safe_timestamp, scope_key=session_scope_key)

    try:
        worker_process = _launch_runtime_job_worker(
            "summary",
            {
                "scope_key": session_scope_key,
                "timestamp": safe_timestamp,
                "requested_at": _utcnow_iso(),
            },
        )
    except Exception as exc:
        failure_message = f"Failed to launch summary worker: {exc}"
        _set_summarization_progress(
            safe_timestamp,
            scope_key=session_scope_key,
            stage="error",
            progress=_safe_int(existing_progress.get("progress", 0)),
            message=failure_message,
            worker_pid=None,
            execution_mode="worker",
        )
        raise HTTPException(status_code=500, detail=failure_message)

    _set_summarization_progress(
        safe_timestamp,
        scope_key=session_scope_key,
        stage="queued",
        progress=max(1, _safe_int(existing_progress.get("progress", 0))),
        message="Summary queued in a durable background worker...",
        worker_pid=worker_process.pid,
        execution_mode="worker",
        started_at=_utcnow_iso(),
        completed_at=None,
    )
    return await _wait_for_summary_result(safe_timestamp, scope_key=session_scope_key)


async def _summarize_session_impl(request: Dict[str, Any], *, request_scope_key: Optional[str] = None):
    """
    Generate AI-powered summary with SPL queries and contextual questions.
    
    This endpoint:
    1. Checks if summary already exists and returns it if found
    2. Loads discovery reports for the session
    3. Generates contextual SPL queries for discovered data
    4. Identifies unknown/ambiguous data sources
    5. Creates executive summary with priority actions
    6. Saves the summary for future use
    """
    from spl.generator import SPLGenerator
    from spl.unknown_identifier import UnknownDataIdentifier
    
    timestamp = request.get("timestamp")
    if not timestamp:
        raise HTTPException(status_code=400, detail="timestamp required")
    
    # Security: Validate session ID format
    try:
        safe_timestamp = validate_session_id(timestamp)
    except HTTPException:
        raise HTTPException(status_code=400, detail="Invalid timestamp format")

    # Normalize to validated timestamp for all downstream file operations
    timestamp = safe_timestamp

    if request_scope_key is not None:
        session = _require_accessible_discovery_session(timestamp, scope_key=request_scope_key)
        request_scope_key = _get_discovery_session_scope_key(session)
    else:
        request_scope_key = _normalize_discovery_scope_key(request.get("scope_key"))

    if not _is_runtime_worker_process():
        return await _handle_summary_background_request(request, scope_key=request_scope_key)

    output_dir = _discovery_scope_output_dir(request_scope_key, create=False)

    # Load current session artifacts only (legacy artifacts intentionally ignored)
    json_file = output_dir / f"v2_intelligence_blueprint_{timestamp}.json"
    detailed_file = output_dir / f"v2_operator_runbook_{timestamp}.md"
    classification_file = output_dir / f"v2_developer_handoff_{timestamp}.md"
    executive_file = output_dir / f"v2_insights_brief_{timestamp}.md"

    summary_file = output_dir / f"v2_ai_summary_{safe_timestamp}.json"
    existing_cached_summary = _load_cached_summary_if_available(
        safe_timestamp,
        json_file,
        scope_key=request_scope_key,
        mark_from_cache=True,
        completion_message="Summary available from cache.",
    )
    if existing_cached_summary is not None:
        return existing_cached_summary

    if not json_file.exists():
        _set_summarization_progress(
            timestamp,
            scope_key=request_scope_key,
            stage="error",
            progress=0,
            message="Discovery session data not found for this summary run.",
        )
        return {"error": "Discovery session data not found"}
    
    # Initialize progress tracking
    _set_summarization_progress(
        timestamp,
        scope_key=request_scope_key,
        stage="loading",
        progress=10,
        message="Loading discovery reports...",
    )
    
    # Load current discovery data
    with open(json_file, 'r', encoding='utf-8') as f:
        discovery_data = json.load(f)
    
    # Extract discovery results from the finding ledger
    finding_ledger = discovery_data.get('finding_ledger', []) if isinstance(discovery_data, dict) else []
    discovery_results = [entry for entry in finding_ledger if isinstance(entry, dict)]
    discovery_entities = []
    for entry in discovery_results:
        data_obj = entry.get('data', {})
        if isinstance(data_obj, dict) and data_obj:
            discovery_entities.append(data_obj)
        else:
            discovery_entities.append(entry)

    coverage_gaps = discovery_data.get("coverage_gaps", []) if isinstance(discovery_data.get("coverage_gaps", []), list) else []
    trend_signals = discovery_data.get("trend_signals", {}) if isinstance(discovery_data.get("trend_signals", {}), dict) else {}
    if not trend_signals:
        trend_signals = {
            "evidence_steps": len(discovery_results),
            "high_priority_recommendations": len([
                r for r in (discovery_data.get("recommendations", []) or [])
                if isinstance(r, dict) and str(r.get("priority", "")).lower() == "high"
            ]),
            "coverage_gap_count": len(coverage_gaps),
            "recommendation_by_domain": {
                "security": len([r for r in (discovery_data.get("recommendations", []) or []) if isinstance(r, dict) and "security" in str(r.get("category", "")).lower()]),
                "performance": len([r for r in (discovery_data.get("recommendations", []) or []) if isinstance(r, dict) and "performance" in str(r.get("category", "")).lower()]),
                "data_quality": len([r for r in (discovery_data.get("recommendations", []) or []) if isinstance(r, dict) and ("data" in str(r.get("category", "")).lower() or "quality" in str(r.get("category", "")).lower())]),
                "compliance": len([r for r in (discovery_data.get("recommendations", []) or []) if isinstance(r, dict) and "compliance" in str(r.get("category", "")).lower()]),
            }
        }

    risk_register = discovery_data.get("risk_register", []) if isinstance(discovery_data.get("risk_register", []), list) else []
    if not risk_register:
        risk_register = [
            {
                "risk": gap.get("gap", "Coverage risk"),
                "severity": str(gap.get("priority", "medium")).lower(),
                "domain": "coverage",
                "impact": gap.get("why_it_matters", ""),
                "mitigation": "Convert this gap into verification + remediation SPL workflows."
            }
            for gap in coverage_gaps[:10]
            if isinstance(gap, dict)
        ]

    recursive_investigations = discovery_data.get("recursive_investigations", []) if isinstance(discovery_data.get("recursive_investigations", []), list) else []
    if not recursive_investigations:
        recursive_investigations = [
            {
                "loop": "Trend Baseline Expansion",
                "objective": "Re-run discovery weekly and compare high-priority recommendations over time.",
                "next_iteration_trigger": "Recommendation volume or severity increases.",
                "output": "Delta report with priority shifts and anomaly candidates."
            },
            {
                "loop": "Risk Verification Loop",
                "objective": "Validate each high-severity risk with focused SPL and record closure evidence.",
                "next_iteration_trigger": "Any high risk remains unresolved after runbook execution.",
                "output": "Residual risk register with owners and due dates."
            }
        ]

    vulnerability_hypotheses = discovery_data.get("vulnerability_hypotheses", []) if isinstance(discovery_data.get("vulnerability_hypotheses", []), list) else []
    readiness_score = discovery_data.get("readiness_score")
    
    # Update progress
    _set_summarization_progress(
        timestamp,
        scope_key=request_scope_key,
        stage="generating_queries",
        progress=25,
        message="Generating SPL queries...",
    )
    
    # Generate template SPL queries (used as fallback if AI generation fails)
    spl_gen = SPLGenerator(discovery_results)
    template_queries = []
    
    # Security queries
    security_queries = spl_gen.generate_security_queries()
    template_queries.extend([{
        **q,
        "category": "Security & Compliance",
        "query_source": "template"
    } for q in security_queries])
    
    # Infrastructure queries
    infra_queries = spl_gen.generate_infrastructure_queries()
    template_queries.extend([{
        **q,
        "category": "Infrastructure & Performance",
        "query_source": "template"
    } for q in infra_queries])
    
    # Performance queries
    perf_queries = spl_gen.generate_performance_queries()
    template_queries.extend([{
        **q,
        "category": "Capacity Planning",
        "query_source": "template"
    } for q in perf_queries])
    
    # Exploratory queries
    explore_queries = spl_gen.generate_exploratory_queries()
    template_queries.extend([{
        **q,
        "category": "Data Exploration",
        "query_source": "template"
    } for q in explore_queries])
    
    print(f"Generated {len(template_queries)} template queries as fallback")
    
    # Update progress
    _set_summarization_progress(
        timestamp,
        scope_key=request_scope_key,
        stage="identifying_unknowns",
        progress=50,
        message="Identifying unknown data sources...",
    )
    
    # Identify unknown data sources
    unknown_id = UnknownDataIdentifier(discovery_entities)
    unknown_items = unknown_id.identify_unknown_items()
    unknown_questions = unknown_id.generate_contextual_questions(unknown_items)
    
    # Update progress
    _set_summarization_progress(
        timestamp,
        scope_key=request_scope_key,
        stage="loading_reports",
        progress=60,
        message="Analyzing discovery reports...",
    )
    
    # Load reports for analysis
    executive_summary = ""
    if executive_file.exists():
        with open(executive_file, 'r', encoding='utf-8') as f:
            executive_summary = f.read()
    
    detailed_findings = ""
    if detailed_file.exists():
        with open(detailed_file, 'r', encoding='utf-8') as f:
            detailed_findings = f.read()
    
    classification_report = ""
    if classification_file.exists():
        with open(classification_file, 'r', encoding='utf-8') as f:
            classification_report = f.read()
    
    # ===== AI-POWERED REPORT ANALYSIS =====
    # Use LLM to extract actual findings from reports
    config = config_manager.get()
    llm_client = get_or_create_llm_client(config)
    
    # Extract environment entities from discovery results
    discovered_indexes = set()
    discovered_sourcetypes = set()
    discovered_hosts = set()
    index_event_counts: Dict[str, int] = {}
    for result in discovery_results:
        data = result.get('data', {})
        if isinstance(data, dict):
            host_value = data.get('host') or data.get('hostname')
            if isinstance(host_value, str) and host_value.strip():
                discovered_hosts.add(host_value.strip())
            if isinstance(data.get('hosts'), list):
                for host in data.get('hosts', []):
                    if isinstance(host, str) and host.strip():
                        discovered_hosts.add(host.strip())
            index_value = data.get('index')
            if isinstance(index_value, str) and index_value.strip():
                discovered_indexes.add(index_value.strip())
        if 'title' in data and 'totalEventCount' in data:
            discovered_indexes.add(data['title'])
            index_event_counts[str(data['title'])] = _safe_int(data.get('totalEventCount'))
        elif 'sourcetype' in data:
            discovered_sourcetypes.add(data['sourcetype'])

    discovered_indexes_list = sorted([idx for idx in discovered_indexes if isinstance(idx, str) and idx.strip()])
    discovered_sourcetypes_list = sorted([st for st in discovered_sourcetypes if isinstance(st, str) and st.strip()])
    discovered_hosts_list = sorted([h for h in discovered_hosts if isinstance(h, str) and h.strip()])

    environment_context_block = {
        "indexes": discovered_indexes_list[:30],
        "sourcetypes": discovered_sourcetypes_list[:40],
        "hosts": discovered_hosts_list[:40],
        "coverage_gaps": [g.get("gap") for g in coverage_gaps[:10] if isinstance(g, dict)],
        "risk_register": [r.get("risk") for r in risk_register[:10] if isinstance(r, dict)],
    }

    def _safe_str(value: Any, fallback: str = "") -> str:
        if value is None:
            return fallback
        text = str(value).strip()
        return text if text else fallback

    def _severity_rank(severity: str) -> int:
        normalized = _safe_str(severity, "medium").lower()
        if normalized == "critical":
            return 4
        if normalized == "high":
            return 3
        if normalized == "medium":
            return 2
        return 1

    def _priority_from_severity(severity: str) -> str:
        rank = _severity_rank(severity)
        if rank >= 4:
            return "🔴 HIGH"
        if rank == 3:
            return "🔴 HIGH"
        if rank == 2:
            return "🟠 MEDIUM"
        return "🟡 LOW"

    def _preferred_anchor_index() -> str:
        """Busiest non-internal index with data; "*" when discovery found none."""
        ranked = sorted(
            (name for name in discovered_indexes_list if index_event_counts.get(name, 0) > 0),
            key=lambda name: (name.startswith("_"), -index_event_counts.get(name, 0), name),
        )
        return ranked[0] if ranked else "*"

    def _anchor_spl_to_environment(spl_query: str) -> str:
        # An unscoped search only reads the role's default indexes, so make it explicit.
        # index=* is used rather than guessing one index the query may not live in;
        # generating commands (| tstats, | rest) and scoped searches are left unchanged.
        query = (spl_query or "").strip()
        if not query:
            return query
        return scope_spl_to_index(query, "*")

    def _strip_code_fence(text: str) -> str:
        cleaned = _safe_str(text)
        cleaned = cleaned.replace("```spl", "").replace("```sql", "").replace("```", "").strip()
        return cleaned

    known_entity_names = {
        "indexes": ("index", {name.lower(): name for name in discovered_indexes_list}),
        "sourcetypes": ("sourcetype", {name.lower(): name for name in discovered_sourcetypes_list}),
        "hosts": ("host", {name.lower(): name for name in discovered_hosts_list}),
    }

    def _extract_environment_evidence(spl_queries: Any) -> List[str]:
        """Discovered entities the SPL actually searches; empty when it uses none."""
        queries = [spl_queries] if isinstance(spl_queries, str) else list(spl_queries or [])
        evidence: List[str] = []
        for spl_query in queries:
            referenced = extract_spl_entities(str(spl_query or ""))
            for category, (label, known_names) in known_entity_names.items():
                for value in referenced.get(category, []):
                    known_name = known_names.get(str(value).lower())
                    if known_name and f"{label}:{known_name}" not in evidence:
                        evidence.append(f"{label}:{known_name}")
        return evidence[:5]

    def _flatten_findings(findings: Dict[str, Any]) -> List[Dict[str, str]]:
        category_to_domain = {
            "security_findings": "Security & Compliance",
            "performance_findings": "Infrastructure & Performance",
            "data_quality_findings": "Data Quality",
            "optimization_findings": "Capacity Planning",
            "compliance_findings": "Security & Compliance",
            "trend_findings": "Infrastructure & Performance",
            "risk_hypotheses": "Security & Compliance",
        }
        flattened: List[Dict[str, str]] = []
        for category, domain in category_to_domain.items():
            entries = findings.get(category, []) if isinstance(findings, dict) else []
            if not isinstance(entries, list):
                continue
            for entry in entries[:10]:
                if not isinstance(entry, dict):
                    continue
                description = _safe_str(entry.get("description"), _safe_str(entry.get("type"), "Discovery finding"))
                flattened.append({
                    "domain": domain,
                    "severity": _safe_str(entry.get("severity"), "medium"),
                    "reference": description[:220],
                    "recommendation": _safe_str(entry.get("recommendation"), "Investigate and validate in Splunk.")
                })
        return flattened

    def _normalize_query_item(query: Dict[str, Any], idx: int, finding_pool: List[Dict[str, str]]) -> Dict[str, Any]:
        category = _safe_str(query.get("category"), "Infrastructure & Performance")
        valid_categories = {
            "Security & Compliance",
            "Infrastructure & Performance",
            "Data Quality",
            "Capacity Planning",
            "Data Exploration"
        }
        if category not in valid_categories:
            category = "Infrastructure & Performance"

        default_use_case_by_category = {
            "Security & Compliance": "Security Investigation",
            "Infrastructure & Performance": "Performance Monitoring",
            "Data Quality": "Data Quality",
            "Capacity Planning": "Capacity Planning",
            "Data Exploration": "Data Quality"
        }

        finding_ref = _safe_str(query.get("finding_reference"))
        matching_finding = None
        if finding_ref:
            for f in finding_pool:
                if finding_ref.lower()[:40] in f.get("reference", "").lower():
                    matching_finding = f
                    break
        if not matching_finding and finding_pool:
            preferred = [f for f in finding_pool if f.get("domain") == category]
            matching_finding = preferred[0] if preferred else finding_pool[0]

        raw_spl = _strip_code_fence(_safe_str(query.get("spl")))
        if not raw_spl:
            anchor_index = _preferred_anchor_index()
            raw_spl = f"index={anchor_index} earliest=-24h | stats count by sourcetype host | sort - count"
        normalized_spl = ensure_spl_time_bounds(_anchor_spl_to_environment(raw_spl), "-24h")

        # Evidence comes from what the SPL searches, not from what the model claims it uses.
        evidence = _extract_environment_evidence(normalized_spl)

        severity = matching_finding.get("severity", "medium") if matching_finding else "medium"
        priority = _safe_str(query.get("priority"), _priority_from_severity(severity))
        if not any(priority.startswith(prefix) for prefix in ["🔴", "🟠", "🟡"]):
            priority = _priority_from_severity(severity)

        title = _safe_str(query.get("title"), f"🔍 Contextual Query {idx + 1}")
        description = _safe_str(query.get("description"), "Investigate this finding with environment-specific telemetry.")

        return {
            "title": title,
            "description": description,
            "use_case": _safe_str(query.get("use_case"), default_use_case_by_category.get(category, "Performance Monitoring")),
            "category": category,
            "spl": normalized_spl,
            "finding_reference": finding_ref or (matching_finding.get("reference") if matching_finding else "Discovery-derived finding"),
            "execution_time": _safe_str(query.get("execution_time"), "< 30s"),
            "business_value": _safe_str(query.get("business_value"), "Provides measurable visibility into operational and risk posture."),
            "priority": priority,
            "difficulty": _safe_str(query.get("difficulty"), "Intermediate"),
            "environment_evidence": evidence,
            "query_source": _safe_str(query.get("query_source"), "ai_finding")
        }

    def _context_engine_queries(finding_pool: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        anchor_index = _preferred_anchor_index()

        candidates = [
            {
                "title": "📈 Data Throughput & Coverage Drift",
                "description": "Track ingestion drift by index and sourcetype to detect sudden blind spots.",
                "use_case": "Performance Monitoring",
                "category": "Infrastructure & Performance",
                "spl": f"index={anchor_index} earliest=-24h | bin _time span=1h | stats count dc(host) as hosts dc(sourcetype) as sourcetypes by _time | eval ingestion_risk=if(count<100,\"review\",\"ok\")",
                "finding_reference": (finding_pool[0]["reference"] if finding_pool else "Coverage and ingestion monitoring"),
                "execution_time": "< 30s",
                "business_value": "Flags ingestion degradation early before detections lose fidelity.",
                "priority": "🔴 HIGH",
                "difficulty": "Intermediate",
                "query_source": "context_engine"
            },
            {
                "title": "🛡️ Security Signal Health by Sourcetype",
                "description": "Validate that expected security telemetry is present and consistent.",
                "use_case": "Security Investigation",
                "category": "Security & Compliance",
                "spl": "| tstats count where index=* earliest=-24h by index sourcetype | sort - count",
                "finding_reference": "Risk validation for security monitoring coverage.",
                "execution_time": "< 30s",
                "business_value": "Confirms security-useful data remains searchable and complete.",
                "priority": "🔴 HIGH",
                "difficulty": "Beginner",
                "query_source": "context_engine"
            },
            {
                "title": "🧪 Unknown Entity Validation",
                "description": "Profile volume and spread for unknown entities requiring classification.",
                "use_case": "Data Quality",
                "category": "Data Quality",
                "spl": "| tstats count where index=* earliest=-7d by index sourcetype host | sort count | head 50",
                "finding_reference": "Unknown entities need context before onboarding decisions.",
                "execution_time": "< 45s",
                "business_value": "Turns unknown data into actionable ownership and onboarding tasks.",
                "priority": "🟠 MEDIUM",
                "difficulty": "Intermediate",
                "query_source": "context_engine"
            },
            {
                "title": "📊 Hotspot Trend for High-Risk Sources",
                "description": "Trend high-volume sources to identify accelerating operational or risk hotspots.",
                "use_case": "Capacity Planning",
                "category": "Capacity Planning",
                "spl": f"index={anchor_index} earliest=-14d | timechart span=1d count by sourcetype limit=10 useother=true",
                "finding_reference": "Trend and hotspot validation from discovery intelligence.",
                "execution_time": "< 60s",
                "business_value": "Supports capacity and risk planning with trend evidence.",
                "priority": "🟠 MEDIUM",
                "difficulty": "Intermediate",
                "query_source": "context_engine"
            }
        ]
        return candidates

    def _normalize_task_item(task: Dict[str, Any], idx: int, finding_pool: List[Dict[str, str]]) -> Dict[str, Any]:
        if not isinstance(task, dict):
            task = {}

        priority_raw = _safe_str(task.get("priority"), "MEDIUM").upper()
        if priority_raw not in {"HIGH", "MEDIUM", "LOW"}:
            priority_raw = "MEDIUM"

        category_raw = _safe_str(task.get("category"), "Configuration")
        valid_categories = {"Security", "Performance", "Compliance", "Data Quality", "Configuration"}
        if category_raw not in valid_categories:
            category_raw = "Configuration"

        steps_raw = task.get("steps") if isinstance(task.get("steps"), list) else []
        normalized_steps: List[Dict[str, str]] = []
        for step_idx, step in enumerate(steps_raw[:5]):
            if isinstance(step, dict):
                action_text = _safe_str(
                    step.get("action") or step.get("step") or step.get("description"),
                    f"Perform remediation step {step_idx + 1}.",
                )
                raw_step_spl = _strip_code_fence(_safe_str(step.get("spl")))
            else:
                action_text = _safe_str(step, f"Perform remediation step {step_idx + 1}.")
                raw_step_spl = ""

            normalized_steps.append({
                "number": step_idx + 1,
                "action": action_text,
                "spl": _anchor_spl_to_environment(raw_step_spl) if raw_step_spl else "",
            })

        if not normalized_steps:
            normalized_steps = [
                {
                    "number": 1,
                    "action": _safe_str(
                        task.get("next_step") or task.get("description"),
                        "Investigate the highlighted finding and apply the recommended control change.",
                    ),
                    "spl": "",
                }
            ]

        verification_spl = _strip_code_fence(_safe_str(task.get("verification_spl")))
        if verification_spl:
            verification_spl = _anchor_spl_to_environment(verification_spl)
        elif normalized_steps and _safe_str(normalized_steps[0].get("spl")):
            verification_spl = _safe_str(normalized_steps[0].get("spl"))
        else:
            verification_spl = f"index={_preferred_anchor_index()} earliest=-24h | stats count as post_change_events"

        evidence = _extract_environment_evidence(
            [verification_spl] + [_safe_str(step.get("spl")) for step in normalized_steps]
        )

        matching_finding = finding_pool[idx] if idx < len(finding_pool) else (finding_pool[0] if finding_pool else None)

        return {
            "title": _safe_str(task.get("title"), f"Contextual remediation task {idx + 1}"),
            "priority": priority_raw,
            "category": category_raw,
            "description": _safe_str(task.get("description"), "Apply this action to reduce risk and improve telemetry quality in your environment."),
            "prerequisites": task.get("prerequisites") if isinstance(task.get("prerequisites"), list) and task.get("prerequisites") else ["Search access to affected indexes", "Change window approval if production-impacting"],
            "steps": normalized_steps,
            "verification_spl": verification_spl,
            "expected_outcome": _safe_str(task.get("expected_outcome"), "Improved stability, visibility, and measurable reduction in the targeted risk."),
            "impact": _safe_str(task.get("impact"), "Improves operational confidence and lowers blind-spot risk."),
            "estimated_time": _safe_str(task.get("estimated_time"), "1-2 hours"),
            "rollback": _safe_str(task.get("rollback"), "Revert configuration changes and re-run baseline query for validation."),
            "environment_evidence": evidence,
            "finding_reference": matching_finding.get("reference") if matching_finding else "Discovery-derived finding"
        }

    def _context_engine_tasks(finding_pool: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        anchor_index = _preferred_anchor_index()
        security_ref = next((f for f in finding_pool if f.get("domain") == "Security & Compliance"), None)
        perf_ref = next((f for f in finding_pool if f.get("domain") == "Infrastructure & Performance"), None)
        quality_ref = next((f for f in finding_pool if f.get("domain") == "Data Quality"), None)

        return [
            {
                "title": "Establish telemetry health baseline and anomaly guardrails",
                "priority": "HIGH",
                "category": "Data Quality",
                "description": "Create a repeatable baseline for ingestion, source diversity, and volatility so regressions can be detected quickly.",
                "prerequisites": ["Access to search indexes", "Agreement on baseline thresholds"],
                "steps": [
                    {"number": 1, "action": "Capture baseline counts by index/sourcetype/host.", "spl": f"index={anchor_index} earliest=-24h | stats count dc(host) as hosts dc(sourcetype) as sourcetypes by index"},
                    {"number": 2, "action": "Define alert thresholds for low-volume or missing data windows."},
                    {"number": 3, "action": "Schedule recurring baseline checks and ownership review."}
                ],
                "verification_spl": f"index={anchor_index} earliest=-24h | timechart span=1h count by sourcetype limit=10",
                "expected_outcome": "Daily and hourly telemetry baselines exist with alertable thresholds.",
                "impact": "Reduces blind spots and shortens mean-time-to-detection for ingestion failures.",
                "estimated_time": "2 hours",
                "rollback": "Remove scheduled checks and revert threshold configs.",
                "finding_reference": (quality_ref or perf_ref or security_ref or {"reference": "Discovery trend validation"}).get("reference")
            },
            {
                "title": "Validate high-risk security signal coverage",
                "priority": "HIGH",
                "category": "Security",
                "description": "Ensure critical security sourcetypes and hosts are consistently represented and searchable.",
                "prerequisites": ["Security data owner mapping", "Access to relevant security indexes"],
                "steps": [
                    {"number": 1, "action": "Measure signal consistency by sourcetype and host.", "spl": f"index={anchor_index} earliest=-7d | stats count by sourcetype host | sort - count"},
                    {"number": 2, "action": "Identify missing/low-volume sources and assign remediation owners."},
                    {"number": 3, "action": "Re-run signal consistency query after remediation."}
                ],
                "verification_spl": f"index={anchor_index} earliest=-24h | stats dc(host) as active_hosts dc(sourcetype) as active_sourcetypes",
                "expected_outcome": "Critical security signals are present with stable source coverage.",
                "impact": "Improves detection reliability and reduces high-severity monitoring gaps.",
                "estimated_time": "3 hours",
                "rollback": "Revert onboarding/filter changes and restore previous source routing.",
                "finding_reference": (security_ref or quality_ref or perf_ref or {"reference": "Security risk validation"}).get("reference")
            },
            {
                "title": "Operationalize recursive risk verification loop",
                "priority": "MEDIUM",
                "category": "Configuration",
                "description": "Convert discovery risks into a repeatable review loop with measurable closure criteria.",
                "prerequisites": ["Risk owner assignment", "Weekly review cadence"],
                "steps": [
                    {"number": 1, "action": "Map each top risk to a validation query and owner.", "spl": f"index={anchor_index} earliest=-14d | timechart span=1d count by sourcetype"},
                    {"number": 2, "action": "Track unresolved items and escalation age."},
                    {"number": 3, "action": "Review weekly deltas and close or re-prioritize risks."}
                ],
                "verification_spl": f"index={anchor_index} earliest=-7d | stats count by host sourcetype",
                "expected_outcome": "Each risk has owner, evidence query, and clear closure criteria.",
                "impact": "Builds predictable risk reduction and continuous improvement.",
                "estimated_time": "1 day",
                "rollback": "Disable loop schedule and revert to ad-hoc review model.",
                "finding_reference": (perf_ref or security_ref or quality_ref or {"reference": "Recursive risk reduction"}).get("reference")
            }
        ]
    
    findings_prompt = f"""Analyze these Splunk discovery artifacts and extract specific, actionable findings.

**Executive Summary:**
{executive_summary[:3000]}

**Detailed Findings:**
{detailed_findings[:3000]}

**Classification Report:**
{classification_report[:2000]}

**Discovered Indexes:** {', '.join(discovered_indexes_list[:20])}
**Discovered Sourcetypes:** {', '.join(discovered_sourcetypes_list[:30])}
**Discovered Hosts:** {', '.join(discovered_hosts_list[:20])}

Extract specific findings in these categories:
1. **Security Issues** (failed logins, suspicious activity, missing security monitoring)
2. **Performance Issues** (high CPU/memory/disk, slow queries, bottlenecks)
3. **Data Quality Issues** (missing data, parsing errors, empty indexes, data gaps)
4. **Optimization Opportunities** (retention policies, acceleration, index consolidation)
5. **Compliance Gaps** (missing audit logs, retention violations, access control issues)
6. **Trend Signals** (behavior shifts over time windows, emerging hot spots)
7. **Risk & Vulnerability Hypotheses** (areas that need follow-up checks)

For each finding, provide:
- **Type**: Specific issue type
- **Severity**: critical/high/medium/low
- **Description**: What was found (include specific numbers, indexes, sourcetypes when mentioned)
- **Affected_Resources**: Specific indexes, sourcetypes, or hosts mentioned
- **Metric**: Specific number/percentage if available
- **Recommendation**: How to investigate or fix it

Return as JSON:
{{
  "security_findings": [
    {{"type": "...", "severity": "...", "description": "...", "affected_resources": [...], "metric": "...", "recommendation": "..."}}
  ],
  "performance_findings": [...],
  "data_quality_findings": [...],
  "optimization_findings": [...],
    "compliance_findings": [...],
    "trend_findings": [...],
    "risk_hypotheses": [...]
}}

Focus on ACTUAL findings from the reports with SPECIFIC details. If no findings in a category, return empty array.
Return ONLY the JSON object."""

    # Update progress - starting AI analysis
    _set_summarization_progress(
        timestamp,
        scope_key=request_scope_key,
        stage="ai_analysis",
        progress=65,
        message="AI analyzing findings (this may take 1-3 minutes)...",
    )
    
    try:
        findings_max_tokens = llm_call_budget(config, 0.5, floor=1536, ceiling=4000)
        findings_response = await llm_client.generate_response(
            prompt=findings_prompt,
            max_tokens=findings_max_tokens,
            temperature=0.3
        )
        
        # Handles fenced JSON, <think> blocks from reasoning models, and trailing commas.
        ai_findings = extract_json_payload(findings_response, expect="dict")
        if not isinstance(ai_findings, dict):
            raise json.JSONDecodeError("No JSON object in findings response", str(findings_response or "")[:200], 0)
        print(f"AI extracted findings: {len(ai_findings.get('security_findings', []))} security, "
              f"{len(ai_findings.get('performance_findings', []))} performance, "
              f"{len(ai_findings.get('data_quality_findings', []))} data quality")
        
    except json.JSONDecodeError as e:
        print(f"Error parsing findings JSON: {e}")
        print(f"Response length: {len(findings_response) if 'findings_response' in locals() else 0}")
        ai_findings = {
            "security_findings": [],
            "performance_findings": [],
            "data_quality_findings": [],
            "optimization_findings": [],
            "compliance_findings": [],
            "trend_findings": [],
            "risk_hypotheses": []
        }
    except Exception as e:
        print(f"Error extracting findings with AI: {e}")
        ai_findings = {
            "security_findings": [],
            "performance_findings": [],
            "data_quality_findings": [],
            "optimization_findings": [],
            "compliance_findings": [],
            "trend_findings": [],
            "risk_hypotheses": []
        }
    
    # Update progress - findings extracted
    _set_summarization_progress(
        timestamp,
        scope_key=request_scope_key,
        stage="generating_queries",
        progress=75,
        message="AI generating SPL queries (1-2 minutes)...",
    )
    
    # ===== AI-POWERED QUERY GENERATION =====
    # Generate SPL queries based on actual findings
    query_generation_prompt = f"""Generate 8 SPL queries based on these Splunk findings.

Findings: {json.dumps(ai_findings, indent=2)[:2000]}

Environment Context: {json.dumps(environment_context_block, indent=2)[:2500]}

Return JSON array with exactly 8 queries. Each query must have:
- title: Clear, actionable title with emoji
- description: 1 sentence explaining the query
- use_case: Security Investigation, Performance Monitoring, Data Quality, or Capacity Planning
- category: Security & Compliance, Infrastructure & Performance, Data Quality, or Capacity Planning
- spl: Valid SPL query using actual indexes/sourcetypes/hosts from this specific environment context
- finding_reference: Which finding this addresses
- execution_time: Estimated time
- business_value: Why this matters
- priority: 🔴 HIGH, 🟠 MEDIUM, or 🟡 LOW
- difficulty: Beginner, Intermediate, or Advanced
- environment_evidence: array of specific discovered entities used (index/sourcetype/host)

NON-NEGOTIABLE RULES:
1) At least 7/8 queries must reference one or more discovered indexes or sourcetypes from Environment Context.
2) Do not use placeholders like index=main unless it exists in Environment Context.
3) Every query must be directly tied to a discovery finding or risk hypothesis.
4) Include time windows (`earliest=...`) and aggregation logic (`stats`, `timechart`, or `tstats`) for operational usefulness.
5) Avoid near-duplicate queries; each query should answer a distinct investigative question.

Example:
[{{"title": "🔍 Investigation Title", "description": "What this does", "use_case": "Security Investigation", "category": "Security & Compliance", "spl": "index=main | stats count", "finding_reference": "Specific finding", "execution_time": "< 30s", "business_value": "Why it matters", "priority": "🔴 HIGH", "difficulty": "Beginner"}}]

Return ONLY the JSON array of 8 queries, nothing else."""

    finding_based_queries = []
    try:
        query_max_tokens = llm_call_budget(config, 1.0, floor=2048, ceiling=8000)
        
        # Debug: Check what we're sending to LLM
        print(f"DEBUG: Generating queries - {len(ai_findings.get('security_findings', []))} security, "
              f"{len(ai_findings.get('data_quality_findings', []))} data quality findings")
        print(f"DEBUG: Using {len(discovered_indexes)} indexes, {len(discovered_sourcetypes)} sourcetypes, "
              f"max_tokens={query_max_tokens}")
        
        queries_response = await llm_client.generate_response(
            prompt=query_generation_prompt,
            max_tokens=query_max_tokens,
            temperature=0.75  # Higher temperature for creative, varied query generation
        )
        
        print(f"DEBUG: LLM response length: {len(queries_response)}")
        print(f"DEBUG: Response starts with: {queries_response[:100]}")
        print(f"DEBUG: Response ends with: {queries_response[-100:]}")
        
        # Truncated arrays are salvaged into their complete elements.
        parsed_queries = extract_json_payload(queries_response, expect="list", list_keys=("queries", "spl_queries", "items"))
        finding_based_queries = [q for q in (parsed_queries or []) if isinstance(q, dict) and str(q.get('spl') or '').strip()]
        if not finding_based_queries:
            print("No usable finding-based queries in the model response; using context and template queries")
        else:
            print(f"✅ AI generated {len(finding_based_queries)} finding-based queries")

        for q in finding_based_queries:
            q['query_source'] = 'ai_finding'
    except Exception as e:
        print(f"Error generating finding-based queries with AI: {e}")
        finding_based_queries = []
    
    # Normalize and enrich query set using finding-aware + context-engine strategies
    finding_pool = _flatten_findings(ai_findings)
    context_engine_query_candidates = _context_engine_queries(finding_pool)

    normalized_query_candidates: List[Dict[str, Any]] = []
    for idx, query_item in enumerate(finding_based_queries):
        if isinstance(query_item, dict):
            normalized_query_candidates.append(_normalize_query_item(query_item, idx, finding_pool))

    for idx, query_item in enumerate(context_engine_query_candidates):
        normalized_query_candidates.append(_normalize_query_item(query_item, len(normalized_query_candidates) + idx, finding_pool))

    for idx, template_query in enumerate(template_queries):
        if not isinstance(template_query, dict):
            continue
        template_copy = dict(template_query)
        template_copy["query_source"] = "template"
        normalized_query_candidates.append(_normalize_query_item(template_copy, len(normalized_query_candidates) + idx, finding_pool))

    deduped_queries: List[Dict[str, Any]] = []
    seen_query_keys = set()
    for query in normalized_query_candidates:
        key = re.sub(r"\s+", " ", _safe_str(query.get("spl"), "").lower()).strip()
        if not key:
            continue
        if key in seen_query_keys:
            continue
        seen_query_keys.add(key)
        deduped_queries.append(query)

    def _query_rank(query: Dict[str, Any]) -> Tuple[int, int, int, int]:
        source_rank = 0 if query.get("query_source") == "ai_finding" else 1 if query.get("query_source") == "context_engine" else 2
        priority_rank = 0 if str(query.get("priority", "")).startswith("🔴") else 1 if str(query.get("priority", "")).startswith("🟠") else 2
        evidence_rank = -len(query.get("environment_evidence", []) if isinstance(query.get("environment_evidence", []), list) else [])
        complexity_rank = -len(_safe_str(query.get("spl"), ""))
        return (source_rank, priority_rank, evidence_rank, complexity_rank)

    deduped_queries.sort(key=_query_rank)
    queries = deduped_queries[:10]

    # Ensure minimum query volume and environment anchoring
    if len(queries) < 8:
        for candidate in deduped_queries[10:]:
            queries.append(candidate)
            if len(queries) >= 8:
                break

    print(f"📊 Query Status: AI raw={len(finding_based_queries)}, context_engine={len(context_engine_query_candidates)}, template={len(template_queries)}, final={len(queries)}")
    
    # Debug: Show query sources
    ai_query_count = sum(1 for q in queries if q.get('query_source') == 'ai_finding')
    template_query_count = sum(1 for q in queries if q.get('query_source') == 'template')
    print(f"📝 Final query breakdown: {ai_query_count} AI-generated, {template_query_count} template-based")
    
    # Prioritize queries (AI findings first, then by priority)
    queries.sort(key=lambda q: (
        0 if q.get('query_source') == 'ai_finding' else 1,  # AI findings first
        0 if q.get('priority', '').startswith('🔴') else 
        1 if q.get('priority', '').startswith('🟠') else
        2 if q.get('priority', '').startswith('🟡') else 3,  # Then by priority
        -len(q.get('spl', ''))  # Then by complexity
    ))
    
    # Update progress - AI summary generation
    _set_summarization_progress(
        timestamp,
        scope_key=request_scope_key,
        stage="generating_summary",
        progress=70,
        message="Building executive summary...",
    )
    
    # Generate AI summary
    config = config_manager.get()
    llm_client = get_or_create_llm_client(config)
    
    # Get current date for temporal context
    from datetime import datetime
    current_date = datetime.now().strftime("%B %d, %Y")
    
    summary_prompt = f"""You are analyzing a Splunk intelligence report. Create a high-value executive summary.

**IMPORTANT CONTEXT:** Today's date is {current_date}. Any timestamps in the reports should be interpreted relative to this date, not as future dates.

**Discovery Reports:**
{executive_summary[:3000]}

**Key Findings:**
{detailed_findings[:2000]}

**Data Classification:**
{classification_report[:2000]}

Please provide:
1. **Executive Summary** (3-4 sentences highlighting most important findings based on ACTUAL data in reports)
2. **Priority Actions** (Top 3 immediate actions the admin should take)
3. **Quick Wins** (2-3 easy implementations with high impact)
4. **Risk Areas** (Any security or compliance gaps identified)
5. **Trend Story** (what appears to be changing, increasing, or degrading)
6. **Next Check** (what to check again in the next discovery run)

Keep it concise and actionable. Focus on business value, risk reduction, and measurable outcomes. Base all statements on actual data from the reports above."""
    
    # Update progress - creating summary
    _set_summarization_progress(
        timestamp,
        scope_key=request_scope_key,
        stage="creating_summary",
        progress=82,
        message="AI creating executive summary (30-60 seconds)...",
    )
    
    try:
        summary_max_tokens = llm_call_budget(config, 0.4, floor=1024, ceiling=2000)
        ai_summary = await llm_client.generate_response(
            prompt=summary_prompt,
            max_tokens=summary_max_tokens,
            temperature=0.7
        )
    except Exception as e:
        ai_summary = f"Could not generate AI summary: {str(e)}"
    
    # Update progress - Admin tasks generation
    _set_summarization_progress(
        timestamp,
        scope_key=request_scope_key,
        stage="generating_tasks",
        progress=88,
        message="AI generating admin tasks (1-2 minutes)...",
    )
    
    # ===== ADMIN TASK GENERATION =====
    # Generate actionable admin tasks based on findings
    admin_tasks = []
    
    tasks_prompt = f"""Based on the Splunk discovery analysis below, generate a prioritized list of implementation tasks for the Splunk administrator.

**Discovery Reports:**
{executive_summary[:2500]}

**Key Findings:**
{detailed_findings[:2000]}

**Environment Context (use this explicitly):**
{json.dumps(environment_context_block, indent=2)[:2500]}

For each task, provide:
1. **Title**: Clear, action-oriented task name
2. **Priority**: HIGH/MEDIUM/LOW based on impact and urgency
3. **Category**: Security/Performance/Compliance/Data Quality/Configuration
4. **Description**: 2-3 sentences explaining why this task matters
5. **Prerequisites**: What's needed before starting (e.g., admin access, specific licenses)
6. **Steps**: 3-5 specific implementation steps with SPL queries where applicable
7. **Verification SPL**: A query to verify the task was completed successfully (use standard SPL commands like 'search', 'stats', 'tstats' - avoid 'rest' or admin-only commands)
8. **Expected Outcome**: What should be true after successful implementation
9. **Impact**: Business value and ROI of completing this task
10. **Estimated Time**: Realistic time estimate (e.g., "30 minutes", "2 hours", "1 day")

IMPORTANT: Verification queries should use standard SPL commands (search, stats, tstats, timechart) that any user can run.
Avoid using administrative commands like 'rest', 'inputlookup' on system lookups, or commands requiring special permissions.

Focus on:
- Tasks that address identified gaps or risks
- Quick wins with high impact
- Security improvements
- Data quality enhancements
- Performance optimizations

HARD REQUIREMENTS:
- At least 3 tasks must include SPL that references discovered indexes/sourcetypes/hosts from Environment Context.
- Verification SPL must validate outcomes against environment-specific telemetry.

Return ONLY a valid JSON array of task objects. Each task should follow this structure:
{{
  "title": "Task name",
  "priority": "HIGH|MEDIUM|LOW",
  "category": "Security|Performance|Compliance|Data Quality|Configuration",
  "description": "Why this matters...",
  "prerequisites": ["requirement 1", "requirement 2"],
  "steps": [
    {{"number": 1, "action": "Step description", "spl": "optional SPL query"}},
    {{"number": 2, "action": "Step description", "spl": "optional SPL query"}}
  ],
  "verification_spl": "SPL query to verify completion",
  "expected_outcome": "What should be true after completion",
  "impact": "Business value description",
  "estimated_time": "time estimate",
  "rollback": "How to undo if needed"
}}

Generate 6-8 prioritized tasks. Keep each task concise but actionable.
At least 4 tasks must include verification SPL anchored to discovered indexes/sourcetypes/hosts.
Return ONLY the JSON array, no other text."""

    try:
        # Tasks are detailed JSON with several fields each, so they get the full budget.
        task_max_tokens = llm_call_budget(config, 1.0, floor=2048, ceiling=8000)
        tasks_response = await llm_client.generate_response(
            prompt=tasks_prompt,
            max_tokens=task_max_tokens,
            temperature=0.6
        )
        
        parsed_tasks = extract_json_payload(tasks_response, expect="list", list_keys=("tasks", "admin_tasks", "items"))
        admin_tasks = [task for task in (parsed_tasks or []) if isinstance(task, dict)]
        print(f"Generated {len(admin_tasks)} admin tasks")
        
        # Update progress - Tasks generated successfully
        _set_summarization_progress(
            timestamp,
            scope_key=request_scope_key,
            stage="finalizing",
            progress=93,
            message="Finalizing summary...",
        )
        
    except Exception as e:
        print(f"Error generating admin tasks: {e}")
        print(f"Raw response: {tasks_response[:500] if 'tasks_response' in locals() else 'No response'}")
        # Create default tasks based on common findings
        admin_tasks = []

    # Normalize + enrich admin tasks with context-engine supplement
    context_engine_tasks = _context_engine_tasks(finding_pool)
    normalized_task_candidates: List[Dict[str, Any]] = []
    for idx, task in enumerate(admin_tasks):
        normalized_task_candidates.append(_normalize_task_item(task, idx, finding_pool))
    for idx, task in enumerate(context_engine_tasks):
        normalized_task_candidates.append(_normalize_task_item(task, len(normalized_task_candidates) + idx, finding_pool))

    deduped_tasks: List[Dict[str, Any]] = []
    seen_task_titles = set()
    for task in normalized_task_candidates:
        title_key = _safe_str(task.get("title"), "").lower()
        if not title_key or title_key in seen_task_titles:
            continue
        seen_task_titles.add(title_key)
        deduped_tasks.append(task)

    def _task_rank(task: Dict[str, Any]) -> Tuple[int, int]:
        priority = _safe_str(task.get("priority"), "MEDIUM").upper()
        priority_rank = 0 if priority == "HIGH" else 1 if priority == "MEDIUM" else 2
        evidence_rank = -len(task.get("environment_evidence", []) if isinstance(task.get("environment_evidence", []), list) else [])
        return (priority_rank, evidence_rank)

    deduped_tasks.sort(key=_task_rank)
    admin_tasks = deduped_tasks[:6]
    if not admin_tasks:
        admin_tasks = [_normalize_task_item(task, idx, finding_pool) for idx, task in enumerate(context_engine_tasks[:3])]

    print(f"📋 Task Status: ai_raw={len(normalized_task_candidates) - len(context_engine_tasks)}, context_engine={len(context_engine_tasks)}, final={len(admin_tasks)}")

    context_explorer = build_context_explorer_payload(
        discovery_data,
        unknown_questions=unknown_questions,
        admin_tasks=admin_tasks,
        coverage_gaps=coverage_gaps,
        risk_register=risk_register,
        readiness_score=readiness_score,
        session_id=timestamp,
    )
    
    # Prepare response
    response_data = {
        "success": True,
        "session_id": timestamp,
        "schema_version": "2.0",
        "ai_summary": ai_summary,
        "spl_queries": queries,
        "admin_tasks": admin_tasks,
        "unknown_data": unknown_questions,
        "readiness_score": readiness_score,
        "coverage_gaps": coverage_gaps,
        "risk_register": risk_register,
        "trend_signals": trend_signals,
        "vulnerability_hypotheses": vulnerability_hypotheses,
        "recursive_investigations": recursive_investigations,
        "context_explorer": context_explorer,
        "v2_context": {
            "readiness_score": readiness_score,
            "coverage_gaps": len(coverage_gaps),
            "risk_register": len(risk_register),
            "recursive_investigations": len(recursive_investigations)
        },
        "stats": {
            "total_queries": len(queries),
            "total_tasks": len(admin_tasks),
            "unknown_items": len(unknown_questions),
            "categories": list({q.get('category', 'General') for q in queries if isinstance(q, dict)})
        },
        "from_cache": False
    }
    
    # Update progress - Saving results
    _set_summarization_progress(
        timestamp,
        scope_key=request_scope_key,
        stage="saving",
        progress=95,
        message="Saving results...",
    )
    
    # Save summary for future use
    try:
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=2)
        print(f"Saved summary to {summary_file}")
    except Exception as e:
        print(f"Error saving summary: {e}")
        # Don't fail the request if save fails
    
    # Update progress - Complete
    _set_summarization_progress(
        timestamp,
        scope_key=request_scope_key,
        stage="complete",
        progress=100,
        message="Analysis complete!",
    )
    
    return response_data


@app.post("/summarize-session")
async def summarize_session(request: Dict[str, Any], http_request: Request):
    request_scope_key = _build_discovery_scope_metadata(request=http_request).get("scope_key")
    return await _summarize_session_impl(request, request_scope_key=request_scope_key)


@app.post("/verify-task")
async def verify_task(request: Dict[str, Any]):
    """
    Execute verification SPL query and analyze results against expected outcome.
    
    Request:
    {
        "session_id": "20251027_165208",
        "task_index": 0,
        "verification_spl": "| rest /services/data/indexes | search disabled=1 | stats count",
        "expected_outcome": "Zero or minimal disabled indexes remaining"
    }
    
    Response:
    {
        "status": "success|partial|failed",
        "message": "Detailed explanation",
        "results": {...},  # Raw SPL results
        "recommendations": [...],  # If partial/failed
        "metrics": {
            "before": "...",
            "after": "...",
            "improvement": "..."
        }
    }
    """
    try:
        # Validate inputs
        session_id = request.get("session_id")
        task_index = request.get("task_index")
        verification_spl = request.get("verification_spl")
        expected_outcome = request.get("expected_outcome")
        
        if not all([session_id, verification_spl, expected_outcome]):
            return {"error": "Missing required fields"}
        
        # Validate session ID format
        try:
            safe_session_id = validate_session_id(session_id)
        except HTTPException as e:
            return {"error": str(e.detail)}
        
        # Validate task index
        try:
            safe_task_index = int(task_index) if task_index is not None else None
            if safe_task_index is not None and (safe_task_index < 0 or safe_task_index > 1000):
                return {"error": "Invalid task index"}
        except (ValueError, TypeError):
            return {"error": "Task index must be a number"}
        
        # Load configuration
        config = config_manager.get()
        
        # Execute SPL via MCP
        print(f"Executing verification SPL for task {task_index}...")
        
        mcp_tool_call = {
            "method": "tools/call",
            "params": {
                "name": "splunk_run_query",
                "arguments": {
                    "query": verification_spl,
                    "earliest_time": "-24h",
                    "latest_time": "now"
                }
            }
        }
        
        spl_result = await execute_mcp_tool_call(mcp_tool_call, config)
        outcome = classify_tool_result(spl_result)

        # In-band tool errors (result.isError) are failures too, not results to grade.
        if outcome["status"] == "error":
            return {
                "status": "error",
                "message": f"Failed to execute verification query: {outcome.get('error') or 'unknown error'}",
                "results": None
            }

        rows = outcome.get("rows") or []
        rows_text, rows_shown = render_rows_for_llm(rows, max_rows=20, max_chars=3000)
        if rows:
            total_rows = outcome.get("total_rows")
            row_summary = f"{len(rows)} rows returned" + (
                f" (truncated; {total_rows} in total)" if outcome.get("truncated") and isinstance(total_rows, int) else ""
            ) + f"; first {rows_shown} shown below."
        elif outcome.get("text"):
            row_summary = "The tool returned text instead of rows; it is shown below."
            rows_text = str(outcome.get("text"))[:3000]
        else:
            row_summary = "The query returned 0 rows."
            rows_text = "(no rows)"

        # Analyze results with AI
        llm_client = get_or_create_llm_client(config)
        
        analysis_prompt = f"""You are analyzing the results of a Splunk admin task verification.

**Task Verification:**
Expected Outcome: {expected_outcome}

**SPL Query Executed (last 24 hours):**
{verification_spl}

**Query Results:** {row_summary}
{rows_text}

**Analysis Instructions:**
1. Decide whether the rows above show the expected outcome. Use only these rows as evidence.
2. Classify the result as: SUCCESS, PARTIAL, or FAILED. Zero rows proves the outcome only when the expected outcome is that nothing should match.
3. Quote the specific values from the rows when you describe the current state; never invent values.
4. If PARTIAL or FAILED, provide actionable recommendations

Return a JSON object with this structure:
{{
  "status": "success|partial|failed",
  "message": "Clear explanation of the verification result",
  "metrics": {{
    "current_value": "What the query found",
    "expected_value": "What was expected",
    "gap": "What's missing (if any)"
  }},
  "recommendations": ["step 1", "step 2"] // Only if partial/failed
}}

Return ONLY the JSON object, no other text."""

        try:
            analysis_max_tokens = llm_call_budget(config, 0.25, floor=512, ceiling=1000)
            analysis_response = await llm_client.generate_response(
                prompt=analysis_prompt,
                max_tokens=analysis_max_tokens,
                temperature=0.3  # Lower temperature for more consistent analysis
            )
            
            analysis = extract_json_payload(analysis_response, expect="dict")
            if not isinstance(analysis, dict):
                raise ValueError("The model did not return a JSON verdict")
            verdict = str(analysis.get("status") or "").strip().lower()
            analysis["status"] = verdict if verdict in {"success", "partial", "failed"} else "unknown"
            if not isinstance(analysis.get("message"), str) or not analysis.get("message", "").strip():
                analysis["message"] = "The model did not explain its verdict; review the query results."
            
        except Exception as e:
            print(f"Error analyzing verification results: {e}")
            # Fallback analysis
            analysis = {
                "status": "unknown",
                "message": f"Could not analyze results automatically. Raw results available for manual review.",
                "metrics": {},
                "recommendations": ["Review the query results manually", "Ensure the SPL query is correct"]
            }
        
        # Combine SPL results with AI analysis
        response = {
            **analysis,
            "row_count": len(rows),
            "results": spl_result,
            "verification_spl": verification_spl,
            "expected_outcome": expected_outcome,
            "timestamp": datetime.now().isoformat()
        }
        
        # Save verification result - use session timestamp to group with other reports
        output_dir = Path("output")
        verification_file = output_dir / f"verification_task{task_index}_{session_id}.json"
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            with open(verification_file, 'w', encoding='utf-8') as f:
                json.dump(response, f, indent=2)
            print(f"Saved verification result to {verification_file}")
        except Exception as e:
            print(f"Error saving verification: {e}")
        
        return response
        
    except Exception as e:
        print(f"Error in verify_task: {e}")
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "message": f"Verification failed: {str(e)}",
            "results": None
        }


@app.post("/get-remediation")
async def get_remediation(request: Dict[str, Any]):
    """
    Generate AI-powered remediation steps for failed/partial verification.
    
    Request:
    {
        "session_id": "20251027_165208",
        "task_index": 0,
        "task_details": {...},
        "verification_result": {...}
    }
    
    Response:
    {
        "remediation_steps": [...],
        "root_cause": "...",
        "estimated_time": "...",
        "success_probability": "high|medium|low"
    }
    """
    try:
        # Validate inputs
        session_id = request.get("session_id")
        task_index = request.get("task_index")
        task_details = request.get("task_details")
        verification_result = request.get("verification_result")
        
        if not all([session_id, task_details, verification_result]):
            return {"error": "Missing required fields"}
        
        # Validate session ID format
        try:
            safe_session_id = validate_session_id(session_id)
        except HTTPException as e:
            return {"error": str(e.detail)}
        
        # Validate task index
        try:
            safe_task_index = int(task_index) if task_index is not None else None
            if safe_task_index is not None and (safe_task_index < 0 or safe_task_index > 1000):
                return {"error": "Invalid task index"}
        except (ValueError, TypeError):
            return {"error": "Task index must be a number"}
        
        # Load configuration
        config = config_manager.get()
        
        # Generate remediation with AI
        llm_client = get_or_create_llm_client(config)
        
        remediation_prompt = f"""You are a Splunk expert helping an administrator troubleshoot a failed task.

**Task Details:**
Title: {task_details.get('title', 'Unknown')}
Priority: {task_details.get('priority', 'Unknown')}
Category: {task_details.get('category', 'Unknown')}
Description: {task_details.get('description', 'No description')}

**Original Steps Taken:**
{json.dumps(task_details.get('steps', []), indent=2)}

**Verification Results:**
Status: {verification_result.get('status', 'unknown')}
Message: {verification_result.get('message', 'No message')}
Metrics: {json.dumps(verification_result.get('metrics', {}), indent=2)}
Current Recommendations: {json.dumps(verification_result.get('recommendations', []), indent=2)}

**Your Task:**
Analyze why the verification failed and provide detailed remediation guidance.

Return a JSON object with:
{{
  "root_cause": "Primary reason for failure (1-2 sentences)",
  "remediation_steps": [
    {{
      "number": 1,
      "action": "Detailed step description",
      "spl": "SPL query if applicable (optional)",
      "explanation": "Why this step helps",
      "risk": "low|medium|high"
    }}
  ],
  "estimated_time": "Realistic time to complete remediation",
  "success_probability": "high|medium|low",
  "preventive_measures": ["How to avoid this issue in the future"],
  "alternative_approaches": ["Other ways to accomplish the same goal"]
}}

Focus on actionable, specific steps. Include SPL queries where helpful.
Return ONLY the JSON object."""

        try:
            remediation_max_tokens = llm_call_budget(config, 0.4, floor=768, ceiling=2000)
            remediation_response = await llm_client.generate_response(
                prompt=remediation_prompt,
                max_tokens=remediation_max_tokens,
                temperature=0.5
            )
            
            remediation = extract_json_payload(remediation_response, expect="dict")
            if not isinstance(remediation, dict) or not remediation.get("remediation_steps"):
                raise ValueError("The model did not return remediation steps as JSON")
            
        except Exception as e:
            print(f"Error generating remediation: {e}")
            # Fallback remediation
            remediation = {
                "root_cause": "Unable to automatically determine the root cause. Manual investigation required.",
                "remediation_steps": [
                    {
                        "number": 1,
                        "action": "Review the verification results and query output carefully",
                        "explanation": "Understanding what the query returned is the first step",
                        "risk": "low"
                    },
                    {
                        "number": 2,
                        "action": "Check Splunk logs for any related errors or warnings",
                        "spl": "index=_internal source=*splunkd.log ERROR OR WARN earliest=-1h",
                        "explanation": "System logs may reveal underlying issues",
                        "risk": "low"
                    },
                    {
                        "number": 3,
                        "action": "Consult Splunk documentation for the specific feature or configuration",
                        "explanation": "Official documentation may have troubleshooting steps",
                        "risk": "low"
                    }
                ],
                "estimated_time": "30-60 minutes",
                "success_probability": "medium",
                "preventive_measures": ["Regular monitoring", "Documentation of changes"],
                "alternative_approaches": ["Manual verification", "Consult Splunk support"]
            }
        
        # Add metadata
        remediation['session_id'] = session_id
        remediation['task_index'] = task_index
        remediation['timestamp'] = datetime.now().isoformat()
        
        # Save remediation
        output_dir = Path("output")
        remediation_file = output_dir / f"remediation_task{task_index}_{session_id}.json"
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            with open(remediation_file, 'w', encoding='utf-8') as f:
                json.dump(remediation, f, indent=2)
            print(f"Saved remediation to {remediation_file}")
        except Exception as e:
            print(f"Error saving remediation: {e}")
        
        return remediation
        
    except Exception as e:
        print(f"Error in get_remediation: {e}")
        import traceback
        traceback.print_exc()
        return {
            "error": f"Failed to generate remediation: {str(e)}"
        }


@app.get("/verification-history/{session_id}/{task_index}")
async def get_verification_history(session_id: str, task_index: int):
    """
    Get verification history for a specific task, showing improvements over time.
    
    Response:
    {
        "verifications": [...],
        "remediations": [...],
        "success_rate": 0.75,
        "total_attempts": 4,
        "time_to_success": "2 hours",
        "improvement_trend": "improving|stable|declining"
    }
    """
    try:
        output_dir = Path("output")
        
        # Find all verification files for this task
        verification_pattern = f"verification_task{task_index}_{session_id}*.json"
        verification_files = sorted(output_dir.glob(verification_pattern))
        
        # Find all remediation files for this task
        remediation_pattern = f"remediation_task{task_index}_{session_id}*.json"
        remediation_files = sorted(output_dir.glob(remediation_pattern))
        
        verifications = []
        for vf in verification_files:
            try:
                with open(vf, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    data['filename'] = vf.name
                    data['file_timestamp'] = datetime.fromtimestamp(vf.stat().st_mtime).isoformat()
                    verifications.append(data)
            except Exception as e:
                print(f"Error loading verification {vf}: {e}")
        
        remediations = []
        for rf in remediation_files:
            try:
                with open(rf, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    data['filename'] = rf.name
                    data['file_timestamp'] = datetime.fromtimestamp(rf.stat().st_mtime).isoformat()
                    remediations.append(data)
            except Exception as e:
                print(f"Error loading remediation {rf}: {e}")
        
        # Calculate metrics
        total_attempts = len(verifications)
        successful = sum(1 for v in verifications if v.get('status') == 'success')
        success_rate = successful / total_attempts if total_attempts > 0 else 0
        
        # Determine improvement trend
        if total_attempts >= 2:
            recent_status = [v.get('status') for v in verifications[-3:]]
            if recent_status[-1] == 'success':
                trend = "improving"
            elif all(s == recent_status[0] for s in recent_status):
                trend = "stable"
            else:
                trend = "declining"
        else:
            trend = "insufficient_data"
        
        # Calculate time to success
        time_to_success = None
        if successful > 0:
            first_timestamp = datetime.fromisoformat(verifications[0].get('timestamp', datetime.now().isoformat()))
            success_timestamp = next((datetime.fromisoformat(v.get('timestamp', datetime.now().isoformat())) 
                                     for v in verifications if v.get('status') == 'success'), None)
            if success_timestamp:
                delta = success_timestamp - first_timestamp
                hours = delta.total_seconds() / 3600
                if hours < 1:
                    time_to_success = f"{int(delta.total_seconds() / 60)} minutes"
                else:
                    time_to_success = f"{hours:.1f} hours"
        
        return {
            "verifications": verifications,
            "remediations": remediations,
            "success_rate": success_rate,
            "total_attempts": total_attempts,
            "successful_attempts": successful,
            "time_to_success": time_to_success,
            "improvement_trend": trend
        }
        
    except Exception as e:
        print(f"Error in get_verification_history: {e}")
        import traceback
        traceback.print_exc()
        return {
            "error": f"Failed to get verification history: {str(e)}"
        }


@app.post("/chat/stream")
async def chat_with_splunk_stream(http_request: Request, request: dict):
    """Stream chat responses with real-time status updates via SSE."""
    # Create a queue for status updates
    status_queue = asyncio.Queue()
    runtime_config = resolve_effective_runtime_config(request=http_request)
    goal_owner = chat_goal_owner(http_request)
    
    async def generate_sse():
        """Generator for Server-Sent Events."""
        try:
            # Process chat in background task
            chat_task = asyncio.create_task(
                process_chat_with_streaming(request, status_queue, runtime_config=runtime_config, goal_owner=goal_owner)
            )
            
            # Stream status updates as they come in
            while True:
                try:
                    # Wait for next status update with timeout
                    update = await asyncio.wait_for(status_queue.get(), timeout=0.1)
                    
                    if update['type'] == 'done':
                        # Send final response and close stream
                        yield f"data: {json.dumps({'type': 'response', 'data': update['data']})}\n\n"
                        break
                    elif update['type'] == 'error':
                        yield f"data: {json.dumps({'type': 'error', 'error': update['error']})}\n\n"
                        break
                    else:
                        # Send status update
                        yield f"data: {json.dumps(update)}\n\n"
                        
                except asyncio.TimeoutError:
                    # No new updates, send keepalive
                    yield ": keepalive\n\n"
                    
                    # The task can enqueue its terminal update and finish in
                    # the small window between wait_for timing out and this
                    # check. Always drain that update before closing the SSE
                    # stream or the UI remains stuck without a final answer.
                    if chat_task.done():
                        terminal_sent = False
                        while True:
                            try:
                                queued_update = status_queue.get_nowait()
                            except asyncio.QueueEmpty:
                                break

                            if queued_update.get("type") == "done":
                                yield f"data: {json.dumps({'type': 'response', 'data': queued_update['data']})}\n\n"
                                terminal_sent = True
                                break
                            if queued_update.get("type") == "error":
                                yield f"data: {json.dumps({'type': 'error', 'error': queued_update['error']})}\n\n"
                                terminal_sent = True
                                break

                            yield f"data: {json.dumps(queued_update)}\n\n"

                        if not terminal_sent:
                            yield f"data: {json.dumps({'type': 'error', 'error': 'Chat processing ended without a final response.'})}\n\n"
                        break
                        
        except Exception as e:
            print(f"SSE Error: {e}")
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'type': 'error', 'error': str(e)})}\n\n"
    
    return StreamingResponse(generate_sse(), media_type="text/event-stream")


def load_latest_discovery_insights():
    """Load key insights from the latest discovery artifacts for agent context."""
    knowledge = load_latest_report_knowledge(chat_session_settings.get("discovery_freshness_days", 7))
    if not knowledge:
        return None

    return {
        'summary_text': knowledge.get('executive_summary', ''),
        'structured': {
            'key_findings': knowledge.get('headline_findings', []),
            'recommendations': [
                rec.get('title') for rec in knowledge.get('recommendations', [])[:5]
                if isinstance(rec, dict) and rec.get('title')
            ],
            'data_patterns': knowledge.get('trend_signals', {}),
            'coverage_gaps': [
                gap.get('gap') for gap in knowledge.get('coverage_gaps', [])[:5]
                if isinstance(gap, dict) and gap.get('gap')
            ],
        },
        'age_days': knowledge.get('age_days', 0),
        'timestamp': knowledge.get('timestamp', ''),
    }


def _read_text_if_exists(path: Path, limit: Optional[int] = None) -> str:
    if not isinstance(path, Path) or not path.exists():
        return ""
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return ""
    if isinstance(limit, int) and limit > 0:
        return text[:limit]
    return text


def _read_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    text = _read_text_if_exists(path)
    if not text:
        return None
    try:
        payload = json.loads(text)
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _extract_markdown_section_items(markdown_text: str, heading: str, max_items: int = 4) -> List[str]:
    if not isinstance(markdown_text, str) or not markdown_text.strip():
        return []

    heading_pattern = re.escape(heading).replace(r'\ ', r'\s+')
    pattern = rf'##\s+(?:\d+[.)]\s*)?(?:\*\*)?{heading_pattern}(?:\*\*)?\s*\n(.*?)(?:\n##\s+|\Z)'
    match = re.search(pattern, markdown_text, re.DOTALL | re.IGNORECASE)
    if not match:
        return []

    items: List[str] = []
    for line in match.group(1).splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        cleaned = re.sub(r'^[-*]\s+', '', cleaned)
        cleaned = re.sub(r'^\d+\.\s+', '', cleaned)
        cleaned = cleaned.replace('**', '').replace('`', '').strip()
        if cleaned:
            items.append(cleaned)
    return items[:max(1, max_items)]


def _decode_jsonish_string(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""

    try:
        return json.loads(f'"{text}"')
    except Exception:
        return (
            text
            .replace('\\n', ' ')
            .replace('\\r', ' ')
            .replace('\\t', ' ')
            .replace('\\"', '"')
            .strip()
        )


def _extract_v2_notable_patterns_from_text(raw_text: str) -> List[Dict[str, Any]]:
    if not isinstance(raw_text, str) or not raw_text.strip():
        return []

    extracted: List[Dict[str, Any]] = []
    segments = re.split(r'(?="category"\s*:)', raw_text)
    for segment in segments:
        category_match = re.search(r'"category"\s*:\s*"((?:\\.|[^"\\])*)"', segment)
        insight_match = re.search(r'"insight"\s*:\s*"((?:\\.|[^"\\])*)"', segment, re.DOTALL)
        if not category_match and not insight_match:
            continue

        evidence_items: List[str] = []
        evidence_match = re.search(r'"evidence"\s*:\s*\[(.*?)\]', segment, re.DOTALL)
        if evidence_match:
            for item in re.findall(r'"((?:\\.|[^"\\])*)"', evidence_match.group(1)):
                decoded_item = _decode_jsonish_string(item)
                if decoded_item:
                    evidence_items.append(decoded_item)
                if len(evidence_items) >= 6:
                    break

        extracted.append({
            "category": _decode_jsonish_string(category_match.group(1)) if category_match else "",
            "insight": _decode_jsonish_string(insight_match.group(1)) if insight_match else "",
            "evidence": evidence_items,
        })

    return extracted


def _plain_text_notable_pattern(raw_text: str) -> Dict[str, Any]:
    """Turn a plain observation such as "Largest indexes: a, b" into a titled pattern."""
    cleaned = raw_text.strip()
    head, separator, tail = cleaned.partition(": ")
    if separator and 0 < len(head) <= 60 and tail.strip():
        return {"title": head, "insight": tail.strip()[:600], "evidence": []}
    return {"category": "Observation", "insight": cleaned[:600], "evidence": []}


def _parse_v2_notable_patterns(raw_patterns: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw_patterns, list):
        return []

    parsed_patterns: List[Dict[str, Any]] = []
    for item in raw_patterns:
        payload = item
        if isinstance(item, str):
            try:
                payload = json.loads(item)
            except Exception:
                recovered = _extract_v2_notable_patterns_from_text(item)
                if recovered:
                    parsed_patterns.extend(recovered)
                elif item.strip() and item.strip()[0] not in "[{":
                    parsed_patterns.append(_plain_text_notable_pattern(item))
                continue
        if isinstance(payload, dict) and isinstance(payload.get('patterns'), list):
            parsed_patterns.extend([pattern for pattern in payload.get('patterns', []) if isinstance(pattern, dict)])
        elif isinstance(payload, dict):
            parsed_patterns.append(payload)

    deduped_patterns: List[Dict[str, Any]] = []
    seen = set()
    for pattern in parsed_patterns:
        title = str(pattern.get('title') or pattern.get('name') or pattern.get('pattern') or pattern.get('category') or '').strip().lower()
        description = str(pattern.get('description') or pattern.get('summary') or pattern.get('insight') or '').strip().lower()
        signal = str(pattern.get('signal') or '').strip().lower()
        if not (title or description or signal):
            continue
        key = f"{title}::{description}::{signal}"
        if key in seen:
            continue
        seen.add(key)
        deduped_patterns.append(pattern)
    return deduped_patterns


def _canonicalize_v2_pattern_text(value: Any) -> str:
    cleaned = str(value or '').strip().lower()
    if not cleaned:
        return ''
    cleaned = cleaned.replace('&', ' and ')
    cleaned = re.sub(r'[_\-\s]+', ' ', cleaned)
    cleaned = re.sub(r'[^a-z0-9 ]+', '', cleaned)
    return re.sub(r'\s+', ' ', cleaned).strip()


def _normalize_v2_notable_patterns_for_ui(raw_patterns: Any, limit: int = 6) -> List[Dict[str, Any]]:
    normalized_patterns: List[Dict[str, Any]] = []
    pattern_lookup: Dict[str, int] = {}

    for pattern in _parse_v2_notable_patterns(raw_patterns):
        category = str(pattern.get('category') or '').strip()
        title = str(
            pattern.get('title')
            or pattern.get('name')
            or pattern.get('pattern')
            or category
            or pattern.get('signal')
            or ''
        ).strip()
        description = str(pattern.get('description') or pattern.get('summary') or pattern.get('insight') or '').strip()

        evidence: List[str] = []
        raw_evidence = pattern.get('evidence')
        if isinstance(raw_evidence, list):
            for item in raw_evidence:
                evidence_item = str(item or '').strip()
                if not evidence_item:
                    continue
                evidence.append(evidence_item)
                if len(evidence) >= 3:
                    break
        elif isinstance(raw_evidence, str) and raw_evidence.strip():
            evidence.append(raw_evidence.strip())

        signal = str(pattern.get('signal') or '').strip()
        if not signal and evidence:
            signal = ', '.join(evidence[:2])

        display_title = title or description or 'Pattern'
        if not (display_title or description or signal):
            continue

        dedupe_key = _canonicalize_v2_pattern_text(title or category or description or signal or display_title)
        if not dedupe_key:
            continue

        normalized_evidence: List[str] = []
        seen_evidence = set()
        for item in evidence:
            item_key = _canonicalize_v2_pattern_text(item)
            if not item_key or item_key in seen_evidence:
                continue
            seen_evidence.add(item_key)
            normalized_evidence.append(item)
            if len(normalized_evidence) >= 4:
                break

        normalized_category = category if category and _canonicalize_v2_pattern_text(category) != _canonicalize_v2_pattern_text(display_title) else ''

        existing_index = pattern_lookup.get(dedupe_key)
        if existing_index is not None:
            existing = normalized_patterns[existing_index]

            if normalized_category and not existing.get('category'):
                existing['category'] = normalized_category

            existing_description = str(existing.get('description') or '').strip()
            if description:
                existing_description_key = _canonicalize_v2_pattern_text(existing_description)
                description_key = _canonicalize_v2_pattern_text(description)
                if not existing_description or (description_key and description_key != existing_description_key and len(description) > len(existing_description)):
                    existing['description'] = description

            if title:
                current_title = str(existing.get('title') or '').strip()
                current_title_key = _canonicalize_v2_pattern_text(current_title)
                title_key = _canonicalize_v2_pattern_text(title)
                category_key = _canonicalize_v2_pattern_text(category)
                if title_key and (not current_title or (current_title_key == category_key and title_key != category_key)):
                    existing['title'] = display_title

            if not existing.get('signal') and signal:
                existing['signal'] = signal

            existing_evidence = existing.get('evidence') if isinstance(existing.get('evidence'), list) else []
            existing_evidence_keys = {_canonicalize_v2_pattern_text(item) for item in existing_evidence if _canonicalize_v2_pattern_text(item)}
            for item in normalized_evidence:
                item_key = _canonicalize_v2_pattern_text(item)
                if not item_key or item_key in existing_evidence_keys:
                    continue
                existing_evidence_keys.add(item_key)
                existing_evidence.append(item)
                if len(existing_evidence) >= 4:
                    break
            existing['evidence'] = existing_evidence
            continue

        normalized_patterns.append({
            'title': display_title,
            'category': normalized_category,
            'description': description if description.lower() != title.lower() else '',
            'signal': signal,
            'evidence': normalized_evidence,
        })
        pattern_lookup[dedupe_key] = len(normalized_patterns) - 1
        if len(normalized_patterns) >= limit:
            break

    return normalized_patterns


def _dedupe_ranked_entities(items: List[Dict[str, Any]], limit: int = 6) -> List[Dict[str, Any]]:
    ranked = sorted(items, key=lambda item: item.get('events', 0), reverse=True)
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for item in ranked:
        name = str(item.get('name', '')).strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        deduped.append(item)
        if len(deduped) >= limit:
            break
    return deduped


def _rank_v2_entities(finding_ledger: Any, entity_type: str, limit: int = 6) -> List[Dict[str, Any]]:
    if not isinstance(finding_ledger, list):
        return []

    ranked: List[Dict[str, Any]] = []
    for entry in finding_ledger:
        if not isinstance(entry, dict):
            continue
        data = entry.get('data', {}) if isinstance(entry.get('data', {}), dict) else {}
        if not data:
            continue

        name = None
        events = 0
        size_mb = None

        if entity_type == 'indexes' and 'title' in data and 'totalEventCount' in data:
            name = data.get('title')
            events = _safe_int(data.get('totalEventCount'))
            size_mb = _safe_int(data.get('currentDBSizeMB'))
        elif entity_type == 'sourcetypes':
            name = data.get('sourcetype') or (data.get('title') if str(data.get('type', '')).lower() in {'sourcetypes', 'source_types'} else None)
            events = _safe_int(data.get('totalCount') or data.get('count') or data.get('eventCount'))
        elif entity_type == 'hosts':
            name = data.get('host') or data.get('hostname')
            events = _safe_int(data.get('totalCount') or data.get('count') or data.get('eventCount'))
        elif entity_type == 'sources':
            name = data.get('source')
            events = _safe_int(data.get('totalCount') or data.get('count') or data.get('eventCount'))

        if isinstance(name, str) and name.strip():
            entity = {
                'name': name.strip(),
                'events': events,
            }
            if size_mb is not None:
                entity['size_mb'] = size_mb
            recent_time = metadata_recent_time_utc(data)
            if recent_time:
                entity['recent_time'] = recent_time
            ranked.append(entity)

    return _dedupe_ranked_entities(ranked, limit=limit)


def _format_ranked_entities(items: List[Dict[str, Any]], include_size: bool = False) -> str:
    formatted: List[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        label = str(item.get('name', '')).strip()
        if not label:
            continue
        events = _safe_int(item.get('events'))
        if include_size and item.get('size_mb') is not None:
            formatted.append(f"{label} ({events:,} events, {item.get('size_mb')}MB)")
        else:
            formatted.append(f"{label} ({events:,} events)")
    return ', '.join(formatted)


def _extract_report_priority_actions(ai_summary_payload: Dict[str, Any]) -> List[str]:
    ai_summary_text = ai_summary_payload.get('ai_summary', '') if isinstance(ai_summary_payload, dict) else ''
    return _extract_markdown_section_items(ai_summary_text, 'Priority Actions', max_items=4)


def _extract_report_quick_wins(ai_summary_payload: Dict[str, Any]) -> List[str]:
    ai_summary_text = ai_summary_payload.get('ai_summary', '') if isinstance(ai_summary_payload, dict) else ''
    return _extract_markdown_section_items(ai_summary_text, 'Quick Wins', max_items=4)


def _build_report_viability(bundle: Dict[str, Any], staleness_days: int) -> Dict[str, Any]:
    timestamp = str(bundle.get('timestamp', '')).strip()
    age_days = 999
    try:
        if timestamp:
            bundle_time = datetime.strptime(timestamp, '%Y%m%d_%H%M%S')
            age_days = max(0, int((datetime.now() - bundle_time).total_seconds() / 86400))
    except Exception:
        age_days = 999

    blueprint = bundle.get('blueprint', {}) if isinstance(bundle.get('blueprint', {}), dict) else {}
    ai_summary = bundle.get('ai_summary', {}) if isinstance(bundle.get('ai_summary', {}), dict) else {}
    insights_text = bundle.get('insights_brief_text', '') if isinstance(bundle.get('insights_brief_text', ''), str) else ''

    score = 0
    reasons: List[str] = []

    if blueprint:
        score += 40
    else:
        reasons.append('Missing intelligence blueprint')

    if insights_text or ai_summary:
        score += 20
    else:
        reasons.append('Missing summarized discovery narrative')

    if isinstance(blueprint.get('overview', {}), dict) and blueprint.get('overview'):
        score += 10
    else:
        reasons.append('Overview section is incomplete')

    if isinstance(blueprint.get('finding_ledger', []), list) and blueprint.get('finding_ledger'):
        score += 10
    else:
        reasons.append('Finding ledger is missing or empty')

    if isinstance(blueprint.get('recommendations', []), list) and blueprint.get('recommendations'):
        score += 10
    elif isinstance(ai_summary.get('risk_register', []), list) and ai_summary.get('risk_register'):
        score += 5
    else:
        reasons.append('Recommendations and risk register are thin')

    freshness_window = max(1, int(staleness_days))
    if age_days <= freshness_window:
        score += 10
    elif age_days <= freshness_window * 2:
        reasons.append(f'Discovery bundle is {age_days} days old')
    else:
        reasons.append(f'Discovery bundle is stale at {age_days} days old')

    has_core_artifacts = bool(blueprint) and bool(insights_text or ai_summary)
    fresh = age_days <= freshness_window
    usable = bool(blueprint) and score >= 45
    viable = has_core_artifacts and score >= 60 and fresh

    status = 'viable'
    if not viable and usable:
        status = 'stale' if has_core_artifacts else 'partial'
    elif not usable:
        status = 'partial'

    warning = None
    if status == 'stale':
        warning = f"⚠️ Discovery reports are {age_days} days old. Treat them as baseline context and validate live findings before acting."
    elif status == 'partial':
        warning = '⚠️ Discovery reports are incomplete. Strategic guidance is available, but it should be treated as partial context.'

    return {
        'timestamp': timestamp,
        'age_days': age_days,
        'score': score,
        'status': status,
        'fresh': fresh,
        'usable': usable,
        'viable': viable,
        'reasons': reasons,
        'warning': warning,
    }


_ENTITY_FACT_KINDS = ('index', 'sourcetype', 'source', 'host')
_ENTITY_FACT_SIGNAL_WORDS = ('stale', 'no recent', 'no events', 'error', 'fail', 'gap', 'drop', 'skew')
# Name fragments too generic to tie a request to one entity ("splunk health" should not pull in snmp4splunk:health).
_ENTITY_TOKEN_STOPWORDS = frozenset({
    'splunk', 'splunkd', 'local', 'localdomain', 'localhost', 'internal', 'audit', 'introspection', 'metrics',
    'events', 'event', 'error', 'errors', 'python', 'script', 'scripts', 'server', 'default', 'access', 'system',
    'health', 'stats', 'status', 'history', 'demo', 'guide', 'linux', 'windows', 'json', 'data', 'logs',
})


def _build_entity_facts(finding_ledger: Any, freshness: Any) -> List[Dict[str, str]]:
    """One short fact line per index/sourcetype/source/host that discovery analyzed."""
    if not isinstance(finding_ledger, list):
        return []
    freshness = freshness if isinstance(freshness, dict) else {}
    stale_indexes = {str(name) for name in freshness.get('stale_indexes') or [] if name}
    empty_indexes = {str(name) for name in freshness.get('empty_indexes') or [] if name}
    facts: List[Dict[str, str]] = []
    seen: set = set()
    for entry in finding_ledger:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get('kind') or '').strip().lower()
        if kind not in _ENTITY_FACT_KINDS:
            continue
        data = entry.get('data') if isinstance(entry.get('data'), dict) else {}
        name = str(data.get('name' if kind == 'index' else kind) or '').strip()
        if not name:
            title = str(entry.get('title') or '')
            name = title.split(':', 1)[1].strip() if ':' in title else ''
        if not name or (kind, name.lower()) in seen:
            continue
        seen.add((kind, name.lower()))

        parts: List[str] = []
        if kind == 'index':
            parts.append(f"{_safe_int(data.get('totalEventCount')):,} events in total, {_safe_int(data.get('currentDBSizeMB')):,} MB")
            if name in empty_indexes:
                parts.append('no events at all')
            elif name in stale_indexes:
                parts.append('no events in the 24h before discovery')
        else:
            parts.append(f"{_safe_int(data.get('totalCount') or data.get('count')):,} events")
            last_event = metadata_recent_time_utc(data)
            if last_event:
                parts.append(f"last event {last_event}")
        for finding in entry.get('findings') or []:
            cleaned = re.sub(r'^[^\w(]+', '', str(finding or '')).strip()
            if cleaned and any(word in cleaned.lower() for word in _ENTITY_FACT_SIGNAL_WORDS):
                parts.append(cleaned[:160])
                break
        facts.append({'kind': kind, 'name': name, 'summary': '; '.join(parts)})
    return facts


def _entity_mention_strength(name: str, text: str) -> int:
    """2 when the full name appears in ``text``, 1 when a distinctive name fragment does, else 0."""
    lowered = name.lower()
    if re.search(rf'(?<![\w]){re.escape(lowered)}(?![\w])', text):
        return 2
    for token in re.split(r'[^a-z0-9]+', lowered):
        if len(token) >= 5 and token not in _ENTITY_TOKEN_STOPWORDS and re.search(rf'(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])', text):
            return 1
    return 0


def match_entity_facts(text: str, entity_facts: Any, limit: int = 6) -> List[Dict[str, str]]:
    """Discovery facts for entities the text names, full-name matches first.

    A compound name that matched in full only lends its leading fragment to the
    fragment pass, so "homebridge:collector" still finds homebridge_for_splunk
    but does not pull in every other "*collector*" entity.
    """
    if not isinstance(text, str) or not text.strip() or not isinstance(entity_facts, list):
        return []
    lowered = text.lower()
    facts = [fact for fact in entity_facts if isinstance(fact, dict) and fact.get('name')]
    exact = [fact for fact in facts if _entity_mention_strength(str(fact['name']), lowered) == 2]
    residual = lowered
    for fact in sorted(exact, key=lambda item: -len(str(item['name']))):
        name = str(fact['name']).lower()
        tokens = [token for token in re.split(r'[^a-z0-9]+', name) if token]
        if len(tokens) < 2:
            continue
        lead = tokens[0] if len(tokens[0]) >= 5 and tokens[0] not in _ENTITY_TOKEN_STOPWORDS else ''
        residual = re.sub(rf'(?<![\w]){re.escape(name)}(?![\w])', f' {lead} ', residual)
    exact_ids = {id(fact) for fact in exact}
    partial = [fact for fact in facts if id(fact) not in exact_ids and _entity_mention_strength(str(fact['name']), residual)]

    def _kind_rank(fact: Dict[str, Any]) -> int:
        kind = fact.get('kind')
        return _ENTITY_FACT_KINDS.index(kind) if kind in _ENTITY_FACT_KINDS else len(_ENTITY_FACT_KINDS)

    ordered = sorted(exact, key=_kind_rank) + sorted(partial, key=_kind_rank)
    return ordered[:limit]


def _format_discovery_timestamp(value: Any) -> str:
    text = str(value or '').strip()
    try:
        return datetime.strptime(text, '%Y%m%d_%H%M%S').strftime('%Y-%m-%d %H:%M')
    except ValueError:
        return text


def _build_report_knowledge(bundle: Dict[str, Any], viability: Dict[str, Any]) -> Dict[str, Any]:
    blueprint = bundle.get('blueprint', {}) if isinstance(bundle.get('blueprint', {}), dict) else {}
    ai_summary_payload = bundle.get('ai_summary', {}) if isinstance(bundle.get('ai_summary', {}), dict) else {}
    overview = blueprint.get('overview', {}) if isinstance(blueprint.get('overview', {}), dict) else {}
    finding_ledger = blueprint.get('finding_ledger', []) if isinstance(blueprint.get('finding_ledger', []), list) else []
    coverage_gaps = blueprint.get('coverage_gaps', []) if isinstance(blueprint.get('coverage_gaps', []), list) else ai_summary_payload.get('coverage_gaps', [])
    risk_register = blueprint.get('risk_register', []) if isinstance(blueprint.get('risk_register', []), list) else ai_summary_payload.get('risk_register', [])
    recommendations = blueprint.get('recommendations', []) if isinstance(blueprint.get('recommendations', []), list) else []
    suggested_use_cases = blueprint.get('suggested_use_cases', []) if isinstance(blueprint.get('suggested_use_cases', []), list) else []
    trend_signals = blueprint.get('trend_signals', {}) if isinstance(blueprint.get('trend_signals', {}), dict) else {}
    notable_patterns = _parse_v2_notable_patterns(overview.get('notable_patterns', []))
    top_indexes = _rank_v2_entities(finding_ledger, 'indexes', limit=6)
    top_sourcetypes = _rank_v2_entities(finding_ledger, 'sourcetypes', limit=6)
    top_hosts = _rank_v2_entities(finding_ledger, 'hosts', limit=6)
    top_sources = _rank_v2_entities(finding_ledger, 'sources', limit=6)
    priority_actions = _extract_report_priority_actions(ai_summary_payload)
    quick_wins = _extract_report_quick_wins(ai_summary_payload)

    executive_summary = ''
    if isinstance(ai_summary_payload.get('ai_summary'), str) and ai_summary_payload.get('ai_summary', '').strip():
        executive_summary = ai_summary_payload.get('ai_summary', '').strip()[:2400]
    elif isinstance(bundle.get('insights_brief_text', ''), str):
        executive_summary = bundle.get('insights_brief_text', '').strip()[:2400]

    headline_findings: List[str] = []
    for entry in finding_ledger:
        if not isinstance(entry, dict):
            continue
        findings = entry.get('findings', []) if isinstance(entry.get('findings', []), list) else []
        title = str(entry.get('title', '')).strip()
        if title and findings:
            headline_findings.append(title)
        for finding in findings[:2]:
            if isinstance(finding, str) and finding.strip():
                headline_findings.append(finding.strip())
        if len(headline_findings) >= 8:
            break
    headline_findings = list(dict.fromkeys(headline_findings))[:6]

    top_gap_titles = [gap.get('gap') for gap in coverage_gaps[:4] if isinstance(gap, dict) and gap.get('gap')]
    top_recommendation_titles = [rec.get('title') for rec in recommendations[:4] if isinstance(rec, dict) and rec.get('title')]
    top_risk_titles = [risk.get('risk') for risk in risk_register[:4] if isinstance(risk, dict) and risk.get('risk')]

    prompt_context_compact = "\n".join([
        '🔍 DISCOVERY KNOWLEDGE SNAPSHOT:',
        f"- Report viability: {viability.get('status', 'unknown')} (score {viability.get('score', 0)}/100, {viability.get('age_days', 0)} days old)",
        f"- Readiness score: {_safe_int(blueprint.get('readiness_score') or ai_summary_payload.get('readiness_score'))}/100",
        f"- Surface area: {overview.get('total_indexes', 0)} indexes, {overview.get('total_sourcetypes', 0)} sourcetypes, {overview.get('total_hosts', 0)} hosts, {overview.get('total_sources', 0)} sources; 24h ingest {_format_data_volume(overview.get('data_volume_24h'))}",
        f"- Dominant indexes: {_format_ranked_entities(top_indexes[:4], include_size=True) or 'unknown'}",
        f"- Dominant sourcetypes: {_format_ranked_entities(top_sourcetypes[:4]) or 'unknown'}",
        f"- Highest-priority gaps: {', '.join(top_gap_titles[:4]) or 'none identified'}",
        f"- Highest-priority recommendations: {', '.join(top_recommendation_titles[:4]) or 'none identified'}",
    ]).strip()

    prompt_context_strategic = "\n".join([
        '📊 STRATEGIC REPORT CONTEXT:',
        f"- Top risks: {', '.join(top_risk_titles[:4]) or 'none identified'}",
        f"- Priority actions: {', '.join(priority_actions[:4]) or 'none extracted'}",
        f"- Quick wins: {', '.join(quick_wins[:3]) or 'none extracted'}",
        f"- Trend signals: evidence_steps={_safe_int(trend_signals.get('evidence_steps'))}, high_priority_recommendations={_safe_int(trend_signals.get('high_priority_recommendations'))}, coverage_gap_count={_safe_int(trend_signals.get('coverage_gap_count'))}",
        f"- Suggested live validation areas: {', '.join(top_recommendation_titles[:3] or top_gap_titles[:3]) or 'validate the most active indexes and sources live'}",
    ]).strip()

    greeting_context = (
        f"\n🔍 Splunk Environment: {overview.get('total_indexes', 0)} indexes, "
        f"{overview.get('total_sourcetypes', 0)} sourcetypes, {overview.get('total_hosts', 0)} hosts"
    )

    return {
        'timestamp': viability.get('timestamp') or bundle.get('timestamp', ''),
        'age_days': viability.get('age_days', 0),
        'viability': viability,
        'warning': viability.get('warning'),
        'readiness_score': _safe_int(blueprint.get('readiness_score') or ai_summary_payload.get('readiness_score')),
        'overview': overview,
        'finding_ledger': finding_ledger,
        'coverage_gaps': coverage_gaps if isinstance(coverage_gaps, list) else [],
        'risk_register': risk_register if isinstance(risk_register, list) else [],
        'recommendations': recommendations if isinstance(recommendations, list) else [],
        'suggested_use_cases': suggested_use_cases if isinstance(suggested_use_cases, list) else [],
        'trend_signals': trend_signals,
        'notable_patterns': notable_patterns,
        'top_indexes': top_indexes,
        'top_sourcetypes': top_sourcetypes,
        'top_hosts': top_hosts,
        'top_sources': top_sources,
        'priority_actions': priority_actions,
        'quick_wins': quick_wins,
        'executive_summary': executive_summary,
        'headline_findings': headline_findings,
        'prompt_context_compact': prompt_context_compact,
        'prompt_context_strategic': prompt_context_strategic,
        'greeting_context': greeting_context,
        'entity_facts': _build_entity_facts(
            finding_ledger,
            (blueprint.get('discovery_metrics') or {}).get('freshness') if isinstance(blueprint.get('discovery_metrics'), dict) else {},
        ),
        'known_entities': {
            'indexes': [item.get('name') for item in top_indexes if isinstance(item, dict) and item.get('name')],
            'sourcetypes': [item.get('name') for item in top_sourcetypes if isinstance(item, dict) and item.get('name')],
            'hosts': [item.get('name') for item in top_hosts if isinstance(item, dict) and item.get('name')],
            'sources': [item.get('name') for item in top_sources if isinstance(item, dict) and item.get('name')],
        },
    }


_REPORT_KNOWLEDGE_PREFIXES = (
    'v2_intelligence_blueprint_',
    'v2_insights_brief_',
    'v2_ai_summary_',
    'v2_operator_runbook_',
    'v2_developer_handoff_',
)
_REPORT_KNOWLEDGE_CACHE_TTL_SECONDS = 60.0
_report_knowledge_cache: Dict[str, Any] = {"key": None, "expires_at": 0.0, "value": None}


def load_latest_report_knowledge(staleness_days: int = 7) -> Optional[Dict[str, Any]]:
    """Load the latest viable report bundle and synthesize a reusable knowledge object.

    Chat calls this on every turn, so the parsed bundle is reused until a report file
    changes or the short TTL (which bounds report-age drift) expires.
    """
    output_dir = Path('output')
    if not output_dir.exists():
        return None

    report_files = []
    for prefix in _REPORT_KNOWLEDGE_PREFIXES:
        for path in output_dir.glob(f'{prefix}*'):
            if path.is_file():
                try:
                    stat = path.stat()
                except OSError:
                    continue
                report_files.append((prefix, path, stat.st_mtime_ns, stat.st_size))

    cache_key = (str(output_dir.resolve()), staleness_days, tuple(sorted((str(p), m, s) for _, p, m, s in report_files)))
    now = time.monotonic()
    if _report_knowledge_cache.get("key") == cache_key and now < _report_knowledge_cache.get("expires_at", 0.0):
        return copy.deepcopy(_report_knowledge_cache.get("value"))

    knowledge = _load_latest_report_knowledge_uncached(output_dir, staleness_days, report_files)
    _report_knowledge_cache.update({
        "key": cache_key,
        "expires_at": now + _REPORT_KNOWLEDGE_CACHE_TTL_SECONDS,
        "value": copy.deepcopy(knowledge),
    })
    return knowledge


def _load_latest_report_knowledge_uncached(output_dir: Path, staleness_days: int, report_files: List[Any]) -> Optional[Dict[str, Any]]:
    timestamps = {path.stem.replace(prefix, '', 1) for prefix, path, _, _ in report_files}

    best_usable = None
    for timestamp in sorted(timestamps, reverse=True):
        bundle = {
            'timestamp': timestamp,
            'blueprint': _read_json_if_exists(output_dir / f'v2_intelligence_blueprint_{timestamp}.json'),
            'insights_brief_text': _read_text_if_exists(output_dir / f'v2_insights_brief_{timestamp}.md', limit=5000),
            'ai_summary': _read_json_if_exists(output_dir / f'v2_ai_summary_{timestamp}.json'),
            'runbook_text': _read_text_if_exists(output_dir / f'v2_operator_runbook_{timestamp}.md', limit=3000),
            'handoff_text': _read_text_if_exists(output_dir / f'v2_developer_handoff_{timestamp}.md', limit=3000),
        }
        viability = _build_report_viability(bundle, staleness_days)
        knowledge = _build_report_knowledge(bundle, viability)
        if viability.get('viable'):
            return knowledge
        if viability.get('usable') and best_usable is None:
            best_usable = knowledge

    return best_usable


def _known_entity_matches(user_message: str, candidates: List[str], limit: int = 4) -> List[str]:
    if not isinstance(user_message, str):
        return []
    lowered = user_message.lower()
    matches: List[str] = []
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        cleaned = candidate.strip()
        if cleaned and cleaned.lower() in lowered and cleaned not in matches:
            matches.append(cleaned)
        if len(matches) >= limit:
            break
    return matches


# (domain, words in the user message, fragments of index names that usually hold that data)
_QUERY_PLAN_DOMAINS: List[Tuple[str, List[str], List[str]]] = [
    ('security', ['windows', 'security', 'auth', 'login', 'logon', 'privilege', 'lockout', 'malware', 'threat'],
     ['security', 'wineventlog', 'endpoint', 'auth', 'firewall', 'ids', 'edr', '_audit']),
    ('platform operations', ['platform', 'splunk health', 'ingestion', 'license', 'scheduler', 'search performance',
                             '_internal', '_audit', '_introspection', 'indexer', 'queue'],
     ['_internal', '_audit', '_introspection', '_metrics']),
    ('application monitoring', ['application', 'api', 'feed', 'collector', 'service', 'http', 'response time'],
     ['app', 'api', 'web', 'service', 'http']),
    ('network operations', ['network', 'ping', 'latency', 'packet loss', 'interface', 'connectivity', 'firewall', 'dns'],
     ['net', 'firewall', 'ping', 'dns', 'proxy', 'router', 'switch']),
    ('iot monitoring', ['iot', 'sensor', 'device', 'temperature', 'humidity', 'smart home', 'thermostat'],
     ['iot', 'sensor', 'device', 'home', 'esp']),
    ('compliance', ['compliance', 'audit', 'admin action', 'governance'],
     ['_audit', 'audit', 'wineventlog']),
]


def _candidate_indexes_for_domain(domain: str, report_knowledge: Dict[str, Any]) -> List[str]:
    known_indexes = report_knowledge.get('known_entities', {}).get('indexes', []) if isinstance(report_knowledge, dict) else []
    known_indexes = [name for name in known_indexes if isinstance(name, str) and name.strip()]
    fragments = next((hints for name, _words, hints in _QUERY_PLAN_DOMAINS if name == domain), [])
    candidates: List[str] = []
    for fragment in fragments:
        for index_name in known_indexes:
            if fragment in index_name.lower() and index_name not in candidates:
                candidates.append(index_name)
    if candidates:
        return candidates[:4]
    return known_indexes[:4]


def _report_anchor_for_domain(domain: str, report_knowledge: Dict[str, Any]) -> str:
    """Name the report item that matches the domain, or say that none does."""
    words = next((list(message_words) + list(hints) for name, message_words, hints in _QUERY_PLAN_DOMAINS if name == domain), [])
    sources = [
        ('recommendation', 'recommendations', 'title'),
        ('coverage gap', 'coverage_gaps', 'gap'),
        ('risk', 'risk_register', 'risk'),
    ]
    for label, key, field in sources:
        items = report_knowledge.get(key, []) if isinstance(report_knowledge.get(key, []), list) else []
        for item in items:
            title = str(item.get(field) or '').strip() if isinstance(item, dict) else ''
            if title and any(_starts_word(title.lower(), word.strip('_')) for word in words):
                return f"The discovery report lists a related {label}: {title}."
    return 'No discovery report item matches this topic; rely on live queries.'


def _starts_word(text: str, word: str) -> bool:
    """``word`` appears at the start of a word in ``text`` ("api" matches "APIs", not "rapid")."""
    return bool(word) and re.search(rf'(?<![a-z0-9]){re.escape(word)}', text) is not None


def build_query_plan_brief(user_message: str, report_knowledge: Optional[Dict[str, Any]], memory: Optional[Dict[str, Any]] = None) -> str:
    """Build a concise deterministic investigation plan from report knowledge and chat memory."""
    if not isinstance(user_message, str) or not report_knowledge:
        return ''

    message = user_message.lower()
    known_entities = report_knowledge.get('known_entities', {}) if isinstance(report_knowledge, dict) else {}
    domain = 'general'
    anchor = 'Use the report as baseline context and live queries for recency checks.'

    for domain_name, message_words, _index_hints in _QUERY_PLAN_DOMAINS:
        if any(_starts_word(message, word) for word in message_words):
            domain = domain_name
            anchor = _report_anchor_for_domain(domain_name, report_knowledge)
            break

    remembered_index = _remembered_entity(memory or {}, 'index')
    remembered_host = _remembered_entity(memory or {}, 'host')
    mission = normalize_mission((memory or {}).get('mission')) if isinstance(memory, dict) else ''
    matched_facts = match_entity_facts(f"{user_message}\n{mission}", report_knowledge.get('entity_facts'))
    fact_indexes = [fact['name'] for fact in matched_facts if fact.get('kind') == 'index']
    candidate_indexes = (
        _known_entity_matches(user_message, known_entities.get('indexes', []), limit=4)
        or fact_indexes
        or _candidate_indexes_for_domain(domain, report_knowledge)
    )
    candidate_sourcetypes = _known_entity_matches(user_message, known_entities.get('sourcetypes', []), limit=4)
    if not candidate_sourcetypes and domain == 'security':
        candidate_sourcetypes = [name for name in known_entities.get('sourcetypes', []) if isinstance(name, str) and 'wineventlog' in name.lower()][:3]

    lines = [
        'INVESTIGATION PLAN HINTS:',
        f"- Likely domain: {domain}",
        f"- Report anchor: {anchor}",
    ]

    if candidate_indexes:
        lines.append(f"- Candidate indexes: {', '.join(candidate_indexes[:4])}")
    if candidate_sourcetypes:
        lines.append(f"- Candidate sourcetypes: {', '.join(candidate_sourcetypes[:4])}")
    if matched_facts:
        when = _format_discovery_timestamp(report_knowledge.get('timestamp'))
        lines.append(
            f"- Discovery facts for names in the request (from the discovery run{' at ' + when if when else ''}; "
            "confirm recency with a live search):"
        )
        lines.extend(f"  - {fact['kind']} {fact['name']}: {fact['summary']}"[:300] for fact in matched_facts)
    if remembered_index or remembered_host:
        memory_parts = []
        if remembered_index:
            memory_parts.append(f"index={remembered_index}")
        if remembered_host:
            memory_parts.append(f"host={remembered_host}")
        lines.append(f"- Chat memory anchors: {', '.join(memory_parts)}")

    if any(token in message for token in ['summary', 'overview', 'recommend', 'risk', 'gap', 'improve', 'priority']):
        lines.append('- This is partly answerable from the discovery reports; use live queries only to validate freshness, compare drift, or drill deeper.')
    else:
        lines.append('- Start with one focused validation query, then broaden the time range or pivot by sourcetype/host if the first result is thin.')

    return '\n'.join(lines)


def extract_structured_report_request(user_message: str) -> Optional[Dict[str, str]]:
    """Parse structured summary-to-chat prompts so routing can honor the clicked context."""
    if not isinstance(user_message, str) or not user_message.strip():
        return None

    def _extract_field(field_name: str) -> str:
        match = re.search(
            rf'{field_name}\s*:\s*(.*?)(?=\n[A-Za-z][A-Za-z ]*:\s|\Z)',
            user_message,
            flags=re.IGNORECASE | re.DOTALL,
        )
        return str(match.group(1)).strip() if match else ""

    lowered = user_message.lower()
    if 'risk:' in lowered:
        title = _extract_field('risk')
        if title:
            return {
                'kind': 'risk',
                'title': title,
                'impact': _extract_field('impact'),
                'mitigation': _extract_field('mitigation'),
            }

    return None


def _match_report_item(items: List[Dict[str, Any]], key: str, focus_text: str = '') -> Optional[Dict[str, Any]]:
    """Return the first matching report item for a focused prompt, falling back to the first populated item."""
    candidates = [item for item in items if isinstance(item, dict) and item.get(key)] if isinstance(items, list) else []
    if not candidates:
        return None

    lowered_focus = str(focus_text or '').strip().lower()
    if lowered_focus:
        for item in candidates:
            candidate_value = str(item.get(key) or '').strip()
            if candidate_value and candidate_value.lower() in lowered_focus:
                return item

    return candidates[0]


def detect_report_intent(user_message: str, report_knowledge: Optional[Dict[str, Any]]) -> Optional[str]:
    """Detect strategic report-backed questions that should be answered directly from discovery knowledge."""
    if not isinstance(user_message, str) or not report_knowledge:
        return None
    viability = report_knowledge.get('viability', {}) if isinstance(report_knowledge, dict) else {}
    if not viability.get('usable'):
        return None

    message = user_message.lower()
    if detect_latest_entry_index_request(user_message) or detect_last_offline_target(user_message) or detect_edge_processor_template_request(user_message):
        return None
    if detect_basic_inventory_intent(user_message):
        return None
    structured_request = extract_structured_report_request(user_message)
    if structured_request and structured_request.get('kind') == 'risk':
        return 'top_risks'
    if re.search(r'\b(index|host|sourcetype|source)\s*[=:]', message):
        return None
    if any(token in message for token in ['how many', 'count', 'latest event', 'last seen', 'timechart', 'break down', 'show events', 'run query', 'search for']):
        return None
    # Requests to check something live (including the report follow-on prompts) need real
    # searches; answering them from the report snapshot would just repeat the report.
    if any(token in message for token in [
        'validate', 'with live', 'live splunk', 'live query', 'live data', 'right now', 'prototype',
        'measure current', 'run a search', 'run a query', 'query splunk', 'search splunk', 'over the last',
    ]):
        return None

    if any(token in message for token in ['what should i improve', 'what should we improve', 'what should i do next', 'next steps', 'priorities', 'recommend', 'recommendation', 'improve the environment']):
        return 'recommendations'
    if any(token in message for token in ['biggest risk', 'top risk', 'risks', 'weak spot', 'weak spots', 'exposure', 'blind spot']):
        return 'top_risks'
    if any(token in message for token in ['coverage gap', 'coverage gaps', 'gaps', 'missing coverage', 'what is missing']):
        return 'coverage_gaps'
    if any(token in message for token in ['use case', 'use cases', 'detections should', 'dashboards should', 'what should we build', 'monitoring opportunity']):
        return 'use_cases'
    if any(token in message for token in ['readiness', 'maturity', 'posture', 'how ready are we']):
        return 'readiness'
    if any(token in message for token in ['overall environment', 'summarize the environment', 'environment summary', 'what do we know about this environment', 'give me a summary', 'overview of the environment']):
        return 'environment_summary'
    return None


def build_report_intent_response(intent: str, report_knowledge: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Build a deterministic response from the current report knowledge bundle."""
    overview = report_knowledge.get('overview', {}) if isinstance(report_knowledge.get('overview', {}), dict) else {}
    viability = report_knowledge.get('viability', {}) if isinstance(report_knowledge.get('viability', {}), dict) else {}
    coverage_gaps = report_knowledge.get('coverage_gaps', []) if isinstance(report_knowledge.get('coverage_gaps', []), list) else []
    risk_register = report_knowledge.get('risk_register', []) if isinstance(report_knowledge.get('risk_register', []), list) else []
    recommendations = report_knowledge.get('recommendations', []) if isinstance(report_knowledge.get('recommendations', []), list) else []
    suggested_use_cases = report_knowledge.get('suggested_use_cases', []) if isinstance(report_knowledge.get('suggested_use_cases', []), list) else []
    top_indexes = report_knowledge.get('top_indexes', []) if isinstance(report_knowledge.get('top_indexes', []), list) else []
    top_sourcetypes = report_knowledge.get('top_sourcetypes', []) if isinstance(report_knowledge.get('top_sourcetypes', []), list) else []

    opening = (
        f"Latest discovery bundle status: {viability.get('status', 'unknown')} "
        f"(score {viability.get('score', 0)}/100, {viability.get('age_days', 0)} days old)."
    )
    if viability.get('warning'):
        opening = f"{opening}\n\n{viability.get('warning')}"

    insights: List[str] = []
    lines = [opening]

    if intent == 'environment_summary':
        insights = [item for item in (report_knowledge.get('headline_findings', []) or [])[:5] if isinstance(item, str)]
        lines.extend([
            '',
            f"Environment snapshot: {overview.get('total_indexes', 0)} indexes, {overview.get('total_sourcetypes', 0)} sourcetypes, {overview.get('total_hosts', 0)} hosts, and {overview.get('total_sources', 0)} sources; 24h ingest volume: {_format_data_volume(overview.get('data_volume_24h'))}.",
            f"Readiness score: {_safe_int(report_knowledge.get('readiness_score'))} / 100.",
            f"Dominant indexes: {_format_ranked_entities(top_indexes[:4], include_size=True) or 'unknown' }.",
            f"Dominant sourcetypes: {_format_ranked_entities(top_sourcetypes[:4]) or 'unknown' }.",
            f"Highest-value gaps: {', '.join([gap.get('gap') for gap in coverage_gaps[:4] if isinstance(gap, dict) and gap.get('gap')]) or 'none identified' }.",
            f"Priority actions: {', '.join(report_knowledge.get('priority_actions', [])[:3]) or ', '.join([rec.get('title') for rec in recommendations[:3] if isinstance(rec, dict) and rec.get('title')]) or 'no explicit priority actions extracted' }.",
        ])
    elif intent == 'recommendations':
        for rec in recommendations[:5]:
            if not isinstance(rec, dict):
                continue
            title = rec.get('title')
            if not title:
                continue
            insights.append(str(title))
            lines.append(f"- {title} [{str(rec.get('priority', 'medium')).upper()}]: {str(rec.get('description', '')).strip()}")
        if report_knowledge.get('priority_actions'):
            lines.extend(['', 'Fastest priority actions:'])
            lines.extend([f"- {item}" for item in report_knowledge.get('priority_actions', [])[:3]])
    elif intent == 'top_risks':
        for risk in risk_register[:6]:
            if not isinstance(risk, dict):
                continue
            title = risk.get('risk')
            if not title:
                continue
            insights.append(str(title))
            severity = str(risk.get('severity', 'medium')).upper()
            impact = str(risk.get('impact', '')).strip()
            lines.append(f"- {title} [{severity}]: {impact}")
    elif intent == 'coverage_gaps':
        for gap in coverage_gaps[:6]:
            if not isinstance(gap, dict):
                continue
            title = gap.get('gap')
            if not title:
                continue
            insights.append(str(title))
            priority = str(gap.get('priority', 'medium')).upper()
            lines.append(f"- {title} [{priority}]: {str(gap.get('why_it_matters', '')).strip()}")
    elif intent == 'use_cases':
        for use_case in suggested_use_cases[:5]:
            if not isinstance(use_case, dict):
                continue
            title = use_case.get('title')
            if not title:
                continue
            insights.append(str(title))
            lines.append(f"- {title}: {str(use_case.get('scenario') or use_case.get('description') or '').strip()} Business value: {str(use_case.get('business_value', '')).strip()}")
    else:
        blocker_titles = [gap.get('gap') for gap in coverage_gaps[:3] if isinstance(gap, dict) and gap.get('gap')]
        readiness_score = _safe_int(report_knowledge.get('overview', {}).get('readiness_score') or report_knowledge.get('readiness_score') or report_knowledge.get('viability', {}).get('score'))
        insights = blocker_titles
        lines.extend([
            '',
            f"Readiness score: {readiness_score}/100.",
            f"Top blockers: {', '.join(blocker_titles) or 'no major blockers identified'}.",
            f"The main drag on readiness is that the environment is data-rich but still missing higher-order detections and operational monitoring in areas like {', '.join(blocker_titles[:3]) or 'security and platform health'}.",
        ])

    lines.extend([
        '',
        'Use MCP queries to validate current conditions, measure drift since the report snapshot, or drill into one risk area live.',
    ])
    return '\n'.join([line for line in lines if isinstance(line, str)]).strip(), insights[:8]


def build_focused_report_response(
    intent: str,
    report_knowledge: Dict[str, Any],
    focus_request: Optional[Dict[str, str]],
) -> Optional[Tuple[str, List[str]]]:
    """Build a targeted report-backed response for structured summary-to-chat prompts."""
    if intent != 'top_risks' or not isinstance(focus_request, dict) or focus_request.get('kind') != 'risk':
        return None

    risk_register = report_knowledge.get('risk_register', []) if isinstance(report_knowledge.get('risk_register', []), list) else []
    recommendations = report_knowledge.get('recommendations', []) if isinstance(report_knowledge.get('recommendations', []), list) else []
    coverage_gaps = report_knowledge.get('coverage_gaps', []) if isinstance(report_knowledge.get('coverage_gaps', []), list) else []
    title = str(focus_request.get('title') or '').strip()
    matched_risk = _match_report_item(risk_register, 'risk', title)
    matched_recommendation = _match_report_item(recommendations, 'title', title)
    matched_gap = _match_report_item(coverage_gaps, 'gap', title)

    if not title:
        return None

    severity = str((matched_risk or {}).get('severity') or 'medium').strip().upper()
    domain = str((matched_risk or {}).get('domain') or 'general').strip()
    impact = str((matched_risk or {}).get('impact') or focus_request.get('impact') or 'No explicit impact statement was captured.').strip()
    mitigation = str((matched_risk or {}).get('mitigation') or focus_request.get('mitigation') or 'Use live validation to confirm the fastest remediation path.').strip()

    lines = [
        f"Focused risk investigation: {title}",
        f"Severity: {severity} | Domain: {domain}",
        f"Why this matters: {impact}",
        f"Mitigation path: {mitigation}",
    ]

    if isinstance(matched_recommendation, dict) and matched_recommendation.get('description'):
        lines.append(f"Related recommendation: {str(matched_recommendation.get('title')).strip()} - {str(matched_recommendation.get('description')).strip()}")
    if isinstance(matched_gap, dict) and matched_gap.get('why_it_matters'):
        lines.append(f"Related coverage gap: {str(matched_gap.get('gap')).strip()} - {str(matched_gap.get('why_it_matters')).strip()}")

    lines.extend([
        '',
        'Use MCP queries to validate the current severity, check whether the risk is already visible in live telemetry, and confirm whether mitigation work should start with platform health, data quality, or coverage expansion.',
    ])

    insights = [title]
    if isinstance(matched_recommendation, dict) and matched_recommendation.get('title'):
        insights.append(str(matched_recommendation.get('title')).strip())

    return '\n'.join([line for line in lines if isinstance(line, str) and line.strip()]).strip(), insights[:8]


def build_report_follow_on_actions(
    intent: str,
    report_knowledge: Dict[str, Any],
    focus_text: str = '',
    assistant_response: str = '',
) -> List[Dict[str, Any]]:
    """Return live validation prompts that naturally follow a strategic report-backed answer."""
    actions: List[Dict[str, Any]] = _extract_response_follow_on_actions(assistant_response)
    recommendations = report_knowledge.get('recommendations', []) if isinstance(report_knowledge.get('recommendations', []), list) else []
    coverage_gaps = report_knowledge.get('coverage_gaps', []) if isinstance(report_knowledge.get('coverage_gaps', []), list) else []
    risk_register = report_knowledge.get('risk_register', []) if isinstance(report_knowledge.get('risk_register', []), list) else []
    suggested_use_cases = report_knowledge.get('suggested_use_cases', []) if isinstance(report_knowledge.get('suggested_use_cases', []), list) else []
    recommendation_titles = [
        str(rec.get('title')).lower()
        for rec in recommendations[:6]
        if isinstance(rec, dict) and rec.get('title')
    ]
    top_recommendation = _match_report_item(recommendations, 'title', focus_text)
    top_gap = _match_report_item(coverage_gaps, 'gap', focus_text)
    top_risk = _match_report_item(risk_register, 'risk', focus_text)
    top_use_case = _match_report_item(suggested_use_cases, 'title', focus_text)

    if intent == 'recommendations' and isinstance(top_recommendation, dict):
        actions.append(_make_follow_on_action(
            'Validate the top recommendation',
            (
                f"Validate this discovery recommendation with live Splunk data and summarize drift from the report snapshot: "
                f"{str(top_recommendation.get('title')).strip()}. "
                f"Context: {str(top_recommendation.get('description') or 'No additional recommendation context was captured.').strip()}"
            ),
            'validate_top_recommendation',
        ))

    if intent == 'top_risks' and isinstance(top_risk, dict):
        actions.append(_make_follow_on_action(
            'Investigate the top risk live',
            (
                f"Investigate this discovery risk in Splunk and show whether it is visible right now: "
                f"{str(top_risk.get('risk')).strip()}. "
                f"Impact: {str(top_risk.get('impact') or 'No impact statement was captured.').strip()} "
                f"Mitigation: {str(top_risk.get('mitigation') or 'Identify the most direct validation path.').strip()}"
            ),
            'investigate_top_risk',
        ))

    if intent == 'coverage_gaps' and isinstance(top_gap, dict):
        actions.append(_make_follow_on_action(
            'Validate the highest-priority gap',
            (
                f"Validate this coverage gap with live Splunk data and state whether the environment is ready to close it: "
                f"{str(top_gap.get('gap')).strip()}. "
                f"Why it matters: {str(top_gap.get('why_it_matters') or 'No impact summary was captured.').strip()}"
            ),
            'validate_top_gap',
        ))

    if intent == 'use_cases' and isinstance(top_use_case, dict):
        actions.append(_make_follow_on_action(
            'Prototype the strongest use case',
            (
                f"Prototype the strongest report-backed use case with the current data and explain the validation path: "
                f"{str(top_use_case.get('title')).strip()}. "
                f"Scenario: {str(top_use_case.get('scenario') or top_use_case.get('description') or 'No scenario details were captured.').strip()}"
            ),
            'prototype_top_use_case',
        ))

    if any('windows security' in title for title in recommendation_titles):
        actions.append(_make_follow_on_action(
            'Validate Windows security live',
            'Validate Windows security telemetry over the last 24 hours and show failed logons, privilege changes, and account lockouts.',
            'validate_windows_security',
        ))
    if any('platform health' in title for title in recommendation_titles):
        actions.append(_make_follow_on_action(
            'Check Splunk platform health',
            'Check platform health in _internal, _audit, and _introspection over the last 24 hours and summarize ingestion issues, search failures, and license signals.',
            'validate_platform_health',
        ))
    if any(token in title for title in recommendation_titles for token in ('api ', 'feed', 'collector', 'application')):
        actions.append(_make_follow_on_action(
            'Review service feed health',
            'Check API and collector data over the last 24 hours for outages, elevated errors, and latency spikes.',
            'validate_service_health',
        ))
    if any('network' in title for title in recommendation_titles):
        actions.append(_make_follow_on_action(
            'Inspect network connectivity',
            'Show connectivity, latency, and packet-loss trends from ping or network telemetry over the last 24 hours.',
            'validate_network_health',
        ))

    if intent == 'use_cases':
        actions.append(_make_follow_on_action(
            'Show the strongest live use-case candidate',
            'Show the strongest live candidate for a new detection or dashboard based on the most active data sources in this environment.',
            'live_use_case_candidate',
        ))

    if intent == 'readiness' and isinstance(top_gap, dict):
        actions.append(_make_follow_on_action(
            'Measure readiness against the top blocker',
            (
                f"Measure current readiness against this blocker and explain the next implementation step: "
                f"{str(top_gap.get('gap')).strip()}."
            ),
            'measure_readiness_blocker',
        ))

    if not actions:
        actions.append(_make_follow_on_action(
            'Validate the top gap live',
            'Validate the highest-priority discovery gap with a live query and summarize whether the current data supports immediate implementation.',
            'validate_top_gap',
        ))

    return _dedupe_follow_on_actions(actions, limit=3)


def _is_numeric_like(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if isinstance(value, str):
        cleaned = value.strip().replace(',', '')
        if not cleaned:
            return False
        try:
            float(cleaned)
            return True
        except Exception:
            return False
    return False


# Splunk adds these to raw events to describe buckets and parsing; they are never useful pivots.
_SPLUNK_INTERNAL_RESULT_FIELDS = {
    'punct', 'linecount', 'splunk_server', 'splunk_server_group', 'timestartpos', 'timeendpos',
}


def _is_internal_result_field(field: Any) -> bool:
    lowered = str(field or '').strip().lower()
    return (
        not lowered
        or lowered.startswith('_')
        or lowered.startswith('date_')
        or lowered in _SPLUNK_INTERNAL_RESULT_FIELDS
    )


_COUNT_METRIC_NAMES = frozenset({'count', 'event_count', 'eventcount', 'events', 'total', 'total_count', 'totalcount'})


def _count_metric_field(numeric_fields: List[str]) -> Optional[str]:
    for field in numeric_fields:
        lowered = field.lower()
        if lowered in _COUNT_METRIC_NAMES or lowered.startswith(('count', 'sum(', 'dc(')) or lowered.endswith('_count'):
            return field
    return None


def _metric_value(value: Any) -> float:
    try:
        return float(str(value).replace(',', '').strip())
    except (TypeError, ValueError):
        return 0.0


def _format_metric(value: float) -> str:
    return f"{int(value):,}" if float(value).is_integer() else f"{value:,.2f}"


def analyze_result_rows(rows: Any) -> Dict[str, Any]:
    """Extract compact structural clues from query results for planning and summarization."""
    if not isinstance(rows, list) or not rows:
        return {}

    dict_rows = [row for row in rows[:60] if isinstance(row, dict)]
    if not dict_rows:
        return {}

    sample_fields = [
        field for field in dict_rows[0].keys()
        if field == '_time' or not _is_internal_result_field(field)
    ][:12]
    time_fields = [
        field for field in sample_fields
        if field.lower() in {'_time', 'time', 'firsttimeiso', 'lasttimeiso', 'recenttimeiso'}
        or field.lower().endswith('time')
        or field.lower().endswith('timeiso')
    ]

    numeric_fields: List[str] = []
    for field in sample_fields:
        sample_values = [row.get(field) for row in dict_rows[:8] if row.get(field) not in (None, '')]
        if sample_values and all(_is_numeric_like(value) for value in sample_values):
            numeric_fields.append(field)

    # Aggregated results have one row per value, so rank by their count column rather
    # than by how often a value repeats (which would just echo the row order).
    metric_field = _count_metric_field(numeric_fields)
    ranking_rows = [row for row in rows[:5000] if isinstance(row, dict)] if metric_field else dict_rows[:50]
    top_dimensions: List[Dict[str, Any]] = []
    for field in sample_fields:
        lowered = field.lower()
        if field in numeric_fields or lowered in time_fields or lowered.endswith('time') or lowered.endswith('timeiso'):
            continue
        counts: Dict[str, float] = {}
        for row in ranking_rows:
            value = row.get(field)
            if value in (None, ''):
                continue
            text = str(value).strip()
            if not text or len(text) > 80:
                continue
            weight = _metric_value(row.get(metric_field)) if metric_field else 1.0
            counts[text] = counts.get(text, 0.0) + weight
        if len(counts) < 2 or max(counts.values()) <= 0:
            continue
        ranked_counts = sorted(counts.items(), key=lambda item: item[1], reverse=True)
        top_dimensions.append({
            'field': field,
            'distinct_count': len(counts),
            'ranked_by': metric_field or 'rows',
            'values': [f"{name} ({_format_metric(count)})" for name, count in ranked_counts[:5 if metric_field else 3]],
        })

    top_dimensions = sorted(top_dimensions, key=lambda item: item.get('distinct_count', 0), reverse=True)[:3]

    time_bounds = {}
    for field in time_fields[:2]:
        values = [str(row.get(field)).strip() for row in dict_rows if row.get(field) not in (None, '')]
        if values:
            time_bounds = {
                'field': field,
                'first': values[0],
                'last': values[-1],
            }
            break

    query_shape = 'tabular'
    numeric_names = {field.lower() for field in numeric_fields}
    if time_fields and numeric_names.intersection({'count', 'event_count', 'events', 'totalcount'}):
        query_shape = 'time_series'
    elif top_dimensions and numeric_fields:
        query_shape = 'aggregation'
    elif len(rows) <= 5 and len(sample_fields) >= 4:
        query_shape = 'event_sample'

    next_pivots: List[str] = []
    if top_dimensions:
        first_dimension = top_dimensions[0]
        top_value = str(first_dimension['values'][0]).rsplit(' (', 1)[0]
        next_pivots.append(f"Filter on {first_dimension['field']}={top_value}")
    if query_shape == 'time_series':
        next_pivots.append('Compare adjacent time buckets for spikes or drops')
    if len(rows) > 100:
        next_pivots.append('Tighten the query or aggregate by one dimension')

    return {
        'query_shape': query_shape,
        'sample_fields': sample_fields,
        'time_bounds': time_bounds,
        'top_dimensions': top_dimensions,
        'numeric_fields': numeric_fields[:6],
        'next_pivots': next_pivots[:3],
    }


def format_result_summary_for_llm(summary: Dict[str, Any]) -> str:
    """Convert structured result metadata into a compact analysis brief for follow-up reasoning."""
    if not isinstance(summary, dict):
        return ''

    lines: List[str] = []
    for finding in summary.get('findings', [])[:5]:
        if isinstance(finding, str) and finding.strip():
            lines.append(f"- {finding}")

    query_shape = str(summary.get('query_shape', '')).strip()
    if query_shape:
        lines.append(f"- Result shape: {query_shape}")

    time_bounds = summary.get('time_bounds', {}) if isinstance(summary.get('time_bounds', {}), dict) else {}
    if time_bounds.get('field') and (time_bounds.get('first') or time_bounds.get('last')):
        lines.append(
            f"- Time bounds from {time_bounds.get('field')}: {time_bounds.get('first', 'unknown')} -> {time_bounds.get('last', 'unknown')}"
        )

    for dimension in summary.get('top_dimensions', [])[:2]:
        if not isinstance(dimension, dict):
            continue
        field = str(dimension.get('field', '')).strip()
        values = dimension.get('values', []) if isinstance(dimension.get('values', []), list) else []
        ranked_by = str(dimension.get('ranked_by') or '').strip()
        if field and values and ranked_by and ranked_by != 'rows':
            lines.append(f"- Top {field} values by {ranked_by}: {', '.join(values[:5])}")
        elif field and values:
            lines.append(f"- Top {field} values: {', '.join(values[:3])}")

    next_pivots = summary.get('next_pivots', []) if isinstance(summary.get('next_pivots', []), list) else []
    if next_pivots:
        lines.append(f"- Suggested pivots: {', '.join(next_pivots[:3])}")

    return '\n'.join(lines)


_INDEX_LATEST_TIME_FIELDS = ("maxTime", "maxTimeIso", "lastTimeIso", "latest_time", "latest", "last_event")


def _index_names_without_latest_time(rows: List[Any]) -> List[str]:
    """Names of index-metadata rows (totalEventCount) that carry no latest-event time."""
    names: List[str] = []
    for row in rows:
        if not isinstance(row, dict) or "totalEventCount" not in row:
            continue
        if any(row.get(field) not in (None, "") for field in _INDEX_LATEST_TIME_FIELDS):
            continue
        name = str(row.get("title") or row.get("name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def summarize_tool_outcome(tool_name: str, outcome: Dict[str, Any]) -> Dict[str, Any]:
    """Summary stored on each tool call; chat memory, follow-on actions and the UI read it."""
    status = outcome.get("status")
    if status == "error":
        message = str(outcome.get("error") or "Unknown error")
        return {
            "type": "error",
            "status": "error",
            "message": message,
            "row_count": 0,
            "findings": [f"Error: {message[:200]}"],
        }

    rows = list(outcome.get("rows") or [])
    summary: Dict[str, Any] = {"type": tool_name, "status": status, "row_count": len(rows), "findings": []}
    if rows:
        total_rows = outcome.get("total_rows")
        if outcome.get("truncated") and isinstance(total_rows, int) and total_rows > len(rows):
            summary["findings"].append(f"{len(rows)} results returned (truncated; {total_rows} in total)")
        else:
            summary["findings"].append(f"{len(rows)} results returned")
        totals_only = _index_names_without_latest_time(rows)
        if totals_only:
            summary["findings"].append(
                f"Index metadata for {', '.join(totals_only[:3])} holds event totals and sizes only, not the time of the "
                f"latest event, so it does not show whether data is recent. Check recency with "
                f"| tstats latest(_time) as latest where index={totals_only[0]}"
            )
        if outcome.get("zero_counts"):
            summary["zero_counts"] = True
            summary["findings"].append("Every count is 0")
        summary["actual_results"] = rows[:10]
        analysis = analyze_result_rows(rows)
        if analysis:
            summary.update(analysis)
            top_dimensions = analysis.get("top_dimensions") or []
            top = top_dimensions[0] if top_dimensions else None
            if isinstance(top, dict) and top.get("field") and top.get("values"):
                ranked_by = top.get("ranked_by")
                label = f"Top {top['field']} by {ranked_by}" if ranked_by and ranked_by != "rows" else f"Top {top['field']}"
                summary["findings"].append(f"{label}: {', '.join(top['values'][:3])}")
            bounds = analysis.get("time_bounds") or {}
            if isinstance(bounds, dict) and bounds.get("field"):
                summary["findings"].append(
                    f"Time bounds from {bounds['field']}: {bounds.get('first', 'unknown')} -> {bounds.get('last', 'unknown')}"
                )
    elif outcome.get("text"):
        summary["findings"].append("Text result returned")
        summary["text"] = str(outcome["text"])[:2000]
    else:
        summary["findings"].append("0 results returned")
    return summary


def _row_value(row: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """First present, non-empty value; unlike ``a or b`` it keeps a real 0."""
    for key in keys:
        value = row.get(key)
        if value is not None and value != "":
            return value
    return default


def extract_event_count(outcome: Dict[str, Any]) -> Optional[int]:
    """Count from a one-row count search, or None when the search failed."""
    if outcome.get("status") == "error":
        return None
    rows = outcome.get("rows") or []
    if rows and isinstance(rows[0], dict):
        for key in ("event_count", "count", "COUNT"):
            if key in rows[0]:
                return _safe_int(rows[0].get(key))
    return 0


def format_event_count(count: Optional[int]) -> str:
    return "unavailable (the search failed)" if count is None else f"{count:,}"


def format_tool_call_tag(tool_name: str, args: Dict[str, Any]) -> str:
    return "<TOOL_CALL>" + json.dumps({"tool": tool_name, "args": args}, default=str) + "</TOOL_CALL>"


def build_fatal_mcp_error_message(status_code: Any, detail: str) -> str:
    """User-facing explanation for MCP failures that retrying cannot fix."""
    known = {
        401: (
            "Authentication failed",
            [
                "The MCP token in Settings is correct and has not expired.",
                "The token belongs to a Splunk user that is allowed to use the MCP server.",
            ],
        ),
        403: (
            "Access forbidden",
            [
                "The Splunk user behind the MCP token has the roles this tool or index needs.",
                "Network or proxy rules allow the request.",
            ],
        ),
        404: (
            "MCP endpoint not found",
            [
                "The MCP URL in Settings is correct (it usually ends in /services/mcp).",
                "The Splunk MCP Server app is installed and enabled.",
            ],
        ),
    }
    title, checks = known.get(
        status_code,
        (
            "Could not reach the Splunk MCP server",
            [
                "The MCP server is running and reachable from this machine.",
                "Firewall, proxy, and TLS settings allow the connection.",
            ],
        ),
    )
    status_text = f"status {status_code}" if status_code else "an error"
    lines = [
        f"**{title}**",
        "",
        f"The Splunk MCP server returned {status_text}:",
        "",
        "```",
        (str(detail or "").strip() or "No details were returned.")[:600],
        "```",
        "",
        "Please check:",
    ]
    lines.extend(f"{number}. {check}" for number, check in enumerate(checks, 1))
    lines.extend(["", "I stopped here so the same failing request is not retried."])
    return "\n".join(lines)


def finalize_route_tool_calls(
    response_text: str,
    tool_calls: Optional[List[Dict[str, Any]]],
    annotate_reply: bool = True,
) -> str:
    """Mark failed calls of a deterministic route and make its reply say so.

    Deterministic routes build their reply from result rows, so without this
    a failed search reads as "no data". Pass ``annotate_reply=False`` when the
    route already explains the failure itself.
    """
    outcomes: List[Dict[str, Any]] = []
    for call in tool_calls or []:
        if not isinstance(call, dict) or "result" not in call:
            continue
        outcome = classify_tool_result(call.get("result"))
        outcomes.append(outcome)
        if outcome["status"] == "error":
            call["summary"] = summarize_tool_outcome(str(call.get("tool") or ""), outcome)
        elif isinstance(call.get("summary"), dict):
            call["summary"].setdefault("status", outcome["status"])

    failures = [outcome for outcome in outcomes if outcome["status"] == "error"]
    if not failures or not annotate_reply:
        return response_text
    first_error = str(failures[0].get("error") or "unknown error").strip()
    if len(failures) == len(outcomes):
        if failures[0].get("fatal"):
            return build_fatal_mcp_error_message(failures[0].get("status_code"), first_error)
        return (
            "I couldn't get this from Splunk because the request failed:\n\n"
            f"> {first_error[:600]}\n\n"
            "Check that the index and fields exist and that the MCP user can search them, "
            "or rephrase the request and I'll try a different search."
        )
    return f"{response_text}\n\n_Note: {len(failures)} of {len(outcomes)} Splunk requests failed ({first_error[:240]})._"


_SUGGESTED_SPL_FENCE = re.compile(r"```(?:spl|splunk)[ \t]*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_GENERIC_CODE_FENCE = re.compile(r"```[a-zA-Z]*[ \t]*\n(.*?)```", re.DOTALL)


def extract_suggested_spl_from_answer(text: Any) -> Optional[str]:
    """Return the first SPL code block in a direct answer so the UI can offer to run it."""
    if not isinstance(text, str) or "```" not in text:
        return None
    match = _SUGGESTED_SPL_FENCE.search(text)
    candidate = match.group(1).strip() if match else ""
    if not candidate:
        generic = _GENERIC_CODE_FENCE.search(text)
        if generic and _looks_like_spl_query_start(generic.group(1)):
            candidate = generic.group(1).strip()
    return candidate or None

async def process_chat_with_streaming(request: dict, status_queue: asyncio.Queue, runtime_config: Any = None, goal_owner: Optional[str] = None):
    """Process chat request and push status updates to queue."""
    try:
        # Define callback that pushes to queue
        async def status_callback(action: str, iteration: int, time: float):
            await status_queue.put({
                'type': 'status',
                'action': action,
                'iteration': iteration,
                'time': round(time, 1)
            })
        
        # Call chat logic with streaming callback
        result = await chat_with_splunk_logic(request, status_callback, runtime_config=runtime_config, goal_owner=goal_owner)
        record_chat_goal_turn(goal_owner, request, result)
        await status_queue.put({'type': 'done', 'data': result})
    except Exception as e:
        await status_queue.put({'type': 'error', 'error': str(e)})


async def chat_with_splunk_logic(request: dict, status_callback=None, runtime_config: Any = None, goal_owner: Optional[str] = None):
    """Core chat logic that can optionally stream status updates.
    
    Args:
        request: The chat request dict
        status_callback: Optional async function to call with status updates
                        Signature: async def callback(action: str, iteration: int, time: float)
        goal_owner: Whose goal library a goal_id in the request belongs to (see chat_goals.owner_key)
    """
    try:
        print(f"🔵 [CHAT] Request received: {request.get('message', '')[:50]}")
        user_message = request.get('message', '')
        history = request.get('history', [])
        chat_session_id = sanitize_chat_session_id(request.get('chat_session_id', 'default'))
        
        if not user_message.strip():
            return {"error": "Message cannot be empty"}
        
        # Sanitize user message to prevent prompt injection
        # Remove control characters but preserve normal punctuation
        safe_message = ''.join(char for char in user_message if char.isprintable() or char in '\n\r\t')
        
        # Limit message length
        if len(safe_message) > 10000:
            return {"error": "Message too long (max 10000 characters)"}
        
        # Validate history format
        if not isinstance(history, list):
            return {"error": "Invalid history format"}
        
        # Load configuration
        config = runtime_config or config_manager.get()
        sync_chat_settings_for_request(config)
        request_started_at = time.time()

        async def push_status(timeline: List[Dict[str, Any]], action: str, iteration: int = 0):
            elapsed = time.time() - request_started_at
            event = {"iteration": iteration, "action": action, "time": elapsed}
            timeline.append(event)
            if status_callback:
                await status_callback(action, iteration, elapsed)

        # Load and update persistent chat memory for this session
        update_chat_memory(chat_session_id, user_message)
        chat_memory = load_chat_memory(chat_session_id)
        active_goal = load_active_chat_goal(goal_owner, request.get("goal_id"))
        goal_progress = progress_brief(active_goal) if active_goal else None
        if active_goal or "mission" in request or "goal_id" in request:
            requested_mission = normalize_mission(active_goal.get("goal") if active_goal else request.get("mission"))
            requested_open_items = list((goal_progress or {}).get("open") or [])
            if requested_mission != str(chat_memory.get("mission") or "") or requested_open_items != list(chat_memory.get("goal_open_items") or []):
                chat_memory["mission"] = requested_mission
                chat_memory["goal_open_items"] = requested_open_items
                save_chat_memory(chat_session_id, chat_memory)
        mission = normalize_mission(chat_memory.get("mission"))
        memory_context = build_chat_memory_context(chat_memory)

        query_lower = user_message.lower()
        small_talk = is_small_talk(user_message)
        needs_insights = any(keyword in query_lower for keyword in [
            'summary', 'overview', 'recommend', 'best practice', 'optimization',
            'use case', 'compliance', 'security', 'improve', 'assess', 'risk', 'gap', 'priority'
        ])

        report_knowledge = load_latest_report_knowledge(chat_session_settings["discovery_freshness_days"])
        discovery_context = ""
        discovery_age_warning = None

        if report_knowledge:
            discovery_age_warning = report_knowledge.get('warning')
            if small_talk:
                discovery_context = report_knowledge.get('greeting_context', '')
            else:
                discovery_context = report_knowledge.get('prompt_context_compact', '')
                if needs_insights and report_knowledge.get('prompt_context_strategic'):
                    discovery_context = "\n\n".join([
                        section for section in [
                            discovery_context,
                            report_knowledge.get('prompt_context_strategic', ''),
                        ] if isinstance(section, str) and section.strip()
                    ])
        else:
            discovery_age_warning = "⚠️ No discovery data found. Run a discovery first to get environment context."

        report_intent = detect_report_intent(user_message, report_knowledge) if bool(chat_session_settings.get("enable_splunk_augmentation", True)) else None

        query_plan_context = build_query_plan_brief(user_message, report_knowledge, chat_memory)

        if report_intent:
            report_status_timeline: List[Dict[str, Any]] = []
            report_capability_usage: List[Dict[str, Any]] = []
            structured_report_request = extract_structured_report_request(user_message)
            await push_status(report_status_timeline, "📚 Synthesizing discovery knowledge", 0)
            if bool(chat_session_settings.get("enable_rag_context", False)):
                rag_max_chunks = _safe_int(chat_session_settings.get("rag_max_chunks", 3))
                _, report_capability_usage = get_optional_rag_context(user_message, max_chunks=rag_max_chunks)
            focused_report_response = build_focused_report_response(report_intent, report_knowledge, structured_report_request)
            if focused_report_response:
                response_text, report_insights = focused_report_response
            else:
                response_text, report_insights = build_report_intent_response(report_intent, report_knowledge)
            report_context_brief = build_capability_usage_brief(report_capability_usage)
            if report_context_brief:
                response_text = f"{response_text}\n\n{report_context_brief}"
            response_text = apply_reusable_query_reference_to_response(response_text, report_capability_usage)
            follow_on_actions = build_report_follow_on_actions(
                report_intent,
                report_knowledge,
                focus_text=user_message,
                assistant_response=response_text,
            )
            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                assistant_response=response_text,
                report_intent=report_intent,
                record_user_turn=False,
            )
            await push_status(report_status_timeline, "✅ Returning report-backed guidance", 0)
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": [],
                "spl_query": None,
                "iterations": 0,
                "execution_time": f"{time.time() - request_started_at:.2f}s",
                "insights": report_insights,
                "status_timeline": report_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                "capability_usage": report_capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions,
            }

        available_mcp_tools = await discover_mcp_tools(config)
        if not available_mcp_tools:
            available_mcp_tools = {
                "splunk_run_query",
                "splunk_get_info",
                "splunk_get_indexes",
                "splunk_get_index_info",
                "splunk_get_metadata",
                "splunk_get_user_info",
                "splunk_get_knowledge_objects"
            }

        primary_tool_order = [
            "splunk_run_query",
            "splunk_get_info",
            "splunk_get_indexes",
            "splunk_get_index_info",
            "splunk_get_metadata",
            "splunk_get_user_info",
            "splunk_get_knowledge_objects",
            "saia_generate_spl",
            "saia_optimize_spl",
            "saia_explain_spl",
            "saia_ask_splunk_question"
        ]
        try:
            tool_metadata = get_cached_mcp_tool_metadata(config)
        except Exception:
            tool_metadata = {"descriptions": {}, "schemas": {}}
        available_tools_text = build_tool_catalog_text(
            available_mcp_tools,
            descriptions=tool_metadata.get("descriptions"),
            fallback_descriptions=MCP_TOOL_DESCRIPTIONS,
            schemas=tool_metadata.get("schemas"),
            primary_order=primary_tool_order,
        )

        query_tool_name = resolve_tool_name("splunk_run_query", available_mcp_tools)

        # Deterministic path for "latest entry in <index>" requests to avoid LLM misclassification
        latest_index_name = detect_latest_entry_index_request(user_message)
        if latest_index_name:
            latest_status_timeline: List[Dict[str, Any]] = []
            latest_tool_calls: List[Dict[str, Any]] = []
            normalized_index_name = latest_index_name.strip()

            # Step 1: validate index presence from live tool results
            indexes_tool_name = resolve_tool_name("splunk_get_indexes", available_mcp_tools)
            indexes_call = {
                "method": "tools/call",
                "params": {
                    "name": indexes_tool_name,
                    "arguments": {"row_limit": 1000}
                }
            }
            await push_status(latest_status_timeline, "📁 Validating index existence", 1)
            indexes_result = await execute_mcp_tool_call(indexes_call, config)
            parsed_indexes = extract_results_from_mcp_response(indexes_result)
            index_rows = parsed_indexes.get("results", []) if isinstance(parsed_indexes, dict) else []
            index_names = []
            for row in index_rows:
                if not isinstance(row, dict):
                    continue
                candidate = row.get("title") or row.get("name")
                if isinstance(candidate, str) and candidate.strip():
                    index_names.append(candidate.strip())

            index_check_failed = classify_tool_result(indexes_result)["status"] == "error"
            index_exists = any(name.lower() == normalized_index_name.lower() for name in index_names)
            latest_tool_calls.append({
                "iteration": 1,
                "tool": indexes_tool_name,
                "args": {"row_limit": 1000},
                "spl_query": None,
                "result": indexes_result,
                "summary": {
                    "type": indexes_tool_name,
                    "row_count": len(index_rows),
                    "findings": [f"Found {len(index_rows)} indexes"],
                    "actual_results": index_rows[:5]
                }
            })

            if not index_exists and not index_check_failed:
                similar = [name for name in index_names if normalized_index_name.lower() in name.lower()][:5]
                response_text = f"I validated live index metadata and could not find an index named `{normalized_index_name}`."
                if similar:
                    response_text += "\n\nClosest matches: " + ", ".join(similar)
                elif index_names:
                    response_text += "\n\nIf helpful, I can list all currently available indexes."

                await push_status(latest_status_timeline, "✅ Finalizing response", len(latest_tool_calls))
                visualization_spec, capability_usage = augment_capability_usage_with_visualization(latest_tool_calls)
                response_text, capability_usage = enrich_response_with_live_reusable_query_reference(
                    response_text,
                    capability_usage,
                    latest_tool_calls,
                )
                updated_memory = update_chat_memory(
                    chat_session_id,
                    user_message,
                    latest_tool_calls,
                    assistant_response=response_text,
                    record_user_turn=False,
                )
                follow_on_actions = build_follow_on_actions(
                    user_message,
                    updated_memory,
                    latest_tool_calls,
                    assistant_response=response_text,
                )
                return {
                    "response": response_text,
                    "initial_response": user_message,
                    "tool_calls": latest_tool_calls,
                    "spl_query": extract_primary_spl_query(latest_tool_calls),
                    "visualization_spec": visualization_spec,
                    "iterations": len(latest_tool_calls),
                    "execution_time": f"{time.time() - request_started_at:.2f}s",
                    "insights": ["Index was validated directly from Splunk index inventory."],
                    "status_timeline": latest_status_timeline,
                    "discovery_age_warning": discovery_age_warning,
                    "chat_session_id": chat_session_id,
                    "chat_memory": updated_memory,
                    "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                    "capability_usage": capability_usage,
                    "has_follow_on": len(follow_on_actions) > 0,
                    "follow_on_actions": follow_on_actions
                }

            # Step 2: fetch latest event in that index
            latest_query = f"search index={normalized_index_name} | sort - _time | head 1"
            latest_call = {
                "method": "tools/call",
                "params": {
                    "name": query_tool_name,
                    "arguments": {
                        "query": latest_query,
                        "earliest_time": "-30d",
                        "latest_time": "now",
                        "row_limit": 1
                    }
                }
            }
            await push_status(latest_status_timeline, "🔍 Retrieving latest event", 2)
            latest_result = await execute_mcp_tool_call(latest_call, config)
            parsed_latest = extract_results_from_mcp_response(latest_result)
            latest_rows = parsed_latest.get("results", []) if isinstance(parsed_latest, dict) else []
            latest_outcome = classify_tool_result(latest_result)

            latest_tool_calls.append({
                "iteration": 2,
                "tool": query_tool_name,
                "args": {
                    "query": latest_query,
                    "earliest_time": "-30d",
                    "latest_time": "now",
                    "row_limit": 1
                },
                "spl_query": latest_query,
                "result": latest_result,
                "summary": {
                    "type": query_tool_name,
                    "row_count": len(latest_rows),
                    "findings": [f"{len(latest_rows)} results returned"],
                    "actual_results": latest_rows[:1]
                }
            })

            if latest_outcome["status"] == "error":
                index_note = "I could not confirm the index exists, and" if index_check_failed else f"I confirmed index `{normalized_index_name}` exists, but"
                response_text = (
                    f"{index_note} the latest-entry search returned an error:\n\n"
                    f"> {latest_outcome.get('error') or 'No additional error details were returned.'}"
                )
            elif latest_rows:
                latest_event = latest_rows[0] if isinstance(latest_rows[0], dict) else {"value": latest_rows[0]}
                pretty_event = json.dumps(latest_event, indent=2, default=str)
                response_text = (
                    f"Latest event in index `{normalized_index_name}`:\n\n"
                    f"```json\n{pretty_event}\n```"
                )
            else:
                response_text = (
                    f"Index `{normalized_index_name}` exists, but no events were returned for the last 30 days "
                    f"with `search index={normalized_index_name} | sort - _time | head 1`."
                )

            response_text = finalize_route_tool_calls(
                response_text,
                latest_tool_calls,
                annotate_reply=latest_outcome["status"] != "error",
            )
            await push_status(latest_status_timeline, "✅ Finalizing response", len(latest_tool_calls))
            visualization_spec, capability_usage = augment_capability_usage_with_visualization(latest_tool_calls)
            response_text, capability_usage = enrich_response_with_live_reusable_query_reference(
                response_text,
                capability_usage,
                latest_tool_calls,
            )
            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                latest_tool_calls,
                assistant_response=response_text,
                record_user_turn=False,
            )
            follow_on_actions = build_follow_on_actions(
                user_message,
                updated_memory,
                latest_tool_calls,
                assistant_response=response_text,
            )
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": latest_tool_calls,
                "spl_query": extract_primary_spl_query(latest_tool_calls),
                "visualization_spec": visualization_spec,
                "iterations": len(latest_tool_calls),
                "execution_time": f"{time.time() - request_started_at:.2f}s",
                "insights": ["Used deterministic latest-event flow for index validation and retrieval."],
                "status_timeline": latest_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                "capability_usage": capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }

        if bool(chat_session_settings.get("enable_splunk_augmentation", True)) and detect_edge_processor_template_request(user_message):
            skill_status_timeline: List[Dict[str, Any]] = []
            skill_tool_calls: List[Dict[str, Any]] = []

            knowledge_tool_name = resolve_tool_name("splunk_get_knowledge_objects", available_mcp_tools)
            await push_status(skill_status_timeline, "🧭 Fetching knowledge objects", 1)

            attempts = [
                {"type": "saved_searches", "row_limit": 1000},
                {"type": "macros", "row_limit": 1000},
                {"type": "data_models", "row_limit": 500},
            ]

            collected_rows: List[Dict[str, Any]] = []
            for attempt_idx, args in enumerate(attempts, 1):
                call_payload = {
                    "method": "tools/call",
                    "params": {
                        "name": knowledge_tool_name,
                        "arguments": args
                    }
                }
                attempt_result = await execute_mcp_tool_call(call_payload, config)
                parsed = extract_results_from_mcp_response(attempt_result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                if isinstance(rows, list):
                    for row in rows:
                        if isinstance(row, dict):
                            collected_rows.append(row)

                skill_tool_calls.append({
                    "iteration": attempt_idx,
                    "tool": knowledge_tool_name,
                    "args": args,
                    "spl_query": None,
                    "result": attempt_result,
                    "summary": {
                        "type": knowledge_tool_name,
                        "row_count": len(rows) if isinstance(rows, list) else 0,
                        "findings": [f"Attempt {attempt_idx}: {len(rows) if isinstance(rows, list) else 0} objects returned"],
                        "actual_results": rows[:8] if isinstance(rows, list) else []
                    }
                })

            filtered_templates: List[Dict[str, Any]] = []
            for row in collected_rows:
                title = str(row.get("title") or row.get("name") or row.get("id") or "").strip()
                description = str(row.get("description") or row.get("search") or row.get("qualifiedSearch") or "").strip()
                searchable = f"{title} {description}".lower()
                if not searchable:
                    continue
                if "edge" in searchable and ("processor" in searchable or "template" in searchable):
                    filtered_templates.append({
                        "title": title or "Unnamed object",
                        "description": description[:240],
                        "type": row.get("type") or row.get("object_type") or "knowledge_object"
                    })

            deduped: List[Dict[str, Any]] = []
            seen_titles = set()
            for item in filtered_templates:
                key = str(item.get("title", "")).lower()
                if key and key not in seen_titles:
                    seen_titles.add(key)
                    deduped.append(item)

            if deduped:
                lines = ["I found these Splunk knowledge objects that match Edge Processor template intent:"]
                for idx, item in enumerate(deduped[:12], 1):
                    lines.append(f"{idx}. {item.get('title', 'Template')} ({item.get('type', 'knowledge_object')})")
                    if item.get("description"):
                        lines.append(f"   - {item.get('description')}")
                response_text = "\n".join(lines)
            else:
                fallback_query_args = {
                    "query": "| rest /servicesNS/-/-/saved/searches | search title=\"*edge*\" OR search=\"*edge*\" OR title=\"*template*\" | table title description eai:acl.app",
                    "earliest_time": "-24h",
                    "latest_time": "now"
                }
                fallback_result = await execute_mcp_tool_call({
                    "method": "tools/call",
                    "params": {
                        "name": query_tool_name,
                        "arguments": fallback_query_args
                    }
                }, config)
                fallback_parsed = extract_results_from_mcp_response(fallback_result)
                fallback_rows = fallback_parsed.get("results", []) if isinstance(fallback_parsed, dict) else []

                fallback_matches: List[str] = []
                for row in fallback_rows if isinstance(fallback_rows, list) else []:
                    if isinstance(row, dict):
                        title = str(row.get("title") or "").strip()
                        if title:
                            fallback_matches.append(title)

                skill_tool_calls.append({
                    "iteration": len(skill_tool_calls) + 1,
                    "tool": query_tool_name,
                    "args": fallback_query_args,
                    "spl_query": fallback_query_args.get("query"),
                    "result": fallback_result,
                    "summary": {
                        "type": query_tool_name,
                        "row_count": len(fallback_rows) if isinstance(fallback_rows, list) else 0,
                        "findings": [f"Fallback REST lookup returned {len(fallback_matches)} entries"],
                        "actual_results": fallback_rows[:8] if isinstance(fallback_rows, list) else []
                    }
                })

                if fallback_matches:
                    response_text = "I found these template-like saved searches related to edge processing:\n" + "\n".join([f"- {item}" for item in fallback_matches[:20]])
                else:
                    response_text = (
                        "I queried knowledge objects and a saved-search REST fallback, but found no objects clearly tagged as Edge Processor templates. "
                        "If you use a naming convention, I can search for that exact prefix next."
                    )

            response_text = finalize_route_tool_calls(response_text, skill_tool_calls)
            await push_status(skill_status_timeline, "✅ Finalizing response", max(1, len(skill_tool_calls)))
            visualization_spec, capability_usage = augment_capability_usage_with_visualization(skill_tool_calls)
            response_text, capability_usage = enrich_response_with_live_reusable_query_reference(
                response_text,
                capability_usage,
                skill_tool_calls,
            )
            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                skill_tool_calls,
                assistant_response=response_text,
                record_user_turn=False,
            )
            follow_on_actions = build_follow_on_actions(
                user_message,
                updated_memory,
                skill_tool_calls,
                assistant_response=response_text,
            )
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": skill_tool_calls,
                "spl_query": extract_primary_spl_query(skill_tool_calls),
                "visualization_spec": visualization_spec,
                "iterations": len(skill_tool_calls),
                "execution_time": f"{time.time() - request_started_at:.2f}s",
                "insights": ["Used deterministic template lookup for Edge Processor intent."],
                "status_timeline": skill_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                "capability_usage": capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }

        offline_target = detect_last_offline_target(user_message) if bool(chat_session_settings.get("enable_splunk_augmentation", True)) else None
        if offline_target:
            offline_status_timeline: List[Dict[str, Any]] = []
            offline_tool_calls: List[Dict[str, Any]] = []

            memory_indexes = (chat_memory.get("entities", {}).get("indexes", []) if isinstance(chat_memory, dict) else [])
            candidate_indexes = []
            for name in (memory_indexes[-4:] if isinstance(memory_indexes, list) else []):
                if isinstance(name, str) and name and "*" not in name and name not in candidate_indexes:
                    candidate_indexes.append(name)

            offline_terms = '(offline OR down OR unreachable OR disconnected OR "link down" OR status=offline OR status=down)'
            entity_clause = f'(host="{offline_target}" OR src="{offline_target}" OR dest="{offline_target}" OR ip="{offline_target}" OR "{offline_target}")'
            noise_exclusion = 'NOT sourcetype=mcp_server NOT source="*mcp_server*" NOT "Executing SPL query:"'

            query_attempts = []
            for idx_name in candidate_indexes[:5]:
                query_attempts.append({
                    "query": f"search index={idx_name} {entity_clause} {offline_terms} {noise_exclusion} | sort - _time | head 1 | table _time host src dest ip status sourcetype source message",
                    "earliest_time": "-30d",
                    "latest_time": "now"
                })
                query_attempts.append({
                    "query": f"search index={idx_name} {entity_clause} {offline_terms} {noise_exclusion} | sort - _time | head 1 | table _time host src dest ip status sourcetype source message",
                    "earliest_time": "-90d",
                    "latest_time": "now"
                })

            query_attempts.append({
                "query": f"search index=* {entity_clause} {offline_terms} {noise_exclusion} | sort - _time | head 1 | table _time host src dest ip status sourcetype source message",
                "earliest_time": "-90d",
                "latest_time": "now"
            })

            found_event: Optional[Dict[str, Any]] = None
            for attempt_idx, attempt_args in enumerate(query_attempts[:8], 1):
                await push_status(offline_status_timeline, "🔍 Searching for latest offline signal", attempt_idx)
                call_payload = {
                    "method": "tools/call",
                    "params": {
                        "name": query_tool_name,
                        "arguments": attempt_args
                    }
                }
                attempt_result = await execute_mcp_tool_call(call_payload, config)
                parsed = extract_results_from_mcp_response(attempt_result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                row_count = len(rows) if isinstance(rows, list) else 0

                offline_tool_calls.append({
                    "iteration": attempt_idx,
                    "tool": query_tool_name,
                    "args": attempt_args,
                    "spl_query": attempt_args.get("query"),
                    "result": attempt_result,
                    "summary": {
                        "type": query_tool_name,
                        "row_count": row_count,
                        "findings": [f"Attempt {attempt_idx}: {row_count} results returned"],
                        "actual_results": rows[:2] if isinstance(rows, list) else []
                    }
                })

                if row_count > 0:
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        row_message = str(row.get("message") or "")
                        row_source = str(row.get("source") or "")
                        row_sourcetype = str(row.get("sourcetype") or "")
                        is_noise = (
                            "executing spl query:" in row_message.lower()
                            or "mcp_server" in row_source.lower()
                            or row_sourcetype.lower() == "mcp_server"
                        )
                        if not is_noise:
                            found_event = row
                            break
                    if found_event:
                        break

            if found_event:
                raw_time = found_event.get("_time") or found_event.get("time") or found_event.get("timestamp")
                friendly_time = str(raw_time)
                if isinstance(raw_time, (int, float)):
                    try:
                        friendly_time = datetime.fromtimestamp(float(raw_time)).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        friendly_time = str(raw_time)

                pretty_event = json.dumps(found_event, indent=2, default=str)
                response_text = (
                    f"The latest offline event I found for `{offline_target}` was at **{friendly_time}**.\n\n"
                    f"```json\n{pretty_event}\n```"
                )
            else:
                attempted_patterns = [str(call.get("args", {}).get("query", ""))[:90] for call in offline_tool_calls[:3]]
                response_text = (
                    f"I searched multiple indexes and broader time windows but found no offline events for `{offline_target}`. "
                    f"I tried patterns like: {' | '.join(attempted_patterns)}. "
                    f"If you want, I can retry with a custom index list or alternate status keywords used in your environment."
                )

            if not found_event:
                response_text = finalize_route_tool_calls(response_text, offline_tool_calls)
            await push_status(offline_status_timeline, "✅ Finalizing response", max(1, len(offline_tool_calls)))
            visualization_spec, capability_usage = augment_capability_usage_with_visualization(offline_tool_calls)
            response_text, capability_usage = enrich_response_with_live_reusable_query_reference(
                response_text,
                capability_usage,
                offline_tool_calls,
            )
            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                offline_tool_calls,
                assistant_response=response_text,
                record_user_turn=False,
            )
            follow_on_actions = build_follow_on_actions(
                user_message,
                updated_memory,
                offline_tool_calls,
                assistant_response=response_text,
            )
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": offline_tool_calls,
                "spl_query": extract_primary_spl_query(offline_tool_calls),
                "visualization_spec": visualization_spec,
                "iterations": len(offline_tool_calls),
                "execution_time": f"{time.time() - request_started_at:.2f}s",
                "insights": ["Used deterministic offline-event lookup with index and time-range fallbacks."],
                "status_timeline": offline_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                "capability_usage": capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }

        basic_intent = None
        if bool(chat_session_settings.get("enable_splunk_augmentation", True)) and not should_bypass_basic_inventory_intent(request):
            basic_intent = detect_basic_inventory_intent(user_message, chat_memory)
        if basic_intent:
            basic_status_timeline: List[Dict[str, Any]] = []
            basic_tool_calls: List[Dict[str, Any]] = []
            await push_status(basic_status_timeline, "🧭 Interpreting request with deterministic route", 0)

            if basic_intent == "list_indexes":
                indexes_tool_name = resolve_tool_name("splunk_get_indexes", available_mcp_tools)
                args = {"row_limit": 200}
                await push_status(basic_status_timeline, "📁 Loading indexes", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": indexes_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                names = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        candidate = row.get("title") or row.get("name")
                        if isinstance(candidate, str) and candidate.strip():
                            names.append(candidate.strip())
                names = sorted(list(dict.fromkeys(names)))
                response_text = "Available indexes:\n" + "\n".join([f"- {name}" for name in names[:80]]) if names else "No indexes were returned by Splunk."
                basic_tool_calls.append({"iteration": 1, "tool": indexes_tool_name, "args": args, "spl_query": None, "result": result, "summary": {"type": indexes_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(names)} indexes"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            elif basic_intent == "list_sourcetypes":
                args = {"query": "| tstats count where index=* by sourcetype | sort - count | head 50", "earliest_time": "-7d", "latest_time": "now"}
                await push_status(basic_status_timeline, "🧾 Loading sourcetypes", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                sourcetypes = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        value = row.get("sourcetype") or row.get("SOURCETYPE")
                        if isinstance(value, str) and value.strip():
                            sourcetypes.append(value.strip())
                sourcetypes = list(dict.fromkeys(sourcetypes))
                response_text = "Top sourcetypes (last 7d):\n" + "\n".join([f"- {value}" for value in sourcetypes[:50]]) if sourcetypes else "No sourcetypes were returned for the selected time range."
                basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(sourcetypes)} sourcetypes"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            elif basic_intent == "top_indexes":
                args = {"query": "| tstats count where index=* by index | sort - count | head 25", "earliest_time": "-7d", "latest_time": "now"}
                await push_status(basic_status_timeline, "📊 Loading top indexes", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                lines: List[str] = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        idx_name = _row_value(row, "index", "INDEX")
                        count_value = _row_value(row, "count", "COUNT", default="n/a")
                        if idx_name is not None:
                            lines.append(f"- {idx_name}: {count_value}")
                response_text = "Top indexes by event count (last 7d):\n" + "\n".join(lines[:25]) if lines else "No index volume data was returned for the selected time range."
                basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(lines)} index rows"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            elif basic_intent == "top_errors":
                args = {"query": "search index=* (error OR failed OR exception) | stats count by sourcetype | sort - count | head 20", "earliest_time": "-24h", "latest_time": "now"}
                await push_status(basic_status_timeline, "🚨 Loading top error sources", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                lines = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        source_type = _row_value(row, "sourcetype", "SOURCETYPE", default="unknown")
                        count_value = _row_value(row, "count", "COUNT", default="n/a")
                        lines.append(f"- {source_type}: {count_value}")
                response_text = "Top error-producing sourcetypes (last 24h):\n" + "\n".join(lines[:20]) if lines else "No error-focused results were returned for the selected time range."
                basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(lines)} error rows"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            elif basic_intent == "latest_auth_failures":
                args = {"query": "search index=* (\"failed login\" OR \"authentication failed\" OR \"login failed\" OR \"invalid user\" OR action=failure) | sort - _time | head 20 | table _time host user src src_ip action status message sourcetype", "earliest_time": "-7d", "latest_time": "now"}
                await push_status(basic_status_timeline, "🔐 Loading latest authentication failures", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                entries = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        entries.append(f"- {row.get('_time', 'unknown time')} | host={row.get('host', 'n/a')} | user={row.get('user', 'n/a')} | src={row.get('src', row.get('src_ip', 'n/a'))}")
                response_text = "Latest authentication failure events:\n" + "\n".join(entries[:20]) if entries else "No authentication failure events were returned in the last 7 days."
                basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(entries)} auth failure events"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            elif basic_intent == "count_index_events":
                target_index = extract_index_from_message(user_message)
                if not target_index:
                    response_text = "I could not identify the index name. Try a prompt like: 'how many events in index=main'."
                else:
                    count_query = f"| tstats count as event_count where index={target_index}"
                    args_24h = {"query": count_query, "earliest_time": "-24h", "latest_time": "now"}
                    args_7d = {"query": count_query, "earliest_time": "-7d", "latest_time": "now"}
                    await push_status(basic_status_timeline, f"📏 Counting events for index={target_index}", 1)
                    res_24h = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args_24h}}, config)
                    res_7d = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args_7d}}, config)
                    outcome_24h = classify_tool_result(res_24h)
                    outcome_7d = classify_tool_result(res_7d)
                    count_24h = extract_event_count(outcome_24h)
                    count_7d = extract_event_count(outcome_7d)
                    response_text = (
                        f"Event counts for index `{target_index}`:\n"
                        f"- Last 24h: {format_event_count(count_24h)}\n"
                        f"- Last 7d: {format_event_count(count_7d)}"
                    )
                    basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args_24h, "spl_query": args_24h.get("query"), "result": res_24h, "summary": summarize_tool_outcome(query_tool_name, outcome_24h)})
                    basic_tool_calls.append({"iteration": 2, "tool": query_tool_name, "args": args_7d, "spl_query": args_7d.get("query"), "result": res_7d, "summary": summarize_tool_outcome(query_tool_name, outcome_7d)})
            elif basic_intent == "timechart_index_trend":
                target_index = extract_index_from_message(user_message) or _remembered_entity(chat_memory, "index")
                explicit_earliest, explicit_latest = extract_time_range_from_message(user_message)
                memory_window = chat_memory.get("last_result", {}) if isinstance(chat_memory, dict) and isinstance(chat_memory.get("last_result", {}), dict) else {}
                earliest_time = explicit_earliest or str(memory_window.get("earliest_time") or "-24h")
                latest_time = explicit_latest or str(memory_window.get("latest_time") or "now")

                if not target_index:
                    response_text = "I need an index anchor for the trend view. Try including an index, for example: 'Show a timechart for index=main over the last 24 hours'."
                else:
                    span = "1h" if earliest_time in {"-24h", "-7d"} else "1d"
                    args = {
                        "query": f"search index={target_index} | timechart span={span} count",
                        "earliest_time": earliest_time,
                        "latest_time": latest_time,
                    }
                    await push_status(basic_status_timeline, f"📈 Building timechart for index={target_index}", 1)
                    result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                    parsed = extract_results_from_mcp_response(result)
                    rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                    lines = []
                    for row in rows if isinstance(rows, list) else []:
                        if isinstance(row, dict):
                            timestamp = row.get("_time") or row.get("time") or row.get("TIME") or "unknown"
                            count_value = _row_value(row, "count", "COUNT", "value", default=0)
                            lines.append(f"- {timestamp}: {count_value}")
                    response_text = (
                        f"Event volume trend for index `{target_index}` ({_describe_time_window(earliest_time, latest_time)}):\n"
                        + "\n".join(lines[:24])
                    ) if lines else f"No trend data was returned for index `{target_index}` in {_describe_time_window(earliest_time, latest_time)}."
                    basic_tool_calls.append({
                        "iteration": 1,
                        "tool": query_tool_name,
                        "args": args,
                        "spl_query": args.get("query"),
                        "result": result,
                        "summary": {
                            "type": query_tool_name,
                            "row_count": len(rows) if isinstance(rows, list) else 0,
                            "findings": [f"Found {len(lines)} timechart buckets"],
                            "actual_results": rows[:8] if isinstance(rows, list) else []
                        }
                    })

            elif basic_intent == "breakdown_index":
                target_index = extract_index_from_message(user_message) or _remembered_entity(chat_memory, "index")
                explicit_earliest, explicit_latest = extract_time_range_from_message(user_message)
                memory_window = chat_memory.get("last_result", {}) if isinstance(chat_memory, dict) and isinstance(chat_memory.get("last_result", {}), dict) else {}
                earliest_time = explicit_earliest or str(memory_window.get("earliest_time") or "-24h")
                latest_time = explicit_latest or str(memory_window.get("latest_time") or "now")

                if not target_index:
                    response_text = "I need an index anchor for the breakdown. Try including an index, for example: 'Break down index=main by sourcetype and host'."
                else:
                    args = {
                        "query": f"search index={target_index} | stats count by sourcetype host | sort - count | head 20",
                        "earliest_time": earliest_time,
                        "latest_time": latest_time,
                    }
                    await push_status(basic_status_timeline, f"🧩 Breaking down index={target_index}", 1)
                    result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                    parsed = extract_results_from_mcp_response(result)
                    rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                    lines = []
                    for row in rows if isinstance(rows, list) else []:
                        if isinstance(row, dict):
                            sourcetype = row.get("sourcetype") or row.get("SOURCETYPE") or "unknown"
                            host = row.get("host") or row.get("HOST") or "unknown"
                            count_value = _row_value(row, "count", "COUNT", default=0)
                            lines.append(f"- sourcetype={sourcetype} | host={host} | count={count_value}")
                    response_text = (
                        f"Top sourcetype and host breakdown for index `{target_index}` ({_describe_time_window(earliest_time, latest_time)}):\n"
                        + "\n".join(lines[:20])
                    ) if lines else f"No breakdown rows were returned for index `{target_index}` in {_describe_time_window(earliest_time, latest_time)}."
                    basic_tool_calls.append({
                        "iteration": 1,
                        "tool": query_tool_name,
                        "args": args,
                        "spl_query": args.get("query"),
                        "result": result,
                        "summary": {
                            "type": query_tool_name,
                            "row_count": len(rows) if isinstance(rows, list) else 0,
                            "findings": [f"Found {len(lines)} breakdown rows"],
                            "actual_results": rows[:8] if isinstance(rows, list) else []
                        }
                    })

            elif basic_intent == "baseline_index_check":
                target_index = extract_index_from_message(user_message) or _remembered_entity(chat_memory, "index")
                if not target_index:
                    response_text = "I need an index anchor for the baseline check. Try including an index, for example: 'Run a baseline count check for index=main'."
                else:
                    count_query = f"| tstats count as event_count where index={target_index}"
                    args_24h = {"query": count_query, "earliest_time": "-24h", "latest_time": "now"}
                    args_7d = {"query": count_query, "earliest_time": "-7d", "latest_time": "now"}
                    await push_status(basic_status_timeline, f"📏 Running baseline checks for index={target_index}", 1)
                    res_24h = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args_24h}}, config)
                    res_7d = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args_7d}}, config)
                    outcome_24h = classify_tool_result(res_24h)
                    outcome_7d = classify_tool_result(res_7d)
                    count_24h = extract_event_count(outcome_24h)
                    count_7d = extract_event_count(outcome_7d)
                    if count_7d is None:
                        availability = "Could not be determined because the 7-day search failed"
                    elif count_7d > 0:
                        availability = "Data is available"
                    else:
                        availability = "No data was found in the last 7 days"
                    response_text = (
                        f"Baseline check for index `{target_index}`:\n"
                        f"- Last 24h: {format_event_count(count_24h)}\n"
                        f"- Last 7d: {format_event_count(count_7d)}\n"
                        f"- Assessment: {availability}."
                    )
                    basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args_24h, "spl_query": args_24h.get("query"), "result": res_24h, "summary": summarize_tool_outcome(query_tool_name, outcome_24h)})
                    basic_tool_calls.append({"iteration": 2, "tool": query_tool_name, "args": args_7d, "spl_query": args_7d.get("query"), "result": res_7d, "summary": summarize_tool_outcome(query_tool_name, outcome_7d)})
            elif basic_intent == "host_pivot":
                target_host = extract_host_or_ip_from_message(user_message) or _remembered_entity(chat_memory, "host")
                target_index = extract_index_from_message(user_message) or _remembered_entity(chat_memory, "index")
                explicit_earliest, explicit_latest = extract_time_range_from_message(user_message)
                memory_window = chat_memory.get("last_result", {}) if isinstance(chat_memory, dict) and isinstance(chat_memory.get("last_result", {}), dict) else {}
                earliest_time = explicit_earliest or str(memory_window.get("earliest_time") or "-24h")
                latest_time = explicit_latest or str(memory_window.get("latest_time") or "now")

                if not target_host:
                    response_text = "I need a host or IP to pivot on. Try including a host, for example: 'Pivot on host=router-01 and identify related anomalies'."
                else:
                    search_scope = f"index={target_index} " if target_index else "index=* "
                    args = {
                        "query": f"search {search_scope}host=\"{target_host}\" | stats count by sourcetype source | sort - count | head 20",
                        "earliest_time": earliest_time,
                        "latest_time": latest_time,
                    }
                    await push_status(basic_status_timeline, f"🖥️ Pivoting on host={target_host}", 1)
                    result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                    parsed = extract_results_from_mcp_response(result)
                    rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                    lines = []
                    for row in rows if isinstance(rows, list) else []:
                        if isinstance(row, dict):
                            sourcetype = row.get("sourcetype") or row.get("SOURCETYPE") or "unknown"
                            source = row.get("source") or row.get("SOURCE") or "unknown"
                            count_value = _row_value(row, "count", "COUNT", default=0)
                            lines.append(f"- sourcetype={sourcetype} | source={source} | count={count_value}")
                    response_text = (
                        f"Host pivot for `{target_host}` ({_describe_time_window(earliest_time, latest_time)}):\n"
                        + "\n".join(lines[:20])
                    ) if lines else f"No host pivot rows were returned for `{target_host}` in {_describe_time_window(earliest_time, latest_time)}."
                    basic_tool_calls.append({
                        "iteration": 1,
                        "tool": query_tool_name,
                        "args": args,
                        "spl_query": args.get("query"),
                        "result": result,
                        "summary": {
                            "type": query_tool_name,
                            "row_count": len(rows) if isinstance(rows, list) else 0,
                            "findings": [f"Found {len(lines)} host pivot rows"],
                            "actual_results": rows[:8] if isinstance(rows, list) else []
                        }
                    })

            elif basic_intent == "latest_host_heartbeat":
                target_host = extract_host_or_ip_from_message(user_message)
                if not target_host and isinstance(chat_memory, dict):
                    remembered_hosts = chat_memory.get("entities", {}).get("hosts", [])
                    if isinstance(remembered_hosts, list) and remembered_hosts:
                        target_host = remembered_hosts[-1]

                if not target_host:
                    response_text = "I could not identify the host/IP. Try: 'last seen host=router-01' or include an IP address."
                else:
                    attempts = [
                        {"query": f"search index=* host=\"{target_host}\" (heartbeat OR alive OR uptime OR status=up OR status=online) | sort - _time | head 1 | table _time host sourcetype source message", "earliest_time": "-7d", "latest_time": "now"},
                        {"query": f"search index=* host=\"{target_host}\" | sort - _time | head 1 | table _time host sourcetype source message", "earliest_time": "-30d", "latest_time": "now"}
                    ]
                    found_row = None
                    for attempt_idx, args in enumerate(attempts, 1):
                        await push_status(basic_status_timeline, f"📡 Checking last-seen for {target_host}", attempt_idx)
                        result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                        parsed = extract_results_from_mcp_response(result)
                        rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                        basic_tool_calls.append({"iteration": attempt_idx, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Attempt {attempt_idx}: {len(rows) if isinstance(rows, list) else 0} rows"], "actual_results": rows[:5] if isinstance(rows, list) else []}})
                        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                            found_row = rows[0]
                            break

                    if found_row:
                        response_text = (
                            f"Latest event for `{target_host}`:\n"
                            f"- Time: {found_row.get('_time', 'unknown')}\n"
                            f"- Sourcetype: {found_row.get('sourcetype', 'n/a')}\n"
                            f"- Source: {found_row.get('source', 'n/a')}"
                        )
                    else:
                        response_text = f"No events found for `{target_host}` in the attempted heartbeat/last-seen windows."

            elif basic_intent == "list_hosts":
                args = {"query": "| tstats count where index=* by host | sort - count | head 50", "earliest_time": "-7d", "latest_time": "now"}
                await push_status(basic_status_timeline, "🖥️ Loading hosts", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": query_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                hosts = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        value = row.get("host") or row.get("HOST")
                        if isinstance(value, str) and value.strip():
                            hosts.append(value.strip())
                hosts = list(dict.fromkeys(hosts))
                response_text = "Top hosts (last 7d):\n" + "\n".join([f"- {value}" for value in hosts[:50]]) if hosts else "No hosts were returned for the selected time range."
                basic_tool_calls.append({"iteration": 1, "tool": query_tool_name, "args": args, "spl_query": args.get("query"), "result": result, "summary": {"type": query_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(hosts)} hosts"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            else:
                knowledge_tool_name = resolve_tool_name("splunk_get_knowledge_objects", available_mcp_tools)
                args = {"type": "saved_searches", "row_limit": 500}
                await push_status(basic_status_timeline, "📚 Loading knowledge objects", 1)
                result = await execute_mcp_tool_call({"method": "tools/call", "params": {"name": knowledge_tool_name, "arguments": args}}, config)
                parsed = extract_results_from_mcp_response(result)
                rows = parsed.get("results", []) if isinstance(parsed, dict) else []
                templates = []
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        title = str(row.get("title") or row.get("name") or "").strip()
                        searchable = f"{title} {row.get('description', '')} {row.get('search', '')}".lower()
                        if title and "template" in searchable:
                            templates.append(title)
                templates = list(dict.fromkeys(templates))
                response_text = "Template-like knowledge objects:\n" + "\n".join([f"- {value}" for value in templates[:60]]) if templates else "No template-like knowledge objects were returned."
                basic_tool_calls.append({"iteration": 1, "tool": knowledge_tool_name, "args": args, "spl_query": None, "result": result, "summary": {"type": knowledge_tool_name, "row_count": len(rows) if isinstance(rows, list) else 0, "findings": [f"Found {len(templates)} template-like objects"], "actual_results": rows[:8] if isinstance(rows, list) else []}})

            response_text = finalize_route_tool_calls(response_text, basic_tool_calls)
            await push_status(basic_status_timeline, "✅ Finalizing response", max(1, len(basic_tool_calls)))
            visualization_spec, capability_usage = augment_capability_usage_with_visualization(basic_tool_calls)
            response_text, capability_usage = enrich_response_with_live_reusable_query_reference(
                response_text,
                capability_usage,
                basic_tool_calls,
            )
            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                basic_tool_calls,
                assistant_response=response_text,
                record_user_turn=False,
            )
            follow_on_actions = build_follow_on_actions(
                user_message,
                updated_memory,
                basic_tool_calls,
                assistant_response=response_text,
            )
            return {
                "response": response_text,
                "initial_response": user_message,
                "tool_calls": basic_tool_calls,
                "spl_query": extract_primary_spl_query(basic_tool_calls),
                "visualization_spec": visualization_spec,
                "iterations": len(basic_tool_calls),
                "execution_time": f"{time.time() - request_started_at:.2f}s",
                "insights": [f"Used deterministic basic intent route: {basic_intent}."],
                "status_timeline": basic_status_timeline,
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "conversation_history": _build_follow_up_conversation_history(history, user_message, response_text),
                "capability_usage": capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }
        
        rag_context = ""
        capability_usage: List[Dict[str, Any]] = []
        if bool(chat_session_settings.get("enable_rag_context", False)):
            rag_max_chunks = _safe_int(chat_session_settings.get("rag_max_chunks", 3))
            rag_context, capability_usage = get_optional_rag_context(user_message, max_chunks=rag_max_chunks)

        llm_client = get_or_create_llm_client(config)
        chat_runtime_profile = build_chat_runtime_profile(config, llm_client)
        runtime_temperature = chat_runtime_profile["temperature"]
        print(
            f"🔵 [CHAT] Runtime profile: provider={chat_runtime_profile['provider']} "
            f"model={chat_runtime_profile['model'] or getattr(config.llm, 'model', '')} "
            f"compact={chat_runtime_profile['use_compact_prompt']} "
            f"context_limit={chat_runtime_profile['context_history_limit']} "
            f"initial_max_tokens={chat_runtime_profile['initial_max_tokens']}"
        )

        max_iterations = max(1, _safe_int(chat_session_settings.get("max_iterations", 5)) or 5)
        max_execution_time = max(10, _safe_int(chat_session_settings.get("max_execution_time", 90)) or 90)
        stall_limit = max(2, _safe_int(chat_session_settings.get("convergence_detection", 3)) or 3)
        evidence_rows = int(chat_runtime_profile.get("evidence_rows") or 10)
        evidence_chars = int(chat_runtime_profile.get("evidence_chars") or 6000)
        followup_max_tokens = chat_runtime_profile["followup_max_tokens"]

        if chat_runtime_profile["use_compact_prompt"]:
            system_prompt = build_compact_chat_prompt(
                query_tool_name=query_tool_name,
                discovery_context=discovery_context,
                rag_context=rag_context,
                memory_context=memory_context,
                available_tools_text=available_tools_text,
                discovery_age_warning=discovery_age_warning,
                mission=mission,
                goal_progress=goal_progress,
            )
        else:
            system_prompt = build_grounded_chat_prompt(
                query_tool_name=query_tool_name,
                available_tools_text=available_tools_text,
                discovery_context=discovery_context,
                rag_context=rag_context,
                memory_context=memory_context,
                discovery_age_warning=discovery_age_warning,
                mission=mission,
                goal_progress=goal_progress,
                blocked_commands=SPL_BLOCKED_COMMANDS,
                max_tool_steps=max_iterations,
            )
        if chat_runtime_profile["reasoning_guard"]:
            system_prompt = f"{system_prompt}\n{chat_runtime_profile['reasoning_guard']}"

        context_limit = chat_runtime_profile["context_history_limit"]
        continuity_context = build_llm_continuity_context(
            user_message=user_message,
            history=history,
            memory=chat_memory,
            limit=context_limit,
        )
        has_session_context = bool(_build_llm_recent_context_turns(history, chat_memory, limit=max(2, context_limit)))
        requires_spl_explanation = user_requested_spl_explanation(user_message)
        spl_explanation_requirement = build_spl_explanation_requirement(requires_spl_explanation)

        if chat_runtime_profile["short_circuit_greetings"] and small_talk and not has_session_context:
            # Small local models answer greetings faster and better without the full tool prompt.
            greeting_prompt = (
                "You are the Splunk Discovery Tool assistant. Reply warmly in one or two sentences and offer to help "
                "the user explore or troubleshoot their Splunk data."
            )
            mission_block = format_mission_context(mission, goal_progress)
            if mission_block:
                greeting_prompt = f"{greeting_prompt}\n{mission_block}"
            if chat_runtime_profile["reasoning_guard"]:
                greeting_prompt = f"{greeting_prompt}\n{chat_runtime_profile['reasoning_guard']}"
            messages = [
                {"role": "system", "content": greeting_prompt},
                {"role": "user", "content": user_message},
            ]
        else:
            # Always rebuild the prompt gate so the latest memory, discovery context, and continuity rules are fresh.
            has_role_history = bool(history and len(history) > 0 and isinstance(history[0], dict) and 'role' in history[0])
            messages = [{"role": "system", "content": system_prompt}]
            if continuity_context:
                messages.append({"role": "system", "content": continuity_context})

            normalized_history = []
            if has_role_history:
                normalized_history = _compact_chat_role_history(history, limit=context_limit, include_system=False)
            else:
                normalized_history = history[-context_limit:] if context_limit > 0 else []

            for msg in normalized_history:
                if not isinstance(msg, dict):
                    continue
                if has_role_history:
                    messages.append({"role": msg["role"], "content": msg["content"]})
                elif msg.get('type') == 'user':
                    messages.append({"role": "user", "content": msg['content']})
                elif msg.get('type') == 'assistant':
                    messages.append({"role": "assistant", "content": msg['content']})

            if query_plan_context:
                messages.append({"role": "system", "content": query_plan_context})

            messages.append({"role": "user", "content": user_message})

        status_timeline: List[Dict[str, Any]] = []
        await push_status(status_timeline, "🧠 Building investigation plan", 0)
        print(f"🔵 [CHAT] Calling LLM with {len(messages)} messages, max_tokens={chat_runtime_profile['initial_max_tokens']}")
        response = await llm_client.generate_response(
            messages=messages,
            max_tokens=chat_runtime_profile["initial_max_tokens"],
            temperature=runtime_temperature,
        )
        response = response if isinstance(response, str) else str(response or "")
        print(f"🔵 [CHAT] Got response: {len(response)} chars")

        default_earliest, default_latest = extract_time_range_from_message(user_message)
        default_earliest = default_earliest or "-24h"
        default_latest = default_latest or "now"

        def _parse_tool_call(text: str, earliest: str, latest: str) -> Optional[Dict[str, Any]]:
            try:
                parsed = extract_recoverable_tool_call(
                    text,
                    query_tool_name,
                    default_earliest=earliest,
                    default_latest=latest,
                )
            except Exception as parse_error:
                debug_log(f"Error parsing tool call: {parse_error}", "error")
                return None
            if isinstance(parsed, dict) and parsed.get("method") == "tools/call" and isinstance(parsed.get("params"), dict):
                return parsed
            return None

        tool_call = _parse_tool_call(response, default_earliest, default_latest)
        clean_response = sanitize_llm_response_text(response)

        context_request_match = re.search(r'<CONTEXT_REQUEST>(.*?)</CONTEXT_REQUEST>', response, re.DOTALL)
        if context_request_match and not tool_call:
            requested_context_type = context_request_match.group(1).strip()
            formatted_context = ""
            try:
                ctx_mgr = get_context_manager()
                specific_context = ctx_mgr.get_specific_context(requested_context_type)
                if specific_context:
                    formatted_context = ctx_mgr.format_context_for_llm({requested_context_type: specific_context})
            except Exception as context_error:
                debug_log(f"Error loading requested context: {context_error}", "error")
            if formatted_context:
                await push_status(status_timeline, f"📚 Loading {requested_context_type} context", 0)
                messages = messages + [
                    {"role": "assistant", "content": f"<CONTEXT_REQUEST>{requested_context_type}</CONTEXT_REQUEST>"},
                    {
                        "role": "user",
                        "content": (
                            f"[Context loaded: {requested_context_type}]\n{formatted_context}\n\n"
                            "Use this context to answer my request, or make one TOOL_CALL if live data is still needed."
                        ),
                    },
                ]
                response = await llm_client.generate_response(
                    messages=messages,
                    max_tokens=followup_max_tokens,
                    temperature=runtime_temperature,
                )
                response = response if isinstance(response, str) else str(response or "")
                tool_call = _parse_tool_call(response, default_earliest, default_latest)
                clean_response = sanitize_llm_response_text(response)

        if not tool_call and not small_talk and announces_unexecuted_search(clean_response):
            # Models sometimes promise a search without emitting the TOOL_CALL; ask once for the call itself.
            await push_status(status_timeline, "🔁 Asking the model for the search it described", 0)
            nudge_messages = messages + [
                {"role": "assistant", "content": clean_response},
                {"role": "user", "content": UNEXECUTED_SEARCH_NUDGE},
            ]
            nudge_response = await llm_client.generate_response(
                messages=nudge_messages,
                max_tokens=chat_runtime_profile["retry_max_tokens"],
                temperature=runtime_temperature,
            )
            nudge_response = nudge_response if isinstance(nudge_response, str) else str(nudge_response or "")
            nudge_tool_call = _parse_tool_call(nudge_response, default_earliest, default_latest)
            if nudge_tool_call:
                tool_call = nudge_tool_call
                messages = nudge_messages
                clean_response = sanitize_llm_response_text(nudge_response)
            elif sanitize_llm_response_text(nudge_response):
                clean_response = sanitize_llm_response_text(nudge_response)

        if tool_call:
            await push_status(status_timeline, "🛠 Tool plan created", 0)
            conversation_history = list(messages)
            all_tool_calls: List[Dict[str, Any]] = []
            accumulated_insights: List[str] = []
            seen_signatures: Dict[str, int] = {}
            empty_sweeps: Dict[str, int] = {}
            stalled_steps = 0
            iteration = 0
            final_answer = ""
            stop_reason = ""
            fatal_message = ""
            assistant_text = clean_response
            loop_nudged = False

            while tool_call is not None:
                iteration += 1
                if iteration > max_iterations:
                    stop_reason = "max_iterations"
                    break
                if time.time() - request_started_at > max_execution_time:
                    stop_reason = "timeout"
                    break

                params = tool_call.get("params") if isinstance(tool_call.get("params"), dict) else {}
                tool_name = str(params.get("name") or query_tool_name).strip() or query_tool_name
                tool_args = dict(params.get("arguments")) if isinstance(params.get("arguments"), dict) else {}
                query_notes: List[str] = []
                if tool_name in MCP_QUERY_TOOL_NAMES and scope_unscoped_chat_search(tool_args):
                    query_notes.append(UNSCOPED_SEARCH_NOTE)
                    tool_call = {**tool_call, "params": {**params, "name": tool_name, "arguments": tool_args}}
                signature = tool_call_signature(tool_name, tool_args)
                conversation_history.append({
                    "role": "assistant",
                    "content": "\n".join(part for part in (assistant_text, format_tool_call_tag(tool_name, tool_args)) if part),
                })

                sweep_signature = index_agnostic_signature(tool_name, tool_args)
                if signature in seen_signatures or sweep_signature in empty_sweeps:
                    stalled_steps += 1
                    remaining_steps = 0 if stalled_steps >= stall_limit else max(0, max_iterations - iteration)
                    if signature in seen_signatures:
                        skip_reason = (
                            f"not run, because it repeats the tool call from step {seen_signatures[signature]}. "
                            "That result is above."
                        )
                    else:
                        skip_reason = (
                            f"not run, because it repeats the search from step {empty_sweeps[sweep_signature]} with only "
                            "the index changed, and that search found nothing. To check other indexes, search them all in "
                            "one step (index=* OR index=_*) or change the approach."
                        )
                    feedback_lines = [f"TOOL RESULT (step {iteration}): {skip_reason}"]
                    if remaining_steps > 0:
                        feedback_lines.append(
                            f"Answer the user now from the evidence above, or make a different TOOL_CALL ({remaining_steps} tool steps left)."
                        )
                    else:
                        feedback_lines.append("No tool steps are left. Reply to the user now from the evidence above, without a TOOL_CALL.")
                    feedback = "\n".join(feedback_lines)
                else:
                    seen_signatures[signature] = iteration
                    action = "🔍 Querying Splunk" if tool_name in MCP_QUERY_TOOL_NAMES else f"⚙️ Executing {tool_name}"
                    await push_status(status_timeline, action, iteration)
                    print(f"🔄 [Step {iteration}] Executing: {tool_name}")
                    mcp_result = await execute_mcp_tool_call(tool_call, config)
                    outcome = classify_tool_result(mcp_result)
                    if outcome["status"] == "no_data" or outcome.get("zero_counts"):
                        empty_sweeps.setdefault(sweep_signature, iteration)
                    result_summary = summarize_tool_outcome(tool_name, outcome)
                    query_text = tool_args.get("query") if isinstance(tool_args.get("query"), str) else None
                    all_tool_calls.append({
                        "iteration": iteration,
                        "tool": tool_name,
                        "args": tool_args,
                        "spl_query": query_text if tool_name in MCP_QUERY_TOOL_NAMES or query_text else None,
                        "result": mcp_result,
                        "summary": result_summary,
                    })
                    for finding in result_summary.get("findings", []):
                        accumulated_insights.append(f"[Step {iteration}] {finding}")

                    if outcome.get("fatal"):
                        fatal_message = build_fatal_mcp_error_message(outcome.get("status_code"), outcome.get("error", ""))
                        break

                    if outcome["status"] == "error":
                        await push_status(status_timeline, "⚠️ Tool returned an error", iteration)
                    else:
                        await push_status(status_timeline, f"📊 Analyzing {outcome['row_count']} results", iteration)

                    made_progress = outcome["status"] == "data" and not outcome.get("zero_counts")
                    stalled_steps = 0 if made_progress else stalled_steps + 1
                    remaining_steps = max(0, max_iterations - iteration)
                    if stalled_steps >= stall_limit or time.time() - request_started_at > max_execution_time:
                        remaining_steps = 0

                    post_tool_context = ""
                    try:
                        post_tool_context = get_context_manager().get_context_after_tool_call(
                            tool_name=tool_name,
                            tool_args=tool_args,
                            tool_result=mcp_result,
                        ) or ""
                    except Exception as context_error:
                        debug_log(f"Error getting post-tool context: {context_error}", "error")

                    feedback = build_tool_feedback(
                        step=iteration,
                        tool_name=tool_name,
                        args=tool_args,
                        outcome=outcome,
                        evidence_rows=evidence_rows,
                        evidence_chars=evidence_chars,
                        analysis_brief=format_result_summary_for_llm(result_summary) if outcome["status"] == "data" else "",
                        extra_context=str(post_tool_context or ""),
                        explanation_requirement=spl_explanation_requirement,
                        remaining_steps=remaining_steps,
                        notes=query_notes,
                    )

                # Tool results go back as user turns: several providers hoist every system
                # message into the instructions, which would detach results from their call.
                conversation_history.append({"role": "user", "content": feedback})
                await push_status(status_timeline, "🧠 Reviewing results", iteration)
                next_response = await llm_client.generate_response(
                    messages=conversation_history,
                    max_tokens=followup_max_tokens,
                    temperature=runtime_temperature,
                )
                next_response = next_response if isinstance(next_response, str) else str(next_response or "")
                next_tool_call = _parse_tool_call(
                    next_response,
                    str(tool_args.get("earliest_time") or default_earliest),
                    str(tool_args.get("latest_time") or default_latest),
                )
                if next_tool_call is not None and remaining_steps > 0:
                    tool_call = next_tool_call
                    assistant_text = sanitize_llm_response_text(next_response)
                    continue

                final_answer = sanitize_llm_response_text(next_response)
                if next_tool_call is None and remaining_steps > 0 and not loop_nudged and announces_unexecuted_search(final_answer):
                    loop_nudged = True
                    await push_status(status_timeline, "🔁 Asking the model for the search it described", iteration)
                    conversation_history.append({"role": "assistant", "content": final_answer})
                    conversation_history.append({"role": "user", "content": UNEXECUTED_SEARCH_NUDGE})
                    nudge_response = await llm_client.generate_response(
                        messages=conversation_history,
                        max_tokens=chat_runtime_profile["retry_max_tokens"],
                        temperature=runtime_temperature,
                    )
                    nudge_response = nudge_response if isinstance(nudge_response, str) else str(nudge_response or "")
                    nudge_tool_call = _parse_tool_call(
                        nudge_response,
                        str(tool_args.get("earliest_time") or default_earliest),
                        str(tool_args.get("latest_time") or default_latest),
                    )
                    if nudge_tool_call is not None:
                        tool_call = nudge_tool_call
                        assistant_text = sanitize_llm_response_text(nudge_response)
                        continue
                    final_answer = sanitize_llm_response_text(nudge_response) or final_answer
                if next_tool_call is not None:
                    stop_reason = "budget_exhausted"
                tool_call = None

            if fatal_message:
                final_answer = fatal_message
            else:
                needs_final_pass = (
                    not final_answer
                    or announces_unexecuted_search(final_answer)
                    or stop_reason in {"max_iterations", "timeout", "budget_exhausted"}
                    or (requires_spl_explanation and not response_addresses_spl_explanation(final_answer))
                )
                if needs_final_pass:
                    await push_status(status_timeline, "📝 Writing the final answer", len(all_tool_calls))
                    insights_summary = "\n".join(f"  • {item}" for item in accumulated_insights[-8:]) or "  • No tool results were collected."
                    final_prompt = build_final_user_answer_prompt(
                        user_message,
                        insights_summary,
                        require_spl_explanation=requires_spl_explanation,
                    )
                    final_messages = list(conversation_history)
                    if final_messages and final_messages[-1].get("role") == "assistant":
                        final_messages.pop()
                    final_messages.append({"role": "system", "content": final_prompt})
                    final_response = await llm_client.generate_response(
                        messages=final_messages,
                        max_tokens=chat_runtime_profile["final_max_tokens"],
                        temperature=runtime_temperature,
                    )
                    final_text = sanitize_llm_response_text(final_response if isinstance(final_response, str) else str(final_response or ""))
                    if final_text:
                        final_answer = final_text

            user_facing_final_answer = finalize_user_facing_response_text(
                final_answer,
                DEFAULT_TOOL_INVESTIGATION_RESPONSE,
            )
            if not fatal_message and stop_reason in {"max_iterations", "timeout"}:
                if stop_reason == "max_iterations":
                    limit_note = f"I stopped after {len(all_tool_calls)} tool steps (the limit is {max_iterations})."
                else:
                    limit_note = f"I stopped after {int(time.time() - request_started_at)} seconds (the limit is {max_execution_time}s)."
                user_facing_final_answer = f"{user_facing_final_answer}\n\n_{limit_note} Ask me to continue if you need more detail._"

            await push_status(status_timeline, "✅ Finalizing response", len(all_tool_calls))
            primary_spl_query = extract_primary_spl_query(all_tool_calls)
            visualization_spec, capability_usage = augment_capability_usage_with_visualization(all_tool_calls, capability_usage)
            user_facing_final_answer = apply_reusable_query_reference_to_response(
                user_facing_final_answer,
                capability_usage,
                preferred_query=primary_spl_query,
            )
            updated_memory = update_chat_memory(
                chat_session_id,
                user_message,
                all_tool_calls,
                assistant_response=user_facing_final_answer,
                record_user_turn=False,
            )
            follow_on_actions = build_follow_on_actions(
                user_message,
                updated_memory,
                all_tool_calls,
                assistant_response=user_facing_final_answer,
            )
            status_labels = {"error": "error", "data": "success", "no_data": "no_data"}
            return {
                "response": user_facing_final_answer,
                "initial_response": user_message,
                "tool_calls": all_tool_calls,
                "spl_query": primary_spl_query,
                "visualization_spec": visualization_spec,
                "iterations": len(all_tool_calls),
                "execution_time": f"{time.time() - request_started_at:.2f}s",
                "insights": accumulated_insights,
                "status_timeline": status_timeline,
                "reasoning_chain": [
                    {
                        "iteration": index,
                        "tool": call["tool"],
                        "status": status_labels.get(call["summary"].get("status"), "no_data"),
                        "key_finding": (call["summary"].get("findings") or [""])[0],
                    }
                    for index, call in enumerate(all_tool_calls, 1)
                ],
                "stop_reason": stop_reason or ("fatal_error" if fatal_message else "answered"),
                "conversation_history": _build_follow_up_conversation_history(history, user_message, user_facing_final_answer),
                "discovery_age_warning": discovery_age_warning,
                "chat_session_id": chat_session_id,
                "chat_memory": updated_memory,
                "capability_usage": capability_usage,
                "has_follow_on": len(follow_on_actions) > 0,
                "follow_on_actions": follow_on_actions
            }

        await push_status(status_timeline, "✅ Returning direct answer", 0)
        direct_response = finalize_user_facing_response_text(
            clean_response,
            DEFAULT_DIRECT_CHAT_RESPONSE,
        )
        direct_response = apply_reusable_query_reference_to_response(direct_response, capability_usage)
        spl_in_text = extract_suggested_spl_from_answer(direct_response)
        updated_memory = update_chat_memory(
            chat_session_id,
            user_message,
            assistant_response=direct_response,
            record_user_turn=False,
        )
        follow_on_actions = build_follow_on_actions(
            user_message,
            updated_memory,
            assistant_response=direct_response,
        )
        return {
            "response": direct_response,
            "spl_in_text": spl_in_text,
            "status_timeline": status_timeline,
            "iterations": 0,
            "execution_time": f"{time.time() - request_started_at:.2f}s",
            "discovery_age_warning": discovery_age_warning,
            "chat_session_id": chat_session_id,
            "chat_memory": updated_memory,
            "conversation_history": _build_follow_up_conversation_history(history, user_message, direct_response),
            "capability_usage": capability_usage,
            "has_follow_on": len(follow_on_actions) > 0,
            "follow_on_actions": follow_on_actions
        }
    except Exception as e:
        # Log the full error to terminal for debugging
        print(f"ERROR in chat_with_splunk_logic: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"error": f"Chat failed: {str(e)}"}


@app.post("/chat")
async def chat_with_splunk(http_request: Request, request: dict):
    """Handle chat requests (non-streaming version for backward compatibility)."""
    runtime_config = resolve_effective_runtime_config(request=http_request)
    goal_owner = chat_goal_owner(http_request)
    result = await chat_with_splunk_logic(request, status_callback=None, runtime_config=runtime_config, goal_owner=goal_owner)
    record_chat_goal_turn(goal_owner, request, result)
    return result


MCP_QUERY_TOOL_NAMES = frozenset({"splunk_run_query", "run_splunk_query"})
MCP_UNKNOWN_TOOL_SIGNALS = ("tool not found", "unknown tool", "invalid tool", "no such tool", "method not found")


def _looks_like_unknown_tool_error(message: str, code: Any = None) -> bool:
    lowered = str(message or "").lower()
    if code in (-32601, -32004):
        return True
    if any(signal in lowered for signal in MCP_UNKNOWN_TOOL_SIGNALS):
        return True
    return "tool" in lowered and "not found" in lowered


async def execute_mcp_tool_call(tool_call, config):
    """Execute one tools/call request against the MCP server.

    Every caller (the LLM loop, deterministic routes, follow-on actions) goes
    through here, so the read-only SPL check and argument adaptation live here.
    Failures come back as {"error", "detail", "status_code", "fatal"} dicts; tool
    errors reported in-band (result.isError) are returned as-is for the caller
    to classify.
    """
    executed_tool_name = ""
    executed_args: Dict[str, Any] = {}
    try:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        token = getattr(config.mcp, "token", "") or ""
        if token:
            headers["Authorization"] = f"Bearer {token}"
        else:
            debug_log("No MCP token is configured; sending the tool call without Authorization", "warning")

        verify_ssl = bool(getattr(config.mcp, "verify_ssl", False))
        ca_bundle = getattr(config.mcp, "ca_bundle_path", None)
        ssl_verify = ca_bundle if (ca_bundle and verify_ssl) else verify_ssl

        params = tool_call.get("params", {}) if isinstance(tool_call, dict) else {}
        requested_tool_name = str(params.get("name") or "unknown")
        requested_args = params.get("arguments", {}) if isinstance(params.get("arguments"), dict) else {}
        available_tools = await discover_mcp_tools(config)
        resolved_tool_name = resolve_tool_name(requested_tool_name, available_tools)
        default_query_tool_name = resolve_tool_name("splunk_run_query", available_tools)

        if resolved_tool_name not in available_tools:
            if (
                isinstance(requested_args.get("query"), str)
                and requested_args.get("query", "").strip()
                and default_query_tool_name in available_tools
            ):
                debug_log(
                    f"Remapping unavailable tool '{requested_tool_name}' to '{default_query_tool_name}' because it carries a Splunk query",
                    "warning",
                )
                resolved_tool_name = default_query_tool_name
            else:
                available_preview = ", ".join(sorted(available_tools)) if available_tools else "none"
                debug_log(
                    f"Rejected unavailable MCP tool '{requested_tool_name}'. Available tools: {available_preview}",
                    "warning",
                )
                return {
                    "error": f"Requested tool '{requested_tool_name}' is not available",
                    "detail": f"Available tools: {available_preview}",
                    "status_code": 400,
                    "fatal": False,
                }

        def _prepare_arguments(tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
            prepared = normalize_tool_arguments(tool_name, args)
            schema = get_cached_mcp_tool_metadata(config)["schemas"].get(tool_name)
            if isinstance(schema, dict):
                prepared, dropped = adapt_tool_arguments(prepared, schema)
                if dropped:
                    debug_log(f"Dropped arguments not accepted by {tool_name}: {', '.join(dropped)}", "info")
            return prepared

        executed_tool_name = resolved_tool_name
        executed_args = _prepare_arguments(resolved_tool_name, requested_args)

        if executed_tool_name in MCP_QUERY_TOOL_NAMES:
            query_text = executed_args.get("query")
            if not isinstance(query_text, str) or not query_text.strip():
                return {
                    "error": "The search tool needs a non-empty SPL query.",
                    "detail": "No query argument was provided.",
                    "status_code": 400,
                    "fatal": False,
                }
            safety = assess_spl_safety(query_text)
            if not safety.get("allowed"):
                debug_log(f"Blocked SPL before execution: {safety.get('reason')}", "warning")
                return {
                    "error": "Blocked a search that is not read-only",
                    "detail": str(safety.get("reason") or "The query uses a blocked command."),
                    "status_code": 400,
                    "fatal": False,
                    "blocked": True,
                }

        async def _post_tool_call(tool_name: str, args: Dict[str, Any]):
            payload = {
                "jsonrpc": "2.0",
                "id": _next_mcp_request_id(),
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": args},
            }
            async with httpx.AsyncClient(verify=ssl_verify, timeout=_mcp_call_timeout(tool_name)) as client:
                return await client.post(config.mcp.url, json=payload, headers=headers)

        def _decode(response) -> Any:
            try:
                return response.json()
            except Exception:
                return None

        debug_log(f"MCP tools/call {executed_tool_name}", "query", {"tool": executed_tool_name, "arguments": executed_args})
        response = await _post_tool_call(executed_tool_name, executed_args)
        body = _decode(response)
        rpc_error = parse_jsonrpc_error(body)

        unknown_tool_text = ""
        if rpc_error and _looks_like_unknown_tool_error(rpc_error.get("message", ""), rpc_error.get("code")):
            unknown_tool_text = rpc_error.get("message", "")
        elif response.status_code != 200 and body is None and _looks_like_unknown_tool_error(response.text or ""):
            unknown_tool_text = (response.text or "")[:300]

        if unknown_tool_text:
            debug_log(f"Refreshing MCP tools after unknown-tool signal: {unknown_tool_text}", "warning")
            refreshed_tools = await discover_mcp_tools(config, force_refresh=True)
            retried_tool_name = resolve_tool_name(requested_tool_name, refreshed_tools)
            if retried_tool_name != executed_tool_name and retried_tool_name in refreshed_tools:
                executed_tool_name = retried_tool_name
                executed_args = _prepare_arguments(retried_tool_name, requested_args)
                response = await _post_tool_call(executed_tool_name, executed_args)
                body = _decode(response)
                rpc_error = parse_jsonrpc_error(body)

        if response.status_code == 200 and isinstance(body, dict) and rpc_error is None:
            result_obj = body.get("result") if isinstance(body.get("result"), dict) else {}
            if result_obj.get("isError"):
                outcome = classify_tool_result(body)
                maybe_record_rag_spl_query_feedback(
                    executed_tool_name,
                    executed_args,
                    error_payload={"error": "tool error", "detail": outcome.get("error", "")},
                )
            else:
                maybe_record_rag_spl_query_feedback(executed_tool_name, executed_args, mcp_response=body)
            return body

        if rpc_error is not None:
            error_payload = {
                "error": rpc_error.get("message") or "MCP error",
                "detail": f"JSON-RPC error code {rpc_error.get('code')}",
                "status_code": response.status_code,
                "fatal": response.status_code in {401, 403},
            }
            maybe_record_rag_spl_query_feedback(executed_tool_name, executed_args, error_payload=error_payload)
            return error_payload

        error_detail = (response.text or "")[:300] if response.text else "No error details"
        debug_log(f"MCP call failed with HTTP {response.status_code}: {error_detail[:200]}", "error")
        # Auth problems and a missing endpoint will not be fixed by retrying.
        error_payload = {
            "error": f"MCP call failed: {response.status_code}",
            "detail": error_detail,
            "status_code": response.status_code,
            "fatal": response.status_code in {401, 403, 404},
        }
        maybe_record_rag_spl_query_feedback(executed_tool_name, executed_args, error_payload=error_payload)
        return error_payload

    except httpx.TimeoutException as e:
        timeout_seconds = _mcp_call_timeout(executed_tool_name)
        debug_log(f"MCP call timed out after {timeout_seconds:.0f}s: {type(e).__name__}", "error")
        return {
            "error": f"The MCP call timed out after {timeout_seconds:.0f} seconds",
            "detail": "Narrow the time range or aggregate the search, then try again.",
            "status_code": 504,
            "fatal": False,
        }
    except httpx.HTTPError as e:
        debug_log(f"MCP HTTP error: {type(e).__name__} - {e}", "error")
        return {"error": f"HTTP error: {type(e).__name__}", "detail": str(e), "fatal": False}
    except Exception as e:
        debug_log(f"MCP tool call failed: {type(e).__name__} - {e}", "error")
        import traceback
        traceback.print_exc()
        return {"error": f"Failed to execute tool call: {type(e).__name__}", "detail": str(e), "fatal": False}


@app.get("/status")
async def get_status(request: Request):
    """Get current discovery status."""
    _sync_runtime_state_from_disk()
    scope_key = _build_discovery_scope_metadata(request=request).get("scope_key")
    snapshot = _snapshot_discovery_runtime_state(scope_key)
    response: Dict[str, Any] = {
        "status": snapshot.get("status", "idle"),
        "discovery": snapshot,
    }

    if snapshot.get("status") == "error" and snapshot.get("error"):
        response["error"] = snapshot.get("error")
        return response

    if current_discovery_session and current_discovery_session.done() and not current_discovery_session.cancelled():
        try:
            response["result"] = current_discovery_session.result()
        except Exception as exc:
            response["status"] = "error"
            response["error"] = str(exc)

    return response


@app.get("/api/llm/health")
async def get_llm_health():
    """Get LLM endpoint health metrics"""
    try:
        from llm.health_monitor import get_all_health_metrics
        
        metrics = get_all_health_metrics()
        
        if not metrics:
            return {
                "status": "no_data",
                "message": "No LLM requests made yet",
                "endpoints": {}
            }
        
        return {
            "status": "success",
            "endpoints": metrics,
            "summary": {
                "total_endpoints": len(metrics),
                "healthy_count": sum(1 for m in metrics.values() if m["status"] == "healthy"),
                "degraded_count": sum(1 for m in metrics.values() if m["status"] == "degraded"),
                "unhealthy_count": sum(1 for m in metrics.values() if m["status"] == "unhealthy")
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }


@app.get("/")
async def serve_frontend(request: Request):
    """Serve the frontend HTML."""
    if is_auth_enabled():
        auth_provider = get_auth_provider()
        if auth_provider not in {"local_password", "oidc"}:
            return HTMLResponse(
                content=build_auth_error_page("Authentication provider unavailable", "The configured authentication provider is not available in this build."),
                status_code=503,
            )

        current_user = getattr(request.state, "auth_user", None)
        if not isinstance(current_user, dict):
            if auth_provider == "oidc":
                return HTMLResponse(content=build_oidc_login_page(_build_oidc_provider_status()))
            return HTMLResponse(content=build_login_page())
        if auth_provider == "local_password" and bool(current_user.get("require_password_reset")):
            return HTMLResponse(content=build_password_reset_page(str(current_user.get("username", ""))))

    if FRONTEND_INDEX_PATH.exists():
        return FileResponse(FRONTEND_INDEX_PATH)
    return HTMLResponse(content=get_frontend_html())


if __name__ == "__main__":
    import sys
    import io

    def _is_port_available(port: int, host: str = "0.0.0.0") -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            return True
        except OSError:
            return False
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _find_listener_pid_windows(port: int) -> Optional[int]:
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "tcp"],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode != 0:
                return None

            for line in result.stdout.splitlines():
                normalized = " ".join(line.split())
                if not normalized:
                    continue
                if f":{port}" not in normalized:
                    continue
                if "LISTENING" not in normalized.upper():
                    continue

                parts = normalized.split(" ")
                if len(parts) < 5:
                    continue

                try:
                    return int(parts[-1])
                except ValueError:
                    continue
        except Exception:
            return None
        return None

    def _get_process_commandline_windows(pid: int) -> str:
        try:
            ps_command = (
                f"$p = Get-CimInstance Win32_Process -Filter \"ProcessId = {pid}\"; "
                f"if ($p) {{ $p.CommandLine }}"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=False
            )
            if result.returncode != 0:
                return ""
            return (result.stdout or "").strip()
        except Exception:
            return ""

    def _is_safe_tool_owned_process(pid: int, workspace_root: str) -> bool:
        if pid <= 0:
            return False
        try:
            if pid == os.getpid():
                return False
        except Exception:
            pass

        cmdline = _get_process_commandline_windows(pid).lower().replace("\\", "/")
        if not cmdline:
            return False

        workspace_norm = workspace_root.lower().replace("\\", "/")
        return ("web_app.py" in cmdline) and (workspace_norm in cmdline)

    def _try_reclaim_preferred_port_windows(port: int, workspace_root: str) -> bool:
        listener_pid = _find_listener_pid_windows(port)
        if listener_pid is None:
            return False

        if not _is_safe_tool_owned_process(listener_pid, workspace_root):
            return False

        try:
            os.kill(listener_pid, 9)
            time.sleep(0.35)
            return _is_port_available(port)
        except Exception:
            return False

    def _resolve_startup_port(preferred_port: int = 8003, max_scan_ports: int = 20) -> int:
        workspace_root = str(Path(__file__).resolve().parent.parent)

        if _is_port_available(preferred_port):
            return preferred_port

        if sys.platform == "win32":
            reclaimed = _try_reclaim_preferred_port_windows(preferred_port, workspace_root)
            if reclaimed and _is_port_available(preferred_port):
                return preferred_port

        for candidate in range(preferred_port + 1, preferred_port + max_scan_ports + 1):
            if _is_port_available(candidate):
                return candidate

        raise RuntimeError(
            f"No open TCP port found in range {preferred_port}-{preferred_port + max_scan_ports}. "
            f"Please free a port and retry."
        )
    
    # Fix encoding issues on Windows
    if sys.platform == 'win32':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    startup_port = _resolve_startup_port(preferred_port=8003)
    if startup_port != 8003:
        print(f"Preferred port 8003 unavailable; using fallback port {startup_port}.")
    
    print("Starting the Splunk Discovery Tool web interface")
    print(f"Access the interface at: http://localhost:{startup_port}")
    print(f"WebSocket endpoint: ws://localhost:{startup_port}/ws")
    
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=startup_port,
        log_level="info",
        reload=False  # Set to True for development
    )
