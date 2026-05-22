"""Local security store and auth/session helpers for DT4SMS."""

import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError


BOOTSTRAP_ADMIN_USERNAME = "admin"
BOOTSTRAP_ADMIN_PASSWORD = "password"
ALLOWED_USER_ROLES = {"admin", "analyst", "viewer"}
ALLOWED_ACCESS_TOKEN_TYPES = {"external_api", "inbound_mcp"}
ALLOWED_ACCESS_TOKEN_SCOPES = {"rag:search", "rag:assets:read", "mcp:tools:read", "admin:tokens"}
UNSET = object()


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize_username(username: Any) -> str:
    return str(username or "").strip().lower()


def _normalize_role(role: Any) -> str:
    normalized_role = str(role or "").strip().lower()
    if normalized_role not in ALLOWED_USER_ROLES:
        raise ValueError(f"Role must be one of: {', '.join(sorted(ALLOWED_USER_ROLES))}")
    return normalized_role


def _normalize_assignment_name(mcp_config_name: Any) -> Optional[str]:
    cleaned = str(mcp_config_name or "").strip()
    return cleaned or None


def _normalize_auth_provider(provider: Any) -> str:
    cleaned = str(provider or "").strip().lower()
    if not cleaned:
        raise ValueError("auth_provider is required")
    return cleaned


def _normalize_external_subject(subject: Any) -> str:
    cleaned = str(subject or "").strip()
    if not cleaned:
        raise ValueError("External subject is required")
    return cleaned


def _normalize_optional_email(email: Any) -> Optional[str]:
    cleaned = str(email or "").strip().lower()
    return cleaned or None


def _normalize_external_username_candidate(value: Any) -> str:
    raw_value = str(value or "").strip().lower()
    if not raw_value:
        return ""

    cleaned_chars: List[str] = []
    last_was_separator = False
    for char in raw_value:
        if char.isalnum() or char in {".", "_", "-"}:
            cleaned_chars.append(char)
            last_was_separator = False
            continue
        if char in {" ", "@", "/", "\\", ":"}:
            if not last_was_separator:
                cleaned_chars.append("-")
                last_was_separator = True

    return "".join(cleaned_chars).strip(".-_")


def _session_token_hash(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _access_token_hash(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def _normalize_token_type(token_type: Any) -> str:
    normalized_type = str(token_type or "external_api").strip().lower()
    if normalized_type not in ALLOWED_ACCESS_TOKEN_TYPES:
        raise ValueError(f"Token type must be one of: {', '.join(sorted(ALLOWED_ACCESS_TOKEN_TYPES))}")
    return normalized_type


def _normalize_token_scopes(scopes: Any, allow_empty: bool = False) -> List[str]:
    if isinstance(scopes, str):
        candidate_scopes = [scope.strip() for scope in scopes.split(",")]
    elif isinstance(scopes, list):
        candidate_scopes = [str(scope or "").strip() for scope in scopes]
    else:
        candidate_scopes = []

    normalized_scopes: List[str] = []
    seen = set()
    for scope in candidate_scopes:
        normalized_scope = str(scope or "").strip().lower()
        if not normalized_scope:
            continue
        if normalized_scope not in ALLOWED_ACCESS_TOKEN_SCOPES:
            raise ValueError(f"Unsupported token scope: {normalized_scope}")
        if normalized_scope in seen:
            continue
        seen.add(normalized_scope)
        normalized_scopes.append(normalized_scope)

    if not normalized_scopes and not allow_empty:
        raise ValueError("At least one token scope is required")
    return normalized_scopes


def _row_to_user(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    return {
        "id": int(row["id"]),
        "username": str(row["username"]),
        "role": str(row["role"]),
        "is_enabled": bool(row["is_enabled"]),
        "require_password_reset": bool(row["require_password_reset"]),
        "mcp_config_name": row["mcp_config_name"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_login_at": row["last_login_at"],
    }


def _row_to_access_token(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None

    try:
        scopes = json.loads(str(row["scopes_json"] or "[]"))
    except json.JSONDecodeError:
        scopes = []

    return {
        "id": int(row["id"]),
        "name": str(row["name"]),
        "token_type": str(row["token_type"]),
        "token_prefix": str(row["token_prefix"]),
        "owner_user_id": int(row["owner_user_id"]) if row["owner_user_id"] is not None else None,
        "owner_username": row["owner_username"],
        "created_by_user_id": int(row["created_by_user_id"]) if row["created_by_user_id"] is not None else None,
        "created_by_username": row["created_by_username"],
        "scopes": [str(scope) for scope in scopes if str(scope or "").strip()],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "expires_at": row["expires_at"],
        "revoked_at": row["revoked_at"],
        "last_used_at": row["last_used_at"],
        "last_used_from": row["last_used_from"],
        "use_count": int(row["use_count"] or 0),
    }


def _row_to_external_identity(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None

    try:
        claims = json.loads(str(row["claims_json"] or "{}"))
    except json.JSONDecodeError:
        claims = {}

    return {
        "id": int(row["id"]),
        "auth_provider": str(row["auth_provider"]),
        "subject": str(row["subject"]),
        "user_id": int(row["user_id"]),
        "email": row["email"],
        "claims": claims,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "last_login_at": row["last_login_at"],
        "user": {
            "id": int(row["user_id"]),
            "username": str(row["username"]),
            "role": str(row["role"]),
            "is_enabled": bool(row["is_enabled"]),
            "require_password_reset": bool(row["require_password_reset"]),
            "mcp_config_name": row["mcp_config_name"],
        },
    }


class SecurityManager:
    """Persist local auth users and sessions in a dedicated SQLite store."""

    def __init__(self, db_path: str = "security.db"):
        self.db_path = Path(db_path)
        self.password_hasher = PasswordHasher()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _managed_connection(self):
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _init_db(self) -> None:
        with self._managed_connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_enabled INTEGER NOT NULL DEFAULT 1,
                    require_password_reset INTEGER NOT NULL DEFAULT 0,
                    mcp_config_name TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_hash TEXT NOT NULL UNIQUE,
                    user_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    username TEXT,
                    user_id INTEGER,
                    details_json TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS access_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    token_prefix TEXT NOT NULL,
                    token_type TEXT NOT NULL,
                    owner_user_id INTEGER,
                    created_by_user_id INTEGER,
                    scopes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT,
                    revoked_at TEXT,
                    last_used_at TEXT,
                    last_used_from TEXT,
                    use_count INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL,
                    FOREIGN KEY(created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS external_identities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    auth_provider TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    email TEXT,
                    claims_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login_at TEXT,
                    UNIQUE(auth_provider, subject),
                    UNIQUE(auth_provider, user_id),
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                """
            )

    def record_audit_event(
        self,
        event_type: str,
        username: Optional[str] = None,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload = json.dumps(details or {}, sort_keys=True)
        with self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO audit_events (event_type, username, user_id, details_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_type, _normalize_username(username) or None, user_id, payload, _utcnow_iso()),
            )

    def count_users(self) -> int:
        with self._managed_connection() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return int(row["count"] if row else 0)

    def count_enabled_admin_users(self) -> int:
        with self._managed_connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND is_enabled = 1"
            ).fetchone()
        return int(row["count"] if row else 0)

    def list_users(self) -> List[Dict[str, Any]]:
        with self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT id, username, role, is_enabled, require_password_reset, mcp_config_name,
                       created_at, updated_at, last_login_at
                FROM users
                ORDER BY username ASC
                """
            ).fetchall()
        return [_row_to_user(row) for row in rows if _row_to_user(row) is not None]

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        normalized_username = _normalize_username(username)
        if not normalized_username:
            return None
        with self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT id, username, role, is_enabled, require_password_reset, mcp_config_name,
                       created_at, updated_at, last_login_at
                FROM users
                WHERE username = ?
                """,
                (normalized_username,),
            ).fetchone()
        return _row_to_user(row)

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT id, username, role, is_enabled, require_password_reset, mcp_config_name,
                       created_at, updated_at, last_login_at
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
        return _row_to_user(row)

    def get_external_identity(self, auth_provider: Any, subject: Any) -> Optional[Dict[str, Any]]:
        normalized_provider = _normalize_auth_provider(auth_provider)
        normalized_subject = _normalize_external_subject(subject)

        with self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT ei.id, ei.auth_provider, ei.subject, ei.user_id, ei.email,
                       ei.claims_json, ei.created_at, ei.updated_at, ei.last_login_at,
                       u.username, u.role, u.is_enabled, u.require_password_reset, u.mcp_config_name
                FROM external_identities ei
                JOIN users u ON u.id = ei.user_id
                WHERE ei.auth_provider = ? AND ei.subject = ?
                """,
                (normalized_provider, normalized_subject),
            ).fetchone()

        return _row_to_external_identity(row)

    def get_external_identity_for_user(self, auth_provider: Any, user_id: int) -> Optional[Dict[str, Any]]:
        normalized_provider = _normalize_auth_provider(auth_provider)

        with self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT ei.id, ei.auth_provider, ei.subject, ei.user_id, ei.email,
                       ei.claims_json, ei.created_at, ei.updated_at, ei.last_login_at,
                       u.username, u.role, u.is_enabled, u.require_password_reset, u.mcp_config_name
                FROM external_identities ei
                JOIN users u ON u.id = ei.user_id
                WHERE ei.auth_provider = ? AND ei.user_id = ?
                """,
                (normalized_provider, user_id),
            ).fetchone()

        return _row_to_external_identity(row)

    def link_external_identity(
        self,
        user_id: int,
        auth_provider: Any,
        subject: Any,
        email: Optional[str] = None,
        claims: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        user = self.get_user_by_id(int(user_id))
        if user is None:
            raise ValueError("User not found")

        normalized_provider = _normalize_auth_provider(auth_provider)
        normalized_subject = _normalize_external_subject(subject)
        normalized_email = _normalize_optional_email(email)
        identity_claims = claims if isinstance(claims, dict) else {}

        existing_identity = self.get_external_identity(normalized_provider, normalized_subject)
        if existing_identity is not None and int(existing_identity["user_id"]) != int(user_id):
            raise ValueError("External identity is already linked to a different user")

        existing_user_identity = self.get_external_identity_for_user(normalized_provider, int(user_id))
        if existing_user_identity is not None and str(existing_user_identity["subject"]) != normalized_subject:
            raise ValueError(f"User already has a linked {normalized_provider} identity")

        now = _utcnow_iso()
        with self._managed_connection() as connection:
            if existing_identity is None:
                connection.execute(
                    """
                    INSERT INTO external_identities (
                        auth_provider, subject, user_id, email, claims_json,
                        created_at, updated_at, last_login_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (
                        normalized_provider,
                        normalized_subject,
                        int(user_id),
                        normalized_email,
                        json.dumps(identity_claims, sort_keys=True),
                        now,
                        now,
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE external_identities
                    SET email = ?, claims_json = ?, updated_at = ?
                    WHERE auth_provider = ? AND subject = ?
                    """,
                    (
                        normalized_email,
                        json.dumps(identity_claims, sort_keys=True),
                        now,
                        normalized_provider,
                        normalized_subject,
                    ),
                )
            connection.execute("UPDATE users SET updated_at = ? WHERE id = ?", (now, int(user_id)))

        self.record_audit_event(
            "external_identity_linked",
            username=user.get("username"),
            user_id=int(user_id),
            details={
                "auth_provider": normalized_provider,
                "subject": normalized_subject,
                "linked_existing_user": True,
                "admin_link": True,
            },
        )
        return self.get_user_by_id(int(user_id)) or user

    def _generate_unique_external_username(
        self,
        preferred_username: Any,
        email: Optional[str],
        auth_provider: str,
        subject: str,
    ) -> str:
        candidate_values = [
            preferred_username,
            str(email or "").split("@", 1)[0] if email else None,
            f"{auth_provider}-{subject[:12]}",
        ]

        base_username = ""
        for candidate in candidate_values:
            normalized_candidate = _normalize_external_username_candidate(candidate)
            if normalized_candidate:
                base_username = normalized_candidate
                break

        if not base_username:
            base_username = "oidc-user"

        username = base_username
        suffix = 2
        while self.get_user_by_username(username) is not None:
            username = f"{base_username}-{suffix}"
            suffix += 1
        return username

    def resolve_or_provision_external_user(
        self,
        auth_provider: Any,
        subject: Any,
        preferred_username: Any,
        email: Optional[str] = None,
        role: str = "viewer",
        mcp_config_name: Optional[str] = None,
        claims: Optional[Dict[str, Any]] = None,
        sync_role: bool = True,
        sync_mcp_config_name: bool = True,
    ) -> Dict[str, Any]:
        normalized_provider = _normalize_auth_provider(auth_provider)
        normalized_subject = _normalize_external_subject(subject)
        normalized_role = _normalize_role(role)
        normalized_email = _normalize_optional_email(email)
        assignment_name = _normalize_assignment_name(mcp_config_name)
        normalized_username = _normalize_username(preferred_username)
        identity_claims = claims if isinstance(claims, dict) else {}

        existing_identity = self.get_external_identity(normalized_provider, normalized_subject)
        if existing_identity is not None:
            user = self.get_user_by_id(int(existing_identity["user_id"]))
            if user is None:
                raise ValueError("External identity mapping exists without a user record")

            update_kwargs: Dict[str, Any] = {}
            if sync_role and user.get("role") != normalized_role:
                update_kwargs["role"] = normalized_role
            if sync_mcp_config_name and user.get("mcp_config_name") != assignment_name:
                update_kwargs["mcp_config_name"] = assignment_name

            if update_kwargs:
                updated_user = self.update_user(int(user["id"]), **update_kwargs)
                if updated_user is not None:
                    user = updated_user

            now = _utcnow_iso()
            with self._managed_connection() as connection:
                connection.execute(
                    """
                    UPDATE external_identities
                    SET email = ?, claims_json = ?, updated_at = ?, last_login_at = ?
                    WHERE auth_provider = ? AND subject = ?
                    """,
                    (
                        normalized_email,
                        json.dumps(identity_claims, sort_keys=True),
                        now,
                        now,
                        normalized_provider,
                        normalized_subject,
                    ),
                )
                connection.execute(
                    "UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?",
                    (now, now, int(user["id"])),
                )

            self.record_audit_event(
                "external_identity_authenticated",
                username=user.get("username"),
                user_id=int(user["id"]),
                details={"auth_provider": normalized_provider, "subject": normalized_subject, "linked": True},
            )
            return self.get_user_by_id(int(user["id"])) or user

        existing_username_owner = self.get_user_by_username(normalized_username) if normalized_username else None
        linked_user = self.create_user(
            username=self._generate_unique_external_username(
                preferred_username=preferred_username,
                email=normalized_email,
                auth_provider=normalized_provider,
                subject=normalized_subject,
            ),
            password=secrets.token_urlsafe(32),
            role=normalized_role,
            is_enabled=True,
            require_password_reset=False,
            mcp_config_name=assignment_name,
        )

        now = _utcnow_iso()
        try:
            with self._managed_connection() as connection:
                connection.execute(
                    """
                    INSERT INTO external_identities (
                        auth_provider, subject, user_id, email, claims_json,
                        created_at, updated_at, last_login_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_provider,
                        normalized_subject,
                        int(linked_user["id"]),
                        normalized_email,
                        json.dumps(identity_claims, sort_keys=True),
                        now,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    "UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?",
                    (now, now, int(linked_user["id"])),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("External identity is already linked to a different user") from exc

        self.record_audit_event(
            "external_identity_linked",
            username=linked_user.get("username"),
            user_id=int(linked_user["id"]),
            details={
                "auth_provider": normalized_provider,
                "subject": normalized_subject,
                "linked_existing_user": False,
                "username_collision": existing_username_owner is not None,
            },
        )
        self.record_audit_event(
            "external_identity_authenticated",
            username=linked_user.get("username"),
            user_id=int(linked_user["id"]),
            details={"auth_provider": normalized_provider, "subject": normalized_subject, "linked": False},
        )
        return self.get_user_by_id(int(linked_user["id"])) or linked_user

    def ensure_bootstrap_admin(
        self,
        require_password_reset: bool = True,
        default_username: str = BOOTSTRAP_ADMIN_USERNAME,
        default_password: str = BOOTSTRAP_ADMIN_PASSWORD,
    ) -> Dict[str, Any]:
        normalized_username = _normalize_username(default_username)
        if self.count_enabled_admin_users() > 0:
            return {"created": False, "username": normalized_username}

        candidate_username = normalized_username or BOOTSTRAP_ADMIN_USERNAME
        suffix = 2
        while self.get_user_by_username(candidate_username) is not None:
            candidate_username = f"{normalized_username or BOOTSTRAP_ADMIN_USERNAME}{suffix}"
            suffix += 1

        now = _utcnow_iso()
        password_hash = self.password_hasher.hash(default_password)
        with self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO users (
                    username, password_hash, role, is_enabled, require_password_reset,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    candidate_username,
                    password_hash,
                    "admin",
                    1,
                    1 if require_password_reset else 0,
                    now,
                    now,
                ),
            )
        self.record_audit_event(
            "bootstrap_admin_created",
            username=candidate_username,
            details={"require_password_reset": bool(require_password_reset)},
        )
        return {"created": True, "username": candidate_username}

    def _assert_not_last_enabled_admin(self, current_user: Dict[str, Any], next_role: str, next_is_enabled: bool) -> None:
        if current_user.get("role") != "admin":
            return
        if next_role == "admin" and next_is_enabled:
            return
        if self.count_enabled_admin_users() <= 1:
            raise ValueError("At least one enabled admin user is required")

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "analyst",
        is_enabled: bool = True,
        require_password_reset: bool = True,
        mcp_config_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        normalized_username = _normalize_username(username)
        if not normalized_username:
            raise ValueError("Username is required")
        if not str(password or ""):
            raise ValueError("Password is required")
        normalized_role = _normalize_role(role)
        assignment_name = _normalize_assignment_name(mcp_config_name)
        now = _utcnow_iso()
        password_hash = self.password_hasher.hash(str(password or ""))

        try:
            with self._managed_connection() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO users (
                        username, password_hash, role, is_enabled, require_password_reset,
                        mcp_config_name, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_username,
                        password_hash,
                        normalized_role,
                        1 if is_enabled else 0,
                        1 if require_password_reset else 0,
                        assignment_name,
                        now,
                        now,
                    ),
                )
                user_id = int(cursor.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username already exists") from exc

        self.record_audit_event(
            "user_created",
            username=normalized_username,
            user_id=user_id,
            details={"role": normalized_role, "mcp_config_name": assignment_name},
        )
        user = self.get_user_by_id(user_id)
        if user is None:
            raise ValueError("User was created but could not be reloaded")
        return user

    def revoke_sessions_for_user(self, user_id: int) -> int:
        with self._managed_connection() as connection:
            result = connection.execute(
                "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
                (_utcnow_iso(), user_id),
            )
        return int(result.rowcount or 0)

    def update_user(
        self,
        user_id: int,
        username: Any = UNSET,
        role: Any = UNSET,
        is_enabled: Any = UNSET,
        require_password_reset: Any = UNSET,
        mcp_config_name: Any = UNSET,
        new_password: Any = UNSET,
    ) -> Optional[Dict[str, Any]]:
        current_user = self.get_user_by_id(user_id)
        if current_user is None:
            return None

        next_role = current_user["role"] if role is UNSET else _normalize_role(role)
        next_is_enabled = bool(current_user["is_enabled"] if is_enabled is UNSET else is_enabled)
        self._assert_not_last_enabled_admin(current_user, next_role, next_is_enabled)

        updates: List[str] = []
        params: List[Any] = []
        changed_fields: Dict[str, Any] = {}

        if username is not UNSET:
            normalized_username = _normalize_username(username)
            if not normalized_username:
                raise ValueError("Username is required")
            updates.append("username = ?")
            params.append(normalized_username)
            changed_fields["username"] = normalized_username

        if role is not UNSET:
            updates.append("role = ?")
            params.append(next_role)
            changed_fields["role"] = next_role

        if is_enabled is not UNSET:
            updates.append("is_enabled = ?")
            params.append(1 if next_is_enabled else 0)
            changed_fields["is_enabled"] = next_is_enabled

        if require_password_reset is not UNSET:
            reset_required = bool(require_password_reset)
            updates.append("require_password_reset = ?")
            params.append(1 if reset_required else 0)
            changed_fields["require_password_reset"] = reset_required

        if mcp_config_name is not UNSET:
            assignment_name = _normalize_assignment_name(mcp_config_name)
            updates.append("mcp_config_name = ?")
            params.append(assignment_name)
            changed_fields["mcp_config_name"] = assignment_name

        if new_password is not UNSET:
            if not str(new_password or ""):
                raise ValueError("Password is required")
            updates.append("password_hash = ?")
            params.append(self.password_hasher.hash(str(new_password or "")))
            changed_fields["password_updated"] = True

        if not updates:
            return current_user

        updates.append("updated_at = ?")
        params.append(_utcnow_iso())
        params.append(user_id)

        try:
            with self._managed_connection() as connection:
                connection.execute(
                    f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
                    tuple(params),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username already exists") from exc

        if is_enabled is not UNSET and not next_is_enabled:
            revoked_count = self.revoke_sessions_for_user(user_id)
            changed_fields["revoked_sessions"] = revoked_count

        self.record_audit_event(
            "user_updated",
            username=current_user.get("username"),
            user_id=user_id,
            details=changed_fields,
        )
        return self.get_user_by_id(user_id)

    def delete_user(self, user_id: int) -> bool:
        current_user = self.get_user_by_id(user_id)
        if current_user is None:
            return False

        self._assert_not_last_enabled_admin(current_user, current_user["role"], False)
        with self._managed_connection() as connection:
            result = connection.execute("DELETE FROM users WHERE id = ?", (user_id,))

        deleted = result.rowcount > 0
        if deleted:
            self.record_audit_event(
                "user_deleted",
                username=current_user.get("username"),
                user_id=user_id,
                details={"role": current_user.get("role")},
            )
        return deleted

    def _get_user_auth_row(self, username: str) -> Optional[sqlite3.Row]:
        normalized_username = _normalize_username(username)
        if not normalized_username:
            return None
        with self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT id, username, password_hash, role, is_enabled, require_password_reset,
                       mcp_config_name, created_at, updated_at, last_login_at
                FROM users
                WHERE username = ?
                """,
                (normalized_username,),
            ).fetchone()
        return row

    def verify_user_password(self, user_id: int, password: str) -> bool:
        with self._managed_connection() as connection:
            row = connection.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
        if row is None:
            return False

        try:
            return bool(self.password_hasher.verify(str(row["password_hash"]), str(password or "")))
        except (VerifyMismatchError, InvalidHash):
            return False

    def authenticate_local_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        row = self._get_user_auth_row(username)
        normalized_username = _normalize_username(username)
        if row is None or not bool(row["is_enabled"]):
            self.record_audit_event("login_failed", username=normalized_username, details={"reason": "user_missing_or_disabled"})
            return None

        try:
            verified = self.password_hasher.verify(str(row["password_hash"]), str(password or ""))
        except (VerifyMismatchError, InvalidHash):
            self.record_audit_event("login_failed", username=normalized_username, user_id=int(row["id"]), details={"reason": "invalid_password"})
            return None

        if not verified:
            self.record_audit_event("login_failed", username=normalized_username, user_id=int(row["id"]), details={"reason": "invalid_password"})
            return None

        new_hash = None
        if self.password_hasher.check_needs_rehash(str(row["password_hash"])):
            new_hash = self.password_hasher.hash(str(password or ""))

        now = _utcnow_iso()
        with self._managed_connection() as connection:
            if new_hash:
                connection.execute(
                    "UPDATE users SET password_hash = ?, last_login_at = ?, updated_at = ? WHERE id = ?",
                    (new_hash, now, now, int(row["id"])),
                )
            else:
                connection.execute(
                    "UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?",
                    (now, now, int(row["id"])),
                )

        self.record_audit_event("login_succeeded", username=normalized_username, user_id=int(row["id"]))
        return self.get_user_by_id(int(row["id"]))

    def create_session(self, user_id: int, timeout_minutes: int = 480) -> Dict[str, Any]:
        session_token = secrets.token_urlsafe(32)
        created_at = _utcnow_iso()
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=max(1, int(timeout_minutes or 1)))).replace(microsecond=0).isoformat()

        with self._managed_connection() as connection:
            connection.execute(
                """
                INSERT INTO sessions (session_hash, user_id, created_at, last_seen_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (_session_token_hash(session_token), user_id, created_at, created_at, expires_at),
            )

        self.record_audit_event("session_created", user_id=user_id)
        return {"session_token": session_token, "expires_at": expires_at}

    def resolve_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        if not str(session_token or "").strip():
            return None

        now = _utcnow_iso()
        session_hash = _session_token_hash(session_token)
        with self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT u.id, u.username, u.role, u.is_enabled, u.require_password_reset,
                       u.mcp_config_name, u.created_at, u.updated_at, u.last_login_at,
                       s.expires_at
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.session_hash = ?
                  AND s.revoked_at IS NULL
                  AND s.expires_at > ?
                  AND u.is_enabled = 1
                """,
                (session_hash, now),
            ).fetchone()

            if row is None:
                return None

            connection.execute(
                "UPDATE sessions SET last_seen_at = ? WHERE session_hash = ?",
                (now, session_hash),
            )

        user = _row_to_user(row)
        if user is None:
            return None
        user["session_expires_at"] = row["expires_at"]
        return user

    def revoke_session(self, session_token: str) -> bool:
        if not str(session_token or "").strip():
            return False

        with self._managed_connection() as connection:
            result = connection.execute(
                "UPDATE sessions SET revoked_at = ? WHERE session_hash = ? AND revoked_at IS NULL",
                (_utcnow_iso(), _session_token_hash(session_token)),
            )

        revoked = result.rowcount > 0
        if revoked:
            self.record_audit_event("session_revoked")
        return revoked

    def update_password(self, user_id: int, new_password: str, require_password_reset: bool = False) -> bool:
        now = _utcnow_iso()
        password_hash = self.password_hasher.hash(str(new_password or ""))
        with self._managed_connection() as connection:
            result = connection.execute(
                """
                UPDATE users
                SET password_hash = ?, require_password_reset = ?, updated_at = ?
                WHERE id = ?
                """,
                (password_hash, 1 if require_password_reset else 0, now, user_id),
            )

        updated = result.rowcount > 0
        if updated:
            self.record_audit_event("password_updated", user_id=user_id, details={"require_password_reset": bool(require_password_reset)})
        return updated

    def _normalize_token_expiry(self, expires_at: Any = None, expires_in_days: Any = None) -> Optional[str]:
        if expires_at not in (None, "") and expires_in_days not in (None, ""):
            raise ValueError("Provide either expires_at or expires_in_days, not both")

        if expires_in_days not in (None, ""):
            try:
                days = int(expires_in_days)
            except (TypeError, ValueError) as exc:
                raise ValueError("expires_in_days must be an integer") from exc
            if days < 1:
                raise ValueError("expires_in_days must be at least 1")
            return (datetime.now(timezone.utc) + timedelta(days=days)).replace(microsecond=0).isoformat()

        if expires_at in (None, ""):
            return None

        try:
            parsed = datetime.fromisoformat(str(expires_at).strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("expires_at must be a valid ISO-8601 timestamp") from exc

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        parsed = parsed.astimezone(timezone.utc).replace(microsecond=0)
        if parsed <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
        return parsed.isoformat()

    def _assert_existing_user_id(self, user_id: Optional[int], field_name: str) -> Optional[int]:
        if user_id is None:
            return None
        normalized_user_id = int(user_id)
        if self.get_user_by_id(normalized_user_id) is None:
            raise ValueError(f"{field_name} does not reference an existing user")
        return normalized_user_id

    def _get_access_token_row_by_id(self, token_id: int) -> Optional[sqlite3.Row]:
        with self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT t.id, t.name, t.token_hash, t.token_prefix, t.token_type, t.owner_user_id,
                       owner.username AS owner_username,
                       t.created_by_user_id, creator.username AS created_by_username,
                       t.scopes_json, t.created_at, t.updated_at, t.expires_at, t.revoked_at,
                       t.last_used_at, t.last_used_from, t.use_count
                FROM access_tokens t
                LEFT JOIN users owner ON owner.id = t.owner_user_id
                LEFT JOIN users creator ON creator.id = t.created_by_user_id
                WHERE t.id = ?
                """,
                (int(token_id),),
            ).fetchone()
        return row

    def get_access_token(self, token_id: int) -> Optional[Dict[str, Any]]:
        return _row_to_access_token(self._get_access_token_row_by_id(token_id))

    def list_access_tokens(self) -> List[Dict[str, Any]]:
        with self._managed_connection() as connection:
            rows = connection.execute(
                """
                SELECT t.id, t.name, t.token_hash, t.token_prefix, t.token_type, t.owner_user_id,
                       owner.username AS owner_username,
                       t.created_by_user_id, creator.username AS created_by_username,
                       t.scopes_json, t.created_at, t.updated_at, t.expires_at, t.revoked_at,
                       t.last_used_at, t.last_used_from, t.use_count
                FROM access_tokens t
                LEFT JOIN users owner ON owner.id = t.owner_user_id
                LEFT JOIN users creator ON creator.id = t.created_by_user_id
                ORDER BY t.created_at DESC, t.id DESC
                """
            ).fetchall()
        return [_row_to_access_token(row) for row in rows if _row_to_access_token(row) is not None]

    def issue_access_token(
        self,
        name: str,
        scopes: Any,
        token_type: str = "external_api",
        owner_user_id: Optional[int] = None,
        created_by_user_id: Optional[int] = None,
        expires_at: Any = None,
        expires_in_days: Any = None,
    ) -> Dict[str, Any]:
        normalized_name = str(name or "").strip()
        if not normalized_name:
            raise ValueError("Token name is required")

        normalized_type = _normalize_token_type(token_type)
        normalized_scopes = _normalize_token_scopes(scopes)
        normalized_owner_user_id = self._assert_existing_user_id(owner_user_id, "owner_user_id")
        normalized_created_by_user_id = self._assert_existing_user_id(created_by_user_id, "created_by_user_id")
        normalized_expires_at = self._normalize_token_expiry(expires_at=expires_at, expires_in_days=expires_in_days)

        access_token = f"dt4sms_{secrets.token_urlsafe(32)}"
        token_prefix = access_token[:18]
        now = _utcnow_iso()

        with self._managed_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO access_tokens (
                    name, token_hash, token_prefix, token_type, owner_user_id, created_by_user_id,
                    scopes_json, created_at, updated_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized_name,
                    _access_token_hash(access_token),
                    token_prefix,
                    normalized_type,
                    normalized_owner_user_id,
                    normalized_created_by_user_id,
                    json.dumps(normalized_scopes, sort_keys=True),
                    now,
                    now,
                    normalized_expires_at,
                ),
            )
            token_id = int(cursor.lastrowid)

        token_record = self.get_access_token(token_id)
        self.record_audit_event(
            "access_token_issued",
            user_id=normalized_created_by_user_id,
            details={
                "token_id": token_id,
                "token_type": normalized_type,
                "owner_user_id": normalized_owner_user_id,
                "scopes": normalized_scopes,
                "expires_at": normalized_expires_at,
            },
        )
        return {"access_token": access_token, "token": token_record}

    def resolve_access_token(
        self,
        access_token: str,
        required_scopes: Optional[Any] = None,
        token_type: Optional[str] = None,
        used_from: Optional[str] = None,
        record_usage: bool = True,
    ) -> Optional[Dict[str, Any]]:
        normalized_token = str(access_token or "").strip()
        if not normalized_token:
            return None

        normalized_required_scopes = _normalize_token_scopes(required_scopes, allow_empty=True)
        normalized_token_type = _normalize_token_type(token_type) if token_type else None
        now = _utcnow_iso()

        with self._managed_connection() as connection:
            row = connection.execute(
                """
                SELECT t.id, t.name, t.token_hash, t.token_prefix, t.token_type, t.owner_user_id,
                       owner.username AS owner_username,
                       owner.is_enabled AS owner_is_enabled,
                       t.created_by_user_id, creator.username AS created_by_username,
                       t.scopes_json, t.created_at, t.updated_at, t.expires_at, t.revoked_at,
                       t.last_used_at, t.last_used_from, t.use_count
                FROM access_tokens t
                LEFT JOIN users owner ON owner.id = t.owner_user_id
                LEFT JOIN users creator ON creator.id = t.created_by_user_id
                WHERE t.token_hash = ?
                  AND t.revoked_at IS NULL
                  AND (t.expires_at IS NULL OR t.expires_at > ?)
                """,
                (_access_token_hash(normalized_token), now),
            ).fetchone()

            if row is None:
                return None
            if row["owner_user_id"] is not None and not bool(row["owner_is_enabled"]):
                return None

            token_record = _row_to_access_token(row)
            if token_record is None:
                return None
            if normalized_token_type and token_record["token_type"] != normalized_token_type:
                return None
            if normalized_required_scopes and not set(normalized_required_scopes).issubset(set(token_record["scopes"])):
                self.record_audit_event(
                    "access_token_scope_denied",
                    username=token_record.get("owner_username"),
                    user_id=token_record.get("owner_user_id"),
                    details={
                        "token_id": token_record["id"],
                        "required_scopes": normalized_required_scopes,
                        "token_scopes": token_record["scopes"],
                    },
                )
                return None

            if record_usage:
                connection.execute(
                    """
                    UPDATE access_tokens
                    SET last_used_at = ?, last_used_from = ?, use_count = use_count + 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (now, str(used_from or "").strip() or None, now, token_record["id"]),
                )

        if record_usage:
            self.record_audit_event(
                "access_token_used",
                username=token_record.get("owner_username"),
                user_id=token_record.get("owner_user_id"),
                details={
                    "token_id": token_record["id"],
                    "token_type": token_record["token_type"],
                    "used_from": str(used_from or "").strip() or None,
                },
            )
        return self.get_access_token(token_record["id"])

    def revoke_access_token(self, token_id: int, revoked_by_user_id: Optional[int] = None) -> bool:
        existing_token = self.get_access_token(token_id)
        if existing_token is None:
            return False
        normalized_revoked_by_user_id = self._assert_existing_user_id(revoked_by_user_id, "revoked_by_user_id")

        if existing_token.get("revoked_at"):
            return True

        revoked_at = _utcnow_iso()
        with self._managed_connection() as connection:
            connection.execute(
                "UPDATE access_tokens SET revoked_at = ?, updated_at = ? WHERE id = ? AND revoked_at IS NULL",
                (revoked_at, revoked_at, int(token_id)),
            )

        self.record_audit_event(
            "access_token_revoked",
            username=existing_token.get("owner_username"),
            user_id=normalized_revoked_by_user_id,
            details={
                "token_id": int(token_id),
                "token_type": existing_token.get("token_type"),
                "owner_user_id": existing_token.get("owner_user_id"),
            },
        )
        return True

    def delete_access_token(self, token_id: int, deleted_by_user_id: Optional[int] = None) -> bool:
        existing_token = self.get_access_token(token_id)
        if existing_token is None:
            return False
        normalized_deleted_by_user_id = self._assert_existing_user_id(deleted_by_user_id, "deleted_by_user_id")

        with self._managed_connection() as connection:
            connection.execute(
                "DELETE FROM access_tokens WHERE id = ?",
                (int(token_id),),
            )

        self.record_audit_event(
            "access_token_deleted",
            username=existing_token.get("owner_username"),
            user_id=normalized_deleted_by_user_id,
            details={
                "token_id": int(token_id),
                "token_type": existing_token.get("token_type"),
                "owner_user_id": existing_token.get("owner_user_id"),
                "was_revoked": bool(existing_token.get("revoked_at")),
            },
        )
        return True