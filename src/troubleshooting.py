"""Staged checks that explain why an MCP server or AI provider can't connect or can't be saved.

The checks never change saved settings: the save check runs the real save pipeline against a
temporary file next to the config file and removes it afterwards.
"""

from __future__ import annotations

import asyncio
import base64
import errno
import hashlib
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx

from config_manager import AppConfig, LLMCredential, MCPCredential, clean_secret, is_unset_secret

PASS = "pass"
WARN = "warn"
FAIL = "fail"
INFO = "info"
SKIP = "skip"
_SEVERITY = {FAIL: 3, WARN: 2, INFO: 1, PASS: 0, SKIP: 0}

DNS_TIMEOUT_SECONDS = 5.0
TCP_TIMEOUT_SECONDS = 5.0
TLS_TIMEOUT_SECONDS = 8.0
MCP_REQUEST_TIMEOUT_SECONDS = 20.0
INSTANCE_SCAN_SPAN = 20

HOSTED_LLM_PROVIDERS = {"openai", "azure", "anthropic", "gemini"}
KNOWN_LLM_PROVIDERS = HOSTED_LLM_PROVIDERS | {"ollama", "custom"}
LLM_KEY_PAGES = {
    "openai": "https://platform.openai.com/api-keys",
    "anthropic": "https://console.anthropic.com/settings/keys",
    "gemini": "https://aistudio.google.com/app/apikey",
    "azure": "the Keys and Endpoint page of your Azure OpenAI resource",
}


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class Check:
    id: str
    title: str
    status: str
    detail: str = ""
    fix: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "title": self.title, "status": self.status, "detail": self.detail, "fix": self.fix}


@dataclass
class Stage:
    id: str
    title: str
    checks: List[Check] = field(default_factory=list)

    def add(self, check_id: str, title: str, status: str, detail: str = "", fix: str = "") -> Check:
        check = Check(check_id, title, status, detail, fix)
        self.checks.append(check)
        return check

    def skip(self, reason: str) -> "Stage":
        self.add(f"{self.id}_skipped", reason, SKIP)
        return self

    @property
    def status(self) -> str:
        if not self.checks or all(check.status == SKIP for check in self.checks):
            return SKIP
        worst = max(_SEVERITY[check.status] for check in self.checks)
        if worst >= _SEVERITY[FAIL]:
            return FAIL
        if worst >= _SEVERITY[WARN]:
            return WARN
        return PASS

    def as_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "title": self.title, "status": self.status, "checks": [c.as_dict() for c in self.checks]}


def redact(value: Any, secrets: Iterable[str]) -> Any:
    """Replace every secret value (and ?key= query values) anywhere in a nested result."""
    hidden = sorted({s for s in secrets if isinstance(s, str) and len(s) >= 4}, key=len, reverse=True)

    def _clean(text: str) -> str:
        for secret in hidden:
            text = text.replace(secret, "[hidden]")
        return re.sub(r"([?&](?:key|api[_-]?key|token)=)[^&\s'\"]+", r"\1[hidden]", text, flags=re.IGNORECASE)

    def _walk(item: Any) -> Any:
        if isinstance(item, str):
            return _clean(item)
        if isinstance(item, list):
            return [_walk(entry) for entry in item]
        if isinstance(item, dict):
            return {key: _walk(entry) for key, entry in item.items()}
        return item

    return _walk(value)


def build_report(kind: str, target: str, stages: List[Stage], secrets: Iterable[str] = ()) -> Dict[str, Any]:
    active = [stage for stage in stages if stage.status != SKIP]
    worst = max((_SEVERITY[stage.status] for stage in active), default=0)
    status = FAIL if worst >= _SEVERITY[FAIL] else WARN if worst >= _SEVERITY[WARN] else PASS
    first = None
    for wanted in (FAIL, WARN):
        first = next((check for stage in stages for check in stage.checks if check.status == wanted), None)
        if first:
            break
    summary = first.title if first else "All checks passed"
    checked_at = datetime.now(timezone.utc)
    label = "MCP server" if kind == "mcp" else "AI provider"
    lines = [
        f"DT4SMS troubleshooting report: {label}",
        f"Checked: {checked_at.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"Target: {target or '(none entered)'}",
        f"Result: {status.upper()} - {summary}",
        f"Platform: {platform.platform()}; Python {platform.python_version()}",
    ]
    for stage in stages:
        lines.append("")
        lines.append(f"{stage.title}: {stage.status.upper()}")
        for check in stage.checks:
            lines.append(f"  [{check.status}] {check.title}")
            if check.detail:
                lines.append(f"         {check.detail}")
            if check.fix:
                lines.append(f"         Fix: {check.fix}")
    result = {
        "kind": kind,
        "target": target,
        "status": status,
        "summary": summary,
        "summary_fix": first.fix if first else "",
        "checked_at": checked_at.isoformat(),
        "stages": [stage.as_dict() for stage in stages],
        "report": "\n".join(lines),
    }
    return redact(result, secrets)


# ---------------------------------------------------------------------------
# Server and environment
# ---------------------------------------------------------------------------

def code_fingerprint(project_root: Path) -> str:
    """Hash the Python sources and the shipped frontend manifest."""
    digest = hashlib.sha256()
    src = Path(project_root) / "src"
    paths = sorted(p for p in src.rglob("*.py") if "__pycache__" not in p.parts)
    paths.append(src / "static" / "build-manifest.json")
    for path in paths:
        try:
            data = path.read_bytes()
        except OSError:
            continue
        digest.update(path.relative_to(project_root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def read_git_commit(project_root: Path) -> Optional[str]:
    """Read HEAD without running git (it may not be installed)."""
    git_dir = Path(project_root) / ".git"
    try:
        if git_dir.is_file():
            pointer = git_dir.read_text(encoding="utf-8").strip()
            if not pointer.startswith("gitdir:"):
                return None
            git_dir = (Path(project_root) / pointer[len("gitdir:"):].strip()).resolve()
        if not git_dir.is_dir():
            return None
        common_dir = git_dir
        commondir_file = git_dir / "commondir"
        if commondir_file.is_file():
            common_dir = (git_dir / commondir_file.read_text(encoding="utf-8").strip()).resolve()
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref:"):
            return head or None
        ref = head[len("ref:"):].strip()
        for base in (git_dir, common_dir):
            ref_file = base / ref
            if ref_file.is_file():
                return ref_file.read_text(encoding="utf-8").strip() or None
        packed = common_dir / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                parts = line.strip().split(" ", 1)
                if len(parts) == 2 and parts[1] == ref:
                    return parts[0]
    except OSError:
        return None
    return None


def capture_startup_state(project_root: Path) -> Dict[str, Any]:
    return {
        "started_at": time.time(),
        "fingerprint": code_fingerprint(project_root),
        "commit": read_git_commit(project_root),
        "pid": os.getpid(),
    }


def _short(commit: Optional[str]) -> str:
    return commit[:7] if commit else "unknown"


def _local_time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")


def _restart_hint() -> str:
    if os.name == "nt":
        return "Restart the app: run .\\install.ps1 -Restart in the install folder, then reload this page."
    return "Restart the app: run ./install.sh --restart in the install folder, then reload this page."


def server_code_status(project_root: Path, startup: Dict[str, Any]) -> Dict[str, Any]:
    """Compare the code the server started with against the files in the install folder now."""
    return {
        "stale": code_fingerprint(project_root) != startup.get("fingerprint"),
        "started_at": float(startup.get("started_at") or time.time()),
        "running_commit": startup.get("commit"),
        "disk_commit": read_git_commit(project_root),
        "restart_hint": _restart_hint(),
    }


def check_server_code(stage: Stage, project_root: Path, startup: Dict[str, Any]) -> None:
    status = server_code_status(project_root, startup)
    commit_now = status["disk_commit"]
    started = _local_time(status["started_at"])
    started_commit = status["running_commit"]
    if not status["stale"]:
        where = f"commit {_short(commit_now)}" if commit_now else "not a git checkout"
        stage.add(
            "server_code",
            "The server is running the code in the install folder",
            PASS,
            f"Started {started} from {project_root} ({where}).",
        )
        return
    changed = f" (commit {_short(started_commit)} then, {_short(commit_now)} now)" if commit_now and commit_now != started_commit else ""
    stage.add(
        "server_code",
        "The server is running older code than the install folder",
        FAIL,
        (
            f"The server started at {started}, and the files in {project_root} changed after that{changed}. "
            "The browser loads the new pages while the server keeps running the old code, "
            "so saves and tests can fail in ways that are already fixed."
        ),
        _restart_hint(),
    )


def check_python(stage: Stage, project_root: Path) -> None:
    detail = f"Python {platform.python_version()} at {sys.executable}"
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    try:
        uses_project_venv = Path(sys.prefix).resolve() == (Path(project_root) / ".venv").resolve()
    except OSError:
        uses_project_venv = False
    if uses_project_venv:
        stage.add("python", "Python environment", PASS, detail + " (the app's .venv).")
    elif in_venv:
        stage.add("python", "Python environment", INFO, detail + f" (virtual environment {sys.prefix}).")
    else:
        stage.add(
            "python",
            "The app isn't running in a virtual environment",
            WARN,
            detail + ".",
            "Start the app with the installer so it uses its own .venv and the package versions it needs.",
        )


_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(>=|==|~=)?\s*([0-9][0-9A-Za-z.+-]*)?")


def _version_tuple(version: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for piece in str(version or "").split("+", 1)[0].split("."):
        match = re.match(r"\d+", piece)
        if not match:
            break
        parts.append(int(match.group()))
        if match.end() < len(piece):
            break
    return tuple(parts)


def check_dependencies(stage: Stage, project_root: Path) -> None:
    from importlib import metadata

    requirements = Path(project_root) / "requirements.txt"
    try:
        lines = requirements.read_text(encoding="utf-8").splitlines()
    except OSError:
        stage.add("dependencies", "Couldn't read requirements.txt", INFO, str(requirements))
        return
    missing: List[str] = []
    outdated: List[str] = []
    total = 0
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        match = _REQUIREMENT.match(line) if line else None
        if not match:
            continue
        name, operator, wanted = match.groups()
        total += 1
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            missing.append(name)
            continue
        if operator and wanted and _version_tuple(installed) < _version_tuple(wanted):
            outdated.append(f"{name} {installed} (needs {operator}{wanted})")
        elif operator == "==" and wanted and installed != wanted:
            outdated.append(f"{name} {installed} (needs =={wanted})")
    fix = (
        f'Install the required versions: "{sys.executable}" -m pip install -r "{requirements}", then restart the app. '
        "The installer also does this when requirements.txt changes."
    )
    if missing:
        stage.add("dependencies", f"Python packages are missing: {', '.join(missing)}", FAIL,
                  "These were added to requirements.txt after this environment was set up.", fix)
    elif outdated:
        stage.add("dependencies", "Some Python packages are older than required", WARN, "; ".join(outdated), fix)
    else:
        stage.add("dependencies", "Required Python packages are installed", PASS, f"{total} packages from requirements.txt.")


async def _port_open(host: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except Exception:
        return False
    writer.close()
    return True


async def _looks_like_this_app(client: httpx.AsyncClient, port: int) -> bool:
    base = f"http://127.0.0.1:{port}"
    try:
        response = await client.get(f"{base}/api/auth/status")
        data = response.json()
        if isinstance(data, dict) and "demo_mode" in data and "auth_enabled" in data:
            return True
    except Exception:
        pass
    try:
        response = await client.get(f"{base}/")
        page = response.text[:5000]
        return "Splunk MCP Discovery Tool" in page or "DT4SMS" in page
    except Exception:
        return False


async def check_other_instances(stage: Stage, own_port: Optional[int], preferred_port: int) -> None:
    ports = [port for port in range(preferred_port, preferred_port + INSTANCE_SCAN_SPAN + 1) if port != own_port]
    open_flags = await asyncio.gather(*(_port_open("127.0.0.1", port, 0.3) for port in ports))
    candidates = [port for port, is_open in zip(ports, open_flags) if is_open]
    found: List[int] = []
    if candidates:
        async with httpx.AsyncClient(timeout=1.5, trust_env=False) as client:
            for port in candidates:
                if await _looks_like_this_app(client, port):
                    found.append(port)
    port_note = ""
    if own_port and own_port != preferred_port:
        port_note = f" This copy runs on port {own_port} because port {preferred_port} was busy when it started."
    if found:
        listed = ", ".join(str(port) for port in found)
        stage.add(
            "other_instances",
            f"Another copy of the app is running on port {listed}",
            WARN,
            (
                f"This page comes from port {own_port or preferred_port}.{port_note} Each copy has its own code version "
                "and may read a different settings file, so a copy started before an update still behaves the old way."
            ),
            (
                "Use one copy. Stop the others with the installer's stop command in the folder each was started from"
                + (", or find the process with: lsof -nP -iTCP:<port> -sTCP:LISTEN" if os.name != "nt" else "")
                + ". Then open the address the installer prints."
            ),
        )
    else:
        stage.add(
            "other_instances",
            "No other copies of the app are running",
            PASS,
            f"Checked ports {preferred_port}-{preferred_port + INSTANCE_SCAN_SPAN} on this computer.{port_note}",
        )


def check_account(stage: Stage, account: Dict[str, Any]) -> None:
    if not account.get("auth_enabled"):
        stage.add("account", "Saving is allowed", PASS, "Sign-in is off (demo mode), so anyone who opens this page can save settings.")
        return
    username = account.get("username") or "unknown user"
    role = account.get("role") or "no role"
    if account.get("can_manage"):
        stage.add("account", "Your account can save these settings", PASS, f"Signed in as {username} (admin).")
        return
    stage.add(
        "account",
        "Your account can't save or test these settings",
        FAIL,
        f"Signed in as {username} with the {role} role. Saving and testing MCP and AI settings requires an admin.",
        "Sign in with an admin account, or ask an admin to change your role in Settings > Users.",
    )


async def app_stage(
    *, project_root: Path, startup: Dict[str, Any], own_port: Optional[int], preferred_port: int, account: Dict[str, Any]
) -> Stage:
    stage = Stage("app", "App and server")
    check_server_code(stage, project_root, startup)
    check_dependencies(stage, project_root)
    check_python(stage, project_root)
    await check_other_instances(stage, own_port, preferred_port)
    check_account(stage, account)
    return stage


# ---------------------------------------------------------------------------
# Values entered
# ---------------------------------------------------------------------------

@dataclass
class Endpoint:
    raw: str
    scheme: str = ""
    host: str = ""
    port: int = 0
    path: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    @property
    def display(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}{self.path}"


def parse_endpoint(url: str, example: str) -> Endpoint:
    raw = str(url or "").strip()
    endpoint = Endpoint(raw=raw)
    if not raw:
        endpoint.error = "No URL entered"
        return endpoint
    if any(ch.isspace() for ch in raw):
        endpoint.error = "The URL contains spaces"
        return endpoint
    if "://" not in raw:
        endpoint.error = f"The URL is missing https:// (for example {example})"
        return endpoint
    parts = urlsplit(raw)
    endpoint.scheme = (parts.scheme or "").lower()
    if endpoint.scheme not in {"http", "https"}:
        endpoint.error = f"The URL must start with https:// or http://, not {parts.scheme}://"
        return endpoint
    endpoint.host = parts.hostname or ""
    if not endpoint.host:
        endpoint.error = "The URL has no host name"
        return endpoint
    try:
        explicit = parts.port
    except ValueError:
        endpoint.error = "The port in the URL isn't a number between 1 and 65535"
        return endpoint
    endpoint.port = explicit or (443 if endpoint.scheme == "https" else 80)
    endpoint.path = parts.path or ""
    return endpoint


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _format_when(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")


def _jwt_claims(token: str) -> Optional[Dict[str, Any]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))
    except Exception:
        return None
    return claims if isinstance(claims, dict) else None


def describe_secret_source(source: str, name: str, noun: str) -> str:
    if source == "entered":
        return f"Using the {noun} you entered"
    if source == "saved":
        return f"Using the {noun} saved with \u201c{name}\u201d"
    if source == "active":
        return f"Using the active connection's {noun} (same server)"
    return f"No {noun}"


def check_secret_format(stage: Stage, raw: str, cleaned: str, noun: str, check_id: str) -> None:
    """Report paste problems in a secret the user typed."""
    stripped = str(raw or "").strip()
    if raw and raw != stripped:
        stage.add(f"{check_id}_whitespace", f"Removed spaces or line breaks around the {noun}", INFO,
                  "Saving removes them too; HTTP clients reject header values that start or end with whitespace.")
    if stripped[:7].lower() == "bearer ":
        stage.add(f"{check_id}_bearer", f"Removed \u201cBearer \u201d from the start of the {noun}", INFO,
                  "Paste only the token itself; the app adds \u201cBearer\u201d when it connects.")
    if any(ch.isspace() for ch in cleaned):
        stage.add(f"{check_id}_inner_space", f"The {noun} contains spaces or line breaks", FAIL,
                  "A copied value was probably wrapped or combined with other text.",
                  f"Copy the {noun} again as a single line.")
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'"', "'"}:
        stage.add(f"{check_id}_quotes", f"The {noun} is wrapped in quotes", WARN,
                  "The quotes are sent as part of the value.", "Remove the quotes.")


def check_token_claims(stage: Stage, token: str) -> None:
    claims = _jwt_claims(token)
    if claims is None:
        stage.add("token_expiry", "The token's expiry can't be read here", INFO,
                  "It isn't a JWT, so only the server can tell whether it's still valid.")
        return
    now = time.time()
    audience = claims.get("aud")
    audience_note = f" Audience: {', '.join(audience) if isinstance(audience, list) else audience}." if audience else ""
    not_before = claims.get("nbf")
    if isinstance(not_before, (int, float)) and not_before > now + 60:
        stage.add("token_expiry", f"The token isn't valid until {_format_when(not_before)}", FAIL,
                  "Check that this computer's clock is correct." + audience_note,
                  "Wait until then, or create a new token.")
        return
    expires = claims.get("exp")
    if not isinstance(expires, (int, float)):
        stage.add("token_expiry", "The token doesn't expire", PASS, audience_note.strip())
    elif expires <= now:
        stage.add("token_expiry", f"The token expired on {_format_when(expires)}", FAIL,
                  "Splunk rejects expired tokens with HTTP 401." + audience_note,
                  "Create a new token in Splunk (Settings > Tokens) and paste it here.")
    elif expires - now < 3 * 86400:
        stage.add("token_expiry", f"The token expires soon ({_format_when(expires)})", WARN, audience_note.strip(),
                  "Create a token with a longer lifetime before this one runs out.")
    else:
        stage.add("token_expiry", f"The token is valid until {_format_when(expires)}", PASS, audience_note.strip())


@dataclass
class MCPDraft:
    name: str
    url: str
    token: str
    token_source: str
    token_raw: str
    verify_ssl: bool
    ca_bundle_path: Optional[str]
    description: Optional[str]


def build_mcp_draft(payload: Dict[str, Any], config_manager: Any) -> MCPDraft:
    name = str(payload.get("name") or "").strip()
    url = str(payload.get("url") or "").strip()
    raw_token = str(payload.get("token") or "")
    if is_unset_secret(raw_token):
        token, source = config_manager.resolve_mcp_token_with_source(name, url)
        raw_token = ""
    else:
        token, source = raw_token, "entered"
    ca_bundle = str(payload.get("ca_bundle_path") or "").strip() or None
    return MCPDraft(
        name=name,
        url=url,
        token=clean_secret(token),
        token_source=source,
        token_raw=raw_token,
        verify_ssl=bool(payload.get("verify_ssl")),
        ca_bundle_path=ca_bundle,
        description=str(payload.get("description") or "").strip() or None,
    )


def check_ca_bundle(stage: Stage, path: Optional[str], verify: bool) -> None:
    if not path:
        if not verify:
            stage.add("tls_settings", "Certificate checks are off (Verify SSL is unchecked)", INFO,
                      "The app will connect even if the server's certificate isn't trusted.")
        return
    bundle = Path(path).expanduser()
    if not verify:
        stage.add("tls_settings", "The CA bundle is ignored because Verify SSL is off", INFO, str(bundle))
        return
    try:
        text = bundle.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        stage.add("tls_settings", "The CA bundle file doesn't exist", FAIL, str(bundle),
                  "Enter the full path to a PEM file on the computer running the app.")
        return
    except OSError as exc:
        stage.add("tls_settings", "The CA bundle file can't be read", FAIL, f"{bundle}: {exc}",
                  "Check the file's permissions.")
        return
    count = text.count("BEGIN CERTIFICATE")
    if not count:
        stage.add("tls_settings", "The CA bundle has no certificates in it", FAIL, str(bundle),
                  "Use a PEM file (text that starts with -----BEGIN CERTIFICATE-----).")
    else:
        stage.add("tls_settings", f"CA bundle has {count} certificate{'s' if count != 1 else ''}", PASS, str(bundle))


def mcp_values_stage(draft: MCPDraft, validation_errors: List[str]) -> Tuple[Stage, Endpoint]:
    stage = Stage("values", "Values entered")
    for message in validation_errors:
        stage.add("request_validation", "The server would reject these values", FAIL, message,
                  "Correct the field named above.")
    if draft.name:
        stage.add("name", f"Name: \u201c{draft.name}\u201d", PASS)
    else:
        stage.add("name", "No name entered", INFO, "A name is only needed to save. Enter one to check saving under that name.")

    endpoint = parse_endpoint(draft.url, "https://splunk.example.com:8089/services/mcp")
    if not endpoint.ok:
        stage.add("url", endpoint.error, FAIL, draft.url or "", "Use the MCP endpoint, for example https://splunk.example.com:8089/services/mcp")
    else:
        stage.add("url", "URL is well formed", PASS, endpoint.display)
        if endpoint.path in {"", "/"}:
            stage.add("url_path", "The URL has no path", WARN,
                      "The Splunk MCP Server app answers at /services/mcp.",
                      f"Try {endpoint.scheme}://{endpoint.host}:{endpoint.port}/services/mcp")
        if endpoint.port == 8000:
            stage.add("url_port", "Port 8000 is usually Splunk Web, not the MCP endpoint", WARN,
                      "The MCP Server app answers on Splunk's management port.",
                      "Use the management port, usually 8089.")
        if endpoint.scheme == "http" and endpoint.port == 8089:
            stage.add("url_scheme", "Splunk's management port normally uses https", WARN, "", "Try https:// instead of http://.")

    if draft.token:
        stage.add("token", describe_secret_source(draft.token_source, draft.name, "token"), PASS, f"{len(draft.token)} characters.")
        if draft.token_source == "entered":
            check_secret_format(stage, draft.token_raw, draft.token, "token", "token")
        check_token_claims(stage, draft.token)
    else:
        stage.add("token", "No token", WARN,
                  "Nothing was entered, and no saved token matches this name or URL. Splunk's MCP server rejects requests without one.",
                  "Paste a Splunk token. Create one in Splunk under Settings > Tokens.")
    check_ca_bundle(stage, draft.ca_bundle_path, draft.verify_ssl)
    return stage, endpoint


@dataclass
class LLMDraft:
    name: str
    provider: str
    api_key: str
    api_key_source: str
    api_key_raw: str
    model: str
    endpoint_url: Optional[str]
    effective_endpoint: str
    max_tokens: int
    temperature: float
    auto_tune: bool
    context_window: int
    request_timeout: int
    reasoning_effort: str

    def test_payload(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "api_key": self.api_key,
            "model": self.model,
            "endpoint_url": self.endpoint_url,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "auto_tune": self.auto_tune,
            "context_window": self.context_window,
            "request_timeout": self.request_timeout,
            "reasoning_effort": self.reasoning_effort,
        }


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if number == number else default


def build_llm_draft(
    payload: Dict[str, Any],
    config_manager: Any,
    *,
    normalize_provider: Callable[[Any], str],
    effective_endpoint: Callable[[str, Optional[str]], str],
) -> LLMDraft:
    name = str(payload.get("name") or "").strip()
    provider = normalize_provider(payload.get("provider") or "openai")
    endpoint_url = str(payload.get("endpoint_url") or "").strip() or None
    raw_key = str(payload.get("api_key") or "")
    if is_unset_secret(raw_key):
        api_key, source = config_manager.resolve_llm_api_key_with_source(name, provider, endpoint_url)
        raw_key = ""
    else:
        api_key, source = raw_key, "entered"
    return LLMDraft(
        name=name,
        provider=provider,
        api_key=clean_secret(api_key),
        api_key_source=source,
        api_key_raw=raw_key,
        model=str(payload.get("model") or "").strip(),
        endpoint_url=endpoint_url,
        effective_endpoint=effective_endpoint(provider, endpoint_url),
        max_tokens=_as_int(payload.get("max_tokens"), 16000),
        temperature=_as_float(payload.get("temperature"), 0.7),
        auto_tune=payload.get("auto_tune") is not False,
        context_window=_as_int(payload.get("context_window"), 0),
        request_timeout=_as_int(payload.get("request_timeout"), 0),
        reasoning_effort=str(payload.get("reasoning_effort") or ""),
    )


def llm_values_stage(draft: LLMDraft, validation_errors: List[str]) -> Tuple[Stage, Endpoint]:
    stage = Stage("values", "Values entered")
    for message in validation_errors:
        stage.add("request_validation", "The server would reject these values", FAIL, message,
                  "Correct the field named above.")
    if draft.name:
        stage.add("name", f"Name: \u201c{draft.name}\u201d", PASS)
    else:
        stage.add("name", "No name entered", INFO, "A name is only needed to save. Enter one to check saving under that name.")

    if draft.provider not in KNOWN_LLM_PROVIDERS:
        stage.add("provider", f"Unknown provider \u201c{draft.provider}\u201d", FAIL, "",
                  "Choose OpenAI, Azure OpenAI, Anthropic, Gemini, Ollama, or Custom (OpenAI-compatible).")
    else:
        stage.add("provider", f"Provider: {draft.provider}", PASS)

    endpoint = parse_endpoint(draft.effective_endpoint, "http://localhost:11434")
    if draft.provider in {"azure", "custom"} and not draft.endpoint_url:
        stage.add("endpoint", f"The {draft.provider} provider needs an endpoint URL", FAIL, "",
                  "Enter the base URL, for example http://localhost:1234/v1 for LM Studio or http://localhost:8000/v1 for vLLM."
                  if draft.provider == "custom" else "Enter your Azure OpenAI resource URL, for example https://NAME.openai.azure.com")
    elif not endpoint.ok:
        stage.add("endpoint", endpoint.error, FAIL, draft.effective_endpoint, "Enter the provider's base URL.")
    else:
        stage.add("endpoint", "Endpoint URL is well formed", PASS, endpoint.display)
        if re.search(r"/(chat/)?completions/?$", endpoint.path):
            stage.add("endpoint_path", "The endpoint includes the completions path", WARN,
                      "The app adds the API path itself.",
                      "Use the base URL, for example http://localhost:1234/v1")

    key_needed = draft.provider in HOSTED_LLM_PROVIDERS
    if draft.api_key:
        stage.add("api_key", describe_secret_source(draft.api_key_source, draft.name, "API key"), PASS,
                  f"{len(draft.api_key)} characters.")
        if draft.api_key_source == "entered":
            check_secret_format(stage, draft.api_key_raw, draft.api_key, "API key", "api_key")
        uses_default_endpoint = not draft.endpoint_url
        expected_prefix = {"openai": "sk-", "anthropic": "sk-ant-", "gemini": "AIza"}.get(draft.provider)
        if expected_prefix and uses_default_endpoint and not draft.api_key.startswith(expected_prefix):
            stage.add("api_key_shape", f"This doesn't look like a {draft.provider} key", WARN,
                      f"{draft.provider} keys normally start with \u201c{expected_prefix}\u201d.",
                      f"Check that you copied the right key from {LLM_KEY_PAGES.get(draft.provider, 'the provider console')}.")
    elif key_needed:
        stage.add("api_key", "No API key", FAIL,
                  f"{draft.provider} requires an API key, and no saved key matches this name or provider.",
                  f"Create a key at {LLM_KEY_PAGES.get(draft.provider, 'the provider console')} and paste it here.")
    else:
        stage.add("api_key", "No API key (fine for most local servers)", INFO)

    if draft.model:
        stage.add("model", f"Model: {draft.model}", PASS)
    else:
        stage.add("model", "No model selected", FAIL, "", "Click Load Models in the AI settings, or type the model name.")
    return stage, endpoint


# ---------------------------------------------------------------------------
# Saving
# ---------------------------------------------------------------------------

_MAC_PROTECTED = ("Desktop", "Documents", "Downloads")


def _owner_name(path: Path) -> Optional[str]:
    if os.name == "nt":
        return None
    try:
        import pwd

        return pwd.getpwuid(path.stat().st_uid).pw_name
    except (ImportError, KeyError, OSError):
        return None


def _owned_by_root_not_me(path: Path) -> bool:
    if os.name == "nt":
        return False
    try:
        return path.stat().st_uid == 0 and os.geteuid() != 0
    except OSError:
        return False


def _in_mac_protected_folder(path: Path) -> bool:
    if sys.platform != "darwin":
        return False
    home = Path.home()
    try:
        resolved = path.resolve()
    except OSError:
        resolved = path
    if "Mobile Documents" in resolved.parts:
        return True
    return any(str(resolved).startswith(str(home / folder) + os.sep) or resolved == home / folder for folder in _MAC_PROTECTED)


def explain_os_error(exc: BaseException, path: Path) -> Tuple[str, str]:
    """Return (detail, fix) for a filesystem error while saving."""
    folder = path if path.is_dir() else path.parent
    code = getattr(exc, "errno", None)
    detail = f"{type(exc).__name__}: {exc}"
    if code in (errno.EACCES, errno.EPERM):
        owner = _owner_name(path) if path.exists() else _owner_name(folder)
        if owner:
            detail += f" (owned by {owner})"
        if (path.exists() and _owned_by_root_not_me(path)) or _owned_by_root_not_me(folder):
            return detail, (
                "These files were probably created by running the app with sudo. Give them back to your account: "
                f'sudo chown -R "$(whoami)" "{folder}"'
            )
        if code == errno.EPERM and _in_mac_protected_folder(folder):
            return detail, (
                "macOS privacy controls can stop apps from writing in Desktop, Documents, Downloads, or iCloud Drive. "
                "Move the app folder somewhere else (for example ~/dt4sms), or allow your terminal app under "
                "System Settings > Privacy & Security > Files and Folders."
            )
        return detail, f'Make the folder writable for the account running the app: chmod u+w "{folder}"'
    if code == errno.EROFS:
        return detail, "The disk is read-only. Move the app folder to a writable disk."
    if code == errno.ENOSPC:
        return detail, "The disk is full. Free some space and try again."
    if code == errno.ENOENT:
        return detail, "The folder doesn't exist anymore. Start the app from its install folder."
    return detail, ""


def check_storage_location(stage: Stage, config_path: Path, project_root: Path) -> None:
    install_config = (Path(project_root) / config_path.name).resolve()
    if config_path.parent == Path(project_root).resolve():
        stage.add("config_location", "Settings are stored in the install folder", PASS, str(config_path))
        return
    extra = f" The install folder also has a settings file ({install_config}) that this server doesn't use." if install_config.exists() else ""
    stage.add(
        "config_location",
        "Settings are stored outside the install folder",
        WARN,
        (
            f"The app was started from {Path.cwd()}, so it reads and writes {config_path} instead of {install_config}. "
            "Starting it from a different folder gives it a different set of saved settings." + extra
        ),
        (
            f'Start the app with the installer in "{project_root}" (./install.sh or .\\install.ps1); the installers always run it from '
            f"that folder. To keep the settings saved so far, first stop the app and move config.encrypted, .config.key and "
            f"security.db from {Path.cwd()} into the install folder."
        ),
    )


def check_folder_writable(stage: Stage, folder: Path) -> bool:
    import tempfile

    try:
        fd, temp_name = tempfile.mkstemp(prefix=".dt4sms-write-test.", suffix=".tmp", dir=str(folder))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(b"ok")
        finally:
            os.unlink(temp_name)
    except OSError as exc:
        detail, fix = explain_os_error(exc, folder)
        stage.add("folder_writable", "The app can't write to its settings folder", FAIL, detail, fix)
        return False
    free = shutil.disk_usage(str(folder)).free
    free_text = f"{free / (1024 ** 3):.1f} GB free" if free >= 1024 ** 3 else f"{free / (1024 ** 2):.0f} MB free"
    if free < 50 * 1024 ** 2:
        stage.add("folder_writable", "The disk is almost full", FAIL, f"{folder} ({free_text}).", "Free some disk space.")
        return False
    stage.add("folder_writable", "The app can write to its settings folder", PASS, f"{folder} ({free_text}).")
    return True


def check_config_files(stage: Stage, config_manager: Any) -> None:
    config_path = Path(config_manager.config_path).resolve()
    key_path = Path(config_manager.key_path).resolve()
    if not key_path.exists():
        stage.add("key_file", "The encryption key file is missing", FAIL, str(key_path),
                  "Restart the app from its install folder; it creates a key on start.")
    elif _owned_by_root_not_me(key_path):
        stage.add("key_file", "The encryption key file is owned by root", WARN, str(key_path),
                  f'It was probably created with sudo. Run: sudo chown "$(whoami)" "{key_path}"')
    if not config_path.exists():
        stage.add("config_file", "No settings file yet", INFO, f"The first save creates {config_path}.")
        return
    try:
        encrypted = config_path.read_bytes()
    except OSError as exc:
        detail, fix = explain_os_error(exc, config_path)
        stage.add("config_file", "The settings file can't be read", FAIL, detail, fix)
        return
    try:
        config_manager._decrypt(encrypted)
    except Exception:
        backups = sorted(config_path.parent.glob(config_path.name + ".corrupted-*"))
        backup_note = f" A copy of it was kept as {backups[-1].name}." if backups else ""
        stage.add(
            "config_file",
            "The settings file can't be decrypted with this key",
            FAIL,
            (
                f"{config_path.name} and {key_path.name} don't belong together (for example, one was copied from another "
                "computer). The app is running on default settings." + backup_note
            ),
            f"Copy both {config_path.name} and {key_path.name} from the same computer into {config_path.parent}, "
            "or keep the defaults and save your settings again.",
        )
        return
    if _owned_by_root_not_me(config_path):
        stage.add("config_file", "The settings file is owned by root", WARN, str(config_path),
                  f'It was probably created with sudo. Run: sudo chown "$(whoami)" "{config_path}"')
    else:
        stage.add("config_file", "The settings file opens with this key", PASS, str(config_path))


def storage_stage(
    config_manager: Any,
    project_root: Path,
    *,
    plan: List[str],
    apply: Optional[Callable[[AppConfig], None]],
) -> Stage:
    stage = Stage("saving", "Saving")
    config_path = Path(config_manager.config_path).resolve()
    check_storage_location(stage, config_path, project_root)
    writable = check_folder_writable(stage, config_path.parent)
    check_config_files(stage, config_manager)
    last_error = getattr(config_manager, "last_save_error", None)
    if last_error:
        stage.add("last_save_error", "The last save failed", WARN, str(last_error),
                  "If the test save below works, the cause has been fixed since then.")
    if writable:
        try:
            result = config_manager.probe_save(apply)
            stage.add(
                "test_save",
                "A test save with these values worked",
                PASS,
                f"Wrote, read back, and removed a temporary copy in {result['directory']}. Your saved settings weren't changed.",
            )
        except OSError as exc:
            detail, fix = explain_os_error(exc, config_path)
            stage.add("test_save", "A test save failed", FAIL, detail, fix)
        except Exception as exc:
            stage.add("test_save", "A test save failed", FAIL, f"{type(exc).__name__}: {exc}",
                      "Copy this report and send it to the app maintainers.")
    if plan:
        stage.add("save_plan", "What saving would do", INFO, " ".join(plan))
    return stage


def mcp_save_plan(config: AppConfig, draft: MCPDraft, activate: bool) -> Tuple[List[str], Callable[[AppConfig], None]]:
    plan: List[str] = []
    if draft.name:
        plan.append(f"Replaces the saved \u201c{draft.name}\u201d." if draft.name in (config.saved_mcp_configs or {}) else f"Creates \u201c{draft.name}\u201d.")
        if activate:
            plan.append("Makes it the active MCP connection.")
        elif config.active_mcp_config_name:
            plan.append(f"Keeps \u201c{config.active_mcp_config_name}\u201d as the active connection.")
        plan.append({
            "entered": "Stores the token you entered.",
            "saved": "Keeps the token already saved with it.",
            "active": "Stores the active connection's token.",
        }.get(draft.token_source, "Saves it without a token."))

    def apply(candidate: AppConfig) -> None:
        if not draft.name:
            return
        profile = MCPCredential(
            name=draft.name,
            url=draft.url,
            token=draft.token,
            verify_ssl=draft.verify_ssl,
            ca_bundle_path=draft.ca_bundle_path,
            description=draft.description,
        )
        candidate.saved_mcp_configs[draft.name] = profile
        if activate:
            candidate.mcp.url = profile.url
            candidate.mcp.token = profile.token
            candidate.mcp.verify_ssl = profile.verify_ssl
            candidate.mcp.ca_bundle_path = profile.ca_bundle_path
            candidate.active_mcp_config_name = draft.name

    return plan, apply


def llm_save_plan(config: AppConfig, draft: LLMDraft, activate: bool) -> Tuple[List[str], Callable[[AppConfig], None]]:
    plan: List[str] = []
    if draft.name:
        plan.append(f"Replaces the saved \u201c{draft.name}\u201d." if draft.name in (config.saved_credentials or {}) else f"Creates \u201c{draft.name}\u201d.")
        if activate:
            plan.append("Updates the active AI settings, because this is the active credential.")
        plan.append({
            "entered": "Stores the API key you entered.",
            "saved": "Keeps the API key already saved with it.",
            "active": "Stores the active AI settings' API key.",
        }.get(draft.api_key_source, "Saves it without an API key."))

    def apply(candidate: AppConfig) -> None:
        if not draft.name:
            return
        credential = LLMCredential(
            name=draft.name,
            provider=draft.provider,
            api_key=draft.api_key,
            model=draft.model,
            endpoint_url=draft.endpoint_url,
            max_tokens=draft.max_tokens,
            temperature=draft.temperature,
            auto_tune=draft.auto_tune,
            context_window=draft.context_window,
            request_timeout=draft.request_timeout,
            reasoning_effort=draft.reasoning_effort,
        )
        candidate.saved_credentials[draft.name] = credential
        if activate:
            for attribute in ("provider", "api_key", "model", "endpoint_url", "max_tokens", "temperature",
                              "auto_tune", "context_window", "request_timeout", "reasoning_effort"):
                setattr(candidate.llm, attribute, getattr(credential, attribute))
            candidate.active_credential_name = draft.name

    return plan, apply


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def _redact_proxy(proxy: str) -> str:
    parts = urlsplit(proxy)
    if parts.username or parts.password:
        host = parts.hostname or ""
        port = f":{parts.port}" if parts.port else ""
        return f"{parts.scheme}://[credentials hidden]@{host}{port}"
    return proxy


def _proxy_for(endpoint: Endpoint) -> Optional[str]:
    proxies = urllib.request.getproxies_environment()
    proxy = proxies.get(endpoint.scheme) or proxies.get("all")
    if not proxy:
        return None
    if urllib.request.proxy_bypass_environment(endpoint.host, proxies):
        return None
    return proxy


def _certifi_context(cafile: Optional[str] = None) -> ssl.SSLContext:
    if cafile:
        return ssl.create_default_context(cafile=str(Path(cafile).expanduser()))
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _unverified_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


async def _tls_handshake(address: str, port: int, server_hostname: str, context: ssl.SSLContext) -> Tuple[Optional[bytes], str]:
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(address, port, ssl=context, server_hostname=server_hostname),
        TLS_TIMEOUT_SECONDS,
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        version = ssl_object.version() if ssl_object else ""
    finally:
        writer.close()
    return der, version or ""


def describe_certificate(der: Optional[bytes]) -> Dict[str, Any]:
    if not der:
        return {}
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except ImportError:
        return {}
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return {}

    def _name(name: Any, oid: Any) -> str:
        values = name.get_attributes_for_oid(oid)
        return str(values[0].value) if values else ""

    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    names: List[str] = []
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(value) for value in extension.get_values_for_type(x509.DNSName)]
        names += [str(value) for value in extension.get_values_for_type(x509.IPAddress)]
    except Exception:
        names = []
    return {
        "subject": _name(cert.subject, NameOID.COMMON_NAME),
        "issuer": _name(cert.issuer, NameOID.COMMON_NAME) or _name(cert.issuer, NameOID.ORGANIZATION_NAME),
        "issuer_org": _name(cert.issuer, NameOID.ORGANIZATION_NAME),
        "not_after": not_after,
        "names": names,
        "self_signed": cert.issuer == cert.subject,
    }


def _certificate_summary(info: Dict[str, Any]) -> str:
    if not info:
        return ""
    parts = []
    if info.get("subject"):
        parts.append(f"issued to {info['subject']}")
    if info.get("issuer"):
        parts.append(f"by {info['issuer']}")
    if info.get("not_after"):
        parts.append(f"valid until {info['not_after'].strftime('%Y-%m-%d')}")
    summary = "Certificate " + ", ".join(parts) + "." if parts else ""
    if info.get("names"):
        summary += f" Names on it: {', '.join(info['names'][:6])}."
    return summary


def _untrusted_fix(reason: str, info: Dict[str, Any], kind: str, verify: bool) -> str:
    lowered = reason.lower()
    splunk_default = "splunk" in (info.get("issuer", "") + " " + info.get("issuer_org", "")).lower()
    if not verify:
        return "Optional: for production, set the CA bundle to the CA that signed this certificate and turn on Verify SSL."
    if "mismatch" in lowered:
        names = ", ".join(info.get("names") or []) or "the names on the certificate"
        return f"Use a host name that the certificate lists ({names}) in the URL, or turn off Verify SSL."
    if "expired" in lowered:
        return "The server's certificate has expired. Renew it on the server, or turn off Verify SSL for now."
    if kind == "mcp":
        if splunk_default or "self-signed" in lowered or "self signed" in lowered:
            return (
                "Splunk is using a self-signed certificate (Splunk's default certificate is signed by SplunkCommonCA). "
                "Turn off Verify SSL for this connection, or copy the signing CA to this computer "
                "(for Splunk's default certificate: $SPLUNK_HOME/etc/auth/cacert.pem) and enter its path as the CA bundle."
            )
        return "The certificate was issued by a private or company CA. Save that CA's certificate as a PEM file and enter its path as the CA bundle."
    return (
        "Your network may be inspecting HTTPS traffic with a company certificate. Ask IT for the company CA bundle and "
        "start the app with SSL_CERT_FILE=/path/to/company-ca.pem."
    )


async def network_stage(
    endpoint: Endpoint,
    *,
    kind: str,
    verify: bool,
    ca_bundle: Optional[str],
    local_server_hint: str,
) -> Tuple[Stage, bool]:
    """DNS, TCP, proxy, and TLS checks. Returns the stage and whether an HTTP request is worth trying."""
    stage = Stage("network", "Network")
    if not endpoint.ok:
        return stage.skip("Skipped: fix the URL first"), False

    proxy = _proxy_for(endpoint)
    if proxy:
        stage.add(
            "proxy",
            "Some requests go through a proxy",
            INFO,
            (
                f"{_redact_proxy(proxy)} (from the HTTPS_PROXY / HTTP_PROXY environment variables). Connection tests use it"
                + (", but discovery connects directly." if kind == "mcp" else ".")
            ),
        )

    loop = asyncio.get_running_loop()
    addresses: List[str] = []
    if _is_ip(endpoint.host):
        addresses = [endpoint.host]
        stage.add("dns", "Using an IP address (no DNS lookup needed)", PASS, endpoint.host)
    else:
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(endpoint.host, endpoint.port, type=socket.SOCK_STREAM), DNS_TIMEOUT_SECONDS
            )
            for info in infos:
                address = info[4][0]
                if address not in addresses:
                    addresses.append(address)
            stage.add("dns", f"{endpoint.host} resolves", PASS, ", ".join(addresses[:4]))
        except asyncio.TimeoutError:
            stage.add("dns", f"Looking up {endpoint.host} timed out", FAIL, "",
                      "Check this computer's network and DNS settings, or connect to the VPN.")
            return stage, False
        except (socket.gaierror, OSError) as exc:
            lookup = f"dscacheutil -q host -a name {endpoint.host}" if sys.platform == "darwin" else f"nslookup {endpoint.host}"
            stage.add(
                "dns",
                f"Can't find the host {endpoint.host}",
                WARN if proxy else FAIL,
                f"DNS lookup failed: {exc}.",
                f"Check the spelling. If it's an internal name, connect to the VPN or use the IP address. To see what this computer resolves, run: {lookup}",
            )
            return stage, bool(proxy)

    connected: Optional[str] = None
    errors: List[BaseException] = []
    started = time.monotonic()
    for address in addresses[:3]:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(address, endpoint.port), TCP_TIMEOUT_SECONDS)
            writer.close()
            connected = address
            break
        except (OSError, asyncio.TimeoutError) as exc:
            errors.append(exc)
    if connected:
        elapsed = int((time.monotonic() - started) * 1000)
        stage.add("tcp", f"Port {endpoint.port} accepts connections", PASS, f"{connected}:{endpoint.port} answered in {elapsed} ms.")
    else:
        last = errors[-1] if errors else None
        status = WARN if proxy else FAIL
        if isinstance(last, ConnectionRefusedError):
            stage.add("tcp", f"Nothing is listening on {endpoint.host}:{endpoint.port}", status,
                      "The computer answered, but no service accepts connections on that port.", local_server_hint)
        elif isinstance(last, asyncio.TimeoutError):
            stage.add("tcp", f"No answer from {endpoint.host}:{endpoint.port} within {int(TCP_TIMEOUT_SECONDS)} seconds", status,
                      "The connection attempt was silently dropped.",
                      f"A firewall, VPN, or network rule is probably blocking the port. Test from this computer with: nc -vz {endpoint.host} {endpoint.port}")
        elif isinstance(last, OSError) and last.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            stage.add("tcp", f"No network route to {endpoint.host}", status, str(last),
                      "Check the network connection or VPN.")
        else:
            stage.add("tcp", f"Couldn't connect to {endpoint.host}:{endpoint.port}", status,
                      f"{type(last).__name__}: {last}" if last else "", "Check the host, port, and network.")
        return stage, bool(proxy)

    if endpoint.scheme != "https":
        return stage, True

    try:
        verify_context = _certifi_context(ca_bundle if (verify and ca_bundle) else None)
    except (OSError, ssl.SSLError) as exc:
        stage.add("tls", "The CA bundle can't be loaded", FAIL, f"{type(exc).__name__}: {exc}",
                  "Use a readable PEM file with the CA certificate.")
        return stage, False

    try:
        der, version = await _tls_handshake(connected, endpoint.port, endpoint.host, verify_context)
        info = describe_certificate(der)
        detail = f"{_certificate_summary(info)} {version}".strip()
        if verify:
            stage.add("tls", "The server's certificate is trusted", PASS, detail)
            if not ca_bundle:
                await _check_system_trust_store(stage, connected, endpoint, kind)
        else:
            stage.add("tls", "The server's certificate is trusted", PASS,
                      detail + " Verify SSL is off; you can turn it on for this server.")
        return stage, True
    except ssl.SSLCertVerificationError as exc:
        reason = getattr(exc, "verify_message", "") or str(exc)
        info: Dict[str, Any] = {}
        try:
            der, _ = await _tls_handshake(connected, endpoint.port, endpoint.host, _unverified_context())
            info = describe_certificate(der)
        except Exception:
            info = {}
        stage.add(
            "tls",
            f"The server's certificate isn't trusted: {reason}",
            FAIL if verify else WARN,
            (_certificate_summary(info) + ("" if verify else " Verify SSL is off, so the app connects anyway.")).strip(),
            _untrusted_fix(reason, info, kind, verify),
        )
        return stage, not verify
    except ssl.SSLError as exc:
        reason = (getattr(exc, "reason", "") or str(exc)).upper()
        if any(marker in reason for marker in ("WRONG_VERSION_NUMBER", "RECORD_LAYER", "PACKET_LENGTH", "HTTP_REQUEST")):
            stage.add("tls", "This port doesn't speak HTTPS", FAIL, str(exc),
                      "Try the same URL with http:// instead of https://, or check the port number.")
        elif "PROTOCOL_VERSION" in reason or "UNSUPPORTED_PROTOCOL" in reason:
            stage.add("tls", "The server only supports old TLS versions", FAIL, str(exc), "Enable TLS 1.2 or later on the server.")
        else:
            stage.add("tls", "The HTTPS handshake failed", FAIL, str(exc),
                      "A proxy or firewall may be interfering, or a different service is on this port.")
        return stage, False
    except (ConnectionResetError, asyncio.IncompleteReadError, EOFError) as exc:
        stage.add("tls", "The server closed the connection during the HTTPS handshake", FAIL, f"{type(exc).__name__}: {exc}",
                  "A proxy or firewall may be blocking it, or a different service is on this port.")
        return stage, False
    except asyncio.TimeoutError:
        stage.add("tls", "The HTTPS handshake timed out", FAIL, "",
                  "The port accepted the connection but never completed HTTPS. Check that it's the right port.")
        return stage, False
    except OSError as exc:
        stage.add("tls", "The HTTPS handshake failed", FAIL, f"{type(exc).__name__}: {exc}", "")
        return stage, False


async def _check_system_trust_store(stage: Stage, address: str, endpoint: Endpoint, kind: str) -> None:
    """Parts of the app verify certificates with Python's default store instead of certifi."""
    try:
        await _tls_handshake(address, endpoint.port, endpoint.host, ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        reason = getattr(exc, "verify_message", "") or str(exc)
        who = "Discovery" if kind == "mcp" else "Some AI requests"
        fix = (
            "This Python has no system CA certificates. If it came from python.org, run "
            f"\"/Applications/Python {sys.version_info.major}.{sys.version_info.minor}/Install Certificates.command\", then restart the app."
            if sys.platform == "darwin"
            else "Install the operating system's CA certificates package, then restart the app."
        )
        stage.add("system_trust", f"{who} won't trust this certificate: {reason}", WARN,
                  "Connection tests use the certifi certificate list, but that part of the app uses Python's own list.", fix)
    except Exception:
        return


# ---------------------------------------------------------------------------
# Server responses
# ---------------------------------------------------------------------------

def _snippet(body: str, limit: int = 300) -> str:
    text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", body or "", flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("..." if len(text) > limit else "")


def _html_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body or "", flags=re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def _parse_mcp_body(body: str) -> Tuple[Optional[Any], bool]:
    """Return (parsed JSON, came_from_event_stream)."""
    stripped = (body or "").strip()
    if not stripped:
        return None, False
    try:
        return json.loads(stripped), False
    except json.JSONDecodeError:
        pass
    for line in reversed([ln[5:].strip() for ln in stripped.splitlines() if ln.startswith("data:")]):
        try:
            return json.loads(line), True
        except json.JSONDecodeError:
            continue
    return None, False


def _tool_names(result: Any) -> List[str]:
    names: List[str] = []
    if not isinstance(result, dict):
        return names
    for tool in result.get("tools") or []:
        if isinstance(tool, dict) and tool.get("name"):
            names.append(str(tool["name"]))
    for item in result.get("content") or []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            try:
                parsed = json.loads(item["text"])
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                for tool in parsed.get("tools") or []:
                    if isinstance(tool, dict) and tool.get("name"):
                        names.append(str(tool["name"]))
    return names


async def _post_mcp(url: str, headers: Dict[str, str], verify: Any) -> Tuple[httpx.Response, int]:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    timeout = httpx.Timeout(MCP_REQUEST_TIMEOUT_SECONDS, connect=TLS_TIMEOUT_SECONDS)
    async with httpx.AsyncClient(verify=verify, timeout=timeout) as client:
        started = time.monotonic()
        response = await client.post(url, json=payload, headers=headers)
        return response, int((time.monotonic() - started) * 1000)


async def mcp_response_stage(draft: MCPDraft, endpoint: Endpoint, *, reachable: bool) -> Stage:
    stage = Stage("response", "MCP server response")
    if not reachable:
        return stage.skip("Skipped: the server couldn't be reached")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if draft.token:
        headers["Authorization"] = f"Bearer {draft.token}"
    verify: Any = False
    if draft.verify_ssl:
        try:
            verify = _certifi_context(draft.ca_bundle_path) if draft.ca_bundle_path else True
        except (OSError, ssl.SSLError) as exc:
            return stage.skip(f"Skipped: the CA bundle can't be loaded ({type(exc).__name__}: {exc})")
    try:
        response, elapsed = await _post_mcp(draft.url, headers, verify)
    except (httpx.LocalProtocolError, ValueError) as exc:
        stage.add("request", "The token can't be sent in an HTTP header", FAIL, f"{type(exc).__name__}: {exc}",
                  "Copy the token again as a single line without spaces.")
        return stage
    except httpx.TimeoutException:
        stage.add("request", f"The server didn't answer within {int(MCP_REQUEST_TIMEOUT_SECONDS)} seconds", FAIL,
                  "It accepted the connection but sent no reply.",
                  "The MCP server may be overloaded or stuck. Check Splunk's health and the MCP Server app's logs.")
        return stage
    except httpx.HTTPError as exc:
        stage.add("request", "The request failed", FAIL, f"{type(exc).__name__}: {exc}", "")
        return stage

    status = response.status_code
    content_type = response.headers.get("content-type", "").lower()
    body = response.text
    server_said = f"Server said: {_snippet(body)}" if _snippet(body) else ""
    if 300 <= status < 400:
        stage.add("http_status", f"The server redirected the request (HTTP {status})", FAIL,
                  f"Redirected to {response.headers.get('location', '(no location)')}. A redirect usually means this URL is a web page, such as Splunk Web, not the MCP endpoint.",
                  "Use the MCP endpoint on the management port, for example https://splunk.example.com:8089/services/mcp")
        return stage
    if status == 401:
        stage.add("http_status", "The MCP server rejected the token (HTTP 401)", FAIL,
                  ("No token was sent. " if not draft.token else "") + server_said,
                  "Check that the token is current and complete (copy it again), that token authentication is turned on in Splunk "
                  "(Settings > Tokens), and that the token's user may use the MCP Server app.")
        return stage
    if status == 403:
        stage.add("http_status", "The token works but isn't allowed to use the MCP server (HTTP 403)", FAIL, server_said,
                  "Give the token's Splunk user a role with the capabilities the MCP Server app requires, or use a token for a user who has them.")
        return stage
    if status == 404:
        stage.add("http_status", "There's no MCP endpoint at this path (HTTP 404)", FAIL,
                  f"{endpoint.path or '/'} wasn't found on the server.",
                  "Check the path. The Splunk MCP Server app answers at /services/mcp; also check that the app is installed and enabled.")
        return stage
    if status == 405:
        stage.add("http_status", "This URL doesn't accept MCP requests (HTTP 405)", FAIL, server_said,
                  "Check the path. The Splunk MCP Server app answers at /services/mcp.")
        return stage
    if status in (406, 415):
        retry_headers = dict(headers, Accept="application/json, text/event-stream")
        try:
            retry, _ = await _post_mcp(draft.url, retry_headers, verify)
            accepts_streams = 200 <= retry.status_code < 300
        except httpx.HTTPError:
            accepts_streams = False
        if accepts_streams:
            stage.add("http_status", "The server only works with clients that accept event streams", FAIL,
                      f"It answered HTTP {status} to this app's request (Accept: application/json) and worked when text/event-stream was also accepted. "
                      "This app's MCP client doesn't send that yet.",
                      "Send this report to the app maintainers.")
        else:
            stage.add("http_status", f"The server rejected the request format (HTTP {status})", FAIL, server_said, "")
        return stage
    if status == 400 and "session" in body.lower():
        stage.add("http_status", "The server requires an MCP session", FAIL,
                  "It expects an initialize request before tools/list. This app sends each request on its own. " + server_said,
                  "Send this report to the app maintainers.")
        return stage
    if status == 429:
        stage.add("http_status", "The server is limiting requests (HTTP 429)", WARN, server_said, "Wait a minute and run the checks again.")
        return stage
    if status >= 500:
        stage.add("http_status", f"The MCP server had an internal error (HTTP {status})", FAIL, server_said,
                  "Check the MCP Server app and Splunk logs on the server.")
        return stage
    if not 200 <= status < 300:
        stage.add("http_status", f"The server answered HTTP {status}", FAIL, server_said, "")
        return stage
    if "text/html" in content_type:
        title = _html_title(body)
        stage.add("http_status", "Got a web page instead of an MCP response", FAIL,
                  f"The server answered with HTML{f' (page title: {title})' if title else ''}.",
                  "This URL isn't the MCP endpoint. Check the port (usually 8089) and the path (/services/mcp).")
        return stage

    parsed, from_stream = _parse_mcp_body(body)
    if parsed is None:
        stage.add("http_status", "The reply isn't valid JSON", FAIL, server_said, "Check that the URL points at an MCP server.")
        return stage
    stage.add("http_status", f"The MCP server answered (HTTP {status})", PASS, f"Reply in {elapsed} ms.")
    if from_stream:
        stage.add("event_stream", "The server replied with an event stream", WARN,
                  "Discovery reads that format, but the chat tool catalog expects plain JSON, so the tool list there may be empty.",
                  "Send this report to the app maintainers if chat can't see the MCP tools.")
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), dict):
        error = parsed["error"]
        message = str(error.get("message") or error)
        fix = "Check that the token's user can use the MCP Server app." if re.search(r"auth|permission|forbidden|token", message, re.I) else ""
        stage.add("rpc", f"The MCP server returned an error: {message}", FAIL, f"JSON-RPC error code {error.get('code')}.", fix)
        return stage
    result = parsed.get("result") if isinstance(parsed, dict) else None
    if result is None:
        stage.add("rpc", "The reply has no result", WARN, _snippet(json.dumps(parsed)), "Check that the URL points at an MCP server.")
        return stage
    tools = _tool_names(result)
    if tools:
        listed = ", ".join(tools[:8]) + (", ..." if len(tools) > 8 else "")
        stage.add("tools", f"{len(tools)} MCP tools are available", PASS, listed)
    else:
        stage.add("tools", "The server returned no tools", WARN, "",
                  "The token's user may not have access to any MCP tools, or no tools are enabled in the MCP Server app.")
    return stage


def classify_llm_error(message: str, provider: str, model: str, local: bool) -> Tuple[str, str]:
    text = message or ""
    lowered = text.lower()
    key_page = LLM_KEY_PAGES.get(provider, "the provider console")
    if "not installed on this ollama server" in lowered:
        return f"{model} isn't installed in Ollama", f"Run: ollama pull {model}"
    if "insufficient_quota" in lowered or "exceeded your current quota" in lowered:
        return "The provider account has no remaining quota", "Add billing or credits to the provider account."
    if re.search(r"\b401\b", text) or "unauthorized" in lowered or "invalid_api_key" in lowered or "incorrect api key" in lowered or "rejected the api key" in lowered:
        return "The provider rejected the API key (HTTP 401)", f"Check that the key is complete and still active. Create or copy one at {key_page}."
    if re.search(r"\b403\b", text) or "permission" in lowered or "forbidden" in lowered:
        return "The API key isn't allowed to use this model or endpoint (HTTP 403)", "Check the key's project, organization, region, or model access."
    if re.search(r"\b404\b", text) or "model_not_found" in lowered or "does not exist" in lowered or "not found" in lowered:
        return "The model or endpoint wasn't found (HTTP 404)", (
            "Check the model name (Load Models lists what this key can use)"
            + (" and the base URL, which often ends in /v1." if provider == "custom" else ".")
        )
    if re.search(r"\b429\b", text) or "rate limit" in lowered:
        return "The provider is limiting requests (HTTP 429)", "Wait a minute and try again, or use a key with higher limits."
    if "certificate_verify_failed" in lowered or "certificate verify failed" in lowered:
        return "The provider's certificate isn't trusted", (
            "If your network inspects HTTPS, start the app with SSL_CERT_FILE pointing at your company's CA bundle."
        )
    if "timed out" in lowered or "timeout" in lowered:
        return "The provider didn't answer in time", (
            "Local models can take a while to load. Try again, or raise the request timeout under Advanced settings."
            if local else "Check your network or proxy, then try again."
        )
    if "connection refused" in lowered or "all connection attempts failed" in lowered or "not reachable" in lowered or "connect" in lowered:
        return "Couldn't connect to the provider", (
            "Start the model server (Ollama: open the Ollama app or run ollama serve; LM Studio: start the local server)."
            if local else "Check your network or proxy settings."
        )
    if "empty response" in lowered:
        return "The model returned an empty reply", "Try another model, or raise max tokens (reasoning models can use the whole budget thinking)."
    return (text.strip().splitlines() or ["The test failed"])[0][:200], ""


async def llm_response_stage(
    draft: LLMDraft,
    endpoint: Endpoint,
    runner: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
    *,
    reachable: bool,
) -> Stage:
    stage = Stage("response", "AI provider response")
    if not reachable:
        return stage.skip("Skipped: the provider couldn't be reached")
    local = endpoint.ok and (endpoint.host in {"localhost", "127.0.0.1", "::1"} or draft.provider == "ollama")
    try:
        result = await runner(draft.test_payload())
    except Exception as exc:
        title, fix = classify_llm_error(f"{type(exc).__name__}: {exc}", draft.provider, draft.model, local)
        stage.add("connection", title, FAIL, f"{type(exc).__name__}: {exc}", fix)
        return stage
    tests = result.get("tests") if isinstance(result, dict) else None
    if not isinstance(tests, dict) or not tests:
        message = str((result or {}).get("message") or (result or {}).get("error") or "The test returned no results")
        title, fix = classify_llm_error(message, draft.provider, draft.model, local)
        stage.add("connection", title, FAIL, message, fix)
        return stage
    labels = {"connection": "The provider answered", "model": f"{draft.model or 'The model'} replied", "max_tokens": "Suggested settings"}
    for key in ("connection", "model", "max_tokens"):
        entry = tests.get(key)
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status") or "").lower()
        message = str(entry.get("message") or "")
        if status == "success":
            detail = message
            if key == "model" and entry.get("response_preview"):
                detail += f" Reply: \u201c{entry['response_preview']}\u201d"
            stage.add(key, labels[key], PASS if key != "max_tokens" else INFO, detail)
        elif status in {"warning", "info"}:
            stage.add(key, labels[key] if status == "info" else message, INFO if status == "info" else WARN,
                      message if status == "info" else "")
        else:
            title, fix = classify_llm_error(message, draft.provider, draft.model, local)
            stage.add(key, title, FAIL, message, fix)
    models = result.get("available_models") if isinstance(result, dict) else None
    if isinstance(models, list) and models and draft.model and draft.model not in models:
        stage.add("model_listed", f"{draft.model} isn't in the provider's model list", WARN,
                  "Available: " + ", ".join(models[:10]) + (", ..." if len(models) > 10 else ""),
                  "Pick a model from the list.")
    return stage


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def _skipped(stage_id: str, title: str, reason: str) -> Stage:
    return Stage(stage_id, title).skip(reason)


async def run_mcp_diagnostics(
    payload: Dict[str, Any],
    *,
    config_manager: Any,
    project_root: Path,
    startup: Dict[str, Any],
    own_port: Optional[int],
    account: Dict[str, Any],
    activate: bool,
    validation_errors: List[str],
) -> Dict[str, Any]:
    config = config_manager.get()
    preferred_port = _as_int(getattr(config.server, "port", 8003), 8003)
    stages = [await app_stage(project_root=project_root, startup=startup, own_port=own_port,
                              preferred_port=preferred_port, account=account)]
    draft = build_mcp_draft(payload, config_manager)
    secrets = [draft.token, draft.token_raw]
    if not account.get("can_manage"):
        for stage_id, title in (("values", "Values entered"), ("saving", "Saving"), ("network", "Network"), ("response", "MCP server response")):
            stages.append(_skipped(stage_id, title, "Skipped: needs an admin account"))
        return build_report("mcp", draft.url, stages, secrets)

    values, endpoint = mcp_values_stage(draft, validation_errors)
    stages.append(values)
    if payload.get("check_save", True):
        plan, apply = mcp_save_plan(config, draft, activate)
        stages.append(storage_stage(config_manager, project_root, plan=plan, apply=apply))
    else:
        stages.append(_skipped("saving", "Saving", "Skipped: saving checks were turned off"))
    if payload.get("check_connection", True):
        hint = (
            "Check the port number (Splunk's management port, where the MCP Server app answers, is usually 8089) "
            "and that Splunk is running on that host."
        )
        network, reachable = await network_stage(endpoint, kind="mcp", verify=draft.verify_ssl,
                                                 ca_bundle=draft.ca_bundle_path, local_server_hint=hint)
        stages.append(network)
        stages.append(await mcp_response_stage(draft, endpoint, reachable=reachable))
    else:
        stages.append(_skipped("network", "Network", "Skipped: connection checks were turned off"))
        stages.append(_skipped("response", "MCP server response", "Skipped: connection checks were turned off"))
    return build_report("mcp", draft.url, stages, secrets)


async def run_llm_diagnostics(
    payload: Dict[str, Any],
    *,
    config_manager: Any,
    project_root: Path,
    startup: Dict[str, Any],
    own_port: Optional[int],
    account: Dict[str, Any],
    activate: bool,
    validation_errors: List[str],
    normalize_provider: Callable[[Any], str],
    effective_endpoint: Callable[[str, Optional[str]], str],
    runner: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
) -> Dict[str, Any]:
    config = config_manager.get()
    preferred_port = _as_int(getattr(config.server, "port", 8003), 8003)
    stages = [await app_stage(project_root=project_root, startup=startup, own_port=own_port,
                              preferred_port=preferred_port, account=account)]
    draft = build_llm_draft(payload, config_manager, normalize_provider=normalize_provider,
                            effective_endpoint=effective_endpoint)
    secrets = [draft.api_key, draft.api_key_raw]
    target = f"{draft.provider} {draft.model} at {draft.effective_endpoint}".strip()
    if not account.get("can_manage"):
        for stage_id, title in (("values", "Values entered"), ("saving", "Saving"), ("network", "Network"), ("response", "AI provider response")):
            stages.append(_skipped(stage_id, title, "Skipped: needs an admin account"))
        return build_report("llm", target, stages, secrets)

    values, endpoint = llm_values_stage(draft, validation_errors)
    stages.append(values)
    if payload.get("check_save", True):
        plan, apply = llm_save_plan(config, draft, activate)
        stages.append(storage_stage(config_manager, project_root, plan=plan, apply=apply))
    else:
        stages.append(_skipped("saving", "Saving", "Skipped: saving checks were turned off"))
    if payload.get("check_connection", True):
        local = endpoint.ok and (endpoint.host in {"localhost", "127.0.0.1", "::1"} or draft.provider == "ollama")
        hint = (
            "Start the model server (Ollama: open the Ollama app or run ollama serve; LM Studio: start the local server) "
            "and check the port in the endpoint URL."
            if local else "Check the endpoint URL's host and port."
        )
        network, reachable = await network_stage(endpoint, kind="llm", verify=True, ca_bundle=None, local_server_hint=hint)
        stages.append(network)
        stages.append(await llm_response_stage(draft, endpoint, runner, reachable=reachable))
    else:
        stages.append(_skipped("network", "Network", "Skipped: connection checks were turned off"))
        stages.append(_skipped("response", "AI provider response", "Skipped: connection checks were turned off"))
    return build_report("llm", target, stages, secrets)
