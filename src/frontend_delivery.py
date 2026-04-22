"""Helpers for validating shipped frontend assets against the legacy inline source."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List

from frontend_legacy import get_frontend_html


STATIC_DIR = Path(__file__).with_name("static")
STATIC_INDEX_PATH = STATIC_DIR / "index.html"
STATIC_APP_PATH = STATIC_DIR / "app.js"
STATIC_BUILD_MANIFEST_PATH = STATIC_DIR / "build-manifest.json"

REQUIRED_LOCAL_SCRIPT_REFS = [
    "/static/vendor/react/react.production.min.js",
    "/static/vendor/react/react-dom.production.min.js",
    "/static/app.js",
]

REQUIRED_LOCAL_STYLE_REFS = [
    "/static/vendor/tailwind/tailwind.min.css",
    "/static/vendor/fontawesome/css/all.min.css",
]

CDN_ASSET_TOKENS = [
    "https://unpkg.com/react@18/umd/react.production.min.js",
    "https://unpkg.com/react-dom@18/umd/react-dom.production.min.js",
    "https://unpkg.com/@babel/standalone/babel.min.js",
    "https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css",
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css",
]

INLINE_BABEL_PATTERN = re.compile(r'<script type="text/babel">([\s\S]*?)</script>\s*</body>', re.IGNORECASE)


def compute_text_sha256(text: str) -> str:
    normalized = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def render_legacy_frontend_html() -> str:
    return get_frontend_html()


def extract_inline_babel_source(html: str) -> str:
    match = INLINE_BABEL_PATTERN.search(str(html or ""))
    if not match:
        raise ValueError("Unable to locate the legacy inline Babel frontend source.")
    return str(match.group(1)).strip()


def compute_source_fingerprint() -> Dict[str, str]:
    legacy_html = render_legacy_frontend_html()
    app_source = extract_inline_babel_source(legacy_html)
    return {
        "legacy_html_sha256": compute_text_sha256(legacy_html),
        "app_source_sha256": compute_text_sha256(app_source),
    }


def _read_text(path: Path) -> str:
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def compute_artifact_fingerprint(static_dir: Path = STATIC_DIR) -> Dict[str, str]:
    index_text = _read_text(static_dir / "index.html")
    app_text = _read_text(static_dir / "app.js")
    return {
        "index_html_sha256": compute_text_sha256(index_text) if index_text else "",
        "app_js_sha256": compute_text_sha256(app_text) if app_text else "",
    }


def load_build_manifest(static_dir: Path = STATIC_DIR) -> Dict[str, Any]:
    manifest_path = static_dir / "build-manifest.json"
    if not manifest_path.exists() or not manifest_path.is_file():
        return {}

    try:
        parsed = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def get_frontend_sync_status(static_dir: Path = STATIC_DIR) -> Dict[str, Any]:
    build_manifest = load_build_manifest(static_dir)
    source_fingerprint = compute_source_fingerprint()
    artifact_fingerprint = compute_artifact_fingerprint(static_dir)
    static_index_text = _read_text(static_dir / "index.html")

    missing_files = [
        str(path.relative_to(static_dir.parent))
        for path in (static_dir / "index.html", static_dir / "app.js", static_dir / "build-manifest.json")
        if not path.exists() or not path.is_file()
    ]
    missing_script_refs = [ref for ref in REQUIRED_LOCAL_SCRIPT_REFS if ref not in static_index_text]
    missing_style_refs = [ref for ref in REQUIRED_LOCAL_STYLE_REFS if ref not in static_index_text]
    cdn_refs = [token for token in CDN_ASSET_TOKENS if token in static_index_text]
    contains_text_babel = "text/babel" in static_index_text

    issues: List[str] = []
    if missing_files:
        issues.append(f"Missing generated frontend asset files: {', '.join(missing_files)}")
    if not build_manifest:
        issues.append("Missing or unreadable frontend build manifest.")
    if build_manifest.get("source") != source_fingerprint:
        issues.append("Legacy inline frontend source has changed without regenerating src/static assets.")
    if build_manifest.get("artifacts") != artifact_fingerprint:
        issues.append("Generated frontend artifacts do not match the recorded build manifest.")
    if missing_script_refs:
        issues.append(f"Static index is missing required local script references: {', '.join(missing_script_refs)}")
    if missing_style_refs:
        issues.append(f"Static index is missing required local stylesheet references: {', '.join(missing_style_refs)}")
    if cdn_refs:
        issues.append(f"Static index still contains CDN runtime references: {', '.join(cdn_refs)}")
    if contains_text_babel:
        issues.append("Static index still contains a text/babel runtime path.")

    return {
        "ok": len(issues) == 0,
        "issues": issues,
        "missing_files": missing_files,
        "missing_script_refs": missing_script_refs,
        "missing_style_refs": missing_style_refs,
        "cdn_refs": cdn_refs,
        "contains_text_babel": contains_text_babel,
        "source_fingerprint": source_fingerprint,
        "artifact_fingerprint": artifact_fingerprint,
        "build_manifest": build_manifest,
    }