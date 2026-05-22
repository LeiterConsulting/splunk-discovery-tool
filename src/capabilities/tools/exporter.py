"""Deterministic export bundle generation for DT4SMS discovery artifacts."""

import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from capabilities.models import CapabilityConfig, CapabilityDefinition


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalize_operator_voice(value: Any, default: str = "direct") -> str:
    voice = str(value or default).strip().lower()
    return voice if voice in {"direct", "evidence", "executive"} else default


def _operator_voice_label(value: Any) -> str:
    voice = _normalize_operator_voice(value)
    if voice == "evidence":
        return "Evidence-led"
    if voice == "executive":
        return "Executive Brief"
    return "Direct Ops"


class DeterministicExportProvider:
    """Build deterministic session export bundles without third-party exporters."""

    SESSION_PATTERN = re.compile(r"_(\d{8}_\d{6})(?:\.|$)")
    SUMMARY_INFOGRAPHIC_PATTERN = re.compile(r"^summary_infographic_(\d{8}_\d{6})(?:_\d{8}_\d{6})?\.[A-Za-z0-9]+$")
    SUMMARY_INFOGRAPHIC_DIRNAME = "summary_infographics"

    def __init__(self, config: CapabilityConfig, definition: CapabilityDefinition):
        self.config = config
        self.definition = definition

    def get_output_dir(self) -> Path:
        configured = self.config.config.get("source_dir", self.definition.default_config.get("source_dir", "output"))
        return Path(str(configured or "output"))

    def get_export_dir(self) -> Path:
        configured = self.config.config.get("export_dir", self.definition.default_config.get("export_dir", "output/exports"))
        return Path(str(configured or "output/exports"))

    def max_bundle_files(self) -> int:
        configured = self.config.config.get("max_bundle_files", self.definition.default_config.get("max_bundle_files", 12))
        return max(2, min(_safe_int(configured, 12), 24))

    def supported_outputs(self) -> List[str]:
        allowed_outputs = {"bundle_zip", "manifest_json", "summary_markdown"}
        configured = self.config.config.get(
            "formats",
            self.definition.default_config.get("formats", ["bundle_zip", "manifest_json", "summary_markdown"]),
        )
        if isinstance(configured, list):
            values = [str(item).strip() for item in configured if str(item).strip() in allowed_outputs]
            return values or ["bundle_zip", "manifest_json", "summary_markdown"]
        return ["bundle_zip", "manifest_json", "summary_markdown"]

    def get_runtime_summary(self) -> Dict[str, Any]:
        output_dir = self.get_output_dir()
        export_dir = self.get_export_dir()
        sessions = self._load_sessions(output_dir)
        latest_bundle = self._latest_bundle(export_dir)
        package_archives = self._list_package_archives(export_dir)
        return {
            "output_dir": str(output_dir),
            "export_dir": str(export_dir),
            "supported_outputs": self.supported_outputs(),
            "max_bundle_files": self.max_bundle_files(),
            "available_session_count": len(sessions),
            "latest_session_timestamp": sessions[0].get("timestamp") if sessions else None,
            "bundle_count": len(package_archives),
            "latest_bundle": latest_bundle,
        }

    def build_export(self, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        request = payload if isinstance(payload, dict) else {}
        output_dir = self.get_output_dir()
        if not output_dir.exists():
            raise ValueError("The output directory does not exist yet. Run discovery before building report packages.")

        export_dir = self.get_export_dir()
        export_dir.mkdir(parents=True, exist_ok=True)

        sessions = self._load_sessions(output_dir)
        timestamp = self._resolve_timestamp(request, sessions)
        if not timestamp:
            raise ValueError("No discovery session could be resolved for export generation.")

        persona = self._normalize_persona(request.get("persona"))
        voice = _normalize_operator_voice(request.get("voice"))
        voice_label = _operator_voice_label(voice)
        artifacts = self._resolve_artifacts(output_dir, timestamp, request, sessions)
        if not artifacts:
            raise ValueError("No discovery artifacts were found for the selected discovery session.")

        runbook_markdown = str(request.get("runbook_markdown") or "").strip()
        runbook_filename = self._normalize_generated_filename(
            request.get("runbook_filename") or f"runbook_{persona}_{voice}_{timestamp}.md",
            default_name=f"runbook_{persona}_{voice}_{timestamp}.md",
        )

        bundle_stem = self._build_bundle_stem(timestamp, persona, voice, request.get("title"))
        manifest_path = export_dir / f"{bundle_stem}_manifest.json"
        summary_path = export_dir / f"{bundle_stem}_summary.md"
        zip_path = export_dir / f"{bundle_stem}.zip"

        manifest = self._build_manifest(
            timestamp=timestamp,
            persona=persona,
            voice=voice,
            title=request.get("title"),
            artifacts=artifacts,
            runbook_filename=runbook_filename if runbook_markdown else None,
            output_dir=output_dir,
            sessions=sessions,
        )
        summary_markdown = self._build_summary_markdown(manifest)

        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        summary_path.write_text(summary_markdown, encoding="utf-8")

        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(manifest_path, arcname="manifest.json")
            archive.write(summary_path, arcname="README.md")
            for artifact in artifacts:
                archive.write(artifact["path"], arcname=f"artifacts/{artifact['name']}")
            if runbook_markdown:
                archive.writestr(f"generated/{runbook_filename}", runbook_markdown)

        return {
            "bundle_type": "discovery_bundle",
            "bundle_name": zip_path.name,
            "download_name": zip_path.name,
            "download_path": zip_path.name,
            "manifest_name": manifest_path.name,
            "summary_name": summary_path.name,
            "bundle_path": str(zip_path),
            "artifact_count": len(artifacts),
            "session_timestamp": timestamp,
            "persona": persona,
            "operator_voice": voice,
            "operator_voice_label": voice_label,
            "supported_outputs": self.supported_outputs(),
            "generated_at": manifest["generated_at"],
            "bundle_size_bytes": zip_path.stat().st_size,
            "included_files": [artifact["name"] for artifact in artifacts],
            "generated_files": [
                manifest_path.name,
                summary_path.name,
                zip_path.name,
                *([runbook_filename] if runbook_markdown else []),
            ],
            "manifest": manifest,
        }

    def _resolve_timestamp(self, request: Dict[str, Any], sessions: List[Dict[str, Any]]) -> Optional[str]:
        requested = str(request.get("timestamp") or "").strip()
        if requested and requested.lower() != "latest":
            return requested

        artifact_names = request.get("artifact_names") if isinstance(request.get("artifact_names"), list) else []
        for artifact_name in artifact_names:
            timestamp = self._extract_session_timestamp(str(artifact_name))
            if timestamp:
                return timestamp

        if sessions:
            return str(sessions[0].get("timestamp") or "").strip() or None
        return None

    def _resolve_artifacts(
        self,
        output_dir: Path,
        timestamp: str,
        request: Dict[str, Any],
        sessions: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        requested_names = request.get("artifact_names") if isinstance(request.get("artifact_names"), list) else []
        artifact_names = [self._sanitize_existing_filename(name) for name in requested_names if self._sanitize_existing_filename(name)]

        if not artifact_names:
            session = next((item for item in sessions if str(item.get("timestamp") or "") == timestamp), None)
            if session and isinstance(session.get("report_paths"), list):
                artifact_names = [
                    self._sanitize_existing_filename(name)
                    for name in session.get("report_paths", [])
                    if self._sanitize_existing_filename(name)
                ]

        if not artifact_names:
            artifact_names = [
                path.name
                for path in sorted(output_dir.glob(f"v2_*_{timestamp}.*"))
                if path.is_file()
            ]

        unique_names: List[str] = []
        for name in artifact_names:
            if name not in unique_names:
                unique_names.append(name)

        artifacts: List[Dict[str, Any]] = []
        for name in unique_names[: self.max_bundle_files()]:
            path = self._resolve_artifact_path(output_dir, name)
            if not path.exists() or not path.is_file():
                continue
            artifacts.append(
                {
                    "name": path.name,
                    "path": path,
                    "size_bytes": path.stat().st_size,
                    "modified_at": datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
                    "type": path.suffix[1:] if path.suffix else "unknown",
                }
            )
        return artifacts

    def _resolve_artifact_path(self, output_dir: Path, name: str) -> Path:
        candidates = [
            output_dir / name,
            output_dir / self.SUMMARY_INFOGRAPHIC_DIRNAME / name,
        ]
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate
        return output_dir / name

    def _session_has_meaningful_discovery_data(self, session: Dict[str, Any]) -> bool:
        overview = session.get("overview", {}) if isinstance(session, dict) else {}
        if isinstance(overview, dict) and any(value not in (None, "", [], {}, 0) for value in overview.values()):
            return True

        personas = session.get("personas", {}) if isinstance(session, dict) else {}
        if isinstance(personas, dict) and any(personas.values()):
            return True

        mcp_capabilities = session.get("mcp_capabilities", {}) if isinstance(session, dict) else {}
        if isinstance(mcp_capabilities, dict) and any(mcp_capabilities.values()):
            return True

        readiness_score = session.get("readiness_score") if isinstance(session, dict) else None
        if readiness_score not in (None, "", 0):
            return True

        stats = session.get("stats", {}) if isinstance(session, dict) else {}
        if isinstance(stats, dict):
            for value in stats.values():
                try:
                    if int(value) > 0:
                        return True
                except (TypeError, ValueError):
                    continue

        return False

    def _normalize_sessions(self, sessions: List[Dict[str, Any]], output_dir: Path) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []

        for session in sessions:
            if not isinstance(session, dict):
                continue

            timestamp = str(session.get("timestamp") or "").strip()
            if not timestamp:
                continue

            raw_report_paths = session.get("report_paths", [])
            report_paths = raw_report_paths if isinstance(raw_report_paths, list) else []
            clean_report_paths: List[str] = []

            for report_name in report_paths:
                safe_report_name = Path(str(report_name or "")).name
                if not safe_report_name:
                    continue
                if self._extract_session_timestamp(safe_report_name) != timestamp:
                    continue
                artifact_path = self._resolve_artifact_path(output_dir, safe_report_name)
                if not artifact_path.exists() or not artifact_path.is_file():
                    continue
                if safe_report_name not in clean_report_paths:
                    clean_report_paths.append(safe_report_name)

            normalized_session = dict(session)
            normalized_session["report_paths"] = clean_report_paths

            if not clean_report_paths and not self._session_has_meaningful_discovery_data(normalized_session):
                continue

            normalized.append(normalized_session)

        return sorted(normalized, key=lambda item: str(item.get("timestamp") or ""), reverse=True)

    def _load_sessions(self, output_dir: Path) -> List[Dict[str, Any]]:
        manifest_path = output_dir / "discovery_sessions.json"
        if manifest_path.exists():
            try:
                payload = json.loads(manifest_path.read_text(encoding="utf-8"))
                if isinstance(payload, list):
                    normalized = self._normalize_sessions(payload, output_dir)
                    if normalized != payload:
                        manifest_path.write_text(json.dumps(normalized, indent=2), encoding="utf-8")
                    return normalized
            except Exception:
                pass

        sessions: Dict[str, Dict[str, Any]] = {}
        infographic_dir = output_dir / self.SUMMARY_INFOGRAPHIC_DIRNAME
        artifact_paths = [
            *sorted(output_dir.glob("v2_*")),
            *(sorted(infographic_dir.glob("summary_infographic_*")) if infographic_dir.exists() else []),
        ]
        for path in artifact_paths:
            if not path.is_file():
                continue
            timestamp = self._extract_session_timestamp(path.name)
            if not timestamp:
                continue
            entry = sessions.setdefault(
                timestamp,
                {
                    "timestamp": timestamp,
                    "created_at": datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
                    "overview": {},
                    "report_paths": [],
                },
            )
            entry["report_paths"].append(path.name)

        return sorted(sessions.values(), key=lambda item: str(item.get("timestamp") or ""), reverse=True)

    def _extract_session_timestamp(self, artifact_name: str) -> Optional[str]:
        infographic_match = self.SUMMARY_INFOGRAPHIC_PATTERN.match(str(artifact_name or ""))
        if infographic_match:
            return infographic_match.group(1)

        if str(artifact_name or "").startswith("summary_infographic_"):
            return None

        generic_matches = re.findall(r"(\d{8}_\d{6})", str(artifact_name or ""))
        if generic_matches:
            return generic_matches[0]
        return None

    def _build_manifest(
        self,
        timestamp: str,
        persona: str,
        voice: str,
        title: Any,
        artifacts: List[Dict[str, Any]],
        runbook_filename: Optional[str],
        output_dir: Path,
        sessions: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        session = next((item for item in sessions if str(item.get("timestamp") or "") == timestamp), None)
        overview = session.get("overview", {}) if isinstance(session, dict) and isinstance(session.get("overview", {}), dict) else {}
        return {
            "schema_version": "1.0",
            "capability": "export_tools",
            "bundle_type": "discovery_bundle",
            "generated_at": _utc_now_iso(),
            "title": str(title or f"DT4SMS Report Package {timestamp}").strip(),
            "session_timestamp": timestamp,
            "persona": persona,
            "operator_voice": voice,
            "operator_voice_label": _operator_voice_label(voice),
            "source_dir": str(output_dir),
            "artifact_count": len(artifacts),
            "overview": overview,
            "included_artifacts": [
                {
                    "name": artifact["name"],
                    "type": artifact["type"],
                    "size_bytes": artifact["size_bytes"],
                    "modified_at": artifact["modified_at"],
                }
                for artifact in artifacts
            ],
            "generated_runtime_files": [
                item
                for item in [runbook_filename]
                if item
            ],
            "supported_outputs": self.supported_outputs(),
        }

    def _build_summary_markdown(self, manifest: Dict[str, Any]) -> str:
        overview = manifest.get("overview", {}) if isinstance(manifest.get("overview", {}), dict) else {}
        artifact_lines = [
            f"- {artifact.get('name', 'artifact')} ({artifact.get('type', 'file')}, {artifact.get('size_bytes', 0)} bytes)"
            for artifact in manifest.get("included_artifacts", [])
            if isinstance(artifact, dict)
        ]
        runtime_lines = [
            f"- {filename}"
            for filename in manifest.get("generated_runtime_files", [])
            if isinstance(filename, str) and filename.strip()
        ]
        return "\n".join(
            [
                "# DT4SMS Report Package",
                "",
                f"- Generated: {manifest.get('generated_at', '')}",
                f"- Session: {manifest.get('session_timestamp', 'unknown')}",
                f"- Persona: {str(manifest.get('persona', 'admin')).title()}",
                f"- Operator Voice: {manifest.get('operator_voice_label', _operator_voice_label(manifest.get('operator_voice')))}",
                f"- Artifact Count: {manifest.get('artifact_count', 0)}",
                "",
                "## Environment Snapshot",
                "",
                f"- Indexes: {overview.get('total_indexes', 0)}",
                f"- Sourcetypes: {overview.get('total_sourcetypes', 0)}",
                f"- Hosts: {overview.get('total_hosts', 0)}",
                f"- Data Volume 24h: {overview.get('data_volume_24h', 'unknown')}",
                "",
                "## Included Artifacts",
                "",
                *(artifact_lines or ["- No artifacts included"]),
                "",
                "## Generated Files",
                "",
                *(runtime_lines or ["- No runtime-generated files included"]),
            ]
        ).strip() + "\n"

    def _latest_bundle(self, export_dir: Path) -> Optional[Dict[str, Any]]:
        if not export_dir.exists():
            return None
        candidates = sorted(self._list_package_archives(export_dir), key=lambda item: item.stat().st_mtime, reverse=True)
        if not candidates:
            return None
        latest = candidates[0]
        return {
            "name": latest.name,
            "size_bytes": latest.stat().st_size,
            "modified_at": datetime.fromtimestamp(latest.stat().st_mtime).isoformat(),
        }

    @staticmethod
    def _list_package_archives(export_dir: Path) -> List[Path]:
        if not export_dir.exists():
            return []
        candidates = {
            *export_dir.glob("dt4sms_report_package_*.zip"),
            *export_dir.glob("dt4sms_export_*.zip"),
        }
        return [path for path in candidates if path.is_file()]

    @staticmethod
    def _normalize_persona(value: Any) -> str:
        candidate = str(value or "admin").strip().lower()
        return candidate if candidate in {"admin", "analyst", "executive"} else "admin"

    @staticmethod
    def _sanitize_existing_filename(value: Any) -> Optional[str]:
        candidate = str(value or "").strip().replace("\\", "/")
        if not candidate:
            return None
        name = Path(candidate).name
        if not name or name in {".", ".."}:
            return None
        return name

    @staticmethod
    def _normalize_generated_filename(value: Any, default_name: str) -> str:
        candidate = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(value or "").strip())
        return candidate or default_name

    @staticmethod
    def _build_bundle_stem(timestamp: str, persona: str, voice: str, title: Any) -> str:
        raw_title = str(title or "").strip().lower()
        safe_title = re.sub(r"[^a-z0-9]+", "_", raw_title).strip("_")[:40]
        safe_title = safe_title.replace("bundle", "package")
        if safe_title:
            return f"dt4sms_report_package_{timestamp}_{persona}_{voice}_{safe_title}"
        return f"dt4sms_report_package_{timestamp}_{persona}_{voice}"
