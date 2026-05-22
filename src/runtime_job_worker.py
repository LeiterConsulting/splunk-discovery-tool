import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("DT4SMS_RUNTIME_WORKER", "1")

import web_app


def _load_request_payload(path_text: str) -> Dict[str, Any]:
    request_path = Path(path_text)
    with open(request_path, "r", encoding="utf-8") as request_file:
        payload = json.load(request_file)
    try:
        request_path.unlink()
    except OSError:
        pass
    return payload if isinstance(payload, dict) else {}


def _build_discovery_runtime_config(binding: Dict[str, Any]) -> Any:
    runtime_config = web_app.config_manager.get()
    active_name = str(binding.get("active_mcp_config_name") or "").strip()
    clear_runtime_mcp = bool(binding.get("clear_runtime_mcp"))

    if clear_runtime_mcp:
        runtime_config.mcp.url = ""
        runtime_config.mcp.token = ""
        runtime_config.mcp.verify_ssl = False
        runtime_config.mcp.ca_bundle_path = None
        runtime_config.active_mcp_config_name = None
        return runtime_config

    if active_name:
        assigned_config = web_app.config_manager.get_mcp_config(active_name)
        if assigned_config is None:
            runtime_config.mcp.url = ""
            runtime_config.mcp.token = ""
            runtime_config.mcp.verify_ssl = False
            runtime_config.mcp.ca_bundle_path = None
            runtime_config.active_mcp_config_name = None
            return runtime_config

        runtime_config.mcp.url = assigned_config.url
        runtime_config.mcp.token = assigned_config.token
        runtime_config.mcp.verify_ssl = assigned_config.verify_ssl
        runtime_config.mcp.ca_bundle_path = assigned_config.ca_bundle_path
        runtime_config.active_mcp_config_name = active_name

    return runtime_config


async def _run_discovery_job(payload: Dict[str, Any]) -> None:
    scope_info = payload.get("scope") if isinstance(payload.get("scope"), dict) else {}
    scope_key = scope_info.get("scope_key")
    web_app._sync_runtime_state_from_disk()
    web_app._update_discovery_runtime_state(
        scope_key=scope_key,
        scope_label=scope_info.get("scope_label"),
        active_mcp_config_name=scope_info.get("active_mcp_config_name"),
        status="starting",
        worker_pid=os.getpid(),
        execution_mode="worker",
    )
    runtime_config = _build_discovery_runtime_config(payload.get("runtime_binding") or {})
    await web_app.run_discovery(runtime_config=runtime_config, scope_key=scope_key, scope_info=scope_info)


async def _run_summary_job(payload: Dict[str, Any]) -> None:
    session_id = web_app.validate_session_id(payload.get("timestamp") or "")
    scope_key = payload.get("scope_key")
    web_app._sync_runtime_state_from_disk()
    existing_progress = web_app._get_summarization_progress(session_id, scope_key)
    web_app._set_summarization_progress(
        session_id,
        scope_key=scope_key,
        stage="loading",
        progress=max(5, web_app._safe_int(existing_progress.get("progress", 0))),
        message="Summary worker started...",
        worker_pid=os.getpid(),
        execution_mode="worker",
    )
    result = await web_app._summarize_session_impl({"timestamp": session_id, "scope_key": scope_key})
    if isinstance(result, dict) and result.get("error"):
        raise RuntimeError(str(result.get("error")))


async def _run_job(job_type: str, payload: Dict[str, Any]) -> None:
    if job_type == "discovery":
        await _run_discovery_job(payload)
        return
    if job_type == "summary":
        await _run_summary_job(payload)
        return
    raise ValueError(f"Unsupported runtime job type: {job_type}")


def _record_worker_failure(job_type: str, payload: Dict[str, Any], exc: Exception) -> None:
    if job_type == "discovery":
        scope_info = payload.get("scope") if isinstance(payload.get("scope"), dict) else {}
        scope_key = scope_info.get("scope_key")
        web_app._sync_runtime_state_from_disk()
        current_snapshot = web_app._snapshot_discovery_runtime_state(scope_key)
        web_app._update_discovery_runtime_state(
            scope_key=scope_key,
            progress={
                **(current_snapshot.get("progress") or {}),
                "description": f"Discovery failed: {exc}",
            },
        )
        web_app._finalize_discovery_runtime(
            "error",
            scope_key=scope_key,
            error=str(exc),
            worker_pid=None,
        )
        return

    if job_type == "summary":
        session_id_raw = payload.get("timestamp") or ""
        scope_key = payload.get("scope_key")
        try:
            session_id = web_app.validate_session_id(session_id_raw)
        except Exception:
            return

        existing_progress = web_app._get_summarization_progress(session_id, scope_key)
        web_app._set_summarization_progress(
            session_id,
            scope_key=scope_key,
            stage="error",
            progress=existing_progress.get("progress", 0),
            message=f"Summary worker failed: {exc}",
            worker_pid=None,
            execution_mode="worker",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="DT4SMS durable runtime job worker")
    parser.add_argument("job_type", choices=["discovery", "summary"])
    parser.add_argument("request_path")
    args = parser.parse_args()

    payload = _load_request_payload(args.request_path)
    try:
        asyncio.run(_run_job(args.job_type, payload))
        return 0
    except Exception as exc:
        _record_worker_failure(args.job_type, payload, exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())