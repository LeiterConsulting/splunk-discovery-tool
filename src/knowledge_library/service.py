"""Glue between the web routes and the knowledge library: status, background refresh, and packs."""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import httpx

from knowledge_library.catalog import build_catalog
from knowledge_library.profile import build_environment_profile
from knowledge_library.scorecard import build_scorecard
from knowledge_library.sources import (
    DOC_PRODUCTS,
    ONLINE_SOURCE_HOSTS,
    SOURCE_NAMES,
    LibrarySourceError,
    LibraryStore,
    create_library_http_client,
    export_pack,
    fetch_help_docs,
    fetch_security_content,
    fetch_splunkbase,
    import_pack,
    parse_iso,
    utc_now_iso,
)

AUTO_REFRESH_DAYS = 7
AUTO_RETRY_MINUTES = 60
MAX_STATUS_SOURCETYPES = 500
MAX_STATUS_APPS = 600


class LibraryBusyError(RuntimeError):
    """A refresh is already running."""


class KnowledgeLibraryService:
    def __init__(self, root: Path):
        self.store = LibraryStore(root)
        self._task: Optional[asyncio.Task] = None
        self._job: Dict[str, Any] = {"state": "idle"}
        self._last_auto_attempt: Optional[datetime] = None

    # -- refresh -----------------------------------------------------------

    def is_refreshing(self) -> bool:
        return self._task is not None and not self._task.done()

    def job_snapshot(self) -> Dict[str, Any]:
        if self._job.get("state") == "idle":
            last = self.store.load_state().get("last_refresh")
            if isinstance(last, dict):
                return {**last, "state": last.get("state") or "idle", "previous": True}
        return dict(self._job)

    def start_refresh(
        self,
        profile: Dict[str, Any],
        *,
        sources: Optional[Iterable[str]] = None,
        reason: str = "manual",
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> Dict[str, Any]:
        if self.is_refreshing():
            return self.job_snapshot()
        wanted = [name for name in (sources or SOURCE_NAMES) if name in SOURCE_NAMES]
        self._job = {
            "state": "running",
            "reason": reason,
            "sources": wanted,
            "started_at": utc_now_iso(),
            "stage": "",
            "done": 0,
            "total": 0,
            "results": {},
        }
        self._task = asyncio.get_running_loop().create_task(self._run_refresh(profile, wanted, reason, transport))
        return self.job_snapshot()

    async def wait_for_refresh(self) -> Dict[str, Any]:
        if self._task is not None:
            await asyncio.shield(self._task)
        return self.job_snapshot()

    def _progress(self, stage: str, done: int, total: int) -> None:
        self._job.update(stage=stage, done=done, total=total)

    async def _run_refresh(self, profile: Dict[str, Any], wanted: List[str], reason: str, transport: Optional[httpx.AsyncBaseTransport]) -> None:
        results: Dict[str, Dict[str, Any]] = {}
        apps = [app for app in (profile.get("apps") or {}).get("items") or [] if not app.get("builtin")]
        try:
            async with create_library_http_client(transport) as client:
                if "security_content" in wanted:
                    self._progress("security_content", 0, 0)
                    try:
                        payload = await fetch_security_content(client, self._progress)
                        self.store.save_source("security_content", payload)
                        results["security_content"] = {"status": "ok", "count": len(payload["data_sources"]), "version": payload.get("version")}
                    except LibrarySourceError as exc:
                        results["security_content"] = {"status": "error", "error": str(exc)[:400]}
                if "splunkbase" in wanted:
                    self._progress("splunkbase", 0, 0)
                    existing = self.store.load_source("splunkbase") or {}
                    if reason == "apps":
                        known = set((existing.get("apps") or {}).keys()) | {str(name).lower() for name in existing.get("not_found") or []}
                        uids: List[int] = []
                        appids = [app["name"] for app in apps if app["name"].lower() not in known]
                    else:
                        security_content = self.store.load_source("security_content") or {}
                        uids = [
                            ta["splunkbase_uid"]
                            for entry in security_content.get("data_sources") or []
                            for ta in entry.get("supported_tas") or []
                            if ta.get("splunkbase_uid")
                        ]
                        appids = [app["name"] for app in apps]
                    try:
                        payload = await fetch_splunkbase(client, uids=uids, appids=appids, existing=existing, progress=self._progress)
                        self.store.save_source("splunkbase", payload)
                        results["splunkbase"] = {"status": "ok", "count": len(payload["apps"]), "failed_lookups": payload.get("failed_lookups", 0)}
                    except LibrarySourceError as exc:
                        results["splunkbase"] = {"status": "error", "error": str(exc)[:400]}
                if "help_docs" in wanted:
                    self._progress("help_docs", 0, len(DOC_PRODUCTS))
                    try:
                        payload = await fetch_help_docs(client, progress=self._progress)
                        self.store.save_source("help_docs", payload)
                        results["help_docs"] = {
                            "status": "ok",
                            "count": sum(product["page_count"] for product in payload["products"].values()),
                            "errors": payload.get("errors") or [],
                        }
                    except LibrarySourceError as exc:
                        results["help_docs"] = {"status": "error", "error": str(exc)[:400]}
        except Exception as exc:  # noqa: BLE001 - the job must always finish with a recorded state
            results["_unexpected"] = {"status": "error", "error": f"{type(exc).__name__}: {exc}"[:400]}
        finally:
            ok = [name for name, result in results.items() if result.get("status") == "ok"]
            state = "completed" if ok and len(ok) == len(results) else ("partial" if ok else "failed")
            self._job.update(state=state, finished_at=utc_now_iso(), results=results, stage="")
            try:
                self.store.save_state({"last_refresh": dict(self._job)})
            except OSError:
                pass

    def maybe_auto_refresh(self, profile: Dict[str, Any], allow_online: bool, pending_lookups: List[str], now: Optional[datetime] = None) -> Optional[str]:
        """Start a refresh when sources are missing or older than a week, or new apps need a Splunkbase lookup."""
        if not allow_online or self.is_refreshing():
            return None
        now = now or datetime.now(timezone.utc)
        if self._last_auto_attempt and now - self._last_auto_attempt < timedelta(minutes=AUTO_RETRY_MINUTES):
            return None
        summary = self.store.summary()
        fetched = [parse_iso(entry.get("fetched_at")) for entry in summary.values() if entry.get("available")]
        missing = any(not entry.get("available") for entry in summary.values())
        stale = any(stamp is None or now - stamp > timedelta(days=AUTO_REFRESH_DAYS) for stamp in fetched)
        if missing or stale:
            reason, sources = "scheduled", None
        elif pending_lookups and profile.get("available"):
            reason, sources = "apps", ["splunkbase"]
        else:
            return None
        self._last_auto_attempt = now
        self.start_refresh(profile, sources=sources, reason=reason)
        return reason

    # -- packs -------------------------------------------------------------

    def import_pack(self, data: bytes) -> Dict[str, Any]:
        if self.is_refreshing():
            raise LibraryBusyError("Wait for the source refresh to finish, then import the pack.")
        return import_pack(self.store, data)

    def export_pack(self) -> bytes:
        return export_pack(self.store)

    # -- status ------------------------------------------------------------

    def build_status(
        self,
        blueprint: Optional[Dict[str, Any]],
        kb_assets: Optional[List[Dict[str, Any]]],
        *,
        allow_online: bool,
        can_manage: bool,
        auto_refresh: bool = True,
    ) -> Dict[str, Any]:
        profile = build_environment_profile(blueprint)
        sources = self.store.load_sources()
        summary = self.store.summary()
        catalog = build_catalog(profile, sources) if profile.get("available") else None
        auto_started = None
        if auto_refresh:
            auto_started = self.maybe_auto_refresh(profile, allow_online, (catalog or {}).get("pending_splunkbase_lookups") or [])
        scorecard = build_scorecard(profile, catalog, kb_assets, summary)
        apps = profile.get("apps") or {}
        app_items = apps.get("items") or []
        catalog_payload = None
        if catalog:
            app_entries = sorted(catalog["apps"], key=lambda entry: (entry["builtin"], entry["label"].lower()))
            catalog_payload = {
                "sourcetypes": catalog["sourcetypes"][:MAX_STATUS_SOURCETYPES],
                "sourcetype_total": len(catalog["sourcetypes"]),
                "apps": app_entries[:MAX_STATUS_APPS],
                "app_total": len(app_entries),
                "platform_docs": catalog["platform_docs"],
                "app_docs": catalog["app_docs"],
                "pending_splunkbase_lookups": catalog["pending_splunkbase_lookups"],
            }
        return {
            "status": "success",
            "settings": {
                "allow_online_sources": bool(allow_online),
                "online_hosts": ONLINE_SOURCE_HOSTS,
                "auto_refresh_days": AUTO_REFRESH_DAYS,
            },
            "can_manage": bool(can_manage),
            "profile": {
                "available": bool(profile.get("available")),
                "discovery": profile.get("discovery") or {},
                "splunk": profile.get("splunk") or {},
                "apps": {
                    "collected": bool(apps.get("collected")),
                    "status": apps.get("status") or "",
                    "error": apps.get("error") or "",
                    "total": len(app_items),
                    "addons": len([app for app in app_items if not app.get("builtin")]),
                },
                "sourcetype_count": len(profile.get("sourcetypes") or []),
                "index_count": len(profile.get("indexes") or []),
            },
            "sources": [summary[name] for name in SOURCE_NAMES],
            "refresh": {**self.job_snapshot(), "auto_started": auto_started},
            "scorecard": scorecard,
            "catalog": catalog_payload,
        }
