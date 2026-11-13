"""Glue between the web routes and the knowledge library: status, background refresh, documentation, and packs."""

import asyncio
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import httpx

from knowledge_library.catalog import ADDON_DOC_PREFIX, ADDON_DOC_PRODUCT, build_catalog
from knowledge_library.docs import (
    DOCS_DB_NAME,
    DOCS_DIR_NAME,
    DocIndex,
    build_doc_plan,
    plan_coverage,
    plan_signature,
    rank_doc_results,
    sanitize_docs_payload,
    sync_docs,
)
from knowledge_library.profile import build_environment_profile
from knowledge_library.ranking import EnvironmentTerms, query_terms
from knowledge_library.scorecard import build_scorecard
from knowledge_library.sources import (
    DOC_PRODUCTS,
    ONLINE_SOURCE_HOSTS,
    SOURCE_NAMES,
    LibraryPackError,
    LibrarySourceError,
    LibraryStore,
    create_library_http_client,
    export_pack,
    fetch_help_docs,
    fetch_security_content,
    fetch_splunkbase,
    parse_iso,
    read_pack,
    utc_now_iso,
)

AUTO_REFRESH_DAYS = 7
AUTO_RETRY_MINUTES = 60
MAX_STATUS_SOURCETYPES = 500
MAX_STATUS_APPS = 600
ENVIRONMENT_CACHE_SECONDS = 300
DOCS_STAGE = "docs"
REFRESH_STAGES = (*SOURCE_NAMES, DOCS_STAGE)


class LibraryBusyError(RuntimeError):
    """A refresh or pack import is already running."""


class KnowledgeLibraryService:
    def __init__(self, root: Path, *, use_fts: Optional[bool] = None):
        self.store = LibraryStore(root)
        self.docs = DocIndex(Path(root) / DOCS_DIR_NAME / DOCS_DB_NAME, use_fts=use_fts)
        self._task: Optional[asyncio.Task] = None
        self._job: Dict[str, Any] = {"state": "idle"}
        self._last_auto_attempt: Optional[datetime] = None
        self._pack_lock = threading.Lock()
        self._environment: Tuple[float, Optional[EnvironmentTerms]] = (0.0, None)

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
        if self.is_refreshing() or self._pack_lock.locked():
            return self.job_snapshot()
        wanted = [name for name in (sources or REFRESH_STAGES) if name in REFRESH_STAGES]
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

    def resolve_refresh_sources(self, requested: Optional[Iterable[str]]) -> Optional[List[str]]:
        """None refreshes everything. Documentation is planned from the help.splunk.com index, so asking for it alone also loads a missing index."""
        if requested is None:
            return None
        wanted = [name for name in dict.fromkeys(str(item) for item in requested) if name in REFRESH_STAGES]
        if not wanted:
            raise ValueError("Choose at least one library source to refresh.")
        if DOCS_STAGE in wanted and "help_docs" not in wanted and not self.store.load_source("help_docs"):
            wanted.insert(0, "help_docs")
        return wanted

    def _progress(self, stage: str, done: int, total: int) -> None:
        self._job.update(stage=stage, done=done, total=total)

    def _update_state(self, **values: Any) -> None:
        try:
            state = self.store.load_state()
            state.update(values)
            self.store.save_state(state)
        except OSError:
            pass

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
                if DOCS_STAGE in wanted:
                    results[DOCS_STAGE] = await self._sync_docs(client, profile)
        except Exception as exc:  # noqa: BLE001 - the job must always finish with a recorded state
            results["_unexpected"] = {"status": "error", "error": f"{type(exc).__name__}: {exc}"[:400]}
        finally:
            counted = {name: result for name, result in results.items() if result.get("status") != "skipped"}
            ok = [name for name, result in counted.items() if result.get("status") == "ok"]
            state = "completed" if len(ok) == len(counted) else ("partial" if ok else "failed")
            self._job.update(state=state, finished_at=utc_now_iso(), results=results, stage="")
            self._update_state(last_refresh=dict(self._job))

    async def _sync_docs(self, client: httpx.AsyncClient, profile: Dict[str, Any]) -> Dict[str, Any]:
        self._progress(DOCS_STAGE, 0, 0)
        plan = build_doc_plan(profile, self.store.load_source("help_docs"))
        if plan["status"] == "needs_discovery":
            return {"status": "skipped", "reason": "Run discovery first so the library knows which documentation matches your environment."}
        if plan["status"] == "needs_source":
            return {"status": "skipped", "reason": "The help.splunk.com documentation index is not loaded."}
        if not plan["manuals"]:
            return {"status": "skipped", "reason": "No manuals on help.splunk.com match this environment."}
        self._update_state(docs_plan_attempted=plan_signature(plan))
        try:
            result = await sync_docs(client, self.docs, plan, self._progress)
        except LibrarySourceError as exc:
            return {"status": "error", "error": str(exc)[:400]}
        except (sqlite3.Error, OSError) as exc:
            return {"status": "error", "error": f"Could not save the documentation text: {type(exc).__name__}: {exc}"[:400]}
        return {**result, "count": result["pages_fetched"]}

    def _docs_due(self, plan: Dict[str, Any], coverage: Dict[str, Any]) -> bool:
        """New or changed manuals start a download once per plan, so pages that keep failing are not retried every hour."""
        if not plan.get("manuals") or not (coverage.get("missing_manuals") or coverage.get("outdated_manuals")):
            return False
        return self.store.load_state().get("docs_plan_attempted") != plan_signature(plan)

    def maybe_auto_refresh(
        self,
        profile: Dict[str, Any],
        allow_online: bool,
        pending_lookups: List[str],
        now: Optional[datetime] = None,
        *,
        docs_due: bool = False,
    ) -> Optional[str]:
        """Start a refresh when sources are missing or older than a week, new apps need a Splunkbase lookup, or documentation is due."""
        if not allow_online or self.is_refreshing() or self._pack_lock.locked():
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
            reason, sources = "apps", ["splunkbase", DOCS_STAGE] if docs_due else ["splunkbase"]
        elif docs_due:
            reason, sources = DOCS_STAGE, [DOCS_STAGE]
        else:
            return None
        self._last_auto_attempt = now
        self.start_refresh(profile, sources=sources, reason=reason)
        return reason

    # -- documentation search ---------------------------------------------

    def environment_terms(self, load_blueprint: Callable[[], Optional[Dict[str, Any]]]) -> EnvironmentTerms:
        """Names from the latest discovery, cached briefly because chat asks for them on every message."""
        expires, terms = self._environment
        now = time.monotonic()
        if terms is not None and now < expires:
            return terms
        try:
            profile = build_environment_profile(load_blueprint())
        except Exception:  # noqa: BLE001 - ranking still works without environment names
            profile = {"available": False}
        terms = EnvironmentTerms.from_profile(profile)
        self._environment = (now + ENVIRONMENT_CACHE_SECONDS, terms)
        return terms

    def search_docs(
        self,
        query: str,
        *,
        limit: int = 5,
        environment: Optional[EnvironmentTerms] = None,
        min_coverage: float = 0.0,
    ) -> List[Dict[str, Any]]:
        terms = query_terms(query)
        if not terms:
            return []
        try:
            candidates = self.docs.search_candidates(terms)
        except sqlite3.Error:
            return []
        return rank_doc_results(query, candidates, environment, limit=max(1, min(int(limit or 5), 20)), min_coverage=min_coverage)

    def docs_available(self) -> bool:
        try:
            return bool(self.docs.summary().get("available"))
        except sqlite3.Error:
            return False

    # -- packs -------------------------------------------------------------

    def import_pack(self, data: bytes) -> Dict[str, Any]:
        if self.is_refreshing() or not self._pack_lock.acquire(blocking=False):
            raise LibraryBusyError("Wait for the source refresh to finish, then import the pack.")
        try:
            contents = read_pack(data)
            raw_docs = contents["docs"]
            docs = sanitize_docs_payload(raw_docs) if raw_docs is not None else None
            if not contents["sources"] and not docs:
                raise LibraryPackError("The library pack did not contain any usable sources.")
            for name, payload in contents["sources"].items():
                self.store.save_source(name, payload)
            imported = sorted(contents["sources"])
            skipped = list(contents["skipped"])
            docs_pages = 0
            if docs:
                manuals, pages = docs
                docs_pages = self.docs.replace_all(manuals, pages, origin="pack")
                imported.append(DOCS_STAGE)
            elif raw_docs is not None:
                skipped.append(DOCS_STAGE)
            return {"imported": imported, "skipped": skipped, "pack_created_at": contents["pack_created_at"], "docs_pages": docs_pages}
        finally:
            self._pack_lock.release()

    def export_pack(self) -> bytes:
        try:
            docs = self.docs.export_payload()
        except sqlite3.Error:
            docs = None
        return export_pack(self.store, docs)

    # -- status ------------------------------------------------------------

    def _docs_status(self, profile: Dict[str, Any], help_docs: Optional[Dict[str, Any]]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        plan = build_doc_plan(profile, help_docs)
        try:
            states = self.docs.manual_states()
            summary = self.docs.summary()
        except sqlite3.Error as exc:
            states, summary = {}, {"available": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
        coverage = plan_coverage(plan, states)
        addon_overviews = [
            manual for manual in plan.get("manuals") or []
            if manual["product"] == ADDON_DOC_PRODUCT and manual["manual"].startswith(ADDON_DOC_PREFIX)
        ]
        status = {
            "plan_status": plan["status"],
            "platform": plan.get("platform") or {},
            "coverage": coverage,
            "summary": summary,
            "addon_overviews": len(addon_overviews),
        }
        return plan, status

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
        docs_plan, docs_status = self._docs_status(profile, sources.get("help_docs"))
        auto_started = None
        if auto_refresh:
            auto_started = self.maybe_auto_refresh(
                profile,
                allow_online,
                (catalog or {}).get("pending_splunkbase_lookups") or [],
                docs_due=self._docs_due(docs_plan, docs_status["coverage"]),
            )
        scorecard = build_scorecard(profile, catalog, kb_assets, summary, doc_text=docs_status)
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
            "docs": docs_status,
            "refresh": {**self.job_snapshot(), "auto_started": auto_started},
            "scorecard": scorecard,
            "catalog": catalog_payload,
        }
