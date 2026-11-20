"""Private record of dashboard requests, saved before each request is sent.

One JSON file holds every owner's requests. Briefs are kept only while Constellation still admits the
request ID, which is as long as an identical resend can happen.
"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from capabilities.tools.dashboards import RECEIPT_RETENTION, REQUEST_ADMISSION, request_id_issued_at
from incognito.vault import file_lock, write_private_file

MAX_OPERATIONS_PER_OWNER = 50
# Local states besides the receipt statuses: "sending" before a reply, "unconfirmed" when the reply
# left the outcome open, and "error" when the app stopped before sending anything.
ACTIVE_STATES = frozenset({"sending", "running", "unconfirmed"})


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DashboardOperationStore:
    def __init__(self, root: Path, clock: Optional[Callable[[], datetime]] = None):
        self.root = Path(root)
        self._clock = clock or _utc_now
        self._lock = threading.RLock()

    @property
    def path(self) -> Path:
        return self.root / "operations.json"

    @property
    def _lock_path(self) -> Path:
        return self.root / ".operations.lock"

    def _load(self) -> Dict[str, Dict[str, Dict[str, Any]]]:
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        except (OSError, ValueError):
            return {}
        owners = loaded.get("owners") if isinstance(loaded, dict) else None
        if not isinstance(owners, dict):
            return {}
        return {
            str(owner): {str(key): dict(value) for key, value in records.items() if isinstance(value, dict)}
            for owner, records in owners.items()
            if isinstance(records, dict)
        }

    def _save(self, owners: Dict[str, Dict[str, Dict[str, Any]]]) -> None:
        payload = {"version": 1, "owners": owners}
        write_private_file(self.path, json.dumps(payload, ensure_ascii=False, indent=1).encode("utf-8"))

    def _prune(self, owners: Dict[str, Dict[str, Dict[str, Any]]]) -> None:
        now = self._clock()
        for owner in list(owners):
            records = owners[owner]
            for request_id in list(records):
                issued = request_id_issued_at(request_id)
                if issued is None or now - issued > RECEIPT_RETENTION:
                    del records[request_id]
                    continue
                if now - issued > REQUEST_ADMISSION:
                    record = records[request_id]
                    record.pop("brief_json", None)
                    record.pop("brief", None)
            if len(records) > MAX_OPERATIONS_PER_OWNER:
                ordered = sorted(records.values(), key=lambda item: str(item.get("created_at") or ""))
                for record in ordered[: len(records) - MAX_OPERATIONS_PER_OWNER]:
                    if record.get("status") not in ACTIVE_STATES:
                        records.pop(str(record.get("request_id")), None)
            if not records:
                del owners[owner]

    def _mutate(self, change: Callable[[Dict[str, Dict[str, Dict[str, Any]]]], Any]) -> Any:
        with self._lock, file_lock(self._lock_path):
            owners = self._load()
            self._prune(owners)
            outcome = change(owners)
            self._save(owners)
            return outcome

    def add(self, owner: str, record: Dict[str, Any]) -> Dict[str, Any]:
        request_id = str(record["request_id"])
        stamp = self._clock().isoformat()
        stored = dict(record, created_at=record.get("created_at") or stamp, updated_at=stamp)

        def change(owners):
            records = owners.setdefault(owner, {})
            if request_id in records:
                raise ValueError("A dashboard request with this ID already exists.")
            records[request_id] = stored
            return dict(stored)

        return self._mutate(change)

    def update(self, owner: str, request_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
        def change(owners):
            record = owners.get(owner, {}).get(request_id)
            if record is None:
                return None
            record.update(fields)
            record["updated_at"] = self._clock().isoformat()
            return dict(record)

        return self._mutate(change)

    def get(self, owner: str, request_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            owners = self._load()
            self._prune(owners)
            record = owners.get(owner, {}).get(request_id)
            return dict(record) if record else None

    def list(self, owner: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            owners = self._load()
            self._prune(owners)
            records = list(owners.get(owner, {}).values())
        records.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return [dict(record) for record in records[: max(1, limit)]]

    def latest_for_proposal(self, owner: str, proposal_id: str) -> Optional[Dict[str, Any]]:
        if not proposal_id:
            return None
        matches = [record for record in self.list(owner, MAX_OPERATIONS_PER_OWNER) if record.get("proposal_id") == proposal_id]
        return matches[0] if matches else None

    def claim_for_proposal(
        self,
        owner: str,
        proposal_id: str,
        build: Callable[[Optional[Dict[str, Any]]], Optional[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """Atomically return the proposal's current request, or add the one ``build`` makes.

        ``build`` gets the latest request for the proposal (or None) and returns a new record to add,
        or None to reuse the latest one. Two clicks on Create therefore converge on one request.
        """
        stamp = self._clock().isoformat()

        def change(owners):
            records = owners.setdefault(owner, {})
            matches = sorted(
                (record for record in records.values() if proposal_id and record.get("proposal_id") == proposal_id),
                key=lambda item: str(item.get("created_at") or ""),
                reverse=True,
            )
            latest = dict(matches[0]) if matches else None
            record = build(latest)
            if record is None:
                if latest is None:
                    raise ValueError("Nothing to reuse for this plan.")
                return dict(latest, reused=True)
            request_id = str(record["request_id"])
            stored = dict(record, created_at=stamp, updated_at=stamp)
            records[request_id] = stored
            return dict(stored, reused=False)

        return self._mutate(change)
