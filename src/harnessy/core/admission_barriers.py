"""Process-owned admission holds while an asynchronous pause becomes durable."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import threading
from typing import Any, Callable
import uuid


@dataclass
class _Barrier:
    database: str
    kind: str
    workspace_id: str
    chat_id: str
    run_id: str
    state: str
    project_label: str
    model: str
    updated_at: str
    failed: bool = False


class AdmissionBarriers:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._entries: dict[str, _Barrier] = {}
        self._owners: dict[tuple[str, str, str], str] = {}

    def operation(
        self, database: str, kind: str, details: dict[str, Any], state: str,
        write: Callable[[], Any],
    ) -> Callable[[], Any]:
        """Register before yielding; the accepted worker retires its own token.

        A failed write remains conservative until the exact run is durably
        settled, superseded by a new owner, or explicitly acknowledged by Resume.
        Cancellation of an awaiter cannot remove a still-running worker's hold.
        """
        token = uuid.uuid4().hex
        barrier = _Barrier(str(database), kind, str(details.get('workspace_id') or ''),
                           str(details.get('chat_id') or ''), str(details.get('run_id') or ''), state,
                           str(details.get('project_label') or details.get('chat_id') or ''),
                           str(details.get('model') or ''), datetime.now(timezone.utc).isoformat(timespec='milliseconds'))
        if kind not in {'completion', 'backend'} or not barrier.run_id:
            raise ValueError('An admission barrier needs its exact run identity.')
        with self._lock:
            owner = self._owners.get((str(database), barrier.workspace_id, barrier.chat_id))
            if kind == 'completion' and owner is not None and owner != barrier.run_id:
                return write  # The store still applies its canonical stale-run check.
            self._entries[token] = barrier

        def perform():
            try:
                result = write()
            except BaseException:
                with self._lock:
                    if self._entries.get(token) is barrier:
                        barrier.failed = True
                raise
            else:
                with self._lock:
                    self._entries.pop(token, None)
                return result
        return perform

    def rows(self, database: str, owners: dict[tuple[str, str], str]) -> list[dict[str, Any]]:
        """Return holds for current owners and retire replaced run identities."""
        with self._lock:
            rows = []
            for token, entry in list(self._entries.items()):
                if entry.database != database:
                    continue
                current = self._owners.get((database, entry.workspace_id, entry.chat_id),
                                           owners.get((entry.workspace_id, entry.chat_id)))
                if entry.kind == 'completion' and current is not None and current != entry.run_id:
                    self._entries.pop(token, None)
                    continue
                rows.append({'token': token, 'kind': entry.kind, 'workspace_id': entry.workspace_id,
                             'chat_id': entry.chat_id, 'run_id': entry.run_id,
                             'state': entry.state, 'failed': entry.failed,
                             'project_label': entry.project_label, 'model': entry.model,
                             'updated_at': entry.updated_at})
            return rows

    def pending(self, database: str, *, active_only: bool = False) -> bool:
        with self._lock:
            return any(entry.database == database and (not active_only or not entry.failed)
                       for entry in self._entries.values())

    def current(self, database: str, details: dict[str, Any]) -> bool:
        with self._lock:
            owner = self._owners.get((database, str(details.get('workspace_id') or ''),
                                      str(details.get('chat_id') or '')))
            return owner is None or owner == str(details.get('run_id') or '')

    def settle(self, database: str, kind: str, details: dict[str, Any]) -> None:
        """A successful durable write replaces failed holds for this exact run."""
        with self._lock:
            for token, entry in list(self._entries.items()):
                if (entry.database == database and entry.kind == kind and entry.failed
                        and entry.run_id == str(details.get('run_id') or '')
                        and (kind == 'backend' or (
                            entry.workspace_id == str(details.get('workspace_id') or '')
                            and entry.chat_id == str(details.get('chat_id') or '')))):
                    self._entries.pop(token, None)

    def supersede(self, database: str, workspace_id: str, chat_id: str, run_id: str) -> None:
        with self._lock:
            self._owners[(database, workspace_id, chat_id)] = run_id
            for token, entry in list(self._entries.items()):
                if (entry.database == database and entry.kind == 'completion' and entry.workspace_id == workspace_id
                        and entry.chat_id == chat_id and entry.run_id != run_id):
                    self._entries.pop(token, None)

    def clear_failed(self, database: str, *, tokens: set[str] | None = None) -> None:
        with self._lock:
            for token, entry in list(self._entries.items()):
                if entry.database == database and entry.failed and (tokens is None or token in tokens):
                    self._entries.pop(token, None)

    def clear_project(self, database: str, workspace_id: str, chat_id: str) -> None:
        with self._lock:
            for token, entry in list(self._entries.items()):
                if (entry.database == database and entry.workspace_id == workspace_id
                        and entry.chat_id == chat_id):
                    self._entries.pop(token, None)


ADMISSION_BARRIERS = AdmissionBarriers()
