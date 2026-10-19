from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harnessy.diagnostics import log_event

from .manager import EnvironmentManager
from .base import ENVIRONMENT_ID_RE


@dataclass(slots=True)
class _StatusEntry:
    data: dict[str, Any] | None = None
    error: str = ''
    updated_at: float = 0.0
    refresh_count: int = 0
    generation: int = 0
    task: asyncio.Task[dict[str, Any]] | None = field(default=None, repr=False)


class EnvironmentStatusRegistry:
    """Process-owned, deduplicating Environment status cache.

    Browser pages are observers of this service; they never own a Lima polling
    loop. Multiple restored tabs, rerenders or clients can request a snapshot at
    the same time and still cause at most one provider inspection per workspace
    and environment per cache interval.
    """

    def __init__(self, *, default_max_age: float = 2.5) -> None:
        self.default_max_age = max(0.25, float(default_max_age))
        self._entries: dict[tuple[str, str], _StatusEntry] = {}

    @staticmethod
    def _key(workspace_root: str | Path, environment_id: str | None = None) -> tuple[str, str]:
        manager = EnvironmentManager(workspace_root, environment_id=environment_id)
        selected = manager.environment_id
        if not selected and environment_id and ENVIRONMENT_ID_RE.fullmatch(environment_id):
            selected = environment_id
        return str(manager.workspace_root), selected

    def _entry(self, workspace_root: str | Path, environment_id: str | None = None) -> _StatusEntry:
        key = self._key(workspace_root, environment_id)
        return self._entries.setdefault(key, _StatusEntry())

    def invalidate(self, workspace_root: str | Path, *, environment_id: str | None = None) -> None:
        if environment_id is None:
            root = str(Path(workspace_root).expanduser().resolve())
            entries = [entry for key, entry in self._entries.items() if key[0] == root]
        else:
            entries = [self._entry(workspace_root, environment_id)]
        for entry in entries:
            entry.updated_at = 0.0
            entry.generation += 1

    def publish_snapshots(self, workspace_root: str | Path, snapshots: list[str], *, environment_id: str | None = None) -> None:
        """Publish a verified operation result before exposing completion.

        An inspect begun before Create must not overwrite this result afterward.
        Other environment fields retain their last known values pending refresh.
        """
        entry = self._entry(workspace_root, environment_id)
        entry.generation += 1
        entry.data = {**(entry.data or {}), 'snapshots': list(snapshots)}
        entry.data.pop('_snapshot_list_error', None)
        entry.updated_at = 0.0

    def peek(self, workspace_root: str | Path, *, environment_id: str | None = None) -> dict[str, Any] | None:
        entry = self._entry(workspace_root, environment_id)
        return entry.data

    def stats(self, workspace_root: str | Path, *, environment_id: str | None = None) -> dict[str, Any]:
        entry = self._entry(workspace_root, environment_id)
        return {
            'environment_id': self._key(workspace_root, environment_id)[1],
            'environment_count': len(EnvironmentManager(workspace_root).list()),
            'updated_at': entry.updated_at,
            'refresh_count': entry.refresh_count,
            'inflight': bool(entry.task and not entry.task.done()),
            'error': entry.error,
        }

    async def _refresh(self, workspace_root: Path, entry: _StatusEntry, *, environment_id: str) -> dict[str, Any]:
        started = time.monotonic()
        generation = entry.generation
        log_event('runtime', 'environment_status_refresh_started', workspace=str(workspace_root), environment_id=environment_id)
        try:
            info = await EnvironmentManager(workspace_root, environment_id=environment_id).provider().inspect()
            info = {**info, 'environment_id': environment_id,
                    'environment_count': len(EnvironmentManager(workspace_root).list())}
            if generation != entry.generation:
                return entry.data or info  # obsolete in-flight result; next poll refreshes
            if info.get('snapshots') is None and entry.data and isinstance(entry.data.get('snapshots'), list):
                info = {**info, 'snapshots': list(entry.data['snapshots'])}
            entry.data = info
            entry.error = ''
            entry.updated_at = time.monotonic()
            entry.refresh_count += 1
            log_event(
                'runtime', 'environment_status_refresh_finished', workspace=str(workspace_root), environment_id=environment_id,
                duration_seconds=max(0.0, time.monotonic() - started),
                refresh_count=entry.refresh_count,
            )
            return info
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if generation != entry.generation and entry.data is not None:
                return entry.data
            entry.error = f'{type(exc).__name__}: {exc}'
            # Throttle repeated failures too; a broken controller must not become
            # a tight retry loop just because several browser observers exist.
            entry.updated_at = time.monotonic()
            log_event(
                'runtime', 'environment_status_refresh_failed', workspace=str(workspace_root), environment_id=environment_id,
                duration_seconds=max(0.0, time.monotonic() - started), error=entry.error,
            )
            raise
        finally:
            current = asyncio.current_task()
            if entry.task is current:
                entry.task = None

    async def get(
        self,
        workspace_root: str | Path,
        *,
        environment_id: str | None = None,
        max_age: float | None = None,
        force: bool = False,
    ) -> dict[str, Any] | None:
        root = Path(workspace_root).expanduser().resolve()
        manager = EnvironmentManager(root, environment_id=environment_id)
        if manager.config is None:
            return None
        environment_id = manager.environment_id
        entry = self._entry(root, environment_id)

        # Environment lifecycle jobs own the controller while active. Their
        # persisted stage is the live UI signal; do not interleave list/inspect
        # traffic with Start/Stop/Rebuild/Restore.
        try:
            from .operations import ENVIRONMENT_OPERATIONS
            if ENVIRONMENT_OPERATIONS.is_busy(root, environment_id=environment_id):
                return entry.data
        except Exception:
            pass

        ttl = self.default_max_age if max_age is None else max(0.0, float(max_age))
        recent = bool(entry.updated_at and (time.monotonic() - entry.updated_at) < ttl)
        if not force and recent:
            if entry.data is not None:
                return entry.data
            if entry.error:
                # The last refresh failed recently. Surface the same bounded
                # failure without issuing another controller command until the
                # cache interval expires.
                raise RuntimeError(entry.error)

        task = entry.task
        if task is None or task.done():
            task = asyncio.create_task(
                self._refresh(root, entry, environment_id=environment_id),
                name=f'harnessy-env-status-{abs(hash((str(root), environment_id)))}',
            )
            entry.task = task
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # Cancelling a page observer must not cancel the process-owned status
            # request being shared with another page/client.
            raise
        except Exception:
            if entry.data is not None:
                # Preserve the last known state while surfacing the poll failure
                # as metadata. Callers can show it without destroying controls.
                stale = dict(entry.data)
                stale['_status_poll_error'] = entry.error
                return stale
            raise

    async def close(self) -> None:
        tasks = [entry.task for entry in self._entries.values() if entry.task and not entry.task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for entry in self._entries.values():
            entry.task = None


ENVIRONMENT_STATUS = EnvironmentStatusRegistry()
