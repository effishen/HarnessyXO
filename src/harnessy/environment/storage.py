"""Content-free, process-owned observations of VM filesystem capacity.

UI clients only read snapshots. Observers probe already running, admitted VMs;
they never start a guest, repair a filesystem or install a guest tool.
"""
from __future__ import annotations

import asyncio
from contextvars import Context
from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import threading
import time
from typing import Any
import uuid

from .base import ENVIRONMENT_ID_RE, _validate_registry_path, environment_root

STORAGE_ERROR_CODES = frozenset({
    '', 'GUEST_STORAGE_STOPPED', 'GUEST_STORAGE_UNSUPPORTED', 'GUEST_STORAGE_UNAVAILABLE',
    'GUEST_STORAGE_PROBE_FAILED', 'GUEST_STORAGE_INVALID_OUTPUT', 'HOST_STORAGE_MISSING',
    'HOST_STORAGE_UNAVAILABLE', 'HOST_STORAGE_PARTIAL', 'VM_STORAGE_NOT_OBSERVED',
    'VM_STORAGE_NOT_VERIFIED', 'VM_STORAGE_WORKSPACE_UNAVAILABLE', 'VM_STORAGE_DEFINITION_MISSING',
    'VM_STORAGE_LIFECYCLE_BUSY', 'VM_STORAGE_PROBE_TIMEOUT', 'VM_STORAGE_PROBE_FAILED',
    'VM_STORAGE_INVALID_RECEIPT', 'VM_STORAGE_STATUS_WRITE_FAILED',
})
_STATES = {'ready', 'partial', 'unavailable', 'stopped', 'unsupported'}


def _count(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= (1 << 63) - 1:
        raise ValueError('Invalid storage counter.')
    return value


def _error(value, default=''):
    return value if isinstance(value, str) and value in STORAGE_ERROR_CODES else default


def _empty(state='unavailable', code='VM_STORAGE_NOT_OBSERVED'):
    return {'schema_version': 1, 'state': state, 'captured_at': None,
            'guest': {'state': 'stopped' if state == 'stopped' else 'unavailable', 'filesystems': [],
                      'error_code': 'GUEST_STORAGE_STOPPED' if state == 'stopped' else 'GUEST_STORAGE_UNAVAILABLE'},
            'host': {'state': 'unavailable', 'allocated_bytes': None, 'logical_bytes': None,
                     'error_code': 'HOST_STORAGE_UNAVAILABLE'}, 'error_code': code}


def sanitize_storage_usage(value: dict[str, Any]) -> dict[str, Any]:
    """Keep fixed roles/counters only; discard paths, labels and command text."""
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1 or not isinstance(value.get('state'), str)
            or value['state'] not in _STATES):
        raise ValueError('Invalid storage receipt schema.')
    captured = value.get('captured_at')
    if (isinstance(captured, bool) or not isinstance(captured, (int, float))
            or not math.isfinite(captured) or captured <= 0 or captured > time.time() + 60):
        raise ValueError('Invalid storage observation time.')
    guest, host = value.get('guest'), value.get('host')
    if (not isinstance(guest, dict) or guest.get('state') not in {'ready', 'unavailable', 'stopped', 'unsupported'}
            or not isinstance(host, dict) or host.get('state') not in {'ready', 'partial', 'unavailable'}):
        raise ValueError('Invalid storage component state.')
    source = guest.get('filesystems', [])
    if not isinstance(source, (list, tuple)) or len(source) > 2:
        raise ValueError('Invalid guest filesystem observations.')
    rows, roles = [], set()
    for row in source:
        if not isinstance(row, dict) or row.get('role') not in {'root', 'temporary'} or row['role'] in roles:
            raise ValueError('Invalid guest filesystem role.')
        roles.add(row['role'])
        clean = {'role': row['role']}
        for name in ('total_bytes', 'used_bytes', 'available_bytes', 'free_bytes'):
            clean[name] = _count(row.get(name))
            if clean[name] is None:
                raise ValueError('A guest filesystem counter is unavailable.')
        if (clean['used_bytes'] + clean['free_bytes'] != clean['total_bytes']
                or clean['available_bytes'] > clean['free_bytes']):
            raise ValueError('Contradictory guest filesystem counters.')
        for name in ('inodes_total', 'inodes_available'):
            if name in row:
                clean[name] = _count(row[name])
        if 'read_only' in row:
            if not isinstance(row['read_only'], bool):
                raise ValueError('Invalid guest filesystem access state.')
            clean['read_only'] = row['read_only']
        from .storage_probe import FS_KINDS
        if isinstance(row.get('fs_kind'), str) and row['fs_kind'] in FS_KINDS:
            clean['fs_kind'] = row['fs_kind']
        if 'memory_backed' in row:
            if not isinstance(row['memory_backed'], bool):
                raise ValueError('Invalid temporary-storage backing state.')
            kind = clean.get('fs_kind')
            if (kind in {'tmpfs', 'ramfs'} and not row['memory_backed']) or (
                    kind and kind not in {'tmpfs', 'ramfs', 'overlay', 'other'} and row['memory_backed']):
                raise ValueError('Contradictory temporary-storage backing state.')
            clean['memory_backed'] = row['memory_backed']
        rows.append(clean)
    if guest['state'] == 'ready' and not rows:
        raise ValueError('A ready guest receipt has no filesystem counters.')
    if guest['state'] != 'ready':
        rows = []  # Stale counters must never masquerade as current measurements.
    clean_host = {'state': host['state'], 'allocated_bytes': _count(host.get('allocated_bytes')),
                  'logical_bytes': _count(host.get('logical_bytes')),
                  'error_code': _error(host.get('error_code'), 'HOST_STORAGE_UNAVAILABLE')}
    if clean_host['allocated_bytes'] is None and clean_host['logical_bytes'] is None:
        clean_host['state'] = 'unavailable'
    derived = ('stopped' if guest['state'] == 'stopped' else
               'ready' if guest['state'] == 'ready' and clean_host['state'] == 'ready' else
               'partial' if guest['state'] == 'ready' or clean_host['state'] in {'ready', 'partial'} else
               'unsupported' if guest['state'] == 'unsupported' else 'unavailable')
    if value['state'] != derived:
        raise ValueError('Contradictory storage observation states.')
    return {'schema_version': 1, 'state': value['state'], 'captured_at': float(captured),
            'guest': {'state': guest['state'], 'filesystems': rows,
                      'error_code': _error(guest.get('error_code'), '' if guest['state'] == 'ready' else 'GUEST_STORAGE_UNAVAILABLE')},
            'host': clean_host, 'error_code': _error(value.get('error_code'))}


@dataclass
class _StorageEntry:
    admission: Any = None
    running: bool | None = None
    data: dict[str, Any] = field(default_factory=_empty)
    last_known: dict[str, Any] | None = None
    last_success_at: float | None = None
    observed_at: float | None = None
    fresh: bool = False
    pending: bool = False
    refreshing: bool = False
    lifecycle_busy: bool = False
    needs_persist: bool = False
    loaded: bool = False
    task: asyncio.Task | None = None
    wake: asyncio.Event | None = None


class VMStorageRegistry:
    def __init__(self, *, poll_interval: float = 30.0, probe_timeout: float = 8.0):
        self.poll_interval = max(.01, float(poll_interval))
        self.probe_timeout = max(.01, float(probe_timeout))
        self._entries: dict[tuple[str, str], _StorageEntry] = {}
        self._loops = {}
        self._lock = threading.RLock()
        self._logged = {}

    @staticmethod
    def _key(root, environment_id):
        if not isinstance(environment_id, str) or not ENVIRONMENT_ID_RE.fullmatch(environment_id):
            raise ValueError('Storage observations require an exact named VM identity.')
        # UI callers already hold the canonical admitted root. Avoid resolving
        # symlinks/statting a disconnected disk merely to look up cached data.
        return str(Path(root).expanduser().absolute()), environment_id

    @staticmethod
    def _workspace(key):
        from .file_views import FILE_VIEWS
        try:
            return FILE_VIEWS.cached_workspace(key[0])
        except Exception:
            return None

    @staticmethod
    def _definition_exists(key):
        path = environment_root(key[0], key[1]) / 'environment.json'
        _validate_registry_path(path, Path(key[0]))
        return path.is_file()

    def _current(self, key, entry):
        return self._entries.get(key) is entry

    def _admitted_generation(self, key):
        try:
            workspace = self._workspace(key)
            if workspace is not None and self._definition_exists(key):
                return workspace._workspace_generation
        except Exception:
            pass
        return None

    @staticmethod
    def _lifecycle_busy(key):
        from .operations import ENVIRONMENT_OPERATIONS
        return ENVIRONMENT_OPERATIONS.is_busy(key[0], environment_id=key[1])

    async def _verify_admission(self, key, entry):
        from .file_views import finish_file_view_work
        generation = await finish_file_view_work(self._admitted_generation, key)
        if not self._current(key, entry):
            return False
        if generation is None or (entry.admission is not None and generation != entry.admission):
            entry.admission, entry.running = generation, None
            entry.data = _empty(code='VM_STORAGE_WORKSPACE_UNAVAILABLE')
            entry.last_known, entry.last_success_at = None, None
            entry.fresh, entry.pending, entry.needs_persist = False, False, False
            entry.loaded = True
            return False
        entry.admission = generation
        return True

    def status(self, root, *, environment_id) -> dict[str, Any]:
        """Return cached counters; never call a provider or read its state file."""
        key = self._key(root, environment_id)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return {**_empty(), 'fresh': False, 'observed_at': None, 'last_success_at': None,
                        'refreshing': False, 'observation_pending': False}
            busy = entry.lifecycle_busy
            expired = (entry.observed_at is None
                       or time.time() - entry.observed_at > self.poll_interval + self.probe_timeout
                       or (entry.data.get('captured_at') is not None
                           and time.time() - entry.data['captured_at'] > self.poll_interval + self.probe_timeout))
            fresh = bool(entry.fresh and not expired and not busy)
            data = _empty(code='VM_STORAGE_LIFECYCLE_BUSY') if busy else entry.data
            snapshot = {**data, 'fresh': fresh, 'observed_at': entry.observed_at,
                        'last_success_at': entry.last_success_at, 'refreshing': entry.refreshing,
                        'observation_pending': entry.pending}
            if entry.last_known is not None and (not fresh or data['guest']['state'] != 'ready'):
                snapshot['last_known'] = entry.last_known
            # Return a detached, already bounded value; UI consumers cannot
            # mutate the authoritative cache through nested guest/host rows.
            return json.loads(json.dumps(snapshot))

    def observe(self, root, *, environment_id, running: bool, lifecycle_busy: bool = False) -> None:
        key = self._key(root, environment_id)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = self._entries[key] = _StorageEntry()
            previously_running = entry.running
            entry.running = bool(running)
            entry.lifecycle_busy = bool(lifecycle_busy)
            if not running:
                if previously_running is not False:
                    entry.data = _empty('stopped', 'GUEST_STORAGE_STOPPED')
                    entry.observed_at, entry.fresh, entry.pending = time.time(), False, False
                    entry.needs_persist = True
                    self._cancel_task(entry)
            else:
                entry.pending = entry.pending or entry.observed_at is None
        self._schedule(key, wake=False)

    def request(self, root, *, environment_id) -> bool:
        key = self._key(root, environment_id)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry.running is not True:
                return False  # Only an actual status observation establishes Running.
            entry.pending = True
            if entry.refreshing:
                return True  # Share the in-flight measurement rather than queueing another.
        self._schedule(key, wake=True)
        return True

    @staticmethod
    def _cancel_task(entry):
        task = entry.task
        if task is not None and not task.done() and not task.get_loop().is_closed():
            task.get_loop().call_soon_threadsafe(task.cancel)

    def _cancel(self, key):
        with self._lock:
            entry = self._entries.pop(key, None)
            if entry is not None:
                self._cancel_task(entry)

    def _schedule(self, key, *, wake):
        try:
            loop = asyncio.get_running_loop()
            self._loops[key[0]] = loop
        except RuntimeError:
            loop = self._loops.get(key[0])
        if loop is None or loop.is_closed():
            return
        def launch():
            entry = self._entries.get(key)
            if entry is None or (entry.running is not True and not entry.needs_persist):
                return
            if entry.task is not None and not entry.task.done():
                if wake and entry.wake is not None:
                    entry.wake.set()
                return
            entry.wake = asyncio.Event()
            entry.task = loop.create_task(self._worker(key, entry),
                name='harnessy-vm-storage-' + key[1], context=Context())
        loop.call_soon_threadsafe(launch, context=Context())

    def _publish(self, key, entry, payload, *, fresh):
        if not self._current(key, entry):
            return
        with self._lock:
            entry.data, entry.observed_at, entry.fresh = payload, time.time(), fresh
            entry.pending = False
            if fresh and (payload['guest']['state'] == 'ready' or (entry.last_known is None
                          and any(payload['host'].get(name) is not None for name in ('allocated_bytes', 'logical_bytes')))):
                entry.last_known = payload
                entry.last_success_at = payload['captured_at']

    def _load(self, key):
        from harnessy.diagnostics.vm_logs import _read_tail
        path = environment_root(key[0], key[1]) / 'state' / 'storage-usage.json'
        _validate_registry_path(path, Path(key[0]))
        result = _read_tail(path, 65536)
        if result['status'] == 'missing':
            return None
        if result['status'] != 'included' or result['truncated']:
            raise ValueError('Unsafe or oversized storage observation.')
        value = json.loads(result['data'])
        if not isinstance(value, dict) or value.get('environment_id') != key[1]:
            raise ValueError('Invalid persisted storage identity.')
        receipt = value.get('last_known') or value.get('measurement') or value
        if not isinstance(receipt, dict):
            raise ValueError('Invalid persisted storage counters.')
        return sanitize_storage_usage(receipt) if receipt.get('captured_at') is not None else None

    def _persist(self, key, entry):
        if not self._current(key, entry) or self._admitted_generation(key) != entry.admission:
            return
        owned = environment_root(key[0], key[1])
        path = owned / 'state' / 'storage-usage.json'
        for item in (owned, path.parent, path):
            _validate_registry_path(item, Path(key[0]))
        if not self._definition_exists(key):
            return
        # Never recreate a removed VM or workspace, even if removal races a
        # completed guest probe. The immediate owned parent must still exist.
        path.parent.mkdir(exist_ok=True)
        value = {**entry.data, 'environment_id': key[1], 'fresh': False,
                 'observed_at': entry.observed_at, 'last_success_at': entry.last_success_at,
                 'last_known': entry.last_known}
        temporary = path.with_name('.storage-usage-' + uuid.uuid4().hex + '.tmp')
        try:
            with temporary.open('x', encoding='utf-8') as stream:
                json.dump(value, stream, sort_keys=True)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    async def _worker(self, key, entry):
        from .file_views import finish_file_view_work
        try:
            if not await self._verify_admission(key, entry):
                return
            if not entry.loaded:
                entry.loaded = True
                try:
                    previous = await finish_file_view_work(self._load, key)
                    if previous is not None and self._current(key, entry):
                        entry.last_known, entry.last_success_at = previous, previous['captured_at']
                        if entry.running is True:
                            entry.data = _empty(code='VM_STORAGE_NOT_VERIFIED')
                except (OSError, ValueError, TypeError, RecursionError):
                    pass  # A bad observation cannot prevent a fresh safe probe.
            while self._current(key, entry) and entry.running is True:
                if not await self._verify_admission(key, entry):
                    break
                entry.wake.clear()
                entry.lifecycle_busy = await finish_file_view_work(self._lifecycle_busy, key)
                if entry.lifecycle_busy:
                    self._publish(key, entry, _empty(code='VM_STORAGE_LIFECYCLE_BUSY'), fresh=False)
                else:
                    await self._probe(key, entry)
                if not self._current(key, entry) or entry.running is not True:
                    break
                try:
                    await asyncio.wait_for(entry.wake.wait(), timeout=self.poll_interval)
                except asyncio.TimeoutError:
                    pass
            if self._current(key, entry) and entry.needs_persist:
                entry.needs_persist = False
                await finish_file_view_work(self._persist, key, entry)
        except asyncio.CancelledError:
            raise
        except Exception:
            self._publish(key, entry, _empty(code='VM_STORAGE_PROBE_FAILED'), fresh=False)
        finally:
            entry.refreshing = False
            if entry.task is asyncio.current_task():
                entry.task = None
            if self._current(key, entry) and entry.needs_persist:
                self._schedule(key, wake=False)

    async def _probe(self, key, entry):
        from .manager import EnvironmentManager
        from .file_views import finish_file_view_work
        from harnessy.diagnostics import log_event
        started = time.monotonic()
        entry.refreshing, entry.pending = True, True
        try:
            provider = await finish_file_view_work(lambda: EnvironmentManager(key[0], environment_id=key[1]).provider())
            value = await asyncio.wait_for(provider.storage_usage(), timeout=self.probe_timeout)
            payload = sanitize_storage_usage(value)
            fresh = payload['state'] in {'ready', 'partial', 'stopped'}
        except asyncio.TimeoutError:
            payload, fresh = _empty(code='VM_STORAGE_PROBE_TIMEOUT'), False
        except asyncio.CancelledError:
            raise
        except (ValueError, TypeError):
            payload, fresh = _empty(code='VM_STORAGE_INVALID_RECEIPT'), False
        except Exception:
            payload, fresh = _empty(code='VM_STORAGE_PROBE_FAILED'), False
        finally:
            entry.refreshing = False
        if not await self._verify_admission(key, entry) or entry.running is not True:
            return
        self._publish(key, entry, payload, fresh=fresh)
        if payload['guest']['state'] == 'stopped':
            entry.running = False
        try:
            await finish_file_view_work(self._persist, key, entry)
        except asyncio.CancelledError:
            raise
        except Exception:
            entry.data = {**entry.data, 'error_code': 'VM_STORAGE_STATUS_WRITE_FAILED'}
        signature = (payload['state'], payload.get('error_code'), payload['guest']['state'], payload['host']['state'])
        if self._logged.get(key) != signature:
            self._logged[key] = signature
            log_event('runtime', 'vm_storage_observation_finished', environment_id=key[1],
                      state=payload['state'], error_code=payload.get('error_code', ''),
                      guest_state=payload['guest']['state'], host_state=payload['host']['state'],
                      duration_seconds=max(0.0, time.monotonic() - started))

    async def close(self, root=None, *, environment_id=None):
        canonical = str(Path(root).expanduser().absolute()) if root is not None else None
        with self._lock:
            keys = [key for key in self._entries if (canonical is None or key[0] == canonical)
                    and (environment_id is None or key[1] == environment_id)]
            entries = [self._entries.pop(key) for key in keys]
            for key in keys:
                self._logged.pop(key, None)
        tasks = [entry.task for entry in entries if entry.task is not None and not entry.task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if environment_id is None:
            if canonical is None:
                self._loops.clear()
            else:
                self._loops.pop(canonical, None)

    async def close_environment(self, root, *, environment_id):
        await self.close(root, environment_id=environment_id)

    async def shutdown(self):
        await self.close()


VM_STORAGE = VMStorageRegistry()
StorageUsageRegistry = VMStorageRegistry
