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
RESOURCE_ERROR_CODES = frozenset({'', 'GUEST_RESOURCES_STOPPED', 'GUEST_RESOURCES_UNSUPPORTED',
    'GUEST_RESOURCES_UNAVAILABLE', 'GUEST_RESOURCES_PROBE_FAILED', 'GUEST_RESOURCES_INVALID_OUTPUT',
    'VM_RESOURCES_NOT_OBSERVED', 'VM_RESOURCES_NOT_VERIFIED', 'VM_RESOURCES_WORKSPACE_UNAVAILABLE',
    'VM_RESOURCES_LIFECYCLE_BUSY', 'VM_RESOURCES_PROBE_TIMEOUT', 'VM_RESOURCES_PROBE_FAILED',
    'VM_RESOURCES_INVALID_RECEIPT'})


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


def _finite(value, *, minimum=0, maximum=1e12):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not minimum <= value <= maximum or not math.isfinite(value)):
        raise ValueError('Invalid resource observation number.')
    return float(value)


def _empty_resources(state='unavailable', code='VM_RESOURCES_NOT_OBSERVED'):
    component = state if state in {'stopped', 'unsupported'} else 'unavailable'
    return {'schema_version': 1, 'state': state, 'captured_at': None, 'error_code': code,
            'cpu': {'state': component, 'logical_count': None, 'usage_percent': None,
                    'iowait_percent': None, 'steal_percent': None, 'sample_seconds': None},
            'memory': {'state': component, 'total_bytes': None, 'available_bytes': None,
                       'used_bytes': None, 'cache_bytes': None, 'buffers_bytes': None},
            'swap': {'state': component, 'total_bytes': None, 'used_bytes': None, 'free_bytes': None},
            'load': {'state': component, 'one': None, 'five': None, 'fifteen': None}, 'uptime_seconds': None}


def _resource_state(value):
    states = [value[name]['state'] for name in ('cpu', 'memory', 'swap', 'load')]
    if all(state == 'stopped' for state in states):
        return 'stopped'
    if all(state == 'unsupported' for state in states):
        return 'unsupported'
    if all(state == 'ready' for state in states) and value.get('uptime_seconds') is not None:
        return 'ready'
    if any(state == 'ready' for state in states) or value.get('uptime_seconds') is not None:
        return 'partial'
    return 'unavailable'


def sanitize_resource_usage(value: dict[str, Any]) -> dict[str, Any]:
    """Project fixed resource metrics only; raw CPU counters never cross here."""
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1 or not isinstance(value.get('state'), str)
            or value['state'] not in _STATES):
        raise ValueError('Invalid resource receipt schema.')
    clean = _empty_resources()
    clean['captured_at'] = _finite(value.get('captured_at'), minimum=.001, maximum=time.time() + 60)
    code = value.get('error_code')
    clean['error_code'] = code if isinstance(code, str) and code in RESOURCE_ERROR_CODES else ''
    for name in ('cpu', 'memory', 'swap', 'load'):
        source = value.get(name)
        allowed = {'ready', 'unavailable', 'stopped', 'unsupported'} | ({'pending'} if name == 'cpu' else set())
        if not isinstance(source, dict) or not isinstance(source.get('state'), str) or source['state'] not in allowed:
            raise ValueError('Invalid resource component state.')
        clean[name]['state'] = source['state']
    cpu = value['cpu']; count = _count(cpu.get('logical_count'))
    if count is not None and not 1 <= count <= 4096:
        raise ValueError('Invalid guest CPU count.')
    clean['cpu']['logical_count'] = count
    if cpu['state'] == 'ready':
        if count is None:
            raise ValueError('A CPU rate requires its CPU count.')
        for name in ('usage_percent', 'iowait_percent', 'steal_percent'):
            if cpu.get(name) is not None:
                clean['cpu'][name] = _finite(cpu[name], maximum=100)
        if clean['cpu']['usage_percent'] is None:
            raise ValueError('A ready CPU observation requires a rate.')
        clean['cpu']['sample_seconds'] = _finite(cpu.get('sample_seconds'), minimum=.000001, maximum=3600)
        if sum(clean['cpu'][name] or 0 for name in ('usage_percent', 'iowait_percent', 'steal_percent')) > 100.000001:
            raise ValueError('Contradictory CPU rates.')
    memory = value['memory']
    if memory['state'] == 'ready':
        total, available = _count(memory.get('total_bytes')), _count(memory.get('available_bytes'))
        if total is None or total <= 0 or available is None or available > total:
            raise ValueError('Invalid guest memory accounting.')
        used = total - available
        if memory.get('used_bytes') is not None and _count(memory['used_bytes']) != used:
            raise ValueError('Contradictory guest memory accounting.')
        clean['memory'].update(total_bytes=total, available_bytes=available, used_bytes=used)
        for name in ('cache_bytes', 'buffers_bytes'):
            number = _count(memory.get(name))
            if number is not None and number > total:
                raise ValueError('Invalid guest memory counter.')
            clean['memory'][name] = number
        source = memory.get('available_source')
        if isinstance(source, str) and source in {'mem_available', 'estimated'}:
            clean['memory']['available_source'] = source
        estimated = memory.get('available_estimated')
        if estimated is not None:
            if not isinstance(estimated, bool) or (isinstance(source, str) and source in {'mem_available', 'estimated'} and estimated != (source == 'estimated')):
                raise ValueError('Contradictory memory estimation metadata.')
            clean['memory']['available_estimated'] = estimated
    swap = value['swap']
    if swap['state'] == 'ready':
        counters = {name: _count(swap.get(name)) for name in ('total_bytes', 'used_bytes', 'free_bytes')}
        if any(number is None for number in counters.values()) or counters['used_bytes'] + counters['free_bytes'] != counters['total_bytes']:
            raise ValueError('Contradictory guest swap accounting.')
        clean['swap'].update(counters)
    if value['load']['state'] == 'ready':
        clean['load'].update({name: _finite(value['load'].get(name), maximum=1e9) for name in ('one', 'five', 'fifteen')})
    if value.get('uptime_seconds') is not None:
        clean['uptime_seconds'] = _finite(value['uptime_seconds'])
    clean['state'] = _resource_state(clean)
    return clean


def calculate_cpu_usage(sample, previous, *, observed_at=None):
    """Compute aggregate VM CPU rates from two valid volatile tick snapshots."""
    cpu = _empty_resources()['cpu']
    try:
        if not isinstance(sample, dict):
            return cpu, None
        baseline = {name: _count(sample.get(name)) for name in
                    ('total_ticks', 'idle_ticks', 'iowait_ticks', 'steal_ticks', 'logical_count')}
        if baseline['steal_ticks'] is None:
            baseline['steal_ticks'] = 0
        if (any(number is None for number in baseline.values()) or not 1 <= baseline['logical_count'] <= 4096
                or sum(baseline[name] for name in ('idle_ticks', 'iowait_ticks', 'steal_ticks')) > baseline['total_ticks']):
            return cpu, None
        baseline['uptime_seconds'] = _finite(sample.get('uptime_seconds'))
        baseline['_observed_monotonic'] = time.monotonic() if observed_at is None else _finite(observed_at)
    except (ValueError, TypeError):
        return cpu, None
    cpu.update(state='pending', logical_count=baseline['logical_count'])
    if not isinstance(previous, dict):
        return cpu, baseline
    try:
        elapsed = baseline['uptime_seconds'] - previous['uptime_seconds']
        wall_gap = baseline['_observed_monotonic'] - previous.get('_observed_monotonic', baseline['_observed_monotonic'])
        deltas = {name: baseline[name] - previous.get(name, 0) for name in ('total_ticks', 'idle_ticks', 'iowait_ticks', 'steal_ticks')}
        total = deltas['total_ticks']
        if (previous['logical_count'] != baseline['logical_count'] or not 0 < elapsed <= 60
                or not 0 <= wall_gap <= 60 or total <= 0 or any(number < 0 for number in deltas.values())
                or deltas['idle_ticks'] + deltas['iowait_ticks'] + deltas['steal_ticks'] > total):
            return cpu, baseline
        cpu.update(state='ready', usage_percent=100 * (total - deltas['idle_ticks'] - deltas['iowait_ticks'] - deltas['steal_ticks']) / total,
                   iowait_percent=100 * deltas['iowait_ticks'] / total,
                   steal_percent=100 * deltas['steal_ticks'] / total, sample_seconds=elapsed)
        return cpu, baseline
    except (KeyError, TypeError, ValueError):
        return cpu, baseline


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
    resources: dict[str, Any] = field(default_factory=_empty_resources)
    resources_last_known: dict[str, Any] | None = None
    resources_last_success_at: float | None = None
    resources_observed_at: float | None = None
    resources_fresh: bool = False
    resources_pending: bool = False
    resources_refreshing: bool = False
    cpu_baseline: dict[str, Any] | None = None
    storage_due_at: float = 0.0
    force_storage: bool = False
    probing: bool = False
    active_storage: bool = False
    baseline_epoch: int = 0


class VMStorageRegistry:
    def __init__(self, *, poll_interval: float = 30.0, resource_interval: float = 5.0, probe_timeout: float = 8.0):
        self.poll_interval = max(.01, float(poll_interval))
        self.resource_interval = max(.01, float(resource_interval))
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
            entry.resources = _empty_resources(code='VM_RESOURCES_WORKSPACE_UNAVAILABLE')
            entry.resources_last_known, entry.resources_last_success_at = None, None
            entry.resources_fresh, entry.resources_pending, entry.cpu_baseline = False, False, None
            entry.baseline_epoch += 1
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
                        'refreshing': False, 'observation_pending': False,
                        'resources': {**_empty_resources(), 'fresh': False, 'observed_at': None,
                                      'last_success_at': None, 'refreshing': False, 'observation_pending': False}}
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
            resource_expired = (entry.resources_observed_at is None
                or time.time() - entry.resources_observed_at > self.resource_interval + self.probe_timeout
                or (entry.resources.get('captured_at') is not None
                    and time.time() - entry.resources['captured_at'] > self.resource_interval + self.probe_timeout))
            resources_fresh = bool(entry.resources_fresh and not resource_expired and not busy)
            resources = _empty_resources(code='VM_RESOURCES_LIFECYCLE_BUSY') if busy else entry.resources
            snapshot['resources'] = {**resources, 'fresh': resources_fresh,
                'observed_at': entry.resources_observed_at, 'last_success_at': entry.resources_last_success_at,
                'refreshing': entry.resources_refreshing, 'observation_pending': entry.resources_pending}
            if entry.resources_last_known is not None and (not resources_fresh or resources['state'] not in {'ready', 'partial'}):
                snapshot['resources_last_known'] = entry.resources_last_known
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
            previously_busy = entry.lifecycle_busy
            entry.running = bool(running)
            entry.lifecycle_busy = bool(lifecycle_busy)
            if lifecycle_busy:
                entry.cpu_baseline = None
                if not previously_busy:
                    entry.baseline_epoch += 1
            if not running:
                if previously_running is not False:
                    entry.data = _empty('stopped', 'GUEST_STORAGE_STOPPED')
                    entry.observed_at, entry.fresh, entry.pending = time.time(), False, False
                    entry.resources = _empty_resources('stopped', 'GUEST_RESOURCES_STOPPED')
                    entry.resources_observed_at, entry.resources_fresh, entry.resources_pending = time.time(), False, False
                    entry.cpu_baseline = None
                    entry.baseline_epoch += 1
                    entry.needs_persist = True
                    self._cancel_task(entry)
            else:
                entry.pending = entry.pending or entry.observed_at is None
                entry.resources_pending = entry.resources_pending or entry.resources_observed_at is None
        self._schedule(key, wake=False)

    def invalidate_baseline(self, root, *, environment_id) -> None:
        """Discard CPU deltas across lifecycle/settings invalidation events."""
        key = self._key(root, environment_id)
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None:
                entry.cpu_baseline = None
                entry.baseline_epoch += 1
                entry.resources_fresh = False
        self.request(root, environment_id=environment_id)

    def request(self, root, *, environment_id, resources_only: bool = False) -> bool:
        key = self._key(root, environment_id)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry.running is not True:
                return False  # Only an actual status observation establishes Running.
            entry.resources_pending = True
            if not resources_only:
                entry.pending = True
                entry.force_storage = not (entry.probing and entry.active_storage)
            if entry.probing and (resources_only or entry.active_storage):
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

    def _publish_resources(self, key, entry, payload, *, fresh):
        if not self._current(key, entry):
            return
        with self._lock:
            entry.resources, entry.resources_observed_at, entry.resources_fresh = payload, time.time(), fresh
            entry.resources_pending = False
            if fresh and (payload['state'] == 'ready' or (entry.resources_last_known is None and payload['state'] == 'partial')):
                entry.resources_last_known = payload
                entry.resources_last_success_at = payload['captured_at']
            if payload['state'] not in {'ready', 'partial'}:
                entry.cpu_baseline = None

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
        storage = sanitize_storage_usage(receipt) if receipt.get('captured_at') is not None else None
        retained_resources = value.get('resources_last_known') or value.get('resources')
        resources = (sanitize_resource_usage(retained_resources)
                     if isinstance(retained_resources, dict) and retained_resources.get('captured_at') is not None else None)
        return {'storage': storage, 'resources': resources}

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
                 'last_known': entry.last_known,
                 'resources': {**entry.resources, 'fresh': False, 'observed_at': entry.resources_observed_at,
                     'last_success_at': entry.resources_last_success_at, 'refreshing': False, 'observation_pending': False},
                 'resources_last_known': entry.resources_last_known}
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
                        storage = previous.get('storage')
                        if storage is not None:
                            entry.last_known, entry.last_success_at = storage, storage['captured_at']
                        resources = previous.get('resources')
                        if resources is not None:
                            entry.resources_last_known, entry.resources_last_success_at = resources, resources['captured_at']
                        if entry.running is True and storage is not None:
                            entry.data = _empty(code='VM_STORAGE_NOT_VERIFIED')
                        if entry.running is True and resources is not None:
                            entry.resources = _empty_resources(code='VM_RESOURCES_NOT_VERIFIED')
                except (OSError, ValueError, TypeError, RecursionError):
                    pass  # A bad observation cannot prevent a fresh safe probe.
            while self._current(key, entry) and entry.running is True:
                if not await self._verify_admission(key, entry):
                    break
                entry.wake.clear()
                entry.lifecycle_busy = await finish_file_view_work(self._lifecycle_busy, key)
                if entry.lifecycle_busy:
                    self._publish(key, entry, _empty(code='VM_STORAGE_LIFECYCLE_BUSY'), fresh=False)
                    self._publish_resources(key, entry, _empty_resources(code='VM_RESOURCES_LIFECYCLE_BUSY'), fresh=False)
                    entry.cpu_baseline = None
                else:
                    await self._probe(key, entry)
                if not self._current(key, entry) or entry.running is not True:
                    break
                try:
                    delay = min(self.resource_interval, self.poll_interval)
                    await asyncio.wait_for(entry.wake.wait(), timeout=delay)
                except asyncio.TimeoutError:
                    pass
            if self._current(key, entry) and entry.needs_persist:
                entry.needs_persist = False
                await finish_file_view_work(self._persist, key, entry)
        except asyncio.CancelledError:
            raise
        except Exception:
            self._publish(key, entry, _empty(code='VM_STORAGE_PROBE_FAILED'), fresh=False)
            self._publish_resources(key, entry, _empty_resources(code='VM_RESOURCES_PROBE_FAILED'), fresh=False)
        finally:
            entry.refreshing = False
            entry.resources_refreshing, entry.probing = False, False
            if entry.task is asyncio.current_task():
                entry.task = None
            if self._current(key, entry) and entry.needs_persist:
                self._schedule(key, wake=False)

    async def _probe(self, key, entry):
        from .manager import EnvironmentManager
        from .file_views import finish_file_view_work
        from harnessy.diagnostics import log_event
        started = time.monotonic()
        baseline_epoch = entry.baseline_epoch
        include_storage = bool(entry.force_storage or started >= entry.storage_due_at)
        entry.probing, entry.active_storage = True, include_storage
        entry.resources_refreshing, entry.resources_pending = True, True
        if include_storage:
            entry.refreshing, entry.pending, entry.force_storage = True, True, False
            entry.storage_due_at = started + self.poll_interval
        storage_payload, resources = None, None
        storage_fresh, resources_fresh = False, False
        try:
            provider = await finish_file_view_work(lambda: EnvironmentManager(key[0], environment_id=key[1]).provider())
            combined = getattr(provider, 'usage_snapshot', None)
            if callable(combined):
                envelope = await asyncio.wait_for(combined(include_storage=include_storage), timeout=self.probe_timeout)
                if not isinstance(envelope, dict) or type(envelope.get('schema_version')) is not int or envelope['schema_version'] != 1:
                    raise ValueError('Invalid combined usage receipt.')
                raw_resources = envelope.get('resources')
                raw_storage = envelope.get('storage')
            else:
                # Older integrations can still report storage. They must not
                # invent resource measurements or add a second guest command.
                raw_storage = await asyncio.wait_for(provider.storage_usage(), timeout=self.probe_timeout) if include_storage else None
                raw_resources = None
            try:
                if raw_resources is None:
                    resources = _empty_resources('unsupported', 'GUEST_RESOURCES_UNSUPPORTED')
                    entry.cpu_baseline = None
                else:
                    resources = sanitize_resource_usage(raw_resources)
                    if resources['cpu']['state'] in {'ready', 'pending'}:
                        cpu, baseline = calculate_cpu_usage(raw_resources.get('_cpu_sample'), entry.cpu_baseline)
                        if (cpu['logical_count'] is not None and resources['cpu']['logical_count'] is not None
                                and cpu['logical_count'] != resources['cpu']['logical_count']):
                            raise ValueError('CPU count changed inside one resource receipt.')
                        resources['cpu'], entry.cpu_baseline = cpu, baseline
                        resources['state'] = _resource_state(resources)
                    else:
                        entry.cpu_baseline = None
                    resources_fresh = resources['state'] in {'ready', 'partial', 'stopped'}
            except (ValueError, TypeError, OverflowError):
                resources = _empty_resources(code='VM_RESOURCES_INVALID_RECEIPT')
                entry.cpu_baseline = None
            if include_storage:
                try:
                    storage_payload = sanitize_storage_usage(raw_storage)
                    storage_fresh = storage_payload['state'] in {'ready', 'partial', 'stopped'}
                except (ValueError, TypeError):
                    storage_payload = _empty(code='VM_STORAGE_INVALID_RECEIPT')
        except asyncio.TimeoutError:
            resources = _empty_resources(code='VM_RESOURCES_PROBE_TIMEOUT')
            if include_storage:
                storage_payload = _empty(code='VM_STORAGE_PROBE_TIMEOUT')
            entry.cpu_baseline = None
        except asyncio.CancelledError:
            entry.cpu_baseline = None
            raise
        except (ValueError, TypeError):
            resources = _empty_resources(code='VM_RESOURCES_INVALID_RECEIPT')
            if include_storage:
                storage_payload = _empty(code='VM_STORAGE_INVALID_RECEIPT')
            entry.cpu_baseline = None
        except Exception:
            resources = _empty_resources(code='VM_RESOURCES_PROBE_FAILED')
            if include_storage:
                storage_payload = _empty(code='VM_STORAGE_PROBE_FAILED')
            entry.cpu_baseline = None
        finally:
            entry.refreshing, entry.resources_refreshing, entry.probing = False, False, False
        if not await self._verify_admission(key, entry) or entry.running is not True:
            return
        if baseline_epoch != entry.baseline_epoch:
            # An operation reset the VM while this snapshot was in flight.
            # Its old counters must not become the baseline for the new boot.
            resources, resources_fresh = _empty_resources(code='VM_RESOURCES_NOT_VERIFIED'), False
            entry.cpu_baseline = None
        self._publish_resources(key, entry, resources, fresh=resources_fresh)
        if include_storage:
            self._publish(key, entry, storage_payload, fresh=storage_fresh)
        if resources['state'] == 'stopped' or (storage_payload is not None and storage_payload['guest']['state'] == 'stopped'):
            entry.running, entry.cpu_baseline = False, None
        try:
            await finish_file_view_work(self._persist, key, entry)
        except asyncio.CancelledError:
            raise
        except Exception:
            entry.data = {**entry.data, 'error_code': 'VM_STORAGE_STATUS_WRITE_FAILED'}
        if include_storage:
            signature = (storage_payload['state'], storage_payload.get('error_code'), storage_payload['guest']['state'], storage_payload['host']['state'])
            if self._logged.get(key) != signature:
                self._logged[key] = signature
                log_event('runtime', 'vm_storage_observation_finished', environment_id=key[1],
                          state=storage_payload['state'], error_code=storage_payload.get('error_code', ''),
                          guest_state=storage_payload['guest']['state'], host_state=storage_payload['host']['state'],
                          duration_seconds=max(0.0, time.monotonic() - started))
        resource_key = (*key, 'resources')
        signature = (resources['state'], resources.get('error_code'), resources['cpu']['state'])
        if self._logged.get(resource_key) != signature:
            self._logged[resource_key] = signature
            log_event('runtime', 'vm_resources_observation_finished', environment_id=key[1],
                      state=resources['state'], error_code=resources.get('error_code', ''),
                      cpu_state=resources['cpu']['state'], duration_seconds=max(0.0, time.monotonic() - started))

    async def close(self, root=None, *, environment_id=None):
        canonical = str(Path(root).expanduser().absolute()) if root is not None else None
        with self._lock:
            keys = [key for key in self._entries if (canonical is None or key[0] == canonical)
                    and (environment_id is None or key[1] == environment_id)]
            entries = [self._entries.pop(key) for key in keys]
            for key in keys:
                self._logged.pop(key, None)
                self._logged.pop((*key, 'resources'), None)
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
