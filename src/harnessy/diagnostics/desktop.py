"""Bounded desktop readiness receipts; export never contacts a guest."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any
import uuid

FILENAME = 'desktop.json'
MAX_RECEIPTS = 8
MAX_RECEIPT_BYTES = 64 * 1024
_STATES = frozenset({'ready', 'unavailable', 'checking', 'reboot_required',
                     'manual_boot_required', 'failed', 'disabled', 'unknown'})
ERROR_CODES = frozenset({'NONE', 'DESKTOP_PROBE_FAILED', 'DESKTOP_PREREQUISITE_MISSING',
    'DESKTOP_OFFLINE', 'DESKTOP_APT_UPDATE_FAILED', 'DESKTOP_APT_INSTALL_FAILED',
    'DESKTOP_KERNEL_UNSUPPORTED', 'DESKTOP_KERNEL_VERIFY_FAILED', 'DESKTOP_BOOT_POLICY_CUSTOM',
    'DESKTOP_BOOT_VERIFY_FAILED', 'DESKTOP_SESSION_NOT_READY', 'DESKTOP_REPAIR_TIMEOUT',
    'DESKTOP_REPAIR_CANCELLED', 'DESKTOP_REPAIR_BUSY', 'DESKTOP_ARCH_MISMATCH', 'DESKTOP_REPAIR_FAILED'})
FAILURE_REASONS = frozenset({'dns_failed', 'network_timeout', 'repository_error',
    'package_unavailable', 'package_lock', 'storage_full', 'package_command_failed',
    'command_timeout', 'unknown'})
PHASES = frozenset({'checking', 'package_index', 'packages', 'kernel', 'boot', 'session', 'verifying'})
_LIVE_SECONDS = ('elapsed_seconds', 'command_elapsed_seconds', 'last_output_age_seconds')
BOOLEAN_FIELDS = ('cloud_kernel', 'drm_configured', 'drm_supported', 'virtio_gpu_configured',
                  'virtio_gpu_module', 'virtio_gpu_loaded', 'scanout_active', 'framebuffer',
                  'lightdm_active', 'xorg_installed', 'xfce_installed', 'xorg_running',
                  'xfce_running', 'x11_socket')
COUNT_FIELDS = ('drm_cards', 'drm_connectors')
_ID = re.compile(r'^[0-9a-f]{32}$')
_HASH = re.compile(r'^[0-9a-f]{64}$')
_PERSIST_LOCK = threading.Lock()


def _location(workspace_root, environment_id, runtime_root=None):
    from .vm_logs import _workspace_path, _runtime_root
    root = _workspace_path(workspace_root)
    if root is None:
        raise ValueError('Invalid desktop workspace identity.')
    runtime = _runtime_root(root, environment_id, runtime_root)
    return root, runtime, hashlib.sha256(str(root).encode()).hexdigest()


def project_desktop(value: Any) -> dict[str, Any]:
    """Retain only reviewed fixed types, never raw guest or kernel strings."""
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1 or value.get('revision') != '1'):
        raise ValueError('Invalid desktop receipt schema.')
    eid, wid = value.get('environment_id'), value.get('workspace_id')
    if (not isinstance(eid, str) or (eid and not _ID.fullmatch(eid))
            or not isinstance(wid, str) or not _HASH.fullmatch(wid)):
        raise ValueError('Invalid desktop receipt identity.')
    state, code = value.get('state'), value.get('error_code', 'NONE')
    if not isinstance(state, str) or state not in _STATES or not isinstance(code, str) or code not in ERROR_CODES:
        raise ValueError('Invalid desktop receipt category.')
    if state == 'ready' and code != 'NONE':
        raise ValueError('Contradictory desktop readiness error.')
    stamp = value.get('observed_at_epoch')
    if type(stamp) not in (int, float) or not 0 <= stamp <= 1e12 or not math.isfinite(stamp):
        raise ValueError('Invalid desktop observation timestamp.')
    out = {'schema_version': 1, 'revision': '1', 'environment_id': eid,
           'workspace_id': wid, 'state': state, 'error_code': code, 'observed_at_epoch': stamp}
    reason = value.get('failure_reason', 'unknown')
    if not isinstance(reason, str) or reason not in FAILURE_REASONS:
        raise ValueError('Invalid desktop failure reason.')
    out['failure_reason'] = reason
    boot = value.get('boot_id')
    if boot is not None:
        if not isinstance(boot, str) or len(boot) != 36:
            raise ValueError('Invalid desktop boot identity.')
        try:
            parsed = uuid.UUID(boot)
        except ValueError:
            raise ValueError('Invalid desktop boot identity.') from None
        if str(parsed) != boot.lower():
            raise ValueError('Invalid desktop boot identity.')
        out['boot_id'] = str(parsed)
    live_fields = ('phase', *_LIVE_SECONDS, 'output_bytes')
    if any(name in value for name in live_fields):
        if 'boot_id' not in out:
            raise ValueError('Live desktop observations require a boot identity.')
        phase = value.get('phase')
        if not isinstance(phase, str) or phase not in PHASES:
            raise ValueError('Invalid desktop observation phase.')
        out['phase'] = phase
        for name in _LIVE_SECONDS:
            item = value.get(name)
            if item is None and name == 'last_output_age_seconds':
                out[name] = None
            elif type(item) not in (int, float) or not 0 <= item <= 900 or not math.isfinite(item):
                raise ValueError('Invalid desktop observation duration.')
            else:
                out[name] = item
        count = value.get('output_bytes')
        if type(count) is not int or not 0 <= count <= 2**40:
            raise ValueError('Invalid desktop output byte count.')
        out['output_bytes'] = count
    for name in BOOLEAN_FIELDS:
        item = value.get(name)
        if item is not None and type(item) is not bool:
            raise ValueError('Invalid desktop boolean observation.')
        out[name] = item
    for name in COUNT_FIELDS:
        item = value.get(name)
        if item is not None and (type(item) is not int or not 0 <= item <= (8 if name == 'drm_cards' else 32)):
            raise ValueError('Invalid desktop count observation.')
        out[name] = item
    if state == 'ready' and ('boot_id' not in out or not out['drm_cards']
            or not out['drm_connectors'] or any(out[name] is not True for name in
                ('scanout_active', 'lightdm_active', 'xorg_installed', 'xfce_installed',
                 'xorg_running', 'xfce_running', 'x11_socket'))):
        raise ValueError('Desktop readiness has no display/session proof.')
    return out


def _normalize_snapshot(snapshot):
    """Translate the reviewed probe enums to the smaller diagnostics schema."""
    if 'schema_version' in snapshot and (type(snapshot['schema_version']) is not int or snapshot['schema_version'] != 1):
        raise ValueError('Invalid desktop probe schema.')
    value = dict(snapshot)
    for source, target, allowed, true_value in (
            ('drm_config', 'drm_configured', {'y', 'm', 'n', 'unknown'}, {'y', 'm'}),
            ('virtio_gpu_config', 'virtio_gpu_configured', {'y', 'm', 'n', 'unknown'}, {'y', 'm'}),
            ('kernel_graphics', 'drm_supported', {'supported', 'unsupported', 'unknown'}, {'supported'})):
        if source not in snapshot:
            continue
        item = snapshot[source]
        if not isinstance(item, str) or item not in allowed:
            raise ValueError('Invalid desktop probe category.')
        normalized = None if item == 'unknown' else item in true_value
        if target in snapshot and snapshot[target] is not normalized:
            raise ValueError('Contradictory desktop probe category.')
        value[target] = normalized
    active = snapshot.get('lightdm_active')
    if isinstance(active, str):
        if active not in {'active', 'inactive', 'failed', 'activating', 'deactivating', 'unknown'}:
            raise ValueError('Invalid desktop service category.')
        value['lightdm_active'] = None if active == 'unknown' else active == 'active'
    value['revision'] = snapshot.get('revision', '1')
    if value.get('boot_id') == '':
        value.pop('boot_id')
    return value


def _project_document(value, wid, eid):
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1 or value.get('workspace_id') != wid
            or value.get('environment_id') != eid or not isinstance(value.get('receipts'), list)
            or not 1 <= len(value['receipts']) <= MAX_RECEIPTS):
        raise ValueError('Invalid desktop receipt document.')
    rows = [project_desktop(row) for row in value['receipts']]
    if any(row['environment_id'] != eid or row['workspace_id'] != wid for row in rows):
        raise ValueError('Mismatched desktop receipt identity.')
    return {'schema_version': 1, 'workspace_id': wid, 'environment_id': eid, 'receipts': rows}


def _read_document(runtime, wid, eid):
    from .vm_logs import _open_regular
    descriptor = None
    try:
        descriptor = _open_regular(runtime / 'state' / FILENAME)
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            return None, 'unsafe'
        if info.st_size > MAX_RECEIPT_BYTES:
            return None, 'limited'
        payload = os.read(descriptor, MAX_RECEIPT_BYTES + 1)
        if len(payload) > MAX_RECEIPT_BYTES:
            return None, 'limited'
        try:
            return _project_document(json.loads(payload), wid, eid), 'included'
        except (ValueError, RecursionError, UnicodeError):
            return None, 'invalid'
    except FileNotFoundError:
        return None, 'missing'
    except ValueError:
        return None, 'unsafe'
    except OSError:
        return None, 'unreadable'
    finally:
        if descriptor is not None:
            os.close(descriptor)


def latest_desktop(workspace_root, environment_id, runtime_root=None) -> dict[str, Any] | None:
    """Return only a revalidated saved snapshot; never start/probe a VM."""
    try:
        _root, runtime, wid = _location(workspace_root, environment_id, runtime_root)
        document, _status = _read_document(runtime, wid, environment_id)
        return document['receipts'][-1] if document else None
    except (OSError, ValueError, TypeError):
        return None


def record_desktop(workspace_root, environment_id, runtime_root, snapshot) -> bool:
    """Atomically retain eight fixed observations without recreating a VM root."""
    from .workspace_mounts import _open_state_directory
    from .vm_logs import register_workspace_runtime
    parent = lock = descriptor = None
    temporary = '.desktop-' + uuid.uuid4().hex
    acquired = False
    try:
        root, runtime, wid = _location(workspace_root, environment_id, runtime_root)
        if not isinstance(snapshot, dict):
            return False
        receipt = project_desktop({**_normalize_snapshot(snapshot), 'schema_version': 1,
            'workspace_id': wid, 'environment_id': environment_id,
            'observed_at_epoch': snapshot.get('observed_at_epoch', time.time())})
        acquired = _PERSIST_LOCK.acquire(blocking=False)
        if not acquired:
            return False
        parent = _open_state_directory(runtime)
        if stat.S_IMODE(os.fstat(parent).st_mode) & 0o077:
            return False
        import fcntl
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0)
        lock = os.open('.desktop.lock', flags, 0o600, dir_fd=parent)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            return False
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            info = os.stat(FILENAME, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                return False
        except FileNotFoundError:
            pass
        previous, _status = _read_document(runtime, wid, environment_id)
        rows = previous['receipts'] if previous else []
        document = {'schema_version': 1, 'workspace_id': wid, 'environment_id': environment_id,
                    'receipts': [*rows, receipt][-MAX_RECEIPTS:]}
        payload = json.dumps(document, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
        if len(payload) > MAX_RECEIPT_BYTES:
            return False
        descriptor = os.open(temporary, flags | os.O_EXCL, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, 'wb') as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, FILENAME, src_dir_fd=parent, dst_dir_fd=parent)
        register_workspace_runtime(root, environment_id=environment_id, runtime_root=runtime)
        return True
    except (OSError, ValueError, TypeError, RecursionError, ImportError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            try:
                os.unlink(temporary, dir_fd=parent)
            except OSError:
                pass
            os.close(parent)
        if lock is not None:
            os.close(lock)
        if acquired:
            _PERSIST_LOCK.release()


def collect_desktop_diagnostics(latest: Path) -> dict[str, Any]:
    from .vm_logs import _discover_workspaces, _runtime_environments
    deadline = time.monotonic() + 3
    roots, discovery = _discover_workspaces(Path(latest).absolute(), deadline)
    report = {'schema_version': 1, 'status': 'collected' if roots else 'no_workspaces',
        'scope': 'persisted_runtime_observations', 'captured_at': time.time(), 'discovery': discovery,
        'limits': {'environments': 32, 'receipts_per_environment': MAX_RECEIPTS,
                   'receipt_bytes': MAX_RECEIPT_BYTES, 'collection_seconds': 3},
        'environments': [], 'limited': False}
    for root, _origin in roots:
        if time.monotonic() >= deadline:
            report['limited'] = True
            break
        environments, limited = _runtime_environments(root)
        report['limited'] |= limited
        for eid, runtime in environments:
            if len(report['environments']) >= 32 or time.monotonic() >= deadline:
                report['limited'] = True
                break
            wid = hashlib.sha256(str(root).encode()).hexdigest()
            document, status = _read_document(runtime, wid, eid)
            row = {'workspace_id': wid, 'environment_id': eid, 'receipt_status': status, 'receipts': []}
            if document:
                row.update(document)
                row['latest_capture'] = document['receipts'][-1]
            report['environments'].append(row)
    return report


def summary_lines(report) -> str:
    lines = ['\nVM desktops: retained observations in VM_DESKTOP.json; no live guest probe during export.']
    rows = report.get('environments', [])
    for row in rows[:32] if isinstance(rows, list) else []:
        label = '  VM ' + (row.get('environment_id') or 'legacy')
        sample = row.get('latest_capture')
        if row.get('receipt_status') != 'included' or not isinstance(sample, dict):
            lines.append(label + ': desktop receipt ' + str(row.get('receipt_status', 'unavailable')) + '.')
        else:
            phase = sample.get('phase')
            if phase is None and sample.get('boot_id'):
                receipts = row.get('receipts', [])
                phase = next((item['phase'] for item in reversed(receipts[-MAX_RECEIPTS:])
                              if isinstance(item, dict) and item.get('boot_id') == sample['boot_id']
                              and item.get('phase') in PHASES), None)
            lines.append(label + ': last observed ' + sample['state'] + ', epoch '
                         + str(sample['observed_at_epoch']) + ('; ' + sample['error_code'] if sample['error_code'] else '')
                         + ('; reason=' + sample['failure_reason'] if sample['failure_reason'] != 'unknown' else '')
                         + ('; last observed phase=' + phase if phase is not None else '') + '.')
    if not rows:
        lines.append('  No retained per-VM desktop observations were discovered.')
    lines.append('  Retained observations do not establish the current boot or desktop health.')
    return '\n'.join(lines) + '\n'
