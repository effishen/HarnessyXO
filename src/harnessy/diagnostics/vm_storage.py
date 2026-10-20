"""Bounded, content-free storage receipts; export never contacts a guest."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import time
from typing import Any

_STATES = frozenset({'ready', 'partial', 'unavailable', 'stopped', 'unsupported', 'checking', 'pending'})
_CODES = frozenset({'', 'GUEST_STORAGE_STOPPED', 'GUEST_STORAGE_UNSUPPORTED',
    'GUEST_STORAGE_UNAVAILABLE', 'GUEST_STORAGE_PROBE_FAILED', 'GUEST_STORAGE_INVALID_OUTPUT',
    'HOST_STORAGE_MISSING', 'HOST_STORAGE_UNAVAILABLE', 'HOST_STORAGE_PARTIAL',
    'VM_STORAGE_NOT_OBSERVED', 'VM_STORAGE_NOT_VERIFIED', 'VM_STORAGE_WORKSPACE_UNAVAILABLE',
    'VM_STORAGE_DEFINITION_MISSING', 'VM_STORAGE_LIFECYCLE_BUSY', 'VM_STORAGE_PROBE_TIMEOUT',
    'VM_STORAGE_PROBE_FAILED', 'VM_STORAGE_INVALID_RECEIPT', 'VM_STORAGE_STATUS_WRITE_FAILED'})
_KINDS = frozenset({'ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'tmpfs', 'ramfs',
                    'overlay', 'ntfs', 'refs', 'vfat', 'zfs', 'other'})
_NUMBERS = ('total_bytes', 'used_bytes', 'available_bytes', 'free_bytes',
            'inodes_total', 'inodes_available')


def _number(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 2**64 - 1 else None


def _timestamp(value: Any) -> int | float | None:
    if type(value) in (int, float) and 0 <= value <= 1e12 and math.isfinite(value):
        return value
    return None


def _state(value: Any) -> str:
    return value if isinstance(value, str) and value in _STATES else 'unavailable'


def _code(source: dict[str, Any], target: dict[str, Any]) -> None:
    value = source.get('error_code')
    if isinstance(value, str) and value in _CODES:
        target['error_code'] = value


def project_storage(value: Any, *, include_last_known: bool = True) -> dict[str, Any]:
    """Allow only fixed roles, metrics and typed observation metadata from disk."""
    if not isinstance(value, dict) or type(value.get('schema_version')) is not int or value['schema_version'] != 1:
        raise ValueError('Invalid storage receipt schema.')
    output: dict[str, Any] = {'schema_version': 1, 'state': _state(value.get('state'))}
    _code(value, output)
    for name in ('captured_at', 'observed_at', 'last_success_at'):
        number = _timestamp(value.get(name))
        if number is not None:
            output[name] = number
    for name in ('fresh', 'refreshing', 'observation_pending'):
        if isinstance(value.get(name), bool):
            output[name] = value[name]
    # A retained receipt is fresh only relative to the collector's clock.
    captured = output.get('captured_at')
    output['fresh'] = bool(output.get('fresh') and captured is not None
                           and 0 <= time.time() - captured <= 45)
    guest = value.get('guest')
    output['guest'] = {'state': 'unavailable', 'filesystems': []}
    if isinstance(guest, dict):
        safe = output['guest']
        safe['state'] = _state(guest.get('state'))
        _code(guest, safe)
        rows = guest.get('filesystems')
        seen: set[str] = set()
        if isinstance(rows, list) and safe['state'] == 'ready':
            for row in rows[:8]:
                if not isinstance(row, dict):
                    continue
                role = row.get('role')
                if not isinstance(role, str) or role not in {'root', 'temporary'} or role in seen:
                    continue
                seen.add(role)
                clean: dict[str, Any] = {'role': role}
                for name in _NUMBERS:
                    clean[name] = _number(row.get(name))
                for name in ('read_only', 'memory_backed'):
                    if isinstance(row.get(name), bool):
                        clean[name] = row[name]
                kind = row.get('fs_kind')
                if isinstance(kind, str) and kind in _KINDS:
                    clean['fs_kind'] = kind
                safe['filesystems'].append(clean)
    host = value.get('host')
    output['host'] = {'state': 'unavailable', 'allocated_bytes': None, 'logical_bytes': None}
    if isinstance(host, dict):
        output['host'].update(state=_state(host.get('state')),
            allocated_bytes=_number(host.get('allocated_bytes')),
            logical_bytes=_number(host.get('logical_bytes')))
        _code(host, output['host'])
        if output['host']['state'] not in {'ready', 'partial'}:
            output['host']['allocated_bytes'] = output['host']['logical_bytes'] = None
    if include_last_known and isinstance(value.get('last_known'), dict):
        try:
            output['last_known'] = project_storage(value['last_known'], include_last_known=False)
            output['last_known']['fresh'] = False
        except ValueError:
            pass
    return output


def collect_storage_diagnostics(latest: Path) -> dict[str, Any]:
    from .vm_logs import _discover_workspaces, _runtime_environments, _read_tail
    deadline = time.monotonic() + 3
    roots, discovery = _discover_workspaces(Path(latest).absolute(), deadline)
    output: dict[str, Any] = {'schema_version': 1, 'status': 'collected',
        'scope': 'persisted_runtime_observations', 'discovery': discovery,
        'captured_at': time.time(),
        'limits': {'environments': 32, 'receipt_bytes': 64 * 1024, 'collection_seconds': 3},
        'environments': [], 'limited': False}
    for root, _origin in roots:
        if time.monotonic() >= deadline:
            output['limited'] = True
            break
        environments, truncated = _runtime_environments(root)
        output['limited'] = output['limited'] or truncated
        for environment_id, runtime_root in environments:
            if len(output['environments']) >= 32 or time.monotonic() >= deadline:
                output['limited'] = True
                break
            row = {'workspace_id': hashlib.sha256(str(root).encode()).hexdigest(),
                   'environment_id': environment_id}
            result = _read_tail(runtime_root / 'state' / 'storage-usage.json', 64 * 1024)
            row['receipt_status'] = result['status']
            if result['status'] == 'included':
                if result['truncated']:
                    row['receipt_status'] = 'limited'
                else:
                    try:
                        value = json.loads(result['data'])
                        if not isinstance(value, dict) or value.get('environment_id') != environment_id:
                            raise ValueError('Invalid storage observation identity.')
                        row.update(project_storage(value))
                    except (ValueError, RecursionError, UnicodeError):
                        row['receipt_status'] = 'invalid'
            output['environments'].append(row)
    if not roots:
        output['status'] = 'no_workspaces'
    return output


def summary_lines(report: dict[str, Any]) -> str:
    lines = ['\nVM storage: retained observations in VM_STORAGE.json; no live guest probe during export.']
    rows = report.get('environments', [])
    for row in rows[:32] if isinstance(rows, list) else []:
        label = '  VM ' + (row.get('environment_id') or 'legacy')
        if row.get('receipt_status') != 'included':
            lines.append(label + ': storage receipt ' + str(row.get('receipt_status', 'unavailable')) + '.')
            continue
        lines.append(label + ': ' + row.get('state', 'unavailable')
                     + ('; fresh reading.' if row.get('fresh') else '; last observed reading, not verified current.'))
        sample = row.get('last_known') if row.get('state') not in {'ready', 'partial'} else row
        if not isinstance(sample, dict):
            sample = row
        if sample is not row:
            lines.append('    Following metrics are explicitly last-known, captured at epoch ' + str(sample.get('captured_at', 'unrecorded')) + '.')
        for fs in sample.get('guest', {}).get('filesystems', []):
            free = fs.get('available_bytes')
            total = fs.get('total_bytes')
            used = fs.get('used_bytes')
            lines.append('    Guest ' + fs['role'] + ': used=' + str(used) + ', total=' + str(total)
                         + ', available=' + str(free) + ' bytes; inodes available='
                         + str(fs.get('inodes_available')) + '; read-only=' + str(fs.get('read_only')) + '.')
            if free == 0 and total is not None and total > 0:
                lines.append('    WARNING: no available bytes in this observation.')
            if fs.get('inodes_available') == 0 and (fs.get('inodes_total') or 0) > 0:
                lines.append('    WARNING: no available inodes in this observation.')
        host = sample.get('host') or {}
        lines.append('    Host disk images: allocated=' + str(host.get('allocated_bytes'))
                     + ', logical=' + str(host.get('logical_bytes')) + ' bytes.')
    if not rows:
        lines.append('  No retained per-VM storage observations were discovered.')
    lines.append('  Storage pressure at another time and the cause of a failure remain unverified by these samples alone.')
    return '\n'.join(lines) + '\n'
