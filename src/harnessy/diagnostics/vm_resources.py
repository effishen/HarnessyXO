"""Bounded CPU, memory and load receipts; export never contacts a guest."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import time
from typing import Any

_STATES = frozenset({'ready', 'partial', 'unavailable', 'stopped', 'unsupported', 'checking', 'pending'})
_CODES = frozenset({'', 'GUEST_RESOURCES_STOPPED', 'GUEST_RESOURCES_UNSUPPORTED',
    'GUEST_RESOURCES_UNAVAILABLE', 'GUEST_RESOURCES_PROBE_FAILED', 'GUEST_RESOURCES_INVALID_OUTPUT',
    'VM_RESOURCES_NOT_OBSERVED', 'VM_RESOURCES_NOT_VERIFIED', 'VM_RESOURCES_WORKSPACE_UNAVAILABLE',
    'VM_RESOURCES_LIFECYCLE_BUSY', 'VM_RESOURCES_PROBE_TIMEOUT',
    'VM_RESOURCES_PROBE_FAILED', 'VM_RESOURCES_INVALID_RECEIPT'})
_COUNTERS = ('total_bytes', 'available_bytes', 'used_bytes', 'cache_bytes', 'buffers_bytes')
_FRESH_SECONDS = 13  # Default 5-second resource cadence plus 8-second probe deadline.


def _counter(value: Any) -> int | None:
    return value if type(value) is int and 0 <= value <= 2**63 - 1 else None


def _number(value: Any, *, maximum: float = 1e12) -> int | float | None:
    if type(value) in (int, float) and 0 <= value <= maximum and math.isfinite(value):
        return value
    return None


def _state(value: Any) -> str:
    return value if isinstance(value, str) and value in _STATES else 'unavailable'


def _code(source: dict[str, Any], target: dict[str, Any]) -> None:
    value = source.get('error_code')
    if isinstance(value, str) and value in _CODES:
        target['error_code'] = value


def project_resources(value: Any) -> dict[str, Any]:
    """Project an untrusted observation through reviewed numeric fields only."""
    if not isinstance(value, dict) or type(value.get('schema_version')) is not int or value['schema_version'] != 1:
        raise ValueError('Invalid resource receipt schema.')
    output: dict[str, Any] = {'schema_version': 1, 'state': _state(value.get('state'))}
    _code(value, output)
    for name in ('captured_at', 'observed_at', 'last_success_at'):
        number = _number(value.get(name))
        if number is not None:
            output[name] = number
    for name in ('fresh', 'refreshing', 'observation_pending'):
        if isinstance(value.get(name), bool):
            output[name] = value[name]
    captured = output.get('captured_at')
    current = output['state'] in {'ready', 'partial'}
    output['fresh'] = bool(current and output.get('fresh') and captured is not None
                           and 0 <= time.time() - captured <= _FRESH_SECONDS)
    for name in ('cpu', 'memory', 'swap', 'load'):
        source = value.get(name)
        source = source if isinstance(source, dict) else {}
        target: dict[str, Any] = {'state': _state(source.get('state'))}
        if not current:
            target['state'] = output['state']
        _code(source, target)
        ready = target['state'] == 'ready'
        if name == 'cpu':
            count = source.get('logical_count')
            target['logical_count'] = count if current and type(count) is int and 1 <= count <= 4096 else None
            for field in ('usage_percent', 'iowait_percent', 'steal_percent'):
                target[field] = _number(source.get(field), maximum=100) if ready else None
            sample = _number(source.get('sample_seconds'), maximum=3600)
            target['sample_seconds'] = sample if ready and sample is not None and sample > 0 else None
        elif name in {'memory', 'swap'}:
            fields = _COUNTERS if name == 'memory' else ('total_bytes', 'used_bytes', 'free_bytes')
            for field in fields:
                target[field] = _counter(source.get(field)) if ready else None
            if name == 'memory' and ready:
                kind = source.get('available_source')
                if isinstance(kind, str) and kind in {'mem_available', 'estimated'}:
                    target['available_source'] = kind
                if isinstance(source.get('available_estimated'), bool):
                    target['available_estimated'] = source['available_estimated']
        else:
            for field in ('one', 'five', 'fifteen'):
                target[field] = _number(source.get(field), maximum=1e9) if ready else None
        output[name] = target
    output['uptime_seconds'] = (_number(value.get('uptime_seconds'))
                                if output['state'] in {'ready', 'partial'} else None)
    return output


def collect_resource_diagnostics(latest: Path) -> dict[str, Any]:
    from .vm_logs import _discover_workspaces, _runtime_environments, _read_tail
    deadline = time.monotonic() + 3
    roots, discovery = _discover_workspaces(Path(latest).absolute(), deadline)
    output: dict[str, Any] = {'schema_version': 1, 'status': 'collected',
        'scope': 'persisted_runtime_observations', 'discovery': discovery,
        'captured_at': time.time(),
        'limits': {'environments': 32, 'receipt_bytes': 64 * 1024, 'collection_seconds': 3,
                   'freshness_seconds': _FRESH_SECONDS},
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
                        if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
                                or value['schema_version'] != 1 or value.get('environment_id') != environment_id):
                            raise ValueError('Invalid resource observation identity.')
                        current = value.get('resources')
                        if current is None:
                            row['receipt_status'] = 'not_observed'
                        else:
                            row.update(project_resources(current))
                        previous = value.get('resources_last_known')
                        if isinstance(previous, dict):
                            try:
                                row['last_known'] = project_resources(previous)
                                row['last_known']['fresh'] = False
                            except ValueError:
                                pass
                    except (ValueError, RecursionError, UnicodeError):
                        row['receipt_status'] = 'invalid'
            output['environments'].append(row)
    if not roots:
        output['status'] = 'no_workspaces'
    return output


def summary_lines(report: dict[str, Any]) -> str:
    lines = ['\nVM CPU and memory: retained observations in VM_RESOURCES.json; no live guest probe during export.']
    rows = report.get('environments', [])
    for row in rows[:32] if isinstance(rows, list) else []:
        label = '  VM ' + (row.get('environment_id') or 'legacy')
        if row.get('receipt_status') != 'included':
            lines.append(label + ': resource receipt ' + str(row.get('receipt_status', 'unavailable')) + '.')
            continue
        lines.append(label + ': ' + row.get('state', 'unavailable')
                     + ('; fresh reading.' if row.get('fresh') else '; retained reading, not verified current.')
                     + (' (' + row['error_code'] + ')' if row.get('error_code') else ''))
        for description, sample in (('Current', row), ('Last-known', row.get('last_known'))):
            if not isinstance(sample, dict):
                continue
            lines.append('    ' + description + ' sample at epoch ' + str(sample.get('captured_at', 'unrecorded')) + '.')
            cpu, memory, swap, load = (sample.get(name) or {} for name in ('cpu', 'memory', 'swap', 'load'))
            lines.append('    Guest CPU: ' + cpu.get('state', 'unavailable')
                         + '; usage=' + str(cpu.get('usage_percent')) + '%; iowait='
                         + str(cpu.get('iowait_percent')) + '%; steal=' + str(cpu.get('steal_percent'))
                         + '%; vCPUs=' + str(cpu.get('logical_count'))
                         + '; sample seconds=' + str(cpu.get('sample_seconds')) + '.')
            lines.append('    Guest memory: ' + memory.get('state', 'unavailable')
                         + '; used=' + str(memory.get('used_bytes')) + ', total=' + str(memory.get('total_bytes'))
                         + ', available=' + str(memory.get('available_bytes')) + ', cache='
                         + str(memory.get('cache_bytes')) + ', buffers=' + str(memory.get('buffers_bytes'))
                         + ' bytes; available source=' + str(memory.get('available_source')) + '.')
            lines.append('    Guest swap: ' + swap.get('state', 'unavailable')
                         + '; used=' + str(swap.get('used_bytes')) + ', total=' + str(swap.get('total_bytes'))
                         + ', free=' + str(swap.get('free_bytes')) + ' bytes.')
            lines.append('    Guest load (1/5/15 min): ' + load.get('state', 'unavailable') + '; '
                         + '/'.join(str(load.get(name)) for name in ('one', 'five', 'fifteen'))
                         + '; uptime seconds=' + str(sample.get('uptime_seconds')) + '.')
    if not rows:
        lines.append('  No retained per-VM CPU or memory observations were discovered.')
    lines.append('  A retained sample does not establish resource pressure at the time of a failure.')
    return '\n'.join(lines) + '\n'
