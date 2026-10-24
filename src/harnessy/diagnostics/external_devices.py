"""Host-side observations of already requested external-device operations.

This collector never resolves a target, reads credentials, opens a database or
connects to a device. Only fixed event labels, opaque identities and numeric
facts escape; commands, addresses, output and exception text never do.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import time
from typing import Any
import uuid


MAX_ROWS = 512
MAX_SOURCES = 12
PER_SOURCE_BYTES = 512 * 1024
MAX_READ_BYTES = 4 * 1024 * 1024
MAX_PARSE_LINES = 20000
COLLECTION_SECONDS = 3.0
_HEX = re.compile(r'^[0-9a-f]{64}$')
_OPERATIONS = frozenset({'connection_test', 'status', 'exec', 'list_files',
                         'copy_to', 'copy_from', 'ssh_command', 'access_check'})
_PHASES = frozenset({'requested', 'finished', 'blocked'})
_OUTCOMES = frozenset({'requested', 'success', 'remote_failure', 'transport_failure',
    'timeout', 'cancelled', 'spawn_failed', 'client_missing', 'permission_blocked',
    'access_blocked', 'policy_changed', 'target_unavailable', 'local_failure'})
_ERROR_CODES = frozenset({'connection_timeout', 'connection_refused', 'connection_reset',
    'connection_closed', 'network_unreachable', 'dns_resolution_failed',
    'authentication_failed', 'host_key_failed', 'channel_open_failed', 'session_limit',
    'local_resource_limit', 'permission_denied', 'client_missing', 'operation_timeout',
    'operation_cancelled', 'project_access_denied', 'action_disabled',
    'approval_required', 'connection_settings_changed', 'target_unavailable',
    'remote_exit_nonzero', 'ssh_transport_failure', 'local_failure'})
_COUNTERS = frozenset({'stdin_bytes', 'stdout_bytes', 'stderr_bytes'})
_FLAGS = frozenset({'stdout_truncated', 'stderr_truncated', 'output_partial'})


def _number(value: Any, maximum: float = 1e9) -> int | float | None:
    return value if type(value) in (int, float) and 0 <= value <= maximum and math.isfinite(value) else None


def _identity(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if _HEX.fullmatch(value):
        return value
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    return value if value.lower() in {parsed.hex, str(parsed)} else None


def _timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 48:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.isoformat(timespec='milliseconds') if parsed.tzinfo else None
    except (ValueError, OverflowError):
        return None


def validate_external_device_observation(value: Any) -> dict[str, Any] | None:
    """Rebuild the entire record, including records from older saved logs."""
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1 or value.get('transport') != 'ssh'
            or not isinstance(value.get('operation'), str) or value['operation'] not in _OPERATIONS
            or not isinstance(value.get('phase'), str) or value['phase'] not in _PHASES
            or not isinstance(value.get('outcome'), str) or value['outcome'] not in _OUTCOMES
            or not isinstance(value.get('device_id'), str) or not _HEX.fullmatch(value['device_id'])):
        return None
    result: dict[str, Any] = {'schema_version': 1, 'transport': 'ssh',
        'device_id': value['device_id'], 'operation': value['operation'],
        'phase': value['phase'], 'outcome': value['outcome'],
        'timing_scope': 'host_process_lifetime'}
    stamp = _timestamp(value.get('observed_at'))
    if stamp is not None:
        result['observed_at'] = stamp
    for name in ('workspace_id', 'chat_id', 'request_id'):
        identity = _identity(value.get(name))
        if identity is not None:
            result[name] = identity
    for name in ('duration_seconds', 'host_spawn_seconds'):
        number = _number(value.get(name))
        if number is not None:
            result[name] = number
    if type(value.get('returncode')) is int and -255 <= value['returncode'] <= 255:
        result['returncode'] = value['returncode']
    for name in _COUNTERS:
        number = value.get(name)
        if type(number) is int and 0 <= number <= 2**50:
            result[name] = number
    for name in _FLAGS:
        if type(value.get(name)) is bool:
            result[name] = value[name]
    codes = value.get('error_codes')
    result['error_codes'] = sorted({code for code in codes[:len(_ERROR_CODES)]
        if isinstance(code, str) and code in _ERROR_CODES}) if isinstance(codes, list) else []
    return result


def transport_error_codes(stderr: Any) -> list[str]:
    """Classify a bounded tail without ever retaining any guest/SSH prose."""
    text = stderr[-16384:].decode('utf-8', errors='replace') if isinstance(stderr, bytes) else (
        stderr[-16384:] if isinstance(stderr, str) else '')
    lower = text.lower()
    patterns = {
        'connection_timeout': ('connection timed out', 'operation timed out', 'connect timeout'),
        'connection_refused': ('connection refused',),
        'connection_reset': ('connection reset', 'reset by peer'),
        'connection_closed': ('connection closed', 'broken pipe', 'connection lost'),
        'network_unreachable': ('network is unreachable', 'no route to host'),
        'dns_resolution_failed': ('could not resolve hostname', 'name or service not known', 'temporary failure in name resolution'),
        'authentication_failed': ('permission denied (publickey', 'permission denied (password', 'authentication failed', 'too many authentication failures'),
        'host_key_failed': ('host key verification failed', 'remote host identification has changed', 'offending key'),
        'channel_open_failed': ('channel open failed', 'open failed: administratively prohibited', 'open failed: connect failed'),
        'session_limit': ('too many sessions', 'session open refused', 'maxsessions', 'maxstartups'),
        'local_resource_limit': ('too many open files', 'resource temporarily unavailable', 'cannot allocate memory'),
    }
    return sorted(code for code, needles in patterns.items() if any(needle in lower for needle in needles))


def record_external_device_observation(workspace_id: Any, target_id: Any, *, chat_id: Any = '',
        operation: str = 'ssh_command', phase: str, outcome: str, request_id: str = '',
        stderr: Any = b'', error_codes: Any = None, **facts: Any) -> None:
    """Record host facts only; failure to log must never affect an operation."""
    if not isinstance(workspace_id, str) or not isinstance(target_id, str):
        return
    row: dict[str, Any] = {**facts, 'schema_version': 1, 'transport': 'ssh',
        'device_id': hashlib.sha256((workspace_id + '\0' + target_id).encode()).hexdigest(),
        'workspace_id': _identity(workspace_id) or hashlib.sha256(workspace_id.encode()).hexdigest(),
        'operation': operation, 'phase': phase, 'outcome': outcome,
        'observed_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
        'error_codes': transport_error_codes(stderr)}
    if isinstance(chat_id, str) and chat_id:
        row['chat_id'] = _identity(chat_id) or hashlib.sha256(chat_id.encode()).hexdigest()
    if request_id:
        row['request_id'] = request_id
    if isinstance(error_codes, (list, tuple)):
        row['error_codes'] += [code for code in error_codes if isinstance(code, str) and code in _ERROR_CODES]
    safe = validate_external_device_observation(row)
    if safe is not None:
        try:
            from .logging import log_event
            log_event('targets', 'external_device_observation', external_device=safe)
        except Exception:
            pass


def validate_external_device_report(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError('Invalid external-device report')
    raw = value.get('observations')
    records = [safe for row in raw[-MAX_ROWS:] if (safe := validate_external_device_observation(row)) is not None] if isinstance(raw, list) else []
    outcomes, operations = Counter(row['outcome'] for row in records), Counter(row['operation'] for row in records)
    result: dict[str, Any] = {'schema_version': 1, 'status': 'unavailable' if value.get('status') == 'unavailable' else 'collected',
        'scope': 'existing_host_observations_only', 'device_connections_for_diagnostics': 0,
        'device_commands_for_diagnostics': 0, 'counts_are_retained_observations': True,
        'permission_evidence': 'PERMISSIONS.json', 'observations_retained': len(records),
        'devices_observed': len({row['device_id'] for row in records}),
        'outcomes': dict(sorted(outcomes.items())), 'operations': dict(sorted(operations.items())),
        'observations': records, 'limited': value.get('limited') is True,
        'limits': {'observations': MAX_ROWS, 'sources': MAX_SOURCES, 'read_bytes': MAX_READ_BYTES,
                   'per_source_bytes': PER_SOURCE_BYTES, 'parse_lines': MAX_PARSE_LINES,
                   'collection_seconds': COLLECTION_SECONDS}, 'sources': []}
    captured = _number(value.get('captured_at_epoch'), maximum=1e12)
    if captured is not None:
        result['captured_at_epoch'] = captured
    sources = value.get('sources')
    for source in sources[:MAX_SOURCES] if isinstance(sources, list) else []:
        if (not isinstance(source, dict) or not isinstance(source.get('scope'), str)
                or source['scope'] not in {'current', 'previous'}
                or type(source.get('rotation')) is not int or not 0 <= source['rotation'] <= 2
                or not isinstance(source.get('status'), str)
                or source['status'] not in {'included', 'missing', 'unsafe', 'unreadable', 'limited'}):
            continue
        row = {key: source[key] for key in ('scope', 'rotation', 'status')}
        for key in ('bytes_available', 'bytes_read', 'records_examined', 'invalid_observations'):
            number = source.get(key)
            if type(number) is int and 0 <= number <= 2**63 - 1:
                row[key] = number
        row['truncated'] = source.get('truncated') is True
        result['sources'].append(row)
    return result


def collect_external_device_diagnostics(latest: Path) -> dict[str, Any]:
    """Read bounded local receipts. This function has no device/network API."""
    from .vm_logs import _read_tail, _previous_sessions, _complete_lines
    latest = Path(latest).absolute()
    deadline = time.monotonic() + COLLECTION_SECONDS
    previous, previous_limited = _previous_sessions(latest)
    folders = [(latest, 'current'), *((folder, 'previous') for folder in previous[:3])]
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    sources: list[dict[str, Any]] = []
    remaining, lines_seen, limited = MAX_READ_BYTES, 0, bool(previous_limited or len(previous) > 3)
    for folder, scope in folders:
        for rotation in range(3):
            if len(sources) >= MAX_SOURCES or remaining <= 0 or time.monotonic() >= deadline or lines_seen >= MAX_PARSE_LINES:
                limited = True
                break
            tail = _read_tail(folder / ('targets.log' + (f'.{rotation}' if rotation else '')), min(PER_SOURCE_BYTES, remaining))
            data = tail.get('data', b'')
            limited |= tail.get('truncated') is True or tail.get('status') == 'limited'
            remaining -= len(data)
            source: dict[str, Any] = {'scope': scope, 'rotation': rotation,
                'status': tail.get('status', 'unreadable'), 'bytes_available': tail.get('bytes_available', 0),
                'bytes_read': len(data), 'truncated': tail.get('truncated') is True,
                'records_examined': 0, 'invalid_observations': 0}
            for line in _complete_lines(data, tail.get('truncated') is True):
                if lines_seen >= MAX_PARSE_LINES or time.monotonic() >= deadline:
                    limited = True
                    break
                lines_seen += 1
                if len(line) > 32768 or 'external_device_observation' not in line:
                    continue
                try:
                    payload = json.loads(line[line.index('{'):])
                except (ValueError, json.JSONDecodeError, RecursionError):
                    continue
                if not isinstance(payload, dict) or payload.get('event') != 'external_device_observation':
                    continue
                source['records_examined'] += 1
                safe = validate_external_device_observation(payload.get('external_device'))
                if safe is None:
                    source['invalid_observations'] += 1
                    continue
                fingerprint = hashlib.sha256(json.dumps(safe, sort_keys=True).encode()).hexdigest()
                if fingerprint not in seen:
                    seen.add(fingerprint)
                    rows.append(safe)
            sources.append(source)
    rows.sort(key=lambda item: item.get('observed_at', ''))
    limited |= len(rows) > MAX_ROWS
    return validate_external_device_report({'observations': rows[-MAX_ROWS:], 'sources': sources,
        'limited': limited, 'captured_at_epoch': time.time()})


def summary_lines(report: Any) -> str:
    safe = validate_external_device_report(report)
    lines = ['\nExternal-device observations: existing host-side activity only.',
        f'  Retained observations: {safe["observations_retained"]}; opaque devices observed: {safe["devices_observed"]}.',
        '  Diagnostics made no device connections and ran no device commands.']
    if safe['outcomes']:
        lines.append('  Recorded outcomes: ' + ', '.join(f'{key}={value}' for key, value in safe['outcomes'].items()) + '.')
    if not safe['observations_retained']:
        lines.append('  No retained observation does not establish that no external devices were used.')
    lines.append('  Permission decisions remain in PERMISSIONS.json; output, commands, addresses and credentials are omitted.\n')
    return '\n'.join(lines)
