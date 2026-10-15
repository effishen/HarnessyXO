"""Bounded queue admission receipts; never reads a database or user content."""
from __future__ import annotations

from datetime import datetime
import json
import re
from typing import Any
import uuid


QUEUE_EVENTS = frozenset({'run_queue_snapshot', 'run_queue_admission', 'run_queue_holds_retired'})
ROW_LIMIT = 64
COMPLETION_STATES = frozenset({'generating', 'checking', 'continuing', 'running',
                              'unconfirmed', 'interrupted', 'unconfirmed_released'})
BACKEND_STATES = frozenset({'retrying', 'failed', 'cancelled'})
GATE_KINDS = frozenset({'none', 'completion_hold', 'backend_recovery', 'capacity',
                       'related_project', 'history_save', 'unavailable'})
_SOURCES = frozenset({'startup', 'state_change', 'admission', 'diagnostics_download', 'resume'})
_COUNT_KEYS = frozenset({'completion_holds', 'blocking_completion_holds', 'backend_recoveries',
                        'jobs', 'pending_jobs', 'running_jobs'})


def _identity(value: Any, *, run: bool = False) -> str | None:
    if not isinstance(value, str):
        return None
    if run and re.fullmatch(r'queue-[0-9a-f]{32}', value):
        return value
    if len(value) not in {32, 36}:
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    return value if value.lower() in {parsed.hex, str(parsed)} else None


def _number(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 2**31 - 1


def _timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.isoformat(timespec='milliseconds') if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _owner(value: Any, *, backend: bool = False, job: bool = False) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    state_key, choices = ('status', {'pending', 'running'}) if job else (
        'state', BACKEND_STATES if backend else COMPLETION_STATES)
    state = value.get(state_key)
    if not isinstance(state, str) or state not in choices:
        return None
    safe: dict[str, Any] = {state_key: state}
    for key in ('workspace_id', 'chat_id', 'run_id', 'id'):
        if key == 'id' and not job:
            continue
        identifier = _identity(value.get(key), run=key == 'run_id')
        if identifier:
            safe[key] = identifier
    if (job and not all(key in safe for key in ('id', 'workspace_id', 'chat_id'))
            or not job and not backend and not all(key in safe for key in ('workspace_id', 'chat_id'))
            or backend and 'run_id' not in safe):
        return None
    for key in ('updated_at', 'created_at', 'started_at'):
        stamp = _timestamp(value.get(key))
        if stamp:
            safe[key] = stamp
    for key in (('lane', 'preferred_slot') if job else ('attempt',) if backend else ()):
        if _number(value.get(key)):
            safe[key] = value[key]
    for key in ('owner_registered', 'owner_chat_exists'):
        if type(value.get(key)) is bool:
            safe[key] = value[key]
    return safe


def validate_queue_event(event: Any, value: Any) -> dict[str, Any] | None:
    if not isinstance(event, str) or event not in QUEUE_EVENTS or not isinstance(value, dict):
        return None
    safe: dict[str, Any] = {'schema_version': 1, 'event': event}
    if event == 'run_queue_holds_retired':
        if value.get('reason_code') == 'owner_unregistered':
            safe['reason_code'] = 'owner_unregistered'
        if _number(value.get('count')):
            safe['count'] = value['count']
        if isinstance(value.get('cleanup_scope'), str) and value['cleanup_scope'] in {
                'startup', 'after_interrupted_recovery', 'workspace_unregister'}:
            safe['cleanup_scope'] = value['cleanup_scope']
        return safe
    if event == 'run_queue_snapshot':
        if isinstance(value.get('status'), str) and value['status'] in {'observed', 'unavailable'}:
            safe['status'] = value['status']
        if isinstance(value.get('source'), str) and value['source'] in _SOURCES:
            safe['source'] = value['source']
        for key in ('queue_paused', 'resume_allowed'):
            if type(value.get(key)) is bool:
                safe[key] = value[key]
        if isinstance(value.get('counts'), dict):
            safe['counts'] = {key: item for key, item in value['counts'].items()
                              if key in _COUNT_KEYS and _number(item)}
        rejections = value.get('rows_rejected') if isinstance(value.get('rows_rejected'), dict) else {}
        safe['rows_rejected'] = {}
        for key in ('completion_holds', 'backend_recoveries', 'jobs'):
            raw = value.get(key) if isinstance(value.get(key), (list, tuple)) else []
            projected = [_owner(row, backend=key == 'backend_recoveries', job=key == 'jobs')
                         for row in raw[:ROW_LIMIT]]
            safe[key] = [row for row in projected if row is not None]
            rejected = sum(row is None for row in projected)
            safe['rows_rejected'][key] = max(rejected, rejections[key] if _number(rejections.get(key)) else 0)
            safe[key + '_limited'] = len(raw) > ROW_LIMIT or value.get(key + '_limited') is True
        if isinstance(value.get('technical_error'), dict):
            from .technical import validate_technical_evidence
            safe['technical_error'] = validate_technical_evidence(value['technical_error'])
    else:
        for key in ('workspace_id', 'chat_id', 'job_id', 'run_id', 'request_id'):
            identifier = _identity(value.get(key), run=key == 'run_id')
            if identifier:
                safe[key] = identifier
        for key, choices in {'phase': {'waiting', 'admitted', 'cancelled', 'rejected'},
                             'gate_kind': GATE_KINDS}.items():
            if isinstance(value.get(key), str) and value[key] in choices:
                safe[key] = value[key]
        for key in ('include_backend', 'same_owner_exempt', 'resume_allowed'):
            if type(value.get(key)) is bool:
                safe[key] = value[key]
        if isinstance(value.get('gate_kind'), str) and value['gate_kind'] in {'completion_hold', 'backend_recovery'}:
            blocker = _owner(value.get('blocker'), backend=value['gate_kind'] == 'backend_recovery')
            if blocker:
                safe['blocker'] = blocker
    for key in ('slot_limit', 'active_slots', 'pending_slots', 'queue_position'):
        if _number(value.get(key)):
            safe[key] = value[key]
    stamp = _timestamp(value.get('observed_at'))
    if stamp:
        safe['observed_at'] = stamp
    return safe


def build_queue_audit(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """Project existing log receipts only; absence never proves an empty queue."""
    receipts = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        safe = validate_queue_event(row.get('event'), row)
        if safe is None:
            continue
        stamp = row.get('timestamp')
        if isinstance(stamp, str) and len(stamp) == 23:
            try:
                safe['timestamp'] = datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S,%f').strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
            except ValueError:
                pass
        if isinstance(row.get('session_scope'), str) and row['session_scope'] in {'current', 'previous', 'launcher'}:
            safe['session_scope'] = row['session_scope']
        receipts.append(safe)
    snapshots = [row for row in receipts if row['event'] == 'run_queue_snapshot']
    admissions = [row for row in receipts if row['event'] == 'run_queue_admission']
    retired = [row for row in receipts if row['event'] == 'run_queue_holds_retired']
    states: dict[str, dict[str, Any]] = {}
    for row in admissions:
        if row.get('request_id'):
            states[row['request_id']] = row
    latest = snapshots[-1] if snapshots else None
    request_states = sorted(states.values(), key=lambda row: row.get('timestamp', ''))[-16:]
    audit = {'schema_version': 1, 'status': 'observed' if receipts else 'unrecorded',
             'scope': 'bounded_queue_receipts_no_database_collection',
             'limits': {'rows_per_snapshot_kind': ROW_LIMIT, 'snapshots': 20, 'admissions': 120,
                        'retirements': 20, 'latest_request_states': 16},
             'snapshots_available': len(snapshots), 'admissions_available': len(admissions),
             'retirements_available': len(retired), 'counts_are_retained_receipts': True,
             'latest_snapshot': latest, 'recent_snapshots': snapshots[-20:],
             'recent_admissions': admissions[-120:], 'recent_retirements': retired[-20:],
             'latest_request_states': request_states,
             'receipt_limit_reached': len(snapshots) > 20 or len(admissions) > 120 or len(retired) > 20,
             'snapshot_is_not_per_request_admission': True}
    lines = ['Run queue evidence: QUEUE_STATE.json records durable hold snapshots and actual admission transitions without message content.']
    if not receipts:
        lines.extend(['  Queue state/admission was not recorded in the examined logs; the blocker and resume eligibility cannot be reconstructed.', ''])
        return audit, lines
    if latest:
        stamp, scope = latest.get('timestamp', 'unrecorded'), latest.get('session_scope', 'unrecorded')
        lines.append(f'  Latest snapshot {stamp} [{scope}]: {latest.get("status", "unrecorded")}; source {latest.get("source", "unrecorded")}.')
        facts = {key: latest[key] for key in ('queue_paused', 'resume_allowed', 'counts',
                 'slot_limit', 'active_slots', 'pending_slots') if key in latest}
        if facts:
            lines.append('    Recorded queue facts: ' + json.dumps(facts, sort_keys=True) + '.')
        for key in ('completion_holds', 'backend_recoveries', 'jobs'):
            if latest.get(key + '_limited'):
                lines.append(f'    {key}: only the first {ROW_LIMIT} rows are retained; additional owners/jobs may be absent.')
        if any(latest.get('rows_rejected', {}).values()):
            lines.append('    Invalid or unavailable identifiers/states were excluded; rows_rejected records the projection coverage.')
    waiting = [row for row in request_states if row.get('phase') == 'waiting']
    for row in waiting[-4:]:
        owner = {key: row[key] for key in ('workspace_id', 'chat_id', 'job_id', 'request_id') if key in row}
        lines.append(f'  Recorded admission transition {row.get("timestamp", "unrecorded")}: waiting / {row.get("gate_kind", "unrecorded")}; requester ' + json.dumps(owner, sort_keys=True) + '.')
        if row.get('blocker'):
            lines.append('    Recorded blocker: ' + json.dumps(row['blocker'], sort_keys=True) + '.')
        policy = {key: row[key] for key in ('include_backend', 'same_owner_exempt', 'resume_allowed',
                  'slot_limit', 'active_slots', 'queue_position') if key in row}
        if policy:
            lines.append('    Admission facts: ' + json.dumps(policy, sort_keys=True) + '.')
    if admissions and not waiting:
        row = admissions[-1]
        lines.append(f'  Latest admission transition {row.get("timestamp", "unrecorded")}: {row.get("phase", "unrecorded")} / {row.get("gate_kind", "unrecorded")}.')
    for row in retired[-3:]:
        if row.get('reason_code') == 'owner_unregistered' and 'count' in row:
            lines.append(f'  {row.get("timestamp", "unrecorded")}: retired {row["count"]} settled completion hold(s) for unregistered workspace owners; scope {row.get("cleanup_scope", "unrecorded")}.')
    lines.extend(['  Global pause is separate from each chat\'s admission: owner exemptions and backend inclusion are recorded per request. All receipts are timestamped observations, not a live probe.', ''])
    return audit, lines
