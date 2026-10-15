"""Bounded, content-free incident index for a support export.

This reads logs only. It never opens a workspace database or claims that a
nearby operation is a proven lock holder.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
from pathlib import Path
from typing import Any
from .permissions import PERMISSION_EVENTS
from .startup import STARTUP_EVENTS

_CHANNELS = ('harnessy', 'runtime', 'database', 'tools', 'backend', 'targets')
_TAIL_BYTES = 2 * 1024 * 1024
_MAX_ROWS = 20000
_MAX_INCIDENTS = 20
_CONTEXT_SECONDS = 30.0
_TARGET_FOLLOWUP_SECONDS = 300.0
_PERMISSION_RECEIPTS = 120
_ERROR_EVENTS = frozenset({
    'agent_run_error', 'headless_run_error', 'uncaught_exception',
    'sqlite_operation_error', 'tool_execution_error', 'request_error',
    'environment_command_timeout', 'workspace_environment_shutdown_stop_failed',
    'environment_command_spawn_failed', 'vm_failure_evidence_unavailable', 'run_blocked_by_infrastructure',
})


def _bounded_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(rows) <= _MAX_ROWS:
        return rows
    # Reserve sparse target evidence when busy database/model traffic fills the
    # common index. The separate TARGET_TIMELINE retains the same 600-row bound.
    targets = [row for row in rows if str(row.get('event')).startswith('test_target_')][-600:]
    permissions = [row for row in rows if row.get('event') in PERMISSION_EVENTS
                   or (row.get('event') == 'tool_execution_complete'
                       and ('permission_decision' in row or 'target_validation' in row))][-600:]
    startup = [row for row in rows if row.get('event') in STARTUP_EVENTS][-120:]
    from .model_requests import MODEL_EVENTS
    models = [row for row in rows if row.get('event') in MODEL_EVENTS][-600:]
    recent = rows[-(_MAX_ROWS - len(targets) - len(permissions) - len(startup) - len(models)):]
    retained = {id(row): row for row in targets + permissions + startup + models + recent}
    return sorted(retained.values(), key=lambda row: row['timestamp'])


def _vm_failure_classification(row: dict[str, Any]) -> str | None:
    event = row.get('event')
    if event == 'environment_command_spawn_failed':
        return 'vm_controller_spawn_failed'
    if event == 'vm_lifecycle_finished' and row.get('outcome') == 'failed':
        return 'vm_lifecycle_failed'
    if event == 'vm_startup_observation':
        if row.get('outcome') == 'controller_timeout':
            return 'vm_controller_timeout'
        if row.get('outcome') == 'controller_error':
            if row.get('controller_failure_kind') == 'ssh_requirement_wait_failed':
                return 'vm_ssh_requirement_failed'
            code = row.get('controller_returncode')
            return 'vm_controller_interrupted' if type(code) is int and code < 0 else 'vm_startup_failed'
    if event == 'environment_command_timeout':
        return 'vm_controller_timeout'
    action = row.get('controller_action')
    if event == 'environment_command_finished' and isinstance(action, str) and action in {'start', 'stop', 'create', 'delete', 'edit', 'clone', 'snapshot', 'restart', 'factory-reset'}:
        code = row.get('returncode')
        if type(code) is int and code != 0:
            return 'vm_controller_interrupted' if code < 0 else 'vm_controller_failed'
    if event == 'workspace_environment_shutdown_stop_failed':
        return 'vm_shutdown_stop_unverified'
    return None


def _target_failure_classification(row: dict[str, Any]) -> str | None:
    if row.get('event') == 'test_target_view_failed':
        return 'test_target_view_unavailable'
    if row.get('event') == 'test_target_shutdown_failed':
        return 'test_target_shutdown_unverified'
    if row.get('event') != 'test_target_operation_finished':
        return None
    if row.get('target_outcome') not in {'failed', 'timeout'}:
        return None
    code = row.get('target_failure_code')
    if code in {'shell_hostname_unavailable', 'shell_command_missing', 'readiness_probe_failed', 'shell_probe_failed'}:
        return 'test_target_readiness_failed'
    if code in {'boot_timeout', 'shell_probe_timeout', 'controller_timeout'} or row.get('target_outcome') == 'timeout':
        return 'test_target_startup_timeout'
    return 'test_target_operation_failed'


def _target_operation_rows(rows: list[dict[str, Any]], failure: dict[str, Any]) -> list[dict[str, Any]]:
    """Match explicit identities; absent/redacted IDs cannot join operations."""
    identifiers = (failure.get('target_id'), failure.get('operation_id'))
    if not all(isinstance(value, str) and len(value) == 32
               and all(char in '0123456789abcdef' for char in value) for value in identifiers):
        return []
    return [row for row in rows
            if row.get('session_scope') == failure.get('session_scope')
            and row.get('target_id') == failure['target_id']
            and row.get('operation_id') == failure['operation_id']
            and row['timestamp'] <= failure['timestamp']
            and (not failure.get('target_backend')
                 or row.get('target_backend') == failure['target_backend'])
            and (str(row.get('event')).startswith('test_target_operation_')
                 or row.get('event') == 'test_target_radio_result')]


def _target_startup_analysis(rows: list[dict[str, Any]], failure: dict[str, Any],
                             operation: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Explain controlled stage boundaries, keeping later evidence separate.

    A parsed radio probe establishes a successful guest command at its own
    timestamp. It cannot establish guest readiness at the earlier deadline.
    """
    if failure.get('target_action') != 'start' or failure.get('event') != 'test_target_operation_finished':
        return None
    from .permissions import safe_timing

    radio_stages = {'radio_setup', 'bluetooth_packages', 'bluetooth_emulator',
                    'bluetooth_attach', 'bluetooth_verify'}
    stages = {row.get('target_stage') for row in operation}
    start_recorded = any(row.get('event') == 'test_target_operation_started' for row in operation)
    stage = failure.get('target_stage')
    before_radios = {'prerequisites', 'download', 'prepare_disk', 'launch',
                     'launch_reconcile', 'launch_recovered', 'wait_ssh', 'probe_shell'}
    reached = ('reached' if stages & radio_stages else
               'not_reached' if start_recorded and stage in before_radios else 'unrecorded')
    launches = [row for row in operation if row.get('target_stage') in
                {'launch', 'launch_reconcile', 'launch_recovered'}]
    recovered = any(row.get('target_stage') == 'launch_recovered' for row in launches)
    timed_out = (any(row.get('target_stage') == 'launch_reconcile' for row in launches)
                 or (stage in {'launch', 'launch_reconcile'}
                     and failure.get('target_failure_code') == 'controller_timeout'))
    exit_rows = [row for row in launches if type(row.get('returncode')) is int]
    limit = next((safe_timing(row.get('timeout_seconds')) for row in reversed(launches)
                  if safe_timing(row.get('timeout_seconds')) not in (None, 0)), None)
    analysis: dict[str, Any] = {
        'schema_version': 1,
        'launch_wait': 'timeout_recovered' if recovered else 'timeout' if timed_out else
                       'exited' if exit_rows else 'unrecorded',
        'launcher_returncode': exit_rows[-1]['returncode'] if exit_rows else None,
        'launch_timeout_seconds': limit,
        'radio_setup': reached,
        'operation_start_recorded': start_recorded,
        'later_guest_observation': 'unrecorded',
        'later_guest_probe_delay_seconds': None,
        'later_guest_probe_evidence': [],
    }
    if not operation:
        return analysis
    # Do not associate evidence across another start/stop/repair or a session
    # change. The observation may have no operation ID because it is a UI probe.
    later: list[dict[str, Any]] = []
    for row in rows:
        if (row.get('session_scope') != failure.get('session_scope')
                or row.get('target_id') != failure.get('target_id')
                or row.get('target_backend') != failure.get('target_backend')):
            continue
        delay = _seconds(row['timestamp'], failure['timestamp'])
        if not 0 < delay <= _TARGET_FOLLOWUP_SECONDS:
            continue
        later.append(row)
    boundary = min((row['timestamp'] for row in later
                    if row.get('event') == 'test_target_operation_started'), default=None)
    for row in sorted(later, key=lambda item: item['timestamp']):
        if boundary is not None and row['timestamp'] >= boundary:
            break
        if (row.get('event') != 'test_target_radio_result'
                or row.get('target_radio_observation') != 'probe'
                or row.get('target_radio_status') not in {'active', 'unavailable'}):
            continue
        from .test_target_logs import TARGET_ENUMS
        reason = row.get('target_radio_reason')
        if reason not in TARGET_ENUMS['target_radio_reason'] or reason in {
                'probe_failed', 'setup_failed', 'not_requested'}:
            continue
        analysis['later_guest_observation'] = 'live_radio_probe_returned'
        if analysis['later_guest_probe_delay_seconds'] is None:
            analysis['later_guest_probe_delay_seconds'] = round(
                _seconds(row['timestamp'], failure['timestamp']), 3)
        analysis['later_guest_probe_evidence'].append(_evidence(row))
        if len(analysis['later_guest_probe_evidence']) >= 4:
            break
    return analysis


def _permission_failure_classification(row: dict[str, Any]) -> str | None:
    if row.get('event') != 'tool_execution_complete':
        return None
    if row.get('target_validation') in {'missing', 'invalid', 'not_found', 'disabled'}:
        return 'tool_target_validation_failed'
    if row.get('error_code') == 'PERMISSION_POLICY_UNAVAILABLE':
        return 'tool_permission_policy_unavailable'
    return None


def _startup_failure_classification(row: dict[str, Any]) -> str | None:
    if row.get('event') == 'launcher_rea_setup_failed':
        from .startup import validate_storage_issue
        return 'rea_storage_validation_failed' if validate_storage_issue(row.get('storage_issue')) else 'rea_setup_failed'
    return None


def _rows(latest: Path, *, session_scope: str = 'current', tail_bytes: int = _TAIL_BYTES,
          rotations: bool = True) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    # Lazy import avoids a logger/exporter import cycle.
    from .logging import _privacy_safe_value, _read_snapshot_bytes

    rows: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    for channel in _CHANNELS:
        channel_rows: list[dict[str, Any]] = []
        bounded = False
        for suffix in (('.3', '.2', '.1', '') if rotations else ('',)):
            source = latest / f'{channel}.log{suffix}'
            payload = _read_snapshot_bytes(source, tail_bytes=tail_bytes)
            if payload is None:
                continue
            try:
                bounded = bounded or source.stat().st_size > tail_bytes
            except OSError:
                pass
            for line in payload.decode('utf-8', errors='replace').splitlines():
                parts = line.split(' ', 3)
                if len(parts) != 4 or parts[2] not in {'INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL'}:
                    continue
                try:
                    stamp = f'{parts[0]} {parts[1]}'
                    datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S,%f')
                    body = json.loads(parts[3])
                except (ValueError, TypeError, RecursionError):
                    continue
                if not isinstance(body, dict):
                    continue
                try:
                    safe = _privacy_safe_value(body)
                except (ValueError, TypeError, RecursionError):
                    continue
                if not isinstance(safe, dict):
                    continue
                channel_rows.append({
                    **safe, 'timestamp': stamp, 'channel': channel, 'level': parts[2], 'session_scope': session_scope,
                })
        if channel_rows:
            channel_rows.sort(key=lambda row: row['timestamp'])
            coverage.append({
                'channel': channel, 'session_scope': session_scope, 'first_timestamp': channel_rows[0]['timestamp'],
                'last_timestamp': channel_rows[-1]['timestamp'],
                'records_examined': len(channel_rows), 'log_tail_limited': bounded,
            })
        rows.extend(channel_rows)
    rows.sort(key=lambda row: row['timestamp'])
    return _bounded_rows(rows), coverage


def _launcher_startup_rows(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Recover reviewed startup receipts discarded by the launcher's exec."""
    from .logging import _read_snapshot_bytes
    from .startup import validate_startup_event

    limit = 512 * 1024
    payload = _read_snapshot_bytes(path / 'harnessy.log', tail_bytes=limit)
    rows: list[dict[str, Any]] = []
    launcher_handoff = False
    application_started = False
    for line in (payload.decode('utf-8', errors='replace').splitlines() if payload else []):
        parts = line.split(' ', 3)
        if len(parts) != 4 or parts[2] not in {'INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL'}:
            continue
        try:
            stamp = f'{parts[0]} {parts[1]}'
            datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S,%f')
            body = json.loads(parts[3])
            if isinstance(body, dict):
                launcher_handoff = launcher_handoff or body.get('event') == 'launcher_exec_application'
                application_started = application_started or body.get('event') in {
                    'controller_password_login_enabled', 'controller_access_token_enabled',
                }
            safe = validate_startup_event(body.get('event'), body) if isinstance(body, dict) else None
        except (ValueError, TypeError, RecursionError):
            continue
        if safe is not None:
            rows.append({**safe, 'timestamp': stamp, 'channel': 'harnessy',
                         'level': parts[2], 'session_scope': 'launcher'})
    rows = sorted(rows, key=lambda row: row['timestamp'])[-120:]
    if not rows or not launcher_handoff or application_started:
        return [], []
    try:
        limited = (path / 'harnessy.log').stat().st_size > limit
    except OSError:
        limited = True
    return rows, [{'channel': 'harnessy', 'session_scope': 'launcher',
                   'first_timestamp': rows[0]['timestamp'], 'last_timestamp': rows[-1]['timestamp'],
                   'records_examined': len(rows), 'log_tail_limited': limited,
                   'startup_receipts_only': True}]


def _seconds(left: str, right: str) -> float:
    return (datetime.strptime(left, '%Y-%m-%d %H:%M:%S,%f') -
            datetime.strptime(right, '%Y-%m-%d %H:%M:%S,%f')).total_seconds()


def _same_scope(candidate: dict[str, Any], incident: dict[str, Any]) -> bool:
    for key in ('session_scope', 'workspace_id', 'chat_id', 'run_id', 'target_id'):
        if incident.get(key) and candidate.get(key) and incident[key] != candidate[key]:
            return False
    return True


def _is_lock(row: dict[str, Any]) -> bool:
    if type(row.get('sqlite_errorcode')) is int and (row['sqlite_errorcode'] & 255) in {5, 6}:
        return True
    name = row.get('sqlite_errorname')
    if isinstance(name, str) and name.startswith(('SQLITE_BUSY', 'SQLITE_LOCKED')):
        return True
    for key in ('error', 'detail', 'fault', 'exception_evidence'):
        value = row.get(key)
        if isinstance(value, dict):
            if value.get('error_code') == 'sqlite_database_locked':
                return True
            code = value.get('sqlite_errorcode')
            if isinstance(code, int) and (code & 255) in {5, 6}:
                return True
            name = value.get('sqlite_errorname')
            if isinstance(name, str) and name.startswith(('SQLITE_BUSY', 'SQLITE_LOCKED')):
                return True
    return False


def _evidence(row: dict[str, Any]) -> dict[str, Any]:
    # Keep identifiers and reviewed diagnostic structures, never error bodies.
    keys = (
        'timestamp', 'channel', 'event', 'workspace_id', 'chat_id', 'run_id',
        'call_id', 'step', 'tool', 'returncode', 'command_ok', 'drift_seconds',
        'elapsed_ms', 'busy_timeout_ms', 'db_id', 'db_role', 'connection_id',
        'transaction_id', 'transaction_age_ms', 'operation', 'statement_kind',
        'operation_origin', 'sqlite_errorcode', 'sqlite_errorname', 'fault',
        'exception_evidence', 'candidate_holders', 'candidate_holders_truncated',
        'candidate_scope', 'external_holder_unknown', 'journal_mode',
        'pid', 'thread_id', 'task_id', 'monotonic_ns', 'frames',
        'thread_frames', 'sample_age_seconds', 'blocked_seconds',
        'last_stage', 'last_event',
        'session_scope', 'ok', 'execution_status', 'duration_seconds',
        'command_id', 'parent_start_command_id', 'controller_action', 'outcome',
        'controller_returncode', 'controller_signal', 'elapsed_seconds', 'timeout_seconds',
        'app_limit_seconds', 'native_limit_seconds', 'last_boot_milestone', 'controller_failure_kind',
        'controller_status', 'status_probe_error',
        'target_id', 'target_backend', 'target_action', 'target_stage', 'target_outcome',
        'target_failure_code', 'operation_id', 'attempt', 'attempts', 'probe_attempts',
        'target_view_failure_code', 'target_interface',
        'target_radio_kind', 'target_radio_backend', 'target_radio_observation', 'target_radio_status', 'target_radio_reason',
        'target_radio_detail', 'target_radio_requested', 'target_radio_verified',
        'target_radio_count', 'target_radio_interface_count',
        'error_code', 'target_validation', 'permission', 'permission_decision',
        'permission_source', 'permission_reason', 'permission_target_mode',
        'permission_target_state', 'permission_changed', 'permission_states',
        'required_permissions', 'phase', 'approval_required', 'approved',
        'approval_wait_seconds', 'execution_duration_seconds', 'coordination_wait_seconds',
        'state', 'changed', 'archive_check', 'storage_issue', 'version', 'status',
        'exception_class',
        'error_type', 'terminal_stop_reason', 'terminal_reason', 'backend_done_reason',
        'source', 'technical_error', 'controller_evidence', 'requested_vm_config',
        'environment_action', 'lifecycle_action', 'preservation_reason', 'failure_receipt', 'host_resources',
    )
    evidence = {key: row[key] for key in keys if key in row}
    if _is_lock(row):
        evidence['error_code'] = 'sqlite_database_locked'
    return evidence


def _startup_audit(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    from .startup import UPDATE_STATES, UPDATE_SUCCESS_STATES, validate_startup_event

    receipts: list[dict[str, Any]] = []
    for row in rows:
        safe = validate_startup_event(row.get('event'), row)
        if safe is None:
            continue
        for key in ('timestamp', 'channel', 'session_scope'):
            safe[key] = row[key]
        receipts.append(safe)
    checks = [row for row in receipts if row['event'] == 'launcher_source_update']
    failures = [row for row in receipts if row['event'] == 'launcher_rea_setup_failed']
    storage = [row for row in failures if row.get('storage_issue')]
    outcomes = Counter(row['state'] for row in checks if row.get('state') in UPDATE_STATES)
    audit = {
        'schema_version': 1, 'status': 'observed' if receipts else 'unrecorded',
        'scope': 'bounded_current_previous_and_recent_launcher_log_tails',
        'source_checks_recorded': len(checks), 'source_outcome_counts': dict(outcomes),
        'source_update_skip_records': sum(count for state, count in outcomes.items()
                                           if state not in UPDATE_SUCCESS_STATES),
        'rea_setup_failure_records': len(failures),
        'rea_storage_failure_records': len(storage),
        'recent_receipts': receipts[-120:],
        'counts_are_retained_records': True,
    }
    lines = ['Startup evidence: STARTUP.json retains launcher update receipts and historical host REA setup receipts. REA now runs as a workspace VM tool.']
    if not receipts:
        lines.append('  No startup receipts were recorded in the examined logs; updater decisions and REA setup checks cannot be reconstructed.')
    else:
        lines.append(f'  Source checks recorded: {len(checks)}; skipped/uncompleted update outcome records: {audit["source_update_skip_records"]}.')
        if outcomes:
            lines.append('  Update outcomes: ' + '; '.join(f'{key} {count}' for key, count in sorted(outcomes.items())) + '.')
        for row in checks[-3:]:
            lines.append(f'  {row["timestamp"]} [{row["session_scope"]}] source update: {row.get("state", "unrecorded")}.')
            check = row.get('archive_check', {})
            if check:
                lines.append(f'    Archive expected version: {check.get("expected_version", "unrecorded")}; installed version: {check.get("installed_version", "unrecorded")}; comparison: {check.get("comparison", "unrecorded")}.')
                if 'verified_commit' in check:
                    lines.append(f'    Verified baseline commit: {check["verified_commit"]}.')
                lines.append(f'    Initial archive mismatches: {check.get("mismatch_count", "unrecorded")}; executable metadata repairs: {check.get("executable_repairs", "unrecorded")}; only executable metadata differed: {check.get("only_executable_metadata", "unrecorded")}.')
                for item in check.get('mismatches', []):
                    lines.append(f'      {item["path"]}: {item["reason"]}.')
        lines.append(f'  Historical host REA setup failures recorded: {len(failures)}; with storage component facts: {len(storage)}.')
        for row in failures[-3:]:
            if not row.get('storage_issue'):
                lines.append(f'  {row["timestamp"]} [{row["session_scope"]}] REA setup failed: code {row.get("error_code", "unrecorded")}; status {row.get("status", "unrecorded")}; exception class {row.get("exception_class", "unrecorded")}.')
        for row in storage[-3:]:
            issue = row['storage_issue']
            owner = 'yes' if issue.get('owned_by_current_user') is True else 'no' if issue.get('owned_by_current_user') is False else 'unrecorded'
            lines.append(f'  {row["timestamp"]} [{row["session_scope"]}] REA storage component {issue["component"]}: {issue["reason"]}; mode {issue.get("mode", "unrecorded")}; owned by current user: {owner}.')
        if failures:
            lines.append('  These are recorded setup checks; they do not establish what created the storage state or why an earlier install failed.')
    lines.append('')
    return audit, lines


def _permission_audit(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """Summarize recorded boundaries; absence never establishes zero prompting."""
    from .permissions import safe_timing, validate_permission_event

    decisions = [row for row in rows if row.get('event') == 'tool_permission_decision']
    resolutions = [row for row in rows if row.get('event') == 'tool_approval_policy_resolved']
    completions = [row for row in rows if row.get('event') == 'tool_execution_complete']
    request_ids: set[tuple[Any, ...]] = set()
    approved_ids: set[tuple[Any, ...]] = set()
    denied_ids: set[tuple[Any, ...]] = set()
    validation_ids: set[tuple[Any, ...]] = set()
    changed_ids: set[tuple[Any, ...]] = set()
    sources: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    receipts: list[dict[str, Any]] = []

    def identity(row: dict[str, Any]) -> tuple[Any, ...]:
        safe = validate_permission_event('tool_permission_decision', row) or {}
        return (row.get('session_scope'),) + tuple(safe.get(key) for key in ('workspace_id', 'chat_id', 'run_id')) + (
            safe.get('call_id') or row['timestamp'],)

    for row in decisions:
        key = identity(row)
        reason = row.get('permission_reason')
        if isinstance(reason, str):
            reasons[reason] += 1
        source = row.get('permission_source')
        if isinstance(source, str):
            sources[source] += 1
        if reason == 'ask':
            request_ids.add(key)
        if reason == 'approved_once' or row.get('approved') is True:
            approved_ids.add(key)
        if row.get('execution_status') == 'denied' or row.get('approved') is False:
            denied_ids.add(key)
        if row.get('permission_changed') is True:
            changed_ids.add(key)
        if row.get('permission_target_state') in {'missing', 'invalid', 'not_found', 'disabled'}:
            validation_ids.add(key)

    timed = []
    for row in completions:
        if row.get('target_validation') in {'missing', 'invalid', 'not_found', 'disabled'}:
            validation_ids.add(identity(row))
        if row.get('execution_status') == 'denied':
            denied_ids.add(identity(row))
        if any(safe_timing(row.get(key)) is not None for key in (
            'approval_wait_seconds', 'execution_duration_seconds', 'coordination_wait_seconds',
        )):
            timed.append(row)

    evidence_rows = [row for row in rows if row.get('event') in PERMISSION_EVENTS
                     or (row.get('event') == 'tool_execution_complete'
                         and ('permission_decision' in row or 'target_validation' in row
                              or 'approval_wait_seconds' in row))]
    for row in evidence_rows[-_PERMISSION_RECEIPTS:]:
        # Reuse the reviewed permission projection, including its fixed tool
        # names and identity validation. Completion bodies never enter this file.
        safe = validate_permission_event(row['event'] if row['event'] in PERMISSION_EVENTS else 'tool_permission_decision', row) or {}
        safe['event'] = row['event']
        for key in ('timestamp', 'session_scope', 'channel'):
            safe[key] = row[key]
        if row.get('error_code') in {'TARGET_POLICY', 'PERMISSION_POLICY_UNAVAILABLE'}:
            safe['error_code'] = row['error_code']
        receipts.append(safe)
    waits = [safe_timing(row.get('approval_wait_seconds')) for row in timed]
    waits = [value for value in waits if value is not None]
    executions = [safe_timing(row.get('execution_duration_seconds')) for row in timed]
    executions = [value for value in executions if value is not None]
    coordination = [safe_timing(row.get('coordination_wait_seconds')) for row in timed]
    coordination = [value for value in coordination if value is not None]
    unlabelled_policy = sum(row.get('error_code') == 'TARGET_POLICY'
                           and row.get('target_validation') not in {'missing', 'invalid', 'not_found', 'disabled'}
                           for row in completions)
    audit: dict[str, Any] = {
        'schema_version': 1, 'status': 'recorded' if decisions or resolutions or timed or validation_ids else 'unrecorded',
        'scope': 'bounded_current_and_previous_session_log_tails',
        'approval_count_unit': 'unique_tool_calls',
        'decision_records': len(decisions), 'tool_calls_requiring_approval': len(request_ids) if decisions else None,
        'approvals_granted': len(approved_ids) if decisions else None,
        'approvals_denied': len(denied_ids) if decisions else None,
        'permission_changes_observed': len(changed_ids) if decisions else None,
        'target_validation_failures': len(validation_ids) if decisions or validation_ids else None,
        'target_policy_failures_without_validation_label': unlabelled_policy,
        'timed_tool_completions': len(timed), 'approval_wait_records': len(waits),
        'approval_wait_seconds': round(sum(waits), 6) if waits else None,
        'maximum_approval_wait_seconds': max(waits, default=None),
        'execution_duration_seconds': round(sum(executions), 6) if executions else None,
        'coordination_wait_seconds': round(sum(coordination), 6) if coordination else None,
        'decision_source_record_counts': dict(sources), 'decision_reason_record_counts': dict(reasons),
        'automatic_policy_resolution_records': len(resolutions) if decisions or resolutions else None,
        'automatic_policy_resolution_reasons': dict(Counter(row.get('reason') for row in resolutions if isinstance(row.get('reason'), str))),
        'receipts_available': len(evidence_rows), 'receipts_retained': len(receipts),
        'recent_receipts': receipts,
    }
    lines = ['Tool permissions: PERMISSIONS.json contains reviewed decision receipts and separate timing boundaries.']
    if not decisions:
        lines.append('  No permission decision receipts were recorded; effective settings and the reason for a dialog cannot be reconstructed.')
    else:
        lines.append(f'  Tool calls requiring approval: {len(request_ids)}; granted: {len(approved_ids)}; denied: {len(denied_ids)}; '
                     f'permission changes observed: {len(changed_ids)}.')
        lines.append('  Decision source records: ' + '; '.join(f'{key} {value}' for key, value in sorted(sources.items())) + '.')
    if resolutions:
        lines.append(f'  Pending approval resolutions by current policy: {len(resolutions)}; reason records: '
                     + '; '.join(f'{key} {value}' for key, value in sorted(audit['automatic_policy_resolution_reasons'].items())) + '.')
    if waits:
        execution_label = f'{sum(executions):.3f}s' if executions else 'unrecorded'
        coordination_label = f'{sum(coordination):.3f}s' if coordination else 'unrecorded'
        lines.append(f'  Recorded approval wait: {sum(waits):.3f}s across {len(waits)} completed tool records; '
                     f'guest/tool execution: {execution_label}; coordination wait: {coordination_label}.')
    else:
        lines.append('  Approval wait timing was not recorded; total tool duration does not establish time spent waiting for permission.')
    if validation_ids:
        lines.append(f'  Target argument validation failures observed: {len(validation_ids)}; fixed labels distinguish missing/invalid/not-found/disabled targets without target names.')
    if unlabelled_policy:
        lines.append(f'  Target policy failures without a recorded validation label: {unlabelled_policy}; their cause and any approval wait remain unverified.')
    lines.extend(['  Approval counts are unique tool calls, not the number of displayed dialogs; an unavailable approval handler may prevent a dialog from opening.',
                  '  Counts describe retained receipts; pending or older approvals may be absent. No saved settings, commands or target names are collected.', ''])
    return audit, lines


def _has_frames(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get('frames')) or any(_has_frames(child) for child in value.values())
    if isinstance(value, list):
        return any(_has_frames(child) for child in value)
    return False


def _vm_log_coverage(report: dict[str, Any] | None) -> tuple[dict[str, Any] | None, list[str]]:
    if report is None:
        return None, ['VM boot logs were not collected by this standalone summary. A diagnostics export includes VM_LOGS.json when collection runs.', '']
    try:
        from .vm_logs import validate_vm_report
        safe = validate_vm_report(report)
        if not isinstance(safe, dict):
            raise ValueError('Invalid VM coverage')
    except Exception:
        safe = {'schema_version': 1, 'status': 'unavailable', 'reason': 'collector_failed', 'workspaces': []}
    lines = ['VM boot evidence: VM_LOGS.json lists source coverage; retained logs are under vm-logs/.']
    if safe.get('status') == 'unavailable':
        lines.extend(['  VM log collection was unavailable; other diagnostics remain included.', ''])
        return safe, lines
    workspaces = safe.get('workspaces', [])
    if not workspaces:
        lines.append('  No workspace runtime was discovered from the bounded registry/app logs. This does not establish that no VM exists.')
    counts = Counter(source.get('status') for workspace in workspaces for source in workspace.get('sources', []))
    lines.append('  Sources: ' + '; '.join(f'{label} {counts[label]}' for label in ('included', 'missing', 'unsafe', 'unreadable', 'limited')) + '.')
    bounded = sum(bool(source.get('truncated') or source.get('signals_limited'))
                  for workspace in workspaces for source in workspace.get('sources', []))
    lines.append(f'  Sources with bounded/truncated evidence: {bounded}. Counts are retained tails, not complete boot histories.')
    receipts = [receipt for workspace in workspaces for receipt in workspace.get('failure_receipts', [])]
    lines.append(f'  Saved pre-retry/reset/failure receipts: {len(receipts)}. These preserve earlier boot evidence separately from current runtime logs.')
    for receipt in receipts[-3:]:
        lines.append(f'  Saved VM receipt {receipt.get("captured_at", "unrecorded")}: '
                     f'{receipt.get("reason", "unrecorded")} / {receipt.get("operation", "unrecorded")}.')
        for source in receipt.get('sources', []):
            evidence = source.get('evidence') or {}
            text = evidence.get('diagnostic_text') if isinstance(evidence, dict) else None
            if isinstance(text, str) and text:
                lines.append('    Sanitized ' + source.get('name', 'controller') + ': ' + text[-2000:].replace('\n', '\n    '))
    discovery = safe.get('discovery', {})
    if discovery.get('workspaces_limited') or discovery.get('discovery_limited'):
        lines.append('  Workspace discovery reached a configured bound; additional workspace/log sources may be absent.')
    if discovery.get('unsafe_app_sources'):
        lines.append(f'  Unsafe app-log discovery sources excluded: {discovery["unsafe_app_sources"]}.')
    for workspace in workspaces:
        codes = workspace.get('evidence_codes', [])
        if codes:
            lines.append(f'  VM {workspace.get("workspace_id", "unknown")[:12]} / recognized log signals: ' + ', '.join(codes) + '.')
        for source in workspace.get('sources', []):
            if source.get('status') in {'missing', 'unsafe', 'unreadable', 'limited'} or source.get('truncated') or source.get('signals_limited'):
                lines.append(f'  VM {workspace.get("workspace_id", "unknown")[:12]} / {source.get("filename", "unknown")}: '
                             f'{source.get("status", "unavailable")}' + ('; bounded tail' if source.get('truncated') or source.get('signals_limited') else '') + '.')
    lines.extend(['  VM log signals are observations from retained tails, not proof of the cause of a particular controller failure.',
                  '  VM log tails may include earlier boots; match timestamps and command identities before attributing a cause.', ''])
    return safe, lines


def build_support_summary(latest: Path, *, vm_report: dict[str, Any] | None = None,
                          target_report: dict[str, Any] | None = None) -> tuple[dict[str, Any], str]:
    rows, coverage = _rows(Path(latest))
    # After a restart, the previous process may contain the failure the user
    # wants to report. Examine only the same bounded previous tail the ZIP keeps.
    from .logging import _session_is_launcher_only, _read_snapshot_bytes
    current_name = (_read_snapshot_bytes(Path(latest) / 'CURRENT_SESSION.txt') or b'').decode('utf-8', errors='ignore').strip()
    sessions = Path(latest).parent / 'sessions'
    candidates: list[Path] = []
    try:
        candidates = sorted((path for path in sessions.iterdir()
                             if path.is_dir() and not path.is_symlink() and path.name != current_name),
                            key=lambda path: path.stat().st_mtime, reverse=True)
        previous = next((path for path in candidates if not _session_is_launcher_only(path)), None)
    except OSError:
        previous = None
    if previous is not None:
        older_rows, older_coverage = _rows(previous, session_scope='previous', tail_bytes=512 * 1024, rotations=False)
        rows = _bounded_rows(sorted(rows + older_rows, key=lambda row: row['timestamp']))
        coverage.extend(older_coverage)
    launcher_sources = 0
    for launcher in candidates[:4]:
        if launcher == previous:
            continue
        launcher_rows, launcher_coverage = _launcher_startup_rows(launcher)
        rows.extend(launcher_rows)
        coverage.extend(launcher_coverage)
        launcher_sources += bool(launcher_rows)
        if launcher_sources >= 2:
            break
    rows = _bounded_rows(sorted(rows, key=lambda row: row['timestamp']))
    observation_keys = {(row.get('session_scope'), row.get('command_id')) for row in rows
                        if row.get('event') == 'vm_startup_observation' and isinstance(row.get('command_id'), str)
                        and _vm_failure_classification(row)}
    failures = [row for row in rows if (row.get('event') in _ERROR_EVENTS or _vm_failure_classification(row)
                                       or _target_failure_classification(row) or _permission_failure_classification(row)
                                       or _startup_failure_classification(row) or _is_lock(row))
                and not (row.get('event') in {'environment_command_finished', 'environment_command_timeout'}
                         and isinstance(row.get('command_id'), str)
                         and (row.get('session_scope'), row.get('command_id')) in observation_keys)]
    incidents: list[dict[str, Any]] = []
    for failure in failures[-_MAX_INCIDENTS:]:
        before = [row for row in rows if row['session_scope'] == failure['session_scope']
                  and 0 <= _seconds(failure['timestamp'], row['timestamp']) <= _CONTEXT_SECONDS]
        related = [row for row in before if _same_scope(row, failure)]
        lock = _is_lock(failure)
        vm_classification = _vm_failure_classification(failure)
        target_classification = _target_failure_classification(failure)
        permission_classification = _permission_failure_classification(failure)
        startup_classification = _startup_failure_classification(failure)
        target_operation = _target_operation_rows(rows, failure) if target_classification else []
        target_analysis = _target_startup_analysis(rows, failure, target_operation) if target_classification else None
        if vm_classification == 'vm_controller_interrupted' and not isinstance(failure.get('controller_signal'), str):
            code = failure.get('controller_returncode', failure.get('returncode'))
            failure = {**failure, 'controller_signal': {-2: 'SIGINT', -9: 'SIGKILL', -15: 'SIGTERM'}.get(code, 'other')}
        controller_id = failure.get('command_id')
        controller_id = controller_id if isinstance(controller_id, str) else None
        controller_evidence = [_evidence(row) for row in rows if controller_id and
                               row['session_scope'] == failure['session_scope'] and
                               (row.get('command_id') == controller_id or row.get('parent_start_command_id') == controller_id)
                               and row.get('event') in {'environment_command_started', 'environment_command_finished',
                                                       'environment_command_timeout', 'vm_startup_observation',
                                                       'vm_startup_post_failure_state'}]
        # A database event immediately before the run error is a correlation,
        # unless both events carry the same connection/transaction identity.
        database_errors = [row for row in related if row.get('event') == 'sqlite_operation_error'
                           and _seconds(failure['timestamp'], row['timestamp']) <= 2.0]
        starts = [row for row in related if row.get('event') == 'tool_execution_start'
                  and row.get('workspace_id') == failure.get('workspace_id')
                  and row.get('chat_id') == failure.get('chat_id')]
        last_start = starts[-1] if starts else None
        successful_tool = None
        if last_start:
            completions = [row for row in before
                           if row.get('call_id') == last_start.get('call_id')
                           and row.get('event') in {'vm_tool_exec_complete', 'tool_execution_complete', 'tool_execution_result_ready'}
                           and (row.get('command_ok') is True or row.get('returncode') == 0 or row.get('ok') is True)]
            if completions:
                successful_tool = _evidence(completions[-1])
        stalls = [row for row in before if row.get('event') in {'event_loop_stall', 'event_loop_stall_sample'}]
        transcript_deferrals = [row for row in related if row.get('event') == 'transcript_refresh_deferred']
        missing: list[str] = []
        if not vm_classification and not target_classification and not permission_classification and not startup_classification and not _has_frames(failure) and not any(_has_frames(row) for row in database_errors):
            missing.append('exception_traceback_unavailable')
        if vm_classification and not any(
                isinstance(row.get('controller_evidence'), dict) and any(
                    isinstance(value, dict) and value.get('diagnostic_text') for value in row['controller_evidence'].values())
                for row in controller_evidence):
            missing.append('controller_diagnostic_text_not_recorded')
        if target_analysis and target_analysis['launch_wait'] == 'timeout':
            if target_analysis['launcher_returncode'] is None:
                missing.append('target_launcher_exit_status_not_recorded')
            if failure.get('target_stage') == 'launch':
                missing.append('target_launch_reconciliation_not_recorded')
        if lock and not database_errors:
            missing.append('database_operation_not_recorded')
        if lock:
            missing.append('lock_holder_not_identified')
        identity = json.dumps(_evidence(failure), sort_keys=True)
        incidents.append({
            'incident_id': hashlib.sha256(identity.encode()).hexdigest()[:24],
            'classification': 'sqlite_lock_contention' if lock else startup_classification or permission_classification or target_classification or vm_classification or 'operation_error',
            'failure': _evidence(failure),
            'nearby_database_errors': [_evidence(row) for row in database_errors[-3:]],
            'last_successful_tool': successful_tool,
            'nearby_stalls': [_evidence(row) for row in stalls[-4:]],
            'transcript_refresh_deferred_count': len(transcript_deferrals),
            'missing_evidence': missing,
            'correlation_is_not_proof_of_lock_ownership': True,
            'controller_evidence': controller_evidence[-8:],
            'target_operation_evidence': [_evidence(row) for row in target_operation][-16:],
            'target_startup_analysis': target_analysis,
        })
    counts = Counter(str(row.get('event', '')) for row in rows)
    durations = [row['drift_seconds'] for row in rows
                 if row.get('event') == 'event_loop_stall' and isinstance(row.get('drift_seconds'), (int, float))]
    index: dict[str, Any] = {
        'schema_version': 1, 'scope': 'bounded_current_previous_and_recent_launcher_log_tails',
        'records_examined': len(rows), 'coverage': coverage,
        'incidents_available': len(failures), 'incidents_retained': len(incidents),
        'event_loop_stalls': counts['event_loop_stall'],
        'event_loop_stall_samples': counts['event_loop_stall_sample'],
        'maximum_recorded_stall_seconds': max(durations, default=0),
        'transcript_refresh_deferrals': counts['transcript_refresh_deferred'],
        'database_errors': sum(row.get('event') == 'sqlite_operation_error' or _is_lock(row) for row in rows),
        'database_operation_errors': counts['sqlite_operation_error'], 'incidents': incidents,
    }
    permission_audit, permission_lines = _permission_audit(rows)
    index['permission_audit'] = permission_audit
    startup_audit, startup_lines = _startup_audit(rows)
    index['startup_audit'] = startup_audit
    safe_vm_report, vm_lines = _vm_log_coverage(vm_report)
    if safe_vm_report is not None:
        index['vm_log_evidence'] = safe_vm_report
    target_rows = [row for row in rows if str(row.get('event')).startswith('test_target_')]
    target_lines = ['Test-target evidence: TARGET_LOGS.json lists managed target runtime source coverage; TARGET_TIMELINE.json retains target lifecycle receipts separately.']
    if target_report is not None:
        from .test_target_logs import validate_test_target_report
        safe_target_report = validate_test_target_report(target_report)
        index['test_target_log_evidence'] = safe_target_report
        target_lines.append('  Source counts: ' + '; '.join(f'{key} {safe_target_report["summary"][key]}'
                            for key in ('included', 'missing', 'unsafe', 'unreadable', 'limited')) + '.')
        if safe_target_report['status'] == 'unavailable':
            target_lines.append('  Target boot-log collector unavailable; other diagnostics remain included.')
        if safe_target_report['discovery'].get('discovery_limited') or safe_target_report['discovery'].get('targets_limited'):
            target_lines.append('  Target discovery reached a bound; earlier targets or boot observations may be absent.')
    if not target_rows:
        target_lines.append('  No test-target lifecycle observations in examined logs. Target creation/startup timing and failures cannot be reconstructed from their absence.')
    else:
        target_lines.append(f'  Test-target lifecycle records examined: {len(target_rows)}; failure observations: {sum(bool(_target_failure_classification(row)) for row in target_rows)}.')
    recoveries = [row for row in target_rows if row.get('event') == 'test_target_operation_stage'
                  and row.get('target_action') == 'start' and row.get('target_stage') == 'launch_recovered']
    index['test_target_launch_recoveries'] = [_evidence(row) for row in recoveries[-8:]]
    for row in recoveries[-3:]:
        target_lines.append(f'  {row["timestamp"]} launcher wait timed out; identity-checked QMP confirmed the target was running, so startup continued to SSH readiness checks.')
    for row in [item for item in target_rows if item.get('event') == 'test_target_radio_result'][-4:]:
        target_lines.append(f'  {row["timestamp"]} radio {row.get("target_radio_kind", "unrecorded")}: '
                            f'{row.get("target_radio_status", "unrecorded")} / {row.get("target_radio_reason", "unrecorded")}; '
                            f'detail {row.get("target_radio_detail", "unrecorded")}; '
                            f'verified virtual radios {row.get("target_radio_count", "unrecorded")}; '
                            f'interfaces {row.get("target_radio_interface_count", "unrecorded")}.')
    target_lines.extend(['  A running VM monitor does not establish that its guest shell or web service is ready.', ''])
    from .logging import _export_metadata
    metadata = _export_metadata(Path(latest))
    session = metadata.get('session', {})
    version = session.get('app_version', 'unrecorded')
    index['session_app_version'] = version
    from .model_requests import build_model_audit
    model_audit, model_lines = build_model_audit(rows, coverage, Path(latest), metadata.get('captured_at'))
    index['model_request_audit'] = model_audit
    control_rows = [row for row in rows if row.get('level') in {'WARNING', 'ERROR', 'CRITICAL'}
                    or str(row.get('event')).startswith(('vm_', 'environment_', 'workspace_mapping_', 'test_target_'))
                    or row.get('event') in {'headless_run_error', 'agent_run_error', 'run_blocked_by_infrastructure'}]
    index['control_plane_timeline'] = control_rows[-1200:]
    index['control_plane_coverage'] = {'rows_available': len(control_rows), 'rows_retained': min(len(control_rows), 1200),
        'row_limit': 1200, 'row_limit_reached': len(control_rows) > 1200, 'source_coverage': coverage}
    lines = [
        'HarnessyXO support summary', '==========================', '',
        'Start here; machine-readable evidence is in INCIDENTS.json.',
        f'Session application version: {version}; capture time: {metadata.get("captured_at", "unrecorded")}.',
        'This summary examines bounded current/previous-session log tails and startup receipts from up to two recent launcher sessions. Counts are not whole-session totals.',
        'Nearby events and tracked transactions are evidence for investigation, not proven lock ownership.', '',
        *model_lines,
        f'Recorded failures in examined logs: {len(failures)} (latest {len(incidents)} shown)',
        f'Event-loop stalls: {counts["event_loop_stall"]}; maximum recorded delay: {max(durations, default=0):.3f}s',
        f'During-stall stack samples: {counts["event_loop_stall_sample"]}',
        f'Transcript refresh deferrals: {counts["transcript_refresh_deferred"]}', '',
        f'Database failure observations: {index["database_errors"]}; instrumented SQLite operation errors: {counts["sqlite_operation_error"]}.',
        'Zero instrumented SQLite operation errors does not exclude lock errors recorded by other application operations.', '',
        *vm_lines,
        *target_lines,
        *permission_lines,
        *startup_lines,
    ]
    if not incidents:
        lines.append('No recorded failure event was found in the examined logs; this does not establish that no failure occurred.')
    for incident in reversed(incidents):
        failure = incident['failure']
        lines.append(f'{failure["timestamp"]}  {failure.get("event", "operation_error")}  [{incident["classification"]}; {failure["session_scope"]} session]')
        for key in ('run_id', 'call_id', 'workspace_id', 'chat_id'):
            if failure.get(key):
                lines.append(f'  {key}: {failure[key]}')
        classification = incident['classification']
        if classification == 'tool_target_validation_failed':
            lines.append(f'  Target argument validation: {failure.get("target_validation", "unrecorded")}; no target name or command is included.')
        if classification == 'tool_permission_policy_unavailable':
            lines.append('  The saved permission policy was unavailable; execution was blocked rather than using a stale policy.')
        if classification == 'rea_storage_validation_failed':
            issue = failure['storage_issue']
            lines.append(f'  REA rejected settings-relative component {issue["component"]}: {issue["reason"]}.')
            lines.append('  The recorded component check does not identify what created its current permissions or ownership.')
        elif classification == 'rea_setup_failed':
            lines.append(f'  REA setup did not complete; recorded code: {failure.get("error_code", "unrecorded")}.')
        if classification.startswith('test_target_'):
            for key in ('target_id', 'target_backend', 'target_action', 'target_stage', 'target_failure_code',
                        'target_interface', 'target_view_failure_code', 'elapsed_seconds', 'attempt', 'timeout_seconds'):
                if key in failure:
                    lines.append(f'  {key}: {failure[key]}')
            if classification == 'test_target_view_unavailable':
                lines.append('  The browser display transport failed or rejected a bounded request/response. Check the fixed failure code and target boot evidence; VM running state alone does not establish display readiness.')
            else:
                analysis = incident['target_startup_analysis']
                if analysis and analysis['launch_wait'] in {'timeout', 'timeout_recovered'}:
                    limit = analysis['launch_timeout_seconds']
                    duration = f' after {limit:g}s' if limit is not None else ''
                    lines.append(f'  The host launcher wait reached its deadline{duration}; this is separate from the guest SSH readiness deadline.')
                    if analysis['launch_wait'] == 'timeout_recovered':
                        lines.append('  Identity-checked QMP confirmed a running target after that deadline; startup continued to the recorded later failure stage.')
                    elif failure.get('target_stage') == 'launch_reconcile':
                        lines.append('  Launch reconciliation did not verify a running target. Guest boot failure is not established by this timeout alone.')
                if analysis and analysis['radio_setup'] == 'not_reached':
                    lines.append('  This start ended before optional radio setup; the radio installer was not reached in this operation.')
                if analysis and analysis['later_guest_observation'] == 'live_radio_probe_returned':
                    delay = analysis['later_guest_probe_delay_seconds']
                    lines.append(f'  A later live radio probe returned guest data {delay:g}s after the failure; SSH was reachable then. This does not establish when SSH first became ready.')
                    if analysis['radio_setup'] == 'not_reached':
                        lines.append('  Its missing-radio results describe guest capabilities after the interrupted start; they are not radio installation failures.')
                lines.append('  Inspect target_operation_evidence, target_startup_analysis and TARGET_LOGS.json; a shell probe failure does not establish that the VM failed to boot.')
        if classification.startswith('vm_'):
            if classification == 'vm_controller_timeout':
                lines.append('  HarnessyXO reached its controller wait deadline; this does not by itself establish an SSH failure.')
            elif classification == 'vm_ssh_requirement_failed':
                lines.append('  Lima explicitly reported failure to satisfy its SSH boot requirement. The underlying guest cause is not established.')
                lines.append('  A longer controller watch does not by itself repair a guest SSH requirement failure.')
            elif classification == 'vm_controller_interrupted':
                lines.append('  The controller exited after a termination signal. The sender and resulting VM state are not established by this return code.')
            elif classification == 'vm_shutdown_stop_unverified':
                lines.append('  Application shutdown did not record a successful VM stop; inspect the controller receipts and retained VM logs.')
            else:
                lines.append('  The VM controller reported failure; the underlying cause is not established by its exit code or duration.')
            for key, label in (('controller_action', 'Controller action'), ('controller_returncode', 'Observed controller return code'),
                               ('returncode', 'Return code'), ('controller_signal', 'Observed termination signal'),
                               ('elapsed_seconds', 'Elapsed seconds'), ('app_limit_seconds', 'App deadline seconds'),
                               ('native_limit_seconds', 'Lima watch limit seconds'), ('last_boot_milestone', 'Last observed boot milestone')):
                value = failure.get(key)
                if value is not None and not isinstance(value, (dict, list)):
                    lines.append(f'  {label}: {value}')
            states = [row for row in incident['controller_evidence'] if row.get('event') == 'vm_startup_post_failure_state']
            if states:
                value = states[-1].get('controller_status')
                if isinstance(value, str):
                    lines.append(f'  Bounded controller status after failure: {value}; this is not proof of guest SSH readiness.')
            for receipt in reversed(incident['controller_evidence']):
                evidence = receipt.get('controller_evidence') or {}
                stderr = evidence.get('stderr') if isinstance(evidence, dict) else None
                if isinstance(stderr, dict) and stderr.get('diagnostic_text'):
                    lines.append('  Sanitized controller stderr: ' + stderr['diagnostic_text'][-3000:].replace('\n', '\n    '))
                    break
        if failure.get('terminal_stop_reason'):
            lines.append(f'  Terminal stop reason: {failure["terminal_stop_reason"]}.')
        if failure.get('requested_vm_config'):
            lines.append('  Requested VM configuration: ' + json.dumps(failure['requested_vm_config'], sort_keys=True) + '.')
        fault = failure.get('fault') or failure.get('exception_evidence') or {}
        if isinstance(fault, dict):
            if fault.get('exception_type') or fault.get('exception_class'):
                lines.append(f'  Exception: {fault.get("exception_type") or fault.get("exception_class")}')
            for frame in fault.get('frames', [])[-6:]:
                if isinstance(frame, dict):
                    lines.append(f'  Frame: {frame.get("module", "external")}:{frame.get("line", "?")} {frame.get("function", "unknown")}')
            for part in [fault] + (fault.get('chain') if isinstance(fault.get('chain'), list) else []):
                if not isinstance(part, dict):
                    continue
                facts = {key: part[key] for key in ('errno', 'errno_name', 'errno_namespace', 'returncode',
                    'termination_signal', 'timeout_seconds', 'json_error', 'http_status_code',
                    'tls_verify_code', 'ssl_error_code', 'ssl_error_name') if key in part}
                if facts:
                    lines.append('  Exception technical facts: ' + json.dumps(facts, sort_keys=True) + '.')
        for db in incident['nearby_database_errors']:
            lines.append(f'  Database: {db.get("db_role", "unknown")} (identity {db.get("db_id", "unrecorded")})')
            lines.append(f'  Operation: {db.get("operation", "unknown")} / {db.get("statement_kind", "unknown")}; '
                         f'elapsed {db.get("elapsed_ms", "unknown")}ms; configured busy timeout {db.get("busy_timeout_ms", "unknown")}ms')
            origin = db.get('operation_origin')
            if isinstance(origin, dict):
                lines.append(f'  Called from: {origin.get("module", "external")}:{origin.get("line", "?")} {origin.get("function", "unknown")}')
            candidates = db.get('candidate_holders', [])
            lines.append(f'  Tracked transaction/cursor/operation candidates: {len(candidates)}; external lock holder is not identified by this registry.')
            for candidate in candidates[:4]:
                kind = candidate.get('candidate_kind', 'transaction')
                if kind == 'open_result_cursor':
                    origin = candidate.get('oldest_result_cursor_origin') or {}
                    age = candidate.get('oldest_result_cursor_age_ms', 'unknown')
                elif kind == 'active_operation':
                    origin = candidate.get('last_operation_origin') or {}
                    age = candidate.get('current_operation_elapsed_ms', 'unknown')
                else:
                    origin = candidate.get('transaction_origin') or {}
                    age = candidate.get('transaction_age_ms', 'unknown')
                lines.append(f'    Connection {candidate.get("connection_id", "unknown")}, {kind}, age {age}ms, '
                             f'{origin.get("module", "external")}:{origin.get("line", "?")} {origin.get("function", "unknown")}')
        success = incident['last_successful_tool']
        if success:
            boundary = 'command succeeded' if success.get('event') == 'vm_tool_exec_complete' else 'result returned successfully'
            lines.append(f'  Last tool {boundary} at {success["timestamp"]}; call_id {success.get("call_id", "unknown")}.')
        if incident['nearby_stalls']:
            lines.append(f'  Nearby event-loop stall records/samples: {len(incident["nearby_stalls"])}.')
        for missing in incident['missing_evidence']:
            lines.append('  Missing: ' + missing.replace('_', ' ') + '.')
        lines.append('')
    return index, '\n'.join(lines) + '\n'
