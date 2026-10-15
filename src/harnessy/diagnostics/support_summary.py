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

_CHANNELS = ('harnessy', 'runtime', 'database', 'tools', 'backend', 'targets')
_TAIL_BYTES = 2 * 1024 * 1024
_MAX_ROWS = 20000
_MAX_INCIDENTS = 20
_CONTEXT_SECONDS = 30.0
_PERMISSION_RECEIPTS = 120
_ERROR_EVENTS = frozenset({
    'agent_run_error', 'headless_run_error', 'uncaught_exception',
    'sqlite_operation_error', 'tool_execution_error', 'request_error',
    'environment_command_timeout', 'workspace_environment_shutdown_stop_failed',
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
    recent = rows[-(_MAX_ROWS - len(targets) - len(permissions)):]
    retained = {id(row): row for row in targets + permissions + recent}
    return sorted(retained.values(), key=lambda row: row['timestamp'])


def _vm_failure_classification(row: dict[str, Any]) -> str | None:
    event = row.get('event')
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


def _permission_failure_classification(row: dict[str, Any]) -> str | None:
    if row.get('event') != 'tool_execution_complete':
        return None
    if row.get('target_validation') in {'missing', 'invalid', 'not_found', 'disabled'}:
        return 'tool_target_validation_failed'
    if row.get('error_code') == 'PERMISSION_POLICY_UNAVAILABLE':
        return 'tool_permission_policy_unavailable'
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
        'error_code', 'target_validation', 'permission', 'permission_decision',
        'permission_source', 'permission_reason', 'permission_target_mode',
        'permission_target_state', 'permission_changed', 'permission_states',
        'required_permissions', 'phase', 'approval_required', 'approved',
        'approval_wait_seconds', 'execution_duration_seconds', 'coordination_wait_seconds',
    )
    evidence = {key: row[key] for key in keys if key in row}
    if _is_lock(row):
        evidence['error_code'] = 'sqlite_database_locked'
    return evidence


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
    observation_keys = {(row.get('session_scope'), row.get('command_id')) for row in rows
                        if row.get('event') == 'vm_startup_observation' and isinstance(row.get('command_id'), str)
                        and _vm_failure_classification(row)}
    failures = [row for row in rows if (row.get('event') in _ERROR_EVENTS or _vm_failure_classification(row)
                                       or _target_failure_classification(row) or _permission_failure_classification(row) or _is_lock(row))
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
        if not permission_classification and not _has_frames(failure) and not any(_has_frames(row) for row in database_errors):
            missing.append('exception_traceback_unavailable')
        if lock and not database_errors:
            missing.append('database_operation_not_recorded')
        if lock:
            missing.append('lock_holder_not_identified')
        identity = json.dumps(_evidence(failure), sort_keys=True)
        incidents.append({
            'incident_id': hashlib.sha256(identity.encode()).hexdigest()[:24],
            'classification': 'sqlite_lock_contention' if lock else permission_classification or target_classification or vm_classification or 'operation_error',
            'failure': _evidence(failure),
            'nearby_database_errors': [_evidence(row) for row in database_errors[-3:]],
            'last_successful_tool': successful_tool,
            'nearby_stalls': [_evidence(row) for row in stalls[-4:]],
            'transcript_refresh_deferred_count': len(transcript_deferrals),
            'missing_evidence': missing,
            'correlation_is_not_proof_of_lock_ownership': True,
            'controller_evidence': controller_evidence[-8:],
            'target_operation_evidence': [_evidence(row) for row in rows if target_classification
                                         and row.get('session_scope') == failure.get('session_scope')
                                         and row.get('target_id') == failure.get('target_id')
                                         and row.get('operation_id') == failure.get('operation_id')
                                         and str(row.get('event')).startswith('test_target_operation_')][-16:],
        })
    counts = Counter(str(row.get('event', '')) for row in rows)
    durations = [row['drift_seconds'] for row in rows
                 if row.get('event') == 'event_loop_stall' and isinstance(row.get('drift_seconds'), (int, float))]
    index: dict[str, Any] = {
        'schema_version': 1, 'scope': 'bounded_current_and_previous_session_log_tails',
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
    target_lines.extend(['  A running VM monitor does not establish that its guest shell or web service is ready.', ''])
    from .logging import _export_metadata
    metadata = _export_metadata(Path(latest))
    session = metadata.get('session', {})
    version = session.get('app_version', 'unrecorded')
    index['session_app_version'] = version
    lines = [
        'HarnessyXO support summary', '==========================', '',
        'Start here; machine-readable evidence is in INCIDENTS.json.',
        f'Session application version: {version}; capture time: {metadata.get("captured_at", "unrecorded")}.',
        'This summary examines bounded current/previous-session log tails. Counts are not whole-session totals.',
        'Nearby events and tracked transactions are evidence for investigation, not proven lock ownership.', '',
        f'Recorded failures in examined logs: {len(failures)} (latest {len(incidents)} shown)',
        f'Event-loop stalls: {counts["event_loop_stall"]}; maximum recorded delay: {max(durations, default=0):.3f}s',
        f'During-stall stack samples: {counts["event_loop_stall_sample"]}',
        f'Transcript refresh deferrals: {counts["transcript_refresh_deferred"]}', '',
        f'Database failure observations: {index["database_errors"]}; instrumented SQLite operation errors: {counts["sqlite_operation_error"]}.',
        'Zero instrumented SQLite operation errors does not exclude lock errors recorded by other application operations.', '',
        *vm_lines,
        *target_lines,
        *permission_lines,
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
        if classification.startswith('test_target_'):
            for key in ('target_id', 'target_backend', 'target_action', 'target_stage', 'target_failure_code',
                        'target_interface', 'target_view_failure_code', 'elapsed_seconds', 'attempt', 'timeout_seconds'):
                if key in failure:
                    lines.append(f'  {key}: {failure[key]}')
            if classification == 'test_target_view_unavailable':
                lines.append('  The browser display transport failed or rejected a bounded request/response. Check the fixed failure code and target boot evidence; VM running state alone does not establish display readiness.')
            else:
                lines.append('  Inspect target_operation_evidence and TARGET_LOGS.json; a shell probe failure does not establish that the VM failed to boot.')
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
        fault = failure.get('fault') or failure.get('exception_evidence') or {}
        if isinstance(fault, dict):
            if fault.get('exception_type') or fault.get('exception_class'):
                lines.append(f'  Exception: {fault.get("exception_type") or fault.get("exception_class")}')
            for frame in fault.get('frames', [])[-6:]:
                if isinstance(frame, dict):
                    lines.append(f'  Frame: {frame.get("module", "external")}:{frame.get("line", "?")} {frame.get("function", "unknown")}')
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
