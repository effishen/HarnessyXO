"""Bounded, content-free incident index for a support export.

This reads logs only. It never opens a workspace database or claims that a
nearby operation is a proven lock holder.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
from typing import Any
from .permissions import PERMISSION_EVENTS
from .startup import (STARTUP_EVENTS, HOST_SETUP_ERROR_CODES,
                      HOST_ENVIRONMENT_PROVIDERS, HOST_RUNTIME_BACKENDS)
from .controller_observations import (CONTROLLER_OBSERVATION_EVENTS,
                                      validate_controller_observation)
from .windows_media import (WINDOWS_MEDIA_BROWSER_EVENT,
                            validate_windows_media_browser_observation)
from harnessy.agent.permission_provenance import (PERMISSION_ACKNOWLEDGEMENT_EVENTS,
                                                build_permission_acknowledgement_audit)

_CHANNELS = ('harnessy', 'runtime', 'database', 'tools', 'backend', 'targets')
_TAIL_BYTES = 2 * 1024 * 1024
_MAX_ROWS = 20000
_MAX_INCIDENTS = 20
_CONTEXT_SECONDS = 30.0
_TARGET_FOLLOWUP_SECONDS = 300.0
_PERMISSION_RECEIPTS = 120
_ACCESS_RESTORE_EVENTS = frozenset({
    'account_store_check_started', 'account_store_check_completed', 'account_store_check_busy',
    'account_store_check_timed_out', 'account_store_check_failed',
    'login_verification_started', 'login_accepted', 'login_rejected', 'login_busy',
    'login_timed_out', 'login_failed',
    'page_build_started', 'page_session_restore_started', 'page_session_restore_completed',
    'page_workspace_restore_started', 'page_built',
    'saved_tab_restore_failed', 'workspace_open_failed', 'history_lock_busy',
    'workspace_database_health_started', 'workspace_database_health_completed',
    'workspace_database_health_failed', 'workspace_database_store_reused', 'workspace_database_preparation_started',
})
_ACCESS_RESTORE_FAILURES = {
    'account_store_check_busy': 'account_store_busy',
    'account_store_check_timed_out': 'account_store_timed_out',
    'account_store_check_failed': 'account_store_failed',
    'login_busy': 'login_busy', 'login_timed_out': 'login_timed_out', 'login_failed': 'login_failed',
    'saved_tab_restore_failed': 'saved_tab_restore_failed',
    'workspace_open_failed': 'workspace_open_failed',
    'history_lock_busy': 'history_lock_contention',
    'workspace_database_health_failed': 'workspace_database_health_failed',
}
_WORKSPACE_RECOVERY_EVENTS = frozenset({
    'workspace_database_recovery_started', 'workspace_database_recovery_progress',
    'workspace_database_recovery_completed', 'workspace_database_recovery_failed',
})
_ERROR_EVENTS = frozenset({
    'agent_run_error', 'headless_run_error', 'uncaught_exception',
    'sqlite_operation_error', 'tool_execution_error', 'request_error',
    'environment_command_timeout', 'workspace_environment_shutdown_stop_failed',
    'environment_command_spawn_failed', 'vm_failure_evidence_unavailable', 'run_blocked_by_infrastructure',
    'environment_operation_failed', 'environment_operation_timed_out',
    'workspace_terminal_start_failed',
    'file_view_reconciliation_failed',
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
    permission_acknowledgements = [row for row in rows
                                  if row.get('event') in PERMISSION_ACKNOWLEDGEMENT_EVENTS][-240:]
    startup = [row for row in rows if row.get('event') in STARTUP_EVENTS][-120:]
    from .model_requests import MODEL_EVENTS
    models = [row for row in rows if row.get('event') in MODEL_EVENTS][-600:]
    from .controller_observations import CONTROLLER_OBSERVATION_EVENTS
    controllers = _retained_controller_rows([row for row in rows if row.get('event') in CONTROLLER_OBSERVATION_EVENTS])
    from .queue_observations import QUEUE_EVENTS
    queues = [row for row in rows if row.get('event') in QUEUE_EVENTS][-160:]
    access_restore = [row for row in rows if row.get('event') in _ACCESS_RESTORE_EVENTS][-120:]
    recovery = [row for row in rows if row.get('event') in _WORKSPACE_RECOVERY_EVENTS][-600:]
    terminals = [row for row in rows if row.get('event') == 'workspace_terminal_start_failed'][-120:]
    recent = rows[-(_MAX_ROWS - len(targets) - len(permissions) - len(permission_acknowledgements)
                    - len(startup) - len(models) - len(controllers) - len(queues) - len(access_restore) - len(recovery) - len(terminals)):]
    retained = {id(row): row for row in targets + permissions + permission_acknowledgements
                + startup + models + controllers + queues + access_restore + recovery + terminals + recent}
    return sorted(retained.values(), key=lambda row: row['timestamp'])


def _terminal_failure_classification(row: dict[str, Any]) -> str | None:
    if row.get('event') != 'workspace_terminal_start_failed':
        return None
    from .terminal_failures import terminal_failure_code
    return terminal_failure_code(row) or 'workspace_terminal_start_failed'


def _terminal_failure_evidence(row: dict[str, Any]) -> dict[str, Any]:
    from .terminal_failures import TERMINAL_MODES, terminal_failure_evidence
    from .technical import validate_technical_evidence
    evidence = {key: row[key] for key in ('timestamp', 'channel', 'session_scope', 'event') if key in row}
    environment_id = row.get('environment_id')
    if isinstance(environment_id, str) and re.fullmatch(r'[0-9a-f]{32}', environment_id):
        evidence['environment_id'] = environment_id
    mode = row.get('terminal_mode')
    if isinstance(mode, str) and mode in TERMINAL_MODES:
        evidence['terminal_mode'] = mode
    failure = terminal_failure_evidence(row)
    if failure:
        evidence['terminal_failure_code'] = failure['code']
        evidence['terminal_failure_basis'] = failure['basis']
    technical = row.get('technical_error')
    error = row.get('error')
    if not isinstance(technical, dict) and isinstance(error, dict):
        technical = error.get('technical_error')
    if isinstance(technical, dict):
        evidence['technical_error'] = validate_technical_evidence(technical)
    return evidence


def _vm_failure_classification(row: dict[str, Any]) -> str | None:
    event = row.get('event')
    if row.get('provider') == 'host':
        if event == 'environment_controller_timed_out':
            return 'host_prerequisite_command_timeout'
        if event == 'environment_controller_spawn_failed':
            return 'host_prerequisite_command_spawn_failed'
        if event == 'environment_controller_finished' and type(row.get('controller_returncode')) is int and row['controller_returncode'] != 0:
            return 'host_prerequisite_command_failed'
    if (event == 'vm_host_preflight_failed' and row.get('error_code') == 'KVM_ACCESS_DENIED'
            and row.get('kvm_present') is True and row.get('kvm_accessible') is False):
        return 'vm_host_kvm_access_denied'
    if event in {'environment_command_spawn_failed', 'environment_controller_spawn_failed'}:
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
    if event in {'environment_command_timeout', 'environment_controller_timed_out'}:
        return 'vm_controller_timeout'
    action = row.get('controller_action')
    if event == 'environment_controller_finished' and isinstance(action, str) and action in {'start', 'stop', 'create', 'delete', 'edit', 'clone', 'snapshot', 'restart', 'factory-reset'}:
        code = row.get('controller_returncode')
        if type(code) is int and code != 0:
            return 'vm_controller_interrupted' if code < 0 else 'vm_controller_failed'
    if event == 'environment_command_finished' and isinstance(action, str) and action in {'start', 'stop', 'create', 'delete', 'edit', 'clone', 'snapshot', 'restart', 'factory-reset'}:
        code = row.get('returncode')
        if type(code) is int and code != 0:
            return 'vm_controller_interrupted' if code < 0 else 'vm_controller_failed'
    if event == 'workspace_environment_shutdown_stop_failed':
        return 'vm_shutdown_stop_unverified'
    return None




def _host_kvm_facts(report: dict[str, Any] | None) -> dict[str, Any]:
    """Corroborating export-time facts, never an account database assertion."""
    if not isinstance(report, dict):
        return {}
    from .host_state import validate_host_diagnostics
    safe = validate_host_diagnostics(report)
    device, process = safe.get('kvm', {}), safe.get('process', {})
    if device.get('status') != 'ok':
        return {}
    facts: dict[str, Any] = {'capture_scope': 'export_time'}
    for key in ('mode', 'uid', 'gid', 'readable', 'writable'):
        if key in device:
            facts[key] = device[key]
    for key in ('uid', 'euid', 'gid', 'egid'):
        if key in process:
            facts['process_' + key] = process[key]
    groups = process.get('supplementary_group_ids')
    if isinstance(groups, list) and len(groups) < 256 and type(device.get('gid')) is int:
        active = set(groups) | {process.get('gid'), process.get('egid')}
        facts['device_group_active'] = device['gid'] in active
    return facts


def _kvm_permission_cause(failure: dict[str, Any], rows: list[dict[str, Any]],
                          vm_report: dict[str, Any] | None,
                          host_facts: dict[str, Any]) -> dict[str, Any] | None:
    """Require an explicit guard or native error tied to this controller attempt."""
    if not _vm_failure_classification(failure):
        return None
    operation = failure.get('operation_id')
    for row in [failure] + rows:
        if _vm_failure_classification(row) != 'vm_host_kvm_access_denied':
            continue
        if row is not failure and (not isinstance(operation, str)
                or row.get('operation_id') != operation
                or row.get('session_scope') != failure.get('session_scope')
                or row.get('workspace_id') != failure.get('workspace_id')):
            continue
        return {'code': 'KVM_ACCESS_DENIED', 'source': 'host_kvm_preflight',
                'host_access': host_facts}
    # Raw native/guest prose is deliberately absent from diagnostics. Only
    # the explicit host preflight above establishes this precise cause.
    return None


def _kvm_cause_lines(cause: dict[str, Any]) -> list[str]:
    prefix = ('The host preflight blocked this operation because the process lacks read/write KVM access.'
              if cause.get('source') == 'host_kvm_preflight' else
              'QEMU reported the startup cause: KVM access was denied (Permission denied).')
    lines = [prefix]
    facts = cause.get('host_access') or {}
    if facts:
        observed = {key: value for key, value in facts.items() if key != 'capture_scope'}
        lines.append('Corroborating host access facts at export time: ' + json.dumps(observed, sort_keys=True) + '.')
        if facts.get('device_group_active') is False:
            lines.append('The KVM device\'s owning group was not active in this HarnessyXO process; this does not establish the account\'s saved group membership.')
    lines.append('Give your normal account read/write access through the KVM device\'s owning group. After a group change, fully sign out and back in, then restart HarnessyXO so it receives the new groups. Check device ACL/container policy if access remains denied.')
    return lines


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


def _timeout_failure_classification(row: dict[str, Any]) -> str | None:
    if row.get('event') == 'environment_operation_timed_out':
        return ('environment_operation_deadline' if row.get('timeout_scope') == 'operation'
                else 'environment_timeout_unscoped')
    if row.get('event') == 'environment_operation_failed' and row.get('timeout_scope') == 'provider':
        return 'environment_provider_timeout'
    return None


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
    decision = row.get('permission_decision')
    if (row.get('error_code') == 'TARGET_ACTION_OFF'
            or (isinstance(decision, dict) and decision.get('reason') == 'blocked_target_action')):
        return 'tool_target_action_blocked'
    return None


def _startup_failure_classification(row: dict[str, Any]) -> str | None:
    code = row.get('host_prerequisite_error_code')
    if (row.get('event') == 'environment_operation_failed'
            and isinstance(code, str) and code in HOST_SETUP_ERROR_CODES):
        return 'environment_host_prerequisite_failed'
    if row.get('event') == 'host_prerequisite_setup':
        from .startup import validate_startup_event
        receipt = validate_startup_event('host_prerequisite_setup', row)
        if receipt and receipt.get('status') in {'failed', 'action_required'}:
            return 'host_prerequisite_setup_failed' if receipt['status'] == 'failed' else 'host_prerequisite_action_required'
    if row.get('event') == 'launcher_rea_setup_failed':
        from .startup import validate_storage_issue
        return 'rea_storage_validation_failed' if validate_storage_issue(row.get('storage_issue')) else 'rea_setup_failed'
    return None


def _host_prerequisite_failure_lines(row: dict[str, Any]) -> list[str]:
    """Describe fixed host setup facts without retaining the exception text."""
    code = row.get('host_prerequisite_error_code', row.get('error_code'))
    if not isinstance(code, str) or code not in HOST_SETUP_ERROR_CODES:
        return []
    lines = ['  Host prerequisite setup failed; recorded code: ' + code + '.']
    for key, allowed in (('environment_provider', HOST_ENVIRONMENT_PROVIDERS),
                         ('runtime_backend', HOST_RUNTIME_BACKENDS)):
        value = row.get(key)
        if isinstance(value, str) and value in allowed:
            lines.append('  ' + key + ': ' + value + '.')
    stage = row.get('failed_stage')
    if isinstance(stage, str):
        from .logging import _VM_DIAGNOSTIC_ENUMS
        if stage in _VM_DIAGNOSTIC_ENUMS['failed_stage']:
            lines.append('  Recorded operation stage: ' + stage + '.')
    if code == 'provider_unsupported':
        lines.append('  The host prerequisite check rejected the environment provider. '
                     'Runtime setup did not proceed through this prerequisite check.')
    return lines


def _windows_media_failure_classification(row: dict[str, Any]) -> str | None:
    if row.get('event') != 'environment_operation_failed':
        return None
    observed = validate_windows_media_browser_observation(row.get('windows_media_browser'))
    if observed is None or observed['result'] == 'info':
        return None
    return 'windows_media_' + observed['result']


def _windows_media_failure_lines(row: dict[str, Any]) -> list[str]:
    observed = validate_windows_media_browser_observation(row.get('windows_media_browser'))
    if observed is None:
        return []
    explanations = {
        'challenge': 'A visible browser challenge stopped the ordinary Windows download page flow.',
        'rejected': 'The Windows download page reported a rejected request.',
        'page_error': 'The Windows download page reported an error; a download rejection was not established.',
        'network_error': 'A network error was observed during the Windows download page flow.',
        'http_error': 'A Windows download page request returned a failing HTTP status.',
        'timeout': 'The Windows download browser reached its recorded time limit.',
        'browser_unavailable': 'The Windows download browser could not be prepared or started.',
    }
    lines = ['  Windows media browser phase: ' + observed['phase'] + '; result: ' + observed['result'] + '.']
    if observed['result'] in explanations:
        lines.append('  ' + explanations[observed['result']])
    facts = {key: observed[key] for key in ('http_status', 'browser_version', 'error_kind') if key in observed}
    if facts:
        lines.append('  Recorded browser facts: ' + json.dumps(facts, sort_keys=True) + '.')
    return lines


def _windows_media_browser_audit(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    observed = [row for row in rows if row.get('event') == WINDOWS_MEDIA_BROWSER_EVENT
                and validate_windows_media_browser_observation(row.get('windows_media_browser')) is not None]
    records = [_evidence(row) for row in observed[-40:]]
    audit = {'schema_version': 1, 'scope': 'bounded_log_observations',
             'records_available': len(observed), 'records_retained': len(records),
             'record_limit': 40, 'limited': len(observed) > 40, 'records': records}
    if not records:
        return audit, []
    lines = ['Windows download browser: fixed observations from the examined log tails.']
    for row in records[-8:]:
        browser = row['windows_media_browser']
        lines.append(f'  {row["timestamp"]} [{row["session_scope"]}]: phase {browser["phase"]}; result {browser["result"]}.')
        facts = {key: browser[key] for key in ('http_status', 'browser_version', 'error_kind') if key in browser}
        if facts:
            lines.append('    Recorded browser facts: ' + json.dumps(facts, sort_keys=True) + '.')
    lines.extend(['  These are observed page/browser outcomes; a generic page error alone does not establish a Microsoft rejection or browser challenge.', ''])
    return audit, lines


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
    from .startup import is_kvm_refresh_handoff, validate_startup_event
    from .queue_observations import QUEUE_EVENTS, validate_queue_event

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
            launcher_handoff = launcher_handoff or bool(safe and is_kvm_refresh_handoff(safe))
            if safe is None and isinstance(body, dict) and isinstance(body.get('event'), str) and body['event'] in QUEUE_EVENTS:
                safe = validate_queue_event(body['event'], body)
        except (ValueError, TypeError, RecursionError):
            continue
        if safe is not None:
            rows.append({**safe, 'timestamp': stamp, 'channel': 'harnessy',
                         'level': parts[2], 'session_scope': 'launcher'})
    if not launcher_handoff or application_started:
        return [], []
    # Queue repair and prerequisite installation happen before application
    # exec. Their reviewed runtime receipts must survive that session handoff.
    runtime = _read_snapshot_bytes(path / 'runtime.log', tail_bytes=limit)
    for line in (runtime.decode('utf-8', errors='replace').splitlines() if runtime else []):
        parts = line.split(' ', 3)
        if len(parts) != 4 or parts[2] not in {'INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL'}:
            continue
        try:
            stamp = f'{parts[0]} {parts[1]}'
            datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S,%f')
            body = json.loads(parts[3])
            if not isinstance(body, dict):
                continue
            if body.get('event') == 'host_prerequisite_setup':
                safe = validate_startup_event('host_prerequisite_setup', body)
            elif body.get('event') == 'run_queue_holds_retired':
                safe = validate_queue_event('run_queue_holds_retired', body)
            else:
                continue
        except (ValueError, TypeError, RecursionError):
            continue
        if safe is not None:
            rows.append({**safe, 'timestamp': stamp, 'channel': 'runtime',
                         'level': parts[2], 'session_scope': 'launcher'})
    rows = sorted(rows, key=lambda row: row['timestamp'])[-120:]
    coverage = []
    for channel in ('harnessy', 'runtime'):
        channel_rows = [row for row in rows if row['channel'] == channel]
        if not channel_rows:
            continue
        try:
            limited = (path / (channel + '.log')).stat().st_size > limit
        except OSError:
            limited = True
        coverage.append({'channel': channel, 'session_scope': 'launcher',
                         'first_timestamp': channel_rows[0]['timestamp'], 'last_timestamp': channel_rows[-1]['timestamp'],
                         'records_examined': len(channel_rows), 'log_tail_limited': limited,
                         'startup_receipts_only': True})
    return rows, coverage


def _seconds(left: str, right: str) -> float:
    return (datetime.strptime(left, '%Y-%m-%d %H:%M:%S,%f') -
            datetime.strptime(right, '%Y-%m-%d %H:%M:%S,%f')).total_seconds()


def _same_scope(candidate: dict[str, Any], incident: dict[str, Any]) -> bool:
    for key in ('session_scope', 'workspace_id', 'chat_id', 'run_id', 'target_id'):
        if incident.get(key) and candidate.get(key) and incident[key] != candidate[key]:
            return False
    return True


def _recovery_failure_classification(row: dict[str, Any]) -> str | None:
    if row.get('event') not in {'workspace_database_recovery_completed', 'workspace_database_recovery_failed'}:
        return None
    status = row.get('recovery_status')
    if not isinstance(status, str):
        return 'workspace_recovery_failed' if row.get('event') == 'workspace_database_recovery_failed' else None
    if status in {'activation_blocked', 'incomplete_transaction', 'rolled_back'}:
        return 'workspace_recovery_' + status
    if status == 'needs_review' and row.get('corruption_established') is True:
        return 'workspace_recovery_corruption_observed'
    if status in {'partial_salvage', 'partial_salvage_candidate_needs_review',
                  'salvage_candidate_needs_review_completeness_unknown', 'needs_review'}:
        return 'workspace_recovery_needs_review'
    if status in {'timed_out', 'inspection_timed_out_originals_preserved'}:
        return 'workspace_recovery_timeout'
    if status == 'corrupt':
        return 'workspace_recovery_corruption_observed'
    if status in {'failed', 'stopped', 'preserved_recovery_unavailable',
                  'inspection_unavailable_originals_preserved', 'preserved_needs_specialist_recovery',
                  'source_changed_recovery_result_not_usable'} or row.get('event') == 'workspace_database_recovery_failed':
        return 'workspace_recovery_failed'
    return None


def _recovery_evidence(row: dict[str, Any]) -> dict[str, Any]:
    from .logging import validate_workspace_recovery_event
    safe = validate_workspace_recovery_event(row.get('event'), row) or {}
    safe.update({key: row[key] for key in ('timestamp', 'channel', 'session_scope') if key in row})
    return safe


def _workspace_recovery_audit(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    observed = [row for row in rows if row.get('event') in _WORKSPACE_RECOVERY_EVENTS]
    receipts = [_recovery_evidence(row) for row in observed[-600:]]
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for row in receipts:
        identity_key = next((key for key in ('recovery_operation_id', 'recovery_receipt_id', 'db_id') if key in row), 'unidentified')
        groups.setdefault((row.get('session_scope', 'unrecorded'), identity_key, row.get(identity_key, 'unidentified')), []).append(row)
    operations = []
    lines = ['Workspace database recovery: DATABASE_RECOVERY.json retains bounded copy/check/repair/activation receipts; database bytes and recovered SQL are excluded.']
    descriptions = {
        'healthy': 'The private copy passed the recorded checks; no repair or activation is implied.',
        'healthy_preserved_copy': 'The private copy passed the recorded checks; the original database was not repaired by this observation.',
        'healthy_structure_needs_review': 'Structure checks passed, but application-level review remains required.',
        'corrupt': 'A private-copy check reported corruption; the original cause is not established.',
        'index_repaired': 'An index-repair candidate was verified. Activation requires a separate activated receipt.',
        'verified_index_repair_candidate_needs_review': 'An index-repair candidate was verified; it remains separate until activation is recorded.',
        'candidate_ready': 'A verified candidate is available; this does not establish activation or complete recovery of all original rows.',
        'partial_salvage': 'Salvage may omit or reject data. Review the recorded readable-source/candidate counts before activation.',
        'partial_salvage_candidate_needs_review': 'A salvage candidate is partial; readable-source/candidate count differences require review.',
        'salvage_candidate_needs_review_completeness_unknown': 'A salvage candidate exists, but recovery completeness is unknown.',
        'needs_review': 'The recovery result requires review; no complete-data recovery or activation is implied.',
        'activation_blocked': 'Activation was blocked. The fixed failure code identifies the failed precondition.',
        'incomplete_transaction': 'Database replacement did not finish as a complete transaction; keep the workspace closed and use the recorded rollback/recovery state.',
        'rolled_back': 'A rollback completed. This is separate from verifying or activating a repaired candidate.',
        'activated': 'Candidate activation completed according to the receipt. Earlier corruption observations remain historical evidence.',
        'timed_out': 'The private-copy worker reached its time limit; this result does not establish corruption.',
        'inspection_timed_out_originals_preserved': 'The private-copy inspection reached its time limit; no corruption conclusion or repair was made.',
        'cancelled': 'Recovery was cancelled; inspect preservation and transaction facts before retrying.',
        'cancelled_originals_preserved': 'Recovery was cancelled with originals preserved according to its receipt.',
        'source_changed_recovery_result_not_usable': 'The source changed; the recovery result cannot be used for activation.',
    }
    for (scope, identity_key, identity), items in sorted(groups.items(), key=lambda entry: entry[1][-1].get('timestamp', ''))[-12:]:
        latest = items[-1]
        terminal = next((row for row in reversed(items) if row.get('event') in {'workspace_database_recovery_completed', 'workspace_database_recovery_failed'}), None)
        operation = {'session_scope': scope, 'grouping': identity_key, 'records_retained': len(items),
                     'latest': latest, 'latest_terminal': terminal}
        if identity_key != 'unidentified':
            operation[identity_key] = identity
        fact_names = ('elapsed_seconds', 'stage_elapsed_seconds', 'timeout_seconds', 'source_db_bytes',
                      'source_wal_bytes', 'source_shm_bytes', 'source_journal_bytes', 'source_bytes',
                      'copied_bytes', 'total_bytes', 'free_bytes', 'required_bytes', 'candidate_bytes',
                      'recovery_failure_code', 'database_worker_returncode', 'database_worker_signal',
                      'originals_unchanged', 'originals_preserved', 'source_unchanged', 'candidate_verified',
                      'integrity_ok', 'standalone_database', 'completeness_known', 'activated', 'rollback_complete',
                      'row_counts', 'source_row_counts', 'candidate_row_counts', 'recovery_method',
                      'corruption_established', 'integrity_error_count', 'integrity_categories',
                      'sqlite_errorcode', 'sqlite_errorname')
        latest_facts = {}
        for receipt in items:
            for key in fact_names:
                if key in receipt:
                    latest_facts[key] = {'value': receipt[key], 'timestamp': receipt.get('timestamp'),
                                         'recovery_stage': receipt.get('recovery_stage')}
        operation['latest_fact_observations'] = latest_facts
        operations.append(operation)
        status, stage = latest.get('recovery_status', 'unrecorded'), latest.get('recovery_stage', 'unrecorded')
        lines.append(f'  {latest.get("timestamp", "unrecorded")} [{scope}] stage {stage}; status {status}.')
        if status == 'needs_review' and latest.get('corruption_established') is True:
            lines.append('    The private-copy check confirmed corruption; no verified repair or activation is established by this receipt.')
        elif status in descriptions:
            lines.append('    ' + descriptions[status])
        facts = {key: value['value'] for key, value in latest_facts.items()
                 if key not in {'row_counts', 'source_row_counts', 'candidate_row_counts'}}
        if facts:
            lines.append('    Most recent recorded facts per field (may span stages): ' + json.dumps(facts, sort_keys=True) + '.')
        for key, label in (('row_counts', 'Readable row counts'), ('source_row_counts', 'Readable source rows'),
                           ('candidate_row_counts', 'Candidate rows')):
            if key in latest_facts:
                lines.append('    ' + label + ': ' + json.dumps(latest_facts[key]['value'], sort_keys=True) + '.')
    if not receipts:
        lines.append('  No database recovery operation was recorded in these examined tails.')
    lines.extend(['  Check, repair-candidate creation, activation and rollback are distinct stages. A timed-out check is not proof of corruption. Counts cover readable rows only and cannot establish the contents of unreadable pages.',
                  '  Receipts describe observations at their timestamps; no database was opened to construct this export.', ''])
    return {'schema_version': 1, 'scope': 'bounded_current_previous_log_recovery_receipts',
            'records_available': len(observed), 'records_retained': len(receipts), 'record_limit': 600,
            'records_limited': len(observed) > 600, 'operation_groups_available': len(groups),
            'operation_groups_retained': len(operations), 'operation_group_limit': 12,
            'operations': operations, 'records': receipts}, lines


def _workspace_database_classification(row: dict[str, Any]) -> str | None:
    if row.get('event') not in {'workspace_database_health_failed', 'workspace_open_failed', 'saved_tab_restore_failed'}:
        return None
    status = row.get('database_health_status')
    if status == 'unavailable' and (row.get('database_health_reason') == 'sqlite_busy' or _is_lock(row)):
        return 'workspace_database_busy'
    if status == 'unavailable' and row.get('database_health_reason') == 'history_busy':
        return 'workspace_database_history_busy'
    return {
        'corrupt': 'workspace_database_corruption',
        'timed_out': 'workspace_database_health_timeout',
        'worker_failed': 'workspace_database_worker_failed',
        'unavailable': 'workspace_database_unavailable',
    }.get(status) if isinstance(status, str) else None


def _database_condition(row: dict[str, Any]) -> str | None:
    """Classify only SQLite's reviewed numeric or symbolic result identifiers."""
    known_names = {name for name, value in vars(sqlite3).items()
                   if name.startswith('SQLITE_') and type(value) is int}
    pending: list[tuple[Any, int]] = [(row, 0)]
    while pending:
        value, depth = pending.pop()
        if not isinstance(value, dict) or depth > 4:
            continue
        code, name = value.get('sqlite_errorcode'), value.get('sqlite_errorname')
        base = (code & 255) if type(code) is int and 0 <= code <= 2**31 - 1 else None
        if base == sqlite3.SQLITE_CORRUPT:
            return 'sqlite_database_corruption'
        if base == sqlite3.SQLITE_NOTADB:
            return 'sqlite_not_a_database'
        if base is None and isinstance(name, str) and name in known_names:
            if name == 'SQLITE_CORRUPT' or name.startswith('SQLITE_CORRUPT_'):
                return 'sqlite_database_corruption'
            if name == 'SQLITE_NOTADB':
                return 'sqlite_not_a_database'
        for key in ('error', 'detail', 'fault', 'exception_evidence'):
            if isinstance(value.get(key), dict):
                pending.append((value[key], depth + 1))
        chain = value.get('chain')
        if isinstance(chain, list):
            pending.extend((item, depth + 1) for item in chain[:4])
    return None


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
    if row.get('event') in CONTROLLER_OBSERVATION_EVENTS:
        safe = validate_controller_observation(row['event'], row) or {}
        stamp = row.get('timestamp')
        if isinstance(stamp, str) and re.fullmatch(r'\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[,.]\d{1,6})?', stamp):
            safe['timestamp'] = stamp
        if isinstance(row.get('session_scope'), str) and row['session_scope'] in {'current', 'previous', 'launcher'}:
            safe['session_scope'] = row['session_scope']
        if isinstance(row.get('channel'), str) and row['channel'] in _CHANNELS:
            safe['channel'] = row['channel']
        return safe
    if row.get('event') == 'workspace_terminal_start_failed':
        return _terminal_failure_evidence(row)
    if row.get('event') in _WORKSPACE_RECOVERY_EVENTS:
        return _recovery_evidence(row)
    if row.get('event') in _ACCESS_RESTORE_EVENTS:
        return _access_restore_evidence(row)
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
        'required_permissions', 'target_action_permissions', 'phase', 'approval_required', 'approved',
        'approval_wait_seconds', 'execution_duration_seconds', 'coordination_wait_seconds',
        'state', 'changed', 'archive_check', 'storage_issue', 'version', 'status',
        'exception_class',
        'error_type', 'terminal_stop_reason', 'terminal_reason', 'backend_done_reason',
        'source', 'technical_error', 'controller_evidence', 'requested_vm_config',
        'environment_action', 'lifecycle_action', 'preservation_reason', 'failure_receipt', 'host_resources',
        'kvm_present', 'kvm_accessible',
        'timeout_scope', 'failed_stage', 'controller_state', 'completion_phase',
        'stdout_bytes', 'stderr_bytes', 'last_output_age_seconds', 'output_capture',
        'capture_scope', 'pending_progress', 'post_exit_output_not_collected',
    )
    evidence = {key: row[key] for key in keys if key in row}
    environment_id = row.get('environment_id')
    if isinstance(environment_id, str) and re.fullmatch(r'[0-9a-f]{32}', environment_id):
        evidence['environment_id'] = environment_id
    observed_browser = validate_windows_media_browser_observation(row.get('windows_media_browser'))
    if observed_browser is not None:
        evidence['windows_media_browser'] = observed_browser
    for key, allowed in (('host_prerequisite_error_code', HOST_SETUP_ERROR_CODES),
                         ('environment_provider', HOST_ENVIRONMENT_PROVIDERS),
                         ('runtime_backend', HOST_RUNTIME_BACKENDS)):
        value = row.get(key)
        if isinstance(value, str) and value in allowed:
            evidence[key] = value
    if 'guest_transport' in row:
        from .guest_logs import validate_transport_evidence
        evidence['guest_transport'] = validate_transport_evidence(row['guest_transport'])
    if row.get('event') == 'host_prerequisite_setup':
        from .startup import validate_startup_event
        evidence.update(validate_startup_event('host_prerequisite_setup', row) or {})
    condition = _database_condition(row)
    if condition:
        evidence['error_code'] = condition
    elif _is_lock(row):
        evidence['error_code'] = 'sqlite_database_locked'
    return evidence


def _access_restore_evidence(row: dict[str, Any]) -> dict[str, Any]:
    """Fixed stages only; no account, browser, workspace or page identities."""
    evidence = {key: row[key] for key in ('timestamp', 'channel', 'session_scope', 'event') if key in row}
    for key in ('elapsed_seconds', 'waited_seconds', 'lock_timeout_seconds', 'timeout_seconds'):
        value = row.get(key)
        if type(value) in (int, float) and 0 <= value <= 604800 and math.isfinite(value):
            evidence[key] = value
    if isinstance(row.get('lock_kind'), str) and row['lock_kind'] in {'thread', 'process'}:
        evidence['lock_kind'] = row['lock_kind']
    if isinstance(row.get('db_id'), str) and re.fullmatch(r'[0-9a-f]{64}', row['db_id']):
        evidence['db_id'] = row['db_id']
    code, name = row.get('sqlite_errorcode'), row.get('sqlite_errorname')
    if type(code) is int and 0 <= code <= 2**31 - 1:
        evidence['sqlite_errorcode'] = code
    if isinstance(name, str) and name in {key for key, value in vars(sqlite3).items()
                                         if key.startswith('SQLITE_') and type(value) is int}:
        evidence['sqlite_errorname'] = name
    from .logging import _WORKSPACE_DATABASE_ENUMS
    for key, allowed in _WORKSPACE_DATABASE_ENUMS.items():
        if isinstance(row.get(key), str) and row[key] in allowed:
            evidence[key] = row[key]
    if type(row.get('database_worker_returncode')) is int and -255 <= row['database_worker_returncode'] <= 255:
        evidence['database_worker_returncode'] = row['database_worker_returncode']
    from .operational import operational_label
    error_class = operational_label(row.get('error_class'), 'exception_class')
    if error_class:
        evidence['error_class'] = error_class
    return evidence


def _workspace_database_access_audit(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """Report each known database's latest outcome without opening its files."""
    events = {'workspace_database_health_started', 'workspace_database_health_completed',
              'workspace_database_health_failed', 'workspace_database_store_reused', 'workspace_database_preparation_started'}
    observed = [row for row in rows if row.get('event') in events]
    identified = [row for row in observed if isinstance(row.get('db_id'), str)
                  and re.fullmatch(r'[0-9a-f]{64}', row['db_id'])]
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in identified:
        groups.setdefault(row['db_id'], []).append(row)
    databases = []
    lines = ['Latest recorded workspace database access: admission, initialization and reuse are separate from repair.']
    explanations = {
        'workspace_database_busy': 'SQLite reported busy/locked contention, not verified corruption. Wait for active work to finish and retry; these receipts do not identify the lock holder.',
        'workspace_database_history_busy': 'The history lock was busy. This is separate from SQLite corruption or disk unavailability.',
        'workspace_database_health_timeout': 'The isolated check or initialization reached its deadline. A timeout does not establish corruption.',
        'workspace_database_worker_failed': 'The isolated worker failed or exited. A worker failure alone does not establish database corruption.',
        'workspace_database_corruption': 'The database health worker reported corruption; the original cause is not established.',
        'sqlite_database_corruption': 'SQLite reported SQLITE_CORRUPT. This is a corruption result, separately from ordinary contention or timeout.',
        'sqlite_not_a_database': 'SQLite reported that the opened file was not a database; this is separate from ordinary contention.',
    }
    for db_id, items in sorted(groups.items(), key=lambda pair: pair[1][-1]['timestamp'])[-12:]:
        latest = _access_restore_evidence(items[-1])
        failure = next((_access_restore_evidence(row) for row in reversed(items)
                        if row.get('event') == 'workspace_database_health_failed'), None)
        success = next((_access_restore_evidence(row) for row in reversed(items)
                        if row.get('event') in {'workspace_database_health_completed', 'workspace_database_store_reused'}), None)
        classification = (_database_condition(latest) or _workspace_database_classification(latest))
        record = {'db_id': db_id, 'records_examined': len(items), 'latest': latest,
                  'latest_failure': failure, 'latest_success_or_reuse': success,
                  'latest_outcome_classification': classification if latest.get('event') == 'workspace_database_health_failed' else None,
                  'latest_failure_classification': (_database_condition(failure) or _workspace_database_classification(failure)) if failure else None}
        databases.append(record)
        lines.append(f'  Database {db_id[:12]} / {latest.get("session_scope", "unrecorded")}: {latest["event"]} at {latest["timestamp"]}.')
        if latest['event'] == 'workspace_database_store_reused':
            lines.append('    A previously prepared in-process store passed its reuse guard. No fresh integrity scan or migration is implied.')
        elif latest['event'] == 'workspace_database_health_completed':
            lines.append('    The recorded admission/initialization completed successfully; earlier failures remain historical observations.')
        elif latest['event'] in {'workspace_database_health_started', 'workspace_database_preparation_started'}:
            lines.append('    A check or initialization started; this tail contains no later result for this database.')
        elif classification in explanations:
            lines.append('    ' + explanations[classification])
        elif latest.get('database_health_reason') == 'sqlite_error':
            lines.append('    A SQLite operation failed during the recorded phase. This generic error does not establish renewed corruption; inspect the preserved numeric result code/name when present.')
        elif latest.get('database_health_reason') in {'maintenance', 'recovery_pending'}:
            lines.append('    Workspace access is guarded by maintenance or an unfinished replacement transaction; this is separate from a corruption finding.')
        else:
            lines.append('    Workspace access failed; the fixed reason below distinguishes file changes, access, initialization and other failures without assuming corruption.')
        facts = {key: latest[key] for key in ('database_health_status', 'database_health_reason', 'database_health_phase',
                 'sqlite_errorcode', 'sqlite_errorname', 'elapsed_seconds', 'timeout_seconds',
                 'database_worker_returncode', 'database_worker_signal') if key in latest}
        if facts:
            lines.append('    Result facts: ' + json.dumps(facts, sort_keys=True) + '.')
    if not databases:
        lines.append('  No reviewed database identity was retained on these access receipts; outcomes cannot be attributed per database from their absence.')
    lines.extend(['  These are timestamped observations. Healthy checks, normal contention and later access failures can coexist without a new corruption finding.', ''])
    return {'schema_version': 1, 'scope': 'bounded_log_observations_by_reviewed_database_identity',
            'records_examined': len(observed), 'records_without_database_identity': len(observed) - len(identified),
            'databases_available': len(groups), 'databases_retained': len(databases), 'database_limit': 12,
            'databases_limited': len(groups) > 12, 'databases': databases}, lines


def _access_restore_audit(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    observed = [row for row in rows if row.get('event') in _ACCESS_RESTORE_EVENTS]
    counts = Counter(row['event'] for row in observed)
    sessions = []
    lines = ['Sign-in and page restoration: account checks, password verification and page restoration are separate stages.']
    for scope in ('current', 'previous', 'launcher'):
        scoped = [row for row in observed if row.get('session_scope') == scope]
        if not scoped:
            continue
        latest_by_stage = {}
        for stage, events in (
                ('account_store', {event for event in _ACCESS_RESTORE_EVENTS if event.startswith('account_store_')}),
                ('login', {event for event in _ACCESS_RESTORE_EVENTS if event.startswith('login_')}),
                ('page_restore', {event for event in _ACCESS_RESTORE_EVENTS if event.startswith('page_')}
                                 | {'saved_tab_restore_failed', 'workspace_open_failed'}),
                ('history_lock', {'history_lock_busy'}),
                ('workspace_database', {'workspace_database_health_started', 'workspace_database_health_completed',
                                        'workspace_database_health_failed', 'workspace_database_store_reused', 'workspace_database_preparation_started'})):
            latest = next((row for row in reversed(scoped) if row['event'] in events), None)
            if latest:
                receipt = _access_restore_evidence(latest)
                latest_by_stage[stage] = receipt
                elapsed = receipt.get('elapsed_seconds', receipt.get('waited_seconds'))
                timing = f'; elapsed {elapsed:g}s' if elapsed is not None else ''
                lines.append(f'  {scope} session / {stage}: latest recorded {receipt["event"]} at {receipt["timestamp"]}{timing}.')
        accepted = [row for row in scoped if row['event'] == 'login_accepted']
        restore = latest_by_stage.get('page_restore', {})
        unfinished = bool(restore.get('event') in {'page_build_started', 'page_session_restore_started',
                                                  'page_workspace_restore_started'})
        if accepted and unfinished:
            lines.append(f'  {scope} session contains accepted credentials and an unfinished page-restore stage. Password verification passed; no later page completion is present in this examined tail. Browser-attempt identity is not recorded.')
        sessions.append({'session_scope': scope, 'records_examined': len(scoped),
                         'accepted_credentials_observed': bool(accepted),
                         'latest_page_restore_unfinished': unfinished,
                         'event_counts': dict(sorted(Counter(row['event'] for row in scoped).items())),
                         'latest_by_stage': latest_by_stage})
    if not observed:
        lines.append('  No reviewed sign-in or page-restore stage observations were found; older versions did not record every stage.')
    lines.extend([
        f'  Recorded login acceptances: {counts["login_accepted"]}; rejections: {counts["login_rejected"]}; '
        f'login timeouts: {counts["login_timed_out"]}; page builds: {counts["page_built"]}; history lock waits reaching their limit: {counts["history_lock_busy"]}.',
        f'  Runtime workspace-store reuse receipts: {counts["workspace_database_store_reused"]}; reuse is distinct from running another database integrity check.',
        '  A password acceptance does not establish that the page finished restoring. A history lock wait is separate from SQLite locking.',
        '  These process-session tails may contain several browser pages and sign-in attempts; their proximity does not establish a shared attempt or the cause of a hang.', ''])
    return {'scope': 'bounded_log_stage_observations', 'records_examined': len(observed),
            'event_counts': dict(sorted(counts.items())), 'sessions': sessions,
            'recent_events': [_access_restore_evidence(row) for row in observed[-120:]],
            'recent_event_limit': 120, 'recent_events_limited': len(observed) > 120}, lines


def _native_fault_audit(latest: Path, previous: Path | None) -> tuple[dict[str, Any], list[str]]:
    """Index fixed native-fault signatures from bounded existing captures only."""
    from itertools import islice
    from .logging import _read_snapshot_bytes
    from .native_faults import NATIVE_FAULT_SIGNALS, project_native_faults
    from .faults import validate_frames
    sources = [(latest / 'console-error.log', 'current')]
    if previous is not None:
        sources.append((previous / 'console-error.log', 'previous'))
    limited = False
    try:
        session_root = latest.parent / 'sessions'
        if session_root.is_symlink():
            raise OSError('unsafe diagnostic session root')
        sessions = list(islice(session_root.iterdir(), 257))
        limited = len(sessions) > 256
        sessions = sorted((path for path in sessions[:256] if not path.is_symlink() and path.is_dir()),
                          key=lambda path: path.lstat().st_mtime, reverse=True)
        limited |= len(sessions) > 20
        known = {path for path, _scope in sources}
        sources.extend((path / 'console-error.log', 'retained_session') for path in sessions[:20]
                       if path / 'console-error.log' not in known)
    except OSError:
        pass
    try:
        crash_root = latest.parent / 'crashes'
        if crash_root.is_symlink():
            raise OSError('unsafe diagnostic crash root')
        candidates = list(islice(crash_root.glob('*.log'), 257))
        limited |= len(candidates) > 256
        candidates = sorted(candidates[:256], key=lambda path: path.lstat().st_mtime, reverse=True)
        limited |= len(candidates) > 20
        sources.extend((path, 'retained_crash') for path in candidates[:20])
    except OSError:
        pass
    signatures: dict[str, dict[str, Any]] = {}
    sources_read = 0
    for path, scope in sources:
        payload = _read_snapshot_bytes(path, tail_bytes=512 * 1024)
        if payload is None:
            continue
        sources_read += 1
        faults = project_native_faults(payload)
        # Previously exported logs already contain the privacy-safe projection.
        for line in payload.decode('utf-8', errors='replace').splitlines()[-8192:]:
            try:
                value = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if isinstance(value, dict) and value.get('evidence_source') == 'native_fault':
                faults.append(value.get('native_fault'))
        for value in faults[:16]:
            if not isinstance(value, dict):
                continue
            kind = value.get('native_fault_class')
            if not isinstance(kind, str) or kind not in NATIVE_FAULT_SIGNALS or value.get('signal') != NATIVE_FAULT_SIGNALS[kind]:
                continue
            safe = {'native_fault_class': kind, 'signal': NATIVE_FAULT_SIGNALS[kind],
                    'frames': validate_frames(value.get('frames')),
                    'timestamp_status': 'not_in_native_fault_heading'}
            for key in ('observed_thread_count', 'observed_frame_count'):
                if type(value.get(key)) is int and 0 <= value[key] <= 8192:
                    safe[key] = value[key]
            safe['truncated'] = value.get('truncated') is True
            identity = hashlib.sha256(json.dumps(safe, sort_keys=True).encode()).hexdigest()[:24]
            if identity not in signatures:
                signatures[identity] = {**safe, 'signature_id': identity, 'source_scopes': [], 'source_count': 0}
            row = signatures[identity]
            row['source_count'] += 1
            if scope not in row['source_scopes']:
                row['source_scopes'].append(scope)
    rows = list(signatures.values())[-20:]
    lines = ['Native crash evidence: fixed CPython fatal-signal headings from current/previous and up to 20 retained session/crash tails.']
    for row in rows:
        lines.append(f'  Retained native signal {row["signal"]}; observed threads {row.get("observed_thread_count", "unrecorded")}; observed frames {row.get("observed_frame_count", "unrecorded")}; scopes ' + ', '.join(row['source_scopes']) + '.')
        useful_frames = [frame for frame in row['frames'] if frame.get('module', '').startswith('harnessy.')]
        for frame in (useful_frames or row['frames'])[:4]:
            if frame.get('module') != 'external':
                lines.append(f'    {frame["module"]}.{frame["function"]}:{frame["line"]}')
    if not rows:
        lines.append('  No fixed native fatal-signal heading was found in these bounded sources; this does not exclude a native crash.')
    lines.extend(['  Duplicate retained signatures are grouped; counts are not a total of crashes. Native headings carry no timestamp. A signal and sampled frame do not establish why the process crashed or why a database was corrupted.', ''])
    return {'scope': 'bounded_native_fault_captures', 'sources_attempted': len(sources),
            'sources_read': sources_read, 'source_limit_reached': limited,
            'unique_signatures_available': len(signatures), 'unique_signatures_retained': len(rows),
            'signature_limit': 20, 'signatures_limited': len(signatures) > 20, 'signatures': rows}, lines


def _retained_controller_rows(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reserve lifecycle terminal evidence while recent probes keep producing logs."""
    lifecycle = {'start', 'create', 'stop', 'delete', 'factory-reset', 'restart', 'prerequisite_check', 'package_manager'}
    terminal_events = {'environment_controller_finished', 'environment_controller_timed_out',
                       'environment_controller_cancelled', 'environment_controller_spawn_failed'}
    terminal = [row for row in observations
                if row.get('event') in terminal_events and row.get('controller_action') in lifecycle][-40:]
    latest: dict[tuple[Any, Any], dict[str, Any]] = {}
    for row in observations:
        latest[(row.get('session_scope'), row.get('command_id'))] = row
    active = [row for row in latest.values() if row.get('controller_action') in lifecycle
              and row.get('controller_state') == 'running'][-32:]
    recent = observations[-(120 - len(terminal) - len(active)):]
    retained = {id(row): row for row in terminal + active + recent}
    return sorted(retained.values(), key=lambda row: row.get('timestamp', ''))


def _controller_observation_audit(rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    observations = [row for row in rows if row.get('event') in CONTROLLER_OBSERVATION_EVENTS
                    and row.get('provider') in {'lima', 'host'} and isinstance(row.get('command_id'), str)]
    retained = _retained_controller_rows(observations)
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in retained:
        groups.setdefault((row['session_scope'], row['command_id']), []).append(row)
    ordered = sorted(groups.items(), key=lambda item: item[1][-1]['timestamp'], reverse=True)
    lifecycle = {'start', 'create', 'stop', 'delete', 'factory-reset', 'restart', 'prerequisite_check', 'package_manager'}
    active = [item for item in ordered if item[1][-1].get('controller_state') == 'running'
              and item[1][-1].get('controller_action') in lifecycle]
    selected = {key: values for key, values in active + ordered}
    selected_items = list(selected.items())[:16]
    commands: list[dict[str, Any]] = []
    lines = ['Lima controller and host prerequisite observations: process state and captured output are separate from guest readiness.']
    for (scope, command), items in selected_items:
        latest = items[-1]
        parent = next((row for row in reversed(items) if row['event'] in {
            'environment_command_parent_exited', 'environment_controller_parent_exited'}), None)
        handoff = next((row for row in reversed(items) if row['event'] in {
            'environment_command_output_handoff', 'environment_controller_output_handoff'}), None)
        terminal = next((row for row in reversed(rows)
                         if row.get('command_id') == command and row.get('session_scope') == scope
                         and row.get('event') in {'environment_command_finished', 'environment_command_timeout',
                             'environment_command_cancelled', 'environment_command_spawn_failed',
                             'environment_controller_finished', 'environment_controller_timed_out',
                             'environment_controller_cancelled', 'environment_controller_spawn_failed'}), None)
        commands.append({'command_id': command, 'session_scope': scope,
                         'latest_observation': _evidence(latest),
                         'parent_exit': _evidence(parent) if parent else None,
                         'output_handoff': _evidence(handoff) if handoff else None,
                         'terminal_receipt_recorded': terminal is not None,
                         'terminal_receipt': _evidence(terminal) if terminal else None})
        action = latest.get('controller_action', 'unknown')
        ident = latest.get('environment_id', latest.get('target_id', ''))
        owner = f' VM {ident[:12]}' if isinstance(ident, str) and ident else ''
        elapsed = latest.get('elapsed_seconds')
        duration = f' after {elapsed:g}s' if type(elapsed) in {int, float} else ''
        kind = 'host command' if latest.get('provider') == 'host' else 'controller'
        lines.append(f'  {latest["timestamp"]} [{scope}]{owner}: {action} {kind} state was {latest.get("controller_state", "unrecorded")}{duration}; phase {latest.get("completion_phase", "unrecorded")}.')
        if parent:
            lines.append(f'    The spawned controller exited with return code {parent.get("controller_returncode", "unrecorded")}; this records the parent, not descendant completion.')
        facts = {key: latest[key] for key in ('controller_program', 'controller_pid', 'stdout_bytes', 'stderr_bytes',
                 'last_output_age_seconds', 'timeout_seconds', 'pending_progress',
                 'controller_activity', 'controller_signals') if key in latest}
        if facts:
            lines.append('    Recorded capture facts: ' + json.dumps(facts, sort_keys=True) + '.')
        if latest.get('output_capture') == 'inherited_terminal':
            lines.append('    This interactive host command inherited its terminal. Output counts and output age are unobserved, not zero; it may be waiting for terminal input.')
        elif latest.get('output_capture') == 'merged_pipe':
            lines.append('    Captured output bytes combine stdout and stderr; separate stderr bytes were not measured.')
        if latest.get('controller_state') == 'running':
            if latest.get('stdout_bytes') == 0 and latest.get('stderr_bytes') == 0:
                lines.append('    No controller output had been observed at this heartbeat. A living controller can still be waiting; silence does not establish a stall.')
            else:
                lines.append('    Output counts and time since the last output describe controller activity, not verified download progress or guest readiness.')
        if terminal:
            event = terminal['event']
            if event.endswith('timed_out') or event == 'environment_command_timeout':
                lines.append('    The controller command reached its timeout; its final output counts were retained after owned-process cleanup.')
            elif event.endswith('cancelled'):
                lines.append('    The controller command was cancelled; this is separate from an unexpected failure.')
            elif event.endswith('spawn_failed'):
                lines.append('    The controller could not be spawned; guest setup was not verified.')
            else:
                code = terminal.get('controller_returncode', terminal.get('returncode'))
                lines.append(f'    A terminal controller receipt was recorded with return code {code if type(code) is int else "unrecorded"}.')
        else:
            lines.append('    No terminal controller receipt was retained for this command; its final result is not established by this observation.')
        if handoff and handoff.get('post_exit_output_not_collected') is True:
            lines.append('    Anonymous output files were snapshotted for the direct controller lifetime; later descendant output is not collected. No pipe-EOF or descendant-exit claim is made.')
    if not retained:
        lines.append('  No parent-exit, heartbeat or capture-handoff receipts were recorded in the examined logs; native-controller versus output-collection waits cannot be distinguished from their absence.')
    lines.append('  These are timestamped observations, not current liveness probes. Parsed output categories contain no excerpts and do not establish Environment Ready.')
    lines.append('')
    return {'scope': 'bounded_controller_observations', 'records_available': len(observations),
            'records_retained': len(retained), 'record_limit': 120,
            'record_limit_reached': len(observations) > len(retained),
            'command_limit': 16, 'commands_limited': len(groups) > len(selected_items),
            'commands': commands, 'recent_receipts': [_evidence(row) for row in retained]}, lines


_KVM_SETUP_DESCRIPTIONS = {
    'KVM_NOT_REQUIRED': 'KVM setup was not required on this host.',
    'KVM_DEVICE_ABSENT': 'The KVM device was absent; group repair was not applicable.',
    'KVM_READY': 'The launch verified usable KVM access.',
    'KVM_GROUP_REFRESH_VERIFIED': 'The refreshed launch verified usable KVM access.',
    'KVM_IDENTITY_UNSAFE': 'Automatic setup stopped because the launch identity was unsafe.',
    'KVM_DEVICE_UNAVAILABLE': 'The KVM device could not be safely inspected.',
    'KVM_ACCOUNT_UNAVAILABLE': 'The account could not be resolved for automatic setup.',
    'KVM_DEVICE_GROUP_UNAVAILABLE': 'The KVM device owning group could not be resolved.',
    'KVM_MEMBERSHIP_UNAVAILABLE': 'Saved group membership could not be inspected.',
    'KVM_NONINTERACTIVE': 'Privileged setup could not prompt in this noninteractive launch.',
    'KVM_ACTIVE_GROUP_DENIED': 'The device group was active, but KVM access was still denied; inspect device ACL/container policy.',
    'KVM_TOOLS_UNAVAILABLE': 'A required setup or group-refresh tool was unavailable.',
    'KVM_SUDO_UNAVAILABLE': 'sudo was unavailable for privileged group setup.',
    'KVM_GROUP_REFRESH_UNAVAILABLE': 'The group-refresh tool was unavailable.',
    'KVM_SUDO_DENIED': 'sudo did not authorize the group setup.',
    'KVM_SETUP_CANCELLED': 'KVM setup was cancelled.',
    'KVM_SETUP_TIMEOUT': 'The bounded KVM setup operation timed out.',
    'KVM_SETUP_FAILED': 'KVM setup did not complete.',
    'KVM_RELAUNCH_FAILED': 'The requested group-refresh relaunch failed.',
    'KVM_IDENTITY_CHANGED': 'The refreshed launch changed the user identity; setup stopped.',
    'KVM_MEMBERSHIP_NOT_UPDATED': 'The requested saved group membership was not verified.',
    'KVM_GROUP_REFRESH_REQUIRED': 'Saved membership was present; a launch with refreshed groups was requested.',
    'KVM_GROUP_ADDED_REFRESH_REQUIRED': 'Saved group membership was added; a launch with refreshed groups was requested.',
    'KVM_REFRESH_RETRY_STOPPED': 'KVM remained inaccessible after the refresh attempt; automatic retries stopped.',
}


def _kvm_setup_lines(receipt: dict[str, Any]) -> list[str]:
    state, reason = receipt.get('status', 'unrecorded'), receipt.get('reason_code', 'unrecorded')
    lines = [f'KVM startup setup {receipt["timestamp"]} [{receipt["session_scope"]}]: {state} / {reason}.']
    if reason in _KVM_SETUP_DESCRIPTIONS:
        lines.append(_KVM_SETUP_DESCRIPTIONS[reason])
    facts = {key: receipt[key] for key in ('device_gid', 'kvm_present', 'kvm_accessible',
             'device_group_active', 'saved_member', 'membership_changed', 'refresh_attempted') if key in receipt}
    if facts:
        lines.append('Recorded setup facts: ' + json.dumps(facts, sort_keys=True) + '.')
    return lines


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
    kvm_checks = [row for row in receipts if row['event'] == 'launcher_kvm_setup']
    host_checks = [row for row in receipts if row['event'] == 'host_prerequisite_setup']
    latest_host_checks = {}
    for row in host_checks:
        latest_host_checks[(row['scope'], row['architecture'])] = row
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
        'kvm_setup_records': len(kvm_checks),
        'kvm_setup_reason_counts': dict(Counter(row['reason_code'] for row in kvm_checks if 'reason_code' in row)),
        'latest_kvm_setup': kvm_checks[-1] if kvm_checks else None,
        'host_prerequisite_records': len(host_checks),
        'host_prerequisite_status_counts': dict(Counter(row['status'] for row in host_checks)),
        'host_prerequisite_error_counts': dict(Counter(row['error_code'] for row in host_checks if 'error_code' in row)),
        'latest_host_prerequisite_setup': host_checks[-1] if host_checks else None,
        'latest_host_prerequisite_checks': sorted(latest_host_checks.values(), key=lambda row: row['timestamp']),
        'recent_receipts': receipts[-120:],
        'counts_are_retained_records': True,
    }
    lines = ['Startup evidence: STARTUP.json retains host prerequisite checks, launcher updates and KVM setup receipts, plus historical host REA setup receipts. REA now runs as a workspace VM tool.']
    if not receipts:
        lines.append('  No startup receipts were recorded in the examined logs; host prerequisite, updater, KVM setup and REA setup decisions cannot be reconstructed.')
    else:
        lines.append(f'  Host prerequisite records: {len(host_checks)}. Counts are retained checks and installation stages, not package transactions.')
        if not host_checks:
            lines.append('  No host prerequisite receipts were recorded; missing tools and automatic installation outcomes cannot be reconstructed.')
        for row in audit['latest_host_prerequisite_checks']:
            lines.append(f'  {row["timestamp"]} [{row["session_scope"]}] {row["scope"]} / {row["architecture"]}: {row["status"]}; failure code: {row.get("error_code", "none_recorded")}.')
            if 'missing_binaries' in row:
                lines.append('    Missing host tools: ' + (', '.join(row['missing_binaries']) or 'none recorded') + '.')
            if 'broken_binaries' in row:
                lines.append('    Host tools that failed verification: ' + (', '.join(row['broken_binaries']) or 'none recorded') + '.')
            if 'manager' in row:
                lines.append('    Package manager: ' + row['manager'] + '; packages: ' + (', '.join(row.get('packages', [])) or 'none recorded') + '.')
            if 'returncode' in row:
                lines.append(f'    Recorded package-manager return code: {row["returncode"]}.')
            if 'checks_failed' in row:
                lines.append(f'    Failed launcher checks: {row["checks_failed"]}.')
            if row['status'] in {'failed', 'action_required'}:
                lines.extend(_host_prerequisite_failure_lines(row))
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
        lines.append(f'  KVM setup records: {len(kvm_checks)}. Counts are retained receipts, not setup attempts or password prompts.')
        for row in kvm_checks[-4:]:
            lines.extend('  ' + value for value in _kvm_setup_lines(row))
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
    blocked_action_ids: set[tuple[Any, ...]] = set()
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
        if reason == 'blocked_target_action':
            blocked_action_ids.add(key)
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
        if row.get('error_code') in {'TARGET_POLICY', 'PERMISSION_POLICY_UNAVAILABLE', 'TARGET_ACTION_OFF'}:
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
        'target_actions_blocked': len(blocked_action_ids) if decisions else None,
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
    if blocked_action_ids:
        lines.append(f'  Target calls blocked by selected action permissions: {len(blocked_action_ids)}. The required action was Off; this does not indicate a denied approval dialog.')
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
            if isinstance(evidence, dict):
                from .technical import validate_technical_evidence
                facts = validate_technical_evidence(evidence)
                if facts.get('reason_codes'):
                    lines.append('    Recorded source reason codes: ' + json.dumps(facts['reason_codes']) + '.')
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
                          target_report: dict[str, Any] | None = None,
                          host_report: dict[str, Any] | None = None) -> tuple[dict[str, Any], str]:
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
    safe_vm_report, vm_lines = _vm_log_coverage(vm_report)
    host_kvm_facts = _host_kvm_facts(host_report)
    observation_keys = {(row.get('session_scope'), row.get('command_id')) for row in rows
                        if row.get('event') == 'vm_startup_observation' and isinstance(row.get('command_id'), str)
                        and _vm_failure_classification(row)}
    failures = [row for row in rows if (row.get('event') in _ERROR_EVENTS or _vm_failure_classification(row)
                                       or _target_failure_classification(row) or _permission_failure_classification(row)
                                       or _startup_failure_classification(row) or _is_lock(row)
                                       or row.get('event') in _ACCESS_RESTORE_FAILURES or _recovery_failure_classification(row))
                and not (row.get('event') in {'environment_command_finished', 'environment_command_timeout'}
                         and isinstance(row.get('command_id'), str)
                         and (row.get('session_scope'), row.get('command_id')) in observation_keys)]
    incidents: list[dict[str, Any]] = []
    for failure in failures[-_MAX_INCIDENTS:]:
        before = [row for row in rows if row['session_scope'] == failure['session_scope']
                  and 0 <= _seconds(failure['timestamp'], row['timestamp']) <= _CONTEXT_SECONDS]
        related = [row for row in before if _same_scope(row, failure)]
        database_classification = (_database_condition(failure) or _workspace_database_classification(failure)
                                   or _recovery_failure_classification(failure))
        lock = _is_lock(failure) and database_classification is None
        vm_classification = _vm_failure_classification(failure)
        target_classification = _target_failure_classification(failure)
        permission_classification = _permission_failure_classification(failure)
        startup_classification = _startup_failure_classification(failure)
        windows_media_classification = _windows_media_failure_classification(failure)
        timeout_classification = _timeout_failure_classification(failure)
        terminal_classification = _terminal_failure_classification(failure)
        access_restore_classification = _ACCESS_RESTORE_FAILURES.get(failure.get('event'))
        vm_cause = _kvm_permission_cause(failure, rows, safe_vm_report, host_kvm_facts)
        if vm_cause:
            vm_classification = 'vm_host_kvm_access_denied'
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
                                                       'vm_startup_post_failure_state'} | CONTROLLER_OBSERVATION_EVENTS]
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
        if not vm_classification and not target_classification and not permission_classification and not startup_classification and not windows_media_classification and not timeout_classification and not access_restore_classification and terminal_classification in {None, 'workspace_terminal_start_failed'} and not _has_frames(failure) and not any(_has_frames(row) for row in database_errors):
            missing.append('exception_traceback_unavailable')
        if vm_classification and not vm_cause and not any(
                row.get('event') in CONTROLLER_OBSERVATION_EVENTS or
                isinstance(row.get('controller_evidence'), dict) and any(
                    isinstance(value, dict) and value.get('reason_codes') for value in row['controller_evidence'].values())
                for row in controller_evidence):
            missing.append('controller_activity_observation_not_recorded')
        if target_analysis and target_analysis['launch_wait'] == 'timeout':
            if target_analysis['launcher_returncode'] is None:
                missing.append('target_launcher_exit_status_not_recorded')
            if failure.get('target_stage') == 'launch':
                missing.append('target_launch_reconciliation_not_recorded')
        if lock and not database_errors:
            missing.append('database_operation_not_recorded')
        if lock:
            missing.append('lock_holder_not_identified')
        if timeout_classification == 'environment_timeout_unscoped':
            missing.append('timeout_scope_not_recorded')
        identity = json.dumps(_evidence(failure), sort_keys=True)
        incidents.append({
            'incident_id': hashlib.sha256(identity.encode()).hexdigest()[:24],
            'classification': database_classification or access_restore_classification or ('sqlite_lock_contention' if lock else startup_classification or windows_media_classification or permission_classification or target_classification or vm_classification or timeout_classification or terminal_classification or 'operation_error'),
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
            'vm_cause': vm_cause,
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
        'database_errors': sum(row.get('event') == 'sqlite_operation_error' or _is_lock(row) or bool(_database_condition(row)) for row in rows),
        'database_operation_errors': counts['sqlite_operation_error'],
        'workspace_database_health_failures': counts['workspace_database_health_failed'],
        'workspace_terminal_start_failures': counts['workspace_terminal_start_failed'],
        'project_sync_limit_failures': sum(_terminal_failure_classification(row) in {
            'project_sync_byte_limit', 'project_sync_entry_limit', 'project_sync_limit_exceeded'} for row in rows),
        'database_corruption_observations': sum(_database_condition(row) == 'sqlite_database_corruption' for row in rows),
        'database_not_database_observations': sum(_database_condition(row) == 'sqlite_not_a_database' for row in rows),
        'incidents': incidents,
    }
    permission_audit, permission_lines = _permission_audit(rows)
    index['permission_audit'] = permission_audit
    startup_audit, startup_lines = _startup_audit(rows)
    index['startup_audit'] = startup_audit
    browser_audit, browser_lines = _windows_media_browser_audit(rows)
    index['windows_media_browser_observations'] = browser_audit
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
    permission_acknowledgement_audit, permission_acknowledgement_lines = build_permission_acknowledgement_audit(rows)
    index['permission_acknowledgement_audit'] = permission_acknowledgement_audit
    controller_audit, controller_lines = _controller_observation_audit(rows)
    index['controller_observation_audit'] = controller_audit
    from .queue_observations import QUEUE_EVENTS, build_queue_audit
    queue_audit, queue_lines = build_queue_audit(rows)
    index['queue_audit'] = queue_audit
    access_restore_audit, access_restore_lines = _access_restore_audit(rows)
    index['access_restore_audit'] = access_restore_audit
    database_access_audit, database_access_lines = _workspace_database_access_audit(rows)
    index['workspace_database_access'] = database_access_audit
    recovery_audit, recovery_lines = _workspace_recovery_audit(rows)
    index['workspace_database_recovery'] = recovery_audit
    native_audit, native_lines = _native_fault_audit(Path(latest), previous)
    index['native_fault_audit'] = native_audit
    collector_pid = host_report.get('process', {}).get('pid') if isinstance(host_report, dict) else None
    app_pid = session.get('pid') if isinstance(session, dict) else None
    collector_pid = collector_pid if type(collector_pid) is int and 0 < collector_pid < 2**31 else None
    app_pid = app_pid if type(app_pid) is int and 0 < app_pid < 2**31 else None
    process_relation = ('same_process' if collector_pid == app_pid else 'different_process') if collector_pid and app_pid else 'unrecorded'
    index['host_capture_scope'] = {'collector_pid': collector_pid, 'session_app_pid': app_pid,
                                   'process_relationship': process_relation,
                                   'process_metrics_scope': 'collecting_process_only'}
    host_lines = ['Host capture: HOST_STATE.json process metrics describe the diagnostics collecting process.']
    if process_relation == 'different_process':
        host_lines.append(f'  Collector PID {collector_pid} differs from recorded application PID {app_pid}; collector CPU/RAM/thread metrics are not the application metrics.')
    host_lines.extend(['  Dependency versions describe installed distribution metadata; they do not prove which dependency versions the live application has imported.', ''])
    database_lines = []
    if index['database_corruption_observations']:
        database_lines = [f'Recorded database corruption: {index["database_corruption_observations"]} SQLite SQLITE_CORRUPT observations. SQLite reported database corruption, not an ordinary busy/locked database.',
                          '  Retain the database and its journal/WAL files. These receipts do not establish what originally caused the corruption; recreating the workspace VM cannot repair the host workspace database.', '']
    elif index['database_not_database_observations']:
        database_lines = ['SQLite reported SQLITE_NOTADB: the opened bytes were not a valid SQLite database. This is separate from an ordinary busy/locked database.', '']
    latest_health_failure = next((row for row in reversed(rows) if row.get('event') == 'workspace_database_health_failed'), None)
    if latest_health_failure and _workspace_database_classification(latest_health_failure) == 'workspace_database_history_busy':
        database_lines = ['Workspace restoration: the latest isolated initialization reported a busy history lock. This is separate from SQLite corruption and does not establish disk or database-file unavailability.', ''] + database_lines
    control_rows = [row for row in rows if row.get('level') in {'WARNING', 'ERROR', 'CRITICAL'}
                    or str(row.get('event')).startswith(('vm_', 'environment_', 'workspace_mapping_', 'test_target_'))
                    or row.get('event') in STARTUP_EVENTS
                    or row.get('event') == WINDOWS_MEDIA_BROWSER_EVENT
                    or row.get('event') in QUEUE_EVENTS
                    or row.get('event') in _ACCESS_RESTORE_EVENTS or row.get('event') in _WORKSPACE_RECOVERY_EVENTS
                    or row.get('event') in {'headless_run_error', 'agent_run_error', 'run_blocked_by_infrastructure'}]
    index['control_plane_timeline'] = [(_access_restore_evidence(row) if row.get('event') in _ACCESS_RESTORE_EVENTS else row)
                                       for row in control_rows[-1200:]]
    index['control_plane_coverage'] = {'rows_available': len(control_rows), 'rows_retained': min(len(control_rows), 1200),
        'row_limit': 1200, 'row_limit_reached': len(control_rows) > 1200, 'source_coverage': coverage}
    latest_vm = next((item for item in reversed(incidents) if item['classification'].startswith('vm_')), None)
    latest_kvm_setup = startup_audit.get('latest_kvm_setup')
    setup_verified_after_failure = bool(latest_vm and latest_kvm_setup
        and latest_kvm_setup.get('status') == 'ready' and latest_kvm_setup.get('kvm_accessible') is True
        and latest_kvm_setup.get('reason_code') in {'KVM_READY', 'KVM_GROUP_REFRESH_VERIFIED'}
        and latest_kvm_setup['timestamp'] >= latest_vm['failure']['timestamp'])
    primary_cause = (_kvm_cause_lines(latest_vm['vm_cause']) + ['']
                     if latest_vm and latest_vm.get('vm_cause') and not setup_verified_after_failure else [])
    primary_setup = _kvm_setup_lines(latest_kvm_setup) + [''] if latest_kvm_setup else []
    if setup_verified_after_failure and latest_vm.get('vm_cause'):
        primary_setup.insert(-1, 'Earlier recorded KVM-denied VM attempts predate this verified setup check; VM boot readiness is a separate check.')
    lines = [
        'HarnessyXO support summary', '==========================', '',
        'Start here; machine-readable evidence is in INCIDENTS.json.',
        f'Session application version: {version}; capture time: {metadata.get("captured_at", "unrecorded")}.',
        'This summary examines bounded current/previous-session log tails and startup receipts from up to two recent launcher sessions. Counts are not whole-session totals.',
        'Nearby events and tracked transactions are evidence for investigation, not proven lock ownership.', '',
        *primary_setup, *primary_cause,
        *database_access_lines, *recovery_lines, *database_lines, *access_restore_lines, *native_lines, *host_lines,
        *queue_lines,
        *model_lines,
        *permission_acknowledgement_lines,
        *controller_lines,
        *browser_lines,
        f'Recorded failures in examined logs: {len(failures)} (latest {len(incidents)} shown)',
        f'Workspace terminal start failures: {index["workspace_terminal_start_failures"]}; project synchronization limit observations: {index["project_sync_limit_failures"]}.',
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
        for key in ('run_id', 'call_id', 'workspace_id', 'chat_id', 'environment_id'):
            if failure.get(key):
                lines.append(f'  {key}: {failure[key]}')
        classification = incident['classification']
        if classification.startswith('windows_media_'):
            lines.extend(_windows_media_failure_lines(failure))
        if failure.get('event') == 'workspace_terminal_start_failed':
            descriptions = {
                'project_sync_byte_limit': 'Project synchronization reached its byte limit before the terminal opened.',
                'project_sync_entry_limit': 'Project synchronization reached its entry limit before the terminal opened.',
                'project_sync_limit_exceeded': 'Project synchronization reached its byte or entry limit; this older message does not distinguish which.',
                'workspace_terminal_start_failed': 'Workspace terminal setup failed; no reviewed fixed cause was recorded.',
            }
            lines.append('  ' + descriptions.get(classification, descriptions['workspace_terminal_start_failed']))
            if failure.get('terminal_mode'):
                lines.append('  terminal_mode: ' + failure['terminal_mode'])
            if failure.get('terminal_failure_basis') == 'fixed_message_fingerprint':
                lines.append('  Cause inferred from a known fixed-message fingerprint and matching character count; error plaintext was not captured.')
        if classification.startswith('workspace_recovery_'):
            lines.append('  Database recovery reported this outcome; private-copy checking, candidate creation, activation and rollback are distinct stages.')
            for key in ('recovery_stage', 'recovery_status', 'recovery_failure_code', 'elapsed_seconds',
                        'database_worker_returncode', 'database_worker_signal'):
                if key in failure:
                    lines.append(f'  {key}: {failure[key]}')
        elif classification.startswith('workspace_database_'):
            descriptions = {
                'workspace_database_corruption': 'The isolated workspace database health check reported corruption. Existing database files are preserved; the original cause of corruption is not established.',
                'workspace_database_health_timeout': 'The isolated database health or initialization worker reached its deadline; this does not establish that the database is corrupt.',
                'workspace_database_worker_failed': 'The isolated database worker failed or exited. The application stayed outside that native worker; this status alone does not establish database corruption.',
                'workspace_database_busy': 'SQLite reported a busy or locked workspace database. This is contention, not verified corruption; wait for active work to finish and retry. The receipts do not identify the lock holder.',
                'workspace_database_history_busy': 'The isolated workspace initialization reported a busy history lock. This is separate from SQLite corruption and does not establish that the disk or database file is unavailable.',
                'workspace_database_unavailable': 'The workspace database could not be admitted or initialized. The fixed reason below distinguishes invalid input, access, and changed-file observations.',
            }
            lines.append('  ' + descriptions.get(classification, 'Workspace database health checking did not complete.'))
            for key in ('database_health_status', 'database_health_reason', 'database_health_phase',
                        'database_worker_returncode', 'database_worker_signal', 'sqlite_errorcode', 'sqlite_errorname'):
                if key in failure:
                    lines.append(f'  {key}: {failure[key]}')
        elif classification == 'sqlite_database_corruption':
            lines.append('  SQLite reported SQLITE_CORRUPT (base result code 11). This is database corruption, not ordinary lock contention; its original cause is not established.')
        elif classification == 'sqlite_not_a_database':
            lines.append('  SQLite reported SQLITE_NOTADB (base result code 26). The opened bytes were not recognized as a valid SQLite database.')
        elif classification == 'history_lock_contention':
            lines.append('  The history thread/process lock wait reached its configured limit; this is separate from SQLite locking and does not identify its holder.')
            for key in ('lock_kind', 'waited_seconds', 'lock_timeout_seconds'):
                if key in failure:
                    lines.append(f'  {key}: {failure[key]}')
        elif classification.startswith('account_store_'):
            lines.append('  The account-file check did not complete successfully; password verification and page restoration are separate stages.')
        elif classification in {'login_busy', 'login_timed_out', 'login_failed'}:
            lines.append('  Password verification could not complete; this does not establish that the supplied password was rejected.')
        elif classification in {'saved_tab_restore_failed', 'workspace_open_failed'}:
            lines.append('  Page restoration reported this failure; it is separate from password verification.')
            if failure.get('error_class'):
                lines.append('  Exception class: ' + failure['error_class'] + '.')
        if classification in {'environment_host_prerequisite_failed', 'host_prerequisite_setup_failed',
                              'host_prerequisite_action_required'}:
            lines.extend(_host_prerequisite_failure_lines(failure))
        if classification == 'environment_provider_timeout':
            lines.append('  A provider/controller phase raised TimeoutError before the operation deadline was reached; this is not a recorded expiration of the overall operation budget.')
        elif classification == 'environment_operation_deadline':
            lines.append('  The registry reached the overall operation deadline.')
        elif classification == 'environment_timeout_unscoped':
            lines.append('  A timeout was recorded, but these older or incomplete receipts do not distinguish a provider timeout from the overall operation deadline.')
        if classification in {'environment_provider_timeout', 'environment_operation_deadline', 'environment_timeout_unscoped'}:
            if failure.get('failed_stage'):
                lines.append('  Originating stage: ' + failure['failed_stage'] + '.')
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
            if classification == 'vm_host_kvm_access_denied' and incident.get('vm_cause'):
                lines.extend('  ' + value for value in _kvm_cause_lines(incident['vm_cause']))
            elif classification == 'vm_controller_timeout':
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
                if isinstance(stderr, dict) and stderr.get('reason_codes'):
                    from .technical import validate_technical_evidence
                    facts = validate_technical_evidence(stderr)
                    lines.append('  Controller stderr reason codes: ' + json.dumps(facts.get('reason_codes', [])) + '.')
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
