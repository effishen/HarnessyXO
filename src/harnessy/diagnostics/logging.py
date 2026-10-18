from __future__ import annotations

import atexit
import builtins
import json
import logging
import math
import os
import platform
import re
import shlex
import hashlib
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import traceback
import uuid
import zipfile
from collections import deque
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

_LOG_NAMES = ('harnessy', 'backend', 'tools', 'runtime', 'system', 'context_tuning', 'database', 'targets')
_MAX_LOG_BYTES = 25 * 1024 * 1024
_BACKUPS = 2
_SESSION_KEEP = 20
_TOTAL_SESSION_CAP_BYTES = 750 * 1024 * 1024
_STREAM_TAIL_MAX_EVENTS = 2500
_STREAM_TAIL_MAX_CHARS = 2_000_000
_PREVIOUS_SESSION_LOG_TAIL_BYTES = 512 * 1024
# A compact, content-free ledger has independent retention. Large runtime/tool
# payloads and pruning historical session directories cannot evict this history.
_CONTEXT_LOG_MAX_BYTES = 1024 * 1024
_CONTEXT_LOG_BACKUPS = 7
_CONTEXT_HISTORY_MAX_BYTES = 2 * 1024 * 1024
_CONTEXT_HISTORY_BACKUPS = 15
# Database instrumentation is a separate bounded, content-free channel.
_DATABASE_LOG_MAX_BYTES = 2 * 1024 * 1024
_DATABASE_LOG_BACKUPS = 3
_TARGET_LOG_MAX_BYTES = 1024 * 1024
_TARGET_LOG_BACKUPS = 3
_TARGET_VIEW_CAPABILITY = re.compile(
    # Read sizes are bounded by the exporter. Disjoint escape/plain branches
    # consume the complete URI tail in linear time, while preserving enclosing
    # unescaped JSON/log quotes and whitespace. Guest paths and queries can
    # themselves contain LuCI session tokens or passwords.
    rb'((?:\\*/|%2f)api(?:\\*/|%2f)harnessy(?:\\*/|%2f)target-view(?:\\*/|%2f))[0-9a-f]{64}(?:\\[^\r\n]|[^\s\x22\x27<>\\])*',
    re.IGNORECASE,
)


class _DiagnosticsZipFile(zipfile.ZipFile):
    """A target-view URL is a credential in every diagnostics export mode."""
    def writestr(self, zinfo_or_arcname, data, compress_type=None, compresslevel=None):
        encoded = data.encode('utf-8') if isinstance(data, str) else data
        if isinstance(encoded, (bytes, bytearray)):
            data = _TARGET_VIEW_CAPABILITY.sub(lambda match: match.group(1) + b'<redacted>', encoded)
        return super().writestr(zinfo_or_arcname, data, compress_type=compress_type, compresslevel=compresslevel)

    def read_log(self, source, member, *, tail_bytes=None):
        from .operational import ExportCoverage
        if not hasattr(self, 'source_coverage'):
            self.source_coverage = ExportCoverage()
        return self.source_coverage.read(source, member, _read_snapshot_bytes, tail_bytes)

    def write_log(self, member, payload, row, projection):
        from .operational import ExportCoverage, APP_FILE_TAIL_BYTES, APP_TOTAL_READ_BYTES
        payload = _TARGET_VIEW_CAPABILITY.sub(lambda match: match.group(1) + b'<redacted>', payload)
        used = sum(item['exported_bytes'] for item in self.source_coverage.sources)
        cap = max(0, min(APP_FILE_TAIL_BYTES, APP_TOTAL_READ_BYTES - used))
        if len(payload) > cap:
            payload = payload[-cap:].partition(b'\n')[2] if cap else b''
            if row is not None:
                row['export_truncated'] = True
        self.writestr(member, payload)
        ExportCoverage.written(row, payload, projection)
_FILE_OPERATION_TIMELINE_MAX_EVENTS = 1000
_FILE_OPERATION_TIMELINE_LOG_TAIL_BYTES = 8 * 1024 * 1024
_PRIVACY_SAFE_BUNDLE = 'HarnessyXO-Diagnostics-Latest.zip'
_FULL_CONTENT_BUNDLE = 'HarnessyXO-Diagnostics-Latest-Including-Content.zip'


def _trusted_controller_event(value: Any) -> bool:
    return (isinstance(value, dict)
        and value.get('event') in {'environment_command_finished', 'environment_command_timeout',
            'environment_command_cancelled', 'vm_startup_observation', 'environment_command_spawn_failed'}
        and value.get('provider') == 'lima'
        and value.get('controller_action') in {'start', 'create', 'stop', 'delete', 'factory-reset', 'restart'}
        and isinstance(value.get('command_id'), str)
        and re.fullmatch(r'[0-9a-f]{32}', value['command_id']) is not None)


def _controller_evidence(value: Any, *, trusted: bool = False) -> dict[str, Any]:
    from .technical import validate_technical_evidence
    return {name: validate_technical_evidence(value[name],
                trusted_source='controller_' + name if trusted else None)
            for name in ('stderr', 'stdout') if isinstance(value, dict) and isinstance(value.get(name), dict)}

_CONTEXT_TUNING_EVENTS = frozenset({
    'request_prepared', 'request_succeeded', 'recovery_retry', 'recovery_exhausted',
    'probe_scheduled', 'probe_started', 'probe_failed', 'policy_reset',
    'run_started', 'run_finished', 'context_rebuilt',
})
_CONTEXT_TUNING_NUMBERS = frozenset({
    'step', 'request_sequence', 'request_attempt', 'configured_context_ceiling',
    'effective_context_ceiling', 'runtime_context_ceiling', 'estimated_input_tokens',
    'fixed_input_tokens_estimated', 'history_tokens_estimated', 'history_target',
    'actual_prompt_tokens', 'previous_actual_prompt_tokens', 'reported_prompt_tokens',
    'reported_context_tokens', 'estimated_bytes', 'limit_bytes', 'recovery_attempt',
    'recovery_limit', 'recovery_count', 'probe_count', 'probe_failures',
    'epoch_rebuild_count', 'context_epoch', 'before_input_tokens_estimated',
    'after_input_tokens_estimated', 'before_history_tokens_estimated',
    'after_history_tokens_estimated', 'accepted_history_target', 'next_probe_target',
    'probe_cooldown', 'recovery_decrement_tokens', 'reserved_output_tokens',
    'safety_margin_tokens', 'input_budget_tokens', 'request_token_limit',
    'successful_requests', 'consecutive_successes', 'known_good_history_tokens',
    'known_bad_history_tokens', 'last_actual_prompt_tokens', 'last_estimated_input_tokens',
    'actual_usage_step', 'recovery_attempts_total', 'probe_attempts_total',
    'probe_failures_total', 'epoch_rebuilds_total', 'downward_retries', 'upward_probes',
    'history_target_before', 'history_target_after', 'memory_wait_count',
    'output_reserve_tokens', 'request_limit_tokens', 'epoch_runway_tokens',
    'epoch_transition_count', 'schema_version',
    'selected_history_ceiling', 'requested_history_target', 'failed_upward_probes',
})
_CONTEXT_TUNING_BOOLEANS = frozenset({
    'usage_estimated', 'actual_prompt_tokens_estimated', 'probe_active',
    'budget_changed', 'partial_output_seen', 'minimum_preserved',
})
_CONTEXT_TUNING_ENUMS = {
    'actual_prompt_tokens_source': frozenset({
        'backend_usage', 'backend_timings', 'backend_error', 'estimated', 'unavailable',
    }),
    'provider': frozenset({'openai', 'omlx', 'oMLX', 'ollama', 'llamacpp', 'llama.cpp', 'lmstudio', 'lm_studio', 'generic'}),
    'outcome': frozenset({
        'prepared', 'succeeded', 'retry', 'exhausted', 'scheduled', 'started', 'failed',
        'reset', 'finished', 'stopped', 'completed', 'aborted', 'cancelled',
    }),
    'error_code': frozenset({
        'prefill_memory_exceeded', 'context_length_exceeded', 'model_memory_exceeded',
        'memory_pressure', 'model_load_memory_exceeded', 'backend_hang', 'retry_limit',
        'minimum_preserved', 'partial_output', 'context_window_exceeded',
    }),
    'tuning_method': frozenset({
        'memory_ratio', 'memory_slope', 'context_ratio', 'reported_context',
        'progressive', 'progressive_known_good', 'gradual', 'gradual_memory_ratio',
        'gradual_context_ratio', 'fallback_step', 'bounded_step',
    }),
    'context_mode': frozenset({
        'auto', 'maximum', 'custom', 'small', 'medium', 'large',
        '48k', '64k', '80k', '96k', '120k', '128k', '160k', '192k',
    }),
    'context_source': frozenset({
        'observed_runtime', 'profile_cap_runtime_unobserved',
        'unknown_runtime_and_profile', 'native_startup_ceiling_runtime_unobserved',
    }),
    'context_window_source': frozenset({'runtime', 'safe_fallback'}),
    'reason': frozenset({
        'initial', 'run_started', 'run_finished', 'prefill_memory_tuning',
        'auto_context_probe', 'auto_context_probe_failed', 'epoch_budget_exceeded',
        'context_budget_exceeded', 'live_context_setting_changed', 'user_stopped',
        'retry_limit', 'minimum_preserved', 'partial_output', 'stable_capacity_probe',
        'memory_limit_changed', 'backend_context_limit_changed',
        'first_request', 'budget_pressure', 'runtime_budget',
        'capacity_reassessment', 'gradual_growth',
    }),
}
_CONTEXT_TUNING_ENUMS['method'] = _CONTEXT_TUNING_ENUMS['tuning_method']
_CONTEXT_TUNING_IDS = frozenset({'job_id', 'chat_id', 'workspace_id', 'run_id', 'record_id', 'session_id'})


def _context_tuning_payload(event: Any, fields: dict[str, Any]) -> dict[str, Any] | None:
    """Keep only reviewed scalar evidence; never persist prompt/error bodies.

    Invalid or new fields are omitted rather than passed to general-purpose
    logging. Non-UUID caller identities and model names are represented by a
    stable digest, so arbitrary names cannot smuggle content into this ledger.
    """
    if not isinstance(event, str) or event not in _CONTEXT_TUNING_EVENTS:
        return None
    payload: dict[str, Any] = {'event': event}
    for key, value in fields.items():
        if key in _CONTEXT_TUNING_NUMBERS:
            if value is None:
                payload[key] = None
            elif isinstance(value, (int, float)) and not isinstance(value, bool):
                if 0 <= value <= 2**63 - 1 and math.isfinite(value):
                    payload[key] = value
        elif key in _CONTEXT_TUNING_BOOLEANS and isinstance(value, bool):
            payload[key] = value
        elif key in _CONTEXT_TUNING_ENUMS:
            if isinstance(value, str) and value in _CONTEXT_TUNING_ENUMS[key]:
                payload[key] = value
        elif key in _CONTEXT_TUNING_IDS and isinstance(value, str) and value:
            if key == 'session_id' and re.fullmatch(r'\d{4}-\d{2}-\d{2}_\d{6}(?:_\d{1,6})?', value):
                payload[key] = value
            elif re.fullmatch(r'[0-9a-f]{64}', value):
                payload[key] = value
            else:
                try:
                    payload[key] = str(uuid.UUID(value))
                except (ValueError, AttributeError):
                    payload[key] = hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()
        elif key in {'model', 'model_id'} and isinstance(value, str) and value:
            payload['model_id'] = value if key == 'model_id' and re.fullmatch(r'[0-9a-f]{64}', value) else hashlib.sha256(value.encode('utf-8', errors='replace')).hexdigest()
        elif key == 'observed_at' and isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value)
                if parsed.tzinfo is not None:
                    payload[key] = parsed.isoformat(timespec='milliseconds')
            except ValueError:
                pass
        elif key in {'recovery_targets', 'history_targets'} and isinstance(value, (list, tuple)):
            payload[key] = [v for v in value[:64] if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 2**63 - 1]
    return payload


def _is_sensitive_log_key(key: str) -> bool:
    """Credentials are excluded even when content-rich diagnostics are chosen."""
    lowered = str(key).lower()
    return (
        any(part in lowered for part in (
            'api_key', 'apikey', 'password', 'authorization', 'cookie', 'secret',
            'credential',
        ))
        or ('token' in lowered and 'tokens' not in lowered)
        or lowered in {'salt', 'salt_hex', 'salt_b64', 'setup_code'}
    )


def _diagnostic_source_allowed(source: Path) -> bool:
    """Never follow log links or collect a misplaced login-credential file.

    Settings are outside the curated diagnostics tree already. These checks
    also prevent a copied credential file or a log symlink into settings from
    turning an explicit content-rich export into a credential-store export.
    """
    if source.name.lower().startswith(('login_users.json', '.login-users-')):
        return False
    try:
        try:
            info = source.lstat()
        except FileNotFoundError:
            info = None
        if info is not None and not stat.S_ISREG(info.st_mode):
            return False
        for part in (source, *source.parents):
            if part.is_symlink() or part.name == '.settings':
                return False
            if part.name == '.logs':
                break
    except OSError:
        return False
    return True

# Diagnostics are exported privacy-safe by default. These field names are known
# to carry chat/model/tool payloads or project content in structured logs.
_PRIVACY_PAYLOAD_KEYS = {
    'content', 'reasoning', 'reasoning_content', 'thinking', 'text', 'prompt',
    'messages', 'message', 'stream_segments', 'raw_arguments', 'arguments',
    'result', 'tool_calls', 'calls', 'preview', 'body', 'response', 'payload',
    'command', 'query', 'source_text', 'file_content', 'stdout', 'stderr',
}
_PRIVACY_PATH_KEYS = {
    'path', 'paths', 'cwd', 'workspace', 'workspace_root', 'guest_root', 'url',
    'uri', 'endpoint_url', 'filename', 'file',
}
_PRIVACY_SAFE_STRING_KEYS = {
    'event', 'provider', 'backend', 'model', 'finish_reason', 'phase', 'kind',
    'semantics', 'tool', 'category', 'permission', 'status', 'execution_status',
    'error_code', 'mode', 'operation', 'version', 'python', 'platform',
    'projection_error_code', 'projection_probe_code',
    'thinking_selected', 'skill_selected', 'tps_kind', 'tps_source',
    'context_window_source', 'vision_transport', 'backend_family',
    'executable', 'error_class', 'errno_name', 'resource_type', 'diagnostic_summary',
    # Privacy-safe context/cache observability labels. These values are drawn
    # from HarnessyXO's fixed enums/coarse region names and never contain
    # prompt text, paths, tool arguments, or result bodies.
    'strategy', 'cache_strategy', 'active_context_mode', 'context_source',
    'budget_method', 'context_epoch_reason', 'prompt_cacheability_health',
    'prompt_cacheability_transport_reason', 'prompt_cache_first_changed_region',
    'prompt_cache_estimate_kind', 'tuning_method',
    'watchdog_request_state', 'watchdog_evidence', 'recovery_skip_reason',
    'decision',  # Completion-check enum; raw check conversation is never logged here.
}
_PRIVACY_SAFE_STRING_LIST_KEYS = {
    'executables', 'operations', 'control_operators', 'flags', 'detected_error_classes',
    'errno_names', 'error_signatures', 'resource_types', 'environment_claim_signals',
    'output_fields',
}

# These startup fields are evidence from reviewed controller observations,
# never arbitrary guest output or inferred failure causes.
_VM_DIAGNOSTIC_ENUMS = {
    'lock_kind': frozenset({'thread', 'process'}),
    'controller_action': frozenset({'start', 'stop', 'create', 'delete', 'edit', 'clone', 'snapshot', 'list', 'shell',
                                    'factory-reset', 'restart', '--version', 'other', 'unknown'}),
    'outcome': frozenset({'controller_error', 'controller_timeout', 'cancelled', 'completed', 'failed'}),
    'last_boot_milestone': frozenset({'launching_instance', 'launching_vz', 'ssh_port_assigned', 'waiting_ssh',
                                     'waiting_guest_agent', 'waiting_boot_scripts', 'lima_ready', 'unknown'}),
    'controller_failure_kind': frozenset({'ssh_requirement_wait_failed', 'startup_fatal', 'unknown'}),
    'controller_signal': frozenset({'SIGINT', 'SIGTERM', 'SIGKILL', 'other'}),
    'controller_status': frozenset({'running', 'stopped', 'starting', 'stopping', 'broken', 'unknown',
                                  'not_created', 'unavailable', 'probe_failed', 'timeout'}),
    'timeout_scope': frozenset({'operation', 'provider'}),
    'failed_stage': frozenset({
        'queued', 'starting', 'running', 'failed', 'timed_out', 'cancelled', 'unknown',
        'checking_host_dependencies', 'installing_host_dependencies', 'host_dependencies_ready',
        'creating_vm', 'reconciling_environment', 'starting_vm', 'waiting_for_guest',
        'checking_provisioning', 'adopting_provisioning', 'provisioning_packages',
        'provisioning_package_index', 'provisioning_required_packages', 'provisioning_optional_packages',
        'provisioning_ghidra', 'provisioning_ghidra_arm64', 'provisioning_python_re', 'provisioning_rea',
        'provisioning_skipped_offline', 'finalizing_provisioning', 'installing_isolation',
        'applying_isolation', 'verifying_isolation', 'ready', 'stopping_vm',
        'tools_saving', 'tools_removing', 'tools_pending', 'tools_installing', 'tools_complete',
        'preparing_snapshot', 'stopping_snapshot_vm', 'cloning_snapshot', 'saving_snapshot',
        'restarting_snapshot_vm', 'verifying_snapshot_restart', 'preparing_restore',
        'stopping_restore_vm', 'replacing_restore_vm', 'reconciling_restore_files',
        'restarting_restore_vm', 'verifying_restore_restart', 'factory_reset',
        'restarting_reset_vm', 'rebuilding', 'network_stopping', 'network_applying', 'network_starting',
    }),
}
_WORKSPACE_DATABASE_ENUMS = {
    'database_health_status': frozenset({'ready', 'corrupt', 'unavailable', 'timed_out', 'worker_failed'}),
    'database_health_reason': frozenset({
        'integrity_failed', 'sqlite_corrupt', 'sqlite_error', 'sqlite_busy', 'filesystem_error', 'database_changed',
        'admission_required', 'worker_timeout', 'worker_exit', 'worker_protocol', 'invalid_file',
        'empty_database', 'initialization_failed', 'verified', 'cancelled', 'history_busy', 'maintenance', 'recovery_pending',
    }),
    'database_health_phase': frozenset({'database_admission', 'workspace_initialization', 'admission', 'initialization'}),
    'database_worker_signal': frozenset({'SIGBUS', 'SIGSEGV', 'SIGABRT', 'SIGKILL', 'SIGTERM', 'other', 'none'}),
}

WORKSPACE_RECOVERY_EVENTS = frozenset({
    'workspace_database_recovery_started', 'workspace_database_recovery_progress',
    'workspace_database_recovery_completed', 'workspace_database_recovery_failed',
})
_RECOVERY_ENUMS = {
    'sqlite_errorname': frozenset(name for name, value in vars(sqlite3).items()
                                  if name.startswith('SQLITE_') and type(value) is int),
    'recovery_method': frozenset({'check_only', 'reindex', 'salvage'}),
    'recovery_stage': frozenset({'backup', 'copy', 'hash', 'check', 'inspect', 'schema', 'reindex',
                                 'salvage', 'recover', 'verify', 'activate', 'rollback', 'complete'}),
    'recovery_status': frozenset({
        'started', 'queued', 'running', 'waiting', 'cancelling', 'needs_review', 'completed', 'failed', 'cancelled', 'timed_out',
        'healthy', 'corrupt', 'index_repaired', 'partial_salvage', 'activation_blocked',
        'incomplete_transaction', 'rolled_back', 'activated', 'candidate_ready',
        'healthy_preserved_copy', 'healthy_structure_needs_review',
        'inspection_timed_out_originals_preserved', 'inspection_unavailable_originals_preserved',
        'verified_index_repair_candidate_needs_review', 'preserved_needs_specialist_recovery',
        'salvage_candidate_needs_review_completeness_unknown',
        'partial_salvage_candidate_needs_review', 'preserved_recovery_unavailable',
        'cancelled_originals_preserved', 'stopped', 'source_changed_recovery_result_not_usable',
    }),
    'recovery_failure_code': frozenset({
        'candidate_stale', 'not_lossless', 'maintenance_busy', 'source_changed',
        'transaction_incomplete', 'filesystem_error', 'validation_failed', 'cancelled',
        'unsafe_file', 'unsafe_workspace', 'unsafe_app', 'host_unsupported', 'app_running',
        'launch_lock_unsafe', 'open_file', 'open_file_check_failed', 'insufficient_space',
        'missing_database', 'timed_out', 'worker_failed', 'worker_protocol', 'sqlite_error',
        'sqlite_cli_unavailable', 'sqlite_cli_recover_unsupported', 'sqlite_cli_recover_failed',
        'schema_unavailable', 'invalid_report', 'receipt_invalid', 'dependency_missing',
        'copy_failed', 'worker_timeout', 'activity_busy', 'maintenance', 'recovery_pending',
        'report_invalid', 'candidate_unavailable', 'io_error', 'none', 'unknown',
    }),
    'database_worker_signal': frozenset({'SIGBUS', 'SIGSEGV', 'SIGABRT', 'SIGKILL', 'SIGTERM', 'other', 'none'}),
}
_RECOVERY_TABLES = frozenset("""chats chat_output_owners chat_output_id_migrations messages
message_bubble_bookmarks memory workspace_state jobs artifacts attachments
memory_events generation_metrics subagent_metrics instruction_documents
chat_task_state history_checkpoints file_history_snapshots chat_branches
 timeline_rewinds rewind_undo_transactions branch_memory_scopes branch_memory
project_memory_provenance project_dependencies project_access_grants
project_revisions project_upstream_baselines archived_families archived_projects
external_targets external_target_events""".split())
_RECOVERY_INTEGERS = frozenset({
    'source_bytes', 'source_db_bytes', 'source_wal_bytes', 'source_shm_bytes', 'source_journal_bytes',
    'copied_bytes', 'total_bytes', 'free_bytes', 'required_bytes', 'recovered_bytes', 'candidate_bytes',
    'source_file_count', 'copied_file_count', 'integrity_error_count', 'unknown_table_count',
    'foreign_key_violations', 'application_invariant_failures', 'inserted_rows',
    'duplicate_or_rejected_rows', 'failed_insert_statements', 'lost_and_found_rows',
    'unknown_table_rows', 'incomplete_statements', 'ignored_non_insert_statements',
})
_RECOVERY_BOOLEANS = frozenset({
    'source_unchanged', 'originals_unchanged', 'originals_preserved', 'integrity_ok', 'candidate_created', 'candidate_verified',
    'standalone_database', 'completeness_known', 'activated', 'rollback_complete', 'index_only',
    'application_invariants_ok', 'integrity_errors_truncated', 'foreign_key_errors_truncated',
    'foreign_key_check_failed', 'corruption_established', 'cancelled',
})


def validate_workspace_recovery_event(event: Any, value: Any) -> dict[str, Any] | None:
    """Recovery receipts contain operational facts only, including at log write.

    Private copies, recovered SQL and arbitrary schema/row data never enter this
    projection. Only installed canonical table names may label numeric counts.
    """
    if not isinstance(event, str) or event not in WORKSPACE_RECOVERY_EVENTS or not isinstance(value, dict):
        return None
    result: dict[str, Any] = {'event': event}
    for key, allowed in _RECOVERY_ENUMS.items():
        if isinstance(value.get(key), str) and value[key] in allowed:
            result[key] = value[key]
    for key in ('db_id', 'candidate_id', 'source_generation_id'):
        if isinstance(value.get(key), str) and re.fullmatch(r'[0-9a-f]{64}', value[key]):
            result[key] = value[key]
    for key in ('recovery_operation_id',):
        if isinstance(value.get(key), str) and re.fullmatch(r'[0-9a-f]{32}', value[key]):
            result[key] = value[key]
    receipt = value.get('recovery_receipt_id')
    if isinstance(receipt, str) and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', receipt):
        result['recovery_receipt_id'] = receipt
    for key in _RECOVERY_INTEGERS:
        if type(value.get(key)) is int and 0 <= value[key] <= 2**63 - 1:
            result[key] = value[key]
    for key in ('elapsed_seconds', 'stage_elapsed_seconds', 'timeout_seconds'):
        if type(value.get(key)) in (int, float) and math.isfinite(value[key]) and 0 <= value[key] <= 604800:
            result[key] = value[key]
    sqlite_code = value.get('sqlite_errorcode')
    if type(sqlite_code) is int and 0 <= sqlite_code <= 2**31 - 1:
        result['sqlite_errorcode'] = sqlite_code
    code = value.get('database_worker_returncode')
    if type(code) is int and -255 <= code <= 255:
        result['database_worker_returncode'] = code
    for key in _RECOVERY_BOOLEANS:
        if type(value.get(key)) is bool:
            result[key] = value[key]
    for key in ('row_counts', 'source_row_counts', 'candidate_row_counts'):
        rows = value.get(key)
        if isinstance(rows, dict):
            result[key] = {name: rows[name] for name in sorted(_RECOVERY_TABLES)
                           if type(rows.get(name)) is int and 0 <= rows[name] <= 2**63 - 1}
    for key in ('row_count_failures', 'unreadable_or_missing_source_tables', 'tables_with_fewer_rows'):
        rows = value.get(key)
        if isinstance(rows, (list, tuple)):
            result[key] = sorted({name for name in rows[:len(_RECOVERY_TABLES)]
                                  if isinstance(name, str) and name in _RECOVERY_TABLES})
    categories = value.get('integrity_categories')
    if isinstance(categories, dict):
        result['integrity_categories'] = {key: categories[key] for key in ('index_consistency', 'other_structure_or_data')
            if type(categories.get(key)) is int and 0 <= categories[key] <= 100}
    return result


_VM_COMMAND_ID_KEYS = frozenset({'command_id', 'parent_start_command_id', 'startup_attempt_id'})


def _safe_event_field(key: str, value: Any) -> Any:
    """Keep reviewed structured evidence intact, without widening raw limits."""
    if _is_sensitive_log_key(key):
        return '<redacted>'
    if key in {'technical_error', 'controller_evidence', 'host_resources', 'requested_vm_config', 'environment_action',
               'error_type', 'terminal_stop_reason', 'terminal_reason', 'backend_done_reason',
               'completion_state', 'last_error_code', 'source', 'state', 'component', 'missing_dependency'}:
        return _privacy_safe_value(value, key=key)
    if key in _WORKSPACE_DATABASE_ENUMS or key in {'database_worker_returncode', 'sqlite_errorcode', 'sqlite_errorname'}:
        return _privacy_safe_value(value, key=key)
    if key in {'archive_check', 'storage_issue'}:
        return _privacy_safe_value(value, key=key)
    if key == 'error_class':
        return _privacy_safe_value(value, key=key)
    if key in {'client_request_id', 'usage', 'timings', 'backend_timings',
               'prompt_progress', 'native_prompt_progress', 'throughput_source',
               'prefill_throughput_source', 'timing_source', 'tps_source', 'provenance', 'output_provenance'}:
        return _privacy_safe_value(value, key=key)
    if key in {
        'permission_decision', 'permission_states', 'required_permissions',
        'permission_source', 'permission_reason', 'permission_target_mode',
        'permission_target_state', 'target_validation', 'approval_wait_seconds',
        'execution_duration_seconds', 'coordination_wait_seconds',
    }:
        return _privacy_safe_value(value, key=key)
    if key in {'fault', 'exception_evidence'}:
        from .faults import validate_fault_evidence

        return validate_fault_evidence(value)
    if key in {'frames', 'frame_stack'}:
        from .faults import validate_frames

        return validate_frames(value)
    return DiagnosticsManager._safe(value)


def _validated_session_id(value: Any) -> str | None:
    if isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}_\d{6}(?:_\d{1,6})?', value):
        return value
    return None


def _validated_session_metadata(value: Any) -> dict[str, Any]:
    """Metadata is content-free even when logs were manually replaced."""
    if not isinstance(value, dict):
        return {}
    out: dict[str, Any] = {'schema_version': 1}
    session_id = _validated_session_id(value.get('session_id'))
    if session_id is not None:
        out['session_id'] = session_id
    for key in ('app_version', 'python_version', 'sqlite_version'):
        item = value.get(key)
        if isinstance(item, str) and re.fullmatch(r'(?:dev|\d+(?:\.\d+){1,3}(?:(?:a|b|rc|\.post|\.dev)\d+)?)', item):
            out[key] = item
    if isinstance(value.get('platform_system'), str) and value['platform_system'] in {'Darwin', 'Linux', 'Windows', 'FreeBSD', 'OpenBSD', 'NetBSD'}:
        out['platform_system'] = value['platform_system']
    pid = value.get('pid')
    if isinstance(pid, int) and not isinstance(pid, bool) and 0 < pid < 2**63:
        out['pid'] = pid
    started_at = value.get('started_at')
    if isinstance(started_at, str):
        try:
            parsed = datetime.fromisoformat(started_at)
            if parsed.tzinfo is not None:
                out['started_at'] = parsed.isoformat(timespec='milliseconds')
        except ValueError:
            pass
    return out


def _export_metadata(latest: Path) -> dict[str, Any]:
    payload = _read_snapshot_bytes(latest / 'SESSION_METADATA.json', tail_bytes=16 * 1024)
    try:
        decoded = json.loads(payload) if payload else {}
    except (ValueError, RecursionError):
        decoded = {}
    session = _validated_session_metadata(decoded)
    if 'session_id' not in session:
        current = _read_snapshot_bytes(latest / 'CURRENT_SESSION.txt', tail_bytes=256)
        identity = _validated_session_id(current.decode('utf-8', errors='replace').strip()) if current else None
        if identity is not None:
            session['session_id'] = identity
    # Old sessions have no metadata file. Recover only explicit version/PID
    # fields from a startup record, never the system's free-form description.
    if 'app_version' not in session:
        raw = _read_snapshot_bytes(latest / 'harnessy.log', tail_bytes=512 * 1024)
        for line in (raw.decode('utf-8', errors='replace').splitlines() if raw else []):
            parts = line.split(' ', 3)
            if len(parts) != 4:
                continue
            try:
                row = json.loads(parts[3])
            except (ValueError, RecursionError):
                continue
            if isinstance(row, dict) and row.get('event') == 'startup':
                session.update(_validated_session_metadata({
                    'app_version': row.get('version'),
                    'python_version': row.get('python'),
                    'pid': row.get('pid'),
                }))
                break
    return {
        'schema_version': 1,
        'captured_at': datetime.now().astimezone().isoformat(timespec='milliseconds'),
        'session': session,
        'collector_python_version': sys.version.split()[0],
        'collector_sqlite_version': sqlite3.sqlite_version,
    }


_SHELL_OPERATION_BY_EXECUTABLE = {
    'losetup': 'loop_device',
    'mount': 'mount',
    'umount': 'unmount',
    'findmnt': 'mount_inspection',
    'lsblk': 'block_device_inspection',
    'blkid': 'filesystem_signature_inspection',
    'e2fsck': 'filesystem_check',
    'fsck': 'filesystem_check',
    'file': 'file_type_inspection',
    'stat': 'filesystem_metadata_inspection',
    'find': 'filesystem_search',
    'ls': 'filesystem_listing',
    'cat': 'file_read',
    'grep': 'text_search',
    'rg': 'text_search',
    'sed': 'text_transform',
    'awk': 'text_transform',
    'cp': 'filesystem_copy',
    'mv': 'filesystem_move',
    'rm': 'filesystem_delete',
    'mkdir': 'filesystem_create',
    'chmod': 'permissions_change',
    'chown': 'ownership_change',
    'systemctl': 'service_control',
    'journalctl': 'service_log_inspection',
    'ps': 'process_inspection',
    'ss': 'network_socket_inspection',
    'ip': 'network_inspection',
    'curl': 'network_request',
    'wget': 'network_request',
    'python': 'python_execution',
    'python3': 'python_execution',
    'git': 'git_operation',
    'bash': 'shell_execution',
    'sh': 'shell_execution',
    'zsh': 'shell_execution',
    'echo': 'shell_builtin_or_utility',
    'printf': 'shell_builtin_or_utility',
    'head': 'text_read',
    'tail': 'text_read',
    'sort': 'text_transform',
    'uniq': 'text_transform',
    'cut': 'text_transform',
    'tr': 'text_transform',
    'wc': 'text_measurement',
    'xargs': 'command_composition',
    'tee': 'text_write',
}


_ENVIRONMENT_CLAIM_PATTERNS = (
    (re.compile(r'\bpermission denied\b', re.I), 'permission_denied'),
    (re.compile(r"\b(?:cannot|can\'t|could not|unable to)\b.{0,64}\b(?:mount|mounted|remount|remounted)\b|\b(?:mount|mounted|remount|remounted)\b.{0,64}\b(?:cannot|can\'t|unable)\b", re.I), 'mount_unavailable'),
    (re.compile(r'\bloop devices?\b.{0,64}\b(?:permission|unavailable|denied|cannot|can\'t)\b', re.I), 'loop_device_unavailable'),
    (re.compile(r'\b(?:vm|virtual machine)\b.{0,48}\b(?:rebuild|rebuilt|reprovision|reprovisioned|factory reset|snapshot restore)\b|\b(?:rebuild|rebuilt|reprovision|reprovisioned)\b.{0,48}\bvm\b', re.I), 'vm_rebuild_or_reprovision'),
    (re.compile(r'\b(?:file|path)\b.{0,48}\b(?:no longer exists|does not exist|missing)\b', re.I), 'file_missing'),
    (re.compile(r'\b(?:tool|command|package)\b.{0,48}\b(?:not installed|unavailable|not found)\b', re.I), 'tool_unavailable'),
    (re.compile(r'\bnetwork\b.{0,48}\b(?:unavailable|unreachable|down)\b', re.I), 'network_unavailable'),
    (re.compile(r'\bread[- ]only file system\b|\bfilesystem\b.{0,32}\bread[- ]only\b', re.I), 'read_only_filesystem'),
)


def environment_claim_diagnostics(text: str) -> list[str]:
    """Return predefined environment-claim labels without retaining model prose."""
    raw = str(text or '')
    return [label for pattern, label in _ENVIRONMENT_CLAIM_PATTERNS if pattern.search(raw)]


_ERROR_PATTERNS = (
    (re.compile(r'permission denied', re.I), 'PermissionDenied', 'EACCES', 'Permission denied'),
    (re.compile(r'operation not permitted', re.I), 'OperationNotPermitted', 'EPERM', 'Operation not permitted'),
    (re.compile(r'no such file or directory', re.I), 'FileNotFound', 'ENOENT', 'No such file or directory'),
    (re.compile(r'read-only file system', re.I), 'ReadOnlyFilesystem', 'EROFS', 'Read-only file system'),
    (re.compile(r'device or resource busy', re.I), 'DeviceBusy', 'EBUSY', 'Device or resource busy'),
    (re.compile(r'not a block device', re.I), 'NotBlockDevice', '', 'Not a block device'),
    (re.compile(r'wrong fs type|bad superblock|unknown filesystem type', re.I), 'FilesystemMountError', '', 'Filesystem mount/type error'),
    (re.compile(r'command not found', re.I), 'CommandNotFound', '', 'Command not found'),
    (re.compile(r'connection refused', re.I), 'ConnectionRefused', 'ECONNREFUSED', 'Connection refused'),
    (re.compile(r'network is unreachable', re.I), 'NetworkUnreachable', 'ENETUNREACH', 'Network is unreachable'),
    (re.compile(r'timed? out|timeout', re.I), 'Timeout', 'ETIMEDOUT', 'Timed out'),
)

def _shell_segments(command: str) -> tuple[list[str], list[str]]:
    """Return shell-ish segments and control operators without preserving operands."""
    text = str(command or '')
    controls = re.findall(r'&&|\|\||[;|\n]', text)
    parts = [part.strip() for part in re.split(r'&&|\|\||[;|\n]', text) if part.strip()]
    return parts[:64], controls[:64]

def shell_command_diagnostics(command: str) -> dict[str, Any]:
    """Describe a shell command without retaining paths, arguments, or payloads."""
    segments, controls = _shell_segments(command)
    executables: list[str] = []
    operations: list[str] = []
    flags: list[str] = []
    wrappers = {'sudo', 'command', 'builtin', 'exec', 'env', 'nohup', 'setsid'}
    value_wrappers = {'timeout'}
    for segment in segments:
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            tokens = segment.split()
        if not tokens:
            continue
        index = 0
        while index < len(tokens) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.*', tokens[index] or ''):
            index += 1
        while index < len(tokens):
            base = os.path.basename(tokens[index])
            if base in wrappers:
                index += 1
                while index < len(tokens) and tokens[index].startswith('-'):
                    index += 1
                continue
            if base in value_wrappers:
                index += 1
                if index < len(tokens) and re.fullmatch(r'[0-9.]+[smhd]?', tokens[index] or ''):
                    index += 1
                continue
            break
        if index >= len(tokens):
            continue
        executable = os.path.basename(tokens[index])[:80]
        if executable and re.fullmatch(r'[A-Za-z0-9_.+:-]+', executable):
            if executable in _SHELL_OPERATION_BY_EXECUTABLE:
                executables.append(executable)
                operations.append(_SHELL_OPERATION_BY_EXECUTABLE[executable])
            else:
                # A custom executable basename may itself contain a private
                # project/product name. Keep only the fact that some custom
                # executable was invoked, never its basename.
                executables.append('<custom-executable>')
                operations.append('custom_execution')
        for token in tokens[index + 1:]:
            if re.fullmatch(r'--?[A-Za-z0-9][A-Za-z0-9_-]*', token or ''):
                flags.append(token[:80])
    def unique(rows: list[str]) -> list[str]:
        return list(dict.fromkeys(rows))[:32]
    return {
        'redacted': True,
        'segment_count': len(segments),
        'compound': len(segments) > 1,
        'executables': unique(executables),
        'operations': unique(operations),
        'flags': unique(flags),
        'control_operators': unique([{'\n': 'newline'}.get(op, op) for op in controls]),
        'failure_masking_possible': bool(re.search(r'\|\|\s*(?:true|:)(?:\s|$)|;\s*true(?:\s|$)', str(command or ''), re.I)),
        'has_redirection': bool(re.search(r'(?:^|\s)(?:\d?>|\d?>>|<)(?:\s|[^&])', str(command or ''))),
        'stderr_redirected_to_stdout': bool(re.search(r'2\s*>\s*&1|\|&', str(command or ''))),
    }

def shell_result_diagnostics(command: str, stdout: str, stderr: str, returncode: int | None) -> dict[str, Any]:
    """Extract predefined non-sensitive execution/error semantics from shell output."""
    stdout_text = str(stdout or '')
    stderr_text = str(stderr or '')
    shape = shell_command_diagnostics(command)
    rc = int(returncode) if returncode is not None else None
    # Most command diagnostics belong on stderr. Only inspect stdout for error
    # signatures when the shell explicitly merged stderr into stdout, or when a
    # non-zero command produced no stderr. This avoids treating ordinary file
    # contents containing phrases such as "Permission denied" as execution errors.
    error_text = stderr_text
    if not error_text and (bool(shape.get('stderr_redirected_to_stdout')) or (rc is not None and rc != 0)):
        error_text = stdout_text
    all_output = '\n'.join(part for part in (stderr_text, stdout_text) if part)
    classes: list[str] = []
    errnos: list[str] = []
    signatures: list[str] = []
    for pattern, error_class, errno_name, signature in _ERROR_PATTERNS:
        if pattern.search(error_text):
            classes.append(error_class)
            if errno_name:
                errnos.append(errno_name)
            signatures.append(signature)
    def unique(rows: list[str]) -> list[str]:
        return list(dict.fromkeys(rows))[:24]
    classes = unique(classes)
    errnos = unique(errnos)
    signatures = unique(signatures)
    return {
        'overall_returncode': rc,
        'overall_success': rc == 0 if rc is not None else None,
        'detected_error_classes': classes,
        'errno_names': errnos,
        'error_signatures': signatures,
        'detected_error_count': len(classes),
        'overall_success_with_detected_error': bool(rc == 0 and classes),
        'failure_masking_possible': bool(shape.get('failure_masking_possible')),
        'loop_device_reference_present': bool(re.search(r'/dev/loop\d+', all_output)),
        'mount_operation_attempted': 'mount' in (shape.get('operations') or []),
        'loop_operation_attempted': 'loop_device' in (shape.get('operations') or []),
    }


class _Tee:
    def __init__(self, primary, secondary) -> None:
        self.primary = primary
        self.secondary = secondary

    def write(self, data):
        try:
            self.primary.write(data)
        except Exception:
            pass
        try:
            self.secondary.write(data)
            self.secondary.flush()
        except Exception:
            pass
        return len(data or '')

    def flush(self):
        for stream in (self.primary, self.secondary):
            try:
                stream.flush()
            except Exception:
                pass

    def isatty(self):
        try:
            return bool(self.primary.isatty())
        except Exception:
            return False

    def fileno(self):
        return self.primary.fileno()


class DiagnosticsManager:
    """Small host-level diagnostic recorder with bounded files and support bundle."""

    def __init__(self) -> None:
        self.root: Path | None = None
        self.session_dir: Path | None = None
        self.previous_session_dir: Path | None = None
        self.latest_dir: Path | None = None
        self._configured = False
        self._lock = threading.RLock()
        self._stream_tail: deque[str] = deque(maxlen=_STREAM_TAIL_MAX_EVENTS)
        self._stream_tail_chars = 0
        self._stdout_file = None
        self._stderr_file = None
        self._original_excepthook = sys.excepthook
        self._bundle_lock = threading.Lock()
        self._stream_tail_file = None
        self._stream_tail_file_bytes = 0

    def configure(self, app_root: Path, *, version: str = 'dev') -> None:
        with self._lock:
            if self._configured:
                return
            self.root = (Path(app_root).resolve() / '.logs')
            sessions = self.root / 'sessions'
            self.latest_dir = self.root / 'latest'
            crashes = self.root / 'crashes'
            for path in (self.root, sessions, crashes):
                path.mkdir(parents=True, exist_ok=True)
            previous_sessions = sorted(
                (p for p in sessions.iterdir() if p.is_dir()),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            self.previous_session_dir = previous_sessions[0] if previous_sessions else None
            # ``latest`` always describes this process invocation, never a mix
            # of several historical runs. Session history remains under sessions/.
            if self.latest_dir.exists():
                self._preserve_previous_native_fault()
                shutil.rmtree(self.latest_dir, ignore_errors=True)
            self.latest_dir.mkdir(parents=True, exist_ok=True)

            stamp = datetime.now().astimezone().strftime('%Y-%m-%d_%H%M%S')
            self.session_dir = sessions / stamp
            suffix = 1
            while self.session_dir.exists():
                suffix += 1
                self.session_dir = sessions / f'{stamp}_{suffix}'
            self.session_dir.mkdir(parents=True, exist_ok=False)
            # The support ZIP is an export artifact, not live state. Never leave
            # a stale bundle around after a new HarnessyXO process starts: users
            # can create a fresh one from the GUI or .logs/collect_diagnostics.py.
            try:
                for bundle_name in (_PRIVACY_SAFE_BUNDLE, _FULL_CONTENT_BUNDLE):
                    (self.root / bundle_name).unlink(missing_ok=True)
                    (self.root / f'{bundle_name}.tmp').unlink(missing_ok=True)
            except OSError:
                pass
            try:
                (self.latest_dir / 'CURRENT_SESSION.txt').write_text(self.session_dir.name + '\n', encoding='utf-8')
                metadata = {
                    'schema_version': 1,
                    'app_version': version,
                    'session_id': self.session_dir.name,
                    'started_at': datetime.now().astimezone().isoformat(timespec='milliseconds'),
                    'pid': os.getpid(),
                    'python_version': sys.version.split()[0],
                    'sqlite_version': sqlite3.sqlite_version,
                    'platform_system': platform.system(),
                }
                for folder in (self.latest_dir, self.session_dir):
                    (folder / 'SESSION_METADATA.json').write_text(
                        json.dumps(_validated_session_metadata(metadata), ensure_ascii=False, indent=2),
                        encoding='utf-8',
                    )
            except OSError:
                pass
            self._write_collector_script(app_root)

            for name in _LOG_NAMES:
                self._configure_logger(name)
            # Keep the documented latest/ shape stable even before the first
            # backend protocol event arrives. Keep one line-buffered append handle
            # instead of rewriting the whole ring file on every decoder chunk.
            stream_path = self.latest_dir / 'backend-stream-tail.log'
            self._stream_tail_file = stream_path.open('w+', encoding='utf-8', buffering=1)
            self._stream_tail_file_bytes = 0
            self._flush_stream_tail()
            self._configure_console_capture()
            self._install_exception_hook()
            self._configured = True
            self._prune_sessions()
            self.event('harnessy', 'startup', version=version, pid=os.getpid(), python=sys.version.split()[0], platform=platform.platform())
            self.capture_system_snapshot('startup')
            atexit.register(self.close)

    def _configure_logger(self, name: str) -> None:
        assert self.root is not None and self.session_dir is not None and self.latest_dir is not None
        logger = logging.getLogger(f'harnessy.{name}')
        logger.setLevel(logging.INFO)
        logger.propagate = False
        for old_handler in logger.handlers:
            old_handler.close()
        logger.handlers.clear()
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        paths = [self.session_dir / f'{name}.log', self.latest_dir / f'{name}.log']
        if name == 'context_tuning':
            history = self.root / 'context-history'
            history.mkdir(parents=True, exist_ok=True)
            paths.append(history / 'context_tuning.log')
        for path in paths:
            if name == 'database':
                max_bytes, backups = _DATABASE_LOG_MAX_BYTES, _DATABASE_LOG_BACKUPS
            elif name == 'targets':
                max_bytes, backups = _TARGET_LOG_MAX_BYTES, _TARGET_LOG_BACKUPS
            elif name != 'context_tuning':
                max_bytes, backups = _MAX_LOG_BYTES, _BACKUPS
            elif path.parent == self.root / 'context-history':
                max_bytes, backups = _CONTEXT_HISTORY_MAX_BYTES, _CONTEXT_HISTORY_BACKUPS
            else:
                max_bytes, backups = _CONTEXT_LOG_MAX_BYTES, _CONTEXT_LOG_BACKUPS
            handler = RotatingFileHandler(path, maxBytes=max_bytes, backupCount=backups, encoding='utf-8')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

    def _configure_console_capture(self) -> None:
        assert self.session_dir is not None and self.latest_dir is not None
        # Keep terminal output unchanged while retaining prints/tracebacks that do
        # not go through Python logging. Latest is intentionally the active run.
        self._stdout_file = (self.latest_dir / 'console.log').open('a', encoding='utf-8', buffering=1)
        self._stderr_file = (self.latest_dir / 'console-error.log').open('a', encoding='utf-8', buffering=1)
        if not isinstance(sys.stdout, _Tee):
            sys.stdout = _Tee(sys.stdout, self._stdout_file)
        if not isinstance(sys.stderr, _Tee):
            sys.stderr = _Tee(sys.stderr, self._stderr_file)
        from .native_faults import enable_native_fault_capture
        self._native_fault_capture_status = enable_native_fault_capture(self._stderr_file)
        try:
            self.event('harnessy', 'native_fault_capture_configured', status=self._native_fault_capture_status)
        except Exception:
            pass

    def _preserve_previous_native_fault(self) -> None:
        """Retain a bounded crash tail before clearing the previous latest run."""
        if self.latest_dir is None or self.root is None:
            return
        descriptors = []
        try:
            from .native_faults import native_fault_signature
            payload = _read_snapshot_bytes(self.latest_dir / 'console-error.log', tail_bytes=512 * 1024)
            if not payload or not any(native_fault_signature(line) for line in payload.decode(
                    'utf-8', errors='replace').splitlines()):
                return
            identity = _validated_session_id((_read_snapshot_bytes(
                self.latest_dir / 'CURRENT_SESSION.txt', tail_bytes=256) or b'').decode(
                    'utf-8', errors='replace').strip())
            if identity is None:
                return
            # Traverse only existing session directories through no-follow
            # descriptors. An injected CURRENT_SESSION or symlink can never
            # turn this preservation write into an arbitrary path overwrite.
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            sessions_fd = os.open(self.root / 'sessions', flags)
            descriptors.append(sessions_fd)
            session_fd = os.open(identity, flags, dir_fd=sessions_fd)
            descriptors.append(session_fd)
            target_fd = os.open('console-error.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600, dir_fd=session_fd)
            with os.fdopen(target_fd, 'wb') as target:
                target.write(payload)
        except Exception:
            # Preservation cannot block launch if this platform lacks dir_fd
            # support or the prior diagnostic filesystem is unavailable.
            pass
        finally:
            for descriptor in reversed(descriptors):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def _install_exception_hook(self) -> None:
        old = self._original_excepthook

        def hook(exc_type, exc, tb):
            # Ctrl+C and ordinary SystemExit are intentional process shutdowns,
            # not crash artifacts. Keep the terminal behaviour unchanged and do
            # not pollute crashes/ or future diagnostic bundles with them.
            if issubclass(exc_type, (KeyboardInterrupt, SystemExit)):
                old(exc_type, exc, tb)
                return
            try:
                from .faults import exception_evidence

                text = ''.join(traceback.format_exception(exc_type, exc, tb))
                self.event('harnessy', 'uncaught_exception', level=logging.ERROR,
                           detail=text[-12000:], fault=exception_evidence(exc))
                self._write_crash(text)
                self.capture_system_snapshot('uncaught_exception')
            finally:
                old(exc_type, exc, tb)
        sys.excepthook = hook

    def _write_crash(self, text: str) -> None:
        if self.root is None:
            return
        stamp = datetime.now().astimezone().strftime('%Y-%m-%d_%H%M%S')
        try:
            (self.root / 'crashes' / f'crash-{stamp}.log').write_text(text, encoding='utf-8')
        except OSError:
            pass

    @staticmethod
    def _safe(value: Any, *, depth: int = 0) -> Any:
        if depth > 4:
            return '<depth-limit>'
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            if len(value) > 4000:
                return value[:4000] + f'… <{len(value) - 4000} chars omitted>'
            return value
        if isinstance(value, bytes):
            return f'<{len(value)} bytes>'
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, dict):
            out = {}
            for key, item in list(value.items())[:80]:
                if _is_sensitive_log_key(str(key)):
                    out[str(key)] = '<redacted>'
                else:
                    out[str(key)] = DiagnosticsManager._safe(item, depth=depth + 1)
            return out
        if isinstance(value, (list, tuple, set)):
            return [DiagnosticsManager._safe(v, depth=depth + 1) for v in list(value)[:80]]
        return DiagnosticsManager._safe(str(value), depth=depth + 1)

    def event(self, channel: str, event: str, *, level: int = logging.INFO, **fields: Any) -> None:
        if event.startswith('test_target_'):
            # Preserve sparse boot/lifecycle evidence independently of verbose
            # model and workspace command traffic in runtime.log.
            channel = 'targets'
        if channel == 'context_tuning':
            self.record_context_tuning(event, **fields)
            return
        if channel == 'database':
            from .sqlite import validate_database_event

            payload = validate_database_event(event, {
                **fields,
                'observed_at': fields.get('observed_at', datetime.now().astimezone().isoformat(timespec='milliseconds')),
                'session_id': self.session_dir.name if self.session_dir is not None else None,
            })
            if payload is None:
                return
            self.logger(channel).log(level, json.dumps(payload, ensure_ascii=False, separators=(',', ':')))
            # Do not run shell system probes or touch SQLite from its own error
            # hot path. The precise operation evidence has already been stored.
            return
        logger = self.logger(channel)
        if event in WORKSPACE_RECOVERY_EVENTS:
            payload = validate_workspace_recovery_event(event, fields)
            if payload is not None:
                logger.log(level, json.dumps(payload, ensure_ascii=False, separators=(',', ':'), allow_nan=False))
            return
        from harnessy.agent.permission_provenance import (PERMISSION_ACKNOWLEDGEMENT_EVENTS,
                                                        validate_permission_acknowledgement_event)
        if event in PERMISSION_ACKNOWLEDGEMENT_EVENTS:
            payload = validate_permission_acknowledgement_event(event, fields)
            if payload is None:
                payload = validate_permission_acknowledgement_event('permission_acknowledgement_trace_failed', {
                    **fields, 'phase': 'request' if event == 'permission_acknowledgement_input' else 'response',
                    'failure_kind': 'invalid_receipt',
                })
            if payload is not None:
                logger.log(level, json.dumps(payload, ensure_ascii=False, separators=(',', ':')))
            return
        from .queue_observations import QUEUE_EVENTS, validate_queue_event
        if event in QUEUE_EVENTS:
            payload = validate_queue_event(event, fields)
            if payload is not None:
                logger.log(level, json.dumps(payload, ensure_ascii=False, separators=(',', ':')))
            return
        from .controller_observations import CONTROLLER_OBSERVATION_EVENTS, validate_controller_observation
        if event in CONTROLLER_OBSERVATION_EVENTS:
            payload = validate_controller_observation(event, fields)
            if payload is not None:
                logger.log(level, json.dumps(payload, ensure_ascii=False, separators=(',', ':')))
            return
        from .startup import STARTUP_EVENTS, validate_startup_event
        if event in STARTUP_EVENTS:
            payload = validate_startup_event(event, fields)
            if payload is not None:
                logger.log(level, json.dumps(payload, ensure_ascii=False, separators=(',', ':')))
            return
        if event in {'tool_permission_decision', 'tool_approval_policy_resolved'}:
            from .permissions import validate_permission_event

            payload = validate_permission_event(event, fields)
            if payload is not None:
                logger.log(level, json.dumps(payload, ensure_ascii=False, separators=(',', ':')))
            return
        # Process the field names too: passing only each value bypassed the
        # secret-key checks for top-level password/token fields.
        payload = {
            'event': event,
            **{k: (_controller_evidence(v, trusted=True) if k == 'controller_evidence'
                    and _trusted_controller_event({'event': event, **fields})
                    else _safe_event_field(k, v)) for k, v in fields.items()},
        }
        logger.log(level, json.dumps(payload, ensure_ascii=False, separators=(',', ':')))
        if level >= logging.ERROR:
            # Capture raw evidence immediately, but never build a ZIP from the
            # logging hot path. Bundle creation is explicit/on-demand only.
            self.capture_system_snapshot(event)

    def record_context_tuning(self, event: str, **fields: Any) -> None:
        """Record one compact tuning fact in current and cross-session ledgers."""
        with self._lock:
            if not self._configured or self.session_dir is None:
                return
            payload = _context_tuning_payload(event, {
                **fields,
                'schema_version': 1,
                'record_id': str(uuid.uuid4()),
                'session_id': self.session_dir.name,
                'observed_at': datetime.now().astimezone().isoformat(timespec='milliseconds'),
            })
            if payload is not None:
                self.logger('context_tuning').info(json.dumps(payload, ensure_ascii=False, separators=(',', ':')))

    def _write_collector_script(self, app_root: Path) -> None:
        """Install a tiny recovery collector inside .logs/.

        This remains usable even when the NiceGUI page is unavailable. It calls
        the same bounded ZIP collector as the GUI Download Diagnostics action.
        """
        if self.root is None:
            return
        script = self.root / 'collect_diagnostics.py'
        payload = '''#!/usr/bin/env python3
from pathlib import Path
import sys

APP_ROOT = Path(__file__).resolve().parent.parent
SRC = APP_ROOT / "src"
if SRC.is_dir():
    sys.path.insert(0, str(SRC))
else:
    sys.path.insert(0, str(APP_ROOT))

from harnessy.diagnostics import collect_existing_diagnostics
import argparse

parser = argparse.ArgumentParser(description="Create a HarnessyXO diagnostics bundle.")
parser.add_argument(
    "--include-content", action="store_true",
    help="Include raw conversation/model/tool payload content and raw bounded VM boot logs. Default export is privacy-safe.",
)
args = parser.parse_args()
path = collect_existing_diagnostics(APP_ROOT, include_content=args.include_content)
if path is None:
    raise SystemExit("Could not create HarnessyXO diagnostics bundle.")
print(path)
'''
        try:
            script.write_text(payload, encoding='utf-8')
            script.chmod(0o755)
        except OSError:
            pass

    def logger(self, channel: str) -> logging.Logger:
        name = channel if channel in _LOG_NAMES else 'harnessy'
        return logging.getLogger(f'harnessy.{name}')

    def stream_event(self, event: Any) -> None:
        # Legacy callers remain valid. Stamp the receipt itself so a retained
        # protocol tail can be joined to a local invocation without response
        # content, provider IDs or an assumed one-chunk/one-token relationship.
        if isinstance(event, dict):
            from .model_requests import timestamp, validate_protocol_receipt
            event = dict(event)
            event['timestamp'] = (timestamp(event.get('timestamp'))
                or datetime.now().astimezone().isoformat(timespec='milliseconds'))
            if event.get('kind') == 'model_protocol_receipt':
                event = validate_protocol_receipt(event)
        try:
            line = json.dumps(self._safe(event), ensure_ascii=False, separators=(',', ':'))
        except Exception:
            line = repr(event)[:4000]
        encoded = line + '\n'
        with self._lock:
            if self._stream_tail.maxlen and len(self._stream_tail) >= self._stream_tail.maxlen:
                removed = self._stream_tail.popleft()
                self._stream_tail_chars -= len(removed) + 1
            self._stream_tail.append(line)
            self._stream_tail_chars += len(encoded)
            while self._stream_tail and self._stream_tail_chars > _STREAM_TAIL_MAX_CHARS:
                removed = self._stream_tail.popleft()
                self._stream_tail_chars -= len(removed) + 1
            try:
                if self._stream_tail_file is not None:
                    self._stream_tail_file.write(encoded)
                    self._stream_tail_file_bytes += len(encoded.encode('utf-8', errors='replace'))
                elif self.latest_dir is not None:
                    with (self.latest_dir / 'backend-stream-tail.log').open('a', encoding='utf-8') as handle:
                        handle.write(encoded)
                    self._stream_tail_file_bytes += len(encoded.encode('utf-8', errors='replace'))
            except OSError:
                pass
            # The append log can temporarily contain events which have already
            # fallen out of the in-memory ring. Compact only after roughly one
            # extra ring's worth of writes instead of rewriting up to 2 MB for
            # every streamed protocol chunk.
            if self._stream_tail_file_bytes > (_STREAM_TAIL_MAX_CHARS * 2):
                self._flush_stream_tail()

    def _flush_stream_tail(self) -> None:
        if self.latest_dir is None:
            return
        payload = '\n'.join(self._stream_tail) + ('\n' if self._stream_tail else '')
        try:
            if self._stream_tail_file is not None:
                self._stream_tail_file.seek(0)
                self._stream_tail_file.truncate(0)
                self._stream_tail_file.write(payload)
                self._stream_tail_file.flush()
            else:
                path = self.latest_dir / 'backend-stream-tail.log'
                path.write_text(payload, encoding='utf-8')
            self._stream_tail_file_bytes = len(payload.encode('utf-8', errors='replace'))
        except OSError:
            pass

    def capture_system_snapshot(self, reason: str) -> None:
        if not self._configured and self.root is None:
            return
        snapshot: dict[str, Any] = {
            'reason': reason,
            'pid': os.getpid(),
            'platform': platform.platform(),
            'python': sys.version.split()[0],
        }
        try:
            usage = shutil.disk_usage(self.root or Path.cwd())
            snapshot['disk'] = {'total': usage.total, 'used': usage.used, 'free': usage.free}
        except OSError:
            pass
        # Immediate fault snapshots must not enumerate unrelated process names
        # or run a shell. The explicit export collects bounded host probes.
        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            snapshot['process_resources'] = {'user_seconds': usage.ru_utime,
                'system_seconds': usage.ru_stime, 'maximum_rss_native_units': usage.ru_maxrss,
                'major_faults': usage.ru_majflt, 'minor_faults': usage.ru_minflt}
        except (ImportError, OSError, ValueError):
            snapshot['process_resource_status'] = 'unavailable'
        try:
            from .host_state import collect_resource_snapshot
            snapshot['host_resources'] = collect_resource_snapshot()
        except Exception as exc:
            from .technical import technical_error_evidence
            snapshot['host_resources'] = {'status': 'collector_failed',
                                          'technical_error': technical_error_evidence(exc)}
        self.logger('system').info(json.dumps({key: _safe_event_field(key, value)
            for key, value in snapshot.items()}, ensure_ascii=False, separators=(',', ':')))

    def _prune_sessions(self) -> None:
        if self.root is None:
            return
        sessions = self.root / 'sessions'
        rows = sorted((p for p in sessions.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True)
        for path in rows[_SESSION_KEEP:]:
            shutil.rmtree(path, ignore_errors=True)
        rows = sorted((p for p in sessions.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True)
        def tree_size(path: Path) -> int:
            total = 0
            for item in path.rglob('*'):
                try:
                    if item.is_file():
                        total += item.stat().st_size
                except OSError:
                    pass
            return total
        sizes = {path: tree_size(path) for path in rows}
        total = sum(sizes.values())
        for path in reversed(rows):
            if total <= _TOTAL_SESSION_CAP_BYTES:
                break
            if self.session_dir is not None and path == self.session_dir:
                continue
            total -= sizes.get(path, 0)
            shutil.rmtree(path, ignore_errors=True)

    def refresh_bundle(self, *, include_content: bool = False) -> Path | None:
        """Create a point-in-time support ZIP only when explicitly requested.

        The default export is privacy-safe and omits conversation/model/tool
        payload content. Raw payload export requires an explicit opt-in.
        """
        with self._bundle_lock:
            if self.root is None:
                return None
            with self._lock:
                self._flush_stream_tail()
                for name in _LOG_NAMES:
                    for handler in self.logger(name).handlers:
                        try:
                            handler.flush()
                        except Exception:
                            pass
                for handle in (self._stdout_file, self._stderr_file):
                    try:
                        if handle is not None:
                            handle.flush()
                    except Exception:
                        pass
            return collect_existing_diagnostics(self.root.parent, include_content=include_content)

    def close(self) -> None:
        with self._lock:
            if not self._configured:
                return
            try:
                self.event('harnessy', 'shutdown', pid=os.getpid())
            except Exception:
                pass
            if self._stream_tail_file is not None:
                try:
                    self._stream_tail_file.flush()
                    self._stream_tail_file.close()
                except OSError:
                    pass
                self._stream_tail_file = None
            self._configured = False


def _session_is_launcher_only(path: Path) -> bool:
    if not _diagnostic_source_allowed(path / 'harnessy.log'):
        return True
    payload = _read_snapshot_bytes(path / 'harnessy.log', tail_bytes=512 * 1024)
    if payload is None:
        return False
    text = payload.decode('utf-8', errors='ignore')
    application_events = (
        '"event":"controller_access_token_enabled"',  # previous releases
        '"event":"controller_password_login_enabled"',
    )
    handoff = '"event":"launcher_exec_application"' in text
    if not handoff:
        from .startup import is_kvm_refresh_handoff
        for line in text.splitlines():
            parts = line.split(' ', 3)
            if len(parts) != 4:
                continue
            try:
                body = json.loads(parts[3])
            except (ValueError, TypeError, RecursionError):
                continue
            if isinstance(body, dict) and body.get('event') == 'launcher_kvm_setup' and is_kvm_refresh_handoff(body):
                handoff = True
                break
    return handoff and not any(event in text for event in application_events)


def _zip_snapshot_file(zf: zipfile.ZipFile, source: Path, arcname: str, *, tail_bytes: int | None = None) -> None:
    """Write exactly the bytes present at snapshot time, even if logs keep growing."""
    payload, row = (zf.read_log(source, arcname, tail_bytes=tail_bytes)
                    if isinstance(zf, _DiagnosticsZipFile) else
                    (_read_snapshot_bytes(source, tail_bytes=tail_bytes), None))
    if payload is None:
        return
    if re.fullmatch(r'.+\.log(?:\.\d+)?', source.name):
        # Launcher/storage receipts are reviewed metadata in both export modes;
        # content-rich mode does not turn those records into raw error exports.
        payload = _sanitize_startup_log_bytes(payload)
        payload = _sanitize_model_receipt_bytes(payload)
    try:
        if isinstance(zf, _DiagnosticsZipFile):
            zf.write_log(arcname, payload, row, 'explicit_content_mode')
        else:
            zf.writestr(arcname, payload)
    except OSError:
        return


def _privacy_marker(value: Any, *, label: str = 'content') -> str:
    """Return a correlation-friendly marker without retaining the original text."""
    if value is None:
        return f'<redacted {label}; chars=0>'
    if isinstance(value, bytes):
        raw = value
        chars = len(value)
    else:
        text = str(value)
        raw = text.encode('utf-8', errors='replace')
        chars = len(text)
    digest = hashlib.sha256(raw).hexdigest()[:12]
    return f'<redacted {label}; chars={chars}; sha256_12={digest}>'


def _json_shape(value: Any) -> Any:
    """Describe payload structure without retaining user/model values."""
    if isinstance(value, dict):
        return {
            'type': 'object',
            'keys': [str(k) for k in list(value.keys())[:80]],
            'value_types': {str(k): type(v).__name__ for k, v in list(value.items())[:80]},
        }
    if isinstance(value, (list, tuple)):
        return {
            'type': 'array',
            'count': len(value),
            'item_types': sorted({type(v).__name__ for v in list(value)[:80]}),
        }
    return {'type': type(value).__name__, 'chars': len(str(value or ''))}


def _summarize_arguments(value: Any) -> dict[str, Any]:
    raw_text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    summary: dict[str, Any] = {
        'redacted': True,
        'chars': len(raw_text),
        'sha256_12': hashlib.sha256(raw_text.encode('utf-8', errors='replace')).hexdigest()[:12],
    }
    parsed = value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            summary['valid_json'] = True
        except json.JSONDecodeError as exc:
            summary['valid_json'] = False
            summary['json_error'] = {'line': exc.lineno, 'column': exc.colno, 'char': exc.pos}
            return summary
    if isinstance(parsed, dict):
        summary['top_level_keys'] = [str(k) for k in list(parsed.keys())[:80]]
        summary['value_types'] = {str(k): type(v).__name__ for k, v in list(parsed.items())[:80]}
    elif isinstance(parsed, list):
        summary['top_level_type'] = 'array'
        summary['count'] = len(parsed)
    else:
        summary['top_level_type'] = type(parsed).__name__
    return summary


def _summarize_tool_calls(value: Any) -> dict[str, Any]:
    rows = value if isinstance(value, list) else [value]
    calls: list[dict[str, Any]] = []
    for index, item in enumerate(rows[:80]):
        if not isinstance(item, dict):
            calls.append({'index': index, 'shape': _json_shape(item)})
            continue
        fn = item.get('function') if isinstance(item.get('function'), dict) else {}
        name = str(fn.get('name') or item.get('name') or '')
        raw_args = fn.get('arguments', item.get('arguments'))
        call: dict[str, Any] = {
            'index': item.get('index', index),
            'id_present': bool(item.get('id')),
            'type': str(item.get('type') or 'function'),
            'function_name': name[:160] if name else '',
        }
        if raw_args is not None:
            call['arguments'] = _summarize_arguments(raw_args)
        calls.append(call)
    return {'redacted': True, 'count': len(rows), 'calls': calls}


def _summarize_stream_segments(value: Any) -> dict[str, Any]:
    rows = value if isinstance(value, list) else []
    kinds: dict[str, dict[str, int]] = {}
    for row in rows[:2500]:
        if not isinstance(row, dict):
            continue
        kind = str(row.get('kind') or 'unknown')[:80]
        content = str(row.get('content') or '')
        bucket = kinds.setdefault(kind, {'segments': 0, 'chars': 0})
        bucket['segments'] += 1
        bucket['chars'] += len(content)
    return {'redacted': True, 'count': len(rows), 'kinds': kinds}


def _legacy_error_summary(value: Any) -> Any:
    recognized_classes = {
        name for module in (builtins, sqlite3) for name, item in vars(module).items()
        if isinstance(item, type) and issubclass(item, BaseException)
    }
    recognized_codes = {
        'sqlite_database_locked', 'sqlite_database_unavailable',
        'sqlite_storage_full', 'sqlite_disk_io_error',
    }
    if isinstance(value, dict):
        # Exporting an already-private log must preserve its useful evidence
        # rather than hashing the redaction object as if it were raw prose.
        out: dict[str, Any] = {'redacted': True}
        chars = value.get('chars')
        if isinstance(chars, int) and not isinstance(chars, bool) and 0 <= chars < 2**63:
            out['chars'] = chars
        digest = value.get('sha256_12')
        if isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{12}', digest):
            out['sha256_12'] = digest
        if isinstance(value.get('exception_class'), str) and value['exception_class'] in recognized_classes:
            out['exception_class'] = value['exception_class']
        if isinstance(value.get('error_code'), str) and value['error_code'] in recognized_codes:
            out['error_code'] = value['error_code']
        positions = value.get('json_error')
        if isinstance(positions, dict):
            safe_positions = {key: positions[key] for key in ('line', 'column', 'char')
                              if type(positions.get(key)) is int and 0 <= positions[key] < 2**63}
            if safe_positions:
                out['json_error'] = safe_positions
        return out
    text = str(value or '')
    if not text:
        return ''
    out: dict[str, Any] = {
        'redacted': True,
        'chars': len(text),
        'sha256_12': hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()[:12],
    }
    match = re.search(r'line\s+(\d+)\s+column\s+(\d+)\s+\(char\s+(\d+)\)', text, re.IGNORECASE)
    if match:
        out['json_error'] = {'line': int(match.group(1)), 'column': int(match.group(2)), 'char': int(match.group(3))}
    class_match = re.search(r'\b([A-Za-z_][A-Za-z0-9_]*(?:Error|Exception))\b', text)
    if class_match and class_match.group(1) in recognized_classes:
        out['exception_class'] = class_match.group(1)
    for signature, label in (
        ('database is locked', 'sqlite_database_locked'),
        ('unable to open database file', 'sqlite_database_unavailable'),
        ('database or disk is full', 'sqlite_storage_full'),
        ('disk i/o error', 'sqlite_disk_io_error'),
    ):
        if signature in text.lower():
            out['error_code'] = label
            break
    return out


def _safe_error_summary(value: Any) -> Any:
    """Retain technical causes instead of reducing all errors to a fingerprint."""
    from .technical import technical_error_evidence, validate_technical_evidence
    from .faults import exception_evidence, validate_fault_evidence
    if isinstance(value, BaseException):
        return {'technical_error': technical_error_evidence(value), 'fault': exception_evidence(value)}
    legacy = _legacy_error_summary(value)
    technical = (validate_technical_evidence(value.get('technical_error')) if isinstance(value, dict)
                 and isinstance(value.get('technical_error'), dict) else
                 validate_technical_evidence(value) if isinstance(value, dict)
                 and value.get('schema_version') == 1 else technical_error_evidence(value))
    if isinstance(legacy, dict):
        legacy['technical_error'] = technical
        if isinstance(value, dict) and (fault := validate_fault_evidence(value.get('fault'))) is not None:
            legacy['fault'] = fault
        return legacy
    return {'technical_error': technical} if value else legacy


def _privacy_safe_value(value: Any, *, key: str = '') -> Any:
    lowered = key.lower()
    if _is_sensitive_log_key(lowered):
        return '<redacted>'
    if not key and isinstance(value, dict):
        if isinstance(value.get('event'), str) and value['event'] in WORKSPACE_RECOVERY_EVENTS:
            return validate_workspace_recovery_event(value['event'], value)
        from harnessy.agent.permission_provenance import (PERMISSION_ACKNOWLEDGEMENT_EVENTS,
                                                        validate_permission_acknowledgement_event)
        if isinstance(value.get('event'), str) and value['event'] in PERMISSION_ACKNOWLEDGEMENT_EVENTS:
            safe = validate_permission_acknowledgement_event(value['event'], value)
            return safe if safe is not None else validate_permission_acknowledgement_event(
                'permission_acknowledgement_trace_failed', {
                    **value, 'phase': 'request' if value['event'] == 'permission_acknowledgement_input' else 'response',
                    'failure_kind': 'invalid_receipt',
                })
        from .queue_observations import QUEUE_EVENTS, validate_queue_event
        if isinstance(value.get('event'), str) and value['event'] in QUEUE_EVENTS:
            return validate_queue_event(value['event'], value)
        from .controller_observations import CONTROLLER_OBSERVATION_EVENTS, validate_controller_observation
        if isinstance(value.get('event'), str) and value['event'] in CONTROLLER_OBSERVATION_EVENTS:
            return validate_controller_observation(value['event'], value)
    if not key and _trusted_controller_event(value):
        return {str(name): (_controller_evidence(item, trusted=True) if name == 'controller_evidence'
                           else _privacy_safe_value(item, key=str(name)))
                for name, item in list(value.items())[:120]}
    from .operational import LABEL_FIELDS, operational_label
    if lowered == 'error_class':
        return operational_label(value, 'exception_class')
    if (lowered in LABEL_FIELDS or lowered in {'error_type', 'exception_class', 'exception_type'}) and not isinstance(value, dict):
        return operational_label(value, lowered)
    if lowered == 'technical_error':
        from .technical import validate_technical_evidence
        return validate_technical_evidence(value)
    if lowered == 'controller_evidence':
        return _controller_evidence(value)
    if lowered == 'host_resources':
        from .host_state import validate_resource_snapshot
        return validate_resource_snapshot(value)
    if lowered == 'environment_action':
        return value if isinstance(value, str) and value in {'create', 'start', 'stop', 'reset', 'rebuild', 'destroy', 'restore', 'snapshot', 'tools', 'network', 'resources'} else None
    if lowered == 'lifecycle_action':
        return value if isinstance(value, str) and value in {'create', 'start', 'stop', 'reset', 'rebuild', 'destroy'} else None
    if lowered == 'preservation_reason':
        return value if isinstance(value, str) and value in {'before_start', 'before_reset', 'before_delete',
            'controller_error', 'controller_timeout', 'controller_cancelled', 'controller_spawn_error'} else None
    if lowered == 'failure_receipt':
        raw = value if isinstance(value, dict) else {}
        safe = {'schema_version': 1}
        if raw.get('status') in {'preserved', 'no_evidence', 'limited', 'unavailable', 'unsafe', 'rejected', 'busy', 'cancelled'}:
            safe['status'] = raw['status']
        for name in ('receipt_id', 'operation_id', 'command_id'):
            if isinstance(raw.get(name), str) and re.fullmatch(r'[0-9a-f]{32}', raw[name]):
                safe[name] = raw[name]
        for name in ('sources', 'bytes_saved'):
            if type(raw.get(name)) is int and 0 <= raw[name] <= 2**31:
                safe[name] = raw[name]
        if raw.get('guest_console_omitted') is True:
            safe['guest_console_omitted'] = True
        return safe
    if lowered == 'requested_vm_config':
        value = value if isinstance(value, dict) else {}
        safe = {name: value[name] for name, allowed in {
            'architecture': {'arm64', 'amd64'}, 'vm_type': {'qemu', 'vz'},
        }.items() if isinstance(value.get(name), str) and value[name] in allowed}
        for name in ('cpus', 'memory_mb', 'disk_gb'):
            if type(value.get(name)) is int and 0 <= value[name] <= 2**31:
                safe[name] = value[name]
        return safe
    if lowered == 'processes' and isinstance(value, str):
        # Older system snapshots used ps output. Keep numeric resource facts
        # while removing unrelated executable names and all command text.
        samples = []
        for line in value.splitlines()[:512]:
            match = re.match(r'\s*(\d+)\s+(\d+)\s+(\d+(?:\.\d+)?)\s+(\d+(?:\.\d+)?)\s+', line)
            if match:
                samples.append({'pid': int(match[1]), 'ppid': int(match[2]),
                    'cpu_percent': float(match[3]), 'memory_percent': float(match[4])})
        return {'samples': samples, 'command_content_omitted': True}
    if lowered == 'memory' and isinstance(value, str):
        facts = {}
        for name, numbers in re.findall(r'(?m)^(Mem|Swap):\s+([\d\s]+)$', value):
            facts[name.lower()] = [int(item) for item in numbers.split()[:7]]
        return facts or {'raw_content_omitted': True}
    from .model_requests import (SOURCE_ENUMS, identifier, numeric_projection, provenance_projection,
                                 source_label, timestamp, validate_protocol_receipt)
    if isinstance(value, dict) and value.get('kind') == 'model_protocol_receipt':
        return validate_protocol_receipt(value)
    if lowered == 'client_request_id':
        return identifier(value)
    if lowered == 'timestamp':
        return timestamp(value)
    if lowered in SOURCE_ENUMS:
        return source_label(value, lowered)
    if lowered == 'observation':
        return value if isinstance(value, str) and value in {'health_check', 'transport_closed'} else None
    if lowered in {'usage', 'timings', 'backend_timings', 'prompt_progress', 'native_prompt_progress'}:
        kind = 'timings' if lowered == 'backend_timings' else 'prompt_progress' if lowered == 'native_prompt_progress' else lowered
        return numeric_projection(value, kind=kind)
    if lowered in {'provenance', 'output_provenance'}:
        return provenance_projection(value)
    from .startup import (STARTUP_EVENTS, validate_archive_check,
                          validate_startup_event, validate_storage_issue)
    if isinstance(value, dict) and isinstance(value.get('event'), str) and value['event'] in STARTUP_EVENTS:
        return validate_startup_event(value['event'], value) or {'event': value['event']}
    if lowered == 'archive_check':
        return validate_archive_check(value)
    if lowered == 'storage_issue':
        return validate_storage_issue(value)
    if isinstance(value, dict) and isinstance(value.get('event'), str) and value['event'] in {'tool_permission_decision', 'tool_approval_policy_resolved'}:
        from .permissions import validate_permission_event

        return validate_permission_event(value['event'], value) or {'event': 'tool_permission_decision'}
    if lowered in {'permission_decision', 'permission_states', 'required_permissions'}:
        from .permissions import PERMISSION_FAMILIES, validate_permission_decision, validate_permission_states

        if lowered == 'permission_decision':
            return validate_permission_decision(value)
        if lowered == 'permission_states':
            return validate_permission_states(value)
        return [item for item in value[:len(PERMISSION_FAMILIES)]
                if isinstance(item, str) and item in PERMISSION_FAMILIES] if isinstance(value, (list, tuple)) else []
    if lowered in {'approval_wait_seconds', 'execution_duration_seconds', 'coordination_wait_seconds'}:
        from .permissions import safe_timing

        return safe_timing(value)
    if lowered in {'permission_source', 'permission_reason', 'permission_target_mode', 'permission_target_state', 'target_validation'}:
        from .permissions import PERMISSION_ENUMS

        if value is None:
            return None
        return value if isinstance(value, str) and value in PERMISSION_ENUMS[lowered] else _privacy_marker(value, label=lowered)
    if lowered.startswith('target_'):
        from .test_target_logs import TARGET_ENUMS
        if lowered in TARGET_ENUMS:
            return value if isinstance(value, str) and value in TARGET_ENUMS[lowered] else _privacy_marker(value, label=lowered)
        if lowered == 'target_id':
            return value if isinstance(value, str) and re.fullmatch(r'[0-9a-f]{32}', value) else _privacy_marker(value, label=lowered)
    if isinstance(value, dict) and value.get('event') in {
        'vm_controller_command', 'environment_command_started', 'environment_command_finished',
        'environment_command_timeout', 'environment_command_cancelled',
    } and 'controller_action' not in value:
        # Older raw controller logs retain argv. Extract only the fixed command
        # verb before redaction so a failed guest command is not called a boot
        # failure; neither paths nor shell arguments become summary evidence.
        argv = value.get('argv')
        if isinstance(argv, list) and argv:
            position = 1 if argv[0] == '--tty=false' else 0
            action = argv[position] if len(argv) > position else None
            if isinstance(action, str) and action in _VM_DIAGNOSTIC_ENUMS['controller_action']:
                value = {**value, 'controller_action': action}
    if lowered == 'sqlite_errorcode':
        return value if type(value) is int and 0 <= value <= 2**31 - 1 else None
    if lowered == 'sqlite_errorname':
        return value if isinstance(value, str) and value in _RECOVERY_ENUMS['sqlite_errorname'] else None
    if lowered == 'database_worker_returncode':
        return value if type(value) is int and -255 <= value <= 255 else None
    if lowered in _WORKSPACE_DATABASE_ENUMS:
        return value if isinstance(value, str) and value in _WORKSPACE_DATABASE_ENUMS[lowered] else _privacy_marker(value, label=lowered)
    if lowered in _VM_DIAGNOSTIC_ENUMS:
        if value is None:
            return None
        return value if isinstance(value, str) and value in _VM_DIAGNOSTIC_ENUMS[lowered] else _privacy_marker(value, label=lowered)
    if lowered in _VM_COMMAND_ID_KEYS:
        if value is None:
            return None
        if isinstance(value, str) and re.fullmatch(r'[0-9a-f]{32}', value):
            return value
        return _privacy_marker(value, label=lowered)
    if isinstance(value, dict) and isinstance(value.get('event'), str) and value['event'].startswith('sqlite_'):
        from .sqlite import validate_database_event

        return validate_database_event(value['event'], value) or {'event': 'sqlite_unrecognized_record'}
    if lowered in {'fault', 'exception_evidence'}:
        from .faults import validate_fault_evidence

        return validate_fault_evidence(value)
    if lowered in {'frames', 'frame_stack'}:
        from .faults import validate_frames

        return validate_frames(value)
    if lowered in {'operation_origin', 'transaction_origin', 'last_operation_origin'}:
        from .faults import validate_frame_evidence

        return validate_frame_evidence(value)
    if lowered in {'last_stage', 'last_event'}:
        from .faults import RUN_DIAGNOSTIC_EVENTS, RUN_DIAGNOSTIC_STAGES

        allowed = RUN_DIAGNOSTIC_STAGES if lowered == 'last_stage' else RUN_DIAGNOSTIC_EVENTS
        return value if isinstance(value, str) and value in allowed else None
    if lowered in {'resume_tail_status', 'resume_tail_reason'}:
        permitted = {
            'resume_tail_status': {'unavailable', 'retained', 'objective_only'},
            'resume_tail_reason': {'missing_user_objective', 'objective_exceeds_budget',
                                   'entire_previous_turn', 'incomplete_tool_block',
                                   'unit_exceeds_remaining_budget'},
        }
        return value if isinstance(value, str) and value in permitted[lowered] else _privacy_marker(value, label=lowered)
    # File evidence must survive the default export unchanged: re-hashing a
    # digest or timestamp destroys the read -> edit -> human-inspection chain.
    # Validate each newly retained string, rather than allowing arbitrary text
    # merely because it was logged under a trusted-looking metadata key.
    if lowered in {'sha256', 'path_id', 'resolved_path_id', 'db_id'}:
        text = str(value or '')
        return text.lower() if re.fullmatch(r'[0-9a-fA-F]{64}', text) else _privacy_marker(value, label=lowered)
    if lowered == 'working_root_id':
        text = str(value or '')
        return text.lower() if re.fullmatch(r'[0-9a-fA-F]{24,64}', text) else _privacy_marker(value, label=lowered)
    if lowered in {'observed_at', 'verified_at'}:
        if value is None:
            return None
        try:
            return datetime.fromisoformat(str(value)).isoformat(timespec='milliseconds')
        except ValueError:
            return _privacy_marker(value, label=lowered)
    if lowered == 'operation_id':
        text = str(value or '')
        return text if re.fullmatch(r'[A-Za-z0-9_.:-]{1,160}', text) else _privacy_marker(value, label=lowered)
    if lowered in {'working_root_kind', 'scope', 'algorithm', 'source', 'mapping_status'}:
        permitted = {
            'working_root_kind': {'base_files', 'imported_copy', 'historical_branch', 'timeline_rewind', 'files_subdirectory', 'isolated_copy', 'unknown'},
            'scope': {'whole_file'},
            'algorithm': {'sha256'},
            'source': {'tool', 'ui'},
            'mapping_status': {'HOST_ONLY', 'VERIFIED_SAME_STORAGE', 'PROBE_FAILED', 'MISMATCH', 'NOT_CHECKED'},
        }
        if isinstance(value, str) and value in permitted[lowered]:
            return value
        if value is None:
            return None
        return _privacy_marker(value, label=lowered)
    if lowered in {'tool_calls', 'calls'}:
        return _summarize_tool_calls(value)
    if lowered in {'arguments', 'raw_arguments'}:
        return _summarize_arguments(value)
    if lowered == 'stream_segments':
        return _summarize_stream_segments(value)
    if lowered in {'error', 'detail', 'exception', 'traceback'}:
        return _safe_error_summary(value)
    if lowered in _PRIVACY_PAYLOAD_KEYS:
        return _privacy_marker(value, label=lowered or 'content')
    if lowered in _PRIVACY_PATH_KEYS or lowered.endswith('_path') or lowered.endswith('_url'):
        return _privacy_marker(value, label='path-or-location')
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        return _privacy_marker(value, label='bytes')
    if isinstance(value, Path):
        return _privacy_marker(str(value), label='path')
    if isinstance(value, dict):
        return {str(k): _privacy_safe_value(v, key=str(k)) for k, v in list(value.items())[:120]}
    if isinstance(value, (list, tuple, set)):
        # Key/name lists and HarnessyXO-generated semantic labels describe
        # protocol/execution structure and contain no model/project text.
        if lowered.endswith('_keys') or lowered in {'keys', 'delta_keys', 'message_keys'} or lowered in _PRIVACY_SAFE_STRING_LIST_KEYS:
            return [str(v)[:160] for v in list(value)[:120]]
        return [_privacy_safe_value(v, key=key) for v in list(value)[:120]]
    text = str(value)
    if lowered == 'stage' and text in {'scan', 'large_files', 'project_git'}:
        return text
    if lowered in _PRIVACY_SAFE_STRING_KEYS:
        return text[:1000]
    if lowered in {'workspace_id', 'chat_id', 'run_id', 'call_id', 'owner_id'}:
        return text[:160]
    # Preserve short machine-like reason labels, but never arbitrary prose.
    if lowered == 'reason' and len(text) <= 128 and re.fullmatch(r'[A-Za-z0-9_.:/-]+', text):
        return text
    return _privacy_marker(text, label=lowered or 'string')


def _sanitize_startup_log_bytes(payload: bytes) -> bytes:
    """Validate only launcher receipts while retaining other opted-in content."""
    from .startup import STARTUP_EVENTS, validate_startup_event
    out: list[bytes] = []
    for line in payload.splitlines(keepends=True):
        parts = line.split(b' ', 3)
        if len(parts) != 4:
            out.append(line)
            continue
        try:
            decoded = json.loads(parts[3])
            event = decoded.get('event') if isinstance(decoded, dict) else None
            safe = validate_startup_event(event, decoded) if isinstance(event, str) and event in STARTUP_EVENTS else None
        except (ValueError, TypeError, RecursionError):
            safe = None
        if safe is None:
            out.append(line)
        else:
            out.append(b' '.join(parts[:3]) + b' ' + json.dumps(
                safe, ensure_ascii=False, separators=(',', ':'), allow_nan=False,
            ).encode('utf-8') + (b'\n' if line.endswith(b'\n') else b''))
    return b''.join(out)


def _sanitize_model_receipt_bytes(payload: bytes) -> bytes:
    """New numeric protocol receipts remain content-free in either ZIP mode."""
    from .model_requests import validate_protocol_receipt
    out: list[bytes] = []
    for line in payload.splitlines(keepends=True):
        try:
            value = json.loads(line)
            safe = validate_protocol_receipt(value)
        except (ValueError, TypeError, RecursionError):
            safe = None
        out.append((json.dumps(safe, ensure_ascii=False, separators=(',', ':'),
                               allow_nan=False).encode() + b'\n') if safe is not None else line)
    return b''.join(out)


def _sanitize_structured_log_bytes(payload: bytes) -> bytes:
    """Sanitize HarnessyXO's structured log format without leaking payload text."""
    out: list[str] = []
    text = payload.decode('utf-8', errors='replace')
    for line in text.splitlines():
        # Logging format: YYYY-MM-DD HH:MM:SS,mmm LEVEL <JSON message>
        parts = line.split(' ', 3)
        if len(parts) != 4:
            out.append(json.dumps({'kind': 'unstructured_technical_observation',
                'content_omitted': True, 'evidence': _safe_error_summary(line)}, separators=(',', ':')))
            continue
        date, clock, level, message = parts
        try:
            datetime.strptime(f'{date} {clock}', '%Y-%m-%d %H:%M:%S,%f')
            if level not in {'INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL'}:
                raise ValueError('invalid level')
        except ValueError:
            out.append(json.dumps({'kind': 'unstructured_technical_observation',
                'content_omitted': True, 'evidence': _safe_error_summary(line)}, separators=(',', ':')))
            continue
        try:
            decoded = json.loads(message)
        except (ValueError, RecursionError):
            out.append(f'{date} {clock} {level} {_privacy_marker(message, label="unstructured-log-message")}')
            continue
        try:
            safe = _privacy_safe_value(decoded)
        except (ValueError, TypeError, RecursionError):
            safe = {'event': 'diagnostic_record_unavailable'}
        out.append(f'{date} {clock} {level} ' + json.dumps(safe, ensure_ascii=False, separators=(',', ':')))
    return ('\n'.join(out) + ('\n' if out else '')).encode('utf-8')


def _sanitize_database_log_bytes(payload: bytes) -> bytes:
    """Database records remain content-free in both diagnostics modes."""
    from .sqlite import validate_database_event

    lines: list[str] = []
    for line in payload.decode('utf-8', errors='replace').splitlines():
        parts = line.split(' ', 3)
        if len(parts) != 4 or parts[2] not in {'INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL'}:
            continue
        try:
            clock = datetime.strptime(f'{parts[0]} {parts[1]}', '%Y-%m-%d %H:%M:%S,%f')
            decoded = json.loads(parts[3])
        except (ValueError, RecursionError):
            continue
        if not isinstance(decoded, dict):
            continue
        safe = validate_database_event(decoded.get('event'), decoded)
        if safe is not None:
            stamp = clock.strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
            lines.append(f'{stamp} {parts[2]} ' + json.dumps(safe, ensure_ascii=False, separators=(',', ':')))
    return ('\n'.join(lines) + ('\n' if lines else '')).encode('utf-8')


def _context_tuning_rows(payload: bytes) -> list[dict[str, Any]]:
    """Revalidate persisted metadata, including manually replaced log files."""
    rows: list[dict[str, Any]] = []
    for line in payload.decode('utf-8', errors='replace').splitlines():
        parts = line.split(' ', 3)
        if len(parts) != 4 or parts[2] not in {'INFO', 'WARNING', 'ERROR', 'DEBUG'}:
            continue
        try:
            datetime.strptime(f'{parts[0]} {parts[1]}', '%Y-%m-%d %H:%M:%S,%f')
            decoded = json.loads(parts[3])
        except (ValueError, RecursionError):
            continue
        if not isinstance(decoded, dict):
            continue
        safe = _context_tuning_payload(decoded.get('event'), decoded)
        if safe is not None:
            rows.append(safe)
    return rows


def _sanitize_context_tuning_log_bytes(payload: bytes) -> bytes:
    # Canonical rows carry their own timezone-aware observed_at timestamp. The
    # regenerated prefix contains no unvalidated text from the source file.
    lines = []
    for row in _context_tuning_rows(payload):
        observed = row.get('observed_at')
        if observed is None:
            continue
        clock = datetime.fromisoformat(observed).strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        lines.append(f'{clock} INFO ' + json.dumps(row, ensure_ascii=False, separators=(',', ':')))
    return ('\n'.join(lines) + ('\n' if lines else '')).encode('utf-8')


def _context_log_paths(folder: Path, backups: int) -> list[Path]:
    # Highest numbered rotation is oldest. Never glob arbitrary files or links
    # into this deliberately narrow diagnostics source.
    return [folder / f'context_tuning.log.{n}' for n in range(backups, 0, -1)] + [folder / 'context_tuning.log']


def _zip_context_tuning_history(zf: zipfile.ZipFile, root: Path) -> None:
    rows: list[dict[str, Any]] = []
    paths = _context_log_paths(root / 'context-history', _CONTEXT_HISTORY_BACKUPS)
    oldest_rotation_present = paths[0].is_file()
    for path in paths:
        payload = _read_snapshot_bytes(path, tail_bytes=_CONTEXT_HISTORY_MAX_BYTES)
        if payload is None:
            continue
        zf.writestr(str(path.relative_to(root)), _sanitize_context_tuning_log_bytes(payload))
        rows.extend(row for row in _context_tuning_rows(payload) if row.get('observed_at'))
    event_counts: dict[str, int] = {}
    for row in rows:
        event_counts[row['event']] = event_counts.get(row['event'], 0) + 1
    zf.writestr('CONTEXT_TUNING.jsonl', ''.join(
        json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n' for row in rows
    ))
    zf.writestr('CONTEXT_TUNING_RETENTION.json', json.dumps({
        'schema_version': 1,
        'scope': 'retained_cross_session_context_history',
        'history_max_bytes': _CONTEXT_HISTORY_MAX_BYTES * (_CONTEXT_HISTORY_BACKUPS + 1),
        'session_max_bytes': _CONTEXT_LOG_MAX_BYTES * (_CONTEXT_LOG_BACKUPS + 1),
        'retained_records': len(rows),
        'retained_event_counts': event_counts,
        'oldest_observed_at': rows[0].get('observed_at') if rows else None,
        'newest_observed_at': rows[-1].get('observed_at') if rows else None,
        'oldest_rotation_present': oldest_rotation_present,
        'history_is_bounded': True,
        'counts_describe_retained_records': True,
        'note': 'Per-run counters in records distinguish memory retries, upward probes, and epoch rebuilds. Retained-record counts do not prove a complete lifetime history.',
    }, ensure_ascii=False, indent=2))


def _sanitize_stream_tail_bytes(payload: bytes) -> bytes:
    out: list[str] = []
    text = payload.decode('utf-8', errors='replace')
    for line in text.splitlines():
        try:
            decoded = json.loads(line)
        except (ValueError, RecursionError):
            out.append(json.dumps({'kind': 'unstructured', 'content': _privacy_marker(line)}, separators=(',', ':')))
            continue
        try:
            safe = _privacy_safe_value(decoded)
        except (ValueError, TypeError, RecursionError):
            safe = {'kind': 'diagnostic_record_unavailable'}
        out.append(json.dumps(safe, ensure_ascii=False, separators=(',', ':')))
    return ('\n'.join(out) + ('\n' if out else '')).encode('utf-8')


_ENVIRONMENT_TIMELINE_PREFIXES = (
    'vm_', 'environment_operation_', 'environment_command_', 'workspace_mapping_', 'test_target_',
)
_ENVIRONMENT_TIMELINE_EVENTS = {
    'vm_tool_exec_start', 'vm_tool_exec_complete', 'vm_tool_exec_timeout',
    'vm_tool_exec_cancelled', 'vm_tool_exec_error',
}


def _privacy_environment_timeline(latest: Path) -> list[dict[str, Any]]:
    """Build a bounded semantic VM/tool timeline from structured logs only."""
    rows: list[dict[str, Any]] = []
    for channel in ('runtime', 'tools', 'targets'):
        source = latest / f'{channel}.log'
        payload = _read_snapshot_bytes(source, tail_bytes=2 * 1024 * 1024)
        if payload is None:
            continue
        for line in payload.decode('utf-8', errors='replace').splitlines():
            parts = line.split(' ', 3)
            if len(parts) != 4:
                continue
            date, clock, level, message = parts
            try:
                datetime.strptime(f'{date} {clock}', '%Y-%m-%d %H:%M:%S,%f')
                if level not in {'INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL'}:
                    continue
                decoded = json.loads(message)
            except (ValueError, RecursionError):
                continue
            if not isinstance(decoded, dict):
                continue
            event = str(decoded.get('event') or '')
            claim_event = event == 'model_step_complete' and bool(decoded.get('environment_claim_signals'))
            if not claim_event and event not in _ENVIRONMENT_TIMELINE_EVENTS and not event.startswith(_ENVIRONMENT_TIMELINE_PREFIXES):
                continue
            try:
                safe = _privacy_safe_value(decoded)
            except (ValueError, TypeError, RecursionError):
                continue
            if not isinstance(safe, dict):
                continue
            rows.append({
                'timestamp': f'{date} {clock}',
                'channel': channel,
                'level': level,
                **safe,
            })
    rows.sort(key=lambda row: str(row.get('timestamp') or ''))
    return rows[-600:]


def _privacy_test_target_timeline(latest: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for suffix in ('.3', '.2', '.1', ''):
        payload = _read_snapshot_bytes(latest / f'targets.log{suffix}', tail_bytes=512 * 1024)
        for line in (payload.decode('utf-8', errors='replace').splitlines() if payload else []):
            parts = line.split(' ', 3)
            if len(parts) != 4 or parts[2] not in {'INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL'}:
                continue
            try:
                stamp = f'{parts[0]} {parts[1]}'
                datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S,%f')
                decoded = json.loads(parts[3])
                if not isinstance(decoded, dict) or not isinstance(decoded.get('event'), str) or not decoded['event'].startswith('test_target_'):
                    continue
                safe = _privacy_safe_value(decoded)
            except (ValueError, TypeError, RecursionError):
                continue
            rows.append({**safe, 'timestamp': stamp, 'channel': 'targets', 'level': parts[2]})
    rows.sort(key=lambda row: row['timestamp'])
    return rows[-600:]


def _privacy_file_operation_timeline(latest: Path) -> list[dict[str, Any]]:
    """Bounded read/write/inspect evidence, including recent tool-log rotations.

    This is an observation chronology, not an assertion that every write made by
    arbitrary shell commands or external editors was monitored.
    """
    rows: deque[dict[str, Any]] = deque(maxlen=_FILE_OPERATION_TIMELINE_MAX_EVENTS)
    for name in ('tools.log.2', 'tools.log.1', 'tools.log'):
        payload = _read_snapshot_bytes(latest / name, tail_bytes=_FILE_OPERATION_TIMELINE_LOG_TAIL_BYTES)
        if payload is None:
            continue
        for line in payload.decode('utf-8', errors='replace').splitlines():
            parts = line.split(' ', 3)
            if len(parts) != 4:
                continue
            date, clock, level, message = parts
            try:
                datetime.strptime(f'{date} {clock}', '%Y-%m-%d %H:%M:%S,%f')
                if level not in {'INFO', 'WARNING', 'ERROR', 'DEBUG', 'CRITICAL'}:
                    continue
                decoded = json.loads(message)
            except (ValueError, RecursionError):
                continue
            if not isinstance(decoded, dict) or decoded.get('event') != 'file_operation_receipt':
                continue
            try:
                safe = _privacy_safe_value(decoded)
            except (ValueError, TypeError, RecursionError):
                continue
            if isinstance(safe, dict):
                rows.append({'timestamp': f'{date} {clock}', 'channel': 'tools', 'level': level, **safe})
    return sorted(rows, key=lambda row: str(row.get('timestamp') or ''))


def _read_snapshot_bytes(source: Path, *, tail_bytes: int | None = None) -> bytes | None:
    if not _diagnostic_source_allowed(source):
        return None
    descriptor = None
    try:
        # A pre-open path check cannot prevent replacement by a symlink/FIFO.
        # Use the same no-follow, nonblocking descriptor traversal as VM tails.
        from .vm_logs import _open_regular
        descriptor = _open_regular(source.absolute())
        size = os.fstat(descriptor).st_size
        with os.fdopen(descriptor, 'rb') as handle:
            descriptor = None
            if tail_bytes is not None and size > tail_bytes:
                handle.seek(size - tail_bytes)
                return handle.read(tail_bytes)
            return handle.read(size)
    except (OSError, ValueError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _zip_privacy_safe_log(
    zf: zipfile.ZipFile, source: Path, arcname: str, *, tail_bytes: int | None = None,
) -> None:
    is_context = re.fullmatch(r'context_tuning\.log(?:\.\d+)?', source.name)
    is_database = re.fullmatch(r'database\.log(?:\.\d+)?', source.name)
    if is_context:
        cap = _CONTEXT_HISTORY_MAX_BYTES if source.parent.name == 'context-history' else _CONTEXT_LOG_MAX_BYTES
        tail_bytes = min(tail_bytes, cap) if tail_bytes is not None else cap
    elif is_database:
        tail_bytes = min(tail_bytes, _DATABASE_LOG_MAX_BYTES) if tail_bytes is not None else _DATABASE_LOG_MAX_BYTES
    payload, row = (zf.read_log(source, arcname, tail_bytes=tail_bytes)
                    if isinstance(zf, _DiagnosticsZipFile) else
                    (_read_snapshot_bytes(source, tail_bytes=tail_bytes), None))
    if payload is None:
        return
    if is_context:
        payload = _sanitize_context_tuning_log_bytes(payload)
    elif is_database:
        payload = _sanitize_database_log_bytes(payload)
    elif source.name == 'backend-stream-tail.log':
        payload = _sanitize_stream_tail_bytes(payload)
    elif source.name.startswith(('console', 'crash-')):
        payload = _project_freeform_technical_bytes(payload)
    else:
        payload = _sanitize_structured_log_bytes(payload)
    if isinstance(zf, _DiagnosticsZipFile):
        zf.write_log(arcname, payload, row, 'technical_metadata_content_omitted')
    else:
        zf.writestr(arcname, payload)


def _project_freeform_technical_bytes(payload: bytes) -> bytes:
    """Free-form console/crash output is not a trusted controller channel."""
    from .technical import technical_error_evidence
    from .native_faults import project_native_faults
    rows = [{'evidence_source': 'native_fault', 'content_omitted': True, 'native_fault': fault}
            for fault in project_native_faults(payload)]
    for number, line in enumerate(payload.decode('utf-8', errors='replace').splitlines()[-8192:]):
        # Preserve structured app events when stdout capture duplicated them;
        # arbitrary guest/model/file lines retain only technical signatures.
        projected = _safe_error_summary(line)
        rows.append({'line': number + 1, 'content_omitted': True,
                     'evidence_source': 'text_signature',
                     'technical_error': projected.get('technical_error', {}) if isinstance(projected, dict) else {},
                     **{key: projected[key] for key in ('exception_class', 'error_code', 'json_error')
                        if isinstance(projected, dict) and key in projected},
                     'chars': len(line), 'sha256_12': hashlib.sha256(line.encode()).hexdigest()[:12]})
    return ''.join(json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n' for row in rows).encode()


def _export_retained_technical_logs(zf, root: Path, latest: Path, *, include_content: bool) -> None:
    """Cover retained application sessions and crash/console technical facts.

    The current/previous aliases remain compatible; every source attempt and
    all source limits are disclosed by EXPORT_COVERAGE.json.
    """
    from itertools import islice
    existing = set(zf.namelist())
    for channel in _LOG_NAMES:
        expected = latest / (channel + '.log')
        if 'latest/' + expected.name not in existing:
            _zip_privacy_safe_log(zf, expected, 'latest/' + expected.name)
    sessions = root / 'sessions'
    folders = []
    try:
        for folder in islice(sessions.iterdir(), 256):
            if folder.is_dir() and not folder.is_symlink():
                folders.append(folder)
        folders.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    except OSError:
        pass
    current = (_read_snapshot_bytes(latest / 'CURRENT_SESSION.txt', tail_bytes=256) or b'').decode(errors='replace').strip()
    for folder in folders[:_SESSION_KEEP]:
        if folder.name == current:
            continue
        session = _validated_session_id(folder.name) or hashlib.sha256(folder.name.encode()).hexdigest()
        try:
            paths = sorted(islice(folder.rglob('*'), 2048))
        except OSError:
            continue
        for source in paths:
            if not re.fullmatch(r'.+\.log(?:\.\d+)?', source.name):
                continue
            known = re.fullmatch(r'(?:' + '|'.join(re.escape(name) for name in _LOG_NAMES)
                                + r'|console|console-error|backend-stream-tail)\.log(?:\.\d+)?', source.name)
            name = source.name if known else 'additional-' + hashlib.sha256(str(source.relative_to(folder)).encode()).hexdigest()[:16] + '.log'
            member = f'retained-session-logs/{session}/{name}'
            if member in existing:
                continue
            if include_content:
                _zip_snapshot_file(zf, source, member)
            else:
                _zip_privacy_safe_log(zf, source, member)
            existing.add(member)
    crash_dir = root / 'crashes'
    try:
        crashes = sorted(islice(crash_dir.glob('*.log'), 256), key=lambda path: path.lstat().st_mtime, reverse=True)
    except OSError:
        crashes = []
    for source in crashes[:20]:
        member = 'crash-technical/' + hashlib.sha256(source.name.encode()).hexdigest()[:24] + '.jsonl'
        _zip_privacy_safe_log(zf, source, member)


def _privacy_manifest(*, include_content: bool = False) -> str:
    return (
        ('HarnessyXO diagnostics privacy manifest\n' if include_content else 'HarnessyXO privacy-safe diagnostics export\n') +
        '==========================================\n\n'
        + ('Conversation/model/tool content was explicitly requested for this export. '\
           'Curated content-free evidence is still validated as described below.\n\n' if include_content else
        'This is the default diagnostics mode. Conversation text, model reasoning/answers, '\
        'raw tool arguments/results, prompt bodies, file contents, stream payload previews, '\
        'and path/location values are omitted or replaced with length/hash/shape metadata.\n\n') +
        ('Raw console/crash captures and payload logs are included in content-rich mode. '\
         'Credential stores and log symlinks into settings remain excluded.\n\n' if include_content else
        'Raw console capture and raw crash files are intentionally excluded because arbitrary '\
        'free-form output cannot be reliably proven free of project/chat content. ') + 'Structured '\
        'errors, event timing, token/context metrics, finish reasons, tool names, argument '\
        'shape/JSON parse positions, privacy-safe shell operation classes, recognized errno/error '\
        'signatures, environment-claim labels, lifecycle deltas, backend status, and system snapshots '\
        'remain available. ENVIRONMENT_TIMELINE.json provides a bounded semantic VM/tool timeline.\n\n'
        'EXPORT_COVERAGE.json records attempted application log sources, original/read/exported lengths, '
        'missing/unsafe/unreadable sources, line omissions and explicit file/byte/retention bounds. '
        'Retained session logs and projected console/crash technical facts are included under those bounds; '
        'arbitrary console/model/guest/file text stays omitted. COLLECTOR_ERRORS.json retains typed collection failures. '
        'HOST_STATE.json captures bounded technical host prerequisites/resources without commands, accounts, '
        'environment values or filesystem paths. CONTROL_PLANE_TIMELINE.json preserves bounded operational receipts, '
        'requested VM configuration, lifecycle/request/exit identities, and trusted sanitized controller diagnostics. '
        'Saved pre-retry/reset/failure VM receipts keep earlier evidence separate from current boot logs.\n\n'
        'SUMMARY.txt and INCIDENTS.json describe recent failures, relevant tool completion, '\
        'nearby event-loop stalls, and missing evidence. EXPORT_METADATA.json identifies '\
        'the session, application/runtime versions when recorded, and capture time with its timezone.\n\n'
        'PERMISSIONS.json contains bounded, content-free tool permission receipts: reviewed permission '
        'families/states, decision source and reason, argument-validation labels, and approval wait '
        'separately from execution and coordination time. It never reads saved settings or exports '
        'commands, target names or credentials. Missing receipts leave the reason for a dialog unverified.\n\n'
        'STARTUP.json contains bounded launcher update outcomes, reviewed application-relative archive '
        'mismatches, executable metadata repairs, and historical host REA storage-validation facts. Storage descendants '
        'outside known runtime components use fixed parent labels. File contents, home paths, raw errors '
        'and credentials are excluded from these receipts in both export modes. The collector reads logs '
        'only and does not check Git, run an installer, or open an application database.\n\n'
        'QUEUE_STATE.json projects bounded queue snapshots and admission transitions recorded by the live app: '
        'typed owner/request IDs, fixed hold/gate states, counts, resume eligibility, and settled orphan-hold '
        'retirements. Project labels, prompts, models, raw reasons, attachments and saved row bodies are excluded. '
        'Export reads these receipts only and never opens a queue database. A global pause snapshot is not '
        'a per-chat admission verdict; owner exemptions and backend inclusion remain separate facts.\n\n'
        'VM_LOGS.json records bounded Lima serial/hostagent source coverage, missing/unsafe/unreadable sources, '
        'and truncation limits. The default vm-logs/ members contain reviewed technical signal records only; '
        'arbitrary guest lines, paths, names and message bodies are omitted. These tails can contain observations '
        'from earlier boots and do not establish an underlying cause by themselves. VM collection reads existing '
        'files only: it opens no database and runs no VM/controller commands.\n\n'
        'TARGET_LOGS.json records separately bounded managed test-target QEMU serial and Lima log coverage, '
        'including unavailable/unsafe sources. target-logs/ contains fixed technical signals; raw tails require '
        'content-rich export. Test-target operation stages, elapsed time, probe attempts, and fixed failure '
        'codes remain in ENVIRONMENT_TIMELINE.json and INCIDENTS.json. Collection never opens target '
        'databases, SSH keys, ports/access metadata, or starts a target. No registered target observations '
        'means missing evidence, not proof that a test target did not exist.\n\n'
        'targets.log has independent bounded retention (four 1 MiB files per current/session channel); '
        'TARGET_TIMELINE.json preserves up to 600 recent target lifecycle records separately from busy '
        'workspace/model traffic. Counts and timelines still describe retained evidence, not lifetime totals.\n\n'
        'Target-view capability URLs are credentials and their entire scoped path/query tails are redacted from '
        'every archive member, including raw content-rich logs. Credential redaction may reduce exported '
        'member byte counts relative to the bounded source measurements.\n\n'
        + ('Raw bounded serial/hostagent tails are also included under vm-logs/ because content-rich mode was '
           'explicitly selected. They may contain guest/project text. Unsafe or symlinked sources remain excluded; '
           'VM_LOGS.json metadata and incident summaries retain reviewed technical evidence only.\n\n' if include_content else '') +
        'Structured fault evidence retains reviewed exception classes, SQLite numeric codes/names, '\
        'bounded exception cause/context chains, and static source module/function/line locations. '\
        'Stack frames never contain local variables, source lines, exception messages, or plaintext '\
        'filesystem paths; external frame locations are represented by SHA-256 identities.\n\n'
        'database.log has independent retention (8 MiB per current/session channel). '\
        'DATABASE_STATE.json is a bounded snapshot of connections already tracked in the collecting process; '\
        'a separately launched recovery collector may have an empty registry even while the app runs. '\
        'collection never opens a database or runs a checkpoint. Database evidence retains hashed '\
        'database/task identities, generated connection/transaction IDs, operation/statement classes, '\
        'transaction ages and origins, cursor/active-operation ages and origins, timing, '\
        'and same-process transaction/cursor/operation candidates. It never '\
        'includes SQL text, bound parameters, database rows, credentials, or plaintext paths. '\
        'Candidates are not proven lock holders; external processes are not identified. '\
        'Database, fault, incident-summary, and metadata evidence remain content-free even in '\
        'an explicitly content-rich export.\n\n'
        'FILE_OPERATIONS.json retains the latest 1,000 available file-tool/UI observations '\
        '(bounded tails of current and rotated tool logs): hashed path identities, working-root '\
        'identities/kinds, exact whole-file SHA-256 digests, byte counts, observation times, '\
        'before/after states, write-applied flags, and host/VM verification status. These '\
        'hashes allow equality comparisons and identification of already-known file content; '\
        'they do not include plaintext paths or file contents. A receipt observes one instant, '\
        'not every external or shell write, and absent evidence does not prove no change.\n\n'
        'CONTEXT_TUNING.jsonl is a compact, timezone-stamped context ledger with independent '
        'cross-session retention (32 MiB), plus current/previous session ledger rotations '
        '(8 MiB each). CONTEXT_TUNING_RETENTION.json states retained-record counts and '
        'bounds. The ledger records only reviewed IDs, fixed labels, numeric request sizes '
        'and counters; arbitrary model names/non-UUID IDs are represented by digests. '
        'Prompt/error bodies and credentials are excluded even in a content-rich export. '
        'Backend-reported usage and estimates are identified separately.\n\n'
        'To intentionally include raw conversation/model/tool content, use the explicit '\
        '"Include conversation/model/tool content" option in the UI or run '\
        '.logs/collect_diagnostics.py --include-content.\n'
    )


def _collect_vm_export(latest: Path, *, include_content: bool) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Keep VM collection optional and bounded; its failure never blocks export."""
    try:
        from .vm_logs import (MAX_EXPORT_BYTES, MAX_VM_FILES, PER_FILE_TAIL_BYTES,
                              VM_LOG_FILENAMES, collect_vm_diagnostics, validate_vm_report)
        collected = collect_vm_diagnostics(latest, include_content=include_content)
        report = validate_vm_report(collected['report'])
        members = collected['members']
        if not isinstance(report, dict) or not isinstance(members, dict) or len(members) > MAX_VM_FILES * (2 if include_content else 1):
            raise ValueError('Invalid bounded VM collection')
        if report.get('mode') != ('raw_bounded_tails' if include_content else 'signals_only'):
            raise ValueError('VM collection mode did not match the requested privacy mode')
        declared = {source[key] for workspace in report.get('workspaces', [])
                    for source in workspace.get('sources', []) if source.get('status') == 'included'
                    for key in ('archive_member', 'raw_archive_member') if key in source}
        if set(members) != declared:
            raise ValueError('VM archive members do not match validated coverage')
        accepted: dict[str, bytes] = {}
        total = 0
        for name, payload in members.items():
            matched = re.fullmatch(r'vm-logs/([0-9a-f]{64})/(.+)\.(technical\.jsonl|raw\.log)', name) if isinstance(name, str) else None
            if matched is None or matched.group(2) not in VM_LOG_FILENAMES:
                raise ValueError('Invalid VM archive member')
            if name.endswith('.raw.log') and not include_content:
                raise ValueError('Raw VM content was not requested')
            cap = PER_FILE_TAIL_BYTES if name.endswith('.raw.log') else MAX_EXPORT_BYTES
            if not isinstance(payload, bytes) or len(payload) > cap:
                raise ValueError('Invalid bounded VM member')
            total += len(payload)
            if total > MAX_EXPORT_BYTES:
                raise ValueError('Invalid bounded VM collection')
            accepted[name] = payload
        # Validation/serialization is part of collection recovery, rather than
        # allowing a malformed report to break an otherwise useful archive.
        json.dumps(report, ensure_ascii=False, allow_nan=False)
        return report, accepted
    except Exception as exc:
        from .technical import technical_error_evidence
        return {'schema_version': 1, 'status': 'unavailable', 'reason': 'collector_failed',
                'mode': 'raw_bounded_tails' if include_content else 'signals_only', 'workspaces': [],
                'technical_error': technical_error_evidence(exc)}, {}


def _collect_test_target_export(latest: Path, *, include_content: bool) -> tuple[dict[str, Any], dict[str, bytes]]:
    try:
        from .test_target_logs import (MAX_EXPORT_BYTES, MAX_TARGET_FILES,
                                      collect_test_target_diagnostics, validate_test_target_report)
        from .vm_logs import PER_FILE_TAIL_BYTES
        collected = collect_test_target_diagnostics(latest, include_content=include_content)
        report = validate_test_target_report(collected['report'])
        members = collected['members']
        if not isinstance(members, dict) or len(members) > MAX_TARGET_FILES * (2 if include_content else 1):
            raise ValueError('Invalid target collection')
        if report['mode'] != ('raw_bounded_tails' if include_content else 'signals_only'):
            raise ValueError('Invalid target privacy mode')
        declared = {source[key] for target in report['targets'] for source in target['sources']
                    if source['status'] == 'included' for key in ('archive_member', 'raw_archive_member') if key in source}
        if set(members) != declared:
            raise ValueError('Invalid target archive coverage')
        total = 0
        for name, payload in members.items():
            if not isinstance(payload, bytes) or len(payload) > (PER_FILE_TAIL_BYTES if name.endswith('.raw.log') else MAX_EXPORT_BYTES):
                raise ValueError('Invalid target member bounds')
            total += len(payload)
            if total > MAX_EXPORT_BYTES:
                raise ValueError('Invalid target collection bounds')
        json.dumps(report, ensure_ascii=False, allow_nan=False)
        return report, members
    except Exception as exc:
        from .technical import technical_error_evidence
        return {'schema_version': 1, 'status': 'unavailable', 'reason': 'collector_failed',
                'mode': 'raw_bounded_tails' if include_content else 'signals_only', 'targets': [],
                'technical_error': technical_error_evidence(exc)}, {}


def collect_existing_diagnostics(app_root: Path, *, include_content: bool = False) -> Path | None:
    """Build a fresh diagnostics ZIP from current logs.

    Privacy-safe export is the default. Raw conversation/model/tool payloads are
    included only when ``include_content=True`` is explicitly requested.
    """
    app_root = Path(app_root).resolve()
    root = app_root / '.logs'
    latest = root / 'latest'
    if not latest.is_dir():
        try:
            from .technical import technical_error_evidence
            log_event('harnessy', 'diagnostics_export_unavailable', reason='latest_logs_missing',
                      technical_error=technical_error_evidence(FileNotFoundError()))
        except Exception:
            pass
        return None
    bundle_name = _FULL_CONTENT_BUNDLE if include_content else _PRIVACY_SAFE_BUNDLE
    target = root / bundle_name
    tmp = root / f'{bundle_name}.tmp'
    try:
        with _DiagnosticsZipFile(tmp, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            from .sqlite import snapshot_database_connections, validate_database_snapshot
            from .support_summary import build_support_summary

            vm_report, vm_members = _collect_vm_export(latest, include_content=include_content)
            target_report, target_members = _collect_test_target_export(latest, include_content=include_content)
            try:
                from .host_state import collect_host_diagnostics, validate_host_diagnostics
                host_report = validate_host_diagnostics(collect_host_diagnostics(application_root=app_root))
            except Exception as exc:
                from .technical import technical_error_evidence
                host_report = {'schema_version': 1, 'status': 'collector_failed',
                               'technical_error': technical_error_evidence(exc)}
            try:
                incidents, summary = build_support_summary(latest, vm_report=vm_report, target_report=target_report,
                                                           host_report=host_report)
            except Exception as exc:
                from .technical import technical_error_evidence
                # Export is itself a recovery action. A corrupt log or summary
                # bug must not prevent collection of the remaining evidence.
                incidents = {'schema_version': 1, 'summary_status': 'unavailable',
                             'reason': 'summary_generation_failed', 'incidents': [],
                             'technical_error': technical_error_evidence(exc)}
                summary = ('HarnessyXO support summary\n\n'
                           'The incident summary could not be generated. Remaining diagnostic evidence is included.\n'
                           'VM_LOGS.json records VM log source coverage; available retained VM evidence is under vm-logs/.\n')
            zf.writestr('SUMMARY.txt', summary)
            zf.writestr('INCIDENTS.json', json.dumps(incidents, ensure_ascii=False, indent=2))
            zf.writestr('PERMISSIONS.json', json.dumps(incidents.get('permission_audit', {
                'schema_version': 1, 'status': 'unavailable', 'reason': 'summary_generation_failed',
            }), ensure_ascii=False, indent=2, allow_nan=False))
            zf.writestr('PERMISSION_ACKNOWLEDGEMENTS.json', json.dumps(incidents.get('permission_acknowledgement_audit', {
                'schema_version': 1, 'status': 'unavailable', 'reason': 'summary_generation_failed',
            }), ensure_ascii=False, indent=2, allow_nan=False))
            zf.writestr('STARTUP.json', json.dumps(incidents.get('startup_audit', {
                'schema_version': 1, 'status': 'unavailable', 'reason': 'summary_generation_failed',
            }), ensure_ascii=False, indent=2, allow_nan=False))
            zf.writestr('QUEUE_STATE.json', json.dumps(incidents.get('queue_audit', {
                'schema_version': 1, 'status': 'unavailable', 'reason': 'summary_generation_failed',
            }), ensure_ascii=False, indent=2, allow_nan=False))
            zf.writestr('MODEL_REQUESTS.json', json.dumps(incidents.get('model_request_audit', {
                'schema_version': 1, 'status': 'unavailable', 'reason': 'summary_generation_failed',
            }), ensure_ascii=False, indent=2, allow_nan=False))
            zf.writestr('DATABASE_RECOVERY.json', json.dumps(incidents.get('workspace_database_recovery', {
                'schema_version': 1, 'status': 'unavailable', 'reason': 'summary_generation_failed',
            }), ensure_ascii=False, indent=2, allow_nan=False))
            zf.writestr('HOST_STATE.json', json.dumps(host_report, ensure_ascii=False, indent=2, allow_nan=False))
            zf.writestr('CONTROL_PLANE_TIMELINE.json', json.dumps({
                'schema_version': 1, 'coverage': incidents.get('control_plane_coverage', {}),
                'records': incidents.get('control_plane_timeline', []),
            }, ensure_ascii=False, indent=2, allow_nan=False))
            zf.writestr('COLLECTOR_ERRORS.json', json.dumps({
                'schema_version': 1, 'collectors': {name: value for name, value in
                    (('summary', incidents), ('workspace_vm', vm_report), ('test_targets', target_report), ('host', host_report))
                    if value.get('technical_error')},
            }, ensure_ascii=False, indent=2, allow_nan=False))
            zf.writestr('VM_LOGS.json', json.dumps(vm_report, ensure_ascii=False, indent=2, allow_nan=False))
            for name, payload in vm_members.items():
                zf.writestr(name, payload)
            zf.writestr('TARGET_LOGS.json', json.dumps(target_report, ensure_ascii=False, indent=2, allow_nan=False))
            for name, payload in target_members.items():
                zf.writestr(name, payload)
            zf.writestr('TARGET_TIMELINE.json', json.dumps(_privacy_test_target_timeline(latest), ensure_ascii=False, indent=2))
            zf.writestr('EXPORT_METADATA.json', json.dumps(_export_metadata(latest), ensure_ascii=False, indent=2))
            try:
                database_state = validate_database_snapshot(snapshot_database_connections())
            except Exception:
                database_state = {'schema_version': 1, 'snapshot_status': 'unavailable'}
            if not isinstance(database_state, dict):
                database_state = {'schema_version': 1, 'snapshot_status': 'unavailable'}
            database_state['capture_scope'] = 'collecting_process_tracking_registry'
            database_state['collector_pid'] = os.getpid()
            zf.writestr('DATABASE_STATE.json', json.dumps(database_state, ensure_ascii=False, indent=2))
            zf.writestr(
                'FILE_OPERATIONS.json',
                json.dumps(_privacy_file_operation_timeline(latest), ensure_ascii=False, indent=2).encode('utf-8'),
            )
            manifest_name = 'CONTENT_MODE.txt' if include_content else 'PRIVACY.txt'
            zf.writestr(manifest_name, _privacy_manifest(include_content=include_content))
            if not include_content:
                timeline = _privacy_environment_timeline(latest)
                zf.writestr(
                    'ENVIRONMENT_TIMELINE.json',
                    json.dumps(timeline, ensure_ascii=False, indent=2).encode('utf-8'),
                )
            from itertools import islice
            for path in sorted(islice(latest.rglob('*'), 2048)):
                if not path.is_file() and not path.is_symlink():
                    continue
                arcname = str(path.relative_to(root))
                if re.fullmatch(r'.+\.log(?:\.\d+)?', path.name):
                    known = re.fullmatch(r'(?:' + '|'.join(re.escape(name) for name in _LOG_NAMES)
                        + r'|console|console-error|backend-stream-tail)\.log(?:\.\d+)?', path.name)
                    if not known or path.parent != latest:
                        arcname = 'latest/additional-' + hashlib.sha256(str(path.relative_to(latest)).encode()).hexdigest()[:16] + '.log'
                if re.fullmatch(r'context_tuning\.log(?:\.\d+)?', path.name):
                    _zip_privacy_safe_log(zf, path, arcname)
                    continue
                if re.fullmatch(r'database\.log(?:\.\d+)?', path.name):
                    _zip_privacy_safe_log(zf, path, arcname)
                    continue
                if path.name == 'SESSION_METADATA.json':
                    try:
                        decoded = json.loads(_read_snapshot_bytes(path, tail_bytes=16 * 1024) or b'{}')
                    except (ValueError, RecursionError):
                        decoded = {}
                    zf.writestr(arcname, json.dumps(_validated_session_metadata(decoded), ensure_ascii=False, indent=2))
                    continue
                if path.name == 'CURRENT_SESSION.txt':
                    identity = _validated_session_id((_read_snapshot_bytes(path, tail_bytes=256) or b'').decode('utf-8', errors='replace').strip())
                    zf.writestr(arcname, (identity or 'unknown') + '\n')
                    continue
                if include_content:
                    _zip_snapshot_file(zf, path, arcname)
                    continue
                if re.fullmatch(r'.+\.log(?:\.\d+)?', path.name):
                    _zip_privacy_safe_log(zf, path, arcname)

            _zip_context_tuning_history(zf, root)

            current_name = ''
            try:
                current_name = (_read_snapshot_bytes(latest / 'CURRENT_SESSION.txt', tail_bytes=256) or b'').decode('utf-8', errors='ignore').strip()
            except OSError:
                pass
            sessions_dir = root / 'sessions'
            candidates: list[Path] = []
            if sessions_dir.is_dir():
                try:
                    candidates = sorted(
                        (p for p in sessions_dir.iterdir() if p.is_dir() and p.name != current_name),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True,
                    )
                except OSError:
                    candidates = []
            previous = next((p for p in candidates if not _session_is_launcher_only(p)), None)
            if previous is not None:
                previous_id = _validated_session_id(previous.name) or hashlib.sha256(previous.name.encode('utf-8')).hexdigest()
                zf.writestr('previous-session-tail/SESSION.txt', previous_id + '\n')
                for name in _LOG_NAMES:
                    if name == 'context_tuning':
                        for path in _context_log_paths(previous, _CONTEXT_LOG_BACKUPS):
                            if path.is_file():
                                _zip_privacy_safe_log(zf, path, f'previous-session-tail/{path.name}')
                        continue
                    path = previous / f'{name}.log'
                    if not path.is_file():
                        continue
                    arcname = f'previous-session-tail/{name}.log'
                    if name == 'database':
                        _zip_privacy_safe_log(zf, path, arcname, tail_bytes=_PREVIOUS_SESSION_LOG_TAIL_BYTES)
                    elif include_content:
                        _zip_snapshot_file(zf, path, arcname, tail_bytes=_PREVIOUS_SESSION_LOG_TAIL_BYTES)
                    else:
                        _zip_privacy_safe_log(zf, path, arcname, tail_bytes=_PREVIOUS_SESSION_LOG_TAIL_BYTES)

            crash_dir = root / 'crashes'
            if include_content and crash_dir.is_dir():
                try:
                    crashes = sorted(
                        (p for p in crash_dir.glob('*') if p.is_file()),
                        key=lambda p: p.stat().st_mtime,
                        reverse=True,
                    )[:3]
                except OSError:
                    crashes = []
                for path in crashes:
                    _zip_snapshot_file(zf, path, str(path.relative_to(root)))
            _export_retained_technical_logs(zf, root, latest, include_content=include_content)
            coverage = zf.source_coverage.report()
            coverage['archive_members'] = [{'name': info.filename, 'exported_bytes': info.file_size}
                                           for info in zf.infolist()]
            zf.writestr('EXPORT_COVERAGE.json', json.dumps(coverage, ensure_ascii=False, indent=2, allow_nan=False))
        tmp.replace(target)
        return target
    except (OSError, zipfile.BadZipFile) as exc:
        try:
            from .technical import technical_error_evidence
            log_event('harnessy', 'diagnostics_export_failed', technical_error=technical_error_evidence(exc))
        except Exception:
            pass
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        return None


diagnostics = DiagnosticsManager()


def configure_diagnostics(app_root: Path, *, version: str = 'dev') -> None:
    diagnostics.configure(app_root, version=version)


def get_logger(channel: str) -> logging.Logger:
    return diagnostics.logger(channel)


def log_event(channel: str, event: str, **fields: Any) -> None:
    diagnostics.event(channel, event, **fields)


def record_context_tuning(event: str, **fields: Any) -> None:
    diagnostics.record_context_tuning(event, **fields)


def log_stream_event(event: Any) -> None:
    diagnostics.stream_event(event)


def capture_system_snapshot(reason: str) -> None:
    diagnostics.capture_system_snapshot(reason)


def refresh_diagnostics_bundle(
    *, abnormal_reason: str | None = None, include_content: bool = False,
) -> Path | None:
    if abnormal_reason:
        diagnostics.event('harnessy', 'abnormal_event', level=logging.ERROR, reason=abnormal_reason)
    return diagnostics.refresh_bundle(include_content=include_content)
