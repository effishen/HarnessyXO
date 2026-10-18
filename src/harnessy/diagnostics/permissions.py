"""Reviewed permission receipts, without settings, arguments or target names."""
from __future__ import annotations

import hashlib
import math
import re
from typing import Any

PERMISSION_STATES = frozenset({'off', 'ask', 'on'})
PERMISSION_EVENTS = frozenset({'tool_permission_decision', 'tool_approval_policy_resolved'})
PERMISSION_FAMILIES = frozenset({
    'filesystem_read', 'filesystem_write', 'attachments', 'memory', 'shell',
    'processes', 'git_read', 'git_write', 'browser', 'web', 'code_intelligence',
    'rea', 'diagnostics', 'external_targets',
})
# Keep this privacy projection explicit. Action labels, command rules, target
# identifiers and saved connection settings are never diagnostic fields.
TARGET_ACTION_PERMISSIONS = frozenset({
    'allow_status', 'allow_list', 'allow_exec', 'allow_copy_to', 'allow_copy_from',
    'vm_start', 'vm_stop', 'vm_snapshot', 'vm_restore', 'exec_privilege',
    'exec_packages', 'exec_services', 'exec_disks_mounts', 'exec_power',
    'exec_firewall', 'exec_users_groups', 'exec_process_isolation',
    'exec_remote_network', 'exec_system_paths', 'outside_test_root',
})
PERMISSION_ENUMS = {
    'permission_source': frozenset({'run_start', 'saved_settings', 'unavailable'}),
    'permission_reason': frozenset({
        'blocked_off', 'policy_unavailable', 'target_invalid', 'ask', 'global_on',
        'target_on', 'read_only', 'owned_session', 'approved_once', 'target_unavailable',
        'blocked_target_action', 'selected_on',
    }),
    'permission_target_mode': frozenset({'full', 'selected', 'ask', 'on', 'not_applicable'}),
    'permission_target_state': frozenset({
        'enabled', 'disabled', 'missing', 'invalid', 'not_found', 'not_applicable',
    }),
    'target_validation': frozenset({'missing', 'invalid', 'not_found', 'disabled'}),
}
PERMISSION_PHASES = frozenset({
    'before_approval', 'after_approval', 'after_coordination', 'before_execution',
})
PERMISSION_TIMINGS = frozenset({
    'approval_wait_seconds', 'execution_duration_seconds', 'coordination_wait_seconds',
})
_DECISION_FIELDS = {
    'source': 'permission_source', 'reason': 'permission_reason',
    'target_mode': 'permission_target_mode', 'target_state': 'permission_target_state',
}
_TOOLS = frozenset({
    'attach_file', 'browser_back', 'browser_click', 'browser_close', 'browser_dom',
    'browser_open', 'browser_reload', 'browser_screenshot', 'browser_type',
    'browser_wait', 'copy_attachment_to_project', 'delegate_task', 'delete_path',
    'describe_tool', 'diagnostics', 'find_references', 'find_symbol',
    'get_active_model', 'get_attachment_strategy', 'get_backend_status',
    'get_context_usage', 'get_file_fingerprint', 'get_generation_metrics',
    'get_last_request', 'get_task_state', 'get_tool_history', 'get_workspace_state',
    'git_branch', 'git_commit', 'git_diff', 'git_log', 'git_restore', 'git_show',
    'git_status', 'go_to_definition', 'list_attachments', 'list_external_targets',
    'list_files', 'list_processes', 'list_project_access', 'list_skills',
    'list_tool_categories', 'make_directory', 'move_path', 'package_working_copy',
    'poll_process', 'publish_output', 'rea_analyze', 'rea_query', 'rea_status',
    'rea_tools', 'read_attachment', 'read_chat_message', 'read_file',
    'read_project_memory', 'read_skill', 'remember', 'replace_in_file',
    'run_command', 'search_attachment', 'search_chat_history', 'search_text',
    'search_tools', 'search_upstream_memory', 'send_process_input', 'start_process',
    'stop_process', 'target_copy_from', 'target_copy_to', 'target_exec',
    'target_list_files', 'target_status', 'test_vm_control', 'update_checkpoint',
    'update_task_state', 'web_download', 'web_find', 'web_open', 'web_search',
    'workspace_symbols', 'write_file',
})
_CATEGORIES = frozenset({
    'filesystem', 'attachments', 'memory', 'shell', 'processes', 'git', 'browser',
    'web', 'code_intelligence', 'rea', 'diagnostics', 'external_targets',
    'continuity', 'agents', 'skills', 'discovery',
})


def safe_timing(value: Any) -> int | float | None:
    if type(value) in (int, float) and 0 <= value <= 2**63 - 1 and math.isfinite(value):
        return value
    return None


def validate_permission_states(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {key: value[key] for key in sorted(PERMISSION_FAMILIES)
            if key in value and isinstance(value[key], str) and value[key] in PERMISSION_STATES}


def validate_target_action_permissions(value: Any) -> dict[str, str]:
    """Retain only reviewed action IDs and canonical Off/Ask/On states."""
    if not isinstance(value, dict):
        return {}
    return {key: value[key] for key in sorted(TARGET_ACTION_PERMISSIONS)
            if key in value and isinstance(value[key], str) and value[key] in PERMISSION_STATES}


def validate_permission_decision(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    for key, field in _DECISION_FIELDS.items():
        item = value.get(key)
        if isinstance(item, str) and item in PERMISSION_ENUMS[field]:
            safe[key] = item
    if isinstance(value.get('effective'), str) and value['effective'] in PERMISSION_STATES:
        safe['effective'] = value['effective']
    if isinstance(value.get('changed'), bool):
        safe['changed'] = value['changed']
    if isinstance(value.get('states'), dict):
        safe['states'] = validate_permission_states(value['states'])
    if isinstance(value.get('target_actions'), dict):
        safe['target_actions'] = validate_target_action_permissions(value['target_actions'])
    return safe


def validate_permission_event(event: Any, value: Any) -> dict[str, Any] | None:
    if not isinstance(event, str) or event not in PERMISSION_EVENTS or not isinstance(value, dict):
        return None
    safe: dict[str, Any] = {'event': event}
    for key, permitted in PERMISSION_ENUMS.items():
        item = value.get(key)
        if isinstance(item, str) and item in permitted:
            safe[key] = item
    if isinstance(value.get('reason'), str) and value['reason'] in PERMISSION_ENUMS['permission_reason']:
        safe['reason'] = value['reason']
    for key, permitted in (('tool', _TOOLS), ('category', _CATEGORIES),
                           ('permission', PERMISSION_STATES), ('phase', PERMISSION_PHASES),
                           ('execution_status', frozenset({'running', 'completed', 'failed', 'blocked', 'denied', 'cancelled'}))):
        item = value.get(key)
        if isinstance(item, str) and item in permitted:
            safe[key] = item
    for key in ('permission_changed', 'approval_required', 'approved'):
        if isinstance(value.get(key), bool):
            safe[key] = value[key]
    for key in ('workspace_id', 'chat_id', 'run_id', 'call_id'):
        item = value.get(key)
        if not isinstance(item, str) or not item:
            continue
        if re.fullmatch(r'(?:[0-9a-f]{32}|[0-9a-f]{64}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}|call_[0-9a-f]{8,64})', item):
            safe[key] = item
        else:
            safe[key] = hashlib.sha256(item.encode('utf-8', errors='replace')).hexdigest()
    for key in ('step', 'sequence'):
        if type(value.get(key)) is int and 0 <= value[key] <= 2**63 - 1:
            safe[key] = value[key]
    for key in PERMISSION_TIMINGS:
        item = safe_timing(value.get(key))
        if item is not None:
            safe[key] = item
    if isinstance(value.get('permission_states'), dict):
        safe['permission_states'] = validate_permission_states(value['permission_states'])
    if isinstance(value.get('target_action_permissions'), dict):
        safe['target_action_permissions'] = validate_target_action_permissions(value['target_action_permissions'])
    if isinstance(value.get('required_permissions'), (list, tuple)):
        safe['required_permissions'] = [item for item in value['required_permissions'][:len(PERMISSION_FAMILIES)]
                                        if isinstance(item, str) and item in PERMISSION_FAMILIES]
    if isinstance(value.get('permission_decision'), dict):
        safe['permission_decision'] = validate_permission_decision(value['permission_decision'])
    return safe
