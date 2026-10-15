"""Fixed, content-free observations of an owned Lima controller process."""
from __future__ import annotations

import math
import re
from typing import Any
import uuid


CONTROLLER_OBSERVATION_EVENTS = frozenset({
    'environment_command_parent_exited', 'environment_command_output_handoff',
    'environment_command_heartbeat',
})
_ACTIONS = frozenset({'start', 'create', 'stop', 'delete', 'factory-reset', 'restart'})


def _uuid(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) not in {32, 36}:
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    return value if value.lower() in {parsed.hex, str(parsed)} else None


def validate_controller_observation(event: Any, value: Any) -> dict[str, Any] | None:
    if not isinstance(event, str) or event not in CONTROLLER_OBSERVATION_EVENTS or not isinstance(value, dict):
        return None
    command = value.get('command_id')
    if (value.get('provider') != 'lima' or not isinstance(value.get('controller_action'), str)
            or value['controller_action'] not in _ACTIONS
            or not isinstance(command, str) or not re.fullmatch(r'[0-9a-f]{32}', command)):
        return {'event': event, 'observation_status': 'invalid_context'}
    safe: dict[str, Any] = {'event': event, 'provider': 'lima', 'command_id': command,
                            'controller_action': value['controller_action']}
    for key in ('workspace_id', 'operation_id'):
        identifier = _uuid(value.get(key))
        if identifier:
            safe[key] = identifier
    if isinstance(value.get('environment_action'), str) and value['environment_action'] in {'create', 'start', 'stop', 'reset', 'rebuild', 'destroy',
                                           'restore', 'snapshot', 'tools', 'network'}:
        safe['environment_action'] = value['environment_action']
    for key, choices in {'controller_state': {'running', 'exited'},
                         'completion_phase': {'running_controller', 'collecting_output'},
                         'output_capture': {'anonymous_files'},
                         'capture_scope': {'direct_controller_lifetime'}}.items():
        if isinstance(value.get(key), str) and value[key] in choices:
            safe[key] = value[key]
    if value.get('controller_returncode') is None:
        safe['controller_returncode'] = None
    elif type(value.get('controller_returncode')) is int and -2**31 <= value['controller_returncode'] < 2**31:
        safe['controller_returncode'] = value['controller_returncode']
    for key in ('stdout_bytes', 'stderr_bytes'):
        if type(value.get(key)) is int and 0 <= value[key] < 2**63:
            safe[key] = value[key]
    for key in ('elapsed_seconds', 'last_output_age_seconds'):
        number = value.get(key)
        if type(number) in {int, float} and 0 <= number <= 1e9 and math.isfinite(number):
            safe[key] = number
    for key in ('pending_progress', 'post_exit_output_not_collected'):
        if type(value.get(key)) is bool:
            safe[key] = value[key]
    return safe
