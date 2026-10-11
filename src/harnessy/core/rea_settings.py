"""User-owned configuration for the local Reverse Engineer Anything service."""
from __future__ import annotations

from typing import Any

REA_PACKAGE = 'rea-agents'
REA_VERSION = '6.4.0'
DEFAULT_REA_SETTINGS: dict[str, Any] = {
    'command': '',
    'arguments': ['mcp'],
    'provider': 'auto',
    # Ghidra's cold import can take longer than a normal shell command.
    'timeout_seconds': 600,
    'environment': {},
}


def normalize_rea_settings(value: Any) -> dict[str, Any]:
    data = value if isinstance(value, dict) else {}
    command = data.get('command')
    command = command.strip() if isinstance(command, str) and '\x00' not in command else ''
    arguments = data.get('arguments')
    if not isinstance(arguments, list) or len(arguments) > 32 or any(
        not isinstance(arg, str) or '\x00' in arg or len(arg) > 4096 for arg in arguments
    ):
        arguments = ['mcp']
    provider = str(data.get('provider') or 'auto').strip().lower()
    if provider not in {'auto', 'ghidra', 'hopper', 'ida'}:
        provider = 'auto'
    try:
        timeout = max(10, min(1800, int(data.get('timeout_seconds', 600))))
    except (ValueError, TypeError, OverflowError):
        timeout = 600
    environment = data.get('environment')
    environment = {
        key: val for key, val in environment.items()
        if isinstance(key, str) and isinstance(val, str) and '\x00' not in key + val
        and (key.startswith('REA_') or key in {'GHIDRA_INSTALL_DIR', 'JAVA_HOME'})
    } if isinstance(environment, dict) else {}
    return {
        'command': command, 'arguments': list(arguments), 'provider': provider,
        'timeout_seconds': timeout, 'environment': environment,
    }
