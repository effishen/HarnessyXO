"""Fixed, content-free observations of an owned Lima controller process."""
from __future__ import annotations

import json
import math
import re
from typing import Any
import uuid


LEGACY_CONTROLLER_OBSERVATION_EVENTS = frozenset({
    'environment_command_parent_exited', 'environment_command_output_handoff',
    'environment_command_heartbeat',
})
NATIVE_CONTROLLER_OBSERVATION_EVENTS = frozenset({
    'environment_controller_started', 'environment_controller_heartbeat',
    'environment_controller_parent_exited', 'environment_controller_output_handoff',
    'environment_controller_finished', 'environment_controller_timed_out',
    'environment_controller_cancelled', 'environment_controller_spawn_failed',
})
CONTROLLER_OBSERVATION_EVENTS = LEGACY_CONTROLLER_OBSERVATION_EVENTS | NATIVE_CONTROLLER_OBSERVATION_EVENTS
CONTROLLER_ACTIONS = frozenset({
    'start', 'create', 'stop', 'delete', 'factory-reset', 'restart',
    'shell', 'list', 'snapshot', 'clone', 'edit', '--version', 'other',
})
HOST_PROGRAMS = frozenset({'apt', 'apt-get', 'brew', 'dnf', 'yum', 'apk', 'pacman', 'zypper',
    'sudo', 'limactl', 'ssh', 'ssh-keygen', 'qemu-img', 'qemu-system-aarch64', 'qemu-system-x86_64',
    'qemu-system-mips', 'qemu-system-mipsel', 'qemu-system-mips64', 'qemu-system-mips64el',
    'e2fsck', 'debugfs', 'resize2fs', 'swtpm', 'ps', 'other'})
HOST_PREREQUISITE_ACTIONS = frozenset({'prerequisite_check', 'package_manager'})
CONTROLLER_ACTIVITIES = frozenset({
    'unknown', 'downloading', 'verifying_download', 'preparing_disk',
    'creating_instance', 'starting_instance', 'waiting_for_guest',
    'stopping_instance', 'deleting_instance',
})
CONTROLLER_SIGNALS = frozenset({
    'download_started', 'download_progress', 'download_complete',
    'checksum_verification', 'checksum_verified', 'disk_preparation',
    'instance_creation', 'instance_start', 'guest_wait', 'instance_stop',
    'instance_delete', 'controller_warning', 'controller_error',
})
_ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
_HEX32 = re.compile(r'^[0-9a-f]{32}$')


def _uuid(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) not in {32, 36}:
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    return value if value in {parsed.hex, str(parsed)} else None


def validate_controller_observation(event: Any, value: Any) -> dict[str, Any] | None:
    if not isinstance(event, str) or event not in CONTROLLER_OBSERVATION_EVENTS or not isinstance(value, dict):
        return None
    command = value.get('command_id')
    provider = value.get('provider')
    actions = HOST_PREREQUISITE_ACTIONS if provider == 'host' else CONTROLLER_ACTIONS
    if (not isinstance(provider, str) or provider not in {'lima', 'host'}
            or provider == 'host' and event not in NATIVE_CONTROLLER_OBSERVATION_EVENTS
            or not isinstance(value.get('controller_action'), str)
            or value['controller_action'] not in actions
            or not isinstance(command, str) or not _HEX32.fullmatch(command)):
        return {'event': event, 'observation_status': 'invalid_context'}
    safe: dict[str, Any] = {'event': event, 'provider': provider, 'command_id': command,
                            'controller_action': value['controller_action']}
    for key in ('workspace_id', 'operation_id', 'target_id'):
        identifier = _uuid(value.get(key))
        if identifier:
            safe[key] = identifier
    environment = value.get('environment_id')
    if isinstance(environment, str) and _HEX32.fullmatch(environment):
        safe['environment_id'] = environment
    if isinstance(value.get('target_backend'), str) and value['target_backend'] in {'lima', 'qemu'}:
        safe['target_backend'] = value['target_backend']
    if isinstance(value.get('environment_action'), str) and value['environment_action'] in {
            'create', 'start', 'stop', 'reset', 'rebuild', 'destroy', 'remove',
            'restore', 'snapshot', 'tools', 'network', 'resources'}:
        safe['environment_action'] = value['environment_action']
    if isinstance(value.get('target_action'), str) and value['target_action'] in {'start', 'stop', 'delete', 'snapshot', 'restore', 'radios', 'connection_test'}:
        safe['target_action'] = value['target_action']
    for key, choices in {
            'controller_state': {'running', 'exited', 'not_started'},
            'completion_phase': {'running_controller', 'collecting_output'},
            'output_capture': {'anonymous_files', 'pipe_streams', 'merged_pipe', 'inherited_terminal'},
            'capture_scope': {'direct_controller_lifetime', 'command_output_lifetime'},
            'outcome': {'running', 'succeeded', 'failed', 'timed_out', 'cancelled', 'spawn_failed'},
            'controller_activity': CONTROLLER_ACTIVITIES}.items():
        if isinstance(value.get(key), str) and value[key] in choices:
            safe[key] = value[key]
    if isinstance(value.get('controller_program'), str) and value['controller_program'] in HOST_PROGRAMS:
        safe['controller_program'] = value['controller_program']
    if value.get('controller_returncode') is None:
        safe['controller_returncode'] = None
    elif type(value.get('controller_returncode')) is int and -2**31 <= value['controller_returncode'] < 2**31:
        safe['controller_returncode'] = value['controller_returncode']
    pid = value.get('controller_pid')
    if type(pid) is int and 0 < pid < 2**31:
        safe['controller_pid'] = pid
    for key in ('stdout_bytes', 'stderr_bytes'):
        if type(value.get(key)) is int and 0 <= value[key] < 2**63:
            safe[key] = value[key]
    for key in ('elapsed_seconds', 'last_output_age_seconds', 'timeout_seconds'):
        number = value.get(key)
        if type(number) in {int, float} and 0 <= number <= 1e9 and math.isfinite(number):
            safe[key] = number
    for key in ('pending_progress', 'post_exit_output_not_collected'):
        if type(value.get(key)) is bool:
            safe[key] = value[key]
    signals = value.get('controller_signals')
    if isinstance(signals, (list, tuple)):
        safe['controller_signals'] = list(dict.fromkeys(
            code for code in signals[:32] if isinstance(code, str) and code in CONTROLLER_SIGNALS))[:16]
    return safe


class ControllerActivityParser:
    """Reduce bounded native lifecycle lines to fixed categories, never excerpts.

    This reports recognized output patterns. It does not establish that a
    download advanced, that a guest is running, or that setup is Ready.
    """
    MAX_LINE = 16384
    MAX_FEED = 65536

    def __init__(self) -> None:
        self._partial = ''
        self._activity = 'unknown'
        self._signals: list[str] = []

    def _signal(self, signal: str, activity: str | None = None) -> None:
        if signal not in self._signals:
            self._signals.append(signal)
            self._signals = self._signals[-16:]
        if activity is not None:
            self._activity = activity

    def _line(self, line: str) -> None:
        line = _ANSI.sub('', line[-self.MAX_LINE:]).strip()
        if not line:
            return
        try:
            document = json.loads(line)
        except (ValueError, RecursionError):
            document = None
        if isinstance(document, dict):
            level, message = document.get('level'), document.get('msg')
            if level == 'warning':
                self._signal('controller_warning')
            elif level in {'error', 'fatal'}:
                self._signal('controller_error')
            line = message if isinstance(message, str) else ''
        else:
            if re.search(r'\blevel=warning\b', line):
                self._signal('controller_warning')
            elif re.search(r'\blevel=(?:error|fatal)\b', line):
                self._signal('controller_error')
            # Logrus native output prefixes its message with msg=; stripping
            # that prefix is local parsing only and never enters a receipt.
            match = re.search(r'\bmsg="((?:[^"\\]|\\.)*)"', line)
            if match:
                try:
                    line = json.loads('"' + match.group(1) + '"')
                except ValueError:
                    line = ''
        text = line.casefold()
        if text.startswith(('downloaded ', 'download complete', 'download completed')):
            self._signal('download_complete', 'downloading')
        elif text.startswith(('downloading ', 'download ')):
            self._signal('download_started', 'downloading')
        elif re.match(r'^\s*(?:\d{1,3}(?:\.\d+)?%|\[?download\]?\s+\d)', text):
            self._signal('download_progress', 'downloading')
        elif text.startswith(('verifying ', 'validating checksum', 'checking sha256', 'checking digest')):
            self._signal('checksum_verification', 'verifying_download')
        elif text.startswith(('verified ', 'checksum verified', 'digest verified')):
            self._signal('checksum_verified', 'verifying_download')
        elif text.startswith(('creating disk', 'creating a disk', 'resizing disk', 'converting disk', 'preparing disk')):
            self._signal('disk_preparation', 'preparing_disk')
        elif text.startswith(('creating the instance', 'creating instance', 'instance created')):
            self._signal('instance_creation', 'creating_instance')
        elif text.startswith(('starting the instance', 'starting instance', '[hostagent] starting qemu')):
            self._signal('instance_start', 'starting_instance')
        elif text.startswith(('[hostagent] waiting for ', 'waiting for the guest', 'waiting for ssh')):
            self._signal('guest_wait', 'waiting_for_guest')
        elif text.startswith(('stopping the instance', 'stopping instance', 'shutting down qemu')):
            self._signal('instance_stop', 'stopping_instance')
        elif text.startswith(('deleting the instance', 'deleting instance', 'removing instance')):
            self._signal('instance_delete', 'deleting_instance')

    def feed(self, text: str) -> None:
        if not isinstance(text, str):
            return
        # Splitting a single bounded suffix avoids retaining arbitrary command
        # output or an unbounded line; each stream owns its own parser.
        combined = self._partial + text[-self.MAX_FEED:]
        chunks = re.split(r'[\r\n]', combined)
        self._partial = chunks.pop()[-self.MAX_LINE:]
        for line in chunks:
            self._line(line)

    def snapshot(self) -> dict[str, Any]:
        self._line(self._partial)
        return {'controller_activity': self._activity, 'controller_signals': list(self._signals)}
