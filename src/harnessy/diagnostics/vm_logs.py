"""Bounded, read-only Lima boot evidence for the normal diagnostics bundle.

The default projection contains boot signals plus scrubbed control-plane errors,
never a guest message. Raw tails require the existing content-rich export opt-in.
This module deliberately has no database or VM/controller dependency.
"""
from __future__ import annotations

import errno
import hashlib
import json
import math
import os
import re
import stat
import threading
import time
import uuid
import weakref
from collections import OrderedDict, deque
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.paths import settings_path
from .technical import (MAX_TECHNICAL_CHARS, MAX_TECHNICAL_LINES,
                        technical_error_evidence, validate_technical_evidence)
from .radio_setup import RADIO_SETUP_FILENAME, radio_setup_tail

VM_LOG_FILENAMES = ('serial.log', 'serialp.log', 'serialv.log', 'ha.stderr.log', 'ha.stdout.log')
NAMED_VM_LOG_FILENAMES = VM_LOG_FILENAMES + ('qemu.stderr.log', 'qemu.control-plane.log', RADIO_SETUP_FILENAME)
MAX_WORKSPACES = 8
MAX_ENVIRONMENTS = 32
MAX_VM_FILES = MAX_ENVIRONMENTS * len(NAMED_VM_LOG_FILENAMES)
PER_FILE_TAIL_BYTES = 128 * 1024
MAX_EXPORT_BYTES = 2 * 1024 * 1024
MAX_READ_BYTES = MAX_EXPORT_BYTES
MAX_DISCOVERY_BYTES = 2 * 1024 * 1024
MAX_SIGNAL_ROWS = 256
MAX_PARSE_LINES = 8192
MAX_DISCOVERY_RECORDS = 20000
MAX_REGISTRY_ROOTS = 64
MAX_SESSION_ENTRIES = 256
MAX_PREVIOUS_SESSIONS = 8
COLLECTION_SECONDS = 5.0
MAX_FAILURE_RECEIPTS = 8
MAX_FAILURE_RECEIPT_BYTES = 64 * 1024
_FAILURE_NAME = re.compile(r'^\d{8}T\d{12}Z-[0-9a-f]{32}\.json$')
_FAILURE_REASONS = {'before_start', 'before_reset', 'before_delete', 'controller_error',
                    'controller_timeout', 'controller_cancelled', 'controller_spawn_error'}
_FAILURE_OPERATIONS = {'start', 'create', 'stop', 'delete', 'factory-reset', 'restart', 'reset', 'rebuild'}
_FAILURE_LOCKS = weakref.WeakValueDictionary()
_FAILURE_LOCKS_GUARD = threading.Lock()
_LIMITS = {
    'workspaces': MAX_WORKSPACES, 'environments': MAX_ENVIRONMENTS, 'files': MAX_VM_FILES,
    'tail_bytes_per_file': PER_FILE_TAIL_BYTES, 'read_bytes_total': MAX_READ_BYTES,
    'export_bytes_total': MAX_EXPORT_BYTES, 'discovery_bytes_total': MAX_DISCOVERY_BYTES,
    'signal_rows_per_file': MAX_SIGNAL_ROWS, 'parse_lines_per_file': MAX_PARSE_LINES,
    'collection_seconds': COLLECTION_SECONDS,
    'control_plane_chars_per_source': MAX_TECHNICAL_CHARS,
    'control_plane_lines_per_source': MAX_TECHNICAL_LINES,
    'failure_receipts': MAX_FAILURE_RECEIPTS,
    'failure_receipt_bytes': MAX_FAILURE_RECEIPT_BYTES,
}
_REGISTRY: OrderedDict[str, None] = OrderedDict()
_REGISTRY_LOCK = threading.Lock()
_HEX = re.compile(r'^[0-9a-f]{64}$')
_ENVIRONMENT_ID = re.compile(r'^[0-9a-f]{32}$')
_SESSION = re.compile(r'^\d{4}-\d{2}-\d{2}_\d{6}(?:_\d{1,6})?$')
_ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
_ISO = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$')
_LEVELS = {'debug', 'info', 'warning', 'error', 'fatal', 'panic'}
_SERVICES = {
    'ssh.service', 'sshd.service', 'systemd-networkd.service',
    'systemd-networkd-wait-online.service', 'cloud-init.service',
    'cloud-init-local.service', 'cloud-final.service', 'lima-guestagent.service',
    'containerd.service', 'docker.service',
}
EVIDENCE_CODES = frozenset({
    'kernel_boot', 'userspace_started', 'ssh_daemon_started', 'ssh_listening',
    'ssh_local_port', 'ssh_requirement_waiting', 'ssh_requirement_unmet',
    'guestagent_ready', 'guestagent_failed', 'hostagent_started',
    'hostagent_warning', 'hostagent_error', 'hostagent_fatal',
    'vm_backend_vz', 'vm_backend_qemu', 'vm_process_exited', 'controller_timeout',
    'ssh_timeout', 'connection_refused', 'connection_reset', 'no_route_to_host',
    'network_unreachable', 'network_timeout', 'broken_pipe',
    'ssh_authentication_failed', 'ssh_host_key_failed', 'ssh_connection_closed',
    'ssh_kex_failed', 'kernel_panic', 'guest_out_of_memory', 'storage_full',
    'storage_io_error', 'service_failed', 'cloud_init_stage', 'cloud_init_complete',
    'network_device_ready', 'network_online', 'dhcp_lease_lost', 'dns_failure',
    'shell_hostname_unavailable', 'ssh_legacy_kex_warning', 'openwrt_preinit_started',
    'openwrt_boot_complete',
})


def _workspace_path(value: Any) -> Path | None:
    if not isinstance(value, (str, Path)):
        return None
    text = str(value)
    if not text or len(text) > 4096 or any(ord(char) < 32 for char in text):
        return None
    path = Path(text)
    if not path.is_absolute() or '..' in path.parts:
        return None
    return path


def register_workspace_runtime(workspace_root: Path | str, *, environment_id: str = '', runtime_root: Path | str | None = None) -> None:
    """Remember a known workspace in memory, without touching its files."""
    path = _workspace_path(workspace_root)
    if path is None:
        return
    try:
        _runtime_root(path, environment_id, runtime_root)
    except ValueError:
        return
    key = str(path)
    with _REGISTRY_LOCK:
        _REGISTRY.pop(key, None)
        _REGISTRY[key] = None
        while len(_REGISTRY) > MAX_REGISTRY_ROOTS:
            _REGISTRY.popitem(last=False)


def _runtime_root(root: Path, environment_id: str = '', runtime_root: Path | str | None = None) -> Path:
    if not isinstance(environment_id, str) or (environment_id and not _ENVIRONMENT_ID.fullmatch(environment_id)):
        raise ValueError('invalid_environment_id')
    expected = root / '.harnessy' / ('environments' if environment_id else 'environment')
    if environment_id:
        expected /= environment_id
    if runtime_root is not None:
        supplied = _workspace_path(runtime_root)
        if supplied is None or supplied != expected:
            raise ValueError('invalid_environment_runtime')
    return expected


def _runtime_environments(root: Path) -> tuple[list[tuple[str, Path]], bool]:
    """Discover only opaque VM directory names without following redirects."""
    registry = root / '.harnessy' / 'environments'
    items: list[tuple[str, Path]] = []
    limited = False
    descriptor = None
    try:
        if not _allowed_path(registry) or os.open not in os.supports_dir_fd or not hasattr(os, 'O_NOFOLLOW'):
            raise ValueError('safe_directory_operations_unavailable')
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_CLOEXEC', 0)
        descriptor = os.open(registry.anchor, flags)
        for component in registry.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        with os.scandir(descriptor) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_SESSION_ENTRIES:
                    limited = True
                    break
                if _ENVIRONMENT_ID.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False):
                    items.append((entry.name, registry / entry.name))
        items.sort(key=lambda item: item[0])
    except (OSError, ValueError):
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)
    # Legacy logs can coexist with newly created named environments.
    legacy = _runtime_root(root)
    try:
        if legacy.is_dir() and not legacy.is_symlink():
            items.append(('', legacy))
    except OSError:
        pass
    return items[:MAX_ENVIRONMENTS], limited or len(items) > MAX_ENVIRONMENTS


def _allowed_path(path: Path) -> bool:
    if not path.is_absolute() or '..' in path.parts or '.settings' in path.parts:
        return False
    try:
        path.relative_to(settings_path())
    except ValueError:
        return True
    return False


def _open_regular(path: Path) -> int:
    """Open a regular single-link file without following any path symlink.

    POSIX descriptor-relative traversal keeps an ancestor swap from redirecting
    the final open. The fallback verifies every ancestor identity before and
    after opening, before reading even one byte, and uses nonblocking opens.
    """
    if not _allowed_path(path):
        raise ValueError('unsafe')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    flags |= getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0)
    supports_relative = os.open in os.supports_dir_fd and hasattr(os, 'O_NOFOLLOW')
    descriptor = None
    if supports_relative:
        parent_fd = os.open(path.anchor, flags | getattr(os, 'O_DIRECTORY', 0))
        try:
            for component in path.parts[1:-1]:
                child_fd = os.open(component, flags | getattr(os, 'O_DIRECTORY', 0), dir_fd=parent_fd)
                if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
                    os.close(child_fd)
                    raise ValueError('unsafe')
                os.close(parent_fd)
                parent_fd = child_fd
            descriptor = os.open(path.name, flags, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    else:
        ancestors = tuple(reversed(path.parents))
        checked = []
        for ancestor in ancestors:
            info = ancestor.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('unsafe')
            checked.append((ancestor, info.st_dev, info.st_ino))
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError('unsafe')
        descriptor = os.open(path, flags)
        try:
            for ancestor, device, inode in checked:
                current = ancestor.lstat()
                if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (device, inode):
                    raise ValueError('unsafe')
            after = path.lstat()
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(after.st_mode) or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError('unsafe')
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError('unsafe')
        except BaseException:
            os.close(descriptor)
            raise
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('unsafe')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_tail(path: Path, cap: int) -> dict[str, Any]:
    if cap <= 0:
        return {'status': 'limited', 'data': b'', 'bytes_available': 0, 'truncated': True}
    descriptor = None
    try:
        descriptor = _open_regular(path)
        info = os.fstat(descriptor)
        count = min(info.st_size, cap)
        offset = max(0, info.st_size - count)
        os.lseek(descriptor, offset, os.SEEK_SET)
        chunks = []
        remaining = count
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return {
            'status': 'included', 'data': b''.join(chunks),
            'bytes_available': info.st_size, 'truncated': offset > 0,
            'mtime_unix': info.st_mtime if math.isfinite(info.st_mtime) and 0 <= info.st_mtime <= 1e12 else 0,
        }
    except FileNotFoundError:
        return {'status': 'missing', 'data': b'', 'bytes_available': 0, 'truncated': False}
    except ValueError:
        return {'status': 'unsafe', 'data': b'', 'bytes_available': 0, 'truncated': False}
    except OSError as error:
        status = 'unsafe' if error.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENXIO} else 'unreadable'
        return {'status': status, 'data': b'', 'bytes_available': 0, 'truncated': False}
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _complete_lines(data: bytes, truncated: bool) -> list[str]:
    if truncated:
        # The first bytes may start inside a JSON value or guest output line.
        data = data.partition(b'\n')[2]
    return data.decode('utf-8', errors='replace').splitlines()


def _event_payload(line: str) -> dict[str, Any] | None:
    if line.startswith('{'):
        payload = line
    else:
        match = re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,.]\d+ (?:DEBUG|INFO|WARNING|ERROR|CRITICAL) (\{.*)$', line)
        if not match:
            return None
        payload = match.group(1)
    try:
        value = json.loads(payload)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _previous_sessions(latest: Path) -> tuple[list[Path], bool]:
    current = _read_tail(latest / 'CURRENT_SESSION.txt', 256)
    current_name = current['data'].decode('ascii', errors='ignore').strip()
    sessions = latest.parent / 'sessions'
    # Directory discovery also refuses links; it never examines arbitrary names.
    if not _allowed_path(sessions):
        return [], False
    descriptor = None
    try:
        if os.open in os.supports_dir_fd and hasattr(os, 'O_NOFOLLOW'):
            flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_CLOEXEC', 0)
            descriptor = os.open(sessions.anchor, flags)
            for component in sessions.parts[1:]:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            scan_source = descriptor
        else:
            for ancestor in (sessions, *sessions.parents):
                if not stat.S_ISDIR(ancestor.lstat().st_mode):
                    return [], False
            scan_source = sessions
        candidates = []
        limited = False
        with os.scandir(scan_source) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_SESSION_ENTRIES:
                    limited = True
                    break
                if _SESSION.fullmatch(entry.name) and entry.name != current_name and entry.is_dir(follow_symlinks=False):
                    candidates.append(entry.name)
        return [sessions / name for name in sorted(candidates, reverse=True)[:MAX_PREVIOUS_SESSIONS]], limited or len(candidates) > MAX_PREVIOUS_SESSIONS
    except OSError:
        return [], False
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _discover_workspaces(latest: Path, deadline: float) -> tuple[list[tuple[Path, str]], dict[str, Any]]:
    coverage = {'app_bytes_read': 0, 'records_examined': 0, 'candidate_roots': 0,
                'unsafe_app_sources': 0, 'registered_roots': 0, 'workspaces_limited': False,
                'discovery_limited': False, 'previous_session_scanned': False,
                'launcher_sessions_skipped': 0}
    current_roots: list[tuple[Path, str]] = []
    previous_roots: list[tuple[Path, str]] = []
    candidates, session_limited = _previous_sessions(latest)
    coverage['discovery_limited'] = session_limited
    previous = None
    for candidate in candidates:
        remaining = MAX_DISCOVERY_BYTES - coverage['app_bytes_read']
        if time.monotonic() >= deadline or remaining <= 0:
            coverage['discovery_limited'] = True
            break
        probe = _read_tail(candidate / 'harnessy.log', min(32 * 1024, remaining))
        coverage['app_bytes_read'] += len(probe['data'])
        coverage['unsafe_app_sources'] += int(probe['status'] == 'unsafe')
        coverage['discovery_limited'] |= probe['truncated']
        if probe['status'] == 'unsafe':
            continue
        events = set()
        for line in _complete_lines(probe['data'], probe['truncated']):
            if coverage['records_examined'] >= MAX_DISCOVERY_RECORDS or time.monotonic() >= deadline:
                coverage['discovery_limited'] = True
                break
            coverage['records_examined'] += 1
            payload = _event_payload(line)
            if payload is not None and isinstance(payload.get('event'), str):
                events.add(payload['event'])
        launcher_only = ('launcher_exec_application' in events and not
                         events.intersection({'controller_access_token_enabled', 'controller_password_login_enabled'})
                         and not any(name.startswith(('vm_', 'environment_', 'workspace_')) for name in events))
        if launcher_only:
            coverage['launcher_sessions_skipped'] += 1
            continue
        previous = candidate
        break
    sources = [(latest / (name + suffix), 'app_logs') for suffix in ('', '.1', '.2', '.3')
               for name in ('runtime.log', 'harnessy.log', 'tools.log')]
    if previous is not None:
        coverage['previous_session_scanned'] = True
        sources.extend((previous / name, 'previous_session_logs') for name in ('runtime.log', 'harnessy.log', 'tools.log'))
    for path, origin in sources:
        remaining = MAX_DISCOVERY_BYTES - coverage['app_bytes_read']
        if time.monotonic() >= deadline or remaining <= 0 or coverage['records_examined'] >= MAX_DISCOVERY_RECORDS:
            coverage['discovery_limited'] = True
            break
        result = _read_tail(path, min(PER_FILE_TAIL_BYTES, remaining))
        coverage['app_bytes_read'] += len(result['data'])
        coverage['unsafe_app_sources'] += int(result['status'] == 'unsafe')
        coverage['discovery_limited'] |= result['truncated']
        destination = current_roots if origin == 'app_logs' else previous_roots
        for line in reversed(_complete_lines(result['data'], result['truncated'])):
            if coverage['records_examined'] >= MAX_DISCOVERY_RECORDS or time.monotonic() >= deadline:
                coverage['discovery_limited'] = True
                break
            coverage['records_examined'] += 1
            payload = _event_payload(line)
            if payload is None or not isinstance(payload.get('event'), str):
                continue
            if not payload['event'].startswith(('vm_', 'environment_', 'workspace_')):
                continue
            root = _workspace_path(payload.get('workspace'))
            if root is not None and _allowed_path(root):
                destination.append((root, origin))
    with _REGISTRY_LOCK:
        registered = list(reversed(_REGISTRY))
    coverage['registered_roots'] = len(registered)
    candidates = current_roots + [(Path(path), 'registered') for path in registered] + previous_roots
    distinct: OrderedDict[str, tuple[Path, str]] = OrderedDict()
    for root, origin in candidates:
        if _allowed_path(root):
            distinct.setdefault(str(root), (root, origin))
    coverage['candidate_roots'] = len(distinct)
    coverage['workspaces_limited'] = len(distinct) > MAX_WORKSPACES
    return list(distinct.values())[:MAX_WORKSPACES], coverage


def _timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 40 or not _ISO.fullmatch(value):
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).isoformat(timespec='milliseconds')
    except ValueError:
        return None


def _number(text: str, minimum: float, maximum: float) -> float | None:
    try:
        value = float(text)
    except ValueError:
        return None
    return round(value, 3) if math.isfinite(value) and minimum <= value <= maximum else None


def _signals(line: str, kind: str, line_number: int) -> list[dict[str, Any]]:
    """Project only reviewed enums/numbers; never carry a substring of a message."""
    line = _ANSI.sub('', line)
    message = line
    metadata: dict[str, Any] = {'relative_tail_line': line_number}
    if kind == 'hostagent':
        payload = _event_payload(line)
        if payload is not None:
            message = payload.get('msg') if isinstance(payload.get('msg'), str) else ''
            level = payload.get('level')
            if isinstance(level, str) and level.lower() in _LEVELS:
                metadata['level'] = level.lower()
            timestamp = _timestamp(payload.get('time'))
            if timestamp:
                metadata['timestamp'] = timestamp
        else:
            quoted_message = re.search(r'(?:^|\s)msg=("(?:\\.|[^"\\])*")', line)
            if quoted_message:
                try:
                    message = json.loads(quoted_message.group(1))
                except ValueError:
                    message = ''
            level_match = re.search(r'(?:^|\s)level=(debug|info|warning|error|fatal|panic)(?:\s|$)', line)
            if level_match:
                metadata['level'] = level_match.group(1)
            time_match = re.search(r'(?:^|\s)time="([^"]{1,40})"', line)
            if time_match:
                timestamp = _timestamp(time_match.group(1))
                if timestamp:
                    metadata['timestamp'] = timestamp
    uptime = re.match(r'^\[\s*(\d+(?:\.\d+)?)\]', message)
    if uptime:
        seconds = _number(uptime.group(1), 0, 604800)
        if seconds is not None:
            metadata['uptime_seconds'] = seconds
    lower = message.lower()
    projected: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def add(code: str, **fields: Any) -> None:
        projected.setdefault(code, {**metadata, 'code': code, **fields})

    if 'hostname: not found' in lower:
        add('shell_hostname_unavailable')
    if 'connection is not using a post-quantum key exchange algorithm' in lower:
        add('ssh_legacy_kex_warning')
    if 'init: - preinit -' in lower or 'procd: - early -' in lower:
        add('openwrt_preinit_started')
    if 'procd: - init complete -' in lower:
        add('openwrt_boot_complete')
    if 'dropbear' in lower and ('running in background' in lower or 'not forking' in lower):
        add('ssh_daemon_started')

    if kind == 'hostagent' and metadata.get('level') in {'warning', 'error', 'fatal', 'panic'}:
        add('hostagent_' + ('fatal' if metadata['level'] == 'panic' else metadata['level']))
    kernel = re.search(r'\bLinux version (\d{1,3}\.\d{1,3}\.\d{1,4})(?:[-\s]|$)', message)
    if kernel:
        add('kernel_boot', measurements={'kernel_version': kernel.group(1)})
    elif 'booting linux on physical cpu' in lower:
        add('kernel_boot')
    if 'run /sbin/init as init process' in lower:
        add('userspace_started')
    if ('started' in lower and ('openssh server' in lower or 'openbsd secure shell server' in lower)):
        add('ssh_daemon_started')
    listen = re.search(r'\bserver listening on .*?\bport (\d{1,5})\b', lower)
    if listen and 1 <= int(listen.group(1)) <= 65535:
        add('ssh_listening', measurements={'port': int(listen.group(1))})
    local_port = re.search(r'\bssh local port:\s*(\d{1,5})\b', lower)
    if local_port and 1 <= int(local_port.group(1)) <= 65535:
        add('ssh_local_port', measurements={'port': int(local_port.group(1))})
    if 'essential requirement' in lower and re.search(r'["\']ssh["\']', lower):
        code = 'ssh_requirement_unmet' if any(word in lower for word in ('not satisfied', 'failed', 'unmet')) else 'ssh_requirement_waiting'
        fields = {}
        requirement = re.search(r'essential requirement\s+(\d{1,2})\s+of\s+(\d{1,2})', lower)
        if requirement and 1 <= int(requirement.group(1)) <= int(requirement.group(2)) <= 64:
            fields['measurements'] = {'requirement_index': int(requirement.group(1)), 'requirement_total': int(requirement.group(2))}
        add(code, **fields)
    if 'guest agent' in lower or 'guestagent' in lower:
        failed = any(word in lower for word in ('failed', 'error', 'not running', 'not connected', 'not ready', 'not started'))
        if failed:
            add('guestagent_failed')
        elif any(word in lower for word in ('ready', 'running', 'connected', 'started')):
            add('guestagent_ready')
    if ('hostagent' in lower or 'host agent' in lower) and ('started' in lower or 'starting' in lower):
        add('hostagent_started')
    if re.search(r'\b(?:using|starting)\s+["\']?(vz|qemu)["\']?\s+(?:driver|backend)', lower):
        add('vm_backend_vz' if re.search(r'\b(?:using|starting)\s+["\']?vz\b', lower) else 'vm_backend_qemu')
    elif re.match(r'^starting (vz|qemu)(?:\s*\(|\s*$)', lower):
        add('vm_backend_vz' if lower.startswith('starting vz') else 'vm_backend_qemu')
    if re.search(r'\b(?:qemu|virtual machine|vm process)\b.*\b(?:exited|terminated)\b', lower):
        exit_code = re.search(r'\b(?:status|code)\s*[=:]?\s*(\d{1,3})\b', lower)
        fields = {'measurements': {'exit_code': int(exit_code.group(1))}} if exit_code and int(exit_code.group(1)) <= 255 else {}
        add('vm_process_exited', **fields)
    tokens = {
        'context deadline exceeded': 'controller_timeout', 'connection refused': 'connection_refused',
        'connection reset': 'connection_reset', 'no route to host': 'no_route_to_host',
        'network is unreachable': 'network_unreachable', 'i/o timeout': 'network_timeout',
        'broken pipe': 'broken_pipe', 'permission denied (publickey': 'ssh_authentication_failed',
        'host key verification failed': 'ssh_host_key_failed', 'kex_exchange_identification': 'ssh_kex_failed',
        'kernel panic': 'kernel_panic', 'out of memory:': 'guest_out_of_memory',
        'oom-kill:': 'guest_out_of_memory', 'no space left on device': 'storage_full',
        'i/o error': 'storage_io_error', 'network is online': 'network_online',
        'dhcp lease lost': 'dhcp_lease_lost', 'temporary failure in name resolution': 'dns_failure',
    }
    for token, code in tokens.items():
        if token in lower:
            add(code)
    if 'ssh' in lower and ('timed out' in lower or 'timeout waiting' in lower):
        add('ssh_timeout')
    if 'connection closed' in lower and ('ssh' in lower or 'sshd' in lower):
        add('ssh_connection_closed')
    if 'virtio_net' in lower and ('link up' in lower or 'renamed from' in lower):
        add('network_device_ready')
    for service in sorted(_SERVICES):
        if re.search(r'(?<![\w.-])' + re.escape(service) + r'(?![\w.-])', lower) and ('failed' in lower or 'failure' in lower):
            add('service_failed', service=service)
    if 'cloud-init' in lower:
        stage = re.search(r"running ['\"](init-local|init|modules:config|modules:final)['\"]", lower)
        if stage:
            add('cloud_init_stage', stage=stage.group(1))
        if 'finished at' in lower:
            add('cloud_init_complete')
    return list(projected.values())


def _control_plane_evidence(lines: list[str], source: str) -> dict[str, Any]:
    """Keep a QEMU failure even if subsequent SSH cleanup fills the tail."""
    selected = lines
    if len(lines) > MAX_TECHNICAL_LINES:
        important = [index for index, line in enumerate(lines) if re.search(
            r'qemu\[stderr\]|(?:virtiofsd-\d+|swtpm)\[stderr\]|'
            r'"level"\s*:\s*"(?:error|fatal|panic)"|\blevel=(?:error|fatal|panic)\b', line)]
        indices = set(important[-MAX_TECHNICAL_LINES // 2:])
        recent = [index for index in range(len(lines) - 1, -1, -1) if index not in indices]
        indices.update(recent[:MAX_TECHNICAL_LINES - len(indices)])
        selected = [lines[index] for index in sorted(indices)]
    evidence = technical_error_evidence('\n'.join(selected), source=source)
    evidence['truncated'] |= len(selected) < len(lines)
    return evidence


def _technical_tail(data: bytes, kind: str, truncated: bool, deadline: float) -> tuple[bytes, dict[str, Any]]:
    lines = _complete_lines(data, truncated)
    retained: deque[dict[str, Any]] = deque(maxlen=MAX_SIGNAL_ROWS)
    recognized = 0
    codes: set[str] = set()
    limited = len(lines) > MAX_PARSE_LINES
    start = max(0, len(lines) - MAX_PARSE_LINES)
    for index, line in enumerate(lines[start:], start=start + 1):
        if time.monotonic() >= deadline:
            limited = True
            break
        signals = _signals(line, kind, index)
        recognized += len(signals)
        for signal in signals:
            codes.add(signal['code'])
            retained.append(signal)
    rows = list(retained)
    diagnostic = None
    if kind in {'hostagent', 'qemu'} and time.monotonic() < deadline:
        diagnostic = _control_plane_evidence(lines[-MAX_PARSE_LINES:], kind)
        diagnostic['truncated'] |= truncated or len(lines) > MAX_PARSE_LINES
        if diagnostic.get('diagnostic_text'):
            rows.append({'kind': 'control_plane', 'diagnostic': diagnostic})
    output = b''.join((json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii') for row in rows)
    return output, {'line_count': len(lines), 'signals_count': recognized,
                    'signals_exported': len(retained), 'signals_limited': limited or recognized > MAX_SIGNAL_ROWS,
                    'evidence_codes': sorted(codes),
                    'control_plane_included': bool(diagnostic and diagnostic.get('diagnostic_text')),
                    'control_plane_truncated': bool(diagnostic and diagnostic.get('truncated')),
                    'content_omitted': kind == 'serial' or bool(diagnostic and diagnostic.get('omitted_content'))}


def _uuid(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return None
    return parsed.hex if value.lower() in {parsed.hex, str(parsed)} else None


def _requested_config(value: Any) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    result = {}
    for key, choices in {'architecture': {'arm64', 'amd64'}, 'vm_type': {'qemu', 'vz'}}.items():
        if isinstance(value.get(key), str) and value.get(key) in choices:
            result[key] = value[key]
    for key, maximum in {'cpus': 4096, 'memory_mb': 2**32, 'disk_gb': 2**24}.items():
        number = value.get(key)
        if isinstance(number, int) and not isinstance(number, bool) and 0 < number <= maximum:
            result[key] = number
    return result


def validate_failure_receipt(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get('schema_version') != 1:
        return None
    identifier = _uuid(value.get('receipt_id'))
    timestamp = _timestamp(value.get('captured_at'))
    if (identifier is None or timestamp is None or not isinstance(value.get('reason'), str)
            or value.get('reason') not in _FAILURE_REASONS or not isinstance(value.get('operation'), str)
            or value.get('operation') not in _FAILURE_OPERATIONS):
        return None
    environment_id = value.get('environment_id', '')
    if not isinstance(environment_id, str) or (environment_id and not _ENVIRONMENT_ID.fullmatch(environment_id)):
        return None
    result = {'schema_version': 1, 'receipt_id': identifier, 'captured_at': timestamp, 'environment_id': environment_id,
              'reason': value['reason'], 'operation': value['operation'], 'sources': [],
              'guest_console_omitted': True, 'correlation_scope': 'capture_operation',
              'requested_config': _requested_config(value.get('requested_config'))}
    started = value.get('command_started_at_epoch')
    if isinstance(started, (int, float)) and not isinstance(started, bool) and 0 <= started <= 1e12 and math.isfinite(started):
        result['command_started_at_epoch'] = started
        if _uuid(value.get('command_id')):
            result['correlation_scope'] = 'controller_command'
    for key in ('command_id', 'operation_id'):
        identifier = _uuid(value.get(key))
        if identifier:
            result[key] = identifier
    if isinstance(value.get('host_resources'), dict):
        from .host_state import validate_resource_snapshot
        result['host_resources'] = validate_resource_snapshot(value['host_resources'])
    sources = value.get('sources') if isinstance(value.get('sources'), list) else []
    for source in sources[:4]:
        if (not isinstance(source, dict) or not isinstance(source.get('name'), str)
                or source.get('name') not in {'controller_stderr', 'controller_stdout', 'ha.stderr.log', 'ha.stdout.log'}):
            continue
        expected = 'hostagent' if source['name'].startswith('ha.') else source['name']
        evidence = validate_technical_evidence(source.get('evidence'), trusted_source=expected)
        if evidence['source'] != expected:
            continue
        item = {'name': source['name'], 'status': _enum(source.get('status'),
                                 {'included', 'missing', 'unsafe', 'unreadable', 'limited'}, 'unreadable'),
                                 'bytes_read': _integer(source.get('bytes_read'), PER_FILE_TAIL_BYTES),
                                 'truncated': source.get('truncated') is True, 'evidence': evidence}
        mtime = source.get('mtime_unix')
        if isinstance(mtime, (int, float)) and not isinstance(mtime, bool) and 0 <= mtime <= 1e12 and math.isfinite(mtime):
            item['mtime_unix'] = mtime
        scope = 'existing_before_operation' if value['reason'].startswith('before_') else 'stale_or_unknown'
        if source['name'].startswith('controller_'):
            scope = 'current_controller_output'
        elif 'command_started_at_epoch' in result and item.get('mtime_unix', -1) >= result['command_started_at_epoch']:
            scope = 'file_updated_during_attempt'
        item['timestamp_scope'] = scope
        result['sources'].append(item)
    return result


class _CaptureCancelled(Exception):
    pass


def _check_capture_cancelled(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise _CaptureCancelled()


def _failure_directory(root: Path, *, create: bool, environment_id: str = '',
                       cancel_event: threading.Event | None = None) -> tuple[Path, int]:
    """Descriptor-relative traversal refuses redirects even on the write path."""
    path = (_runtime_root(root, environment_id) / 'state' / 'vm-failures') if environment_id else root / '.harnessy' / 'diagnostics' / 'vm-failures'
    if not _allowed_path(path):
        raise ValueError('unsafe')
    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    if os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd:
        raise ValueError('safe_directory_operations_unavailable')
    _check_capture_cancelled(cancel_event)
    fd = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            _check_capture_cancelled(cancel_event)
            try:
                child = os.open(component, flags, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                _check_capture_cancelled(cancel_event)
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                _check_capture_cancelled(cancel_event)
                child = os.open(component, flags, dir_fd=fd)
            try:
                _check_capture_cancelled(cancel_event)
            except _CaptureCancelled:
                os.close(child)
                raise
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                os.close(child)
                raise ValueError('unsafe')
            os.close(fd)
            fd = child
        return path, fd
    except BaseException:
        os.close(fd)
        raise


def preserve_vm_failure(workspace_root: Path | str, *, reason: str, operation: str = 'start',
                        environment_id: str = '', runtime_root: Path | str | None = None,
                        controller_stderr: str = '', controller_stdout: str = '', command_id: str = '',
                        operation_id: str = '', requested_config: Any = None,
                        host_resources: Any = None, command_started_at_epoch: Any = None,
                        cancel_event: threading.Event | None = None) -> dict[str, Any]:
    """Save scrubbed failure evidence before Lima overwrites its log files.

    Call only for host lifecycle controller commands, never guest shell output.
    This does not invoke Lima/QEMU or inspect an application database. The caller
    must bound its worker wait and set ``cancel_event`` on timeout/cancellation.
    Cooperative checks discard an interrupted capture after blocked I/O returns,
    before it can read a later boot's logs or promote a stale receipt.
    """
    root = _workspace_path(workspace_root)
    if (root is None or not isinstance(reason, str) or reason not in _FAILURE_REASONS
            or not isinstance(operation, str) or operation not in _FAILURE_OPERATIONS):
        return {'schema_version': 1, 'status': 'rejected'}
    try:
        vm_root = _runtime_root(root, environment_id, runtime_root)
    except ValueError:
        return {'schema_version': 1, 'status': 'rejected'}
    with _FAILURE_LOCKS_GUARD:
        lock_key = (str(root), environment_id)
        failure_lock = _FAILURE_LOCKS.get(lock_key)
        if failure_lock is None:
            failure_lock = threading.Lock()
            _FAILURE_LOCKS[lock_key] = failure_lock
    lock_deadline = time.monotonic() + 0.5
    while True:
        if cancel_event is not None and cancel_event.is_set():
            return {'schema_version': 1, 'status': 'cancelled'}
        remaining = lock_deadline - time.monotonic()
        if remaining <= 0:
            return {'schema_version': 1, 'status': 'busy'}
        if failure_lock.acquire(timeout=min(0.05, remaining)):
            break
    descriptor = None
    temp_name = None
    try:
        _check_capture_cancelled(cancel_event)
        deadline = time.monotonic() + 2.0
        receipt: dict[str, Any] = {'schema_version': 1, 'receipt_id': uuid.uuid4().hex,
            'captured_at': datetime.now().astimezone().isoformat(timespec='milliseconds'), 'environment_id': environment_id,
            'reason': reason, 'operation': operation, 'command_id': command_id, 'operation_id': operation_id,
            'requested_config': requested_config, 'host_resources': host_resources,
            'command_started_at_epoch': command_started_at_epoch,
            'guest_console_omitted': True, 'sources': []}
        for name, text in (('controller_stderr', controller_stderr), ('controller_stdout', controller_stdout)):
            _check_capture_cancelled(cancel_event)
            if not isinstance(text, str) or not text:
                continue
            receipt['sources'].append({'name': name, 'status': 'included',
                'bytes_read': min(len(text.encode('utf-8', errors='replace')), PER_FILE_TAIL_BYTES),
                'truncated': len(text) > PER_FILE_TAIL_BYTES,
                'evidence': technical_error_evidence(text[-PER_FILE_TAIL_BYTES:], source=name)})
        for name in ('ha.stderr.log', 'ha.stdout.log'):
            _check_capture_cancelled(cancel_event)
            item = _read_tail(vm_root / 'vm' / 'lima' / 'harnessy' / name,
                              PER_FILE_TAIL_BYTES if time.monotonic() < deadline else 0)
            _check_capture_cancelled(cancel_event)
            data = item['data']
            receipt['sources'].append({'name': name, 'status': item['status'], 'bytes_read': len(data),
                'truncated': item['truncated'], 'mtime_unix': item.get('mtime_unix'), 'evidence': _control_plane_evidence(
                    _complete_lines(data, item['truncated']), 'hostagent')})
        if (not any(source['bytes_read'] for source in receipt['sources'])
                and not (reason.startswith('controller_') and isinstance(host_resources, dict) and host_resources)):
            return {'schema_version': 1, 'status': 'no_evidence'}
        safe = validate_failure_receipt(receipt)
        if safe is None:
            return {'schema_version': 1, 'status': 'rejected'}
        payload = json.dumps(safe, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
        # Four individually bounded sources may exceed the receipt envelope,
        # especially after JSON escaping. Keep the latest diagnostic tails and
        # state the truncation rather than losing the entire failure receipt.
        text_cap = 8000
        while len(payload) > MAX_FAILURE_RECEIPT_BYTES and text_cap >= 250:
            for source in safe['sources']:
                evidence = source['evidence']
                text = evidence.get('diagnostic_text')
                if isinstance(text, str) and len(text) > text_cap:
                    evidence['diagnostic_text'] = text[-text_cap:]
                    evidence['truncated'] = True
                    source['truncated'] = True
            payload = json.dumps(safe, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
            text_cap //= 2
        if len(payload) > MAX_FAILURE_RECEIPT_BYTES:
            return {'schema_version': 1, 'status': 'limited'}
        _check_capture_cancelled(cancel_event)
        _, descriptor = _failure_directory(root, create=True, environment_id=environment_id, cancel_event=cancel_event)
        _check_capture_cancelled(cancel_event)
        stamp = datetime.now().astimezone().strftime('%Y%m%dT%H%M%S%fZ')
        name = stamp + '-' + safe['receipt_id'] + '.json'
        temp_name = '.' + safe['receipt_id'] + '.tmp'
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
        _check_capture_cancelled(cancel_event)
        output = os.open(temp_name, flags, 0o600, dir_fd=descriptor)
        try:
            view = memoryview(payload)
            while view:
                _check_capture_cancelled(cancel_event)
                written = os.write(output, view)
                if written <= 0:
                    raise OSError('short write')
                view = view[written:]
            _check_capture_cancelled(cancel_event)
            os.fsync(output)
            _check_capture_cancelled(cancel_event)
        finally:
            os.close(output)
        _check_capture_cancelled(cancel_event)
        os.rename(temp_name, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        temp_name = None
        if cancel_event is not None and cancel_event.is_set():
            # A cancellation may race the atomic promotion itself. Remove only
            # this uniquely named receipt if it arrived during that syscall.
            os.unlink(name, dir_fd=descriptor)
            raise _CaptureCancelled()
        names = []
        with os.scandir(descriptor) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_SESSION_ENTRIES:
                    break
                if _FAILURE_NAME.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                    names.append(entry.name)
        for old in sorted(names, reverse=True)[MAX_FAILURE_RECEIPTS:]:
            _check_capture_cancelled(cancel_event)
            os.unlink(old, dir_fd=descriptor)
        return {'schema_version': 1, 'status': 'preserved', 'receipt_id': safe['receipt_id'],
                'captured_at': safe['captured_at'], 'reason': reason, 'operation': operation, 'environment_id': environment_id,
                'sources': len(safe['sources']), 'bytes_saved': len(payload), 'guest_console_omitted': True}
    except _CaptureCancelled:
        return {'schema_version': 1, 'status': 'cancelled'}
    except (OSError, ValueError, TypeError):
        return {'schema_version': 1, 'status': 'unavailable'}
    finally:
        if descriptor is not None:
            if temp_name:
                try:
                    os.unlink(temp_name, dir_fd=descriptor)
                except OSError:
                    pass
            os.close(descriptor)
        failure_lock.release()


def _failure_receipts(root: Path, deadline: float, cap: int, count: int = MAX_FAILURE_RECEIPTS, *, environment_id: str = '') -> tuple[list[dict[str, Any]], int, bool]:
    receipts = []
    consumed = 0
    limited = False
    descriptor = None
    try:
        path, descriptor = _failure_directory(root, create=False, environment_id=environment_id)
        names = []
        with os.scandir(descriptor) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_SESSION_ENTRIES:
                    limited = True
                    break
                if _FAILURE_NAME.fullmatch(entry.name) and entry.is_file(follow_symlinks=False):
                    names.append(entry.name)
        limited |= len(names) > count
        for name in sorted(names, reverse=True)[:count]:
            if time.monotonic() >= deadline or cap - consumed < MAX_FAILURE_RECEIPT_BYTES:
                limited = True
                break
            read = _read_tail(path / name, MAX_FAILURE_RECEIPT_BYTES)
            consumed += len(read['data'])
            if read['status'] != 'included' or read['truncated']:
                continue
            try:
                safe = validate_failure_receipt(json.loads(read['data']))
            except (ValueError, RecursionError):
                continue
            if safe is not None:
                receipts.append(safe)
    except (OSError, ValueError):
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return receipts, consumed, limited


def collect_vm_diagnostics(latest: Path, include_content: bool = False) -> dict[str, Any]:
    """Collect existing known VM logs; never open SQLite or run a VM command."""
    deadline = time.monotonic() + COLLECTION_SECONDS
    roots, discovery = _discover_workspaces(Path(latest).absolute(), deadline)
    mode = 'raw_bounded_tails' if include_content else 'signals_only'
    report: dict[str, Any] = {'schema_version': 1, 'status': 'collected' if roots else 'no_workspaces',
                              'mode': mode, 'limits': dict(_LIMITS), 'discovery': discovery, 'workspaces': []}
    members: dict[str, bytes] = {}
    read_total = 0
    export_total = 0
    receipt_count = 0
    environment_count = 0
    for root, origin in roots:
        identifier = hashlib.sha256(str(root).encode('utf-8')).hexdigest()
        workspace: dict[str, Any] = {'workspace_id': identifier, 'source': origin, 'sources': [], 'evidence_codes': [], 'failure_receipts': [], 'environment_ids': []}
        workspace_codes: set[str] = set()
        environments, environment_limited = _runtime_environments(root)
        workspace['environments_limited'] = environment_limited or environment_count + len(environments) > MAX_ENVIRONMENTS
        for environment_id, runtime_root in environments[:max(0, MAX_ENVIRONMENTS - environment_count)]:
            environment_count += 1
            workspace['environment_ids'].append(environment_id)
            member_prefix = f'vm-logs/{identifier}' + (f'/{environment_id}' if environment_id else '')
            definition = _read_tail(runtime_root / 'environment.json', 16 * 1024)
            try:
                config = json.loads(definition['data']) if definition['status'] == 'included' and not definition['truncated'] else {}
            except (ValueError, RecursionError):
                config = {}
            backend = 'qemu' if isinstance(config, dict) and config.get('provider') == 'openwrt' else 'lima'
            if backend == 'qemu':
                from .test_target_logs import _runtime, _qemu_technical_tail, _qemu_control_plane_tail
                log_root = _runtime(runtime_root, 'qemu')
                filenames = ('qemu.stderr.log', 'qemu.control-plane.log', 'serial.log', RADIO_SETUP_FILENAME)
            else:
                log_root = runtime_root / 'vm' / 'lima' / 'harnessy'
                filenames = VM_LOG_FILENAMES
            for filename in filenames:
                kind = 'radio_setup' if filename == RADIO_SETUP_FILENAME else 'qemu' if filename.startswith('qemu.') else 'hostagent' if filename.startswith('ha.') else 'serial'
                source: dict[str, Any] = {'filename': filename, 'environment_id': environment_id, 'kind': kind, 'bytes_read': 0, 'bytes_exported': 0,
                                          'line_count': 0, 'signals_count': 0, 'signals_exported': 0,
                                          'signals_limited': False, 'evidence_codes': []}
                remaining = min(MAX_READ_BYTES - read_total, MAX_EXPORT_BYTES - export_total)
                if time.monotonic() >= deadline or remaining <= 0:
                    result = {'status': 'limited', 'data': b'', 'bytes_available': 0, 'truncated': True}
                else:
                    result = _read_tail(log_root / filename,
                                        min(PER_FILE_TAIL_BYTES, remaining))
                data = result.pop('data')
                source.update(result)
                source['bytes_read'] = len(data)
                read_total += len(data)
                if source['status'] == 'included':
                    source['tail_sha256'] = hashlib.sha256(data).hexdigest()
                    technical, measurements = (radio_setup_tail(data, source['truncated'], deadline) if filename == RADIO_SETUP_FILENAME else
                                               _qemu_technical_tail(data, source['truncated'], deadline) if filename == 'qemu.stderr.log' else
                                               _qemu_control_plane_tail(data, source['truncated'], deadline) if kind == 'qemu' else
                                               _technical_tail(data, kind, source['truncated'], deadline))
                    source.update(measurements)
                    output = technical
                    # Projection can grow terse source lines. Preserve complete JSONL
                    # rows while enforcing the same aggregate export byte budget.
                    cap = MAX_EXPORT_BYTES - export_total
                    if len(output) > cap:
                        start = len(output) - cap
                        tail = output[start:] if cap else b''
                        output = tail if start and output[start - 1:start] == b'\n' else tail.partition(b'\n')[2]
                        source['signals_limited'] = True
                        source['truncated'] = True
                    member = f'{member_prefix}/{filename}.technical.jsonl'
                    members[member] = output
                    source['archive_member'] = member
                    source['bytes_exported'] = len(output)
                    source['technical_bytes_exported'] = len(output)
                    export_total += len(output)
                    if include_content:
                        cap = MAX_EXPORT_BYTES - export_total
                        raw = data[-cap:] if cap else b''
                        if len(raw) < len(data):
                            source['truncated'] = True
                        raw_member = f'{member_prefix}/{filename}.raw.log'
                        members[raw_member] = raw
                        source['raw_archive_member'] = raw_member
                        source['raw_bytes_exported'] = len(raw)
                        source['bytes_exported'] += len(raw)
                        export_total += len(raw)
                    workspace_codes.update(source['evidence_codes'])
                workspace['sources'].append(source)
            receipts, receipt_bytes, receipt_limited = _failure_receipts(root, deadline, MAX_READ_BYTES - read_total,
                                                                      MAX_FAILURE_RECEIPTS - receipt_count, environment_id=environment_id)
            workspace['failure_receipts'].extend(receipts)
            workspace['failure_receipts_limited'] = workspace.get('failure_receipts_limited', False) or receipt_limited
            workspace['failure_receipts_bytes_read'] = workspace.get('failure_receipts_bytes_read', 0) + receipt_bytes
            read_total += receipt_bytes
            receipt_count += len(receipts)
        workspace['evidence_codes'] = sorted(workspace_codes)
        report['workspaces'].append(workspace)
    report = validate_vm_report(report)
    return {'report': report, 'members': members}


def _integer(value: Any, maximum: int = 2**63 - 1) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum else 0


def _codes(value: Any) -> list[str]:
    return sorted({item for item in value if isinstance(item, str) and item in EVIDENCE_CODES}) if isinstance(value, list) else []


def _enum(value: Any, choices: set[str], default: str) -> str:
    return value if isinstance(value, str) and value in choices else default


def validate_vm_report(report: Any) -> dict[str, Any]:
    """Rebuild metadata using fixed enums and bounded numbers, ignoring prose."""
    if not isinstance(report, dict):
        report = {'status': 'unavailable', 'reason': 'collector_result_invalid'}
    mode = _enum(report.get('mode'), {'signals_only', 'raw_bounded_tails'}, 'signals_only')
    status = _enum(report.get('status'), {'collected', 'no_workspaces', 'unavailable'}, 'unavailable')
    safe: dict[str, Any] = {'schema_version': 1, 'status': status, 'mode': mode, 'limits': dict(_LIMITS),
                           'discovery': {}, 'workspaces': []}
    if status == 'unavailable':
        safe['reason'] = _enum(report.get('reason'), {'collector_failed', 'collector_result_invalid'}, 'collector_result_invalid')
    discovery = report.get('discovery') if isinstance(report.get('discovery'), dict) else {}
    for key, cap in {'app_bytes_read': MAX_DISCOVERY_BYTES, 'records_examined': MAX_DISCOVERY_RECORDS,
                     'candidate_roots': MAX_DISCOVERY_RECORDS + MAX_REGISTRY_ROOTS,
                     'unsafe_app_sources': 15 + MAX_PREVIOUS_SESSIONS, 'registered_roots': MAX_REGISTRY_ROOTS,
                     'launcher_sessions_skipped': MAX_PREVIOUS_SESSIONS}.items():
        safe['discovery'][key] = _integer(discovery.get(key), cap)
    for key in ('workspaces_limited', 'discovery_limited', 'previous_session_scanned'):
        safe['discovery'][key] = discovery.get(key) is True
    seen_ids = set()
    receipt_count = 0
    workspaces = report.get('workspaces') if isinstance(report.get('workspaces'), list) else []
    for workspace in workspaces[:MAX_WORKSPACES] if status != 'unavailable' else []:
        if not isinstance(workspace, dict):
            continue
        identifier = workspace.get('workspace_id')
        if not isinstance(identifier, str) or not _HEX.fullmatch(identifier) or identifier in seen_ids:
            continue
        seen_ids.add(identifier)
        origin = workspace.get('source')
        origin = _enum(origin, {'app_logs', 'registered', 'previous_session_logs'}, 'registered')
        retained = {'workspace_id': identifier, 'source': origin, 'sources': [], 'evidence_codes': [], 'failure_receipts': [],
                    'failure_receipts_limited': workspace.get('failure_receipts_limited') is True,
                    'failure_receipts_bytes_read': _integer(workspace.get('failure_receipts_bytes_read'), MAX_READ_BYTES),
                    'environment_ids': [], 'environments_limited': workspace.get('environments_limited') is True}
        for environment_id in workspace.get('environment_ids', [])[:MAX_ENVIRONMENTS] if isinstance(workspace.get('environment_ids'), list) else []:
            if isinstance(environment_id, str) and (not environment_id or _ENVIRONMENT_ID.fullmatch(environment_id)) and environment_id not in retained['environment_ids']:
                retained['environment_ids'].append(environment_id)
        for value in workspace.get('failure_receipts', [])[:MAX_FAILURE_RECEIPTS - receipt_count] if isinstance(workspace.get('failure_receipts'), list) else []:
            receipt = validate_failure_receipt(value)
            if receipt is not None:
                retained['failure_receipts'].append(receipt)
                receipt_count += 1
        sources = workspace.get('sources') if isinstance(workspace.get('sources'), list) else []
        seen_files = set()
        for source in sources[:MAX_VM_FILES]:
            if not isinstance(source, dict) or source.get('filename') not in NAMED_VM_LOG_FILENAMES:
                continue
            filename = source['filename']
            environment_id = source.get('environment_id', '')
            if not isinstance(environment_id, str) or (environment_id and not _ENVIRONMENT_ID.fullmatch(environment_id)):
                continue
            source_key = (environment_id, filename)
            if source_key in seen_files:
                continue
            seen_files.add(source_key)
            source_status = source.get('status')
            source_status = _enum(source_status, {'included', 'missing', 'unsafe', 'unreadable', 'limited'}, 'unreadable')
            item = {'filename': filename, 'environment_id': environment_id, 'kind': 'radio_setup' if filename == RADIO_SETUP_FILENAME else 'qemu' if filename.startswith('qemu.') else 'hostagent' if filename.startswith('ha.') else 'serial', 'status': source_status}
            for key, cap in {'bytes_available': 2**63 - 1, 'bytes_read': PER_FILE_TAIL_BYTES,
                             'bytes_exported': MAX_EXPORT_BYTES, 'line_count': PER_FILE_TAIL_BYTES,
                             'technical_bytes_exported': MAX_EXPORT_BYTES, 'raw_bytes_exported': PER_FILE_TAIL_BYTES,
                             'signals_count': MAX_PARSE_LINES * len(EVIDENCE_CODES), 'signals_exported': MAX_SIGNAL_ROWS}.items():
                item[key] = _integer(source.get(key), cap)
            item['truncated'] = source.get('truncated') is True
            item['signals_limited'] = source.get('signals_limited') is True
            for key in ('control_plane_included', 'control_plane_truncated', 'content_omitted'):
                item[key] = source.get(key) is True
            item['evidence_codes'] = _codes(source.get('evidence_codes'))
            mtime = source.get('mtime_unix')
            if isinstance(mtime, (int, float)) and not isinstance(mtime, bool) and 0 <= mtime <= 1e12 and math.isfinite(mtime):
                item['mtime_unix'] = mtime
            tail_hash = source.get('tail_sha256')
            if isinstance(tail_hash, str) and _HEX.fullmatch(tail_hash):
                item['tail_sha256'] = tail_hash
            prefix = f'vm-logs/{identifier}' + (f'/{environment_id}' if environment_id else '')
            expected = f'{prefix}/{filename}.technical.jsonl'
            if source.get('archive_member') == expected and source_status == 'included':
                item['archive_member'] = expected
            raw_expected = f'{prefix}/{filename}.raw.log'
            if mode == 'raw_bounded_tails' and source.get('raw_archive_member') == raw_expected and source_status == 'included':
                item['raw_archive_member'] = raw_expected
            retained['sources'].append(item)
        retained['evidence_codes'] = sorted({code for source in retained['sources'] for code in source['evidence_codes']})
        safe['workspaces'].append(retained)
    all_sources = [source for workspace in safe['workspaces'] for source in workspace['sources']]
    safe['summary'] = {'workspaces': len(safe['workspaces']),
                       'environments': sum(len(workspace['environment_ids']) for workspace in safe['workspaces']), 'sources': len(all_sources),
                       'bytes_read': sum(source['bytes_read'] for source in all_sources) + sum(workspace['failure_receipts_bytes_read'] for workspace in safe['workspaces']),
                       'bytes_exported': sum(source['bytes_exported'] for source in all_sources),
                       'recognized_signals': sum(source['signals_count'] for source in all_sources)}
    safe['summary']['failure_receipts'] = sum(len(workspace['failure_receipts']) for workspace in safe['workspaces'])
    safe['omissions'] = {'guest_console_text': mode != 'raw_bounded_tails', 'command_and_guest_output_records': True,
                         'credentials_and_identifying_paths': True,
                         'control_plane_policy': 'scrubbed_technical_text', 'raw_control_plane_included': mode == 'raw_bounded_tails'}
    for source_status in ('included', 'missing', 'unsafe', 'unreadable', 'limited'):
        safe['summary'][source_status] = sum(source['status'] == source_status for source in all_sources)
    safe['summary']['bounded'] = sum(source['truncated'] or source['signals_limited'] or source['control_plane_truncated'] or source['status'] == 'limited' for source in all_sources)
    return safe
