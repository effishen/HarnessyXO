"""Bounded, sanitized guest observations for the normal diagnostics bundle.

The guest is an untrusted source. Only fixed event codes, numeric observations
and syntactically checked timestamps leave the capture path. Raw guest output,
command bodies, log messages, names, addresses and paths are never persisted.
Export revalidates every saved receipt and does not contact a guest.
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import inspect
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from typing import Any
import uuid
import weakref

MAX_ENVIRONMENTS = 32
MAX_EXPORT_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 128 * 1024
MAX_OUTPUT_BYTES = 128 * 1024
MAX_RECEIPTS = 8
MAX_RECORDS = 32
MAX_REGISTERED = 64
PROBE_SECONDS = 5.0
REFRESH_SECONDS = 12.0
CAPTURE_COOLDOWN = 30.0
RECOVERY_DELAY = 8.0
FILENAME = 'guest-events.jsonl'
_KINDS = frozenset({'openwrt', 'linux', 'unsupported'})
_STATES = frozenset({'ready', 'partial', 'unavailable', 'stopped', 'unsupported', 'invalid_output'})
_REASONS = frozenset({'export', 'transport_failure', 'mapping_failure', 'sshfs_failure', 'manual', 'recovery', 'vm_ready'})
_OPERATIONS = frozenset({'ssh_command', 'mapping_probe', 'sshfs'})
_SOURCE_NAMES = ('system', 'kernel', 'ssh')
_SOURCE_STATES = frozenset({'available', 'missing', 'permission_denied', 'failed', 'not_observed'})
_GUEST_CODES = frozenset({
    'out_of_memory', 'oom_kill', 'kernel_panic', 'kernel_oops', 'soft_lockup', 'hung_task',
    'filesystem_error', 'io_error', 'storage_full', 'read_only_filesystem', 'fuse_disconnected',
    'ssh_authentication_failed', 'ssh_session_opened', 'ssh_session_closed', 'ssh_server_started',
    'ssh_session_closed_before_auth', 'ssh_session_closed_after_auth',
    'ssh_connection_limit', 'connection_timeout', 'connection_refused', 'connection_reset',
    'connection_closed', 'broken_pipe', 'too_many_open_files', 'process_limit',
    'service_crash', 'network_link_down', 'network_link_up', 'permission_denied',
    'segmentation_fault', 'watchdog_reset',
})
_TRANSPORT_CODES = frozenset({
    'connection_timeout', 'connection_refused', 'connection_reset', 'connection_closed',
    'network_unreachable', 'dns_failed', 'authentication_failed', 'host_key_failed',
    'channel_limit', 'channel_open_failed', 'local_resource_limit', 'broken_pipe',
    'multiplex_unavailable', 'ssh_exit_255', 'command_timeout',
})
_TRANSPORT_STAGES = frozenset({'unknown', 'tcp_connect', 'ssh_identification', 'key_exchange',
    'host_key_verification', 'authentication', 'session_open', 'multiplex'})
_SSH_CLOSE_REASONS = frozenset({'authentication_timeout', 'idle_timeout', 'keepalive_timeout',
                              'connection_reset', 'connection_closed', 'unknown'})
MAX_PROCESS_SCAN = 128
_PROCESS_METRICS = frozenset(
    name + '_' + state for name in ('dropbear', 'sshd', 'sshfs')
    for state in ('processes', 'running', 'sleeping', 'blocked', 'stopped', 'zombie', 'other'))
_METRICS = frozenset({'mem_total_kib', 'mem_available_kib', 'swap_total_kib', 'swap_free_kib',
                      'uptime_seconds', 'process_scan_examined', 'process_scan_limited',
                      'process_scan_errors'}) | _PROCESS_METRICS
_ID = re.compile(r'^[0-9a-f]{32}$')
_HASH = re.compile(r'^[0-9a-f]{64}$')
_TIMESTAMP = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$')
_GUEST_TIME = re.compile(r'(?:^|\s)(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2}))')
_LOCAL_TIME = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$')
_OPENWRT_TIME = re.compile(r'^((?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})(?:\s|$)')
_UPTIME = re.compile(r'^\s*\[\s*(\d{1,10}(?:\.\d{1,6})?)\s*\]')
_ANSI = re.compile(r'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))')
_IN_CAPTURE: ContextVar[bool] = ContextVar('harnessy_guest_log_capture', default=False)
_REGISTRY_LOCK = threading.RLock()
_REGISTRY: OrderedDict[tuple[str, str], '_Probe'] = OrderedDict()
_TASKS: dict[tuple[str, str, int], asyncio.Task] = {}
_BACKGROUND_TASKS: set[asyncio.Task] = set()
_WAITERS: dict[asyncio.Task, int] = {}
_LAST_CAPTURE: dict[tuple[str, str, int], float] = {}
_SEMAPHORES: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()
_PERSIST_TASKS: dict[tuple[str, str, int], asyncio.Task] = {}
_PERSIST_PENDING: dict[tuple[str, str, int], list[tuple[Path, dict[str, Any]]]] = {}
_LAST_REFRESH: dict[str, Any] = {'status': 'not_requested', 'registered': 0, 'completed': 0, 'limited': False}

# Every source is bounded before transport: <= 96 lines * 384 characters.
# Status markers are observations, not attestations from the untrusted guest.
GUEST_LOG_SCRIPT = r'''set +e
LC_ALL=C
export LC_ALL
printf '__HXGL_BEGIN__ system\n'
if command -v logread >/dev/null 2>&1; then
  (logread 2>&1; printf '\n__HXGL_RC__ %s\n' "$?") | tail -n 98 | cut -c 1-384
elif command -v journalctl >/dev/null 2>&1; then
  (journalctl -n 96 --no-pager -o short-iso 2>&1; printf '\n__HXGL_RC__ %s\n' "$?") | tail -n 98 | cut -c 1-384
else printf '__HXGL_MISSING__\n'; fi
printf '__HXGL_END__\n__HXGL_BEGIN__ kernel\n'
if command -v dmesg >/dev/null 2>&1; then
  (dmesg 2>&1; printf '\n__HXGL_RC__ %s\n' "$?") | tail -n 98 | cut -c 1-384
else printf '__HXGL_MISSING__\n'; fi
printf '__HXGL_END__\n__HXGL_BEGIN__ ssh\n'
if command -v logread >/dev/null 2>&1; then
  (logread 2>&1; printf '\n__HXGL_RC__ %s\n' "$?") | tail -n 98 | cut -c 1-384
elif command -v journalctl >/dev/null 2>&1; then
  (journalctl -n 96 --no-pager -o short-iso -u ssh -u sshd -u dropbear 2>&1; printf '\n__HXGL_RC__ %s\n' "$?") | tail -n 98 | cut -c 1-384
else printf '__HXGL_MISSING__\n'; fi
printf '__HXGL_END__\n'
if test -r /proc/meminfo; then
  awk '$1=="MemTotal:" {print "__HXGL_METRIC__ mem_total_kib "$2} $1=="MemAvailable:" {print "__HXGL_METRIC__ mem_available_kib "$2} $1=="SwapTotal:" {print "__HXGL_METRIC__ swap_total_kib "$2} $1=="SwapFree:" {print "__HXGL_METRIC__ swap_free_kib "$2}' /proc/meminfo
fi
if test -r /proc/uptime; then awk '{print "__HXGL_METRIC__ uptime_seconds "$1}' /proc/uptime; fi
if test -r /proc/sys/kernel/random/boot_id; then printf '__HXGL_BOOT__ '; cat /proc/sys/kernel/random/boot_id; fi
if test -d /proc; then
  dropbear_processes=0 dropbear_running=0 dropbear_sleeping=0 dropbear_blocked=0 dropbear_stopped=0 dropbear_zombie=0 dropbear_other=0
  sshd_processes=0 sshd_running=0 sshd_sleeping=0 sshd_blocked=0 sshd_stopped=0 sshd_zombie=0 sshd_other=0
  sshfs_processes=0 sshfs_running=0 sshfs_sleeping=0 sshfs_blocked=0 sshfs_stopped=0 sshfs_zombie=0 sshfs_other=0
  scanned=0 limited=0 scan_errors=0
  for process in /proc/[0-9]*; do
    test -d "$process" || continue
    if test "$scanned" -ge 128; then limited=1; break; fi
    scanned=$((scanned + 1))
    if ! IFS= read -r name < "$process/comm" 2>/dev/null; then scan_errors=$((scan_errors + 1)); continue; fi
    case "$name" in dropbear|sshd|sshfs) ;; *) continue ;; esac
    state=unknown
    if IFS= read -r value < "$process/stat" 2>/dev/null; then
      value=${value##*) }; state=${value%% *}
    fi
    # Names are fixed cases; no guest command line or path is emitted.
    case "$name" in
      dropbear)
        dropbear_processes=$((dropbear_processes + 1))
        case "$state" in
          R) dropbear_running=$((dropbear_running + 1));;
          S|I) dropbear_sleeping=$((dropbear_sleeping + 1));;
          D) dropbear_blocked=$((dropbear_blocked + 1));;
          T|t) dropbear_stopped=$((dropbear_stopped + 1));;
          Z) dropbear_zombie=$((dropbear_zombie + 1));;
          *) dropbear_other=$((dropbear_other + 1));;
        esac;;
      sshd)
        sshd_processes=$((sshd_processes + 1))
        case "$state" in
          R) sshd_running=$((sshd_running + 1));;
          S|I) sshd_sleeping=$((sshd_sleeping + 1));;
          D) sshd_blocked=$((sshd_blocked + 1));;
          T|t) sshd_stopped=$((sshd_stopped + 1));;
          Z) sshd_zombie=$((sshd_zombie + 1));;
          *) sshd_other=$((sshd_other + 1));;
        esac;;
      sshfs)
        sshfs_processes=$((sshfs_processes + 1))
        case "$state" in
          R) sshfs_running=$((sshfs_running + 1));;
          S|I) sshfs_sleeping=$((sshfs_sleeping + 1));;
          D) sshfs_blocked=$((sshfs_blocked + 1));;
          T|t) sshfs_stopped=$((sshfs_stopped + 1));;
          Z) sshfs_zombie=$((sshfs_zombie + 1));;
          *) sshfs_other=$((sshfs_other + 1));;
        esac;;
    esac
  done
  printf '__HXGL_METRIC__ process_scan_examined %s\n__HXGL_METRIC__ process_scan_limited %s\n__HXGL_METRIC__ process_scan_errors %s\n' "$scanned" "$limited" "$scan_errors"
  for entry in \
    "dropbear_processes=$dropbear_processes" "dropbear_running=$dropbear_running" "dropbear_sleeping=$dropbear_sleeping" "dropbear_blocked=$dropbear_blocked" "dropbear_stopped=$dropbear_stopped" "dropbear_zombie=$dropbear_zombie" "dropbear_other=$dropbear_other" \
    "sshd_processes=$sshd_processes" "sshd_running=$sshd_running" "sshd_sleeping=$sshd_sleeping" "sshd_blocked=$sshd_blocked" "sshd_stopped=$sshd_stopped" "sshd_zombie=$sshd_zombie" "sshd_other=$sshd_other" \
    "sshfs_processes=$sshfs_processes" "sshfs_running=$sshfs_running" "sshfs_sleeping=$sshfs_sleeping" "sshfs_blocked=$sshfs_blocked" "sshfs_stopped=$sshfs_stopped" "sshfs_zombie=$sshfs_zombie" "sshfs_other=$sshfs_other"; do
    printf '__HXGL_METRIC__ %s %s\n' "${entry%%=*}" "${entry#*=}"
  done
fi
printf '__HXGL_COMPLETE__\n'
'''


class GuestProbeUnavailable(RuntimeError):
    def __init__(self, state: str = 'unavailable', code: str = '') -> None:
        self.state = state if isinstance(state, str) and state in {'stopped', 'unsupported', 'unavailable'} else 'unavailable'
        expected = {'stopped': 'guest_stopped', 'unsupported': 'unsupported_guest', 'unavailable': 'guest_unavailable'}
        self.code = code if isinstance(code, str) and code in expected.values() else expected[self.state]
        super().__init__(self.code)


@dataclass
class _Probe:
    root: Path
    environment_id: str
    runtime: Path
    kind: str
    callback: Any

    def get(self):
        return self.callback() if self.callback is not None else None


def _number(value: Any, maximum: float = 1e15) -> int | float | None:
    if type(value) is int:
        return value if 0 <= value <= maximum else None
    return value if type(value) is float and math.isfinite(value) and 0 <= value <= maximum else None


def _integer(value: Any, maximum: int = 2**31 - 1) -> int:
    return value if type(value) is int and 0 <= value <= maximum else 0


def _metric_number(name: str, value: Any) -> int | float | None:
    if name == 'uptime_seconds':
        return _number(value)
    limit = (1 if name == 'process_scan_limited' else MAX_PROCESS_SCAN
             if name in _PROCESS_METRICS or name.startswith('process_scan_') else 1e15)
    return value if type(value) is int and 0 <= value <= limit else None


def _enum(value: Any, choices: Any, default: str = '') -> str:
    return value if isinstance(value, str) and value in choices else default


def _timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return value if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _boot_id(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) != 36:
        return None
    try:
        parsed = uuid.UUID(value)
        return str(parsed) if str(parsed) == value.lower() else None
    except ValueError:
        return None


def _local_time(value: Any) -> str | None:
    if not isinstance(value, str) or not _LOCAL_TIME.fullmatch(value):
        return None
    try:
        datetime.fromisoformat(value)
        return value
    except ValueError:
        return None


def guest_capture_in_progress() -> bool:
    return _IN_CAPTURE.get()


def validate_transport_evidence(value: Any) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    codes = value.get('codes') if isinstance(value.get('codes'), list) else []
    out = {'codes': list(dict.fromkeys(x for x in codes[:32] if isinstance(x, str) and x in _TRANSPORT_CODES)),
           'timed_out': value.get('timed_out') is True,
           'bytes_seen': _integer(value.get('bytes_seen')),
           'omitted_lines': _integer(value.get('omitted_lines'))}
    out['failure_stage'] = _enum(value.get('failure_stage'), _TRANSPORT_STAGES, 'unknown')
    code = value.get('returncode')
    if type(code) is int and -255 <= code <= 255:
        out['returncode'] = code
    return out


def transport_evidence(stderr: Any = b'', returncode: int | None = None, timed_out: bool = False) -> dict[str, Any]:
    """Classify errors without exporting even a sanitized copy of guest prose."""
    data = stderr if isinstance(stderr, bytes) else stderr.encode('utf-8', errors='replace') if isinstance(stderr, str) else b''
    text = data[-16384:].decode('utf-8', errors='replace').lower()
    rules = (
        ('connection_timeout', ('timed out', 'timeout', 'deadline exceeded')),
        ('connection_refused', ('connection refused',)),
        ('connection_reset', ('connection reset',)),
        ('connection_closed', ('connection closed', 'remote host closed')),
        ('network_unreachable', ('network is unreachable', 'no route to host', 'network unreachable')),
        ('dns_failed', ('could not resolve hostname', 'name or service not known')),
        ('authentication_failed', ('permission denied (', 'authentication failed', 'no supported authentication methods')),
        ('host_key_failed', ('host key verification failed', 'remote host identification has changed', 'offending ')),
        ('channel_limit', ('administratively prohibited', 'too many sessions', 'no more sessions', 'maxstartups', 'maxsessions')),
        ('channel_open_failed', ('channel open failed', 'open failed:')),
        ('local_resource_limit', ('too many open files', 'cannot allocate memory', 'resource temporarily unavailable')),
        ('broken_pipe', ('broken pipe',)),
        ('multiplex_unavailable', ('control socket connect', 'mux_client', 'muxclient', 'multiplex')),
    )
    codes = [code for code, signatures in rules if any(word in text for word in signatures)]
    # These labels describe explicit stderr signatures only. A command deadline
    # with no SSH output does not establish whether TCP or SSH was reached.
    stage = 'unknown'
    if any(phrase in text for phrase in ('during banner exchange', 'kex_exchange_identification', 'ssh_exchange_identification')):
        stage = 'ssh_identification'
    elif re.search(r'(?m)^ssh: connect to host .+ port [0-9]+:', text):
        stage = 'tcp_connect'
    elif any(phrase in text for phrase in ('no matching key exchange method found', 'no matching cipher found', 'no matching host key type found')):
        stage = 'key_exchange'
    elif any(phrase in text for phrase in ('host key verification failed', 'remote host identification has changed')):
        stage = 'host_key_verification'
    elif any(phrase in text for phrase in ('permission denied (', 'authentication failed', 'no supported authentication methods')):
        stage = 'authentication'
    elif any(phrase in text for phrase in ('channel open failed', 'open failed:', 'administratively prohibited', 'too many sessions', 'no more sessions', 'maxsessions')):
        stage = 'session_open'
    elif any(phrase in text for phrase in ('control socket connect', 'mux_client', 'muxclient', 'multiplex')):
        stage = 'multiplex'
    if timed_out:
        codes.append('command_timeout')
    if returncode == 255:
        codes.append('ssh_exit_255')
    return validate_transport_evidence({'codes': codes, 'returncode': returncode, 'timed_out': timed_out, 'failure_stage': stage,
        'bytes_seen': min(len(data), 2**31 - 1), 'omitted_lines': len(text.splitlines())})


def _guest_record(line: str) -> dict[str, Any] | None:
    lower = line.lower()
    rules = (
        ('oom_kill', ('killed process ', 'oom-kill:', 'oom_reaper:')),
        ('out_of_memory', ('out of memory', 'cannot allocate memory')),
        ('kernel_panic', ('kernel panic', 'not syncing:')),
        ('kernel_oops', ('kernel bug at ', 'oops:')),
        ('soft_lockup', ('soft lockup', 'hard lockup')),
        ('hung_task', ('blocked for more than', 'hung task')),
        ('filesystem_error', ('ext4-fs error', 'ext4-fs warning', 'jffs2 error', 'ubifs error')),
        ('io_error', ('i/o error', 'input/output error', 'buffer i/o error')),
        ('storage_full', ('no space left', 'out of inodes', 'disk quota exceeded')),
        ('read_only_filesystem', ('read-only file system', 'remounting filesystem read-only')),
        ('fuse_disconnected', ('transport endpoint is not connected', 'fuse: failed', 'sshfs: connection')),
        ('ssh_connection_limit', ('maxstartups', 'maxsessions', 'too many sessions', 'no more sessions')),
        ('ssh_authentication_failed', ('bad password attempt', 'pubkey auth failed', 'failed password', 'authentication failure')),
        ('ssh_session_opened', ('pubkey auth succeeded', 'accepted publickey', 'session opened for user')),
        ('ssh_session_closed_before_auth', ('exit before auth', 'connection closed by authenticating user', 'connection closed by invalid user')),
        ('ssh_session_closed_after_auth', ('exit (', 'session closed for user')),
        ('ssh_server_started', ('running in background', 'server listening on')),
        ('connection_timeout', ('connection timed out', 'timeout before auth')),
        ('connection_refused', ('connection refused',)),
        ('connection_reset', ('connection reset',)),
        ('connection_closed', ('connection closed', 'remote host closed')),
        ('broken_pipe', ('broken pipe',)),
        ('too_many_open_files', ('too many open files',)),
        ('process_limit', ('fork: resource temporarily unavailable', 'cannot fork', 'failed to fork')),
        ('service_crash', ('in a crash loop', 'procd: instance ', 'service exited with')),
        ('network_link_down', ('link is down', 'link down', 'entered disabled state')),
        ('network_link_up', ('link is up', 'link up', 'entered forwarding state')),
        ('permission_denied', ('permission denied', 'operation not permitted')),
        ('segmentation_fault', ('segmentation fault', 'segfault at')),
        ('watchdog_reset', ('watchdog: watchdog', 'watchdog reset', 'watchdog detected')),
    )
    code = next((code for code, signatures in rules if any(part in lower for part in signatures)), None)
    if code is None:
        return None
    # Session signatures require an actual SSH-daemon label rather than a
    # general application line containing a similar English phrase.
    if code.startswith('ssh_') and not re.search(r'\b(?:dropbear|sshd)(?:\[|\s|:)', lower):
        return None
    row: dict[str, Any] = {'code': code}
    if code in {'ssh_session_closed_before_auth', 'ssh_session_closed_after_auth'}:
        row['close_reason'] = next((label for label, phrases in (
            ('authentication_timeout', ('timeout before auth', 'authentication timeout')),
            ('idle_timeout', ('idle timeout',)),
            ('keepalive_timeout', ('keepalive timeout', 'keepalive failure')),
            ('connection_reset', ('connection reset',)),
            ('connection_closed', ('connection closed', 'remote host closed')),
        ) if any(phrase in lower for phrase in phrases)), 'unknown')
    match = _GUEST_TIME.search(line)
    if match and _timestamp(match.group(1)):
        row['timestamp'] = match.group(1)
    else:
        local = _OPENWRT_TIME.match(line)
        if local:
            try:
                row['guest_local_time'] = datetime.strptime(local.group(1), '%a %b %d %H:%M:%S %Y').isoformat()
            except ValueError:
                pass
    uptime = _UPTIME.match(line)
    if uptime:
        value = _number(float(uptime.group(1)))
        if value is not None:
            row['uptime_seconds'] = value
    pid = re.search(r'\b(?:dropbear|sshd)\[(\d{1,10})\]', lower)
    if pid:
        row['pid'] = int(pid.group(1))
    return row


def _validate_source(value: Any) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    rows = value.get('records') if isinstance(value.get('records'), list) else []
    valid = []
    for row in rows[-MAX_RECORDS:]:
        if not isinstance(row, dict) or not _enum(row.get('code'), _GUEST_CODES):
            continue
        item = {'code': row['code']}
        if row['code'] in {'ssh_session_closed_before_auth', 'ssh_session_closed_after_auth'}:
            item['close_reason'] = _enum(row.get('close_reason'), _SSH_CLOSE_REASONS, 'unknown')
        stamp = _timestamp(row.get('timestamp'))
        if stamp:
            item['timestamp'] = stamp
        local_time = _local_time(row.get('guest_local_time'))
        if local_time:
            item['guest_local_time'] = local_time
        uptime = _number(row.get('uptime_seconds'))
        if uptime is not None:
            item['uptime_seconds'] = uptime
        if type(row.get('pid')) is int and 0 <= row['pid'] <= 2**31 - 1:
            item['pid'] = row['pid']
        valid.append(item)
    return {'state': _enum(value.get('state'), _SOURCE_STATES, 'not_observed'),
            'records': valid, 'lines_seen': _integer(value.get('lines_seen')),
            'omitted_lines': _integer(value.get('omitted_lines')), 'truncated': value.get('truncated') is True}


def _project_guest_output(output: Any) -> dict[str, Any]:
    data = output if isinstance(output, bytes) else output.encode('utf-8', errors='replace') if isinstance(output, str) else b''
    text = _ANSI.sub('', data[:MAX_OUTPUT_BYTES].decode('utf-8', errors='replace'))
    sources = {name: {'state': 'not_observed', 'records': [], 'lines_seen': 0, 'omitted_lines': 0,
                      'truncated': len(data) > MAX_OUTPUT_BYTES} for name in _SOURCE_NAMES}
    metrics: dict[str, int | float] = {}
    source = None
    complete = False
    boot_id = None
    for line in text.splitlines()[:400]:
        if line.startswith('__HXGL_BEGIN__ '):
            candidate = line.partition(' ')[2]
            source = candidate if candidate in sources else None
            continue
        if line == '__HXGL_END__':
            source = None
            continue
        if line == '__HXGL_COMPLETE__':
            complete = True
            continue
        if line.startswith('__HXGL_BOOT__ '):
            boot_id = _boot_id(line.partition(' ')[2])
            continue
        if line.startswith('__HXGL_METRIC__ '):
            parts = line.split()
            if len(parts) == 3 and parts[1] in _METRICS:
                try:
                    value = float(parts[2])
                    value = _number(value)
                    if value is not None:
                        parsed = int(value) if value.is_integer() else value
                        validated = _metric_number(parts[1], parsed)
                        if validated is not None:
                            metrics[parts[1]] = validated
                except (ValueError, OverflowError):
                    pass
            continue
        if source is None:
            continue
        target = sources[source]
        if line == '__HXGL_MISSING__':
            target['state'] = 'missing'
            continue
        if line.startswith('__HXGL_RC__ '):
            try:
                rc = int(line.partition(' ')[2])
                target['state'] = 'available' if rc == 0 else ('permission_denied' if any(
                    r['code'] == 'permission_denied' for r in target['records']) else 'failed')
            except ValueError:
                target['state'] = 'failed'
            continue
        if not line.strip():
            continue
        target['lines_seen'] += 1
        target['truncated'] |= len(line) >= 384 or target['lines_seen'] >= 96
        record = _guest_record(line[:384])
        if source == 'ssh' and record is not None and record['code'] not in {
                'ssh_connection_limit', 'ssh_authentication_failed', 'ssh_session_opened', 'ssh_session_closed',
                'ssh_session_closed_before_auth', 'ssh_session_closed_after_auth',
                'ssh_server_started', 'fuse_disconnected', 'connection_timeout', 'connection_refused',
                'connection_reset', 'connection_closed', 'broken_pipe', 'too_many_open_files', 'process_limit'}:
            record = None
        if record is not None:
            target['records'].append(record)
            if len(target['records']) > MAX_RECORDS:
                target['records'].pop(0)
                target['truncated'] = True
        else:
            target['omitted_lines'] += 1
    result = {'sources': {name: _validate_source(value) for name, value in sources.items()},
            'metrics': metrics, 'complete': complete, 'bytes_seen': min(len(data), 2**31 - 1),
            'truncated': len(data) > MAX_OUTPUT_BYTES}
    if boot_id is not None:
        result['guest_boot_id'] = boot_id
    return result


def validate_guest_receipt(value: Any) -> dict[str, Any] | None:
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int or value['schema_version'] != 1 or
            not _enum(value.get('event'), {'guest_log_capture', 'guest_transport'}) or
            not _enum(value.get('kind'), _KINDS) or not _enum(value.get('state'), _STATES) or
            not _enum(value.get('reason'), _REASONS)):
        return None
    stamp = _timestamp(value.get('captured_at'))
    if stamp is None:
        return None
    row = {'schema_version': 1, 'event': value['event'], 'kind': value['kind'],
           'state': value['state'], 'reason': value['reason'], 'captured_at': stamp,
           'content_omitted': True, 'guest_observation_is_not_attestation': True,
           'transport': validate_transport_evidence(value.get('transport'))}
    if value['event'] == 'guest_transport':
        if not _enum(value.get('operation'), _OPERATIONS):
            return None
        row['operation'] = value['operation']
    else:
        sources = value.get('sources') if isinstance(value.get('sources'), dict) else {}
        row['sources'] = {name: _validate_source(sources.get(name)) for name in _SOURCE_NAMES}
        metrics = value.get('metrics') if isinstance(value.get('metrics'), dict) else {}
        row['metrics'] = {name: number for name in _METRICS if (number := _metric_number(name, metrics.get(name))) is not None}
        row['complete'] = value.get('complete') is True
        row['bytes_seen'] = _integer(value.get('bytes_seen'))
        row['truncated'] = value.get('truncated') is True
        boot_id = _boot_id(value.get('guest_boot_id'))
        if boot_id is not None:
            row['guest_boot_id'] = boot_id
    return row


def _location(root: Any, environment_id: Any, runtime_root: Any) -> tuple[Path, str, Path]:
    from .vm_logs import _runtime_root
    root = Path(root).expanduser().absolute()
    if not isinstance(environment_id, str) or (environment_id and not _ID.fullmatch(environment_id)):
        raise ValueError('Invalid guest environment identity.')
    runtime = _runtime_root(root, environment_id, runtime_root)
    return root, environment_id, runtime


def register_guest_probe(workspace_root: Any, *, environment_id: str, runtime_root: Any,
                         kind: str, probe: Any = None) -> bool:
    try:
        root, environment_id, runtime = _location(workspace_root, environment_id, runtime_root)
        if not _enum(kind, _KINDS):
            return False
        callback = weakref.WeakMethod(probe) if inspect.ismethod(probe) else weakref.ref(probe) if probe is not None else None
        with _REGISTRY_LOCK:
            key = str(root), environment_id
            _REGISTRY.pop(key, None)
            _REGISTRY[key] = _Probe(root, environment_id, runtime, kind, callback)
            while len(_REGISTRY) > MAX_REGISTERED:
                _REGISTRY.popitem(last=False)
        from .vm_logs import register_workspace_runtime
        register_workspace_runtime(root, environment_id=environment_id, runtime_root=runtime)
        return True
    except (OSError, ValueError, TypeError):
        return False


def _open_capture_directory(runtime: Path) -> int:
    """Pin every ancestor; never redirect a capture through a symlink."""
    from .vm_logs import _allowed_path
    if not _allowed_path(runtime) or os.open not in os.supports_dir_fd or not hasattr(os, 'O_NOFOLLOW'):
        raise ValueError('Safe guest capture paths are unavailable.')
    path = runtime
    if path.parts[:2] == ('/', 'tmp'):
        path = Path('/tmp').resolve().joinpath(*path.parts[2:])
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_CLOEXEC', 0)
    parent = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        info = os.fstat(parent)
        # Environment roots can legitimately inherit group write from umask
        # 0002. The pinned, account-owned root is not the receipt directory:
        # observations below still require their own private 0700 directory.
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o002:
            raise ValueError('Guest runtime is unsafe.')
        try:
            os.mkdir('guest-diagnostics', 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        child = os.open('guest-diagnostics', flags, dir_fd=parent)
        info = os.fstat(child)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            os.close(child)
            raise ValueError('Guest capture directory is unsafe.')
        return child
    finally:
        os.close(parent)


def _read_rows(runtime: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from .vm_logs import _read_tail, _complete_lines
    result = _read_tail(runtime / 'guest-diagnostics' / FILENAME, MAX_RECEIPT_BYTES)
    rows = []
    invalid = 0
    for line in _complete_lines(result['data'], result['truncated'])[-MAX_RECEIPTS:]:
        try:
            row = validate_guest_receipt(json.loads(line))
        except (ValueError, RecursionError):
            row = None
        if row is None:
            invalid += 1
        else:
            rows.append(row)
    result['invalid_receipts'] = invalid
    return rows, result


def _persist(runtime: Path, receipt: dict[str, Any]) -> bool:
    parent = lock = temporary = None
    temp_name = '.guest-' + uuid.uuid4().hex
    try:
        import fcntl
        valid = validate_guest_receipt(receipt)
        if valid is None:
            return False
        parent = _open_capture_directory(runtime)
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0)
        lock = os.open('.lock', flags, 0o600, dir_fd=parent)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            return False
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            info = os.stat(FILENAME, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                return False
        except FileNotFoundError:
            pass
        rows, _ = _read_rows(runtime)
        last_success = next((r for r in reversed(rows) if r['event'] == 'guest_log_capture'
                             and r['state'] in {'ready', 'partial'}), None)
        rows.append(valid)
        rows = rows[-MAX_RECEIPTS:]
        if last_success is not None and last_success not in rows and valid['state'] not in {'ready', 'partial'}:
            rows = [last_success, *rows[-(MAX_RECEIPTS - 1):]]
        payload = b''.join((json.dumps(row, ensure_ascii=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii') for row in rows)
        while len(payload) > MAX_RECEIPT_BYTES and len(rows) > 1:
            rows.pop(1 if rows[0] is last_success else 0)
            payload = b''.join((json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii') for row in rows)
        if len(payload) > MAX_RECEIPT_BYTES:
            return False
        temporary = os.open(temp_name, flags | os.O_EXCL, 0o600, dir_fd=parent)
        while payload:
            written = os.write(temporary, payload)
            if written <= 0:
                return False
            payload = payload[written:]
        os.fsync(temporary)
        os.close(temporary)
        temporary = None
        os.replace(temp_name, FILENAME, src_dir_fd=parent, dst_dir_fd=parent)
        return True
    except (OSError, ValueError, RuntimeError, ImportError):
        return False
    finally:
        if temporary is not None:
            os.close(temporary)
        if parent is not None:
            try:
                os.unlink(temp_name, dir_fd=parent)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            os.close(parent)
        if lock is not None:
            os.close(lock)


def _blank(probe: _Probe, reason: str, state: str = 'unavailable') -> dict[str, Any]:
    return {'schema_version': 1, 'event': 'guest_log_capture', 'kind': probe.kind,
            'state': state, 'reason': reason, 'captured_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'sources': {}, 'metrics': {}, 'transport': {}, 'complete': False, 'truncated': False, 'bytes_seen': 0}


def _semaphore() -> asyncio.Semaphore:
    loop = asyncio.get_running_loop()
    return _SEMAPHORES.setdefault(loop, asyncio.Semaphore(2))


async def _capture(probe: _Probe, reason: str) -> dict[str, Any]:
    row = _blank(probe, reason)
    callback = probe.get()
    if probe.kind == 'unsupported':
        row['state'] = 'unsupported'
    elif callback is None:
        row['state'] = 'unavailable'
    else:
        async with _semaphore():
            token = _IN_CAPTURE.set(True)
            try:
                rc, output, error = await asyncio.wait_for(callback(GUEST_LOG_SCRIPT, PROBE_SECONDS), PROBE_SECONDS + .5)
                row.update(_project_guest_output(output))
                row['transport'] = transport_evidence(error, returncode=rc)
                available = sum(source['state'] == 'available' for source in row['sources'].values())
                if type(rc) is not int or rc != 0:
                    row['state'] = 'unavailable'
                elif not row['complete']:
                    row['state'] = 'invalid_output'
                else:
                    row['state'] = 'ready' if available == len(_SOURCE_NAMES) else 'partial'
            except GuestProbeUnavailable as error:
                row['state'] = error.state
            except (TimeoutError, asyncio.TimeoutError):
                row['transport'] = transport_evidence(timed_out=True)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                row['transport'] = transport_evidence(str(error))
            finally:
                _IN_CAPTURE.reset(token)
    valid = validate_guest_receipt(row)
    if valid is None:
        valid = validate_guest_receipt(_blank(probe, reason, 'invalid_output'))
    await asyncio.to_thread(_persist, probe.runtime, valid)
    return valid


def request_guest_capture(workspace_root: Any, environment_id: str, reason: str = 'transport_failure') -> bool:
    if guest_capture_in_progress() or not _enum(reason, _REASONS):
        return False
    try:
        loop = asyncio.get_running_loop()
        root = str(Path(workspace_root).expanduser().absolute())
        with _REGISTRY_LOCK:
            probe = _REGISTRY.get((root, environment_id))
        if probe is None:
            return False
        key = root, environment_id, id(loop)
        if key in _TASKS and not _TASKS[key].done():
            return False
        now = time.monotonic()
        if now - _LAST_CAPTURE.get(key, -CAPTURE_COOLDOWN) < CAPTURE_COOLDOWN:
            return False
        _LAST_CAPTURE[key] = now
        async def run():
            try:
                row = await _capture(probe, reason)
                # One read-only recovery observation can preserve the guest's
                # ring log after a short SSH outage. It never replays a task.
                if row['state'] in {'unavailable', 'invalid_output'}:
                    await asyncio.sleep(RECOVERY_DELAY)
                    await _capture(probe, 'recovery')
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            finally:
                current = asyncio.current_task()
                _BACKGROUND_TASKS.discard(current)
                if _TASKS.get(key) is current:
                    _TASKS.pop(key, None)
        task = loop.create_task(run(), name='harnessy-guest-log-capture')
        _TASKS[key] = task
        _BACKGROUND_TASKS.add(task)
        while len(_LAST_CAPTURE) > MAX_REGISTERED * 2:
            _LAST_CAPTURE.pop(next(iter(_LAST_CAPTURE)))
        return True
    except (RuntimeError, ValueError, TypeError):
        return False


def record_guest_transport(workspace_root: Any, *, environment_id: str, runtime_root: Any,
                           kind: str, operation: str = 'ssh_command', stderr: Any = b'',
                           returncode: int | None = None, timed_out: bool = False) -> bool:
    if guest_capture_in_progress() or not _enum(kind, _KINDS) or not _enum(operation, _OPERATIONS):
        return False
    try:
        root, environment_id, runtime = _location(workspace_root, environment_id, runtime_root)
        reason = {'mapping_probe': 'mapping_failure', 'sshfs': 'sshfs_failure'}.get(operation, 'transport_failure')
        receipt = {'schema_version': 1, 'event': 'guest_transport', 'kind': kind,
            'state': 'unavailable', 'reason': reason, 'operation': operation,
            'captured_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'transport': transport_evidence(stderr, returncode=returncode, timed_out=timed_out)}
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return _persist(runtime, receipt)
        key = str(root), environment_id, id(loop)
        if key not in _PERSIST_TASKS and len(_PERSIST_TASKS) >= MAX_REGISTERED:
            return False
        pending = _PERSIST_PENDING.setdefault(key, [])
        pending.append((runtime, receipt))
        del pending[:-MAX_RECEIPTS]
        if key not in _PERSIST_TASKS or _PERSIST_TASKS[key].done():
            async def write_pending():
                try:
                    while _PERSIST_PENDING.get(key):
                        path, row = _PERSIST_PENDING[key].pop(0)
                        await asyncio.to_thread(_persist, path, row)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass
                finally:
                    _PERSIST_TASKS.pop(key, None)
                    _PERSIST_PENDING.pop(key, None)
            _PERSIST_TASKS[key] = loop.create_task(write_pending(), name='harnessy-guest-transport-receipt')
        request_guest_capture(root, environment_id, reason)
        return True  # Accepted for bounded background persistence, not a disk-write receipt.
    except (OSError, ValueError, TypeError):
        return False


async def refresh_guest_logs() -> dict[str, Any]:
    """Refresh registered guests without creating/starting one for export."""
    global _LAST_REFRESH
    with _REGISTRY_LOCK:
        probes = list(_REGISTRY.values())[-16:]
        limited = len(_REGISTRY) > 16
    tasks = []
    for probe in probes:
        key = str(probe.root), probe.environment_id, id(asyncio.get_running_loop())
        running = _TASKS.get(key)
        if running is None or running.done() or running.cancelling():
            async def run_export(probe=probe, key=key):
                try:
                    return await _capture(probe, 'export')
                finally:
                    if _TASKS.get(key) is asyncio.current_task():
                        _TASKS.pop(key, None)
            running = asyncio.create_task(run_export(), name='harnessy-guest-export-capture')
            _TASKS[key] = running
        tasks.append(running)
        _WAITERS[running] = _WAITERS.get(running, 0) + 1
    done = set()
    try:
        if tasks:
            done, pending = await asyncio.wait(tasks, timeout=REFRESH_SECONDS)
            limited = limited or bool(pending)
        _LAST_REFRESH = {'status': 'limited' if limited else 'completed', 'registered': len(probes), 'completed': len(done),
                         'limited': limited, 'observed_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds')}
        return dict(_LAST_REFRESH)
    finally:
        cancelled = []
        for task in tasks:
            remaining = _WAITERS.get(task, 1) - 1
            if remaining:
                _WAITERS[task] = remaining
            else:
                _WAITERS.pop(task, None)
            if not remaining and task not in _BACKGROUND_TASKS and not task.done():
                task.cancel()
                cancelled.append(task)
        if cancelled:
            # Provider cleanup must not turn a bounded diagnostics download
            # into an unbounded wait on an unavailable guest or disk.
            await asyncio.wait(cancelled, timeout=.25)


def _capture_metadata(row: Any) -> dict[str, Any] | None:
    valid = validate_guest_receipt(row)
    if valid is None or valid['event'] != 'guest_log_capture':
        return None
    result = {'captured_at': valid['captured_at'], 'state': valid['state'], 'reason': valid['reason'], 'kind': valid['kind'],
            'source_states': {name: value['state'] for name, value in valid['sources'].items()},
            'metrics': valid['metrics'], 'transport': valid['transport'], 'content_omitted': True}
    if 'guest_boot_id' in valid:
        result['guest_boot_id'] = valid['guest_boot_id']
    return result


def validate_guest_log_report(value: Any) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    environments = value.get('environments') if isinstance(value.get('environments'), list) else []
    report = {'schema_version': 1, 'status': 'collected' if value.get('status') == 'collected' else 'unavailable',
        'scope': 'sanitized_guest_observations', 'environments': [], 'limited': value.get('limited') is True,
        'limits': {'environments': MAX_ENVIRONMENTS, 'receipt_bytes': MAX_RECEIPT_BYTES, 'export_bytes': MAX_EXPORT_BYTES,
                   'receipts_per_environment': MAX_RECEIPTS, 'guest_probe_seconds': PROBE_SECONDS},
        'capture_policy': 'fixed_readonly_commands; unavailable_guests_not_started; raw_guest_content_never_saved'}
    refresh = value.get('refresh') if isinstance(value.get('refresh'), dict) else {}
    report['refresh'] = {'status': _enum(refresh.get('status'), {'not_requested', 'completed', 'limited'}, 'not_requested'),
        'registered': _integer(refresh.get('registered'), 16), 'completed': _integer(refresh.get('completed'), 16),
        'limited': refresh.get('limited') is True}
    stamp = _timestamp(refresh.get('observed_at'))
    if stamp:
        report['refresh']['observed_at'] = stamp
    for row in environments[:MAX_ENVIRONMENTS]:
        if not isinstance(row, dict) or not isinstance(row.get('workspace_id'), str) or not _HASH.fullmatch(row['workspace_id']):
            continue
        eid = row.get('environment_id')
        if not isinstance(eid, str) or (eid and not _ID.fullmatch(eid)):
            continue
        status = _enum(row.get('receipt_status'), {'included', 'missing', 'unsafe', 'unreadable', 'limited'}, 'unreadable')
        item = {'workspace_id': row['workspace_id'], 'environment_id': eid, 'receipt_status': status,
                'captures_retained': _integer(row.get('captures_retained'), MAX_RECEIPTS),
                'transport_failures_retained': _integer(row.get('transport_failures_retained'), MAX_RECEIPTS),
                'invalid_receipts': _integer(row.get('invalid_receipts'))}
        member = f"guest-logs/{row['workspace_id']}/{eid or 'legacy'}/guest-events.technical.jsonl"
        if status == 'included' and row.get('archive_member') == member:
            item['archive_member'] = member
        else:
            item['receipt_status'] = 'missing' if status == 'included' else status
        capture = row.get('latest_capture')
        if isinstance(capture, dict):
            # Rebuild metadata by routing it through the full receipt schema.
            states = capture.get('source_states') if isinstance(capture.get('source_states'), dict) else {}
            projected = _capture_metadata({'schema_version': 1, 'event': 'guest_log_capture', **capture,
                'sources': {name: {'state': states.get(name)} for name in _SOURCE_NAMES}})
            if projected:
                item['latest_capture'] = projected
        for name in ('last_success_at', 'last_failure_at'):
            stamp = _timestamp(row.get(name))
            if stamp:
                item[name] = stamp
        report['environments'].append(item)
    return report


def collect_guest_log_diagnostics(latest: Path) -> dict[str, Any]:
    from .vm_logs import _discover_workspaces, _runtime_environments
    deadline = time.monotonic() + 3
    roots, _discovery = _discover_workspaces(Path(latest).absolute(), deadline)
    report: dict[str, Any] = {'status': 'collected', 'environments': [], 'limited': False, 'refresh': dict(_LAST_REFRESH)}
    members: dict[str, bytes] = {}
    total = 0
    for root, _origin in roots:
        environments, limited = _runtime_environments(root)
        report['limited'] |= limited
        for eid, runtime in environments:
            if len(report['environments']) >= MAX_ENVIRONMENTS or time.monotonic() >= deadline:
                report['limited'] = True
                break
            rows, status = _read_rows(runtime)
            item = {'workspace_id': hashlib.sha256(str(root).encode()).hexdigest(), 'environment_id': eid,
                'receipt_status': status['status'], 'captures_retained': sum(r['event'] == 'guest_log_capture' for r in rows),
                'transport_failures_retained': sum(r['event'] == 'guest_transport' for r in rows),
                'invalid_receipts': status['invalid_receipts']}
            payload = b''.join((json.dumps(row, ensure_ascii=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii') for row in rows)
            if rows and total + len(payload) <= MAX_EXPORT_BYTES:
                member = f"guest-logs/{item['workspace_id']}/{eid or 'legacy'}/guest-events.technical.jsonl"
                item['archive_member'] = member
                members[member] = payload
                total += len(payload)
            elif status['status'] == 'included':
                item['receipt_status'] = 'limited' if rows else 'missing'
                report['limited'] |= bool(rows)
            captures = [r for r in rows if r['event'] == 'guest_log_capture']
            if captures:
                item['latest_capture'] = _capture_metadata(captures[-1])
            success = next((r for r in reversed(captures) if r['state'] in {'ready', 'partial'}), None)
            failure = next((r for r in reversed(rows) if r['event'] == 'guest_transport'), None)
            if success:
                item['last_success_at'] = success['captured_at']
            if failure:
                item['last_failure_at'] = failure['captured_at']
            report['environments'].append(item)
    return {'report': validate_guest_log_report(report), 'members': members}


def summary_lines(report: Any) -> str:
    clean = validate_guest_log_report(report)
    lines = ['\nGuest system logs: GUEST_LOGS.json and guest-logs/ contain sanitized, bounded VM observations.',
             '  Only fixed operational signals and numeric facts are retained; guest prose and content are omitted.']
    for row in clean['environments']:
        name = row['environment_id'][:12] if row['environment_id'] else 'legacy'
        capture = row.get('latest_capture')
        if capture:
            sources = ', '.join(name + '=' + state for name, state in capture['source_states'].items())
            lines.append(f"  VM {name}: {capture['state']} at {capture['captured_at']}; {sources}.")
            codes = capture['transport']['codes']
            if codes:
                lines.append('    Transport signals: ' + ', '.join(codes) + '.')
        else:
            lines.append(f"  VM {name}: guest capture {row['receipt_status']}; retained transport failures {row['transport_failures_retained']}.")
    if clean['limited']:
        lines.append('  Collection reached a configured bound; additional observations may be absent.')
    lines.append('  Captures are timestamped observations, not proof of current guest health or a particular failure cause.\n')
    return '\n'.join(lines)
