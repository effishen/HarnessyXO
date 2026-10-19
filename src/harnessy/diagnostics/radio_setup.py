"""Bounded receipts from HarnessyXO's fixed guest radio setup scripts.

These are guest setup results, not trusted QEMU/controller output. Only reviewed
radio markers, package diagnostics and transport signatures are projected.
Unknown output, script bodies, credentials and guest file content are omitted.
The same schema is rebuilt when exporting an existing receipt.
"""
from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

from .technical import technical_error_evidence, validate_technical_evidence

RADIO_SETUP_FILENAME = 'radio-setup.log'
MAX_RADIO_RECEIPTS = 8
MAX_OUTPUT_BYTES = 16384
MAX_OUTPUT_RECORDS = 32
_LABELS = frozenset({'radio_probe', 'wifi_setup', 'bluetooth_packages',
    'bluetooth_emulator', 'bluetooth_attach', 'bluetooth_setup', 'bluetooth_stop',
    'bluetooth_h4_stop'})
_REASONS = frozenset({'not_requested', 'verified', 'not_detected', 'probe_failed',
    'setup_failed', 'package_install_failed', 'feed_update_failed',
    'stock_feeds_unavailable', 'module_load_failed', 'iw_missing',
    'insufficient_radios', 'btvirt_missing', 'vhci_missing', 'service_conflict',
    'service_start_failed', 'insufficient_controllers', 'interfaces_missing',
    'interface_create_failed', 'helper_unavailable', 'helper_integrity_failed',
    'helper_install_failed', 'cli_missing', 'controller_attach_failed',
    'crypto_unavailable'})
_DETAILS = frozenset({'none', 'unknown', 'dns_resolution_failed',
    'tls_verification_failed', 'network_unreachable', 'connection_failed',
    'kernel_abi_mismatch', 'signature_failed', 'disk_full', 'package_unavailable',
    'operation_timeout', 'ssh_command_failed', 'interface_create_failed',
    'network_permission_denied'})
_CODES = frozenset({'radio_setup', 'radio_detail', 'helper_result', 'radio_probe',
    'bluetooth_probe', 'package_dependency_missing', 'package_install_failed',
    'package_verification_failed',
    'package_unknown', 'package_version_conflict', 'package_download_failed',
    'feed_download_failed',
    'package_signature_failed', 'package_kernel_mismatch', 'storage_full',
    'tls_verification_failed', 'dns_resolution_failed', 'network_unreachable',
    'connection_refused', 'connection_timeout', 'permission_denied',
    'ssh_authentication_failed', 'ssh_host_key_failed', 'ssh_connection_closed',
    'shell_command_missing', 'module_missing', 'module_load_failed'})
_TOKEN = r'[a-zA-Z0-9][a-zA-Z0-9_.+~-]{0,95}'
_PACKAGE = re.compile('^' + _TOKEN + '$')
_HEX = re.compile(r'^[0-9a-f]{64}$')
_NUMERIC = frozenset({'wifi', 'wifi_interfaces', 'iw', 'bluetooth', 'vhci',
    'btvirt', 'btvirt_running', 'controllers', 'installed', 'helper', 'attach', 'cli'})


@lru_cache(maxsize=1)
def _script_identities() -> dict[tuple[int, str], str]:
    """Classify exact shipped scripts; a comment prefix alone is insufficient."""
    from ..environment import test_bluetooth as bt, test_radios as radios
    scripts = {
        'radio_probe': radios.PROBE_SCRIPT, 'wifi_setup': radios.WIFI_SETUP_SCRIPT,
        'bluetooth_packages': bt.BLUETOOTH_PACKAGES_SCRIPT,
        'bluetooth_attach': bt.BLUETOOTH_H4_SETUP_SCRIPT,
        'bluetooth_setup': radios.BLUETOOTH_SETUP_SCRIPT,
        'bluetooth_stop': radios.BLUETOOTH_STOP_SCRIPT,
        'bluetooth_h4_stop': bt.BLUETOOTH_H4_STOP_SCRIPT,
    }
    result = {}
    for label, script in scripts.items():
        encoded = script.encode('utf-8')
        result[(len(encoded), hashlib.sha256(encoded).hexdigest())] = label
    for arch in ('mips', 'mipsel', 'mips64', 'mips64el', 'arm64', 'x86_64'):
        try:
            encoded = bt.helper_install_script(arch).encode('utf-8')
        except bt.BluetoothHelperError:
            continue
        result[(len(encoded), hashlib.sha256(encoded).hexdigest())] = 'bluetooth_emulator'
    return result


def _integer(value: Any, maximum: int) -> int:
    return max(0, min(maximum, value)) if type(value) is int else 0


def _record(value: Any) -> dict[str, Any] | None:
    if (not isinstance(value, dict) or not isinstance(value.get('code'), str)
            or value['code'] not in _CODES):
        return None
    result = {'code': value['code']}
    if value['code'] in {'radio_setup', 'radio_detail'}:
        if not isinstance(value.get('kind'), str) or value['kind'] not in {'wifi', 'bluetooth'}:
            return None
        choices = _REASONS if value['code'] == 'radio_setup' else _DETAILS
        if not isinstance(value.get('result'), str) or value['result'] not in choices:
            return None
        result.update(kind=value['kind'], result=value['result'])
    elif value['code'] == 'helper_result':
        if not isinstance(value.get('result'), str) or value['result'] not in _REASONS:
            return None
        result['result'] = value['result']
    for field in ({'package_dependency_missing': ('package', 'dependency'),
                   'package_install_failed': ('package',), 'package_unknown': ('package',),
                   'package_verification_failed': ('package',),
                   'package_download_failed': ('package',),
                   'module_missing': ('module',)}.get(value['code'], ())):
        name = value.get(field)
        if isinstance(name, str) and _PACKAGE.fullmatch(name):
            result[field] = name
    for field in _NUMERIC if value['code'] in {'radio_probe', 'bluetooth_probe'} else ():
        if type(value.get(field)) is int and 0 <= value[field] <= 999:
            result[field] = value[field]
    return result


def _output(value: Any) -> dict[str, Any]:
    value = value if isinstance(value, dict) else {}
    records = value.get('records') if isinstance(value.get('records'), list) else []
    return {'records': [clean for item in records[-MAX_OUTPUT_RECORDS:]
                        if (clean := _record(item)) is not None],
            'bytes_seen': _integer(value.get('bytes_seen'), 2**31 - 1),
            'omitted_lines': _integer(value.get('omitted_lines'), 2**31 - 1),
            'truncated': value.get('truncated') is True}


def _project_output(data: bytes) -> dict[str, Any]:
    """Extract facts rather than relabeling arbitrary guest prose as trusted."""
    data = data if isinstance(data, bytes) else b''
    bounded = data[-MAX_OUTPUT_BYTES:]
    if len(data) > MAX_OUTPUT_BYTES:
        bounded = bounded.partition(b'\n')[2]
    lines = bounded.decode('utf-8', errors='replace').splitlines()
    rows, omitted = [], 0
    signatures = (
        ('no space left', 'storage_full'), ('not enough space', 'storage_full'),
        ('certificate verification failed', 'tls_verification_failed'),
        ('ssl certificate', 'tls_verification_failed'),
        ('bad signature', 'package_signature_failed'),
        ('signature check failed', 'package_signature_failed'),
        ('failed to resolve', 'dns_resolution_failed'),
        ('could not resolve', 'dns_resolution_failed'),
        ('name resolution', 'dns_resolution_failed'),
        ('bad address', 'dns_resolution_failed'),
        ('network is unreachable', 'network_unreachable'),
        ('no route to host', 'network_unreachable'),
        ('connection refused', 'connection_refused'),
        ('connection timed out', 'connection_timeout'),
        ('permission denied (publickey', 'ssh_authentication_failed'),
        ('host key verification failed', 'ssh_host_key_failed'),
        ('remote host identification has changed', 'ssh_host_key_failed'),
        ('connection closed', 'ssh_connection_closed'),
        ('permission denied', 'permission_denied'),
        ('operation not permitted', 'permission_denied'),
    )
    for line in lines[-256:]:
        row = None
        match = re.fullmatch(r'HX_RADIO_(SETUP|DETAIL) (wifi|bluetooth)=([a-z_]+)', line)
        if match:
            row = _record({'code': 'radio_' + match[1].lower(),
                           'kind': match[2], 'result': match[3]})
        match = re.fullmatch(r'HX_BT_HELPER ([a-z_]+)', line)
        if match:
            row = _record({'code': 'helper_result', 'result': match[1]})
        if re.fullmatch(r'HX_RADIO_V1 wifi=\d{1,3} wifi_interfaces=\d{1,3} iw=[01] bluetooth=\d{1,3} vhci=[01] btvirt=[01] btvirt_running=[01]', line):
            row = {'code': 'radio_probe', **{key: int(number) for key, number in re.findall(r'(\w+)=(\d+)', line)}}
        if re.fullmatch(r'HX_BT_H4_V1 controllers=\d{1,3} installed=[01] helper=[01] attach=[012] cli=[01]', line):
            row = {'code': 'bluetooth_probe', **{key: int(number) for key, number in re.findall(r'(\w+)=(\d+)', line)}}
        # These package-manager structures preserve the package/dependency that
        # failed without exporting an arbitrary package post-install message.
        match = re.fullmatch(r'The pinned OpenWrt feed does not provide required package: (' + _TOKEN + r')', line)
        if match:
            row = {'code': 'package_unknown', 'package': match[1]}
        match = re.fullmatch(r'OpenWrt package verification failed: (' + _TOKEN + r'(?:, ' + _TOKEN + r')*)', line)
        if match:
            rows.extend({'code': 'package_verification_failed', 'package': name}
                        for name in match[1].split(', ')[:MAX_OUTPUT_RECORDS])
            continue
        if line.startswith('OpenWrt package installation failed: '):
            row = {'code': 'package_install_failed'}
        match = re.search(r'cannot find dependency (' + _TOKEN + r') for (' + _TOKEN + r')(?:\s|[,.]|$)', line)
        if match:
            row = {'code': 'package_dependency_missing', 'dependency': match[1], 'package': match[2]}
        match = re.search(r"(?:Cannot install package|Unknown package|No such package) ['\"]?(" + _TOKEN + r")[ '\".]*$", line)
        if match:
            row = {'code': 'package_install_failed' if 'Cannot install' in line else 'package_unknown', 'package': match[1]}
        if re.search(r'\bFailed to download the package list\b', line):
            row = {'code': 'feed_download_failed'}
        elif re.search(r'\bFailed to download\b', line):
            # opkg's next word can be "the" (a feed list) or a URL. Neither
            # is a package identity. Require the explicit package form before
            # attaching a name; retain a fixed failure fact otherwise.
            row = {'code': 'package_download_failed'}
            match = re.search(r'\bFailed to download package [\'\"]?(' + _TOKEN + r')[ \'\".]*$', line)
            if match:
                row['package'] = match[1]
        match = re.search(r"(?:module|Module) ['\"]?(" + _TOKEN + r")[ '\"]+(?:not found|is missing)", line)
        if match:
            row = {'code': 'module_missing', 'module': match[1]}
        if row is None:
            lower = line.lower()
            if 'kernel' in lower and any(part in lower for part in ('incompatible', 'mismatch', 'cannot find dependency', 'cannot satisfy')):
                row = {'code': 'package_kernel_mismatch'}
            else:
                for token, code in signatures:
                    if token in lower:
                        row = {'code': code}
                        break
        if row is not None:
            rows.append(row)
        elif line.strip():
            omitted += 1
    return _output({'records': rows, 'bytes_seen': len(data),
                    'omitted_lines': omitted + max(0, len(lines) - 256),
                    'truncated': len(data) > MAX_OUTPUT_BYTES or len(rows) > MAX_OUTPUT_RECORDS})


def validate_radio_setup_receipt(value: Any) -> dict[str, Any] | None:
    """Rebuild fixed fields; never trust saved guest text or extra JSON keys."""
    from . import vm_logs
    if (not isinstance(value, dict) or value.get('event') != 'radio_setup_command'
            or not isinstance(value.get('script'), str) or value['script'] not in _LABELS
            or not isinstance(value.get('script_sha256'), str)
            or not _HEX.fullmatch(value['script_sha256'])):
        return None
    phase = value.get('phase', 'guest_script')
    if (phase not in ('guest_script', 'host_package_setup')
            or (phase == 'host_package_setup' and value['script'] not in {'wifi_setup', 'bluetooth_packages'})):
        return None
    host_packages = phase == 'host_package_setup'
    result = {'schema_version': 1, 'event': 'radio_setup_command',
              'source': 'verified_radio_package_setup' if host_packages else 'fixed_guest_radio_setup',
              'phase': phase,
              'command': 'opkg install <verified-local-packages>' if host_packages else
                  value.get('command') if value.get('command') in ('/bin/ash -s', 'sh -s') else '/bin/ash -s',
              'transport': 'host_verified_packages' if host_packages else 'ssh_stdin',
              'script': value['script'],
              'script_sha256': value['script_sha256'],
              'script_bytes': _integer(value.get('script_bytes'), 16 * 1024 * 1024),
              'stdout': _output(value.get('stdout')), 'stderr': _output(value.get('stderr')),
              'diagnostic': validate_technical_evidence(value.get('diagnostic'))}
    timestamp = vm_logs._timestamp(value.get('timestamp'))
    if timestamp:
        result['timestamp'] = timestamp
    code = value.get('returncode')
    if type(code) is int and -255 <= code <= 255:
        result['returncode'] = code
    timeout = value.get('timeout_seconds')
    if type(timeout) in (int, float) and math.isfinite(timeout) and 0 <= timeout <= 86400:
        result['timeout_seconds'] = timeout
    return result


def record_radio_setup_evidence(runtime: Path, script: str, *, stdout: bytes = b'',
        stderr: bytes = b'', returncode: int | None = None,
        error: BaseException | None = None, timeout_seconds: float = 0,
        command: str = '/bin/ash -s', phase: str = 'guest_script') -> bool:
    """Record a known setup attempt; evidence failure never changes VM state."""
    from . import vm_logs
    from .test_target_logs import _open_private_runtime
    parent = descriptor = None
    try:
        import fcntl
        if not isinstance(script, str):
            return False
        encoded = script.encode('utf-8')
        digest = hashlib.sha256(encoded).hexdigest()
        label = _script_identities().get((len(encoded), digest))
        if label is None:
            return False
        if (phase not in ('guest_script', 'host_package_setup')
                or (phase == 'host_package_setup' and label not in {'wifi_setup', 'bluetooth_packages'})):
            return False
        if label == 'radio_probe' and error is None and returncode == 0:
            # UI polling must not evict the setup failure that explains why a
            # running guest has no controller. Probe failures remain useful.
            return True
        error_output = _project_output(stderr)
        if phase == 'host_package_setup' and type(error) is RuntimeError and error.args and isinstance(error.args[0], str):
            # The host installer raises fixed RuntimeError messages. Project
            # their reviewed structures without invoking arbitrary __str__ or
            # exporting the exception message itself.
            host_error = _project_output(error.args[0].encode('utf-8', errors='replace'))
            error_output = _output({'records': error_output['records'] + host_error['records'],
                'bytes_seen': error_output['bytes_seen'] + host_error['bytes_seen'],
                'omitted_lines': error_output['omitted_lines'] + host_error['omitted_lines'],
                'truncated': error_output['truncated'] or host_error['truncated']})
        receipt = validate_radio_setup_receipt({
            'event': 'radio_setup_command', 'script': label,
            'command': command, 'phase': phase,
            'script_bytes': len(encoded), 'script_sha256': digest,
            'timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'stdout': _project_output(stdout), 'stderr': error_output,
            'returncode': returncode, 'timeout_seconds': timeout_seconds,
            'diagnostic': technical_error_evidence(error) if error is not None else {},
        })
        parent = _open_private_runtime(runtime)
        descriptor = os.open(RADIO_SETUP_FILENAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
            | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0), 0o600, dir_fd=parent)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            return False
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fchmod(descriptor, 0o600)
        prior = os.pread(descriptor, vm_logs.PER_FILE_TAIL_BYTES,
                         max(0, info.st_size - vm_logs.PER_FILE_TAIL_BYTES))
        rows = []
        for line in vm_logs._complete_lines(prior, info.st_size > vm_logs.PER_FILE_TAIL_BYTES):
            try:
                valid = validate_radio_setup_receipt(json.loads(line))
            except (ValueError, RecursionError):
                valid = None
            if valid is not None:
                rows.append(valid)
        rows.append(receipt)
        encoded_rows = [(json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')
                        for row in rows[-MAX_RADIO_RECEIPTS:]]
        while sum(map(len, encoded_rows)) > vm_logs.PER_FILE_TAIL_BYTES:
            encoded_rows.pop(0)
        payload = b''.join(encoded_rows)
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        while payload:
            count = os.write(descriptor, payload)
            if not count:
                return False
            payload = payload[count:]
        return True
    except (OSError, ValueError, ImportError, RuntimeError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def radio_setup_tail(data: bytes, truncated: bool, deadline: float) -> tuple[bytes, dict[str, Any]]:
    """Validate only our JSON receipts, never a raw guest-output log."""
    from . import vm_logs
    lines = vm_logs._complete_lines(data, truncated)
    rows, invalid = [], 0
    for line in lines[-MAX_RADIO_RECEIPTS:]:
        if time.monotonic() >= deadline:
            break
        try:
            row = validate_radio_setup_receipt(json.loads(line))
        except (ValueError, RecursionError):
            row = None
        if row is not None:
            rows.append(row)
        else:
            invalid += 1
    payload = b''.join((json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii') for row in rows)
    count = sum(len(row[stream]['records']) for row in rows for stream in ('stdout', 'stderr'))
    return payload, {'line_count': len(lines), 'signals_count': count,
        'signals_exported': count, 'signals_limited': truncated or len(lines) > MAX_RADIO_RECEIPTS
            or len(rows) + invalid < min(len(lines), MAX_RADIO_RECEIPTS)
            or any(row[stream]['truncated'] for row in rows for stream in ('stdout', 'stderr')),
        'technical_records_exported': len(rows), 'technical_lines_exported': count,
        'omitted_lines': invalid + sum(row[stream]['omitted_lines'] for row in rows for stream in ('stdout', 'stderr')),
        'content_omitted': True, 'control_plane_included': False,
        'control_plane_truncated': False, 'evidence_codes': []}
