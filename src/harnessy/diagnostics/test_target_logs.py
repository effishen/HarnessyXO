"""Read-only, bounded boot evidence for managed external/test targets.

Only registered target roots and fixed runtime filenames are examined. Collection
never queries SQLite, starts a guest, invokes SSH, or follows a runtime symlink.
"""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid
from typing import Any

from . import vm_logs
from .vm_logs import (_fixed_technical_evidence as technical_error_evidence,
                      _fixed_validated_technical_evidence as validate_technical_evidence)
from .radio_setup import RADIO_SETUP_FILENAME, MAX_RADIO_RECEIPTS, radio_setup_tail

MAX_TARGETS = 16
MAX_REGISTRY_TARGETS = 64
QEMU_LOG_FILENAMES = ('qemu.stderr.log', 'qemu.control-plane.log', 'serial.log', RADIO_SETUP_FILENAME)
MAX_QEMU_RECEIPTS = 8
MAX_TARGET_FILES = MAX_TARGETS * max(len(QEMU_LOG_FILENAMES), len(vm_logs.VM_LOG_FILENAMES))
MAX_DISCOVERY_BYTES = 1024 * 1024
MAX_EXPORT_BYTES = 2 * 1024 * 1024
COLLECTION_SECONDS = 5.0
TARGET_ENUMS = {
    'target_backend': frozenset({'qemu', 'lima'}),
    'target_action': frozenset({'start', 'stop', 'create', 'delete', 'snapshot', 'restore', 'shell', 'web', 'desktop', 'connection_test', 'status', 'radios'}),
    'target_radio_kind': frozenset({'wifi', 'bluetooth'}),
    'target_radio_backend': frozenset({'mac80211_hwsim', 'bluez_btvirt_vhci', 'bluez_h4', 'bluez_h4_uart'}),
    'target_radio_observation': frozenset({'setup', 'probe'}),
    'target_radio_status': frozenset({'disabled', 'active', 'unavailable', 'error', 'unverified'}),
    'target_radio_reason': frozenset({'not_requested', 'verified', 'not_detected', 'probe_failed', 'setup_failed',
        'package_install_failed', 'feed_update_failed', 'stock_feeds_unavailable', 'module_load_failed',
        'iw_missing', 'insufficient_radios', 'btvirt_missing', 'vhci_missing', 'service_conflict',
        'service_start_failed', 'insufficient_controllers', 'interfaces_missing', 'interface_create_failed', 'helper_unavailable', 'helper_integrity_failed', 'helper_install_failed', 'cli_missing', 'controller_attach_failed', 'crypto_unavailable'}),
    'target_radio_detail': frozenset({'none', 'unknown', 'dns_resolution_failed', 'tls_verification_failed',
        'network_unreachable', 'connection_failed', 'kernel_abi_mismatch', 'signature_failed', 'disk_full',
        'package_unavailable', 'operation_timeout', 'ssh_command_failed', 'interface_create_failed',
        'network_permission_denied'}),
    'target_stage': frozenset({'prerequisites', 'download', 'prepare_disk', 'launch', 'launch_reconcile', 'launch_recovered', 'wait_ssh', 'probe_shell', 'radio_setup', 'bluetooth_packages', 'bluetooth_emulator', 'bluetooth_attach', 'bluetooth_verify', 'connection_test', 'web_transport', 'vnc_transport', 'ready', 'stopped', 'failed', 'cancelled', 'snapshot', 'restore', 'delete'}),
    'target_outcome': frozenset({'running', 'completed', 'failed', 'cancelled', 'timeout'}),
    'target_interface': frozenset({'web', 'vnc'}),
    'target_view_failure_code': frozenset({'compressed_response_rejected', 'response_size_limit', 'request_size_limit',
                                          'web_transport_unavailable', 'vnc_transport_unavailable', 'web_http_error'}),
    'target_failure_code': frozenset({'none', 'no_failure', 'unknown', 'host_command_failed', 'prerequisite_missing', 'host_dependency_missing', 'image_download_failed', 'disk_prepare_failed', 'launch_failed', 'ssh_unavailable', 'ssh_authentication_failed', 'ssh_host_key_failed', 'shell_hostname_unavailable', 'shell_command_missing', 'shell_probe_failed', 'readiness_probe_failed', 'shell_probe_timeout', 'boot_timeout', 'guest_exited', 'controller_timeout', 'controller_failed', 'cancelled', 'emulation_setup_failed', 'radio_setup_failed', 'snapshot_failed', 'target_state_unknown', 'monitor_unavailable', 'log_capture_failed'}),
}
_REGISTRY: OrderedDict[tuple[str, str], None] = OrderedDict()
_LOCK = threading.Lock()
_ID = re.compile(r'^[0-9a-f]{32}$')
_HEX = re.compile(r'^[0-9a-f]{64}$')
_LIMITS = {'targets': MAX_TARGETS, 'files': MAX_TARGET_FILES,
           'qemu_handoff_receipts': MAX_QEMU_RECEIPTS,
           'radio_setup_receipts': MAX_RADIO_RECEIPTS,
           'tail_bytes_per_file': vm_logs.PER_FILE_TAIL_BYTES,
           'read_bytes_total': MAX_EXPORT_BYTES, 'export_bytes_total': MAX_EXPORT_BYTES,
           'discovery_bytes_total': MAX_DISCOVERY_BYTES, 'collection_seconds': COLLECTION_SECONDS}


def _safe_enum(value: Any, choices: set[str], default: str) -> str:
    return value if isinstance(value, str) and value in choices else default


def _open_private_runtime(runtime: Path) -> int:
    runtime = Path(runtime).absolute()
    # macOS /tmp is a trusted OS alias. Resolve that fixed base alone; all
    # target-controlled descendants still use descriptor-relative no-follow.
    if runtime.parts[:2] == ('/', 'tmp'):
        runtime = Path('/tmp').resolve().joinpath(*runtime.parts[2:])
    if not vm_logs._allowed_path(runtime) or os.open not in os.supports_dir_fd or not hasattr(os, 'O_NOFOLLOW'):
        raise ValueError('Private QEMU runtime capture is unavailable.')
    parent = None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_CLOEXEC', 0)
        parent = os.open(runtime.anchor, flags)
        for part in runtime.parts[1:]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent); parent = child
        info = os.fstat(parent)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError('Private QEMU runtime capture is unsafe.')
        result, parent = parent, None
        return result
    finally:
        if parent is not None:
            os.close(parent)


def open_qemu_control_plane_capture(runtime: Path):
    """Keep daemon stdout/stderr readable without waiting for inherited FD EOF.

    Guest serial is explicitly redirected elsewhere by qemu_argv. Raw host
    control-plane output stays in this private local file; all diagnostics
    retain fixed facts from a bounded tail. Earlier facts enter bounded receipts
    before replacing the current capture for a new launch attempt.
    """
    parent = _open_private_runtime(runtime)
    descriptor = old = None
    name = '.qemu-control-plane-' + uuid.uuid4().hex
    try:
        try:
            old = os.open('qemu.control-plane.log', os.O_RDONLY | os.O_NOFOLLOW
                          | getattr(os, 'O_NONBLOCK', 0), dir_fd=parent)
        except FileNotFoundError:
            pass
        if old is not None:
            info = os.fstat(old)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
                raise ValueError('Previous QEMU control-plane capture is unsafe.')
            data = os.pread(old, vm_logs.PER_FILE_TAIL_BYTES, max(0, info.st_size - vm_logs.PER_FILE_TAIL_BYTES))
            if data and not record_qemu_launcher_evidence(runtime, data, capture_context='previous_controller_tail'):
                raise ValueError('Previous QEMU control-plane evidence could not be preserved.')
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                             | getattr(os, 'O_CLOEXEC', 0), 0o600, dir_fd=parent)
        os.replace(name, 'qemu.control-plane.log', src_dir_fd=parent, dst_dir_fd=parent)
        capture = os.fdopen(descriptor, 'w+b')
        descriptor = None
        return capture
    finally:
        if old is not None:
            os.close(old)
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(name, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def _qemu_receipt(value: Any) -> dict[str, Any] | None:
    """Validate only our bounded launcher receipts, never guest console JSON."""
    if not isinstance(value, dict) or value.get('event') != 'qemu_launcher':
        return None
    diagnostic = value.get('diagnostic')
    if (not isinstance(diagnostic, dict) or not isinstance(diagnostic.get('source'), str)
            or diagnostic['source'] not in {'qemu', 'exception'}):
        return None
    result = {'schema_version': 1, 'event': 'qemu_launcher',
              'stage': _safe_enum(value.get('stage'), set(TARGET_ENUMS['target_stage']), 'launch'),
              'outcome': _safe_enum(value.get('outcome'),
                  {'completed', 'recovered', 'failed', 'timeout', 'cancelled', 'unknown'}, 'unknown'),
              'capture_context': _safe_enum(value.get('capture_context'),
                  {'launch_handoff', 'previous_controller_tail'}, 'launch_handoff'),
              'diagnostic': validate_technical_evidence(
                  diagnostic, trusted_source='qemu' if diagnostic.get('source') == 'qemu' else None)}
    timestamp = vm_logs._timestamp(value.get('timestamp'))
    if timestamp:
        result['timestamp'] = timestamp
    operation_id = value.get('operation_id')
    if isinstance(operation_id, str) and _ID.fullmatch(operation_id):
        result['operation_id'] = operation_id
    returncode = value.get('returncode')
    if isinstance(returncode, int) and not isinstance(returncode, bool) and -255 <= returncode <= 255:
        result['returncode'] = returncode
    timeout = value.get('timeout_seconds')
    if isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and 0 <= timeout <= 86400 and math.isfinite(timeout):
        result['timeout_seconds'] = timeout
    return result


def record_qemu_launcher_evidence(runtime: Path, data: bytes, *, stage: str = 'launch',
                                  operation_id: str = '', returncode: int | None = None,
                                  timeout_seconds: float = 0, error: BaseException | None = None,
                                  capture_context: str = 'launch_handoff') -> bool:
    """Persist fixed launcher facts, keeping bounded earlier attempts.

    The input is QEMU's host stdout/stderr capture. Guest serial is a different
    file and must never be passed here. A failed evidence write cannot change
    launch, UUID verification, cancellation, or guest readiness behavior.
    """
    try:
        import fcntl
    except ImportError:
        return False
    outcome = ('unknown' if capture_context == 'previous_controller_tail' else
               'cancelled' if type(error).__name__ == 'CancelledError' else
               'timeout' if isinstance(error, TimeoutError) or getattr(error, 'failure_code', '') == 'controller_timeout' else
               'failed' if error is not None or returncode else
               'recovered' if stage == 'launch_recovered' else 'completed')
    receipt = _qemu_receipt({
        'event': 'qemu_launcher', 'stage': stage, 'outcome': outcome,
        'timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
        'operation_id': operation_id, 'returncode': returncode, 'timeout_seconds': timeout_seconds,
        'capture_context': capture_context,
        'diagnostic': technical_error_evidence(data, source='qemu') if data or error is None else technical_error_evidence(error),
    })
    parent = descriptor = None
    try:
        parent = _open_private_runtime(runtime)
        descriptor = os.open('qemu.stderr.log', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
                             | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0),
                             0o600, dir_fd=parent)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            return False
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fchmod(descriptor, 0o600)
        size = os.fstat(descriptor).st_size
        prior = os.pread(descriptor, vm_logs.PER_FILE_TAIL_BYTES,
                         max(0, size - vm_logs.PER_FILE_TAIL_BYTES))
        rows = []
        for line in vm_logs._complete_lines(prior, size > vm_logs.PER_FILE_TAIL_BYTES):
            try:
                valid = _qemu_receipt(json.loads(line))
            except (ValueError, RecursionError):
                valid = None
            if valid:
                rows.append(valid)
        rows.append(receipt)
        encoded = [(json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')
                   for row in rows[-MAX_QEMU_RECEIPTS:]]
        while sum(map(len, encoded)) > vm_logs.PER_FILE_TAIL_BYTES:
            encoded.pop(0)
        payload = b''.join(encoded)
        os.lseek(descriptor, 0, os.SEEK_SET)
        os.ftruncate(descriptor, 0)
        while payload:
            written = os.write(descriptor, payload)
            if not written:
                return False
            payload = payload[written:]
        return True
    except (OSError, ValueError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)


def _qemu_technical_tail(data: bytes, truncated: bool, deadline: float) -> tuple[bytes, dict[str, Any]]:
    lines = vm_logs._complete_lines(data, truncated)
    rows, omitted = [], 0
    for line in lines[-MAX_QEMU_RECEIPTS:]:
        if time.monotonic() >= deadline:
            break
        try:
            value = _qemu_receipt(json.loads(line))
        except (ValueError, RecursionError):
            value = None
        if value:
            rows.append(value)
        else:
            omitted += 1
    payload = b''.join((json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii') for row in rows)
    technical_lines = sum(len(row['diagnostic'].get('diagnostic_text', '').splitlines()) for row in rows)
    codes = {signal['code'] for row in rows for signal in vm_logs._signals(
        row['diagnostic'].get('diagnostic_text', ''), 'hostagent', 0)}
    return payload, {'line_count': len(lines), 'signals_count': len(codes), 'signals_exported': len(codes),
                     'signals_limited': truncated or len(lines) > MAX_QEMU_RECEIPTS or len(rows) + omitted < min(len(lines), MAX_QEMU_RECEIPTS),
                     'technical_records_exported': len(rows), 'technical_lines_exported': technical_lines,
                     'omitted_lines': omitted, 'content_omitted': any(row['diagnostic']['omitted_content'] for row in rows),
                     'evidence_codes': sorted(codes)}


def _qemu_control_plane_tail(data: bytes, truncated: bool, deadline: float) -> tuple[bytes, dict[str, Any]]:
    lines = vm_logs._complete_lines(data, truncated)
    signals, measurements = vm_logs._technical_tail(data, 'serial', truncated, deadline)
    diagnostic = technical_error_evidence('\n'.join(lines), source='qemu')
    text = diagnostic.get('diagnostic_text', '')
    fixed = vm_logs._has_fixed_technical_facts(diagnostic)
    if fixed:
        signals += (json.dumps({'relative_tail_line': len(lines), 'diagnostic': diagnostic},
                              ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')
    measurements.update(technical_records_exported=int(fixed),
                        technical_lines_exported=len(text.splitlines()),
                        omitted_lines=max(0, len(lines) - len(text.splitlines())),
                        content_omitted=diagnostic['omitted_content'])
    measurements['signals_limited'] |= diagnostic['truncated']
    return signals, measurements


def classify_target_failure(value: Any) -> str:
    """Return a fixed technical code; never preserve any exception/output text."""
    if isinstance(value, (TimeoutError,)):
        return 'controller_timeout'
    text = str(value).lower()[-4000:]
    for signatures, code in (
        (('hostname: not found',), 'shell_command_missing'),
        (('permission denied (publickey', 'authentication failed'), 'ssh_authentication_failed'),
        (('host key verification failed', 'remote host identification has changed'), 'ssh_host_key_failed'),
        (('connection refused', 'no route to host', 'connection timed out'), 'ssh_unavailable'),
        (('monitor is unavailable', 'vm monitor closed'), 'monitor_unavailable'),
        (('install the missing packages', 'lima is required', 'missing host dependency'), 'host_dependency_missing'),
        (('shell did not become ready',), 'boot_timeout'),
    ):
        if any(signature in text for signature in signatures):
            return code
    return 'controller_failed'


def _target_root(value: Any) -> Path | None:
    root = vm_logs._workspace_path(value)
    if root is None or not _ID.fullmatch(root.name) or root.parent.name != 'test_targets' or root.parent.parent.name != '.harnessy':
        return None
    return root if vm_logs._allowed_path(root) else None


def register_test_target_runtime(target_root: Path, backend: str) -> None:
    """Register a controller-owned root; no file or database is read here."""
    root = _target_root(target_root)
    if root is None or not isinstance(backend, str) or backend not in TARGET_ENUMS['target_backend']:
        return
    item = (str(root), backend)
    with _LOCK:
        fresh = item not in _REGISTRY
        _REGISTRY.pop(item, None)
        _REGISTRY[item] = None
        while len(_REGISTRY) > MAX_REGISTRY_TARGETS:
            _REGISTRY.popitem(last=False)
    from .runtime_locations import remember_runtime_location
    remember_runtime_location('target', root, backend)
    if fresh:
        from .logging import log_event
        log_event('runtime', 'test_target_runtime_registered', target_runtime_root=str(root),
                  target_backend=backend, target_id=root.name)


def _discover(latest: Path, deadline: float) -> tuple[list[tuple[Path, str]], dict[str, Any]]:
    with _LOCK:
        registered = list(reversed(_REGISTRY))
    from .runtime_locations import load_runtime_locations
    index = load_runtime_locations(latest.parent)
    indexed = [(str(root), row['backend']) for row in index['locations']
               if row['kind'] == 'target' and (root := _target_root(row['path'])) is not None]
    candidates = list(registered) + indexed
    coverage = {'registered_targets': len(registered), 'app_bytes_read': 0,
                'records_examined': 0, 'discovery_limited': False, 'unsafe_app_sources': 0,
                'runtime_index_status': index['status'], 'runtime_index_roots': len(indexed)}
    previous, limited = vm_logs._previous_sessions(latest)
    coverage['discovery_limited'] = limited
    sources = [latest / (name + suffix) for name in ('targets.log', 'runtime.log') for suffix in ('', '.1', '.2', '.3')]
    sources += [folder / name for folder in previous for name in ('targets.log', 'runtime.log')]
    for source in sources:
        remaining = MAX_DISCOVERY_BYTES - coverage['app_bytes_read']
        if remaining <= 0 or time.monotonic() >= deadline or coverage['records_examined'] >= vm_logs.MAX_DISCOVERY_RECORDS:
            coverage['discovery_limited'] = True
            break
        read = vm_logs._read_tail(source, min(vm_logs.PER_FILE_TAIL_BYTES, remaining))
        coverage['app_bytes_read'] += len(read['data'])
        coverage['unsafe_app_sources'] += int(read['status'] == 'unsafe')
        coverage['discovery_limited'] |= read['truncated']
        for line in reversed(vm_logs._complete_lines(read['data'], read['truncated'])):
            coverage['records_examined'] += 1
            if coverage['records_examined'] >= vm_logs.MAX_DISCOVERY_RECORDS or time.monotonic() >= deadline:
                coverage['discovery_limited'] = True
                break
            payload = vm_logs._event_payload(line)
            if not payload or payload.get('event') != 'test_target_runtime_registered':
                continue
            root = _target_root(payload.get('target_runtime_root'))
            backend = payload.get('target_backend')
            if root is not None and isinstance(backend, str) and backend in TARGET_ENUMS['target_backend']:
                candidates.append((str(root), backend))
    distinct = list(dict.fromkeys(candidates))
    coverage['candidate_targets'] = len(distinct)
    coverage['targets_limited'] = len(distinct) > MAX_TARGETS
    return [(Path(root), backend) for root, backend in distinct[:MAX_TARGETS]], coverage


def _runtime(root: Path, backend: str) -> Path:
    if backend == 'lima':
        return root / 'lima' / 'test'
    # /tmp itself is a trusted OS alias on macOS. Resolve just that fixed base,
    # never an untrusted target component; all subsequent opens refuse links.
    base = Path('/tmp').resolve() / f'hy-openwrt-{os.getuid()}'
    identity = hashlib.sha256(str(root).encode()).hexdigest()[:24]
    return base / identity


def collect_test_target_diagnostics(latest: Path, include_content: bool = False) -> dict[str, Any]:
    deadline = time.monotonic() + COLLECTION_SECONDS
    targets, discovery = _discover(Path(latest).absolute(), deadline)
    report: dict[str, Any] = {'schema_version': 1, 'status': 'collected' if targets else 'no_targets',
                              'mode': 'signals_only',
                              'discovery': discovery, 'targets': []}
    members: dict[str, bytes] = {}
    read_total = export_total = 0
    for root, backend in targets:
        identity = hashlib.sha256(str(root).encode()).hexdigest()
        target = {'target_id': root.name, 'runtime_id': identity, 'target_backend': backend, 'sources': []}
        filenames = QEMU_LOG_FILENAMES if backend == 'qemu' else vm_logs.VM_LOG_FILENAMES
        for filename in filenames:
            remaining = min(MAX_EXPORT_BYTES - read_total, MAX_EXPORT_BYTES - export_total)
            result = ({'status': 'limited', 'data': b'', 'bytes_available': 0, 'truncated': True}
                      if time.monotonic() >= deadline or remaining <= 0 else
                      vm_logs._read_tail(_runtime(root, backend) / filename,
                                         min(vm_logs.PER_FILE_TAIL_BYTES, remaining)))
            data = result.pop('data')
            read_total += len(data)
            source = {'filename': filename, **result, 'bytes_read': len(data), 'bytes_exported': 0,
                      'signals_count': 0, 'signals_exported': 0, 'signals_limited': False, 'evidence_codes': []}
            if result['status'] == 'included':
                kind = 'radio_setup' if filename == RADIO_SETUP_FILENAME else 'qemu' if filename.startswith('qemu.') else 'hostagent' if filename.startswith('ha.') else 'serial'
                projected, measurements = (radio_setup_tail(data, result['truncated'], deadline) if filename == RADIO_SETUP_FILENAME else
                                           _qemu_technical_tail(data, result['truncated'], deadline) if filename == 'qemu.stderr.log' else
                                           _qemu_control_plane_tail(data, result['truncated'], deadline) if kind == 'qemu' else
                                           vm_logs._technical_tail(data, kind, result['truncated'], deadline))
                source.update(measurements)
                cap = MAX_EXPORT_BYTES - export_total
                if len(projected) > cap:
                    projected = projected[-cap:].partition(b'\n')[2] if cap else b''
                    source['signals_limited'] = True
                name = f'target-logs/{identity}/{backend}.{filename}.technical.jsonl'
                members[name] = projected
                source.update(archive_member=name, bytes_exported=len(projected), signals_exported=projected.count(b'\n'))
                export_total += len(projected)
            target['sources'].append(source)
        report['targets'].append(target)
    return {'report': validate_test_target_report(report), 'members': members}


def validate_test_target_report(report: Any) -> dict[str, Any]:
    """Rebuild persisted metadata using fixed enums and bounded measurements."""
    report = report if isinstance(report, dict) else {}
    mode = 'signals_only'
    status = _safe_enum(report.get('status'), {'collected', 'no_targets', 'unavailable'}, 'unavailable')
    safe = {'schema_version': 1, 'status': status, 'mode': mode, 'limits': dict(_LIMITS), 'targets': [], 'discovery': {}}
    if status == 'unavailable':
        safe['reason'] = 'collector_failed'
    discovery = report.get('discovery') if isinstance(report.get('discovery'), dict) else {}
    for key, cap in {'registered_targets': MAX_REGISTRY_TARGETS, 'candidate_targets': vm_logs.MAX_DISCOVERY_RECORDS,
                     'app_bytes_read': MAX_DISCOVERY_BYTES, 'records_examined': vm_logs.MAX_DISCOVERY_RECORDS + 1,
                     'unsafe_app_sources': 8 + 2 * vm_logs.MAX_PREVIOUS_SESSIONS, 'runtime_index_roots': MAX_REGISTRY_TARGETS}.items():
        safe['discovery'][key] = vm_logs._integer(discovery.get(key), cap)
    from .runtime_locations import INDEX_STATUSES
    safe['discovery']['runtime_index_status'] = _safe_enum(discovery.get('runtime_index_status'), INDEX_STATUSES, 'missing')
    for key in ('targets_limited', 'discovery_limited'):
        safe['discovery'][key] = discovery.get(key) is True
    targets = report.get('targets') if isinstance(report.get('targets'), list) else []
    seen = set()
    for target in targets[:MAX_TARGETS] if status != 'unavailable' else []:
        if not isinstance(target, dict):
            continue
        identity, identifier, backend = target.get('runtime_id'), target.get('target_id'), target.get('target_backend')
        if not isinstance(identity, str) or not _HEX.fullmatch(identity) or not isinstance(identifier, str) or not _ID.fullmatch(identifier) or not isinstance(backend, str) or backend not in TARGET_ENUMS['target_backend'] or (identity, backend) in seen:
            continue
        seen.add((identity, backend))
        clean = {'runtime_id': identity, 'target_id': identifier, 'target_backend': backend, 'sources': []}
        filenames = QEMU_LOG_FILENAMES if backend == 'qemu' else vm_logs.VM_LOG_FILENAMES
        sources = target.get('sources') if isinstance(target.get('sources'), list) else []
        used = set()
        for source in sources[:len(filenames)]:
            if not isinstance(source, dict) or source.get('filename') not in filenames or source['filename'] in used:
                continue
            filename = source['filename']; used.add(filename)
            state = _safe_enum(source.get('status'), {'included', 'missing', 'unsafe', 'unreadable', 'limited'}, 'unreadable')
            kind = 'radio_setup' if filename == RADIO_SETUP_FILENAME else 'qemu' if filename.startswith('qemu.') else 'hostagent' if filename.startswith('ha.') else 'serial'
            item = {'filename': filename, 'status': state, 'kind': kind,
                    'projection': 'fixed_guest_radio_setup' if kind == 'radio_setup' else 'fixed_boot_signals' if kind == 'serial' else 'fixed_control_plane_facts'}
            for key, cap in {'bytes_available': 2**63 - 1, 'bytes_read': vm_logs.PER_FILE_TAIL_BYTES,
                             'bytes_exported': MAX_EXPORT_BYTES, 'raw_bytes_exported': vm_logs.PER_FILE_TAIL_BYTES,
                             'line_count': vm_logs.PER_FILE_TAIL_BYTES, 'signals_count': vm_logs.MAX_PARSE_LINES * len(vm_logs.EVIDENCE_CODES),
                             'signals_exported': vm_logs.MAX_SIGNAL_ROWS,
                             'technical_records_exported': vm_logs.MAX_SIGNAL_ROWS,
                             'technical_lines_exported': vm_logs.MAX_PARSE_LINES,
                             'omitted_lines': vm_logs.MAX_PARSE_LINES}.items():
                item[key] = vm_logs._integer(source.get(key), cap)
            item['truncated'] = source.get('truncated') is True
            item['signals_limited'] = source.get('signals_limited') is True
            item['content_omitted'] = kind == 'serial' or source.get('content_omitted') is True
            item['coverage'] = ('guest_content_excluded' if kind == 'serial' else
                                'partial_technical_evidence' if item['omitted_lines'] or item['signals_limited'] or item['truncated'] else
                                'technical_evidence' if item['technical_lines_exported'] else
                                'no_controller_output' if item['technical_records_exported'] or not item['bytes_read'] else
                                'technical_evidence_unavailable') if state == 'included' else state
            mtime = source.get('mtime_unix')
            if isinstance(mtime, (int, float)) and not isinstance(mtime, bool) and 0 <= mtime <= 1e12 and math.isfinite(mtime):
                item['mtime_unix'] = mtime
            item['evidence_codes'] = vm_logs._codes(source.get('evidence_codes'))
            expected = f'target-logs/{identity}/{backend}.{filename}.technical.jsonl'
            if state == 'included' and source.get('archive_member') == expected:
                item['archive_member'] = expected
            item['raw_bytes_exported'] = 0
            item['content_omitted'] = True
            clean['sources'].append(item)
        safe['targets'].append(clean)
    sources = [source for target in safe['targets'] for source in target['sources']]
    safe['coverage'] = {'scope': 'registered_and_logged_targets_only',
                        'undiscovered_targets': 'unknown', 'runtime_state': 'not_probed',
                        'guest_serial_policy': 'fixed_signals_only',
                        'controller_output_policy': 'fixed_operational_facts',
                        'qemu_control_plane_scope': 'current_controller_output_and_bounded_handoff_history',
                        'radio_setup_scope': 'fixed_script_results_and_typed_transport_errors',
                        'absence_of_evidence_proves_no_failure': False}
    safe['summary'] = {'targets': len(safe['targets']), 'sources': len(sources),
                       'technical_records_exported': sum(source['technical_records_exported'] for source in sources),
                       'technical_lines_exported': sum(source['technical_lines_exported'] for source in sources),
                       'content_omitted_sources': sum(source['content_omitted'] for source in sources),
                       'bytes_read': sum(source['bytes_read'] for source in sources),
                       'bytes_exported': sum(source['bytes_exported'] for source in sources)}
    for state in ('included', 'missing', 'unsafe', 'unreadable', 'limited'):
        safe['summary'][state] = sum(source['status'] == state for source in sources)
    return safe
