"""Read-only, bounded boot evidence for managed external/test targets.

Only registered target roots and fixed runtime filenames are examined. Collection
never queries SQLite, starts a guest, invokes SSH, or follows a runtime symlink.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
from typing import Any

from . import vm_logs

MAX_TARGETS = 16
MAX_REGISTRY_TARGETS = 64
MAX_TARGET_FILES = MAX_TARGETS * len(vm_logs.VM_LOG_FILENAMES)
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
    'target_failure_code': frozenset({'none', 'no_failure', 'unknown', 'host_command_failed', 'prerequisite_missing', 'host_dependency_missing', 'image_download_failed', 'disk_prepare_failed', 'launch_failed', 'ssh_unavailable', 'ssh_authentication_failed', 'ssh_host_key_failed', 'shell_hostname_unavailable', 'shell_command_missing', 'shell_probe_failed', 'readiness_probe_failed', 'shell_probe_timeout', 'boot_timeout', 'guest_exited', 'controller_timeout', 'controller_failed', 'cancelled', 'emulation_setup_failed', 'radio_setup_failed', 'snapshot_failed', 'target_state_unknown', 'monitor_unavailable'}),
}
_REGISTRY: OrderedDict[tuple[str, str], None] = OrderedDict()
_LOCK = threading.Lock()
_ID = re.compile(r'^[0-9a-f]{32}$')
_HEX = re.compile(r'^[0-9a-f]{64}$')
_LIMITS = {'targets': MAX_TARGETS, 'files': MAX_TARGET_FILES,
           'tail_bytes_per_file': vm_logs.PER_FILE_TAIL_BYTES,
           'read_bytes_total': MAX_EXPORT_BYTES, 'export_bytes_total': MAX_EXPORT_BYTES,
           'discovery_bytes_total': MAX_DISCOVERY_BYTES, 'collection_seconds': COLLECTION_SECONDS}


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
    if fresh:
        from .logging import log_event
        log_event('runtime', 'test_target_runtime_registered', target_runtime_root=str(root),
                  target_backend=backend, target_id=root.name)


def _discover(latest: Path, deadline: float) -> tuple[list[tuple[Path, str]], dict[str, Any]]:
    with _LOCK:
        registered = list(reversed(_REGISTRY))
    candidates = list(registered)
    coverage = {'registered_targets': len(registered), 'app_bytes_read': 0,
                'records_examined': 0, 'discovery_limited': False, 'unsafe_app_sources': 0}
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
                              'mode': 'raw_bounded_tails' if include_content else 'signals_only',
                              'discovery': discovery, 'targets': []}
    members: dict[str, bytes] = {}
    read_total = export_total = 0
    for root, backend in targets:
        identity = hashlib.sha256(str(root).encode()).hexdigest()
        target = {'target_id': root.name, 'runtime_id': identity, 'target_backend': backend, 'sources': []}
        filenames = ('serial.log',) if backend == 'qemu' else vm_logs.VM_LOG_FILENAMES
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
                kind = 'hostagent' if filename.startswith('ha.') else 'serial'
                projected, measurements = vm_logs._technical_tail(data, kind, result['truncated'], deadline)
                source.update(measurements)
                cap = MAX_EXPORT_BYTES - export_total
                if len(projected) > cap:
                    projected = projected[-cap:].partition(b'\n')[2] if cap else b''
                    source['signals_limited'] = True
                name = f'target-logs/{identity}/{backend}.{filename}.technical.jsonl'
                members[name] = projected
                source.update(archive_member=name, bytes_exported=len(projected), signals_exported=projected.count(b'\n'))
                export_total += len(projected)
                if include_content:
                    raw = data[-(MAX_EXPORT_BYTES - export_total):] if export_total < MAX_EXPORT_BYTES else b''
                    name = f'target-logs/{identity}/{backend}.{filename}.raw.log'
                    members[name] = raw
                    source.update(raw_archive_member=name, raw_bytes_exported=len(raw),
                                  bytes_exported=source['bytes_exported'] + len(raw))
                    source['truncated'] |= len(raw) < len(data)
                    export_total += len(raw)
            target['sources'].append(source)
        report['targets'].append(target)
    return {'report': validate_test_target_report(report), 'members': members}


def validate_test_target_report(report: Any) -> dict[str, Any]:
    """Rebuild persisted metadata using fixed enums and bounded measurements."""
    report = report if isinstance(report, dict) else {}
    mode = vm_logs._enum(report.get('mode'), {'signals_only', 'raw_bounded_tails'}, 'signals_only')
    status = vm_logs._enum(report.get('status'), {'collected', 'no_targets', 'unavailable'}, 'unavailable')
    safe = {'schema_version': 1, 'status': status, 'mode': mode, 'limits': dict(_LIMITS), 'targets': [], 'discovery': {}}
    if status == 'unavailable':
        safe['reason'] = 'collector_failed'
    discovery = report.get('discovery') if isinstance(report.get('discovery'), dict) else {}
    for key, cap in {'registered_targets': MAX_REGISTRY_TARGETS, 'candidate_targets': vm_logs.MAX_DISCOVERY_RECORDS,
                     'app_bytes_read': MAX_DISCOVERY_BYTES, 'records_examined': vm_logs.MAX_DISCOVERY_RECORDS + 1,
                     'unsafe_app_sources': 8 + 2 * vm_logs.MAX_PREVIOUS_SESSIONS}.items():
        safe['discovery'][key] = vm_logs._integer(discovery.get(key), cap)
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
        filenames = ('serial.log',) if backend == 'qemu' else vm_logs.VM_LOG_FILENAMES
        sources = target.get('sources') if isinstance(target.get('sources'), list) else []
        used = set()
        for source in sources[:len(filenames)]:
            if not isinstance(source, dict) or source.get('filename') not in filenames or source['filename'] in used:
                continue
            filename = source['filename']; used.add(filename)
            state = vm_logs._enum(source.get('status'), {'included', 'missing', 'unsafe', 'unreadable', 'limited'}, 'unreadable')
            item = {'filename': filename, 'status': state}
            for key, cap in {'bytes_available': 2**63 - 1, 'bytes_read': vm_logs.PER_FILE_TAIL_BYTES,
                             'bytes_exported': MAX_EXPORT_BYTES, 'raw_bytes_exported': vm_logs.PER_FILE_TAIL_BYTES,
                             'line_count': vm_logs.PER_FILE_TAIL_BYTES, 'signals_count': vm_logs.MAX_PARSE_LINES * len(vm_logs.EVIDENCE_CODES),
                             'signals_exported': vm_logs.MAX_SIGNAL_ROWS}.items():
                item[key] = vm_logs._integer(source.get(key), cap)
            item['truncated'] = source.get('truncated') is True
            item['signals_limited'] = source.get('signals_limited') is True
            item['evidence_codes'] = vm_logs._codes(source.get('evidence_codes'))
            expected = f'target-logs/{identity}/{backend}.{filename}.technical.jsonl'
            if state == 'included' and source.get('archive_member') == expected:
                item['archive_member'] = expected
            expected = f'target-logs/{identity}/{backend}.{filename}.raw.log'
            if state == 'included' and mode == 'raw_bounded_tails' and source.get('raw_archive_member') == expected:
                item['raw_archive_member'] = expected
            clean['sources'].append(item)
        safe['targets'].append(clean)
    sources = [source for target in safe['targets'] for source in target['sources']]
    safe['summary'] = {'targets': len(safe['targets']), 'sources': len(sources),
                       'bytes_read': sum(source['bytes_read'] for source in sources),
                       'bytes_exported': sum(source['bytes_exported'] for source in sources)}
    for state in ('included', 'missing', 'unsafe', 'unreadable', 'limited'):
        safe['summary'][state] = sum(source['status'] == state for source in sources)
    return safe
