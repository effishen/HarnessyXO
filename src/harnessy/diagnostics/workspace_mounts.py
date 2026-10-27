"""Bounded backing-mount observations; exporting never contacts a VM."""
from __future__ import annotations

import hashlib
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

FILENAME = 'workspace-mounts.json'
MAX_RECEIPTS = 8
MAX_RECEIPT_BYTES = 64 * 1024
_TRANSPORTS = frozenset({'9p', 'virtiofs', 'reverse-sshfs'})
_STATES = frozenset({'ready', 'unavailable', 'error'})
_PHASES = frozenset({'before_guard', 'after_guard', 'verification_failed'})
_ROLES = frozenset({'files', 'worktrees', 'references'})
_FILESYSTEMS = frozenset({'9p', 'virtiofs', 'fuse.sshfs', 'other', 'unknown'})
_ERRORS = frozenset({'', 'timeout', 'transport_unavailable', 'invalid_output',
                    'mount_missing', 'source_mismatch', 'permission_denied',
                    'guard_failed', 'probe_failed', 'unsupported'})
_ID = re.compile(r'^[0-9a-f]{32}$')
_WORKSPACE_ID = re.compile(r'^[0-9a-f]{64}$')
_PERSIST_LOCK = threading.Lock()


def project_workspace_mount_receipt(value: Any) -> dict[str, Any]:
    """Revalidate untrusted disk/probe data; retain only fixed typed fields."""
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1):
        raise ValueError('Invalid mount receipt schema.')
    environment_id, workspace_id = value.get('environment_id'), value.get('workspace_id')
    if (not isinstance(environment_id, str) or (environment_id and not _ID.fullmatch(environment_id))
            or not isinstance(workspace_id, str) or not _WORKSPACE_ID.fullmatch(workspace_id)):
        raise ValueError('Invalid mount receipt identity.')
    clean: dict[str, Any] = {'schema_version': 1, 'workspace_id': workspace_id,
                             'environment_id': environment_id}
    for name, allowed in (('transport', _TRANSPORTS), ('state', _STATES),
                          ('phase', _PHASES), ('probe_error', _ERRORS)):
        item = value.get(name, '' if name == 'probe_error' else None)
        if not isinstance(item, str) or item not in allowed:
            raise ValueError('Invalid mount receipt category.')
        clean[name] = item
    if clean['state'] == 'ready' and clean['probe_error']:
        raise ValueError('Contradictory mount readiness error.')
    captured_at = value.get('captured_at')
    if (type(captured_at) not in (int, float) or not 0 <= captured_at <= 1e12
            or not math.isfinite(captured_at)):
        raise ValueError('Invalid mount receipt timestamp.')
    clean['captured_at'] = captured_at
    supported = value.get('kernel_9p_supported')
    if supported is not None and type(supported) is not bool:
        raise ValueError('Invalid kernel support observation.')
    clean['kernel_9p_supported'] = supported
    references_required = value.get('references_required', True)
    if type(references_required) is not bool:
        raise ValueError('Invalid references mount requirement.')
    clean['references_required'] = references_required
    boot_id = value.get('boot_id')
    if boot_id is not None:
        if not isinstance(boot_id, str) or len(boot_id) != 36:
            raise ValueError('Invalid mount boot identity.')
        try:
            parsed = uuid.UUID(boot_id)
        except ValueError:
            raise ValueError('Invalid mount boot identity.') from None
        if str(parsed) != boot_id.lower():
            raise ValueError('Invalid mount boot identity.')
        clean['boot_id'] = str(parsed)
    rows = value.get('mounts')
    if not isinstance(rows, list) or len(rows) > len(_ROLES):
        raise ValueError('Invalid mount observations.')
    mounts = []
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Invalid mount observation.')
        role = row.get('role')
        filesystem = row.get('filesystem')
        if (not isinstance(role, str) or role not in _ROLES or role in seen
                or not isinstance(filesystem, str) or filesystem not in _FILESYSTEMS):
            raise ValueError('Invalid mount role or filesystem.')
        seen.add(role)
        mount: dict[str, Any] = {'role': role, 'filesystem': filesystem}
        for name in ('directory_exists', 'is_mount', 'read_only', 'source_verified'):
            item = row.get(name)
            if item is not None and type(item) is not bool:
                raise ValueError('Invalid mount boolean observation.')
            mount[name] = item
        mounts.append(mount)
    required = _ROLES if references_required else _ROLES - {'references'}
    if clean['state'] == 'ready' and (not required.issubset(seen) or any(
            row['role'] in required and (row['directory_exists'] is not True or row['is_mount'] is not True)
            for row in mounts)):
        raise ValueError('Contradictory mount readiness observation.')
    clean['mounts'] = mounts
    return clean


def _project_document(value: Any, workspace_id: str, environment_id: str) -> dict[str, Any]:
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1 or value.get('workspace_id') != workspace_id
            or value.get('environment_id') != environment_id
            or not isinstance(value.get('receipts'), list) or len(value['receipts']) > MAX_RECEIPTS):
        raise ValueError('Invalid mount receipt document.')
    rows = [project_workspace_mount_receipt(row) for row in value['receipts']]
    if any(row['workspace_id'] != workspace_id or row['environment_id'] != environment_id for row in rows):
        raise ValueError('Mismatched mount receipt identity.')
    return {'schema_version': 1, 'workspace_id': workspace_id,
            'environment_id': environment_id, 'receipts': rows}


def _open_state_directory(runtime: Path) -> int:
    """Pin existing ancestors and create only state, never a removed runtime."""
    from .vm_logs import _allowed_path
    if not _allowed_path(runtime) or os.open not in os.supports_dir_fd or not hasattr(os, 'O_NOFOLLOW'):
        raise ValueError('Safe mount receipt persistence unavailable.')
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_CLOEXEC', 0)
    parent = os.open(runtime.anchor, flags)
    try:
        for part in runtime.parts[1:]:
            child = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = child
        info = os.fstat(parent)
        # Registered roots may legitimately inherit group write from umask 0002.
        # Descriptor traversal pins their identity; only receipt state is private.
        if info.st_uid != os.getuid():
            raise ValueError('Unsafe mount receipt runtime.')
        try:
            os.mkdir('state', 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        child = os.open('state', flags, dir_fd=parent)
        info = os.fstat(child)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            os.close(child)
            raise ValueError('Unsafe mount receipt state directory.')
        return child
    finally:
        os.close(parent)


def record_workspace_mounts(workspace_root: Path | str, *, environment_id: str,
                            runtime_root: Path | str | None = None, transport: str,
                            state: str, phase: str, mounts: list[dict[str, Any]],
                            kernel_9p_supported: bool | None = None,
                            boot_id: str | None = None, probe_error: str = '',
                            references_required: bool = True) -> bool:
    """Atomically retain up to eight validated observations; never raise on IO."""
    from .vm_logs import _workspace_path, _runtime_root, _read_tail, register_workspace_runtime
    parent = lock = descriptor = None
    temporary = '.workspace-mounts-' + uuid.uuid4().hex
    acquired = False
    try:
        root = _workspace_path(workspace_root)
        if root is None:
            return False
        runtime = _runtime_root(root, environment_id, runtime_root)
        workspace_id = hashlib.sha256(str(root).encode()).hexdigest()
        receipt = project_workspace_mount_receipt({'schema_version': 1,
            'workspace_id': workspace_id, 'environment_id': environment_id,
            'captured_at': time.time(), 'transport': transport, 'state': state, 'phase': phase,
            'mounts': mounts, 'kernel_9p_supported': kernel_9p_supported,
            'boot_id': boot_id, 'probe_error': probe_error,
            'references_required': references_required})
        acquired = _PERSIST_LOCK.acquire(blocking=False)
        if not acquired:
            return False
        parent = _open_state_directory(runtime)
        import fcntl
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0)
        lock = os.open('.workspace-mounts.lock', flags, 0o600, dir_fd=parent)
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
        previous = _read_tail(runtime / 'state' / FILENAME, MAX_RECEIPT_BYTES)
        rows = []
        if previous['status'] == 'included' and not previous['truncated']:
            try:
                rows = _project_document(json.loads(previous['data']), workspace_id, environment_id)['receipts']
            except (ValueError, RecursionError, UnicodeError):
                pass  # A valid new observation can replace an invalid old receipt.
        document = {'schema_version': 1, 'workspace_id': workspace_id,
                    'environment_id': environment_id, 'receipts': [*rows, receipt][-MAX_RECEIPTS:]}
        payload = json.dumps(document, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
        if len(payload) > MAX_RECEIPT_BYTES:
            return False
        descriptor = os.open(temporary, flags | os.O_EXCL, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, 'wb') as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, FILENAME, src_dir_fd=parent, dst_dir_fd=parent)
        register_workspace_runtime(root, environment_id=environment_id, runtime_root=runtime)
        return True
    except (OSError, ValueError, TypeError, RecursionError, ImportError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            try:
                os.unlink(temporary, dir_fd=parent)
            except OSError:
                pass
            os.close(parent)
        if lock is not None:
            os.close(lock)
        if acquired:
            _PERSIST_LOCK.release()


def collect_workspace_mount_diagnostics(latest: Path) -> dict[str, Any]:
    """Read bounded saved observations only; missing and invalid remain explicit."""
    from .vm_logs import _discover_workspaces, _runtime_environments, _read_tail
    deadline = time.monotonic() + 3
    roots, discovery = _discover_workspaces(Path(latest).absolute(), deadline)
    output: dict[str, Any] = {'schema_version': 1, 'status': 'collected',
        'scope': 'persisted_runtime_observations', 'discovery': discovery,
        'captured_at': time.time(), 'limits': {'environments': 32, 'receipts_per_environment': MAX_RECEIPTS,
        'receipt_bytes': MAX_RECEIPT_BYTES, 'collection_seconds': 3}, 'environments': [], 'limited': False}
    for root, _origin in roots:
        if time.monotonic() >= deadline:
            output['limited'] = True
            break
        environments, truncated = _runtime_environments(root)
        output['limited'] = output['limited'] or truncated
        for environment_id, runtime in environments:
            if len(output['environments']) >= 32 or time.monotonic() >= deadline:
                output['limited'] = True
                break
            workspace_id = hashlib.sha256(str(root).encode()).hexdigest()
            row: dict[str, Any] = {'workspace_id': workspace_id, 'environment_id': environment_id, 'receipts': []}
            result = _read_tail(runtime / 'state' / FILENAME, MAX_RECEIPT_BYTES)
            row['receipt_status'] = result['status']
            if result['status'] == 'included':
                if result['truncated']:
                    row['receipt_status'] = 'limited'
                else:
                    try:
                        row.update(_project_document(json.loads(result['data']), workspace_id, environment_id))
                    except (ValueError, RecursionError, UnicodeError):
                        row['receipt_status'] = 'invalid'
            output['environments'].append(row)
    if not roots:
        output['status'] = 'no_workspaces'
    return output


def summary_lines(report: dict[str, Any]) -> str:
    lines = ['\nVM backing mounts: retained observations in VM_MOUNTS.json; no live guest probe during export.']
    rows = report.get('environments', [])
    for row in rows[:32] if isinstance(rows, list) else []:
        label = '  VM ' + (row.get('environment_id') or 'legacy')
        receipts = row.get('receipts', [])
        if row.get('receipt_status') != 'included' or not receipts:
            lines.append(label + ': mount receipt ' + str(row.get('receipt_status', 'unavailable')) + '.')
        else:
            sample = receipts[-1]
            lines.append(label + ': last observed ' + sample['state'] + ' (' + sample['phase'] + ', '
                         + sample['transport'] + '), epoch ' + str(sample['captured_at']) + '.')
    if not rows:
        lines.append('  No retained per-VM mount observations were discovered.')
    lines.append('  Retained observations do not verify current mount readiness or establish the cause of a failure.')
    return '\n'.join(lines) + '\n'
