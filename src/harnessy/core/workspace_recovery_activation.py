"""Explicit, crash-recoverable activation of a verified lossless REINDEX copy.

This module never opens SQLite. Validation runs in owned isolated workers;
original database generations are moved intact to a private same-volume backup.
An unfinished manifest blocks normal workspace access until rollback succeeds.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
import uuid

_PENDING = 'workspace-recovery-pending.json'
_GENERATION = 'workspace-generation'
_STORE = 'workspace-recovery-activations'
_DB_NAMES = ('workspace.db', 'workspace.db-wal', 'workspace.db-shm', 'workspace.db-journal')
_SOURCE_NAMES = (*_DB_NAMES, 'workspace.json')
_SHA = frozenset('0123456789abcdef')


class WorkspaceRecoveryActivationError(RuntimeError):
    def __init__(self, code: str, message: str = '') -> None:
        allowed = {'candidate_stale', 'not_lossless', 'maintenance_busy', 'source_changed',
                   'transaction_incomplete', 'filesystem_error', 'validation_failed', 'timed_out'}
        self.code = code if code in allowed else 'filesystem_error'
        super().__init__(message or {
            'candidate_stale': 'This repaired copy is no longer current. Run recovery again.',
            'not_lossless': 'Only a verified lossless index repair can replace the workspace database.',
            'maintenance_busy': 'Close active workspace work before using the repaired database.',
            'source_changed': 'The original workspace changed. Recovery preserved its files; run recovery again.',
            'transaction_incomplete': 'Database replacement is incomplete. Keep this workspace closed until rollback finishes.',
            'filesystem_error': 'Database replacement could not finish safely. Check the workspace disk and retry.',
            'validation_failed': 'The repaired database did not pass its final isolated validation.',
            'timed_out': 'Database replacement timed out before it could finish safely.',
        }[self.code])


def _event(event: str, root: Path, started: float, stage: str, status: str, **fields) -> None:
    try:
        from ..diagnostics import log_event
        identity = ('harnessyxo-sqlite-v1\0' + str(root / '.harnessy' / 'workspace.db')).encode('utf-8', errors='surrogatepass')
        log_event('harnessy', event, db_id=hashlib.sha256(identity).hexdigest(),
                  recovery_stage=stage, recovery_status=status,
                  elapsed_seconds=round(max(0., time.monotonic() - started), 3), **fields)
    except Exception:
        pass


def _tick(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise WorkspaceRecoveryActivationError('timed_out')


def _exists(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def _signature(info) -> list[int]:
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _describe(path: Path, deadline: float) -> dict | None:
    _tick(deadline)
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise WorkspaceRecoveryActivationError('filesystem_error')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    fd = os.open(path, flags)
    try:
        if _signature(os.fstat(fd)) != _signature(before):
            raise WorkspaceRecoveryActivationError('source_changed')
        digest = hashlib.sha256()
        while True:
            _tick(deadline)
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        if _signature(os.fstat(fd)) != _signature(before) or _signature(path.lstat()) != _signature(before):
            raise WorkspaceRecoveryActivationError('source_changed')
    finally:
        os.close(fd)
    return {'bytes': before.st_size, 'sha256': digest.hexdigest(), 'signature': _signature(before)}


def _same_bytes(actual: dict | None, expected: dict | None) -> bool:
    return actual is None and expected is None or bool(actual and expected
        and actual.get('bytes') == expected.get('bytes') and actual.get('sha256') == expected.get('sha256'))


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _private_dir(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700)
        _fsync_dir(path.parent)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or (os.name != 'nt' and
            (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077)):
        raise WorkspaceRecoveryActivationError('filesystem_error')


def _atomic_bytes(path: Path, payload: bytes) -> None:
    if _exists(path) and (path.is_symlink() or not path.is_file()):
        raise WorkspaceRecoveryActivationError('filesystem_error')
    fd, temporary = tempfile.mkstemp(prefix='.recovery-state-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_dir(path.parent)
    finally:
        try:
            Path(temporary).unlink()
        except FileNotFoundError:
            pass


def _write_manifest(path: Path, manifest: dict) -> None:
    _atomic_bytes(path, (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode())


def _read_manifest(path: Path) -> dict:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024 or info.st_nlink != 1:
        raise WorkspaceRecoveryActivationError('transaction_incomplete')
    if os.name != 'nt' and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise WorkspaceRecoveryActivationError('transaction_incomplete')
    try:
        value = json.loads(path.read_text('utf-8'))
    except (ValueError, OSError) as exc:
        raise WorkspaceRecoveryActivationError('transaction_incomplete') from exc
    if not isinstance(value, dict) or value.get('schema_version') != 1:
        raise WorkspaceRecoveryActivationError('transaction_incomplete')
    try:
        transaction = str(uuid.UUID(value['transaction_id']))
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise WorkspaceRecoveryActivationError('transaction_incomplete') from exc
    if transaction != value.get('transaction_id') or value.get('state') not in {
            'prepared', 'moving_originals', 'installing_candidate', 'writing_generation',
            'activated', 'rolling_back', 'rolled_back'}:
        raise WorkspaceRecoveryActivationError('transaction_incomplete')
    originals = value.get('originals')
    if not isinstance(originals, dict) or set(originals) != set(_SOURCE_NAMES):
        raise WorkspaceRecoveryActivationError('transaction_incomplete')
    for descriptor in [*originals.values(), value.get('candidate')]:
        if descriptor is None:
            continue
        if (not isinstance(descriptor, dict) or type(descriptor.get('bytes')) is not int or descriptor['bytes'] < 0
                or not isinstance(descriptor.get('sha256'), str) or len(descriptor['sha256']) != 64
                or not set(descriptor['sha256']) <= _SHA):
            raise WorkspaceRecoveryActivationError('transaction_incomplete')
    if not originals.get('workspace.db') or not originals.get('workspace.json') or not value.get('candidate'):
        raise WorkspaceRecoveryActivationError('transaction_incomplete')
    old_generation = value.get('old_generation')
    if old_generation is not None and (not isinstance(old_generation, str) or len(old_generation) > 128):
        raise WorkspaceRecoveryActivationError('transaction_incomplete')
    return value


def _paths(root: str | Path) -> tuple[Path, Path]:
    root = Path(root).expanduser().resolve(strict=True)
    meta = root / '.harnessy'
    info = meta.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise WorkspaceRecoveryActivationError('filesystem_error')
    return root, meta


def _stage_path(meta: Path, transaction: str, *, create: bool = True) -> Path:
    parent = meta / _STORE
    if not parent.exists():
        if not create:
            raise WorkspaceRecoveryActivationError('transaction_incomplete')
        _private_dir(parent, create=True)
    else:
        _private_dir(parent)
    stage = parent / transaction
    if not stage.exists():
        if not create:
            raise WorkspaceRecoveryActivationError('transaction_incomplete')
        _private_dir(stage, create=True)
    else:
        _private_dir(stage)
    return stage


def _archive_pending(meta: Path, stage: Path, manifest: dict) -> None:
    _write_manifest(stage / 'activation.json', manifest)
    (meta / _PENDING).unlink()
    _fsync_dir(meta)


def _rollback(meta: Path, stage: Path, manifest: dict, deadline: float) -> dict:
    """Restore the original file set without invoking SQLite or deleting bytes."""
    pending = meta / _PENDING
    if not _same_bytes(_describe(meta / 'workspace.json', deadline), manifest['originals']['workspace.json']):
        raise WorkspaceRecoveryActivationError('transaction_incomplete')
    manifest['state'] = 'rolling_back'
    _write_manifest(pending, manifest)
    for name in _DB_NAMES:
        _tick(deadline)
        original = manifest['originals'][name]
        source, backup = meta / name, stage / name
        current, saved = _describe(source, deadline), _describe(backup, deadline)
        if original is not None and _same_bytes(current, original):
            if saved is not None and not _same_bytes(saved, original):
                raise WorkspaceRecoveryActivationError('transaction_incomplete')
            continue
        if original is not None and not _same_bytes(saved, original):
            raise WorkspaceRecoveryActivationError('transaction_incomplete')
        if current is not None:
            quarantine = stage / ('uncommitted-' + name)
            prior = _describe(quarantine, deadline)
            if prior is not None:
                # A prior rollback interruption can only leave identical bytes
                # at both names if an external actor intervened. Preserve both.
                raise WorkspaceRecoveryActivationError('transaction_incomplete')
            os.replace(source, quarantine)
            _fsync_dir(stage)
            _fsync_dir(meta)
        if original is not None:
            os.replace(backup, source)
            _fsync_dir(stage)
            _fsync_dir(meta)
    if not _same_bytes(_describe(meta / 'workspace.json', deadline), manifest['originals']['workspace.json']):
        raise WorkspaceRecoveryActivationError('transaction_incomplete')
    old = manifest.get('old_generation')
    generation_path = meta / _GENERATION
    if old is None:
        if generation_path.exists():
            quarantine = stage / 'uncommitted-generation'
            if quarantine.exists():
                raise WorkspaceRecoveryActivationError('transaction_incomplete')
            os.replace(generation_path, quarantine)
            _fsync_dir(stage)
            _fsync_dir(meta)
    else:
        _atomic_bytes(generation_path, old.encode())
    for name in _SOURCE_NAMES:
        if not _same_bytes(_describe(meta / name, deadline), manifest['originals'][name]):
            raise WorkspaceRecoveryActivationError('transaction_incomplete')
    manifest['state'] = 'rolled_back'
    _archive_pending(meta, stage, manifest)
    from .workspace_health import forget_workspace_admission
    forget_workspace_admission(meta.parent)
    return {'status': 'rolled_back', 'receipt_id': manifest['transaction_id']}


def resume_workspace_recovery_activation(root: str | Path, *, timeout: float = 60.) -> dict | None:
    """Roll back an interrupted activation before any normal database opening."""
    started = time.monotonic()
    root, meta = _paths(root)
    if not _exists(meta / _PENDING):
        return None
    from .workspace_access import workspace_maintenance_access
    try:
        with ExitStack() as stack:
            from ..environment.activity import reserve_environment_change
            release = reserve_environment_change(root, 'workspace database recovery')
            stack.callback(release)
            stack.enter_context(workspace_maintenance_access(root, allow_pending=True))
            if not _exists(meta / _PENDING):
                return None
            manifest = _read_manifest(meta / _PENDING)
            stage = _stage_path(meta, manifest['transaction_id'], create=False)
            result = _rollback(meta, stage, manifest, started + min(900., max(1., float(timeout))))
        _event('workspace_database_recovery_completed', root, started, 'rollback', 'rolled_back')
        return result
    except Exception as exc:
        _event('workspace_database_recovery_failed', root, started, 'rollback', 'incomplete_transaction',
               recovery_failure_code='transaction_incomplete')
        if isinstance(exc, WorkspaceRecoveryActivationError):
            raise
        raise WorkspaceRecoveryActivationError('transaction_incomplete') from exc


def _candidate_facts(validation: dict) -> dict:
    keys = ('schema_fingerprints', 'table_row_digests', 'row_counts', 'column_counts')
    if not isinstance(validation, dict) or any(not isinstance(validation.get(key), dict) for key in keys):
        raise WorkspaceRecoveryActivationError('validation_failed')
    if not validation['table_row_digests'] or set(validation['table_row_digests']) != set(validation['row_counts']):
        raise WorkspaceRecoveryActivationError('validation_failed')
    return {key: validation[key] for key in keys}


def _require_healthy_candidate(validation: dict) -> None:
    if (not isinstance(validation, dict) or validation.get('integrity_ok') is not True
            or validation.get('foreign_key_violations') != 0
            or validation.get('application_invariants_ok') is not True
            or validation.get('row_count_failures') or validation.get('row_digest_failures')
            or validation.get('foreign_key_check_failed')
            or validation.get('unknown_table_count', 0) != 0):
        raise WorkspaceRecoveryActivationError('validation_failed')


def _copy_candidate(source: Path, destination: Path, descriptor: dict, deadline: float) -> None:
    if shutil.disk_usage(destination.parent).free < descriptor['bytes'] + 1024 * 1024:
        raise WorkspaceRecoveryActivationError('filesystem_error')
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as target, source.open('rb') as original:
            while True:
                _tick(deadline)
                chunk = original.read(1024 * 1024)
                if not chunk:
                    break
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        _fsync_dir(destination.parent)
    except BaseException:
        # This copy is not an original. Keep it for inspection if copying fails.
        raise
    if not _same_bytes(_describe(destination, deadline), descriptor):
        raise WorkspaceRecoveryActivationError('candidate_stale')


def activate_repaired_workspace(root: str | Path, receipt: dict, *, maintenance_held: bool = False,
                                timeout: float = 900.) -> dict:
    """Use only an engine-verified lossless index repair, after explicit UI choice.

    The caller persists the workspace's queue hold first. Internal callers may
    set maintenance_held only while already owning the exclusive access lease
    and activity reservation. Ordinary calls obtain both here.
    """
    started = time.monotonic()
    deadline = started + min(1800., max(1., float(timeout)))
    root, meta = _paths(root)
    try:
        identifier = str(uuid.UUID(receipt['receipt_id']))
        if receipt['receipt_id'] not in {identifier, identifier.replace('-', '')}:
            raise ValueError()
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise WorkspaceRecoveryActivationError('candidate_stale') from exc
    _event('workspace_database_recovery_started', root, started, 'activate', 'started',
           recovery_receipt_id=identifier)
    pending_written = False
    manifest = None
    with ExitStack() as stack:
        if maintenance_held:
            from .workspace_access import owns_workspace_maintenance
            if not owns_workspace_maintenance(root):
                raise WorkspaceRecoveryActivationError('maintenance_busy')
        if not maintenance_held:
            try:
                from ..environment.activity import reserve_environment_change
                release = reserve_environment_change(root, 'workspace database recovery')
                stack.callback(release)
                from .workspace_access import workspace_maintenance_access
                stack.enter_context(workspace_maintenance_access(root, allow_pending=True))
            except Exception as exc:
                raise WorkspaceRecoveryActivationError('maintenance_busy') from exc
        stage = _stage_path(meta, identifier)
        completed = stage / 'activation.json'
        if _exists(meta / _PENDING):
            raise WorkspaceRecoveryActivationError('transaction_incomplete')
        if completed.exists():
            prior = _read_manifest(completed)
            if prior['state'] == 'activated':
                return {'status': 'activated', 'receipt_id': identifier, 'already_activated': True}
            raise WorkspaceRecoveryActivationError('candidate_stale')
        try:
            from .workspace_recovery import validate_candidate_report, inspect_activation_candidate
            fresh = validate_candidate_report(root, identifier, receipt['state_root'])
            report = fresh['report']
            candidate = report.get('candidate', {})
            if (candidate.get('kind') != 'reindex' or candidate.get('eligible_for_activation') is not True
                    or candidate.get('standalone_database') is not True):
                raise WorkspaceRecoveryActivationError('not_lossless')
            expected_facts = _candidate_facts(report['reindex']['validation'])
            _require_healthy_candidate(report['reindex']['validation'])
            if _candidate_facts(report['inspection']) != expected_facts:
                raise WorkspaceRecoveryActivationError('not_lossless')
            original = {name: _describe(meta / name, deadline) for name in _SOURCE_NAMES}
            if not original['workspace.db'] or not original['workspace.json']:
                raise WorkspaceRecoveryActivationError('source_changed')
            candidate_path = Path(fresh['candidate_path'])
            descriptor = _describe(candidate_path, deadline)
            if not descriptor or descriptor['sha256'] != candidate.get('sha256'):
                raise WorkspaceRecoveryActivationError('candidate_stale')
            for suffix in ('-wal', '-shm', '-journal'):
                if Path(str(candidate_path) + suffix).exists():
                    raise WorkspaceRecoveryActivationError('not_lossless')
            temporary = meta / ('.workspace-repaired-' + identifier + '.tmp')
            if temporary.exists():
                # A pre-transaction failure may leave a bounded copy. Preserve
                # it under a fresh private name before retrying this receipt.
                os.replace(temporary, stage / ('unused-candidate-' + uuid.uuid4().hex + '.db'))
                _fsync_dir(stage)
                _fsync_dir(meta)
            _copy_candidate(candidate_path, temporary, descriptor, deadline)
            validation = inspect_activation_candidate(temporary, timeout=max(.1, deadline-time.monotonic()))
            _require_healthy_candidate(validation)
            if _candidate_facts(validation) != expected_facts:
                raise WorkspaceRecoveryActivationError('validation_failed')
            if any(Path(str(temporary) + suffix).exists() for suffix in ('-wal', '-shm', '-journal')):
                raise WorkspaceRecoveryActivationError('not_lossless')
            if not _same_bytes(_describe(temporary, deadline), descriptor):
                raise WorkspaceRecoveryActivationError('validation_failed')
            # Revalidate the engine receipt after copy/SQLite validation and
            # require the exact original inode generation and every sidecar.
            validate_candidate_report(root, identifier, receipt['state_root'])
            if any(_describe(meta / name, deadline) != original[name] for name in _SOURCE_NAMES):
                raise WorkspaceRecoveryActivationError('source_changed')
            generation_path = meta / _GENERATION
            old_generation = generation_path.read_text('utf-8') if generation_path.exists() else None
            if old_generation is not None and len(old_generation) > 128:
                raise WorkspaceRecoveryActivationError('filesystem_error')
            manifest = {'schema_version': 1, 'transaction_id': identifier, 'state': 'prepared',
                        'workspace_id': fresh['workspace_id'], 'originals': original,
                        'candidate': descriptor, 'old_generation': old_generation,
                        'new_generation': str(uuid.uuid4())}
            _write_manifest(meta / _PENDING, manifest)
            pending_written = True
            manifest['state'] = 'moving_originals'
            _write_manifest(meta / _PENDING, manifest)
            for name in _DB_NAMES:
                _tick(deadline)
                if _describe(meta / name, deadline) != original[name]:
                    raise WorkspaceRecoveryActivationError('source_changed')
                if original[name] is not None:
                    if (stage / name).exists():
                        raise WorkspaceRecoveryActivationError('transaction_incomplete')
                    os.replace(meta / name, stage / name)
                    _fsync_dir(stage)
                    _fsync_dir(meta)
            manifest['state'] = 'installing_candidate'
            _write_manifest(meta / _PENDING, manifest)
            if any((meta / name).exists() for name in _DB_NAMES):
                raise WorkspaceRecoveryActivationError('source_changed')
            os.replace(temporary, meta / 'workspace.db')
            _fsync_dir(meta)
            manifest['state'] = 'writing_generation'
            _write_manifest(meta / _PENDING, manifest)
            _atomic_bytes(generation_path, manifest['new_generation'].encode())
            if (not _same_bytes(_describe(meta / 'workspace.db', deadline), descriptor)
                    or any((meta / name).exists() for name in _DB_NAMES[1:])
                    or not _same_bytes(_describe(meta / 'workspace.json', deadline), original['workspace.json'])
                    or any(not _same_bytes(_describe(stage / name, deadline), original[name])
                           for name in _DB_NAMES)):
                raise WorkspaceRecoveryActivationError('source_changed')
            manifest['state'] = 'activated'
            from .workspace_health import remember_verified_workspace_database, workspace_database_fingerprint
            remember_verified_workspace_database(root, workspace_database_fingerprint(root))
            _archive_pending(meta, stage, manifest)
            _event('workspace_database_recovery_completed', root, started, 'activate', 'activated',
                   candidate_bytes=descriptor['bytes'], recovery_receipt_id=identifier)
            return {'status': 'activated', 'receipt_id': identifier, 'already_activated': False,
                    'backup_path': str(stage)}
        except Exception as exc:
            if pending_written and manifest is not None:
                try:
                    _rollback(meta, stage, manifest, time.monotonic() + 60.)
                except Exception as rollback_error:
                    _event('workspace_database_recovery_failed', root, started, 'activate', 'incomplete_transaction',
                           recovery_failure_code='transaction_incomplete')
                    raise WorkspaceRecoveryActivationError('transaction_incomplete') from rollback_error
            code = exc.code if isinstance(exc, WorkspaceRecoveryActivationError) else {
                'source_changed': 'source_changed', 'candidate_unavailable': 'candidate_stale',
                'report_invalid': 'candidate_stale', 'database_open': 'maintenance_busy',
                'stop_check_unknown': 'maintenance_busy', 'worker_timeout': 'timed_out',
            }.get(getattr(exc, 'code', ''), 'filesystem_error')
            _event('workspace_database_recovery_failed', root, started, 'activate', 'activation_blocked',
                   recovery_failure_code=code)
            if isinstance(exc, WorkspaceRecoveryActivationError):
                raise
            raise WorkspaceRecoveryActivationError(code) from exc
