"""Process-owned, copy-first workspace database recovery operations.

The app remains available. A workspace maintenance lease and lifecycle
reservation exclude work only in the selected workspace. Native SQLite runs in
bounded children against private copies; installation is an explicit operation
implemented separately by workspace_recovery_activation.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import threading
import time
import uuid

from . import recovery_worker as worker
from .workspace_access import workspace_maintenance_access
from .workspace_health import (
    remember_verified_workspace_database, workspace_database_fingerprint,
)
from ..environment.activity import reserve_environment_change

_ID = re.compile(r'[0-9a-f]{32}\Z')
_HASH = re.compile(r'[0-9a-f]{64}\Z')
_TIMEOUT = 900.0


def _root(root) -> Path:
    return Path(root).expanduser().resolve()


def _db_id(root: Path) -> str:
    value = str((root / '.harnessy' / 'workspace.db').resolve())
    return hashlib.sha256(('harnessyxo-sqlite-v1\0' + value).encode('utf-8', errors='surrogatepass')).hexdigest()


def _root_id(root: Path) -> str:
    return hashlib.sha256(str(root).encode('utf-8', errors='surrogatepass')).hexdigest()


def _write_json(path: Path, value) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.partial')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', closefd=False) as stream:
            stream.write(encoded + '\n')
            stream.flush()
            os.fsync(descriptor)
        os.replace(temporary, path)
    finally:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _private_directory(path: Path, *, create=False) -> Path:
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    entry = path.lstat()
    if (not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.getuid()
            or entry.st_mode & 0o077):
        raise worker.RecoveryError('unsafe_file', f'Recovery storage must be a private directory owned by your account: {path}')
    return path


def _operation_base(root: Path, state_root: Path, *, create=False) -> Path:
    top = state_root / 'workspace-recovery'
    if top == root or root in top.parents:
        raise worker.RecoveryError('unsafe_file', 'Recovery storage must be outside the selected workspace.')
    _private_directory(top, create=create)
    return _private_directory(top / _root_id(root), create=create)


def _read_json(path: Path, *, limit=2 * 1024 * 1024):
    value = path.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_uid != os.getuid()
            or value.st_mode & 0o077 or value.st_size > limit):
        raise worker.RecoveryError('report_invalid', 'Recovery metadata is unavailable or unsafe.')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        with os.fdopen(descriptor, 'r', encoding='utf-8', closefd=False) as stream:
            return json.load(stream)
    finally:
        os.close(descriptor)


def _source_snapshot(root: Path) -> tuple[dict, dict]:
    files = worker.original_files(root)
    return files, {name: worker.signature(path) for name, path in files.items()}


def _verify_sources(root: Path, files: dict, signatures: dict, preservation: dict) -> dict:
    current, current_signatures = _source_snapshot(root)
    stable = set(current) == set(files) and current_signatures == signatures
    hashes = {}
    for name, entry in preservation.items():
        try:
            current_hash = worker.digest(Path(entry['source']))
            hashes[name] = {'sha256_after': current_hash, 'unchanged': current_hash == entry['sha256']}
        except (OSError, worker.RecoveryError):
            hashes[name] = {'unchanged': False, 'verification_failed': True}
    stable = (stable and len(hashes) == len(files)
              and all(value.get('unchanged') is True for value in hashes.values()))
    # Recheck the complete generation after hashing, including newly created WAL.
    final, final_signatures = _source_snapshot(root)
    stable = stable and set(final) == set(files) and final_signatures == signatures
    return {'original_hash_verification': hashes, 'original_file_set_unchanged': set(final) == set(files),
            'original_generation_unchanged': bool(stable)}


def _canonical_app_root(app_root: Path) -> Path:
    for candidate in (app_root, Path(__file__).resolve().parents[3]):
        if any((candidate / suffix).is_file() for suffix in (
            'src/harnessy/core/workspace.py', 'harnessy/core/workspace.py',
        )):
            return candidate
    return app_root


def _diag(event: str, job: '_Job', **facts) -> None:
    try:
        from ..diagnostics import log_event
        log_event('harnessy', event, db_id=_db_id(job.root),
                  recovery_operation_id=job.id, recovery_stage=job.state['stage'],
                  recovery_status=job.state['status'], elapsed_seconds=max(0, time.time() - job.started),
                  **facts)
    except Exception:
        pass


def _worker_facts(result: dict) -> dict:
    keys = ('integrity_ok', 'integrity_error_count', 'integrity_categories', 'index_only',
            'application_invariants_ok', 'foreign_key_violations', 'unknown_table_count',
            'application_invariant_failures', 'integrity_errors_truncated',
            'foreign_key_errors_truncated', 'standalone_database')
    facts = {key: result[key] for key in keys if key in result and result[key] is not None}
    if type(result.get('returncode')) is int:
        facts['database_worker_returncode'] = result['returncode']
    if type(result.get('sqlite_errorcode')) is int:
        facts['sqlite_errorcode'] = result['sqlite_errorcode']
    if isinstance(result.get('sqlite_errorname'), str):
        facts['sqlite_errorname'] = result['sqlite_errorname']
    if result.get('signal') in {'SIGBUS', 'SIGSEGV', 'SIGABRT', 'SIGKILL', 'SIGTERM', 'other', 'none'}:
        facts['database_worker_signal'] = result['signal']
    if result.get('worker_status') == 'timed_out' or result.get('operation_status') == 'timed_out' or result.get('sqlite_errorcode') == 9:
        facts['recovery_failure_code'] = 'worker_timeout'
    elif result.get('worker_status') == 'protocol_error':
        facts['recovery_failure_code'] = 'worker_protocol'
    elif result.get('worker_status') == 'failed':
        facts['recovery_failure_code'] = 'worker_failed'
    return facts


@dataclass
class _Job:
    root: Path
    app_root: Path
    state_root: Path
    action: str
    id: str
    directory: Path
    state: dict
    started: float = field(default_factory=time.time)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    task: asyncio.Task | None = None
    report: dict = field(default_factory=dict)
    lock: threading.RLock = field(default_factory=threading.RLock)


class RecoveryOperations:
    def __init__(self):
        self._jobs: dict[str, _Job] = {}
        self._lock = threading.RLock()
        self._closing = False
        self._limit = asyncio.Semaphore(2)

    def _new(self, root, app_root, state_root, action: str, *, receipt_id=None) -> dict:
        if self._closing:
            raise RuntimeError('HarnessyXO is stopping. Recovery was not started.')
        root, app_root, state_root = _root(root), _root(app_root), _root(state_root)
        key = str(root)
        with self._lock:
            existing = self._jobs.get(key)
            if existing and existing.state.get('busy'):
                raise RuntimeError('A workspace database operation is already in progress.')
            base = _operation_base(root, state_root, create=True)
            job_id = uuid.uuid4().hex
            directory = _private_directory(base / job_id, create=True)
            now = time.time()
            state = {'job_id': job_id, 'action': action, 'busy': True, 'status': 'queued',
                     'stage': action if action in {'activate', 'rollback'} else 'backup',
                     'message': ('Preparing to restore the preserved original database.' if action == 'rollback' else
                                 ('Preparing to use the verified repaired database.' if action == 'activate' else 'Waiting to check the workspace database.')),
                     'error': '', 'started_unix_seconds': int(now), 'updated_unix_seconds': int(now),
                     'elapsed_seconds': 0.0, 'progress_bytes': 0, 'total_bytes': 0,
                     'report_path': str(directory / 'recovery-report.json'),
                     'backup_path': str(directory / 'original'), 'healthy': False,
                     'candidate_path': '', 'candidate_verified': False, 'candidate_receipt_id': '',
                     'candidate_counts': {'before': {}, 'after': {}}, 'partial_salvage': False,
                     'can_cancel': action not in {'activate', 'rollback'}}
            if receipt_id is not None:
                state['activation_receipt_id'] = str(receipt_id)
            job = _Job(root, app_root, state_root, action, job_id, directory, state)
            self._jobs[key] = job
            try:
                self._persist(job)
                job.task = asyncio.create_task(self._run(job), name='workspace-database-' + action)
            except BaseException:
                if existing is None:
                    self._jobs.pop(key, None)
                else:
                    self._jobs[key] = existing
                raise
        return self._with_pending(root, self._snapshot(job))

    def start_check(self, root, app_root, state_root) -> dict:
        return self._new(root, app_root, state_root, 'check')

    def start_repair(self, root, app_root, state_root) -> dict:
        return self._new(root, app_root, state_root, 'repair')

    def start_activation(self, root, receipt_id, app_root, state_root) -> dict:
        return self._new(root, app_root, state_root, 'activate', receipt_id=receipt_id)

    def start_rollback(self, root, app_root, state_root) -> dict:
        return self._new(root, app_root, state_root, 'rollback')

    def _persist(self, job: _Job) -> None:
        _write_json(job.directory / 'state.json', job.state)
        _write_json(job.directory.parent / 'latest.json', {'job_id': job.id})

    def _update(self, job: _Job, **changes) -> None:
        with job.lock:
            job.state.update(changes, updated_unix_seconds=int(time.time()),
                             elapsed_seconds=round(max(0, time.time() - job.started), 3))
            try:
                self._persist(job)
            except OSError:
                # UI state must still reach a terminal state after disk-full
                # errors. A missing report never creates an activatable receipt.
                job.state['persistence_error'] = True

    def _snapshot(self, job: _Job) -> dict:
        with job.lock:
            state = deepcopy(job.state)
        if state.get('busy'):
            state['elapsed_seconds'] = round(max(0, time.time() - job.started), 3)
        return state

    def snapshot(self, root, state_root=None) -> dict:
        root = _root(root)
        with self._lock:
            job = self._jobs.get(str(root))
        if job:
            return self._with_pending(root, self._snapshot(job))
        if state_root is None:
            return self._with_pending(root, {})
        try:
            base = _operation_base(root, _root(state_root))
            latest = _read_json(base / 'latest.json', limit=4096)
            identifier = str(latest.get('job_id', ''))
            if not _ID.fullmatch(identifier):
                return {}
            directory = _private_directory(base / identifier)
            state = _read_json(directory / 'state.json')
            if state.get('busy'):
                state.update(busy=False, status='failed', can_cancel=False, healthy=False,
                             error='The previous recovery operation stopped before finishing. Its private preservation copies were kept.',
                             message='Previous recovery interrupted. Start a new check, or finish any pending recovery rollback.')
            return self._with_pending(root, state)
        except (OSError, ValueError, worker.RecoveryError):
            return self._with_pending(root, {})

    def _with_pending(self, root, state):
        try:
            (root / '.harnessy' / 'workspace-recovery-pending.json').lstat()
            pending = True
        except FileNotFoundError:
            pending = False
        except OSError:
            pending = True
        state['activation_pending'] = pending
        state['pending_switch'] = pending
        state['rollback_ready'] = pending and not state.get('busy')
        return state

    def cancel(self, root) -> dict:
        with self._lock:
            job = self._jobs.get(str(_root(root)))
        if not job:
            return {}
        if job.action in {'activate', 'rollback'} and job.state.get('busy'):
            self._update(job, message='Finishing the database switch or restoring the preserved generation. Wait for this operation to finish.', can_cancel=False)
            return self._snapshot(job)
        if job.state.get('busy'):
            job.cancel_event.set()
            self._update(job, status='cancelling', message='Stopping the private recovery worker. Original database files will remain in place.', can_cancel=False)
        return self._snapshot(job)

    async def close(self):
        self._closing = True
        with self._lock:
            jobs = list(self._jobs.values())
        for job in jobs:
            if job.action not in {'activate', 'rollback'}:
                job.cancel_event.set()
        tasks = [job.task for job in jobs if job.task and not job.task.done()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _run(self, job: _Job) -> None:
        try:
            async with self._limit:
                if job.cancel_event.is_set():
                    raise worker.RecoveryCancelled()
                _diag('workspace_database_recovery_started', job, timeout_seconds=_TIMEOUT)
                operation = self._activate if job.action == 'activate' else (self._rollback if job.action == 'rollback' else self._work)
                await asyncio.to_thread(operation, job)
        except worker.RecoveryCancelled:
            self._record_early_failure(job, 'cancelled', 'cancelled')
            self._finish(job, 'cancelled', 'Recovery cancelled. Original database files were not replaced.', error='')
        except Exception as exc:
            code = getattr(exc, 'reason', None) if getattr(exc, 'reason', None) in {'maintenance', 'recovery_pending'} else getattr(exc, 'code', 'io_error')
            message = str(exc) if isinstance(exc, (worker.RecoveryError, RuntimeError)) else 'The recovery operation could not finish. Preservation copies were kept.'
            self._record_early_failure(job, 'failed', code)
            self._finish(job, 'failed', 'Workspace database recovery stopped.', error=message)
            _diag('workspace_database_recovery_failed', job, recovery_failure_code=code)

    def _record_early_failure(self, job: _Job, status: str, code: str):
        path = job.directory / 'recovery-report.json'
        if not path.exists():
            pending = self._with_pending(job.root, {})['activation_pending']
            report = {'report_version': 1, 'operation_id': job.id, 'action': job.action,
                      'workspace_root': str(job.root), 'db_id': _db_id(job.root),
                      'status': status, 'failure_code': code, 'stage': job.state['stage'],
                      'original_sqlite_opened': False, 'original_hashes_verified': False,
                      'originals_replaced': None if job.action in {'activate', 'rollback'} else False,
                      'activation_pending': pending, 'preservation': {},
                      'completed_unix_seconds': int(time.time())}
            try:
                _write_json(path, report)
            except OSError:
                pass
        if not (job.directory / 'original').is_dir() and job.action not in {'activate', 'rollback'}:
            self._update(job, backup_path='')

    def _finish(self, job: _Job, status: str, message: str, *, error='') -> None:
        self._update(job, busy=False, status=status, message=message, error=error, can_cancel=False)
        _diag('workspace_database_recovery_completed' if status not in {'failed', 'cancelled'} else 'workspace_database_recovery_failed', job)

    def _progress(self, job: _Job, action: str, message: str) -> None:
        stage = 'hash' if action == 'READ' and 'Hashing' in message else ('copy' if action == 'COPY' else job.state['stage'])
        facts = {}
        match = re.search(r'([\d,]+)/([\d,]+) bytes', message)
        if match:
            facts['progress_bytes'], facts['total_bytes'] = (int(value.replace(',', '')) for value in match.groups())
        self._update(job, stage=stage, message=message, **facts)
        _diag('workspace_database_recovery_progress', job,
              copied_bytes=job.state['progress_bytes'], total_bytes=job.state['total_bytes'])

    def _stage(self, job: _Job, stage: str, message: str):
        worker.check_cancel()
        self._update(job, stage=stage, message=message, status='running')
        _diag('workspace_database_recovery_progress', job)

    def _work(self, job: _Job) -> None:
        try:
            release = reserve_environment_change(job.root, 'workspace database recovery')
        except RuntimeError as exc:
            raise worker.RecoveryError('activity_busy', str(exc)) from exc
        try:
            with workspace_maintenance_access(job.root):
                with worker.operation_context(lambda action, message: self._progress(job, action, message), job.cancel_event):
                    assert_no_external_database_users(job.root)
                    self._work_locked(job)
        finally:
            release()

    def _work_locked(self, job: _Job) -> None:
        self._stage(job, 'backup', 'Preserving the workspace database and journals before checking private copies.')
        files, signatures = _source_snapshot(job.root)
        original_fingerprint = workspace_database_fingerprint(job.root)
        sizes = {name: value[2] for name, value in signatures.items()}
        total = sum(sizes.values())
        self._update(job, total_bytes=total, progress_bytes=0)
        free = shutil.disk_usage(job.directory).free
        required = total * 6 + 64 * 1024 * 1024
        _diag('workspace_database_recovery_progress', job, source_bytes=total,
              source_db_bytes=sizes.get('workspace.db', 0), source_wal_bytes=sizes.get('workspace.db-wal', 0),
              source_shm_bytes=sizes.get('workspace.db-shm', 0), source_journal_bytes=sizes.get('workspace.db-journal', 0),
              total_bytes=total, free_bytes=free, required_bytes=required)
        if free < required:
            raise worker.RecoveryError('insufficient_space', 'There is not enough free space for verified preservation and working copies.')
        report = {'report_version': 1, 'operation_id': job.id, 'action': job.action, 'workspace_root': str(job.root),
                  'state_root': str(job.state_root), 'workspace_id': '', 'db_id': _db_id(job.root),
                  'started_unix_seconds': int(job.started), 'original_sqlite_opened': False,
                  'originals_replaced': False, 'activated': False, 'status': 'running',
                  'source_signatures': {name: list(value) for name, value in signatures.items()},
                  'preservation': {}}
        job.report = report
        try:
            worker.preserve(files, job.directory / 'original', report['preservation'])
            self._update(job, total_bytes=total, progress_bytes=total)
            if _source_snapshot(job.root)[1] != signatures:
                raise worker.RecoveryError('source_changed', 'Original workspace files changed while preservation copies were made.')
            metadata = _read_json(job.directory / 'original' / 'workspace.json')
            report['workspace_id'] = str(metadata.get('id') or '')
            report['optional_recovery_candidates'] = worker.inventory(job.root)
            inspection_db = worker.working_copy(job.directory / 'original', job.directory / 'working' / 'inspect')
            self._stage(job, 'inspect', 'Checking the complete private database copy. Large workspaces can take several minutes.')
            baseline = worker.run_worker('inspect', {'database': str(inspection_db)}, job.directory / 'working' / 'inspect', _TIMEOUT)
            report['inspection'] = baseline
            _diag('workspace_database_recovery_progress', job, **_worker_facts(baseline))
            if worker.healthy_workspace(baseline):
                report['status'] = 'healthy'
            elif baseline.get('integrity_ok') is True:
                report['status'] = 'needs_review'
            elif (baseline.get('worker_status') == 'timed_out' or baseline.get('operation_status') == 'timed_out'
                  or baseline.get('sqlite_errorcode') == 9):
                raise worker.RecoveryError('worker_timeout', 'The extended database check reached its time limit. No corruption conclusion was made.')
            elif not (baseline.get('integrity_error_count', 0) > 0 or (baseline.get('sqlite_errorcode') or 0) & 255 in {11, 26}):
                raise worker.RecoveryError('worker_failed', 'The isolated check stopped without establishing database corruption.')
            elif job.action == 'check':
                report['status'] = 'corrupt'
                report['corruption_established'] = True
            else:
                report['corruption_established'] = True
                self._repair_locked(job, report, inspection_db)
            self._stage(job, 'verify', 'Verifying that the original database and every journal are unchanged.')
            assert_no_external_database_users(job.root)
            report.update(_verify_sources(job.root, files, signatures, report['preservation']))
            if report['original_generation_unchanged'] is not True:
                raise worker.RecoveryError('source_changed', 'The original workspace changed during recovery. Candidate eligibility was invalidated.')
            if report['status'] == 'healthy':
                remember_verified_workspace_database(job.root, original_fingerprint)
            report['completed_unix_seconds'] = int(time.time())
            _write_json(job.directory / 'recovery-report.json', report)
            self._publish_result(job, report)
        except BaseException:
            # Cancellation still leaves a useful bounded metadata report. All
            # native work occurred only on disposable copies, never originals.
            report['status'] = 'cancelled' if job.cancel_event.is_set() else 'failed'
            if 'candidate' in report:
                report['candidate']['eligible_for_activation'] = False
            # Never turn Cancel/shutdown into a fresh multi-gigabyte hash.
            # Failure reports keep completed preservation receipts, but an
            # unfinished final proof stays unknown and cannot activate copies.
            report.setdefault('original_generation_unchanged', None)
            report.setdefault('original_file_set_unchanged', None)
            report.setdefault('original_hash_verification', {})
            report['completed_unix_seconds'] = int(time.time())
            _write_json(job.directory / 'recovery-report.json', report)
            raise

    def _repair_locked(self, job: _Job, report: dict, inspection_db: Path):
        baseline = report['inspection']
        if baseline.get('index_only') is True:
            self._stage(job, 'reindex', 'Rebuilding damaged indexes on a fresh private candidate copy.')
            candidate = worker.working_copy(job.directory / 'original', job.directory / 'working' / 'reindex')
            result = worker.run_worker('reindex', {'database': str(candidate)}, job.directory / 'working' / 'reindex', _TIMEOUT)
            report['reindex'] = result
            _diag('workspace_database_recovery_progress', job, **_worker_facts(result),
                  **_worker_facts(result.get('validation', {})))
            if worker.verified_candidate(baseline, result.get('validation', {})):
                report['status'] = 'candidate_ready'
                report['candidate'] = {'receipt_id': job.id, 'kind': 'reindex', 'path': str(candidate),
                                       'sha256': worker.digest(candidate), 'eligible_for_activation': True,
                                       'standalone_database': True}
                return
        self._stage(job, 'schema', 'Preparing the installed canonical schema for a separate salvage candidate.')
        template = worker.schema_template(_canonical_app_root(job.app_root), job.directory / 'canonical-schema.json')
        report['canonical_schema'] = template
        if not template.get('available'):
            report['status'] = 'needs_review'
            return
        self._stage(job, 'salvage', 'Attempting SQLite salvage on the private copy. Salvage cannot be activated automatically.')
        directory = job.directory / 'working' / 'salvage'
        directory.mkdir(mode=0o700, parents=True)
        request = {'database': str(inspection_db), 'sqlite_cli_candidates': worker.sqlite_cli_candidates(),
                   'recovered_sql': str(directory / 'recovered.sql'), 'candidate': str(directory / 'candidate.sqlite'),
                   'template': template['template_path']}
        result = worker.run_worker('recover', request, directory, _TIMEOUT)
        report['salvage'] = result
        _diag('workspace_database_recovery_progress', job, **_worker_facts(result),
              **_worker_facts(result.get('validation', {})))
        report['status'] = 'partial_salvage' if result.get('candidate_created') else 'needs_review'
        if result.get('candidate_created'):
            candidate = Path(result['candidate'])
            report['candidate'] = {'receipt_id': job.id, 'kind': 'salvage', 'path': str(candidate),
                                   'sha256': worker.digest(candidate), 'eligible_for_activation': False,
                                   'standalone_database': bool(result.get('validation', {}).get('standalone_database')),
                                   'completeness': 'unknown'}

    def _publish_result(self, job: _Job, report: dict):
        candidate = report.get('candidate', {})
        baseline = report.get('inspection', {})
        final = (report.get('reindex', {}).get('validation') or report.get('salvage', {}).get('validation') or {})
        status = report['status']
        self._update(job, healthy=status == 'healthy', partial_salvage=status == 'partial_salvage',
                     candidate=deepcopy(candidate), candidate_path=candidate.get('path', ''),
                     candidate_receipt_id=candidate.get('receipt_id', ''),
                     candidate_verified=candidate.get('eligible_for_activation') is True,
                     candidate_counts={'before': baseline.get('row_counts', {}), 'after': final.get('row_counts', {})})
        messages = {'healthy': 'The full database check passed. Open the workspace to continue.',
                    'candidate_ready': 'A repaired copy passed integrity, relationship and row-by-row checks. Choose Use repaired database to install it.',
                    'partial_salvage': 'A salvage copy was created. Its completeness is unknown; download the report for review.',
                    'corrupt': 'Database corruption was confirmed on the preserved copy. Choose Repair workspace to create a recovery candidate.',
                    'needs_review': 'The check needs review. Original database files remain in place; download the report.'}
        self._finish(job, status if status != 'corrupt' else 'needs_review', messages[status])
        _diag('workspace_database_recovery_completed', job, source_unchanged=True,
              corruption_established=report.get('corruption_established') is True,
              recovery_method='reindex' if candidate.get('kind') == 'reindex' else ('salvage' if candidate.get('kind') == 'salvage' else 'check_only'),
              originals_preserved=True, completeness_known=candidate.get('kind') != 'salvage',
              candidate_verified=candidate.get('eligible_for_activation') is True,
              source_row_counts=baseline.get('row_counts', {}), candidate_row_counts=final.get('row_counts', {}))

    def candidate_for_activation(self, root, receipt_id, state_root):
        return validate_candidate_report(root, receipt_id, state_root)

    def _activate(self, job: _Job):
        from .workspace_recovery_activation import activate_repaired_workspace
        identifier = job.state['activation_receipt_id']
        self._stage(job, 'activate', 'Verifying the repaired candidate before switching database generations.')
        # The activation module validates the complete receipt under its own
        # exclusive lease, after recognizing an already-completed transaction.
        # Pre-validating against the old source here would break that retry.
        receipt = {'receipt_id': identifier, 'state_root': job.state_root}
        result = activate_repaired_workspace(job.root, receipt, maintenance_held=False, timeout=_TIMEOUT)
        _write_json(job.directory / 'recovery-report.json', {'action': 'activate', 'operation_id': job.id,
                    'receipt_id': identifier, 'result': result, 'completed_unix_seconds': int(time.time())})
        activated = result.get('status') == 'activated'
        self._update(job, activation_result=result, healthy=activated,
                     backup_path=str(result.get('backup_path') or
                                     job.directory.parent / identifier.replace('-', '') / 'original'))
        self._finish(job, 'activated' if activated else 'failed',
                     'The verified repaired database is active. Open the workspace to continue.' if activated else 'The database switch did not finish. Original recovery files were retained.')

    def _rollback(self, job: _Job):
        from .workspace_recovery_activation import resume_workspace_recovery_activation
        self._stage(job, 'rollback', 'Restoring the preserved original database generation from an interrupted switch.')
        result = resume_workspace_recovery_activation(job.root)
        _write_json(job.directory / 'recovery-report.json', {'action': 'rollback', 'operation_id': job.id,
                    'result': result, 'completed_unix_seconds': int(time.time())})
        self._update(job, healthy=False, activation_result=result)
        self._finish(job, 'rolled_back', 'The interrupted switch was rolled back. Check the preserved original database before continuing.')

    def mark_activated(self, root, receipt_id):
        with self._lock:
            job = self._jobs.get(str(_root(root)))
        if job:
            self._update(job, status='activated', healthy=True, candidate_verified=False, busy=False, can_cancel=False)


def validate_candidate_report(root, receipt_id, state_root) -> dict:
    root, state_root = _root(root), _root(state_root)
    identifier = str(receipt_id).replace('-', '')
    if not _ID.fullmatch(identifier):
        raise worker.RecoveryError('report_invalid', 'Invalid recovery receipt identifier.')
    base = _operation_base(root, state_root)
    directory = _private_directory(base / identifier)
    report_path = directory / 'recovery-report.json'
    report = _read_json(report_path)
    candidate = report.get('candidate', {})
    if (report.get('operation_id') != identifier or report.get('workspace_root') != str(root)
            or report.get('state_root') != str(state_root) or candidate.get('receipt_id') != identifier
            or report.get('status') != 'candidate_ready' or report.get('original_generation_unchanged') is not True
            or candidate.get('kind') != 'reindex' or candidate.get('eligible_for_activation') is not True
            or candidate.get('standalone_database') is not True):
        raise worker.RecoveryError('candidate_unavailable', 'This recovery copy is not eligible for automatic activation.')
    path = directory / 'working' / 'reindex' / 'workspace.db'
    for parent in (directory / 'working', path.parent):
        _private_directory(parent)
    if candidate.get('path') != str(path) or not _HASH.fullmatch(str(candidate.get('sha256', ''))):
        raise worker.RecoveryError('report_invalid', 'Recovery candidate path is not the verified private candidate.')
    if worker.digest(path) != candidate['sha256'] or any(Path(str(path) + suffix).exists() for suffix in worker.SIDECARS[1:]):
        raise worker.RecoveryError('candidate_unavailable', 'The repaired candidate changed or has unfinished journal state.')
    if not worker.verified_candidate(report.get('inspection', {}), report.get('reindex', {}).get('validation', {})):
        raise worker.RecoveryError('report_invalid', 'The repaired candidate lacks matching row-by-row verification.')
    files, signatures = _source_snapshot(root)
    expected = {name: tuple(value) for name, value in report.get('source_signatures', {}).items()}
    if signatures != expected:
        raise worker.RecoveryError('source_changed', 'Original database files changed since this candidate was created. Run a new check.')
    preservation = report.get('preservation', {})
    if set(preservation) != set(files):
        raise worker.RecoveryError('report_invalid', 'Recovery preservation records do not cover the original file set.')
    original_directory = _private_directory(directory / 'original')
    for name, source in files.items():
        entry = preservation[name]
        preserved = original_directory / name
        if (not isinstance(entry, dict) or entry.get('source') != str(source)
                or entry.get('preserved_copy') != str(preserved) or entry.get('verified') is not True
                or not _HASH.fullmatch(str(entry.get('sha256', '')))
                or entry.get('copy_sha256') != entry.get('sha256')
                or worker.digest(preserved) != entry['sha256']):
            raise worker.RecoveryError('report_invalid', 'A private preservation copy no longer matches its verified receipt.')
    original_metadata = _read_json(original_directory / 'workspace.json')
    if not original_metadata.get('id') or report.get('workspace_id') != original_metadata.get('id'):
        raise worker.RecoveryError('report_invalid', 'Recovery workspace identity does not match its preserved metadata.')
    proof = _verify_sources(root, files, expected, report.get('preservation', {}))
    if proof['original_generation_unchanged'] is not True:
        raise worker.RecoveryError('source_changed', 'The original database no longer matches this recovery receipt.')
    assert_no_external_database_users(root)
    return {'report': report, 'report_path': report_path, 'candidate_path': path,
            'workspace_id': str(report.get('workspace_id') or ''), 'receipt_id': identifier,
            'state_root': state_root, 'root': root}


def inspect_activation_candidate(candidate_path, *, timeout=_TIMEOUT) -> dict:
    path = Path(candidate_path).expanduser().resolve()
    directory = path.parent / ('activation-check-' + uuid.uuid4().hex)
    directory.mkdir(mode=0o700)
    copy = directory / 'candidate.sqlite'
    descriptor = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with path.open('rb') as incoming, os.fdopen(descriptor, 'wb') as outgoing:
        shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
        outgoing.flush()
        os.fsync(outgoing.fileno())
    if worker.digest(copy) != worker.digest(path):
        raise worker.RecoveryError('copy_failed', 'The activation verification copy did not match its candidate.')
    return worker.run_worker('inspect', {'database': str(copy)}, directory, float(timeout))


def assert_no_external_database_users(root) -> dict:
    return worker.verify_no_open_database(worker.original_files(_root(root)))


RECOVERY_OPERATIONS = RecoveryOperations()
