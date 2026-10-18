"""Bounded admission of existing workspace databases outside the app process.

Admission opens the original through SQLite's read-only mode in an isolated
worker and checks a coherent disposable backup, including committed WAL rows.
It performs no repair or rebuild. SQLite may create empty WAL/SHM sidecars or
update transient SHM read-lock bookkeeping as for any WAL reader. Successful admission can then be followed by
ordinary store initialization in another contained child. The admission worker
uses only the standard library; initialization imports core modules without
the UI runtime or global settings loader.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time


_ERROR_MESSAGES = {
    'corrupt': 'The workspace database failed its integrity check. Its database, journals and project files were preserved. Keep this workspace closed and retain a copy for recovery.',
    'unavailable': 'The workspace database is unavailable or changed during its check. Its files were preserved. Check the mounted disk and retry the workspace.',
    'timed_out': 'The workspace database check timed out. The check was stopped and its files were preserved. Retry after checking the workspace disk.',
    'worker_failed': 'The isolated workspace database check stopped unexpectedly. Its files were preserved. Retry the workspace and include diagnostics if this repeats.',
}
_REASONS = frozenset({
    'integrity_failed', 'sqlite_corrupt', 'sqlite_error', 'sqlite_busy', 'filesystem_error',
    'database_changed', 'admission_required', 'worker_timeout', 'worker_exit',
    'worker_protocol', 'invalid_file', 'empty_database', 'initialization_failed', 'cancelled',
    'history_busy', 'maintenance', 'recovery_pending',
})
_SIDECARS = ('', '-wal', '-journal')
_CACHE_LOCK = threading.RLock()
_CACHE: dict[str, 'WorkspaceAdmission | WorkspaceDatabaseError'] = {}
_PROBE_LOCKS: dict[str, threading.Lock] = {}
_PREPARE_LOCKS: dict[str, threading.Lock] = {}
_ACTIVE_WORKERS: dict[int, subprocess.Popen] = {}
_CANCELLING = threading.Event()
_INITIALIZING_IN_WORKER: tuple[int, str, tuple] | None = None
_SQLITE_CONSTANTS = {name: value for name, value in vars(sqlite3).items()
                     if name.startswith('SQLITE_') and type(value) is int}


def _sqlite_fields(code, name) -> dict:
    """Retain only numeric result codes and matching SQLite-owned identifiers."""
    fields = {}
    if type(code) is int and 0 <= code <= 2**31 - 1:
        fields['sqlite_errorcode'] = code
        if isinstance(name, str) and _SQLITE_CONSTANTS.get(name) == code:
            fields['sqlite_errorname'] = name
    return fields


def _sqlite_failure(exc: sqlite3.Error) -> dict:
    fields = _sqlite_fields(getattr(exc, 'sqlite_errorcode', None),
                            getattr(exc, 'sqlite_errorname', None))
    primary = fields.get('sqlite_errorcode', 0) & 255
    if primary in {sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB}:
        code, reason = 'corrupt', 'sqlite_corrupt'
    elif primary in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        code, reason = 'unavailable', 'sqlite_busy'
    elif primary == sqlite3.SQLITE_INTERRUPT:
        code, reason = 'timed_out', 'worker_timeout'
    else:
        code, reason = 'unavailable', 'sqlite_error'
    return {'status': 'error', 'code': code, 'reason': reason, **fields}


class WorkspaceDatabaseError(RuntimeError):
    """Content-free, recoverable failure of workspace database admission."""

    def __init__(
        self, code: str, *, reason: str = '', phase: str = 'admission',
        worker_returncode: int | None = None,
        sqlite_errorcode: int | None = None, sqlite_errorname: str | None = None,
    ) -> None:
        self.code = code if code in _ERROR_MESSAGES else 'worker_failed'
        self.reason = reason if reason in _REASONS else 'worker_protocol'
        self.phase = phase if phase in {'admission', 'initialization'} else 'admission'
        self.worker_returncode = worker_returncode if type(worker_returncode) is int else None
        sqlite_fields = _sqlite_fields(sqlite_errorcode, sqlite_errorname)
        self.sqlite_errorcode = sqlite_fields.get('sqlite_errorcode')
        self.sqlite_errorname = sqlite_fields.get('sqlite_errorname')
        signals = {getattr(signal, name, object()): name for name in (
            'SIGBUS', 'SIGSEGV', 'SIGABRT', 'SIGKILL', 'SIGTERM',
        )}
        self.worker_signal = (signals.get(-worker_returncode, 'other')
                              if type(worker_returncode) is int and worker_returncode < 0 else 'none')
        if self.reason == 'sqlite_busy':
            message = 'Another operation is using the workspace database. Wait for that operation to finish, then retry opening the workspace.'
        elif self.reason == 'maintenance':
            message = 'This workspace is being checked or repaired. Wait for the operation to finish, then retry.'
        elif self.reason == 'recovery_pending':
            message = 'Workspace recovery was interrupted. Finish or roll back recovery before opening this workspace.'
        elif self.reason == 'database_changed':
            message = 'The workspace database changed or disappeared. Reopen the workspace to load its current database.'
        elif self.reason == 'history_busy':
            message = (
                'Private file history is busy in another operation. Wait for active history work to finish, '
                'then retry opening this workspace or the history action. '
                'Existing project files and lock files were preserved.'
            )
        else:
            message = _ERROR_MESSAGES[self.code]
        super().__init__(message)


@dataclass(frozen=True)
class WorkspaceAdmission:
    status: str
    fingerprint: tuple


def _database_path(root: str | Path) -> Path:
    return Path(root).expanduser().resolve() / '.harnessy' / 'workspace.db'


def _fingerprint(db: Path) -> tuple:
    """Watch durable generations, including committed uncheckpointed WAL rows.

    SHM is a transient coordination index. Reading SQLite may change it without
    changing any database content, so it does not invalidate admission.
    """
    result = []
    for suffix in _SIDECARS:
        path = Path(str(db) + suffix)
        try:
            value = path.lstat()
        except FileNotFoundError:
            result.append(None)
            continue
        if not stat.S_ISREG(value.st_mode):
            raise WorkspaceDatabaseError('unavailable', reason='invalid_file')
        result.append((value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns))
    return tuple(result)


def forget_workspace_admission(root: str | Path) -> None:
    with _CACHE_LOCK:
        _CACHE.pop(str(_database_path(root)), None)


def require_workspace_not_quarantined(root: str | Path) -> None:
    """Reject a known failed admission without treating WAL writes as damage.

    Live stores use this cache-only check while holding their shared lease.
    A confirmed failure remains authoritative until an explicit successful
    probe or verified recovery replaces it, even if the main inode is stable.
    """
    key = str(_database_path(root))
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
    if isinstance(cached, WorkspaceDatabaseError):
        raise cached


def workspace_preparation_timeout(root: str | Path, *, minimum: float = 20.0,
                                  maximum: float = 300.0) -> float:
    """Budget a cold check from DB/WAL sizes without opening either in SQLite.

    Up to 128 MiB keeps the ordinary 20-second limit. Larger snapshots receive
    one additional second per 16 MiB, bounded at five minutes. Explicit caller
    timeouts remain separate from this default sizing policy.
    """
    from .workspace_access import workspace_shared_access
    with workspace_shared_access(root, allow_missing=True):
        fingerprint = _fingerprint(_database_path(root))
    total = sum(row[2] for row in fingerprint[:2] if row is not None)
    extra = math.ceil(max(0, total - 128 * 1024 * 1024) / (16 * 1024 * 1024))
    return min(float(maximum), max(float(minimum), 20.0 + extra))


def _remember_failure(key: str, error: 'WorkspaceDatabaseError') -> None:
    # A reader/writer lock or bounded timeout says nothing about corruption.
    # Keep any previous admission (including a quarantine) rather than making
    # an ordinary retry fail forever after the competing operation finishes.
    primary = (error.sqlite_errorcode or 0) & 255
    if (error.code == 'timed_out' or error.reason == 'sqlite_busy'
            or primary in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}):
        return
    with _CACHE_LOCK:
        _CACHE[key] = error


def workspace_database_fingerprint(root: str | Path) -> tuple:
    """Read durable database identities while the caller owns an access lease."""
    return _fingerprint(_database_path(root))


def remember_verified_workspace_database(root: str | Path, expected_fingerprint: tuple) -> WorkspaceAdmission:
    """Acknowledge the recovery engine's full check under its exclusive lease.

    This performs no SQLite work. The engine must already have verified its
    cold copy and unchanged original generation; only the exact final durable
    fingerprint can replace a prior admission failure.
    """
    from .workspace_access import owns_workspace_maintenance
    if not owns_workspace_maintenance(root):
        raise WorkspaceDatabaseError('unavailable', reason='maintenance')
    db = _database_path(root)
    actual = _fingerprint(db)
    if actual != expected_fingerprint or actual[0] is None:
        raise WorkspaceDatabaseError('unavailable', reason='database_changed')
    result = WorkspaceAdmission('healthy', actual)
    with _CACHE_LOCK:
        _CACHE[str(db)] = result
    return result


def require_workspace_database_admitted(root: str | Path) -> WorkspaceAdmission:
    """Cache-only admission for UI callers; never starts/waits for a worker.

    A previous fixed failure remains visible until an explicit retry, rather
    than repeatedly probing the same damaged database from UI refreshes.
    """
    db = _database_path(root)
    with _CACHE_LOCK:
        cached = _CACHE.get(str(db))
    if isinstance(cached, WorkspaceDatabaseError):
        raise cached
    try:
        current = _fingerprint(db)
    except OSError as exc:
        raise WorkspaceDatabaseError('unavailable', reason='filesystem_error') from exc
    if current[0] is None:
        if any(part is not None for part in current[1:]):
            raise WorkspaceDatabaseError('unavailable', reason='invalid_file')
        return WorkspaceAdmission('new', current)
    if isinstance(cached, WorkspaceAdmission) and cached.fingerprint == current:
        return cached
    # The contained initialization child starts from a previously admitted
    # coherent snapshot. Other connections may commit while it initializes;
    # accepting the same main-file identity here avoids rejecting ordinary WAL
    # growth. This context is never set in the app process or via environment.
    worker = _INITIALIZING_IN_WORKER
    if (worker is not None and worker[:2] == (os.getpid(), str(db))
            and current[0] is not None and current[0][:2] == worker[2]
            and isinstance(cached, WorkspaceAdmission)):
        return cached
    raise WorkspaceDatabaseError('unavailable', reason='admission_required')


def remember_workspace_database_admitted(root: str | Path, admission: WorkspaceAdmission) -> None:
    """Refresh an admitted generation after its successful store initialization.

    Only the constructor that already obtained this exact admission can use
    this refresh. A failed constructor must leave admission unchanged.
    """
    db = _database_path(root)
    try:
        current = _fingerprint(db)
    except OSError:
        return
    with _CACHE_LOCK:
        previous = _CACHE.get(str(db))
        if previous is admission or (admission.status == 'new' and previous is None):
            _CACHE[str(db)] = WorkspaceAdmission('healthy', current)


def _stop_worker(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name != 'nt':
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        return
    try:
        process.communicate(timeout=.3)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if os.name != 'nt':
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        return
    try:
        process.communicate(timeout=.3)
    except subprocess.TimeoutExpired:
        # An uninterruptible OS storage operation must not hold the UI hostage.
        # The admission child cannot write the originals. An initialization
        # child owns only its ordinary SQLite transaction, never a user VM.
        for pipe in (process.stdin, process.stdout):
            if pipe is not None:
                pipe.close()


def cancel_pending_workspace_workers() -> None:
    """Stop only owned admission/initialization children during app shutdown.

    Waiting threads wake as their pipes close. Groups include Git subprocesses
    spawned by initialization, and never include the app or unrelated VMs.
    """
    _CANCELLING.set()
    with _CACHE_LOCK:
        processes = list(_ACTIVE_WORKERS.values())
    for process in processes:
        if process.poll() is None:
            try:
                if os.name != 'nt':
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + .3
    while any(process.poll() is None for process in processes) and time.monotonic() < deadline:
        time.sleep(.01)
    for process in processes:
        if process.poll() is None:
            try:
                if os.name != 'nt':
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass


def _run_worker(db: Path, mode: str, timeout: float, *, name: str | None = None) -> dict:
    try:
        return _run_worker_inner(db, mode, timeout, name=name)
    except WorkspaceDatabaseError as exc:
        exc.phase = 'initialization' if mode == '--prepare' else 'admission'
        raise


def _run_worker_inner(db: Path, mode: str, timeout: float, *, name: str | None = None) -> dict:
    # Parent-owned scratch state is removed even after a native worker crash.
    with tempfile.TemporaryDirectory(prefix='harnessy-workspace-check-') as temporary:
        command = [sys.executable, '-I', '-u', str(Path(__file__).resolve()),
                   mode, str(db), temporary, str(timeout)]
        if mode == '--prepare':
            command.append(json.dumps(name))
        if _CANCELLING.is_set():
            raise WorkspaceDatabaseError('unavailable', reason='cancelled')
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True, cwd=temporary,
            start_new_session=(os.name != 'nt'),
        )
        with _CACHE_LOCK:
            _ACTIVE_WORKERS[process.pid] = process
        try:
            if _CANCELLING.is_set():
                _stop_worker(process)
                raise WorkspaceDatabaseError('unavailable', reason='cancelled')
            try:
                output, _ = process.communicate(timeout=timeout)
            except BaseException as exc:
                _stop_worker(process)
                if isinstance(exc, subprocess.TimeoutExpired):
                    raise WorkspaceDatabaseError('timed_out', reason='worker_timeout') from exc
                raise
        except WorkspaceDatabaseError as exc:
            exc.phase = 'initialization' if mode == '--prepare' else 'admission'
            raise
        finally:
            with _CACHE_LOCK:
                _ACTIVE_WORKERS.pop(process.pid, None)
        if _CANCELLING.is_set():
            raise WorkspaceDatabaseError('unavailable', reason='cancelled',
                                         phase='initialization' if mode == '--prepare' else 'admission')
        if process.returncode != 0:
            raise WorkspaceDatabaseError('worker_failed', reason='worker_exit',
                                         phase='initialization' if mode == '--prepare' else 'admission',
                                         worker_returncode=process.returncode)
        if len(output) > 1024 * 1024:
            raise WorkspaceDatabaseError('worker_failed', reason='worker_protocol')
        try:
            report = json.loads(output)
        except (ValueError, TypeError, UnicodeDecodeError) as exc:
            raise WorkspaceDatabaseError('worker_failed', reason='worker_protocol') from exc
        if not isinstance(report, dict) or report.get('status') not in {'healthy', 'error', 'prepared'}:
            raise WorkspaceDatabaseError('worker_failed', reason='worker_protocol')
        return report


def probe_workspace_database(
    root: str | Path, *, timeout: float = 12.0, force: bool = False,
) -> WorkspaceAdmission:
    from .workspace_access import workspace_shared_access
    with workspace_shared_access(root, allow_missing=True):
        return _probe_workspace_database(root, timeout=timeout, force=force)


def _probe_workspace_database(
    root: str | Path, *, timeout: float = 12.0, force: bool = False,
) -> WorkspaceAdmission:
    """Check one stable database copy in a bounded, separately spawned process.

    Async UI callers should run this through ``asyncio.to_thread``. The cached
    constructor mode is the corresponding non-waiting admission gate.
    """
    db = _database_path(root)
    key = str(db)
    with _CACHE_LOCK:
        lock = _PROBE_LOCKS.setdefault(key, threading.Lock())
    timeout = min(7200.0, max(.1, float(timeout)))
    started = time.monotonic()
    if not lock.acquire(timeout=timeout):
        raise WorkspaceDatabaseError('timed_out', reason='worker_timeout')
    try:
        if not force:
            try:
                return require_workspace_database_admitted(root)
            except WorkspaceDatabaseError as exc:
                if exc.reason != 'admission_required':
                    raise
        before = _fingerprint(db)
        if before[0] is None:
            if any(part is not None for part in before[1:]):
                raise WorkspaceDatabaseError('unavailable', reason='invalid_file')
            result = WorkspaceAdmission('new', before)
        else:
            if before[0][2] == 0:
                raise WorkspaceDatabaseError('corrupt', reason='empty_database')
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise WorkspaceDatabaseError('timed_out', reason='worker_timeout')
            report = _run_worker(db, '--probe', remaining)
            if report['status'] not in {'healthy', 'error'}:
                raise WorkspaceDatabaseError('worker_failed', reason='worker_protocol')
            after = _fingerprint(db)
            # Other connections may append WAL transactions while the backup
            # reader holds a coherent snapshot. Replacing the main DB is a
            # different workspace generation and must be refused.
            if after[0] is None or before[0][:2] != after[0][:2]:
                raise WorkspaceDatabaseError('unavailable', reason='database_changed')
            if report['status'] == 'error':
                raise WorkspaceDatabaseError(str(report.get('code')), reason=str(report.get('reason')),
                                             sqlite_errorcode=report.get('sqlite_errorcode'),
                                             sqlite_errorname=report.get('sqlite_errorname'))
            result = WorkspaceAdmission('healthy', after)
        with _CACHE_LOCK:
            _CACHE[key] = result
        return result
    except WorkspaceDatabaseError as exc:
        _remember_failure(key, exc)
        raise
    except (OSError, ValueError) as exc:
        error = WorkspaceDatabaseError('unavailable', reason='filesystem_error')
        with _CACHE_LOCK:
            _CACHE[key] = error
        raise error from exc
    finally:
        lock.release()


def _worker_probe(db: Path, temporary: Path, timeout: float) -> dict:
    # A parent dying must not release the only lease while its SQLite child
    # remains alive. The isolated worker acquires its own descriptor.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from harnessy.core.workspace_access import workspace_shared_access
    with workspace_shared_access(db.parent.parent):
        return _worker_probe_inner(db, temporary, timeout)


def _worker_probe_inner(db: Path, temporary: Path, timeout: float) -> dict:
    """Worker-only SQLite work. Never call this directly in the app process."""
    deadline = time.monotonic() + max(.05, timeout * .95)
    before = _fingerprint(db)
    copy = temporary / 'workspace.db'
    source = None
    connection = None

    def backup_progress(_status: int, _remaining: int, _total: int) -> None:
        if time.monotonic() >= deadline:
            raise TimeoutError('database backup deadline')

    try:
        # SQLite's online backup includes committed WAL rows and remains
        # coherent if other connections commit while it copies. A raw file
        # copy of an actively written DB/WAL pair would not have that property.
        source = sqlite3.connect(db.as_uri() + '?mode=ro', uri=True, timeout=.2)
        source.execute('PRAGMA mmap_size=0').close()
        source.execute('PRAGMA query_only=ON').close()
        source.execute('PRAGMA temp_store=MEMORY').close()
        source.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        destination = sqlite3.connect(copy)
        try:
            source.backup(destination, pages=256, progress=backup_progress, sleep=.01)
        finally:
            destination.close()
        source.close()
        source = None
        after_backup = _fingerprint(db)
        if after_backup[0] is None or after_backup[0][:2] != before[0][:2]:
            return {'status': 'error', 'code': 'unavailable', 'reason': 'database_changed'}
        connection = sqlite3.connect(copy.as_uri() + '?mode=ro', uri=True, timeout=.2)
        connection.execute('PRAGMA mmap_size=0').close()
        connection.execute('PRAGMA query_only=ON').close()
        connection.execute('PRAGMA temp_store=MEMORY').close()
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        # Full integrity_check checks index/table consistency as well as page
        # structure. Do not return any diagnostic row: it may contain content.
        cursor = connection.execute('PRAGMA integrity_check(1)')
        row = cursor.fetchone()
        cursor.close()
        if row != ('ok',):
            return {'status': 'error', 'code': 'corrupt', 'reason': 'integrity_failed'}
        if time.monotonic() >= deadline:
            return {'status': 'error', 'code': 'timed_out', 'reason': 'worker_timeout'}
    except TimeoutError:
        return {'status': 'error', 'code': 'timed_out', 'reason': 'worker_timeout'}
    except sqlite3.Error as exc:
        return _sqlite_failure(exc)
    finally:
        if connection is not None:
            connection.close()
        if source is not None:
            source.close()
    after = _fingerprint(db)
    if after[0] is None or before[0][:2] != after[0][:2]:
        return {'status': 'error', 'code': 'unavailable', 'reason': 'database_changed'}
    return {'status': 'healthy'}


def prepare_workspace_store(
    root: str | Path, name: str | None = None, *, timeout: float = 20.0, force: bool = False,
):
    from .workspace_access import workspace_shared_access
    with workspace_shared_access(root, allow_missing=True):
        return _prepare_workspace_store(root, name, timeout=timeout, force=force)


def _prepare_workspace_store(
    root: str | Path, name: str | None = None, *, timeout: float = 20.0, force: bool = False,
):
    """Admit and initialize a workspace in bounded isolated processes.

    This is the UI bootstrap entry point, run through ``asyncio.to_thread``.
    Native initialization failures stay in the child; the returned store is
    hydrated without repeating initialization or opening SQLite in the parent.
    """
    db = _database_path(root)
    key = str(db)
    timeout = min(7200.0, max(.1, float(timeout)))
    started = time.monotonic()
    with _CACHE_LOCK:
        lock = _PREPARE_LOCKS.setdefault(key, threading.Lock())
    if not lock.acquire(timeout=timeout):
        raise WorkspaceDatabaseError('timed_out', reason='worker_timeout')
    try:
        admission = probe_workspace_database(root, timeout=timeout, force=force)
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise WorkspaceDatabaseError('timed_out', reason='worker_timeout')
        report = _run_worker(db, '--prepare', remaining, name=name)
        if report['status'] == 'error':
            raise WorkspaceDatabaseError(str(report.get('code')), reason=str(report.get('reason')),
                                         phase='initialization',
                                         sqlite_errorcode=report.get('sqlite_errorcode'),
                                         sqlite_errorname=report.get('sqlite_errorname'))
        metadata = report.get('metadata')
        is_vm_workspace = report.get('is_vm_workspace')
        if (report['status'] != 'prepared' or not isinstance(metadata, dict)
                or type(is_vm_workspace) is not bool
                or any(not isinstance(metadata.get(field), str) or not metadata[field]
                       for field in ('id', 'name', 'files_storage_id'))
                or type(metadata.get('schema_version')) is not int):
            raise WorkspaceDatabaseError('worker_failed', reason='worker_protocol')
        after = _fingerprint(db)
        if (after[0] is None or (admission.status != 'new'
                and admission.fingerprint[0][:2] != after[0][:2])):
            raise WorkspaceDatabaseError('unavailable', reason='database_changed')
        with _CACHE_LOCK:
            if isinstance(_CACHE.get(key), WorkspaceDatabaseError):
                raise WorkspaceDatabaseError('unavailable', reason='database_changed')
            _CACHE[key] = WorkspaceAdmission('healthy', after)
        from .workspace import WorkspaceStore
        return WorkspaceStore._from_prepared_metadata(db.parent.parent, metadata, is_vm_workspace)
    except WorkspaceDatabaseError as exc:
        _remember_failure(key, exc)
        raise
    except (OSError, ValueError) as exc:
        error = WorkspaceDatabaseError('unavailable', reason='filesystem_error')
        with _CACHE_LOCK:
            _CACHE[key] = error
        raise error from exc
    finally:
        lock.release()


def _worker_prepare(db: Path, name: str | None) -> dict:
    # -I deliberately ignores PYTHONPATH and site customizations. Add only the
    # trusted source tree of this exact installed worker, then import the
    # stdlib-only core. No NiceGUI, settings loader or configured log session.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from harnessy.core import workspace_health as health
    from harnessy.core.workspace import WorkspaceStore
    from harnessy.core.history import HistoryBusyError, HistoryError
    current = health._fingerprint(db)
    with health._CACHE_LOCK:
        health._CACHE[str(db)] = health.WorkspaceAdmission(
            'new' if current[0] is None else 'healthy', current,
        )
    if current[0] is not None:
        health._INITIALIZING_IN_WORKER = (os.getpid(), str(db), current[0][:2])
    try:
        store = WorkspaceStore(db.parent.parent, name, database_admission='cached')
    except sqlite3.Error as exc:
        return _sqlite_failure(exc)
    except HistoryBusyError:
        return {'status': 'error', 'code': 'unavailable', 'reason': 'history_busy'}
    except (HistoryError, RuntimeError, ValueError):
        return {'status': 'error', 'code': 'unavailable', 'reason': 'initialization_failed'}
    return {'status': 'prepared', 'metadata': store.metadata, 'is_vm_workspace': store.is_vm_workspace}


if __name__ == '__main__':
    try:
        # Native faults are reported by the parent as fixed signal evidence.
        # Do not leave a potentially huge, content-bearing core dump behind.
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ImportError, OSError, ValueError):
            pass
        if len(sys.argv) == 5 and sys.argv[1] == '--probe':
            report = _worker_probe(Path(sys.argv[2]), Path(sys.argv[3]), float(sys.argv[4]))
        elif len(sys.argv) == 6 and sys.argv[1] == '--prepare':
            name = json.loads(sys.argv[5])
            if name is not None and not isinstance(name, str):
                raise ValueError('invalid workspace name')
            report = _worker_prepare(Path(sys.argv[2]), name)
        else:
            raise ValueError('invalid worker invocation')
    except WorkspaceDatabaseError as exc:
        report = {'status': 'error', 'code': exc.code, 'reason': exc.reason}
    except (OSError, ValueError):
        report = {'status': 'error', 'code': 'unavailable', 'reason': 'filesystem_error'}
    print(json.dumps(report, separators=(',', ':')), flush=True)
