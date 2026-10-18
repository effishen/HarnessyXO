"""Nonblocking, process-shared leases for workspace database maintenance.

Normal SQLite connections retain a shared lease until they close. Recovery
holds the exclusive lease while preserving or replacing database generations.
The lock itself never expires and is never deleted; the OS releases leases
when their owning descriptors close.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import threading
import weakref
from typing import Any

from .sqlite_store import StoreConnection

LOCK_NAME = 'workspace-access.lock'
PENDING_NAME = 'workspace-recovery-pending.json'
GENERATION_NAME = 'workspace-generation'
_TOKEN = re.compile(r'[A-Za-z0-9_-]{1,128}\Z', re.ASCII)
_LEASE_LOCK = threading.RLock()
_LEASES: weakref.WeakSet['WorkspaceAccessLease'] = weakref.WeakSet()
WorkspaceGeneration = tuple[int | None, int | None, str]


def _error(reason: str):
    # workspace_health uses this module lazily, keeping the worker import path
    # and its public error class independent of the SQLite connection subclass.
    from .workspace_health import WorkspaceDatabaseError
    return WorkspaceDatabaseError('unavailable', reason=reason)


def _root(root: str | Path) -> Path:
    return Path(root).expanduser().resolve()


def _pending(meta: Path) -> bool:
    try:
        (meta / PENDING_NAME).lstat()
        return True
    except FileNotFoundError:
        return False


def _generation(meta: Path) -> WorkspaceGeneration:
    marker = meta / GENERATION_NAME
    token = ''
    descriptor = None
    try:
        descriptor = os.open(marker, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                             | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0))
        entry = os.fstat(descriptor)
        if not stat.S_ISREG(entry.st_mode) or entry.st_size > 129:
            raise _error('database_changed')
        token = os.read(descriptor, 130).decode('ascii').strip()
        if not _TOKEN.fullmatch(token):
            raise _error('database_changed')
    except FileNotFoundError:
        pass
    except (UnicodeError, OSError) as exc:
        raise _error('database_changed') from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        entry = (meta / 'workspace.db').lstat()
    except FileNotFoundError:
        return None, None, token
    if not stat.S_ISREG(entry.st_mode):
        raise _error('database_changed')
    return entry.st_dev, entry.st_ino, token


def workspace_generation(root: str | Path) -> WorkspaceGeneration:
    """Read a generation while the caller holds a shared or maintenance lease."""
    try:
        return _generation(_root(root) / '.harnessy')
    except OSError as exc:
        raise _error('filesystem_error') from exc


def owns_workspace_maintenance(root: str | Path) -> bool:
    """Require an actual live exclusive lease owned by this process."""
    root = _root(root)
    with _LEASE_LOCK:
        return any(lease.descriptor >= 0 and lease.exclusive
                   and lease._pid == os.getpid() and lease.root == root
                   for lease in _LEASES)


class WorkspaceAccessLease:
    def __init__(self, descriptor: int, root: Path, generation: WorkspaceGeneration,
                 *, exclusive: bool) -> None:
        self.descriptor = descriptor
        self.root = root
        self.generation = generation
        self.exclusive = exclusive
        self._pid = os.getpid()
        with _LEASE_LOCK:
            _LEASES.add(self)

    def close(self) -> None:
        with _LEASE_LOCK:
            descriptor, self.descriptor = self.descriptor, -1
            _LEASES.discard(self)
        if descriptor >= 0:
            # Closing (without explicit LOCK_UN) also remains safe in a forked
            # child: an inherited duplicate cannot unlock its parent's lease.
            os.close(descriptor)

    def __enter__(self) -> 'WorkspaceAccessLease':
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def _after_fork_child() -> None:
    try:
        for lease in list(_LEASES):
            lease.close()
    finally:
        _LEASE_LOCK.release()


if hasattr(os, 'register_at_fork'):
    os.register_at_fork(before=_LEASE_LOCK.acquire, after_in_parent=_LEASE_LOCK.release,
                        after_in_child=_after_fork_child)


def _acquire(root: str | Path, *, exclusive: bool, allow_pending: bool,
             expected_generation: WorkspaceGeneration | None,
             allow_missing: bool) -> WorkspaceAccessLease:
    # Register every opened descriptor before another thread can fork. The
    # at-fork hook then closes all child duplicates without unlocking parents.
    with _LEASE_LOCK:
        return _acquire_locked(root, exclusive=exclusive, allow_pending=allow_pending,
                               expected_generation=expected_generation, allow_missing=allow_missing)


def _acquire_locked(root: str | Path, *, exclusive: bool, allow_pending: bool,
                    expected_generation: WorkspaceGeneration | None,
                    allow_missing: bool) -> WorkspaceAccessLease:
    import fcntl

    root = _root(root)
    meta = root / '.harnessy'
    descriptor = None
    try:
        if not root.is_dir():
            raise _error('filesystem_error')
        meta.mkdir(exist_ok=True)
        info = meta.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise _error('invalid_file')
        path = meta / LOCK_NAME
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
                             | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0), 0o600)
        os.set_inheritable(descriptor, False)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or info.st_mode & 0o022):
            raise _error('invalid_file')
        try:
            fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise _error('maintenance') from None
        current_lock = path.lstat()
        if (info.st_dev, info.st_ino) != (current_lock.st_dev, current_lock.st_ino):
            raise _error('database_changed')
        if not allow_pending and _pending(meta):
            raise _error('recovery_pending')
        generation = _generation(meta)
        if (not allow_missing and generation[0] is None
                or expected_generation is not None and generation != expected_generation):
            raise _error('database_changed')
        lease = WorkspaceAccessLease(descriptor, root, generation, exclusive=exclusive)
        descriptor = None
        return lease
    except OSError as exc:
        raise _error('filesystem_error') from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def workspace_shared_access(root: str | Path, *,
                            expected_generation: WorkspaceGeneration | None = None,
                            allow_missing: bool = False) -> WorkspaceAccessLease:
    """Acquire immediately or report maintenance; never wait on the UI loop."""
    return _acquire(root, exclusive=False, allow_pending=False,
                    expected_generation=expected_generation, allow_missing=allow_missing)


def workspace_maintenance_access(root: str | Path, *, allow_pending: bool = False) -> WorkspaceAccessLease:
    """Require all normal connections/preparations to have released their leases."""
    return _acquire(root, exclusive=True, allow_pending=allow_pending,
                    expected_generation=None, allow_missing=True)


class WorkspaceConnection(StoreConnection):
    """A SQLite connection owns its shared lease through native close."""

    _workspace_lease: WorkspaceAccessLease | None = None

    def attach_workspace_lease(self, lease: WorkspaceAccessLease) -> None:
        self._workspace_lease = lease

    def cursor(self, *args: Any, **kwargs: Any):
        cursor = super().cursor(*args, **kwargs)
        registry = getattr(self, '_workspace_cursors', None)
        if registry is None:
            registry = self._workspace_cursors = {}
        identity = id(cursor)
        registry[identity] = weakref.ref(cursor, lambda _reference, rows=registry, key=identity: rows.pop(key, None))
        return cursor

    def close(self, *args: Any, **kwargs: Any) -> None:
        # sqlite3_close_v2 otherwise leaves the database/WAL descriptors alive
        # until unexhausted cursors are collected, even after Python considers
        # the connection closed. Finalize them before releasing maintenance.
        registry = getattr(self, '_workspace_cursors', {})
        for reference in list(registry.values()):
            cursor = reference()
            if cursor is not None:
                cursor.close()
        registry.clear()
        # Retain the lease if SQLite raises while closing. Maintenance must not
        # proceed while a potentially live native handle remains outstanding.
        super().close(*args, **kwargs)
        lease, self._workspace_lease = self._workspace_lease, None
        if lease is not None:
            lease.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
