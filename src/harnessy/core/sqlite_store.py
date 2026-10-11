"""SQLite lifetime and journal policy for Harnessy-owned persistent stores."""
from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from typing import Any

from ..diagnostics.sqlite import DiagnosticConnection, connect_database


class StoreConnection(DiagnosticConnection):
    """Commit/roll back like SQLite, then release the store's connection.

    The generic DiagnosticConnection deliberately retains SQLite's native
    context-manager behavior. Store methods own their short-lived connections,
    so their contexts must additionally close them, including on commit failure.
    A connection obtained without ``with`` still supports the ordinary raw API
    and remains the caller's responsibility to close.
    """

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> Any:
        pending_error = exc_type is not None
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        except BaseException:
            pending_error = True
            raise
        finally:
            try:
                self.close()
            except BaseException:
                # Never replace a body/commit exception with cleanup failure.
                if not pending_error:
                    raise


def enable_store_wal(connection: sqlite3.Connection) -> None:
    """Require persistent WAL once at store initialization, before transactions.

    Already-WAL databases need only a mode read, avoiding a mode-change lock on
    every open. Timeout, synchronous durability and checkpoint policy retain
    their SQLite defaults. WAL lets long transcript reads coexist with commits;
    other writers still obey SQLite's normal locking and exceptions.
    """
    try:
        with closing(connection.execute('PRAGMA journal_mode')) as cursor:
            current = str(cursor.fetchone()[0]).lower()
        if current == 'wal':
            return
        with closing(connection.execute('PRAGMA journal_mode=WAL')) as cursor:
            actual = str(cursor.fetchone()[0]).lower()
    except sqlite3.Error as exc:
        raise RuntimeError(
            'Cannot enable SQLite WAL for this Harnessy database. Close other '
            'applications using the database and reopen the workspace. The '
            'database must be on storage that supports SQLite WAL.'
        ) from exc
    if actual != 'wal':
        raise RuntimeError(
            'This Harnessy database cannot use SQLite WAL. Move the workspace '
            'to local storage that supports SQLite WAL before opening it.'
        )


def backup_legacy_store_database(source: Path, destination: Path) -> None:
    """Import a coherent database including committed, uncheckpointed WAL rows.

    The legacy database and its sidecars stay untouched. Only a completed,
    closed SQLite backup is installed at the new machine-state path; a failed
    import leaves no partial copied database behind.
    """
    descriptor, temporary_name = tempfile.mkstemp(
        prefix='.machine-import-', suffix='.db', dir=destination.parent,
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    deadline = time.monotonic() + 5.0

    def progress(_status: int, _remaining: int, _total: int) -> None:
        if time.monotonic() > deadline:
            raise TimeoutError('Legacy database import remained busy; no database was installed.')

    try:
        with closing(connect_database(source.resolve().as_uri() + '?mode=ro', role='machine', uri=True)) as old:
            with closing(connect_database(temporary, role='machine')) as new:
                old.backup(new, pages=128, progress=progress, sleep=.01)
        try:
            # Both files share a directory/filesystem. Installing without
            # replacement also protects a concurrent first opener's live DB
            # and sidecars after it wins the initial existence-check race.
            os.link(temporary, destination)
        except FileExistsError:
            pass
    finally:
        for path in (temporary, Path(str(temporary) + '-wal'), Path(str(temporary) + '-shm')):
            path.unlink(missing_ok=True)
