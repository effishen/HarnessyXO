"""Content-free SQLite timing and transaction evidence.

The registry identifies possible holders in this process, not the owner of an
SQLite lock. Other processes and uninstrumented connections remain unknown.
Recording never uses the application's SQLite database and cannot change the
outcome of a database operation.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import os
import re
import sqlite3
import threading
import time
import uuid
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlsplit

from .logging import log_event

_REGISTRY_LIMIT = 256
_CANDIDATE_LIMIT = 16
_RESULT_CURSOR_LIMIT = 32
_SLOW_OPERATION_MS = 100.0
_REGISTRY_LOCK = threading.RLock()
_REGISTRY: OrderedDict[str, '_ConnectionRecord'] = OrderedDict()
_REGISTRY_EVICTIONS = 0
_ROLES = frozenset({'workspace', 'machine', 'other'})
_JOURNALS = frozenset({'delete', 'truncate', 'persist', 'memory', 'wal', 'off', 'unknown'})
_BEGIN_MODES = frozenset({'IMPLICIT', 'DEFERRED', 'IMMEDIATE', 'EXCLUSIVE', 'UNKNOWN'})
_STATEMENTS = frozenset({
    'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'WITH', 'BEGIN', 'COMMIT',
    'END', 'ROLLBACK', 'SAVEPOINT', 'RELEASE', 'CREATE', 'ALTER', 'DROP',
    'PRAGMA', 'VACUUM', 'ATTACH', 'DETACH', 'ANALYZE', 'REINDEX', 'OTHER', 'NONE',
})
_WRITES = frozenset({'INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'CREATE', 'ALTER', 'DROP'})
_OPERATIONS = frozenset({
    'connect', 'execute', 'executemany', 'executescript', 'fetchone', 'fetchmany',
    'fetchall', 'cursor_next', 'cursor_close', 'commit', 'rollback', 'context_exit', 'close', 'backup',
})
_EVENTS = frozenset({
    'sqlite_connection_opened', 'sqlite_operation_slow', 'sqlite_operation_error',
    'sqlite_transaction_started', 'sqlite_transaction_finished', 'sqlite_connection_closed',
})
_SQLITE_ERROR_NAMES = frozenset(name for name in vars(sqlite3)
                               if name.startswith('SQLITE_') and isinstance(getattr(sqlite3, name), int))


@dataclass
class _ConnectionRecord:
    connection_id: str
    db_id: str
    db_role: str
    reference: Any = None
    busy_timeout_ms: int | None = None
    journal_mode: str = 'unknown'
    pid: int = field(default_factory=os.getpid)
    thread_id: int = field(default_factory=threading.get_ident)
    task_id: str | None = None
    in_transaction: bool = False
    transaction_id: str | None = None
    transaction_started_ns: int | None = None
    transaction_origin: dict[str, Any] | None = None
    transaction_pid: int | None = None
    transaction_thread_id: int | None = None
    transaction_task_id: str | None = None
    begin_mode: str = 'UNKNOWN'
    write_attempted: bool = False
    last_operation_origin: dict[str, Any] | None = None
    last_statement_kind: str = 'NONE'
    current_operation: str | None = None
    current_operation_started_ns: int | None = None
    result_cursors: OrderedDict[str, tuple[Any, int, dict[str, Any] | None]] = field(default_factory=OrderedDict)
    result_cursor_registry_truncated: bool = False
    closed: bool = False


def _task_identity() -> str | None:
    try:
        task = asyncio.current_task()
    except RuntimeError:
        return None
    if task is None:
        return None
    # Task names can contain user text, so only a process-local hash is retained.
    return hashlib.sha256(f'{os.getpid()}:{id(task)}'.encode('ascii')).hexdigest()


def _caller_origin() -> dict[str, Any] | None:
    frame = inspect.currentframe()
    try:
        frame = frame.f_back if frame else None
        while frame is not None:
            if frame.f_globals.get('__name__') != __name__:
                from .faults import frame_evidence
                return frame_evidence(frame)
            frame = frame.f_back
    except Exception:
        return None
    finally:
        del frame
    return None


def _fault(exc: BaseException) -> dict[str, Any] | None:
    try:
        from .faults import exception_evidence
        return exception_evidence(exc)
    except Exception:
        return None


def _statement_kind(sql: Any) -> tuple[str, str]:
    if not isinstance(sql, str):
        return 'OTHER', 'UNKNOWN'
    # Inspect only a bounded prefix. The result contains fixed keywords, never
    # the SQL prefix, identifiers, literals, or parameters.
    prefix = sql[:2048]
    prefix = re.sub(r'\A(?:\s+|--[^\n]*(?:\n|$)|/\*[\s\S]*?\*/)*', '', prefix)
    match = re.match(r'([A-Za-z]+)', prefix)
    token = match.group(1).upper() if match else 'OTHER'
    kind = token if token in _STATEMENTS else 'OTHER'
    mode = 'UNKNOWN'
    if kind == 'BEGIN':
        rest = prefix[match.end():] if match else ''
        words = re.findall(r'[A-Za-z]+', rest[:64].upper())
        mode = next((word for word in words if word in {'DEFERRED', 'IMMEDIATE', 'EXCLUSIVE'}), 'DEFERRED')
    return kind, mode


def _database_identity(database: Any, *, uri: bool = False) -> str:
    try:
        text = os.fsdecode(os.fspath(database))
        if text == ':memory:':
            text = ':private-memory:' + uuid.uuid4().hex
        elif uri and text.startswith('file:'):
            parts = urlsplit(text)
            options = parse_qs(parts.query)
            if parts.path == ':memory:' or options.get('mode') == ['memory']:
                text = unquote(parts.path)
                if options.get('cache') != ['shared']:
                    text += ':private-memory:' + uuid.uuid4().hex
                else:
                    text += ':shared-memory:'
            elif parts.netloc in {'', 'localhost'}:
                text = str(Path(unquote(parts.path)).expanduser().resolve())
        elif not text.startswith('file:'):
            text = str(Path(text).expanduser().resolve())
    except Exception:
        text = type(database).__name__
    return hashlib.sha256(('harnessyxo-sqlite-v1\0' + text).encode('utf-8', errors='surrogatepass')).hexdigest()


def _record_fields(record: _ConnectionRecord, now: int | None = None) -> dict[str, Any]:
    now = time.monotonic_ns() if now is None else now
    cursors = [item for item in record.result_cursors.values() if item[0]() is not None]
    oldest = min(cursors, key=lambda item: item[1]) if cursors else None
    return {
        'schema_version': 1, 'db_id': record.db_id, 'db_role': record.db_role,
        'connection_id': record.connection_id, 'pid': record.pid,
        'thread_id': record.thread_id, 'task_id': record.task_id,
        'monotonic_ns': now, 'busy_timeout_ms': record.busy_timeout_ms,
        'journal_mode': record.journal_mode, 'in_transaction': record.in_transaction,
        'transaction_id': record.transaction_id,
        'transaction_pid': record.transaction_pid, 'transaction_thread_id': record.transaction_thread_id,
        'transaction_task_id': record.transaction_task_id,
        'transaction_age_ms': round((now - record.transaction_started_ns) / 1_000_000, 3)
        if record.transaction_started_ns is not None else None,
        'begin_mode': record.begin_mode, 'write_attempted': record.write_attempted,
        'transaction_origin': record.transaction_origin,
        'last_operation_origin': record.last_operation_origin,
        'last_statement_kind': record.last_statement_kind,
        'current_operation': record.current_operation,
        'current_operation_elapsed_ms': round((now - record.current_operation_started_ns) / 1_000_000, 3)
        if record.current_operation_started_ns is not None else None,
        'open_result_cursor_count': len(cursors),
        'result_cursor_registry_truncated': record.result_cursor_registry_truncated,
        'oldest_result_cursor_age_ms': round((now - oldest[1]) / 1_000_000, 3) if oldest else None,
        'oldest_result_cursor_origin': oldest[2] if oldest else None,
    }


def _emit(event: str, record: _ConnectionRecord, **extra: Any) -> None:
    try:
        with _REGISTRY_LOCK:
            fields = _record_fields(record)
        fields.update(extra)
        fields['observed_at'] = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
        log_event('database', event, **fields)
    except Exception:
        # Failure to write diagnostics must never fail a successful transaction
        # or replace the original SQLite exception.
        pass


def _remove_connection(connection_id: str) -> None:
    with _REGISTRY_LOCK:
        _REGISTRY.pop(connection_id, None)


def _candidate_holders(record: _ConnectionRecord) -> tuple[list[dict[str, Any]], bool]:
    with _REGISTRY_LOCK:
        holders = [item for item in _REGISTRY.values()
                   if item.connection_id != record.connection_id
                   and item.db_id == record.db_id and not item.closed
                   and (item.in_transaction or item.result_cursors or item.current_operation is not None)]
        # A write attempt is useful evidence, but does not establish lock ownership.
        holders.sort(key=lambda item: (not item.write_attempted, item.transaction_started_ns or 0))
        now = time.monotonic_ns()
        evidence = []
        for item in holders[:_CANDIDATE_LIMIT]:
            fields = _record_fields(item, now)
            fields['candidate_kind'] = ('transaction' if item.in_transaction else 'open_result_cursor'
                                        if fields['open_result_cursor_count'] else 'active_operation')
            evidence.append(fields)
        return evidence, len(holders) > _CANDIDATE_LIMIT


def snapshot_database_connections() -> dict[str, Any]:
    """Return a bounded, content-free view for an exported diagnostics bundle."""
    with _REGISTRY_LOCK:
        now = time.monotonic_ns()
        records = [_record_fields(item, now) for item in _REGISTRY.values()
                   if not item.closed and item.reference is not None and item.reference() is not None]
        return {
            'schema_version': 1, 'observed_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'sqlite_version': sqlite3.sqlite_version, 'sqlite_threadsafety': sqlite3.threadsafety,
            'registry_limit': _REGISTRY_LIMIT, 'registry_evictions': _REGISTRY_EVICTIONS,
            'connections': records, 'candidate_scope': 'tracked_same_process_connections',
            'external_holder_unknown': True,
        }


class DiagnosticCursor(sqlite3.Cursor):
    def _result_cursor_state(self, operation: str, result: Any, exhausted: bool, sql: Any) -> None:
        connection = self.connection
        record = getattr(connection, '_diagnostic_record', None)
        if record is None:
            return
        identity = getattr(self, '_diagnostic_cursor_id', None)
        with _REGISTRY_LOCK:
            if identity is not None and (sql is not None or exhausted or operation in {'fetchall', 'cursor_close'}):
                record.result_cursors.pop(identity, None)
            if operation in {'execute', 'executemany', 'executescript'} and self.description is not None:
                identity = uuid.uuid4().hex
                self._diagnostic_cursor_id = identity
                def remove(ref: Any, owner: _ConnectionRecord = record, cursor_id: str = identity) -> None:
                    with _REGISTRY_LOCK:
                        owner.result_cursors.pop(cursor_id, None)
                record.result_cursors[identity] = (weakref.ref(self, remove), time.monotonic_ns(), _caller_origin())
                while len(record.result_cursors) > _RESULT_CURSOR_LIMIT:
                    record.result_cursors.popitem(last=False)
                    record.result_cursor_registry_truncated = True

    def _perform(self, operation: str, call: Callable[[], Any], sql: Any = None) -> Any:
        connection = self.connection
        if not isinstance(connection, DiagnosticConnection):
            return call()
        if sql is not None:
            self._diagnostic_kind, self._diagnostic_mode = _statement_kind(sql)
        try:
            result = connection._perform(
                operation, call, getattr(self, '_diagnostic_kind', 'NONE'),
                getattr(self, '_diagnostic_mode', 'UNKNOWN'),
            )
        except StopIteration:
            try:
                self._result_cursor_state(operation, None, True, sql)
            except Exception:
                pass
            raise
        else:
            try:
                exhausted = operation == 'fetchone' and result is None or operation == 'fetchmany' and not result
                self._result_cursor_state(operation, result, exhausted, sql)
            except Exception:
                pass
            return result

    def execute(self, *args: Any, **kwargs: Any) -> 'DiagnosticCursor':
        return self._perform('execute', lambda: super(DiagnosticCursor, self).execute(*args, **kwargs),
                             args[0] if args else kwargs.get('sql'))

    def executemany(self, *args: Any, **kwargs: Any) -> 'DiagnosticCursor':
        return self._perform('executemany', lambda: super(DiagnosticCursor, self).executemany(*args, **kwargs),
                             args[0] if args else kwargs.get('sql'))

    def executescript(self, *args: Any, **kwargs: Any) -> 'DiagnosticCursor':
        return self._perform('executescript', lambda: super(DiagnosticCursor, self).executescript(*args, **kwargs),
                             args[0] if args else kwargs.get('sql_script'))

    def fetchone(self, *args: Any, **kwargs: Any) -> Any:
        return self._perform('fetchone', lambda: super(DiagnosticCursor, self).fetchone(*args, **kwargs))

    def fetchmany(self, *args: Any, **kwargs: Any) -> Any:
        return self._perform('fetchmany', lambda: super(DiagnosticCursor, self).fetchmany(*args, **kwargs))

    def fetchall(self, *args: Any, **kwargs: Any) -> Any:
        return self._perform('fetchall', lambda: super(DiagnosticCursor, self).fetchall(*args, **kwargs))

    def __next__(self) -> Any:
        return self._perform('cursor_next', lambda: super(DiagnosticCursor, self).__next__())

    def close(self, *args: Any, **kwargs: Any) -> None:
        return self._perform('cursor_close', lambda: super(DiagnosticCursor, self).close(*args, **kwargs))


class DiagnosticConnection(sqlite3.Connection):
    def _setup_diagnostics(self, database: Any, role: str, *, uri: bool = False) -> None:
        global _REGISTRY_EVICTIONS
        record = _ConnectionRecord(uuid.uuid4().hex, _database_identity(database, uri=uri),
                                   role if role in _ROLES else 'other', task_id=_task_identity())
        self._diagnostic_record = record
        record.reference = weakref.ref(self, lambda ref, identity=record.connection_id: _remove_connection(identity))
        # These reads use the base implementation to avoid recursion. Inspecting
        # journal_mode can itself need a lock; a temporary zero timeout prevents
        # this optional observation from introducing a second blocking wait.
        try:
            row = sqlite3.Connection.execute(self, 'PRAGMA busy_timeout').fetchone()
            record.busy_timeout_ms = int(row[0]) if row is not None else None
            if record.busy_timeout_ms is not None:
                sqlite3.Connection.execute(self, 'PRAGMA busy_timeout=0')
                try:
                    row = sqlite3.Connection.execute(self, 'PRAGMA journal_mode').fetchone()
                    mode = str(row[0]).lower() if row is not None else 'unknown'
                    record.journal_mode = mode if mode in _JOURNALS else 'unknown'
                finally:
                    sqlite3.Connection.execute(self, f'PRAGMA busy_timeout={record.busy_timeout_ms}')
        except Exception:
            pass
        with _REGISTRY_LOCK:
            _REGISTRY[record.connection_id] = record
            while len(_REGISTRY) > _REGISTRY_LIMIT:
                _REGISTRY.popitem(last=False)
                _REGISTRY_EVICTIONS += 1
        _emit('sqlite_connection_opened', record, operation='connect', operation_origin=_caller_origin(), elapsed_ms=0.0)

    def _transaction_state(self) -> bool:
        try:
            return bool(self.in_transaction)
        except sqlite3.ProgrammingError:
            return False

    def _perform(self, operation: str, call: Callable[[], Any], kind: str = 'NONE', mode: str = 'UNKNOWN') -> Any:
        record = getattr(self, '_diagnostic_record', None)
        if record is None:
            return call()
        origin = _caller_origin()
        started = time.monotonic_ns()
        before = self._transaction_state()
        with _REGISTRY_LOCK:
            record.pid, record.thread_id, record.task_id = os.getpid(), threading.get_ident(), _task_identity()
            record.last_operation_origin = origin
            record.last_statement_kind = kind
            record.current_operation, record.current_operation_started_ns = operation, started
            transaction_id_before = record.transaction_id
            transaction_age_ms_before = round((started - record.transaction_started_ns) / 1_000_000, 3) \
                if record.transaction_started_ns is not None else None
        error: BaseException | None = None
        try:
            return call()
        except BaseException as exc:
            error = exc
            raise
        finally:
            try:
                self._finish_diagnostics(record, operation, kind, mode, origin, started, before,
                                         error, transaction_id_before, transaction_age_ms_before)
            except Exception:
                # Even a failed diagnostic snapshot must preserve the database
                # result, including the exact original SQLite exception object.
                pass

    def _finish_diagnostics(
        self, record: _ConnectionRecord, operation: str, kind: str, mode: str,
        origin: dict[str, Any] | None, started: int, before: bool,
        error: BaseException | None, transaction_id_before: str | None,
        transaction_age_ms_before: float | None,
    ) -> None:
        ended = time.monotonic_ns()
        elapsed = round((ended - started) / 1_000_000, 3)
        after = self._transaction_state()
        transaction_started = False
        finished: dict[str, Any] | None = None
        with _REGISTRY_LOCK:
            record.in_transaction = after
            if after and not before:
                record.transaction_id = uuid.uuid4().hex
                record.transaction_started_ns = started
                record.transaction_origin = origin
                record.transaction_pid = record.pid
                record.transaction_thread_id = record.thread_id
                record.transaction_task_id = record.task_id
                record.begin_mode = mode if kind == 'BEGIN' else 'IMPLICIT'
                record.write_attempted = kind in _WRITES
                transaction_started = True
            elif after and kind in _WRITES:
                record.write_attempted = True
            elif before and not after:
                finished = {
                    'transaction_id': record.transaction_id,
                    'transaction_age_ms': round((ended - record.transaction_started_ns) / 1_000_000, 3)
                    if record.transaction_started_ns is not None else None,
                    'transaction_origin': record.transaction_origin,
                    'transaction_pid': record.transaction_pid,
                    'transaction_thread_id': record.transaction_thread_id,
                    'transaction_task_id': record.transaction_task_id,
                    'begin_mode': record.begin_mode,
                    'write_attempted': record.write_attempted,
                }
                record.transaction_id = None
                record.transaction_started_ns = None
                record.transaction_origin = None
                record.transaction_pid = record.transaction_thread_id = record.transaction_task_id = None
                record.begin_mode, record.write_attempted = 'UNKNOWN', False
            record.current_operation = None
            record.current_operation_started_ns = None
        common = {'operation': operation, 'statement_kind': kind, 'operation_origin': origin, 'elapsed_ms': elapsed}
        if transaction_started:
            _emit('sqlite_transaction_started', record, **common)
        if finished is not None:
            _emit('sqlite_transaction_finished', record, **common, **finished,
                  end_reason='failed_operation' if error is not None else operation)
        if error is not None and not isinstance(error, StopIteration):
            holders, truncated = _candidate_holders(record)
            code = getattr(error, 'sqlite_errorcode', None)
            name = getattr(error, 'sqlite_errorname', None)
            _emit('sqlite_operation_error', record, **common, exception_evidence=_fault(error),
                  in_transaction_before=before, transaction_id_before=transaction_id_before,
                  transaction_age_ms_before=transaction_age_ms_before,
                  sqlite_errorcode=code if isinstance(code, int) else None,
                  sqlite_errorname=name if isinstance(name, str) and name in _SQLITE_ERROR_NAMES else None,
                  candidate_holders=holders, candidate_holders_truncated=truncated,
                  candidate_scope='tracked_same_process_connections', external_holder_unknown=True)
        elif elapsed >= _SLOW_OPERATION_MS:
            _emit('sqlite_operation_slow', record, **common)
        if operation == 'close' and error is None:
            record.closed = True
            record.result_cursors.clear()
            _remove_connection(record.connection_id)
            _emit('sqlite_connection_closed', record, **common)

    def cursor(self, factory: Any = DiagnosticCursor) -> sqlite3.Cursor:
        return super().cursor(factory)

    def execute(self, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        return self.cursor().execute(*args, **kwargs)

    def executemany(self, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        return self.cursor().executemany(*args, **kwargs)

    def executescript(self, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        return self.cursor().executescript(*args, **kwargs)

    def commit(self, *args: Any, **kwargs: Any) -> None:
        return self._perform('commit', lambda: super(DiagnosticConnection, self).commit(*args, **kwargs))

    def rollback(self, *args: Any, **kwargs: Any) -> None:
        return self._perform('rollback', lambda: super(DiagnosticConnection, self).rollback(*args, **kwargs))

    def __exit__(self, *args: Any, **kwargs: Any) -> Any:
        return self._perform('context_exit', lambda: super(DiagnosticConnection, self).__exit__(*args, **kwargs))

    def close(self, *args: Any, **kwargs: Any) -> None:
        return self._perform('close', lambda: super(DiagnosticConnection, self).close(*args, **kwargs))

    def backup(self, *args: Any, **kwargs: Any) -> None:
        return self._perform('backup', lambda: super(DiagnosticConnection, self).backup(*args, **kwargs))


def connect_database(database: Any, *, role: str = 'other', **kwargs: Any) -> sqlite3.Connection:
    """Connect with the same SQLite settings and exceptions as sqlite3.connect."""
    kwargs.setdefault('factory', DiagnosticConnection)
    started = time.monotonic_ns()
    try:
        connection = sqlite3.connect(database, **kwargs)
    except BaseException as exc:
        record = _ConnectionRecord(uuid.uuid4().hex, _database_identity(database, uri=bool(kwargs.get('uri'))),
                                   role if role in _ROLES else 'other', task_id=_task_identity())
        _emit('sqlite_operation_error', record, operation='connect', statement_kind='NONE',
              operation_origin=_caller_origin(), elapsed_ms=round((time.monotonic_ns() - started) / 1_000_000, 3),
              exception_evidence=_fault(exc), sqlite_errorcode=getattr(exc, 'sqlite_errorcode', None),
              sqlite_errorname=getattr(exc, 'sqlite_errorname', None), candidate_holders=[],
              candidate_holders_truncated=False, candidate_scope='tracked_same_process_connections',
              external_holder_unknown=True)
        raise
    if isinstance(connection, DiagnosticConnection):
        try:
            connection._setup_diagnostics(database, role, uri=bool(kwargs.get('uri')))
        except Exception:
            pass
    return connection


def _validated_fields(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {}
    integer_keys = {'schema_version', 'pid', 'thread_id', 'monotonic_ns', 'busy_timeout_ms', 'sqlite_errorcode',
                    'transaction_pid', 'transaction_thread_id', 'open_result_cursor_count'}
    number_keys = {'elapsed_ms', 'transaction_age_ms', 'current_operation_elapsed_ms', 'transaction_age_ms_before',
                   'oldest_result_cursor_age_ms'}
    bool_keys = {'in_transaction', 'in_transaction_before', 'write_attempted', 'candidate_holders_truncated',
                 'external_holder_unknown', 'result_cursor_registry_truncated'}
    for key in integer_keys:
        item = value.get(key)
        if isinstance(item, int) and not isinstance(item, bool) and 0 <= item < 2**64:
            result[key] = item
        elif item is None and key in {'busy_timeout_ms', 'sqlite_errorcode', 'transaction_pid', 'transaction_thread_id'}:
            result[key] = None
    for key in number_keys:
        item = value.get(key)
        if isinstance(item, (int, float)) and not isinstance(item, bool) and 0 <= item < 1e15:
            result[key] = item
        elif item is None:
            result[key] = None
    for key in bool_keys:
        if isinstance(value.get(key), bool):
            result[key] = value[key]
    for key, length in {'db_id': 64, 'task_id': 64, 'connection_id': 32, 'transaction_id': 32,
                        'transaction_id_before': 32, 'transaction_task_id': 64}.items():
        item = value.get(key)
        if isinstance(item, str) and re.fullmatch(r'[0-9a-f]{' + str(length) + '}', item):
            result[key] = item
        elif item is None and key in {'task_id', 'transaction_id', 'transaction_id_before', 'transaction_task_id'}:
            result[key] = None
    enums = {'db_role': _ROLES, 'journal_mode': _JOURNALS, 'operation': _OPERATIONS,
             'current_operation': _OPERATIONS, 'begin_mode': _BEGIN_MODES,
             'statement_kind': _STATEMENTS, 'last_statement_kind': _STATEMENTS,
             'end_reason': _OPERATIONS | {'failed_operation'},
             'candidate_kind': {'transaction', 'open_result_cursor', 'active_operation'},
             'candidate_scope': {'tracked_same_process_connections'}}
    for key, options in enums.items():
        if isinstance(value.get(key), str) and value[key] in options:
            result[key] = value[key]
        elif value.get(key) is None and key == 'current_operation':
            result[key] = None
    item = value.get('sqlite_errorname')
    if isinstance(item, str) and item in _SQLITE_ERROR_NAMES:
        result['sqlite_errorname'] = item
    elif item is None:
        result['sqlite_errorname'] = None
    for key in ('operation_origin', 'transaction_origin', 'last_operation_origin', 'oldest_result_cursor_origin'):
        try:
            from .faults import validate_frame_evidence
            evidence = validate_frame_evidence(value.get(key))
        except Exception:
            evidence = None
        if evidence is not None:
            result[key] = evidence
        elif value.get(key) is None:
            result[key] = None
    try:
        from .faults import validate_fault_evidence
        evidence = validate_fault_evidence(value.get('exception_evidence'))
        if evidence is not None:
            result['exception_evidence'] = evidence
    except Exception:
        pass
    item = value.get('observed_at')
    if isinstance(item, str) and len(item) <= 40:
        try:
            stamp = datetime.fromisoformat(item)
            if stamp.tzinfo is not None:
                result['observed_at'] = stamp.isoformat()
        except ValueError:
            pass
    # Logger session IDs are generated timestamps or UUIDs, never arbitrary names.
    item = value.get('session_id')
    if isinstance(item, str) and (re.fullmatch(r'[0-9a-fA-F-]{8,64}', item)
                                 or re.fullmatch(r'\d{4}-\d{2}-\d{2}_\d{6}(?:_\d{1,6})?', item)):
        result['session_id'] = item
    return result


def validate_database_event(event: Any, payload: Any) -> dict[str, Any] | None:
    """Strict allowlist used during collection, including full-content exports."""
    if not isinstance(event, str) or event not in _EVENTS or not isinstance(payload, dict):
        return None
    result = _validated_fields(payload)
    if not all(key in result for key in ('db_id', 'db_role', 'connection_id')):
        return None
    if isinstance(payload.get('candidate_holders'), list):
        candidates = [_validated_fields(item) for item in payload['candidate_holders'][:_CANDIDATE_LIMIT]]
        result['candidate_holders'] = [item for item in candidates
                                       if all(key in item for key in ('db_id', 'db_role', 'connection_id'))]
    result['event'] = event
    return result


def validate_database_snapshot(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get('schema_version') != 1:
        return None
    result = {key: item for key, item in _validated_fields(value).items()
              if key in {'schema_version', 'observed_at', 'candidate_scope', 'external_holder_unknown'}}
    for key in ('registry_limit', 'registry_evictions', 'sqlite_threadsafety'):
        item = value.get(key)
        if isinstance(item, int) and not isinstance(item, bool) and 0 <= item < 2**64:
            result[key] = item
    version = value.get('sqlite_version')
    if isinstance(version, str) and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version):
        result['sqlite_version'] = version
    connections = value.get('connections')
    if not isinstance(connections, list):
        return None
    rows = [_validated_fields(item) for item in connections[:_REGISTRY_LIMIT]]
    result['connections'] = [item for item in rows
                             if all(key in item for key in ('db_id', 'db_role', 'connection_id'))]
    return result
