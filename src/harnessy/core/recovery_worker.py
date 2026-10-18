"""Copy-only SQLite recovery algorithms and isolated worker entry point.

Adapted from the privately verified standalone recovery helper. Application
coordination, permissions, activation and lifecycle state live in the manager.
"""
from __future__ import annotations


import argparse

import ast

import errno

import hashlib

import json

import os

from pathlib import Path

import re

import shutil

import signal

import sqlite3

import stat

import subprocess

import sys

import tempfile

import time

import uuid
import threading
from contextlib import contextmanager

VERSION = '1.0.0'

SIDECARS = ('', '-wal', '-shm', '-journal')

TABLES = frozenset('''chats chat_output_owners chat_output_id_migrations messages
message_bubble_bookmarks memory workspace_state jobs artifacts attachments
memory_events generation_metrics subagent_metrics instruction_documents
chat_task_state history_checkpoints file_history_snapshots chat_branches
timeline_rewinds rewind_undo_transactions branch_memory_scopes branch_memory
project_memory_provenance project_dependencies project_access_grants
project_revisions project_upstream_baselines archived_families archived_projects
external_targets external_target_events'''.split())

SAFE_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,127}$')

_LOCAL = threading.local()

class RecoveryError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class RecoveryCancelled(RecoveryError):
    def __init__(self):
        super().__init__('cancelled', 'Workspace recovery was cancelled. Original database files were not replaced.')


def check_cancel() -> None:
    event = getattr(_LOCAL, 'cancel_event', None)
    if event is not None and event.is_set():
        raise RecoveryCancelled()


def private_mkdir(path: Path) -> None:
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)


@contextmanager
def operation_context(progress=None, cancel_event=None):
    old = (getattr(_LOCAL, 'progress', None), getattr(_LOCAL, 'cancel_event', None))
    _LOCAL.progress, _LOCAL.cancel_event = progress, cancel_event
    try:
        yield
    finally:
        _LOCAL.progress, _LOCAL.cancel_event = old

def log(action: str, message: str) -> None:
    check_cancel()
    for line in str(message).replace('\r', '\n').splitlines():
        print(f'[{int(time.time())}] {action} {line}', flush=True)
        callback = getattr(_LOCAL, 'progress', None)
        if callback is not None:
            callback(action, line)

def signature(path: Path):
    try:
        entry = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1:
        raise RecoveryError('unsafe_file', f'Expected a real, unshared regular file: {path}')
    return (entry.st_dev, entry.st_ino, entry.st_size, entry.st_mtime_ns, entry.st_ctime_ns)

def digest(path: Path) -> str:
    before = signature(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    result = hashlib.sha256()
    processed = 0
    last = time.monotonic()
    try:
        value = os.fstat(descriptor)
        if before[:2] != (value.st_dev, value.st_ino):
            raise RecoveryError('source_changed', f'File identity changed: {path}')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            while block := stream.read(1024 * 1024):
                check_cancel()
                result.update(block)
                processed += len(block)
                if time.monotonic() - last >= 5:
                    log('READ', f'Hashing {path}: {processed:,}/{before[2]:,} bytes')
                    last = time.monotonic()
    finally:
        os.close(descriptor)
    if signature(path) != before:
        raise RecoveryError('source_changed', f'File changed while hashing: {path}')
    return result.hexdigest()

def write_json(path: Path, value) -> None:
    log('WRITE', f'Content-free report: {path}')
    temporary = path.with_suffix(path.suffix + '.partial')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)

def original_files(workspace: Path) -> dict[str, Path]:
    base = workspace / '.harnessy' / 'workspace.db'
    result = {}
    for suffix in SIDECARS:
        path = Path(str(base) + suffix)
        if signature(path) is not None:
            result[path.name] = path
    metadata = base.with_name('workspace.json')
    if signature(base) is None or signature(metadata) is None:
        raise RecoveryError('workspace_missing', f'workspace.db and workspace.json must both exist: {base.parent}')
    result[metadata.name] = metadata
    return result

def preserve(files: dict[str, Path], destination: Path, proof: dict) -> dict:
    destination.mkdir(mode=0o700)
    before = {name: signature(path) for name, path in files.items()}
    for name, source in files.items():
        target = destination / name
        log('READ', f'Hashing original, read-only: {source}')
        source_hash = digest(source)
        proof[name] = {'source': str(source), 'preserved_copy': str(target), 'bytes': before[name][2],
                       'sha256': source_hash, 'verified': False}
        log('COPY', f'{source} -> {target} ({before[name][2]:,} bytes)')
        source_fd = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        target_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        copied = 0
        last = time.monotonic()
        try:
            with os.fdopen(source_fd, 'rb', closefd=False) as incoming, os.fdopen(target_fd, 'wb', closefd=False) as outgoing:
                while block := incoming.read(1024 * 1024):
                    check_cancel()
                    outgoing.write(block)
                    copied += len(block)
                    if time.monotonic() - last >= 5:
                        log('COPY', f'{source} -> {target}: {copied:,}/{before[name][2]:,} bytes')
                        last = time.monotonic()
                outgoing.flush()
                os.fsync(target_fd)
        finally:
            os.close(source_fd)
            os.close(target_fd)
        target_hash = digest(target)
        if source_hash != target_hash or signature(source) != before[name]:
            raise RecoveryError('source_changed', f'Preservation verification failed; leave originals untouched and retry after stopping writers: {source}')
        proof[name] = {'source': str(source), 'preserved_copy': str(target), 'bytes': copied,
                       'sha256': source_hash, 'copy_sha256': target_hash, 'verified': True}
        log('VERIFY', f'Original and preservation copy SHA-256 match: {source} -> {target}')
    if before != {name: signature(path) for name, path in files.items()}:
        raise RecoveryError('source_changed', 'Workspace files changed during preservation. No original was opened by SQLite.')
    return proof

def working_copy(preserved: Path, target: Path) -> Path:
    private_mkdir(target)
    for source in preserved.iterdir():
        if source.name.startswith('workspace.db'):
            destination = target / source.name
            log('COPY', f'Preservation copy -> disposable working copy: {source} -> {destination}')
            destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
            with source.open('rb') as incoming, os.fdopen(destination_fd, 'wb') as outgoing:
                copied = 0
                total = source.stat().st_size
                last = time.monotonic()
                while block := incoming.read(1024 * 1024):
                    check_cancel()
                    outgoing.write(block)
                    copied += len(block)
                    if time.monotonic() - last >= 5:
                        log('COPY', f'{source} -> {destination}: {copied:,}/{total:,} bytes')
                        last = time.monotonic()
                outgoing.flush()
                os.fsync(outgoing.fileno())
            if digest(source) != digest(destination):
                raise RecoveryError('copy_failed', f'Working-copy verification failed: {destination}')
    return target / 'workspace.db'

def stop_child(process) -> None:
    if process is None:
        return
    # A crashed leader may leave a live SQLite CLI descendant in its group.
    # This exact group was created and retained by this helper, not a user VM.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        try:
            process.wait(timeout=.5)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass

def run_worker(stage: str, request: dict, directory: Path, timeout: float) -> dict:
    private_mkdir(directory)
    request_path = directory / f'{stage}-request.json'
    result_path = directory / f'{stage}-result.json'
    write_json(request_path, request)
    log('CHECK' if stage == 'inspect' else 'DERIVE', f'Starting {stage} on private copies; maximum {timeout:g}s: {directory}')
    command = [sys.executable, '-I', '-u', str(Path(__file__).resolve()), '--worker', stage,
               str(request_path), str(result_path), str(timeout)]
    started = time.monotonic()
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
                               cwd=directory, umask=0o077)
    try:
        while process.poll() is None:
            check_cancel()
            elapsed = time.monotonic() - started
            if elapsed >= timeout:
                stop_child(process)
                return {'worker_status': 'timed_out', 'stage': stage, 'elapsed_seconds': round(elapsed, 3)}
            try:
                process.wait(timeout=min(.2, timeout - elapsed))
            except subprocess.TimeoutExpired:
                elapsed_now = time.monotonic() - started
                if int(elapsed_now // 5) > int(elapsed // 5):
                    log('CHECK', f'{stage} still running on private copies: {directory}; elapsed {elapsed_now:.0f}s')
        if process.returncode:
            code = process.returncode
            return {'worker_status': 'failed', 'stage': stage, 'returncode': code,
                    'signal': signal.Signals(-code).name if code < 0 and -code in signal.valid_signals() else 'none',
                    'elapsed_seconds': round(time.monotonic() - started, 3)}
        if not result_path.is_file() or result_path.stat().st_size > 2 * 1024 * 1024:
            return {'worker_status': 'protocol_error', 'stage': stage}
        result = json.loads(result_path.read_text('utf-8'))
        result.update(worker_status='completed', stage=stage,
                      elapsed_seconds=round(time.monotonic() - started, 3))
        log('VERIFY', f'{stage} completed on private copies in {result["elapsed_seconds"]:.3f}s: {directory}')
        return result
    finally:
        stop_child(process)

def schema_template(app: Path, target: Path) -> dict:
    choices = [app / 'src/harnessy/core/workspace.py', app / 'harnessy/core/workspace.py']
    source = next((path for path in choices if path.is_file()), None)
    if source is None:
        return {'available': False, 'reason': 'trusted_app_schema_missing'}
    log('READ', f'Extracting installed canonical schema as text, without importing or executing the app: {source}')
    tree = ast.parse(source.read_text('utf-8'))
    store = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'WorkspaceStore')
    init = next(node for node in store.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == '_init_db')
    statements = []
    alters = []
    for node in ast.walk(init):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute) or not node.args:
            continue
        value = node.args[0]
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        sql = value.value.strip()
        if node.func.attr == 'executescript' and sql.startswith('CREATE TABLE'):
            statements.append(sql)
        elif node.func.attr == 'execute' and re.match(r'CREATE (?:UNIQUE )?INDEX', sql, re.I):
            statements.append(sql + ';')
        elif node.func.attr == 'execute' and re.match(r'ALTER TABLE \w+ ADD COLUMN \w+ ', sql, re.I):
            alters.append(sql)
    if not statements:
        return {'available': False, 'reason': 'trusted_app_schema_unrecognized'}
    data = {'statements': statements, 'alters': alters}
    write_json(target, data)
    return {'available': True, 'source_path': str(source), 'source_sha256': digest(source),
            'template_path': str(target), 'template_sha256': digest(target)}

def inventory(workspace: Path) -> list[dict]:
    result = []
    patterns = [workspace / '.harnessy' / 'archives', workspace / '.harnessy' / 'worktrees' / 'rewinds',
                workspace / '.harnessy' / 'rewinds']
    for base in patterns:
        log('SCAN', f'Checking known optional recovery metadata locations: {base}')
        if not base.is_dir() or base.is_symlink():
            continue
        iterator = base.glob('*/manifest.json') if base.name == 'archives' else base.glob('*/*/undo.json')
        for path in iterator:
            parents = path.relative_to(base).parts[:-1]
            current = base
            redirected = False
            for component in parents:
                current = current / component
                if current.is_symlink():
                    redirected = True
                    break
            if not redirected and path.is_file() and not path.is_symlink():
                info = path.stat()
                result.append({'kind': 'archive_database_snapshot' if path.name == 'manifest.json' else 'rewind_undo_snapshot',
                               'path': str(path), 'bytes': info.st_size, 'mtime_ns': info.st_mtime_ns})
            if len(result) >= 128:
                break
    base = Path(tempfile.gettempdir())
    log('SCAN', f'Checking own abandoned export snapshot locations, metadata only: {base}/harnessy-export-*/snapshot.sqlite')
    for path in base.glob('harnessy-export-*/snapshot.sqlite'):
        try:
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not path.parent.is_symlink():
                result.append({'kind': 'abandoned_export_database_unverified', 'path': str(path),
                               'bytes': info.st_size, 'mtime_ns': info.st_mtime_ns})
        except OSError:
            continue
        if len(result) >= 160:
            break
    return result

def connect_copy(path: Path, *, writable=False, deadline=None):
    connection = sqlite3.connect(path.as_uri() + ('?mode=rw' if writable else '?mode=ro'), uri=True, timeout=1)
    connection.execute('PRAGMA mmap_size=0').close()
    connection.execute('PRAGMA trusted_schema=OFF').close()
    if not writable:
        connection.execute('PRAGMA query_only=ON').close()
    if deadline is not None:
        connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    return connection

def inspect_copy(path: Path, deadline: float) -> dict:
    result = {'integrity_ok': False, 'index_only': False, 'integrity_error_count': 0,
              'integrity_errors_truncated': False, 'integrity_categories': {},
              'row_counts': {}, 'row_count_failures': [], 'schema_fingerprints': {},
              'column_counts': {},
              'table_row_digests': {}, 'row_digest_failures': [],
              'foreign_key_violations': None, 'application_invariants_ok': None}
    connection = None
    try:
        connection = connect_copy(path, deadline=deadline)
        rows = connection.execute('PRAGMA integrity_check(100)').fetchall()
        errors = [str(row[0]) for row in rows if str(row[0]) != 'ok']
        result['integrity_ok'] = not errors and rows == [('ok',)]
        result['integrity_error_count'] = len(errors)
        result['integrity_errors_truncated'] = len(errors) >= 100
        index_only = bool(errors) and len(errors) < 100
        for error in errors:
            if re.fullmatch(r'(?:row \d+ missing from index |wrong # of entries in index |non-unique entry in index )[A-Za-z_][A-Za-z0-9_]*', error):
                category = 'index_consistency'
            else:
                category = 'other_structure_or_data'
                index_only = False
            result['integrity_categories'][category] = result['integrity_categories'].get(category, 0) + 1
        result['index_only'] = index_only
    except sqlite3.Error as exc:
        result['sqlite_errorcode'] = getattr(exc, 'sqlite_errorcode', None)
        result['sqlite_errorname'] = getattr(exc, 'sqlite_errorname', 'unknown')
    if connection is None:
        return result
    try:
        schema = connection.execute("SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
        result['unknown_table_count'] = sum(name not in TABLES for name, _sql in schema)
        for name, sql in schema:
            if name not in TABLES:
                continue
            result['schema_fingerprints'][name] = hashlib.sha256(str(sql).encode('utf-8')).hexdigest()
            result['column_counts'][name] = len(connection.execute(f'PRAGMA table_info("{name}")').fetchall())
            try:
                result['row_counts'][name] = int(connection.execute(f'SELECT COUNT(*) FROM "{name}" NOT INDEXED').fetchone()[0])
            except sqlite3.Error:
                result['row_count_failures'].append(name)
            try:
                digest_rows = hashlib.sha256()
                cursor = connection.execute(f'SELECT rowid,* FROM "{name}" NOT INDEXED ORDER BY rowid')
                while batch := cursor.fetchmany(64):
                    for row in batch:
                        if time.monotonic() > deadline:
                            raise TimeoutError('row digest deadline')
                        digest_rows.update(b'row:')
                        for value in row:
                            if value is None:
                                marker, encoded = b'n', b''
                            elif isinstance(value, bytes):
                                marker, encoded = b'b', value
                            elif isinstance(value, str):
                                marker, encoded = b's', value.encode('utf-8')
                            elif isinstance(value, int):
                                marker, encoded = b'i', str(value).encode('ascii')
                            elif isinstance(value, float):
                                marker, encoded = b'f', value.hex().encode('ascii')
                            else:
                                raise ValueError('unknown SQLite value type')
                            digest_rows.update(marker + str(len(encoded)).encode('ascii') + b':' + encoded)
                cursor.close()
                result['table_row_digests'][name] = digest_rows.hexdigest()
            except (sqlite3.Error, UnicodeError, ValueError):
                result['row_digest_failures'].append(name)
        try:
            failures = connection.execute('PRAGMA foreign_key_check').fetchmany(101)
            result['foreign_key_violations'] = len(failures)
            result['foreign_key_errors_truncated'] = len(failures) > 100
        except sqlite3.Error:
            result['foreign_key_check_failed'] = True
        if {'chats', 'chat_output_owners'} <= set(result['row_counts']):
            bad = 0
            for chat_id, public_id, active_root, owner_chat_id, folder in connection.execute(
                'SELECT c.id,c.public_id,c.active_root,o.chat_id,o.folder_name FROM chats c '
                'LEFT JOIN chat_output_owners o ON o.public_id=c.public_id'):
                value = str(public_id or '')
                if (not re.fullmatch(r'[34679ACDEFHJKMNPRTVWXY]{4}', value)
                        or active_root != 'Project-' + value or owner_chat_id != chat_id or folder != active_root):
                    bad += 1
            result['application_invariant_failures'] = bad
            result['application_invariants_ok'] = bad == 0
    except sqlite3.Error as exc:
        result['metadata_read_errorcode'] = getattr(exc, 'sqlite_errorcode', None)
    finally:
        connection.close()
    return result

def create_canonical(path: Path, template: Path, deadline: float):
    data = json.loads(template.read_text('utf-8'))
    connection = sqlite3.connect(path)
    connection.execute('PRAGMA mmap_size=0')
    connection.execute('PRAGMA trusted_schema=OFF')
    connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    for sql in data['statements']:
        connection.executescript(sql)
    for sql in data['alters']:
        match = re.match(r'ALTER TABLE (\w+) ADD COLUMN (\w+) ', sql, re.I)
        table, column = match.groups()
        if column not in {row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')}:
            connection.execute(sql)
    connection.commit()
    return connection

def recover_copy(request: dict, deadline: float) -> dict:
    choices = request.get('sqlite_cli_candidates', [])
    if not choices:
        return {'recovery_status': 'sqlite_cli_unavailable', 'candidate_created': False}
    env = dict(os.environ, SQLITE_HISTORY=os.devnull)
    cli = None
    for choice in choices:
        try:
            help_result = subprocess.run([choice, '-batch', '-init', os.devnull, ':memory:', '.help recover'],
                                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
                                         timeout=min(15, max(.1, deadline - time.monotonic())))
            if not help_result.returncode and b'.recover' in help_result.stdout[:65536]:
                cli = choice
                break
        except (OSError, subprocess.TimeoutExpired):
            continue
    if cli is None:
        return {'recovery_status': 'sqlite_cli_recover_unsupported', 'candidate_created': False}
    source = Path(request['database'])
    sql_path = Path(request['recovered_sql'])
    with sql_path.open('xb') as output:
        recovered = subprocess.run([cli, '-batch', '-init', os.devnull, '-readonly', str(source),
                                    '.recover --ignore-freelist'], stdout=output, stderr=subprocess.DEVNULL,
                                   stdin=subprocess.DEVNULL, env=env, timeout=max(.1, deadline - time.monotonic()))
    if recovered.returncode or not sql_path.stat().st_size:
        return {'recovery_status': 'sqlite_cli_recover_failed', 'candidate_created': False,
                'sqlite_cli_returncode': recovered.returncode}
    candidate = Path(request['candidate'])
    connection = create_canonical(candidate, Path(request['template']), deadline)
    counts = {'inserted_rows': 0, 'duplicate_or_rejected_rows': 0, 'failed_insert_statements': 0,
              'lost_and_found_rows': 0, 'unknown_table_rows': 0, 'ignored_non_insert_statements': 0,
              'incomplete_statements': 0, 'unsupported_text_function_statements': 0}
    def authorizer(action, arg1, arg2, database, trigger):
        if action == sqlite3.SQLITE_INSERT and arg1 in TABLES and database == 'main':
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_READ and arg1 in TABLES and database == 'main':
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_TRANSACTION:
            return sqlite3.SQLITE_OK
        # SQLite CLI emits these literal text encoders for line breaks and
        # control characters. Every other function, including extension APIs,
        # stays denied. Older Python SQLite may lack unistr; count that failure.
        if action == sqlite3.SQLITE_FUNCTION and str(arg2 or '').lower() in {'char', 'replace', 'unistr'}:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    connection.set_authorizer(authorizer)
    identifier = r'''(?:'([A-Za-z_][A-Za-z0-9_]*)'|"([A-Za-z_][A-Za-z0-9_]*)"|`([A-Za-z_][A-Za-z0-9_]*)`|\[([A-Za-z_][A-Za-z0-9_]*)\]|([A-Za-z_][A-Za-z0-9_]*))'''
    insert = re.compile(r'^INSERT(?:\s+OR\s+(?:IGNORE|REPLACE|ABORT|FAIL|ROLLBACK))?\s+INTO\s+' + identifier, re.I)
    pending = ''
    try:
        with sql_path.open('r', encoding='utf-8', errors='strict') as incoming:
            for line in incoming:
                if time.monotonic() > deadline:
                    raise TimeoutError()
                pending += line
                if len(pending) > 64 * 1024 * 1024:
                    counts['incomplete_statements'] += 1
                    break
                if not sqlite3.complete_statement(pending):
                    continue
                sql = pending.strip()
                pending = ''
                # Remove only lexical leading comments. A later line starting
                # with "--" can be private text inside a multiline SQL string.
                while sql.startswith('--'):
                    _comment, separator, sql = sql.partition('\n')
                    sql = sql.lstrip()
                    if not separator:
                        break
                match = insert.match(sql)
                if not match:
                    counts['ignored_non_insert_statements'] += 1
                    continue
                table = next(value for value in match.groups() if value is not None)
                if table.startswith('lost_and_found'):
                    counts['lost_and_found_rows'] += 1
                    continue
                if table not in TABLES:
                    counts['unknown_table_rows'] += 1
                    continue
                # Never execute recovered DDL, triggers, PRAGMAs or ATTACH.
                # Canonical constraints remain authoritative. Keep duplicates
                # in the private SQL salvage rather than replacing good rows.
                statement = f'INSERT OR IGNORE INTO "{table}"' + sql[match.end():]
                try:
                    cursor = connection.execute(statement)
                    counts['inserted_rows' if cursor.rowcount > 0 else 'duplicate_or_rejected_rows'] += max(1, cursor.rowcount)
                except sqlite3.Error as exc:
                    counts['failed_insert_statements'] += 1
                    if 'no such function' in str(exc).lower():
                        counts['unsupported_text_function_statements'] += 1
        if pending.strip():
            counts['incomplete_statements'] += 1
        connection.commit()
    finally:
        connection.close()
    validation = seal_candidate(candidate, deadline)
    return {'recovery_status': 'salvage_candidate_created', 'candidate_created': True,
            'candidate': str(candidate), 'recovered_sql': str(sql_path), 'salvage_counts': counts,
            'sqlite_cli': cli, 'validation': validation, 'requires_review': True,
            'completeness': 'unknown',
            'fixed_warnings': ['SQLite salvage may lose or alter data, types, text and row ordering. Matching row counts do not prove matching contents.',
                               'Recovered or unidentified rows require review. No candidate has been activated.']}

def seal_candidate(path: Path, deadline: float) -> dict:
    connection = connect_copy(path, writable=True, deadline=deadline)
    try:
        checkpoint = connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
        journal = connection.execute('PRAGMA journal_mode=DELETE').fetchone()
        if (checkpoint is not None and checkpoint[0] != 0) or journal != ('delete',):
            raise RecoveryError('candidate_busy', 'Private candidate could not be consolidated.')
    finally:
        connection.close()
    validation = inspect_copy(path, deadline)
    validation['standalone_database'] = not any(
        signature(Path(str(path) + suffix)) is not None for suffix in ('-wal', '-journal')
    )
    return validation


def _bounded_host_command(command: list[str], timeout: float):
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
    deadline = time.monotonic() + timeout
    try:
        while True:
            check_cancel()
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(command, timeout)
            try:
                output, error = process.communicate(timeout=min(.2, deadline - time.monotonic()))
                return subprocess.CompletedProcess(command, process.returncode, output, error)
            except subprocess.TimeoutExpired:
                continue
    finally:
        stop_child(process)


def verify_no_open_database(files: dict[str, Path]) -> dict:
    paths = [path for name, path in files.items() if name != 'workspace.json']
    lsof = shutil.which('lsof') or next((path for path in ('/usr/sbin/lsof', '/usr/bin/lsof')
                                       if Path(path).is_file() and os.access(path, os.X_OK)), None)
    if lsof:
        log('CHECK', 'Inspecting open database files: ' + ' '.join(str(path) for path in paths))
        try:
            result = _bounded_host_command([lsof, '-nP', '-F0p', '--', *map(str, paths)], 15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RecoveryError('stop_check_unknown', 'Open-file inspection could not finish. Stop processes using this workspace and retry.') from exc
        holders = sorted({int(value) for value in re.findall(rb'(?:^|[\x00\n])p(\d+)', result.stdout)
                          if int(value) != os.getpid()})
        if holders:
            raise RecoveryError('database_open', f'Workspace database files are still open by PID(s): {", ".join(map(str, holders))}. Close those processes before retrying.')
        if result.returncode not in (0, 1) or result.stderr.strip() or result.stdout.strip(b'\x00\n'):
            if not Path('/proc').is_dir():
                raise RecoveryError('stop_check_unknown', 'Open-file inspection was incomplete or unrecognized. No recovery copy was opened by SQLite.')
            log('CHECK', 'lsof visibility was incomplete; checking all process descriptors independently through /proc before proceeding.')
        else:
            return {'method': 'lsof', 'holders': 0, 'verified': True}
    proc = Path('/proc')
    if not proc.is_dir():
        raise RecoveryError('stop_check_unknown', 'lsof is unavailable, so the helper cannot verify that database users stopped. Install lsof using your normal host tools, then retry.')
    log('CHECK', f'Inspecting process file descriptors against workspace database identities: {proc}')
    identities = {signature(path)[:2] for path in paths}
    unknown = 0
    holders = set()
    for process in proc.iterdir():
        check_cancel()
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        try:
            descriptors = list((process / 'fd').iterdir())
        except FileNotFoundError:
            continue
        except PermissionError:
            unknown += 1
            continue
        for descriptor in descriptors:
            check_cancel()
            try:
                info = descriptor.stat()
                if (info.st_dev, info.st_ino) in identities:
                    holders.add(int(process.name))
            except FileNotFoundError:
                pass
            except PermissionError:
                unknown += 1
    if holders:
        raise RecoveryError('database_open', f'Workspace database files are still open by PID(s): {", ".join(map(str, sorted(holders)))}. Close those processes and retry.')
    if unknown:
        raise RecoveryError('stop_check_unknown', 'Some process file descriptors could not be inspected. Use a host terminal with complete lsof visibility; no recovery was attempted.')
    return {'method': 'proc_fd', 'holders': 0, 'verified': True}


def worker(stage: str, request_path: Path, result_path: Path, timeout: float) -> None:
    os.umask(0o077)
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, OSError, ValueError):
        pass
    deadline = time.monotonic() + timeout * .98
    request = json.loads(request_path.read_text('utf-8'))
    try:
        if stage == 'inspect':
            result = inspect_copy(Path(request['database']), deadline)
        elif stage == 'reindex':
            connection = connect_copy(Path(request['database']), writable=True, deadline=deadline)
            try:
                connection.execute('REINDEX')
                connection.commit()
            finally:
                connection.close()
            result = {'validation': seal_candidate(Path(request['database']), deadline)}
        elif stage == 'recover':
            result = recover_copy(request, deadline)
        else:
            raise ValueError('unknown recovery stage')
    except sqlite3.Error as exc:
        result = {'operation_status': 'sqlite_error', 'sqlite_errorcode': getattr(exc, 'sqlite_errorcode', None),
                  'sqlite_errorname': getattr(exc, 'sqlite_errorname', 'unknown')}
    except (TimeoutError, subprocess.TimeoutExpired):
        result = {'operation_status': 'timed_out'}
    except (OSError, ValueError, SyntaxError, RecoveryError):
        result = {'operation_status': 'failed'}
    result_path.write_text(json.dumps(result, separators=(',', ':')), encoding='utf-8')

def verified_candidate(before: dict, after: dict) -> bool:
    return (healthy_workspace(after) and after.get('standalone_database') is True
            and not before.get('row_count_failures') and bool(before.get('row_counts'))
            and before.get('row_counts') == after.get('row_counts')
            and before.get('schema_fingerprints') == after.get('schema_fingerprints')
            and not before.get('row_digest_failures') and not after.get('row_digest_failures')
            and set(before.get('table_row_digests', {})) == TABLES
            and before.get('table_row_digests') == after.get('table_row_digests'))

def sqlite_cli_candidates() -> list[str]:
    choices = ['/opt/homebrew/opt/sqlite/bin/sqlite3', '/usr/local/opt/sqlite/bin/sqlite3',
               shutil.which('sqlite3'), '/usr/bin/sqlite3']
    return list(dict.fromkeys(str(Path(path).resolve()) for path in choices
                             if path and Path(path).is_file() and os.access(path, os.X_OK)))

def healthy_workspace(result: dict) -> bool:
    return (result.get('integrity_ok') is True and result.get('foreign_key_violations') == 0
            and result.get('application_invariants_ok') is True
            and not result.get('row_count_failures') and result.get('unknown_table_count') == 0
            and not result.get('row_digest_failures') and set(result.get('table_row_digests', {})) == TABLES
            and set(result.get('row_counts', {})) == TABLES)

if __name__ == '__main__':
    if len(sys.argv) != 6 or sys.argv[1] != '--worker':
        raise SystemExit(2)
    worker(sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]), float(sys.argv[5]))
