"""Private, incremental filesystem history for canonical project recovery.

HarnessyXO deliberately keeps this repository separate from a project's own
``.git`` directory.  Ordinary working files are stored in a private bare Git
object database.  Large/opaque files and project Git metadata are stored in an
immutable object area, using copy-on-write clones when the host filesystem
supports them.
"""
from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from harnessy.diagnostics import log_event

try:  # Linux reflink support; unavailable on some Python/platform builds.
    import fcntl
except ImportError:  # pragma: no cover - exercised on non-POSIX ports only
    fcntl = None


HISTORY_SCHEMA_VERSION = 1
DEFAULT_LARGE_FILE_THRESHOLD = 64 * 1024 * 1024
DEFAULT_HISTORY_LOCK_TIMEOUT_SECONDS = 10.0
BRANCHES_DIR_NAME = '.harnessyxo-branches'
REWINDS_DIR_NAME = '.harnessyxo-rewinds'
FICLONE = 0x40049409


class HistoryError(RuntimeError):
    """A checkpoint could not be made or restored safely."""


class HistoryBusyError(HistoryError):
    """Another history operation kept its lock past this caller's deadline."""


@dataclass(slots=True)
class HistorySnapshot:
    shadow_commit: str
    file_manifest: dict[str, Any]
    large_manifest: dict[str, Any]
    git_manifest: dict[str, Any]
    restorable: bool
    warnings: list[str]


_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.RLock()


def _lock_for(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.RLock())


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _run(
    argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None,
    input_bytes: bytes | None = None, check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            argv, cwd=str(cwd) if cwd is not None else None, env=env,
            input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=3600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HistoryError(f'History command failed to start: {argv[0]}: {exc}') from exc
    if check and result.returncode != 0:
        detail = result.stderr.decode('utf-8', errors='replace').strip()
        raise HistoryError(f'History command failed ({argv[0]}): {detail or result.returncode}')
    return result


def _raise_if_cancelled(cancel_event: Any | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise HistoryError('Historical branch creation was cancelled.')


def _copy_file_cow(source: Path, destination: Path, *, cancel_event: Any | None = None) -> str:
    """Clone a file without unsafe hardlinks, falling back to a real copy."""
    _raise_if_cancelled(cancel_event)
    source = source.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)

    if os.name == 'posix' and sys_platform() == 'darwin':
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            clonefile = libc.clonefile
            clonefile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
            clonefile.restype = ctypes.c_int
            if clonefile(os.fsencode(source), os.fsencode(destination), 0) == 0:
                shutil.copystat(source, destination, follow_symlinks=False)
                if cancel_event is not None and cancel_event.is_set():
                    destination.unlink(missing_ok=True)
                    _raise_if_cancelled(cancel_event)
                return 'clonefile'
        except (AttributeError, OSError, ValueError):
            destination.unlink(missing_ok=True)

    if fcntl is not None and os.name == 'posix':
        try:
            with source.open('rb') as src, destination.open('xb') as dst:
                fcntl.ioctl(dst.fileno(), FICLONE, src.fileno())
            shutil.copystat(source, destination, follow_symlinks=False)
            if cancel_event is not None and cancel_event.is_set():
                destination.unlink(missing_ok=True)
                _raise_if_cancelled(cancel_event)
            return 'reflink'
        except (OSError, ValueError):
            destination.unlink(missing_ok=True)

    try:
        with source.open('rb') as src, destination.open('xb') as dst:
            while True:
                _raise_if_cancelled(cancel_event)
                chunk = src.read(4 * 1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
        shutil.copystat(source, destination, follow_symlinks=False)
        _raise_if_cancelled(cancel_event)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return 'copy'


def clone_or_copy_file(source: Path, destination: Path, *, cancel_event: Any | None = None) -> str:
    """Public helper used for branch-private attachment copies."""
    return _copy_file_cow(source, destination, cancel_event=cancel_event)


def sys_platform() -> str:
    # Isolated for tests without importing the much larger ``platform`` module.
    import sys
    return sys.platform


def _file_signature(path: Path, *, sample: bool) -> dict[str, Any]:
    info = path.stat(follow_symlinks=False)
    signature: dict[str, Any] = {
        'size': int(info.st_size),
        'mtime_ns': int(info.st_mtime_ns),
        'ctime_ns': int(info.st_ctime_ns),
        'mode': stat.S_IMODE(info.st_mode),
        'device': int(info.st_dev),
        'inode': int(info.st_ino),
    }
    if sample:
        digest = hashlib.sha256()
        size = int(info.st_size)
        digest.update(str(size).encode('ascii'))
        chunk = 64 * 1024
        offsets = sorted({0, max(0, size // 2 - chunk // 2), max(0, size - chunk)})
        with path.open('rb') as handle:
            for offset in offsets:
                handle.seek(offset)
                data = handle.read(chunk)
                digest.update(offset.to_bytes(8, 'big'))
                digest.update(data)
        signature['sample_sha256'] = digest.hexdigest()
    return signature


def _same_signature(left: dict[str, Any] | None, right: dict[str, Any]) -> bool:
    if not isinstance(left, dict):
        return False
    keys = ('size', 'mtime_ns', 'ctime_ns', 'mode', 'device', 'inode', 'sample_sha256')
    return all(left.get(key) == right.get(key) for key in keys if key in right or key in left)


def _same_sampled_content(left: dict[str, Any] | None, right: dict[str, Any]) -> bool:
    """Compare the bounded content evidence used to prefilter large objects.

    Large files deliberately use bounded sampling instead of a whole-file hash.
    A workspace move, metadata touch, or remount can change inode/ctime/device
    without changing that existing content evidence.  Treating those identity
    changes as new bytes caused HarnessyXO to clone/copy huge files on every
    prompt on some external volumes.
    """
    if not isinstance(left, dict):
        return False
    left_sample = str(left.get('sample_sha256') or '')
    right_sample = str(right.get('sample_sha256') or '')
    return bool(
        left_sample
        and right_sample
        and int(left.get('size') or -1) == int(right.get('size') or -2)
        and left_sample == right_sample
    )


def _same_file_bytes(left: Path, right: Path) -> bool:
    """Return true only when two regular files are byte-for-byte identical."""
    try:
        if left.stat().st_size != right.stat().st_size:
            return False
        with left.open('rb') as first, right.open('rb') as second:
            while True:
                first_chunk = first.read(4 * 1024 * 1024)
                second_chunk = second.read(4 * 1024 * 1024)
                if first_chunk != second_chunk:
                    return False
                if not first_chunk:
                    return True
    except OSError:
        return False


class ShadowHistory:
    """Capture and materialize one chat's active working root."""

    def __init__(
        self, meta_root: Path, files_root: Path, *,
        large_file_threshold: int | None = None,
        additional_working_roots: Iterable[Path] = (),
    ) -> None:
        self.meta_root = meta_root.resolve()
        self.files_root = files_root.resolve()
        self.working_roots = (
            self.files_root,
            *(Path(root).resolve() for root in additional_working_roots),
        )
        self.history_root = self.meta_root / 'history'
        self.repo = self.history_root / 'workspace.git'
        self.indexes = self.history_root / 'indexes'
        self.large_objects = self.history_root / 'large-objects'
        self.opaque_objects = self.history_root / 'opaque-objects'
        self.tmp = self.history_root / 'tmp'
        configured = os.environ.get('HARNESSY_HISTORY_LARGE_FILE_BYTES', '').strip()
        if large_file_threshold is None and configured:
            try:
                large_file_threshold = int(configured)
            except ValueError:
                large_file_threshold = None
        self.large_file_threshold = max(1024, int(large_file_threshold or DEFAULT_LARGE_FILE_THRESHOLD))
        for directory in (
            self.history_root, self.indexes, self.large_objects, self.opaque_objects, self.tmp,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        self._lock = _lock_for(self.history_root)

    @contextmanager
    def _locked(self, *, lock_timeout_seconds: float = DEFAULT_HISTORY_LOCK_TIMEOUT_SECONDS):
        """Bound thread and process lock acquisition without disturbing the holder."""
        timeout = float(lock_timeout_seconds)
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError('History lock timeout must be a finite nonnegative number.')
        started = time.monotonic()
        deadline = started + timeout
        thread_acquired = False
        process_acquired = False

        def busy(kind: str) -> None:
            try:
                log_event('history', 'history_lock_busy', lock_kind=kind,
                          waited_seconds=round(max(0.0, time.monotonic() - started), 6),
                          lock_timeout_seconds=timeout)
            except Exception:
                pass
            raise HistoryBusyError(
                'Private file history is busy in another operation. Wait for active history work to finish, '
                'then retry opening this workspace or the history action. '
                'Existing project files and lock files were preserved.'
            )

        lock_path = self.history_root / 'history.lock'
        try:
            thread_acquired = self._lock.acquire(timeout=max(0.0, deadline - time.monotonic()))
            if not thread_acquired:
                busy('thread')
            with lock_path.open('a+b') as handle:
                if fcntl is not None and hasattr(fcntl, 'flock'):
                    while True:
                        try:
                            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                            process_acquired = True
                            break
                        except OSError as exc:
                            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                                raise
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                busy('process')
                            time.sleep(min(0.05, remaining))
                try:
                    yield
                finally:
                    if process_acquired:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            if thread_acquired:
                self._lock.release()

    def _git_env(self, *, index: Path | None = None) -> dict[str, str]:
        env = dict(os.environ)
        for key in list(env):
            if key.startswith('GIT_'):
                env.pop(key, None)
        env.update({
            'GIT_DIR': str(self.repo),
            'GIT_CONFIG_GLOBAL': os.devnull,
            'GIT_AUTHOR_NAME': 'HarnessyXO History',
            'GIT_AUTHOR_EMAIL': 'history@harnessyxo.invalid',
            'GIT_COMMITTER_NAME': 'HarnessyXO History',
            'GIT_COMMITTER_EMAIL': 'history@harnessyxo.invalid',
            'GIT_CONFIG_NOSYSTEM': '1',
            'LC_ALL': 'C',
        })
        if index is not None:
            env['GIT_INDEX_FILE'] = str(index)
        return env

    def _git(self, args: list[str], *, work_tree: Path | None = None, index: Path | None = None,
             input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        argv = ['git', f'--git-dir={self.repo}']
        if work_tree is not None:
            argv.append(f'--work-tree={work_tree}')
        argv.extend(args)
        return _run(argv, env=self._git_env(index=index), input_bytes=input_bytes, check=check)

    def _ensure_repo(self) -> None:
        if shutil.which('git') is None:
            raise HistoryError('Git is required for historical prompt rewind, but it is not installed or not in PATH.')
        if not (self.repo / 'HEAD').is_file():
            self.repo.mkdir(parents=True, exist_ok=True)
            _run(['git', 'init', '--bare', '--quiet', str(self.repo)], env=self._git_env())
        for key, expected in (('core.autocrlf', b'false'), ('core.filemode', b'true')):
            current = self._git(['config', '--get', key], check=False)
            if current.returncode != 0 or current.stdout.strip() != expected:
                self._git(['config', key, expected.decode('ascii')])

    def _file_history_refs(self) -> dict[str, str]:
        result = self._git(['for-each-ref', '--format=%(refname) %(objectname)',
                            'refs/harnessy/file-history/', 'refs/harnessy/file-history-commits/'])
        return dict(line.split(' ', 1) for line in result.stdout.decode('ascii').splitlines() if ' ' in line)

    def retain_file_history_commits(
        self, snapshots: Iterable[tuple[str, str]], *,
        lock_timeout_seconds: float = DEFAULT_HISTORY_LOCK_TIMEOUT_SECONDS,
    ) -> None:
        """Keep catalogue commits reachable even after another chat advances HEAD."""
        candidates: list[tuple[str, str]] = []
        for snapshot_id, commit in snapshots:
            value = str(commit or '').strip()
            if not re.fullmatch(r'(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})', value):
                continue
            token = hashlib.sha256(str(snapshot_id).encode('utf-8')).hexdigest()
            candidates.append((f'refs/harnessy/file-history/{token}', value.lower()))
        if not candidates:
            return
        with self._locked(lock_timeout_seconds=lock_timeout_seconds):
            if not (self.repo / 'HEAD').is_file():
                self._ensure_repo()
            current_refs = self._file_history_refs()
            candidates = [(ref, commit) for ref, commit in dict(candidates).items()
                          if current_refs.get(ref) != commit]
            if not candidates:
                return
            check_payload = ''.join(f'{commit}^{{commit}}\n' for _ref, commit in candidates).encode('ascii')
            checked = self._git(
                ['cat-file', '--batch-check=%(objectname) %(objecttype)'],
                input_bytes=check_payload, check=False,
            )
            lines = checked.stdout.decode('ascii', errors='replace').splitlines()
            updates = [
                candidate for candidate, line in zip(candidates, lines)
                if line.endswith(' commit') and ' missing' not in line
            ]
            if not updates:
                return
            # These refs are reachability pins, never snapshot lookup keys.
            # Pin the DB's immutable commit separately instead of touching a
            # snapshot-ID ref that another live Git transaction may own.
            for attempt in range(4):
                current_refs = self._file_history_refs()
                protected = {value for ref, value in current_refs.items()
                             if ref.startswith('refs/harnessy/file-history-commits/')}
                wanted = list(dict.fromkeys(commit for ref, commit in updates
                                            if current_refs.get(ref) != commit and commit not in protected))
                if not wanted:
                    return
                pins = []
                for commit in wanted:
                    canonical = f'refs/harnessy/file-history-commits/{commit}'
                    ref = (canonical if attempt == 0 and canonical not in current_refs else
                           canonical + '-' + uuid.uuid4().hex)
                    pins.append((ref, commit))
                payload = ''.join(f'create {ref} {commit}\n' for ref, commit in pins).encode('ascii')
                result = self._git(['update-ref', '--stdin'], input_bytes=payload, check=False)
                if result.returncode == 0:
                    return
            raise HistoryError(
                'Private file history could not retain its snapshot commits because Git ref updates are busy. '
                'Finish active Git operations and retry opening this workspace. '
                'Existing project files and lock files were preserved.'
            )

    def _validate_root(self, root: Path) -> Path:
        root = root.resolve()
        if not any(base == root or base in root.parents for base in self.working_roots):
            raise HistoryError('The active working root is outside this workspace working-tree roots.')
        if not root.is_dir():
            raise HistoryError(f'The active working root is unavailable: {root}')
        return root

    def _excluded(self, root: Path, relative: Path, name: str) -> bool:
        if name == '.git':
            return True
        if root == self.files_root and len(relative.parts) == 1:
            return name in {
                '.harnessy', '.LLM', '.imports', BRANCHES_DIR_NAME, REWINDS_DIR_NAME,
                '.harnessyxo-probes',
            }
        return False

    def _scan_work_tree(self, root: Path) -> tuple[list[str], list[tuple[str, Path]], dict[str, Any], list[str]]:
        ordinary: list[str] = []
        large: list[tuple[str, Path]] = []
        metadata: dict[str, Any] = {
            'root_mode': stat.S_IMODE(root.stat().st_mode),
            'entries': {},
            'nested_git_roots': [],
        }
        warnings: list[str] = []
        stack: list[tuple[Path, Path]] = [(root, Path('.'))]
        while stack:
            directory, relative_dir = stack.pop()
            try:
                entries = sorted(os.scandir(directory), key=lambda row: os.fsencode(row.name))
            except OSError as exc:
                raise HistoryError(f'Cannot read working directory {directory}: {exc}') from exc
            for entry in entries:
                rel = Path(entry.name) if relative_dir == Path('.') else relative_dir / entry.name
                if self._excluded(root, rel, entry.name):
                    if entry.name == '.git' and relative_dir != Path('.'):
                        metadata['nested_git_roots'].append(relative_dir.as_posix())
                    continue
                rel_text = rel.as_posix()
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise HistoryError(f'Cannot stat {rel_text}: {exc}') from exc
                mode = stat.S_IMODE(info.st_mode)
                if stat.S_ISDIR(info.st_mode):
                    metadata['entries'][rel_text] = {'kind': 'directory', 'mode': mode}
                    stack.append((Path(entry.path), rel))
                elif stat.S_ISLNK(info.st_mode):
                    metadata['entries'][rel_text] = {'kind': 'symlink', 'mode': mode}
                    ordinary.append(rel_text)
                elif stat.S_ISREG(info.st_mode):
                    metadata['entries'][rel_text] = {'kind': 'file', 'mode': mode, 'size': int(info.st_size)}
                    if info.st_size > self.large_file_threshold:
                        large.append((rel_text, Path(entry.path)))
                    else:
                        ordinary.append(rel_text)
                else:
                    metadata['entries'][rel_text] = {'kind': 'unsupported', 'mode': mode}
                    warnings.append(f'Unsupported special filesystem entry cannot be restored: {rel_text}')
        ordinary.sort(key=os.fsencode)
        large.sort(key=lambda row: os.fsencode(row[0]))
        metadata['nested_git_roots'].sort(key=os.fsencode)
        return ordinary, large, metadata, warnings

    @staticmethod
    def _write_pathspec(path: Path, values: Iterable[str]) -> None:
        with path.open('wb') as handle:
            for value in values:
                handle.write(os.fsencode(value))
                handle.write(b'\0')

    def _stage_nested_repository_files(
        self, root: Path, values: Iterable[str], *, index: Path,
    ) -> None:
        """Stage visible files below nested .git boundaries as ordinary bytes.

        A broad ``git add`` records an embedded repository as a gitlink and
        drops its visible files. Historical checkpoints intentionally exclude
        nested Git metadata but preserve those visible working bytes, so hash
        and index only this uncommon subset explicitly.
        """
        records: list[bytes] = []
        for rel in values:
            source = root / rel
            info = source.lstat()
            if stat.S_ISLNK(info.st_mode):
                blob = self._git(
                    ['hash-object', '-w', '--stdin'],
                    input_bytes=os.fsencode(os.readlink(source)),
                ).stdout.decode('ascii').strip()
                mode = '120000'
            elif stat.S_ISREG(info.st_mode):
                blob = self._git([
                    'hash-object', '-w', '--no-filters', '--', str(source),
                ]).stdout.decode('ascii').strip()
                mode = '100755' if stat.S_IMODE(info.st_mode) & 0o111 else '100644'
            else:  # The scan classified every supplied value first.
                raise HistoryError(f'Working file changed type while checkpointing: {rel}')
            records.append(
                mode.encode('ascii') + b' ' + blob.encode('ascii') + b'\t'
                + os.fsencode(rel) + b'\0'
            )
        if records:
            self._git(
                ['update-index', '-z', '--index-info'], index=index,
                input_bytes=b''.join(records),
            )

    def _tree_commit(
        self, root: Path, chat_id: str, checkpoint_id: str, ordinary: list[str],
        previous_commit: str, *, excluded_paths: Iterable[str] = (),
        nested_git_roots: Iterable[str] = (),
    ) -> tuple[str, bool]:
        safe_chat = ''.join(ch for ch in str(chat_id) if ch.isalnum() or ch in '-_')[:120] or 'chat'
        persistent_index = self.indexes / f'{safe_chat}.index'
        root_marker = self.indexes / f'{safe_chat}.root'
        previous_valid = bool(previous_commit and self._git(
            ['cat-file', '-e', f'{previous_commit}^{{commit}}'], check=False,
        ).returncode == 0)
        with tempfile.TemporaryDirectory(prefix='checkpoint-', dir=self.tmp) as tmp_name:
            tmp_dir = Path(tmp_name)
            index = tmp_dir / 'index'
            marker_value = str(root)
            reused_persistent_index = bool(
                persistent_index.is_file()
                and root_marker.is_file()
                and root_marker.read_text('utf-8', errors='replace') == marker_value
            )
            if reused_persistent_index:
                shutil.copy2(persistent_index, index)
            else:
                if previous_valid:
                    self._git(['read-tree', previous_commit], index=index)
                else:
                    self._git(['read-tree', '--empty'], index=index)

            listed = self._git(['ls-files', '-z'], index=index).stdout
            tracked = {os.fsdecode(item) for item in listed.split(b'\0') if item}
            current = set(ordinary)
            stale = sorted(tracked - current, key=os.fsencode)
            nested_roots = tuple(
                f'{value.rstrip("/")}/' for value in nested_git_roots if value.rstrip('/')
            )
            nested_files = [
                value for value in ordinary if any(value.startswith(prefix) for prefix in nested_roots)
            ]

            # The persistent index already contains the last checkpoint's stat
            # cache.  Ask Git's optimized C work-tree comparison whether any
            # tracked bytes or modes changed before feeding every path through
            # `git add` again.  The Python scan above independently established
            # the complete current path set, including untracked additions and
            # large-file transitions, so this shortcut cannot hide a new or
            # deleted ordinary path.
            if previous_valid and reused_persistent_index and tracked == current:
                unchanged = self._git(
                    ['diff-files', '--quiet', '--ignore-submodules', '--'],
                    work_tree=root, index=index, check=False,
                )
                if unchanged.returncode == 0:
                    # A post-run revision may have refreshed this index since
                    # the last pre-prompt checkpoint. Comparing the worktree to
                    # that index does not prove it matches previous_commit.
                    index_tree = self._git(['write-tree'], index=index).stdout.strip()
                    previous_tree = self._git(['show', '-s', '--format=%T', previous_commit]).stdout.strip()
                    if index_tree == previous_tree:
                        return previous_commit, True

            for start in range(0, len(stale), 400):
                # Git 2.51 rejects update-index removals against a bare repo
                # unless a work tree is supplied, even though the temporary
                # index is authoritative. Keep the explicit root so deletion
                # checkpoints and File History restores work across versions.
                self._git(
                    ['update-index', '--force-remove', '--', *stale[start:start + 400]],
                    work_tree=root, index=index,
                )

            broad_ordinary = set(ordinary) - set(nested_files)
            if broad_ordinary:
                pathspec = tmp_dir / 'paths'
                # Feeding every file to Git as an individual pathspec scales
                # extremely poorly on large trees (and was the source of
                # multi-thousand-second checkpoints on external storage). Let
                # Git walk the tree once, with exact negative pathspecs for the
                # large/special files managed outside the shadow repository.
                pathspec_values = [
                    ':(top)**',
                    *(
                        f':(top,exclude,literal){value}'
                        for value in sorted(
                            {*excluded_paths, *(value.rstrip('/') for value in nested_git_roots)},
                            key=os.fsencode,
                        )
                    ),
                ]
                self._write_pathspec(pathspec, pathspec_values)
                self._git([
                    'add', '--all', '--force', f'--pathspec-from-file={pathspec}', '--pathspec-file-nul',
                ], work_tree=root, index=index)
            if nested_files:
                self._stage_nested_repository_files(root, nested_files, index=index)

            staged = {
                os.fsdecode(item)
                for item in self._git(['ls-files', '-z'], index=index).stdout.split(b'\0')
                if item
            }
            if staged != current:
                raise HistoryError(
                    'The working file set changed while the historical checkpoint was being created. Retry when writers are idle.'
                )

            tree = self._git(['write-tree'], index=index).stdout.decode('ascii').strip()
            commit = ''
            if previous_valid:
                previous_tree = self._git(['show', '-s', '--format=%T', previous_commit]).stdout.decode('ascii').strip()
                if tree == previous_tree:
                    commit = previous_commit
            if not commit:
                args = ['commit-tree', tree]
                if previous_valid:
                    args.extend(['-p', previous_commit])
                commit = self._git(args, input_bytes=f'HarnessyXO checkpoint {checkpoint_id}\n'.encode()).stdout.decode('ascii').strip()
                self._git(['update-ref', 'refs/heads/checkpoints', commit])
            if self._git(['cat-file', '-e', f'{commit}^{{commit}}'], check=False).returncode != 0:
                raise HistoryError('The shadow Git checkpoint was not finalized.')
            staged_index = tmp_dir / 'saved-index'
            shutil.copy2(index, staged_index)
            os.replace(staged_index, persistent_index)
            staged_marker = tmp_dir / 'saved-root'
            staged_marker.write_text(marker_value, encoding='utf-8')
            os.replace(staged_marker, root_marker)
            return commit, False

    def _snapshot_large_files(self, rows: list[tuple[str, Path]], previous: dict[str, Any] | None) -> dict[str, Any]:
        prior_entries = (previous or {}).get('entries') if isinstance(previous, dict) else {}
        prior_entries = prior_entries if isinstance(prior_entries, dict) else {}
        result: dict[str, Any] = {'version': 1, 'threshold': self.large_file_threshold, 'entries': {}}
        for rel, source in rows:
            signature = _file_signature(source, sample=True)
            prior = prior_entries.get(rel) if isinstance(prior_entries.get(rel), dict) else None
            if prior:
                object_rel = str(prior.get('object') or '')
                candidate = self.history_root / object_rel
                strict_match = _same_signature(prior.get('signature'), signature)
                verified_metadata_only_match = bool(
                    not strict_match
                    and _same_sampled_content(prior.get('signature'), signature)
                    and candidate.is_file()
                    and _same_file_bytes(source, candidate)
                )
                if (
                    (strict_match or verified_metadata_only_match)
                    and candidate.is_file()
                    and candidate.stat().st_size == signature['size']
                ):
                    reused = _json_copy(prior)
                    # Rebase identity metadata to the current working file so
                    # the following prompt can take the strict zero-I/O path.
                    reused['signature'] = signature
                    result['entries'][rel] = reused
                    continue
            object_path = self.large_objects / uuid.uuid4().hex
            method = _copy_file_cow(source, object_path)
            after = _file_signature(source, sample=True)
            stored = _file_signature(object_path, sample=True)
            if not _same_signature(signature, after) or stored.get('size') != signature.get('size') or stored.get('sample_sha256') != signature.get('sample_sha256'):
                object_path.unlink(missing_ok=True)
                raise HistoryError(f'Large file changed while checkpointing: {rel}. Retry after the writer is idle.')
            result['entries'][rel] = {
                'object': object_path.relative_to(self.history_root).as_posix(),
                'signature': signature,
                'storage': method,
            }
        return result

    @staticmethod
    def _plain_git_env() -> dict[str, str]:
        env = dict(os.environ)
        for key in list(env):
            if key.startswith('GIT_'):
                env.pop(key, None)
        env['LC_ALL'] = 'C'
        return env

    def _project_git_roots(self, root: Path) -> tuple[Path, Path] | None:
        local_marker = os.path.lexists(root / '.git')
        probe = _run(['git', '-C', str(root), 'rev-parse', '--show-toplevel'], env=self._plain_git_env(), check=False)
        if probe.returncode != 0:
            if local_marker:
                raise HistoryError(
                    'The project has a .git entry that Git cannot read safely; repair it before creating a historical checkpoint.'
                )
            return None
        try:
            top = Path(probe.stdout.decode('utf-8', errors='surrogateescape').strip()).resolve()
        except (OSError, ValueError):
            if local_marker:
                raise HistoryError('Git returned an invalid project root; the historical checkpoint was not created.')
            return None
        if top != root:
            if local_marker:
                raise HistoryError(
                    'The active root has a .git entry but Git resolved a different work tree; the historical checkpoint was not created.'
                )
            return None
        git_dir_raw = _run(['git', '-C', str(root), 'rev-parse', '--absolute-git-dir'], env=self._plain_git_env()).stdout
        common_raw = _run(['git', '-C', str(root), 'rev-parse', '--git-common-dir'], env=self._plain_git_env()).stdout
        git_dir = Path(git_dir_raw.decode('utf-8', errors='surrogateescape').strip()).resolve()
        common_text = common_raw.decode('utf-8', errors='surrogateescape').strip()
        common = Path(common_text)
        if not common.is_absolute():
            common = (root / common).resolve()
        else:
            common = common.resolve()
        if not git_dir.is_dir() or not common.is_dir():
            raise HistoryError('The project Git metadata directory is unavailable; the historical checkpoint was not created.')
        return common, git_dir

    def rebase_materialized_manifests(
        self, destination: Path, large_manifest: dict[str, Any], git_manifest: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Bind immutable manifests to the fresh branch copy's file identities.

        Materialization changes inode/ctime even when clonefile/reflink preserves
        bytes and mtime. Recording those new identities lets the branch's first
        prompt reuse the existing immutable large objects while still detecting
        an intervening edit through the normal strict signature comparison.
        """
        destination = destination.resolve()
        rebased_large = _json_copy(large_manifest or {})
        entries = rebased_large.get('entries') if isinstance(rebased_large.get('entries'), dict) else {}
        for rel, entry in entries.items():
            target = destination / rel
            if not target.is_file():
                raise HistoryError(f'Materialized large file is missing: {rel}')
            signature = _file_signature(target, sample=True)
            original = entry.get('signature') if isinstance(entry, dict) else {}
            if (
                signature.get('size') != original.get('size')
                or signature.get('sample_sha256') != original.get('sample_sha256')
            ):
                raise HistoryError(f'Materialized large file verification failed: {rel}')
            entry['signature'] = signature

        # Large Git packfiles benefit from the same identity rebasing. Small
        # metadata files stay content-addressed and are cheap to verify again;
        # notably, the restored config is intentionally changed to point its
        # worktree at this branch rather than the original timeline.
        rebased_git = _json_copy(git_manifest or {})
        git_entries = rebased_git.get('entries') if isinstance(rebased_git.get('entries'), dict) else {}
        for rel, entry in git_entries.items():
            if not isinstance(entry, dict) or entry.get('kind') != 'file':
                continue
            original = entry.get('signature') if isinstance(entry.get('signature'), dict) else {}
            if not original.get('sample_sha256'):
                continue
            target = destination / '.git' / rel
            if not target.is_file():
                raise HistoryError(f'Materialized project Git object is missing: {rel}')
            signature = _file_signature(target, sample=True)
            if (
                signature.get('size') == original.get('size')
                and signature.get('sample_sha256') == original.get('sample_sha256')
            ):
                entry['signature'] = signature
        return rebased_large, rebased_git

    @staticmethod
    def _git_transient(rel: str) -> bool:
        name = Path(rel).name
        return name in {'commondir', 'gitdir'}

    def _scan_opaque_root(self, source_root: Path, virtual: dict[str, tuple[str, Any]]) -> None:
        stack: list[tuple[Path, Path]] = [(source_root, Path('.'))]
        while stack:
            directory, relative_dir = stack.pop()
            for entry in sorted(os.scandir(directory), key=lambda row: os.fsencode(row.name)):
                rel = Path(entry.name) if relative_dir == Path('.') else relative_dir / entry.name
                rel_text = rel.as_posix()
                if entry.name.endswith('.lock') or entry.name == 'gc.pid':
                    raise HistoryError(
                        f'The project Git repository is busy ({rel_text}); retry after the Git operation finishes.'
                    )
                if self._git_transient(rel_text):
                    continue
                info = entry.stat(follow_symlinks=False)
                mode = stat.S_IMODE(info.st_mode)
                if stat.S_ISDIR(info.st_mode):
                    virtual[rel_text] = ('directory', {'mode': mode})
                    stack.append((Path(entry.path), rel))
                elif stat.S_ISLNK(info.st_mode):
                    virtual[rel_text] = ('symlink', {'mode': mode, 'target': os.readlink(entry.path)})
                elif stat.S_ISREG(info.st_mode):
                    virtual[rel_text] = ('file', {'mode': mode, 'source': Path(entry.path)})

    def _snapshot_project_git(self, root: Path, previous: dict[str, Any] | None) -> dict[str, Any]:
        roots = self._project_git_roots(root)
        if roots is None:
            return {'version': 1, 'present': False, 'entries': {}}
        common, git_dir = roots
        virtual: dict[str, tuple[str, Any]] = {}
        self._scan_opaque_root(common, virtual)
        if git_dir != common:
            self._scan_opaque_root(git_dir, virtual)
        prior_entries = (previous or {}).get('entries') if isinstance(previous, dict) else {}
        prior_entries = prior_entries if isinstance(prior_entries, dict) else {}
        result: dict[str, Any] = {'version': 1, 'present': True, 'entries': {}}
        for rel in sorted(virtual, key=os.fsencode):
            kind, payload = virtual[rel]
            if kind != 'file':
                result['entries'][rel] = {'kind': kind, **payload}
                continue
            source = payload['source']
            sample = source.stat().st_size > self.large_file_threshold
            signature = _file_signature(source, sample=sample)
            prior = prior_entries.get(rel) if isinstance(prior_entries.get(rel), dict) else None
            if prior and prior.get('kind') == 'file':
                object_rel = str(prior.get('object') or '')
                candidate = self.history_root / object_rel
                strict_match = _same_signature(prior.get('signature'), signature)
                verified_metadata_only_match = bool(
                    sample
                    and not strict_match
                    and _same_sampled_content(prior.get('signature'), signature)
                    and candidate.is_file()
                    and _same_file_bytes(source, candidate)
                )
                if (
                    (strict_match or verified_metadata_only_match)
                    and candidate.is_file()
                    and candidate.stat().st_size == signature['size']
                ):
                    reused = _json_copy(prior)
                    reused['signature'] = signature
                    result['entries'][rel] = reused
                    continue
            if sample:
                object_path = self.opaque_objects / uuid.uuid4().hex
                storage = _copy_file_cow(source, object_path)
            else:
                digest = hashlib.sha256()
                with source.open('rb') as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                        digest.update(chunk)
                object_path = self.opaque_objects / digest.hexdigest()[:2] / digest.hexdigest()
                if not object_path.is_file():
                    storage = _copy_file_cow(source, object_path)
                else:
                    storage = 'content-addressed-reuse'
            after = _file_signature(source, sample=sample)
            if not _same_signature(signature, after) or object_path.stat().st_size != signature['size']:
                if storage not in {'content-addressed-reuse'}:
                    object_path.unlink(missing_ok=True)
                raise HistoryError(f'Project Git metadata changed while checkpointing: {rel}. Retry when Git is idle.')
            result['entries'][rel] = {
                'kind': 'file', 'mode': payload['mode'],
                'object': object_path.relative_to(self.history_root).as_posix(),
                'signature': signature, 'storage': storage,
            }
        return result

    def capture(
        self, root: Path, *, chat_id: str, checkpoint_id: str,
        previous_commit: str = '', previous_large: dict[str, Any] | None = None,
        previous_git: dict[str, Any] | None = None,
    ) -> HistorySnapshot:
        with self._locked():
            started = time.perf_counter()
            self._ensure_repo()
            root = self._validate_root(root)

            stage = time.perf_counter()
            ordinary, large, file_manifest, warnings = self._scan_work_tree(root)
            scan_seconds = time.perf_counter() - stage
            log_event(
                'history', 'checkpoint_stage_completed', chat_id=chat_id,
                checkpoint_id=checkpoint_id, stage='scan', seconds=round(scan_seconds, 6),
                ordinary_files=len(ordinary), large_files=len(large),
                manifest_entries=len(file_manifest.get('entries') or {}),
            )

            stage = time.perf_counter()
            large_manifest = self._snapshot_large_files(large, previous_large)
            large_seconds = time.perf_counter() - stage
            previous_large_entries = (
                (previous_large or {}).get('entries')
                if isinstance((previous_large or {}).get('entries'), dict) else {}
            )
            reused_large = sum(
                1 for rel, entry in (large_manifest.get('entries') or {}).items()
                if isinstance(previous_large_entries.get(rel), dict)
                and previous_large_entries[rel].get('object') == entry.get('object')
            )
            log_event(
                'history', 'checkpoint_stage_completed', chat_id=chat_id,
                checkpoint_id=checkpoint_id, stage='large_files', seconds=round(large_seconds, 6),
                files=len(large), reused_objects=reused_large,
                new_objects=max(0, len(large) - reused_large),
            )

            stage = time.perf_counter()
            git_manifest = self._snapshot_project_git(root, previous_git)
            project_git_seconds = time.perf_counter() - stage
            log_event(
                'history', 'checkpoint_stage_completed', chat_id=chat_id,
                checkpoint_id=checkpoint_id, stage='project_git',
                seconds=round(project_git_seconds, 6),
                present=bool(git_manifest.get('present')),
                entries=len(git_manifest.get('entries') or {}),
            )

            stage = time.perf_counter()
            non_git_paths = [rel for rel, _source in large]
            non_git_paths.extend(
                rel for rel, entry in (file_manifest.get('entries') or {}).items()
                if isinstance(entry, dict) and entry.get('kind') == 'unsupported'
            )
            commit, tree_reused = self._tree_commit(
                root, chat_id, checkpoint_id, ordinary, previous_commit,
                excluded_paths=non_git_paths,
                nested_git_roots=file_manifest.get('nested_git_roots') or (),
            )
            shadow_git_seconds = time.perf_counter() - stage
            total_seconds = time.perf_counter() - started
            log_event(
                'history', 'checkpoint_capture_completed', chat_id=chat_id,
                checkpoint_id=checkpoint_id, seconds=round(total_seconds, 6),
                scan_seconds=round(scan_seconds, 6),
                large_file_seconds=round(large_seconds, 6),
                project_git_seconds=round(project_git_seconds, 6),
                shadow_git_seconds=round(shadow_git_seconds, 6),
                shadow_tree_reused=tree_reused,
                ordinary_files=len(ordinary), large_files=len(large),
            )
            return HistorySnapshot(
                shadow_commit=commit,
                file_manifest=file_manifest,
                large_manifest=large_manifest,
                git_manifest=git_manifest,
                restorable=not warnings,
                warnings=warnings,
            )

    @staticmethod
    def _validated_history_path(relative_path: str) -> str:
        value = str(relative_path or '').replace('\\', '/').strip('/')
        path = Path(value)
        if not value or path.is_absolute() or any(part in {'', '.', '..'} for part in path.parts):
            raise HistoryError('Historical file path must be a safe relative file path.')
        if '\x00' in value:
            raise HistoryError('Historical file path contains an invalid character.')
        return Path(*path.parts).as_posix()

    def describe_path(
        self, *, shadow_commit: str, relative_path: str,
        file_manifest: dict[str, Any] | None = None,
        large_manifest: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Describe one path in an immutable snapshot without materializing it."""
        rel = self._validated_history_path(relative_path)
        with self._locked():
            self._ensure_repo()
            large_entries = (large_manifest or {}).get('entries')
            large_entries = large_entries if isinstance(large_entries, dict) else {}
            large = large_entries.get(rel)
            if isinstance(large, dict):
                signature = large.get('signature') if isinstance(large.get('signature'), dict) else {}
                object_rel = str(large.get('object') or '')
                source = (self.history_root / object_rel).resolve()
                exists = self.history_root in source.parents and source.is_file()
                return {
                    'exists': exists,
                    'path': rel,
                    'kind': 'file',
                    'storage': 'large_object',
                    'identity': f'large:{object_rel}',
                    'size': int(signature.get('size') or (source.stat().st_size if exists else 0)),
                    'mode': int(signature.get('mode') or 0),
                }

            result = self._git(['ls-tree', '-z', str(shadow_commit), '--', rel], check=False)
            if result.returncode != 0 or not result.stdout:
                return {'exists': False, 'path': rel, 'kind': 'missing', 'storage': 'none', 'identity': 'missing'}
            record = result.stdout.split(b'\0', 1)[0]
            try:
                header, _stored_path = record.split(b'\t', 1)
                mode_b, kind_b, object_b = header.split(b' ', 2)
                mode_text = mode_b.decode('ascii')
                kind_text = kind_b.decode('ascii')
                object_id = object_b.decode('ascii')
            except (ValueError, UnicodeDecodeError) as exc:
                raise HistoryError(f'Historical Git entry is invalid for {rel}.') from exc
            if kind_text == 'tree':
                return {
                    'exists': True, 'path': rel, 'kind': 'directory', 'storage': 'shadow_git',
                    'identity': f'git-tree:{object_id}', 'size': None, 'mode': int(mode_text, 8),
                }
            size_result = self._git(['cat-file', '-s', object_id], check=False)
            try:
                size = int(size_result.stdout.strip()) if size_result.returncode == 0 else 0
            except ValueError:
                size = 0
            return {
                'exists': True,
                'path': rel,
                'kind': 'symlink' if mode_text == '120000' else 'file',
                'storage': 'shadow_git',
                'identity': f'git:{object_id}',
                'object_id': object_id,
                'size': size,
                'mode': int(mode_text, 8),
            }

    def read_path(
        self, *, shadow_commit: str, relative_path: str,
        file_manifest: dict[str, Any] | None = None,
        large_manifest: dict[str, Any] | None = None,
        max_bytes: int | None = None,
    ) -> tuple[bytes, dict[str, Any]]:
        descriptor = self.describe_path(
            shadow_commit=shadow_commit, relative_path=relative_path,
            file_manifest=file_manifest, large_manifest=large_manifest,
        )
        if not descriptor.get('exists') or descriptor.get('kind') == 'directory':
            raise FileNotFoundError(relative_path)
        size = int(descriptor.get('size') or 0)
        if max_bytes is not None and size > max(0, int(max_bytes)):
            raise HistoryError(f'Historical file is too large to preview ({size} bytes).')
        with self._locked():
            if descriptor.get('storage') == 'large_object':
                object_rel = str(descriptor.get('identity') or '').removeprefix('large:')
                source = (self.history_root / object_rel).resolve()
                if self.history_root not in source.parents or not source.is_file():
                    raise HistoryError(f'Historical object is missing: {object_rel}')
                return source.read_bytes(), descriptor
            object_id = str(descriptor.get('object_id') or '')
            result = self._git(['cat-file', 'blob', object_id])
            return bytes(result.stdout), descriptor

    def list_snapshot_paths(
        self, *, shadow_commit: str, file_manifest: dict[str, Any] | None = None,
        large_manifest: dict[str, Any] | None = None,
    ) -> list[str]:
        with self._locked():
            self._ensure_repo()
            result = self._git(['ls-tree', '-r', '-z', '--name-only', str(shadow_commit)], check=False)
            values = {
                os.fsdecode(item) for item in result.stdout.split(b'\0') if item
            } if result.returncode == 0 else set()
            large_entries = (large_manifest or {}).get('entries')
            if isinstance(large_entries, dict):
                values.update(str(key) for key in large_entries)
            return sorted(values, key=os.fsencode)

    def restore_path(
        self, destination: Path, *, shadow_commit: str, relative_path: str,
        file_manifest: dict[str, Any] | None = None,
        large_manifest: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        descriptor = self.describe_path(
            shadow_commit=shadow_commit, relative_path=relative_path,
            file_manifest=file_manifest, large_manifest=large_manifest,
        )
        if not descriptor.get('exists') or descriptor.get('kind') == 'directory':
            raise FileNotFoundError(relative_path)
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.unlink(missing_ok=True)
        if descriptor.get('storage') == 'large_object':
            object_rel = str(descriptor.get('identity') or '').removeprefix('large:')
            source = (self.history_root / object_rel).resolve()
            if self.history_root not in source.parents or not source.is_file():
                raise HistoryError(f'Historical object is missing: {object_rel}')
            _copy_file_cow(source, destination)
        else:
            raw, _ = self.read_path(
                shadow_commit=shadow_commit, relative_path=relative_path,
                file_manifest=file_manifest, large_manifest=large_manifest,
            )
            if descriptor.get('kind') == 'symlink':
                os.symlink(os.fsdecode(raw), destination)
            else:
                destination.write_bytes(raw)
        mode = int(descriptor.get('mode') or 0)
        if mode and descriptor.get('kind') != 'symlink':
            os.chmod(destination, mode, follow_symlinks=False)
        return descriptor

    def _restore_object(
        self, entry: dict[str, Any], destination: Path, *, cancel_event: Any | None = None,
    ) -> None:
        object_rel = str(entry.get('object') or '')
        source = (self.history_root / object_rel).resolve()
        if self.history_root not in source.parents or not source.is_file():
            raise HistoryError(f'Historical object is missing: {object_rel}')
        expected = int((entry.get('signature') or {}).get('size') or source.stat().st_size)
        if source.stat().st_size != expected:
            raise HistoryError(f'Historical object size mismatch: {object_rel}')
        _copy_file_cow(source, destination, cancel_event=cancel_event)
        mode = int((entry.get('signature') or {}).get('mode') or entry.get('mode') or 0)
        if mode:
            os.chmod(destination, mode, follow_symlinks=False)

    def _restore_git_metadata(
        self, manifest: dict[str, Any], destination_root: Path, *, cancel_event: Any | None = None,
    ) -> None:
        if not bool(manifest.get('present')):
            return
        git_root = destination_root / '.git'
        git_root.mkdir(parents=True, exist_ok=True)
        entries = manifest.get('entries') if isinstance(manifest.get('entries'), dict) else {}
        for rel, entry in sorted(entries.items(), key=lambda row: (len(Path(row[0]).parts), os.fsencode(row[0]))):
            _raise_if_cancelled(cancel_event)
            target = git_root / rel
            kind = str(entry.get('kind') or '')
            if kind == 'directory':
                target.mkdir(parents=True, exist_ok=True)
            elif kind == 'symlink':
                target.parent.mkdir(parents=True, exist_ok=True)
                target.unlink(missing_ok=True)
                os.symlink(str(entry.get('target') or ''), target)
            elif kind == 'file':
                target.parent.mkdir(parents=True, exist_ok=True)
                self._restore_object(entry, target, cancel_event=cancel_event)
        # Never let a copied absolute core.worktree point Git commands back at
        # the original timeline. This edits only the private branch copy.
        _run([
            'git', f'--git-dir={git_root}', 'config', '--local', 'core.worktree', '..',
        ], env=self._plain_git_env())
        probe = _run(['git', '-C', str(destination_root), 'rev-parse', '--is-inside-work-tree'], env=self._plain_git_env(), check=False)
        if probe.returncode != 0 or probe.stdout.strip() != b'true':
            raise HistoryError('Restored project Git metadata is not a usable isolated repository.')

    def materialize(
        self, destination: Path, *, shadow_commit: str, file_manifest: dict[str, Any],
        large_manifest: dict[str, Any], git_manifest: dict[str, Any], cancel_event: Any | None = None,
    ) -> None:
        with self._locked():
            _raise_if_cancelled(cancel_event)
            self._ensure_repo()
            if self._git(['cat-file', '-e', f'{shadow_commit}^{{commit}}'], check=False).returncode != 0:
                raise HistoryError('The historical shadow commit is missing.')
            if destination.exists() and any(destination.iterdir()):
                raise HistoryError('Historical branch destination is not empty.')
            destination.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='restore-', dir=self.tmp) as tmp_name:
                index = Path(tmp_name) / 'index'
                self._git(['read-tree', shadow_commit], index=index)
                prefix = str(destination.resolve()) + os.sep
                self._git(
                    ['checkout-index', '--all', '--force', f'--prefix={prefix}'],
                    work_tree=destination, index=index,
                )
            _raise_if_cancelled(cancel_event)

            large_entries = large_manifest.get('entries') if isinstance(large_manifest.get('entries'), dict) else {}
            for rel, entry in sorted(large_entries.items(), key=lambda row: os.fsencode(row[0])):
                _raise_if_cancelled(cancel_event)
                target = destination / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.unlink(missing_ok=True)
                self._restore_object(entry, target, cancel_event=cancel_event)

            entries = file_manifest.get('entries') if isinstance(file_manifest.get('entries'), dict) else {}
            for rel, entry in sorted(entries.items(), key=lambda row: (len(Path(row[0]).parts), os.fsencode(row[0]))):
                _raise_if_cancelled(cancel_event)
                target = destination / rel
                if entry.get('kind') == 'directory':
                    target.mkdir(parents=True, exist_ok=True)
                if target.exists() and not target.is_symlink():
                    try:
                        os.chmod(target, int(entry.get('mode') or 0), follow_symlinks=False)
                    except OSError:
                        pass
            try:
                os.chmod(destination, int(file_manifest.get('root_mode') or 0), follow_symlinks=False)
            except OSError:
                pass
            self._restore_git_metadata(git_manifest, destination, cancel_event=cancel_event)
            _raise_if_cancelled(cancel_event)
