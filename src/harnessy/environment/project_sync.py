"""Conflict-checked project synchronization for guests without shared mounts.

Never recursively delete source trees or follow a guest-controlled symlink.
A changed path is applied only if its host value still matches the common
baseline; conflicts preserve both copies and stop synchronization.
"""
from __future__ import annotations

import hashlib
import io
import os
import stat
import tarfile
import tempfile
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_PROJECT_BYTES = 512 * 1024 * 1024
MAX_PROJECT_ENTRIES = 100_000


@dataclass(frozen=True)
class Entry:
    kind: str
    data: bytes = b''
    mode: int = 0o644

    @property
    def signature(self) -> str:
        return self.kind + ':' + hashlib.sha256(self.data).hexdigest() + ':' + oct(self.mode & 0o777)


def relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in {'..', ''} for part in path.parts) or '\\' in value or '\x00' in value:
        raise ValueError('Invalid synchronized project path.')
    return path.as_posix()


def _safe_link(name: str, target: str) -> None:
    if not target or PurePosixPath(target).is_absolute() or '\x00' in target or '\\' in target:
        raise ValueError('Project symlinks must have relative targets within the selected project: ' + name)
    parts = list(PurePosixPath(name).parent.parts)
    for part in PurePosixPath(target).parts:
        if part == '..':
            if not parts:
                raise ValueError('Project symlink leaves the selected project: ' + name)
            parts.pop()
        elif part != '.':
            parts.append(part)


def scan_tree(root: Path, *, excluded: tuple[str, ...] = ()) -> dict[str, Entry]:
    root = Path(root)
    rows: dict[str, Entry] = {}
    total = 0
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0)
    root_fd = os.open(root, flags)
    def visit(directory_fd: int, prefix: str = '') -> None:
        nonlocal total
        with os.scandir(directory_fd) as iterator:
            names = sorted(item.name for item in iterator)
        for basename in names:
            name = relative_path(prefix + basename)
            if any(name == part or name.startswith(part + '/') for part in excluded):
                continue
            metadata = os.stat(basename, dir_fd=directory_fd, follow_symlinks=False)
            mode = stat.S_IMODE(metadata.st_mode) & 0o777
            if stat.S_ISLNK(metadata.st_mode):
                target = os.readlink(basename, dir_fd=directory_fd)
                _safe_link(name, target)
                entry = Entry('link', target.encode(), mode)
            elif stat.S_ISDIR(metadata.st_mode):
                entry = Entry('directory', mode=mode)
            elif stat.S_ISREG(metadata.st_mode):
                descriptor = os.open(basename, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0), dir_fd=directory_fd)
                with os.fdopen(descriptor, 'rb') as stream:
                    opened = os.fstat(stream.fileno())
                    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise RuntimeError('Project changed during synchronization: ' + name)
                    if opened.st_size > MAX_PROJECT_BYTES - total:
                        raise ValueError('Project synchronization exceeds its 512 MiB limit; use a smaller project or explicit artifact transfer.')
                    data = stream.read(MAX_PROJECT_BYTES - total + 1)
                    after = os.fstat(stream.fileno())
                    if (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns):
                        raise RuntimeError('Project file changed during synchronization: ' + name)
                total += len(data)
                entry = Entry('file', data, mode)
            else:
                raise ValueError('Special files cannot be synchronized: ' + name)
            if len(rows) >= MAX_PROJECT_ENTRIES or total > MAX_PROJECT_BYTES:
                raise ValueError('Project synchronization limit exceeded.')
            rows[name] = entry
            if entry.kind == 'directory':
                child_fd = os.open(basename, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise RuntimeError('Project directory changed during synchronization: ' + name)
                    visit(child_fd, name + '/')
                finally:
                    os.close(child_fd)
    try:
        visit(root_fd)
    finally:
        os.close(root_fd)
    return rows


def archive_tree(rows: dict[str, Entry]) -> bytes:
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w') as archive:
        for name, entry in sorted(rows.items()):
            info = tarfile.TarInfo(relative_path(name))
            info.mode, info.uid, info.gid = entry.mode, 0, 0
            if entry.kind == 'directory':
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif entry.kind == 'link':
                target = entry.data.decode()
                _safe_link(name, target)
                info.type, info.linkname = tarfile.SYMTYPE, target
                archive.addfile(info)
            elif entry.kind == 'file':
                info.size = len(entry.data)
                archive.addfile(info, io.BytesIO(entry.data))
            else:
                raise ValueError('Unsupported project entry.')
    return data.getvalue()


def read_archive(data: bytes) -> dict[str, Entry]:
    if len(data) > MAX_PROJECT_BYTES + MAX_PROJECT_ENTRIES * 1024:
        raise ValueError('Guest project archive exceeds the transfer limit.')
    rows: dict[str, Entry] = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as archive:
        for info in archive:
            name = info.name.removeprefix('./').rstrip('/')
            if name in {'', '.'}:
                continue
            name = relative_path(name)
            if name in rows or len(rows) >= MAX_PROJECT_ENTRIES:
                raise ValueError('Guest project archive contains repeated paths or too many entries.')
            if info.isdir():
                entry = Entry('directory', mode=info.mode & 0o777)
            elif info.issym():
                _safe_link(name, info.linkname)
                entry = Entry('link', info.linkname.encode(), info.mode & 0o777)
            elif info.isfile():
                total += info.size
                if total > MAX_PROJECT_BYTES:
                    raise ValueError('Guest project files exceed the synchronization limit.')
                stream = archive.extractfile(info)
                if stream is None:
                    raise ValueError('Guest project file payload is missing.')
                payload = stream.read(info.size + 1)
                if len(payload) != info.size:
                    raise ValueError('Guest project file payload is incomplete.')
                entry = Entry('file', payload, info.mode & 0o777)
            else:
                raise ValueError('Guest project archive contains hardlinks or special files: ' + name)
            rows[name] = entry
    for name in rows:
        for parent in PurePosixPath(name).parents:
            if parent.as_posix() != '.' and parent.as_posix() in rows and rows[parent.as_posix()].kind != 'directory':
                raise ValueError('Guest archive traverses a file or symlink: ' + name)
    return rows


def signatures(rows: dict[str, Entry]) -> dict[str, str]:
    return {name: entry.signature for name, entry in rows.items()}


def _checked_destination(root: Path, name: str) -> Path:
    target = root / relative_path(name)
    for part in target.relative_to(root).parts[:-1]:
        root = root / part
        if root.is_symlink() or (root.exists() and not root.is_dir()):
            raise RuntimeError('Project synchronization refused a symlink or file in the destination path: ' + name)
    return target


def merge_guest_changes(root: Path, baseline: dict[str, str], guest: dict[str, Entry], *, excluded: tuple[str, ...] = ()) -> dict[str, Entry]:
    root = Path(root)
    def blocked(name):
        return any(name == part or name.startswith(part + '/') for part in excluded)
    # Empty ancestor mount-point directories are controller scaffolding. Their
    # contents are never a writable part of the selected project.
    forbidden = [name for name, entry in guest.items() if blocked(name) and entry.kind != 'directory']
    if forbidden:
        raise RuntimeError('Guest changes target a protected project path: ' + ', '.join(sorted(forbidden)[:12]))
    guest = {name: entry for name, entry in guest.items() if not blocked(name)}
    baseline = {name: value for name, value in baseline.items() if not blocked(name)}
    current = scan_tree(root, excluded=excluded)
    current_signatures, guest_signatures = signatures(current), signatures(guest)
    changed = {name for name in baseline.keys() | guest.keys() if baseline.get(name) != guest_signatures.get(name)}
    conflicts = [name for name in changed if current_signatures.get(name) not in {baseline.get(name), guest_signatures.get(name)}]
    for name in changed:
        old, new = current.get(name), guest.get(name)
        if old and old.kind == 'directory' and (new is None or new.kind != 'directory'):
            if any(child.startswith(name + '/') and child not in changed for child in current):
                conflicts.append(name)
    if conflicts:
        raise RuntimeError('Project synchronization conflict; both copies were preserved: ' + ', '.join(sorted(set(conflicts))[:12]))
    if not changed:
        return current
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0)
    root_fd = os.open(root, flags)
    opened_root = os.fstat(root_fd)
    # All new payloads and original backups are staged before source changes.
    # The journal is on the same filesystem so rollback uses renames/hardlinks,
    # rather than depending on available space after an I/O failure.
    journal = Path(tempfile.mkdtemp(prefix='.harnessy-sync-transaction-', dir=root.parent))
    journal_fd = os.open(journal, flags)
    originals: dict[str, str] = {}
    staged: dict[str, str] = {}
    def parent_fd(name, *, create=False):
        fd = os.dup(root_fd)
        try:
            parts = PurePosixPath(relative_path(name)).parts
            for part in parts[:-1]:
                if create:
                    try: os.mkdir(part, 0o755, dir_fd=fd)
                    except FileExistsError: pass
                child = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = child
            return fd, parts[-1]
        except BaseException:
            os.close(fd)
            raise
    def remove(name):
        fd, basename = parent_fd(name)
        try:
            try: metadata = os.stat(basename, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError: return
            if stat.S_ISDIR(metadata.st_mode): os.rmdir(basename, dir_fd=fd)
            else: os.unlink(basename, dir_fd=fd)
        finally: os.close(fd)
    def directory(name, mode):
        fd, basename = parent_fd(name, create=True)
        try:
            try: os.mkdir(basename, mode, dir_fd=fd)
            except FileExistsError: pass
            child = os.open(basename, flags, dir_fd=fd)
            try: os.fchmod(child, mode)
            finally: os.close(child)
        finally: os.close(fd)
    mutated = False
    try:
        for index, name in enumerate(sorted(changed)):
            old, new = current.get(name), guest.get(name)
            if old and old.kind != 'directory':
                fd, basename = parent_fd(name)
                backup = 'old-' + str(index)
                try:
                    if old.kind == 'file':
                        os.link(basename, backup, src_dir_fd=fd, dst_dir_fd=journal_fd, follow_symlinks=False)
                    else:
                        os.symlink(old.data.decode(), backup, dir_fd=journal_fd)
                finally: os.close(fd)
                originals[name] = backup
            if new and new.kind != 'directory':
                payload = 'new-' + str(index)
                if new.kind == 'file':
                    descriptor = os.open(payload, os.O_WRONLY | os.O_CREAT | os.O_EXCL, new.mode, dir_fd=journal_fd)
                    with os.fdopen(descriptor, 'wb') as stream:
                        stream.write(new.data)
                        stream.flush()
                        os.fchmod(stream.fileno(), new.mode)
                else:
                    os.symlink(new.data.decode(), payload, dir_fd=journal_fd)
                staged[name] = payload
        # Detect another actor replacing the root while the journal was built.
        current_root = root.stat(follow_symlinks=False)
        if (current_root.st_dev, current_root.st_ino) != (opened_root.st_dev, opened_root.st_ino):
            raise RuntimeError('Selected project root changed during synchronization.')
        if signatures(scan_tree(root, excluded=excluded)) != current_signatures:
            raise RuntimeError('Project changed during synchronization; source changes were not applied.')
        mutated = True
        for name in sorted(changed, key=lambda value: (-value.count('/'), value)):
            old, new = current.get(name), guest.get(name)
            if old and (new is None or (old.kind == 'directory' and new.kind != 'directory') or (old.kind != 'directory' and new.kind == 'directory')):
                remove(name)
        for name in sorted(changed, key=lambda value: (value.count('/'), value)):
            entry = guest.get(name)
            if entry is None: continue
            if entry.kind == 'directory': directory(name, entry.mode)
            else:
                fd, basename = parent_fd(name, create=True)
                try: os.replace(staged[name], basename, src_dir_fd=journal_fd, dst_dir_fd=fd)
                finally: os.close(fd)
        return scan_tree(root, excluded=excluded)
    except BaseException as error:
        if mutated:
            try:
                for name in sorted(changed, key=lambda value: (-value.count('/'), value)):
                    try: remove(name)
                    except FileNotFoundError: pass
                for name in sorted(changed, key=lambda value: (value.count('/'), value)):
                    old = current.get(name)
                    if old is None: continue
                    if old.kind == 'directory': directory(name, old.mode)
                    else:
                        fd, basename = parent_fd(name, create=True)
                        try: os.replace(originals[name], basename, src_dir_fd=journal_fd, dst_dir_fd=fd)
                        finally: os.close(fd)
            except BaseException as rollback_error:
                raise RuntimeError('Project synchronization failed and rollback was incomplete. Original files were retained in ' + str(journal) + ': ' + str(rollback_error)) from error
        raise
    finally:
        os.close(root_fd)
        os.close(journal_fd)
        # Keep the journal if rollback could not restore all originals.
        if not any(journal.glob('old-*')) or not mutated:
            import shutil
            shutil.rmtree(journal)
        elif sys.exc_info()[0] is None:
            import shutil
            shutil.rmtree(journal)
