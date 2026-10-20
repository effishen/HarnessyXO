"""A single-export SFTP v3 endpoint for an owned SSHFS passive channel.

This is a protocol endpoint, not an SSH server: the caller supplies the byte
streams of its authenticated, owned guest connection. There is no listener,
shell, subprocess, host account access or whole-tree inventory here. Every
filesystem operation stays relative to a pinned export directory descriptor.
Symlinks, multiply linked files and special files are deliberately unavailable.
Excluded subtrees appear only as empty, read-only mount-point directories.

``mutation`` is an optional zero-argument async context-manager factory. The
caller can use it to serialize each filesystem mutation with project writers.
Revoking the supplied event closes this endpoint and all its open handles.
``status_callback`` receives fixed operational metadata, never paths or data.

Wire formats: draft-ietf-secsh-filexfer-02 and OpenSSH's PROTOCOL document.
"""
from __future__ import annotations

import asyncio
import contextlib
import ctypes
import errno
import inspect
import os
import secrets
import stat
import struct
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncContextManager, Callable

MAX_PACKET = 512 * 1024
MAX_READ = 128 * 1024
MAX_WRITE = 256 * 1024
MAX_HANDLES = 128
MAX_READDIR = 128
MAX_PATH = 4096
MAX_FILE_OFFSET = (1 << 63) - 1

_U32 = struct.Struct('>I')
_U64 = struct.Struct('>Q')
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_OK, _EOF, _NO_FILE, _DENIED, _FAILURE, _BAD_MESSAGE, _UNSUPPORTED = 0, 1, 2, 3, 4, 5, 8
_MESSAGES = {
    _OK: b'OK', _EOF: b'End of file', _NO_FILE: b'No such file',
    _DENIED: b'Access denied', _FAILURE: b'Filesystem operation failed',
    _BAD_MESSAGE: b'Invalid request', _UNSUPPORTED: b'Operation unsupported',
}


def _string(value: bytes) -> bytes:
    return _U32.pack(len(value)) + value


class _PacketError(ValueError):
    pass


class _Unsupported(Exception):
    pass


class _RootReplaced(PermissionError):
    pass


class _Packet:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise _PacketError('Truncated request')
        result = self.data[self.offset:self.offset + size]
        self.offset += size
        return result

    def uint32(self) -> int:
        return _U32.unpack(self.take(4))[0]

    def uint64(self) -> int:
        return _U64.unpack(self.take(8))[0]

    def string(self, maximum: int = MAX_PATH) -> bytes:
        size = self.uint32()
        if size > maximum:
            raise _PacketError('Field too large')
        return self.take(size)

    def end(self) -> None:
        if self.offset != len(self.data):
            raise _PacketError('Unexpected request fields')

    def attrs(self) -> dict[str, int]:
        flags = self.uint32()
        if flags & ~0x8000000F:
            raise _PacketError('Invalid attribute flags')
        result: dict[str, int] = {}
        if flags & 1:
            result['size'] = self.uint64()
        if flags & 2:
            result['uid'], result['gid'] = self.uint32(), self.uint32()
        if flags & 4:
            result['mode'] = self.uint32()
        if flags & 8:
            result['atime'], result['mtime'] = self.uint32(), self.uint32()
        if flags & 0x80000000:
            count = self.uint32()
            if count > 16:
                raise _PacketError('Too many extended attributes')
            for _ in range(count):
                self.string(), self.string()
            if count:
                raise _Unsupported()
        return result


def _attrs(value: os.stat_result | None = None) -> bytes:
    if value is None:
        # A mount-point placeholder has no relation to hidden host contents.
        values = (0, os.getuid(), os.getgid(), stat.S_IFDIR | 0o555, 0, 0)
    else:
        values = (max(0, value.st_size), value.st_uid, value.st_gid,
                  value.st_mode, max(0, int(value.st_atime)), max(0, int(value.st_mtime)))
    size, uid, gid, mode, atime, mtime = values
    return struct.pack('>IQIIIII', 15, size, uid & 0xFFFFFFFF, gid & 0xFFFFFFFF,
                       mode & 0xFFFFFFFF, min(atime, 0xFFFFFFFF), min(mtime, 0xFFFFFFFF))


def _parts(raw: bytes) -> tuple[str, ...]:
    if len(raw) > MAX_PATH or b'\x00' in raw or b'\\' in raw:
        raise PermissionError(errno.EACCES, 'Invalid export path')
    value = os.fsdecode(raw)
    result = tuple(part for part in value.split('/') if part not in {'', '.'})
    if len(result) > 256 or '..' in result:
        raise PermissionError(errno.EACCES, 'Path traversal denied')
    return result


def _name_key(value: str) -> str:
    """Conservatively protect aliases on case/normalization-insensitive hosts."""
    return unicodedata.normalize('NFD', unicodedata.normalize('NFD', value).casefold())


def _path_key(parts: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(_name_key(part) for part in parts)


def _checked_kind(value: os.stat_result) -> None:
    if not (stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode)):
        raise PermissionError(errno.EACCES, 'Unsupported export entry')
    if stat.S_ISREG(value.st_mode) and value.st_nlink != 1:
        raise PermissionError(errno.EACCES, 'Multiply linked file denied')


def _root_descriptor(path: Path) -> int:
    """Open every component without following a symlink, including ancestors."""
    absolute = os.path.abspath(os.fspath(path))
    descriptor = os.open('/', _DIRECTORY)
    try:
        for part in Path(absolute).parts[1:]:
            child = os.open(part, _DIRECTORY, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _rename_noreplace(old_fd: int, old: str, new_fd: int, new: str) -> None:
    """The v3 no-overwrite promise needs an atomic OS operation, not a stat."""
    library = ctypes.CDLL(None, use_errno=True)
    symbol, flags = ('renameatx_np', 4) if sys.platform == 'darwin' else ('renameat2', 1)
    function = getattr(library, symbol, None)
    if function is None:
        raise _Unsupported()
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(old_fd, os.fsencode(old), new_fd, os.fsencode(new), flags) != 0:
        number = ctypes.get_errno()
        if number in {errno.ENOSYS, errno.ENOTSUP, errno.EINVAL}:
            raise _Unsupported()
        raise OSError(number, 'Export rename failed')


@dataclass
class _Handle:
    fd: int | None
    parts: tuple[str, ...]
    readable: bool = False
    writable: bool = False
    append: bool = False
    iterator: Any = None
    placeholders: tuple[str, ...] = ()
    placeholder_index: int = 0
    virtual: bool = False

    def close(self) -> None:
        if self.iterator is not None:
            self.iterator.close()
            self.iterator = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class _Export:
    def __init__(self, root: Path, writable: bool, excluded: tuple[str, ...]):
        if len(excluded) > 256:
            raise ValueError('Too many export exclusions.')
        self.excluded = tuple(_parts(os.fsencode(path)) for path in excluded)
        if any(not path for path in self.excluded):
            raise ValueError('An export exclusion cannot hide its root.')
        self.excluded_keys = tuple(_path_key(path) for path in self.excluded)
        self.root_path = Path(os.path.abspath(os.fspath(root)))
        self.root = _root_descriptor(root)
        self.root_identity = os.fstat(self.root)
        self.writable = writable
        self.handles: dict[bytes, _Handle] = {}

    def check_root(self) -> None:
        """An unplugged/replaced source must not keep serving its old inode."""
        try:
            descriptor = _root_descriptor(self.root_path)
        except OSError as error:
            raise _RootReplaced(errno.EACCES, 'Export root unavailable') from error
        try:
            current = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != (self.root_identity.st_dev, self.root_identity.st_ino):
                raise _RootReplaced(errno.EACCES, 'Export root replaced')
        finally:
            os.close(descriptor)

    def close(self) -> None:
        for handle in self.handles.values():
            handle.close()
        self.handles.clear()
        if self.root >= 0:
            os.close(self.root)
            self.root = -1

    def hidden(self, parts: tuple[str, ...]) -> bool:
        key = _path_key(parts)
        return any(len(key) > len(path) and key[:len(path)] == path for path in self.excluded_keys)

    def virtual(self, parts: tuple[str, ...]) -> bool:
        return _path_key(parts) in self.excluded_keys

    def placeholders(self, parts: tuple[str, ...]) -> tuple[str, ...]:
        key = _path_key(parts)
        names: dict[str, str] = {}
        for path, protected in zip(self.excluded, self.excluded_keys):
            if len(protected) > len(key) and protected[:len(key)] == key:
                name = path[len(key)]
                names.setdefault(_name_key(name), name)
        return tuple(sorted(names.values()))

    def check(self, parts: tuple[str, ...], *, mutate: bool = False) -> None:
        if self.hidden(parts):
            raise FileNotFoundError(errno.ENOENT, 'Excluded export path')
        key = _path_key(parts)
        if mutate and (not self.writable or not key or any(
                key[:len(path)] == path or path[:len(key)] == key for path in self.excluded_keys)):
            raise PermissionError(errno.EACCES, 'Protected export path')

    @contextlib.contextmanager
    def parent(self, parts: tuple[str, ...]):
        self.check(parts)
        descriptor = os.dup(self.root)
        try:
            for part in parts[:-1]:
                child = os.open(part, _DIRECTORY, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            yield descriptor, parts[-1] if parts else '.'
        finally:
            os.close(descriptor)

    def metadata(self, parts: tuple[str, ...]) -> os.stat_result | None:
        self.check(parts)
        if self.virtual(parts):
            return None
        try:
            with self.parent(parts) as (parent, name):
                result = os.stat(name, dir_fd=parent, follow_symlinks=False)
                _checked_kind(result)
                return result
        except FileNotFoundError:
            if self.placeholders(parts):
                return None
            raise

    def descriptor(self, parts: tuple[str, ...], flags: int = os.O_RDONLY) -> int:
        self.check(parts)
        if self.virtual(parts):
            raise PermissionError(errno.EACCES, 'Virtual export directory')
        with self.parent(parts) as (parent, name):
            descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        try:
            _checked_kind(os.fstat(descriptor))
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def add(self, handle: _Handle) -> bytes:
        if len(self.handles) >= MAX_HANDLES:
            handle.close()
            raise OSError(errno.EMFILE, 'Export handle limit reached')
        token = secrets.token_bytes(16)
        self.handles[token] = handle
        return token

    def handle(self, token: bytes, *, directory: bool = False) -> _Handle:
        handle = self.handles.get(token)
        if handle is None or (directory != (handle.iterator is not None or handle.virtual)):
            raise OSError(errno.EBADF, 'Unknown export handle')
        if handle.fd is not None:
            opened = os.fstat(handle.fd)
            _checked_kind(opened)
            # Do not write/read a pinned inode that a host process moved out of
            # this export or replaced. In-export renames update handle paths.
            current = self.metadata(handle.parts)
            if current is None or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise PermissionError(errno.EACCES, 'Export handle path changed')
        return handle

    def _setattrs(self, descriptor: int, values: dict[str, int]) -> None:
        current = os.fstat(descriptor)
        _checked_kind(current)
        if 'uid' in values and (values['uid'], values['gid']) != (current.st_uid, current.st_gid):
            raise PermissionError(errno.EPERM, 'Ownership changes unavailable')
        if 'size' in values and (not stat.S_ISREG(current.st_mode) or values['size'] > MAX_FILE_OFFSET):
            raise PermissionError(errno.EACCES, 'Invalid file size')
        if 'mode' in values and values['mode'] & 0o7000:
            raise PermissionError(errno.EACCES, 'Special permission bits unavailable')
        if 'size' in values:
            os.ftruncate(descriptor, values['size'])
        if 'mode' in values:
            os.fchmod(descriptor, values['mode'] & 0o777)
        if 'atime' in values:
            os.utime(descriptor, ns=(values['atime'] * 1_000_000_000, values['mtime'] * 1_000_000_000))

    def request(self, kind: int, packet: _Packet) -> tuple[int, bytes]:
        """Execute one fully parsed request; return response type and payload."""
        if kind == 3:  # OPEN. Validate before create/truncate and before handle allocation.
            parts, flags, values = _parts(packet.string()), packet.uint32(), packet.attrs()
            packet.end()
            if flags & ~63 or not flags & 3 or flags & 60 and not flags & 2 or flags & 32 and not flags & 8:
                raise _PacketError('Invalid open flags')
            self.check(parts, mutate=bool(flags & 2))
            if not parts or self.virtual(parts):
                raise IsADirectoryError(errno.EISDIR, 'Export directory')
            if len(self.handles) >= MAX_HANDLES:
                raise OSError(errno.EMFILE, 'Export handle limit reached')
            if set(values) - {'mode'}:
                raise _Unsupported()
            if values.get('mode', 0) & 0o7000:
                raise PermissionError(errno.EACCES, 'Special permission bits unavailable')
            access = os.O_RDWR if flags & 1 and flags & 2 else os.O_WRONLY if flags & 2 else os.O_RDONLY
            with self.parent(parts) as (parent, name):
                options = access | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
                if flags & 4:
                    options |= os.O_APPEND
                if flags & 8:
                    try:
                        descriptor = os.open(name, options | os.O_CREAT | os.O_EXCL,
                                             values.get('mode', 0o644) & 0o777, dir_fd=parent)
                    except FileExistsError:
                        if flags & 32:
                            raise
                        _checked_kind(os.stat(name, dir_fd=parent, follow_symlinks=False))
                        descriptor = os.open(name, options, dir_fd=parent)
                else:
                    _checked_kind(os.stat(name, dir_fd=parent, follow_symlinks=False))
                    descriptor = os.open(name, options, dir_fd=parent)
            try:
                current = os.fstat(descriptor)
                _checked_kind(current)
                if not stat.S_ISREG(current.st_mode):
                    raise IsADirectoryError(errno.EISDIR, 'Export directory')
                if flags & 16:
                    os.ftruncate(descriptor, 0)
                token = self.add(_Handle(descriptor, parts, bool(flags & 1), bool(flags & 2), bool(flags & 4)))
                descriptor = -1
                return 102, _string(token)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        if kind == 4:  # CLOSE
            token = packet.string(128)
            packet.end()
            handle = self.handles.pop(token, None)
            if handle is None:
                raise OSError(errno.EBADF, 'Unknown export handle')
            handle.close()
            return 101, _U32.pack(_OK) + _string(_MESSAGES[_OK]) + _string(b'')
        if kind == 5:  # READ
            token, offset, size = packet.string(128), packet.uint64(), packet.uint32()
            packet.end()
            handle = self.handle(token)
            if not handle.readable or offset > MAX_FILE_OFFSET:
                raise PermissionError(errno.EACCES, 'Read unavailable')
            data = os.pread(handle.fd, min(size, MAX_READ), offset)
            if not data and size:
                return 101, _U32.pack(_EOF) + _string(_MESSAGES[_EOF]) + _string(b'')
            return 103, _string(data)
        if kind == 6:  # WRITE
            token, offset, data = packet.string(128), packet.uint64(), packet.string(MAX_WRITE)
            packet.end()
            handle = self.handle(token)
            self.check(handle.parts, mutate=True)
            if not handle.writable or offset > MAX_FILE_OFFSET - len(data):
                raise PermissionError(errno.EACCES, 'Write unavailable')
            written = 0
            while written < len(data):
                count = (os.write(handle.fd, data[written:]) if handle.append else
                         os.pwrite(handle.fd, data[written:], offset + written))
                if count <= 0:
                    raise OSError(errno.EIO, 'Incomplete export write')
                written += count
            return self.ok()
        if kind in {7, 17}:  # LSTAT / STAT; neither follows symlinks.
            parts = _parts(packet.string())
            packet.end()
            return 105, _attrs(self.metadata(parts))
        if kind == 8:  # FSTAT
            token = packet.string(128)
            packet.end()
            handle = self.handles.get(token)
            if handle is None:
                raise OSError(errno.EBADF, 'Unknown export handle')
            self.handle(token, directory=handle.iterator is not None or handle.virtual)
            value = os.fstat(handle.fd) if handle.fd is not None else None
            if value is not None:
                _checked_kind(value)
            return 105, _attrs(value)
        if kind in {9, 10}:  # SETSTAT / FSETSTAT
            name, values = packet.string(128 if kind == 10 else MAX_PATH), packet.attrs()
            packet.end()
            if kind == 10:
                handle = self.handles.get(name)
                if handle is None or handle.fd is None:
                    raise OSError(errno.EBADF, 'Unknown export handle')
                self.handle(name, directory=handle.iterator is not None or handle.virtual)
                self.check(handle.parts, mutate=True)
                if not handle.writable:
                    raise PermissionError(errno.EACCES, 'Read-only export handle')
                self._setattrs(handle.fd, values)
            else:
                parts = _parts(name)
                self.check(parts, mutate=True)
                descriptor = self.descriptor(parts, os.O_WRONLY if 'size' in values else os.O_RDONLY)
                try:
                    self._setattrs(descriptor, values)
                finally:
                    os.close(descriptor)
            return self.ok()
        if kind == 11:  # OPENDIR
            parts = _parts(packet.string())
            packet.end()
            self.check(parts)
            placeholders = self.placeholders(parts)
            if self.virtual(parts):
                return 102, _string(self.add(_Handle(None, parts, virtual=True)))
            try:
                descriptor = self.descriptor(parts, _DIRECTORY)
            except FileNotFoundError:
                if placeholders:
                    return 102, _string(self.add(_Handle(None, parts, placeholders=placeholders, virtual=True)))
                raise
            try:
                iterator = os.scandir(descriptor)
                handle = _Handle(descriptor, parts, iterator=iterator, placeholders=placeholders)
                descriptor = -1
                return 102, _string(self.add(handle))
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        if kind == 12:  # READDIR, bounded and streamed; no recursive inventory.
            token = packet.string(128)
            packet.end()
            handle = self.handle(token, directory=True)
            rows: list[bytes] = []
            placeholder_keys = {_name_key(name) for name in handle.placeholders}
            while handle.placeholder_index < len(handle.placeholders) and len(rows) < MAX_READDIR:
                name = os.fsencode(handle.placeholders[handle.placeholder_index])
                handle.placeholder_index += 1
                rows.append(_string(name) + _string(name) + _attrs())
            examined = 0
            while handle.iterator is not None and len(rows) < MAX_READDIR and examined < 1024:
                try:
                    entry = next(handle.iterator)
                except StopIteration:
                    break
                examined += 1
                if _name_key(entry.name) in placeholder_keys:
                    continue
                try:
                    self.check(handle.parts + (entry.name,))
                    value = os.stat(entry.name, dir_fd=handle.fd, follow_symlinks=False)
                    _checked_kind(value)
                except OSError:
                    continue
                name = os.fsencode(entry.name)
                rows.append(_string(name) + _string(name) + _attrs(value))
            if not rows and examined < 1024:
                return 101, _U32.pack(_EOF) + _string(_MESSAGES[_EOF]) + _string(b'')
            if not rows:
                # v3 NAME requires at least one entry. Do not claim EOF (or
                # scan indefinitely) when this bounded batch was all denied.
                raise OSError(errno.EOVERFLOW, 'Directory batch contains only unsupported entries')
            return 104, _U32.pack(len(rows)) + b''.join(rows)
        if kind in {13, 14, 15}:  # REMOVE / MKDIR / RMDIR
            parts = _parts(packet.string())
            values = packet.attrs() if kind == 14 else {}
            packet.end()
            self.check(parts, mutate=True)
            if set(values) - {'mode'}:
                raise _Unsupported()
            if values.get('mode', 0) & 0o7000:
                raise PermissionError(errno.EACCES, 'Special permission bits unavailable')
            with self.parent(parts) as (parent, name):
                if kind == 14:
                    os.mkdir(name, values.get('mode', 0o755) & 0o777, dir_fd=parent)
                else:
                    _checked_kind(os.stat(name, dir_fd=parent, follow_symlinks=False))
                    if kind == 13:
                        os.unlink(name, dir_fd=parent)
                    else:
                        os.rmdir(name, dir_fd=parent)
            return self.ok()
        if kind == 16:  # REALPATH is export-relative, never the host path.
            parts = _parts(packet.string())
            packet.end()
            self.check(parts)
            # Validate every real component, including the final entry.
            self.metadata(parts)
            path = b'/' + b'/'.join(os.fsencode(part) for part in parts)
            return 104, _U32.pack(1) + _string(path) + _string(path) + _attrs(self.metadata(parts))
        if kind == 18:  # Standard v3 rename must not overwrite an existing name.
            old, new = _parts(packet.string()), _parts(packet.string())
            packet.end()
            return self.rename(old, new, replace=False)
        if kind in {19, 20}:  # READLINK / SYMLINK. Links are never exported/created.
            raise _Unsupported()
        if kind == 200:
            extension = packet.string(128)
            if extension == b'posix-rename@openssh.com':
                old, new = _parts(packet.string()), _parts(packet.string())
                packet.end()
                return self.rename(old, new, replace=True)
            if extension == b'fsync@openssh.com':
                handle = self.handle(packet.string(128))
                packet.end()
                if not handle.writable:
                    raise PermissionError(errno.EACCES, 'Read-only export handle')
                self.check(handle.parts, mutate=True)
                os.fsync(handle.fd)
                return self.ok()
            if extension in {b'statvfs@openssh.com', b'fstatvfs@openssh.com'}:
                if extension == b'statvfs@openssh.com':
                    parts = _parts(packet.string())
                    packet.end()
                    self.metadata(parts)
                    descriptor = self.root
                else:
                    handle = self.handles.get(packet.string(128))
                    packet.end()
                    if handle is None:
                        raise OSError(errno.EBADF, 'Unknown export handle')
                    descriptor = handle.fd if handle.fd is not None else self.root
                value = os.fstatvfs(descriptor)
                flags = (1 if value.f_flag & getattr(os, 'ST_RDONLY', 1) or not self.writable else 0)
                flags |= 2 if value.f_flag & getattr(os, 'ST_NOSUID', 2) else 0
                return 201, struct.pack('>11Q', value.f_bsize, value.f_frsize,
                    value.f_blocks, value.f_bfree, value.f_bavail, value.f_files,
                    value.f_ffree, value.f_favail, 0, flags, value.f_namemax)
            raise _Unsupported()
        raise _Unsupported()

    @staticmethod
    def ok() -> tuple[int, bytes]:
        return 101, _U32.pack(_OK) + _string(_MESSAGES[_OK]) + _string(b'')

    def rename(self, old: tuple[str, ...], new: tuple[str, ...], *, replace: bool) -> tuple[int, bytes]:
        self.check(old, mutate=True)
        self.check(new, mutate=True)
        with self.parent(old) as (old_fd, old_name), self.parent(new) as (new_fd, new_name):
            _checked_kind(os.stat(old_name, dir_fd=old_fd, follow_symlinks=False))
            try:
                destination = os.stat(new_name, dir_fd=new_fd, follow_symlinks=False)
            except FileNotFoundError:
                destination = None
            if destination is not None:
                _checked_kind(destination)
                if not replace:
                    raise FileExistsError(errno.EEXIST, 'Rename destination exists')
            if replace:
                os.rename(old_name, new_name, src_dir_fd=old_fd, dst_dir_fd=new_fd)
            else:
                _rename_noreplace(old_fd, old_name, new_fd, new_name)
        # Keep ordinary open handles usable after an in-export rename.
        for handle in self.handles.values():
            if handle.parts[:len(old)] == old:
                handle.parts = new + handle.parts[len(old):]
        return self.ok()


def _mutates(kind: int, packet: bytes) -> bool:
    if kind in {6, 9, 10, 13, 14, 15, 18, 20}:
        return True
    if kind == 3:
        value = _Packet(packet)
        value.string()
        return bool(value.uint32() & 2)
    if kind == 200:
        return _Packet(packet).string(128) in {b'posix-rename@openssh.com', b'fsync@openssh.com', b'hardlink@openssh.com'}
    return False


@contextlib.asynccontextmanager
async def _no_mutation():
    yield


async def _finish_thread(function):
    """Join owned disk work even on repeated cancellation before closing FDs."""
    task = asyncio.create_task(asyncio.to_thread(function))
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
        except BaseException:
            break
    if cancelled:
        with contextlib.suppress(BaseException):
            task.result()
        raise asyncio.CancelledError()
    return task.result()


async def serve_sftp(reader: Any, writer: Any, export_root: Path, *, writable: bool,
                     excluded: tuple[str, ...] = (), revoked: asyncio.Event | None = None,
                     mutation: Callable[[], AsyncContextManager[Any]] | None = None,
                     status_callback: Callable[[dict[str, Any]], Any] | None = None) -> None:
    """Serve a bounded SFTP v3 session until EOF, revocation or cancellation.

    ``reader.readexactly``, ``writer.write`` and ``writer.drain`` follow the
    asyncio streams API. Revocation also interrupts idle reads/backpressure and
    waits for any mutation lease to release before returning. Writer ownership
    transfers to this function; it is closed on every exit.
    """
    export: _Export | None = None
    revoke_task = asyncio.create_task(revoked.wait()) if revoked is not None else None
    requests = 0

    async def status(event: str) -> None:
        if status_callback is None:
            return
        try:
            result = status_callback({'event': event, 'requests': requests,
                                      'handles': len(export.handles) if export else 0,
                                      'writable': bool(writable)})
            if inspect.isawaitable(result):
                await result
        except Exception:
            pass  # Optional observations must never change source access.

    async def guarded(awaitable):
        if revoked is not None and revoked.is_set():
            if inspect.iscoroutine(awaitable):
                awaitable.close()
            raise PermissionError(errno.EACCES, 'Export revoked')
        task = asyncio.ensure_future(awaitable)
        try:
            if revoke_task is None:
                return await task
            done, _ = await asyncio.wait({task, revoke_task}, return_when=asyncio.FIRST_COMPLETED)
            if revoke_task in done:
                raise PermissionError(errno.EACCES, 'Export revoked')
            return task.result()
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def send(kind: int, payload: bytes) -> None:
        data = bytes([kind]) + payload
        writer.write(_U32.pack(len(data)) + data)
        await guarded(writer.drain())

    async def perform(kind: int, payload: bytes) -> tuple[int, bytes]:
        changes = _mutates(kind, payload)
        async with (mutation() if mutation is not None and changes else _no_mutation()):
            if revoked is not None and revoked.is_set():
                raise PermissionError(errno.EACCES, 'Export revoked')
            def execute():
                export.check_root()
                if revoked is not None and revoked.is_set():
                    raise PermissionError(errno.EACCES, 'Export revoked')
                return export.request(kind, _Packet(payload))
            return await _finish_thread(execute)

    try:
        def open_export():
            nonlocal export
            # Assign inside the joined worker, so cancellation during opening
            # cannot orphan a newly opened root descriptor.
            export = _Export(Path(export_root), bool(writable), excluded)
        await _finish_thread(open_export)
        initialized = False
        while True:
            header = await guarded(reader.readexactly(4))
            size = _U32.unpack(header)[0]
            if not 1 <= size <= MAX_PACKET:
                break
            data = await guarded(reader.readexactly(size))
            kind, body = data[0], data[1:]
            if not initialized:
                packet = _Packet(body)
                if kind != 1 or packet.uint32() < 3:
                    break
                # INIT extension pairs are bounded by the packet limit.
                while packet.offset < len(body):
                    packet.string(), packet.string()
                extensions = b''.join(_string(name) + _string(version) for name, version in (
                    (b'posix-rename@openssh.com', b'1'), (b'fsync@openssh.com', b'1'),
                    (b'statvfs@openssh.com', b'2'), (b'fstatvfs@openssh.com', b'2')))
                await send(2, _U32.pack(3) + extensions)
                initialized = True
                await status('connected')
                continue
            if len(body) < 4:
                break
            request_id, payload = body[:4], body[4:]
            requests += 1
            try:
                response, value = await guarded(perform(kind, payload))
            except _RootReplaced:
                break
            except _Unsupported:
                response, value = 101, _U32.pack(_UNSUPPORTED) + _string(_MESSAGES[_UNSUPPORTED]) + _string(b'')
            except (_PacketError, OverflowError, struct.error):
                response, value = 101, _U32.pack(_BAD_MESSAGE) + _string(_MESSAGES[_BAD_MESSAGE]) + _string(b'')
            except OSError as error:
                code = _NO_FILE if error.errno in {errno.ENOENT, errno.ENOTDIR} else (
                    _DENIED if error.errno in {errno.EACCES, errno.EPERM, errno.ELOOP, errno.EROFS} else _FAILURE)
                response, value = 101, _U32.pack(code) + _string(_MESSAGES[code]) + _string(b'')
            if revoked is not None and revoked.is_set():
                break
            await send(response, request_id + value)
    except (asyncio.IncompleteReadError, BrokenPipeError, ConnectionError, PermissionError, _PacketError):
        pass
    finally:
        # Joining disk work may itself observe another cancellation. Keep
        # stream ownership and watcher retirement in nested cleanup regions so
        # no cancellation can skip closing the writer after the FDs are joined.
        try:
            if export is not None:
                await _finish_thread(export.close)
        finally:
            try:
                if revoke_task is not None:
                    revoke_task.cancel()
                    await asyncio.gather(revoke_task, return_exceptions=True)
            finally:
                writer.close()
                try:
                    await status('revoked' if revoked is not None and revoked.is_set() else 'closed')
                finally:
                    wait_closed = getattr(writer, 'wait_closed', None)
                    if wait_closed is not None:
                        try:
                            await asyncio.wait_for(wait_closed(), 2)
                        except (OSError, TimeoutError):
                            pass
