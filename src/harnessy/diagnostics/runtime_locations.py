"""Private runtime-location metadata for offline diagnostics discovery.

This index is never a diagnostics archive member. It stores root locations only,
without reading workspace files, project trees, a database, or guest content.
"""
from __future__ import annotations

from collections import OrderedDict
import errno
import json
import os
from pathlib import Path
import re
import stat
from threading import RLock
from typing import Any
import uuid

INDEX_NAME = 'runtime-locations.json'
MAX_LOCATIONS = 64
MAX_INDEX_BYTES = 256 * 1024
INDEX_STATUSES = frozenset({'ready', 'missing', 'unsafe', 'unreadable', 'invalid'})
_LOCK = RLock()
_KNOWN: OrderedDict[tuple[str, str, str], dict[str, str]] = OrderedDict()
_ROOT: Path | None = None
_ROOT_ID: tuple[int, int] | None = None


def _location(kind: Any, path: Any, backend: Any = '') -> dict[str, str] | None:
    if kind not in {'workspace', 'target'} or not isinstance(path, (str, Path)):
        return None
    text = str(path)
    if not text or len(text) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in text):
        return None
    value = Path(text)
    if not value.is_absolute() or '..' in value.parts or '.settings' in value.parts:
        return None
    if kind == 'target' and (backend not in {'lima', 'qemu'}
            or not re.fullmatch(r'[0-9a-f]{32}', value.name)
            or value.parent.name != 'test_targets' or value.parent.parent.name != '.harnessy'):
        return None
    result = {'kind': kind, 'path': str(value)}
    if kind == 'target':
        result['backend'] = backend
    return result


def _key(location: dict[str, str]) -> tuple[str, str, str]:
    return location['kind'], location['path'], location.get('backend', '')


def _open_root(root: Path, expected=None) -> int:
    if (not root.is_absolute() or '..' in root.parts
            or any(ord(c) < 32 or ord(c) == 127 for c in str(root))
            or os.open not in os.supports_dir_fd or not hasattr(os, 'O_NOFOLLOW')):
        raise ValueError('unsafe')
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_CLOEXEC', 0)
    descriptor = os.open(root.anchor, flags)
    try:
        for component in root.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o022
                or expected is not None and (info.st_dev, info.st_ino) != expected):
            raise ValueError('unsafe')
        result, descriptor = descriptor, None
        return result
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read(descriptor: int) -> tuple[list[dict[str, str]], str]:
    file_descriptor = None
    try:
        file_descriptor = os.open(INDEX_NAME, os.O_RDONLY | os.O_NOFOLLOW
                                  | getattr(os, 'O_NONBLOCK', 0), dir_fd=descriptor)
        info = os.fstat(file_descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size > MAX_INDEX_BYTES):
            return [], 'unsafe'
        chunks, count = [], 0
        while count <= MAX_INDEX_BYTES:
            chunk = os.read(file_descriptor, min(65536, MAX_INDEX_BYTES + 1 - count))
            if not chunk:
                break
            chunks.append(chunk); count += len(chunk)
        if count > MAX_INDEX_BYTES:
            return [], 'unsafe'
        value = json.loads(b''.join(chunks))
        if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
                or value['schema_version'] != 1 or not isinstance(value.get('locations'), list)
                or len(value['locations']) > MAX_LOCATIONS):
            return [], 'invalid'
        records, seen = [], set()
        for row in value['locations']:
            if not isinstance(row, dict):
                return [], 'invalid'
            location = _location(row.get('kind'), row.get('path'), row.get('backend', ''))
            if location is None:
                return [], 'invalid'
            if _key(location) not in seen:
                records.append(location); seen.add(_key(location))
        return records, 'ready'
    except FileNotFoundError:
        return [], 'missing'
    except (ValueError, TypeError, RecursionError, UnicodeError):
        return [], 'invalid'
    except OSError as error:
        return [], 'unsafe' if error.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENXIO} else 'unreadable'
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)


def load_runtime_locations(logs_root: Path) -> dict[str, Any]:
    """Read only the private fixed index, with no workspace traversal."""
    descriptor = None
    try:
        descriptor = _open_root(Path(logs_root))
        locations, status = _read(descriptor)
        return {'status': status, 'locations': locations}
    except (OSError, ValueError, TypeError):
        return {'status': 'unsafe', 'locations': []}
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _write_locked() -> bool:
    if _ROOT is None or _ROOT_ID is None:
        return False
    descriptor = temporary = None
    name = '.runtime-locations-' + uuid.uuid4().hex
    try:
        descriptor = _open_root(_ROOT, _ROOT_ID)
        existing, status = _read(descriptor)
        if status not in {'ready', 'missing'}:
            return False
        records = list(_KNOWN.values())[-MAX_LOCATIONS:]
        while True:
            data = (json.dumps({'schema_version': 1, 'locations': records},
                               ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')
            if len(data) <= MAX_INDEX_BYTES or not records:
                break
            records.pop(0)
        if status == 'ready' and existing == records:
            return True
        temporary = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                            0o600, dir_fd=descriptor)
        os.fchmod(temporary, 0o600)
        position = 0
        while position < len(data):
            position += os.write(temporary, data[position:])
        os.fsync(temporary)
        os.close(temporary); temporary = None
        check = _open_root(_ROOT, _ROOT_ID)
        os.close(check)
        os.replace(name, INDEX_NAME, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        return True
    except (OSError, ValueError, TypeError):
        return False
    finally:
        if temporary is not None:
            os.close(temporary)
        if descriptor is not None:
            try:
                os.unlink(name, dir_fd=descriptor)
            except OSError:
                pass
            os.close(descriptor)


def configure_runtime_locations(logs_root: Path) -> bool:
    """Seed pre-configuration registrations and retain prior-process locations."""
    global _ROOT, _ROOT_ID
    descriptor = None
    with _LOCK:
        try:
            root = Path(logs_root)
            descriptor = _open_root(root)
            info = os.fstat(descriptor)
            saved, status = _read(descriptor)
            if status not in {'ready', 'missing'}:
                _ROOT = _ROOT_ID = None
                return False
            pending = list(_KNOWN.values())
            _KNOWN.clear()
            for row in saved + pending:
                _KNOWN[_key(row)] = row
                while len(_KNOWN) > MAX_LOCATIONS:
                    _KNOWN.popitem(last=False)
            _ROOT, _ROOT_ID = root, (info.st_dev, info.st_ino)
            return _write_locked()
        except (OSError, ValueError, TypeError):
            _ROOT = _ROOT_ID = None
            return False
        finally:
            if descriptor is not None:
                os.close(descriptor)


def remember_runtime_location(kind: str, path: str | Path, backend: str = '') -> None:
    """Unchanged status-poll registrations perform no index I/O."""
    location = _location(kind, path, backend)
    if location is None:
        return
    with _LOCK:
        key = _key(location)
        if key in _KNOWN:
            return
        _KNOWN[key] = location
        while len(_KNOWN) > MAX_LOCATIONS:
            _KNOWN.popitem(last=False)
        _write_locked()
