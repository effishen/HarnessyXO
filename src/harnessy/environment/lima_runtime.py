"""Short, real, same-filesystem Lima homes with stopped-only adoption.

Lima resolves symlinks in LIMA_HOME.  A short symlink to a workspace therefore
does not shorten its Unix sockets.  Keep the complete Lima tree on the same
volume and record its private real location in the environment's state.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import threading
import uuid


_LOCKS: dict[str, threading.RLock] = {}
_LONGEST_INSTANCE = 'harnessy-snap-' + 'f' * 20
_LONGEST_SOCKET = 'ssh.sock.1234567890123456'
# macOS is stricter than Linux.  Reserve the snapshot clone name too.
_UNIX_PATH_MAX = 104


class LimaHomeMigrationRequired(RuntimeError):
    pass


def _identity(legacy: Path) -> str:
    return hashlib.sha256(str(legacy).encode('utf-8')).hexdigest()[:16]


def _owned_directory(path: Path, *, create: bool = False, private: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & (0o077 if private else 0o022)):
        raise RuntimeError('The Lima storage directory must be a real, private account-owned directory.')


def _secure_metadata_directory(path: Path) -> None:
    """Repair old app-owned mkdir permissions without following a redirect.

    Earlier builds used the process umask for these controller directories.
    A normal shared-group umask can therefore leave them 0775. Tighten this
    account's real directory through its verified descriptor; never chmod the
    user's workspace, home directory, or a caller-supplied redirect.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
    except OSError as exc:
        raise RuntimeError('The Lima metadata directory is unavailable or was redirected.') from exc
    try:
        info = os.fstat(descriptor)
        current = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or not stat.S_ISDIR(current.st_mode)
                or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino)):
            raise RuntimeError('The Lima metadata directory is not owned by this account or was redirected.')
        if stat.S_IMODE(info.st_mode) != 0o700:
            os.fchmod(descriptor, 0o700)
        after = path.lstat()
        if (info.st_dev, info.st_ino) != (after.st_dev, after.st_ino) or not stat.S_ISDIR(after.st_mode):
            raise RuntimeError('The Lima metadata directory changed while securing it. No VM command was run.')
    finally:
        os.close(descriptor)


def _regular_json(path: Path) -> dict:
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 8192):
            raise RuntimeError('The Lima storage binding is not a private regular file.')
        value = json.loads(stream.read(8193))
    if not isinstance(value, dict):
        raise RuntimeError('The Lima storage binding is invalid.')
    return value


def _write_binding(path: Path, value: dict) -> None:
    temporary = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _legacy_home(environment_root: Path) -> Path:
    return Path(environment_root).absolute() / 'vm' / 'lima'


def _validate_runtime_anchors(environment_root: Path) -> None:
    from .base import _validate_registry_path
    for path in (environment_root / 'state' / 'lima-home.json', _legacy_home(environment_root)):
        _validate_registry_path(path, environment_root)


def _candidate_ancestors(legacy: Path):
    # An external workspace keeps its virtual disks on that external volume.
    # Home is useful for root-run development and ordinary home workspaces.
    values = [Path.home().resolve(), *legacy.parents]
    return sorted(dict.fromkeys(values), key=lambda p: (len(os.fsencode(p)), str(p)))


def _fits(home: Path) -> bool:
    return len(os.fsencode(home / _LONGEST_INSTANCE / _LONGEST_SOCKET)) < _UNIX_PATH_MAX


def _select_home(legacy: Path) -> Path:
    device = legacy.stat().st_dev
    digest = _identity(legacy)
    for ancestor in _candidate_ancestors(legacy):
        if ancestor == Path(ancestor.anchor):
            continue
        try:
            _owned_directory(ancestor)
            if ancestor.resolve() != ancestor or ancestor.stat().st_dev != device:
                continue
            target = ancestor / '.hl' / digest
            if _fits(target):
                _owned_directory(ancestor / '.hl', create=True, private=True)
                return target
        except (OSError, RuntimeError):
            continue
    raise RuntimeError('No short private Lima home is available on the workspace volume. '
        'Move the stopped workspace to a shorter account-owned path on that volume and retry. '
        'The VM disk and workspace files were preserved.')


def _validate_target(legacy: Path, target: Path) -> None:
    if (not target.is_absolute() or target.name != _identity(legacy)
            or target.parent.name != '.hl' or not _fits(target)
            or target.parent.parent not in _candidate_ancestors(legacy)):
        raise RuntimeError('The saved Lima storage binding does not match this environment.')
    for directory in (target.parent.parent, target.parent):
        _owned_directory(directory, private=directory == target.parent)
        if directory.resolve() != directory:
            raise RuntimeError('The Lima storage path cannot contain symbolic link redirects.')
    if target.parent.stat().st_dev != legacy.stat().st_dev:
        raise RuntimeError('The saved Lima home is no longer on the workspace volume. VM data was preserved.')
    if target.exists() or target.is_symlink():
        _owned_directory(target)
        if target.resolve() != target:
            raise RuntimeError('The Lima home cannot be a symbolic link.')


def _migration_stopped(legacy: Path, state_root: Path) -> bool:
    instances = [p for p in legacy.iterdir() if not p.name.startswith(('.', '_'))]
    if not instances:
        return True
    try:
        # A controller-owned Stop receipt is required for a previously created
        # guest.  Absence of a live PID alone does not prove it is stopped.
        readiness_path = state_root / 'readiness.json'
        if readiness_path.is_symlink() or readiness_path.stat().st_size > 65536:
            return False
        readiness = json.loads(readiness_path.read_text('utf-8'))
        if readiness.get('phase') not in {'stopped', 'destroyed', 'deleted'}:
            return False
        for instance in instances:
            _owned_directory(instance)
            for pidfile in instance.glob('*.pid'):
                if pidfile.is_symlink() or not pidfile.is_file() or pidfile.stat().st_size > 32:
                    return False
                pid = int(pidfile.read_text('ascii').strip())
                if pid <= 0:
                    return False
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    continue
                except (PermissionError, OSError):
                    return False
                return False
    except (OSError, ValueError, TypeError, RuntimeError):
        return False
    return True


def _verify_relocatable_backings(legacy: Path) -> None:
    """Do not break an older qcow2 overlay's absolute backing-file reference."""
    for instance in legacy.iterdir():
        if not instance.is_dir() or instance.is_symlink():
            continue
        for name in ('disk', 'diffdisk', 'basedisk', 'image'):
            disk = instance / name
            if not disk.exists():
                continue
            resolved = disk.resolve(strict=True)
            descriptor = os.open(resolved, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                                 | getattr(os, 'O_NONBLOCK', 0))
            with os.fdopen(descriptor, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise RuntimeError('The old VM disk is not a regular file; its storage was preserved.')
                header = stream.read(20)
                if len(header) != 20 or header[:4] != b'QFI\xfb':
                    continue
                offset = int.from_bytes(header[8:16], 'big')
                size = int.from_bytes(header[16:20], 'big')
                if not size:
                    continue
                if offset > 1024 * 1024 or size > 4096 or offset + size > info.st_size:
                    raise RuntimeError('The old VM disk backing reference could not be verified; its storage was preserved.')
                stream.seek(offset)
                backing = Path(os.fsdecode(stream.read(size)))
                if backing.is_absolute() and (backing == legacy or legacy in backing.parents):
                    raise LimaHomeMigrationRequired('This stopped VM has an absolute disk backing-file path in its old '
                        'Lima home. A disk-aware relocation is required before shortening that home. '
                        'The original VM disk and backing files were preserved without modification.')


def bound_lima_home(environment_root: Path) -> Path:
    """Read an existing verified binding without creating or migrating a VM."""
    root = Path(environment_root).absolute()
    _validate_runtime_anchors(root)
    legacy = _legacy_home(root)
    binding = root / 'state' / 'lima-home.json'
    if not binding.exists() and not binding.is_symlink():
        return legacy
    value = _regular_json(binding)
    if value.get('schema') != 1 or value.get('legacy_home') != str(legacy):
        raise RuntimeError('The Lima storage binding belongs to another environment.')
    target = Path(str(value.get('lima_home') or ''))
    _validate_target(legacy, target)
    if value.get('state') != 'ready' or not target.is_dir():
        raise RuntimeError('The saved Lima home is unavailable; restore its volume before using this VM. '
                           'No replacement VM was created.')
    if (target.stat().st_dev, target.stat().st_ino) != tuple(value.get('source_identity') or ()):
        raise RuntimeError('The saved Lima home was replaced; no replacement VM was created.')
    return target


def prepare_lima_home(environment_root: Path, *, allow_legacy: bool = False) -> Path:
    """Adopt only a stopped legacy home using an inode-preserving rename."""
    root = Path(environment_root).absolute()
    _validate_runtime_anchors(root)
    legacy = _legacy_home(root)
    state_root = root / 'state'
    _secure_metadata_directory(state_root)
    legacy.mkdir(mode=0o700, parents=True, exist_ok=True)
    _secure_metadata_directory(legacy)
    binding = state_root / 'lima-home.json'
    key = str(legacy)
    with _LOCKS.setdefault(key, threading.RLock()):
        import fcntl
        lock_path = state_root / 'lima-home.lock'
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(descriptor, 'w') as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
                raise RuntimeError('The Lima storage lock is not owned by this account.')
            fcntl.flock(lock, fcntl.LOCK_EX)
            if binding.exists() or binding.is_symlink():
                value = _regular_json(binding)
                if value.get('schema') != 1 or value.get('legacy_home') != str(legacy):
                    raise RuntimeError('The Lima storage binding belongs to another environment.')
                target = Path(str(value.get('lima_home') or ''))
                _validate_target(legacy, target)
                if value.get('state') == 'ready':
                    if not target.is_dir():
                        raise RuntimeError('The saved Lima home is missing. Restore its volume; no replacement VM was created.')
                    if (target.stat().st_dev, target.stat().st_ino) != tuple(value.get('source_identity') or ()):
                        raise RuntimeError('The saved Lima home was replaced; no replacement VM was created.')
                    if any(legacy.iterdir()):
                        raise RuntimeError('Both old and relocated Lima homes contain state. No VM command was run.')
                    return target
                if value.get('state') != 'moving':
                    raise RuntimeError('The Lima storage binding is invalid.')
                if target.exists():
                    if (target.stat().st_dev, target.stat().st_ino) != tuple(value.get('source_identity') or ()):
                        raise RuntimeError('The interrupted Lima relocation cannot be verified; all VM data was preserved.')
                    if any(legacy.iterdir()):
                        raise RuntimeError('The interrupted Lima relocation has two source trees; all VM data was preserved.')
                    target.chmod(0o700)
                    value['state'] = 'ready'
                    _write_binding(binding, value)
                    return target
                current_source = legacy.stat()
                if (current_source.st_dev, current_source.st_ino) != tuple(value.get('source_identity') or ()):
                    raise RuntimeError('The original Lima storage changed during relocation; all VM data was preserved.')
            else:
                if _fits(legacy):
                    # Already-short installations need no relocation or new
                    # binding, including a currently running older VM.
                    return legacy
                if not _migration_stopped(legacy, state_root):
                    if allow_legacy:
                        return legacy
                    raise LimaHomeMigrationRequired('Stop this VM, then Start it again to move its controller files '
                        'to a short private path on the same volume. Running VM data was left untouched.')
                try:
                    _verify_relocatable_backings(legacy)
                except LimaHomeMigrationRequired:
                    if allow_legacy:
                        return legacy
                    raise
                target = _select_home(legacy)
                if target.exists() or target.is_symlink():
                    raise RuntimeError('The short Lima storage location is occupied; no VM data was replaced.')
                metadata = legacy.stat()
                value = {'schema': 1, 'state': 'moving', 'legacy_home': str(legacy),
                         'lima_home': str(target), 'source_identity': [metadata.st_dev, metadata.st_ino]}
                _write_binding(binding, value)
            if not _migration_stopped(legacy, state_root):
                raise LimaHomeMigrationRequired('Stop this VM before completing its same-volume controller relocation.')
            _verify_relocatable_backings(legacy)
            try:
                from harnessy.diagnostics import log_event
                log_event('runtime', 'vm_lima_home_relocating', legacy_home=str(legacy),
                          lima_home=str(target), same_filesystem=True)
                legacy.rename(target)
            except OSError as exc:
                if exc.errno == errno.EXDEV:
                    raise RuntimeError('Lima storage relocation would cross filesystems. The original VM was preserved; '
                                       'use a shorter workspace path on the same volume.') from exc
                raise
            # Keep the legacy directory as a safe empty discovery anchor. VM
            # bytes and sparse-file inodes remain together on the original disk.
            legacy.mkdir(mode=0o700)
            target.chmod(0o700)
            value['state'] = 'ready'
            _write_binding(binding, value)
            log_event('runtime', 'vm_lima_home_relocated', legacy_home=str(legacy),
                      lima_home=str(target), same_filesystem=True, disk_inodes_preserved=True)
            return target


def validate_lima_path(environment_root: Path, path: Path) -> None:
    home = bound_lima_home(environment_root)
    target = Path(path).absolute()
    try:
        relative = target.relative_to(home)
    except ValueError as exc:
        raise ValueError('VM controller metadata is outside its owned Lima home.') from exc
    current = home
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError('VM controller metadata cannot use symbolic link redirects.')


def clear_lima_home(environment_root: Path, home: Path) -> None:
    """Clear a verified home after explicit destroy, retaining its identity."""
    if bound_lima_home(environment_root) != home:
        raise RuntimeError('The Lima storage binding changed during deletion.')
    for child in home.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def _uncreated_home(home: Path) -> bool:
    """Recognize only an absent/empty home or Lima's key/config bootstrap.

    Any instance directory, disk cache, PID/socket, special file or unknown
    tree is inconclusive. Missing PID files alone never prove a VM stopped.
    """
    if not home.exists() and not home.is_symlink():
        return True
    info = home.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise RuntimeError('The selected Lima home is not a real account-owned directory.')
    entries = list(home.iterdir())
    if len(entries) > 16:
        return False
    allowed_config = {'user', 'user.pub', 'networks.yaml', 'default.yaml', 'override.yaml', 'base.yaml'}
    total_bytes = 0
    for entry in entries:
        metadata = entry.lstat()
        if entry.name != '_config':
            return False
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise RuntimeError('Lima bootstrap metadata was redirected or belongs to another account.')
        children = list(entry.iterdir())
        if len(children) > len(allowed_config):
            return False
        for child in children:
            detail = child.lstat()
            if (child.name not in allowed_config or not stat.S_ISREG(detail.st_mode)
                    or detail.st_nlink != 1 or detail.st_uid != os.geteuid()):
                return False
            total_bytes += detail.st_size
            if total_bytes > 1024 * 1024:
                return False
    return True


def verify_uncreated_lima_home(environment_root: Path) -> Path | None:
    """Verify a failed-first-create Remove without constructing its provider.

    Returns the verified (possibly absent) home only when both legacy and bound
    locations contain no VM instance/data/process evidence. Returns None for
    existing or ambiguous VM data, and raises for an invalid storage binding.
    This does not create directories, migrate storage, stop a VM or delete data.
    The caller must hold its selected environment's removal lease and recheck
    immediately before deleting that registered environment and returned home.
    """
    root = Path(environment_root).absolute()
    _validate_runtime_anchors(root)
    # Removing the registration also recursively removes these environment
    # siblings. An empty Lima home must not hide snapshot or other VM data.
    for snapshot_root in (root / 'snapshots', root / 'vm' / 'snapshots'):
        if snapshot_root.exists() or snapshot_root.is_symlink():
            info = snapshot_root.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or next(snapshot_root.iterdir(), None) is not None):
                return None
    for container in (root, root / 'vm', root / 'state'):
        if not container.is_dir():
            continue
        for entry in container.iterdir():
            if entry.name.endswith(('.pid', '.sock')) or (container == root and entry.name == 'qemu'):
                return None
            if container == root / 'vm' and entry.name not in {'lima', 'snapshots'}:
                return None
    legacy = _legacy_home(root)
    binding = root / 'state' / 'lima-home.json'
    if not binding.exists() and not binding.is_symlink():
        return legacy if _uncreated_home(legacy) else None
    value = _regular_json(binding)
    if value.get('schema') != 1 or value.get('legacy_home') != str(legacy):
        raise RuntimeError('The Lima storage binding belongs to another environment.')
    target = Path(str(value.get('lima_home') or ''))
    _validate_target(legacy, target)
    if value.get('state') == 'ready' or (value.get('state') == 'moving' and target.exists()):
        if not target.is_dir():
            raise RuntimeError('The saved Lima home is missing; restore its volume before removing this environment.')
        info = target.stat()
        if (info.st_dev, info.st_ino) != tuple(value.get('source_identity') or ()):
            raise RuntimeError('The saved Lima home was replaced; no VM data was removed.')
        selected = target
    elif value.get('state') == 'moving':
        info = legacy.stat()
        if (info.st_dev, info.st_ino) != tuple(value.get('source_identity') or ()):
            raise RuntimeError('The original Lima storage changed during relocation; no VM data was removed.')
        selected = legacy
    else:
        raise RuntimeError('The Lima storage binding is invalid.')
    if not _uncreated_home(legacy) or (selected != legacy and not _uncreated_home(selected)):
        return None
    return selected
