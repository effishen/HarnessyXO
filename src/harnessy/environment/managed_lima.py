"""Verified user-owned Linux Lima distribution, shared by launcher and VM Start.

Official core and additional-agent archives are a matching immutable release.
Installation changes only HarnessyXO's private tools cache. No system package,
shell profile, existing Lima installation or VM disk is replaced.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import uuid

LIMA_VERSION = '2.2.1'
RELEASE_URL = f'https://github.com/lima-vm/lima/releases/download/v{LIMA_VERSION}'
# Official v2.2.1 SHA256SUMS, whose published SHA256 is
# 4805ceeb791229ecaddcde32bf04b14742f4d036b343ad5d8c478ba5d220fff2.
ASSET_SHA256 = {
    'lima-2.2.1-Linux-aarch64.tar.gz': 'fbcf4d127936666aa2cf6013b663c250431f2a59394757b404070f8d6a160e10',
    'lima-2.2.1-Linux-x86_64.tar.gz': 'b391ac7fcac2b2a5a1628107756463188ded4d18d3104a40a66a8bb6fec01bcb',
    'lima-additional-guestagents-2.2.1-Linux-aarch64.tar.gz': '0759fecb79a5f9322188ff25677d5600722b122a86cccf141f3a410dd9effcce',
    'lima-additional-guestagents-2.2.1-Linux-x86_64.tar.gz': 'bdc6d385517ed41101782d10b59ed23cbbb36c1bf54b030adb98f577211fd4d9',
}
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_UNPACKED_BYTES = 512 * 1024 * 1024
MAX_FILES = 8192
_DISTRIBUTION_DIRS = {'bin', 'share', 'libexec'}
_CACHE: dict[str, tuple[tuple, Path]] = {}


class ManagedLimaError(RuntimeError):
    """A bounded safe reason; downloader/process output is never interpolated."""


def _architecture(value: str | None = None) -> str:
    value = (value or platform.machine()).lower()
    result = {'arm64': 'aarch64', 'aarch64': 'aarch64', 'x64': 'x86_64',
              'amd64': 'x86_64', 'x86_64': 'x86_64'}.get(value)
    if result is None:
        raise ManagedLimaError('unsupported_architecture')
    return result


def tool_root() -> Path:
    from harnessy.core.paths import settings_path
    return settings_path() / 'host-tools' / 'lima'


def release_directory(root: Path | None = None, architecture: str | None = None) -> Path:
    return (root or tool_root()) / 'releases' / f'{LIMA_VERSION}-Linux-{_architecture(architecture)}'


def _owned_directory(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(exist_ok=True, mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o022):
        raise ManagedLimaError('unsafe_storage')


def _storage(root: Path) -> None:
    # Construct cache directories one component at a time. Parent settings
    # validation remains owned by the application's account/settings store.
    from harnessy.core.paths import settings_path
    settings = settings_path()
    if root == settings / 'host-tools' / 'lima':
        settings.mkdir(parents=True, exist_ok=True, mode=0o700)
        _owned_directory(settings)
        _owned_directory(settings / 'host-tools', create=True)
    else:
        root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _owned_directory(root, create=True)
    _owned_directory(root / 'releases', create=True)


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(data)
    return value.hexdigest()


def _download(url: str, destination: Path, expected: str) -> None:
    started = time.monotonic()
    total = 0
    digest = hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=30) as response, destination.open('xb') as output:
            while data := response.read(1024 * 1024):
                total += len(data)
                if total > MAX_ARCHIVE_BYTES or time.monotonic() - started > 180:
                    raise ManagedLimaError('download_limit')
                digest.update(data)
                output.write(data)
    except ManagedLimaError:
        raise
    except Exception:
        raise ManagedLimaError('download_failed') from None
    if digest.hexdigest() != expected:
        raise ManagedLimaError('checksum_failed')


def _extract(archive: Path, destination: Path, records: dict) -> None:
    try:
        with tarfile.open(archive, 'r:gz') as package:
            members = package.getmembers()
            if len(members) + len(records) > MAX_FILES or sum(item.size for item in members) > MAX_UNPACKED_BYTES:
                raise ManagedLimaError('archive_limit')
            for item in members:
                path = PurePosixPath(item.name)
                if str(path) == '.':
                    continue
                if (path.is_absolute() or not path.parts or '..' in path.parts
                        or path.parts[0] not in _DISTRIBUTION_DIRS
                        or not (item.isfile() or item.isdir() or item.issym())):
                    raise ManagedLimaError('archive_invalid')
                if item.issym():
                    try:
                        ((destination / path).parent / item.linkname).resolve().relative_to(destination.resolve())
                    except ValueError:
                        raise ManagedLimaError('archive_invalid') from None
            # Write files before symlinks and never restore publisher uid/gid.
            for item in members:
                path = PurePosixPath(item.name)
                if str(path) == '.':
                    continue
                target = destination / path
                if item.isdir():
                    if target.is_symlink():
                        raise ManagedLimaError('archive_invalid')
                    target.mkdir(parents=True, exist_ok=True, mode=0o755)
                    target.chmod(0o755)
                elif item.isfile():
                    if str(path) in records or target.is_symlink():
                        raise ManagedLimaError('archive_duplicate')
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                    source = package.extractfile(item)
                    if source is None:
                        raise ManagedLimaError('archive_invalid')
                    with source, target.open('xb') as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                    target.chmod(0o755 if item.mode & 0o111 else 0o644)
                    records[str(path)] = {'sha256': _digest(target), 'size': target.stat().st_size,
                                          'executable': bool(item.mode & 0o111)}
            for item in members:
                if item.issym():
                    path = str(PurePosixPath(item.name))
                    target = destination / path
                    if path in records or target.exists() or target.is_symlink():
                        raise ManagedLimaError('archive_duplicate')
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                    target.symlink_to(item.linkname)
                    records[path] = {'symlink': item.linkname}
    except ManagedLimaError:
        raise
    except Exception:
        raise ManagedLimaError('archive_invalid') from None


def _agent(prefix: Path, architecture: str) -> Path | None:
    for suffix in ('', '.gz'):
        candidate = prefix / 'share' / 'lima' / f'lima-guestagent.Linux-{architecture}{suffix}'
        if candidate.is_file() and not candidate.is_symlink() and candidate.stat().st_size:
            return candidate
    return None


def _probe(prefix: Path) -> None:
    try:
        result = subprocess.run([str(prefix / 'bin' / 'limactl'), '--version'],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15, check=True, text=True)
    except subprocess.CalledProcessError as exc:
        if (platform.system() == 'Linux' and os.geteuid() == 0
                and 'must not run as the root user' in ((exc.stderr or '') + (exc.stdout or ''))[:1024]):
            raise ManagedLimaError('root_account_unsupported') from None
        raise ManagedLimaError('controller_unusable') from None
    except (OSError, subprocess.SubprocessError):
        raise ManagedLimaError('controller_unusable') from None
    if not re.search(r'\b' + re.escape(LIMA_VERSION) + r'\b', result.stdout[:512]):
        raise ManagedLimaError('controller_version_mismatch')
    for architecture, machine in (('aarch64', 183), ('x86_64', 62)):
        path = _agent(prefix, architecture)
        if path is None:
            raise ManagedLimaError('guest_agent_missing')
        opener = gzip.open if path.suffix == '.gz' else open
        with opener(path, 'rb') as stream:
            header = stream.read(64)
        if len(header) < 20 or header[:4] != b'\x7fELF' or int.from_bytes(header[18:20], 'little') != machine:
            raise ManagedLimaError('guest_agent_invalid')


def managed_bin_directory(*, root: Path | None = None, architecture: str | None = None) -> Path | None:
    root = root or tool_root()
    try:
        prefix = release_directory(root, architecture)
        for directory in (root, root / 'releases', prefix):
            _owned_directory(directory)
        manifest = prefix / 'harnessy-lima.json'
        if manifest.is_symlink() or manifest.stat().st_size > 2 * 1024 * 1024:
            return None
        value = json.loads(manifest.read_text('utf-8'))
        arch = _architecture(architecture)
        expected_assets = {name: digest for name, digest in ASSET_SHA256.items() if name.endswith(f'Linux-{arch}.tar.gz')}
        if not isinstance(value, dict):
            return None
        records = value.get('files', {})
        if (value.get('schema') != 1 or value.get('version') != LIMA_VERSION or value.get('architecture') != arch
                or value.get('assets') != expected_assets or not isinstance(records, dict)
                or len(records) > MAX_FILES or 'bin/limactl' not in records):
            return None
        signature = [(manifest.stat().st_ino, manifest.stat().st_mtime_ns, manifest.stat().st_size)]
        for name, record in records.items():
            if not isinstance(name, str) or not isinstance(record, dict):
                return None
            if 'symlink' in record:
                if set(record) != {'symlink'} or not isinstance(record['symlink'], str):
                    return None
            elif (set(record) != {'sha256', 'size', 'executable'}
                  or not isinstance(record['sha256'], str)
                  or not re.fullmatch(r'[0-9a-f]{64}', record['sha256'])
                  or type(record['size']) is not int or not 0 <= record['size'] <= MAX_UNPACKED_BYTES
                  or type(record['executable']) is not bool):
                return None
            path = PurePosixPath(name)
            if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] not in _DISTRIBUTION_DIRS:
                return None
            target = prefix / path
            info = target.lstat()
            if info.st_uid != os.geteuid() or (not stat.S_ISLNK(info.st_mode) and stat.S_IMODE(info.st_mode) & 0o022):
                return None
            if 'symlink' in record:
                if not stat.S_ISLNK(info.st_mode) or os.readlink(target) != record['symlink']:
                    return None
                target.resolve().relative_to(prefix.resolve())
            elif (not stat.S_ISREG(info.st_mode) or info.st_size != record.get('size')
                  or bool(info.st_mode & stat.S_IXUSR) != record.get('executable')):
                return None
            signature.append((name, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
        key = str(prefix)
        fingerprint = tuple(signature)
        if _CACHE.get(key, (None, None))[0] != fingerprint:
            for name, record in records.items():
                if 'sha256' in record and _digest(prefix / name) != record['sha256']:
                    return None
            _probe(prefix)
            _CACHE[key] = (fingerprint, prefix / 'bin')
        return prefix / 'bin'
    except (OSError, ValueError, TypeError, KeyError, EOFError, RuntimeError):
        return None


def install_managed_lima(*, root: Path | None = None, architecture: str | None = None) -> dict:
    if platform.system() != 'Linux':
        raise ManagedLimaError('unsupported_host')
    root = root or tool_root()
    arch = _architecture(architecture)
    cached = managed_bin_directory(root=root, architecture=arch)
    if cached:
        return {'binary': str(cached / 'limactl'), 'version': LIMA_VERSION, 'cached': True}
    _storage(root)
    import fcntl
    descriptor = os.open(root / '.install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        cached = managed_bin_directory(root=root, architecture=arch)
        if cached:
            return {'binary': str(cached / 'limactl'), 'version': LIMA_VERSION, 'cached': True}
        with tempfile.TemporaryDirectory(prefix='.install-', dir=root) as temporary:
            work = Path(temporary)
            prefix = work / 'distribution'
            prefix.mkdir(mode=0o700)
            records: dict = {}
            assets = {name: digest for name, digest in ASSET_SHA256.items() if name.endswith(f'Linux-{arch}.tar.gz')}
            for name, digest in assets.items():
                archive = work / name
                _download(f'{RELEASE_URL}/{name}', archive, digest)
                _extract(archive, prefix, records)
            _probe(prefix)
            manifest = {'schema': 1, 'version': LIMA_VERSION, 'architecture': arch, 'assets': assets, 'files': records}
            (prefix / 'harnessy-lima.json').write_text(json.dumps(manifest, sort_keys=True), encoding='utf-8')
            (prefix / 'harnessy-lima.json').chmod(0o600)
            target = release_directory(root, arch)
            if target.exists() or target.is_symlink():
                target.rename(target.with_name('.invalid-' + target.name + '-' + uuid.uuid4().hex[:8]))
            prefix.rename(target)
            result = managed_bin_directory(root=root, architecture=arch)
            if result is None:
                raise ManagedLimaError('installed_verification_failed')
            return {'binary': str(result / 'limactl'), 'version': LIMA_VERSION, 'cached': False}
