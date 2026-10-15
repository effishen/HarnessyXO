"""Private, verified Node/npm bootstrap using only the Python standard library."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
from typing import Any, Callable, Iterator
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

from .paths import settings_dir, settings_path
from .auth_users import UserStore, UserStoreError


NODE_VERSION = '24.21.0'
# Published in https://nodejs.org/dist/v24.21.0/SHASUMS256.txt.
NODE_ARCHIVES = {
    ('darwin', 'arm64'): ('node-v24.21.0-darwin-arm64.tar.gz', 'bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057'),
    ('darwin', 'x64'): ('node-v24.21.0-darwin-x64.tar.gz', '1462cb3b3046b815cf8ea436d3da450ec1a9f11dac7e5a46b0ada5305d7e8097'),
    ('linux', 'arm64'): ('node-v24.21.0-linux-arm64.tar.gz', '724282c3b43aec998aa9527380465b45d229e021b58035f5f4f63095eabfe5d5'),
    ('linux', 'x64'): ('node-v24.21.0-linux-x64.tar.gz', '6e1db87ef58b8819e5d5402eff1536491b18edd8eb7bee5ef7897876e88dc5ff'),
    ('win', 'arm64'): ('node-v24.21.0-win-arm64.zip', '8779b1bde1d39f8d420e3b57aa657b39891af434d3de44a919044cec06785921'),
    ('win', 'x64'): ('node-v24.21.0-win-x64.zip', '158f7685b44de51f6c0df1d153526cbcd3e1bc739a8dfc607721cef75de9e541'),
}
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
DOWNLOAD_TIMEOUT_SECONDS = 180.0


class ReaStorageValidationError(ValueError):
    """Content-free evidence for a rejected component inside REA settings."""

    def __init__(self, root: Path, path: Path, reason: str, info: os.stat_result | None = None) -> None:
        try:
            component = path.relative_to(root).as_posix()
            if component in {'', '.'}:
                component = 'settings_root'
        except ValueError:
            component = 'settings_root'
        component = re.sub(r'[^A-Za-z0-9@._/+-]', '_', component)[:240]
        self.storage_issue: dict[str, Any] = {'component': component, 'reason': reason}
        if info is not None:
            self.storage_issue.update(
                mode=f'{stat.S_IMODE(info.st_mode):04o}',
                owned_by_current_user=os.name == 'nt' or info.st_uid == os.geteuid(),
            )
        self.remediation = f'Check {component}: {reason.replace("_", " ")}.'
        if info is not None:
            self.remediation += (f' Mode {stat.S_IMODE(info.st_mode):04o}; '
                                 f'owned by current user: {"yes" if os.name == "nt" or info.st_uid == os.geteuid() else "no"}.')
        super().__init__(self.remediation)


def validate_storage_component(
    root: Path, path: Path, *, directory: bool, allow_missing: bool = True,
    check_mode: bool = True,
) -> os.stat_result | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return None
        raise ReaStorageValidationError(root, path, 'missing') from None
    except OSError:
        raise ReaStorageValidationError(root, path, 'unreadable') from None
    reason = (
        'symlink_redirect' if stat.S_ISLNK(info.st_mode) else
        'wrong_type' if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) else
        'wrong_owner' if os.name != 'nt' and info.st_uid != os.geteuid() else
        'writable_by_others' if check_mode and os.name != 'nt' and stat.S_IMODE(info.st_mode) & 0o022 else
        ''
    )
    if reason:
        raise ReaStorageValidationError(root, path, reason, info)
    return info


def _tighten_owned_component(root: Path, path: Path, *, directory: bool) -> None:
    before = validate_storage_component(root, path, directory=directory, allow_missing=False, check_mode=False)
    if os.name == 'nt':
        return
    assert before is not None
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    if directory:
        flags |= getattr(os, 'O_DIRECTORY', 0)
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            raise ReaStorageValidationError(root, path, 'changed_during_validation', info)
        if info.st_uid != os.geteuid() or (not directory and info.st_nlink != 1):
            raise ReaStorageValidationError(root, path, 'wrong_owner' if info.st_uid != os.geteuid() else 'hard_link', info)
        os.fchmod(descriptor, (stat.S_IMODE(info.st_mode) & 0o755) | (0o700 if directory else 0o600))
    except OSError:
        raise ReaStorageValidationError(root, path, 'cannot_secure_permissions', before) from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def secure_owned_tree(root: Path, tree: Path) -> None:
    """Tighten an installer's private owned tree without following symlinks."""
    _tighten_owned_component(root, tree, directory=True)
    def walk_failed(_error: OSError) -> None:
        raise ReaStorageValidationError(root, tree, 'unreadable') from None

    for directory, dirs, files in os.walk(tree, followlinks=False, onerror=walk_failed):
        parent = Path(directory)
        for name in [*dirs, *files]:
            path = parent / name
            try:
                info = path.lstat()
            except OSError:
                raise ReaStorageValidationError(root, path, 'unreadable') from None
            if stat.S_ISLNK(info.st_mode):
                try:
                    contained = path.resolve(strict=True).is_relative_to(tree.resolve())
                except (OSError, RuntimeError):
                    contained = False
                if not contained or (os.name != 'nt' and info.st_uid != os.geteuid()):
                    raise ReaStorageValidationError(root, path, 'symlink_redirect', info)
                # npm's .bin and official Node's bin/npm are contained links.
                # Their target is checked independently; never chmod a link.
                continue
            _tighten_owned_component(root, path, directory=stat.S_ISDIR(info.st_mode))


def prepare_rea_storage(root: Path) -> Path:
    """Prepare known caches only beneath an already private REA parent."""
    try:
        UserStore(root)
    except UserStoreError:
        validate_storage_component(root, root, directory=True, allow_missing=False)
        raise ReaStorageValidationError(root, root, 'cannot_prepare_storage') from None
    parent = root / 'rea'
    validate_storage_component(root, parent, directory=True)
    try:
        parent.mkdir(mode=0o700, exist_ok=True)
    except OSError:
        raise ReaStorageValidationError(root, parent, 'cannot_prepare_storage') from None
    info = validate_storage_component(root, parent, directory=True, allow_missing=False)
    # Older installers created children with the caller's umask, although the
    # REA parent was 700. Such children were never reachable by other users.
    # Do not repair a cache that lacked that enclosing private boundary.
    private_parent = os.name == 'nt' or info is not None and not stat.S_IMODE(info.st_mode) & 0o077
    if private_parent:
        for name in ('node', 'runtime', 'npm-cache'):
            tree = parent / name
            if tree.exists() or tree.is_symlink():
                secure_owned_tree(root, tree)
    return parent


_MESSAGES = {
    'REA_NODE_UNSUPPORTED_PLATFORM': 'Automatic Node setup supports macOS, glibc Linux and Windows on x64 or arm64. Install a supported Node.js and npm manually on this platform.',
    'REA_NODE_SETTINGS_UNSAFE': 'Node.js setup requires settings and runtime directories owned by you, not symlinks or writable by other users.',
    'REA_NODE_DOWNLOAD_FAILED': 'Node.js could not be downloaded from nodejs.org. Check connectivity and run HarnessyXO again; existing cached files were preserved.',
    'REA_NODE_CHECKSUM_FAILED': 'The Node.js archive did not match its pinned official SHA-256 checksum. Run HarnessyXO again to retry the download.',
    'REA_NODE_ARCHIVE_INVALID': 'The Node.js archive contained an unsafe or unsupported entry. The private runtime was not replaced.',
    'REA_NODE_VERIFY_FAILED': 'The staged Node.js and npm could not be verified. The private runtime was not replaced.',
    'REA_NODE_LOCK_TIMEOUT': 'Another HarnessyXO setup is still running. Wait for it to finish, then run HarnessyXO again.',
    'REA_NODE_INSTALL_FAILED': 'Private Node.js setup could not finish. Check available disk space and settings-folder access, then run HarnessyXO again.',
    'REA_NODE_CLEANUP_FAILED': 'Temporary Node.js setup files could not be removed from the settings folder. Check folder access and free space, then run HarnessyXO again; the verified runtime was preserved.',
    'REA_NODE_BOOTSTRAP_CANCELLED': 'Node.js setup was cancelled; existing cached files were preserved.',
}


class ReaBootstrapError(RuntimeError):
    def __init__(self, code: str, *, storage_issue: dict[str, Any] | None = None,
                 detail: str = '') -> None:
        self.code = code if code in _MESSAGES else 'REA_NODE_INSTALL_FAILED'
        self.remediation = _MESSAGES[self.code]
        self.storage_issue = storage_issue
        if detail:
            self.remediation += ' ' + detail
        super().__init__(self.remediation)


class ReaBootstrapCancelled(ReaBootstrapError):
    def __init__(self) -> None:
        super().__init__('REA_NODE_BOOTSTRAP_CANCELLED')


def _check_cancel(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise ReaBootstrapCancelled()


def _notify(progress: Callable[[str], Any] | None, message: str) -> None:
    if progress is not None:
        progress(message)


def _host_key() -> tuple[str, str]:
    system = {'Darwin': 'darwin', 'Linux': 'linux', 'Windows': 'win'}.get(platform.system(), '')
    machine = platform.machine().lower()
    architecture = {'x86_64': 'x64', 'amd64': 'x64', 'x64': 'x64',
                    'aarch64': 'arm64', 'arm64': 'arm64'}.get(machine, '')
    if system == 'linux':
        libc = platform.libc_ver()[0].lower()
        try:
            gnu_libc = os.confstr('CS_GNU_LIBC_VERSION') or ''
        except (AttributeError, OSError, ValueError):
            gnu_libc = ''
        if libc == 'musl' or any(Path('/lib').glob('ld-musl-*.so*')):
            system = 'linux-musl'
        elif libc != 'glibc' and not gnu_libc.startswith('glibc '):
            system = 'linux-unknown-libc'
    return system, architecture


def host_identity() -> dict[str, str]:
    """Cache identity for host-specific Node and REA native dependencies."""
    system, architecture = _host_key()
    return {'platform': system or platform.system().lower(),
            'architecture': architecture or platform.machine().lower()}


def _settings_parent() -> Path:
    try:
        root = settings_dir()
        parent = prepare_rea_storage(root)
        for directory in (parent, parent / 'node'):
            try:
                info = directory.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(info.st_mode) or (os.name != 'nt' and
                    (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022)):
                validate_storage_component(root, directory, directory=True, allow_missing=False)
        return parent
    except ReaStorageValidationError as exc:
        raise ReaBootstrapError('REA_NODE_SETTINGS_UNSAFE', storage_issue=exc.storage_issue,
                                detail=exc.remediation) from None
    except (OSError, UserStoreError):
        raise ReaBootstrapError('REA_NODE_SETTINGS_UNSAFE', storage_issue={
            'component': 'settings_root', 'reason': 'cannot_prepare_storage',
        }, detail='Check settings_root: cannot prepare storage.') from None


def _supported_version(value: str) -> bool:
    if not re.fullmatch(r'\d+\.\d+\.\d+', value):
        return False
    major, minor, patch = map(int, value.split('.'))
    return (major == 22 and (minor, patch) >= (19, 0) or
            major == 24 and (minor, patch) >= (11, 0) or major >= 26)


def _probe_runtime(node: Path, npm_cli: Path) -> tuple[str, str] | None:
    environment = dict(os.environ)
    for key in ('NODE_OPTIONS', 'NODE_PATH'):
        environment.pop(key, None)
    try:
        options: dict[str, Any] = {'stdout': subprocess.PIPE, 'stderr': subprocess.DEVNULL,
                                   'timeout': 4, 'env': environment}
        if os.name == 'nt':
            options['creationflags'] = subprocess.CREATE_NO_WINDOW
        node_result = subprocess.run([str(node), '--version'], **options)
        version = node_result.stdout[:128].decode('ascii').strip().removeprefix('v')
        if node_result.returncode or not _supported_version(version):
            return None
        npm_result = subprocess.run([str(node), str(npm_cli), '--version'], **options)
        npm_version = npm_result.stdout[:128].decode('ascii').strip()
        if npm_result.returncode or not re.fullmatch(r'\d+\.\d+\.\d+', npm_version):
            return None
        return version, npm_version
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None


def _system_node_candidates() -> list[Path]:
    name = 'node.exe' if os.name == 'nt' else 'node'
    paths = [shutil.which(name), *[str(Path(folder) / name) for folder in os.environ.get('PATH', '').split(os.pathsep) if folder],
             f'/opt/homebrew/bin/{name}', f'/usr/local/bin/{name}']
    return list(dict.fromkeys(Path(value) for value in paths if value and Path(value).is_file()))[:64]


def _system_runtime(cancel_event: threading.Event | None) -> dict[str, Any] | None:
    npm_executable = shutil.which('npm')
    private_root = (settings_dir() / 'rea' / 'node').resolve()
    for candidate in _system_node_candidates():
        _check_cancel(cancel_event)
        resolved = candidate.resolve()
        # A PATH entry or alias cannot bypass the private cache's pinned host
        # metadata. The cache is considered separately after this search.
        if resolved.is_relative_to(private_root):
            continue
        prefixes = {candidate.parent.parent.resolve(), resolved.parent.parent}
        npm_candidates = [prefix / 'lib' / 'node_modules' / 'npm' / 'bin' / 'npm-cli.js' for prefix in prefixes]
        npm_candidates.extend([candidate.parent / 'node_modules' / 'npm' / 'bin' / 'npm-cli.js',
                               resolved.parent / 'node_modules' / 'npm' / 'bin' / 'npm-cli.js'])
        if npm_executable:
            npm_resolved = Path(npm_executable).resolve()
            if any(npm_resolved.is_relative_to(prefix) for prefix in prefixes):
                npm_candidates.append(npm_resolved)
        for npm in dict.fromkeys(npm_candidates):
            if npm.name not in {'npm-cli.js', 'npm-cli.cjs'} or not npm.is_file():
                continue
            if npm.resolve().is_relative_to(private_root):
                continue
            versions = _probe_runtime(resolved, npm.resolve())
            _check_cancel(cancel_event)
            if versions:
                return _runtime_result(resolved, npm.resolve(), versions, source='system', installed=False, cached=False)
    return None


def _runtime_result(node: Path, npm: Path, versions: tuple[str, str], *, source: str,
                    installed: bool, cached: bool) -> dict[str, Any]:
    return {'ok': True, 'node_path': str(node), 'npm_cli_path': str(npm),
            'npm_command': [str(node), str(npm)], 'node_version': versions[0], 'npm_version': versions[1],
            'source': source, 'installed': installed, 'cached': cached}


def _private_paths(root: Path, host: tuple[str, str]) -> tuple[Path, Path]:
    if host[0] == 'win':
        return root / 'node.exe', root / 'node_modules' / 'npm' / 'bin' / 'npm-cli.js'
    return root / 'bin' / 'node', root / 'lib' / 'node_modules' / 'npm' / 'bin' / 'npm-cli.js'


def _validated_cached_paths(root: Path, host: tuple[str, str], checksum: str) -> dict[str, Any] | None:
    try:
        for directory in (root.parent.parent, root.parent, root):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or (os.name != 'nt' and
                    (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022)):
                return None
        marker = root / 'harnessy-node.json'
        info = marker.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 4096
                or (os.name != 'nt' and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022))):
            return None
        metadata = json.loads(marker.read_text('utf-8'))
        if metadata != {'version': NODE_VERSION, 'platform': host[0], 'architecture': host[1], 'archive_sha256': checksum}:
            return None
        node, npm = _private_paths(root, host)
        for path in (node, npm):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or not path.resolve().is_relative_to(root.resolve())
                    or (os.name != 'nt' and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022))):
                return None
        return {'node_path': str(node), 'npm_cli_path': str(npm), 'node_version': NODE_VERSION,
                'platform': host[0], 'architecture': host[1]}
    except (OSError, ValueError, TypeError):
        return None


def cached_node_paths(root: Path | None = None) -> dict[str, Any] | None:
    """Validate the pinned cache without executing, creating or downloading."""
    host = _host_key()
    archive = NODE_ARCHIVES.get(host)
    if archive is None:
        return None
    root = Path(root) if root is not None else settings_path() / 'rea' / 'node'
    return _validated_cached_paths(root, host, archive[1])


def _cached_runtime(root: Path, host: tuple[str, str], checksum: str) -> dict[str, Any] | None:
    paths = _validated_cached_paths(root, host, checksum)
    if paths is None:
        return None
    node, npm = Path(paths['node_path']), Path(paths['npm_cli_path'])
    versions = _probe_runtime(node, npm)
    if not versions or versions[0] != NODE_VERSION:
        return None
    return _runtime_result(node, npm, versions, source='private', installed=False, cached=True)


@contextmanager
def installation_lock(cancel_event: threading.Event | None = None, *, timeout: float = 300.0) -> Iterator[None]:
    """Cross-process phase lock; callers run acquisition in an owned worker."""
    parent = _settings_parent()
    deadline = time.monotonic() + timeout
    try:
        descriptor = UserStore(parent)._open_private(parent / 'install.lock', os.O_CREAT | os.O_RDWR)
        stream = os.fdopen(descriptor, 'r+b')
    except (OSError, UserStoreError):
        raise ReaBootstrapError('REA_NODE_SETTINGS_UNSAFE') from None
    acquired = False
    try:
        if stream.seek(0, os.SEEK_END) == 0:
            stream.write(b'0')
            stream.flush()
        while not acquired:
            _check_cancel(cancel_event)
            try:
                if os.name == 'nt':
                    import msvcrt
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError:
                if time.monotonic() >= deadline:
                    raise ReaBootstrapError('REA_NODE_LOCK_TIMEOUT') from None
                if cancel_event is not None:
                    cancel_event.wait(0.05)
                else:
                    time.sleep(0.05)
        _check_cancel(cancel_event)
        yield
    finally:
        if acquired:
            if os.name == 'nt':
                import msvcrt
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        stream.close()


class _OfficialRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if (url.scheme != 'https' or url.hostname != 'nodejs.org' or url.port not in (None, 443)
                or url.username is not None or url.password is not None):
            raise ReaBootstrapError('REA_NODE_DOWNLOAD_FAILED')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download_archive(filename: str, destination: Path, cancel_event: threading.Event | None) -> str:
    request = urllib.request.Request(f'https://nodejs.org/dist/v{NODE_VERSION}/{filename}',
                                     headers={'User-Agent': 'HarnessyXO-REA-Setup'})
    opener = urllib.request.build_opener(_OfficialRedirects())
    deadline = time.monotonic() + DOWNLOAD_TIMEOUT_SECONDS
    digest = hashlib.sha256()
    size = 0
    try:
        with opener.open(request, timeout=15) as response, destination.open('xb') as output:
            length = response.headers.get('Content-Length')
            if length and int(length) > MAX_DOWNLOAD_BYTES:
                raise ReaBootstrapError('REA_NODE_DOWNLOAD_FAILED')
            while True:
                _check_cancel(cancel_event)
                if time.monotonic() > deadline:
                    raise ReaBootstrapError('REA_NODE_DOWNLOAD_FAILED')
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES:
                    raise ReaBootstrapError('REA_NODE_DOWNLOAD_FAILED')
                digest.update(chunk)
                output.write(chunk)
        _check_cancel(cancel_event)
        return digest.hexdigest()
    except ReaBootstrapError:
        raise
    except (OSError, ValueError, urllib.error.URLError):
        raise ReaBootstrapError('REA_NODE_DOWNLOAD_FAILED') from None


def _member_path(name: str, prefix: str) -> Path:
    if '\\' in name or '\x00' in name or ':' in name:
        raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID')
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or not path.parts or path.parts[0] != prefix:
        raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID')
    return Path(*path.parts[1:])


def _safe_link(name: str, target: str, prefix: str) -> None:
    if not target or target.startswith('/') or '\\' in target or '\x00' in target or ':' in target:
        raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID')
    normalized = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
    if normalized != prefix and not normalized.startswith(prefix + '/'):
        raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID')


def _extract_archive(archive: Path, destination: Path, prefix: str,
                     cancel_event: threading.Event | None) -> None:
    """Validate all entries before writes; create relative symlinks last."""
    destination.mkdir(mode=0o700)
    entries = []
    seen: set[Path] = set()
    total = 0
    try:
        container = zipfile.ZipFile(archive) if archive.name.endswith('.zip') else tarfile.open(archive, 'r:*')
        with container:
            members = container.infolist() if isinstance(container, zipfile.ZipFile) else container
            for member in members:
                _check_cancel(cancel_event)
                if len(entries) >= MAX_ARCHIVE_MEMBERS:
                    raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID')
                if isinstance(container, zipfile.ZipFile):
                    name, size, mode = member.filename, member.file_size, member.external_attr >> 16
                    if member.flag_bits & 1:
                        raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID')
                    kind = 'directory' if member.is_dir() else 'symlink' if stat.S_ISLNK(mode) else 'file'
                else:
                    name, size, mode = member.name, member.size, member.mode
                    kind = 'directory' if member.isdir() else 'symlink' if member.issym() else 'file' if member.isfile() else 'unsupported'
                relative = _member_path(name, prefix)
                if relative in seen or kind == 'unsupported' or size < 0:
                    raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID')
                seen.add(relative)
                total += size
                if total > MAX_EXTRACTED_BYTES:
                    raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID')
                link = None
                if kind == 'symlink':
                    if size > 4096:
                        raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID')
                    link = container.read(member).decode('utf-8') if isinstance(container, zipfile.ZipFile) else member.linkname
                    _safe_link(name, link, prefix)
                entries.append((member, relative, kind, mode, link))
            # An archive may not replace a directory with a later symlink, or
            # place any file underneath one of its symlink entries.
            symlinks = {relative for _, relative, kind, _, _ in entries if kind == 'symlink'}
            if any(any(parent in symlinks for parent in relative.parents) for _, relative, _, _, _ in entries):
                raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID')
            for member, relative, kind, mode, _ in entries:
                _check_cancel(cancel_event)
                target = destination / relative
                if kind == 'directory':
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                elif kind == 'file':
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    source = container.open(member) if isinstance(container, zipfile.ZipFile) else container.extractfile(member)
                    if source is None:
                        raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID')
                    with source, target.open('xb') as output:
                        while True:
                            _check_cancel(cancel_event)
                            chunk = source.read(256 * 1024)
                            if not chunk:
                                break
                            output.write(chunk)
                    target.chmod((mode & 0o755) | 0o600)
            for _, relative, kind, _, link in entries:
                _check_cancel(cancel_event)
                if kind == 'symlink':
                    target = destination / relative
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    target.symlink_to(link)
            secure_owned_tree(destination.parent, destination)
    except ReaBootstrapError:
        raise
    except (OSError, ValueError, UnicodeError, tarfile.TarError, zipfile.BadZipFile):
        raise ReaBootstrapError('REA_NODE_ARCHIVE_INVALID') from None


def _remove_setup_tree(path: Path) -> None:
    # Windows scanners can briefly retain a just-closed archive. Retry only
    # this setup's owned tree and surface a persistent failure instead of
    # silently leaving a large downloaded archive behind.
    for attempt in range(3):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            if attempt == 2:
                raise ReaBootstrapError('REA_NODE_CLEANUP_FAILED') from None
            time.sleep(0.05 * (attempt + 1))


def ensure_node_runtime(progress: Callable[[str], Any] | None = None, *,
                        cancel_event: threading.Event | None = None) -> dict[str, Any]:
    """Use a supported Node/npm pair, or install the pinned private runtime."""
    _check_cancel(cancel_event)
    parent = _settings_parent()  # Validate before running any local executable.
    existing = _system_runtime(cancel_event)
    if existing:
        return existing
    host = _host_key()
    if host not in NODE_ARCHIVES:
        raise ReaBootstrapError('REA_NODE_UNSUPPORTED_PLATFORM')
    filename, checksum = NODE_ARCHIVES[host]
    root = parent / 'node'
    cached = _cached_runtime(root, host, checksum)
    _check_cancel(cancel_event)
    if cached:
        return cached
    _notify(progress, 'Preparing private Node.js and npm for REA…')
    try:
        with installation_lock(cancel_event):
            cached = _cached_runtime(root, host, checksum)
            _check_cancel(cancel_event)
            if cached:
                return cached
            staging = Path(tempfile.mkdtemp(prefix='node-install-', dir=root.parent))
            try:
                archive = staging / filename
                _notify(progress, f'Downloading official Node.js {NODE_VERSION}…')
                if _download_archive(filename, archive, cancel_event) != checksum:
                    raise ReaBootstrapError('REA_NODE_CHECKSUM_FAILED')
                extracted = staging / 'runtime'
                prefix = filename.removesuffix('.tar.gz').removesuffix('.zip')
                _notify(progress, 'Verifying and unpacking Node.js…')
                _extract_archive(archive, extracted, prefix, cancel_event)
                node, npm = _private_paths(extracted, host)
                versions = _probe_runtime(node, npm)
                _check_cancel(cancel_event)
                if not versions or versions[0] != NODE_VERSION:
                    raise ReaBootstrapError('REA_NODE_VERIFY_FAILED')
                (extracted / 'harnessy-node.json').write_text(json.dumps({
                    'version': NODE_VERSION, 'platform': host[0], 'architecture': host[1], 'archive_sha256': checksum,
                }), encoding='utf-8')
                (extracted / 'harnessy-node.json').chmod(0o600)
                backup = root.parent / ('node-replaced-' + uuid.uuid4().hex)
                moved = False
                _check_cancel(cancel_event)
                try:
                    if root.exists():
                        root.replace(backup)
                        moved = True
                    _check_cancel(cancel_event)
                    extracted.replace(root)
                except BaseException:
                    if moved and not root.exists():
                        backup.replace(root)
                    raise
                finally:
                    if moved and root.exists():
                        _remove_setup_tree(backup)
                node, npm = _private_paths(root, host)
                _notify(progress, 'Private Node.js and npm are ready.')
                return _runtime_result(node, npm, versions, source='private', installed=True, cached=False)
            finally:
                _remove_setup_tree(staging)
    except ReaBootstrapError:
        raise
    except OSError:
        raise ReaBootstrapError('REA_NODE_INSTALL_FAILED') from None
