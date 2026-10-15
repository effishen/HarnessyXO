"""Guest-only optional REA CLI provisioning; importing this module does no setup.

Install/update runs only from explicit VM tool provisioning. A verified package
and its Node runtime are staged together before the active release is switched.
No agent registration, host cache or user REA configuration is touched.
"""
from __future__ import annotations

import contextlib
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
import urllib.error
import uuid

TOOL_ID = 'rea'
PACKAGE = 'rea-agents'
ROOT = Path('/opt/harnessy-rea')
COMMAND = Path('/usr/local/bin/rea')
REGISTRY = 'https://registry.npmjs.org'
NODE_DIST = 'https://nodejs.org/dist'
INSTALL_SCHEMA = 1
WRAPPER_MARKER = '# HarnessyXO guest REA CLI'
_VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\Z')
_PHASES = {'storage', 'latest_release', 'node_runtime', 'npm_install', 'cli_verification', 'publish'}
_FAILURES = {'metadata_too_large', 'download_limit', 'command_failed', 'command_output_limit',
             'unsafe_storage', 'unsupported_architecture', 'supported_node_unavailable',
             'cached_runtime_invalid', 'node_checksum_missing', 'node_checksum_failed',
             'node_archive_limit', 'node_archive_invalid', 'node_verification_failed',
             'invalid_stable_release', 'package_verification_failed', 'cli_verification_failed',
             'command_conflict', 'network_or_metadata_failed', 'filesystem_failed'}


class InstallFailure(RuntimeError):
    pass


def _json_url(url: str):
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise InstallFailure('metadata_too_large')
    return json.loads(data)


def _download(url: str, destination: Path, *, maximum: int) -> None:
    total = 0
    started = time.monotonic()
    with urllib.request.urlopen(url, timeout=30) as response, destination.open('xb') as output:
        while True:
            data = response.read(1024 * 1024)
            if not data:
                return
            total += len(data)
            if total > maximum or time.monotonic() - started > 180:
                raise InstallFailure('download_limit')
            output.write(data)


def _run(arguments: list[str], *, env: dict | None = None, timeout: int = 30) -> str:
    try:
        result = subprocess.run(arguments, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=True, text=True)
    except (OSError, subprocess.SubprocessError):
        raise InstallFailure('command_failed') from None
    if len(result.stdout) > 1024 * 1024:
        raise InstallFailure('command_output_limit')
    return result.stdout.strip()


def supported_node(version: str) -> bool:
    if not _VERSION.fullmatch(version):
        return False
    major, minor, patch = map(int, version.split('.'))
    return ((major == 22 and (minor, patch) >= (19, 0))
            or (major == 24 and (minor, patch) >= (11, 0)) or major >= 26)


def _safe_root(root: Path) -> None:
    for path in (root, root / 'runtimes', root / 'releases'):
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise InstallFailure('unsafe_storage')
        if path.exists():
            info = path.stat()
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
                raise InstallFailure('unsafe_storage')
        path.mkdir(parents=True, exist_ok=True, mode=0o755)
        path.chmod(0o755)


def _release(root: Path) -> Path | None:
    current = root / 'current'
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to((root / 'releases').resolve(strict=True))
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_dir() else None


def _update_status(root: Path, result: dict[str, str]) -> dict[str, str]:
    try:
        descriptor = os.open(root / 'last-update.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 16384:
                return result
            last = json.loads(os.read(descriptor, 16385))
        finally:
            os.close(descriptor)
        if not isinstance(last, dict):
            return result
        if last.get('state') == 'failed' and last.get('phase') in _PHASES and last.get('reason_code') in _FAILURES:
            result.update(update_state='failed', reason_code=last['reason_code'], phase=last['phase'])
            result['detail'] += ' Last install/update failed at ' + last['phase'] + ': ' + last['reason_code'] + '. Apply Tools again to retry.'
        elif last.get('version') == result.get('version') and last.get('state') == 'current':
            result['update_state'] = 'current'
    except (OSError, ValueError, TypeError):
        pass
    return result


def status(root: Path = ROOT, command: Path = COMMAND) -> dict[str, str]:
    for path in (root, root / 'runtimes', root / 'releases'):
        try:
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()}
                    or stat.S_IMODE(info.st_mode) & 0o022):
                return {'state': 'partial', 'detail': 'The guest REA CLI storage needs repair: unsafe_storage.',
                        'update_state': 'failed', 'phase': 'storage', 'reason_code': 'unsafe_storage'}
        except FileNotFoundError:
            return _update_status(root, {'state': 'missing', 'detail': 'REA CLI is not installed in this guest.', 'update_state': 'unknown'})
    release = _release(root)
    if release is None:
        return _update_status(root, {'state': 'missing', 'detail': 'REA CLI is not installed in this guest.', 'update_state': 'unknown'})
    try:
        metadata = json.loads((release / 'harnessy-rea.json').read_text('utf-8'))
        package = json.loads((release / 'node_modules' / PACKAGE / 'package.json').read_text('utf-8'))
        version = package.get('version', '')
        node = release / 'runtime' / 'bin' / 'node'
        script = release / 'node_modules' / PACKAGE / 'scripts' / 'rea.mjs'
        if (package.get('name') != PACKAGE or not _VERSION.fullmatch(version)
                or metadata.get('version') != version or not script.is_file()
                or not os.access(node, os.X_OK) or not command.is_file()
                or WRAPPER_MARKER not in command.read_text('utf-8')[:4096]):
            raise ValueError()
        installed_node = _run([str(node), '--version'], timeout=4).removeprefix('v')
        if not supported_node(installed_node):
            raise ValueError()
        result = {'state': 'installed', 'detail': f'REA CLI {version} is installed inside this VM.',
                  'version': version, 'node_version': installed_node, 'update_state': 'unknown'}
        return _update_status(root, result)
    except (OSError, ValueError, TypeError, InstallFailure):
        return _update_status(root, {'state': 'partial', 'detail': 'The guest REA CLI installation needs repair.', 'update_state': 'unknown'})


def _node_runtime(root: Path, work: Path, architecture: str) -> Path:
    arch = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'x64', 'amd64': 'x64'}.get(architecture)
    if arch is None:
        raise InstallFailure('unsupported_architecture')
    index = _json_url(NODE_DIST + '/index.json')
    candidates = []
    for entry in index if isinstance(index, list) else []:
        version = str(entry.get('version', '')).removeprefix('v')
        if entry.get('lts') and supported_node(version) and f'linux-{arch}' in entry.get('files', []):
            candidates.append(version)
    if not candidates:
        raise InstallFailure('supported_node_unavailable')
    version = max(candidates, key=lambda value: tuple(map(int, value.split('.'))))
    name = f'node-v{version}-linux-{arch}'
    target = root / 'runtimes' / name
    if target.is_dir() and not target.is_symlink():
        if _run([str(target / 'bin' / 'node'), '--version']) == 'v' + version:
            return target
        raise InstallFailure('cached_runtime_invalid')
    sums = work / 'SHASUMS256.txt'
    _download(f'{NODE_DIST}/v{version}/SHASUMS256.txt', sums, maximum=1024 * 1024)
    filename = name + '.tar.gz'
    expected = None
    for line in sums.read_text('ascii').splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1] == filename and re.fullmatch(r'[0-9a-f]{64}', fields[0]):
            expected = fields[0]
            break
    if expected is None:
        raise InstallFailure('node_checksum_missing')
    archive = work / filename
    _download(f'{NODE_DIST}/v{version}/{filename}', archive, maximum=128 * 1024 * 1024)
    digest = hashlib.sha256()
    with archive.open('rb') as handle:
        for data in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(data)
    if digest.hexdigest() != expected:
        raise InstallFailure('node_checksum_failed')
    with tarfile.open(archive, 'r:gz') as package:
        members = package.getmembers()
        if len(members) > 10000 or sum(item.size for item in members) > 512 * 1024 * 1024:
            raise InstallFailure('node_archive_limit')
        for item in members:
            path = PurePosixPath(item.name)
            if (not path.parts or path.parts[0] != name or path.is_absolute()
                    or '..' in path.parts or not (item.isfile() or item.isdir() or item.issym())):
                raise InstallFailure('node_archive_invalid')
            if item.issym():
                link = (work / item.name).parent / item.linkname
                try:
                    link.resolve().relative_to((work / name).resolve())
                except ValueError:
                    raise InstallFailure('node_archive_invalid') from None
        # Do not import archive uid/gid ownership. Every installed Node file
        # belongs to the guest installer, with public non-writable modes.
        for item in members:
            if item.isdir():
                (work / item.name).mkdir(parents=True, exist_ok=True, mode=0o755)
        for item in members:
            if not item.isfile():
                continue
            target_path = work / item.name
            target_path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            source = package.extractfile(item)
            if source is None:
                raise InstallFailure('node_archive_invalid')
            with source, target_path.open('xb') as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            target_path.chmod(0o755 if item.mode & 0o111 else 0o644)
        for item in members:
            if item.issym():
                (work / item.name).symlink_to(item.linkname)
        for parent, directories, _files in os.walk(work / name, followlinks=False):
            Path(parent).chmod(0o755)
            for directory in directories:
                path = Path(parent) / directory
                if not path.is_symlink():
                    path.chmod(0o755)
    extracted = work / name
    if _run([str(extracted / 'bin' / 'node'), '--version']) != 'v' + version:
        raise InstallFailure('node_verification_failed')
    extracted.rename(target)
    target.chmod(0o755)
    return target


def _atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    try:
        temporary.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')
        temporary.chmod(0o644)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _wrapper(root: Path) -> str:
    import shlex
    return (f'#!/bin/sh\n{WRAPPER_MARKER}\n'
            f'base=$(readlink -f -- {shlex.quote(str(root / "current"))}) || exit 1\n'
            'PATH="$base/runtime/bin:$PATH"; export PATH\n'
            'exec "$base/runtime/bin/node" "$base/node_modules/rea-agents/scripts/rea.mjs" "$@"\n')


def _publish_modes(prefix: Path) -> None:
    # npm inherits the caller's umask. Published package files are public
    # software, so make them readable/traversable by ordinary guest users and
    # remove group/other write access before the release is activated.
    for parent, directories, files in os.walk(prefix, followlinks=False):
        Path(parent).chmod(0o755)
        for name in (*directories, *files):
            path = Path(parent) / name
            if path.is_symlink():
                continue
            info = path.stat()
            path.chmod(0o755 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o111 else 0o644)


def install(root: Path = ROOT, command: Path = COMMAND, *, network: bool = False,
            architecture: str | None = None) -> dict[str, str]:
    if not network:
        return {'state': 'pending', 'reason': 'outbound_disabled'}
    phase = 'storage'
    storage_safe = False
    try:
        import fcntl  # Provisioning executes only inside supported Linux guests.
        _safe_root(root)
        storage_safe = True
        descriptor = os.open(root / '.install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            phase = 'latest_release'
            latest = _json_url(REGISTRY + '/' + PACKAGE + '/latest')
            version = latest.get('version', '') if isinstance(latest, dict) else ''
            if (not isinstance(latest, dict) or latest.get('name') != PACKAGE
                    or not isinstance(version, str) or not _VERSION.fullmatch(version)):
                raise InstallFailure('invalid_stable_release')
            existing = status(root, command)
            if existing.get('state') == 'installed' and existing.get('version') == version:
                _atomic_json(root / 'last-update.json', {'state': 'current', 'version': version})
                return {'state': 'installed', 'version': version, 'reason': 'up_to_date'}
            with tempfile.TemporaryDirectory(prefix='.install-', dir=root) as temporary:
                work = Path(temporary)
                phase = 'node_runtime'
                runtime = _node_runtime(root, work, architecture or platform.machine())
                prefix = work / 'package'
                prefix.mkdir(mode=0o755)
                env = dict(os.environ)
                env['PATH'] = str(runtime / 'bin') + os.pathsep + env.get('PATH', '/usr/bin:/bin')
                env['npm_config_cache'] = str(root / 'npm-cache')
                phase = 'npm_install'
                npm = runtime / 'lib' / 'node_modules' / 'npm' / 'bin' / 'npm-cli.js'
                _run([str(runtime / 'bin' / 'node'), str(npm), 'install', '--prefix', str(prefix),
                      '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', '--no-progress',
                      '--engine-strict', '--registry', REGISTRY, f'{PACKAGE}@{version}'], env=env, timeout=600)
                package = prefix / 'node_modules' / PACKAGE
                metadata = json.loads((package / 'package.json').read_text('utf-8'))
                if metadata.get('name') != PACKAGE or metadata.get('version') != version:
                    raise InstallFailure('package_verification_failed')
                phase = 'cli_verification'
                if _run([str(runtime / 'bin' / 'node'), str(package / 'scripts' / 'rea.mjs'), '--version'],
                        env=env, timeout=30) != version:
                    raise InstallFailure('cli_verification_failed')
                _publish_modes(prefix)
                (prefix / 'runtime').symlink_to(runtime, target_is_directory=True)
                _atomic_json(prefix / 'harnessy-rea.json', {'schema': INSTALL_SCHEMA, 'version': version})
                if command.exists() or command.is_symlink():
                    if command.is_symlink() or WRAPPER_MARKER not in command.read_text('utf-8')[:4096]:
                        raise InstallFailure('command_conflict')
                phase = 'publish'
                command.parent.mkdir(parents=True, exist_ok=True)
                release = root / 'releases' / (version + '-' + uuid.uuid4().hex[:12])
                prefix.rename(release)
                current = root / ('.current-' + uuid.uuid4().hex)
                current.symlink_to(release, target_is_directory=True)
                wrapper = command.with_name('.rea-' + uuid.uuid4().hex)
                try:
                    wrapper.write_text(_wrapper(root), encoding='utf-8')
                    wrapper.chmod(0o755)
                    _atomic_json(root / 'last-update.json', {'state': 'current', 'version': version})
                    wrapper.replace(command)
                    # Last operation: every download, probe and filesystem write
                    # must succeed before changing the working installation.
                    current.replace(root / 'current')
                finally:
                    wrapper.unlink(missing_ok=True)
                    current.unlink(missing_ok=True)
                return {'state': 'installed', 'version': version, 'reason': 'updated'}
    except Exception as exc:
        # No partially prepared package replaces current. Old releases and their
        # runtime remain available, including when the registry is offline.
        reason_code = (str(exc) if isinstance(exc, InstallFailure) and str(exc) in _FAILURES else
                       'filesystem_failed' if isinstance(exc, OSError) and not isinstance(exc, urllib.error.URLError)
                       else 'network_or_metadata_failed')
        with contextlib.suppress(OSError):
            if storage_safe:
                _atomic_json(root / 'last-update.json', {'state': 'failed', 'phase': phase, 'reason_code': reason_code})
        cached = status(root, command)
        return {'state': cached['state'], 'reason': 'update_failed_cached' if cached['state'] == 'installed' else 'install_failed',
                'phase': phase, 'reason_code': reason_code}


def _guest_main(action: str, root: Path, command: Path) -> None:
    if action == 'status':
        print(json.dumps(status(root, command), sort_keys=True))
        return
    if action == 'remove':
        if command.is_file() and not command.is_symlink() and WRAPPER_MARKER in command.read_text('utf-8')[:4096]:
            command.unlink()
        if root.is_dir() and not root.is_symlink():
            shutil.rmtree(root)
        return
    result = install(root, command, network=True)
    if result.get('reason') in {'install_failed', 'update_failed_cached'}:
        print('HARNESSY_PROVISION_WARNING=REA CLI update failed at ' + result.get('phase', 'unknown')
              + ' (' + result.get('reason_code', 'network_or_metadata_failed') + ')'
              + '; any existing working guest installation was preserved. Apply Tools again to retry.')
    else:
        print('HARNESSY_REA_VERSION=' + result.get('version', ''))


def _script(action: str, root: Path, command: Path) -> str:
    source = Path(__file__).read_text('utf-8')
    return ("python3 - <<'HARNESSY_REA_GUEST_TOOL'\n" + source
            + f'\n_guest_main({action!r}, Path({str(root)!r}), Path({str(command)!r}))\n'
            + 'HARNESSY_REA_GUEST_TOOL\n')


def install_script(*, network: bool, root: Path = ROOT, command: Path = COMMAND) -> str:
    if not network:
        return "printf '%s\\n' 'HARNESSY_PROVISION_WARNING=REA CLI download skipped: public outbound is disabled.'\n"
    return ("printf '%s\\n' HARNESSY_PROVISION_STAGE=rea_cli\n"
            "printf '%s\\n' HARNESSY_OPTIONAL_TOOL=rea\n" + _script('install', root, command))


def status_script(*, root: Path = ROOT, command: Path = COMMAND) -> str:
    return _script('status', root, command)


def remove_script() -> str:
    return _script('remove', ROOT, COMMAND)
