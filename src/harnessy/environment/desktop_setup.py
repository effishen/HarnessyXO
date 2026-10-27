"""Bounded guest graphics observations and an explicit, disk-preserving repair."""
from __future__ import annotations

import json
import math
import re

DESKTOP_SETUP_REVISION = '1'
DESKTOP_PROBE_TIMEOUT_SECONDS = 20
DESKTOP_REPAIR_TIMEOUT_SECONDS = 900
DESKTOP_SETUP_ERRORS = frozenset({'NONE', 'DESKTOP_PROBE_FAILED',
    'DESKTOP_PREREQUISITE_MISSING', 'DESKTOP_OFFLINE', 'DESKTOP_APT_UPDATE_FAILED',
    'DESKTOP_APT_INSTALL_FAILED', 'DESKTOP_KERNEL_UNSUPPORTED',
    'DESKTOP_KERNEL_VERIFY_FAILED', 'DESKTOP_BOOT_POLICY_CUSTOM',
    'DESKTOP_BOOT_VERIFY_FAILED', 'DESKTOP_SESSION_NOT_READY',
    'DESKTOP_REPAIR_TIMEOUT', 'DESKTOP_REPAIR_CANCELLED', 'DESKTOP_REPAIR_BUSY',
    'DESKTOP_ARCH_MISMATCH', 'DESKTOP_REPAIR_FAILED'})
DESKTOP_SETUP_STATES = frozenset({'ready', 'unavailable', 'checking', 'reboot_required',
    'manual_boot_required', 'failed', 'disabled', 'unknown'})
DESKTOP_FAILURE_REASONS = frozenset({'dns_failed', 'network_timeout', 'repository_error',
    'command_timeout', 'package_unavailable', 'package_lock', 'storage_full', 'package_command_failed', 'unknown'})
DESKTOP_EVENT_STAGES = frozenset({'checking', 'package_index', 'packages', 'kernel',
                                 'boot', 'session', 'verifying'})
_VERSION = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,4}')
_UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
_HASH = re.compile(r'[0-9a-f]{64}')
_BOOL_FIELDS = ('kali', 'cloud_kernel', 'virtio_gpu_module', 'virtio_gpu_loaded',
    'scanout_active', 'framebuffer', 'xorg_installed', 'xfce_installed', 'xorg_running',
    'xfce_running', 'x11_socket', 'kernel_repair_needed', 'kernel_staged',
    'boot_configured', 'requires_reboot')


def _project(raw: object) -> dict:
    if not isinstance(raw, dict) or type(raw.get('schema_version')) is not int or raw['schema_version'] != 1:
        raw = {}
    result = {'schema_version': 1, 'state': 'unavailable', 'error_code': 'DESKTOP_PROBE_FAILED',
              'failure_reason': 'unknown'}
    for field, allowed in (
        ('state', DESKTOP_SETUP_STATES), ('error_code', DESKTOP_SETUP_ERRORS),
        ('failure_reason', DESKTOP_FAILURE_REASONS),
        ('architecture', {'arm64', 'amd64', 'unsupported'}),
        ('drm_config', {'y', 'm', 'n', 'unknown'}),
        ('virtio_gpu_config', {'y', 'm', 'n', 'unknown'}),
        ('kernel_graphics', {'supported', 'unsupported', 'unknown'}),
        ('lightdm_active', {'active', 'inactive', 'failed', 'activating', 'deactivating', 'unknown'}),
        ('lightdm_enabled', {'enabled', 'disabled', 'static', 'masked', 'not-found', 'unknown'}),
    ):
        value = raw.get(field)
        result[field] = value if isinstance(value, str) and value in allowed else result.get(field, 'unknown')
    for field in _BOOL_FIELDS:
        result[field] = raw.get(field) is True
    for field, maximum in (('drm_cards', 8), ('drm_connectors', 32)):
        value = raw.get(field)
        result[field] = value if type(value) is int and 0 <= value <= maximum else 0
    for field, expression in (('boot_id', _UUID), ('kernel_version', _VERSION),
                              ('candidate_kernel_version', _VERSION),
                              ('running_kernel_sha256', _HASH), ('candidate_kernel_sha256', _HASH)):
        value = raw.get(field)
        result[field] = value if isinstance(value, str) and expression.fullmatch(value) else ''
    ready = (result['error_code'] == 'NONE' and bool(result['boot_id'])
             and result['drm_cards'] > 0 and result['drm_connectors'] > 0 and result['scanout_active']
             and result['lightdm_active'] == 'active' and all(result[name] for name in
             ('xorg_installed', 'xfce_installed', 'xorg_running', 'xfce_running', 'x11_socket')))
    if result['state'] == 'ready' and not ready:
        result.update(state='unavailable', error_code='DESKTOP_SESSION_NOT_READY')
    if result['state'] == 'reboot_required' and not (result['kernel_staged']
            and result['boot_configured'] and result['requires_reboot']
            and result['candidate_kernel_version'] and result['candidate_kernel_sha256']):
        result.update(state='failed', error_code='DESKTOP_BOOT_VERIFY_FAILED', requires_reboot=False)
    if result['state'] == 'manual_boot_required' and not (result['kernel_staged']
            and result['candidate_kernel_version'] and result['candidate_kernel_sha256']):
        result.update(state='failed', error_code='DESKTOP_KERNEL_VERIFY_FAILED', requires_reboot=False)
    return result


def parse_desktop_probe(stdout: str) -> dict:
    try:
        raw = json.loads(stdout) if isinstance(stdout, str) and len(stdout) <= 16384 else None
    except (ValueError, TypeError):
        raw = None
    return _project(raw)


def parse_desktop_repair(stdout: str) -> dict:
    raw = None
    if isinstance(stdout, str) and len(stdout) <= 131072:
        for line in stdout.splitlines():
            if line.startswith('HARNESSY_DESKTOP_REPAIR=') and len(line) <= 16410:
                try:
                    raw = json.loads(line.partition('=')[2])
                except ValueError:
                    raw = None
    return _project(raw)


def parse_desktop_event(line: str) -> dict | None:
    """Accept only the bounded technical protocol, never child command output."""
    if not isinstance(line, str) or len(line) > 2048 or not line.startswith('HARNESSY_DESKTOP_EVENT='):
        return None
    try:
        raw = json.loads(line.partition('=')[2])
    except (ValueError, TypeError):
        return None
    if (not isinstance(raw, dict) or type(raw.get('schema_version')) is not int
            or raw['schema_version'] != 1 or not isinstance(raw.get('boot_id'), str)
            or not _UUID.fullmatch(raw['boot_id']) or not isinstance(raw.get('stage'), str)
            or raw['stage'] not in DESKTOP_EVENT_STAGES):
        return None
    result = {name: raw[name] for name in ('schema_version', 'boot_id', 'stage')}
    for field in ('elapsed_seconds', 'command_elapsed_seconds', 'last_output_age_seconds'):
        if field not in raw:
            return None
        value = raw[field]
        if field == 'last_output_age_seconds' and value is None:
            result[field] = None
        elif type(value) in (int, float) and 0 <= value <= 900 and math.isfinite(value):
            result[field] = float(value)
        else:
            return None
    value = raw.get('output_bytes')
    if type(value) is not int or not 0 <= value <= 2 ** 40:
        return None
    result['output_bytes'] = value
    return result


_GUEST = r'''
import fcntl
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import time

BOOT = Path('/boot')
MODULES = Path('/lib/modules')
PROC = Path('/proc')
DRM = Path('/sys/class/drm')
GRAPHICS = Path('/sys/class/graphics')
X11 = Path('/tmp/.X11-unix')
OS_RELEASE = Path('/etc/os-release')
GRUB_DEFAULT = Path('/etc/default/grub')
GRUB_DROPINS = Path('/etc/default/grub.d')
GRUB_LINUX = Path('/etc/grub.d/10_linux')
OWN_GRUB = GRUB_DROPINS / '60_harnessy-desktop.cfg'
GRUB_CFG = BOOT / 'grub/grub.cfg'
GRUB_ENV = BOOT / 'grub/grubenv'
LIGHTDM_DIR = Path('/etc/lightdm/lightdm.conf.d')
OWN_LIGHTDM = LIGHTDM_DIR / '50-harnessy.conf'
LOCK = Path('/run/harnessy-desktop-setup.lock')
LOG_ACTIONS = False
DEADLINE = time.monotonic() + 16.0
LOCK_FD = None
RELEASE = os.uname().release
RELEASE_SAFE = bool(re.fullmatch(r'[A-Za-z0-9._+-]{1,96}', RELEASE))
BOOT_ID = ''
EVENT_STARTED = time.monotonic()
EVENT_STAGE = 'checking'
HEARTBEAT_SECONDS = 10.0

class Failure(Exception):
    def __init__(self, code, reason='unknown'):
        self.code, self.reason = code, reason

def event(stage=None, *, command_elapsed=0.0, output_bytes=0, last_output_age=None):
    global EVENT_STAGE
    if not LOG_ACTIONS:
        return
    if stage is not None:
        EVENT_STAGE = stage
    boot = BOOT_ID or text(PROC / 'sys/kernel/random/boot_id', 64, root=False)
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot):
        return
    payload = dict(schema_version=1, boot_id=boot, stage=EVENT_STAGE,
        elapsed_seconds=round(min(900.0, max(0.0, time.monotonic() - EVENT_STARTED)), 3),
        command_elapsed_seconds=round(min(900.0, max(0.0, command_elapsed)), 3),
        output_bytes=min(2 ** 40, max(0, output_bytes)),
        last_output_age_seconds=None if last_output_age is None else round(min(900.0, max(0.0, last_output_age)), 3))
    print('HARNESSY_DESKTOP_EVENT=' + json.dumps(payload, separators=(',', ':')), flush=True)

def action(name, text, stage=None):
    if LOG_ACTIONS:
        if stage is not None:
            event(stage)
        print('[%d] %s %s' % (int(time.time()), name, text), flush=True)

def read_file(path, limit, root=True):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit or (root and
                (info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1)):
            raise OSError('unsafe file')
        data = os.read(fd, limit + 1)
        if len(data) > limit:
            raise OSError('oversized file')
        return data
    finally:
        os.close(fd)

def text(path, limit=4096, root=True):
    try:
        return read_file(path, limit, root).decode('utf-8', errors='replace').strip()
    except OSError:
        return ''

def atomic(path, data, mode=0o644):
    info = path.parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Failure('DESKTOP_PREREQUISITE_MISSING')
    try:
        old = path.lstat()
        if not stat.S_ISREG(old.st_mode) or old.st_uid != 0 or old.st_nlink != 1 or old.st_mode & 0o022:
            raise Failure('DESKTOP_PREREQUISITE_MISSING')
    except FileNotFoundError:
        pass
    fd, temporary = tempfile.mkstemp(prefix='.harnessy-desktop-', dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass

def terminate(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass

def run(arguments, seconds):
    remaining = min(seconds, DEADLINE - time.monotonic())
    if remaining <= 0:
        raise Failure('DESKTOP_REPAIR_TIMEOUT', 'command_timeout')
    environment = dict(os.environ, LC_ALL='C', LANG='C', DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='a')
    for key in list(environment):
        if key.startswith('GRUB_'):
            environment.pop(key)
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True, env=environment)
    except OSError:
        return 127, b''
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    started = time.monotonic()
    expires = started + remaining
    next_heartbeat = started + HEARTBEAT_SECONDS
    output_bytes = 0
    last_output = None
    exited = None
    try:
        event(command_elapsed=0.0, output_bytes=0, last_output_age=None)
        while time.monotonic() < expires:
            for key, _ in selector.select(min(.1, max(.001, expires - time.monotonic()))):
                data = os.read(key.fileobj.fileno(), 8192)
                if data:
                    output_bytes += len(data)
                    last_output = time.monotonic()
                    output.extend(data)
                    del output[:-65536]
                else:
                    selector.unregister(key.fileobj)
            code = process.poll()
            now = time.monotonic()
            if code is None and now >= next_heartbeat:
                event(command_elapsed=now - started, output_bytes=output_bytes,
                      last_output_age=None if last_output is None else now - last_output)
                next_heartbeat = now + HEARTBEAT_SECONDS
            if code is not None:
                if not selector.get_map():
                    return code, bytes(output)
                exited = exited or time.monotonic()
                if time.monotonic() - exited > .2:
                    return code, bytes(output)
        return 124, bytes(output)
    finally:
        terminate(process)
        selector.close()
        process.stdout.close()

def config(release):
    result = {'CONFIG_DRM': 'unknown', 'CONFIG_DRM_VIRTIO_GPU': 'unknown'}
    data = text(BOOT / ('config-' + release), 1048576)
    for key in result:
        match = re.search(r'^' + key + r'=([ymn])$', data, re.M)
        if match:
            result[key] = match.group(1)
        elif re.search(r'^# ' + key + r' is not set$', data, re.M):
            result[key] = 'n'
    if result['CONFIG_DRM'] == 'n':
        result['CONFIG_DRM_VIRTIO_GPU'] = 'n'
    return result

def kernel_hash(release):
    if not re.fullmatch(r'[A-Za-z0-9._+-]{1,96}', release):
        return ''
    try:
        path = BOOT / ('vmlinuz-' + release)
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022 or not 0 < before.st_size <= 134217728:
                return ''
            digest = hashlib.sha256()
            total = 0
            while True:
                if time.monotonic() >= DEADLINE:
                    return ''
                data = os.read(fd, 1048576)
                if not data:
                    break
                total += len(data)
                if total > 134217728:
                    return ''
                digest.update(data)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                return ''
            return digest.hexdigest()
        finally:
            os.close(fd)
    except OSError:
        return ''

def version(release):
    match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,4})(?:[-+.]|$)', release)
    return match.group(1) if match else ''

def machine_arch():
    return {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64', 'amd64': 'amd64'}.get(os.uname().machine, 'unsupported')

def executable(name):
    if name == 'Xorg':
        return bool(shutil.which(name) or os.access('/usr/lib/xorg/Xorg', os.X_OK))
    return bool(shutil.which(name))

def process_names():
    found = set()
    try:
        with os.scandir(PROC) as entries:
            for count, entry in enumerate(entries):
                if count >= 2048 or time.monotonic() >= DEADLINE:
                    break
                if entry.name.isdecimal():
                    name = text(Path(entry.path) / 'comm', 64, root=False)
                    if name in ('Xorg', 'Xorg.wrap', 'xfce4-session'):
                        try:
                            executable_name = Path(os.readlink(Path(entry.path) / 'exe')).name
                            if executable_name in ('Xorg', 'Xorg.wrap', 'xfce4-session'):
                                found.add(executable_name)
                        except OSError:
                            pass
    except OSError:
        pass
    return found

def system_state(option, allowed):
    code, output = run(['systemctl', option, 'lightdm'], 2)
    value = output.decode(errors='replace').strip()
    return value if value in allowed else 'unknown'

def probe():
    global BOOT_ID
    boot = text(PROC / 'sys/kernel/random/boot_id', 64, root=False)
    BOOT_ID = boot if re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot) else ''
    cfg = config(RELEASE) if RELEASE_SAFE else {'CONFIG_DRM': 'unknown', 'CONFIG_DRM_VIRTIO_GPU': 'unknown'}
    module = run(['modinfo', '-k', RELEASE, '-F', 'filename', 'virtio_gpu'], 2)[0] == 0 if RELEASE_SAFE else False
    support = ('supported' if cfg['CONFIG_DRM_VIRTIO_GPU'] in ('y', 'm') or module else
               'unsupported' if cfg['CONFIG_DRM'] == 'n' or cfg['CONFIG_DRM_VIRTIO_GPU'] == 'n' else 'unknown')
    try:
        distribution = text(OS_RELEASE.resolve(strict=True), 16384)
    except OSError:
        distribution = ''
    kali = bool(re.search(r'^ID=(?:kali|"kali"|\x27kali\x27)$', distribution, re.M))
    cloud = bool(re.search(r'(?:^|[-+])cloud(?:-|$)', RELEASE)) if RELEASE_SAFE else False
    cards = connectors = 0
    scanout = False
    try:
        for entry in itertools.islice(DRM.iterdir(), 64):
            if re.fullmatch(r'card\d+', entry.name):
                cards = min(8, cards + 1)
            elif re.fullmatch(r'card\d+-.{1,40}', entry.name):
                connectors = min(32, connectors + 1)
                if text(entry / 'status', root=False) == 'connected' and text(entry / 'enabled', root=False) == 'enabled':
                    scanout = True
    except OSError:
        pass
    framebuffer = any((GRAPHICS / ('fb%d' % n)).exists() for n in range(8))
    sockets = False
    for n in range(8):
        try:
            sockets = sockets or stat.S_ISSOCK((X11 / ('X%d' % n)).lstat().st_mode)
        except OSError:
            pass
    processes = process_names()
    result = dict(schema_version=1, boot_id=BOOT_ID, architecture=machine_arch(),
        kernel_version=version(RELEASE), running_kernel_sha256=kernel_hash(RELEASE),
        kali=kali, cloud_kernel=cloud, drm_config=cfg['CONFIG_DRM'],
        virtio_gpu_config=cfg['CONFIG_DRM_VIRTIO_GPU'], virtio_gpu_module=module,
        virtio_gpu_loaded=(Path('/sys/module/virtio_gpu')).exists(), kernel_graphics=support,
        drm_cards=cards, drm_connectors=connectors, scanout_active=scanout, framebuffer=framebuffer,
        xorg_installed=executable('Xorg'), xfce_installed=executable('startxfce4'),
        xorg_running=bool(processes & {'Xorg', 'Xorg.wrap'}), xfce_running='xfce4-session' in processes,
        x11_socket=sockets, lightdm_active=system_state('is-active', {'active', 'inactive', 'failed', 'activating', 'deactivating'}),
        lightdm_enabled=system_state('is-enabled', {'enabled', 'disabled', 'static', 'masked', 'not-found'}),
        kernel_repair_needed=kali and cloud and support == 'unsupported', kernel_staged=False,
        boot_configured=False, requires_reboot=False, candidate_kernel_version='', candidate_kernel_sha256='',
        failure_reason='unknown')
    ready = (bool(BOOT_ID) and cards > 0 and connectors > 0 and scanout and result['lightdm_active'] == 'active'
        and all(result[key] for key in ('xorg_installed', 'xfce_installed', 'xorg_running', 'xfce_running', 'x11_socket')))
    result.update(state='ready' if ready else 'unavailable',
                  error_code='NONE' if ready else ('DESKTOP_KERNEL_UNSUPPORTED' if result['kernel_repair_needed'] else 'DESKTOP_SESSION_NOT_READY'))
    return result
'''

_REPAIR = r'''
EXPECTED_ARCH = __ARCHITECTURE__
PUBLIC_NETWORK = __PUBLIC_NETWORK__
ALLOW_KERNEL = __ALLOW_KERNEL__
LOG_ACTIONS = True
DEADLINE = time.monotonic() + 880.0
EVENT_STARTED = time.monotonic()
RESULT = dict(schema_version=1, state='failed', error_code='DESKTOP_REPAIR_FAILED', failure_reason='unknown')

def interrupted(signum, frame):
    for item in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(item, signal.SIG_IGN)
    raise Failure('DESKTOP_REPAIR_CANCELLED')

def classify(code, output):
    value = output.decode(errors='replace').lower()
    for label, words in (
        ('storage_full', ('no space left', 'disk quota exceeded', 'read-only file system')),
        ('package_lock', ('could not get lock', 'unable to acquire', 'dpkg frontend lock')),
        ('dns_failed', ('temporary failure resolving', 'could not resolve', 'name or service not known')),
        ('network_timeout', ('timed out', 'connection timeout', 'network is unreachable')),
        ('package_unavailable', ('unable to locate package', 'has no installation candidate', 'package is not available')),
        ('repository_error', ('release file', 'not signed', 'certificate verification failed', '404 not found', '403 forbidden')),
    ):
        if any(word in value for word in words):
            return label
    return 'command_timeout' if code == 124 else 'package_command_failed'

def lock():
    global LOCK_FD
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise Failure('DESKTOP_REPAIR_BUSY', 'package_lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Failure('DESKTOP_REPAIR_BUSY', 'package_lock')
        LOCK_FD = fd
    except BaseException:
        os.close(fd)
        raise

def apt(packages):
    if not PUBLIC_NETWORK:
        raise Failure('DESKTOP_OFFLINE')
    options = ['-o', 'Acquire::Retries=1', '-o', 'Acquire::http::Timeout=15',
        '-o', 'Acquire::https::Timeout=15', '-o', 'DPkg::Lock::Timeout=30']
    action('INSTALL', 'Refreshing guest package indexes for the graphical desktop', 'package_index')
    code, output = run(['apt-get', *options, 'update'], 90)
    if code:
        raise Failure('DESKTOP_APT_UPDATE_FAILED', classify(code, output))
    action('INSTALL', 'Installing selected graphical desktop dependencies',
           'kernel' if any(item.startswith('linux-image-') for item in packages) else 'packages')
    code, output = run(['apt-get', *options, 'install', '-y', '--no-install-recommends', *packages], 650)
    if code:
        raise Failure('DESKTOP_APT_INSTALL_FAILED', classify(code, output))

def install_desktop():
    if shutil.which('apt-get'):
        apt(['xorg', 'xfce4', 'xfce4-terminal', 'lightdm', 'dbus-x11'])
        return
    if not PUBLIC_NETWORK:
        raise Failure('DESKTOP_OFFLINE')
    if not shutil.which('dnf'):
        raise Failure('DESKTOP_PREREQUISITE_MISSING')
    action('INSTALL', 'Installing selected graphical desktop dependencies', 'packages')
    code, output = run(['dnf', '--setopt=timeout=15', '--setopt=retries=1', 'install', '-y',
        '@xfce-desktop-environment', 'lightdm', 'xorg-x11-server-Xorg', 'dbus-x11'], 650)
    if code:
        raise Failure('DESKTOP_APT_INSTALL_FAILED', classify(code, output))

def candidate():
    candidates = []
    try:
        entries = list(itertools.islice(BOOT.iterdir(), 256))
    except OSError:
        return None
    for path in entries:
        if not path.name.startswith('config-'):
            continue
        release = path.name[len('config-'):]
        if not re.fullmatch(r'[A-Za-z0-9._+-]{1,96}', release) or not release.endswith('-' + EXPECTED_ARCH) or 'cloud' in release or not version(release):
            continue
        cfg = config(release)
        if cfg['CONFIG_DRM'] not in ('y', 'm') or cfg['CONFIG_DRM_VIRTIO_GPU'] not in ('y', 'm'):
            continue
        digest = kernel_hash(release)
        try:
            initrd = BOOT / ('initrd.img-' + release)
            info = initrd.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size <= 0:
                continue
        except OSError:
            continue
        if cfg['CONFIG_DRM_VIRTIO_GPU'] == 'm':
            code, output = run(['modinfo', '-k', release, '-F', 'filename', 'virtio_gpu'], 3)
            module_path = output.decode(errors='replace').strip()
            try:
                module = Path(module_path)
                info = module.lstat()
                if code or not module.is_relative_to(MODULES / release) or not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size <= 0:
                    continue
            except (OSError, ValueError):
                continue
        if digest:
            candidates.append((tuple(int(n) for n in version(release).split('.')), release, digest))
    return max(candidates) if candidates else None

def boot_policy():
    # Standard 41_custom sources this file after the generated menu. Its
    # commands can change the effective default outside /etc/default/grub.
    if (BOOT / 'grub/custom.cfg').exists() or (BOOT / 'grub/custom.cfg').is_symlink():
        return False
    code = text(GRUB_LINUX, 262144)
    if 'reverse_sorted_list=$(grub_move_to_front "$GRUB_TOP_LEVEL" ${reverse_sorted_list})' not in code:
        return False
    paths = [GRUB_DEFAULT]
    try:
        if GRUB_DROPINS.exists():
            entries = sorted(itertools.islice(GRUB_DROPINS.iterdir(), 65))
            if len(entries) > 64:
                return False
            paths.extend(path for path in entries if path.suffix == '.cfg' and path != OWN_GRUB)
    except OSError:
        return False
    default = None
    for path in paths:
        try:
            contents = read_file(path, 65536).decode()
        except (OSError, UnicodeError):
            return False
        for line in contents.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            match = re.fullmatch(r'(?:export\s+)?([A-Za-z_]\w*)=(.*)', line)
            if not match:
                return False
            name, value = match.groups()
            if name not in ('GRUB_DEFAULT', 'GRUB_TOP_LEVEL', 'GRUB_SAVEDEFAULT'):
                continue
            try:
                words = shlex.split(value, comments=True)
            except ValueError:
                return False
            value = words[0] if len(words) == 1 else '' if not words else 'unknown'
            if name == 'GRUB_DEFAULT':
                if value != '0':
                    return False
                default = value
            if name == 'GRUB_TOP_LEVEL' and value:
                return False
            if name == 'GRUB_SAVEDEFAULT' and value not in ('', 'false', '0'):
                return False
    if default != '0':
        return False
    try:
        own = read_file(OWN_GRUB, 4096).decode()
    except FileNotFoundError:
        own = ''
    except (OSError, UnicodeError):
        return False
    if own and not re.fullmatch(r'# Managed by HarnessyXO desktop repair\.\nGRUB_TOP_LEVEL=\x27/boot/vmlinuz-[A-Za-z0-9._+-]{1,96}\x27\n', own):
        return False
    code, output = run(['grub-editenv', str(GRUB_ENV), 'list'], 3)
    if code:
        return False
    for line in output.decode(errors='replace').splitlines():
        key, separator, value = line.partition('=')
        if separator and key in ('next_entry', 'prev_saved_entry') and value:
            return False
    return True

def select_boot(release):
    action('CHECK', 'Inspecting the guest boot policy', 'boot')
    if not boot_policy():
        return False
    before_cfg = read_file(GRUB_CFG, 4194304)
    try:
        before_own = read_file(OWN_GRUB, 4096)
    except FileNotFoundError:
        before_own = None
    GRUB_DROPINS.mkdir(mode=0o755, exist_ok=True)
    payload = ("# Managed by HarnessyXO desktop repair.\nGRUB_TOP_LEVEL='/boot/vmlinuz-" + release + "'\n").encode()
    atomic(OWN_GRUB, payload)
    action('CONFIGURE', 'Selecting the verified generic kernel: /etc/default/grub.d/60_harnessy-desktop.cfg', 'boot')
    try:
        code, output = run(['update-grub'], 40)
        if code:
            raise Failure('DESKTOP_BOOT_VERIFY_FAILED')
        generated = read_file(GRUB_CFG, 4194304).decode('utf-8')
        # GRUB_DEFAULT=0 selects a menu entry, not the first Linux command.
        # A preceding chainloader/submenu must never silently pass this proof.
        first = None
        offset = 0
        for line in generated.splitlines(keepends=True):
            if not line.lstrip().startswith('#') and re.search(r'(?<![\w$])(?:menuentry|submenu)(?![\w])', line):
                first = re.fullmatch(r'menuentry[ \t]+[^\n]*\{[ \t]*\n?', line)
                if first:
                    first = (offset, offset + first.end())
                break
            offset += len(line)
        if first is None:
            raise Failure('DESKTOP_BOOT_POLICY_CUSTOM')
        prefix, suffix = generated[:first[0]], generated[first[0]:]
        # Default 0 and GRUB's standard, empty next_entry branch are the only
        # accepted generated policies. Custom overrides after any entry are
        # never inferred safe from the /etc/default/grub setting.
        if re.search(r'(?m)^[ \t]*[^#\n]*\bset[ \t]+default\b', suffix):
            raise Failure('DESKTOP_BOOT_POLICY_CUSTOM')
        for line in generated.splitlines():
            if line.lstrip().startswith('#'):
                continue
            if re.search(r'\bconfigfile\b', line):
                raise Failure('DESKTOP_BOOT_POLICY_CUSTOM')
            if re.search(r'\bsource\b', line) and not re.fullmatch(
                    r'[ \t]*source[ \t]+(?:\$prefix/|\$\{config_directory\}/)custom\.cfg[ \t]*', line):
                raise Failure('DESKTOP_BOOT_POLICY_CUSTOM')
        defaults = []
        for line in prefix.splitlines():
            if line.lstrip().startswith('#'):
                continue
            if re.search(r'\bset[ \t]+default\b', line):
                if not re.fullmatch(r'[ \t]*set[ \t]+default=(?:[\x22\x27]?0[\x22\x27]?|\x22\$\{next_entry\}\x22)[ \t]*', line):
                    raise Failure('DESKTOP_BOOT_POLICY_CUSTOM')
                defaults.append(line.strip())
        if not defaults or not re.fullmatch(r'set[ \t]+default=[\x22\x27]?0[\x22\x27]?', defaults[-1]):
            raise Failure('DESKTOP_BOOT_POLICY_CUSTOM')
        if any('${next_entry}' in item for item in defaults):
            save = (r'(?:[ \t]*save_env next_entry|[ \t]*if \[ "\$\{env_block\}" \] ; then\s*\n'
                r'[ \t]*save_env -f "\$\{env_block\}" next_entry\s*\n[ \t]*else\s*\n'
                r'[ \t]*save_env next_entry\s*\n[ \t]*fi)')
            branch = re.search(r'if \[ "\$\{next_entry\}" \] ; then\s*\n[ \t]*set default="\$\{next_entry\}"\s*\n[ \t]*set next_entry=\s*\n'
                + save + r'\s*\n[ \t]*set boot_once=true\s*\nelse\s*\n[ \t]*set default=[\x22\x27]?0[\x22\x27]?\s*\nfi', prefix)
            if not branch or sum('${next_entry}' in item for item in defaults) != 1:
                raise Failure('DESKTOP_BOOT_POLICY_CUSTOM')
        end = re.search(r'^\}', generated[first[1]:], re.M)
        if not end:
            raise Failure('DESKTOP_BOOT_VERIFY_FAILED')
        body = generated[first[1]:first[1] + end.start()]
        match = re.search(r'^\s*linux(?:efi)?\s+(\S+)', body, re.M)
        if not match:
            raise Failure('DESKTOP_BOOT_POLICY_CUSTOM')
        if match.group(1) not in ('/boot/vmlinuz-' + release, '/vmlinuz-' + release):
            raise Failure('DESKTOP_BOOT_VERIFY_FAILED')
    except BaseException as exc:
        # Restore only the files managed by this operation; existing kernels,
        # partitions, user GRUB settings and the VM disk are retained.
        if before_own is None:
            OWN_GRUB.unlink(missing_ok=True)
        else:
            atomic(OWN_GRUB, before_own)
        atomic(GRUB_CFG, before_cfg)
        if isinstance(exc, Failure) and exc.code == 'DESKTOP_BOOT_POLICY_CUSTOM':
            return False
        raise
    return True

def configure_session():
    action('CHECK', 'Checking the graphical session configuration', 'session')
    code, output = run(['id', '-un', os.environ.get('SUDO_USER', '')], 3) if os.environ.get('SUDO_USER') else (1, b'')
    user = output.decode(errors='replace').strip()
    if code or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', user) or user == 'root':
        raise Failure('DESKTOP_PREREQUISITE_MISSING')
    LIGHTDM_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    payload = ('[Seat:*]\nautologin-user=' + user + '\nautologin-user-timeout=0\nuser-session=xfce\n').encode()
    atomic(OWN_LIGHTDM, payload)
    action('CONFIGURE', 'Graphical session: /etc/lightdm/lightdm.conf.d/50-harnessy.conf', 'session')
    for arguments in (['systemctl', 'set-default', 'graphical.target'], ['systemctl', 'enable', 'lightdm'], ['systemctl', 'restart', 'lightdm']):
        if run(arguments, 20)[0]:
            raise Failure('DESKTOP_SESSION_NOT_READY')

def main():
    global RESULT
    if os.geteuid() != 0 or not RELEASE_SAFE or not shutil.which('timeout'):
        raise Failure('DESKTOP_PREREQUISITE_MISSING')
    if machine_arch() != EXPECTED_ARCH:
        raise Failure('DESKTOP_ARCH_MISMATCH')
    lock()
    action('CHECK', 'Inspecting the current guest graphics and desktop session', 'checking')
    RESULT = probe()
    if RESULT['state'] == 'ready':
        return
    needs_kernel = RESULT['kernel_repair_needed']
    if needs_kernel and not ALLOW_KERNEL:
        raise Failure('DESKTOP_KERNEL_UNSUPPORTED')
    if needs_kernel:
        action('CHECK', 'Verifying the available generic graphics kernel', 'kernel')
    selected = candidate() if needs_kernel and ALLOW_KERNEL else None
    missing_desktop = not (RESULT['xorg_installed'] and RESULT['xfce_installed'] and executable('lightdm'))
    missing_kernel = needs_kernel and ALLOW_KERNEL and selected is None
    if missing_kernel:
        apt((['xorg', 'xfce4', 'xfce4-terminal', 'lightdm', 'dbus-x11'] if missing_desktop else [])
            + ['linux-image-' + EXPECTED_ARCH])
    elif missing_desktop:
        install_desktop()
    if not (executable('Xorg') and executable('startxfce4') and executable('lightdm')):
        raise Failure('DESKTOP_APT_INSTALL_FAILED')
    if needs_kernel:
        action('VERIFY', 'Verifying the installed generic graphics kernel', 'kernel')
        selected = candidate()
        if selected is None:
            raise Failure('DESKTOP_KERNEL_VERIFY_FAILED')
        _, release, digest = selected
        RESULT.update(kernel_staged=True, candidate_kernel_version=version(release), candidate_kernel_sha256=digest)
        if not select_boot(release):
            RESULT.update(state='manual_boot_required', error_code='DESKTOP_BOOT_POLICY_CUSTOM', requires_reboot=False)
            return
        configure_session()
        RESULT.update(state='reboot_required', error_code='NONE', boot_configured=True, requires_reboot=True)
        action('REBOOT_REQUIRED', 'Verified generic kernel staged; the existing VM disk and fallback kernel are retained')
        return
    if RESULT['kernel_graphics'] == 'supported' and not RESULT['virtio_gpu_loaded']:
        action('CONFIGURE', 'Loading the available guest graphics driver', 'kernel')
        run(['modprobe', 'virtio_gpu'], 10)
    configure_session()
    action('VERIFY', 'Waiting for an active graphical scanout and Xfce session', 'verifying')
    end = min(DEADLINE - 5, time.monotonic() + 30)
    while time.monotonic() < end:
        RESULT = probe()
        if RESULT['state'] == 'ready':
            return
        time.sleep(.5)
    raise Failure('DESKTOP_SESSION_NOT_READY')

for item in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(item, interrupted)
try:
    main()
except Failure as exc:
    RESULT.update(state='failed', error_code=exc.code, failure_reason=exc.reason, requires_reboot=False)
except (OSError, ValueError, UnicodeError):
    RESULT.update(state='failed', error_code='DESKTOP_REPAIR_FAILED', requires_reboot=False)
finally:
    if LOCK_FD is not None:
        os.close(LOCK_FD)
action('RESULT', 'Desktop repair: ' + RESULT.get('state', 'failed') + ' (' + RESULT.get('error_code', 'DESKTOP_REPAIR_FAILED') + ')')
print('HARNESSY_DESKTOP_REPAIR=' + json.dumps(RESULT, separators=(',', ':')), flush=True)
'''


def _script(body: str, timeout: int, *, repair: bool) -> str:
    fallback = json.dumps({'schema_version': 1, 'state': 'failed' if repair else 'unavailable',
                           'error_code': 'DESKTOP_PREREQUISITE_MISSING'}, separators=(',', ':'))
    prefix = 'HARNESSY_DESKTOP_REPAIR=' if repair else ''
    return ("#!/bin/sh\nset -eu\n"
            "if ! command -v python3 >/dev/null 2>&1 || ! command -v timeout >/dev/null 2>&1; then\n"
            + "  printf '%s\\n' " + repr(prefix + fallback) + "\n  exit 0\nfi\n"
            + f"exec timeout --signal=TERM --kill-after=5s {timeout}s python3 - <<'HARNESSY_DESKTOP_PY'\n"
            + body + '\nHARNESSY_DESKTOP_PY\n')


def build_desktop_probe_script() -> str:
    return _script(_GUEST + "\ntry:\n    result = probe()\nexcept (OSError, ValueError, Failure):\n    result = dict(schema_version=1, state='unavailable', error_code='DESKTOP_PROBE_FAILED')\nprint(json.dumps(result, separators=(',', ':')))\n", DESKTOP_PROBE_TIMEOUT_SECONDS, repair=False)


def build_desktop_repair_script(architecture: str, public_network: bool,
                                allow_kernel_repair: bool = True) -> str:
    if architecture not in ('arm64', 'amd64'):
        raise ValueError('Unsupported desktop architecture')
    if type(public_network) is not bool or type(allow_kernel_repair) is not bool:
        raise TypeError('Desktop repair policy must be boolean')
    body = _REPAIR.replace('__ARCHITECTURE__', repr(architecture)).replace(
        '__PUBLIC_NETWORK__', repr(public_network)).replace('__ALLOW_KERNEL__', repr(allow_kernel_repair))
    return _script(_GUEST + body, DESKTOP_REPAIR_TIMEOUT_SECONDS, repair=True)
