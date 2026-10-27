"""Minimal, bounded Lima dependency setup and content-free status receipts."""
from __future__ import annotations

import json
import re

SSHFS_SETUP_TIMEOUT_SECONDS = 180
SSHFS_SETUP_STATUS_PATH = '/run/harnessy-sshfs-setup.json'
SSHFS_SETUP_STAGES = frozenset({'checking', 'installing', 'ready', 'failed'})
SSHFS_SETUP_ERRORS = frozenset({'NONE', 'SSHFS_SETUP_OFFLINE', 'SSHFS_SETUP_TIMEOUT',
    'SSHFS_SETUP_GUARD_FAILED', 'SSHFS_SETUP_APT_UPDATE_FAILED', 'SSHFS_SETUP_APT_INSTALL_FAILED',
    'SSHFS_SETUP_VERIFY_FAILED', 'SSHFS_SETUP_PREREQUISITE_MISSING', 'SSHFS_SETUP_STATUS_MISSING',
    'SSHFS_SETUP_STATUS_UNSAFE', 'SSHFS_SETUP_STALE_BOOT'})
SSHFS_SETUP_FAILURE_REASONS = frozenset({'dns_failed', 'network_timeout', 'repository_error',
    'package_unavailable', 'package_lock', 'storage_full', 'package_command_failed', 'unknown'})
_BOOT_ID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')

_SHELL_BOOT = r'''
_hy_boot=''
IFS= read -r _hy_boot < /proc/sys/kernel/random/boot_id || _hy_boot=''
case "$_hy_boot" in *[!0-9a-f-]*|'') _hy_boot='' ;; esac
[ "${#_hy_boot}" -eq 36 ] || _hy_boot=''
_hy_missing_json() {
  printf '{"schema_version":1,"boot_id":"%s","current_boot_id":"%s","stage":"failed","error_code":"SSHFS_SETUP_PREREQUISITE_MISSING","failure_reason":"unknown"}\n' "$_hy_boot" "$_hy_boot"
}
'''

_INSTALLER = r'''
import collections
import fcntl
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time

PUBLIC_NETWORK = __PUBLIC_NETWORK__
GUARD_TEXT = __GUARD_TEXT__
STATUS = Path('/run/harnessy-sshfs-setup.json')
SETUP_LOCK = Path('/run/harnessy-sshfs-setup.lock')
GUARD = Path('/usr/local/sbin/harnessy-network-guard')
GUARD_UNIT = Path('/etc/systemd/system/harnessy-network-guard.service')
BOOT_PATH = Path('/proc/sys/kernel/random/boot_id')
FUSE_DEVICE = Path('/dev/fuse')
FUSE_CONFIGS = (Path('/etc/fuse3.conf'), Path('/etc/fuse.conf'))
DEADLINE = time.monotonic() + 170.0
TEMPORARIES = set()
BOOT_ID = ''
LOCK_DESCRIPTOR = None

class SetupFailure(Exception):
    def __init__(self, code, reason='unknown'):
        self.code, self.reason = code, reason

def action(name, message):
    print('[%d] %s %s' % (int(time.time()), name, message), flush=True)

def root_file(path, *, missing=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return missing
    return stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1

def atomic_write(path, payload, mode):
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise SetupFailure('SSHFS_SETUP_PREREQUISITE_MISSING')
    if not root_file(path, missing=True):
        raise SetupFailure('SSHFS_SETUP_PREREQUISITE_MISSING')
    descriptor, name = tempfile.mkstemp(prefix='.harnessy-sshfs-', dir=str(path.parent))
    TEMPORARIES.add(name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        TEMPORARIES.discard(name)

def read_root_file(path, limit):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_size > limit:
            raise SetupFailure('SSHFS_SETUP_VERIFY_FAILED')
        data = os.read(descriptor, limit + 1)
        if len(data) > limit:
            raise SetupFailure('SSHFS_SETUP_VERIFY_FAILED')
        return data
    finally:
        os.close(descriptor)

def status(stage, code='NONE', reason='unknown'):
    receipt = dict(schema_version=1, boot_id=BOOT_ID, stage=stage, error_code=code,
                   failure_reason=reason, public_network=PUBLIC_NETWORK,
                   updated_at_epoch=int(time.time()))
    atomic_write(STATUS, (json.dumps(receipt, separators=(',', ':')) + '\n').encode(), 0o600)
    action('WRITE', 'SSHFS setup status: /run/harnessy-sshfs-setup.json (%s, %s)' % (stage, code))

def acquire_setup_lock():
    global LOCK_DESCRIPTOR
    descriptor = os.open(SETUP_LOCK, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
                         | getattr(os, 'O_NONBLOCK', 0), 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise SetupFailure('SSHFS_SETUP_PREREQUISITE_MISSING', 'package_lock')
        announced = False
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                LOCK_DESCRIPTOR = descriptor
                action('LOCK', 'Minimal file-sharing setup: /run/harnessy-sshfs-setup.lock')
                return
            except BlockingIOError:
                if not announced:
                    action('WAIT', 'Existing file-sharing setup: /run/harnessy-sshfs-setup.lock')
                    announced = True
                if time.monotonic() >= DEADLINE:
                    raise SetupFailure('SSHFS_SETUP_TIMEOUT', 'package_lock')
                time.sleep(.1)
    except BaseException:
        os.close(descriptor)
        raise

def remaining(limit):
    value = min(float(limit), DEADLINE - time.monotonic())
    if value <= 0:
        raise SetupFailure('SSHFS_SETUP_TIMEOUT', 'network_timeout')
    return value

def terminate(process):
    # The session belongs to this Popen call. Its leader can exit while a
    # package hook still owns the pipe; cleanup must cover that child too.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    # Reap inherited group members even when the already-exited leader made
    # wait() return immediately. Do not wait for pipe EOF from those children.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

def run(arguments, seconds):
    limit = time.monotonic() + remaining(seconds)
    output = bytearray()
    process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    exited_at = None
    try:
        while True:
            if time.monotonic() >= limit:
                terminate(process)
                return 124, bytes(output)
            events = selector.select(min(.1, max(.001, limit - time.monotonic())))
            for key, _ in events:
                data = os.read(key.fileobj.fileno(), 8192)
                if not data:
                    selector.unregister(key.fileobj)
                else:
                    output.extend(data)
                    del output[:-65536]
            code = process.poll()
            if code is not None:
                if not selector.get_map():
                    return code, bytes(output)
                exited_at = exited_at or time.monotonic()
                if time.monotonic() - exited_at > .2:
                    return code, bytes(output)
    finally:
        terminate(process)
        selector.close()
        process.stdout.close()

def classify(code, output):
    text = output.decode('utf-8', errors='replace').lower()
    patterns = (
        ('storage_full', ('no space left', 'disk quota exceeded', 'read-only file system')),
        ('package_lock', ('could not get lock', 'unable to acquire', 'another process using', 'dpkg frontend lock')),
        ('dns_failed', ('temporary failure resolving', 'could not resolve', 'name or service not known', 'temporary failure in name resolution')),
        ('network_timeout', ('timed out', 'connection timeout', 'connection failed', 'network is unreachable')),
        ('package_unavailable', ('unable to locate package', 'has no installation candidate', 'package is not available')),
        ('repository_error', ('does not have a release file', 'not signed', 'release file', 'certificate verification failed', '404 not found', '403 forbidden', '401 unauthorized')),
    )
    for label, words in patterns:
        if any(word in text for word in words):
            return label
    return 'network_timeout' if code == 124 else ('package_command_failed' if code else 'unknown')

def binaries():
    checks = {}
    for package, names, arguments in (
        ('sshfs', ('sshfs',), ('-V',)),
        ('fuse3', ('fusermount3', 'fusermount'), ('-V',)),
        ('rsync', ('rsync',), ('--version',)),
        ('iptables', ('iptables',), ('--version',)),
    ):
        found = next((shutil.which(name) for name in names if shutil.which(name)), None)
        checks[package] = bool(found and run([found, *arguments], 5)[0] == 0)
    return checks

def refresh_guard():
    if not (GUARD.exists() or GUARD.is_symlink() or GUARD_UNIT.exists()):
        action('VERIFY', 'No earlier network guard is installed; initial integration setup continues')
        return
    action('REPLACE', 'Current saved network policy: /usr/local/sbin/harnessy-network-guard')
    if not root_file(GUARD, missing=True):
        raise SetupFailure('SSHFS_SETUP_GUARD_FAILED')
    atomic_write(GUARD, GUARD_TEXT.encode(), 0o755)
    action('RUN', 'Network guard: /usr/local/sbin/harnessy-network-guard')
    code, _ = run(['/bin/bash', str(GUARD)], 25)
    if code:
        raise SetupFailure('SSHFS_SETUP_GUARD_FAILED', 'network_timeout' if code == 124 else 'unknown')
    action('VERIFY', 'Current saved network policy applied')

def configure_fuse():
    action('VERIFY', 'FUSE device: /dev/fuse')
    if not FUSE_DEVICE.is_char_device():
        modprobe = shutil.which('modprobe')
        if modprobe:
            run([modprobe, 'fuse'], 5)
    if not FUSE_DEVICE.is_char_device():
        raise SetupFailure('SSHFS_SETUP_VERIFY_FAILED')
    config = next((path for path in FUSE_CONFIGS if path.exists() or path.is_symlink()), FUSE_CONFIGS[0])
    if not root_file(config, missing=True):
        raise SetupFailure('SSHFS_SETUP_VERIFY_FAILED')
    content = read_root_file(config, 65536) if config.exists() else b''
    if not re.search(rb'(?m)^\s*user_allow_other\s*(?:#.*)?$', content):
        action('REPLACE', 'FUSE allow_other configuration: ' + str(config))
        atomic_write(config, content.rstrip(b'\n') + b'\nuser_allow_other\n', 0o644)
    action('VERIFY', 'FUSE allow_other configuration is present')

def main():
    global BOOT_ID
    if os.geteuid() != 0:
        raise SetupFailure('SSHFS_SETUP_PREREQUISITE_MISSING')
    with BOOT_PATH.open('r') as stream:
        BOOT_ID = stream.read(128).strip()
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', BOOT_ID):
        raise SetupFailure('SSHFS_SETUP_PREREQUISITE_MISSING')
    acquire_setup_lock()
    status('checking')
    action('VERIFY', 'SSHFS, FUSE helper, rsync and iptables executables')
    checks = binaries()
    missing = [name for name, installed in checks.items() if not installed]
    if missing:
        if not PUBLIC_NETWORK:
            raise SetupFailure('SSHFS_SETUP_OFFLINE')
        if not shutil.which('apt-get'):
            raise SetupFailure('SSHFS_SETUP_PREREQUISITE_MISSING')
        refresh_guard()
        status('installing')
        options = ['-o', 'Acquire::Retries=1', '-o', 'Acquire::http::Timeout=15',
                   '-o', 'Acquire::https::Timeout=15', '-o', 'DPkg::Lock::Timeout=30']
        os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
        os.environ['NEEDRESTART_MODE'] = 'a'
        os.environ['LC_ALL'] = 'C'
        os.environ['LANG'] = 'C'
        action('UPDATE', 'Guest package index for minimal file-sharing dependencies')
        code, output = run(['apt-get', *options, 'update'], 40)
        if code:
            raise SetupFailure('SSHFS_SETUP_APT_UPDATE_FAILED', classify(code, output))
        action('INSTALL', 'Minimal file-sharing packages: ' + ', '.join(missing))
        code, output = run(['apt-get', *options, 'install', '-y', '--no-upgrade',
            '--no-install-recommends', *missing], 90)
        checks = binaries()
        if not all(checks.values()):
            raise SetupFailure('SSHFS_SETUP_APT_INSTALL_FAILED' if code else 'SSHFS_SETUP_VERIFY_FAILED', classify(code, output))
        action('VERIFY', 'Required executables are installed and respond')
    configure_fuse()
    status('ready')
    action('READY', 'Minimal file-sharing dependencies verified')

def interrupted(_number, _frame):
    # Once cancellation is accepted, later SSH/timeout signals must not raise
    # through the bounded child-group cleanup in run()'s finally block.
    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, signal.SIG_IGN)
    raise SetupFailure('SSHFS_SETUP_TIMEOUT', 'network_timeout')

signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)
signal.signal(signal.SIGHUP, interrupted)
try:
    main()
except SetupFailure as exc:
    try:
        if LOCK_DESCRIPTOR is not None:
            status('failed', exc.code, exc.reason)
    except Exception:
        pass
    action('FAILED', exc.code + ' (' + exc.reason + ')')
    raise SystemExit(72)
except Exception:
    try:
        if LOCK_DESCRIPTOR is not None:
            status('failed', 'SSHFS_SETUP_VERIFY_FAILED', 'unknown')
    except Exception:
        pass
    action('FAILED', 'SSHFS_SETUP_VERIFY_FAILED (unknown)')
    raise SystemExit(72)
finally:
    for name in list(TEMPORARIES):
        try:
            os.unlink(name)
        except OSError:
            pass
    if LOCK_DESCRIPTOR is not None:
        os.close(LOCK_DESCRIPTOR)
'''

_PROBE = r'''
import json, os, re, stat, sys, time
from pathlib import Path
STAGES = __STAGES__
ERRORS = __ERRORS__
REASONS = __REASONS__
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
path = Path('/run/harnessy-sshfs-setup.json')
boot_path = Path('/proc/sys/kernel/random/boot_id')
print('[%d] READ SSHFS setup status: /run/harnessy-sshfs-setup.json' % int(time.time()), file=sys.stderr)
result = dict(schema_version=1, stage='failed', error_code='SSHFS_SETUP_STATUS_MISSING', failure_reason='unknown', boot_id='')
try:
    with boot_path.open() as stream:
        current = stream.read(128).strip()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 4096:
            raise ValueError()
        saved = json.loads(os.read(descriptor, 4097))
        if not isinstance(saved, dict):
            raise ValueError()
        stage, code = saved.get('stage'), saved.get('error_code')
        if type(saved.get('schema_version')) is not int or saved['schema_version'] != 1 or not isinstance(stage, str) or stage not in STAGES or not isinstance(code, str) or code not in ERRORS:
            raise ValueError()
        result = dict(schema_version=1, stage=stage, error_code=code, failure_reason='unknown', boot_id='')
        if isinstance(saved.get('boot_id'), str) and UUID.fullmatch(saved['boot_id']):
            result['boot_id'] = saved['boot_id']
        if isinstance(saved.get('failure_reason'), str) and saved['failure_reason'] in REASONS:
            result['failure_reason'] = saved['failure_reason']
        if type(saved.get('public_network')) is bool:
            result['public_network'] = saved['public_network']
    finally:
        os.close(descriptor)
except FileNotFoundError:
    current = current if 'current' in locals() else ''
except Exception:
    current = current if 'current' in locals() else ''
    result['error_code'] = 'SSHFS_SETUP_STATUS_UNSAFE'
result['current_boot_id'] = current if isinstance(current, str) and UUID.fullmatch(current) else ''
print(json.dumps(result, separators=(',', ':')))
'''


def build_sshfs_setup_script(public_network: bool, guard_script: str) -> str:
    if type(public_network) is not bool or not isinstance(guard_script, str) or not guard_script.strip():
        raise ValueError('SSHFS setup requires the current network policy and guard')
    program = _INSTALLER.replace('__PUBLIC_NETWORK__', repr(public_network)).replace('__GUARD_TEXT__', repr(guard_script))
    fallback = _SHELL_BOOT + r'''
if ! command -v python3 >/dev/null 2>&1 || ! command -v timeout >/dev/null 2>&1; then
  _hy_tmp=/run/.harnessy-sshfs-status-$$
  if [ ! -e /run/harnessy-sshfs-setup.lock ] && [ ! -L /run/harnessy-sshfs-setup.lock ] && (umask 077; set -C; _hy_missing_json >"$_hy_tmp") 2>/dev/null; then
    if [ ! -L /run/harnessy-sshfs-setup.json ]; then
      mv -f "$_hy_tmp" /run/harnessy-sshfs-setup.json 2>/dev/null || true
    fi
    rm -f "$_hy_tmp" 2>/dev/null || true
  fi
  _hy_now=$(date +%s 2>/dev/null || printf 0)
  case "$_hy_now" in *[!0-9]*|'') _hy_now=0 ;; esac
  printf '[%s] FAILED SSHFS_SETUP_PREREQUISITE_MISSING (unknown)\n' "$_hy_now"
  exit 72
fi
'''
    return ('#!/bin/sh\nset -eu\n' + fallback + '\nexec timeout --signal=TERM --kill-after=5s '
            f'{SSHFS_SETUP_TIMEOUT_SECONDS}s python3 - <<\'HARNESSY_SSHFS_SETUP_PY\'\n'
            + program + '\nHARNESSY_SSHFS_SETUP_PY\n')


def build_sshfs_status_script() -> str:
    program = (_PROBE.replace('__STAGES__', repr(sorted(SSHFS_SETUP_STAGES)))
               .replace('__ERRORS__', repr(sorted(SSHFS_SETUP_ERRORS)))
               .replace('__REASONS__', repr(sorted(SSHFS_SETUP_FAILURE_REASONS))))
    fallback = _SHELL_BOOT + r'''
if ! command -v python3 >/dev/null 2>&1; then
  _hy_now=$(date +%s 2>/dev/null || printf 0)
  case "$_hy_now" in *[!0-9]*|'') _hy_now=0 ;; esac
  printf '[%s] VERIFY SSHFS setup prerequisite: python3 is unavailable\n' "$_hy_now" >&2
  _hy_missing_json
  exit 0
fi
'''
    return fallback + "\npython3 - <<'HARNESSY_SSHFS_STATUS_PY'\n" + program + '\nHARNESSY_SSHFS_STATUS_PY\n'


def parse_sshfs_status(stdout: str, *, expected_boot_id: str = '') -> dict:
    """Project only fixed facts and require a current-boot receipt for Ready."""
    missing = dict(schema_version=1, state='unavailable', stage='failed', error_code='SSHFS_SETUP_STATUS_UNSAFE',
                   failure_reason='unknown', boot_id='', current_boot_id='', boot_matches=False)
    if not isinstance(stdout, str) or len(stdout) > 8192:
        return missing
    try:
        raw = json.loads(stdout)
    except (ValueError, RecursionError):
        return missing
    if not isinstance(raw, dict) or type(raw.get('schema_version')) is not int or raw['schema_version'] != 1:
        return missing
    stage, code, reason = raw.get('stage'), raw.get('error_code'), raw.get('failure_reason')
    if (not isinstance(stage, str) or stage not in SSHFS_SETUP_STAGES
            or not isinstance(code, str) or code not in SSHFS_SETUP_ERRORS):
        return missing
    result = {**missing, 'stage': stage, 'error_code': code,
              'failure_reason': reason if isinstance(reason, str) and reason in SSHFS_SETUP_FAILURE_REASONS else 'unknown'}
    boot = raw.get('boot_id')
    current = raw.get('current_boot_id')
    if isinstance(boot, str) and _BOOT_ID.fullmatch(boot):
        result['boot_id'] = boot
    if isinstance(current, str) and _BOOT_ID.fullmatch(current):
        result['current_boot_id'] = current
    if type(raw.get('public_network')) is bool:
        result['public_network'] = raw['public_network']
    result['boot_matches'] = bool(result['boot_id'] and result['boot_id'] == result['current_boot_id']
        and (not expected_boot_id or expected_boot_id == result['current_boot_id']))
    if code in {'SSHFS_SETUP_STATUS_MISSING', 'SSHFS_SETUP_STATUS_UNSAFE'}:
        return result
    if not result['boot_matches']:
        result.update(state='stale', error_code='SSHFS_SETUP_STALE_BOOT')
    elif stage == 'ready' and code == 'NONE':
        result['state'] = 'ready'
    elif stage == 'failed':
        result['state'] = 'failed'
    elif code == 'NONE':
        result['state'] = 'pending'
    return result
