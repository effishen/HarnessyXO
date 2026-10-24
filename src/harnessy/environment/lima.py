from __future__ import annotations

import asyncio
import base64
import codecs
from concurrent.futures import Future
from contextvars import copy_context
import errno
import functools
import hashlib
import inspect
import json
import os
import platform
import re
import shlex
import shutil
import tempfile
import threading
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from harnessy.diagnostics import log_event
from harnessy.core.outputs import CHAT_OUTPUT_DIR_RE

from .base import EnvironmentConfig, EnvironmentStatus, ExecResult, WorkspaceEnvironment, _validate_registry_path, FileViewUnavailableError
from .presets import (
    get_preset, execution_mode,
    GHIDRA_VERSION, GHIDRA_RELEASE_TAG, GHIDRA_RELEASE_FILE,
    GHIDRA_RELEASE_SHA256, GHIDRA_RELEASE_DIR,
    MINIMUM_PACKAGES, RPM_MINIMUM,
)
from .packages import package_commands, missing_packages_script
from .host_prerequisites import (discover_binary, repaired_path, ensure_host_prerequisites,
                                 validate_native_kvm_access, HostKVMAccessError)
from .activity import reserve_policy_change, reserve_environment_change, activity, acquire_activity
from .base import load_environment_config, save_environment_config


class LimaUnavailableError(RuntimeError):
    pass


class _LimaDesktopView:
    """Read-only GUI adapter; lifecycle stays in the named VM registry."""

    def __init__(self, provider, workspace):
        from types import SimpleNamespace
        self.provider = provider
        self.workspace = workspace
        self.environment_id = provider.config.id
        self.target = SimpleNamespace(id=provider.config.id, name=provider.config.name)
        self.guest = SimpleNamespace(label=get_preset(provider.config.preset).guest_os,
                                     family='linux', shell='Bash', interface='desktop')
        self.config = {'desktop': provider.config.desktop}
        self.windows = False
        self.backend = 'lima'
        self.root = provider.vm_root
        self.key = str(provider.environment_root)

    @property
    def busy(self):
        from .operations import ENVIRONMENT_OPERATIONS
        return ENVIRONMENT_OPERATIONS.state(self.provider.workspace_root, environment_id=self.environment_id).busy

    async def status(self):
        return (await self.provider.status()).to_dict()

    def acquire(self):
        return acquire_activity(self.provider.workspace_root, 'VM graphical view',
                                environment_id=self.environment_id, project_id='__guest_console__')

    def desktop_info(self):
        if not self.provider.config.desktop:
            raise ValueError('This VM was created without a graphical desktop.')
        root = self.provider.vm_root / self.provider.INSTANCE
        display_path = root / 'vncdisplay'
        _validate_registry_path(display_path, self.provider.workspace_root)
        if not display_path.is_file():
            raise RuntimeError('The graphical display is not available yet. Start the VM first.')
        display = display_path.read_text().strip()
        match = re.fullmatch(r'(?:127\.0\.0\.1|localhost):(\d+)', display)
        if not match:
            raise RuntimeError('The VM returned an unsupported graphical display address.')
        password_path = root / 'vncpassword'
        _validate_registry_path(password_path, self.provider.workspace_root)
        port = 5900 + int(match.group(1))
        return {'url': f'vnc://127.0.0.1:{port}', 'port': str(port),
                'password': password_path.read_text().strip() if password_path.is_file() else '', 'username': 'harnessy'}


# Process-wide controller metadata cache. `limactl --version` is invariant for
# the lifetime of a HarnessyXO process and must never be part of the status poll
# hot path.
_LIMA_VERSION_CACHE: dict[str, str] = {}
_LIMA_VERSION_LOCKS: dict[str, asyncio.Lock] = {}
_LIMA_VERSION_LOCK_LOOPS: dict[str, asyncio.AbstractEventLoop] = {}

# Readiness and boot serialization are process-owned per named VM, not per
# transient EnvironmentManager/provider instance. Restored tabs, terminals and
# model tools therefore converge on one boot handshake and reuse the verified
# boot marker after it succeeds.
_RUNTIME_READY_BOOT: dict[str, str] = {}
_START_LOCKS: dict[str, asyncio.Lock] = {}
_START_LOCK_LOOPS: dict[str, asyncio.AbstractEventLoop] = {}
_COPY_LOCKS: dict[str, threading.RLock] = {}

# A disconnected filesystem must not exhaust executor workers or block process
# shutdown. At most one daemon worker performs diagnostic I/O; later requests
# report unavailable until that actual call has returned.
_DIAGNOSTIC_IO_LOCK = threading.Lock()
_DIAGNOSTIC_IO_FUTURE: Future | None = None


async def _bounded_diagnostic_io(function, *args, timeout: float, **kwargs):
    global _DIAGNOSTIC_IO_FUTURE
    with _DIAGNOSTIC_IO_LOCK:
        if _DIAGNOSTIC_IO_FUTURE is not None and not _DIAGNOSTIC_IO_FUTURE.done():
            raise BlockingIOError(errno.EAGAIN, 'VM diagnostics collection is already in progress')
        future = Future()
        context = copy_context()

        def collect() -> None:
            if not future.set_running_or_notify_cancel():
                return
            try:
                result = context.run(function, *args, **kwargs)
            except BaseException as exc:
                future.set_exception(exc)
            else:
                future.set_result(result)

        _DIAGNOSTIC_IO_FUTURE = future
        try:
            threading.Thread(target=collect, name='harnessy-vm-diagnostics', daemon=True).start()
        except BaseException:
            future.cancel()
            raise
    return await asyncio.wait_for(asyncio.wrap_future(future), timeout=timeout)

FILES_BACKING_GUEST_PATH = '/mnt/harnessyxo-files'
PRIVATE_WORKTREES_GUEST_PATH = '/mnt/harnessyxo-worktrees'
# This separate host read-only parent export supplies live References only;
# scoped namespaces detach the parent. It also keeps copy-mode Projects separate.
REFERENCES_BACKING_GUEST_PATH = '/mnt/harnessyxo-reference-source'
WORKSPACE_VIEW_GUEST_PATH = '/workspace'
PERSISTENT_VIEW_STATE_GUEST_PATH = '/run/harnessy/project-views'
WORKSPACE_VIEW_REVISION = '0.6.125-named-vm-project-views'

_WORKSPACE_VIEW_FAILURES = {
    'INVALID_BACKING_PATH', 'ACTIVE_ROOT_UNAVAILABLE', 'BACKING_MOUNTS_UNAVAILABLE',
    'INVALID_OUTPUT_DIRECTORY', 'OUTPUT_DIRECTORY_UNAVAILABLE',
    'RAW_MOUNT_DETACH_FAILED', 'INVALID_WORKSPACE_CWD', 'MOUNT_PROJECTION_FAILED',
    'PERSISTENT_VIEW_START_FAILED', 'PERSISTENT_VIEW_UNAVAILABLE',
}

_WORKSPACE_PROBE_FAILURES = {
    'OWN_PROJECT_MISSING', 'REFERENCES_MISSING', 'FILES_BACKING_EXPOSED',
    'WORKTREES_BACKING_EXPOSED', 'ANCESTOR_MISSING', 'ACCESS_PROJECT_MISSING',
}


def workspace_projection_failure(returncode: int, stderr: str) -> str | None:
    """Identify controller projection failures, not arbitrary command exits.

    Codes contain no user paths or command text, so diagnostics can retain the
    cause even when the surrounding stderr/argv is privacy-redacted.
    """
    if returncode != 72:
        return None
    match = re.search(r'\[HARNESSY_WORKSPACE_VIEW:([A-Z_]+)\]', str(stderr or ''))
    if match and match.group(1) in _WORKSPACE_VIEW_FAILURES:
        return match.group(1)
    legacy = {
        'HarnessyXO active working root is unavailable': 'ACTIVE_ROOT_UNAVAILABLE',
        'HarnessyXO rejected an invalid workspace backing path': 'INVALID_BACKING_PATH',
        'HarnessyXO could not detach private workspace backing mounts': 'RAW_MOUNT_DETACH_FAILED',
        'HarnessyXO rejected an invalid workspace working directory': 'INVALID_WORKSPACE_CWD',
        'HarnessyXO output directory is unavailable': 'OUTPUT_DIRECTORY_UNAVAILABLE',
        'HarnessyXO rejected an invalid Project/Chat output directory': 'INVALID_OUTPUT_DIRECTORY',
    }
    return next((code for message, code in legacy.items() if message in str(stderr or '')), None)


def workspace_projection_probe_failure(stderr: str) -> str | None:
    """Return the privacy-safe failed isolation invariant, when present."""
    match = re.search(r'\[HARNESSY_WORKSPACE_PROBE:([A-Z_]+)\]', str(stderr or ''))
    if match and match.group(1) in _WORKSPACE_PROBE_FAILURES:
        return match.group(1)
    return None


def _lifecycle_diagnostics(action: str):
    """Give direct/model lifecycle requests the same scope as UI operations."""
    def decorate(method):
        @functools.wraps(method)
        async def observed(self, *args, **kwargs):
            from .manager import environment_operation_context
            from harnessy.diagnostics.technical import technical_error_evidence

            with environment_operation_context(action=action):
                fields = self._controller_diagnostic_fields()
                started = time.monotonic()
                log_event('runtime', 'vm_lifecycle_requested', workspace=str(self.workspace_root),
                          provider='lima', lifecycle_action=action, **fields)
                try:
                    result = await method(self, *args, **kwargs)
                except asyncio.CancelledError:
                    log_event('runtime', 'vm_lifecycle_finished', workspace=str(self.workspace_root),
                              provider='lima', lifecycle_action=action, outcome='cancelled',
                              elapsed_seconds=max(0.0, time.monotonic() - started), **fields)
                    raise
                except Exception as exc:
                    log_event('runtime', 'vm_lifecycle_finished', workspace=str(self.workspace_root),
                              provider='lima', lifecycle_action=action, outcome='failed',
                              elapsed_seconds=max(0.0, time.monotonic() - started),
                              technical_error=technical_error_evidence(exc), **fields)
                    raise
                log_event('runtime', 'vm_lifecycle_finished', workspace=str(self.workspace_root),
                          provider='lima', lifecycle_action=action, outcome='completed',
                          elapsed_seconds=max(0.0, time.monotonic() - started), **fields)
                if action in {'create', 'start', 'stop', 'reset', 'rebuild', 'restore', 'destroy'}:
                    from .file_views import FILE_VIEWS
                    FILE_VIEWS.request(self.workspace_root, reason='vm_' + action, environment_id=self.config.id)
                return result
        return observed
    return decorate


class LimaVMEnvironment(WorkspaceEnvironment):
    """Persistent workspace VM using Lima as a fixed host-side controller.

    Arbitrary model commands are never passed to a host shell. HarnessyXO invokes
    only the fixed ``limactl`` controller on the host; the command string becomes
    an argument to ``/bin/bash -lc`` *inside* the guest.
    """

    INSTANCE = 'harnessy'

    # Every host-controller invocation is bounded. The generous image/provision
    # limits exist for first boot on slower networks; they are still finite so a
    # lifecycle job can never own an eternal spinner.
    TIMEOUT_CREATE = 900.0
    TIMEOUT_START = 1200.0
    # Lima's native watch defaults to 600s independently of our subprocess
    # deadline. Pass our startup budget to Lima, then allow it to report its
    # own failure before the application's outer watchdog stops the controller.
    TIMEOUT_START_CONTROLLER_GRACE = 30.0
    TIMEOUT_STARTUP_STATUS = 3.0
    TIMEOUT_STOP = 180.0
    TIMEOUT_DELETE = 180.0
    TIMEOUT_SNAPSHOT = 900.0
    TIMEOUT_RESET = 900.0
    TIMEOUT_EDIT = 120.0
    TIMEOUT_PROVISION = 2400.0
    TIMEOUT_PROVISION_CHECK = 12.0
    TIMEOUT_SHELL_SHORT = 8.0
    TIMEOUT_CONTROLLER_STOP_GRACE = 1.5
    TIMEOUT_DIAGNOSTIC_RESOURCES = 2.0
    TIMEOUT_DIAGNOSTIC_PRESERVE = 3.0
    CONTROLLER_HEARTBEAT_SECONDS = 15.0


    def __init__(self, workspace_root: Path, config: EnvironmentConfig) -> None:
        super().__init__(workspace_root, config)
        self.canonical_files_root = self.files_root
        self.canonical_worktrees_root = self.private_worktrees_root
        _validate_registry_path(self.canonical_files_root, self.workspace_root)
        if self.config.files_mode == 'copy':
            self.files_root = self.environment_root / 'project-copy' / 'Files'
            self.private_worktrees_root = self.environment_root / 'project-copy' / 'worktrees'
        _validate_registry_path(self.environment_root, self.workspace_root)
        self.vm_root = self.environment_root / 'vm' / 'lima'
        self.templates_root = self.environment_root / 'templates'
        self.state_root = self.environment_root / 'state'
        self.snapshots_root = self.environment_root / 'snapshots'
        self.snapshot_index_path = self.snapshots_root / 'index.json'
        self.template_path = self.templates_root / 'lima.yaml'
        self.runtime_binding_path = self.state_root / 'runtime-binding.json'
        self.readiness_path = self.state_root / 'readiness.json'
        self.lifecycle_path = self.state_root / 'lifecycle.json'
        for owned_path in (self.vm_root, self.templates_root, self.state_root, self.snapshots_root,
                           self.files_root, self.private_worktrees_root):
            _validate_registry_path(owned_path, self.workspace_root)
        self.vm_root.mkdir(parents=True, exist_ok=True)
        self.templates_root.mkdir(parents=True, exist_ok=True)
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.snapshots_root.mkdir(parents=True, exist_ok=True)
        self.files_root.mkdir(parents=True, exist_ok=True)
        self.private_worktrees_root.mkdir(parents=True, exist_ok=True)
        self._runtime_guard_verified = False
        self._runtime_boot_id = ''
        self._controller_output_callback = None
        self._diagnostic_workspace_id: str | None = None
        # Register only the runtime already owned by this provider. The support
        # collector never searches unrelated home directories for Lima logs.
        try:
            from harnessy.diagnostics.vm_logs import register_workspace_runtime
            register_workspace_runtime(self.workspace_root, environment_id=self.config.id, runtime_root=self.environment_root)
        except Exception:
            pass

        try:
            from harnessy.diagnostics.guest_logs import register_guest_probe
            register_guest_probe(self.workspace_root, environment_id=self.config.id,
                runtime_root=self.environment_root, kind='linux', probe=self._guest_diagnostic_probe)
        except Exception:
            pass

    async def _guest_diagnostic_probe(self, script: str, timeout: float) -> tuple[int, bytes, bytes]:
        from harnessy.diagnostics.guest_logs import GuestProbeUnavailable
        _validate_registry_path(self.environment_root, self.workspace_root)
        if self._read_readiness().get('phase') in {'stopped', 'destroyed', 'deleted', 'creating'}:
            raise GuestProbeUnavailable(state='stopped', code='guest_stopped')
        # limactl shell only inspects an already-running guest. In particular,
        # do not call _ensure_running or prepare a project execution view.
        rc, out, err = await self._run('shell', '--workdir', '/', self.INSTANCE,
            'sudo', '-n', '--', '/bin/sh', '-c', script, timeout=timeout, check=False,
            diagnostic_probe=True)
        return rc, out.encode('utf-8', errors='replace'), err.encode('utf-8', errors='replace')

    def _guest_transport_failure(self, *, stderr: str = '', returncode: int | None = None,
                                 timed_out: bool = False) -> None:
        try:
            from harnessy.diagnostics.guest_logs import record_guest_transport
            record_guest_transport(self.workspace_root, environment_id=self.config.id,
                runtime_root=self.environment_root, kind='linux', operation='ssh_command',
                stderr=stderr.encode('utf-8', errors='replace'), returncode=returncode, timed_out=timed_out)
        except Exception:
            pass

    def _workspace_cache_key(self) -> str:
        return str(self.environment_root.expanduser().resolve())

    def _workspace_start_lock(self) -> asyncio.Lock:
        key = self._workspace_cache_key()
        loop = asyncio.get_running_loop()
        # Tests and embedding environments may construct multiple event loops in
        # one process. Never carry an asyncio lock across loops. HarnessyXO itself
        # normally has one loop, so every provider instance shares this lock.
        if _START_LOCK_LOOPS.get(key) is not loop:
            _START_LOCKS[key] = asyncio.Lock()
            _START_LOCK_LOOPS[key] = loop
        return _START_LOCKS[key]

    def _binary(self) -> str:
        binary = discover_binary('limactl')
        if not binary:
            host = platform.system()
            if host == 'Linux':
                raise LimaUnavailableError(
                    'Lima (limactl) is not installed yet. Start the VM to install verified Lima '
                    'and matching guest agents automatically. python3 run.py also prepares it.'
                )
            raise LimaUnavailableError(
                'Lima (limactl) is not installed. Install Lima on the host, then retry. '
                'On macOS with Homebrew: brew install lima.'
            )
        return binary

    def _runtime_home(self) -> Path:
        # macOS sockaddr_un is only 104 bytes. Its normal tempfile directory
        # can itself be long, so use the OS /tmp namespace and a private
        # account-owned directory; durable disks stay below the workspace.
        _validate_registry_path(self.vm_root, self.workspace_root)
        actual = self.vm_root.resolve()
        digest = hashlib.sha256(str(actual).encode()).hexdigest()[:16]
        base = Path('/tmp') / f'hy-lima-{os.getuid()}'
        if base.is_symlink():
            raise RuntimeError('The VM runtime alias directory cannot be a symbolic link.')
        base.mkdir(exist_ok=True, mode=0o700)
        if not base.is_dir() or base.stat().st_uid != os.getuid():
            raise RuntimeError('The VM runtime alias directory is not owned by this account.')
        base.chmod(0o700)
        alias = base / digest
        if alias.is_symlink():
            if alias.resolve() != actual:
                raise RuntimeError('The VM runtime alias points to a different environment. No VM command was run.')
        elif alias.exists():
            raise RuntimeError('The VM runtime alias is occupied by a non-link path. No VM command was run.')
        else:
            try:
                alias.symlink_to(actual, target_is_directory=True)
            except FileExistsError:
                if not alias.is_symlink() or alias.resolve() != actual:
                    raise RuntimeError('The VM runtime alias changed while it was being created.')
        return alias

    def _host_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env['PATH'] = repaired_path()
        env['LIMA_HOME'] = str(self._runtime_home())
        # HarnessyXO never uses `limactl shell --preserve-env`. Block everything
        # anyway so a future controller refactor cannot accidentally propagate
        # host credentials merely by adding that flag.
        env['LIMA_SHELLENV_BLOCK'] = '*'
        env.pop('LIMA_SHELLENV_ALLOW', None)
        return env

    def _desired_runtime_binding(self) -> dict[str, Any]:
        _validate_registry_path(self.canonical_files_root, self.workspace_root)
        binding = {
            'version': 4,
            'environment_id': self.config.id,
            'files_mode': self.config.files_mode,
            'files_host_path': str(self.files_root.resolve()),
            'files_backing_guest_path': FILES_BACKING_GUEST_PATH,
            'private_worktrees_host_path': str(self.private_worktrees_root.resolve()),
            'private_worktrees_guest_path': PRIVATE_WORKTREES_GUEST_PATH,
            'workspace_view_guest_path': WORKSPACE_VIEW_GUEST_PATH,
            'mount_type': self._mount_type(),
            # v2 means Lima's heavy per-boot provision list has been removed.
            # Preset packages are provisioned explicitly once after VM creation/
            # reset, never as part of an ordinary Stop -> Start.
            'boot_provisioning': 'explicit-once',
        }
        parent = self.canonical_files_root.stat()
        binding.update(references_host_path=str(self.canonical_files_root.resolve()),
                       references_backing_guest_path=REFERENCES_BACKING_GUEST_PATH,
                       references_parent_device=parent.st_dev, references_parent_inode=parent.st_ino)
        return binding

    def _references_backing_guest_path(self) -> str:
        return REFERENCES_BACKING_GUEST_PATH

    def _references_binding_matches(self) -> bool:
        try:
            _validate_registry_path(self.runtime_binding_path, self.workspace_root)
            _validate_registry_path(self.canonical_files_root, self.workspace_root)
            raw = json.loads(self.runtime_binding_path.read_text('utf-8'))
            parent = self.canonical_files_root.stat()
        except (OSError, ValueError):
            return False
        return (isinstance(raw, dict) and raw.get('references_host_path') == str(self.canonical_files_root.resolve())
                and raw.get('references_backing_guest_path') == REFERENCES_BACKING_GUEST_PATH
                and raw.get('references_parent_device') == parent.st_dev
                and raw.get('references_parent_inode') == parent.st_ino)

    def _runtime_binding_matches(self) -> bool:
        try:
            raw = json.loads(self.runtime_binding_path.read_text('utf-8'))
        except (OSError, json.JSONDecodeError):
            return False
        # The console-only References export may be pending an explicit
        # Stop/Start on an otherwise usable older running VM. It cannot revoke
        # readiness of independent, already verified Project views.
        references_fields = {'references_host_path', 'references_backing_guest_path',
                             'references_parent_device', 'references_parent_inode'}
        return (isinstance(raw, dict)
                and {key: value for key, value in raw.items() if key not in references_fields}
                == {key: value for key, value in self._desired_runtime_binding().items()
                    if key not in references_fields})

    def _write_runtime_binding(self) -> None:
        _validate_registry_path(self.runtime_binding_path, self.workspace_root)
        self.state_root.mkdir(parents=True, exist_ok=True)
        tmp = self.runtime_binding_path.with_suffix('.tmp')
        _validate_registry_path(tmp, self.workspace_root)
        tmp.write_text(json.dumps(self._desired_runtime_binding(), indent=2, sort_keys=True) + '\n', encoding='utf-8')
        tmp.replace(self.runtime_binding_path)

    def _mounts_set_expression(self) -> str:
        # `limactl edit --set` uses yq syntax. JSON is valid YAML/yq input and
        # lets us preserve the fixed guest mount point while safely encoding
        # spaces/unicode in the host workspace path.
        _validate_registry_path(self.canonical_files_root, self.workspace_root)
        mounts = [
            {
                'location': str(self.files_root.resolve()),
                'mountPoint': FILES_BACKING_GUEST_PATH,
                'writable': self.config.files_mode != 'readonly',
            },
            {
                'location': str(self.private_worktrees_root.resolve()),
                'mountPoint': PRIVATE_WORKTREES_GUEST_PATH,
                'writable': self.config.files_mode != 'readonly',
            },
        ]
        mounts.append({'location': str(self.canonical_files_root.resolve()),
                       'mountPoint': REFERENCES_BACKING_GUEST_PATH, 'writable': False})
        return '.mounts=' + json.dumps(mounts, ensure_ascii=False, separators=(',', ':'))

    async def _reconcile_runtime_binding(self, *, force: bool = False) -> None:
        """Keep a moved/copied VM pointed at this workspace's own working roots.

        Lima persists absolute host mount locations in the instance config. A
        workspace copy therefore must not blindly reuse that stale location, or
        its guest could mount the source workspace's Files/ or private chat
        worktrees. The portable environment.json remains host-path-free; these
        host-specific bindings are repaired while the instance is stopped and
        tracked only under state/.
        """
        if not force and self._runtime_binding_matches() and self._references_binding_matches():
            return
        await self._run(
            'edit', self.INSTANCE,
            '--mount-type', self._mount_type(),
            '--set', self._mounts_set_expression(),
            # Older HarnessyXO instances embedded apt-get provisioning in Lima's
            # per-boot provision list. Remove it while the VM is stopped so an
            # upgraded existing workspace also gets fast normal boots.
            '--set', '.provision=[]',
            timeout=self.TIMEOUT_EDIT, check=True,
        )
        self._write_runtime_binding()
        self._write_template()
        log_event(
            'harnessy', 'vm_runtime_binding_reconciled', workspace=str(self.workspace_root),
            files_host_path=str(self.files_root.resolve()),
            files_backing_guest_path=FILES_BACKING_GUEST_PATH,
            private_worktrees_host_path=str(self.private_worktrees_root.resolve()),
            private_worktrees_guest_path=PRIVATE_WORKTREES_GUEST_PATH,
            workspace_view_guest_path=WORKSPACE_VIEW_GUEST_PATH,
            mount_type=self._mount_type(), boot_provisioning='explicit-once',
        )

    @staticmethod
    def _q(value: str) -> str:
        return json.dumps(str(value))

    def _network_guard_script(self) -> str:
        # Deterministic guest egress guard. It intentionally performs no DNS or
        # hostname lookups during startup and bounds all xtables lock waits.
        public_network = '1' if self.config.network else '0'
        return rf'''#!/usr/bin/env bash
set -euo pipefail
PUBLIC_NETWORK={public_network}
LOCK=/run/harnessy-network-guard.lock
READY=/run/harnessy-network-guard.ready
STAGE=/run/harnessy-network-guard.stage

exec 9>"$LOCK"
if ! flock -w 5 9; then
  echo "lock_timeout" >"$STAGE"
  echo "HarnessyXO network guard could not acquire its lock" >&2
  exit 70
fi

stage() {{ printf '%s\n' "$1" >"$STAGE"; }}
ipt() {{ iptables -w 3 "$@"; }}
ip6t() {{ ip6tables -w 3 "$@"; }}

rm -f "$READY"
stage reset
ipt -F OUTPUT
ip6t -F OUTPUT
ipt -P OUTPUT ACCEPT
ip6t -P OUTPUT ACCEPT

stage controller
ipt -A OUTPUT -o lo -j ACCEPT
ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt -A OUTPUT -p udp --sport 68 --dport 67 -j ACCEPT
ip6t -A OUTPUT -o lo -j ACCEPT
ip6t -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6t -A OUTPUT -p udp --sport 546 --dport 547 -j ACCEPT

if [ "$PUBLIC_NETWORK" = "1" ]; then
  stage dns
  # Permit DNS only to resolvers already configured by the VM runtime.  A
  # systemd-resolved guest normally exposes only the loopback stub
  # (127.0.0.53) through /etc/resolv.conf; the actual DHCP/Lima resolver lives
  # in /run/systemd/resolve/resolv.conf and/or `resolvectl dns`.  Collect both
  # views before private-range rejects so DNS to a private Lima gateway stays
  # possible without opening arbitrary private-LAN traffic.  All controller
  # inspection is local and bounded; no hostname lookup occurs here.
  RESOLVECTL_DNS="$(timeout 2 resolvectl dns 2>/dev/null || true)"
  DNS4="$({{
    awk '/^[[:space:]]*nameserver[[:space:]]+/ {{print $2}}' /etc/resolv.conf /run/systemd/resolve/resolv.conf 2>/dev/null || true
    printf '%s\n' "$RESOLVECTL_DNS" | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){{3}}$' || true
  }} | grep -E '^[0-9]+(\.[0-9]+){{3}}$' | sort -u | tr '\n' ' ' || true)"
  DNS6="$({{
    awk '/^[[:space:]]*nameserver[[:space:]]+/ {{print $2}}' /etc/resolv.conf /run/systemd/resolve/resolv.conf 2>/dev/null || true
    printf '%s\n' "$RESOLVECTL_DNS" | tr ' ' '\n' | sed 's/%[^[:space:]]*$//' | grep -E '^[0-9A-Fa-f:]+$' | grep ':' || true
  }} | grep ':' | sort -u | tr '\n' ' ' || true)"
  for ip in $DNS4; do
    ipt -A OUTPUT -d "$ip" -p udp --dport 53 -j ACCEPT
    ipt -A OUTPUT -d "$ip" -p tcp --dport 53 -j ACCEPT
  done
  for ip in $DNS6; do
    ip6t -A OUTPUT -d "$ip" -p udp --dport 53 -j ACCEPT
    ip6t -A OUTPUT -d "$ip" -p tcp --dport 53 -j ACCEPT
  done
fi

stage private_ipv4
for net in \
  0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
  172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 \
  198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
  ipt -A OUTPUT -d "$net" -j REJECT
done

stage private_ipv6
for net in \
  ::/128 ::1/128 ::ffff:0:0/96 100::/64 2001:db8::/32 fc00::/7 fe80::/10 ff00::/8; do
  ip6t -A OUTPUT -d "$net" -j REJECT
done

stage policy
if [ "$PUBLIC_NETWORK" = "1" ]; then
  ipt -P OUTPUT ACCEPT
  ip6t -P OUTPUT ACCEPT
else
  ipt -P OUTPUT DROP
  ip6t -P OUTPUT DROP
fi

stage verified
printf '%s\n' "$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo unknown)" >"$READY"
exit 0
'''

    @staticmethod
    def _network_guard_service() -> str:
        return '''[Unit]
Description=HarnessyXO workspace VM egress isolation guard
Wants=network-online.target
After=network-online.target systemd-resolved.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/harnessy-network-guard
TimeoutStartSec=20
TimeoutStopSec=3
KillMode=control-group
StandardOutput=journal
StandardError=journal
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
'''

    def _provision_revision(self) -> str:
        preset = get_preset(self.config.preset)
        selected_optional = self._selected_optional_tool_ids(preset)
        payload = {
            'schema': 2,
            'preset': preset.id,
            'required_packages': list(preset.packages),
            'selected_optional_tools': list(selected_optional),
            # Network-disabled workspaces intentionally skip repository-backed
            # tool provisioning. Including this in the revision means enabling
            # outbound later naturally schedules the selected tools once.
            'public_outbound': bool(self.config.network),
            'ghidra_version': GHIDRA_VERSION if 'ghidra' in selected_optional else '',
            'rea_cli_schema': 1 if 'rea' in selected_optional else 0,
            'workspace_profile': 2,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        ).hexdigest()[:20]

    def _provision_marker_payload(self) -> dict[str, Any]:
        preset = get_preset(self.config.preset)
        return {
            'schema': 2,
            'preset': preset.id,
            'revision': self._provision_revision(),
            'public_outbound': bool(self.config.network),
            'selected_optional_tools': list(self._selected_optional_tool_ids(preset)),
        }

    def _selected_optional_tool_ids(self, preset=None) -> tuple[str, ...]:
        preset = preset or get_preset(self.config.preset)
        available = tuple(preset.optional_tool_ids)
        configured = tuple(self.config.optional_tools or ())
        if '*' in configured:
            return available
        selected = set(configured)
        return tuple(tool_id for tool_id in available if tool_id in selected)

    def _selected_optional_packages(self, preset=None) -> tuple[str, ...]:
        preset = preset or get_preset(self.config.preset)
        selected = set(self._selected_optional_tool_ids(preset))
        return tuple(pkg for pkg in preset.optional_packages if pkg in selected)

    def _selected_supplemental_tools(self, preset=None) -> tuple[str, ...]:
        preset = preset or get_preset(self.config.preset)
        selected = set(self._selected_optional_tool_ids(preset))
        return tuple(tool for tool in preset.supplemental_tools if tool in selected)

    async def optional_tool_status(self) -> dict[str, dict[str, str]]:
        """Return current guest installation state for every selectable tool.

        This is an on-demand Environment-page inspection; it is deliberately not
        part of the frequent status poll. A stopped VM reports ``unknown`` rather
        than starting merely to answer the dialog.
        """
        preset = get_preset(self.config.preset)
        result: dict[str, dict[str, str]] = {
            tool_id: {'state': 'unknown', 'detail': 'VM is stopped; installation status was not probed.'}
            for tool_id in preset.optional_tool_ids
        }
        status = await self.status()
        if not status.running:
            return result

        missing_packages = set(await self._missing_packages(tuple(preset.optional_packages)))
        for package in preset.optional_packages:
            if package in missing_packages:
                result[package] = {'state': 'missing', 'detail': 'Not installed in the running guest.'}
            else:
                result[package] = {'state': 'installed', 'detail': 'Installed by the guest package manager.'}

        if 'ghidra' in preset.supplemental_tools:
            rc, stdout, _ = await self._run(
                'shell', self.INSTANCE, '/bin/bash', '-lc',
                f'test -x /opt/{GHIDRA_RELEASE_DIR}/support/analyzeHeadless && printf installed || printf missing',
                timeout=8, check=False,
            )
            installed = rc == 0 and stdout.strip() == 'installed'
            result['ghidra'] = {
                'state': 'installed' if installed else 'missing',
                'detail': f'Ghidra {GHIDRA_VERSION} headless is installed.' if installed else 'Ghidra headless is not installed.',
            }

        if 'python-re' in preset.supplemental_tools:
            probes = (
                '/opt/harnessy-re/angr/bin/python',
                '/opt/harnessy-re/capa/bin/capa',
                '/opt/harnessy-re/floss/bin/floss',
                '/opt/harnessy-re/binarylibs/bin/python',
                '/opt/harnessy-re/firmware/bin/ubireader_extract_files',
                '/opt/harnessy-re/frida/bin/frida',
            )
            quoted = ' '.join(shlex.quote(path) for path in probes)
            rc, stdout, _ = await self._run(
                'shell', self.INSTANCE, '/bin/bash', '-lc',
                'count=0; for p in ' + quoted + '; do [ -x "$p" ] && count=$((count+1)); done; printf "%s" "$count"',
                timeout=8, check=False,
            )
            try:
                count = int(stdout.strip()) if rc == 0 else 0
            except ValueError:
                count = 0
            state = 'installed' if count == len(probes) else ('partial' if count else 'missing')
            result['python-re'] = {
                'state': state,
                'detail': f'{count}/{len(probes)} HarnessyXO Python RE environments detected.',
            }
        if 'rea' in preset.supplemental_tools:
            from .rea_cli import status_script
            rc, stdout, _ = await self._run(
                'shell', self.INSTANCE, '/bin/bash', '-lc', status_script(), timeout=10, check=False,
            )
            try:
                details = json.loads(stdout) if rc == 0 else {}
            except (ValueError, TypeError):
                details = {}
            if isinstance(details, dict) and details.get('state') in {'installed', 'partial', 'missing'}:
                result['rea'] = {key: str(details[key]) for key in
                                 ('state', 'detail', 'version', 'node_version', 'update_state', 'reason_code', 'phase') if key in details}
            else:
                result['rea'] = {'state': 'unknown', 'detail': 'Could not inspect the REA CLI in this guest.', 'update_state': 'unknown'}
        return result

    def _remove_supplemental_tools_script(self, tool_ids: tuple[str, ...]) -> str:
        commands: list[str] = ['set -euo pipefail']
        selected = set(tool_ids)
        if 'ghidra' in selected:
            commands.extend([
                "rm -f /usr/local/bin/ghidra /usr/local/bin/ghidra-headless",
                f"rm -rf /opt/{GHIDRA_RELEASE_DIR}",
                f"rm -f /var/lib/harnessy/ghidra-{GHIDRA_VERSION}-linux-arm64-natives.ok",
            ])
        if 'python-re' in selected:
            commands.extend([
                "rm -rf /opt/harnessy-re",
                "rm -f /usr/local/bin/angr-python /usr/local/bin/capa /usr/local/bin/floss /usr/local/bin/re-python",
                "rm -f /usr/local/bin/ubireader-extract-files /usr/local/bin/ubireader-info /usr/local/bin/jefferson",
                "rm -f /usr/local/bin/frida /usr/local/bin/frida-ps /usr/local/bin/frida-trace",
            ])
        if 'rea' in selected:
            from .rea_cli import remove_script
            commands.append(remove_script())
        return '\n'.join(commands) + '\n'

    async def apply_optional_tools(
        self, selected: tuple[str, ...], *, expected: tuple[str, ...] | None = None,
        remove_deselected_bundles: bool = False, expected_removed_bundles: tuple[str, ...] | None = None,
        progress=None, reservation_held: bool = False,
    ) -> EnvironmentStatus:
        """Save and reconcile a workspace's post-creation optional-tool selection.

        Newly selected/missing tools are installed immediately only when the VM
        is already running and public outbound is enabled. A stopped/offline VM
        retains the desired selection for the next usable setup. Package-managed
        tools are never automatically removed on deselection; that could cascade
        through distro dependencies. HarnessyXO-owned supplemental bundles can be
        explicitly removed safely.
        """
        preset = get_preset(self.config.preset)
        allowed = tuple(preset.optional_tool_ids)
        desired = tuple(tool for tool in allowed if tool in set(selected))

        def confirmed_removals(inspection: dict[str, dict[str, str]]) -> tuple[str, ...]:
            candidates = tuple(
                tool for tool in preset.supplemental_tools
                if tool not in desired and inspection.get(tool, {}).get('state') in {'installed', 'partial'}
            ) if remove_deselected_bundles else ()
            if remove_deselected_bundles and expected_removed_bundles is not None:
                if any(inspection.get(tool, {}).get('state') not in {'installed', 'partial', 'missing'}
                       for tool in preset.supplemental_tools):
                    raise RuntimeError('Some managed tool bundles could not be inspected. Reopen Manage Optional Tools after their installed state is available. No bundles were removed.')
                if set(expected_removed_bundles) != set(candidates):
                    raise RuntimeError('Installed tool bundles changed since removal was confirmed. Reopen Manage Optional Tools to review the current removal list. No bundles were removed.')
            return candidates

        release = (lambda: None) if reservation_held else reserve_environment_change(self.workspace_root, 'optional tools', environment_id=self.config.id)
        try:
            async with self._workspace_start_lock():
                original = load_environment_config(self.workspace_root, self.config.id)
                if original is None:
                    raise RuntimeError('The workspace environment definition is missing.')
                if original.preset != preset.id:
                    raise RuntimeError('The VM tool preset changed since this editor opened. Reopen Manage Optional Tools before applying.')
                old_selected = tuple(
                    allowed if '*' in tuple(original.optional_tools or ())
                    else (tool for tool in allowed if tool in set(original.optional_tools or ()))
                )
                if expected is not None and tuple(expected) != old_selected:
                    raise RuntimeError('Optional tool selection changed since this editor opened. Reopen Manage Optional Tools before applying.')

                status = await self.status()
                if remove_deselected_bundles and expected_removed_bundles is not None:
                    if not status.running:
                        raise RuntimeError('Start this VM and reopen Manage Optional Tools before uninstalling managed bundles. No settings or bundles were changed.')
                    # Reject a stale/partial preview before saving selections
                    # or installing any required packages. Recheck immediately
                    # before removal as setup may change the installed state.
                    confirmed_removals(await self.optional_tool_status())
                changed = EnvironmentConfig.from_dict({**original.to_dict(), 'optional_tools': desired})
                self._save_controller_config(changed)
                await self._emit_progress(
                    progress, 'tools_saving', 'Saving optional tool selection…',
                    detail=f'{len(desired)}/{len(allowed)} optional tools selected.', stage_timeout_seconds=20.0,
                )

                if not status.running:
                    await self._emit_progress(
                        progress, 'tools_pending', 'Optional tool selection saved for next start.',
                        detail='The VM is stopped, so no guest packages were changed.', stage_timeout_seconds=10.0,
                    )
                    return await self.status()

                missing_required = await self._missing_required_packages()
                if changed.network and missing_required:
                    await self._emit_progress(progress, 'tools_installing', 'Installing required packages for the selected tool preset…',
                                              detail=', '.join(missing_required), stage_timeout_seconds=self.TIMEOUT_PROVISION)
                    await self._run('shell', self.INSTANCE, 'sudo', '/bin/bash', '-lc',
                                    self._provision_script(missing_required, optional_packages_override=(), supplemental_tools_override=()),
                                    timeout=self.TIMEOUT_PROVISION, check=True)
                    unresolved_required = await self._missing_required_packages()
                    if unresolved_required:
                        raise RuntimeError('Required tool-preset packages are still missing: ' + ', '.join(unresolved_required) + '. Existing installed tools were retained; Apply or Start again to retry.')
                inspection = await self.optional_tool_status()
                desired_set = set(desired)
                missing_packages = tuple(
                    tool for tool in preset.optional_packages
                    if tool in desired_set and inspection.get(tool, {}).get('state') != 'installed'
                )
                missing_supplemental = tuple(
                    tool for tool in preset.supplemental_tools
                    if tool in desired_set and (tool == 'rea' or inspection.get(tool, {}).get('state') != 'installed')
                )
                remove_bundles = confirmed_removals(inspection)

                if remove_bundles:
                    await self._emit_progress(
                        progress, 'tools_removing', 'Removing deselected HarnessyXO tool bundles…',
                        detail=', '.join(remove_bundles), stage_timeout_seconds=180.0,
                    )
                    await self._run(
                        'shell', self.INSTANCE, 'sudo', '/bin/bash', '-lc',
                        self._remove_supplemental_tools_script(remove_bundles), timeout=180, check=True,
                    )

                if not changed.network:
                    # This revision is complete *for the offline policy*: selected
                    # downloads were intentionally skipped. Enabling outbound changes
                    # the revision and naturally schedules the pending tools later.
                    await self._finalize_guest_provisioning()
                    await self._emit_progress(
                        progress, 'tools_pending', 'Optional tool downloads pending — public outbound is disabled.',
                        detail=(f'{len(missing_required)} required preset package(s) and {len(missing_packages) + len(missing_supplemental)} optional tool install/update action(s) are deferred. '
                                'Existing installed tools remain available. Enable public outbound and Apply again, or start after enabling it.'),
                        stage_timeout_seconds=10.0,
                    )
                    return await self.status()

                if missing_packages or missing_supplemental:
                    await self._emit_progress(
                        progress, 'tools_installing', 'Installing selected optional tools…',
                        detail=', '.join((*missing_packages, *missing_supplemental)),
                        stage_timeout_seconds=self.TIMEOUT_PROVISION,
                    )
                    previous_observer = self._controller_output_callback
                    async def observe(_stream: str, line: str) -> None:
                        text = str(line or '')
                        if 'HARNESSY_OPTIONAL_BATCH=' in text:
                            names = text.split('HARNESSY_OPTIONAL_BATCH=', 1)[1].strip().split()[0]
                            await self._emit_progress(progress, 'provisioning_optional_packages',
                                                      'Installing optional tools: ' + names.replace(',', ', '),
                                                      detail='Post-creation tool reconciliation.',
                                                      stage_timeout_seconds=self.TIMEOUT_PROVISION)
                        elif 'HARNESSY_PROVISION_STAGE=ghidra' in text:
                            await self._emit_progress(progress, 'provisioning_ghidra', 'Installing Ghidra headless…',
                                                      detail='Post-creation tool reconciliation.', stage_timeout_seconds=self.TIMEOUT_PROVISION)
                        elif 'HARNESSY_PROVISION_STAGE=python_re_tools' in text:
                            await self._emit_progress(progress, 'provisioning_python_re', 'Installing Python RE tool environments…',
                                                      detail='Post-creation tool reconciliation.', stage_timeout_seconds=self.TIMEOUT_PROVISION)
                        elif 'HARNESSY_PROVISION_STAGE=rea_cli' in text:
                            await self._emit_progress(progress, 'provisioning_rea', 'Installing or checking the REA CLI…',
                                                      detail='Latest stable package inside this VM; a working cached version is retained on failure.',
                                                      stage_timeout_seconds=self.TIMEOUT_PROVISION)
                    self._controller_output_callback = observe
                    try:
                        await self._run(
                            'shell', self.INSTANCE, 'sudo', '/bin/bash', '-lc',
                            self._provision_script(
                                (), optional_packages_override=missing_packages,
                                supplemental_tools_override=missing_supplemental,
                            ),
                            timeout=self.TIMEOUT_PROVISION, check=True,
                        )
                    finally:
                        self._controller_output_callback = previous_observer

                final = await self.optional_tool_status()
                unresolved = [tool for tool in desired if final.get(tool, {}).get('state') != 'installed'
                              or (tool == 'rea' and final.get(tool, {}).get('update_state') == 'failed')]
                if unresolved:
                    # Do not write a marker claiming this selection is complete.
                    # Leaving the previous revision in place makes the next Ready
                    # setup retry the still-missing selected tools automatically.
                    await self._emit_progress(
                        progress, 'tools_complete', 'Optional tool reconciliation completed with warnings.',
                        detail='Needs attention: ' + ', '.join(unresolved) + '. Existing working tool versions are retained when an update check fails; Apply again to retry.',
                        stage_timeout_seconds=10.0,
                    )
                else:
                    await self._finalize_guest_provisioning()
                    await self._emit_progress(
                        progress, 'tools_complete', 'Optional tools are up to date.',
                        detail=f'{len(desired)} selected optional tool(s) installed.', stage_progress_percent=100.0,
                        progress_source='tools', stage_timeout_seconds=10.0,
                    )
                # A same-image preset update invalidates the old Ready marker.
                # Applying its tools may restore readiness without restarting
                # or replacing this VM disk.
                await self._enforce_runtime_guard(progress=progress)
                await self._record_verified_guest()
                return await self.status()
        finally:
            from .manager import clear_environment_provider_cache
            clear_environment_provider_cache(self.workspace_root, self.config.id)
            release()

    def _provision_finalize_script(self) -> str:
        marker = json.dumps(self._provision_marker_payload(), sort_keys=True)
        return f'''set -euo pipefail
mkdir -p /workspace /var/lib/harnessy
chmod 0755 /workspace || true
cat >/etc/profile.d/harnessy-workspace.sh <<'EOF'
export HARNESSY_WORKSPACE=/workspace
export HARNESSY_VM=1
EOF
cat >/var/lib/harnessy/provisioning.json <<'EOF'
{marker}
EOF
chmod 0644 /var/lib/harnessy/provisioning.json
'''

    def _provision_script(
        self, required_packages: tuple[str, ...] | None = None, *,
        optional_packages_override: tuple[str, ...] | None = None,
        supplemental_tools_override: tuple[str, ...] | None = None,
    ) -> str:
        """Explicit one-time preset provisioning; never embedded in Lima boot YAML.

        The override arguments are used by post-creation tool management so a
        running VM installs only the missing tools the user selected instead of
        recreating already-present heavy Python environments.
        """
        preset = get_preset(self.config.preset)
        required = tuple(required_packages if required_packages is not None else preset.packages)
        packages = ' '.join(shlex.quote(p) for p in required)
        optional_packages = tuple(optional_packages_override) if optional_packages_override is not None else self._selected_optional_packages(preset)
        supplemental_tools = tuple(supplemental_tools_override) if supplemental_tools_override is not None else self._selected_supplemental_tools(preset)
        index_command, install_command, _ = package_commands(preset.image.package_manager)
        install_required = (
            f'{install_command} {packages} || '
            "printf '%s\\n' 'HARNESSY_PROVISION_WARNING=Required package command returned non-zero; HarnessyXO will verify installed packages before declaring failure.' >&2"
            if packages else ':'
        )
        optional_install = "printf '%s\\n' HARNESSY_PROVISION_STAGE=optional_packages\n"
        if optional_packages:
            # Installing fifty optional packages one apt invocation at a time is
            # unnecessarily slow (and repeatedly runs package-manager hooks like
            # needrestart). Try small batches first; if a distro is missing one
            # name, fall back only that batch to per-package best effort.
            batch_size = 8
            for offset in range(0, len(optional_packages), batch_size):
                batch = optional_packages[offset:offset + batch_size]
                quoted = ' '.join(shlex.quote(pkg) for pkg in batch)
                display = ','.join(batch)
                optional_install += (
                    f"printf '%s\\n' {shlex.quote('HARNESSY_OPTIONAL_BATCH=' + display)}\n"
                    f"if ! {install_command} {quoted}; then\n"
                    f"  for pkg in {quoted}; do\n"
                    "    printf 'HARNESSY_OPTIONAL_FALLBACK_TOOL=%s\\n' \"$pkg\"\n"
                    f"    {install_command} \"$pkg\" || true\n"
                    "  done\n"
                    "fi\n"
                    f"printf '%s\\n' {shlex.quote('HARNESSY_OPTIONAL_BATCH_DONE=' + str(len(batch)))}\n"
                )
        else:
            optional_install += "printf '%s\\n' HARNESSY_OPTIONAL_BATCH=none\n"
        supplemental = ''
        if 'ghidra' in supplemental_tools:
            ghidra_url = (
                'https://github.com/NationalSecurityAgency/ghidra/releases/download/'
                f'{GHIDRA_RELEASE_TAG}/{GHIDRA_RELEASE_FILE}'
            )
            # The official public archive includes Linux x86-64 natives. On
            # Linux ARM64 upstream requires building native components locally;
            # do that best-effort so an ARM VM still receives the Java/headless
            # framework without making a native-build failure brick provisioning.
            supplemental = f'''\nprintf '%s\\n' HARNESSY_OPTIONAL_TOOL=ghidra
printf '%s\\n' HARNESSY_PROVISION_STAGE=ghidra
install_harnessy_ghidra() {{
ghidra_root=/opt/{GHIDRA_RELEASE_DIR}
if [ ! -x "$ghidra_root/support/analyzeHeadless" ]; then
  tmp_ghidra="$(mktemp /tmp/harnessy-ghidra.XXXXXX.zip)"
  trap 'rm -f "$tmp_ghidra"' EXIT
  curl -fL --retry 3 --connect-timeout 20 {shlex.quote(ghidra_url)} -o "$tmp_ghidra" || return 1
  printf '%s  %s\\n' {shlex.quote(GHIDRA_RELEASE_SHA256)} "$tmp_ghidra" | sha256sum -c - || return 1
  rm -rf "$ghidra_root"
  unzip -q "$tmp_ghidra" -d /opt || return 1
  rm -f "$tmp_ghidra"
  trap - EXIT
fi
ln -sfn "$ghidra_root/support/analyzeHeadless" /usr/local/bin/ghidra-headless || return 1
ln -sfn "$ghidra_root/ghidraRun" /usr/local/bin/ghidra || return 1
if [ "$(uname -m)" = "aarch64" ] || [ "$(uname -m)" = "arm64" ]; then
  native_marker=/var/lib/harnessy/ghidra-{GHIDRA_VERSION}-linux-arm64-natives.ok
  if [ ! -f "$native_marker" ]; then
    printf '%s\\n' HARNESSY_PROVISION_STAGE=ghidra_arm64_natives
    chmod +x "$ghidra_root/support/gradle/gradlew" 2>/dev/null || true
    if (cd "$ghidra_root/support/gradle" && timeout 900 ./gradlew --no-daemon buildNatives); then
      touch "$native_marker"
    else
      printf '%s\\n' 'HARNESSY_PROVISION_WARNING=Ghidra Linux ARM64 native build did not complete; use an x86_64 reverse VM for the fully supported prebuilt native components.' >&2
    fi
  fi
fi
}}
if ! install_harnessy_ghidra; then
  printf '%s\\n' 'HARNESSY_PROVISION_WARNING=Optional Ghidra installation did not complete.' >&2
fi
'''
        if 'python-re' in supplemental_tools:
            # Heavy Python RE stacks live in isolated guest virtualenvs so
            # dependency churn cannot affect system Python or HarnessyXO.
            supplemental += r'''
printf '%s\n' HARNESSY_OPTIONAL_TOOL=python-re
printf '%s\n' HARNESSY_PROVISION_STAGE=python_re_tools
re_root=/opt/harnessy-re
mkdir -p "$re_root"
install_re_venv() {
  name="$1"; shift
  target="$re_root/$name"
  rm -rf "$target.tmp"
  if python3 -m venv "$target.tmp" \
      && "$target.tmp/bin/python" -m pip install --disable-pip-version-check --no-input --upgrade pip setuptools wheel \
      && "$target.tmp/bin/python" -m pip install --disable-pip-version-check --no-input "$@"; then
    rm -rf "$target"
    mv "$target.tmp" "$target"
    return 0
  fi
  rm -rf "$target.tmp"
  printf '%s\n' "HARNESSY_PROVISION_WARNING=Optional Python RE environment $name did not install." >&2
  return 1
}
install_re_venv angr 'angr==9.3.4' || true
install_re_venv capa 'flare-capa==9.4.0' || true
install_re_venv floss 'flare-floss==3.1.1' || true
install_re_venv binarylibs 'lief==1.0.0' 'r2pipe==1.9.8' 'keystone-engine' 'capstone' 'unicorn' 'pefile' 'pyelftools' 'dnfile' 'macholib' 'construct' || true
install_re_venv firmware 'ubi-reader' 'jefferson' || true
install_re_venv frida 'frida-tools' || true
[ -x "$re_root/angr/bin/python" ] && ln -sfn "$re_root/angr/bin/python" /usr/local/bin/angr-python || true
[ -x "$re_root/capa/bin/capa" ] && ln -sfn "$re_root/capa/bin/capa" /usr/local/bin/capa || true
[ -x "$re_root/floss/bin/floss" ] && ln -sfn "$re_root/floss/bin/floss" /usr/local/bin/floss || true
[ -x "$re_root/binarylibs/bin/python" ] && ln -sfn "$re_root/binarylibs/bin/python" /usr/local/bin/re-python || true
[ -x "$re_root/firmware/bin/ubireader_extract_files" ] && ln -sfn "$re_root/firmware/bin/ubireader_extract_files" /usr/local/bin/ubireader-extract-files || true
[ -x "$re_root/firmware/bin/ubireader_display_info" ] && ln -sfn "$re_root/firmware/bin/ubireader_display_info" /usr/local/bin/ubireader-info || true
[ -x "$re_root/firmware/bin/jefferson" ] && ln -sfn "$re_root/firmware/bin/jefferson" /usr/local/bin/jefferson || true
[ -x "$re_root/frida/bin/frida" ] && ln -sfn "$re_root/frida/bin/frida" /usr/local/bin/frida || true
[ -x "$re_root/frida/bin/frida-ps" ] && ln -sfn "$re_root/frida/bin/frida-ps" /usr/local/bin/frida-ps || true
[ -x "$re_root/frida/bin/frida-trace" ] && ln -sfn "$re_root/frida/bin/frida-trace" /usr/local/bin/frida-trace || true
'''
        if 'rea' in supplemental_tools:
            from .rea_cli import install_script
            supplemental += install_script(network=bool(self.config.network))
        script = f'''#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
printf '%s\\n' HARNESSY_PROVISION_STAGE=package_index
{index_command} || printf '%s\\n' 'HARNESSY_PROVISION_WARNING=Package index refresh returned non-zero; continuing with cached metadata and verifying required packages afterward.' >&2
printf '%s\\n' HARNESSY_PROVISION_STAGE=required_packages
{install_required}
{optional_install}
{supplemental}printf '%s\\n' HARNESSY_PROVISION_STAGE=package_phase_complete
'''
        return script

    async def _guest_provision_marker(self) -> dict[str, Any]:
        rc, stdout, _ = await self._run(
            'shell', self.INSTANCE, 'cat', '/var/lib/harnessy/provisioning.json',
            timeout=5, check=False,
        )
        if rc != 0 or not stdout.strip():
            return {}
        try:
            raw = json.loads(stdout)
        except json.JSONDecodeError:
            return {}
        return raw if isinstance(raw, dict) else {}

    async def _missing_packages(self, packages: tuple[str, ...]) -> tuple[str, ...]:
        preset = get_preset(self.config.preset)
        packages = tuple(packages)
        if not packages:
            return ()
        script = missing_packages_script(preset.image.package_manager, packages)
        rc, stdout, stderr = await self._run(
            'shell', self.INSTANCE, '/bin/bash', '-lc', script,
            timeout=self.TIMEOUT_PROVISION_CHECK, check=False,
        )
        if rc != 0:
            raise RuntimeError((stderr or stdout).strip() or 'could not inspect installed workspace packages')
        missing = tuple(line.strip() for line in stdout.splitlines() if line.strip())
        allowed = set(packages)
        return tuple(pkg for pkg in missing if pkg in allowed)

    async def _missing_required_packages(self) -> tuple[str, ...]:
        return await self._missing_packages(get_preset(self.config.preset).packages)

    async def _missing_integration_packages(self) -> tuple[str, ...]:
        preset = get_preset(self.config.preset)
        packages = MINIMUM_PACKAGES if preset.image.package_manager == 'apt' else RPM_MINIMUM
        return await self._missing_packages(tuple(packages))

    async def _finalize_guest_provisioning(self) -> None:
        await self._run(
            'shell', self.INSTANCE, 'sudo', '/bin/bash', '-lc', self._provision_finalize_script(),
            timeout=20, check=True,
        )

    async def _ensure_preset_provisioned(self, progress=None) -> None:
        """Ensure the preset exists without tying package management to VM boot.

        Fresh/rebuilt/reset disks have no marker and are provisioned once here.
        v0.2.19-and-older disks also have no marker, but usually already contain
        every required package because Lima used to reinstall them on each boot;
        those are adopted after a cheap dpkg check, avoiding one final apt cycle.
        """
        preset = get_preset(self.config.preset)
        marker = await self._guest_provision_marker()
        if str(marker.get('preset') or '') == preset.id and int(marker.get('schema') or 0) >= 1:
            marker_revision = str(marker.get('revision') or '')
            current_revision = self._provision_revision()
            if marker_revision == current_revision:
                log_event(
                    'runtime', 'vm_preset_provisioning_skipped', workspace=str(self.workspace_root),
                    provider='lima', preset=preset.id, reason='marker_present',
                )
                return
            if marker_revision:
                # Selected optional tools or network policy changed. Reconcile
                # the explicit workspace tool selection rather than pretending
                # the old marker still describes the current environment.
                log_event(
                    'runtime', 'vm_preset_provisioning_revision_changed',
                    workspace=str(self.workspace_root), provider='lima', preset=preset.id,
                    installed_revision=marker_revision, current_revision=current_revision,
                )

        await self._emit_progress(
            progress, 'checking_provisioning', 'Checking workspace tools…',
            detail='Normal VM starts do not install packages. Checking whether this disk was already provisioned.',
            stage_timeout_seconds=self.TIMEOUT_PROVISION_CHECK,
        )
        missing = await self._missing_required_packages()
        selected_optional = self._selected_optional_tool_ids(preset)

        # Public outbound disabled is authoritative. Never run apt/dnf/curl/pip
        # merely to discover that downloads are blocked. We only verify the tiny
        # integration baseline needed for the VM isolation/readiness handshake.
        if not self.config.network:
            missing_integration = await self._missing_integration_packages()
            if missing_integration:
                raise RuntimeError(
                    'Public outbound network is disabled and the guest is missing required '
                    'HarnessyXO integration packages: ' + ', '.join(missing_integration) + '. '
                    'Enable public outbound temporarily, finish setup, then disable it again.'
                )
            await self._emit_progress(
                progress, 'provisioning_skipped_offline', 'Skipping downloadable workspace tools…',
                detail=(
                    f'Public outbound is disabled. {len(missing)} preset package(s) and '
                    f'{len(selected_optional)} selected optional tool(s) will not be downloaded. '
                    'The VM can still become Ready with tools already present in the image.'
                ),
                stage_timeout_seconds=20.0,
            )
            await self._finalize_guest_provisioning()
            log_event(
                'runtime', 'vm_preset_provisioning_skipped_offline', workspace=str(self.workspace_root),
                provider='lima', preset=preset.id, missing_required=list(missing),
                selected_optional=list(selected_optional),
            )
            return

        if not missing and not marker:
            await self._emit_progress(
                progress, 'adopting_provisioning', 'Recording existing workspace tools…',
                detail='Required tools are already present; adopting this existing disk without starting a surprise download cycle.',
                stage_timeout_seconds=20.0,
            )
            await self._finalize_guest_provisioning()
            log_event(
                'runtime', 'vm_preset_provisioning_adopted', workspace=str(self.workspace_root),
                provider='lima', preset=preset.id, revision=self._provision_revision(),
            )
            return

        await self._emit_progress(
            progress, 'provisioning_packages', 'Installing workspace tools…',
            detail=(
                f'{len(missing)} missing preset package(s) · {len(selected_optional)} selected optional tool(s). '
                'This runs after Create/Rebuild/Factory Reset or when the selected tool/network configuration changes.'
            ),
            stage_timeout_seconds=self.TIMEOUT_PROVISION,
        )
        log_event(
            'runtime', 'vm_preset_provisioning_started', workspace=str(self.workspace_root),
            provider='lima', preset=preset.id, missing_required=list(missing),
        )

        optional_index = {'value': 0}
        optional_total = len(self._selected_optional_packages(preset)) + len(self._selected_supplemental_tools(preset))

        async def observe_provision(_stream: str, line: str) -> None:
            text = str(line or '')
            if 'HARNESSY_OPTIONAL_BATCH=' in text:
                batch = text.split('HARNESSY_OPTIONAL_BATCH=', 1)[1].strip().split()[0]
                names = [name for name in batch.split(',') if name and name != 'none']
                if names:
                    await self._emit_progress(
                        progress, 'provisioning_optional_packages',
                        'Installing optional tools: ' + ', '.join(names),
                        detail=(
                            f'Batch of {len(names)} selected package(s). If the batch contains an unavailable '
                            'distro package, HarnessyXO falls back to the individual package names in this batch.'
                        ),
                        progress_source='tools',
                        stage_timeout_seconds=max(1.0, provision_deadline - time.monotonic()),
                    )
                return
            if 'HARNESSY_OPTIONAL_FALLBACK_TOOL=' in text:
                tool = text.split('HARNESSY_OPTIONAL_FALLBACK_TOOL=', 1)[1].strip().split()[0]
                await self._emit_progress(
                    progress, 'provisioning_optional_packages',
                    f'Installing optional tool {tool}…',
                    detail=f'Batch fallback · trying {tool} individually.',
                    progress_source='tools',
                    stage_timeout_seconds=max(1.0, provision_deadline - time.monotonic()),
                )
                return
            if 'HARNESSY_OPTIONAL_BATCH_DONE=' in text:
                try:
                    completed_count = max(0, int(text.split('HARNESSY_OPTIONAL_BATCH_DONE=', 1)[1].strip().split()[0]))
                except (TypeError, ValueError):
                    completed_count = 0
                optional_index['value'] = min(optional_total, optional_index['value'] + completed_count)
                await self._emit_progress(
                    progress, 'provisioning_optional_packages',
                    'Installing optional workspace tools…',
                    detail=f'{optional_index["value"]}/{max(1, optional_total)} selected optional tools processed.',
                    stage_progress_percent=optional_index['value'] / max(1, optional_total) * 100.0,
                    progress_source='tools',
                    stage_timeout_seconds=max(1.0, provision_deadline - time.monotonic()),
                )
                return
            if 'HARNESSY_OPTIONAL_TOOL=' in text:
                tool = text.split('HARNESSY_OPTIONAL_TOOL=', 1)[1].strip().split()[0]
                optional_index['value'] += 1
                await self._emit_progress(
                    progress, 'provisioning_optional_packages',
                    f'Installing optional tool {tool}…',
                    detail=f'{optional_index["value"]}/{max(1, optional_total)} selected optional tools · {tool}',
                    stage_progress_percent=(optional_index['value'] - 1) / max(1, optional_total) * 100.0,
                    progress_source='tools',
                    stage_timeout_seconds=max(1.0, provision_deadline - time.monotonic()),
                )
                return
            mapping = {
                'HARNESSY_PROVISION_STAGE=package_index': (
                    'provisioning_package_index', 'Updating guest package index…',
                    'Refreshing package metadata for this newly provisioned VM.',
                ),
                'HARNESSY_PROVISION_STAGE=required_packages': (
                    'provisioning_required_packages', 'Installing required workspace tools…',
                    f'Installing {len(missing)} missing required package(s).',
                ),
                'HARNESSY_PROVISION_STAGE=optional_packages': (
                    'provisioning_optional_packages', 'Installing optional workspace tools…',
                    f'{optional_total} selected optional tool(s). Optional failures do not block environment readiness.',
                ),
                'HARNESSY_PROVISION_STAGE=ghidra': (
                    'provisioning_ghidra', 'Installing Ghidra headless…',
                    'Downloading and verifying the pinned official Ghidra release.',
                ),
                'HARNESSY_PROVISION_STAGE=ghidra_arm64_natives': (
                    'provisioning_ghidra_arm64', 'Building Ghidra ARM64 native components…',
                    'Official Ghidra releases do not ship Linux ARM64 natives; building supported local native components.',
                ),
                'HARNESSY_PROVISION_STAGE=python_re_tools': (
                    'provisioning_python_re', 'Installing Python RE tool environments…',
                    'Installing isolated angr, capa, FLOSS and binary-analysis Python environments.',
                ),
                'HARNESSY_PROVISION_STAGE=rea_cli': (
                    'provisioning_rea', 'Installing the REA CLI inside this VM…',
                    'Resolving the latest stable npm package and verifying a guest-local Node runtime.',
                ),
                'HARNESSY_PROVISION_STAGE=finalizing': (
                    'finalizing_provisioning', 'Finalizing workspace tools…',
                    'Recording the one-time provisioning marker and workspace shell profile.',
                ),
            }
            for sentinel, (phase, message, detail) in mapping.items():
                if sentinel in text:
                    await self._emit_progress(
                        progress, phase, message, detail=detail,
                        stage_timeout_seconds=max(1.0, provision_deadline - time.monotonic()),
                    )
                    break

        provision_deadline = time.monotonic() + self.TIMEOUT_PROVISION
        previous_observer = self._controller_output_callback
        self._controller_output_callback = observe_provision
        try:
            await self._run(
                'shell', self.INSTANCE, 'sudo', '/bin/bash', '-lc', self._provision_script(missing),
                timeout=self.TIMEOUT_PROVISION, check=True,
            )
        finally:
            self._controller_output_callback = previous_observer

        # Some package-manager hooks (notably needrestart/systemd service restart
        # helpers) can make apt return non-zero even after every requested
        # package landed. The script keeps going; this explicit verification is
        # the authority. Never mark the disk provisioned while required packages
        # are actually absent.
        remaining = await self._missing_required_packages()
        if remaining:
            raise RuntimeError('Workspace tool provisioning left required packages missing: ' + ', '.join(remaining))
        await self._emit_progress(
            progress, 'finalizing_provisioning', 'Finalizing workspace tools…',
            detail='Required packages verified. Recording the workspace provisioning state.',
            stage_timeout_seconds=20.0,
        )
        await self._finalize_guest_provisioning()
        log_event(
            'runtime', 'vm_preset_provisioning_completed', workspace=str(self.workspace_root),
            provider='lima', preset=preset.id, revision=self._provision_revision(),
        )

    def _vm_type(self) -> str:
        if self.config.desktop:
            return 'qemu'  # Lima exposes the guest graphical display through QEMU VNC.
        return execution_mode(self.config.architecture, host_arch=platform.machine(), host_os=platform.system())[0]

    def _mount_type(self) -> str:
        return 'virtiofs' if self._vm_type() == 'vz' else get_preset(self.config.preset).image.qemu_mount

    def _uses_clone_snapshots(self) -> bool:
        return self._vm_type() == 'vz'

    def _template_text(self) -> str:
        _validate_registry_path(self.canonical_files_root, self.workspace_root)
        preset = get_preset(self.config.preset)
        vm_type = self._vm_type()
        mount_type = self._mount_type()
        files = str(self.files_root.resolve())
        worktrees = str(self.private_worktrees_root.resolve())
        references_mount = (f'- location: {self._q(str(self.canonical_files_root.resolve()))}\n'
                            f'  mountPoint: {self._q(REFERENCES_BACKING_GUEST_PATH)}\n  writable: false\n')
        image_spec = (f'images:\n- location: {self._q(str(self.environment_root / "images" / "kali.img"))}\n  arch: {"aarch64" if self.config.architecture == "arm64" else "x86_64"}'
                      if preset.image_id == 'kali-2026.2' else f'base:\n- template:{preset.image.template}')
        video_spec = ('video:\n  display: vnc\n  vnc:\n    display: "127.0.0.1:0,to=99"' if self.config.desktop else 'video:\n  display: none')
        return f'''# Generated by HarnessyXO from portable environment.json.
minimumLimaVersion: 2.0.0
{image_spec}
vmType: {vm_type}
arch: {"aarch64" if self.config.architecture == "arm64" else "x86_64"}
cpus: {self.config.cpu}
memory: "{self.config.memory_mb}MiB"
disk: "{self.config.disk_gb}GiB"
{video_spec}
mountType: {mount_type}
mounts:
- location: {self._q(files)}
  mountPoint: {self._q(FILES_BACKING_GUEST_PATH)}
  writable: {"false" if self.config.files_mode == "readonly" else "true"}
- location: {self._q(worktrees)}
  mountPoint: {self._q(PRIVATE_WORKTREES_GUEST_PATH)}
  writable: {"false" if self.config.files_mode == "readonly" else "true"}
{references_mount.rstrip()}
mountInotify: false
ssh:
{"  overVsock: false" if preset.image_id.startswith("fedora") else ""}
  loadDotSSHPubKeys: false
  forwardAgent: false
  forwardX11: false
containerd:
  system: false
  user: false
# Host proxy settings may contain host-only endpoints/credentials; the guest
# gets ordinary NAT networking instead of inheriting the host process proxy env.
propagateProxyEnv: false
# Disable Lima's automatic guest-service forwarding. SSH/controller transport
# is internal to Lima and is the only exception.
portForwards:
- guestIP: "127.0.0.1"
  proto: any
  guestPortRange: [1, 65535]
  ignore: true
- guestIP: "0.0.0.0"
  guestIPMustBeZero: false
  proto: any
  guestPortRange: [1, 65535]
  ignore: true
message: "HarnessyXO workspace VM · {preset.name} · {self.config.architecture} · CPU only"
'''

    def _write_template(self) -> None:
        _validate_registry_path(self.template_path, self.workspace_root)
        self.template_path.write_text(self._template_text(), encoding='utf-8')

    @staticmethod
    async def _emit_progress(progress, phase: str, message: str, **meta: Any) -> None:
        if progress is None:
            return
        supports_meta = False
        try:
            signature = inspect.signature(progress)
            supports_meta = any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            ) or all(key in signature.parameters for key in meta)
        except (TypeError, ValueError):
            supports_meta = False
        result = progress(phase, message, **meta) if supports_meta else progress(phase, message)
        if asyncio.iscoroutine(result):
            await result

    @staticmethod
    async def _call_with_optional_progress(method, *args: Any, progress=None):
        supports_progress = False
        try:
            signature = inspect.signature(method)
            supports_progress = 'progress' in signature.parameters or any(
                parameter.kind == inspect.Parameter.VAR_KEYWORD
                for parameter in signature.parameters.values()
            )
        except (TypeError, ValueError):
            supports_progress = False
        if supports_progress:
            return await method(*args, progress=progress)
        return await method(*args)

    @staticmethod
    def _lima_log_message(raw_line: str) -> str:
        text = re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]', '', str(raw_line or '')).strip()
        if not text:
            return ''
        # Redirected logrus output uses msg="...". Decode that JSON-style quoted
        # value when possible, otherwise retain the complete line as evidence.
        match = re.search(r'\bmsg=("(?:\\.|[^"\\])*")', text)
        if match:
            try:
                return str(json.loads(match.group(1))).strip()
            except (json.JSONDecodeError, TypeError):
                pass
        # Interactive-style output uses INFO[0001] / WARN[0001] prefixes.
        text = re.sub(r'^(?:INFO|WARN|DEBU|TRAC|ERRO|FATA)\[\d+\]\s*', '', text)
        return text.strip()

    @classmethod
    def _lima_startup_signal(cls, raw_line: str) -> tuple[str | None, str | None]:
        """Classify known controller messages without retaining their content.

        A port allocation or a waiting milestone is not a successful SSH
        handshake. A duration or nonzero exit alone never identifies its cause.
        """
        raw = re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]', '', str(raw_line or '')).strip()
        message = cls._lima_log_message(raw)
        fatal = bool(re.search(r'\blevel=fatal\b|^FATA\[\d+\]', raw))
        if raw.startswith('{'):
            try:
                record = json.loads(raw)
                if isinstance(record, dict) and isinstance(record.get('msg'), str):
                    message = record['msg']
                    fatal = record.get('level') == 'fatal'
            except (ValueError, TypeError):
                pass
        message = re.sub(r'^\[hostagent\]\s*', '', message, flags=re.IGNORECASE).strip()
        lowered = message.lower()
        requirement = re.search(
            r'(waiting for|failed to satisfy) the (?:essential|optional|final) requirement '
            r'\d+ of \d+:?\s*"([^"]+)"', lowered,
        )
        milestone = None
        failure = 'startup_fatal' if fatal else None
        if requirement:
            description = requirement.group(2)
            if description in {'ssh', 'explicitly start ssh controlmaster', 'user session is ready for ssh'}:
                milestone = 'waiting_ssh'
                if requirement.group(1) == 'failed to satisfy':
                    failure = 'ssh_requirement_wait_failed'
            elif description == 'boot scripts must have finished':
                milestone = 'waiting_boot_scripts'
        elif lowered.startswith('starting the instance '):
            milestone = 'launching_instance'
        elif lowered.startswith('starting vz'):
            milestone = 'launching_vz'
        elif re.match(r'^ssh local port:\s*\d+\b', lowered):
            milestone = 'ssh_port_assigned'
        elif lowered.startswith(('waiting for the guest agent', 'waiting for guest agent')):
            milestone = 'waiting_guest_agent'
        elif lowered == 'ready' or lowered.startswith('ready. run `'):
            milestone = 'lima_ready'
        return milestone, failure

    @staticmethod
    def _controller_action(args: tuple[str, ...]) -> str:
        action = args[0] if args else ''
        return action if action in {
            'start', 'stop', 'create', 'delete', 'edit', 'shell', 'list', 'snapshot',
            'clone', 'factory-reset', 'restart', '--version',
        } else 'other'

    async def _observe_startup_failure_state(self, command_id: str) -> None:
        """Read one bounded host-controller status; never repair or retry."""
        controller_status = 'unknown'
        try:
            rc, stdout, _ = await self._run(
                'list', '--format', 'json', self.INSTANCE,
                timeout=self.TIMEOUT_STARTUP_STATUS, check=False,
            )
            if rc != 0:
                controller_status = 'probe_failed'
            else:
                data = json.loads(stdout)
                if isinstance(data, list):
                    row = next((item for item in data if isinstance(item, dict) and item.get('name') == self.INSTANCE), None)
                else:
                    row = data if isinstance(data, dict) and data.get('name') == self.INSTANCE else None
                if row is None:
                    controller_status = 'not_created'
                else:
                    value = str(row.get('status') or row.get('Status') or '').lower()
                    if value in {'running', 'stopped', 'starting', 'stopping', 'broken'}:
                        controller_status = value
        except asyncio.TimeoutError:
            controller_status = 'timeout'
        except LimaUnavailableError:
            controller_status = 'unavailable'
        except Exception:
            controller_status = 'probe_failed'
        log_event(
            'runtime', 'vm_startup_post_failure_state', workspace=str(self.workspace_root),
            provider='lima', controller_action='start', parent_start_command_id=command_id,
            controller_status=controller_status, ready=False, **self._controller_diagnostic_fields(),
        )

    @classmethod
    def _lima_progress_update(cls, raw_line: str) -> tuple[str, float | None] | None:
        message = cls._lima_log_message(raw_line)
        if not message:
            return None
        lowered = message.lower()
        raw_clean = re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]', '', str(raw_line or ''))

        # Lima can emit direct "Waiting N / M" progress and byte-copy progress.
        direct = re.search(r'\bWaiting\s+(\d+)\s*/\s*(\d+)\b', message, re.IGNORECASE)
        if direct:
            current, total = int(direct.group(1)), max(1, int(direct.group(2)))
            description = re.search(r'"([^"]+)"', message)
            label = f'Boot checks {current}/{total}'
            if description:
                label += f' · {description.group(1)}'
            return label, max(0.0, min(100.0, current / total * 100.0))

        pct = re.search(r'(?<!\d)(\d{1,3}(?:\.\d+)?)\s*%', raw_clean)
        percent = max(0.0, min(100.0, float(pct.group(1)))) if pct else None
        if 'attempting to download the image' in lowered:
            return 'Checking or downloading the guest OS image…', percent
        if 'using cache' in lowered and 'download' not in lowered:
            return 'Using cached Lima image data…', percent
        if 'converting ' in lowered and ('basedisk' in lowered or 'disk' in lowered):
            return 'Preparing the VM disk image…', percent
        if 'expanding to ' in lowered:
            return 'Expanding the VM disk…', percent
        if 'starting the instance' in lowered:
            return 'Launching the workspace VM…', percent
        if '[hostagent] starting vz' in lowered or 'starting vz' in lowered:
            return 'Launching Apple Virtualization (VZ)…', percent
        if 'ssh local port' in lowered:
            return 'VM launched · waiting for SSH…', percent
        requirement = re.search(r'waiting for the (?:essential|optional|final) requirement \d+ of \d+:\s*"([^"]+)"', message, re.IGNORECASE)
        if requirement:
            return f'Waiting for guest: {requirement.group(1)}…', percent
        if 'cloud-init' in lowered or 'provision' in lowered or 'boot scripts must have finished' in lowered:
            return 'Finishing Lima guest boot checks…', percent
        if message.rstrip('.').endswith('READY') or ' ready. run `lima`' in lowered:
            return 'Lima reports the VM Ready.', 100.0
        if percent is not None:
            return message[-220:], percent
        return None

    @staticmethod
    def _controller_progress_should_emit(
        state: dict[str, Any], detail: str, percent: float | None, *, min_interval: float = 0.5,
    ) -> bool:
        """Throttle redraw-style Lima progress without hiding meaningful milestones."""
        now = time.monotonic()
        previous_detail = str(state.get('detail') or '')
        previous_percent = state.get('percent')
        last_at = float(state.get('at') or 0.0)
        detail_changed = detail != previous_detail
        percent_changed = percent is not None and (
            previous_percent is None or abs(float(percent) - float(previous_percent)) >= 1.0
            or float(percent) in {0.0, 100.0}
        )
        if not detail_changed and not percent_changed and now - last_at < min_interval:
            return False
        state['detail'] = detail
        if percent is not None:
            state['percent'] = float(percent)
        state['at'] = now
        return True

    @classmethod
    def _lima_clone_progress_update(cls, raw_line: str) -> tuple[str, float | None] | None:
        message = cls._lima_log_message(raw_line)
        if not message:
            return None
        raw_clean = re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]', '', str(raw_line or ''))
        pct = re.search(r'(?<!\d)(\d{1,3}(?:\.\d+)?)\s*%', raw_clean)
        percent = max(0.0, min(100.0, float(pct.group(1)))) if pct else None
        lowered = message.lower()
        if percent is not None:
            return f'Copying VM checkpoint · {percent:.0f}%', percent
        if any(token in lowered for token in ('clone', 'copy', 'disk', 'instance')):
            return message[-220:], None
        return None

    @staticmethod
    def _guest_wrapper(command: str) -> str:
        # The remote shell owns a fresh session for the model command. If the
        # Lima/SSH controller disappears (Stop generation, timeout, terminal
        # close), HUP/TERM cleanup kills that command's guest process group.
        payload = shlex.quote(str(command))
        return (
            "child=''\n"
            "cleanup() { if [ -n \"$child\" ]; then kill -TERM -- -\"$child\" 2>/dev/null || kill -TERM \"$child\" 2>/dev/null || true; fi; }\n"
            "trap cleanup HUP INT TERM EXIT\n"
            f"setsid /bin/bash -lc {payload} </dev/stdin >/dev/stdout 2>/dev/stderr &\n"
            "child=$!\n"
            "wait \"$child\"\n"
            "rc=$?\n"
            "trap - HUP INT TERM EXIT\n"
            "exit $rc"
        )

    def _bridge_host_path(self, path: Path) -> Path:
        for root in (self.files_root, self.private_worktrees_root,
                     self.canonical_files_root, self.canonical_worktrees_root):
            _validate_registry_path(root, self.workspace_root)
        target = Path(path).resolve()
        if self.config.files_mode != 'copy':
            return target
        for canonical, deployed in ((self.canonical_files_root, self.files_root),
                                    (self.canonical_worktrees_root, self.private_worktrees_root)):
            canonical = canonical.resolve()
            if target == canonical or canonical in target.parents:
                return deployed.resolve() / target.relative_to(canonical)
        # Internal calls may already pass an environment-owned deployed root.
        for deployed in (self.files_root.resolve(), self.private_worktrees_root.resolve()):
            if target == deployed or deployed in target.parents:
                return target
        raise ValueError('Project copy source is outside the workspace project roots.')

    def copy_project_root(self, active_root: Path) -> Path:
        if self.config.files_mode != 'copy':
            raise ValueError('This VM uses shared project files, not a separate copy.')
        return self._bridge_host_path(active_root)

    def _prepare_project_copy(self, active_root: Path | None,
                              output_policy: dict[str, Any] | None = None, *, refresh: bool = False) -> dict[str, Any]:
        """Deploy authorized project roots once; never copy guest edits back.

        A user-opened whole-workspace terminal may deliberately request Files/.
        Model tools pass their selected project and its explicit access policy.
        Copies preserve symlinks as links, so a link cannot copy host data from
        outside the authorized roots into the guest export.
        """
        if self.config.files_mode != 'copy':
            raise ValueError('Only separate-copy VMs support deploying project copies.')
        policy = output_policy if isinstance(output_policy, dict) else {}
        selected = Path(active_root or self.canonical_files_root)
        _validate_registry_path(selected, self.workspace_root)
        selected_root = selected.resolve()
        if selected_root == self.canonical_files_root.resolve():
            # The user terminal's workspace-wide view copies each existing
            # directory independently, preserving any previously deployed
            # project edits instead of replacing the whole export.
            roots = [child for child in selected_root.iterdir() if child.is_dir() and not child.is_symlink()]
        else:
            roots = [selected_root]
        references = self.canonical_files_root / 'References'
        if references.is_dir():
            roots.append(references)
        for row in (*tuple(policy.get('ancestors') or ()), *tuple(policy.get('access_projects') or ())):
            if not isinstance(row, dict):
                raise ValueError('Invalid project-copy access policy.')
            raw = str(row.get('host_path') or '')
            if raw:
                roots.append(Path(raw))
        deployed: list[str] = []
        # Serialized per VM so two simultaneous first-use commands cannot
        # install partial trees over one another.
        lock = _COPY_LOCKS.setdefault(str(self.environment_root), threading.RLock())
        with lock:
            for source_path in dict.fromkeys(roots):
                _validate_registry_path(source_path, self.workspace_root)
                source = source_path.resolve()
                destination = self._bridge_host_path(source)
                _validate_registry_path(destination, self.workspace_root)
                if source.is_symlink() or not source.is_dir():
                    raise ValueError('The selected project-copy source is unavailable.')
                if destination.exists() and not refresh:
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                staging = destination.with_name('.' + destination.name + '.deploy-' + uuid.uuid4().hex)
                previous = destination.with_name('.' + destination.name + '.previous-' + uuid.uuid4().hex)
                try:
                    shutil.copytree(source, staging, symlinks=True)
                    if destination.exists():
                        destination.rename(previous)
                    staging.rename(destination)
                except BaseException:
                    if previous.exists() and not destination.exists():
                        previous.rename(destination)
                    raise
                finally:
                    if staging.exists():
                        shutil.rmtree(staging)
                if previous.exists():
                    shutil.rmtree(previous)
                deployed.append(source.name)
        return {'environment_id': self.config.id, 'files_mode': 'copy',
                'deployed_projects': deployed, 'refreshed': bool(refresh),
                'canonical_files_changed': False}

    async def deploy_project(self, active_root: Path, *, output_policy: dict[str, Any] | None = None) -> dict[str, Any]:
        self._authorize_model_project(output_policy)
        # Replacing an export while a process holds it would strand old inodes.
        from .activity import active_work
        if active_work(self.workspace_root, environment_id=self.config.id):
            raise RuntimeError("Stop this VM's commands and terminals before refreshing its project copy.")
        release = reserve_environment_change(self.workspace_root, 'project deployment', environment_id=self.config.id)
        try:
            result = await asyncio.to_thread(self._prepare_project_copy, active_root, output_policy, refresh=True)
            self._authorize_model_project(output_policy)
            return result
        finally:
            release()

    def _guest_source_for_active_root(self, active_root: Path | None) -> str:
        """Return a controller-only guest backing path for one host worktree."""
        target = self._bridge_host_path(Path(active_root or self.files_root))
        files = self.files_root.resolve()
        private = self.private_worktrees_root.resolve()
        if target == files or files in target.parents:
            relative = target.relative_to(files).as_posix()
            return FILES_BACKING_GUEST_PATH if relative == '.' else f'{FILES_BACKING_GUEST_PATH}/{relative}'
        if private in target.parents:
            relative_path = target.relative_to(private)
            parts = relative_path.parts
            valid = (
                len(parts) >= 3 and parts[0] in {'imports', 'branches'} and parts[2] == 'working'
            ) or (
                len(parts) >= 4 and parts[0] == 'rewinds' and parts[3] == 'working'
            )
            if not valid:
                raise ValueError('Active private root does not select one concrete worktree')
            relative = relative_path.as_posix()
            return f'{PRIVATE_WORKTREES_GUEST_PATH}/{relative}'
        raise ValueError('Active working root is outside the workspace Files/private-worktree mounts')

    @staticmethod
    def _validated_workspace_cwd(cwd: str) -> str:
        raw = str(cwd or WORKSPACE_VIEW_GUEST_PATH).replace('\\', '/')
        path = PurePosixPath(raw)
        if not path.is_absolute() or not path.parts or path.parts[0] != '/':
            raise ValueError('Guest working directory must be an absolute /workspace path')
        if '..' in path.parts:
            raise ValueError('Guest working directory cannot traverse outside /workspace')
        normalized = path.as_posix().rstrip('/') or '/'
        if normalized != WORKSPACE_VIEW_GUEST_PATH and not normalized.startswith(WORKSPACE_VIEW_GUEST_PATH + '/'):
            raise ValueError('Guest working directory is outside the isolated /workspace view')
        return normalized

    @staticmethod
    def _user_command_trampoline() -> str:
        """Restore the controller-selected cwd after login profiles run.

        Existing workspace VMs may still have the old profile hook which runs
        ``cd /workspace`` for every login shell.  The Tool result must never
        report a project cwd which the payload did not actually receive, so the
        final cwd change and proof deliberately happen *inside* the login-shell
        command, after all profiles have completed.
        """
        return '''set -e
target_cwd=$1
view_command=$2
if ! cd -- "$target_cwd"; then
  printf '[HARNESSY_WORKSPACE_VIEW:INVALID_WORKSPACE_CWD] HarnessyXO could not enter the selected project directory\n' >&2
  exit 72
fi
actual_cwd=$(/bin/pwd -P)
if [ "$actual_cwd" != "$target_cwd" ]; then
  printf '[HARNESSY_WORKSPACE_VIEW:INVALID_WORKSPACE_CWD] HarnessyXO selected project cwd verification failed\n' >&2
  exit 72
fi
exec /bin/bash -c "$view_command"
'''

    def _workspace_view_command(
        self, command: str, *, cwd: str = WORKSPACE_VIEW_GUEST_PATH,
        active_root: Path | None = None, output_policy: dict[str, Any] | None = None,
    ) -> str:
        """Build a guest-only view exposing exactly one active root.

        Lima mounts Files/ and controller worktrees at raw backing paths and no
        model command is launched there.  v0.6 project policies enter a retained
        project namespace; legacy/internal views still use a fresh namespace.
        Both forms detach the raw parents before dropping to the Lima user.
        """
        command = self._guest_work_path_exports(active_root) + '\n' + str(command)
        source = self._guest_source_for_active_root(active_root)
        view_cwd = self._validated_workspace_cwd(cwd)
        user_command_trampoline = shlex.quote(self._user_command_trampoline())
        policy = output_policy if isinstance(output_policy, dict) else {}
        if int(policy.get('namespace_version') or 0) == 2:
            return self._project_workspace_view_command(
                source=source, view_cwd=view_cwd, command=command, policy=policy,
            )
        output_names: list[str] = []
        for value in policy.get('folders') or ():
            name = str(value or '')
            if not CHAT_OUTPUT_DIR_RE.fullmatch(name):
                raise ValueError('Invalid protected Project/Chat output directory name')
            if name not in output_names:
                output_names.append(name)
        if len(output_names) > 1000:
            raise ValueError('Too many protected Project/Chat output directories')
        writable_output = str(policy.get('writable_folder') or '')
        if writable_output and writable_output not in output_names:
            raise ValueError('Writable Project/Chat output directory is not registered')
        output_names_csv = ','.join(output_names)
        inner = f'''set -euo pipefail
source_path=$1
view_cwd=$2
view_command=$3
output_names=$4
writable_output=$5
view_user=$6
cleanup_names=""
view_failure() {{
  printf '[HARNESSY_WORKSPACE_VIEW:%s] %s\\n' "$1" "$2" >&2
  exit 72
}}
trap 'view_failure MOUNT_PROJECTION_FAILED "HarnessyXO could not prepare the isolated workspace view"' ERR
case "$source_path" in
  {FILES_BACKING_GUEST_PATH}|{FILES_BACKING_GUEST_PATH}/*|{PRIVATE_WORKTREES_GUEST_PATH}/*) ;;
  *) view_failure INVALID_BACKING_PATH "HarnessyXO rejected an invalid workspace backing path" ;;
esac
[ -d "$source_path" ] || view_failure ACTIVE_ROOT_UNAVAILABLE "HarnessyXO active working root is unavailable"
# An old VM can still have /workspace mounted directly while the new raw
# backing paths are absent. Never bind an ordinary empty guest directory and
# call it the authoritative host worktree.
if ! /usr/bin/mountpoint -q {FILES_BACKING_GUEST_PATH} || ! /usr/bin/mountpoint -q {PRIVATE_WORKTREES_GUEST_PATH}; then
  view_failure BACKING_MOUNTS_UNAVAILABLE "HarnessyXO workspace backing mounts are unavailable; restart the environment to reconcile its configuration"
fi
/usr/bin/mkdir -p {WORKSPACE_VIEW_GUEST_PATH}
/usr/bin/mount --bind "$source_path" {WORKSPACE_VIEW_GUEST_PATH}
/usr/bin/mount --make-private {WORKSPACE_VIEW_GUEST_PATH}
{"/usr/bin/mount -o remount,bind,ro " + WORKSPACE_VIEW_GUEST_PATH if self.config.files_mode == "readonly" else ":"}
if [ -n "$output_names" ]; then
  old_ifs=$IFS
  IFS=','
  for output_name in $output_names; do
    IFS=$old_ifs
    case "$output_name" in
      *_output) ;;
      *) view_failure INVALID_OUTPUT_DIRECTORY "HarnessyXO rejected an invalid Project/Chat output directory" ;;
    esac
    output_source={FILES_BACKING_GUEST_PATH}/$output_name
    output_target={WORKSPACE_VIEW_GUEST_PATH}/$output_name
    if [ -L "$output_source" ] || [ -L "$output_target" ]; then
      view_failure INVALID_OUTPUT_DIRECTORY "HarnessyXO refused a symlink in a protected Project/Chat output directory"
    fi
    [ -d "$output_source" ] || view_failure OUTPUT_DIRECTORY_UNAVAILABLE "HarnessyXO output directory is unavailable"
    if [ ! -d "$output_target" ]; then
      /usr/bin/mkdir -p "$output_target"
      case "$source_path" in
        {PRIVATE_WORKTREES_GUEST_PATH}/*) cleanup_names="${{cleanup_names:+$cleanup_names,}}$output_name" ;;
      esac
    elif [ -z "$(/usr/bin/find "$output_target" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
      case "$source_path" in
        {PRIVATE_WORKTREES_GUEST_PATH}/*) cleanup_names="${{cleanup_names:+$cleanup_names,}}$output_name" ;;
      esac
    fi
    /usr/bin/mount --bind "$output_source" "$output_target"
    if [ "$output_name" != "$writable_output" ]; then
      /usr/bin/mount -o remount,bind,ro "$output_target"
    fi
    IFS=','
  done
  IFS=$old_ifs
fi
/usr/bin/umount -l {FILES_BACKING_GUEST_PATH} 2>/dev/null || true
/usr/bin/umount -l {PRIVATE_WORKTREES_GUEST_PATH} 2>/dev/null || true
/usr/bin/umount -l {REFERENCES_BACKING_GUEST_PATH} 2>/dev/null || true
if /usr/bin/mountpoint -q {FILES_BACKING_GUEST_PATH} || /usr/bin/mountpoint -q {PRIVATE_WORKTREES_GUEST_PATH} || /usr/bin/mountpoint -q {REFERENCES_BACKING_GUEST_PATH}; then
  view_failure RAW_MOUNT_DETACH_FAILED "HarnessyXO could not detach private workspace backing mounts"
fi
case "$view_cwd" in
  {WORKSPACE_VIEW_GUEST_PATH}|{WORKSPACE_VIEW_GUEST_PATH}/*) ;;
  *) view_failure INVALID_WORKSPACE_CWD "HarnessyXO rejected an invalid workspace working directory" ;;
esac
cd "$view_cwd" || view_failure INVALID_WORKSPACE_CWD "HarnessyXO workspace working directory is unavailable"
# User command failure is not projection failure; preserve its real exit code.
trap - ERR
set +e
/usr/bin/sudo -n -u "$view_user" -- /bin/bash -lc {user_command_trampoline} \
  harnessy-workspace-command "$view_cwd" "$view_command"
rc=$?
set -e
if [ -n "$output_names" ]; then
  old_ifs=$IFS
  IFS=','
  for output_name in $output_names; do
    /usr/bin/umount -l {WORKSPACE_VIEW_GUEST_PATH}/$output_name 2>/dev/null || true
  done
  IFS=$old_ifs
fi
if [ -n "$cleanup_names" ]; then
  old_ifs=$IFS
  IFS=','
  for output_name in $cleanup_names; do
    /usr/bin/rmdir {WORKSPACE_VIEW_GUEST_PATH}/$output_name 2>/dev/null || true
  done
  IFS=$old_ifs
fi
exit $rc
'''
        argv = ' '.join(shlex.quote(value) for value in (
            'harnessy-workspace-view', source, view_cwd, str(command), output_names_csv, writable_output,
        ))
        # The final user is evaluated by the outer guest shell, while every
        # controller-derived/user-derived payload remains a quoted positional
        # argument to the root-owned namespace script.
        prefix = 'view_user=$(id -un); exec /usr/bin/sudo -n /usr/bin/unshare --mount --propagation private --fork /bin/bash -c '
        return prefix + shlex.quote(inner) + ' ' + argv + ' "$view_user"'

    def _project_workspace_view_command_ephemeral(
        self, *, source: str, view_cwd: str, command: str, policy: dict[str, Any],
    ) -> str:
        """Legacy one-command project view retained for focused compatibility tests."""
        user_command_trampoline = shlex.quote(self._user_command_trampoline())
        own = str(policy.get('writable_folder') or '')
        if not CHAT_OUTPUT_DIR_RE.fullmatch(own):
            raise ValueError('Invalid writable Project/Chat directory name')
        ancestor_paths: list[str] = []
        for row in policy.get('ancestors') or ():
            if not isinstance(row, dict):
                raise ValueError('Invalid ancestor project record')
            nested = str(row.get('nested_path') or '')
            parts = PurePosixPath(nested).parts
            if not parts or any(not CHAT_OUTPUT_DIR_RE.fullmatch(part) for part in parts):
                raise ValueError('Invalid live ancestor project path')
            normalized = '/'.join(parts)
            if normalized not in ancestor_paths:
                ancestor_paths.append(normalized)
        if len(ancestor_paths) > 100:
            raise ValueError('Too many live ancestor projects')
        ancestor_csv = ','.join(ancestor_paths)
        access_names: list[str] = []
        for row in policy.get('access_projects') or ():
            if not isinstance(row, dict):
                raise ValueError('Invalid Project Access record')
            if not bool(row.get('direct_mount')):
                continue
            name = str(row.get('folder') or '')
            if not CHAT_OUTPUT_DIR_RE.fullmatch(name) or name == own:
                raise ValueError('Invalid Project Access directory name')
            if name not in access_names:
                access_names.append(name)
        if len(access_names) > 100:
            raise ValueError('Too many Project Access sources')
        access_csv = ','.join(access_names)
        inner = f'''set -euo pipefail
source_path=$1
view_cwd=$2
view_command=$3
own_name=$4
ancestor_paths=$5
access_names=$6
view_user=$7
view_failure() {{
  printf '[HARNESSY_WORKSPACE_VIEW:%s] %s\\n' "$1" "$2" >&2
  exit 72
}}
trap 'view_failure MOUNT_PROJECTION_FAILED "HarnessyXO could not prepare the isolated project view"' ERR
case "$source_path" in
  {FILES_BACKING_GUEST_PATH}/Project-*) ;;
  *) view_failure INVALID_BACKING_PATH "HarnessyXO rejected an invalid project backing path" ;;
esac
[ "${{source_path##*/}}" = "$own_name" ] || view_failure INVALID_BACKING_PATH "HarnessyXO project identity does not match its backing path"
[ -d "$source_path" ] || view_failure ACTIVE_ROOT_UNAVAILABLE "HarnessyXO project directory is unavailable"
if ! /usr/bin/mountpoint -q {FILES_BACKING_GUEST_PATH} || ! /usr/bin/mountpoint -q {PRIVATE_WORKTREES_GUEST_PATH}; then
  view_failure BACKING_MOUNTS_UNAVAILABLE "HarnessyXO workspace backing mounts are unavailable; restart the environment to reconcile its configuration"
fi
[ -d {FILES_BACKING_GUEST_PATH}/References ] || view_failure ACTIVE_ROOT_UNAVAILABLE "HarnessyXO References directory is unavailable"
/usr/bin/mkdir -p {WORKSPACE_VIEW_GUEST_PATH}
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs {WORKSPACE_VIEW_GUEST_PATH}
/usr/bin/mkdir -p {WORKSPACE_VIEW_GUEST_PATH}/Files/{own} {WORKSPACE_VIEW_GUEST_PATH}/Files/References
/usr/bin/mount --bind "$source_path" {WORKSPACE_VIEW_GUEST_PATH}/Files/{own}
{"/usr/bin/mount -o remount,bind,ro " + WORKSPACE_VIEW_GUEST_PATH + "/Files/" + own if self.config.files_mode == "readonly" else ":"}
/usr/bin/mount --bind {FILES_BACKING_GUEST_PATH}/References {WORKSPACE_VIEW_GUEST_PATH}/Files/References
/usr/bin/mount -o remount,bind,ro {WORKSPACE_VIEW_GUEST_PATH}/Files/References
if [ -n "$ancestor_paths" ]; then
  old_ifs=$IFS
  IFS=','
  for nested in $ancestor_paths; do
    IFS=$old_ifs
    case "$nested" in
      Project-*) ;;
      *) view_failure INVALID_OUTPUT_DIRECTORY "HarnessyXO rejected an invalid live ancestor path" ;;
    esac
    ancestor_name=${{nested##*/}}
    ancestor_source={FILES_BACKING_GUEST_PATH}/$ancestor_name
    ancestor_target={WORKSPACE_VIEW_GUEST_PATH}/Files/{own}/$nested
    [ -d "$ancestor_source" ] && [ ! -L "$ancestor_source" ] || view_failure OUTPUT_DIRECTORY_UNAVAILABLE "A live ancestor project is unavailable"
    [ -d "$ancestor_target" ] && [ ! -L "$ancestor_target" ] || view_failure INVALID_OUTPUT_DIRECTORY "A live ancestor mount point is unavailable"
    /usr/bin/mount --bind "$ancestor_source" "$ancestor_target"
    IFS=','
  done
  IFS=$old_ifs
  IFS=','
  for nested in $ancestor_paths; do
    /usr/bin/mount -o remount,bind,ro {WORKSPACE_VIEW_GUEST_PATH}/Files/{own}/$nested
  done
  IFS=$old_ifs
fi
if [ -n "$access_names" ]; then
  old_ifs=$IFS
  IFS=','
  for access_name in $access_names; do
    IFS=$old_ifs
    case "$access_name" in
      Project-????) ;;
      *) view_failure INVALID_OUTPUT_DIRECTORY "HarnessyXO rejected an invalid Project Access path" ;;
    esac
    access_source={FILES_BACKING_GUEST_PATH}/$access_name
    access_target={WORKSPACE_VIEW_GUEST_PATH}/Files/$access_name
    [ -d "$access_source" ] && [ ! -L "$access_source" ] || view_failure OUTPUT_DIRECTORY_UNAVAILABLE "A Project Access source is unavailable"
    /usr/bin/mkdir -p "$access_target"
    [ ! -L "$access_target" ] || view_failure INVALID_OUTPUT_DIRECTORY "A Project Access mount point is unavailable"
    /usr/bin/mount --bind "$access_source" "$access_target"
    /usr/bin/mount -o remount,bind,ro "$access_target"
    IFS=','
  done
  IFS=$old_ifs
fi
/usr/bin/chmod 0555 {WORKSPACE_VIEW_GUEST_PATH} {WORKSPACE_VIEW_GUEST_PATH}/Files
/usr/bin/umount -l {FILES_BACKING_GUEST_PATH} 2>/dev/null || true
/usr/bin/umount -l {PRIVATE_WORKTREES_GUEST_PATH} 2>/dev/null || true
/usr/bin/umount -l {REFERENCES_BACKING_GUEST_PATH} 2>/dev/null || true
if /usr/bin/mountpoint -q {FILES_BACKING_GUEST_PATH} || /usr/bin/mountpoint -q {PRIVATE_WORKTREES_GUEST_PATH} || /usr/bin/mountpoint -q {REFERENCES_BACKING_GUEST_PATH}; then
  view_failure RAW_MOUNT_DETACH_FAILED "HarnessyXO could not detach private workspace backing mounts"
fi
case "$view_cwd" in
  {WORKSPACE_VIEW_GUEST_PATH}/Files/{own}|{WORKSPACE_VIEW_GUEST_PATH}/Files/{own}/*) ;;
  *) view_failure INVALID_WORKSPACE_CWD "HarnessyXO rejected a working directory outside the owned project" ;;
esac
cd "$view_cwd" || view_failure INVALID_WORKSPACE_CWD "HarnessyXO project working directory is unavailable"
trap - ERR
set +e
/usr/bin/sudo -n -u "$view_user" -- /bin/bash -lc {user_command_trampoline} \
  harnessy-project-command "$view_cwd" "$view_command"
rc=$?
exit $rc
'''
        argv = ' '.join(shlex.quote(value) for value in (
            'harnessy-project-view', source, view_cwd, str(command), own, ancestor_csv, access_csv,
        ))
        prefix = (
            'view_user=$(id -un); exec /usr/bin/sudo -n /usr/bin/unshare '
            '--mount --propagation private --fork /bin/bash -c '
        )
        return prefix + shlex.quote(inner) + ' ' + argv + ' "$view_user"'

    def _project_workspace_view_command(
        self, *, source: str, view_cwd: str, command: str, policy: dict[str, Any],
    ) -> str:
        """Build a VM-lifetime, project-isolated mount namespace command.

        A root-owned keeper retains the project's mount and PID namespaces so
        mounts made by one model Tool call remain present for later calls.  The
        keeper is signed with the host directory inodes for the owned project,
        References, and each ancestor.  Rewind/root replacement therefore
        recreates the namespace rather than pinning an obsolete directory.
        """
        own = str(policy.get('writable_folder') or '')
        if not CHAT_OUTPUT_DIR_RE.fullmatch(own):
            raise ValueError('Invalid writable Project/Chat directory name')

        ancestor_paths: list[str] = []
        identity_paths: list[tuple[str, str]] = [
            ('project', str(policy.get('project_root') or '')),
            ('references', str(policy.get('references_root') or '')),
        ]
        for row in policy.get('ancestors') or ():
            if not isinstance(row, dict):
                raise ValueError('Invalid ancestor project record')
            nested = str(row.get('nested_path') or '')
            parts = PurePosixPath(nested).parts
            if not parts or any(not CHAT_OUTPUT_DIR_RE.fullmatch(part) for part in parts):
                raise ValueError('Invalid live ancestor project path')
            normalized = '/'.join(parts)
            if normalized not in ancestor_paths:
                ancestor_paths.append(normalized)
                identity_paths.append((normalized, str(row.get('host_path') or '')))
        if len(ancestor_paths) > 100:
            raise ValueError('Too many live ancestor projects')
        ancestor_csv = ','.join(ancestor_paths)

        access_names: list[str] = []
        for row in policy.get('access_projects') or ():
            if not isinstance(row, dict):
                raise ValueError('Invalid Project Access record')
            if not bool(row.get('direct_mount')):
                continue
            name = str(row.get('folder') or '')
            if not CHAT_OUTPUT_DIR_RE.fullmatch(name) or name == own:
                raise ValueError('Invalid Project Access directory name')
            if name not in access_names:
                access_names.append(name)
                identity_paths.append((f'access:{name}', str(row.get('host_path') or '')))
        if len(access_names) > 100:
            raise ValueError('Too many Project Access sources')
        access_csv = ','.join(access_names)

        host_identities: list[tuple[str, int, int]] = []
        for label, raw_path in identity_paths:
            try:
                stat = self._bridge_host_path(Path(raw_path)).stat()
                host_identities.append((label, int(stat.st_dev), int(stat.st_ino)))
            except (OSError, ValueError):
                host_identities.append((label, -1, -1))
        signature_payload = {
            'revision': WORKSPACE_VIEW_REVISION,
            'environment_id': self.config.id,
            'files_mode': self.config.files_mode,
            'source': source,
            'own': own,
            'ancestors': ancestor_paths,
            'access_projects': access_names,
            'host_identities': host_identities,
        }
        view_signature = hashlib.sha256(
            json.dumps(signature_payload, sort_keys=True, separators=(',', ':')).encode('utf-8')
        ).hexdigest()
        key_digest = hashlib.sha256(
            f'{self.environment_root.resolve()}\0{own}'.encode('utf-8')
        ).hexdigest()[:16]
        state_key = f'{own.lower()}-{key_digest}'

        keeper = f'''set -euo pipefail
source_path=$1
own_name=$2
ancestor_paths=$3
access_names=$4
state_dir=$5
view_signature=$6
view_token=$7
view_failure() {{
  failure_line=$(printf '[HARNESSY_WORKSPACE_VIEW:%s] %s' "$1" "$2")
  printf '%s\n' "$failure_line" >"$state_dir/start.failure" 2>/dev/null || true
  printf '%s\n' "$failure_line" >&2
  exit 72
}}
trap 'view_failure MOUNT_PROJECTION_FAILED "HarnessyXO could not prepare the persistent project view"' ERR
case "$source_path" in
  {FILES_BACKING_GUEST_PATH}/Project-*) ;;
  *) view_failure INVALID_BACKING_PATH "HarnessyXO rejected an invalid project backing path" ;;
esac
[ "${{source_path##*/}}" = "$own_name" ] || view_failure INVALID_BACKING_PATH "HarnessyXO project identity does not match its backing path"
[ -d "$source_path" ] || view_failure ACTIVE_ROOT_UNAVAILABLE "HarnessyXO project directory is unavailable"
if ! /usr/bin/mountpoint -q {FILES_BACKING_GUEST_PATH} || ! /usr/bin/mountpoint -q {PRIVATE_WORKTREES_GUEST_PATH}; then
  view_failure BACKING_MOUNTS_UNAVAILABLE "HarnessyXO workspace backing mounts are unavailable; restart the environment to reconcile its configuration"
fi
[ -d {FILES_BACKING_GUEST_PATH}/References ] || view_failure ACTIVE_ROOT_UNAVAILABLE "HarnessyXO References directory is unavailable"
/usr/bin/mkdir -p {WORKSPACE_VIEW_GUEST_PATH}
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs {WORKSPACE_VIEW_GUEST_PATH}
/usr/bin/mkdir -p {WORKSPACE_VIEW_GUEST_PATH}/Files/{own} {WORKSPACE_VIEW_GUEST_PATH}/Files/References
/usr/bin/mount --bind "$source_path" {WORKSPACE_VIEW_GUEST_PATH}/Files/{own}
{"/usr/bin/mount -o remount,bind,ro " + WORKSPACE_VIEW_GUEST_PATH + "/Files/" + own if self.config.files_mode == "readonly" else ":"}
/usr/bin/mount --bind {FILES_BACKING_GUEST_PATH}/References {WORKSPACE_VIEW_GUEST_PATH}/Files/References
/usr/bin/mount -o remount,bind,ro {WORKSPACE_VIEW_GUEST_PATH}/Files/References
if [ -n "$ancestor_paths" ]; then
  old_ifs=$IFS
  IFS=','
  for nested in $ancestor_paths; do
    IFS=$old_ifs
    case "$nested" in
      Project-*) ;;
      *) view_failure INVALID_OUTPUT_DIRECTORY "HarnessyXO rejected an invalid live ancestor path" ;;
    esac
    ancestor_name=${{nested##*/}}
    ancestor_source={FILES_BACKING_GUEST_PATH}/$ancestor_name
    ancestor_target={WORKSPACE_VIEW_GUEST_PATH}/Files/{own}/$nested
    [ -d "$ancestor_source" ] && [ ! -L "$ancestor_source" ] || view_failure OUTPUT_DIRECTORY_UNAVAILABLE "A live ancestor project is unavailable"
    [ -d "$ancestor_target" ] && [ ! -L "$ancestor_target" ] || view_failure INVALID_OUTPUT_DIRECTORY "A live ancestor mount point is unavailable"
    /usr/bin/mount --bind "$ancestor_source" "$ancestor_target"
    IFS=','
  done
  IFS=$old_ifs
  IFS=','
  for nested in $ancestor_paths; do
    /usr/bin/mount -o remount,bind,ro {WORKSPACE_VIEW_GUEST_PATH}/Files/{own}/$nested
  done
  IFS=$old_ifs
fi
if [ -n "$access_names" ]; then
  old_ifs=$IFS
  IFS=','
  for access_name in $access_names; do
    IFS=$old_ifs
    case "$access_name" in
      Project-????) ;;
      *) view_failure INVALID_OUTPUT_DIRECTORY "HarnessyXO rejected an invalid Project Access path" ;;
    esac
    access_source={FILES_BACKING_GUEST_PATH}/$access_name
    access_target={WORKSPACE_VIEW_GUEST_PATH}/Files/$access_name
    [ -d "$access_source" ] && [ ! -L "$access_source" ] || view_failure OUTPUT_DIRECTORY_UNAVAILABLE "A Project Access source is unavailable"
    /usr/bin/mkdir -p "$access_target"
    [ ! -L "$access_target" ] || view_failure INVALID_OUTPUT_DIRECTORY "A Project Access mount point is unavailable"
    /usr/bin/mount --bind "$access_source" "$access_target"
    /usr/bin/mount -o remount,bind,ro "$access_target"
    IFS=','
  done
  IFS=$old_ifs
fi
/usr/bin/chmod 0555 {WORKSPACE_VIEW_GUEST_PATH} {WORKSPACE_VIEW_GUEST_PATH}/Files
/usr/bin/umount -l {FILES_BACKING_GUEST_PATH} 2>/dev/null || true
/usr/bin/umount -l {PRIVATE_WORKTREES_GUEST_PATH} 2>/dev/null || true
/usr/bin/umount -l {REFERENCES_BACKING_GUEST_PATH} 2>/dev/null || true
if /usr/bin/mountpoint -q {FILES_BACKING_GUEST_PATH} || /usr/bin/mountpoint -q {PRIVATE_WORKTREES_GUEST_PATH} || /usr/bin/mountpoint -q {REFERENCES_BACKING_GUEST_PATH}; then
  view_failure RAW_MOUNT_DETACH_FAILED "HarnessyXO could not detach private workspace backing mounts"
fi
printf '%s\n' "$view_token" >"$state_dir/ready"
# Hide all controller namespace records from commands inside this project.
/usr/bin/mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs {PERSISTENT_VIEW_STATE_GUEST_PATH}
trap - ERR
exec -a "harnessy-project-view-$view_token" /bin/sleep infinity
'''

        view_probe = f'''set -e
probe_failure() {{
  printf '[HARNESSY_WORKSPACE_PROBE:%s] %s\n' "$1" "$2" >&2
  exit 1
}}
/usr/bin/mountpoint -q {WORKSPACE_VIEW_GUEST_PATH}/Files/$1 \
  || probe_failure OWN_PROJECT_MISSING "The owned project mount is unavailable"
/usr/bin/mountpoint -q {WORKSPACE_VIEW_GUEST_PATH}/Files/References \
  || probe_failure REFERENCES_MISSING "The References mount is unavailable"
! /usr/bin/mountpoint -q {FILES_BACKING_GUEST_PATH} \
  || probe_failure FILES_BACKING_EXPOSED "The private Files backing mount is still exposed"
! /usr/bin/mountpoint -q {PRIVATE_WORKTREES_GUEST_PATH} \
  || probe_failure WORKTREES_BACKING_EXPOSED "The private worktree backing mount is still exposed"
! /usr/bin/mountpoint -q {REFERENCES_BACKING_GUEST_PATH} \
  || probe_failure FILES_BACKING_EXPOSED "The private References source mount is still exposed"
if [ -n "$2" ]; then
  old_ifs=$IFS
  IFS=','
  for nested in $2; do
    /usr/bin/mountpoint -q {WORKSPACE_VIEW_GUEST_PATH}/Files/$1/$nested \
      || probe_failure ANCESTOR_MISSING "A live parent/ancestor mount is unavailable: $nested"
  done
  IFS=$old_ifs
fi
if [ -n "$3" ]; then
  old_ifs=$IFS
  IFS=','
  for access_name in $3; do
    /usr/bin/mountpoint -q {WORKSPACE_VIEW_GUEST_PATH}/Files/$access_name \
      || probe_failure ACCESS_PROJECT_MISSING "A Project Access mount is unavailable: $access_name"
  done
  IFS=$old_ifs
fi
'''

        supervisor = f'''set -euo pipefail
source_path=$1
view_cwd=$2
view_command=$3
own_name=$4
ancestor_paths=$5
access_names=$6
state_key=$7
view_signature=$8
keeper_script=$9
view_probe_script=${{10}}
user_command_script=${{11}}
view_user=${{12}}
view_failure() {{
  printf '[HARNESSY_WORKSPACE_VIEW:%s] %s\n' "$1" "$2" >&2
  exit 72
}}
printf '%s' "$state_key" | /usr/bin/grep -Eq '^project-[a-z0-9]{{4}}-[a-f0-9]{{16}}$' \
  || view_failure INVALID_BACKING_PATH "HarnessyXO rejected an invalid persistent project identity"
printf '%s' "$view_signature" | /usr/bin/grep -Eq '^[a-f0-9]{{64}}$' \
  || view_failure INVALID_BACKING_PATH "HarnessyXO rejected an invalid project view signature"
state_root={PERSISTENT_VIEW_STATE_GUEST_PATH}
state_dir="$state_root/$state_key"
/usr/bin/mkdir -p "$state_dir"
/usr/bin/chmod 0700 "$state_root" "$state_dir"
exec 9>"$state_dir/lock"
/usr/bin/flock -x 9

keeper_identity_valid() {{
  [ -s "$state_dir/pid" ] && [ -s "$state_dir/token" ] && [ -s "$state_dir/signature" ] || return 1
  keeper_pid=$(cat "$state_dir/pid")
  view_token=$(cat "$state_dir/token")
  recorded_signature=$(cat "$state_dir/signature")
  case "$keeper_pid" in *[!0-9]*|'') return 1 ;; esac
  case "$view_token" in *[!a-zA-Z0-9._-]*|'') return 1 ;; esac
  [ "$recorded_signature" = "$view_signature" ] || return 1
  /bin/kill -0 "$keeper_pid" 2>/dev/null || return 1
  [ -e "/proc/$keeper_pid/ns/mnt" ] && [ -e "/proc/$keeper_pid/ns/pid" ] || return 1
  first_arg=$(tr '\\000' '\\n' <"/proc/$keeper_pid/cmdline" | /usr/bin/head -n 1)
  [ "$first_arg" = "harnessy-project-view-$view_token" ]
}}

stop_recorded_keeper() {{
  if [ -s "$state_dir/pid" ] && [ -s "$state_dir/token" ]; then
    old_pid=$(cat "$state_dir/pid")
    old_token=$(cat "$state_dir/token")
    case "$old_pid" in *[!0-9]*|'') old_pid='' ;; esac
    if [ -n "$old_pid" ] && [ -r "/proc/$old_pid/cmdline" ]; then
      old_first=$(tr '\\000' '\\n' <"/proc/$old_pid/cmdline" | /usr/bin/head -n 1)
      if [ "$old_first" = "harnessy-project-view-$old_token" ]; then
        /bin/kill -TERM "$old_pid" 2>/dev/null || true
        for _wait in $(/usr/bin/seq 1 40); do
          /bin/kill -0 "$old_pid" 2>/dev/null || break
          /bin/sleep 0.05
        done
        /bin/kill -KILL "$old_pid" 2>/dev/null || true
      fi
    fi
  fi
  /bin/rm -f "$state_dir/pid" "$state_dir/token" "$state_dir/signature" \
    "$state_dir/ready" "$state_dir/start.failure"
}}

find_keeper_for_token() {{
  expected_token=$1
  for proc_path in /proc/[0-9]*; do
    [ -r "$proc_path/cmdline" ] || continue
    candidate_first=$(tr '\\000' '\\n' <"$proc_path/cmdline" 2>/dev/null | /usr/bin/head -n 1 || true)
    if [ "$candidate_first" = "harnessy-project-view-$expected_token" ]; then
      printf '%s\n' "${{proc_path##*/}}"
      return 0
    fi
  done
  return 1
}}

start_keeper() {{
  /bin/rm -f "$state_dir/ready" "$state_dir/start.failure" "$state_dir/start.stderr" \
    "$state_dir/pid" "$state_dir/token" "$state_dir/signature"
  view_token="$view_signature-$$-$(/bin/date +%s%N)"
  /usr/bin/setsid --fork /usr/bin/unshare --mount --pid --fork --mount-proc --propagation private \
    /bin/bash -c "$keeper_script" harnessy-project-view-keeper \
    "$source_path" "$own_name" "$ancestor_paths" "$access_names" "$state_dir" "$view_signature" "$view_token" \
    </dev/null >"$state_dir/start.stdout" 2>"$state_dir/start.stderr"
  keeper_pid=''
  for _wait in $(/usr/bin/seq 1 160); do
    if [ "$(cat "$state_dir/ready" 2>/dev/null || true)" = "$view_token" ]; then
      keeper_pid=$(find_keeper_for_token "$view_token" || true)
      if [ -n "$keeper_pid" ]; then
        break
      fi
    fi
    [ ! -s "$state_dir/start.failure" ] || break
    /bin/sleep 0.05
  done
  if [ -z "$keeper_pid" ]; then
    if [ -s "$state_dir/start.failure" ]; then
      cat "$state_dir/start.failure" >&2
      exit 72
    fi
    tail -c 2000 "$state_dir/start.stderr" >&2 2>/dev/null || true
    view_failure PERSISTENT_VIEW_START_FAILED "HarnessyXO could not start the persistent project mount namespace"
  fi
  printf '%s\n' "$keeper_pid" >"$state_dir/pid"
  printf '%s\n' "$view_token" >"$state_dir/token"
  printf '%s\n' "$view_signature" >"$state_dir/signature"
}}

keeper_view_valid() {{
  /bin/rm -f "$state_dir/probe.stderr"
  # The keeper owns both mount and PID namespaces, and its /proc mount belongs
  # to that PID namespace. Enter both so mountpoint(1) can read the correct
  # /proc/self/mountinfo. Entering only --mount makes nested same-filesystem
  # ancestor binds look absent even though the bind succeeded.
  if /usr/bin/nsenter --target "$keeper_pid" --mount --pid -- \
    /bin/bash -c "$view_probe_script" harnessy-project-view-probe "$own_name" "$ancestor_paths" "$access_names" \
    >/dev/null 2>"$state_dir/probe.stderr"; then
    /bin/rm -f "$state_dir/probe.stderr"
    return 0
  fi
  return 1
}}

wait_for_keeper_view() {{
  for _probe_wait in $(/usr/bin/seq 1 4); do
    if keeper_identity_valid && keeper_view_valid; then
      return 0
    fi
    /bin/sleep 0.05
  done
  return 1
}}

keeper_ready=0
if keeper_identity_valid && wait_for_keeper_view; then
  keeper_ready=1
fi
if [ "$keeper_ready" != 1 ]; then
  # The model command has not run yet, so rebuilding this isolated namespace is
  # safe.  A newly-created child may briefly race the host/guest mount view;
  # repair it here instead of requiring a whole-VM restart from the user.
  for _repair_attempt in $(/usr/bin/seq 1 3); do
    stop_recorded_keeper
    start_keeper
    if wait_for_keeper_view; then
      keeper_ready=1
      break
    fi
  done
fi
if [ "$keeper_ready" != 1 ]; then
  if ! keeper_identity_valid; then
    view_failure PERSISTENT_VIEW_UNAVAILABLE "HarnessyXO could not establish the persistent project namespace after 3 automatic repair attempts"
  fi
  if ! keeper_view_valid; then
    tail -c 2000 "$state_dir/probe.stderr" >&2 2>/dev/null || true
    view_failure PERSISTENT_VIEW_UNAVAILABLE "HarnessyXO persistent project namespace failed its isolation check after 3 automatic repair attempts"
  fi
  view_failure PERSISTENT_VIEW_UNAVAILABLE "HarnessyXO persistent project namespace remained unavailable after 3 automatic repair attempts"
fi

case "$view_cwd" in
  {WORKSPACE_VIEW_GUEST_PATH}/Files/{own}|{WORKSPACE_VIEW_GUEST_PATH}/Files/{own}/*) ;;
  *) view_failure INVALID_WORKSPACE_CWD "HarnessyXO rejected a working directory outside the owned project" ;;
esac
/usr/bin/flock -u 9
set +e
/usr/bin/nsenter --target "$keeper_pid" --mount --pid -- \
  /usr/bin/sudo -n -u "$view_user" -- /bin/bash -lc "$user_command_script" \
  harnessy-project-command "$view_cwd" "$view_command"
rc=$?
set -e
exit $rc
'''
        argv = ' '.join(shlex.quote(value) for value in (
            'harnessy-project-view-supervisor', source, view_cwd, str(command), own,
            ancestor_csv, access_csv, state_key, view_signature, keeper, view_probe,
            self._user_command_trampoline(),
        ))
        prefix = 'view_user=$(id -un); exec /usr/bin/sudo -n /bin/bash -c '
        return prefix + shlex.quote(supervisor) + ' ' + argv + ' "$view_user"'

    def _requested_vm_config(self) -> dict[str, Any]:
        # Keep only the requested machine facts, never mounts, tool selections,
        # template text, guest commands or user-provided labels.
        return {
            'architecture': self.config.architecture,
            'vm_type': self._vm_type(),
            'cpus': self.config.cpu,
            'memory_mb': self.config.memory_mb,
            'disk_gb': self.config.disk_gb,
        }

    def _controller_diagnostic_fields(self) -> dict[str, Any]:
        from .manager import current_environment_operation

        fields: dict[str, Any] = {**current_environment_operation(), 'environment_id': self.config.id,
                                  'requested_vm_config': self._requested_vm_config()}
        # UUID metadata is immutable for a provider. Read it once through the
        # collector's nonblocking, regular-file-only, no-symlink opener. A FIFO
        # or redirected metadata path must not block or redirect VM operations.
        if getattr(self, '_diagnostic_workspace_id', None) is None:
            self._diagnostic_workspace_id = ''
            descriptor = None
            try:
                from harnessy.diagnostics.vm_logs import _open_regular

                descriptor = _open_regular(self.workspace_root / '.harnessy' / 'workspace.json')
                if os.fstat(descriptor).st_size <= 65536:
                    payload = os.read(descriptor, 65537)
                    data = json.loads(payload) if len(payload) <= 65536 else None
                    workspace_id = data.get('id') if isinstance(data, dict) else None
                    if isinstance(workspace_id, str) and re.fullmatch(r'[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', workspace_id):
                        self._diagnostic_workspace_id = workspace_id
            except Exception:
                pass
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        if self._diagnostic_workspace_id:
            fields['workspace_id'] = self._diagnostic_workspace_id
        return fields

    async def _preserve_vm_failure(
        self, *, reason: str, operation: str, command_id: str = '',
        controller_stdout: str = '', controller_stderr: str = '',
        host_resources: dict[str, Any] | None = None,
        command_started_at_epoch: float | None = None,
    ) -> None:
        """Preserve bounded scrubbed evidence before controller logs change.

        Collection is read-only with respect to the VM. Failure to write a
        diagnostics receipt must never change an authorized lifecycle action.
        """
        from harnessy.diagnostics.technical import technical_error_evidence

        fields = self._controller_diagnostic_fields()
        cancel_event = threading.Event()
        try:
            from harnessy.diagnostics.vm_logs import preserve_vm_failure

            if host_resources is None:
                host_resources = await self._collect_host_resources()
            receipt = await _bounded_diagnostic_io(
                preserve_vm_failure, self.workspace_root, reason=reason, operation=operation,
                environment_id=self.config.id, runtime_root=self.environment_root,
                controller_stdout=controller_stdout, controller_stderr=controller_stderr,
                command_id=command_id, operation_id=fields.get('operation_id', ''),
                requested_config=fields['requested_vm_config'],
                host_resources=host_resources,
                command_started_at_epoch=command_started_at_epoch,
                cancel_event=cancel_event, timeout=self.TIMEOUT_DIAGNOSTIC_PRESERVE,
            )
        except asyncio.CancelledError:
            cancel_event.set()
            raise
        except Exception as exc:
            cancel_event.set()
            evidence = technical_error_evidence(exc)
            if isinstance(exc, asyncio.TimeoutError):
                evidence['timeout_seconds'] = self.TIMEOUT_DIAGNOSTIC_PRESERVE
            log_event('runtime', 'vm_failure_evidence_unavailable', workspace=str(self.workspace_root),
                      provider='lima', preservation_reason=reason, controller_action=operation,
                      command_id=command_id, technical_error=evidence, **fields)
            return
        log_event('runtime', 'vm_failure_evidence_preserved', workspace=str(self.workspace_root),
                  provider='lima', preservation_reason=reason, controller_action=operation,
                  command_id=command_id, failure_receipt=receipt, **fields)

    async def _collect_host_resources(self) -> dict[str, Any]:
        # Capture at the lifecycle event, rather than treating an export made
        # hours later as evidence of launch-time resource availability.
        try:
            from harnessy.diagnostics.host_state import collect_resource_snapshot

            return await _bounded_diagnostic_io(collect_resource_snapshot, [self.workspace_root],
                                                timeout=self.TIMEOUT_DIAGNOSTIC_RESOURCES)
        except Exception as exc:
            from harnessy.diagnostics.technical import technical_error_evidence

            evidence = technical_error_evidence(exc)
            if isinstance(exc, asyncio.TimeoutError):
                evidence['timeout_seconds'] = self.TIMEOUT_DIAGNOSTIC_RESOURCES
            return {'schema_version': 1, 'capture_scope': 'current_host_resources',
                    'status': 'unavailable', 'collection_error': evidence,
                    **({'errno': evidence['errno']} if 'errno' in evidence else {})}

    async def _run(
        self, *args: str, timeout: float | None = 120.0, check: bool = False,
        input_text: str | None = None, diagnostic_probe: bool = False,
    ) -> tuple[int, str, str]:
        from harnessy.diagnostics.technical import technical_error_evidence

        binary = self._binary()
        cmd = [binary, '--tty=false', *args]
        command_id = uuid.uuid4().hex
        controller_action = self._controller_action(args)
        diagnostic_fields = self._controller_diagnostic_fields()
        trusted_control_plane = controller_action in {'start', 'create', 'stop', 'delete', 'factory-reset', 'restart'}
        if controller_action == 'start':
            await self._preserve_vm_failure(reason='before_start', operation='start', command_id=command_id)
        launch_resources = await self._collect_host_resources() if trusted_control_plane else {}
        started = time.monotonic()
        started_at_epoch = time.time()
        startup = {'last_boot_milestone': 'unknown', 'controller_failure_kind': 'unknown'}
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        buffer_limit = 128 * 1024 + 1 if diagnostic_probe else 512 * 1024
        capture_files: dict[str, Any] = {}
        capture_sizes = {'stdout': 0, 'stderr': 0}
        final_capture_sizes: dict[str, int] | None = None
        pending_progress = {'stdout': False, 'stderr': False}
        last_output_at: float | None = None

        def captured_sizes() -> dict[str, int]:
            nonlocal last_output_at
            sizes = final_capture_sizes if final_capture_sizes is not None else {
                name: os.fstat(handle.fileno()).st_size for name, handle in capture_files.items()}
            for name, size in sizes.items():
                if size > capture_sizes[name]:
                    last_output_at = time.monotonic()
                capture_sizes[name] = size
            return sizes

        def freeze_capture() -> None:
            nonlocal final_capture_sizes
            if final_capture_sizes is None:
                final_capture_sizes = dict(captured_sizes())

        def capture_observation(event: str, *, phase: str) -> None:
            captured_sizes()
            now = time.monotonic()
            log_event('runtime', event, workspace=str(self.workspace_root), provider='lima',
                      command_id=command_id, controller_action=controller_action,
                      controller_returncode=process.returncode,
                      controller_state='running' if process.returncode is None else 'exited',
                      completion_phase=phase, elapsed_seconds=max(0.0, now - started),
                      stdout_bytes=capture_sizes['stdout'], stderr_bytes=capture_sizes['stderr'],
                      last_output_age_seconds=None if last_output_at is None else max(0.0, now - last_output_at),
                      pending_progress=any(pending_progress.values()),
                      output_capture='anonymous_files', capture_scope='direct_controller_lifetime',
                      **({'post_exit_output_not_collected': True} if event == 'environment_command_output_handoff' else {}),
                      **diagnostic_fields)

        class CapturedReader:
            """Read an anonymous capture without changing its inherited write offset."""
            def __init__(reader, name: str) -> None:
                reader.name, reader.offset, reader.skipped_bytes = name, 0, 0

            async def read(reader, count: int) -> bytes:
                # Yield even with continuous output, so child-exit/timeout and
                # progress callbacks cannot be starved by a file backlog.
                await asyncio.sleep(0)
                while True:
                    if process.returncode is not None:
                        freeze_capture()
                    size = captured_sizes()[reader.name]
                    if size - reader.offset > buffer_limit:
                        skipped = size - reader.offset - buffer_limit
                        reader.offset += skipped
                        reader.skipped_bytes += skipped
                    if reader.offset < size:
                        chunk = os.pread(capture_files[reader.name].fileno(),
                                         min(count, size - reader.offset), reader.offset)
                        if chunk:
                            reader.offset += len(chunk)
                            return chunk
                    if final_capture_sizes is not None:
                        return b''
                    await asyncio.sleep(0.05)

        def controller_evidence() -> dict[str, Any]:
            if not trusted_control_plane:
                return {}
            return {
                'stdout': technical_error_evidence(bytes(stdout_buffer), source='controller_stdout'),
                'stderr': technical_error_evidence(bytes(stderr_buffer), source='controller_stderr'),
            }

        async def preserve_failure(reason: str, resources: dict[str, Any]) -> None:
            if trusted_control_plane:
                await self._preserve_vm_failure(
                    reason=reason, operation=controller_action, command_id=command_id,
                    controller_stdout=stdout_buffer.decode('utf-8', errors='replace'),
                    controller_stderr=stderr_buffer.decode('utf-8', errors='replace'),
                    host_resources=resources,
                    command_started_at_epoch=started_at_epoch,
                )

        native_limit = None
        for argument in args[1:]:
            match = re.fullmatch(r'--timeout=(\d+(?:\.\d+)?)s', argument)
            if match and len(argument) < 32:
                native_limit = float(match.group(1))
                break

        def observe_startup(line: str) -> None:
            if controller_action == 'start':
                milestone, failure = self._lima_startup_signal(line)
                if milestone:
                    startup['last_boot_milestone'] = milestone
                if failure:
                    startup['controller_failure_kind'] = failure

        def record_startup(outcome: str, returncode: int | None, elapsed: float) -> None:
            if controller_action != 'start':
                return
            controller_signal = None
            if returncode is not None and returncode < 0:
                controller_signal = {-2: 'SIGINT', -9: 'SIGKILL', -15: 'SIGTERM'}.get(returncode, 'other')
            log_event(
                'runtime', 'vm_startup_observation', workspace=str(self.workspace_root),
                provider='lima', command_id=command_id, controller_action='start', outcome=outcome,
                controller_returncode=returncode, controller_signal=controller_signal,
                elapsed_seconds=elapsed, app_limit_seconds=timeout,
                native_limit_seconds=native_limit, **startup, **diagnostic_fields,
            )
        log_event(
            'runtime', 'vm_controller_command', workspace=str(self.workspace_root),
            provider='lima', command_id=command_id, controller_action=controller_action,
            argv=cmd[1:], timeout_seconds=timeout, command_started_at_epoch=started_at_epoch,
            host_resources=launch_resources, **diagnostic_fields,
        )
        log_event(
            'runtime', 'environment_command_started', workspace=str(self.workspace_root),
            provider='lima', command_id=command_id, controller_action=controller_action,
            argv=cmd[1:], timeout_seconds=timeout, command_started_at_epoch=started_at_epoch,
            host_resources=launch_resources, **diagnostic_fields,
        )
        try:
            if trusted_control_plane:
                # A background hostagent can inherit the controller's handles.
                # Anonymous regular files let wait() observe the direct child
                # independently, and closing our handles cannot send SIGPIPE to
                # that descendant. Only a bounded in-memory tail is retained.
                for name in ('stdout', 'stderr'):
                    capture_files[name] = tempfile.TemporaryFile(mode='w+b')
                    os.fchmod(capture_files[name].fileno(), 0o600)
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_text is not None else None,
                stdout=capture_files.get('stdout', asyncio.subprocess.PIPE),
                stderr=capture_files.get('stderr', asyncio.subprocess.PIPE),
                env=self._host_env(),
            )
        except asyncio.CancelledError:
            for handle in capture_files.values():
                handle.close()
            raise
        except Exception as exc:
            for handle in capture_files.values():
                handle.close()
            elapsed = max(0.0, time.monotonic() - started)
            failure_resources = await self._collect_host_resources() if trusted_control_plane else {}
            log_event('runtime', 'environment_command_spawn_failed', workspace=str(self.workspace_root),
                      provider='lima', command_id=command_id, controller_action=controller_action,
                      elapsed_seconds=elapsed, technical_error=technical_error_evidence(exc),
                      host_resources=failure_resources, **diagnostic_fields)
            record_startup('controller_error', None, elapsed)
            await preserve_failure('controller_spawn_error', failure_resources)
            raise

        async def stop_controller() -> None:
            if process.returncode is not None:
                return
            try:
                process.terminate()
            except ProcessLookupError:
                return
            try:
                await asyncio.wait_for(process.wait(), timeout=self.TIMEOUT_CONTROLLER_STOP_GRACE)
                return
            except asyncio.TimeoutError:
                pass
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    return
                try:
                    await asyncio.wait_for(process.wait(), timeout=self.TIMEOUT_CONTROLLER_STOP_GRACE)
                except asyncio.TimeoutError:
                    # Never turn failure cleanup itself into another unbounded
                    # controller wait. The OS will reap the process on exit.
                    pass

        try:
            payload = input_text.encode('utf-8') if input_text is not None else None
            observer = None if diagnostic_probe else self._controller_output_callback
            if observer is None and not trusted_control_plane and not diagnostic_probe:
                communicate = process.communicate(payload)
                stdout_b, stderr_b = await asyncio.wait_for(communicate, timeout=timeout) if timeout else await communicate
            else:
                if payload is not None and process.stdin is not None:
                    process.stdin.write(payload)
                    await process.stdin.drain()
                    process.stdin.close()
                async def drain(stream, stream_name: str, buffer: bytearray) -> None:
                    if stream is None:
                        return
                    # Lima download/copy progress may redraw one terminal line with
                    # carriage returns rather than emitting newline-delimited logs.
                    # Read chunks so those updates reach the UI as they happen.
                    decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
                    pending = ''
                    discarding_line = False
                    logical_line_limit = 16 * 1024
                    observed_skipped = 0

                    async def publish(text: str) -> None:
                        if not text.strip():
                            return
                        observe_startup(text)
                        if observer is None:
                            return
                        try:
                            callback_result = observer(stream_name, text)
                            if asyncio.iscoroutine(callback_result):
                                await callback_result
                        except Exception as callback_exc:
                            log_event(
                                'runtime', 'environment_command_progress_callback_failed',
                                workspace=str(self.workspace_root), provider='lima',
                                command_id=command_id, error=f'{type(callback_exc).__name__}: {callback_exc}',
                                **diagnostic_fields,
                            )

                    while True:
                        chunk = await stream.read(4096)
                        skipped = stream.skipped_bytes if isinstance(stream, CapturedReader) else 0
                        if skipped > observed_skipped:
                            # A bounded tail may start in a UTF-8 sequence or
                            # logical line; never classify that partial line.
                            decoder.reset()
                            pending, discarding_line = '', True
                            observed_skipped = skipped
                        if not chunk:
                            pending += decoder.decode(b'', final=True)
                            if pending and not discarding_line:
                                await publish(pending)
                            pending_progress[stream_name] = False
                            return
                        buffer.extend(chunk)
                        if len(buffer) > buffer_limit:
                            del buffer[:len(buffer) - buffer_limit]
                        pending += decoder.decode(chunk)
                        parts = re.split(r'[\r\n]+', pending)
                        pending = parts.pop()
                        if discarding_line and parts:
                            # Ignore the tail of an oversized logical line;
                            # classification resumes only at its delimiter.
                            parts = parts[1:]
                            discarding_line = False
                        for part in parts:
                            if len(part) <= logical_line_limit:
                                await publish(part)
                        if len(pending) > logical_line_limit:
                            pending = ''
                            discarding_line = True
                        pending_progress[stream_name] = bool(pending or decoder.getstate()[0])

                async def stream_command() -> tuple[bytes, bytes]:
                    async def parent_exit() -> None:
                        await process.wait()
                        if trusted_control_plane:
                            freeze_capture()
                            capture_observation('environment_command_parent_exited', phase='collecting_output')

                    async def heartbeat() -> None:
                        while True:
                            await asyncio.sleep(self.CONTROLLER_HEARTBEAT_SECONDS)
                            capture_observation('environment_command_heartbeat',
                                phase='running_controller' if process.returncode is None else 'collecting_output')

                    readers = {name: CapturedReader(name) if trusted_control_plane else getattr(process, name)
                               for name in ('stdout', 'stderr')}
                    tasks = [asyncio.create_task(drain(readers['stdout'], 'stdout', stdout_buffer)),
                             asyncio.create_task(drain(readers['stderr'], 'stderr', stderr_buffer)),
                             asyncio.create_task(parent_exit())]
                    heartbeat_task = asyncio.create_task(heartbeat()) if trusted_control_plane else None
                    try:
                        await asyncio.gather(*tasks)
                        if trusted_control_plane:
                            capture_observation('environment_command_output_handoff', phase='collecting_output')
                    finally:
                        for task in (*tasks, heartbeat_task):
                            if task is not None and not task.done():
                                task.cancel()
                        await asyncio.gather(*(task for task in (*tasks, heartbeat_task) if task is not None),
                                             return_exceptions=True)
                    return bytes(stdout_buffer), bytes(stderr_buffer)

                streamed = stream_command()
                stdout_b, stderr_b = await asyncio.wait_for(streamed, timeout=timeout) if timeout else await streamed
        except asyncio.TimeoutError as exc:
            elapsed = max(0.0, time.monotonic() - started)
            observed_returncode = process.returncode
            await stop_controller()
            failure_resources = await self._collect_host_resources() if trusted_control_plane else {}
            log_event(
                'runtime', 'environment_command_timeout', workspace=str(self.workspace_root),
                provider='lima', command_id=command_id, controller_action=controller_action, argv=cmd[1:],
                timeout_seconds=timeout, elapsed_seconds=elapsed,
                controller_returncode=observed_returncode,
                controller_evidence=controller_evidence(), host_resources=failure_resources, **diagnostic_fields,
            )
            record_startup('controller_timeout', observed_returncode, elapsed)
            await preserve_failure('controller_timeout', failure_resources)
            if controller_action == 'start':
                await self._observe_startup_failure_state(command_id)
            raise asyncio.TimeoutError(f'Lima controller timed out: {" ".join(args)}') from exc
        except asyncio.CancelledError:
            elapsed = max(0.0, time.monotonic() - started)
            observed_returncode = process.returncode
            await asyncio.shield(stop_controller())
            failure_resources = await self._collect_host_resources() if trusted_control_plane else {}
            log_event(
                'runtime', 'environment_command_cancelled', workspace=str(self.workspace_root),
                provider='lima', command_id=command_id, controller_action=controller_action, argv=cmd[1:],
                elapsed_seconds=elapsed, controller_returncode=observed_returncode,
                controller_evidence=controller_evidence(), host_resources=failure_resources, **diagnostic_fields,
            )
            record_startup('cancelled', observed_returncode, elapsed)
            await asyncio.shield(preserve_failure('controller_cancelled', failure_resources))
            raise
        finally:
            for handle in capture_files.values():
                handle.close()
        stdout = stdout_b.decode(errors='replace')
        stderr = stderr_b.decode(errors='replace')
        elapsed = max(0.0, time.monotonic() - started)
        failure_resources = await self._collect_host_resources() if trusted_control_plane and process.returncode else {}
        log_event(
            'runtime', 'environment_command_finished', workspace=str(self.workspace_root),
            provider='lima', command_id=command_id, controller_action=controller_action, argv=cmd[1:],
            returncode=int(process.returncode or 0), elapsed_seconds=elapsed,
            stdout_chars=len(stdout), stderr_chars=len(stderr),
            controller_evidence=controller_evidence() if process.returncode else {},
            host_resources=failure_resources, **diagnostic_fields,
        )
        record_startup('controller_error' if process.returncode else 'completed', process.returncode, elapsed)
        if process.returncode:
            await preserve_failure('controller_error', failure_resources)
        if check and process.returncode:
            if controller_action == 'start':
                await self._observe_startup_failure_state(command_id)
            detail = (stderr or stdout).strip()[-4000:]
            raise RuntimeError(f'Lima controller failed ({process.returncode}): {detail}')
        return int(process.returncode or 0), stdout, stderr

    async def _backend_version(self) -> str:
        binary = self._binary()
        cached = _LIMA_VERSION_CACHE.get(binary)
        if cached:
            return cached
        loop = asyncio.get_running_loop()
        if _LIMA_VERSION_LOCK_LOOPS.get(binary) is not loop:
            _LIMA_VERSION_LOCKS[binary] = asyncio.Lock()
            _LIMA_VERSION_LOCK_LOOPS[binary] = loop
        async with _LIMA_VERSION_LOCKS[binary]:
            cached = _LIMA_VERSION_CACHE.get(binary)
            if cached:
                return cached
            try:
                rc, version_out, _ = await self._run('--version', timeout=5, check=False)
                value = version_out.strip().splitlines()[0] if rc == 0 and version_out.strip() else Path(binary).name
            except Exception:
                value = Path(binary).name
            _LIMA_VERSION_CACHE[binary] = value
            return value

    async def _instance_row_named(self, name: str) -> dict[str, Any] | None:
        try:
            rc, stdout, _ = await self._run('list', '--format', 'json', str(name), timeout=15)
        except LimaUnavailableError:
            raise
        if rc != 0 or not stdout.strip():
            return None
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError:
            return None
        if isinstance(data, list):
            return next((row for row in data if isinstance(row, dict) and row.get('name') == name), None)
        return data if isinstance(data, dict) and data.get('name') == name else None

    async def _instance_row(self) -> dict[str, Any] | None:
        return await self._instance_row_named(self.INSTANCE)

    def _expected_guard_hash(self) -> str:
        # Readiness covers the command projection as well as network policy.
        # Otherwise a running pre-private-worktree VM can retain an identical
        # network guard hash while lacking the mounts required by new tools.
        signature = self._network_guard_script() + '\n' + WORKSPACE_VIEW_REVISION + '\n' + self._provision_revision()
        return hashlib.sha256(signature.encode('utf-8')).hexdigest()

    def _read_readiness(self) -> dict[str, Any]:
        try:
            _validate_registry_path(self.readiness_path, self.workspace_root)
            raw = json.loads(self.readiness_path.read_text('utf-8'))
        except (OSError, ValueError):
            return {}
        return raw if isinstance(raw, dict) else {}

    def _write_readiness(
        self, *, ready: bool, phase: str, error: str = '', boot_id: str = '', guard_hash: str = '',
    ) -> None:
        _validate_registry_path(self.readiness_path, self.workspace_root)
        previous = self._read_readiness()
        self.state_root.mkdir(parents=True, exist_ok=True)
        payload = {
            'ready': bool(ready),
            'phase': str(phase or ''),
            'error': str(error or ''),
            'boot_id': str(boot_id or ''),
            'guard_hash': str(guard_hash or ''),
            'updated_at': time.time(),
        }
        tmp = self.readiness_path.with_suffix('.tmp')
        _validate_registry_path(tmp, self.workspace_root)
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        tmp.replace(self.readiness_path)
        self._runtime_guard_verified = bool(ready)
        self._runtime_boot_id = str(boot_id or '') if ready else ''
        cache_key = self._workspace_cache_key()
        if ready and self._runtime_boot_id:
            _RUNTIME_READY_BOOT[cache_key] = self._runtime_boot_id
        else:
            _RUNTIME_READY_BOOT.pop(cache_key, None)
        if ready and phase == 'ready' and (not previous.get('ready') or previous.get('boot_id') != boot_id):
            try:
                from harnessy.diagnostics.guest_logs import request_guest_capture
                request_guest_capture(self.workspace_root, self.config.id, 'vm_ready')
            except Exception:
                pass

    def _clear_readiness(self, phase: str = 'stopped') -> None:
        self._write_readiness(ready=False, phase=phase, error='', boot_id='')

    def _read_lifecycle(self) -> dict[str, Any]:
        try:
            _validate_registry_path(self.lifecycle_path, self.workspace_root)
            raw = json.loads(self.lifecycle_path.read_text('utf-8'))
        except (OSError, ValueError):
            return {}
        return raw if isinstance(raw, dict) else {}

    def _record_lifecycle(self, event: str) -> dict[str, Any]:
        _validate_registry_path(self.lifecycle_path, self.workspace_root)
        previous = self._read_lifecycle()
        try:
            generation = max(0, int(previous.get('generation') or 0)) + 1
        except (TypeError, ValueError):
            generation = 1
        payload = {
            'generation': generation,
            'event': str(event or 'unknown'),
            'updated_at': time.time(),
            **self._controller_diagnostic_fields(),
        }
        self.state_root.mkdir(parents=True, exist_ok=True)
        tmp = self.lifecycle_path.with_suffix('.tmp')
        _validate_registry_path(tmp, self.workspace_root)
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        tmp.replace(self.lifecycle_path)
        log_event(
            'runtime', 'vm_lifecycle_generation_changed', workspace=str(self.workspace_root), provider='lima',
            generation=generation, lifecycle_event=payload['event'],
            **self._controller_diagnostic_fields(),
        )
        return payload

    def runtime_identity(self) -> dict[str, Any]:
        readiness = self._read_readiness()
        lifecycle = self._read_lifecycle()
        phase = str(readiness.get('phase') or '')
        created: bool | None = True if (readiness or lifecycle) else None
        if phase in {'stopped', 'creating', 'starting_vm', 'not_created'}:
            running: bool | None = False
        elif readiness.get('ready') or phase.startswith(('running', 'installing', 'applying', 'verifying', 'waiting')):
            running = True
        else:
            running = None
        return {
            **super().runtime_identity(),
            'verified_guest': self._read_verified_guest(),
            'provider': 'lima',
            'vm_created': created,
            'vm_running': running,
            'vm_ready': bool(readiness.get('ready')) if readiness else None,
            'vm_generation': int(lifecycle.get('generation') or 0),
            'vm_lifecycle_event': str(lifecycle.get('event') or ('legacy_unknown' if not lifecycle else 'unknown')),
            'vm_lifecycle_updated_at': lifecycle.get('updated_at'),
            'vm_boot_id': str(readiness.get('boot_id') or self._runtime_boot_id or ''),
            'vm_readiness_updated_at': readiness.get('updated_at'),
        }

    async def _guest_boot_id(self) -> str:
        rc, stdout, _ = await self._run(
            'shell', self.INSTANCE, 'cat', '/proc/sys/kernel/random/boot_id',
            timeout=5, check=False,
        )
        return stdout.strip() if rc == 0 else ''

    async def _current_boot_is_verified(self) -> bool:
        state = self._read_readiness()
        if not state.get('ready'):
            return False
        expected = str(state.get('boot_id') or '')
        if not expected:
            return False
        if str(state.get('guard_hash') or '') != self._expected_guard_hash():
            # A workspace may already be running across a HarnessyXO upgrade. Do
            # not trust a readiness marker produced by an older guard revision;
            # repair/reapply the current policy for this same VM boot first.
            self._clear_readiness('guard_update_required')
            return False
        if not self._runtime_binding_matches():
            self._clear_readiness('workspace_binding_update_required')
            return False
        cache_key = self._workspace_cache_key()
        # A VM can be restarted outside HarnessyXO. A process-local cached boot
        # id must not override the guest's actual current boot indefinitely.
        try:
            actual = await self._guest_boot_id()
        except Exception:
            return False
        if actual and actual == expected:
            self._runtime_guard_verified = True
            self._runtime_boot_id = actual
            _RUNTIME_READY_BOOT[cache_key] = actual
            return True
        self._clear_readiness('running_not_ready')
        return False

    async def status(self) -> EnvironmentStatus:
        guest = {'guest_architecture': self.config.architecture, 'guest_os': get_preset(self.config.preset).guest_os,
                 'environment_id': self.config.id, 'environment_name': self.config.name}
        try:
            binary = self._binary()
        except LimaUnavailableError as exc:
            return EnvironmentStatus('backend_missing', 'lima', False, False, False, str(exc), ready=False, phase='backend_missing', error=str(exc), **guest)
        row = await self._instance_row()
        version = await self._backend_version()
        if not row:
            if (self.vm_root / self.INSTANCE).exists():
                raise RuntimeError('Lima did not report the selected VM although its files exist. Restore controller access before changing its data.')
            return EnvironmentStatus('not_created', 'lima', True, False, False, 'Workspace VM has not been created yet.', version, ready=False, phase='not_created', **guest)
        raw = str(row.get('status') or row.get('Status') or 'Stopped')
        running = raw.lower() == 'running'
        readiness = self._read_readiness() if running else {}
        ready = bool(running and readiness.get('ready'))
        phase = str(readiness.get('phase') or ('ready' if ready else ('running_not_ready' if running else raw.lower())))
        error = str(readiness.get('error') or '')
        state = 'ready' if ready else ('running_not_ready' if running else raw.lower())
        detail = error or ('Ready for workspace execution.' if ready else raw)
        return EnvironmentStatus(state, 'lima', True, True, running, detail, version, ready=ready, phase=phase, error=error, **guest)

    async def _ensure_host_prerequisites(self, *, progress=None, allow_install: bool = True) -> None:
        async def report(phase, message, **meta):
            await self._emit_progress(progress, phase, message, **meta)
        await ensure_host_prerequisites(self.config, vm_type=self._vm_type(), progress=report,
                                        allow_install=allow_install)

    def _preflight_acceleration_access(self) -> None:
        try:
            validate_native_kvm_access(self.config.architecture, self._vm_type())
        except HostKVMAccessError as exc:
            log_event('runtime', 'vm_host_preflight_failed', workspace=str(self.workspace_root),
                      provider='lima', error_code='KVM_ACCESS_DENIED', kvm_present=True,
                      kvm_accessible=False, kvm_device_group_active=getattr(exc, 'kvm_device_group_active', None),
                      errno=getattr(exc, 'errno', None),
                      **self._controller_diagnostic_fields())
            raise

    @_lifecycle_diagnostics('create')
    async def create(self, progress=None) -> EnvironmentStatus:
        current = await self.status()
        if current.created:
            return current
        self._preflight_acceleration_access()
        await self._ensure_host_prerequisites(progress=progress)
        await self._prepare_guest_image(progress=progress)
        self._write_template()
        self._write_readiness(ready=False, phase='creating')
        await self._emit_progress(
            progress, 'creating_vm', 'Creating workspace VM…',
            detail='Preparing the Lima instance and selected OS image…',
            stage_timeout_seconds=self.TIMEOUT_CREATE,
        )

        create_progress_state: dict[str, Any] = {}

        async def observe_create(_stream: str, line: str) -> None:
            update = self._lima_progress_update(line)
            if update is None:
                return
            detail, stage_percent = update
            if not self._controller_progress_should_emit(create_progress_state, detail, stage_percent):
                return
            await self._emit_progress(
                progress, 'creating_vm', 'Creating workspace VM…', detail=detail,
                stage_progress_percent=stage_percent, progress_source='lima',
                stage_timeout_seconds=self.TIMEOUT_CREATE,
            )

        previous_observer = self._controller_output_callback
        self._controller_output_callback = observe_create
        try:
            await self._run('create', '--name', self.INSTANCE, str(self.template_path), timeout=self.TIMEOUT_CREATE, check=True)
        finally:
            self._controller_output_callback = previous_observer
        self._write_runtime_binding()
        self._write_readiness(ready=False, phase='stopped')
        self._record_lifecycle('created')
        log_event('harnessy', 'vm_created', workspace=str(self.workspace_root), provider='lima', preset=self.config.preset)
        return await self.status()

    async def _prepare_guest_image(self, progress=None) -> None:
        if get_preset(self.config.preset).image_id != 'kali-2026.2':
            return
        from .test_catalog import KALI_IMAGES
        from .test_images import download_verified, extract_cloud_disk, finish_thread
        architecture, digest = KALI_IMAGES[self.config.architecture]
        images = self.environment_root / 'images'
        images.mkdir(parents=True, exist_ok=True)
        destination = images / 'kali.img'
        if destination.is_file():
            return
        await self._emit_progress(progress, 'creating_vm', 'Downloading the verified Kali cloud image…')
        archive = await download_verified(
            f'https://kali.download/cloud-images/kali-2026.2/kali-linux-2026.2-cloud-genericcloud-{architecture}.tar.xz',
            digest, images / 'kali.tar.xz', lambda _line: None)
        await finish_thread(extract_cloud_disk, archive, destination)

    async def _ensure_desktop(self, progress=None) -> None:
        if not self.config.desktop:
            return
        probe = 'test -f /var/lib/harnessy-desktop-ready && command -v startxfce4 >/dev/null && systemctl is-enabled lightdm >/dev/null'
        rc, _, _ = await self._run('shell', self.INSTANCE, '/bin/bash', '-lc', probe, timeout=15, check=False)
        if rc == 0:
            return
        if not self.config.network:
            raise RuntimeError('The selected graphical desktop is not installed and VM network access is off. Enable networking to install it first.')
        await self._emit_progress(progress, 'provisioning_packages', 'Installing the optional graphical desktop…',
                                  stage_timeout_seconds=self.TIMEOUT_PROVISION)
        apt = get_preset(self.config.preset).image.package_manager == 'apt'
        install = ("export DEBIAN_FRONTEND=noninteractive\napt-get update\n"
                   "echo 'lightdm shared/default-x-display-manager select lightdm' | debconf-set-selections\n"
                   "apt-get install -y --no-install-recommends xorg xfce4 xfce4-terminal lightdm dbus-x11"
                   if apt else 'dnf install -y @xfce-desktop-environment lightdm xorg-x11-server-Xorg')
        script = '''set -euo pipefail
desktop_user=$1
''' + install + '''
mkdir -p /etc/lightdm/lightdm.conf.d /var/lib
printf '[Seat:*]\\nautologin-user=%s\\nautologin-user-timeout=0\\nuser-session=xfce\\n' "$desktop_user" >/etc/lightdm/lightdm.conf.d/50-harnessy.conf
systemctl set-default graphical.target
systemctl enable lightdm
systemctl restart lightdm
touch /var/lib/harnessy-desktop-ready
'''
        command = 'desktop_user=$(id -un); exec sudo -n /bin/bash -c ' + shlex.quote(script) + ' harnessy-desktop "$desktop_user"'
        await self._run('shell', self.INSTANCE, '/bin/bash', '-lc', command,
                        timeout=self.TIMEOUT_PROVISION, check=True)

    def _read_verified_guest(self) -> dict[str, Any]:
        path = self.state_root / 'verified-guest.json'
        try:
            _validate_registry_path(path, self.workspace_root)
            value = json.loads(path.read_text('utf-8'))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    async def _record_verified_guest(self) -> None:
        """Cache fixed guest facts without entering or initializing a project."""
        script = '''import json, os, platform, shutil, sys
facts={"os":platform.system(),"kernel":platform.release(),"architecture":platform.machine(),
       "byte_order":sys.byteorder,"libc":list(platform.libc_ver()),"python":platform.python_version(),
       "tools":{name:bool(shutil.which(name)) for name in ("python3","pip3","git","gcc","g++","make","cmake","ninja","gdb","strace","tcpdump","btmon","bluetoothctl","rea")}}
try:
 facts["os_release"]={line.split("=",1)[0]:line.split("=",1)[1].strip().strip('"') for line in open("/etc/os-release") if "=" in line}
except OSError: pass
print(json.dumps(facts))
'''
        try:
            rc, out, _ = await self._run('shell', self.INSTANCE, 'python3', '-c', script, timeout=10, check=False)
            if rc:
                return
            value = json.loads(out.strip().splitlines()[-1])
            if not isinstance(value, dict):
                return
            value.update({'environment_id': self.config.id, 'boot_id': self._runtime_boot_id,
                          'observed_at': time.time(), 'observation': 'fixed_guest_probe'})
            path = self.state_root / 'verified-guest.json'
            _validate_registry_path(path, self.workspace_root)
            temporary = path.with_suffix('.tmp')
            _validate_registry_path(temporary, self.workspace_root)
            temporary.write_text(json.dumps(value, sort_keys=True) + '\n', encoding='utf-8')
            temporary.replace(path)
        except (RuntimeError, OSError, ValueError, asyncio.TimeoutError):
            # Missing optional metadata must not turn a verified VM boot into
            # a failed operation. No configured fact is labelled as measured.
            return

    def project_guest_root(self, active_root: Path, *, output_policy: dict[str, Any] | None = None) -> str:
        policy = output_policy or {}
        name = str(policy.get('writable_folder') or Path(active_root).name)
        if CHAT_OUTPUT_DIR_RE.fullmatch(name):
            return WORKSPACE_VIEW_GUEST_PATH + '/Files/' + name
        self._guest_source_for_active_root(active_root)  # validate the selected backing root
        return WORKSPACE_VIEW_GUEST_PATH

    async def _install_runtime_guard(self) -> None:
        # Repair older/broken guards in-place so a workspace created by a prior
        # HarnessyXO build does not require Factory Reset/Rebuild merely to become
        # usable again.
        guard = self._network_guard_script()
        service = self._network_guard_service()
        guard_b64 = base64.b64encode(guard.encode('utf-8')).decode('ascii')
        service_b64 = base64.b64encode(service.encode('utf-8')).decode('ascii')
        await self._run(
            'shell', self.INSTANCE, 'sudo', '/bin/sh', '-c',
            'systemctl kill --signal=KILL harnessy-network-guard.service >/dev/null 2>&1 || true; '
            "pkill -KILL -f '[h]arnessy-network-guard' >/dev/null 2>&1 || true",
            timeout=8, check=False,
        )
        await self._run(
            'shell', self.INSTANCE, 'sudo', '/bin/sh', '-c',
            f"printf %s {shlex.quote(guard_b64)} | base64 -d > /usr/local/sbin/harnessy-network-guard",
            timeout=8, check=True,
        )
        await self._run(
            'shell', self.INSTANCE, 'sudo', '/bin/sh', '-c',
            f"printf %s {shlex.quote(service_b64)} | base64 -d > /etc/systemd/system/harnessy-network-guard.service",
            timeout=8, check=True,
        )
        await self._run(
            'shell', self.INSTANCE, 'sudo', '/bin/sh', '-c',
            'chmod 0755 /usr/local/sbin/harnessy-network-guard && '
            'systemctl daemon-reload && '
            'systemctl reset-failed harnessy-network-guard.service >/dev/null 2>&1 || true; '
            'systemctl enable harnessy-network-guard.service >/dev/null',
            timeout=12, check=True,
        )

    @staticmethod
    def _parse_guard_service_state(text: str) -> dict[str, str]:
        state: dict[str, str] = {}
        for raw_line in str(text or '').splitlines():
            line = raw_line.strip()
            if '=' not in line:
                continue
            key, value = line.split('=', 1)
            if key in {
                'ActiveState', 'SubState', 'Result', 'ExecMainCode', 'ExecMainStatus',
                'ExecMainPID', 'StateChangeTimestampMonotonic', 'HARNESSY_GUARD_STAGE',
            }:
                state[key] = value.strip()
        return state

    async def _guard_service_state(self) -> dict[str, str]:
        # One short controller round-trip gets the systemd result and the guard's
        # own stage marker. The service writes stdout/stderr to journald, so no
        # guard child can inherit the limactl shell pipes used by this query.
        rc, stdout, stderr = await self._run(
            'shell', self.INSTANCE, 'sudo', '/bin/sh', '-c',
            "systemctl show harnessy-network-guard.service "
            "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,ExecMainPID,StateChangeTimestampMonotonic "
            "--no-pager 2>/dev/null; "
            "printf 'HARNESSY_GUARD_STAGE='; cat /run/harnessy-network-guard.stage 2>/dev/null || echo unknown",
            timeout=5, check=False,
        )
        if rc != 0 and not stdout.strip():
            raise RuntimeError((stderr or stdout).strip() or f'could not query isolation service (exit {rc})')
        return self._parse_guard_service_state(stdout)

    async def _queue_runtime_guard_service(self) -> None:
        # `--no-block` is deliberate: the controller command only queues the
        # systemd job and returns. HarnessyXO then observes completion with separate
        # bounded status calls, eliminating dependence on the guard process's
        # stdout/stderr lifetime.
        rc, stdout, stderr = await self._run(
            'shell', self.INSTANCE, 'sudo', '/bin/sh', '-c',
            "rm -f /run/harnessy-network-guard.ready; "
            "systemctl reset-failed harnessy-network-guard.service >/dev/null 2>&1 || true; "
            "systemctl restart --no-block harnessy-network-guard.service",
            timeout=8, check=False,
        )
        if rc != 0:
            raise RuntimeError((stderr or stdout).strip() or f'could not queue isolation service (exit {rc})')

    async def _wait_for_runtime_guard_service(self, *, timeout_seconds: float = 24.0) -> dict[str, str]:
        deadline = time.monotonic() + max(1.0, timeout_seconds)
        last: dict[str, str] = {}
        last_stage = ''
        while time.monotonic() < deadline:
            last = await self._guard_service_state()
            stage = str(last.get('HARNESSY_GUARD_STAGE') or 'unknown')
            if stage != last_stage:
                last_stage = stage
                log_event(
                    'runtime', 'vm_isolation_guard_stage', workspace=str(self.workspace_root),
                    provider='lima', guard_stage=stage, active_state=last.get('ActiveState', ''),
                    sub_state=last.get('SubState', ''),
                )
            active = str(last.get('ActiveState') or '').lower()
            sub = str(last.get('SubState') or '').lower()
            result = str(last.get('Result') or '').lower()
            exit_status = str(last.get('ExecMainStatus') or '')
            if active == 'failed' or result in {'failed', 'timeout', 'exit-code', 'signal', 'core-dump'}:
                raise RuntimeError(
                    'isolation service failed: '
                    f'ActiveState={active or "unknown"}, SubState={sub or "unknown"}, '
                    f'Result={result or "unknown"}, ExecMainStatus={exit_status or "unknown"}, stage={stage}'
                )
            # A successful oneshot with RemainAfterExit=yes settles at active/exited.
            if active == 'active' and sub == 'exited' and result in {'', 'success'} and exit_status in {'', '0'}:
                return last
            await asyncio.sleep(0.6)
        raise asyncio.TimeoutError(
            'isolation service did not complete before its readiness deadline; '
            f'last state: {json.dumps(last, sort_keys=True)}'
        )

    async def _guard_failure_detail(self) -> str:
        try:
            _rc, stdout, stderr = await self._run(
                'shell', self.INSTANCE, 'sudo', '/bin/sh', '-c',
                "printf 'guard-stage: '; cat /run/harnessy-network-guard.stage 2>/dev/null || echo unknown; "
                "printf '\nready-marker: '; cat /run/harnessy-network-guard.ready 2>/dev/null || echo missing; "
                "printf '\nservice-show:\n'; systemctl show harnessy-network-guard.service "
                "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,ExecMainPID,StateChangeTimestampMonotonic --no-pager 2>&1; "
                "printf '\nservice-status:\n'; systemctl status harnessy-network-guard.service --no-pager -l 2>&1 | tail -35; "
                "printf '\nservice-journal:\n'; journalctl -u harnessy-network-guard.service -n 45 --no-pager 2>&1 | tail -45; "
                "printf '\nguard-processes:\n'; ps -eo pid,ppid,stat,comm,args 2>/dev/null | grep '[h]arnessy-network-guard' | tail -20 || true",
                timeout=8, check=False,
            )
            return (stdout or stderr).strip()[-10000:]
        except Exception as exc:
            return f'Unable to collect guest guard diagnostics: {type(exc).__name__}: {exc}'

    async def _verify_workspace_view_isolation(self) -> None:
        """Prove that an isolated controller view works before declaring the VM Ready."""
        command = (
            'test "$(pwd -P)" = /workspace '
            f'&& ! /usr/bin/mountpoint -q {shlex.quote(FILES_BACKING_GUEST_PATH)} '
            f'&& ! /usr/bin/mountpoint -q {shlex.quote(PRIVATE_WORKTREES_GUEST_PATH)}'
        )
        view_command = self._workspace_view_command(
            command, cwd=WORKSPACE_VIEW_GUEST_PATH, active_root=self.files_root,
        )
        rc, stdout, stderr = await self._run(
            'shell', '--workdir', '/', self.INSTANCE, '/bin/bash', '-lc',
            self._guest_wrapper(view_command), timeout=15, check=False,
        )
        if rc != 0:
            detail = (stderr or stdout).strip()[-2000:]
            raise RuntimeError(
                'isolated /workspace view verification failed'
                + (f': {detail}' if detail else f' (exit {rc})')
            )

    async def _enforce_runtime_guard(self, progress=None) -> None:
        async def report(phase: str, message: str, **meta: Any) -> None:
            self._write_readiness(ready=False, phase=phase)
            await self._emit_progress(progress, phase, message, **meta)

        await report(
            'installing_isolation', 'Installing workspace isolation guard…',
            stage_timeout_seconds=36.0,
        )
        log_event('runtime', 'vm_isolation_guard_begin', workspace=str(self.workspace_root), provider='lima')
        boot_id = ''
        try:
            await self._install_runtime_guard()
            await report(
                'applying_isolation', 'Applying workspace network isolation…',
                stage_timeout_seconds=8.0,
            )
            await self._queue_runtime_guard_service()
            await report(
                'verifying_isolation', 'Verifying workspace isolation…',
                stage_timeout_seconds=36.0,
            )
            service_state = await self._wait_for_runtime_guard_service(timeout_seconds=24.0)
            rc, marker, marker_err = await self._run(
                'shell', self.INSTANCE, 'cat', '/run/harnessy-network-guard.ready',
                timeout=5, check=False,
            )
            boot_id = marker.strip() if rc == 0 else ''
            if not boot_id:
                raise RuntimeError((marker_err or marker).strip() or 'network guard did not produce its readiness marker')
            actual_boot = await self._guest_boot_id()
            if not actual_boot:
                raise RuntimeError('could not verify the current VM boot id after isolation setup')
            if actual_boot != boot_id:
                raise RuntimeError('network guard readiness marker belongs to a different VM boot')
            await self._verify_workspace_view_isolation()
            log_event(
                'runtime', 'vm_isolation_guard_service_complete', workspace=str(self.workspace_root),
                provider='lima', boot_id=boot_id, service_state=service_state,
            )
        except Exception as exc:
            detail = await self._guard_failure_detail()
            message = f'{type(exc).__name__}: {exc}'
            if detail:
                message += f'\n\n{detail}'
            self._write_readiness(ready=False, phase='isolation_failed', error=message)
            log_event(
                'harnessy', 'vm_isolation_guard_failed', workspace=str(self.workspace_root),
                provider='lima', detail=message,
            )
            raise RuntimeError(
                'Workspace VM started, but its isolation/readiness setup failed. '
                'The VM is not Ready and no workspace terminal or model command was run. '
                f'{message}'
            ) from exc
        self._write_readiness(ready=True, phase='ready', boot_id=boot_id, guard_hash=self._expected_guard_hash())
        log_event('runtime', 'vm_isolation_guard_verified', workspace=str(self.workspace_root), provider='lima', boot_id=boot_id)

    @_lifecycle_diagnostics('start')
    async def start(self, progress=None) -> EnvironmentStatus:
        async with self._workspace_start_lock():
            return await self._start_locked(progress=progress)

    def _save_controller_config(self, config: EnvironmentConfig) -> None:
        save_environment_config(self.workspace_root, config, preserve_user_metadata=True)
        saved = load_environment_config(self.workspace_root, config.id)
        if saved is None:
            raise RuntimeError('The selected VM environment no longer exists.')
        self.config = saved

    def _refresh_saved_network_policy(self) -> None:
        saved = load_environment_config(self.workspace_root, self.config.id)
        if saved is None:
            raise RuntimeError('The selected VM environment no longer exists.')
        from .manager import EnvironmentManager
        EnvironmentManager._validate_config(saved)
        current_image = get_preset(self.config.preset).image_id
        saved_image = get_preset(saved.preset).image_id
        if (self.config.provider, current_image, self.config.architecture, self.config.files_mode, self.config.desktop) != (
                saved.provider, saved_image, saved.architecture, saved.files_mode, saved.desktop):
            raise RuntimeError('The VM identity changed outside its settings editor. Reload this environment before executing commands.')
        # A retained toolbox/provider must observe a same-image tool-preset
        # update as well as live ACL/name/network changes made by another tab.
        self.config = saved

    async def _start_locked(self, progress=None) -> EnvironmentStatus:
        self._refresh_saved_network_policy()
        async def report(phase: str, message: str, **meta: Any) -> None:
            self._write_readiness(ready=False, phase=phase)
            await self._emit_progress(progress, phase, message, **meta)

        status = await self.status()
        if not status.running:
            self._preflight_acceleration_access()
            await self._ensure_host_prerequisites(progress=progress)
        if not status.created:
            await report('creating_vm', 'Creating workspace VM…')
            status = await self._call_with_optional_progress(self.create, progress=progress)
        binding_needs_reconcile = not self._runtime_binding_matches()
        if status.running and binding_needs_reconcile:
            self._preflight_acceleration_access()
            await report(
                'reconciling_environment', 'Updating workspace VM configuration…',
                detail='Stopping the VM briefly to rebind working roots and remove legacy per-boot provisioning.',
                stage_timeout_seconds=self.TIMEOUT_STOP + self.TIMEOUT_EDIT,
            )
            await self.stop()
            status = await self.status()
        if not status.running:
            if binding_needs_reconcile or not self._references_binding_matches():
                await report(
                    'reconciling_environment', 'Updating workspace VM configuration…',
                    detail='Rebinding working roots and removing legacy per-boot provisioning before startup.',
                    stage_timeout_seconds=self.TIMEOUT_EDIT,
                )
            await self._reconcile_runtime_binding()
            self._clear_readiness('starting_vm')
            await report(
                'starting_vm', 'Starting workspace VM…', detail='Launching Lima…',
                stage_timeout_seconds=self.TIMEOUT_START,
            )

            start_progress_state: dict[str, Any] = {}

            async def observe_start(_stream: str, line: str) -> None:
                update = self._lima_progress_update(line)
                if update is None:
                    return
                detail, stage_percent = update
                if not self._controller_progress_should_emit(start_progress_state, detail, stage_percent):
                    return
                await report(
                    'starting_vm', 'Starting workspace VM…', detail=detail,
                    stage_progress_percent=stage_percent, progress_source='lima',
                    stage_timeout_seconds=self.TIMEOUT_START,
                )

            previous_observer = self._controller_output_callback
            self._controller_output_callback = observe_start
            try:
                # Bound Lima's own hostagent event watch as well as the outer
                # application wait. Native SSH requirements retain their own
                # retry limits, and success still requires our isolation guard.
                await self._run(
                    'start', self.INSTANCE, f'--timeout={self.TIMEOUT_START:g}s',
                    timeout=self.TIMEOUT_START + self.TIMEOUT_START_CONTROLLER_GRACE, check=True,
                )
            finally:
                self._controller_output_callback = previous_observer
            log_event('harnessy', 'vm_started', workspace=str(self.workspace_root), provider='lima')
            await report('waiting_for_guest', 'Waiting for guest control channel…')
            status = await self.status()
        if not status.running:
            raise RuntimeError(f'Workspace VM did not reach running state: {status.detail or status.state}')
        # A boot already verified by this/another HarnessyXO process necessarily
        # passed provisioning + isolation. Reuse it immediately; opening another
        # Terminal must not add even a package-marker shell round-trip.
        if await self._current_boot_is_verified():
            if not self._read_verified_guest():
                await self._record_verified_guest()
            await self._emit_progress(progress, 'ready', 'Environment Ready', stage_progress_percent=100.0, progress_source='lima')
            return await self.status()
        # Package installation is explicit one-time disk setup, never a Lima
        # per-boot provision script. Existing older VMs are adopted in place.
        await self._ensure_preset_provisioned(progress=progress)
        await self._ensure_desktop(progress=progress)
        await self._enforce_runtime_guard(progress=progress)
        await self._record_verified_guest()
        await self._emit_progress(progress, 'ready', 'Environment Ready', stage_progress_percent=100.0, progress_source='lima')
        return await self.status()

    async def apply_network_policy(self, enabled: bool, *, expected: bool | None = None,
                                   progress=None, reservation_held: bool = False) -> EnvironmentStatus:
        """Stop/apply/start an existing VM policy; never delete disk or Files/.

        The operation registry reserves exclusion before queueing. Direct
        callers take the same reservation here. A failed restart leaves a
        stopped VM and restores the previous saved policy, with an explicit
        error; it never silently starts an old policy after failure.
        """
        if not isinstance(enabled, bool):
            raise ValueError('Public outbound network must be a boolean.')
        release = (lambda: None) if reservation_held else reserve_policy_change(self.workspace_root, environment_id=self.config.id)
        try:
            async with self._workspace_start_lock():
                original = load_environment_config(self.workspace_root, self.config.id)
                if original is None:
                    raise RuntimeError('The workspace environment definition is missing.')
                if expected is not None and original.network != expected:
                    raise RuntimeError('Network policy changed since this editor opened. Reload Details before applying.')
                self.config = original.normalized()
                status = await self.status()
                if original.network == enabled:
                    return status
                # A stopped VM is deliberately left stopped. For a running VM,
                # verify host prerequisites before interrupting its idle boot.
                if status.running:
                    await self._ensure_host_prerequisites(progress=progress, allow_install=False)
                    await self._emit_progress(progress, 'network_stopping', 'Stopping the idle VM to apply network policy…')
                    stopped = await self.stop()
                    if stopped.running:
                        raise RuntimeError('VM did not stop; network policy was not changed.')
                changed = EnvironmentConfig.from_dict({**original.to_dict(), 'network': enabled})
                try:
                    await self._emit_progress(progress, 'network_applying', 'Saving public outbound policy…')
                    self._save_controller_config(changed)
                    self._clear_readiness('network_policy_changed')
                    self._write_template()
                    if status.running:
                        await self._emit_progress(progress, 'network_starting', 'Restarting and verifying network isolation…')
                        result = await self._start_locked(progress=progress)
                        if not result.running or not result.ready:
                            raise RuntimeError('VM did not become Ready under the new network policy.')
                    else:
                        result = await self.status()
                    await self._emit_progress(progress, 'ready', 'Public outbound policy saved; VM disk and Files/ preserved.')
                    return result
                except BaseException as exc:
                    # Fail closed. Never advertise rollback as successful unless
                    # the controller confirms the VM stopped before restoring.
                    rollback_error = ''
                    try:
                        stopped = await self.stop()
                        if stopped.running:
                            raise RuntimeError('VM is still running')
                        self._save_controller_config(original)
                        self._clear_readiness('network_policy_failed')
                        self._write_template()
                    except BaseException as rollback:
                        rollback_error = str(rollback) or type(rollback).__name__
                    if isinstance(exc, asyncio.CancelledError):
                        log_event('runtime', 'network_policy_cancelled', workspace=str(self.workspace_root),
                                  rollback_error=rollback_error)
                        raise
                    if rollback_error:
                        raise RuntimeError(f'Network policy failed: {exc}. Rollback could not be verified: {rollback_error}. '
                                           'Inspect VM status before retrying; no disk or Files/ deletion was attempted.') from exc
                    raise RuntimeError(f'Network policy failed: {exc}. The previous saved policy was restored; '
                                       'the VM was left stopped. VM disk and Files/ were preserved.') from exc
        finally:
            from .manager import clear_environment_provider_cache
            clear_environment_provider_cache(self.workspace_root, self.config.id)
            release()

    async def apply_resources(self, *, cpu: int, memory_mb: int, disk_gb: int,
                              expected: dict[str, Any] | None = None, progress=None,
                              reservation_held: bool = False) -> EnvironmentStatus:
        """Edit a stopped VM in place; primary-disk growth takes effect on Start.

        Lima validates the edit. Read its reported configuration back before
        committing portable settings. A failed/uncertain edit leaves the saved
        definition unchanged and never attempts a compensating disk shrink.
        """
        from .resources import changed_resources, lima_resource_values, resources_match

        release = (lambda: None) if reservation_held else reserve_environment_change(self.workspace_root, 'VM resources', environment_id=self.config.id)
        try:
            async with self._workspace_start_lock():
                original = load_environment_config(self.workspace_root, self.config.id)
                if original is None:
                    raise RuntimeError('The workspace environment definition is missing.')
                if expected is not None and expected != original.to_dict():
                    raise RuntimeError('Workspace settings changed since this editor opened. Reopen Edit VM Resources before applying.')
                changed = changed_resources(original, cpu=cpu, memory_mb=memory_mb, disk_gb=disk_gb)
                self.config = original
                await self._emit_progress(progress, 'resources_checking', 'Checking stopped VM resources…',
                                          stage_timeout_seconds=45.0)
                status = await self.status()
                if status.running or (status.created and status.state != 'stopped'):
                    raise RuntimeError('Stop the workspace VM before changing CPU, RAM, or storage. No work was interrupted.')
                if not status.created and (self.vm_root / self.INSTANCE).exists():
                    raise RuntimeError('Cannot verify the existing VM state. Resource settings were not changed; restore host backend access and retry.')
                if status.created:
                    row = await self._instance_row()
                    if not row or str(row.get('name') or row.get('Name') or '') != self.INSTANCE:
                        raise RuntimeError('Cannot verify the workspace VM identity. Resource settings were not changed.')
                    if str(row.get('status') or row.get('Status') or '').lower() != 'stopped':
                        raise RuntimeError('The VM is no longer stopped. Resource settings were not changed.')
                    current = lima_resource_values(row)
                    if changed.disk_gb * 1024 ** 3 < current['disk']:
                        raise ValueError('Storage cannot be smaller than the current Lima disk. Reopen the editor and choose at least its existing capacity; no disk shrink was attempted.')
                    if not resources_match(row, changed):
                        await self._emit_progress(progress, 'resources_applying', 'Applying stopped VM resource settings…',
                                                  detail='The VM stays stopped. Storage can grow; the existing disk is preserved.',
                                                  stage_timeout_seconds=self.TIMEOUT_EDIT)
                        try:
                            await self._run('edit', self.INSTANCE, '--cpus', str(changed.cpu),
                                            '--memory', f'{changed.memory_mb / 1024:.10f}'.rstrip('0').rstrip('.'),
                                            '--disk', str(changed.disk_gb), timeout=self.TIMEOUT_EDIT, check=True)
                            verified = await self._instance_row()
                            if (not verified or str(verified.get('name') or verified.get('Name') or '') != self.INSTANCE
                                    or str(verified.get('status') or verified.get('Status') or '').lower() != 'stopped'
                                    or not resources_match(verified, changed)):
                                raise RuntimeError('Lima did not confirm all requested values on the stopped VM.')
                        except BaseException as exc:
                            if isinstance(exc, asyncio.CancelledError):
                                raise
                            raise RuntimeError(f'Resource update could not be verified: {exc}. The previous saved settings remain. '
                                               'Lima may have accepted part of the edit; keep the VM stopped and retry the same or larger storage size. '
                                               'No disk shrink, rebuild, or deletion was attempted.') from exc
                await self._emit_progress(progress, 'resources_saving', 'Saving verified VM resources…', stage_timeout_seconds=20.0)
                self.config = changed
                try:
                    self._write_template()
                    self._clear_readiness('resources_changed')
                    self._save_controller_config(changed)
                except BaseException as exc:
                    self.config = original
                    if isinstance(exc, asyncio.CancelledError):
                        raise
                    raise RuntimeError(f'Could not save the new resource settings: {exc}. The portable settings remain unchanged; '
                                       'keep the VM stopped and retry. No disk shrink or deletion was attempted.') from exc
                log_event('runtime', 'vm_resources_applied', workspace=str(self.workspace_root), provider='lima',
                          cpu=changed.cpu, memory_mb=changed.memory_mb, disk_gb=changed.disk_gb,
                          vm_running=False, disk_growth_pending=changed.disk_gb > original.disk_gb)
                await self._emit_progress(progress, 'resources_complete', 'VM resources saved. Start the VM to use them.',
                                          detail='The VM disk and workspace files were preserved.', stage_timeout_seconds=10.0)
                return status
        finally:
            from .manager import clear_environment_provider_cache
            clear_environment_provider_cache(self.workspace_root, self.config.id)
            release()

    @_lifecycle_diagnostics('stop')
    async def stop(self, *, force: bool = False) -> EnvironmentStatus:
        status = await self.status()
        if not status.created or not status.running:
            self._clear_readiness('stopped')
            return status
        args = ['stop']
        if force:
            args.append('--force')
        args.append(self.INSTANCE)
        await self._run(*args, timeout=self.TIMEOUT_STOP, check=True)
        self._clear_readiness('stopped')
        log_event('harnessy', 'vm_stopped', workspace=str(self.workspace_root), provider='lima', force=force)
        return await self.status()

    async def _ensure_running(self) -> None:
        self._refresh_saved_network_policy()
        status = await self.status()
        if (not status.available or not status.running or not self._runtime_binding_matches()
                or not await self._current_boot_is_verified()):
            # start() owns the process-wide per-workspace readiness lock, so concurrent tools
            # converge on one guard handshake rather than racing systemd/xtables.
            status = await self.start()
        else:
            status = await self.status()
        if not status.running or not status.ready:
            raise RuntimeError(f'Workspace VM is not Ready: {status.error or status.detail or status.state}')

    async def exec(
        self, command: str, *, cwd: str = '/workspace', timeout: float | None = None,
        active_root: Path | None = None, output_policy: dict[str, Any] | None = None,
    ) -> ExecResult:
        if not str(command or '').strip():
            raise ValueError('command must not be empty')
        self._authorize_model_project(output_policy)
        project_id = (output_policy or {}).get('_model_project_id') or (output_policy or {}).get('_human_project_id')
        owner_id = str((output_policy or {}).get('_file_view_owner_id') or '')
        with activity(self.workspace_root, 'Guest command', environment_id=self.config.id, project_id=project_id, owner_id=owner_id):
            await self._ensure_running()
            if project_id:
                from .file_views import FILE_VIEWS
                verified = await FILE_VIEWS.ensure_project(self.workspace_root, environment_id=self.config.id,
                    project_id=project_id, owner_id=owner_id, human='_human_project_id' in output_policy)
                if verified['policy_revision'] != output_policy.get('policy_revision'):
                    raise FileViewUnavailableError('Project file policy changed before this command could start.', 'FILE_VIEW_POLICY_CHANGED')
            if self.config.files_mode == 'copy':
                await asyncio.to_thread(self._prepare_project_copy, active_root, output_policy)
            view_command = self._workspace_view_command(
                command, cwd=cwd, active_root=active_root, output_policy=output_policy,
            )
            self._authorize_model_project(output_policy)
            started = time.perf_counter()
            try:
                rc, stdout, stderr = await self._run(
                    'shell', '--workdir', '/', self.INSTANCE, '/bin/bash', '-lc', self._guest_wrapper(view_command),
                    timeout=timeout, check=False,
                )
            except asyncio.TimeoutError:
                self._guest_transport_failure(timed_out=True)
                raise
            if rc == 255:
                self._guest_transport_failure(stderr=stderr, returncode=rc)
            duration = max(0.0, time.perf_counter() - started)
            projection_error_code = workspace_projection_failure(rc, stderr)
            projection_probe_code = workspace_projection_probe_failure(stderr)
            if projection_error_code:
                self._write_readiness(
                    ready=False, phase='workspace_projection_failed', error=projection_error_code,
                )
            log_event(
                'runtime', 'vm_exec_complete', workspace=str(self.workspace_root), provider='lima',
                returncode=rc, duration_seconds=duration, stdout_chars=len(stdout), stderr_chars=len(stderr),
                projection_error_code=projection_error_code, projection_probe_code=projection_probe_code,
            )
            return ExecResult(rc, stdout, stderr, duration)

    async def spawn(
        self, command: str, *, cwd: str = '/workspace', active_root: Path | None = None,
        output_policy: dict[str, Any] | None = None,
    ) -> asyncio.subprocess.Process:
        if not str(command or '').strip():
            raise ValueError('command must not be empty')
        self._authorize_model_project(output_policy)
        project_id = (output_policy or {}).get('_model_project_id') or (output_policy or {}).get('_human_project_id')
        owner_id = str((output_policy or {}).get('_file_view_owner_id') or '')
        # A running job must never be exempted by a later call from this run.
        release = acquire_activity(self.workspace_root, 'Guest process', environment_id=self.config.id,
                                   project_id=project_id, owner_id=owner_id)
        try:
            await self._ensure_running()
            if project_id:
                from .file_views import FILE_VIEWS
                verified = await FILE_VIEWS.ensure_project(self.workspace_root, environment_id=self.config.id,
                    project_id=project_id, owner_id=owner_id, human='_human_project_id' in output_policy)
                if verified['policy_revision'] != output_policy.get('policy_revision'):
                    raise FileViewUnavailableError('Project file policy changed before this process could start.', 'FILE_VIEW_POLICY_CHANGED')
            if self.config.files_mode == 'copy':
                await asyncio.to_thread(self._prepare_project_copy, active_root, output_policy)
            view_command = self._workspace_view_command(
                command, cwd=cwd, active_root=active_root, output_policy=output_policy,
            )
            self._authorize_model_project(output_policy)
            binary = self._binary()
            argv = [
                binary, '--tty=false', 'shell', '--workdir', '/', self.INSTANCE,
                '/bin/bash', '-lc', self._guest_wrapper(view_command),
            ]
            log_event('runtime', 'vm_spawn', workspace=str(self.workspace_root), provider='lima')
            process = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, env=self._host_env(),
            )
            process_release = acquire_activity(self.workspace_root, 'Running guest process',
                environment_id=self.config.id, project_id=project_id, owner_id=uuid.uuid4().hex)
            release()
            release = process_release
        except BaseException:
            release()
            raise
        async def release_after_exit():
            try:
                await process.wait()
            finally:
                release()
        # Strong reference lasts until the child ends, independent of UI tabs.
        tasks = getattr(self, '_process_activity_tasks', None)
        if tasks is None:
            tasks = self._process_activity_tasks = set()
        task = asyncio.create_task(release_after_exit())
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return process

    @staticmethod
    def _clean_snapshot_tag(tag: str) -> str:
        clean = ''.join(c if c.isalnum() or c in '._-' else '-' for c in str(tag or '').strip())[:80]
        return clean or time.strftime('snapshot-%Y%m%d-%H%M%S')

    @staticmethod
    def _clone_snapshot_instance(tag: str) -> str:
        # Never put user-controlled snapshot text in a host controller instance
        # name. The mapping lives in index.json and the model never receives a
        # way to address these stopped checkpoint instances directly.
        digest = hashlib.sha256(f'{tag}:{time.time_ns()}'.encode()).hexdigest()[:20]
        return f'harnessy-snap-{digest}'

    @staticmethod
    def _valid_clone_snapshot_instance(value: Any) -> bool:
        name = str(value or '')
        prefix = 'harnessy-snap-'
        suffix = name[len(prefix):] if name.startswith(prefix) else ''
        return len(suffix) == 20 and all(c in '0123456789abcdef' for c in suffix)

    def _read_snapshot_index(self) -> dict[str, dict[str, Any]]:
        try:
            raw = json.loads(self.snapshot_index_path.read_text('utf-8'))
        except FileNotFoundError:
            return {}
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f'Cannot read snapshot index {self.snapshot_index_path.name}: {exc}') from exc
        if not isinstance(raw, dict) or raw.get('version') != 1 or not isinstance(raw.get('items'), dict):
            raise RuntimeError('Snapshot index has an unsupported or damaged format; no snapshots were deleted.')
        items = raw['items']
        if any(not isinstance(tag, str) or not isinstance(meta, dict)
               or meta.get('kind') != 'lima-clone'
               or not self._valid_clone_snapshot_instance(meta.get('instance'))
               for tag, meta in items.items()):
            raise RuntimeError('Snapshot index contains invalid checkpoint metadata; no snapshots were deleted.')
        return {tag: dict(meta) for tag, meta in items.items()}

    def _write_snapshot_index(self, items: dict[str, dict[str, Any]]) -> None:
        self.snapshots_root.mkdir(parents=True, exist_ok=True)
        payload = {'version': 1, 'items': items}
        tmp = self.snapshot_index_path.with_suffix('.tmp')
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        tmp.replace(self.snapshot_index_path)

    async def snapshot(self, tag: str, progress=None) -> list[str]:
        clean = self._clean_snapshot_tag(tag)
        await self._emit_progress(
            progress, 'preparing_snapshot', 'Preparing VM snapshot…',
            detail=f'Checkpoint name: {clean}',
        )
        existing = await self.list_snapshots()
        if clean in existing:
            raise ValueError(f'Snapshot already exists: {clean}')

        if not self._uses_clone_snapshots():
            await self._ensure_running()
            await self._emit_progress(
                progress, 'cloning_snapshot', 'Creating VM snapshot…',
                detail='Lima native snapshot in progress…',
                stage_timeout_seconds=self.TIMEOUT_SNAPSHOT,
            )
            await self._run('snapshot', 'create', self.INSTANCE, '--tag', clean, timeout=self.TIMEOUT_SNAPSHOT, check=True)
            log_event(
                'harnessy', 'vm_snapshot_created', workspace=str(self.workspace_root),
                tag=clean, strategy='lima-native',
            )
            await self._emit_progress(progress, 'saving_snapshot', 'Finalizing snapshot…', stage_progress_percent=100.0)
            snapshots = await self.list_snapshots()
            if clean not in snapshots:
                raise RuntimeError(
                    f'Snapshot creation could not be verified: {clean} was not returned by Lima snapshot list.'
                )
            return snapshots

        # Lima's VZ driver does not provide native snapshot/apply. On macOS we
        # make a real persistent checkpoint by cloning the stopped Lima instance.
        # `limactl clone` does not start the destination unless --start is given.
        await self._ensure_running()
        was_running = (await self.status()).running
        clone_name = self._clone_snapshot_instance(clean)
        clone_created = False
        try:
            if was_running:
                await self._emit_progress(
                    progress, 'stopping_snapshot_vm', 'Pausing VM for a consistent snapshot…',
                    detail='Stopping the workspace VM before cloning its persistent state.',
                    stage_timeout_seconds=self.TIMEOUT_STOP,
                )
                await self.stop()
            await self._emit_progress(
                progress, 'cloning_snapshot', 'Creating VM checkpoint…',
                detail='Lima is cloning the stopped VM. Large VM state can make this the longest snapshot stage.',
                stage_timeout_seconds=self.TIMEOUT_SNAPSHOT,
            )

            clone_progress_state: dict[str, Any] = {}

            async def observe_clone(_stream: str, line: str) -> None:
                update = self._lima_clone_progress_update(line)
                if update is None:
                    return
                detail, stage_percent = update
                if not self._controller_progress_should_emit(clone_progress_state, detail, stage_percent):
                    return
                await self._emit_progress(
                    progress, 'cloning_snapshot', 'Creating VM checkpoint…',
                    detail=detail, stage_progress_percent=stage_percent, progress_source='lima',
                    stage_timeout_seconds=self.TIMEOUT_SNAPSHOT,
                )

            previous_observer = self._controller_output_callback
            self._controller_output_callback = observe_clone
            try:
                await self._run('clone', self.INSTANCE, clone_name, timeout=self.TIMEOUT_SNAPSHOT, check=True)
            finally:
                self._controller_output_callback = previous_observer
            clone_created = True
            await self._emit_progress(
                progress, 'saving_snapshot', 'Saving snapshot metadata…',
                detail='VM checkpoint complete; recording the restorable snapshot entry.',
                stage_progress_percent=100.0,
            )
            items = self._read_snapshot_index()
            if clean in items:
                raise ValueError(f'Snapshot already exists: {clean}')
            items[clean] = {
                'kind': 'lima-clone',
                'instance': clone_name,
                'created_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            }
            self._write_snapshot_index(items)
            log_event(
                'harnessy', 'vm_snapshot_created', workspace=str(self.workspace_root),
                tag=clean, strategy='lima-clone', instance=clone_name,
            )
        except Exception:
            if clone_created:
                try:
                    await self._run('delete', '--force', clone_name, timeout=self.TIMEOUT_DELETE, check=False)
                except Exception:
                    pass
            raise
        finally:
            if was_running:
                await self._emit_progress(
                    progress, 'restarting_snapshot_vm', 'Restarting workspace VM…',
                    detail='Snapshot is saved. Bringing the workspace environment back online.',
                    stage_timeout_seconds=self.TIMEOUT_START,
                )

                async def restart_progress(phase: str, message: str, **meta: Any) -> None:
                    verifying = phase in {'installing_isolation', 'applying_isolation', 'verifying_isolation', 'ready'}
                    mapped = 'verifying_snapshot_restart' if verifying else 'restarting_snapshot_vm'
                    detail = str(meta.get('detail') or message or '')
                    await self._emit_progress(
                        progress, mapped,
                        'Verifying restarted environment…' if verifying else 'Restarting workspace VM…',
                        detail=detail,
                        stage_progress_percent=meta.get('stage_progress_percent'),
                        progress_source=str(meta.get('progress_source') or ''),
                        stage_timeout_seconds=meta.get('stage_timeout_seconds'),
                    )

                await self._call_with_optional_progress(self.start, progress=restart_progress)
        snapshots = await self.list_snapshots()
        if clean not in snapshots:
            raise RuntimeError(
                f'Snapshot creation could not be verified: {clean} is missing from the snapshot index/list.'
            )
        return snapshots

    async def _list_snapshots_for_status(self, status: EnvironmentStatus) -> list[str]:
        if self._uses_clone_snapshots():
            return list(self._read_snapshot_index())
        if not status.created:
            return []
        rc, stdout, stderr = await self._run('snapshot', 'list', self.INSTANCE, '--quiet', timeout=30)
        if rc != 0:
            raise RuntimeError(f'Snapshot list failed (exit {rc}): {(stderr or stdout).strip()[:1600]}')
        return [line.strip() for line in stdout.splitlines() if line.strip()]

    async def list_snapshots(self) -> list[str]:
        if self._uses_clone_snapshots():
            return list(self._read_snapshot_index())
        return await self._list_snapshots_for_status(await self.status())

    async def restore_snapshot(self, tag: str, progress=None) -> EnvironmentStatus:
        requested = str(tag or '').strip()
        if not requested:
            raise ValueError('snapshot tag is required')
        self._preflight_acceleration_access()
        await self._emit_progress(
            progress, 'preparing_restore', f'Preparing snapshot {requested} for restore…',
        )

        if not self._uses_clone_snapshots():
            await self._emit_progress(
                progress, 'stopping_restore_vm', 'Stopping workspace VM…',
                stage_timeout_seconds=self.TIMEOUT_STOP,
            )
            await self.stop()
            await self._emit_progress(
                progress, 'replacing_restore_vm', f'Applying snapshot {requested}…',
                stage_timeout_seconds=self.TIMEOUT_SNAPSHOT,
            )
            await self._run('snapshot', 'apply', self.INSTANCE, '--tag', requested, timeout=self.TIMEOUT_SNAPSHOT, check=True)
            self._record_lifecycle('snapshot_restored')
            log_event(
                'harnessy', 'vm_snapshot_restored', workspace=str(self.workspace_root),
                tag=requested, strategy='lima-native',
            )
            await self._emit_progress(progress, 'restarting_restore_vm', 'Restarting restored environment…')
            return await self.start()

        items = self._read_snapshot_index()
        meta = items.get(requested)
        if not meta:
            raise ValueError(f'Unknown snapshot: {requested}')
        clone_name = str(meta['instance'])
        if not await self._instance_row_named(clone_name):
            raise RuntimeError(
                f'Snapshot backing checkpoint is unavailable: {requested}. '
                'The current workspace VM was not modified.'
            )
        status = await self.status()
        if status.created and status.running:
            await self._emit_progress(
                progress, 'stopping_restore_vm', 'Stopping workspace VM…',
                stage_timeout_seconds=self.TIMEOUT_STOP,
            )
            await self.stop()
        await self._emit_progress(
            progress, 'replacing_restore_vm', 'Replacing VM state from checkpoint…',
            detail='The selected stopped checkpoint is being cloned back into the workspace VM.',
            stage_timeout_seconds=self.TIMEOUT_SNAPSHOT,
        )
        if status.created:
            await self._run('delete', '--force', self.INSTANCE, timeout=self.TIMEOUT_DELETE, check=True)
        await self._run('clone', clone_name, self.INSTANCE, timeout=self.TIMEOUT_SNAPSHOT, check=True)
        await self._emit_progress(progress, 'reconciling_restore_files', 'Rebinding workspace working roots…')
        # The stopped checkpoint may have been created before the workspace was
        # moved/copied. Always rewrite its host mount binding before starting the
        # restored main instance.
        await self._reconcile_runtime_binding(force=True)
        self._record_lifecycle('snapshot_restored')
        log_event(
            'harnessy', 'vm_snapshot_restored', workspace=str(self.workspace_root),
            tag=requested, strategy='lima-clone', instance=clone_name,
        )
        await self._emit_progress(progress, 'restarting_restore_vm', 'Restarting restored environment…')

        async def restart_progress(phase: str, message: str, **meta: Any) -> None:
            verifying = phase in {'installing_isolation', 'applying_isolation', 'verifying_isolation', 'ready'}
            mapped = 'verifying_restore_restart' if verifying else 'restarting_restore_vm'
            await self._emit_progress(
                progress, mapped,
                'Verifying restored environment…' if verifying else 'Restarting restored environment…',
                detail=str(meta.get('detail') or message or ''),
                stage_progress_percent=meta.get('stage_progress_percent'),
                progress_source=str(meta.get('progress_source') or ''),
                stage_timeout_seconds=meta.get('stage_timeout_seconds'),
            )

        return await self._call_with_optional_progress(self.start, progress=restart_progress)

    @_lifecycle_diagnostics('reset')
    async def reset(self, progress=None) -> EnvironmentStatus:
        status = await self.status()
        if not status.created:
            return await self._call_with_optional_progress(self.start, progress=progress)
        self._preflight_acceleration_access()
        await self._preserve_vm_failure(reason='before_reset', operation='reset')
        await self._emit_progress(
            progress, 'factory_reset', 'Factory resetting VM while preserving working roots…',
            stage_timeout_seconds=self.TIMEOUT_RESET,
        )
        await self.stop()
        await self._run('factory-reset', self.INSTANCE, timeout=self.TIMEOUT_RESET, check=True)
        self._record_lifecycle('factory_reset')
        log_event('harnessy', 'vm_factory_reset', workspace=str(self.workspace_root))
        await self._emit_progress(progress, 'restarting_reset_vm', 'Starting reset workspace VM…')
        return await self._call_with_optional_progress(self.start, progress=progress)

    @_lifecycle_diagnostics('rebuild')
    async def rebuild(self, progress=None) -> EnvironmentStatus:
        self._preflight_acceleration_access()
        status = await self.status()
        if status.created:
            await self._preserve_vm_failure(reason='before_delete', operation='rebuild')
            await self._emit_progress(
                progress, 'rebuilding', 'Removing old workspace VM state…',
                stage_timeout_seconds=self.TIMEOUT_DELETE,
            )
            await self.stop(force=True)
            await self._run('delete', '--force', self.INSTANCE, timeout=self.TIMEOUT_DELETE, check=True)
        # Do not remove Files/ or private chat worktrees. All VM-owned bytes are
        # below vm_root and are recreated from environment.json + the template.
        await self._prepare_guest_image(progress=progress)
        self._write_template()
        await self._emit_progress(
            progress, 'creating_vm', 'Creating clean workspace VM…',
            stage_timeout_seconds=self.TIMEOUT_CREATE,
        )
        await self._run('create', '--name', self.INSTANCE, str(self.template_path), timeout=self.TIMEOUT_CREATE, check=True)
        self._write_runtime_binding()
        self._record_lifecycle('rebuild')
        log_event('harnessy', 'vm_rebuilt', workspace=str(self.workspace_root), files_preserved=True)
        return await self._call_with_optional_progress(self.start, progress=progress)

    @_lifecycle_diagnostics('destroy')
    async def destroy(self) -> None:
        status = await self.status()
        if not status.available:
            raise RuntimeError('Restore VM backend access before removing this environment. Existing virtual disks were preserved.')
        for path in (self.vm_root, self.snapshots_root):
            _validate_registry_path(path, self.workspace_root)
        if status.created:
            await self._preserve_vm_failure(reason='before_delete', operation='delete')
            await self.stop(force=True)
            await self._run('delete', '--force', self.INSTANCE, timeout=self.TIMEOUT_DELETE, check=True)
        shutil.rmtree(self.vm_root, ignore_errors=True)
        self.vm_root.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(self.snapshots_root, ignore_errors=True)
        self.snapshots_root.mkdir(parents=True, exist_ok=True)
        self._record_lifecycle('destroyed')
        log_event('harnessy', 'vm_destroyed', workspace=str(self.workspace_root))

    def file_view_capabilities(self) -> dict[str, Any]:
        return {'supported_modes': ('live', 'readonly', 'copy'),
                'transport': 'copy' if self.config.files_mode == 'copy' else 'bind',
                'runtime_mounts': self.config.files_mode != 'copy', 'project_isolation': True,
                'readonly_inputs': True, 'reconcile': True, 'project_terminal': True, 'composite': True,
                'persistent_project_namespace': self.config.files_mode != 'copy',
                'guest_references': True, 'guest_references_path': '/workspace/Files/References'}

    def _references_view_key(self) -> str:
        digest = hashlib.sha256(str(self.environment_root.resolve()).encode()).hexdigest()[:16]
        return 'guest-console-' + digest

    @staticmethod
    def _references_view_probe() -> str:
        return f'''set -euo pipefail
/usr/bin/mountpoint -q {WORKSPACE_VIEW_GUEST_PATH}/Files/References
case ",$(/usr/bin/findmnt -rn -M {WORKSPACE_VIEW_GUEST_PATH}/Files/References -o VFS-OPTIONS)," in
  *,ro,*) ;; *) exit 72 ;; esac
[ "$(/usr/bin/find {WORKSPACE_VIEW_GUEST_PATH}/Files -mindepth 1 -maxdepth 1 -printf '%f\\n')" = References ]
for backing in {FILES_BACKING_GUEST_PATH} {PRIVATE_WORKTREES_GUEST_PATH} {REFERENCES_BACKING_GUEST_PATH}; do
  ! /usr/bin/mountpoint -q "$backing"
done
'''

    def _references_view_command(self, policy: dict[str, Any], command: str = ':', *, prepare: bool = False) -> str:
        """Prepare or enter the independent, read-only human References view.

        Only reconciliation may replace its keeper after acquiring the console
        activity barrier. Terminal entry verifies an existing keeper and never
        repairs/kills it, closing the prepare-to-PTY race without touching any
        Project namespace or source file.
        """
        from harnessy.core.project_mounts import GUEST_CONSOLE_VIEW_ID
        revision = str(policy.get('policy_revision') or '')
        if (policy.get('view_id') != GUEST_CONSOLE_VIEW_ID or policy.get('readonly') is not True
                or not re.fullmatch('[a-f0-9]{64}', revision)):
            raise ValueError('Invalid read-only References file-view policy.')
        backing = self._references_backing_guest_path()
        signature = hashlib.sha256((revision + '\0' + backing + '\0references-console-v1').encode()).hexdigest()
        probe = self._references_view_probe()
        keeper = f'''set -euo pipefail
state_dir=$1; view_token=$2
/usr/bin/mount --make-rprivate /
/usr/bin/mountpoint -q {backing}
[ -d {backing}/References ] && [ ! -L {backing}/References ]
/usr/bin/mkdir -p {WORKSPACE_VIEW_GUEST_PATH}
/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs {WORKSPACE_VIEW_GUEST_PATH}
/usr/bin/mkdir -p {WORKSPACE_VIEW_GUEST_PATH}/Files/References
/usr/bin/mount --bind {backing}/References {WORKSPACE_VIEW_GUEST_PATH}/Files/References
/usr/bin/mount -o remount,bind,ro {WORKSPACE_VIEW_GUEST_PATH}/Files/References
/usr/bin/chmod 0555 {WORKSPACE_VIEW_GUEST_PATH} {WORKSPACE_VIEW_GUEST_PATH}/Files
for raw in {FILES_BACKING_GUEST_PATH} {PRIVATE_WORKTREES_GUEST_PATH} {REFERENCES_BACKING_GUEST_PATH}; do
  /usr/bin/umount -l "$raw" 2>/dev/null || true
  ! /usr/bin/mountpoint -q "$raw"
done
{probe}
printf '%s\\n' "$view_token" >"$state_dir/ready"
/usr/bin/mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs {PERSISTENT_VIEW_STATE_GUEST_PATH}
exec -a "harnessy-references-view-$view_token" /bin/sleep infinity
'''
        supervisor = f'''set -euo pipefail
signature=$1; keeper_script=$2; probe_script=$3; user_command=$4; prepare=$5; console_user=$6
state_root={PERSISTENT_VIEW_STATE_GUEST_PATH}
state_dir="$state_root/{self._references_view_key()}"
failure() {{ printf '%s\\n' 'HarnessyXO read-only References view is unavailable; retry its file-view setup.' >&2; exit 72; }}
[ ! -L "$state_root" ] && [ ! -L "$state_dir" ] || failure
/usr/bin/mkdir -p "$state_dir"
/usr/bin/chmod 0700 "$state_root" "$state_dir"
for name in lock pid token signature ready; do [ ! -L "$state_dir/$name" ] || failure; done
exec 9>"$state_dir/lock"
/usr/bin/flock -x 9
identity_valid() {{
  [ -s "$state_dir/pid" ] && [ -s "$state_dir/token" ] && [ -s "$state_dir/signature" ] || return 1
  keeper_pid=$(cat "$state_dir/pid"); token=$(cat "$state_dir/token")
  case "$keeper_pid" in *[!0-9]*|'') return 1 ;; esac
  case "$token" in *[!a-zA-Z0-9._-]*|'') return 1 ;; esac
  [ "$(cat "$state_dir/signature")" = "$signature" ] || return 1
  /bin/kill -0 "$keeper_pid" 2>/dev/null || return 1
  first=$(tr '\\000' '\\n' <"/proc/$keeper_pid/cmdline" | /usr/bin/head -n 1)
  [ "$first" = "harnessy-references-view-$token" ]
}}
view_valid() {{
  identity_valid && /usr/bin/nsenter --target "$keeper_pid" --mount --pid -- /bin/bash -c "$probe_script"
}}
if ! view_valid; then
  [ "$prepare" = 1 ] || failure
  if [ -s "$state_dir/pid" ] && [ -s "$state_dir/token" ]; then
    old_pid=$(cat "$state_dir/pid"); old_token=$(cat "$state_dir/token")
    case "$old_pid" in *[!0-9]*|'') failure ;; esac
    if [ -r "/proc/$old_pid/cmdline" ]; then
      old_first=$(tr '\\000' '\\n' <"/proc/$old_pid/cmdline" | /usr/bin/head -n 1)
      [ "$old_first" = "harnessy-references-view-$old_token" ] || failure
      /bin/kill -TERM "$old_pid" 2>/dev/null || true
      for attempt in $(/usr/bin/seq 1 40); do /bin/kill -0 "$old_pid" 2>/dev/null || break; /bin/sleep 0.05; done
      if /bin/kill -0 "$old_pid" 2>/dev/null; then
        old_first=$(tr '\\000' '\\n' <"/proc/$old_pid/cmdline" | /usr/bin/head -n 1)
        [ "$old_first" = "harnessy-references-view-$old_token" ] || failure
        /bin/kill -KILL "$old_pid"
      fi
    fi
  fi
  /bin/rm -f "$state_dir/pid" "$state_dir/token" "$state_dir/signature" "$state_dir/ready"
  token="$signature-$$-$(/bin/date +%s%N)"
  /usr/bin/setsid --fork /usr/bin/unshare --mount --pid --fork --mount-proc --propagation private \\
    /bin/bash -c "$keeper_script" harnessy-references-keeper "$state_dir" "$token" \\
    </dev/null >"$state_dir/start.stdout" 2>"$state_dir/start.stderr"
  keeper_pid=''
  for attempt in $(/usr/bin/seq 1 160); do
    if [ "$(cat "$state_dir/ready" 2>/dev/null || true)" = "$token" ]; then
      for candidate in /proc/[0-9]*; do
        [ -r "$candidate/cmdline" ] || continue
        first=$(tr '\\000' '\\n' <"$candidate/cmdline" 2>/dev/null | /usr/bin/head -n 1 || true)
        if [ "$first" = "harnessy-references-view-$token" ]; then keeper_pid=${{candidate##*/}}; break; fi
      done
      [ -z "$keeper_pid" ] || break
    fi
    /bin/sleep 0.05
  done
  [ -n "$keeper_pid" ] || failure
  printf '%s\\n' "$keeper_pid" >"$state_dir/pid"
  printf '%s\\n' "$token" >"$state_dir/token"
  printf '%s\\n' "$signature" >"$state_dir/signature"
  view_valid || failure
fi
/usr/bin/flock -u 9
exec /usr/bin/nsenter --target "$keeper_pid" --mount --pid -- \\
  /usr/bin/sudo -n -H -u "$console_user" -- /bin/bash -c "$user_command"
'''
        args = ' '.join(shlex.quote(value) for value in ('harnessy-references-supervisor', signature, keeper,
                                                       probe, str(command), '1' if prepare else '0'))
        return ('console_user=$(id -un); exec /usr/bin/sudo -n /bin/bash -c '
                + shlex.quote(supervisor) + ' ' + args + ' "$console_user"')

    async def _probe_references_view(self, policy: dict[str, Any]) -> bool:
        command = self._references_view_command(policy)
        rc, _, _ = await self._run('shell', '--workdir', '/', self.INSTANCE, '/bin/bash', '-lc',
                                   command, timeout=12, check=False)
        return rc == 0

    async def _retire_references_view(self) -> None:
        """Retire only the signed console keeper, never its source directory."""
        script = f'''set -euo pipefail
state_dir={PERSISTENT_VIEW_STATE_GUEST_PATH}/{self._references_view_key()}
[ ! -L "$state_dir" ] || exit 72
[ -d "$state_dir" ] || exit 0
for name in lock pid token signature ready; do [ ! -L "$state_dir/$name" ] || exit 72; done
exec 9>"$state_dir/lock"
/usr/bin/flock -x 9
if [ -s "$state_dir/pid" ] && [ -s "$state_dir/token" ]; then
  pid=$(cat "$state_dir/pid"); token=$(cat "$state_dir/token")
  case "$pid" in *[!0-9]*|'') exit 72 ;; esac
  case "$token" in *[!a-zA-Z0-9._-]*|'') exit 72 ;; esac
  if [ -r "/proc/$pid/cmdline" ]; then
    first=$(tr '\\000' '\\n' <"/proc/$pid/cmdline" | /usr/bin/head -n 1)
    [ "$first" = "harnessy-references-view-$token" ] || exit 72
    /bin/kill -TERM "$pid" 2>/dev/null || true
    for attempt in $(/usr/bin/seq 1 40); do /bin/kill -0 "$pid" 2>/dev/null || break; /bin/sleep 0.05; done
    if /bin/kill -0 "$pid" 2>/dev/null; then
      first=$(tr '\\000' '\\n' <"/proc/$pid/cmdline" | /usr/bin/head -n 1)
      [ "$first" = "harnessy-references-view-$token" ] || exit 72
      /bin/kill -KILL "$pid"
    fi
  fi
fi
/bin/rm -f "$state_dir/pid" "$state_dir/token" "$state_dir/signature" "$state_dir/ready" "$state_dir/start.failure"
'''
        await self._run('shell', '--workdir', '/', self.INSTANCE, 'sudo', '/bin/bash', '-c',
                        script, timeout=15, check=True)

    async def _reconcile_references_view(self, plan: dict[str, Any], records: dict[str, Any], workspace) -> dict[str, Any]:
        from harnessy.core.project_mounts import build_references_policy, GUEST_CONSOLE_VIEW_ID
        from .activity import reserve_project_view_change
        from .file_views import finish_file_view_work
        policy = plan.get('references_policy')
        if policy is None:
            failure = dict(plan.get('references_error') or {'project_id': GUEST_CONSOLE_VIEW_ID,
                           'folder': 'References', 'state': 'error', 'error_code': 'FILE_VIEW_SOURCE_INVALID'})
            try:
                release = reserve_project_view_change(self.workspace_root, environment_id=self.config.id,
                    project_id=GUEST_CONSOLE_VIEW_ID, owner_id=str(plan.get('_owner_id') or ''))
            except RuntimeError as exc:
                return {**failure, 'state': 'pending', 'detail': str(exc)}
            try:
                await self._retire_references_view()
                records.pop('references', None)
                return failure
            except Exception as exc:
                return {**failure, 'error_code': 'FILE_VIEW_MOUNT_FAILED', 'detail': str(exc)[:500]}
            finally:
                release()
        revision = policy['policy_revision']
        row = {'project_id': GUEST_CONSOLE_VIEW_ID, 'folder': 'References', 'policy_revision': revision}
        if not self._references_binding_matches():
            return {**row, 'state': 'pending', 'detail': 'Stop and start this VM once to add its read-only live References export.'}
        previous = records.get('references', {})
        if previous.get('policy_revision') == revision:
            try:
                if await self._probe_references_view(policy):
                    return {**row, 'state': 'ready'}
            except Exception:
                pass
        try:
            release = reserve_project_view_change(self.workspace_root, environment_id=self.config.id,
                project_id=GUEST_CONSOLE_VIEW_ID, owner_id=str(plan.get('_owner_id') or ''))
        except RuntimeError as exc:
            return {**row, 'state': 'pending', 'detail': str(exc)}
        try:
            fresh = await finish_file_view_work(build_references_policy, workspace)
            if fresh['policy_revision'] != revision:
                raise FileViewUnavailableError('References changed while preparing its console view.', 'FILE_VIEW_POLICY_CHANGED')
            await self._run('shell', '--workdir', '/', self.INSTANCE, '/bin/bash', '-lc',
                            self._references_view_command(policy, prepare=True), timeout=45, check=True)
            fresh = await finish_file_view_work(build_references_policy, workspace)
            if fresh['policy_revision'] != revision:
                raise FileViewUnavailableError('References changed while mounting its console view.', 'FILE_VIEW_POLICY_CHANGED')
            records['references'] = {'policy_revision': revision}
            return {**row, 'state': 'ready'}
        except Exception as exc:
            return {**row, 'state': 'error', 'error_code': getattr(exc, 'error_code', 'FILE_VIEW_MOUNT_FAILED'),
                    'detail': str(exc)[:500]}
        finally:
            release()

    def _file_view_records(self) -> dict[str, Any]:
        path = self.state_root / 'lima-file-views.json'
        _validate_registry_path(path, self.workspace_root)
        try:
            if path.stat().st_size > 1024 * 1024:
                raise RuntimeError('Lima file-view metadata is oversized.')
            value = json.loads(path.read_text())
            return value if isinstance(value, dict) else {}
        except FileNotFoundError:
            return {}

    def _save_file_view_records(self, records):
        path = self.state_root / 'lima-file-views.json'
        _validate_registry_path(path, self.workspace_root)
        temporary = path.with_name('.lima-file-views-' + uuid.uuid4().hex + '.tmp')
        try:
            with temporary.open('x', encoding='utf-8') as stream:
                json.dump(records, stream, sort_keys=True)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    async def _retire_project_view(self, folder: str):
        if not CHAT_OUTPUT_DIR_RE.fullmatch(folder):
            raise RuntimeError('Invalid project file-view identity.')
        digest = hashlib.sha256(f'{self.environment_root.resolve()}\0{folder}'.encode()).hexdigest()[:16]
        state_key = folder.lower() + '-' + digest
        script = f'''set -euo pipefail
state_dir={PERSISTENT_VIEW_STATE_GUEST_PATH}/{state_key}
[ ! -L "$state_dir" ] || exit 72
[ -d "$state_dir" ] || exit 0
for name in pid token signature ready; do [ ! -L "$state_dir/$name" ] || exit 72; done
if [ -s "$state_dir/pid" ] && [ -s "$state_dir/token" ]; then
  old_pid=$(cat "$state_dir/pid"); old_token=$(cat "$state_dir/token")
  case "$old_pid" in *[!0-9]*|'') exit 72 ;; esac
  if [ -r "/proc/$old_pid/cmdline" ]; then
    first=$(tr '\\000' '\\n' <"/proc/$old_pid/cmdline" | head -n 1)
    [ "$first" = "harnessy-project-view-$old_token" ] || exit 72
    kill -TERM "$old_pid" 2>/dev/null || true
    for attempt in $(seq 1 40); do kill -0 "$old_pid" 2>/dev/null || break; sleep 0.05; done
    if kill -0 "$old_pid" 2>/dev/null; then
      first=$(tr '\\000' '\\n' <"/proc/$old_pid/cmdline" | head -n 1)
      [ "$first" = "harnessy-project-view-$old_token" ] || exit 72
      kill -KILL "$old_pid"
    fi
  fi
fi
rm -f "$state_dir/pid" "$state_dir/token" "$state_dir/signature" "$state_dir/ready" "$state_dir/start.failure"
'''
        await self._run('shell', '--workdir', '/', self.INSTANCE, 'sudo', '/bin/bash', '-c', script, timeout=15, check=True)

    async def _probe_project_view(self, policy: dict[str, Any]) -> bool:
        """Verify a retained view without repairing or interrupting its work."""
        folder = policy['writable_folder']
        digest = hashlib.sha256(f'{self.environment_root.resolve()}\0{folder}'.encode()).hexdigest()[:16]
        paths = ['/workspace/Files/' + folder, '/workspace/Files/References']
        paths.extend('/workspace/Files/' + folder + '/' + row['nested_path'] for row in policy['ancestors'])
        paths.extend('/workspace/Files/' + row['folder'] for row in policy['access_projects'] if row['direct_mount'])
        probe = ('set -eu\n' + '\n'.join('/usr/bin/mountpoint -q ' + shlex.quote(path) for path in paths)
                 + '\n! /usr/bin/mountpoint -q ' + FILES_BACKING_GUEST_PATH
                 + '\n! /usr/bin/mountpoint -q ' + PRIVATE_WORKTREES_GUEST_PATH
                 + '\n! /usr/bin/mountpoint -q ' + REFERENCES_BACKING_GUEST_PATH)
        script = f'''set -euo pipefail
state_dir={PERSISTENT_VIEW_STATE_GUEST_PATH}/{folder.lower()}-{digest}
[ ! -L "$state_dir" ] || exit 72
for name in pid token signature; do [ -s "$state_dir/$name" ] && [ ! -L "$state_dir/$name" ] || exit 72; done
pid=$(cat "$state_dir/pid"); token=$(cat "$state_dir/token")
case "$pid" in *[!0-9]*|'') exit 72 ;; esac
first=$(tr '\\000' '\\n' <"/proc/$pid/cmdline" | head -n 1)
[ "$first" = "harnessy-project-view-$token" ] || exit 72
exec /usr/bin/nsenter --target "$pid" --mount --pid -- /bin/bash -c {shlex.quote(probe)}
'''
        rc, _, _ = await self._run('shell', '--workdir', '/', self.INSTANCE, 'sudo', '/bin/bash', '-c',
                                   script, timeout=12, check=False)
        return rc == 0

    async def reconcile_file_views(self, plan: dict[str, Any]) -> dict[str, Any]:
        from .activity import reserve_project_view_change
        from harnessy.core.project_mounts import build_project_policy
        from .file_views import FILE_VIEWS, finish_file_view_work
        workspace = FILE_VIEWS.cached_workspace(self.workspace_root)
        if workspace is None or plan.get('environment_id') != self.config.id:
            raise RuntimeError('Project file plan identity could not be verified.')
        records = self._file_view_records()
        boot_id = str(self._read_readiness().get('boot_id') or '')
        if records.get('boot_id') != boot_id:
            records = {'boot_id': boot_id, 'projects': {}}
        actual = records.setdefault('projects', {})
        desired = {row['project_id']: row for row in plan['projects']}
        known = {row['project_id']: row for row in plan['known_projects']}
        rows, pending, errors = [], [], []
        verified = getattr(self, '_verified_file_views', set())
        self._verified_file_views = verified
        for project_id, row in known.items():
            target = desired.get(project_id)
            policy = target['policy'] if target else None
            previous = actual.get(project_id, {})
            revision = policy['policy_revision'] if policy else ''
            if self.config.files_mode == 'copy':
                # Preserve independent copies; selecting access never refreshes
                # or deletes them. Explicit project operations deploy as before.
                rows.append({'project_id': project_id, 'folder': row['folder'],
                             'state': 'ready' if target else 'removed',
                             'policy_revision': revision,
                             'detail': 'Independent project copy; deployment and collection are explicit.'})
                continue
            marker = (project_id, revision, boot_id)
            if target and previous.get('policy_revision') == revision and boot_id:
                try:
                    present = marker in verified or await self._probe_project_view(policy)
                except Exception:
                    present = False
                if present:
                    verified.add(marker)
                    rows.append({'project_id': project_id, 'folder': row['folder'], 'state': 'ready', 'policy_revision': revision})
                    continue
            if not target and previous.get('removed') and boot_id:
                rows.append({'project_id': project_id, 'folder': row['folder'], 'state': 'removed'})
                continue
            try:
                release = reserve_project_view_change(self.workspace_root, environment_id=self.config.id,
                    project_id=project_id, owner_id=str(plan.get('_owner_id') or ''))
            except RuntimeError as exc:
                pending.append(project_id)
                rows.append({'project_id': project_id, 'folder': row['folder'], 'state': 'pending', 'detail': str(exc)})
                continue
            try:
                if target:
                    fresh = await finish_file_view_work(build_project_policy, workspace, project_id)
                    if fresh['policy_revision'] != revision:
                        raise RuntimeError('Project source policy changed while preparing its mount view.')
                    command = self._workspace_view_command(':', cwd='/workspace/Files/' + row['folder'],
                        active_root=Path(policy['project_root']), output_policy=policy)
                    await self._run('shell', '--workdir', '/', self.INSTANCE, '/bin/bash', '-lc',
                                    command, timeout=45, check=True)
                    fresh = await finish_file_view_work(build_project_policy, workspace, project_id)
                    if fresh['policy_revision'] != revision:
                        raise RuntimeError('Project source identities changed while mounting its view.')
                    actual[project_id] = {'folder': row['folder'], 'policy_revision': revision}
                    verified.add(marker)
                    rows.append({'project_id': project_id, 'folder': row['folder'], 'state': 'ready', 'policy_revision': revision})
                else:
                    await self._retire_project_view(row['folder'])
                    actual[project_id] = {'folder': row['folder'], 'removed': True}
                    verified.difference_update(item for item in tuple(verified) if item[0] == project_id)
                    rows.append({'project_id': project_id, 'folder': row['folder'], 'state': 'removed'})
            except Exception as exc:
                errors.append(project_id)
                rows.append({'project_id': project_id, 'folder': row['folder'], 'state': 'error',
                             'error_code': 'FILE_VIEW_MOUNT_FAILED', 'detail': str(exc)[:500]})
            finally:
                release()
        references = await self._reconcile_references_view(plan, records, workspace)
        self._save_file_view_records(records)
        references_state = references.get('state')
        failed = bool(errors) or references_state not in ('ready', 'pending')
        waiting = bool(pending) or references_state == 'pending'
        return {'state': 'error' if failed else 'pending' if waiting else 'ready', 'revision': plan['revision'],
                'projects': rows, 'references': references, 'pending_project_ids': pending,
                'error_code': (references.get('error_code') or 'FILE_VIEW_MOUNT_FAILED') if failed else '',
                'detail': ('Unmount pending: finish affected project work.' if pending else references.get('detail'))
                           if waiting else 'Project file views verified.'}

    async def open_project_terminal(self, *, active_root: Path, output_policy: dict[str, Any], workspace=None):
        self._authorize_model_project(output_policy)
        await self._ensure_running()
        from .file_views import FILE_VIEWS
        project_id = output_policy.get('_human_project_id') or output_policy.get('_model_project_id')
        if not project_id:
            raise RuntimeError('A project-files terminal requires an authoritative project identity.')
        verified = await FILE_VIEWS.ensure_project(self.workspace_root, environment_id=self.config.id,
            project_id=project_id, owner_id=str(output_policy.get('_file_view_owner_id') or ''),
            human='_human_project_id' in output_policy)
        if verified['policy_revision'] != output_policy.get('policy_revision'):
            raise FileViewUnavailableError('Project file policy changed before this terminal could start.', 'FILE_VIEW_POLICY_CHANGED')
        if self.config.files_mode == 'copy':
            await asyncio.to_thread(self._prepare_project_copy, active_root, output_policy)
        self._authorize_model_project(output_policy)
        from harnessy.core.terminal import guest_activity_shell_command
        command = self._workspace_view_command(guest_activity_shell_command(),
            cwd='/workspace/Files/' + output_policy['writable_folder'], active_root=active_root, output_policy=output_policy)
        return ([self._binary(), 'shell', '--workdir', '/', self.INSTANCE, '/bin/bash', '-lc', command],
                self._host_env(), self.workspace_root)

    async def open_guest_terminal(self, *, workspace=None, owner_id: str = '') -> tuple[list[str], dict[str, str], Path]:
        """Open guest home with live RO References and no Project exports."""
        from .file_views import FILE_VIEWS, finish_file_view_work
        from harnessy.core.project_mounts import build_references_policy
        if workspace is not None:
            if Path(workspace.root).resolve() != self.workspace_root.resolve():
                raise ValueError('The guest console workspace identity does not match this VM.')
        if FILE_VIEWS.cached_workspace(self.workspace_root) is None:
            raise FileViewUnavailableError('Open the workspace again before opening its References console.', 'FILE_VIEW_FAILED')
        owner_id = str(owner_id or uuid.uuid4().hex)
        release = await FILE_VIEWS.acquire_terminal_activity(self.workspace_root, environment_id=self.config.id,
            project_id='__guest_console__', owner_id=owner_id, label='Opening VM guest console')
        try:
            await self.start()
            policy = await FILE_VIEWS.ensure_references(self.workspace_root, environment_id=self.config.id,
                                                       owner_id=owner_id)
            admitted = FILE_VIEWS.cached_workspace(self.workspace_root)
            if admitted is None:
                raise FileViewUnavailableError('Open the workspace again before opening its References console.', 'FILE_VIEW_FAILED')
            try:
                fresh = await finish_file_view_work(build_references_policy, admitted)
            except (OSError, ValueError) as exc:
                raise FileViewUnavailableError('References changed before this console could open.', 'FILE_VIEW_POLICY_CHANGED') from exc
            if (FILE_VIEWS.cached_workspace(self.workspace_root) is not admitted
                    or fresh['policy_revision'] != policy['policy_revision']):
                raise FileViewUnavailableError('References changed before this console could open.', 'FILE_VIEW_POLICY_CHANGED')
            return await asyncio.to_thread(self._guest_terminal_command, policy)
        finally:
            release()

    def _guest_terminal_command(self, policy: dict[str, Any]) -> tuple[list[str], dict[str, str], Path]:
        # Enter only the independently verified console namespace; never deploy
        # a Project or rebuild a stale keeper while a PTY is being created.
        from harnessy.core.terminal import _GUEST_ACTIVITY_RC
        console_rc = (_GUEST_ACTIVITY_RC + '\ncd -- "$HOME" || exit 72\n'
                      + self._guest_work_path_exports())
        command = 'exec /bin/bash --rcfile <(printf %s ' + shlex.quote(console_rc) + ') -i'
        view_command = self._references_view_command(policy, command)
        argv = [self._binary(), 'shell', '--workdir', '/', self.INSTANCE, '/bin/bash', '-lc', view_command]
        return argv, self._host_env(), self.workspace_root

    def terminal_command(self, *, active_root: Path | None = None) -> tuple[list[str], dict[str, str], Path]:
        binary = self._binary()
        from harnessy.core.terminal import guest_activity_shell_command
        if self.config.files_mode == 'copy':
            self._prepare_project_copy(active_root)
        view_command = self._workspace_view_command(
            guest_activity_shell_command(), cwd=WORKSPACE_VIEW_GUEST_PATH,
            active_root=active_root,
        )
        argv = [binary, 'shell', '--workdir', '/', self.INSTANCE, '/bin/bash', '-lc', view_command]
        return argv, self._host_env(), self.workspace_root

    def desktop_manager(self, workspace):
        return _LimaDesktopView(self, workspace)

    def _host_storage_usage(self):
        from .storage_probe import host_disk_usage, LIMA_DISK_NAMES
        return host_disk_usage(self.vm_root / self.INSTANCE, LIMA_DISK_NAMES)

    async def storage_usage(self) -> dict[str, Any]:
        from .storage_probe import (LINUX_STORAGE_PYTHON, parse_linux_storage,
                                    storage_result, unavailable_guest)
        host = await asyncio.to_thread(self._host_storage_usage)
        try:
            row = await asyncio.wait_for(self._instance_row(), 2)
        except (OSError, RuntimeError, ValueError, asyncio.TimeoutError):
            return storage_result(unavailable_guest(), host)
        if not row:
            guest = unavailable_guest() if (self.vm_root / self.INSTANCE).exists() else unavailable_guest('GUEST_STORAGE_STOPPED', state='stopped')
            return storage_result(guest, host)
        state = str(row.get('status') or row.get('Status') or '').lower()
        if state != 'running':
            guest = unavailable_guest('GUEST_STORAGE_STOPPED', state='stopped') if state == 'stopped' else unavailable_guest()
            return storage_result(guest, host)
        try:
            rc, output, _ = await self._run('shell', '--workdir', '/', self.INSTANCE, '/bin/sh', '-c',
                'python3 -I -S -B -c ' + shlex.quote(LINUX_STORAGE_PYTHON), timeout=5, check=False)
            guest = parse_linux_storage(output) if rc == 0 else unavailable_guest('GUEST_STORAGE_PROBE_FAILED')
        except (OSError, RuntimeError, ValueError, asyncio.TimeoutError):
            guest = unavailable_guest('GUEST_STORAGE_PROBE_FAILED')
        return storage_result(guest, host)

    async def usage_snapshot(self, *, include_storage: bool = False) -> dict[str, Any]:
        from .resource_probe import build_usage_script, parse_usage_output, unavailable_resources
        from .storage_probe import LINUX_STORAGE_PYTHON, parse_linux_storage, storage_result, unavailable_guest
        host = await asyncio.to_thread(self._host_storage_usage) if include_storage else None

        def result(resources, guest=None):
            return {'schema_version': 1, 'resources': resources,
                    'storage': storage_result(guest, host) if include_storage else None}

        try:
            row = await asyncio.wait_for(self._instance_row(), 2)
        except (OSError, RuntimeError, ValueError, asyncio.TimeoutError):
            return result(unavailable_resources(), unavailable_guest())
        if not row:
            stopped = not (self.vm_root / self.INSTANCE).exists()
            return result(unavailable_resources('GUEST_RESOURCES_STOPPED', state='stopped') if stopped else unavailable_resources(),
                          unavailable_guest('GUEST_STORAGE_STOPPED', state='stopped') if stopped else unavailable_guest())
        state = str(row.get('status') or row.get('Status') or '').lower()
        if state != 'running':
            stopped = state == 'stopped'
            return result(unavailable_resources('GUEST_RESOURCES_STOPPED', state='stopped') if stopped else unavailable_resources(),
                          unavailable_guest('GUEST_STORAGE_STOPPED', state='stopped') if stopped else unavailable_guest())
        try:
            storage_script = 'python3 -I -S -B -c ' + shlex.quote(LINUX_STORAGE_PYTHON) if include_storage else None
            rc, output, _ = await self._run('shell', '--workdir', '/', self.INSTANCE, '/bin/sh', '-c',
                build_usage_script(storage_script), timeout=5, check=False)
            if rc != 0:
                return result(unavailable_resources('GUEST_RESOURCES_PROBE_FAILED'), unavailable_guest('GUEST_STORAGE_PROBE_FAILED'))
            resources, guest = parse_usage_output(output, include_storage=include_storage, storage_parser=parse_linux_storage)
            return result(resources, guest)
        except (OSError, RuntimeError, ValueError, asyncio.TimeoutError):
            return result(unavailable_resources('GUEST_RESOURCES_PROBE_FAILED'), unavailable_guest('GUEST_STORAGE_PROBE_FAILED'))

    async def inspect(self) -> dict[str, Any]:
        status = await self.status()
        snapshot_error = ''
        try:
            snapshots = await self._list_snapshots_for_status(status)
        except Exception as exc:
            snapshots = None
            snapshot_error = str(exc)
        host_storage = await asyncio.to_thread(self._host_storage_usage)
        storage_compat = {}
        if host_storage['allocated_bytes'] is not None:
            storage_compat['vm_storage_bytes'] = host_storage['allocated_bytes']
        if host_storage['logical_bytes'] is not None:
            storage_compat['vm_storage_logical_bytes'] = host_storage['logical_bytes']
        return {
            'environment_id': self.config.id,
            'environment_name': self.config.name,
            'runtime_identity': self.runtime_identity(),
            'verified_guest': self._read_verified_guest(),
            'config': self.config.to_dict(),
            'status': status.to_dict(),
            'snapshots': snapshots,
            '_snapshot_list_error': snapshot_error,
            **storage_compat,
            'files_root': str(self.files_root),
            'guest_files_root': '/workspace',
            'durable_vm_root': str(self.vm_root),
            'runtime_lima_home': str(self._runtime_home()),
            'vm_type': self._vm_type(),
            'mount_type': self._mount_type(),
            'snapshot_strategy': 'lima-clone' if self._uses_clone_snapshots() else 'lima-native',
        }
