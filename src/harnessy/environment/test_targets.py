"""Independent, internet-connected test guests; never workspace environments.

Only the target controllers invoke host Lima/QEMU. Guests receive copied test files, no
host mounts, forwarded credentials, or workspace controller metadata.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import re
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Any

from .host_prerequisites import discover_binary, repaired_path
from .presets import canonical_arch
from .test_catalog import guest_os, KALI_IMAGES, target_architectures


def normalize_vm_config(raw: dict[str, Any]) -> dict[str, Any]:
    os_name = str(raw.get('os') or 'ubuntu-24.04')
    guest = guest_os(os_name)
    arch = canonical_arch(str(raw.get('architecture') or platform.machine()))
    if arch not in target_architectures(os_name):
        raise ValueError('Choose an architecture available for this operating system and release.')
    mips = arch.startswith('mips')
    def number(key, default, low, high):
        value = int(raw.get(key, default))
        if not low <= value <= high:
            raise ValueError(f'{key} must be between {low} and {high}.')
        return value
    iso = str(raw.get('iso_path') or '').strip()
    if any(c in iso for c in ('\x00', '\n', '\r')):
        raise ValueError('Invalid installer path.')
    if os_name == 'windows-11' and not iso:
        raise ValueError('Select a Windows 11 English (United States) ISO on the HarnessyXO host.')
    emulation = raw.get('emulation', {})
    if not isinstance(emulation, dict) or any(
        not isinstance(emulation.get(key, False), bool) for key in ('wifi', 'bluetooth')
    ):
        raise ValueError('Radio emulation settings must be true or false.')
    emulation = {key: emulation.get(key, False) for key in ('wifi', 'bluetooth')}
    if guest.family != 'openwrt' and any(emulation.values()):
        raise ValueError('Radio emulation is currently available only for OpenWrt test targets.')
    return {
        'os': os_name, 'architecture': arch,
        'cpu': number('cpu', 1 if mips else guest.cpu, 2 if os_name == 'windows-11' else 1, 1 if mips else 32),
        'memory_mb': number('memory_mb', guest.memory, guest.min_memory, 2048 if mips else 131072),
        'disk_gb': number('disk_gb', guest.disk, guest.min_disk, 2048 if guest.family != 'openwrt' else 64),
        'desktop': bool(raw.get('desktop', True)), 'internet': True,
        'iso_path': iso if os_name == 'windows-11' else '',
        'emulation': emulation,
    }


class TestTargetFailure(RuntimeError):
    """User-visible failure with a fixed, content-free diagnostic identity."""
    __test__ = False

    def __init__(self, message: str, code: str, *, returncode: int | None = None):
        super().__init__(message)
        self.failure_code, self.returncode = code, returncode


@dataclass
class TargetOperation:
    action: str
    state: str = 'running'
    output: str = ''
    error: str = ''
    task: asyncio.Task | None = None
    started: float = field(default_factory=time.monotonic)
    stage: str = 'prerequisites'
    stage_timeout_seconds: float = 0.0
    failure_code: str = 'none'
    operation_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def note(self, text: str) -> None:
        self.output = (self.output + str(text))[-60000:]


def target_operation_error(operation: TargetOperation, error: BaseException | None = None) -> str:
    """Always provide an actionable failure, including for empty TimeoutError."""
    text = str(error if error is not None else operation.error or '').strip()
    code = str(operation.failure_code or 'controller_failed')
    if code == 'none':
        code = 'controller_failed'
    stage = {
        'prerequisites': 'checking host requirements', 'download': 'downloading the guest image',
        'prepare_disk': 'preparing the guest disk', 'launch': 'launching the guest',
        'launch_reconcile': 'checking the VM after the launcher timed out',
        'wait_ssh': 'waiting for guest SSH', 'probe_shell': 'checking the guest shell',
        'radio_setup': 'setting up emulated radios',
    }.get(operation.stage, str(operation.stage or 'setup').replace('_', ' '))
    action = 'Start setup' if operation.action == 'start' else (
        'Radio setup' if operation.action == 'radios' else operation.action.capitalize())
    fallback = not text
    timeout_error = isinstance(error, (TimeoutError, asyncio.TimeoutError)) or (fallback and code.endswith('timeout'))
    if timeout_error:
        timeout = max(0.0, float(getattr(operation, 'stage_timeout_seconds', 0) or 0))
        duration = f' after {timeout:g} seconds' if timeout else ' at its configured time limit'
        text = f'{action} timed out{duration} while {stage} [{code}].' + (f' {text}' if text else '')
    elif not text:
        kind = type(error).__name__ if error is not None else 'controller error'
        text = f'{action} failed while {stage} [{code}; {kind}].'
    if operation.action == 'start' and (timeout_error or fallback):
        if operation.stage in {'launch', 'launch_reconcile', 'wait_ssh', 'probe_shell'}:
            text += ' The guest may still be booting or running.'
        text += ' Retry Start to check the existing VM and finish setup without replacing its disk.'
    return text


_OPERATIONS: dict[str, TargetOperation] = {}
_ACTIVE: dict[str, int] = {}
_RADIOS: dict[str, tuple[float, dict[str, Any]]] = {}
_VIEW_CLEANUP: list[Any] = []
# Retain the validated controllers this process has used independently of a
# replaceable workspace database/store. A repair can invalidate every old store
# while its already-running test guests still need normal host shutdown.
_MANAGERS: dict[str, 'TestTargetManager'] = {}
_MANAGERS_LOCK = RLock()


def register_target_view_cleanup(callback) -> None:
    """Register a UI transport cleanup without a controller-to-UI import."""
    if callback not in _VIEW_CLEANUP:
        _VIEW_CLEANUP.append(callback)


class TestTargetManager:
    __test__ = False

    def __new__(cls, workspace, target):
        if cls is TestTargetManager and target.managed_vm and guest_os(target.managed_vm.get('os', 'ubuntu-24.04')).family == 'openwrt':
            from .openwrt_target import OpenWrtTargetManager
            return object.__new__(OpenWrtTargetManager)
        return object.__new__(cls)

    def __init__(self, workspace, target):
        if not target.managed_vm or not re.fullmatch(r'[a-f0-9]{32}', target.id):
            raise ValueError('This is not a managed test VM.')
        self.workspace, self.target = workspace, target
        self.config = normalize_vm_config(target.managed_vm)
        self.guest = guest_os(self.config['os'])
        self.root = workspace.meta / 'test_targets' / target.id
        self.home = self.root / 'lima'
        if self.root.parent.is_symlink() or self.root.is_symlink() or self.home.is_symlink():
            raise ValueError('Managed VM state directories cannot be symbolic links.')
        self.instance = 'test'
        self.instance_dir = self.home / self.instance
        self.key = str(self.root.resolve())
        self.windows = self.config['os'] == 'windows-11'
        self.backend = 'qemu' if self.guest.family == 'openwrt' else 'lima'
        from harnessy.diagnostics.test_target_logs import register_test_target_runtime
        register_test_target_runtime(Path(self.key), self.backend)
        if type(self) is TestTargetManager:
            self._remember_for_shutdown()

    def _remember_for_shutdown(self) -> None:
        # Subclasses call this only after their additional path validation.
        with _MANAGERS_LOCK:
            _MANAGERS[self.key] = self

    def stage(self, stage: str, *, attempt: int = 0, timeout_seconds: float = 0,
              failure_code: str = 'none', returncode: int | None = None) -> None:
        from harnessy.diagnostics import log_event
        op = self.operation
        if op:
            op.stage = stage
            op.stage_timeout_seconds = max(0.0, float(timeout_seconds or 0))
        fields = dict(target_id=self.target.id, target_backend=self.backend,
                      operation_id=op.operation_id if op else '',
                      target_action=op.action if op else 'connection_test',
                      target_stage=stage, target_outcome='running',
                      target_failure_code=failure_code, attempt=max(0, attempt),
                      elapsed_seconds=max(0, time.monotonic() - op.started) if op else 0,
                      timeout_seconds=max(0, timeout_seconds))
        if returncode is not None:
            fields['returncode'] = returncode
        log_event('runtime', 'test_target_operation_stage', **fields)

    @property
    def operation(self) -> TargetOperation | None:
        return _OPERATIONS.get(self.key)

    @property
    def busy(self) -> bool:
        op = self.operation
        return bool(op and op.task and not op.task.done())

    def acquire(self):
        _ACTIVE[self.key] = _ACTIVE.get(self.key, 0) + 1
        released = False
        def release():
            nonlocal released
            if not released:
                released = True
                _ACTIVE[self.key] = max(0, _ACTIVE.get(self.key, 0) - 1)
        return release

    def radio_state(self) -> dict[str, Any]:
        """Describe configured emulation without claiming a cached probe is live."""
        from .test_radios import public_radio_snapshot
        cached = _RADIOS.get(self.key)
        requested = self.config['emulation']
        state = public_radio_snapshot(cached[1] if cached else {
            kind: {'requested': requested[kind],
                   'status': 'unverified' if requested[kind] else 'disabled',
                   'reason': 'not_detected' if requested[kind] else 'not_requested'}
            for kind in ('wifi', 'bluetooth')
        })
        for kind in ('wifi', 'bluetooth'):
            state[kind]['requested'] = requested[kind]
        state['observation'] = 'last_guest_probe' if cached else 'not_probed'
        state['probe_age_seconds'] = round(max(0, time.monotonic() - cached[0]), 3) if cached else None
        state['current_state_verified'] = False
        return state

    async def _radio_command(self, script: str, *, timeout: float = 20) -> str:
        from harnessy.agent.external_targets import ExternalTargetBroker
        from harnessy.diagnostics.radio_setup import record_radio_setup_evidence
        result, failure = None, None
        try:
            result = await ExternalTargetBroker(self.workspace)._run_ssh(
                self.target, 'sh -s', input_bytes=script.encode('utf-8'), timeout=timeout,
            )
            if not result.ok:
                raise RuntimeError('The optional guest radio command failed.')
            return result.stdout
        except (OSError, RuntimeError, TimeoutError, asyncio.CancelledError) as error:
            failure = error
            raise
        finally:
            if self.backend == 'qemu':
                try:
                    record_radio_setup_evidence(
                        self.runtime_dir(), script,
                        stdout=getattr(result, 'stdout', '').encode('utf-8'),
                        stderr=getattr(result, 'stderr', '').encode('utf-8'),
                        returncode=getattr(result, 'returncode', None), error=failure,
                        timeout_seconds=timeout, command='sh -s',
                    )
                except (OSError, RuntimeError, ValueError):
                    pass  # A diagnostics write cannot change guest readiness.

    def radio_repair_hint(self) -> str:
        return 'Use Set up / repair radios on this running VM to retry.'

    async def inspect_radios(self) -> dict[str, Any]:
        from .test_radios import probe_radios
        state = await probe_radios(self.config['emulation'], self._radio_command)
        _RADIOS[self.key] = (time.monotonic(), state)
        self._record_radio_result(state, observation='probe')
        while len(_RADIOS) > 64:
            _RADIOS.pop(next(iter(_RADIOS)))
        return {**state, 'observation': 'live_guest_probe', 'probe_age_seconds': 0,
                'current_state_verified': all(
                    state[kind]['status'] not in {'unverified', 'error'}
                    for kind in ('wifi', 'bluetooth'))}

    def _record_radio_result(self, state: dict[str, Any], *, observation: str) -> None:
        from harnessy.diagnostics import log_event
        for kind in ('wifi', 'bluetooth'):
            item = state[kind]
            op = self.operation
            log_event('runtime', 'test_target_radio_result', target_id=self.target.id,
                      target_backend=self.backend,
                      operation_id=op.operation_id if op and self.busy else '',
                      target_action=op.action if op and self.busy else 'status',
                      target_stage='radio_setup', target_radio_kind=kind,
                      target_radio_backend=item['backend'],
                      target_radio_observation=observation,
                      target_radio_status=item['status'], target_radio_reason=item['reason'],
                      target_radio_detail=item.get('detail_code', 'none'),
                      target_radio_requested=item['requested'], target_radio_verified=item['verified'],
                      target_radio_count=item['radio_count'], target_radio_interface_count=item['interface_count'])

    async def configure_radios(self) -> None:
        if self.guest.family != 'openwrt':
            _RADIOS.pop(self.key, None)
            return
        from .test_radios import configure_radios, radio_summary, stop_radios
        if not self.config['emulation']['bluetooth']:
            # An unchecked selection must not restart our persistent controller
            # service. Guest packages and unrelated Bluetooth services stay put.
            try:
                await stop_radios(self._radio_command)
            except (OSError, RuntimeError, TimeoutError):
                self.stage('radio_setup', failure_code='radio_setup_failed')
                raise TestTargetFailure(
                    'The VM shell is running, but the managed Bluetooth controllers could not be stopped. '
                    'Retry Start on this running VM to complete controller cleanup.',
                    'radio_setup_failed',
                ) from None
        if not any(self.config['emulation'].values()):
            _RADIOS.pop(self.key, None)
            return
        self.stage('radio_setup', timeout_seconds=900)
        if self.operation:
            self.operation.note('Checking requested guest radios. Installing signed packages for this exact OpenWrt release. First-time Bluetooth setup may take several minutes; its package stage has a 10-minute limit.\n')
        state = await configure_radios(
            self.config['emulation'], self._radio_command, arch=self.config['architecture'],
            on_stage=lambda stage: self.stage(stage, timeout_seconds={
                'bluetooth_packages': 600, 'bluetooth_emulator': 30,
                'bluetooth_attach': 45, 'bluetooth_verify': 15,
            }.get(stage, 240)),
        )
        _RADIOS[self.key] = (time.monotonic(), state)
        self._record_radio_result(state, observation='setup')
        if self.operation:
            self.operation.note('\n' + radio_summary(state) + '\n')
        if any(state[kind]['requested'] and (not state[kind]['verified'] or state[kind]['reason'] in {
            'interface_create_failed', 'insufficient_radios', 'insufficient_controllers',
        }) for kind in ('wifi', 'bluetooth')):
            self.stage('radio_setup', failure_code='radio_setup_failed')
            raise TestTargetFailure(
                'The VM shell is running, but requested radio setup is incomplete. '
                + radio_summary(state)
                + ' ' + self.radio_repair_hint() + ' '
                + 'Inspect Wi-Fi with iw dev and iw phy; AP/station configuration remains yours. '
                'Bluetooth setup needs matching guest packages and the bundled software controller helper.',
                'radio_setup_failed',
            )

    def forget_radios(self) -> None:
        _RADIOS.pop(self.key, None)

    def invalidate_views(self) -> None:
        # Runs before a controller can stop a VM or allocate replacement ports.
        # Callbacks close only capabilities belonging to this exact target root.
        for callback in tuple(_VIEW_CLEANUP):
            try:
                callback(self.key)
            except Exception:
                from harnessy.diagnostics import log_event
                log_event('runtime', 'test_target_view_cleanup_failed',
                          target_id=self.target.id, target_backend=self.backend,
                          target_action='web', target_stage='connection_test',
                          target_outcome='failed', target_failure_code='controller_failed')

    def _env(self) -> dict[str, str]:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Short runtime alias avoids macOS's Unix socket path-length limit.
        base = Path(tempfile.gettempdir()) / f'harnessy-test-lima-{os.getuid()}'
        base.mkdir(mode=0o700, exist_ok=True)
        if base.is_symlink() or base.stat().st_uid != os.getuid():
            raise RuntimeError('Test VM runtime directory is not owned by this user.')
        base.chmod(0o700)
        alias = base / hashlib.sha256(str(self.home.resolve()).encode()).hexdigest()[:16]
        if alias.is_symlink():
            if alias.resolve() != self.home.resolve():
                raise RuntimeError('Test VM runtime alias points to another directory.')
        elif alias.exists():
            raise RuntimeError('Test VM runtime alias is occupied.')
        else:
            alias.symlink_to(self.home.resolve(), target_is_directory=True)
        env = os.environ.copy()
        env.update(PATH=repaired_path(), LIMA_HOME=str(alias))
        for name in ('SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'LIMA_INSTANCE', 'LIMA_SHELL', 'LIMA_WORKDIR'):
            env.pop(name, None)
        return env

    def _binary(self) -> str:
        path = discover_binary('limactl')
        if not path:
            raise RuntimeError('Lima is required on the HarnessyXO host. Install Lima and QEMU, then retry Start.')
        return path

    async def _run(self, *args: str, timeout: float = 120, input_bytes: bytes | None = None, check=True) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            self._binary(), *args, env=self._env(), cwd=self.root,
            stdin=asyncio.subprocess.PIPE if input_bytes is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        buffers = ['', '']
        async def read(stream, index):
            while chunk := await stream.read(4096):
                text = chunk.decode('utf-8', errors='replace')
                buffers[index] = (buffers[index] + text)[-100000:]
                if self.operation and self.busy and args and args[0] in {'create', 'start', 'stop', 'delete'}:
                    self.operation.note(text)
        async def drive():
            if input_bytes is not None:
                proc.stdin.write(input_bytes)
                await proc.stdin.drain()
                proc.stdin.close()
            await asyncio.gather(read(proc.stdout, 0), read(proc.stderr, 1))
            return await proc.wait()
        try:
            rc = await asyncio.wait_for(drive(), timeout)
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
        if check and rc:
            raise RuntimeError((buffers[1] or buffers[0] or f'Lima exited {rc}')[-3000:])
        return rc, buffers[0], buffers[1]

    def vm_document(self) -> dict[str, Any]:
        c = self.config
        document = {
            'minimumLimaVersion': self.minimum_lima_version,
            'base': 'template:' + self.guest.template,
            'vmType': 'qemu', 'arch': 'aarch64' if c['architecture'] == 'arm64' else 'x86_64',
            'cpus': c['cpu'], 'memory': f"{c['memory_mb']}MiB", 'disk': f"{c['disk_gb']}GiB",
            'mounts': [], 'mountInotify': False, 'plain': True,
            'containerd': {'system': False, 'user': False},
            'user': {'name': 'harnessy', 'home': 'C:/Users/harnessy' if self.windows else '/home/harnessy'},
            'ssh': {'forwardAgent': False, 'forwardX11': False, 'forwardX11Trusted': False},
            'propagateProxyEnv': False,
            'portForwards': [{'guestPortRange': [1, 65535], 'ignore': True}],
            'video': {'display': 'vnc', 'vnc': {'display': '127.0.0.1:0,to=99'}} if c['desktop'] else {'display': 'none'},
        }
        if self.windows:
            document['os'] = 'Windows'
            document['tpm'] = True
            document['images'] = [{'location': str(Path(c['iso_path']).expanduser().resolve()), 'arch': document['arch']}]
        else:
            if self.config['os'].startswith('kali-'):
                document.pop('base')
                document['images'] = [{'location': str(self.root / 'images' / 'kali.img'), 'arch': document['arch']}]
            script = '''#!/bin/bash
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl python3
install -d -o harnessy -g harnessy /home/harnessy/hx-test
'''
            if c['desktop']:
                script += '''echo 'lightdm shared/default-x-display-manager select lightdm' | debconf-set-selections
apt-get install -y --no-install-recommends xorg xfce4 xfce4-terminal lightdm dbus-x11
mkdir -p /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/50-harnessy-test.conf <<'DESKTOP'
[Seat:*]
autologin-user=harnessy
autologin-user-timeout=0
user-session=xfce
DESKTOP
systemctl set-default graphical.target
systemctl enable lightdm
systemctl restart lightdm
'''
            if self.guest.family == 'fedora':
                script = script.replace('export DEBIAN_FRONTEND=noninteractive\napt-get update\napt-get install -y ca-certificates curl python3',
                                        'dnf install -y ca-certificates curl python3')
                script = script.replace("echo 'lightdm shared/default-x-display-manager select lightdm' | debconf-set-selections\n", '')
                script = script.replace('apt-get install -y --no-install-recommends xorg xfce4 xfce4-terminal lightdm dbus-x11',
                                        'dnf install -y @xfce-desktop-environment lightdm xorg-x11-server-Xorg')
                script = script.replace('user-session=xfce', 'user-session=xfce')
            document['provision'] = [{'mode': 'system', 'script': script}]
        return document

    @property
    def minimum_lima_version(self):
        return '2.0.0' if self.config['os'] in {'ubuntu-24.04', 'kali-2026.2'} else '2.2.0'

    def _prerequisite_progress(self, phase: str, message: str, **metadata) -> None:
        operation = self.operation
        if operation:
            detail = str(metadata.get('detail') or '').strip()
            operation.note(message + (' ' + detail if detail else '') + '\n')

    async def prerequisites(self):
        _, out, err = await self._run('--version')
        match = re.search(r'(\d+)\.(\d+)\.(\d+)', out + err)
        required = tuple(map(int, self.minimum_lima_version.split('.')))
        if not match or tuple(map(int, match.groups())) < required:
            raise RuntimeError('This test VM needs Lima ' + '.'.join(map(str, required)) + ' or later. Update Lima on the host and retry.')
        binaries = ['qemu-img', 'qemu-system-aarch64' if self.config['architecture'] == 'arm64' else 'qemu-system-x86_64']
        if self.windows:
            binaries.append('swtpm')
        missing = [name for name in binaries if not discover_binary(name)]
        if missing:
            raise RuntimeError('Missing test VM host prerequisites: ' + ', '.join(missing) + '. Install QEMU' + (' and swtpm' if self.windows else '') + ', then retry Start.')

    async def status(self) -> dict[str, Any]:
        if not self.instance_dir.exists():
            return {'state': 'not_created', 'running': False, 'created': False}
        _, out, _ = await self._run('list', '--json', self.instance, timeout=30)
        rows = []
        for line in out.splitlines():
            try:
                item = json.loads(line)
                rows.extend(item if isinstance(item, list) else [item])
            except json.JSONDecodeError:
                continue
        row = next((x for x in rows if isinstance(x, dict) and x.get('name') == self.instance), None)
        if row is None:
            raise RuntimeError('Lima did not report this test VM; its state is unknown.')
        state = str(row.get('status') or 'unknown').lower()
        return {'state': state, 'running': state == 'running', 'created': True, 'architecture': self.config['architecture'], 'internet': True}

    def begin(self, action: str, *, tag: str = '') -> TargetOperation:
        if action not in {'start', 'stop', 'snapshot', 'restore', 'delete', 'radios'}:
            raise ValueError('Unsupported test VM action.')
        if self.busy:
            raise RuntimeError('A test VM operation is already running. Wait for it to finish.')
        if action in {'snapshot', 'restore', 'delete'} and _ACTIVE.get(self.key, 0):
            raise RuntimeError('Close this target’s shell and graphical interface tabs, and finish its commands before changing VM data.')
        op = TargetOperation(action, stage='prerequisites' if action == 'start' else
                             'radio_setup' if action == 'radios' else ('stopped' if action == 'stop' else action))
        _OPERATIONS[self.key] = op
        async def work():
            from harnessy.diagnostics import log_event
            from harnessy.diagnostics.test_target_logs import classify_target_failure
            started = time.monotonic()
            log_event('runtime', 'test_target_operation_started', target_id=self.target.id,
                      operation_id=op.operation_id,
                      target_backend=self.backend, target_action=action, target_stage=op.stage,
                      target_outcome='running', elapsed_seconds=0)
            try:
                op.note(f'{action.capitalize()} · {self.target.name}\n')
                if action == 'start':
                    await self.start()
                elif action == 'radios':
                    if self.guest.family != 'openwrt' or not (await self.status()).get('running'):
                        raise TestTargetFailure('Start this OpenWrt VM before setting up its radios.', 'radio_setup_failed')
                    await self.configure_radios()
                elif action == 'stop':
                    await self.stop()
                elif action == 'snapshot':
                    await self.snapshot(tag)
                elif action == 'restore':
                    self.forget_radios()
                    await self.restore(tag)
                else:
                    await self.delete()
                op.state = 'succeeded'
            except asyncio.CancelledError:
                op.state, op.error = 'cancelled', 'Operation cancelled; check VM status before retrying.'
                op.failure_code = 'cancelled'
            except Exception as exc:
                op.state = 'failed'
                op.failure_code = getattr(exc, 'failure_code', None) or (
                    'controller_timeout' if isinstance(exc, (TimeoutError, asyncio.TimeoutError)) else classify_target_failure(exc))
                if op.stage == 'prerequisites' and op.failure_code == 'controller_failed':
                    op.failure_code = 'host_dependency_missing'
                op.error = target_operation_error(op, exc)
                op.note('\n' + op.error)
            finally:
                log_event('runtime', 'test_target_operation_finished', target_id=self.target.id,
                          operation_id=op.operation_id,
                          target_backend=self.backend, target_action=action, target_stage=op.stage,
                          target_outcome={'succeeded': 'completed', 'failed': 'failed', 'cancelled': 'cancelled'}.get(op.state, 'failed'),
                          target_failure_code=op.failure_code,
                          timeout_seconds=op.stage_timeout_seconds,
                          elapsed_seconds=max(0, time.monotonic() - started))
                # Durable diagnostics must survive an unavailable workspace DB.
                try:
                    if self.workspace.get_external_target(self.target.id):
                        self.workspace.record_external_target_event(self.target.id, action=action, detail=tag,
                            ok=op.state == 'succeeded', duration_seconds=time.monotonic() - started)
                except Exception as exc:
                    log_event('runtime', 'test_target_audit_failed', target_id=self.target.id,
                              target_backend=self.backend, target_action=action,
                              exception_class=type(exc).__name__)
        op.task = asyncio.create_task(work(), name=f'harnessy-test-{action}-{self.target.id}')
        return op

    async def request_stop(self) -> TargetOperation:
        if self.busy:
            if self.operation.action != 'start':
                raise RuntimeError('Wait for the current test VM operation to finish.')
            if not self.instance_dir.exists():
                raise RuntimeError('Host prerequisites are still being prepared. Retry Stop once the VM has been created.')
            task = self.operation.task
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return self.begin('stop')

    async def stop(self):
        self.invalidate_views()
        self.forget_radios()
        if not self.instance_dir.exists():
            return
        try:
            await self._run('stop', self.instance, timeout=90)
        except (RuntimeError, asyncio.TimeoutError):
            if self.operation:
                self.operation.note('\nGraceful stop did not finish; powering off this test VM.\n')
            await self._run('stop', '--force', self.instance, timeout=30)

    async def start(self):
        # Use the same prerequisite installer as workspace VMs for Lima/QEMU.
        self.invalidate_views()
        from .base import EnvironmentConfig
        from .host_prerequisites import ensure_host_prerequisites, ensure_test_target_prerequisites
        self.stage('prerequisites')
        await ensure_test_target_prerequisites(
            self.config['architecture'], windows=self.windows, progress=self._prerequisite_progress,
        )
        await ensure_host_prerequisites(
            EnvironmentConfig(architecture=self.config['architecture']), vm_type='qemu',
            progress=self._prerequisite_progress,
        )
        await self.prerequisites()
        if not self.instance_dir.exists():
            if self.windows and not Path(self.config['iso_path']).expanduser().is_file():
                raise RuntimeError('The Windows installer ISO was not found on the HarnessyXO host.')
            if self.config['os'].startswith('kali-'):
                self.stage('download')
                from .test_images import download_verified, extract_cloud_disk, finish_thread
                arch, digest = KALI_IMAGES[self.config['architecture']]
                images = self.root / 'images'
                archive = await download_verified(
                    f'https://kali.download/cloud-images/kali-2026.2/kali-linux-2026.2-cloud-genericcloud-{arch}.tar.xz',
                    digest, images / 'kali.tar.xz', self.operation.note if self.operation else lambda _: None)
                await finish_thread(extract_cloud_disk, archive, images / 'kali.img')
            spec = self.root / 'test.yaml'
            self.stage('prepare_disk')
            spec.write_text(json.dumps(self.vm_document(), indent=2), encoding='utf-8')
            await self._run('create', '--tty=false', '--name', self.instance, str(spec), timeout=3600)
        self.stage('launch', timeout_seconds=7200)
        await self._run('start', '--tty=false', self.instance, timeout=7200)
        # Readiness includes command execution and a usable test root, not just a
        # running hypervisor. The Windows installer may spend a long time here.
        from harnessy.agent.external_targets import ExternalTargetBroker
        self.stage('probe_shell')
        result = await ExternalTargetBroker(self.workspace).test_connection(self.target, initialize_root=True)
        if not result['ok']:
            raise RuntimeError(result.get('stderr') or 'Guest started but its test shell is not ready.')
        if self.operation:
            self.operation.note('\nTest VM ready. Internet access and software installation are available.\n')
        self.stage('ready')

    def command(self, command: str) -> tuple[list[str], dict[str, str]]:
        prefix = [self._binary(), 'shell', '--workdir', 'C:/' if self.windows else '/', self.instance]
        if self.windows:
            # Windows commands are always a fixed PowerShell launcher followed
            # by UTF-16LE base64, independent of SSH/host quoting rules.
            if not re.fullmatch(r'powershell\.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/=]+', command):
                raise ValueError('Expected an encoded PowerShell command.')
            argv = prefix + command.split(' ')
        else:
            argv = prefix + ['/bin/bash', '-lc', command]
        return argv, self._env()

    def terminal_command(self):
        argv = [self._binary(), 'shell', '--workdir', self.target.remote_root, self.instance]
        argv += ['powershell.exe', '-NoLogo'] if self.windows else ['/bin/bash', '-il']
        return argv, self._env(), self.root

    @staticmethod
    def _tag(tag):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', str(tag)) or tag in {'.', '..'}:
            raise ValueError('Snapshot names use letters, numbers, dots, hyphens and underscores (1–64 characters).')
        return str(tag)

    async def _require_stopped(self):
        status = await self.status()
        if status['state'] != 'stopped':
            raise RuntimeError('Stop this test VM before taking or restoring a snapshot, or deleting it.')
        if _ACTIVE.get(self.key, 0):
            raise RuntimeError('Close the target shell and graphical interface tabs, and finish target commands first.')

    def snapshots(self) -> list[str]:
        root = self.root / 'snapshots'
        return sorted(p.name for p in root.iterdir() if p.is_dir() and not p.name.startswith('.')) if root.is_dir() else []

    async def _copy_tree(self, source, destination):
        from harnessy.core.history import clone_or_copy_file
        task = asyncio.create_task(asyncio.to_thread(shutil.copytree, source, destination, symlinks=True,
            copy_function=lambda a, b: clone_or_copy_file(Path(a), Path(b))))
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            await task
            raise

    async def snapshot(self, tag):
        tag = self._tag(tag)
        await self._require_stopped()
        dest = self.root / 'snapshots' / tag
        if dest.exists():
            raise ValueError('A snapshot with that name already exists.')
        temp = dest.with_name('.' + tag + '.creating')
        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if temp.exists():
            shutil.rmtree(temp)
        try:
            await self._copy_tree(self.instance_dir, temp)
            temp.rename(dest)
        finally:
            if temp.exists():
                shutil.rmtree(temp)

    async def restore(self, tag):
        source = self.root / 'snapshots' / self._tag(tag)
        if not source.is_dir():
            raise ValueError('Snapshot not found.')
        await self._require_stopped()
        temp, previous = self.home / '.restore-new', self.home / '.restore-previous'
        if temp.exists() or previous.exists():
            raise RuntimeError('A previous restore needs recovery; preserved VM directories have not been deleted.')
        try:
            await self._copy_tree(source, temp)
        except BaseException:
            if temp.exists():
                await asyncio.to_thread(shutil.rmtree, temp)
            raise
        self.instance_dir.rename(previous)
        try:
            temp.rename(self.instance_dir)
        except BaseException:
            previous.rename(self.instance_dir)
            raise
        await asyncio.to_thread(shutil.rmtree, previous)

    async def delete(self):
        self.forget_radios()
        if self.instance_dir.exists():
            await self._require_stopped()
            await self._run('delete', '--force', self.instance, timeout=180)
        await asyncio.to_thread(shutil.rmtree, self.root, True)
        self.workspace.delete_external_target(self.target.id)

    def desktop_info(self) -> dict[str, str]:
        if not self.config['desktop']:
            raise ValueError('This target was created without a desktop.')
        path = self.instance_dir / 'vncdisplay'
        if not path.is_file():
            raise RuntimeError('Desktop is not ready yet. Start the VM and wait for its display to appear.')
        display = path.read_text().strip()
        match = re.fullmatch(r'(?:127\.0\.0\.1|localhost):(\d+)', display)
        if not match:
            raise RuntimeError('Lima returned an unsupported VNC address: ' + display)
        port = 5900 + int(match.group(1))
        password_path = self.instance_dir / 'vncpassword'
        return {'url': f'vnc://127.0.0.1:{port}', 'port': str(port),
                'password': password_path.read_text().strip() if password_path.is_file() else '', 'username': 'harnessy'}


async def stop_workspace_test_targets(workspace):
    """Stop this workspace's guests before removal; failure preserves workspace."""
    for target in workspace.list_external_targets():
        if not target.managed_vm:
            continue
        manager = TestTargetManager(workspace, target)
        operation = await manager.request_stop()
        await operation.task
        if operation.state != 'succeeded':
            raise TestTargetFailure(
                'A test target could not be stopped. The workspace has been kept; '
                'check its target status and diagnostics before removing it.',
                operation.failure_code,
            )


def _shutdown_inventory_failure(exc: BaseException, manager=None) -> None:
    """A diagnostic write must not interrupt cleanup of the other guests."""
    try:
        from harnessy.diagnostics import log_event
        from harnessy.diagnostics.test_target_logs import classify_target_failure
        fields = dict(target_action='stop', target_stage='stopped', target_outcome='failed',
                      target_failure_code=classify_target_failure(exc), exception_class=type(exc).__name__)
        if manager is not None:
            fields.update(target_id=manager.target.id, target_backend=manager.backend)
        log_event('runtime', 'test_target_shutdown_failed' if manager is not None else
                  'test_target_shutdown_inventory_failed', **fields)
    except Exception:
        pass


async def close_test_targets(workspaces):
    """Stop known guests without initializing any workspace database.

    A supplied healthy store can discover targets not used in this process.
    Remembered validated managers remain sufficient when that enumeration is
    unavailable or its store belongs to an older database generation.
    """
    with _MANAGERS_LOCK:
        managers = dict(_MANAGERS)
    for ws in workspaces:
        try:
            targets = ws.list_external_targets()
        except Exception as exc:
            _shutdown_inventory_failure(exc)
            continue
        try:
            for target in targets:
                try:
                    if target.managed_vm:
                        manager = TestTargetManager(ws, target)
                        managers[manager.key] = manager
                except Exception as exc:
                    _shutdown_inventory_failure(exc)
        except Exception as exc:
            # Enumeration may itself be lazy; isolate failure after any already
            # yielded targets rather than discarding the retained controllers.
            _shutdown_inventory_failure(exc)
    keys = set(managers)
    tasks = [op.task for key, op in list(_OPERATIONS.items())
             if key in keys and op.task and not op.task.done()]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    async def stop_one(manager):
        try:
            if (await manager.status())['running']:
                # stop/status operate on controller state. Do not use begin(),
                # whose optional audit path writes the old workspace database.
                await manager.stop()
        except Exception as exc:
            _shutdown_inventory_failure(exc, manager)
            return
        with _MANAGERS_LOCK:
            if _MANAGERS.get(manager.key) is manager:
                _MANAGERS.pop(manager.key, None)

    await asyncio.gather(*(stop_one(manager) for manager in managers.values()))
