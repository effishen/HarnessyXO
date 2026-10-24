"""Named OpenWrt VMs with scoped live SSHFS mounts or explicit guest copies."""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import shlex
import shutil
import sys
import tarfile
import time
import urllib.request
import uuid
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any
from contextlib import asynccontextmanager
from contextvars import ContextVar

from .activity import (acquire_activity, reserve_environment_change, active_work,
                       reserve_project_view_change, active_project_work)
from .base import EnvironmentConfig, EnvironmentStatus, ExecResult, WorkspaceEnvironment
from .host_prerequisites import discover_binary
from .openwrt_target import OpenWrtTargetManager, OPENWRT_READINESS_SECONDS
from .openwrt_tools import OPENWRT_REQUIRED_PACKAGES, OPENWRT_TOOL_BY_ID, OPENWRT_UNAVAILABLE_TOOLS, selected_openwrt_tools
from .project_sync import Entry, archive_tree, read_archive, scan_tree, signatures, merge_guest_changes, relative_path
from .test_catalog import guest_os, OPENWRT_RELEASE_IMAGES
from .test_images import download_verified, finish_thread as _finish_thread
from .openwrt_mounts import close_workspace_live_mounts, close_environment_live_mounts, LiveMountBusyError
from functools import partial


async def finish_thread(function, *args, **kwargs):
    return await _finish_thread(partial(function, *args, **kwargs))

_START_LOCKS: dict[str, asyncio.Lock] = {}
_SYNC_LOCKS: dict[str, asyncio.Lock] = {}
_GUEST_CONSOLE_VIEW_ID = '__guest_console__'


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name('.' + path.name + '-' + uuid.uuid4().hex)
    try:
        temporary.write_text(json.dumps(value, sort_keys=True) + '\n')
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


class _Controller(OpenWrtTargetManager):
    """Reuse QEMU ownership checks without registering an external target."""
    def __new__(cls, owner):
        return object.__new__(cls)

    def __init__(self, owner: 'OpenWrtEnvironment'):
        self.owner = owner
        self.workspace = SimpleNamespace(root=owner.workspace_root, meta=owner.meta_root)
        self.target = SimpleNamespace(id=owner.config.id, name=owner.config.name, remote_root='/workspace', enabled=owner.config.enabled)
        self.config = dict(os=owner.config.preset, architecture=owner.config.architecture,
                           cpu=owner.config.cpu, memory_mb=owner.config.memory_mb, disk_gb=owner.config.disk_gb,
                           desktop=bool(getattr(owner.config, 'desktop', True)), internet=owner.config.network, emulation=dict(getattr(owner.config, 'emulation', None) or {'wifi': False, 'bluetooth': False}))
        self.guest = guest_os(owner.config.preset)
        self.root = owner.environment_root
        self.home, self.instance = self.root / 'qemu', 'guest'
        self.instance_dir = self.home / self.instance
        self.environment_id = owner.config.id
        self.key, self.windows, self.backend = str(self.root.resolve()), False, 'qemu'
        for path in (self.root, self.home, self.instance_dir):
            if path.is_symlink():
                raise ValueError('OpenWrt environment directories cannot be symlinks.')
        from harnessy.diagnostics.test_target_logs import register_test_target_runtime
        register_test_target_runtime(self.root, 'qemu')
        self._remember_for_shutdown()

    @property
    def operation(self):
        return None

    def invalidate_views(self):
        return None

    def qemu_argv(self, ssh_port: int, web_port: int):
        argv = super().qemu_argv(ssh_port, web_port)
        argv[argv.index('-name') + 1] = 'harnessy-env-' + self.target.id
        argv += ['-vga', 'none']
        for index, value in enumerate(argv[:-1]):
            if value == '-device' and ',netdev=' in argv[index + 1]:
                argv[index + 1] += ',romfile='
        # Restrict at QEMU's boundary, outside the guest. Controlled package
        # installation uses host-verified local ipks, including for offline VMs.
        if not self.owner.config.network:
            index = argv.index('user,id=wan')
            argv[index] = 'user,id=wan,restrict=on'
        return argv

    def command(self, command, *, reuse_connection=True):
        argv, env = super().command(command, reuse_connection=reuse_connection)
        # OpenWrt's login profile prints a banner even for noninteractive SSH.
        # Binary project/artifact transfers must receive only their payload.
        argv[-1] = '/bin/ash -c ' + shlex.quote(command)
        return argv, env

    async def _radio_command(self, script, *, timeout=20):
        # The bundled Bluetooth ELF makes this script larger than Linux's
        # per-argument limit. Keep SSH's command fixed and stream the script on
        # stdin, as the legacy target transport already does.
        from harnessy.diagnostics.radio_setup import record_radio_setup_evidence
        from .test_bluetooth import (
            BLUETOOTH_PACKAGES_SCRIPT, BLUETOOTH_H4_SETUP_SCRIPT,
            BLUETOOTH_RADIO_PACKAGES,
        )
        from .test_radios import WIFI_SETUP_SCRIPT
        message = (
            'Installing matching Bluetooth packages; first setup may take several minutes…'
            if script == BLUETOOTH_PACKAGES_SCRIPT else
            'Installing the verified software Bluetooth controller helper…'
            if script.startswith('# HarnessyXO verified Bluetooth helper installation v1\n') else
            'Attaching and verifying the software Bluetooth controllers…'
            if script == BLUETOOTH_H4_SETUP_SCRIPT else
            'Setting up and verifying the software Wi-Fi radios…'
            if script == WIFI_SETUP_SCRIPT else None
        )
        if message:
            await self.owner._emit('provisioning_optional_packages', message)
        out, err, returncode, failure = b'', b'', None, None
        partial_output = {}
        evidence_phase = 'guest_script'
        command_timeout = timeout
        try:
            packages, radio = (), None
            if script == BLUETOOTH_PACKAGES_SCRIPT:
                packages, radio = BLUETOOTH_RADIO_PACKAGES, 'bluetooth'
            elif script == WIFI_SETUP_SCRIPT:
                packages, radio = ('kmod-mac80211-hwsim', 'iw'), 'wifi'
            if packages and not self.owner._basic_copy:
                # Use the same pinned-release, SHA-verified host downloader as
                # the VM tool installer. Guest WAN can remain disabled. The
                # unchanged fixed guest scripts then verify modules/utilities
                # and skip their feed fetch when everything is already present.
                try:
                    evidence_phase = 'host_package_setup'
                    started = time.monotonic()
                    await asyncio.wait_for(self.owner._install_packages(packages), timeout=timeout)
                    command_timeout = max(0.001, timeout - (time.monotonic() - started))
                except (OSError, RuntimeError, TimeoutError) as error:
                    failure = error
                    detail = 'operation_timeout' if isinstance(error, TimeoutError) else 'unknown'
                    out = (f'HX_RADIO_SETUP {radio}=package_install_failed\n'
                           f'HX_RADIO_DETAIL {radio}={detail}\n').encode('ascii')
                    err = str(error).encode('utf-8', errors='replace')[-16384:]
                    return out.decode('ascii')
                evidence_phase = 'guest_script'
            returncode, out, err = await self.owner._raw(
                '/bin/ash -s', data=script.encode('utf-8'), timeout=command_timeout,
                output_limit=256 * 1024, failure_capture=partial_output,
            )
            if returncode:
                raise RuntimeError('The optional guest radio command failed.')
            return out.decode(errors='replace')
        except (OSError, RuntimeError, TimeoutError, asyncio.CancelledError) as error:
            failure = error
            raise
        finally:
            try:
                record_radio_setup_evidence(
                    self.runtime_dir(), script,
                    stdout=out or partial_output.get('stdout', b''),
                    stderr=err or partial_output.get('stderr', b''),
                    returncode=returncode, error=failure, timeout_seconds=timeout,
                    phase=evidence_phase,
                )
            except (OSError, RuntimeError, ValueError):
                pass  # Evidence capture cannot change the actual guest result.

    def radio_repair_hint(self):
        return 'Use Retry Setup on this running VM to finish radio setup without rebuilding it.'

    async def _copy_tree(self, source, destination):
        def copy_file(old, new):
            import errno
            old, new = Path(old), Path(new)
            with old.open('rb') as stream, new.open('xb') as output:
                size = os.fstat(stream.fileno()).st_size
                sparse = hasattr(os, 'SEEK_DATA') and hasattr(os, 'SEEK_HOLE')
                position = 0
                while sparse and position < size:
                    try:
                        data = os.lseek(stream.fileno(), position, os.SEEK_DATA)
                        hole = min(size, os.lseek(stream.fileno(), data, os.SEEK_HOLE))
                    except OSError as exc:
                        if exc.errno == errno.ENXIO:
                            position = size
                            break
                        if exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                            raise
                        sparse = False
                        break
                    stream.seek(data)
                    output.seek(data)
                    remaining = hole - data
                    while remaining:
                        chunk = stream.read(min(4 * 1024 * 1024, remaining))
                        if not chunk: raise RuntimeError('VM disk ended during snapshot copy.')
                        output.write(chunk)
                        remaining -= len(chunk)
                    position = hole
                if not sparse:
                    stream.seek(0)
                    output.seek(0)
                    output.truncate(0)
                    while chunk := stream.read(4 * 1024 * 1024):
                        if chunk.strip(b'\0'): output.write(chunk)
                        else: output.seek(len(chunk), 1)
                output.truncate(size)
            shutil.copystat(old, new, follow_symlinks=False)
            return str(new)
        await finish_thread(shutil.copytree, source, destination, symlinks=True, copy_function=copy_file)

    async def start(self):
        await self.owner.start()


class OpenWrtEnvironment(WorkspaceEnvironment):
    def __init__(self, workspace_root: Path, config: EnvironmentConfig):
        super().__init__(workspace_root, config)
        if self.config.provider != 'openwrt' or self.config.preset not in OPENWRT_RELEASE_IMAGES:
            raise ValueError('Choose an implemented OpenWrt release.')
        if self.config.architecture not in OPENWRT_RELEASE_IMAGES[self.config.preset]:
            raise ValueError('This OpenWrt image does not provide the selected architecture.')
        if self.config.architecture.startswith('mips') and (self.config.cpu != 1 or self.config.memory_mb > 2048):
            raise ValueError('Malta MIPS environments support one CPU and at most 2048 MiB RAM.')
        if self.config.disk_gb > 64:
            raise ValueError('OpenWrt environments support disks up to 64 GiB.')
        if self.config.files_mode not in {'live', 'readonly', 'copy'}:
            raise ValueError('Unsupported project files mode.')
        selected_openwrt_tools(self.config.optional_tools)
        self.state_root = self.environment_root / 'state'
        self.state_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.controller = _Controller(self)
        self.vm_root = self.controller.home
        self._tasks: set[asyncio.Task] = set()
        self._ready = False
        self._basic_copy = self.config.preset == 'openwrt-25.12.5'
        self._progress_context = ContextVar("openwrt_progress_" + self.config.id, default=None)
        self._terminal_projections = {}
        from harnessy.diagnostics.vm_logs import register_workspace_runtime
        register_workspace_runtime(self.workspace_root, environment_id=self.config.id, runtime_root=self.environment_root)
        try:
            from harnessy.diagnostics.guest_logs import register_guest_probe
            register_guest_probe(self.workspace_root, environment_id=self.config.id,
                runtime_root=self.environment_root, kind='openwrt', probe=self._guest_diagnostic_probe)
        except Exception:
            pass  # Optional diagnostics must never prevent opening the VM.

    async def _guest_diagnostic_probe(self, script: str, timeout: float) -> tuple[int, bytes, bytes]:
        from harnessy.diagnostics.guest_logs import GuestProbeUnavailable
        self._validate_private_runtime()
        if not self.controller.instance_dir.is_dir() or self._state().get('running') is False:
            raise GuestProbeUnavailable(state='stopped', code='guest_stopped')
        # A fixed read-only administrative probe never starts a VM, mounts a
        # project, runs a login profile or changes the active project policy.
        return await self._raw(script, timeout=timeout, output_limit=128 * 1024, login_shell=False)

    def _guest_transport_failure(self, *, stderr: bytes = b'', returncode: int | None = None,
                                 timed_out: bool = False) -> None:
        try:
            from harnessy.diagnostics.guest_logs import record_guest_transport
            record_guest_transport(self.workspace_root, environment_id=self.config.id,
                runtime_root=self.environment_root, kind='openwrt', operation='ssh_command',
                stderr=stderr, returncode=returncode, timed_out=timed_out)
        except Exception:
            pass  # Recording evidence cannot change a command's outcome.

    @property
    def _live_mounts(self):
        from .openwrt_mounts import live_mounts
        return live_mounts(self)

    async def _emit(self, phase: str, message: str, **metadata):
        phase = {'prerequisites': 'checking_host_dependencies', 'preparing': 'creating_vm', 'starting': 'starting_vm', 'waiting_ssh': 'waiting_for_guest', 'provisioning': 'provisioning_packages', 'optional_tool_failed': 'provisioning_optional_packages'}.get(phase, phase)
        progress = self._progress_context.get()
        if progress:
            result = progress(phase, message, **metadata)
            if hasattr(result, '__await__'):
                await result

    async def _raw(self, command: str, *, data: bytes | None = None, timeout: float = 120, output_limit: int = 16 * 1024 * 1024,
                   failure_capture: dict[str, bytes] | None = None, login_shell: bool = True) -> tuple[int, bytes, bytes]:
        argv, env = self.controller.command(command)
        if not login_shell:
            # Metadata probes must not execute a guest login profile. Keep the
            # existing model, lifecycle, and interactive transports unchanged.
            argv[-1] = '/bin/ash -c ' + shlex.quote(command)
        try:
            process = await asyncio.create_subprocess_exec(*argv, env=env, cwd=self.environment_root,
                stdin=asyncio.subprocess.PIPE if data is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except OSError as exc:
            self._guest_transport_failure(stderr=str(exc).encode('utf-8', errors='replace'))
            raise
        diagnostic_stderr = bytearray()
        async def read(stream, limit, name):
            chunks, count = [], 0
            while chunk := await stream.read(65536):
                if name == 'stderr':
                    diagnostic_stderr.extend(chunk)
                    del diagnostic_stderr[:-8192]
                if failure_capture is not None:
                    # Preserve a bounded tail even when wait_for cancels the
                    # transfer. Only fixed radio setup callers export it.
                    failure_capture[name] = (failure_capture.get(name, b'') + chunk)[-16384:]
                count += len(chunk)
                if count > limit:
                    raise RuntimeError('OpenWrt command output exceeded its bounded transfer limit; guest data was retained.')
                chunks.append(chunk)
            return b''.join(chunks)
        async def write():
            if data is None:
                return
            try:
                for offset in range(0, len(data), 65536):
                    process.stdin.write(data[offset:offset + 65536])
                    await process.stdin.drain()
                process.stdin.close()
                await process.stdin.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass
        tasks = [asyncio.create_task(write()), asyncio.create_task(read(process.stdout, output_limit, 'stdout')),
                 asyncio.create_task(read(process.stderr, 4 * 1024 * 1024, 'stderr')), asyncio.create_task(process.wait())]
        try:
            _, out, err, code = await asyncio.wait_for(asyncio.gather(*tasks), timeout)
            if code == 255:
                self._guest_transport_failure(stderr=bytes(diagnostic_stderr), returncode=code)
            return code, out, err
        except asyncio.TimeoutError:
            self._guest_transport_failure(stderr=bytes(diagnostic_stderr), timed_out=True)
            raise
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
            for task in tasks:
                if not task.done(): task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _checked(self, command: str, *, data: bytes | None = None, timeout: float = 120) -> bytes:
        limit = 620 * 1024 * 1024 if command.startswith('tar -cf - ') or command.startswith('python3 -c ' + shlex.quote(_READ_GUEST_FILE)) else 16 * 1024 * 1024
        rc, out, err = await self._raw(command, data=data, timeout=timeout, output_limit=limit)
        if rc:
            raise RuntimeError('OpenWrt guest command failed: ' + err.decode(errors='replace')[-2000:])
        return out

    def _state(self) -> dict:
        try:
            return json.loads((self.state_root / 'readiness.json').read_text())
        except (OSError, ValueError):
            return {}

    def runtime_identity(self) -> dict[str, Any]:
        row = self._state()
        return {'provider': 'openwrt', 'environment_id': self.config.id, 'environment_name': self.config.name,
                'environment_enabled': self.config.enabled, 'vm_created': self.controller.instance_dir.is_dir(), 'vm_running': row.get('running'),
                'vm_ready': row.get('ready', False), 'vm_generation': row.get('generation', 0),
                'vm_boot_id': row.get('boot_id', ''), 'vm_lifecycle_event': row.get('event', 'unknown'),
                'vm_lifecycle_updated_at': row.get('updated_at'), 'vm_readiness_updated_at': row.get('updated_at'),
                'files_bridge': 'copy' if self.config.files_mode == 'copy' else 'sshfs', 'files_mode': self.config.files_mode,
                'administrative_guest_commands': self.config.files_mode == 'copy',
                'egress_scope': 'public_and_private_nat' if self.config.network else 'qemu_wan_restricted',
                'guest_disk_scope': 'all_previously_deployed_copies' if self.config.files_mode == 'copy' else 'authorized_project_namespace'}

    def _record(self, *, ready: bool, running: bool, event: str, boot_id: str = ''):
        previous = self._state()
        _atomic_json(self.state_root / 'readiness.json', {
            'ready': ready, 'running': running, 'event': event, 'updated_at': time.time(),
            'generation': int(previous.get('generation', 0)) + (event in {'created', 'reset', 'restored'}),
            'boot_id': boot_id if running else '',
        })
        self._ready = ready
        if ready and event == 'ready' and (not previous.get('ready') or previous.get('boot_id') != boot_id):
            try:
                from harnessy.diagnostics.guest_logs import request_guest_capture
                request_guest_capture(self.workspace_root, self.config.id, 'vm_ready')
            except Exception:
                pass

    async def status(self) -> EnvironmentStatus:
        try:
            row = await self.controller.status()
            running, created, state = row['running'], row['created'], row['state']
            error = ''
        except Exception as exc:
            running, created, state, error = False, self.controller.instance_dir.is_dir(), 'unknown', str(exc)
        ready = bool(running and self._state().get('ready'))
        return EnvironmentStatus(state=state, provider='openwrt', available=bool(discover_binary('ssh')),
            created=created, running=running, ready=ready, phase='ready' if ready else state, error=error,
            guest_architecture=self.config.architecture, guest_os=guest_os(self.config.preset).label,
            environment_id=self.config.id, environment_name=self.config.name,
            files_mount='/workspace', detail='Independent guest copies.' if self.config.files_mode == 'copy' else 'Scoped live SSHFS source mounts; host-enforced read-only inputs.')

    def _host_storage_usage(self):
        from .storage_probe import host_disk_usage
        return host_disk_usage(self.controller.instance_dir, ('rootfs.raw',))

    async def storage_usage(self) -> dict[str, Any]:
        from .storage_probe import (OPENWRT_STORAGE_SCRIPT, MAX_OUTPUT, parse_openwrt_storage,
                                    storage_result, unavailable_guest)
        host = await finish_thread(self._host_storage_usage)
        try:
            status = await asyncio.wait_for(self.controller.status(), 2)
        except (OSError, RuntimeError, ValueError, asyncio.TimeoutError):
            return storage_result(unavailable_guest(), host)
        if not status.get('running'):
            state = str(status.get('state', ''))
            guest = unavailable_guest('GUEST_STORAGE_STOPPED', state='stopped') if state in {'stopped', 'not_created'} else unavailable_guest()
            return storage_result(guest, host)
        try:
            rc, output, _ = await self._raw(OPENWRT_STORAGE_SCRIPT, timeout=5, output_limit=MAX_OUTPUT,
                                          login_shell=False)
            guest = parse_openwrt_storage(output) if rc == 0 else unavailable_guest('GUEST_STORAGE_PROBE_FAILED')
        except (OSError, RuntimeError, ValueError, asyncio.TimeoutError):
            guest = unavailable_guest('GUEST_STORAGE_PROBE_FAILED')
        return storage_result(guest, host)

    async def usage_snapshot(self, *, include_storage: bool = False) -> dict[str, Any]:
        from .resource_probe import (MAX_OUTPUT, build_usage_script, parse_usage_output,
                                     unavailable_resources)
        from .storage_probe import (OPENWRT_STORAGE_SCRIPT, MAX_OUTPUT as STORAGE_MAX,
                                    parse_openwrt_storage, storage_result, unavailable_guest)
        host = await finish_thread(self._host_storage_usage) if include_storage else None

        def result(resources, guest=None):
            return {'schema_version': 1, 'resources': resources,
                    'storage': storage_result(guest, host) if include_storage else None}

        try:
            status = await asyncio.wait_for(self.controller.status(), 2)
        except (OSError, RuntimeError, ValueError, asyncio.TimeoutError):
            return result(unavailable_resources(), unavailable_guest())
        if not status.get('running'):
            stopped = status.get('state') in {'stopped', 'not_created'}
            return result(unavailable_resources('GUEST_RESOURCES_STOPPED', state='stopped') if stopped else unavailable_resources(),
                          unavailable_guest('GUEST_STORAGE_STOPPED', state='stopped') if stopped else unavailable_guest())
        try:
            script = build_usage_script(OPENWRT_STORAGE_SCRIPT if include_storage else None)
            rc, output, _ = await self._raw(script, timeout=5,
                output_limit=MAX_OUTPUT + (STORAGE_MAX if include_storage else 0), login_shell=False)
            if rc != 0:
                return result(unavailable_resources('GUEST_RESOURCES_PROBE_FAILED'), unavailable_guest('GUEST_STORAGE_PROBE_FAILED'))
            resources, guest = parse_usage_output(output, include_storage=include_storage, storage_parser=parse_openwrt_storage)
            return result(resources, guest)
        except (OSError, RuntimeError, ValueError, asyncio.TimeoutError):
            return result(unavailable_resources('GUEST_RESOURCES_PROBE_FAILED'), unavailable_guest('GUEST_STORAGE_PROBE_FAILED'))

    async def create(self, progress=None) -> EnvironmentStatus:
        return await self.start(progress=progress)

    async def start(self, progress=None) -> EnvironmentStatus:
        token = self._progress_context.set(progress)
        try:
            result = await self._start_locked()
            from .file_views import FILE_VIEWS
            FILE_VIEWS.request(self.workspace_root, reason='vm_start', environment_id=self.config.id)
            return result
        finally:
            self._progress_context.reset(token)

    def _validate_private_runtime(self, extra: Path | None = None):
        from .base import _validate_registry_path
        for path in (self.environment_root, self.controller.home, self.controller.instance_dir, self.environment_root / 'snapshots', self.state_root):
            _validate_registry_path(path, self.workspace_root)
        if extra is not None:
            _validate_registry_path(extra, self.workspace_root)

    async def _start_locked(self) -> EnvironmentStatus:
        self._validate_private_runtime()
        async with _START_LOCKS.setdefault(str(self.environment_root), asyncio.Lock()):
            self.controller._env()
            await self._emit('prerequisites', 'Checking OpenWrt host tools…')
            await self.controller.prerequisites()
            if not self.controller.instance_dir.exists():
                await self._emit('preparing', 'Downloading and preparing the pinned OpenWrt image…')
                await self.controller._prepare()
                self._record(ready=False, running=False, event='created')
            if not (await self.controller.status())['running']:
                runtime = self.controller.runtime_dir()
                for filename in ('qmp.sock', 'qemu.pid'):
                    (runtime / filename).unlink(missing_ok=True)
                ssh, web = self.controller._port(), self.controller._port()
                while ssh == web:
                    web = self.controller._port()
                _atomic_json(self.controller.instance_dir / 'ports.json', {'ssh': ssh, 'web': web})
                await self._emit('starting', 'Booting OpenWrt; MIPS uses software CPU emulation…')
                await self.controller._launch_qemu(self.controller.qemu_argv(ssh, web))
            await self._emit('waiting_ssh', 'Waiting for OpenWrt SSH and first-boot configuration…')
            deadline = time.monotonic() + OPENWRT_READINESS_SECONDS
            last_error = ''
            while time.monotonic() < deadline:
                try:
                    rc, out, err = await self._raw('test -f /etc/harnessy-test-ready && echo HX_READY', timeout=10)
                    if rc == 0 and b'HX_READY' in out:
                        break
                    last_error = err.decode(errors='replace')[-800:]
                except (OSError, RuntimeError, asyncio.TimeoutError) as exc:
                    last_error = str(exc)
                if not (await self.controller.status())['running']:
                    raise RuntimeError('OpenWrt exited during boot; inspect its QEMU console log.')
                await asyncio.sleep(2)
            else:
                self._record(ready=False, running=True, event='boot_timeout')
                raise RuntimeError('OpenWrt did not become ready within its boot deadline. VM retained for inspection. ' + last_error)
            try:
                await self._ensure_integration()
                boot_id = (await self._checked('cat /proc/sys/kernel/random/boot_id')).decode().strip()
                if any(self.controller.config['emulation'].values()):
                    await self.controller.configure_radios()
                else:
                    # Stock images can already contain software radios. Report
                    # actual observed controllers even when none were requested.
                    await self.controller.inspect_radios()
                self._record(ready=True, running=True, event='ready', boot_id=boot_id)
            except BaseException:
                self._record(ready=False, running=True, event='integration_failed')
                raise
            await self._emit('ready', 'OpenWrt is ready. Its actual guest identity and selected tool results are available.')
            return await self.status()

    @staticmethod
    def _parse_packages(text: str, base: str) -> dict[str, dict]:
        result = {}
        for block in text.split('\n\n'):
            row = dict(line.split(': ', 1) for line in block.splitlines() if ': ' in line)
            if row.get('Package') and row.get('Filename') and re.fullmatch(r'[a-f0-9]{64}', row.get('SHA256sum', '')):
                row['base'] = base
                result[row['Package']] = row
        return result

    async def _package_catalog(self) -> dict[str, dict]:
        release = self.config.preset.removeprefix('openwrt-')
        folder = OPENWRT_RELEASE_IMAGES[self.config.preset][self.config.architecture][0]
        # Ask the guest for its actual package ABI, never guess from QEMU's CPU.
        architectures = (await self._checked('opkg print-architecture')).decode().splitlines()
        package_arch = next((row.split()[1] for row in reversed(architectures) if len(row.split()) == 3 and row.split()[1] not in {'all', 'noarch'}), '')
        if not re.fullmatch(r'[a-zA-Z0-9_]+', package_arch):
            raise RuntimeError('OpenWrt did not report a valid package architecture.')
        urls = [f'https://downloads.openwrt.org/releases/{release}/targets/{folder}/packages/',
                *(f'https://downloads.openwrt.org/releases/{release}/packages/{package_arch}/{feed}/' for feed in ('base', 'packages'))]
        catalog = {}
        for base in urls:
            await self._emit('provisioning', 'Reading official OpenWrt package metadata…')
            def fetch():
                with urllib.request.urlopen(base + 'Packages', timeout=60) as response:
                    data = response.read(32 * 1024 * 1024 + 1)
                if len(data) > 32 * 1024 * 1024:
                    raise RuntimeError('OpenWrt package metadata exceeds its size limit.')
                return data.decode('utf-8')
            catalog.update(self._parse_packages(await finish_thread(fetch), base))
        return catalog

    async def _install_packages(self, names: tuple[str, ...], catalog: dict[str, dict] | None = None):
        installed = set((await self._checked("opkg list-installed | cut -d ' ' -f 1")).decode().splitlines())
        pending = [name for name in names if name not in installed]
        if not pending:
            return
        catalog = catalog or await self._package_catalog()
        resolved, visiting = {}, set()
        provides = {}
        for package, row in catalog.items():
            for alternative in row.get('Provides', '').split(','):
                provides.setdefault(alternative.strip().split(' ')[0], package)
        def resolve(name):
            name = name.strip().split(' ')[0]
            if name in installed or name in visiting or name in resolved:
                return
            if name not in catalog:
                name = provides.get(name, name)
            if name not in catalog:
                raise RuntimeError('The pinned OpenWrt feed does not provide required package: ' + name)
            visiting.add(name)
            row = catalog[name]
            for dependency in row.get('Depends', '').split(','):
                if dependency.strip():
                    alternatives = [item.strip().split(' ')[0] for item in dependency.split('|')]
                    candidate = next((item for item in alternatives if item in installed or item in catalog or item in provides), alternatives[0])
                    resolve(candidate)
            visiting.remove(name)
            resolved[name] = row
        for name in pending:
            resolve(name)
        semaphore = asyncio.Semaphore(4)
        async def fetch_package(name, row):
            filename = str(row['Filename']).removeprefix('./')
            if '/' in filename or not filename.endswith('.ipk'):
                raise RuntimeError('Unsafe filename in the OpenWrt package feed.')
            async with semaphore:
                await self._emit('provisioning', 'Downloading OpenWrt package: ' + name)
                file = await download_verified(row['base'] + filename, row['SHA256sum'], self.environment_root / 'images' / 'packages' / filename, lambda _: None)
                return file, filename
        tasks = [asyncio.create_task(fetch_package(name, row)) for name, row in resolved.items()]
        try:
            downloaded = await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w') as bundle:
            for file, filename in downloaded:
                bundle.add(file, arcname=filename, recursive=False)
        target = '/tmp/harnessy-install-' + uuid.uuid4().hex
        await self._emit('provisioning', 'Installing verified local OpenWrt packages…')
        command = f'mkdir -m 700 {target} && tar -xf - -C {target} && opkg install {target}/*.ipk; rc=$?; rm -rf -- {target}; exit "$rc"'
        rc, out, err = await self._raw(command, data=archive.getvalue(), timeout=1800)
        if rc:
            raise RuntimeError('OpenWrt package installation failed: ' + (out + err).decode(errors='replace')[-3000:])
        installed = set((await self._checked("opkg list-installed | cut -d ' ' -f 1")).decode().splitlines())
        missing = set(names) - installed
        if missing:
            raise RuntimeError('OpenWrt package verification failed: ' + ', '.join(sorted(missing)))

    async def _ensure_integration(self):
        if self._basic_copy:
            if self.config.files_mode != 'copy':
                raise RuntimeError('This OpenWrt release currently supports separate guest copies only.')
            await self._checked('command -v tar >/dev/null && command -v /bin/ash >/dev/null && mkdir -p /workspace/Files /opt/harnessy-private/projections')
            identity = (await self._checked('cat /etc/openwrt_release; uname -a; command -v apk >/dev/null && apk --version || true')).decode(errors='replace')
            _atomic_json(self.state_root / 'guest.json', {'observation': 'verified_guest_probe', 'identity': identity, 'observed_at': time.time(), 'package_manager': 'apk', 'project_files': 'separate_guest_copy'})
            _atomic_json(self.state_root / 'tools.json', {name: {'status': 'unavailable', 'detail': 'Automatic APK tool provisioning is not implemented for this release; use the guest package manager.'} for name in selected_openwrt_tools(self.config.optional_tools)})
            return
        # No model payload executes until mandatory tools and kernel isolation
        # have been verified. Package installs do not need guest internet.
        await self._install_packages(OPENWRT_REQUIRED_PACKAGES)
        script = '''set -eu
mkdir -p /opt/harnessy-private/projections /workspace /home/harnessy
chmod 700 /opt/harnessy-private /opt/harnessy-private/projections
if ! id harnessy >/dev/null 2>&1; then
 printf 'harnessy:x:1000:1000:Harnessy environment:/home/harnessy:/bin/bash\\n' >> /etc/passwd
 printf 'harnessy:x:1000:\\n' >> /etc/group
fi
chown 1000:1000 /home/harnessy
chmod 700 /home/harnessy
unshare --mount --pid --fork --mount-proc /bin/sh -c 'mount --make-rprivate /; mount -t tmpfs -o mode=0700 tmpfs /opt/harnessy-private; test -d /proc/1' || exit 72
python3 -c 'import sys; print(sys.version)'
'''
        await self._checked(script)
        selected = selected_openwrt_tools(self.config.optional_tools)
        results = {}
        catalog = None
        installed = set((await self._checked("opkg list-installed | cut -d ' ' -f 1")).decode().splitlines())
        for name in selected:
            try:
                if set(OPENWRT_TOOL_BY_ID[name].packages) - installed:
                    catalog = catalog or await self._package_catalog()
                    await self._install_packages(OPENWRT_TOOL_BY_ID[name].packages, catalog)
                results[name] = {'status': 'installed', 'detail': 'Verified using opkg list-installed.'}
            except Exception as exc:
                results[name] = {'status': 'failed', 'detail': str(exc)}
                await self._emit('optional_tool_failed', name + ': ' + str(exc))
        _atomic_json(self.state_root / 'tools.json', results)
        identity = (await self._checked("printf 'RELEASE='; . /etc/openwrt_release; echo \"$DISTRIB_RELEASE\"; printf 'KERNEL='; uname -r; printf 'MACHINE='; uname -m; printf 'ARCH='; opkg print-architecture; for loader in /lib/ld-musl-*.so.1; do \"$loader\" 2>&1 | head -3; break; done; python3 -c 'import sys; print(\"PYTHON=\"+sys.version.split()[0]); print(\"ENDIAN=\"+sys.byteorder); print(\"POINTER_BITS=\"+str(sys.maxsize.bit_length()+1))'" )).decode()
        _atomic_json(self.state_root / 'guest.json', {'observation': 'verified_guest_probe', 'identity': identity, 'observed_at': time.time()})

    async def optional_tool_status(self) -> dict[str, dict[str, Any]]:
        if self._basic_copy:
            return {}
        try:
            results = json.loads((self.state_root / 'tools.json').read_text())
        except (OSError, ValueError):
            results = {}
        selected = selected_openwrt_tools(self.config.optional_tools)
        installed = None
        if self._ready:
            try:
                installed = set((await self._checked("opkg list-installed | cut -d ' ' -f 1")).decode().splitlines())
            except (OSError, RuntimeError, asyncio.TimeoutError):
                pass
        output = {}
        for name, tool in OPENWRT_TOOL_BY_ID.items():
            row = dict(results.get(name, {'status': 'pending' if name in selected else 'not_selected', 'detail': ''}))
            if installed is not None:
                count = len(set(tool.packages) & installed)
                if count == len(tool.packages):
                    row = {'status': 'installed', 'detail': 'Verified using opkg list-installed.' + (' Deselecting does not uninstall system packages.' if name not in selected else '')}
                elif count:
                    row = {'status': 'partial', 'detail': f'{count}/{len(tool.packages)} packages installed.'}
            row['state'] = row['status']
            row['selected'] = name in selected
            output[name] = row
        return output

    async def apply_optional_tools(self, selected, *, expected=None, remove_deselected_bundles=False, progress=None, reservation_held=False):
        from dataclasses import replace
        from .base import load_environment_config, save_environment_config
        desired = selected_openwrt_tools(selected)
        release = (lambda: None) if reservation_held else reserve_environment_change(self.workspace_root, 'optional tools', environment_id=self.config.id)
        try:
            original = load_environment_config(self.workspace_root, self.config.id)
            if original is None:
                raise RuntimeError('The selected VM environment no longer exists.')
            if expected is not None and tuple(expected) != selected_openwrt_tools(original.optional_tools):
                raise RuntimeError('Optional tools changed since this editor opened; refresh before applying.')
            self.config = replace(original, optional_tools=desired)
            save_environment_config(self.workspace_root, self.config, preserve_user_metadata=True)
            self.config = load_environment_config(self.workspace_root, self.config.id) or self.config
            if (await self.status()).running:
                return await self.start(progress=progress)
            return await self.status()
        finally:
            release()

    def _projection(self, active_root: Path | None, policy: dict | None) -> dict:
        root = Path(active_root or self.files_root).resolve()
        files, private = self.files_root.resolve(), self.private_worktrees_root.resolve()
        if root != files and files not in root.parents and private not in root.parents:
            raise ValueError('Selected project is outside this workspace.')
        policy = dict(policy or {})
        if self.config.files_mode != 'copy' and int(policy.get('namespace_version', 0)) != 2:
            raise ValueError('Choose an exact Project / Chat file view; the whole workspace is not exported.')
        key = hashlib.sha256(str(root).encode()).hexdigest()[:24]
        mounts = []
        if int(policy.get('namespace_version', 0)) == 2:
            own = str(policy.get('writable_folder', ''))
            if not re.fullmatch(r'Project-[A-Za-z0-9]{4}', own) or Path(policy.get('project_root', '')).resolve() != root:
                raise ValueError('Project identity does not match the selected root.')
            excluded = tuple(str(row['nested_path']) for row in policy.get('ancestors', ()))
            mounts.append({'host': root, 'guest': 'Files/' + own, 'writable': self.config.files_mode != 'readonly', 'excluded': excluded})
            references = Path(policy.get('references_root', '')).resolve()
            if references != files / 'References':
                raise ValueError('Invalid workspace References root.')
            mounts.append({'host': references, 'guest': 'Files/References', 'writable': False, 'excluded': ()})
            for row in policy.get('ancestors', ()):
                nested = relative_path(str(row['nested_path']))
                if any(not re.fullmatch(r'Project-[A-Za-z0-9]{4}', part) for part in PurePosixPath(nested).parts):
                    raise ValueError('Invalid ancestor project path.')
                host = Path(row['host_path']).resolve()
                if host.parent != files or host.name != PurePosixPath(nested).name:
                    raise ValueError('Ancestor project is outside workspace Files.')
                mounts.append({'host': host, 'guest': 'Files/' + own + '/' + nested, 'writable': False, 'excluded': tuple()})
            for row in policy.get('access_projects', ()):
                if not row.get('direct_mount'):
                    continue
                folder, host = str(row['folder']), Path(row['host_path']).resolve()
                if not re.fullmatch(r'Project-[A-Za-z0-9]{4}', folder) or host.parent != files or host.name != folder:
                    raise ValueError('Invalid Project Access source.')
                mounts.append({'host': host, 'guest': 'Files/' + folder, 'writable': False, 'excluded': ()})
        else:
            mounts.append({'host': root, 'guest': '', 'writable': self.config.files_mode != 'readonly', 'excluded': ()})
        if self.config.files_mode != 'copy':
            # Synthetic, read-only directories are provided by SFTP for nested
            # ancestor mount points; creating them never modifies host source.
            for row in mounts:
                prefix = row['guest'] + '/'
                row['excluded'] = tuple(sorted(set(row['excluded']) | {
                    item['guest'][len(prefix):] for item in mounts
                    if item is not row and item['guest'].startswith(prefix)}))
        remote = '/opt/harnessy-private/' + ('projections/' if self.config.files_mode == 'copy' else 'live/') + key
        return {'key': key, 'root': root, 'mounts': mounts, 'remote': remote, 'policy': policy, 'files_mode': self.config.files_mode}

    def _references_projection(self, policy: dict) -> dict:
        """The human root console receives only this read-only capability."""
        policy = dict(policy or {})
        references = self.files_root.resolve() / 'References'
        if (policy.get('namespace_version') != 2 or
                policy.get('view_id') != _GUEST_CONSOLE_VIEW_ID or
                policy.get('project_id') != _GUEST_CONSOLE_VIEW_ID or
                policy.get('references_folder') != 'References' or
                Path(policy.get('references_root', '')) != references or
                policy.get('readonly') is not True or not policy.get('policy_revision')):
            raise ValueError('The guest console needs the current read-only References policy.')
        key = hashlib.sha256(('guest-console-references\0' + str(self.workspace_root)).encode()).hexdigest()[:24]
        return {'key': key, 'root': references,
                'mounts': [{'host': references, 'guest': 'Files/References', 'writable': False, 'excluded': ()}],
                'remote': '/opt/harnessy-private/live/' + key, 'policy': policy, 'files_mode': 'readonly'}

    def file_view_capabilities(self):
        supported = not self._basic_copy
        return {'supported_modes': ('live', 'readonly', 'copy') if supported else ('copy',),
                'transport': 'sshfs' if supported and self.config.files_mode != 'copy' else 'copy',
                'runtime_mounts': supported and self.config.files_mode != 'copy',
                'project_isolation': supported, 'readonly_inputs': supported,
                'reconcile': supported, 'project_terminal': True, 'composite': supported,
                'whole_project_deployment': self.config.files_mode == 'copy',
                'file_backed_mmap': True, 'guest_references': supported,
                'guest_references_path': '/workspace/Files/References' if supported else ''}

    async def _reconcile_references(self, plan):
        # Older callers which do not plan the console view must leave an
        # existing console capability alone. Production plans always include
        # both fields, independently of Project membership and file mode.
        if 'references_policy' not in plan:
            return None
        if self._basic_copy:
            return {'state': 'unsupported',
                    'detail': 'Verified live References support is unavailable for this OpenWrt release.'}
        policy, invalid = plan.get('references_policy'), plan.get('references_error')
        result = {'policy_revision': str((policy or {}).get('policy_revision') or '')}
        projection = None
        try:
            if policy is not None and not invalid:
                projection = self._references_projection(policy)
                existing = self._live_mounts.views.get(projection['key'])
                if existing and existing.signature == self._live_mounts.signature(projection) and all(
                        not item.serving.done() and item.process.returncode is None for item in existing.exports):
                    await self._live_mounts.ensure(projection, project_id=_GUEST_CONSOLE_VIEW_ID)
                    return {**result, 'state': 'ready'}
            try:
                release = reserve_project_view_change(self.workspace_root, environment_id=self.config.id,
                    project_id=_GUEST_CONSOLE_VIEW_ID, owner_id=str(plan.get('_owner_id') or ''))
            except RuntimeError as busy:
                return {**result, 'state': 'pending', 'detail': str(busy)[:500]}
            try:
                await self._live_mounts.retire_project(_GUEST_CONSOLE_VIEW_ID)
                if projection is None:
                    return {**result, 'state': 'error', 'error_code': 'FILE_VIEW_SOURCE_INVALID',
                            'detail': str((invalid or {}).get('detail') or 'The References source is unavailable.')[:1000]}
                await self._live_mounts.ensure(projection, project_id=_GUEST_CONSOLE_VIEW_ID)
                return {**result, 'state': 'ready'}
            finally:
                release()
        except LiveMountBusyError as error:
            return {**result, 'state': 'pending', 'detail': str(error)[:500]}
        except Exception as error:
            from harnessy.diagnostics import log_event
            log_event('runtime', 'file_view_reconciliation_failed', environment_id=self.config.id,
                      project_id=_GUEST_CONSOLE_VIEW_ID, error_code='FILE_VIEW_TRANSPORT_FAILED', error=error)
            return {**result, 'state': 'error', 'error_code': 'FILE_VIEW_TRANSPORT_FAILED', 'detail': str(error)[:1000]}

    async def _projection_writer_context(self, projection, *, owner_id=''):
        policy = projection['policy']
        if not policy.get('_mutation_workspace_id') or not policy.get('_mutation_conflict_keys'):
            from .file_views import FILE_VIEWS
            workspace = await FILE_VIEWS.workspace(self.workspace_root)
            project_id = str(policy.get('project_id') or policy.get('_model_project_id') or policy.get('_human_project_id') or '')
            if not project_id:
                raise ValueError('A live file view needs its exact Project / Chat identity.')
            keys = await finish_thread(workspace.project_conflict_ids, project_id)
            policy.update(_mutation_workspace_id=workspace.id, _mutation_conflict_keys=tuple(keys),
                          _mutation_chat_id=project_id)
        if owner_id:
            policy['_mutation_owner_id'] = owner_id
        return projection

    def _refresh_file_config(self):
        from .base import load_environment_config
        current = load_environment_config(self.workspace_root, self.config.id)
        if current is None:
            raise RuntimeError('The selected VM no longer exists.')
        if (current.preset, current.architecture) != (self.config.preset, self.config.architecture):
            raise RuntimeError('This VM image changed; reopen its environment before using project files.')
        self.config = current
        return current

    async def reconcile_file_views(self, plan):
        current = self._refresh_file_config()
        if plan.get('environment_id') != current.id:
            raise ValueError('Project file plan belongs to a different VM.')
        if plan.get('files_mode') != current.files_mode:
            raise RuntimeError('The VM file mode changed while its plan was prepared; request its current plan.')
        errors = [dict(row) for row in plan.get('errors', ())]
        if not (await self.status()).running:
            return {'state': 'stopped', 'revision': plan['revision'], 'projects': [], 'pending_project_ids': [],
                    'references': {'state': 'stopped'}}
        references = await self._reconcile_references(plan)
        reference_result = {'references': references} if references is not None else {}
        if current.files_mode == 'copy':
            return {'state': 'error' if errors or (references or {}).get('state') == 'error' else
                    'pending' if (references or {}).get('state') == 'pending' else 'ready',
                'revision': plan['revision'], 'projects': [
                {'project_id': row['project_id'], 'folder': row['folder'], 'state': 'ready',
                 'policy_revision': row['policy']['policy_revision'],
                 'detail': 'Independent guest copy; explicit deployment limits apply.'} for row in plan['projects']] + errors,
                'pending_project_ids': [], **reference_result}
        if self._basic_copy:
            return {'state': 'unsupported', 'revision': plan['revision'], 'projects': [], 'pending_project_ids': [],
                    'detail': 'Verified live SSHFS integration is unavailable for this OpenWrt release.', **reference_result}
        requested = {row['project_id']: row for row in plan['projects'] if row['project_id'] != _GUEST_CONSOLE_VIEW_ID}
        known = {row['project_id']: row for row in plan.get('known_projects', ()) if row['project_id'] != _GUEST_CONSOLE_VIEW_ID}
        known.update(requested)
        # Permanently removed chats no longer occur in the database plan, but
        # their owned live transports must still be retired.
        for view in tuple(self._live_mounts.views.values()):
            if view.project_id == _GUEST_CONSOLE_VIEW_ID:
                continue
            known.setdefault(view.project_id, {'project_id': view.project_id,
                'folder': view.projection['policy'].get('writable_folder', '')})
        rows, pending = list(errors), []
        invalid = {row['project_id'] for row in errors}
        for project_id, row in known.items():
            wanted = requested.get(project_id)
            result = {'project_id': project_id, 'folder': row.get('folder', '')}
            if wanted:
                result['policy_revision'] = wanted['policy']['policy_revision']
            projection = None
            try:
                if wanted:
                    policy = dict(wanted['policy'])
                    projection = self._projection(Path(policy['project_root']), policy)
                    await self._projection_writer_context(projection)
                    existing = self._live_mounts.views.get(projection['key'])
                    if existing and existing.signature == self._live_mounts.signature(projection) and all(
                            not item.serving.done() and item.process.returncode is None for item in existing.exports):
                        await self._live_mounts.ensure(projection, project_id=project_id)
                        rows.append({**result, 'state': 'ready'})
                        continue
                try:
                    release = reserve_project_view_change(self.workspace_root, environment_id=current.id,
                        project_id=project_id, owner_id=str(plan.get('_owner_id') or ''))
                except RuntimeError as busy:
                    pending.append(project_id)
                    rows.append({**result, 'state': 'pending', 'detail': str(busy)[:500]})
                    continue
                try:
                    await self._live_mounts.retire_project(project_id)
                    if projection is not None:
                        await self._live_mounts.ensure(projection, project_id=project_id)
                    elif project_id not in invalid:
                        await self._live_mounts.retire_stale(row.get('folder', ''))
                    if project_id not in invalid:
                        rows.append({**result, 'state': 'ready' if wanted else 'unmounted'})
                finally:
                    release()
            except LiveMountBusyError as error:
                pending.append(project_id)
                rows.append({**result, 'state': 'pending', 'detail': str(error)[:500]})
            except Exception as error:
                from harnessy.diagnostics import log_event
                log_event('runtime', 'file_view_reconciliation_failed', environment_id=current.id,
                          project_id=project_id, error_code='FILE_VIEW_TRANSPORT_FAILED', error=error)
                # Setup/package/transport failures need an actionable retry;
                # only a known activity reservation is classified as pending.
                rows.append({**result, 'state': 'error', 'error_code': 'FILE_VIEW_TRANSPORT_FAILED',
                             'detail': str(error)[:1000]})
        failed = any(row['state'] == 'error' for row in rows) or (references or {}).get('state') == 'error'
        return {'state': 'error' if failed else 'pending' if pending or (references or {}).get('state') == 'pending' else 'ready',
                'revision': plan['revision'], 'projects': rows,
                'pending_project_ids': pending,
                **({'error_code': 'FILE_VIEW_TRANSPORT_FAILED'} if failed else {}), **reference_result}

    async def _live_projection(self, active_root, policy, *, human=False):
        self._refresh_file_config()
        policy = dict(policy or {})
        view_owner = str(policy.get('_file_view_owner_id') or uuid.uuid4().hex)
        project_id = str(policy.get('project_id') or policy.get('_model_project_id') or policy.get('_human_project_id') or '')
        if not project_id:
            raise ValueError('Choose an exact Project / Chat before opening its VM files.')
        if project_id:
            from .file_views import FILE_VIEWS
            fresh = await FILE_VIEWS.ensure_project(self.workspace_root, environment_id=self.config.id,
                project_id=project_id, owner_id=view_owner, human=human)
            # Preserve the trusted active-run lease context, never caller ACLs.
            fresh.update({key: value for key, value in policy.items() if key.startswith('_mutation_')})
            policy = fresh
        policy['_file_view_owner_id'] = view_owner
        projection = self._projection(active_root, policy)
        await self._projection_writer_context(projection)
        self._live_mounts.verified(projection)
        return projection

    def _destination(self, projection, index):
        if self._basic_copy:
            return '/workspace' + ('/' + projection['mounts'][index]['guest'] if projection['mounts'][index]['guest'] else '')
        return projection['remote'] + '/' + str(index)

    def _baseline_path(self, projection, index):
        return self.state_root / f'projection-{projection["key"]}-{index}.json'

    def _authorize_model(self, policy):
        self._authorize_model_project(policy)

    @asynccontextmanager
    async def _host_writer(self, projection):
        # A retained writable export must keep its writer coordination even
        # while a newer mode change is waiting for active work to finish.
        if projection.get('files_mode') == 'copy':
            yield
            return
        policy = projection['policy']
        project_id = str(policy.get('project_id') or policy.get('_mutation_chat_id') or '')
        # Mounts are shared by human and model sessions. Model enablement is
        # enforced on command admission; the source server enforces exact
        # current Project access and policy for every canonical write.
        source_policy = {**policy, '_human_project_id': project_id}
        self._authorize_model(source_policy)
        workspace_id = str(policy.get('_mutation_workspace_id') or '')
        keys = tuple(policy.get('_mutation_conflict_keys') or ())
        if not workspace_id or not keys:
            raise RuntimeError('Live project files are missing their shared writer context; source files were preserved.')
        from harnessy.agent.scheduler import WORKSPACE_MUTATIONS
        async with WORKSPACE_MUTATIONS.project_io(
            workspace_id=workspace_id, label='OpenWrt live project file write', conflict_keys=keys,
            project_chat_id=str(policy.get('_mutation_chat_id') or ''),
        ):
            self._authorize_model(source_policy)
            yield

    async def _sync(self, projection: dict, *, refresh: bool = False):
        if projection.get('files_mode', self.config.files_mode) != 'copy':
            self._live_mounts.verified(projection)
            return
        async with self._host_writer(projection), _SYNC_LOCKS.setdefault(str(self.environment_root) + projection['key'], asyncio.Lock()):
            for index, mount in enumerate(projection['mounts']):
                destination = self._destination(projection, index)
                marker = self._baseline_path(projection, index)
                try:
                    baseline = json.loads(marker.read_text())
                except (OSError, ValueError):
                    baseline = {}
                exists = (await self._raw('test -d ' + destination))[0] == 0
                if self.config.files_mode == 'copy' and exists and not refresh:
                    continue
                host = await finish_thread(scan_tree, mount['host'], excluded=mount['excluded'])
                if exists and marker.exists() and mount['writable'] and self.config.files_mode == 'live' and not refresh:
                    raw = await self._checked('tar -cf - -C ' + destination + ' .', timeout=120)
                    guest = await finish_thread(read_archive, raw)
                    self._authorize_model(projection['policy'])
                    host = await finish_thread(merge_guest_changes, mount['host'], baseline, guest, excluded=mount['excluded'])
                # Changing a projection's backing directory in place would
                # invalidate open files. Update regular files through a checked
                # guest Python transaction, retaining the directory inode.
                archive = await finish_thread(archive_tree, host)
                self._authorize_model(projection['policy'])
                await self._push(destination, archive)
                _atomic_json(marker, signatures(host))

    async def _push(self, destination: str, archive: bytes):
        # The incoming archive is produced by scan_tree/archive_tree, which
        # validate every path and relative symlink before transmission.
        stage = destination + '.incoming-' + uuid.uuid4().hex
        if self._basic_copy:
            previous = destination + '.previous-' + uuid.uuid4().hex
            script = f'''set -eu
mkdir -p {shlex.quote(str(PurePosixPath(destination).parent))}
[ ! -L {shlex.quote(destination)} ] || exit 72
mkdir -m 700 {shlex.quote(stage)}
tar -xf - -C {shlex.quote(stage)}
if [ -e {shlex.quote(destination)} ]; then mv {shlex.quote(destination)} {shlex.quote(previous)}; fi
if ! mv {shlex.quote(stage)} {shlex.quote(destination)}; then
 [ ! -e {shlex.quote(previous)} ] || mv {shlex.quote(previous)} {shlex.quote(destination)}
 exit 73
fi
rm -rf -- {shlex.quote(previous)}
'''
            await self._checked(script, data=archive, timeout=300)
            return
        script = f'''set -eu
mkdir -p -m 700 {shlex.quote(stage)}
tar -xf - -C {shlex.quote(stage)}
mkdir -p -m 700 {shlex.quote(destination)}
python3 -c {shlex.quote(_REPLACE_GUEST_TREE)} {shlex.quote(stage)} {shlex.quote(destination)}
'''
        await self._checked(script, data=archive, timeout=300)

    async def _collect(self, projection: dict):
        # Live writes are served directly to canonical source; independent
        # copies are never collected implicitly.
        return

    def _command(self, projection: dict, command: str, cwd: str) -> str:
        path = PurePosixPath(str(cwd))
        if not path.is_absolute() or '..' in path.parts or (str(path) != '/workspace' and not str(path).startswith('/workspace/')):
            raise ValueError('Working directory must be inside /workspace.')
        command = self._guest_work_path_exports(projection['root']) + '\n' + command
        if self._basic_copy:
            return 'cd ' + shlex.quote(str(path)) + ' && exec /bin/ash -c ' + shlex.quote(command)
        lines = ['set -e', 'mount --make-rprivate /', 'mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /workspace']
        own_guest = projection['mounts'][0]['guest']
        if self.config.files_mode == 'copy':
            for row in projection['mounts'][1:]:
                if own_guest and row['guest'].startswith(own_guest + '/'):
                    lines.append('mkdir -p ' + shlex.quote(projection['remote'] + '/0/' + row['guest'][len(own_guest) + 1:]))
        for index, row in enumerate(projection['mounts']):
            target = '/workspace' + ('/' + row['guest'] if row['guest'] else '')
            source = projection['remote'] + '/' + str(index)
            lines += ['[ -d ' + shlex.quote(target) + ' ] || mkdir -p ' + shlex.quote(target), 'mount --bind ' + shlex.quote(source) + ' ' + shlex.quote(target)]
            if not row['writable']:
                lines.append('mount -o remount,bind,ro ' + shlex.quote(target))
        # Neither backing projections nor host controller paths are available
        # to model code. Root-only setup finishes before dropping privileges.
        executor = 'exec /bin/bash -c ' if self.config.files_mode == 'copy' else 'exec sudo -n -H -u harnessy -- /bin/bash -c '
        lines += ['mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs /opt/harnessy-private',
                  'cd ' + shlex.quote(str(path)), executor + shlex.quote('cd ' + shlex.quote(str(path)) + ' && ' + command)]
        return 'exec unshare --mount --pid --fork --mount-proc /bin/bash -c ' + shlex.quote('\n'.join(lines))

    async def exec(self, command: str, *, cwd='/workspace', timeout=None, active_root=None, output_policy=None) -> ExecResult:
        self._refresh_file_config()
        if not str(command).strip():
            raise ValueError('Command must not be empty.')
        self._authorize_model(output_policy)
        if not self._ready:
            await self.start()
        projection = (self._projection(active_root, output_policy) if self.config.files_mode == 'copy'
                      else await self._live_projection(active_root, output_policy))
        project_id = str(projection['policy'].get('project_id') or projection['policy'].get('_model_project_id') or projection['policy'].get('_mutation_chat_id') or '')
        release = acquire_activity(self.workspace_root, 'OpenWrt guest command', environment_id=self.config.id,
            project_id=project_id or None, owner_id=str(projection['policy'].get('_file_view_owner_id') or uuid.uuid4().hex))
        started = time.monotonic()
        try:
            await self._sync(projection)
            self._authorize_model(projection['policy'])
            try:
                rc, out, err = await self._raw(self._command(projection, command, cwd), timeout=timeout or 3600)
            except BaseException:
                collection = asyncio.create_task(self._collect(projection))
                try:
                    await asyncio.shield(collection)
                except BaseException as sync_error:
                    _atomic_json(self.state_root / 'sync-error.json', {'error': str(sync_error), 'updated_at': time.time()})
                    if not collection.done():
                        await collection
                raise
            try:
                await self._collect(projection)
            except Exception as exc:
                return ExecResult(74, out.decode(errors='replace'), err.decode(errors='replace') + '\n' + str(exc), time.monotonic() - started)
            return ExecResult(rc, out.decode(errors='replace'), err.decode(errors='replace'), time.monotonic() - started)
        finally:
            release()

    async def spawn(self, command: str, *, cwd='/workspace', active_root=None, output_policy=None):
        self._refresh_file_config()
        if not str(command).strip():
            raise ValueError('Command must not be empty.')
        self._authorize_model(output_policy)
        if not self._ready:
            await self.start()
        projection = (self._projection(active_root, output_policy) if self.config.files_mode == 'copy'
                      else await self._live_projection(active_root, output_policy))
        await self._sync(projection)
        self._authorize_model(projection['policy'])
        project_id = str(projection['policy'].get('project_id') or projection['policy'].get('_model_project_id') or projection['policy'].get('_mutation_chat_id') or '')
        release = acquire_activity(self.workspace_root, 'OpenWrt guest process', environment_id=self.config.id,
            project_id=project_id or None, owner_id=uuid.uuid4().hex)
        argv, env = self.controller.command(self._command(projection, command, cwd))
        try:
            process = await asyncio.create_subprocess_exec(*argv, env=env, cwd=self.environment_root,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except BaseException:
            release()
            raise
        async def watch():
            waiter = asyncio.create_task(process.wait())
            try:
                while process.returncode is None:
                    try:
                        await asyncio.wait_for(asyncio.shield(waiter), 2)
                    except asyncio.TimeoutError:
                        try:
                            await self._collect(projection)
                        except Exception as exc:
                            _atomic_json(self.state_root / 'sync-error.json', {'error': str(exc), 'updated_at': time.time()})
                await self._collect(projection)
            finally:
                release()
        task = asyncio.create_task(watch())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return process

    async def refresh_project_copy(self, active_root=None, output_policy=None):
        self._refresh_file_config()
        self._authorize_model(output_policy)
        if self.config.files_mode != 'copy':
            raise ValueError('Explicit deployment refresh is for independent-copy mode.')
        if not self._ready:
            await self.start()
        release = reserve_environment_change(self.workspace_root, 'project deployment', environment_id=self.config.id)
        try:
            projection = self._projection(active_root, output_policy)
            self._authorize_model(output_policy)
            await self._sync(projection, refresh=True)
            self._authorize_model(output_policy)
            return {'environment_id': self.config.id, 'files_mode': 'copy', 'deployed': True}
        finally:
            release()

    async def collect_file(self, relative_path: str, destination: Path, *, active_root=None, output_policy=None):
        self._refresh_file_config()
        self._authorize_model(output_policy)
        from .project_sync import relative_path as checked_relative
        name = checked_relative(str(relative_path))
        if not self._ready:
            await self.start()
        projection = (self._projection(active_root, output_policy) if self.config.files_mode == 'copy'
                      else await self._live_projection(active_root, output_policy))
        await self._sync(projection)
        self._authorize_model(projection['policy'])
        source = self._destination(projection, 0) + '/' + name
        if self._basic_copy:
            # No guest interpreter is assumed. A tar member is inspected on
            # the host and only a regular file payload is accepted.
            payload = await self._checked('tar -cf - -C ' + shlex.quote(self._destination(projection, 0)) + ' ' + shlex.quote(name))
            rows = read_archive(payload)
            entry = rows.get(name)
            if entry is None or entry.kind != 'file':
                raise ValueError('Artifact must be a regular guest file.')
            data = entry.data
        else:
            command = 'python3 -c ' + shlex.quote(_READ_GUEST_FILE) + ' ' + shlex.quote(source)
            data = await self._checked(command)
        self._authorize_model(output_policy)
        destination = Path(destination)
        if destination.is_symlink() or destination.exists():
            raise ValueError('Artifact destination already exists.')
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open('xb') as stream:
            stream.write(data)
        return {'path': str(destination), 'bytes': len(data)}

    def _human_policy(self, active_root, workspace):
        root = Path(active_root or self.files_root).resolve()
        chats = workspace.list_chats(archived=None)
        own = next((chat for chat in chats if Path(workspace.active_root_path(chat.id)).resolve() == root), None)
        policy = workspace.output_policy(own.id) if own else {}
        if own:
            policy.update(project_id=own.id, _human_project_id=own.id)
        policy.update(_mutation_workspace_id=workspace.id,
                      _mutation_conflict_keys=tuple(dict.fromkeys(key for chat in (own,) if chat for key in workspace.project_conflict_ids(chat.id))) if own else tuple(dict.fromkeys(key for chat in chats for key in workspace.project_conflict_ids(chat.id))),
                      _mutation_chat_id=own.id if own else '', _mutation_owner_id='')
        if not policy['_mutation_conflict_keys']:
            policy['_mutation_conflict_keys'] = ('workspace-terminal:' + workspace.id,)
        return policy

    def _guest_console_command(self, projection=None):
        command = ('set -eu\ncd /root\n' + self._guest_work_path_exports()
                   + '\nexec /bin/ash -i')
        if projection is None:
            return command
        target = '/workspace/Files/References'
        source = projection['remote'] + '/0'
        # A fresh namespace exposes References alongside the VM's own files,
        # without binding any Project. Guest-root administration is retained;
        # the host-side SFTP capability independently rejects every write.
        lines = ['set -eu', 'mount --make-rprivate /',
                 'mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /workspace',
                 'mkdir -p ' + shlex.quote(target),
                 'mount --bind ' + shlex.quote(source) + ' ' + shlex.quote(target),
                 'mount -o remount,bind,ro ' + shlex.quote(target),
                 'mount -t tmpfs -o mode=0700,nosuid,nodev tmpfs /opt/harnessy-private', command]
        return 'exec unshare --mount --pid --fork --mount-proc /bin/bash -c ' + shlex.quote('\n'.join(lines))

    async def open_guest_terminal(self, *, workspace=None, owner_id=''):
        """Open a root console with verified read-only References when supported."""
        from .file_views import FILE_VIEWS, FileViewUnavailableError
        self._refresh_file_config()
        if workspace is not None and Path(workspace.root).resolve() != self.workspace_root.resolve():
            raise ValueError('The guest console workspace identity does not match this VM.')
        if not self._basic_copy and FILE_VIEWS.cached_workspace(self.workspace_root) is None:
            raise FileViewUnavailableError('Open the workspace again before opening its References console.', 'FILE_VIEW_FAILED')
        owner_id = str(owner_id or uuid.uuid4().hex)
        if self._basic_copy:
            release = acquire_activity(self.workspace_root, 'Opening OpenWrt guest console',
                environment_id=self.config.id, project_id=_GUEST_CONSOLE_VIEW_ID, owner_id=owner_id)
        else:
            release = await FILE_VIEWS.acquire_terminal_activity(self.workspace_root,
                environment_id=self.config.id, project_id=_GUEST_CONSOLE_VIEW_ID,
                owner_id=owner_id, label='Opening OpenWrt guest console')
        try:
            await self.start()
            projection = None
            if not self._basic_copy:
                policy = await FILE_VIEWS.ensure_references(self.workspace_root, environment_id=self.config.id,
                                                            owner_id=owner_id)
                admitted = FILE_VIEWS.cached_workspace(self.workspace_root)
                if admitted is None:
                    raise FileViewUnavailableError('Open the workspace again before opening its References console.', 'FILE_VIEW_FAILED')
                from harnessy.core.project_mounts import build_references_policy
                try:
                    fresh = await finish_thread(build_references_policy, admitted)
                except (OSError, ValueError) as error:
                    raise FileViewUnavailableError('References changed before this console could open.', 'FILE_VIEW_POLICY_CHANGED') from error
                if (FILE_VIEWS.cached_workspace(self.workspace_root) is not admitted or
                        fresh['policy_revision'] != policy['policy_revision']):
                    raise FileViewUnavailableError('References changed before this console could open.', 'FILE_VIEW_POLICY_CHANGED')
                projection = self._references_projection(policy)
                self._live_mounts.verified(projection)
            argv, env = self.controller.command(self._guest_console_command(projection))
            argv[argv.index('-T')] = '-tt'
            return argv, env, self.workspace_root
        finally:
            release()

    async def open_terminal(self, *, active_root=None, output_policy=None, workspace=None):
        return await self.open_project_terminal(active_root=active_root, output_policy=output_policy, workspace=workspace)

    def _project_terminal_shell(self) -> str:
        if self._basic_copy:
            return 'exec /bin/ash -i'
        # Stock OpenWrt has no Bash rc file to replace its bare bash-5.x$
        # fallback. Supply an interactive default, while allowing a user's
        # own .bashrc to override it. Keep the VM label in a separate variable
        # so prompt expansion never treats a name as shell code.
        label = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', str(self.config.name)).strip()[:120] or 'OpenWrt'
        return ('export HARNESSY_VM_NAME=' + shlex.quote(label)
                + "\nexport PS1='\\u@${HARNESSY_VM_NAME}:\\w\\$ '\nexec /bin/bash -i")

    async def open_project_terminal(self, *, active_root=None, output_policy=None, workspace=None):
        self._refresh_file_config()
        await self.start()
        if output_policy is None and workspace is not None:
            output_policy = self._human_policy(active_root, workspace)
        if output_policy is None:
            # Only explicit user terminals can select all workspace Files. The
            # store is loaded for writer identity, not for guest execution.
            from harnessy.core.workspace import WorkspaceStore
            store = await finish_thread(WorkspaceStore, self.workspace_root)
            output_policy = await finish_thread(self._human_policy, active_root, store)
        projection = (self._projection(active_root, output_policy) if self.config.files_mode == 'copy'
                      else await self._live_projection(active_root, output_policy, human=True))
        await self._sync(projection)
        self._authorize_model(projection['policy'])
        cwd = '/workspace/' + projection['mounts'][0]['guest'] if projection['mounts'][0]['guest'] else '/workspace'
        argv, env = self.controller.command(self._command(projection, self._project_terminal_shell(), cwd))
        argv[argv.index('-T')] = '-tt'
        self._terminal_projections[tuple(argv)] = projection
        return argv, env, self.workspace_root

    def terminal_command(self, *, active_root=None, output_policy=None):
        raise RuntimeError('OpenWrt terminals need asynchronous project preparation; use open_terminal().')

    async def attach_terminal_session(self, session, *, workspace=None):
        projection = self._terminal_projections.pop(tuple(session.command_argv or ()), None)
        if projection is None:
            raise RuntimeError('Terminal does not belong to this prepared OpenWrt project view.')
        if self.config.files_mode != 'copy':
            # TerminalSession owns the project-scoped lifecycle token. Live
            # source writes are served on demand and need no copy collector.
            return None
        if workspace is not None:
            projection['policy'].update(self._human_policy(projection['root'], workspace))
        release = acquire_activity(self.workspace_root, 'OpenWrt terminal synchronization', environment_id=self.config.id)
        async def watch():
            try:
                while session.process is not None and session.process.poll() is None:
                    await asyncio.sleep(2)
                    try:
                        await self._collect(projection)
                    except Exception as exc:
                        _atomic_json(self.state_root / 'sync-error.json', {'error': str(exc), 'updated_at': time.time()})
                await self._collect(projection)
            finally:
                release()
        task = asyncio.create_task(watch())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def stop(self, *, force=False) -> EnvironmentStatus:
        self._validate_private_runtime()
        if not force and active_work(self.workspace_root, environment_id=self.config.id):
            raise RuntimeError("Finish this VM’s commands and close its terminals before stopping it.")
        if not force:
            await self._live_mounts.close()
        if force and (await self.controller.status())['running']:
            await self.controller.qmp('quit')
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    if not (await self.controller.status())['running']:
                        break
                except (OSError, RuntimeError, asyncio.TimeoutError):
                    pass
                await asyncio.sleep(0.25)
            else:
                raise RuntimeError('Could not verify that this VM stopped; its disk was preserved.')
        else:
            await self.controller.stop()
        if force:
            await self._live_mounts.close(force=True)
        self._record(ready=False, running=False, event='stopped')
        from .file_views import FILE_VIEWS
        FILE_VIEWS.request(self.workspace_root, reason='vm_stop', environment_id=self.config.id)
        return await self.status()

    async def snapshot(self, tag, progress=None) -> list[str]:
        self._validate_private_runtime(self.environment_root / 'snapshots' / self.controller._tag(tag))
        if active_work(self.workspace_root, environment_id=self.config.id):
            raise RuntimeError('Finish this VM commands and close its terminals before taking a snapshot.')
        await self.controller.snapshot(tag)
        return await self.list_snapshots()

    async def list_snapshots(self) -> list[str]:
        return self.controller.snapshots()

    async def restore_snapshot(self, tag, progress=None) -> EnvironmentStatus:
        self._validate_private_runtime(self.environment_root / 'snapshots' / self.controller._tag(tag))
        if active_work(self.workspace_root, environment_id=self.config.id):
            raise RuntimeError('Finish this VM commands and close its terminals before restoring a snapshot.')
        await self.controller.restore(tag)
        # Snapshots contain guest project copies. Canonical project source is
        # authoritative; never interpret a restored old copy as a new edit.
        for marker in self.state_root.glob('projection-*.json'):
            marker.unlink()
        self._record(ready=False, running=False, event='restored')
        return await self.start(progress=progress)

    async def reset(self, progress=None) -> EnvironmentStatus:
        self._validate_private_runtime()
        await self.stop()
        if self.controller.instance_dir.exists():
            await finish_thread(shutil.rmtree, self.controller.instance_dir)
        for marker in self.state_root.glob('projection-*.json'):
            marker.unlink()
        self._record(ready=False, running=False, event='reset')
        # Project source is outside the private guest directory and preserved.
        return await self.start(progress=progress)

    async def rebuild(self, progress=None) -> EnvironmentStatus:
        return await self.reset(progress=progress)

    async def destroy(self):
        self._validate_private_runtime()
        await self.stop()
        if (await self.controller.status())['state'] not in {'stopped', 'not_created'}:
            raise RuntimeError('The selected VM could not be verified stopped; its disk was preserved.')
        self._validate_private_runtime()
        # Delete only controller-owned guest data, never workspace files,
        # configuration, snapshots, or the caller's selected source directory.
        if self.controller.instance_dir.exists():
            await finish_thread(shutil.rmtree, self.controller.instance_dir)
        self._record(ready=False, running=False, event='destroyed')

    async def apply_network_policy(self, enabled: bool, *, expected=None, progress=None, reservation_held=False):
        from dataclasses import replace
        from .base import load_environment_config, save_environment_config
        release = (lambda: None) if reservation_held else reserve_environment_change(self.workspace_root, 'network policy', environment_id=self.config.id)
        try:
            original = load_environment_config(self.workspace_root, self.config.id)
            if original is None:
                raise RuntimeError('The selected VM environment no longer exists.')
            if expected is not None and original.network != expected:
                raise RuntimeError('This VM network setting changed; refresh its settings.')
            if (await self.status()).running:
                raise RuntimeError('Stop this OpenWrt VM before changing its QEMU network policy.')
            self.config = replace(original, network=bool(enabled))
            self.controller.config['internet'] = self.config.network
            save_environment_config(self.workspace_root, self.config, preserve_user_metadata=True)
            self.config = load_environment_config(self.workspace_root, self.config.id) or self.config
            return await self.status()
        finally:
            release()

    async def apply_resources(self, *, cpu, memory_mb, disk_gb, expected=None, progress=None, reservation_held=False):
        from dataclasses import replace
        from .base import load_environment_config, save_environment_config
        release = (lambda: None) if reservation_held else reserve_environment_change(self.workspace_root, 'VM resources', environment_id=self.config.id)
        try:
            if (await self.status()).running:
                raise RuntimeError('Stop this OpenWrt VM before changing resources.')
            original = load_environment_config(self.workspace_root, self.config.id)
            if original is None:
                raise RuntimeError('The selected VM environment no longer exists.')
            if expected is not None and any(int(expected[key]) != getattr(original, key) for key in ('cpu', 'memory_mb', 'disk_gb')):
                raise RuntimeError('VM resources changed since this editor opened; refresh before applying.')
            desired = replace(original, cpu=int(cpu), memory_mb=int(memory_mb), disk_gb=int(disk_gb)).normalized()
            if desired.architecture.startswith('mips') and (desired.cpu != 1 or desired.memory_mb > 2048):
                raise ValueError('Malta MIPS supports one CPU and at most 2048 MiB RAM.')
            if desired.disk_gb > 64 or desired.disk_gb < original.disk_gb:
                raise ValueError('OpenWrt storage can only grow, up to 64 GiB.')
            disk = self.controller.instance_dir / 'rootfs.raw'
            if disk.exists() and desired.disk_gb != original.disk_gb:
                from .openwrt_target import e2fs_binary
                with disk.open('r+b') as stream:
                    stream.truncate(desired.disk_gb * 1024**3)
                await self.controller.host_command([e2fs_binary('e2fsck'), '-f', '-p', disk], allowed=(0, 1))
                await self.controller.host_command([e2fs_binary('resize2fs'), disk])
            self.config = desired
            self.controller.config.update(cpu=desired.cpu, memory_mb=desired.memory_mb, disk_gb=desired.disk_gb)
            save_environment_config(self.workspace_root, desired, preserve_user_metadata=True)
            self.config = load_environment_config(self.workspace_root, desired.id) or desired
            return await self.status()
        finally:
            release()

    def desktop_manager(self, workspace=None):
        return self.controller

    async def inspect(self) -> dict[str, Any]:
        status = await self.status()
        host_storage = await finish_thread(self._host_storage_usage)
        storage_compat = {}
        if host_storage['allocated_bytes'] is not None:
            storage_compat['vm_storage_bytes'] = host_storage['allocated_bytes']
        if host_storage['logical_bytes'] is not None:
            storage_compat['vm_storage_logical_bytes'] = host_storage['logical_bytes']
        try:
            identity = json.loads((self.state_root / 'guest.json').read_text())
        except (OSError, ValueError):
            identity = {'observation': 'not_probed'}
        return {'config': self.config.to_dict(), 'status': status.to_dict(), 'snapshots': await self.list_snapshots(),
                **storage_compat,
                'files_root': str(self.files_root), 'guest_files_root': '/workspace',
                'durable_vm_root': str(self.vm_root), 'runtime_qemu_root': str(self.controller.runtime_dir()),
                'vm_type': 'qemu', 'mount_type': 'separate-copy' if self.config.files_mode == 'copy' else 'sshfs', 'snapshot_strategy': 'stopped-disk-copy',
                'guest_identity': identity, 'optional_tools': await self.optional_tool_status(),
                'unavailable_tools': OPENWRT_UNAVAILABLE_TOOLS,
                'capabilities': {'administrative_guest_commands': self.config.files_mode == 'copy', 'project_files': 'separate_guest_copy' if self.config.files_mode == 'copy' else 'live_authorized_view'},
                'hardware_emulation': self.controller.radio_state(),
                'files_bridge': {'kind': 'copy' if self.config.files_mode == 'copy' else 'sshfs', 'mode': self.config.files_mode,
                    'capabilities': self.file_view_capabilities(),
                    'note': 'Explicit bounded deployment and artifact collection.' if self.config.files_mode == 'copy' else
                    'Exact host sources served on demand over owned SSHFS channels. New opens see host edits; existing descriptors and mapped pages follow network filesystem cache semantics.'}}


_REPLACE_GUEST_TREE = r'''
import os, stat, sys
source, target = sys.argv[1:]
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
src_fd, dst_fd = os.open(source, flags), os.open(target, flags)
def names(fd):
 with os.scandir(fd) as iterator: return [row.name for row in iterator]
def remove(fd, name):
 info = os.stat(name, dir_fd=fd, follow_symlinks=False)
 if stat.S_ISDIR(info.st_mode):
  child = os.open(name, flags, dir_fd=fd)
  try:
   for entry in names(child): remove(child, entry)
  finally: os.close(child)
  os.rmdir(name, dir_fd=fd)
 else: os.unlink(name, dir_fd=fd)
def same_file(left, right, name):
 try:
  a = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=left)
  b = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=right)
 except OSError: return False
 try:
  sa, sb = os.fstat(a), os.fstat(b)
  if not stat.S_ISREG(sa.st_mode) or not stat.S_ISREG(sb.st_mode) or sa.st_size != sb.st_size or (sa.st_mode & 0o777) != (sb.st_mode & 0o777): return False
  while True:
   x, y = os.read(a, 1024*1024), os.read(b, 1024*1024)
   if x != y: return False
   if not x: return True
 finally: os.close(a); os.close(b)
def reconcile(src, dst):
 incoming = set(names(src))
 for old in names(dst):
  if old not in incoming: remove(dst, old)
 for name in incoming:
  info = os.stat(name, dir_fd=src, follow_symlinks=False)
  try: old = os.stat(name, dir_fd=dst, follow_symlinks=False)
  except FileNotFoundError: old = None
  if stat.S_ISDIR(info.st_mode):
   if old is not None and not stat.S_ISDIR(old.st_mode): remove(dst, name); old = None
   if old is None: os.mkdir(name, info.st_mode & 0o777, dir_fd=dst)
   child_src, child_dst = os.open(name, flags, dir_fd=src), os.open(name, flags, dir_fd=dst)
   try:
    reconcile(child_src, child_dst)
    os.fchown(child_dst, 1000, 1000); os.fchmod(child_dst, info.st_mode & 0o777)
   finally: os.close(child_src); os.close(child_dst)
  elif stat.S_ISREG(info.st_mode):
   if old is not None and stat.S_ISREG(old.st_mode) and same_file(src, dst, name): continue
   if old is not None and stat.S_ISDIR(old.st_mode): remove(dst, name)
   os.chown(name, 1000, 1000, dir_fd=src, follow_symlinks=False)
   os.replace(name, name, src_dir_fd=src, dst_dir_fd=dst)
  elif stat.S_ISLNK(info.st_mode):
   if old is not None and stat.S_ISLNK(old.st_mode) and os.readlink(name, dir_fd=src) == os.readlink(name, dir_fd=dst): continue
   if old is not None and stat.S_ISDIR(old.st_mode): remove(dst, name)
   os.chown(name, 1000, 1000, dir_fd=src, follow_symlinks=False)
   os.replace(name, name, src_dir_fd=src, dst_dir_fd=dst)
  else: raise RuntimeError('Incoming project has a special file')
try:
 reconcile(src_fd, dst_fd)
 os.fchown(dst_fd, 1000, 1000)
finally:
 os.close(src_fd); os.close(dst_fd)
# The incoming directory is controller-owned and cannot be edited by the
# unprivileged project user. Cleanup remains entirely inside the guest.
import shutil
shutil.rmtree(source)
'''
_READ_GUEST_FILE = r'''
import os, stat, sys
path = sys.argv[1]
parts = path.split('/')[1:]
fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
try:
 for part in parts[:-1]:
  child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
  os.close(fd)
  fd = child
 stream_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
finally:
 os.close(fd)
with os.fdopen(stream_fd, 'rb') as stream:
 if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise SystemExit('Artifact must be a regular file')
 if os.fstat(stream.fileno()).st_size > 512*1024*1024: raise SystemExit('Artifact exceeds 512 MiB limit')
 while True:
  data = stream.read(1024*1024)
  if not data: break
  sys.stdout.buffer.write(data)
'''
