"""Rootless OpenWrt test guests using official kernel + ext4 rootfs images.

OpenWrt has no cloud-init. Prepare its private filesystem with e2fsprogs, then
boot QEMU directly, following upstream scripts/qemustart's root=/dev/vda path.
No host mounts, TAP interfaces, bridge permissions or forwarded host agent.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import platform
import secrets
import shlex
import shutil
import socket
import tempfile
import threading
import time
import uuid
from pathlib import Path

from .host_prerequisites import (discover_binary, repaired_path, ensure_test_target_prerequisites,
                                 test_target_qemu_binary)
from .presets import canonical_arch
from .test_catalog import OPENWRT_RELEASE_IMAGES
from .test_images import download_verified, expand_gzip, finish_thread
from .test_targets import TestTargetManager, TestTargetFailure

OPENWRT_READINESS_SECONDS = 240.0
OPENWRT_POLL_SECONDS = 2.0
OPENWRT_LAUNCH_SECONDS = 30.0
_LAUNCH_REAPERS: set[asyncio.Task] = set()
_COMMAND_TRANSPORT_SESSION = secrets.token_hex(8)
_COMMAND_TRANSPORTS: dict[str, tuple[str, int]] = {}
_COMMAND_TRANSPORT_LOCK = threading.Lock()


def qemu_binary(architecture: str) -> str:
    return test_target_qemu_binary(architecture)


def e2fs_binary(name: str) -> str | None:
    found = discover_binary(name)
    if found:
        return found
    for prefix in ('/opt/homebrew/opt/e2fsprogs', '/usr/local/opt/e2fsprogs', '/home/linuxbrew/.linuxbrew/opt/e2fsprogs'):
        candidate = Path(prefix) / 'sbin' / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def bootstrap_script(public_key: str, password: str, web: bool) -> str:
    if '\n' in public_key.strip() or not public_key.startswith('ssh-ed25519 ') or not password.isalnum():
        raise ValueError('Invalid guest bootstrap credentials.')
    return f'''#!/bin/sh
set -eu
cat > /etc/config/network <<'NETWORK'
config interface 'loopback'
    option device 'lo'
    option proto 'static'
    option ipaddr '127.0.0.1'
    option netmask '255.0.0.0'
config interface 'lan'
    option device 'eth0'
    option proto 'static'
    option ipaddr '192.168.77.2'
    option netmask '255.255.255.0'
config interface 'wan'
    option device 'eth1'
    option proto 'dhcp'
NETWORK
uci set dhcp.lan.ignore='1'
uci set dropbear.@dropbear[0].PasswordAuth='off'
uci set dropbear.@dropbear[0].RootPasswordAuth='off'
uci set dropbear.@dropbear[0].Interface='lan'
uci commit
mkdir -p /etc/dropbear /root/hx-test
printf '%s\n' {shlex.quote(public_key.strip())} > /etc/dropbear/authorized_keys
chmod 600 /etc/dropbear/authorized_keys
printf '%s\n%s\n' '{password}' '{password}' | passwd root
{'/etc/init.d/uhttpd enable' if web else '/etc/init.d/uhttpd disable'}
touch /etc/harnessy-test-ready
exit 0
'''


class OpenWrtTargetManager(TestTargetManager):
    def __init__(self, workspace, target):
        super().__init__(workspace, target)
        self.home = self.root / 'qemu'
        self.instance_dir = self.home / 'guest'
        if self.home.is_symlink() or self.instance_dir.is_symlink():
            raise ValueError('Managed VM state directories cannot be symbolic links.')
        self._remember_for_shutdown()

    def _env(self):
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        env = os.environ.copy()
        env['PATH'] = repaired_path()
        for key in ('SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'LIMA_HOME', 'LIMA_INSTANCE'):
            env.pop(key, None)
        return env

    def runtime_dir(self):
        # Keep the QMP socket below macOS's 104-byte sockaddr_un limit.
        base = Path('/tmp') / f'hy-openwrt-{os.getuid()}'
        identity = hashlib.sha256(self.key.encode()).hexdigest()[:24]
        for path in (base, base / identity):
            if path.is_symlink():
                raise RuntimeError('OpenWrt runtime directory cannot be a symbolic link.')
            path.mkdir(mode=0o700, exist_ok=True)
            if path.stat().st_uid != os.getuid():
                raise RuntimeError('OpenWrt runtime directory belongs to another user.')
            path.chmod(0o700)
        return base / identity

    async def host_command(self, argv, *, timeout=120, allowed=(0,)):
        proc = await asyncio.create_subprocess_exec(*map(str, argv), cwd=self.root, env=self._env(),
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), timeout)
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
        text = output.decode(errors='replace')
        if proc.returncode not in allowed:
            raise RuntimeError(text[-2000:] or 'Host VM preparation command failed.')
        return text

    @staticmethod
    def _reap_launcher_later(proc):
        # A wrapper can remain alive even after its VM monitor is ready. Its
        # subprocess handle is not proof that it is safe to stop the guest.
        task = asyncio.create_task(proc.wait())
        _LAUNCH_REAPERS.add(task)
        task.add_done_callback(_LAUNCH_REAPERS.discard)

    async def _stop_launcher(self, proc):
        # Only this invocation's child handle is eligible for cleanup. Never
        # signal a PID read from the runtime directory or a process group.
        if proc.returncode is not None:
            return
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), 2)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), 2)
            except asyncio.TimeoutError:
                self._reap_launcher_later(proc)

    async def _owned_launch_running(self):
        try:
            # qmp() checks query-uuid before issuing query-status. A live PID,
            # occupied port, or unrelated monitor never proves this VM is up.
            result = await asyncio.wait_for(self.qmp('query-status'), 5)
            return isinstance(result, dict) and result.get('running') is True
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError, asyncio.TimeoutError):
            return False

    async def _launch_qemu(self, argv, *, timeout=OPENWRT_LAUNCH_SECONDS):
        # QEMU -daemonize (or a launcher wrapper) can leave a descendant holding
        # stdout/stderr open after the parent exits. Waiting for pipe EOF then
        # mistakes a running guest for a launch timeout. A private regular file
        # captures errors without making daemon FD lifetime part of readiness.
        try:
            from harnessy.diagnostics.test_target_logs import open_qemu_control_plane_capture
            capture_file = open_qemu_control_plane_capture(self.runtime_dir())
        except (OSError, ValueError):
            # Evidence setup must not prevent a VM launch. Preserve the private
            # prior file and retain the original regular-file handoff behavior.
            capture_file = tempfile.TemporaryFile(mode='w+b', dir=self.runtime_dir())
        with capture_file as capture:
            proc, evidence_error = None, None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *map(str, argv), cwd=self.root, env=self._env(),
                    stdin=asyncio.subprocess.DEVNULL, stdout=capture,
                    stderr=asyncio.subprocess.STDOUT,
                )
                try:
                    try:
                        await asyncio.wait_for(proc.wait(), timeout)
                    except asyncio.TimeoutError:
                        self.stage('launch_reconcile', failure_code='controller_timeout',
                                   timeout_seconds=timeout)
                        if await self._owned_launch_running():
                            if proc.returncode is None:
                                self._reap_launcher_later(proc)
                            self.stage('launch_recovered', returncode=proc.returncode,
                                       timeout_seconds=timeout)
                            if self.operation:
                                self.operation.note(
                                    'QEMU launch handoff exceeded its deadline, but this '
                                    'target\'s running VM was verified. Checking its shell '
                                    'and first-boot configuration with the existing ports.\n')
                            return
                        await self._stop_launcher(proc)
                        raise TestTargetFailure(
                            f'QEMU launch handoff did not finish within {timeout:g} seconds, '
                            'and this target\'s running VM could not be verified. '
                            'No replacement VM was launched. Download diagnostics for '
                            'the launch stage and boot log, then inspect the VM state '
                            'before retrying Start.', 'controller_timeout',
                        ) from None
                except asyncio.CancelledError:
                    # Cancellation can arrive after QEMU has booted. Preserve a
                    # UUID-verified running VM even when the spawned handle lingers.
                    if await self._owned_launch_running():
                        if proc.returncode is None:
                            self._reap_launcher_later(proc)
                    else:
                        await self._stop_launcher(proc)
                    raise
                self.stage('launch', returncode=proc.returncode,
                           timeout_seconds=timeout)
                if proc.returncode:
                    size = os.fstat(capture.fileno()).st_size
                    detail = os.pread(capture.fileno(), 2000, max(0, size - 2000)).decode(errors='replace').strip()
                    raise TestTargetFailure(
                        f'QEMU launcher exited with status {proc.returncode}. '
                        + (detail or 'Download diagnostics for the launch stage and VM boot log.'),
                        'launch_failed', returncode=proc.returncode,
                    )
            except BaseException as error:
                evidence_error = error
                raise
            finally:
                # Host launcher output is separate from -serial file:serial.log.
                # Preserve a bounded, scrubbed receipt even for failed/cancelled
                # handoff; this evidence path never changes VM lifecycle decisions.
                try:
                    from harnessy.diagnostics.test_target_logs import record_qemu_launcher_evidence
                    size = os.fstat(capture.fileno()).st_size
                    data = os.pread(capture.fileno(), 128 * 1024, max(0, size - 128 * 1024))
                    operation = self.operation
                    captured = record_qemu_launcher_evidence(
                        self.runtime_dir(), data,
                        stage=operation.stage if operation else 'launch',
                        operation_id=operation.operation_id if operation else '',
                        returncode=proc.returncode if proc is not None else None,
                        timeout_seconds=timeout, error=evidence_error,
                    )
                    if not captured:
                        from harnessy.diagnostics import log_event
                        log_event('runtime', 'test_target_log_capture_failed', target_id=self.target.id,
                                  target_backend='qemu', target_action='start', target_stage='launch',
                                  target_failure_code='log_capture_failed')
                except Exception:
                    # Missing/unsafe evidence is explicit in TARGET_LOGS.json.
                    pass

    async def prerequisites(self):
        # OpenWrt starts QEMU directly, but shares host setup with the launcher
        # and Lima-backed targets instead of requiring a manual package command.
        await ensure_test_target_prerequisites(
            self.config['architecture'], progress=self._prerequisite_progress,
        )

    async def _prepare(self):
        note = self.operation.note if self.operation else lambda _: None
        self.stage('download')
        try:
            folder, target, root_hash, kernel_hash = OPENWRT_RELEASE_IMAGES[self.config['os']][self.config['architecture']]
        except KeyError:
            raise ValueError('Unsupported OpenWrt test VM release or architecture.') from None
        release = self.config['os'].removeprefix('openwrt-')
        mips = self.config['architecture'].startswith('mips')
        base = f'https://downloads.openwrt.org/releases/{release}/targets/{folder}/openwrt-{release}-{target}-' + ('' if mips else 'generic-')
        images = self.root / 'images'
        root_archive = await download_verified(base + ('rootfs-ext4.img.gz' if mips else 'ext4-rootfs.img.gz'), root_hash, images / 'rootfs.img.gz', note)
        kernel = await download_verified(base + ('vmlinux.elf' if mips else 'kernel.bin'), kernel_hash, images / 'kernel.bin', note)
        self.stage('prepare_disk')
        stage = self.home / '.create-new'
        if stage.exists():
            await finish_thread(shutil.rmtree, stage)
        stage.mkdir(mode=0o700)
        try:
            disk = stage / 'rootfs.raw'
            await finish_thread(expand_gzip, root_archive, disk)
            with disk.open('r+b') as output:
                output.truncate(self.config['disk_gb'] * 1024**3)
            await self.host_command([e2fs_binary('e2fsck'), '-f', '-p', disk], allowed=(0, 1))
            await self.host_command([e2fs_binary('resize2fs'), disk])
            # Older release images can need resize-inode repair after growing.
            # Check the private staging disk before installing credentials or
            # promoting it; unrepairable errors leave no created guest.
            await self.host_command([e2fs_binary('e2fsck'), '-f', '-p', disk], allowed=(0, 1))
            await self.host_command([discover_binary('ssh-keygen'), '-q', '-t', 'ed25519', '-N', '', '-f', stage / 'id_ed25519'])
            password = secrets.token_hex(12)
            script = stage / 'bootstrap.sh'
            script.write_text(bootstrap_script((stage / 'id_ed25519.pub').read_text(), password, self.config['desktop']))
            script.chmod(0o600)
            # debugfs accepts its own quoting, not shell quoting. JSON quotes
            # preserve spaces in host paths and cannot introduce new commands.
            guest_path = '/etc/uci-defaults/99-harnessy-test'
            commands = stage / 'debugfs.txt'
            commands.write_text(f'write {json.dumps(str(script))} {guest_path}\nset_inode_field {guest_path} mode 0100700\n')
            result = await self.host_command([e2fs_binary('debugfs'), '-w', '-f', commands, disk])
            if 'Allocated inode' not in result:
                raise RuntimeError('Could not write the OpenWrt first-boot configuration: ' + result[-1000:])
            check = await self.host_command([e2fs_binary('debugfs'), '-R', f'stat {guest_path}', disk])
            if 'Type: regular' not in check or '0700' not in check:
                raise RuntimeError('Could not verify the OpenWrt first-boot configuration.')
            script.unlink()
            commands.unlink()
            shutil.copyfile(kernel, stage / 'kernel.bin')
            (stage / 'access.json').write_text(json.dumps({'web_password': password}))
            (stage / 'access.json').chmod(0o600)
            stage.rename(self.instance_dir)
            note('OpenWrt disk prepared. Starting private LAN and internet-facing NAT.\n')
        finally:
            if stage.exists():
                await finish_thread(shutil.rmtree, stage)

    async def qmp(self, command: str):
        async def communicate():
            reader, writer = await asyncio.open_unix_connection(str(self.runtime_dir() / 'qmp.sock'))
            try:
                greeting = json.loads(await reader.readline())
                if 'QMP' not in greeting:
                    raise RuntimeError('Unexpected VM monitor.')
                async def execute(name):
                    writer.write((json.dumps({'execute': name, 'id': name}) + '\n').encode())
                    await writer.drain()
                    for _ in range(100):
                        line = await reader.readline()
                        if not line:
                            raise ConnectionError('VM monitor closed the connection.')
                        reply = json.loads(line)
                        if reply.get('id') == name:
                            if 'error' in reply:
                                raise RuntimeError(str(reply['error']))
                            return reply.get('return', {})
                    raise RuntimeError('VM monitor did not answer.')
                await execute('qmp_capabilities')
                identity = await execute('query-uuid')
                if identity.get('UUID', '').lower() != str(uuid.UUID(self.target.id)):
                    raise RuntimeError('VM monitor belongs to another target.')
                return await execute(command)
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionError:
                    pass
        return await asyncio.wait_for(communicate(), 5)

    def _pid_alive(self):
        file = self.runtime_dir() / 'qemu.pid'
        if not file.exists():
            return False
        try:
            pid = int(file.read_text().strip())
            if pid < 2:
                raise ValueError('Invalid VM process ID.')
            os.kill(pid, 0)  # Liveness only; never signal a PID from disk.
            return True
        except ProcessLookupError:
            return False

    async def status(self):
        if not self.instance_dir.exists():
            return {'state': 'not_created', 'running': False, 'created': False,
                    'hardware_emulation': self.radio_state()}
        try:
            result = await self.qmp('query-status')
        except (FileNotFoundError, ConnectionRefusedError):
            if self._pid_alive():
                raise RuntimeError('OpenWrt process exists but its monitor is unavailable; its state is unknown.')
            return {'state': 'stopped', 'running': False, 'created': True,
                    'hardware_emulation': self.radio_state()}
        return {'state': 'running' if result.get('running') else result.get('status', 'paused'),
                'running': True, 'created': True, 'internet': True,
                'hardware_emulation': self.radio_state()}

    @staticmethod
    def _port():
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            return probe.getsockname()[1]

    def qemu_argv(self, ssh_port: int, web_port: int):
        arm = self.config['architecture'] == 'arm64'
        mips = self.config['architecture'].startswith('mips')
        native = not mips and canonical_arch(platform.machine()) == self.config['architecture']
        accel = 'hvf' if native and platform.system() == 'Darwin' else ('kvm' if native and os.access('/dev/kvm', os.R_OK | os.W_OK) else 'tcg')
        cpu = ('MIPS64R2-generic' if '64' in self.config['architecture'] else '24Kc') if mips else ('host' if accel != 'tcg' else ('cortex-a57' if arm else 'max'))
        runtime = self.runtime_dir()
        # Escape QEMU key/value commas; host paths remain one fixed argv value.
        disk = str(self.instance_dir / 'rootfs.raw').replace(',', ',,')
        lan = f'user,id=lan,net=192.168.77.0/24,host=192.168.77.1,restrict=on,hostfwd=tcp:127.0.0.1:{ssh_port}-192.168.77.2:22'
        if self.config['desktop']:
            lan += f',hostfwd=tcp:127.0.0.1:{web_port}-192.168.77.2:80'
        network = 'pcnet' if mips else 'virtio-net-pci'
        return [discover_binary(qemu_binary(self.config['architecture'])),
            '-name', 'harnessy-test-' + self.target.id, '-uuid', str(uuid.UUID(self.target.id)),
            '-machine', 'malta' if mips else ('virt' if arm else 'pc'), '-accel', accel, '-cpu', cpu,
            '-smp', str(self.config['cpu']), '-m', str(self.config['memory_mb']),
            '-kernel', str(self.instance_dir / 'kernel.bin'),
            '-append', ('root=/dev/sda' if mips else 'root=/dev/vda') + ' rootwait rw console=' + ('ttyAMA0' if arm else 'ttyS0'),
            '-drive', f'file={disk},format=raw,if=' + ('ide' if mips else 'virtio'),
            '-netdev', lan, '-device', network + ',netdev=lan,mac=52:54:00:77:00:01',
            '-netdev', 'user,id=wan', '-device', network + ',netdev=wan,mac=52:54:00:77:00:02',
            '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(runtime / 'serial.log'),
            '-qmp', 'unix:' + str(runtime / 'qmp.sock') + ',server=on,wait=off',
            '-pidfile', str(runtime / 'qemu.pid'), '-daemonize']

    async def start(self):
        self.invalidate_views()
        self.stage('prerequisites')
        self._env()
        await self.prerequisites()
        if not self.instance_dir.exists():
            await self._prepare()
        if not (await self.status())['running']:
            self.forget_radios()
            runtime = self.runtime_dir()
            for filename in ('qmp.sock', 'qemu.pid'):
                (runtime / filename).unlink(missing_ok=True)
            ssh_port, web_port = self._port(), self._port()
            while web_port == ssh_port:
                web_port = self._port()
            state = self.instance_dir / 'ports.json'
            state.write_text(json.dumps({'ssh': ssh_port, 'web': web_port}))
            state.chmod(0o600)
            self.stage('launch', timeout_seconds=OPENWRT_LAUNCH_SECONDS)
            await self._launch_qemu(self.qemu_argv(ssh_port, web_port),
                                    timeout=OPENWRT_LAUNCH_SECONDS)
        from harnessy.agent.external_targets import ExternalTargetBroker
        from harnessy.diagnostics.test_target_logs import classify_target_failure
        broker = ExternalTargetBroker(self.workspace)
        deadline = time.monotonic() + OPENWRT_READINESS_SECONDS
        attempt, last_code = 0, 'ssh_unavailable'
        while time.monotonic() < deadline:
            attempt += 1
            remaining = deadline - time.monotonic()
            self.stage('wait_ssh', attempt=attempt, timeout_seconds=remaining)
            try:
                # One bounded SSH invocation checks bootstrap, writable test
                # root and shell together. Metadata utilities are optional.
                result = await broker.test_connection(
                    self.target, initialize_root=True, timeout=min(10, remaining),
                    require_bootstrap=True, audit=False,
                )
                if result['ok'] and 'HX_OK' in result['stdout'].splitlines():
                    self.stage('probe_shell', attempt=attempt, returncode=0)
                    if self.operation:
                        self.operation.note('OpenWrt ready. Shell and package installation are available.\n')
                    await self.configure_radios()
                    self.stage('ready', attempt=attempt)
                    return
                rc = result.get('returncode')
                last_code = classify_target_failure(result.get('stderr', '')) if rc == 255 else 'readiness_probe_failed'
                if rc in (126, 127, 72, 73):
                    code = 'shell_command_missing' if rc in (126, 127) else 'readiness_probe_failed'
                    self.stage('probe_shell', attempt=attempt, failure_code=code, returncode=rc)
                    raise TestTargetFailure(
                        'OpenWrt answered SSH, but its shell or writable test root check failed. '
                        'Open Shell to inspect it; download diagnostics for the failure stage and boot log.',
                        code, returncode=rc,
                    )
                self.stage('probe_shell', attempt=attempt, failure_code=last_code, returncode=rc)
            except TestTargetFailure:
                raise
            except (RuntimeError, asyncio.TimeoutError) as exc:
                last_code = 'shell_probe_timeout' if isinstance(exc, asyncio.TimeoutError) else classify_target_failure(exc)
                self.stage('probe_shell', attempt=attempt, failure_code=last_code)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                running = (await asyncio.wait_for(self.status(), timeout=min(5, remaining)))['running']
            except asyncio.TimeoutError:
                running = True  # Unknown monitor state is not proof of exit.
                last_code = 'monitor_unavailable'
            if not running:
                raise TestTargetFailure('OpenWrt exited before its shell became ready. Download diagnostics for the boot log.', 'guest_exited')
            await asyncio.sleep(min(OPENWRT_POLL_SECONDS, max(0, deadline - time.monotonic())))
        self.stage('probe_shell', attempt=attempt, failure_code=last_code,
                   timeout_seconds=OPENWRT_READINESS_SECONDS)
        raise TestTargetFailure(
            f'OpenWrt shell was not ready after {OPENWRT_READINESS_SECONDS:g} seconds '
            f'({last_code}). Download diagnostics for the startup stages and VM boot log. '
            'The VM has been left available for inspection.', 'boot_timeout',
        )

    async def stop(self):
        self.invalidate_views()
        self.forget_radios()
        if not (await self.status())['running']:
            return
        if self.config['emulation']['bluetooth']:
            from .test_radios import stop_radios
            try:
                await stop_radios(self._radio_command)
            except (OSError, RuntimeError, asyncio.TimeoutError):
                pass  # Optional emulation cleanup cannot prevent guest shutdown.
        try:
            await self.host_command(self.command('sync; poweroff')[0], timeout=10)
        except (RuntimeError, asyncio.TimeoutError):
            await self.qmp('system_powerdown')
        for _ in range(30):
            if not (await self.status())['running']:
                return
            await asyncio.sleep(1)
        if self.operation:
            self.operation.note('Graceful shutdown timed out; powering off this test VM.\n')
        await self.qmp('quit')
        for _ in range(10):
            if not (await self.status())['running']:
                return
            await asyncio.sleep(0.5)
        raise RuntimeError('Could not confirm OpenWrt has stopped; its data was preserved.')

    def _command_transport(self) -> tuple[str, str, int]:
        """Return the current command socket identity across provider instances.

        Rotation only selects the socket for future clients. Existing masters
        and their active channels are owned by OpenSSH and remain untouched.
        """
        ports_file = self.instance_dir / 'ports.json'
        ports = json.loads(ports_file.read_text())
        key = (self.instance_dir / 'id_ed25519').stat()
        identity = hashlib.sha256(json.dumps([
            _COMMAND_TRANSPORT_SESSION,
            int(ports['ssh']), ports_file.stat().st_mtime_ns,
            key.st_dev, key.st_ino, key.st_size, key.st_mtime_ns,
        ]).encode()).hexdigest()[:16]
        runtime = str(self.runtime_dir())
        with _COMMAND_TRANSPORT_LOCK:
            previous_identity, generation = _COMMAND_TRANSPORTS.get(runtime, (identity, 0))
            if previous_identity != identity:
                generation = 0
            _COMMAND_TRANSPORTS[runtime] = (identity, generation)
        return runtime, identity, generation

    def command_transport_token(self) -> str:
        _, identity, generation = self._command_transport()
        return f'{identity}:{generation}'

    def rotate_command_transport(self, *, expected_token: str) -> bool:
        runtime, identity, generation = self._command_transport()
        with _COMMAND_TRANSPORT_LOCK:
            current = _COMMAND_TRANSPORTS.get(runtime)
            if current != (identity, generation) or expected_token != f'{identity}:{generation}':
                return False
            _COMMAND_TRANSPORTS[runtime] = (identity, generation + 1)
        return True

    def command(self, command, *, reuse_connection=True):
        ports = json.loads((self.instance_dir / 'ports.json').read_text())
        if reuse_connection:
            # Reuse authentication for command/probe channels. A new VM launch
            # or replaced identity gets a different socket in the existing
            # private, short runtime directory (also safe on macOS).
            runtime, identity, generation = self._command_transport()
            suffix = '' if generation == 0 else '-' + str(generation)
            control = Path(runtime) / ('ssh-' + identity + suffix + '.sock')
            connection_options = [
                '-o', 'ControlMaster=auto', '-o', 'ControlPersist=60',
                '-o', 'ControlPath=' + str(control),
                '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3',
            ]
        else:
            connection_options = ['-o', 'ControlMaster=no', '-o', 'ControlPath=none']
        argv = [discover_binary('ssh') or 'ssh', '-F', os.devnull, '-T', '-p', str(int(ports['ssh'])),
            '-i', str(self.instance_dir / 'id_ed25519'), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=5', '-o', 'ForwardAgent=no', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'HostKeyAlias=harnessy-test-' + self.target.id,
            '-o', 'UserKnownHostsFile=' + str(self.instance_dir / 'known_hosts'),
            '-o', 'GlobalKnownHostsFile=' + os.devnull, *connection_options, 'root@127.0.0.1',
            '/bin/ash -lc ' + shlex.quote(command)]
        return argv, self._env()

    def terminal_command(self):
        argv, env = self.command('cd ' + shlex.quote(self.target.remote_root) + '; exec /bin/ash -il')
        argv[argv.index('-T')] = '-tt'
        return argv, env, self.root

    def desktop_info(self):
        if not self.config['desktop']:
            raise ValueError('This target was created without the web interface.')
        ports = json.loads((self.instance_dir / 'ports.json').read_text())
        access = json.loads((self.instance_dir / 'access.json').read_text())
        return {'url': f"http://127.0.0.1:{int(ports['web'])}/", 'port': str(int(ports['web'])),
                'username': 'root', 'password': access['web_password'], 'kind': 'web'}

    async def delete(self):
        self.forget_radios()
        if self.instance_dir.exists():
            await self._require_stopped()
        if self.root.exists():
            await finish_thread(shutil.rmtree, self.root)
        await finish_thread(shutil.rmtree, self.runtime_dir())
        self.workspace.delete_external_target(self.target.id)
