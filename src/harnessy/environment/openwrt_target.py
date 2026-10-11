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
import uuid
from pathlib import Path

from .host_prerequisites import discover_binary, repaired_path
from .presets import canonical_arch
from .test_catalog import OPENWRT_RELEASE_IMAGES
from .test_images import download_verified, expand_gzip, finish_thread
from .test_targets import TestTargetManager


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

    async def prerequisites(self):
        names = ['ssh', 'ssh-keygen', 'qemu-system-aarch64' if self.config['architecture'] == 'arm64' else 'qemu-system-x86_64']
        missing = [name for name in names if not discover_binary(name)]
        missing += [name for name in ('debugfs', 'e2fsck', 'resize2fs') if not e2fs_binary(name)]
        if missing:
            command = 'brew install qemu e2fsprogs' if platform.system() == 'Darwin' else 'sudo apt-get install qemu-system-arm qemu-system-x86 e2fsprogs openssh-client'
            raise RuntimeError('OpenWrt needs ' + ', '.join(missing) + ' on the HarnessyXO host. Install the missing packages and retry Start. Example: ' + command)

    async def _prepare(self):
        note = self.operation.note if self.operation else lambda _: None
        try:
            folder, target, root_hash, kernel_hash = OPENWRT_RELEASE_IMAGES[self.config['os']][self.config['architecture']]
        except KeyError:
            raise ValueError('Unsupported OpenWrt test VM release or architecture.') from None
        release = self.config['os'].removeprefix('openwrt-')
        base = f'https://downloads.openwrt.org/releases/{release}/targets/{folder}/openwrt-{release}-{target}-generic-'
        images = self.root / 'images'
        root_archive = await download_verified(base + 'ext4-rootfs.img.gz', root_hash, images / 'rootfs.img.gz', note)
        kernel = await download_verified(base + 'kernel.bin', kernel_hash, images / 'kernel.bin', note)
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
            return {'state': 'not_created', 'running': False, 'created': False}
        try:
            result = await self.qmp('query-status')
        except (FileNotFoundError, ConnectionRefusedError):
            if self._pid_alive():
                raise RuntimeError('OpenWrt process exists but its monitor is unavailable; its state is unknown.')
            return {'state': 'stopped', 'running': False, 'created': True}
        return {'state': 'running' if result.get('running') else result.get('status', 'paused'),
                'running': True, 'created': True, 'internet': True}

    @staticmethod
    def _port():
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            return probe.getsockname()[1]

    def qemu_argv(self, ssh_port: int, web_port: int):
        arm = self.config['architecture'] == 'arm64'
        native = canonical_arch(platform.machine()) == self.config['architecture']
        accel = 'hvf' if native and platform.system() == 'Darwin' else ('kvm' if native and os.access('/dev/kvm', os.R_OK | os.W_OK) else 'tcg')
        cpu = 'host' if accel != 'tcg' else ('cortex-a57' if arm else 'max')
        runtime = self.runtime_dir()
        # Escape QEMU key/value commas; host paths remain one fixed argv value.
        disk = str(self.instance_dir / 'rootfs.raw').replace(',', ',,')
        lan = f'user,id=lan,net=192.168.77.0/24,host=192.168.77.1,restrict=on,hostfwd=tcp:127.0.0.1:{ssh_port}-192.168.77.2:22'
        if self.config['desktop']:
            lan += f',hostfwd=tcp:127.0.0.1:{web_port}-192.168.77.2:80'
        return [discover_binary('qemu-system-aarch64' if arm else 'qemu-system-x86_64'),
            '-name', 'harnessy-test-' + self.target.id, '-uuid', str(uuid.UUID(self.target.id)),
            '-machine', 'virt' if arm else 'pc', '-accel', accel, '-cpu', cpu,
            '-smp', str(self.config['cpu']), '-m', str(self.config['memory_mb']),
            '-kernel', str(self.instance_dir / 'kernel.bin'),
            '-append', 'root=/dev/vda rootwait rw console=' + ('ttyAMA0' if arm else 'ttyS0'),
            '-drive', f'file={disk},format=raw,if=virtio',
            '-netdev', lan, '-device', 'virtio-net-pci,netdev=lan,mac=52:54:00:77:00:01',
            '-netdev', 'user,id=wan', '-device', 'virtio-net-pci,netdev=wan,mac=52:54:00:77:00:02',
            '-display', 'none', '-monitor', 'none', '-serial', 'file:' + str(runtime / 'serial.log'),
            '-qmp', 'unix:' + str(runtime / 'qmp.sock') + ',server=on,wait=off',
            '-pidfile', str(runtime / 'qemu.pid'), '-daemonize']

    async def start(self):
        self._env()
        await self.prerequisites()
        if not self.instance_dir.exists():
            await self._prepare()
        if not (await self.status())['running']:
            runtime = self.runtime_dir()
            for filename in ('qmp.sock', 'qemu.pid'):
                (runtime / filename).unlink(missing_ok=True)
            ssh_port, web_port = self._port(), self._port()
            while web_port == ssh_port:
                web_port = self._port()
            state = self.instance_dir / 'ports.json'
            state.write_text(json.dumps({'ssh': ssh_port, 'web': web_port}))
            state.chmod(0o600)
            await self.host_command(self.qemu_argv(ssh_port, web_port), timeout=30)
        from harnessy.agent.external_targets import ExternalTargetBroker
        broker = ExternalTargetBroker(self.workspace)
        detail = ''
        for _ in range(120):
            try:
                await self.host_command(self.command('test -f /etc/harnessy-test-ready')[0], timeout=10)
                result = await broker.test_connection(self.target, initialize_root=True)
                if result['ok']:
                    if self.operation:
                        self.operation.note('OpenWrt ready. Shell and package installation are available.\n')
                    return
                detail = result.get('stderr', '')
            except (RuntimeError, asyncio.TimeoutError) as exc:
                detail = str(exc)
            if not (await self.status())['running']:
                break
            await asyncio.sleep(2)
        raise RuntimeError('OpenWrt shell did not become ready. ' + detail[-600:] + ' Check the private VM serial.log on the host.')

    async def stop(self):
        if not (await self.status())['running']:
            return
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

    def command(self, command):
        ports = json.loads((self.instance_dir / 'ports.json').read_text())
        argv = [discover_binary('ssh') or 'ssh', '-F', os.devnull, '-T', '-p', str(int(ports['ssh'])),
            '-i', str(self.instance_dir / 'id_ed25519'), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=5', '-o', 'ForwardAgent=no', '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'HostKeyAlias=harnessy-test-' + self.target.id,
            '-o', 'UserKnownHostsFile=' + str(self.instance_dir / 'known_hosts'),
            '-o', 'GlobalKnownHostsFile=' + os.devnull, 'root@127.0.0.1',
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
        if self.instance_dir.exists():
            await self._require_stopped()
        if self.root.exists():
            await finish_thread(shutil.rmtree, self.root)
        await finish_thread(shutil.rmtree, self.runtime_dir())
        self.workspace.delete_external_target(self.target.id)
