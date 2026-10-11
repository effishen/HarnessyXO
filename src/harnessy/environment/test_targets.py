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
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .host_prerequisites import discover_binary, repaired_path
from .presets import canonical_arch
from .test_catalog import guest_os, KALI_IMAGES


def normalize_vm_config(raw: dict[str, Any]) -> dict[str, Any]:
    os_name = str(raw.get('os') or 'ubuntu-24.04')
    guest = guest_os(os_name)
    arch = canonical_arch(str(raw.get('architecture') or platform.machine()))
    if arch not in {'arm64', 'x86_64'}:
        raise ValueError('Test VMs support ARM64 and x86-64.')
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
    return {
        'os': os_name, 'architecture': arch,
        'cpu': number('cpu', guest.cpu, 2 if os_name == 'windows-11' else 1, 32),
        'memory_mb': number('memory_mb', guest.memory, guest.min_memory, 131072),
        'disk_gb': number('disk_gb', guest.disk, guest.min_disk, 2048 if guest.family != 'openwrt' else 64),
        'desktop': bool(raw.get('desktop', True)), 'internet': True,
        'iso_path': iso if os_name == 'windows-11' else '',
    }


@dataclass
class TargetOperation:
    action: str
    state: str = 'running'
    output: str = ''
    error: str = ''
    task: asyncio.Task | None = None

    def note(self, text: str) -> None:
        self.output = (self.output + str(text))[-60000:]


_OPERATIONS: dict[str, TargetOperation] = {}
_ACTIVE: dict[str, int] = {}


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
        if action not in {'start', 'stop', 'snapshot', 'restore', 'delete'}:
            raise ValueError('Unsupported test VM action.')
        if self.busy:
            raise RuntimeError('A test VM operation is already running. Wait for it to finish.')
        if action in {'snapshot', 'restore', 'delete'} and _ACTIVE.get(self.key, 0):
            raise RuntimeError('Close this target’s shell and finish its commands before changing VM data.')
        op = TargetOperation(action)
        _OPERATIONS[self.key] = op
        async def work():
            started = time.perf_counter()
            try:
                op.note(f'{action.capitalize()} · {self.target.name}\n')
                if action == 'start':
                    await self.start()
                elif action == 'stop':
                    await self.stop()
                elif action == 'snapshot':
                    await self.snapshot(tag)
                elif action == 'restore':
                    await self.restore(tag)
                else:
                    await self.delete()
                op.state = 'succeeded'
            except asyncio.CancelledError:
                op.state, op.error = 'cancelled', 'Operation cancelled; check VM status before retrying.'
            except Exception as exc:
                op.state, op.error = 'failed', str(exc)
                op.note('\n' + op.error)
            finally:
                if self.workspace.get_external_target(self.target.id):
                    self.workspace.record_external_target_event(self.target.id, action=action, detail=tag,
                        ok=op.state == 'succeeded', duration_seconds=time.perf_counter() - started)
        op.task = asyncio.create_task(work(), name=f'harnessy-test-{action}-{self.target.id}')
        return op

    async def request_stop(self) -> TargetOperation:
        if self.busy:
            if self.operation.action != 'start':
                raise RuntimeError('Wait for the current snapshot/restore/delete operation to finish.')
            if not self.instance_dir.exists():
                raise RuntimeError('Host prerequisites are still being prepared. Retry Stop once the VM has been created.')
            task = self.operation.task
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return self.begin('stop')

    async def stop(self):
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
        from .base import EnvironmentConfig
        from .host_prerequisites import ensure_host_prerequisites
        await ensure_host_prerequisites(EnvironmentConfig(architecture=self.config['architecture']), vm_type='qemu')
        await self.prerequisites()
        if not self.instance_dir.exists():
            if self.windows and not Path(self.config['iso_path']).expanduser().is_file():
                raise RuntimeError('The Windows installer ISO was not found on the HarnessyXO host.')
            if self.config['os'].startswith('kali-'):
                from .test_images import download_verified, extract_cloud_disk, finish_thread
                arch, digest = KALI_IMAGES[self.config['architecture']]
                images = self.root / 'images'
                archive = await download_verified(
                    f'https://kali.download/cloud-images/kali-2026.2/kali-linux-2026.2-cloud-genericcloud-{arch}.tar.xz',
                    digest, images / 'kali.tar.xz', self.operation.note if self.operation else lambda _: None)
                await finish_thread(extract_cloud_disk, archive, images / 'kali.img')
            spec = self.root / 'test.yaml'
            spec.write_text(json.dumps(self.vm_document(), indent=2), encoding='utf-8')
            await self._run('create', '--tty=false', '--name', self.instance, str(spec), timeout=3600)
        await self._run('start', '--tty=false', self.instance, timeout=7200)
        # Readiness includes command execution and a usable test root, not just a
        # running hypervisor. The Windows installer may spend a long time here.
        from harnessy.agent.external_targets import ExternalTargetBroker
        result = await ExternalTargetBroker(self.workspace).test_connection(self.target, initialize_root=True)
        if not result['ok']:
            raise RuntimeError(result.get('stderr') or 'Guest started but its test shell is not ready.')
        if self.operation:
            self.operation.note('\nTest VM ready. Internet access and software installation are available.\n')

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
            raise RuntimeError('Close the target shell and finish target commands first.')

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


async def close_test_targets(workspaces):
    """Release controller tasks and guest RAM when the application exits."""
    tasks = [op.task for op in _OPERATIONS.values() if op.task and not op.task.done()]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    managers = []
    for ws in workspaces:
        for target in ws.list_external_targets():
            if target.managed_vm:
                try:
                    managers.append(TestTargetManager(ws, target))
                except (ValueError, OSError):
                    pass  # One damaged record must not prevent other guests stopping.
    async def stop_one(manager):
        try:
            if (await manager.status())['running']:
                await manager.stop()
        except Exception:
            pass  # Shutdown must continue even if a host controller is unavailable.
    await asyncio.gather(*(stop_one(manager) for manager in managers))
