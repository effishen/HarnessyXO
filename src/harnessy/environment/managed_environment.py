"""Named Windows VM integration using the existing fixed Lima controller.

Windows receives explicit project copies on its own virtual disk. No canonical
workspace, controller metadata, host home, credentials or host sockets are mounted.
Its model command shell is PowerShell, not an implicit Linux or host fallback.
"""
from __future__ import annotations

import asyncio
import base64
import io
import json
import os
import re
import shlex
import shutil
import tarfile
import time
import unicodedata
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Any

from .activity import acquire_activity, activity, active_work, reserve_environment_change
from .base import (EnvironmentConfig, EnvironmentStatus, ExecResult, WorkspaceEnvironment,
                   _validate_registry_path, load_environment_config, save_environment_config)
from .host_prerequisites import discover_binary, ensure_host_prerequisites, ensure_test_target_prerequisites, repaired_path
from .test_catalog import guest_os
from .test_targets import TestTargetManager, normalize_vm_config

_LOCKS: dict[tuple[str, int], asyncio.Lock] = {}


class _ManagedController(TestTargetManager):
    """Reuse tested controller/desktop/snapshot operations without target records."""

    def __new__(cls, owner):
        return object.__new__(cls)

    def __init__(self, owner: 'ManagedEnvironment') -> None:
        self.owner = owner
        self.workspace = SimpleNamespace(root=owner.workspace_root, meta=owner.meta_root)
        self.target = SimpleNamespace(id=owner.config.id, name=owner.config.name,
                                      remote_root='C:/harnessy/workspace', shell='powershell')
        self.config = normalize_vm_config({
            'os': owner.config.preset, 'architecture': owner.config.architecture,
            'cpu': owner.config.cpu, 'memory_mb': owner.config.memory_mb,
            'disk_gb': owner.config.disk_gb, 'desktop': True, 'iso_path': owner.config.iso_path,
        })
        self.target.managed_vm = self.config
        self.guest = guest_os(self.config['os'])
        self.root = owner.environment_root / 'vm'
        self.home = self.root / 'lima'
        self.instance = 'harnessy'
        self.instance_dir = self.home / self.instance
        self.key = str(self.root.resolve())
        self.environment_id = owner.config.id
        self.windows = True
        self.backend = 'lima'
        for path in (self.root, self.home, self.instance_dir):
            _validate_registry_path(path, owner.workspace_root)
        from harnessy.diagnostics.test_target_logs import register_test_target_runtime
        register_test_target_runtime(self.root, 'lima')
        self._remember_for_shutdown()

    @property
    def busy(self) -> bool:
        from .operations import ENVIRONMENT_OPERATIONS
        return ENVIRONMENT_OPERATIONS.state(self.owner.workspace_root, environment_id=self.environment_id).busy

    def _env(self):
        for path in (self.root, self.home, self.instance_dir):
            _validate_registry_path(path, self.owner.workspace_root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        from .lima import LimaVMEnvironment
        env = os.environ.copy()
        env.update(PATH=repaired_path(), LIMA_HOME=str(LimaVMEnvironment._runtime_home(self.owner)))
        env['LIMA_SHELLENV_BLOCK'] = '*'
        env.pop('LIMA_SHELLENV_ALLOW', None)
        for name in ('SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'LIMA_INSTANCE', 'LIMA_SHELL', 'LIMA_WORKDIR'):
            env.pop(name, None)
        return env

    def vm_document(self):
        document = super().vm_document()
        document['ssh']['loadDotSSHPubKeys'] = False
        return document

    def acquire(self):
        release_environment = acquire_activity(self.owner.workspace_root, 'Windows graphical view',
                                               environment_id=self.environment_id)
        try:
            release_controller = super().acquire()
        except BaseException:
            release_environment()
            raise
        def release():
            release_controller()
            release_environment()
        return release

    async def set_windows_password(self, value: str) -> dict[str, Any]:
        if not value or any(char in value for char in ('\x00', '\r', '\n')):
            raise ValueError('Enter a non-empty Windows password without line breaks.')
        rc, out, err = await self.owner._raw(
            "$ErrorActionPreference='Stop'; Set-LocalUser -Name 'harnessy' -Password (ConvertTo-SecureString "
            + self.owner._quoted(value) + ' -AsPlainText -Force)', check=False)
        return {'ok': rc == 0, 'stdout': '', 'stderr': '' if rc == 0 else 'Windows could not update the sign-in password. Verify that setup is complete and the guest user has administrator access.'}


class ManagedEnvironment(WorkspaceEnvironment):
    TIMEOUT_START = 120.0

    def __init__(self, workspace_root: Path, config: EnvironmentConfig) -> None:
        super().__init__(workspace_root, config)
        if config.provider != 'managed' or config.preset != 'windows-11' or config.files_mode != 'copy':
            raise ValueError('Windows VM environments require the separate project-copy integration.')
        _validate_registry_path(self.environment_root, self.workspace_root)
        self.state_root = self.environment_root / 'state'
        _validate_registry_path(self.state_root, self.workspace_root)
        self.state_root.mkdir(parents=True, exist_ok=True)
        self.readiness_path = self.state_root / 'readiness.json'
        self.controller = _ManagedController(self)
        self.vm_root = self.controller.home
        self.snapshots_root = self.controller.root / 'snapshots'
        self._process_tasks: set[asyncio.Task] = set()

    def _lock(self) -> asyncio.Lock:
        key = str(self.environment_root), id(asyncio.get_running_loop())
        return _LOCKS.setdefault(key, asyncio.Lock())

    @staticmethod
    def _ps(script: str) -> list[str]:
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        return ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded]

    @staticmethod
    def _quoted(value: str) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    async def _raw(self, script: str, *, timeout: float = 30, input_bytes: bytes | None = None,
                   check: bool = True) -> tuple[int, str, str]:
        return await self.controller._run('shell', '--workdir', 'C:/', self.controller.instance,
                                          *self._ps(script), timeout=timeout,
                                          input_bytes=input_bytes, check=check)

    def _readiness(self) -> dict[str, Any]:
        try:
            _validate_registry_path(self.readiness_path, self.workspace_root)
            value = json.loads(self.readiness_path.read_text('utf-8'))
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def _record(self, *, ready: bool, phase: str, boot_id: str = '', error: str = '') -> None:
        _validate_registry_path(self.readiness_path, self.workspace_root)
        previous = self._readiness()
        try:
            generation = max(0, int(previous.get('generation') or 0))
        except (TypeError, ValueError):
            generation = 0
        if (ready and boot_id != previous.get('boot_id')) or phase == 'destroyed':
            generation += 1
        self.state_root.mkdir(parents=True, exist_ok=True)
        path = self.readiness_path.with_suffix('.tmp')
        _validate_registry_path(path, self.workspace_root)
        path.write_text(json.dumps({'ready': ready, 'phase': phase, 'boot_id': boot_id or str(previous.get('boot_id') or ''),
                                    'generation': generation,
                                    'error': error, 'updated_at': time.time()}) + '\n', encoding='utf-8')
        path.replace(self.readiness_path)

    async def _progress(self, callback, phase: str, message: str) -> None:
        if callback is not None:
            value = callback(phase, message)
            if hasattr(value, '__await__'):
                await value

    async def status(self) -> EnvironmentStatus:
        fields = dict(environment_id=self.config.id, environment_name=self.config.name,
                      guest_architecture=self.config.architecture, guest_os='Windows 11',
                      files_mount='C:/harnessy/workspace', cpu_only=True)
        if not discover_binary('limactl'):
            return EnvironmentStatus('backend_missing', 'managed', False, False, False,
                                     'Lima is required. Start the VM to prepare host prerequisites.', **fields)
        data = await self.controller.status()
        running = bool(data.get('running'))
        marker = self._readiness() if running else {}
        ready = bool(running and marker.get('ready'))
        phase = 'ready' if ready else (str(marker.get('phase') or 'installer_pending') if running else str(data.get('state') or 'not_created'))
        detail = ('Ready for PowerShell commands; project files are separate deployed copies.' if ready else
                  'Windows is running. Finish Windows setup in its graphical tab; guest SSH and PowerShell must become available.'
                  if running else 'Windows VM has not been created.' if not data.get('created') else 'Stopped')
        if phase == 'network_policy_failed':
            detail = 'Windows is running, but its requested firewall policy is unverified. Finish administrator setup and retry Start.'
        return EnvironmentStatus('ready' if ready else phase, 'managed', True,
                                 bool(data.get('created')), running, detail,
                                 ready=ready, phase=phase, **fields)

    async def create(self, progress=None) -> EnvironmentStatus:
        current = await self.status()
        if current.created:
            return current
        iso = Path(self.config.iso_path).expanduser()
        if not iso.is_file():
            raise ValueError('The selected Windows installer ISO does not exist on the HarnessyXO host.')
        await self._progress(progress, 'checking_host_dependencies', 'Checking Windows VM prerequisites…')
        await ensure_test_target_prerequisites(self.config.architecture, windows=True, progress=progress)
        await ensure_host_prerequisites(self.config, vm_type='qemu', progress=progress)
        self.controller._env()
        specification = self.environment_root / 'windows.json'
        specification.write_text(json.dumps(self.controller.vm_document(), indent=2) + '\n', encoding='utf-8')
        await self._progress(progress, 'creating_vm', 'Creating Windows VM from the selected ISO…')
        await self.controller._run('create', '--tty=false', '--name', self.controller.instance,
                                   str(specification), timeout=1200)
        self._record(ready=False, phase='stopped')
        return await self.status()

    async def start(self, progress=None) -> EnvironmentStatus:
        async with self._lock():
            saved = load_environment_config(self.workspace_root, self.config.id)
            if saved is None:
                raise RuntimeError('The selected Windows VM environment no longer exists.')
            self.config = saved
            state = await self.create(progress=progress)
            if not state.running:
                self._record(ready=False, phase='starting_vm')
                await self._progress(progress, 'starting_vm', 'Starting Windows VM…')
                # An installer can run before guest SSH exists. A controller
                # readiness timeout does not mean that the hypervisor failed.
                try:
                    await self.controller._run('start', '--tty=false', '--timeout=90s',
                                               self.controller.instance, timeout=110, check=False)
                except asyncio.TimeoutError:
                    pass
            state = await self.status()
            if not state.running:
                raise RuntimeError('Windows VM did not enter the running state. Check the VM diagnostics.')
            try:
                rc, out, _ = await self._raw(
                    "$ErrorActionPreference='Stop'; (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')",
                    timeout=12, check=False)
                if rc or not out.strip():
                    raise RuntimeError('Guest PowerShell is not ready.')
            except (RuntimeError, asyncio.TimeoutError):
                self._record(ready=False, phase='installer_pending')
                await self._progress(progress, 'installer_pending', 'Windows is running; finish setup in its graphical tab.')
                return await self.status()
            try:
                await self._apply_network(self.config.network)
            except BaseException:
                self._record(ready=False, phase='network_policy_failed')
                raise RuntimeError('Windows started, but its requested firewall policy could not be verified. Finish administrator setup and retry Start.')
            self._record(ready=True, phase='ready', boot_id=out.strip())
            await self._progress(progress, 'ready', 'Windows VM Ready')
            return await self.status()

    async def stop(self, *, force: bool = False) -> EnvironmentStatus:
        state = await self.status()
        if state.running:
            args = ['stop'] + (['--force'] if force else []) + [self.controller.instance]
            await self.controller._run(*args, timeout=180)
        self._record(ready=False, phase='stopped')
        return await self.status()

    async def _ensure_running(self) -> None:
        state = await self.status()
        if not state.ready:
            state = await self.start()
        if not state.ready:
            raise RuntimeError(state.detail)

    async def _apply_network(self, enabled: bool) -> None:
        action = 'Allow' if enabled else 'Block'
        await self._raw("$ErrorActionPreference='Stop'; Set-NetFirewallProfile -Profile Domain,Public,Private "
                        f"-DefaultOutboundAction {action}; "
                        "$p=Get-NetFirewallProfile; if (@($p | Where-Object {$_.DefaultOutboundAction -ne '" + action + "'}).Count) {throw 'Firewall policy verification failed'}",
                        timeout=25)

    async def apply_network_policy(self, enabled: bool, *, expected: bool | None = None,
                                   progress=None, reservation_held: bool = False) -> EnvironmentStatus:
        if not isinstance(enabled, bool):
            raise ValueError('VM network access must be a boolean.')
        release = (lambda: None) if reservation_held else reserve_environment_change(
            self.workspace_root, 'network policy', environment_id=self.config.id)
        try:
            original = load_environment_config(self.workspace_root, self.config.id)
            if original is None or (expected is not None and original.network != expected):
                raise RuntimeError('VM network settings changed. Reopen the editor before applying.')
            state = await self.status()
            if state.ready:
                await self._apply_network(enabled)
            changed = EnvironmentConfig.from_dict({**original.to_dict(), 'network': enabled})
            save_environment_config(self.workspace_root, changed, preserve_user_metadata=True)
            self.config = load_environment_config(self.workspace_root, changed.id) or changed
            return await self.status()
        finally:
            release()

    def project_guest_root(self, active_root: Path, *, output_policy: dict[str, Any] | None = None) -> str:
        root = Path(active_root).resolve()
        for parent in (self.files_root.resolve(), self.private_worktrees_root.resolve()):
            if root == parent or parent in root.parents:
                relative = root.relative_to(parent)
                if any(part in {'.', '..'} for part in relative.parts):
                    break
                prefix = 'Files' if parent == self.files_root.resolve() else 'Worktrees'
                return 'C:/harnessy/workspace/' + prefix + ('/' + relative.as_posix() if relative.parts else '')
        raise ValueError('The selected project is outside this workspace.')

    def _cwd(self, value: str, active_root: Path) -> str:
        raw = str(value or '/workspace').replace('\\', '/')
        if '..' in PurePosixPath(raw).parts:
            raise ValueError('Guest working directory cannot traverse outside its project copy.')
        if raw == '/workspace' or raw.startswith('/workspace/'):
            raw = 'C:/harnessy/workspace' + raw[len('/workspace'):]
        root = self.project_guest_root(active_root)
        if raw == 'C:/harnessy/workspace':
            return root
        if raw.casefold() != root.casefold() and not raw.casefold().startswith(root.casefold() + '/'):
            raise ValueError('The guest working directory is outside the selected project copy.')
        return raw

    def _command_script(self, command: str, cwd: str, root: Path) -> str:
        return ("$ErrorActionPreference='Stop'; " + self._guest_work_path_powershell(root)
                + '; Set-Location -LiteralPath '
                + self._quoted(self._cwd(cwd, root))
                + '; $global:LASTEXITCODE=0;\n& {\n' + str(command)
                + '\n}\nif ($global:LASTEXITCODE -ne 0) { exit $global:LASTEXITCODE }')

    def guest_work_paths(self, active_root: Path | None = None) -> dict[str, str]:
        key = self._guest_project_key(active_root)
        prefix = '$env:USERPROFILE/AppData/Local/Harnessy'
        return {
            'HARNESSY_BUILD_ROOT': f'{prefix}/build/{key}',
            'HARNESSY_VENV_ROOT': f'{prefix}/venvs/{key}',
            'XDG_CACHE_HOME': f'{prefix}/cache/{key}',
            'PYTHONPYCACHEPREFIX': f'{prefix}/cache/{key}/pycache',
        }

    def _guest_work_path_powershell(self, active_root: Path | None) -> str:
        key = self._guest_project_key(active_root)
        return ("if (!$env:USERPROFILE) { throw 'The Windows guest user profile is unavailable' }; "
                + '; '.join(f"$env:{name}=Join-Path $env:USERPROFILE 'AppData/Local/Harnessy/{relative}'"
                            for name, relative in (
                                ('HARNESSY_BUILD_ROOT', f'build/{key}'),
                                ('HARNESSY_VENV_ROOT', f'venvs/{key}'),
                                ('XDG_CACHE_HOME', f'cache/{key}'),
                                ('PYTHONPYCACHEPREFIX', f'cache/{key}/pycache')))
                + '; New-Item -ItemType Directory -Force -Path $env:HARNESSY_BUILD_ROOT,$env:HARNESSY_VENV_ROOT,$env:XDG_CACHE_HOME,$env:PYTHONPYCACHEPREFIX | Out-Null')

    def _archive(self, active_root: Path) -> bytes:
        root = Path(active_root).resolve()
        self.project_guest_root(root)  # validate before reading
        if not root.is_dir():
            raise ValueError('The project-copy source is unavailable.')
        buffer = io.BytesIO()
        windows_paths: set[str] = set()
        with tarfile.open(fileobj=buffer, mode='w', dereference=True) as archive:
            for item in sorted(root.rglob('*')):
                if item.is_symlink():
                    raise ValueError('Windows project deployment cannot preserve symbolic links. Deploy a source tree without symlinks.')
                if item.is_file() or item.is_dir():
                    relative = item.relative_to(root).as_posix()
                    parts = PurePosixPath(relative).parts
                    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}
                    if any(part in {'.', '..'} or part.endswith((' ', '.'))
                           or part.split('.')[0].upper() in reserved
                           or any(ord(char) < 32 or char in '<>:"|?*\\' for char in part) for part in parts):
                        raise ValueError('The source contains a path that cannot be safely deployed to Windows.')
                    canonical = unicodedata.normalize('NFC', relative).casefold()
                    if canonical in windows_paths:
                        raise ValueError('The source has names that collide on Windows. Rename case-equivalent files before deployment.')
                    windows_paths.add(canonical)
                    archive.add(item, arcname=relative, recursive=False)
                    if buffer.tell() > 100 * 1024 * 1024:
                        raise ValueError('Deploy at most 100 MiB at a time to this Windows guest.')
        return buffer.getvalue()

    async def _deploy(self, active_root: Path, *, refresh: bool, output_policy: dict[str, Any] | None = None) -> dict[str, Any]:
        self._authorize_model_project(output_policy)
        destination = self.project_guest_root(active_root)
        key = str(self.environment_root) + '|' + destination, id(asyncio.get_running_loop())
        async with _LOCKS.setdefault(key, asyncio.Lock()):
            return await self._deploy_locked(active_root, refresh=refresh, output_policy=output_policy)

    async def _deploy_locked(self, active_root: Path, *, refresh: bool, output_policy: dict[str, Any] | None = None) -> dict[str, Any]:
        await self._ensure_running()
        self._authorize_model_project(output_policy)
        destination = self.project_guest_root(active_root)
        if not refresh:
            rc, out, _ = await self._raw('if (Test-Path -LiteralPath ' + self._quoted(destination) + ") { 'EXISTS' }", check=False)
            if rc == 0 and 'EXISTS' in out:
                return {'environment_id': self.config.id, 'files_mode': 'copy', 'deployed_projects': [], 'canonical_files_changed': False}
        archive = await asyncio.to_thread(self._archive, active_root)
        # The archive arrives on stdin instead of an oversized host argv. The
        # fixed PowerShell helper writes only into this guest's selected copy.
        script = "$ErrorActionPreference='Stop'; $dest=" + self._quoted(destination) + r''';
function Assert-NoRedirect([string]$path) {
  $current=[System.IO.Path]::GetFullPath($path);
  while ($current) {
    if (Test-Path -LiteralPath $current) {
      $entry=Get-Item -LiteralPath $current -Force;
      if ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'Project deployment refuses a redirected guest path' }
    }
    $parent=[System.IO.Path]::GetDirectoryName($current);
    if ($parent -eq $current) { break }; $current=$parent;
  }
}
Assert-NoRedirect $dest;
$parent=[System.IO.Path]::GetDirectoryName($dest);
New-Item -ItemType Directory -Force -Path $parent | Out-Null;
$token=[guid]::NewGuid().ToString('N'); $stage=$dest+'.deploy-'+$token; $previous=$dest+'.previous-'+$token;
$archive=Join-Path $parent ('harnessy-'+$token+'.tar'); $payload=[Console]::In.ReadToEnd();
try {
  [System.IO.File]::WriteAllBytes($archive,[Convert]::FromBase64String($payload));
  New-Item -ItemType Directory -Path $stage | Out-Null;
  & tar.exe -xf $archive -C $stage; if ($LASTEXITCODE -ne 0) { throw 'Project archive extraction failed' }
  Assert-NoRedirect $dest;
  if (Test-Path -LiteralPath $dest) { [System.IO.Directory]::Move($dest,$previous) }
  try { [System.IO.Directory]::Move($stage,$dest) }
  catch { if ((Test-Path -LiteralPath $previous) -and !(Test-Path -LiteralPath $dest)) { [System.IO.Directory]::Move($previous,$dest) }; throw }
  if (Test-Path -LiteralPath $previous) { Remove-Item -LiteralPath $previous -Recurse -Force }
}
finally {
  Remove-Item -LiteralPath $archive -Force -ErrorAction SilentlyContinue;
  if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
'''
        self._authorize_model_project(output_policy)
        await self._raw(script, timeout=120, input_bytes=base64.b64encode(archive))
        return {'environment_id': self.config.id, 'files_mode': 'copy', 'deployed_projects': [Path(active_root).name],
                'refreshed': refresh, 'canonical_files_changed': False}

    async def deploy_project(self, active_root: Path, *, output_policy: dict[str, Any] | None = None) -> dict[str, Any]:
        self._authorize_model_project(output_policy)
        if active_work(self.workspace_root, environment_id=self.config.id):
            raise RuntimeError('Stop guest commands and terminals before refreshing its project copy.')
        release = reserve_environment_change(self.workspace_root, 'project deployment', environment_id=self.config.id)
        try:
            return await self._deploy(active_root, refresh=True, output_policy=output_policy)
        finally:
            release()

    async def exec(self, command: str, *, cwd: str = '/workspace', timeout: float | None = None,
                   active_root: Path | None = None, output_policy: dict[str, Any] | None = None) -> ExecResult:
        if not str(command).strip():
            raise ValueError('command must not be empty')
        self._authorize_model_project(output_policy)
        root = Path(active_root or self.files_root)
        with activity(self.workspace_root, 'Windows command', environment_id=self.config.id):
            await self._deploy(root, refresh=False, output_policy=output_policy)
            script = self._command_script(command, cwd, root)
            self._authorize_model_project(output_policy)
            started = time.monotonic()
            rc, out, err = await self._raw(script, timeout=timeout or 120, check=False)
            return ExecResult(rc, out, err, time.monotonic() - started)

    async def spawn(self, command: str, *, cwd: str = '/workspace', active_root: Path | None = None,
                    output_policy: dict[str, Any] | None = None) -> asyncio.subprocess.Process:
        self._authorize_model_project(output_policy)
        root = Path(active_root or self.files_root)
        release = acquire_activity(self.workspace_root, 'Windows process', environment_id=self.config.id)
        try:
            await self._deploy(root, refresh=False, output_policy=output_policy)
            script = self._command_script(command, cwd, root)
            self._authorize_model_project(output_policy)
            process = await asyncio.create_subprocess_exec(
                self.controller._binary(), 'shell', '--workdir', 'C:/', self.controller.instance,
                *self._ps(script), env=self.controller._env(), stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except BaseException:
            release(); raise
        async def finished():
            try: await process.wait()
            finally: release()
        task = asyncio.create_task(finished()); self._process_tasks.add(task)
        task.add_done_callback(self._process_tasks.discard)
        return process

    async def open_terminal(self, *, active_root: Path | None = None):
        with activity(self.workspace_root, 'Opening Windows terminal', environment_id=self.config.id):
            await self._ensure_running()
            await self._deploy(Path(active_root or self.files_root), refresh=False)
            return await asyncio.to_thread(self.terminal_command, active_root=active_root)

    def terminal_command(self, *, active_root: Path | None = None):
        project = Path(active_root or self.files_root)
        root = self.project_guest_root(project)
        setup = ("$ErrorActionPreference='Stop'; " + self._guest_work_path_powershell(project)
                 + '; Set-Location -LiteralPath ' + self._quoted(root))
        encoded = base64.b64encode(setup.encode('utf-16-le')).decode('ascii')
        argv = [self.controller._binary(), 'shell', '--workdir', root, self.controller.instance,
                'powershell.exe', '-NoLogo', '-NoProfile', '-NoExit', '-EncodedCommand', encoded]
        return argv, self.controller._env(), self.workspace_root

    async def snapshot(self, tag: str, progress=None) -> list[str]:
        await self.controller.snapshot(tag)
        return await self.list_snapshots()

    async def list_snapshots(self) -> list[str]:
        return self.controller.snapshots()

    async def restore_snapshot(self, tag: str, progress=None) -> EnvironmentStatus:
        await self.controller.restore(tag)
        self._record(ready=False, phase='stopped')
        return await self.start(progress=progress)

    async def reset(self, progress=None) -> EnvironmentStatus:
        return await self.rebuild(progress=progress)

    async def rebuild(self, progress=None) -> EnvironmentStatus:
        await self.stop(force=True)
        if self.controller.instance_dir.exists():
            await self.controller._run('delete', '--force', self.controller.instance, timeout=180)
        self._record(ready=False, phase='not_created')
        await self.create(progress=progress)
        return await self.start(progress=progress)

    async def destroy(self) -> None:
        state = await self.status()
        if not state.available:
            raise RuntimeError('Restore Windows VM backend access before removing this environment. Existing virtual disks were preserved.')
        if state.running:
            raise RuntimeError('Stop the Windows VM before removing it.')
        if state.created:
            await self.controller._run('delete', '--force', self.controller.instance, timeout=180)
        _validate_registry_path(self.controller.root, self.workspace_root)
        await asyncio.to_thread(shutil.rmtree, self.controller.root, True)
        self._record(ready=False, phase='destroyed')

    def desktop_manager(self, workspace=None):
        if workspace is not None:
            self.controller.workspace = workspace
        return self.controller

    def runtime_identity(self) -> dict[str, Any]:
        marker = self._readiness()
        return {**super().runtime_identity(), 'guest_os': 'Windows 11', 'guest_shell': 'PowerShell',
                'guest_files_root': 'C:/harnessy/workspace', 'shared_files': False,
                'project_isolation': 'explicit_guest_disk_copies', 'network_policy': 'windows_firewall_outbound',
                'guest_filesystem_access': 'full_guest_filesystem_including_previous_deployed_copies',
                'vm_ready': bool(marker.get('ready')), 'vm_boot_id': str(marker.get('boot_id') or ''),
                'vm_generation': int(marker.get('generation') or 0), 'vm_readiness_updated_at': marker.get('updated_at')}

    async def inspect(self) -> dict[str, Any]:
        state = await self.status()
        return {'environment_id': self.config.id, 'environment_name': self.config.name,
                'config': self.config.to_dict(), 'status': state.to_dict(),
                'runtime_identity': self.runtime_identity(), 'snapshots': await self.list_snapshots(),
                'durable_vm_root': str(self.controller.home), 'guest_files_root': 'C:/harnessy/workspace',
                'vm_type': 'qemu', 'mount_type': 'separate-copy',
                'files_note': 'Project files are explicit copies on the guest disk. No host directories are mounted.'}
